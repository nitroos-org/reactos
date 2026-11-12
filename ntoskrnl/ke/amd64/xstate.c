/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Extended processor state management
 * COPYRIGHT:   Copyright 2025 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

#include <ntoskrnl.h>
#include <x86x64/Cpuid.h>
#include <x86x64/Msr.h>
#define NDEBUG
#include <debug.h>

// These are not officially documented
#define XSTATE_PKRU                         9
#define XSTATE_HDC                          13
#define XSTATE_UINTR                        14
#define XSTATE_LBR                          15
#define XSTATE_MASK_PKRU                    (1LL << (XSTATE_PKRU))
#define XSTATE_MASK_HDC                     (1LL << (XSTATE_HDC))
#define XSTATE_MASK_UINTR                   (1LL << (XSTATE_UINTR))
#define XSTATE_MASK_LBR                     (1LL << (XSTATE_LBR))

#define XSTATE_MASK_SUPERVISOR \
    (XSTATE_MASK_IPT | \
     XSTATE_MASK_PASID | \
     XSTATE_MASK_CET_U | \
     XSTATE_MASK_CET_S | \
     XSTATE_MASK_HDC | \
     XSTATE_MASK_UINTR | \
     XSTATE_MASK_LBR)

/* Features a thread context can load into the processor. They have no reserved bits, so XRSTOR cannot fault on
   what the caller put into them. The others (MPX BNDCSR, LWP, AMX tile configuration) keep their current value. */
#define XSTATE_MASK_CONTEXT_LOADABLE \
    (XSTATE_MASK_AVX | \
     XSTATE_MASK_AVX512 | \
     (1ULL << (XSTATE_MPX_BNDREGS)))

#define TAG_XSTATE_CONTEXT 'cSXK'

/* The context functions save and load the user features with XSAVE and XRSTOR in the standard format, which
   every processor with XSAVE has. These are the offsets of that format (CPUID 0xD), whatever format the
   configuration in KUSER_SHARED_DATA describes, and the length of the area up to the last enabled user feature. */
static ULONG KiXStateStandardOffsets[MAXIMUM_XSTATE_FEATURES];
static ULONG KiXStateStandardLength;

/*!
 *   \brief Determines the extended state configuration for the current processor
 *
 *   \param XStateConfig - Pointer to a XSTATE_CONFIGURATION structure that receives the configuration
 *
 *   \see https://windows-internals.com/cet-on-windows/#3-xstate-configuration
 */
CODE_SEG("INIT")
static
VOID
KiGetXStateConfiguration(
    _Out_ PXSTATE_CONFIGURATION XStateConfig)
{
    ULONG64 SupportedUserMask;
    ULONG64 SupportedSupervisorMask;
    ULONG64 SupportedComponentMask;
    ULONG NextUserOffset, NextSupervisorOffset, NextOffset;

    RtlZeroMemory(XStateConfig, sizeof(*XStateConfig));

    /* Read CPUID_EXTENDED_STATE main leaf (0x0D, 0x00) */
    CPUID_EXTENDED_STATE_MAIN_LEAF_REGS ExtStateMain;
    __cpuidex(ExtStateMain.AsInt32,
              CPUID_EXTENDED_STATE,
              CPUID_EXTENDED_STATE_MAIN_LEAF);

    /* Get the supported XCR0 bits */
    SupportedUserMask = (ULONG64)ExtStateMain.Edx << 32 |
                        (ULONG64)ExtStateMain.Eax.Uint32;

    /* FIXME: Temporary workaround until we have dynamic kernel stack size */
    SupportedUserMask &= ~XSTATE_MASK_LARGE_FEATURES;

    /* Mask the allowed components */
    SupportedUserMask &= XSTATE_MASK_ALLOWED;

    /* Read CPUID_EXTENDED_STATE sub-leaf (0x0D, 0x01) */
    CPUID_EXTENDED_STATE_SUB_LEAF_REGS ExtStateSub;
    __cpuidex(ExtStateSub.AsInt32,
              CPUID_EXTENDED_STATE,
              CPUID_EXTENDED_STATE_SUB_LEAF);

    /* Save control flags */
    XStateConfig->OptimizedSave = ExtStateSub.Eax.Bits.XSAVEOPT;
    XStateConfig->CompactionEnabled = ExtStateSub.Eax.Bits.XSAVEC;
    XStateConfig->ExtendedFeatureDisable = ExtStateSub.Eax.Bits.Xfd;

    /* Determine supported supervisor features */
    SupportedSupervisorMask = 0;
    if (ExtStateSub.Eax.Bits.XSAVES)
    {
        SupportedSupervisorMask = (ULONG64)ExtStateSub.Edx << 32 |
                                  (ULONG64)ExtStateSub.Ecx.Uint32;
        SupportedSupervisorMask &= XSTATE_MASK_ALLOWED & XSTATE_MASK_SUPERVISOR;
    }

    /* Calculate full mask */
    SupportedComponentMask = SupportedUserMask | SupportedSupervisorMask;

    /* Basic features (always enabled) */
    XStateConfig->Features[XSTATE_LEGACY_FLOATING_POINT].Offset = 0;
    XStateConfig->Features[XSTATE_LEGACY_FLOATING_POINT].Size = FIELD_OFFSET(XSAVE_FORMAT, XmmRegisters);
    XStateConfig->AllFeatures[XSTATE_LEGACY_FLOATING_POINT] = FIELD_OFFSET(XSAVE_FORMAT, XmmRegisters);
    XStateConfig->Features[XSTATE_LEGACY_SSE].Offset = FIELD_OFFSET(XSAVE_FORMAT, XmmRegisters);
    XStateConfig->Features[XSTATE_LEGACY_SSE].Size = FIELD_SIZE(XSAVE_FORMAT, XmmRegisters);
    XStateConfig->AllFeatures[XSTATE_LEGACY_SSE] = FIELD_SIZE(XSAVE_FORMAT, XmmRegisters);

    /* Other components start after legacy state + header */
    NextUserOffset = NextSupervisorOffset = sizeof(XSAVE_AREA);

    /* Loop all components from 2 up */
    for (ULONG Component = 2; Component < MAXIMUM_XSTATE_FEATURES; Component++)
    {
        ULONG64 ComponentBit = (1ULL << Component);

        /* Query component features */
        CPUID_EXTENDED_STATE_SIZE_OFFSET_REGS ExtStateComponent;
        __cpuidex(ExtStateComponent.AsInt32,
                  CPUID_EXTENDED_STATE,
                  Component);

        /* Save size for all features */
        XStateConfig->AllFeatures[Component] = ExtStateComponent.Size;

        /* If the offset is 0, this component isn't valid */
        if (ExtStateComponent.Size == 0) continue;

        /* Check for components that are not OS supported */
        if ((ComponentBit & SupportedComponentMask) == 0)
        {
            /* This emulates weird (broken) Windows behavior */
            if ((ComponentBit & XSTATE_MASK_SUPERVISOR) == 0)
            {
                XStateConfig->Features[Component].Offset = ExtStateComponent.Offset;
                XStateConfig->Features[Component].Size = ExtStateComponent.Size;
            }

            /* Skip the rest */
            continue;
        }

        /* Check if compaction is enabled */
        if (XStateConfig->CompactionEnabled)
        {
            /* Align the offsets, if needed */
            if (ExtStateComponent.Ecx.Bits.Aligned)
            {
                XStateConfig->AlignedFeatures |= ComponentBit;
                NextSupervisorOffset = ALIGN_UP(NextSupervisorOffset, 64);
                if ((ComponentBit & SupportedUserMask) != 0)
                {
                    NextUserOffset = ALIGN_UP(NextUserOffset, 64);
                }
            }

            /* Update the supervisor offset */
            NextSupervisorOffset += ExtStateComponent.Size;

            /* For user components save and update the offset and size */
            if ((ComponentBit & SupportedUserMask) != 0)
            {
                XStateConfig->Features[Component].Offset = NextUserOffset;
                XStateConfig->Features[Component].Size = ExtStateComponent.Size;
                NextUserOffset += ExtStateComponent.Size;
            }
        }
        else
        {
            /* Not compacted, use the offset and size specified by the CPUID */
            NextOffset = ExtStateComponent.Offset + ExtStateComponent.Size;
            NextSupervisorOffset = max(NextSupervisorOffset, NextOffset);

            /* For user components save and update the offset and size */
            if ((ComponentBit & SupportedUserMask) != 0)
            {
                XStateConfig->Features[Component].Offset = ExtStateComponent.Offset;
                XStateConfig->Features[Component].Size = ExtStateComponent.Size;
                NextUserOffset = max(NextUserOffset, NextOffset);
            }
        }
    }

    /* Save the features to be enabled */
    XStateConfig->EnabledFeatures = SupportedUserMask;
    XStateConfig->EnabledVolatileFeatures =
        SupportedUserMask & ~XSTATE_MASK_PERSISTENT;
    XStateConfig->EnabledSupervisorFeatures = SupportedSupervisorMask;
    XStateConfig->EnabledUserVisibleSupervisorFeatures =
        SupportedSupervisorMask & XSTATE_MASK_USER_VISIBLE_SUPERVISOR;

    /* Save the calculated sizes */
    XStateConfig->Size = NextUserOffset;
    XStateConfig->AllFeatureSize = NextSupervisorOffset;
    ASSERT(XStateConfig->AllFeatureSize >= XStateConfig->Size);
}

/*!
 *   \brief Validates the provided extended state configuration against the global one
 *
 *   \param XStateConfig - Pointer to a XSTATE_CONFIGURATION structure containing the configuration
 */
CODE_SEG("INIT")
static
VOID
ValidateXStateConfig(
    _In_ PXSTATE_CONFIGURATION XState)
{
    PXSTATE_CONFIGURATION GlobalXState = &SharedUserData->XState;

    if ((XState->EnabledFeatures != GlobalXState->EnabledFeatures) ||
        (XState->EnabledSupervisorFeatures != GlobalXState->EnabledSupervisorFeatures) ||
        (XState->Size != GlobalXState->Size) ||
        (XState->AllFeatureSize != GlobalXState->AllFeatureSize))
    {
        /* Invalid features */
        KeBugCheck(MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED);
    }

    for (ULONG i = 0; i < MAXIMUM_XSTATE_FEATURES; i++)
    {
        if ((XState->Features[i].Size != GlobalXState->Features[i].Size) ||
            (XState->Features[i].Offset != GlobalXState->Features[i].Offset) ||
            (XState->AllFeatures[i] != GlobalXState->AllFeatures[i]))
        {
            /* Invalid features */
            KeBugCheck(MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED);
        }
    }
}

/*!
 *   \brief Records the standard format layout of the enabled user features for the context functions
 */
CODE_SEG("INIT")
static
VOID
KiInitializeXStateStandardLayout(
    _In_ ULONG64 EnabledFeatures)
{
    KiXStateStandardLength = sizeof(XSAVE_AREA);

    for (ULONG Component = 2; Component < MAXIMUM_XSTATE_FEATURES; Component++)
    {
        CPUID_EXTENDED_STATE_SIZE_OFFSET_REGS ExtStateComponent;

        if ((EnabledFeatures & (1ULL << Component)) == 0)
            continue;

        __cpuidex(ExtStateComponent.AsInt32, CPUID_EXTENDED_STATE, Component);
        KiXStateStandardOffsets[Component] = ExtStateComponent.Offset;
        KiXStateStandardLength = max(KiXStateStandardLength,
                                     ExtStateComponent.Offset + ExtStateComponent.Size);
    }
}

/*!
 *   \brief Initializes the extended state configuration for the current processor
 *
 *   \param ProcessorNumber - Number of the current processor
 */
CODE_SEG("INIT")
VOID
NTAPI
KiInitializeXStateConfiguration(
    _In_ ULONG ProcessorNumber)
{
    /* Check if XSAVE is supported */
    if ((KeFeatureBits & KF_XSTATE) == 0)
    {
        /* XSAVE is not supported */
        return;
    }

    if (ProcessorNumber == 0)
    {
        /* Processor 0: Retrieve the global configuration */
        KiGetXStateConfiguration(&SharedUserData->XState);

        if (SharedUserData->XState.AllFeatureSize == 0)
        {
            KeFeatureBits &= ~KF_XSTATE;
            return;
        }

        KeXStateLength = SharedUserData->XState.AllFeatureSize;
        KiInitializeXStateStandardLayout(SharedUserData->XState.EnabledFeatures);
    }
    else
    {
        /* Processor 1+: validate the configuration against the global one */
        XSTATE_CONFIGURATION XState;
        KiGetXStateConfiguration(&XState);
        ValidateXStateConfig(&XState);
    }

    /* Enable the user mode components in XCR0 */
    _xsetbv(0, SharedUserData->XState.EnabledFeatures);

    /* The context functions load features into the processor with XRSTOR, which faults on a feature that is not
       enabled in XCR0. Every processor has to have what the configuration says. */
    if ((_xgetbv(0) & SharedUserData->XState.EnabledFeatures) != SharedUserData->XState.EnabledFeatures)
    {
        KeBugCheck(MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED);
    }

    /* Now that we have set everything up, query CPUID again to get the required
       size based on components enabled in XCR0 */
    CPUID_EXTENDED_STATE_MAIN_LEAF_REGS ExtStateMain;
    __cpuidex(ExtStateMain.AsInt32,
              CPUID_EXTENDED_STATE,
              CPUID_EXTENDED_STATE_MAIN_LEAF);

    /* CPUID 0xD, leaf 0, EBX should return the size required by all components
       enabled in XCR0 and thus match our calculation. But VBox doesn't handle
       this correctly and simply returns the full size of all *supported*
       features, independent of XCR0. We check and warn. */
    if (ExtStateMain.Ebx > SharedUserData->XState.Size)
    {
        DPRINT1("Processor %lu, CPUID 0xD, leaf 0, EBX returns 0x%x, but we calculated 0x%lx\n",
                ProcessorNumber,
                ExtStateMain.Ebx,
                SharedUserData->XState.Size);
    }

    /* Check if we have any supervisor components enabled */
    if (SharedUserData->XState.EnabledSupervisorFeatures != 0)
    {
        /* Enable the supervisor components in IA32_XSS */
        __writemsr(MSR_IA32_XSS, SharedUserData->XState.EnabledSupervisorFeatures);

        /* Get the required size for features enabled in both XCR0 and IA32_XSS */
        CPUID_EXTENDED_STATE_SUB_LEAF_REGS ExtStateSubLeaf;
        __cpuidex(ExtStateSubLeaf.AsInt32,
                  CPUID_EXTENDED_STATE,
                  CPUID_EXTENDED_STATE_SUB_LEAF);

        /* Check if all components fit into what we calculated. Same VBox issue
           here as described above. */
        if (ExtStateSubLeaf.Ebx.XSaveAreaSize > SharedUserData->XState.AllFeatureSize)
        {
            DPRINT1("Processor %lu, CPUID 0xD, leaf 1, EBX returns 0x%x, but we calculated 0x%lx\n",
                    ProcessorNumber,
                    ExtStateMain.Ebx,
                    SharedUserData->XState.Size);

            /* The problem is likely the VM, but to be safe, we adjust the size */
            SharedUserData->XState.AllFeatureSize = ExtStateSubLeaf.Ebx.XSaveAreaSize;
        }
    }
}

/* CONTEXT_XSTATE *************************************************************/

/*
 * The extended state of a CONTEXT is described by the CONTEXT_EX that directly follows it. Its XState chunk holds
 * an XSAVE_AREA_HEADER followed by the features from 2 up (x87 and SSE are in the CONTEXT itself). In the standard
 * format a feature lives at XSTATE_CONFIGURATION.Features[n].Offset from the start of the whole XSAVE area, which is
 * sizeof(XSAVE_FORMAT) before the header. In the compacted format the features of the header's compaction mask follow
 * one another, and a feature that asks for it is aligned to 64 bytes: the same rule as ntdll's RtlLocateExtendedFeature.
 *
 * The chunk the caller describes is captured into kernel memory once: the description is read and checked a single
 * time and every later step uses the captured values, so neither its length nor its masks can change under the
 * kernel. Only the features that fit entirely inside the described length are transferred.
 */

static
ULONG
KiGetXStateContextOffset(
    _In_ const XSTATE_CONFIGURATION *Config,
    _In_ ULONG64 CompactionMask,
    _In_ ULONG Feature)
{
    ULONG Offset, Component;

    if (!Config->CompactionEnabled)
        return Config->Features[Feature].Offset - sizeof(XSAVE_FORMAT);

    Offset = sizeof(XSAVE_AREA_HEADER);
    for (Component = 2; Component < Feature; Component++)
    {
        if (CompactionMask & (1ULL << Component))
            Offset += Config->Features[Component].Size;
        if (Config->AlignedFeatures & (1ULL << (Component + 1)))
            Offset = ALIGN_UP_BY(Offset, XSAVE_ALIGN);
    }
    return Offset;
}

/*!
 *   \brief Keeps the features that fit into Length bytes of a chunk, returns the length they need
 */
static
ULONG
KiFitXStateContextFeatures(
    _Inout_ PULONG64 Features,
    _In_ ULONG Length)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    ULONG64 Fitting = 0;
    ULONG Needed = sizeof(XSAVE_AREA_HEADER);
    ULONG Feature, End;

    for (Feature = 2; Feature < MAXIMUM_XSTATE_FEATURES; Feature++)
    {
        if ((*Features & (1ULL << Feature)) == 0)
            continue;
        End = KiGetXStateContextOffset(Config, *Features, Feature) + Config->Features[Feature].Size;
        if (End > Length)
            continue;
        Fitting |= 1ULL << Feature;
        Needed = max(Needed, End);
    }

    *Features = Fitting;
    return Needed;
}

/* Every exception dispatched to user mode and every NtContinue of its context take one of these buffers, so they
   come from a lookaside list instead of the pool: with AVX-512 a buffer is larger than a page, which the pool
   allocates as whole pages under its locks. The list is set up at the first use, when the pool is ready; until it
   is (and for a buffer that would not fit, which the sizes below rule out) the pool is used. */
static NPAGED_LOOKASIDE_LIST KiXStateContextLookaside;
static ULONG KiXStateContextEntrySize;
static volatile LONG KiXStateContextLookasideState; /* 0 not set up, 1 being set up, 2 ready */

static
BOOLEAN
KiXStateContextLookasideReady(VOID)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    ULONG64 All;

    if (KiXStateContextLookasideState == 2)
        return TRUE;

    /* Another processor is setting it up: use the pool meanwhile */
    if (InterlockedCompareExchange(&KiXStateContextLookasideState, 1, 0) != 0)
        return FALSE;

    /* Room for the save area and the chunk of a context with every enabled feature, the largest one asked for */
    All = Config->EnabledFeatures & ~XSTATE_MASK_LEGACY;
    KiXStateContextEntrySize = XSAVE_ALIGN + ALIGN_UP_BY(KiXStateStandardLength, XSAVE_ALIGN) +
                               KiFitXStateContextFeatures(&All, MAXULONG);
    ExInitializeNPagedLookasideList(&KiXStateContextLookaside,
                                    NULL,
                                    NULL,
                                    0,
                                    KiXStateContextEntrySize,
                                    TAG_XSTATE_CONTEXT,
                                    0);
    InterlockedExchange(&KiXStateContextLookasideState, 2);
    return TRUE;
}

static
NTSTATUS
KiAllocateXStateContext(
    _Inout_ PKI_XSTATE_CONTEXT XState)
{
    ULONG SaveLength = ALIGN_UP_BY(KiXStateStandardLength, XSAVE_ALIGN);
    ULONG Size = XSAVE_ALIGN + SaveLength + XState->Length;
    PUCHAR Allocation;

    if (KiXStateContextLookasideReady() && (Size <= KiXStateContextEntrySize))
    {
        Allocation = ExAllocateFromNPagedLookasideList(&KiXStateContextLookaside);
        if (!Allocation)
            return STATUS_INSUFFICIENT_RESOURCES;

        /* Zeroed like the pool allocation below: XRSTOR needs the reserved bytes of the save area's header clear */
        RtlZeroMemory(Allocation, Size);
        XState->FromLookaside = TRUE;
    }
    else
    {
        Allocation = ExAllocatePoolZero(NonPagedPool, Size, TAG_XSTATE_CONTEXT);
        if (!Allocation)
            return STATUS_INSUFFICIENT_RESOURCES;
        XState->FromLookaside = FALSE;
    }

    XState->Allocation = Allocation;
    XState->Save = (PXSAVE_AREA)ALIGN_UP_POINTER_BY(Allocation, XSAVE_ALIGN);
    XState->Chunk = (PXSAVE_AREA_HEADER)((PUCHAR)XState->Save + SaveLength);
    return STATUS_SUCCESS;
}

/*!
 *   \brief Captures the extended state description of a caller's CONTEXT
 *
 *   \param Context - The caller's CONTEXT, with CONTEXT_XSTATE in its flags. The CONTEXT_EX follows it.
 *   \param PreviousMode - Mode of the caller; user mode buffers are probed
 *   \param ForGet - TRUE when the state will be written to the caller's chunk, FALSE when it is read from it
 *   \param XState - Receives the description and a kernel copy of the chunk; free it with KiFreeXStateContext
 *
 *   \return STATUS_NOT_SUPPORTED without extended state, STATUS_INVALID_PARAMETER for a chunk that cannot hold the
 *           header, or the status of the probe. Must be called at or below APC_LEVEL.
 */
NTSTATUS
NTAPI
KiCaptureXStateContext(
    _In_ PCONTEXT Context,
    _In_ KPROCESSOR_MODE PreviousMode,
    _In_ BOOLEAN ForGet,
    _Out_ PKI_XSTATE_CONTEXT XState)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    PCONTEXT_EX ContextEx;
    PXSAVE_AREA_HEADER Header;
    XSAVE_AREA_HEADER HeaderCopy;
    LONG ChunkOffset, LegacyOffset, AllOffset;
    ULONG ChunkLength, LegacyLength, AllLength;
    ULONG64 Features, All;
    ULONG MaxLength;
    NTSTATUS Status;

    RtlZeroMemory(XState, sizeof(*XState));

    Features = Config->EnabledFeatures & ~XSTATE_MASK_LEGACY;
    if (((KeFeatureBits & KF_XSTATE) == 0) || (Features == 0))
        return STATUS_NOT_SUPPORTED;

    All = Features;
    MaxLength = KiFitXStateContextFeatures(&All, MAXULONG);

    _SEH2_TRY
    {
        ContextEx = (PCONTEXT_EX)(Context + 1);
        if (PreviousMode != KernelMode)
            ProbeForRead(ContextEx, sizeof(*ContextEx), sizeof(ULONG));

        ChunkOffset = ContextEx->XState.Offset;
        ChunkLength = ContextEx->XState.Length;
        LegacyOffset = ContextEx->Legacy.Offset;
        LegacyLength = ContextEx->Legacy.Length;
        AllOffset = ContextEx->All.Offset;
        AllLength = ContextEx->All.Length;

        /* A CONTEXT whose flags kept CONTEXT_XSTATE without a real CONTEXT_EX behind it must not steer the reads:
           the legacy part and the whole area both start at the CONTEXT, which directly precedes the CONTEXT_EX,
           the legacy part is the CONTEXT and the whole area holds at least the CONTEXT and the CONTEXT_EX */
        if ((LegacyOffset != -(LONG)sizeof(CONTEXT)) ||
            (LegacyLength != sizeof(CONTEXT)) ||
            (AllOffset != -(LONG)sizeof(CONTEXT)) ||
            (AllLength < sizeof(CONTEXT) + sizeof(CONTEXT_EX)))
        {
            _SEH2_YIELD(return STATUS_INVALID_PARAMETER);
        }

        /* The chunk follows the CONTEXT_EX and holds at least the header. A chunk longer than the one of a context
           for every enabled feature (InitializeContext) is an invalid parameter, as on Windows */
        if ((ChunkOffset < (LONG)sizeof(CONTEXT_EX)) ||
            (ChunkLength < sizeof(XSAVE_AREA_HEADER)) ||
            (ChunkLength > MaxLength))
        {
            _SEH2_YIELD(return STATUS_INVALID_PARAMETER);
        }

        Header = (PXSAVE_AREA_HEADER)((PUCHAR)ContextEx + ChunkOffset);
        if (PreviousMode != KernelMode)
            ProbeForRead(Header, sizeof(*Header), sizeof(UCHAR));

        /* The header is read once: its masks come from this copy, here and when the chunk is copied below */
        RtlCopyMemory(&HeaderCopy, Header, sizeof(HeaderCopy));

        /* A compacted chunk has room for the features of its compaction mask */
        if (Config->CompactionEnabled)
            Features &= HeaderCopy.CompactionMask;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    /* The features the caller asks for, and those of them the chunk has room for. A get that asks for more than
       fits still reports what is in use (Mask, CompactionMask) and then fails with STATUS_BUFFER_OVERFLOW */
    XState->Requested = Features;
    XState->Length = KiFitXStateContextFeatures(&Features, ChunkLength);
    XState->Features = Features;
    XState->Overflow = (Features != XState->Requested);
    XState->UserHeader = Header;

    Status = KiAllocateXStateContext(XState);
    if (!NT_SUCCESS(Status))
        return Status;

    _SEH2_TRY
    {
        if (PreviousMode != KernelMode)
        {
            if (ForGet)
                ProbeForWrite(Header, XState->Length, sizeof(UCHAR));
            else
                ProbeForRead(Header, XState->Length, sizeof(UCHAR));
        }

        /* Only the masks of the copy are used, and only within the captured features */
        if (!ForGet)
        {
            RtlCopyMemory(XState->Chunk, Header, XState->Length);
            *XState->Chunk = HeaderCopy;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        KiFreeXStateContext(XState);
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    return STATUS_SUCCESS;
}

/*!
 *   \brief Prepares the extended state description for an exception dispatched to user mode: all enabled user
 *          features, in the format of the configuration
 *
 *   \return FALSE when there is no extended state or no memory for it; the exception goes without it then
 */
BOOLEAN
NTAPI
KiPrepareXStateDispatch(
    _Out_ PKI_XSTATE_CONTEXT XState)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    ULONG64 Features;

    RtlZeroMemory(XState, sizeof(*XState));

    Features = Config->EnabledFeatures & ~XSTATE_MASK_LEGACY;
    if (((KeFeatureBits & KF_XSTATE) == 0) || (Features == 0))
        return FALSE;

    XState->Length = KiFitXStateContextFeatures(&Features, MAXULONG);
    XState->Features = Features;
    XState->Requested = Features;
    return NT_SUCCESS(KiAllocateXStateContext(XState));
}

/*!
 *   \brief Copies the result of KiGetXStateContext back to the caller
 *
 *   Writes the masks of the header and the data of the features that are in use. The data of a feature in its
 *   initial configuration is not written: the caller's buffer keeps what it had, as on Windows.
 *
 *   \return STATUS_BUFFER_OVERFLOW when the chunk had no room for every feature asked for
 */
NTSTATUS
NTAPI
KiCopyOutXStateContext(
    _In_ PKI_XSTATE_CONTEXT XState)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    ULONG64 Present = XState->Chunk->Mask & XState->Features;
    ULONG Feature, Offset;

    _SEH2_TRY
    {
        XState->UserHeader->Mask = XState->Chunk->Mask;
        XState->UserHeader->CompactionMask = XState->Chunk->CompactionMask;

        for (Feature = 2; Feature < MAXIMUM_XSTATE_FEATURES; Feature++)
        {
            if ((Present & (1ULL << Feature)) == 0)
                continue;
            Offset = KiGetXStateContextOffset(Config, XState->Requested, Feature);
            RtlCopyMemory((PUCHAR)XState->UserHeader + Offset,
                          (PUCHAR)XState->Chunk + Offset,
                          Config->Features[Feature].Size);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return _SEH2_GetExceptionCode());
    }
    _SEH2_END;

    return XState->Overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
}

VOID
NTAPI
KiFreeXStateContext(
    _Inout_ PKI_XSTATE_CONTEXT XState)
{
    if (XState->Allocation)
    {
        if (XState->FromLookaside)
            ExFreeToNPagedLookasideList(&KiXStateContextLookaside, XState->Allocation);
        else
            ExFreePoolWithTag(XState->Allocation, TAG_XSTATE_CONTEXT);
    }
    XState->Allocation = NULL;
    XState->Save = NULL;
    XState->Chunk = NULL;
}

/*!
 *   \brief Stores the current thread's extended state into the captured chunk
 *
 *   The kernel does not use the extended registers, so they hold the user mode values of the current thread.
 *   The header of the chunk tells which features are not in their initial configuration, like the processor's
 *   XSTATE_BV: the data of the others is zero.
 */
VOID
NTAPI
KiGetXStateContext(
    _Inout_ PKI_XSTATE_CONTEXT XState)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    ULONG64 InUse;
    ULONG Feature;
    KIRQL OldIrql;

    RtlZeroMemory(XState->Chunk, XState->Length);
    XState->Chunk->CompactionMask = Config->CompactionEnabled ?
        (XSTATE_COMPACTION_ENABLE_MASK | XState->Requested) : 0;
    if (XState->Requested == 0)
        return;

    /* No context switch while the state is saved */
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    XState->Save->Header.Mask = 0;
    _xsave64(XState->Save, XState->Requested);
    KeLowerIrql(OldIrql);

    /* The mask tells what is in use of everything asked for, the data is kept for what there is room for */
    InUse = XState->Save->Header.Mask & XState->Requested;
    XState->Chunk->Mask = InUse;
    InUse &= XState->Features;
    for (Feature = 2; Feature < MAXIMUM_XSTATE_FEATURES; Feature++)
    {
        if ((InUse & (1ULL << Feature)) == 0)
            continue;
        RtlCopyMemory((PUCHAR)XState->Chunk + KiGetXStateContextOffset(Config, XState->Requested, Feature),
                      (PUCHAR)XState->Save + KiXStateStandardOffsets[Feature],
                      Config->Features[Feature].Size);
    }
}

/*!
 *   \brief Loads the captured chunk into the current thread's extended state
 *
 *   The features of the chunk whose bit is clear in the header's mask go to their initial configuration, as XRSTOR
 *   does. Features that are not loadable keep their value.
 */
VOID
NTAPI
KiSetXStateContext(
    _In_ PKI_XSTATE_CONTEXT XState)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    ULONG64 Load, Present;
    ULONG Feature;
    KIRQL OldIrql;

    /* Never ask for a feature this processor has not enabled in XCR0: XRSTOR would fault in the kernel */
    Load = XState->Features & XSTATE_MASK_CONTEXT_LOADABLE & _xgetbv(0);
    if (Load == 0)
        return;
    Present = XState->Chunk->Mask & Load;

    /* No context switch between the save and the load */
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);

    /* Save first: the load takes MXCSR from the area too, it has to stay */
    _xsave64(XState->Save, Load);
    XState->Save->Header.Mask = Present;
    XState->Save->Header.CompactionMask = 0;
    RtlZeroMemory(XState->Save->Header.Reserved2, sizeof(XState->Save->Header.Reserved2));

    for (Feature = 2; Feature < MAXIMUM_XSTATE_FEATURES; Feature++)
    {
        if ((Present & (1ULL << Feature)) == 0)
            continue;
        RtlCopyMemory((PUCHAR)XState->Save + KiXStateStandardOffsets[Feature],
                      (PUCHAR)XState->Chunk + KiGetXStateContextOffset(Config, XState->Features, Feature),
                      Config->Features[Feature].Size);
    }

    _xrstor64(XState->Save, Load);
    KeLowerIrql(OldIrql);
}
