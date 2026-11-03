/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Extended (XSTATE) context primitives of Windows 7 and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The layout of a context with extended state follows Windows and Wine's ntdll (exception.c):
 *
 *     [CONTEXT][XCONTEXT_EX][pad to 64][XSAVE_AREA_HEADER][extended features]
 *
 * The XCONTEXT_EX directly follows the CONTEXT. Its chunk offsets are relative to the XCONTEXT_EX: Legacy points back
 * to the CONTEXT, XState points to the XSAVE_AREA_HEADER, which is 64 byte aligned. The x87 and SSE state (features 0
 * and 1) stays in the CONTEXT, so the XState chunk holds the header and the features from 2 up: in the standard
 * XSAVE format a feature lives at XSTATE_CONFIGURATION.Features[n].Offset from the start of the whole area, which is
 * 512 bytes before the header; in the compacted format the features of the compaction mask follow one another.
 * The configuration comes from KUSER_SHARED_DATA. A kernel that publishes none (i386 today) enables no feature: the
 * functions then answer STATUS_NOT_SUPPORTED for CONTEXT_XSTATE, as Windows does on a processor without XSAVE.
 * The behaviour is ported from Wine's ntdll/exception.c, including the copy range tables and the compacted offsets.
 */

#include <ntdll.h>

#define NDEBUG
#include <debug.h>

#if defined(_M_IX86) || defined(_M_AMD64)

#include <reactos/xcontext.h>

#define XCTX_XSTATE_FLAG        0x40UL
#define XCTX_XSAVE_LEGACY_SIZE  512UL   /* sizeof(XSAVE_FORMAT): the area before the XSAVE_AREA_HEADER */
#define XCTX_XSAVE_ALIGNMENT    64UL
#define XCTX_COMPACTED          0x8000000000000000ULL
#define XCTX_EX_SIZE            24UL    /* sizeof(XCONTEXT_EX) */

typedef struct _XCTX_RANGE
{
    ULONG Start;
    ULONG Flag;
} XCTX_RANGE;

/*
 * Each entry covers the bytes up to the next one and is copied when its flag is requested; the last entry stands at
 * the size of the CONTEXT. Same tables as Wine's: the amd64 floating point copy stops at 0x2a0 (the x87 and XMM state,
 * not the reserved tail of the FXSAVE area), the debug copy takes the last branch records, and the i386 extended
 * registers copy stops after the XMM registers.
 */
static const XCTX_RANGE XctxRangesAmd64[] =
{
    {0x38, 0x1}, {0x3a, 0x4}, {0x42, 0x1}, {0x48, 0x10}, {0x78, 0x2}, {0x98, 0x1},
    {0xa0, 0x2}, {0xf8, 0x1}, {0x100, 0x8}, {0x2a0, 0}, {0x4b0, 0x10}, {0x4d0, 0}
};

static const XCTX_RANGE XctxRangesI386[] =
{
    {0x4, 0x10}, {0x1c, 0x8}, {0x8c, 0x4}, {0x9c, 0x2}, {0xb4, 0x1}, {0xcc, 0x20}, {0x1ec, 0}, {0x2cc, 0}
};

#if defined(_M_AMD64)
C_ASSERT(sizeof(CONTEXT) == 0x4d0);
#else
C_ASSERT(sizeof(CONTEXT) == 0x2cc);
#endif

typedef struct _XCTX_PARAMETERS
{
    ULONG ArchFlag;
    ULONG SupportedFlags;
    ULONG ContextSize;      /* sizeof(CONTEXT) of the architecture */
    ULONG LegacySize;       /* the legacy chunk without the extended registers */
    ULONG Alignment;        /* of the CONTEXT in the buffer, minus one */
    ULONG ExLength;         /* what Windows counts for the CONTEXT_EX when it sizes a buffer with extended state */
    ULONG FlagsOffset;
    const XCTX_RANGE *Ranges;
} XCTX_PARAMETERS;

/* Both architectures are known so that a WOW64 context can be handled by the 64 bit functions */
static const XCTX_PARAMETERS XctxParameters[] =
{
    { 0x100000UL, 0xd8000000UL | 0x100000UL | 0x1fUL | 0x40UL, 0x4d0, 0x4d0, 15, 0x20, 0x30, XctxRangesAmd64 },
    { 0x10000UL,  0xd8000000UL | 0x10000UL  | 0x3fUL | 0x40UL, 0x2cc, 0xcc,  3,  0x18, 0,    XctxRangesI386 },
};

static
const XCTX_PARAMETERS *
RtlpXctxParameters(
    _In_ ULONG ContextFlags)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(XctxParameters); i++)
    {
        if (ContextFlags & XctxParameters[i].ArchFlag)
            return (ContextFlags & ~XctxParameters[i].SupportedFlags) ? NULL : &XctxParameters[i];
    }
    return NULL;
}

/* Offset counts from the header. The feature is added when the mask has it, then the next one is aligned if it asks */
static
ULONG
RtlpXctxNextCompacted(
    _In_ const XSTATE_CONFIGURATION *Config,
    _In_ ULONG Offset,
    _In_ ULONG64 CompactionMask,
    _In_ ULONG Feature)
{
    ULONG64 Bit = 1ULL << Feature;

    if (CompactionMask & Bit)
        Offset += Config->Features[Feature].Size;
    if (Config->AlignedFeatures & (Bit << 1))
        Offset = ALIGN_UP_BY(Offset, XCTX_XSAVE_ALIGNMENT);
    return Offset;
}

/* Includes the header, not the legacy area */
static
ULONG
RtlpXctxCompactedSize(
    _In_ const XSTATE_CONFIGURATION *Config,
    _In_ ULONG64 Mask)
{
    ULONG64 CompactionMask = XCTX_COMPACTED | Mask;
    ULONG Offset = sizeof(XSAVE_AREA_HEADER), Feature = 2;

    Mask >>= 2;
    while (Mask)
    {
        if (Mask == 1)
            return Offset + Config->Features[Feature].Size;
        Offset = RtlpXctxNextCompacted(Config, Offset, CompactionMask, Feature);
        Mask >>= 1;
        Feature++;
    }
    return Offset;
}

/* Standard format: up to the end of the highest feature of the mask */
static
ULONG
RtlpXctxStandardSize(
    _In_ const XSTATE_CONFIGURATION *Config,
    _In_ ULONG64 Mask)
{
    ULONG Feature = 2;

    Mask >>= 2;
    if (!Mask)
        return sizeof(XSAVE_AREA_HEADER);
    while (Mask != 1)
    {
        Mask >>= 1;
        Feature++;
    }
    return Config->Features[Feature].Offset + Config->Features[Feature].Size - XCTX_XSAVE_LEGACY_SIZE;
}

static
ULONG
RtlpXctxChunkLength(
    _In_ const XSTATE_CONFIGURATION *Config,
    _In_ ULONG64 CompactionMask)
{
    if (Config->CompactionEnabled)
        return RtlpXctxCompactedSize(Config, CompactionMask);
    if (CompactionMask & ~XSTATE_MASK_LEGACY)
        return RtlpXctxStandardSize(Config, CompactionMask);
    return sizeof(XSAVE_AREA_HEADER);
}

ULONG64
NTAPI
RtlGetEnabledExtendedFeatures(
    _In_ ULONG64 FeatureMask)
{
    return SharedUserData->XState.EnabledFeatures & FeatureMask;
}

NTSTATUS
NTAPI
RtlGetExtendedContextLength2(
    _In_ ULONG ContextFlags,
    _Out_ PULONG ContextLength,
    _In_ ULONG64 CompactionMask)
{
    const XCTX_PARAMETERS *Parameters;
    ULONG64 Supported, Length;

    if (!ContextLength || !(Parameters = RtlpXctxParameters(ContextFlags)))
        return STATUS_INVALID_PARAMETER;

    /* The CONTEXT is aligned inside of the buffer, and the header inside of what follows it */
    Length = Parameters->ContextSize + XCTX_EX_SIZE + Parameters->Alignment;
    if (ContextFlags & XCTX_XSTATE_FLAG)
    {
        Supported = RtlGetEnabledExtendedFeatures(~0ULL);
        if (!Supported)
            return STATUS_NOT_SUPPORTED;

        CompactionMask &= Supported & ~XSTATE_MASK_LEGACY;
        /* The header is aligned to 64 inside of the buffer. Windows counts the CONTEXT_EX the way its structure
           has it (8 bytes more than the chunks on amd64) and no alignment of the CONTEXT: with the 64 byte
           alignment of the header that holds the worst case of both */
        Length = Parameters->ContextSize + Parameters->ExLength + (XCTX_XSAVE_ALIGNMENT - 1) +
                 RtlpXctxChunkLength(&SharedUserData->XState, CompactionMask);
    }

    *ContextLength = (ULONG)Length;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlGetExtendedContextLength(
    _In_ ULONG ContextFlags,
    _Out_ PULONG ContextLength)
{
    return RtlGetExtendedContextLength2(ContextFlags, ContextLength, ~0ULL);
}

/*
 * The buffer has to hold at least what RtlGetExtendedContextLength2 says for the same flags and mask. On success
 * *ContextEx is the XCONTEXT_EX; the CONTEXT is at ContextEx + ContextEx->Legacy.Offset.
 */
NTSTATUS
NTAPI
RtlInitializeExtendedContext2(
    _Out_ PVOID Buffer,
    _In_ ULONG ContextFlags,
    _Out_ PXCONTEXT_EX *ContextEx,
    _In_ ULONG64 CompactionMask)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    const XCTX_PARAMETERS *Parameters;
    ULONG64 Supported = 0;
    PUCHAR Context;
    PXCONTEXT_EX Ex;

    if (!Buffer || !ContextEx || !(Parameters = RtlpXctxParameters(ContextFlags)))
        return STATUS_INVALID_PARAMETER;

    if ((ContextFlags & XCTX_XSTATE_FLAG) && !(Supported = RtlGetEnabledExtendedFeatures(~0ULL)))
        return STATUS_NOT_SUPPORTED;

    Context = (PUCHAR)(((ULONG_PTR)Buffer + Parameters->Alignment) & ~(ULONG_PTR)Parameters->Alignment);
    Ex = (PXCONTEXT_EX)(Context + Parameters->ContextSize);

    /* Only the flags and the CONTEXT_EX are written; the rest of the CONTEXT is the caller's, as on Windows */
    *(PULONG)(Context + Parameters->FlagsOffset) = ContextFlags;

    Ex->Legacy.Offset = Ex->All.Offset = -(LONG)Parameters->ContextSize;
    Ex->Legacy.Length = (ContextFlags & 0x20) ? Parameters->ContextSize : Parameters->LegacySize;

    if (ContextFlags & XCTX_XSTATE_FLAG)
    {
        PXSAVE_AREA_HEADER Header = (PXSAVE_AREA_HEADER)(((ULONG_PTR)(Ex + 1) + 63) & ~(ULONG_PTR)63);

        CompactionMask &= Supported;
        Ex->XState.Offset = (LONG)((PUCHAR)Header - (PUCHAR)Ex);
        Ex->XState.Length = RtlpXctxChunkLength(Config, CompactionMask & ~XSTATE_MASK_LEGACY);

        RtlZeroMemory(Header, sizeof(*Header));
        if (Config->CompactionEnabled)
            Header->CompactionMask = XCTX_COMPACTED | CompactionMask;

        Ex->All.Length = Parameters->ContextSize + Ex->XState.Offset + Ex->XState.Length;
    }
    else
    {
        /* The values Windows leaves for a context without extended state */
        Ex->XState.Offset = 25;
        Ex->XState.Length = 0;
        Ex->All.Length = Parameters->ContextSize + XCTX_EX_SIZE;
    }

    *ContextEx = Ex;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlInitializeExtendedContext(
    _Out_ PVOID Buffer,
    _In_ ULONG ContextFlags,
    _Out_ PXCONTEXT_EX *ContextEx)
{
    return RtlInitializeExtendedContext2(Buffer, ContextFlags, ContextEx, ~0ULL);
}

static
PXSAVE_AREA_HEADER
RtlpXctxHeader(
    _In_ PXCONTEXT_EX ContextEx)
{
    if (!ContextEx || ContextEx->XState.Offset <= 0 || ContextEx->XState.Length < sizeof(XSAVE_AREA_HEADER))
        return NULL;
    return (PXSAVE_AREA_HEADER)((PUCHAR)ContextEx + ContextEx->XState.Offset);
}

/* Features 0 and 1 are the legacy x87 and SSE state in the CONTEXT itself, not in the XState chunk: NULL for them */
PVOID
NTAPI
RtlLocateExtendedFeature2(
    _In_ PXCONTEXT_EX ContextEx,
    _In_ ULONG FeatureId,
    _In_ PXSTATE_CONFIGURATION XStateConfig,
    _Out_opt_ PULONG Length)
{
    PXSAVE_AREA_HEADER Header = RtlpXctxHeader(ContextEx);
    ULONG64 Bit, Offset;
    ULONG Feature;

    if (!Header || !XStateConfig || FeatureId < 2 || FeatureId >= MAXIMUM_XSTATE_FEATURES)
        return NULL;

    Bit = 1ULL << FeatureId;
    if (!(Bit & XStateConfig->EnabledFeatures))
        return NULL;

    /* The size of an enabled feature is answered even when this context has no room for it */
    if (Length)
        *Length = XStateConfig->Features[FeatureId].Size;

    if (XStateConfig->CompactionEnabled)
    {
        if (!(Header->CompactionMask & Bit))
            return NULL;
        Offset = sizeof(XSAVE_AREA_HEADER);
        for (Feature = 2; Feature < FeatureId; Feature++)
            Offset = RtlpXctxNextCompacted(XStateConfig, (ULONG)Offset, Header->CompactionMask, Feature);
    }
    else
    {
        Offset = XStateConfig->Features[FeatureId].Offset;
        if (Offset < XCTX_XSAVE_LEGACY_SIZE + sizeof(XSAVE_AREA_HEADER))
            return NULL;
        Offset -= XCTX_XSAVE_LEGACY_SIZE;
    }

    /* The feature has to be inside of the chunk */
    if (XStateConfig->Features[FeatureId].Size == 0 ||
        Offset + XStateConfig->Features[FeatureId].Size > ContextEx->XState.Length)
        return NULL;

    return (PUCHAR)Header + Offset;
}

PVOID
NTAPI
RtlLocateExtendedFeature(
    _In_ PXCONTEXT_EX ContextEx,
    _In_ ULONG FeatureId,
    _Out_opt_ PULONG Length)
{
    return RtlLocateExtendedFeature2(ContextEx, FeatureId, &SharedUserData->XState, Length);
}

PVOID
NTAPI
RtlLocateLegacyContext(
    _In_ PXCONTEXT_EX ContextEx,
    _Out_opt_ PULONG Length)
{
    if (Length)
        *Length = ContextEx->Legacy.Length;
    return (PUCHAR)ContextEx + ContextEx->Legacy.Offset;
}

/* Only enabled features are stored, and the two legacy bits not at all: the flags of the CONTEXT carry them */
VOID
NTAPI
RtlSetExtendedFeaturesMask(
    _In_ PXCONTEXT_EX ContextEx,
    _In_ ULONG64 FeatureMask)
{
    PXSAVE_AREA_HEADER Header = RtlpXctxHeader(ContextEx);

    if (Header)
        Header->Mask = RtlGetEnabledExtendedFeatures(FeatureMask) & ~XSTATE_MASK_LEGACY;
}

ULONG64
NTAPI
RtlGetExtendedFeaturesMask(
    _In_ PXCONTEXT_EX ContextEx)
{
    PXSAVE_AREA_HEADER Header = RtlpXctxHeader(ContextEx);

    return Header ? (Header->Mask & ~XSTATE_MASK_LEGACY) : 0;
}

static
VOID
RtlpXctxCopyRanges(
    _In_ PUCHAR Destination,
    _In_ ULONG ContextFlags,
    _In_ PUCHAR Source,
    _In_ const XCTX_PARAMETERS *Parameters)
{
    const XCTX_RANGE *Range = Parameters->Ranges;
    ULONG Start = 0;

    *(PULONG)(Destination + Parameters->FlagsOffset) |= ContextFlags;

    do
    {
        if (Range->Flag & ContextFlags)
        {
            if (!Start)
                Start = Range->Start;
        }
        else if (Start)
        {
            RtlCopyMemory(Destination + Start, Source + Start, Range->Start - Start);
            Start = 0;
        }
    }
    while (Range++->Start != Parameters->ContextSize);
}

/*
 * Copies what ContextFlags selects and both contexts have. The flags the source lacks are left out, and are not
 * added to the destination. A destination without the XSTATE bit cannot take extended state.
 */
NTSTATUS
NTAPI
RtlCopyContext(
    _Inout_ PCONTEXT Destination,
    _In_ ULONG ContextFlags,
    _In_ PCONTEXT Source)
{
    const XCTX_PARAMETERS *Parameters;
    ULONG ArchFlag, DestinationFlags, SourceFlags, i;
    PUCHAR D = (PUCHAR)Destination, S = (PUCHAR)Source;

    if (!Destination || !Source)
        return STATUS_INVALID_PARAMETER;

    if ((ContextFlags & XCTX_XSTATE_FLAG) && !RtlGetEnabledExtendedFeatures(~0ULL))
        return STATUS_NOT_SUPPORTED;

    ArchFlag = 0;
    for (i = 0; i < RTL_NUMBER_OF(XctxParameters); i++)
    {
        if ((ContextFlags & (0x100000UL | 0x10000UL)) == XctxParameters[i].ArchFlag)
            ArchFlag = XctxParameters[i].ArchFlag;
    }
    if (!ArchFlag)
        return STATUS_INVALID_PARAMETER;
    Parameters = (ArchFlag == XctxParameters[0].ArchFlag) ? &XctxParameters[0] : &XctxParameters[1];

    DestinationFlags = *(PULONG)(D + Parameters->FlagsOffset);
    SourceFlags = *(PULONG)(S + Parameters->FlagsOffset);
    if ((DestinationFlags & (0x100000UL | 0x10000UL)) != ArchFlag || (SourceFlags & (0x100000UL | 0x10000UL)) != ArchFlag)
        return STATUS_INVALID_PARAMETER;

    ContextFlags &= SourceFlags;
    if ((ContextFlags & ~DestinationFlags) & XCTX_XSTATE_FLAG)
        return STATUS_BUFFER_OVERFLOW;

    if (ContextFlags & XCTX_XSTATE_FLAG)
        return RtlCopyExtendedContext((PXCONTEXT_EX)(D + Parameters->ContextSize),
                                      ContextFlags,
                                      (PXCONTEXT_EX)(S + Parameters->ContextSize));

    if (!(Parameters = RtlpXctxParameters(ContextFlags)))
        return STATUS_INVALID_PARAMETER;

    RtlpXctxCopyRanges(D, ContextFlags, S, Parameters);
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
RtlCopyExtendedContext(
    _Inout_ PXCONTEXT_EX Destination,
    _In_ ULONG ContextFlags,
    _In_ PXCONTEXT_EX Source)
{
    const XSTATE_CONFIGURATION *Config = &SharedUserData->XState;
    const XCTX_PARAMETERS *Parameters;
    PXSAVE_AREA_HEADER DestinationHeader, SourceHeader;
    ULONG64 Enabled, Features;
    ULONG Feature, Offset, Size;

    if (!Destination || !Source || !(Parameters = RtlpXctxParameters(ContextFlags)))
        return STATUS_INVALID_PARAMETER;

    Enabled = RtlGetEnabledExtendedFeatures(~0ULL);
    if (!Enabled && (ContextFlags & XCTX_XSTATE_FLAG))
        return STATUS_NOT_SUPPORTED;

    RtlpXctxCopyRanges(RtlLocateLegacyContext(Destination, NULL), ContextFlags,
                       RtlLocateLegacyContext(Source, NULL), Parameters);

    if (!(ContextFlags & XCTX_XSTATE_FLAG))
        return STATUS_SUCCESS;

    DestinationHeader = RtlpXctxHeader(Destination);
    if (!DestinationHeader)
        return STATUS_BUFFER_OVERFLOW;
    SourceHeader = RtlpXctxHeader(Source);
    if (!SourceHeader)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(DestinationHeader, sizeof(*DestinationHeader));
    DestinationHeader->Mask = (SourceHeader->Mask & ~XSTATE_MASK_LEGACY) & Enabled;
    DestinationHeader->CompactionMask = Config->CompactionEnabled ?
        (XCTX_COMPACTED | (SourceHeader->CompactionMask & Enabled)) : 0;
    Features = DestinationHeader->Mask >> 2;

    Feature = 2;
    Offset = sizeof(XSAVE_AREA_HEADER);
    while (Features)
    {
        if (Features & 1)
        {
            if (!DestinationHeader->CompactionMask)
                Offset = Config->Features[Feature].Offset - XCTX_XSAVE_LEGACY_SIZE;
            Size = Config->Features[Feature].Size;
            if (Source->XState.Length < Offset + Size || Destination->XState.Length < Offset + Size)
                break;
            RtlCopyMemory((PUCHAR)DestinationHeader + Offset, (PUCHAR)SourceHeader + Offset, Size);
        }
        if (!(Features >>= 1))
            break;
        if (DestinationHeader->CompactionMask)
            Offset = RtlpXctxNextCompacted(Config, Offset, DestinationHeader->CompactionMask, Feature);
        Feature++;
    }
    return STATUS_SUCCESS;
}

#endif /* _M_IX86 || _M_AMD64 */
