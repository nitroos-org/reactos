/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS NT User-Mode Library
 * FILE:            dll/ntdll/ldr/ldrinit.c
 * PURPOSE:         User-Mode Process/Thread Startup
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 *                  Aleksey Bragin (aleksey@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntdll.h>
#include <compat_undoc.h>
#include <compatguid_undoc.h>

#define NDEBUG
#include <debug.h>


/* GLOBALS *******************************************************************/

HANDLE ImageExecOptionsKey;
HANDLE Wow64ExecOptionsKey;
UNICODE_STRING ImageExecOptionsString = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");
UNICODE_STRING Wow64OptionsString = RTL_CONSTANT_STRING(L"");
UNICODE_STRING NtDllString = RTL_CONSTANT_STRING(L"ntdll.dll");
UNICODE_STRING Kernel32String = RTL_CONSTANT_STRING(L"kernel32.dll");
const UNICODE_STRING LdrpDotLocal = RTL_CONSTANT_STRING(L".Local");

BOOLEAN LdrpInLdrInit;
LONG LdrpProcessInitialized;
BOOLEAN LdrpLoaderLockInit;
BOOLEAN LdrpLdrDatabaseIsSetup;
BOOLEAN LdrpShutdownInProgress;
HANDLE LdrpShutdownThreadId;

BOOLEAN LdrpDllValidation;

PLDR_DATA_TABLE_ENTRY LdrpImageEntry;
PUNICODE_STRING LdrpTopLevelDllBeingLoaded;
WCHAR StringBuffer[156];
extern PTEB LdrpTopLevelDllBeingLoadedTeb; // defined in rtlsupp.c!
PLDR_DATA_TABLE_ENTRY LdrpCurrentDllInitializer;
PLDR_DATA_TABLE_ENTRY LdrpNtDllDataTableEntry;

static NTSTATUS (WINAPI *Kernel32ProcessInitPostImportFunction)(VOID);
static BOOL (WINAPI *Kernel32BaseQueryModuleData)(IN LPSTR ModuleName, IN LPSTR Unk1, IN PVOID Unk2, IN PVOID Unk3, IN PVOID Unk4);

RTL_BITMAP TlsBitMap;
RTL_BITMAP TlsExpansionBitMap;
RTL_BITMAP FlsBitMap;
BOOLEAN LdrpImageHasTls;
#ifdef BUILD_WOW64_ENABLED
static BOOLEAN LdrpIsWow64;
#endif
LIST_ENTRY LdrpTlsList;
ULONG LdrpNumberOfTlsEntries;
ULONG LdrpNumberOfProcessors;
PVOID NtDllBase;
extern LARGE_INTEGER RtlpTimeout;
extern BOOLEAN RtlpTimeoutDisable;
LIST_ENTRY LdrpHashTable[LDR_HASH_TABLE_ENTRIES];
HANDLE LdrpKnownDllObjectDirectory;
UNICODE_STRING LdrpKnownDllPath;
WCHAR LdrpKnownDllPathBuffer[128];
UNICODE_STRING LdrpDefaultPath;

PEB_LDR_DATA PebLdr;

RTL_CRITICAL_SECTION_DEBUG LdrpLoaderLockDebug;
RTL_CRITICAL_SECTION LdrpLoaderLock =
{
    &LdrpLoaderLockDebug,
    -1,
    0,
    0,
    0,
    0
};
RTL_CRITICAL_SECTION FastPebLock;

BOOLEAN ShowSnaps;

ULONG LdrpFatalHardErrorCount;
ULONG LdrpActiveUnloadCount;

//extern LIST_ENTRY RtlCriticalSectionList;

VOID NTAPI RtlpInitializeVectoredExceptionHandling(VOID);
VOID NTAPI RtlpInitDeferredCriticalSection(VOID);
VOID NTAPI RtlInitializeHeapManager(VOID);
NTSTATUS NTAPI RtlpInitializeLocaleTable(VOID);

ULONG RtlpDisableHeapLookaside; // TODO: Move to heap.c
ULONG RtlpShutdownProcessFlags; // TODO: Use it

NTSTATUS LdrPerformRelocations(PIMAGE_NT_HEADERS NTHeaders, PVOID ImageBase);
NTSTATUS NTAPI RtlpInitializeActCtx(PVOID* pOldShimData);
extern BOOLEAN RtlpUse16ByteSLists;

#ifdef _M_AMD64
extern ULONG NTAPI RtlGetCurrentDirectory_U_RtlpMsysDecoy(ULONG MaximumLength, PWSTR Buffer);
#endif

#ifdef _WIN64
#define DEFAULT_SECURITY_COOKIE 0x00002B992DDFA232ll
#else
#define DEFAULT_SECURITY_COOKIE 0xBB40E64E
#endif

/* FUNCTIONS *****************************************************************/

static NTSTATUS LdrpGetTlsDirectory(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry, _Out_ PIMAGE_TLS_DIRECTORY *TlsDirectory);

/*
 * @implemented
 */
NTSTATUS
NTAPI
LdrOpenImageFileOptionsKey(
    _In_ PUNICODE_STRING SubKey,
    _In_ BOOLEAN Wow64,
    _Out_ PHANDLE NewKeyHandle)
{
    PHANDLE RootKeyLocation;
    HANDLE RootKey;
    UNICODE_STRING SubKeyString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    PWCHAR p1;

    /* Check which root key to open */
    if (Wow64)
        RootKeyLocation = &Wow64ExecOptionsKey;
    else
        RootKeyLocation = &ImageExecOptionsKey;

    /* Get the current key */
    RootKey = *RootKeyLocation;

    /* Setup the object attributes */
    InitializeObjectAttributes(&ObjectAttributes,
                               Wow64 ?
                               &Wow64OptionsString : &ImageExecOptionsString,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    /* Open the root key */
    Status = ZwOpenKey(&RootKey, KEY_ENUMERATE_SUB_KEYS, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        /* Write the key handle */
        if (InterlockedCompareExchangePointer(RootKeyLocation, RootKey, NULL) != NULL)
        {
            /* Someone already opened it, use it instead */
            NtClose(RootKey);
            RootKey = *RootKeyLocation;
        }

        /* Extract the name */
        SubKeyString = *SubKey;
        p1 = (PWCHAR)((ULONG_PTR)SubKeyString.Buffer + SubKeyString.Length);
        while (SubKeyString.Length)
        {
            if (p1[-1] == L'\\') break;
            p1--;
            SubKeyString.Length -= sizeof(*p1);
        }
        SubKeyString.Buffer = p1;
        SubKeyString.Length = SubKey->Length - SubKeyString.Length;

        /* Setup the object attributes */
        InitializeObjectAttributes(&ObjectAttributes,
                                   &SubKeyString,
                                   OBJ_CASE_INSENSITIVE,
                                   RootKey,
                                   NULL);

        /* Open the setting key */
        Status = ZwOpenKey((PHANDLE)NewKeyHandle, GENERIC_READ, &ObjectAttributes);
    }

    /* Return to caller */
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
LdrQueryImageFileKeyOption(
    _In_ HANDLE KeyHandle,
    _In_ PCWSTR ValueName,
    _In_ ULONG Type,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ReturnedLength)
{
    ULONG KeyInfo[256];
    UNICODE_STRING ValueNameString, IntegerString;
    ULONG KeyInfoSize, ResultSize;
    PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation = (PKEY_VALUE_PARTIAL_INFORMATION)&KeyInfo;
    BOOLEAN FreeHeap = FALSE;
    NTSTATUS Status;

    /* Build a string for the value name */
    Status = RtlInitUnicodeStringEx(&ValueNameString, ValueName);
    if (!NT_SUCCESS(Status)) return Status;

    /* Query the value */
    Status = ZwQueryValueKey(KeyHandle,
                             &ValueNameString,
                             KeyValuePartialInformation,
                             KeyValueInformation,
                             sizeof(KeyInfo),
                             &ResultSize);
    if (Status == STATUS_BUFFER_OVERFLOW)
    {
        /* Our local buffer wasn't enough, allocate one */
        KeyInfoSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                      KeyValueInformation->DataLength;
        KeyValueInformation = RtlAllocateHeap(RtlGetProcessHeap(),
                                              0,
                                              KeyInfoSize);
        if (KeyValueInformation != NULL)
        {
            /* Try again */
            Status = ZwQueryValueKey(KeyHandle,
                                     &ValueNameString,
                                     KeyValuePartialInformation,
                                     KeyValueInformation,
                                     KeyInfoSize,
                                     &ResultSize);
            FreeHeap = TRUE;
        }
        else
        {
            /* Give up this time */
            Status = STATUS_NO_MEMORY;
        }
    }

    /* Check for success */
    if (NT_SUCCESS(Status))
    {
        /* Handle binary data */
        if (KeyValueInformation->Type == REG_BINARY)
        {
            /* Check validity */
            if ((Buffer) && (KeyValueInformation->DataLength <= BufferSize))
            {
                /* Copy into buffer */
                RtlMoveMemory(Buffer,
                              &KeyValueInformation->Data,
                              KeyValueInformation->DataLength);
            }
            else
            {
                Status = STATUS_BUFFER_OVERFLOW;
            }

            /* Copy the result length */
            if (ReturnedLength) *ReturnedLength = KeyValueInformation->DataLength;
        }
        else if (KeyValueInformation->Type == REG_DWORD)
        {
            /* Check for valid type */
            if (KeyValueInformation->Type != Type)
            {
                /* Error */
                Status = STATUS_OBJECT_TYPE_MISMATCH;
            }
            else
            {
                /* Check validity */
                if ((Buffer) &&
                    (BufferSize == sizeof(ULONG)) &&
                    (KeyValueInformation->DataLength <= BufferSize))
                {
                    /* Copy into buffer */
                    RtlMoveMemory(Buffer,
                                  &KeyValueInformation->Data,
                                  KeyValueInformation->DataLength);
                }
                else
                {
                    Status = STATUS_BUFFER_OVERFLOW;
                }

                /* Copy the result length */
                if (ReturnedLength) *ReturnedLength = KeyValueInformation->DataLength;
            }
        }
        else if (KeyValueInformation->Type != REG_SZ)
        {
            /* We got something weird */
            Status = STATUS_OBJECT_TYPE_MISMATCH;
        }
        else
        {
            /*  String, check what you requested */
            if (Type == REG_DWORD)
            {
                /* Validate */
                if (BufferSize != sizeof(ULONG))
                {
                    /* Invalid size */
                    BufferSize = 0;
                    Status = STATUS_INFO_LENGTH_MISMATCH;
                }
                else
                {
                    /* OK, we know what you want... */
                    IntegerString.Buffer = (PWSTR)KeyValueInformation->Data;
                    IntegerString.Length = (USHORT)KeyValueInformation->DataLength -
                                           sizeof(WCHAR);
                    IntegerString.MaximumLength = (USHORT)KeyValueInformation->DataLength;
                    Status = RtlUnicodeStringToInteger(&IntegerString, 0, (PULONG)Buffer);
                }
            }
            else
            {
                /* Validate */
                if (KeyValueInformation->DataLength > BufferSize)
                {
                    /* Invalid */
                    Status = STATUS_BUFFER_OVERFLOW;
                }
                else
                {
                    /* Set the size */
                    BufferSize = KeyValueInformation->DataLength;
                }

                /* Copy the string */
                RtlMoveMemory(Buffer, &KeyValueInformation->Data, BufferSize);
            }

            /* Copy the result length */
            if (ReturnedLength) *ReturnedLength = KeyValueInformation->DataLength;
        }
    }

    /* Check if buffer was in heap */
    if (FreeHeap) RtlFreeHeap(RtlGetProcessHeap(), 0, KeyValueInformation);

    /* Return status */
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
LdrQueryImageFileExecutionOptionsEx(
    _In_ PUNICODE_STRING SubKey,
    _In_ PCWSTR ValueName,
    _In_ ULONG Type,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ReturnedLength,
    _In_ BOOLEAN Wow64)
{
    NTSTATUS Status;
    HANDLE KeyHandle;

    /* Open a handle to the key */
    Status = LdrOpenImageFileOptionsKey(SubKey, Wow64, &KeyHandle);

    /* Check for success */
    if (NT_SUCCESS(Status))
    {
        /* Query the data */
        Status = LdrQueryImageFileKeyOption(KeyHandle,
                                            ValueName,
                                            Type,
                                            Buffer,
                                            BufferSize,
                                            ReturnedLength);

        /* Close the key */
        NtClose(KeyHandle);
    }

    /* Return to caller */
    return Status;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
LdrQueryImageFileExecutionOptions(
    _In_ PUNICODE_STRING SubKey,
    _In_ PCWSTR ValueName,
    _In_ ULONG Type,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_opt_ PULONG ReturnedLength)
{
    /* Call the newer function */
    return LdrQueryImageFileExecutionOptionsEx(SubKey,
                                               ValueName,
                                               Type,
                                               Buffer,
                                               BufferSize,
                                               ReturnedLength,
                                               FALSE);
}

VOID
NTAPI
LdrpEnsureLoaderLockIsHeld(VOID)
{
    // Ignored atm
}

PVOID
NTAPI
LdrpFetchAddressOfSecurityCookie(PVOID BaseAddress, ULONG SizeOfImage)
{
    PIMAGE_LOAD_CONFIG_DIRECTORY ConfigDir;
    ULONG DirSize;
    PVOID Cookie = NULL;

    /* Check NT header first */
    if (!RtlImageNtHeader(BaseAddress)) return NULL;

    /* Get the pointer to the config directory */
    ConfigDir = RtlImageDirectoryEntryToData(BaseAddress,
                                             TRUE,
                                             IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
                                             &DirSize);

    /* Check for sanity */
    if (!ConfigDir ||
        (DirSize != 64 && ConfigDir->Size != DirSize) ||
        (ConfigDir->Size < 0x48))
        return NULL;

    /* Now get the cookie */
    Cookie = (PVOID)ConfigDir->SecurityCookie;

    /* Check this cookie */
    if ((PCHAR)Cookie <= (PCHAR)BaseAddress ||
        (PCHAR)Cookie >= (PCHAR)BaseAddress + SizeOfImage)
    {
        Cookie = NULL;
    }

    /* Return validated security cookie */
    return Cookie;
}

PVOID
NTAPI
LdrpInitSecurityCookie(PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PULONG_PTR Cookie;
    LARGE_INTEGER Counter;
    ULONG_PTR NewCookie;

    /* Fetch address of the cookie */
    Cookie = LdrpFetchAddressOfSecurityCookie(LdrEntry->DllBase, LdrEntry->SizeOfImage);

    if (Cookie)
    {
        /* Check if it's a default one */
        if ((*Cookie == DEFAULT_SECURITY_COOKIE) ||
            (*Cookie == 0xBB40))
        {
            /* Make up a cookie from a bunch of values which may uniquely represent
               current moment of time, environment, etc */
            Counter.QuadPart = 0;
            RtlQueryPerformanceCounter(&Counter);

            NewCookie = Counter.LowPart ^ Counter.HighPart;
            NewCookie ^= (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
            NewCookie ^= (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;

            /* Loop like it's done in KeQueryTickCount(). We don't want to call it directly. */
            while (SharedUserData->SystemTime.High1Time != SharedUserData->SystemTime.High2Time)
            {
                YieldProcessor();
            };

            /* Calculate the milliseconds value and xor it to the cookie */
            NewCookie ^= Int64ShrlMod32(UInt32x32To64(SharedUserData->TickCountMultiplier, SharedUserData->TickCount.LowPart), 24) +
                (SharedUserData->TickCountMultiplier * (SharedUserData->TickCount.High1Time << 8));

            /* Make the cookie 16bit if necessary */
            if (*Cookie == 0xBB40) NewCookie &= 0xFFFF;

            /* If the result is 0 or the same as we got, just subtract one from the existing value
               and that's it */
            if ((NewCookie == 0) || (NewCookie == *Cookie))
            {
                NewCookie = *Cookie - 1;
            }

            /* Set the new cookie value */
            *Cookie = NewCookie;
        }
    }

    return Cookie;
}

NTSTATUS
NTAPI
LdrpInitializeThread(IN PCONTEXT Context)
{
    NTSTATUS TlsStatus = STATUS_SUCCESS;
    PPEB Peb = NtCurrentPeb();
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PLIST_ENTRY NextEntry, ListHead;
    RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED ActCtx;
    NTSTATUS Status;
    PVOID EntryPoint;

    DPRINT("LdrpInitializeThread() called for %wZ (%p/%p)\n",
            &LdrpImageEntry->BaseDllName,
            NtCurrentTeb()->RealClientId.UniqueProcess,
            NtCurrentTeb()->RealClientId.UniqueThread);

    /* Acquire the loader Lock */
    RtlEnterCriticalSection(&LdrpLoaderLock);

    /* Allocate an Activation Context Stack */
    DPRINT("ActivationContextStack %p\n", NtCurrentTeb()->ActivationContextStackPointer);
    Status = RtlAllocateActivationContextStack(&NtCurrentTeb()->ActivationContextStackPointer);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Warning: Unable to allocate ActivationContextStack\n");
    }

    /* Make sure we are not shutting down */
    if (LdrpShutdownInProgress) goto Exit;

    /* Allocate TLS: a thread must not run with part of it */
    TlsStatus = LdrpAllocateTls();
    if (!NT_SUCCESS(TlsStatus))
    {
        DPRINT1("LDR: No TLS for thread %p: 0x%08lx\n", NtCurrentTeb()->RealClientId.UniqueThread, TlsStatus);
        LdrpFreeTls();
        goto Exit;
    }

    /* Start at the beginning */
    ListHead = &Peb->Ldr->InMemoryOrderModuleList;
    NextEntry = ListHead->Flink;
    while (NextEntry != ListHead)
    {
        /* Get the current entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        /* Make sure it's not ourselves */
        if (Peb->ImageBaseAddress != LdrEntry->DllBase)
        {
            /* Check if we should call */
            if (!(LdrEntry->Flags & LDRP_DONT_CALL_FOR_THREADS))
            {
                /* Get the entrypoint */
                EntryPoint = LdrEntry->EntryPoint;

                /* Check if we are ready to call it */
                if ((EntryPoint) &&
                    (LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED) &&
                    (LdrEntry->Flags & LDRP_IMAGE_DLL))
                {
                    /* Set up the Act Ctx */
                    ActCtx.Size = sizeof(ActCtx);
                    ActCtx.Format = 1;
                    RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

                    /* Activate the ActCtx */
                    RtlActivateActivationContextUnsafeFast(&ActCtx,
                                                           LdrEntry->EntryPointActivationContext);

                    _SEH2_TRY
                    {
                        /* Check if it has TLS */
                        if (LdrEntry->TlsIndex)
                        {
                            /* Make sure we're not shutting down */
                            if (!LdrpShutdownInProgress)
                            {
                                /* Call TLS */
                                LdrpCallTlsInitializers(LdrEntry, DLL_THREAD_ATTACH);
                            }
                        }

                        /* Make sure we're not shutting down */
                        if (!LdrpShutdownInProgress)
                        {
                            /* Call the Entrypoint */
                            DPRINT("%wZ - Calling entry point at %p for thread attaching, %p/%p\n",
                                   &LdrEntry->BaseDllName, LdrEntry->EntryPoint,
                                   NtCurrentTeb()->RealClientId.UniqueProcess,
                                   NtCurrentTeb()->RealClientId.UniqueThread);
                            LdrpCallInitRoutine(LdrEntry->EntryPoint,
                                                LdrEntry->DllBase,
                                                DLL_THREAD_ATTACH,
                                                NULL);
                        }
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_THREAD_ATTACH) for %wZ\n",
                                _SEH2_GetExceptionCode(), &LdrEntry->BaseDllName);
                    }
                    _SEH2_END;

                    /* Deactivate the ActCtx */
                    RtlDeactivateActivationContextUnsafeFast(&ActCtx);
                }
            }
        }

        /* Next entry */
        NextEntry = NextEntry->Flink;
    }

    /* Check for TLS */
    if (LdrpImageHasTls && !LdrpShutdownInProgress)
    {
        /* Set up the Act Ctx */
        ActCtx.Size = sizeof(ActCtx);
        ActCtx.Format = 1;
        RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

        /* Activate the ActCtx */
        RtlActivateActivationContextUnsafeFast(&ActCtx,
                                               LdrpImageEntry->EntryPointActivationContext);

        _SEH2_TRY
        {
            /* Do TLS callbacks */
            LdrpCallTlsInitializers(LdrpImageEntry, DLL_THREAD_ATTACH);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Do nothing */
        }
        _SEH2_END;

        /* Deactivate the ActCtx */
        RtlDeactivateActivationContextUnsafeFast(&ActCtx);
    }

Exit:

    /* Release the loader lock */
    RtlLeaveCriticalSection(&LdrpLoaderLock);

    DPRINT("LdrpInitializeThread() done\n");
    return TlsStatus;
}

NTSTATUS
NTAPI
LdrpRunInitializeRoutines(IN PCONTEXT Context OPTIONAL)
{
    PLDR_DATA_TABLE_ENTRY LocalArray[16];
    PLIST_ENTRY ListHead;
    PLIST_ENTRY NextEntry;
    PLDR_DATA_TABLE_ENTRY LdrEntry, *LdrRootEntry, OldInitializer;
    PVOID EntryPoint;
    ULONG Count, i;
    //ULONG BreakOnInit;
    NTSTATUS Status = STATUS_SUCCESS;
    PPEB Peb = NtCurrentPeb();
    RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED ActCtx;
    ULONG BreakOnDllLoad;
    PTEB OldTldTeb;
    BOOLEAN DllStatus;

    DPRINT("LdrpRunInitializeRoutines() called for %wZ (%p/%p)\n",
        &LdrpImageEntry->BaseDllName,
        NtCurrentTeb()->RealClientId.UniqueProcess,
        NtCurrentTeb()->RealClientId.UniqueThread);

    /* Check the Loader Lock */
    LdrpEnsureLoaderLockIsHeld();

     /* Get the number of entries to call */
    if ((Count = LdrpClearLoadInProgress()))
    {
        /* Check if we can use our local buffer */
        if (Count > 16)
        {
            /* Allocate space for all the entries */
            LdrRootEntry = RtlAllocateHeap(LdrpHeap,
                                           0,
                                           Count * sizeof(*LdrRootEntry));
            if (!LdrRootEntry) return STATUS_NO_MEMORY;
        }
        else
        {
            /* Use our local array */
            LdrRootEntry = LocalArray;
        }
    }
    else
    {
        /* Don't need one */
        LdrRootEntry = NULL;
    }

    /* Show debug message */
    if (ShowSnaps)
    {
        DPRINT1("[%p,%p] LDR: Real INIT LIST for Process %wZ\n",
                NtCurrentTeb()->RealClientId.UniqueThread,
                NtCurrentTeb()->RealClientId.UniqueProcess,
                &Peb->ProcessParameters->ImagePathName);
    }

    /* Loop in order */
    ListHead = &Peb->Ldr->InInitializationOrderModuleList;
    NextEntry = ListHead->Flink;
    i = 0;
    while (NextEntry != ListHead)
    {
        /* Get the Data Entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

        /* A DLL with TLS loaded after process start gets its TLS now, entry point or not (at start LdrpInitializeTls did);
           not an image loaded without its references resolved, nor an executable */
        if (!(LdrEntry->Flags & LDRP_ENTRY_PROCESSED) && (LdrEntry->Flags & LDRP_IMAGE_DLL) &&
            !Context && !LdrEntry->TlsIndex)
        {
            PIMAGE_TLS_DIRECTORY TlsDirectory;

            Status = LdrpGetTlsDirectory(LdrEntry, &TlsDirectory);
            if (NT_SUCCESS(Status) && TlsDirectory)
                Status = LdrpAddDynamicTls(LdrEntry, TlsDirectory);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("LDR: No TLS for %wZ: 0x%08lx\n", &LdrEntry->BaseDllName, Status);
                if (LdrRootEntry && LdrRootEntry != LocalArray)
                    RtlFreeHeap(LdrpHeap, 0, LdrRootEntry);
                return Status;
            }
        }

        /* Check if we have a Root Entry */
        if (LdrRootEntry)
        {
            /* Check flags */
            if (!(LdrEntry->Flags & LDRP_ENTRY_PROCESSED))
            {
                /* Setup the Cookie for the DLL */
                LdrpInitSecurityCookie(LdrEntry);

                /* Check for valid entrypoint */
                if (LdrEntry->EntryPoint)
                {
                    /* Write in array */
                    ASSERT(i < Count);
                    LdrRootEntry[i] = LdrEntry;

                    /* Display debug message */
                    if (ShowSnaps)
                    {
                        DPRINT1("[%p,%p] LDR: %wZ init routine %p\n",
                                NtCurrentTeb()->RealClientId.UniqueThread,
                                NtCurrentTeb()->RealClientId.UniqueProcess,
                                &LdrEntry->FullDllName,
                                LdrEntry->EntryPoint);
                    }
                    i++;
                }
            }
        }

        /* Set the flag */
        LdrEntry->Flags |= LDRP_ENTRY_PROCESSED;
        NextEntry = NextEntry->Flink;
    }

    Status = STATUS_SUCCESS;

    /* If we got a context, then we have to call Kernel32 for TS support */
    if (Context)
    {
        /* Check if we have one */
        if (Kernel32ProcessInitPostImportFunction)
        {
            /* Call it */
            Status = Kernel32ProcessInitPostImportFunction();
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("LDR: LdrpRunInitializeRoutines - Failed running kernel32 post-import function, Status=0x%08lx\n", Status);
            }
        }
        /* Clear it */
        Kernel32ProcessInitPostImportFunction = NULL;
    }

    /* No root entry? return */
    if (!LdrRootEntry)
        return Status;

    /* Set the TLD TEB */
    OldTldTeb = LdrpTopLevelDllBeingLoadedTeb;
    LdrpTopLevelDllBeingLoadedTeb = NtCurrentTeb();

    /* Loop */
    i = 0;
    while (i < Count)
    {
        /* Get an entry */
        LdrEntry = LdrRootEntry[i];

        /* FIXME: Verify NX Compat */

        /* Move to next entry */
        i++;

        /* Get its entrypoint */
        EntryPoint = LdrEntry->EntryPoint;

        /* Are we being debugged? */
        BreakOnDllLoad = 0;
        if (Peb->BeingDebugged || Peb->ReadImageFileExecOptions)
        {
            /* Check if we should break on load */
            Status = LdrQueryImageFileExecutionOptions(&LdrEntry->BaseDllName,
                                                       L"BreakOnDllLoad",
                                                       REG_DWORD,
                                                       &BreakOnDllLoad,
                                                       sizeof(ULONG),
                                                       NULL);
            if (!NT_SUCCESS(Status)) BreakOnDllLoad = 0;

            /* Reset status back to STATUS_SUCCESS */
            Status = STATUS_SUCCESS;
        }

        /* Break if aksed */
        if (BreakOnDllLoad)
        {
            /* Check if we should show a message */
            if (ShowSnaps)
            {
                DPRINT1("LDR: %wZ loaded.", &LdrEntry->BaseDllName);
                DPRINT1(" - About to call init routine at %p\n", EntryPoint);
            }

            /* Break in debugger */
            DbgBreakPoint();
        }

        /* Make sure we have an entrypoint */
        if (EntryPoint)
        {
            /* Save the old Dll Initializer and write the current one */
            OldInitializer = LdrpCurrentDllInitializer;
            LdrpCurrentDllInitializer = LdrEntry;

            /* Set up the Act Ctx */
            ActCtx.Size = sizeof(ActCtx);
            ActCtx.Format = 1;
            RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

            /* Activate the ActCtx */
            RtlActivateActivationContextUnsafeFast(&ActCtx,
                                                   LdrEntry->EntryPointActivationContext);

            _SEH2_TRY
            {
                /* Check if it has TLS */
                if (LdrEntry->TlsIndex)
                {
                    /* Call TLS */
                    LdrpCallTlsInitializers(LdrEntry, DLL_PROCESS_ATTACH);
                }

                /* Call the Entrypoint */
                if (ShowSnaps)
                {
                    DPRINT1("%wZ - Calling entry point at %p for DLL_PROCESS_ATTACH\n",
                            &LdrEntry->BaseDllName, EntryPoint);
                }
                DllStatus = LdrpCallInitRoutine(EntryPoint,
                                                LdrEntry->DllBase,
                                                DLL_PROCESS_ATTACH,
                                                Context);
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                DllStatus = FALSE;
                DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_PROCESS_ATTACH) for %wZ\n",
                        _SEH2_GetExceptionCode(), &LdrEntry->BaseDllName);
            }
            _SEH2_END;

            /* Deactivate the ActCtx */
            RtlDeactivateActivationContextUnsafeFast(&ActCtx);

            /* Save the Current DLL Initializer */
            LdrpCurrentDllInitializer = OldInitializer;

            /* Mark the entry as processed. NT6+ does not send DLL_PROCESS_DETACH
               to a module whose DLL_PROCESS_ATTACH failed (VERBUMP B5) */
            if (DllStatus || (SharedUserData->NtMajorVersion < 6))
                LdrEntry->Flags |= LDRP_PROCESS_ATTACH_CALLED;

            /* Fail if DLL init failed */
            if (!DllStatus)
            {
                DPRINT1("LDR: DLL_PROCESS_ATTACH for dll \"%wZ\" (InitRoutine: %p) failed\n",
                    &LdrEntry->BaseDllName, EntryPoint);

                Status = STATUS_DLL_INIT_FAILED;
                goto Quickie;
            }
        }
    }

    /* Loop in order */
    ListHead = &Peb->Ldr->InInitializationOrderModuleList;
    NextEntry = NextEntry->Flink;
    while (NextEntry != ListHead)
    {
        /* Get the Data Entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

        /* FIXME: Verify NX Compat */
        // LdrpCheckNXCompatibility()

        /* Next entry */
        NextEntry = NextEntry->Flink;
    }

    /* Check for TLS */
    if (LdrpImageHasTls && Context)
    {
        /* Set up the Act Ctx */
        ActCtx.Size = sizeof(ActCtx);
        ActCtx.Format = 1;
        RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

        /* Activate the ActCtx */
        RtlActivateActivationContextUnsafeFast(&ActCtx,
                                               LdrpImageEntry->EntryPointActivationContext);

        _SEH2_TRY
        {
            /* Do TLS callbacks */
            LdrpCallTlsInitializers(LdrpImageEntry, DLL_PROCESS_ATTACH);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Do nothing */
        }
        _SEH2_END;

        /* Deactivate the ActCtx */
        RtlDeactivateActivationContextUnsafeFast(&ActCtx);
    }

Quickie:
    /* Restore old TEB */
    LdrpTopLevelDllBeingLoadedTeb = OldTldTeb;

    /* Check if the array is in the heap */
    if (LdrRootEntry != LocalArray)
    {
        /* Free the array */
        RtlFreeHeap(LdrpHeap, 0, LdrRootEntry);
    }

    /* Return to caller */
    DPRINT("LdrpRunInitializeRoutines() done\n");
    return Status;
}

/*
 * Runs the FLS callbacks of the calling thread (the C++ runtime destroys its
 * thread_local objects from one) and empties the slots. The data block stays
 * for the caller, which frees it with the thread.
 */
static
VOID
LdrpRundownFls(VOID)
{
    PTEB Teb = NtCurrentTeb();
    ULONG n, FlsHighIndex;
    PRTL_FLS_DATA pFlsData;
    PFLS_CALLBACK_FUNCTION lpCallback;

    /* Mimic BaseRundownFls */
    pFlsData = Teb->FlsData;
    if (!pFlsData)
        return;

    /* Unlinked first, so that a concurrent FlsFree does not call the callbacks a second time */
    RtlAcquirePebLock();
    FlsHighIndex = NtCurrentPeb()->FlsHighIndex;
    RemoveEntryList(&pFlsData->ListEntry);
    InitializeListHead(&pFlsData->ListEntry);
    RtlReleasePebLock();

    for (n = 1; n <= FlsHighIndex; ++n)
    {
        /* An index that FlsFree released (its callback may have raised) runs nothing */
        RtlAcquirePebLock();
        lpCallback = RtlAreBitsSet(NtCurrentPeb()->FlsBitmap, n, 1) ? RTL_FLS_CALLBACK_SLOT(NtCurrentPeb(), n) : NULL;
        RtlReleasePebLock();
        if (lpCallback && pFlsData->Data[n])
        {
            lpCallback(pFlsData->Data[n]);

            /* The callback saw its value; the DLL notifications after it must not */
            pFlsData->Data[n] = NULL;
        }
    }
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
LdrShutdownProcess(VOID)
{
    PPEB Peb = NtCurrentPeb();
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PLIST_ENTRY NextEntry, ListHead;
    RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED ActCtx;
    PVOID EntryPoint;

    DPRINT("LdrShutdownProcess() called for %wZ\n", &LdrpImageEntry->BaseDllName);
    if (LdrpShutdownInProgress) return STATUS_SUCCESS;

    /* Tell the Shim Engine */
    if (g_ShimsEnabled)
    {
        VOID(NTAPI *SE_ProcessDying)();
        SE_ProcessDying = RtlDecodeSystemPointer(g_pfnSE_ProcessDying);
        SE_ProcessDying();
    }

    /* Tell the world */
    if (ShowSnaps)
    {
        DPRINT1("\n");
    }

    /* Set the shutdown variables */
    LdrpShutdownThreadId = NtCurrentTeb()->RealClientId.UniqueThread;
    LdrpShutdownInProgress = TRUE;

    /* The calling thread's FLS callbacks come before the DLL notifications, as on Windows */
    LdrpRundownFls();

    /* Enter the Loader Lock */
    RtlEnterCriticalSection(&LdrpLoaderLock);

#if (NTDDI_VERSION < NTDDI_VISTA)
    /* Cleanup trace logging data (Etw) */
    if (SharedUserData->TraceLogging)
    {
        /* FIXME */
        DPRINT1("We don't support Etw yet.\n");
    }
#endif

    /* Start at the end */
    ListHead = &Peb->Ldr->InInitializationOrderModuleList;
    NextEntry = ListHead->Blink;
    while (NextEntry != ListHead)
    {
        /* Get the current entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        NextEntry = NextEntry->Blink;

        /* Make sure it's not ourselves */
        if (Peb->ImageBaseAddress != LdrEntry->DllBase)
        {
            /* Get the entrypoint */
            EntryPoint = LdrEntry->EntryPoint;

            /* Check if we are ready to call it */
            if (EntryPoint &&
                (LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED) &&
                LdrEntry->Flags)
            {
                /* Set up the Act Ctx */
                ActCtx.Size = sizeof(ActCtx);
                ActCtx.Format = 1;
                RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

                /* Activate the ActCtx */
                RtlActivateActivationContextUnsafeFast(&ActCtx,
                                                       LdrEntry->EntryPointActivationContext);

                _SEH2_TRY
                {
                    /* Check if it has TLS */
                    if (LdrEntry->TlsIndex)
                    {
                        /* Call TLS */
                        LdrpCallTlsInitializers(LdrEntry, DLL_PROCESS_DETACH);
                    }

                    /* Call the Entrypoint */
                    DPRINT("%wZ - Calling entry point at %p for thread detaching\n",
                           &LdrEntry->BaseDllName, LdrEntry->EntryPoint);
                    LdrpCallInitRoutine(EntryPoint,
                                        LdrEntry->DllBase,
                                        DLL_PROCESS_DETACH,
                                        (PVOID)1);
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_PROCESS_DETACH) for %wZ\n",
                            _SEH2_GetExceptionCode(), &LdrEntry->BaseDllName);
                }
                _SEH2_END;

                /* Deactivate the ActCtx */
                RtlDeactivateActivationContextUnsafeFast(&ActCtx);
            }
        }
    }

    /* Check for TLS */
    if (LdrpImageHasTls)
    {
        /* Set up the Act Ctx */
        ActCtx.Size = sizeof(ActCtx);
        ActCtx.Format = 1;
        RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

        /* Activate the ActCtx */
        RtlActivateActivationContextUnsafeFast(&ActCtx,
                                               LdrpImageEntry->EntryPointActivationContext);

        _SEH2_TRY
        {
            /* Do TLS callbacks */
            LdrpCallTlsInitializers(LdrpImageEntry, DLL_PROCESS_DETACH);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Do nothing */
        }
        _SEH2_END;

        /* Deactivate the ActCtx */
        RtlDeactivateActivationContextUnsafeFast(&ActCtx);
    }

    /* FIXME: Do Heap detection and Etw final shutdown */

    /* Release the lock */
    RtlLeaveCriticalSection(&LdrpLoaderLock);
    DPRINT("LdrpShutdownProcess() done\n");

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
LdrShutdownThread(VOID)
{
    PPEB Peb = NtCurrentPeb();
    PTEB Teb = NtCurrentTeb();
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PLIST_ENTRY NextEntry, ListHead;
    RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED ActCtx;
    PVOID EntryPoint;

    DPRINT("LdrShutdownThread() called for %wZ\n",
            &LdrpImageEntry->BaseDllName);

#if (NTDDI_VERSION < NTDDI_VISTA)
    /* Cleanup trace logging data (Etw) */
    if (SharedUserData->TraceLogging)
    {
        /* FIXME */
        DPRINT1("We don't support Etw yet.\n");
    }
#endif

    /* The FLS callbacks run first, like on Windows: before the DLL notifications and with the TLS still there */
    LdrpRundownFls();

    /* Get the Ldr Lock */
    RtlEnterCriticalSection(&LdrpLoaderLock);

    /* Start at the end */
    ListHead = &Peb->Ldr->InInitializationOrderModuleList;
    NextEntry = ListHead->Blink;
    while (NextEntry != ListHead)
    {
        /* Get the current entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        NextEntry = NextEntry->Blink;

        /* Make sure it's not ourselves */
        if (Peb->ImageBaseAddress != LdrEntry->DllBase)
        {
            /* Check if we should call */
            if (!(LdrEntry->Flags & LDRP_DONT_CALL_FOR_THREADS) &&
                (LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED) &&
                (LdrEntry->Flags & LDRP_IMAGE_DLL))
            {
                /* Get the entrypoint */
                EntryPoint = LdrEntry->EntryPoint;

                /* Check if we are ready to call it */
                if (EntryPoint)
                {
                    /* Set up the Act Ctx */
                    ActCtx.Size = sizeof(ActCtx);
                    ActCtx.Format = 1;
                    RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

                    /* Activate the ActCtx */
                    RtlActivateActivationContextUnsafeFast(&ActCtx,
                                                           LdrEntry->EntryPointActivationContext);

                    _SEH2_TRY
                    {
                        /* Check if it has TLS */
                        if (LdrEntry->TlsIndex)
                        {
                            /* Make sure we're not shutting down */
                            if (!LdrpShutdownInProgress)
                            {
                                /* Call TLS */
                                LdrpCallTlsInitializers(LdrEntry, DLL_THREAD_DETACH);
                            }
                        }

                        /* Make sure we're not shutting down */
                        if (!LdrpShutdownInProgress)
                        {
                            /* Call the Entrypoint */
                            DPRINT("%wZ - Calling entry point at %p for thread detaching\n",
                                   &LdrEntry->BaseDllName, LdrEntry->EntryPoint);
                            LdrpCallInitRoutine(EntryPoint,
                                                LdrEntry->DllBase,
                                                DLL_THREAD_DETACH,
                                                NULL);
                        }
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_THREAD_DETACH) for %wZ\n",
                                _SEH2_GetExceptionCode(), &LdrEntry->BaseDllName);
                    }
                    _SEH2_END;

                    /* Deactivate the ActCtx */
                    RtlDeactivateActivationContextUnsafeFast(&ActCtx);
                }
            }
        }
    }

    /* Check for TLS */
    if (LdrpImageHasTls)
    {
        /* Set up the Act Ctx */
        ActCtx.Size = sizeof(ActCtx);
        ActCtx.Format = 1;
        RtlZeroMemory(&ActCtx.Frame, sizeof(RTL_ACTIVATION_CONTEXT_STACK_FRAME));

        /* Activate the ActCtx */
        RtlActivateActivationContextUnsafeFast(&ActCtx,
                                               LdrpImageEntry->EntryPointActivationContext);

        _SEH2_TRY
        {
            /* Do TLS callbacks */
            LdrpCallTlsInitializers(LdrpImageEntry, DLL_THREAD_DETACH);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Do nothing */
        }
        _SEH2_END;

        /* Deactivate the ActCtx */
        RtlDeactivateActivationContextUnsafeFast(&ActCtx);
    }

    /* Free TLS */
    LdrpFreeTls();
    RtlLeaveCriticalSection(&LdrpLoaderLock);

    /* Check for expansion slots */
    if (Teb->TlsExpansionSlots)
    {
        /* Free expansion slots */
        RtlFreeHeap(RtlGetProcessHeap(), 0, Teb->TlsExpansionSlots);
    }

    /* Free the FLS data, its callbacks already ran */
    if (Teb->FlsData)
    {
        /* A DLL notification may have called FlsSetValue after the rundown: on a thread that had no
           FLS data yet that links a new block, which FlsFree must not find once it is freed */
        RtlAcquirePebLock();
        RemoveEntryList(&((PRTL_FLS_DATA)Teb->FlsData)->ListEntry);
        RtlReleasePebLock();

        RtlFreeHeap(RtlGetProcessHeap(), 0, Teb->FlsData);
        Teb->FlsData = NULL;
    }

    /* Check for Fiber data */
#if (NTDDI_VERSION < NTDDI_LONGHORN)
    if (Teb->HasFiberData)
#else
    if (Teb->DbgHasFiberData)
#endif
    {
        /* Free Fiber data*/
        RtlFreeHeap(RtlGetProcessHeap(), 0, Teb->NtTib.FiberData);
        Teb->NtTib.FiberData = NULL;
    }

    /* Free the activation context stack */
    RtlFreeThreadActivationContextStack();
    DPRINT("LdrShutdownThread() done\n");

    return STATUS_SUCCESS;
}

/*
 * TLS
 *
 * Every module with a TLS directory has an index in LdrpTlsList, and every
 * thread a TLS vector (Teb->ThreadLocalStoragePointer) with the module's
 * block at that index: the template, then the zero fill. The modules present
 * at process start get theirs from LdrpInitializeTls; a module loaded later
 * gets the next free index from LdrpAddDynamicTls, which gives every thread
 * that has a vector a new one through the kernel (ProcessTlsInformation),
 * and LdrpRemoveDynamicTls frees the blocks and the index when the module is
 * unloaded. Threads allocate their vector in LdrpInitializeThread and free it
 * in LdrShutdownThread. All of this runs with the loader lock held.
 *
 * A thread may be reading its old vector while the kernel replaces it, so the
 * old vectors of other threads are only freed when their thread ends; the
 * loading thread frees its own at once.
 */

#ifndef IMAGE_SCN_ALIGN_MASK
#define IMAGE_SCN_ALIGN_MASK 0x00F00000
#endif

static ULONG LdrpTlsIndexLimit;     /* Length of every thread's vector */
static PULONG LdrpFreeTlsIndexes;   /* Indexes below the limit that no module uses */
static ULONG LdrpFreeTlsIndexCount;

typedef struct _LDRP_RETIRED_TLS_VECTOR
{
    LIST_ENTRY Links;
    HANDLE ThreadId;
    PVOID *TlsVector;
} LDRP_RETIRED_TLS_VECTOR, *PLDRP_RETIRED_TLS_VECTOR;

static LIST_ENTRY LdrpRetiredTlsVectors = { &LdrpRetiredTlsVectors, &LdrpRetiredTlsVectors };

/*
 * Whether Length bytes at Address lie in the module's image. SizeOfImage
 * comes from the header and is checked without wrapping; the mapping is what
 * counts, so both ends must be in the module's own view.
 */
static
BOOLEAN
LdrpIsInImage(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _In_ ULONG_PTR Address,
    _In_ SIZE_T Length)
{
    ULONG_PTR Base = (ULONG_PTR)LdrEntry->DllBase;
    MEMORY_BASIC_INFORMATION Info;
    ULONG_PTR Last;

    if (!Length || Address < Base || Address - Base >= LdrEntry->SizeOfImage ||
        Length > LdrEntry->SizeOfImage - (Address - Base))
    {
        return FALSE;
    }
    Last = Address + Length - 1;
    if (Last < Address)
        return FALSE;

    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)Address, MemoryBasicInformation,
                                         &Info, sizeof(Info), NULL)) ||
        Info.AllocationBase != LdrEntry->DllBase)
    {
        return FALSE;
    }
    if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)Last, MemoryBasicInformation,
                                         &Info, sizeof(Info), NULL)) ||
        Info.AllocationBase != LdrEntry->DllBase)
    {
        return FALSE;
    }
    return TRUE;
}

/* The TLS directory of a module: NULL when it has none; one outside the image makes the image invalid */
static
NTSTATUS
LdrpGetTlsDirectory(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _Out_ PIMAGE_TLS_DIRECTORY *TlsDirectory)
{
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG Rva = 0, Count = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    *TlsDirectory = NULL;
    NtHeaders = RtlImageNtHeader(LdrEntry->DllBase);
    if (!NtHeaders)
        return STATUS_INVALID_IMAGE_FORMAT;

    /* The optional header can be in a page that faults */
    _SEH2_TRY
    {
        Count = NtHeaders->OptionalHeader.NumberOfRvaAndSizes;
        if (Count > IMAGE_DIRECTORY_ENTRY_TLS)
            Rva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
        return Status;
    if (!Rva)
        return STATUS_SUCCESS;

    /* The offset is checked before it is added to the base, which could wrap */
    if (Rva >= LdrEntry->SizeOfImage || LdrEntry->SizeOfImage - Rva < sizeof(IMAGE_TLS_DIRECTORY) ||
        !LdrpIsInImage(LdrEntry, (ULONG_PTR)LdrEntry->DllBase + Rva, sizeof(IMAGE_TLS_DIRECTORY)))
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    *TlsDirectory = (PIMAGE_TLS_DIRECTORY)((ULONG_PTR)LdrEntry->DllBase + Rva);
    return STATUS_SUCCESS;
}

/* Checks a TLS directory and fills in the block size and alignment of a module */
static
NTSTATUS
LdrpCaptureTlsDirectory(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _In_ PIMAGE_TLS_DIRECTORY TlsDirectory,
    _Out_ PLDRP_TLS_DATA TlsData)
{
    IMAGE_TLS_DIRECTORY Directory;
    ULONG_PTR Page;
    NTSTATUS Status = STATUS_SUCCESS;
    SIZE_T RawSize;
    ULONG AlignShift;

    /* The directory must lie in the image */
    if (!LdrpIsInImage(LdrEntry, (ULONG_PTR)TlsDirectory, sizeof(IMAGE_TLS_DIRECTORY)))
        return STATUS_INVALID_IMAGE_FORMAT;

    _SEH2_TRY
    {
        Directory = *TlsDirectory;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
        return Status;

    /* The template and the index must lie in the image, and template plus zero fill must not wrap */
    if (Directory.EndAddressOfRawData < Directory.StartAddressOfRawData ||
        (Directory.StartAddressOfRawData != Directory.EndAddressOfRawData &&
         !LdrpIsInImage(LdrEntry, Directory.StartAddressOfRawData,
                        Directory.EndAddressOfRawData - Directory.StartAddressOfRawData)) ||
        !LdrpIsInImage(LdrEntry, Directory.AddressOfIndex, sizeof(ULONG)))
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    RawSize = Directory.EndAddressOfRawData - Directory.StartAddressOfRawData;
    if (RawSize + Directory.SizeOfZeroFill < RawSize || RawSize + Directory.SizeOfZeroFill > MAXLONG)
        return STATUS_INVALID_IMAGE_FORMAT;

    /* The template must be readable (a section can be PAGE_NOACCESS) */
    _SEH2_TRY
    {
        for (Page = Directory.StartAddressOfRawData; Page < Directory.EndAddressOfRawData; Page = ALIGN_DOWN_BY(Page, PAGE_SIZE) + PAGE_SIZE)
            (VOID)*(volatile UCHAR *)Page;
        if (RawSize)
            (VOID)*(volatile UCHAR *)(Directory.EndAddressOfRawData - 1);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
        return Status;

    TlsData->TlsDirectory = Directory;
    TlsData->Module = LdrEntry;
    TlsData->Size = RawSize + Directory.SizeOfZeroFill;

    /* IMAGE_SCN_ALIGN_* in the characteristics: 2^(n-1) bytes */
    AlignShift = (Directory.Characteristics & IMAGE_SCN_ALIGN_MASK) >> 20;
    TlsData->Alignment = AlignShift ? (1 << (AlignShift - 1)) : 0;
    if (TlsData->Alignment <= MEMORY_ALLOCATION_ALIGNMENT)
        TlsData->Alignment = 0;

    return STATUS_SUCCESS;
}

static VOID LdrpFreeTlsBlock(_In_ PLDRP_TLS_DATA TlsData, _In_opt_ PVOID Block);

/* A new TLS block of a module for one thread: the template, then zeros, aligned as the module asks */
static
PVOID
LdrpAllocateTlsBlock(
    _In_ PLDRP_TLS_DATA TlsData)
{
    SIZE_T RawSize = TlsData->TlsDirectory.EndAddressOfRawData - TlsData->TlsDirectory.StartAddressOfRawData;
    PVOID Allocation, Block;

    if (!TlsData->Alignment)
    {
        Block = RtlAllocateHeap(RtlGetProcessHeap(), 0, TlsData->Size ? TlsData->Size : 1);
        if (!Block)
            return NULL;
    }
    else
    {
        /* Over-allocate, align, and keep the allocation just before the block */
        Allocation = RtlAllocateHeap(RtlGetProcessHeap(), 0, TlsData->Size + TlsData->Alignment + sizeof(PVOID));
        if (!Allocation)
            return NULL;
        Block = (PVOID)ALIGN_UP_BY((ULONG_PTR)Allocation + sizeof(PVOID), TlsData->Alignment);
        ((PVOID *)Block)[-1] = Allocation;
    }

    /* Checked readable when the module was loaded; a module changing that later gets no block */
    _SEH2_TRY
    {
        RtlCopyMemory(Block, (PVOID)TlsData->TlsDirectory.StartAddressOfRawData, RawSize);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        LdrpFreeTlsBlock(TlsData, Block);
        _SEH2_YIELD(return NULL);
    }
    _SEH2_END;
    RtlZeroMemory((PUCHAR)Block + RawSize, TlsData->TlsDirectory.SizeOfZeroFill);
    return Block;
}

static
VOID
LdrpFreeTlsBlock(
    _In_ PLDRP_TLS_DATA TlsData,
    _In_opt_ PVOID Block)
{
    if (!Block)
        return;
    RtlFreeHeap(RtlGetProcessHeap(), 0, TlsData->Alignment ? ((PVOID *)Block)[-1] : Block);
}

/*
 * A TLS vector of Count entries, zeroed; its number of entries is kept in the
 * ULONG_PTR before it, which the kernel checks (ProcessTlsInformation).
 */
static
PVOID *
LdrpAllocateTlsVectorEntries(
    _In_ ULONG Count)
{
    PULONG_PTR Allocation;

    Allocation = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, (Count + 1) * sizeof(PVOID));
    if (!Allocation)
        return NULL;
    Allocation[0] = Count;
    return (PVOID *)(Allocation + 1);
}

static
VOID
LdrpFreeTlsVectorEntries(
    _In_opt_ PVOID *TlsVector)
{
    if (TlsVector)
        RtlFreeHeap(RtlGetProcessHeap(), 0, (PULONG_PTR)TlsVector - 1);
}

static
ULONG_PTR
LdrpTlsVectorLength(
    _In_ PVOID *TlsVector)
{
    return ((PULONG_PTR)TlsVector)[-1];
}

/* Frees a thread's TLS vector and the blocks in it */
static
VOID
LdrpFreeTlsVector(
    _In_ PVOID *TlsVector)
{
    PLIST_ENTRY NextEntry;
    PLDRP_TLS_DATA TlsData;

    for (NextEntry = LdrpTlsList.Flink; NextEntry != &LdrpTlsList; NextEntry = NextEntry->Flink)
    {
        TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks);
        if (TlsData->Index < LdrpTlsVectorLength(TlsVector))
            LdrpFreeTlsBlock(TlsData, TlsVector[TlsData->Index]);
    }

    LdrpFreeTlsVectorEntries(TlsVector);
}

NTSTATUS
NTAPI
LdrpInitializeTls(VOID)
{
    PLIST_ENTRY NextEntry, ListHead;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PIMAGE_TLS_DIRECTORY TlsDirectory;
    PLDRP_TLS_DATA TlsData;
    NTSTATUS Status;

    /* Initialize the TLS List */
    InitializeListHead(&LdrpTlsList);

    /* Loop all the modules */
    ListHead = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    NextEntry = ListHead->Flink;
    while (ListHead != NextEntry)
    {
        /* Get the entry */
        LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        NextEntry = NextEntry->Flink;

        /* Get the TLS directory */
        Status = LdrpGetTlsDirectory(LdrEntry, &TlsDirectory);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("LDR: Invalid TLS directory in %wZ\n", &LdrEntry->BaseDllName);
            return Status;
        }

        /* Check if we have a directory */
        if (!TlsDirectory) continue;

        /* Check if the image has TLS */
        if (!LdrpImageHasTls) LdrpImageHasTls = TRUE;

        /* Show debug message */
        if (ShowSnaps)
        {
            DPRINT1("LDR: Tls Found in %wZ at %p\n",
                    &LdrEntry->BaseDllName,
                    TlsDirectory);
        }

        /* Allocate an entry */
        TlsData = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(LDRP_TLS_DATA));
        if (!TlsData) return STATUS_NO_MEMORY;

        Status = LdrpCaptureTlsDirectory(LdrEntry, TlsDirectory, TlsData);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("LDR: Invalid TLS directory in %wZ\n", &LdrEntry->BaseDllName);
            RtlFreeHeap(RtlGetProcessHeap(), 0, TlsData);
            return Status;
        }

        /* Lock the DLL and mark it for TLS Usage */
        LdrEntry->LoadCount = -1;
        LdrEntry->TlsIndex = -1;

        /* Save the cached TLS data */
        InsertTailList(&LdrpTlsList, &TlsData->TlsLinks);

        /* Update the index */
        *(PLONG)TlsData->TlsDirectory.AddressOfIndex = LdrpNumberOfTlsEntries;
        TlsData->Index = LdrpNumberOfTlsEntries++;
    }
    LdrpTlsIndexLimit = LdrpNumberOfTlsEntries;

    /* Done setting up TLS, allocate entries */
    return LdrpAllocateTls();
}

NTSTATUS
NTAPI
LdrpAllocateTls(VOID)
{
    PTEB Teb = NtCurrentTeb();
    PLIST_ENTRY NextEntry, ListHead;
    PLDRP_TLS_DATA TlsData;
    PVOID *TlsVector;

    /*
     * Every initialized thread has a vector, even an empty one: a thread
     * without one is skipped when a module with TLS is loaded later.
     */
    TlsVector = LdrpAllocateTlsVectorEntries(LdrpTlsIndexLimit);
    if (!TlsVector) return STATUS_NO_MEMORY;
    Teb->ThreadLocalStoragePointer = TlsVector;

    /* Loop the TLS Array */
    ListHead = &LdrpTlsList;
    NextEntry = ListHead->Flink;
    while (NextEntry != ListHead)
    {
        /* Get the entry */
        TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks);
        NextEntry = NextEntry->Flink;

        /* Allocate and initialize this module's block */
        TlsVector[TlsData->Index] = LdrpAllocateTlsBlock(TlsData);
        if (!TlsVector[TlsData->Index])
        {
            /* Out of memory */
            return STATUS_NO_MEMORY;
        }

        /* Show debug message */
        if (ShowSnaps)
        {
            DPRINT1("LDR: TlsVector %p Index %lu = %p copied from %x to %p\n",
                    TlsVector,
                    TlsData->Index,
                    &TlsVector[TlsData->Index],
                    TlsData->TlsDirectory.StartAddressOfRawData,
                    TlsVector[TlsData->Index]);
        }
    }

    /* Done */
    return STATUS_SUCCESS;
}

VOID
NTAPI
LdrpFreeTls(VOID)
{
    PTEB Teb = NtCurrentTeb();

    /* The vectors this thread had before modules with TLS were loaded */
    LdrpFreeRetiredTlsVectors(Teb->RealClientId.UniqueThread);

    /* Free the blocks and the vector itself */
    if (Teb->ThreadLocalStoragePointer)
    {
        LdrpFreeTlsVector(Teb->ThreadLocalStoragePointer);
        Teb->ThreadLocalStoragePointer = NULL;
    }
}

/* Frees the old TLS vectors of a thread (blocks not included: they live on in its current vector) */
VOID
NTAPI
LdrpFreeRetiredTlsVectors(
    _In_ HANDLE ThreadId)
{
    PLIST_ENTRY NextEntry;
    PLDRP_RETIRED_TLS_VECTOR Retired;

    NextEntry = LdrpRetiredTlsVectors.Flink;
    while (NextEntry != &LdrpRetiredTlsVectors)
    {
        Retired = CONTAINING_RECORD(NextEntry, LDRP_RETIRED_TLS_VECTOR, Links);
        NextEntry = NextEntry->Flink;

        if (Retired->ThreadId == ThreadId)
        {
            RemoveEntryList(&Retired->Links);
            LdrpFreeTlsVectorEntries(Retired->TlsVector);
            RtlFreeHeap(RtlGetProcessHeap(), 0, Retired);
        }
    }
}

/*
 * Asks the kernel to change the TLS of every thread that has a vector. The
 * request is sized for the threads there are; the kernel changes nothing if
 * it is too small, and the number of threads with a vector cannot grow while
 * the loader lock is held, so a second try with the size it asks for fits.
 * Prepare fills in each entry's NewTlsData; entries the kernel did not use
 * are handed to Discard. On success, and also when a fault stopped the kernel
 * part way (then *Result holds the entries it changed, marked
 * THREAD_TLS_INFORMATION_ASSIGNED), the caller gets *Result to finish with.
 */
typedef NTSTATUS (*PLDRP_PREPARE_TLS_ENTRY)(_In_ PLDRP_TLS_DATA TlsData, _Out_ PVOID *NewTlsData);
typedef VOID (*PLDRP_DISCARD_TLS_ENTRY)(_In_ PLDRP_TLS_DATA TlsData, _In_opt_ PVOID NewTlsData);

static
NTSTATUS
LdrpChangeThreadsTls(
    _In_ ULONG OperationType,
    _In_ PLDRP_TLS_DATA TlsData,
    _In_ PLDRP_PREPARE_TLS_ENTRY Prepare,
    _In_ PLDRP_DISCARD_TLS_ENTRY Discard,
    _Out_ PPROCESS_TLS_INFORMATION *Result)
{
    PPROCESS_TLS_INFORMATION Info = NULL;
    ULONG Count = 8, Prepared, Used, Size, i;
    NTSTATUS Status;

    *Result = NULL;
    for (;;)
    {
        Size = FIELD_OFFSET(PROCESS_TLS_INFORMATION, ThreadData[Count]);
        Info = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
        if (!Info)
            return STATUS_NO_MEMORY;

        Info->OperationType = OperationType;
        Info->ThreadDataCount = Count;
        Info->TlsIndex = TlsData->Index;

        Status = STATUS_SUCCESS;
        for (Prepared = 0; Prepared < Count; Prepared++)
        {
            Status = Prepare(TlsData, &Info->ThreadData[Prepared].NewTlsData);
            if (!NT_SUCCESS(Status))
                break;
        }

        if (NT_SUCCESS(Status))
            Status = NtSetInformationProcess(NtCurrentProcess(), ProcessTlsInformation, Info, Size);

        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;

        /* Nothing was changed: try again with the size the kernel asks for */
        for (i = 0; i < Prepared; i++)
            Discard(TlsData, Info->ThreadData[i].NewTlsData);
        Count = Info->ThreadDataCount + 4;
        RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
    }

    /* Entries the kernel used are the caller's now; the rest go */
    Used = 0;
    for (i = 0; i < Prepared; i++)
    {
        if (Info->ThreadData[i].Flags & THREAD_TLS_INFORMATION_ASSIGNED)
            Used = i + 1;
        else
            Discard(TlsData, Info->ThreadData[i].NewTlsData);
    }

    if (!Used)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
        return NT_SUCCESS(Status) ? STATUS_SUCCESS : Status;
    }

    Info->ThreadDataCount = Used;
    *Result = Info;
    return Status;
}

/* PROCESS_TLS_REPLACE_VECTOR: a vector one entry longer, with the new block at the end */
static
NTSTATUS
LdrpPrepareTlsVector(
    _In_ PLDRP_TLS_DATA TlsData,
    _Out_ PVOID *NewTlsData)
{
    PVOID *Vector;

    Vector = LdrpAllocateTlsVectorEntries(TlsData->Index + 1);
    if (!Vector)
        return STATUS_NO_MEMORY;

    Vector[TlsData->Index] = LdrpAllocateTlsBlock(TlsData);
    if (!Vector[TlsData->Index])
    {
        LdrpFreeTlsVectorEntries(Vector);
        return STATUS_NO_MEMORY;
    }

    *NewTlsData = Vector;
    return STATUS_SUCCESS;
}

static
VOID
LdrpDiscardTlsVector(
    _In_ PLDRP_TLS_DATA TlsData,
    _In_opt_ PVOID NewTlsData)
{
    PVOID *Vector = NewTlsData;

    if (!Vector)
        return;
    LdrpFreeTlsBlock(TlsData, Vector[TlsData->Index]);
    LdrpFreeTlsVectorEntries(Vector);
}

/* PROCESS_TLS_REPLACE_INDEX on a free index: just the new block */
static
NTSTATUS
LdrpPrepareTlsBlock(
    _In_ PLDRP_TLS_DATA TlsData,
    _Out_ PVOID *NewTlsData)
{
    *NewTlsData = LdrpAllocateTlsBlock(TlsData);
    return *NewTlsData ? STATUS_SUCCESS : STATUS_NO_MEMORY;
}

static
VOID
LdrpDiscardTlsBlock(
    _In_ PLDRP_TLS_DATA TlsData,
    _In_opt_ PVOID NewTlsData)
{
    LdrpFreeTlsBlock(TlsData, NewTlsData);
}

/* PROCESS_TLS_REPLACE_INDEX to empty an index: nothing to prepare */
static
NTSTATUS
LdrpPrepareNoTls(
    _In_ PLDRP_TLS_DATA TlsData,
    _Out_ PVOID *NewTlsData)
{
    *NewTlsData = NULL;
    return STATUS_SUCCESS;
}

static
VOID
LdrpDiscardNoTls(
    _In_ PLDRP_TLS_DATA TlsData,
    _In_opt_ PVOID NewTlsData)
{
}

/* Old vectors from PROCESS_TLS_REPLACE_VECTOR: the loading thread's goes at once, the others' when their thread ends */
static
VOID
LdrpRetireTlsVectors(
    _In_ PPROCESS_TLS_INFORMATION Info)
{
    PLDRP_RETIRED_TLS_VECTOR Entry;
    ULONG i;

    for (i = 0; i < Info->ThreadDataCount; i++)
    {
        if (!(Info->ThreadData[i].Flags & THREAD_TLS_INFORMATION_ASSIGNED) || !Info->ThreadData[i].OldTlsData)
            continue;

        if (Info->ThreadData[i].ThreadId == NtCurrentTeb()->RealClientId.UniqueThread)
        {
            LdrpFreeTlsVectorEntries(Info->ThreadData[i].OldTlsData);
            continue;
        }

        Entry = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Entry));
        if (!Entry)
        {
            /* Not freeing it is all that can be done safely */
            DPRINT1("LDR: Keeping an old TLS vector of thread %p\n", Info->ThreadData[i].ThreadId);
            continue;
        }
        Entry->ThreadId = Info->ThreadData[i].ThreadId;
        Entry->TlsVector = Info->ThreadData[i].OldTlsData;
        InsertTailList(&LdrpRetiredTlsVectors, &Entry->Links);
    }
}

/* Sets up the TLS of a module with a TLS directory that is loaded after process start */
NTSTATUS
NTAPI
LdrpAddDynamicTls(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _In_ PIMAGE_TLS_DIRECTORY TlsDirectory)
{
    PPROCESS_TLS_INFORMATION Info;
    PLDRP_TLS_DATA TlsData;
    PULONG FreeIndexes;
    BOOLEAN NewIndex;
    LONG OldIndexValue = 0;
    NTSTATUS Status;

    LdrpEnsureLoaderLockIsHeld();

    TlsData = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(LDRP_TLS_DATA));
    if (!TlsData)
        return STATUS_NO_MEMORY;

    Status = LdrpCaptureTlsDirectory(LdrEntry, TlsDirectory, TlsData);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, TlsData);
        return Status;
    }

    /* A free index below the limit: every vector has that entry already. Otherwise vectors grow by one. */
    NewIndex = (LdrpFreeTlsIndexCount == 0);
    TlsData->Index = NewIndex ? LdrpTlsIndexLimit : LdrpFreeTlsIndexes[LdrpFreeTlsIndexCount - 1];

    if (ShowSnaps)
    {
        DPRINT1("LDR: Tls Found in %wZ at %p, loaded after process start: index %lu\n",
                &LdrEntry->BaseDllName, TlsDirectory, TlsData->Index);
    }

    if (NewIndex)
    {
        /* Room to record the index as free again when the module unloads */
        FreeIndexes = LdrpFreeTlsIndexes ?
            RtlReAllocateHeap(RtlGetProcessHeap(), 0, LdrpFreeTlsIndexes, (LdrpTlsIndexLimit + 1) * sizeof(ULONG)) :
            RtlAllocateHeap(RtlGetProcessHeap(), 0, (LdrpTlsIndexLimit + 1) * sizeof(ULONG));
        if (!FreeIndexes)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, TlsData);
            return STATUS_NO_MEMORY;
        }
        LdrpFreeTlsIndexes = FreeIndexes;
    }

    /* The module's index variable must be writable: set it before anything is published */
    _SEH2_TRY
    {
        OldIndexValue = *(volatile LONG *)TlsData->TlsDirectory.AddressOfIndex;
        *(volatile LONG *)TlsData->TlsDirectory.AddressOfIndex = TlsData->Index;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, TlsData);
        return Status;
    }

    Status = LdrpChangeThreadsTls(NewIndex ? PROCESS_TLS_REPLACE_VECTOR : PROCESS_TLS_REPLACE_INDEX,
                                  TlsData,
                                  NewIndex ? LdrpPrepareTlsVector : LdrpPrepareTlsBlock,
                                  NewIndex ? LdrpDiscardTlsVector : LdrpDiscardTlsBlock,
                                  &Info);
    if (Info)
    {
        /* Threads the kernel changed keep their new vector or block */
        if (NewIndex)
            LdrpRetireTlsVectors(Info);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
    }

    if (!NT_SUCCESS(Status))
    {
        /*
         * If the kernel stopped part way, some threads have the module's
         * block at the index and others do not: the index is never handed
         * out again (the blocks stay where they are). The module is not
         * loaded, so nothing uses them.
         */
        if (Info)
        {
            if (NewIndex)
                LdrpTlsIndexLimit++;
            else
                LdrpFreeTlsIndexCount--;
        }
        _SEH2_TRY
        {
            *(volatile LONG *)TlsData->TlsDirectory.AddressOfIndex = OldIndexValue;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;
        RtlFreeHeap(RtlGetProcessHeap(), 0, TlsData);
        return Status;
    }

    if (NewIndex)
        LdrpTlsIndexLimit++;
    else
        LdrpFreeTlsIndexCount--;

    /* Publish the module to threads that start from now on */
    InsertTailList(&LdrpTlsList, &TlsData->TlsLinks);
    LdrpNumberOfTlsEntries++;

    /* Mark the module for TLS use */
    LdrEntry->TlsIndex = -1;
    return STATUS_SUCCESS;
}

/* Frees the TLS of a module loaded after process start, when it is unloaded */
VOID
NTAPI
LdrpRemoveDynamicTls(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PPROCESS_TLS_INFORMATION Info;
    PLIST_ENTRY NextEntry;
    PLDRP_TLS_DATA TlsData = NULL;
    NTSTATUS Status;
    ULONG i;

    LdrpEnsureLoaderLockIsHeld();

    for (NextEntry = LdrpTlsList.Flink; NextEntry != &LdrpTlsList; NextEntry = NextEntry->Flink)
    {
        if (CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks)->Module == LdrEntry)
        {
            TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks);
            break;
        }
    }
    if (!TlsData)
        return;

    /* The module goes from the list first: threads that start now do not get its block */
    RemoveEntryList(&TlsData->TlsLinks);
    LdrpNumberOfTlsEntries--;

    /* Take the module's block out of every thread's vector */
    Status = LdrpChangeThreadsTls(PROCESS_TLS_REPLACE_INDEX, TlsData, LdrpPrepareNoTls, LdrpDiscardNoTls, &Info);
    if (Info)
    {
        for (i = 0; i < Info->ThreadDataCount; i++)
        {
            if (Info->ThreadData[i].Flags & THREAD_TLS_INFORMATION_ASSIGNED)
                LdrpFreeTlsBlock(TlsData, Info->ThreadData[i].OldTlsData);
        }
        RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
    }

    if (NT_SUCCESS(Status))
    {
        LdrpFreeTlsIndexes[LdrpFreeTlsIndexCount++] = TlsData->Index;
    }
    else
    {
        /* Blocks may be left in some vectors: the index is never handed out again, those blocks stay */
        DPRINT1("LDR: Cannot free the TLS of %wZ: 0x%08lx\n", &LdrEntry->BaseDllName, Status);
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, TlsData);
}

NTSTATUS
NTAPI
LdrpInitializeExecutionOptions(PUNICODE_STRING ImagePathName, PPEB Peb, PHANDLE OptionsKey)
{
    NTSTATUS Status;
    HANDLE KeyHandle;
    ULONG ExecuteOptions, MinimumStackCommit = 0, GlobalFlag;

    /* Return error if we were not provided a pointer where to save the options key handle */
    if (!OptionsKey) return STATUS_INVALID_HANDLE;

    /* Zero initialize the options key pointer */
    *OptionsKey = NULL;

    /* Open the options key */
    Status = LdrOpenImageFileOptionsKey(ImagePathName, 0, &KeyHandle);

    /* Save it if it was opened successfully */
    if (NT_SUCCESS(Status))
        *OptionsKey = KeyHandle;

    if (KeyHandle)
    {
        /* There are image specific options, read them starting with NXCOMPAT */
        Status = LdrQueryImageFileKeyOption(KeyHandle,
                                            L"ExecuteOptions",
                                            4,
                                            &ExecuteOptions,
                                            sizeof(ExecuteOptions),
                                            0);

        if (NT_SUCCESS(Status))
        {
            /* TODO: Set execution options for the process */
            /*
            if (ExecuteOptions == 0)
                ExecuteOptions = 1;
            else
                ExecuteOptions = 2;
            ZwSetInformationProcess(NtCurrentProcess(),
                                    ProcessExecuteFlags,
                                    &ExecuteOptions,
                                    sizeof(ULONG));*/

        }

        /* Check if this image uses large pages */
        if (Peb->ImageUsesLargePages)
        {
            /* TODO: If it does, open large page key */
            UNIMPLEMENTED;
        }

        /* Get various option values */
        LdrQueryImageFileKeyOption(KeyHandle,
                                   L"DisableHeapLookaside",
                                   REG_DWORD,
                                   &RtlpDisableHeapLookaside,
                                   sizeof(RtlpDisableHeapLookaside),
                                   NULL);

        LdrQueryImageFileKeyOption(KeyHandle,
                                   L"ShutdownFlags",
                                   REG_DWORD,
                                   &RtlpShutdownProcessFlags,
                                   sizeof(RtlpShutdownProcessFlags),
                                   NULL);

        LdrQueryImageFileKeyOption(KeyHandle,
                                   L"MinimumStackCommitInBytes",
                                   REG_DWORD,
                                   &MinimumStackCommit,
                                   sizeof(MinimumStackCommit),
                                   NULL);

        /* Update PEB's minimum stack commit if it's lower */
        if (Peb->MinimumStackCommit < MinimumStackCommit)
            Peb->MinimumStackCommit = MinimumStackCommit;

        /* Set the global flag */
        Status = LdrQueryImageFileKeyOption(KeyHandle,
                                            L"GlobalFlag",
                                            REG_DWORD,
                                            &GlobalFlag,
                                            sizeof(GlobalFlag),
                                            NULL);

        if (NT_SUCCESS(Status))
            Peb->NtGlobalFlag = GlobalFlag;
        else
            GlobalFlag = 0;

        /* Call AVRF if necessary */
        if (Peb->NtGlobalFlag & (FLG_APPLICATION_VERIFIER | FLG_HEAP_PAGE_ALLOCS))
        {
            Status = LdrpInitializeApplicationVerifierPackage(KeyHandle, Peb, FALSE, FALSE);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("AVRF: LdrpInitializeApplicationVerifierPackage failed with %08X\n", Status);
            }
        }
    }
    else
    {
        /* There are no image-specific options, so perform global initialization */
        if (Peb->NtGlobalFlag & (FLG_APPLICATION_VERIFIER | FLG_HEAP_PAGE_ALLOCS))
        {
            /* Initialize app verifier package */
            Status = LdrpInitializeApplicationVerifierPackage(KeyHandle, Peb, TRUE, FALSE);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("AVRF: LdrpInitializeApplicationVerifierPackage failed with %08X\n", Status);
            }
        }
    }

    return STATUS_SUCCESS;
}

VOID
NTAPI
LdrpValidateImageForMp(IN PLDR_DATA_TABLE_ENTRY LdrDataTableEntry)
{
    DPRINT("LdrpValidateImageForMp is unimplemented\n");
    // TODO:
    // Scan the LockPrefixTable in the load config directory
}

BOOLEAN
NTAPI
LdrpDisableProcessCompatGuidDetection(VOID)
{
    UNICODE_STRING PolicyKey = RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat");
    UNICODE_STRING DisableDetection = RTL_CONSTANT_STRING(L"DisableCompatGuidDetection");
    OBJECT_ATTRIBUTES PolicyKeyAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&PolicyKey, OBJ_CASE_INSENSITIVE);
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    ULONG ResultLength;
    NTSTATUS Status;
    HANDLE KeyHandle;

    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &PolicyKeyAttributes);
    if (NT_SUCCESS(Status))
    {
        Status = NtQueryValueKey(KeyHandle,
                                 &DisableDetection,
                                 KeyValuePartialInformation,
                                 &KeyInfo,
                                 sizeof(KeyInfo),
                                 &ResultLength);
        NtClose(KeyHandle);
        if ((NT_SUCCESS(Status)) &&
            (KeyInfo.Type == REG_DWORD) &&
            (KeyInfo.DataLength == sizeof(ULONG)) &&
            (KeyInfo.Data[0] == TRUE))
        {
            return TRUE;
        }
    }
    return FALSE;
}


/* Highest manifest compat version we select (the Windows version we emulate) */
#define LDRP_COMPAT_CEILING _WIN32_WINNT_WIN7

VOID
NTAPI
LdrpInitializeProcessCompat(PVOID pProcessActctx, PVOID* pOldShimData)
{
    static const struct
    {
        const GUID* Guid;
        const DWORD Version;
    } KnownCompatGuids[] = {
        { &COMPAT_GUID_WIN10, _WIN32_WINNT_WIN10 },
        { &COMPAT_GUID_WIN81, _WIN32_WINNT_WINBLUE },
        { &COMPAT_GUID_WIN8, _WIN32_WINNT_WIN8 },
        { &COMPAT_GUID_WIN7, _WIN32_WINNT_WIN7 },
        { &COMPAT_GUID_VISTA, _WIN32_WINNT_VISTA },
    };

    ULONG Buffer[(sizeof(COMPATIBILITY_CONTEXT_ELEMENT) * 10 + sizeof(ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION)) / sizeof(ULONG)];
    ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION* ContextCompatInfo;
    SIZE_T SizeRequired;
    NTSTATUS Status;
    DWORD n, cur, i, pass;
    ReactOS_ShimData* pShimData = *pOldShimData;

    if (pShimData)
    {
        if (pShimData->dwMagic != REACTOS_SHIMDATA_MAGIC ||
            pShimData->dwSize != sizeof(ReactOS_ShimData))
        {
            DPRINT1("LdrpInitializeProcessCompat: Corrupt pShimData (0x%x, %u)\n", pShimData->dwMagic, pShimData->dwSize);
            return;
        }
#ifdef _M_AMD64
        pShimData->RtlGetCurrentDirectory_U_RtlpMsysDecoy = &RtlGetCurrentDirectory_U_RtlpMsysDecoy;   /* We need this private symbol for a MSYS shim */
#endif
        if (pShimData->dwRosProcessCompatVersion)
        {
            if (pShimData->dwRosProcessCompatVersion == REACTOS_COMPATVERSION_IGNOREMANIFEST)
            {
                DPRINT1("LdrpInitializeProcessCompat: ProcessCompatVersion set to ignore manifest\n");
            }
            else
            {
                DPRINT1("LdrpInitializeProcessCompat: ProcessCompatVersion already set to 0x%x\n", pShimData->dwRosProcessCompatVersion);
            }
            return;
        }
    }

    SizeRequired = sizeof(Buffer);
    Status = RtlQueryInformationActivationContext(RTL_QUERY_ACTIVATION_CONTEXT_FLAG_NO_ADDREF,
                                                  pProcessActctx,
                                                  NULL,
                                                  CompatibilityInformationInActivationContext,
                                                  Buffer,
                                                  sizeof(Buffer),
                                                  &SizeRequired);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("LdrpInitializeProcessCompat: Unable to query process actctx with status %x\n", Status);
        return;
    }

    ContextCompatInfo = (ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION*)Buffer;
    /* No Compatibility elements present, bail out */
    if (ContextCompatInfo->ElementCount == 0)
        return;

    /* Pick the highest declared supportedOS GUID that we are willing to report.
       Windows reports the highest supportedOS from the manifest that the host
       supports, so a Vista..Win10 manifest reports 6.1 on Windows 7 (Burn-based
       installers gate on VersionNT >= 6.1).
       ReactOS does not claim more than Windows 7, so GUIDs above that are skipped
       while a lower declared one exists: a manifest that also lists Win8/8.1/10
       must not make the process take Win10-only code paths we do not implement.
       If nothing at or below the ceiling is declared, fall back to the lowest
       declared GUID (the previous behavior).
       Pass 0: newest to oldest, ceiling applied. Pass 1: oldest to newest. */
    for (pass = 0; pass < 2; ++pass)
    for (i = 0; i < RTL_NUMBER_OF(KnownCompatGuids); ++i)
    {
        cur = (pass == 0) ? i : (RTL_NUMBER_OF(KnownCompatGuids) - 1 - i);
        if (pass == 0 && KnownCompatGuids[cur].Version > LDRP_COMPAT_CEILING)
            continue;

        for (n = 0; n < ContextCompatInfo->ElementCount; ++n)
        {
            if (ContextCompatInfo->Elements[n].Type == ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS &&
                RtlCompareMemory(&ContextCompatInfo->Elements[n].Id, KnownCompatGuids[cur].Guid, sizeof(GUID)) == sizeof(GUID))
            {
                if (LdrpDisableProcessCompatGuidDetection())
                {
                    DPRINT1("LdrpInitializeProcessCompat: Not applying automatic fix for winver 0x%x due to policy\n", KnownCompatGuids[cur].Version);
                    return;
                }

                /* If this process did not need shim data before, allocate and store it */
                if (pShimData == NULL)
                {
                    PPEB Peb = NtCurrentPeb();

                    ASSERT(Peb->pShimData == NULL);
                    pShimData = RtlAllocateHeap(Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(*pShimData));

                    if (!pShimData)
                    {
                        DPRINT1("LdrpInitializeProcessCompat: Unable to allocated %u bytes\n", sizeof(*pShimData));
                        return;
                    }

                    pShimData->dwSize = sizeof(*pShimData);
                    pShimData->dwMagic = REACTOS_SHIMDATA_MAGIC;
#ifdef _M_AMD64
                    /* The process did not ask for shims, but we want to make sure that if the Peb->pShimData is available, the data in it is complete */
                    pShimData->RtlGetCurrentDirectory_U_RtlpMsysDecoy = &RtlGetCurrentDirectory_U_RtlpMsysDecoy;
#endif

                    Peb->pShimData = pShimData;
                    *pOldShimData = pShimData;
                }

                /* Store the selected version, and bail out. */
                pShimData->dwRosProcessCompatVersion = KnownCompatGuids[cur].Version;
                DPRINT("LdrpInitializeProcessCompat: Found guid for winver 0x%x in manifest from %wZ\n",
                        KnownCompatGuids[cur].Version,
                        &(NtCurrentPeb()->ProcessParameters->ImagePathName));
                return;
            }
        }
    }
}

VOID
NTAPI
LdrpInitializeDotLocalSupport(PRTL_USER_PROCESS_PARAMETERS ProcessParameters)
{
    UNICODE_STRING ImagePathName = ProcessParameters->ImagePathName;
    WCHAR LocalBuffer[MAX_PATH];
    UNICODE_STRING DotLocal;
    NTSTATUS Status;
    ULONG RequiredSize;

    RequiredSize = ImagePathName.Length + LdrpDotLocal.Length + sizeof(UNICODE_NULL);
    if (RequiredSize <= sizeof(LocalBuffer))
    {
        RtlInitEmptyUnicodeString(&DotLocal, LocalBuffer, sizeof(LocalBuffer));
    }
    else if (RequiredSize <= UNICODE_STRING_MAX_BYTES)
    {
        DotLocal.Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, RequiredSize);
        DotLocal.Length = 0;
        DotLocal.MaximumLength = RequiredSize;
        if (!DotLocal.Buffer)
            DPRINT1("LDR: Failed to allocate memory for .local check\n");
    }
    else
    {
        DotLocal.Buffer = NULL;
        DotLocal.Length = 0;
        DotLocal.MaximumLength = 0;
        DPRINT1("LDR: String too big for .local check\n");
    }

    if (DotLocal.Buffer)
    {
        Status = RtlAppendUnicodeStringToString(&DotLocal, &ImagePathName);
        ASSERT(NT_SUCCESS(Status));
        if (NT_SUCCESS(Status))
        {
            Status = RtlAppendUnicodeStringToString(&DotLocal, &LdrpDotLocal);
            ASSERT(NT_SUCCESS(Status));
        }

        if (NT_SUCCESS(Status))
        {
            if (RtlDoesFileExists_UStr(&DotLocal))
            {
                ProcessParameters->Flags |= RTL_USER_PROCESS_PARAMETERS_PRIVATE_DLL_PATH;
            }
        }
        else
        {
            DPRINT1("LDR: Failed to append: 0x%lx\n", Status);
        }

        if (DotLocal.Buffer != LocalBuffer)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, DotLocal.Buffer);
        }
    }
}


NTSTATUS
NTAPI
LdrpInitializeProcess(IN PCONTEXT Context,
                      IN PVOID SystemArgument1)
{
    RTL_HEAP_PARAMETERS HeapParameters;
    ULONG ComSectionSize;
    ANSI_STRING BaseProcessInitPostImportName = RTL_CONSTANT_STRING("BaseProcessInitPostImport");
    ANSI_STRING BaseQueryModuleDataName = RTL_CONSTANT_STRING("BaseQueryModuleData");
    PVOID OldShimData;
    OBJECT_ATTRIBUTES ObjectAttributes;
    //UNICODE_STRING LocalFileName, FullImageName;
    HANDLE SymLinkHandle;
    //ULONG DebugHeapOnly;
    UNICODE_STRING CommandLine, NtSystemRoot, ImagePathName, FullPath, ImageFileName, KnownDllString;
    PPEB Peb = NtCurrentPeb();
    BOOLEAN IsDotNetImage = FALSE;
    BOOLEAN FreeCurDir = FALSE;
    //HANDLE CompatKey;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    //LPWSTR ImagePathBuffer;
    ULONG ConfigSize;
    UNICODE_STRING CurrentDirectory;
    HANDLE OptionsKey;
    ULONG HeapFlags;
    PIMAGE_NT_HEADERS NtHeader;
#ifdef BUILD_WOW64_ENABLED
    IMAGE_NT_HEADERS NativeHeader;
    BOOLEAN IsWow64 = FALSE;
#endif
#ifdef _WIN64
    BOOLEAN IsAnyCpuImage = FALSE;
#endif
    LPWSTR NtDllName = NULL;
    NTSTATUS Status, ImportStatus;
    NLSTABLEINFO NlsTable;
    PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfig;
    PTEB Teb = NtCurrentTeb();
    PLIST_ENTRY ListHead;
    PLIST_ENTRY NextEntry;
    ULONG i;
    PWSTR ImagePath;
    ULONG DebugProcessHeapOnly = 0;
    PLDR_DATA_TABLE_ENTRY NtLdrEntry;
    PWCHAR Current;
    ULONG ExecuteOptions = 0;
    PVOID ViewBase;

    /* Set a NULL SEH Filter */
    RtlSetUnhandledExceptionFilter(NULL);

    /* Get the image path */
    ImagePath = Peb->ProcessParameters->ImagePathName.Buffer;

    /* Check if it's not normalized */
    if (!(Peb->ProcessParameters->Flags & RTL_USER_PROCESS_PARAMETERS_NORMALIZED))
    {
        /* Normalize it*/
        ImagePath = (PWSTR)((ULONG_PTR)ImagePath + (ULONG_PTR)Peb->ProcessParameters);
    }

    /* Create a unicode string for the Image Path */
    ImagePathName.Length = Peb->ProcessParameters->ImagePathName.Length;
    ImagePathName.MaximumLength = ImagePathName.Length + sizeof(WCHAR);
    ImagePathName.Buffer = ImagePath;

    /* Get the NT Headers */
    NtHeader = RtlImageNtHeader(Peb->ImageBaseAddress);

#ifdef _WIN64
    /* A PE32 image in a process that the kernel did not start under WOW64 is an AnyCPU .NET executable (IL-only,
     * neither requiring nor preferring 32 bits). As Windows does, rewrite its headers to PE32+ as for such a DLL:
     * it is not relocated, its PE32 imports are not snapped, and instead of its x86 entry stub the process starts
     * at mscoree!_CorExeMain. */
    if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        ULONG_PTR Wow64Peb = 0;

        Status = NtQueryInformationProcess(NtCurrentProcess(),
                                           ProcessWow64Information,
                                           &Wow64Peb,
                                           sizeof(Wow64Peb),
                                           NULL);
        if (NT_SUCCESS(Status) && !Wow64Peb)
        {
            if (!LdrpCorFixupIlOnlyImage(Peb->ImageBaseAddress, NtHeader))
            {
                DPRINT1("LDR: %wZ is a 32-bit image in a 64-bit process\n", &ImagePathName);
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (ShowSnaps)
            {
                DPRINT1("LDR: %wZ is an AnyCPU .NET image, its headers are now PE32+\n", &ImagePathName);
            }
            IsAnyCpuImage = TRUE;
            NtHeader = RtlImageNtHeader(Peb->ImageBaseAddress);
        }
    }
#endif

#ifdef BUILD_WOW64_ENABLED
    IsWow64 = NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    LdrpIsWow64 = IsWow64;
    if (IsWow64)
    {
        /* The native runtime owns its own heap and loader. Never interpret
         * PE32 pointer-sized optional-header fields as PE32+. */
        PIMAGE_NT_HEADERS32 Header32 = (PIMAGE_NT_HEADERS32)NtHeader;
        NativeHeader = *(PIMAGE_NT_HEADERS)RtlImageNtHeader(SystemArgument1);
        NativeHeader.OptionalHeader.SizeOfHeapReserve = Header32->OptionalHeader.SizeOfHeapReserve;
        NativeHeader.OptionalHeader.SizeOfHeapCommit = Header32->OptionalHeader.SizeOfHeapCommit;
        NativeHeader.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_NATIVE;
        NtHeader = &NativeHeader;
    }
#endif

    /* Get the execution options */
    Status = LdrpInitializeExecutionOptions(&ImagePathName, Peb, &OptionsKey);

    /* Check if this is a .NET executable */
    if (RtlImageDirectoryEntryToData(Peb->ImageBaseAddress,
                                     TRUE,
                                     IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
                                     &ComSectionSize))
    {
        /* Remember this for later */
        IsDotNetImage = TRUE;
    }

    /* Save the NTDLL Base address */
    NtDllBase = SystemArgument1;

    /* If this is a Native Image */
    if (NtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE)
    {
        /* Then do DLL Validation */
        LdrpDllValidation = TRUE;
    }

    /* Save the old Shim Data */
    OldShimData = Peb->pShimData;

    /* ReactOS specific: do not clear it. (Windows starts doing the same in later versions) */
    //Peb->pShimData = NULL;

    /* Save the number of processors and CS timeout */
    LdrpNumberOfProcessors = Peb->NumberOfProcessors;
    RtlpTimeout = Peb->CriticalSectionTimeout;

    /* Normalize the parameters */
    ProcessParameters = RtlNormalizeProcessParams(Peb->ProcessParameters);
    if (ProcessParameters)
    {
        /* Save the Image and Command Line Names */
        ImageFileName = ProcessParameters->ImagePathName;
        CommandLine = ProcessParameters->CommandLine;
    }
    else
    {
        /* It failed, initialize empty strings */
        RtlInitUnicodeString(&ImageFileName, NULL);
        RtlInitUnicodeString(&CommandLine, NULL);
    }

    /* Initialize NLS data */
    RtlInitNlsTables(Peb->AnsiCodePageData,
                     Peb->OemCodePageData,
                     Peb->UnicodeCaseTableData,
                     &NlsTable);

    /* Reset NLS Translations */
    RtlResetRtlTranslations(&NlsTable);

    /* Get the Image Config Directory */
    LoadConfig = RtlImageDirectoryEntryToData(Peb->ImageBaseAddress,
                                              TRUE,
                                              IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
                                              &ConfigSize);

#ifdef BUILD_WOW64_ENABLED
    if (IsWow64) LoadConfig = NULL;
#endif

    /* Setup the Heap Parameters */
    RtlZeroMemory(&HeapParameters, sizeof(HeapParameters));
    HeapFlags = HEAP_GROWABLE;
    HeapParameters.Length = sizeof(HeapParameters);

    /* Check if we have Configuration Data */
#define VALID_CONFIG_FIELD(Name) (ConfigSize >= RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY, Name))
    /* The 'original' load config ends after SecurityCookie */
    if ((LoadConfig) && ConfigSize && (VALID_CONFIG_FIELD(SecurityCookie) || ConfigSize == LoadConfig->Size))
    {
        if (ConfigSize != sizeof(IMAGE_LOAD_CONFIG_DIRECTORY))
            DPRINT1("WARN: Accepting different LOAD_CONFIG size!\n");
        else
            DPRINT1("Applying LOAD_CONFIG\n");

        if (VALID_CONFIG_FIELD(GlobalFlagsSet) && LoadConfig->GlobalFlagsSet)
            Peb->NtGlobalFlag |= LoadConfig->GlobalFlagsSet;

        if (VALID_CONFIG_FIELD(GlobalFlagsClear) && LoadConfig->GlobalFlagsClear)
            Peb->NtGlobalFlag &= ~LoadConfig->GlobalFlagsClear;

        /* Convert the default CS timeout from milliseconds to 100ns units */
        if (VALID_CONFIG_FIELD(CriticalSectionDefaultTimeout) && LoadConfig->CriticalSectionDefaultTimeout)
            RtlpTimeout.QuadPart = Int32x32To64(LoadConfig->CriticalSectionDefaultTimeout, -10000);

        if (VALID_CONFIG_FIELD(DeCommitFreeBlockThreshold) && LoadConfig->DeCommitFreeBlockThreshold)
            HeapParameters.DeCommitFreeBlockThreshold = LoadConfig->DeCommitFreeBlockThreshold;

        if (VALID_CONFIG_FIELD(DeCommitTotalFreeThreshold) && LoadConfig->DeCommitTotalFreeThreshold)
            HeapParameters.DeCommitTotalFreeThreshold = LoadConfig->DeCommitTotalFreeThreshold;

        if (VALID_CONFIG_FIELD(MaximumAllocationSize) && LoadConfig->MaximumAllocationSize)
            HeapParameters.MaximumAllocationSize = LoadConfig->MaximumAllocationSize;

        if (VALID_CONFIG_FIELD(VirtualMemoryThreshold) && LoadConfig->VirtualMemoryThreshold)
            HeapParameters.VirtualMemoryThreshold = LoadConfig->VirtualMemoryThreshold;

        if (VALID_CONFIG_FIELD(ProcessHeapFlags) && LoadConfig->ProcessHeapFlags)
            HeapFlags = LoadConfig->ProcessHeapFlags;
    }
#undef VALID_CONFIG_FIELD

    /* Check for custom affinity mask */
    if (Peb->ImageProcessAffinityMask)
    {
        /* Set it */
        Status = NtSetInformationProcess(NtCurrentProcess(),
                                         ProcessAffinityMask,
                                         &Peb->ImageProcessAffinityMask,
                                         sizeof(Peb->ImageProcessAffinityMask));
    }

    /* Check if verbose debugging (ShowSnaps) was requested */
    ShowSnaps = Peb->NtGlobalFlag & FLG_SHOW_LDR_SNAPS;

    /* Start verbose debugging messages right now if they were requested */
    if (ShowSnaps)
    {
        DPRINT1("LDR: PID: 0x%p started - '%wZ'\n",
                Teb->ClientId.UniqueProcess,
                &CommandLine);
    }

    /* If the CS timeout is longer than 1 hour, disable it */
    if (RtlpTimeout.QuadPart < Int32x32To64(3600, -10000000))
        RtlpTimeoutDisable = TRUE;

    /* Initialize Critical Section Data */
    RtlpInitDeferredCriticalSection();

    /* Initialize VEH Call lists */
    RtlpInitializeVectoredExceptionHandling();

    /* Set TLS/FLS Bitmap data */
    Peb->FlsBitmap = &FlsBitMap;
    Peb->TlsBitmap = &TlsBitMap;
    Peb->TlsExpansionBitmap = &TlsExpansionBitMap;

    /* Initialize FLS Bitmap */
    RtlInitializeBitMap(&FlsBitMap,
                        Peb->FlsBitmapBits,
                        FLS_MAXIMUM_AVAILABLE);
    RtlSetBit(&FlsBitMap, 0);
    InitializeListHead(&Peb->FlsListHead);

    /* Initialize TLS Bitmap */
    RtlInitializeBitMap(&TlsBitMap,
                        Peb->TlsBitmapBits,
                        TLS_MINIMUM_AVAILABLE);
    RtlSetBit(&TlsBitMap, 0);
#ifdef BUILD_WOW64_ENABLED
    if (IsWow64) RtlSetBit(&TlsBitMap, 1); /* WOW64_TLS_CPU */
#endif
    RtlInitializeBitMap(&TlsExpansionBitMap,
                        Peb->TlsExpansionBitmapBits,
                        TLS_EXPANSION_SLOTS);
    RtlSetBit(&TlsExpansionBitMap, 0);

    /* Initialize the Hash Table */
    for (i = 0; i < LDR_HASH_TABLE_ENTRIES; i++)
    {
        InitializeListHead(&LdrpHashTable[i]);
    }

    /* Initialize the Loader Lock */
    // FIXME: What's the point of initing it manually, if two lines lower
    //        a call to RtlInitializeCriticalSection() is being made anyway?
    //InsertTailList(&RtlCriticalSectionList, &LdrpLoaderLock.DebugInfo->ProcessLocksList);
    //LdrpLoaderLock.DebugInfo->CriticalSection = &LdrpLoaderLock;
    RtlInitializeCriticalSection(&LdrpLoaderLock);
    LdrpLoaderLockInit = TRUE;

    /* Check if User Stack Trace Database support was requested */
    if (Peb->NtGlobalFlag & FLG_USER_STACK_TRACE_DB)
    {
        DPRINT1("We don't support user stack trace databases yet\n");
    }

    /* Setup Fast PEB Lock */
    RtlInitializeCriticalSection(&FastPebLock);
    Peb->FastPebLock = &FastPebLock;
    //Peb->FastPebLockRoutine = (PPEBLOCKROUTINE)RtlEnterCriticalSection;
    //Peb->FastPebUnlockRoutine = (PPEBLOCKROUTINE)RtlLeaveCriticalSection;

    /* Setup Callout Lock */
    //RtlInitializeCriticalSection(&RtlpCalloutEntryLock);

    /* For old executables, use 16-byte aligned heap */
    if ((NtHeader->OptionalHeader.MajorSubsystemVersion <= 3) &&
        (NtHeader->OptionalHeader.MinorSubsystemVersion < 51))
    {
        HeapFlags |= HEAP_CREATE_ALIGN_16;
    }

    /* Setup the Heap */
    RtlInitializeHeapManager();
    Peb->ProcessHeap = RtlCreateHeap(HeapFlags,
                                     NULL,
                                     NtHeader->OptionalHeader.SizeOfHeapReserve,
                                     NtHeader->OptionalHeader.SizeOfHeapCommit,
                                     NULL,
                                     &HeapParameters);

    if (!Peb->ProcessHeap)
    {
        DPRINT1("Failed to create process heap\n");
        return STATUS_NO_MEMORY;
    }

    Status = RtlpInitializeLocaleTable();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to initialize locale table\n");
        return Status;
    }

    /* Allocate an Activation Context Stack */
    Status = RtlAllocateActivationContextStack(&Teb->ActivationContextStackPointer);
    if (!NT_SUCCESS(Status)) return Status;

    RtlZeroMemory(&HeapParameters, sizeof(HeapParameters));
    HeapFlags = HEAP_GROWABLE | HEAP_CLASS_1;
    HeapParameters.Length = sizeof(HeapParameters);
    LdrpHeap = RtlCreateHeap(HeapFlags, 0, 0x10000, 0x6000, 0, &HeapParameters);
    if (!LdrpHeap)
    {
        DPRINT1("Failed to create loader private heap\n");
        return STATUS_NO_MEMORY;
    }

    /* Check for Debug Heap */
    if (OptionsKey)
    {
        /* Query the setting */
        Status = LdrQueryImageFileKeyOption(OptionsKey,
                                            L"DebugProcessHeapOnly",
                                            REG_DWORD,
                                            &DebugProcessHeapOnly,
                                            sizeof(ULONG),
                                            NULL);

        if (NT_SUCCESS(Status))
        {
            /* Reset DPH if requested */
            if (RtlpPageHeapEnabled && DebugProcessHeapOnly)
            {
                RtlpDphGlobalFlags &= ~DPH_FLAG_DLL_NOTIFY;
                RtlpPageHeapEnabled = FALSE;
            }
        }
    }

    /* Build the NTDLL Path */
    FullPath.Buffer = StringBuffer;
    FullPath.Length = 0;
    FullPath.MaximumLength = sizeof(StringBuffer);
    RtlInitUnicodeString(&NtSystemRoot, SharedUserData->NtSystemRoot);
    RtlAppendUnicodeStringToString(&FullPath, &NtSystemRoot);
#ifdef _M_IX86
    if (NtCurrentTeb()->WOW32Reserved)
        RtlAppendUnicodeToString(&FullPath, L"\\SysWOW64\\");
    else
#endif
    RtlAppendUnicodeToString(&FullPath, L"\\System32\\");

    /* Open the Known DLLs directory */
#ifdef _M_IX86
    if (NtCurrentTeb()->WOW32Reserved)
        RtlInitUnicodeString(&KnownDllString, L"\\KnownDlls32");
    else
#endif
    RtlInitUnicodeString(&KnownDllString, L"\\KnownDlls");
    InitializeObjectAttributes(&ObjectAttributes,
                               &KnownDllString,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = ZwOpenDirectoryObject(&LdrpKnownDllObjectDirectory,
                                   DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
                                   &ObjectAttributes);

    /* Check if it exists */
    if (NT_SUCCESS(Status))
    {
        /* Open the Known DLLs Path */
        RtlInitUnicodeString(&KnownDllString, L"KnownDllPath");
        InitializeObjectAttributes(&ObjectAttributes,
                                   &KnownDllString,
                                   OBJ_CASE_INSENSITIVE,
                                   LdrpKnownDllObjectDirectory,
                                   NULL);
        Status = NtOpenSymbolicLinkObject(&SymLinkHandle,
                                          SYMBOLIC_LINK_QUERY,
                                          &ObjectAttributes);
        if (NT_SUCCESS(Status))
        {
            /* Query the path */
            LdrpKnownDllPath.Length = 0;
            LdrpKnownDllPath.MaximumLength = sizeof(LdrpKnownDllPathBuffer);
            LdrpKnownDllPath.Buffer = LdrpKnownDllPathBuffer;
            Status = ZwQuerySymbolicLinkObject(SymLinkHandle, &LdrpKnownDllPath, NULL);
            NtClose(SymLinkHandle);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("LDR: %s - failed call to ZwQuerySymbolicLinkObject with status %x\n", "", Status);
                return Status;
            }
        }
    }

    /* Check if we failed */
    if (!NT_SUCCESS(Status))
    {
        /* Assume System32 */
        LdrpKnownDllObjectDirectory = NULL;
        RtlInitUnicodeString(&LdrpKnownDllPath, StringBuffer);
        LdrpKnownDllPath.Length -= sizeof(WCHAR);
    }

    /* If we have process parameters, get the default path and current path */
    if (ProcessParameters)
    {
        /* Check if we have a Dll Path */
        if (ProcessParameters->DllPath.Length)
        {
            /* Get the path */
            LdrpDefaultPath = *(PUNICODE_STRING)&ProcessParameters->DllPath;
        }
        else
        {
            /* We need a valid path */
            DPRINT1("No valid DllPath was given!\n");
            LdrpInitFailure(STATUS_INVALID_PARAMETER);
        }

        /* Set the current directory */
        CurrentDirectory = ProcessParameters->CurrentDirectory.DosPath;

        /* Check if it's empty or invalid */
        if ((!CurrentDirectory.Buffer) ||
            (CurrentDirectory.Buffer[0] == UNICODE_NULL) ||
            (!CurrentDirectory.Length))
        {
            /* Allocate space for the buffer */
            CurrentDirectory.Buffer = RtlAllocateHeap(Peb->ProcessHeap,
                                                      0,
                                                      3 * sizeof(WCHAR) +
                                                      sizeof(UNICODE_NULL));
            if (!CurrentDirectory.Buffer)
            {
                DPRINT1("LDR: LdrpInitializeProcess - unable to allocate current working directory buffer\n");
                // FIXME: And what?
            }

            /* Copy the drive of the system root */
            RtlMoveMemory(CurrentDirectory.Buffer,
                          SharedUserData->NtSystemRoot,
                          3 * sizeof(WCHAR));
            CurrentDirectory.Buffer[3] = UNICODE_NULL;
            CurrentDirectory.Length = 3 * sizeof(WCHAR);
            CurrentDirectory.MaximumLength = CurrentDirectory.Length + sizeof(WCHAR);

            FreeCurDir = TRUE;
            DPRINT("Using dynamically allocd curdir\n");
        }
        else
        {
            /* Use the local buffer */
            DPRINT("Using local system root\n");
        }
    }

    /* Setup Loader Data */
    Peb->Ldr = &PebLdr;
    InitializeListHead(&PebLdr.InLoadOrderModuleList);
    InitializeListHead(&PebLdr.InMemoryOrderModuleList);
    InitializeListHead(&PebLdr.InInitializationOrderModuleList);
    PebLdr.Length = sizeof(PEB_LDR_DATA);
    PebLdr.Initialized = TRUE;

    /* Allocate a data entry for the Image */
    LdrpImageEntry = LdrpAllocateDataTableEntry(Peb->ImageBaseAddress);

    /* Set it up */
    LdrpImageEntry->EntryPoint = LdrpFetchAddressOfEntryPoint(LdrpImageEntry->DllBase);
    LdrpImageEntry->LoadCount = -1;
    LdrpImageEntry->EntryPointActivationContext = 0;
    LdrpImageEntry->FullDllName = ImageFileName;

    if (IsDotNetImage)
        LdrpImageEntry->Flags = LDRP_COR_IMAGE;
    else
        LdrpImageEntry->Flags = 0;

    /* Check if the name is empty */
    if (!ImageFileName.Buffer[0])
    {
        /* Use the same Base name */
        LdrpImageEntry->BaseDllName = LdrpImageEntry->FullDllName;
    }
    else
    {
        /* Find the last slash */
        Current = ImageFileName.Buffer;
        while (*Current)
        {
            if (*Current++ == '\\')
            {
                /* Set this path */
                NtDllName = Current;
            }
        }

        /* Did we find anything? */
        if (!NtDllName)
        {
            /* Use the same Base name */
            LdrpImageEntry->BaseDllName = LdrpImageEntry->FullDllName;
        }
        else
        {
            /* Setup the name */
            LdrpImageEntry->BaseDllName.Length = (USHORT)((ULONG_PTR)ImageFileName.Buffer + ImageFileName.Length - (ULONG_PTR)NtDllName);
            LdrpImageEntry->BaseDllName.MaximumLength = LdrpImageEntry->BaseDllName.Length + sizeof(WCHAR);
            LdrpImageEntry->BaseDllName.Buffer = (PWSTR)((ULONG_PTR)ImageFileName.Buffer +
                                                     (ImageFileName.Length - LdrpImageEntry->BaseDllName.Length));
        }
    }

    /* Processing done, insert it */
    LdrpInsertMemoryTableEntry(LdrpImageEntry);
    LdrpImageEntry->Flags |= LDRP_ENTRY_PROCESSED;

    /* Now add an entry for NTDLL */
    NtLdrEntry = LdrpAllocateDataTableEntry(SystemArgument1);
    NtLdrEntry->Flags = LDRP_IMAGE_DLL;
    NtLdrEntry->EntryPoint = LdrpFetchAddressOfEntryPoint(NtLdrEntry->DllBase);
    NtLdrEntry->LoadCount = -1;
    NtLdrEntry->EntryPointActivationContext = 0;

    NtLdrEntry->FullDllName.Length = FullPath.Length;
    NtLdrEntry->FullDllName.MaximumLength = FullPath.MaximumLength;
    NtLdrEntry->FullDllName.Buffer = StringBuffer;
    RtlAppendUnicodeStringToString(&NtLdrEntry->FullDllName, &NtDllString);

    NtLdrEntry->BaseDllName.Length = NtDllString.Length;
    NtLdrEntry->BaseDllName.MaximumLength = NtDllString.MaximumLength;
    NtLdrEntry->BaseDllName.Buffer = NtDllString.Buffer;

    /* Processing done, insert it */
    LdrpNtDllDataTableEntry = NtLdrEntry;
    LdrpInsertMemoryTableEntry(NtLdrEntry);

    /* Let the world know */
    if (ShowSnaps)
    {
        DPRINT1("LDR: NEW PROCESS\n");
        DPRINT1("     Image Path: %wZ (%wZ)\n", &LdrpImageEntry->FullDllName, &LdrpImageEntry->BaseDllName);
        DPRINT1("     Current Directory: %wZ\n", &CurrentDirectory);
        DPRINT1("     Search Path: %wZ\n", &LdrpDefaultPath);
    }

    /* Link the Init Order List */
    InsertHeadList(&Peb->Ldr->InInitializationOrderModuleList,
                   &LdrpNtDllDataTableEntry->InInitializationOrderLinks);

    /* Initialize Wine's active context implementation for the current process */
    RtlpInitializeActCtx(&OldShimData);

    /* Set the current directory */
    Status = RtlSetCurrentDirectory_U(&CurrentDirectory);
    if (!NT_SUCCESS(Status))
    {
        /* We failed, check if we should free it */
        if (FreeCurDir) RtlFreeUnicodeString(&CurrentDirectory);

        /* Set it to the NT Root */
        CurrentDirectory = NtSystemRoot;
        RtlSetCurrentDirectory_U(&CurrentDirectory);
    }
    else
    {
        /* We're done with it, free it */
        if (FreeCurDir) RtlFreeUnicodeString(&CurrentDirectory);
    }

    /* Check if we should look for a .local file */
    if (ProcessParameters && !(ProcessParameters->Flags & RTL_USER_PROCESS_PARAMETERS_LOCAL_DLL_PATH))
    {
        LdrpInitializeDotLocalSupport(ProcessParameters);
    }

    /* Check if the Application Verifier was enabled */
    if (Peb->NtGlobalFlag & FLG_APPLICATION_VERIFIER)
    {
        Status = AVrfInitializeVerifier();
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("LDR: AVrfInitializeVerifier failed (ntstatus 0x%x)\n", Status);
            return Status;
        }

    }

    if (NtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI ||
        NtHeader->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI)
    {
        PVOID Kernel32BaseAddress;
        PVOID FunctionAddress;

        Status = LdrLoadDll(NULL, NULL, &Kernel32String, &Kernel32BaseAddress);

        if (!NT_SUCCESS(Status))
        {
            if (ShowSnaps)
                DPRINT1("LDR: Unable to load %wZ, Status=0x%08lx\n", &Kernel32String, Status);
            return Status;
        }

        Status = LdrGetProcedureAddress(Kernel32BaseAddress,
                                        &BaseProcessInitPostImportName,
                                        0,
                                        &FunctionAddress);

        if (!NT_SUCCESS(Status))
        {
            if (ShowSnaps)
                DPRINT1("LDR: Unable to find post-import process init function, Status=0x%08lx\n", Status);
            return Status;
        }
        Kernel32ProcessInitPostImportFunction = FunctionAddress;

        Status = LdrGetProcedureAddress(Kernel32BaseAddress,
                                        &BaseQueryModuleDataName,
                                        0,
                                        &FunctionAddress);

        if (!NT_SUCCESS(Status))
        {
            if (ShowSnaps)
                DPRINT1("LDR: Unable to find BaseQueryModuleData, Status=0x%08lx\n", Status);
            return Status;
        }
        Kernel32BaseQueryModuleData = FunctionAddress;
    }

    /* Walk the IAT and load all the DLLs */
#ifdef BUILD_WOW64_ENABLED
    if (IsWow64) ImportStatus = STATUS_SUCCESS;
    else
#endif
#ifdef _WIN64
    /* Its import tables are PE32 ones, for the x86 entry stub */
    if (IsAnyCpuImage) ImportStatus = STATUS_SUCCESS;
    else
#endif
    ImportStatus = LdrpWalkImportDescriptor(LdrpDefaultPath.Buffer, LdrpImageEntry);

    /* An IL-only .NET executable need not have a native entry point (PE32+ ones
     * never do), and an AnyCPU one has only an x86 stub. As on Windows, such a
     * process starts at mscoree!_CorExeMain. */
    if (IsDotNetImage && NT_SUCCESS(ImportStatus)
#ifdef BUILD_WOW64_ENABLED
        && !IsWow64
#endif
        && (!NtHeader->OptionalHeader.AddressOfEntryPoint
#ifdef _WIN64
            || IsAnyCpuImage
#endif
           ))
    {
        PIMAGE_COR20_HEADER CorHeader;
        ULONG CorHeaderSize;
        BOOLEAN CorHeaderReadable = FALSE, IlOnly = FALSE;

        CorHeader = RtlImageDirectoryEntryToData(Peb->ImageBaseAddress,
                                                 TRUE,
                                                 IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
                                                 &CorHeaderSize);
        if (CorHeader && CorHeaderSize >= sizeof(*CorHeader))
        {
            /* The descriptor is image data: its RVA may point at memory the
             * section did not map, so read it guarded. */
            _SEH2_TRY
            {
                IlOnly = !!(CorHeader->Flags & COMIMAGE_FLAGS_ILONLY);
                CorHeaderReadable = TRUE;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                CorHeaderReadable = FALSE;
            }
            _SEH2_END;

            if (!CorHeaderReadable)
            {
                DPRINT1("LDR: the COM descriptor of the .NET image is not mapped\n");
                if (OptionsKey) NtClose(OptionsKey);
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        if (IlOnly)
        {
            /* Load mscoree.dll from the system directory only, as Windows does:
             * the application directory must not be able to supply it. */
            WCHAR MscoreePath[MAX_PATH];
            UNICODE_STRING MscoreeString;
            ANSI_STRING CorExeMainName = RTL_CONSTANT_STRING("_CorExeMain");
            PVOID MscoreeBase, CorExeMain = NULL;

            RtlInitEmptyUnicodeString(&MscoreeString, MscoreePath, sizeof(MscoreePath));
            Status = RtlAppendUnicodeStringToString(&MscoreeString, &NtSystemRoot);
            if (NT_SUCCESS(Status))
            {
                /* The 32-bit ntdll built for SysWOW64 only ever runs under
                 * WoW64, which has set up TEB32.WOW32Reserved (the gate)
                 * before it enters this loader; decide at build time anyway,
                 * so the choice does not depend on that. */
#if defined(SYSWOW64_GUEST)
                Status = RtlAppendUnicodeToString(&MscoreeString, L"\\SysWOW64\\mscoree.dll");
#else
#ifdef _M_IX86
                if (NtCurrentTeb()->WOW32Reserved)
                    Status = RtlAppendUnicodeToString(&MscoreeString, L"\\SysWOW64\\mscoree.dll");
                else
#endif
                Status = RtlAppendUnicodeToString(&MscoreeString, L"\\System32\\mscoree.dll");
#endif
            }
            if (NT_SUCCESS(Status))
                Status = LdrLoadDll(NULL, NULL, &MscoreeString, &MscoreeBase);
            if (NT_SUCCESS(Status))
                Status = LdrGetProcedureAddress(MscoreeBase, &CorExeMainName, 0, &CorExeMain);
            if (!NT_SUCCESS(Status))
            {
                DPRINT1("LDR: cannot start the .NET image, mscoree!_CorExeMain: 0x%08lx\n", Status);
                if (OptionsKey) NtClose(OptionsKey);
                return Status;
            }

            LdrpImageEntry->EntryPoint = CorExeMain;
#if defined(_M_AMD64)
            Context->Rcx = (ULONG_PTR)CorExeMain;
#elif defined(_M_IX86)
            Context->Eax = (ULONG_PTR)CorExeMain;
#endif
        }
    }

    /* Check if relocation is needed. Windows leaves an AnyCPU image where the
     * kernel mapped it, unrelocated: its only fixup is in the x86 stub */
    if (
#ifdef BUILD_WOW64_ENABLED
        !IsWow64 &&
#endif
#ifdef _WIN64
        !IsAnyCpuImage &&
#endif
        Peb->ImageBaseAddress != (PVOID)NtHeader->OptionalHeader.ImageBase)
    {
        DPRINT1("LDR: Performing EXE relocation\n");

        /* Change the protection to prepare for relocation */
        ViewBase = Peb->ImageBaseAddress;
        Status = LdrpSetProtection(ViewBase, FALSE);
        if (!NT_SUCCESS(Status)) return Status;

        /* Do the relocation */
        Status = LdrRelocateImageWithBias(ViewBase,
                                          0LL,
                                          NULL,
                                          STATUS_SUCCESS,
                                          STATUS_CONFLICTING_ADDRESSES,
                                          STATUS_INVALID_IMAGE_FORMAT);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("LdrRelocateImageWithBias() failed\n");
            return Status;
        }

        /* Restore the protection */
        Status = LdrpSetProtection(ViewBase, TRUE);
        if (!NT_SUCCESS(Status)) return Status;
    }

    /* Lock the DLLs */
    ListHead = &Peb->Ldr->InLoadOrderModuleList;
    NextEntry = ListHead->Flink;
    while (ListHead != NextEntry)
    {
        NtLdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        NtLdrEntry->LoadCount = -1;
        NextEntry = NextEntry->Flink;
    }

    /* Phase 0 is done */
    LdrpLdrDatabaseIsSetup = TRUE;

    /* Check whether all static imports were properly loaded and return here */
    if (!NT_SUCCESS(ImportStatus)) return ImportStatus;

    /* Following two calls are for Vista+ support, required for winesync */
    /* Initialize the keyed event for condition variables */
    RtlpInitializeKeyedEvent();
    RtlpInitializeThreadPooling();

    /* Initialize TLS */
#ifdef BUILD_WOW64_ENABLED
    if (IsWow64)
    {
        /* The i386 loader owns the PE32 image's TLS. The native list stays
         * empty, but every later thread walks it and gets an (empty) vector */
        InitializeListHead(&LdrpTlsList);
        Status = LdrpAllocateTls();
    }
    else
#endif
    Status = LdrpInitializeTls();
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("LDR: LdrpProcessInitialization failed to initialize TLS slots; status %x\n",
                Status);
        return Status;
    }

    /* FIXME Mark the DLL Ranges for Stack Traces later */

    /* Notify the debugger now */
    if (Peb->BeingDebugged)
    {
        /* Break */
        DbgBreakPoint();

        /* Update show snaps again */
        ShowSnaps = Peb->NtGlobalFlag & FLG_SHOW_LDR_SNAPS;
    }

    /* Validate the Image for MP Usage */
    if (LdrpNumberOfProcessors > 1) LdrpValidateImageForMp(LdrpImageEntry);

    /* Check NX options and set them */
    if (SharedUserData->NXSupportPolicy == NX_SUPPORT_POLICY_ALWAYSON)
    {
        ExecuteOptions = MEM_EXECUTE_OPTION_DISABLE |
                         MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION |
                         MEM_EXECUTE_OPTION_PERMANENT;
    }
    else if (SharedUserData->NXSupportPolicy == NX_SUPPORT_POLICY_ALWAYSOFF)
    {
        ExecuteOptions = MEM_EXECUTE_OPTION_ENABLE | MEM_EXECUTE_OPTION_PERMANENT;
    }
#ifndef _M_AMD64 /* a native 64-bit process has DEP fixed by the kernel, as on Windows */
    Status = NtSetInformationProcess(NtCurrentProcess(),
                                     ProcessExecuteFlags,
                                     &ExecuteOptions,
                                     sizeof(ExecuteOptions));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("LDR: Could not set process execute flags 0x%x; status %x\n",
                ExecuteOptions, Status);
    }
#endif

    // FIXME: Should be done by Application Compatibility features,
    // by reading the registry, etc...
    // For now, this is the old code from ntdll!RtlGetVersion().
    RtlInitEmptyUnicodeString(&Peb->CSDVersion, NULL, 0);
    if (((Peb->OSCSDVersion >> 8) & 0xFF) != 0)
    {
        WCHAR szCSDVersion[128];
        LONG i;
        USHORT Length = (USHORT)ARRAYSIZE(szCSDVersion) - 1;
        i = _snwprintf(szCSDVersion, Length,
                       L"Service Pack %d",
                       ((Peb->OSCSDVersion >> 8) & 0xFF));
        if (i < 0)
        {
            /* Null-terminate if it was overflowed */
            szCSDVersion[Length] = UNICODE_NULL;
        }

        Length *= sizeof(WCHAR);
        Peb->CSDVersion.Buffer = RtlAllocateHeap(RtlGetProcessHeap(),
                                                 0,
                                                 Length + sizeof(UNICODE_NULL));
        if (Peb->CSDVersion.Buffer)
        {
            Peb->CSDVersion.Length = Length;
            Peb->CSDVersion.MaximumLength = Length + sizeof(UNICODE_NULL);

            RtlCopyMemory(Peb->CSDVersion.Buffer,
                          szCSDVersion,
                          Peb->CSDVersion.MaximumLength);
            Peb->CSDVersion.Buffer[Peb->CSDVersion.Length / sizeof(WCHAR)] = UNICODE_NULL;
        }
    }

    /* The guest loader applies shims to PE32 imports after WoW64 copies the
     * compatibility data. The native support loader has no PE32 imports. */
    if (OldShimData
#ifdef BUILD_WOW64_ENABLED
        && !IsWow64
#endif
       )
    {
        /* Load the Shim Engine */
        Peb->AppCompatInfo = NULL;
        LdrpLoadShimEngine(OldShimData, &ImagePathName, OldShimData);
    }
    else
    {
        /* Check for Application Compatibility Goo */
        //LdrQueryApplicationCompatibilityGoo(hKey);
        DPRINT("Querying app compat hacks is missing!\n");
    }

    /*
     * FIXME: Check for special images, SecuROM, SafeDisc and other NX-
     * incompatible images.
     */

    /* Now call the Init Routines */
    Status = LdrpRunInitializeRoutines(Context);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("LDR: LdrpProcessInitialization failed running initialization routines; status %x\n",
                Status);
        return Status;
    }

    /* Notify Shim Engine */
    if (g_ShimsEnabled)
    {
        VOID(NTAPI *SE_InstallAfterInit)(PUNICODE_STRING, PVOID);
        SE_InstallAfterInit = RtlDecodeSystemPointer(g_pfnSE_InstallAfterInit);
        SE_InstallAfterInit(&ImagePathName, OldShimData);
    }

    /* Check if we have a user-defined Post Process Routine */
    if (NT_SUCCESS(Status) && Peb->PostProcessInitRoutine)
    {
        /* Call it */
        Peb->PostProcessInitRoutine();
    }

    /* Close the key if we have one opened */
    if (OptionsKey) NtClose(OptionsKey);

    /* Return status */
    return Status;
}

VOID
NTAPI
LdrpInitFailure(NTSTATUS Status)
{
    ULONG Response;
    PPEB Peb = NtCurrentPeb();

    /* Print a debug message */
    DPRINT1("LDR: Process initialization failure for %wZ; NTSTATUS = %08lx\n",
            &Peb->ProcessParameters->ImagePathName, Status);

    /* Raise a hard error */
    if (!LdrpFatalHardErrorCount)
    {
        ZwRaiseHardError(STATUS_APP_INIT_FAILURE, 1, 0, (PULONG_PTR)&Status, OptionOk, &Response);
    }
}

VOID
NTAPI
LdrpInit(PCONTEXT Context,
         PVOID SystemArgument1,
         PVOID SystemArgument2)
{
    LARGE_INTEGER Timeout;
    PTEB Teb = NtCurrentTeb();
    NTSTATUS Status, LoaderStatus = STATUS_SUCCESS;
    MEMORY_BASIC_INFORMATION MemoryBasicInfo;
    PPEB Peb = NtCurrentPeb();
#ifdef BUILD_WOW64_ENABLED
    BOOLEAN ProcessStartup = FALSE;
#endif

    DPRINT("LdrpInit() %p/%p\n",
        NtCurrentTeb()->RealClientId.UniqueProcess,
        NtCurrentTeb()->RealClientId.UniqueThread);

#ifdef _WIN64
    /* Set the SList header usage */
    RtlpUse16ByteSLists = SharedUserData->ProcessorFeatures[PF_COMPARE_EXCHANGE128];
#endif /* _WIN64 */

    /* Check if we have a deallocation stack */
    if (!Teb->DeallocationStack)
    {
        /* We don't, set one */
        Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                      Teb->NtTib.StackLimit,
                                      MemoryBasicInformation,
                                      &MemoryBasicInfo,
                                      sizeof(MEMORY_BASIC_INFORMATION),
                                      NULL);
        if (!NT_SUCCESS(Status))
        {
            /* Fail */
            LdrpInitFailure(Status);
            RtlRaiseStatus(Status);
            return;
        }

        /* Set the stack */
        Teb->DeallocationStack = MemoryBasicInfo.AllocationBase;
    }

    /* Now check if the process is already being initialized */
    while (_InterlockedCompareExchange(&LdrpProcessInitialized,
                                      1,
                                      0) == 1)
    {
        /* Set the timeout to 30 milliseconds */
        Timeout.QuadPart = Int32x32To64(30, -10000);

        /* Make sure the status hasn't changed */
        while (LdrpProcessInitialized == 1)
        {
            /* Do the wait */
            ZwDelayExecution(FALSE, &Timeout);
        }
    }

    /* Check if we have already setup LDR data */
    if (!Peb->Ldr)
    {
#ifdef BUILD_WOW64_ENABLED
        ProcessStartup = TRUE;
#endif
        /* Setup the Loader Lock */
        Peb->LoaderLock = &LdrpLoaderLock;

        /* Let other code know we're initializing */
        LdrpInLdrInit = TRUE;

        /* Protect with SEH */
        _SEH2_TRY
        {
            /* Initialize the Process */
            LoaderStatus = LdrpInitializeProcess(Context,
                                                 SystemArgument1);

            /* Check for success and if MinimumStackCommit was requested */
            if (NT_SUCCESS(LoaderStatus) && Peb->MinimumStackCommit)
            {
                /* Enforce the limit */
                //LdrpTouchThreadStack(Peb->MinimumStackCommit);
                UNIMPLEMENTED;
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Fail with the SEH error */
            LoaderStatus = _SEH2_GetExceptionCode();
        }
        _SEH2_END;

        /* We're not initializing anymore */
        LdrpInLdrInit = FALSE;

        /* Check if init worked */
        if (NT_SUCCESS(LoaderStatus))
        {
            /* Set the process as Initialized */
            _InterlockedIncrement(&LdrpProcessInitialized);
        }
    }
    else
    {
        /* Loader data is there... is this a fork() ? */
        if(Peb->InheritedAddressSpace)
        {
            /* Handle the fork() */
            //LoaderStatus = LdrpForkProcess();
            LoaderStatus = STATUS_NOT_IMPLEMENTED;
            UNIMPLEMENTED;
        }
        else
        {
            /* This is a new thread initializing; one that cannot get its TLS ends here */
            Status = LdrpInitializeThread(Context);
            if (!NT_SUCCESS(Status))
            {
                /* No DLL saw it attach, so none is told it detaches; free what the thread has, its stack included */
                RtlFreeThreadActivationContextStack();
                NtCurrentTeb()->FreeStackOnTermination = TRUE;
                NtTerminateThread(NtCurrentThread(), Status);
            }
        }
    }

#ifdef BUILD_WOW64_ENABLED
    /* Bitness is established during process initialization. Applications may
     * discard their image headers before starting subsequent native threads. */
    if (NT_SUCCESS(LoaderStatus) && LdrpIsWow64)
    {
        UNICODE_STRING Name = RTL_CONSTANT_STRING(L"wow64.dll");
        ANSI_STRING Entry = RTL_CONSTANT_STRING("Wow64LdrpInitialize");
        PVOID Module, Procedure;
        extern PVOID Wow64PrepareForException, Wow64PrepareForApc;
        ANSI_STRING ApcEntry = RTL_CONSTANT_STRING("Wow64PrepareForApc");
        ANSI_STRING ExceptionEntry = RTL_CONSTANT_STRING("Wow64PrepareForException");
        LoaderStatus = LdrLoadDll(NULL, NULL, &Name, &Module);
        if (NT_SUCCESS(LoaderStatus))
            LoaderStatus = LdrGetProcedureAddress(Module, &Entry, 0, &Procedure);
        if (NT_SUCCESS(LoaderStatus))
            LoaderStatus = LdrGetProcedureAddress(Module, &ExceptionEntry, 0, &Wow64PrepareForException);
        if (NT_SUCCESS(LoaderStatus))
            LoaderStatus = LdrGetProcedureAddress(Module, &ApcEntry, 0, &Wow64PrepareForApc);
        if (NT_SUCCESS(LoaderStatus))
            ((VOID (NTAPI *)(PCONTEXT, BOOLEAN))Procedure)(Context, ProcessStartup);
    }
#endif

    /* All done, test alert the thread */
    NtTestAlert();

    /* Return */
    if (!NT_SUCCESS(LoaderStatus))
    {
        /* Fail */
        LdrpInitFailure(LoaderStatus);
        RtlRaiseStatus(LoaderStatus);
    }
}

/* EOF */

#if defined(_M_IX86) || defined(_M_AMD64)
/* __fastcall on x86 as kernel32's (and Windows') BaseThreadInitThunk: ECX Unknown, EDX the routine, the parameter on the stack */
#ifdef _M_IX86
#define BASE_THREAD_INIT_THUNK_CALL FASTCALL
#else
#define BASE_THREAD_INIT_THUNK_CALL NTAPI
#endif
typedef VOID (BASE_THREAD_INIT_THUNK_CALL *PBASE_THREAD_INIT_THUNK)(ULONG Unknown, PVOID StartAddress, PVOID Parameter);

/* kernel32's BaseThreadInitThunk, which RtlUserThreadStart runs the thread's routine through (Windows'
 * Kernel32ThreadInitThunkFunction). Found once kernel32 is loaded; a process without it runs the routine directly.
 * Hooking libraries (Firefox mozglue) patch the export, so the lookup is by name, as on Windows. */
static PBASE_THREAD_INIT_THUNK Kernel32ThreadInitThunkFunction;

static PBASE_THREAD_INIT_THUNK RtlpGetThreadInitThunk(VOID)
{
    static ANSI_STRING ThunkName = RTL_CONSTANT_STRING("BaseThreadInitThunk");
    PBASE_THREAD_INIT_THUNK Thunk = Kernel32ThreadInitThunkFunction;
    PVOID Kernel32;

    if (!Thunk &&
        NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &Kernel32String, &Kernel32)) &&
        NT_SUCCESS(LdrGetProcedureAddress(Kernel32, &ThunkName, 0, (PVOID *)&Thunk)))
    {
        Kernel32ThreadInitThunkFunction = Thunk;
    }
    return Thunk;
}
#endif

#if defined(_M_IX86)
VOID NTAPI RtlpUserThreadStart(PVOID Routine, PVOID Parameter);
ULONG NTAPI RtlpCallThreadStart(PVOID Routine, PVOID Parameter);

#ifdef SYSWOW64_GUEST
/* Entered only by the native WoW64 loader, with an initialized PEB32/TEB32.
 * The main thread's StartContext is the one the kernel staged when the thread
 * was created (and a debugger may have changed since): RtlUserThreadStart with
 * the image's entry in EAX, which the loader replaces for an IL-only .NET image,
 * and the PEB32 in EBX. Without one, the process starts here. */
VOID NTAPI LdrInitializeWow64(PVOID NtdllBase, PCONTEXT StartContext)
{
    CONTEXT Context;
    if (StartContext) Context = *StartContext;
    else RtlCaptureContext(&Context);
    LdrpInit(&Context, NtdllBase, NULL);
    if (StartContext) NtContinue(&Context, TRUE);
    RtlpUserThreadStart(NULL, NtCurrentPeb());
}
#endif

/* RtlUserThreadStart (dispatch.S) with its EAX and EBX: Routine(Parameter) ends
 * the thread with its result, through kernel32's thread start (BaseThreadInitThunk)
 * (it reports an exception that no frame of the routine handles and ends the
 * thread or the process). A NULL Routine is the image's entry (the WoW64 loader's
 * start): the loader's, which the IL-only start of a .NET image without an entry
 * point replaced with mscoree!_CorExeMain, or the header's. Without kernel32 the
 * routine runs here and its result ends the thread. */
VOID NTAPI RtlpUserThreadStart(PVOID Routine, PVOID Parameter)
{
    PBASE_THREAD_INIT_THUNK Thunk;
    PIMAGE_NT_HEADERS Header;

    if (!Routine)
    {
        if (LdrpImageEntry && LdrpImageEntry->EntryPoint)
        {
            Routine = LdrpImageEntry->EntryPoint;
        }
        else
        {
            Header = RtlImageNtHeader(NtCurrentPeb()->ImageBaseAddress);
            Routine = (PVOID)((ULONG_PTR)NtCurrentPeb()->ImageBaseAddress +
                              Header->OptionalHeader.AddressOfEntryPoint);
        }
    }

    Thunk = RtlpGetThreadInitThunk();
    if (Thunk) Thunk(0, Routine, Parameter);
    RtlExitUserThread(RtlpCallThreadStart(Routine, Parameter));
}
#elif defined(_M_AMD64)
/* A user thread starts here with its routine in RCX and its parameter in RDX (the first thread of a
 * process: the image entry and the PEB), and runs the routine through kernel32's thread start (BaseThreadInitThunk)
 * as on Windows, so a stack walk of any thread ends in ntdll!RtlUserThreadStart. Without kernel32 the
 * routine runs here and its result ends the thread. */
VOID NTAPI RtlUserThreadStart(PVOID Routine, PVOID Parameter)
{
    PBASE_THREAD_INIT_THUNK Thunk = RtlpGetThreadInitThunk();

    if (Thunk) Thunk(0, Routine, Parameter);
    RtlExitUserThread(((ULONG (NTAPI *)(PVOID))Routine)(Parameter));
}
#endif
