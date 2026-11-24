/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/kdbg/kdb_symbols.c
 * PURPOSE:         Getting symbol information...
 *
 * PROGRAMMERS:     David Welch (welch@cwcom.net)
 *                  Colin Finck (colin@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#include "kdb.h"

#define NDEBUG
#include "debug.h"

/* The loader thread runs outside the debugger, where KdbPrintf does not freeze the other processors */
#define LOADER_DPRINT1(fmt, ...) \
    DbgPrint("(%s:%d) " fmt, __RELFILE__, __LINE__, ##__VA_ARGS__)

/* GLOBALS ******************************************************************/

typedef struct _IMAGE_SYMBOL_INFO_CACHE
{
    LIST_ENTRY ListEntry;
    ULONG RefCount;
    UNICODE_STRING FileName;
    PROSSYM_INFO RosSymInfo;
}
IMAGE_SYMBOL_INFO_CACHE, *PIMAGE_SYMBOL_INFO_CACHE;

static BOOLEAN LoadSymbols = FALSE;
/* Lock-free, since the debugger queues entries with other processors frozen */
static SLIST_HEADER SymbolsToLoad;
/* Symbols of modules unloaded above DISPATCH_LEVEL, freed by the loader thread */
static SLIST_HEADER SymbolsToFree;
static KEVENT SymbolsToLoadEvent;

/* FUNCTIONS ****************************************************************/

static
BOOLEAN
KdbpSymSearchModuleList(
    IN PLIST_ENTRY current_entry,
    IN PLIST_ENTRY end_entry,
    IN PLONG Count,
    IN PVOID Address,
    IN INT Index,
    OUT PLDR_DATA_TABLE_ENTRY* pLdrEntry)
{
    while (current_entry && current_entry != end_entry)
    {
        *pLdrEntry = CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if ((Address && Address >= (PVOID)(*pLdrEntry)->DllBase && Address < (PVOID)((ULONG_PTR)(*pLdrEntry)->DllBase + (*pLdrEntry)->SizeOfImage)) ||
            (Index >= 0 && (*Count)++ == Index))
        {
            return TRUE;
        }

        current_entry = current_entry->Flink;
    }

    return FALSE;
}

/*! \brief Find a module...
 *
 * \param Address      If \a Address is not NULL the module containing \a Address
 *                     is searched.
 * \param Name         If \a Name is not NULL the module named \a Name will be
 *                     searched.
 * \param Index        If \a Index is >= 0 the Index'th module will be returned.
 * \param pLdrEntry    Pointer to a PLDR_DATA_TABLE_ENTRY which is filled.
 *
 * \retval TRUE    Module was found, \a pLdrEntry was filled.
 * \retval FALSE   No module was found.
 */
/*
 * The debugger runs with the other processors frozen. Any of them, or the
 * code this processor interrupted, can hold the loaded module lock at that
 * moment (RtlPcToFileHeader takes it for every frame of a stack capture), and
 * waiting for it then never ends: the holder only runs again when the
 * debugger has finished. So the debugger never waits for the lock: it walks
 * the list without it when the lock is taken. That is safe there: a frozen
 * holder does not move, inserting or removing an entry keeps every forward
 * link valid at each step, and an entry is freed only after its remover has
 * released the lock. Outside the debugger the lock is taken as before.
 */
static
BOOLEAN
KdbpAcquireLoadedModuleLock(VOID)
{
    if (KeTryToAcquireSpinLockAtDpcLevel(&PsLoadedModuleSpinLock))
        return TRUE;

    if (KiFreezeOwner == KeGetCurrentPrcb())
        return FALSE;

    KeAcquireSpinLockAtDpcLevel(&PsLoadedModuleSpinLock);
    return TRUE;
}

BOOLEAN
KdbpSymFindModule(
    IN PVOID Address  OPTIONAL,
    IN INT Index  OPTIONAL,
    OUT PLDR_DATA_TABLE_ENTRY* pLdrEntry)
{
    LONG Count = 0;
    PEPROCESS CurrentProcess;
    BOOLEAN Locked, Found;

    /* First try to look up the module in the kernel module list. */
    Locked = KdbpAcquireLoadedModuleLock();
    Found = KdbpSymSearchModuleList(PsLoadedModuleList.Flink,
                                    &PsLoadedModuleList,
                                    &Count,
                                    Address,
                                    Index,
                                    pLdrEntry);
    if (Locked)
        KeReleaseSpinLockFromDpcLevel(&PsLoadedModuleSpinLock);
    if (Found)
        return TRUE;

    /* That didn't succeed. Try the module list of the current process now. */
    CurrentProcess = PsGetCurrentProcess();

    if(!CurrentProcess || !CurrentProcess->Peb || !CurrentProcess->Peb->Ldr)
        return FALSE;

    return KdbpSymSearchModuleList(CurrentProcess->Peb->Ldr->InLoadOrderModuleList.Flink,
                                   &CurrentProcess->Peb->Ldr->InLoadOrderModuleList,
                                   &Count,
                                   Address,
                                   Index,
                                   pLdrEntry);
}

static
PCHAR
NTAPI
KdbpSymUnicodeToAnsi(IN PUNICODE_STRING Unicode,
                     OUT PCHAR Ansi,
                     IN ULONG Length)
{
    PCHAR p;
    PWCHAR pw;
    ULONG i;

    /* Set length and normalize it */
    i = Unicode->Length / sizeof(WCHAR);
    i = min(i, Length - 1);

    /* Set source and destination, and copy */
    pw = Unicode->Buffer;
    p = Ansi;
    while (i--) *p++ = (CHAR)*pw++;

    /* Null terminate and return */
    *p = ANSI_NULL;
    return Ansi;
}

/*! \brief Print address...
 *
 * Tries to lookup line number, file name and function name for the given
 * address and prints it.
 * If no such information is found the address is printed in the format
 * <module: offset>, otherwise the format will be
 * <module: offset (filename:linenumber (functionname))>
 *
 * \retval TRUE  Module containing \a Address was found, \a Address was printed.
 * \retval FALSE  No module containing \a Address was found, nothing was printed.
 */
BOOLEAN
KdbSymPrintAddress(
    IN PVOID Address,
    IN PCONTEXT Context)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    ULONG_PTR RelativeAddress;
    BOOLEAN Printed = FALSE;
    CHAR ModuleNameAnsi[64];

    if (!KdbpSymFindModule(Address, -1, &LdrEntry))
        return FALSE;

    RelativeAddress = (ULONG_PTR)Address - (ULONG_PTR)LdrEntry->DllBase;

    KdbpSymUnicodeToAnsi(&LdrEntry->BaseDllName,
                        ModuleNameAnsi,
                        sizeof(ModuleNameAnsi));

    if (LdrEntry->PatchInformation)
    {
        ULONG LineNumber;
        CHAR FileName[256];
        CHAR FunctionName[256];

        if (RosSymGetAddressInformation(LdrEntry->PatchInformation,
                                        RelativeAddress,
                                        &LineNumber,
                                        FileName,
                                        FunctionName))
        {
            KdbPrintf("<%s:%x (%s:%d (%s))>",
                      ModuleNameAnsi, RelativeAddress,
                      FileName, LineNumber, FunctionName);
            Printed = TRUE;
        }
    }

    if (!Printed)
    {
        /* Just print module & address */
        KdbPrintf("<%s:%x>", ModuleNameAnsi, RelativeAddress);
    }

    return TRUE;
}


static KSTART_ROUTINE LoadSymbolsRoutine;
/*! \brief          The symbol loader thread routine.
 *                  This opens the image file for reading and loads the symbols
 *                  section from there.
 *
 * \note            We must do this because KdbSymProcessSymbols is
 *                  called at high IRQL and we can't set the event from here
 *
 * \param Context   Unused
 */
_Use_decl_annotations_
VOID
NTAPI
LoadSymbolsRoutine(
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    while (TRUE)
    {
        PSLIST_ENTRY ListEntry;
        LARGE_INTEGER Interval;
        NTSTATUS Status;

        /* Entries queued while the debugger froze the other processors cannot
           set the event, as that could wait for a lock a frozen processor holds */
        Interval.QuadPart = -10 * 1000 * 1000;
        Status = KeWaitForSingleObject(&SymbolsToLoadEvent, WrKernel, KernelMode, FALSE, &Interval);
        if (!NT_SUCCESS(Status))
        {
            LOADER_DPRINT1("KeWaitForSingleObject failed?! 0x%08x\n", Status);
            LoadSymbols = FALSE;
            return;
        }

        ListEntry = InterlockedFlushSList(&SymbolsToFree);
        while (ListEntry)
        {
            PROSSYM_INFO RosSymInfo = (PROSSYM_INFO)ListEntry;
            ListEntry = ListEntry->Next;
            RosSymDelete(RosSymInfo);
        }

        ListEntry = InterlockedFlushSList(&SymbolsToLoad);
        while (ListEntry)
        {
            PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
            ListEntry = ListEntry->Next;
            HANDLE FileHandle;
            OBJECT_ATTRIBUTES Attrib;
            IO_STATUS_BLOCK Iosb;
            InitializeObjectAttributes(&Attrib, &LdrEntry->FullDllName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            LOADER_DPRINT1("Trying %wZ\n", &LdrEntry->FullDllName);
            Status = ZwOpenFile(&FileHandle,
                                FILE_READ_ACCESS | SYNCHRONIZE,
                                &Attrib,
                                &Iosb,
                                FILE_SHARE_READ,
                                FILE_SYNCHRONOUS_IO_NONALERT);
            if (!NT_SUCCESS(Status))
            {
                /* Try system paths */
                static const UNICODE_STRING System32Dir = RTL_CONSTANT_STRING(L"\\SystemRoot\\system32\\");
                UNICODE_STRING ImagePath;
                WCHAR ImagePathBuffer[256];
                RtlInitEmptyUnicodeString(&ImagePath, ImagePathBuffer, sizeof(ImagePathBuffer));
                RtlCopyUnicodeString(&ImagePath, &System32Dir);
                RtlAppendUnicodeStringToString(&ImagePath, &LdrEntry->BaseDllName);
                InitializeObjectAttributes(&Attrib, &ImagePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                LOADER_DPRINT1("Trying %wZ\n", &ImagePath);
                Status = ZwOpenFile(&FileHandle,
                                    FILE_READ_ACCESS | SYNCHRONIZE,
                                    &Attrib,
                                    &Iosb,
                                    FILE_SHARE_READ,
                                    FILE_SYNCHRONOUS_IO_NONALERT);
                if (!NT_SUCCESS(Status))
                {
                    static const UNICODE_STRING DriversDir= RTL_CONSTANT_STRING(L"\\SystemRoot\\system32\\drivers\\");

                    RtlInitEmptyUnicodeString(&ImagePath, ImagePathBuffer, sizeof(ImagePathBuffer));
                    RtlCopyUnicodeString(&ImagePath, &DriversDir);
                    RtlAppendUnicodeStringToString(&ImagePath, &LdrEntry->BaseDllName);
                    InitializeObjectAttributes(&Attrib, &ImagePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
                    LOADER_DPRINT1("Trying %wZ\n", &ImagePath);
                    Status = ZwOpenFile(&FileHandle,
                                        FILE_READ_ACCESS | SYNCHRONIZE,
                                        &Attrib,
                                        &Iosb,
                                        FILE_SHARE_READ,
                                        FILE_SYNCHRONOUS_IO_NONALERT);
                }
            }

            if (!NT_SUCCESS(Status))
            {
                LOADER_DPRINT1("Failed opening file %wZ (%wZ) for reading symbols (0x%08x)\n", &LdrEntry->FullDllName, &LdrEntry->BaseDllName, Status);
                /* We took a ref previously */
                MmUnloadSystemImage(LdrEntry);
                continue;
            }

            /* Hand it to Rossym */
            if (!RosSymCreateFromFile(&FileHandle, (PROSSYM_INFO*)&LdrEntry->PatchInformation))
                LdrEntry->PatchInformation = NULL;

            /* We're done for this one. */
            NtClose(FileHandle);
            MmUnloadSystemImage(LdrEntry);
        }
    }
}

/*! \brief          Load symbols from image mapping. If this fails,
 *
 * \param LdrEntry  The entry to load symbols from
 */
VOID
KdbSymProcessSymbols(
    _Inout_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _In_ BOOLEAN Load)
{
    if (!LoadSymbols)
        return;

    /* Check if this is unload */
    if (!Load)
    {
        PROSSYM_INFO RosSymInfo = LdrEntry->PatchInformation;

        /* Did we process it */
        if (RosSymInfo)
        {
            LdrEntry->PatchInformation = NULL;

            /* Pool can only be freed up to DISPATCH_LEVEL: above it, queue the block itself */
            if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
                RosSymDelete(RosSymInfo);
            else
                InterlockedPushEntrySList(&SymbolsToFree, (PSLIST_ENTRY)RosSymInfo);
        }
        return;
    }

    /* Pool can only be allocated up to DISPATCH_LEVEL; the debugger runs higher
     * when it froze other processors, so leave the work to the loader thread */
    if (KeGetCurrentIrql() <= DISPATCH_LEVEL &&
        RosSymCreateFromMem(LdrEntry->DllBase, LdrEntry->SizeOfImage, (PROSSYM_INFO*)&LdrEntry->PatchInformation))
    {
        return;
    }

    /* Add a ref until we really process it */
    LdrEntry->LoadCount++;

    /* Tell our worker thread to read from it */
    InterlockedPushEntrySList(&SymbolsToLoad, (PSLIST_ENTRY)&LdrEntry->InInitializationOrderLinks);

    /* Above DISPATCH_LEVEL the loader thread finds the entry when its wait times out */
    if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
        KeSetEvent(&SymbolsToLoadEvent, IO_NO_INCREMENT, FALSE);
}


/**
 * @brief   Initializes the KDB symbols implementation.
 *
 * @param[in]   BootPhase
 * Phase of initialization.
 *
 * @return
 * TRUE if symbols are to be loaded at this given BootPhase; FALSE if not.
 **/
BOOLEAN
KdbSymInit(
    _In_ ULONG BootPhase)
{
#if 1 // FIXME: This is a workaround HACK!!
    static BOOLEAN OrigLoadSymbols = FALSE;
#endif

    DPRINT("KdbSymInit() BootPhase=%d\n", BootPhase);

    if (BootPhase == 0)
    {
        PSTR CommandLine;
        SHORT Found = FALSE;
        CHAR YesNo;

        /* By default, load symbols in DBG builds, but not in REL builds
           or anything other than x86, because they only work on x86
           and can cause the system to hang on x64. */
#if DBG && defined(_M_IX86)
        LoadSymbols = TRUE;
#else
        LoadSymbols = FALSE;
#endif

        /* Check the command line for LOADSYMBOLS, NOLOADSYMBOLS,
         * LOADSYMBOLS={YES|NO}, NOLOADSYMBOLS={YES|NO} */
        ASSERT(KeLoaderBlock);
        CommandLine = KeLoaderBlock->LoadOptions;
        while (*CommandLine)
        {
            /* Skip any whitespace */
            while (isspace(*CommandLine))
                ++CommandLine;

            Found = 0;
            if (_strnicmp(CommandLine, "LOADSYMBOLS", 11) == 0)
            {
                Found = +1;
                CommandLine += 11;
            }
            else if (_strnicmp(CommandLine, "NOLOADSYMBOLS", 13) == 0)
            {
                Found = -1;
                CommandLine += 13;
            }
            if (Found != 0)
            {
                if (*CommandLine == '=')
                {
                    ++CommandLine;
                    YesNo = toupper(*CommandLine);
                    if (YesNo == 'N' || YesNo == '0')
                    {
                        Found = -1 * Found;
                    }
                }
                LoadSymbols = (0 < Found);
            }

            /* Move on to the next option */
            while (*CommandLine && !isspace(*CommandLine))
                ++CommandLine;
        }

#if 1 // FIXME: This is a workaround HACK!!
// Save the actual value of LoadSymbols but disable it for BootPhase 0.
        OrigLoadSymbols = LoadSymbols;
        LoadSymbols = FALSE;
        return OrigLoadSymbols;
#endif
    }
    else if (BootPhase == 1)
    {
        HANDLE Thread;
        NTSTATUS Status;
        KIRQL OldIrql;
        PLIST_ENTRY ListEntry;

#if 1 // FIXME: This is a workaround HACK!!
// Now, restore the actual value of LoadSymbols.
        LoadSymbols = OrigLoadSymbols;
#endif

        /* Do not continue loading symbols if we have less than 96MB of RAM */
        if (MmNumberOfPhysicalPages < (96 * 1024 * 1024 / PAGE_SIZE))
            LoadSymbols = FALSE;

        /* Continue this phase only if we need to load symbols */
        if (!LoadSymbols)
            return LoadSymbols;

        /* Launch our worker thread */
        InitializeSListHead(&SymbolsToLoad);
        InitializeSListHead(&SymbolsToFree);
        KeInitializeEvent(&SymbolsToLoadEvent, SynchronizationEvent, FALSE);

        Status = PsCreateSystemThread(&Thread,
                                      THREAD_ALL_ACCESS,
                                      NULL, NULL, NULL,
                                      LoadSymbolsRoutine,
                                      NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed starting symbols loader thread: 0x%08x\n", Status);
            LoadSymbols = FALSE;
            return LoadSymbols;
        }

        RosSymInitKernelMode();

        KeAcquireSpinLock(&PsLoadedModuleSpinLock, &OldIrql);

        for (ListEntry = PsLoadedModuleList.Flink;
             ListEntry != &PsLoadedModuleList;
             ListEntry = ListEntry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            KdbSymProcessSymbols(LdrEntry, TRUE);
        }

        KeReleaseSpinLock(&PsLoadedModuleSpinLock, OldIrql);
    }

    return LoadSymbols;
}

/* EOF */
