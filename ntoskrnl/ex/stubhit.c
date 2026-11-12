/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Stub-hit logger: the first time an exported but unimplemented
 *              ("stubbed") routine is called, record which module called it.
 *
 * Stubbed exports resolve at load time, so the missing-import log does not
 * see them; they simply return STATUS_NOT_IMPLEMENTED, silently on Release.
 * NTOS_STUB_HIT() (internal/ex.h) calls ExpStubHit, which, once per routine:
 *  - prints one line with DbgPrintEx (also on Release),
 *  - records the routine and the calling module in the registry:
 *    HKLM\SYSTEM\CurrentControlSet\Control\NitroOS\StubHits, one REG_SZ value
 *    per routine named after it, holding the name of the calling module,
 *  - writes a System event (source NitroKernel, id 0x7003).
 * The caller is the module whose image range contains the return address.
 * Registry and event are written from a work item (the stub may be called at
 * DISPATCH_LEVEL). Boot drivers call stubs every boot, and a registry write
 * that early dirties the SYSTEM hive while the session manager still runs the
 * disk check on the boot volume: the hive flush then races with it (a FAT
 * boot volume reported its hive backup file as corrupt, seen in a guest). So
 * the work item runs no earlier than EXP_STUBHIT_PERSIST_DELAY after boot (the
 * debugger line is immediate), a value that is already recorded with the same
 * caller is not written again (no hive change on later boots), and entries
 * whose write failed stay pending until the next hit.
 */
#define EXP_STUBHIT_PERSIST_DELAY   (60ULL * 10 * 1000 * 1000) /* 100 ns units */

/* INCLUDES *****************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define EXP_STUBHIT_MAX     192
#define EXP_STUBHIT_NAME    64
#define EXP_STUBHIT_MODULE  32

typedef struct _EXP_STUBHIT_ENTRY
{
    PCSTR Function;                         /* the __FUNCTION__ literal */
    WCHAR Name[EXP_STUBHIT_NAME];
    WCHAR Module[EXP_STUBHIT_MODULE];
    BOOLEAN Persisted;
    BOOLEAN Evented;
} EXP_STUBHIT_ENTRY;

static EXP_STUBHIT_ENTRY ExpStubHits[EXP_STUBHIT_MAX];
static volatile ULONG ExpStubHitCount;
static KSPIN_LOCK ExpStubHitLock;
static WORK_QUEUE_ITEM ExpStubHitWorkItem;
static BOOLEAN ExpStubHitWorkQueued;
static KTIMER ExpStubHitTimer;
static KDPC ExpStubHitDpc;
static BOOLEAN ExpStubHitTimerInit;

/* FUNCTIONS ****************************************************************/

static
VOID
NTAPI
ExpStubHitWorker(
    _In_ PVOID Context)
{
    static PCWSTR Paths[] =
    {
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\NitroOS",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\NitroOS\\StubHits"
    };
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Key = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG i, Disposition;
    KIRQL OldIrql;

    UNREFERENCED_PARAMETER(Context);
    PAGED_CODE();

    /* Best effort: a registry that is not writable yet only delays the
       persistent copy to the next run of this worker */
    for (i = 0; i < RTL_NUMBER_OF(Paths); i++)
    {
        if (Key) ZwClose(Key);
        Key = NULL;
        RtlInitUnicodeString(&Name, Paths[i]);
        InitializeObjectAttributes(&ObjectAttributes, &Name,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL, NULL);
        Status = ZwCreateKey(&Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL,
                             REG_OPTION_NON_VOLATILE, &Disposition);
        if (!NT_SUCCESS(Status))
        {
            Key = NULL;
            break;
        }
    }

    for (i = 0; ; i++)
    {
        EXP_STUBHIT_ENTRY Todo;
        BOOLEAN NeedEvent, NeedPersist;

        KeAcquireSpinLock(&ExpStubHitLock, &OldIrql);
        if (i >= ExpStubHitCount)
        {
            /* Entries added from now on queue the worker again */
            ExpStubHitWorkQueued = FALSE;
            KeReleaseSpinLock(&ExpStubHitLock, OldIrql);
            break;
        }
        Todo = ExpStubHits[i];
        NeedEvent = !Todo.Evented;
        NeedPersist = !Todo.Persisted && Key != NULL;
        ExpStubHits[i].Evented = TRUE;
        KeReleaseSpinLock(&ExpStubHitLock, OldIrql);

        if (NeedPersist)
        {
            UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + EXP_STUBHIT_MODULE * sizeof(WCHAR)];
            PKEY_VALUE_PARTIAL_INFORMATION Info = (PVOID)Buffer;
            ULONG Length;
            ULONG ModuleBytes = (ULONG)(wcslen(Todo.Module) + 1) * sizeof(WCHAR);

            RtlInitUnicodeString(&Name, Todo.Name);

            /* Already recorded with the same caller: leave the hive alone */
            Status = ZwQueryValueKey(Key, &Name, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
            if (NT_SUCCESS(Status) && Info->Type == REG_SZ && Info->DataLength == ModuleBytes &&
                RtlEqualMemory(Info->Data, Todo.Module, ModuleBytes))
            {
                /* nothing to write */
            }
            else
            {
                Status = ZwSetValueKey(Key, &Name, 0, REG_SZ, Todo.Module, ModuleBytes);
            }
            if (NT_SUCCESS(Status))
            {
                KeAcquireSpinLock(&ExpStubHitLock, &OldIrql);
                ExpStubHits[i].Persisted = TRUE;
                KeReleaseSpinLock(&ExpStubHitLock, OldIrql);
            }
        }
        if (NeedEvent)
            IopLogNitroEvent(NITRO_WARN_STUB_CALLED, STATUS_SUCCESS, Todo.Name, Todo.Module, NULL);
    }

    if (Key) ZwClose(Key);
}

/* Time since boot in 100 ns units */
static
ULONGLONG
ExpStubHitUptime(VOID)
{
    LARGE_INTEGER Time;

    do
    {
        Time.HighPart = SharedUserData->InterruptTime.High1Time;
        Time.LowPart = SharedUserData->InterruptTime.LowPart;
    } while (Time.HighPart != SharedUserData->InterruptTime.High2Time);

    return (ULONGLONG)Time.QuadPart;
}

static
VOID
NTAPI
ExpStubHitDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExQueueWorkItem(&ExpStubHitWorkItem, DelayedWorkQueue);
}

static
VOID
ExpStubHitFindModule(
    _In_ PVOID Address,
    _Out_writes_(EXP_STUBHIT_MODULE) PWCHAR Module)
{
    PLIST_ENTRY NextEntry;
    KIRQL OldIrql;
    ULONG n;

    wcscpy(Module, L"unknown");

    KeAcquireSpinLock(&PsLoadedModuleSpinLock, &OldIrql);
    for (NextEntry = PsLoadedModuleList.Flink;
         NextEntry != &PsLoadedModuleList;
         NextEntry = NextEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if ((ULONG_PTR)Address >= (ULONG_PTR)Entry->DllBase &&
            (ULONG_PTR)Address < (ULONG_PTR)Entry->DllBase + Entry->SizeOfImage)
        {
            if (Entry->BaseDllName.Buffer)
            {
                n = min(Entry->BaseDllName.Length / sizeof(WCHAR), EXP_STUBHIT_MODULE - 1);
                RtlCopyMemory(Module, Entry->BaseDllName.Buffer, n * sizeof(WCHAR));
                Module[n] = UNICODE_NULL;
            }
            break;
        }
    }
    KeReleaseSpinLock(&PsLoadedModuleSpinLock, OldIrql);
}

VOID
NTAPI
ExpStubHit(
    _In_ PCSTR Function,
    _In_ PVOID ReturnAddress)
{
    EXP_STUBHIT_ENTRY *Slot = NULL;
    BOOLEAN Queue = FALSE;
    KIRQL OldIrql;
    ULONG i, Count, n;
    WCHAR Module[EXP_STUBHIT_MODULE];

    /* Cheap pre-check without the lock: most calls are repeats */
    Count = ExpStubHitCount;
    for (i = 0; i < Count; i++)
    {
        if (ExpStubHits[i].Function == Function)
            return;
    }

    /* Spin locks at IRQL > DISPATCH_LEVEL would be wrong: skip the logger */
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        return;

    ExpStubHitFindModule(ReturnAddress, Module);

    KeAcquireSpinLock(&ExpStubHitLock, &OldIrql);
    Count = ExpStubHitCount;
    for (i = 0; i < Count; i++)
    {
        if (ExpStubHits[i].Function == Function)
            break;
    }
    if (i == Count && Count < EXP_STUBHIT_MAX)
    {
        Slot = &ExpStubHits[Count];
        Slot->Function = Function;
        for (n = 0; Function[n] && n < EXP_STUBHIT_NAME - 1; n++)
            Slot->Name[n] = (WCHAR)(UCHAR)Function[n];
        Slot->Name[n] = UNICODE_NULL;
        RtlCopyMemory(Slot->Module, Module, sizeof(Slot->Module));
        Slot->Persisted = FALSE;
        Slot->Evented = FALSE;
        ExpStubHitCount = Count + 1;
        if (!ExpStubHitWorkQueued)
        {
            ExpStubHitWorkQueued = TRUE;
            Queue = TRUE;
        }
    }
    KeReleaseSpinLock(&ExpStubHitLock, OldIrql);

    if (Slot)
    {
        DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL,
                   "NITRO: stub %s called by %ws (unimplemented stub)\n",
                   Function, Module);
    }
    if (Queue)
    {
        ULONGLONG Now = ExpStubHitUptime();

        ExInitializeWorkItem(&ExpStubHitWorkItem, ExpStubHitWorker, NULL);
        if (Now >= EXP_STUBHIT_PERSIST_DELAY)
        {
            ExQueueWorkItem(&ExpStubHitWorkItem, DelayedWorkQueue);
        }
        else
        {
            LARGE_INTEGER DueTime;

            /* The queued flag is held, so only one hit gets here */
            if (!ExpStubHitTimerInit)
            {
                KeInitializeTimer(&ExpStubHitTimer);
                KeInitializeDpc(&ExpStubHitDpc, ExpStubHitDpcRoutine, NULL);
                ExpStubHitTimerInit = TRUE;
            }
            DueTime.QuadPart = -(LONGLONG)(EXP_STUBHIT_PERSIST_DELAY - Now);
            KeSetTimer(&ExpStubHitTimer, DueTime, &ExpStubHitDpc);
        }
    }
}
