/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Object manager callbacks: ObRegisterCallbacks, ObUnRegisterCallbacks,
 *              ObGetFilterVersion, and the dispatch of the pre and post operation
 *              callbacks around handle creation and duplication of processes and
 *              threads (the object types Windows lets drivers filter besides desktops).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Semantics from the WDK reference of ObRegisterCallbacks: registrations are
 * ordered by altitude (a decimal string), pre-operation callbacks run from the
 * highest altitude to the lowest, post-operation callbacks the other way round,
 * each callback sees the access the ones before it left and can only remove
 * access bits, and the CallContext a pre-operation callback sets is handed to
 * its post-operation callback.
 *
 * Divergence from Windows (operator decision 2026-11-08): Windows refuses
 * ObRegisterCallbacks (STATUS_ACCESS_DENIED) for a driver image that is not
 * linked with the integrity check flag. NitroOS has no driver signing story yet
 * and its drivers are unsigned in practice, so the call is allowed and a warning
 * naming the driver goes to the debugger and the System event log.
 * Not implemented: desktop objects (ExDesktopObjectType), registering from
 * a driver that is unloaded without ObUnRegisterCallbacks is not detected.
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define TAG_OB_CALLBACK 'bCbO'
#define OBP_MAX_REGISTRATIONS_PER_CALL 16

/* MM, no header exports it */
PLDR_DATA_TABLE_ENTRY
NTAPI
MiLookupDataTableEntry(IN PVOID Address);

typedef struct _OBP_CALLBACK_OPERATION
{
    POBJECT_TYPE ObjectType;
    OB_OPERATION Operations;
    POB_PRE_OPERATION_CALLBACK PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OBP_CALLBACK_OPERATION;

typedef struct _OBP_CALLBACK_REGISTRATION
{
    LIST_ENTRY Link;                /* ObpCallbackList, highest altitude first */
    PVOID Context;
    UNICODE_STRING Altitude;
    ULONG Count;
    EX_RUNDOWN_REF Rundown;         /* held by every handle operation that is inside the callbacks */
    OBP_CALLBACK_OPERATION Operation[ANYSIZE_ARRAY];
} OBP_CALLBACK_REGISTRATION, *POBP_CALLBACK_REGISTRATION;

/* What one handle operation remembers between its pre and post callbacks */
typedef struct _OBP_CALLBACK_CALL
{
    ULONG Count;
    OB_OPERATION Operation;
    BOOLEAN KernelHandle;
    PVOID Object;
    POBJECT_TYPE ObjectType;
    struct
    {
        POBP_CALLBACK_REGISTRATION Registration;
        PVOID CallContext;
    } Entry[ANYSIZE_ARRAY];
} OBP_CALLBACK_CALL;

/* GLOBALS ********************************************************************/

/* The push lock is valid zeroed; the list head is set up by the first registration */
static EX_PUSH_LOCK ObpCallbackLock;
static LIST_ENTRY ObpCallbackList;
volatile LONG ObpCallbackCount;

/* PRIVATE FUNCTIONS **********************************************************/

/* "380010" or "321000.5": digits with at most one dot, not empty, not starting with a dot */
static
BOOLEAN
ObpValidAltitude(IN PCUNICODE_STRING Altitude)
{
    ULONG i, Chars = Altitude->Length / sizeof(WCHAR);
    BOOLEAN Dot = FALSE;

    if (!Chars || !Altitude->Buffer || Altitude->Buffer[0] == L'.')
        return FALSE;
    for (i = 0; i < Chars; i++)
    {
        WCHAR c = Altitude->Buffer[i];
        if (c == L'.')
        {
            if (Dot) return FALSE;
            Dot = TRUE;
        }
        else if (c < L'0' || c > L'9')
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* -1, 0, 1 for two altitudes that passed ObpValidAltitude: numeric, not textual */
static
LONG
ObpCompareAltitude(IN PCUNICODE_STRING A, IN PCUNICODE_STRING B)
{
    PCWSTR a = A->Buffer, b = B->Buffer;
    ULONG aLen = A->Length / sizeof(WCHAR), bLen = B->Length / sizeof(WCHAR);
    ULONG aInt = 0, bInt = 0, i;

    while (aInt < aLen && a[aInt] != L'.') aInt++;
    while (bInt < bLen && b[bInt] != L'.') bInt++;

    /* Integer parts without leading zeros: the longer is the bigger, else compare the digits */
    while (aInt > 1 && *a == L'0') { a++; aInt--; aLen--; }
    while (bInt > 1 && *b == L'0') { b++; bInt--; bLen--; }
    if (aInt != bInt) return (aInt > bInt) ? 1 : -1;
    for (i = 0; i < aInt; i++)
        if (a[i] != b[i]) return (a[i] > b[i]) ? 1 : -1;

    /* Fractions: a missing digit is a zero */
    for (i = 1; ; i++)
    {
        WCHAR ca = (aInt + i < aLen) ? a[aInt + i] : L'0';
        WCHAR cb = (bInt + i < bLen) ? b[bInt + i] : L'0';
        if (aInt + i >= aLen && bInt + i >= bLen) return 0;
        if (ca != cb) return (ca > cb) ? 1 : -1;
    }
}

static
BOOLEAN
ObpIsFilterableType(IN POBJECT_TYPE ObjectType)
{
    return (ObjectType == PsProcessType) || (ObjectType == PsThreadType);
}

/* A registration's operation entry for the object type, or NULL */
static
OBP_CALLBACK_OPERATION *
ObpFindOperation(IN POBP_CALLBACK_REGISTRATION Registration,
                 IN POBJECT_TYPE ObjectType,
                 IN OB_OPERATION Operation)
{
    ULONG i;

    for (i = 0; i < Registration->Count; i++)
    {
        if (Registration->Operation[i].ObjectType == ObjectType &&
            (Registration->Operation[i].Operations & Operation))
        {
            return &Registration->Operation[i];
        }
    }
    return NULL;
}

/*
 * The image that holds the callback, and whether it carries the integrity
 * check flag. Windows refuses a driver without it; here it is a warning.
 */
static
VOID
ObpWarnWithoutIntegrityFlag(IN PVOID CallbackAddress)
{
    PLDR_DATA_TABLE_ENTRY Entry;
    PIMAGE_NT_HEADERS NtHeaders;
    WCHAR Name[64];
    ULONG Chars;

    Entry = MiLookupDataTableEntry(CallbackAddress);
    if (!Entry || !Entry->DllBase) return;

    NtHeaders = RtlImageNtHeader(Entry->DllBase);
    if (NtHeaders &&
        (NtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY))
    {
        return;
    }

    Chars = min(Entry->BaseDllName.Length / sizeof(WCHAR), RTL_NUMBER_OF(Name) - 1);
    RtlCopyMemory(Name, Entry->BaseDllName.Buffer, Chars * sizeof(WCHAR));
    Name[Chars] = UNICODE_NULL;

    DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL,
               "NITRO: ObRegisterCallbacks: %ws is not linked with the integrity check flag; "
               "Windows would refuse it, NitroOS allows it for now\n", Name);
    IopLogNitroEvent(NITRO_WARN_OB_CALLBACKS_NO_INTEGRITY, STATUS_SUCCESS, Name, NULL, NULL);
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * Called around a handle creation or duplication of a process or thread. On
 * return *DesiredAccess has the access the callbacks left. *Call is NULL when
 * no callback applies; otherwise it must be handed to ObpCallPostOperation,
 * which also releases the registrations (rundown protection).
 */
VOID
NTAPI
ObpCallPreOperation(IN OB_OPERATION Operation,
                    IN PVOID Object,
                    IN POBJECT_TYPE ObjectType,
                    IN BOOLEAN KernelHandle,
                    IN OUT PACCESS_MASK DesiredAccess,
                    IN PEPROCESS SourceProcess OPTIONAL,
                    IN PEPROCESS TargetProcess OPTIONAL,
                    OUT POBP_CALLBACK_CALL *Call)
{
    PLIST_ENTRY Entry;
    POBP_CALLBACK_REGISTRATION Registration;
    OBP_CALLBACK_OPERATION *Op;
    POBP_CALLBACK_CALL State;
    ULONG Matches = 0, i;
    ACCESS_MASK Original = *DesiredAccess;

    PAGED_CODE();

    *Call = NULL;
    if (!ObpIsFilterableType(ObjectType)) return;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&ObpCallbackLock);

    if (!ObpCallbackCount)
    {
        ExReleasePushLockShared(&ObpCallbackLock);
        KeLeaveCriticalRegion();
        return;
    }

    for (Entry = ObpCallbackList.Flink; Entry != &ObpCallbackList; Entry = Entry->Flink)
    {
        Registration = CONTAINING_RECORD(Entry, OBP_CALLBACK_REGISTRATION, Link);
        if (ObpFindOperation(Registration, ObjectType, Operation)) Matches++;
    }
    State = Matches ? ExAllocatePoolWithTag(PagedPool,
                                            FIELD_OFFSET(OBP_CALLBACK_CALL, Entry) +
                                            Matches * sizeof(State->Entry[0]),
                                            TAG_OB_CALLBACK) : NULL;
    if (State)
    {
        RtlZeroMemory(State, FIELD_OFFSET(OBP_CALLBACK_CALL, Entry) + Matches * sizeof(State->Entry[0]));
        State->Operation = Operation;
        State->KernelHandle = KernelHandle;
        State->Object = Object;
        State->ObjectType = ObjectType;

        /*
         * Highest altitude first. Each registration stays alive through its
         * rundown protection, so the lock is not held while the callbacks
         * run (a callback may open handles itself, which comes back here).
         */
        for (Entry = ObpCallbackList.Flink; Entry != &ObpCallbackList; Entry = Entry->Flink)
        {
            Registration = CONTAINING_RECORD(Entry, OBP_CALLBACK_REGISTRATION, Link);
            if (!ObpFindOperation(Registration, ObjectType, Operation)) continue;
            if (!ExAcquireRundownProtection(&Registration->Rundown)) continue;
            State->Entry[State->Count++].Registration = Registration;
        }
    }
    else if (Matches)
    {
        /* A handle operation does not fail for a filter that cannot run */
        DPRINT1("ObRegisterCallbacks: no memory for the callback state, callbacks skipped\n");
    }
    ExReleasePushLockShared(&ObpCallbackLock);
    KeLeaveCriticalRegion();
    if (!State) return;

    for (i = 0; i < State->Count; i++)
    {
        OB_PRE_OPERATION_INFORMATION Info;
        OB_PRE_OPERATION_PARAMETERS Params;

        Registration = State->Entry[i].Registration;
        Op = ObpFindOperation(Registration, ObjectType, Operation);
        if (!Op->PreOperation) continue;

        RtlZeroMemory(&Info, sizeof(Info));
        RtlZeroMemory(&Params, sizeof(Params));
        Info.Operation = Operation;
        Info.KernelHandle = KernelHandle ? 1 : 0;
        Info.Object = Object;
        Info.ObjectType = ObjectType;
        Info.Parameters = &Params;
        if (Operation == OB_OPERATION_HANDLE_DUPLICATE)
        {
            Params.DuplicateHandleInformation.DesiredAccess = *DesiredAccess;
            Params.DuplicateHandleInformation.OriginalDesiredAccess = Original;
            Params.DuplicateHandleInformation.SourceProcess = SourceProcess;
            Params.DuplicateHandleInformation.TargetProcess = TargetProcess;
        }
        else
        {
            Params.CreateHandleInformation.DesiredAccess = *DesiredAccess;
            Params.CreateHandleInformation.OriginalDesiredAccess = Original;
        }

        Op->PreOperation(Registration->Context, &Info);

        /* A callback can only take access away */
        if (Operation == OB_OPERATION_HANDLE_DUPLICATE)
            *DesiredAccess &= Params.DuplicateHandleInformation.DesiredAccess;
        else
            *DesiredAccess &= Params.CreateHandleInformation.DesiredAccess;
        State->Entry[i].CallContext = Info.CallContext;
    }

    *Call = State;
}

VOID
NTAPI
ObpCallPostOperation(IN POBP_CALLBACK_CALL Call,
                     IN NTSTATUS ReturnStatus,
                     IN ACCESS_MASK GrantedAccess)
{
    OBP_CALLBACK_OPERATION *Op;
    LONG i;

    PAGED_CODE();

    /* Lowest altitude first */
    for (i = (LONG)Call->Count - 1; i >= 0; i--)
    {
        OB_POST_OPERATION_INFORMATION Info;
        OB_POST_OPERATION_PARAMETERS Params;

        Op = ObpFindOperation(Call->Entry[i].Registration, Call->ObjectType, Call->Operation);
        if (!Op || !Op->PostOperation) continue;

        RtlZeroMemory(&Info, sizeof(Info));
        RtlZeroMemory(&Params, sizeof(Params));
        Info.Operation = Call->Operation;
        Info.KernelHandle = Call->KernelHandle ? 1 : 0;
        Info.Object = Call->Object;
        Info.ObjectType = Call->ObjectType;
        Info.CallContext = Call->Entry[i].CallContext;
        Info.ReturnStatus = ReturnStatus;
        Info.Parameters = &Params;
        if (Call->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            Params.DuplicateHandleInformation.GrantedAccess = GrantedAccess;
        else
            Params.CreateHandleInformation.GrantedAccess = GrantedAccess;

        Op->PostOperation(Call->Entry[i].Registration->Context, &Info);
    }

    for (i = 0; i < (LONG)Call->Count; i++)
        ExReleaseRundownProtection(&Call->Entry[i].Registration->Rundown);
    ExFreePoolWithTag(Call, TAG_OB_CALLBACK);
}

/*
 * @implemented
 */
NTSTATUS
NTAPI
ObRegisterCallbacks(IN POB_CALLBACK_REGISTRATION CallbackRegistration,
                    OUT PVOID *RegistrationHandle)
{
    POBP_CALLBACK_REGISTRATION Registration, Other;
    PLIST_ENTRY Entry;
    ULONG i, j, Size;
    PVOID WarnAddress = NULL;
    LONG Cmp;

    PAGED_CODE();

    if (!CallbackRegistration || !RegistrationHandle)
        return STATUS_INVALID_PARAMETER;
    *RegistrationHandle = NULL;

    if (CallbackRegistration->Version != OB_FLT_REGISTRATION_VERSION ||
        CallbackRegistration->OperationRegistrationCount == 0 ||
        CallbackRegistration->OperationRegistrationCount > OBP_MAX_REGISTRATIONS_PER_CALL ||
        !CallbackRegistration->OperationRegistration ||
        !ObpValidAltitude(&CallbackRegistration->Altitude))
    {
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < CallbackRegistration->OperationRegistrationCount; i++)
    {
        OB_OPERATION_REGISTRATION *Op = &CallbackRegistration->OperationRegistration[i];

        if (!Op->ObjectType || !ObpIsFilterableType(*Op->ObjectType) ||
            !(Op->Operations & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE)) ||
            (Op->Operations & ~(OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE)) ||
            (!Op->PreOperation && !Op->PostOperation))
        {
            return STATUS_INVALID_PARAMETER;
        }
        /* One entry per object type */
        for (j = 0; j < i; j++)
            if (*CallbackRegistration->OperationRegistration[j].ObjectType == *Op->ObjectType)
                return STATUS_INVALID_PARAMETER;
        if (!WarnAddress) WarnAddress = Op->PreOperation ? (PVOID)Op->PreOperation : (PVOID)Op->PostOperation;
    }

    Size = FIELD_OFFSET(OBP_CALLBACK_REGISTRATION, Operation) +
           CallbackRegistration->OperationRegistrationCount * sizeof(OBP_CALLBACK_OPERATION) +
           CallbackRegistration->Altitude.Length;
    Registration = ExAllocatePoolWithTag(PagedPool, Size, TAG_OB_CALLBACK);
    if (!Registration)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(Registration, Size);

    ExInitializeRundownProtection(&Registration->Rundown);
    Registration->Context = CallbackRegistration->RegistrationContext;
    Registration->Count = CallbackRegistration->OperationRegistrationCount;
    for (i = 0; i < Registration->Count; i++)
    {
        OB_OPERATION_REGISTRATION *Op = &CallbackRegistration->OperationRegistration[i];

        Registration->Operation[i].ObjectType = *Op->ObjectType;
        Registration->Operation[i].Operations = Op->Operations;
        Registration->Operation[i].PreOperation = Op->PreOperation;
        Registration->Operation[i].PostOperation = Op->PostOperation;
    }
    Registration->Altitude.Buffer = (PWCHAR)&Registration->Operation[Registration->Count];
    Registration->Altitude.Length = CallbackRegistration->Altitude.Length;
    Registration->Altitude.MaximumLength = CallbackRegistration->Altitude.Length;
    RtlCopyMemory(Registration->Altitude.Buffer, CallbackRegistration->Altitude.Buffer,
                  CallbackRegistration->Altitude.Length);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ObpCallbackLock);
    if (!ObpCallbackList.Flink) InitializeListHead(&ObpCallbackList);

    /* Sorted highest first; the same altitude twice is refused */
    for (Entry = ObpCallbackList.Flink; Entry != &ObpCallbackList; Entry = Entry->Flink)
    {
        Other = CONTAINING_RECORD(Entry, OBP_CALLBACK_REGISTRATION, Link);
        Cmp = ObpCompareAltitude(&Registration->Altitude, &Other->Altitude);
        if (Cmp == 0)
        {
            ExReleasePushLockExclusive(&ObpCallbackLock);
            KeLeaveCriticalRegion();
            ExFreePoolWithTag(Registration, TAG_OB_CALLBACK);
            return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
        }
        if (Cmp > 0) break;
    }
    /* Insert before Entry (the head when the new one is the lowest) */
    Registration->Link.Flink = Entry;
    Registration->Link.Blink = Entry->Blink;
    Entry->Blink->Flink = &Registration->Link;
    Entry->Blink = &Registration->Link;
    InterlockedIncrement(&ObpCallbackCount);

    ExReleasePushLockExclusive(&ObpCallbackLock);
    KeLeaveCriticalRegion();

    ObpWarnWithoutIntegrityFlag(WarnAddress);

    *RegistrationHandle = Registration;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
VOID
NTAPI
ObUnRegisterCallbacks(IN PVOID RegistrationHandle)
{
    POBP_CALLBACK_REGISTRATION Registration = RegistrationHandle;

    PAGED_CODE();

    if (!Registration) return;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&ObpCallbackLock);
    RemoveEntryList(&Registration->Link);
    InterlockedDecrement(&ObpCallbackCount);
    ExReleasePushLockExclusive(&ObpCallbackLock);
    KeLeaveCriticalRegion();

    /* Waits for the handle operations that are inside its callbacks right now */
    ExWaitForRundownProtectionRelease(&Registration->Rundown);

    ExFreePoolWithTag(Registration, TAG_OB_CALLBACK);
}

/*
 * @implemented
 */
USHORT
NTAPI
ObGetFilterVersion(VOID)
{
    return OB_FLT_REGISTRATION_VERSION;
}
