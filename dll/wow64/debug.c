/* ReactOS WoW64 user-mode debugging services. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"

/*
 * The debug object services of a 32-bit debugger (kernel32 and ntdll DbgUi*). The handles and
 * the flags pass through; NtDebugContinue takes a CLIENT_ID of two 32-bit values and
 * NtWaitForDebugEvent returns the i386 DBGUI_WAIT_STATE_CHANGE.
 *
 * What a 32-bit debugger sees of a WoW64 debuggee follows Windows 10 22H2 (measured with a
 * 32-bit debugger on a 32-bit debuggee): only the 32-bit side. The events of the native side
 * (the native ntdll, wow64*.dll, the native loader's initial breakpoint, exceptions raised in
 * native code) have addresses a 32-bit debugger cannot hold, so they are continued here without
 * reaching it: a breakpoint with DBG_CONTINUE, any other exception with DBG_EXCEPTION_NOT_HANDLED,
 * so that its native handlers run as without a debugger. A 32-bit breakpoint or single step
 * that the kernel reports as STATUS_WX86_BREAKPOINT / STATUS_WX86_SINGLE_STEP reaches the 32-bit
 * debugger as STATUS_BREAKPOINT / STATUS_SINGLE_STEP, as on Windows. The start address of a
 * thread is its Win32 start address (the guest's thread routine), as Windows reports it.
 */

typedef struct { ULONG UniqueProcess, UniqueThread; } WOW64_CLIENT_ID;
typedef struct { ULONG SubSystemKey, StartAddress; } WOW64_DBGKM_CREATE_THREAD;

typedef struct
{
    ULONG NewState;
    WOW64_CLIENT_ID AppClientId;
    union
    {
        struct { ULONG HandleToThread; WOW64_DBGKM_CREATE_THREAD NewThread; } CreateThread;
        struct
        {
            ULONG HandleToProcess, HandleToThread;
            struct
            {
                ULONG SubSystemKey, FileHandle, BaseOfImage, DebugInfoFileOffset, DebugInfoSize;
                WOW64_DBGKM_CREATE_THREAD InitialThread;
            } NewProcess;
        } CreateProcessInfo;
        struct { NTSTATUS ExitStatus; } ExitThread, ExitProcess;
        struct { EXCEPTION_RECORD32 ExceptionRecord; ULONG FirstChance; } Exception;
        struct { ULONG FileHandle, BaseOfDll, DebugInfoFileOffset, DebugInfoSize, NamePointer; } LoadDll;
        struct { ULONG BaseAddress; } UnloadDll;
    } StateInfo;
} WOW64_DBGUI_WAIT_STATE_CHANGE;

/* The i386 layout of ntdll's structure */
C_ASSERT(FIELD_OFFSET(WOW64_DBGUI_WAIT_STATE_CHANGE, StateInfo) == 12);
C_ASSERT(sizeof(WOW64_DBGUI_WAIT_STATE_CHANGE) == 96);

#define WOW64_ABOVE_GUEST(Pointer) ((ULONG_PTR)(Pointer) > MAXULONG)

static ULONG Narrow32(PVOID Value)
{
    return WOW64_ABOVE_GUEST(Value) ? 0 : PtrToUlong(Value);
}

/* The start address of a new thread as a 32-bit debugger sees it */
static ULONG ThreadStart32(HANDLE Thread, PVOID Reported)
{
    ULONG_PTR Win32Start = 0;
    if (Thread &&
        NT_SUCCESS(NtQueryInformationThread(Thread, ThreadQuerySetWin32StartAddress,
                                            &Win32Start, sizeof(Win32Start), NULL)) &&
        Win32Start && !WOW64_ABOVE_GUEST(Win32Start))
        return (ULONG)Win32Start;
    return Narrow32(Reported);
}

/* TRUE: the event belongs to the native side of the debuggee; *Continue is how to continue it */
static BOOLEAN NativeOnlyEvent(const DBGUI_WAIT_STATE_CHANGE *Change, NTSTATUS *Continue)
{
    const EXCEPTION_RECORD *Record;
    *Continue = DBG_CONTINUE;
    switch (Change->NewState)
    {
    case DbgExceptionStateChange:
    case DbgBreakpointStateChange:
    case DbgSingleStepStateChange:
        Record = &Change->StateInfo.Exception.ExceptionRecord;
        if (!WOW64_ABOVE_GUEST(Record->ExceptionAddress)) return FALSE;
        if (Record->ExceptionCode != STATUS_BREAKPOINT && Record->ExceptionCode != STATUS_SINGLE_STEP)
            *Continue = DBG_EXCEPTION_NOT_HANDLED;
        return TRUE;
    case DbgLoadDllStateChange:
        return WOW64_ABOVE_GUEST(Change->StateInfo.LoadDll.BaseOfDll);
    case DbgUnloadDllStateChange:
        return WOW64_ABOVE_GUEST(Change->StateInfo.UnloadDll.BaseAddress);
    default:
        return FALSE;
    }
}

/* The handles the kernel opened for this debugger with an event it does not receive */
static VOID CloseEventHandles(const DBGUI_WAIT_STATE_CHANGE *Change)
{
    switch (Change->NewState)
    {
    case DbgCreateThreadStateChange:
        if (Change->StateInfo.CreateThread.HandleToThread) NtClose(Change->StateInfo.CreateThread.HandleToThread);
        break;
    case DbgCreateProcessStateChange:
        if (Change->StateInfo.CreateProcessInfo.HandleToProcess)
            NtClose(Change->StateInfo.CreateProcessInfo.HandleToProcess);
        if (Change->StateInfo.CreateProcessInfo.HandleToThread)
            NtClose(Change->StateInfo.CreateProcessInfo.HandleToThread);
        if (Change->StateInfo.CreateProcessInfo.NewProcess.FileHandle)
            NtClose(Change->StateInfo.CreateProcessInfo.NewProcess.FileHandle);
        break;
    case DbgLoadDllStateChange:
        if (Change->StateInfo.LoadDll.FileHandle) NtClose(Change->StateInfo.LoadDll.FileHandle);
        break;
    default:
        break;
    }
}

static VOID StateChangeTo32(WOW64_DBGUI_WAIT_STATE_CHANGE *To, const DBGUI_WAIT_STATE_CHANGE *From)
{
    ULONG i, Count;
    RtlZeroMemory(To, sizeof(*To));
    To->NewState = From->NewState;
    To->AppClientId.UniqueProcess = HandleToUlong(From->AppClientId.UniqueProcess);
    To->AppClientId.UniqueThread = HandleToUlong(From->AppClientId.UniqueThread);
    switch (From->NewState)
    {
    case DbgCreateThreadStateChange:
        To->StateInfo.CreateThread.HandleToThread = HandleToUlong(From->StateInfo.CreateThread.HandleToThread);
        To->StateInfo.CreateThread.NewThread.SubSystemKey = From->StateInfo.CreateThread.NewThread.SubSystemKey;
        To->StateInfo.CreateThread.NewThread.StartAddress =
            ThreadStart32(From->StateInfo.CreateThread.HandleToThread,
                          From->StateInfo.CreateThread.NewThread.StartAddress);
        break;
    case DbgCreateProcessStateChange:
    {
        const DBGKM_CREATE_PROCESS *Process = &From->StateInfo.CreateProcessInfo.NewProcess;
        To->StateInfo.CreateProcessInfo.HandleToProcess = HandleToUlong(From->StateInfo.CreateProcessInfo.HandleToProcess);
        To->StateInfo.CreateProcessInfo.HandleToThread = HandleToUlong(From->StateInfo.CreateProcessInfo.HandleToThread);
        To->StateInfo.CreateProcessInfo.NewProcess.SubSystemKey = Process->SubSystemKey;
        To->StateInfo.CreateProcessInfo.NewProcess.FileHandle = HandleToUlong(Process->FileHandle);
        To->StateInfo.CreateProcessInfo.NewProcess.BaseOfImage = Narrow32(Process->BaseOfImage);
        To->StateInfo.CreateProcessInfo.NewProcess.DebugInfoFileOffset = Process->DebugInfoFileOffset;
        To->StateInfo.CreateProcessInfo.NewProcess.DebugInfoSize = Process->DebugInfoSize;
        To->StateInfo.CreateProcessInfo.NewProcess.InitialThread.SubSystemKey = Process->InitialThread.SubSystemKey;
        To->StateInfo.CreateProcessInfo.NewProcess.InitialThread.StartAddress = Narrow32(Process->InitialThread.StartAddress);
        break;
    }
    case DbgExitThreadStateChange:
        To->StateInfo.ExitThread.ExitStatus = From->StateInfo.ExitThread.ExitStatus;
        break;
    case DbgExitProcessStateChange:
        To->StateInfo.ExitProcess.ExitStatus = From->StateInfo.ExitProcess.ExitStatus;
        break;
    case DbgExceptionStateChange:
    case DbgBreakpointStateChange:
    case DbgSingleStepStateChange:
    {
        const EXCEPTION_RECORD *Record = &From->StateInfo.Exception.ExceptionRecord;
        EXCEPTION_RECORD32 *Record32 = &To->StateInfo.Exception.ExceptionRecord;
        Record32->ExceptionCode = Record->ExceptionCode;
        if (Record32->ExceptionCode == STATUS_WX86_BREAKPOINT)
        {
            Record32->ExceptionCode = STATUS_BREAKPOINT;
            To->NewState = DbgBreakpointStateChange;
        }
        else if (Record32->ExceptionCode == STATUS_WX86_SINGLE_STEP)
        {
            Record32->ExceptionCode = STATUS_SINGLE_STEP;
            To->NewState = DbgSingleStepStateChange;
        }
        Record32->ExceptionFlags = Record->ExceptionFlags;
        Record32->ExceptionRecord = Narrow32(Record->ExceptionRecord);
        Record32->ExceptionAddress = PtrToUlong(Record->ExceptionAddress);
        Count = min(Record->NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
        Record32->NumberParameters = Count;
        for (i = 0; i < Count; ++i)
            Record32->ExceptionInformation[i] = (ULONG)Record->ExceptionInformation[i];
        To->StateInfo.Exception.FirstChance = From->StateInfo.Exception.FirstChance;
        break;
    }
    case DbgLoadDllStateChange:
        To->StateInfo.LoadDll.FileHandle = HandleToUlong(From->StateInfo.LoadDll.FileHandle);
        To->StateInfo.LoadDll.BaseOfDll = PtrToUlong(From->StateInfo.LoadDll.BaseOfDll);
        To->StateInfo.LoadDll.DebugInfoFileOffset = From->StateInfo.LoadDll.DebugInfoFileOffset;
        To->StateInfo.LoadDll.DebugInfoSize = From->StateInfo.LoadDll.DebugInfoSize;
        /* &TEB->NtTib.ArbitraryUserPointer of the native TEB, which lies below 4 GB in a WoW64
         * process; its low half is the 32-bit loader's name (see NtMapViewOfSection) */
        To->StateInfo.LoadDll.NamePointer = Narrow32(From->StateInfo.LoadDll.NamePointer);
        break;
    case DbgUnloadDllStateChange:
        To->StateInfo.UnloadDll.BaseAddress = PtrToUlong(From->StateInfo.UnloadDll.BaseAddress);
        break;
    default:
        break;
    }
}

/* NtWaitForDebugEvent(DebugObject, Alertable, Timeout, StateChange) */
NTSTATUS Wow64WaitForDebugEvent(const ULONG *a)
{
    DBGUI_WAIT_STATE_CHANGE Native;
    WOW64_DBGUI_WAIT_STATE_CHANGE Guest;
    LARGE_INTEGER Timeout, Deadline, *TimeoutPointer = NULL;
    NTSTATUS Status, Continue;

    /* The output must be writable before an event is taken off the object */
    ProbeOutput(a[3], sizeof(Guest));
    if (a[2])
    {
        Timeout = *(volatile LARGE_INTEGER *)PTR32(a[2]);
        TimeoutPointer = &Timeout;
        /* A relative timeout covers the whole call, including events continued here: after the
         * first one, wait until the absolute time it ends */
        Deadline.QuadPart = 0;
        if (Timeout.QuadPart < 0)
        {
            NtQuerySystemTime(&Deadline);
            Deadline.QuadPart -= Timeout.QuadPart;
        }
    }
    for (;;)
    {
        Status = NtWaitForDebugEvent(HANDLE32(a[0]), (BOOLEAN)a[1], TimeoutPointer, &Native);
        if (Status != STATUS_SUCCESS) return Status;
        if (!NativeOnlyEvent(&Native, &Continue)) break;
        CloseEventHandles(&Native);
        NtDebugContinue(HANDLE32(a[0]), &Native.AppClientId, Continue);
        if (TimeoutPointer && Deadline.QuadPart) Timeout = Deadline;
    }
    StateChangeTo32(&Guest, &Native);
    _SEH2_TRY
    {
        RtlCopyMemory(PTR32(a[3]), &Guest, sizeof(Guest));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* The guest released its buffer meanwhile: it cannot receive the handles */
        CloseEventHandles(&Native);
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    return Status;
}

/* NtDebugContinue(DebugObject, ClientId, ContinueStatus) */
NTSTATUS Wow64DebugContinue(const ULONG *a)
{
    CLIENT_ID Id;
    const volatile WOW64_CLIENT_ID *Guest = PTR32(a[1]);
    if (!a[1]) return NtDebugContinue(HANDLE32(a[0]), NULL, a[2]);
    Id.UniqueProcess = UlongToHandle(Guest->UniqueProcess);
    Id.UniqueThread = UlongToHandle(Guest->UniqueThread);
    return NtDebugContinue(HANDLE32(a[0]), &Id, a[2]);
}
