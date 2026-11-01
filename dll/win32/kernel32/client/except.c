/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/except.c
 * PURPOSE:         Exception functions
 * PROGRAMMER:      Ariadne (ariadne@xs4all.nl)
 *                  Modified from WINE [ Onno Hovers, (onno@stack.urc.tue.nl) ]
 * UPDATE HISTORY:
 *                  Created 01/11/98
 */

/* INCLUDES *******************************************************************/

#include <k32.h>
#include <strsafe.h>
#ifdef _M_IX86
#include "i386/ketypes.h"
#endif

#define NDEBUG
#include <debug.h>

/*
 * Private helper function to lookup the module name from a given address.
 * The address can point to anywhere within the module.
 */
static const char*
_module_name_from_addr(const void* addr, void **module_start_addr,
                       char* psz, size_t nChars, char** module_name)
{
    MEMORY_BASIC_INFORMATION mbi;

    if ((nChars > MAXDWORD) ||
        (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) ||
        !GetModuleFileNameA((HMODULE)mbi.AllocationBase, psz, (DWORD)nChars))
    {
        psz[0] = '\0';
        *module_name = psz;
        *module_start_addr = 0;
    }
    else
    {
        char* s1 = strrchr(psz, '\\'), *s2 = strrchr(psz, '/');
        if (s2 && !s1)
            s1 = s2;
        else if (s1 && s2 && s1 < s2)
            s1 = s2;

        if (!s1)
            s1 = psz;
        else
            s1++;

        *module_name = s1;
        *module_start_addr = (void *)mbi.AllocationBase;
    }
    return psz;
}


static VOID
_dump_context(PCONTEXT pc)
{
#ifdef _M_IX86
    /*
     * Print out the CPU registers
     */
    DbgPrint("CS:EIP %x:%x\n", pc->SegCs&0xffff, pc->Eip );
    DbgPrint("DS %x ES %x FS %x GS %x\n", pc->SegDs&0xffff, pc->SegEs&0xffff,
             pc->SegFs&0xffff, pc->SegGs&0xfff);
    DbgPrint("EAX: %.8x   EBX: %.8x   ECX: %.8x\n", pc->Eax, pc->Ebx, pc->Ecx);
    DbgPrint("EDX: %.8x   EBP: %.8x   ESI: %.8x   ESP: %.8x\n", pc->Edx,
             pc->Ebp, pc->Esi, pc->Esp);
    DbgPrint("EDI: %.8x   EFLAGS: %.8x\n", pc->Edi, pc->EFlags);
#elif defined(_M_AMD64)
    DbgPrint("CS:RIP %x:%I64x\n", pc->SegCs&0xffff, pc->Rip );
    DbgPrint("DS %x ES %x FS %x GS %x\n", pc->SegDs&0xffff, pc->SegEs&0xffff,
             pc->SegFs&0xffff, pc->SegGs&0xfff);
    DbgPrint("RAX: %I64x   RBX: %I64x   RCX: %I64x RDI: %I64x\n", pc->Rax, pc->Rbx, pc->Rcx, pc->Rdi);
    DbgPrint("RDX: %I64x   RBP: %I64x   RSI: %I64x   RSP: %I64x\n", pc->Rdx, pc->Rbp, pc->Rsi, pc->Rsp);
    DbgPrint("R8: %I64x   R9: %I64x   R10: %I64x   R11: %I64x\n", pc->R8, pc->R9, pc->R10, pc->R11);
    DbgPrint("R12: %I64x   R13: %I64x   R14: %I64x   R15: %I64x\n", pc->R12, pc->R13, pc->R14, pc->R15);
    DbgPrint("EFLAGS: %.8x\n", pc->EFlags);
#elif defined(_M_ARM)
    DbgPrint("PC:  %08lx   LR:  %08lx   SP:  %08lx\n", pc->Pc, pc->Lr, pc->Sp);
    DbgPrint("R0:  %08lx   R1:  %08lx   R2:  %08lx   R3:  %08lx\n", pc->R0, pc->R1, pc->R2, pc->R3);
    DbgPrint("R4:  %08lx   R5:  %08lx   R6:  %08lx   R7:  %08lx\n", pc->R4, pc->R5, pc->R6, pc->R7);
    DbgPrint("R8:  %08lx   R9:  %08lx   R10: %08lx   R11: %08lx\n", pc->R8, pc->R9, pc->R10, pc->R11);
    DbgPrint("R12: %08lx   CPSR: %08lx  FPSCR: %08lx\n", pc->R12, pc->Cpsr, pc->Fpscr);
#else
    #error "Unknown architecture"
#endif
}

static VOID
PrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo)
{
    PVOID StartAddr;
    CHAR szMod[128] = "", *szModFile;
    PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

    /* Print a stack trace */
    DbgPrint("Unhandled exception\n");
    DbgPrint("ExceptionCode:    %8x\n", ExceptionRecord->ExceptionCode);

    if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION &&
        ExceptionRecord->NumberParameters == 2)
    {
        DbgPrint("Faulting Address: %p\n", (PVOID)ExceptionRecord->ExceptionInformation[1]);
    }

    /* Trace the wine special error and show the modulename and functionname */
    if (ExceptionRecord->ExceptionCode == 0x80000100 /* EXCEPTION_WINE_STUB */ &&
        ExceptionRecord->NumberParameters == 2)
    {
        DbgPrint("Missing function: %s!%s\n", (PSZ)ExceptionRecord->ExceptionInformation[0], (PSZ)ExceptionRecord->ExceptionInformation[1]);
    }

    _dump_context(ContextRecord);
    _module_name_from_addr(ExceptionRecord->ExceptionAddress, &StartAddr, szMod, sizeof(szMod), &szModFile);
    DbgPrint("Address:\n<%s:%x> (%s@%x)\n",
             szModFile,
             (ULONG_PTR)ExceptionRecord->ExceptionAddress - (ULONG_PTR)StartAddr,
             szMod,
             StartAddr);
#ifdef _M_IX86
    DbgPrint("Frames:\n");

    _SEH2_TRY
    {
        UINT i;
        PULONG Frame = (PULONG)ContextRecord->Ebp;

        for (i = 0; Frame[1] != 0 && Frame[1] != 0xdeadbeef && i < 128; i++)
        {
            if (IsBadReadPtr((PVOID)Frame[1], 4))
            {
                DbgPrint("<%s:%x>\n", "[invalid address]", Frame[1]);
            }
            else
            {
                _module_name_from_addr((const void*)Frame[1], &StartAddr,
                                       szMod, sizeof(szMod), &szModFile);
                DbgPrint("<%s:%x> (%s@%x)\n",
                         szModFile,
                         (ULONG_PTR)Frame[1] - (ULONG_PTR)StartAddr,
                         szMod,
                         StartAddr);
            }

            if (IsBadReadPtr((PVOID)Frame[0], sizeof(*Frame) * 2))
                break;

            Frame = (PULONG)Frame[0];
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("<error dumping stack trace: 0x%x>\n", _SEH2_GetExceptionCode());
    }
    _SEH2_END;
#endif
}

/* GLOBALS ********************************************************************/

LPTOP_LEVEL_EXCEPTION_FILTER GlobalTopLevelExceptionFilter;
DWORD g_dwLastErrorToBreakOn;

/* FUNCTIONS ******************************************************************/

LONG
WINAPI
BasepCheckForReadOnlyResource(IN PVOID Ptr)
{
    PVOID Data;
    ULONG Size, OldProtect;
    SIZE_T Size2;
    MEMORY_BASIC_INFORMATION mbi;
    NTSTATUS Status;
    LONG Ret = EXCEPTION_CONTINUE_SEARCH;

    /* Check if it was an attempt to write to a read-only image section! */
    Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                  Ptr,
                                  MemoryBasicInformation,
                                  &mbi,
                                  sizeof(mbi),
                                  NULL);
    if (NT_SUCCESS(Status) &&
        mbi.Protect == PAGE_READONLY && mbi.Type == MEM_IMAGE)
    {
        /* Attempt to treat it as a resource section. We need to
           use SEH here because we don't know if it's actually a
           resource mapping */
        _SEH2_TRY
        {
            Data = RtlImageDirectoryEntryToData(mbi.AllocationBase,
                                                TRUE,
                                                IMAGE_DIRECTORY_ENTRY_RESOURCE,
                                                &Size);

            if (Data != NULL &&
                (ULONG_PTR)Ptr >= (ULONG_PTR)Data &&
                (ULONG_PTR)Ptr < (ULONG_PTR)Data + Size)
            {
                /* The user tried to write into the resources. Make the page
                   writable... */
                Size2 = 1;
                Status = NtProtectVirtualMemory(NtCurrentProcess(),
                                                &Ptr,
                                                &Size2,
                                                PAGE_READWRITE,
                                                &OldProtect);
                if (NT_SUCCESS(Status))
                {
                    Ret = EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
        }
        _SEH2_END;
    }

    return Ret;
}

/* Thread that is reporting an unhandled exception, 0 if none */
static LONG BasepReportingThread;

/* Declared by winbase.h for newer targets only */
UINT WINAPI GetErrorMode(VOID);

static
BOOLEAN
BasepIsGpFaultErrorBoxDisabled(VOID)
{
    return (GetErrorMode() & SEM_NOGPFAULTERRORBOX) ||
           (RtlGetThreadErrorMode() & RTL_SEM_NOGPFAULTERRORBOX);
}

/*
 * The crash reporter normally decides whether a dialog is shown (see
 * CanShowUi in drwtsn32). When it did not answer, the classic hard error box
 * is the fallback, which must follow the same rules: no box when error
 * reporting is told not to show its UI, nor on a window station without a
 * display. DontShowUI is read from the machine key and its policy key, in the
 * 64-bit view also for a 32-bit program, like drwtsn32 does.
 */
#define BASEP_WER_KEY           L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"
#define BASEP_WER_POLICY_KEY    L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting"
#define BASEP_UOI_FLAGS         1
#define BASEP_WSF_VISIBLE       1

typedef struct _BASEP_USEROBJECTFLAGS
{
    BOOL fInherit;
    BOOL fReserved;
    DWORD dwFlags;
} BASEP_USEROBJECTFLAGS;

static
BOOLEAN
BasepIsDontShowUiSet(
    _In_ PCWSTR KeyName)
{
    static UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"DontShowUI");
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PVOID)Buffer;
    HANDLE KeyHandle;
    ULONG Length;
    NTSTATUS Status;
    BOOLEAN Set = FALSE;

    RtlInitUnicodeString(&Name, KeyName);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Status = NtQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length);
    if (NT_SUCCESS(Status) && Info->Type == REG_DWORD && Info->DataLength == sizeof(ULONG))
        Set = (*(PULONG)Info->Data != 0);
    NtClose(KeyHandle);
    return Set;
}

/* TRUE when it cannot be said (no user32): the box stays as it always was */
static
BOOLEAN
BasepIsWindowStationVisible(VOID)
{
    HMODULE User32 = GetModuleHandleW(L"user32.dll");
    HANDLE (WINAPI *GetWinSta)(VOID);
    BOOL (WINAPI *GetObjectInfo)(HANDLE, int, PVOID, DWORD, PDWORD);
    BASEP_USEROBJECTFLAGS Flags;
    HANDLE WinSta;

    if (!User32)
        return TRUE;
    GetWinSta = (PVOID)GetProcAddress(User32, "GetProcessWindowStation");
    GetObjectInfo = (PVOID)GetProcAddress(User32, "GetUserObjectInformationW");
    if (!GetWinSta || !GetObjectInfo)
        return TRUE;

    WinSta = GetWinSta();
    return WinSta &&
           GetObjectInfo(WinSta, BASEP_UOI_FLAGS, &Flags, sizeof(Flags), NULL) &&
           (Flags.dwFlags & BASEP_WSF_VISIBLE);
}

static
BOOLEAN
BasepCanShowCrashBox(VOID)
{
    BOOLEAN CanShow = TRUE;

    /* A damaged process may fault here; then the box is shown as before */
    _SEH2_TRY
    {
        CanShow = !BasepIsDontShowUiSet(BASEP_WER_POLICY_KEY) &&
                  !BasepIsDontShowUiSet(BASEP_WER_KEY) &&
                  BasepIsWindowStationVisible();
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        CanShow = TRUE;
    }
    _SEH2_END;
    return CanShow;
}

/* Exit codes of "drwtsn32 -u -ui"; any other code keeps the classic hard error box */
#define CRASH_REPORTER_CLOSE    0x00C105ED
#define CRASH_REPORTER_DEBUG    0x00DEB06D

typedef struct _BASEP_CRASH_REPORT
{
    PEXCEPTION_POINTERS ExceptionInfo;
    ULONG ThreadId;
    BOOLEAN ShowUi;
    BOOLEAN OfferDebug;
    /* Set by the reporter once the report is written, before it shows its dialog */
    HANDLE ReportedEvent;
    /* Exit code of the reporter, MAXULONG when it did not finish */
    ULONG Result;
} BASEP_CRASH_REPORT, *PBASEP_CRASH_REPORT;

/*
 * Start drwtsn32, which writes the crash report out of process, and wait for
 * it. Returns FALSE when it did not finish by itself, so it may still read
 * this process or have left threads suspended.
 */
static
BOOLEAN
BasepStartCrashReporter(
    _In_ PBASEP_CRASH_REPORT Report)
{
    LARGE_INTEGER Timeout;
    WCHAR ReporterPath[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 128];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    HANDLE WaitHandles[2];
    ULONG ExitCode;
    BOOL Started = FALSE;
    BOOLEAN Faulted = FALSE;
    NTSTATUS Status;

    if (FAILED(StringCchPrintfW(ReporterPath,
                                ARRAYSIZE(ReporterPath),
                                L"%s\\System32\\drwtsn32.exe",
                                SharedUserData->NtSystemRoot)) ||
        FAILED(StringCchPrintfW(CommandLine,
                                ARRAYSIZE(CommandLine),
                                L"\"%s\" -u -p %lu -t %lu -x %Ix%s%s -r %Ix",
                                ReporterPath,
                                HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess),
                                Report->ThreadId,
                                (ULONG_PTR)Report->ExceptionInfo,
                                Report->ShowUi ? L" -ui" : L"",
                                Report->OfferDebug ? L" -d" : L"",
                                (ULONG_PTR)Report->ReportedEvent)))
    {
        return TRUE;
    }

    /* A damaged process may fault here, possibly after the reporter started */
    _SEH2_TRY
    {
        RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
        StartupInfo.cb = sizeof(StartupInfo);
        Started = CreateProcessW(ReporterPath,
                                 CommandLine,
                                 NULL, NULL,
                                 FALSE,
                                 CREATE_DEFAULT_ERROR_MODE,
                                 NULL, NULL,
                                 &StartupInfo, &ProcessInfo);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Faulted = TRUE;
    }
    _SEH2_END;
    if (Faulted)
        return FALSE;
    if (!Started)
    {
        DPRINT1("Cannot start the crash reporter: %lu\n", GetLastError());
        return TRUE;
    }

    /* A full dump of a large process takes a while; never wait forever for it */
    Timeout.QuadPart = -10 * 60 * 10000000LL;
    WaitHandles[0] = ProcessInfo.hProcess;
    WaitHandles[1] = Report->ReportedEvent;
    Status = NtWaitForMultipleObjects(Report->ReportedEvent ? 2 : 1, WaitHandles, WaitAny, FALSE, &Timeout);
    if (Status == STATUS_WAIT_1)
    {
        /* The report is written; the user takes as long as needed to answer the dialog */
        Status = NtWaitForSingleObject(ProcessInfo.hProcess, FALSE, NULL);
    }
    if (Status == STATUS_WAIT_0 && GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode))
        Report->Result = ExitCode;
    if (Status != STATUS_WAIT_0)
    {
        /* Stop it before the exception data goes away; the threads it suspended stay so */
        NtTerminateProcess(ProcessInfo.hProcess, STATUS_TIMEOUT);
        Timeout.QuadPart = -10 * 10000000LL;
        NtWaitForSingleObject(ProcessInfo.hProcess, FALSE, &Timeout);
    }

    NtClose(ProcessInfo.hThread);
    NtClose(ProcessInfo.hProcess);
    return (Status == STATUS_WAIT_0);
}

static
DWORD
WINAPI
BasepCrashReporterThread(
    _In_ PVOID Parameter)
{
    BOOLEAN Stopped = FALSE;

    /* A fault here ends this thread only; the crashed thread waits for it */
    _SEH2_TRY
    {
        Stopped = BasepStartCrashReporter(Parameter);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Stopped = FALSE;
    }
    _SEH2_END;
    return Stopped;
}

/*
 * After a stack overflow too little stack is left to start a process: use a
 * new thread. Returns FALSE when that thread did not finish.
 */
static
BOOLEAN
BasepStartCrashReporterOnThread(
    _In_ PBASEP_CRASH_REPORT Report)
{
    PRTL_CRITICAL_SECTION LoaderLock = NtCurrentPeb()->LoaderLock;
    LARGE_INTEGER Timeout;
    HANDLE WaitHandles[2];
    HANDLE Thread;
    DWORD Stopped = FALSE;
    NTSTATUS Status;

    /* A new thread takes the loader lock before it runs */
    if (LoaderLock && LoaderLock->OwningThread == NtCurrentTeb()->ClientId.UniqueThread)
        return TRUE;

    Thread = CreateThread(NULL, 0, BasepCrashReporterThread, Report, 0, NULL);
    if (!Thread)
        return TRUE;

    Timeout.QuadPart = -11 * 60 * 10000000LL;
    WaitHandles[0] = Thread;
    WaitHandles[1] = Report->ReportedEvent;
    Status = NtWaitForMultipleObjects(Report->ReportedEvent ? 2 : 1, WaitHandles, WaitAny, FALSE, &Timeout);
    if (Status == STATUS_WAIT_1)
        Status = NtWaitForSingleObject(Thread, FALSE, NULL);
    if (Status == STATUS_WAIT_0)
        GetExitCodeThread(Thread, &Stopped);
    NtClose(Thread);
    return (Status == STATUS_WAIT_0) && Stopped;
}

/*
 * Let drwtsn32 log the crash of this process and write its LocalDumps
 * report, then, with ShowUi, ask the user in its "has stopped working"
 * dialog. The collection runs out of process; this thread only waits, so
 * the exception record and context stay valid. Result receives the exit
 * code of the reporter, MAXULONG when it did not run. Returns FALSE when
 * this thread faulted while reporting or the reporter could not be
 * stopped; then the caller ends the process.
 */
static
BOOLEAN
BasepReportUnhandledException(
    _In_ PEXCEPTION_POINTERS ExceptionInfo,
    _In_ BOOLEAN ShowUi,
    _In_ BOOLEAN OfferDebug,
    _Out_opt_ PULONG Result)
{
    LONG ThreadId = HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread);
    LONG Owner;
    LARGE_INTEGER Delay;
    BASEP_CRASH_REPORT Report;
    BOOLEAN Stopped = TRUE;

    if (Result)
        *Result = MAXULONG;

    /* A CSR server must not start processes */
    if (BaseRunningInServerProcess)
        return TRUE;

    /* One report at a time; another crashing thread waits for its turn */
    Delay.QuadPart = -50 * 10000LL;
    for (;;)
    {
        Owner = InterlockedCompareExchange(&BasepReportingThread, ThreadId, 0);
        if (Owner == 0)
            break;
        if (Owner == ThreadId)
            return FALSE;
        NtDelayExecution(FALSE, &Delay);
    }

    /* The reporter always logs the crash; it writes a dump when LocalDumps asks for one */
    Report.ExceptionInfo = ExceptionInfo;
    Report.ThreadId = ThreadId;
    Report.ShowUi = ShowUi;
    Report.OfferDebug = OfferDebug;
    Report.ReportedEvent = NULL;
    Report.Result = MAXULONG;
    /* Without the event the time limit would stay on during the dialog: report only, the caller falls back */
    if (ShowUi &&
        !NT_SUCCESS(NtCreateEvent(&Report.ReportedEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE)))
    {
        Report.ReportedEvent = NULL;
        Report.ShowUi = FALSE;
        Report.OfferDebug = FALSE;
    }
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_STACK_OVERFLOW)
        Stopped = BasepStartCrashReporterOnThread(&Report);
    else
        Stopped = BasepStartCrashReporter(&Report);
    if (Report.ReportedEvent)
        NtClose(Report.ReportedEvent);
    if (Result)
        *Result = Report.ShowUi ? Report.Result : MAXULONG;

    /* Keep the claim when a reporter may still run: the caller ends the process */
    if (!Stopped)
        return FALSE;

    /* A debugger may continue this process; its next crash is reported again */
    InterlockedExchange(&BasepReportingThread, 0);
    return TRUE;
}

/*
 * For an exception after which the process ends: the reporter's dialog
 * without Debug, else the hard error box with only OK.
 */
static
VOID
BasepReportFatalException(
    _In_ PEXCEPTION_POINTERS ExceptionInfo)
{
    PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
    ULONG_PTR ErrorParameters[4];
    ULONG Result, ErrorResponse;

    if (BasepIsGpFaultErrorBoxDisabled())
        return;
    if (!BasepReportUnhandledException(ExceptionInfo, TRUE, FALSE, &Result) ||
        Result == CRASH_REPORTER_CLOSE ||
        BaseRunningInServerProcess)
    {
        return;
    }

    /* The reporter did not answer: the box follows its rules */
    if (!BasepCanShowCrashBox())
        return;

    ErrorParameters[0] = (ULONG_PTR)ExceptionRecord->ExceptionCode;
    ErrorParameters[1] = (ULONG_PTR)ExceptionRecord->ExceptionAddress;
    ErrorParameters[2] = (ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR) ?
                         ExceptionRecord->ExceptionInformation[2] : ExceptionRecord->ExceptionInformation[0];
    ErrorParameters[3] = ExceptionRecord->ExceptionInformation[1];
    NtRaiseHardError(STATUS_UNHANDLED_EXCEPTION | HARDERROR_OVERRIDE_ERRORMODE,
                     4, 0, ErrorParameters, OptionOk, &ErrorResponse);
}

static
LONG
BasepFilterFaulted(
    _In_ PEXCEPTION_POINTERS ExceptionInfo)
{
    BasepReportFatalException(ExceptionInfo);
    return EXCEPTION_EXECUTE_HANDLER;
}

UINT
WINAPI
GetErrorMode(VOID)
{
    NTSTATUS Status;
    UINT ErrMode;

    /* Query the current setting */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessDefaultHardErrorMode,
                                       &ErrMode,
                                       sizeof(ErrMode),
                                       NULL);
    if (!NT_SUCCESS(Status))
    {
        /* Fail if we couldn't query */
        BaseSetLastNTError(Status);
        return 0;
    }

    /* Check if NOT failing critical errors was requested */
    if (ErrMode & SEM_FAILCRITICALERRORS)
    {
        /* Mask it out, since the native API works differently */
        ErrMode &= ~SEM_FAILCRITICALERRORS;
    }
    else
    {
        /* OR it if the caller didn't, due to different native semantics */
        ErrMode |= SEM_FAILCRITICALERRORS;
    }

    /* Return the mode */
    return ErrMode;
}

/* The native thread mode keeps SEM_NOOPENFILEERRORBOX in bit 6 */
#define RTL_SEM_NOOPENFILEERRORBOX 0x40

/*
 * @implemented
 */
DWORD
WINAPI
GetThreadErrorMode(VOID)
{
    ULONG NativeMode = RtlGetThreadErrorMode();
    DWORD ErrMode = 0;

    if (NativeMode & RTL_SEM_FAILCRITICALERRORS)
        ErrMode |= SEM_FAILCRITICALERRORS;
    if (NativeMode & RTL_SEM_NOGPFAULTERRORBOX)
        ErrMode |= SEM_NOGPFAULTERRORBOX;
    if (NativeMode & RTL_SEM_NOOPENFILEERRORBOX)
        ErrMode |= SEM_NOOPENFILEERRORBOX;

    return ErrMode;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetThreadErrorMode(
    _In_ DWORD dwNewMode,
    _Out_opt_ LPDWORD lpOldMode)
{
    ULONG NativeMode = 0;
    DWORD OldMode;

    if (dwNewMode & ~(SEM_FAILCRITICALERRORS |
                      SEM_NOGPFAULTERRORBOX |
                      SEM_NOOPENFILEERRORBOX))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (dwNewMode & SEM_FAILCRITICALERRORS)
        NativeMode |= RTL_SEM_FAILCRITICALERRORS;
    if (dwNewMode & SEM_NOGPFAULTERRORBOX)
        NativeMode |= RTL_SEM_NOGPFAULTERRORBOX;
    if (dwNewMode & SEM_NOOPENFILEERRORBOX)
        NativeMode |= RTL_SEM_NOOPENFILEERRORBOX;

    OldMode = GetThreadErrorMode();
    RtlSetThreadErrorMode(NativeMode, NULL);
    if (lpOldMode)
        *lpOldMode = OldMode;

    return TRUE;
}

/*
 * @implemented
 */
LONG
WINAPI
UnhandledExceptionFilter(IN PEXCEPTION_POINTERS ExceptionInfo)
{
    static UNICODE_STRING AeDebugKey =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" REGSTR_PATH_AEDEBUG);

    static BOOLEAN IsSecondChance = FALSE;

    /* Exception data */
    NTSTATUS Status;
    PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
    LPTOP_LEVEL_EXCEPTION_FILTER RealFilter;
    LONG RetValue;

    /* Debugger and hard error parameters */
    HANDLE DebugPort = NULL;
    ULONG_PTR ErrorParameters[4];
    ULONG DebugResponse, ErrorResponse;

    /* Post-Mortem "Auto-Execute" (AE) Debugger registry data */
    HANDLE KeyHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING ValueString;
    ULONG Length;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_PATH * sizeof(WCHAR)];
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = (PVOID)Buffer;
    BOOLEAN AeDebugAuto = FALSE;
    PWCHAR AeDebugPath = NULL;
    WCHAR AeDebugCmdLine[MAX_PATH];

    /* Crash reporter */
    BOOLEAN ShowUi;
    ULONG ReporterResult;

    /* Debugger process data */
    BOOL Success;
    HRESULT hr;
    ULONG PrependLength;
    HANDLE hDebugEvent;
    HANDLE WaitHandles[2];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;

    /*
     * A nested exception (for example a fault in an exception filter) is
     * reported like any other, without calling the filters again, and then
     * ends the process.
     */
    if (ExceptionRecord->ExceptionFlags & EXCEPTION_NESTED_CALL)
    {
        BasepReportFatalException(ExceptionInfo);
        NtTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    if ((ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) &&
        (ExceptionRecord->NumberParameters >= 2))
    {
        switch (ExceptionRecord->ExceptionInformation[0])
        {
            case EXCEPTION_WRITE_FAULT:
            {
                /*
                 * Change the protection on some write attempts,
                 * some InstallShield setups have this bug.
                 */
                RetValue = BasepCheckForReadOnlyResource(
                    (PVOID)ExceptionRecord->ExceptionInformation[1]);
                if (RetValue == EXCEPTION_CONTINUE_EXECUTION)
                    return EXCEPTION_CONTINUE_EXECUTION;
                break;
            }

            case EXCEPTION_EXECUTE_FAULT:
                /* FIXME */
                break;
        }
    }

    /* If the process is being debugged, pass the exception to the debugger */
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessDebugPort,
                                       &DebugPort,
                                       sizeof(DebugPort),
                                       NULL);
    if (NT_SUCCESS(Status) && DebugPort)
    {
        DPRINT("Passing exception to debugger\n");
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* No debugger present, let's continue... */

    RealFilter = RtlDecodePointer(GlobalTopLevelExceptionFilter);
    if (RealFilter)
    {
        /* A fault in the filter is reported, as Windows does, and ends the process */
        _SEH2_TRY
        {
            RetValue = RealFilter(ExceptionInfo);
        }
        _SEH2_EXCEPT(BasepFilterFaulted(_SEH2_GetExceptionInformation()))
        {
            NtTerminateProcess(NtCurrentProcess(), _SEH2_GetExceptionCode());
            RetValue = EXCEPTION_EXECUTE_HANDLER;
        }
        _SEH2_END;

        if (RetValue != EXCEPTION_CONTINUE_SEARCH)
            return RetValue;
    }

    /* ReactOS-specific: DPRINT a stack trace */
    PrintStackTrace(ExceptionInfo);

    /*
     * Now pop up an error if needed. Check both the process-wide (Win32)
     * and per-thread error-mode flags (NT). Like Windows, such a process
     * is not reported either.
     */
    if (BasepIsGpFaultErrorBoxDisabled())
    {
        /* Do not display the pop-up error box, just transfer control to the exception handler */
        return EXCEPTION_EXECUTE_HANDLER;
    }

    /* Save exception code and address */
    ErrorParameters[0] = (ULONG_PTR)ExceptionRecord->ExceptionCode;
    ErrorParameters[1] = (ULONG_PTR)ExceptionRecord->ExceptionAddress;

    if (ExceptionRecord->ExceptionCode == STATUS_IN_PAGE_ERROR)
    {
        /*
         * Get the underlying status code that resulted in the exception,
         * and just forget about the type of operation (read/write).
         */
        ErrorParameters[2] = ExceptionRecord->ExceptionInformation[2];
    }
    else // if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) or others...
    {
        /* Get the type of operation that caused the access violation */
        ErrorParameters[2] = ExceptionRecord->ExceptionInformation[0];
    }

    /* Save faulting address */
    ErrorParameters[3] = ExceptionRecord->ExceptionInformation[1];

    /*
     * Prepare the hard error dialog: default to only OK
     * in case we do not have any debugger at our disposal.
     */
    DebugResponse = OptionOk;
    AeDebugAuto = FALSE;

    /*
     * Retrieve Post-Mortem Debugger settings from the registry, under:
     * HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
     * (REGSTR_PATH_AEDEBUG).
     */

    InitializeObjectAttributes(&ObjectAttributes,
                               &AeDebugKey,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    if (NT_SUCCESS(Status))
    {
        /*
         * Read the 'Auto' REG_SZ value:
         * "0" (or any other value): Prompt the user for starting the debugger.
         * "1": Start the debugger without prompting.
         */
        RtlInitUnicodeString(&ValueString, REGSTR_VAL_AEDEBUG_AUTO);
        Status = NtQueryValueKey(KeyHandle,
                                 &ValueString,
                                 KeyValuePartialInformation,
                                 PartialInfo,
                                 sizeof(Buffer),
                                 &Length);
        if (NT_SUCCESS(Status) && (PartialInfo->Type == REG_SZ))
        {
            AeDebugAuto = (*(PWCHAR)PartialInfo->Data == L'1');
        }
        else
        {
            AeDebugAuto = FALSE;
        }

        /*
         * Read and store the 'Debugger' REG_SZ value. Its usual format is:
         *    C:\dbgtools\ntsd.exe -p %ld -e %ld -g
         * with the first and second parameters being respectively
         * the process ID and a notification event handle.
         */
        RtlInitUnicodeString(&ValueString, REGSTR_VAL_AEDEBUG_DEBUGGER);
        Status = NtQueryValueKey(KeyHandle,
                                 &ValueString,
                                 KeyValuePartialInformation,
                                 PartialInfo,
                                 sizeof(Buffer),
                                 &Length);
        if (NT_SUCCESS(Status) && (PartialInfo->Type == REG_SZ))
        {
            /* We hope the string is NULL-terminated */
            AeDebugPath = (PWCHAR)PartialInfo->Data;

            /* Skip any prepended whitespace */
            while (  *AeDebugPath &&
                   ((*AeDebugPath == L' ') ||
                    (*AeDebugPath == L'\t')) ) // iswspace(*AeDebugPath)
            {
                ++AeDebugPath;
            }

            if (*AeDebugPath)
            {
                /* We have a debugger path, we can prompt the user to debug the program */
                DebugResponse = OptionOkCancel;
            }
            else
            {
                /* We actually do not have anything, reset the pointer */
                AeDebugPath = NULL;
            }
        }
        else
        {
            AeDebugPath = NULL;
        }

        NtClose(KeyHandle);
    }

    /*
     * drwtsn32 logs the crash and writes its report, then asks the user in
     * its "has stopped working" dialog, unless the debugger starts by itself.
     * The classic hard error box (the Windows 2000 way) stays the fallback
     * when the reporter cannot run or cannot show its dialog.
     */
    ShowUi = !(AeDebugPath && AeDebugAuto);
    if (!BasepReportUnhandledException(ExceptionInfo,
                                       ShowUi,
                                       (AeDebugPath != NULL) && !IsSecondChance,
                                       &ReporterResult))
    {
        NtTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    if (ShowUi && (ReporterResult == CRASH_REPORTER_CLOSE))
    {
        /* Like OK in the hard error box */
        Status = STATUS_SUCCESS;
        ErrorResponse = ResponseOk;
    }
    else if (ShowUi && (ReporterResult == CRASH_REPORTER_DEBUG) && AeDebugPath && !IsSecondChance)
    {
        Status = STATUS_SUCCESS;
        ErrorResponse = ResponseCancel;
    }
    else if (ShowUi && !BasepCanShowCrashBox())
    {
        /* The reporter did not answer, and the box is not wanted: end the process */
        Status = STATUS_SUCCESS;
        ErrorResponse = ResponseOk;
    }
    else if (ShowUi)
    {
        /*
         * Either there is no debugger specified, or the debugger should
         * not start automatically: display the hard error no matter what.
         * For a first chance exception, allow continuing or debugging;
         * for a second chance exception, just debug or kill the process.
         */
        Status = NtRaiseHardError(STATUS_UNHANDLED_EXCEPTION | HARDERROR_OVERRIDE_ERRORMODE,
                                  4,
                                  0,
                                  ErrorParameters,
                                  (!IsSecondChance ? DebugResponse : OptionOk),
                                  &ErrorResponse);
    }
    else
    {
        Status = STATUS_SUCCESS;
        ErrorResponse = (AeDebugPath ? ResponseCancel : ResponseOk);
    }

    /*
     * If the user has chosen not to debug the process, or
     * if this is a second chance exception, kill the process.
     */
    if (!NT_SUCCESS(Status) || (ErrorResponse != ResponseCancel) || IsSecondChance)
        goto Quit;

    /* If the exception comes from a CSR Server, kill it (this will lead to ReactOS shutdown) */
    if (BaseRunningInServerProcess)
    {
        IsSecondChance = TRUE;
        goto Quit;
    }

    /*
     * Attach a debugger to this process. The debugger process is given
     * the process ID of the current process to be debugged, as well as
     * a notification event handle. After being spawned, the debugger
     * initializes and attaches to the process by calling DebugActiveProcess.
     * When the debugger is ready, it signals the notification event,
     * so that we can give it control over the process being debugged,
     * by passing it the exception.
     *
     * See https://learn.microsoft.com/en-us/previous-versions/ms809754(v=msdn.10)
     * and http://www.debuginfo.com/articles/ntsdwatson.html
     * and https://sourceware.org/ml/gdb-patches/2012-08/msg00893.html
     * for more details.
     */

    /* Create an inheritable notification debug event for the debugger */
    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               OBJ_INHERIT,
                               NULL,
                               NULL);
    Status = NtCreateEvent(&hDebugEvent,
                           EVENT_ALL_ACCESS,
                           &ObjectAttributes,
                           NotificationEvent,
                           FALSE);
    if (!NT_SUCCESS(Status))
        hDebugEvent = NULL;

    /* Build the debugger command line */

    Success = FALSE;

    /*
     * We will add two longs (process ID and event handle) to the command
     * line. The biggest 32-bit unsigned int (0xFFFFFFFF == 4.294.967.295)
     * takes 10 decimal digits. We then count the terminating NULL.
     */
    Length = (ULONG)wcslen(AeDebugPath) + 2*10 + 1;

    /* Check whether the debugger path may be a relative path */
    if ((*AeDebugPath != L'"') &&
        (RtlDetermineDosPathNameType_U(AeDebugPath) == RtlPathTypeRelative))
    {
        /* Relative path, prepend SystemRoot\System32 */
        PrependLength = (ULONG)wcslen(SharedUserData->NtSystemRoot) + 10 /* == wcslen(L"\\System32\\") */;
        if (PrependLength + Length <= ARRAYSIZE(AeDebugCmdLine))
        {
            hr = StringCchPrintfW(AeDebugCmdLine,
                                  PrependLength + 1,
                                  L"%s\\System32\\",
                                  SharedUserData->NtSystemRoot);
            Success = SUCCEEDED(hr);
        }
    }
    else
    {
        /* Full path */
        PrependLength = 0;
        if (Length <= ARRAYSIZE(AeDebugCmdLine))
            Success = TRUE;
    }

    /* Format the command line */
    if (Success)
    {
        hr = StringCchPrintfW(&AeDebugCmdLine[PrependLength],
                              Length,
                              AeDebugPath,
                              HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess), // GetCurrentProcessId()
                              hDebugEvent);
        Success = SUCCEEDED(hr);
    }

    /* Start the debugger */
    if (Success)
    {
        DPRINT1("\nStarting debugger: '%S'\n", AeDebugCmdLine);

        RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
        RtlZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

        StartupInfo.cb = sizeof(StartupInfo);
        StartupInfo.lpDesktop = L"WinSta0\\Default";

        Success = CreateProcessW(NULL,
                                 AeDebugCmdLine,
                                 NULL, NULL,
                                 TRUE, 0,
                                 NULL, NULL,
                                 &StartupInfo, &ProcessInfo);
    }

    if (Success)
    {
        WaitHandles[0] = hDebugEvent;
        WaitHandles[1] = ProcessInfo.hProcess;

        /* Loop until the debugger gets ready or terminates unexpectedly */
        do
        {
            /* Alertable wait */
            Status = NtWaitForMultipleObjects(ARRAYSIZE(WaitHandles),
                                              WaitHandles,
                                              WaitAny,
                                              TRUE, NULL);
        } while ((Status == STATUS_ALERTED) || (Status == STATUS_USER_APC));

        /*
         * The debugger terminated unexpectedly and we cannot attach to it.
         * Kill the process being debugged.
         */
        if (Status == STATUS_WAIT_1)
        {
            /* Be sure there is no other debugger attached */
            Status = NtQueryInformationProcess(NtCurrentProcess(),
                                               ProcessDebugPort,
                                               &DebugPort,
                                               sizeof(DebugPort),
                                               NULL);
            if (!NT_SUCCESS(Status) || !DebugPort)
            {
                /* No debugger is attached, kill the process at next round */
                IsSecondChance = TRUE;
            }
        }

        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);

        if (hDebugEvent)
            NtClose(hDebugEvent);

        return EXCEPTION_CONTINUE_SEARCH;
    }

    /* We failed starting the debugger, close the event handle and kill the process */

    if (hDebugEvent)
        NtClose(hDebugEvent);

    IsSecondChance = TRUE;


Quit:
    /* If this is a second chance exception, kill the process */
    if (IsSecondChance)
        NtTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);

    /* Otherwise allow handling exceptions in first chance */

    /*
     * Returning EXCEPTION_EXECUTE_HANDLER means that the code in
     * the __except block will be executed. Normally this will end up in a
     * Terminate process.
     */

    return EXCEPTION_EXECUTE_HANDLER;
}

/* kernel32 is built for an older _WIN32_WINNT */
#ifndef FAIL_FAST_GENERATE_EXCEPTION_ADDRESS
#define FAIL_FAST_GENERATE_EXCEPTION_ADDRESS 0x1
#endif

static NTSTATUS BasepFailFastCode;

/* A debugger that continues a fail fast exception resumes the thread here */
static
DECLSPEC_NORETURN
VOID
NTAPI
BasepFailFastExit(VOID)
{
    NtTerminateProcess(NtCurrentProcess(), BasepFailFastCode);
    for (;;);
}

/* Show the exception to the debugger. A debugger that continues it resumes
   the thread in BasepFailFastExit on this stack, also when the caller
   supplied the context */
static
DECLSPEC_NOINLINE
VOID
BasepFailFastRaise(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_opt_ PCONTEXT ContextRecord)
{
    CONTEXT Context;
#if defined(_M_IX86)
    /* No capture here: the x86 one needs a frame pointer, which /Oy omits */
    if (ContextRecord)
    {
        Context = *ContextRecord;
    }
    else
    {
        RtlZeroMemory(&Context, sizeof(Context));
#if defined(__GNUC__) || defined(__clang__)
        /* Lets the debugger walk the frames of the caller */
        Context.Ebp = (ULONG_PTR)__builtin_frame_address(0);
#endif
    }
    Context.ContextFlags |= CONTEXT_CONTROL | CONTEXT_SEGMENTS;
    Context.Eip = (ULONG_PTR)BasepFailFastExit;
    /* As if the caller of this function had called it */
    Context.Esp = (ULONG_PTR)_AddressOfReturnAddress();
    Context.EFlags = __readeflags();
    Context.SegCs = KGDT_R3_CODE;
    Context.SegSs = KGDT_R3_DATA;
    Context.SegDs = KGDT_R3_DATA;
    Context.SegEs = KGDT_R3_DATA;
    Context.SegFs = KGDT_R3_TEB;
    Context.SegGs = 0;
#elif defined(_M_AMD64)
    CONTEXT ResumeContext;

    RtlCaptureContext(&ResumeContext);
    if (ContextRecord)
    {
        Context = *ContextRecord;
        Context.ContextFlags |= CONTEXT_CONTROL;
    }
    else
    {
        Context = ResumeContext;
    }
    Context.ContextFlags |= CONTEXT_SEGMENTS;
    Context.Rip = (ULONG_PTR)BasepFailFastExit;
    Context.Rsp = (ResumeContext.Rsp & ~(ULONG64)15) - 8;
    Context.EFlags = ResumeContext.EFlags;
    Context.SegCs = ResumeContext.SegCs;
    Context.SegSs = ResumeContext.SegSs;
    Context.SegDs = ResumeContext.SegDs;
    Context.SegEs = ResumeContext.SegEs;
    Context.SegFs = ResumeContext.SegFs;
    Context.SegGs = ResumeContext.SegGs;
#else
    /* The resume point is not redirected here: do not report it */
    UNREFERENCED_PARAMETER(ExceptionRecord);
    UNREFERENCED_PARAMETER(ContextRecord);
    return;
#endif
    NtRaiseException(ExceptionRecord, &Context, FALSE);
}

/*
 * @implemented
 */
VOID
WINAPI
RaiseFailFastException(
    _In_opt_ PEXCEPTION_RECORD pExceptionRecord,
    _In_opt_ PCONTEXT pContextRecord,
    _In_ DWORD dwFlags)
{
    EXCEPTION_RECORD ExceptionRecord;
    EXCEPTION_POINTERS ExceptionInfo;
    CONTEXT Context;

    if (pExceptionRecord)
    {
        ExceptionRecord = *pExceptionRecord;
        if (ExceptionRecord.NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS)
            ExceptionRecord.NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
        if (dwFlags & FAIL_FAST_GENERATE_EXCEPTION_ADDRESS)
            ExceptionRecord.ExceptionAddress = _ReturnAddress();
    }
    else
    {
        RtlZeroMemory(&ExceptionRecord, sizeof(ExceptionRecord));
        ExceptionRecord.ExceptionCode = STATUS_FAIL_FAST_EXCEPTION;
        ExceptionRecord.ExceptionAddress = _ReturnAddress();
    }
    ExceptionRecord.ExceptionFlags |= EXCEPTION_NONCONTINUABLE;

    DPRINT1("Fail fast exception 0x%lx at %p\n",
            ExceptionRecord.ExceptionCode, ExceptionRecord.ExceptionAddress);

    /* Bypass every handler and only show a debugger the second chance. Without
       one, the exception port could continue the thread instead of ending it */
    BasepFailFastCode = ExceptionRecord.ExceptionCode;
    if (NtCurrentPeb()->BeingDebugged)
    {
        BasepFailFastRaise(&ExceptionRecord, pContextRecord);
    }
    else if (!BasepIsGpFaultErrorBoxDisabled())
    {
        /* Reported like an unhandled exception; no filter runs, as on Windows.
           The record comes from the caller, and the reporter copies its parameters */
        if (!pContextRecord)
        {
            RtlZeroMemory(&Context, sizeof(Context));
#if defined(_M_IX86) && !defined(__GNUC__)
            /* The x86 capture reads the frame pointer, which /Oy omits; the caller's EBP stays unknown */
            Context.ContextFlags = CONTEXT_CONTROL;
            Context.Eip = (ULONG_PTR)_ReturnAddress();
            Context.Esp = (ULONG_PTR)_AddressOfReturnAddress() + sizeof(PVOID);
            Context.EFlags = __readeflags();
            Context.SegCs = KGDT_R3_CODE | RPL_MASK;
            Context.SegSs = KGDT_R3_DATA | RPL_MASK;
#else
            RtlCaptureContext(&Context);
#endif
            pContextRecord = &Context;
        }
        ExceptionInfo.ExceptionRecord = &ExceptionRecord;
        ExceptionInfo.ContextRecord = pContextRecord;
        BasepReportUnhandledException(&ExceptionInfo, FALSE, FALSE, NULL);
    }
    NtTerminateProcess(NtCurrentProcess(), ExceptionRecord.ExceptionCode);
}

/*
 * @implemented
 */
VOID
WINAPI
RaiseException(
    _In_ DWORD dwExceptionCode,
    _In_ DWORD dwExceptionFlags,
    _In_ DWORD nNumberOfArguments,
    _In_opt_ const ULONG_PTR *lpArguments)
{
    EXCEPTION_RECORD ExceptionRecord;

    /* Setup the exception record */
    RtlZeroMemory(&ExceptionRecord, sizeof(ExceptionRecord));
    ExceptionRecord.ExceptionCode = dwExceptionCode;
    ExceptionRecord.ExceptionRecord = NULL;
    ExceptionRecord.ExceptionAddress = (PVOID)RaiseException;
    ExceptionRecord.ExceptionFlags = dwExceptionFlags & EXCEPTION_NONCONTINUABLE;

    /* Check if we have arguments */
    if (!lpArguments)
    {
        /* We don't */
        ExceptionRecord.NumberParameters = 0;
    }
    else
    {
        /* We do, normalize the count */
        if (nNumberOfArguments > EXCEPTION_MAXIMUM_PARAMETERS)
            nNumberOfArguments = EXCEPTION_MAXIMUM_PARAMETERS;

        /* Set the count of parameters and copy them */
        ExceptionRecord.NumberParameters = nNumberOfArguments;
        RtlCopyMemory(ExceptionRecord.ExceptionInformation,
                      lpArguments,
                      nNumberOfArguments * sizeof(ULONG_PTR));
    }

    /* Better handling of Delphi Exceptions... a ReactOS Hack */
    if (dwExceptionCode == 0xeedface || dwExceptionCode == 0xeedfade)
    {
        DPRINT1("Delphi Exception at address: %p\n", ExceptionRecord.ExceptionInformation[0]);
        DPRINT1("Exception-Object: %p\n", ExceptionRecord.ExceptionInformation[1]);
        DPRINT1("Exception text: %lx\n", ExceptionRecord.ExceptionInformation[2]);
    }

    /* Raise the exception */
    RtlRaiseException(&ExceptionRecord);
}

/*
 * @implemented
 */
UINT
WINAPI
SetErrorMode(IN UINT uMode)
{
    UINT PrevErrMode, NewMode;

    /* Get the previous mode */
    PrevErrMode = GetErrorMode();
    NewMode = uMode;

    /* Check if failing critical errors was requested */
    if (NewMode & SEM_FAILCRITICALERRORS)
    {
        /* Mask it out, since the native API works differently */
        NewMode &= ~SEM_FAILCRITICALERRORS;
    }
    else
    {
        /* OR it if the caller didn't, due to different native semantics */
        NewMode |= SEM_FAILCRITICALERRORS;
    }

    /* Always keep no alignment faults if they were set */
    NewMode |= (PrevErrMode & SEM_NOALIGNMENTFAULTEXCEPT);

    /* Set the new mode */
    NtSetInformationProcess(NtCurrentProcess(),
                            ProcessDefaultHardErrorMode,
                            (PVOID)&NewMode,
                            sizeof(NewMode));

    /* Return the previous mode */
    return PrevErrMode;
}

/*
 * @implemented
 */
LPTOP_LEVEL_EXCEPTION_FILTER
WINAPI
DECLSPEC_HOTPATCH
SetUnhandledExceptionFilter(IN LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
    PVOID EncodedPointer, EncodedOldPointer;

    EncodedPointer = RtlEncodePointer(lpTopLevelExceptionFilter);
    EncodedOldPointer = InterlockedExchangePointer((PVOID*)&GlobalTopLevelExceptionFilter,
                                            EncodedPointer);
    return RtlDecodePointer(EncodedOldPointer);
}

/*
 * @implemented
 */
BOOL
WINAPI
IsBadReadPtr(IN LPCVOID lp,
             IN UINT_PTR ucb)
{
    ULONG PageSize;
    BOOLEAN Result = FALSE;
    volatile CHAR *Current;
    PCHAR Last;

    /* Quick cases */
    if (!ucb) return FALSE;
    if (!lp) return TRUE;

    /* Get the page size */
    PageSize = BaseStaticServerData->SysInfo.PageSize;

    /* Calculate start and end */
    Current = (volatile CHAR*)lp;
    Last = (PCHAR)((ULONG_PTR)lp + ucb - 1);

    /* Another quick failure case */
    if (Last < Current) return TRUE;

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Do an initial probe */
        *Current;

        /* Align the addresses */
        Current = (volatile CHAR *)ALIGN_DOWN_POINTER_BY(Current, PageSize);
        Last = (PCHAR)ALIGN_DOWN_POINTER_BY(Last, PageSize);

        /* Probe the entire range */
        while (Current != Last)
        {
            Current += PageSize;
            *Current;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* We hit an exception, so return true */
        Result = TRUE;
    }
    _SEH2_END

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
BOOL
NTAPI
IsBadHugeReadPtr(LPCVOID lp,
                 UINT_PTR ucb)
{
    /* Implementation is the same on 32-bit */
    return IsBadReadPtr(lp, ucb);
}

/*
 * @implemented
 */
BOOL
NTAPI
IsBadCodePtr(FARPROC lpfn)
{
    /* Executing has the same privileges as reading */
    return IsBadReadPtr((LPVOID)lpfn, 1);
}

/*
 * @implemented
 */
BOOL
NTAPI
IsBadWritePtr(IN LPVOID lp,
              IN UINT_PTR ucb)
{
    ULONG PageSize;
    BOOLEAN Result = FALSE;
    volatile CHAR *Current;
    PCHAR Last;

    /* Quick cases */
    if (!ucb) return FALSE;
    if (!lp) return TRUE;

    /* Get the page size */
    PageSize = BaseStaticServerData->SysInfo.PageSize;

    /* Calculate start and end */
    Current = (volatile CHAR*)lp;
    Last = (PCHAR)((ULONG_PTR)lp + ucb - 1);

    /* Another quick failure case */
    if (Last < Current) return TRUE;

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Do an initial probe */
        *Current = *Current;

        /* Align the addresses */
        Current = (volatile CHAR *)ALIGN_DOWN_POINTER_BY(Current, PageSize);
        Last = (PCHAR)ALIGN_DOWN_POINTER_BY(Last, PageSize);

        /* Probe the entire range */
        while (Current != Last)
        {
            Current += PageSize;
            *Current = *Current;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* We hit an exception, so return true */
        Result = TRUE;
    }
    _SEH2_END

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
BOOL
NTAPI
IsBadHugeWritePtr(IN LPVOID lp,
                  IN UINT_PTR ucb)
{
    /* Implementation is the same on 32-bit */
    return IsBadWritePtr(lp, ucb);
}

/*
 * @implemented
 */
BOOL
NTAPI
IsBadStringPtrW(IN LPCWSTR lpsz,
                IN UINT_PTR ucchMax)
{
    BOOLEAN Result = FALSE;
    volatile WCHAR *Current;
    PWCHAR Last;
    WCHAR Char;

    /* Quick cases */
    if (!ucchMax) return FALSE;
    if (!lpsz) return TRUE;

    /* Calculate start and end */
    Current = (volatile WCHAR*)lpsz;
    Last = (PWCHAR)((ULONG_PTR)lpsz + (ucchMax * 2) - 2);

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Probe the entire range */
        Char = *Current++;
        while ((Char) && (Current != Last)) Char = *Current++;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* We hit an exception, so return true */
        Result = TRUE;
    }
    _SEH2_END

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
BOOL
NTAPI
IsBadStringPtrA(IN LPCSTR lpsz,
                IN UINT_PTR ucchMax)
{
    BOOLEAN Result = FALSE;
    volatile CHAR *Current;
    PCHAR Last;
    CHAR Char;

    /* Quick cases */
    if (!ucchMax) return FALSE;
    if (!lpsz) return TRUE;

    /* Calculate start and end */
    Current = (volatile CHAR*)lpsz;
    Last = (PCHAR)((ULONG_PTR)lpsz + ucchMax - 1);

    /* Enter SEH */
    _SEH2_TRY
    {
        /* Probe the entire range */
        Char = *Current++;
        while ((Char) && (Current != Last)) Char = *Current++;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        /* We hit an exception, so return true */
        Result = TRUE;
    }
    _SEH2_END

    /* Return exception status */
    return Result;
}

/*
 * @implemented
 */
VOID
WINAPI
SetLastError(IN DWORD dwErrCode)
{
    /* Break if a debugger requested checking for this error code */
    if ((g_dwLastErrorToBreakOn) && (g_dwLastErrorToBreakOn == dwErrCode)) DbgBreakPoint();

    /* Set last error if it's a new error */
    if (NtCurrentTeb()->LastErrorValue != dwErrCode) NtCurrentTeb()->LastErrorValue = dwErrCode;
}

/*
 * @implemented
 */
DWORD
WINAPI
GetLastError(VOID)
{
    /* Return the current value */
    return NtCurrentTeb()->LastErrorValue;
}

/* EOF */
