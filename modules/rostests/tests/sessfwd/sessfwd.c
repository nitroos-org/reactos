/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Sessions design 3.5, option A: a process created into another
 *              session is registered with the csrss of that session. The
 *              creator's basesrv asks SMSS (SmForwardProcessRegistration),
 *              which serves only a csrss it started and forwards the request
 *              over the target csrss's Sb port (SbCreateRemoteProcess), which
 *              serves only SMSS.
 *              Run it as LocalSystem in session 0, as a service:
 *                sc create sfwd binPath= "C:\ReactOS\bin\sessfwd.exe svc C:\harness\out\sessfwd.txt"
 *              with NitroSessions 5 and a session-1 test command that keeps
 *              running (sesswin2.exe hold). One line per check, PASS or FAIL,
 *              to the file and to the debugger.
 *              "child <session>" is the process the test creates: it exits
 *              with 0x5E55 when it runs in that session.
 *              Without a session 1 (NitroSessions absent or 0) the cases that
 *              need it are reported as SKIP, not FAIL.
 *              "concurrent-forwards": STRESS_THREADS threads create children
 *              into session 1 at once, console and detached, which exit at
 *              once: forwards through SMSS overlap with each other and with
 *              the exits of forwarded processes (SmSessionComplete), more of
 *              them than SMSS has API threads. Every create must return and
 *              every child must run, within a bound; then one more forward
 *              must still work.
 *              "svc <file> soak <seconds> [session [detached]]": only that,
 *              repeated for <seconds>, one line a minute with the counts,
 *              the slowest create and the private bytes and handles of SMSS
 *              and of the csrss of that session. Session 0 is the control:
 *              the same creates in the service's own session, no forward.
 *              "detached": no console children (consrv leaks a desktop
 *              handle per console, which exhausts session 1 after about 650).
 *              The datagram path of \SmApiPort (smss smloop.c): the test connects
 *              as a LocalSystem service (no subsystem, so it is not a csrss) and
 *              sends datagrams: another API, SmSessionComplete, a short one, a
 *              flood of DATAGRAM_FLOOD of them with every session id below it.
 *              SMSS must keep answering (a refused forward is the probe, it
 *              needs a free API thread), and the record of a child that runs in
 *              session 1 meanwhile must survive: its csrss's SmSessionComplete
 *              at exit then finds it (the SMSS log, which the gate reads, says
 *              SUCCESS, not NOT_FOUND; NitroSessionsTestForward bit 2, value 4).
 *              "svc <file> stuck": a stuck target csrss (NitroSessionsTestForwardStall
 *              makes every forward wait in SMSS instead of the target answering):
 *              concurrent creates into session 1 must neither wedge SMSS (probe
 *              answers while they are stuck) nor hang (every create returns).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winsvc.h>
#include <tlhelp32.h>
#define NTOS_MODE_USER
#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/lpcfuncs.h>
#include <ndk/mmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/setypes.h>
#include <csr/csr.h>
#include <win/basemsg.h>
#include <sm/smmsg.h>

/* The ntdll export (the NDK declares the Windows 7 form for this NTDDI) */
typedef NTSTATUS (NTAPI *PRTL_CREATE_USER_THREAD)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T,
                                                  PTHREAD_START_ROUTINE, PVOID, PHANDLE, PCLIENT_ID);

#define CHILD_OK 0x5E55
#define TARGET_SESSION 1

#define DATAGRAM_FLOOD 10000
#define DATAGRAM_HOLD_MS 20000
#define PROBE_BOUND_MS 15000
#define STUCK_THREADS 3
#define STUCK_BOUND_MS 120000

#define STRESS_THREADS 4
#define STRESS_ROUNDS 15
#define STRESS_CHILD_WAIT 60000
#define STRESS_BOUND 300000

static BOOL SmssAnswers(const char *Name, DWORD BoundMs);

static FILE *Out;
static BOOL StressDetachedOnly;
static ULONG Failures;
static ULONG Skips;

static
VOID
Log(const char *Format, ...)
{
    char Buffer[512];
    va_list Args;

    va_start(Args, Format);
    _vsnprintf(Buffer, sizeof(Buffer) - 1, Format, Args);
    va_end(Args);
    Buffer[sizeof(Buffer) - 1] = 0;
    OutputDebugStringA(Buffer);
    if (Out)
    {
        fputs(Buffer, Out);
        fflush(Out);
    }
}

static
VOID
Check(const char *Name, NTSTATUS Status, NTSTATUS Expected)
{
    BOOL Pass = (Status == Expected);
    Log("SESSFWD %s status=%08lx expect=%08lx %s\n", Name, Status, Expected, Pass ? "PASS" : "FAIL");
    if (!Pass) Failures++;
}

static
VOID
Skip(const char *Name, const char *Why)
{
    Log("SESSFWD %s SKIP (%s)\n", Name, Why);
    Skips++;
}

static
ULONG
ProcessSession(HANDLE Process)
{
    ULONG Session = (ULONG)-1;
    NtQueryInformationProcess(Process, ProcessSessionInformation, &Session, sizeof(Session), NULL);
    return Session;
}

/* The id of the first process with this image name in the given session, or 0 */
static
DWORD
FindPidInSession(const WCHAR *Image, ULONG Session)
{
    HANDLE Snapshot;
    PROCESSENTRY32W Entry;
    DWORD Pid = 0, ProcSession;

    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) return 0;
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snapshot, &Entry))
    {
        do
        {
            if (!_wcsicmp(Entry.szExeFile, Image) &&
                ProcessIdToSessionId(Entry.th32ProcessID, &ProcSession) &&
                (ProcSession == Session))
            {
                Pid = Entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
    return Pid;
}

/* A primary token of this process with the given session (needs SeTcbPrivilege) */
static
HANDLE
TokenForSession(ULONG Session)
{
    HANDLE Token, Dup = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token)) return NULL;
    if (!DuplicateTokenEx(Token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Dup)) Dup = NULL;
    CloseHandle(Token);
    if (Dup && !SetTokenInformation(Dup, TokenSessionId, &Session, sizeof(Session)))
    {
        Log("SESSFWD token for session %lu failed %lu\n", Session, GetLastError());
        CloseHandle(Dup);
        Dup = NULL;
    }
    return Dup;
}

/*
 * A process of the target session, created by us and registered nowhere: the
 * process object from our own image with the session attribute, and one
 * suspended thread that never runs.
 */
static
NTSTATUS
CreateBareProcess(PHANDLE Process, PHANDLE Thread, PCLIENT_ID ClientId)
{
    WCHAR Self[MAX_PATH];
    HANDLE File, Section = NULL;
    SECTION_IMAGE_INFORMATION ImageInfo;
    ULONG Session = TARGET_SESSION;
    struct
    {
        SIZE_T TotalLength;
        ROS_PS_ATTRIBUTE Attributes[1];
    } List;
    PRTL_CREATE_USER_THREAD CreateUserThread;
    NTSTATUS Status;

    *Process = *Thread = NULL;
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    File = CreateFileW(Self, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, File);
    CloseHandle(File);
    if (!NT_SUCCESS(Status)) return Status;
    Status = NtQuerySection(Section, SectionImageInformation, &ImageInfo, sizeof(ImageInfo), NULL);
    if (!NT_SUCCESS(Status)) goto Quit;

    RtlZeroMemory(&List, sizeof(List));
    List.TotalLength = sizeof(List);
    List.Attributes[0].Attribute = ROS_PS_ATTRIBUTE_SESSION_ID;
    List.Attributes[0].Size = sizeof(Session);
    List.Attributes[0].ValuePtr = &Session;
    Status = NtCreateProcessWithAttributes(Process, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), 0,
                                           Section, NULL, NULL, FALSE, (PROS_PS_ATTRIBUTE_LIST)&List);
    if (!NT_SUCCESS(Status)) goto Quit;

    CreateUserThread = (PRTL_CREATE_USER_THREAD)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                               "RtlCreateUserThread");
    if (!CreateUserThread)
    {
        Status = STATUS_PROCEDURE_NOT_FOUND;
        NtTerminateProcess(*Process, Status);
        NtClose(*Process);
        *Process = NULL;
        goto Quit;
    }
    Status = CreateUserThread(*Process, NULL, TRUE, 0, 0, 0,
                                 (PTHREAD_START_ROUTINE)ImageInfo.TransferAddress,
                                 NULL, Thread, ClientId);
    if (!NT_SUCCESS(Status))
    {
        NtTerminateProcess(*Process, Status);
        NtClose(*Process);
        *Process = NULL;
    }

Quit:
    NtClose(Section);
    return Status;
}

/* BasepCreateProcess to our own csrss, as kernel32 sends it, with the given handles and ids */
static
NTSTATUS
CallBaseCreateProcess(HANDLE Process, HANDLE Thread, PCLIENT_ID ClientId)
{
    BASE_API_MESSAGE ApiMessage;
    PBASE_CREATE_PROCESS Request = &ApiMessage.Data.CreateProcessRequest;

    RtlZeroMemory(&ApiMessage, sizeof(ApiMessage));
    /* Bit 1: a GUI application (no console) */
    Request->ProcessHandle = (HANDLE)((ULONG_PTR)Process | 2);
    Request->ThreadHandle = Thread;
    Request->ClientId = *ClientId;
#ifdef _WIN64
    Request->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
#else
    Request->ProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
#endif
    CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage, NULL,
                        CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateProcess),
                        sizeof(*Request));
    return ApiMessage.Status;
}

/* SbCreateRemoteProcess sent straight to the target csrss's Sb port */
static
NTSTATUS
SendSbCreateRemoteProcess(PCLIENT_ID ClientId)
{
    UNICODE_STRING Name;
    SECURITY_QUALITY_OF_SERVICE Qos;
    HANDLE Port;
    SB_API_MSG Message;
    WCHAR PortName[64];
    NTSTATUS Status;

    _snwprintf(PortName, RTL_NUMBER_OF(PortName), L"\\Sessions\\%lu\\Windows\\SbApiPort", (ULONG)TARGET_SESSION);
    RtlInitUnicodeString(&Name, PortName);
    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityIdentification;
    Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Qos.EffectiveOnly = TRUE;
    Status = NtConnectPort(&Port, &Name, &Qos, NULL, NULL, NULL, NULL, NULL);
    Log("SESSFWD sb-connect status=%08lx\n", Status);
    if (!NT_SUCCESS(Status)) return Status;

    RtlZeroMemory(&Message, sizeof(Message));
    Message.ApiNumber = SbpCreateRemoteProcess;
    Message.u.CreateRemoteProcess.SessionId = 0x5E55;
    Message.u.CreateRemoteProcess.MuSessionId = TARGET_SESSION;
    Message.u.CreateRemoteProcess.ClientId = *ClientId;
    Message.u.CreateRemoteProcess.Flags = 0;
    Message.h.u1.s1.DataLength = sizeof(SB_CREATE_REMOTE_PROCESS_MSG) + 8;
    Message.h.u1.s1.TotalLength = sizeof(Message);
    Status = NtRequestWaitReplyPort(Port, &Message.h, &Message.h);
    if (NT_SUCCESS(Status)) Status = Message.ReturnValue;
    NtClose(Port);
    return Status;
}

/* The first process with this image name in the given session, and one of its threads */
static
BOOL
FindProcessInSession(const WCHAR *Image, ULONG Session, PHANDLE Process, PHANDLE Thread, PCLIENT_ID ClientId)
{
    HANDLE Snapshot;
    PROCESSENTRY32W Entry;
    THREADENTRY32 ThreadEntry;
    DWORD Pid = 0, ProcSession;

    *Process = *Thread = NULL;
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) return FALSE;
    Entry.dwSize = sizeof(Entry);
    if (Process32FirstW(Snapshot, &Entry))
    {
        do
        {
            if (!_wcsicmp(Entry.szExeFile, Image) &&
                ProcessIdToSessionId(Entry.th32ProcessID, &ProcSession) &&
                (ProcSession == Session))
            {
                Pid = Entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(Snapshot, &Entry));
    }
    ThreadEntry.dwSize = sizeof(ThreadEntry);
    if (Pid && Thread32First(Snapshot, &ThreadEntry))
    {
        do
        {
            if (ThreadEntry.th32OwnerProcessID == Pid)
            {
                *Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
                *Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadEntry.th32ThreadID);
                ClientId->UniqueProcess = UlongToHandle(Pid);
                ClientId->UniqueThread = UlongToHandle(ThreadEntry.th32ThreadID);
                break;
            }
        } while (Thread32Next(Snapshot, &ThreadEntry));
    }
    CloseHandle(Snapshot);
    if (*Process && *Thread) return TRUE;
    if (*Process) CloseHandle(*Process);
    if (*Thread) CloseHandle(*Thread);
    return FALSE;
}

/* "sessfwd.exe child <session>" created as the token (or as us); its exit code */
static
VOID
RunChild(const char *Name, HANDLE Token, ULONG Session, DWORD CreationFlags)
{
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 32];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 0, Wait;
    BOOL Created;

    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" child %lu", Self, Session);
    if (Token)
        Created = CreateProcessAsUserW(Token, NULL, CommandLine, NULL, NULL, FALSE, CreationFlags,
                                       NULL, NULL, &StartupInfo, &ProcessInfo);
    else
        Created = CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, CreationFlags,
                                 NULL, NULL, &StartupInfo, &ProcessInfo);
    if (!Created)
    {
        Log("SESSFWD %s create failed error=%lu FAIL\n", Name, GetLastError());
        Failures++;
        return;
    }
    Wait = WaitForSingleObject(ProcessInfo.hProcess, 60000);
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    Log("SESSFWD %s process-session=%lu wait=%lu exit=%08lx expect=%08lx %s\n", Name,
        ProcessSession(ProcessInfo.hProcess), Wait, ExitCode, CHILD_OK,
        (Wait == WAIT_OBJECT_0 && ExitCode == CHILD_OK) ? "PASS" : "FAIL");
    if (!(Wait == WAIT_OBJECT_0 && ExitCode == CHILD_OK)) Failures++;
    if (Wait != WAIT_OBJECT_0) TerminateProcess(ProcessInfo.hProcess, 1);
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
}

/* "sessfwd.exe child <session>" created as the token: TRUE when it ran there; the create time in ms */
static
BOOL
StressChild(HANDLE Token, ULONG Session, DWORD CreationFlags, PDWORD CreateMs, PDWORD Error)
{
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 32];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 0, Wait, Start;
    BOOL Created;

    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" child %lu", Self, Session);
    Start = GetTickCount();
    Created = CreateProcessAsUserW(Token, NULL, CommandLine, NULL, NULL, FALSE, CreationFlags,
                                   NULL, NULL, &StartupInfo, &ProcessInfo);
    *CreateMs = GetTickCount() - Start;
    *Error = Created ? 0 : GetLastError();
    if (!Created) return FALSE;
    Wait = WaitForSingleObject(ProcessInfo.hProcess, STRESS_CHILD_WAIT);
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    if (Wait != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
        *Error = 0x80000000 | Wait;
    }
    else if (ExitCode != CHILD_OK)
    {
        *Error = ExitCode;
    }
    CloseHandle(ProcessInfo.hProcess);
    CloseHandle(ProcessInfo.hThread);
    return (Wait == WAIT_OBJECT_0) && (ExitCode == CHILD_OK);
}

typedef struct _STRESS
{
    HANDLE Token;
    ULONG Session;
    ULONG Index;
    ULONG Rounds;
    LONG Ok;
    LONG Bad;
    DWORD MaxCreateMs;
    DWORD FirstError;
} STRESS, *PSTRESS;

static
DWORD
WINAPI
StressThread(PVOID Parameter)
{
    PSTRESS Stress = Parameter;
    DWORD CreateMs, Error;
    ULONG i;

    for (i = 0; i < Stress->Rounds; i++)
    {
        /* Odd threads: console children (a console of their own in session 1, consrv on exit too) */
        if (StressChild(Stress->Token, Stress->Session, ((Stress->Index & 1) && !StressDetachedOnly) ? 0 : DETACHED_PROCESS, &CreateMs, &Error))
        {
            Stress->Ok++;
        }
        else
        {
            if (!Stress->Bad) Stress->FirstError = Error;
            Stress->Bad++;
        }
        if (CreateMs > Stress->MaxCreateMs) Stress->MaxCreateMs = CreateMs;
    }
    return 0;
}

/*
 * STRESS_THREADS threads, Rounds children each, all at once. TRUE when every create returned and every
 * child ran in session 1 within the bound. On a hang the threads are left behind (stuck in the create).
 */
static
BOOL
StressRun(HANDLE Token, ULONG Session, ULONG Rounds, PLONG Ok, PLONG Bad, PDWORD MaxCreateMs, PDWORD FirstError, PDWORD Wait)
{
    STRESS Stress[STRESS_THREADS];
    HANDLE Threads[STRESS_THREADS];
    ULONG i, Started = 0;

    *Ok = *Bad = 0;
    *MaxCreateMs = *FirstError = 0;
    RtlZeroMemory(Stress, sizeof(Stress));
    for (i = 0; i < STRESS_THREADS; i++)
    {
        Stress[i].Token = Token;
        Stress[i].Session = Session;
        Stress[i].Index = i;
        Stress[i].Rounds = Rounds;
        Threads[i] = CreateThread(NULL, 0, StressThread, &Stress[i], 0, NULL);
        if (!Threads[i]) break;
        Started++;
    }
    *Wait = Started ? WaitForMultipleObjects(Started, Threads, TRUE, STRESS_BOUND) : WAIT_FAILED;
    for (i = 0; i < Started; i++)
    {
        *Ok += Stress[i].Ok;
        *Bad += Stress[i].Bad;
        if (Stress[i].MaxCreateMs > *MaxCreateMs) *MaxCreateMs = Stress[i].MaxCreateMs;
        if (Stress[i].Bad && !*FirstError) *FirstError = Stress[i].FirstError;
        CloseHandle(Threads[i]);
    }
    return (Started == STRESS_THREADS) && (*Wait == WAIT_OBJECT_0) && !*Bad &&
           (*Ok == (LONG)(STRESS_THREADS * Rounds));
}

/* Private bytes and handle count of the process with this pid */
static
VOID
ProcessUsage(DWORD Pid, PSIZE_T Private, PULONG Handles)
{
    HANDLE Process;
    VM_COUNTERS_EX Counters;

    *Private = 0;
    *Handles = 0;
    Process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, Pid);
    if (!Process) return;
    if (NT_SUCCESS(NtQueryInformationProcess(Process, ProcessVmCounters, &Counters, sizeof(Counters), NULL)))
        *Private = Counters.PrivateUsage;
    NtQueryInformationProcess(Process, ProcessHandleCount, Handles, sizeof(*Handles), NULL);
    CloseHandle(Process);
}

/* "svc <file> soak <seconds> [session]": the stress again and again; one line a minute. Session 0 (our own)
   is the control without any forward */
static
VOID
Soak(ULONG Seconds, ULONG Session)
{
    BOOLEAN Old;
    HANDLE Token;
    DWORD Start, LastLine, MaxCreateMs, FirstError, Wait, SmssPid, CsrPid, Max = 0;
    LONG Ok, Bad;
    ULONG Batches = 0, TotalOk = 0, TotalBad = 0, SmssHandles, CsrHandles;
    SIZE_T SmssPrivate, CsrPrivate;
    BOOL Pass;

    RtlAdjustPrivilege(SE_TCB_PRIVILEGE, TRUE, FALSE, &Old);
    Log("SESSFWD soak start seconds=%lu threads=%u session=%lu%s\n", Seconds, STRESS_THREADS, Session,
        StressDetachedOnly ? " detached only" : "");
    SmssPid = FindPidInSession(L"smss.exe", 0);
    CsrPid = FindPidInSession(L"csrss.exe", Session);
    Token = TokenForSession(Session);
    if (!Token || !CsrPid)
    {
        Log("SESSFWD soak no session 1 (token %p, csrss %lu) FAIL\n", Token, CsrPid);
        Failures++;
        return;
    }
    Start = LastLine = GetTickCount();
    /* SMSS logs its session-record count for a refused forward (NitroSessionsTestForward bit 1, value 2) */
    SmssAnswers("soak-start", PROBE_BOUND_MS);
    ProcessUsage(SmssPid, &SmssPrivate, &SmssHandles);
    ProcessUsage(CsrPid, &CsrPrivate, &CsrHandles);
    Log("SESSFWD soak t=0 smss-private=%Iu smss-handles=%lu csrss-private=%Iu csrss-handles=%lu\n",
        SmssPrivate, SmssHandles, CsrPrivate, CsrHandles);
    for (;;)
    {
        Pass = StressRun(Token, Session, 5, &Ok, &Bad, &MaxCreateMs, &FirstError, &Wait);
        Batches++;
        TotalOk += Ok;
        TotalBad += Bad;
        if (MaxCreateMs > Max) Max = MaxCreateMs;
        if (!Pass)
        {
            Log("SESSFWD soak batch %lu FAIL ok=%ld bad=%ld wait=%lx first-error=%lx\n",
                Batches, Ok, Bad, Wait, FirstError);
            Failures++;
            if (Wait != WAIT_OBJECT_0) break;
        }
        if ((GetTickCount() - LastLine >= 60000) || (GetTickCount() - Start >= Seconds * 1000))
        {
            LastLine = GetTickCount();
            ProcessUsage(SmssPid, &SmssPrivate, &SmssHandles);
            ProcessUsage(CsrPid, &CsrPrivate, &CsrHandles);
            Log("SESSFWD soak t=%lu batches=%lu ok=%lu bad=%lu max-create-ms=%lu smss-private=%Iu smss-handles=%lu "
                "csrss-private=%Iu csrss-handles=%lu\n",
                (GetTickCount() - Start) / 1000, Batches, TotalOk, TotalBad, Max,
                SmssPrivate, SmssHandles, CsrPrivate, CsrHandles);
        }
        if (GetTickCount() - Start >= Seconds * 1000) break;
    }
    CloseHandle(Token);
    /* The children are gone; the count then logged by SMSS is the records that stayed behind */
    Sleep(5000);
    SmssAnswers("soak-end", PROBE_BOUND_MS);
    ProcessUsage(SmssPid, &SmssPrivate, &SmssHandles);
    Log("SESSFWD soak end smss-private=%Iu smss-handles=%lu\n", SmssPrivate, SmssHandles);
    Log("SESSFWD soak done batches=%lu ok=%lu bad=%lu max-create-ms=%lu failures=%lu %s\n",
        Batches, TotalOk, TotalBad, Max, Failures, Failures ? "FAIL" : "PASS");
}

/* One probe of SMSS: connect to \\SmApiPort and send a forward, which SMSS refuses (we are not a csrss) */
typedef struct _PROBE
{
    NTSTATUS ConnectStatus;
    NTSTATUS Status;
    DWORD Ms;
} PROBE, *PPROBE;

static
DWORD
WINAPI
ProbeThread(PVOID Parameter)
{
    PPROBE Probe = Parameter;
    HANDLE Port;
    CLIENT_ID OwnId;
    DWORD Start = GetTickCount();

    OwnId.UniqueProcess = UlongToHandle(GetCurrentProcessId());
    OwnId.UniqueThread = UlongToHandle(GetCurrentThreadId());
    Probe->ConnectStatus = SmConnectToSm(NULL, NULL, 0, &Port);
    if (NT_SUCCESS(Probe->ConnectStatus))
    {
        Probe->Status = SmForwardProcessRegistration(Port, &OwnId, TARGET_SESSION, 0);
        NtClose(Port);
    }
    Probe->Ms = GetTickCount() - Start;
    return 0;
}

/* TRUE when SMSS answered the probe within the bound. A probe that does not return is left behind */
static
BOOL
SmssAnswers(const char *Name, DWORD BoundMs)
{
    PPROBE Probe = calloc(1, sizeof(*Probe));
    HANDLE Thread;
    BOOL Pass = FALSE;
    DWORD Wait = WAIT_FAILED;

    Thread = Probe ? CreateThread(NULL, 0, ProbeThread, Probe, 0, NULL) : NULL;
    if (Thread)
    {
        Wait = WaitForSingleObject(Thread, BoundMs);
        CloseHandle(Thread);
    }
    if (Wait == WAIT_OBJECT_0)
        Pass = NT_SUCCESS(Probe->ConnectStatus) && (Probe->Status == STATUS_ACCESS_DENIED);
    Log("SESSFWD %s smss-answers connect=%08lx status=%08lx wait=%lx ms=%lu bound=%lu %s\n", Name,
        Probe ? Probe->ConnectStatus : 0, Probe ? Probe->Status : 0, Wait, Probe ? Probe->Ms : 0, BoundMs,
        Pass ? "PASS" : "FAIL");
    if (!Pass) Failures++;
    if (Wait == WAIT_OBJECT_0) free(Probe);
    return Pass;
}

/* An SM_API_MSG datagram of the given length; the kernel copies only DataLength bytes after the header */
static
NTSTATUS
SendDatagram(HANDLE Port, ULONG Api, ULONG SessionId, USHORT DataLength, PULONG Retries)
{
    SM_API_MSG Msg;
    NTSTATUS Status;
    ULONG Try;

    RtlZeroMemory(&Msg, sizeof(Msg));
    Msg.ApiNumber = Api;
    Msg.u.SessionComplete.SessionId = SessionId;
    Msg.u.SessionComplete.SessionStatus = STATUS_SUCCESS;
    Msg.h.u1.s1.DataLength = DataLength;
    Msg.h.u1.s1.TotalLength = DataLength + sizeof(Msg.h);
    for (Try = 0; Try < 20000; Try++)
    {
        Status = NtRequestPort(Port, &Msg.h);
        /* The port's message zone is full: SMSS has not drained it yet */
        if ((Status != STATUS_NO_MEMORY) && (Status != STATUS_INSUFFICIENT_RESOURCES)) break;
        (*Retries)++;
        Sleep(1);
    }
    return Status;
}

#define FULL_DATAGRAM (sizeof(SM_SESSION_COMPLETE_MSG) + FIELD_OFFSET(SM_API_MSG, u) - sizeof(PORT_MESSAGE))

/*
 * The datagram path. Token is a session-1 token, or NULL without a session 1: then only SMSS's answers are
 * tested; with it a child of session 1 is registered (it holds a session record in SMSS) for the whole flood.
 */
static
VOID
DatagramTests(HANDLE Token)
{
    HANDLE Port = NULL, Child = NULL, ChildThread = NULL;
    NTSTATUS Status;
    ULONG Retries = 0, i, Failed = 0;
    DWORD Start, ExitCode = 0, Wait;
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 48];

    Status = SmConnectToSm(NULL, NULL, 0, &Port);
    Log("SESSFWD datagram sm-connect status=%08lx\n", Status);
    if (!NT_SUCCESS(Status))
    {
        Failures++;
        return;
    }

    /* A child of session 1 that stays: its record is in SMSS's list now */
    if (Token)
    {
        STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
        PROCESS_INFORMATION ProcessInfo;

        GetModuleFileNameW(NULL, Self, MAX_PATH);
        _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" child %lu hold %u", Self,
                   (ULONG)TARGET_SESSION, DATAGRAM_HOLD_MS);
        if (CreateProcessAsUserW(Token, NULL, CommandLine, NULL, NULL, FALSE, DETACHED_PROCESS,
                                 NULL, NULL, &StartupInfo, &ProcessInfo))
        {
            Child = ProcessInfo.hProcess;
            ChildThread = ProcessInfo.hThread;
        }
        Log("SESSFWD datagram-survival-begin child=%lu error=%lu\n",
            Child ? GetProcessId(Child) : 0, Child ? 0 : GetLastError());
        if (!Child) Failures++;
    }

    /* Datagrams of other APIs are dropped, never dispatched (these would start a process or a csrss) */
    Check("datagram-other-api-forward", SendDatagram(Port, SmpForwardProcessRegistrationApi, 1, FULL_DATAGRAM, &Retries),
          STATUS_SUCCESS);
    Check("datagram-other-api-execpgm", SendDatagram(Port, SmpExecPgmApi, 1, FULL_DATAGRAM, &Retries), STATUS_SUCCESS);
    Check("datagram-other-api-startcsr", SendDatagram(Port, SmpStartCsrApi, 1, FULL_DATAGRAM, &Retries), STATUS_SUCCESS);
    /* SmSessionComplete from a connection that is not a csrss: refused, whatever the session id */
    Check("datagram-session-complete-from-non-csrss",
          SendDatagram(Port, SmpSessionCompleteApi, 1, FULL_DATAGRAM, &Retries), STATUS_SUCCESS);
    /* Too short to carry a SessionId: dropped before SMSS reads ApiNumber (the status is the kernel's) */
    Status = SendDatagram(Port, SmpSessionCompleteApi, 1, 0, &Retries);
    Log("SESSFWD datagram-short-header-only status=%08lx\n", Status);
    Status = SendDatagram(Port, SmpSessionCompleteApi, 1, (USHORT)(FIELD_OFFSET(SM_API_MSG, u) - sizeof(PORT_MESSAGE)),
                          &Retries);
    Log("SESSFWD datagram-short-no-session-id status=%08lx\n", Status);
    SmssAnswers("after-single-datagrams", PROBE_BOUND_MS);

    /* The flood: every session id below DATAGRAM_FLOOD (the child's is among them), mixed with other APIs and short ones */
    Start = GetTickCount();
    for (i = 0; i < DATAGRAM_FLOOD; i++)
    {
        switch (i % 4)
        {
            case 0:
            case 1:
                Status = SendDatagram(Port, SmpSessionCompleteApi, i, FULL_DATAGRAM, &Retries);
                break;
            case 2:
                Status = SendDatagram(Port, SmpForwardProcessRegistrationApi, i, FULL_DATAGRAM, &Retries);
                break;
            default:
                Status = SendDatagram(Port, SmpSessionCompleteApi, i, 4, &Retries);
                break;
        }
        if (!NT_SUCCESS(Status) && ((i % 4) != 3)) Failed++;
    }
    Log("SESSFWD datagram-flood sent=%u failed=%lu retries=%lu ms=%lu\n", DATAGRAM_FLOOD, Failed, Retries,
        GetTickCount() - Start);
    if (Failed) Log("SESSFWD datagram-flood: some datagrams could not be queued (LPC), not counted\n");
    SmssAnswers("after-flood", PROBE_BOUND_MS);
    NtClose(Port);
    SmssAnswers("after-flood-reconnect", PROBE_BOUND_MS);

    if (Child)
    {
        /* The child exits: its csrss tells SMSS, which must still have the record (SMSS log: SUCCESS) */
        Wait = WaitForSingleObject(Child, DATAGRAM_HOLD_MS + 60000);
        GetExitCodeProcess(Child, &ExitCode);
        Log("SESSFWD datagram-child-after-flood wait=%lu exit=%08lx expect=%08lx %s\n", Wait, ExitCode, CHILD_OK,
            (Wait == WAIT_OBJECT_0 && ExitCode == CHILD_OK) ? "PASS" : "FAIL");
        if (!(Wait == WAIT_OBJECT_0 && ExitCode == CHILD_OK)) Failures++;
        if (Wait != WAIT_OBJECT_0) TerminateProcess(Child, 1);
        CloseHandle(Child);
        CloseHandle(ChildThread);
        /* Let the datagram of that exit reach SMSS before the end marker */
        Sleep(3000);
        Log("SESSFWD datagram-survival-end\n");
    }
}

typedef struct _STUCK
{
    HANDLE Token;
    BOOL Ok;
    DWORD CreateMs;
    DWORD Error;
} STUCK, *PSTUCK;

static
DWORD
WINAPI
StuckThread(PVOID Parameter)
{
    PSTUCK Stuck = Parameter;

    Stuck->Ok = StressChild(Stuck->Token, TARGET_SESSION, DETACHED_PROCESS, &Stuck->CreateMs, &Stuck->Error);
    return 0;
}

/*
 * A stuck target csrss (SMSS test switch NitroSessionsTestForwardStall, longer than the retry of csrsrv):
 * STUCK_THREADS creates into session 1 at once. One forward is stuck in SMSS, the others are told BUSY
 * and retried. SMSS must go on answering other requests all the while, and every create must return (fail).
 */
static
VOID
StuckTests(HANDLE Token)
{
    STUCK Stuck[STUCK_THREADS + 1];
    HANDLE Threads[STUCK_THREADS + 1];
    ULONG i, Started = 0, Returned = 0, Failed = 0;
    DWORD Wait;
    BOOL Late;

    RtlZeroMemory(Stuck, sizeof(Stuck));
    for (i = 0; i < STUCK_THREADS; i++)
    {
        Stuck[i].Token = Token;
        Threads[i] = CreateThread(NULL, 0, StuckThread, &Stuck[i], 0, NULL);
        if (!Threads[i]) break;
        Started++;
    }
    Log("SESSFWD stuck started=%lu of %u\n", Started, STUCK_THREADS);
    if (Started != STUCK_THREADS) Failures++;

    /* While they are in flight (the stall is longer than all of this) */
    Sleep(1500);
    SmssAnswers("stuck-while-forwards-in-flight-1", PROBE_BOUND_MS);
    Sleep(1500);
    SmssAnswers("stuck-while-forwards-in-flight-2", PROBE_BOUND_MS);
    Sleep(6000);
    SmssAnswers("stuck-after-busy-retries-expired", PROBE_BOUND_MS);

    /* One more create, while the first forward is still stuck */
    Stuck[Started].Token = Token;
    Threads[Started] = CreateThread(NULL, 0, StuckThread, &Stuck[Started], 0, NULL);
    Late = (Threads[Started] != NULL);
    Started += Late ? 1 : 0;

    Wait = WaitForMultipleObjects(Started, Threads, TRUE, STUCK_BOUND_MS);
    for (i = 0; i < Started; i++)
    {
        BOOL Done = (WaitForSingleObject(Threads[i], 0) == WAIT_OBJECT_0);

        Log("SESSFWD stuck create %lu returned=%d ok=%d create-ms=%lu error=%lx\n", i, Done, Stuck[i].Ok,
            Stuck[i].CreateMs, Stuck[i].Error);
        if (Done)
        {
            Returned++;
            if (!Stuck[i].Ok) Failed++;
            CloseHandle(Threads[i]);
        }
    }
    /* A stalled forward ends in a failed create and so does a busy one, none may hang or succeed */
    Log("SESSFWD stuck-creates-fail-cleanly started=%lu returned=%lu failed=%lu wait=%lx %s\n", Started, Returned,
        Failed, Wait, ((Wait == WAIT_OBJECT_0) && (Returned == Started) && (Failed == Started)) ? "PASS" : "FAIL");
    if (!((Wait == WAIT_OBJECT_0) && (Returned == Started) && (Failed == Started))) Failures++;
    SmssAnswers("stuck-after-all-returned", PROBE_BOUND_MS);
}

static
VOID
Tests(VOID)
{
    BOOLEAN Old;
    HANDLE Token, Process, Thread, OtherProcess, OtherThread, SmPort = NULL;
    CLIENT_ID ClientId, BadId, OtherId, OwnId;
    NTSTATUS Status;
    BOOL Session1;

    Log("SESSFWD start session=%lu pid=%lu\n", ProcessSession(NtCurrentProcess()), GetCurrentProcessId());
    RtlAdjustPrivilege(SE_TCB_PRIVILEGE, TRUE, FALSE, &Old);

    /* Control: a child in our own session, registered with our csrss as before */
    RunChild("own-session-child", NULL, ProcessSession(NtCurrentProcess()), 0);

    /* Negative: SMSS forwards only for a csrss it started; we are LocalSystem in session 0. It refuses
       the sender before it looks at the request, so any ids do (this needs no session 1) */
    OwnId.UniqueProcess = UlongToHandle(GetCurrentProcessId());
    OwnId.UniqueThread = UlongToHandle(GetCurrentThreadId());
    Status = SmConnectToSm(NULL, NULL, 0, &SmPort);
    Log("SESSFWD sm-connect status=%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Status = SmForwardProcessRegistration(SmPort, &OwnId, TARGET_SESSION, 0);
        Check("sm-forward-from-system-service", Status, STATUS_ACCESS_DENIED);
        NtClose(SmPort);
    }
    else
    {
        Failures++;
    }

    /* Everything else needs a session 1 (NitroSessions 4 or 5) */
    Session1 = (FindPidInSession(L"csrss.exe", TARGET_SESSION) != 0);
    Log("SESSFWD session-1 %s\n", Session1 ? "present" : "absent");
    if (!Session1)
    {
        DatagramTests(NULL);
        Skip("session1-detached-child", "no session 1");
        Skip("session1-console-child", "no session 1");
        Skip("concurrent-forwards", "no session 1");
        Skip("sb-create-remote-from-system-service", "no session 1");
        Skip("base-create-wrong-tid", "no session 1");
        Skip("base-create-thread-of-another-process", "no session 1");
        Skip("base-create-not-our-child", "no session 1");
        Skip("base-create-forwarded", "no session 1");
        Skip("base-create-forwarded-twice", "no session 1");
        goto Done;
    }

    /* CreateProcessAsUser into session 1: registered with session 1's csrss */
    Token = TokenForSession(TARGET_SESSION);
    if (Token)
    {
        LONG Ok, Bad;
        DWORD MaxCreateMs, FirstError, Wait;
        BOOL Pass;

        RunChild("session1-detached-child", Token, TARGET_SESSION, DETACHED_PROCESS);
        RunChild("session1-console-child", Token, TARGET_SESSION, 0);

        /* The datagram path, with a child of session 1 holding a record through the flood */
        DatagramTests(Token);

        /* Concurrent forwards, more than SMSS has API threads, while forwarded children exit */
        Pass = StressRun(Token, TARGET_SESSION, STRESS_ROUNDS, &Ok, &Bad, &MaxCreateMs, &FirstError, &Wait);
        Log("SESSFWD concurrent-forwards threads=%u rounds=%u ok=%ld bad=%ld wait=%lx max-create-ms=%lu "
            "first-error=%lx %s\n", STRESS_THREADS, STRESS_ROUNDS, Ok, Bad, Wait, MaxCreateMs, FirstError,
            Pass ? "PASS" : "FAIL");
        if (!Pass) Failures++;
        if (Wait != WAIT_OBJECT_0)
        {
            /* A hang: the stuck threads keep the token; the rest would hang as well */
            Log("SESSFWD concurrent-forwards: creates did not return within %u ms\n", STRESS_BOUND);
            goto Done;
        }

        /* SMSS and session 1's csrss still serve a forward afterwards */
        RunChild("after-concurrent-forwards-child", Token, TARGET_SESSION, DETACHED_PROCESS);
        CloseHandle(Token);
    }
    else
    {
        Log("SESSFWD no session-1 token FAIL\n");
        Failures++;
    }

    /* A process of session 1 that we created and that nobody registered */
    Status = CreateBareProcess(&Process, &Thread, &ClientId);
    Log("SESSFWD bare-process status=%08lx pid=%lu tid=%lu session=%lu\n", Status,
        HandleToUlong(ClientId.UniqueProcess), HandleToUlong(ClientId.UniqueThread),
        NT_SUCCESS(Status) ? ProcessSession(Process) : (ULONG)-1);
    if (!NT_SUCCESS(Status))
    {
        Failures++;
        goto Done;
    }

    /* Negative: the target csrss serves its Sb port only for SMSS: the connection itself is refused
       (main, CSRSS-sb-port-any-localsystem-client), so the request is never read */
    Status = SendSbCreateRemoteProcess(&ClientId);
    Check("sb-create-remote-from-system-service", Status, STATUS_PORT_CONNECTION_REFUSED);

    /* Negative: the ids must be those of the handles */
    BadId = ClientId;
    BadId.UniqueThread = UlongToHandle(GetCurrentThreadId());
    Status = CallBaseCreateProcess(Process, Thread, &BadId);
    Check("base-create-wrong-tid", Status, STATUS_INVALID_CID);

    /* Negative: the thread must belong to the process (our own thread, with its id) */
    {
        HANDLE OwnThread;
        CLIENT_ID Mixed;

        DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &OwnThread,
                        0, FALSE, DUPLICATE_SAME_ACCESS);
        Mixed.UniqueProcess = ClientId.UniqueProcess;
        Mixed.UniqueThread = UlongToHandle(GetCurrentThreadId());
        Status = CallBaseCreateProcess(Process, OwnThread, &Mixed);
        Check("base-create-thread-of-another-process", Status, STATUS_INVALID_CID);
        CloseHandle(OwnThread);
    }

    /* Negative: a process of session 1 that is not our child */
    if (FindProcessInSession(L"sesswin2.exe", TARGET_SESSION, &OtherProcess, &OtherThread, &OtherId))
    {
        Status = CallBaseCreateProcess(OtherProcess, OtherThread, &OtherId);
        Check("base-create-not-our-child", Status, STATUS_ACCESS_DENIED);
        CloseHandle(OtherProcess);
        CloseHandle(OtherThread);
    }
    else
    {
        Log("SESSFWD base-create-not-our-child: no sesswin2.exe in session 1 FAIL\n");
        Failures++;
    }

    /* Positive: our child in session 1, through basesrv, SMSS and session 1's csrss */
    Status = CallBaseCreateProcess(Process, Thread, &ClientId);
    Check("base-create-forwarded", Status, STATUS_SUCCESS);

    /* Negative: the same process again: already registered */
    Status = CallBaseCreateProcess(Process, Thread, &ClientId);
    Check("base-create-forwarded-twice", Status, STATUS_OBJECT_NAME_COLLISION);

    NtTerminateProcess(Process, STATUS_SUCCESS);
    NtClose(Thread);
    NtClose(Process);

Done:
    Log("SESSFWD done failures=%lu skipped=%lu\n", Failures, Skips);
}

/* "svc <file> stuck": only the stuck-target test */
static
VOID
StuckMain(VOID)
{
    BOOLEAN Old;
    HANDLE Token;

    RtlAdjustPrivilege(SE_TCB_PRIVILEGE, TRUE, FALSE, &Old);
    Log("SESSFWD stuck start session=%lu\n", ProcessSession(NtCurrentProcess()));
    Token = FindPidInSession(L"csrss.exe", TARGET_SESSION) ? TokenForSession(TARGET_SESSION) : NULL;
    if (!Token)
    {
        Skip("stuck-target", "no session 1");
    }
    else
    {
        StuckTests(Token);
        CloseHandle(Token);
    }
    Log("SESSFWD done failures=%lu skipped=%lu\n", Failures, Skips);
}

static SERVICE_STATUS_HANDLE StatusHandle;

static
VOID
Report(DWORD State)
{
    SERVICE_STATUS Status = { SERVICE_WIN32_OWN_PROCESS, State, 0, NO_ERROR, 0, 0, 0 };
    SetServiceStatus(StatusHandle, &Status);
}

static ULONG SoakSeconds, SoakSession = TARGET_SESSION;
static BOOL StuckMode;

static
VOID
WINAPI
ServiceMain(DWORD Argc, LPWSTR *Argv)
{
    StatusHandle = RegisterServiceCtrlHandlerW(L"sfwd", NULL);
    Report(SERVICE_RUNNING);
    if (SoakSeconds) Soak(SoakSeconds, SoakSession);
    else if (StuckMode) StuckMain();
    else Tests();
    Report(SERVICE_STOPPED);
}

int
wmain(int argc, wchar_t *argv[])
{
    if ((argc > 2) && !_wcsicmp(argv[1], L"child"))
    {
        ULONG Expected = wcstoul(argv[2], NULL, 10);
        if ((argc > 4) && !_wcsicmp(argv[3], L"hold")) Sleep(wcstoul(argv[4], NULL, 10));
        return (ProcessSession(NtCurrentProcess()) == Expected) ? CHILD_OK : 1;
    }

    if ((argc > 1) && !_wcsicmp(argv[1], L"svc"))
    {
        SERVICE_TABLE_ENTRYW Table[] = { { L"sfwd", ServiceMain }, { NULL, NULL } };

        if (argc > 2) Out = _wfopen(argv[2], L"w");
        if ((argc > 3) && !_wcsicmp(argv[3], L"stuck")) StuckMode = TRUE;
        if ((argc > 4) && !_wcsicmp(argv[3], L"soak")) SoakSeconds = wcstoul(argv[4], NULL, 10);
        if ((argc > 5) && SoakSeconds) SoakSession = wcstoul(argv[5], NULL, 10);
        if ((argc > 6) && SoakSeconds && !_wcsicmp(argv[6], L"detached")) StressDetachedOnly = TRUE;
        StartServiceCtrlDispatcherW(Table);
        if (Out) fclose(Out);
        return 0;
    }

    if (argc > 1) Out = _wfopen(argv[1], L"w");
    Tests();
    if (Out) fclose(Out);
    return Failures ? 1 : 0;
}
