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

static FILE *Out;
static ULONG Failures;

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
ULONG
ProcessSession(HANDLE Process)
{
    ULONG Session = (ULONG)-1;
    NtQueryInformationProcess(Process, ProcessSessionInformation, &Session, sizeof(Session), NULL);
    return Session;
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

static
VOID
Tests(VOID)
{
    BOOLEAN Old;
    HANDLE Token, Process, Thread, OtherProcess, OtherThread, SmPort = NULL;
    CLIENT_ID ClientId, BadId, OtherId;
    NTSTATUS Status;

    Log("SESSFWD start session=%lu pid=%lu\n", ProcessSession(NtCurrentProcess()), GetCurrentProcessId());
    RtlAdjustPrivilege(SE_TCB_PRIVILEGE, TRUE, FALSE, &Old);

    /* Control: a child in our own session, registered with our csrss as before */
    RunChild("own-session-child", NULL, ProcessSession(NtCurrentProcess()), 0);

    /* CreateProcessAsUser into session 1: registered with session 1's csrss */
    Token = TokenForSession(TARGET_SESSION);
    if (Token)
    {
        RunChild("session1-detached-child", Token, TARGET_SESSION, DETACHED_PROCESS);
        RunChild("session1-console-child", Token, TARGET_SESSION, 0);
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

    /* Negative: SMSS forwards only for a csrss it started; we are LocalSystem in session 0 */
    Status = SmConnectToSm(NULL, NULL, 0, &SmPort);
    Log("SESSFWD sm-connect status=%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        Status = SmForwardProcessRegistration(SmPort, &ClientId, TARGET_SESSION, 0);
        Check("sm-forward-from-system-service", Status, STATUS_ACCESS_DENIED);
        NtClose(SmPort);
    }
    else
    {
        Failures++;
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
    Log("SESSFWD done failures=%lu\n", Failures);
}

static SERVICE_STATUS_HANDLE StatusHandle;

static
VOID
Report(DWORD State)
{
    SERVICE_STATUS Status = { SERVICE_WIN32_OWN_PROCESS, State, 0, NO_ERROR, 0, 0, 0 };
    SetServiceStatus(StatusHandle, &Status);
}

static
VOID
WINAPI
ServiceMain(DWORD Argc, LPWSTR *Argv)
{
    StatusHandle = RegisterServiceCtrlHandlerW(L"sfwd", NULL);
    Report(SERVICE_RUNNING);
    Tests();
    Report(SERVICE_STOPPED);
}

int
wmain(int argc, wchar_t *argv[])
{
    if ((argc > 2) && !_wcsicmp(argv[1], L"child"))
    {
        ULONG Expected = wcstoul(argv[2], NULL, 10);
        return (ProcessSession(NtCurrentProcess()) == Expected) ? CHILD_OK : 1;
    }

    if ((argc > 1) && !_wcsicmp(argv[1], L"svc"))
    {
        SERVICE_TABLE_ENTRYW Table[] = { { L"sfwd", ServiceMain }, { NULL, NULL } };

        if (argc > 2) Out = _wfopen(argv[2], L"w");
        StartServiceCtrlDispatcherW(Table);
        if (Out) fclose(Out);
        return 0;
    }

    if (argc > 1) Out = _wfopen(argv[1], L"w");
    Tests();
    if (Out) fclose(Out);
    return Failures ? 1 : 0;
}
