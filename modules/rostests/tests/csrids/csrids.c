/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     csrss registers only what the client really created:
 *              - BasepCreateProcess: the process and thread ids must be those
 *                of the handles the client passes, and the process must be the
 *                client's child;
 *              - the Sb port of csrss serves only the Session Manager that
 *                started it ("svc" mode only: the port admits LocalSystem).
 *              Run it as an administrator ("csrids [file]") and as LocalSystem:
 *                sc create csrids binPath= "C:\ReactOS\bin\csrids.exe svc C:\harness\out\csrids-svc.txt"
 *              One line per check, PASS or FAIL, to the file (or stdout) and
 *              to the debugger.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
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
#include <csr/csr.h>
#include <win/basemsg.h>
#include <sm/smmsg.h>

/* The ntdll export (the NDK declares the Windows 7 form for this NTDDI) */
typedef NTSTATUS (NTAPI *PRTL_CREATE_USER_THREAD)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T,
                                                  PTHREAD_START_ROUTINE, PVOID, PHANDLE, PCLIENT_ID);

#define CHILD_OK 0x5E55

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
    fputs(Buffer, Out ? Out : stdout);
    fflush(Out ? Out : stdout);
}

static
VOID
Check(const char *Name, NTSTATUS Status, NTSTATUS Expected)
{
    BOOL Pass = (Status == Expected);
    Log("CSRIDS %s status=%08lx expect=%08lx %s\n", Name, Status, Expected, Pass ? "PASS" : "FAIL");
    if (!Pass) Failures++;
}

/* A child of ours that nobody registered: the process object of our own image and one suspended thread */
static
NTSTATUS
CreateBareChild(PHANDLE Process, PHANDLE Thread, PCLIENT_ID ClientId)
{
    WCHAR Self[MAX_PATH];
    HANDLE File, Section = NULL;
    SECTION_IMAGE_INFORMATION ImageInfo;
    PRTL_CREATE_USER_THREAD CreateUserThread;
    NTSTATUS Status;

    *Process = *Thread = NULL;
    CreateUserThread = (PRTL_CREATE_USER_THREAD)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
    if (!CreateUserThread) return STATUS_PROCEDURE_NOT_FOUND;
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    File = CreateFileW(Self, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, File);
    CloseHandle(File);
    if (!NT_SUCCESS(Status)) return Status;
    Status = NtQuerySection(Section, SectionImageInformation, &ImageInfo, sizeof(ImageInfo), NULL);
    if (NT_SUCCESS(Status))
        Status = NtCreateProcessEx(Process, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), 0, Section, NULL, NULL, FALSE);
    NtClose(Section);
    if (!NT_SUCCESS(Status)) return Status;

    Status = CreateUserThread(*Process, NULL, TRUE, 0, 0, 0, (PTHREAD_START_ROUTINE)ImageInfo.TransferAddress,
                              NULL, Thread, ClientId);
    if (!NT_SUCCESS(Status))
    {
        NtTerminateProcess(*Process, Status);
        NtClose(*Process);
        *Process = NULL;
    }
    return Status;
}

/* BasepCreateProcess to our csrss, as kernel32 sends it, with the given handles and ids */
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

/* Our parent process (not our child) and one of its threads */
static
BOOL
OpenParent(PHANDLE Process, PHANDLE Thread, PCLIENT_ID ClientId)
{
    PROCESS_BASIC_INFORMATION Info;
    HANDLE Snapshot;
    THREADENTRY32 Entry;
    DWORD Pid;

    *Process = *Thread = NULL;
    if (!NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &Info, sizeof(Info), NULL)))
        return FALSE;
    Pid = (DWORD)Info.InheritedFromUniqueProcessId;
    Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Snapshot == INVALID_HANDLE_VALUE) return FALSE;
    Entry.dwSize = sizeof(Entry);
    if (Thread32First(Snapshot, &Entry))
    {
        do
        {
            if (Entry.th32OwnerProcessID == Pid)
            {
                *Process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
                *Thread = OpenThread(THREAD_ALL_ACCESS, FALSE, Entry.th32ThreadID);
                ClientId->UniqueProcess = UlongToHandle(Pid);
                ClientId->UniqueThread = UlongToHandle(Entry.th32ThreadID);
                break;
            }
        } while (Thread32Next(Snapshot, &Entry));
    }
    CloseHandle(Snapshot);
    if (*Process && *Thread) return TRUE;
    if (*Process) CloseHandle(*Process);
    if (*Thread) CloseHandle(*Thread);
    return FALSE;
}

static
VOID
BaseTests(VOID)
{
    WCHAR Self[MAX_PATH], CommandLine[MAX_PATH + 16];
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    HANDLE Process, Thread, OwnThread;
    CLIENT_ID ClientId, Ids;
    DWORD ExitCode = 0;
    NTSTATUS Status;

    /* Control: CreateProcess, as every program does */
    GetModuleFileNameW(NULL, Self, MAX_PATH);
    _snwprintf(CommandLine, RTL_NUMBER_OF(CommandLine), L"\"%s\" child", Self);
    if (CreateProcessW(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
    {
        WaitForSingleObject(ProcessInfo.hProcess, 60000);
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
        CloseHandle(ProcessInfo.hProcess);
        CloseHandle(ProcessInfo.hThread);
    }
    Check("createprocess-child", (NTSTATUS)ExitCode, CHILD_OK);

    /* An unregistered child of ours */
    Status = CreateBareChild(&Process, &Thread, &ClientId);
    Log("CSRIDS bare-child status=%08lx pid=%lu tid=%lu\n", Status,
        HandleToUlong(ClientId.UniqueProcess), HandleToUlong(ClientId.UniqueThread));
    if (!NT_SUCCESS(Status))
    {
        Failures++;
        return;
    }

    /* Negative: the request names another thread than the handle's */
    Ids = ClientId;
    Ids.UniqueThread = UlongToHandle(GetCurrentThreadId());
    Check("wrong-tid", CallBaseCreateProcess(Process, Thread, &Ids), STATUS_INVALID_CID);

    /* Negative: the request names another process than the handle's (ours) */
    Ids = ClientId;
    Ids.UniqueProcess = UlongToHandle(GetCurrentProcessId());
    Check("wrong-pid", CallBaseCreateProcess(Process, Thread, &Ids), STATUS_INVALID_CID);

    /* Negative: a thread of another process (ours, with its own id) */
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &OwnThread,
                    0, FALSE, DUPLICATE_SAME_ACCESS);
    Ids.UniqueProcess = ClientId.UniqueProcess;
    Ids.UniqueThread = UlongToHandle(GetCurrentThreadId());
    Check("thread-of-another-process", CallBaseCreateProcess(Process, OwnThread, &Ids), STATUS_INVALID_CID);
    CloseHandle(OwnThread);

    /* Positive: our child with its own ids */
    Check("own-child", CallBaseCreateProcess(Process, Thread, &ClientId), STATUS_SUCCESS);

    NtTerminateProcess(Process, STATUS_SUCCESS);
    NtClose(Thread);
    NtClose(Process);

    /* Negative: a process that is not our child (our parent), with its own ids */
    if (OpenParent(&Process, &Thread, &ClientId))
    {
        Check("not-our-child", CallBaseCreateProcess(Process, Thread, &ClientId), STATUS_ACCESS_DENIED);
        CloseHandle(Process);
        CloseHandle(Thread);
    }
    else
    {
        Log("CSRIDS not-our-child: cannot open the parent FAIL\n");
        Failures++;
    }
}

/* LocalSystem only: the Sb port of our session's csrss refuses anyone but the Session Manager */
static
VOID
SbTests(VOID)
{
    UNICODE_STRING Name;
    SECURITY_QUALITY_OF_SERVICE Qos;
    HANDLE Port = NULL;
    ULONG Session = 0;
    WCHAR PortName[64];
    NTSTATUS Status;

    NtQueryInformationProcess(NtCurrentProcess(), ProcessSessionInformation, &Session, sizeof(Session), NULL);
    if (Session)
        _snwprintf(PortName, RTL_NUMBER_OF(PortName), L"\\Sessions\\%lu\\Windows\\SbApiPort", Session);
    else
        _snwprintf(PortName, RTL_NUMBER_OF(PortName), L"\\Windows\\SbApiPort");
    RtlInitUnicodeString(&Name, PortName);
    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityIdentification;
    Qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Qos.EffectiveOnly = TRUE;
    Status = NtConnectPort(&Port, &Name, &Qos, NULL, NULL, NULL, NULL, NULL);
    Check("sb-connect-from-system", Status, STATUS_PORT_CONNECTION_REFUSED);
    if (NT_SUCCESS(Status)) NtClose(Port);
}

static
VOID
Tests(BOOL System)
{
    Log("CSRIDS start pid=%lu system=%d\n", GetCurrentProcessId(), System);
    BaseTests();
    if (System) SbTests();
    Log("CSRIDS done failures=%lu\n", Failures);
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
    StatusHandle = RegisterServiceCtrlHandlerW(L"csrids", NULL);
    Report(SERVICE_RUNNING);
    Tests(TRUE);
    Report(SERVICE_STOPPED);
}

int
wmain(int argc, wchar_t *argv[])
{
    if ((argc > 1) && !_wcsicmp(argv[1], L"child")) return CHILD_OK;

    if ((argc > 1) && !_wcsicmp(argv[1], L"svc"))
    {
        SERVICE_TABLE_ENTRYW Table[] = { { L"csrids", ServiceMain }, { NULL, NULL } };

        if (argc > 2) Out = _wfopen(argv[2], L"w");
        StartServiceCtrlDispatcherW(Table);
        if (Out) fclose(Out);
        return 0;
    }

    if (argc > 1) Out = _wfopen(argv[1], L"w");
    Tests(FALSE);
    if (Out) fclose(Out);
    return Failures ? 1 : 0;
}
