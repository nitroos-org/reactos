/*
 * PROJECT:     NitroOS SMB mini-redirector tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Who may open the engine device and the engine process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * smbengacl run      (administrator) for each engine state (never started, running, killed, stopped):
 *                    scratch services of other accounts try to open \Device\NitroSmbEngine and the
 *                    engine process; every open must be refused. Prints "ROW <name> PASS|FAIL ..." and
 *                    "SUMMARY pass=N fail=M".
 * smbengacl svc NAME DIR MILLISECONDS   (service side) try the opens for MILLISECONDS, write DIR\NAME.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <drivers/smbrdr/smbupcall.h>
#include "sysopen.h"

static int Pass, Fail;

static void
Row(BOOL Ok, const char *Name, const char *Detail)
{
    printf("ROW %s %s %s\n", Name, Ok ? "PASS" : "FAIL", Detail);
    if (Ok) Pass++; else Fail++;
}

/* ---- service side ---- */
static WCHAR SvcName[64], SvcDir[MAX_PATH];
static DWORD SvcMillis;
static BOOL SvcConsole;     /* "probe": the same opens from the console (no service) */
static SERVICE_STATUS_HANDLE SvcHandle;
static HANDLE SvcStop;

static void
SvcReport(DWORD State)
{
    SERVICE_STATUS S = {0};
    S.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    S.dwCurrentState = State;
    S.dwControlsAccepted = State == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    S.dwWaitHint = 5000;
    SetServiceStatus(SvcHandle, &S);
}

static DWORD WINAPI
SvcCtrl(DWORD Control, DWORD Type, LPVOID Data, LPVOID Ctx)
{
    if (Control == SERVICE_CONTROL_STOP)
    {
        SvcReport(SERVICE_STOP_PENDING);
        SetEvent(SvcStop);
    }
    return NO_ERROR;
}

static void WINAPI
SvcMain(DWORD argc, LPWSTR *argv)
{
    static const DWORD DevAccess[] = { GENERIC_READ | GENERIC_WRITE, GENERIC_READ, READ_CONTROL,
                                       FILE_READ_ATTRIBUTES, MAXIMUM_ALLOWED, 0 };
    static const DWORD ProcAccess[] = { PROCESS_DUP_HANDLE, PROCESS_VM_READ, WRITE_DAC, WRITE_OWNER,
                                        PROCESS_ALL_ACCESS };
    WCHAR Path[MAX_PATH], Tmp[MAX_PATH];
    ULONG DevOk[6] = {0}, DevTries = 0, ProcOk[5] = {0}, ProcTries = 0, LastDevErr[6] = {0};
    DWORD Start, Pid = 0, i;
    HANDLE h;
    FILE *f;

    if (!SvcConsole)
    {
        SvcHandle = RegisterServiceCtrlHandlerExW(SvcName, SvcCtrl, NULL);
        SvcReport(SERVICE_RUNNING);
    }
    swprintf(Path, MAX_PATH, L"%ls\\engine.pid", SvcDir);
    Start = GetTickCount();
    do
    {
        for (i = 0; i < 6; i++)
        {
            h = CreateFileW(NITRO_SMBRDR_ENGINE_DOS_NAME, DevAccess[i], 0, NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                DevOk[i]++;
                CloseHandle(h);
            }
            else
                LastDevErr[i] = GetLastError();
        }
        DevTries++;
        f = _wfopen(Path, L"r");
        if (f)
        {
            if (fscanf(f, "%lu", &Pid) != 1)
                Pid = 0;
            fclose(f);
        }
        for (i = 0; Pid != 0 && i < 5; i++)
        {
            h = OpenProcess(ProcAccess[i], FALSE, Pid);
            if (h)
            {
                ProcOk[i]++;
                CloseHandle(h);
            }
        }
        if (Pid)
            ProcTries++;
        Sleep(10);
    } while (GetTickCount() - Start < SvcMillis);

    swprintf(Tmp, MAX_PATH, L"%ls\\%ls.tmp", SvcDir, SvcName);
    f = _wfopen(Tmp, L"w");
    if (!f)
    {
        WCHAR Msg[MAX_PATH + 64];
        swprintf(Msg, MAX_PATH + 64, L"smbengacl: cannot write %ls (%lu)\n", Tmp, GetLastError());
        OutputDebugStringW(Msg);
        if (SvcConsole)
            wprintf(L"%ls", Msg);
    }
    if (f)
    {
        fprintf(f, "TRIES %lu %lu\n", DevTries, ProcTries);
        for (i = 0; i < 6; i++)
            fprintf(f, "DEV 0x%08lx %lu err=%lu\n", DevAccess[i], DevOk[i], LastDevErr[i]);
        for (i = 0; i < 5; i++)
            fprintf(f, "PROC 0x%08lx %lu\n", ProcAccess[i], ProcOk[i]);
        fprintf(f, "END\n");
        fclose(f);
        swprintf(Path, MAX_PATH, L"%ls\\%ls.txt", SvcDir, SvcName);
        MoveFileExW(Tmp, Path, MOVEFILE_REPLACE_EXISTING);
    }
    if (SvcConsole)
        return;
    WaitForSingleObject(SvcStop, 60000);
    SvcReport(SERVICE_STOPPED);
}

/* ---- tester side ---- */
static WCHAR Dir[MAX_PATH], Exe[MAX_PATH];
static SC_HANDLE Scm;

static BOOL
WaitState(SC_HANDLE h, DWORD State, DWORD *Pid)
{
    SERVICE_STATUS_PROCESS S;
    DWORD n, t;
    for (t = 0; t < 300; t++)
    {
        if (QueryServiceStatusEx(h, SC_STATUS_PROCESS_INFO, (LPBYTE)&S, sizeof(S), &n) && S.dwCurrentState == State)
        {
            if (Pid) *Pid = S.dwProcessId;
            return TRUE;
        }
        Sleep(100);
    }
    return FALSE;
}

/* Start a prober service of ACCOUNT (SID type SIDTYPE) that tries the opens for MILLIS */
static SC_HANDLE
StartProber(LPCWSTR Name, LPCWSTR Account, DWORD SidType, DWORD Millis)
{
    WCHAR Cmd[2 * MAX_PATH + 64], File[MAX_PATH];
    struct { DWORD dwServiceSidType; } Sid;     /* SERVICE_SID_INFO (not in our SDK headers) */
    SC_HANDLE h;

    swprintf(File, MAX_PATH, L"%ls\\%ls.txt", Dir, Name);
    DeleteFileW(File);
    swprintf(Cmd, sizeof(Cmd) / sizeof(WCHAR), L"\"%ls\" svc %ls \"%ls\" %lu", Exe, Name, Dir, Millis);
    h = CreateServiceW(Scm, Name, Name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                       SERVICE_ERROR_IGNORE, Cmd, NULL, NULL, NULL, Account, L"");
    if (!h)
    {
        printf("CreateService %ls failed %lu\n", Name, GetLastError());
        return NULL;
    }
    if (SidType)
    {
        Sid.dwServiceSidType = SidType;
        ChangeServiceConfig2W(h, SERVICE_CONFIG_SERVICE_SID_INFO, &Sid);
    }
    if (!StartServiceW(h, 0, NULL))
        printf("StartService %ls failed %lu\n", Name, GetLastError());
    return h;
}

/* Wait for the prober's result, stop and delete it; check that nothing was opened */
static void
FinishProber(SC_HANDLE h, LPCWSTR Name, const char *State, BOOL ExpectProc)
{
    WCHAR File[MAX_PATH];
    char Line[256], RowName[160], Detail[512] = "";
    ULONG Access, Count, Err, Tries = 0, PTries = 0;
    BOOL Ok = TRUE, Seen = FALSE;
    SERVICE_STATUS S;
    FILE *f = NULL;
    int t;

    swprintf(File, MAX_PATH, L"%ls\\%ls.txt", Dir, Name);
    for (t = 0; t < 400 && !(f = _wfopen(File, L"r")); t++)
        Sleep(100);
    sprintf(RowName, "%s/%ls", State, Name);
    if (!f)
    {
        Row(FALSE, RowName, "no result");
    }
    else
    {
        while (fgets(Line, sizeof(Line), f))
        {
            if (sscanf(Line, "TRIES %lu %lu", &Tries, &PTries) == 2)
                continue;
            if (sscanf(Line, "DEV 0x%lx %lu err=%lu", &Access, &Count, &Err) == 3)
            {
                Seen = TRUE;
                if (Count)
                    Ok = FALSE;
                sprintf(Detail + strlen(Detail), "dev(%lx)=%lu/err%lu ", Access, Count, Err);
            }
            else if (sscanf(Line, "PROC 0x%lx %lu", &Access, &Count) == 2)
            {
                if (Count)
                    Ok = FALSE;
                sprintf(Detail + strlen(Detail), "proc(%lx)=%lu ", Access, Count);
            }
        }
        fclose(f);
        sprintf(Detail + strlen(Detail), "tries=%lu/%lu", Tries, PTries);
        if (ExpectProc && PTries == 0)
            Ok = FALSE;
        Row(Ok && Seen, RowName, Detail);
    }
    ControlService(h, SERVICE_CONTROL_STOP, &S);
    WaitState(h, SERVICE_STOPPED, NULL);
    DeleteService(h);
    CloseServiceHandle(h);
    DeleteFileW(File);
}

static void
Probe(const char *State, DWORD Millis, BOOL ExpectProc, void (*During)(void))
{
    SC_HANDLE a, b, c;
    WCHAR Na[64], Nb[64], Nc[64];
    DWORD Tick = GetTickCount();

    swprintf(Na, 64, L"RosEngAclLs%lu", Tick);
    swprintf(Nb, 64, L"RosEngAclLsSid%lu", Tick);
    swprintf(Nc, 64, L"RosEngAclNs%lu", Tick);
    a = StartProber(Na, L"NT AUTHORITY\\LocalService", 0, Millis);
    b = StartProber(Nb, L"NT AUTHORITY\\LocalService", SERVICE_SID_TYPE_UNRESTRICTED, Millis);
    c = StartProber(Nc, L"NT AUTHORITY\\NetworkService", 0, Millis);
    if (During)
        During();
    if (a) FinishProber(a, Na, State, ExpectProc);
    if (b) FinishProber(b, Nb, State, ExpectProc);
    if (c) FinishProber(c, Nc, State, ExpectProc);
}

static BOOL
Control(LPCWSTR Name, BOOL StartIt, DWORD *Pid)
{
    SC_HANDLE h = OpenServiceW(Scm, Name, SERVICE_ALL_ACCESS);
    SERVICE_STATUS S;
    BOOL r;
    if (!h)
        return FALSE;
    if (StartIt)
    {
        StartServiceW(h, 0, NULL);
        r = WaitState(h, SERVICE_RUNNING, Pid);
    }
    else
    {
        ControlService(h, SERVICE_CONTROL_STOP, &S);
        r = WaitState(h, SERVICE_STOPPED, NULL);
    }
    CloseServiceHandle(h);
    return r;
}

static void
WritePid(DWORD Pid)
{
    WCHAR Path[MAX_PATH];
    FILE *f;
    swprintf(Path, MAX_PATH, L"%ls\\engine.pid", Dir);
    if (Pid == 0)
    {
        DeleteFileW(Path);
        return;
    }
    f = _wfopen(Path, L"w");
    if (f)
    {
        fprintf(f, "%lu\n", Pid);
        fclose(f);
    }
}

static DWORD EnginePid;

static void
KillEngine(void)
{
    HANDLE h;
    Sleep(1500);    /* the probers are looping */
    h = OpenProcess(PROCESS_TERMINATE, FALSE, EnginePid);
    printf("kill engine %lu: %s\n", EnginePid, (h && TerminateProcess(h, 99)) ? "terminated" : "failed");
    if (h) CloseHandle(h);
    /* the probers then try the restarted engine */
    WritePid(0);
    {
        SC_HANDLE s = OpenServiceW(Scm, L"smbengine", SERVICE_QUERY_STATUS);
        SERVICE_STATUS_PROCESS S;
        DWORD n, t;
        for (t = 0; s && t < 40; t++)
        {
            if (QueryServiceStatusEx(s, SC_STATUS_PROCESS_INFO, (LPBYTE)&S, sizeof(S), &n) &&
                S.dwCurrentState == SERVICE_RUNNING && S.dwProcessId != 0 && S.dwProcessId != EnginePid)
            {
                printf("engine restarted: pid %lu\n", S.dwProcessId);
                EnginePid = S.dwProcessId;
                WritePid(EnginePid);
                break;
            }
            Sleep(100);
        }
        if (s) CloseServiceHandle(s);
    }
}

static void
EnableDebug(void)
{
    HANDLE h;
    TOKEN_PRIVILEGES Tp;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &h))
    {
        Tp.PrivilegeCount = 1;
        Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Tp.Privileges[0].Luid))
            AdjustTokenPrivileges(h, FALSE, &Tp, 0, NULL, NULL);
        CloseHandle(h);
    }
}

static int
Run(void)
{
    SECURITY_ATTRIBUTES Sa;
    HANDLE h;
    DWORD Pid = 0;
    char Detail[128];

    EnableDebug();
    GetModuleFileNameW(NULL, Exe, MAX_PATH);
    GetEnvironmentVariableW(L"ALLUSERSPROFILE", Dir, MAX_PATH);
    wcscat(Dir, L"\\RosEngAcl");
    /* test directory: every prober writes its result there */
    Sa.nLength = sizeof(Sa);
    Sa.bInheritHandle = FALSE;
    Sa.lpSecurityDescriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                                                              SDDL_REVISION_1, &Sa.lpSecurityDescriptor, NULL))
    {
        printf("SDDL failed %lu\n", GetLastError());
        return 2;
    }
    if (!CreateDirectoryW(Dir, &Sa) && GetLastError() != ERROR_ALREADY_EXISTS)
        printf("CreateDirectory failed %lu\n", GetLastError());
    LocalFree(Sa.lpSecurityDescriptor);
    WritePid(0);

    Scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!Scm)
    {
        printf("OpenSCManager failed %lu (needs an administrator)\n", GetLastError());
        return 2;
    }

    /* The engine is stopped; the driver is loaded (as after a crash or before the first start) */
    Control(L"smbengine", FALSE, NULL);
    Row(Control(L"mrxsmb", TRUE, NULL), "setup/mrxsmb-started", "");
    Probe("never-started", 3000, FALSE, NULL);

    /* Engine running */
    Row(Control(L"smbengine", TRUE, &Pid) && Pid != 0, "setup/engine-running", "");
    EnginePid = Pid;
    WritePid(Pid);
    Probe("running", 3000, TRUE, NULL);

    /* A second engine while the engine holds the device: SYSTEM may open it, the attach is refused */
    h = SmbTestOpenAsSystem(NITRO_SMBRDR_ENGINE_DOS_NAME, GENERIC_READ | GENERIC_WRITE, 0);
    if (h == INVALID_HANDLE_VALUE)
    {
        sprintf(Detail, "open err=%lu", GetLastError());
        Row(FALSE, "running/second-attach-as-system", Detail);
    }
    else
    {
        SMBUP_ATTACH Attach;
        DWORD Ret;
        BOOL Ok;

        memset(&Attach, 0, sizeof(Attach));
        Attach.Magic = SMBUP_MAGIC;
        Attach.Version = SMBUP_VERSION;
        Attach.MaxMessageSize = SMBUP_MAX_MESSAGE;
        Ok = DeviceIoControl(h, IOCTL_SMBRDR_ENGINE_ATTACH, &Attach, sizeof(Attach), NULL, 0, &Ret, NULL);
        sprintf(Detail, "attach=%d err=%lu", Ok, Ok ? 0 : GetLastError());
        Row(!Ok && GetLastError() == ERROR_SHARING_VIOLATION, "running/second-attach-as-system", Detail);
        CloseHandle(h);
    }

    /* Engine killed while the probers loop (recovery restarts it after 1 s) */
    Probe("killed", 6000, TRUE, KillEngine);
    WritePid(0);

    /* Engine stopped */
    Control(L"smbengine", FALSE, NULL);
    Probe("stopped", 3000, FALSE, NULL);

    RemoveDirectoryW(Dir);
    CloseServiceHandle(Scm);
    printf("SUMMARY pass=%d fail=%d\n", Pass, Fail);
    return Fail ? 1 : 0;
}

int
wmain(int argc, WCHAR **argv)
{
    if (argc >= 5 && (!wcscmp(argv[1], L"svc") || !wcscmp(argv[1], L"probe")))
    {
        SERVICE_TABLE_ENTRYW T[2] = { { SvcName, SvcMain }, { NULL, NULL } };
        wcsncpy(SvcName, argv[2], 63);
        wcsncpy(SvcDir, argv[3], MAX_PATH - 1);
        SvcMillis = wcstoul(argv[4], NULL, 10);
        SvcStop = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!wcscmp(argv[1], L"probe"))
        {
            SvcConsole = TRUE;
            SvcMain(0, NULL);
            return 0;
        }
        if (!StartServiceCtrlDispatcherW(T))
        {
            OutputDebugStringW(L"smbengacl: StartServiceCtrlDispatcher failed\n");
            return 1;
        }
        return 0;
    }
    if (argc >= 2 && !wcscmp(argv[1], L"run"))
        return Run();
    printf("usage: smbengacl run\n");
    return 2;
}
