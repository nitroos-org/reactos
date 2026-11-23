/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The LSA authentication port survives clients that end while they are served, and releases the
 *              connections of clients that end
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <lm.h>
#include <ntsecapi.h>
#include <ndk/exfuncs.h>

/*
 * Contract 1: a client process that ends while lsass serves its request (its logon in progress, a reply that
 * can no longer be delivered, a request it withdraws) does not stop the LSA from serving the others.
 * Contract 2: a connection made without a logon context (secur32 makes one per process for
 * LsaEnumerateLogonSessions) is released when its process ends: lsass does not keep a handle per process.
 */

typedef NTSTATUS (NTAPI *LSACONNECTUNTRUSTED)(PHANDLE);
typedef NTSTATUS (NTAPI *LSADEREGISTERLOGONPROCESS)(HANDLE);
typedef NTSTATUS (NTAPI *LSALOOKUPAUTHENTICATIONPACKAGE)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (NTAPI *LSAENUMERATELOGONSESSIONS)(PULONG, PLUID *);
typedef NTSTATUS (NTAPI *LSAFREERETURNBUFFER)(PVOID);

static LSACONNECTUNTRUSTED pLsaConnectUntrusted;
static LSADEREGISTERLOGONPROCESS pLsaDeregisterLogonProcess;
static LSALOOKUPAUTHENTICATIONPACKAGE pLsaLookupAuthenticationPackage;
static LSAENUMERATELOGONSESSIONS pLsaEnumerateLogonSessions;
static LSAFREERETURNBUFFER pLsaFreeReturnBuffer;

static WCHAR TestUser[] = L"lsaportclient";
static WCHAR TestPassword[] = L"Lsa-Port-Client-2026!";

static BOOL
LoadSecur32(VOID)
{
    HMODULE hSecur32 = LoadLibraryW(L"secur32.dll");

    if (!hSecur32)
        return FALSE;
    pLsaConnectUntrusted = (LSACONNECTUNTRUSTED)GetProcAddress(hSecur32, "LsaConnectUntrusted");
    pLsaDeregisterLogonProcess = (LSADEREGISTERLOGONPROCESS)GetProcAddress(hSecur32, "LsaDeregisterLogonProcess");
    pLsaLookupAuthenticationPackage = (LSALOOKUPAUTHENTICATIONPACKAGE)GetProcAddress(hSecur32, "LsaLookupAuthenticationPackage");
    pLsaEnumerateLogonSessions = (LSAENUMERATELOGONSESSIONS)GetProcAddress(hSecur32, "LsaEnumerateLogonSessions");
    pLsaFreeReturnBuffer = (LSAFREERETURNBUFFER)GetProcAddress(hSecur32, "LsaFreeReturnBuffer");
    return pLsaConnectUntrusted && pLsaDeregisterLogonProcess && pLsaLookupAuthenticationPackage &&
           pLsaEnumerateLogonSessions && pLsaFreeReturnBuffer;
}

/* lsass' process id and handle count */
static BOOL
GetLsass(PULONG ProcessId, PULONG HandleCount)
{
    ULONG Length = 0x40000, Returned;
    PVOID Buffer;
    PSYSTEM_PROCESS_INFORMATION Process;
    NTSTATUS Status;
    BOOL Found = FALSE;

    for (;;)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Length);
        if (!Buffer)
            return FALSE;
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Length, &Returned);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        HeapFree(GetProcessHeap(), 0, Buffer);
        Length *= 2;
    }

    if (NT_SUCCESS(Status))
    {
        Process = Buffer;
        for (;;)
        {
            if (Process->ImageName.Buffer &&
                !_wcsnicmp(Process->ImageName.Buffer, L"lsass.exe", Process->ImageName.Length / sizeof(WCHAR)))
            {
                *ProcessId = HandleToUlong(Process->UniqueProcessId);
                *HandleCount = Process->HandleCount;
                Found = TRUE;
            }
            if (!Process->NextEntryOffset)
                break;
            Process = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Process + Process->NextEntryOffset);
        }
    }

    HeapFree(GetProcessHeap(), 0, Buffer);
    return Found;
}

/* The client: logons (right and wrong password) and lookups from several threads, until it is ended */
static DWORD WINAPI
ClientThread(LPVOID Param)
{
    HANDLE Lsa = NULL, Token;
    LSA_STRING Name;
    ULONG Package, i;

    pLsaConnectUntrusted(&Lsa);
    RtlInitString((PSTRING)&Name, MSV1_0_PACKAGE_NAME);
    for (i = 0; ; i++)
    {
        pLsaLookupAuthenticationPackage(Lsa, &Name, &Package);
        if (LogonUserW(TestUser, L".", (i % 2) ? TestPassword : L"wrong", LOGON32_LOGON_INTERACTIVE,
                       LOGON32_PROVIDER_DEFAULT, &Token))
            CloseHandle(Token);
    }
    return 0;
}

static VOID
Client(VOID)
{
    ULONG i;

    for (i = 0; i < 4; i++)
        CreateThread(NULL, 0, ClientThread, NULL, 0, NULL);
    Sleep(INFINITE);
}

static VOID
EnumClient(VOID)
{
    ULONG Count = 0;
    PLUID List = NULL;

    if (pLsaEnumerateLogonSessions(&Count, &List) == STATUS_SUCCESS)
        pLsaFreeReturnBuffer(List);
}

static BOOL
StartChild(PCSTR Mode, PPROCESS_INFORMATION ProcessInfo)
{
    CHAR FileName[MAX_PATH], Command[MAX_PATH + 64];
    STARTUPINFOA StartupInfo = { sizeof(StartupInfo) };

    GetModuleFileNameA(NULL, FileName, _countof(FileName));
    StringCbPrintfA(Command, sizeof(Command), "\"%s\" LsaPortClients %s", FileName, Mode);
    return CreateProcessA(NULL, Command, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, ProcessInfo);
}

START_TEST(LsaPortClients)
{
    USER_INFO_1 UserInfo = { 0 };
    PROCESS_INFORMATION ProcessInfo;
    ULONG Pid0 = 0, Pid = 0, Handles0 = 0, Handles1 = 0, Handles2 = 0, i;
    HANDLE Lsa = NULL, Token = NULL;
    LSA_STRING Name;
    ULONG Package = 0;
    NTSTATUS Status;
    DWORD Error;
    int argc;
    char **argv;

    if (!LoadSecur32())
    {
        skip("secur32 functions not found\n");
        return;
    }

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "client"))
    {
        Client();
        return;
    }
    if (argc >= 3 && !strcmp(argv[2], "enum"))
    {
        EnumClient();
        return;
    }

    UserInfo.usri1_name = TestUser;
    UserInfo.usri1_password = TestPassword;
    UserInfo.usri1_priv = USER_PRIV_USER;
    UserInfo.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    Error = NetUserAdd(NULL, 1, (LPBYTE)&UserInfo, NULL);
    if (Error != NERR_Success && Error != NERR_UserExists)
    {
        skip("NetUserAdd failed with %lu\n", Error);
        return;
    }

    ok(GetLsass(&Pid0, &Handles0), "lsass not found\n");

    /* 1: clients that are ended while they are served */
    for (i = 0; i < 30; i++)
    {
        if (!StartChild("client", &ProcessInfo))
        {
            ok(0, "CreateProcess failed with %lu\n", GetLastError());
            break;
        }
        Sleep(40 + (i * 37) % 300);
        TerminateProcess(ProcessInfo.hProcess, 1);
        WaitForSingleObject(ProcessInfo.hProcess, 30000);
        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);
    }
    Sleep(1000);

    ok(GetLsass(&Pid, &Handles1), "lsass not found after the clients ended\n");
    ok(Pid == Pid0, "lsass is process %lu, was %lu\n", Pid, Pid0);
    Status = pLsaConnectUntrusted(&Lsa);
    ok(Status == STATUS_SUCCESS, "LsaConnectUntrusted returned 0x%08lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        RtlInitString((PSTRING)&Name, MSV1_0_PACKAGE_NAME);
        Status = pLsaLookupAuthenticationPackage(Lsa, &Name, &Package);
        ok(Status == STATUS_SUCCESS, "LsaLookupAuthenticationPackage returned 0x%08lx\n", Status);
        pLsaDeregisterLogonProcess(Lsa);
    }
    ok(LogonUserW(TestUser, L".", TestPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token),
       "LogonUserW failed with %lu\n", GetLastError());
    if (Token)
        CloseHandle(Token);

    /* 2: processes that each made a connection without a logon context, then ended */
    GetLsass(&Pid, &Handles1);
    for (i = 0; i < 40; i++)
    {
        if (!StartChild("enum", &ProcessInfo))
        {
            ok(0, "CreateProcess failed with %lu\n", GetLastError());
            break;
        }
        WaitForSingleObject(ProcessInfo.hProcess, 30000);
        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);
    }
    Sleep(1000);
    ok(GetLsass(&Pid, &Handles2), "lsass not found\n");
    /* idle RPC threads of lsass come and go: a few handles either way */
    ok(Handles2 < Handles1 + 20, "lsass had %lu handles, %lu after 40 processes used LsaEnumerateLogonSessions\n",
       Handles1, Handles2);
    trace("lsass handles: %lu at the start, %lu, %lu\n", Handles0, Handles1, Handles2);

    NetUserDel(NULL, TestUser);
}
