/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     OpenThreadToken on an impersonating thread does not leak handles or token objects,
 *              with OpenAsSelf both ways and for both kinds of impersonation (SetThreadToken,
 *              and a named pipe client, whose token the thread opens copy-on-open)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/obtypes.h>
#include <lm.h>
#include <ndk/umtypes.h>
#include <ndk/obfuncs.h>

#define WARMUP      200
#define CYCLES      20000
/* ACCESS_SYSTEM_SECURITY needs SeSecurityPrivilege, enabled or not: the open fails after the token was copied */
#define DENIED_ACCESS   (TOKEN_QUERY | ACCESS_SYSTEM_SECURITY)
#define SLACK       16

/* Live Token objects according to the object manager's type statistics; FALSE if unreadable */
static BOOL QueryTokenObjects(PLONG Objects)
{
    ULONG Size = 0x20000, Length = 0, Count, i;
    PUCHAR Buffer, Entry;
    NTSTATUS Status;
    BOOL Found = FALSE;

    Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Buffer)
        return FALSE;
    Status = NtQueryObject(NULL, ObjectTypesInformation, Buffer, Size, &Length);
    if (NT_SUCCESS(Status))
    {
        Count = *(PULONG)Buffer;
        Entry = Buffer + sizeof(ULONG_PTR);
        for (i = 0; i < Count; i++)
        {
            POBJECT_TYPE_INFORMATION Info = (POBJECT_TYPE_INFORMATION)Entry;

            if (Info->TypeName.Length == 5 * sizeof(WCHAR) && !_wcsnicmp(Info->TypeName.Buffer, L"Token", 5))
            {
                *Objects = (LONG)Info->TotalNumberOfObjects;
                Found = TRUE;
                break;
            }
            Entry = (PUCHAR)(((ULONG_PTR)Info->TypeName.Buffer + Info->TypeName.MaximumLength +
                              sizeof(ULONG_PTR) - 1) & ~(ULONG_PTR)(sizeof(ULONG_PTR) - 1));
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return Found;
}

static LONG ProcessHandles(void)
{
    DWORD Count = 0;

    GetProcessHandleCount(GetCurrentProcess(), &Count);
    return (LONG)Count;
}

/* Informational: whether two opens return the same token (a copy-on-open thread copies each time) */
static void ObserveTokenIds(PCSTR What, BOOL OpenAsSelf)
{
    TOKEN_STATISTICS Stats1, Stats2;
    HANDLE hToken1, hToken2;
    DWORD Size;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, OpenAsSelf, &hToken1))
        return;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, OpenAsSelf, &hToken2))
    {
        if (GetTokenInformation(hToken1, TokenStatistics, &Stats1, sizeof(Stats1), &Size) &&
            GetTokenInformation(hToken2, TokenStatistics, &Stats2, sizeof(Stats2), &Size))
        {
            trace("%s, OpenAsSelf %d: two opens return TokenId %08lx:%08lx and %08lx:%08lx\n", What, OpenAsSelf,
                  Stats1.TokenId.HighPart, Stats1.TokenId.LowPart, Stats2.TokenId.HighPart, Stats2.TokenId.LowPart);
        }
        CloseHandle(hToken2);
    }
    CloseHandle(hToken1);
}

static void RunLoop(PCSTR What, BOOL OpenAsSelf, ACCESS_MASK Access)
{
    ULONG Cycles = CYCLES;
    PCSTR Env = getenv("OTL_CYCLES");
    LONG HandlesBefore, HandlesAfter, ObjectsBefore = 0, ObjectsAfter = 0;
    BOOL HaveObjects;
    HANDLE hToken;
    ULONG i;

    if (Env && atol(Env) > 0)
        Cycles = atol(Env);
    /* every failed open prints in a checked kernel: fewer of those */
    if (Access == DENIED_ACCESS)
        Cycles = (Cycles + 19) / 20;
    for (i = 0; i < WARMUP; i++)
    {
        if (OpenThreadToken(GetCurrentThread(), Access, OpenAsSelf, &hToken))
            CloseHandle(hToken);
    }

    if (Access == TOKEN_QUERY)
        ObserveTokenIds(What, OpenAsSelf);
    if (OpenThreadToken(GetCurrentThread(), Access, OpenAsSelf, &hToken))
    {
        trace("%s, OpenAsSelf %d, access 0x%lx: opens\n", What, OpenAsSelf, (ULONG)Access);
        CloseHandle(hToken);
    }
    else
    {
        trace("%s, OpenAsSelf %d, access 0x%lx: fails with %lu\n", What, OpenAsSelf, (ULONG)Access, GetLastError());
    }

    HandlesBefore = ProcessHandles();
    HaveObjects = QueryTokenObjects(&ObjectsBefore);

    for (i = 0; i < Cycles; i++)
    {
        if (!OpenThreadToken(GetCurrentThread(), Access, OpenAsSelf, &hToken))
        {
            if (Access == DENIED_ACCESS && GetLastError() == ERROR_PRIVILEGE_NOT_HELD)
                continue;
            if (Access == DENIED_ACCESS && GetLastError() == ERROR_ACCESS_DENIED)
                continue;
            ok(0, "%s: OpenThreadToken(OpenAsSelf %d) failed, error %lu\n", What, OpenAsSelf, GetLastError());
            return;
        }
        CloseHandle(hToken);
    }

    HandlesAfter = ProcessHandles();
    ok(HandlesAfter - HandlesBefore <= SLACK, "%s, OpenAsSelf %d, access 0x%lx: process handles %ld -> %ld over %lu calls\n",
       What, OpenAsSelf, (ULONG)Access, HandlesBefore, HandlesAfter, Cycles);

    if (HaveObjects && QueryTokenObjects(&ObjectsAfter))
    {
        ok(ObjectsAfter - ObjectsBefore <= SLACK, "%s, OpenAsSelf %d, access 0x%lx: Token objects %ld -> %ld over %lu calls\n",
           What, OpenAsSelf, (ULONG)Access, ObjectsBefore, ObjectsAfter, Cycles);
    }
    else
    {
        skip("%s: token object counts are not available\n", What);
    }
}

/* The thread impersonates a token with SetThreadToken: no copy on open */
static void TestSetThreadToken(void)
{
    HANDLE hProcessToken, hImpersonation;
    BOOL Success;

    Success = OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hProcessToken);
    ok(Success, "OpenProcessToken failed, error %lu\n", GetLastError());
    if (!Success)
        return;
    Success = DuplicateTokenEx(hProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
                               TokenImpersonation, &hImpersonation);
    ok(Success, "DuplicateTokenEx failed, error %lu\n", GetLastError());
    CloseHandle(hProcessToken);
    if (!Success)
        return;

    Success = SetThreadToken(NULL, hImpersonation);
    ok(Success, "SetThreadToken failed, error %lu\n", GetLastError());
    if (Success)
    {
        RunLoop("SetThreadToken", TRUE, TOKEN_QUERY);
        RunLoop("SetThreadToken", FALSE, TOKEN_QUERY);
        RunLoop("SetThreadToken denied", TRUE, DENIED_ACCESS);
        RunLoop("SetThreadToken denied", FALSE, DENIED_ACCESS);
        RevertToSelf();
    }
    CloseHandle(hImpersonation);
}

/* The thread impersonates a named pipe client: the token is opened copy-on-open.
 * With hUser the client connects while impersonating that user's token. */
static void TestPipeClient(PCSTR What, HANDLE hUser)
{
    WCHAR PipeName[MAX_PATH];
    HANDLE hServer, hClient;
    DWORD Done;
    CHAR Byte = 'x';
    LONG ObjectsBefore = 0, ObjectsAfter = 0;
    BOOL Success, HaveObjects;

    SECURITY_DESCRIPTOR Sd;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), &Sd, FALSE };

    /* A NULL DACL: the other user must be able to connect */
    InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&Sd, TRUE, NULL, FALSE);
    StringCchPrintfW(PipeName, _countof(PipeName), L"\\\\.\\pipe\\rostest_otl_%lu", GetCurrentProcessId());
    hServer = CreateNamedPipeW(PipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                               1, 64, 64, 0, &Sa);
    ok(hServer != INVALID_HANDLE_VALUE, "CreateNamedPipeW failed, error %lu\n", GetLastError());
    if (hServer == INVALID_HANDLE_VALUE)
        return;
    if (hUser && !ImpersonateLoggedOnUser(hUser))
    {
        ok(0, "%s: ImpersonateLoggedOnUser failed, error %lu\n", What, GetLastError());
        CloseHandle(hServer);
        return;
    }
    hClient = CreateFileW(PipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                          SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, NULL);
    if (hUser)
        RevertToSelf();
    ok(hClient != INVALID_HANDLE_VALUE, "%s: CreateFileW failed, error %lu\n", What, GetLastError());
    if (hClient == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hServer);
        return;
    }
    Success = ConnectNamedPipe(hServer, NULL) || GetLastError() == ERROR_PIPE_CONNECTED;
    ok(Success, "ConnectNamedPipe failed, error %lu\n", GetLastError());
    Success = Success && WriteFile(hClient, &Byte, 1, &Done, NULL) && ReadFile(hServer, &Byte, 1, &Done, NULL);
    ok(Success, "pipe transfer failed, error %lu\n", GetLastError());

    HaveObjects = QueryTokenObjects(&ObjectsBefore);
    if (Success && ImpersonateNamedPipeClient(hServer))
    {
        RunLoop(What, TRUE, TOKEN_QUERY);
        RunLoop(What, FALSE, TOKEN_QUERY);
        RunLoop(What, TRUE, DENIED_ACCESS);
        RunLoop(What, FALSE, DENIED_ACCESS);
        RevertToSelf();
    }
    else if (Success)
    {
        ok(0, "%s: ImpersonateNamedPipeClient failed, error %lu\n", What, GetLastError());
    }
    CloseHandle(hClient);
    CloseHandle(hServer);

    /* After the impersonation ends and the pipe is gone every copy made is gone */
    if (HaveObjects && QueryTokenObjects(&ObjectsAfter))
        ok(ObjectsAfter - ObjectsBefore <= SLACK, "%s: Token objects %ld -> %ld after the pipe closed\n",
           What, ObjectsBefore, ObjectsAfter);
}

/* A token of another user than the caller's */
static void TestOtherUser(void)
{
    static WCHAR Password[] = L"Open-Thread-Token-2026!";
    WCHAR Name[32];
    USER_INFO_1 Info;
    HANDLE hUser = NULL;
    DWORD Err, Try;
    NET_API_STATUS Net = NERR_UserExists;

    for (Try = 0; Try < 5 && Net == NERR_UserExists; Try++)
    {
        StringCchPrintfW(Name, _countof(Name), L"otltest%lx", (GetTickCount() + Try * 7919) & 0xffffff);
        ZeroMemory(&Info, sizeof(Info));
        Info.usri1_name = Name;
        Info.usri1_password = Password;
        Info.usri1_priv = USER_PRIV_USER;
        Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
        Net = NetUserAdd(NULL, 1, (PBYTE)&Info, &Err);
    }
    if (Net != NERR_Success)
    {
        skip("NetUserAdd failed, status %lu\n", Net);
        return;
    }
    if (LogonUserW(Name, L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hUser))
    {
        TestPipeClient("pipe client, other user", hUser);
        CloseHandle(hUser);
    }
    else
    {
        skip("LogonUserW failed, error %lu\n", GetLastError());
    }
    NetUserDel(NULL, Name);
}

START_TEST(OpenThreadTokenLeak)
{
    TestSetThreadToken();
    TestPipeClient("pipe client", NULL);
    TestOtherUser();
}
