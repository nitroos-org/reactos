/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The pipe of an RPC endpoint: the first instance is made as the first instance, a name another user
 *              made first is not joined, and the SecurityDescriptor of RpcServerUseProtseqEp is the pipe's
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Documentation (RpcServerUseProtseqEp): "SecurityDescriptor: pointer to a SECURITY_DESCRIPTOR ... if NULL the
 * system default"; RPC_S_DUPLICATE_ENDPOINT "the endpoint is a duplicate"; RPC_S_INVALID_SECURITY_DESC "security
 * descriptor is invalid". CreateNamedPipe with FILE_FLAG_FIRST_PIPE_INSTANCE fails with ERROR_ACCESS_DENIED when
 * the name exists.
 */

#include <apitest.h>
#include <windows.h>
#include <rpc.h>
#include <lm.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>

static WCHAR UserName[] = L"rpcsqtest";
static WCHAR Password[] = L"Rpc-Squat-Test-2026!";

static HANDLE LogonScratchUser(void)
{
    USER_INFO_1 Info = { 0 };
    HANDLE Token = NULL;
    DWORD Err;

    NetUserDel(NULL, UserName);
    Info.usri1_name = UserName;
    Info.usri1_password = Password;
    Info.usri1_priv = USER_PRIV_USER;
    Info.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    Err = NetUserAdd(NULL, 1, (LPBYTE)&Info, NULL);
    if (Err != NERR_Success)
    {
        skip("NetUserAdd failed %lu\n", Err);
        return NULL;
    }
    if (!LogonUserW(UserName, L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token) &&
        !LogonUserW(UserName, L".", Password, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        skip("LogonUser failed %lu\n", GetLastError());
        NetUserDel(NULL, UserName);
        return NULL;
    }
    return Token;
}

static HANDLE CreatePipeAs(HANDLE Token, PCWSTR Name)
{
    HANDLE Pipe = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    PSECURITY_DESCRIPTOR Sd = NULL;

    /* Everybody may open it: the squatter wants clients */
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &Sd, NULL);
    Sa.lpSecurityDescriptor = Sd;
    if (!Token || ImpersonateLoggedOnUser(Token))
    {
        Pipe = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
                                PIPE_UNLIMITED_INSTANCES, 4096, 4096, 5000, &Sa);
        if (Token)
            RevertToSelf();
    }
    LocalFree(Sd);
    return Pipe;
}

static RPC_STATUS UseEndpoint(PCWSTR Endpoint, PVOID Descriptor)
{
    return RpcServerUseProtseqEpW((RPC_WSTR)L"ncacn_np", 5, (RPC_WSTR)Endpoint, Descriptor);
}

START_TEST(FirstPipeInstance)
{
    HANDLE Token, Squatter, Probe;
    RPC_STATUS Status;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    PSECURITY_DESCRIPTOR PipeSd = NULL;
    BOOL Present = FALSE, Defaulted = FALSE;
    SECURITY_DESCRIPTOR Garbage;

    /* A pipe that nobody made: the endpoint makes it, a second registration in this process is the same endpoint */
    Status = UseEndpoint(L"\\pipe\\rpcfpi1", NULL);
    ok(Status == RPC_S_OK, "first registration: %ld\n", Status);
    Probe = CreateFileW(L"\\\\.\\pipe\\rpcfpi1", READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(Probe != INVALID_HANDLE_VALUE, "the endpoint's pipe is not there: %lu\n", GetLastError());
    if (Probe != INVALID_HANDLE_VALUE)
        CloseHandle(Probe);
    Status = UseEndpoint(L"\\pipe\\rpcfpi1", NULL);
    ok(Status == RPC_S_OK, "second registration of the same endpoint: %ld\n", Status);

    /* A pipe of this (trusted: SYSTEM or administrator) process is shared by a server, as the plug and play server
     * shares \pipe\ntsvcs with the service controller */
    Squatter = CreatePipeAs(NULL, L"\\\\.\\pipe\\rpcfpi2");
    ok(Squatter != INVALID_HANDLE_VALUE, "CreateNamedPipe failed %lu\n", GetLastError());
    Status = UseEndpoint(L"\\pipe\\rpcfpi2", NULL);
    ok(Status == RPC_S_OK, "a pipe of an administrator exists: %ld\n", Status);
    if (Squatter != INVALID_HANDLE_VALUE)
        CloseHandle(Squatter);

    /* A pipe a standard user made first: not joined */
    Token = LogonScratchUser();
    if (Token)
    {
        Squatter = CreatePipeAs(Token, L"\\\\.\\pipe\\rpcfpi3");
        ok(Squatter != INVALID_HANDLE_VALUE, "the standard user could not create a pipe: %lu\n", GetLastError());
        if (Squatter != INVALID_HANDLE_VALUE)
        {
            Status = UseEndpoint(L"\\pipe\\rpcfpi3", NULL);
            ok(Status == RPC_S_DUPLICATE_ENDPOINT, "a pipe of a standard user exists: %ld, expected %d\n", Status, RPC_S_DUPLICATE_ENDPOINT);
            CloseHandle(Squatter);
        }
        CloseHandle(Token);
        NetUserDel(NULL, UserName);
    }

    /* The descriptor of the endpoint is the pipe's: one entry, the Administrators */
    ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;GA;;;BA)", SDDL_REVISION_1, &Sd, NULL);
    Status = UseEndpoint(L"\\pipe\\rpcfpi4", Sd);
    ok(Status == RPC_S_OK, "registration with a descriptor: %ld\n", Status);
    Probe = CreateFileW(L"\\\\.\\pipe\\rpcfpi4", READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                        SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
    ok(Probe != INVALID_HANDLE_VALUE, "the endpoint's pipe is not there: %lu\n", GetLastError());
    if (Probe != INVALID_HANDLE_VALUE)
    {
        DWORD Err = GetSecurityInfo(Probe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &PipeSd);
        ok(Err == ERROR_SUCCESS, "GetSecurityInfo failed %lu\n", Err);
        if (Err == ERROR_SUCCESS)
        {
            ok(Dacl != NULL && Dacl->AceCount == 1, "the pipe has %u entries, expected the 1 of the descriptor\n", Dacl ? Dacl->AceCount : 0);
            if (Dacl && Dacl->AceCount == 1)
            {
                PACCESS_ALLOWED_ACE Ace;
                PWSTR Text = NULL;

                GetAce(Dacl, 0, (PVOID *)&Ace);
                if (ConvertSidToStringSidW((PSID)&Ace->SidStart, &Text))
                {
                    ok(!wcscmp(Text, L"S-1-5-32-544"), "the entry is for %ls\n", Text);
                    LocalFree(Text);
                }
            }
            LocalFree(PipeSd);
        }
        CloseHandle(Probe);
    }
    LocalFree(Sd);

    /* A descriptor that is none */
    memset(&Garbage, 0xAA, sizeof(Garbage));
    Status = UseEndpoint(L"\\pipe\\rpcfpi5", &Garbage);
    ok(Status == RPC_S_INVALID_SECURITY_DESC, "a garbage descriptor: %ld, expected %d\n", Status, RPC_S_INVALID_SECURITY_DESC);
    (void)Present; (void)Defaulted;
}
