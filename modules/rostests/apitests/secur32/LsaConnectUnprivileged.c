/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LsaConnectUntrusted needs no privilege: a standard user, who is in no administrator group, gets a
 *              connection to the authentication port of the local security authority and can look up a package
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define WIN32_NO_STATUS
#include <apitest.h>
#include <ntstatus.h>
#include <ntsecapi.h>
#include <lmaccess.h>
#include <lmerr.h>
#include <stdio.h>

#define TEST_PASSWORD L"Lsa#Port1pw"

static NTSTATUS ConnectAndLookup(void)
{
    HANDLE LsaHandle = NULL;
    LSA_STRING Name;
    ULONG Package;
    NTSTATUS Status;

    Status = LsaConnectUntrusted(&LsaHandle);
    if (Status != STATUS_SUCCESS)
        return Status;
    Name.Buffer = MSV1_0_PACKAGE_NAME;
    Name.Length = sizeof(MSV1_0_PACKAGE_NAME) - sizeof(CHAR);
    Name.MaximumLength = sizeof(MSV1_0_PACKAGE_NAME);
    Status = LsaLookupAuthenticationPackage(LsaHandle, &Name, &Package);
    LsaDeregisterLogonProcess(LsaHandle);
    return Status;
}

START_TEST(LsaConnectUnprivileged)
{
    WCHAR User[32];
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;
    HANDLE token = NULL;
    NTSTATUS Status;

    /* the caller itself (an administrator in the test runs) */
    Status = ConnectAndLookup();
    ok_ntstatus(Status, STATUS_SUCCESS);

    _snwprintf(User, ARRAYSIZE(User), L"lsaport%lu", GetCurrentProcessId() % 100000);
    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = User;
    ui.usri1_password = (LPWSTR)TEST_PASSWORD;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &err);
    if (st != NERR_Success)
    {
        skip("NetUserAdd failed (%lu)\n", (unsigned long)st);
        return;
    }

    if (!LogonUserW(User, L".", TEST_PASSWORD, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &token))
    {
        skip("LogonUser failed (%lu)\n", GetLastError());
    }
    else if (!ImpersonateLoggedOnUser(token))
    {
        skip("ImpersonateLoggedOnUser failed (%lu)\n", GetLastError());
    }
    else
    {
        Status = ConnectAndLookup();
        RevertToSelf();
        ok_ntstatus(Status, STATUS_SUCCESS);
    }

    if (token)
        CloseHandle(token);
    NetUserDel(NULL, User);
}
