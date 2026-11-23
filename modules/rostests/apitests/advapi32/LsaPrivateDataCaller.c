/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LsaRetrievePrivateData and LsaStorePrivateData are decided by the caller's token, not by the
 *              access of the policy handle: an elevated administrator may use them through a handle opened with
 *              any access (even none), an administrator whose token is not elevated and a standard user are
 *              refused through every handle they can open; the value of a machine secret ("M$") is never
 *              returned
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected statuses were measured on Windows Server 2022 (build 20348) with the same three callers.
 * Run as an elevated administrator. The scratch user and secrets are made up and removed by the test; the
 * password and the values are made at run time and never printed.
 */

#include "precomp.h"
#include <ntsecapi.h>
#include <lmaccess.h>
#include <lmerr.h>

#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#endif

static const WCHAR UserName[] = L"lpdcstd";
static WCHAR Password[24];

static const struct { PCSTR Name; ACCESS_MASK Mask; } Handles[] =
{
    { "none(0)",              0 },
    { "VIEW_LOCAL_INFO",      POLICY_VIEW_LOCAL_INFORMATION },
    { "GET_PRIVATE_INFO",     POLICY_GET_PRIVATE_INFORMATION },
    { "TRUST_ADMIN",          POLICY_TRUST_ADMIN },
    { "CREATE_SECRET",        POLICY_CREATE_SECRET },
    { "LOOKUP_NAMES",         POLICY_LOOKUP_NAMES },
    { "READ_CONTROL",         READ_CONTROL },
    { "MAXIMUM_ALLOWED",      MAXIMUM_ALLOWED },
    { "POLICY_ALL_ACCESS",    POLICY_ALL_ACCESS },
};

static const PCWSTR Existing[] = { L"LpdcPlain", L"L$LpdcLocal", L"G$LpdcGlobal", L"M$LpdcMachine" };

static VOID InitString(PLSA_UNICODE_STRING String, PCWSTR Text)
{
    String->Buffer = (PWSTR)Text;
    String->Length = (USHORT)(wcslen(Text) * sizeof(WCHAR));
    String->MaximumLength = String->Length + sizeof(WCHAR);
}

static NTSTATUS OpenPolicyH(ACCESS_MASK Access, PLSA_HANDLE Policy)
{
    LSA_OBJECT_ATTRIBUTES Attributes = {0};

    *Policy = NULL;
    return LsaOpenPolicy(NULL, &Attributes, Access, Policy);
}

static NTSTATUS StoreAs(LSA_HANDLE Policy, PCWSTR Name, BOOL Delete)
{
    LSA_UNICODE_STRING Key, Data;
    WCHAR Value[] = L"lpdc-value";

    InitString(&Key, Name);
    InitString(&Data, Value);
    return LsaStorePrivateData(Policy, &Key, Delete ? NULL : &Data);
}

static NTSTATUS RetrieveAs(LSA_HANDLE Policy, PCWSTR Name)
{
    LSA_UNICODE_STRING Key;
    PLSA_UNICODE_STRING Data = NULL;
    NTSTATUS Status;

    InitString(&Key, Name);
    Status = LsaRetrievePrivateData(Policy, &Key, &Data);
    if (NT_SUCCESS(Status) && Data)
        LsaFreeMemory(Data);
    return Status;
}

/*
 * One caller (the thread's present identity): every handle it can open, every secret.
 * Elevated: success except the machine secret (denied) and a name that does not exist (not found).
 * Others: STATUS_ACCESS_DENIED for everything, including the names that do not exist.
 */
static VOID RunRows(PCSTR Caller, BOOL Elevated)
{
    ULONG h, s;
    ULONG Opened = 0;

    for (h = 0; h < RTL_NUMBER_OF(Handles); h++)
    {
        LSA_HANDLE Policy;
        NTSTATUS Status = OpenPolicyH(Handles[h].Mask, &Policy);
        WCHAR Fresh[32];
        NTSTATUS St;

        if (!NT_SUCCESS(Status))
        {
            ok(!Elevated, "%s: LsaOpenPolicy(%s) 0x%08lx\n", Caller, Handles[h].Name, Status);
            continue;
        }
        Opened++;

        for (s = 0; s < RTL_NUMBER_OF(Existing); s++)
        {
            NTSTATUS Expected = !Elevated ? STATUS_ACCESS_DENIED :
                                (s == 3 ? STATUS_ACCESS_DENIED : STATUS_SUCCESS);

            St = RetrieveAs(Policy, Existing[s]);
            ok(St == Expected, "%s, handle %s: retrieve %ls 0x%08lx, expected 0x%08lx\n",
               Caller, Handles[h].Name, Existing[s], St, Expected);
            St = StoreAs(Policy, Existing[s], FALSE);
            Expected = Elevated ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
            ok(St == Expected, "%s, handle %s: store %ls 0x%08lx, expected 0x%08lx\n",
               Caller, Handles[h].Name, Existing[s], St, Expected);
        }

        /* A name that does not exist: not found for the elevated administrator, denied for the others; a store creates it */
        StringCchPrintfW(Fresh, RTL_NUMBER_OF(Fresh), L"LpdcNone%lu", h);
        St = RetrieveAs(Policy, Fresh);
        ok(St == (Elevated ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_ACCESS_DENIED),
           "%s, handle %s: retrieve of a missing name 0x%08lx\n", Caller, Handles[h].Name, St);
        St = StoreAs(Policy, Fresh, FALSE);
        ok(St == (Elevated ? STATUS_SUCCESS : STATUS_ACCESS_DENIED),
           "%s, handle %s: store of a new name 0x%08lx\n", Caller, Handles[h].Name, St);
        if (Elevated)
        {
            St = RetrieveAs(Policy, Fresh);
            ok(St == STATUS_SUCCESS, "%s, handle %s: retrieve after the store 0x%08lx\n", Caller, Handles[h].Name, St);
            St = StoreAs(Policy, Fresh, TRUE);
            ok(St == STATUS_SUCCESS, "%s, handle %s: delete 0x%08lx\n", Caller, Handles[h].Name, St);
        }
        LsaClose(Policy);
    }
    ok(Opened >= 2, "%s: only %lu handles could be opened\n", Caller, Opened);
}

static BOOL ElevatedAdmin(HANDLE Token)
{
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    DWORD Len = sizeof(Sid);
    BOOL Member = FALSE;

    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Sid, &Len))
        return FALSE;
    return CheckTokenMembership(Token, Sid, &Member) && Member;
}

START_TEST(LsaPrivateDataCaller)
{
    USER_INFO_1 User = {0};
    HANDLE Restricted = NULL, StdToken = NULL;
    SID_AND_ATTRIBUTES Admins;
    BYTE AdminSid[SECURITY_MAX_SID_SIZE];
    DWORD Len = sizeof(AdminSid), Pe, i;
    LSA_HANDLE Policy;
    BYTE Random[16];
    NTSTATUS Status;

    if (!ElevatedAdmin(NULL))
    {
        skip("must run as an elevated administrator\n");
        return;
    }

    /* A random password; never printed */
    RtlGenRandom(Random, sizeof(Random));
    for (i = 0; i < 16; i++)
        Password[i] = L'a' + (Random[i] & 15);
    Password[16] = L'A'; Password[17] = L'#'; Password[18] = L'7'; Password[19] = 0;

    NetUserDel(NULL, (LPWSTR)UserName);
    User.usri1_name = (LPWSTR)UserName;
    User.usri1_password = Password;
    User.usri1_priv = USER_PRIV_USER;
    User.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    ok(NetUserAdd(NULL, 1, (PBYTE)&User, &Pe) == NERR_Success, "NetUserAdd failed\n");

    /* The secrets that exist before the callers run */
    Status = OpenPolicyH(POLICY_ALL_ACCESS, &Policy);
    ok(NT_SUCCESS(Status), "LsaOpenPolicy(all) 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
        goto cleanup;
    for (i = 0; i < RTL_NUMBER_OF(Existing); i++)
        ok(StoreAs(Policy, Existing[i], FALSE) == STATUS_SUCCESS, "setup of %ls failed\n", Existing[i]);
    LsaClose(Policy);

    /* 1: the elevated administrator (this process) */
    RunRows("elevated administrator", TRUE);

    /* 2: the same administrator with the Administrators group deny-only and the privileges removed */
    CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminSid, &Len);
    Admins.Sid = AdminSid;
    Admins.Attributes = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &StdToken) &&
        CreateRestrictedToken(StdToken, DISABLE_MAX_PRIVILEGE, 1, &Admins, 0, NULL, 0, NULL, &Restricted))
    {
        ok(!ElevatedAdmin(Restricted), "the filtered token is still an administrator\n");
        if (ImpersonateLoggedOnUser(Restricted))
        {
            RunRows("administrator, not elevated", FALSE);
            RevertToSelf();
        }
        else
            skip("cannot impersonate the filtered token (%lu)\n", GetLastError());
        CloseHandle(Restricted);
    }
    else
        skip("cannot make a filtered token (%lu)\n", GetLastError());
    if (StdToken)
        CloseHandle(StdToken);

    /* 3: a standard user */
    StdToken = NULL;
    if (LogonUserW((LPWSTR)UserName, (LPWSTR)L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &StdToken))
    {
        if (ImpersonateLoggedOnUser(StdToken))
        {
            RunRows("standard user", FALSE);
            RevertToSelf();
        }
        else
            skip("cannot impersonate the standard user (%lu)\n", GetLastError());
        CloseHandle(StdToken);
    }
    else
        skip("LogonUser of the scratch user failed (%lu)\n", GetLastError());

cleanup:
    if (NT_SUCCESS(OpenPolicyH(POLICY_ALL_ACCESS, &Policy)))
    {
        for (i = 0; i < RTL_NUMBER_OF(Existing); i++)
            StoreAs(Policy, Existing[i], TRUE);
        LsaClose(Policy);
    }
    NetUserDel(NULL, (LPWSTR)UserName);
    SecureZeroMemory(Password, sizeof(Password));
}
