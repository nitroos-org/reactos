/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     What a thread running as a restricted token (restricting SIDs: Everyone, Users and the
 *              logon SID, as the sandboxes of web browsers make them) can do with its own token, and
 *              that it can acquire a verify-context crypto provider
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>
#include <wincrypt.h>

/*
 * Measured on Windows Server 2022 (build 20348), an elevated administrator, a 64-bit and a 32-bit process:
 * - The default DACL of the token of the logon session is (BA:GA)(SY:GA)(logon SID:GENERIC_READ|GENERIC_EXECUTE),
 *   and the security descriptor of the token object, made from it with the token's generic mapping, has the
 *   logon SID ACE with TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY |
 *   TOKEN_QUERY_SOURCE | READ_CONTROL. Tokens made from it (CreateRestrictedToken, DuplicateTokenEx without a
 *   descriptor) get the same descriptor.
 * - A thread that runs as a token restricted to {Everyone, Users, logon SID} (DISABLE_MAX_PRIVILEGE, with or
 *   without Restricted Code, with or without Administrators as deny-only) can open the thread token and the
 *   process token with TOKEN_QUERY, and CryptAcquireContext(CRYPT_VERIFYCONTEXT) and CryptGenRandom succeed.
 * - A thread that runs as a token restricted to {Everyone} cannot open the thread token with OpenAsSelf FALSE
 *   (ERROR_ACCESS_DENIED), and CryptAcquireContext(CRYPT_VERIFYCONTEXT) fails.
 */

static PSID FindLogonSid(HANDLE Token, PBYTE Buffer, DWORD BufferSize)
{
    PTOKEN_GROUPS Groups = (PTOKEN_GROUPS)Buffer;
    DWORD Length, i;

    if (!GetTokenInformation(Token, TokenGroups, Buffer, BufferSize, &Length))
        return NULL;
    for (i = 0; i < Groups->GroupCount; i++)
    {
        if ((Groups->Groups[i].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
            return Groups->Groups[i].Sid;
    }
    return NULL;
}

static ACCESS_MASK GrantedToSid(PACL Dacl, PSID Sid, BOOL ObjectMask)
{
    DWORD i;
    ACCESS_MASK Mask = 0;
    PACCESS_ALLOWED_ACE Ace;

    UNREFERENCED_PARAMETER(ObjectMask);
    if (!Dacl)
        return 0;
    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (!GetAce(Dacl, i, (PVOID *)&Ace))
            continue;
        if (Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid((PSID)&Ace->SidStart, Sid))
            Mask |= Ace->Mask;
    }
    return Mask;
}

static void TestTokenDescriptors(HANDLE Process, PSID Logon)
{
    BYTE Buffer[2048];
    PTOKEN_DEFAULT_DACL Default = (PTOKEN_DEFAULT_DACL)Buffer;
    DWORD Length;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PACL Dacl = NULL;
    ACCESS_MASK Mask;
    HANDLE Query;

    ok(GetTokenInformation(Process, TokenDefaultDacl, Buffer, sizeof(Buffer), &Length),
       "TokenDefaultDacl failed: %lu\n", GetLastError());
    Mask = GrantedToSid(Default->DefaultDacl, Logon, FALSE);
    ok(Mask == (GENERIC_READ | GENERIC_EXECUTE), "Default DACL: logon SID has %08lx\n", Mask);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | READ_CONTROL, &Query))
    {
        skip("OpenProcessToken(READ_CONTROL) failed: %lu\n", GetLastError());
        return;
    }
    ok(GetSecurityInfo(Query, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd) == ERROR_SUCCESS,
       "GetSecurityInfo failed\n");
    if (Sd)
    {
        Mask = GrantedToSid(Dacl, Logon, TRUE);
        ok(Mask == (READ_CONTROL | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY),
           "Token object DACL: logon SID has %08lx\n", Mask);
        LocalFree(Sd);
    }
    CloseHandle(Query);
}

static HANDLE MakeImpersonation(HANDLE Process, DWORD Flags, DWORD DisableCount, PSID_AND_ATTRIBUTES Disable,
                                DWORD RestrictCount, PSID_AND_ATTRIBUTES Restrict)
{
    HANDLE Restricted = NULL, Impersonation = NULL;

    if (!CreateRestrictedToken(Process, Flags, DisableCount, Disable, 0, NULL, RestrictCount, Restrict, &Restricted))
    {
        ok(0, "CreateRestrictedToken failed: %lu\n", GetLastError());
        return NULL;
    }
    if (!DuplicateTokenEx(Restricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation))
    {
        ok(0, "DuplicateTokenEx failed: %lu\n", GetLastError());
        Impersonation = NULL;
    }
    CloseHandle(Restricted);
    return Impersonation;
}

static void TestAcquire(HANDLE Impersonation, PCSTR What, BOOL ExpectSuccess)
{
    HCRYPTPROV Prov = 0;
    HANDLE Token;
    BYTE Random[16];
    BOOL Ret, Opened;
    DWORD Error;

    ok(SetThreadToken(NULL, Impersonation), "%s: SetThreadToken failed: %lu\n", What, GetLastError());

    SetLastError(0xdeadbeef);
    Opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &Token);
    Error = GetLastError();
    if (ExpectSuccess)
        ok(Opened, "%s: OpenThreadToken(TOKEN_QUERY, FALSE) failed: %lu\n", What, Error);
    else
    {
        ok(!Opened, "%s: OpenThreadToken(TOKEN_QUERY, FALSE) succeeded\n", What);
        ok(Error == ERROR_ACCESS_DENIED, "%s: error %lu\n", What, Error);
    }
    if (Opened)
        CloseHandle(Token);

    SetLastError(0xdeadbeef);
    Opened = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token);
    Error = GetLastError();
    if (ExpectSuccess)
        ok(Opened, "%s: OpenProcessToken(TOKEN_QUERY) failed: %lu\n", What, Error);
    else
        ok(!Opened, "%s: OpenProcessToken(TOKEN_QUERY) succeeded\n", What);
    if (Opened)
        CloseHandle(Token);

    Ret = CryptAcquireContextW(&Prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    Error = GetLastError();
    if (ExpectSuccess)
    {
        ok(Ret, "%s: CryptAcquireContext failed: 0x%08lx\n", What, Error);
        if (Ret)
        {
            ok(CryptGenRandom(Prov, sizeof(Random), Random), "%s: CryptGenRandom failed: 0x%08lx\n", What, GetLastError());
            ok(CryptReleaseContext(Prov, 0), "%s: CryptReleaseContext failed\n", What);
        }
        Prov = 0;
        Ret = CryptAcquireContextW(&Prov, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
        ok(Ret, "%s: CryptAcquireContext(AES) failed: 0x%08lx\n", What, GetLastError());
        if (Ret)
            CryptReleaseContext(Prov, 0);
    }
    else
    {
        ok(!Ret, "%s: CryptAcquireContext succeeded\n", What);
        if (Ret)
            CryptReleaseContext(Prov, 0);
    }

    SetThreadToken(NULL, NULL);
}

START_TEST(RestrictedTokenCrypt)
{
    BYTE GroupBuffer[8192], Everyone[SECURITY_MAX_SID_SIZE], Users[SECURITY_MAX_SID_SIZE],
         Admins[SECURITY_MAX_SID_SIZE], Restricted[SECURITY_MAX_SID_SIZE];
    DWORD Size;
    HANDLE Process, Impersonation;
    PSID Logon;
    SID_AND_ATTRIBUTES Restrict[4], Disable[1];
    BOOL IsAdmin = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Process))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }
    Logon = FindLogonSid(Process, GroupBuffer, sizeof(GroupBuffer));
    if (!Logon)
    {
        skip("The process token has no logon SID\n");
        CloseHandle(Process);
        return;
    }

    Size = sizeof(Everyone); CreateWellKnownSid(WinWorldSid, NULL, Everyone, &Size);
    Size = sizeof(Users); CreateWellKnownSid(WinBuiltinUsersSid, NULL, Users, &Size);
    Size = sizeof(Admins); CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, Admins, &Size);
    Size = sizeof(Restricted); CreateWellKnownSid(WinRestrictedCodeSid, NULL, Restricted, &Size);

    TestTokenDescriptors(Process, Logon);

    /* The restricting SIDs of a sandboxed browser process */
    Restrict[0].Sid = Everyone; Restrict[0].Attributes = 0;
    Restrict[1].Sid = Users; Restrict[1].Attributes = 0;
    Restrict[2].Sid = Logon; Restrict[2].Attributes = 0;
    Restrict[3].Sid = Restricted; Restrict[3].Attributes = 0;

    Impersonation = MakeImpersonation(Process, DISABLE_MAX_PRIVILEGE, 0, NULL, 3, Restrict);
    if (Impersonation)
    {
        TestAcquire(Impersonation, "restricted to Everyone, Users, logon SID", TRUE);
        CloseHandle(Impersonation);
    }

    Impersonation = MakeImpersonation(Process, DISABLE_MAX_PRIVILEGE, 0, NULL, 4, Restrict);
    if (Impersonation)
    {
        TestAcquire(Impersonation, "restricted to Everyone, Users, logon SID, Restricted Code", TRUE);
        CloseHandle(Impersonation);
    }

    if (CheckTokenMembership(NULL, Admins, &IsAdmin) && IsAdmin)
    {
        Disable[0].Sid = Admins; Disable[0].Attributes = 0;
        Impersonation = MakeImpersonation(Process, DISABLE_MAX_PRIVILEGE, 1, Disable, 3, Restrict);
        if (Impersonation)
        {
            TestAcquire(Impersonation, "Administrators deny-only, restricted to Everyone, Users, logon SID", TRUE);
            CloseHandle(Impersonation);
        }
    }

    /* Only Everyone: the token object is not open to it */
    Impersonation = MakeImpersonation(Process, DISABLE_MAX_PRIVILEGE, 0, NULL, 1, Restrict);
    if (Impersonation)
    {
        TestAcquire(Impersonation, "restricted to Everyone", FALSE);
        CloseHandle(Impersonation);
    }

    CloseHandle(Process);
}
