/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The descriptor of the token that a process gets from CreateProcessAsUser: made from the token itself
 *              (its default DACL), with the query right of the Administrators last, whether the handle has
 *              TOKEN_DUPLICATE or not
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows Server 2022 (build 20348, measured): the first process of a secondary logon of a standard user has the token
 * descriptor O:<user>G:<group>D:(A;;all;;;<user>)(A;;all;;;SY)(A;;RC|query...;;;<logon SID>)(A;;TOKEN_QUERY;;;BA): the
 * entries of the default DACL of the token it was made from, then the Administrators' query entry. Here the caller's
 * own token, a primary duplicate with the default DACL (SY: all)(Everyone: generic read), makes the child.
 */

#include "precomp.h"
#include <sddl.h>

#define CHILD_ACES 3    /* SY, Everyone, and the query entry of the Administrators */

static PACL ReadDacl(HANDLE Token, PSECURITY_DESCRIPTOR *Sd)
{
    DWORD Needed = 0;
    BOOL Present = FALSE, Defaulted;
    PACL Dacl = NULL;

    *Sd = NULL;
    GetKernelObjectSecurity(Token, DACL_SECURITY_INFORMATION, NULL, 0, &Needed);
    if (Needed == 0)
        return NULL;
    *Sd = HeapAlloc(GetProcessHeap(), 0, Needed);
    if (!*Sd || !GetKernelObjectSecurity(Token, DACL_SECURITY_INFORMATION, *Sd, Needed, &Needed))
        return NULL;
    GetSecurityDescriptorDacl(*Sd, &Present, &Dacl, &Defaulted);
    return Present ? Dacl : NULL;
}

static void CheckChild(PCSTR Name, HANDLE Token)
{
    WCHAR Cmd[MAX_PATH + 16];
    STARTUPINFOW Si = { sizeof(Si) };
    PROCESS_INFORMATION Pi;
    HANDLE ChildToken;
    PSECURITY_DESCRIPTOR Sd;
    PACL Dacl;
    BOOL Ret;

    GetSystemDirectoryW(Cmd, MAX_PATH);
    lstrcatW(Cmd, L"\\cmd.exe");
    Ret = CreateProcessAsUserW(Token, NULL, Cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi);
    ok(Ret, "%s: CreateProcessAsUser failed with %lu\n", Name, GetLastError());
    if (!Ret)
        return;

    if (!OpenProcessToken(Pi.hProcess, TOKEN_QUERY | READ_CONTROL, &ChildToken))
    {
        skip("%s: cannot open the token of the child (%lu)\n", Name, GetLastError());
    }
    else
    {
        Dacl = ReadDacl(ChildToken, &Sd);
        ok(Dacl != NULL, "%s: no DACL\n", Name);
        if (Dacl)
        {
            PACCESS_ALLOWED_ACE Ace = NULL;
            BYTE AdminsSid[SECURITY_MAX_SID_SIZE];
            DWORD cbSid = sizeof(AdminsSid);

            ok(Dacl->AceCount == CHILD_ACES, "%s: %u entries, expected %u\n", Name, Dacl->AceCount, CHILD_ACES);
            if (Dacl->AceCount == CHILD_ACES && GetAce(Dacl, CHILD_ACES - 1, (PVOID *)&Ace) &&
                CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminsSid, &cbSid))
            {
                ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
                   EqualSid((PSID)&Ace->SidStart, AdminsSid) && Ace->Mask == TOKEN_QUERY,
                   "%s: the last entry is not (A;;TOKEN_QUERY;;;BA): type %u mask 0x%lx\n", Name, Ace->Header.AceType, Ace->Mask);
            }
        }
        HeapFree(GetProcessHeap(), 0, Sd);
        CloseHandle(ChildToken);
    }
    TerminateProcess(Pi.hProcess, 0);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
}

START_TEST(CreateProcessAsUserTokenSd)
{
    HANDLE Own, Primary, NoDuplicate;
    PSECURITY_DESCRIPTOR Given = NULL;
    TOKEN_DEFAULT_DACL DefaultDacl;
    BOOL Present, Defaulted;
    PACL Acl = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Own))
    {
        skip("no access to the own token (%lu)\n", GetLastError());
        return;
    }
    if (!DuplicateTokenEx(Own, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &Primary))
    {
        skip("cannot duplicate the own token (%lu)\n", GetLastError());
        CloseHandle(Own);
        return;
    }
    CloseHandle(Own);

    ok(ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;;GA;;;SY)(A;;GR;;;WD)", SDDL_REVISION_1, &Given, NULL),
       "ConvertStringSecurityDescriptorToSecurityDescriptor failed with %lu\n", GetLastError());
    if (Given && GetSecurityDescriptorDacl(Given, &Present, &Acl, &Defaulted) && Present && Acl)
    {
        DefaultDacl.DefaultDacl = Acl;
        ok(SetTokenInformation(Primary, TokenDefaultDacl, &DefaultDacl, sizeof(DefaultDacl)),
           "SetTokenInformation(TokenDefaultDacl) failed with %lu\n", GetLastError());

        /* a handle with TOKEN_DUPLICATE */
        CheckChild("handle with TOKEN_DUPLICATE", Primary);

        /* a handle without it (TOKEN_QUERY and TOKEN_ASSIGN_PRIMARY only) */
        if (DuplicateHandle(GetCurrentProcess(), Primary, GetCurrentProcess(), &NoDuplicate,
                            TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, FALSE, 0))
        {
            CheckChild("handle without TOKEN_DUPLICATE", NoDuplicate);
            CloseHandle(NoDuplicate);
        }
        else
        {
            skip("cannot make a handle without TOKEN_DUPLICATE (%lu)\n", GetLastError());
        }
    }
    LocalFree(Given);
    CloseHandle(Primary);
}
