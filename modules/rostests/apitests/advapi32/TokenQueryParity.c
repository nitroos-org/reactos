/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GetTokenInformation, PrivilegeCheck, IsTokenRestricted and CreateRestrictedToken(LUA_TOKEN)
 *              against Windows 10 22H2 (see the ntdll test NtTokenQueryParity for the measurements)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Built for amd64 and i386; the i386 build also runs under WoW64, where PrivilegeCheck,
 * IsTokenRestricted and several classes used to fail.
 */

#include "precomp.h"

#ifndef LUA_TOKEN
#define LUA_TOKEN 0x4
#endif

BOOL WINAPI IsTokenRestricted(HANDLE TokenHandle);

#define CLASS_ACCESSINFORMATION 22
#define CLASS_CAPABILITIES      30

static void TestOversizedBuffers(HANDLE Token)
{
    DWORD Buffer[16];
    DWORD Length;
    HANDLE Impersonation = NULL;

    /* Windows accepts a larger buffer for these and reports their size */
    Length = 0xdeadbeef;
    ok(GetTokenInformation(Token, TokenSessionId, Buffer, sizeof(Buffer), &Length), "TokenSessionId: error %lu\n", GetLastError());
    ok(Length == sizeof(DWORD), "TokenSessionId length %lu\n", Length);

    Length = 0xdeadbeef;
    ok(GetTokenInformation(Token, TokenSandBoxInert, Buffer, sizeof(Buffer), &Length), "TokenSandBoxInert: error %lu\n", GetLastError());
    ok(Length == sizeof(DWORD), "TokenSandBoxInert length %lu\n", Length);

    Length = 0xdeadbeef;
    ok(GetTokenInformation(Token, TokenOrigin, Buffer, sizeof(Buffer), &Length), "TokenOrigin: error %lu\n", GetLastError());
    ok(Length == sizeof(TOKEN_ORIGIN), "TokenOrigin length %lu\n", Length);

    if (DuplicateToken(Token, SecurityImpersonation, &Impersonation))
    {
        Length = 0xdeadbeef;
        ok(GetTokenInformation(Impersonation, TokenImpersonationLevel, Buffer, sizeof(Buffer), &Length),
           "TokenImpersonationLevel: error %lu\n", GetLastError());
        ok(Length == sizeof(DWORD), "TokenImpersonationLevel length %lu\n", Length);
        ok(*(SECURITY_IMPERSONATION_LEVEL *)Buffer == SecurityImpersonation, "level %d\n", *(SECURITY_IMPERSONATION_LEVEL *)Buffer);
        CloseHandle(Impersonation);
    }
    else
        ok(FALSE, "DuplicateToken failed: %lu\n", GetLastError());
}

static void TestNewClasses(HANDLE Token)
{
    DWORD Buffer[1024];
    DWORD Length;
    SetLastError(0xdeadbeef);
    ok(!GetTokenInformation(Token, (TOKEN_INFORMATION_CLASS)CLASS_ACCESSINFORMATION, NULL, 0, &Length), "TokenAccessInformation size query succeeded\n");
    ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "TokenAccessInformation: error %lu\n", GetLastError());
    ok(Length > 0 && Length <= sizeof(Buffer), "TokenAccessInformation size %lu\n", Length);
    if (Length > 0 && Length <= sizeof(Buffer))
    {
        DWORD Length2 = 0;

        ok(GetTokenInformation(Token, (TOKEN_INFORMATION_CLASS)CLASS_ACCESSINFORMATION, Buffer, sizeof(Buffer), &Length2),
           "TokenAccessInformation: error %lu\n", GetLastError());
        ok(Length2 == Length, "TokenAccessInformation length %lu, size query said %lu\n", Length2, Length);
    }

    Length = 0xdeadbeef;
    ok(GetTokenInformation(Token, (TOKEN_INFORMATION_CLASS)CLASS_CAPABILITIES, Buffer, sizeof(Buffer), &Length),
       "TokenCapabilities: error %lu\n", GetLastError());
    ok(Length == FIELD_OFFSET(TOKEN_GROUPS, Groups), "TokenCapabilities length %lu\n", Length);
    ok(((PTOKEN_GROUPS)Buffer)->GroupCount == 0, "TokenCapabilities has groups\n");
}

static BOOL GroupAttributes(HANDLE Token, PSID Sid, PDWORD Attributes)
{
    DWORD Length = 0, i;
    PTOKEN_GROUPS Groups;
    BOOL Found = FALSE;

    GetTokenInformation(Token, TokenGroups, NULL, 0, &Length);
    Groups = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Groups && GetTokenInformation(Token, TokenGroups, Groups, Length, &Length))
    {
        for (i = 0; i < Groups->GroupCount; i++)
        {
            if (EqualSid(Groups->Groups[i].Sid, Sid))
            {
                *Attributes = Groups->Groups[i].Attributes;
                Found = TRUE;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Groups);
    return Found;
}

static DWORD PrivilegeCount(HANDLE Token)
{
    DWORD Length = 0, Count = 0xdeadbeef;
    PTOKEN_PRIVILEGES Privileges;

    GetTokenInformation(Token, TokenPrivileges, NULL, 0, &Length);
    Privileges = HeapAlloc(GetProcessHeap(), 0, Length);
    if (Privileges && GetTokenInformation(Token, TokenPrivileges, Privileges, Length, &Length))
        Count = Privileges->PrivilegeCount;
    HeapFree(GetProcessHeap(), 0, Privileges);
    return Count;
}

static void TestPrivilegeCheckAndRestricted(HANDLE Token)
{
    HANDLE Filtered = NULL, Impersonation = NULL;
    PRIVILEGE_SET Set;
    BOOL Result;
    SID_IDENTIFIER_AUTHORITY WorldAuthority = {SECURITY_WORLD_SID_AUTHORITY};
    PSID World = NULL;
    SID_AND_ATTRIBUTES Restrict;
    HANDLE Restricted = NULL;

    ok(!IsTokenRestricted(Token), "The process token is restricted\n");

    ok(CreateRestrictedToken(Token, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &Filtered), "CreateRestrictedToken: %lu\n", GetLastError());
    if (Filtered && DuplicateToken(Filtered, SecurityImpersonation, &Impersonation))
    {
        Set.PrivilegeCount = 1;
        Set.Control = PRIVILEGE_SET_ALL_NECESSARY;
        Set.Privilege[0].Attributes = 0;
        ok(LookupPrivilegeValueA(NULL, SE_CHANGE_NOTIFY_NAME, &Set.Privilege[0].Luid), "LookupPrivilegeValue: %lu\n", GetLastError());
        Result = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        ok(PrivilegeCheck(Impersonation, &Set, &Result), "PrivilegeCheck: error %lu\n", GetLastError());
        ok(Result == TRUE, "SeChangeNotifyPrivilege is not held (%d)\n", Result);

        ok(LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &Set.Privilege[0].Luid), "LookupPrivilegeValue: %lu\n", GetLastError());
        Set.Privilege[0].Attributes = 0;
        Result = 0xdeadbeef;
        ok(PrivilegeCheck(Impersonation, &Set, &Result), "PrivilegeCheck: error %lu\n", GetLastError());
        ok(Result == FALSE, "SeDebugPrivilege is held (%d)\n", Result);
        ok(!IsTokenRestricted(Filtered), "A token without privileges is restricted\n");
        CloseHandle(Impersonation);
    }
    if (Filtered)
        CloseHandle(Filtered);

    /* A restricting SID makes the token restricted */
    if (AllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &World))
    {
        Restrict.Sid = World;
        Restrict.Attributes = 0;
        ok(CreateRestrictedToken(Token, 0, 0, NULL, 0, NULL, 1, &Restrict, &Restricted), "CreateRestrictedToken: %lu\n", GetLastError());
        if (Restricted)
        {
            ok(IsTokenRestricted(Restricted), "A token with a restricting SID is not restricted\n");
            CloseHandle(Restricted);
        }
        FreeSid(World);
    }
}

static void TestLua(HANDLE Token)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID Admins = NULL;
    HANDLE Lua = NULL, LuaImpersonation = NULL;
    DWORD Attributes, Length, Original, Count;
    TOKEN_ELEVATION Elevation;
    DWORD Flag;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Admins))
        return;
    if (!GroupAttributes(Token, Admins, &Attributes) || !(Attributes & SE_GROUP_ENABLED) || (Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
    {
        skip("Not running elevated: no enabled Administrators group\n");
        FreeSid(Admins);
        return;
    }
    Original = PrivilegeCount(Token);
    ok(GetTokenInformation(Token, TokenElevation, &Elevation, sizeof(Elevation), &Length), "TokenElevation: %lu\n", GetLastError());
    ok(Elevation.TokenIsElevated == 1, "The process token is not elevated\n");

    ok(CreateRestrictedToken(Token, LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &Lua), "CreateRestrictedToken(LUA_TOKEN): %lu\n", GetLastError());
    if (Lua)
    {
        /* A LUA token is the filtered form of the token: Administrators deny-only, 5 privileges at most, not elevated */
        ok(GroupAttributes(Lua, Admins, &Attributes), "No Administrators group\n");
        ok(Attributes == SE_GROUP_USE_FOR_DENY_ONLY, "Administrators attributes 0x%lx\n", Attributes);
        Count = PrivilegeCount(Lua);
        ok(Count <= 5 && Count <= Original, "A LUA token has %lu privileges (original %lu)\n", Count, Original);
        ok(GetTokenInformation(Lua, TokenElevation, &Elevation, sizeof(Elevation), &Length), "TokenElevation: %lu\n", GetLastError());
        ok(Elevation.TokenIsElevated == 0, "A LUA token is elevated\n");
        Flag = 0xCCCCCC00;
        ok(GetTokenInformation(Lua, TokenHasRestrictions, &Flag, sizeof(Flag), &Length), "TokenHasRestrictions: %lu\n", GetLastError());
        ok(Flag == 0xCCCCCC01 && Length == 1, "TokenHasRestrictions 0x%lx (length %lu)\n", Flag, Length);
        ok(!IsTokenRestricted(Lua), "A LUA token has restricting SIDs\n");
        /* the impersonation copy keeps it */
        if (DuplicateToken(Lua, SecurityImpersonation, &LuaImpersonation))
        {
            ok(GroupAttributes(LuaImpersonation, Admins, &Attributes) && Attributes == SE_GROUP_USE_FOR_DENY_ONLY, "A copy changed the attributes\n");
            ok(PrivilegeCount(LuaImpersonation) == Count, "A copy changed the privileges\n");
            CloseHandle(LuaImpersonation);
        }
        CloseHandle(Lua);
    }
    FreeSid(Admins);
}

START_TEST(TokenQueryParity)
{
    HANDLE Token = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token))
    {
        skip("OpenProcessToken failed: %lu\n", GetLastError());
        return;
    }
    TestOversizedBuffers(Token);
    TestNewClasses(Token);
    TestPrivilegeCheckAndRestricted(Token);
    TestLua(Token);
    CloseHandle(Token);
}
