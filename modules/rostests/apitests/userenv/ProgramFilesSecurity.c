/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     No file or directory below Program Files lets the groups of every user write, delete or re-secure it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Program Files and Program Files (x86) carry the DACL of Windows (SYSTEM, Administrators, Users and the application
 * packages read only); what is installed in them inherits it. Setup used to create them with the entries of the volume
 * root (Authenticated Users: Modify) and install PowerShell 7 and Common Files below them before they got their DACL:
 * those objects kept Authenticated Users: Modify (any user could replace pwsh.exe, in the machine Path). Checked: every
 * object (up to 8 levels down, no reparse point followed) has no allow entry for Authenticated Users, Users, Everyone,
 * INTERACTIVE or the console logon that writes, deletes or re-secures it or, inherited, what is created in it.
 */

#include <apitest.h>
#include <windows.h>
#include <strsafe.h>

#define WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | \
                      GENERIC_WRITE | GENERIC_ALL)

static BYTE s_Sids[5][SECURITY_MAX_SID_SIZE];
static ULONG s_Objects, s_Bad;

static BOOL IsEveryUserSid(PSID Sid)
{
    UINT i;

    for (i = 0; i < ARRAYSIZE(s_Sids); i++)
        if (EqualSid(Sid, (PSID)s_Sids[i]))
            return TRUE;
    return FALSE;
}

static void CheckObject(PCWSTR Path)
{
    BYTE Buffer[8192];
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)Buffer;
    DWORD Needed = 0, i;
    BOOL Present, Defaulted;
    PACL Dacl = NULL;

    s_Objects++;
    if (!GetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Sd, sizeof(Buffer), &Needed) ||
        !GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted))
    {
        ok(0, "%ls: DACL not read (%lu)\n", Path, GetLastError());
        return;
    }
    if (!Present || !Dacl)
    {
        if (s_Bad++ < 10)
            ok(0, "%ls: no DACL (everybody may do everything)\n", Path);
        return;
    }
    for (i = 0; i < Dacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE Ace;

        if (!GetAce(Dacl, i, (PVOID *)&Ace) || Ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        if ((Ace->Mask & WRITE_RIGHTS) && IsEveryUserSid((PSID)&Ace->SidStart))
        {
            if (s_Bad++ < 10)
                ok(0, "%ls: entry %lu (flags 0x%x, mask 0x%lx) for a group of every user\n", Path, i,
                   Ace->Header.AceFlags, Ace->Mask);
            break;
        }
    }
}

static void Walk(PCWSTR Directory, UINT Depth)
{
    WCHAR Pattern[MAX_PATH], Path[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find;

    if (Depth > 8 || FAILED(StringCchPrintfW(Pattern, ARRAYSIZE(Pattern), L"%s\\*", Directory)))
        return;
    Find = FindFirstFileW(Pattern, &Data);
    if (Find == INVALID_HANDLE_VALUE)
        return;
    do
    {
        if (!wcscmp(Data.cFileName, L".") || !wcscmp(Data.cFileName, L".."))
            continue;
        if (FAILED(StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\%s", Directory, Data.cFileName)))
            continue;
        CheckObject(Path);
        if ((Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(Data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
            Walk(Path, Depth + 1);
    } while (FindNextFileW(Find, &Data));
    FindClose(Find);
}

START_TEST(ProgramFilesSecurity)
{
    static const WELL_KNOWN_SID_TYPE Types[] = { WinAuthenticatedUserSid, WinBuiltinUsersSid, WinWorldSid,
                                                 WinInteractiveSid, WinConsoleLogonSid };
    static const PCWSTR Values[] = { L"ProgramFilesDir", L"ProgramFilesDir (x86)" };
    WCHAR Path[MAX_PATH];
    DWORD Size, Type;
    UINT i;

    for (i = 0; i < ARRAYSIZE(Types); i++)
    {
        Size = SECURITY_MAX_SID_SIZE;
        if (!CreateWellKnownSid(Types[i], NULL, s_Sids[i], &Size))
            Size = SECURITY_MAX_SID_SIZE, CreateWellKnownSid(WinAuthenticatedUserSid, NULL, s_Sids[i], &Size);
    }

    for (i = 0; i < ARRAYSIZE(Values); i++)
    {
        HKEY Key;
        LONG Error;

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", 0,
                          KEY_QUERY_VALUE | KEY_WOW64_64KEY, &Key) != ERROR_SUCCESS)
        {
            continue;
        }
        Size = sizeof(Path) - sizeof(WCHAR);
        Error = RegQueryValueExW(Key, Values[i], NULL, &Type, (PBYTE)Path, &Size);
        RegCloseKey(Key);
        if (Error != ERROR_SUCCESS || Type != REG_SZ)
            continue;
        Path[Size / sizeof(WCHAR)] = UNICODE_NULL;
        if (GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES)
            continue;
        CheckObject(Path);
        Walk(Path, 0);
    }

    ok(s_Objects > 0, "nothing checked\n");
    ok(s_Bad == 0, "%lu of %lu objects below Program Files let every user write, delete or re-secure them\n", s_Bad, s_Objects);
    trace("%lu objects checked\n", s_Objects);
}
