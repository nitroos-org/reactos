/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registry key security, the switch to enforcement: what a boot that enforces reports about
 *              the check of the machine hives' stored descriptors, and the marker that says enforcement
 *              has protected them since (a NitroOS mechanism, no Windows counterpart)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The behaviour across boots (descriptors a standard user stored while an earlier boot did not enforce are
 * replaced at the first boot that does; the registry value cannot take the mode below enforcement where it
 * is the default; the marker goes away at a boot that does not enforce) needs several boots and is tested
 * outside this program. Here: the state one boot leaves.
 */

#include "precomp.h"
#include <sddl.h>

#define MARKER L"\\System32\\config\\RegAclEnforced"

static BOOL GetStat(PCWSTR Name, DWORD *Value)
{
    HKEY Key;
    DWORD Size = sizeof(*Value), Type;
    LONG Error;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\RegAcl\\AuditStats",
                      0, KEY_QUERY_VALUE, &Key) != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(Key, Name, NULL, &Type, (BYTE *)Value, &Size);
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS && Type == REG_DWORD;
}

static BOOL IsSid(PSID Sid, WELL_KNOWN_SID_TYPE Type)
{
    BYTE Buffer[SECURITY_MAX_SID_SIZE];
    DWORD Size = sizeof(Buffer);

    return CreateWellKnownSid(Type, NULL, Buffer, &Size) && EqualSid(Sid, Buffer);
}

/* The marker: owned by SYSTEM, a protected DACL with SYSTEM and Administrators only */
static VOID TestMarker(PCWSTR Path)
{
    BYTE Buffer[4096];
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)Buffer;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD Size = sizeof(Buffer), Revision, i;
    PSID Owner;
    PACL Dacl;
    BOOL Present, Defaulted;
    PACCESS_ALLOWED_ACE Ace;

    if (!GetFileSecurityW(Path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Sd, Size, &Size))
    {
        ok(0, "GetFileSecurity(%ls) failed: %lu\n", Path, GetLastError());
        return;
    }
    ok(GetSecurityDescriptorOwner(Sd, &Owner, &Defaulted) && Owner && IsSid(Owner, WinLocalSystemSid),
       "the marker is not owned by SYSTEM\n");
    ok(GetSecurityDescriptorControl(Sd, &Control, &Revision) && (Control & SE_DACL_PROTECTED),
       "the marker's DACL is not protected\n");
    ok(GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) && Present && Dacl,
       "the marker has no DACL\n");
    if (!Present || !Dacl)
        return;
    ok(Dacl->AceCount == 2, "the marker's DACL has %u ACEs, expected 2\n", Dacl->AceCount);
    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (!GetAce(Dacl, i, (PVOID *)&Ace))
            continue;
        ok(Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ACE %lu: type %u\n", i, Ace->Header.AceType);
        ok(IsSid((PSID)&Ace->SidStart, WinLocalSystemSid) || IsSid((PSID)&Ace->SidStart, WinBuiltinAdministratorsSid),
           "ACE %lu names a principal other than SYSTEM and Administrators\n", i);
    }
}

START_TEST(RegEnforceTransition)
{
    WCHAR Path[MAX_PATH];
    DWORD Mode, Transition, Failed, Fallback, Configured, Source, Ignored, Attributes;
    HKEY Key;
    DWORD Value, Size = sizeof(Value), Type;
    BOOL LowerValue = FALSE;

    if (!GetStat(L"Mode", &Mode) || !GetStat(L"Transition", &Transition))
    {
        skip("no registry access control statistics (AuditStats\\Transition)\n");
        return;
    }
    GetSystemDirectoryW(Path, MAX_PATH);
    *wcsrchr(Path, L'\\') = UNICODE_NULL;
    StringCchCatW(Path, MAX_PATH, MARKER);
    Attributes = GetFileAttributesW(Path);

    if (Mode == 2)
    {
        /* The check ran at this boot or an earlier one, and the marker says so */
        ok(Transition == 1 || Transition == 2, "Transition %lu, expected 1 (checked now) or 2 (marker found)\n", Transition);
        ok(GetStat(L"RestampFailed", &Failed) && Failed == 0, "RestampFailed %lu\n", Failed);
        ok(GetStat(L"EnforceFallback", &Fallback) && Fallback == 0, "EnforceFallback %lu\n", Fallback);
        ok(Attributes != INVALID_FILE_ATTRIBUTES, "no marker %ls in enforcement mode: %lu\n", Path, GetLastError());
        if (Attributes != INVALID_FILE_ATTRIBUTES)
            TestMarker(Path);
    }
    else
    {
        /* A boot that does not enforce removes the marker: users may change keys from now on */
        ok(Transition == 0, "Transition %lu outside enforcement mode\n", Transition);
        ok(Attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND,
           "the marker %ls is there in mode %lu (attributes 0x%lx, error %lu)\n", Path, Mode, Attributes, GetLastError());
    }

    /* RegistryAclMode below 2 where 2 is the compiled default: ignored, said so (SwitchesIgnored 0x4) */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager",
                      0, KEY_QUERY_VALUE, &Key) == ERROR_SUCCESS)
    {
        LowerValue = RegQueryValueExW(Key, L"RegistryAclMode", NULL, &Type, (BYTE *)&Value, &Size) == ERROR_SUCCESS &&
                     Type == REG_DWORD && Value < 2;
        RegCloseKey(Key);
    }
    if (LowerValue && GetStat(L"ConfiguredMode", &Configured) && GetStat(L"ModeSource", &Source) &&
        GetStat(L"SwitchesIgnored", &Ignored) && Source == 0 && Configured == 2)
    {
        ok(Ignored & 0x4, "RegistryAclMode %lu under the enforcing default: SwitchesIgnored 0x%lx\n", Value, Ignored);
        ok(Mode == 2, "RegistryAclMode %lu took the mode to %lu\n", Value, Mode);
    }
    else
    {
        trace("RegistryAclMode row not applicable (value %s)\n", LowerValue ? "below 2, mode set otherwise" : "absent or 2");
    }
}
