/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registry key security, the switch to enforcement: what a boot that enforces reports about
 *              the check of the machine hives' stored descriptors, and the marker that says enforcement
 *              has protected them since (a NitroOS mechanism, no Windows counterpart)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The behaviour across boots (descriptors a standard user stored while an earlier boot did not enforce are
 * replaced at the first boot that enforces; the value RegistryAclMode of an earlier kernel is deleted and has
 * no effect) needs several boots and is tested outside this program. Here: the state one boot leaves.
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
    DWORD Transition, Failed, Unrepaired, Attributes, Removed, Was;
    HKEY Key;
    LONG Error;

    if (!GetStat(L"Transition", &Transition))
    {
        skip("no registry access control statistics (AuditStats\\Transition)\n");
        return;
    }
    GetSystemDirectoryW(Path, MAX_PATH);
    *wcsrchr(Path, L'\\') = UNICODE_NULL;
    StringCchCatW(Path, MAX_PATH, MARKER);
    Attributes = GetFileAttributesW(Path);

    /* The check ran at this boot or an earlier one, and the marker says so */
    ok(Transition == 1 || Transition == 2, "Transition %lu, expected 1 (checked now) or 2 (marker found)\n", Transition);
    ok(GetStat(L"RestampFailed", &Failed) && Failed == 0, "RestampFailed %lu\n", Failed);
    ok(GetStat(L"BootKeysUnrepaired", &Unrepaired) && Unrepaired == 0, "BootKeysUnrepaired %lu\n", Unrepaired);
    ok(Attributes != INVALID_FILE_ATTRIBUTES, "no marker %ls: %lu\n", Path, GetLastError());
    if (Attributes != INVALID_FILE_ATTRIBUTES)
        TestMarker(Path);

    /* There is no mode and no mode statistics: the old names are not published */
    ok(!GetStat(L"Mode", &Failed), "AuditStats\\Mode is published\n");
    ok(!GetStat(L"ConfiguredMode", &Failed), "AuditStats\\ConfiguredMode is published\n");
    ok(!GetStat(L"EnforceFallback", &Failed), "AuditStats\\EnforceFallback is published\n");

    /*
     * The value RegistryAclMode of earlier kernels: deleted at the boot that found it, so it is not there now
     * (unless something wrote it after the boot, which this test does not do), and when this boot deleted it the
     * statistics say so
     */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager",
                          0, KEY_QUERY_VALUE, &Key);
    /* The key itself may not exist (a fresh install has no value in it): then the value is not there either */
    ok(Error == ERROR_SUCCESS || Error == ERROR_FILE_NOT_FOUND, "Configuration Manager key: %ld\n", Error);
    if (Error == ERROR_SUCCESS)
    {
        Error = RegQueryValueExW(Key, L"RegistryAclMode", NULL, NULL, NULL, NULL);
        ok(Error == ERROR_FILE_NOT_FOUND, "RegistryAclMode is still there after the boot: %ld\n", Error);
        RegCloseKey(Key);
    }
    if (GetStat(L"ModeValueRemoved", &Removed) && Removed)
    {
        ok(GetStat(L"ModeValueWas", &Was), "ModeValueRemoved without ModeValueWas\n");
        trace("this boot deleted RegistryAclMode (data 0x%lx)\n", Was);
    }
}
