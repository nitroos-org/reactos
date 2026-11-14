/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     NtQuerySecurityObject / NtSetSecurityObject on registry keys, as Windows 10 22H2
 *              does them (oracle probe of the registry ACL work, slice R4): which parts a
 *              SecurityInformation returns, the rights a query needs, what a set changes (generic
 *              rights, control bits, NULL DACL, owner and group rules, SACL and label parts, last
 *              write time, change notification, no propagation to subkeys).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Reads only existing keys (READ_CONTROL opens) and writes only a volatile scratch key (and one
 * volatile child) under HKCU\Software, deleted at the end. Tokens for the owner rules are
 * impersonated duplicates of the process token with privileges switched off or on; the process
 * token is not changed. The owner, SACL and BACKUP parts need an administrator (skipped otherwise).
 */

#include "precomp.h"
#include <sddl.h>
#include <ndk/obfuncs.h>

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION 0x00000010
#endif
#define BACKUP_SI       0x00010000
#define OGD (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)

static const WCHAR ScratchPath[] = L"Software\\ReactOS-apitest-RegSecurityQuerySet";
static const WCHAR ChildName[] = L"Child";

/* T0: privileges off; T1: + SeRestorePrivilege; T2: + SeSecurityPrivilege */
static HANDLE Tok[3];

static BOOL SetPrivilege(HANDLE Token, PCWSTR Name, DWORD Attributes)
{
    TOKEN_PRIVILEGES Tp;

    if (!LookupPrivilegeValueW(NULL, Name, &Tp.Privileges[0].Luid))
        return FALSE;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = Attributes;
    return AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
}

static BOOL MakeTokens(void)
{
    static const PCWSTR Off[] = { L"SeRestorePrivilege", L"SeSecurityPrivilege", L"SeTakeOwnershipPrivilege",
                                  L"SeRelabelPrivilege", L"SeBackupPrivilege" };
    HANDLE Process;
    BOOL Ok = TRUE;
    ULONG i, k;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &Process))
        return FALSE;
    for (i = 0; i < 3 && Ok; i++)
    {
        Ok = DuplicateTokenEx(Process, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Tok[i]);
        for (k = 0; Ok && k < ARRAYSIZE(Off); k++)
            SetPrivilege(Tok[i], Off[k], 0);
    }
    CloseHandle(Process);
    if (!Ok)
        return FALSE;
    /* Only an administrator holds these */
    return SetPrivilege(Tok[1], L"SeRestorePrivilege", SE_PRIVILEGE_ENABLED) &&
           SetPrivilege(Tok[2], L"SeSecurityPrivilege", SE_PRIVILEGE_ENABLED);
}

static void As(int t) { ok(SetThreadToken(NULL, Tok[t]), "SetThreadToken failed: %lu\n", GetLastError()); }
static void Self(void) { SetThreadToken(NULL, NULL); }

/* Query into a buffer; returns the status, *Sd points into Buffer */
static NTSTATUS Query(HANDLE Key, SECURITY_INFORMATION Info, BYTE *Buffer, ULONG Size, PULONG Length)
{
    *Length = 0;
    memset(Buffer, 0xcc, Size);
    return NtQuerySecurityObject(Key, Info, Buffer, Size, Length);
}

static SECURITY_DESCRIPTOR_CONTROL Control(BYTE *Sd)
{
    return ((PISECURITY_DESCRIPTOR_RELATIVE)Sd)->Control;
}

static NTSTATUS SetSddl(int t, HANDLE Key, SECURITY_INFORMATION Info, PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    NTSTATUS Status;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
    {
        ok(0, "%ls: not parsed (%lu)\n", Sddl, GetLastError());
        return STATUS_UNSUCCESSFUL;
    }
    if (t >= 0)
        As(t);
    Status = NtSetSecurityObject(Key, Info, Sd);
    if (t >= 0)
        Self();
    LocalFree(Sd);
    return Status;
}

/* The DACL of the key: ACE count, and the mask of the ACE for Sid (0 if none) */
static ACCESS_MASK DaclMask(HANDLE Key, WELL_KNOWN_SID_TYPE Type, PULONG Count, PSECURITY_DESCRIPTOR_CONTROL Ctl, BOOL *Null)
{
    BYTE Buffer[1024], SidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD SidSize = sizeof(SidBuffer);
    BOOL Present = FALSE, Defaulted;
    PACL Dacl = NULL;
    ACCESS_ALLOWED_ACE *Ace;
    ACCESS_MASK Mask = 0;
    ULONG Length, i;

    *Count = 0;
    *Null = FALSE;
    *Ctl = 0;
    if (Query(Key, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length) != STATUS_SUCCESS)
        return 0;
    *Ctl = Control(Buffer);
    CreateWellKnownSid(Type, NULL, SidBuffer, &SidSize);
    GetSecurityDescriptorDacl(Buffer, &Present, &Dacl, &Defaulted);
    *Null = Present && !Dacl;
    if (!Dacl)
        return 0;
    *Count = Dacl->AceCount;
    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (GetAce(Dacl, i, (PVOID *)&Ace) && EqualSid(&Ace->SidStart, SidBuffer))
            Mask = Ace->Mask;
    }
    return Mask;
}

static void TestQueryParts(void)
{
    BYTE Buffer[2048];
    ULONG Length;
    HKEY Key, KeyQv;
    NTSTATUS Status;
    LONG Error;
    DWORD Needed;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, READ_CONTROL, &Key);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        return;

    /* Nothing asked: an empty descriptor */
    Status = Query(Key, 0, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok_long(Length, sizeof(SECURITY_DESCRIPTOR_RELATIVE));
    ok_hex(Control(Buffer), SE_SELF_RELATIVE);
    Status = NtQuerySecurityObject(Key, 0, NULL, 0, &Length);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok_long(Length, sizeof(SECURITY_DESCRIPTOR_RELATIVE));

    /* Owner only: an owner, no DACL, no DACL bits */
    Status = Query(Key, OWNER_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok(((PISECURITY_DESCRIPTOR_RELATIVE)Buffer)->Owner != 0, "no owner\n");
    ok(((PISECURITY_DESCRIPTOR_RELATIVE)Buffer)->Dacl == 0, "a DACL\n");
    ok_hex(Control(Buffer), SE_SELF_RELATIVE);

    /* The DACL with its bits, nothing of the SACL */
    Status = Query(Key, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Control(Buffer) & SE_DACL_PRESENT, "no DACL (0x%x)\n", Control(Buffer));
    ok(!(Control(Buffer) & (SE_SACL_PRESENT | SE_SACL_AUTO_INHERITED)), "SACL bits (0x%x)\n", Control(Buffer));
    ok(((PISECURITY_DESCRIPTOR_RELATIVE)Buffer)->Owner == 0, "an owner\n");

    /* (UN)PROTECTED_DACL_SECURITY_INFORMATION change nothing in a query */
    {
        BYTE Other[2048];
        ULONG OtherLength;

        Status = Query(Key, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, Other, sizeof(Other), &OtherLength);
        ok_hex(Status, STATUS_SUCCESS);
        ok(OtherLength == Length && !memcmp(Other, Buffer, Length), "the protected flag changed the result\n");
    }

    /* The SACL and the whole descriptor need ACCESS_SYSTEM_SECURITY on the handle */
    Status = Query(Key, SACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    Status = NtQuerySecurityObject(Key, SACL_SECURITY_INFORMATION, NULL, 0, &Length);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    Status = Query(Key, BACKUP_SI, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    Needed = 0;
    Error = RegGetKeySecurity(Key, SACL_SECURITY_INFORMATION, NULL, &Needed);
    ok_long(Error, ERROR_ACCESS_DENIED);

    /* The label part needs READ_CONTROL only */
    Status = Query(Key, LABEL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    ok(((PISECURITY_DESCRIPTOR_RELATIVE)Buffer)->Dacl == 0 && ((PISECURITY_DESCRIPTOR_RELATIVE)Buffer)->Owner == 0,
       "the label query returned more\n");
    RegCloseKey(Key);

    /* A handle without READ_CONTROL: nothing but the empty descriptor */
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_QUERY_VALUE, &KeyQv);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        Status = Query(KeyQv, DACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
        ok_hex(Status, STATUS_ACCESS_DENIED);
        Status = Query(KeyQv, 0, Buffer, sizeof(Buffer), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        RegCloseKey(KeyQv);
    }
}

/* ACCESS_SYSTEM_SECURITY: the privilege decides the open; with it, BACKUP is the whole descriptor */
static void TestSaclAccess(void)
{
    BYTE Buffer[2048];
    ULONG Length;
    HKEY Key = NULL;
    NTSTATUS Status;
    LONG Error;

    As(0);
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, READ_CONTROL | ACCESS_SYSTEM_SECURITY, &Key);
    Self();
    ok_long(Error, ERROR_ACCESS_DENIED);
    if (!Error)
        RegCloseKey(Key);

    Key = NULL;
    As(2);
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, READ_CONTROL | ACCESS_SYSTEM_SECURITY, &Key);
    Self();
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        return;
    Status = Query(Key, BACKUP_SI, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (Status == STATUS_SUCCESS)
    {
        PISECURITY_DESCRIPTOR_RELATIVE Sd = (PISECURITY_DESCRIPTOR_RELATIVE)Buffer;
        ok(Sd->Owner && Sd->Group && (Sd->Control & SE_DACL_PRESENT), "BACKUP: owner %lu group %lu control 0x%x\n",
           Sd->Owner, Sd->Group, Sd->Control);
    }
    Status = Query(Key, SACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    RegCloseKey(Key);
}

static void TestSet(BOOL Admin)
{
    HKEY Root = NULL, Child = NULL, Notify1 = NULL, Notify2 = NULL, Weak = NULL, Sacl = NULL;
    HANDLE Event1, Event2;
    FILETIME Before, After;
    SECURITY_DESCRIPTOR_CONTROL Ctl;
    BOOL Null;
    ULONG Count;
    ACCESS_MASK Mask;
    NTSTATUS Status;
    LONG Error;
    BYTE Buffer[1024];
    ULONG Length;
    WCHAR Sddl[256];
    PWSTR UserSid = NULL;

    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\ReactOS-apitest-RegSecurityQuerySet\\Child");
    RegDeleteKeyW(HKEY_CURRENT_USER, ScratchPath);
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Root, NULL);
    ok_long(Error, ERROR_SUCCESS);
    if (Error)
        return;

    /* A set changes the last write time, and tells security and attribute watchers */
    RegQueryInfoKeyW(Root, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &Before);
    Event1 = CreateEventW(NULL, TRUE, FALSE, NULL);
    Event2 = CreateEventW(NULL, TRUE, FALSE, NULL);
    RegOpenKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, KEY_NOTIFY, &Notify1);
    RegOpenKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, KEY_NOTIFY, &Notify2);
    ok_long(RegNotifyChangeKeyValue(Notify1, FALSE, REG_NOTIFY_CHANGE_SECURITY, Event1, TRUE), ERROR_SUCCESS);
    ok_long(RegNotifyChangeKeyValue(Notify2, FALSE, REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET, Event2, TRUE),
            ERROR_SUCCESS);
    Sleep(20);
    Status = SetSddl(-1, Root, DACL_SECURITY_INFORMATION, L"D:(A;;KA;;;BA)(A;;KR;;;WD)(A;;KA;;;SY)(A;;KA;;;OW)");
    ok_hex(Status, STATUS_SUCCESS);
    ok(WaitForSingleObject(Event1, 2000) == WAIT_OBJECT_0, "no REG_NOTIFY_CHANGE_SECURITY notification\n");
    ok(WaitForSingleObject(Event2, 2000) == WAIT_OBJECT_0, "no attribute notification\n");
    RegQueryInfoKeyW(Root, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &After);
    ok(CompareFileTime(&Before, &After) != 0, "the last write time did not change\n");
    Mask = DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
    ok_long(Count, 4);
    ok_hex(Mask, KEY_READ);

    /* No propagation: a child keeps what it has when the parent's DACL changes */
    Error = RegCreateKeyExW(Root, ChildName, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Child, NULL);
    ok_long(Error, ERROR_SUCCESS);

    /* The parent gets inheritable ACEs: the existing child is not changed */
    Status = SetSddl(-1, Root, DACL_SECURITY_INFORMATION, L"D:(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KA;;;SY)(A;CI;KR;;;AU)(A;;KA;;;OW)");
    ok_hex(Status, STATUS_SUCCESS);
    if (Child)
        ok_hex(DaclMask(Child, WinWorldSid, &Count, &Ctl, &Null), 0);

    /* Generic rights in an ACE that applies to the key are mapped */
    Status = SetSddl(-1, Root, DACL_SECURITY_INFORMATION, L"D:(A;;GR;;;WD)(A;;GA;;;BA)(A;;KA;;;SY)(A;;KA;;;OW)");
    ok_hex(Status, STATUS_SUCCESS);
    ok_hex(DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null), KEY_READ);
    ok_hex(DaclMask(Root, WinBuiltinAdministratorsSid, &Count, &Ctl, &Null), KEY_ALL_ACCESS);

    /* Control bits: AI only with an auto-inherit request, P kept, the info flags ignored */
    SetSddl(-1, Root, DACL_SECURITY_INFORMATION, L"D:AI(A;;KA;;;BA)(A;;KA;;;SY)(A;;KA;;;OW)");
    DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
    ok_hex(Ctl, SE_SELF_RELATIVE | SE_DACL_PRESENT);
    SetSddl(-1, Root, DACL_SECURITY_INFORMATION, L"D:ARAI(A;;KA;;;BA)(A;;KA;;;SY)(A;;KA;;;OW)");
    DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
    ok_hex(Ctl, SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_AUTO_INHERITED);
    SetSddl(-1, Root, DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;;KA;;;OW)");
    DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
    ok_hex(Ctl, SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED);
    SetSddl(-1, Root, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, L"D:(A;;KA;;;BA)(A;;KA;;;SY)(A;;KA;;;OW)");
    DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
    ok_hex(Ctl, SE_SELF_RELATIVE | SE_DACL_PRESENT);
    SetSddl(-1, Root, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, L"D:P(A;;KA;;;BA)(A;;KA;;;SY)(A;;KA;;;OW)");
    DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
    ok_hex(Ctl, SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED);

    /* A NULL DACL, and a descriptor without one, both set a present NULL DACL */
    {
        SECURITY_DESCRIPTOR Abs;

        InitializeSecurityDescriptor(&Abs, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&Abs, TRUE, NULL, FALSE);
        ok_hex(NtSetSecurityObject(Root, DACL_SECURITY_INFORMATION, &Abs), STATUS_SUCCESS);
        DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
        ok(Null, "not a NULL DACL\n");
        ok_hex(Ctl, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        InitializeSecurityDescriptor(&Abs, SECURITY_DESCRIPTOR_REVISION);
        ok_hex(NtSetSecurityObject(Root, DACL_SECURITY_INFORMATION, &Abs), STATUS_SUCCESS);
        DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null);
        ok(Null, "not a NULL DACL\n");
        ok_hex(Ctl, SE_SELF_RELATIVE | SE_DACL_PRESENT);
        /* an owner named but not in the descriptor */
        ok_hex(NtSetSecurityObject(Root, OWNER_SECURITY_INFORMATION, &Abs), STATUS_INVALID_SECURITY_DESCR);
        ok_hex(SetSddl(-1, Root, DACL_SECURITY_INFORMATION, L"D:(A;;KA;;;BA)(A;;KA;;;SY)(A;;KR;;;WD)(A;;KA;;;OW)"), STATUS_SUCCESS);
    }

    /* Nothing named: success, nothing changes */
    ok_hex(SetSddl(-1, Root, 0, L"D:(A;;KA;;;BA)"), STATUS_SUCCESS);
    ok_long((DaclMask(Root, WinWorldSid, &Count, &Ctl, &Null), Count), 4);

    /* The child did not change */
    if (Child)
    {
        Mask = DaclMask(Child, WinWorldSid, &Count, &Ctl, &Null);
        ok_hex(Mask, 0);
        RegCloseKey(Child);
        RegDeleteKeyW(Root, ChildName);
    }

    /* A handle without WRITE_DAC */
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, KEY_READ, &Weak);
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        ok_hex(SetSddl(-1, Weak, DACL_SECURITY_INFORMATION, L"D:(A;;KA;;;BA)"), STATUS_ACCESS_DENIED);
        RegCloseKey(Weak);
    }

    if (!Admin)
    {
        skip("Not an administrator: owner, group and SACL rules not tested\n");
        goto Cleanup;
    }

    /* The owner: the user or an owner group; others only with SeRestorePrivilege, even unchanged */
    {
        HANDLE Process;
        BYTE UserBuffer[256];
        DWORD UserLength;

        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Process);
        GetTokenInformation(Process, TokenUser, UserBuffer, sizeof(UserBuffer), &UserLength);
        CloseHandle(Process);
        ConvertSidToStringSidW(((TOKEN_USER *)UserBuffer)->User.Sid, &UserSid);
    }
    StringCbPrintfW(Sddl, sizeof(Sddl), L"O:%ls", UserSid);
    ok_hex(SetSddl(0, Root, OWNER_SECURITY_INFORMATION, Sddl), STATUS_SUCCESS);
    ok_hex(SetSddl(0, Root, OWNER_SECURITY_INFORMATION, L"O:BA"), STATUS_SUCCESS);
    ok_hex(SetSddl(0, Root, OWNER_SECURITY_INFORMATION, L"O:SY"), STATUS_INVALID_OWNER);
    ok_hex(SetSddl(0, Root, OWNER_SECURITY_INFORMATION, L"O:BU"), STATUS_INVALID_OWNER);
    ok_hex(SetSddl(0, Root, OWNER_SECURITY_INFORMATION, L"O:WD"), STATUS_INVALID_OWNER);
    ok_hex(SetSddl(2, Root, OWNER_SECURITY_INFORMATION, L"O:SY"), STATUS_INVALID_OWNER);
    ok_hex(SetSddl(1, Root, OWNER_SECURITY_INFORMATION, L"O:SY"), STATUS_SUCCESS);
    Status = Query(Root, OWNER_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    {
        PSID Owner = NULL;
        BOOL Defaulted;

        GetSecurityDescriptorOwner(Buffer, &Owner, &Defaulted);
        ok(Owner && IsWellKnownSid(Owner, WinLocalSystemSid), "the owner is not SYSTEM\n");
    }
    ok_hex(SetSddl(0, Root, OWNER_SECURITY_INFORMATION, L"O:SY"), STATUS_INVALID_OWNER);
    ok_hex(SetSddl(0, Root, OWNER_SECURITY_INFORMATION, L"O:BA"), STATUS_SUCCESS);
    /* any group */
    ok_hex(SetSddl(0, Root, GROUP_SECURITY_INFORMATION, L"G:BU"), STATUS_SUCCESS);
    ok_hex(SetSddl(0, Root, GROUP_SECURITY_INFORMATION, L"G:SY"), STATUS_SUCCESS);
    /* RegSetKeySecurity gives the Win32 error */
    {
        PSECURITY_DESCRIPTOR Sd = NULL;

        ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:WD", SDDL_REVISION_1, &Sd, NULL);
        As(0);
        ok_long(RegSetKeySecurity(Root, OWNER_SECURITY_INFORMATION, Sd), ERROR_INVALID_OWNER);
        Self();
        LocalFree(Sd);
    }

    /* SACL and label: separate parts of the SACL */
    ok_hex(SetSddl(2, Root, SACL_SECURITY_INFORMATION, L"S:(AU;SA;KA;;;WD)"), STATUS_ACCESS_DENIED);
    As(2);
    Error = RegOpenKeyExW(HKEY_CURRENT_USER, ScratchPath, 0, READ_CONTROL | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY, &Sacl);
    Self();
    ok_long(Error, ERROR_SUCCESS);
    if (!Error)
    {
        PACL Acl;
        BOOL Present, Defaulted;

        ok_hex(SetSddl(2, Sacl, SACL_SECURITY_INFORMATION, L"S:(AU;SA;KA;;;WD)"), STATUS_SUCCESS);
        ok_hex(SetSddl(0, Sacl, LABEL_SECURITY_INFORMATION, L"S:(ML;;NW;;;LW)"), STATUS_SUCCESS);

        ok_hex(Query(Sacl, LABEL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length), STATUS_SUCCESS);
        Acl = NULL; GetSecurityDescriptorSacl(Buffer, &Present, &Acl, &Defaulted);
        ok(Present && Acl && Acl->AceCount == 1, "label part: %u ACEs\n", Acl ? Acl->AceCount : 0);
        ok_hex(Control(Buffer), SE_SELF_RELATIVE | SE_SACL_PRESENT);

        ok_hex(Query(Sacl, SACL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length), STATUS_SUCCESS);
        Acl = NULL; GetSecurityDescriptorSacl(Buffer, &Present, &Acl, &Defaulted);
        ok(Present && Acl && Acl->AceCount == 1, "audit part: %u ACEs\n", Acl ? Acl->AceCount : 0);

        ok_hex(Query(Sacl, SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length), STATUS_SUCCESS);
        Acl = NULL; GetSecurityDescriptorSacl(Buffer, &Present, &Acl, &Defaulted);
        ok(Present && Acl && Acl->AceCount == 2, "whole SACL: %u ACEs\n", Acl ? Acl->AceCount : 0);

        /* An empty SACL set keeps the label */
        ok_hex(SetSddl(2, Sacl, SACL_SECURITY_INFORMATION, L"S:"), STATUS_SUCCESS);
        ok_hex(Query(Sacl, SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, Buffer, sizeof(Buffer), &Length), STATUS_SUCCESS);
        Acl = NULL; GetSecurityDescriptorSacl(Buffer, &Present, &Acl, &Defaulted);
        ok(Present && Acl && Acl->AceCount == 1, "after an empty SACL: %u ACEs\n", Acl ? Acl->AceCount : 0);
        RegCloseKey(Sacl);
    }

Cleanup:
    if (UserSid)
        LocalFree(UserSid);
    RegCloseKey(Notify1);
    RegCloseKey(Notify2);
    CloseHandle(Event1);
    CloseHandle(Event2);
    RegCloseKey(Root);
    ok_long(RegDeleteKeyW(HKEY_CURRENT_USER, ScratchPath), ERROR_SUCCESS);
}

START_TEST(RegSecurityQuerySet)
{
    BOOL Admin = MakeTokens();

    TestQueryParts();
    if (Admin)
        TestSaclAccess();
    else
        skip("Not an administrator: ACCESS_SYSTEM_SECURITY not tested\n");
    TestSet(Admin);
    if (Tok[0]) CloseHandle(Tok[0]);
    if (Tok[1]) CloseHandle(Tok[1]);
    if (Tok[2]) CloseHandle(Tok[2]);
}
