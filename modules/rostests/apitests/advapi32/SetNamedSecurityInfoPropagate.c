/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SetNamedSecurityInfo / SetSecurityInfo propagate inheritable ACEs to existing children
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Microsoft Learn, SetNamedSecurityInfoW, Remarks: "the system automatically propagates any inheritable access
 * control entries (ACEs) to existing child objects, according to the ACE inheritance rules". A tree of files and
 * directories (an auto-inherited child, a child with an explicit ACE of its own, a protected child, a junction to a
 * directory outside the tree, a child the caller may not change, a chain of 520 directories) and a tree of keys;
 * the root's DACL gains and then loses an inheritable ACE for Users. Not measured on Windows here (the documented
 * rule, and for keys the earlier measured rows of SetSecurityInfoKeyInherit): the skipped child, the junction.
 * SetNamedSecurityInfoPropagatePerf (only with PROPPERF set in the environment) prints the cost on a tree of
 * 100 000 files.
 */

#include "precomp.h"
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <ndk/iofuncs.h>
#include <ndk/rtlfuncs.h>

#define PROP_DEPTH 520

static WCHAR User[128];
static PSID UsersSid;

static PSECURITY_DESCRIPTOR SdFromSddl(PCWSTR Format)
{
    WCHAR Sddl[1024];
    PSECURITY_DESCRIPTOR Sd = NULL;

    StringCbPrintfW(Sddl, sizeof(Sddl), Format, User, User, User, User);
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL), "%S: %lu\n", Sddl, GetLastError());
    return Sd;
}

/* The DACL of a file object as SDDL (LocalFree), read through a handle to the object itself (a link is not followed) */
static PWSTR FileDaclString(PCWSTR Path)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PWSTR String = NULL;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE h;
    NTSTATUS Status;

    /* without SYNCHRONIZE (CreateFile asks for it): a DACL may deny it */
    if (!RtlDosPathNameToNtPathName_U(Path, &Name, NULL, NULL))
        return NULL;
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&h, READ_CONTROL, &Attributes, &Iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_OPEN_REPARSE_POINT);
    RtlFreeUnicodeString(&Name);
    if (!NT_SUCCESS(Status))
        return NULL;
    if (GetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Sd) == ERROR_SUCCESS)
    {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &String, NULL);
        LocalFree(Sd);
    }
    CloseHandle(h);
    return String;
}

/* What an object's DACL says about Users: 0 none, else the mask of the ACE (*Flags its flags) */
static ACCESS_MASK UsersAce(PSECURITY_DESCRIPTOR Sd, PUCHAR Flags, PBOOL AutoInherited)
{
    SECURITY_DESCRIPTOR_CONTROL Control = 0;
    PACCESS_ALLOWED_ACE Ace;
    BOOL Present, Defaulted;
    DWORD Revision, i;
    PACL Dacl = NULL;

    *Flags = 0;
    GetSecurityDescriptorControl(Sd, &Control, &Revision);
    if (AutoInherited)
        *AutoInherited = (Control & SE_DACL_AUTO_INHERITED) != 0;
    if (!GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted) || !Present || !Dacl)
        return 0;
    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (GetAce(Dacl, i, (PVOID *)&Ace) && Ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE &&
            EqualSid((PSID)&Ace->SidStart, UsersSid) && !(Ace->Header.AceFlags & INHERIT_ONLY_ACE))
        {
            *Flags = Ace->Header.AceFlags;
            return Ace->Mask;
        }
    }
    return 0;
}

static ACCESS_MASK FileUsersAce(PCWSTR Path, PUCHAR Flags, PBOOL AutoInherited)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    ACCESS_MASK Mask = 0xdeadbeef;

    if (GetNamedSecurityInfoW((PWSTR)Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Sd) ==
        ERROR_SUCCESS)
    {
        Mask = UsersAce(Sd, Flags, AutoInherited);
        LocalFree(Sd);
    }
    return Mask;
}

static BOOL MakeJunction(PCWSTR Link, PCWSTR Target)
{
    struct
    {
        ULONG ReparseTag;
        USHORT ReparseDataLength, Reserved, SubstituteNameOffset, SubstituteNameLength, PrintNameOffset, PrintNameLength;
        WCHAR PathBuffer[2 * MAX_PATH + 8];
    } Data;
    USHORT cb = (USHORT)(wcslen(Target) * sizeof(WCHAR));
    DWORD Size = 16 + (cb + 8) + cb + 4, Ret;   /* the header and the four name fields, the two names and their nulls */
    HANDLE h;
    BOOL Ok;

    ZeroMemory(&Data, sizeof(Data));
    Data.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    Data.ReparseDataLength = (USHORT)(Size - 8);
    Data.SubstituteNameLength = cb + 8;
    Data.PrintNameOffset = cb + 8 + 2;
    Data.PrintNameLength = cb;
    wcscpy(Data.PathBuffer, L"\\??\\");
    wcscat(Data.PathBuffer, Target);
    wcscpy(&Data.PathBuffer[Data.PrintNameOffset / sizeof(WCHAR)], Target);
    if (!CreateDirectoryW(Link, NULL))
        return FALSE;
    h = CreateFileW(Link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &Data, Size, NULL, 0, &Ret, NULL);
    CloseHandle(h);
    return Ok;
}

static void MakeFile(PCWSTR Path)
{
    HANDLE h = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);

    ok(h != INVALID_HANDLE_VALUE, "%S: %lu\n", Path, GetLastError());
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
}

/* Removes a tree below Path (and Path), without following junctions */
static void RemoveTree(PCWSTR Path)
{
    WCHAR Pattern[2 * MAX_PATH], Child[2 * MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE h;
    DWORD Attributes = GetFileAttributesW(Path);

    if (Attributes == INVALID_FILE_ATTRIBUTES)
        return;
    if ((Attributes & FILE_ATTRIBUTE_DIRECTORY) && !(Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        StringCbPrintfW(Pattern, sizeof(Pattern), L"%s\\*", Path);
        h = FindFirstFileW(Pattern, &Find);
        if (h != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (wcscmp(Find.cFileName, L".") && wcscmp(Find.cFileName, L".."))
                {
                    StringCbPrintfW(Child, sizeof(Child), L"%s\\%s", Path, Find.cFileName);
                    RemoveTree(Child);
                }
            } while (FindNextFileW(h, &Find));
            FindClose(h);
        }
    }
    SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
    if (Attributes & FILE_ATTRIBUTE_DIRECTORY)
        RemoveDirectoryW(Path);
    else
        DeleteFileW(Path);
}

/* Sets the root's DACL (protected): SYSTEM, Administrators and the user full, and Users read when WithUsers */
static DWORD SetRoot(PCWSTR Root, BOOL WithUsers, BOOL ByHandle)
{
    PSECURITY_DESCRIPTOR Sd = SdFromSddl(WithUsers ? L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)(A;OICI;FR;;;BU)"
                                                   : L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)");
    BOOL Present, Defaulted;
    PACL Dacl = NULL;
    DWORD Error;
    HANDLE h;

    GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
    if (ByHandle)
    {
        h = CreateFileW(Root, READ_CONTROL | WRITE_DAC, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        ok(h != INVALID_HANDLE_VALUE, "open %S: %lu\n", Root, GetLastError());
        Error = SetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                NULL, NULL, Dacl, NULL);
        CloseHandle(h);
    }
    else
    {
        Error = SetNamedSecurityInfoW((PWSTR)Root, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                      NULL, NULL, Dacl, NULL);
    }
    LocalFree(Sd);
    return Error;
}

static void TestFiles(VOID)
{
    WCHAR Temp[MAX_PATH], Root[MAX_PATH], Path[MAX_PATH], Target[MAX_PATH], Deep[PROP_DEPTH * 2 + MAX_PATH];
    PWSTR Before[4], After, HardLinkBefore = NULL;
    PSECURITY_DESCRIPTOR Sd;
    BOOL Present, Defaulted, Auto, HardLink;
    PACL Dacl = NULL;
    UCHAR Flags;
    ACCESS_MASK Mask;
    DWORD Error, i;
    static const PCWSTR Fixed[4] = { L"prot", L"prot\\f", L"noaccess", L"noaccess\\f" };

    GetTempPathW(_countof(Temp), Temp);
    StringCbPrintfW(Root, sizeof(Root), L"%sProp%lu", Temp, GetCurrentProcessId());
    StringCbPrintfW(Target, sizeof(Target), L"%sPropTarget%lu", Temp, GetCurrentProcessId());
    RemoveTree(Root);
    RemoveTree(Target);

    /* The tree, under a protected root without Users */
    ok(CreateDirectoryW(Root, NULL), "%S: %lu\n", Root, GetLastError());
    ok(SetRoot(Root, FALSE, FALSE) == ERROR_SUCCESS, "root\n");
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a", Root);            CreateDirectoryW(Path, NULL);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\f1", Root);        MakeFile(Path);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\sub", Root);       CreateDirectoryW(Path, NULL);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\sub\\f2", Root);   MakeFile(Path);

    /* expl: an explicit ACE of its own (a SID of nobody), inheriting the rest */
    StringCbPrintfW(Path, sizeof(Path), L"%s\\expl", Root);
    CreateDirectoryW(Path, NULL);
    Sd = SdFromSddl(L"D:(A;;FR;;;S-1-5-21-1-2-3-4242)");
    GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
    Error = SetNamedSecurityInfoW(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                  NULL, NULL, Dacl, NULL);
    ok(Error == ERROR_SUCCESS, "expl: %lu\n", Error);
    LocalFree(Sd);

    /* prot: protected, with a file */
    StringCbPrintfW(Path, sizeof(Path), L"%s\\prot", Root);
    CreateDirectoryW(Path, NULL);
    Sd = SdFromSddl(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)");
    GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
    ok(SetNamedSecurityInfoW(Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                             NULL, NULL, Dacl, NULL) == ERROR_SUCCESS, "prot\n");
    LocalFree(Sd);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\prot\\f", Root);
    MakeFile(Path);

    /* noaccess: unprotected, but the caller may not change its DACL (no WRITE_DAC, the owner only READ_CONTROL) */
    StringCbPrintfW(Path, sizeof(Path), L"%s\\noaccess\\f", Root);
    StringCbPrintfW(Deep, sizeof(Deep), L"%s\\noaccess", Root);
    CreateDirectoryW(Deep, NULL);
    MakeFile(Path);
    Sd = SdFromSddl(L"D:(D;;WD;;;%s)(D;;WD;;;BA)(A;;RC;;;S-1-3-4)(A;OICI;FA;;;%s)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)");
    ok(SetFileSecurityW(Deep, DACL_SECURITY_INFORMATION, Sd), "noaccess: %lu\n", GetLastError());
    LocalFree(Sd);

    /*
     * J: a junction to a directory outside the tree, with a file; both with entries flagged inherited, so that a walk
     * that followed the junction would take them for children that inherit and change them
     */
    ok(CreateDirectoryW(Target, NULL), "%S: %lu\n", Target, GetLastError());
    Sd = SdFromSddl(L"D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;%s)");
    ok(SetFileSecurityW(Target, DACL_SECURITY_INFORMATION, Sd), "target: %lu\n", GetLastError());
    LocalFree(Sd);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\tf", Target);
    MakeFile(Path);
    Sd = SdFromSddl(L"D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;%s)");
    ok(SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Sd), "tf: %lu\n", GetLastError());
    LocalFree(Sd);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\J", Root);
    ok(MakeJunction(Path, Target), "junction: %lu\n", GetLastError());

    /*
     * a\hl: a hard link to the file hf outside the tree, whose DACL has entries flagged inherited (so the walk would
     * take it for a child that inherits): it is another object's descriptor, left alone
     */
    StringCbPrintfW(Path, sizeof(Path), L"%s\\hf", Target);
    MakeFile(Path);
    Sd = SdFromSddl(L"D:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;%s)");
    ok(SetFileSecurityW(Path, DACL_SECURITY_INFORMATION, Sd), "hf: %lu\n", GetLastError());
    LocalFree(Sd);
    StringCbPrintfW(Deep, sizeof(Deep), L"%s\\a\\hl", Root);
    HardLink = CreateHardLinkW(Deep, Path, NULL);
    ok(HardLink, "CreateHardLinkW: %lu\n", GetLastError());
    HardLinkBefore = FileDaclString(Path);
    ok(HardLinkBefore != NULL, "hf: no DACL\n");

    /* a chain of PROP_DEPTH directories below a */
    StringCbPrintfW(Deep, sizeof(Deep), L"\\\\?\\%s\\a", Root);
    for (i = 0; i < PROP_DEPTH; i++)
    {
        StringCbCatW(Deep, sizeof(Deep), L"\\d");
        if (!CreateDirectoryW(Deep, NULL))
        {
            ok(0, "depth %lu: %lu\n", i, GetLastError());
            break;
        }
    }

    for (i = 0; i < _countof(Fixed); i++)
    {
        StringCbPrintfW(Path, sizeof(Path), L"%s\\%s", Root, Fixed[i]);
        Before[i] = FileDaclString(Path);
        ok(Before[i] != NULL, "%S: no DACL\n", Path);
    }
    {
        PWSTR TargetBefore = FileDaclString(Target), TargetFileBefore;

        StringCbPrintfW(Path, sizeof(Path), L"%s\\tf", Target);
        TargetFileBefore = FileDaclString(Path);

        /* 1. Users read goes on the root: the children follow */
        Error = SetRoot(Root, TRUE, FALSE);
        ok(Error == ERROR_SUCCESS, "SetNamedSecurityInfoW: %lu\n", Error);

        StringCbPrintfW(Path, sizeof(Path), L"%s\\a", Root);
        Mask = FileUsersAce(Path, &Flags, &Auto);
        ok(Mask == FILE_GENERIC_READ && (Flags & INHERITED_ACE) && (Flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) ==
           (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) && Auto, "a: Users %#lx flags %#x auto %d\n", Mask, Flags, Auto);
        StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\f1", Root);
        Mask = FileUsersAce(Path, &Flags, &Auto);
        ok(Mask == FILE_GENERIC_READ && Flags == INHERITED_ACE && Auto, "a\\f1: Users %#lx flags %#x auto %d\n", Mask, Flags, Auto);
        StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\sub\\f2", Root);
        Mask = FileUsersAce(Path, &Flags, &Auto);
        ok(Mask == FILE_GENERIC_READ && Flags == INHERITED_ACE, "a\\sub\\f2: Users %#lx flags %#x\n", Mask, Flags);
        Mask = FileUsersAce(Deep, &Flags, &Auto);
        ok(Mask == FILE_GENERIC_READ && (Flags & INHERITED_ACE), "depth %u: Users %#lx flags %#x\n", PROP_DEPTH, Mask, Flags);

        /* expl keeps its own ACE, first, and inherits Users after it */
        StringCbPrintfW(Path, sizeof(Path), L"%s\\expl", Root);
        After = FileDaclString(Path);
        ok(After && !wcsncmp(After, L"D:AI(A;;FR;;;S-1-5-21-1-2-3-4242)", wcslen(L"D:AI(A;;FR;;;S-1-5-21-1-2-3-4242)")),
           "expl: %S\n", After);
        ok(After && wcsstr(After, L"(A;OICIID;FR;;;BU)") != NULL, "expl: %S\n", After);
        LocalFree(After);

        /* protected, not changeable, behind the junction: as they were */
        for (i = 0; i < _countof(Fixed); i++)
        {
            StringCbPrintfW(Path, sizeof(Path), L"%s\\%s", Root, Fixed[i]);
            After = FileDaclString(Path);
            ok(Before[i] && After && !wcscmp(Before[i], After), "%s: %S -> %S\n", Fixed[i], Before[i], After);
            LocalFree(After);
        }
        After = FileDaclString(Target);
        ok(TargetBefore && After && !wcscmp(TargetBefore, After), "junction target: %S -> %S\n", TargetBefore, After);
        LocalFree(After);
        StringCbPrintfW(Path, sizeof(Path), L"%s\\tf", Target);
        After = FileDaclString(Path);
        ok(TargetFileBefore && After && !wcscmp(TargetFileBefore, After), "file behind the junction: %S -> %S\n",
           TargetFileBefore, After);
        LocalFree(After);
        if (HardLink)
        {
            StringCbPrintfW(Path, sizeof(Path), L"%s\\hf", Target);
            After = FileDaclString(Path);
            ok(HardLinkBefore && After && !wcscmp(HardLinkBefore, After), "file with a hard link in the tree: %S -> %S\n",
               HardLinkBefore, After);
            LocalFree(After);
        }
        LocalFree(TargetBefore);
        LocalFree(TargetFileBefore);
    }

    /* 2. Users goes again: so does what the children inherited */
    Error = SetRoot(Root, FALSE, FALSE);
    ok(Error == ERROR_SUCCESS, "SetNamedSecurityInfoW: %lu\n", Error);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\f1", Root);
    Mask = FileUsersAce(Path, &Flags, NULL);
    ok(Mask == 0, "a\\f1: Users %#lx flags %#x after the removal\n", Mask, Flags);
    Mask = FileUsersAce(Deep, &Flags, NULL);
    ok(Mask == 0, "depth %u: Users %#lx after the removal\n", PROP_DEPTH, Mask);

    /* 3. SetSecurityInfo through a handle does the same */
    Error = SetRoot(Root, TRUE, TRUE);
    ok(Error == ERROR_SUCCESS, "SetSecurityInfo: %lu\n", Error);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\sub\\f2", Root);
    Mask = FileUsersAce(Path, &Flags, NULL);
    ok(Mask == FILE_GENERIC_READ && Flags == INHERITED_ACE, "handle: a\\sub\\f2: Users %#lx flags %#x\n", Mask, Flags);

    for (i = 0; i < _countof(Fixed); i++)
        LocalFree(Before[i]);
    if (HardLinkBefore)
        LocalFree(HardLinkBefore);

    /* cleanup: the junction first (RemoveTree does not follow it), the deep chain through the extended path */
    StringCbPrintfW(Path, sizeof(Path), L"%s\\J", Root);
    RemoveDirectoryW(Path);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\hl", Root);
    DeleteFileW(Path);
    for (i = PROP_DEPTH; i > 0; i--)
    {
        RemoveDirectoryW(Deep);
        *wcsrchr(Deep, L'\\') = UNICODE_NULL;
    }
    RemoveTree(Root);
    RemoveTree(Target);
}

static ACCESS_MASK KeyUsersAce(HKEY Root, PCWSTR Sub, PUCHAR Flags)
{
    UCHAR Buffer[4096];
    DWORD Size = sizeof(Buffer);
    HKEY Key;
    ACCESS_MASK Mask = 0xdeadbeef;

    if (RegOpenKeyExW(Root, Sub, 0, READ_CONTROL, &Key) == ERROR_SUCCESS)
    {
        if (RegGetKeySecurity(Key, DACL_SECURITY_INFORMATION, Buffer, &Size) == ERROR_SUCCESS)
            Mask = UsersAce(Buffer, Flags, NULL);
        RegCloseKey(Key);
    }
    return Mask;
}

static void TestKeys(VOID)
{
    WCHAR Name[64];
    PSECURITY_DESCRIPTOR Sd;
    BOOL Present, Defaulted;
    PACL Dacl = NULL;
    HKEY Root = NULL, Sub;
    UCHAR Flags, Buffer[4096];
    DWORD Error, Size = sizeof(Buffer);
    PWSTR Before = NULL, After = NULL;
    ACCESS_MASK Mask;

    StringCbPrintfW(Name, sizeof(Name), L"Software\\Prop%lu", GetCurrentProcessId());
    Error = RegCreateKeyExW(HKEY_CURRENT_USER, Name, 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Root, NULL);
    ok(Error == ERROR_SUCCESS, "RegCreateKeyExW: %lu\n", Error);
    if (Error)
        return;
    RegCreateKeyExW(Root, L"a", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Sub, NULL);
    RegCloseKey(Sub);
    RegCreateKeyExW(Root, L"a\\b", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Sub, NULL);
    RegCloseKey(Sub);
    RegCreateKeyExW(Root, L"prot", 0, NULL, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &Sub, NULL);
    Sd = SdFromSddl(L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;%s)");
    GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
    ok(SetSecurityInfo(Sub, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL,
                       Dacl, NULL) == ERROR_SUCCESS, "prot key\n");
    LocalFree(Sd);
    if (RegGetKeySecurity(Sub, DACL_SECURITY_INFORMATION, Buffer, &Size) == ERROR_SUCCESS)
        ConvertSecurityDescriptorToStringSecurityDescriptorW(Buffer, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &Before, NULL);
    RegCloseKey(Sub);

    Sd = SdFromSddl(L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;%s)(A;CI;KR;;;BU)");
    GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
    Error = SetSecurityInfo(Root, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL,
                            NULL, Dacl, NULL);
    ok(Error == ERROR_SUCCESS, "SetSecurityInfo key: %lu\n", Error);
    LocalFree(Sd);

    Mask = KeyUsersAce(Root, L"a", &Flags);
    ok(Mask == KEY_READ && (Flags & INHERITED_ACE), "key a: Users %#lx flags %#x\n", Mask, Flags);
    Mask = KeyUsersAce(Root, L"a\\b", &Flags);
    ok(Mask == KEY_READ && (Flags & INHERITED_ACE), "key a\\b: Users %#lx flags %#x\n", Mask, Flags);
    if (RegOpenKeyExW(Root, L"prot", 0, READ_CONTROL, &Sub) == ERROR_SUCCESS)
    {
        Size = sizeof(Buffer);
        if (RegGetKeySecurity(Sub, DACL_SECURITY_INFORMATION, Buffer, &Size) == ERROR_SUCCESS)
            ConvertSecurityDescriptorToStringSecurityDescriptorW(Buffer, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &After, NULL);
        RegCloseKey(Sub);
    }
    ok(Before && After && !wcscmp(Before, After), "protected key: %S -> %S\n", Before, After);
    LocalFree(Before);
    LocalFree(After);

    RegDeleteKeyW(Root, L"a\\b");
    RegDeleteKeyW(Root, L"a");
    RegDeleteKeyW(Root, L"prot");
    RegCloseKey(Root);
    RegDeleteKeyW(HKEY_CURRENT_USER, Name);
}

/* Sets the DACL of Path from SDDL (the user's SID in place of every %s), with the protection given */
static DWORD SetFromSddl(PCWSTR Path, PCWSTR Format, DWORD Protection)
{
    PSECURITY_DESCRIPTOR Sd = SdFromSddl(Format);
    BOOL Present, Defaulted;
    PACL Dacl = NULL;
    DWORD Error;

    GetSecurityDescriptorDacl(Sd, &Present, &Dacl, &Defaulted);
    Error = SetNamedSecurityInfoW((PWSTR)Path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | Protection, NULL, NULL, Dacl, NULL);
    LocalFree(Sd);
    return Error;
}

/*
 * An entry that denies SYNCHRONIZE (to Everyone, say) in the DACL of the directories below the one that is set: the
 * children cannot be opened with SYNCHRONIZE, but READ_CONTROL | WRITE_DAC and FILE_LIST_DIRECTORY open without it
 * (Windows Server 2022: an open with SYNCHRONIZE is refused, the others work), and the propagation changes them all.
 */
static void TestDeniedSynchronize(VOID)
{
    WCHAR Temp[MAX_PATH], Root[MAX_PATH], Path[MAX_PATH], Sub[MAX_PATH];
    PWSTR After;
    DWORD Error;
    static const PCWSTR Names[] = { L"a", L"a\\f1", L"a\\sub", L"a\\sub\\f2" };
    ULONG i;

    GetTempPathW(_countof(Temp), Temp);
    StringCbPrintfW(Root, sizeof(Root), L"%sPropSync%lu", Temp, GetCurrentProcessId());
    RemoveTree(Root);
    ok(CreateDirectoryW(Root, NULL), "%S: %lu\n", Root, GetLastError());
    ok(SetFromSddl(Root, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", PROTECTED_DACL_SECURITY_INFORMATION) == ERROR_SUCCESS,
       "root\n");
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a", Root);          CreateDirectoryW(Path, NULL);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\f1", Root);      MakeFile(Path);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\sub", Root);     CreateDirectoryW(Path, NULL);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\sub\\f2", Root); MakeFile(Path);

    /* 1. Everyone is denied SYNCHRONIZE on the root: the children get the entry */
    Error = SetFromSddl(Root, L"D:P(D;OICI;0x100000;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)",
                        PROTECTED_DACL_SECURITY_INFORMATION);
    ok(Error == ERROR_SUCCESS, "denying SYNCHRONIZE: %lu\n", Error);
    for (i = 0; i < _countof(Names); i++)
    {
        StringCbPrintfW(Path, sizeof(Path), L"%s\\%s", Root, Names[i]);
        After = FileDaclString(Path);
        ok(After && wcsstr(After, L"(D;") != NULL, "%s: %S\n", Names[i], After ? After : L"(none)");
        LocalFree(After);
    }

    /* 2. The entry goes again: so does what the children inherited, though they cannot be opened with SYNCHRONIZE */
    Error = SetFromSddl(Root, L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", PROTECTED_DACL_SECURITY_INFORMATION);
    ok(Error == ERROR_SUCCESS, "removing it: %lu\n", Error);
    for (i = 0; i < _countof(Names); i++)
    {
        StringCbPrintfW(Path, sizeof(Path), L"%s\\%s", Root, Names[i]);
        After = FileDaclString(Path);
        ok(After && wcsstr(After, L"(D;") == NULL, "%s still has the entry: %S\n", Names[i], After ? After : L"(none)");
        LocalFree(After);
    }

    /* 3. The same with a directory in the middle that is reset: a\sub denies SYNCHRONIZE of its own, a is reset */
    StringCbPrintfW(Sub, sizeof(Sub), L"%s\\a", Root);
    Error = SetFromSddl(Sub, L"D:(D;OICI;0x100000;;;WD)", UNPROTECTED_DACL_SECURITY_INFORMATION);
    ok(Error == ERROR_SUCCESS, "denying on a: %lu\n", Error);
    StringCbPrintfW(Path, sizeof(Path), L"%s\\a\\sub\\f2", Root);
    After = FileDaclString(Path);
    ok(After && wcsstr(After, L"(D;") != NULL, "a\\sub\\f2: %S\n", After ? After : L"(none)");
    LocalFree(After);
    Error = SetFromSddl(Sub, L"D:", UNPROTECTED_DACL_SECURITY_INFORMATION);
    ok(Error == ERROR_SUCCESS, "reset of a: %lu\n", Error);
    After = FileDaclString(Path);
    ok(After && wcsstr(After, L"(D;") == NULL, "a\\sub\\f2 after the reset of a: %S\n", After ? After : L"(none)");
    LocalFree(After);

    RemoveTree(Root);
}

static BOOL Init(VOID)
{
    UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    DWORD Length, Size = SECURITY_MAX_SID_SIZE;
    HANDLE Token;
    PWSTR String;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
        return FALSE;
    GetTokenInformation(Token, TokenUser, Buffer, sizeof(Buffer), &Length);
    CloseHandle(Token);
    if (!ConvertSidToStringSidW(((PTOKEN_USER)Buffer)->User.Sid, &String))
        return FALSE;
    StringCbCopyW(User, sizeof(User), String);
    LocalFree(String);
    UsersSid = LocalAlloc(LPTR, Size);
    return UsersSid && CreateWellKnownSid(WinBuiltinUsersSid, NULL, UsersSid, &Size);
}

START_TEST(SetNamedSecurityInfoPropagate)
{
    WCHAR Root[MAX_PATH];
    DWORD FileSystemFlags = 0;

    if (!Init())
    {
        skip("no token user\n");
        return;
    }
    GetTempPathW(_countof(Root), Root);
    Root[3] = UNICODE_NULL;
    if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &FileSystemFlags, NULL, 0) ||
        GetNamedSecurityInfoW(Root, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, NULL) == ERROR_NOT_SUPPORTED)
    {
        skip("no ACLs on %S\n", Root);
    }
    else
    {
        TestFiles();
        TestDeniedSynchronize();
    }
    TestKeys();
    LocalFree(UsersSid);
}

/* The cost: a tree of 100 directories of 1 000 files (and 100 000 objects), Users added to and removed from the root */
START_TEST(SetNamedSecurityInfoPropagatePerf)
{
    WCHAR Temp[MAX_PATH], Root[MAX_PATH], Path[MAX_PATH];
    LARGE_INTEGER Frequency, Start, End;
    DWORD d, f, Error;
    HANDLE h;

    /* minutes on a slow disk: only when asked for */
    if (!GetEnvironmentVariableW(L"PROPPERF", Temp, _countof(Temp)))
    {
        skip("set PROPPERF=1 to measure\n");
        return;
    }
    if (!Init())
        return;
    QueryPerformanceFrequency(&Frequency);
    GetTempPathW(_countof(Temp), Temp);
    StringCbPrintfW(Root, sizeof(Root), L"%sPropPerf%lu", Temp, GetCurrentProcessId());
    CreateDirectoryW(Root, NULL);
    SetRoot(Root, FALSE, FALSE);
    QueryPerformanceCounter(&Start);
    for (d = 0; d < 100; d++)
    {
        StringCbPrintfW(Path, sizeof(Path), L"%s\\d%03lu", Root, d);
        CreateDirectoryW(Path, NULL);
        for (f = 0; f < 1000; f++)
        {
            StringCbPrintfW(Path, sizeof(Path), L"%s\\d%03lu\\f%04lu", Root, d, f);
            h = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
            if (h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    }
    QueryPerformanceCounter(&End);
    trace("PROPPERF create 100100 objects ms %I64u\n", (End.QuadPart - Start.QuadPart) * 1000 / Frequency.QuadPart);

    QueryPerformanceCounter(&Start);
    Error = SetRoot(Root, TRUE, FALSE);
    QueryPerformanceCounter(&End);
    trace("PROPPERF set+propagate (add Users) rc %lu ms %I64u\n", Error, (End.QuadPart - Start.QuadPart) * 1000 / Frequency.QuadPart);

    QueryPerformanceCounter(&Start);
    Error = SetRoot(Root, TRUE, FALSE);
    QueryPerformanceCounter(&End);
    trace("PROPPERF set again (nothing changes below) rc %lu ms %I64u\n", Error, (End.QuadPart - Start.QuadPart) * 1000 / Frequency.QuadPart);

    QueryPerformanceCounter(&Start);
    Error = SetRoot(Root, FALSE, FALSE);
    QueryPerformanceCounter(&End);
    trace("PROPPERF set+propagate (remove Users) rc %lu ms %I64u\n", Error, (End.QuadPart - Start.QuadPart) * 1000 / Frequency.QuadPart);

    StringCbPrintfW(Path, sizeof(Path), L"%s\\d050\\f0500", Root);
    {
        UCHAR Flags;
        ACCESS_MASK Mask = FileUsersAce(Path, &Flags, NULL);
        ok(Mask == 0, "after the removal: %#lx\n", Mask);
    }
    RemoveTree(Root);
}
