/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The flags of label ACEs and the auto-inherit control bit of the descriptors of new files, directories, keys and named objects
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/obfuncs.h>
#include <ndk/exfuncs.h>
#include <ndk/rtlfuncs.h>
#include <sddl.h>
#include <aclapi.h>

/*
 * Measured on Windows Server 2022 (x64 and x86 under WoW64; creators at High, Medium and Low, the same rows): an object made
 * in a parent whose SACL carries the label (ML;OICI;NW;;;LW) gets the label inherited with INHERITED_ACE (a file and an event
 * (ML;ID;..), a directory and a key (ML;OICIID;..)) and the descriptor's control has SE_SACL_AUTO_INHERITED, SDDL "S:AI"; an
 * explicit label ACE of the creator replaces the inherited one (one label ACE, no ID flag, also AI) and loses its OI and CI
 * flags on a file and an event (a directory and a key keep them); a parent whose SACL has no ACE that applies to the object
 * (the label is CI only, the object a file) still marks the new object's control AI, with no SACL.
 */

typedef struct { PCSTR Name; PCWSTR Explicit; PCWSTR Want[4]; } ROW;   /* file, dir, key, event */

static const ROW Rows[] =
{
    {"inherit", NULL,
     {L"S:AI(ML;ID;NW;;;LW)", L"S:AI(ML;OICIID;NW;;;LW)", L"S:AI(ML;OICIID;NW;;;LW)", L"S:AI(ML;ID;NW;;;LW)"}},
    {"explicit label", L"D:(A;;GA;;;WD)S:(ML;;NW;;;LW)",
     {L"S:AI(ML;;NW;;;LW)", L"S:AI(ML;;NW;;;LW)", L"S:AI(ML;;NW;;;LW)", L"S:AI(ML;;NW;;;LW)"}},
    {"explicit label OICI", L"D:(A;;GA;;;WD)S:(ML;OICI;NW;;;LW)",
     {L"S:AI(ML;;NW;;;LW)", L"S:AI(ML;OICI;NW;;;LW)", L"S:AI(ML;OICI;NW;;;LW)", L"S:AI(ML;;NW;;;LW)"}},
};

static VOID Describe(HANDLE Handle, PCWSTR Path, SE_OBJECT_TYPE Type, PWSTR Out, ULONG OutSize, PWORD Control)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    PWSTR Text = NULL;
    DWORD Error, Revision;
    SECURITY_DESCRIPTOR_CONTROL Ctl = 0;

    Out[0] = 0;
    *Control = 0;
    if (Handle)
        Error = GetSecurityInfo(Handle, Type, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Sd);
    else
        Error = GetNamedSecurityInfoW((PWSTR)Path, Type, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &Sd);
    if (Error)
    {
        StringCchPrintfW(Out, OutSize, L"error %lu", Error);
        return;
    }
    GetSecurityDescriptorControl(Sd, &Ctl, &Revision);
    *Control = Ctl;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(Sd, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &Text, NULL))
    {
        StringCchCopyW(Out, OutSize, Text);
        LocalFree(Text);
    }
    LocalFree(Sd);
}

static PSECURITY_DESCRIPTOR Make(PCWSTR Sddl)
{
    PSECURITY_DESCRIPTOR Sd = NULL;
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL), "SDDL %ls: %lu\n", Sddl, GetLastError());
    return Sd;
}

static VOID InitName(UNICODE_STRING *Name, PCWSTR Text)
{
    RtlInitUnicodeString(Name, Text);
}

START_TEST(LabelAutoInherit)
{
    WCHAR BaseDir[MAX_PATH], KeyBase[128], ObjDir[200], Text[512], Path[MAX_PATH], Windows[MAX_PATH];
    SECURITY_ATTRIBUTES Sa = {sizeof(Sa), NULL, FALSE}, *Psa;
    PSECURITY_DESCRIPTOR Parent, Explicit;
    HANDLE Dir = NULL, Handle;
    DWORD Session = 0, Disposition;
    HKEY Root = NULL, Key;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES Oa;
    UNICODE_STRING Name;
    WORD Control;
    ULONG r;

    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    GetWindowsDirectoryW(Windows, RTL_NUMBER_OF(Windows));
    StringCchPrintfW(BaseDir, RTL_NUMBER_OF(BaseDir), L"%.2s\\lai%lu", Windows, GetCurrentProcessId());
    StringCchPrintfW(KeyBase, RTL_NUMBER_OF(KeyBase), L"Software\\LaiTest%lu", GetCurrentProcessId());
    if (Session == 0)
        StringCchPrintfW(ObjDir, RTL_NUMBER_OF(ObjDir), L"\\BaseNamedObjects\\lai%lu", GetCurrentProcessId());
    else
        StringCchPrintfW(ObjDir, RTL_NUMBER_OF(ObjDir), L"\\Sessions\\%lu\\BaseNamedObjects\\lai%lu", Session, GetCurrentProcessId());

    {
        WCHAR Root[4] = {Windows[0], L':', L'\\', 0}, Fs[MAX_PATH];
        DWORD Flags = 0;

        if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &Flags, Fs, RTL_NUMBER_OF(Fs)) ||
            !((Flags & FILE_PERSISTENT_ACLS) || !_wcsicmp(Fs, L"NTFS")))
        {
            skip("the volume keeps no security descriptors (FAT)\n");
            return;
        }
    }

    /* The parents: a label (ML;OICI;NW;;;LW), Everyone full control, inheritable */
    Parent = Make(L"D:P(A;OICI;GA;;;WD)S:(ML;OICI;NW;;;LW)");
    if (!Parent)
        return;
    Sa.lpSecurityDescriptor = Parent;
    ok(CreateDirectoryW(BaseDir, &Sa), "CreateDirectory %ls: %lu\n", BaseDir, GetLastError());
    ok(RegCreateKeyExW(HKEY_CURRENT_USER, KeyBase, 0, NULL, 0, KEY_ALL_ACCESS, &Sa, &Root, &Disposition) == ERROR_SUCCESS, "RegCreateKeyEx %ls\n", KeyBase);
    InitName(&Name, ObjDir);
    InitializeObjectAttributes(&Oa, &Name, OBJ_CASE_INSENSITIVE, NULL, Parent);
    Status = NtCreateDirectoryObject(&Dir, DIRECTORY_ALL_ACCESS, &Oa);
    ok(NT_SUCCESS(Status), "NtCreateDirectoryObject %ls: 0x%lx\n", ObjDir, Status);

    for (r = 0; r < RTL_NUMBER_OF(Rows); r++)
    {
        Explicit = Rows[r].Explicit ? Make(Rows[r].Explicit) : NULL;
        Sa.lpSecurityDescriptor = Explicit;
        Psa = Explicit ? &Sa : NULL;

        /* a file */
        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\f%lu", BaseDir, r);
        Handle = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, Psa, CREATE_NEW, 0, NULL);
        ok(Handle != INVALID_HANDLE_VALUE, "%s: CreateFile: %lu\n", Rows[r].Name, GetLastError());
        if (Handle != INVALID_HANDLE_VALUE)
        {
            Describe(Handle, NULL, SE_FILE_OBJECT, Text, RTL_NUMBER_OF(Text), &Control);
            ok(!wcscmp(Text, Rows[r].Want[0]), "%s file: %ls, expected %ls\n", Rows[r].Name, Text, Rows[r].Want[0]);
            ok(Control & SE_SACL_AUTO_INHERITED, "%s file: control 0x%x\n", Rows[r].Name, Control);
            CloseHandle(Handle);
        }
        /* a directory */
        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\d%lu", BaseDir, r);
        if (CreateDirectoryW(Path, Psa))
        {
            Handle = CreateFileW(Path, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            if (Handle != INVALID_HANDLE_VALUE)
            {
                Describe(Handle, NULL, SE_FILE_OBJECT, Text, RTL_NUMBER_OF(Text), &Control);
                ok(!wcscmp(Text, Rows[r].Want[1]), "%s directory: %ls, expected %ls\n", Rows[r].Name, Text, Rows[r].Want[1]);
                ok(Control & SE_SACL_AUTO_INHERITED, "%s directory: control 0x%x\n", Rows[r].Name, Control);
                CloseHandle(Handle);
            }
        }
        else
            ok(0, "%s: CreateDirectory: %lu\n", Rows[r].Name, GetLastError());
        /* a key */
        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"k%lu", r);
        if (Root && RegCreateKeyExW(Root, Path, 0, NULL, 0, KEY_ALL_ACCESS, Psa, &Key, &Disposition) == ERROR_SUCCESS)
        {
            Describe((HANDLE)Key, NULL, SE_REGISTRY_KEY, Text, RTL_NUMBER_OF(Text), &Control);
            ok(!wcscmp(Text, Rows[r].Want[2]), "%s key: %ls, expected %ls\n", Rows[r].Name, Text, Rows[r].Want[2]);
            ok(Control & SE_SACL_AUTO_INHERITED, "%s key: control 0x%x\n", Rows[r].Name, Control);
            RegCloseKey(Key);
        }
        /* an event in the object directory */
        if (Dir)
        {
            HANDLE Event = NULL;
            OBJECT_ATTRIBUTES EventOa;
            UNICODE_STRING EventName;
            WCHAR EventText[32];

            StringCchPrintfW(EventText, RTL_NUMBER_OF(EventText), L"ev%lu", r);
            InitName(&EventName, EventText);
            InitializeObjectAttributes(&EventOa, &EventName, OBJ_CASE_INSENSITIVE, Dir, Explicit);
            Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS | READ_CONTROL, &EventOa, NotificationEvent, FALSE);
            ok(NT_SUCCESS(Status), "%s: NtCreateEvent: 0x%lx\n", Rows[r].Name, Status);
            if (NT_SUCCESS(Status))
            {
                Describe(Event, NULL, SE_KERNEL_OBJECT, Text, RTL_NUMBER_OF(Text), &Control);
                ok(!wcscmp(Text, Rows[r].Want[3]), "%s event: %ls, expected %ls\n", Rows[r].Name, Text, Rows[r].Want[3]);
                ok(Control & SE_SACL_AUTO_INHERITED, "%s event: control 0x%x\n", Rows[r].Name, Control);
                CloseHandle(Event);
            }
        }
        if (Explicit)
            LocalFree(Explicit);
    }

    /* Below a CI-only label a file gets no label, but its control is marked */
    {
        PSECURITY_DESCRIPTOR CiParent = Make(L"D:P(A;OICI;GA;;;WD)S:(ML;CI;NW;;;LW)");
        WCHAR CiDir[MAX_PATH];

        if (CiParent)
        {
            Sa.lpSecurityDescriptor = CiParent;
            StringCchPrintfW(CiDir, RTL_NUMBER_OF(CiDir), L"%ls\\ci", BaseDir);
            if (CreateDirectoryW(CiDir, &Sa))
            {
                StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\f", CiDir);
                Handle = CreateFileW(Path, GENERIC_WRITE | READ_CONTROL, 0, NULL, CREATE_NEW, 0, NULL);
                ok(Handle != INVALID_HANDLE_VALUE, "CreateFile %ls: %lu\n", Path, GetLastError());
                if (Handle != INVALID_HANDLE_VALUE)
                {
                    Describe(Handle, NULL, SE_FILE_OBJECT, Text, RTL_NUMBER_OF(Text), &Control);
                    ok(Text[0] == 0, "CI-only label, file: %ls\n", Text);
                    /* Windows marks the control AI with no SACL; the stored descriptor of ours drops the bit without a SACL */
                    todo_ros ok(Control & SE_SACL_AUTO_INHERITED, "CI-only label, file: control 0x%x\n", Control);
                    CloseHandle(Handle);
                    DeleteFileW(Path);
                }
                RemoveDirectoryW(CiDir);
            }
            LocalFree(CiParent);
        }
    }

    if (Dir) CloseHandle(Dir);
    if (Root)
    {
        RegCloseKey(Root);
        for (r = 0; r < RTL_NUMBER_OF(Rows); r++)
        {
            StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\k%lu", KeyBase, r);
            RegDeleteKeyW(HKEY_CURRENT_USER, Path);
        }
        RegDeleteKeyW(HKEY_CURRENT_USER, KeyBase);
    }
    for (r = 0; r < RTL_NUMBER_OF(Rows); r++)
    {
        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\f%lu", BaseDir, r);
        DeleteFileW(Path);
        StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"%ls\\d%lu", BaseDir, r);
        RemoveDirectoryW(Path);
    }
    RemoveDirectoryW(BaseDir);
    LocalFree(Parent);
}
