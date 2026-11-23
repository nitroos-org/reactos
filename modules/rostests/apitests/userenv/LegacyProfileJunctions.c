/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the junctions from the NT 5 profile paths to the Vista ones
 */

#include <apitest.h>
#include <winioctl.h>
#include <aclapi.h>
#include <userenv.h>
#include <strsafe.h>

typedef struct _JUNCTION
{
    PCWSTR Base;        /* 'P' profile, 'D' ProgramData */
    PCWSTR Link;
    PCWSTR Target;      /* Relative to the profile, or to ProgramData, "" is the base itself */
    BOOL RosOnly;       /* The target differs between Windows versions */
} JUNCTION;

static const JUNCTION Junctions[] =
{
    {L"P", L"Application Data", L"AppData\\Roaming"},
    {L"P", L"Cookies", L"AppData\\Local\\Microsoft\\Windows\\INetCookies", TRUE},
    {L"P", L"Local Settings", L"AppData\\Local"},
    {L"P", L"My Documents", L"Documents"},
    {L"P", L"NetHood", L"AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts"},
    {L"P", L"PrintHood", L"AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts"},
    {L"P", L"Recent", L"AppData\\Roaming\\Microsoft\\Windows\\Recent"},
    {L"P", L"SendTo", L"AppData\\Roaming\\Microsoft\\Windows\\SendTo"},
    {L"P", L"Start Menu", L"AppData\\Roaming\\Microsoft\\Windows\\Start Menu"},
    {L"P", L"AppData\\Local\\Application Data", L"AppData\\Local"},
    {L"P", L"AppData\\Local\\History", L"AppData\\Local\\Microsoft\\Windows\\History"},
    {L"P", L"AppData\\Local\\Temporary Internet Files", L"AppData\\Local\\Microsoft\\Windows\\INetCache", TRUE},
    {L"D", L"Application Data", L""},
    {L"D", L"Start Menu", L"Microsoft\\Windows\\Start Menu"},
    {L"D", L"Templates", L"Microsoft\\Windows\\Templates"},
};

typedef struct _MOUNTPOINT_DATA
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR PathBuffer[512];
} MOUNTPOINT_DATA;

/* The target of a junction (the link itself is opened), without \??\ */
static BOOL
GetJunctionTarget(PCWSTR Link, PWSTR Target, ULONG Count)
{
    MOUNTPOINT_DATA Data;
    DWORD Length;
    HANDLE hLink;
    BOOL Ret;

    hLink = CreateFileW(Link, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hLink == INVALID_HANDLE_VALUE)
        return FALSE;

    Ret = DeviceIoControl(hLink, FSCTL_GET_REPARSE_POINT, NULL, 0, &Data, sizeof(Data), &Length, NULL);
    CloseHandle(hLink);
    if (!Ret || Data.ReparseTag != IO_REPARSE_TAG_MOUNT_POINT)
        return FALSE;

    Length = Data.SubstituteNameLength / sizeof(WCHAR);
    if (Length < 4 || Length >= Count)
        return FALSE;
    memcpy(Target, &Data.PathBuffer[Data.SubstituteNameOffset / sizeof(WCHAR)], Length * sizeof(WCHAR));
    Target[Length] = UNICODE_NULL;
    if (wcsncmp(Target, L"\\??\\", 4))
        return FALSE;
    memmove(Target, Target + 4, (Length - 3) * sizeof(WCHAR));
    return TRUE;
}

static void
TestJunctions(PCWSTR ProfilePath, PCWSTR ProgramDataPath, PCWSTR Name)
{
    WCHAR Link[MAX_PATH], Expected[MAX_PATH], Target[MAX_PATH];
    ULONG i;

    for (i = 0; i < _countof(Junctions); i++)
    {
        PCWSTR Base = Junctions[i].Base[0] == L'P' ? ProfilePath : ProgramDataPath;
        DWORD Attributes;
        WIN32_FIND_DATAW Find;
        HANDLE hFind;

        if (FAILED(StringCchPrintfW(Link, _countof(Link), L"%s\\%s", Base, Junctions[i].Link)) ||
            FAILED(StringCchPrintfW(Expected, _countof(Expected), L"%s\\%s", Base, Junctions[i].Target)))
        {
            skip("%S: path too long\n", Base);
            continue;
        }
        if (!Junctions[i].Target[0])
            StringCchCopyW(Expected, _countof(Expected), Base);

        Attributes = GetFileAttributesW(Link);
        ok(Attributes != INVALID_FILE_ATTRIBUTES, "%S: %S: error %lu\n", Name, Link, GetLastError());
        if (Attributes == INVALID_FILE_ATTRIBUTES)
            continue;

        ok((Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0, "%S: %S: attributes %#lx\n", Name, Link, Attributes);
        ok((Attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) == (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM),
           "%S: %S: attributes %#lx\n", Name, Link, Attributes);
        ok((Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0, "%S: %S: attributes %#lx\n", Name, Link, Attributes);

        if (!(Junctions[i].RosOnly && !is_reactos()))
        {
            BOOL IsJunction = GetJunctionTarget(Link, Target, _countof(Target));

            ok(IsJunction, "%S: %S: no junction, error %lu\n", Name, Link, GetLastError());
            if (IsJunction)
            {
                ok(!_wcsicmp(Target, Expected), "%S: %S: target %S, expected %S\n", Name, Link, Target, Expected);
            }
        }

        /* Listing it is denied, so a copy or removal of a profile can not walk into it */
        if (FAILED(StringCchCatW(Link, _countof(Link), L"\\*")))
            continue;
        SetLastError(0xdeadbeef);
        hFind = FindFirstFileW(Link, &Find);
        ok(hFind == INVALID_HANDLE_VALUE, "%S: %S: listing succeeded\n", Name, Link);
        ok(GetLastError() == ERROR_ACCESS_DENIED, "%S: %S: error %lu\n", Name, Link, GetLastError());
        if (hFind != INVALID_HANDLE_VALUE)
            FindClose(hFind);
    }
}

static void
TestOpenThrough(PCWSTR ProfilePath)
{
    WCHAR FileName[64], ViaLink[MAX_PATH], Real[MAX_PATH];
    HANDLE hFile;
    DWORD Written;

    StringCchPrintfW(FileName, _countof(FileName), L"junction-test-%lu.txt", GetCurrentProcessId());
    if (FAILED(StringCchPrintfW(ViaLink, _countof(ViaLink), L"%s\\Application Data\\%s", ProfilePath, FileName)) ||
        FAILED(StringCchPrintfW(Real, _countof(Real), L"%s\\AppData\\Roaming\\%s", ProfilePath, FileName)))
    {
        skip("%S: path too long\n", ProfilePath);
        return;
    }

    /* The profile has to be writable at all, directly */
    hFile = CreateFileW(Real, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        skip("Not allowed to write to the profile, error %lu\n", GetLastError());
        return;
    }
    CloseHandle(hFile);
    DeleteFileW(Real);

    hFile = CreateFileW(ViaLink, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "Create through the junction: error %lu\n", GetLastError());
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    ok(WriteFile(hFile, "x", 1, &Written, NULL) && Written == 1, "WriteFile: error %lu\n", GetLastError());
    CloseHandle(hFile);

    ok(GetFileAttributesW(Real) != INVALID_FILE_ATTRIBUTES, "The file is not in AppData\\Roaming: error %lu\n", GetLastError());
    ok(GetFileAttributesW(ViaLink) != INVALID_FILE_ATTRIBUTES, "Not found through the junction\n");
    ok(DeleteFileW(ViaLink), "Delete through the junction: error %lu\n", GetLastError());
    ok(GetFileAttributesW(Real) == INVALID_FILE_ATTRIBUTES, "The file is still in AppData\\Roaming\n");
}

/*
 * The DACL of a junction object in the root of the volume (the object itself, not its target): not what the root passes
 * on (Authenticated Users: Modify), but the DACL of its target, protected, after the deny of the listing. Users,
 * Authenticated Users, Everyone and the interactive logon may neither write nor delete it nor change its DACL or owner.
 * On ReactOS only: the DACL of the Windows object is not measured.
 */
static void
TestRootJunctionDacl(PCWSTR Link)
{
    static const WELL_KNOWN_SID_TYPE Others[] = { WinBuiltinUsersSid, WinAuthenticatedUserSid, WinWorldSid, WinInteractiveSid };
    const ACCESS_MASK Write = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD |
                              FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    BYTE Sid[SECURITY_MAX_SID_SIZE];
    PSECURITY_DESCRIPTOR Sd = NULL;
    SECURITY_DESCRIPTOR_CONTROL Control = 0;
    PACCESS_ALLOWED_ACE Ace;
    PACL Dacl = NULL;
    DWORD Error, Revision, Size, i, j;
    HANDLE hLink;

    if (!is_reactos())
    {
        skip("%S: the DACL of the Windows junction is not known\n", Link);
        return;
    }

    hLink = CreateFileW(Link, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(hLink != INVALID_HANDLE_VALUE, "%S: open: error %lu\n", Link, GetLastError());
    if (hLink == INVALID_HANDLE_VALUE)
        return;
    Error = GetSecurityInfo(hLink, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &Dacl, NULL, &Sd);
    CloseHandle(hLink);
    ok(Error == ERROR_SUCCESS, "%S: GetSecurityInfo: error %lu\n", Link, Error);
    if (Error != ERROR_SUCCESS)
        return;

    ok(GetSecurityDescriptorControl(Sd, &Control, &Revision), "GetSecurityDescriptorControl: error %lu\n", GetLastError());
    ok((Control & SE_DACL_PROTECTED) != 0, "%S: the DACL is not protected (control %#x)\n", Link, Control);
    ok(Dacl != NULL && Dacl->AceCount > 2, "%S: DACL %p\n", Link, Dacl);
    if (Dacl == NULL)
        goto done;

    /* The first entry denies the listing to Everyone */
    Size = sizeof(Sid);
    CreateWellKnownSid(WinWorldSid, NULL, Sid, &Size);
    ok(GetAce(Dacl, 0, (PVOID *)&Ace) && Ace->Header.AceType == ACCESS_DENIED_ACE_TYPE &&
       (Ace->Mask & FILE_LIST_DIRECTORY) && EqualSid((PSID)&Ace->SidStart, (PSID)Sid),
       "%S: the first entry does not deny the listing to Everyone\n", Link);

    for (i = 0; i < Dacl->AceCount; i++)
    {
        if (!GetAce(Dacl, i, (PVOID *)&Ace) || Ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        ok(!(Ace->Header.AceFlags & INHERITED_ACE), "%S: entry %lu is inherited\n", Link, i);
        for (j = 0; j < _countof(Others); j++)
        {
            Size = sizeof(Sid);
            if (CreateWellKnownSid(Others[j], NULL, Sid, &Size) && EqualSid((PSID)&Ace->SidStart, (PSID)Sid))
                ok(!(Ace->Mask & Write), "%S: entry %lu grants %#lx to well-known SID %u\n", Link, i, Ace->Mask, Others[j]);
        }
    }

done:
    LocalFree(Sd);
}

START_TEST(LegacyProfileJunctions)
{
    WCHAR DefaultPath[MAX_PATH], ProgramDataPath[MAX_PATH], Root[MAX_PATH], Link[MAX_PATH], Target[MAX_PATH];
    WCHAR ProfilesPath[MAX_PATH], FileSystem[MAX_PATH];
    DWORD Size;

    Size = _countof(DefaultPath);
    if (!GetDefaultUserProfileDirectoryW(DefaultPath, &Size))
    {
        skip("No default profile: error %lu\n", GetLastError());
        return;
    }
    if (!ExpandEnvironmentStringsW(L"%SystemDrive%\\ProgramData", ProgramDataPath, _countof(ProgramDataPath)))
    {
        skip("No ProgramData: error %lu\n", GetLastError());
        return;
    }

    if (!GetVolumePathNameW(DefaultPath, Root, _countof(Root)) ||
        !GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, FileSystem, _countof(FileSystem)) ||
        _wcsicmp(FileSystem, L"NTFS"))
    {
        skip("%S is not NTFS\n", Root);
        return;
    }

    TestJunctions(DefaultPath, ProgramDataPath, L"Default");
    TestOpenThrough(DefaultPath);

    /* Documents and Settings is the profiles directory */
    Size = _countof(ProfilesPath);
    if (GetProfilesDirectoryW(ProfilesPath, &Size) &&
        ExpandEnvironmentStringsW(L"%SystemDrive%\\Documents and Settings", Link, _countof(Link)))
    {
        BOOL IsJunction = GetJunctionTarget(Link, Target, _countof(Target));

        ok(IsJunction, "%S: no junction, error %lu\n", Link, GetLastError());
        if (IsJunction)
        {
            ok(!_wcsicmp(Target, ProfilesPath), "%S: target %S, expected %S\n", Link, Target, ProfilesPath);
            TestRootJunctionDacl(Link);
        }
    }
}
