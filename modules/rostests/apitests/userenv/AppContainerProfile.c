/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for userenv!CreateAppContainerProfile, DeleteAppContainerProfile, GetAppContainerFolderPath and
 *              GetAppContainerRegistryLocation (Windows 8 and later)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The create and delete round trips change the state of the user (registry keys and folders under Packages, all
 * removed again, and a canary file in LOCALAPPDATA and in Packages). On ReactOS they always run; on Windows they
 * run only when the environment variable ROSAPITEST_APPCONTAINER_PROFILE is set.
 */

#include <apitest.h>
#include <winreg.h>
#include <sddl.h>
#include <objbase.h>

typedef HRESULT (WINAPI *PFN_Create)(PCWSTR, PCWSTR, PCWSTR, PSID_AND_ATTRIBUTES, DWORD, PSID *);
typedef HRESULT (WINAPI *PFN_Delete)(PCWSTR);
typedef HRESULT (WINAPI *PFN_Derive)(PCWSTR, PSID *);
typedef HRESULT (WINAPI *PFN_FolderPath)(PCWSTR, PWSTR *);
typedef HRESULT (WINAPI *PFN_RegistryLocation)(REGSAM, PHKEY);

static PFN_Create pCreate;
static PFN_Delete pDelete;
static PFN_Derive pDerive;
static PFN_FolderPath pFolderPath;
static PFN_RegistryLocation pRegistryLocation;

#define APPCONTAINER_KEY L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\"
#define TEST_NAME L"ReactOS.ApiTest.AppContainerProfile"
#define TEST_NAME_LOWER L"reactos.apitest.appcontainerprofile"
#define TEST_DISPLAY L"ReactOS API test AppContainer profile"
#define TEST_DESCRIPTION L"Throwaway profile of the ReactOS API test"
#define ERROR_NOT_AN_APPCONTAINER_SID 4250

static BOOL RegistryKeyExists(PCWSTR Path)
{
    HKEY Key;
    LONG Error = RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, KEY_READ, &Key);

    if (Error == ERROR_SUCCESS)
        RegCloseKey(Key);
    return Error == ERROR_SUCCESS;
}

static BOOL ReadString(PCWSTR Path, PCWSTR Name, PWSTR Buffer, DWORD Chars)
{
    HKEY Key;
    DWORD Type, Size = Chars * sizeof(WCHAR);
    LONG Error = RegOpenKeyExW(HKEY_CURRENT_USER, Path, 0, KEY_READ, &Key);

    if (Error != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(Key, Name, NULL, &Type, (PBYTE)Buffer, &Size);
    RegCloseKey(Key);
    return Error == ERROR_SUCCESS && Type == REG_SZ;
}

static BOOL IsDirectory(PCWSTR Path)
{
    DWORD Attributes = GetFileAttributesW(Path);

    return Attributes != INVALID_FILE_ATTRIBUTES && (Attributes & FILE_ATTRIBUTE_DIRECTORY);
}

/* Everything that these functions do not need a profile for */
static void TestWithoutProfile(void)
{
    PWSTR Path = (PWSTR)(ULONG_PTR)0x33;
    HKEY Key = (HKEY)(ULONG_PTR)0x44;
    HRESULT hr;

    /* a well-formed AppContainer SID that is not registered */
    hr = pFolderPath(L"S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742", &Path);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "unregistered SID: hr %#lx\n", hr);
    ok(Path == (PWSTR)(ULONG_PTR)0x33, "unregistered SID: the result was written\n");

    /* a SID that is not an AppContainer SID */
    Path = (PWSTR)(ULONG_PTR)0x33;
    hr = pFolderPath(L"S-1-5-32-544", &Path);
    ok(hr == HRESULT_FROM_WIN32(ERROR_NOT_AN_APPCONTAINER_SID), "Administrators SID: hr %#lx\n", hr);
    ok(Path == (PWSTR)(ULONG_PTR)0x33, "Administrators SID: the result was written\n");

    /* this process does not run in an AppContainer */
    hr = pRegistryLocation(KEY_READ, &Key);
    ok(hr == E_UNEXPECTED, "GetAppContainerRegistryLocation: hr %#lx\n", hr);
    ok(Key == (HKEY)(ULONG_PTR)0x44, "GetAppContainerRegistryLocation: the key was written\n");
}

/* Removes a folder with everything in it. Only called with paths below LOCALAPPDATA that the test built. */
static void RemoveTree(PCWSTR Path)
{
    WIN32_FIND_DATAW Data;
    WCHAR Pattern[MAX_PATH], Child[MAX_PATH], LocalAppData[MAX_PATH];
    HANDLE Find;
    DWORD Attributes = GetFileAttributesW(Path);
    ULONG Length;

    Length = GetEnvironmentVariableW(L"LOCALAPPDATA", LocalAppData, MAX_PATH);
    if (!Length || Length >= MAX_PATH || wcslen(Path) <= Length + 1 || _wcsnicmp(Path, LocalAppData, Length))
    {
        ok(0, "RemoveTree refuses %ls\n", Path);
        return;
    }
    if (Attributes == INVALID_FILE_ATTRIBUTES)
        return;
    if ((Attributes & FILE_ATTRIBUTE_DIRECTORY) && !(Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        _snwprintf(Pattern, MAX_PATH, L"%ls\\*", Path);
        Find = FindFirstFileW(Pattern, &Data);
        if (Find != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!wcscmp(Data.cFileName, L".") || !wcscmp(Data.cFileName, L".."))
                    continue;
                _snwprintf(Child, MAX_PATH, L"%ls\\%ls", Path, Data.cFileName);
                RemoveTree(Child);
            } while (FindNextFileW(Find, &Data));
            FindClose(Find);
        }
    }
    SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
    if (Attributes & FILE_ATTRIBUTE_DIRECTORY)
        RemoveDirectoryW(Path);
    else
        DeleteFileW(Path);
}

static void MakeCanary(PCWSTR Path)
{
    HANDLE File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    ok(File != INVALID_HANDLE_VALUE, "cannot create the canary %ls: %lu\n", Path, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
}

/*
 * What create and delete answer for names that are not plain folder names (Windows 10 22H2, measured; the raw
 * oracle output is in the ticket). The folder of a profile is Packages\<name in lower case> built as a Win32 path:
 * "/" and "\" separate folders, "." and ".." are dots of the path, one trailing dot is dropped.
 * Create answers:
 *  - E_INVALIDARG for no name and more than 64 characters;
 *  - ERROR_INVALID_NAME for control characters and * ? " < > |, and for colons except a single one inside the name,
 *    which is ERROR_DIRECTORY;
 *  - ERROR_PATH_NOT_FOUND where a folder does not exist ("a/b" and "a\b" without folder "a") or a folder name still
 *    ends in a dot or a space once one dot is dropped ("a " "a.." "..." ". "); Windows leaves the root folder of such
 *    a create behind, ReactOS does not.
 * Everything else is created.
 */
static void TestInvalidNames(BOOL ChangeState)
{
    static const struct
    {
        PCWSTR Name;
        HRESULT Result;
    } Failures[] =
    {
        { L"", E_INVALIDARG },
        { L"a*b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"a?b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"a\"b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"a<b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"a>b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"a|b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"a\x01" L"b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"a\tb", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-a:b", HRESULT_FROM_WIN32(ERROR_DIRECTORY) },
        { L"RosApiTest-a::b", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-a:b:c", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L":RosApiTest-a", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-a:", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-NoParent/b", HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) },
        { L"RosApiTest-NoParent\\b", HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) },
        { L"RosApiTest-NoParent/b/../c", HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) },
    };
    /* these leave a folder behind on Windows: the trimmed name, which the test removes if it is new */
    static const struct
    {
        PCWSTR Name;
        PCWSTR Folder;
    } Leaves[] =
    {
        { L"RosApiTest-Sp ", L"rosapitest-sp" },
        { L"RosApiTest-Sp2  ", L"rosapitest-sp2" },
        { L"RosApiTest-Dots..", L"rosapitest-dots" },
        { L"RosApiTest-DotSp. ", L"rosapitest-dotsp" },
        { L"RosApiTest-SpDot .", L"rosapitest-spdot" },
        { L"...", NULL },
        { L".. ", NULL },
        { L". ", NULL },
    };
    static const struct
    {
        PCWSTR Name;
        HRESULT Result;
    } DeleteNoProfile[] =
    {
        { L"", E_INVALIDARG },
        { L".", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"..", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-x/y", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"/", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-x/..", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"../RosApiTest-x", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-x\\.", S_OK },
        { L"RosApiTest-x\\..", S_OK },
        { L"\\RosApiTest-x", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-x\\\\", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-x*y", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-x|y", HRESULT_FROM_WIN32(ERROR_INVALID_NAME) },
        { L"RosApiTest-x:y", S_OK },
        { L"RosApiTest-x\\y", S_OK },
        { L"RosApiTest-x\\", S_OK },
        { L"RosApiTest-x.", S_OK },
        { L"RosApiTest-x ", S_OK },
        { L"RosApiTest-x", S_OK },
    };
    WCHAR Long[70], LocalAppData[MAX_PATH], Packages[MAX_PATH], Folder[MAX_PATH], CanaryOutside[MAX_PATH],
        CanaryInside[MAX_PATH];
    PSID Sid;
    HRESULT hr;
    ULONG i;
    BOOL Existed;

    ok(GetEnvironmentVariableW(L"LOCALAPPDATA", LocalAppData, MAX_PATH) != 0, "no LOCALAPPDATA\n");
    _snwprintf(Packages, MAX_PATH, L"%ls\\Packages", LocalAppData);
    _snwprintf(CanaryOutside, MAX_PATH, L"%ls\\ReactOS-AppContainerProfile-canary.txt", LocalAppData);
    _snwprintf(CanaryInside, MAX_PATH, L"%ls\\ReactOS-AppContainerProfile-canary.txt", Packages);
    if (ChangeState)
    {
        CreateDirectoryW(Packages, NULL);
        MakeCanary(CanaryOutside);
        MakeCanary(CanaryInside);
    }

    for (i = 0; i < RTL_NUMBER_OF(Failures); i++)
    {
        Sid = (PSID)(ULONG_PTR)0x55;
        hr = pCreate(Failures[i].Name, L"invalid name", L"invalid name", NULL, 0, &Sid);
        ok(hr == Failures[i].Result, "create '%ls': hr %#lx, expected %#lx\n", Failures[i].Name, hr, Failures[i].Result);
        ok(Sid == (PSID)(ULONG_PTR)0x55, "create '%ls': the result was written\n", Failures[i].Name);
        if (hr == S_OK)
        {
            FreeSid(Sid);
            pDelete(Failures[i].Name);
        }
    }

    for (i = 0; i < 65; i++)
        Long[i] = L'a';
    Long[65] = UNICODE_NULL;
    Sid = (PSID)(ULONG_PTR)0x55;
    hr = pCreate(Long, L"invalid name", L"invalid name", NULL, 0, &Sid);
    ok(hr == E_INVALIDARG, "create with 65 characters: hr %#lx\n", hr);
    hr = pDelete(Long);
    ok(hr == E_INVALIDARG, "delete with 65 characters: hr %#lx\n", hr);
    hr = pDerive(Long, &Sid);
    ok(hr == E_INVALIDARG, "derive with 65 characters: hr %#lx\n", hr);

    if (!ChangeState)
        return;

    for (i = 0; i < RTL_NUMBER_OF(Leaves); i++)
    {
        Existed = FALSE;
        Folder[0] = UNICODE_NULL;
        if (Leaves[i].Folder)
        {
            _snwprintf(Folder, MAX_PATH, L"%ls\\%ls", Packages, Leaves[i].Folder);
            Existed = GetFileAttributesW(Folder) != INVALID_FILE_ATTRIBUTES;
        }
        Sid = (PSID)(ULONG_PTR)0x55;
        hr = pCreate(Leaves[i].Name, L"invalid name", L"invalid name", NULL, 0, &Sid);
        ok(hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND), "create '%ls': hr %#lx\n", Leaves[i].Name, hr);
        ok(Sid == (PSID)(ULONG_PTR)0x55, "create '%ls': the result was written\n", Leaves[i].Name);
        if (hr == S_OK)
        {
            FreeSid(Sid);
            pDelete(Leaves[i].Name);
        }
        if (Leaves[i].Folder && !Existed)
        {
            ok(!is_reactos() || GetFileAttributesW(Folder) == INVALID_FILE_ATTRIBUTES, "create '%ls' left %ls\n",
               Leaves[i].Name, Folder);
            RemoveTree(Folder);
        }
    }

    /* delete of a name that has no profile: the result is the one of the folder step, and nothing is touched */
    for (i = 0; i < RTL_NUMBER_OF(DeleteNoProfile); i++)
    {
        hr = pDelete(DeleteNoProfile[i].Name);
        ok(hr == DeleteNoProfile[i].Result, "delete '%ls': hr %#lx, expected %#lx\n", DeleteNoProfile[i].Name, hr,
           DeleteNoProfile[i].Result);
        ok(GetFileAttributesW(CanaryOutside) != INVALID_FILE_ATTRIBUTES, "delete '%ls' removed the canary\n",
           DeleteNoProfile[i].Name);
        ok(GetFileAttributesW(CanaryInside) != INVALID_FILE_ATTRIBUTES,
           "delete '%ls' removed the canary in Packages\n", DeleteNoProfile[i].Name);
    }
    DeleteFileW(CanaryOutside);
    DeleteFileW(CanaryInside);
}

/*
 * Create and delete of the names that are accepted but are not plain folder names. Root is the profile folder below
 * Packages (L"" when the name resolves to Packages itself, where the AC folder is Packages\AC; NULL when it
 * resolves outside of Packages). Windows makes the AC folder outside of Packages too (Outside, below LOCALAPPDATA);
 * ReactOS never creates anything outside of Packages. Delete is the result of the folder step; Remains says
 * whether the folder is still there after it (Windows only removes the folder of a name it can spell as a path
 * without "/", "." and ".."). Parent is a folder that must exist for a nested name. After the delete the canaries
 * in LOCALAPPDATA and in Packages, and the Packages folder, must be there: delete never leaves Packages.
 */
static void TestNameClasses(void)
{
    static const WCHAR SubFolders[][12] = { L"INetCache", L"INetCookies", L"INetHistory", L"Temp" };
    static const struct
    {
        PCWSTR Name;
        PCWSTR Root;
        PCWSTR Outside;
        PCWSTR Parent;
        HRESULT Delete;
        BOOL Remains;
    } Rows[] =
    {
#define INVNAME HRESULT_FROM_WIN32(ERROR_INVALID_NAME)
        { L"RosApiTest-Case", L"rosapitest-case", NULL, NULL, S_OK, FALSE },
        { L"RosApiTest-UPPER", L"rosapitest-upper", NULL, NULL, S_OK, FALSE },
        { L"RosApiTest a b", L"rosapitest a b", NULL, NULL, S_OK, FALSE },
        { L".RosApiTest-LeadDot", L".rosapitest-leaddot", NULL, NULL, S_OK, FALSE },
        { L"..RosApiTest-LeadDots", L"..rosapitest-leaddots", NULL, NULL, S_OK, FALSE },
        { L" RosApiTest-LeadSpace", L" rosapitest-leadspace", NULL, NULL, S_OK, FALSE },
        { L"RosApiTest-In..ner", L"rosapitest-in..ner", NULL, NULL, S_OK, FALSE },
        { L"RosApiTest-Dot.", L"rosapitest-dot", NULL, NULL, S_OK, TRUE },
        { L"RosApiTest-BsEnd\\", L"rosapitest-bsend", NULL, NULL, S_OK, FALSE },
        { L"RosApiTest-Slash/", L"rosapitest-slash", NULL, NULL, INVNAME, TRUE },
        { L"/RosApiTest-LeadSlash", L"rosapitest-leadslash", NULL, NULL, INVNAME, TRUE },
        { L"\\RosApiTest-LeadBs", L"rosapitest-leadbs", NULL, NULL, INVNAME, TRUE },
        { L"./RosApiTest-DotSlash", L"rosapitest-dotslash", NULL, NULL, INVNAME, TRUE },
        { L"RosApiTest-Q/.", L"rosapitest-q", NULL, NULL, INVNAME, TRUE },
        { L"RosApiTest-Q2\\.", L"rosapitest-q2", NULL, NULL, INVNAME, TRUE },
        { L"RosApiTest-A/../RosApiTest-B", L"rosapitest-b", NULL, NULL, INVNAME, TRUE },
        { L"../Packages/RosApiTest-Rt", L"rosapitest-rt", NULL, NULL, INVNAME, TRUE },
        { L"RosApiTest-Par/b", L"rosapitest-par\\b", NULL, L"rosapitest-par", INVNAME, TRUE },
        { L"RosApiTest-Par2\\b", L"rosapitest-par2\\b", NULL, L"rosapitest-par2", S_OK, FALSE },
        { L".", L"", NULL, NULL, INVNAME, TRUE },
        { L"/", L"", NULL, NULL, INVNAME, TRUE },
        { L"RosApiTest-P/..", L"", NULL, NULL, INVNAME, TRUE },
        { L"..", NULL, L"AC", NULL, INVNAME, TRUE },
        { L"../RosApiTest-Esc", NULL, L"rosapitest-esc\\AC", NULL, INVNAME, TRUE },
    };
    WCHAR LocalAppData[MAX_PATH], Packages[MAX_PATH], CanaryOutside[MAX_PATH], CanaryInside[MAX_PATH];
    ULONG Row, i;

    ok(GetEnvironmentVariableW(L"LOCALAPPDATA", LocalAppData, MAX_PATH) != 0, "no LOCALAPPDATA\n");
    _snwprintf(Packages, MAX_PATH, L"%ls\\Packages", LocalAppData);
    CreateDirectoryW(Packages, NULL);
    _snwprintf(CanaryOutside, MAX_PATH, L"%ls\\ReactOS-AppContainerProfile-canary.txt", LocalAppData);
    _snwprintf(CanaryInside, MAX_PATH, L"%ls\\ReactOS-AppContainerProfile-canary.txt", Packages);
    MakeCanary(CanaryOutside);
    MakeCanary(CanaryInside);

    for (Row = 0; Row < RTL_NUMBER_OF(Rows); Row++)
    {
        PCWSTR Name = Rows[Row].Name;
        WCHAR Lower[80], Mapping[400], Storage[300], Text[600], Expected[MAX_PATH], Folder[MAX_PATH], ParentPath[MAX_PATH];
        WCHAR OutsidePath[MAX_PATH], OutsideTop[MAX_PATH], AcPackages[MAX_PATH];
        PSID Derived = NULL, Created = NULL, Again = (PSID)(ULONG_PTR)0x66;
        LPWSTR SidString = NULL;
        PWSTR Path;
        HRESULT hr;
        BOOL OutsideExisted = FALSE, AcExisted = FALSE;

        for (i = 0; Name[i]; i++)
            Lower[i] = (Name[i] >= L'A' && Name[i] <= L'Z') ? Name[i] + (L'a' - L'A') : Name[i];
        Lower[i] = UNICODE_NULL;

        /* what is there before; a row that would run over something real is skipped */
        OutsidePath[0] = OutsideTop[0] = ParentPath[0] = AcPackages[0] = UNICODE_NULL;
        if (Rows[Row].Outside)
        {
            WCHAR *Slash;

            _snwprintf(OutsidePath, MAX_PATH, L"%ls\\%ls", LocalAppData, Rows[Row].Outside);
            wcscpy(OutsideTop, OutsidePath);
            Slash = wcschr(OutsideTop + wcslen(LocalAppData) + 1, L'\\');
            if (Slash)
                *Slash = UNICODE_NULL;
            OutsideExisted = GetFileAttributesW(OutsideTop) != INVALID_FILE_ATTRIBUTES;
        }
        if (Rows[Row].Root && !Rows[Row].Root[0])
        {
            _snwprintf(AcPackages, MAX_PATH, L"%ls\\AC", Packages);
            AcExisted = GetFileAttributesW(AcPackages) != INVALID_FILE_ATTRIBUTES;
        }
        if (Rows[Row].Root && Rows[Row].Root[0])
        {
            _snwprintf(Expected, MAX_PATH, L"%ls\\%ls", Packages, Rows[Row].Root);
            AcExisted = GetFileAttributesW(Expected) != INVALID_FILE_ATTRIBUTES;
        }
        if (AcExisted || OutsideExisted)
        {
            skip("'%ls': the folder it needs exists already\n", Name);
            continue;
        }
        if (Rows[Row].Parent)
        {
            _snwprintf(ParentPath, MAX_PATH, L"%ls\\%ls", Packages, Rows[Row].Parent);
            ok(CreateDirectoryW(ParentPath, NULL), "cannot create %ls: %lu\n", ParentPath, GetLastError());
        }

        hr = pDerive(Name, &Derived);
        ok(hr == S_OK, "'%ls': Derive hr %#lx\n", Name, hr);
        if (!Derived || !ConvertSidToStringSidW(Derived, &SidString))
            goto Cleanup;
        _snwprintf(Mapping, 400, APPCONTAINER_KEY L"Mappings\\%ls", SidString);
        _snwprintf(Storage, 300, APPCONTAINER_KEY L"Storage\\%ls", Lower);
        ok(!RegistryKeyExists(Mapping), "'%ls': the mapping exists before the create\n", Name);

        hr = pCreate(Name, TEST_DISPLAY, TEST_DESCRIPTION, NULL, 0, &Created);
        ok(hr == S_OK, "create '%ls': hr %#lx\n", Name, hr);
        if (hr != S_OK)
            goto Cleanup;
        ok(EqualSid(Created, Derived), "'%ls': the profile SID is not the derived SID\n", Name);

        /* the moniker and the Storage key carry the name in lower case */
        ok(ReadString(Mapping, L"Moniker", Text, 600) && !wcscmp(Text, Lower), "'%ls': Moniker is '%ls'\n", Name, Text);
        ok(RegistryKeyExists(Storage), "'%ls': the Storage key %ls does not exist\n", Name, Lower);

        /* the folders */
        if (Rows[Row].Root)
        {
            if (Rows[Row].Root[0])
                _snwprintf(Folder, MAX_PATH, L"%ls\\%ls\\AC", Packages, Rows[Row].Root);
            else
                _snwprintf(Folder, MAX_PATH, L"%ls\\AC", Packages);
            ok(IsDirectory(Folder), "'%ls': %ls is not a folder\n", Name, Folder);
            for (i = 0; i < RTL_NUMBER_OF(SubFolders); i++)
            {
                WCHAR Sub[MAX_PATH];

                _snwprintf(Sub, MAX_PATH, L"%ls\\%ls", Folder, SubFolders[i]);
                ok(IsDirectory(Sub), "'%ls': %ls is not a folder\n", Name, Sub);
            }
        }
        else if (is_reactos())
        {
            ok(!IsDirectory(OutsideTop), "'%ls': ReactOS made %ls, outside of Packages\n", Name, OutsideTop);
        }
        else
        {
            ok(IsDirectory(OutsidePath), "'%ls': Windows made no %ls\n", Name, OutsidePath);
        }

        /* the folder path is the moniker appended to Packages, as it is */
        Path = NULL;
        hr = pFolderPath(SidString, &Path);
        ok(hr == S_OK, "'%ls': GetAppContainerFolderPath hr %#lx\n", Name, hr);
        if (hr == S_OK)
        {
            _snwprintf(Folder, MAX_PATH, L"%ls\\%ls\\AC", Packages, Lower);
            ok(!wcscmp(Path, Folder), "'%ls': GetAppContainerFolderPath '%ls', expected '%ls'\n", Name, Path, Folder);
            CoTaskMemFree(Path);
        }

        hr = pCreate(Name, TEST_DISPLAY, TEST_DESCRIPTION, NULL, 0, &Again);
        ok(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "'%ls': second create hr %#lx\n", Name, hr);
        if (hr == S_OK)
            FreeSid(Again);

        hr = pDelete(Name);
        ok(hr == Rows[Row].Delete, "delete '%ls': hr %#lx, expected %#lx\n", Name, hr, Rows[Row].Delete);
        ok(!RegistryKeyExists(Mapping), "'%ls': the mapping exists after the delete\n", Name);
        ok(!RegistryKeyExists(Storage), "'%ls': the Storage key exists after the delete\n", Name);
        if (Rows[Row].Root && Rows[Row].Root[0])
        {
            _snwprintf(Expected, MAX_PATH, L"%ls\\%ls", Packages, Rows[Row].Root);
            ok(IsDirectory(Expected) == Rows[Row].Remains, "'%ls': %ls %s after the delete\n", Name, Expected,
               Rows[Row].Remains ? "is gone" : "is still there");
        }
        hr = pDelete(Name);
        ok(hr == Rows[Row].Delete, "second delete '%ls': hr %#lx, expected %#lx\n", Name, hr, Rows[Row].Delete);

        /* delete never leaves Packages */
        ok(GetFileAttributesW(CanaryOutside) != INVALID_FILE_ATTRIBUTES, "delete '%ls' removed the canary\n", Name);
        ok(GetFileAttributesW(CanaryInside) != INVALID_FILE_ATTRIBUTES, "delete '%ls' removed the canary in Packages\n", Name);
        ok(IsDirectory(Packages), "delete '%ls' removed the Packages folder\n", Name);
        ok(IsDirectory(LocalAppData), "delete '%ls' removed LOCALAPPDATA\n", Name);

Cleanup:
        pDelete(Name);
        if (Rows[Row].Root && Rows[Row].Root[0])
        {
            WCHAR Top[MAX_PATH], *Slash;

            _snwprintf(Top, MAX_PATH, L"%ls\\%ls", Packages, Rows[Row].Parent ? Rows[Row].Parent : Rows[Row].Root);
            Slash = Rows[Row].Parent ? NULL : wcschr(Top + wcslen(Packages) + 1, L'\\');
            if (Slash)
                *Slash = UNICODE_NULL;
            RemoveTree(Top);
        }
        if (AcPackages[0])
            RemoveTree(AcPackages);
        if (OutsideTop[0])
            RemoveTree(OutsideTop);
        if (wcschr(Lower, L'\\'))
        {
            /* a name with a backslash made the keys of its folders in Storage, and delete leaves all but the last */
            WCHAR *Backslash = wcschr(Lower, L'\\');

            *Backslash = UNICODE_NULL;
            _snwprintf(Storage, 300, APPCONTAINER_KEY L"Storage\\%ls", Lower);
            RegDeleteKeyW(HKEY_CURRENT_USER, Storage);
        }
        if (Created)
            FreeSid(Created);
        if (SidString)
            LocalFree(SidString);
        if (Derived)
            FreeSid(Derived);
    }
    DeleteFileW(CanaryOutside);
    DeleteFileW(CanaryInside);
}

static void TestRoundTrip(void)
{
    static const WCHAR SubFolders[][12] = { L"INetCache", L"INetCookies", L"INetHistory", L"Temp" };
    SID_IDENTIFIER_AUTHORITY AppPackageAuthority = { { 0, 0, 0, 0, 0, 15 } };
    SID_AND_ATTRIBUTES Capability;
    PSID Derived = NULL, Created = NULL, Again = (PSID)(ULONG_PTR)0x66, CapabilitySid = NULL;
    LPWSTR SidString = NULL;
    WCHAR Mapping[400], Storage[200], Text[600], LocalAppData[MAX_PATH], Expected[MAX_PATH], Folder[MAX_PATH];
    PWSTR Path;
    HRESULT hr;
    ULONG i;

    ok(GetEnvironmentVariableW(L"LOCALAPPDATA", LocalAppData, MAX_PATH) != 0, "no LOCALAPPDATA\n");
    _snwprintf(Expected, MAX_PATH, L"%ls\\Packages\\%ls", LocalAppData, TEST_NAME);

    hr = pDerive(TEST_NAME, &Derived);
    ok(hr == S_OK, "Derive: hr %#lx\n", hr);
    if (!Derived)
        return;
    ok(ConvertSidToStringSidW(Derived, &SidString), "ConvertSidToStringSid failed with %lu\n", GetLastError());
    if (!SidString)
        goto Cleanup;
    _snwprintf(Mapping, 400, APPCONTAINER_KEY L"Mappings\\%ls", SidString);
    _snwprintf(Storage, 200, APPCONTAINER_KEY L"Storage\\%ls", TEST_NAME);

    /* a profile of an earlier run that did not finish */
    pDelete(TEST_NAME);

    ok(AllocateAndInitializeSid(&AppPackageAuthority, 2, 3, 1, 0, 0, 0, 0, 0, 0, &CapabilitySid),
       "AllocateAndInitializeSid failed with %lu\n", GetLastError());
    Capability.Sid = CapabilitySid;
    Capability.Attributes = SE_GROUP_ENABLED;

    ok(!RegistryKeyExists(Mapping), "the mapping exists before the create\n");
    ok(!IsDirectory(Expected), "the folder exists before the create\n");

    hr = pCreate(TEST_NAME, TEST_DISPLAY, TEST_DESCRIPTION, &Capability, 1, &Created);
    ok(hr == S_OK, "CreateAppContainerProfile: hr %#lx\n", hr);
    if (hr != S_OK)
        goto Cleanup;
    ok(EqualSid(Created, Derived), "the profile SID is not the derived SID\n");

    /* the registration: moniker (in lower case, as Windows keeps it), display name, and the keys of the AppContainer */
    ok(ReadString(Mapping, L"Moniker", Text, 600) && !wcscmp(Text, TEST_NAME_LOWER), "Moniker is '%ls'\n", Text);
    ok(ReadString(Mapping, L"DisplayName", Text, 600) && !wcscmp(Text, TEST_DISPLAY), "DisplayName is '%ls'\n", Text);
    wcscat(Mapping, L"\\Children");
    ok(RegistryKeyExists(Mapping), "the Children key of the mapping does not exist\n");
    ok(RegistryKeyExists(Storage), "the Storage key does not exist\n");
    wcscat(Storage, L"\\Children");
    ok(RegistryKeyExists(Storage), "the Children key of the Storage key does not exist\n");

    /* the folders: Packages\<name>\AC and four folders below it */
    ok(IsDirectory(Expected), "%ls is not a folder\n", Expected);
    _snwprintf(Folder, MAX_PATH, L"%ls\\AC", Expected);
    ok(IsDirectory(Folder), "%ls is not a folder\n", Folder);
    for (i = 0; i < RTL_NUMBER_OF(SubFolders); i++)
    {
        DWORD Attributes;

        _snwprintf(Folder, MAX_PATH, L"%ls\\AC\\%ls", Expected, SubFolders[i]);
        Attributes = GetFileAttributesW(Folder);
        ok(Attributes != INVALID_FILE_ATTRIBUTES && (Attributes & FILE_ATTRIBUTE_DIRECTORY), "%ls is not a folder\n", Folder);
        if (i < 3)
            ok((Attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) == (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM),
               "%ls: attributes %#lx\n", Folder, Attributes);
    }

    /* the folder path is the AC folder; the caller frees it with CoTaskMemFree */
    Path = NULL;
    hr = pFolderPath(SidString, &Path);
    ok(hr == S_OK, "GetAppContainerFolderPath: hr %#lx\n", hr);
    if (hr == S_OK)
    {
        _snwprintf(Folder, MAX_PATH, L"%ls\\AC", Expected);
        ok(!wcsicmp(Path, Folder), "GetAppContainerFolderPath: '%ls', expected '%ls'\n", Path, Folder);
        CoTaskMemFree(Path);
    }

    /* the same name again: the result is left alone */
    hr = pCreate(TEST_NAME, TEST_DISPLAY, TEST_DESCRIPTION, &Capability, 1, &Again);
    ok(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), "second create: hr %#lx\n", hr);
    ok(Again == (PSID)(ULONG_PTR)0x66, "second create: the result was written\n");
    if (hr == S_OK)
        FreeSid(Again);

    /* delete removes everything, and deleting what is not there succeeds */
    hr = pDelete(TEST_NAME);
    ok(hr == S_OK, "DeleteAppContainerProfile: hr %#lx\n", hr);
    wcscpy(Mapping + wcslen(Mapping) - 9, L"");
    ok(!RegistryKeyExists(Mapping), "the mapping exists after the delete\n");
    ok(!RegistryKeyExists(Storage), "the Children key of the Storage key exists after the delete\n");
    _snwprintf(Storage, 200, APPCONTAINER_KEY L"Storage\\%ls", TEST_NAME);
    ok(!RegistryKeyExists(Storage), "the Storage key exists after the delete\n");
    ok(!IsDirectory(Expected), "%ls exists after the delete\n", Expected);
    Path = (PWSTR)(ULONG_PTR)0x33;
    hr = pFolderPath(SidString, &Path);
    ok(hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), "GetAppContainerFolderPath after the delete: hr %#lx\n", hr);
    hr = pDelete(TEST_NAME);
    ok(hr == S_OK, "second delete: hr %#lx\n", hr);

Cleanup:
    pDelete(TEST_NAME);
    if (Created)
        FreeSid(Created);
    if (CapabilitySid)
        FreeSid(CapabilitySid);
    if (SidString)
        LocalFree(SidString);
    FreeSid(Derived);
}

START_TEST(AppContainerProfile)
{
    HMODULE Userenv = LoadLibraryW(L"userenv.dll");

    pCreate = (PFN_Create)GetProcAddress(Userenv, "CreateAppContainerProfile");
    pDelete = (PFN_Delete)GetProcAddress(Userenv, "DeleteAppContainerProfile");
    pDerive = (PFN_Derive)GetProcAddress(Userenv, "DeriveAppContainerSidFromAppContainerName");
    pFolderPath = (PFN_FolderPath)GetProcAddress(Userenv, "GetAppContainerFolderPath");
    pRegistryLocation = (PFN_RegistryLocation)GetProcAddress(Userenv, "GetAppContainerRegistryLocation");

    if (!pCreate || !pDelete || !pDerive || !pFolderPath || !pRegistryLocation)
    {
        /* Windows 7 has none of them; ReactOS exports them from export level 0x601 on */
        ok(!(is_reactos() && GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "K32EnumProcessModules")),
           "the AppContainer profile functions are not all exported\n");
        skip("the AppContainer profile functions are not available\n");
        return;
    }

    TestWithoutProfile();

    if (is_reactos() || GetEnvironmentVariableW(L"ROSAPITEST_APPCONTAINER_PROFILE", NULL, 0))
    {
        TestInvalidNames(TRUE);
        TestNameClasses();
        TestRoundTrip();
    }
    else
    {
        TestInvalidNames(FALSE);
        skip("ROSAPITEST_APPCONTAINER_PROFILE is not set, not creating a profile\n");
    }
}
