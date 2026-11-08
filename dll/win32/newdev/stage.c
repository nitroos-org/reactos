/*
 * PROJECT:     ReactOS New Device Wizard
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Stages a driver package for the Plug and Play service.
 *
 * The process that picks a driver (the wizard, Device Manager's Update Driver,
 * UpdateDriverForPlugAndPlayDevices) runs as an administrator who can read the
 * source: a UNC path, a mapped drive, a folder that other users can write, a path
 * longer than MAX_PATH. The service installs as SYSTEM and must read none of that. So
 * this process copies the package (the INF, every file the INF copies, the catalog)
 * into a new directory under %SystemRoot%\PnpStage that only SYSTEM and Administrators
 * can write (it is created with that DACL), and the service installs from that copy only.
 */

#include "newdev_private.h"

#include <sddl.h>
#include <setupapi.h>
#include <stdio.h>

/* Exported by setupapi (setupapi.spec), not declared in the public header */
WINSETUPAPI BOOL WINAPI SetupEnumInfSectionsW(HINF InfHandle, UINT Index, PWSTR Buffer, DWORD Size, PDWORD RequiredSize);

#define STAGE_MAX_FILES         4096
#define STAGE_MAX_DISKS         64
#define STAGE_EXTENDED_LENGTH   240     /* paths from here on are opened in the \\?\ form */
#define STAGE_MAX_SOURCE        32000   /* characters */

typedef struct _STAGE_STRINGS
{
    PWSTR *Items;
    ULONG Count;
    ULONG Capacity;
} STAGE_STRINGS;

typedef struct _STAGE_DISK
{
    WCHAR Id[32];
    WCHAR Path[MAX_PATH];
    WCHAR Cabinet[MAX_PATH];
} STAGE_DISK;

typedef struct _STAGE_SOURCE_FILE
{
    PWSTR Name;     /* as the INF names it */
    PWSTR Path;     /* relative to the INF's directory */
} STAGE_SOURCE_FILE;

static VOID
StringsFree(STAGE_STRINGS *List)
{
    ULONG i;

    for (i = 0; i < List->Count; i++)
        HeapFree(GetProcessHeap(), 0, List->Items[i]);
    HeapFree(GetProcessHeap(), 0, List->Items);
    ZeroMemory(List, sizeof(*List));
}

/* Adds a copy of String unless it is in the list already (the paths of a package compare
   case-insensitively); FALSE when the list is full or out of memory */
static BOOL
StringsAdd(STAGE_STRINGS *List, PCWSTR String)
{
    ULONG i;
    PWSTR Copy;

    for (i = 0; i < List->Count; i++)
    {
        if (_wcsicmp(List->Items[i], String) == 0)
            return TRUE;
    }
    if (List->Count >= STAGE_MAX_FILES)
        return FALSE;
    if (List->Count == List->Capacity)
    {
        ULONG Capacity = List->Capacity ? List->Capacity * 2 : 64;
        PWSTR *Items;

        if (List->Items)
            Items = HeapReAlloc(GetProcessHeap(), 0, List->Items, Capacity * sizeof(PWSTR));
        else
            Items = HeapAlloc(GetProcessHeap(), 0, Capacity * sizeof(PWSTR));
        if (!Items)
            return FALSE;
        List->Items = Items;
        List->Capacity = Capacity;
    }
    Copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(String) + 1) * sizeof(WCHAR));
    if (!Copy)
        return FALSE;
    wcscpy(Copy, String);
    List->Items[List->Count++] = Copy;
    return TRUE;
}

static BOOL
GetStageRoot(_Out_writes_(MAX_PATH) PWSTR Root)
{
    UINT Length = GetSystemWindowsDirectoryW(Root, MAX_PATH - 64);

    if (Length == 0 || Length >= MAX_PATH - 64)
        return FALSE;
    if (Root[Length - 1] == L'\\')
        Root[Length - 1] = UNICODE_NULL;
    wcscat(Root, L"\\" PNP_INSTALL_STAGE_ROOT);
    return TRUE;
}

/* Is Path directly in %SystemRoot%\<SubDir>? (SubDir may be a directory of the staging root;
   Path is a full path) */
static BOOL
IsUnderWindowsSubDir(PCWSTR Path, PCWSTR SubDir, BOOL Nested)
{
    WCHAR Prefix[MAX_PATH];
    SIZE_T Length;
    PCWSTR Rest;

    Length = GetSystemWindowsDirectoryW(Prefix, MAX_PATH - 64);
    if (Length == 0 || Length >= MAX_PATH - 64)
        return FALSE;
    if (Prefix[Length - 1] == L'\\')
        Prefix[--Length] = UNICODE_NULL;
    wcscat(Prefix, L"\\");
    wcscat(Prefix, SubDir);
    wcscat(Prefix, L"\\");
    Length = wcslen(Prefix);
    if (_wcsnicmp(Path, Prefix, Length) != 0)
        return FALSE;
    Rest = Path + Length;
    if (Nested)
    {
        /* <request directory>\<file> */
        PCWSTR Slash = wcschr(Rest, L'\\');

        return Slash && Slash != Rest && Slash[1] != UNICODE_NULL && wcschr(Slash + 1, L'\\') == NULL;
    }
    return *Rest != UNICODE_NULL && wcschr(Rest, L'\\') == NULL;
}

/* An INF that needs no staging: already in %SystemRoot%\inf, or a staged copy */
BOOL
IsStagedOrSystemInf(
    IN LPCWSTR InfPath)
{
    return IsUnderWindowsSubDir(InfPath, L"inf", FALSE) ||
           IsUnderWindowsSubDir(InfPath, PNP_INSTALL_STAGE_ROOT, TRUE);
}

/*
 * The full path of Path, in the \\?\ form (UNC paths as \\?\UNC\) when it is long: the
 * Win32 path functions need it beyond MAX_PATH. Free with HeapFree. NULL on failure.
 */
static PWSTR
OpenForm(PCWSTR Path)
{
    PWSTR Full, Result;
    DWORD Length;

    Full = HeapAlloc(GetProcessHeap(), 0, (STAGE_MAX_SOURCE + 8) * sizeof(WCHAR));
    if (!Full)
        return NULL;
    Length = GetFullPathNameW(Path, STAGE_MAX_SOURCE, Full, NULL);
    if (Length == 0 || Length >= STAGE_MAX_SOURCE)
    {
        HeapFree(GetProcessHeap(), 0, Full);
        return NULL;
    }
    if (Length < STAGE_EXTENDED_LENGTH ||
        wcsncmp(Full, L"\\\\?\\", 4) == 0 || wcsncmp(Full, L"\\\\.\\", 4) == 0)
    {
        return Full;
    }

    Result = HeapAlloc(GetProcessHeap(), 0, (Length + 16) * sizeof(WCHAR));
    if (Result)
    {
        if (Full[0] == L'\\' && Full[1] == L'\\')
        {
            wcscpy(Result, L"\\\\?\\UNC\\");
            wcscat(Result, Full + 2);
        }
        else
        {
            wcscpy(Result, L"\\\\?\\");
            wcscat(Result, Full);
        }
    }
    HeapFree(GetProcessHeap(), 0, Full);
    return Result;
}

/*
 * A relative path of the package from the INF's fields, normalised: no drive, no
 * leading backslash, no ".." and no "." parts, no doubled backslash, no forward slash.
 * FALSE for a path that leaves the INF's directory (not staged: such a driver
 * file is not copied, and the install reports it missing).
 */
static BOOL
BuildRelativePath(
    _Out_writes_(MAX_PATH) PWSTR Result,
    PCWSTR Part1,
    PCWSTR Part2,
    PCWSTR Part3)
{
    PCWSTR Parts[3];
    ULONG i;
    SIZE_T Length = 0;

    Parts[0] = Part1;
    Parts[1] = Part2;
    Parts[2] = Part3;
    Result[0] = UNICODE_NULL;

    for (i = 0; i < 3; i++)
    {
        PCWSTR Part = Parts[i];

        while (Part && *Part)
        {
            PCWSTR End = Part;
            SIZE_T PartLength;

            while (*End && *End != L'\\')
                End++;
            PartLength = End - Part;
            if (PartLength == 1 && Part[0] == L'.')
            {
                /* skipped */
            }
            else if (PartLength == 2 && Part[0] == L'.' && Part[1] == L'.')
            {
                return FALSE;
            }
            else if (PartLength > 0)
            {
                PCWSTR p;

                for (p = Part; p < End; p++)
                {
                    if (*p == L':' || *p == L'/' || *p == L'*' || *p == L'?' || *p == L'"' ||
                        *p == L'<' || *p == L'>' || *p == L'|' || *p < L' ')
                    {
                        return FALSE;
                    }
                }
                if (Length + PartLength + 2 >= MAX_PATH)
                    return FALSE;
                if (Length)
                    Result[Length++] = L'\\';
                wcsncpy(Result + Length, Part, PartLength);
                Length += PartLength;
                Result[Length] = UNICODE_NULL;
            }
            Part = *End ? End + 1 : End;
        }
    }
    return Length != 0;
}

static BOOL
FieldString(PINFCONTEXT Context, DWORD Field, _Out_writes_(Size) PWSTR Buffer, DWORD Size)
{
    Buffer[0] = UNICODE_NULL;
    if (!SetupGetStringFieldW(Context, Field, Buffer, Size, NULL))
    {
        Buffer[0] = UNICODE_NULL;
        return FALSE;
    }
    return TRUE;
}

/* Every file the INF names: its catalogs, the cabinets and files of SourceDisksFiles, and
   what CopyFiles copies, as paths relative to the INF's directory */
static BOOL
CollectPackageFiles(
    HINF hInf,
    STAGE_STRINGS *Files)
{
    STAGE_STRINGS Sections;
    STAGE_DISK *Disks = NULL;
    STAGE_SOURCE_FILE *Sources = NULL;
    ULONG DiskCount = 0, SourceCount = 0;
    ULONG i, s;
    WCHAR Name[MAX_PATH], Value[MAX_PATH], Value2[MAX_PATH], Relative[MAX_PATH];
    WCHAR SectionName[LINE_LEN];
    INFCONTEXT Context;
    BOOL Ok = FALSE;

    ZeroMemory(&Sections, sizeof(Sections));

    Disks = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, STAGE_MAX_DISKS * sizeof(STAGE_DISK));
    Sources = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, STAGE_MAX_FILES * sizeof(STAGE_SOURCE_FILE));
    if (!Disks || !Sources)
        goto Quit;

    for (i = 0; SetupEnumInfSectionsW(hInf, i, SectionName, ARRAYSIZE(SectionName), NULL); i++)
    {
        if (!StringsAdd(&Sections, SectionName))
            goto Quit;
    }

    /* [Version]: the catalogs (CatalogFile, CatalogFile.NTamd64, ...) */
    if (SetupFindFirstLineW(hInf, L"Version", NULL, &Context))
    {
        do
        {
            if (FieldString(&Context, 0, Name, ARRAYSIZE(Name)) &&
                _wcsnicmp(Name, L"CatalogFile", 11) == 0 &&
                FieldString(&Context, 1, Value, ARRAYSIZE(Value)) &&
                BuildRelativePath(Relative, Value, NULL, NULL))
            {
                StringsAdd(Files, Relative);
            }
        } while (SetupFindNextLine(&Context, &Context));
    }

    /* [SourceDisksNames*]: disk ID = description, tag or cabinet, , path */
    for (s = 0; s < Sections.Count; s++)
    {
        if (_wcsnicmp(Sections.Items[s], L"SourceDisksNames", 16) != 0)
            continue;
        if (!SetupFindFirstLineW(hInf, Sections.Items[s], NULL, &Context))
            continue;
        do
        {
            STAGE_DISK *Disk;

            if (DiskCount >= STAGE_MAX_DISKS)
                break;
            Disk = &Disks[DiskCount];
            if (!FieldString(&Context, 0, Disk->Id, ARRAYSIZE(Disk->Id)))
                continue;
            FieldString(&Context, 4, Disk->Path, ARRAYSIZE(Disk->Path));
            if (FieldString(&Context, 2, Value, ARRAYSIZE(Value)))
            {
                SIZE_T Length = wcslen(Value);

                if (Length > 4 && _wcsicmp(Value + Length - 4, L".cab") == 0)
                {
                    wcscpy(Disk->Cabinet, Value);
                    if (BuildRelativePath(Relative, Disk->Path, Value, NULL))
                        StringsAdd(Files, Relative);
                }
            }
            DiskCount++;
        } while (SetupFindNextLine(&Context, &Context));
    }

    /* [SourceDisksFiles*]: file = disk ID, subdirectory */
    for (s = 0; s < Sections.Count; s++)
    {
        if (_wcsnicmp(Sections.Items[s], L"SourceDisksFiles", 16) != 0)
            continue;
        if (!SetupFindFirstLineW(hInf, Sections.Items[s], NULL, &Context))
            continue;
        do
        {
            PCWSTR DiskPath = L"";

            if (!FieldString(&Context, 0, Name, ARRAYSIZE(Name)))
                continue;
            FieldString(&Context, 1, Value, ARRAYSIZE(Value));
            FieldString(&Context, 2, Value2, ARRAYSIZE(Value2));
            for (i = 0; i < DiskCount; i++)
            {
                if (_wcsicmp(Disks[i].Id, Value) == 0)
                {
                    DiskPath = Disks[i].Path;
                    break;
                }
            }
            if (!BuildRelativePath(Relative, DiskPath, Value2, Name))
            {
                TRACE("Not staged: %s (outside the INF's directory)\n", debugstr_w(Name));
                continue;
            }
            if (!StringsAdd(Files, Relative))
                goto Quit;
            if (SourceCount < STAGE_MAX_FILES)
            {
                Sources[SourceCount].Name = HeapAlloc(GetProcessHeap(), 0, (wcslen(Name) + 1) * sizeof(WCHAR));
                Sources[SourceCount].Path = HeapAlloc(GetProcessHeap(), 0, (wcslen(Relative) + 1) * sizeof(WCHAR));
                if (Sources[SourceCount].Name && Sources[SourceCount].Path)
                {
                    wcscpy(Sources[SourceCount].Name, Name);
                    wcscpy(Sources[SourceCount].Path, Relative);
                    SourceCount++;
                }
                else
                {
                    HeapFree(GetProcessHeap(), 0, Sources[SourceCount].Name);
                    HeapFree(GetProcessHeap(), 0, Sources[SourceCount].Path);
                }
            }
        } while (SetupFindNextLine(&Context, &Context));
    }

    /* CopyFiles = @file | section [, ...] in every section; a file SourceDisksFiles does not
       list is looked for in the INF's directory */
    for (s = 0; s < Sections.Count; s++)
    {
        INFCONTEXT Line;

        if (!SetupFindFirstLineW(hInf, Sections.Items[s], L"CopyFiles", &Line))
            continue;
        do
        {
            DWORD Count = SetupGetFieldCount(&Line), f;

            if (!FieldString(&Line, 0, Name, ARRAYSIZE(Name)) || _wcsicmp(Name, L"CopyFiles") != 0)
                continue;
            for (f = 1; f <= Count; f++)
            {
                PCWSTR Source;
                ULONG k;

                if (!FieldString(&Line, f, Value, ARRAYSIZE(Value)) || Value[0] == UNICODE_NULL)
                    continue;

                if (Value[0] == L'@')
                {
                    ULONG Found = 0;

                    for (k = 0; k < SourceCount; k++)
                    {
                        if (_wcsicmp(Sources[k].Name, Value + 1) == 0)
                            Found = 1;
                    }
                    if (!Found && BuildRelativePath(Relative, Value + 1, NULL, NULL))
                        StringsAdd(Files, Relative);
                    continue;
                }

                /* A file list section: destination [, source] per line */
                if (!SetupFindFirstLineW(hInf, Value, NULL, &Context))
                    continue;
                do
                {
                    ULONG Found = 0;

                    if (!FieldString(&Context, 1, Value2, ARRAYSIZE(Value2)))
                        continue;
                    Source = Value2;
                    FieldString(&Context, 2, Name, ARRAYSIZE(Name));
                    if (Name[0] != UNICODE_NULL)
                        Source = Name;
                    for (k = 0; k < SourceCount; k++)
                    {
                        if (_wcsicmp(Sources[k].Name, Source) == 0)
                            Found = 1;
                    }
                    if (!Found && BuildRelativePath(Relative, Source, NULL, NULL))
                        StringsAdd(Files, Relative);
                } while (SetupFindNextLine(&Context, &Context));
            }
        } while (SetupFindNextMatchLineW(&Line, L"CopyFiles", &Line));
    }

    Ok = TRUE;

Quit:
    for (i = 0; Sources && i < SourceCount; i++)
    {
        HeapFree(GetProcessHeap(), 0, Sources[i].Name);
        HeapFree(GetProcessHeap(), 0, Sources[i].Path);
    }
    HeapFree(GetProcessHeap(), 0, Sources);
    HeapFree(GetProcessHeap(), 0, Disks);
    StringsFree(&Sections);
    return Ok;
}

/* Removes a directory tree; reparse points are removed, never followed */
static VOID
RemoveTree(PCWSTR Path, ULONG Depth)
{
    WCHAR Pattern[MAX_PATH];
    WCHAR Child[MAX_PATH];
    WIN32_FIND_DATAW Find;
    HANDLE hFind;
    SIZE_T Length = wcslen(Path);

    if (Length + 3 >= ARRAYSIZE(Pattern) || Depth > 16)
        return;
    wcscpy(Pattern, Path);
    wcscat(Pattern, L"\\*");
    hFind = FindFirstFileW(Pattern, &Find);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (wcscmp(Find.cFileName, L".") == 0 || wcscmp(Find.cFileName, L"..") == 0)
                continue;
            if (Length + 1 + wcslen(Find.cFileName) >= ARRAYSIZE(Child))
                continue;
            wcscpy(Child, Path);
            wcscat(Child, L"\\");
            wcscat(Child, Find.cFileName);
            if (Find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (Find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                    RemoveDirectoryW(Child);
                else
                    RemoveTree(Child, Depth + 1);
            }
            else
            {
                SetFileAttributesW(Child, FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(Child);
            }
        } while (FindNextFileW(hFind, &Find));
        FindClose(hFind);
    }
    RemoveDirectoryW(Path);
}

/* Removes a staged package (the request directory StageDirectory of StageDriverPackage) */
VOID
RemoveStagedPackage(
    IN LPCWSTR StageDirectory)
{
    WCHAR Root[MAX_PATH];
    SIZE_T Length;

    /* Only ever below the staging root */
    if (!GetStageRoot(Root))
        return;
    Length = wcslen(Root);
    if (_wcsnicmp(StageDirectory, Root, Length) != 0 || StageDirectory[Length] != L'\\' ||
        StageDirectory[Length + 1] == UNICODE_NULL || wcsstr(StageDirectory, L"..") != NULL)
    {
        return;
    }
    RemoveTree(StageDirectory, 0);
}

static DWORD
CreateStageDirectory(
    _Out_writes_(MAX_PATH) PWSTR StageDirectory,
    PSECURITY_ATTRIBUTES Attributes)
{
    static LONG Counter;
    WCHAR Root[MAX_PATH];
    LARGE_INTEGER Counts;
    ULONG Try;
    DWORD Error;

    if (!GetStageRoot(Root))
        return ERROR_PATH_NOT_FOUND;
    if (!CreateDirectoryW(Root, Attributes) && GetLastError() != ERROR_ALREADY_EXISTS)
        return GetLastError();

    for (Try = 0; Try < 16; Try++)
    {
        QueryPerformanceCounter(&Counts);
        _snwprintf(StageDirectory, MAX_PATH, L"%s\\%08lX-%08lX-%08lX", Root, GetCurrentProcessId(),
                   (ULONG)Counts.LowPart ^ GetTickCount(), (ULONG)InterlockedIncrement(&Counter));
        StageDirectory[MAX_PATH - 1] = UNICODE_NULL;
        if (CreateDirectoryW(StageDirectory, Attributes))
            return ERROR_SUCCESS;
        Error = GetLastError();
        if (Error != ERROR_ALREADY_EXISTS)
            return Error;
    }
    return Error;
}

/* Copies one file of the package; a file the source does not have is skipped */
static DWORD
CopyPackageFile(
    PCWSTR SourceDirectory,
    PCWSTR StageDirectory,
    PCWSTR Relative,
    PSECURITY_ATTRIBUTES Attributes)
{
    WCHAR Destination[MAX_PATH];
    WCHAR Joined[STAGE_MAX_SOURCE / 8];
    PWSTR Source;
    PCWSTR Slash;
    SIZE_T Length;
    DWORD Error = ERROR_SUCCESS;

    Length = wcslen(StageDirectory) + 1 + wcslen(Relative);
    if (Length >= ARRAYSIZE(Destination))
        return ERROR_FILENAME_EXCED_RANGE;
    wcscpy(Destination, StageDirectory);
    wcscat(Destination, L"\\");
    wcscat(Destination, Relative);

    /* Subdirectories of the package */
    for (Slash = wcschr(Relative, L'\\'); Slash; Slash = wcschr(Slash + 1, L'\\'))
    {
        WCHAR Sub[MAX_PATH];
        SIZE_T SubLength = wcslen(StageDirectory) + 1 + (Slash - Relative);

        wcscpy(Sub, StageDirectory);
        wcscat(Sub, L"\\");
        wcsncat(Sub, Relative, Slash - Relative);
        Sub[SubLength] = UNICODE_NULL;
        if (!CreateDirectoryW(Sub, Attributes) && GetLastError() != ERROR_ALREADY_EXISTS)
            return GetLastError();
    }

    if (wcslen(SourceDirectory) + 1 + wcslen(Relative) >= ARRAYSIZE(Joined))
        return ERROR_FILENAME_EXCED_RANGE;
    wcscpy(Joined, SourceDirectory);
    wcscat(Joined, L"\\");
    wcscat(Joined, Relative);
    Source = OpenForm(Joined);
    if (!Source)
        return ERROR_FILENAME_EXCED_RANGE;

    if (!CopyFileW(Source, Destination, TRUE))
    {
        Error = GetLastError();
        if (Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND || Error == ERROR_FILE_EXISTS ||
            Error == ERROR_ALREADY_EXISTS)
        {
            TRACE("Not copied (%lu): %s\n", Error, debugstr_w(Joined));
            Error = ERROR_SUCCESS;
        }
    }
    HeapFree(GetProcessHeap(), 0, Source);
    return Error;
}

/*
 * Copies the driver package of SourceInf (a path the caller can read: local, UNC, a
 * mapped drive, longer than MAX_PATH) into a new protected directory under
 * %SystemRoot%\PnpStage. StagedInf receives the path of the INF in that copy, StageDirectory
 * the request directory (for RemoveStagedPackage). Returns a Win32 error code.
 */
DWORD
StageDriverPackage(
    IN LPCWSTR SourceInf,
    OUT PWSTR StagedInf,
    OUT PWSTR StageDirectory)
{
    SECURITY_ATTRIBUTES Attributes;
    PSECURITY_DESCRIPTOR Sd = NULL;
    PWSTR Full = NULL, SourceDirectory = NULL, SourceInfOpen = NULL;
    PWSTR Slash;
    STAGE_STRINGS Files;
    HINF hInf = INVALID_HANDLE_VALUE;
    DWORD Error;
    ULONG i;
    SIZE_T Length;

    ZeroMemory(&Files, sizeof(Files));
    StagedInf[0] = UNICODE_NULL;
    StageDirectory[0] = UNICODE_NULL;

    Full = HeapAlloc(GetProcessHeap(), 0, (STAGE_MAX_SOURCE + 8) * sizeof(WCHAR));
    if (!Full)
        return ERROR_NOT_ENOUGH_MEMORY;
    Length = GetFullPathNameW(SourceInf, STAGE_MAX_SOURCE, Full, NULL);
    if (Length == 0 || Length >= STAGE_MAX_SOURCE)
    {
        Error = ERROR_BAD_PATHNAME;
        goto Quit;
    }
    Slash = wcsrchr(Full, L'\\');
    Length = wcslen(Full);
    if (!Slash || Slash[1] == UNICODE_NULL || Length < 5 || _wcsicmp(Full + Length - 4, L".inf") != 0)
    {
        Error = ERROR_BAD_PATHNAME;
        goto Quit;
    }
    /* The file name becomes a name in the staging directory: no stream, nothing odd */
    if (wcslen(Slash + 1) > 100 || wcschr(Slash + 1, L':') != NULL)
    {
        Error = ERROR_BAD_PATHNAME;
        goto Quit;
    }
    /* Source directory (without the trailing backslash, except for a drive's root) */
    if (Slash - Full == 2 && Full[1] == L':')
        Slash++;
    SourceDirectory = HeapAlloc(GetProcessHeap(), 0, (Slash - Full + 2) * sizeof(WCHAR));
    if (!SourceDirectory)
    {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto Quit;
    }
    wcsncpy(SourceDirectory, Full, Slash - Full);
    SourceDirectory[Slash - Full] = UNICODE_NULL;
    Slash = wcsrchr(Full, L'\\');

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(PNP_INSTALL_STAGE_SDDL, SDDL_REVISION_1, &Sd, NULL))
    {
        Error = GetLastError();
        goto Quit;
    }
    Attributes.nLength = sizeof(Attributes);
    Attributes.lpSecurityDescriptor = Sd;
    Attributes.bInheritHandle = FALSE;

    Error = CreateStageDirectory(StageDirectory, &Attributes);
    if (Error != ERROR_SUCCESS)
    {
        StageDirectory[0] = UNICODE_NULL;
        goto Quit;
    }

    /* The INF first, so that it is parsed from the copy (setupapi's paths are MAX_PATH-bound) */
    _snwprintf(StagedInf, MAX_PATH, L"%s\\%s", StageDirectory, Slash + 1);
    StagedInf[MAX_PATH - 1] = UNICODE_NULL;
    SourceInfOpen = OpenForm(Full);
    if (!SourceInfOpen)
    {
        Error = ERROR_FILENAME_EXCED_RANGE;
        goto Quit;
    }
    if (!CopyFileW(SourceInfOpen, StagedInf, TRUE))
    {
        Error = GetLastError();
        goto Quit;
    }

    hInf = SetupOpenInfFileW(StagedInf, NULL, INF_STYLE_WIN4, NULL);
    if (hInf == INVALID_HANDLE_VALUE)
    {
        Error = GetLastError();
        goto Quit;
    }
    if (!CollectPackageFiles(hInf, &Files))
    {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto Quit;
    }

    Error = ERROR_SUCCESS;
    for (i = 0; i < Files.Count && Error == ERROR_SUCCESS; i++)
        Error = CopyPackageFile(SourceDirectory, StageDirectory, Files.Items[i], &Attributes);

Quit:
    if (hInf != INVALID_HANDLE_VALUE)
        SetupCloseInfFile(hInf);
    if (Error != ERROR_SUCCESS && StageDirectory[0] != UNICODE_NULL)
    {
        RemoveStagedPackage(StageDirectory);
        StageDirectory[0] = UNICODE_NULL;
        StagedInf[0] = UNICODE_NULL;
    }
    StringsFree(&Files);
    if (Sd)
        LocalFree(Sd);
    HeapFree(GetProcessHeap(), 0, SourceInfOpen);
    HeapFree(GetProcessHeap(), 0, SourceDirectory);
    HeapFree(GetProcessHeap(), 0, Full);
    return Error;
}
