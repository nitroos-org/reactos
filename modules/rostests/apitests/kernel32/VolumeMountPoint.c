/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for SetVolumeMountPointW and DeleteVolumeMountPointW
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected error codes were measured on Windows Server 2008 R2 with a probe that called both functions
 * on two scratch NTFS volumes and a FAT32 volume; the folder that is not there and the letter in use with a
 * bad volume name were measured again on Windows Server 2022 (they differ).The first part needs no scratch volume. The second part
 * changes drive letters of a volume and runs only when the environment names a scratch volume that has no
 * drive letter and no path: KERNEL32_TEST_VOLUME is its name ("\\?\Volume{GUID}\"), or KERNEL32_TEST_LABEL
 * is the label to look for. KERNEL32_TEST_HOST, the root of an NTFS volume ("Q:\"), is where the mount
 * point folders of the last part are made; without it the temporary folder is used. The two checks that delete a
 * drive letter that this test does not own run only when KERNEL32_TEST_ISOLATED is set, where nothing else assigns letters.
 */

#include "precomp.h"
#include <versionhelpers.h>

#define ok_lasterr(Expected) \
    ok(GetLastError() == (Expected), "error %lu, expected %lu\n", GetLastError(), (DWORD)(Expected))

static WCHAR
FreeDriveLetter(VOID)
{
    DWORD Used = GetLogicalDrives();
    WCHAR Letter;

    for (Letter = L'Z'; Letter >= L'D'; Letter--)
        if (!(Used & (1UL << (Letter - L'A'))))
            return Letter;
    return 0;
}

static BOOL
VolumeHasPath(PCWSTR Volume, PCWSTR Wanted)
{
    WCHAR Paths[512];
    DWORD Length = 0;
    PCWSTR Path;

    ZeroMemory(Paths, sizeof(Paths));
    if (!GetVolumePathNamesForVolumeNameW(Volume, Paths, ARRAYSIZE(Paths) - 1, &Length))
        return FALSE;
    for (Path = Paths; *Path; Path += wcslen(Path) + 1)
        if (_wcsicmp(Path, Wanted) == 0)
            return TRUE;
    return FALSE;
}

/* the number of paths of the volume, or (DWORD)-1 when they cannot be listed */
static DWORD
VolumePathCount(PCWSTR Volume)
{
    PWSTR Paths;
    DWORD Length = 0, Size = 1024, Count = 0;
    PCWSTR Path;
    BOOL Ok;

    for (;;)
    {
        Paths = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (Size + 2) * sizeof(WCHAR));
        if (Paths == NULL)
            return (DWORD)-1;
        Ok = GetVolumePathNamesForVolumeNameW(Volume, Paths, Size, &Length);
        if (Ok || GetLastError() != ERROR_MORE_DATA)
            break;
        HeapFree(GetProcessHeap(), 0, Paths);
        Size = Length + 2;
    }
    if (Ok)
        for (Path = Paths; *Path; Path += wcslen(Path) + 1)
            Count++;
    HeapFree(GetProcessHeap(), 0, Paths);
    return Ok ? Count : (DWORD)-1;
}

/* Deleting a drive letter that nothing of ours owns could remove the mapping of another process that took it in
 * the meantime: those checks run only where the drive letters are controlled (KERNEL32_TEST_ISOLATED is set) */
static BOOL
IsIsolatedEnvironment(VOID)
{
    return GetEnvironmentVariableW(L"KERNEL32_TEST_ISOLATED", NULL, 0) != 0;
}

static VOID
Test_Arguments(VOID)
{
    WCHAR Root[4], SystemRoot[4], SystemVolume[MAX_PATH], Windows[MAX_PATH], Temp[MAX_PATH], Missing[MAX_PATH];
    WCHAR Letter = FreeDriveLetter();
    BOOL Ret;

    SetLastError(0xDEADBEEF);
    Ret = SetVolumeMountPointW(NULL, NULL);
    ok(Ret == FALSE, "SetVolumeMountPointW(NULL, NULL) succeeded\n");
    ok_lasterr(ERROR_INVALID_PARAMETER);

    SetLastError(0xDEADBEEF);
    Ret = DeleteVolumeMountPointW(NULL);
    ok(Ret == FALSE, "DeleteVolumeMountPointW(NULL) succeeded\n");
    ok_lasterr(ERROR_INVALID_PARAMETER);

    if (Letter == 0)
    {
        skip("no free drive letter\n");
        return;
    }
    Root[0] = Letter; Root[1] = L':'; Root[2] = L'\\'; Root[3] = 0;

    if (GetWindowsDirectoryW(Windows, ARRAYSIZE(Windows)) < 3)
        return;
    SystemRoot[0] = Windows[0]; SystemRoot[1] = L':'; SystemRoot[2] = L'\\'; SystemRoot[3] = 0;
    if (!GetVolumeNameForVolumeMountPointW(SystemRoot, SystemVolume, ARRAYSIZE(SystemVolume)))
    {
        skip("no volume name for %ls: %lu\n", SystemRoot, GetLastError());
        return;
    }

    /* the mount point must end with a backslash; only "X:\" is a drive letter */
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(L"Y:", SystemVolume), "Y: without a backslash\n");
    ok_lasterr(ERROR_INVALID_NAME);
    SetLastError(0xDEADBEEF);
    ok(!DeleteVolumeMountPointW(L"Y:"), "Y: without a backslash\n");
    ok_lasterr(ERROR_INVALID_NAME);

    /* the volume name must be a volume name */
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(Root, L"Y:\\"), "a drive letter as the volume name\n");
    ok_lasterr(ERROR_INVALID_PARAMETER);
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(Root, L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\"), "a volume that is not there\n");
    ok_lasterr(ERROR_INVALID_PARAMETER);
    {
        WCHAR NoBackslash[MAX_PATH];

        wcscpy(NoBackslash, SystemVolume);
        NoBackslash[wcslen(NoBackslash) - 1] = 0;
        SetLastError(0xDEADBEEF);
        ok(!SetVolumeMountPointW(Root, NoBackslash), "a volume name without the closing backslash\n");
        ok_lasterr(ERROR_INVALID_NAME);
    }

    /* a letter that is in use is refused, also for the volume that has it */
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(SystemRoot, SystemVolume), "the system drive letter again\n");
    ok_lasterr(ERROR_DIR_NOT_EMPTY);

    /* deleting what is not there */
    if (IsIsolatedEnvironment())
    {
        SetLastError(0xDEADBEEF);
        ok(!DeleteVolumeMountPointW(Root), "a letter nothing uses\n");
        ok_lasterr(ERROR_FILE_NOT_FOUND);
    }
    else
    {
        skip("KERNEL32_TEST_ISOLATED is not set: no drive letter is deleted that this test does not own\n");
    }

    /* a folder that is no mount point: on a file system without reparse points there is nothing to ask about */
    StringCchPrintfW(Temp, ARRAYSIZE(Temp), L"%ls\\", Windows);
    {
        DWORD Flags = 0;

        GetVolumeInformationW(SystemRoot, NULL, 0, NULL, NULL, &Flags, NULL, 0);
        SetLastError(0xDEADBEEF);
        ok(!DeleteVolumeMountPointW(Temp), "the Windows folder\n");
        ok_lasterr((Flags & FILE_SUPPORTS_REPARSE_POINTS) ? ERROR_NOT_A_REPARSE_POINT : ERROR_INVALID_FUNCTION);
    }
    StringCchPrintfW(Missing, ARRAYSIZE(Missing), L"%ls\\no-such-folder-%lu\\", Windows, GetCurrentProcessId());
    SetLastError(0xDEADBEEF);
    ok(!DeleteVolumeMountPointW(Missing), "a folder that is not there\n");
    ok_lasterr(ERROR_FILE_NOT_FOUND);
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(Missing, SystemVolume), "a mount point folder that is not there\n");
    ok_lasterr(ERROR_FILE_NOT_FOUND);   /* Windows Server 2022; Server 2008 R2 answered ERROR_INVALID_PARAMETER */

    /* a drive letter that is in use is refused before the volume name is looked at (Windows Server 2022) */
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(SystemRoot, L"Y:\\"), "the system drive letter with a bad volume name\n");
    ok_lasterr(ERROR_DIR_NOT_EMPTY);

    /* the ANSI forms */
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointA(NULL, NULL), "SetVolumeMountPointA(NULL, NULL)\n");
    ok_lasterr(ERROR_INVALID_PARAMETER);
    SetLastError(0xDEADBEEF);
    ok(!DeleteVolumeMountPointA(NULL), "DeleteVolumeMountPointA(NULL)\n");
    ok_lasterr(ERROR_INVALID_NAME);
}

/* TRUE when the letter names the volume: only then the test may delete it */
static BOOL
LetterIsVolume(PCWSTR Root, PCWSTR Volume)
{
    WCHAR Name[MAX_PATH];

    return GetVolumeNameForVolumeMountPointW(Root, Name, ARRAYSIZE(Name)) && _wcsicmp(Name, Volume) == 0;
}

static VOID
Test_Letters(PCWSTR Volume)
{
    WCHAR Letter = FreeDriveLetter(), Other, Root[4], OtherRoot[4], Lower[4];

    if (Letter == 0)
    {
        skip("no free drive letter\n");
        return;
    }
    Other = Letter - 1;
    if (Other < L'D' || (GetLogicalDrives() & (1UL << (Other - L'A'))))
        Other = 0;
    Root[0] = Letter; Root[1] = L':'; Root[2] = L'\\'; Root[3] = 0;

    ok_int(VolumePathCount(Volume), 0);

    if (!SetVolumeMountPointW(Root, Volume))
    {
        ok(0, "SetVolumeMountPointW(%ls) failed: %lu\n", Root, GetLastError());
        return;
    }
    ok(VolumeHasPath(Volume, Root), "the volume has no path %ls\n", Root);
    ok(LetterIsVolume(Root, Volume), "volume of %ls is not the scratch volume\n", Root);
    ok_int(GetDriveTypeW(Root), DRIVE_FIXED);

    /* the same letter again, and a second letter for a volume that has one */
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(Root, Volume), "the same letter twice\n");
    ok_lasterr(ERROR_DIR_NOT_EMPTY);
    if (Other)
    {
        OtherRoot[0] = Other; OtherRoot[1] = L':'; OtherRoot[2] = L'\\'; OtherRoot[3] = 0;
        SetLastError(0xDEADBEEF);
        ok(!SetVolumeMountPointW(OtherRoot, Volume), "a second letter for the volume\n");
        ok_lasterr(ERROR_INVALID_PARAMETER);
    }

    if (!LetterIsVolume(Root, Volume))
        return;
    ok(DeleteVolumeMountPointW(Root), "DeleteVolumeMountPointW(%ls) failed: %lu\n", Root, GetLastError());
    ok(!VolumeHasPath(Volume, Root), "the volume keeps %ls\n", Root);
    ok_int(GetDriveTypeW(Root), DRIVE_NO_ROOT_DIR);
    if (IsIsolatedEnvironment())
    {
        SetLastError(0xDEADBEEF);
        ok(!DeleteVolumeMountPointW(Root), "the letter twice\n");
        ok_lasterr(ERROR_FILE_NOT_FOUND);
    }

    /* upper and lower case are the same letter */
    Lower[0] = (WCHAR)towlower(Letter); Lower[1] = L':'; Lower[2] = L'\\'; Lower[3] = 0;
    if (!SetVolumeMountPointW(Lower, Volume))
    {
        ok(0, "lower case letter failed: %lu\n", GetLastError());
        return;
    }
    ok(VolumeHasPath(Volume, Root), "the volume has no path %ls\n", Root);
    if (LetterIsVolume(Lower, Volume))
        ok(DeleteVolumeMountPointW(Lower), "deleting the lower case letter failed: %lu\n", GetLastError());
    ok_int(VolumePathCount(Volume), 0);
}

static VOID
Test_Folder(PCWSTR Volume)
{
    WCHAR Base[MAX_PATH], Root[MAX_PATH], Folder[MAX_PATH], Full[MAX_PATH], FullFile[MAX_PATH], Name[MAX_PATH];
    HANDLE File = INVALID_HANDLE_VALUE;
    BOOL MadeRoot = FALSE, MadeFolder = FALSE, MadeFull = FALSE;
    DWORD HostFlags = 0;

    if (GetEnvironmentVariableW(L"KERNEL32_TEST_HOST", Base, ARRAYSIZE(Base)) == 0 && GetTempPathW(ARRAYSIZE(Base), Base) == 0)
        return;

    /* a folder of its own, made new: the test removes only what it made */
    StringCchPrintfW(Root, ARRAYSIZE(Root), L"%lssdm-mp-%lu-%lu\\", Base, GetCurrentProcessId(), GetTickCount());
    StringCchPrintfW(Folder, ARRAYSIZE(Folder), L"%lsmnt\\", Root);
    StringCchPrintfW(Full, ARRAYSIZE(Full), L"%lsfull\\", Root);
    StringCchPrintfW(FullFile, ARRAYSIZE(FullFile), L"%lsfile.txt", Full);
    MadeRoot = CreateDirectoryW(Root, NULL);
    ok(MadeRoot, "cannot make %ls: %lu\n", Root, GetLastError());
    if (!MadeRoot)
        return;
    MadeFolder = CreateDirectoryW(Folder, NULL);
    MadeFull = CreateDirectoryW(Full, NULL);
    ok(MadeFolder && MadeFull, "cannot make the folders under %ls\n", Root);
    if (MadeFull)
    {
        /* the file goes away with this handle, whatever the path has become by then */
        File = CreateFileW(FullFile, GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    }
    if (!MadeFolder || !MadeFull || File == INVALID_HANDLE_VALUE)
        goto Cleanup;

    if (!SetVolumeMountPointW(Folder, Volume))
    {
        DWORD MountError = GetLastError();
        WCHAR HostRoot[MAX_PATH];

        /* a file system that keeps no reparse points says so with this error; anything else is a failure */
        if (!GetVolumePathNameW(Root, HostRoot, ARRAYSIZE(HostRoot)) ||
            !GetVolumeInformationW(HostRoot, NULL, 0, NULL, NULL, &HostFlags, NULL, 0))
        {
            ok(0, "cannot query the host volume of %ls: %lu\n", Root, GetLastError());
        }
        else if (!(HostFlags & FILE_SUPPORTS_REPARSE_POINTS) && MountError == ERROR_INVALID_FUNCTION)
        {
            skip("the file system of %ls keeps no mount points\n", Root);
        }
        else
        {
            ok(0, "SetVolumeMountPointW(%ls) failed: %lu\n", Folder, MountError);
        }
        goto Cleanup;
    }
    /* the mount manager of ReactOS rejects the notice of a new folder mount, so it does not list the path */
    if (!VolumeHasPath(Volume, Folder) && IsReactOS())
        skip("the mount manager lists no folder mount points\n");
    else
        ok(VolumeHasPath(Volume, Folder), "the volume has no path %ls\n", Folder);
    ok(GetVolumeNameForVolumeMountPointW(Folder, Name, ARRAYSIZE(Name)), "no volume name for %ls\n", Folder);
    ok(_wcsicmp(Name, Volume) == 0, "volume of %ls is %ls\n", Folder, Name);

    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(Folder, Volume), "a mount point mounted twice\n");
    ok_lasterr(ERROR_DIR_NOT_EMPTY);
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(Full, Volume), "a folder that holds a file\n");
    ok_lasterr(ERROR_DIR_NOT_EMPTY);
    SetLastError(0xDEADBEEF);
    ok(!SetVolumeMountPointW(Folder, L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\"), "a volume that is not there\n");

    ok(DeleteVolumeMountPointW(Folder), "DeleteVolumeMountPointW(%ls) failed: %lu\n", Folder, GetLastError());
    ok_int(VolumePathCount(Volume), 0);
    ok_int(GetFileAttributesW(Folder) != INVALID_FILE_ATTRIBUTES, TRUE);
    SetLastError(0xDEADBEEF);
    ok(!DeleteVolumeMountPointW(Folder), "the mount point twice\n");
    ok_lasterr(ERROR_NOT_A_REPARSE_POINT);

Cleanup:
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    if (MadeFull)
        RemoveDirectoryW(Full);
    if (MadeFolder)
        RemoveDirectoryW(Folder);
    if (MadeRoot)
        RemoveDirectoryW(Root);
}

/* the volume with the label that has no path at all */
static BOOL
FindScratchVolume(PCWSTR Label, PWSTR Volume, SIZE_T Count)
{
    WCHAR Guid[MAX_PATH], Found[64];
    HANDLE Find = FindFirstVolumeW(Guid, ARRAYSIZE(Guid));
    BOOL Result = FALSE;

    if (Find == INVALID_HANDLE_VALUE)
        return FALSE;
    do
    {
        if (GetVolumeInformationW(Guid, Found, ARRAYSIZE(Found), NULL, NULL, NULL, NULL, 0) &&
            wcscmp(Found, Label) == 0 && VolumePathCount(Guid) == 0)
        {
            Result = SUCCEEDED(StringCchCopyW(Volume, Count, Guid));
            break;
        }
    } while (FindNextVolumeW(Find, Guid, ARRAYSIZE(Guid)));
    FindVolumeClose(Find);
    return Result;
}

START_TEST(VolumeMountPoint)
{
    WCHAR Volume[MAX_PATH], Label[64];

    Test_Arguments();

    if (GetEnvironmentVariableW(L"KERNEL32_TEST_VOLUME", Volume, ARRAYSIZE(Volume)) == 0)
    {
        if (GetEnvironmentVariableW(L"KERNEL32_TEST_LABEL", Label, ARRAYSIZE(Label)) == 0 ||
            !FindScratchVolume(Label, Volume, ARRAYSIZE(Volume)))
        {
            skip("no scratch volume: KERNEL32_TEST_VOLUME or KERNEL32_TEST_LABEL names one; the live part is not run\n");
            return;
        }
    }
    Test_Letters(Volume);
    Test_Folder(Volume);
}
