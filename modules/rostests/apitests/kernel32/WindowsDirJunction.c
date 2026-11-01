/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     Setup makes \Windows a junction to the system directory on NTFS installs
 */

#include "precomp.h"
#include <winioctl.h>

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003
#endif

typedef struct _JUNCTION_DATA
{
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    USHORT SubstituteNameOffset;
    USHORT SubstituteNameLength;
    USHORT PrintNameOffset;
    USHORT PrintNameLength;
    WCHAR PathBuffer[2 * MAX_PATH];
} JUNCTION_DATA;

typedef DWORD (WINAPI *FN_GetFinalPathNameByHandleW)(HANDLE, LPWSTR, DWORD, DWORD);
typedef BOOL (WINAPI *FN_IsWow64Process)(HANDLE, PBOOL);

static HANDLE OpenDir(PCWSTR Path, DWORD Flags)
{
    return CreateFileW(Path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | Flags, NULL);
}

static void TestReparseData(PCWSTR Link, PCWSTR System)
{
    JUNCTION_DATA Data;
    WCHAR Expected[MAX_PATH + 4];
    HANDLE Handle;
    DWORD Returned = 0;
    BOOL Ret;
    PCWSTR Sub, Print;

    Handle = OpenDir(Link, FILE_FLAG_OPEN_REPARSE_POINT);
    ok(Handle != INVALID_HANDLE_VALUE, "Opening %S as a reparse point failed, error %lu\n", Link, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;

    memset(&Data, 0, sizeof(Data));
    Ret = DeviceIoControl(Handle, FSCTL_GET_REPARSE_POINT, NULL, 0, &Data, sizeof(Data), &Returned, NULL);
    CloseHandle(Handle);
    ok(Ret, "FSCTL_GET_REPARSE_POINT on %S failed, error %lu\n", Link, GetLastError());
    if (!Ret)
        return;

    ok(Data.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT, "ReparseTag = 0x%lx\n", Data.ReparseTag);
    ok(Data.SubstituteNameOffset == 0, "SubstituteNameOffset = %u\n", Data.SubstituteNameOffset);
    Sub = (PCWSTR)((PUCHAR)Data.PathBuffer + Data.SubstituteNameOffset);
    Print = (PCWSTR)((PUCHAR)Data.PathBuffer + Data.PrintNameOffset);

    /* Like mklink /J: substitute name is the NT path, print name the Win32 path */
    wcscpy(Expected, L"\\??\\");
    wcscat(Expected, System);
    ok(Data.SubstituteNameLength == wcslen(Expected) * sizeof(WCHAR) &&
       !_wcsnicmp(Sub, Expected, Data.SubstituteNameLength / sizeof(WCHAR)),
       "Substitute name is %.*S, expected %S\n", Data.SubstituteNameLength / (int)sizeof(WCHAR), Sub, Expected);
    ok(Data.PrintNameLength == wcslen(System) * sizeof(WCHAR) &&
       !_wcsnicmp(Print, System, Data.PrintNameLength / sizeof(WCHAR)),
       "Print name is %.*S, expected %S\n", Data.PrintNameLength / (int)sizeof(WCHAR), Print, System);
    ok(Data.PrintNameOffset == Data.SubstituteNameLength + sizeof(WCHAR),
       "PrintNameOffset = %u\n", Data.PrintNameOffset);
    ok(Data.ReparseDataLength == 8 + Data.SubstituteNameLength + Data.PrintNameLength + 2 * sizeof(WCHAR),
       "ReparseDataLength = %u\n", Data.ReparseDataLength);
}

static void TestEnumeration(PCWSTR Link)
{
    WIN32_FIND_DATAW Find;
    HANDLE Handle;

    /* This is what cmd's dir shows as <JUNCTION> and what directory walkers test */
    Handle = FindFirstFileW(Link, &Find);
    ok(Handle != INVALID_HANDLE_VALUE, "FindFirstFile(%S) failed, error %lu\n", Link, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    FindClose(Handle);
    ok((Find.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ==
       (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT),
       "dwFileAttributes = 0x%lx\n", Find.dwFileAttributes);
    ok(Find.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT, "dwReserved0 = 0x%lx\n", Find.dwReserved0);
}

static void TestResolve(PCWSTR Drive, PCWSTR System)
{
    FN_GetFinalPathNameByHandleW pGetFinalPathNameByHandleW;
    FN_IsWow64Process pIsWow64Process;
    BY_HANDLE_FILE_INFORMATION ViaLink, Direct;
    WCHAR Path[MAX_PATH + 4], Expected[MAX_PATH + 4];
    BOOL Wow64 = FALSE;
    HANDLE Handle;
    DWORD Length;

    pGetFinalPathNameByHandleW = (FN_GetFinalPathNameByHandleW)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFinalPathNameByHandleW");
    pIsWow64Process = (FN_IsWow64Process)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process");
    if (pIsWow64Process)
        pIsWow64Process(GetCurrentProcess(), &Wow64);

    ok(GetFileAttributesW(L"C:\\") != INVALID_FILE_ATTRIBUTES, "Cannot reach the drive root\n");

    /* A file below the junction is the file below the system directory (through the WoW64
     * file system redirection for a 32-bit process on both paths) */
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\Windows\\System32\\kernel32.dll", Drive);
    Handle = CreateFileW(Path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "Opening %S failed, error %lu\n", Path, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    ok(GetFileInformationByHandle(Handle, &ViaLink), "GetFileInformationByHandle failed\n");
    CloseHandle(Handle);

    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\System32\\kernel32.dll", System);
    Handle = CreateFileW(Path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "Opening %S failed, error %lu\n", Path, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    ok(GetFileInformationByHandle(Handle, &Direct), "GetFileInformationByHandle failed\n");
    CloseHandle(Handle);
    ok(ViaLink.dwVolumeSerialNumber == Direct.dwVolumeSerialNumber &&
       ViaLink.nFileIndexHigh == Direct.nFileIndexHigh && ViaLink.nFileIndexLow == Direct.nFileIndexLow,
       "Different files: %08lx:%08lx%08lx vs %08lx:%08lx%08lx\n",
       ViaLink.dwVolumeSerialNumber, ViaLink.nFileIndexHigh, ViaLink.nFileIndexLow,
       Direct.dwVolumeSerialNumber, Direct.nFileIndexHigh, Direct.nFileIndexLow);

    if (!pGetFinalPathNameByHandleW)
    {
        skip("GetFinalPathNameByHandleW is not available\n");
        return;
    }

    /* \Windows\System32 resolves to the system directory's System32 (SysWOW64 for 32-bit code on 64-bit) */
    StringCchPrintfW(Path, ARRAYSIZE(Path), L"%s\\Windows\\System32", Drive);
    Handle = OpenDir(Path, 0);
    ok(Handle != INVALID_HANDLE_VALUE, "Opening %S failed, error %lu\n", Path, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return;
    Length = pGetFinalPathNameByHandleW(Handle, Path, ARRAYSIZE(Path), 0);
    CloseHandle(Handle);
    ok(Length && Length < ARRAYSIZE(Path), "GetFinalPathNameByHandleW returned %lu, error %lu\n", Length, GetLastError());
    StringCchPrintfW(Expected, ARRAYSIZE(Expected), L"\\\\?\\%s\\%s", System, Wow64 ? L"SysWOW64" : L"System32");
    ok(!_wcsicmp(Path, Expected), "Final path is %S, expected %S\n", Path, Expected);
}

START_TEST(WindowsDirJunction)
{
    WCHAR System[MAX_PATH], Root[4], Link[MAX_PATH], Drive[3], FsName[MAX_PATH];
    DWORD Attributes, FsFlags;

    if (!GetWindowsDirectoryW(System, ARRAYSIZE(System)) || System[1] != L':' || System[2] != L'\\')
    {
        skip("Unexpected system directory\n");
        return;
    }
    Drive[0] = System[0];
    Drive[1] = L':';
    Drive[2] = UNICODE_NULL;
    StringCchPrintfW(Root, ARRAYSIZE(Root), L"%s\\", Drive);
    StringCchPrintfW(Link, ARRAYSIZE(Link), L"%s\\Windows", Drive);

    if (!_wcsicmp(System, Link))
    {
        skip("The system directory is %S itself\n", Link);
        return;
    }
    if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, &FsFlags, FsName, ARRAYSIZE(FsName)) ||
        !(FsFlags & FILE_SUPPORTS_REPARSE_POINTS))
    {
        skip("%S has no reparse points (%S)\n", Root, FsName);
        return;
    }

    Attributes = GetFileAttributesW(Link);
    if (Attributes != INVALID_FILE_ATTRIBUTES && !(Attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        skip("%S is another directory (another Windows on this volume), not ours\n", Link);
        return;
    }
    ok(Attributes != INVALID_FILE_ATTRIBUTES, "%S does not exist on a %S volume, error %lu\n",
       Link, FsName, GetLastError());
    if (Attributes == INVALID_FILE_ATTRIBUTES)
        return;
    ok(Attributes & FILE_ATTRIBUTE_DIRECTORY, "Attributes = 0x%lx\n", Attributes);

    TestReparseData(Link, System);
    TestEnumeration(Link);
    TestResolve(Drive, System);
}
