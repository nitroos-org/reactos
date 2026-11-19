/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SetFileInformationByHandle(FileDispositionInfoEx): the flags reach the file system. A file with a
 *              view of its data is refused the classic delete and the POSIX delete that asks for the image check
 *              (what DeleteFile asks for) with ERROR_ACCESS_DENIED; without a view both work
 *              (the expected values are the ones measured on Windows Server 2022, NTFS)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define DISP_DELETE 0x1
#define DISP_POSIX  0x2
#define DISP_FORCE_IMAGE 0x4
#define FILE_DISPOSITION_INFO_EX_CLASS 21

static void MakeFile(const char *Path, DWORD Size, BYTE Fill)
{
    BYTE Buffer[4096];
    DWORD Done, Total = 0;
    HANDLE File = CreateFileA(Path, GENERIC_WRITE, SHARE_ALL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    ok(File != INVALID_HANDLE_VALUE, "create %s failed %lu\n", Path, GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    memset(Buffer, Fill, sizeof(Buffer));
    while (Total < Size)
    {
        WriteFile(File, Buffer, min(Size - Total, (DWORD)sizeof(Buffer)), &Done, NULL);
        Total += Done ? Done : 1;
    }
    CloseHandle(File);
}

/* maps the file and closes the handles: only the view is left */
static PVOID MapOnly(const char *Path)
{
    HANDLE File = CreateFileA(Path, GENERIC_READ | GENERIC_WRITE, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE Map = File == INVALID_HANDLE_VALUE ? NULL : CreateFileMappingA(File, NULL, PAGE_READWRITE, 0, 0, NULL);
    PVOID View = Map ? MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, 0) : NULL;

    ok(View != NULL, "map failed %lu\n", GetLastError());
    if (Map) CloseHandle(Map);
    if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
    return View;
}

static DWORD SetDisposition(const char *Path, DWORD Flags)
{
    BOOL Ok;
    DWORD Error;
    HANDLE File;
    /* not declared for the Windows 2003 headers: looked up */
    BOOL (WINAPI *pSetFileInformationByHandle)(HANDLE, INT, LPVOID, DWORD) =
        (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetFileInformationByHandle");

    if (!pSetFileInformationByHandle)
        return ERROR_CALL_NOT_IMPLEMENTED;
    File = CreateFileA(Path, DELETE | GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return GetLastError();
    Ok = pSetFileInformationByHandle(File, FILE_DISPOSITION_INFO_EX_CLASS, &Flags, sizeof(Flags));
    Error = Ok ? 0 : GetLastError();
    CloseHandle(File);
    return Error;
}

static BOOL Exists(const char *Path)
{
    return GetFileAttributesA(Path) != INVALID_FILE_ATTRIBUTES;
}

START_TEST(FileDispositionEx)
{
    char Dir[MAX_PATH], Target[MAX_PATH];
    PVOID View;

    if (!GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetFileInformationByHandle"))
    {
        skip("SetFileInformationByHandle is not available\n");
        return;
    }
    GetTempPathA(sizeof(Dir), Dir);
    sprintf(Target, "%sdispex_%lu_t.bin", Dir, GetCurrentProcessId());

    /* no view: the classic and the POSIX delete work, with and without the image check */
    MakeFile(Target, 65536, 'x');
    ok_dec(SetDisposition(Target, DISP_DELETE), 0);
    ok_dec(Exists(Target), FALSE);
    MakeFile(Target, 65536, 'x');
    ok_dec(SetDisposition(Target, DISP_DELETE | DISP_POSIX), 0);
    ok_dec(Exists(Target), FALSE);
    MakeFile(Target, 65536, 'x');
    ok_dec(SetDisposition(Target, DISP_DELETE | DISP_POSIX | DISP_FORCE_IMAGE), 0);
    ok_dec(Exists(Target), FALSE);

    /* a view of the data and no handle: the classic delete and the POSIX delete with the image check are refused */
    MakeFile(Target, 65536, 'x');
    View = MapOnly(Target);
    ok_dec(SetDisposition(Target, DISP_DELETE), ERROR_ACCESS_DENIED);
    ok_dec(Exists(Target), TRUE);
    ok_dec(SetDisposition(Target, DISP_DELETE | DISP_POSIX | DISP_FORCE_IMAGE), ERROR_ACCESS_DENIED);
    ok_dec(Exists(Target), TRUE);
    if (View)
    {
        ok_hex(((PBYTE)View)[0], 'x');
        UnmapViewOfFile(View);
    }
    ok_dec(SetDisposition(Target, DISP_DELETE), 0);
    ok_dec(Exists(Target), FALSE);
    DeleteFileA(Target);
}
