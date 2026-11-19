/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DeleteFile on a file that a process has mapped: refused for as long as a view exists, whether the view
 *              is of a data or of an image section, whatever the share mode, and also when only the view is left
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expectations were measured with the same code on Windows Server 2022 (10.0.20348, NTFS): ERROR_ACCESS_DENIED
 * (5) for every data view, read-only or writable, opened with any share mode and with the file or the mapping handle
 * kept or closed; ERROR_SHARING_VIOLATION (32) while the handle that made the view is open without FILE_SHARE_DELETE;
 * the delete works once the view is unmapped.
 */

#ifdef FILEDELMAP_PROBE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int g_fail;
#define ok(c, ...) do { if (!(c)) { g_fail++; printf("MISMATCH: "); printf(__VA_ARGS__); } } while (0)
#define trace(...) printf(__VA_ARGS__)
#else
#include "precomp.h"
#endif

static void MakePath(char *Path)
{
    char Dir[MAX_PATH];
    GetTempPathA(sizeof(Dir), Dir);
    sprintf(Path, "%sdelmap_%lu.tmp", Dir, GetCurrentProcessId());
}

static BOOL MakeFile(const char *Path)
{
    HANDLE File = CreateFileA(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    BYTE Data[65536] = { 0 };
    DWORD Written;

    if (File == INVALID_HANDLE_VALUE) return FALSE;
    WriteFile(File, Data, sizeof(Data), &Written, NULL);
    CloseHandle(File);
    return TRUE;
}

/* The Win32 error of DeleteFile (0 when the file is gone) */
static DWORD DeleteRow(const char *Path)
{
    if (DeleteFileA(Path)) return 0;
    return GetLastError();
}

static void TestDataView(BOOL Writable, DWORD Share, int Keep)
{
    char Path[MAX_PATH];
    char Name[160];
    HANDLE File, Mapping;
    void *View;
    DWORD Error, Expected;
    static const char *const KeepNames[] = { "file and mapping handles kept", "file handle closed", "only the view left" };

    MakePath(Path);
    ok(MakeFile(Path), "MakeFile failed with %lu\n", GetLastError());
    File = CreateFileA(Path, GENERIC_READ | (Writable ? GENERIC_WRITE : 0) | DELETE, Share, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "open failed with %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE) { DeleteFileA(Path); return; }
    Mapping = CreateFileMappingA(File, NULL, Writable ? PAGE_READWRITE : PAGE_READONLY, 0, 0, NULL);
    View = Mapping ? MapViewOfFile(Mapping, Writable ? FILE_MAP_WRITE : FILE_MAP_READ, 0, 0, 0) : NULL;
    ok(View != NULL, "map failed with %lu\n", GetLastError());
    if (!View)
    {
        if (Mapping) CloseHandle(Mapping);
        CloseHandle(File);
        DeleteFileA(Path);
        return;
    }
    if (Keep >= 1) CloseHandle(File);
    if (Keep >= 2) CloseHandle(Mapping);

    /* the handle that made the view, still open without FILE_SHARE_DELETE, stops the delete by sharing first */
    Expected = (Keep == 0 && !(Share & FILE_SHARE_DELETE)) ? ERROR_SHARING_VIOLATION : ERROR_ACCESS_DENIED;
    sprintf(Name, "%s view, share 0x%lx, %s", Writable ? "writable" : "read-only", Share, KeepNames[Keep]);
    Error = DeleteRow(Path);
    trace("%s: %lu\n", Name, Error);
    ok(Error == Expected, "%s: DeleteFile error %lu, expected %lu\n", Name, Error, Expected);

    UnmapViewOfFile(View);
    if (Keep < 2) CloseHandle(Mapping);
    if (Keep < 1) CloseHandle(File);
    Error = DeleteRow(Path);
    ok(Error == 0, "%s: DeleteFile after the view is gone: error %lu\n", Name, Error);
    DeleteFileA(Path);
}

/* A delete disposition on a handle with DELETE access: STATUS_CANNOT_DELETE, ERROR_ACCESS_DENIED in Win32 */
typedef LONG (NTAPI *PFN_SETINFO)(HANDLE, PVOID, PVOID, ULONG, ULONG);
typedef ULONG (NTAPI *PFN_TODOS)(LONG);

static void TestDisposition(void)
{
    char Path[MAX_PATH];
    HANDLE File, Mapping, Delete;
    void *View;
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");
    PFN_SETINFO pNtSetInformationFile = (PFN_SETINFO)GetProcAddress(Ntdll, "NtSetInformationFile");
    PFN_TODOS pRtlNtStatusToDosError = (PFN_TODOS)GetProcAddress(Ntdll, "RtlNtStatusToDosError");
    struct { ULONG_PTR Status; ULONG_PTR Information; } IoStatus = { 0, 0 };
    BOOLEAN DeleteFlag = TRUE;
    LONG Status;

    if (!pNtSetInformationFile || !pRtlNtStatusToDosError) return;
    MakePath(Path);
    ok(MakeFile(Path), "MakeFile failed with %lu\n", GetLastError());
    File = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    Mapping = CreateFileMappingA(File, NULL, PAGE_READONLY, 0, 0, NULL);
    View = MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, 0);
    ok(View != NULL, "map failed with %lu\n", GetLastError());
    Delete = CreateFileA(Path, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    /* FileDispositionInformation = 13 */
    Status = pNtSetInformationFile(Delete, &IoStatus, &DeleteFlag, sizeof(DeleteFlag), 13);
    ok(Status < 0 && pRtlNtStatusToDosError(Status) == ERROR_ACCESS_DENIED, "disposition: status 0x%lx, Win32 error %lu\n",
       (ULONG)Status, Status < 0 ? pRtlNtStatusToDosError(Status) : 0);
    CloseHandle(Delete);
    UnmapViewOfFile(View);
    CloseHandle(Mapping);
    CloseHandle(File);
    ok(DeleteRow(Path) == 0, "DeleteFile after the view is gone failed\n");
    DeleteFileA(Path);
}

/* An image section: the view of SEC_IMAGE and a process that runs from the file */
static void TestImage(void)
{
    char Path[MAX_PATH], Exe[MAX_PATH];
    HANDLE File, Mapping;
    void *View;
    DWORD Error;

    GetModuleFileNameA(NULL, Exe, sizeof(Exe));
    MakePath(Path);
    ok(CopyFileA(Exe, Path, FALSE), "CopyFile failed with %lu\n", GetLastError());
    File = CreateFileA(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    Mapping = (File != INVALID_HANDLE_VALUE) ? CreateFileMappingA(File, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL) : NULL;
    View = Mapping ? MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, 0) : NULL;
    ok(View != NULL, "image map failed with %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE) CloseHandle(File);
    Error = DeleteRow(Path);
    ok(Error == ERROR_ACCESS_DENIED, "image view: DeleteFile error %lu, expected %lu\n", Error, (DWORD)ERROR_ACCESS_DENIED);
    if (View) UnmapViewOfFile(View);
    if (Mapping) CloseHandle(Mapping);
    Error = DeleteRow(Path);
    ok(Error == 0, "image unmapped: DeleteFile error %lu\n", Error);
    DeleteFileA(Path);
}

#ifdef FILEDELMAP_PROBE
int main(void)
#else
START_TEST(FileDeleteMapped)
#endif
{
    static const DWORD Shares[] = { 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SHARE_DELETE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE };
    SIZE_T i;
    int Keep, Writable;

    for (Writable = 0; Writable < 2; Writable++)
        for (i = 0; i < sizeof(Shares) / sizeof(Shares[0]); i++)
            for (Keep = 0; Keep < 3; Keep++)
                TestDataView(Writable, Shares[i], Keep);
    TestDisposition();
    TestImage();
#ifdef FILEDELMAP_PROBE
    printf("mismatches: %d\n", g_fail);
    return g_fail != 0;
#endif
}
