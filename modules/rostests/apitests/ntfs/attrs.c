/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: when the archive attribute is set (write, SetEndOfFile, SetFileTime on a writing handle, rename)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* Every expectation was measured on Windows 10 22H2 (2026-11-10, a scratch file under %TEMP% on NTFS). */

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

static void CheckAttrs(PCWSTR Path, DWORD Expected, PCSTR Step)
{
    DWORD Attrs = GetFileAttributesW(Path);
    ok(Attrs == Expected, "%s: attributes 0x%lx, expected 0x%lx\n", Step, Attrs, Expected);
}

static HANDLE OpenForWrite(PCWSTR Path, DWORD Access)
{
    HANDLE H = CreateFileW(Path, Access, SHARE_ALL, NULL, OPEN_EXISTING, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "open of %ls failed %lu\n", Path, GetLastError());
    return H;
}

START_TEST(NtfsArchiveAttribute)
{
    WCHAR F1[MAX_PATH], F2[MAX_PATH];
    FILETIME Ft;
    SYSTEMTIME St = { 2003, 4, 0, 5, 6, 7, 8, 0 };
    HANDLE H;
    DWORD Written;
    LARGE_INTEGER Li;

    if (!NtInit("NtfsArchiveAttribute"))
        return;
    NtPath(F1, L"f1.dat");
    NtPath(F2, L"f2.dat");
    SystemTimeToFileTime(&St, &Ft);

    H = CreateFileW(F1, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create failed %lu\n", GetLastError());
    if (H == INVALID_HANDLE_VALUE)
        goto done;
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "new empty file");

    ok(SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL), "SetFileAttributes failed %lu\n", GetLastError());
    CheckAttrs(F1, FILE_ATTRIBUTE_NORMAL, "NORMAL");

    /* a time set on a handle that wrote nothing leaves the attribute cleared */
    H = OpenForWrite(F1, FILE_WRITE_ATTRIBUTES);
    ok(SetFileTime(H, NULL, NULL, &Ft), "SetFileTime failed %lu\n", GetLastError());
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_NORMAL, "SetFileTime on a handle that did not write");

    /* open and close without a write */
    H = OpenForWrite(F1, GENERIC_READ | GENERIC_WRITE);
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_NORMAL, "open and close, no write");

    /* a write */
    H = OpenForWrite(F1, GENERIC_WRITE);
    WriteFile(H, "x", 1, &Written, NULL);
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "write of one byte");

    /* SetEndOfFile at the same size */
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    H = OpenForWrite(F1, GENERIC_WRITE);
    SetEndOfFile(H);
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "SetEndOfFile at the same size");

    /* the handle that wrote, the attribute cleared meanwhile (another handle), then SetFileTime on the writing handle */
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    H = OpenForWrite(F1, GENERIC_WRITE);
    WriteFile(H, "y", 1, &Written, NULL);
    CheckAttrs(F1, FILE_ATTRIBUTE_NORMAL, "write on an open handle");
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    CheckAttrs(F1, FILE_ATTRIBUTE_NORMAL, "NORMAL while the writing handle is open");
    ok(SetFileTime(H, NULL, NULL, &Ft), "SetFileTime failed %lu\n", GetLastError());
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "SetFileTime on the handle that wrote");
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "after the close");

    /* a write, NORMAL while the handle is open, close */
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    H = OpenForWrite(F1, GENERIC_WRITE);
    WriteFile(H, "z", 1, &Written, NULL);
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "write, NORMAL while open, close");

    /* the time first, the write after it */
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    H = OpenForWrite(F1, GENERIC_WRITE);
    SetFileTime(H, NULL, NULL, &Ft);
    WriteFile(H, "w", 1, &Written, NULL);
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "SetFileTime then a write");

    /* growing the file */
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    H = OpenForWrite(F1, GENERIC_WRITE);
    Li.QuadPart = 4096;
    SetFilePointerEx(H, Li, NULL, FILE_BEGIN);
    SetEndOfFile(H);
    CloseHandle(H);
    CheckAttrs(F1, FILE_ATTRIBUTE_ARCHIVE, "SetEndOfFile(4096)");

    /* a rename of a file sets it, also after NORMAL */
    SetFileAttributesW(F1, FILE_ATTRIBUTE_NORMAL);
    ok(MoveFileW(F1, F2), "MoveFile failed %lu\n", GetLastError());
    CheckAttrs(F2, FILE_ATTRIBUTE_ARCHIVE, "rename after NORMAL");

    /* a read does not */
    SetFileAttributesW(F2, FILE_ATTRIBUTE_NORMAL);
    H = OpenForWrite(F2, GENERIC_READ);
    ReadFile(H, &Written, 1, &Written, NULL);
    CloseHandle(H);
    CheckAttrs(F2, FILE_ATTRIBUTE_NORMAL, "read");

    /* the attributes of one request replace them (NORMAL clears, ARCHIVE sets, READONLY alone) */
    SetFileAttributesW(F2, FILE_ATTRIBUTE_ARCHIVE);
    CheckAttrs(F2, FILE_ATTRIBUTE_ARCHIVE, "SetFileAttributes(ARCHIVE)");
    SetFileAttributesW(F2, FILE_ATTRIBUTE_HIDDEN);
    CheckAttrs(F2, FILE_ATTRIBUTE_HIDDEN, "SetFileAttributes(HIDDEN) from ARCHIVE");
    SetFileAttributesW(F2, FILE_ATTRIBUTE_NORMAL);

done:
    NtCleanup();
}
