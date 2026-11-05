/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DeleteFile with POSIX semantics (FileDispositionInformationEx), Windows 10 behaviour
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 DeleteFileW asks for FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS |
 * FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK: the name goes when its handle closes, even while other
 * handles (opened with FILE_SHARE_DELETE) stay open, so the parent directory can be removed and the name
 * created again at once; those handles keep working until the last one closes.  The expectations below
 * were measured on Windows 10 22H2 (NTFS).  The NTFS-only parts (names in $Extend\$Deleted, link counts)
 * are skipped on other file systems, where DeleteFile falls back to the classic request.
 */

#include "precomp.h"
#include <winioctl.h>
#include <ndk/iofuncs.h>

#ifndef STATUS_CANNOT_DELETE
#define STATUS_CANNOT_DELETE ((NTSTATUS)0xC0000121)
#endif
#ifndef FSCTL_REQUEST_BATCH_OPLOCK
#define FSCTL_REQUEST_BATCH_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef STATUS_FILE_DELETED
#define STATUS_FILE_DELETED ((NTSTATUS)0xC0000123)
#endif

#define DISP_DELETE         0x01
#define DISP_POSIX          0x02
#define DISP_FORCE_IMAGE    0x04
#define DISP_ON_CLOSE       0x08
#define DISP_IGNORE_RO      0x10
#define CLASS_DISP_EX       ((FILE_INFORMATION_CLASS)64)
#define SHARE_ALL           (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

static WCHAR Base[MAX_PATH];
static BOOL IsNtfs;

static void P(WCHAR *Out, PCWSTR Rel)
{
    StringCchPrintfW(Out, MAX_PATH, L"%s\\%s", Base, Rel);
}

static HANDLE Open(PCWSTR Rel, DWORD Access, DWORD Share, DWORD Disposition, DWORD Flags)
{
    WCHAR Path[MAX_PATH];
    P(Path, Rel);
    return CreateFileW(Path, Access, Share, NULL, Disposition, Flags, NULL);
}

static void Make(PCWSTR Rel, const char *Data)
{
    DWORD Done;
    HANDLE h = Open(Rel, GENERIC_WRITE, 0, CREATE_ALWAYS, 0);
    ok(h != INVALID_HANDLE_VALUE, "create %S failed, error %lu\n", Rel, GetLastError());
    if (h == INVALID_HANDLE_VALUE)
        return;
    WriteFile(h, Data, (DWORD)strlen(Data), &Done, NULL);
    CloseHandle(h);
}

/* 0 when the name exists, else the error of GetFileAttributesW */
static DWORD Attr(PCWSTR Rel)
{
    WCHAR Path[MAX_PATH];
    P(Path, Rel);
    SetLastError(0);
    return GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES ? GetLastError() : 0;
}

static BOOL Del(PCWSTR Rel)
{
    WCHAR Path[MAX_PATH];
    P(Path, Rel);
    return DeleteFileW(Path);
}

static BOOL RmDir(PCWSTR Rel)
{
    WCHAR Path[MAX_PATH];
    P(Path, Rel);
    return RemoveDirectoryW(Path);
}

static BOOL MkDir(PCWSTR Rel)
{
    WCHAR Path[MAX_PATH];
    P(Path, Rel);
    return CreateDirectoryW(Path, NULL);
}

static NTSTATUS SetEx(HANDLE h, ULONG Flags)
{
    IO_STATUS_BLOCK Io;
    return NtSetInformationFile(h, &Io, &Flags, sizeof(Flags), CLASS_DISP_EX);
}

static NTSTATUS SetClassic(HANDLE h, BOOLEAN Delete)
{
    IO_STATUS_BLOCK Io;
    FILE_DISPOSITION_INFORMATION D;
    D.DeleteFile = Delete;
    return NtSetInformationFile(h, &Io, &D, sizeof(D), FileDispositionInformation);
}

static NTSTATUS Standard(HANDLE h, FILE_STANDARD_INFORMATION *S)
{
    IO_STATUS_BLOCK Io;
    RtlZeroMemory(S, sizeof(*S));
    return NtQueryInformationFile(h, &Io, S, sizeof(*S), FileStandardInformation);
}

static NTSTATUS Rename(HANDLE h, PCWSTR Rel)
{
    UCHAR Buffer[sizeof(FILE_RENAME_INFORMATION) + MAX_PATH * sizeof(WCHAR) * 2];
    PFILE_RENAME_INFORMATION R = (PFILE_RENAME_INFORMATION)Buffer;
    WCHAR Path[MAX_PATH * 2];
    IO_STATUS_BLOCK Io;
    StringCchPrintfW(Path, RTL_NUMBER_OF(Path), L"\\??\\%s\\%s", Base, Rel);
    RtlZeroMemory(Buffer, sizeof(Buffer));
    R->ReplaceIfExists = FALSE;
    R->RootDirectory = NULL;
    R->FileNameLength = (ULONG)wcslen(Path) * sizeof(WCHAR);
    RtlCopyMemory(R->FileName, Path, R->FileNameLength);
    return NtSetInformationFile(h, &Io, R, FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) + R->FileNameLength,
                                FileRenameInformation);
}

static DWORD ReadAll(HANDLE h, char *Buf, DWORD Size)
{
    DWORD Got = 0;
    SetFilePointer(h, 0, NULL, FILE_BEGIN);
    if (!ReadFile(h, Buf, Size - 1, &Got, NULL))
        Got = 0;
    Buf[Got] = 0;
    return Got;
}

static BOOL Append(HANDLE h, const char *Data)
{
    DWORD Done = 0;
    SetFilePointer(h, 0, NULL, FILE_END);
    return WriteFile(h, Data, (DWORD)strlen(Data), &Done, NULL) && Done == strlen(Data);
}

static void CheckDeletedName(HANDLE h, const char *What)
{
    UCHAR Buffer[sizeof(FILE_NAME_INFORMATION) + MAX_PATH * sizeof(WCHAR)];
    PFILE_NAME_INFORMATION N = (PFILE_NAME_INFORMATION)Buffer;
    IO_STATUS_BLOCK Io;
    static const WCHAR Prefix[] = L"\\$Extend\\$Deleted\\";
    NTSTATUS Status;
    if (!IsNtfs)
        return;
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryInformationFile(h, &Io, N, sizeof(Buffer) - sizeof(WCHAR), FileNameInformation);
    ok(Status == STATUS_SUCCESS, "%s: FileNameInformation 0x%08lx\n", What, Status);
    ok(N->FileNameLength == sizeof(Prefix) - sizeof(WCHAR) + 24 * sizeof(WCHAR) &&
       !_wcsnicmp(N->FileName, Prefix, RTL_NUMBER_OF(Prefix) - 1),
       "%s: name '%.*S'\n", What, (int)(N->FileNameLength / sizeof(WCHAR)), N->FileName);
}

/* DeleteFile with another handle open, then RemoveDirectory(parent), the name created again, I/O on the old handle */
static void TestOpenHandle(void)
{
    FILE_STANDARD_INFORMATION S;
    char Buf[64];
    HANDLE h, h2;

    ok(MkDir(L"d1"), "CreateDirectory failed, error %lu\n", GetLastError());
    Make(L"d1\\f", "hello");
    h = Open(L"d1\\f", GENERIC_READ | GENERIC_WRITE, SHARE_ALL, OPEN_EXISTING, 0);
    ok(h != INVALID_HANDLE_VALUE, "open failed, error %lu\n", GetLastError());
    if (h == INVALID_HANDLE_VALUE)
        return;
    ok(Del(L"d1\\f"), "DeleteFile failed, error %lu\n", GetLastError());
    ok_long(Attr(L"d1\\f"), ERROR_FILE_NOT_FOUND);
    h2 = Open(L"d1\\f", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok(h2 == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND, "reopen: %p, error %lu\n", h2, GetLastError());
    if (h2 != INVALID_HANDLE_VALUE)
        CloseHandle(h2);
    ok_hex(Standard(h, &S), STATUS_SUCCESS);
    ok(S.DeletePending == TRUE, "DeletePending %u\n", S.DeletePending);
    if (IsNtfs)
        ok(S.NumberOfLinks == 0, "NumberOfLinks %lu\n", S.NumberOfLinks);
    CheckDeletedName(h, "open handle");
    ok_long(ReadAll(h, Buf, sizeof(Buf)), 5);
    ok(!strcmp(Buf, "hello"), "read '%s'\n", Buf);
    ok(Append(h, " world"), "write failed, error %lu\n", GetLastError());
    ok_long(ReadAll(h, Buf, sizeof(Buf)), 11);
    ok(!strcmp(Buf, "hello world"), "read '%s'\n", Buf);
    SetFilePointer(h, 100000, NULL, FILE_BEGIN);
    ok(SetEndOfFile(h), "SetEndOfFile failed, error %lu\n", GetLastError());
    ok_hex(Standard(h, &S), STATUS_SUCCESS);
    ok(S.EndOfFile.QuadPart == 100000, "EndOfFile %I64d\n", S.EndOfFile.QuadPart);
    ok(FlushFileBuffers(h), "FlushFileBuffers failed, error %lu\n", GetLastError());

    /* the name is gone: the parent can be removed, made again, and the name created again */
    ok(RmDir(L"d1"), "RemoveDirectory(parent) failed, error %lu\n", GetLastError());
    ok(MkDir(L"d1"), "CreateDirectory again failed, error %lu\n", GetLastError());
    h2 = Open(L"d1\\f", GENERIC_READ | GENERIC_WRITE, SHARE_ALL, CREATE_NEW, 0);
    ok(h2 != INVALID_HANDLE_VALUE, "create the name again failed, error %lu\n", GetLastError());
    if (h2 != INVALID_HANDLE_VALUE)
    {
        ok(Append(h2, "new"), "write new failed\n");
        CloseHandle(h2);
    }
    ok_long(ReadAll(h, Buf, 12), 11);
    ok(!strcmp(Buf, "hello world"), "old handle reads '%s'\n", Buf);

    /* a POSIX-deleted handle cannot be renamed or given a disposition (it has no DELETE access here) */
    CloseHandle(h);
    h = Open(L"d1\\f", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok_long(ReadAll(h, Buf, sizeof(Buf)), 3);
    ok(!strcmp(Buf, "new"), "new file reads '%s'\n", Buf);
    CloseHandle(h);
    ok(Del(L"d1\\f"), "DeleteFile new failed, error %lu\n", GetLastError());
    ok(RmDir(L"d1"), "RemoveDirectory failed, error %lu\n", GetLastError());
}

/* rename, link and dispositions through a handle with DELETE access after the POSIX delete */
static void TestOrphanHandle(void)
{
    FILE_STANDARD_INFORMATION S;
    HANDLE h;
    Make(L"o1", "x");
    h = Open(L"o1", GENERIC_READ | GENERIC_WRITE | DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    ok(h != INVALID_HANDLE_VALUE, "open failed, error %lu\n", GetLastError());
    if (h == INVALID_HANDLE_VALUE)
        return;
    ok(Del(L"o1"), "DeleteFile failed, error %lu\n", GetLastError());
    ok_hex(Rename(h, L"o1r"), STATUS_ACCESS_DENIED);
    ok_long(Attr(L"o1r"), ERROR_FILE_NOT_FOUND);
    ok_hex(SetClassic(h, FALSE), STATUS_FILE_DELETED);
    ok_hex(SetClassic(h, TRUE), STATUS_FILE_DELETED);
    ok_hex(SetEx(h, DISP_DELETE | DISP_POSIX), STATUS_FILE_DELETED);
    ok_hex(SetEx(h, 0), STATUS_FILE_DELETED);
    ok_hex(Standard(h, &S), STATUS_SUCCESS);
    ok(S.DeletePending == TRUE, "DeletePending %u\n", S.DeletePending);
    CloseHandle(h);
    ok_long(Attr(L"o1"), ERROR_FILE_NOT_FOUND);
}

/* the name stays while the handle that asked for the POSIX delete is open; it goes when that one closes */
static void TestSetterHandle(void)
{
    FILE_STANDARD_INFORMATION S;
    HANDLE h, h2;

    Make(L"s1", "x");
    h = Open(L"s1", GENERIC_READ | GENERIC_WRITE | DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    h2 = Open(L"s1", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok(h != INVALID_HANDLE_VALUE && h2 != INVALID_HANDLE_VALUE, "open failed, error %lu\n", GetLastError());
    ok_hex(SetEx(h, DISP_DELETE | DISP_POSIX), STATUS_SUCCESS);
    ok_long(Attr(L"s1"), ERROR_ACCESS_DENIED);  /* delete pending */
    ok_hex(Standard(h2, &S), STATUS_SUCCESS);
    ok(S.DeletePending == TRUE, "DeletePending %u\n", S.DeletePending);
    if (IsNtfs)
        ok(S.NumberOfLinks == 0, "NumberOfLinks %lu\n", S.NumberOfLinks);
    CloseHandle(h);
    ok_long(Attr(L"s1"), ERROR_FILE_NOT_FOUND);
    CheckDeletedName(h2, "other handle");
    CloseHandle(h2);
    ok_long(Attr(L"s1"), ERROR_FILE_NOT_FOUND);

    /* cancelled before the close: the name stays */
    Make(L"s2", "x");
    h = Open(L"s2", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    h2 = Open(L"s2", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetEx(h, DISP_DELETE | DISP_POSIX), STATUS_SUCCESS);
    ok_hex(SetEx(h, DISP_POSIX), STATUS_SUCCESS);
    CloseHandle(h);
    ok_long(Attr(L"s2"), 0);
    CloseHandle(h2);
    ok(Del(L"s2"), "DeleteFile failed, error %lu\n", GetLastError());

    /* a classic delete set through one handle, POSIX through another: the name goes with the POSIX handle */
    Make(L"s3", "x");
    h = Open(L"s3", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    h2 = Open(L"s3", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetClassic(h, TRUE), STATUS_SUCCESS);
    ok_hex(SetEx(h2, DISP_DELETE | DISP_POSIX), STATUS_SUCCESS);
    CloseHandle(h2);
    ok_long(Attr(L"s3"), ERROR_FILE_NOT_FOUND);
    CloseHandle(h);

    /* the classic class keeps the name until the last handle closes */
    Make(L"s4", "x");
    h = Open(L"s4", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    h2 = Open(L"s4", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetClassic(h, TRUE), STATUS_SUCCESS);
    CloseHandle(h);
    ok_long(Attr(L"s4"), ERROR_ACCESS_DENIED);
    CloseHandle(h2);
    ok_long(Attr(L"s4"), ERROR_FILE_NOT_FOUND);
}

/* flags, FILE_DISPOSITION_ON_CLOSE and FILE_DELETE_ON_CLOSE */
static void TestFlags(void)
{
    HANDLE h, h2;
    WCHAR Path[MAX_PATH];

    Make(L"f1", "x");
    h = Open(L"f1", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetEx(h, DISP_DELETE | 0x20), STATUS_NOT_SUPPORTED);
    ok_hex(SetEx(h, DISP_DELETE | DISP_ON_CLOSE), STATUS_NOT_SUPPORTED);  /* not opened with FILE_DELETE_ON_CLOSE */
    ok_hex(SetEx(h, DISP_POSIX), STATUS_SUCCESS);
    ok_hex(SetEx(h, DISP_IGNORE_RO), STATUS_SUCCESS);
    CloseHandle(h);
    ok_long(Attr(L"f1"), 0);
    ok(Del(L"f1"), "DeleteFile failed, error %lu\n", GetLastError());

    /* FILE_DELETE_ON_CLOSE: classic */
    Make(L"f2", "x");
    h = Open(L"f2", GENERIC_READ | DELETE, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE);
    h2 = Open(L"f2", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    CloseHandle(h);
    ok_long(Attr(L"f2"), ERROR_ACCESS_DENIED);
    CloseHandle(h2);
    ok_long(Attr(L"f2"), ERROR_FILE_NOT_FOUND);

    /* FILE_DISPOSITION_ON_CLOSE | POSIX on it: POSIX at its close */
    Make(L"f3", "x");
    h = Open(L"f3", GENERIC_READ | DELETE, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE);
    h2 = Open(L"f3", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetEx(h, DISP_ON_CLOSE | DISP_POSIX | DISP_DELETE), STATUS_SUCCESS);
    CloseHandle(h);
    ok_long(Attr(L"f3"), ERROR_FILE_NOT_FOUND);
    CloseHandle(h2);

    /* POSIX without FILE_DISPOSITION_ON_CLOSE on a FILE_DELETE_ON_CLOSE handle: classic at its close */
    Make(L"f4", "x");
    h = Open(L"f4", GENERIC_READ | DELETE, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE);
    h2 = Open(L"f4", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetEx(h, DISP_POSIX | DISP_DELETE), STATUS_SUCCESS);
    CloseHandle(h);
    ok_long(Attr(L"f4"), ERROR_ACCESS_DENIED);
    CloseHandle(h2);
    ok_long(Attr(L"f4"), ERROR_FILE_NOT_FOUND);

    /* FILE_DISPOSITION_ON_CLOSE alone clears FILE_DELETE_ON_CLOSE */
    Make(L"f5", "x");
    h = Open(L"f5", GENERIC_READ | DELETE, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE);
    ok_hex(SetEx(h, DISP_ON_CLOSE), STATUS_SUCCESS);
    CloseHandle(h);
    ok_long(Attr(L"f5"), 0);
    ok(Del(L"f5"), "DeleteFile failed, error %lu\n", GetLastError());

    /* read-only: DeleteFile refuses, IGNORE_READONLY_ATTRIBUTE deletes */
    Make(L"f6", "x");
    P(Path, L"f6");
    SetFileAttributesW(Path, FILE_ATTRIBUTE_READONLY);
    ok(!Del(L"f6") && GetLastError() == ERROR_ACCESS_DENIED, "DeleteFile of a read-only file: error %lu\n", GetLastError());
    h = Open(L"f6", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetEx(h, DISP_DELETE | DISP_POSIX), STATUS_CANNOT_DELETE);
    ok_hex(SetEx(h, DISP_DELETE | DISP_POSIX | DISP_IGNORE_RO), STATUS_SUCCESS);
    CloseHandle(h);
    ok_long(Attr(L"f6"), ERROR_FILE_NOT_FOUND);
}

/* hard links: only the name the handle was opened by goes */
static void TestHardLink(void)
{
    FILE_STANDARD_INFORMATION S;
    WCHAR A[MAX_PATH], B[MAX_PATH];
    char Buf[64];
    HANDLE h, h2;

    if (!IsNtfs)
    {
        skip("hard links need NTFS\n");
        return;
    }
    Make(L"hl1", "link");
    h = Open(L"hl1", GENERIC_READ | GENERIC_WRITE | DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    P(A, L"hl2");
    P(B, L"hl1");
    ok(CreateHardLinkW(A, B, NULL), "CreateHardLink failed, error %lu\n", GetLastError());
    ok(Del(L"hl1"), "DeleteFile failed, error %lu\n", GetLastError());
    ok_long(Attr(L"hl1"), ERROR_FILE_NOT_FOUND);
    ok_long(Attr(L"hl2"), 0);
    ok_hex(Standard(h, &S), STATUS_SUCCESS);
    ok(S.DeletePending == TRUE && S.NumberOfLinks == 1, "DeletePending %u, NumberOfLinks %lu\n", S.DeletePending, S.NumberOfLinks);
    CheckDeletedName(h, "removed link");
    ok(Append(h, "+more"), "write failed, error %lu\n", GetLastError());
    ok_hex(Rename(h, L"hl3"), STATUS_ACCESS_DENIED);
    ok_hex(SetClassic(h, FALSE), STATUS_FILE_DELETED);
    h2 = Open(L"hl2", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok(h2 != INVALID_HANDLE_VALUE, "open of the other link failed, error %lu\n", GetLastError());
    ok_long(ReadAll(h2, Buf, sizeof(Buf)), 9);
    ok(!strcmp(Buf, "link+more"), "other link reads '%s'\n", Buf);
    ok_hex(Standard(h2, &S), STATUS_SUCCESS);
    ok(S.DeletePending == FALSE && S.NumberOfLinks == 1, "other link: DeletePending %u, NumberOfLinks %lu\n", S.DeletePending, S.NumberOfLinks);
    CloseHandle(h2);
    CloseHandle(h);
    ok_long(Attr(L"hl2"), 0);
    ok(Del(L"hl2"), "DeleteFile failed, error %lu\n", GetLastError());
}

/* a mapped image cannot be deleted; a data view stays readable after a POSIX delete */
static void TestSections(void)
{
    WCHAR Self[MAX_PATH], Img[MAX_PATH];
    HANDLE h, h2, m;
    PVOID View;

    GetModuleFileNameW(NULL, Self, MAX_PATH);
    P(Img, L"img.exe");
    ok(CopyFileW(Self, Img, FALSE), "CopyFile failed, error %lu\n", GetLastError());
    h = Open(L"img.exe", GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE, OPEN_EXISTING, 0);
    m = CreateFileMappingW(h, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    ok(m != NULL, "SEC_IMAGE mapping failed, error %lu\n", GetLastError());
    View = m ? MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0) : NULL;
    ok(View != NULL, "MapViewOfFile failed, error %lu\n", GetLastError());
    CloseHandle(h);
    if (m)
        CloseHandle(m);
    ok(!Del(L"img.exe") && GetLastError() == ERROR_ACCESS_DENIED, "DeleteFile of a mapped image: error %lu\n", GetLastError());
    ok_long(Attr(L"img.exe"), 0);
    h2 = Open(L"img.exe", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    ok(h2 != INVALID_HANDLE_VALUE, "open failed, error %lu\n", GetLastError());
    ok_hex(SetEx(h2, DISP_DELETE | DISP_POSIX), STATUS_CANNOT_DELETE);
    ok_hex(SetEx(h2, DISP_DELETE | DISP_POSIX | DISP_FORCE_IMAGE), STATUS_CANNOT_DELETE);
    ok_hex(SetClassic(h2, TRUE), STATUS_CANNOT_DELETE);
    CloseHandle(h2);
    ok_long(Attr(L"img.exe"), 0);
    if (View)
        UnmapViewOfFile(View);
    ok(Del(L"img.exe"), "DeleteFile after the unmap failed, error %lu\n", GetLastError());
    ok_long(Attr(L"img.exe"), ERROR_FILE_NOT_FOUND);

    /* data view: POSIX without the image section check deletes the name; the view still reads */
    Make(L"map", "mapdata");
    h = Open(L"map", GENERIC_READ | GENERIC_WRITE, SHARE_ALL, OPEN_EXISTING, 0);
    m = CreateFileMappingW(h, NULL, PAGE_READONLY, 0, 0, NULL);
    View = m ? MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0) : NULL;
    ok(View != NULL, "data view failed, error %lu\n", GetLastError());
    h2 = Open(L"map", DELETE, SHARE_ALL, OPEN_EXISTING, 0);
    ok_hex(SetEx(h2, DISP_DELETE | DISP_POSIX), STATUS_SUCCESS);
    CloseHandle(h2);
    ok_long(Attr(L"map"), ERROR_FILE_NOT_FOUND);
    if (View)
    {
        ok(!memcmp(View, "mapdata", 7), "view reads '%.7s'\n", (char *)View);
        UnmapViewOfFile(View);
    }
    if (m)
        CloseHandle(m);
    CloseHandle(h);
}

/* a directory: RemoveDirectory with a list handle open; nothing new inside; the parent can go */
static void TestDirectory(void)
{
    HANDLE h, Created;
    NTSTATUS Status;
    IO_STATUS_BLOCK Io;
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"zz");
    OBJECT_ATTRIBUTES Oa;
    FILE_STANDARD_INFORMATION S;

    ok(MkDir(L"dp"), "CreateDirectory failed, error %lu\n", GetLastError());
    ok(MkDir(L"dp\\c"), "CreateDirectory failed, error %lu\n", GetLastError());
    h = Open(L"dp\\c", FILE_LIST_DIRECTORY | SYNCHRONIZE, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS);
    ok(h != INVALID_HANDLE_VALUE, "open failed, error %lu\n", GetLastError());
    ok(RmDir(L"dp\\c"), "RemoveDirectory failed, error %lu\n", GetLastError());
    ok_long(Attr(L"dp\\c"), ERROR_FILE_NOT_FOUND);
    ok(RmDir(L"dp"), "RemoveDirectory(parent) failed, error %lu\n", GetLastError());
    ok_hex(Standard(h, &S), STATUS_SUCCESS);
    ok(S.DeletePending == TRUE, "DeletePending %u\n", S.DeletePending);
    CheckDeletedName(h, "directory");
    InitializeObjectAttributes(&Oa, &Name, OBJ_CASE_INSENSITIVE, h, NULL);
    Status = NtCreateFile(&Created, GENERIC_WRITE | SYNCHRONIZE, &Oa, &Io, NULL, 0, SHARE_ALL, FILE_CREATE,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(Status))
        CloseHandle(Created);
    if (IsNtfs)
        ok_hex(Status, STATUS_DELETE_PENDING);
    CloseHandle(h);
    ok_long(Attr(L"dp"), ERROR_FILE_NOT_FOUND);
}

/* A batch oplock on another handle does not keep DeleteFile waiting: DeleteFile breaks the oplock, the holder
 * sees the break and closes its handle, the delete goes through.  The same sequence used to bugcheck a FAT
 * volume (STOP 0x23): FsRtl queued the create of the delete on the oplock but reported success, and granted
 * the oplock request without leaving it pending, so FastFAT completed the request itself and the oplock kept a
 * stale pointer to it.  Runs on every file system. */
static DWORD WINAPI OplockBreak(PVOID Param)
{
    HANDLE *H = Param;
    DWORD Wait = WaitForSingleObject(H[1], 5000);   /* the break; without an oplock, the timeout */
    CloseHandle(H[0]);
    return Wait;
}

static void TestOplock(void)
{
    OVERLAPPED Ov = {0};
    HANDLE H[2], Thread;
    DWORD Bytes, Start, BreakWait = WAIT_FAILED;
    BOOL Ret, Granted = FALSE;

    Make(L"op", "x");
    H[0] = Open(L"op", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED);
    Ov.hEvent = H[1] = CreateEventW(NULL, TRUE, FALSE, NULL);
    Ret = DeviceIoControl(H[0], FSCTL_REQUEST_BATCH_OPLOCK, NULL, 0, NULL, 0, &Bytes, &Ov);
    if (!Ret && GetLastError() == ERROR_OPLOCK_NOT_GRANTED)
        skip("the file system grants no batch oplock\n");   /* the delete below still has to work */
    else
    {
        ok(!Ret && GetLastError() == ERROR_IO_PENDING, "oplock: %d, error %lu\n", Ret, GetLastError());
        Granted = !Ret && GetLastError() == ERROR_IO_PENDING;
    }
    Thread = CreateThread(NULL, 0, OplockBreak, H, 0, NULL);
    Start = GetTickCount();
    ok(Del(L"op"), "DeleteFile failed, error %lu\n", GetLastError());
    ok(GetTickCount() - Start < 8000, "DeleteFile took %lu ms\n", GetTickCount() - Start);
    WaitForSingleObject(Thread, 15000);
    GetExitCodeThread(Thread, &BreakWait);
    CloseHandle(Thread);
    CloseHandle(H[1]);
    if (Granted)
        ok(BreakWait == WAIT_OBJECT_0, "the oplock break was not seen: wait %lu\n", BreakWait);
    ok_long(Attr(L"op"), ERROR_FILE_NOT_FOUND);
}

/* A file system without the Ex class (FAT): DeleteFile falls back to the classic request */
static void TestFallback(void)
{
    FILE_STANDARD_INFORMATION S;
    WCHAR Path[MAX_PATH];
    HANDLE h;

    Make(L"fb1", "x");
    ok(Del(L"fb1"), "DeleteFile failed, error %lu\n", GetLastError());
    ok_long(Attr(L"fb1"), ERROR_FILE_NOT_FOUND);

    Make(L"fb2", "x");
    h = Open(L"fb2", GENERIC_READ, SHARE_ALL, OPEN_EXISTING, 0);
    ok(h != INVALID_HANDLE_VALUE, "open failed, error %lu\n", GetLastError());
    ok(Del(L"fb2"), "DeleteFile with a handle open failed, error %lu\n", GetLastError());
    ok_hex(Standard(h, &S), STATUS_SUCCESS);
    ok(S.DeletePending == TRUE, "DeletePending %u\n", S.DeletePending);
    ok(Attr(L"fb2") != 0, "the name is still usable\n");
    CloseHandle(h);
    ok_long(Attr(L"fb2"), ERROR_FILE_NOT_FOUND);

    Make(L"fb3", "x");
    P(Path, L"fb3");
    SetFileAttributesW(Path, FILE_ATTRIBUTE_READONLY);
    ok(!Del(L"fb3") && GetLastError() == ERROR_ACCESS_DENIED, "DeleteFile of a read-only file: error %lu\n", GetLastError());
    SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
    ok(Del(L"fb3"), "DeleteFile failed, error %lu\n", GetLastError());
}

START_TEST(DeleteFilePosix)
{
    WCHAR Temp[MAX_PATH], Fs[32], Root[4] = L"C:\\";
    PCWSTR Dir = _wgetenv(L"DELETEFILEPOSIX_DIR");

    if (Dir && *Dir)
        StringCchCopyW(Base, RTL_NUMBER_OF(Base), Dir);
    else
    {
        GetTempPathW(MAX_PATH, Temp);
        StringCchPrintfW(Base, RTL_NUMBER_OF(Base), L"%sdfposix%lu", Temp, GetCurrentProcessId());
    }
    CreateDirectoryW(Base, NULL);
    Root[0] = Base[0];
    IsNtfs = GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, Fs, RTL_NUMBER_OF(Fs)) && !_wcsicmp(Fs, L"NTFS");
    trace("directory %S, file system %S\n", Base, IsNtfs ? L"NTFS" : Fs);

    if (!IsNtfs)
    {
        skip("POSIX delete semantics need NTFS: the classic fallback only\n");
        TestFallback();
        TestOplock();
    }
    else
    {
        TestOpenHandle();
        TestOrphanHandle();
        TestSetterHandle();
        TestFlags();
        TestHardLink();
        TestSections();
        TestDirectory();
        TestOplock();
    }
    ok(RemoveDirectoryW(Base), "RemoveDirectory(%S) failed, error %lu\n", Base, GetLastError());
}
