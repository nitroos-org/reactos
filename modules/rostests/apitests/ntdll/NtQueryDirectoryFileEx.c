/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for NtQueryDirectoryFileEx and ZwQueryDirectoryFileEx (Windows 8 and later)
 *
 * The expected values are what Windows Server 2022 gives on an NTFS volume (one scratch directory with the files
 * a1 b2 c3 d4 e5 and the directory sub, FileDirectoryInformation, no mask).
 */

#include "precomp.h"

#define QF_RESTART      0x01
#define QF_SINGLE       0x02
#define QF_INDEX        0x04
#define QF_ON_DISK      0x08
#define QF_NO_CURSOR    0x10

typedef NTSTATUS (NTAPI *PFN_QUERY_EX)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
                                       FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);

static PFN_QUERY_EX pNtQueryDirectoryFileEx;
static WCHAR TestDirectory[MAX_PATH];
static BOOL IsNtfs;
static const WCHAR *const Names[] = { L"a1", L"b2", L"c3", L"d4", L"e5" };

static HANDLE
OpenDirectory(DWORD Access)
{
    return CreateFileW(TestDirectory, Access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
}

/* One query: the status, and the names of the entries returned, comma separated ("" for none) */
static NTSTATUS
Query(HANDLE Directory, ULONG Class, ULONG Flags, PCWSTR Mask, ULONG Length, WCHAR *Out, ULONG OutChars)
{
    static UCHAR Buffer[4096];
    IO_STATUS_BLOCK Iosb;
    UNICODE_STRING Name;
    NTSTATUS Status;
    PFILE_DIRECTORY_INFORMATION Info;

    RtlFillMemory(Buffer, sizeof(Buffer), 0xCC);
    Iosb.Status = 0x12345678;
    Iosb.Information = 0;
    if (Mask)
        RtlInitUnicodeString(&Name, Mask);
    Status = pNtQueryDirectoryFileEx(Directory, NULL, NULL, NULL, &Iosb, Buffer, Length, Class, Flags,
                                     Mask ? &Name : NULL);
    Out[0] = UNICODE_NULL;
    if (NT_SUCCESS(Status))
    {
        Info = (PFILE_DIRECTORY_INFORMATION)Buffer;
        for (;;)
        {
            ULONG Chars = Info->FileNameLength / sizeof(WCHAR);

            if (Out[0] && wcslen(Out) + 1 < OutChars)
                wcscat(Out, L",");
            if (wcslen(Out) + Chars < OutChars)
                wcsncat(Out, Info->FileName, Chars);
            if (!Info->NextEntryOffset)
                break;
            Info = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
        }
    }
    return Status;
}

#define QUERY(Flags, Mask, Status, Expected) do {                                                   \
    WCHAR Out_[256];                                                                                \
    NTSTATUS St_ = Query(Dir, FileDirectoryInformation, (Flags), (Mask), 4096, Out_, 256);          \
    ok(St_ == (Status), "flags 0x%x: status 0x%08lx, expected 0x%08lx\n", (UINT)(Flags), St_, (NTSTATUS)(Status)); \
    ok(!wcscmp(Out_, (Expected)), "flags 0x%x: entries '%ls', expected '%ls'\n", (UINT)(Flags), Out_, (Expected)); \
} while (0)

static void
TestFlags(void)
{
    HANDLE Dir;
    const WCHAR *All = L".,..,a1,b2,c3,d4,e5,sub";

    /* a first call without a restart starts at the beginning, a second one finds nothing */
    Dir = OpenDirectory(FILE_LIST_DIRECTORY | SYNCHRONIZE);
    ok(Dir != INVALID_HANDLE_VALUE, "opening the directory failed, error %lu\n", GetLastError());
    QUERY(0, NULL, STATUS_SUCCESS, All);
    QUERY(0, NULL, STATUS_NO_MORE_FILES, L"");
    CloseHandle(Dir);

    /* single entries; a restart goes back to the first; the end is STATUS_NO_MORE_FILES */
    Dir = OpenDirectory(FILE_LIST_DIRECTORY | SYNCHRONIZE);
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L".");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"..");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"a1");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"b2");
    QUERY(QF_RESTART | QF_SINGLE, NULL, STATUS_SUCCESS, L".");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"..");
    QUERY(QF_RESTART, NULL, STATUS_SUCCESS, All);
    QUERY(QF_SINGLE, NULL, STATUS_NO_MORE_FILES, L"");
    QUERY(QF_SINGLE, NULL, STATUS_NO_MORE_FILES, L"");
    CloseHandle(Dir);

    /* the bits the file system does not know are no error; QF_INDEX and QF_ON_DISK change nothing on NTFS */
    Dir = OpenDirectory(FILE_LIST_DIRECTORY | SYNCHRONIZE);
    QUERY(QF_RESTART | QF_SINGLE, NULL, STATUS_SUCCESS, L".");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"..");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"a1");
    QUERY(QF_INDEX | QF_SINGLE, NULL, STATUS_SUCCESS, L"b2");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"c3");
    QUERY(QF_INDEX, NULL, STATUS_SUCCESS, L"d4,e5,sub");
    QUERY(QF_RESTART | QF_ON_DISK | QF_SINGLE, NULL, STATUS_SUCCESS, L".");
    QUERY(0x20 | QF_SINGLE, NULL, STATUS_SUCCESS, L"..");
    QUERY(0xFFFFFF00 | QF_SINGLE, NULL, STATUS_SUCCESS, L"a1");
    QUERY(0x80000000, NULL, STATUS_SUCCESS, L"b2,c3,d4,e5,sub");
    CloseHandle(Dir);

    /* a mask */
    Dir = OpenDirectory(FILE_LIST_DIRECTORY | SYNCHRONIZE);
    QUERY(QF_RESTART, L"b*", STATUS_SUCCESS, L"b2");
    CloseHandle(Dir);

    if (!IsNtfs)
    {
        skip("QF_NO_CURSOR needs a file system that implements it (NTFS)\n");
        return;
    }

    /* QF_NO_CURSOR: the query starts at the first entry and the handle's position stays */
    Dir = OpenDirectory(FILE_LIST_DIRECTORY | SYNCHRONIZE);
    QUERY(QF_RESTART | QF_SINGLE, NULL, STATUS_SUCCESS, L".");
    QUERY(QF_SINGLE | QF_NO_CURSOR, NULL, STATUS_SUCCESS, L".");
    QUERY(QF_SINGLE | QF_NO_CURSOR, NULL, STATUS_SUCCESS, L".");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"..");
    QUERY(QF_SINGLE | QF_NO_CURSOR, NULL, STATUS_SUCCESS, L".");
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"a1");
    QUERY(QF_NO_CURSOR, NULL, STATUS_SUCCESS, All);
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"b2");
    QUERY(QF_RESTART | QF_NO_CURSOR, NULL, STATUS_SUCCESS, All);
    QUERY(QF_SINGLE, NULL, STATUS_SUCCESS, L"c3");
    CloseHandle(Dir);
}

static void
TestRules(void)
{
    HANDLE Dir, File;
    WCHAR Out[256], Path[MAX_PATH];
    NTSTATUS Status;

    Dir = OpenDirectory(FILE_LIST_DIRECTORY | SYNCHRONIZE);
    /* FILE_DIRECTORY_INFORMATION is 64 bytes and the name; 80 holds the first entry, 64 does not */
    Status = Query(Dir, FileDirectoryInformation, QF_RESTART | QF_SINGLE, NULL, 64, Out, 256);
    ok(Status == STATUS_INFO_LENGTH_MISMATCH, "length 64: 0x%08lx\n", Status);
    Status = Query(Dir, FileDirectoryInformation, QF_RESTART | QF_SINGLE, NULL, 80, Out, 256);
    ok(Status == STATUS_SUCCESS && !wcscmp(Out, L"."), "length 80: 0x%08lx '%ls'\n", Status, Out);
    /* classes that are no directory classes */
    Status = Query(Dir, FileBasicInformation, QF_RESTART | QF_SINGLE, NULL, 4096, Out, 256);
    ok(Status == STATUS_INVALID_INFO_CLASS, "FileBasicInformation: 0x%08lx\n", Status);
    Status = Query(Dir, FileNamesInformation, QF_RESTART | QF_SINGLE, NULL, 4096, Out, 256);
    ok(Status == STATUS_SUCCESS, "FileNamesInformation: 0x%08lx\n", Status);
    CloseHandle(Dir);

    Dir = OpenDirectory(SYNCHRONIZE | FILE_READ_ATTRIBUTES);
    Status = Query(Dir, FileDirectoryInformation, QF_RESTART | QF_SINGLE, NULL, 4096, Out, 256);
    ok(Status == STATUS_ACCESS_DENIED, "a handle without FILE_LIST_DIRECTORY: 0x%08lx\n", Status);
    CloseHandle(Dir);

    swprintf(Path, MAX_PATH, L"%ls\\a1", TestDirectory);
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    Status = Query(File, FileDirectoryInformation, QF_RESTART | QF_SINGLE, NULL, 4096, Out, 256);
    ok(Status == STATUS_INVALID_PARAMETER, "a file handle: 0x%08lx\n", Status);
    CloseHandle(File);

    Status = Query((HANDLE)(ULONG_PTR)0xdeadbeef, FileDirectoryInformation, QF_RESTART | QF_SINGLE, NULL, 4096, Out, 256);
    ok(Status == STATUS_INVALID_HANDLE, "an invalid handle: 0x%08lx\n", Status);
}

START_TEST(NtQueryDirectoryFileEx)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    WCHAR Temp[MAX_PATH], Path[MAX_PATH], Root[4], Fs[32];
    PVOID pZw;
    HANDLE File;
    UINT i;

    pNtQueryDirectoryFileEx = (PFN_QUERY_EX)GetProcAddress(Ntdll, "NtQueryDirectoryFileEx");
    if (!pNtQueryDirectoryFileEx)
    {
        skip("NtQueryDirectoryFileEx is not available\n");
        return;
    }
    pZw = GetProcAddress(Ntdll, "ZwQueryDirectoryFileEx");
    ok(pZw == (PVOID)pNtQueryDirectoryFileEx, "ZwQueryDirectoryFileEx %p, NtQueryDirectoryFileEx %p\n", pZw,
       pNtQueryDirectoryFileEx);

    GetTempPathW(MAX_PATH, Temp);
    swprintf(TestDirectory, MAX_PATH, L"%lskqdx_%lu", Temp, GetCurrentProcessId());
    ok(CreateDirectoryW(TestDirectory, NULL), "CreateDirectoryW(%ls) failed, error %lu\n", TestDirectory, GetLastError());
    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        swprintf(Path, MAX_PATH, L"%ls\\%ls", TestDirectory, Names[i]);
        File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (File != INVALID_HANDLE_VALUE)
            CloseHandle(File);
    }
    swprintf(Path, MAX_PATH, L"%ls\\sub", TestDirectory);
    CreateDirectoryW(Path, NULL);

    Root[0] = TestDirectory[0]; Root[1] = L':'; Root[2] = L'\\'; Root[3] = UNICODE_NULL;
    IsNtfs = GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, Fs, ARRAYSIZE(Fs)) && !wcscmp(Fs, L"NTFS");

    TestFlags();
    TestRules();

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        swprintf(Path, MAX_PATH, L"%ls\\%ls", TestDirectory, Names[i]);
        DeleteFileW(Path);
    }
    swprintf(Path, MAX_PATH, L"%ls\\sub", TestDirectory);
    RemoveDirectoryW(Path);
    RemoveDirectoryW(TestDirectory);
}
