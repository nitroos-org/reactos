/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for ReOpenFile: argument checks, access and sharing, FILE_FLAG_* options, other object types
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows Server 2022 (x64 and WOW64) with a probe that acts only on
 * files, directories and pipes it creates. Windows 10 was not measured.
 */

#include "precomp.h"

typedef HANDLE (WINAPI *PFN_ReOpenFile)(HANDLE, DWORD, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_SetFileInformationByHandle)(HANDLE, int, LPVOID, DWORD);

/* FILE_BASIC_INFO of the documentation (the headers of the old Windows versions do not have it) */
typedef struct _BASIC_INFO
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    DWORD FileAttributes;
} BASIC_INFO;
typedef LONG (NTAPI *PFN_NtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

static PFN_ReOpenFile pReOpenFile;
static PFN_SetFileInformationByHandle pSetFileInformationByHandle;
static PFN_NtQueryInformationFile pNtQueryInformationFile;
static WCHAR TempDir[MAX_PATH];
static BOOL g_IsNtfs;

#define SHARE_RW (FILE_SHARE_READ | FILE_SHARE_WRITE)
#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define NO_SIZE 0xdeadbeef

static DWORD QueryDword(HANDLE Handle, ULONG Class)
{
    IO_STATUS_BLOCK Io;
    DWORD Value = NO_SIZE;

    if (pNtQueryInformationFile(Handle, &Io, &Value, sizeof(Value), Class) < 0)
        return NO_SIZE;
    return Value;
}

#define ACCESS_OF(h) QueryDword(h, 8)   /* FileAccessInformation */
#define MODE_OF(h) QueryDword(h, 16)    /* FileModeInformation */

static PCWSTR FilePath(PCWSTR Name)
{
    static WCHAR Path[4][MAX_PATH];
    static int Index;

    Index = (Index + 1) & 3;
    StringCchPrintfW(Path[Index], MAX_PATH, L"%ls\\%ls", TempDir, Name);
    return Path[Index];
}

static void MakeFile(PCWSTR Name, PCSTR Data)
{
    HANDLE File = CreateFileW(FilePath(Name), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Written;

    ok(File != INVALID_HANDLE_VALUE, "%ls: error %lu\n", Name, GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        WriteFile(File, Data, (DWORD)strlen(Data), &Written, NULL);
        CloseHandle(File);
    }
}

/* ERROR 0 = success; Access and Mode are the access mask and the FileModeInformation of the new handle */
static void Check(PCSTR Name, HANDLE Original, DWORD Access, DWORD Share, DWORD Flags,
                  DWORD Error, DWORD Granted, DWORD Mode)
{
    HANDLE New;
    DWORD Err;

    SetLastError(0xdeadbeef);
    New = pReOpenFile(Original, Access, Share, Flags);
    Err = GetLastError();
    if (Error)
    {
        ok(New == INVALID_HANDLE_VALUE, "%s: got %p, expected failure\n", Name, New);
        ok(Err == Error, "%s: error %lu, expected %lu\n", Name, Err, Error);
    }
    else
    {
        ok(New != INVALID_HANDLE_VALUE, "%s: failed, error %lu\n", Name, Err);
    }
    if (New != INVALID_HANDLE_VALUE)
    {
        if (!Error)
        {
            ok(ACCESS_OF(New) == Granted, "%s: access %08lx, expected %08lx\n", Name, ACCESS_OF(New), Granted);
            ok(MODE_OF(New) == Mode, "%s: mode %02lx, expected %02lx\n", Name, MODE_OF(New), Mode);
        }
        CloseHandle(New);
    }
}

static void TestOrdinaryFile(void)
{
    HANDLE File;
    HANDLE New;
    DWORD Bit, Flags;
    CHAR Buffer[16];
    DWORD Size;
    OVERLAPPED Overlapped;
    BOOL Ret;

    MakeFile(L"a.txt", "hello world");
    File = CreateFileW(FilePath(L"a.txt"), GENERIC_READ | GENERIC_WRITE, SHARE_RW, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    ok(ACCESS_OF(File) == 0x0012019f, "original access %08lx\n", ACCESS_OF(File));

    /* The original handle allows read and write sharing only, so every request that includes delete is a sharing violation */
    Check("read, share rw", File, GENERIC_READ, SHARE_RW, 0, 0, 0x00120089, 0x20);
    Check("read, share 0", File, GENERIC_READ, 0, 0, ERROR_SHARING_VIOLATION, 0, 0);
    Check("write, share rw", File, GENERIC_WRITE, SHARE_RW, 0, 0, 0x00120196, 0x20);
    Check("write, share r", File, GENERIC_WRITE, FILE_SHARE_READ, 0, ERROR_SHARING_VIOLATION, 0, 0);
    Check("read+write, share rw", File, GENERIC_READ | GENERIC_WRITE, SHARE_RW, 0, 0, 0x0012019f, 0x20);
    Check("all, share rw", File, GENERIC_ALL, SHARE_RW, 0, ERROR_SHARING_VIOLATION, 0, 0);
    Check("execute, share rw", File, GENERIC_EXECUTE, SHARE_RW, 0, 0, 0x001200a0, 0x20);
    Check("access 0, share 0", File, 0, 0, 0, 0, 0x00100080, 0x20);
    Check("FILE_WRITE_ATTRIBUTES, share 0", File, FILE_WRITE_ATTRIBUTES, 0, 0, 0, 0x00100180, 0x20);
    Check("DELETE, share rwd", File, DELETE, SHARE_ALL, 0, ERROR_SHARING_VIOLATION, 0, 0);
    /* MAXIMUM_ALLOWED includes DELETE on NTFS; a FAT volume grants other bits, and the sharing conflict is not there */
    if (g_IsNtfs)
        Check("MAXIMUM_ALLOWED, share rw", File, MAXIMUM_ALLOWED, SHARE_RW, 0, ERROR_SHARING_VIOLATION, 0, 0);
    else
        skip("MAXIMUM_ALLOWED: not an NTFS volume\n");
    Check("READ_CONTROL, share rw", File, READ_CONTROL, SHARE_RW, 0, 0, 0x00120080, 0x20);
    Check("WRITE_DAC, share rw", File, WRITE_DAC, SHARE_RW, 0, 0, 0x00140080, 0x20);
    Check("share bits 0xffffffff", File, GENERIC_READ, 0xffffffff, 0, ERROR_INVALID_PARAMETER, 0, 0);

    /* Every FILE_ATTRIBUTE_* value is refused (the parameter takes FILE_FLAG_* only); the other single bits are accepted */
    for (Bit = 0; Bit < 32; Bit++)
    {
        CHAR Name[32];
        BOOL Invalid;

        Flags = 1u << Bit;
        Invalid = (Flags & 0x005affb7) != 0;
        sprintf(Name, "flag bit %08lx", Flags);
        if (Flags == FILE_FLAG_DELETE_ON_CLOSE)
            Check(Name, File, GENERIC_READ, SHARE_RW, Flags, ERROR_SHARING_VIOLATION, 0, 0);
        else if (Invalid)
            Check(Name, File, GENERIC_READ, SHARE_RW, Flags, ERROR_INVALID_PARAMETER, 0, 0);
        else
        {
            DWORD Mode = 0x20;

            if (Flags == FILE_FLAG_OVERLAPPED)
                Mode = 0x00;
            else if (Flags == FILE_FLAG_NO_BUFFERING)
                Mode = 0x28;
            else if (Flags == FILE_FLAG_SEQUENTIAL_SCAN)
                Mode = 0x24;
            else if (Flags == FILE_FLAG_WRITE_THROUGH)
                Mode = 0x22;
            Check(Name, File, GENERIC_READ, SHARE_RW, Flags, 0, 0x00120089, Mode);
        }
    }
    Check("FILE_FLAG_BACKUP_SEMANTICS", File, GENERIC_READ, SHARE_RW, FILE_FLAG_BACKUP_SEMANTICS, 0, 0x00120089, 0x20);
    Check("FILE_FLAG_OPEN_REPARSE_POINT", File, GENERIC_READ, SHARE_RW, FILE_FLAG_OPEN_REPARSE_POINT, 0, 0x00120089, 0x20);
    Check("flags 0xfff80000", File, GENERIC_READ, SHARE_RW, 0xfff80000, ERROR_INVALID_PARAMETER, 0, 0);
    Check("flags 0xffffffff", File, GENERIC_READ, SHARE_RW, 0xffffffff, ERROR_INVALID_PARAMETER, 0, 0);

    /* the new handle has its own file pointer, and is not inheritable */
    SetFilePointer(File, 5, NULL, FILE_BEGIN);
    New = pReOpenFile(File, GENERIC_READ, SHARE_RW, 0);
    ok(New != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (New != INVALID_HANDLE_VALUE)
    {
        DWORD HandleFlags = 0xdeadbeef;

        ZeroMemory(Buffer, sizeof(Buffer));
        Ret = ReadFile(New, Buffer, 5, &Size, NULL);
        ok(Ret && Size == 5 && !memcmp(Buffer, "hello", 5), "read %d %lu '%s'\n", Ret, Size, Buffer);
        ok(SetFilePointer(File, 0, NULL, FILE_CURRENT) == 5, "the original file pointer moved\n");
        Ret = GetHandleInformation(New, &HandleFlags);
        ok(Ret && !(HandleFlags & HANDLE_FLAG_INHERIT), "handle flags %lx\n", HandleFlags);
        CloseHandle(New);
    }

    /* an overlapped handle takes overlapped reads (the mode of the handle, FileModeInformation without the synchronous bits, is in the rows above;
       whether a read of a cached file completes at once or is pending depends on the file system, so both are accepted) */
    New = pReOpenFile(File, GENERIC_READ, SHARE_RW, FILE_FLAG_OVERLAPPED);
    ok(New != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (New != INVALID_HANDLE_VALUE)
    {
        ZeroMemory(&Overlapped, sizeof(Overlapped));
        Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        SetLastError(0xdeadbeef);
        Ret = ReadFile(New, Buffer, 2, NULL, &Overlapped);
        ok(Ret || GetLastError() == ERROR_IO_PENDING, "overlapped read: %d, error %lu\n", Ret, GetLastError());
        Size = 0;
        Ret = GetOverlappedResult(New, &Overlapped, &Size, TRUE);
        ok(Ret && Size == 2, "overlapped result: %d, %lu bytes, error %lu\n", Ret, Size, GetLastError());
        CloseHandle(Overlapped.hEvent);
        CloseHandle(New);
    }

    /* the way Node.js and libuv change the mode of a file: an attribute-only handle */
    New = pReOpenFile(File, FILE_WRITE_ATTRIBUTES, 0, 0);
    ok(New != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (New != INVALID_HANDLE_VALUE)
    {
        BASIC_INFO Info;

        ZeroMemory(&Info, sizeof(Info));
        Info.FileAttributes = FILE_ATTRIBUTE_READONLY;
        if (pSetFileInformationByHandle)
        {
            Ret = pSetFileInformationByHandle(New, 0 /* FileBasicInfo */, &Info, sizeof(Info));
            ok(Ret, "SetFileInformationByHandle: error %lu\n", GetLastError());
            ok(GetFileAttributesW(FilePath(L"a.txt")) == FILE_ATTRIBUTE_READONLY, "attributes %lx\n", GetFileAttributesW(FilePath(L"a.txt")));
            Info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            pSetFileInformationByHandle(New, 0, &Info, sizeof(Info));
        }
        CloseHandle(New);
    }
    CloseHandle(File);

    /* an exclusive original handle blocks every reopen */
    File = CreateFileW(FilePath(L"a.txt"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Check("original share 0, reopen share rw", File, GENERIC_READ, SHARE_RW, 0, ERROR_SHARING_VIOLATION, 0, 0);
    Check("original share 0, reopen share 0", File, GENERIC_READ, 0, 0, ERROR_SHARING_VIOLATION, 0, 0);
    CloseHandle(File);

    /* the access of the original handle does not limit the new one */
    File = CreateFileW(FilePath(L"a.txt"), GENERIC_READ, SHARE_RW, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Check("original read, reopen write", File, GENERIC_WRITE, SHARE_RW, 0, 0, 0x00120196, 0x20);
    CloseHandle(File);
    File = CreateFileW(FilePath(L"a.txt"), FILE_READ_ATTRIBUTES, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Check("original attributes only, reopen read", File, GENERIC_READ, SHARE_RW, 0, 0, 0x00120089, 0x20);
    Check("original attributes only, reopen write", File, GENERIC_WRITE, SHARE_RW, 0, 0, 0x00120196, 0x20);
    Check("original attributes only, reopen delete", File, DELETE, SHARE_ALL, 0, 0, 0x00110080, 0x20);
    CloseHandle(File);
    File = CreateFileW(FilePath(L"a.txt"), 0, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Check("original access 0, reopen read", File, GENERIC_READ, SHARE_RW, 0, 0, 0x00120089, 0x20);
    CloseHandle(File);

    /* the original handle's own mode does not carry over */
    File = CreateFileW(FilePath(L"a.txt"), GENERIC_READ, SHARE_RW, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    ok(MODE_OF(File) == 0x00, "overlapped original mode %02lx\n", MODE_OF(File));
    Check("overlapped original, flags 0", File, GENERIC_READ, SHARE_RW, 0, 0, 0x00120089, 0x20);
    CloseHandle(File);

    /* a third open sees the sharing of the new handle */
    File = CreateFileW(FilePath(L"a.txt"), GENERIC_READ, SHARE_RW, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    New = pReOpenFile(File, GENERIC_READ, FILE_SHARE_READ, 0);
    ok(New != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (New != INVALID_HANDLE_VALUE)
    {
        HANDLE Third = CreateFileW(FilePath(L"a.txt"), GENERIC_WRITE, SHARE_RW, NULL, OPEN_EXISTING, 0, NULL);

        ok(Third == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION, "third open %p, error %lu\n", Third, GetLastError());
        if (Third != INVALID_HANDLE_VALUE)
            CloseHandle(Third);
        CloseHandle(New);
    }
    CloseHandle(File);
}

static void TestAttributesAndDeleteOnClose(void)
{
    HANDLE File, New;

    MakeFile(L"ro.txt", "ro");
    SetFileAttributesW(FilePath(L"ro.txt"), FILE_ATTRIBUTE_READONLY);
    File = CreateFileW(FilePath(L"ro.txt"), GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Check("read-only file, reopen write", File, GENERIC_WRITE, SHARE_RW, 0, ERROR_ACCESS_DENIED, 0, 0);
    Check("read-only file, FILE_WRITE_ATTRIBUTES", File, FILE_WRITE_ATTRIBUTES, SHARE_RW, 0, 0, 0x00100180, 0x20);
    Check("read-only file, DELETE", File, DELETE, SHARE_ALL, 0, 0, 0x00110080, 0x20);
    Check("read-only file, DELETE_ON_CLOSE", File, GENERIC_READ, SHARE_ALL, FILE_FLAG_DELETE_ON_CLOSE, ERROR_ACCESS_DENIED, 0, 0);
    CloseHandle(File);
    SetFileAttributesW(FilePath(L"ro.txt"), FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(FilePath(L"ro.txt"));

    MakeFile(L"del1.txt", "x");
    File = CreateFileW(FilePath(L"del1.txt"), GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    New = pReOpenFile(File, GENERIC_READ, SHARE_ALL, FILE_FLAG_DELETE_ON_CLOSE);
    ok(New != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (New != INVALID_HANDLE_VALUE)
    {
        ok(ACCESS_OF(New) == 0x00130089, "access %08lx\n", ACCESS_OF(New));
        CloseHandle(New);
        ok(GetFileAttributesW(FilePath(L"del1.txt")) == INVALID_FILE_ATTRIBUTES, "the file is still there after the new handle was closed\n");
    }
    CloseHandle(File);
    DeleteFileW(FilePath(L"del1.txt"));

    MakeFile(L"del2.txt", "x");
    File = CreateFileW(FilePath(L"del2.txt"), GENERIC_READ, SHARE_RW, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    Check("original lacks share delete, DELETE_ON_CLOSE", File, GENERIC_READ, SHARE_ALL, FILE_FLAG_DELETE_ON_CLOSE, ERROR_SHARING_VIOLATION, 0, 0);
    CloseHandle(File);
    DeleteFileW(FilePath(L"del2.txt"));
}

static void TestDirectoryAndOtherObjects(void)
{
    HANDLE Dir, File, Event, Pipe, New, Read, Write;
    CHAR Buffer[8];
    DWORD Size;

    /* a directory handle is refused with access denied, whatever the flags (the open is of a non-directory file) */
    CreateDirectoryW(FilePath(L"sub"), NULL);
    Dir = CreateFileW(FilePath(L"sub"), GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(Dir != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (Dir != INVALID_HANDLE_VALUE)
    {
        Check("directory, flags 0", Dir, GENERIC_READ, SHARE_RW, 0, ERROR_ACCESS_DENIED, 0, 0);
        Check("directory, BACKUP_SEMANTICS", Dir, GENERIC_READ, SHARE_RW, FILE_FLAG_BACKUP_SEMANTICS, ERROR_ACCESS_DENIED, 0, 0);
        Check("directory, BACKUP_SEMANTICS|OPEN_REPARSE_POINT", Dir, GENERIC_READ, SHARE_RW,
              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, ERROR_ACCESS_DENIED, 0, 0);
        Check("directory, write, BACKUP_SEMANTICS", Dir, GENERIC_WRITE, SHARE_RW, FILE_FLAG_BACKUP_SEMANTICS, ERROR_ACCESS_DENIED, 0, 0);
        CloseHandle(Dir);
    }
    RemoveDirectoryW(FilePath(L"sub"));

    /* handles that are not files */
    Check("INVALID_HANDLE_VALUE", INVALID_HANDLE_VALUE, GENERIC_READ, 7, 0, ERROR_INVALID_HANDLE, 0, 0);
    Check("NULL", NULL, GENERIC_READ, 7, 0, ERROR_BAD_PATHNAME, 0, 0);
    Check("bogus handle", (HANDLE)(ULONG_PTR)0x7777, GENERIC_READ, 7, 0, ERROR_INVALID_HANDLE, 0, 0);
    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    Check("event", Event, GENERIC_READ, 7, 0, ERROR_INVALID_HANDLE, 0, 0);
    CloseHandle(Event);
    File = CreateFileW(FilePath(L"a.txt"), GENERIC_READ, 7, NULL, OPEN_EXISTING, 0, NULL);
    CloseHandle(File);
    Check("closed handle", File, GENERIC_READ, 7, 0, ERROR_INVALID_HANDLE, 0, 0);

    /* a named pipe: the server end can be opened again and reads what the server end writes */
    Pipe = CreateNamedPipeW(L"\\\\.\\pipe\\reopenfile_apitest", PIPE_ACCESS_DUPLEX, 0, 1, 1000, 1000, 1000, NULL);
    ok(Pipe != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (Pipe != INVALID_HANDLE_VALUE)
    {
        New = pReOpenFile(Pipe, GENERIC_READ, SHARE_RW, 0);
        ok(New != INVALID_HANDLE_VALUE, "named pipe: error %lu\n", GetLastError());
        if (New != INVALID_HANDLE_VALUE)
        {
            ZeroMemory(Buffer, sizeof(Buffer));
            ok(WriteFile(Pipe, "foo", 4, &Size, NULL), "WriteFile: %lu\n", GetLastError());
            ok(ReadFile(New, Buffer, 4, &Size, NULL) && Size == 4 && !strcmp(Buffer, "foo"), "read '%s' %lu\n", Buffer, Size);
            CloseHandle(New);
        }
        CloseHandle(Pipe);
    }

    /* the read end of an anonymous pipe is busy (a pipe has one reader) */
    if (CreatePipe(&Read, &Write, NULL, 0))
    {
        Check("anonymous pipe read end", Read, GENERIC_READ, 7, 0, ERROR_PIPE_BUSY, 0, 0);
        CloseHandle(Read);
        CloseHandle(Write);
    }

    /* the NUL device */
    File = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, 7, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        New = pReOpenFile(File, GENERIC_READ, 7, 0);
        ok(New != INVALID_HANDLE_VALUE, "NUL: error %lu\n", GetLastError());
        if (New != INVALID_HANDLE_VALUE)
            CloseHandle(New);
        CloseHandle(File);
    }
}

static void TestStreamsAndDeletedFiles(void)
{
    HANDLE File;

    MakeFile(L"s.txt", "x");
    File = CreateFileW(FilePath(L"s.txt:ads"), GENERIC_READ | GENERIC_WRITE, 7, NULL, CREATE_ALWAYS, 0, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        Check("stream handle", File, GENERIC_READ, 7, 0, 0, 0x00120089, 0x20);
        CloseHandle(File);
    }
    else
        skip("no alternate data streams on this volume (error %lu)\n", GetLastError());
    DeleteFileW(FilePath(L"s.txt"));

    /* the object is reached through the handle, not the name: renamed or delete-pending files can be opened again */
    MakeFile(L"ren.txt", "abc");
    File = CreateFileW(FilePath(L"ren.txt"), GENERIC_READ | DELETE, 7, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "error %lu\n", GetLastError());
    if (File != INVALID_HANDLE_VALUE)
    {
        ok(MoveFileW(FilePath(L"ren.txt"), FilePath(L"ren2.txt")), "MoveFile: %lu\n", GetLastError());
        Check("after rename", File, GENERIC_READ, 7, 0, 0, 0x00120089, 0x20);
        DeleteFileW(FilePath(L"ren2.txt"));
        /* Windows opens a delete-pending file again through its handle; NitroOS answers STATUS_DELETE_PENDING (access denied): the file
           system's answer for a relative open */
        todo_if(is_reactos())
        Check("after delete (delete pending)", File, GENERIC_READ, 7, 0, 0, 0x00120089, 0x20);
        CloseHandle(File);
    }
    DeleteFileW(FilePath(L"ren2.txt"));
}

START_TEST(ReOpenFile)
{
    WCHAR Base[MAX_PATH];

    pReOpenFile = (PFN_ReOpenFile)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReOpenFile");
    pSetFileInformationByHandle = (PFN_SetFileInformationByHandle)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetFileInformationByHandle");
    pNtQueryInformationFile = (PFN_NtQueryInformationFile)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationFile");
    if (!pReOpenFile || !pNtQueryInformationFile)
    {
        skip("ReOpenFile is not available\n");
        return;
    }

    GetTempPathW(MAX_PATH, Base);
    StringCchPrintfW(TempDir, MAX_PATH, L"%lsreopenfile_apitest_%lu", Base, GetCurrentProcessId());
    ok(CreateDirectoryW(TempDir, NULL), "CreateDirectory: %lu\n", GetLastError());
    {
        WCHAR Root[4] = { TempDir[0], L':', L'\\', 0 };
        WCHAR FsName[32] = L"";

        GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, FsName, ARRAYSIZE(FsName));
        g_IsNtfs = !_wcsicmp(FsName, L"NTFS");
    }

    TestOrdinaryFile();
    TestAttributesAndDeleteOnClose();
    TestDirectoryAndOtherObjects();
    TestStreamsAndDeletedFiles();

    DeleteFileW(FilePath(L"a.txt"));
    RemoveDirectoryW(TempDir);
}
