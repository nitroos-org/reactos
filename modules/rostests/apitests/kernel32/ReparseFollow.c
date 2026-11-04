/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Following symbolic links in the object manager: names relative to a RootDirectory handle,
 *              loops, link data that cannot be followed, deleting a link and not its target
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Functional tests only. A symbolic link is created with CreateSymbolicLinkW (or by hand with
 * FSCTL_SET_REPARSE_POINT) and opened again with NtOpenFile: the open has to give the target, or fail with a
 * clean status; it must never hang or crash. The test needs SeCreateSymbolicLinkPrivilege and skips without it.
 */

#include "precomp.h"
#include <winuser.h>
#include <winioctl.h>
#include <ndk/iofuncs.h>

#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000CL
#endif
#ifndef FSCTL_SET_REPARSE_POINT
#define FSCTL_SET_REPARSE_POINT CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 41, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef STATUS_REPARSE_POINT_NOT_RESOLVED
#define STATUS_REPARSE_POINT_NOT_RESOLVED ((NTSTATUS)0xC0000280)
#endif
#ifndef STATUS_IO_REPARSE_DATA_INVALID
#define STATUS_IO_REPARSE_DATA_INVALID ((NTSTATUS)0xC0000278)
#endif
#ifndef SYMBOLIC_LINK_FLAG_DIRECTORY
#define SYMBOLIC_LINK_FLAG_DIRECTORY 0x1
#endif
#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define LINK_RELATIVE 1

typedef struct
{
    DWORD ReparseTag;
    WORD  ReparseDataLength;
    WORD  Reserved;
    WORD  SubstituteNameOffset;
    WORD  SubstituteNameLength;
    WORD  PrintNameOffset;
    WORD  PrintNameLength;
    DWORD Flags;
    WCHAR PathBuffer[1];
} LINK_DATA;

typedef BOOLEAN (WINAPI *PFN_CSLW)(LPCWSTR, LPCWSTR, DWORD);
static PFN_CSLW pCreateSymbolicLinkW;

static WCHAR Base[MAX_PATH];       /* C:\...\ReparseFollow-<pid> */
static WCHAR BaseNt[MAX_PATH];     /* \Device\HarddiskVolumeN\...\ReparseFollow-<pid> */
static WCHAR DeviceName[MAX_PATH]; /* \Device\HarddiskVolumeN */
static WCHAR BaseBelowDevice[MAX_PATH]; /* HarddiskVolumeN\...\ReparseFollow-<pid> */

static void P(WCHAR *Out, PCWSTR Rel)
{
    wsprintfW(Out, L"%s\\%s", Base, Rel);
}

static void MakeFile(PCWSTR Rel, const char *Data)
{
    WCHAR Path[MAX_PATH];
    HANDLE h;
    DWORD n;

    P(Path, Rel);
    h = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h != INVALID_HANDLE_VALUE, "creating %ls failed: %lu\n", Path, GetLastError());
    if (h != INVALID_HANDLE_VALUE)
    {
        WriteFile(h, Data, (DWORD)strlen(Data), &n, NULL);
        CloseHandle(h);
    }
}

static void MakeDir(PCWSTR Rel)
{
    WCHAR Path[MAX_PATH];

    P(Path, Rel);
    ok(CreateDirectoryW(Path, NULL), "creating %ls failed: %lu\n", Path, GetLastError());
}

static BOOL EnableLinkPrivilege(BOOL *Held)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Tp;
    BOOL Ret = FALSE;

    *Held = FALSE;
    Tp.PrivilegeCount = 1;
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, L"SeCreateSymbolicLinkPrivilege", &Tp.Privileges[0].Luid))
        return FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;
    Ret = AdjustTokenPrivileges(Token, FALSE, &Tp, 0, NULL, NULL);
    *Held = Ret && GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return *Held;
}

/* Opens Name (relative to Root, or absolute) with NtOpenFile and reads up to 31 bytes */
static NTSTATUS OpenRead(HANDLE Root, PCWSTR Name, ULONG Options, char *Out)
{
    UNICODE_STRING Us;
    OBJECT_ATTRIBUTES Oa;
    IO_STATUS_BLOCK Io;
    HANDLE File;
    NTSTATUS Status;
    LARGE_INTEGER Pos = {{0}};

    Out[0] = 0;
    RtlInitUnicodeString(&Us, Name);
    InitializeObjectAttributes(&Oa, &Us, OBJ_CASE_INSENSITIVE, Root, NULL);
    Status = NtOpenFile(&File, GENERIC_READ | SYNCHRONIZE, &Oa, &Io, SHARE_ALL,
                        FILE_SYNCHRONOUS_IO_NONALERT | Options);
    if (NT_SUCCESS(Status))
    {
        /* A link opened itself has no data to read */
        if (!(Options & FILE_OPEN_REPARSE_POINT))
        {
            Status = NtReadFile(File, NULL, NULL, NULL, &Io, Out, 31, &Pos, NULL);
            if (NT_SUCCESS(Status))
                Out[Io.Information] = 0;
        }
        NtClose(File);
    }
    return Status;
}

static HANDLE OpenObjectDirectory(PCWSTR Name)
{
    UNICODE_STRING Us;
    OBJECT_ATTRIBUTES Oa;
    HANDLE Dir = NULL;
    NTSTATUS Status;

    RtlInitUnicodeString(&Us, Name);
    InitializeObjectAttributes(&Oa, &Us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenDirectoryObject(&Dir, DIRECTORY_TRAVERSE | DIRECTORY_QUERY, &Oa);
    ok(NT_SUCCESS(Status), "opening %ls failed: 0x%08lx\n", Name, Status);
    return NT_SUCCESS(Status) ? Dir : NULL;
}

static HANDLE OpenFileDirectory(PCWSTR DosPath)
{
    HANDLE h = CreateFileW(DosPath, FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE, SHARE_ALL, NULL, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(h != INVALID_HANDLE_VALUE, "opening directory %ls failed: %lu\n", DosPath, GetLastError());
    return h == INVALID_HANDLE_VALUE ? NULL : h;
}

static void Link(PCWSTR LinkRel, PCWSTR Target, BOOL IsDir)
{
    WCHAR Path[MAX_PATH];

    P(Path, LinkRel);
    ok(pCreateSymbolicLinkW(Path, Target, IsDir ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0),
       "CreateSymbolicLinkW(%ls -> %ls) failed: %lu\n", LinkRel, Target, GetLastError());
}

/* A link with data of our own, to be opened after */
static BOOL RawLink(PCWSTR LinkRel, DWORD Flags, PCWSTR Sub, BOOL IsDir)
{
    BYTE Buf[1024];
    LINK_DATA *Rp = (LINK_DATA *)Buf;
    DWORD SubLen = lstrlenW(Sub) * sizeof(WCHAR), Size, Ret;
    WCHAR Path[MAX_PATH];
    HANDLE h;
    BOOL Ok;

    Rp->ReparseTag = IO_REPARSE_TAG_SYMLINK;
    Rp->Reserved = 0;
    Rp->SubstituteNameOffset = 0;
    Rp->SubstituteNameLength = (WORD)SubLen;
    Rp->PrintNameOffset = (WORD)SubLen;
    Rp->PrintNameLength = (WORD)SubLen;
    Rp->Flags = Flags;
    memcpy(Rp->PathBuffer, Sub, SubLen);
    memcpy((BYTE *)Rp->PathBuffer + SubLen, Sub, SubLen);
    Size = FIELD_OFFSET(LINK_DATA, PathBuffer) + 2 * SubLen;
    Rp->ReparseDataLength = (WORD)(Size - 8);

    P(Path, LinkRel);
    if (IsDir)
    {
        ok(CreateDirectoryW(Path, NULL), "creating %ls failed: %lu\n", Path, GetLastError());
        h = CreateFileW(Path, GENERIC_WRITE | DELETE, SHARE_ALL, NULL, OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    else
    {
        h = CreateFileW(Path, GENERIC_WRITE | DELETE, SHARE_ALL, NULL, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    }
    if (h == INVALID_HANDLE_VALUE)
    {
        ok(0, "opening %ls for the link data failed: %lu\n", Path, GetLastError());
        return FALSE;
    }
    Ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, Buf, Size, NULL, 0, &Ret, NULL);
    CloseHandle(h);
    if (!Ok)
    {
        if (IsDir) RemoveDirectoryW(Path); else DeleteFileW(Path);
    }
    return Ok;
}

static void Unlink(PCWSTR Rel, BOOL IsDir)
{
    WCHAR Path[MAX_PATH];

    P(Path, Rel);
    if (IsDir) RemoveDirectoryW(Path); else DeleteFileW(Path);
}

static void Test_RootDirectory(void)
{
    HANDLE DeviceDir, DosDir, FileDir, SubDir;
    WCHAR Name[MAX_PATH], Path[MAX_PATH];
    char Buf[32];
    NTSTATUS Status;

    Link(L"rel-file", L"tfile.txt", FALSE);
    Link(L"rel-dir", L"tdir", TRUE);
    Link(L"sub\\up-file", L"..\\tfile.txt", FALSE);
    Link(L"sub\\up-dir", L"..\\tdir", TRUE);

    /* The root is an object directory: the name below it is not rooted. A relative link in it is
       resolved against the directory that holds the link, and the result is parsed again from that root. */
    DeviceDir = OpenObjectDirectory(L"\\Device");
    if (DeviceDir)
    {
        wsprintfW(Name, L"%s\\rel-file", BaseBelowDevice);
        Status = OpenRead(DeviceDir, Name, 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "HELLO"), "file link below \\Device: 0x%08lx '%s'\n", Status, Buf);

        wsprintfW(Name, L"%s\\rel-dir\\inner.txt", BaseBelowDevice);
        Status = OpenRead(DeviceDir, Name, 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "INNER"), "directory link below \\Device: 0x%08lx '%s'\n", Status, Buf);

        wsprintfW(Name, L"%s\\sub\\up-file", BaseBelowDevice);
        Status = OpenRead(DeviceDir, Name, 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "HELLO"), "link with .. below \\Device: 0x%08lx '%s'\n", Status, Buf);

        wsprintfW(Name, L"%s\\sub\\up-dir\\inner.txt", BaseBelowDevice);
        Status = OpenRead(DeviceDir, Name, 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "INNER"), "directory link with .. below \\Device: 0x%08lx '%s'\n", Status, Buf);

        /* The same names, opened itself: the link's own data is there and nothing is followed */
        wsprintfW(Name, L"%s\\rel-file", BaseBelowDevice);
        Status = OpenRead(DeviceDir, Name, FILE_OPEN_REPARSE_POINT, Buf);
        ok(NT_SUCCESS(Status), "link itself below \\Device: 0x%08lx\n", Status);

        /* Nothing that does not exist */
        wsprintfW(Name, L"%s\\rel-file-nothere", BaseBelowDevice);
        Status = OpenRead(DeviceDir, Name, 0, Buf);
        ok(Status == STATUS_OBJECT_NAME_NOT_FOUND, "missing name below \\Device: 0x%08lx\n", Status);
        NtClose(DeviceDir);
    }

    /* The root is the DOS device directory */
    DosDir = OpenObjectDirectory(L"\\??");
    if (DosDir)
    {
        wsprintfW(Name, L"%c:%s\\rel-file", Base[0], Base + 2);
        Status = OpenRead(DosDir, Name, 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "HELLO"), "file link below \\??: 0x%08lx '%s'\n", Status, Buf);
        wsprintfW(Name, L"%c:%s\\rel-dir\\inner.txt", Base[0], Base + 2);
        Status = OpenRead(DosDir, Name, 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "INNER"), "directory link below \\??: 0x%08lx '%s'\n", Status, Buf);
        NtClose(DosDir);
    }

    /* The root is a directory of the file system: the relative link is resolved against its name */
    FileDir = OpenFileDirectory(Base);
    if (FileDir)
    {
        Status = OpenRead(FileDir, L"rel-file", 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "HELLO"), "file link below a directory handle: 0x%08lx '%s'\n", Status, Buf);
        Status = OpenRead(FileDir, L"rel-dir\\inner.txt", 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "INNER"), "directory link below a directory handle: 0x%08lx '%s'\n", Status, Buf);
        Status = OpenRead(FileDir, L"sub\\up-file", 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "HELLO"), "link with .. below a directory handle: 0x%08lx '%s'\n", Status, Buf);
        Status = OpenRead(FileDir, L"sub\\up-dir\\deeper\\deep.txt", 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "DEEP"), "two levels below a directory link: 0x%08lx '%s'\n", Status, Buf);
        NtClose(FileDir);
    }

    P(Path, L"sub");
    SubDir = OpenFileDirectory(Path);
    if (SubDir)
    {
        Status = OpenRead(SubDir, L"up-file", 0, Buf);
        ok(NT_SUCCESS(Status) && !strcmp(Buf, "HELLO"), ".. link below a directory handle in the subdirectory: 0x%08lx '%s'\n", Status, Buf);
        NtClose(SubDir);
    }

    Unlink(L"rel-file", FALSE);
    Unlink(L"rel-dir", TRUE);
    Unlink(L"sub\\up-file", FALSE);
    Unlink(L"sub\\up-dir", TRUE);
}

static void Test_Loops(void)
{
    WCHAR Path[MAX_PATH], Name[MAX_PATH];
    HANDLE h, DeviceDir;
    char Buf[32];
    NTSTATUS Status;
    DWORD Start, Elapsed;

    /* a -> b -> a, and a link to itself, for a file and a directory */
    Link(L"loop-a", L"loop-b", FALSE);
    Link(L"loop-b", L"loop-a", FALSE);
    Link(L"loop-self", L"loop-self", FALSE);
    Link(L"loop-da", L"loop-db", TRUE);
    Link(L"loop-db", L"loop-da", TRUE);

    Start = GetTickCount();
    P(Path, L"loop-a");
    SetLastError(0xdeadbeef);
    h = CreateFileW(Path, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_CANT_RESOLVE_FILENAME,
       "loop a -> b -> a: handle %p, error %lu (expected ERROR_CANT_RESOLVE_FILENAME)\n", h, GetLastError());
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    P(Path, L"loop-self");
    SetLastError(0xdeadbeef);
    h = CreateFileW(Path, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_CANT_RESOLVE_FILENAME,
       "link to itself: handle %p, error %lu (expected ERROR_CANT_RESOLVE_FILENAME)\n", h, GetLastError());
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    wsprintfW(Path, L"%s\\loop-da\\x.txt", Base);
    SetLastError(0xdeadbeef);
    h = CreateFileW(Path, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_CANT_RESOLVE_FILENAME,
       "directory loop: handle %p, error %lu (expected ERROR_CANT_RESOLVE_FILENAME)\n", h, GetLastError());
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    /* Below an object directory (the path that kept a stale name) */
    DeviceDir = OpenObjectDirectory(L"\\Device");
    if (DeviceDir)
    {
        wsprintfW(Name, L"%s\\loop-a", BaseBelowDevice);
        Status = OpenRead(DeviceDir, Name, 0, Buf);
        ok(Status == STATUS_REPARSE_POINT_NOT_RESOLVED, "loop below \\Device: 0x%08lx\n", Status);
        NtClose(DeviceDir);
    }

    Elapsed = GetTickCount() - Start;
    ok(Elapsed < 20000, "the loops took %lu ms\n", Elapsed);

    /* The links of the loop can be opened themselves and deleted, and the file still reads */
    P(Path, L"loop-a");
    h = CreateFileW(Path, 0, SHARE_ALL, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    ok(h != INVALID_HANDLE_VALUE, "opening the loop link itself failed: %lu\n", GetLastError());
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

    Unlink(L"loop-a", FALSE);
    Unlink(L"loop-b", FALSE);
    Unlink(L"loop-self", FALSE);
    Unlink(L"loop-da", TRUE);
    Unlink(L"loop-db", TRUE);
    P(Path, L"loop-a");
    ok(GetFileAttributesW(Path) == INVALID_FILE_ATTRIBUTES, "loop link not deleted\n");
}

/* Link data that cannot be followed: the open fails cleanly */
static void Test_BadData(void)
{
    WCHAR Path[MAX_PATH], Name[MAX_PATH];
    HANDLE h, DeviceDir;
    char Buf[32];
    NTSTATUS Status;

    /* Absolute (no relative flag) with a substitute name that is not an absolute NT name: it could only be
       resolved against whatever directory the caller named */
    if (RawLink(L"bad-unrooted", 0, L"tfile.txt", FALSE))
    {
        P(Path, L"bad-unrooted");
        SetLastError(0xdeadbeef);
        h = CreateFileW(Path, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_NAME,
           "an absolute link with an unrooted substitute name: handle %p, error %lu (Windows 10: ERROR_INVALID_NAME)\n",
           h, GetLastError());
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);

        DeviceDir = OpenObjectDirectory(L"\\Device");
        if (DeviceDir)
        {
            wsprintfW(Name, L"%s\\bad-unrooted", BaseBelowDevice);
            Status = OpenRead(DeviceDir, Name, 0, Buf);
            ok(!NT_SUCCESS(Status), "the unrooted link was followed below \\Device: 0x%08lx '%s'\n", Status, Buf);
            NtClose(DeviceDir);
        }
        Unlink(L"bad-unrooted", FALSE);
    }

    /* A link to an object that is not a file system object */
    if (RawLink(L"bad-object", 0, L"\\BaseNamedObjects", FALSE))
    {
        P(Path, L"bad-object");
        SetLastError(0xdeadbeef);
        h = CreateFileW(Path, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(h == INVALID_HANDLE_VALUE, "a link to a non-file object was followed\n");
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        Unlink(L"bad-object", FALSE);
    }
}

/* Using a link: write through it, list a directory through it, delete the link and not the target */
static void Test_Use(void)
{
    WCHAR Path[MAX_PATH], Target[MAX_PATH];
    HANDLE h, Find;
    WIN32_FIND_DATAW Fd;
    DWORD n;
    char Buf[32] = {0};
    BOOL Found = FALSE;

    Link(L"use-file", L"tfile.txt", FALSE);
    Link(L"use-dir", L"tdir", TRUE);

    P(Path, L"use-file");
    h = CreateFileW(Path, GENERIC_WRITE, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h != INVALID_HANDLE_VALUE, "opening the file link for writing failed: %lu\n", GetLastError());
    if (h != INVALID_HANDLE_VALUE)
    {
        ok(WriteFile(h, "WORLD", 5, &n, NULL), "write failed: %lu\n", GetLastError());
        CloseHandle(h);
    }
    P(Target, L"tfile.txt");
    h = CreateFileW(Target, GENERIC_READ, SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        ReadFile(h, Buf, 31, &n, NULL);
        ok(n == 5 && !memcmp(Buf, "WORLD", 5), "the target reads '%s' after writing through the link\n", Buf);
        CloseHandle(h);
    }

    /* A file in the directory behind the link */
    wsprintfW(Path, L"%s\\use-dir\\new.txt", Base);
    h = CreateFileW(Path, GENERIC_WRITE, SHARE_ALL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(h != INVALID_HANDLE_VALUE, "creating a file below the directory link failed: %lu\n", GetLastError());
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    wsprintfW(Path, L"%s\\tdir\\new.txt", Base);
    ok(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "the file is not in the target directory\n");
    DeleteFileW(Path);

    wsprintfW(Path, L"%s\\use-dir\\*", Base);
    Find = FindFirstFileW(Path, &Fd);
    ok(Find != INVALID_HANDLE_VALUE, "dir through the link failed: %lu\n", GetLastError());
    if (Find != INVALID_HANDLE_VALUE)
    {
        do Found |= !lstrcmpW(Fd.cFileName, L"inner.txt"); while (FindNextFileW(Find, &Fd));
        FindClose(Find);
        ok(Found, "inner.txt is not listed through the link\n");
    }

    P(Path, L"use-file");
    ok(DeleteFileW(Path), "deleting the file link failed: %lu\n", GetLastError());
    P(Path, L"use-dir");
    ok(RemoveDirectoryW(Path), "removing the directory link failed: %lu\n", GetLastError());
    P(Path, L"tfile.txt");
    ok(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "the target file went with its link\n");
    wsprintfW(Path, L"%s\\tdir\\inner.txt", Base);
    ok(GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES, "the target directory content went with its link\n");
}

static void Cleanup(void)
{
    static const PCWSTR Files[] = { L"tdir\\deeper\\deep.txt", L"tdir\\inner.txt", L"tdir\\new.txt", L"tfile.txt" };
    static const PCWSTR Dirs[] = { L"tdir\\deeper", L"tdir", L"sub" };
    static const PCWSTR Links[] = { L"rel-file", L"sub\\up-file", L"loop-a", L"loop-b", L"loop-self", L"bad-unrooted",
                                    L"bad-volume", L"bad-object", L"use-file" };
    static const PCWSTR DirLinks[] = { L"rel-dir", L"sub\\up-dir", L"loop-da", L"loop-db", L"use-dir" };
    WCHAR Path[MAX_PATH];
    UINT i;

    for (i = 0; i < ARRAYSIZE(Links); i++) { P(Path, Links[i]); DeleteFileW(Path); }
    for (i = 0; i < ARRAYSIZE(DirLinks); i++) { P(Path, DirLinks[i]); RemoveDirectoryW(Path); }
    for (i = 0; i < ARRAYSIZE(Files); i++) { P(Path, Files[i]); DeleteFileW(Path); }
    for (i = 0; i < ARRAYSIZE(Dirs); i++) { P(Path, Dirs[i]); RemoveDirectoryW(Path); }
    RemoveDirectoryW(Base);
}

START_TEST(ReparseFollow)
{
    WCHAR Temp[MAX_PATH], Drive[3], Device[MAX_PATH];
    BOOL Held;

    pCreateSymbolicLinkW = (PFN_CSLW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateSymbolicLinkW");
    if (!pCreateSymbolicLinkW)
    {
        skip("CreateSymbolicLinkW is not available\n");
        return;
    }
    /* "force": run without the privilege (only a system that does not ask for it, to see how it behaves) */
    if (!EnableLinkPrivilege(&Held) && !wcsstr(GetCommandLineW(), L"force"))
    {
        skip("SeCreateSymbolicLinkPrivilege is not held\n");
        return;
    }

    GetTempPathW(MAX_PATH, Temp);
    wsprintfW(Base, L"%sReparseFollow-%lu", Temp, GetCurrentProcessId());
    Drive[0] = Base[0]; Drive[1] = L':'; Drive[2] = 0;
    if (Base[1] != L':' || !QueryDosDeviceW(Drive, Device, MAX_PATH) ||
        _wcsnicmp(Device, L"\\Device\\", 8))
    {
        skip("the temp path %ls is not on a local volume with a device name\n", Base);
        return;
    }
    lstrcpyW(DeviceName, Device);
    wsprintfW(BaseNt, L"%s%s", Device, Base + 2);
    wsprintfW(BaseBelowDevice, L"%s%s", Device + 8, Base + 2);

    Cleanup();
    if (!CreateDirectoryW(Base, NULL))
    {
        skip("cannot create the test directory %ls: %lu\n", Base, GetLastError());
        return;
    }
    MakeFile(L"tfile.txt", "HELLO");
    MakeDir(L"tdir");
    MakeDir(L"sub");
    MakeFile(L"tdir\\inner.txt", "INNER");
    MakeDir(L"tdir\\deeper");
    MakeFile(L"tdir\\deeper\\deep.txt", "DEEP");

    {
        /* A volume without symbolic links ends the test */
        WCHAR Probe[MAX_PATH];
        P(Probe, L"probe");
        if (!pCreateSymbolicLinkW(Probe, L"tfile.txt", 0))
        {
            DWORD Err = GetLastError();
            skip("no symbolic links on this volume (%lu)\n", Err);
            Cleanup();
            return;
        }
        DeleteFileW(Probe);
    }

    Test_RootDirectory();
    Test_Loops();
    Test_BadData();
    Test_Use();

    Cleanup();
}
