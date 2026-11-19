/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     RDBSS tests through the loopback mini-redirector: user-mode part
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Every operation is done on \\looprdr\share\... (RDBSS + loopback
 * mini-redirector) and, where the result can be compared, on the same local
 * directory the share maps to. RdbssLoop is the functional set,
 * RdbssLoopStress the random-operation stress (RDBSS_STRESS_SECONDS,
 * default 60) with a byte compare against the local directory.
 */

#include <kmt_test.h>
#include <winioctl.h>
#include <stdlib.h>
#include <ndk/exfuncs.h>

#include "RdbssLoop.h"
#include <pseh/pseh2.h>
#include "RdbssHostile.h"
#include "RdbssLockTorture.h"

#define LOCAL_ROOT      L"C:\\RdbssLoopRoot"
#define LOCAL_ROOT_NT   L"\\??\\C:\\RdbssLoopRoot"
#define UNC_ROOT        L"\\\\" LOOPRDR_SERVER L"\\" LOOPRDR_SHARE
#define FCB_READ_CACHE  0x02000000  /* FCB_STATE_READCACHING_ENABLED */
#define FCB_READ_BUF    0x01000000  /* FCB_STATE_READBUFFERING_ENABLED */
#define FCB_WRITE_CACHE 0x08000000  /* FCB_STATE_WRITECACHING_ENABLED */
#define FCB_WRITE_BUF   0x04000000  /* FCB_STATE_WRITEBUFFERING_ENABLED */
#define FCB_ALL_CACHE   (FCB_READ_CACHE | FCB_READ_BUF | FCB_WRITE_CACHE | FCB_WRITE_BUF)
#define FCB_LOCK_BUF    0x00200000  /* FCB_STATE_LOCK_BUFFERING_ENABLED */

static HANDLE LoopDevice = INVALID_HANDLE_VALUE;

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

static
PCWSTR
P(
    _Out_writes_(MAX_PATH) PWSTR Buffer,
    _In_ BOOLEAN Unc,
    _In_ PCWSTR Relative)
{
    StringCchPrintfW(Buffer, MAX_PATH, L"%s\\%s", Unc ? UNC_ROOT : LOCAL_ROOT, Relative);
    return Buffer;
}

static
BOOL
LoopIoctl(
    _In_ DWORD Code,
    _In_opt_ PVOID In,
    _In_ DWORD InLength,
    _Out_opt_ PVOID Out,
    _In_ DWORD OutLength)
{
    DWORD Returned;

    return DeviceIoControl(LoopDevice, Code, In, InLength, Out, OutLength, &Returned, NULL);
}

static
VOID
LoopCounters(
    _Out_ PLOOPRDR_COUNTERS Counters)
{
    RtlZeroMemory(Counters, sizeof(*Counters));
    ok(LoopIoctl(IOCTL_LOOPRDR_GET_COUNTERS, NULL, 0, Counters, sizeof(*Counters)),
       "GET_COUNTERS failed: %lu\n", GetLastError());
}

static
VOID
LoopOptions(
    _In_ ULONG BufferingFlags,
    _In_ ULONG Flags)
{
    LOOPRDR_OPTIONS Options;

    Options.BufferingFlags = BufferingFlags;
    Options.Flags = Flags;
    ok(LoopIoctl(IOCTL_LOOPRDR_SET_OPTIONS, &Options, sizeof(Options), NULL, 0),
       "SET_OPTIONS failed: %lu\n", GetLastError());
}

static
VOID
Fill(
    _Out_writes_bytes_(Length) PUCHAR Buffer,
    _In_ SIZE_T Length,
    _In_ ULONG Seed)
{
    SIZE_T i;

    for (i = 0; i < Length; ++i)
    {
        Seed = Seed * 1103515245 + 12345;
        Buffer[i] = (UCHAR)(Seed >> 16);
    }
}

/* Reads a whole local file into a heap buffer */
static
PUCHAR
ReadWhole(
    _In_ PCWSTR Path,
    _Out_ PSIZE_T Length)
{
    HANDLE File;
    LARGE_INTEGER Size;
    PUCHAR Buffer;
    DWORD Read;

    *Length = 0;
    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }
    GetFileSizeEx(File, &Size);
    Buffer = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)Size.QuadPart + 1);
    if (Buffer != NULL && Size.QuadPart != 0 &&
        (!ReadFile(File, Buffer, (DWORD)Size.QuadPart, &Read, NULL) || Read != Size.QuadPart))
    {
        HeapFree(GetProcessHeap(), 0, Buffer);
        Buffer = NULL;
    }
    CloseHandle(File);
    *Length = (SIZE_T)Size.QuadPart;
    return Buffer;
}

static
BOOLEAN
SameContent(
    _In_ PCWSTR Relative,
    _In_reads_bytes_(Length) const UCHAR *Expected,
    _In_ SIZE_T Length)
{
    WCHAR Path[MAX_PATH];
    PUCHAR Data;
    SIZE_T Got;
    BOOLEAN Same;

    Data = ReadWhole(P(Path, FALSE, Relative), &Got);
    Same = (Data != NULL || Length == 0) && Got == Length && (Length == 0 || memcmp(Data, Expected, Length) == 0);
    if (Data != NULL)
    {
        HeapFree(GetProcessHeap(), 0, Data);
    }
    return Same;
}

/* Waits up to TimeoutMs for a local path to (dis)appear */
static
BOOLEAN
WaitExists(
    _In_ PCWSTR Relative,
    _In_ BOOLEAN Exists,
    _In_ DWORD TimeoutMs)
{
    WCHAR Path[MAX_PATH];
    DWORD Waited;

    P(Path, FALSE, Relative);
    for (Waited = 0; ; Waited += 50)
    {
        BOOLEAN Now = (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES);

        if (Now == Exists)
        {
            return TRUE;
        }
        if (Waited >= TimeoutMs)
        {
            return FALSE;
        }
        Sleep(50);
    }
}

static
VOID
DeleteTree(
    _In_ PCWSTR Directory)
{
    WCHAR Pattern[MAX_PATH], Path[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find;

    StringCchPrintfW(Pattern, MAX_PATH, L"%s\\*", Directory);
    Find = FindFirstFileW(Pattern, &Data);
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!wcscmp(Data.cFileName, L".") || !wcscmp(Data.cFileName, L".."))
            {
                continue;
            }
            StringCchPrintfW(Path, MAX_PATH, L"%s\\%s", Directory, Data.cFileName);
            SetFileAttributesW(Path, FILE_ATTRIBUTE_NORMAL);
            if (Data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                DeleteTree(Path);
                RemoveDirectoryW(Path);
            }
            else
            {
                DeleteFileW(Path);
            }
        } while (FindNextFileW(Find, &Data));
        FindClose(Find);
    }
}

/* Sum of the pool tags RDBSS and the loopback driver use ("Rx??", "NxLp") */
typedef struct _POOL_SUM
{
    LONGLONG Outstanding;   /* allocations minus frees */
    LONGLONG Bytes;
    CHAR Detail[512];       /* per tag: "RxFc=12/3456 ..." */
} POOL_SUM;

static
BOOLEAN
PoolSum(
    _Out_ POOL_SUM *Sum)
{
    NTSTATUS Status;
    ULONG Length = 256 * 1024, i;
    PSYSTEM_POOLTAG_INFORMATION Info;

    Sum->Outstanding = 0;
    Sum->Bytes = 0;
    Sum->Detail[0] = 0;
    for (;;)
    {
        Info = HeapAlloc(GetProcessHeap(), 0, Length);
        if (Info == NULL)
        {
            return FALSE;
        }
        Status = NtQuerySystemInformation(SystemPoolTagInformation, Info, Length, &Length);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
        {
            break;
        }
        HeapFree(GetProcessHeap(), 0, Info);
        Length += 64 * 1024;
    }
    if (!NT_SUCCESS(Status))
    {
        HeapFree(GetProcessHeap(), 0, Info);
        return FALSE;
    }
    for (i = 0; i < Info->Count; ++i)
    {
        PSYSTEM_POOLTAG Tag = &Info->TagInfo[i];

        if ((Tag->Tag[0] == 'R' && Tag->Tag[1] == 'x') ||
            (Tag->Tag[0] == 'N' && Tag->Tag[1] == 'x' && Tag->Tag[2] == 'L' && Tag->Tag[3] == 'p'))
        {
            LONGLONG Blocks = (LONGLONG)Tag->PagedAllocs - Tag->PagedFrees +
                              (LONGLONG)Tag->NonPagedAllocs - Tag->NonPagedFrees;
            LONGLONG Bytes = (LONGLONG)Tag->PagedUsed + (LONGLONG)Tag->NonPagedUsed;

            Sum->Outstanding += Blocks;
            Sum->Bytes += Bytes;
            if (Blocks != 0)
            {
                CHAR One[48];

                StringCbPrintfA(One, sizeof(One), "%c%c%c%c=%I64d/%I64d ", Tag->Tag[0], Tag->Tag[1], Tag->Tag[2],
                                Tag->Tag[3], Blocks, Bytes);
                StringCbCatA(Sum->Detail, sizeof(Sum->Detail), One);
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return TRUE;
}

/* ---------------------------------------------------------------------- */
/* Driver setup                                                           */
/* ---------------------------------------------------------------------- */

static
BOOLEAN
LoopSetUp(
    _Out_ POOL_SUM *Before)
{
    DWORD Error;
    static const WCHAR Root[] = LOCAL_ROOT_NT;

    CreateDirectoryW(LOCAL_ROOT, NULL);
    DeleteTree(LOCAL_ROOT);

    if (!PoolSum(Before))
    {
        trace("SystemPoolTagInformation not available\n");
    }

    Error = KmtLoadDriver(L"RdbssLoop", TRUE);
    ok_eq_int(Error, ERROR_SUCCESS);
    if (Error)
    {
        return FALSE;
    }

    LoopDevice = CreateFileW(LOOPRDR_USER_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    ok(LoopDevice != INVALID_HANDLE_VALUE, "Opening the device failed: %lu\n", GetLastError());
    if (LoopDevice == INVALID_HANDLE_VALUE)
    {
        KmtUnloadDriver();
        return FALSE;
    }

    ok(LoopIoctl(IOCTL_LOOPRDR_SET_ROOT, (PVOID)Root, sizeof(Root), NULL, 0), "SET_ROOT failed: %lu\n", GetLastError());
    ok(LoopIoctl(IOCTL_LOOPRDR_START, NULL, 0, NULL, 0), "START failed: %lu\n", GetLastError());
    LoopOptions(FCB_ALL_CACHE, 0);
    return TRUE;
}

static
VOID
LoopTearDown(
    _In_ POOL_SUM *Before)
{
    LOOPRDR_COUNTERS C;
    POOL_SUM After;
    BOOL Stopped = FALSE;
    ULONG Try;

    /* Structures are finalized by the scavenger (2 s) or by the stop */
    for (Try = 0; Try < 20 && !Stopped; ++Try)
    {
        Stopped = LoopIoctl(IOCTL_LOOPRDR_STOP, NULL, 0, NULL, 0);
        if (!Stopped)
        {
            Sleep(500);
        }
    }
    ok(Stopped, "STOP failed: %lu\n", GetLastError());

    LoopCounters(&C);
    ok_eq_long(C.SrvCalls, 0L);
    ok_eq_long(C.NetRoots, 0L);
    ok_eq_long(C.VNetRoots, 0L);
    ok_eq_long(C.Fcbs, 0L);
    ok_eq_long(C.SrvOpens, 0L);
    ok_eq_long(C.Fobxs, 0L);
    ok_eq_long(C.BackingHandles, 0L);
    ok_eq_long(C.PendingAsync, 0L);
    ok_eq_long(C.LeakedServerLocks, 0L);
    trace("RDBSS counters: reads %ld writes %ld paging r/w %ld/%ld locks %ld unlocks %ld unlock-multiple %ld flushes %ld fsctl %ld ioctl %ld cbs compute/ack %ld/%ld async %ld\n",
          C.Reads, C.Writes, C.PagingReads, C.PagingWrites, C.Locks, C.Unlocks, C.UnlockMultiple, C.Flushes,
          C.FsCtls, C.IoCtls, C.ComputeBufferingState, C.CompleteBufferingState, C.AsyncCompletions);

    CloseHandle(LoopDevice);
    LoopDevice = INVALID_HANDLE_VALUE;
    KmtUnloadDriver();

    if (PoolSum(&After))
    {
        trace("RDBSS pool tags: before load %I64d blocks/%I64d bytes, after unload %I64d blocks/%I64d bytes\n",
              Before->Outstanding, Before->Bytes, After.Outstanding, After.Bytes);
        ok(After.Outstanding == Before->Outstanding,
           "RDBSS pool blocks leaked: %I64d before, %I64d after\n", Before->Outstanding, After.Outstanding);
    }

    DeleteTree(LOCAL_ROOT);
    RemoveDirectoryW(LOCAL_ROOT);
}

/* ---------------------------------------------------------------------- */
/* Create, share modes, directories                                       */
/* ---------------------------------------------------------------------- */

static
VOID
TestCreate(VOID)
{
    WCHAR U[MAX_PATH], L[MAX_PATH];
    HANDLE H1, H2;
    DWORD Error, Written;
    BOOLEAN Unc;

    for (Unc = 0; Unc <= 1; ++Unc)
    {
        PCWSTR Side = Unc ? L"unc" : L"local";

        P(U, Unc, L"create.bin");
        DeleteFileW(U);

        H1 = CreateFileW(U, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
        ok(H1 != INVALID_HANDLE_VALUE, "%ls: CREATE_NEW failed: %lu\n", Side, GetLastError());
        WriteFile(H1, "abc", 3, &Written, NULL);
        CloseHandle(H1);

        H1 = CreateFileW(U, GENERIC_READ, 0, NULL, CREATE_NEW, 0, NULL);
        Error = GetLastError();
        ok(H1 == INVALID_HANDLE_VALUE && Error == ERROR_FILE_EXISTS, "%ls: CREATE_NEW again: %p %lu\n", Side, H1, Error);

        SetLastError(0xdeadbeef);
        H1 = CreateFileW(U, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
        Error = GetLastError();
        ok(H1 != INVALID_HANDLE_VALUE && Error == ERROR_ALREADY_EXISTS, "%ls: OPEN_ALWAYS existing: %p %lu\n", Side, H1, Error);
        ok_eq_ulong(GetFileSize(H1, NULL), 3UL);

        /* Share modes: read-only sharing refuses a writer */
        H2 = CreateFileW(U, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        Error = GetLastError();
        ok(H2 == INVALID_HANDLE_VALUE && Error == ERROR_SHARING_VIOLATION, "%ls: writer vs FILE_SHARE_READ: %p %lu\n", Side, H2, Error);
        H2 = CreateFileW(U, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        ok(H2 != INVALID_HANDLE_VALUE, "%ls: second reader failed: %lu\n", Side, GetLastError());
        CloseHandle(H2);
        CloseHandle(H1);

        /* No sharing at all */
        H1 = CreateFileW(U, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        ok(H1 != INVALID_HANDLE_VALUE, "%ls: exclusive open failed: %lu\n", Side, GetLastError());
        H2 = CreateFileW(U, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        Error = GetLastError();
        ok(H2 == INVALID_HANDLE_VALUE && Error == ERROR_SHARING_VIOLATION, "%ls: open vs share 0: %p %lu\n", Side, H2, Error);
        CloseHandle(H1);

        /* CREATE_ALWAYS and TRUNCATE_EXISTING truncate */
        H1 = CreateFileW(U, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        Error = GetLastError();
        ok(H1 != INVALID_HANDLE_VALUE && Error == ERROR_ALREADY_EXISTS, "%ls: CREATE_ALWAYS: %p %lu\n", Side, H1, Error);
        ok_eq_ulong(GetFileSize(H1, NULL), 0UL);
        WriteFile(H1, "abcdef", 6, &Written, NULL);
        CloseHandle(H1);
        H1 = CreateFileW(U, GENERIC_WRITE, 0, NULL, TRUNCATE_EXISTING, 0, NULL);
        ok(H1 != INVALID_HANDLE_VALUE, "%ls: TRUNCATE_EXISTING failed: %lu\n", Side, GetLastError());
        ok_eq_ulong(GetFileSize(H1, NULL), 0UL);
        CloseHandle(H1);

        /* Missing files and paths */
        H1 = CreateFileW(P(L, Unc, L"missing.bin"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        Error = GetLastError();
        ok(H1 == INVALID_HANDLE_VALUE && Error == ERROR_FILE_NOT_FOUND, "%ls: missing file: %lu\n", Side, Error);
        H1 = CreateFileW(P(L, Unc, L"nodir\\missing.bin"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        Error = GetLastError();
        ok(H1 == INVALID_HANDLE_VALUE && Error == ERROR_PATH_NOT_FOUND, "%ls: missing path: %lu\n", Side, Error);

        /* Directories */
        ok(CreateDirectoryW(P(L, Unc, L"dir"), NULL), "%ls: CreateDirectory failed: %lu\n", Side, GetLastError());
        ok(!CreateDirectoryW(P(L, Unc, L"dir"), NULL) && GetLastError() == ERROR_ALREADY_EXISTS,
           "%ls: CreateDirectory again: %lu\n", Side, GetLastError());
        H1 = CreateFileW(P(L, Unc, L"dir"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, NULL);
        ok(H1 != INVALID_HANDLE_VALUE, "%ls: opening a directory failed: %lu\n", Side, GetLastError());
        CloseHandle(H1);
        H1 = CreateFileW(P(L, Unc, L"dir"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        Error = GetLastError();
        ok(H1 == INVALID_HANDLE_VALUE && Error == ERROR_ACCESS_DENIED, "%ls: directory as file: %lu\n", Side, Error);
        ok(GetFileAttributesW(P(L, Unc, L"dir")) & FILE_ATTRIBUTE_DIRECTORY, "%ls: not a directory\n", Side);
        ok(RemoveDirectoryW(P(L, Unc, L"dir")), "%ls: RemoveDirectory failed: %lu\n", Side, GetLastError());
        ok(DeleteFileW(U), "%ls: DeleteFile failed: %lu\n", Side, GetLastError());
    }
}

/* Relative opens (a RootDirectory handle): RDBSS joins the related file's
 * name and the relative name. Each case must behave as it does locally. */
static
NTSTATUS
RelativeOpen(
    _In_ HANDLE Root,
    _In_ PCWSTR Name,
    _In_ ULONG Disposition,
    _In_ ULONG Options,
    _Out_ PHANDLE Handle)
{
    UNICODE_STRING String;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;

    *Handle = NULL;
    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&Attributes, &String, OBJ_CASE_INSENSITIVE, Root, NULL);
    return NtCreateFile(Handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, Disposition,
                        Options | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

static
VOID
TestRelative(VOID)
{
    static const struct
    {
        PCWSTR Root;        /* opened by path, relative to the share */
        PCWSTR Name;        /* opened relative to Root */
        ULONG Disposition;
        ULONG Options;
    } Cases[] =
    {
        { L"rel",           L"a.bin",       FILE_OPEN,      FILE_NON_DIRECTORY_FILE },
        { L"rel",           L"sub\\b.bin",  FILE_OPEN,      FILE_NON_DIRECTORY_FILE },
        { L"rel",           L"c.bin",       FILE_CREATE,    FILE_NON_DIRECTORY_FILE },
        { L"rel",           L"",            FILE_OPEN,      FILE_DIRECTORY_FILE },
        { L"rel",           L"missing.bin", FILE_OPEN,      FILE_NON_DIRECTORY_FILE },
        { L"rel",           L"\\a.bin",     FILE_OPEN,      FILE_NON_DIRECTORY_FILE },
        { L"rel\\sub",      L"b.bin",       FILE_OPEN,      FILE_NON_DIRECTORY_FILE },
        { L"",              L"rel\\a.bin",  FILE_OPEN,      FILE_NON_DIRECTORY_FILE },
        { L"rel\\a.bin",    L"x.bin",       FILE_OPEN,      FILE_NON_DIRECTORY_FILE },
    };
    NTSTATUS Statuses[2][ARRAYSIZE(Cases)];
    WCHAR Path[MAX_PATH];
    BOOLEAN Unc;
    ULONG i;
    DWORD Written;
    HANDLE File;

    for (Unc = 0; Unc <= 1; ++Unc)
    {
        PCWSTR Side = Unc ? L"unc" : L"local";

        CreateDirectoryW(P(Path, Unc, L"rel"), NULL);
        CreateDirectoryW(P(Path, Unc, L"rel\\sub"), NULL);
        File = CreateFileW(P(Path, Unc, L"rel\\a.bin"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ok(File != INVALID_HANDLE_VALUE, "%ls: creating rel\\a.bin failed: %lu\n", Side, GetLastError());
        WriteFile(File, "rel-a", 5, &Written, NULL);
        CloseHandle(File);
        File = CreateFileW(P(Path, Unc, L"rel\\sub\\b.bin"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        WriteFile(File, "rel-b", 5, &Written, NULL);
        CloseHandle(File);

        for (i = 0; i < ARRAYSIZE(Cases); ++i)
        {
            HANDLE Root, Handle;
            NTSTATUS Status;

            Root = CreateFileW(Cases[i].Root[0] ? P(Path, Unc, Cases[i].Root) : (Unc ? UNC_ROOT L"\\" : LOCAL_ROOT L"\\"),
                               GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                               OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
            ok(Root != INVALID_HANDLE_VALUE, "%ls: case %lu: opening the root %ls failed: %lu\n",
               Side, i, Cases[i].Root, GetLastError());
            if (Root == INVALID_HANDLE_VALUE)
            {
                Statuses[Unc][i] = STATUS_UNSUCCESSFUL;
                continue;
            }

            Status = RelativeOpen(Root, Cases[i].Name, Cases[i].Disposition, Cases[i].Options, &Handle);
            Statuses[Unc][i] = Status;
            if (NT_SUCCESS(Status))
            {
                CHAR Data[8] = { 0 };
                DWORD Read = 0;

                /* The right file was opened */
                if (Cases[i].Options & FILE_NON_DIRECTORY_FILE)
                {
                    ReadFile(Handle, Data, sizeof(Data), &Read, NULL);
                    if (Cases[i].Disposition == FILE_OPEN)
                    {
                        ok(Read == 5 && !memcmp(Data, wcsstr(Cases[i].Name, L"b.bin") ? "rel-b" : "rel-a", 5),
                           "%ls: case %lu: read %lu bytes '%.5s'\n", Side, i, Read, Data);
                    }
                }
                NtClose(Handle);
            }
            CloseHandle(Root);
        }

        DeleteFileW(P(Path, Unc, L"rel\\c.bin"));
        DeleteFileW(P(Path, Unc, L"rel\\sub\\b.bin"));
        DeleteFileW(P(Path, Unc, L"rel\\a.bin"));
        RemoveDirectoryW(P(Path, Unc, L"rel\\sub"));
        ok(RemoveDirectoryW(P(Path, Unc, L"rel")), "%ls: RemoveDirectory rel failed: %lu\n", Side, GetLastError());
    }

    for (i = 0; i < ARRAYSIZE(Cases); ++i)
    {
        trace("relative open %lu (%ls + %ls): local %lx, unc %lx\n", i, Cases[i].Root, Cases[i].Name,
              Statuses[0][i], Statuses[1][i]);
        ok(Statuses[1][i] == Statuses[0][i], "relative open %lu (%ls + %ls): local %lx, unc %lx\n",
           i, Cases[i].Root, Cases[i].Name, Statuses[0][i], Statuses[1][i]);
    }
}

/* CopyFile of files above kernel32's buffered-copy limit (4 MB) both ways:
 * the copy reads its source with FILE_FLAG_NO_BUFFERING, so a copy from the
 * share is a run of non-cached reads that flush the cache first, and a
 * buffered read of a file just written by a copy follows. Done with the
 * redirector caching and without it (as a mini-redirector that disables
 * local buffering runs). */
static
VOID
TestCopyFile(VOID)
{
    static const ULONG Size = 24 * 1024 * 1024 + 4321;
    WCHAR L[MAX_PATH], U[MAX_PATH], L2[MAX_PATH];
    PUCHAR Data, Back;
    HANDLE File;
    DWORD Written, Read;
    ULONG Round;

    Data = HeapAlloc(GetProcessHeap(), 0, Size);
    Back = HeapAlloc(GetProcessHeap(), 0, Size);
    if (Data == NULL || Back == NULL)
    {
        ok(0, "no memory for the copy test\n");
        goto Out;
    }

    for (Round = 0; Round < 2; ++Round)
    {
        LoopOptions(Round == 0 ? FCB_ALL_CACHE : 0, 0);
        Fill(Data, Size, 0x5eed + Round);

        File = CreateFileW(P(L, FALSE, L"copysrc.bin"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ok(File != INVALID_HANDLE_VALUE, "round %lu: creating the source failed: %lu\n", Round, GetLastError());
        ok(WriteFile(File, Data, Size, &Written, NULL) && Written == Size, "round %lu: writing the source failed\n", Round);
        CloseHandle(File);

        /* Local to share, then the share's copy read back buffered */
        ok(CopyFileW(L, P(U, TRUE, L"copy1.bin"), FALSE), "round %lu: copy to the share failed: %lu\n", Round, GetLastError());
        ok(SameContent(L"copy1.bin", Data, Size), "round %lu: copy to the share differs locally\n", Round);
        File = CreateFileW(U, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        ok(File != INVALID_HANDLE_VALUE, "round %lu: reopening the copy failed: %lu\n", Round, GetLastError());
        Read = 0;
        ok(ReadFile(File, Back, Size, &Read, NULL) && Read == Size && !memcmp(Back, Data, Size),
           "round %lu: buffered read of the copy: %lu bytes\n", Round, Read);
        CloseHandle(File);

        /* Share to local: non-cached reads of the share */
        ok(CopyFileW(U, P(L2, FALSE, L"copy2.bin"), FALSE), "round %lu: copy from the share failed: %lu\n", Round, GetLastError());
        ok(SameContent(L"copy2.bin", Data, Size), "round %lu: copy from the share differs\n", Round);

        /* Share to share */
        ok(CopyFileW(U, P(L2, TRUE, L"copy3.bin"), FALSE), "round %lu: copy within the share failed: %lu\n", Round, GetLastError());
        ok(SameContent(L"copy3.bin", Data, Size), "round %lu: copy within the share differs\n", Round);

        ok(DeleteFileW(P(U, TRUE, L"copy3.bin")), "round %lu: delete copy3 failed: %lu\n", Round, GetLastError());
        ok(DeleteFileW(P(U, TRUE, L"copy1.bin")), "round %lu: delete copy1 failed: %lu\n", Round, GetLastError());
        DeleteFileW(P(L2, FALSE, L"copy2.bin"));
        DeleteFileW(L);
    }
    LoopOptions(FCB_ALL_CACHE, 0);

Out:
    if (Data != NULL)
        HeapFree(GetProcessHeap(), 0, Data);
    if (Back != NULL)
        HeapFree(GetProcessHeap(), 0, Back);
}

/* ---------------------------------------------------------------------- */
/* Read/write                                                             */
/* ---------------------------------------------------------------------- */

static const DWORD Sizes[] = { 1, 511, 4096, 65535, 65536, 65537, 1048575, 1048576, 1048577, 3 * 1048576 + 123 };

static
VOID
TestReadWrite(VOID)
{
    WCHAR U[MAX_PATH];
    PUCHAR Data, Back;
    HANDLE H;
    DWORD i, Done;
    const DWORD Max = 3 * 1048576 + 123 + 4096;
    LARGE_INTEGER Size;
    LOOPRDR_COUNTERS C0, C1;

    Data = VirtualAlloc(NULL, Max, MEM_COMMIT, PAGE_READWRITE);
    Back = VirtualAlloc(NULL, Max, MEM_COMMIT, PAGE_READWRITE);
    if (!Data || !Back)
    {
        skip(0, "No memory\n");
        return;
    }

    LoopCounters(&C0);

    /* Cached: write, read back through the redirector, compare locally */
    for (i = 0; i < RTL_NUMBER_OF(Sizes); ++i)
    {
        Fill(Data, Sizes[i], i + 1);
        H = CreateFileW(P(U, TRUE, L"rw.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ok(H != INVALID_HANDLE_VALUE, "create failed: %lu\n", GetLastError());
        if (H == INVALID_HANDLE_VALUE)
            continue;
        ok(WriteFile(H, Data, Sizes[i], &Done, NULL) && Done == Sizes[i], "write %lu: %lu (%lu)\n", Sizes[i], Done, GetLastError());
        SetFilePointer(H, 0, NULL, FILE_BEGIN);
        RtlZeroMemory(Back, Sizes[i] + 16);
        ok(ReadFile(H, Back, Sizes[i] + 16, &Done, NULL) && Done == Sizes[i], "read %lu: %lu (%lu)\n", Sizes[i], Done, GetLastError());
        ok(memcmp(Data, Back, Sizes[i]) == 0, "cached data differs at size %lu\n", Sizes[i]);
        /* Reading at the end of file */
        ok(ReadFile(H, Back, 16, &Done, NULL) && Done == 0, "read at EOF: %lu\n", Done);
        CloseHandle(H);
        ok(SameContent(L"rw.bin", Data, Sizes[i]), "local copy differs at size %lu\n", Sizes[i]);
    }

    /* Non-cached, sector-sized */
    for (i = 0; i < RTL_NUMBER_OF(Sizes); ++i)
    {
        DWORD Length = (Sizes[i] + 511) & ~511;

        Fill(Data, Length, 100 + i);
        H = CreateFileW(P(U, TRUE, L"nc.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
        ok(H != INVALID_HANDLE_VALUE, "create nc failed: %lu\n", GetLastError());
        if (H == INVALID_HANDLE_VALUE)
            continue;
        ok(WriteFile(H, Data, Length, &Done, NULL) && Done == Length, "nc write %lu: %lu (%lu)\n", Length, Done, GetLastError());
        SetFilePointer(H, 0, NULL, FILE_BEGIN);
        ok(ReadFile(H, Back, Length, &Done, NULL) && Done == Length, "nc read %lu: %lu (%lu)\n", Length, Done, GetLastError());
        ok(memcmp(Data, Back, Length) == 0, "non-cached data differs at size %lu\n", Length);
        CloseHandle(H);
        ok(SameContent(L"nc.bin", Data, Length), "local nc copy differs at size %lu\n", Length);
    }

    /* Extend, truncate, append */
    H = CreateFileW(P(U, TRUE, L"size.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create size failed: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        Fill(Data, 70000, 7);
        WriteFile(H, Data, 70000, &Done, NULL);
        Size.QuadPart = 2 * 1048576 + 5;
        ok(SetFilePointerEx(H, Size, NULL, FILE_BEGIN) && SetEndOfFile(H), "extend failed: %lu\n", GetLastError());
        ok(GetFileSizeEx(H, &Size) && Size.QuadPart == 2 * 1048576 + 5, "size after extend %I64d\n", Size.QuadPart);
        SetFilePointer(H, 69990, NULL, FILE_BEGIN);
        ok(ReadFile(H, Back, 20, &Done, NULL) && Done == 20, "read across old EOF: %lu\n", Done);
        ok(memcmp(Back, Data + 69990, 10) == 0 && Back[10] == 0 && Back[19] == 0, "extended part not zero\n");
        Size.QuadPart = 1000;
        ok(SetFilePointerEx(H, Size, NULL, FILE_BEGIN) && SetEndOfFile(H), "truncate failed: %lu\n", GetLastError());
        ok(GetFileSizeEx(H, &Size) && Size.QuadPart == 1000, "size after truncate %I64d\n", Size.QuadPart);
        CloseHandle(H);
        ok(SameContent(L"size.bin", Data, 1000), "local copy after truncate differs\n");
    }

    H = CreateFileW(P(U, TRUE, L"size.bin"), FILE_APPEND_DATA | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "append open failed: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        ok(WriteFile(H, Data + 1000, 500, &Done, NULL) && Done == 500, "append failed: %lu\n", GetLastError());
        CloseHandle(H);
        ok(SameContent(L"size.bin", Data, 1500), "local copy after append differs\n");
    }

    /* Memory mapped: paging reads and writes */
    H = CreateFileW(P(U, TRUE, L"map.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create map failed: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        HANDLE Section;
        PUCHAR View;
        const DWORD MapSize = 256 * 1024 + 100;

        Fill(Data, MapSize, 33);
        WriteFile(H, Data, MapSize, &Done, NULL);
        FlushFileBuffers(H);
        Section = CreateFileMappingW(H, NULL, PAGE_READWRITE, 0, 0, NULL);
        ok(Section != NULL, "CreateFileMapping failed: %lu\n", GetLastError());
        if (Section != NULL)
        {
            View = MapViewOfFile(Section, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
            ok(View != NULL, "MapViewOfFile failed: %lu\n", GetLastError());
            if (View != NULL)
            {
                ok(memcmp(View, Data, MapSize) == 0, "mapped view differs\n");
                Fill(View + 4096, 8192, 44);
                Fill(Data + 4096, 8192, 44);
                ok(FlushViewOfFile(View, 0), "FlushViewOfFile failed: %lu\n", GetLastError());
                UnmapViewOfFile(View);
            }
            CloseHandle(Section);
        }
        /* Read through the handle: the cache and the view are one */
        SetFilePointer(H, 0, NULL, FILE_BEGIN);
        ok(ReadFile(H, Back, MapSize, &Done, NULL) && Done == MapSize, "read after map: %lu\n", Done);
        ok(memcmp(Back, Data, MapSize) == 0, "handle read differs from mapped write\n");
        CloseHandle(H);
        ok(SameContent(L"map.bin", Data, MapSize), "local copy differs from mapped write\n");
    }

    /* Asynchronous I/O completed from a worker (RxLowIoCompletion) */
    LoopOptions(FCB_ALL_CACHE, LOOPRDR_OPT_ASYNC_LOWIO);
    H = CreateFileW(P(U, TRUE, L"async.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create async failed: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        OVERLAPPED Ov;
        BOOL Ret;

        Fill(Data, 65536, 55);
        RtlZeroMemory(&Ov, sizeof(Ov));
        Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        Ret = WriteFile(H, Data, 65536, NULL, &Ov);
        ok(Ret || GetLastError() == ERROR_IO_PENDING, "async write: %lu\n", GetLastError());
        ok(GetOverlappedResult(H, &Ov, &Done, TRUE) && Done == 65536, "async write result: %lu (%lu)\n", Done, GetLastError());
        ResetEvent(Ov.hEvent);
        Ov.Offset = 0;
        Ret = ReadFile(H, Back, 65536, NULL, &Ov);
        ok(Ret || GetLastError() == ERROR_IO_PENDING, "async read: %lu\n", GetLastError());
        ok(GetOverlappedResult(H, &Ov, &Done, TRUE) && Done == 65536, "async read result: %lu (%lu)\n", Done, GetLastError());
        ok(memcmp(Data, Back, 65536) == 0, "async data differs\n");

        /* Close while a read may still be in flight */
        ResetEvent(Ov.hEvent);
        Ov.Offset = 0;
        Ret = ReadFile(H, Back, 65536, NULL, &Ov);
        CloseHandle(H);
        if (!Ret)
        {
            WaitForSingleObject(Ov.hEvent, 10000);
        }
        CloseHandle(Ov.hEvent);
    }
    LoopOptions(FCB_ALL_CACHE, 0);

    LoopCounters(&C1);
    ok(C1.Writes > C0.Writes && C1.Reads > C0.Reads, "no non-paging I/O reached the mini-redirector\n");
    ok(C1.PagingWrites > C0.PagingWrites, "no paging write reached the mini-redirector\n");
    ok(C1.AsyncCompletions > C0.AsyncCompletions, "no asynchronous completion\n");
    trace("paging reads %ld, paging writes %ld, async completions %ld\n",
          C1.PagingReads - C0.PagingReads, C1.PagingWrites - C0.PagingWrites, C1.AsyncCompletions - C0.AsyncCompletions);

    VirtualFree(Data, 0, MEM_RELEASE);
    VirtualFree(Back, 0, MEM_RELEASE);
}

/* ---------------------------------------------------------------------- */
/* Information classes                                                    */
/* ---------------------------------------------------------------------- */

static
NTSTATUS
SetInfo(
    _In_ HANDLE File,
    _In_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS Class)
{
    IO_STATUS_BLOCK Iosb;

    return NtSetInformationFile(File, &Iosb, Buffer, Length, Class);
}

static
NTSTATUS
QueryInfo(
    _In_ HANDLE File,
    _Out_ PVOID Buffer,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS Class)
{
    IO_STATUS_BLOCK Iosb;

    return NtQueryInformationFile(File, &Iosb, Buffer, Length, Class);
}

static
VOID
TestInformation(VOID)
{
    WCHAR U[MAX_PATH], L[MAX_PATH];
    HANDLE H;
    DWORD Done;
    BY_HANDLE_FILE_INFORMATION Info;
    FILE_BASIC_INFORMATION Basic;
    FILE_STANDARD_INFORMATION Standard;
    FILE_ALLOCATION_INFORMATION Allocation;
    FILE_END_OF_FILE_INFORMATION Eof;
    FILE_POSITION_INFORMATION Position;
    FILE_INTERNAL_INFORMATION Internal;
    FILE_DISPOSITION_INFORMATION Disposition;
    FILETIME Time;
    NTSTATUS Status;
    UCHAR NameBuffer[sizeof(FILE_NAME_INFORMATION) + MAX_PATH * sizeof(WCHAR)];
    PFILE_NAME_INFORMATION NameInfo = (PFILE_NAME_INFORMATION)NameBuffer;
    UCHAR AllBuffer[1024]; /* FILE_ALL_INFORMATION and the name */
    LARGE_INTEGER Size;

    H = CreateFileW(P(U, TRUE, L"info.txt"), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                    NULL, CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create failed: %lu\n", GetLastError());
    if (H == INVALID_HANDLE_VALUE)
        return;
    WriteFile(H, "0123456789", 10, &Done, NULL);

    /* FileAllInformation: basic, standard, internal, EA, position, name */
    ok(GetFileInformationByHandle(H, &Info), "GetFileInformationByHandle failed: %lu\n", GetLastError());
    ok_eq_ulong(Info.nFileSizeLow, 10UL);
    ok_eq_ulong(Info.nNumberOfLinks, 1UL);
    Status = QueryInfo(H, AllBuffer, sizeof(AllBuffer), FileAllInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    Status = QueryInfo(H, &Internal, sizeof(Internal), FileInternalInformation);
    ok(NT_SUCCESS(Status) && Internal.IndexNumber.QuadPart != 0, "internal: %lx\n", Status);

    Status = QueryInfo(H, &Standard, sizeof(Standard), FileStandardInformation);
    ok(NT_SUCCESS(Status) && Standard.EndOfFile.QuadPart == 10 && !Standard.Directory && !Standard.DeletePending,
       "standard info: %lx %I64d\n", Status, Standard.EndOfFile.QuadPart);
    Status = QueryInfo(H, NameInfo, sizeof(NameBuffer), FileNameInformation);
    ok(NT_SUCCESS(Status), "name: %lx\n", Status);
    if (NT_SUCCESS(Status))
    {
        NameInfo->FileName[min(NameInfo->FileNameLength / sizeof(WCHAR), MAX_PATH - 1)] = 0;
        ok(wcsstr(NameInfo->FileName, L"info.txt") != NULL, "name is %ls\n", NameInfo->FileName);
    }

    Status = QueryInfo(H, &Position, sizeof(Position), FilePositionInformation);
    ok(NT_SUCCESS(Status) && Position.CurrentByteOffset.QuadPart == 10, "position %lx %I64d\n", Status, Position.CurrentByteOffset.QuadPart);
    Position.CurrentByteOffset.QuadPart = 3;
    Status = SetInfo(H, &Position, sizeof(Position), FilePositionInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok_eq_ulong(SetFilePointer(H, 0, NULL, FILE_CURRENT), 3UL);

    /* Basic: times */
    Status = QueryInfo(H, &Basic, sizeof(Basic), FileBasicInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /* End of file and allocation through the information classes */
    Eof.EndOfFile.QuadPart = 300000;
    Status = SetInfo(H, &Eof, sizeof(Eof), FileEndOfFileInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(GetFileSizeEx(H, &Size) && Size.QuadPart == 300000, "size %I64d\n", Size.QuadPart);
    Allocation.AllocationSize.QuadPart = 4;
    Status = SetInfo(H, &Allocation, sizeof(Allocation), FileAllocationInformation);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ok(GetFileSizeEx(H, &Size) && Size.QuadPart == 4, "size after allocation %I64d\n", Size.QuadPart);
    CloseHandle(H);

    /* A last write time set through a handle reaches the share (an open
     * that does not write, so that the share's own update on close does not
     * interfere) */
    H = CreateFileW(P(U, TRUE, L"info.txt"), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "attribute open failed: %lu\n", GetLastError());
    Time.dwLowDateTime = 0x12345678;
    Time.dwHighDateTime = 0x01d00000;
    ok(SetFileTime(H, NULL, NULL, &Time), "SetFileTime failed: %lu\n", GetLastError());
    CloseHandle(H);
    ok(SameContent(L"info.txt", (const UCHAR *)"0123", 4), "local copy after allocation differs\n");

    /* The last write time set through the handle reached the backing file */
    H = CreateFileW(P(L, FALSE, L"info.txt"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (H != INVALID_HANDLE_VALUE)
    {
        FILETIME Got;

        FILETIME Expected = Time;
        HANDLE Ref;

        GetFileTime(H, NULL, NULL, &Got);
        CloseHandle(H);

        /* What the share's file system makes of that time (FAT keeps 2 s) */
        Ref = CreateFileW(P(L, FALSE, L"timeref.txt"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (Ref != INVALID_HANDLE_VALUE)
        {
            SetFileTime(Ref, NULL, NULL, &Time);
            CloseHandle(Ref);
            Ref = CreateFileW(P(L, FALSE, L"timeref.txt"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
            GetFileTime(Ref, NULL, NULL, &Expected);
            CloseHandle(Ref);
            DeleteFileW(P(L, FALSE, L"timeref.txt"));
        }
        ok(CompareFileTime(&Got, &Expected) == 0, "last write time not set: %08lx%08lx, expected %08lx%08lx\n",
           Got.dwHighDateTime, Got.dwLowDateTime, Expected.dwHighDateTime, Expected.dwLowDateTime);
    }

    ok(SetFileAttributesW(P(U, TRUE, L"info.txt"), FILE_ATTRIBUTE_HIDDEN), "SetFileAttributes: %lu\n", GetLastError());
    ok(GetFileAttributesW(P(L, FALSE, L"info.txt")) & FILE_ATTRIBUTE_HIDDEN, "attribute did not reach the share\n");
    SetFileAttributesW(P(U, TRUE, L"info.txt"), FILE_ATTRIBUTE_NORMAL);

    /* Rename within the share, replace, delete */
    ok(MoveFileW(P(U, TRUE, L"info.txt"), P(L, TRUE, L"renamed.txt")), "MoveFile failed: %lu\n", GetLastError());
    ok(WaitExists(L"renamed.txt", TRUE, 0) && WaitExists(L"info.txt", FALSE, 0), "rename not seen locally\n");
    H = CreateFileW(P(U, TRUE, L"other.txt"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CloseHandle(H);
    ok(!MoveFileExW(P(U, TRUE, L"renamed.txt"), P(L, TRUE, L"other.txt"), 0) && GetLastError() == ERROR_ALREADY_EXISTS,
       "rename onto existing: %lu\n", GetLastError());
    ok(MoveFileExW(P(U, TRUE, L"renamed.txt"), P(L, TRUE, L"other.txt"), MOVEFILE_REPLACE_EXISTING),
       "rename replacing: %lu\n", GetLastError());
    ok(SameContent(L"other.txt", (const UCHAR *)"0123", 4), "replaced file content wrong\n");
    ok(CreateDirectoryW(P(U, TRUE, L"sub"), NULL), "CreateDirectory: %lu\n", GetLastError());
    ok(MoveFileW(P(U, TRUE, L"other.txt"), P(L, TRUE, L"sub\\moved.txt")), "move into subdirectory: %lu\n", GetLastError());
    ok(WaitExists(L"sub\\moved.txt", TRUE, 0), "move not seen locally\n");
    ok(DeleteFileW(P(U, TRUE, L"sub\\moved.txt")), "DeleteFile: %lu\n", GetLastError());
    ok(WaitExists(L"sub\\moved.txt", FALSE, 5000), "delete not seen locally\n");
    ok(RemoveDirectoryW(P(U, TRUE, L"sub")), "RemoveDirectory: %lu\n", GetLastError());

    /* Delete on close, with a second handle that allows it */
    H = CreateFileW(P(U, TRUE, L"doc.txt"), GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                    CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    ok(H != INVALID_HANDLE_VALUE, "delete-on-close create: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        HANDLE H2;

        WriteFile(H, "x", 1, &Done, NULL);
        H2 = CreateFileW(P(U, TRUE, L"doc.txt"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, 0, NULL);
        ok(H2 != INVALID_HANDLE_VALUE, "second open of a delete-on-close file: %lu\n", GetLastError());
        CloseHandle(H);
        if (H2 != INVALID_HANDLE_VALUE)
        {
            CHAR Byte;

            /* The other handle keeps working until it is closed */
            ok(ReadFile(H2, &Byte, 1, &Done, NULL), "read on the remaining handle: %lu\n", GetLastError());
            CloseHandle(H2);
        }
        ok(WaitExists(L"doc.txt", FALSE, 5000), "delete-on-close did not delete\n");
    }

    /* Disposition through the information class */
    H = CreateFileW(P(U, TRUE, L"disp.txt"), GENERIC_WRITE | DELETE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (H != INVALID_HANDLE_VALUE)
    {
        Disposition.DeleteFile = TRUE;
        Status = SetInfo(H, &Disposition, sizeof(Disposition), FileDispositionInformation);
        ok_eq_hex(Status, STATUS_SUCCESS);
        Status = QueryInfo(H, &Standard, sizeof(Standard), FileStandardInformation);
        ok(NT_SUCCESS(Status) && Standard.DeletePending, "delete not pending: %lx\n", Status);
        CloseHandle(H);
        ok(WaitExists(L"disp.txt", FALSE, 5000), "disposition did not delete\n");
    }
}

/* ---------------------------------------------------------------------- */
/* Directory queries                                                      */
/* ---------------------------------------------------------------------- */

static
ULONG
CountFind(
    _In_ BOOLEAN Unc,
    _In_ PCWSTR Pattern,
    _Out_opt_ PULONG Hash)
{
    WCHAR Path[MAX_PATH];
    WIN32_FIND_DATAW Data;
    HANDLE Find;
    ULONG Count = 0, Sum = 0;

    Find = FindFirstFileW(P(Path, Unc, Pattern), &Data);
    if (Find != INVALID_HANDLE_VALUE)
    {
        do
        {
            PWCHAR c;

            ++Count;
            for (c = Data.cFileName; *c; ++c)
            {
                Sum += towlower(*c) * (ULONG)(c - Data.cFileName + 1);
            }
            Sum += Data.nFileSizeLow;
        } while (FindNextFileW(Find, &Data));
        FindClose(Find);
    }
    if (Hash)
        *Hash = Sum;
    return Count;
}

static
VOID
TestDirectory(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE H;
    ULONG i, LocalCount, UncCount, LocalHash, UncHash;
    static const PCWSTR Patterns[] = { L"dq\\*", L"dq\\*.txt", L"dq\\f?le1*", L"dq\\file17.txt", L"dq\\none*", L"dq\\*.*" };
    static const FILE_INFORMATION_CLASS Classes[] = { FileDirectoryInformation, FileFullDirectoryInformation,
                                                      FileBothDirectoryInformation, FileNamesInformation,
                                                      FileIdBothDirectoryInformation };
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    UCHAR Buffer[4096];
    DWORD Done;

    CreateDirectoryW(P(U, TRUE, L"dq"), NULL);
    for (i = 0; i < 40; ++i)
    {
        WCHAR Name[64];

        StringCchPrintfW(Name, 64, i % 2 ? L"dq\\file%lu.txt" : L"dq\\file%lu.dat", i);
        H = CreateFileW(P(U, TRUE, Name), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (H != INVALID_HANDLE_VALUE)
        {
            WriteFile(H, Buffer, i * 3, &Done, NULL);
            CloseHandle(H);
        }
    }
    CreateDirectoryW(P(U, TRUE, L"dq\\subdir"), NULL);

    for (i = 0; i < RTL_NUMBER_OF(Patterns); ++i)
    {
        LocalCount = CountFind(FALSE, Patterns[i], &LocalHash);
        UncCount = CountFind(TRUE, Patterns[i], &UncHash);
        ok(LocalCount == UncCount && LocalHash == UncHash, "%ls: local %lu (%lx), unc %lu (%lx)\n",
           Patterns[i], LocalCount, LocalHash, UncCount, UncHash);
    }

    /* Classes, restart and single entry, with the native call */
    H = CreateFileW(P(U, TRUE, L"dq"), FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    ok(H != INVALID_HANDLE_VALUE, "directory open: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        for (i = 0; i < RTL_NUMBER_OF(Classes); ++i)
        {
            ULONG Entries = 0;
            BOOLEAN Restart = TRUE;

            for (;;)
            {
                Status = NtQueryDirectoryFile(H, NULL, NULL, NULL, &Iosb, Buffer, sizeof(Buffer), Classes[i],
                                              FALSE, NULL, Restart);
                Restart = FALSE;
                if (Status == STATUS_NO_MORE_FILES)
                    break;
                ok(NT_SUCCESS(Status), "class %d: %lx\n", Classes[i], Status);
                if (!NT_SUCCESS(Status))
                    break;
                {
                    PUCHAR Entry = Buffer;
                    for (;;)
                    {
                        ULONG Next = *(PULONG)Entry;
                        ++Entries;
                        if (Next == 0)
                            break;
                        Entry += Next;
                    }
                }
            }
            ok_eq_ulong(Entries, 43UL); /* 40 files, subdir, . and .. */
        }

        Status = NtQueryDirectoryFile(H, NULL, NULL, NULL, &Iosb, Buffer, sizeof(Buffer), FileNamesInformation,
                                      TRUE, NULL, TRUE);
        ok(NT_SUCCESS(Status) && *(PULONG)Buffer == 0, "single entry: %lx\n", Status);
        CloseHandle(H);
    }
}

/* ---------------------------------------------------------------------- */
/* Volume, flush, security, EAs, controls                                 */
/* ---------------------------------------------------------------------- */

static
VOID
TestVolumeFlushSecurity(VOID)
{
    WCHAR U[MAX_PATH], Fs[64];
    HANDLE H;
    DWORD Serial, MaxLen, Flags, Done, Needed;
    ULARGE_INTEGER Free, Total;
    IO_STATUS_BLOCK Iosb;
    FILE_FS_DEVICE_INFORMATION Device;
    NTSTATUS Status;
    UCHAR Sd[4096];
    UCHAR Pattern[8192];
    LOOPRDR_COUNTERS C0, C1;

    /* The steps of GetVolumeInformation, one by one */
    {
        UNICODE_STRING Root = RTL_CONSTANT_STRING(L"\\??\\UNC\\" LOOPRDR_SERVER L"\\" LOOPRDR_SHARE L"\\");
        OBJECT_ATTRIBUTES Attributes;
        HANDLE V;
        UCHAR Info[600];

        InitializeObjectAttributes(&Attributes, &Root, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = NtOpenFile(&V, SYNCHRONIZE, &Attributes, &Iosb, 0,
                            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Status = NtQueryInformationFile(V, &Iosb, Info, sizeof(Info), FileNameInformation);
            ok_eq_hex(Status, STATUS_SUCCESS);
            if (NT_SUCCESS(Status))
            {
                PFILE_NAME_INFORMATION Name = (PFILE_NAME_INFORMATION)Info;
                Name->FileName[min(Name->FileNameLength / sizeof(WCHAR), 200)] = 0;
                ok(wcscmp(Name->FileName, L"\\" LOOPRDR_SERVER L"\\" LOOPRDR_SHARE L"\\") == 0,
                   "share root name: '%ls'\n", Name->FileName);
            }
            Status = NtQueryVolumeInformationFile(V, &Iosb, Info, sizeof(Info), FileFsVolumeInformation);
            ok_eq_hex(Status, STATUS_SUCCESS);
            Status = NtQueryVolumeInformationFile(V, &Iosb, Info, sizeof(Info), FileFsAttributeInformation);
            ok_eq_hex(Status, STATUS_SUCCESS);
            NtClose(V);
        }
    }

    ok_eq_ulong(GetDriveTypeW(UNC_ROOT L"\\"), (ULONG)DRIVE_REMOTE);
    /* kernel32 checks that a root path is a symbolic link object, which a
     * UNC share root is not: reported, the native steps above are the test */
    if (!GetVolumeInformationW(UNC_ROOT L"\\", NULL, 0, &Serial, &MaxLen, &Flags, Fs, 64))
        trace("GetVolumeInformation on the share root: %lu (kernel32)\n", GetLastError());
    ok(GetDiskFreeSpaceExW(UNC_ROOT L"\\", &Free, &Total, NULL) && Total.QuadPart != 0, "GetDiskFreeSpaceEx: %lu\n", GetLastError());

    LoopCounters(&C0);
    H = CreateFileW(P(U, TRUE, L"flush.bin"), GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                    FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (H == INVALID_HANDLE_VALUE)
        return;

    Status = NtQueryVolumeInformationFile(H, &Iosb, &Device, sizeof(Device), FileFsDeviceInformation);
    ok(NT_SUCCESS(Status) && (Device.Characteristics & FILE_REMOTE_DEVICE), "device info %lx %lx\n", Status, Device.Characteristics);

    /* Flush: the data is in the share while the handle stays open */
    Fill(Pattern, sizeof(Pattern), 9);
    WriteFile(H, Pattern, sizeof(Pattern), &Done, NULL);
    ok(FlushFileBuffers(H), "FlushFileBuffers: %lu\n", GetLastError());
    ok(SameContent(L"flush.bin", Pattern, sizeof(Pattern)), "flushed data not in the share\n");

    /* Security: query (short buffer too), set back the same descriptor */
    ok(!GetFileSecurityW(U, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Sd, 8, &Needed) &&
       GetLastError() == ERROR_INSUFFICIENT_BUFFER && Needed > 8, "short security buffer: %lu needed %lu\n", GetLastError(), Needed);
    ok(GetFileSecurityW(U, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, Sd, sizeof(Sd), &Needed),
       "GetFileSecurity: %lu\n", GetLastError());
    ok(SetKernelObjectSecurity(H, DACL_SECURITY_INFORMATION, (PSECURITY_DESCRIPTOR)Sd), "SetKernelObjectSecurity: %lu\n", GetLastError());

    /* FSCTL and IOCTL pass-through */
    {
        CHAR In[] = "abcdef", Out[16] = { 0 };

        IO_STATUS_BLOCK Iosb;
        NTSTATUS Status;

        /* Codes of a network file system device type: kernel32 would send
         * them as IOCTLs, so use the native call for the FSCTL path */
        Status = NtFsControlFile(H, NULL, NULL, NULL, &Iosb, FSCTL_LOOPRDR_ECHO, In, 6, Out, sizeof(Out));
        ok(NT_SUCCESS(Status) && Iosb.Information == 6 && !memcmp(Out, "fedcba", 6),
           "FSCTL echo: %lx %Iu '%s'\n", Status, Iosb.Information, Out);
        RtlZeroMemory(Out, sizeof(Out));
        Status = NtFsControlFile(H, NULL, NULL, NULL, &Iosb, FSCTL_LOOPRDR_ECHO_DIRECT, In, 6, Out, 6);
        ok(NT_SUCCESS(Status) && Iosb.Information == 6 && !memcmp(Out, "fedcba", 6),
           "FSCTL direct echo: %lx %Iu\n", Status, Iosb.Information);
        RtlZeroMemory(Out, sizeof(Out));
        ok(DeviceIoControl(H, IOCTL_LOOPRDR_FILE_ECHO, In, 6, Out, sizeof(Out), &Done, NULL) && Done == 6 &&
           !memcmp(Out, "fedcba", 6), "IOCTL echo: %lu %lu\n", GetLastError(), Done);
    }

    /* Change notification: not provided by this mini-redirector */
    {
        HANDLE Dir;
        UCHAR Notify[512];

        Dir = CreateFileW(UNC_ROOT, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                          OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        ok(Dir != INVALID_HANDLE_VALUE, "share root open: %lu\n", GetLastError());
        if (Dir != INVALID_HANDLE_VALUE)
        {
            ok(!ReadDirectoryChangesW(Dir, Notify, sizeof(Notify), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &Done, NULL, NULL),
               "change notification unexpectedly worked\n");
            CloseHandle(Dir);
        }
    }

    CloseHandle(H);
    LoopCounters(&C1);
    ok(C1.Flushes > C0.Flushes, "MRxFlush not called\n");
    ok(C1.QuerySd > C0.QuerySd && C1.SetSd > C0.SetSd, "security not passed to the mini-redirector\n");
    ok(C1.FsCtls > C0.FsCtls && C1.IoCtls > C0.IoCtls, "controls not passed to the mini-redirector\n");
}

static
VOID
TestEas(VOID)
{
    WCHAR U[MAX_PATH], L[MAX_PATH];
    UCHAR EaBuffer[64];
    PFILE_FULL_EA_INFORMATION Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS LocalStatus, UncStatus;
    HANDLE H;
    FILE_EA_INFORMATION EaInfo;
    WCHAR NtPath[MAX_PATH];

    /* An EA in the create: whatever the share's file system does locally,
     * the redirector must do the same (pass-through) */
    RtlZeroMemory(EaBuffer, sizeof(EaBuffer));
    Ea->EaNameLength = 4;
    Ea->EaValueLength = 3;
    memcpy(Ea->EaName, "TEST\0abc", 8);

    StringCchPrintfW(NtPath, MAX_PATH, L"\\??\\%s", P(L, FALSE, L"ea.bin"));
    RtlInitUnicodeString(&Name, NtPath);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    LocalStatus = NtCreateFile(&H, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL, 0, 0,
                               FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, Ea, sizeof(EaBuffer));
    if (NT_SUCCESS(LocalStatus))
        NtClose(H);

    StringCchPrintfW(NtPath, MAX_PATH, L"\\??\\UNC\\%s\\%s\\ea2.bin", LOOPRDR_SERVER, LOOPRDR_SHARE);
    RtlInitUnicodeString(&Name, NtPath);
    UncStatus = NtCreateFile(&H, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL, 0, 0,
                             FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, Ea, sizeof(EaBuffer));
    ok(NT_SUCCESS(UncStatus) == NT_SUCCESS(LocalStatus), "EA create: local %lx, unc %lx\n", LocalStatus, UncStatus);
    if (NT_SUCCESS(UncStatus))
    {
        NTSTATUS Status = NtQueryInformationFile(H, &Iosb, &EaInfo, sizeof(EaInfo), FileEaInformation);
        ok_eq_hex(Status, STATUS_SUCCESS);
        NtClose(H);
    }
    DeleteFileW(P(U, TRUE, L"ea2.bin"));
    DeleteFileW(P(L, FALSE, L"ea.bin"));
}

/* ---------------------------------------------------------------------- */
/* Byte-range locks                                                       */
/* ---------------------------------------------------------------------- */

typedef struct _WAIT_LOCK
{
    HANDLE File;
    BOOL Result;
    DWORD Error;
} WAIT_LOCK;

static
DWORD
WINAPI
WaitLockThread(
    _In_ PVOID Parameter)
{
    WAIT_LOCK *Wait = Parameter;
    OVERLAPPED Ov;

    RtlZeroMemory(&Ov, sizeof(Ov));
    Wait->Result = LockFileEx(Wait->File, LOCKFILE_EXCLUSIVE_LOCK, 0, 100, 0, &Ov);
    Wait->Error = GetLastError();
    if (Wait->Result)
    {
        UnlockFileEx(Wait->File, 0, 100, 0, &Ov);
    }
    return 0;
}

static
VOID
TestLocks(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE H1, H2, Thread;
    OVERLAPPED Ov;
    DWORD Done, Error;
    UCHAR Buffer[200];
    LOOPRDR_COUNTERS C0, C1;
    WAIT_LOCK Wait;

    LoopCounters(&C0);
    P(U, TRUE, L"locks.bin");
    H1 = CreateFileW(U, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    H2 = CreateFileW(U, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    ok(H1 != INVALID_HANDLE_VALUE && H2 != INVALID_HANDLE_VALUE, "open: %lu\n", GetLastError());
    if (H1 == INVALID_HANDLE_VALUE || H2 == INVALID_HANDLE_VALUE)
        return;
    Fill(Buffer, sizeof(Buffer), 1);
    WriteFile(H1, Buffer, sizeof(Buffer), &Done, NULL);

    /* Exclusive lock on h1, conflicts seen from h2: whatever the local file
     * system does for two handles of one process, the redirector must do the
     * same (the local check is FsRtl's; a lock conflict for another lock is
     * always refused) */
    {
        BOOLEAN Unc;
        BOOL ReadOk[2], WriteOk[2], OwnerOk[2];

        for (Unc = 0; Unc <= 1; ++Unc)
        {
            WCHAR Path[MAX_PATH];
            HANDLE A, B;

            P(Path, Unc, L"locks2.bin");
            A = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, CREATE_ALWAYS, 0, NULL);
            B = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, 0, NULL);
            ok(A != INVALID_HANDLE_VALUE && B != INVALID_HANDLE_VALUE, "%d: lock file open: %lu\n", Unc, GetLastError());
            WriteFile(A, Buffer, sizeof(Buffer), &Done, NULL);
            RtlZeroMemory(&Ov, sizeof(Ov));
            ok(LockFileEx(A, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 100, 0, &Ov), "%d: lock: %lu\n", Unc, GetLastError());
            SetFilePointer(B, 10, NULL, FILE_BEGIN);
            ReadOk[Unc] = ReadFile(B, Buffer, 10, &Done, NULL);
            SetFilePointer(B, 10, NULL, FILE_BEGIN);
            WriteOk[Unc] = WriteFile(B, Buffer, 10, &Done, NULL);
            ok(!LockFileEx(B, LOCKFILE_FAIL_IMMEDIATELY, 0, 10, 0, &Ov) && GetLastError() == ERROR_LOCK_VIOLATION,
               "%d: conflicting lock: %lu\n", Unc, GetLastError());
            SetFilePointer(A, 0, NULL, FILE_BEGIN);
            OwnerOk[Unc] = ReadFile(A, Buffer, 50, &Done, NULL) && WriteFile(A, Buffer, 50, &Done, NULL);
            ok(UnlockFileEx(A, 0, 100, 0, &Ov), "%d: unlock: %lu\n", Unc, GetLastError());
            ok(!UnlockFileEx(A, 0, 100, 0, &Ov) && GetLastError() == ERROR_NOT_LOCKED, "%d: unlock twice: %lu\n", Unc, GetLastError());
            CloseHandle(A);
            CloseHandle(B);
            DeleteFileW(Path);
        }
        ok(ReadOk[0] == ReadOk[1] && WriteOk[0] == WriteOk[1] && OwnerOk[1] && OwnerOk[0] == OwnerOk[1],
           "lock behaviour differs: local read %d write %d owner %d, unc read %d write %d owner %d\n",
           ReadOk[0], WriteOk[0], OwnerOk[0], ReadOk[1], WriteOk[1], OwnerOk[1]);
        trace("other handle under an exclusive lock: read %d write %d\n", ReadOk[1], WriteOk[1]);
    }

    /* Shared locks stack */
    RtlZeroMemory(&Ov, sizeof(Ov));
    ok(LockFileEx(H1, LOCKFILE_FAIL_IMMEDIATELY, 0, 100, 0, &Ov), "shared lock 1: %lu\n", GetLastError());
    ok(LockFileEx(H2, LOCKFILE_FAIL_IMMEDIATELY, 0, 100, 0, &Ov), "shared lock 2: %lu\n", GetLastError());
    ok(!LockFileEx(H2, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 100, 0, &Ov) &&
       GetLastError() == ERROR_LOCK_VIOLATION, "exclusive over shared: %lu\n", GetLastError());
    SetFilePointer(H2, 0, NULL, FILE_BEGIN);
    ok(ReadFile(H2, Buffer, 10, &Done, NULL), "read under shared locks: %lu\n", GetLastError());
    UnlockFileEx(H1, 0, 100, 0, &Ov);
    UnlockFileEx(H2, 0, 100, 0, &Ov);

    /* A waiting lock is granted when the holder unlocks */
    ok(LockFileEx(H1, LOCKFILE_EXCLUSIVE_LOCK, 0, 100, 0, &Ov), "lock for waiter: %lu\n", GetLastError());
    Wait.File = H2;
    Wait.Result = FALSE;
    Thread = CreateThread(NULL, 0, WaitLockThread, &Wait, 0, NULL);
    Sleep(500);
    ok(WaitForSingleObject(Thread, 0) == WAIT_TIMEOUT, "waiting lock did not wait\n");
    UnlockFileEx(H1, 0, 100, 0, &Ov);
    ok(WaitForSingleObject(Thread, 15000) == WAIT_OBJECT_0, "waiting lock never granted\n");
    ok(Wait.Result, "waiting lock failed: %lu\n", Wait.Error);
    CloseHandle(Thread);

    /* Closing with locks held releases them (unlock-all at cleanup) */
    ok(LockFileEx(H1, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 10, 0, &Ov), "lock a: %lu\n", GetLastError());
    Ov.Offset = 20;
    ok(LockFileEx(H1, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 10, 0, &Ov), "lock b: %lu\n", GetLastError());
    CloseHandle(H1);
    Ov.Offset = 0;
    ok(LockFileEx(H2, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 30, 0, &Ov), "lock after close: %lu\n", GetLastError());
    Error = GetLastError();
    UnlockFileEx(H2, 0, 30, 0, &Ov);
    CloseHandle(H2);
    (void)Error;

    /* An exclusive open gets local lock buffering (no one else can open):
     * locks are kept by RDBSS alone (FsRtlProcessFileLock path) */
    {
        LOOPRDR_COUNTERS B0, B1;
        HANDLE X;

        LoopCounters(&B0);
        X = CreateFileW(U, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        ok(X != INVALID_HANDLE_VALUE, "exclusive open: %lu\n", GetLastError());
        if (X != INVALID_HANDLE_VALUE)
        {
            RtlZeroMemory(&Ov, sizeof(Ov));
            ok(LockFileEx(X, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 10, 0, &Ov), "buffered lock: %lu\n", GetLastError());
            ok(!LockFileEx(X, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 10, 0, &Ov) &&
               GetLastError() == ERROR_LOCK_VIOLATION, "buffered lock twice: %lu\n", GetLastError());
            ok(UnlockFileEx(X, 0, 10, 0, &Ov), "buffered unlock: %lu\n", GetLastError());
            ok(!UnlockFileEx(X, 0, 10, 0, &Ov) && GetLastError() == ERROR_NOT_LOCKED, "buffered unlock twice: %lu\n", GetLastError());
            ok(LockFileEx(X, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 10, 0, &Ov), "buffered lock again: %lu\n", GetLastError());
            CloseHandle(X);
        }
        LoopCounters(&B1);
        ok(B1.Locks == B0.Locks, "buffered locks reached the mini-redirector (%ld)\n", B1.Locks - B0.Locks);
    }

    LoopCounters(&C1);
    ok(C1.Locks > C0.Locks && C1.Unlocks > C0.Unlocks, "locks did not reach the mini-redirector\n");
    ok(C1.UnlockMultiple > C0.UnlockMultiple, "no unlock-all at cleanup\n");
    DeleteFileW(U);
}

/* ---------------------------------------------------------------------- */
/* Buffering state changes (the oplock/lease break path)                  */
/* ---------------------------------------------------------------------- */

static
VOID
TestBufferingState(VOID)
{
    WCHAR U[MAX_PATH], L[MAX_PATH];
    HANDLE H, Local;
    UCHAR Data[4096], Back[4096];
    DWORD Done, Round;
    LOOPRDR_BREAK Break;
    LOOPRDR_COUNTERS C0, C1;

    for (Round = 0; Round < 2; ++Round)
    {
        LoopCounters(&C0);
        H = CreateFileW(P(U, TRUE, L"cbs.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        CREATE_ALWAYS, 0, NULL);
        ok(H != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
        if (H == INVALID_HANDLE_VALUE)
            return;

        /* Cached write, then a cached read that fills the cache */
        Fill(Data, sizeof(Data), 70 + Round);
        WriteFile(H, Data, sizeof(Data), &Done, NULL);
        SetFilePointer(H, 0, NULL, FILE_BEGIN);
        ReadFile(H, Back, sizeof(Back), &Done, NULL);

        /* The "server" revokes all caching and waits for the acknowledgement */
        Break.FileHandle = (ULONG_PTR)H;
        Break.NewBufferingState = 0;
        Break.Flags = LOOPRDR_BREAK_WAIT | (Round ? LOOPRDR_BREAK_FOR_SRVOPEN : 0);
        ok(LoopIoctl(IOCTL_LOOPRDR_BREAK, &Break, sizeof(Break), NULL, 0), "break (%lu): %lu\n", Round, GetLastError());

        /* Dirty data was written back before the acknowledgement */
        ok(SameContent(L"cbs.bin", Data, sizeof(Data)), "break (%lu) did not flush\n", Round);

        /* Change the file behind the client's back: no stale cache */
        Local = CreateFileW(P(L, FALSE, L"cbs.bin"), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, 0, NULL);
        ok(Local != INVALID_HANDLE_VALUE, "local open: %lu\n", GetLastError());
        if (Local != INVALID_HANDLE_VALUE)
        {
            Fill(Data, 100, 90 + Round);
            WriteFile(Local, Data, 100, &Done, NULL);
            CloseHandle(Local);
        }
        SetFilePointer(H, 0, NULL, FILE_BEGIN);
        ok(ReadFile(H, Back, 100, &Done, NULL) && Done == 100 && !memcmp(Back, Data, 100),
           "break (%lu): stale data after the break\n", Round);
        CloseHandle(H);

        LoopCounters(&C1);
        ok(C1.ComputeBufferingState > C0.ComputeBufferingState, "break (%lu): MRxComputeNewBufferingState not called\n", Round);
        ok(C1.CompleteBufferingState > C0.CompleteBufferingState, "break (%lu): not acknowledged\n", Round);
    }
    DeleteFileW(P(U, TRUE, L"cbs.bin"));
}

static
VOID
TestPipeShare(VOID)
{
    HANDLE H;
    DWORD Error;
    LOOPRDR_COUNTERS C;

    /* IPC$ is a pipe share: classified as such, opens on it refused cleanly */
    H = CreateFileW(L"\\\\" LOOPRDR_SERVER L"\\" LOOPRDR_IPC_SHARE L"\\somepipe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    Error = GetLastError();
    ok(H == INVALID_HANDLE_VALUE, "open on IPC$ succeeded\n");
    if (H != INVALID_HANDLE_VALUE)
        CloseHandle(H);
    trace("open on IPC$: %lu\n", Error);
    LoopCounters(&C);
    ok(C.PipeNetRoots > 0, "IPC$ was not classified as a pipe share\n");
}

START_TEST(RdbssLoop)
{
    POOL_SUM Before;

    if (!LoopSetUp(&Before))
        return;

    TestCreate();
    TestRelative();
    TestCopyFile();
    TestReadWrite();
    TestInformation();
    TestDirectory();
    TestVolumeFlushSecurity();
    TestEas();
    TestLocks();
    TestBufferingState();
    TestPipeShare();

    LoopTearDown(&Before);
}

/* ---------------------------------------------------------------------- */
/* Stress                                                                 */
/* ---------------------------------------------------------------------- */

#define STRESS_THREADS  8
#define STRESS_FILES    4
#define STRESS_MAXSIZE  (2 * 1024 * 1024)

typedef struct _STRESS
{
    volatile LONG Op;           /* operation in progress, -1 between operations */
    volatile DWORD OpStart;     /* GetTickCount() when it started */
    ULONG Index;
    DWORD EndTick;
    ULONG Ops;
    ULONG Failures;
    PUCHAR Model;       /* expected content of each file */
    PUCHAR Buffer;
} STRESS;

static
ULONG
Rand(
    _Inout_ PULONG Seed)
{
    *Seed = *Seed * 1103515245 + 12345;
    return *Seed >> 8;
}

static
DWORD
WINAPI
StressThread(
    _In_ PVOID Parameter)
{
    STRESS *S = Parameter;
    ULONG Seed = 0x1234 + S->Index * 7919;
    ULONG Sizes[STRESS_FILES] = { 0 };
    WCHAR U[MAX_PATH], Rel[64];

    /* Each thread works on its own files: the model is exact */
    while ((LONG)(GetTickCount() - S->EndTick) < 0)
    {
        ULONG File = Rand(&Seed) % STRESS_FILES, Op = Rand(&Seed) % 10;
        PUCHAR Model = S->Model + File * STRESS_MAXSIZE;
        DWORD Flags = (Rand(&Seed) % 4 == 0) ? FILE_FLAG_WRITE_THROUGH : 0;
        HANDLE H;
        DWORD Done;

        StringCchPrintfW(Rel, 64, L"stress\\t%lu_f%lu.bin", S->Index, File);
        P(U, TRUE, Rel);
        S->OpStart = GetTickCount();
        S->Op = 100 + Op;
        H = CreateFileW(U, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_ALWAYS, Flags, NULL);
        if (H == INVALID_HANDLE_VALUE)
        {
            ++S->Failures;
            S->Op = -1;
            continue;
        }

        S->Op = Op;
        switch (Op)
        {
            case 0: case 1: case 2: case 3:     /* write somewhere */
            {
                ULONG Offset = Rand(&Seed) % (STRESS_MAXSIZE - 70000), Length = 1 + Rand(&Seed) % 70000;

                Fill(S->Buffer, Length, Seed);
                SetFilePointer(H, Offset, NULL, FILE_BEGIN);
                if (!WriteFile(H, S->Buffer, Length, &Done, NULL) || Done != Length)
                {
                    ++S->Failures;
                    break;
                }
                if (Offset > Sizes[File])
                    RtlZeroMemory(Model + Sizes[File], Offset - Sizes[File]);
                memcpy(Model + Offset, S->Buffer, Length);
                if (Offset + Length > Sizes[File])
                    Sizes[File] = Offset + Length;
                break;
            }
            case 4: case 5: case 6:             /* read and compare */
            {
                ULONG Offset = Sizes[File] ? Rand(&Seed) % Sizes[File] : 0, Length = 1 + Rand(&Seed) % 70000;
                ULONG Expected = (Offset + Length > Sizes[File]) ? Sizes[File] - Offset : Length;

                SetFilePointer(H, Offset, NULL, FILE_BEGIN);
                if (!ReadFile(H, S->Buffer, Length, &Done, NULL) || Done != Expected ||
                    memcmp(S->Buffer, Model + Offset, Expected) != 0)
                {
                    ++S->Failures;
                    trace("stress t%lu f%lu: read %lu at %lu got %lu, expected %lu\n", S->Index, File, Length, Offset, Done, Expected);
                }
                break;
            }
            case 7:                             /* resize */
            {
                ULONG NewSize = Rand(&Seed) % STRESS_MAXSIZE;

                SetFilePointer(H, NewSize, NULL, FILE_BEGIN);
                if (!SetEndOfFile(H))
                {
                    ++S->Failures;
                    break;
                }
                if (NewSize > Sizes[File])
                    RtlZeroMemory(Model + Sizes[File], NewSize - Sizes[File]);
                Sizes[File] = NewSize;
                break;
            }
            case 8:                             /* lock, write, unlock */
            {
                OVERLAPPED Ov;

                RtlZeroMemory(&Ov, sizeof(Ov));
                if (!LockFileEx(H, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &Ov))
                    ++S->Failures;
                else if (!UnlockFileEx(H, 0, 4096, 0, &Ov))
                    ++S->Failures;
                break;
            }
            case 9:                             /* flush, or delete and start over */
                if (Rand(&Seed) % 8 == 0)
                {
                    FILE_DISPOSITION_INFORMATION Disposition;

                    Disposition.DeleteFile = TRUE;
                    if (!NT_SUCCESS(SetInfo(H, &Disposition, sizeof(Disposition), FileDispositionInformation)))
                        ++S->Failures;
                    else
                        Sizes[File] = 0;
                }
                else if (!FlushFileBuffers(H))
                {
                    ++S->Failures;
                }
                break;
        }
        S->Op = 200 + Op;
        CloseHandle(H);
        S->Op = -1;
        ++S->Ops;
    }

    /* Final byte compare of every file against the local directory */
    {
        ULONG File;

        for (File = 0; File < STRESS_FILES; ++File)
        {
            StringCchPrintfW(Rel, 64, L"stress\\t%lu_f%lu.bin", S->Index, File);
            if (Sizes[File] == 0)
                continue;
            if (!SameContent(Rel, S->Model + File * STRESS_MAXSIZE, Sizes[File]))
            {
                ++S->Failures;
                trace("stress t%lu f%lu: local file differs from the model\n", S->Index, File);
            }
        }
    }
    return 0;
}

START_TEST(RdbssLoopStress)
{
    POOL_SUM Before, Mid;
    HANDLE Threads[STRESS_THREADS];
    STRESS State[STRESS_THREADS];
    WCHAR U[MAX_PATH], Env[32];
    ULONG Seconds = 60, i, Ops = 0, Failures = 0;
    DWORD Start;

    if (GetEnvironmentVariableW(L"RDBSS_STRESS_SECONDS", Env, RTL_NUMBER_OF(Env)))
    {
        PWCHAR c;

        Seconds = 0;
        for (c = Env; *c >= L'0' && *c <= L'9'; ++c)
            Seconds = Seconds * 10 + (*c - L'0');
    }

    if (!LoopSetUp(&Before))
        return;

    CreateDirectoryW(P(U, TRUE, L"stress"), NULL);
    Start = GetTickCount();
    for (i = 0; i < STRESS_THREADS; ++i)
    {
        State[i].Index = i;
        State[i].EndTick = Start + Seconds * 1000;
        State[i].Ops = State[i].Failures = 0;
        State[i].Op = -1;
        State[i].OpStart = Start;
        State[i].Model = VirtualAlloc(NULL, STRESS_FILES * STRESS_MAXSIZE, MEM_COMMIT, PAGE_READWRITE);
        State[i].Buffer = VirtualAlloc(NULL, 128 * 1024, MEM_COMMIT, PAGE_READWRITE);
        Threads[i] = CreateThread(NULL, 0, StressThread, &State[i], 0, NULL);
    }
    /* Report operations that take far too long (to the debugger, since a
     * hung run never writes its output), and sample the pool tags */
    while (WaitForMultipleObjects(STRESS_THREADS, Threads, TRUE, 15000) == WAIT_TIMEOUT)
    {
        static DWORD LastSample;

        if (GetTickCount() - LastSample >= 300000 || LastSample == 0)
        {
            POOL_SUM Sample;
            CHAR Msg[700];

            LastSample = GetTickCount();
            if (PoolSum(&Sample))
            {
                StringCbPrintfA(Msg, sizeof(Msg), "RdbssLoopStress: t+%lus pool %I64d blocks/%I64d bytes: %s\n",
                                (GetTickCount() - Start) / 1000, Sample.Outstanding, Sample.Bytes, Sample.Detail);
                OutputDebugStringA(Msg);
            }
        }

        for (i = 0; i < STRESS_THREADS; ++i)
        {
            LONG Op = State[i].Op;

            if (Op >= 0 && GetTickCount() - State[i].OpStart > 15000)
            {
                CHAR Msg[128];

                StringCbPrintfA(Msg, sizeof(Msg), "RdbssLoopStress: thread %lu stuck in op %ld for %lu ms\n",
                                i, Op, GetTickCount() - State[i].OpStart);
                OutputDebugStringA(Msg);
            }
        }
    }
    for (i = 0; i < STRESS_THREADS; ++i)
    {
        Ops += State[i].Ops;
        Failures += State[i].Failures;
        CloseHandle(Threads[i]);
        VirtualFree(State[i].Model, 0, MEM_RELEASE);
        VirtualFree(State[i].Buffer, 0, MEM_RELEASE);
    }
    trace("stress: %lu s, %lu threads, %lu operations, %lu failures\n", Seconds, STRESS_THREADS, Ops, Failures);
    ok_eq_ulong(Failures, 0UL);

    if (PoolSum(&Mid))
    {
        trace("RDBSS pool tags at the end of the run (mounted): %I64d blocks/%I64d bytes: %s\n", Mid.Outstanding, Mid.Bytes, Mid.Detail);
    }

    LoopTearDown(&Before);
}

/* ---------------------------------------------------------------------- */
/* Races and hostile callers (review tests)                               */
/* ---------------------------------------------------------------------- */

static
ULONG
EnvNumber(
    _In_ PCWSTR Name,
    _In_ ULONG Default)
{
    WCHAR Env[32];
    PWCHAR c;
    ULONG Value = 0;

    if (!GetEnvironmentVariableW(Name, Env, RTL_NUMBER_OF(Env)))
        return Default;
    if (Env[0] == L'0' && (Env[1] == L'x' || Env[1] == L'X'))
        return wcstoul(Env, NULL, 16);
    for (c = Env; *c >= L'0' && *c <= L'9'; ++c)
        Value = Value * 10 + (*c - L'0');
    return Value;
}

/* RDBSS_RACES selects the subtests (default all): s = stop vs create,
 * i = file ID, a = FileAllInformation layout, o = overlapped I/O completed
 * inline, p = posted asynchronous read completed late, q = late asynchronous
 * read of an FCB that caches reads, l = latency of a
 * posted request behind a waiting lock (measurement), n = odd names,
 * m = image section of a share file, u = user buffers, b = break vs close,
 * w = a waiting lock does not stall other requests, and ends on cancel and
 * on the cleanup of its handle */
static
BOOLEAN
RaceSelected(
    _In_ WCHAR Which)
{
    WCHAR Env[32];

    if (!GetEnvironmentVariableW(L"RDBSS_RACES", Env, RTL_NUMBER_OF(Env)))
        return TRUE;
    return wcschr(Env, Which) != NULL;
}

static
DWORD
WINAPI
InFlightCreate(
    _In_ PVOID Parameter)
{
    PHANDLE Out = Parameter;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    /* Straight to the redirector's device, as MUP forwards a claimed name:
     * through MUP, the stop's deregistration fails the create before it
     * reaches RDBSS's create path */
    RtlInitUnicodeString(&Name, LOOPRDR_DEVICE_NAME L"\\" LOOPRDR_SERVER L"\\" LOOPRDR_SHARE L"\\race\\inflight.bin");
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateFile(Out, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Iosb, NULL, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(Status))
        *Out = INVALID_HANDLE_VALUE;
    return (DWORD)Status;
}

/* A stop must not succeed while a create that passed RDBSS's state check is
 * still building its connection: the create would go on with a stopped
 * device and leave structures behind for the unload */
static
VOID
TestStopVsCreate(VOID)
{
    HANDLE Thread, Created = INVALID_HANDLE_VALUE;
    BOOL Stopped;
    DWORD Error, Wait, CreateStatus = 0;
    LOOPRDR_COUNTERS C;

    LoopOptions(FCB_ALL_CACHE, LOOPRDR_OPT_SLOW_CONNECT);
    Thread = CreateThread(NULL, 0, InFlightCreate, &Created, 0, NULL);
    ok(Thread != NULL, "CreateThread: %lu\n", GetLastError());
    if (Thread == NULL)
        return;
    Sleep(300);
    Stopped = LoopIoctl(IOCTL_LOOPRDR_STOP, NULL, 0, NULL, 0);
    Error = GetLastError();
    Wait = WaitForSingleObject(Thread, 30000);
    ok(Wait == WAIT_OBJECT_0, "the in-flight create did not end\n");
    GetExitCodeThread(Thread, &CreateStatus);
    CloseHandle(Thread);
    LoopCounters(&C);
    trace("stop vs create: stop %s (%lu), create 0x%lx, slow connects %ld, srvcalls %ld, started %ld\n",
          Stopped ? "succeeded" : "failed", Stopped ? 0 : Error, CreateStatus, C.SlowConnects, C.SrvCalls, C.Started);
    ok(C.SlowConnects > 0, "the create did not go through MRxGetConnectionId\n");
    /* Either the stop waits and fails (the create left a handle), or the
     * create fails; never a stopped redirector with a new open on it */
    ok(!(Stopped && Created != INVALID_HANDLE_VALUE), "a create succeeded on a redirector that was stopped under it\n");
    ok(!(Stopped && C.SrvCalls != 0), "a stopped redirector has %ld connections\n", C.SrvCalls);
    if (Created != INVALID_HANDLE_VALUE)
        CloseHandle(Created);
    LoopOptions(FCB_ALL_CACHE, 0);
    if (Stopped)
    {
        /* Let the rest run on a started device; the bug's leftovers need
         * the scavenger first */
        Sleep(3000);
        ok(LoopIoctl(IOCTL_LOOPRDR_START, NULL, 0, NULL, 0), "restart after the stop: %lu\n", GetLastError());
    }
}

/* With a server that has no file IDs, RDBSS makes one up: never the address
 * of a kernel structure */
static
VOID
TestInternalInfo(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE H;
    NTSTATUS Status;
    FILE_INTERNAL_INFORMATION Internal;
    /* FILE_ALL_INFORMATION: basic, standard, then internal information */
    UCHAR AllBuffer[1024];
    PFILE_INTERNAL_INFORMATION AllInternal =
        (PFILE_INTERNAL_INFORMATION)(AllBuffer + sizeof(FILE_BASIC_INFORMATION) + sizeof(FILE_STANDARD_INFORMATION));

    LoopOptions(FCB_ALL_CACHE, LOOPRDR_OPT_NO_INTERNAL_INFO);
    H = CreateFileW(P(U, TRUE, L"race\\id.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        Internal.IndexNumber.QuadPart = 0;
        Status = QueryInfo(H, &Internal, sizeof(Internal), FileInternalInformation);
        ok_eq_hex(Status, STATUS_SUCCESS);
        trace("file ID without server support: 0x%I64x\n", Internal.IndexNumber.QuadPart);
        ok(Internal.IndexNumber.HighPart == 0, "file ID 0x%I64x looks like a kernel address\n", Internal.IndexNumber.QuadPart);
        Status = QueryInfo(H, AllBuffer, sizeof(AllBuffer), FileAllInformation);
        if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
        {
            ok(AllInternal->IndexNumber.HighPart == 0, "FileAllInformation file ID 0x%I64x looks like a kernel address\n",
               AllInternal->IndexNumber.QuadPart);
        }
        CloseHandle(H);
    }
    LoopOptions(FCB_ALL_CACHE, 0);
}

/* FILE_ALL_INFORMATION as the kernel lays it out (same compiler, same ABI) */
typedef struct _TEST_ALL_INFORMATION
{
    FILE_BASIC_INFORMATION Basic;
    FILE_STANDARD_INFORMATION Standard;
    FILE_INTERNAL_INFORMATION Internal;
    ULONG EaSize;
    ACCESS_MASK AccessFlags;
    LARGE_INTEGER CurrentByteOffset;
    ULONG Mode;
    ULONG AlignmentRequirement;
    ULONG FileNameLength;
    WCHAR FileName[1];
} TEST_ALL_INFORMATION;

/* FileAllInformation: every part where FILE_ALL_INFORMATION has it, the
 * access and mode parts (the I/O manager's) kept, the same name and
 * position as the single classes; compared with the local file system */
static
VOID
TestAllInfo(VOID)
{
    WCHAR U[MAX_PATH], L[MAX_PATH];
    ULONG Round;

    for (Round = 0; Round < 2; ++Round)
    {
        HANDLE H;
        NTSTATUS Status;
        UCHAR AllBuffer[1024], NameBuffer[1024];
        TEST_ALL_INFORMATION *All = (TEST_ALL_INFORMATION *)AllBuffer;
        PFILE_NAME_INFORMATION Name = (PFILE_NAME_INFORMATION)NameBuffer;
        LARGE_INTEGER Position;

        H = CreateFileW(Round ? P(L, FALSE, L"race\\all.bin") : P(U, TRUE, L"race\\all.bin"),
                        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
        ok(H != INVALID_HANDLE_VALUE, "create (%s): %lu\n", Round ? "local" : "share", GetLastError());
        if (H == INVALID_HANDLE_VALUE)
            continue;
        Position.QuadPart = 1234;
        SetFilePointerEx(H, Position, NULL, FILE_BEGIN);
        RtlFillMemory(AllBuffer, sizeof(AllBuffer), 0xAB);
        Status = QueryInfo(H, AllBuffer, sizeof(AllBuffer), FileAllInformation);
        ok(NT_SUCCESS(Status), "FileAllInformation (%s): 0x%lx\n", Round ? "local" : "share", Status);
        Status = QueryInfo(H, NameBuffer, sizeof(NameBuffer), FileNameInformation);
        ok(NT_SUCCESS(Status), "FileNameInformation (%s): 0x%lx\n", Round ? "local" : "share", Status);
        trace("FileAllInformation (%s): access 0x%lx, position %I64d, mode 0x%lx, name length %lu (single class %lu)\n",
              Round ? "local" : "share", All->AccessFlags, All->CurrentByteOffset.QuadPart, All->Mode,
              All->FileNameLength, Name->FileNameLength);
        ok(All->AccessFlags != 0, "FileAllInformation (%s): no access flags\n", Round ? "local" : "share");
        ok(All->CurrentByteOffset.QuadPart == 1234, "FileAllInformation (%s): position %I64d\n",
           Round ? "local" : "share", All->CurrentByteOffset.QuadPart);
        ok(All->FileNameLength == Name->FileNameLength && All->FileNameLength < sizeof(AllBuffer) &&
           !memcmp(All->FileName, Name->FileName, Name->FileNameLength),
           "FileAllInformation (%s): name differs from FileNameInformation\n", Round ? "local" : "share");
        CloseHandle(H);
    }
}

/* Cached I/O with user buffers Cc cannot copy to or from: the request must
 * fail, as on a local file system, instead of taking the system down */
static
VOID
TestUserBuffers(VOID)
{
    WCHAR U[MAX_PATH], L[MAX_PATH];
    HANDLE H, Local;
    PUCHAR Region, Data;
    DWORD Done, Error, LocalError;
    BOOL Ok, LocalOk;
    ULONG i;
    HOSTILE_DECOMMIT D;
    HANDLE Thread;

    LoopOptions(FCB_ALL_CACHE, 0);
    Data = HeapAlloc(GetProcessHeap(), 0, 128 * 1024);
    if (Data == NULL)
        return;
    Fill(Data, 128 * 1024, 1234);
    H = CreateFileW(P(U, TRUE, L"race\\ub.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    CREATE_ALWAYS, 0, NULL);
    Local = CreateFileW(P(L, FALSE, L"race\\ub_local.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE && Local != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (H == INVALID_HANDLE_VALUE || Local == INVALID_HANDLE_VALUE)
        goto out;
    WriteFile(H, Data, 128 * 1024, &Done, NULL);
    WriteFile(Local, Data, 128 * 1024, &Done, NULL);

    /* Write from 64 KB of which only the first page is committed */
    Region = VirtualAlloc(NULL, 64 * 1024, MEM_RESERVE, PAGE_READWRITE);
    ok(Region != NULL && VirtualAlloc(Region, 4096, MEM_COMMIT, PAGE_READWRITE) != NULL, "VirtualAlloc: %lu\n", GetLastError());
    if (Region != NULL)
    {
        SetFilePointer(H, 4096, NULL, FILE_BEGIN);
        Done = 0;
        Ok = WriteFile(H, Region, 64 * 1024, &Done, NULL);
        Error = Ok ? 0 : GetLastError();
        SetFilePointer(Local, 4096, NULL, FILE_BEGIN);
        LocalOk = WriteFile(Local, Region, 64 * 1024, &Done, NULL);
        LocalError = LocalOk ? 0 : GetLastError();
        trace("cached write from a partly committed buffer: share %s (%lu), local %s (%lu)\n",
              Ok ? "ok" : "failed", Error, LocalOk ? "ok" : "failed", LocalError);
        ok(!Ok, "a write from an uncommitted buffer succeeded on the share\n");

        /* Read into the same buffer: the I/O manager's probe catches it */
        SetFilePointer(H, 0, NULL, FILE_BEGIN);
        Ok = ReadFile(H, Region, 64 * 1024, &Done, NULL);
        trace("cached read into a partly committed buffer: share %s (%lu)\n", Ok ? "ok" : "failed", Ok ? 0 : GetLastError());
        VirtualFree(Region, 0, MEM_RELEASE);
    }

    /* Read into a buffer another thread keeps decommitting (the probe passes,
     * the copy faults): many rounds to hit the window */
    D.Region = VirtualAlloc(NULL, 64 * 1024, MEM_COMMIT, PAGE_READWRITE);
    D.Stop = 0;
    if (D.Region != NULL)
    {
        ULONG Failed = 0;

        Thread = CreateThread(NULL, 0, HostileDecommitter, &D, 0, NULL);
        for (i = 0; i < 2000; ++i)
        {
            SetFilePointer(H, (i % 4) * 4096, NULL, FILE_BEGIN);
            if (!ReadFile(H, D.Region, 64 * 1024, &Done, NULL))
                ++Failed;
        }
        D.Stop = 1;
        if (Thread != NULL)
        {
            WaitForSingleObject(Thread, INFINITE);
            CloseHandle(Thread);
        }
        trace("cached reads into a buffer being decommitted: %lu of 2000 failed\n", Failed);
        VirtualFree(D.Region, 0, MEM_RELEASE);
    }

    /* The file is still usable */
    SetFilePointer(H, 0, NULL, FILE_BEGIN);
    Ok = ReadFile(H, Data, 4096, &Done, NULL);
    ok(Ok && Done == 4096, "read after the failures: %lu\n", GetLastError());

out:
    if (H != INVALID_HANDLE_VALUE)
        CloseHandle(H);
    if (Local != INVALID_HANDLE_VALUE)
        CloseHandle(Local);
    HeapFree(GetProcessHeap(), 0, Data);
}

/* Overlapped unbuffered I/O the mini-redirector completes inline, with
 * success and with a failure: RDBSS marked the IRP pending before calling
 * it and must take the mark back, or the I/O manager completes it twice */
static
VOID
TestInlineAsync(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE H;
    PUCHAR Data;
    DWORD Done;
    ULONG i;
    OVERLAPPED Ov;
    BOOL Ok;

    LoopOptions(0, 0);
    Data = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (Data == NULL)
        return;
    Fill(Data, 4096, 9);
    H = CreateFileW(P(U, TRUE, L"race\\inline.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        RtlZeroMemory(&Ov, sizeof(Ov));
        Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        for (i = 0; i < 8; ++i)
        {
            ResetEvent(Ov.hEvent);
            Ok = (i & 1) ? ReadFile(H, Data, 4096, NULL, &Ov) : WriteFile(H, Data, 4096, NULL, &Ov);
            if (!Ok && GetLastError() == ERROR_IO_PENDING)
                Ok = GetOverlappedResult(H, &Ov, &Done, TRUE);
            ok(Ok, "inline %s %lu: %lu\n", (i & 1) ? "read" : "write", i, GetLastError());
        }
        /* A failure: an offset the backing file system refuses */
        Ov.Offset = 0;
        Ov.OffsetHigh = 0x7FFFFFFF;
        ResetEvent(Ov.hEvent);
        Ok = WriteFile(H, Data, 4096, NULL, &Ov);
        if (!Ok && GetLastError() == ERROR_IO_PENDING)
            Ok = GetOverlappedResult(H, &Ov, &Done, TRUE);
        trace("inline write at 0x7FFFFFFF00000000: %s (%lu)\n", Ok ? "ok" : "failed", Ok ? 0 : GetLastError());
        CloseHandle(Ov.hEvent);
        CloseHandle(H);
    }
    VirtualFree(Data, 0, MEM_RELEASE);
    LoopOptions(FCB_ALL_CACHE, 0);
}

static
DWORD
WINAPI
SlowFlushThread(
    _In_ PVOID Parameter)
{
    return FlushFileBuffers((HANDLE)Parameter) ? 0 : GetLastError();
}

/* An overlapped read that finds the FCB busy is posted to the FSP, which
 * hands the FCB lock over to the request; the mini-redirector completes it
 * later, on another thread, which must release it as that owner */
static
VOID
TestPostedAsyncRead(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE Writer, Reader, Thread;
    PUCHAR Data;
    DWORD Done;
    ULONG i;
    OVERLAPPED Ov;
    BOOL Ok;

    Data = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    if (Data == NULL)
        return;
    Fill(Data, 65536, 11);
    /* No read caching granted: reads go to the server under the FCB lock */
    LoopOptions(0, 0);
    Writer = CreateFileW(P(U, TRUE, L"race\\posted.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, 0, NULL);
    Reader = CreateFileW(P(U, TRUE, L"race\\posted.bin"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    ok(Writer != INVALID_HANDLE_VALUE && Reader != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (Writer != INVALID_HANDLE_VALUE && Reader != INVALID_HANDLE_VALUE)
    {
        WriteFile(Writer, Data, 65536, &Done, NULL);
        LoopOptions(0, LOOPRDR_OPT_SLOW_FLUSH | LOOPRDR_OPT_ASYNC_LOWIO);
        RtlZeroMemory(&Ov, sizeof(Ov));
        Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        for (i = 0; i < 4; ++i)
        {
            /* The flush holds the FCB exclusive in the mini-redirector */
            Thread = CreateThread(NULL, 0, SlowFlushThread, Writer, 0, NULL);
            Sleep(150);
            ResetEvent(Ov.hEvent);
            Ov.Offset = (i % 2) * 4096;
            Ok = ReadFile(Reader, Data, 4096, NULL, &Ov);
            if (!Ok && GetLastError() == ERROR_IO_PENDING)
                Ok = GetOverlappedResult(Reader, &Ov, &Done, TRUE);
            ok(Ok, "posted read %lu: %lu\n", i, GetLastError());
            if (Thread != NULL)
            {
                WaitForSingleObject(Thread, INFINITE);
                CloseHandle(Thread);
            }
        }
        CloseHandle(Ov.hEvent);
    }
    if (Writer != INVALID_HANDLE_VALUE)
        CloseHandle(Writer);
    if (Reader != INVALID_HANDLE_VALUE)
        CloseHandle(Reader);
    VirtualFree(Data, 0, MEM_RELEASE);
    LoopOptions(FCB_ALL_CACHE, 0);
}

/* An overlapped unbuffered read of a file whose FCB caches reads: the read
 * takes no FCB lock, so its late completion must not release one */
static
VOID
TestCachedFcbAsyncRead(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE Writer, Reader;
    PUCHAR Data;
    DWORD Done;
    ULONG i;
    OVERLAPPED Ov;
    BOOL Ok;

    Data = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    if (Data == NULL)
        return;
    Fill(Data, 65536, 13);
    LoopOptions(FCB_ALL_CACHE, 0);
    Writer = CreateFileW(P(U, TRUE, L"race\\cachedasync.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, 0, NULL);
    Reader = CreateFileW(P(U, TRUE, L"race\\cachedasync.bin"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    ok(Writer != INVALID_HANDLE_VALUE && Reader != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (Writer != INVALID_HANDLE_VALUE && Reader != INVALID_HANDLE_VALUE)
    {
        WriteFile(Writer, Data, 65536, &Done, NULL);
        FlushFileBuffers(Writer);
        LoopOptions(FCB_ALL_CACHE, LOOPRDR_OPT_ASYNC_LOWIO);
        RtlZeroMemory(&Ov, sizeof(Ov));
        Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        for (i = 0; i < 4; ++i)
        {
            ResetEvent(Ov.hEvent);
            Ov.Offset = i * 4096;
            Ok = ReadFile(Reader, Data, 4096, NULL, &Ov);
            if (!Ok && GetLastError() == ERROR_IO_PENDING)
                Ok = GetOverlappedResult(Reader, &Ov, &Done, TRUE);
            ok(Ok, "async read %lu: %lu\n", i, GetLastError());
        }
        /* The FCB is still usable by an exclusive acquirer (a set end of file) */
        ok(SetFilePointer(Writer, 8192, NULL, FILE_BEGIN) == 8192 && SetEndOfFile(Writer), "truncate after: %lu\n", GetLastError());
        CloseHandle(Ov.hEvent);
    }
    if (Writer != INVALID_HANDLE_VALUE)
        CloseHandle(Writer);
    if (Reader != INVALID_HANDLE_VALUE)
        CloseHandle(Reader);
    VirtualFree(Data, 0, MEM_RELEASE);
    LoopOptions(FCB_ALL_CACHE, 0);
}

/* Measurement (not a pass/fail row): an overlapped lock that has to wait
 * for another owner is posted, and the FSP sends it to the mini-redirector
 * synchronously; posted requests are serialized through one FSP work item,
 * so an unrelated posted read waits behind it. Prints the read's latency */
static
VOID
TestWaitingLockBlocksFsp(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE Holder, Waiter, Writer, Reader, Thread;
    OVERLAPPED LockOv, ReadOv;
    PUCHAR Data;
    DWORD Done, T0, Latency;
    BOOL Ok;

    Data = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    if (Data == NULL)
        return;
    LoopOptions(0, 0);
    Holder = CreateFileW(P(U, TRUE, L"race\\lock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, 0, NULL);
    Waiter = CreateFileW(P(U, TRUE, L"race\\lock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    Writer = CreateFileW(P(U, TRUE, L"race\\other.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, 0, NULL);
    Reader = CreateFileW(P(U, TRUE, L"race\\other.bin"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    if (Holder == INVALID_HANDLE_VALUE || Waiter == INVALID_HANDLE_VALUE ||
        Writer == INVALID_HANDLE_VALUE || Reader == INVALID_HANDLE_VALUE)
    {
        ok(FALSE, "opens failed: %lu\n", GetLastError());
        goto out;
    }
    WriteFile(Writer, Data, 65536, &Done, NULL);
    RtlZeroMemory(&LockOv, sizeof(LockOv));
    RtlZeroMemory(&ReadOv, sizeof(ReadOv));
    LockOv.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ReadOv.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    /* The holder's lock, then a waiting overlapped lock on the same range */
    LockFileEx(Holder, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &LockOv);
    ResetEvent(LockOv.hEvent);
    Ok = LockFileEx(Waiter, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &LockOv);
    trace("waiting lock: %s (%lu)\n", Ok ? "granted at once" : "pending", Ok ? 0 : GetLastError());
    Sleep(500);

    /* A read on another file that has to be posted (its FCB is held by a
     * slow flush when it arrives) */
    LoopOptions(0, LOOPRDR_OPT_SLOW_FLUSH);
    Thread = CreateThread(NULL, 0, SlowFlushThread, Writer, 0, NULL);
    Sleep(150);
    T0 = GetTickCount();
    Ok = ReadFile(Reader, Data, 4096, NULL, &ReadOv);
    if (!Ok && GetLastError() == ERROR_IO_PENDING)
        Ok = GetOverlappedResult(Reader, &ReadOv, &Done, TRUE);
    Latency = GetTickCount() - T0;
    trace("posted read behind a waiting lock: %s after %lu ms (the flush alone holds the FCB 500 ms)\n",
          Ok ? "done" : "failed", Latency);
    if (Thread != NULL)
    {
        WaitForSingleObject(Thread, INFINITE);
        CloseHandle(Thread);
    }
    LoopOptions(0, 0);
    UnlockFileEx(Holder, 0, 4096, 0, &LockOv);
    WaitForSingleObject(LockOv.hEvent, 60000);
    CloseHandle(LockOv.hEvent);
    CloseHandle(ReadOv.hEvent);

out:
    if (Holder != INVALID_HANDLE_VALUE) CloseHandle(Holder);
    if (Waiter != INVALID_HANDLE_VALUE) CloseHandle(Waiter);
    if (Writer != INVALID_HANDLE_VALUE) CloseHandle(Writer);
    if (Reader != INVALID_HANDLE_VALUE) CloseHandle(Reader);
    VirtualFree(Data, 0, MEM_RELEASE);
    LoopOptions(FCB_ALL_CACHE, 0);
}

/* w: a waiting lock must not stall anybody else. One handle holds an
 * exclusive lock; an overlapped lock of another handle waits for it (pending
 * at the mini-redirector) for RDBSS_WL_SECS seconds (default 25; the
 * loopback "server" gives up after 30). Meanwhile 3 threads, each on its own
 * file, do overlapped lock/unlock pairs (which RDBSS posted to its FSP before
 * the waiting lock went asynchronous) and overlapped unbuffered reads: every
 * single operation must finish within 1 s. Then the waiting lock is
 * cancelled (CancelIoEx), a second one ends with the cleanup of its handle,
 * a third one is granted when the holder unlocks: each within 1 s */
typedef struct _WL_WORKER
{
    ULONG Index;
    DWORD Seconds;
    ULONG Ops;
    ULONG Failures;
    DWORD MaxLatency;
    PCWSTR MaxOp;
} WL_WORKER, *PWL_WORKER;

static
BOOL
WlWait(
    _In_ HANDLE File,
    _In_ BOOL Ok,
    _Inout_ LPOVERLAPPED Ov)
{
    DWORD Done;

    if (!Ok && GetLastError() == ERROR_IO_PENDING)
        Ok = GetOverlappedResult(File, Ov, &Done, TRUE);
    return Ok;
}

static
DWORD
WINAPI
WlWorker(
    _In_ PVOID Parameter)
{
    PWL_WORKER W = Parameter;
    WCHAR U[MAX_PATH], Name[64];
    HANDLE File;
    OVERLAPPED Ov;
    PUCHAR Data;
    DWORD Start, T0, Latency;
    ULONG i;

    Data = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"race\\wl%lu.bin", W->Index);
    File = CreateFileW(P(U, TRUE, Name), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       CREATE_ALWAYS, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    if (File == INVALID_HANDLE_VALUE || Data == NULL)
    {
        W->Failures++;
        return 1;
    }
    RtlZeroMemory(&Ov, sizeof(Ov));
    Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    for (i = 0; i < 16; ++i)
    {
        Ov.Offset = i * 4096;
        ResetEvent(Ov.hEvent);
        WlWait(File, WriteFile(File, Data, 4096, NULL, &Ov), &Ov);
    }

    Start = GetTickCount();
    for (i = 0; GetTickCount() - Start < W->Seconds * 1000; ++i)
    {
        static const PCWSTR Names[] = { L"lock", L"unlock", L"read" };
        ULONG k;

        for (k = 0; k < 3; ++k)
        {
            BOOL Ok;

            Ov.Offset = (i % 16) * 4096;
            ResetEvent(Ov.hEvent);
            T0 = GetTickCount();
            if (k == 0)
                Ok = WlWait(File, LockFileEx(File, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &Ov), &Ov);
            else if (k == 1)
                Ok = WlWait(File, UnlockFileEx(File, 0, 4096, 0, &Ov), &Ov);
            else
                Ok = WlWait(File, ReadFile(File, Data, 4096, NULL, &Ov), &Ov);
            Latency = GetTickCount() - T0;
            W->Ops++;
            if (!Ok)
                W->Failures++;
            if (Latency > W->MaxLatency)
            {
                W->MaxLatency = Latency;
                W->MaxOp = Names[k];
            }
        }
    }
    CloseHandle(Ov.hEvent);
    CloseHandle(File);
    VirtualFree(Data, 0, MEM_RELEASE);
    return 0;
}

static
VOID
TestWaitingLockNoStall(VOID)
{
    WCHAR U[MAX_PATH], Env[16];
    HANDLE Holder, Waiter, Threads[3];
    OVERLAPPED HolderOv, LockOv;
    WL_WORKER Workers[3];
    LOOPRDR_COUNTERS Counters;
    DWORD Seconds = 25, T0, Latency, Done;
    ULONG i;
    BOOL Ok;

    if (GetEnvironmentVariableW(L"RDBSS_WL_SECS", Env, RTL_NUMBER_OF(Env)))
        Seconds = wcstoul(Env, NULL, 10);
    LoopOptions(0, 0);
    Holder = CreateFileW(P(U, TRUE, L"race\\wlock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);
    Waiter = CreateFileW(P(U, TRUE, L"race\\wlock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (Holder == INVALID_HANDLE_VALUE || Waiter == INVALID_HANDLE_VALUE)
    {
        ok(FALSE, "opens failed: %lu\n", GetLastError());
        goto out;
    }
    RtlZeroMemory(&HolderOv, sizeof(HolderOv));
    RtlZeroMemory(&LockOv, sizeof(LockOv));
    HolderOv.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    LockOv.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ok(WlWait(Holder, LockFileEx(Holder, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &HolderOv), &HolderOv),
       "holder lock: %lu\n", GetLastError());

    /* The waiting lock */
    Ok = LockFileEx(Waiter, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &LockOv);
    ok(!Ok && GetLastError() == ERROR_IO_PENDING, "waiting lock: ok %d, error %lu (expected pending)\n", Ok, GetLastError());
    Sleep(300);

    /* Three other users of the redirector, on other files */
    for (i = 0; i < 3; ++i)
    {
        RtlZeroMemory(&Workers[i], sizeof(Workers[i]));
        Workers[i].Index = i;
        Workers[i].Seconds = Seconds;
        Workers[i].MaxOp = L"-";
        Threads[i] = CreateThread(NULL, 0, WlWorker, &Workers[i], 0, NULL);
    }
    for (i = 0; i < 3; ++i)
    {
        if (Threads[i] != NULL)
        {
            WaitForSingleObject(Threads[i], (Seconds + 120) * 1000);
            CloseHandle(Threads[i]);
        }
        trace("waiting lock: worker %lu: %lu operations, %lu failed, slowest %lu ms (%ls)\n", i, Workers[i].Ops,
              Workers[i].Failures, Workers[i].MaxLatency, Workers[i].MaxOp);
        ok(Workers[i].Ops > 0 && Workers[i].Failures == 0, "worker %lu: %lu operations, %lu failed\n", i,
           Workers[i].Ops, Workers[i].Failures);
        ok(Workers[i].MaxLatency < 1000, "worker %lu: an operation took %lu ms (%ls) behind a waiting lock\n", i,
           Workers[i].MaxLatency, Workers[i].MaxOp);
    }
    ok(WaitForSingleObject(LockOv.hEvent, 0) == WAIT_TIMEOUT, "the waiting lock ended before it was cancelled\n");

    /* CancelIoEx reaches the waiting lock */
    T0 = GetTickCount();
    HostileCancel(Waiter, &LockOv);
    Ok = GetOverlappedResult(Waiter, &LockOv, &Done, TRUE);
    Latency = GetTickCount() - T0;
    trace("waiting lock: cancel done after %lu ms, ok %d, error %lu\n", Latency, Ok, Ok ? 0 : GetLastError());
    ok(!Ok && GetLastError() == ERROR_OPERATION_ABORTED, "cancelled lock: ok %d, error %lu\n", Ok, GetLastError());
    ok(Latency < 1000, "cancel took %lu ms\n", Latency);

    /* Closing the handle ends a waiting lock */
    ResetEvent(LockOv.hEvent);
    Ok = LockFileEx(Waiter, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &LockOv);
    ok(!Ok && GetLastError() == ERROR_IO_PENDING, "second waiting lock: ok %d, error %lu\n", Ok, GetLastError());
    Sleep(300);
    T0 = GetTickCount();
    CloseHandle(Waiter);
    Waiter = INVALID_HANDLE_VALUE;
    ok(WaitForSingleObject(LockOv.hEvent, 5000) == WAIT_OBJECT_0, "lock not ended by the cleanup of its handle\n");
    Latency = GetTickCount() - T0;
    trace("waiting lock: ended %lu ms after CloseHandle, status %lx\n", Latency, (ULONG)LockOv.Internal);
    ok(Latency < 1000, "close took %lu ms to end the waiting lock\n", Latency);
    ok((ULONG)LockOv.Internal != 0, "a lock granted after the cleanup of its handle\n");

    /* A waiting lock is granted when the holder unlocks */
    Waiter = CreateFileW(P(U, TRUE, L"race\\wlock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    ok(Waiter != INVALID_HANDLE_VALUE, "reopen: %lu\n", GetLastError());
    if (Waiter != INVALID_HANDLE_VALUE)
    {
        ResetEvent(LockOv.hEvent);
        Ok = LockFileEx(Waiter, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &LockOv);
        ok(!Ok && GetLastError() == ERROR_IO_PENDING, "third waiting lock: ok %d, error %lu\n", Ok, GetLastError());
        Sleep(300);
        ResetEvent(HolderOv.hEvent);
        T0 = GetTickCount();
        ok(WlWait(Holder, UnlockFileEx(Holder, 0, 4096, 0, &HolderOv), &HolderOv), "holder unlock: %lu\n", GetLastError());
        Ok = GetOverlappedResult(Waiter, &LockOv, &Done, TRUE);
        Latency = GetTickCount() - T0;
        trace("waiting lock: granted %lu ms after the unlock (ok %d)\n", Latency, Ok);
        ok(Ok, "third waiting lock not granted: %lu\n", GetLastError());
        ok(Latency < 1000, "grant took %lu ms\n", Latency);
        ResetEvent(LockOv.hEvent);
        ok(WlWait(Waiter, UnlockFileEx(Waiter, 0, 4096, 0, &LockOv), &LockOv), "unlock: %lu\n", GetLastError());
    }
    CloseHandle(HolderOv.hEvent);
    CloseHandle(LockOv.hEvent);

    LoopCounters(&Counters);
    trace("waiting lock: pended %ld, granted %ld, cancelled %ld, timed out %ld, still pending %ld\n",
          Counters.LocksPended, Counters.LocksPendingGranted, Counters.LocksPendingCancelled,
          Counters.LocksPendingTimedOut, Counters.LocksPendingNow);
    ok(Counters.LocksPendingNow == 0, "%ld locks still pending at the mini-redirector\n", Counters.LocksPendingNow);

out:
    if (Holder != INVALID_HANDLE_VALUE) CloseHandle(Holder);
    if (Waiter != INVALID_HANDLE_VALUE) CloseHandle(Waiter);
    LoopOptions(FCB_ALL_CACHE, 0);
}

/* c: a lock request still queued for the FSP when its handle is closed. The
 * FSP is kept busy by a read posted behind a slow flush on another file; an
 * overlapped lock of handle H queues behind it; H is closed (its cleanup
 * runs at once: its FCB is free). When the FSP gets to the lock, the handle
 * is cleaned up: the lock must not be granted (it would be held, locally and
 * at the server, by a handle that no longer exists, and nobody could unlock
 * it), and another handle must get the range. Both with locks sent to the
 * server and with lock buffering (FsRtl). (RDBSS refuses it with
 * STATUS_FILE_CLOSED when it takes the FCB: RxVerifyOperationIsLegal) */
static
VOID
TestLockQueuedAtClose(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE H, G, Writer, Reader, Thread;
    OVERLAPPED LockOv, ReadOv;
    PUCHAR Data;
    DWORD Done, Error, Buffering;
    BOOL Ok, Granted;
    ULONG Round, Orphans = 0, Cancelled = 0, Early = 0;

    Data = VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    if (Data == NULL)
        return;
    LoopOptions(0, 0);
    Writer = CreateFileW(P(U, TRUE, L"race\\qother.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, CREATE_ALWAYS, 0, NULL);
    Reader = CreateFileW(P(U, TRUE, L"race\\qother.bin"), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    G = CreateFileW(P(U, TRUE, L"race\\qlock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, CREATE_ALWAYS, 0, NULL);
    if (Writer == INVALID_HANDLE_VALUE || Reader == INVALID_HANDLE_VALUE || G == INVALID_HANDLE_VALUE)
    {
        ok(FALSE, "opens failed: %lu\n", GetLastError());
        goto out;
    }
    WriteFile(Writer, Data, 65536, &Done, NULL);
    RtlZeroMemory(&LockOv, sizeof(LockOv));
    RtlZeroMemory(&ReadOv, sizeof(ReadOv));
    LockOv.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ReadOv.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    CloseHandle(G);
    G = INVALID_HANDLE_VALUE;
    for (Round = 0; Round < 4; ++Round)
    {
        /* Rounds 0-1: locks go to the "server" (which refuses a lock on a
         * server open that the cleanup closed: the loopback has one per
         * handle). Rounds 2-3: lock buffering granted, locks are kept by
         * RDBSS in the FCB's FILE_LOCK (FsRtl) */
        Buffering = (Round < 2) ? 0 : FCB_LOCK_BUF;
        LoopOptions(Buffering, 0);
        G = CreateFileW(P(U, TRUE, L"race\\qlock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
        H = CreateFileW(P(U, TRUE, L"race\\qlock.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (H == INVALID_HANDLE_VALUE || G == INVALID_HANDLE_VALUE)
        {
            ok(FALSE, "open H/G: %lu\n", GetLastError());
            break;
        }
        {
            LOOPRDR_COUNTERS C0, C1;
            OVERLAPPED Ov0;

            /* Where do this FCB's locks go (the server counts its locks)? */
            RtlZeroMemory(&Ov0, sizeof(Ov0));
            Ov0.Offset = 8192;
            LoopCounters(&C0);
            LockFileEx(G, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 16, 0, &Ov0);
            LoopCounters(&C1);
            UnlockFileEx(G, 0, 16, 0, &Ov0);
            trace("round %lu: a lock of this FCB went to the %s\n", Round, (C1.Locks != C0.Locks) ? "server" : "FCB's FILE_LOCK");
        }

        /* Occupy the FSP: a read posted behind a 500 ms flush of its FCB */
        LoopOptions(Buffering, LOOPRDR_OPT_SLOW_FLUSH);
        Thread = CreateThread(NULL, 0, SlowFlushThread, Writer, 0, NULL);
        Sleep(150);
        ResetEvent(ReadOv.hEvent);
        Ok = ReadFile(Reader, Data, 4096, NULL, &ReadOv);
        Sleep(50);

        /* The lock queues behind the read; then its handle goes away */
        ResetEvent(LockOv.hEvent);
        LockOv.Offset = 0;
        Ok = LockFileEx(H, LOCKFILE_EXCLUSIVE_LOCK, 0, 4096, 0, &LockOv);
        if (Ok || GetLastError() != ERROR_IO_PENDING)
            ++Early;
        CloseHandle(H);

        Granted = GetOverlappedResult(H, &LockOv, &Done, TRUE);
        Error = Granted ? 0 : GetLastError();
        if (Error == ERROR_INVALID_HANDLE)
        {
            /* H is closed: wait on the event itself */
            WaitForSingleObject(LockOv.hEvent, 60000);
            Granted = (LockOv.Internal == 0);
            Error = (ULONG)LockOv.Internal;
        }
        GetOverlappedResult(Reader, &ReadOv, &Done, TRUE);
        if (Thread != NULL)
        {
            WaitForSingleObject(Thread, INFINITE);
            CloseHandle(Thread);
        }
        LoopOptions(Buffering, 0);
        Sleep(200);

        /* Another handle must get the range now */
        RtlZeroMemory(&ReadOv, sizeof(ReadOv) - sizeof(HANDLE));
        Ok = LockFileEx(G, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 4096, 0, &ReadOv);
        trace("round %lu (%s): queued lock of the closed handle: %s (status %lx); other handle's lock afterwards: %s (%lu)\n",
              Round, Buffering ? "lock buffering" : "server locks", Granted ? "granted" : "not granted", Error,
              Ok ? "granted" : "refused", Ok ? 0 : GetLastError());
        if (Ok)
        {
            UnlockFileEx(G, 0, 4096, 0, &ReadOv);
        }
        else
        {
            ++Orphans;
        }
        if (!Granted)
            ++Cancelled;
        CloseHandle(G);
        G = INVALID_HANDLE_VALUE;
    }
    ok(Orphans == 0, "%lu of 4 locks were left held by a closed handle\n", Orphans);
    ok(Cancelled == 4, "%lu of 4 queued locks of a closed handle were not granted (expected 4)\n", Cancelled);
    trace("locks not queued (answered at once): %lu\n", Early);
    CloseHandle(LockOv.hEvent);
    CloseHandle(ReadOv.hEvent);

out:
    if (Writer != INVALID_HANDLE_VALUE) CloseHandle(Writer);
    if (Reader != INVALID_HANDLE_VALUE) CloseHandle(Reader);
    if (G != INVALID_HANDLE_VALUE) CloseHandle(G);
    VirtualFree(Data, 0, MEM_RELEASE);
    LoopOptions(FCB_ALL_CACHE, 0);
}

/* t: the end of file and a mapped view (RdbssHostile's "truncated under a
 * mapped view" check). (1) A view of the whole 64 KB file: setting the end
 * of file to 2000 must fail, and the size stays. (2) The race of the
 * hostile check, done in order: the size is queried (64 KB), another handle
 * sets the end of file to 100, the file is mapped (the section is 100
 * bytes), and the end of file is set to 2000: an extension past the
 * section, which must succeed although 2000 is below the size queried */
static
VOID
TestEofUnderView(VOID)
{
    WCHAR U[MAX_PATH];
    HANDLE F, Other, Section;
    PUCHAR View;
    LARGE_INTEGER Size, Small, Now;
    BOOL Ok;

    LoopOptions(FCB_ALL_CACHE, 0);
    F = CreateFileW(P(U, TRUE, L"race\\eofview.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, CREATE_ALWAYS, 0, NULL);
    Other = CreateFileW(P(U, TRUE, L"race\\eofview.bin"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (F == INVALID_HANDLE_VALUE || Other == INVALID_HANDLE_VALUE)
    {
        ok(FALSE, "opens failed: %lu\n", GetLastError());
        goto out;
    }

    /* (1) */
    Size.QuadPart = 65536;
    SetFilePointerEx(F, Size, NULL, FILE_BEGIN);
    ok(SetEndOfFile(F), "extend: %lu\n", GetLastError());
    Section = CreateFileMappingW(F, NULL, PAGE_READWRITE, 0, 0, NULL);
    ok(Section != NULL, "section: %lu\n", GetLastError());
    View = Section ? MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    ok(View != NULL, "view: %lu\n", GetLastError());
    Small.QuadPart = 2000;
    SetFilePointerEx(F, Small, NULL, FILE_BEGIN);
    Ok = SetEndOfFile(F);
    ok(!Ok && GetLastError() == ERROR_USER_MAPPED_FILE, "truncation under a view: %d, %lu\n", Ok, GetLastError());
    ok(GetFileSizeEx(F, &Now) && Now.QuadPart == 65536, "size after: %I64d\n", Now.QuadPart);
    if (View != NULL)
        UnmapViewOfFile(View);
    if (Section != NULL)
        CloseHandle(Section);

    /* (2) */
    ok(GetFileSizeEx(F, &Size) && Size.QuadPart == 65536, "queried size %I64d\n", Size.QuadPart);
    Small.QuadPart = 100;
    SetFilePointerEx(Other, Small, NULL, FILE_BEGIN);
    ok(SetEndOfFile(Other), "other handle's truncation (no view yet): %lu\n", GetLastError());
    Section = CreateFileMappingW(F, NULL, PAGE_READWRITE, 0, 0, NULL);
    View = Section ? MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    ok(View != NULL, "view: %lu\n", GetLastError());
    Small.QuadPart = 2000;
    SetFilePointerEx(F, Small, NULL, FILE_BEGIN);
    Ok = SetEndOfFile(F);
    ok(Ok, "extension past a 100-byte section: %lu\n", GetLastError());
    trace("queried %I64d, end of file set to 2000 under a view of the 100-byte section: %s (what RdbssHostile used to report as a truncation)\n",
          Size.QuadPart, Ok ? "allowed" : "refused");
    if (View != NULL)
        UnmapViewOfFile(View);
    if (Section != NULL)
        CloseHandle(Section);

out:
    if (F != INVALID_HANDLE_VALUE) CloseHandle(F);
    if (Other != INVALID_HANDLE_VALUE) CloseHandle(Other);
}

/* Names the server-specs canonicalization walks to their last character:
 * short last components, dots, stream colons (with special pool on the RDBSS
 * tags, a read past the name stops the machine) */
static
VOID
TestOddNames(VOID)
{
    static const PCWSTR Names[] =
    {
        L"ab", L"race\\ab", L"race\\a.", L"race\\.b", L"race\\..x", L"race\\ab:s", L"race\\a:b", L"race\\x\\..\\ab",
        L"a", L"race\\b", L"race\\abc", L"race\\ab\\", L"race\\.."
    };
    WCHAR U[MAX_PATH], Rel[64];
    ULONG i, k;
    HANDLE H;

    LoopOptions(FCB_ALL_CACHE, 0);
    for (i = 0; i < RTL_NUMBER_OF(Names); ++i)
    {
        H = CreateFileW(P(U, TRUE, Names[i]), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
        trace("odd name %ls: %s (%lu)\n", Names[i], H != INVALID_HANDLE_VALUE ? "opened" : "refused",
              H != INVALID_HANDLE_VALUE ? 0 : GetLastError());
        if (H != INVALID_HANDLE_VALUE)
            CloseHandle(H);
    }
    /* A last component of two characters after every name length modulo the
     * pool granularity, so that the name ends where its block ends at least
     * once (the directories do not exist: the name is canonicalized all the
     * same) */
    for (k = 1; k <= 24; ++k)
    {
        for (i = 0; i < k; ++i)
            Rel[i] = L'd';
        Rel[k] = L'\\';
        Rel[k + 1] = L'a';
        Rel[k + 2] = L'b';
        Rel[k + 3] = 0;
        H = CreateFileW(P(U, TRUE, Rel), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (H != INVALID_HANDLE_VALUE)
            CloseHandle(H);
    }
}

/* An image section of a file on the share (the loader's read of the
 * headers and the image pages go through RDBSS) */
static
VOID
TestImageSection(VOID)
{
    WCHAR U[MAX_PATH], Dll[MAX_PATH];
    HANDLE H, Section;
    PVOID View;

    LoopOptions(FCB_ALL_CACHE, 0);
    GetSystemDirectoryW(Dll, MAX_PATH);
    StringCchCatW(Dll, MAX_PATH, L"\\version.dll");
    ok(CopyFileW(Dll, P(U, TRUE, L"race\\img.dll"), FALSE), "copy %ls: %lu\n", Dll, GetLastError());
    H = CreateFileW(U, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "open: %lu\n", GetLastError());
    if (H == INVALID_HANDLE_VALUE)
        return;
    Section = CreateFileMappingW(H, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    trace("image section on the share: %s (%lu)\n", Section != NULL ? "created" : "refused", Section != NULL ? 0 : GetLastError());
    if (Section != NULL)
    {
        View = MapViewOfFile(Section, FILE_MAP_READ, 0, 0, 0);
        ok(View != NULL, "map image: %lu\n", GetLastError());
        if (View != NULL)
        {
            ok(((PUCHAR)View)[0] == 'M' && ((PUCHAR)View)[1] == 'Z', "image does not start with MZ\n");
            UnmapViewOfFile(View);
        }
        CloseHandle(Section);
    }
    CloseHandle(H);
    DeleteFileW(U);
}

/* The server breaks the oplock of a handle being closed: the buffering state
 * handler must not touch the closed SRV_OPEN or a freed FCB, and must still
 * work afterwards */
static
VOID
TestBreakInClose(VOID)
{
    WCHAR U[MAX_PATH], Rel[64];
    HANDLE H;
    UCHAR Data[4096];
    DWORD Done;
    ULONG i;
    LOOPRDR_BREAK Break;
    LOOPRDR_COUNTERS C;

    LoopOptions(FCB_ALL_CACHE, LOOPRDR_OPT_BREAK_IN_CLOSE);
    Fill(Data, sizeof(Data), 77);
    for (i = 0; i < 10; ++i)
    {
        StringCchPrintfW(Rel, 64, L"race\\bic%lu.bin", i);
        H = CreateFileW(P(U, TRUE, Rel), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ok(H != INVALID_HANDLE_VALUE, "create %lu: %lu\n", i, GetLastError());
        if (H == INVALID_HANDLE_VALUE)
            continue;
        WriteFile(H, Data, sizeof(Data), &Done, NULL);
        CloseHandle(H);
    }
    /* Delayed closes happen in the scavenger (2 s) */
    Sleep(5000);
    LoopOptions(FCB_ALL_CACHE, 0);

    /* The handler is still alive: a break is acknowledged */
    H = CreateFileW(P(U, TRUE, L"race\\probe.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create probe: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        WriteFile(H, Data, sizeof(Data), &Done, NULL);
        Break.FileHandle = (ULONG_PTR)H;
        Break.NewBufferingState = 0;
        Break.Flags = LOOPRDR_BREAK_WAIT;
        ok(LoopIoctl(IOCTL_LOOPRDR_BREAK, &Break, sizeof(Break), NULL, 0), "break after the closes: %lu\n", GetLastError());
        CloseHandle(H);
    }
    LoopCounters(&C);
    trace("breaks indicated in close: %ld\n", C.BreaksInClose);
    ok(C.BreaksInClose > 0, "no break was indicated in a close\n");
}

/* Two logon sessions on one share: each gets its own V_NET_ROOT. A lookup
 * that finds the other logon's V_NET_ROOT first must go on with the one of
 * its own logon (it went on with the other's, without a reference: freed
 * while still in use once the other logon closed its files) */
typedef struct _RACE_USER_INFO_1
{
    LPWSTR Name;
    LPWSTR Password;
    DWORD PasswordAge;
    DWORD Priv;
    LPWSTR HomeDir;
    LPWSTR Comment;
    DWORD Flags;
    LPWSTR ScriptPath;
} RACE_USER_INFO_1;
typedef DWORD (WINAPI *PFN_NETUSERADD)(LPCWSTR, DWORD, LPBYTE, LPDWORD);
typedef DWORD (WINAPI *PFN_NETUSERDEL)(LPCWSTR, LPCWSTR);

static
VOID
TestTwoLogons(VOID)
{
    WCHAR U[MAX_PATH], Rel[64];
    WCHAR User[] = L"rdbssrace", Password[] = L"Rdbss-race-7";
    HMODULE Net;
    PFN_NETUSERADD pNetUserAdd;
    PFN_NETUSERDEL pNetUserDel;
    RACE_USER_INFO_1 Info;
    HANDLE Token = NULL, Mine[8], Theirs[8];
    DWORD Error, Done;
    ULONG Round, i;

    Net = LoadLibraryW(L"netapi32.dll");
    pNetUserAdd = Net ? (PFN_NETUSERADD)GetProcAddress(Net, "NetUserAdd") : NULL;
    pNetUserDel = Net ? (PFN_NETUSERDEL)GetProcAddress(Net, "NetUserDel") : NULL;
    if (pNetUserAdd == NULL || pNetUserDel == NULL)
    {
        skip(FALSE, "no NetUserAdd\n");
        return;
    }
    RtlZeroMemory(&Info, sizeof(Info));
    Info.Name = User;
    Info.Password = Password;
    Info.Priv = 1;              /* USER_PRIV_USER */
    Info.Flags = 0x10001;       /* UF_SCRIPT | UF_DONT_EXPIRE_PASSWD */
    Error = pNetUserAdd(NULL, 1, (LPBYTE)&Info, NULL);
    if (Error != 0 && Error != 2224)    /* NERR_UserExists */
    {
        skip(FALSE, "NetUserAdd: %lu\n", Error);
        return;
    }
    if (!LogonUserW(User, L".", Password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &Token))
    {
        skip(FALSE, "LogonUser: %lu\n", GetLastError());
        pNetUserDel(NULL, User);
        return;
    }

    for (Round = 0; Round < 6; ++Round)
    {
        /* Alternate which logon opens first, so that both lookup orders
         * occur; keep every handle until the end of the round */
        for (i = 0; i < 8; ++i)
        {
            BOOLEAN UserFirst = ((Round + i) & 1) != 0;
            ULONG Pass;

            StringCchPrintfW(Rel, 64, L"race\\logon%lu.bin", i);
            for (Pass = 0; Pass < 2; ++Pass)
            {
                BOOLEAN AsUser = (Pass == 0) == UserFirst;
                HANDLE H;

                if (AsUser && !ImpersonateLoggedOnUser(Token))
                {
                    ok(0, "impersonate: %lu\n", GetLastError());
                    continue;
                }
                H = CreateFileW(P(U, TRUE, Rel), GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_ALWAYS, 0, NULL);
                Error = GetLastError();
                if (AsUser)
                    RevertToSelf();
                ok(H != INVALID_HANDLE_VALUE, "round %lu file %lu %s: %lu\n", Round, i, AsUser ? "user" : "self", Error);
                if (H != INVALID_HANDLE_VALUE)
                    WriteFile(H, Rel, sizeof(Rel), &Done, NULL);
                if (AsUser)
                    Theirs[i] = H;
                else
                    Mine[i] = H;
            }
        }
        /* One logon's files closed first, then the other's */
        for (i = 0; i < 8; ++i)
        {
            HANDLE First = (Round & 1) ? Mine[i] : Theirs[i];
            if (First != INVALID_HANDLE_VALUE)
                CloseHandle(First);
        }
        /* Let the scavenger finalize what the first logon left */
        Sleep(3000);
        for (i = 0; i < 8; ++i)
        {
            HANDLE Second = (Round & 1) ? Theirs[i] : Mine[i];
            if (Second != INVALID_HANDLE_VALUE)
            {
                ok(ReadFile(Second, Rel, sizeof(Rel), &Done, NULL) || GetLastError() == ERROR_HANDLE_EOF,
                   "round %lu file %lu: read after the other logon closed: %lu\n", Round, i, GetLastError());
                CloseHandle(Second);
            }
        }
    }
    CloseHandle(Token);
    pNetUserDel(NULL, User);
    FreeLibrary(Net);
}

/* The name of a share file as the object manager asks for it: the size the
 * first query returns must be enough for the second (process creation from
 * a share asks for the image's name this way), and a program on the share
 * must run */
typedef LONG (NTAPI *PFN_NTQUERYOBJECT)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static
VOID
TestNameQueryAndProgram(VOID)
{
    WCHAR U[MAX_PATH], Exe[MAX_PATH], Cmd[MAX_PATH + 32];
    PFN_NTQUERYOBJECT pNtQueryObject;
    UCHAR Small[sizeof(UNICODE_STRING)];
    PUNICODE_STRING Name;
    ULONG Needed = 0, Got = 0;
    LONG Status;
    HANDLE H;
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    DWORD Code = 0xFFFF;

    pNtQueryObject = (PFN_NTQUERYOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    H = CreateFileW(P(U, TRUE, L"race\\name-query.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE && pNtQueryObject != NULL)
    {
        Status = pNtQueryObject(H, 1 /* ObjectNameInformation */, Small, sizeof(Small), &Needed);
        ok(Status == (LONG)0x80000005 && Needed > sizeof(Small), "small query: %lx, %lu\n", Status, Needed);
        Name = HeapAlloc(GetProcessHeap(), 0, Needed);
        if (Name != NULL)
        {
            Status = pNtQueryObject(H, 1, Name, Needed, &Got);
            ok(Status == 0, "query with the size the first one returned (%lu): %lx (needs %lu)\n", Needed, Status, Got);
            if (Status == 0)
                trace("object name %.*ls\n", (int)(Name->Length / sizeof(WCHAR)), Name->Buffer);
            HeapFree(GetProcessHeap(), 0, Name);
        }
        CloseHandle(H);
    }

    /* A program on the share */
    GetSystemDirectoryW(Exe, MAX_PATH);
    StringCchCatW(Exe, MAX_PATH, L"\\find.exe");
    ok(CopyFileW(Exe, P(U, TRUE, L"race\\rfind.exe"), FALSE), "copy find.exe: %lu\n", GetLastError());
    StringCchPrintfW(Cmd, RTL_NUMBER_OF(Cmd), L"\"%s\" /?", U);
    RtlZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    if (CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
    {
        ok(WaitForSingleObject(Pi.hProcess, 30000) == WAIT_OBJECT_0, "the program did not end\n");
        GetExitCodeProcess(Pi.hProcess, &Code);
        trace("find.exe from the share exited with %lu\n", Code);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
    }
    else
    {
        ok(0, "CreateProcess of a program on the share: %lu\n", GetLastError());
    }
    /* Mm keeps the image section (and its file) until the file is deleted:
     * delete it, or the redirector cannot stop at the end of the test */
    ok(DeleteFileW(U), "delete the program: %lu\n", GetLastError());
    Sleep(3000);
}

START_TEST(RdbssRaces)
{
    POOL_SUM Before;
    WCHAR L[MAX_PATH];

    if (!LoopSetUp(&Before))
        return;
    CreateDirectoryW(P(L, FALSE, L"race"), NULL);

    /* First: no connection structure exists yet */
    if (RaceSelected(L's'))
        TestStopVsCreate();
    if (RaceSelected(L'i'))
        TestInternalInfo();
    if (RaceSelected(L'a'))
        TestAllInfo();
    if (RaceSelected(L'o'))
        TestInlineAsync();
    if (RaceSelected(L'p'))
        TestPostedAsyncRead();
    if (RaceSelected(L'q'))
        TestCachedFcbAsyncRead();
    if (RaceSelected(L'l'))
        TestWaitingLockBlocksFsp();
    if (RaceSelected(L'w'))
        TestWaitingLockNoStall();
    if (RaceSelected(L'c'))
        TestLockQueuedAtClose();
    if (RaceSelected(L't'))
        TestEofUnderView();
    if (RaceSelected(L'n'))
        TestOddNames();
    if (RaceSelected(L'm'))
        TestImageSection();
    if (RaceSelected(L'u'))
        TestUserBuffers();
    if (RaceSelected(L'b'))
        TestBreakInClose();
    if (RaceSelected(L'v'))
        TestTwoLogons();
    if (RaceSelected(L'x'))
        TestNameQueryAndProgram();

    LoopTearDown(&Before);
}

/* A mini-redirector that calls RxLowIoCompletion twice: RDBSS refuses the
 * second call (and a Debug build stops on an assertion right there) */
START_TEST(RdbssDupComplete)
{
    POOL_SUM Before;
    WCHAR U[MAX_PATH];
    HANDLE H;
    PUCHAR Data;
    DWORD Done;
    ULONG i;
    LOOPRDR_COUNTERS C;
    OVERLAPPED Ov;

    if (!LoopSetUp(&Before))
        return;

    /* Unbuffered handles: every read and write is a low I/O submission */
    LoopOptions(0, LOOPRDR_OPT_LATE | LOOPRDR_OPT_DUP_COMPLETE | LOOPRDR_OPT_ASYNC_LOWIO);
    Data = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
    if (Data == NULL)
        return;
    Fill(Data, 4096, 5);
    H = CreateFileW(P(U, TRUE, L"dup.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING, NULL);
    ok(H != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (H != INVALID_HANDLE_VALUE)
    {
        for (i = 0; i < 16; ++i)
        {
            WriteFile(H, Data, 4096, &Done, NULL);
            SetFilePointer(H, 0, NULL, FILE_BEGIN);
            ReadFile(H, Data, 4096, &Done, NULL);
        }
        CloseHandle(H);
    }
    H = CreateFileW(P(U, TRUE, L"dup.bin"), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, NULL);
    if (H != INVALID_HANDLE_VALUE)
    {
        RtlZeroMemory(&Ov, sizeof(Ov));
        Ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        for (i = 0; i < 16; ++i)
        {
            ResetEvent(Ov.hEvent);
            if (ReadFile(H, Data, 4096, NULL, &Ov) || GetLastError() == ERROR_IO_PENDING)
                ok(WaitForSingleObject(Ov.hEvent, 30000) == WAIT_OBJECT_0, "async read %lu never completed\n", i);
        }
        CloseHandle(Ov.hEvent);
        CloseHandle(H);
    }
    LoopOptions(FCB_ALL_CACHE, 0);
    LoopCounters(&C);
    trace("late completions %ld, second completions refused %ld\n", C.LateCompletions, C.DupRefused);
    ok(C.DupRefused > 0, "no second completion was refused\n");
    DeleteFileW(P(U, TRUE, L"dup.bin"));
    VirtualFree(Data, 0, MEM_RELEASE);

    LoopTearDown(&Before);
}

/* Runs "cmd /c copy /y From To" and returns its exit code */
static
DWORD
CmdCopy(
    _In_ PCWSTR From,
    _In_ PCWSTR To)
{
    WCHAR Cmd[3 * MAX_PATH];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    DWORD Code = 0xFFFFFFFF;

    RtlZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    StringCchPrintfW(Cmd, RTL_NUMBER_OF(Cmd), L"cmd.exe /c copy /y \"%s\" \"%s\"", From, To);
    if (!CreateProcessW(NULL, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
        return GetLastError();
    WaitForSingleObject(Pi.hProcess, INFINITE);
    GetExitCodeProcess(Pi.hProcess, &Code);
    CloseHandle(Pi.hProcess);
    CloseHandle(Pi.hThread);
    return Code;
}

/* Compares a file with the generator (Fill with Seed, 1 MB blocks), reading
 * it with ordinary buffered 64 KB reads */
static
BOOLEAN
SameAsGenerated(
    _In_ PCWSTR Path,
    _In_ ULONG Megabytes,
    _In_ ULONG Seed,
    _In_ PUCHAR Expected,
    _In_ PUCHAR Got)
{
    HANDLE H;
    ULONG Mb, Off;
    DWORD Done;
    BOOLEAN Same = TRUE;
    LARGE_INTEGER Size;

    H = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (H == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!GetFileSizeEx(H, &Size) || Size.QuadPart != (LONGLONG)Megabytes * 1024 * 1024)
        Same = FALSE;
    for (Mb = 0; Same && Mb < Megabytes; ++Mb)
    {
        Fill(Expected, 1024 * 1024, Seed + Mb);
        for (Off = 0; Off < 1024 * 1024; Off += 65536)
        {
            if (!ReadFile(H, Got + Off, 65536, &Done, NULL) || Done != 65536)
            {
                Same = FALSE;
                break;
            }
        }
        if (Same && memcmp(Expected, Got, 1024 * 1024) != 0)
            Same = FALSE;
    }
    CloseHandle(H);
    return Same;
}

/* The R2 shape through the loopback redirector: cmd copy of a large file to
 * the share, a buffered read of the copy, cmd copy back, compared byte for
 * byte; RDBSS_COPY_MB (300) and RDBSS_COPY_ROUNDS (10) */
START_TEST(RdbssCopy)
{
    POOL_SUM Before;
    WCHAR Src[MAX_PATH], U[MAX_PATH], Back[MAX_PATH];
    ULONG Megabytes, Rounds, Round, Mb;
    PUCHAR Expected, Got;
    HANDLE H;
    DWORD Done, Code;

    Megabytes = EnvNumber(L"RDBSS_COPY_MB", 300);
    Rounds = EnvNumber(L"RDBSS_COPY_ROUNDS", 10);
    Expected = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
    Got = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT, PAGE_READWRITE);
    if (Expected == NULL || Got == NULL)
        return;
    if (!LoopSetUp(&Before))
        return;

    /* The source lives outside the share root (the root is emptied) */
    StringCchCopyW(Src, MAX_PATH, L"C:\\RdbssCopySource.bin");
    StringCchCopyW(Back, MAX_PATH, L"C:\\RdbssCopyBack.bin");
    H = CreateFileW(Src, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(H != INVALID_HANDLE_VALUE, "source: %lu\n", GetLastError());
    if (H == INVALID_HANDLE_VALUE)
        goto out;
    for (Mb = 0; Mb < Megabytes; ++Mb)
    {
        Fill(Expected, 1024 * 1024, 300 + Mb);
        WriteFile(H, Expected, 1024 * 1024, &Done, NULL);
    }
    CloseHandle(H);

    for (Round = 0; Round < Rounds; ++Round)
    {
        DWORD T0 = GetTickCount();

        P(U, TRUE, L"r2copy.bin");
        Code = CmdCopy(Src, U);
        ok(Code == 0, "round %lu: copy to the share: %lu\n", Round, Code);
        ok(SameAsGenerated(U, Megabytes, 300, Expected, Got), "round %lu: buffered read of the copy differs\n", Round);
        Code = CmdCopy(U, Back);
        ok(Code == 0, "round %lu: copy from the share: %lu\n", Round, Code);
        ok(SameAsGenerated(Back, Megabytes, 300, Expected, Got), "round %lu: copy back differs\n", Round);
        DeleteFileW(Back);
        ok(DeleteFileW(U), "round %lu: delete: %lu\n", Round, GetLastError());
        trace("round %lu: %lu MB both ways in %lu ms\n", Round, Megabytes, GetTickCount() - T0);
    }

out:
    DeleteFileW(Src);
    LoopTearDown(&Before);
    VirtualFree(Expected, 0, MEM_RELEASE);
    VirtualFree(Got, 0, MEM_RELEASE);
}

/* Hostile callers on shared files, with a second process, while the
 * mini-redirector injects failures, late and DPC-level completions:
 * RDBSS_HOSTILE_SECONDS (60), RDBSS_HOSTILE_FLAGS (FAULTS | LATE |
 * DPC_COMPLETE), RDBSS_HOSTILE_CHILDREN (2) */
START_TEST(RdbssHostile)
{
    POOL_SUM Before, Mid;
    WCHAR L[MAX_PATH], Exe[MAX_PATH], Cmd[MAX_PATH + 128];
    PROCESS_INFORMATION Children[4];
    ULONG Seconds, Flags, ChildCount, i, Ops, Errors, Problems, Mask;
    LOOPRDR_COUNTERS C;
    PWCHAR Slash;

    Mask = EnvNumber(L"RDBSS_HOSTILE_OPS", 0xFFFFFFFF);
    Seconds = EnvNumber(L"RDBSS_HOSTILE_SECONDS", 60);
    Flags = EnvNumber(L"RDBSS_HOSTILE_FLAGS", LOOPRDR_OPT_FAULTS | LOOPRDR_OPT_LATE | LOOPRDR_OPT_DPC_COMPLETE);
    ChildCount = min(EnvNumber(L"RDBSS_HOSTILE_CHILDREN", 2), 4);

    RtlZeroMemory(Children, sizeof(Children));
    if (!LoopSetUp(&Before))
        return;
    CreateDirectoryW(P(L, FALSE, L"hostile"), NULL);
    LoopOptions(FCB_ALL_CACHE, Flags);

    /* The second process: rdbsshostile.exe next to kmtest.exe */
    GetModuleFileNameW(NULL, Exe, MAX_PATH);
    Slash = wcsrchr(Exe, L'\\');
    if (Slash != NULL)
        StringCchCopyW(Slash + 1, MAX_PATH - (Slash + 1 - Exe), L"rdbsshostile.exe");
    for (i = 0; i < ChildCount; ++i)
    {
        STARTUPINFOW Si;

        RtlZeroMemory(&Si, sizeof(Si));
        Si.cb = sizeof(Si);
        StringCchPrintfW(Cmd, RTL_NUMBER_OF(Cmd), L"\"%s\" %s\\hostile %lu %lu %lx", Exe, UNC_ROOT, Seconds, 1000 + i, Mask);
        ok(CreateProcessW(Exe, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Children[i]),
           "starting %ls: %lu\n", Exe, GetLastError());
    }

    Problems = HostileRun(UNC_ROOT L"\\hostile", 8, Seconds, 42, LoopDevice, Mask, &Ops, &Errors);
    trace("hostile (kmtest process): %lu s, 8 threads, %lu operations, %lu failed (expected with faults), %lu problems\n",
          Seconds, Ops, Errors, Problems);
    ok_eq_ulong(Problems, 0UL);

    for (i = 0; i < ChildCount; ++i)
    {
        DWORD Code = 0xFFFFFFFF;

        if (Children[i].hProcess == NULL)
            continue;
        ok(WaitForSingleObject(Children[i].hProcess, 300000) == WAIT_OBJECT_0, "child %lu did not end\n", i);
        GetExitCodeProcess(Children[i].hProcess, &Code);
        trace("hostile child %lu: exit %lu (problems)\n", i, Code);
        ok(Code == 0, "child %lu reported %lu problems\n", i, Code);
        CloseHandle(Children[i].hProcess);
        CloseHandle(Children[i].hThread);
    }

    LoopOptions(FCB_ALL_CACHE, 0);
    LoopCounters(&C);
    trace("faults injected %ld, late completions %ld (DPC %ld), pending %ld\n",
          C.FaultsInjected, C.LateCompletions, C.DpcCompletions, C.PendingAsync);
    if (PoolSum(&Mid))
        trace("RDBSS pool tags at the end of the run (mounted): %I64d blocks/%I64d bytes: %s\n", Mid.Outstanding, Mid.Bytes, Mid.Detail);

    LoopTearDown(&Before);
}

/* Byte-range lock torture (RdbssLockTorture.h): 6 model and 2 chaos threads
 * in this process and in a second one (whose chaos threads are terminated at
 * random), plus a third process that takes waiting locks and is terminated
 * every 1-3 s. RDBSS_LT_SECONDS (60), RDBSS_LT_FLAGS (loopback options, 0).
 * At the end every range must be free again and nothing may wait at the
 * mini-redirector */
typedef struct _LT_ARGS
{
    PCWSTR Root;
    ULONG Seconds;
    ULONG Seed;
    ULONG Problems;
} LT_ARGS;

static
DWORD
WINAPI
LtSelfThread(
    _In_ PVOID Parameter)
{
    LT_ARGS *Args = Parameter;

    /* This process: model and chaos threads, none terminated (a handle a
     * terminated thread had not closed would outlive the test here) */
    Args->Problems = LtRun(Args->Root, 0, Args->Seconds, Args->Seed, TRUE, FALSE);
    return 0;
}

START_TEST(RdbssLockTorture)
{
    POOL_SUM Before;
    WCHAR L[MAX_PATH], Root[MAX_PATH], Exe[MAX_PATH], Cmd[MAX_PATH + 128];
    PROCESS_INFORMATION Partner, Victim;
    STARTUPINFOW Si;
    ULONG Seconds, Flags, Seed, Problems, File, Victims = 0;
    DWORD Code, End;
    LOOPRDR_COUNTERS C;
    PWCHAR Slash;
    HANDLE F;

    Seconds = EnvNumber(L"RDBSS_LT_SECONDS", 60);
    Flags = EnvNumber(L"RDBSS_LT_FLAGS", 0);
    Seed = EnvNumber(L"RDBSS_LT_SEED", 7);
    if (!LoopSetUp(&Before))
        return;
    CreateDirectoryW(P(L, FALSE, L"lt"), NULL);
    for (File = 0; File < LT_FILES; ++File)
    {
        WCHAR Name[32];

        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"lt\\f%lu.bin", File);
        F = CreateFileW(P(L, TRUE, Name), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        CREATE_ALWAYS, 0, NULL);
        ok(F != INVALID_HANDLE_VALUE, "create %ls: %lu\n", Name, GetLastError());
        if (F != INVALID_HANDLE_VALUE)
            CloseHandle(F);
    }
    LoopOptions(0, Flags);
    StringCchPrintfW(Root, RTL_NUMBER_OF(Root), L"%s\\lt", UNC_ROOT);

    GetModuleFileNameW(NULL, Exe, MAX_PATH);
    Slash = wcsrchr(Exe, L'\\');
    if (Slash != NULL)
        StringCchCopyW(Slash + 1, MAX_PATH - (Slash + 1 - Exe), L"rdbsshostile.exe");
    RtlZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    RtlZeroMemory(&Partner, sizeof(Partner));
    RtlZeroMemory(&Victim, sizeof(Victim));
    /* The shared table must exist before the other processes open it: the
     * partner creates or opens the same named mapping, so either order works */
    StringCchPrintfW(Cmd, RTL_NUMBER_OF(Cmd), L"\"%s\" lt %s %lu %lu 1 1 1", Exe, Root, Seconds, Seed + 1);
    ok(CreateProcessW(Exe, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Partner), "start partner: %lu\n", GetLastError());

    /* The victim process: started and terminated in a loop by a thread of
     * ours would complicate things; do it from here, in slices, while this
     * process's own threads run */
    {
        HANDLE Self;
        static LT_ARGS Args;

        Args.Root = Root;
        Args.Seconds = Seconds;
        Args.Seed = Seed;
        Self = CreateThread(NULL, 0, LtSelfThread, &Args, 0, NULL);
        End = GetTickCount() + Seconds * 1000;
        while ((LONG)(GetTickCount() - End) < 0)
        {
            StringCchPrintfW(Cmd, RTL_NUMBER_OF(Cmd), L"\"%s\" lt %s %lu %lu 2 0 0", Exe, Root, Seconds + 60, Seed + 100 + Victims);
            if (CreateProcessW(Exe, Cmd, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Victim))
            {
                Sleep(1000 + (Victims * 7919) % 2000);
                TerminateProcess(Victim.hProcess, 99);
                WaitForSingleObject(Victim.hProcess, 60000);
                CloseHandle(Victim.hProcess);
                CloseHandle(Victim.hThread);
                ++Victims;
            }
            else
            {
                Sleep(1000);
            }
        }
        ok(WaitForSingleObject(Self, 300000) == WAIT_OBJECT_0, "the torture threads of this process did not end\n");
        CloseHandle(Self);
        Problems = Args.Problems;
    }
    trace("lock torture (kmtest process): %lu problems; %lu victim processes terminated\n", Problems, Victims);
    ok_eq_ulong(Problems, 0UL);

    if (Partner.hProcess != NULL)
    {
        Code = 0xFFFFFFFF;
        ok(WaitForSingleObject(Partner.hProcess, 300000) == WAIT_OBJECT_0, "partner did not end\n");
        GetExitCodeProcess(Partner.hProcess, &Code);
        ok(Code == 0, "partner reported %lu problems\n", Code);
        CloseHandle(Partner.hProcess);
        CloseHandle(Partner.hThread);
    }

    /* Everything released: each range free for a new handle */
    Sleep(500);
    for (File = 0; File < LT_FILES; ++File)
    {
        WCHAR Name[32];
        ULONG Region;

        StringCchPrintfW(Name, RTL_NUMBER_OF(Name), L"lt\\f%lu.bin", File);
        F = CreateFileW(P(L, TRUE, Name), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (F == INVALID_HANDLE_VALUE)
            continue;
        for (Region = 0; Region < 2; ++Region)
        {
            OVERLAPPED Ov;
            LONGLONG Offset = Region ? LT_HIGH_BASE : 0;

            RtlZeroMemory(&Ov, sizeof(Ov));
            Ov.Offset = (DWORD)Offset;
            Ov.OffsetHigh = (DWORD)(Offset >> 32);
            ok(LockFileEx(F, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, (LT_SLOTS + 3) * LT_SLOT, 0, &Ov),
               "file %lu region %lu: a lock is left behind (%lu)\n", File, Region, GetLastError());
            UnlockFileEx(F, 0, (LT_SLOTS + 3) * LT_SLOT, 0, &Ov);
        }
        CloseHandle(F);
    }
    LoopCounters(&C);
    trace("loopback: locks %ld, unlocks %ld, pended %ld, granted after a wait %ld, cancelled %ld, timed out %ld, pending now %ld\n",
          C.Locks, C.Unlocks, C.LocksPended, C.LocksPendingGranted, C.LocksPendingCancelled, C.LocksPendingTimedOut,
          C.LocksPendingNow);
    ok(C.LocksPendingNow == 0, "%ld locks still pending at the mini-redirector\n", C.LocksPendingNow);
    LoopOptions(FCB_ALL_CACHE, 0);
    LoopTearDown(&Before);
}
