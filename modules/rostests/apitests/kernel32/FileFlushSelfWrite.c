/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     More ways for a paging write to reach a purge of the page it writes (truncation on close, volume
 *              flush, section deletion), a flush killed with its process, and a pagefile-backed section
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <stdio.h>
#include <ndk/iofuncs.h>

/*
 * FileFlushAllocCut cuts the allocation with FileAllocationInformation.  FAT cuts it without telling the cache manager
 * in two more places: the truncation on the last close (FCB_STATE_TRUNCATE_ON_CLOSE, set when the allocation was
 * raised), which leaves the cache map's section size where it was when the map outlives the close, and the volume
 * flush, which truncates every such file before it flushes it.  A page of the file dirtied through a view past the
 * valid data length is then written by a paging write that extends the valid data length and makes Cc purge from the
 * new allocation, inside that page.  These rows build both cases, the deletion of the section with that page still
 * dirty (the last reference writes it), a flushing process killed again and again, and a pagefile-backed section
 * (no file system at all).  Every case runs in a worker thread: no end in STALL_SECONDS is reported as a stall.
 * The directories are the temp directory and every FAT volume (FLUSHSELF_DIRS replaces the list, ';'-separated).
 */
#define STALL_SECONDS   60
#define KILL_ROUNDS     12

static WCHAR Dirs[16][MAX_PATH];
static ULONG DirCount;
static ULONG DirCluster[16];
static BOOL Stalled;

static BOOL SetSizeInfo(HANDLE File, FILE_INFORMATION_CLASS Class, ULONG Size)
{
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Info;
    NTSTATUS Status;

    Info.QuadPart = Size;
    Status = NtSetInformationFile(File, &Iosb, &Info, sizeof(Info), Class);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }
    return TRUE;
}

static ULONG ClusterOf(PCWSTR Dir)
{
    WCHAR Root[MAX_PATH];
    DWORD SectorsPerCluster, BytesPerSector, Free, Total;

    if (!GetVolumePathNameW(Dir, Root, MAX_PATH) ||
        !GetDiskFreeSpaceW(Root, &SectorsPerCluster, &BytesPerSector, &Free, &Total))
        return 0;
    return SectorsPerCluster * BytesPerSector;
}

static void AddDir(PCWSTR Dir)
{
    if (DirCount >= _countof(Dirs))
        return;
    StringCchCopyW(Dirs[DirCount], MAX_PATH, Dir);
    DirCluster[DirCount] = ClusterOf(Dir);
    DirCount++;
}

static void FindDirs(void)
{
    WCHAR Buffer[2048], Root[4] = L"C:\\", FsName[32];
    DWORD Drives;
    ULONG i;

    if (DirCount)
        return;

    if (GetEnvironmentVariableW(L"FLUSHSELF_DIRS", Buffer, _countof(Buffer)))
    {
        PWSTR Token = wcstok(Buffer, L";");
        while (Token)
        {
            AddDir(Token);
            Token = wcstok(NULL, L";");
        }
        return;
    }

    GetTempPathW(_countof(Buffer), Buffer);
    AddDir(Buffer);

    Drives = GetLogicalDrives();
    for (i = 2; i < 26; i++)
    {
        if (!(Drives & (1 << i)))
            continue;
        Root[0] = (WCHAR)(L'A' + i);
        if (GetDriveTypeW(Root) != DRIVE_FIXED)
            continue;
        if (!GetVolumeInformationW(Root, NULL, 0, NULL, NULL, NULL, FsName, _countof(FsName)))
            continue;
        if (_wcsnicmp(FsName, L"FAT", 3) == 0 && _wcsnicmp(Buffer, Root, 3) != 0)
            AddDir(Root);
    }
}

static UCHAR Pattern(ULONG Offset, ULONG Seed)
{
    return (UCHAR)((Offset * 7) + (Offset >> 8) + Seed) | 1;
}

static void MakePath(PWSTR Path, ULONG DirIndex, PCWSTR Name)
{
    PCWSTR Dir = Dirs[DirIndex];

    StringCchPrintfW(Path, MAX_PATH, L"%s%s%s_%lu.tmp", Dir, Dir[wcslen(Dir) - 1] == L'\\' ? L"" : L"\\", Name,
                     GetCurrentProcessId());
}

/* Reads the file through a non-cached handle (the file system writes what the cache holds first) and checks it */
static BOOL CheckDisk(PCWSTR Path, ULONG Size, ULONG Seed, PSTR Error, SIZE_T ErrorSize)
{
    HANDLE File;
    PUCHAR Data;
    ULONG Rounded = (Size + 4095) & ~4095UL, i;
    DWORD Done = 0;
    BOOL Ok = FALSE;

    File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        StringCchPrintfA(Error, ErrorSize, "reopen %lu", GetLastError());
        return FALSE;
    }
    Data = VirtualAlloc(NULL, Rounded, MEM_COMMIT, PAGE_READWRITE);
    if (!Data)
    {
        StringCchPrintfA(Error, ErrorSize, "no memory");
        goto Out;
    }
    if (GetFileSize(File, NULL) != Size)
    {
        StringCchPrintfA(Error, ErrorSize, "size %lu, expected %lu", GetFileSize(File, NULL), Size);
        goto Out;
    }
    if (!ReadFile(File, Data, Rounded, &Done, NULL) || Done != Size)
    {
        StringCchPrintfA(Error, ErrorSize, "read %lu (%lu bytes)", GetLastError(), Done);
        goto Out;
    }
    for (i = 0; i < Size; i++)
    {
        if (Data[i] != Pattern(i, Seed))
        {
            StringCchPrintfA(Error, ErrorSize, "byte at %lu is 0x%02x, expected 0x%02x", i, Data[i], Pattern(i, Seed));
            goto Out;
        }
    }
    Ok = TRUE;
Out:
    if (Data)
        VirtualFree(Data, 0, MEM_RELEASE);
    CloseHandle(File);
    return Ok;
}

/* ------------------------------------------------------------------------------------------------------------ */

typedef struct _SELF_CASE
{
    ULONG DirIndex;
    WCHAR Path[MAX_PATH];
    ULONG FileSize;
    ULONG Kind;         /* 0: truncation on close, 1: volume flush, 2: section deleted with the pages dirty */
    volatile LONG Step;
    BOOL Ok;
    BOOL Skipped;
    CHAR Error[160];
} SELF_CASE;

#define BIG_ALLOC (256 * 1024)

static DWORD WINAPI SelfThread(PVOID Param)
{
    SELF_CASE *Case = Param;
    HANDLE File = INVALID_HANDLE_VALUE, File2 = INVALID_HANDLE_VALUE, Mapping = NULL, Volume = INVALID_HANDLE_VALUE;
    PUCHAR View = NULL;
    DWORD Done, i;
    UCHAR Byte;
    BOOL Ok = FALSE;

#define FAIL(...) do { StringCchPrintfA(Case->Error, sizeof(Case->Error), __VA_ARGS__); goto Out; } while (0)

    Case->Step = 1;
    File = CreateFileW(Case->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        FAIL("create %lu", GetLastError());

    /* Cached write: a cache map, valid data length 1.  Allocation up: Cc is told, and FAT marks the file for the
     * truncation on close.  End of file up: the valid data length stays at 1 */
    Case->Step = 2;
    if (!WriteFile(File, "A", 1, &Done, NULL) || Done != 1)
        FAIL("write %lu", GetLastError());
    if (!SetSizeInfo(File, FileAllocationInformation, BIG_ALLOC))
        FAIL("alloc up %lu", GetLastError());
    if (!SetSizeInfo(File, FileEndOfFileInformation, Case->FileSize))
        FAIL("eof %lu", GetLastError());

    /* Dirty every page through a view, past the valid data length */
    Case->Step = 3;
    Mapping = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!Mapping)
        FAIL("mapping %lu", GetLastError());
    View = MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, Case->FileSize);
    if (!View)
        FAIL("view %lu", GetLastError());
    for (i = 0; i < Case->FileSize; i++)
        View[i] = Pattern(i, Case->FileSize);

    Case->Step = 4;
    if (Case->Kind == 0)
    {
        /* A cached write keeps the cache map past the last close (the lazy writer writes it and deletes the map);
         * the last close truncates the allocation to the end of file without telling Cc.  A new handle that
         * reads through the cache takes over the map before the lazy writer deletes it, and its flush writes the
         * view's pages */
        Byte = Pattern(0, Case->FileSize);
        if (SetFilePointer(File, 0, NULL, FILE_BEGIN) != 0 || !WriteFile(File, &Byte, 1, &Done, NULL) || Done != 1)
            FAIL("rewrite %lu", GetLastError());
        CloseHandle(File);
        File = INVALID_HANDLE_VALUE;
        File2 = CreateFileW(Case->Path, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
        if (File2 == INVALID_HANDLE_VALUE)
            FAIL("reopen %lu", GetLastError());
        if (!ReadFile(File2, &Byte, 1, &Done, NULL) || Done != 1)
            FAIL("cached read %lu", GetLastError());
        Case->Step = 5;
        if (!FlushViewOfFile(View, 0))
            FAIL("flushview %lu", GetLastError());
        if (!FlushFileBuffers(File2))
            FAIL("flush %lu", GetLastError());
    }
    else if (Case->Kind == 1)
    {
        /* The volume flush truncates the allocation of every file marked for it, then flushes the file */
        WCHAR VolumePath[MAX_PATH], Root[MAX_PATH];

        if (!GetVolumePathNameW(Case->Path, Root, MAX_PATH) || wcslen(Root) < 2 || Root[1] != L':')
            FAIL("volume path %lu", GetLastError());
        StringCchPrintfW(VolumePath, MAX_PATH, L"\\\\.\\%c:", Root[0]);
        Volume = CreateFileW(VolumePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, 0, NULL);
        if (Volume == INVALID_HANDLE_VALUE)
        {
            Case->Skipped = TRUE;
            FAIL("volume open %lu", GetLastError());
        }
        Case->Step = 5;
        if (!FlushFileBuffers(Volume))
            FAIL("volume flush %lu", GetLastError());
    }
    else
    {
        /* Cut the allocation (Cc not told), then drop the view, the section and the handle with the pages still
         * dirty: the last reference to the segment writes them */
        if (!SetSizeInfo(File, FileAllocationInformation, Case->FileSize))
            FAIL("alloc down %lu", GetLastError());
        Case->Step = 5;
        UnmapViewOfFile(View);
        View = NULL;
        CloseHandle(Mapping);
        Mapping = NULL;
        CloseHandle(File);
        File = INVALID_HANDLE_VALUE;
        Sleep(200);
    }

    Case->Step = 6;
    if (View)
        UnmapViewOfFile(View);
    View = NULL;
    if (Mapping)
        CloseHandle(Mapping);
    Mapping = NULL;
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    File = INVALID_HANDLE_VALUE;
    if (File2 != INVALID_HANDLE_VALUE)
        CloseHandle(File2);
    File2 = INVALID_HANDLE_VALUE;

    /* What the disk holds */
    Case->Step = 7;
    if (!CheckDisk(Case->Path, Case->FileSize, Case->FileSize, Case->Error, sizeof(Case->Error)))
        goto Out;
    Ok = TRUE;

Out:
#undef FAIL
    if (View)
        UnmapViewOfFile(View);
    if (Mapping)
        CloseHandle(Mapping);
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    if (File2 != INVALID_HANDLE_VALUE)
        CloseHandle(File2);
    if (Volume != INVALID_HANDLE_VALUE)
        CloseHandle(Volume);
    DeleteFileW(Case->Path);
    Case->Ok = Ok;
    Case->Step = 100;
    return 0;
}

static const char *KindName[] = { "truncate-on-close", "volume flush", "section delete" };

static void TestSelf(ULONG DirIndex, ULONG Kind)
{
    static const ULONG Sizes[] = { 1239, 3000, 4097, 6000, 12000, 70000 };
    ULONG s, Cases = 0, Passed = 0, Skipped = 0;
    DWORD Start = GetTickCount();

    for (s = 0; s < _countof(Sizes) && !Stalled; s++)
    {
        static SELF_CASE Case;
        HANDLE Thread;

        ZeroMemory(&Case, sizeof(Case));
        Case.DirIndex = DirIndex;
        MakePath(Case.Path, DirIndex, L"flushself");
        Case.FileSize = Sizes[s];
        Case.Kind = Kind;

        Thread = CreateThread(NULL, 0, SelfThread, &Case, 0, NULL);
        ok(Thread != NULL, "CreateThread failed %lu\n", GetLastError());
        if (!Thread)
            return;
        if (WaitForSingleObject(Thread, STALL_SECONDS * 1000) != WAIT_OBJECT_0)
        {
            ok(FALSE, "%s: %S (cluster %lu): size %lu: STALLED at step %ld for %u s\n", KindName[Kind],
               Dirs[DirIndex], DirCluster[DirIndex], Case.FileSize, Case.Step, STALL_SECONDS);
            Stalled = TRUE;
            return;
        }
        CloseHandle(Thread);
        if (Case.Skipped)
        {
            Skipped++;
            continue;
        }
        Cases++;
        ok(Case.Ok, "%s: %S (cluster %lu): size %lu: step %ld: %s\n", KindName[Kind], Dirs[DirIndex],
           DirCluster[DirIndex], Case.FileSize, Case.Step, Case.Error);
        if (Case.Ok)
            Passed++;
    }
    trace("%s: %S (cluster %lu): %lu/%lu cases right, %lu skipped, in %lu ms\n", KindName[Kind], Dirs[DirIndex],
          DirCluster[DirIndex], Passed, Cases, Skipped, GetTickCount() - Start);
}

/* ------------------------------------------------------------------------------------------------------------ */
/* A process that flushes a cut file again and again, killed at random moments                                 */

#define KILL_SIZE (2 * 1024 * 1024 + 1239)

static void KillChild(PCWSTR Path)
{
    HANDLE File, Mapping, Flushing = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"FlushSelfWriteFlushing");
    PUCHAR View;
    ULONG Round, i;
    DWORD Done;

    /* Runs until it is killed */
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        ExitProcess(2);
    for (Round = 0;; Round++)
    {
        SetSizeInfo(File, FileEndOfFileInformation, 1);
        if (!WriteFile(File, "A", 1, &Done, NULL))
            ExitProcess(3);
        SetSizeInfo(File, FileAllocationInformation, KILL_SIZE + BIG_ALLOC);
        SetSizeInfo(File, FileEndOfFileInformation, KILL_SIZE);
        SetSizeInfo(File, FileAllocationInformation, KILL_SIZE);
        Mapping = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (!Mapping)
            ExitProcess(4);
        View = MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, KILL_SIZE);
        if (!View)
            ExitProcess(5);
        for (i = 0; i < KILL_SIZE; i += 16)
            View[i] = Pattern(i, Round);
        /* Tell the parent that the flush starts: it kills this process a few milliseconds later */
        if (Flushing)
            SetEvent(Flushing);
        FlushViewOfFile(View, 0);
        FlushFileBuffers(File);
        UnmapViewOfFile(View);
        CloseHandle(Mapping);
        SetFilePointer(File, 0, NULL, FILE_BEGIN);
    }
}

static void TestKill(ULONG DirIndex)
{
    WCHAR Path[MAX_PATH], Exe[MAX_PATH], CmdLine[MAX_PATH + 64];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    ULONG Round, Killed = 0;
    HANDLE File;
    DWORD Wait;
    HANDLE Flushing = CreateEventW(NULL, TRUE, FALSE, L"FlushSelfWriteFlushing");

    MakePath(Path, DirIndex, L"flushkill");
    DeleteFileW(Path);
    GetModuleFileNameW(NULL, Exe, MAX_PATH);
    StringCchPrintfW(CmdLine, _countof(CmdLine), L"\"%s\" FileFlushSelfWrite", Exe);
    SetEnvironmentVariableW(L"FLUSHSELF_CHILD", Path);

    for (Round = 0; Round < KILL_ROUNDS && !Stalled; Round++)
    {
        ZeroMemory(&Si, sizeof(Si));
        Si.cb = sizeof(Si);
        if (!CreateProcessW(Exe, CmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &Si, &Pi))
        {
            ok(FALSE, "CreateProcess failed %lu\n", GetLastError());
            break;
        }
        /* Kill it a few milliseconds into one of its flushes (or after a while, if it never gets there) */
        ResetEvent(Flushing);
        WaitForSingleObject(Flushing, 10000);
        Sleep((Round * 7) % 40);
        TerminateProcess(Pi.hProcess, 99);
        Wait = WaitForSingleObject(Pi.hProcess, STALL_SECONDS * 1000);
        ok(Wait == WAIT_OBJECT_0, "kill: %S: round %lu: the killed process did not end in %u s\n", Dirs[DirIndex],
           Round, STALL_SECONDS);
        if (Wait != WAIT_OBJECT_0)
            Stalled = TRUE;
        else
            Killed++;
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
    }
    SetEnvironmentVariableW(L"FLUSHSELF_CHILD", NULL);
    if (Flushing)
        CloseHandle(Flushing);

    /* The file is usable: opened, read through, deleted */
    if (!Stalled)
    {
        File = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(File != INVALID_HANDLE_VALUE, "kill: %S: reopen failed %lu\n", Dirs[DirIndex], GetLastError());
        if (File != INVALID_HANDLE_VALUE)
        {
            static UCHAR Buffer[64 * 1024];
            DWORD Done, Total = 0;

            while (ReadFile(File, Buffer, sizeof(Buffer), &Done, NULL) && Done)
                Total += Done;
            ok(Total == GetFileSize(File, NULL), "kill: %S: read %lu of %lu bytes\n", Dirs[DirIndex], Total,
               GetFileSize(File, NULL));
            CloseHandle(File);
        }
        ok(DeleteFileW(Path), "kill: %S: delete failed %lu\n", Dirs[DirIndex], GetLastError());
    }
    trace("kill: %S (cluster %lu): %lu/%u flushing processes killed and ended\n", Dirs[DirIndex], DirCluster[DirIndex],
          Killed, KILL_ROUNDS);
}

/* ------------------------------------------------------------------------------------------------------------ */
/* A pagefile-backed section: no file system, no segment writer                                                */

static void TestPagefileSection(void)
{
    const SIZE_T Size = 48 * 1024 * 1024;
    HANDLE Mapping;
    PUCHAR View, View2;
    SIZE_T i;
    ULONG Bad = 0, Round;

    for (Round = 0; Round < 3; Round++)
    {
        Mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)Size, NULL);
        ok(Mapping != NULL, "pagefile section: CreateFileMapping failed %lu\n", GetLastError());
        if (!Mapping)
            return;
        View = MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, 0);
        View2 = MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, 0);
        ok(View && View2, "pagefile section: MapViewOfFile failed %lu\n", GetLastError());
        if (View && View2)
        {
            for (i = 0; i < Size; i += 512)
                View[i] = Pattern((ULONG)i, Round);
            ok(FlushViewOfFile(View, 0), "pagefile section: FlushViewOfFile failed %lu\n", GetLastError());
            for (i = 0; i < Size; i += 512)
            {
                if (View2[i] != Pattern((ULONG)i, Round))
                    Bad++;
            }
        }
        if (View)
            UnmapViewOfFile(View);
        if (View2)
            UnmapViewOfFile(View2);
        CloseHandle(Mapping);
    }
    ok(Bad == 0, "pagefile section: %lu bytes differ\n", Bad);
    trace("pagefile section: 3 x %lu MB written, flushed and read back, %lu differ\n", (ULONG)(Size >> 20), Bad);
}

START_TEST(FileFlushSelfWrite)
{
    WCHAR Child[MAX_PATH], Rows[16];
    ULONG i, Kind;

    if (GetEnvironmentVariableW(L"FLUSHSELF_CHILD", Child, _countof(Child)))
    {
        KillChild(Child);
        return;
    }

    /* FLUSHSELF_ROWS: the rows to run, digits 0-4 (0 truncation on close, 1 volume flush, 2 section delete,
     * 3 kill, 4 pagefile-backed section); default all */
    if (!GetEnvironmentVariableW(L"FLUSHSELF_ROWS", Rows, _countof(Rows)))
        StringCchCopyW(Rows, _countof(Rows), L"01234");

    FindDirs();
    for (i = 0; i < DirCount && !Stalled; i++)
    {
        for (Kind = 0; Kind < 3 && !Stalled; Kind++)
        {
            if (wcschr(Rows, (WCHAR)(L'0' + Kind)))
                TestSelf(i, Kind);
        }
    }
    for (i = 0; i < DirCount && !Stalled && wcschr(Rows, L'3'); i++)
        TestKill(i);
    if (!Stalled && wcschr(Rows, L'4'))
        TestPagefileSection();
    if (Stalled)
    {
        /* The stuck thread holds the file: leave without the cleanup that would wait for it */
        trace("stalled: exiting without cleanup\n");
        fflush(stdout);
    }
}
