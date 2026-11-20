/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A flush of a mapped file whose allocation was cut must not wait for its own write; file contents stay
 *              right under racing size changes, mapped and cached writes and flushes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <stdio.h>
#include <ndk/iofuncs.h>

/*
 * The file system may cut a file's allocation without telling the cache manager (the WDK asks for CcSetFileSizes on
 * an allocation increase, not on a decrease): FileAllocationInformation below the allocation but not below the end of
 * file does that on FAT.  A page written through a mapped view past the valid data length is then written by the flush
 * (FlushFileBuffers) as a paging write; FAT extends the valid data length and tells Cc (CcSetFileSizes), and Cc
 * purged the segment from the new allocation, from inside the page that the same thread was writing: the flush
 * waited for itself for ever, holding the file.  That needs a cluster smaller than a page (the allocation then ends
 * inside the page), so the first test runs on every FAT volume with small clusters it finds (and on the temp
 * directory for the other file systems); FLUSHCUT_DIRS (directories separated by ';') replaces that list.
 *
 * Each case runs in a worker thread: a stall is reported after STALL_SECONDS, and the test stops there (the stuck
 * thread holds the file; the process will not exit).
 *
 * The second test races size changes (end of file and allocation, up and down, at cluster and page boundaries),
 * cached and mapped writes, close and reopen (the truncation on close), with flushes of the file and the lazy writer
 * running meanwhile, and checks the file against a model after every few operations and at the end through a
 * non-cached handle (the disk).  FLUSHCUT_SECONDS sets how long it runs per directory (default 20), FLUSHCUT_SEED
 * the seed.
 */
#define STALL_SECONDS   60
#define MAX_SIZE        (256 * 1024)

static WCHAR Dirs[16][MAX_PATH];
static ULONG DirCount;
static ULONG DirCluster[16];
static BOOL Stalled;

static ULONG Rand32(ULONG *State)
{
    ULONG X = *State;
    X ^= X << 13;
    X ^= X >> 17;
    X ^= X << 5;
    return *State = X;
}

static BOOL SetSizeInfo(HANDLE File, FILE_INFORMATION_CLASS Class, ULONG Size)
{
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Info;     /* FILE_END_OF_FILE_INFORMATION and FILE_ALLOCATION_INFORMATION are one LARGE_INTEGER */
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

static BOOL SetEof(HANDLE File, ULONG Size)
{
    return SetSizeInfo(File, FileEndOfFileInformation, Size);
}

static BOOL SetAlloc(HANDLE File, ULONG Size)
{
    return SetSizeInfo(File, FileAllocationInformation, Size);
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

    if (GetEnvironmentVariableW(L"FLUSHCUT_DIRS", Buffer, _countof(Buffer)))
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

/* ------------------------------------------------------------------------------------------------------------ */
/* The cut: one file, one size, one way to flush                                                               */

typedef struct _CUT_CASE
{
    WCHAR Path[MAX_PATH];
    ULONG FileSize;
    ULONG BigAlloc;
    ULONG Flush;        /* 0: FlushFileBuffers with the view mapped, 1: FlushViewOfFile, 2: unmap then FlushFileBuffers */
    volatile LONG Step;
    BOOL Ok;
    CHAR Error[160];
} CUT_CASE;

static DWORD WINAPI CutThread(PVOID Param)
{
    CUT_CASE *Case = Param;
    HANDLE File, Mapping = NULL;
    PUCHAR View = NULL, Data = NULL;
    DWORD Done, i;
    BOOL Ok = FALSE;

#define FAIL(...) do { StringCchPrintfA(Case->Error, sizeof(Case->Error), __VA_ARGS__); goto Out; } while (0)

    Case->Step = 1;
    File = CreateFileW(Case->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        FAIL("create %lu", GetLastError());

    /* A cached write: the file gets its cache map, valid data length 1 */
    Case->Step = 2;
    if (!WriteFile(File, "A", 1, &Done, NULL) || Done != 1)
        FAIL("write %lu", GetLastError());

    /* Allocation up (Cc is told: section size BigAlloc), end of file up (valid data length stays), allocation down
     * to the end of file (Cc is not told) */
    Case->Step = 3;
    if (!SetAlloc(File, Case->BigAlloc))
        FAIL("alloc up %lu", GetLastError());
    if (!SetEof(File, Case->FileSize))
        FAIL("eof %lu", GetLastError());
    if (!SetAlloc(File, Case->FileSize))
        FAIL("alloc down %lu", GetLastError());

    /* Dirty the pages through a view, past the valid data length */
    Case->Step = 4;
    Mapping = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!Mapping)
        FAIL("mapping %lu", GetLastError());
    View = MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, Case->FileSize);
    if (!View)
        FAIL("view %lu", GetLastError());
    for (i = 0; i < Case->FileSize; i++)
        View[i] = Pattern(i, Case->FileSize);

    /* The flush: the paging write extends the valid data length */
    Case->Step = 5;
    if (Case->Flush == 1 && !FlushViewOfFile(View, 0))
        FAIL("flushview %lu", GetLastError());
    if (Case->Flush == 2)
    {
        UnmapViewOfFile(View);
        View = NULL;
    }
    if (!FlushFileBuffers(File))
        FAIL("flush %lu", GetLastError());

    Case->Step = 6;
    if (View)
        UnmapViewOfFile(View);
    View = NULL;
    CloseHandle(Mapping);
    Mapping = NULL;
    CloseHandle(File);

    /* What the file holds now */
    Case->Step = 7;
    File = CreateFileW(Case->Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        FAIL("reopen %lu", GetLastError());
    if (GetFileSize(File, NULL) != Case->FileSize)
        FAIL("size %lu, expected %lu", GetFileSize(File, NULL), Case->FileSize);
    Data = HeapAlloc(GetProcessHeap(), 0, Case->FileSize + 16);
    if (!Data || !ReadFile(File, Data, Case->FileSize + 16, &Done, NULL) || Done != Case->FileSize)
        FAIL("read %lu (%lu bytes)", GetLastError(), Done);
    for (i = 0; i < Case->FileSize; i++)
    {
        if (Data[i] != Pattern(i, Case->FileSize))
            FAIL("byte at %lu is 0x%02x, expected 0x%02x", i, Data[i], Pattern(i, Case->FileSize));
    }
    Ok = TRUE;

Out:
#undef FAIL
    if (Data)
        HeapFree(GetProcessHeap(), 0, Data);
    if (View)
        UnmapViewOfFile(View);
    if (Mapping)
        CloseHandle(Mapping);
    if (File != INVALID_HANDLE_VALUE)
        CloseHandle(File);
    DeleteFileW(Case->Path);
    Case->Ok = Ok;
    Case->Step = 100;
    return 0;
}

static void TestCut(ULONG DirIndex)
{
    static const ULONG Sizes[] = { 1239, 3000, 4095, 4097, 6000, 8191, 12000 };
    static const ULONG BigAllocs[] = { 64 * 1024, 1024 * 1024 };
    ULONG s, b, f, Cases = 0, Passed = 0;
    DWORD Start = GetTickCount();

    for (s = 0; s < _countof(Sizes) && !Stalled; s++)
    for (b = 0; b < _countof(BigAllocs) && !Stalled; b++)
    for (f = 0; f < 3 && !Stalled; f++)
    {
        static CUT_CASE Case;
        HANDLE Thread;

        ZeroMemory(&Case, sizeof(Case));
        StringCchPrintfW(Case.Path, MAX_PATH, L"%s%sflushcut_%lu.tmp", Dirs[DirIndex],
                         Dirs[DirIndex][wcslen(Dirs[DirIndex]) - 1] == L'\\' ? L"" : L"\\", GetCurrentProcessId());
        Case.FileSize = Sizes[s];
        Case.BigAlloc = BigAllocs[b];
        Case.Flush = f;

        Thread = CreateThread(NULL, 0, CutThread, &Case, 0, NULL);
        ok(Thread != NULL, "CreateThread failed %lu\n", GetLastError());
        if (!Thread)
            return;
        if (WaitForSingleObject(Thread, STALL_SECONDS * 1000) != WAIT_OBJECT_0)
        {
            ok(FALSE, "%S (cluster %lu): size %lu, allocation %lu, flush %lu: STALLED at step %ld for %u s\n",
               Dirs[DirIndex], DirCluster[DirIndex], Case.FileSize, Case.BigAlloc, Case.Flush, Case.Step, STALL_SECONDS);
            Stalled = TRUE;
            return;
        }
        CloseHandle(Thread);
        Cases++;
        ok(Case.Ok, "%S (cluster %lu): size %lu, allocation %lu, flush %lu: step %ld: %s\n",
           Dirs[DirIndex], DirCluster[DirIndex], Case.FileSize, Case.BigAlloc, Case.Flush, Case.Step, Case.Error);
        if (Case.Ok)
            Passed++;
    }
    trace("cut: %S (cluster %lu): %lu/%lu cases right in %lu ms\n", Dirs[DirIndex], DirCluster[DirIndex], Passed, Cases,
          GetTickCount() - Start);
}

START_TEST(FileFlushAllocCut)
{
    ULONG i;

    FindDirs();
    for (i = 0; i < DirCount && !Stalled; i++)
    {
        if (DirCluster[i] >= 4096)
            trace("cut: %S has %lu-byte clusters: the allocation ends on a page boundary there (runs as a control)\n",
                  Dirs[i], DirCluster[i]);
        TestCut(i);
    }
    if (Stalled)
    {
        /* The stuck thread holds the file: leave without the cleanup that would wait for it */
        trace("stalled: exiting without cleanup\n");
        fflush(stdout);
    }
}

/* ------------------------------------------------------------------------------------------------------------ */
/* The race, against a model                                                                                   */

typedef struct _RACE
{
    WCHAR Path[MAX_PATH];
    ULONG Seed;
    DWORD EndTick;
    CRITICAL_SECTION Lock;          /* every change of the contents and the model's update are one step */
    HANDLE File;                    /* the mutator's cached handle (may be closed and reopened) */
    HANDLE Mapping;                 /* a held view (keeps the section past closes and blocks some cuts) */
    PUCHAR View;
    ULONG ViewSize;
    UCHAR Model[MAX_SIZE];
    ULONG Size;
    volatile LONG Progress;         /* operations done, by all threads */
    volatile LONG Stop;
    volatile LONG LastOp;
    ULONG Ops[10], Refused[10], Flushes, Mismatch;
    CHAR Error[200];
} RACE;

static ULONG PickSize(RACE *Race, ULONG *Rand)
{
    /* Around cluster (512 .. 4096) and page boundaries, some anywhere */
    ULONG Base, Delta;

    switch (Rand32(Rand) % 4)
    {
        case 0: Base = (Rand32(Rand) % 64) * 512; break;
        case 1: Base = (Rand32(Rand) % 64) * 4096; break;
        case 2: Base = Race->Size; break;
        default: return Rand32(Rand) % MAX_SIZE;
    }
    Delta = Rand32(Rand) % 3;
    Base = (Delta == 0) ? Base : (Delta == 1) ? Base + 1 : (Base ? Base - 1 : 0);
    return min(Base, MAX_SIZE - 1);
}

static BOOL CheckFile(RACE *Race, HANDLE File, PCSTR When)
{
    static UCHAR Data[MAX_SIZE + 512];
    LARGE_INTEGER Zero = { { 0 } };
    DWORD Done = 0, Size = GetFileSize(File, NULL), i;

    if (Size != Race->Size)
    {
        StringCchPrintfA(Race->Error, sizeof(Race->Error), "%s: size %lu, model %lu", When, Size, Race->Size);
        return FALSE;
    }
    SetFilePointerEx(File, Zero, NULL, FILE_BEGIN);
    if (!ReadFile(File, Data, sizeof(Data), &Done, NULL) || Done != Race->Size)
    {
        StringCchPrintfA(Race->Error, sizeof(Race->Error), "%s: read %lu bytes of %lu, error %lu", When, Done, Race->Size,
                         GetLastError());
        return FALSE;
    }
    for (i = 0; i < Race->Size; i++)
    {
        if (Data[i] != Race->Model[i])
        {
            StringCchPrintfA(Race->Error, sizeof(Race->Error), "%s: byte at %lu is 0x%02x, model 0x%02x (size %lu)", When, i,
                             Data[i], Race->Model[i], Race->Size);
            return FALSE;
        }
    }
    return TRUE;
}

static HANDLE OpenRaceFile(RACE *Race, DWORD Disposition, DWORD Flags)
{
    return CreateFileW(Race->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, Disposition, FILE_ATTRIBUTE_NORMAL | Flags, NULL);
}

static void DropView(RACE *Race)
{
    if (Race->View)
        UnmapViewOfFile(Race->View);
    if (Race->Mapping)
        CloseHandle(Race->Mapping);
    Race->View = NULL;
    Race->Mapping = NULL;
    Race->ViewSize = 0;
}

static DWORD WINAPI MutatorThread(PVOID Param)
{
    RACE *Race = Param;
    ULONG Rand = Race->Seed | 1;
    static UCHAR Buffer[16384];
    ULONG Count = 0;

    while (!Race->Stop && GetTickCount() < Race->EndTick)
    {
        ULONG Op = Rand32(&Rand) % 10, Offset, Length, NewSize, i;
        DWORD Done;
        BOOL Ok;

        EnterCriticalSection(&Race->Lock);
        Race->LastOp = Op;
        Race->Ops[Op]++;
        switch (Op)
        {
            case 0: case 1:     /* cached write, often extending */
                Offset = PickSize(Race, &Rand);
                Length = 1 + Rand32(&Rand) % sizeof(Buffer);
                if (Offset + Length > MAX_SIZE)
                    Length = MAX_SIZE - Offset;
                for (i = 0; i < Length; i++)
                    Buffer[i] = (UCHAR)Rand32(&Rand) | 1;
                {
                    LARGE_INTEGER Pos;
                    Pos.QuadPart = Offset;
                    SetFilePointerEx(Race->File, Pos, NULL, FILE_BEGIN);
                }
                Ok = WriteFile(Race->File, Buffer, Length, &Done, NULL) && Done == Length;
                if (Ok)
                {
                    if (Offset > Race->Size)
                        ZeroMemory(Race->Model + Race->Size, Offset - Race->Size);
                    memcpy(Race->Model + Offset, Buffer, Length);
                    Race->Size = max(Race->Size, Offset + Length);
                }
                else
                {
                    Race->Refused[Op]++;
                }
                break;

            case 2: case 3:     /* end of file, up or down */
                NewSize = PickSize(Race, &Rand);
                if (SetEof(Race->File, NewSize))
                {
                    if (NewSize > Race->Size)
                        ZeroMemory(Race->Model + Race->Size, NewSize - Race->Size);
                    Race->Size = NewSize;
                    if (Race->ViewSize > Race->Size)
                        Race->ViewSize = Race->Size;   /* never write through the view past the end of file */
                }
                else
                {
                    Race->Refused[Op]++;
                }
                break;

            case 4:             /* allocation, up or down (below the end of file it cuts the file) */
                NewSize = (Rand32(&Rand) & 1) ? PickSize(Race, &Rand) : Race->Size + Rand32(&Rand) % 70000;
                if (SetAlloc(Race->File, min(NewSize, MAX_SIZE)))
                {
                    NewSize = min(NewSize, MAX_SIZE);
                    if (NewSize < Race->Size)
                    {
                        Race->Size = NewSize;
                        if (Race->ViewSize > Race->Size)
                            Race->ViewSize = Race->Size;
                    }
                }
                else
                {
                    Race->Refused[Op]++;
                }
                break;

            case 5: case 6:     /* write through a view (a new one, or the held one) */
                if (!Race->View || (Rand32(&Rand) % 4) == 0)
                {
                    DropView(Race);
                    if (Race->Size)
                    {
                        Race->Mapping = CreateFileMappingW(Race->File, NULL, PAGE_READWRITE, 0, 0, NULL);
                        Race->View = Race->Mapping ? MapViewOfFile(Race->Mapping, FILE_MAP_WRITE, 0, 0, 0) : NULL;
                        Race->ViewSize = Race->View ? Race->Size : 0;
                        if (!Race->View)
                        {
                            Race->Refused[Op]++;
                            DropView(Race);
                        }
                    }
                }
                if (Race->View && Race->ViewSize)
                {
                    Offset = Rand32(&Rand) % Race->ViewSize;
                    Length = 1 + Rand32(&Rand) % min(Race->ViewSize - Offset, 12000);
                    for (i = 0; i < Length; i++)
                        Race->Model[Offset + i] = Race->View[Offset + i] = (UCHAR)Rand32(&Rand) | 1;
                }
                if ((Rand32(&Rand) % 3) == 0)
                    DropView(Race);
                break;

            case 7:             /* close and reopen: the last cleanup truncates the allocation */
                CloseHandle(Race->File);
                Race->File = OpenRaceFile(Race, OPEN_EXISTING, 0);
                if (Race->File == INVALID_HANDLE_VALUE)
                {
                    StringCchPrintfA(Race->Error, sizeof(Race->Error), "reopen: %lu", GetLastError());
                    Race->Mismatch++;
                    Race->Stop = TRUE;
                }
                break;

            case 8:             /* flush with the lock held: nothing changes meanwhile */
                FlushFileBuffers(Race->File);
                break;

            case 9:             /* check */
                if (!CheckFile(Race, Race->File, "check"))
                {
                    Race->Mismatch++;
                    Race->Stop = TRUE;
                }
                break;
        }
        LeaveCriticalSection(&Race->Lock);
        InterlockedIncrement(&Race->Progress);
        if ((++Count % 64) == 0)
            Sleep(Rand32(&Rand) % 3);
    }
    return 0;
}

static DWORD WINAPI FlusherThread(PVOID Param)
{
    RACE *Race = Param;
    ULONG Rand = Race->Seed * 3 + 7;

    while (!Race->Stop && GetTickCount() < Race->EndTick)
    {
        /* Its own handle: a close of the mutator's then is not the last one, or this close is */
        HANDLE File = OpenRaceFile(Race, OPEN_EXISTING, 0);
        if (File != INVALID_HANDLE_VALUE)
        {
            FlushFileBuffers(File);
            CloseHandle(File);
        }
        InterlockedIncrement(&Race->Progress);
        Race->Flushes++;
        Sleep(Rand32(&Rand) % 4);
    }
    return 0;
}

static void TestRace(ULONG DirIndex, ULONG Seconds, ULONG Seed)
{
    static RACE Race;
    HANDLE Threads[3], File;
    LONG LastProgress = -1;
    DWORD LastTick = GetTickCount(), Wait;
    ULONG i, Total = 0, Refused = 0;

    ZeroMemory(&Race, sizeof(Race));
    StringCchPrintfW(Race.Path, MAX_PATH, L"%s%sflushrace_%lu.tmp", Dirs[DirIndex],
                     Dirs[DirIndex][wcslen(Dirs[DirIndex]) - 1] == L'\\' ? L"" : L"\\", GetCurrentProcessId());
    Race.Seed = Seed;
    InitializeCriticalSection(&Race.Lock);
    Race.File = OpenRaceFile(&Race, CREATE_ALWAYS, 0);
    ok(Race.File != INVALID_HANDLE_VALUE, "create %S: %lu\n", Race.Path, GetLastError());
    if (Race.File == INVALID_HANDLE_VALUE)
        return;
    Race.EndTick = GetTickCount() + Seconds * 1000;

    Threads[0] = CreateThread(NULL, 0, MutatorThread, &Race, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, FlusherThread, &Race, 0, NULL);
    Threads[2] = CreateThread(NULL, 0, FlusherThread, &Race, 0, NULL);

    for (;;)
    {
        Wait = WaitForMultipleObjects(3, Threads, TRUE, 1000);
        if (Wait != WAIT_TIMEOUT)
            break;
        if (Race.Progress != LastProgress)
        {
            LastProgress = Race.Progress;
            LastTick = GetTickCount();
        }
        else if (GetTickCount() - LastTick > STALL_SECONDS * 1000)
        {
            ok(FALSE, "race %S (cluster %lu, seed %lu): STALLED, no progress for %u s (last operation %ld, %ld done)\n",
               Dirs[DirIndex], DirCluster[DirIndex], Seed, STALL_SECONDS, Race.LastOp, Race.Progress);
            Stalled = TRUE;
            return;
        }
    }
    for (i = 0; i < 3; i++)
        CloseHandle(Threads[i]);

    ok(Race.Mismatch == 0, "race %S (cluster %lu, seed %lu): %s\n", Dirs[DirIndex], DirCluster[DirIndex], Seed, Race.Error);

    /* The end: through the cache, then from the disk */
    DropView(&Race);
    if (Race.File != INVALID_HANDLE_VALUE)
    {
        ok(CheckFile(&Race, Race.File, "end, cached"), "race %S seed %lu: %s\n", Dirs[DirIndex], Seed, Race.Error);
        FlushFileBuffers(Race.File);
        CloseHandle(Race.File);
    }
    File = CreateFileW(Race.Path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
                       FILE_FLAG_NO_BUFFERING, NULL);
    if (File != INVALID_HANDLE_VALUE)
    {
        /* Non-cached reads go in whole sectors: read through a sector-aligned buffer, compare what the model has */
        static UCHAR Data[MAX_SIZE + 4096];
        PUCHAR Aligned = (PUCHAR)(((ULONG_PTR)Data + 4095) & ~(ULONG_PTR)4095);
        DWORD Done = 0;
        BOOL Ok = ReadFile(File, Aligned, MAX_SIZE, &Done, NULL);

        ok(Ok && Done == Race.Size, "race %S seed %lu: non-cached read %lu bytes of %lu, error %lu\n", Dirs[DirIndex], Seed,
           Done, Race.Size, GetLastError());
        for (i = 0; Ok && i < min(Done, Race.Size); i++)
        {
            if (Aligned[i] != Race.Model[i])
            {
                ok(FALSE, "race %S seed %lu: on disk, byte at %lu is 0x%02x, model 0x%02x\n", Dirs[DirIndex], Seed, i,
                   Aligned[i], Race.Model[i]);
                break;
            }
        }
        CloseHandle(File);
    }
    DeleteFileW(Race.Path);
    DeleteCriticalSection(&Race.Lock);

    for (i = 0; i < 10; i++)
    {
        Total += Race.Ops[i];
        Refused += Race.Refused[i];
    }
    trace("race: %S (cluster %lu, seed %lu, %lu s): %lu operations (%lu refused), %lu flushes, final size %lu\n",
          Dirs[DirIndex], DirCluster[DirIndex], Seed, Seconds, Total, Refused, Race.Flushes, Race.Size);
}

START_TEST(FileFlushRace)
{
    WCHAR Value[32];
    ULONG Seconds = 20, Seed = GetTickCount(), i;

    if (GetEnvironmentVariableW(L"FLUSHCUT_SECONDS", Value, _countof(Value)))
        Seconds = wcstoul(Value, NULL, 10);
    if (GetEnvironmentVariableW(L"FLUSHCUT_SEED", Value, _countof(Value)))
        Seed = wcstoul(Value, NULL, 10);
    if (!Seed)
        Seed = 1;

    FindDirs();
    for (i = 0; i < DirCount && !Stalled; i++)
        TestRace(i, Seconds, Seed + i);
}
