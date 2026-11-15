/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: a freed MFT record is reused at once, and create/delete churn keeps the driver's pool flat
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define RECORD(Id) ((Id) & 0xffffffffffffULL)

/* Creates Path with a few bytes (resident data); its file ID, or 0. */
static ULONGLONG CreateWithId(PCWSTR Path)
{
    ULONGLONG Id = 0;
    DWORD Written;
    HANDLE H = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (H == INVALID_HANDLE_VALUE)
        return 0;
    WriteFile(H, "record", 6, &Written, NULL);
    Id = NtFileId(H);
    CloseHandle(H);
    return Id;
}

/*
 * Windows 10 (22H2) gives a new file the record a file deleted just before had (with the next
 * sequence number), and the lowest free record when several are free.
 */
START_TEST(NtfsRecordReuse)
{
    WCHAR Path[MAX_PATH], A[MAX_PATH], C[MAX_PATH], D[MAX_PATH];
    ULONGLONG Prev = 0, Id, IdA = 0, IdC = 0, IdD = 0;
    ULONG i, Same = 0, Tries = 0, Attempt;

    if (!NtInit("NtfsRecordReuse"))
        return;
    for (i = 0; i < 8; i++)
    {
        NtPath(Path, i & 1 ? L"odd.tmp" : L"even.tmp");
        Id = CreateWithId(Path);
        ok(Id != 0, "Creating %ls failed: %lu\n", Path, GetLastError());
        ok(Id == 0 || Id >> 48 != 0, "File %ls has sequence number 0 (file ID 0x%I64x)\n", Path, Id);
        ok(DeleteFileW(Path), "Deleting %ls failed: %lu\n", Path, GetLastError());
        if (Prev && Id)
        {
            Tries++;
            if (RECORD(Id) == RECORD(Prev))
            {
                Same++;
                ok(Id >> 48 != Prev >> 48, "Record %I64u reused with the same sequence number %I64u\n",
                   RECORD(Id), Id >> 48);
            }
            else
            {
                trace("Create %lu got record %I64u, the file deleted before had %I64u\n", i, RECORD(Id), RECORD(Prev));
            }
        }
        Prev = Id;
    }
    /* Another process may take a freed record in between: most, not all. */
    ok(Tries == 7 && Same >= 5, "A freed record was reused %lu times of %lu\n", Same, Tries);

    NtPath(A, L"a.tmp");
    NtPath(C, L"c.tmp");
    NtPath(D, L"d.tmp");
    /*
     * A is the lowest free record when it is created (the loop above freed it), C is created after it,
     * and A is deleted: D must get exactly A's record, with the next sequence number.  Another process
     * creating or deleting a file in these few microseconds could take or lower it, so the sequence
     * is tried up to three times; a driver that does not reuse the lowest free record fails all three.
     */
    for (Attempt = 0; Attempt < 3; Attempt++)
    {
        IdA = CreateWithId(A);
        IdC = CreateWithId(C);
        ok(DeleteFileW(A), "Deleting %ls failed: %lu\n", A, GetLastError());
        IdD = CreateWithId(D);
        ok(IdA && IdC && IdD, "Creating the files failed\n");
        DeleteFileW(C);
        DeleteFileW(D);
        if (RECORD(IdD) == RECORD(IdA))
            break;
        trace("Attempt %lu: the new file got record %I64u, not the freed %I64u (kept: %I64u)\n",
              Attempt, RECORD(IdD), RECORD(IdA), RECORD(IdC));
    }
    ok(RECORD(IdD) == RECORD(IdA),
       "The new file got record %I64u, not the freed lowest %I64u (kept: %I64u)\n", RECORD(IdD), RECORD(IdA), RECORD(IdC));
    ok(RECORD(IdD) != RECORD(IdA) || IdD >> 48 != IdA >> 48,
       "Record %I64u reused with the same sequence number %I64u\n", RECORD(IdD), IdD >> 48);
    ok(IdD >> 48 != 0, "The reused record has sequence number 0 (file ID 0x%I64x)\n", IdD);
    NtCleanup();
}

#define STRESS_ITER 1500
#define STRESS_THREADS 2

typedef struct
{
    WCHAR Path[MAX_PATH];
    ULONGLONG Ids[STRESS_ITER];
    ULONG Failed;
    ULONG ZeroSeq;
} STRESS;

static DWORD WINAPI StressThread(PVOID Param)
{
    STRESS *S = Param;
    ULONG i;

    for (i = 0; i < STRESS_ITER; i++)
    {
        S->Ids[i] = CreateWithId(S->Path);
        if (!S->Ids[i] || !DeleteFileW(S->Path))
            S->Failed++;
        else if (!(S->Ids[i] >> 48))
            S->ZeroSeq++;
    }
    return 0;
}

/*
 * Two threads create and delete a file each, in a loop.  A freed record is the next one allocated,
 * so the working set is a handful of records; a driver that does not reuse freed records (or loses
 * the update that makes the allocator start at the lowest free one, when a delete races with a
 * create) walks on through the MFT instead.  A lost update only misses one reuse until the next
 * delete, and the race window is a few instructions, so this does not fail reliably on that
 * alone; it fails reliably when reuse is broken under concurrency.  The bound allows for other
 * processes creating files meanwhile.
 */
START_TEST(NtfsRecordReuseThreads)
{
    static STRESS Stress[STRESS_THREADS];
    HANDLE Threads[STRESS_THREADS];
    ULONGLONG Seen[STRESS_THREADS * STRESS_ITER];
    ULONG t, i, j, Distinct = 0, Failed = 0, ZeroSeq = 0, N = 0;
    WCHAR Name[32];

    if (!NtInit("NtfsRecordReuseThreads"))
        return;
    for (t = 0; t < STRESS_THREADS; t++)
    {
        _snwprintf(Name, 31, L"thread%lu.tmp", t);
        NtPath(Stress[t].Path, Name);
    }
    for (t = 0; t < STRESS_THREADS; t++)
    {
        Threads[t] = CreateThread(NULL, 0, StressThread, &Stress[t], 0, NULL);
        ok(Threads[t] != NULL, "CreateThread failed: %lu\n", GetLastError());
    }
    for (t = 0; t < STRESS_THREADS; t++)
    {
        if (!Threads[t])
            continue;
        WaitForSingleObject(Threads[t], INFINITE);
        CloseHandle(Threads[t]);
    }
    for (t = 0; t < STRESS_THREADS; t++)
    {
        Failed += Stress[t].Failed;
        ZeroSeq += Stress[t].ZeroSeq;
        for (i = 0; i < STRESS_ITER; i++)
        {
            ULONGLONG Rec = RECORD(Stress[t].Ids[i]);
            if (!Rec)
                continue;
            for (j = 0; j < N && Seen[j] != Rec; j++)
                ;
            if (j == N)
                Seen[N++] = Rec;
        }
    }
    Distinct = N;
    ok(Failed == 0, "%lu create or delete operations failed\n", Failed);
    ok(ZeroSeq == 0, "%lu files got sequence number 0\n", ZeroSeq);
    trace("%lu distinct records in %d create/delete cycles\n", Distinct, STRESS_THREADS * STRESS_ITER);
    ok(Distinct <= 16, "%lu distinct records for %d create/delete cycles of %d files: freed records are not reused\n",
       Distinct, STRESS_THREADS * STRESS_ITER, STRESS_THREADS);
    NtCleanup();
}

#define RACE_SHARED     4
#define RACE_OPENERS    4
#define RACE_DELETERS   2
#define RACE_CREATORS   2
#define RACE_RING       8
#define RACE_SECONDS    20

typedef struct
{
    ULONG Index;
    ULONG Ops;
    ULONG Failed;
    DWORD FirstError;
    CHAR FirstStep[16];
    WCHAR FirstName[MAX_PATH];
} RACE;

static WCHAR RaceShared[RACE_SHARED][MAX_PATH];
static volatile LONG RaceStop;

/* A cached write to a shared file: the cache keeps its FCB after the handle is closed. */
static DWORD WINAPI RaceOpener(PVOID Param)
{
    RACE *R = Param;
    static const CHAR Data[4096];
    DWORD Done;
    ULONG i;

    for (i = R->Index; !RaceStop; i++)
    {
        HANDLE H = CreateFileW(RaceShared[i % RACE_SHARED], GENERIC_READ | GENERIC_WRITE, SHARE_ALL, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (H == INVALID_HANDLE_VALUE)
            continue;   /* delete pending: expected */
        WriteFile(H, Data, sizeof(Data), &Done, NULL);
        CloseHandle(H);
        R->Ops++;
    }
    return 0;
}

static DWORD WINAPI RaceDeleter(PVOID Param)
{
    RACE *R = Param;
    ULONG i;

    for (i = R->Index; !RaceStop; i++)
    {
        if (DeleteFileW(RaceShared[i % RACE_SHARED]))
            R->Ops++;
    }
    return 0;
}

static VOID RaceFail(RACE *R, PCSTR Step, PCWSTR Name, DWORD Error)
{
    if (!R->Failed++)
    {
        R->FirstError = Error;
        lstrcpynA(R->FirstStep, Step, sizeof(R->FirstStep));
        lstrcpynW(R->FirstName, Name, MAX_PATH);
    }
}

/* New files of its own (they get the records the shared files free): every step must succeed, a deleted one must be gone. */
static DWORD WINAPI RaceCreator(PVOID Param)
{
    RACE *R = Param;
    static const CHAR Data[4096];
    WCHAR Name[32], Path[MAX_PATH];
    LARGE_INTEGER Size;
    DWORD Done;
    ULONG i;

    for (i = 0; !RaceStop; i++)
    {
        HANDLE H;
        _snwprintf(Name, 31, L"new-%lu-%lu.tmp", R->Index, i % RACE_RING);
        NtPath(Path, Name);
        H = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (H == INVALID_HANDLE_VALUE)
        {
            RaceFail(R, "create", Path, GetLastError());
            continue;
        }
        if (!WriteFile(H, Data, sizeof(Data), &Done, NULL) || Done != sizeof(Data))
            RaceFail(R, "write", Path, GetLastError());
        Size.QuadPart = 2 * sizeof(Data);
        if (!SetFilePointerEx(H, Size, NULL, FILE_BEGIN) || !SetEndOfFile(H))
            RaceFail(R, "set size", Path, GetLastError());
        CloseHandle(H);
        if (!DeleteFileW(Path))
            RaceFail(R, "delete", Path, GetLastError());
        else if (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
            RaceFail(R, "still there", Path, 0);
        R->Ops++;
    }
    return 0;
}

/*
 * Opens of shared files race with their deletes, and other threads create new files meanwhile.  An open whose
 * lookup found a file that another handle's delete then removed got an FCB of a file that no longer had a name;
 * the cache kept that FCB after the handle closed and it stayed in the driver's lookup by record number, so a
 * new file that got the freed record took it over: its writes and size changes failed with
 * ERROR_FILE_NOT_FOUND, and its delete returned success while the file stayed, until a reboot.  It needs the
 * race to be lost, so a run that does not fail proves little alone; with 1 GB and 2 processors the broken
 * driver failed within one run (thousands of failed steps, files left that could not be deleted).
 */
START_TEST(NtfsOpenDeleteRace)
{
    static RACE Openers[RACE_OPENERS], Deleters[RACE_DELETERS], Creators[RACE_CREATORS];
    HANDLE Threads[RACE_OPENERS + RACE_DELETERS + RACE_CREATORS];
    ULONG t, n = 0, i, Created = 0, Opened = 0, Deleted = 0, Left = 0;
    WCHAR Name[32], Path[MAX_PATH];

    if (!NtInit("NtfsOpenDeleteRace"))
        return;
    for (i = 0; i < RACE_SHARED; i++)
    {
        _snwprintf(Name, 31, L"shared%lu.tmp", i);
        NtPath(RaceShared[i], Name);
    }
    RaceStop = 0;
    for (t = 0; t < RACE_OPENERS; t++)
    {
        Openers[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, RaceOpener, &Openers[t], 0, NULL);
    }
    for (t = 0; t < RACE_DELETERS; t++)
    {
        Deleters[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, RaceDeleter, &Deleters[t], 0, NULL);
    }
    for (t = 0; t < RACE_CREATORS; t++)
    {
        Creators[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, RaceCreator, &Creators[t], 0, NULL);
    }
    for (t = 0; t < n; t++)
        ok(Threads[t] != NULL, "CreateThread failed: %lu\n", GetLastError());
    Sleep(RACE_SECONDS * 1000);
    RaceStop = 1;
    for (t = 0; t < n; t++)
    {
        if (!Threads[t])
            continue;
        WaitForSingleObject(Threads[t], INFINITE);
        CloseHandle(Threads[t]);
    }
    for (t = 0; t < RACE_OPENERS; t++)
        Opened += Openers[t].Ops;
    for (t = 0; t < RACE_DELETERS; t++)
        Deleted += Deleters[t].Ops;
    for (t = 0; t < RACE_CREATORS; t++)
    {
        Created += Creators[t].Ops;
        ok(Creators[t].Failed == 0, "%lu steps on new files failed, first: %s of %ls, error %lu\n",
           Creators[t].Failed, Creators[t].FirstStep, Creators[t].FirstName, Creators[t].FirstError);
        for (i = 0; i < RACE_RING; i++)
        {
            /* A name that could not be removed is left by a broken driver: try once more, then count it. */
            _snwprintf(Name, 31, L"new-%lu-%lu.tmp", t, i);
            NtPath(Path, Name);
            DeleteFileW(Path);
            if (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
                Left++;
        }
    }
    trace("%lu shared opens, %lu deletes, %lu new files in %d s\n", Opened, Deleted, Created, RACE_SECONDS);
    ok(Created > 0 && Opened > 0 && Deleted > 0, "The threads did not run (%lu, %lu, %lu)\n", Created, Opened, Deleted);
    ok(Left == 0, "%lu new files cannot be deleted\n", Left);
    for (i = 0; i < RACE_SHARED; i++)
        DeleteFileW(RaceShared[i]);
    NtCleanup();
}

/* Bytes of nonpaged pool under Tag, or -1 when the tag has none or the information is not available. */
static LONGLONG NonPagedOfTag(ULONG Tag)
{
    static PSYSTEM_POOLTAG_INFORMATION Info;
    static ULONG Size = 0x10000;
    ULONG i, Len;
    NTSTATUS Status;

    for (;;)
    {
        if (!Info)
            Info = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Info)
            return -1;
        Status = NtQuerySystemInformation(SystemPoolTagInformation, Info, Size, &Len);
        if (Status != STATUS_INFO_LENGTH_MISMATCH || Size >= 0x1000000)
            break;
        HeapFree(GetProcessHeap(), 0, Info);
        Info = NULL;
        Size *= 2;
    }
    if (!NT_SUCCESS(Status))
        return -1;
    for (i = 0; i < Info->Count; i++)
    {
        if (Info->TagInfo[i].TagUlong == Tag)
            return Info->TagInfo[i].NonPagedAllocs != Info->TagInfo[i].NonPagedFrees ?
                   (LONGLONG)Info->TagInfo[i].NonPagedUsed : -1;
    }
    return -1;
}

/* A directory with a subdirectory and 20 small files is created and removed again (an install and uninstall). */
static VOID Churn(PCWSTR Dir)
{
    WCHAR Sub[MAX_PATH], File[MAX_PATH];
    ULONG i;

    CreateDirectoryW(Dir, NULL);
    _snwprintf(Sub, MAX_PATH - 1, L"%ls\\sub", Dir);
    CreateDirectoryW(Sub, NULL);
    for (i = 0; i < 20; i++)
    {
        _snwprintf(File, MAX_PATH - 1, L"%ls\\f%lu.dll", i & 1 ? Sub : Dir, i);
        CreateWithId(File);
    }
    for (i = 0; i < 20; i++)
    {
        _snwprintf(File, MAX_PATH - 1, L"%ls\\f%lu.dll", i & 1 ? Sub : Dir, i);
        DeleteFileW(File);
    }
    RemoveDirectoryW(Sub);
    RemoveDirectoryW(Dir);
}

/*
 * ntfsng keeps MFT pages in nonpaged pool ('cNTN', up to its cache limit).  Created and deleted files
 * that reuse their records touch the same few pages; with records allocated onward from the last one
 * every round of churn read about 140 new pages (about 560 KB) until the cache limit dropped them.
 */
START_TEST(NtfsCreateDeletePool)
{
    const ULONG Tag = 'cNTN';
    WCHAR Dir[MAX_PATH];
    LONGLONG Before, After;
    ULONG Round, i, Grew = 0;

    if (!NtInit("NtfsCreateDeletePool"))
        return;
    NtPath(Dir, L"tree");
    for (i = 0; i < 5; i++)
        Churn(Dir);
    Before = NonPagedOfTag(Tag);
    if (Before < 0)
    {
        skip("No nonpaged pool under tag cNTN (not ntfsng)\n");
        NtCleanup();
        return;
    }
    for (Round = 0; Round < 16; Round++)
    {
        for (i = 0; i < 25; i++)
            Churn(Dir);
        After = NonPagedOfTag(Tag);
        if (After - Before > 256 * 1024)
        {
            Grew++;
            trace("Round %lu: cNTN %I64d -> %I64d bytes\n", Round, Before, After);
        }
        Before = After;
    }
    ok(Grew <= 2, "cNTN grew by more than 256 KB in %lu of 16 rounds of 25 create/delete cycles\n", Grew);
    NtCleanup();
}

#define LRACE_LINKERS   1
#define LRACE_RENAMERS  2

static WCHAR LinkNames[RACE_SHARED][MAX_PATH];

/* The same shared files under a second name: a file that loses one name keeps its record. */
static DWORD WINAPI LinkOpener(PVOID Param)
{
    RACE *R = Param;
    static const CHAR Data[4096];
    DWORD Done;
    ULONG i;

    for (i = R->Index; !RaceStop; i++)
    {
        WCHAR Path[MAX_PATH];
        HANDLE H;

        /* Some opens are of a named stream of the file (its FCB is found and listed separately). */
        _snwprintf(Path, MAX_PATH - 1, (i & 8) ? L"%ls:s" : L"%ls", i & 4 ? LinkNames[i % RACE_SHARED] : RaceShared[i % RACE_SHARED]);
        H = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, SHARE_ALL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (H == INVALID_HANDLE_VALUE)
            continue;
        WriteFile(H, Data, sizeof(Data), &Done, NULL);
        CloseHandle(H);
        R->Ops++;
    }
    return 0;
}

/* Both names, one after the other: the file is gone with the second. */
static DWORD WINAPI LinkDeleter(PVOID Param)
{
    RACE *R = Param;
    ULONG i;

    for (i = R->Index; !RaceStop; i++)
    {
        BOOL A = DeleteFileW(RaceShared[i % RACE_SHARED]);
        BOOL B = DeleteFileW(LinkNames[i % RACE_SHARED]);
        if (A || B)
            R->Ops++;
    }
    return 0;
}

static DWORD WINAPI LinkMaker(PVOID Param)
{
    RACE *R = Param;
    ULONG i;

    for (i = R->Index; !RaceStop; i++)
    {
        if (CreateHardLinkW(LinkNames[i % RACE_SHARED], RaceShared[i % RACE_SHARED], NULL))
            R->Ops++;
    }
    return 0;
}

/* A new file replaces a shared name: the file that had the name loses it (and its record, with the last name). */
static DWORD WINAPI LinkRenamer(PVOID Param)
{
    RACE *R = Param;
    WCHAR Name[32], Path[MAX_PATH];
    ULONG i;

    for (i = R->Index; !RaceStop; i++)
    {
        HANDLE H;
        _snwprintf(Name, 31, L"mv-%lu.tmp", R->Index);
        NtPath(Path, Name);
        H = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (H == INVALID_HANDLE_VALUE)
            continue;
        CloseHandle(H);
        if (MoveFileExW(Path, RaceShared[i % RACE_SHARED], MOVEFILE_REPLACE_EXISTING))
            R->Ops++;
        else
            DeleteFileW(Path);
    }
    return 0;
}

/*
 * NtfsOpenDeleteRace with a second name for every shared file (hard links), deletes of one name and then the other,
 * and replacing renames: every way a file can lose its last name while an open of it is between its lookup and its FCB.
 * The threads that create new files check every step, as there.
 */
static VOID RunLinkRace(PCSTR TestName, BOOLEAN Racers)
{
    static RACE Openers[RACE_OPENERS], Deleters[RACE_DELETERS], Makers[LRACE_LINKERS], Renamers[LRACE_RENAMERS],
                Creators[RACE_CREATORS];
    HANDLE Threads[RACE_OPENERS + RACE_DELETERS + LRACE_LINKERS + LRACE_RENAMERS + RACE_CREATORS];
    ULONG t, n = 0, i, Created = 0, Opened = 0, Deleted = 0, Left = 0;
    WCHAR Name[32], Path[MAX_PATH];
    LONGLONG PoolBefore, PoolAfter;

    if (!NtInit(TestName))
        return;
    for (i = 0; i < RACE_SHARED; i++)
    {
        _snwprintf(Name, 31, L"shared%lu.tmp", i);
        NtPath(RaceShared[i], Name);
        _snwprintf(Name, 31, L"link%lu.tmp", i);
        NtPath(LinkNames[i], Name);
    }
    PoolBefore = NonPagedOfTag('GNTN');
    RaceStop = 0;
    for (t = 0; Racers && t < RACE_OPENERS; t++)
    {
        Openers[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, LinkOpener, &Openers[t], 0, NULL);
    }
    for (t = 0; Racers && t < RACE_DELETERS; t++)
    {
        Deleters[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, LinkDeleter, &Deleters[t], 0, NULL);
    }
    for (t = 0; Racers && t < LRACE_LINKERS; t++)
    {
        Makers[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, LinkMaker, &Makers[t], 0, NULL);
    }
    for (t = 0; Racers && t < LRACE_RENAMERS; t++)
    {
        Renamers[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, LinkRenamer, &Renamers[t], 0, NULL);
    }
    for (t = 0; t < RACE_CREATORS; t++)
    {
        Creators[t].Index = t;
        Threads[n++] = CreateThread(NULL, 0, RaceCreator, &Creators[t], 0, NULL);
    }
    for (t = 0; t < n; t++)
        ok(Threads[t] != NULL, "CreateThread failed: %lu\n", GetLastError());
    Sleep(RACE_SECONDS * 1000);
    RaceStop = 1;
    for (t = 0; t < n; t++)
    {
        if (!Threads[t])
            continue;
        WaitForSingleObject(Threads[t], INFINITE);
        CloseHandle(Threads[t]);
    }
    for (t = 0; t < RACE_OPENERS; t++)
        Opened += Openers[t].Ops;
    for (t = 0; t < RACE_DELETERS; t++)
        Deleted += Deleters[t].Ops;
    for (t = 0; t < RACE_CREATORS; t++)
    {
        Created += Creators[t].Ops;
        ok(Creators[t].Failed == 0, "%lu steps on new files failed, first: %s of %ls, error %lu\n",
           Creators[t].Failed, Creators[t].FirstStep, Creators[t].FirstName, Creators[t].FirstError);
        for (i = 0; i < RACE_RING; i++)
        {
            _snwprintf(Name, 31, L"new-%lu-%lu.tmp", t, i);
            NtPath(Path, Name);
            DeleteFileW(Path);
            if (GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES)
                Left++;
        }
    }
    PoolAfter = NonPagedOfTag('GNTN');
    trace("%lu opens, %lu deletes, %lu new files in %d s; GNTN nonpaged %I64d -> %I64d bytes\n",
          Opened, Deleted, Created, RACE_SECONDS, PoolBefore, PoolAfter);
    ok(Created > 0 && (!Racers || (Opened > 0 && Deleted > 0)), "The threads did not run (%lu, %lu, %lu)\n", Created, Opened, Deleted);
    ok(Left == 0, "%lu new files cannot be deleted\n", Left);
    for (i = 0; i < RACE_SHARED; i++)
    {
        DeleteFileW(RaceShared[i]);
        DeleteFileW(LinkNames[i]);
    }
    NtCleanup();
}

START_TEST(NtfsOpenDeleteLinkRace)
{
    RunLinkRace("NtfsOpenDeleteLinkRace", TRUE);
}

/* The same threads that create new files, alone: the pool of the driver without the races (a baseline for the run above). */
START_TEST(NtfsCreateOnlyPool)
{
    RunLinkRace("NtfsCreateOnlyPool", FALSE);
}
