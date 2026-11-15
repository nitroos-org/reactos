/*
 * PROJECT:     ReactOS tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     File system stress: clusters that are freed and allocated again while transfers run.
 *              "Churn" files are shared by all threads, written and read without the cache and truncated or
 *              deleted while those transfers are in flight. "Canary" files belong to one thread each and are
 *              written once. Every 512 byte sector carries a stamp that says which file, generation and sector
 *              it is. A sector of a canary that holds anything else, or a churn read that returns a canary's
 *              sector, means a transfer reached clusters that had gone to another file. Other threads list the
 *              directory and query attributes meanwhile.
 *
 * usage: fsngrace <dir> <seconds> [threads]
 * exit code 0: no mismatch, 1: mismatches (count printed), 2: usage or setup failure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define SECTOR          512
#define CHURN_FILES     6
#define MAX_SECTORS     2048            /* 1 MB */
#define CANARIES        24              /* per thread, a ring */

#define MAGIC_CANARY    0x43414E41u     /* 'CANA' */
#define MAGIC_CHURN     0x4348524Eu     /* 'CHRN' */

typedef struct _STAMP
{
    ULONG Magic;
    ULONG Owner;        /* thread (canary) or churn file number */
    ULONG Generation;
    ULONG Sector;
    ULONG Check;        /* of the four above */
} STAMP;

static WCHAR Dir[MAX_PATH];
static volatile LONG Stop;
static volatile LONG CanaryBad, ChurnBad, Errors, CanaryOk, ChurnOps, Lists;
static CRITICAL_SECTION PrintLock;

static ULONG
Next(ULONG *Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return *Seed >> 8;
}

static VOID
MakeStamp(STAMP *s, ULONG Magic, ULONG Owner, ULONG Generation, ULONG Sector)
{
    s->Magic = Magic;
    s->Owner = Owner;
    s->Generation = Generation;
    s->Sector = Sector;
    s->Check = Magic ^ (Owner * 2654435761u) ^ (Generation * 40503u) ^ ~Sector;
}

static BOOL
StampValid(const STAMP *s)
{
    return s->Check == (s->Magic ^ (s->Owner * 2654435761u) ^ (s->Generation * 40503u) ^ ~s->Sector);
}

static VOID
FillSectors(PUCHAR Buffer, ULONG First, ULONG Count, ULONG Magic, ULONG Owner, ULONG Generation)
{
    ULONG i, j;

    for (i = 0; i < Count; i++)
    {
        STAMP *s = (STAMP *)(Buffer + i * SECTOR);
        MakeStamp(s, Magic, Owner, Generation, First + i);
        /* the rest of the sector repeats the stamp, so a torn sector shows too */
        for (j = sizeof(STAMP); j + sizeof(STAMP) <= SECTOR; j += sizeof(STAMP))
            memcpy(Buffer + i * SECTOR + j, s, sizeof(STAMP));
    }
}

static BOOL
IsZero(const UCHAR *p, ULONG n)
{
    ULONG i;
    for (i = 0; i < n; i++)
        if (p[i]) return FALSE;
    return TRUE;
}

static VOID
Report(const char *What, const WCHAR *Path, ULONG Sector, const STAMP *s)
{
    EnterCriticalSection(&PrintLock);
    printf("MISMATCH %s %ls sector %lu: magic %08lx owner %lu gen %lu sector %lu valid %d\n",
           What, Path, Sector, s->Magic, s->Owner, s->Generation, s->Sector, StampValid(s));
    fflush(stdout);
    LeaveCriticalSection(&PrintLock);
}

static WCHAR FailedNames[32][MAX_PATH];
static ULONG FailedCount;

/* An operation on a thread's own file that failed: counted, the first ones printed with the error */
static VOID
NoteError(const char *What, const WCHAR *Path, ULONG Done, ULONG Wanted)
{
    DWORD Error = GetLastError();

    LONG n = InterlockedIncrement(&Errors);

    EnterCriticalSection(&PrintLock);
    if (n <= 40)
    {
        printf("ERROR %s %ls: error %lu, %lu of %lu bytes\n", What, Path, Error, Done, Wanted);
        fflush(stdout);
    }
    /* the names that failed, for the probe at the end */
    if (FailedCount < _countof(FailedNames))
    {
        ULONG i;
        for (i = 0; i < FailedCount; i++)
            if (!lstrcmpiW(FailedNames[i], Path)) break;
        if (i == FailedCount)
            lstrcpynW(FailedNames[FailedCount++], Path, MAX_PATH);
    }
    LeaveCriticalSection(&PrintLock);
}

/* With every thread gone: what each way of reaching a name that failed says about it */
static ULONG
ProbeFailedNames(VOID)
{
    ULONG i, Stuck = 0;

    for (i = 0; i < FailedCount; i++)
    {
        WIN32_FIND_DATAW fd;
        HANDLE h;
        DWORD Create, Open, Attr, AttrError, Delete, Again;
        BOOL Listed;

        h = CreateFileW(FailedNames[i], GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        Create = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        if (h != INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
            DeleteFileW(FailedNames[i]);
            continue;
        }
        h = FindFirstFileW(FailedNames[i], &fd);
        Listed = (h != INVALID_HANDLE_VALUE);
        if (Listed)
            FindClose(h);
        h = CreateFileW(FailedNames[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        Open = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
        SetLastError(0);
        Attr = GetFileAttributesW(FailedNames[i]);
        AttrError = GetLastError();
        SetLastError(0);
        Delete = DeleteFileW(FailedNames[i]) ? 0 : GetLastError();
        h = CreateFileW(FailedNames[i], GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        Again = (h == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
        if (h != INVALID_HANDLE_VALUE)
        {
            CloseHandle(h);
            DeleteFileW(FailedNames[i]);
        }
        Stuck++;
        printf("STUCK %ls: create error %lu, listed in the directory %s (size %lu), open error %lu, "
               "attributes 0x%lx error %lu, delete error %lu, create again error %lu\n",
               FailedNames[i], Create, Listed ? "yes" : "no", Listed ? fd.nFileSizeLow : 0, Open,
               Attr, AttrError, Delete, Again);
    }
    return Stuck;
}

/* --- canaries */

typedef struct _CANARY
{
    WCHAR Path[MAX_PATH];
    ULONG Generation, Sectors;
    BOOL Live;
    /* of the last write that failed */
    ULONG Mode, FailError, FailDone;
    const char *FailStep;
} CANARY;

static BOOL
WriteCanary(CANARY *c, ULONG Thread, ULONG *Seed, PUCHAR Buffer)
{
    ULONG Mode = Next(Seed) % 3;
    HANDLE h;
    DWORD Done;
    BOOL Ok;

    c->Sectors = 1 + Next(Seed) % (Next(Seed) % 4 ? 64 : MAX_SECTORS);
    FillSectors(Buffer, 0, c->Sectors, MAGIC_CANARY, Thread, c->Generation);

    c->Mode = Mode;
    c->FailStep = "create";
    h = CreateFileW(c->Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                    Mode == 0 ? FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH : FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        c->FailError = GetLastError();
        return FALSE;
    }

    if (Mode == 2)
    {
        /* through a mapped view */
        HANDLE Map = NULL;
        PVOID View = NULL;
        LARGE_INTEGER Size;

        Size.QuadPart = (ULONGLONG)c->Sectors * SECTOR;
        c->FailStep = "set size";
        Ok = SetFilePointerEx(h, Size, NULL, FILE_BEGIN) && SetEndOfFile(h);
        if (Ok)
        {
            c->FailStep = "create mapping";
            Map = CreateFileMappingW(h, NULL, PAGE_READWRITE, 0, 0, NULL);
        }
        if (Map)
        {
            c->FailStep = "map view";
            View = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, 0);
        }
        if (View)
        {
            memcpy(View, Buffer, c->Sectors * SECTOR);
            FlushViewOfFile(View, 0);
            UnmapViewOfFile(View);
        }
        else
        {
            c->FailError = GetLastError();
            Ok = FALSE;
        }
        if (Map)
            CloseHandle(Map);
    }
    else
    {
        c->FailStep = "write";
        Done = 0;
        Ok = WriteFile(h, Buffer, c->Sectors * SECTOR, &Done, NULL) && Done == c->Sectors * SECTOR;
        if (!Ok)
            c->FailError = GetLastError();
        c->FailDone = Done;
    }
    if (Ok)
        FlushFileBuffers(h);
    CloseHandle(h);
    /* a file that could not be written must not stay behind under the name */
    if (!Ok)
        DeleteFileW(c->Path);
    c->Live = Ok;
    return Ok;
}

static VOID
CheckCanary(CANARY *c, ULONG Thread, ULONG *Seed, PUCHAR Buffer)
{
    BOOL Direct = Next(Seed) % 2;
    HANDLE h;
    DWORD Done = 0;
    ULONG i;

    h = CreateFileW(c->Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    Direct ? FILE_FLAG_NO_BUFFERING : FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        NoteError("open canary to check", c->Path, 0, 0);
        return;
    }
    if (!ReadFile(h, Buffer, c->Sectors * SECTOR, &Done, NULL) || Done != c->Sectors * SECTOR)
    {
        NoteError(Direct ? "read canary (direct)" : "read canary (cached)", c->Path, Done, c->Sectors * SECTOR);
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    for (i = 0; i < c->Sectors; i++)
    {
        STAMP Want, *Got = (STAMP *)(Buffer + i * SECTOR);
        MakeStamp(&Want, MAGIC_CANARY, Thread, c->Generation, i);
        /* the stamp at the start of the sector and its last repeat */
        if (memcmp(&Want, Got, sizeof(STAMP)) ||
            memcmp(&Want, Buffer + i * SECTOR + ((SECTOR / sizeof(STAMP)) - 1) * sizeof(STAMP), sizeof(STAMP)))
        {
            if (InterlockedIncrement(&CanaryBad) <= 20)
                Report(Direct ? "canary(direct read)" : "canary(cached read)", c->Path, i, Got);
        }
    }
    InterlockedIncrement(&CanaryOk);
}

/* --- churn files */

static VOID
ChurnPath(WCHAR *Path, ULONG File)
{
    _snwprintf(Path, MAX_PATH, L"%s\\churn%lu.bin", Dir, File);
}

static VOID
ChurnOp(ULONG *Seed, PUCHAR Buffer)
{
    ULONG File = Next(Seed) % CHURN_FILES, Op = Next(Seed) % 100;
    WCHAR Path[MAX_PATH];
    HANDLE h;
    LARGE_INTEGER Pos;
    DWORD Done;
    ULONG First, Count, i;

    ChurnPath(Path, File);
    InterlockedIncrement(&ChurnOps);

    if (Op < 6)
    {
        DeleteFileW(Path);
        return;
    }

    h = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_ALWAYS, (Op % 4) ? FILE_FLAG_NO_BUFFERING : FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;

    First = Next(Seed) % (MAX_SECTORS / 2);
    Count = 1 + Next(Seed) % (MAX_SECTORS / 2);
    Pos.QuadPart = (ULONGLONG)First * SECTOR;

    if (Op < 45)
    {
        FillSectors(Buffer, First, Count, MAGIC_CHURN, File, 0);
        if (SetFilePointerEx(h, Pos, NULL, FILE_BEGIN))
            WriteFile(h, Buffer, Count * SECTOR, &Done, NULL);
    }
    else if (Op < 70)
    {
        /* truncate: to nothing, or to somewhere inside */
        Pos.QuadPart = (Op < 58) ? 0 : (ULONGLONG)(Next(Seed) % MAX_SECTORS) * SECTOR;
        if (SetFilePointerEx(h, Pos, NULL, FILE_BEGIN))
            SetEndOfFile(h);
    }
    else
    {
        Done = 0;
        if (SetFilePointerEx(h, Pos, NULL, FILE_BEGIN) && ReadFile(h, Buffer, Count * SECTOR, &Done, NULL))
        {
            /* whatever a churn file returns is zero or a churn stamp, never a canary's sector */
            for (i = 0; i < Done / SECTOR; i++)
            {
                STAMP *Got = (STAMP *)(Buffer + i * SECTOR);
                if (Got->Magic == MAGIC_CANARY && StampValid(Got))
                {
                    if (InterlockedIncrement(&ChurnBad) <= 20)
                        Report("churn read returned a canary sector", Path, First + i, Got);
                }
                else if (Got->Magic != MAGIC_CHURN && !IsZero((PUCHAR)Got, sizeof(STAMP)))
                {
                    if (InterlockedIncrement(&ChurnBad) <= 20)
                        Report("churn read returned foreign data", Path, First + i, Got);
                }
            }
        }
    }
    CloseHandle(h);
}

static DWORD WINAPI
Worker(PVOID Param)
{
    ULONG Thread = (ULONG)(ULONG_PTR)Param, Seed = 0xC0FFEE + Thread * 7919, Slot = 0, i;
    static CANARY Canaries[32][CANARIES];
    CANARY *Mine = Canaries[Thread % 32];
    PUCHAR Buffer = VirtualAlloc(NULL, MAX_SECTORS * SECTOR, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG Generation = 1;

    if (!Buffer)
        return 1;

    while (!Stop)
    {
        CANARY *c = &Mine[Slot];

        /* the canary that has been around longest is checked, then replaced */
        if (c->Live)
        {
            CheckCanary(c, Thread, &Seed, Buffer);
            DeleteFileW(c->Path);
            c->Live = FALSE;
        }
        for (i = 0; i < 6 && !Stop; i++)
            ChurnOp(&Seed, Buffer);

        _snwprintf(c->Path, MAX_PATH, L"%s\\canary-of-thread-%lu-number-%lu.dat", Dir, Thread, Slot);
        c->Generation = Generation++;
        if (!WriteCanary(c, Thread, &Seed, Buffer))
        {
            static const char *const Modes[] = { "direct", "cached", "mapped" };
            char What[80];

            _snprintf(What, sizeof(What), "write canary (%s, step %s)", Modes[c->Mode % 3], c->FailStep);
            What[sizeof(What) - 1] = 0;
            SetLastError(c->FailError);
            NoteError(What, c->Path, c->FailDone, c->Sectors * SECTOR);
        }

        for (i = 0; i < 6 && !Stop; i++)
            ChurnOp(&Seed, Buffer);

        /* and now and then every live one */
        if (Next(&Seed) % 16 == 0)
        {
            for (i = 0; i < CANARIES; i++)
                if (Mine[i].Live)
                    CheckCanary(&Mine[i], Thread, &Seed, Buffer);
        }
        Slot = (Slot + 1) % CANARIES;
    }

    for (i = 0; i < CANARIES; i++)
    {
        if (Mine[i].Live)
        {
            CheckCanary(&Mine[i], Thread, &Seed, Buffer);
            DeleteFileW(Mine[i].Path);
        }
    }
    VirtualFree(Buffer, 0, MEM_RELEASE);
    return 0;
}

static DWORD WINAPI
Lister(PVOID Param)
{
    WCHAR Pattern[MAX_PATH], Path[MAX_PATH];
    WIN32_FIND_DATAW fd;

    _snwprintf(Pattern, MAX_PATH, L"%s\\*", Dir);
    while (!Stop)
    {
        HANDLE h = FindFirstFileW(Pattern, &fd);
        if (h == INVALID_HANDLE_VALUE)
            continue;
        do
        {
            _snwprintf(Path, MAX_PATH, L"%s\\%s", Dir, fd.cFileName);
            GetFileAttributesW(Path);
        } while (FindNextFileW(h, &fd) && !Stop);
        FindClose(h);
        InterlockedIncrement(&Lists);
    }
    return 0;
}

int
wmain(int argc, WCHAR **argv)
{
    HANDLE Threads[40];
    ULONG Count, Seconds, i, n = 0, StuckNames;
    WCHAR Path[MAX_PATH];

    if (argc < 3)
    {
        printf("usage: fsngrace <dir> <seconds> [threads]\n");
        return 2;
    }
    lstrcpynW(Dir, argv[1], MAX_PATH - 64);
    Seconds = _wtoi(argv[2]);
    Count = argc > 3 ? _wtoi(argv[3]) : 6;
    if (Count < 1 || Count > 32)
        Count = 6;
    CreateDirectoryW(Dir, NULL);
    if (GetFileAttributesW(Dir) == INVALID_FILE_ATTRIBUTES)
    {
        printf("cannot create %ls\n", Dir);
        return 2;
    }
    InitializeCriticalSection(&PrintLock);

    for (i = 0; i < Count; i++)
        Threads[n++] = CreateThread(NULL, 0, Worker, (PVOID)(ULONG_PTR)i, 0, NULL);
    Threads[n++] = CreateThread(NULL, 0, Lister, NULL, 0, NULL);
    Threads[n++] = CreateThread(NULL, 0, Lister, NULL, 0, NULL);

    for (i = 0; i < Seconds; i++)
    {
        Sleep(1000);
        if (i % 30 == 29)
        {
            printf("t=%lu canaries checked %ld bad %ld, churn ops %ld bad %ld, lists %ld, errors %ld\n",
                   i + 1, CanaryOk, CanaryBad, ChurnOps, ChurnBad, Lists, Errors);
            fflush(stdout);
        }
    }
    Stop = 1;
    WaitForMultipleObjects(n, Threads, TRUE, 120000);

    for (i = 0; i < CHURN_FILES; i++)
    {
        ChurnPath(Path, i);
        DeleteFileW(Path);
    }
    Sleep(3000);
    StuckNames = ProbeFailedNames();
    printf("RESULT canaries checked %ld bad %ld, churn ops %ld bad %ld, lists %ld, errors %ld, "
           "names that failed %lu, of them unusable afterwards %lu\n",
           CanaryOk, CanaryBad, ChurnOps, ChurnBad, Lists, Errors, FailedCount, StuckNames);
    return (CanaryBad || ChurnBad || StuckNames) ? 1 : 0;
}
