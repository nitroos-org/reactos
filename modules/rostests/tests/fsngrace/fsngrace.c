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
 *              "Twin" threads (the optional fourth argument) open one of a few shared files through two handles at
 *              the same time, while others delete and recreate it, and check that what one handle writes, truncates
 *              or extends (cached or through a mapped view) is what the other handle reads and reports as the size.
 *
 * usage: fsngrace <dir> <seconds> [threads] [twin threads]
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

/* --- twins: one file, two handles */

#define TWIN_FILES      2
#define TWIN_MAX        (256 * 1024)
#define TWIN_BLOCK_MAX  (16 * 1024)
#define TWIN_BUFFER     (TWIN_MAX + 4 * TWIN_BLOCK_MAX)

/* Under TwinLock[File]: the size the file was last given and its file ID (TwinSize -1: not known) */
static CRITICAL_SECTION TwinLock[TWIN_FILES];
static LONGLONG TwinSizeNow[TWIN_FILES];
static DWORD TwinIdHigh[TWIN_FILES], TwinIdLow[TWIN_FILES];
static volatile LONG TwinChecks, TwinBad, TwinOther, TwinGen, TwinChanges;

static VOID
TwinPath(WCHAR *Path, ULONG File)
{
    _snwprintf(Path, MAX_PATH, L"%s\\twin%lu.bin", Dir, File);
}

static VOID
TwinReport(const char *What, ULONG File, LONGLONG A, LONGLONG B, LONGLONG C)
{
    if (InterlockedIncrement(&TwinBad) > 40)
        return;
    EnterCriticalSection(&PrintLock);
    printf("TWIN MISMATCH %s: twin%lu %I64d %I64d %I64d\n", What, File, A, B, C);
    fflush(stdout);
    LeaveCriticalSection(&PrintLock);
}

static LONGLONG
TwinSize(HANDLE h)
{
    LARGE_INTEGER Size;
    return GetFileSizeEx(h, &Size) ? Size.QuadPart : -1;
}

/* Reads Length bytes at Offset through h; the count read, or -1. */
static LONG
TwinRead(HANDLE h, LONGLONG Offset, PUCHAR Buffer, ULONG Length)
{
    OVERLAPPED Ov;
    DWORD Done = 0;

    ZeroMemory(&Ov, sizeof(Ov));
    Ov.Offset = (DWORD)Offset;
    Ov.OffsetHigh = (DWORD)(Offset >> 32);
    if (!ReadFile(h, Buffer, Length, &Done, &Ov))
        return GetLastError() == ERROR_HANDLE_EOF ? 0 : -1;
    return (LONG)Done;
}

static BOOL
TwinWrite(HANDLE h, LONGLONG Offset, const UCHAR *Buffer, ULONG Length)
{
    OVERLAPPED Ov;
    DWORD Done = 0;

    ZeroMemory(&Ov, sizeof(Ov));
    Ov.Offset = (DWORD)Offset;
    Ov.OffsetHigh = (DWORD)(Offset >> 32);
    return WriteFile(h, Buffer, Length, &Done, &Ov) && Done == Length;
}

static BOOL
TwinSetSize(HANDLE h, LONGLONG Size)
{
    LARGE_INTEGER Pos;
    Pos.QuadPart = Size;
    return SetFilePointerEx(h, Pos, NULL, FILE_BEGIN) && SetEndOfFile(h);
}

/*
 * The changer of a twin file: under the file's lock it deletes the file and creates it again, or changes the size of
 * the existing one, through a handle without the cache, writes stamps over the whole file and records its size and
 * file ID; the handle is closed before the lock is let go.  A file that nobody opened through the cache has no cache
 * map, so its control block goes with that close, and the next open builds a new one: the opens of the checkers
 * race with these changes.
 */
static VOID
TwinChange(ULONG File, ULONG *Seed, PUCHAR Buffer)
{
    BY_HANDLE_FILE_INFORMATION I;
    WCHAR Path[MAX_PATH];
    HANDLE h;
    ULONG Sectors = 1 + Next(Seed) % (TWIN_MAX / SECTOR), Gen;
    BOOL Recreate = Next(Seed) % 4 == 0;

    TwinPath(Path, File);
    EnterCriticalSection(&TwinLock[File]);
    TwinSizeNow[File] = -1;
    if (Recreate)
        DeleteFileW(Path);
    /* a checker's handle keeps a deleted file (delete pending): then the create fails until it is closed */
    h = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                    OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        Gen = (ULONG)InterlockedIncrement(&TwinGen);
        FillSectors(Buffer, 0, Sectors, MAGIC_CHURN, 300 + File, Gen);
        if (TwinSetSize(h, (LONGLONG)Sectors * SECTOR) && TwinWrite(h, 0, Buffer, Sectors * SECTOR) &&
            GetFileInformationByHandle(h, &I))
        {
            TwinSizeNow[File] = (LONGLONG)Sectors * SECTOR;
            TwinIdHigh[File] = I.nFileIndexHigh;
            TwinIdLow[File] = I.nFileIndexLow;
            InterlockedIncrement(&TwinChanges);
        }
        CloseHandle(h);
    }
    LeaveCriticalSection(&TwinLock[File]);
    Sleep(Next(Seed) % 3);
}

/*
 * Opens a twin file through two handles at once (the changer's deletes, creates and size changes race with these
 * opens; both handles go through the cache, or one time in three both without it), then, holding the file's lock so
 * that nothing changes it meanwhile: a read of the whole file through the second handle, before anything asks the file
 * system for the size, must return exactly the size the file was last given (what the handle's file control block
 * says, not a size query, which refreshes it); then a change through one handle
 * and a check through the other: the size each reports, the bytes a cached read returns after a cached or mapped write,
 * the end after a truncation, zeros after an extension.  Two handles of one file must agree on all of it.
 */
static VOID
TwinOp(ULONG *Seed, PUCHAR Buffer, PUCHAR Back)
{
    ULONG File = Next(Seed) % TWIN_FILES, Op = Next(Seed) % 100, Gen, Length, i;
    /* one time in three both handles go without the cache: then no cache map keeps the file's control block */
    DWORD Flags = (Next(Seed) % 3 == 0) ? FILE_FLAG_NO_BUFFERING : FILE_ATTRIBUTE_NORMAL;
    BY_HANDLE_FILE_INFORMATION I1, I2;
    WCHAR Path[MAX_PATH];
    HANDLE h1, h2, Map;
    LONGLONG Size1, Size2, Offset, NewSize;
    LONG Got;

    TwinPath(Path, File);
    h1 = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                     OPEN_EXISTING, Flags, NULL);
    if (h1 == INVALID_HANDLE_VALUE)
        return;
    h2 = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                     OPEN_EXISTING, Flags, NULL);
    if (h2 == INVALID_HANDLE_VALUE)
    {
        CloseHandle(h1);
        return;
    }
    /* A delete between the two opens can leave them on two files: then there is nothing to compare. */
    if (!GetFileInformationByHandle(h1, &I1) || !GetFileInformationByHandle(h2, &I2) ||
        I1.nFileIndexHigh != I2.nFileIndexHigh || I1.nFileIndexLow != I2.nFileIndexLow)
    {
        InterlockedIncrement(&TwinOther);
        CloseHandle(h2);
        CloseHandle(h1);
        return;
    }

    EnterCriticalSection(&TwinLock[File]);
    if (TwinSizeNow[File] < 0 || TwinIdHigh[File] != I1.nFileIndexHigh || TwinIdLow[File] != I1.nFileIndexLow)
    {
        /* opened a file the changer has replaced since, or one whose size is not known */
        LeaveCriticalSection(&TwinLock[File]);
        InterlockedIncrement(&TwinOther);
        CloseHandle(h2);
        CloseHandle(h1);
        return;
    }
    InterlockedIncrement(&TwinChecks);
    Got = TwinRead(h2, 0, Back, TWIN_BUFFER - TWIN_BLOCK_MAX);
    if (Got != TwinSizeNow[File])
        TwinReport(Flags == FILE_FLAG_NO_BUFFERING ? "read (no cache) of the whole file: other length than the file has" :
                   "cached read of the whole file: other length than the file has", File, Got,
                   TwinSizeNow[File], 0);
    Size1 = TwinSize(h1);
    Size2 = TwinSize(h2);
    if (Size1 != Size2 || Size1 != TwinSizeNow[File])
        TwinReport("sizes of two handles differ", File, Size1, Size2, TwinSizeNow[File]);

    Offset = (LONGLONG)(Next(Seed) % (TWIN_MAX / SECTOR)) * SECTOR;
    Length = (1 + Next(Seed) % (TWIN_BLOCK_MAX / SECTOR)) * SECTOR;
    Gen = (ULONG)InterlockedIncrement(&TwinGen);
    /* What the reading handle has cached before the change is what a second cache would keep. */
    TwinRead(h2, Offset, Back, Length);

    if (Op < 50)
    {
        /* cached write through one handle, cached read through the other */
        FillSectors(Buffer, (ULONG)(Offset / SECTOR), Length / SECTOR, MAGIC_CHURN, 100 + File, Gen);
        if (TwinWrite(h1, Offset, Buffer, Length))
        {
            Got = TwinRead(h2, Offset, Back, Length);
            if (Got != (LONG)Length)
                TwinReport("read after write: length", File, Offset, Length, Got);
            else if (memcmp(Buffer, Back, Length))
                TwinReport("read after write: other bytes", File, Offset, Length, Gen);
            Size1 = TwinSize(h1);
            Size2 = TwinSize(h2);
            if (Size1 != Size2 || Size2 < Offset + Length)
                TwinReport("size after write", File, Size1, Size2, Offset + Length);
        }
    }
    else if (Op < 65)
    {
        /* through a mapped view of one handle, cached read through the other (a read without the cache is not
         * coherent with a mapped view: only with cached handles) */
        if (Size1 >= SECTOR && Flags != FILE_FLAG_NO_BUFFERING)
        {
            Offset = (LONGLONG)(Next(Seed) % (ULONG)(Size1 / SECTOR)) * SECTOR;
            Length = SECTOR;
            FillSectors(Buffer, (ULONG)(Offset / SECTOR), 1, MAGIC_CHURN, 200 + File, Gen);
            Map = CreateFileMappingW(h1, NULL, PAGE_READWRITE, 0, 0, NULL);
            if (Map)
            {
                PUCHAR View = MapViewOfFile(Map, FILE_MAP_WRITE, 0, 0, 0);
                if (View)
                {
                    memcpy(View + Offset, Buffer, SECTOR);
                    Got = TwinRead(h2, Offset, Back, SECTOR);
                    if (Got != SECTOR || memcmp(Buffer, Back, SECTOR))
                        TwinReport("read after a mapped write", File, Offset, Got, Gen);
                    UnmapViewOfFile(View);
                }
                CloseHandle(Map);
            }
        }
    }
    else if (Op < 85)
    {
        /* truncation through one handle: the other sees the new end and nothing past it */
        /* whole sectors: a handle without the cache reads at sector offsets only */
        NewSize = (LONGLONG)(Next(Seed) % (TWIN_MAX / SECTOR) / (Op < 75 ? 8 : 1)) * SECTOR;
        if (NewSize < Size1 && TwinSetSize(h1, NewSize))
        {
            Size2 = TwinSize(h2);
            if (Size2 != NewSize)
                TwinReport("size after truncation", File, Size1, NewSize, Size2);
            Got = TwinRead(h2, NewSize, Back, SECTOR);
            if (Got != 0)
                TwinReport("read past the end after truncation", File, NewSize, Got, Size1);
            if (NewSize >= SECTOR)
            {
                Got = TwinRead(h2, NewSize - SECTOR, Back, 2 * SECTOR);
                if (Got != SECTOR)
                    TwinReport("read at the end after truncation", File, NewSize, Got, Size1);
            }
        }
    }
    else
    {
        /* extension through the second handle: the first reads zeros there */
        NewSize = Size1 + (1 + Next(Seed) % 64) * SECTOR;
        if (NewSize <= TWIN_MAX + TWIN_BLOCK_MAX && TwinSetSize(h2, NewSize))
        {
            Size1 = TwinSize(h1);
            if (Size1 != NewSize)
                TwinReport("size after extension", File, Size1, NewSize, 0);
            Got = TwinRead(h1, NewSize - SECTOR, Back, SECTOR);
            if (Got != SECTOR)
                TwinReport("read of the extension: length", File, NewSize, Got, 0);
            else
                for (i = 0; i < SECTOR; i++)
                    if (Back[i])
                    {
                        TwinReport("extension not zero", File, NewSize - SECTOR + i, Back[i], 0);
                        break;
                    }
        }
    }
    /* what the next checker must find (a size query answers from the file system) */
    TwinSizeNow[File] = TwinSize(h2);
    LeaveCriticalSection(&TwinLock[File]);
    if (Op & 1)
    {
        CloseHandle(h1);
        CloseHandle(h2);
    }
    else
    {
        CloseHandle(h2);
        CloseHandle(h1);
    }
}

static DWORD WINAPI
Twin(PVOID Param)
{
    ULONG Index = (ULONG)(ULONG_PTR)Param, Seed = 0x7717 + Index * 104729;
    PUCHAR Buffer = VirtualAlloc(NULL, 2 * TWIN_BUFFER, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!Buffer)
        return 1;
    /* one thread in four changes a file (they take the files in turn), the others check */
    while (!Stop)
    {
        if (Index % 4 == 0)
            TwinChange((Index / 4) % TWIN_FILES, &Seed, Buffer);
        else
            TwinOp(&Seed, Buffer, Buffer + TWIN_BUFFER);
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
    HANDLE Threads[80];
    ULONG Count, Twins, Seconds, i, n = 0, StuckNames;
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
    Twins = argc > 4 ? _wtoi(argv[4]) : 0;
    if (Twins > 32)
        Twins = 32;
    CreateDirectoryW(Dir, NULL);
    if (GetFileAttributesW(Dir) == INVALID_FILE_ATTRIBUTES)
    {
        printf("cannot create %ls\n", Dir);
        return 2;
    }
    InitializeCriticalSection(&PrintLock);
    for (i = 0; i < TWIN_FILES; i++)
        InitializeCriticalSection(&TwinLock[i]);

    for (i = 0; i < Count; i++)
        Threads[n++] = CreateThread(NULL, 0, Worker, (PVOID)(ULONG_PTR)i, 0, NULL);
    for (i = 0; i < Twins; i++)
        Threads[n++] = CreateThread(NULL, 0, Twin, (PVOID)(ULONG_PTR)i, 0, NULL);
    Threads[n++] = CreateThread(NULL, 0, Lister, NULL, 0, NULL);
    Threads[n++] = CreateThread(NULL, 0, Lister, NULL, 0, NULL);

    for (i = 0; i < Seconds; i++)
    {
        Sleep(1000);
        if (i % 30 == 29)
        {
            printf("t=%lu canaries checked %ld bad %ld, churn ops %ld bad %ld, lists %ld, errors %ld, "
                   "twin checks %ld bad %ld\n",
                   i + 1, CanaryOk, CanaryBad, ChurnOps, ChurnBad, Lists, Errors, TwinChecks, TwinBad);
            fflush(stdout);
        }
    }
    Stop = 1;
    /* WaitForMultipleObjects takes at most MAXIMUM_WAIT_OBJECTS handles */
    for (i = 0; i < n; i += MAXIMUM_WAIT_OBJECTS)
        WaitForMultipleObjects(min(n - i, MAXIMUM_WAIT_OBJECTS), Threads + i, TRUE, 120000);

    for (i = 0; i < CHURN_FILES; i++)
    {
        ChurnPath(Path, i);
        DeleteFileW(Path);
    }
    for (i = 0; i < TWIN_FILES; i++)
    {
        TwinPath(Path, i);
        DeleteFileW(Path);
    }
    Sleep(3000);
    StuckNames = ProbeFailedNames();
    printf("RESULT canaries checked %ld bad %ld, churn ops %ld bad %ld, lists %ld, errors %ld, "
           "names that failed %lu, of them unusable afterwards %lu, twin checks %ld bad %ld (opens on two files %ld)\n",
           CanaryOk, CanaryBad, ChurnOps, ChurnBad, Lists, Errors, FailedCount, StuckNames, TwinChecks, TwinBad,
           TwinOther);
    return (CanaryBad || ChurnBad || StuckNames || TwinBad) ? 1 : 0;
}
