/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: two handles of one file opened at the same time agree on its size and contents while other
 *              threads change, delete and create it again
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define TWIN_FILES      2
#define TWIN_THREADS    8               /* one changer per file, the others check */
#define TWIN_SECONDS    20
#define TWIN_MAX        (128 * 1024)
#define TWIN_BLOCK      4096
#define TWIN_BUFFER     (TWIN_MAX + 4 * TWIN_BLOCK)
#define TWIN_SHARE      (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

typedef struct
{
    CRITICAL_SECTION Lock;
    WCHAR Path[MAX_PATH];
    LONGLONG Size;                      /* the size the file was last given, -1: not known (under Lock) */
    DWORD IdHigh, IdLow;                /* its file ID */
    ULONG Gen;                          /* the generation its whole content was written with */
} TWIN_FILE;

typedef struct
{
    ULONG Index;
    ULONG Seed;
    ULONG Changes, Checks, Other, Bad;
    char First[160];
} TWIN_THREAD;

static TWIN_FILE TwinFile[TWIN_FILES];
static volatile LONG TwinStop, TwinGen;

static ULONG TwinNext(ULONG *Seed)
{
    *Seed = *Seed * 1664525u + 1013904223u;
    return *Seed >> 8;
}

/* Every 4-byte word of the file says its generation and its offset. */
static VOID TwinFill(PULONG Buffer, ULONG Offset, ULONG Length, ULONG Gen)
{
    ULONG i;
    for (i = 0; i < Length / sizeof(ULONG); i++)
        Buffer[i] = (Gen << 20) ^ (Offset + i * sizeof(ULONG));
}

static VOID TwinBad(TWIN_THREAD *T, const char *What, LONGLONG A, LONGLONG B)
{
    if (!T->Bad++)
        _snprintf(T->First, sizeof(T->First) - 1, "%s (%I64d, %I64d)", What, A, B);
}

static LONG TwinRead(HANDLE h, LONGLONG Offset, PVOID Buffer, ULONG Length)
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

static BOOL TwinWrite(HANDLE h, LONGLONG Offset, PVOID Buffer, ULONG Length)
{
    OVERLAPPED Ov;
    DWORD Done = 0;
    ZeroMemory(&Ov, sizeof(Ov));
    Ov.Offset = (DWORD)Offset;
    Ov.OffsetHigh = (DWORD)(Offset >> 32);
    return WriteFile(h, Buffer, Length, &Done, &Ov) && Done == Length;
}

static BOOL TwinSetSize(HANDLE h, LONGLONG Size)
{
    LARGE_INTEGER Pos;
    Pos.QuadPart = Size;
    return SetFilePointerEx(h, Pos, NULL, FILE_BEGIN) && SetEndOfFile(h);
}

static LONGLONG TwinSize(HANDLE h)
{
    LARGE_INTEGER Size;
    return GetFileSizeEx(h, &Size) ? Size.QuadPart : -1;
}

/*
 * Under the file's lock: delete the file and create it again (one time in four), or take the existing one, through a
 * handle without the cache, give it a new size and new contents, record both, close.  A file nobody opened through
 * the cache keeps no cache map, so the file system lets its control block go with that close.
 */
static VOID TwinChange(TWIN_THREAD *T, TWIN_FILE *F, PULONG Buffer)
{
    BY_HANDLE_FILE_INFORMATION I;
    ULONG Length = (1 + TwinNext(&T->Seed) % (TWIN_MAX / 512)) * 512, Gen;
    HANDLE h;

    EnterCriticalSection(&F->Lock);
    F->Size = -1;
    if (TwinNext(&T->Seed) % 4 == 0)
        DeleteFileW(F->Path);
    h = CreateFileW(F->Path, GENERIC_READ | GENERIC_WRITE, TWIN_SHARE, NULL, OPEN_ALWAYS,
                    FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        Gen = (ULONG)InterlockedIncrement(&TwinGen);
        TwinFill(Buffer, 0, Length, Gen);
        if (TwinSetSize(h, Length) && TwinWrite(h, 0, Buffer, Length) && GetFileInformationByHandle(h, &I))
        {
            F->Size = Length;
            F->Gen = Gen;
            F->IdHigh = I.nFileIndexHigh;
            F->IdLow = I.nFileIndexLow;
            T->Changes++;
        }
        CloseHandle(h);
    }
    LeaveCriticalSection(&F->Lock);
    Sleep(TwinNext(&T->Seed) % 3);
}

/*
 * Opens the file through two handles at once (racing the changer; both through the cache or both without it), then
 * under the file's lock: a read of the whole file through the second handle, before anything asks for the size,
 * returns the size and the contents the changer gave it; then a write through the first handle is what the second
 * reads, and both handles report the same size.
 */
static VOID TwinCheck(TWIN_THREAD *T, TWIN_FILE *F, PULONG Buffer, PULONG Back)
{
    BY_HANDLE_FILE_INFORMATION I1, I2;
    HANDLE h1, h2;
    LONGLONG Offset, S1, S2;
    LONG Got;
    ULONG i, Gen;
    /* every other time both handles go without the cache: then no cache map keeps the file's control block */
    DWORD Flags = (TwinNext(&T->Seed) % 2) ? FILE_FLAG_NO_BUFFERING : 0;

    h1 = CreateFileW(F->Path, GENERIC_READ | GENERIC_WRITE, TWIN_SHARE, NULL, OPEN_EXISTING, Flags, NULL);
    if (h1 == INVALID_HANDLE_VALUE)
        return;
    h2 = CreateFileW(F->Path, GENERIC_READ | GENERIC_WRITE, TWIN_SHARE, NULL, OPEN_EXISTING, Flags, NULL);
    if (h2 == INVALID_HANDLE_VALUE)
    {
        CloseHandle(h1);
        return;
    }
    EnterCriticalSection(&F->Lock);
    if (!GetFileInformationByHandle(h1, &I1) || !GetFileInformationByHandle(h2, &I2) || F->Size < 0 ||
        I1.nFileIndexHigh != F->IdHigh || I1.nFileIndexLow != F->IdLow ||
        I2.nFileIndexHigh != F->IdHigh || I2.nFileIndexLow != F->IdLow)
    {
        /* an open of the file the changer has since replaced */
        T->Other++;
        goto done;
    }
    T->Checks++;
    Got = TwinRead(h2, 0, Back, TWIN_BUFFER);
    if (Got != F->Size)
        TwinBad(T, "read of the whole file: length, size given", Got, F->Size);
    else
        for (i = 0; i < (ULONG)Got / sizeof(ULONG); i++)
            if (Back[i] != ((F->Gen << 20) ^ (i * sizeof(ULONG))))
            {
                TwinBad(T, "read of the whole file: other contents at offset, generation", i * sizeof(ULONG), F->Gen);
                break;
            }
    /* a write through one handle is what the other reads */
    Offset = (LONGLONG)(TwinNext(&T->Seed) % (TWIN_MAX / TWIN_BLOCK)) * TWIN_BLOCK;
    Gen = (ULONG)InterlockedIncrement(&TwinGen);
    TwinRead(h2, Offset, Back, TWIN_BLOCK);
    TwinFill(Buffer, (ULONG)Offset, TWIN_BLOCK, Gen);
    if (TwinWrite(h1, Offset, Buffer, TWIN_BLOCK))
    {
        Got = TwinRead(h2, Offset, Back, TWIN_BLOCK);
        if (Got != TWIN_BLOCK || memcmp(Buffer, Back, TWIN_BLOCK))
            TwinBad(T, "read through the second handle after a write through the first: offset, length", Offset, Got);
    }
    S1 = TwinSize(h1);
    S2 = TwinSize(h2);
    if (S1 != S2 || S1 < Offset + TWIN_BLOCK)
        TwinBad(T, "sizes of the two handles after the write", S1, S2);
    /* the contents are no longer one generation: the next check needs the changer first */
    F->Size = -1;
done:
    LeaveCriticalSection(&F->Lock);
    CloseHandle(h2);
    CloseHandle(h1);
}

static DWORD WINAPI TwinThread(PVOID Param)
{
    TWIN_THREAD *T = Param;
    PULONG Buffer = VirtualAlloc(NULL, 2 * TWIN_BUFFER, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!Buffer)
        return 1;
    while (!TwinStop)
    {
        if (T->Index < TWIN_FILES)
            TwinChange(T, &TwinFile[T->Index], Buffer);
        else
            TwinCheck(T, &TwinFile[TwinNext(&T->Seed) % TWIN_FILES], Buffer, Buffer + TWIN_BUFFER / sizeof(ULONG));
    }
    VirtualFree(Buffer, 0, MEM_RELEASE);
    return 0;
}

/*
 * NTFS keeps one control block per stream of a file, shared by all its handles: what one handle writes, truncates or
 * extends is what every other handle of the file reads.  Two changers create, delete and resize two files through
 * handles without the cache while six threads open each file through two handles at once and check, under a lock
 * that keeps the changer out, that a cached read returns the size and contents the changer gave the file, and that
 * the two handles agree after a write.  A driver that builds a control block from a state read before a change that
 * came in the middle of the open (and lists it after) shows the earlier size or contents through such a handle.
 * The race has to be lost to fail, so a pass of one run proves little alone.
 */
START_TEST(NtfsTwinHandles)
{
    static TWIN_THREAD Threads[TWIN_THREADS];
    HANDLE H[TWIN_THREADS];
    ULONG t, i, Checks = 0, Changes = 0, Other = 0;
    WCHAR Name[32];

    if (!NtInit("NtfsTwinHandles"))
        return;
    for (i = 0; i < TWIN_FILES; i++)
    {
        InitializeCriticalSection(&TwinFile[i].Lock);
        _snwprintf(Name, 31, L"twin%lu.tmp", i);
        NtPath(TwinFile[i].Path, Name);
        TwinFile[i].Size = -1;
    }
    TwinStop = 0;
    for (t = 0; t < TWIN_THREADS; t++)
    {
        Threads[t].Index = t;
        Threads[t].Seed = 0x5eed + t * 7919;
        H[t] = CreateThread(NULL, 0, TwinThread, &Threads[t], 0, NULL);
        ok(H[t] != NULL, "CreateThread failed: %lu\n", GetLastError());
    }
    Sleep(TWIN_SECONDS * 1000);
    TwinStop = 1;
    for (t = 0; t < TWIN_THREADS; t++)
    {
        if (!H[t])
            continue;
        WaitForSingleObject(H[t], INFINITE);
        CloseHandle(H[t]);
        Checks += Threads[t].Checks;
        Changes += Threads[t].Changes;
        Other += Threads[t].Other;
        ok(Threads[t].Bad == 0, "Thread %lu: %lu checks failed, first: %s\n", t, Threads[t].Bad, Threads[t].First);
    }
    trace("%lu changes, %lu checks, %lu opens of a replaced file in %d s\n", Changes, Checks, Other, TWIN_SECONDS);
    ok(Changes > 0 && Checks > 0, "The threads did not run (%lu changes, %lu checks)\n", Changes, Checks);
    for (i = 0; i < TWIN_FILES; i++)
    {
        DeleteFileW(TwinFile[i].Path);
        DeleteCriticalSection(&TwinFile[i].Lock);
    }
    NtCleanup();
}
