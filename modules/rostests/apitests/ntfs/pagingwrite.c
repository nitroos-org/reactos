/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: paging writes of cached and mapped files reach the disk intact, from several threads,
 *              for files whose data is split into many runs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define PW_THREADS 4
#define PW_ROUNDS 3
#define PW_CHUNK (256 * 1024)
#define PW_CHUNKS 24                /* 6 MB per cached file */
#define PW_MAPPED (4 * 1024 * 1024) /* per mapped file */

typedef struct
{
    ULONG Index;
    LONG Errors;
} PW_THREAD;

static ULONG PwPattern(ULONG File, ULONG Round, ULONGLONG Offset)
{
    return (ULONG)(Offset / sizeof(ULONG)) * 2654435761u ^ (File << 24) ^ (Round << 16);
}

static VOID PwFill(PULONG Buffer, ULONG Bytes, ULONG File, ULONG Round, ULONGLONG Offset)
{
    ULONG i;

    for (i = 0; i < Bytes / sizeof(ULONG); i++)
        Buffer[i] = PwPattern(File, Round, Offset + i * sizeof(ULONG));
}

/* Reads Path without the cache (what the paging writes left on the disk) and compares it; 0 if equal. */
static LONG PwVerify(PCWSTR Path, ULONG File, ULONG Round, ULONGLONG Size, PULONG Buffer)
{
    HANDLE H;
    ULONGLONG Offset;
    DWORD Read;
    ULONG i;

    H = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, NULL);
    if (H == INVALID_HANDLE_VALUE)
        return 1;
    for (Offset = 0; Offset < Size; Offset += PW_CHUNK)
    {
        if (!ReadFile(H, Buffer, PW_CHUNK, &Read, NULL) || Read != PW_CHUNK)
        {
            CloseHandle(H);
            return 2;
        }
        for (i = 0; i < PW_CHUNK / sizeof(ULONG); i++)
            if (Buffer[i] != PwPattern(File, Round, Offset + i * sizeof(ULONG)))
            {
                trace("%ls: offset 0x%I64x has 0x%08lx, expected 0x%08lx\n", Path,
                      Offset + i * sizeof(ULONG), Buffer[i], PwPattern(File, Round, Offset + i * sizeof(ULONG)));
                CloseHandle(H);
                return 3;
            }
    }
    CloseHandle(H);
    return 0;
}

/*
 * Two cached files grow in turn by PW_CHUNK and are flushed after every pair of chunks, so their clusters
 * interleave and one flush writes several runs; then a mapped file is written through its view and flushed.
 */
static DWORD WINAPI PwThread(PVOID Param)
{
    PW_THREAD *T = Param;
    WCHAR PathA[MAX_PATH], PathB[MAX_PATH], PathM[MAX_PATH], Name[32];
    PULONG Buffer;
    ULONG Round, c;

    Buffer = VirtualAlloc(NULL, PW_CHUNK, MEM_COMMIT, PAGE_READWRITE);
    if (!Buffer)
    {
        T->Errors++;
        return 0;
    }
    for (Round = 0; Round < PW_ROUNDS; Round++)
    {
        HANDLE A, B, M, Section;
        PULONG View;
        DWORD Written;
        LARGE_INTEGER Size;

        _snwprintf(Name, RTL_NUMBER_OF(Name), L"pw%lu-a.tmp", T->Index);
        NtPath(PathA, Name);
        _snwprintf(Name, RTL_NUMBER_OF(Name), L"pw%lu-b.tmp", T->Index);
        NtPath(PathB, Name);
        _snwprintf(Name, RTL_NUMBER_OF(Name), L"pw%lu-m.tmp", T->Index);
        NtPath(PathM, Name);
        A = CreateFileW(PathA, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        B = CreateFileW(PathB, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (A == INVALID_HANDLE_VALUE || B == INVALID_HANDLE_VALUE)
        {
            T->Errors++;
            if (A != INVALID_HANDLE_VALUE)
                CloseHandle(A);
            if (B != INVALID_HANDLE_VALUE)
                CloseHandle(B);
            break;
        }
        for (c = 0; c < PW_CHUNKS; c++)
        {
            PwFill(Buffer, PW_CHUNK, T->Index * 3, Round, (ULONGLONG)c * PW_CHUNK);
            if (!WriteFile(A, Buffer, PW_CHUNK, &Written, NULL) || Written != PW_CHUNK)
                T->Errors++;
            PwFill(Buffer, PW_CHUNK, T->Index * 3 + 1, Round, (ULONGLONG)c * PW_CHUNK);
            if (!WriteFile(B, Buffer, PW_CHUNK, &Written, NULL) || Written != PW_CHUNK)
                T->Errors++;
            if (c & 1)
            {
                if (!FlushFileBuffers(A) || !FlushFileBuffers(B))
                    T->Errors++;
            }
        }
        if (!FlushFileBuffers(A) || !FlushFileBuffers(B))
            T->Errors++;
        CloseHandle(A);
        CloseHandle(B);

        M = CreateFileW(PathM, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (M == INVALID_HANDLE_VALUE)
        {
            T->Errors++;
            break;
        }
        Size.QuadPart = PW_MAPPED;
        Section = CreateFileMappingW(M, NULL, PAGE_READWRITE, Size.HighPart, Size.LowPart, NULL);
        View = Section ? MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, PW_MAPPED) : NULL;
        if (View)
        {
            PwFill(View, PW_MAPPED, T->Index * 3 + 2, Round, 0);
            if (!FlushViewOfFile(View, PW_MAPPED))
                T->Errors++;
            UnmapViewOfFile(View);
        }
        else
        {
            T->Errors++;
        }
        if (Section)
            CloseHandle(Section);
        if (!FlushFileBuffers(M))
            T->Errors++;
        CloseHandle(M);

        if (PwVerify(PathA, T->Index * 3, Round, (ULONGLONG)PW_CHUNKS * PW_CHUNK, Buffer) ||
            PwVerify(PathB, T->Index * 3 + 1, Round, (ULONGLONG)PW_CHUNKS * PW_CHUNK, Buffer) ||
            PwVerify(PathM, T->Index * 3 + 2, Round, PW_MAPPED, Buffer))
        {
            T->Errors++;
        }
    }
    VirtualFree(Buffer, 0, MEM_RELEASE);
    return 0;
}

/*
 * The data of a flushed cached or mapped file is on the disk, byte for byte, when the flush returns
 * (read back without the cache).  NTFS-NG sends these paging writes from the caller's locked pages; a
 * driver below may map them, and checked builds stopped at boot while that mapping was leaked
 * (ticket KERNEL-debug-amd64-smp4-ntfsng-iomdl-assert-at-boot).
 */
START_TEST(NtfsPagingWrite)
{
    PW_THREAD Threads[PW_THREADS];
    HANDLE Handles[PW_THREADS];
    ULONG i, Started = 0;

    if (!NtInit("NtfsPagingWrite"))
        return;
    for (i = 0; i < PW_THREADS; i++)
    {
        Threads[i].Index = i;
        Threads[i].Errors = 0;
        Handles[i] = CreateThread(NULL, 0, PwThread, &Threads[i], 0, NULL);
        ok(Handles[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (Handles[i])
            Started++;
    }
    for (i = 0; i < PW_THREADS; i++)
    {
        if (!Handles[i])
            continue;
        ok(WaitForSingleObject(Handles[i], 600000) == WAIT_OBJECT_0, "Thread %lu did not finish\n", i);
        CloseHandle(Handles[i]);
        ok(Threads[i].Errors == 0, "Thread %lu: %ld errors\n", i, Threads[i].Errors);
    }
    ok(Started == PW_THREADS, "%lu of %u threads started\n", Started, PW_THREADS);
    NtCleanup();
}
