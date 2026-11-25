/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     After a cut in the middle of cached dirty data, a regrow and a non-cached rewrite, every reader gets
 *              the rewritten data
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A file is written non-cached, then changed through the cache in two places of one 256 KB range (the dirty data
 * stays in the cache, nothing waits for the lazy writer): around a block X and a few blocks above it.  The file is
 * cut in the middle of block X and set back to its size, so the upper dirty blocks lie past the cut, and blocks
 * [X, X + 16) are written again through a handle without buffering.  Then a cached read and a non-cached read of
 * [X, X + 16) must return what the non-cached write wrote: the data written is the data read.
 * The test uses the volume of the temporary directory, or the directory named by FILECUTREGROW_DIR.
 */

#include "precomp.h"

#define BLOCK 4096
#define BLOCKS 256          /* 1 MB */
#define RUN 16

static DWORD Tag(DWORD Block, DWORD Generation, DWORD Word)
{
    return (Block * 2654435761u) ^ (Generation * 40503u) ^ (Word * 0x9E3779B9u) ^ 0x43435831u;
}

static void Fill(PBYTE Buffer, DWORD FirstBlock, DWORD Count, DWORD Generation)
{
    DWORD b, w;

    for (b = 0; b < Count; b++)
        for (w = 0; w < BLOCK / sizeof(DWORD); w++)
            ((PDWORD)(Buffer + b * BLOCK))[w] = Tag(FirstBlock + b, Generation, w);
}

/* Index of the first block that differs, or Count */
static DWORD FirstBad(PBYTE Buffer, DWORD FirstBlock, DWORD Count, DWORD Generation)
{
    DWORD b, w;

    for (b = 0; b < Count; b++)
        for (w = 0; w < BLOCK / sizeof(DWORD); w++)
            if (((PDWORD)(Buffer + b * BLOCK))[w] != Tag(FirstBlock + b, Generation, w))
                return b;
    return Count;
}

static BOOL At(HANDLE File, DWORD Offset)
{
    LARGE_INTEGER Li;

    Li.QuadPart = Offset;
    return SetFilePointerEx(File, Li, NULL, FILE_BEGIN);
}

static BOOL Io(HANDLE File, BOOL Write, DWORD Offset, PBYTE Buffer, DWORD Length)
{
    DWORD Done = 0;

    if (!At(File, Offset))
        return FALSE;
    if (Write)
        return WriteFile(File, Buffer, Length, &Done, NULL) && Done == Length;
    return ReadFile(File, Buffer, Length, &Done, NULL) && Done == Length;
}

START_TEST(FileCutRegrowNoncached)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    HANDLE Direct, Cached;
    PBYTE Buffer;
    DWORD Case, Generation = 1, Bad, BadCached = 0, BadDirect = 0;

    if (!GetEnvironmentVariableW(L"FILECUTREGROW_DIR", Dir, _countof(Dir)) && !GetTempPathW(_countof(Dir), Dir))
    {
        skip("no directory\n");
        return;
    }
    if (!GetTempFileNameW(Dir, L"cut", 0, Path))
    {
        skip("GetTempFileName failed %lu\n", GetLastError());
        return;
    }

    Buffer = VirtualAlloc(NULL, BLOCKS * BLOCK, MEM_COMMIT, PAGE_READWRITE);
    ok(Buffer != NULL, "VirtualAlloc failed %lu\n", GetLastError());
    if (!Buffer)
        return;

    Direct = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
                         FILE_FLAG_NO_BUFFERING, NULL);
    Cached = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                         0, NULL);
    ok(Direct != INVALID_HANDLE_VALUE && Cached != INVALID_HANDLE_VALUE, "open failed %lu\n", GetLastError());
    if (Direct == INVALID_HANDLE_VALUE || Cached == INVALID_HANDLE_VALUE)
        goto done;

    Fill(Buffer, 0, BLOCKS, Generation);
    ok(Io(Direct, TRUE, 0, Buffer, BLOCKS * BLOCK), "initial write failed %lu\n", GetLastError());

    /* One case per 256 KB range of the file, the cut at a different sector of block X each time */
    for (Case = 0; Case < 12; Case++)
    {
        DWORD Range = (Case % 4) * 64;
        DWORD X = Range + 20 + (Case * 5) % 24;
        DWORD Sector = 1 + Case % 7;

        /* Dirty cached data: blocks [X + 8, X + 12) and [X - 4, X + 2) */
        Generation++;
        Fill(Buffer, X + 8, 4, Generation);
        ok(Io(Cached, TRUE, (X + 8) * BLOCK, Buffer, 4 * BLOCK), "case %lu: cached write failed %lu\n", Case, GetLastError());
        Fill(Buffer, X - 4, 6, Generation);
        ok(Io(Cached, TRUE, (X - 4) * BLOCK, Buffer, 6 * BLOCK), "case %lu: cached write failed %lu\n", Case, GetLastError());

        /* Cut in the middle of block X, then back to the full size */
        ok(At(Cached, X * BLOCK + Sector * 512) && SetEndOfFile(Cached), "case %lu: cut failed %lu\n", Case, GetLastError());
        ok(At(Cached, BLOCKS * BLOCK) && SetEndOfFile(Cached), "case %lu: regrow failed %lu\n", Case, GetLastError());

        /* What lies past the cut reads as zeros */
        ok(Io(Cached, FALSE, (X + 1) * BLOCK, Buffer, RUN * BLOCK), "case %lu: read failed %lu\n", Case, GetLastError());
        for (Bad = 0; Bad < RUN * BLOCK / sizeof(DWORD); Bad++)
            if (((PDWORD)Buffer)[Bad])
                break;
        ok(Bad == RUN * BLOCK / sizeof(DWORD), "case %lu: not zero past the cut at byte %lu\n", Case, Bad * 4);

        /* Non-cached rewrite of [X, X + 16) */
        Generation++;
        Fill(Buffer, X, RUN, Generation);
        ok(Io(Direct, TRUE, X * BLOCK, Buffer, RUN * BLOCK), "case %lu: non-cached write failed %lu\n", Case, GetLastError());

        ZeroMemory(Buffer, RUN * BLOCK);
        ok(Io(Cached, FALSE, X * BLOCK, Buffer, RUN * BLOCK), "case %lu: cached read failed %lu\n", Case, GetLastError());
        Bad = FirstBad(Buffer, X, RUN, Generation);
        ok(Bad == RUN, "case %lu: cached read: block %lu of %lu is not the one written (X %lu, sector %lu)\n",
           Case, Bad, RUN, X, Sector);
        BadCached += (Bad != RUN);

        ZeroMemory(Buffer, RUN * BLOCK);
        ok(Io(Direct, FALSE, X * BLOCK, Buffer, RUN * BLOCK), "case %lu: non-cached read failed %lu\n", Case, GetLastError());
        Bad = FirstBad(Buffer, X, RUN, Generation);
        ok(Bad == RUN, "case %lu: non-cached read: block %lu of %lu is not the one written (X %lu, sector %lu)\n",
           Case, Bad, RUN, X, Sector);
        BadDirect += (Bad != RUN);

        /* The rest of the file gets the same generation again, written non-cached */
        Fill(Buffer, X + RUN, BLOCKS - X - RUN, Generation);
        ok(Io(Direct, TRUE, (X + RUN) * BLOCK, Buffer, (BLOCKS - X - RUN) * BLOCK), "case %lu: refill failed %lu\n",
           Case, GetLastError());
        if (X > 0)
        {
            Fill(Buffer, 0, X, Generation);
            ok(Io(Direct, TRUE, 0, Buffer, X * BLOCK), "case %lu: refill failed %lu\n", Case, GetLastError());
        }
    }
    trace("%lu cases with a wrong cached read, %lu with a wrong non-cached read\n", BadCached, BadDirect);

done:
    if (Cached != INVALID_HANDLE_VALUE)
        CloseHandle(Cached);
    if (Direct != INVALID_HANDLE_VALUE)
        CloseHandle(Direct);
    DeleteFileW(Path);
    VirtualFree(Buffer, 0, MEM_RELEASE);
}
