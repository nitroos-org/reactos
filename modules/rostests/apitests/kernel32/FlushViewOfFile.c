/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     FlushViewOfFile writes the data written through a live view to the file
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Documented contract: FlushViewOfFile writes the dirty pages of the range of the view to the file (FlushFileBuffers
 * then makes them durable).  After it returns, a NON-CACHED read through another handle (FILE_FLAG_NO_BUFFERING:
 * from the disk) must return the data written through the view, while the view stays mapped.  Before the fix the
 * data stayed dirty only in the view's PTEs and the read returned the old disk contents (ticket
 * NTFSNG-mapped-view-writes-not-durable; FAT32 the same).  The volume of the temporary directory is used, or the
 * directory named by FLUSHVIEWOFFILE_DIR.
 */

#include "precomp.h"

#define VIEW_SIZE   (4 * 1024 * 1024)
#define CHUNK       4096

static WCHAR FilePath[MAX_PATH];

static BYTE Pattern(DWORD Offset, BYTE Round)
{
    BYTE Value = (BYTE)(Offset / CHUNK * 13 + Offset * 7 + Round * 31);
    return Value ? Value : 1;
}

/* Reads [Offset, Offset + Length) from the disk through a second handle; returns the number of bytes that differ */
static ULONG CompareUncached(DWORD Offset, DWORD Length, BYTE Round, PBYTE Buffer)
{
    HANDLE Reader;
    LARGE_INTEGER Position;
    DWORD Read = 0, i;
    ULONG Bad = 0;

    Reader = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                         FILE_FLAG_NO_BUFFERING, NULL);
    ok(Reader != INVALID_HANDLE_VALUE, "non-cached open failed, error %lu\n", GetLastError());
    if (Reader == INVALID_HANDLE_VALUE)
        return Length;
    Position.QuadPart = Offset;
    ok(SetFilePointerEx(Reader, Position, NULL, FILE_BEGIN), "seek failed, error %lu\n", GetLastError());
    ok(ReadFile(Reader, Buffer, Length, &Read, NULL), "non-cached read failed, error %lu\n", GetLastError());
    ok(Read == Length, "read %lu of %lu bytes\n", Read, Length);
    CloseHandle(Reader);
    for (i = 0; i < Length; i++)
    {
        if (Buffer[i] != Pattern(Offset + i, Round))
            Bad++;
    }
    return Bad;
}

static VOID WriteChunk(PBYTE View, DWORD Offset, BYTE Round)
{
    DWORD i;

    for (i = 0; i < CHUNK; i++)
        View[Offset + i] = Pattern(Offset + i, Round);
}

START_TEST(FlushViewOfFile)
{
    WCHAR Dir[MAX_PATH];
    HANDLE File, Mapping;
    PBYTE View, Buffer, Fill;
    DWORD Written, Offset;
    ULONG Bad, Round;

    if (!GetEnvironmentVariableW(L"FLUSHVIEWOFFILE_DIR", Dir, RTL_NUMBER_OF(Dir)))
        GetTempPathW(RTL_NUMBER_OF(Dir), Dir);
    StringCbPrintfW(FilePath, sizeof(FilePath), L"%s\\fvof_%lu.tmp", Dir, GetCurrentProcessId());

    Buffer = VirtualAlloc(NULL, VIEW_SIZE, MEM_COMMIT, PAGE_READWRITE);
    Fill = VirtualAlloc(NULL, VIEW_SIZE, MEM_COMMIT, PAGE_READWRITE);
    ok(Buffer && Fill, "VirtualAlloc failed\n");
    if (!Buffer || !Fill)
        return;

    /* The file: round 0 written normally and flushed, so the disk holds it */
    File = CreateFileW(FilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile failed, error %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    for (Offset = 0; Offset < VIEW_SIZE; Offset++)
        Fill[Offset] = Pattern(Offset, 0);
    ok(WriteFile(File, Fill, VIEW_SIZE, &Written, NULL) && Written == VIEW_SIZE, "WriteFile failed, error %lu\n", GetLastError());
    ok(FlushFileBuffers(File), "FlushFileBuffers failed, error %lu\n", GetLastError());
    ok_eq_ulong(CompareUncached(0, VIEW_SIZE, 0, Buffer), 0UL);

    Mapping = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL);
    View = Mapping ? MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, 0) : NULL;
    ok(View != NULL, "mapping failed, error %lu\n", GetLastError());
    if (!View)
        goto out;

    /* One chunk written through the live view, a range of one byte inside it flushed: the whole page is written */
    WriteChunk(View, 5 * CHUNK, 1);
    ok(FlushViewOfFile(View + 5 * CHUNK + 100, 1), "FlushViewOfFile failed, error %lu\n", GetLastError());
    ok_eq_ulong(CompareUncached(5 * CHUNK, CHUNK, 1, Buffer), 0UL);

    /* The same page again: its dirty bit must be armed again after the first flush */
    WriteChunk(View, 5 * CHUNK, 2);
    ok(FlushViewOfFile(View + 5 * CHUNK, CHUNK), "FlushViewOfFile failed, error %lu\n", GetLastError());
    ok_eq_ulong(CompareUncached(5 * CHUNK, CHUNK, 2, Buffer), 0UL);

    /* Every page of the view, three rounds, size 0 = the whole view */
    for (Round = 3; Round < 6; Round++)
    {
        for (Offset = 0; Offset < VIEW_SIZE; Offset += CHUNK)
            WriteChunk(View, Offset, (BYTE)Round);
        ok(FlushViewOfFile(View, 0), "FlushViewOfFile failed, error %lu\n", GetLastError());
        Bad = CompareUncached(0, VIEW_SIZE, (BYTE)Round, Buffer);
        ok(Bad == 0, "round %lu: %lu bytes on disk differ from the view after FlushViewOfFile\n", Round, Bad);
    }

    /* A second view of the same mapping: the pages written through it are flushed through it */
    {
        PBYTE View2 = MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, 0);

        ok(View2 != NULL, "second view failed, error %lu\n", GetLastError());
        if (View2)
        {
            WriteChunk(View2, 9 * CHUNK, 6);
            ok(FlushViewOfFile(View2 + 9 * CHUNK, CHUNK), "FlushViewOfFile failed, error %lu\n", GetLastError());
            ok_eq_ulong(CompareUncached(9 * CHUNK, CHUNK, 6, Buffer), 0UL);
            ok(View[9 * CHUNK] == Pattern(9 * CHUNK, 6), "first view does not show the write\n");
            UnmapViewOfFile(View2);
        }
    }

    /*
     * Pages written through another view: FlushViewOfFile on a second view of the range, and FlushFileBuffers alone,
     * write them too (the pages of every mapping of the file, as the flush of the file's cache does on Windows,
     * where a non-cached read of such a page returns the new data).
     */
    {
        PBYTE View2 = MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, 0);

        ok(View2 != NULL, "second view failed, error %lu\n", GetLastError());
        if (View2)
        {
            WriteChunk(View, 11 * CHUNK, 7);
            ok(FlushViewOfFile(View2 + 11 * CHUNK, CHUNK), "FlushViewOfFile failed, error %lu\n", GetLastError());
            ok_eq_ulong(CompareUncached(11 * CHUNK, CHUNK, 7, Buffer), 0UL);

            WriteChunk(View, 12 * CHUNK, 8);
            WriteChunk(View2, 13 * CHUNK, 8);
            ok(FlushFileBuffers(File), "FlushFileBuffers failed, error %lu\n", GetLastError());
            ok_eq_ulong(CompareUncached(12 * CHUNK, 2 * CHUNK, 8, Buffer), 0UL);
            UnmapViewOfFile(View2);
        }
    }

    /* Durable: FlushFileBuffers after the view flush succeeds; the data is still there after the unmap */
    ok(FlushFileBuffers(File), "FlushFileBuffers failed, error %lu\n", GetLastError());
    UnmapViewOfFile(View);
    ok_eq_ulong(CompareUncached(9 * CHUNK, CHUNK, 6, Buffer), 0UL);
out:
    if (Mapping)
        CloseHandle(Mapping);
    CloseHandle(File);
    DeleteFileW(FilePath);
    VirtualFree(Buffer, 0, MEM_RELEASE);
    VirtualFree(Fill, 0, MEM_RELEASE);
}
