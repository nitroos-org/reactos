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
    ULONGLONG Prev = 0, Id, IdA, IdC, IdD;
    ULONG i, Same = 0, Tries = 0;

    if (!NtInit("NtfsRecordReuse"))
        return;
    for (i = 0; i < 8; i++)
    {
        NtPath(Path, i & 1 ? L"odd.tmp" : L"even.tmp");
        Id = CreateWithId(Path);
        ok(Id != 0, "Creating %ls failed: %lu\n", Path, GetLastError());
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
    IdA = CreateWithId(A);
    IdC = CreateWithId(C);
    ok(DeleteFileW(A), "Deleting %ls failed: %lu\n", A, GetLastError());
    IdD = CreateWithId(D);
    ok(IdA && IdC && IdD, "Creating the files failed\n");
    ok(RECORD(IdD) == RECORD(IdA) || RECORD(IdD) < RECORD(IdC),
       "The new file got record %I64u, not the freed lower %I64u (kept: %I64u)\n", RECORD(IdD), RECORD(IdA), RECORD(IdC));
    DeleteFileW(C);
    DeleteFileW(D);
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
