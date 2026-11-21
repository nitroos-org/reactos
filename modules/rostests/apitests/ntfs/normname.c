/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NTFS: FileNormalizedNameInformation of a file opened with an explicit ::$DATA suffix or by a
 *              named stream (the type ":$DATA" is not part of the name; measured on Windows Server 2022)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define NORM_SHARE (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
#define FileNormalizedNameInformation 48

static BOOLEAN NormalizedName(PCWSTR Path, PWSTR Out, ULONG OutChars)
{
    BYTE Buffer[2048];
    PFILE_NAME_INFORMATION Info = (PFILE_NAME_INFORMATION)Buffer;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    HANDLE Handle;
    ULONG Chars;

    Out[0] = 0;
    Handle = CreateFileW(Path, FILE_READ_ATTRIBUTES | SYNCHRONIZE, NORM_SHARE, NULL, OPEN_EXISTING, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "Opening %ls failed %lu\n", Path, GetLastError());
    if (Handle == INVALID_HANDLE_VALUE)
        return FALSE;
    Status = NtQueryInformationFile(Handle, &Iosb, Buffer, sizeof(Buffer), (FILE_INFORMATION_CLASS)FileNormalizedNameInformation);
    CloseHandle(Handle);
    ok(Status == STATUS_SUCCESS, "FileNormalizedNameInformation of %ls: 0x%08lx\n", Path, Status);
    if (Status != STATUS_SUCCESS)
        return FALSE;
    Chars = min(Info->FileNameLength / sizeof(WCHAR), OutChars - 1);
    RtlCopyMemory(Out, Info->FileName, Chars * sizeof(WCHAR));
    Out[Chars] = 0;
    return TRUE;
}

START_TEST(NtfsNormalizedName)
{
    WCHAR File[MAX_PATH], Name[MAX_PATH], Expected[MAX_PATH + 16], Got[MAX_PATH + 16], Path[MAX_PATH + 16];
    HANDLE Handle;
    DWORD Written;
    ULONG i;
    static const struct { PCWSTR Suffix; PCWSTR Stream; } Rows[] =
    {
        { L"", L"" },
        { L"::$DATA", L"" },
        { L":Strm", L":Strm" },
        { L":Strm:$DATA", L":Strm" },
    };

    if (!NtInit("NtfsNormalizedName"))
        return;
    NtPath(File, L"NormFile.txt");
    Handle = CreateFileW(File, GENERIC_WRITE, NORM_SHARE, NULL, CREATE_ALWAYS, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "Creating %ls failed %lu\n", File, GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
    {
        WriteFile(Handle, "x", 1, &Written, NULL);
        CloseHandle(Handle);
    }
    _snwprintf(Name, RTL_NUMBER_OF(Name), L"%ls:Strm", File);
    Handle = CreateFileW(Name, GENERIC_WRITE, NORM_SHARE, NULL, CREATE_ALWAYS, 0, NULL);
    ok(Handle != INVALID_HANDLE_VALUE, "Creating %ls failed %lu\n", Name, GetLastError());
    if (Handle != INVALID_HANDLE_VALUE)
        CloseHandle(Handle);

    if (!NormalizedName(File, Expected, RTL_NUMBER_OF(Expected)))
        return;
    ok(Expected[0] == L'\\', "plain name %ls does not start at the volume root\n", Expected);
    ok(wcschr(Expected, L':') == NULL, "plain name %ls has a colon\n", Expected);

    for (i = 0; i < RTL_NUMBER_OF(Rows); i++)
    {
        _snwprintf(Path, RTL_NUMBER_OF(Path), L"%ls%ls", File, Rows[i].Suffix);
        if (!NormalizedName(Path, Got, RTL_NUMBER_OF(Got)))
            continue;
        _snwprintf(Name, RTL_NUMBER_OF(Name), L"%ls%ls", Expected, Rows[i].Stream);
        ok(!wcscmp(Got, Name), "opened as '%ls': normalized name '%ls', expected '%ls'\n", Rows[i].Suffix, Got, Name);
    }
}
