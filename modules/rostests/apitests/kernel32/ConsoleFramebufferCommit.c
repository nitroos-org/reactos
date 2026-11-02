/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test that a console window does not commit memory for the whole screen buffer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/* A buffer of 200 x 9001 cells is 920 MB as a 32-bit framebuffer of 8x16 pixel cells, 7 MB as the cells themselves */
#define BUFFER_WIDTH    200
#define BUFFER_HEIGHT   9001
#define MAX_GROWTH      (64 * 1024 * 1024)

/* The memory committed by the console server: all csrss.exe processes together */
static
BOOL
GetCsrssCommit(
    _Out_ PSIZE_T Commit)
{
    ULONG Size = 256 * 1024, Needed;
    PSYSTEM_PROCESS_INFORMATION Info, Entry;
    NTSTATUS Status;

    *Commit = 0;
    for (;;)
    {
        Info = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Info)
            return FALSE;
        Status = NtQuerySystemInformation(SystemProcessInformation, Info, Size, &Needed);
        if (Status != STATUS_INFO_LENGTH_MISMATCH)
            break;
        HeapFree(GetProcessHeap(), 0, Info);
        Size = Needed + 64 * 1024;
    }
    if (!NT_SUCCESS(Status))
    {
        HeapFree(GetProcessHeap(), 0, Info);
        return FALSE;
    }

    for (Entry = Info;; Entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Entry + Entry->NextEntryOffset))
    {
        if (Entry->ImageName.Buffer &&
            Entry->ImageName.Length == 9 * sizeof(WCHAR) &&
            !_wcsnicmp(Entry->ImageName.Buffer, L"csrss.exe", 9))
        {
            *Commit += Entry->PagefileUsage;
        }
        if (!Entry->NextEntryOffset)
            break;
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return TRUE;
}

START_TEST(ConsoleFramebufferCommit)
{
    HANDLE hOrig, hCon;
    COORD Size = { BUFFER_WIDTH, BUFFER_HEIGHT };
    CONSOLE_SCREEN_BUFFER_INFO Info;
    SIZE_T Before, After;

    if (!GetConsoleWindow())
    {
        skip("No console window\n");
        return;
    }
    if (!GetCsrssCommit(&Before))
    {
        skip("Cannot query the processes\n");
        return;
    }

    hOrig = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    ok(hOrig != INVALID_HANDLE_VALUE, "Opening CONOUT$ failed with error %lu\n", GetLastError());
    if (hOrig == INVALID_HANDLE_VALUE)
        return;

    hCon = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
    ok(hCon != INVALID_HANDLE_VALUE, "CreateConsoleScreenBuffer failed with error %lu\n", GetLastError());
    if (hCon == INVALID_HANDLE_VALUE)
        goto Done;

    if (!SetConsoleScreenBufferSize(hCon, Size) ||
        !GetConsoleScreenBufferInfo(hCon, &Info) || Info.dwSize.Y != BUFFER_HEIGHT)
    {
        skip("Cannot make a %dx%d screen buffer\n", BUFFER_WIDTH, BUFFER_HEIGHT);
        CloseHandle(hCon);
        goto Done;
    }

    /* Show it: the window builds its framebuffer for what it displays */
    ok(SetConsoleActiveScreenBuffer(hCon), "SetConsoleActiveScreenBuffer failed with error %lu\n", GetLastError());
    Sleep(1500);

    ok(GetCsrssCommit(&After), "Cannot query the processes\n");
    ok(After < Before + MAX_GROWTH,
       "csrss commit grew from %Iu KB to %Iu KB for a %dx%d buffer that shows %dx%d cells\n",
       Before / 1024, After / 1024, BUFFER_WIDTH, BUFFER_HEIGHT, Info.srWindow.Right - Info.srWindow.Left + 1,
       Info.srWindow.Bottom - Info.srWindow.Top + 1);

    ok(SetConsoleActiveScreenBuffer(hOrig), "SetConsoleActiveScreenBuffer failed with error %lu\n", GetLastError());
    CloseHandle(hCon);

Done:
    CloseHandle(hOrig);
}
