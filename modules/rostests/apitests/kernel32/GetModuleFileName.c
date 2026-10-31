/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Test for GetModuleFileName
 * PROGRAMMER:      Thomas Faber <thomas.faber@reactos.org>
 */

#include "precomp.h"

#include <shlwapi.h>

static
VOID
StartChild(char **argv)
{
    BOOL Success;
    WCHAR Path[MAX_PATH];
    PWSTR FileName;
    PWSTR Slash;
    WCHAR CommandLine[MAX_PATH];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    DWORD Ret;
    int Length;

    Length = MultiByteToWideChar(CP_ACP,
                                 0,
                                 argv[0],
                                 -1,
                                 Path,
                                 sizeof(Path) / sizeof(WCHAR));
    ok(Length > 0, "Length = %d\n", Length);

    FileName = wcsrchr(Path, '\\');
    Slash = wcsrchr(Path, L'/');
    if (Slash && (!FileName || Slash > FileName))
        FileName = Slash;

    if (FileName)
    {
        /* It's an absolute path. Set it as current dir and get the file name */
        FileName++;
        FileName[-1] = L'\0';

        Success = SetCurrentDirectoryW(Path);
        ok(Success == TRUE, "SetCurrentDirectory failed for path '%ls'\n", Path);

        trace("Starting '%ls' in path '%ls'\n", FileName, Path);
    }
    else
    {
        FileName = Path;
        trace("Starting '%ls', which is already relative\n", FileName);
    }

    _swprintf(CommandLine, L"\"%ls\" GetModuleFileName relative", FileName);

    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);

    Success = CreateProcessW(FileName,
                             CommandLine,
                             NULL,
                             NULL,
                             FALSE,
                             0,
                             NULL,
                             NULL,
                             &StartupInfo,
                             &ProcessInfo);
    if (!Success)
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return;
    }
    CloseHandle(ProcessInfo.hThread);
    Ret = WaitForSingleObject(ProcessInfo.hProcess, 30 * 1000);
    ok(Ret == WAIT_OBJECT_0, "WaitForSingleObject returns %lu\n", Ret);
    CloseHandle(ProcessInfo.hProcess);
}

static
VOID
TestGetModuleFileNameA(VOID)
{
    CHAR Buffer[MAX_PATH];
    DWORD Length;
    BOOL Relative;

    Length = GetModuleFileNameA(NULL, Buffer, sizeof(Buffer));
    ok(Length != 0, "Length = %lu\n", Length);
    ok(Length < sizeof(Buffer), "Length = %lu\n", Length);
    ok(Buffer[Length] == 0, "Buffer not null terminated\n");
    Relative = PathIsRelativeA(Buffer);
    ok(Relative == FALSE, "GetModuleFileNameA returned relative path: %s\n", Buffer);
}

static
VOID
TestGetModuleFileNameW(VOID)
{
    WCHAR Buffer[MAX_PATH];
    DWORD Length;
    BOOL Relative;

    Length = GetModuleFileNameW(NULL, Buffer, sizeof(Buffer) / sizeof(WCHAR));
    ok(Length != 0, "Length = %lu\n", Length);
    ok(Length < sizeof(Buffer) / sizeof(WCHAR), "Length = %lu\n", Length);
    ok(Buffer[Length] == 0, "Buffer not null terminated\n");
    Relative = PathIsRelativeW(Buffer);
    ok(Relative == FALSE, "GetModuleFileNameW returned relative path: %ls\n", Buffer);
}

static
VOID
TestTruncation(VOID)
{
    WCHAR BufferW[MAX_PATH + 2], FullW[MAX_PATH];
    CHAR BufferA[MAX_PATH + 2];
    DWORD Full, Length, Error, Size;
    DWORD Sizes[3];
    int i;

    Full = GetModuleFileNameW(NULL, FullW, MAX_PATH);
    ok(Full > 6 && Full < MAX_PATH, "Full = %lu\n", Full);
    if (Full <= 6 || Full >= MAX_PATH)
        return;

    /* A success clears the last error */
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameW(NULL, BufferW, MAX_PATH);
    Error = GetLastError();
    ok(Length == Full, "Length = %lu, expected %lu\n", Length, Full);
    ok(Error == ERROR_SUCCESS, "Error = %lu\n", Error);
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameA(NULL, BufferA, MAX_PATH);
    Error = GetLastError();
    ok(Length == Full, "Length = %lu, expected %lu\n", Length, Full);
    ok(Error == ERROR_SUCCESS, "Error = %lu\n", Error);

    /* Too small: truncated to Size - 1 characters, zero terminated, Size returned */
    Sizes[0] = 1;
    Sizes[1] = 5;
    Sizes[2] = Full;
    for (i = 0; i < 3; i++)
    {
        Size = Sizes[i];

        memset(BufferW, 0x55, sizeof(BufferW));
        SetLastError(0xdeadbeef);
        Length = GetModuleFileNameW(NULL, BufferW, Size);
        Error = GetLastError();
        ok(Length == Size, "W size %lu: Length = %lu\n", Size, Length);
        ok(Error == ERROR_INSUFFICIENT_BUFFER, "W size %lu: Error = %lu\n", Size, Error);
        ok(BufferW[Size - 1] == 0, "W size %lu: not null terminated\n", Size);
        ok(Size < 2 || memcmp(BufferW, FullW, (Size - 1) * sizeof(WCHAR)) == 0,
           "W size %lu: wrong contents\n", Size);
        ok(BufferW[Size] == 0x5555, "W size %lu: wrote past the buffer\n", Size);

        memset(BufferA, 0x55, sizeof(BufferA));
        SetLastError(0xdeadbeef);
        Length = GetModuleFileNameA(NULL, BufferA, Size);
        Error = GetLastError();
        ok(Length == Size, "A size %lu: Length = %lu\n", Size, Length);
        ok(Error == ERROR_INSUFFICIENT_BUFFER, "A size %lu: Error = %lu\n", Size, Error);
        ok(BufferA[Size - 1] == 0, "A size %lu: not null terminated\n", Size);
        ok(BufferA[Size] == 0x55, "A size %lu: wrote past the buffer\n", Size);
    }

    /* Exactly enough */
    memset(BufferW, 0x55, sizeof(BufferW));
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameW(NULL, BufferW, Full + 1);
    Error = GetLastError();
    ok(Length == Full, "Length = %lu, expected %lu\n", Length, Full);
    ok(Error == ERROR_SUCCESS, "Error = %lu\n", Error);
    ok(BufferW[Full] == 0, "not null terminated\n");
    memset(BufferA, 0x55, sizeof(BufferA));
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameA(NULL, BufferA, Full + 1);
    Error = GetLastError();
    ok(Length == Full, "Length = %lu, expected %lu\n", Length, Full);
    ok(Error == ERROR_SUCCESS, "Error = %lu\n", Error);
    ok(BufferA[Full] == 0, "not null terminated\n");

    /* Size zero: nothing is written */
    memset(BufferW, 0x55, sizeof(BufferW));
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameW(NULL, BufferW, 0);
    Error = GetLastError();
    ok(Length == 0, "Length = %lu\n", Length);
    ok(Error == ERROR_INSUFFICIENT_BUFFER, "Error = %lu\n", Error);
    ok(BufferW[0] == 0x5555, "buffer written\n");
    memset(BufferA, 0x55, sizeof(BufferA));
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameA(NULL, BufferA, 0);
    Error = GetLastError();
    ok(Length == 0, "Length = %lu\n", Length);
    ok(Error == ERROR_INSUFFICIENT_BUFFER, "Error = %lu\n", Error);
    ok(BufferA[0] == 0x55, "buffer written\n");

    /* A module handle that is not loaded */
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameW((HMODULE)(ULONG_PTR)0x12340000, BufferW, MAX_PATH);
    Error = GetLastError();
    ok(Length == 0, "Length = %lu\n", Length);
    ok(Error == ERROR_MOD_NOT_FOUND, "Error = %lu\n", Error);
    SetLastError(0xdeadbeef);
    Length = GetModuleFileNameA((HMODULE)(ULONG_PTR)0x12340000, BufferA, MAX_PATH);
    Error = GetLastError();
    ok(Length == 0, "Length = %lu\n", Length);
    ok(Error == ERROR_MOD_NOT_FOUND, "Error = %lu\n", Error);
}

START_TEST(GetModuleFileName)
{
    int argc;
    char **argv;

    argc = winetest_get_mainargs(&argv);
    if (argc < 3)
    {
        TestTruncation();
        StartChild(argv);
    }
    else
    {
        TestGetModuleFileNameA();
        TestGetModuleFileNameW();
    }
}
