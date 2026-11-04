/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Cross-bitness process creation and executable redirection fixture
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Cross-bitness process creation and executable redirection fixture. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
ULONG __cdecl DbgPrint(const char *, ...);

static unsigned Failures;
#define CHECK(x) do { if (!(x)) { printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); ++Failures; } } while (0)

static void Run(const WCHAR *Name, unsigned Bits, BOOL Suspended, BOOL Search)
{
    STARTUPINFOW Startup = {sizeof(Startup)};
    PROCESS_INFORMATION Process;
    WCHAR Command[2048];
    DWORD Exit = 0;
    BOOL Wow = FALSE;
    _snwprintf(Command, 2048, L"\"%ls\" child \"argument with spaces\"", Name);
    printf("CREATE %ls expected=%u suspended=%u search=%u\n", Name, Bits, Suspended, Search);
    DbgPrint("PROCESS CREATE %S expected=%u\n", Name, Bits);
    fflush(stdout);
    if (!CreateProcessW(Search ? NULL : Name, Command, NULL, NULL, FALSE,
                        Suspended ? CREATE_SUSPENDED : 0, NULL, NULL, &Startup, &Process))
    {
        CHECK(FALSE);
        return;
    }
    CHECK(IsWow64Process(Process.hProcess, &Wow));
#ifndef _WIN64
    CHECK(Wow == (Bits == 32));
#endif
    if (Suspended)
    {
        CHECK(WaitForSingleObject(Process.hProcess, 0) == WAIT_TIMEOUT);
        CHECK(ResumeThread(Process.hThread) == 1);
    }
    if (WaitForSingleObject(Process.hProcess, 30000) != WAIT_OBJECT_0)
    {
        CHECK(FALSE);
        TerminateProcess(Process.hProcess, 99);
    }
    CHECK(GetExitCodeProcess(Process.hProcess, &Exit));
    CHECK(Exit == Bits);
    printf("CHILD exit=%lu wow64=%u\n", Exit, Wow);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
}

int wmain(int argc, WCHAR **argv)
{
    WCHAR Root[MAX_PATH], Path[MAX_PATH], Value[64];
    PVOID Old;
    BOOL Wow = FALSE;
    DbgPrint("PROCESS MAIN bits=%u argc=%u\n", (unsigned)(sizeof(void *) * 8), argc);
    if (argc > 1 && !wcscmp(argv[1], L"version"))
    {
        OSVERSIONINFOEXW Version = {sizeof(Version)};
        typedef LONG (WINAPI *GET_VERSION)(OSVERSIONINFOEXW *);
        typedef VOID (WINAPI *GET_NUMBERS)(PDWORD, PDWORD, PDWORD);
        GET_VERSION RtlVersion = (GET_VERSION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
        GET_NUMBERS RtlNumbers = (GET_NUMBERS)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetNtVersionNumbers");
        DWORD Major = 0, Minor = 0, Build = 0;
        CHECK(GetVersionExW((OSVERSIONINFOW *)&Version));
        printf("VERSION bits=%u GetVersion=%lx Ex=%lu.%lu.%lu SP=%u type=%u\n",
               (unsigned)(sizeof(void *) * 8), GetVersion(), Version.dwMajorVersion,
               Version.dwMinorVersion, Version.dwBuildNumber, Version.wServicePackMajor, Version.wProductType);
        CHECK(Version.dwMajorVersion == 6 && Version.dwMinorVersion == 1 &&
              Version.dwBuildNumber == 7601 && Version.wServicePackMajor == 1);
        CHECK(RtlVersion && RtlVersion(&Version) == 0);
        printf("RTL VERSION %lu.%lu.%lu SP=%u\n", Version.dwMajorVersion,
               Version.dwMinorVersion, Version.dwBuildNumber, Version.wServicePackMajor);
        CHECK(Version.dwMajorVersion == 6 && Version.dwMinorVersion == 1 &&
              Version.dwBuildNumber == 7601 && Version.wServicePackMajor == 1);
        CHECK(RtlNumbers != NULL);
        if (RtlNumbers) RtlNumbers(&Major, &Minor, &Build);
        printf("RTL NUMBERS %lu.%lu.%lu\n", Major, Minor, Build & 0xffff);
        CHECK(Major == 6 && Minor == 1 && (Build & 0xffff) == 7601);
        printf("VERSION COMPLETE failures=%u\n", Failures);
        return Failures ? 1 : 0;
    }
    if (argc > 1 && !wcscmp(argv[1], L"child"))
    {
        CHECK(GetModuleFileNameW(NULL, Path, MAX_PATH));
        CHECK(wcsncmp(Path, L"\\\\?\\", 4));
        CHECK(argc == 3 && !wcscmp(argv[2], L"argument with spaces"));
        CHECK(GetEnvironmentVariableW(L"W643C_CHILD_ENV", Value, 64) == 9);
        CHECK(!wcscmp(Value, L"inherited"));
        printf("CHILD started bits=%u failures=%u\n", (unsigned)(sizeof(void *) * 8), Failures);
        return Failures ? 99 : sizeof(void *) * 8;
    }
    CHECK(IsWow64Process(GetCurrentProcess(), &Wow) && Wow);
    CHECK(SetEnvironmentVariableW(L"W643C_CHILD_ENV", L"inherited"));
    Run(L"C:\\harness\\process32.exe", 32, FALSE, FALSE);
    Run(L"C:\\harness\\process64.exe", 64, FALSE, FALSE);
    Run(L"C:\\harness\\process32.exe", 32, TRUE, TRUE);
    Run(L"C:\\harness\\process64.exe", 64, TRUE, TRUE);
    CHECK(GetWindowsDirectoryW(Root, MAX_PATH));
    _snwprintf(Path, MAX_PATH, L"%ls\\SysWOW64\\w643c-child.exe", Root);
    Run(Path, 32, FALSE, FALSE);
    _snwprintf(Path, MAX_PATH, L"%ls\\System32\\w643c-child.exe", Root);
    Run(Path, 32, FALSE, FALSE);
    CHECK(Wow64DisableWow64FsRedirection(&Old));
    Run(Path, 64, FALSE, FALSE);
    CHECK(Wow64RevertWow64FsRedirection(Old));
    Run(Path, 32, FALSE, FALSE);
    _snwprintf(Path, MAX_PATH, L"%ls\\Sysnative\\w643c-child.exe", Root);
    Run(Path, 64, FALSE, FALSE);
    CHECK(GetSystemDirectoryW(Path, MAX_PATH));
    _snwprintf(Value, 64, L"%ls\\System32", Root);
    CHECK(!wcsicmp(Path, Value));
    wcscat(Path, L"\\w643c-child.exe");
    Run(Path, 32, FALSE, TRUE);
    CHECK(Wow64DisableWow64FsRedirection(&Old));
    Run(Path, 64, FALSE, TRUE);
    CHECK(Wow64RevertWow64FsRedirection(Old));
    printf("PROCESS COMPLETE failures=%u\n", Failures);
    return Failures ? 1 : 0;
}
