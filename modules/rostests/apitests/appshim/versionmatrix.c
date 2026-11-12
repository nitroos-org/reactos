/*
 * PROJECT:     appshim_apitest
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     The version a program is told by GetVersion/GetVersionEx/VerifyVersionInfo (the S2 version lie,
 *              switch HKLM\SYSTEM\CurrentControlSet\Control\ReactOS\Settings\Version\UnmanifestedVersionLie).
 *              The rows are the ones measured on Windows 10 22H2 (19045): a program is told 6.2.9200 unless its
 *              own manifest names Windows 8.1 (6.3.9600) or Windows 10 (the real version); without a supportedOS its PE
 *              header OS version counts; a supportedOS beats the header; an embedded manifest beats a sidecar one.
 *              RtlGetVersion, RtlVerifyVersionInfo, RtlGetNtVersionNumbers and KUSER_SHARED_DATA never lie.
 *              With the switch off (the default on ReactOS) every program is told the real version.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>
#include <stdio.h>
#include "wine/test.h"

typedef LONG (WINAPI *RTLGETVERSIONPROC)(OSVERSIONINFOEXW *);

enum { L_WIN8 = 0, L_WIN81 = 1, L_REAL = 2 };

static const struct
{
    PCSTR Name;     /* appshim_vm_<Name>.exe */
    int Level;
    PCSTR What;
} g_Rows[] =
{
    { "none",       L_WIN8,  "no manifest, header 5.1" },
    { "hdr63",      L_WIN81, "no manifest, header 6.3" },
    { "hdr100",     L_REAL,  "no manifest, header 10.0" },
    { "man",        L_WIN8,  "manifest without compatibility section" },
    { "man_hdr63",  L_WIN81, "manifest without compatibility section, header 6.3 (the header counts without a supportedOS)" },
    { "empty",      L_WIN8,  "compatibility section without supportedOS" },
    { "vista",      L_WIN8,  "Vista only" },
    { "w7",         L_WIN8,  "Windows 7 only" },
    { "w8",         L_WIN8,  "Windows 8 only" },
    { "w81",        L_WIN81, "Windows 8.1 only" },
    { "w10",        L_REAL,  "Windows 10 only" },
    { "w7w8w81",    L_WIN81, "Windows 7, 8, 8.1" },
    { "w10w7",      L_REAL,  "Windows 10, then 7 (the highest wins, not the first)" },
    { "hdr63_w8",   L_WIN8,  "Windows 8 only, header 6.3 (a manifest beats the header)" },
    { "hdr100_w8",  L_WIN8,  "Windows 8 only, header 10.0" },
    { "hdr100_w7",  L_WIN8,  "Windows 7 only, header 10.0" },
    { "hdr63_w81",  L_WIN81, "Windows 8.1 only, header 6.3" },
    { "hdr40_w10",  L_REAL,  "Windows 10 only, header 4.0" },
};

static const char g_Win10Manifest[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n"
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\r\n"
    "  <assemblyIdentity type=\"win32\" name=\"appshim.vermatrix.sidecar\" version=\"1.0.0.0\" processorArchitecture=\"*\"/>\r\n"
    "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application>\r\n"
    "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>\r\n"
    "  </application></compatibility>\r\n"
    "</assembly>\r\n";

static BOOL switch_on(void)
{
    HKEY hKey;
    DWORD Value = 0, Size = sizeof(Value), Type;

    if (!is_reactos())
        return TRUE; /* Windows 10 does it always */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ReactOS\\Settings\\Version",
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, L"UnmanifestedVersionLie", NULL, &Type, (PBYTE)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD)
        Value = 0;
    RegCloseKey(hKey);
    return Value == 1;
}

static void expected_line(char *Line, int Level, const OSVERSIONINFOEXW *Real)
{
    DWORD Maj = Real->dwMajorVersion, Min = Real->dwMinorVersion, Build = Real->dwBuildNumber;
    int Vvi = 1;

    if (Level == L_WIN8)
    {
        Maj = 6; Min = 2; Build = 9200;
    }
    else if (Level == L_WIN81)
    {
        Maj = 6; Min = 3; Build = 9600;
    }
    sprintf(Line, "GV=%08lx EXW=%lu.%lu.%lu EXA=%lu.%lu.%lu VVI=%d%d%d RTL=%lu.%lu.%lu RVVI=111 NT=%lu.%lu.%lx KUSER=%lu.%lu.%lu SP=%u.%u PT=%u",
            (Build << 16) | (Min << 8) | Maj, Maj, Min, Build, Maj, Min, Build,
            Vvi, Level >= L_WIN81, Level >= L_REAL,
            Real->dwMajorVersion, Real->dwMinorVersion, Real->dwBuildNumber,
            Real->dwMajorVersion, Real->dwMinorVersion, 0xF0000000UL | Real->dwBuildNumber,
            *(volatile ULONG *)(ULONG_PTR)0x7FFE026C, *(volatile ULONG *)(ULONG_PTR)0x7FFE0270,
            *(volatile ULONG *)(ULONG_PTR)0x7FFE0260,
            Real->wServicePackMajor, Real->wServicePackMinor, Real->wProductType);
}

static BOOL run_probe(PCWSTR Exe, PCWSTR Result, char *Line, size_t LineSize)
{
    WCHAR Command[2 * MAX_PATH + 8];
    STARTUPINFOW Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Process;
    DWORD Code = 0xdeadbeef;
    FILE *f;
    size_t n;

    Line[0] = 0;
    DeleteFileW(Result);
    swprintf(Command, ARRAYSIZE(Command), L"\"%ls\" \"%ls\"", Exe, Result);
    if (!CreateProcessW(Exe, Command, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Process))
    {
        ok(0, "CreateProcess(%ls) failed: %lu\n", Exe, GetLastError());
        return FALSE;
    }
    if (WaitForSingleObject(Process.hProcess, 60000) != WAIT_OBJECT_0)
    {
        ok(0, "%ls did not exit\n", Exe);
        TerminateProcess(Process.hProcess, 1);
        WaitForSingleObject(Process.hProcess, 10000);
    }
    else
        GetExitCodeProcess(Process.hProcess, &Code);
    CloseHandle(Process.hThread);
    CloseHandle(Process.hProcess);
    if (Code != 0)
    {
        ok(0, "%ls exit code %lu\n", Exe, Code);
        return FALSE;
    }
    f = _wfopen(Result, L"r");
    if (!f)
    {
        ok(0, "no result from %ls\n", Exe);
        return FALSE;
    }
    n = fread(Line, 1, LineSize - 1, f);
    fclose(f);
    Line[n] = 0;
    while (n && (Line[n - 1] == '\n' || Line[n - 1] == '\r'))
        Line[--n] = 0;
    return TRUE;
}

static void dir_of_test(PWSTR Dir, size_t Count)
{
    PWSTR Slash;

    GetModuleFileNameW(NULL, Dir, Count);
    Slash = wcsrchr(Dir, L'\\');
    if (Slash)
        Slash[1] = 0;
}

static void check_row(PCWSTR Exe, PCWSTR Result, int Level, PCSTR What, const OSVERSIONINFOEXW *Real, BOOL On)
{
    char Got[600], Want[600];

    if (!run_probe(Exe, Result, Got, sizeof(Got)))
        return;
    expected_line(Want, On ? Level : L_REAL, Real);
    ok(!strcmp(Got, Want), "%s: got\n  %s\nwanted\n  %s\n", What, Got, Want);
}

START_TEST(versionmatrix)
{
    RTLGETVERSIONPROC pRtlGetVersion = (RTLGETVERSIONPROC)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    OSVERSIONINFOEXW Real = { sizeof(Real) };
    WCHAR Dir[MAX_PATH], Tmp[MAX_PATH], Exe[MAX_PATH + 40], Result[MAX_PATH + 40], Copy[MAX_PATH + 40], Side[MAX_PATH + 50];
    BOOL On = switch_on();
    SIZE_T i;
    HANDLE hFile;
    DWORD Written;

    pRtlGetVersion(&Real);
    if (Real.dwMajorVersion < 10)
    {
        skip("the matrix is for a Windows 10 system, this one is %lu.%lu\n", Real.dwMajorVersion, Real.dwMinorVersion);
        return;
    }
    trace("switch %s, real version %lu.%lu.%lu\n", On ? "ON" : "OFF", Real.dwMajorVersion, Real.dwMinorVersion, Real.dwBuildNumber);

    dir_of_test(Dir, ARRAYSIZE(Dir));
    GetTempPathW(ARRAYSIZE(Tmp), Tmp);
    swprintf(Result, ARRAYSIZE(Result), L"%lsvermatrix_result.txt", Tmp);

    for (i = 0; i < ARRAYSIZE(g_Rows); ++i)
    {
        swprintf(Exe, ARRAYSIZE(Exe), L"%lsappshim_vm_%S.exe", Dir, g_Rows[i].Name);
        check_row(Exe, Result, g_Rows[i].Level, g_Rows[i].What, &Real, On);
    }

    /* A sidecar manifest (x.exe.manifest) is honoured for a program without an embedded manifest, and ignored
       when there is an embedded one. The copies are made in the temp directory. */
    {
        static const struct { PCSTR Src; int Level; PCSTR What; } Side_[] =
        {
            { "none", L_REAL,  "no embedded manifest + sidecar Windows 10 (the sidecar counts)" },
            { "man",  L_WIN8,  "embedded manifest (no compatibility) + sidecar Windows 10 (the embedded one wins)" },
        };
        for (i = 0; i < ARRAYSIZE(Side_); ++i)
        {
            swprintf(Exe, ARRAYSIZE(Exe), L"%lsappshim_vm_%S.exe", Dir, Side_[i].Src);
            swprintf(Copy, ARRAYSIZE(Copy), L"%lsvm_side_%S.exe", Tmp, Side_[i].Src);
            swprintf(Side, ARRAYSIZE(Side), L"%ls.manifest", Copy);
            if (!CopyFileW(Exe, Copy, FALSE))
            {
                ok(0, "cannot copy %ls: %lu\n", Exe, GetLastError());
                continue;
            }
            hFile = CreateFileW(Side, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                ok(0, "cannot create %ls: %lu\n", Side, GetLastError());
                DeleteFileW(Copy);
                continue;
            }
            WriteFile(hFile, g_Win10Manifest, sizeof(g_Win10Manifest) - 1, &Written, NULL);
            CloseHandle(hFile);
            check_row(Copy, Result, Side_[i].Level, Side_[i].What, &Real, On);
            DeleteFileW(Side);
            DeleteFileW(Copy);
        }
    }
    DeleteFileW(Result);
}
