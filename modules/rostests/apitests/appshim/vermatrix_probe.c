/*
 * PROJECT:     appshim_apitest
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     What this process is told about the Windows version, by every API that answers it.
 *              Writes one line to the file named by argv[1]; the manifest and PE header of the
 *              build of this probe decide the answers (see versionmatrix.c).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */
#include <windows.h>
#include <stdio.h>

typedef LONG (WINAPI *RTLGETVERSIONPROC)(OSVERSIONINFOEXW *);
typedef BOOLEAN (WINAPI *RTLVERIFYPROC)(OSVERSIONINFOEXW *, ULONG, ULONGLONG);
typedef VOID (WINAPI *RTLNTNUMBERSPROC)(PULONG, PULONG, PULONG);

static int Vvi(DWORD Major, DWORD Minor)
{
    OSVERSIONINFOEXW Want = { sizeof(Want) };
    DWORDLONG Mask = 0;

    Want.dwMajorVersion = Major;
    Want.dwMinorVersion = Minor;
    Mask = VerSetConditionMask(Mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    Mask = VerSetConditionMask(Mask, VER_MINORVERSION, VER_GREATER_EQUAL);
    return VerifyVersionInfoW(&Want, VER_MAJORVERSION | VER_MINORVERSION, Mask) ? 1 : 0;
}

/* Major >= wanted, or (equal and Minor >= wanted): the way an application asks, with both fields in one condition each */
static int VviRtl(RTLVERIFYPROC pVerify, DWORD Major, DWORD Minor)
{
    OSVERSIONINFOEXW Want = { sizeof(Want) };
    DWORDLONG Mask = 0;

    Want.dwMajorVersion = Major;
    Want.dwMinorVersion = Minor;
    Mask = VerSetConditionMask(Mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    Mask = VerSetConditionMask(Mask, VER_MINORVERSION, VER_GREATER_EQUAL);
    return pVerify(&Want, VER_MAJORVERSION | VER_MINORVERSION, Mask) == 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    RTLGETVERSIONPROC pRtlGetVersion = (RTLGETVERSIONPROC)GetProcAddress(hNtdll, "RtlGetVersion");
    RTLVERIFYPROC pRtlVerify = (RTLVERIFYPROC)GetProcAddress(hNtdll, "RtlVerifyVersionInfo");
    RTLNTNUMBERSPROC pNtNumbers = (RTLNTNUMBERSPROC)GetProcAddress(hNtdll, "RtlGetNtVersionNumbers");
    OSVERSIONINFOEXW Ex = { sizeof(Ex) }, Rtl = { sizeof(Rtl) };
    OSVERSIONINFOEXA ExA = { sizeof(ExA) };
    ULONG NtMajor = 0, NtMinor = 0, NtBuild = 0;
    char Line[512];
    DWORD Gv = GetVersion();
    FILE *f;

    GetVersionExW((OSVERSIONINFOW *)&Ex);
    GetVersionExA((OSVERSIONINFOA *)&ExA);
    pRtlGetVersion(&Rtl);
    pNtNumbers(&NtMajor, &NtMinor, &NtBuild);

    sprintf(Line, "GV=%08lx EXW=%lu.%lu.%lu EXA=%lu.%lu.%lu VVI=%d%d%d RTL=%lu.%lu.%lu RVVI=%d%d%d NT=%lu.%lu.%lx KUSER=%lu.%lu.%lu SP=%u.%u PT=%u",
            Gv, Ex.dwMajorVersion, Ex.dwMinorVersion, Ex.dwBuildNumber,
            ExA.dwMajorVersion, ExA.dwMinorVersion, ExA.dwBuildNumber,
            Vvi(6, 2), Vvi(6, 3), Vvi(10, 0),
            Rtl.dwMajorVersion, Rtl.dwMinorVersion, Rtl.dwBuildNumber,
            VviRtl(pRtlVerify, 6, 2), VviRtl(pRtlVerify, 6, 3), VviRtl(pRtlVerify, 10, 0),
            NtMajor, NtMinor, NtBuild,
            *(volatile ULONG *)(ULONG_PTR)0x7FFE026C, *(volatile ULONG *)(ULONG_PTR)0x7FFE0270,
            *(volatile ULONG *)(ULONG_PTR)0x7FFE0260,
            Ex.wServicePackMajor, Ex.wServicePackMinor, Ex.wProductType);
    if (argc > 1)
    {
        f = fopen(argv[1], "w");
        if (!f)
            return 2;
        fprintf(f, "%s\n", Line);
        fclose(f);
    }
    else
        printf("%s\n", Line);
    return 0;
}
