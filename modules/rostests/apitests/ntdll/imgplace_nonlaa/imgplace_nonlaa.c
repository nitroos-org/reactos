/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper of the ImagePlacement test: an executable linked without LARGEADDRESSAWARE. A 64-bit process
 *              of that kind keeps what the system places for it below 2 GB. The exit code is a mask of failed checks.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <stdio.h>
#include <windows.h>

#ifndef IMAGE_FILE_LARGE_ADDRESS_AWARE
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#endif

#define TWO_GB 0x80000000ULL

static DWORD g_Failed;

#ifdef _WIN64
static void
Check(DWORD Bit, const char *What, PVOID Base, SIZE_T Size)
{
    ULONG_PTR Start = (ULONG_PTR)Base;

    if (!Base)
    {
        printf("imgplace_nonlaa: %s: no address\n", What);
        g_Failed |= Bit;
    }
    else if ((ULONG_PTR)Start >= TWO_GB || Size - 1 >= TWO_GB - Start)
    {
        printf("imgplace_nonlaa: %s: %p + %Ix is not below 2 GB\n", What, Base, Size);
        g_Failed |= Bit;
    }
    else
    {
        printf("imgplace_nonlaa: %s: %p ok\n", What, Base);
    }
}

#endif

typedef LONG (NTAPI *PNtCreateSection)(PHANDLE, ULONG, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef LONG (NTAPI *PNtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T,
                                          ULONG, ULONG, ULONG);
typedef LONG (NTAPI *PNtUnmapViewOfSection)(HANDLE, PVOID);

int wmain(int argc, WCHAR **argv)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PNtCreateSection pCreate = (PNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    PNtMapViewOfSection pMap = (PNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    PNtUnmapViewOfSection pUnmap = (PNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    PBYTE Exe = (PBYTE)GetModuleHandleW(NULL);
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(Exe + ((PIMAGE_DOS_HEADER)Exe)->e_lfanew);

    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
    {
        printf("imgplace_nonlaa: this executable is large address aware\n");
        return 0x100;
    }
    if (argc < 2 || !pCreate || !pMap || !pUnmap)
        return 0x200;

#ifdef _WIN64
    {
        HANDLE File, Section = NULL, Mapping;
        PVOID Base1 = NULL, Base2 = NULL, Base3 = NULL, P;
        SIZE_T Size1 = 0, Size2 = 0, Size3 = 0;
        LARGE_INTEGER Offset;
        HMODULE hDll;
        LONG Status;

        File = CreateFileW(argv[1], GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, 0, NULL);
        if (File == INVALID_HANDLE_VALUE)
            return 0x400;
        Status = pCreate(&Section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, NULL, NULL, PAGE_EXECUTE_READ,
                         SEC_IMAGE, File);
        CloseHandle(File);
        if (Status < 0)
            return 0x400;

        /* The first view takes the preferred base, so the next ones are relocated */
        Offset.QuadPart = 0;
        pMap(Section, GetCurrentProcess(), &Base1, 0, 0, &Offset, &Size1, 2 /* ViewUnmap */, 0, PAGE_READONLY);
        pMap(Section, GetCurrentProcess(), &Base2, 0, 0, &Offset, &Size2, 2, 0, PAGE_READONLY);
        pMap(Section, GetCurrentProcess(), &Base3, 0, 0, &Offset, &Size3, 2, 0, PAGE_READONLY);
        printf("imgplace_nonlaa: views %p %p %p\n", Base1, Base2, Base3);
        if (Base2 == Base1 || Base3 == Base2)
            g_Failed |= 0x1;
        Check(0x2, "relocated image view", Base2, Size2);
        Check(0x4, "second relocated image view", Base3, Size3);

        /* The loader goes through the same placement */
        hDll = LoadLibraryW(argv[1]);
        if (hDll)
            Check(0x8, "LoadLibrary", hDll, 0x1000);
        else
            g_Failed |= 0x8;

        P = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        Check(0x10, "VirtualAlloc(NULL)", P, 0x10000);
        P = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
        Check(0x20, "VirtualAlloc(NULL, MEM_TOP_DOWN)", P, 0x10000);
        P = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS);
        Check(0x40, "VirtualAlloc(NULL, MEM_RESERVE)", P, 0x10000);

        Mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x10000, NULL);
        P = Mapping ? MapViewOfFile(Mapping, FILE_MAP_WRITE, 0, 0, 0) : NULL;
        Check(0x80, "MapViewOfFile", P, 0x10000);

        if (Base3) pUnmap(GetCurrentProcess(), Base3);
        if (Base2) pUnmap(GetCurrentProcess(), Base2);
        if (Base1) pUnmap(GetCurrentProcess(), Base1);
    }
#else
    printf("imgplace_nonlaa: 32-bit build, nothing to check\n");
#endif
    return (int)g_Failed;
}
