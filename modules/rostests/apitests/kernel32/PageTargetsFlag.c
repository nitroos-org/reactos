/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     PAGE_TARGETS_INVALID / PAGE_TARGETS_NO_UPDATE (0x40000000) in VirtualAlloc, VirtualAlloc2, VirtualProtect
 *              and MapViewOfFile3
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * V8 (Node.js, Chrome, Electron) asks for PAGE_EXECUTE_READ|PAGE_TARGETS_INVALID and
 * PAGE_EXECUTE_READWRITE|PAGE_TARGETS_INVALID on every executable commit on Windows 10, and aborts when the call
 * fails. Windows accepts the bit with an execute protection only (error 87 otherwise) and reports the plain
 * protection afterwards. The expectations are what a Windows 10 22H2 system answered to this matrix.
 */

#include "precomp.h"

#ifndef PAGE_TARGETS_INVALID
#define PAGE_TARGETS_INVALID 0x40000000
#endif

typedef PVOID (WINAPI *FN_VirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, PVOID, ULONG);
typedef PVOID (WINAPI *FN_MapViewOfFile3)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, PVOID, ULONG);

static FN_VirtualAlloc2 pVirtualAlloc2;
static FN_MapViewOfFile3 pMapViewOfFile3;

static const struct
{
    DWORD Protect;
    const char *Name;
    BOOL Exec;          /* the bit is accepted with this protection */
    BOOL Private;       /* the protection exists for private memory */
} g_Bases[] =
{
    { PAGE_NOACCESS,          "NOACCESS", FALSE, TRUE },
    { PAGE_READONLY,          "RO",       FALSE, TRUE },
    { PAGE_READWRITE,         "RW",       FALSE, TRUE },
    { PAGE_WRITECOPY,         "WC",       FALSE, FALSE },
    { PAGE_EXECUTE,           "X",        TRUE,  TRUE },
    { PAGE_EXECUTE_READ,      "RX",       TRUE,  TRUE },
    { PAGE_EXECUTE_READWRITE, "RWX",      TRUE,  TRUE },
    { PAGE_EXECUTE_WRITECOPY, "XWC",      TRUE,  FALSE },
};

static DWORD
QueryProtect(PVOID Address)
{
    MEMORY_BASIC_INFORMATION Info;

    memset(&Info, 0, sizeof(Info));
    if (VirtualQuery(Address, &Info, sizeof(Info)) != sizeof(Info)) return 0xDEAD;
    return Info.Protect;
}

static void
TestPrivate(unsigned i)
{
    const char *Name = g_Bases[i].Name;
    DWORD Base = g_Bases[i].Protect;
    DWORD Flagged = Base | PAGE_TARGETS_INVALID;
    BOOL Expect = g_Bases[i].Exec && g_Bases[i].Private;
    DWORD Error, Old;
    PVOID Mem, Reserved;
    BOOL Ret;

    /* reserve and commit in one call */
    SetLastError(0xDEADBEEF);
    Mem = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, Flagged);
    Error = GetLastError();
    ok(!!Mem == Expect, "%s: VirtualAlloc(reserve+commit) returned %p, error %lu\n", Name, Mem, Error);
    if (Mem)
    {
        ok(QueryProtect(Mem) == Base, "%s: queried protection %#lx, expected %#lx\n", Name, QueryProtect(Mem), Base);
        VirtualFree(Mem, 0, MEM_RELEASE);
    }
    else
    {
        ok(Error == ERROR_INVALID_PARAMETER, "%s: error %lu, expected 87\n", Name, Error);
    }

    /* reserve only: the protection is checked, not applied */
    SetLastError(0xDEADBEEF);
    Mem = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, Flagged);
    Error = GetLastError();
    ok(!!Mem == Expect, "%s: VirtualAlloc(reserve) returned %p, error %lu\n", Name, Mem, Error);
    if (Mem)
        VirtualFree(Mem, 0, MEM_RELEASE);
    else
        ok(Error == ERROR_INVALID_PARAMETER, "%s: error %lu, expected 87\n", Name, Error);

    /* commit into a reservation: VirtualAlloc, and VirtualAlloc2 as V8 does */
    Reserved = VirtualAlloc(NULL, 0x20000, MEM_RESERVE, PAGE_NOACCESS);
    ok(Reserved != NULL, "reserve failed: %lu\n", GetLastError());
    if (Reserved)
    {
        SetLastError(0xDEADBEEF);
        Mem = VirtualAlloc(Reserved, 0x10000, MEM_COMMIT, Flagged);
        Error = GetLastError();
        ok(!!Mem == Expect, "%s: VirtualAlloc(commit) returned %p, error %lu\n", Name, Mem, Error);
        if (Mem)
            ok(QueryProtect(Mem) == Base, "%s: queried protection %#lx, expected %#lx\n", Name, QueryProtect(Mem), Base);
        else
            ok(Error == ERROR_INVALID_PARAMETER, "%s: error %lu, expected 87\n", Name, Error);

        if (pVirtualAlloc2)
        {
            SetLastError(0xDEADBEEF);
            Mem = pVirtualAlloc2(GetCurrentProcess(), (PBYTE)Reserved + 0x10000, 0x10000, MEM_COMMIT, Flagged, NULL, 0);
            Error = GetLastError();
            ok(!!Mem == Expect, "%s: VirtualAlloc2(commit) returned %p, error %lu\n", Name, Mem, Error);
            if (Mem)
                ok(QueryProtect(Mem) == Base, "%s: queried protection %#lx, expected %#lx\n", Name, QueryProtect(Mem), Base);
            else
                ok(Error == ERROR_INVALID_PARAMETER, "%s: error %lu, expected 87\n", Name, Error);
        }
        VirtualFree(Reserved, 0, MEM_RELEASE);
    }

    /* protection change; the bit is PAGE_TARGETS_NO_UPDATE here */
    if (g_Bases[i].Private)
    {
        Mem = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok(Mem != NULL, "alloc failed: %lu\n", GetLastError());
        if (Mem)
        {
            Old = 0xDEAD;
            SetLastError(0xDEADBEEF);
            Ret = VirtualProtect(Mem, 0x1000, Flagged, &Old);
            Error = GetLastError();
            ok(Ret == Expect, "%s: VirtualProtect returned %d, error %lu\n", Name, Ret, Error);
            if (Ret)
            {
                ok(Old == PAGE_READWRITE, "%s: old protection %#lx\n", Name, Old);
                ok(QueryProtect(Mem) == Base, "%s: queried protection %#lx, expected %#lx\n", Name, QueryProtect(Mem), Base);
                /* the bit is not remembered */
                Old = 0xDEAD;
                ok(VirtualProtect(Mem, 0x1000, PAGE_READWRITE, &Old), "VirtualProtect back: %lu\n", GetLastError());
                ok(Old == Base, "%s: old protection %#lx, expected %#lx\n", Name, Old, Base);
            }
            else
            {
                ok(Error == ERROR_INVALID_PARAMETER, "%s: error %lu, expected 87\n", Name, Error);
            }
            VirtualFree(Mem, 0, MEM_RELEASE);
        }
    }
}

static void
TestView(unsigned i)
{
    const char *Name = g_Bases[i].Name;
    DWORD Flagged = g_Bases[i].Protect | PAGE_TARGETS_INVALID;
    DWORD Error;
    HANDLE Section;
    PVOID View;
    /* Windows maps an execute-write-copy view with the bit too */
    BOOL Expect = g_Bases[i].Exec;

    if (!pMapViewOfFile3) return;

    Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x10000, NULL);
    ok(Section != NULL, "CreateFileMapping failed: %lu\n", GetLastError());
    if (!Section) return;

    SetLastError(0xDEADBEEF);
    View = pMapViewOfFile3(Section, GetCurrentProcess(), NULL, 0, 0x10000, 0, Flagged, NULL, 0);
    Error = GetLastError();
    ok(!!View == Expect, "%s: MapViewOfFile3 returned %p, error %lu\n", Name, View, Error);
    if (View)
    {
        ok(QueryProtect(View) == g_Bases[i].Protect, "%s: queried protection %#lx, expected %#lx\n",
           Name, QueryProtect(View), g_Bases[i].Protect);
        UnmapViewOfFile(View);
    }
    else
    {
        ok(Error == ERROR_INVALID_PARAMETER, "%s: error %lu, expected 87\n", Name, Error);
    }

    /* VirtualProtect on a view takes the bit with an execute protection, execute-write-copy included */
    View = MapViewOfFile(Section, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0x10000);
    ok(View != NULL, "MapViewOfFile failed: %lu\n", GetLastError());
    if (View)
    {
        DWORD Old;
        BOOL Ret;

        SetLastError(0xDEADBEEF);
        Ret = VirtualProtect(View, 0x1000, Flagged, &Old);
        Error = GetLastError();
        ok(Ret == Expect, "%s: VirtualProtect on a view returned %d, error %lu\n", Name, Ret, Error);
        if (!Ret)
            ok(Error == ERROR_INVALID_PARAMETER, "%s: error %lu, expected 87\n", Name, Error);
        UnmapViewOfFile(View);
    }
    CloseHandle(Section);
}

START_TEST(PageTargetsFlag)
{
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    PVOID Mem;
    DWORD Old;
    unsigned i;

    if (!hKernelBase) hKernelBase = LoadLibraryW(L"kernelbase.dll");
    if (hKernelBase)
    {
        pVirtualAlloc2 = (FN_VirtualAlloc2)GetProcAddress(hKernelBase, "VirtualAlloc2");
        pMapViewOfFile3 = (FN_MapViewOfFile3)GetProcAddress(hKernelBase, "MapViewOfFile3");
    }

    for (i = 0; i < _countof(g_Bases); i++)
    {
        TestPrivate(i);
        TestView(i);
    }

    /* the bit alone, and with no protection at all, is never valid */
    SetLastError(0xDEADBEEF);
    Mem = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_TARGETS_INVALID);
    ok(Mem == NULL && GetLastError() == ERROR_INVALID_PARAMETER, "alone: %p, error %lu\n", Mem, GetLastError());
    if (Mem) VirtualFree(Mem, 0, MEM_RELEASE);

    /* execute memory moves to another execute protection with the bit */
    Mem = VirtualAlloc(NULL, 0x10000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
    ok(Mem != NULL, "alloc failed: %lu\n", GetLastError());
    if (Mem)
    {
        Old = 0xDEAD;
        ok(VirtualProtect(Mem, 0x1000, PAGE_TARGETS_INVALID | PAGE_EXECUTE_READWRITE, &Old),
           "RX -> RWX with the bit: %lu\n", GetLastError());
        ok(Old == PAGE_EXECUTE_READ, "old protection %#lx\n", Old);
        ok(QueryProtect(Mem) == PAGE_EXECUTE_READWRITE, "queried protection %#lx\n", QueryProtect(Mem));
        VirtualFree(Mem, 0, MEM_RELEASE);
    }
}
