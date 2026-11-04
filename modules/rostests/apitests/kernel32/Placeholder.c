/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Placeholder memory (Windows 10 1803 and later): VirtualAlloc2 with MEM_RESERVE_PLACEHOLDER and
 *              MEM_REPLACE_PLACEHOLDER, VirtualFree with MEM_PRESERVE_PLACEHOLDER and MEM_COALESCE_PLACEHOLDERS,
 *              MapViewOfFile3 with MEM_REPLACE_PLACEHOLDER and UnmapViewOfFile2 with MEM_PRESERVE_PLACEHOLDER
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * V8 (Chrome, Electron) uses exactly these calls when kernelbase exports VirtualAlloc2, MapViewOfFile3 and
 * UnmapViewOfFile2. The error codes are those of Windows 10 as Wine's kernelbase and ntdll tests record them.
 */

#include "precomp.h"
#include <ndk/mmfuncs.h>
#include <ndk/psfuncs.h>

#define GRANULE 0x10000
#define PAGE    0x1000

typedef PVOID (WINAPI *FN_VirtualAlloc2)(HANDLE, PVOID, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
typedef PVOID (WINAPI *FN_MapViewOfFile3)(HANDLE, HANDLE, PVOID, ULONG64, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
typedef PVOID (WINAPI *FN_MapViewOfFileNuma2)(HANDLE, HANDLE, ULONG64, PVOID, SIZE_T, ULONG, ULONG, ULONG);
typedef BOOL (WINAPI *FN_UnmapViewOfFile2)(HANDLE, PVOID, ULONG);
typedef NTSTATUS (NTAPI *FN_NtAllocateVirtualMemoryEx)(HANDLE, PVOID *, PSIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG);
typedef NTSTATUS (NTAPI *FN_NtUnmapViewOfSectionEx)(HANDLE, PVOID, ULONG);
typedef BOOL (WINAPI *FN_UnmapViewOfFileEx)(PVOID, ULONG);

static FN_VirtualAlloc2 pVirtualAlloc2;
static FN_MapViewOfFile3 pMapViewOfFile3;
static FN_MapViewOfFileNuma2 pMapViewOfFileNuma2;
static FN_UnmapViewOfFile2 pUnmapViewOfFile2;
static FN_NtAllocateVirtualMemoryEx pNtAllocateVirtualMemoryEx;
static FN_NtUnmapViewOfSectionEx pNtUnmapViewOfSectionEx;
static FN_UnmapViewOfFileEx pUnmapViewOfFileEx;

/* The private commit of the process (VM_COUNTERS.PagefileUsage) */
static SIZE_T
PrivateCommit(void)
{
    VM_COUNTERS Counters;
    NTSTATUS Status;

    memset(&Counters, 0, sizeof(Counters));
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &Counters, sizeof(Counters), NULL);
    ok(Status == STATUS_SUCCESS, "ProcessVmCounters: %#lx\n", Status);
    return Counters.PagefileUsage;
}

#define check_region(p, s, st, ty, pr) check_region_(__LINE__, p, s, st, ty, pr)
static void
check_region_(int line, PVOID p, SIZE_T Size, DWORD State, DWORD Type, DWORD Protect)
{
    MEMORY_BASIC_INFORMATION Info;

    memset(&Info, 0, sizeof(Info));
    ok_(__FILE__, line)(VirtualQuery(p, &Info, sizeof(Info)) == sizeof(Info), "VirtualQuery(%p) failed\n", p);
    ok_(__FILE__, line)(Info.State == State, "%p: state %#lx, expected %#lx\n", p, Info.State, State);
    if (State != MEM_FREE)
    {
        ok_(__FILE__, line)(Info.AllocationBase == p, "%p: allocation base %p\n", p, Info.AllocationBase);
        ok_(__FILE__, line)(Info.RegionSize == Size, "%p: size %Ix, expected %Ix\n", p, Info.RegionSize, Size);
        ok_(__FILE__, line)(Info.Type == Type, "%p: type %#lx, expected %#lx\n", p, Info.Type, Type);
        ok_(__FILE__, line)(Info.AllocationProtect == Protect, "%p: protection %#lx, expected %#lx\n",
                            p, Info.AllocationProtect, Protect);
    }
}

#define check_placeholder(p, s) check_region(p, s, MEM_RESERVE, MEM_PRIVATE, PAGE_NOACCESS)

#define expect_error(r, e) expect_error_(__LINE__, (r) != 0, e)
static void
expect_error_(int line, BOOL Succeeded, DWORD Expected)
{
    DWORD Error = GetLastError();
    ok_(__FILE__, line)(!Succeeded, "call succeeded, expected error %lu\n", Expected);
    ok_(__FILE__, line)(Error == Expected, "error %lu, expected %lu\n", Error, Expected);
}

static PVOID
NewPlaceholder(SIZE_T Size)
{
    PVOID p = pVirtualAlloc2(NULL, NULL, Size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, NULL, 0);
    ok(p != NULL, "placeholder of %Ix: error %lu\n", Size, GetLastError());
    return p;
}

static void
test_Reserve(void)
{
    PVOID p, q;
    SIZE_T Size;
    NTSTATUS Status;
    DWORD Old;

    p = NewPlaceholder(4 * GRANULE);
    if (!p) return;
    ok(((ULONG_PTR)p & (GRANULE - 1)) == 0, "%p is not on a granule\n", p);
    check_placeholder(p, 4 * GRANULE);

    /* a placeholder cannot be committed or protected, and nothing else can be reserved over it */
    SetLastError(0xdeadbeef);
    expect_error(VirtualAlloc(p, PAGE, MEM_COMMIT, PAGE_READWRITE), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(VirtualAlloc(p, GRANULE, MEM_RESERVE, PAGE_READWRITE), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(VirtualProtect(p, PAGE, PAGE_READWRITE, &Old), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(UnmapViewOfFile(p), ERROR_INVALID_ADDRESS);
    check_placeholder(p, 4 * GRANULE);

    /* a placeholder is freed like any reservation */
    ok(VirtualFree(p, 0, MEM_RELEASE), "release: error %lu\n", GetLastError());
    check_region(p, 0, MEM_FREE, 0, 0);

    /* the arguments */
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, NULL, GRANULE, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, NULL, GRANULE, MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, NULL, 0),
                 ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, NULL, GRANULE, MEM_RESERVE | MEM_COMMIT | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
                                NULL, 0), ERROR_INVALID_PARAMETER);

    /* only the Ex service knows placeholders */
    q = NULL;
    Size = GRANULE;
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &q, 0, &Size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS);
    ok(Status == STATUS_INVALID_PARAMETER, "NtAllocateVirtualMemory: %#lx\n", Status);

    if (pNtAllocateVirtualMemoryEx)
    {
        q = NULL;
        Size = GRANULE;
        Status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &q, &Size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
                                            PAGE_NOACCESS, NULL, 0);
        ok(Status == STATUS_SUCCESS, "NtAllocateVirtualMemoryEx: %#lx\n", Status);
        ok(Size == GRANULE, "size %Ix\n", Size);
        if (NT_SUCCESS(Status))
        {
            /* a reservation at the placeholder's address conflicts */
            Status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &q, &Size, MEM_RESERVE, PAGE_NOACCESS, NULL, 0);
            ok(Status == STATUS_CONFLICTING_ADDRESSES, "reserve over a placeholder: %#lx\n", Status);
            Status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &q, &Size, MEM_COMMIT, PAGE_READWRITE, NULL, 0);
            ok(Status == STATUS_CONFLICTING_ADDRESSES, "commit of a placeholder: %#lx\n", Status);
            Size = 0;
            Status = NtFreeVirtualMemory(NtCurrentProcess(), &q, &Size, MEM_RELEASE);
            ok(Status == STATUS_SUCCESS, "free: %#lx\n", Status);
        }

        q = NULL;
        Size = PAGE;
        Status = pNtAllocateVirtualMemoryEx(NULL, &q, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 0);
        ok(Status == STATUS_INVALID_HANDLE, "NULL process: %#lx\n", Status);
        Status = pNtAllocateVirtualMemoryEx(NtCurrentProcess(), &q, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, NULL, 1);
        ok(Status == STATUS_INVALID_PARAMETER, "count without parameters: %#lx\n", Status);
    }
}

static void
test_Split(void)
{
    char *p, *p1, *p2;
    PVOID r;

    /* in three, at page granularity */
    p = NewPlaceholder(4 * GRANULE);
    if (!p) return;
    p1 = p + GRANULE + PAGE;
    p2 = p1 + 3 * PAGE;
    ok(VirtualFree(p1, 3 * PAGE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "split: error %lu\n", GetLastError());
    check_placeholder(p, GRANULE + PAGE);
    check_placeholder(p1, 3 * PAGE);
    check_placeholder(p2, 4 * GRANULE - GRANULE - 4 * PAGE);

    /* a whole placeholder, a size of 0, and a range across two placeholders */
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p1, 3 * PAGE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p1, 0, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p, 2 * GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_PARAMETER);

    ok(VirtualFree(p, 0, MEM_RELEASE), "release p: error %lu\n", GetLastError());
    ok(VirtualFree(p1, 0, MEM_RELEASE), "release p1: error %lu\n", GetLastError());
    ok(VirtualFree(p2, 0, MEM_RELEASE), "release p2: error %lu\n", GetLastError());

    /* the lower part, the upper part */
    p = NewPlaceholder(2 * GRANULE);
    if (p)
    {
        ok(VirtualFree(p, GRANULE / 2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "lower: error %lu\n", GetLastError());
        check_placeholder(p, GRANULE / 2);
        check_placeholder(p + GRANULE / 2, 2 * GRANULE - GRANULE / 2);
        ok(VirtualFree(p + GRANULE, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "upper: error %lu\n", GetLastError());
        check_placeholder(p + GRANULE / 2, GRANULE / 2);
        check_placeholder(p + GRANULE, GRANULE);
        VirtualFree(p, 0, MEM_RELEASE);
        VirtualFree(p + GRANULE / 2, 0, MEM_RELEASE);
        VirtualFree(p + GRANULE, 0, MEM_RELEASE);
    }

    /* an ordinary reservation is not a placeholder */
    r = VirtualAlloc(NULL, 2 * GRANULE, MEM_RESERVE, PAGE_NOACCESS);
    ok(r != NULL, "reserve: error %lu\n", GetLastError());
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(r, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_ADDRESS);
    check_region(r, 2 * GRANULE, MEM_RESERVE, MEM_PRIVATE, PAGE_NOACCESS);
    VirtualFree(r, 0, MEM_RELEASE);
}

static void
test_Coalesce(void)
{
    char *p, *p1, *p2, *q;
    NTSTATUS Status;
    PVOID Base;
    SIZE_T Size;

    p = NewPlaceholder(GRANULE);
    if (!p) return;
    p1 = p + GRANULE / 4;
    p2 = p1 + GRANULE / 4;
    ok(VirtualFree(p, GRANULE / 4, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "split 1: error %lu\n", GetLastError());
    ok(VirtualFree(p1, GRANULE / 4, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "split 2: error %lu\n", GetLastError());
    check_placeholder(p, GRANULE / 4);
    check_placeholder(p1, GRANULE / 4);
    check_placeholder(p2, GRANULE / 2);

    /* one placeholder alone, a size that does not end on a placeholder, a start that is not one */
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p, GRANULE / 4, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p, GRANULE - PAGE, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p, GRANULE + PAGE, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p + PAGE, GRANULE - PAGE, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p, 0, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), ERROR_INVALID_PARAMETER);

    /* the NT codes */
    Base = p;
    Size = GRANULE;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_COALESCE_PLACEHOLDERS);
    ok(Status == STATUS_INVALID_PARAMETER_4, "coalesce without release: %#lx\n", Status);
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
    ok(Status == STATUS_UNABLE_TO_FREE_VM, "release across placeholders: %#lx\n", Status);

    /* the first two only, then all */
    ok(VirtualFree(p, GRANULE / 2, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), "coalesce 2: error %lu\n", GetLastError());
    check_placeholder(p, GRANULE / 2);
    check_placeholder(p2, GRANULE / 2);
    Base = p;
    Size = GRANULE;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS);
    ok(Status == STATUS_SUCCESS, "coalesce all: %#lx\n", Status);
    ok(Base == p && Size == GRANULE, "got %p %Ix\n", Base, Size);
    check_placeholder(p, GRANULE);

    /* an allocation that replaced a placeholder is not a placeholder any more */
    ok(VirtualFree(p, GRANULE / 2, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "split: error %lu\n", GetLastError());
    q = pVirtualAlloc2(NULL, p2, GRANULE / 2, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
    ok(q == p2, "replace: %p, error %lu\n", q, GetLastError());
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(p, GRANULE, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), ERROR_INVALID_ADDRESS);
    ok(VirtualFree(p2, 0, MEM_RELEASE), "release p2: error %lu\n", GetLastError());
    ok(VirtualFree(p, 0, MEM_RELEASE), "release p: error %lu\n", GetLastError());
}

static void
test_ReplacePrivate(void)
{
    char *p, *q;
    MEMORY_BASIC_INFORMATION Info;
    PVOID Base;
    SIZE_T Size;
    NTSTATUS Status;

    p = NewPlaceholder(2 * GRANULE);
    if (!p) return;
    ok(VirtualFree(p + GRANULE, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "split: error %lu\n", GetLastError());

    /* the size must be the placeholder's */
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, p, PAGE, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, p, 2 * GRANULE, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE,
                                NULL, 0), ERROR_INVALID_ADDRESS);
    /* MEM_RESERVE is required, and an address */
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, p, GRANULE, MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, NULL, GRANULE, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE,
                                NULL, 0), ERROR_INVALID_PARAMETER);

    /* committed */
    q = pVirtualAlloc2(NULL, p, GRANULE, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
    ok(q == p, "replace: %p, error %lu\n", q, GetLastError());
    if (q != p) return;
    check_region(p, GRANULE, MEM_COMMIT, MEM_PRIVATE, PAGE_READWRITE);
    check_placeholder(p + GRANULE, GRANULE);
    memset(p, 0xcc, GRANULE);

    /* a second replacement of the same range is not one of a placeholder */
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, p, GRANULE, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_INVALID_PARAMETER);

    /* back into a placeholder: the contents are gone */
    ok(VirtualFree(p, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "preserve: error %lu\n", GetLastError());
    check_placeholder(p, GRANULE);
    q = pVirtualAlloc2(NULL, p, GRANULE, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER, PAGE_READONLY, NULL, 0);
    ok(q == p, "replace again: %p, error %lu\n", q, GetLastError());
    ok(*(volatile ULONG *)p == 0, "got %#lx\n", *(volatile ULONG *)p);
    check_region(p, GRANULE, MEM_COMMIT, MEM_PRIVATE, PAGE_READONLY);
    ok(VirtualFree(p, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "preserve: error %lu\n", GetLastError());

    /* reserved only, then committed in part */
    q = pVirtualAlloc2(NULL, p, GRANULE, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
    ok(q == p, "replace reserved: %p, error %lu\n", q, GetLastError());
    memset(&Info, 0, sizeof(Info));
    VirtualQuery(p, &Info, sizeof(Info));
    ok(Info.State == MEM_RESERVE && Info.AllocationProtect == PAGE_READWRITE, "state %#lx protection %#lx\n",
       Info.State, Info.AllocationProtect);
    ok(VirtualAlloc(p + PAGE, PAGE, MEM_COMMIT, PAGE_READWRITE) == p + PAGE, "commit: error %lu\n", GetLastError());
    p[PAGE] = 1;
    ok(VirtualFree(p, 0, MEM_DECOMMIT), "decommit: error %lu\n", GetLastError());

    /* a plain release of a replacement frees the range for good */
    Base = p;
    Size = 0;
    Status = NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
    ok(Status == STATUS_SUCCESS && Size == GRANULE, "release: %#lx, size %Ix\n", Status, Size);
    check_region(p, 0, MEM_FREE, 0, 0);
    check_placeholder(p + GRANULE, GRANULE);

    /* a replacement where there is no placeholder */
    SetLastError(0xdeadbeef);
    expect_error(pVirtualAlloc2(NULL, p, GRANULE, MEM_RESERVE | MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_INVALID_PARAMETER);
    ok(VirtualFree(p + GRANULE, 0, MEM_RELEASE), "release: error %lu\n", GetLastError());
}

static HANDLE
NewFileSection(PWSTR Path, SIZE_T Size)
{
    HANDLE File, Section;
    DWORD Written;
    static BYTE Page[PAGE];
    SIZE_T i;

    GetTempPathW(MAX_PATH, Path);
    wcscat(Path, L"phtest.bin");
    File = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "CreateFile: error %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE) return NULL;
    for (i = 0; i < Size; i += PAGE)
    {
        memset(Page, (BYTE)(i / PAGE + 1), sizeof(Page));
        WriteFile(File, Page, PAGE, &Written, NULL);
    }
    Section = CreateFileMappingW(File, NULL, PAGE_READWRITE, 0, 0, NULL);
    ok(Section != NULL, "CreateFileMapping: error %lu\n", GetLastError());
    CloseHandle(File);
    return Section;
}

static void
test_ReplaceView(BOOL FileBacked)
{
    WCHAR Path[MAX_PATH];
    HANDLE Section;
    char *p, *v, *w;

    trace("%s section\n", FileBacked ? "file" : "paging file");
    if (FileBacked)
        Section = NewFileSection(Path, 4 * GRANULE);
    else
        Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4 * GRANULE, NULL);
    ok(Section != NULL, "section: error %lu\n", GetLastError());
    if (!Section) return;

    p = NewPlaceholder(2 * GRANULE);
    if (!p) return;
    ok(VirtualFree(p + GRANULE, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "split: error %lu\n", GetLastError());

    /* the view must be the placeholder's size, on a page */
    SetLastError(0xdeadbeef);
    expect_error(pMapViewOfFile3(Section, NULL, p, 0, PAGE, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(pMapViewOfFile3(Section, NULL, p - 1, 0, GRANULE, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_MAPPED_ALIGNMENT);
    SetLastError(0xdeadbeef);
    expect_error(pMapViewOfFile3(Section, NULL, p, PAGE - 1, GRANULE, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0),
                 ERROR_MAPPED_ALIGNMENT);
    /* without MEM_REPLACE_PLACEHOLDER an address on a placeholder conflicts, and an offset on a page is not enough */
    SetLastError(0xdeadbeef);
    expect_error(pMapViewOfFile3(Section, NULL, p, 0, GRANULE, 0, PAGE_READWRITE, NULL, 0), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(pMapViewOfFile3(Section, NULL, NULL, PAGE, GRANULE, 0, PAGE_READWRITE, NULL, 0), ERROR_MAPPED_ALIGNMENT);

    /* into the first placeholder, at a page offset */
    v = pMapViewOfFile3(Section, NULL, p, PAGE, GRANULE, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
    ok(v == p, "map: %p, error %lu\n", v, GetLastError());
    if (v != p) return;
    check_region(p, GRANULE, MEM_COMMIT, MEM_MAPPED, PAGE_READWRITE);
    check_placeholder(p + GRANULE, GRANULE);

    /* the same pages as an ordinary view */
    w = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, 2 * GRANULE);
    ok(w != NULL, "second view: error %lu\n", GetLastError());
    if (w)
    {
        if (FileBacked)
        {
            ok(w[0] == 1, "first byte of the file %d\n", w[0]);
            ok(v[0] == 2, "first byte of the view at a page offset %d\n", v[0]);
        }
        v[0] = 0x5a;
        ok(w[PAGE] == 0x5a, "the views do not share pages: %#x\n", (BYTE)w[PAGE]);
        w[2 * PAGE] = 0x33;
        ok(v[PAGE] == 0x33, "the views do not share pages: %#x\n", (BYTE)v[PAGE]);

        /* an ordinary view cannot give a placeholder back */
        SetLastError(0xdeadbeef);
        expect_error(pUnmapViewOfFile2(GetCurrentProcess(), w, MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_ADDRESS);
        ok(UnmapViewOfFile(w), "unmap: error %lu\n", GetLastError());
    }

    /* the flags and the process are checked */
    SetLastError(0xdeadbeef);
    expect_error(pUnmapViewOfFile2(NULL, v, MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    expect_error(pUnmapViewOfFile2(GetCurrentProcess(), v, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    expect_error(VirtualFree(v, GRANULE, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_PARAMETER);

    /* back into a placeholder */
    ok(pUnmapViewOfFile2(GetCurrentProcess(), v, MEM_PRESERVE_PLACEHOLDER), "unmap preserving: error %lu\n", GetLastError());
    check_placeholder(p, GRANULE);
    SetLastError(0xdeadbeef);
    expect_error(pUnmapViewOfFile2(GetCurrentProcess(), v, MEM_PRESERVE_PLACEHOLDER), ERROR_INVALID_ADDRESS);
    SetLastError(0xdeadbeef);
    expect_error(UnmapViewOfFile(v), ERROR_INVALID_ADDRESS);

    /* the two placeholders join and take one view; UnmapViewOfFileEx keeps it too */
    ok(VirtualFree(p, 2 * GRANULE, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), "coalesce: error %lu\n", GetLastError());
    v = pMapViewOfFile3(Section, GetCurrentProcess(), p, 0, 2 * GRANULE, MEM_REPLACE_PLACEHOLDER, PAGE_READONLY, NULL, 0);
    ok(v == p, "map 2: %p, error %lu\n", v, GetLastError());
    if (v == p)
    {
        ok(v[PAGE] == 0x5a, "contents %#x\n", (BYTE)v[PAGE]);
        check_region(p, 2 * GRANULE, MEM_COMMIT, MEM_MAPPED, PAGE_READONLY);
        if (pUnmapViewOfFileEx)
        {
            ok(pUnmapViewOfFileEx(v, MEM_PRESERVE_PLACEHOLDER), "UnmapViewOfFileEx: error %lu\n", GetLastError());
        }
        else
        {
            ok(pUnmapViewOfFile2(GetCurrentProcess(), v, MEM_PRESERVE_PLACEHOLDER), "unmap: error %lu\n", GetLastError());
        }
        check_placeholder(p, 2 * GRANULE);
    }

    /* a plain unmap of a view that replaced a placeholder frees the range */
    v = pMapViewOfFile3(Section, NULL, p, 0, 2 * GRANULE, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
    ok(v == p, "map 3: %p, error %lu\n", v, GetLastError());
    ok(UnmapViewOfFile(v), "unmap: error %lu\n", GetLastError());
    check_region(p, 0, MEM_FREE, 0, 0);

    /* MapViewOfFileNuma2: node 0 and no preferred node */
    if (pMapViewOfFileNuma2)
    {
        v = pMapViewOfFileNuma2(Section, GetCurrentProcess(), 0, NULL, GRANULE, 0, PAGE_READWRITE, 0xFFFFFFFF);
        ok(v != NULL, "MapViewOfFileNuma2 no node: error %lu\n", GetLastError());
        if (v) UnmapViewOfFile(v);
        v = pMapViewOfFileNuma2(Section, GetCurrentProcess(), 0, NULL, GRANULE, 0, PAGE_READWRITE, 0);
        ok(v != NULL, "MapViewOfFileNuma2 node 0: error %lu\n", GetLastError());
        if (v) UnmapViewOfFile(v);
    }

    CloseHandle(Section);
    if (FileBacked) DeleteFileW(Path);
}

/* V8's pattern: one big placeholder, pieces split off, replaced by private memory or views, given back, joined */
static ULONG
CountRegions(char *Base, SIZE_T Size)
{
    MEMORY_BASIC_INFORMATION Info;
    char *p = Base;
    ULONG Count = 0;

    while (p < Base + Size && VirtualQuery(p, &Info, sizeof(Info)))
    {
        Count++;
        p = (char *)Info.BaseAddress + Info.RegionSize;
    }
    return Count;
}

static void
test_Pattern(void)
{
    const SIZE_T Total = 64 * GRANULE, Piece = 4 * GRANULE;
    SIZE_T Before, After;
    HANDLE Section;
    char *p, *q;
    ULONG Round, i;

    Section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)Piece, NULL);
    ok(Section != NULL, "section: error %lu\n", GetLastError());
    p = NewPlaceholder(Total);
    if (!p || !Section) return;

    Before = PrivateCommit();
    for (Round = 0; Round < 20; Round++)
    {
        /* split into pieces */
        for (i = 0; i + 1 < Total / Piece; i++)
            ok(VirtualFree(p + i * Piece, Piece, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "split %lu: error %lu\n", i, GetLastError());
        ok(CountRegions(p, Total) == Total / Piece, "%lu regions\n", CountRegions(p, Total));

        /* replace each: private memory or a view */
        for (i = 0; i < Total / Piece; i++)
        {
            if (i & 1)
                q = pMapViewOfFile3(Section, NULL, p + i * Piece, 0, Piece, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, NULL, 0);
            else
                q = pVirtualAlloc2(NULL, p + i * Piece, Piece, MEM_RESERVE | MEM_COMMIT | MEM_REPLACE_PLACEHOLDER,
                                   PAGE_READWRITE, NULL, 0);
            ok(q == p + i * Piece, "replace %lu: %p, error %lu\n", i, q, GetLastError());
            if (q) q[Round] = (char)i;
        }

        /* give them back */
        for (i = 0; i < Total / Piece; i++)
        {
            if (i & 1)
                ok(pUnmapViewOfFile2(GetCurrentProcess(), p + i * Piece, MEM_PRESERVE_PLACEHOLDER), "unmap %lu: error %lu\n", i, GetLastError());
            else
                ok(VirtualFree(p + i * Piece, Piece, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER), "free %lu: error %lu\n", i, GetLastError());
        }

        /* and join */
        ok(VirtualFree(p, Total, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS), "coalesce: error %lu\n", GetLastError());
        check_placeholder(p, Total);
    }
    After = PrivateCommit();
    ok(After <= Before + 4 * PAGE, "private commit grew from %Iu to %Iu\n", Before, After);

    ok(VirtualFree(p, 0, MEM_RELEASE), "release: error %lu\n", GetLastError());
    CloseHandle(Section);
}

START_TEST(Placeholder)
{
    HMODULE Kernelbase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");

    if (!Kernelbase) Kernelbase = LoadLibraryW(L"kernelbase.dll");
    pVirtualAlloc2 = Kernelbase ? (PVOID)GetProcAddress(Kernelbase, "VirtualAlloc2") : NULL;
    pMapViewOfFile3 = Kernelbase ? (PVOID)GetProcAddress(Kernelbase, "MapViewOfFile3") : NULL;
    pMapViewOfFileNuma2 = Kernelbase ? (PVOID)GetProcAddress(Kernelbase, "MapViewOfFileNuma2") : NULL;
    pUnmapViewOfFile2 = Kernelbase ? (PVOID)GetProcAddress(Kernelbase, "UnmapViewOfFile2") : NULL;
    pNtAllocateVirtualMemoryEx = (PVOID)GetProcAddress(Ntdll, "NtAllocateVirtualMemoryEx");
    pNtUnmapViewOfSectionEx = (PVOID)GetProcAddress(Ntdll, "NtUnmapViewOfSectionEx");
    pUnmapViewOfFileEx = (PVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "UnmapViewOfFileEx");

    if (!pVirtualAlloc2 || !pMapViewOfFile3 || !pUnmapViewOfFile2)
    {
        skip("VirtualAlloc2 %p, MapViewOfFile3 %p, UnmapViewOfFile2 %p\n", pVirtualAlloc2, pMapViewOfFile3, pUnmapViewOfFile2);
        return;
    }

    test_Reserve();
    test_Split();
    test_Coalesce();
    test_ReplacePrivate();
    test_ReplaceView(FALSE);
    test_ReplaceView(TRUE);
    test_Pattern();
}
