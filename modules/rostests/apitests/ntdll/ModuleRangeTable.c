/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     RtlPcToFileHeader while modules are loaded and unloaded: the module found for an address never
 *              outlives the module, more than 512 modules, exceptions raised while the loader changes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <winuser.h>

#define EMPTY_DLL_ID        102
#define MANY_MODULES        560
#define RAISE_CODE          0xE0000005

static WCHAR TempDir[MAX_PATH];

static BOOL ExtractDll(ULONG Id, PCWSTR Path)
{
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(Id), (PCWSTR)RT_RCDATA);
    HGLOBAL hGlobal = hRsrc ? LoadResource(NULL, hRsrc) : NULL;
    PVOID Data = hGlobal ? LockResource(hGlobal) : NULL;
    DWORD Size = hRsrc ? SizeofResource(NULL, hRsrc) : 0, Written = 0;
    HANDLE hFile;
    BOOL Ret;

    if (!Data)
        return FALSE;
    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(hFile, Data, Size, &Written, NULL) && Written == Size;
    CloseHandle(hFile);
    return Ret;
}

static PVOID PcToFileHeader(PVOID Pc)
{
    PVOID Base = (PVOID)(ULONG_PTR)0xdeadbeef, Ret;

    Ret = RtlPcToFileHeader(Pc, &Base);
    ok(Ret == Base, "RtlPcToFileHeader returned %p, base %p\n", Ret, Base);
    return Ret;
}

static ULONG ImageSize(HMODULE Module)
{
    return RtlImageNtHeader(Module)->OptionalHeader.SizeOfImage;
}

static void TestBasics(void)
{
    WCHAR Path[MAX_PATH];
    HMODULE Module;
    PVOID Local;
    ULONG i, Size;

    /* Stack and heap addresses belong to no module, code addresses to the module that contains them */
    ok(PcToFileHeader(&Local) == NULL, "stack address has a module\n");
    ok(PcToFileHeader(GetProcessHeap()) == NULL, "heap address has a module\n");
    ok(PcToFileHeader(NULL) == NULL, "NULL has a module\n");
    ok(PcToFileHeader(RtlPcToFileHeader) == GetModuleHandleW(L"ntdll.dll"), "ntdll code\n");
    ok(PcToFileHeader(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateEventW")) ==
       (PVOID)GetModuleHandleW(L"kernel32.dll"), "kernel32 code\n");

    StringCchPrintfW(Path, _countof(Path), L"%smrt_%lu_basic.dll", TempDir, GetCurrentProcessId());
    if (!ExtractDll(EMPTY_DLL_ID, Path))
    {
        skip("Could not write %ls\n", Path);
        return;
    }

    for (i = 0; i < 20; i++)
    {
        Module = LoadLibraryW(Path);
        ok(Module != NULL, "LoadLibrary failed with %lu\n", GetLastError());
        if (!Module)
            break;
        Size = ImageSize(Module);
        ok(PcToFileHeader(Module) == Module, "image base\n");
        ok(PcToFileHeader((PBYTE)Module + 0x10) == Module, "inside\n");
        ok(PcToFileHeader((PBYTE)Module + Size - 1) == Module, "last byte\n");
        ok(PcToFileHeader((PBYTE)Module + Size) != Module, "first byte after the image\n");

        ok(FreeLibrary(Module), "FreeLibrary failed\n");

        /* The range left with the module, nothing else is mapped there */
        ok(PcToFileHeader(Module) == NULL, "round %lu: unloaded module %p is still found\n", i, Module);
        ok(PcToFileHeader((PBYTE)Module + 0x10) == NULL, "round %lu: unloaded module %p is still found\n", i, Module);
    }

    DeleteFileW(Path);
}

/* The same image with a larger SizeOfImage (and the same base): the sections stay where they are, the module just
   covers more address space */
static BOOL ExtractBigDll(PCWSTR Path, ULONG Extra)
{
    HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(EMPTY_DLL_ID), (PCWSTR)RT_RCDATA);
    HGLOBAL hGlobal = hRsrc ? LoadResource(NULL, hRsrc) : NULL;
    PVOID Data = hGlobal ? LockResource(hGlobal) : NULL;
    DWORD Size = hRsrc ? SizeofResource(NULL, hRsrc) : 0, Written = 0;
    PIMAGE_NT_HEADERS NtHeaders;
    PBYTE Copy;
    HANDLE hFile;
    BOOL Ret = FALSE;

    if (!Data)
        return FALSE;
    Copy = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Copy)
        return FALSE;
    memcpy(Copy, Data, Size);
    NtHeaders = RtlImageNtHeader(Copy);
    if (NtHeaders)
    {
        NtHeaders->OptionalHeader.SizeOfImage += Extra;
        hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            Ret = WriteFile(hFile, Copy, Size, &Written, NULL) && Written == Size;
            CloseHandle(hFile);
        }
    }
    HeapFree(GetProcessHeap(), 0, Copy);
    return Ret;
}

/* An image of another size at the base that was just freed: the old size must not stay. Both directions: the
   larger one first (its range would swallow addresses of the smaller one), then the smaller one first. */
static void TestReloadOtherSize(void)
{
    const ULONG Extra = 0x10000;
    WCHAR Small[MAX_PATH], Big[MAX_PATH];
    HMODULE First, Second;
    ULONG Order, SizeFirst, SizeSecond;
    PBYTE Probe;

    StringCchPrintfW(Small, _countof(Small), L"%smrt_%lu_small.dll", TempDir, GetCurrentProcessId());
    StringCchPrintfW(Big, _countof(Big), L"%smrt_%lu_big.dll", TempDir, GetCurrentProcessId());
    if (!ExtractDll(EMPTY_DLL_ID, Small) || !ExtractBigDll(Big, Extra))
    {
        skip("Could not write the images\n");
        return;
    }

    for (Order = 0; Order < 2; Order++)
    {
        First = LoadLibraryW(Order ? Small : Big);
        if (!First)
        {
            skip("Could not load the image with the other size: %lu\n", GetLastError());
            break;
        }
        SizeFirst = ImageSize(First);
        ok(PcToFileHeader((PBYTE)First + SizeFirst - 1) == First, "first image\n");
        ok(FreeLibrary(First), "FreeLibrary failed\n");

        Second = LoadLibraryW(Order ? Big : Small);
        if (!Second)
        {
            skip("Could not load the second image: %lu\n", GetLastError());
            break;
        }
        SizeSecond = ImageSize(Second);
        if (Second != First || SizeSecond == SizeFirst)
        {
            skip("The second image is at %p, not at %p, or has the same size\n", Second, First);
            FreeLibrary(Second);
            continue;
        }

        ok(PcToFileHeader(Second) == Second, "second image, base\n");
        ok(PcToFileHeader((PBYTE)Second + SizeSecond - 1) == Second, "second image, last byte\n");
        if (SizeFirst > SizeSecond)
        {
            /* Not in the second image, so not in any module: the range of the first one is gone */
            Probe = (PBYTE)Second + SizeSecond;
            ok(PcToFileHeader(Probe) != Second, "order %lu: the size of the unloaded image is still in use\n", Order);
            ok(PcToFileHeader((PBYTE)Second + SizeFirst - 1) != Second,
               "order %lu: the size of the unloaded image is still in use\n", Order);
        }
        else
        {
            ok(PcToFileHeader((PBYTE)Second + SizeFirst) == Second, "order %lu: the larger image is not found\n", Order);
        }
        ok(FreeLibrary(Second), "FreeLibrary failed\n");
        ok(PcToFileHeader((PBYTE)Second + 0x10) == NULL, "order %lu: unloaded image is still found\n", Order);
    }

    DeleteFileW(Small);
    DeleteFileW(Big);
}

typedef struct _PROBE
{
    HANDLE Thread;
    HANDLE Locked;
    HANDLE Go;
    volatile LONG Done;
} PROBE;

static DWORD WINAPI LookupThread(PVOID Parameter)
{
    PROBE *Probe = Parameter;
    PVOID Local;

    SetEvent(Probe->Locked);
    WaitForSingleObject(Probe->Go, 10000);
    ok(PcToFileHeader(&Local) == NULL, "stack address has a module\n");
    InterlockedExchange(&Probe->Done, 1);
    return 0;
}

/* The lookup of an address that is in no module must not wait for the loader lock while the table covers
   every module (Windows does not take it either). */
static BOOLEAN LookupWithoutLoaderLock(void)
{
    PROBE Probe = { 0 };
    ULONG_PTR Cookie = 0;
    ULONG State = 0, Waited;
    NTSTATUS Status;
    BOOLEAN Ok;

    Probe.Locked = CreateEventW(NULL, FALSE, FALSE, NULL);
    Probe.Go = CreateEventW(NULL, FALSE, FALSE, NULL);
    Probe.Thread = CreateThread(NULL, 0, LookupThread, &Probe, 0, NULL);
    WaitForSingleObject(Probe.Locked, 10000);

    Status = LdrLockLoaderLock(0, &State, &Cookie);
    ok(NT_SUCCESS(Status) && State == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED, "LdrLockLoaderLock: %lx, %lu\n", Status, State);
    SetEvent(Probe.Go);
    for (Waited = 0; Waited < 3000 && !Probe.Done; Waited += 50)
        Sleep(50);
    Ok = Probe.Done != 0;
    LdrUnlockLoaderLock(0, Cookie);

    WaitForSingleObject(Probe.Thread, 10000);
    CloseHandle(Probe.Thread);
    CloseHandle(Probe.Locked);
    CloseHandle(Probe.Go);
    return Ok;
}

static void TestManyModules(void)
{
    static HMODULE Modules[MANY_MODULES];
    WCHAR Path[MAX_PATH];
    ULONG i, Loaded = 0, Bad = 0;

    ok(LookupWithoutLoaderLock(), "The lookup waited for the loader lock before the modules were loaded\n");

    for (i = 0; i < MANY_MODULES; i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%smrt_%lu_%03lu.dll", TempDir, GetCurrentProcessId(), i);
        if (!ExtractDll(EMPTY_DLL_ID, Path))
            break;
        Modules[i] = LoadLibraryW(Path);
        if (!Modules[i])
            break;
        Loaded++;
    }
    ok(Loaded == MANY_MODULES, "Loaded %lu of %u modules (error %lu)\n", Loaded, MANY_MODULES, GetLastError());

    /* Every module is found, whatever the table holds */
    for (i = 0; i < Loaded; i++)
    {
        if (PcToFileHeader((PBYTE)Modules[i] + 0x10) != Modules[i])
            Bad++;
    }
    ok(Bad == 0, "%lu of %lu modules are not found\n", Bad, Loaded);
    ok(PcToFileHeader(RtlPcToFileHeader) == GetModuleHandleW(L"ntdll.dll"), "ntdll code\n");

    /* Unload every other module first, then the rest */
    for (i = 0; i < Loaded; i += 2)
    {
        ok(FreeLibrary(Modules[i]), "FreeLibrary failed\n");
        if (PcToFileHeader((PBYTE)Modules[i] + 0x10) != NULL)
            Bad++;
    }
    ok(Bad == 0, "%lu unloaded modules are still found\n", Bad);
    for (i = 1; i < Loaded; i += 2)
    {
        if (PcToFileHeader((PBYTE)Modules[i] + 0x10) != Modules[i])
            Bad++;
    }
    ok(Bad == 0, "%lu modules that stayed are not found\n", Bad);
    for (i = 1; i < Loaded; i += 2)
    {
        ok(FreeLibrary(Modules[i]), "FreeLibrary failed\n");
        if (PcToFileHeader((PBYTE)Modules[i] + 0x10) != NULL)
            Bad++;
    }
    ok(Bad == 0, "%lu unloaded modules are still found\n", Bad);

    /* Few modules again: addresses in no module are answered without the loader lock again */
    ok(LookupWithoutLoaderLock(), "The lookup waits for the loader lock after the many modules are gone\n");

    for (i = 0; i < Loaded; i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%smrt_%lu_%03lu.dll", TempDir, GetCurrentProcessId(), i);
        DeleteFileW(Path);
    }
}

/* Exceptions raised on several threads while another thread loads and unloads modules */
static volatile LONG Stop, Raised, Wrong;
static PVOID NtdllBase;

static LONG NTAPI RaiseHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode != RAISE_CODE)
        return EXCEPTION_CONTINUE_SEARCH;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI RaiserThread(PVOID Parameter)
{
    PVOID Base, Local;

    while (!Stop)
    {
        RaiseException(RAISE_CODE, 0, 0, NULL);
        InterlockedIncrement(&Raised);

        /* The modules that stay loaded are always found, no matter what the table is doing, the addresses in no
           module never */
        if ((RtlPcToFileHeader(RtlPcToFileHeader, &Base) != NtdllBase) || (Base != NtdllBase))
            InterlockedIncrement(&Wrong);
        if (RtlPcToFileHeader(&Local, &Base) != NULL)
            InterlockedIncrement(&Wrong);
    }
    return 0;
}

static DWORD WINAPI LoaderThread(PVOID Parameter)
{
    WCHAR Path[8][MAX_PATH];
    HMODULE Module;
    PVOID Base;
    ULONG i, Round = 0;

    for (i = 0; i < 8; i++)
    {
        StringCchPrintfW(Path[i], MAX_PATH, L"%smrt_%lu_c%lu.dll", TempDir, GetCurrentProcessId(), i);
        if (!ExtractDll(EMPTY_DLL_ID, Path[i]))
            return 1;
    }

    while (!Stop)
    {
        for (i = 0; i < 8; i++)
        {
            Module = LoadLibraryW(Path[i]);
            if (!Module)
            {
                InterlockedIncrement(&Wrong);
                continue;
            }
            if (RtlPcToFileHeader((PBYTE)Module + 0x10, &Base) != Module)
                InterlockedIncrement(&Wrong);
            FreeLibrary(Module);
        }
        Round++;
    }

    for (i = 0; i < 8; i++)
        DeleteFileW(Path[i]);
    return Round ? 0 : 2;
}

static void TestConcurrent(void)
{
    HANDLE Threads[5], Handler;
    DWORD ExitCode;
    ULONG i;

    NtdllBase = GetModuleHandleW(L"ntdll.dll");
    Handler = RtlAddVectoredExceptionHandler(TRUE, RaiseHandler);
    ok(Handler != NULL, "RtlAddVectoredExceptionHandler failed\n");
    if (!Handler)
        return;

    for (i = 0; i < 4; i++)
        Threads[i] = CreateThread(NULL, 0, RaiserThread, NULL, 0, NULL);
    Threads[4] = CreateThread(NULL, 0, LoaderThread, NULL, 0, NULL);

    Sleep(3000);
    InterlockedExchange(&Stop, 1);
    for (i = 0; i < 5; i++)
    {
        ok(Threads[i] != NULL, "CreateThread failed\n");
        if (!Threads[i])
            continue;
        ok(WaitForSingleObject(Threads[i], 30000) == WAIT_OBJECT_0, "Thread %lu did not finish\n", i);
        if (i == 4 && GetExitCodeThread(Threads[i], &ExitCode))
            ok(ExitCode == 0, "The loader thread failed: %lu\n", ExitCode);
        CloseHandle(Threads[i]);
    }

    ok(RtlRemoveVectoredExceptionHandler(Handler) != 0, "Remove failed\n");
    ok(Wrong == 0, "%ld wrong answers\n", Wrong);
    ok(Raised > 100, "Only %ld exceptions\n", Raised);
    trace("%ld exceptions, %ld wrong\n", Raised, Wrong);
}

START_TEST(ModuleRangeTable)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    GetTempPathW(_countof(TempDir), TempDir);

    if (!FindResourceW(NULL, MAKEINTRESOURCEW(EMPTY_DLL_ID), (PCWSTR)RT_RCDATA))
    {
        skip("empty_dll.dll is not embedded\n");
        return;
    }

    TestBasics();
    TestReloadOtherSize();
    TestManyModules();
    TestConcurrent();
}
