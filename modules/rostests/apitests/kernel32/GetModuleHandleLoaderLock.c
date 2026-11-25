/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     GetModuleHandle(Ex) does not wait for the loader lock
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on a Windows Server 2022 (10.0.20348) with the same logic: while another thread holds the loader
 * lock, every variant below returns at once (the control that asks for the lock itself waits). Windows 10 was
 * not measured. A program that calls these with one of its own locks held deadlocks against a thread that holds
 * the loader lock in a DLL entry point and needs that lock (Firefox at shutdown): the variants that still wait
 * here are todo.
 */

#include "precomp.h"
#include <ndk/ldrfuncs.h>

#define HOLD_MS         2000
#define FAST_MS         500     /* "at once": far below the time the lock is held */

typedef enum _CASE_KIND
{
    ByNameW,
    ByNameExUnchanged,
    ByAddressExUnchangedW,
    ByAddressExUnchangedA,
    ByAddressExCounted,
    ByNameExCounted,
    LoaderLockItself,
    ByNameA,
    ByNameExUnchangedA,
    ByNameMissing
} CASE_KIND;

static PVOID CallerThread_Address(void);

static
BOOL
CallVariant(CASE_KIND Variant)
{
    HMODULE Module = NULL;
    BOOL Result = FALSE;

    switch (Variant)
    {
        case ByNameW:
            Module = GetModuleHandleW(L"kernel32.dll");
            Result = (Module != NULL);
            break;
        case ByNameA:
            Module = GetModuleHandleA("kernel32");
            Result = (Module != NULL);
            break;
        case ByNameMissing:
            SetLastError(0xdeadbeef);
            Module = GetModuleHandleW(L"gmh_no_such_module.dll");
            Result = (Module == NULL) && (GetLastError() == ERROR_MOD_NOT_FOUND);
            break;
        case ByNameExUnchanged:
            Result = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"kernel32.dll", &Module);
            break;
        case ByNameExUnchangedA:
            Result = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "ntdll.dll", &Module);
            break;
        case ByAddressExUnchangedW:
            Result = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        (LPCWSTR)CallerThread_Address(), &Module);
            break;
        case ByAddressExUnchangedA:
            Result = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        (LPCSTR)CallerThread_Address(), &Module);
            break;
        case ByAddressExCounted:
            /* The reference is not given back: FreeLibrary takes the loader lock */
            Result = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)CallerThread_Address(), &Module);
            break;
        case ByNameExCounted:
            Result = GetModuleHandleExW(0, L"kernel32.dll", &Module);
            break;
        case LoaderLockItself:
        {
            ULONG_PTR Cookie = 0;
            ULONG Disposition = 0;

            Result = NT_SUCCESS(LdrLockLoaderLock(0, &Disposition, &Cookie));
            if (Result)
                LdrUnlockLoaderLock(0, Cookie);
            break;
        }
    }
    return Result;
}

static HANDLE g_Held, g_Go;

static
DWORD
WINAPI
HolderThread(LPVOID Parameter)
{
    ULONG_PTR Cookie = 0;
    ULONG Disposition = 0;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Parameter);
    Status = LdrLockLoaderLock(0, &Disposition, &Cookie);
    if (!NT_SUCCESS(Status))
        return 1;
    SetEvent(g_Held);
    Sleep(HOLD_MS);
    LdrUnlockLoaderLock(0, Cookie);
    return 0;
}

typedef struct _CALL
{
    CASE_KIND Variant;
    DWORD Elapsed;
    BOOL Result;
} CALL, *PCALL;

static
DWORD
WINAPI
CallerThread(LPVOID Parameter)
{
    PCALL Call = Parameter;
    DWORD Start;

    /* The thread exists before the lock is taken: a new thread waits for the loader lock itself */
    WaitForSingleObject(g_Go, 10000);
    Start = GetTickCount();
    Call->Result = CallVariant(Call->Variant);
    Call->Elapsed = GetTickCount() - Start;
    return 0;
}

static PVOID CallerThread_Address(void)
{
    return (PVOID)CallerThread;
}

/* Loads gmhblock_dll.dll, whose entry point blocks (the loader lock held) until it is let go */
static HMODULE g_Blocking;

static
DWORD
WINAPI
LoaderThread(LPVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    g_Blocking = LoadLibraryW(L"gmhblock_dll.dll");
    return 0;
}

typedef struct _RELEASER
{
    HANDLE Ready, Entered, Release;
} RELEASER;

/* Lets the entry point go HOLD_MS after it entered. It runs before the entry point blocks: a thread that starts
   while the loader lock is held waits for it itself */
static
DWORD
WINAPI
ReleaseLater(LPVOID Parameter)
{
    RELEASER *Releaser = Parameter;

    SetEvent(Releaser->Ready);
    if (WaitForSingleObject(Releaser->Entered, 10000) == WAIT_OBJECT_0)
        Sleep(HOLD_MS);
    SetEvent(Releaser->Release);
    return 0;
}

/* The time a variant takes while another thread is in a DLL entry point that blocks (for HOLD_MS at most) */
static
DWORD
TimeWhileEntryPointBlocks(CASE_KIND Variant, PBOOL Result)
{
    WCHAR EnteredName[64], ReleaseName[64];
    HANDLE Entered, Release, Loader = NULL, Releaser = NULL;
    RELEASER Context;
    DWORD Start, Elapsed = (DWORD)-1;

    *Result = FALSE;
    StringCchPrintfW(EnteredName, _countof(EnteredName), L"GmhEntered.%lu", GetCurrentProcessId());
    StringCchPrintfW(ReleaseName, _countof(ReleaseName), L"GmhRelease.%lu", GetCurrentProcessId());
    Entered = CreateEventW(NULL, TRUE, FALSE, EnteredName);
    Release = CreateEventW(NULL, TRUE, FALSE, ReleaseName);
    Context.Ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    Context.Entered = Entered;
    Context.Release = Release;
    g_Blocking = NULL;

    /* The entry point goes on after HOLD_MS whatever happens here (the loader lock waits of the base) */
    if (Entered && Release && Context.Ready)
    {
        Releaser = CreateThread(NULL, 0, ReleaseLater, &Context, 0, NULL);
        if (Releaser && WaitForSingleObject(Context.Ready, 10000) == WAIT_OBJECT_0)
            Loader = CreateThread(NULL, 0, LoaderThread, NULL, 0, NULL);
    }
    if (!Loader || WaitForSingleObject(Entered, 10000) != WAIT_OBJECT_0)
    {
        skip("gmhblock_dll.dll did not enter its entry point\n");
    }
    else
    {
        Start = GetTickCount();
        *Result = CallVariant(Variant);
        Elapsed = GetTickCount() - Start;
    }
    if (Release)
        SetEvent(Release);
    if (Loader)
    {
        WaitForSingleObject(Loader, 30000);
        CloseHandle(Loader);
    }
    if (Releaser)
    {
        WaitForSingleObject(Releaser, 30000);
        CloseHandle(Releaser);
    }
    if (g_Blocking)
        FreeLibrary(g_Blocking);
    else if (Elapsed != (DWORD)-1)
        ok(0, "LoadLibraryW(gmhblock_dll.dll) failed: %lu\n", GetLastError());
    if (Entered)
        CloseHandle(Entered);
    if (Release)
        CloseHandle(Release);
    if (Context.Ready)
        CloseHandle(Context.Ready);
    return Elapsed;
}

static
VOID
TestEntryPointBlocks(VOID)
{
    static const struct
    {
        CASE_KIND Variant;
        PCSTR Name;
        BOOL Todo;
    } Rows[] =
    {
        { ByNameW,               "GetModuleHandleW(kernel32.dll)",                       FALSE },
        { ByNameA,               "GetModuleHandleA(kernel32)",                           FALSE },
        { ByNameMissing,         "GetModuleHandleW(a module that is not loaded)",        FALSE },
        { ByNameExUnchanged,     "GetModuleHandleExW(UNCHANGED_REFCOUNT, kernel32.dll)", FALSE },
        { ByNameExUnchangedA,    "GetModuleHandleExA(UNCHANGED_REFCOUNT, ntdll.dll)",    FALSE },
        { ByAddressExUnchangedW, "GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT)", FALSE },
        { ByAddressExCounted,    "GetModuleHandleExW(FROM_ADDRESS)",                     TRUE },
        { ByNameExCounted,       "GetModuleHandleExW(0, kernel32.dll)",                  TRUE },
    };
    BOOL Result;
    DWORD Elapsed;
    ULONG i;

    for (i = 0; i < _countof(Rows); i++)
    {
        Elapsed = TimeWhileEntryPointBlocks(Rows[i].Variant, &Result);
        if (Elapsed == (DWORD)-1)
            return;
        ok(Result, "%s failed while a DLL entry point blocked\n", Rows[i].Name);
        todo_if(Rows[i].Todo && is_reactos())
            ok(Elapsed < FAST_MS, "%s waited %lu ms while a DLL entry point blocked\n", Rows[i].Name, Elapsed);
    }
}

static
DWORD
TimeVariant(CASE_KIND Variant, PBOOL Result)
{
    CALL Call = { Variant, 0, FALSE };
    HANDLE Holder, Caller;

    g_Held = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_Go = CreateEventW(NULL, TRUE, FALSE, NULL);
    Caller = CreateThread(NULL, 0, CallerThread, &Call, 0, NULL);
    Sleep(300);
    Holder = CreateThread(NULL, 0, HolderThread, NULL, 0, NULL);
    if (!Caller || !Holder || WaitForSingleObject(g_Held, 5000) != WAIT_OBJECT_0)
    {
        skip("Could not set up the loader lock holder\n");
        SetEvent(g_Go);
        if (Caller) { WaitForSingleObject(Caller, 10000); CloseHandle(Caller); }
        if (Holder) { WaitForSingleObject(Holder, 10000); CloseHandle(Holder); }
        CloseHandle(g_Held);
        CloseHandle(g_Go);
        *Result = FALSE;
        return (DWORD)-1;
    }
    SetEvent(g_Go);
    WaitForSingleObject(Caller, 10000);
    WaitForSingleObject(Holder, 10000);
    CloseHandle(Caller);
    CloseHandle(Holder);
    CloseHandle(g_Held);
    CloseHandle(g_Go);
    *Result = Call.Result;
    return Call.Elapsed;
}

START_TEST(GetModuleHandleLoaderLock)
{
    BOOL Result;
    DWORD Elapsed;

    Elapsed = TimeVariant(LoaderLockItself, &Result);
    if (Elapsed == (DWORD)-1)
        return;
    ok(Result, "LdrLockLoaderLock failed\n");
    ok(Elapsed >= HOLD_MS - 600, "The control returned after %lu ms, the lock is held for %d ms\n", Elapsed, HOLD_MS);

    Elapsed = TimeVariant(ByAddressExUnchangedW, &Result);
    ok(Result, "GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT) failed\n");
    ok(Elapsed < FAST_MS, "GetModuleHandleExW(FROM_ADDRESS | UNCHANGED_REFCOUNT) waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByAddressExUnchangedA, &Result);
    ok(Result, "GetModuleHandleExA(FROM_ADDRESS | UNCHANGED_REFCOUNT) failed\n");
    ok(Elapsed < FAST_MS, "GetModuleHandleExA(FROM_ADDRESS | UNCHANGED_REFCOUNT) waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByNameW, &Result);
    ok(Result, "GetModuleHandleW failed\n");
    ok(Elapsed < FAST_MS, "GetModuleHandleW waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByNameExUnchanged, &Result);
    ok(Result, "GetModuleHandleExW(UNCHANGED_REFCOUNT) failed\n");
    ok(Elapsed < FAST_MS, "GetModuleHandleExW(UNCHANGED_REFCOUNT) waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByAddressExCounted, &Result);
    ok(Result, "GetModuleHandleExW(FROM_ADDRESS) failed\n");
    todo_if(is_reactos())
        ok(Elapsed < FAST_MS, "GetModuleHandleExW(FROM_ADDRESS) waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByNameExCounted, &Result);
    ok(Result, "GetModuleHandleExW(0) failed\n");
    todo_if(is_reactos())
        ok(Elapsed < FAST_MS, "GetModuleHandleExW(0) waited %lu ms for the loader lock\n", Elapsed);

    /* The same while another thread's DLL entry point blocks (it holds the loader lock) */
    TestEntryPointBlocks();
}
