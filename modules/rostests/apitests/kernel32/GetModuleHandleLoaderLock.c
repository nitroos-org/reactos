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
    LoaderLockItself
} CASE_KIND;

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
    HMODULE Module = NULL;
    DWORD Start;

    /* The thread exists before the lock is taken: a new thread waits for the loader lock itself */
    WaitForSingleObject(g_Go, 10000);
    Start = GetTickCount();
    switch (Call->Variant)
    {
        case ByNameW:
            Module = GetModuleHandleW(L"kernel32.dll");
            Call->Result = (Module != NULL);
            break;
        case ByNameExUnchanged:
            Call->Result = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"kernel32.dll", &Module);
            break;
        case ByAddressExUnchangedW:
            Call->Result = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                              (LPCWSTR)CallerThread, &Module);
            break;
        case ByAddressExUnchangedA:
            Call->Result = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                              (LPCSTR)CallerThread, &Module);
            break;
        case ByAddressExCounted:
            Call->Result = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)CallerThread, &Module);
            break;
        case ByNameExCounted:
            Call->Result = GetModuleHandleExW(0, L"kernel32.dll", &Module);
            break;
        case LoaderLockItself:
        {
            ULONG_PTR Cookie = 0;
            ULONG Disposition = 0;

            Call->Result = NT_SUCCESS(LdrLockLoaderLock(0, &Disposition, &Cookie));
            if (Call->Result)
                LdrUnlockLoaderLock(0, Cookie);
            break;
        }
    }
    Call->Elapsed = GetTickCount() - Start;
    return 0;
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
    todo_if(is_reactos())
        ok(Elapsed < FAST_MS, "GetModuleHandleW waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByNameExUnchanged, &Result);
    ok(Result, "GetModuleHandleExW(UNCHANGED_REFCOUNT) failed\n");
    todo_if(is_reactos())
        ok(Elapsed < FAST_MS, "GetModuleHandleExW(UNCHANGED_REFCOUNT) waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByAddressExCounted, &Result);
    ok(Result, "GetModuleHandleExW(FROM_ADDRESS) failed\n");
    todo_if(is_reactos())
        ok(Elapsed < FAST_MS, "GetModuleHandleExW(FROM_ADDRESS) waited %lu ms for the loader lock\n", Elapsed);

    Elapsed = TimeVariant(ByNameExCounted, &Result);
    ok(Result, "GetModuleHandleExW(0) failed\n");
    todo_if(is_reactos())
        ok(Elapsed < FAST_MS, "GetModuleHandleExW(0) waited %lu ms for the loader lock\n", Elapsed);
}
