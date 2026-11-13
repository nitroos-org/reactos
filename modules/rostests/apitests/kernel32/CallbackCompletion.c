/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the *WhenCallbackReturns functions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#if DLL_EXPORT_VERSION >= 0x600 /* uses NT6 exports */

typedef struct
{
    PTP_CALLBACK_INSTANCE Instance;
    HMODULE Library;
    HANDLE Event, Mutex, Semaphore;
    CRITICAL_SECTION Section;
    HANDLE Done;
    BOOL EventSetEarly, SemaphoreEarly, SectionOwnedInCallback;
} CONTEXT_DATA;

static VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work)
{
    CONTEXT_DATA *Data = Context;

    EnterCriticalSection(&Data->Section);
    Data->SectionOwnedInCallback = TRUE;
    LeaveCriticalSectionWhenCallbackReturns(Instance, &Data->Section);

    /* the actions wait for the callback to return */
    WaitForSingleObject(Data->Mutex, 0);
    ReleaseMutexWhenCallbackReturns(Instance, Data->Mutex);
    SetEventWhenCallbackReturns(Instance, Data->Event);
    ReleaseSemaphoreWhenCallbackReturns(Instance, Data->Semaphore, 1);
    Data->EventSetEarly = WaitForSingleObject(Data->Event, 0) == WAIT_OBJECT_0;
    Data->SemaphoreEarly = WaitForSingleObject(Data->Semaphore, 0) == WAIT_OBJECT_0;
    /* TRUE when another pool thread can take over, FALSE when the pool has none to spare: both are fine */
    CallbackMayRunLong(Instance);

    if (Data->Library)
        FreeLibraryWhenCallbackReturns(Instance, Data->Library);
}

START_TEST(CallbackCompletion)
{
    CONTEXT_DATA Data;
    PTP_WORK Work;
    HMODULE Probe;
    DWORD Wait;

    if (!GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibraryWhenCallbackReturns"))
    {
        ok(!is_reactos(), "FreeLibraryWhenCallbackReturns is not exported by kernel32.dll\n");
        skip("the threadpool callback functions are not available\n");
        return;
    }

    ZeroMemory(&Data, sizeof(Data));
    InitializeCriticalSection(&Data.Section);
    Data.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    Data.Mutex = CreateMutexW(NULL, FALSE, NULL);
    Data.Semaphore = CreateSemaphoreW(NULL, 0, 4, NULL);

    /* a library nothing else keeps: lz32.dll, one reference */
    Probe = GetModuleHandleW(L"lz32.dll");
    if (!Probe)
        Data.Library = LoadLibraryW(L"lz32.dll");
    ok(Probe || Data.Library, "LoadLibrary failed with %lu\n", GetLastError());

    Work = CreateThreadpoolWork(WorkCallback, &Data, NULL);
    ok(Work != NULL, "CreateThreadpoolWork failed with %lu\n", GetLastError());
    if (!Work)
        return;
    SubmitThreadpoolWork(Work);
    WaitForThreadpoolWorkCallbacks(Work, FALSE);
    CloseThreadpoolWork(Work);

    ok(Data.SectionOwnedInCallback, "the callback did not run\n");
    ok(!Data.EventSetEarly, "the event was set before the callback returned\n");
    ok(!Data.SemaphoreEarly, "the semaphore was released before the callback returned\n");
    Wait = WaitForSingleObject(Data.Event, 5000);
    ok(Wait == WAIT_OBJECT_0, "the event was not set after the callback returned: %lu\n", Wait);
    Wait = WaitForSingleObject(Data.Semaphore, 5000);
    ok(Wait == WAIT_OBJECT_0, "the semaphore was not released after the callback returned: %lu\n", Wait);

    /* the critical section was left (this thread can take it) and the mutex released by the pool thread */
    ok(TryEnterCriticalSection(&Data.Section), "the critical section is still held\n");
    LeaveCriticalSection(&Data.Section);
    Wait = WaitForSingleObject(Data.Mutex, 0);
    ok(Wait == WAIT_OBJECT_0, "the mutex is still owned: %lu\n", Wait);
    ReleaseMutex(Data.Mutex);

    if (Data.Library)
    {
        /* the callback's reference to the library was dropped when it returned */
        ok(GetModuleHandleW(L"lz32.dll") == NULL, "lz32.dll is still loaded\n");
    }
}

#else

START_TEST(CallbackCompletion)
{
    skip("CallbackCompletion needs the NT6 exports\n");
}

#endif
