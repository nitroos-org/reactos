/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A thread starts in ntdll!RtlUserThreadStart, which calls kernel32's thread start (Windows'
 *              BaseThreadInitThunk), which calls the start routine: the stack a
 *              debugger or a stack walker sees
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <ndk/psfuncs.h>

#define TSF_MAX_FRAMES  64

typedef struct _TSF_RESULT
{
    USHORT Count;
    PVOID Frames[TSF_MAX_FRAMES];
} TSF_RESULT;

static
HMODULE
ModuleOf(PVOID Address)
{
    HMODULE Module = NULL;

    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            Address,
                            &Module))
        return NULL;
    return Module;
}

static
DWORD
WINAPI
CaptureProc(PVOID Parameter)
{
    TSF_RESULT *Result = Parameter;

    Result->Count = RtlCaptureStackBackTrace(0, TSF_MAX_FRAMES, Result->Frames, NULL);
    return 0x1234;
}

static
VOID
CheckStack(const TSF_RESULT *Result, PCSTR What)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    PUCHAR Thunk = (PUCHAR)GetProcAddress(Kernel32, "BaseThreadInitThunk");
    PUCHAR Start = (PUCHAR)GetProcAddress(Ntdll, "RtlUserThreadStart");
    USHORT i;
    BOOLEAN FoundThunk = FALSE;

    ok(Result->Count >= 2, "%s: %u frames\n", What, Result->Count);
    if (Result->Count < 2)
        return;

    ok(ModuleOf(Result->Frames[Result->Count - 1]) == Ntdll,
       "%s: last frame %p is not in ntdll (module %p)\n",
       What, Result->Frames[Result->Count - 1], ModuleOf(Result->Frames[Result->Count - 1]));

    ok(Start != NULL, "%s: ntdll does not export RtlUserThreadStart\n", What);
    ok(Thunk != NULL, "%s: kernel32 does not export BaseThreadInitThunk\n", What);

    for (i = 0; Thunk && i < Result->Count; i++)
    {
        if ((PUCHAR)Result->Frames[i] > Thunk && (PUCHAR)Result->Frames[i] < Thunk + 0x400)
            FoundThunk = TRUE;
    }
    ok(FoundThunk, "%s: no frame in BaseThreadInitThunk %p\n", What, Thunk);

    /* BaseThreadInitThunk is called from ntdll, the start routine from kernel32 */
    for (i = 1; Thunk && i < Result->Count; i++)
    {
        if ((PUCHAR)Result->Frames[i - 1] > Thunk && (PUCHAR)Result->Frames[i - 1] < Thunk + 0x400)
        {
            ok(ModuleOf(Result->Frames[i]) == Ntdll,
               "%s: the caller of BaseThreadInitThunk %p is not in ntdll\n", What, Result->Frames[i]);
            break;
        }
    }
}

START_TEST(ThreadStartFrame)
{
    TSF_RESULT Result;
    HANDLE Thread;
    DWORD Exit, Id;
    PVOID Win32Start = NULL;
    NTSTATUS Status;

    /* A new thread */
    memset(&Result, 0, sizeof(Result));
    Thread = CreateThread(NULL, 0, CaptureProc, &Result, 0, &Id);
    ok(Thread != NULL, "CreateThread failed %lu\n", GetLastError());
    if (!Thread)
        return;
    ok_dec(WaitForSingleObject(Thread, 10000), WAIT_OBJECT_0);
    ok(GetExitCodeThread(Thread, &Exit) && Exit == 0x1234, "exit code %lx\n", Exit);
    CheckStack(&Result, "thread");

    /* The start routine is what the thread reports as its Win32 start address */
    Status = NtQueryInformationThread(Thread, ThreadQuerySetWin32StartAddress, &Win32Start, sizeof(Win32Start), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Win32Start == (PVOID)CaptureProc, "Win32StartAddress %p, expected %p\n", Win32Start, CaptureProc);
    CloseHandle(Thread);

    /* The thread that runs the test started the same way */
    memset(&Result, 0, sizeof(Result));
    Result.Count = RtlCaptureStackBackTrace(0, TSF_MAX_FRAMES, Result.Frames, NULL);
    CheckStack(&Result, "main thread");
}
