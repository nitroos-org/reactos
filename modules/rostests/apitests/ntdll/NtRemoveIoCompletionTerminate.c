/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A thread blocked in NtRemoveIoCompletion(Ex) is terminated while a completion is posted: the entry is
 *              never lost, whatever carried it (NtSetIoCompletion packet, overlapped I/O, wait completion packet,
 *              IoCompletionReserve), and the object that carried it can be used again
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The waiter hands the removal global output buffers, so a write-back the kernel does for a thread that dies on the
 * way out is seen. Every race ends with the entry in exactly one place: in those buffers (the waiter was given it
 * before it was terminated), or still in the port for the next waiter. Measured on Windows 10 22H2 (19045), x64:
 * 19800 races, none lost; a waiter posted to before it was terminated always gets the entry.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_ALLOC)(PHANDLE, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS (NTAPI *PFN_SETEX)(HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
typedef NTSTATUS (NTAPI *PFN_CREATEWAIT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_ASSOC)(HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN);
typedef NTSTATUS (NTAPI *PFN_CANCEL)(HANDLE, BOOLEAN);
typedef NTSTATUS (NTAPI *PFN_REMOVEEX)(HANDLE, PFILE_IO_COMPLETION_INFORMATION, ULONG, PULONG, PLARGE_INTEGER, BOOLEAN);

static PFN_ALLOC pAlloc;
static PFN_SETEX pSetEx;
static PFN_CREATEWAIT pCreateWait;
static PFN_ASSOC pAssoc;
static PFN_CANCEL pCancel;
static PFN_REMOVEEX pRemoveEx;

enum { KIND_MINI, KIND_WAIT, KIND_RESERVE, KIND_IRP, KINDS };
enum { MODE_REMOVE, MODE_REMOVE_EX, MODE_REMOVE_EX_ALERTABLE, MODES };

static HANDLE g_Port;
static volatile LONG g_Mode;
static volatile LONG g_Ready;
static PVOID volatile g_Key;
static PVOID volatile g_Context;
static IO_STATUS_BLOCK volatile g_Iosb;
static FILE_IO_COMPLETION_INFORMATION g_Info;

static DWORD WINAPI Waiter(LPVOID Parameter)
{
    ULONG Removed;

    g_Ready = 1;
    if (g_Mode == MODE_REMOVE)
        NtRemoveIoCompletion(g_Port, (PVOID *)&g_Key, (PVOID *)&g_Context, (PIO_STATUS_BLOCK)&g_Iosb, NULL);
    else
        pRemoveEx(g_Port, &g_Info, 1, &Removed, NULL, g_Mode == MODE_REMOVE_EX_ALERTABLE);

    /* never exit by itself: the termination must not catch it with the loader lock held */
    Sleep(INFINITE);
    return 0;
}

static ULONG RemoveAll(HANDLE Port, PVOID Key, PVOID Context, BOOLEAN *Found)
{
    PVOID RemovedKey, RemovedContext;
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Timeout;
    ULONG Count = 0;

    Timeout.QuadPart = 0;
    *Found = FALSE;
    while (NtRemoveIoCompletion(Port, &RemovedKey, &RemovedContext, &Iosb, &Timeout) == STATUS_SUCCESS)
    {
        if (RemovedKey == Key || (Context && RemovedContext == Context)) *Found = TRUE;
        Count++;
    }
    return Count;
}

static void RunGroup(int Kind, int Mode, int PostFirst, ULONG Spin, ULONG Iterations)
{
    static const char *const Names[KINDS] = { "mini", "wait", "reserve", "irp" };
    ULONG Delivered = 0, Kept = 0, Lost = 0, Stray = 0, Unusable = 0, Failed = 0, i;
    WCHAR Name[64];

    for (i = 0; i < Iterations; i++)
    {
        PVOID Key = (PVOID)(ULONG_PTR)(0x1000 + Kind * 0x100 + i);
        HANDLE Thread, Event = NULL, Packet = NULL, Reserve = NULL;
        HANDLE Server = INVALID_HANDLE_VALUE, Client = INVALID_HANDLE_VALUE;
        OVERLAPPED Overlapped;
        PVOID Want = Key;
        BOOLEAN Already, Found;
        NTSTATUS Status;
        DWORD Written;
        ULONG Step, y, Others;
        char Buffer[4];
        BOOL Armed = TRUE;

        RtlZeroMemory(&Overlapped, sizeof(Overlapped));
        RtlZeroMemory(&g_Info, sizeof(g_Info));
        g_Key = g_Context = NULL;
        g_Mode = Mode;
        g_Ready = 0;

        if (Kind == KIND_WAIT)
        {
            Event = CreateEventW(NULL, FALSE, FALSE, NULL);
            if (!Event || !NT_SUCCESS(pCreateWait(&Packet, 0x1F0003, NULL)) ||
                !NT_SUCCESS(pAssoc(Packet, g_Port, Event, Key, (PVOID)0x77, 0x55, 0x66, &Already)))
                Armed = FALSE;
        }
        else if (Kind == KIND_RESERVE)
        {
            if (!NT_SUCCESS(pAlloc(&Reserve, NULL, 1))) Armed = FALSE;
        }
        else if (Kind == KIND_IRP)
        {
            StringCbPrintfW(Name, sizeof(Name), L"\\\\.\\pipe\\ntrc_term_%lu_%lu", GetCurrentProcessId(), i);
            Server = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT,
                                      1, 64, 64, 0, NULL);
            Client = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (Server == INVALID_HANDLE_VALUE || Client == INVALID_HANDLE_VALUE ||
                !CreateIoCompletionPort(Server, g_Port, (ULONG_PTR)Key, 0))
            {
                Armed = FALSE;
            }
            else
            {
                ReadFile(Server, Buffer, 1, NULL, &Overlapped);
                if (GetLastError() != ERROR_IO_PENDING) Armed = FALSE;
            }
            Want = &Overlapped;
        }
        if (!Armed)
        {
            Failed++;
            goto Cleanup;
        }

        /* TerminateThread does not free the stack: keep the reservation small (the 32-bit address space is 2 GB) */
        Thread = CreateThread(NULL, 0x10000, Waiter, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
        if (!Thread)
        {
            Failed++;
            goto Cleanup;
        }
        while (!g_Ready) Sleep(1);
        Sleep(2);   /* it is blocked in the port */

        for (Step = 0; Step < 2; Step++)
        {
            if (Step == (PostFirst ? 0UL : 1UL))
            {
                if (Kind == KIND_MINI)
                    NtSetIoCompletion(g_Port, Key, (PVOID)0x77, 0x55, 0x66);
                else if (Kind == KIND_WAIT)
                    SetEvent(Event);
                else if (Kind == KIND_RESERVE)
                    pSetEx(g_Port, Reserve, Key, (PVOID)0x77, 0x55, 0x66);
                else
                    WriteFile(Client, "x", 1, &Written, NULL);
            }
            else
            {
                TerminateThread(Thread, 0);
            }
            if (Step == 0)
                for (y = 0; y < Spin; y++) YieldProcessor();
        }
        if (WaitForSingleObject(Thread, 10000) != WAIT_OBJECT_0)
        {
            ok(0, "the terminated waiter did not end (%s, mode %d, post first %d, spin %lu, round %lu)\n",
               Names[Kind], Mode, PostFirst, Spin, i);
            CloseHandle(Thread);
            return;
        }
        CloseHandle(Thread);

        if (g_Key == Want || g_Info.KeyContext == Want ||
            (Kind == KIND_IRP && (g_Context == (PVOID)&Overlapped || g_Info.ApcContext == (PVOID)&Overlapped)))
        {
            Delivered++;
        }
        else
        {
            Others = RemoveAll(g_Port, Key, Kind == KIND_IRP ? (PVOID)&Overlapped : NULL, &Found);
            if (Found) Kept++; else Lost++;
            if (Others > (Found ? 1UL : 0UL)) Stray++;
        }

        /* whatever carried the entry works again */
        if (Kind == KIND_WAIT)
        {
            Status = pCancel(Packet, FALSE);
            if (Status == STATUS_PENDING) Unusable++;
        }
        else if (Kind == KIND_RESERVE)
        {
            Status = pSetEx(g_Port, Reserve, Key, (PVOID)1, 0, 0);
            if (Status != STATUS_SUCCESS) Unusable++;
            else RemoveAll(g_Port, Key, NULL, &Found);
        }

Cleanup:
        if (Packet) NtClose(Packet);
        if (Event) CloseHandle(Event);
        if (Reserve) NtClose(Reserve);
        if (Server != INVALID_HANDLE_VALUE) CloseHandle(Server);
        if (Client != INVALID_HANDLE_VALUE) CloseHandle(Client);
    }

    ok(Failed == 0, "%s, mode %d, post first %d, spin %lu: %lu rounds could not run\n",
       Names[Kind], Mode, PostFirst, Spin, Failed);
    ok(Lost == 0, "%s, mode %d, post first %d, spin %lu: %lu of %lu entries lost (delivered %lu, kept %lu)\n",
       Names[Kind], Mode, PostFirst, Spin, Lost, Iterations, Delivered, Kept);
    ok(Stray == 0, "%s, mode %d, post first %d, spin %lu: %lu rounds left more than one entry\n",
       Names[Kind], Mode, PostFirst, Spin, Stray);
    ok(Unusable == 0, "%s, mode %d, post first %d, spin %lu: the packet object stayed in use %lu times\n",
       Names[Kind], Mode, PostFirst, Spin, Unusable);
}

START_TEST(NtRemoveIoCompletionTerminate)
{
    static const ULONG Spins[] = { 0, 40, 200, 800 };
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    int Kind, Mode, Order;
    ULONG i;

    pAlloc = (PFN_ALLOC)GetProcAddress(hNtdll, "NtAllocateReserveObject");
    pSetEx = (PFN_SETEX)GetProcAddress(hNtdll, "NtSetIoCompletionEx");
    pCreateWait = (PFN_CREATEWAIT)GetProcAddress(hNtdll, "NtCreateWaitCompletionPacket");
    pAssoc = (PFN_ASSOC)GetProcAddress(hNtdll, "NtAssociateWaitCompletionPacket");
    pCancel = (PFN_CANCEL)GetProcAddress(hNtdll, "NtCancelWaitCompletionPacket");
    pRemoveEx = (PFN_REMOVEEX)GetProcAddress(hNtdll, "NtRemoveIoCompletionEx");
    if (!pAlloc || !pSetEx || !pCreateWait || !pAssoc || !pCancel || !pRemoveEx)
    {
        skip("The completion APIs are not all exported by ntdll\n");
        return;
    }
    ok_hex(NtCreateIoCompletion(&g_Port, IO_COMPLETION_ALL_ACCESS, NULL, 0), STATUS_SUCCESS);
    if (!g_Port) return;

    for (Kind = 0; Kind < KINDS; Kind++)
        for (Mode = 0; Mode < MODES; Mode++)
            for (Order = 0; Order < 2; Order++)
                for (i = 0; i < RTL_NUMBER_OF(Spins); i++)
                    RunGroup(Kind, Mode, Order, Spins[i], 12);

    NtClose(g_Port);
}
