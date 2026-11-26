/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for NotifyAddrChange and CancelIPChangeNotify
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <iphlpapi.h>

#define CHANGE_TIMEOUT 15000

typedef struct _TARGET
{
    BOOL Found;
    DWORD Index;
    IPAddr Address;
    IPMask Mask;
    ULONG Nte;
} TARGET;

static BOOL FindTarget(TARGET *Target)
{
    IP_ADAPTER_INFO *Info, *Adapter;
    ULONG Size = 0;

    memset(Target, 0, sizeof(*Target));
    if (GetAdaptersInfo(NULL, &Size) != ERROR_BUFFER_OVERFLOW)
        return FALSE;
    Info = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Info)
        return FALSE;
    if (GetAdaptersInfo(Info, &Size) == NO_ERROR)
    {
        for (Adapter = Info; Adapter; Adapter = Adapter->Next)
        {
            IPAddr Address = inet_addr(Adapter->IpAddressList.IpAddress.String);
            if (Address != 0 && Address != INADDR_NONE && (Address & 0xff) != 127)
            {
                Target->Found = TRUE;
                Target->Index = Adapter->Index;
                Target->Address = Address;
                Target->Mask = inet_addr(Adapter->IpAddressList.IpMask.String);
                Target->Nte = Adapter->Index;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, Info);
    return Target->Found;
}

static BOOL AdapterHasAddress(const TARGET *Target)
{
    TARGET Now;
    return FindTarget(&Now) && Now.Index == Target->Index && Now.Address == Target->Address;
}

static void TestParameters(void)
{
    OVERLAPPED Overlapped = { 0 };
    HANDLE Handle = NULL;
    DWORD Error;
    BOOL Ret;

    if (!is_reactos())
        return;

    Error = NotifyAddrChange(&Handle, NULL);
    ok(Error == ERROR_INVALID_PARAMETER, "Handle without OVERLAPPED: %lu\n", Error);
    Error = NotifyAddrChange(NULL, &Overlapped);
    ok(Error == ERROR_INVALID_PARAMETER, "OVERLAPPED without Handle: %lu\n", Error);

    SetLastError(0xdeadbeef);
    Ret = CancelIPChangeNotify(NULL);
    ok(Ret == FALSE, "CancelIPChangeNotify(NULL) returned TRUE\n");
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "Error %lu\n", GetLastError());
}

static void TestCancel(void)
{
    OVERLAPPED Overlapped;
    HANDLE Handle = NULL, Event;
    DWORD Error, Bytes;
    BOOL Ret;

    /* no event: the file handle is what the caller waits on */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Error = NotifyAddrChange(&Handle, &Overlapped);
    ok(Error == ERROR_IO_PENDING, "NotifyAddrChange returned %lu\n", Error);
    ok(GetLastError() == ERROR_IO_PENDING, "Last error %lu\n", GetLastError());
    ok(Handle != NULL && Handle != INVALID_HANDLE_VALUE, "Handle %p\n", Handle);
    Ret = CancelIPChangeNotify(&Overlapped);
    ok(Ret == TRUE, "CancelIPChangeNotify returned FALSE\n");
    ok(WaitForSingleObject(Handle, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "Cancel did not signal the file handle\n");
    Ret = GetOverlappedResult(Handle, &Overlapped, &Bytes, FALSE);
    ok(!Ret && GetLastError() == ERROR_OPERATION_ABORTED, "Result %d, error %lu\n", Ret, GetLastError());

    /* nothing registered for this one */
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Ret = CancelIPChangeNotify(&Overlapped);
    ok(Ret == FALSE, "CancelIPChangeNotify of an unknown OVERLAPPED returned TRUE\n");

    /* with an event: cancelling signals it; the same OVERLAPPED can be registered again */
    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = Event;
    Handle = NULL;
    Error = NotifyAddrChange(&Handle, &Overlapped);
    ok(Error == ERROR_IO_PENDING, "NotifyAddrChange returned %lu\n", Error);
    ok(WaitForSingleObject(Event, 300) == WAIT_TIMEOUT, "Event signalled without a change or cancel\n");
    Ret = GetOverlappedResult(Handle, &Overlapped, &Bytes, FALSE);
    ok(!Ret && GetLastError() == ERROR_IO_INCOMPLETE, "Result %d, error %lu\n", Ret, GetLastError());
    Ret = CancelIPChangeNotify(&Overlapped);
    ok(Ret == TRUE, "CancelIPChangeNotify returned FALSE\n");
    ok(WaitForSingleObject(Event, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "Cancel did not signal the event\n");
    Ret = GetOverlappedResult(Handle, &Overlapped, &Bytes, FALSE);
    ok(!Ret && GetLastError() == ERROR_OPERATION_ABORTED, "Result %d, error %lu\n", Ret, GetLastError());

    Handle = NULL;
    Error = NotifyAddrChange(&Handle, &Overlapped);
    ok(Error == ERROR_IO_PENDING, "Second NotifyAddrChange returned %lu\n", Error);
    Ret = CancelIPChangeNotify(&Overlapped);
    ok(Ret == TRUE, "Second CancelIPChangeNotify returned FALSE\n");
    ok(WaitForSingleObject(Event, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "Second cancel did not signal the event\n");
    CloseHandle(Event);
}

/* An address change is made by removing the address of an adapter and putting it back. */
static BOOL RemoveAddress(TARGET *Target)
{
    DWORD Error = DeleteIPAddress(Target->Nte);
    ok(Error == NO_ERROR, "DeleteIPAddress returned %lu\n", Error);
    return Error == NO_ERROR;
}

static BOOL RestoreAddress(TARGET *Target)
{
    ULONG Nte = 0, Instance = 0;
    DWORD Error = AddIPAddress(Target->Address, Target->Mask, Target->Index, &Nte, &Instance);

    /* the DHCP client may have bound the address again already: that is a change as well */
    if (Error == ERROR_OBJECT_ALREADY_EXISTS && AdapterHasAddress(Target))
        return TRUE;

    ok(Error == NO_ERROR, "AddIPAddress returned %lu\n", Error);
    if (Error == NO_ERROR)
        Target->Nte = Nte;
    return Error == NO_ERROR;
}

static void TestChange(TARGET *Target)
{
    OVERLAPPED Overlapped;
    HANDLE Handle = NULL, Event;
    DWORD Error, Bytes;
    BOOL Ret;

    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ZeroMemory(&Overlapped, sizeof(Overlapped));
    Overlapped.hEvent = Event;

    /* the address goes away */
    Error = NotifyAddrChange(&Handle, &Overlapped);
    ok(Error == ERROR_IO_PENDING, "NotifyAddrChange returned %lu\n", Error);
    ok(WaitForSingleObject(Event, 200) == WAIT_TIMEOUT, "Event signalled before a change\n");
    if (RemoveAddress(Target))
    {
        ok(WaitForSingleObject(Event, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "No notification when the address was removed\n");
        Ret = GetOverlappedResult(Handle, &Overlapped, &Bytes, FALSE);
        ok(Ret == TRUE, "GetOverlappedResult failed with %lu\n", GetLastError());
    }
    else
    {
        CancelIPChangeNotify(&Overlapped);
    }

    /* a completed request is gone: nothing signals until the next registration sees a change */
    ok(WaitForSingleObject(Event, 200) == WAIT_TIMEOUT, "Event signalled again without a registration\n");
    Ret = CancelIPChangeNotify(&Overlapped);
    ok(Ret == FALSE, "CancelIPChangeNotify of a completed request returned TRUE\n");

    /* the address comes back; the OVERLAPPED is reused */
    Handle = NULL;
    Error = NotifyAddrChange(&Handle, &Overlapped);
    ok(Error == ERROR_IO_PENDING, "NotifyAddrChange returned %lu\n", Error);
    if (RestoreAddress(Target))
    {
        ok(WaitForSingleObject(Event, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "No notification when the address was added\n");
        Ret = GetOverlappedResult(Handle, &Overlapped, &Bytes, FALSE);
        ok(Ret == TRUE, "GetOverlappedResult failed with %lu\n", GetLastError());
    }
    else
    {
        CancelIPChangeNotify(&Overlapped);
    }
    ok(AdapterHasAddress(Target), "The address of adapter %lu was not restored\n", Target->Index);

    /* two waiters are both woken by one change */
    {
        OVERLAPPED Second;
        HANDLE SecondHandle = NULL, SecondEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

        ZeroMemory(&Second, sizeof(Second));
        Second.hEvent = SecondEvent;
        Handle = NULL;
        Error = NotifyAddrChange(&Handle, &Overlapped);
        ok(Error == ERROR_IO_PENDING, "First NotifyAddrChange returned %lu\n", Error);
        Error = NotifyAddrChange(&SecondHandle, &Second);
        ok(Error == ERROR_IO_PENDING, "Second NotifyAddrChange returned %lu\n", Error);
        if (RemoveAddress(Target))
        {
            ok(WaitForSingleObject(Event, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "First waiter was not woken\n");
            ok(WaitForSingleObject(SecondEvent, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "Second waiter was not woken\n");
        }
        else
        {
            CancelIPChangeNotify(&Overlapped);
            CancelIPChangeNotify(&Second);
        }
        RestoreAddress(Target);
        CloseHandle(SecondEvent);
    }
    CloseHandle(Event);
    ok(AdapterHasAddress(Target), "The address of adapter %lu was not restored\n", Target->Index);
}

typedef struct _BLOCKER
{
    HANDLE Started;
    DWORD Result;
} BLOCKER;

static DWORD WINAPI BlockingThread(PVOID Context)
{
    BLOCKER *Blocker = Context;

    SetEvent(Blocker->Started);
    Blocker->Result = NotifyAddrChange(NULL, NULL);
    return 0;
}

static void TestBlocking(TARGET *Target)
{
    BLOCKER Blocker;
    HANDLE Thread;

    Blocker.Started = CreateEventW(NULL, FALSE, FALSE, NULL);
    Blocker.Result = 0xdeadbeef;
    Thread = CreateThread(NULL, 0, BlockingThread, &Blocker, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    if (!Thread)
        return;
    WaitForSingleObject(Blocker.Started, CHANGE_TIMEOUT);
    ok(WaitForSingleObject(Thread, 500) == WAIT_TIMEOUT, "Blocking NotifyAddrChange returned without a change: %lu\n", Blocker.Result);

    if (RemoveAddress(Target))
    {
        ok(WaitForSingleObject(Thread, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "Blocking NotifyAddrChange did not return after a change\n");
        ok(Blocker.Result == NO_ERROR, "Blocking NotifyAddrChange returned %lu\n", Blocker.Result);
        RestoreAddress(Target);
    }
    else
    {
        /* free the thread with a change of any kind */
        RestoreAddress(Target);
        WaitForSingleObject(Thread, CHANGE_TIMEOUT);
    }
    CloseHandle(Thread);
    CloseHandle(Blocker.Started);
    ok(AdapterHasAddress(Target), "The address of adapter %lu was not restored\n", Target->Index);
}

/* A change is a few events of the stack (the address, its route, the DHCP client binding it again); the loop of the
   defect gave hundreds */
#define REARM_MAX_WAKES 10

typedef struct _REARM
{
    HANDLE Stop;
    HANDLE Armed;
    HANDLE Event;
    OVERLAPPED Overlapped;
    volatile LONG Wakes;
} REARM;

/* A waiter that queues its next request as soon as it is woken, at a higher priority than the thread that makes the
   change, on the same processor: it runs between the completion of its request and the end of the change. */
static DWORD WINAPI RearmThread(PVOID Context)
{
    REARM *Rearm = Context;
    HANDLE Handle, Wait[2];

    SetThreadAffinityMask(GetCurrentThread(), 1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    Wait[0] = Rearm->Stop;
    Wait[1] = Rearm->Event;
    for (;;)
    {
        Handle = NULL;
        ZeroMemory(&Rearm->Overlapped, sizeof(Rearm->Overlapped));
        Rearm->Overlapped.hEvent = Rearm->Event;
        ResetEvent(Rearm->Event);
        if (NotifyAddrChange(&Handle, &Rearm->Overlapped) != ERROR_IO_PENDING)
            break;
        SetEvent(Rearm->Armed);
        if (WaitForMultipleObjects(2, Wait, FALSE, INFINITE) == WAIT_OBJECT_0)
        {
            CancelIPChangeNotify(&Rearm->Overlapped);
            WaitForSingleObject(Rearm->Event, 5000);
            break;
        }
        InterlockedIncrement(&Rearm->Wakes);
    }
    return 0;
}

/* One change of the address table wakes a waiter once; the request that the waiter queues after it belongs to the
   next change. A request that was queued while the change was still being reported was completed as well, the waiter
   queued the next one, and the waiter ran in a loop for as long as it kept up (hundreds of wake-ups a second). */
static void TestRearm(TARGET *Target)
{
    REARM Rearm;
    HANDLE Thread;
    LONG AfterRemove, AfterRestore;
    BOOL Present;
    DWORD_PTR ProcessMask = 1, SystemMask = 1;

    GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask);
    SystemMask = ProcessMask;
    ZeroMemory(&Rearm, sizeof(Rearm));
    Rearm.Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    Rearm.Armed = CreateEventW(NULL, FALSE, FALSE, NULL);
    Rearm.Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    SetThreadAffinityMask(GetCurrentThread(), 1);
    Thread = CreateThread(NULL, 0, RearmThread, &Rearm, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    if (Thread)
    {
        ok(WaitForSingleObject(Rearm.Armed, CHANGE_TIMEOUT) == WAIT_OBJECT_0, "The waiter did not queue its request\n");
        Sleep(300);
        ok(Rearm.Wakes == 0, "%ld wake-ups without a change\n", Rearm.Wakes);

        if (RemoveAddress(Target))
        {
            Sleep(1500);
            AfterRemove = Rearm.Wakes;
            ok(AfterRemove >= 1, "No wake-up when the address was removed\n");
            ok(AfterRemove <= REARM_MAX_WAKES, "%ld wake-ups for the removal of an address\n", AfterRemove);
            /* the DHCP client may have bound the address again already: then nothing is added, and nothing wakes */
            Present = AdapterHasAddress(Target);
            RestoreAddress(Target);
            Sleep(1500);
            AfterRestore = Rearm.Wakes - AfterRemove;
            if (!Present)
                ok(AfterRestore >= 1, "No wake-up when the address was added\n");
            ok(AfterRestore <= REARM_MAX_WAKES, "%ld wake-ups for the addition of an address\n", AfterRestore);
        }
        SetEvent(Rearm.Stop);
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }
    SetThreadAffinityMask(GetCurrentThread(), SystemMask);
    CloseHandle(Rearm.Stop);
    CloseHandle(Rearm.Armed);
    CloseHandle(Rearm.Event);
    ok(AdapterHasAddress(Target), "The address of adapter %lu was not restored\n", Target->Index);
}

START_TEST(NotifyAddrChange)
{
    TARGET Target;
    int Tries;

    TestParameters();
    TestCancel();

    if (!is_reactos())
    {
        skip("Address changes are only made on ReactOS\n");
        return;
    }
    /* a DHCP lease may still be on its way in a freshly booted system */
    for (Tries = 0; Tries < 30 && !FindTarget(&Target); Tries++)
        Sleep(1000);
    if (!Target.Found)
    {
        skip("No adapter with an IPv4 address\n");
        return;
    }
    TestChange(&Target);
    TestBlocking(&Target);
    TestRearm(&Target);
}
