/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtQueryWnfStateData and RtlSubscribe/UnsubscribeWnfStateChangeNotification of ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 and x86 (WOW64), identical results:
 *  - WNF_SHEL_QUIETHOURS_ACTIVE_PROFILE_CHANGED (0x0D83063EA3BF1C75): STATUS_SUCCESS, change stamp (4 on the
 *    oracle, depends on history), 4 bytes of data = 0. A buffer size of 0 to 3 gives STATUS_BUFFER_TOO_SMALL with the
 *    change stamp and BufferSize = 4 written. A NULL buffer with a size of 4, a NULL stamp or size pointer or a pointer
 *    that cannot be read or written is STATUS_ACCESS_VIOLATION and nothing is written; a NULL buffer with a size of 0
 *    is STATUS_BUFFER_TOO_SMALL. An all-zero type id is accepted, a non-NULL explicit scope is STATUS_INVALID_PARAMETER.
 *  - the state name is the 64-bit name XORed with 0x41C64E6DA3BC0074: version (4 bits, has to be 1), lifetime (2),
 *    data scope (4), permanent (1), sequence. Version not 1 and scopes 1, 3 and 9 are STATUS_INVALID_PARAMETER; a name
 *    that is valid and has no data (other sequence, tag, lifetime 1..3, scope 2 and 4) is STATUS_OBJECT_NAME_NOT_FOUND
 *    and writes nothing.
 *  - RtlSubscribeWnfStateChangeNotification(&h, name, stamp, cb, ctx, NULL, 0, 0): a name that is not valid or not known
 *    returns the status above and no handle. With a change stamp older than the current one the callback runs once, on
 *    another thread, with the current stamp, the context and the data; with the current or a newer stamp it does
 *    not run. Unsubscribe of the handle is STATUS_SUCCESS.
 * The stamp of the name is not compared: it differs between systems.
 */

#include "precomp.h"

#define SHEL_QUIETHOURS 0x0D83063EA3BF1C75ULL
#define WNF_KEY         0x41C64E6DA3BC0074ULL

typedef struct { ULONG Data[2]; } NAME;
typedef NTSTATUS (NTAPI *PFN_Query)(const NAME*, const GUID*, const void*, ULONG*, void*, ULONG*);
typedef NTSTATUS (NTAPI *PFN_Callback)(ULONGLONG, ULONG, void*, void*, const void*, ULONG);
typedef NTSTATUS (NTAPI *PFN_Sub)(void**, ULONGLONG, ULONG, PFN_Callback, void*, const GUID*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_Unsub)(void*);

static PFN_Query Query;

static NAME Mk(ULONGLONG Name)
{
    NAME n;
    n.Data[0] = (ULONG)Name;
    n.Data[1] = (ULONG)(Name >> 32);
    return n;
}

static ULONGLONG Name_(ULONGLONG Internal)
{
    return Internal ^ WNF_KEY;
}

static void Expect(const char *Tag, ULONGLONG Name, NTSTATUS Expected)
{
    NAME n = Mk(Name);
    ULONG Stamp = 0xDEADBEEF, Size = 64;
    UCHAR Buffer[64];
    NTSTATUS Status;

    memset(Buffer, 0xCC, sizeof(Buffer));
    Status = Query(&n, NULL, NULL, &Stamp, Buffer, &Size);
    ok_hex(Status, Expected);
    if (Expected != STATUS_SUCCESS)
    {
        if (Status == Expected)
        {
            ok(Stamp == 0xDEADBEEF, "%s: stamp written (%lx)\n", Tag, Stamp);
            ok(Size == 64, "%s: size written (%lu)\n", Tag, Size);
            ok(Buffer[0] == 0xCC, "%s: buffer written\n", Tag);
        }
    }
}

static void Test_Quiet(void)
{
    NAME n = Mk(SHEL_QUIETHOURS);
    ULONG Stamp, Size, Size2;
    UCHAR Buffer[64];
    NTSTATUS Status;
    ULONG Stamp1;
    GUID Type;
    ULONG Scope = 0;

    memset(Buffer, 0xCC, sizeof(Buffer));
    Stamp = 0xDEADBEEF; Size = 4;
    Status = Query(&n, NULL, NULL, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Stamp != 0 && Stamp != 0xDEADBEEF, "stamp %lx\n", Stamp);
    Stamp1 = Stamp;
    ok_dec(Size, 4);
    ok(*(ULONG *)Buffer == 0, "data %08lx\n", *(ULONG *)Buffer);
    ok(Buffer[4] == 0xCC, "wrote past the data\n");

    memset(Buffer, 0xCC, sizeof(Buffer));
    Stamp = 0xDEADBEEF; Size = 64;
    Status = Query(&n, NULL, NULL, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Size, 4);
    ok(Stamp == Stamp1, "stamp changed %lx %lx\n", Stamp, Stamp1);
    ok(Buffer[4] == 0xCC, "wrote past the data\n");

    /* too small: stamp and size are written */
    for (Size2 = 0; Size2 < 4; Size2++)
    {
        memset(Buffer, 0xCC, sizeof(Buffer));
        Stamp = 0xDEADBEEF; Size = Size2;
        Status = Query(&n, NULL, NULL, &Stamp, Buffer, &Size);
        ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
        ok_dec(Size, 4);
        ok(Stamp == Stamp1, "stamp %lx\n", Stamp);
        ok(Buffer[0] == 0xCC, "buffer written\n");
    }
    Stamp = 0xDEADBEEF; Size = 0;
    Status = Query(&n, NULL, NULL, &Stamp, NULL, &Size);
    ok_hex(Status, STATUS_BUFFER_TOO_SMALL);
    ok_dec(Size, 4);

    /* larger buffer */
    Stamp = 0xDEADBEEF; Size = 8;
    memset(Buffer, 0xCC, sizeof(Buffer));
    Status = Query(&n, NULL, NULL, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Size, 4);
    ok(Buffer[4] == 0xCC, "wrote past the data\n");

    /* pointers */
    Stamp = 0xDEADBEEF; Size = 4;
    Status = Query(&n, NULL, NULL, &Stamp, NULL, &Size);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    ok(Stamp == 0xDEADBEEF, "stamp written %lx\n", Stamp);
    ok_dec(Size, 4);
    Size = 4;
    Status = Query(&n, NULL, NULL, NULL, Buffer, &Size);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = Query(&n, NULL, NULL, &Stamp, Buffer, NULL);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Size = 4;
    Status = Query((NAME *)(ULONG_PTR)1, NULL, NULL, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = Query(&n, NULL, NULL, (ULONG *)(ULONG_PTR)1, Buffer, &Size);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = Query(&n, NULL, NULL, &Stamp, (void *)(ULONG_PTR)1, &Size);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = Query(&n, NULL, NULL, &Stamp, Buffer, (ULONG *)(ULONG_PTR)1);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = Query(&n, (const GUID *)(ULONG_PTR)1, NULL, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    Status = Query(&n, NULL, NULL, &Stamp, (void *)(ULONG_PTR)0x80000000, &Size);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    /* type id and explicit scope */
    memset(&Type, 0, sizeof(Type));
    Size = 4;
    Status = Query(&n, &Type, NULL, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_SUCCESS);
    Size = 4; Stamp = 0xDEADBEEF;
    Status = Query(&n, NULL, &Scope, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok(Stamp == 0xDEADBEEF, "stamp written\n");
    Status = Query(&n, NULL, (void *)(ULONG_PTR)1, &Stamp, Buffer, &Size);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
}

static void Test_Names(void)
{
    ULONGLONG In = SHEL_QUIETHOURS ^ WNF_KEY;

    Expect("seq+1", Name_(In + 0x800), STATUS_OBJECT_NAME_NOT_FOUND);
    Expect("tag", Name_(In ^ 0x100000000ULL), STATUS_OBJECT_NAME_NOT_FOUND);
    Expect("scope 2", Name_((In & ~(0xFULL << 6)) | (2ULL << 6)), STATUS_OBJECT_NAME_NOT_FOUND);
    Expect("scope 4", Name_((In & ~(0xFULL << 6)) | (4ULL << 6)), STATUS_OBJECT_NAME_NOT_FOUND);
    Expect("scope 1", Name_((In & ~(0xFULL << 6)) | (1ULL << 6)), STATUS_INVALID_PARAMETER);
    Expect("scope 3", Name_((In & ~(0xFULL << 6)) | (3ULL << 6)), STATUS_INVALID_PARAMETER);
    Expect("scope 9", Name_((In & ~(0xFULL << 6)) | (9ULL << 6)), STATUS_INVALID_PARAMETER);
    Expect("life 1", Name_((In & ~(3ULL << 4)) | (1ULL << 4)), STATUS_OBJECT_NAME_NOT_FOUND);
    Expect("life 2", Name_((In & ~(3ULL << 4)) | (2ULL << 4)), STATUS_OBJECT_NAME_NOT_FOUND);
    Expect("life 3", Name_((In & ~(3ULL << 4)) | (3ULL << 4)), STATUS_OBJECT_NAME_NOT_FOUND);
    Expect("version 2", Name_((In & ~0xFULL) | 2ULL), STATUS_INVALID_PARAMETER);
    Expect("version 0", Name_((In & ~0xFULL) | 0ULL), STATUS_INVALID_PARAMETER);
    Expect("zero", 0, STATUS_INVALID_PARAMETER);
    Expect("ones", ~0ULL, STATUS_INVALID_PARAMETER);
    Expect("0x1234", 0x1234, STATUS_INVALID_PARAMETER);
}

static volatile LONG Hits;
static ULONG LastStamp, LastSize;
static ULONGLONG LastName;
static void *LastContext;
static ULONG LastData;
static DWORD LastThread;
static HANDLE Event;

static NTSTATUS NTAPI Callback(ULONGLONG Name, ULONG Stamp, void *Type, void *Context, const void *Buffer, ULONG Size)
{
    LastName = Name;
    LastStamp = Stamp;
    LastSize = Size;
    LastContext = Context;
    LastData = Size >= 4 ? *(const ULONG *)Buffer : 0xFFFFFFFF;
    LastThread = GetCurrentThreadId();
    InterlockedIncrement(&Hits);
    SetEvent(Event);
    return STATUS_SUCCESS;
}

static void Test_Subscribe(HMODULE Ntdll)
{
    PFN_Sub Subscribe = (PFN_Sub)GetProcAddress(Ntdll, "RtlSubscribeWnfStateChangeNotification");
    PFN_Unsub Unsubscribe = (PFN_Unsub)GetProcAddress(Ntdll, "RtlUnsubscribeWnfStateChangeNotification");
    NAME n = Mk(SHEL_QUIETHOURS);
    ULONG Current = 0, Size = 4, Data, i;
    ULONG Stamps[3];
    NTSTATUS Status;
    void *Handle;
    ULONGLONG In = SHEL_QUIETHOURS ^ WNF_KEY;

    if (!Subscribe || !Unsubscribe)
    {
        skip("no subscription functions\n");
        return;
    }
    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    Status = Query(&n, NULL, NULL, &Current, &Data, &Size);
    ok_hex(Status, STATUS_SUCCESS);

    /* older stamps (including a wrapped one): one callback on another thread */
    Stamps[0] = Current - 1;
    Stamps[1] = Current - 2;
    Stamps[2] = 0xFFFFFFFF;
    for (i = 0; i < 3; i++)
    {
        if (Stamps[i] == Current)
            continue;
        Hits = 0; LastThread = 0; Handle = (void *)(ULONG_PTR)0x77;
        Status = Subscribe(&Handle, SHEL_QUIETHOURS, Stamps[i], Callback, (void *)(ULONG_PTR)0xABCD, NULL, 0, 0);
        ok_hex(Status, STATUS_SUCCESS);
        ok(Handle != NULL && Handle != (void *)(ULONG_PTR)0x77, "handle %p\n", Handle);
        ok(WaitForSingleObject(Event, 3000) == WAIT_OBJECT_0, "no callback for stamp %lx\n", Stamps[i]);
        Sleep(200);
        ok_dec(Hits, 1);
        ok(LastName == SHEL_QUIETHOURS, "name %I64x\n", LastName);
        ok(LastStamp == Current, "stamp %lx, current %lx\n", LastStamp, Current);
        ok_dec(LastSize, 4);
        ok(LastData == 0, "data %lx\n", LastData);
        ok(LastContext == (void *)(ULONG_PTR)0xABCD, "context %p\n", LastContext);
        ok(LastThread != GetCurrentThreadId(), "callback ran on the calling thread\n");
        Status = Unsubscribe(Handle);
        ok_hex(Status, STATUS_SUCCESS);
    }

    /* the current stamp or a newer one: no callback */
    Hits = 0; Handle = NULL;
    Status = Subscribe(&Handle, SHEL_QUIETHOURS, Current, Callback, NULL, NULL, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Sleep(500);
    ok_dec(Hits, 0);
    if (Handle) Unsubscribe(Handle);
    Handle = NULL;
    Status = Subscribe(&Handle, SHEL_QUIETHOURS, Current + 1, Callback, NULL, NULL, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Sleep(500);
    ok_dec(Hits, 0);
    if (Handle) Unsubscribe(Handle);

    /* names that cannot be subscribed to: status of the lookup, no handle */
    Handle = NULL;
    Status = Subscribe(&Handle, Name_(In + 0x800), 0, Callback, NULL, NULL, 0, 0);
    ok_hex(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    ok(Handle == NULL, "handle %p\n", Handle);
    Status = Subscribe(&Handle, 0x1234, 0, Callback, NULL, NULL, 0, 0);
    ok_hex(Status, STATUS_INVALID_PARAMETER);
    ok(Handle == NULL, "handle %p\n", Handle);
    Status = Subscribe(&Handle, Name_((In & ~(3ULL << 4)) | (1ULL << 4)), 0, Callback, NULL, NULL, 0, 0);
    ok_hex(Status, STATUS_OBJECT_NAME_NOT_FOUND);
    ok(Handle == NULL, "handle %p\n", Handle);

    /* a NULL callback is accepted */
    Status = Subscribe(&Handle, SHEL_QUIETHOURS, 0, NULL, NULL, NULL, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    ok(Handle != NULL, "no handle\n");
    if (Handle) Unsubscribe(Handle);
    CloseHandle(Event);
}

START_TEST(NtQueryWnfStateData)
{
    HMODULE Ntdll = GetModuleHandleA("ntdll.dll");

    Query = (PFN_Query)GetProcAddress(Ntdll, "NtQueryWnfStateData");
    if (!Query)
    {
        skip("NtQueryWnfStateData is not exported\n");
        return;
    }
    ok(GetProcAddress(Ntdll, "ZwQueryWnfStateData") != NULL, "ZwQueryWnfStateData is not exported\n");

    Test_Quiet();
    Test_Names();
    Test_Subscribe(Ntdll);
}
