/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for IoWMISetNotificationCallback
 *              (semantics from the public WDK documentation)
 */

#include <kmt_test.h>
#include <wmistr.h>

/* a GUID of our own, no real data block */
static const GUID KmtWmiEventGuid =
    { 0x2b0e0a10, 0x8a52, 0x4b6c, { 0x9d, 0x3e, 0x6f, 0x11, 0x42, 0x07, 0xaa, 0x01 } };

static LONG CallbackCount;
static PVOID LastContext;
static GUID LastGuid;
static ULONG LastBufferSize;

static
VOID
NTAPI
WmiCallback(
    _In_ PVOID Wnode,
    _In_ PVOID Context)
{
    PWNODE_HEADER Header = Wnode;

    LastContext = Context;
    LastGuid = Header->Guid;
    LastBufferSize = Header->BufferSize;
    InterlockedIncrement(&CallbackCount);
}

static
VOID
WriteEvent(
    _In_ const GUID *Guid,
    _In_ ULONG ExpectedCalls)
{
    PWNODE_HEADER Event;
    NTSTATUS Status;
    LONG Before = CallbackCount;

    Event = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Event), 'tmWK');
    ok(Event != NULL, "no memory\n");
    if (Event != NULL)
    {
        RtlZeroMemory(Event, sizeof(*Event));
        Event->BufferSize = sizeof(*Event);
        Event->Guid = *Guid;
        Event->Flags = WNODE_FLAG_EVENT_ITEM;
        /* IoWMIWriteEvent takes ownership of the buffer */
        Status = IoWMIWriteEvent(Event);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ok_eq_long(CallbackCount - Before, (LONG)ExpectedCalls);
    }
}

START_TEST(IoWMINotification)
{
    NTSTATUS Status;
    PVOID Block, Block2;
    GUID OtherGuid = KmtWmiEventGuid;
    PVOID Context = (PVOID)(ULONG_PTR)0x1234;

    OtherGuid.Data1++;

    Status = IoWMIOpenBlock((LPGUID)&KmtWmiEventGuid, WMIGUID_NOTIFICATION, &Block);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    /* no callback registered yet */
    WriteEvent(&KmtWmiEventGuid, 0);

    Status = IoWMISetNotificationCallback(Block, WmiCallback, Context);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /* an event of the registered GUID is delivered once, with our context */
    WriteEvent(&KmtWmiEventGuid, 1);
    ok_eq_pointer(LastContext, Context);
    ok(IsEqualGUID(&LastGuid, &KmtWmiEventGuid), "wrong GUID delivered\n");
    ok_eq_ulong(LastBufferSize, (ULONG)sizeof(WNODE_HEADER));

    /* an event of another GUID is not */
    WriteEvent(&OtherGuid, 0);

    /* a second block for the same GUID receives it too */
    Status = IoWMIOpenBlock((LPGUID)&KmtWmiEventGuid, WMIGUID_NOTIFICATION, &Block2);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        Status = IoWMISetNotificationCallback(Block2, WmiCallback, Context);
        ok_eq_hex(Status, STATUS_SUCCESS);
        WriteEvent(&KmtWmiEventGuid, 2);

        /* removing one leaves the other */
        Status = IoWMISetNotificationCallback(Block2, NULL, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        WriteEvent(&KmtWmiEventGuid, 1);

        /* dropping the object of a registered callback unregisters it */
        Status = IoWMISetNotificationCallback(Block2, WmiCallback, Context);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ObDereferenceObject(Block2);
        WriteEvent(&KmtWmiEventGuid, 1);
    }

    /* removal */
    Status = IoWMISetNotificationCallback(Block, NULL, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    WriteEvent(&KmtWmiEventGuid, 0);

    /* parameter checks */
    Status = IoWMISetNotificationCallback(NULL, WmiCallback, Context);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);

    ObDereferenceObject(Block);
}
