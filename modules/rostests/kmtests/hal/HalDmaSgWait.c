/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite test for scatter/gather requests that wait for map registers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A 32-bit PCI scatter/gather bus master on a system with memory above 4 GB takes its map registers
 * from a master adapter of the HAL. A request that finds none waits, and the callback of
 * HalGetScatterGatherList is its only sign of life. This test checks that the wait always ends:
 *  - the registers are all held, and one request waits: it is served when one of the holders is done
 *    (no fault needed, the registers run out at the master adapter's limit)
 *  - checked HAL only (Services\HalDmaFault\FailMask): the map buffers cannot grow for a request that
 *    needs more registers than the master adapter has, so no register will ever be free. The HAL
 *    must call the routine back without a list instead of leaving the request, and everything
 *    behind it, queued forever
 *  - afterwards nothing is stuck and no map register is lost
 */

#include <kmt_test.h>

#define TEST_PAGES      20
#define OFFSET          256
/* A transfer that does not start on a page spans one page more */
#define SPAN(Pages)     ((Pages) + 1)
#define FAULT_KEY       L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\HalDmaFault"

#define FAULT_GROW_FAILS    1
#define FAULT_NO_WORK_ITEM  2
#define FAULT_NO_PREGROW    4

/* Requests live in nonpaged pool: one that never completes cannot be left on this stack */
typedef struct _SG_REQUEST
{
    KEVENT Event;
    volatile LONG Called;
    PSCATTER_GATHER_LIST List;
    PUCHAR Buffer;
    PMDL Mdl;
    ULONG Length;
} SG_REQUEST, *PSG_REQUEST;

static DRIVER_LIST_CONTROL ListControl;
static
VOID
NTAPI
ListControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PSCATTER_GATHER_LIST ScatterGather,
    _In_ PVOID Context)
{
    PSG_REQUEST Request = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    Request->List = ScatterGather;
    InterlockedExchange(&Request->Called, 1);
    KeSetEvent(&Request->Event, IO_NO_INCREMENT, FALSE);
}

static
BOOLEAN
MemoryAbove4Gb(VOID)
{
    PPHYSICAL_MEMORY_RANGE Ranges;
    BOOLEAN Above = FALSE;
    ULONG i;

    Ranges = MmGetPhysicalMemoryRanges();
    if (!Ranges)
        return FALSE;
    for (i = 0; Ranges[i].NumberOfBytes.QuadPart != 0; i++)
    {
        if ((ULONGLONG)(Ranges[i].BaseAddress.QuadPart +
                        Ranges[i].NumberOfBytes.QuadPart) > 0x100000000ULL)
        {
            Above = TRUE;
        }
    }
    ExFreePool(Ranges);
    return Above;
}

static
PDMA_ADAPTER
GetAdapter(
    _In_ ULONG Pages,
    _Out_ PULONG MapRegisters)
{
    DEVICE_DESCRIPTION Description;

    RtlZeroMemory(&Description, sizeof(Description));
    Description.Version = DEVICE_DESCRIPTION_VERSION;
    Description.Master = TRUE;
    Description.ScatterGather = TRUE;
    Description.Dma32BitAddresses = TRUE;
    Description.InterfaceType = PCIBus;
    Description.MaximumLength = Pages * PAGE_SIZE;
    *MapRegisters = 0;
    return (PDMA_ADAPTER)HalGetAdapter(&Description, MapRegisters);
}

/* A request for Pages pages from a buffer that starts OFFSET into a page: SPAN(Pages) map registers */
static
PSG_REQUEST
AllocateRequest(
    _In_ ULONG Pages)
{
    PSG_REQUEST Request;

    Request = ExAllocatePoolWithTag(NonPagedPool, sizeof(*Request), 'qRgS');
    if (!Request)
        return NULL;
    RtlZeroMemory(Request, sizeof(*Request));
    KeInitializeEvent(&Request->Event, NotificationEvent, FALSE);
    Request->Length = Pages * PAGE_SIZE;
    Request->Buffer = ExAllocatePoolWithTag(NonPagedPool, SPAN(Pages) * PAGE_SIZE, 'qRgS');
    if (!Request->Buffer)
    {
        ExFreePoolWithTag(Request, 'qRgS');
        return NULL;
    }
    RtlZeroMemory(Request->Buffer, SPAN(Pages) * PAGE_SIZE);
    Request->Mdl = IoAllocateMdl(Request->Buffer, SPAN(Pages) * PAGE_SIZE, FALSE, FALSE, NULL);
    if (!Request->Mdl)
    {
        ExFreePoolWithTag(Request->Buffer, 'qRgS');
        ExFreePoolWithTag(Request, 'qRgS');
        return NULL;
    }
    MmBuildMdlForNonPagedPool(Request->Mdl);
    return Request;
}

static
VOID
FreeRequest(
    _In_ PSG_REQUEST Request)
{
    IoFreeMdl(Request->Mdl);
    ExFreePoolWithTag(Request->Buffer, 'qRgS');
    ExFreePoolWithTag(Request, 'qRgS');
}

static
NTSTATUS
StartRequest(
    _In_ PDMA_ADAPTER Adapter,
    _In_ PSG_REQUEST Request)
{
    NTSTATUS Status;
    KIRQL OldIrql;

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    Status = Adapter->DmaOperations->GetScatterGatherList(Adapter,
                                                         KmtDriverObject->DeviceObject,
                                                         Request->Mdl,
                                                         Request->Buffer + OFFSET,
                                                         Request->Length,
                                                         ListControl,
                                                         Request,
                                                         TRUE);
    KeLowerIrql(OldIrql);
    return Status;
}

static
BOOLEAN
WaitRequest(
    _In_ PSG_REQUEST Request,
    _In_ ULONG Seconds)
{
    LARGE_INTEGER Timeout;

    Timeout.QuadPart = -10 * 1000 * 1000 * (LONGLONG)Seconds;
    return KeWaitForSingleObject(&Request->Event, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS;
}

static
VOID
PutRequest(
    _In_ PDMA_ADAPTER Adapter,
    _In_ PSG_REQUEST Request)
{
    KIRQL OldIrql;

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    Adapter->DmaOperations->PutScatterGatherList(Adapter, Request->List, TRUE);
    KeLowerIrql(OldIrql);
    Request->List = NULL;
}

static
VOID
SetFaultMask(
    _In_ ULONG Mask)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(FAULT_KEY);
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"FailMask");
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE Key;

    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateKey(&Key, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    if (Mask)
        Status = ZwSetValueKey(Key, &ValueName, 0, REG_DWORD, &Mask, sizeof(Mask));
    else
        Status = ZwDeleteValueKey(Key, &ValueName);
    ok(NT_SUCCESS(Status) || Status == STATUS_OBJECT_NAME_NOT_FOUND, "Fault mask 0x%lx: 0x%lx\n", Mask, Status);
    ZwClose(Key);
}

/*
 * No map register will ever be free for this request: the adapter needs more than the master
 * adapter holds, and the map buffers cannot grow. The checked HAL fails it; a free HAL has no way
 * to make that happen (the registers always suffice), so there the request is just served.
 */
static
BOOLEAN
TestStarvedRequest(
    _In_ ULONG Mask)
{
    PDMA_ADAPTER Adapter;
    PSG_REQUEST Request;
    ULONG MapRegisters;
    NTSTATUS Status;
    BOOLEAN Done;

    SetFaultMask(Mask);
    /* 47 pages: 48 map registers, the most one device gets */
    Adapter = GetAdapter(47, &MapRegisters);
    ok(Adapter != NULL, "HalGetAdapter failed\n");
    if (!Adapter)
        return FALSE;
    trace("Fault mask 0x%lx: %lu map registers per request\n", Mask, MapRegisters);

    Request = AllocateRequest(47);
    ok(Request != NULL, "Out of memory\n");
    if (!Request)
    {
        Adapter->DmaOperations->PutDmaAdapter(Adapter);
        return FALSE;
    }

    Status = StartRequest(Adapter, Request);
    ok_eq_hex(Status, STATUS_SUCCESS);

    /* Well past any work item and retry of the HAL */
    Done = WaitRequest(Request, 15);
    ok(Done, "Mask 0x%lx: the request that waits for map registers was never called back\n", Mask);
    if (!Done)
    {
        /* Still queued in the HAL: leave it its memory, and the adapter */
        return FALSE;
    }

    if (Request->List)
    {
        trace("Mask 0x%lx: served with %lu elements (the master adapter held enough registers, or a free HAL)\n",
              Mask, Request->List->NumberOfElements);
        PutRequest(Adapter, Request);
    }
    else
    {
        trace("Mask 0x%lx: called back without a list\n", Mask);
    }

    FreeRequest(Request);
    Adapter->DmaOperations->PutDmaAdapter(Adapter);
    return TRUE;
}

/*
 * Hold all the registers, queue one request more: it is served when a holder is done, and not
 * before. Returns how many holders fitted.
 */
static
ULONG
TestExhaustion(VOID)
{
    PDMA_ADAPTER Adapter;
    PSG_REQUEST Holders[24] = { NULL };
    PSG_REQUEST Waiter = NULL;
    ULONG MapRegisters, Count = 0, i;
    NTSTATUS Status;

    Adapter = GetAdapter(TEST_PAGES, &MapRegisters);
    ok(Adapter != NULL, "HalGetAdapter failed\n");
    if (!Adapter)
        return 0;
    ok_eq_ulong(MapRegisters, SPAN(TEST_PAGES));

    while (Count < RTL_NUMBER_OF(Holders))
    {
        PSG_REQUEST Request = AllocateRequest(TEST_PAGES);

        ok(Request != NULL, "Out of memory\n");
        if (!Request)
            break;
        Status = StartRequest(Adapter, Request);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (!WaitRequest(Request, 3))
        {
            Waiter = Request;
            break;
        }
        ok(Request->List != NULL, "Request %lu got no list\n", Count);
        Holders[Count++] = Request;
    }
    trace("%lu requests hold map registers, a request waits: %s\n", Count, Waiter ? "yes" : "no");

    if (Waiter)
    {
        ok(Waiter->Called == 0, "The waiting request was called back\n");

        /* A holder is done: the registers go to the waiter */
        PutRequest(Adapter, Holders[0]);
        ok(WaitRequest(Waiter, 15), "The waiting request was not served when registers were freed\n");
        if (Waiter->Called)
        {
            ok(Waiter->List != NULL, "The waiting request was served without a list\n");
            if (Waiter->List)
                PutRequest(Adapter, Waiter);
            FreeRequest(Waiter);
        }
        FreeRequest(Holders[0]);
        Holders[0] = NULL;
    }

    for (i = 0; i < Count; i++)
    {
        if (!Holders[i])
            continue;
        PutRequest(Adapter, Holders[i]);
        FreeRequest(Holders[i]);
    }
    Adapter->DmaOperations->PutDmaAdapter(Adapter);
    return Count;
}

START_TEST(HalDmaSgWait)
{
    ULONG Holders, HoldersAgain;
    PDMA_ADAPTER Adapter;
    PSG_REQUEST Request;
    ULONG MapRegisters;
    BOOLEAN Healthy = TRUE;

    if (skip(MemoryAbove4Gb(), "No memory above 4 GB\n"))
        return;

    /* First, while the master adapter holds as few registers as it will: nothing to wait for any more */
    Healthy &= TestStarvedRequest(FAULT_GROW_FAILS | FAULT_NO_PREGROW);
    Healthy &= TestStarvedRequest(FAULT_NO_WORK_ITEM | FAULT_NO_PREGROW);
    SetFaultMask(0);

    /* A request of a device that works must not wait behind them */
    if (skip(Healthy, "A request is still queued in the HAL\n"))
        return;
    Adapter = GetAdapter(TEST_PAGES, &MapRegisters);
    ok(Adapter != NULL, "HalGetAdapter failed\n");
    if (Adapter)
    {
        Request = AllocateRequest(TEST_PAGES);
        ok(Request != NULL, "Out of memory\n");
        if (Request)
        {
            ok_eq_hex(StartRequest(Adapter, Request), STATUS_SUCCESS);
            ok(WaitRequest(Request, 15), "A request after the failed ones was never served\n");
            if (Request->Called)
            {
                ok(Request->List != NULL, "It got no list\n");
                if (Request->List)
                    PutRequest(Adapter, Request);
                FreeRequest(Request);
            }
        }
        Adapter->DmaOperations->PutDmaAdapter(Adapter);
    }

    /* The registers run out at the master adapter's limit: nothing is lost, the waiter is served */
    Holders = TestExhaustion();
    ok(Holders >= 10, "Only %lu requests of %u map registers fitted: map registers were lost\n",
       Holders, SPAN(TEST_PAGES));
    HoldersAgain = TestExhaustion();
    ok(HoldersAgain >= Holders, "Second round: %lu requests fitted, first round %lu\n", HoldersAgain, Holders);
}
