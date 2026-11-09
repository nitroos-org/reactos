/*
 * PROJECT:         ReactOS kernel-mode tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Kernel-Mode Test Suite Interrupt test
 * PROGRAMMER:      Thomas Faber <thomas.faber@reactos.org>
 */

#include <kmt_test.h>

#define NDEBUG
#include <debug.h>

#define CheckSpinLock(Lock, Locked) do                  \
{                                                       \
    if (KmtIsMultiProcessorBuild)                       \
        ok_eq_ulongptr(*(Lock), (Locked) != 0);         \
    else if (KmtIsCheckedBuild)                         \
        ok_eq_bool(*(Lock) != 0, (Locked) != 0);        \
    else                                                \
        ok_eq_ulongptr(*(Lock), 0);                     \
} while (0)

typedef struct
{
    BOOLEAN ReturnValue;
    KIRQL ExpectedIrql;
    PKINTERRUPT Interrupt;
} TEST_CONTEXT, *PTEST_CONTEXT;

static KSYNCHRONIZE_ROUTINE SynchronizeRoutine;

static
BOOLEAN
NTAPI
SynchronizeRoutine(
    IN PVOID Context)
{
    PTEST_CONTEXT TestContext = Context;

    ok_irql(TestContext->ExpectedIrql);

    CheckSpinLock(TestContext->Interrupt->ActualLock, TRUE);

    return TestContext->ReturnValue;
}

static
VOID
TestSynchronizeExecution(VOID)
{
    KINTERRUPT Interrupt;
    TEST_CONTEXT TestContext;
    KIRQL SynchIrql;
    KIRQL OriginalIrql;
    KIRQL Irql;
    KSPIN_LOCK ActualLock;
    BOOLEAN Ret;

    if (skip(GetNTVersion() < _WIN32_WINNT_VISTA, "We can't create fake interrupts on Vista+.\n"))
        return;

    RtlFillMemory(&Interrupt, sizeof Interrupt, 0x55);
    Interrupt.ActualLock = &ActualLock;
    KeInitializeSpinLock(Interrupt.ActualLock);
    CheckSpinLock(Interrupt.ActualLock, FALSE);

    TestContext.Interrupt = &Interrupt;
    TestContext.ReturnValue = TRUE;

    for (TestContext.ReturnValue = 0; TestContext.ReturnValue <= 2; ++TestContext.ReturnValue)
    {
        for (OriginalIrql = PASSIVE_LEVEL; OriginalIrql <= HIGH_LEVEL; ++OriginalIrql)
        {
            /* TODO: don't hardcode this :| */
            if (OriginalIrql == 3 || (OriginalIrql >= 11 && OriginalIrql <= 26) || OriginalIrql == 30)
                continue;
            KeRaiseIrql(OriginalIrql, &Irql);
            for (SynchIrql = max(DISPATCH_LEVEL, OriginalIrql); SynchIrql <= HIGH_LEVEL; ++SynchIrql)
            {
                if (SynchIrql == 3 || (SynchIrql >= 11 && SynchIrql <= 26) || SynchIrql == 30)
                    continue;
                Interrupt.SynchronizeIrql = SynchIrql;
                ok_irql(OriginalIrql);
                CheckSpinLock(Interrupt.ActualLock, FALSE);
                TestContext.ExpectedIrql = SynchIrql;
                Ret = KeSynchronizeExecution(&Interrupt, SynchronizeRoutine, &TestContext);
                ok_eq_int(Ret, TestContext.ReturnValue);
                ok_irql(OriginalIrql);
                CheckSpinLock(Interrupt.ActualLock, FALSE);
                /* TODO: Check that all other fields of the interrupt are untouched */
            }
            KeLowerIrql(Irql);
        }
    }
}

static
VOID
TestConnectInterrupt(VOID)
{
    PKINTERRUPT InterruptObject;
    NTSTATUS Status;

    /* If the IoConnectInterrupt() fails, the interrupt object should be set to NULL */
    InterruptObject = KmtInvalidPointer;

    /* Test for invalid interrupt */
    Status = IoConnectInterrupt(&InterruptObject,
                                (PKSERVICE_ROUTINE)TestConnectInterrupt,
                                NULL,
                                NULL,
                                0,
                                0,
                                0,
                                LevelSensitive,
                                TRUE,
                                (KAFFINITY)-1,
                                FALSE);
    ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    ok_eq_pointer(InterruptObject, NULL);
}

/* --- Shared interrupt line: one DIRQL per vector ---------------------------- */

static
BOOLEAN
NTAPI
SharedLineIsr(
    IN PKINTERRUPT Interrupt,
    IN PVOID Context)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(Context);
    return FALSE;
}

static
BOOLEAN
NTAPI
SharedLineSynchronize(
    IN PVOID Context)
{
    PTEST_CONTEXT TestContext = Context;

    /* KeSynchronizeExecution raises to the object's SynchronizeIrql: that is the DIRQL of the
       vector only if the object was connected with the DIRQL the HAL reports for the line */
    ok_irql(TestContext->ExpectedIrql);
    return TRUE;
}

static
VOID
TestSharedLineIrql(VOID)
{
    /* The HAL must report the same vector and DIRQL every time one interrupt line is translated:
       drivers sharing the line connect with what they are told, and an interrupt object connected
       at a lower IRQL than its vector is not excluded from the ISR by KeSynchronizeExecution */
    ULONG Line;
    ULONG Vector1, Vector2, Vector3;
    KIRQL Irql1 = 0, Irql2 = 0, Irql3 = 0;
    KAFFINITY Affinity1 = 0, Affinity2 = 0, Affinity3 = 0;
    PKINTERRUPT Interrupt1 = NULL, Interrupt2 = NULL;
    TEST_CONTEXT TestContext;
    NTSTATUS Status;
    BOOLEAN Ret;

    /* Lines the HAL has not allocated a vector for yet: the first translation allocates it. Use the
       last I/O APIC inputs, no device has them; the last one gets the chained connection below */
    for (Line = 20; Line < 23; Line++)
    {
        Vector1 = HalGetInterruptVector(Isa, 0, Line, Line, &Irql1, &Affinity1);
        Vector2 = HalGetInterruptVector(Isa, 0, Line, Line, &Irql2, &Affinity2);
        if (Vector1 == 0)
            continue;
        ok_eq_ulong(Vector2, Vector1);
        ok_eq_int(Irql2, Irql1);
    }

    Line = 23;
    Vector1 = HalGetInterruptVector(Isa, 0, Line, Line, &Irql1, &Affinity1);
    Vector2 = HalGetInterruptVector(Isa, 0, Line, Line, &Irql2, &Affinity2);
    Vector3 = HalGetInterruptVector(Isa, 0, Line, Line, &Irql3, &Affinity3);
    if (skip(Vector1 != 0, "Cannot translate line %lu\n", Line))
        return;

    ok_eq_ulong(Vector2, Vector1);
    ok_eq_ulong(Vector3, Vector1);
    ok_eq_int(Irql2, Irql1);
    ok_eq_int(Irql3, Irql1);
    ok_eq_ulongptr(Affinity2, Affinity1);

    Status = IoConnectInterrupt(&Interrupt1, SharedLineIsr, NULL, NULL, Vector1, Irql1, Irql1,
                                LevelSensitive, TRUE, Affinity1, FALSE);
    if (skip(NT_SUCCESS(Status), "Cannot connect to line %lu: %lx\n", Line, Status))
        return;

    Status = IoConnectInterrupt(&Interrupt2, SharedLineIsr, NULL, NULL, Vector2, Irql2, Irql2,
                                LevelSensitive, TRUE, Affinity2, FALSE);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        TestContext.ExpectedIrql = Irql1;
        Ret = KeSynchronizeExecution(Interrupt2, SharedLineSynchronize, &TestContext);
        ok_eq_int(Ret, TRUE);
        ok_irql(PASSIVE_LEVEL);
        IoDisconnectInterrupt(Interrupt2);
    }
    IoDisconnectInterrupt(Interrupt1);
}

/* --- IoConnectInterruptEx / IoDisconnectInterruptEx ------------------------ */

#define TAG_INTEX 'xInK'

typedef NTSTATUS (NTAPI *PFN_CONNECT_EX)(PIO_CONNECT_INTERRUPT_PARAMETERS);
typedef VOID (NTAPI *PFN_DISCONNECT_EX)(PIO_DISCONNECT_INTERRUPT_PARAMETERS);
/* NTDDI_WS03SP1 headers do not declare the Ex routines (Vista+): resolve them at run time */
static PFN_CONNECT_EX pIoConnectInterruptEx;
static PFN_DISCONNECT_EX pIoDisconnectInterruptEx;
#define IoConnectInterruptEx pIoConnectInterruptEx
#define IoDisconnectInterruptEx pIoDisconnectInterruptEx

/* Registers of QEMU's "edu" PCI test device (vendor 1234, device 11e8) */
#define EDU_IRQ_STATUS  0x24
#define EDU_IRQ_RAISE   0x60
#define EDU_IRQ_ACK     0x64

static volatile LONG IsrCount;
static volatile LONG IsrFallbackCount;
static volatile LONG IsrMessageCount;
static PUCHAR EduRegs;

static
BOOLEAN
NTAPI
EduIsr(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID Context)
{
    ULONG Status;

    UNREFERENCED_PARAMETER(Interrupt);

    if (!EduRegs)
        return FALSE;
    Status = READ_REGISTER_ULONG((PULONG)(EduRegs + EDU_IRQ_STATUS));
    if (!Status)
        return FALSE;
    WRITE_REGISTER_ULONG((PULONG)(EduRegs + EDU_IRQ_ACK), Status);
    InterlockedIncrement((volatile LONG *)Context);
    return TRUE;
}

static
BOOLEAN
NTAPI
UnusedMessageIsr(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID Context,
    _In_ ULONG MessageId)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(MessageId);
    InterlockedIncrement(&IsrMessageCount);
    return FALSE;
}

static
BOOLEAN
NTAPI
DummyIsr(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(Context);
    return FALSE;
}

/* Referenced snapshot of the physical device objects of a driver */
static
NTSTATUS
GetDriverPdos(
    _In_ PCWSTR Name,
    _Out_ PDEVICE_OBJECT **List,
    _Out_ PULONG Count)
{
    UNICODE_STRING DriverName;
    PDRIVER_OBJECT DriverObject;
    NTSTATUS Status;

    *List = NULL;
    RtlInitUnicodeString(&DriverName, Name);
    Status = ObReferenceObjectByName(&DriverName, OBJ_CASE_INSENSITIVE, NULL, 0,
                                     IoDriverObjectType, KernelMode, NULL,
                                     (PVOID *)&DriverObject);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = IoEnumerateDeviceObjectList(DriverObject, NULL, 0, Count);
    if (Status != STATUS_BUFFER_TOO_SMALL || *Count == 0)
    {
        ObDereferenceObject(DriverObject);
        return STATUS_NOT_FOUND;
    }
    *List = ExAllocatePoolWithTag(NonPagedPool, *Count * sizeof(**List), TAG_INTEX);
    if (!*List)
    {
        ObDereferenceObject(DriverObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    Status = IoEnumerateDeviceObjectList(DriverObject, *List, *Count * sizeof(**List), Count);
    ObDereferenceObject(DriverObject);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(*List, TAG_INTEX);
        *List = NULL;
    }
    return Status;
}

static
VOID
ReleaseDriverPdos(
    _In_ PDEVICE_OBJECT *List,
    _In_ ULONG Count,
    _In_opt_ PDEVICE_OBJECT Keep)
{
    ULONG i;

    for (i = 0; i < Count; i++)
        if (List[i] != Keep)
            ObDereferenceObject(List[i]);
    ExFreePoolWithTag(List, TAG_INTEX);
}

/* Every connect must be "success <=> a usable connection". Run on any PDO. */
static
VOID
TestNoSilentSuccess(
    _In_ PDEVICE_OBJECT Pdo)
{
    IO_CONNECT_INTERRUPT_PARAMETERS Params;
    IO_DISCONNECT_INTERRUPT_PARAMETERS DisParams;
    PKINTERRUPT Interrupt;
    NTSTATUS Status;
    ULONG Which;

    for (Which = 0; Which < 3; Which++)
    {
        RtlZeroMemory(&Params, sizeof(Params));
        Interrupt = KmtInvalidPointer;
        if (Which == 0)
        {
            Params.Version = CONNECT_LINE_BASED;
            Params.LineBased.PhysicalDeviceObject = Pdo;
            Params.LineBased.InterruptObject = &Interrupt;
            Params.LineBased.ServiceRoutine = DummyIsr;
        }
        else
        {
            Params.Version = CONNECT_MESSAGE_BASED;
            Params.MessageBased.PhysicalDeviceObject = Pdo;
            Params.MessageBased.ConnectionContext.Generic = (PVOID *)&Interrupt;
            Params.MessageBased.MessageServiceRoutine = UnusedMessageIsr;
            Params.MessageBased.FallBackServiceRoutine = (Which == 2) ? DummyIsr : NULL;
        }

        Status = IoConnectInterruptEx(&Params);
        if (NT_SUCCESS(Status))
        {
            ok(Interrupt != NULL && Interrupt != KmtInvalidPointer,
               "Which %lu: success with interrupt %p\n", Which, Interrupt);
            ok(Params.Version == CONNECT_LINE_BASED,
               "Which %lu: Version %lu\n", Which, Params.Version);
            if (Interrupt && Interrupt != KmtInvalidPointer)
            {
                DisParams.Version = Params.Version;
                DisParams.ConnectionContext.InterruptObject = Interrupt;
                IoDisconnectInterruptEx(&DisParams);
            }
        }
        else
        {
            ok(Interrupt == NULL, "Which %lu: failure 0x%lx left interrupt %p\n",
               Which, Status, Interrupt);
        }
    }
}

/* Returns the edu device's PDO (referenced), or NULL */
static
PDEVICE_OBJECT
FindEduPdo(
    _Out_ PULONG BusNumber,
    _Out_ PULONG Address)
{
    PDEVICE_OBJECT *List;
    ULONG Count, i, Len;
    PDEVICE_OBJECT Found = NULL;
    WCHAR Ids[256];
    NTSTATUS Status;

    Status = GetDriverPdos(L"\\Driver\\pci", &List, &Count);
    if (!NT_SUCCESS(Status))
        return NULL;

    for (i = 0; i < Count && !Found; i++)
    {
        PCWSTR p;

        if (!(List[i]->Flags & DO_BUS_ENUMERATED_DEVICE))
            continue;
        RtlZeroMemory(Ids, sizeof(Ids));
        Status = IoGetDeviceProperty(List[i], DevicePropertyHardwareID, sizeof(Ids) - sizeof(WCHAR), Ids, &Len);
        if (!NT_SUCCESS(Status))
            continue;
        for (p = Ids; *p; p += wcslen(p) + 1)
        {
            if (!_wcsnicmp(p, L"PCI\\VEN_1234&DEV_11E8", 21))
            {
                Len = sizeof(ULONG);
                if (NT_SUCCESS(IoGetDeviceProperty(List[i], DevicePropertyBusNumber, sizeof(ULONG), BusNumber, &Len)) &&
                    NT_SUCCESS(IoGetDeviceProperty(List[i], DevicePropertyAddress, sizeof(ULONG), Address, &Len)))
                    Found = List[i];
                break;
            }
        }
    }
    ReleaseDriverPdos(List, Count, Found);
    return Found;
}

static
BOOLEAN
WaitForCount(
    _In_ volatile LONG *Counter,
    _In_ LONG Target)
{
    LARGE_INTEGER Interval;
    ULONG i;

    Interval.QuadPart = -10 * 1000 * 10; /* 10 ms */
    for (i = 0; i < 200 && *Counter < Target; i++)
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    return *Counter >= Target;
}

static
VOID
TestEduConnect(
    _In_ PDEVICE_OBJECT Pdo,
    _In_ ULONG Version,
    _In_ BOOLEAN WithFallback)
{
    IO_CONNECT_INTERRUPT_PARAMETERS Params;
    IO_DISCONNECT_INTERRUPT_PARAMETERS DisParams;
    PKINTERRUPT Interrupt;
    NTSTATUS Status;
    ULONG Round;
    volatile LONG *Counter = (Version == CONNECT_LINE_BASED) ? &IsrCount : &IsrFallbackCount;

    for (Round = 0; Round < 2; Round++)
    {
        LONG Before = *Counter;

        RtlZeroMemory(&Params, sizeof(Params));
        Interrupt = KmtInvalidPointer;
        Params.Version = Version;
        if (Version == CONNECT_LINE_BASED)
        {
            Params.LineBased.PhysicalDeviceObject = Pdo;
            Params.LineBased.InterruptObject = &Interrupt;
            Params.LineBased.ServiceRoutine = EduIsr;
            Params.LineBased.ServiceContext = (PVOID)Counter;
        }
        else
        {
            Params.MessageBased.PhysicalDeviceObject = Pdo;
            Params.MessageBased.ConnectionContext.Generic = (PVOID *)&Interrupt;
            Params.MessageBased.MessageServiceRoutine = UnusedMessageIsr;
            Params.MessageBased.ServiceContext = (PVOID)Counter;
            Params.MessageBased.FallBackServiceRoutine = WithFallback ? EduIsr : NULL;
        }

        Status = IoConnectInterruptEx(&Params);
        if (Version == CONNECT_MESSAGE_BASED && !WithFallback)
        {
            ok(!NT_SUCCESS(Status), "message-based without fallback succeeded 0x%lx\n", Status);
            ok_eq_pointer(Interrupt, NULL);
            if (NT_SUCCESS(Status) && Interrupt)
            {
                DisParams.Version = Params.Version;
                DisParams.ConnectionContext.InterruptObject = Interrupt;
                IoDisconnectInterruptEx(&DisParams);
            }
            return;
        }

        ok_eq_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
        {
            ok_eq_pointer(Interrupt, NULL);
            return;
        }
        ok(Interrupt != NULL && Interrupt != KmtInvalidPointer, "interrupt %p\n", Interrupt);
        ok_eq_ulong(Params.Version, CONNECT_LINE_BASED);

        /* Raise the device interrupt: the ISR must fire and acknowledge it */
        WRITE_REGISTER_ULONG((PULONG)(EduRegs + EDU_IRQ_RAISE), 0x1234);
        ok(WaitForCount(Counter, Before + 1), "round %lu version %lu: ISR did not fire\n", Round, Version);
        if (!*Counter || *Counter == Before)
            WRITE_REGISTER_ULONG((PULONG)(EduRegs + EDU_IRQ_ACK), 0xFFFFFFFF);

        DisParams.Version = Params.Version;
        DisParams.ConnectionContext.InterruptObject = Interrupt;
        IoDisconnectInterruptEx(&DisParams);

        /* Disconnected: a raised interrupt must no longer reach the ISR */
        Before = *Counter;
        WRITE_REGISTER_ULONG((PULONG)(EduRegs + EDU_IRQ_RAISE), 0x1234);
        {
            LARGE_INTEGER Interval;
            Interval.QuadPart = -10 * 1000 * 100; /* 100 ms */
            KeDelayExecutionThread(KernelMode, FALSE, &Interval);
        }
        ok_eq_long(*Counter, Before);
        WRITE_REGISTER_ULONG((PULONG)(EduRegs + EDU_IRQ_ACK), 0xFFFFFFFF);
    }
}

static
VOID
TestExConnect(VOID)
{
    PDEVICE_OBJECT Edu, *List;
    UNICODE_STRING Name;
    ULONG Bus = 0, Address = 0, Count, i, Len;
    PCI_SLOT_NUMBER Slot;
    ULONG Bar0 = 0, Command = 0;
    PHYSICAL_ADDRESS Phys;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, L"IoConnectInterruptEx");
    pIoConnectInterruptEx = MmGetSystemRoutineAddress(&Name);
    RtlInitUnicodeString(&Name, L"IoDisconnectInterruptEx");
    pIoDisconnectInterruptEx = MmGetSystemRoutineAddress(&Name);
    if (skip(pIoConnectInterruptEx && pIoDisconnectInterruptEx, "No IoConnectInterruptEx\n"))
        return;

    /* Any PnpManager (root) PDO and a few PCI PDOs: success must mean a real connection */
    if (NT_SUCCESS(GetDriverPdos(L"\\Driver\\pci", &List, &Count)))
    {
        for (i = 0; i < Count && i < 16; i++)
            if (List[i]->Flags & DO_BUS_ENUMERATED_DEVICE)
                TestNoSilentSuccess(List[i]);
        ReleaseDriverPdos(List, Count, NULL);
    }
    if (NT_SUCCESS(GetDriverPdos(L"\\Driver\\PnpManager", &List, &Count)))
    {
        for (i = 0; i < Count && i < 16; i++)
            if (List[i]->Flags & DO_BUS_ENUMERATED_DEVICE)
                TestNoSilentSuccess(List[i]);
        ReleaseDriverPdos(List, Count, NULL);
    }

    /* Invalid parameters */
    {
        IO_CONNECT_INTERRUPT_PARAMETERS Params;

        RtlZeroMemory(&Params, sizeof(Params));
        Params.Version = 0x99;
        Status = IoConnectInterruptEx(&Params);
        ok_eq_hex(Status, STATUS_INVALID_PARAMETER);
    }

    Edu = FindEduPdo(&Bus, &Address);
    if (skip(Edu != NULL, "No QEMU edu device (-device edu) present\n"))
        return;

    Slot.u.AsULONG = 0;
    Slot.u.bits.DeviceNumber = Address >> 16;
    Slot.u.bits.FunctionNumber = Address & 0xFFFF;
    Len = HalGetBusDataByOffset(PCIConfiguration, Bus, Slot.u.AsULONG, &Bar0, 0x10, sizeof(Bar0));
    ok_eq_ulong(Len, sizeof(Bar0));
    Len = HalGetBusDataByOffset(PCIConfiguration, Bus, Slot.u.AsULONG, &Command, 4, 2);
    Command |= 2; /* memory space enable; INTx stays as PnP left it */
    HalSetBusDataByOffset(PCIConfiguration, Bus, Slot.u.AsULONG, &Command, 4, 2);

    Phys.QuadPart = Bar0 & ~0xFUL;
    EduRegs = MmMapIoSpace(Phys, 0x100, MmNonCached);
    if (skip(EduRegs != NULL, "Cannot map edu BAR0 %08lx\n", Bar0))
    {
        ObDereferenceObject(Edu);
        return;
    }

    Status = STATUS_SUCCESS;
    DbgPrint("IoInterrupt: edu id register %08lx\n", READ_REGISTER_ULONG((PULONG)EduRegs));

    TestEduConnect(Edu, CONNECT_LINE_BASED, FALSE);
    TestEduConnect(Edu, CONNECT_MESSAGE_BASED, TRUE);
    TestEduConnect(Edu, CONNECT_MESSAGE_BASED, FALSE);

    {
        PUCHAR Regs = EduRegs;
        EduRegs = NULL;
        MmUnmapIoSpace(Regs, 0x100);
    }
    ObDereferenceObject(Edu);
}

START_TEST(IoInterrupt)
{
    TestSynchronizeExecution();
    TestConnectInterrupt();
    TestSharedLineIrql();
    TestExConnect();
}
