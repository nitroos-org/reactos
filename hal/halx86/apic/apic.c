/*
 * PROJECT:         ReactOS HAL
 * LICENSE:         GNU GPL - See COPYING in the top level directory
 * FILE:            hal/halx86/apic/apic.c
 * PURPOSE:         HAL APIC Management and Control Code
 * PROGRAMMERS:     Timo Kreuzer (timo.kreuzer@reactos.org)
 * REFERENCES:      https://web.archive.org/web/20190407074221/http://www.joseflores.com/docs/ExploringIrql.html
 *                  https://www.codeproject.com/KB/system/soviet_kernel_hack.aspx
 *                  http://bbs.unixmap.net/thread-2022-1-1.html (DEAD_LINK)
 *                  https://codemachine.com/articles/interrupt_dispatching.html
 *                  https://www.osronline.com/article.cfm%5Earticle=211.htm
 */

/* INCLUDES *******************************************************************/

#include <hal.h>
#include "apicp.h"
#define NDEBUG
#include <debug.h>

#ifndef _M_AMD64
#define APIC_LAZY_IRQL
#endif

/* GLOBALS ********************************************************************/

ULONG ApicVersion;
BOOLEAN HalpX2ApicEnabled;
UCHAR HalpVectorToIndex[256];

/* Processor that receives each device interrupt vector, and the next one to pick */
static UCHAR HalpVectorTarget[256];
static ULONG HalpNextInterruptTarget;

/* Message vectors whose interrupt was disconnected; a new message reuses them */
static BOOLEAN HalpMessageVectorUnused[256];

/* The IRQL each I/O APIC input was given when its vector was allocated. On x86 several IRQLs
   share one vector class (HalpIRQLtoTPR), so HalpVectorToIrql cannot give it back: a second
   translation of a shared input has to report the same DIRQL as the first, or the devices
   sharing the vector connect their interrupt objects at different IRQLs. */
static KIRQL HalpVectorDirql[256];

#ifndef _M_AMD64
const UCHAR
HalpIRQLtoTPR[32] =
{
    0x00, /*  0 PASSIVE_LEVEL */
    0x3d, /*  1 APC_LEVEL */
    0x41, /*  2 DISPATCH_LEVEL */
    0x41, /*  3 \  */
    0x51, /*  4  \ */
    0x61, /*  5  | */
    0x71, /*  6  | */
    0x81, /*  7  | */
    0x91, /*  8  | */
    0xa1, /*  9  | */
    0xb1, /* 10  | */
    0xb1, /* 11  | */
    0xb1, /* 12  | */
    0xb1, /* 13  | */
    0xb1, /* 14  | */
    0xb1, /* 15 DEVICE IRQL */
    0xb1, /* 16  | */
    0xb1, /* 17  | */
    0xb1, /* 18  | */
    0xb1, /* 19  | */
    0xb1, /* 20  | */
    0xb1, /* 21  | */
    0xb1, /* 22  | */
    0xb1, /* 23  | */
    0xb1, /* 24  | */
    0xb1, /* 25  / */
    0xb1, /* 26 /  */
    0xc1, /* 27 PROFILE_LEVEL */
    0xd1, /* 28 CLOCK2_LEVEL */
    0xe1, /* 29 IPI_LEVEL */
    0xef, /* 30 POWER_LEVEL */
    0xff, /* 31 HIGH_LEVEL */
};

const KIRQL
HalVectorToIRQL[16] =
{
       0, /* 00 PASSIVE_LEVEL */
    0xff, /* 10 */
    0xff, /* 20 */
       1, /* 3D APC_LEVEL */
       2, /* 41 DISPATCH_LEVEL */
       4, /* 50 \ */
       5, /* 60  \ */
       6, /* 70  | */
       7, /* 80 DEVICE IRQL */
       8, /* 90  | */
       9, /* A0  / */
      10, /* B0 /  */
      27, /* C1 PROFILE_LEVEL */
      28, /* D1 CLOCK2_LEVEL */
      29, /* E1 IPI_LEVEL / EF POWER_LEVEL */
      31, /* FF HIGH_LEVEL */
};
#endif

/* PRIVATE FUNCTIONS **********************************************************/

/* apic.c is built once for the UP and the SMP HALs, without CONFIG_SMP, so its locks
   cannot use KxAcquireSpinLock, which takes the lock only when CONFIG_SMP is defined */
FORCEINLINE
VOID
HalpAcquireApicLock(
    _Inout_ PKSPIN_LOCK SpinLock)
{
    while (InterlockedBitTestAndSet((PLONG)SpinLock, 0))
    {
        while (*(volatile KSPIN_LOCK *)SpinLock & 1)
            YieldProcessor();
    }
}

FORCEINLINE
VOID
HalpReleaseApicLock(
    _Inout_ PKSPIN_LOCK SpinLock)
{
    InterlockedAnd((PLONG)SpinLock, 0);
}

/* All processors share the select and window registers */
KSPIN_LOCK HalpIoApicLock;

/* Serializes the lookup and allocation of interrupt vectors */
KSPIN_LOCK HalpVectorAllocationLock;

#ifdef APIC_LAZY_IRQL
/* Trigger mode of each redirection entry, for the lazy IRQL deferral in interrupt context */
UCHAR HalpIoApicTriggerMode[APIC_MAX_IRQ];
#endif

FORCEINLINE
ULONG
IOApicRead(UCHAR Register)
{
    ULONG_PTR Flags;
    ULONG Value;

    /* Select the register, then do the read */
    ASSERT(Register <= 0x3F);
    Flags = __readeflags();
    _disable();
    HalpAcquireApicLock(&HalpIoApicLock);
    WRITE_REGISTER_ULONG((PULONG)(IOAPIC_BASE + IOAPIC_IOREGSEL), Register);
    Value = READ_REGISTER_ULONG((PULONG)(IOAPIC_BASE + IOAPIC_IOWIN));
    HalpReleaseApicLock(&HalpIoApicLock);
    __writeeflags(Flags);
    return Value;
}

FORCEINLINE
VOID
IOApicWrite(UCHAR Register, ULONG Value)
{
    ULONG_PTR Flags;

    /* Select the register, then do the write */
    ASSERT(Register <= 0x3F);
    Flags = __readeflags();
    _disable();
    HalpAcquireApicLock(&HalpIoApicLock);
    WRITE_REGISTER_ULONG((PULONG)(IOAPIC_BASE + IOAPIC_IOREGSEL), Register);
    WRITE_REGISTER_ULONG((PULONG)(IOAPIC_BASE + IOAPIC_IOWIN), Value);
    HalpReleaseApicLock(&HalpIoApicLock);
    __writeeflags(Flags);
}

FORCEINLINE
VOID
ApicWriteIORedirectionEntry(
    UCHAR Index,
    IOAPIC_REDIRECTION_REGISTER ReDirReg)
{
    ASSERT(Index < APIC_MAX_IRQ);
#ifdef APIC_LAZY_IRQL
    HalpIoApicTriggerMode[Index] = (UCHAR)ReDirReg.TriggerMode;
#endif

    /* The low dword holds the mask bit: mask an entry before changing its destination,
       and unmask it only after */
    if (ReDirReg.Mask)
    {
        IOApicWrite(IOAPIC_REDTBL + 2 * Index, ReDirReg.Long0);
        IOApicWrite(IOAPIC_REDTBL + 2 * Index + 1, ReDirReg.Long1);
    }
    else
    {
        IOApicWrite(IOAPIC_REDTBL + 2 * Index + 1, ReDirReg.Long1);
        IOApicWrite(IOAPIC_REDTBL + 2 * Index, ReDirReg.Long0);
    }
}

FORCEINLINE
IOAPIC_REDIRECTION_REGISTER
ApicReadIORedirectionEntry(
    UCHAR Index)
{
    IOAPIC_REDIRECTION_REGISTER ReDirReg;

    ASSERT(Index < APIC_MAX_IRQ);
    ReDirReg.Long0 = IOApicRead(IOAPIC_REDTBL + 2 * Index);
    ReDirReg.Long1 = IOApicRead(IOAPIC_REDTBL + 2 * Index + 1);

    return ReDirReg;
}

FORCEINLINE
VOID
ApicRequestSelfInterrupt(IN UCHAR Vector, UCHAR TriggerMode)
{
    ULONG Flags;
    APIC_INTERRUPT_COMMAND_REGISTER Icr;
    APIC_INTERRUPT_COMMAND_REGISTER IcrStatus;

    /*
     * The IRR registers are spaced 16 bytes apart and hold 32 status bits each.
     * Pre-compute the register and bit that match our vector.
     */
    ULONG VectorHigh = Vector / 32;
    ULONG VectorLow = Vector % 32;
    ULONG Irr = APIC_IRR + 0x10 * VectorHigh;
    ULONG IrrBit = 1UL << VectorLow;

    /* Setup the command register */
    Icr.LongLong = 0;
    Icr.Vector = Vector;
    Icr.MessageType = APIC_MT_Fixed;
    Icr.TriggerMode = TriggerMode;
    Icr.DestinationShortHand = APIC_DSH_Self;

    /* Disable interrupts so that we can change IRR without being interrupted */
    Flags = __readeflags();
    _disable();

    if (HalpX2ApicEnabled)
    {
        /* The self IPI register sends fixed edge-triggered interrupts only */
        X2ApicFenceBeforeIpi();
        if (TriggerMode == APIC_TGM_Edge)
            __writemsr(X2APIC_MSR_SELF_IPI, Vector);
        else
            __writemsr(X2APIC_MSR_ICR, Icr.Long0);
    }
    else
    {
        /* Wait for the APIC to be idle */
        do
        {
            IcrStatus.Long0 = ApicRead(APIC_ICR0);
        } while (IcrStatus.DeliveryStatus);

        /* Write high dword first, then low dword to send the interrupt */
        ApicWrite(APIC_ICR1, Icr.Long1);
        ApicWrite(APIC_ICR0, Icr.Long0);
    }

    /* Wait until we see the interrupt request.
     * It will stay in requested state until we re-enable interrupts.
     */
    while (!(ApicRead(Irr) & IrrBit))
    {
        YieldProcessor();
    }

    /* Finally, restore the original interrupt state */
    if (Flags & EFLAGS_INTERRUPT_MASK)
    {
        _enable();
    }
}

FORCEINLINE
VOID
ApicSendEOI(void)
{
    ApicWrite(APIC_EOI, 0);
}

FORCEINLINE
KIRQL
ApicGetProcessorIrql(VOID)
{
    /* Read the TPR and convert it to an IRQL */
    return TprToIrql(ApicRead(APIC_PPR));
}

FORCEINLINE
KIRQL
ApicGetCurrentIrql(VOID)
{
#ifdef _M_AMD64
    return (KIRQL)__readcr8();
#elif defined(APIC_LAZY_IRQL)
    /* Return the field in the PCR */
    return (KIRQL)__readfsbyte(FIELD_OFFSET(KPCR, Irql));
#else
    /* Read the TPR and convert it to an IRQL */
    return TprToIrql(ApicRead(APIC_TPR));
#endif
}

FORCEINLINE
VOID
ApicSetIrql(KIRQL Irql)
{
#ifdef _M_AMD64
    __writecr8(Irql);
#elif defined(APIC_LAZY_IRQL)
    __writefsbyte(FIELD_OFFSET(KPCR, Irql), Irql);
#else
    /* Convert IRQL and write the TPR */
    ApicWrite(APIC_TPR, IrqlToTpr(Irql));
#endif
}
#define ApicRaiseIrql ApicSetIrql

#ifdef APIC_LAZY_IRQL
FORCEINLINE
VOID
ApicLowerIrql(KIRQL Irql)
{
    ULONG_PTR EFlags;

    __writefsbyte(FIELD_OFFSET(KPCR, Irql), Irql);

    /* Is the new Irql lower than set in the TPR? */
    if (Irql < __readfsdword(FIELD_OFFSET(KPCR, IRR)))
    {
        /* A thread moved to another processor in here would leave this one's TPR above its saved hard IRQL for good */
        EFlags = __readeflags();
        _disable();

        if (Irql < __readfsdword(FIELD_OFFSET(KPCR, IRR)))
        {
            /* Save the new hard IRQL in the IRR field */
            __writefsdword(FIELD_OFFSET(KPCR, IRR), Irql);

            /* Need to lower it back */
            ApicWrite(APIC_TPR, IrqlToTpr(Irql));
        }

        __writeeflags(EFlags);
    }
}
#else
#define ApicLowerIrql ApicSetIrql
#endif

UCHAR
FASTCALL
HalpIrqToVector(UCHAR Irq)
{
    IOAPIC_REDIRECTION_REGISTER ReDirReg;

    if (Irq >= APIC_MAX_IRQ)
        return APIC_FREE_VECTOR;

    /* Read low dword of the redirection entry */
    ReDirReg.Long0 = IOApicRead(IOAPIC_REDTBL + 2 * Irq);

    /* Return the vector */
    return (UCHAR)ReDirReg.Vector;
}

KIRQL
FASTCALL
HalpVectorToIrql(UCHAR Vector)
{
    return TprToIrql(Vector);
}

UCHAR
FASTCALL
HalpVectorToIrq(UCHAR Vector)
{
    return HalpVectorToIndex[Vector];
}

VOID
NTAPI
HalpSendEOI(VOID)
{
    ApicSendEOI();
}

BOOLEAN
NTAPI
X2ApicIsSupported(VOID)
{
    INT CpuInfo[4];

    __cpuid(CpuInfo, 1);
    return (CpuInfo[2] & (1 << CPUID_X2APIC_FEATURE_BIT)) != 0;
}

VOID
NTAPI
X2ApicEnable(VOID)
{
    X2APIC_BASE_ADDRESS_REGISTER BaseRegister;

    BaseRegister.LongLong = __readmsr(MSR_APIC_BASE);
    BaseRegister.Enable = 1;
    BaseRegister.EnableX2Apic = 1;
    __writemsr(MSR_APIC_BASE, BaseRegister.LongLong);
}

VOID
ApicSelectMode(
    _In_ PLOADER_PARAMETER_BLOCK LoaderBlock)
{
    X2APIC_BASE_ADDRESS_REGISTER BaseRegister;

    if (!X2ApicIsSupported())
        return;

    /* Leaving x2APIC mode means disabling the APIC, so keep a mode the firmware chose */
    BaseRegister.LongLong = __readmsr(MSR_APIC_BASE);
    if (BaseRegister.Enable && BaseRegister.EnableX2Apic)
    {
        HalpX2ApicEnabled = TRUE;
        return;
    }

    if (LoaderBlock->LoadOptions && strstr(LoaderBlock->LoadOptions, "NOX2APIC"))
        return;

    /* The I/O APIC reaches 8-bit APIC IDs without interrupt remapping, which the MADT parser ensures */
    HalpX2ApicEnabled = TRUE;
}

VOID
NTAPI
ApicInitializeLocalApic(ULONG Cpu)
{
    APIC_BASE_ADDRESS_REGISTER BaseRegister;
    APIC_SPURIOUS_INERRUPT_REGISTER SpIntRegister;
    LVT_REGISTER LvtEntry;

    /* Enable the APIC if it wasn't yet */
    BaseRegister.LongLong = __readmsr(MSR_APIC_BASE);
    BaseRegister.Enable = 1;
    BaseRegister.BootStrapCPUCore = (Cpu == 0);
    __writemsr(MSR_APIC_BASE, BaseRegister.LongLong);

    /* Every processor uses the mode the boot processor chose, before any other APIC access */
    if (HalpX2ApicEnabled)
        X2ApicEnable();

    /* Set spurious vector and SoftwareEnable to 1 */
    SpIntRegister.Long = ApicRead(APIC_SIVR);
    SpIntRegister.Vector = APIC_SPURIOUS_VECTOR;
    SpIntRegister.SoftwareEnable = 1;
    SpIntRegister.FocusCPUCoreChecking = 0;
    ApicWrite(APIC_SIVR, SpIntRegister.Long);

    /* Read the version and save it globally */
    if (Cpu == 0) ApicVersion = ApicRead(APIC_VER);

    /* In x2APIC mode the logical ID is derived from the APIC ID and there is no DFR */
    if (!HalpX2ApicEnabled)
    {
        /* Set the mode to flat (max 8 CPUs supported!) */
        ApicWrite(APIC_DFR, APIC_DF_Flat);

        /* Set logical apic ID */
        ApicWrite(APIC_LDR, ApicLogicalId(Cpu) << 24);
    }

    /* Set the spurious ISR */
    KeRegisterInterruptHandler(APIC_SPURIOUS_VECTOR, ApicSpuriousService);

    /* Create a template LVT */
    LvtEntry.Long = 0;
    LvtEntry.Vector = APIC_FREE_VECTOR;
    LvtEntry.MessageType = APIC_MT_Fixed;
    LvtEntry.DeliveryStatus = 0;
    LvtEntry.RemoteIRR = 0;
    LvtEntry.TriggerMode = APIC_TGM_Edge;
    LvtEntry.Mask = 1;
    LvtEntry.TimerMode = 0;

    /* Initialize and mask LVTs */
    ApicWrite(APIC_TMRLVTR, LvtEntry.Long);
    ApicWrite(APIC_THRMLVTR, LvtEntry.Long);
    ApicWrite(APIC_PCLVTR, LvtEntry.Long);
    /* The x2APIC register space ends before the AMD extended registers */
    if (!HalpX2ApicEnabled)
    {
        ApicWrite(APIC_EXT0LVTR, LvtEntry.Long);
        ApicWrite(APIC_EXT1LVTR, LvtEntry.Long);
        ApicWrite(APIC_EXT2LVTR, LvtEntry.Long);
        ApicWrite(APIC_EXT3LVTR, LvtEntry.Long);
    }

    /* LINT0 */
    LvtEntry.Vector = APIC_SPURIOUS_VECTOR;
    LvtEntry.MessageType = APIC_MT_ExtInt;
    ApicWrite(APIC_LINT0, LvtEntry.Long);

    /* Enable LINT1 (NMI) */
    LvtEntry.Mask = 0;
    LvtEntry.Vector = APIC_NMI_VECTOR;
    LvtEntry.MessageType = APIC_MT_NMI;
    LvtEntry.TriggerMode = APIC_TGM_Level;
    ApicWrite(APIC_LINT1, LvtEntry.Long);

    /* Enable error LVTR; it has no trigger mode, the bit is reserved there */
    LvtEntry.Vector = APIC_ERROR_VECTOR;
    LvtEntry.MessageType = APIC_MT_Fixed;
    LvtEntry.TriggerMode = APIC_TGM_Edge;
    ApicWrite(APIC_ERRLVTR, LvtEntry.Long);

    /* Set the IRQL from the PCR */
    ApicSetIrql(KeGetPcr()->Irql);
#ifdef APIC_LAZY_IRQL
    /* Save the new hard IRQL in the IRR field */
    KeGetPcr()->IRR = KeGetPcr()->Irql;
#endif
}

static
UCHAR
HalpChooseInterruptTarget(VOID)
{
    ULONG Count = (ULONG)KeNumberProcessors;

    /* Spread device interrupts over the processors, leaving the boot processor
       (it takes the clock interrupt) to the last ones */
    if (Count <= 1)
        return 0;
    return (UCHAR)(1 + (HalpNextInterruptTarget++ % (Count - 1)));
}

static
UCHAR
HalpFindFreeVector(
    _Out_ PKIRQL OutIrql)
{
    ULONG Offset;
    KIRQL Irql;
    UCHAR Vector;

    /* Outer loop to find alternative slots, when all IRQLs are in use */
    for (Offset = 0; Offset < 15; Offset++)
    {
        /* Loop allowed IRQL range */
        for (Irql = CLOCK_LEVEL - 1; Irql >= CMCI_LEVEL; Irql--)
        {
            /* Calculate the vector and check if it is free */
            Vector = IrqlToTpr(Irql) + Offset;
            if (HalpVectorToIrq(Vector) == APIC_FREE_VECTOR)
            {
                *OutIrql = Irql;
                return Vector;
            }
        }
    }

    return 0;
}

/*
 * A message-signaled interrupt has its own vector and goes to one processor:
 * the device writes the vector to that processor's local APIC (Intel SDM,
 * "Message Signalled Interrupts"; the bus driver programs the device).
 * BusInterruptVector is CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN to allocate one,
 * or a vector allocated before, to translate it again.
 */
static
ULONG
HalpGetMessageInterruptVector(
    _In_ ULONG MessageCount,
    _In_ ULONG BusInterruptVector,
    _Out_ PKIRQL OutIrql,
    _Out_ PKAFFINITY OutAffinity)
{
    ULONG Index;
    UCHAR Vector = 0;
    KIRQL Irql;

    *OutIrql = 0;
    *OutAffinity = 0;

    /* Each message has its own descriptor */
    if (MessageCount != 1)
        return 0;

    if (BusInterruptVector == CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN)
    {
        /* Prefer a message vector that was given up, so stopping and starting
           a device does not use up the vectors */
        for (Index = 0; Index < RTL_NUMBER_OF(HalpMessageVectorUnused); Index++)
        {
            if (HalpMessageVectorUnused[Index])
            {
                Vector = (UCHAR)Index;
                Irql = HalpVectorToIrql(Vector);
                break;
            }
        }

        if (Vector == 0)
            Vector = HalpFindFreeVector(&Irql);
        if (Vector == 0)
        {
            DPRINT1("Failed to get a vector for a message-signaled interrupt\n");
            return 0;
        }

        HalpVectorToIndex[Vector] = APIC_MSI_INDEX;
        HalpMessageVectorUnused[Vector] = FALSE;
        HalpVectorTarget[Vector] = HalpChooseInterruptTarget();

        /* Report the IRQL a later translation of the vector reports */
        Irql = HalpVectorToIrql(Vector);
    }
    else
    {
        if ((BusInterruptVector >= RTL_NUMBER_OF(HalpVectorToIndex)) ||
            (HalpVectorToIndex[BusInterruptVector] != APIC_MSI_INDEX))
        {
            return 0;
        }

        Vector = (UCHAR)BusInterruptVector;
        Irql = HalpVectorToIrql(Vector);
    }

    *OutIrql = Irql;
    *OutAffinity = (KAFFINITY)1 << HalpVectorTarget[Vector];
    return Vector;
}

UCHAR
NTAPI
HalpAllocateSystemInterrupt(
    _In_ UCHAR Irq,
    _In_ UCHAR Vector)
{
    IOAPIC_REDIRECTION_REGISTER ReDirReg;

    ASSERT(Irq < APIC_MAX_IRQ);
    ASSERT(HalpVectorToIndex[Vector] == APIC_FREE_VECTOR);

    /* Setup a redirection entry */
    ReDirReg.Vector = Vector;
    ReDirReg.MessageType = APIC_MT_LowestPriority;
    ReDirReg.DestinationMode = APIC_DM_Logical;
    ReDirReg.DeliveryStatus = 0;
    ReDirReg.Polarity = 0;
    ReDirReg.RemoteIRR = 0;
    ReDirReg.TriggerMode = APIC_TGM_Edge;
    ReDirReg.Mask = 1;
    ReDirReg.Reserved = 0;
    ReDirReg.Destination = ApicGetLocalId();

    /* Initialize entry */
    ApicWriteIORedirectionEntry(Irq, ReDirReg);

    /* Save irq in the table */
    HalpVectorToIndex[Vector] = Irq;

    return Vector;
}

static
ULONG
HalpGetRootInterruptVectorLocked(
    _In_ ULONG BusInterruptLevel,
    _In_ ULONG BusInterruptVector,
    _Out_ PKIRQL OutIrql,
    _Out_ PKAFFINITY OutAffinity)
{
    UCHAR Vector;
    KIRQL Irql;

    /* The high word of the level of a message-signaled interrupt is its message count */
    if (BusInterruptLevel >> 16)
    {
        return HalpGetMessageInterruptVector(BusInterruptLevel >> 16,
                                             BusInterruptVector,
                                             OutIrql,
                                             OutAffinity);
    }

    /* Get the vector currently registered */
    Vector = HalpIrqToVector(BusInterruptLevel);

    /* Check if it's used; every device of a shared input gets its processor */
    if (Vector != APIC_FREE_VECTOR)
    {
        /* Report the IRQL the vector was allocated with */
        NT_ASSERT(HalpVectorToIndex[Vector] == BusInterruptLevel);
        *OutIrql = HalpVectorDirql[Vector] ? HalpVectorDirql[Vector] : HalpVectorToIrql(Vector);
    }
    else
    {
        /* Find a free vector and allocate the interrupt */
        Vector = HalpFindFreeVector(&Irql);
        if (Vector == 0)
        {
            DPRINT1("Failed to get an interrupt vector for IRQ %lu\n", BusInterruptLevel);
            *OutAffinity = 0;
            *OutIrql = 0;
            return 0;
        }

        Vector = HalpAllocateSystemInterrupt(BusInterruptLevel, Vector);
        HalpVectorDirql[Vector] = Irql;
        *OutIrql = Irql;

        /* The input goes to one processor, chosen in turn */
        HalpVectorTarget[Vector] = HalpChooseInterruptTarget();
    }

    *OutAffinity = (KAFFINITY)1 << HalpVectorTarget[Vector];
    ASSERT(*OutAffinity & HalpDefaultInterruptAffinity);

    return Vector;
}

ULONG
NTAPI
HalpGetRootInterruptVector(
    _In_ ULONG BusInterruptLevel,
    _In_ ULONG BusInterruptVector,
    _Out_ PKIRQL OutIrql,
    _Out_ PKAFFINITY OutAffinity)
{
    ULONG Vector;
    KIRQL Irql;
    KAFFINITY Affinity;
    ULONG_PTR Flags;

    if (!(BusInterruptLevel >> 16) && (BusInterruptLevel >= APIC_MAX_IRQ))
    {
        DPRINT1("IRQ %lu is not an I/O APIC input\n", BusInterruptLevel);
        *OutAffinity = 0;
        *OutIrql = 0;
        return 0;
    }

    /* Concurrent lookups could otherwise allocate two vectors for one IRQ, or one vector
       for two IRQs. Interrupts stay disabled: the lock does not raise the IRQL. */
    Flags = __readeflags();
    _disable();
    HalpAcquireApicLock(&HalpVectorAllocationLock);
    Vector = HalpGetRootInterruptVectorLocked(BusInterruptLevel, BusInterruptVector, &Irql, &Affinity);
    HalpReleaseApicLock(&HalpVectorAllocationLock);
    __writeeflags(Flags);

    /* The caller's output may be pageable: write it with its interrupt state restored */
    *OutIrql = Irql;
    *OutAffinity = Affinity;

    return Vector;
}

VOID
NTAPI
ApicInitializeIOApic(VOID)
{
    PHARDWARE_PTE Pte;
    IOAPIC_REDIRECTION_REGISTER ReDirReg;
    UCHAR Index;
    ULONG Vector;

    /* Map the I/O Apic page */
    Pte = HalAddressToPte(IOAPIC_BASE);
    Pte->PageFrameNumber = IOAPIC_PHYS_BASE / PAGE_SIZE;
    Pte->Valid = 1;
    Pte->Write = 1;
    Pte->Owner = 1;
    Pte->CacheDisable = 1;
    Pte->Global = 1;
    _ReadWriteBarrier();

    /* Setup a redirection entry */
    ReDirReg.Vector = APIC_FREE_VECTOR;
    ReDirReg.MessageType = APIC_MT_Fixed;
    ReDirReg.DestinationMode = APIC_DM_Physical;
    ReDirReg.DeliveryStatus = 0;
    ReDirReg.Polarity = 0;
    ReDirReg.RemoteIRR = 0;
    ReDirReg.TriggerMode = APIC_TGM_Edge;
    ReDirReg.Mask = 1;
    ReDirReg.Reserved = 0;
    ReDirReg.Destination = ApicGetLocalId();

    /* Loop all table entries */
    for (Index = 0; Index < APIC_MAX_IRQ; Index++)
    {
        /* Initialize entry */
        ApicWriteIORedirectionEntry(Index, ReDirReg);
    }

    /* Init the vactor to index table */
    for (Vector = 0; Vector <= 255; Vector++)
    {
        HalpVectorToIndex[Vector] = APIC_FREE_VECTOR;
    }

    /* Enable the timer interrupt (but keep it masked) */
    ReDirReg.Vector = APIC_CLOCK_VECTOR;
    ReDirReg.MessageType = APIC_MT_Fixed;
    ReDirReg.DestinationMode = APIC_DM_Physical;
    ReDirReg.TriggerMode = APIC_TGM_Level;
    ReDirReg.Mask = 1;
    ReDirReg.Destination = ApicGetLocalId();
    ApicWriteIORedirectionEntry(APIC_CLOCK_INDEX, ReDirReg);
}

VOID
NTAPI
HalpInitializePICs(IN BOOLEAN EnableInterrupts)
{
    ULONG_PTR EFlags;

    /* Save EFlags and disable interrupts */
    EFlags = __readeflags();
    _disable();

    /* Initialize and mask the PIC */
    HalpInitializeLegacyPICs();

    /* Initialize the I/O APIC */
    ApicInitializeIOApic();

    /* Manually reserve some vectors */
    HalpVectorToIndex[APC_VECTOR] = APIC_RESERVED_VECTOR;
    HalpVectorToIndex[DISPATCH_VECTOR] = APIC_RESERVED_VECTOR;
    HalpVectorToIndex[APIC_CLOCK_VECTOR] = 8;
    HalpVectorToIndex[CLOCK_IPI_VECTOR] = APIC_RESERVED_VECTOR;
    HalpVectorToIndex[APIC_IPI_VECTOR] = APIC_RESERVED_VECTOR;
    HalpVectorToIndex[APIC_SPURIOUS_VECTOR] = APIC_RESERVED_VECTOR;
    HalpVectorToIndex[APIC_PROFILE_VECTOR] = APIC_RESERVED_VECTOR;

    /* Set interrupt handlers in the IDT */
    KeRegisterInterruptHandler(APIC_CLOCK_VECTOR, HalpClockInterrupt);
    KeRegisterInterruptHandler(CLOCK_IPI_VECTOR, HalpClockIpi);
#ifndef _M_AMD64
    KeRegisterInterruptHandler(APC_VECTOR, HalpApcInterrupt);
    KeRegisterInterruptHandler(DISPATCH_VECTOR, HalpDispatchInterrupt);
#endif

    /* Register the vectors for APC and dispatch interrupts */
    HalpRegisterVector(IDT_INTERNAL, 0, APC_VECTOR, APC_LEVEL);
    HalpRegisterVector(IDT_INTERNAL, 0, DISPATCH_VECTOR, DISPATCH_LEVEL);

    /* Restore interrupt state */
    if (EnableInterrupts) EFlags |= EFLAGS_INTERRUPT_MASK;
    __writeeflags(EFlags);
}


/* SOFTWARE INTERRUPT TRAPS ***************************************************/

#ifndef _M_AMD64
VOID
DECLSPEC_NORETURN
FASTCALL
HalpApcInterruptHandler(IN PKTRAP_FRAME TrapFrame)
{
    KPROCESSOR_MODE ProcessorMode;
    KIRQL OldIrql;
    ASSERT(ApicGetProcessorIrql() == APC_LEVEL);

   /* Enter trap */
    KiEnterInterruptTrap(TrapFrame);

#ifdef APIC_LAZY_IRQL
    /* Send the EOI before interrupts are enabled: a DPC interrupt could
       switch threads first and leave this vector in service */
    OldIrql = ApicGetCurrentIrql();
    if (OldIrql >= APC_LEVEL)
    {
        /* Not allowed now: defer it and end this one */
        HalBeginSystemInterrupt(APC_LEVEL, APC_VECTOR, &OldIrql);
        KiEoiHelper(TrapFrame);
    }
#else
    /* Save the old IRQL */
    OldIrql = ApicGetCurrentIrql();
    ASSERT(OldIrql < APC_LEVEL);
#endif

    /* Raise to APC_LEVEL */
    ApicRaiseIrql(APC_LEVEL);

    /* End the interrupt */
    ApicSendEOI();

    /* Kernel or user APC? */
    if (KiUserTrap(TrapFrame)) ProcessorMode = UserMode;
    else if (TrapFrame->EFlags & EFLAGS_V86_MASK) ProcessorMode = UserMode;
    else ProcessorMode = KernelMode;

    /* Enable interrupts and call the kernel's APC interrupt handler */
    _enable();
    KiDeliverApc(ProcessorMode, NULL, TrapFrame);

    /* Disable interrupts */
    _disable();

    /* Restore the old IRQL */
    ApicLowerIrql(OldIrql);

    /* Exit the interrupt */
    KiEoiHelper(TrapFrame);
}

VOID
DECLSPEC_NORETURN
FASTCALL
HalpDispatchInterruptHandler(IN PKTRAP_FRAME TrapFrame)
{
    KIRQL OldIrql;
    ASSERT(ApicGetProcessorIrql() == DISPATCH_LEVEL);

   /* Enter trap */
    KiEnterInterruptTrap(TrapFrame);

#ifdef APIC_LAZY_IRQL
    if (!HalBeginSystemInterrupt(DISPATCH_LEVEL, DISPATCH_VECTOR, &OldIrql))
    {
        /* "Spurious" interrupt, exit the interrupt */
        KiEoiHelper(TrapFrame);
    }
#else
    /* Get the current IRQL */
    OldIrql = ApicGetCurrentIrql();
    ASSERT(OldIrql < DISPATCH_LEVEL);
#endif

    /* Raise to DISPATCH_LEVEL */
    ApicRaiseIrql(DISPATCH_LEVEL);

    /* End the interrupt */
    ApicSendEOI();

    /* Enable interrupts and call the kernel's DPC interrupt handler */
    _enable();
    KiDispatchInterrupt();
    _disable();

    /* Restore the old IRQL */
    ApicLowerIrql(OldIrql);

    /* Exit the interrupt */
    KiEoiHelper(TrapFrame);
}
#endif


/* SOFTWARE INTERRUPTS ********************************************************/


VOID
FASTCALL
HalRequestSoftwareInterrupt(IN KIRQL Irql)
{
    /* Convert irql to vector and request an interrupt */
    ApicRequestSelfInterrupt(IrqlToSoftVector(Irql), APIC_TGM_Edge);
}

VOID
FASTCALL
HalClearSoftwareInterrupt(
    IN KIRQL Irql)
{
    /* Nothing to do */
}


/* SYSTEM INTERRUPTS **********************************************************/

BOOLEAN
NTAPI
HalEnableSystemInterrupt(
    IN ULONG Vector,
    IN KIRQL Irql,
    IN KINTERRUPT_MODE InterruptMode)
{
    IOAPIC_REDIRECTION_REGISTER ReDirReg;
    UCHAR Index;
    ASSERT(Irql <= HIGH_LEVEL);
    ASSERT((IrqlToTpr(Irql) & 0xF0) == (Vector & 0xF0));

    /* Get the irq for this vector */
    Index = HalpVectorToIndex[Vector];

    /* A message-signaled interrupt is enabled and masked in the device */
    if (Index == APIC_MSI_INDEX)
    {
        HalpMessageVectorUnused[Vector] = FALSE;
        return TRUE;
    }

    /* Check if its valid */
    if (Index >= APIC_MAX_IRQ)
    {
        /* Interrupt is not in use, or not an I/O APIC input */
        return FALSE;
    }

    /* Read the redirection entry. This read-modify-write needs no lock of its own:
       KeConnectInterrupt and KeDisconnectInterrupt hold the dispatcher lock, the HAL's
       own callers run before the other processors start, and allocation only writes
       free entries. */
    ReDirReg = ApicReadIORedirectionEntry(Index);

    /* Check if the interrupt is already enabled */
    if (ReDirReg.Mask == FALSE)
    {
        /* If the vector doesn't match, something is wrong */
        if (ReDirReg.Vector != Vector)
            return FALSE;

        return TRUE;
    }

    /* Set up the redirection entry; drivers connect on the processor that
       HalpGetRootInterruptVector reported as the affinity */
    ReDirReg.Vector = Vector;
    ReDirReg.MessageType = APIC_MT_Fixed;
    ReDirReg.DestinationMode = APIC_DM_Physical;
    ReDirReg.Destination = ApicGetLocalId();
    ReDirReg.TriggerMode = (InterruptMode == LevelSensitive) ?
        APIC_TGM_Level : APIC_TGM_Edge;
    ReDirReg.Mask = FALSE;

    /* Write back the entry */
    ApicWriteIORedirectionEntry(Index, ReDirReg);

    return TRUE;
}

VOID
NTAPI
HalDisableSystemInterrupt(
    IN ULONG Vector,
    IN KIRQL Irql)
{
    IOAPIC_REDIRECTION_REGISTER ReDirReg;
    UCHAR Index;
    ASSERT(Irql <= HIGH_LEVEL);
    ASSERT(Vector < RTL_NUMBER_OF(HalpVectorToIndex));

    Index = HalpVectorToIndex[Vector];

    /* Only I/O APIC inputs can be masked here; a message vector whose
       interrupt is gone can be handed to the next message */
    if (Index >= APIC_MAX_IRQ)
    {
        if (Index == APIC_MSI_INDEX)
            HalpMessageVectorUnused[Vector] = TRUE;
        return;
    }

    /* Read lower dword of redirection entry */
    ReDirReg.Long0 = IOApicRead(IOAPIC_REDTBL + 2 * Index);

    /* Mask it */
    ReDirReg.Mask = 1;

    /* Write back lower dword */
    IOApicWrite(IOAPIC_REDTBL + 2 * Index, ReDirReg.Long0);
}

BOOLEAN
NTAPI
HalBeginSystemInterrupt(
    IN KIRQL Irql,
    IN ULONG Vector,
    OUT PKIRQL OldIrql)
{
    KIRQL CurrentIrql;

    /* Get the current IRQL */
    CurrentIrql = ApicGetCurrentIrql();

#ifdef APIC_LAZY_IRQL
    /* Check if this interrupt is allowed */
    if (CurrentIrql >= Irql)
    {
        UCHAR Index;

        /* It is not, set the real Irql in the TPR! */
        ApicWrite(APIC_TPR, IrqlToTpr(CurrentIrql));

        /* Save the new hard IRQL in the IRR field */
        KeGetPcr()->IRR = CurrentIrql;

        /* End this interrupt */
        ApicSendEOI();

        /* Get the irq for this vector */
        Index = HalpVectorToIndex[Vector];

        /* Check if it's valid */
        if (Index < APIC_MAX_IRQ)
        {
            /* Re-request the interrupt to be handled later, with the saved trigger mode:
               reading the redirection entry here would take the I/O APIC lock and make
               four uncached register accesses in interrupt context */
            ApicRequestSelfInterrupt(Vector, HalpIoApicTriggerMode[Index]);
       }
       else
       {
            /* This should be a reserved vector or a message-signaled interrupt */
            ASSERT((Index == APIC_RESERVED_VECTOR) || (Index == APIC_MSI_INDEX));

            /* Re-request the interrupt to be handled later */
            ApicRequestSelfInterrupt(Vector, APIC_TGM_Edge);
       }

        /* Pretend it was a spurious interrupt */
        return FALSE;
    }
#endif
    /* Save the current IRQL */
    *OldIrql = CurrentIrql;

    /* Set the new IRQL */
    ApicRaiseIrql(Irql);

    /* Turn on interrupts */
    _enable();

    /* Success */
    return TRUE;
}

VOID
NTAPI
HalEndSystemInterrupt(
    IN KIRQL OldIrql,
    IN PKTRAP_FRAME TrapFrame)
{
    /* Send an EOI */
    ApicSendEOI();

    /* Restore the old IRQL */
    ApicLowerIrql(OldIrql);
}


/* IRQL MANAGEMENT ************************************************************/

#ifndef _M_AMD64
KIRQL
NTAPI
KeGetCurrentIrql(VOID)
{
    /* Read the current TPR and convert it to an IRQL */
    return ApicGetCurrentIrql();
}

VOID
FASTCALL
KfLowerIrql(
    IN KIRQL OldIrql)
{
#if DBG
    /* Validate correct lower */
    if (OldIrql > ApicGetCurrentIrql())
    {
        /* Crash system */
        KeBugCheck(IRQL_NOT_LESS_OR_EQUAL);
    }
#endif
    /* Set the new IRQL */
    ApicLowerIrql(OldIrql);
}

KIRQL
FASTCALL
KfRaiseIrql(
    IN KIRQL NewIrql)
{
    KIRQL OldIrql;

    /* Read the current IRQL */
    OldIrql = ApicGetCurrentIrql();
#if DBG
    /* Validate correct raise */
    if (OldIrql > NewIrql)
    {
        /* Crash system */
        KeBugCheck(IRQL_NOT_GREATER_OR_EQUAL);
    }
#endif
    /* Convert the new IRQL to a TPR value and write the register */
    ApicRaiseIrql(NewIrql);

    /* Return old IRQL */
    return OldIrql;
}

KIRQL
NTAPI
KeRaiseIrqlToDpcLevel(VOID)
{
    return KfRaiseIrql(DISPATCH_LEVEL);
}

KIRQL
NTAPI
KeRaiseIrqlToSynchLevel(VOID)
{
    return KfRaiseIrql(SYNCH_LEVEL);
}

#endif /* !_M_AMD64 */

