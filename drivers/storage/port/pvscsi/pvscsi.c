/*
 * PROJECT:     ReactOS VMware PVSCSI SCSI miniport driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SCSI port miniport for the VMware paravirtual SCSI controller (PCI 15AD:07C0)
 * COPYRIGHT:   Copyright 2026 ReactOS Project contributors
 *
 * The register offsets, command numbers and the layouts of the request ring, the completion
 * ring and the shared ring state below describe the device interface. They were taken from
 * the OpenBSD driver vmwpvs(4), sys/dev/pci/vmwpvs.c revision 1.31, which carries this notice:
 *
 *   Copyright (c) 2013 David Gwynne <dlg@openbsd.org>
 *
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * The driver code itself is new. It uses the legacy SCSI port interface like the BusLogic
 * miniport, one bus, one logical unit per target, INTx interrupts, no message ring (no hot
 * plug). Everything that the device writes (the ring indices, the completion records) is
 * validated before it is used.
 */

#include <ntddk.h>
#include <srb.h>
#include <scsi.h>

#define PV_TAG                      'scVP'

/* Device interface (see the notice above) */
#define PV_REG_COMMAND              0x0000
#define PV_REG_COMMAND_DATA         0x0004
#define PV_REG_INTR_STATUS          0x100C
#define PV_REG_INTR_MASK            0x2010
#define PV_REG_KICK_NON_RW_IO       0x3014
#define PV_REG_KICK_RW_IO           0x4018
#define PV_REGS_LENGTH              0x5000      /* highest register used + 4, rounded to a page */

#define PV_INTR_CMPL_MASK           0x03
#define PV_INTR_MSG_MASK            0x0C

#define PV_CMD_ADAPTER_RESET        1
#define PV_CMD_SETUP_RINGS          3
#define PV_CMD_RESET_BUS            4
#define PV_CMD_RESET_DEVICE         5

#define PV_REQ_SGL                  (1 << 0)
#define PV_REQ_DIR_NONE             (1 << 2)
#define PV_REQ_DIR_IN               (1 << 3)
#define PV_REQ_DIR_OUT              (1 << 4)

#define PV_HOST_SUCCESS             0x00
#define PV_HOST_LINKED_CMD          0x0A
#define PV_HOST_LINKED_CMD_FLAG     0x0B
#define PV_HOST_UNDERRUN            0x0C
#define PV_HOST_SELTIMEOUT          0x11
#define PV_HOST_BUS_RESET           0x25

#define PV_MAX_RING_PAGES           32
#define PV_PAGE_SHIFT               12

#include <pshpack1.h>

typedef struct _PV_RING_STATE
{
    ULONG ReqProd;
    ULONG ReqCons;
    ULONG ReqEntriesLog2;
    ULONG CmpProd;
    ULONG CmpCons;
    ULONG CmpEntriesLog2;
    ULONG Reserved[26];
    ULONG MsgProd;
    ULONG MsgCons;
    ULONG MsgEntriesLog2;
} PV_RING_STATE, *PPV_RING_STATE;

typedef struct _PV_REQ
{
    ULONGLONG Context;
    ULONGLONG DataAddr;
    ULONGLONG DataLen;
    ULONGLONG SenseAddr;
    ULONG SenseLen;
    ULONG Flags;
    UCHAR Cdb[16];
    UCHAR CdbLen;
    UCHAR Lun[8];
    UCHAR Tag;
    UCHAR Bus;
    UCHAR Target;
    UCHAR VcpuHint;
    UCHAR Reserved[59];
} PV_REQ, *PPV_REQ;

typedef struct _PV_CMP
{
    ULONGLONG Context;
    ULONGLONG DataLen;
    ULONG SenseLen;
    USHORT HostStatus;
    USHORT ScsiStatus;
    ULONG Reserved[2];
} PV_CMP, *PPV_CMP;

typedef struct _PV_SGE
{
    ULONGLONG Addr;
    ULONG Len;
    ULONG Flags;
} PV_SGE, *PPV_SGE;

typedef struct _PV_SETUP_RINGS
{
    ULONG ReqPages;
    ULONG CmpPages;
    ULONGLONG StatePpn;
    ULONGLONG ReqPagePpn[PV_MAX_RING_PAGES];
    ULONGLONG CmpPagePpn[PV_MAX_RING_PAGES];
} PV_SETUP_RINGS, *PPV_SETUP_RINGS;

#include <poppack.h>

/* Driver layout */
#define PV_RING_PAGES               2
#define PV_REQ_COUNT                ((PV_RING_PAGES * PAGE_SIZE) / sizeof(PV_REQ))     /* 64 */
#define PV_CMP_COUNT                ((PV_RING_PAGES * PAGE_SIZE) / sizeof(PV_CMP))     /* 256 */
#define PV_MAX_SG                   32
#define PV_SENSE_SLOT               32
#define PV_MAX_TARGETS              16
#define PV_MAX_TRANSFER             ((PV_MAX_SG - 1) * PAGE_SIZE)

/* The uncached extension: ring state, request ring, completion ring, one SG list and one sense slot per request */
#define PV_OFF_STATE                0
#define PV_OFF_REQ                  (PV_OFF_STATE + PAGE_SIZE)
#define PV_OFF_CMP                  (PV_OFF_REQ + PV_RING_PAGES * PAGE_SIZE)
#define PV_OFF_SGL                  (PV_OFF_CMP + PV_RING_PAGES * PAGE_SIZE)
#define PV_OFF_SENSE                (PV_OFF_SGL + PV_REQ_COUNT * PV_MAX_SG * sizeof(PV_SGE))
#define PV_MEM_SIZE                 ((PV_OFF_SENSE + PV_REQ_COUNT * PV_SENSE_SLOT + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

C_ASSERT(sizeof(PV_REQ) == 128);
C_ASSERT(sizeof(PV_CMP) == 32);
C_ASSERT(sizeof(PV_SGE) == 16);
C_ASSERT(sizeof(PV_RING_STATE) == 140);
C_ASSERT(sizeof(PV_SETUP_RINGS) == 528);
C_ASSERT((PV_REQ_COUNT & (PV_REQ_COUNT - 1)) == 0);
C_ASSERT((PV_CMP_COUNT & (PV_CMP_COUNT - 1)) == 0);

typedef struct _PV_SLOT
{
    PSCSI_REQUEST_BLOCK Srb;
    ULONG Generation;
} PV_SLOT;

typedef struct _PV_EXTENSION
{
    PUCHAR Regs;
    PUCHAR Mem;
    ULONGLONG MemPa;
    volatile PV_RING_STATE *State;
    volatile PV_CMP *Cmp;
    PV_REQ *Req;
    PV_SGE *Sgl;
    PUCHAR Sense;
    ULONG ReqProd;
    ULONG CmpCons;
    ULONG FreeCount;
    BOOLEAN Throttled;
    UCHAR FreeStack[PV_REQ_COUNT];
    PV_SLOT Slots[PV_REQ_COUNT];
} PV_EXTENSION, *PPV_EXTENSION;

static ULONG
PvRead(PPV_EXTENSION Ext, ULONG Reg)
{
    return ScsiPortReadRegisterUlong((PULONG)(Ext->Regs + Reg));
}

static VOID
PvWrite(PPV_EXTENSION Ext, ULONG Reg, ULONG Value)
{
    ScsiPortWriteRegisterUlong((PULONG)(Ext->Regs + Reg), Value);
}

static VOID
PvCommand(PPV_EXTENSION Ext, ULONG Command, PVOID Data, ULONG Length)
{
    PULONG Dwords = Data;
    ULONG i;

    PvWrite(Ext, PV_REG_COMMAND, Command);
    for (i = 0; i < Length / sizeof(ULONG); i++)
        PvWrite(Ext, PV_REG_COMMAND_DATA, Dwords[i]);
}

static VOID
PvResetSlots(PPV_EXTENSION Ext)
{
    ULONG i;

    for (i = 0; i < PV_REQ_COUNT; i++)
    {
        Ext->Slots[i].Srb = NULL;
        Ext->FreeStack[i] = (UCHAR)(PV_REQ_COUNT - 1 - i);
    }
    Ext->FreeCount = PV_REQ_COUNT;
    Ext->Throttled = FALSE;
}

/* Reset the adapter and hand it the rings. The memory is the uncached extension, already zeroed or reused. */
static BOOLEAN
PvStartAdapter(PPV_EXTENSION Ext)
{
    PV_SETUP_RINGS Setup;
    ULONGLONG Ppn;
    ULONG i;

    PvWrite(Ext, PV_REG_INTR_MASK, 0);
    PvCommand(Ext, PV_CMD_ADAPTER_RESET, NULL, 0);

    RtlZeroMemory(Ext->Mem, PV_OFF_SGL);
    Ext->ReqProd = 0;
    Ext->CmpCons = 0;
    PvResetSlots(Ext);

    RtlZeroMemory(&Setup, sizeof(Setup));
    Setup.ReqPages = PV_RING_PAGES;
    Setup.CmpPages = PV_RING_PAGES;
    Setup.StatePpn = (Ext->MemPa + PV_OFF_STATE) >> PV_PAGE_SHIFT;
    Ppn = (Ext->MemPa + PV_OFF_REQ) >> PV_PAGE_SHIFT;
    for (i = 0; i < PV_RING_PAGES; i++)
        Setup.ReqPagePpn[i] = Ppn + i;
    Ppn = (Ext->MemPa + PV_OFF_CMP) >> PV_PAGE_SHIFT;
    for (i = 0; i < PV_RING_PAGES; i++)
        Setup.CmpPagePpn[i] = Ppn + i;

    KeMemoryBarrier();
    PvCommand(Ext, PV_CMD_SETUP_RINGS, &Setup, sizeof(Setup));
    return TRUE;
}

static VOID
PvCompleteSrb(PPV_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb, UCHAR Status)
{
    Srb->SrbStatus = Status;
    ScsiPortNotification(RequestComplete, Ext, Srb);
}

static UCHAR
PvStatusFromHost(PSCSI_REQUEST_BLOCK Srb, ULONG HostStatus, ULONGLONG DataLen)
{
    switch (HostStatus)
    {
        case PV_HOST_SUCCESS:
        case PV_HOST_LINKED_CMD:
        case PV_HOST_LINKED_CMD_FLAG:
            return SRB_STATUS_SUCCESS;

        case PV_HOST_UNDERRUN:
            if (DataLen < Srb->DataTransferLength)
                Srb->DataTransferLength = (ULONG)DataLen;
            return SRB_STATUS_DATA_OVERRUN;

        case PV_HOST_SELTIMEOUT:
            return SRB_STATUS_SELECTION_TIMEOUT;

        case PV_HOST_BUS_RESET:
            return SRB_STATUS_BUS_RESET;

        default:
            return SRB_STATUS_ERROR;
    }
}

/* Handle the completion records the device has produced. The indices come from device memory: never trust them. */
static VOID
PvProcessCompletions(PPV_EXTENSION Ext)
{
    ULONG Budget;

    for (Budget = 0; Budget < 2 * PV_CMP_COUNT; Budget++)
    {
        ULONG Prod = Ext->State->CmpProd;
        ULONGLONG Context, DataLen;
        ULONG Index, SenseLen;
        USHORT HostStatus, ScsiStatus;
        PSCSI_REQUEST_BLOCK Srb;
        UCHAR Status;

        if (Prod == Ext->CmpCons)
            break;

        if ((ULONG)(Prod - Ext->CmpCons) > PV_CMP_COUNT)
        {
            /* More records than the ring holds: the shared state is corrupt. Drop the backlog. */
            DbgPrint("pvscsi: completion ring indices out of range (prod %lu cons %lu)\n", Prod, Ext->CmpCons);
            Ext->CmpCons = Prod;
            Ext->State->CmpCons = Prod;
            break;
        }

        KeMemoryBarrier();
        Context = Ext->Cmp[Ext->CmpCons % PV_CMP_COUNT].Context;
        DataLen = Ext->Cmp[Ext->CmpCons % PV_CMP_COUNT].DataLen;
        SenseLen = Ext->Cmp[Ext->CmpCons % PV_CMP_COUNT].SenseLen;
        HostStatus = Ext->Cmp[Ext->CmpCons % PV_CMP_COUNT].HostStatus;
        ScsiStatus = Ext->Cmp[Ext->CmpCons % PV_CMP_COUNT].ScsiStatus;
        Ext->CmpCons++;
        Ext->State->CmpCons = Ext->CmpCons;

        Index = (ULONG)Context;
        if (Index >= PV_REQ_COUNT || Ext->Slots[Index].Srb == NULL ||
            Ext->Slots[Index].Generation != (ULONG)(Context >> 32))
        {
            DbgPrint("pvscsi: completion for unknown request %I64x ignored\n", Context);
            continue;
        }

        Srb = Ext->Slots[Index].Srb;
        Ext->Slots[Index].Srb = NULL;
        Ext->FreeStack[Ext->FreeCount++] = (UCHAR)Index;

        Status = PvStatusFromHost(Srb, HostStatus, DataLen);
        if (HostStatus == PV_HOST_SUCCESS && ScsiStatus != SCSISTAT_GOOD)
            Status = SRB_STATUS_ERROR;
        Srb->ScsiStatus = (UCHAR)ScsiStatus;

        if (ScsiStatus == SCSISTAT_CHECK_CONDITION && SenseLen != 0 &&
            Srb->SenseInfoBuffer != NULL && !(Srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE))
        {
            ULONG Copy = min(SenseLen, PV_SENSE_SLOT);

            Copy = min(Copy, Srb->SenseInfoBufferLength);
            RtlCopyMemory(Srb->SenseInfoBuffer, Ext->Sense + Index * PV_SENSE_SLOT, Copy);
            Srb->SenseInfoBufferLength = (UCHAR)Copy;
            Status |= SRB_STATUS_AUTOSENSE_VALID;
        }

        PvCompleteSrb(Ext, Srb, Status);
    }

    if (Ext->Throttled && Ext->FreeCount != 0)
    {
        Ext->Throttled = FALSE;
        ScsiPortNotification(NextRequest, Ext, NULL);
    }
}

static BOOLEAN
PvBuildSgl(PPV_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb, PV_REQ *Req, ULONG Index)
{
    PV_SGE *Sgl = Ext->Sgl + Index * PV_MAX_SG;
    PUCHAR Va = Srb->DataBuffer;
    ULONG Remaining = Srb->DataTransferLength;
    ULONG Count = 0;

    while (Remaining != 0)
    {
        ULONG Chunk = 0;
        SCSI_PHYSICAL_ADDRESS Pa = ScsiPortGetPhysicalAddress(Ext, Srb, Va, &Chunk);

        if (Chunk == 0 || Pa.QuadPart == (LONGLONG)SP_UNINITIALIZED_VALUE)
            return FALSE;
        Chunk = min(Chunk, Remaining);

        if (Count != 0 && Sgl[Count - 1].Addr + Sgl[Count - 1].Len == (ULONGLONG)Pa.QuadPart &&
            (ULONGLONG)Sgl[Count - 1].Len + Chunk <= 0x7FFFFFFF)
        {
            Sgl[Count - 1].Len += Chunk;
        }
        else
        {
            if (Count == PV_MAX_SG)
                return FALSE;
            Sgl[Count].Addr = (ULONGLONG)Pa.QuadPart;
            Sgl[Count].Len = Chunk;
            Sgl[Count].Flags = 0;
            Count++;
        }
        Va += Chunk;
        Remaining -= Chunk;
    }

    Req->DataLen = Srb->DataTransferLength;
    if (Count == 1)
    {
        Req->DataAddr = Sgl[0].Addr;
    }
    else
    {
        Req->DataAddr = Ext->MemPa + PV_OFF_SGL + (ULONGLONG)Index * PV_MAX_SG * sizeof(PV_SGE);
        Req->Flags |= PV_REQ_SGL;
    }
    return TRUE;
}

static BOOLEAN
PvExecuteScsi(PPV_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb)
{
    PV_REQ *Req;
    ULONG Index;

    if (Srb->PathId != 0 || Srb->TargetId >= PV_MAX_TARGETS || Srb->Lun != 0)
    {
        PvCompleteSrb(Ext, Srb, SRB_STATUS_NO_DEVICE);
        goto Next;
    }
    if (Srb->CdbLength == 0 || Srb->CdbLength > sizeof(Req->Cdb))
    {
        PvCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
        goto Next;
    }
    if (Ext->FreeCount == 0)
    {
        /* The port should not send more than it was told to: ask for a retry and stop the flow */
        Ext->Throttled = TRUE;
        PvCompleteSrb(Ext, Srb, SRB_STATUS_BUSY);
        return TRUE;
    }

    Index = Ext->FreeStack[Ext->FreeCount - 1];
    Req = &Ext->Req[Ext->ReqProd % PV_REQ_COUNT];
    RtlZeroMemory(Req, sizeof(*Req));

    if (Srb->DataTransferLength != 0 && (Srb->SrbFlags & (SRB_FLAGS_DATA_IN | SRB_FLAGS_DATA_OUT)))
    {
        if (!PvBuildSgl(Ext, Srb, Req, Index))
        {
            PvCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
            goto Next;
        }
        Req->Flags |= (Srb->SrbFlags & SRB_FLAGS_DATA_IN) ? PV_REQ_DIR_IN : PV_REQ_DIR_OUT;
    }
    else
    {
        Req->Flags |= PV_REQ_DIR_NONE;
    }

    Ext->FreeCount--;
    Ext->Slots[Index].Srb = Srb;
    Ext->Slots[Index].Generation++;
    Req->Context = ((ULONGLONG)Ext->Slots[Index].Generation << 32) | Index;
    Req->SenseAddr = Ext->MemPa + PV_OFF_SENSE + (ULONGLONG)Index * PV_SENSE_SLOT;
    Req->SenseLen = PV_SENSE_SLOT;
    RtlCopyMemory(Req->Cdb, Srb->Cdb, Srb->CdbLength);
    Req->CdbLen = Srb->CdbLength;
    Req->Lun[1] = Srb->Lun;
    Req->Tag = SRB_SIMPLE_TAG_REQUEST;
    Req->Bus = 0;
    Req->Target = Srb->TargetId;

    KeMemoryBarrier();
    Ext->ReqProd++;
    Ext->State->ReqProd = Ext->ReqProd;
    KeMemoryBarrier();
    PvWrite(Ext, (Srb->Cdb[0] == SCSIOP_READ || Srb->Cdb[0] == SCSIOP_WRITE ||
                  Srb->Cdb[0] == SCSIOP_READ16 || Srb->Cdb[0] == SCSIOP_WRITE16) ?
                 PV_REG_KICK_RW_IO : PV_REG_KICK_NON_RW_IO, 0);

    if (Ext->FreeCount != 0)
        ScsiPortNotification(NextLuRequest, Ext, Srb->PathId, Srb->TargetId, Srb->Lun);
    else
        Ext->Throttled = TRUE;
    return TRUE;

Next:
    ScsiPortNotification(NextRequest, Ext, NULL);
    return TRUE;
}

static BOOLEAN NTAPI
PvStartIo(PVOID HwDeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
    PPV_EXTENSION Ext = HwDeviceExtension;

    switch (Srb->Function)
    {
        case SRB_FUNCTION_EXECUTE_SCSI:
            return PvExecuteScsi(Ext, Srb);

        case SRB_FUNCTION_RESET_DEVICE:
        {
            ULONG Cmd[3] = { Srb->TargetId, 0, 0 };    /* target, then the 8 byte LUN (zero) */

            PvCommand(Ext, PV_CMD_RESET_DEVICE, Cmd, sizeof(Cmd));
            PvCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;
        }

        case SRB_FUNCTION_ABORT_COMMAND:
            /* the adapter has no way to abort one command by its context: the port escalates to a bus reset */
            PvCompleteSrb(Ext, Srb, SRB_STATUS_ABORT_FAILED);
            break;

        case SRB_FUNCTION_FLUSH:
        case SRB_FUNCTION_SHUTDOWN:
            /* nothing is cached in the adapter; the disk's cache is flushed by SYNCHRONIZE CACHE */
            PvCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;

        default:
            PvCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
            break;
    }

    ScsiPortNotification(NextRequest, Ext, NULL);
    return TRUE;
}

static BOOLEAN NTAPI
PvInterrupt(PVOID HwDeviceExtension)
{
    PPV_EXTENSION Ext = HwDeviceExtension;
    ULONG Status = PvRead(Ext, PV_REG_INTR_STATUS);

    if ((Status & (PV_INTR_CMPL_MASK | PV_INTR_MSG_MASK)) == 0)
        return FALSE;

    PvWrite(Ext, PV_REG_INTR_STATUS, Status);
    PvProcessCompletions(Ext);
    return TRUE;
}

static BOOLEAN NTAPI
PvResetBus(PVOID HwDeviceExtension, ULONG PathId)
{
    PPV_EXTENSION Ext = HwDeviceExtension;
    ULONG Index;

    PvCommand(Ext, PV_CMD_RESET_BUS, NULL, 0);

    /* whatever the device still reports for the old requests is ignored: the generation no longer matches */
    for (Index = 0; Index < PV_REQ_COUNT; Index++)
    {
        if (Ext->Slots[Index].Srb != NULL)
            Ext->Slots[Index].Generation++;
    }
    ScsiPortCompleteRequest(Ext, (UCHAR)PathId, SP_UNTAGGED, SP_UNTAGGED, SRB_STATUS_BUS_RESET);
    for (Index = 0; Index < PV_REQ_COUNT; Index++)
        Ext->Slots[Index].Srb = NULL;
    for (Index = 0; Index < PV_REQ_COUNT; Index++)
        Ext->FreeStack[Index] = (UCHAR)(PV_REQ_COUNT - 1 - Index);
    Ext->FreeCount = PV_REQ_COUNT;
    Ext->Throttled = FALSE;
    return TRUE;
}

static BOOLEAN NTAPI
PvInitialize(PVOID HwDeviceExtension)
{
    /* the rings were set up in HwFindAdapter; the interrupt is connected by now */
    PvWrite(HwDeviceExtension, PV_REG_INTR_MASK, PV_INTR_CMPL_MASK);
    return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS NTAPI
PvAdapterControl(PVOID HwDeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
{
    PPV_EXTENSION Ext = HwDeviceExtension;

    switch (ControlType)
    {
        case ScsiQuerySupportedControlTypes:
        {
            PSCSI_SUPPORTED_CONTROL_TYPE_LIST List = Parameters;
            static const BOOLEAN Supported[ScsiAdapterControlMax] = { TRUE, TRUE, TRUE, FALSE, FALSE };
            ULONG i;

            for (i = 0; i < List->MaxControlType && i < ScsiAdapterControlMax; i++)
                List->SupportedTypeList[i] = Supported[i];
            return ScsiAdapterControlSuccess;
        }

        case ScsiStopAdapter:
            PvWrite(Ext, PV_REG_INTR_MASK, 0);
            PvCommand(Ext, PV_CMD_ADAPTER_RESET, NULL, 0);
            return ScsiAdapterControlSuccess;

        case ScsiRestartAdapter:
            if (!PvStartAdapter(Ext))
                return ScsiAdapterControlUnsuccessful;
            PvWrite(Ext, PV_REG_INTR_MASK, PV_INTR_CMPL_MASK);
            return ScsiAdapterControlSuccess;

        default:
            return ScsiAdapterControlUnsuccessful;
    }
}

static ULONG NTAPI
PvFindAdapter(
    IN PVOID HwDeviceExtension,
    IN PVOID Context,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again)
{
    PPV_EXTENSION Ext = HwDeviceExtension;
    PACCESS_RANGE Range = NULL;
    SCSI_PHYSICAL_ADDRESS Pa;
    ULONG Length = 0;
    ULONG i;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);

    *Again = FALSE;

    /* The registers are in the first memory BAR (32 KB) */
    for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
    {
        if ((*ConfigInfo->AccessRanges)[i].RangeInMemory && (*ConfigInfo->AccessRanges)[i].RangeLength != 0)
        {
            Range = &(*ConfigInfo->AccessRanges)[i];
            break;
        }
    }
    if (Range == NULL || Range->RangeLength < PV_REGS_LENGTH)
        return SP_RETURN_NOT_FOUND;

    if (!ScsiPortValidateRange(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                               Range->RangeStart, Range->RangeLength, FALSE))
        return SP_RETURN_BAD_CONFIG;

    Ext->Regs = ScsiPortGetDeviceBase(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                                      Range->RangeStart, Range->RangeLength, FALSE);
    if (Ext->Regs == NULL)
        return SP_RETURN_ERROR;

    ConfigInfo->NumberOfBuses = 1;
    ConfigInfo->MaximumNumberOfTargets = PV_MAX_TARGETS;
    ConfigInfo->MaximumNumberOfLogicalUnits = 1;
    ConfigInfo->MaximumTransferLength = PV_MAX_TRANSFER;
    ConfigInfo->NumberOfPhysicalBreaks = PV_MAX_SG - 1;
    ConfigInfo->ScatterGather = TRUE;
    ConfigInfo->Master = TRUE;
    ConfigInfo->NeedPhysicalAddresses = TRUE;
    ConfigInfo->Dma32BitAddresses = TRUE;
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;     /* the device takes 64-bit data and ring addresses */
    ConfigInfo->TaggedQueuing = TRUE;
    ConfigInfo->MultipleRequestPerLu = TRUE;
    ConfigInfo->AlignmentMask = 0;
    ConfigInfo->InterruptMode = LevelSensitive;
    ConfigInfo->WmiDataProvider = FALSE;

    Ext->Mem = ScsiPortGetUncachedExtension(Ext, ConfigInfo, PV_MEM_SIZE);
    if (Ext->Mem == NULL)
        return SP_RETURN_ERROR;

    /* the rings must start on a page boundary and the extension must be contiguous */
    Pa = ScsiPortGetPhysicalAddress(Ext, NULL, Ext->Mem, &Length);
    if (Length < PV_MEM_SIZE || (Pa.QuadPart & (PAGE_SIZE - 1)) != 0)
        return SP_RETURN_ERROR;
    Ext->MemPa = (ULONGLONG)Pa.QuadPart;

    Ext->State = (volatile PV_RING_STATE *)(Ext->Mem + PV_OFF_STATE);
    Ext->Req = (PV_REQ *)(Ext->Mem + PV_OFF_REQ);
    Ext->Cmp = (volatile PV_CMP *)(Ext->Mem + PV_OFF_CMP);
    Ext->Sgl = (PV_SGE *)(Ext->Mem + PV_OFF_SGL);
    Ext->Sense = Ext->Mem + PV_OFF_SENSE;

    if (!PvStartAdapter(Ext))
        return SP_RETURN_ERROR;

    /* *Again stays FALSE: the port crashes in its second pass for a miniport that asks for another adapter (known), so only the first controller of a machine is driven */
    return SP_RETURN_FOUND;
}

NTSTATUS NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    HW_INITIALIZATION_DATA Init;
    UCHAR VendorId[4] = { '1', '5', 'a', 'd' };
    UCHAR DeviceId[4] = { '0', '7', 'c', '0' };

    RtlZeroMemory(&Init, sizeof(Init));
    Init.HwInitializationDataSize = sizeof(Init);
    Init.HwInitialize = PvInitialize;
    Init.HwStartIo = PvStartIo;
    Init.HwInterrupt = PvInterrupt;
    Init.HwFindAdapter = PvFindAdapter;
    Init.HwResetBus = PvResetBus;
    Init.HwAdapterControl = PvAdapterControl;
    Init.AdapterInterfaceType = PCIBus;
    Init.VendorId = VendorId;
    Init.VendorIdLength = sizeof(VendorId);
    Init.DeviceId = DeviceId;
    Init.DeviceIdLength = sizeof(DeviceId);
    Init.NumberOfAccessRanges = 2;
    Init.DeviceExtensionSize = sizeof(PV_EXTENSION);
    Init.SrbExtensionSize = 0;
    Init.NeedPhysicalAddresses = TRUE;
    Init.TaggedQueuing = TRUE;
    Init.MultipleRequestPerLu = TRUE;
    Init.AutoRequestSense = TRUE;

    return ScsiPortInitialize(DriverObject, RegistryPath, &Init, NULL);
}
