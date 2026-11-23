/*
 * PROJECT:     ReactOS LSI MegaRAID SAS (MFI) SCSI miniport driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SCSI port miniport for the LSI MegaRAID SAS 1078 (PCI 1000:0060) and SAS 2108 (PCI 1000:0079)
 *              controllers, as emulated by QEMU (megasas, megasas-gen2) and offered by Proxmox VE as the
 *              "MegaRAID SAS 8708EM2" controller
 * COPYRIGHT:   Copyright 2026 ReactOS Project contributors
 *
 * The register offsets, the firmware states, the layouts of the message frames (header,
 * pass-through frame, direct command frame, init frame and queue description), the scatter/gather element
 * and the command and status numbers below describe the MegaRAID Firmware Interface. They were taken from
 * the OpenBSD driver mfi(4), sys/dev/ic/mfireg.h revision 1.52 and the start-up and command sequence of
 * sys/dev/ic/mfi.c (the OpenBSD revision of the 2024 tree), which carry this notice:
 *
 *   Copyright (c) 2006 Marco Peereboom <marco@peereboom.us>
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
 * The driver code itself is new. It uses the legacy SCSI port interface like the BusLogic, PVSCSI and
 * MPT miniports: one bus, one logical unit per target (a target is a logical drive of the controller),
 * INTx interrupts, one frame (with its scatter/gather list and sense slot) per request in flight.
 * Everything that the controller writes (reply queue indices and contexts, the sense length, the command
 * limits) is validated before it is used and every wait on the controller is bounded.
 */

#include <ntddk.h>
#include <srb.h>
#include <scsi.h>

/* Registers (the memory BAR, 8 KB) */
#define MFI_REG_IDB                 0x20    /* inbound doorbell */
#define MFI_REG_OSTS                0x30    /* outbound interrupt status */
#define MFI_REG_OMSK                0x34    /* outbound interrupt mask */
#define MFI_REG_IQP                 0x40    /* inbound queue port */
#define MFI_REG_ODC                 0xA0    /* outbound doorbell clear */
#define MFI_REG_OSP                 0xB0    /* outbound scratch pad: the firmware state */
#define MFI_REGS_LENGTH             0x100

#define MFI_OSTS_PPC_INTR_VALID     0x80000000UL
#define MFI_OSTS_GEN2_INTR_VALID    0x00000005UL

#define MFI_STATE_MASK              0xF0000000UL
#define MFI_STATE_UNDEFINED         0x00000000UL
#define MFI_STATE_BB_INIT           0x10000000UL
#define MFI_STATE_FW_INIT           0x40000000UL
#define MFI_STATE_WAIT_HANDSHAKE    0x60000000UL
#define MFI_STATE_FW_INIT_2         0x70000000UL
#define MFI_STATE_DEVICE_SCAN       0x80000000UL
#define MFI_STATE_BOOT_MSG_PENDING  0x90000000UL
#define MFI_STATE_FLUSH_CACHE       0xA0000000UL
#define MFI_STATE_READY             0xB0000000UL
#define MFI_STATE_OPERATIONAL       0xC0000000UL
#define MFI_STATE_FAULT             0xF0000000UL
#define MFI_STATE_MAXSGL_MASK       0x00FF0000UL
#define MFI_STATE_MAXCMD_MASK       0x0000FFFFUL

#define MFI_INIT_READY              0x00000002UL
#define MFI_INIT_CLEAR_HANDSHAKE    0x00000008UL

/* Frame flags */
#define MFI_FRAME_DONT_POST_IN_REPLY_QUEUE  0x0001
#define MFI_FRAME_SGL64             0x0002
#define MFI_FRAME_DIR_WRITE         0x0008
#define MFI_FRAME_DIR_READ          0x0010

/* Commands */
#define MFI_CMD_INIT                0x00
#define MFI_CMD_LD_SCSI_IO          0x03
#define MFI_CMD_DCMD                0x05

#define MR_DCMD_CTRL_CACHE_FLUSH    0x01101000UL
#define MR_FLUSH_CTRL_CACHE         0x01
#define MR_FLUSH_DISK_CACHE         0x02

/* Command status */
#define MFI_STAT_OK                 0x00
#define MFI_STAT_DEVICE_NOT_FOUND   0x0C
#define MFI_STAT_SCSI_DONE_WITH_ERROR 0x2D
#define MFI_STAT_PENDING            0xFF    /* written by the driver, replaced by the controller */

#define MFI_INVALID_CTX             0xFFFFFFFFUL
#define MFI_FRAME_SIZE              64
#define MFI_SENSE_SIZE              128

#include <pshpack1.h>

typedef struct _MFI_SG64
{
    ULONGLONG Addr;
    ULONG Len;
} MFI_SG64, *PMFI_SG64;

typedef struct _MFI_HEADER
{
    UCHAR Cmd;
    UCHAR SenseLen;
    UCHAR CmdStatus;
    UCHAR ScsiStatus;
    UCHAR TargetId;
    UCHAR LunId;
    UCHAR CdbLen;
    UCHAR SgCount;
    ULONG Context;
    ULONG Pad0;
    USHORT Flags;
    USHORT Timeout;
    ULONG DataLen;
} MFI_HEADER, *PMFI_HEADER;

typedef struct _MFI_INIT_FRAME
{
    MFI_HEADER Header;
    ULONGLONG QinfoNewAddr;
    ULONGLONG QinfoOldAddr;
    ULONG Reserved[6];
} MFI_INIT_FRAME, *PMFI_INIT_FRAME;

typedef struct _MFI_INIT_QINFO
{
    ULONG Flags;
    ULONG RqEntries;
    ULONGLONG RqAddr;
    ULONGLONG PiAddr;
    ULONGLONG CiAddr;
} MFI_INIT_QINFO, *PMFI_INIT_QINFO;

typedef struct _MFI_PASS_FRAME
{
    MFI_HEADER Header;
    ULONGLONG SenseAddr;
    UCHAR Cdb[16];
    MFI_SG64 Sgl[1];
} MFI_PASS_FRAME, *PMFI_PASS_FRAME;

typedef struct _MFI_DCMD_FRAME
{
    MFI_HEADER Header;
    ULONG Opcode;
    UCHAR Mbox[12];
} MFI_DCMD_FRAME, *PMFI_DCMD_FRAME;

#include <poppack.h>

C_ASSERT(sizeof(MFI_SG64) == 12);
C_ASSERT(sizeof(MFI_HEADER) == 24);
C_ASSERT(sizeof(MFI_INIT_FRAME) == 64);
C_ASSERT(sizeof(MFI_INIT_QINFO) == 32);
C_ASSERT(FIELD_OFFSET(MFI_PASS_FRAME, Sgl) == 48);
C_ASSERT(sizeof(MFI_DCMD_FRAME) == 40);

/* Driver layout */
#define MFI_MAX_REQS                64              /* requests in flight */
#define MFI_FRAME_BYTES             512             /* eight frames of 64 bytes: the request and its scatter/gather list */
#define MFI_BUNDLE_SIZE             (MFI_FRAME_BYTES + MFI_SENSE_SIZE)
#define MFI_MAX_SEGS                33              /* data elements per request: 48 + 33 * 12 bytes fit in the frames */
#define MFI_MAX_TARGETS             64              /* logical drives */
#define MFI_MAX_FW_CMDS             1024            /* the reply queue has as many entries as the firmware has commands */
#define MFI_MAX_REPLIES             MFI_MAX_FW_CMDS

/* The uncached extension: one bundle per request, one for the internal request, the reply queue */
#define MFI_BUNDLE_INTERNAL         MFI_MAX_REQS
#define MFI_OFF_REPLYQ              ((MFI_MAX_REQS + 1) * MFI_BUNDLE_SIZE)
#define MFI_MEM_SIZE                ((MFI_OFF_REPLYQ + 2 * sizeof(ULONG) + MFI_MAX_REPLIES * sizeof(ULONG) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

C_ASSERT((MFI_BUNDLE_SIZE % MFI_FRAME_SIZE) == 0);
C_ASSERT(sizeof(MFI_PASS_FRAME) - sizeof(MFI_SG64) + MFI_MAX_SEGS * sizeof(MFI_SG64) <= MFI_FRAME_BYTES);

/* Bounds on waiting for the controller, in microseconds */
#define MFI_WAIT_STEP               100
#define MFI_WAIT_STATE              5000000
#define MFI_WAIT_INIT               5000000

typedef struct _MFI_REPLYQ
{
    ULONG Producer;
    ULONG Consumer;
    ULONG Context[MFI_MAX_REPLIES];
} MFI_REPLYQ, *PMFI_REPLYQ;

typedef struct _MFI_SLOT
{
    PSCSI_REQUEST_BLOCK Srb;
    ULONG Generation;
} MFI_SLOT;

typedef struct _MFI_EXTENSION
{
    PUCHAR Regs;
    ULONGLONG RegsPa;
    PUCHAR Mem;
    ULONGLONG MemPa;
    ULONG IntrValid;            /* the bits of OSTS that mean "this controller interrupted" */
    ULONG IntrMask;             /* value for OMSK that enables the interrupt */
    ULONG NumReqs;
    ULONG NumReplies;
    ULONG MaxSegs;
    ULONG Consumer;
    ULONG FreeCount;
    BOOLEAN Throttled;
    BOOLEAN BadQueueReported;
    BOOLEAN SenseReported;
    UCHAR FreeStack[MFI_MAX_REQS];
    MFI_SLOT Slots[MFI_MAX_REQS];
} MFI_EXTENSION, *PMFI_EXTENSION;

static ULONG
MfiRead(PMFI_EXTENSION Ext, ULONG Reg)
{
    return ScsiPortReadRegisterUlong((PULONG)(Ext->Regs + Reg));
}

static VOID
MfiWrite(PMFI_EXTENSION Ext, ULONG Reg, ULONG Value)
{
    ScsiPortWriteRegisterUlong((PULONG)(Ext->Regs + Reg), Value);
}

static PUCHAR
MfiBundle(PMFI_EXTENSION Ext, ULONG Index)
{
    return Ext->Mem + Index * MFI_BUNDLE_SIZE;
}

static ULONGLONG
MfiBundlePa(PMFI_EXTENSION Ext, ULONG Index)
{
    return Ext->MemPa + Index * MFI_BUNDLE_SIZE;
}

static PMFI_REPLYQ
MfiReplyQ(PMFI_EXTENSION Ext)
{
    return (PMFI_REPLYQ)(Ext->Mem + MFI_OFF_REPLYQ);
}

/* Wait until the firmware state leaves Current. The state register reads all ones when the device is gone,
   which is the fault state. */
static ULONG
MfiWaitStateChange(PMFI_EXTENSION Ext, ULONG Current, ULONG Microseconds)
{
    ULONG Waited, State = MfiRead(Ext, MFI_REG_OSP) & MFI_STATE_MASK;

    for (Waited = 0; State == Current && Waited < Microseconds; Waited += MFI_WAIT_STEP)
    {
        ScsiPortStallExecution(MFI_WAIT_STEP);
        State = MfiRead(Ext, MFI_REG_OSP) & MFI_STATE_MASK;
    }
    return State;
}

/* Bring the firmware to the READY state (the sequence of the OpenBSD driver, with bounded waits) */
static BOOLEAN
MfiTransitionToReady(PMFI_EXTENSION Ext)
{
    ULONG State = MfiRead(Ext, MFI_REG_OSP) & MFI_STATE_MASK;
    ULONG Steps;

    for (Steps = 0; Steps < 16 && State != MFI_STATE_READY; Steps++)
    {
        ULONG Current = State;
        ULONG Wait = MFI_WAIT_STATE;

        switch (State)
        {
            case MFI_STATE_WAIT_HANDSHAKE:
                MfiWrite(Ext, MFI_REG_IDB, MFI_INIT_CLEAR_HANDSHAKE);
                break;
            case MFI_STATE_OPERATIONAL:
                MfiWrite(Ext, MFI_REG_IDB, MFI_INIT_READY);
                break;
            case MFI_STATE_UNDEFINED:
            case MFI_STATE_BB_INIT:
            case MFI_STATE_FW_INIT:
            case MFI_STATE_FW_INIT_2:
            case MFI_STATE_DEVICE_SCAN:
            case MFI_STATE_BOOT_MSG_PENDING:
            case MFI_STATE_FLUSH_CACHE:
                break;
            default:
                return FALSE;                   /* the fault state, or a value that is not a state */
        }
        State = MfiWaitStateChange(Ext, Current, Wait);
        if (State == Current)
            return FALSE;                       /* stuck */
    }
    return State == MFI_STATE_READY;
}

/* Hand a frame to the firmware: the address (below 4 GB), a valid bit and the number of extra frames */
static VOID
MfiPost(PMFI_EXTENSION Ext, ULONG Index, ULONG ExtraFrames)
{
    KeMemoryBarrier();
    MfiWrite(Ext, MFI_REG_IQP, (ULONG)MfiBundlePa(Ext, Index) | 0x1 | (ExtraFrames << 1));
}

/* Tell the firmware where the reply queue is (the init frame), polled */
static BOOLEAN
MfiInitFirmware(PMFI_EXTENSION Ext)
{
    PMFI_INIT_FRAME Frame = (PMFI_INIT_FRAME)MfiBundle(Ext, MFI_BUNDLE_INTERNAL);
    PMFI_INIT_QINFO Qinfo = (PMFI_INIT_QINFO)((PUCHAR)Frame + MFI_FRAME_SIZE);
    ULONGLONG FramePa = MfiBundlePa(Ext, MFI_BUNDLE_INTERNAL);
    ULONGLONG QueuePa = Ext->MemPa + MFI_OFF_REPLYQ;
    ULONG Waited;

    RtlZeroMemory(Frame, MFI_FRAME_SIZE + sizeof(*Qinfo));
    Qinfo->RqEntries = Ext->NumReplies;
    Qinfo->RqAddr = QueuePa + FIELD_OFFSET(MFI_REPLYQ, Context);
    Qinfo->PiAddr = QueuePa + FIELD_OFFSET(MFI_REPLYQ, Producer);
    Qinfo->CiAddr = QueuePa + FIELD_OFFSET(MFI_REPLYQ, Consumer);

    Frame->Header.Cmd = MFI_CMD_INIT;
    Frame->Header.Context = MFI_INVALID_CTX;
    Frame->Header.DataLen = sizeof(*Qinfo);
    Frame->Header.Flags = MFI_FRAME_DONT_POST_IN_REPLY_QUEUE;
    Frame->QinfoNewAddr = FramePa + MFI_FRAME_SIZE;
    Frame->Header.CmdStatus = MFI_STAT_PENDING;

    MfiPost(Ext, MFI_BUNDLE_INTERNAL, 1);       /* the frame and the queue description behind it */

    for (Waited = 0; Waited < MFI_WAIT_INIT; Waited += MFI_WAIT_STEP)
    {
        KeMemoryBarrier();
        if (*(volatile UCHAR *)&Frame->Header.CmdStatus != MFI_STAT_PENDING)
            return *(volatile UCHAR *)&Frame->Header.CmdStatus == MFI_STAT_OK;
        if (MfiRead(Ext, MFI_REG_OSP) == 0xFFFFFFFFUL)
            return FALSE;
        ScsiPortStallExecution(MFI_WAIT_STEP);
    }
    return FALSE;
}

static VOID
MfiEnableInterrupts(PMFI_EXTENSION Ext)
{
    MfiWrite(Ext, MFI_REG_ODC, 0xFFFFFFFFUL);
    MfiWrite(Ext, MFI_REG_OMSK, Ext->IntrMask);
}

static BOOLEAN
MfiStartAdapter(PMFI_EXTENSION Ext)
{
    ULONG Status, Index, MaxCmds, MaxSgl;
    PMFI_REPLYQ Queue;

    MfiWrite(Ext, MFI_REG_OMSK, 0xFFFFFFFFUL);      /* interrupts off until the queue is set up */

    if (!MfiTransitionToReady(Ext))
    {
        DbgPrint("megasas: the firmware does not become ready (state register %lx)\n", MfiRead(Ext, MFI_REG_OSP));
        return FALSE;
    }

    Status = MfiRead(Ext, MFI_REG_OSP);
    MaxCmds = Status & MFI_STATE_MAXCMD_MASK;
    MaxSgl = (Status & MFI_STATE_MAXSGL_MASK) >> 16;
    if (MaxCmds < 2 || MaxSgl < 2)
    {
        DbgPrint("megasas: the firmware reports %lu commands and %lu scatter/gather elements\n", MaxCmds, MaxSgl);
        return FALSE;
    }

    if (MaxCmds > MFI_MAX_FW_CMDS)
        return FALSE;
    Ext->NumReqs = min(MaxCmds - 1, (ULONG)MFI_MAX_REQS);   /* the firmware keeps one command for itself */
    Ext->NumReplies = MaxCmds;                              /* the queue may not be longer than the firmware's command limit */
    Ext->MaxSegs = min(MaxSgl, (ULONG)MFI_MAX_SEGS);

    Queue = MfiReplyQ(Ext);
    Queue->Producer = 0;
    Queue->Consumer = 0;
    for (Index = 0; Index < MFI_MAX_REPLIES; Index++)
        Queue->Context[Index] = MFI_INVALID_CTX;
    Ext->Consumer = 0;

    if (!MfiInitFirmware(Ext))
    {
        DbgPrint("megasas: the firmware does not take the queue description\n");
        return FALSE;
    }

    for (Index = 0; Index < Ext->NumReqs; Index++)
        Ext->FreeStack[Index] = (UCHAR)(Ext->NumReqs - 1 - Index);
    Ext->FreeCount = Ext->NumReqs;
    Ext->Throttled = FALSE;
    return TRUE;
}

static VOID
MfiCompleteSrb(PMFI_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb, UCHAR Status)
{
    Srb->SrbStatus = Status;
    ScsiPortNotification(RequestComplete, Ext, Srb);
}

/* One context from the reply queue. It comes from the device: never trust it. */
static VOID
MfiHandleReply(PMFI_EXTENSION Ext, ULONG Context)
{
    ULONG Index = Context & 0xFF;
    PMFI_HEADER Header;
    PSCSI_REQUEST_BLOCK Srb;
    UCHAR Status, CmdStatus;

    if (Index >= Ext->NumReqs || Ext->Slots[Index].Srb == NULL || Ext->Slots[Index].Generation != (Context >> 8))
    {
        DbgPrint("megasas: completion for unknown request %lx ignored\n", Context);
        return;
    }

    Srb = Ext->Slots[Index].Srb;
    Ext->Slots[Index].Srb = NULL;
    Ext->FreeStack[Ext->FreeCount++] = (UCHAR)Index;

    Header = (PMFI_HEADER)MfiBundle(Ext, Index);
    CmdStatus = Header->CmdStatus;

    switch (CmdStatus)
    {
        case MFI_STAT_OK:
            Srb->ScsiStatus = SCSISTAT_GOOD;
            Status = SRB_STATUS_SUCCESS;
            break;

        case MFI_STAT_DEVICE_NOT_FOUND:
            Srb->ScsiStatus = SCSISTAT_GOOD;
            Status = SRB_STATUS_SELECTION_TIMEOUT;
            break;

        default:
        {
            ULONG SenseLen = Header->SenseLen;

            Srb->ScsiStatus = Header->ScsiStatus;
            Status = SRB_STATUS_ERROR;
            if (CmdStatus == MFI_STAT_SCSI_DONE_WITH_ERROR && Srb->ScsiStatus == SCSISTAT_GOOD)
                Srb->ScsiStatus = SCSISTAT_CHECK_CONDITION;
            if (Srb->ScsiStatus == SCSISTAT_BUSY || Srb->ScsiStatus == SCSISTAT_QUEUE_FULL)
                Status = SRB_STATUS_BUSY;
            else if (Srb->ScsiStatus == SCSISTAT_CHECK_CONDITION && SenseLen != 0 && Srb->SenseInfoBuffer != NULL &&
                     !(Srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE))
            {
                /* the length is written by the controller: bounded by the slot and by the buffer of the request */
                ULONG Copy = min(SenseLen, (ULONG)MFI_SENSE_SIZE);

                Copy = min(Copy, Srb->SenseInfoBufferLength);
                if (!Ext->SenseReported)
                {
                    Ext->SenseReported = TRUE;
                    DbgPrint("megasas: first request that ends with sense data (%lu bytes)\n", Copy);
                }
                RtlCopyMemory(Srb->SenseInfoBuffer, MfiBundle(Ext, Index) + MFI_FRAME_BYTES, Copy);
                Srb->SenseInfoBufferLength = (UCHAR)Copy;
                Status |= SRB_STATUS_AUTOSENSE_VALID;
            }
            break;
        }
    }

    MfiCompleteSrb(Ext, Srb, Status);
}

/* Handle what the controller has put in the reply queue. Both indices are checked and the loop is bounded. */
static VOID
MfiProcessReplies(PMFI_EXTENSION Ext)
{
    PMFI_REPLYQ Queue = MfiReplyQ(Ext);
    ULONG Producer, Consumer = Ext->Consumer, Budget;

    KeMemoryBarrier();
    Producer = *(volatile ULONG *)&Queue->Producer;
    if (Producer >= Ext->NumReplies)
    {
        if (!Ext->BadQueueReported)
        {
            Ext->BadQueueReported = TRUE;
            DbgPrint("megasas: reply queue producer index %lx is out of range, ignored\n", Producer);
        }
        return;
    }

    for (Budget = 0; Consumer != Producer && Budget < Ext->NumReplies; Budget++)
    {
        ULONG Context = Queue->Context[Consumer];

        Queue->Context[Consumer] = MFI_INVALID_CTX;
        Consumer++;
        if (Consumer == Ext->NumReplies)
            Consumer = 0;

        if (Context != MFI_INVALID_CTX)
            MfiHandleReply(Ext, Context);
    }

    Ext->Consumer = Consumer;
    Queue->Consumer = Consumer;
    KeMemoryBarrier();

    if (Ext->Throttled && Ext->FreeCount != 0)
    {
        Ext->Throttled = FALSE;
        ScsiPortNotification(NextRequest, Ext, NULL);
    }
}

/* Build the scatter/gather list behind the frame head. Returns the number of elements, or 0 when the buffer
   does not fit. */
static ULONG
MfiBuildSgl(PMFI_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb, PMFI_SG64 Sgl)
{
    PUCHAR Va = Srb->DataBuffer;
    ULONG Remaining = Srb->DataTransferLength;
    ULONG Count = 0;

    while (Remaining != 0)
    {
        ULONG Chunk = 0;
        SCSI_PHYSICAL_ADDRESS Pa = ScsiPortGetPhysicalAddress(Ext, Srb, Va, &Chunk);

        if (Chunk == 0 || Pa.QuadPart == (LONGLONG)SP_UNINITIALIZED_VALUE)
            return 0;
        Chunk = min(Chunk, Remaining);

        if (Count != 0 && Sgl[Count - 1].Addr + Sgl[Count - 1].Len == (ULONGLONG)Pa.QuadPart &&
            (ULONGLONG)Sgl[Count - 1].Len + Chunk <= 0x7FFFFFFF)
        {
            Sgl[Count - 1].Len += Chunk;
        }
        else
        {
            if (Count == Ext->MaxSegs)
                return 0;
            Sgl[Count].Addr = (ULONGLONG)Pa.QuadPart;
            Sgl[Count].Len = Chunk;
            Count++;
        }
        Va += Chunk;
        Remaining -= Chunk;
    }
    return Count;
}

static BOOLEAN
MfiExecuteScsi(PMFI_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb)
{
    PMFI_HEADER Header;
    ULONG Index, Generation, Count = 0, FrameBytes;
    ULONGLONG BundlePa;

    if (Srb->PathId != 0 || Srb->TargetId >= MFI_MAX_TARGETS || Srb->Lun != 0)
    {
        MfiCompleteSrb(Ext, Srb, SRB_STATUS_NO_DEVICE);
        goto Next;
    }
    if (Srb->CdbLength == 0 || Srb->CdbLength > 16)
    {
        MfiCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
        goto Next;
    }
    if (Ext->FreeCount == 0)
    {
        /* The port should not send more than it was told to: ask for a retry and stop the flow */
        Ext->Throttled = TRUE;
        MfiCompleteSrb(Ext, Srb, SRB_STATUS_BUSY);
        return TRUE;
    }

    Index = Ext->FreeStack[Ext->FreeCount - 1];
    Header = (PMFI_HEADER)MfiBundle(Ext, Index);
    BundlePa = MfiBundlePa(Ext, Index);
    RtlZeroMemory(Header, MFI_FRAME_SIZE);

    Generation = (Ext->Slots[Index].Generation + 1) & 0xFFFFFF;

    if (Srb->Cdb[0] == SCSIOP_SYNCHRONIZE_CACHE)
    {
        PMFI_DCMD_FRAME Dcmd = (PMFI_DCMD_FRAME)Header;

        Dcmd->Header.Cmd = MFI_CMD_DCMD;
        Dcmd->Opcode = MR_DCMD_CTRL_CACHE_FLUSH;
        Dcmd->Mbox[0] = MR_FLUSH_CTRL_CACHE | MR_FLUSH_DISK_CACHE;
        FrameBytes = sizeof(MFI_DCMD_FRAME);
    }
    else
    {
        PMFI_PASS_FRAME Pass = (PMFI_PASS_FRAME)Header;

        /* every command, reads and writes too, goes to the logical drive as a pass-through frame with its CDB */
        if (Srb->DataTransferLength != 0)
        {
            Count = MfiBuildSgl(Ext, Srb, Pass->Sgl);
            if (Count == 0)
            {
                MfiCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
                goto Next;
            }
        }
        Pass->Header.Cmd = MFI_CMD_LD_SCSI_IO;
        Pass->Header.CdbLen = Srb->CdbLength;
        Pass->Header.DataLen = Srb->DataTransferLength;
        Pass->SenseAddr = BundlePa + MFI_FRAME_BYTES;
        RtlCopyMemory(Pass->Cdb, Srb->Cdb, Srb->CdbLength);
        FrameBytes = FIELD_OFFSET(MFI_PASS_FRAME, Sgl) + Count * sizeof(MFI_SG64);

        if (Count != 0)
        {
            Header->Flags = MFI_FRAME_SGL64;
            if (Srb->SrbFlags & SRB_FLAGS_DATA_IN)
                Header->Flags |= MFI_FRAME_DIR_READ;
            else
                Header->Flags |= MFI_FRAME_DIR_WRITE;
            Header->SgCount = (UCHAR)Count;
        }
    }

    Ext->FreeCount--;
    Ext->Slots[Index].Generation = Generation;
    Ext->Slots[Index].Srb = Srb;

    Header->TargetId = Srb->TargetId;
    Header->SenseLen = MFI_SENSE_SIZE;
    Header->Context = (Generation << 8) | Index;
    Header->CmdStatus = MFI_STAT_PENDING;

    MfiPost(Ext, Index, (FrameBytes - 1) / MFI_FRAME_SIZE);

    if (Ext->FreeCount != 0)
        ScsiPortNotification(NextLuRequest, Ext, Srb->PathId, Srb->TargetId, Srb->Lun);
    else
        Ext->Throttled = TRUE;
    return TRUE;

Next:
    ScsiPortNotification(NextRequest, Ext, NULL);
    return TRUE;
}

/* Fail what is outstanding and start the controller again: the one recovery the driver has (bus reset,
   device reset, restart after the power state changed) */
static BOOLEAN
MfiReinitialize(PMFI_EXTENSION Ext, ULONG PathId)
{
    ULONG Index;
    BOOLEAN Ok;

    ScsiPortCompleteRequest(Ext, (UCHAR)PathId, SP_UNTAGGED, SP_UNTAGGED, SRB_STATUS_BUS_RESET);
    for (Index = 0; Index < MFI_MAX_REQS; Index++)
    {
        /* whatever the controller still reports for the old requests is ignored: the generation no longer matches */
        Ext->Slots[Index].Srb = NULL;
        Ext->Slots[Index].Generation++;
    }

    /* the firmware is taken back to ready (that drops the commands it still holds) and to operational again */
    Ok = MfiStartAdapter(Ext);
    DbgPrint("megasas: reset of the bus, the controller was started again (%s)\n", Ok ? "ok" : "failed");
    if (Ok)
        MfiEnableInterrupts(Ext);
    return Ok;
}

static BOOLEAN NTAPI
MfiStartIo(PVOID HwDeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
    PMFI_EXTENSION Ext = HwDeviceExtension;

    switch (Srb->Function)
    {
        case SRB_FUNCTION_EXECUTE_SCSI:
            return MfiExecuteScsi(Ext, Srb);

        case SRB_FUNCTION_RESET_DEVICE:
            /* the controller is started again: that ends every command of the device, and of the others */
            MfiReinitialize(Ext, Srb->PathId);
            MfiCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;

        case SRB_FUNCTION_ABORT_COMMAND:
            /* no abort by tag here: the port escalates to a bus reset */
            MfiCompleteSrb(Ext, Srb, SRB_STATUS_ABORT_FAILED);
            break;

        case SRB_FUNCTION_FLUSH:
        case SRB_FUNCTION_SHUTDOWN:
            /* the disk caches are flushed by SYNCHRONIZE CACHE */
            MfiCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;

        default:
            MfiCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
            break;
    }

    ScsiPortNotification(NextRequest, Ext, NULL);
    return TRUE;
}

static BOOLEAN NTAPI
MfiInterrupt(PVOID HwDeviceExtension)
{
    PMFI_EXTENSION Ext = HwDeviceExtension;
    ULONG Status = MfiRead(Ext, MFI_REG_OSTS);

    if (Status == 0xFFFFFFFFUL || (Status & Ext->IntrValid) == 0)
        return FALSE;

    MfiWrite(Ext, MFI_REG_ODC, Status);         /* acknowledge */
    MfiProcessReplies(Ext);
    return TRUE;
}

static BOOLEAN NTAPI
MfiResetBus(PVOID HwDeviceExtension, ULONG PathId)
{
    return MfiReinitialize(HwDeviceExtension, PathId);
}

static BOOLEAN NTAPI
MfiInitialize(PVOID HwDeviceExtension)
{
    /* the controller was started in HwFindAdapter; the interrupt is connected by now */
    MfiEnableInterrupts(HwDeviceExtension);
    return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS NTAPI
MfiAdapterControl(PVOID HwDeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
{
    PMFI_EXTENSION Ext = HwDeviceExtension;

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
            MfiWrite(Ext, MFI_REG_OMSK, 0xFFFFFFFFUL);
            return ScsiAdapterControlSuccess;

        case ScsiRestartAdapter:
            if (!MfiStartAdapter(Ext))
                return ScsiAdapterControlUnsuccessful;
            MfiEnableInterrupts(Ext);
            return ScsiAdapterControlSuccess;

        default:
            return ScsiAdapterControlUnsuccessful;
    }
}

/* Make sure the controller decodes its registers and may master the bus: a firmware that has no driver for the device (UEFI
   boots without a megasas driver) leaves the decode and bus master bits off. */
static VOID
MfiEnableDevice(PVOID Ext, PPORT_CONFIGURATION_INFORMATION ConfigInfo)
{
    PCI_COMMON_CONFIG Pci;
    USHORT Command;

    if (ScsiPortGetBusData(Ext, PCIConfiguration, ConfigInfo->SystemIoBusNumber, ConfigInfo->SlotNumber, &Pci,
                           sizeof(Pci)) < FIELD_OFFSET(PCI_COMMON_CONFIG, Status))
        return;

    Command = Pci.Command | PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE | PCI_ENABLE_BUS_MASTER;
    if (Command != Pci.Command)
        ScsiPortSetBusDataByOffset(Ext, PCIConfiguration, ConfigInfo->SystemIoBusNumber, ConfigInfo->SlotNumber,
                                   &Command, FIELD_OFFSET(PCI_COMMON_CONFIG, Command), sizeof(Command));
}

/* The port hands over a 64-bit memory BAR above 4 GB with the upper half cut off (the controller sits there on a machine
   with a large address space: QEMU q35). When the cut address is the lower half of such a BAR, the address is taken from
   the BAR itself. */
static ULONGLONG
MfiRegisterBase(PVOID Ext, PPORT_CONFIGURATION_INFORMATION ConfigInfo, PACCESS_RANGE Range)
{
    PCI_COMMON_CONFIG Pci;
    ULONG i;

    if (ScsiPortGetBusData(Ext, PCIConfiguration, ConfigInfo->SystemIoBusNumber, ConfigInfo->SlotNumber, &Pci,
                           sizeof(Pci)) < sizeof(Pci))
        return (ULONGLONG)Range->RangeStart.QuadPart;

    for (i = 0; i + 1 < PCI_TYPE0_ADDRESSES; i++)
    {
        ULONG Bar = Pci.u.type0.BaseAddresses[i];

        if ((Bar & 1) == 0 && (Bar & 6) == 4)
        {
            ULONGLONG Full = ((ULONGLONG)Pci.u.type0.BaseAddresses[i + 1] << 32) | (Bar & ~0xFUL);

            if (Full != (ULONGLONG)Range->RangeStart.QuadPart && (ULONG)Full == Range->RangeStart.LowPart)
            {
                DbgPrint("megasas: the port reports the registers at %lx, the BAR says %I64x\n", Range->RangeStart.LowPart, Full);
                return Full;
            }
            i++;
        }
    }
    return (ULONGLONG)Range->RangeStart.QuadPart;
}

static ULONG NTAPI
MfiFindAdapter(
    IN PVOID HwDeviceExtension,
    IN PVOID Context,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again)
{
    PMFI_EXTENSION Ext = HwDeviceExtension;
    PACCESS_RANGE Range = NULL;
    SCSI_PHYSICAL_ADDRESS Pa, RegsAddress;
    ULONG Length = 0;
    ULONG i;
    BOOLEAN Gen2 = (Context != NULL);

    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);

    *Again = FALSE;
    MfiEnableDevice(Ext, ConfigInfo);

    /* The registers are in a memory BAR of 8 KB or more; the I/O port BAR and the 256 KB queue BAR are not used */
    for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
    {
        PACCESS_RANGE R = &(*ConfigInfo->AccessRanges)[i];

        if (R->RangeInMemory && R->RangeLength >= MFI_REGS_LENGTH && R->RangeLength <= 0x10000)
        {
            Range = R;
            break;
        }
    }
    if (Range == NULL)
    {
        DbgPrint("megasas: no register range among %lu\n", ConfigInfo->NumberOfAccessRanges);
        return SP_RETURN_NOT_FOUND;
    }

    Ext->RegsPa = MfiRegisterBase(Ext, ConfigInfo, Range);
    RegsAddress.QuadPart = (LONGLONG)Ext->RegsPa;

    if (!ScsiPortValidateRange(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                               RegsAddress, Range->RangeLength, FALSE))
        return SP_RETURN_BAD_CONFIG;

    Ext->Regs = ScsiPortGetDeviceBase(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                                      RegsAddress, Range->RangeLength, FALSE);
    if (Ext->Regs == NULL)
    {
        DbgPrint("megasas: cannot map the registers\n");
        return SP_RETURN_ERROR;
    }

    if (Gen2)
    {
        Ext->IntrValid = MFI_OSTS_GEN2_INTR_VALID;
        Ext->IntrMask = ~MFI_OSTS_GEN2_INTR_VALID;
    }
    else
    {
        Ext->IntrValid = MFI_OSTS_PPC_INTR_VALID;
        Ext->IntrMask = ~(MFI_OSTS_PPC_INTR_VALID | 0x4UL);
    }

    ConfigInfo->NumberOfBuses = 1;
    ConfigInfo->MaximumNumberOfTargets = MFI_MAX_TARGETS;
    ConfigInfo->MaximumNumberOfLogicalUnits = 1;
    ConfigInfo->MaximumTransferLength = (MFI_MAX_SEGS - 1) * PAGE_SIZE;
    ConfigInfo->NumberOfPhysicalBreaks = MFI_MAX_SEGS - 1;
    ConfigInfo->ScatterGather = TRUE;
    ConfigInfo->Master = TRUE;
    ConfigInfo->NeedPhysicalAddresses = TRUE;
    ConfigInfo->Dma32BitAddresses = TRUE;
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;     /* the data elements take 64-bit addresses */
    ConfigInfo->TaggedQueuing = TRUE;
    ConfigInfo->MultipleRequestPerLu = TRUE;
    ConfigInfo->AlignmentMask = 0;
    ConfigInfo->InterruptMode = LevelSensitive;
    ConfigInfo->WmiDataProvider = FALSE;

    Ext->Mem = ScsiPortGetUncachedExtension(Ext, ConfigInfo, MFI_MEM_SIZE);
    if (Ext->Mem == NULL)
    {
        DbgPrint("megasas: no uncached extension\n");
        return SP_RETURN_ERROR;
    }

    /* The frames are posted through a 32-bit register: the block must be contiguous, aligned and below 4 GB */
    Pa = ScsiPortGetPhysicalAddress(Ext, NULL, Ext->Mem, &Length);
    if (Length < MFI_MEM_SIZE || (Pa.QuadPart & (PAGE_SIZE - 1)) != 0 ||
        (ULONGLONG)Pa.QuadPart + MFI_MEM_SIZE > 0x100000000ULL)
    {
        DbgPrint("megasas: the uncached extension is not usable (%I64x, %lu bytes)\n", (ULONGLONG)Pa.QuadPart, Length);
        return SP_RETURN_ERROR;
    }
    Ext->MemPa = (ULONGLONG)Pa.QuadPart;

    if (!MfiStartAdapter(Ext))
    {
        DbgPrint("megasas: the controller does not start (registers at %I64x, %lu bytes)\n", Ext->RegsPa, Range->RangeLength);
        return SP_RETURN_ERROR;
    }

    /* Ask to be called again: the port looks for the next controller of this kind on the bus */
    *Again = TRUE;
    return SP_RETURN_FOUND;
}

static NTSTATUS
MfiInitialization(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath, PUCHAR DeviceId, PVOID HwContext)
{
    HW_INITIALIZATION_DATA Init;
    UCHAR VendorId[4] = { '1', '0', '0', '0' };

    RtlZeroMemory(&Init, sizeof(Init));
    Init.HwInitializationDataSize = sizeof(Init);
    Init.HwInitialize = MfiInitialize;
    Init.HwStartIo = MfiStartIo;
    Init.HwInterrupt = MfiInterrupt;
    Init.HwFindAdapter = MfiFindAdapter;
    Init.HwResetBus = MfiResetBus;
    Init.HwAdapterControl = MfiAdapterControl;
    Init.AdapterInterfaceType = PCIBus;
    Init.VendorId = VendorId;
    Init.VendorIdLength = sizeof(VendorId);
    Init.DeviceId = DeviceId;
    Init.DeviceIdLength = 4;
    Init.NumberOfAccessRanges = 6;
    Init.DeviceExtensionSize = sizeof(MFI_EXTENSION);
    Init.SrbExtensionSize = 0;
    Init.NeedPhysicalAddresses = TRUE;
    Init.TaggedQueuing = TRUE;
    Init.MultipleRequestPerLu = TRUE;
    Init.AutoRequestSense = TRUE;

    return ScsiPortInitialize(DriverObject, RegistryPath, &Init, HwContext);
}

NTSTATUS NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UCHAR Id1078[4] = { '0', '0', '6', '0' };
    UCHAR Id2108[4] = { '0', '0', '7', '9' };
    NTSTATUS Status1, Status2;

    /* One pass per controller family: the registers differ in the interrupt bits */
    Status1 = MfiInitialization(DriverObject, RegistryPath, Id1078, NULL);
    Status2 = MfiInitialization(DriverObject, RegistryPath, Id2108, (PVOID)1);

    return NT_SUCCESS(Status1) ? Status1 : Status2;
}
