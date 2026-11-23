/*
 * PROJECT:     ReactOS LSI Logic Fusion-MPT SAS SCSI miniport driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SCSI port miniport for the LSI Logic SAS1068 controller (PCI 1000:0054), the SCSI
 *              controller that VMware offers for Windows guests and that QEMU emulates as mptsas1068
 * COPYRIGHT:   Copyright 2026 ReactOS Project contributors
 *
 * The register offsets, the doorbell and reply queue bits, the message function numbers and the
 * layouts of the messages (IOC facts, IOC init, port facts, port enable, SCSI I/O request and its
 * error reply) and of the scatter/gather elements below describe the Fusion-MPT interface. They
 * were taken from the OpenBSD driver mpi(4), sys/dev/ic/mpireg.h revision 1.45 and the
 * initialisation sequence of sys/dev/ic/mpi.c revision 1.226, which carry this notice:
 *
 *   Copyright (c) 2005, 2006, 2009 David Gwynne <dlg@openbsd.org>
 *   Copyright (c) 2005, 2008, 2009 Marco Peereboom <marco@openbsd.org>
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
 * The driver code itself is new. It uses the legacy SCSI port interface like the BusLogic and
 * PVSCSI miniports: one bus, one logical unit per target, INTx interrupts, one request frame
 * (with its scatter/gather list and sense slot) per request in flight, no events (no hot plug),
 * no configuration pages. Everything that the device writes (reply addresses, contexts, lengths,
 * the sizes reported by the controller) is validated before it is used, and every wait on the
 * device is bounded.
 */

#include <ntddk.h>
#include <srb.h>
#include <scsi.h>

#define MPT_TAG                     'tpMS'

/* Registers (BAR1, 16 KB) */
#define MPT_REG_DOORBELL            0x00
#define MPT_REG_WRITESEQ            0x04
#define MPT_REG_HOSTDIAG            0x08
#define MPT_REG_INTR_STATUS         0x30
#define MPT_REG_INTR_MASK           0x34
#define MPT_REG_REQ_QUEUE           0x40
#define MPT_REG_REPLY_QUEUE         0x44
#define MPT_REGS_LENGTH             0x100

#define MPT_DB_STATE                (0xFUL << 28)
#define MPT_DB_STATE_RESET          (0x0UL << 28)
#define MPT_DB_STATE_READY          (0x1UL << 28)
#define MPT_DB_STATE_OPER           (0x2UL << 28)
#define MPT_DB_STATE_FAULT          (0x4UL << 28)
#define MPT_DB_INUSE                (0x1UL << 27)
#define MPT_DB_FUNCTION(x)          (((ULONG)(x) << 24) & 0xFF000000UL)
#define MPT_DB_DWORDS(x)            (((ULONG)(x) << 16) & 0x00FF0000UL)
#define MPT_DB_DATA_MASK            0xFFFFUL

#define MPT_WRITESEQ_1              0x04
#define MPT_WRITESEQ_2              0x0B
#define MPT_WRITESEQ_3              0x02
#define MPT_WRITESEQ_4              0x07
#define MPT_WRITESEQ_5              0x0D
#define MPT_HOSTDIAG_RESET_ADAPTER  (1UL << 2)

#define MPT_INTR_IOCDOORBELL        (1UL << 31)
#define MPT_INTR_REPLY              (1UL << 3)
#define MPT_INTR_DOORBELL           (1UL << 0)

#define MPT_REPLY_EMPTY             0xFFFFFFFFUL
#define MPT_REPLY_ADDRESS           (1UL << 31)
#define MPT_REPLY_ADDRESS_MASK      0x7FFFFFFFUL
#define MPT_REPLY_TYPE_MASK         (3UL << 29)
#define MPT_REPLY_TYPE_INIT         (0UL << 29)
#define MPT_REPLY_CONTEXT_MASK      0x1FFFFFFFUL

/* Message functions */
#define MPT_FUNC_SCSI_IO            0x00
#define MPT_FUNC_IOC_INIT           0x02
#define MPT_FUNC_IOC_FACTS          0x03
#define MPT_FUNC_PORT_FACTS         0x05
#define MPT_FUNC_PORT_ENABLE        0x06
#define MPT_FUNC_IOC_MSG_UNIT_RESET 0x40
#define MPT_FUNC_HANDSHAKE          0x42

#define MPT_WHOINIT_HOST_DRIVER     0x04

/* IOC status values of replies */
#define MPT_IOCSTATUS_MASK          0x7FFF
#define MPT_IOCSTATUS_SUCCESS       0x0000
#define MPT_IOCSTATUS_BUSY          0x0002
#define MPT_IOCSTATUS_INSUFF_RES    0x0006
#define MPT_IOCSTATUS_RECOVERED     0x0040
#define MPT_IOCSTATUS_INVALID_BUS   0x0041
#define MPT_IOCSTATUS_INVALID_TID   0x0042
#define MPT_IOCSTATUS_NOT_THERE     0x0043
#define MPT_IOCSTATUS_UNDERRUN      0x0045
#define MPT_IOCSTATUS_TASK_TERM     0x0048
#define MPT_IOCSTATUS_IOC_TERM      0x004B
#define MPT_IOCSTATUS_EXT_TERM      0x004C

/* SCSI I/O message flags, direction and state bits of the error reply */
#define MPT_SCSIIO_SENSE_ADDR_64    0x01
#define MPT_SCSIIO_ATTR_SIMPLE_Q    0x00
#define MPT_SCSIIO_DIR_NONE         0x00
#define MPT_SCSIIO_DIR_WRITE        0x01
#define MPT_SCSIIO_DIR_READ         0x02
#define MPT_STATE_AUTOSENSE_VALID   0x01
#define MPT_STATE_NO_SCSI_STATUS    0x08

/* Scatter/gather element flags */
#define MPT_SGE_LAST                (1UL << 31)
#define MPT_SGE_EOB                 (1UL << 30)
#define MPT_SGE_TYPE_SIMPLE         (1UL << 28)
#define MPT_SGE_TYPE_CHAIN          (3UL << 28)
#define MPT_SGE_DIR_OUT             (1UL << 26)
#define MPT_SGE_SIZE_64             (1UL << 25)
#define MPT_SGE_EOL                 (1UL << 24)

#include <pshpack1.h>

typedef struct _MPT_SGE
{
    ULONG Hdr;
    ULONG AddrLo;
    ULONG AddrHi;
} MPT_SGE, *PMPT_SGE;

typedef struct _MPT_SCSI_IO
{
    UCHAR TargetId;
    UCHAR Bus;
    UCHAR ChainOffset;
    UCHAR Function;
    UCHAR CdbLength;
    UCHAR SenseBufLen;
    UCHAR Reserved1;
    UCHAR MsgFlags;
    ULONG MsgContext;
    USHORT Lun[4];
    UCHAR Reserved2;
    UCHAR Tagging;
    UCHAR Reserved3;
    UCHAR Direction;
    UCHAR Cdb[16];
    ULONG DataLength;
    ULONG SenseBufLowAddr;
    /* the scatter/gather list follows */
} MPT_SCSI_IO, *PMPT_SCSI_IO;

/* The common head of every reply, and the SCSI I/O error reply */
typedef struct _MPT_REPLY
{
    UCHAR Word0[2];
    UCHAR MsgLength;
    UCHAR Function;
    UCHAR Word1[3];
    UCHAR MsgFlags;
    ULONG MsgContext;
    UCHAR ScsiStatus;       /* reserved in the replies of the other functions */
    UCHAR ScsiState;
    USHORT IocStatus;
    ULONG IocLogInfo;
    /* function specific (SCSI I/O error reply) */
    ULONG TransferCount;
    ULONG SenseCount;
    ULONG ResponseInfo;
    USHORT Tag;
    USHORT Reserved2;
} MPT_REPLY, *PMPT_REPLY;

typedef struct _MPT_IOCFACTS_REQUEST
{
    UCHAR Reserved1[2];
    UCHAR ChainOffset;
    UCHAR Function;
    UCHAR Reserved2[3];
    UCHAR MsgFlags;
    ULONG MsgContext;
} MPT_IOCFACTS_REQUEST;

typedef struct _MPT_IOCFACTS_REPLY
{
    UCHAR MsgVersionMin;
    UCHAR MsgVersionMaj;
    UCHAR MsgLength;
    UCHAR Function;
    UCHAR HeaderVersionMin;
    UCHAR HeaderVersionMaj;
    UCHAR IocNumber;
    UCHAR MsgFlags;
    ULONG MsgContext;
    USHORT IocExceptions;
    USHORT IocStatus;
    ULONG IocLogInfo;
    UCHAR MaxChainDepth;
    UCHAR WhoInit;
    UCHAR BlockSize;
    UCHAR Flags;
    USHORT ReplyQueueDepth;
    USHORT RequestFrameSize;
    USHORT Reserved1;
    USHORT ProductId;
    ULONG CurrentHostMfaHiAddr;
    USHORT GlobalCredits;
    UCHAR NumberOfPorts;
    UCHAR EventState;
    ULONG CurrentSenseBufferHiAddr;
    USHORT CurrentReplyFrameSize;
    UCHAR MaxDevices;
    UCHAR MaxBuses;
    ULONG FwImageSize;
    ULONG IocCapabilities;
    UCHAR FwVersionDev;
    UCHAR FwVersionUnit;
    UCHAR FwVersionMin;
    UCHAR FwVersionMaj;
    USHORT HiPriorityQueueDepth;
    USHORT Reserved2;
    MPT_SGE HostPageBufferSge;
    ULONG ReplyFifoHostSignallingAddr;
} MPT_IOCFACTS_REPLY;

typedef struct _MPT_IOCINIT_REQUEST
{
    UCHAR WhoInit;
    UCHAR Reserved1;
    UCHAR ChainOffset;
    UCHAR Function;
    UCHAR Flags;
    UCHAR MaxDevices;
    UCHAR MaxBuses;
    UCHAR MsgFlags;
    ULONG MsgContext;
    USHORT ReplyFrameSize;
    USHORT Reserved2;
    ULONG HostMfaHiAddr;
    ULONG SenseBufferHiAddr;
    ULONG ReplyFifoHostSignallingAddr;
    MPT_SGE HostPageBufferSge;
    UCHAR MsgVersionMin;
    UCHAR MsgVersionMaj;
    UCHAR HdrVersionUnit;
    UCHAR HdrVersionDev;
} MPT_IOCINIT_REQUEST;

typedef struct _MPT_IOCINIT_REPLY
{
    UCHAR WhoInit;
    UCHAR Reserved1;
    UCHAR MsgLength;
    UCHAR Function;
    UCHAR Flags;
    UCHAR MaxDevices;
    UCHAR MaxBuses;
    UCHAR MsgFlags;
    ULONG MsgContext;
    USHORT Reserved2;
    USHORT IocStatus;
    ULONG IocLogInfo;
} MPT_IOCINIT_REPLY;

/* PORT FACTS and PORT ENABLE requests have the same head */
typedef struct _MPT_PORT_REQUEST
{
    UCHAR Reserved1[2];
    UCHAR ChainOffset;
    UCHAR Function;
    UCHAR Reserved2[2];
    UCHAR PortNumber;
    UCHAR MsgFlags;
    ULONG MsgContext;
} MPT_PORT_REQUEST;

#include <poppack.h>

C_ASSERT(sizeof(MPT_SGE) == 12);
C_ASSERT(sizeof(MPT_SCSI_IO) == 48);
C_ASSERT(sizeof(MPT_REPLY) == 36);
C_ASSERT(sizeof(MPT_IOCFACTS_REQUEST) == 12);
C_ASSERT(sizeof(MPT_IOCFACTS_REPLY) == 80);
C_ASSERT(sizeof(MPT_IOCINIT_REQUEST) == 44);
C_ASSERT(sizeof(MPT_IOCINIT_REPLY) == 20);
C_ASSERT(sizeof(MPT_PORT_REQUEST) == 12);

/* Driver layout */
#define MPT_MAX_REQS                64              /* requests in flight */
#define MPT_BUNDLE_SIZE             512             /* request frame, scatter/gather list and sense slot of one request */
#define MPT_BUNDLE_SGES             36
#define MPT_SENSE_SLOT              32
#define MPT_OFF_SENSE               (sizeof(MPT_SCSI_IO) + MPT_BUNDLE_SGES * sizeof(MPT_SGE))   /* 480 */
#define MPT_MAX_SEGS                (MPT_BUNDLE_SGES - 1)   /* the chain element takes one of them: 35 data elements */
#define MPT_MAX_REPLIES             128
#define MPT_REPLY_SIZE              80
#define MPT_MAX_TARGETS             32
#define MPT_MIN_FRAME_BYTES         96              /* room for the request head and a few elements */
#define MPT_MAX_FRAME_BYTES         MPT_BUNDLE_SIZE    /* the controller reads the frame from the bundle: it must fit there */
#define MPT_FRAME_SGES              8               /* elements put in the request frame; a longer list continues in a chain */

/* The uncached extension: one bundle per request, one for the internal requests, the reply frames */
#define MPT_BUNDLE_INTERNAL         MPT_MAX_REQS
#define MPT_OFF_BUNDLES             0
#define MPT_OFF_REPLIES             ((MPT_MAX_REQS + 1) * MPT_BUNDLE_SIZE)
#define MPT_MEM_SIZE                ((MPT_OFF_REPLIES + MPT_MAX_REPLIES * MPT_REPLY_SIZE + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

C_ASSERT(MPT_OFF_SENSE + MPT_SENSE_SLOT == MPT_BUNDLE_SIZE);

/* Contexts: requests carry index + generation, internal ones a fixed value above any of those */
#define MPT_CTX_PORTFACTS           0x10000001UL
#define MPT_CTX_PORTENABLE          0x10000002UL

/* Bounds on waiting for the controller, in microseconds */
#define MPT_WAIT_STEP               50
#define MPT_WAIT_NORMAL             3000000
#define MPT_WAIT_PORT_ENABLE        20000000

typedef struct _MPT_SLOT
{
    PSCSI_REQUEST_BLOCK Srb;
    ULONG Generation;
} MPT_SLOT;

typedef struct _MPT_EXTENSION
{
    PUCHAR Regs;
    PUCHAR Mem;
    ULONGLONG MemPa;
    ULONG NumReqs;
    ULONG NumReplies;
    ULONG FrameBytes;
    ULONG FirstSgl;             /* elements that fit in the request frame after the head */
    ULONG MaxTargets;
    ULONG FreeCount;
    BOOLEAN Throttled;
    BOOLEAN ChainReported;
    UCHAR FreeStack[MPT_MAX_REQS];
    MPT_SLOT Slots[MPT_MAX_REQS];
} MPT_EXTENSION, *PMPT_EXTENSION;

static ULONG
MptRead(PMPT_EXTENSION Ext, ULONG Reg)
{
    return ScsiPortReadRegisterUlong((PULONG)(Ext->Regs + Reg));
}

static VOID
MptWrite(PMPT_EXTENSION Ext, ULONG Reg, ULONG Value)
{
    ScsiPortWriteRegisterUlong((PULONG)(Ext->Regs + Reg), Value);
}

/* Wait until (register & Mask) == Value (or != Value when Equal is FALSE). A register that reads all ones means
   the device is gone: no register has that value legitimately. */
static BOOLEAN
MptWait(PMPT_EXTENSION Ext, ULONG Reg, ULONG Mask, ULONG Value, BOOLEAN Equal, ULONG Microseconds)
{
    ULONG Waited;

    for (Waited = 0; ; Waited += MPT_WAIT_STEP)
    {
        ULONG Current = MptRead(Ext, Reg);

        if (Current == 0xFFFFFFFFUL)
            return FALSE;
        if (((Current & Mask) == Value) == Equal)
            return TRUE;
        if (Waited >= Microseconds)
            return FALSE;
        ScsiPortStallExecution(MPT_WAIT_STEP);
    }
}

#define MptWaitDoorbellInt(Ext)     MptWait((Ext), MPT_REG_INTR_STATUS, MPT_INTR_DOORBELL, 0, FALSE, MPT_WAIT_NORMAL)
#define MptWaitDoorbellAck(Ext)     MptWait((Ext), MPT_REG_INTR_STATUS, MPT_INTR_IOCDOORBELL, 0, TRUE, MPT_WAIT_NORMAL)

/* Send a message of Dwords through the doorbell (used before the request queue works) */
static BOOLEAN
MptHandshakeSend(PMPT_EXTENSION Ext, PULONG Message, ULONG Dwords)
{
    ULONG i;

    if (MptRead(Ext, MPT_REG_DOORBELL) & MPT_DB_INUSE)
        return FALSE;
    if (MptRead(Ext, MPT_REG_INTR_STATUS) & MPT_INTR_DOORBELL)
        MptWrite(Ext, MPT_REG_INTR_STATUS, 0);

    MptWrite(Ext, MPT_REG_DOORBELL, MPT_DB_FUNCTION(MPT_FUNC_HANDSHAKE) | MPT_DB_DWORDS(Dwords));
    if (!MptWaitDoorbellInt(Ext))
        return FALSE;
    MptWrite(Ext, MPT_REG_INTR_STATUS, 0);
    if (!MptWaitDoorbellAck(Ext))
        return FALSE;

    for (i = 0; i < Dwords; i++)
    {
        MptWrite(Ext, MPT_REG_DOORBELL, Message[i]);
        if (!MptWaitDoorbellAck(Ext))
            return FALSE;
    }
    return TRUE;
}

static BOOLEAN
MptHandshakeRecvDword(PMPT_EXTENSION Ext, PULONG Dword)
{
    ULONG Value = 0;
    ULONG i;

    for (i = 0; i < 2; i++)
    {
        if (!MptWaitDoorbellInt(Ext))
            return FALSE;
        Value |= (MptRead(Ext, MPT_REG_DOORBELL) & MPT_DB_DATA_MASK) << (16 * i);
        MptWrite(Ext, MPT_REG_INTR_STATUS, 0);
    }
    *Dword = Value;
    return TRUE;
}

/* Receive a reply of the message length in its head (a dword count the device chose: it is bounded by the
   0xFF the field can hold); what does not fit in Buffer is read and dropped */
static BOOLEAN
MptHandshakeRecv(PMPT_EXTENSION Ext, PULONG Buffer, ULONG Dwords)
{
    ULONG First, Total, i, Dummy;

    if (!MptHandshakeRecvDword(Ext, &First))
        return FALSE;
    Buffer[0] = First;
    Total = (First >> 16) & 0xFF;       /* the message length of the reply head */

    for (i = 1; i < Total; i++)
    {
        if (!MptHandshakeRecvDword(Ext, i < Dwords ? &Buffer[i] : &Dummy))
            return FALSE;
    }

    if (!MptWaitDoorbellInt(Ext))
        return FALSE;
    MptWrite(Ext, MPT_REG_INTR_STATUS, 0);
    return TRUE;
}

static BOOLEAN
MptResetSoft(PMPT_EXTENSION Ext)
{
    if (MptRead(Ext, MPT_REG_DOORBELL) & MPT_DB_INUSE)
        return FALSE;

    MptWrite(Ext, MPT_REG_DOORBELL, MPT_DB_FUNCTION(MPT_FUNC_IOC_MSG_UNIT_RESET));
    if (!MptWaitDoorbellAck(Ext))
        return FALSE;
    return MptWait(Ext, MPT_REG_DOORBELL, MPT_DB_STATE, MPT_DB_STATE_READY, TRUE, MPT_WAIT_NORMAL);
}

static VOID
MptResetHard(PMPT_EXTENSION Ext)
{
    MptWrite(Ext, MPT_REG_WRITESEQ, 0xFF);
    MptWrite(Ext, MPT_REG_WRITESEQ, MPT_WRITESEQ_1);
    MptWrite(Ext, MPT_REG_WRITESEQ, MPT_WRITESEQ_2);
    MptWrite(Ext, MPT_REG_WRITESEQ, MPT_WRITESEQ_3);
    MptWrite(Ext, MPT_REG_WRITESEQ, MPT_WRITESEQ_4);
    MptWrite(Ext, MPT_REG_WRITESEQ, MPT_WRITESEQ_5);
    MptWrite(Ext, MPT_REG_HOSTDIAG, MPT_HOSTDIAG_RESET_ADAPTER);
    ScsiPortStallExecution(10000);
    MptWrite(Ext, MPT_REG_WRITESEQ, 0xFF);
}

/* Bring the IOC to the READY state, whatever the firmware or the previous owner left it in */
static BOOLEAN
MptReadyIoc(PMPT_EXTENSION Ext)
{
    ULONG Try;

    if (!MptWait(Ext, MPT_REG_DOORBELL, MPT_DB_STATE, MPT_DB_STATE_RESET, FALSE, MPT_WAIT_NORMAL))
        return FALSE;

    for (Try = 0; Try < 5; Try++)
    {
        ULONG Db = MptRead(Ext, MPT_REG_DOORBELL);

        if (Db == 0xFFFFFFFFUL)
            return FALSE;

        switch (Db & MPT_DB_STATE)
        {
            case MPT_DB_STATE_READY:
                return TRUE;

            case MPT_DB_STATE_OPER:
            case MPT_DB_STATE_FAULT:
                if (!MptResetSoft(Ext))
                    MptResetHard(Ext);
                break;

            default:
                if (!MptWait(Ext, MPT_REG_DOORBELL, MPT_DB_STATE, MPT_DB_STATE_RESET, FALSE, MPT_WAIT_NORMAL))
                    return FALSE;
                break;
        }
    }
    return (MptRead(Ext, MPT_REG_DOORBELL) & MPT_DB_STATE) == MPT_DB_STATE_READY;
}

static PUCHAR
MptBundle(PMPT_EXTENSION Ext, ULONG Index)
{
    return Ext->Mem + MPT_OFF_BUNDLES + Index * MPT_BUNDLE_SIZE;
}

static ULONGLONG
MptBundlePa(PMPT_EXTENSION Ext, ULONG Index)
{
    return Ext->MemPa + MPT_OFF_BUNDLES + (ULONGLONG)Index * MPT_BUNDLE_SIZE;
}

/* Give a reply frame (given by its index) back to the controller */
static VOID
MptPostReply(PMPT_EXTENSION Ext, ULONG Index)
{
    PUCHAR Frame = Ext->Mem + MPT_OFF_REPLIES + Index * MPT_REPLY_SIZE;

    RtlZeroMemory(Frame, MPT_REPLY_SIZE);
    KeMemoryBarrier();
    MptWrite(Ext, MPT_REG_REPLY_QUEUE, (ULONG)(Ext->MemPa + MPT_OFF_REPLIES + Index * MPT_REPLY_SIZE));
}

/* The index of the reply frame that a value from the reply queue names, or MPT_MAX_REPLIES when it names none.
   The value comes from the device: it must be one of the frames that were given to it. */
static ULONG
MptReplyIndex(PMPT_EXTENSION Ext, ULONG Reg)
{
    ULONG Address = (Reg & MPT_REPLY_ADDRESS_MASK) << 1;
    ULONG Base = (ULONG)(Ext->MemPa + MPT_OFF_REPLIES);
    ULONG Offset = Address - Base;

    if (Offset >= Ext->NumReplies * MPT_REPLY_SIZE || (Offset % MPT_REPLY_SIZE) != 0)
        return MPT_MAX_REPLIES;
    return Offset / MPT_REPLY_SIZE;
}

/* Send an internal request through the request queue and poll for its reply (used while the interrupt is not connected) */
static BOOLEAN
MptInternalRequest(PMPT_EXTENSION Ext, UCHAR Function, ULONG Context, ULONG Microseconds, PMPT_REPLY ReplyOut)
{
    MPT_PORT_REQUEST *Req = (MPT_PORT_REQUEST *)MptBundle(Ext, MPT_BUNDLE_INTERNAL);
    ULONG Waited;

    RtlZeroMemory(Req, sizeof(*Req));
    Req->Function = Function;
    Req->PortNumber = 0;
    Req->MsgContext = Context;
    KeMemoryBarrier();
    MptWrite(Ext, MPT_REG_REQ_QUEUE, (ULONG)MptBundlePa(Ext, MPT_BUNDLE_INTERNAL));

    for (Waited = 0; Waited < Microseconds; )
    {
        ULONG Reg = MptRead(Ext, MPT_REG_REPLY_QUEUE);

        if (Reg == MPT_REPLY_EMPTY)
        {
            ScsiPortStallExecution(MPT_WAIT_STEP);
            Waited += MPT_WAIT_STEP;
            continue;
        }
        if (Reg & MPT_REPLY_ADDRESS)
        {
            ULONG Index = MptReplyIndex(Ext, Reg);

            if (Index < MPT_MAX_REPLIES)
            {
                MPT_REPLY Copy;

                RtlCopyMemory(&Copy, Ext->Mem + MPT_OFF_REPLIES + Index * MPT_REPLY_SIZE, sizeof(Copy));
                MptPostReply(Ext, Index);
                if (Copy.MsgContext == Context)
                {
                    *ReplyOut = Copy;
                    return (Copy.Function == Function) && ((Copy.IocStatus & MPT_IOCSTATUS_MASK) == MPT_IOCSTATUS_SUCCESS);
                }
            }
        }
    }
    return FALSE;
}

/* Reset the IOC and bring it to the operational state with the reply frames posted and the port enabled.
   The memory is the uncached extension, already zeroed or reused. */
static BOOLEAN
MptStartAdapter(PMPT_EXTENSION Ext)
{
    MPT_IOCFACTS_REQUEST FactsReq;
    MPT_IOCFACTS_REPLY Facts;
    MPT_IOCINIT_REQUEST InitReq;
    MPT_IOCINIT_REPLY InitReply;
    MPT_REPLY Reply;
    ULONG Frame, Credits, ReplyDepth, i;

    MptWrite(Ext, MPT_REG_INTR_MASK, MPT_INTR_REPLY | MPT_INTR_DOORBELL);

    if (!MptReadyIoc(Ext))
    {
        DbgPrint("mptsas: the controller does not become ready\n");
        return FALSE;
    }

    /* what the controller can do */
    RtlZeroMemory(&FactsReq, sizeof(FactsReq));
    RtlZeroMemory(&Facts, sizeof(Facts));
    FactsReq.Function = MPT_FUNC_IOC_FACTS;
    FactsReq.MsgContext = 0xDEADBEEF;
    if (!MptHandshakeSend(Ext, (PULONG)&FactsReq, sizeof(FactsReq) / sizeof(ULONG)) ||
        !MptHandshakeRecv(Ext, (PULONG)&Facts, sizeof(Facts) / sizeof(ULONG)))
    {
        DbgPrint("mptsas: IOC facts failed\n");
        return FALSE;
    }
    if (Facts.Function != MPT_FUNC_IOC_FACTS || (Facts.IocStatus & MPT_IOCSTATUS_MASK) != MPT_IOCSTATUS_SUCCESS)
    {
        DbgPrint("mptsas: IOC facts reply is bad (function %x, status %x)\n", Facts.Function, Facts.IocStatus);
        return FALSE;
    }

    /* the sizes are written by the device: they limit what the driver lays out, they are never taken as they are */
    Frame = (ULONG)Facts.RequestFrameSize * sizeof(ULONG);
    Credits = Facts.GlobalCredits;
    ReplyDepth = Facts.ReplyQueueDepth;
    if (Frame < MPT_MIN_FRAME_BYTES || Frame > MPT_MAX_FRAME_BYTES || Credits < 2 || ReplyDepth < 4)
    {
        DbgPrint("mptsas: unusable sizes: frame %lu bytes, credits %lu, reply queue %lu\n", Frame, Credits, ReplyDepth);
        return FALSE;
    }
    Ext->FrameBytes = Frame;
    Ext->FirstSgl = min((Frame - sizeof(MPT_SCSI_IO)) / sizeof(MPT_SGE), MPT_FRAME_SGES);
    Ext->NumReplies = min(ReplyDepth, MPT_MAX_REPLIES);
    Ext->NumReqs = min(min(Credits, MPT_MAX_REQS), Ext->NumReplies);
    Ext->MaxTargets = Facts.MaxDevices == 0 ? MPT_MAX_TARGETS : min((ULONG)Facts.MaxDevices, MPT_MAX_TARGETS);

    /* the request frames, the sense slots and the reply frames are all in the one block: the high half of their addresses is common */
    RtlZeroMemory(&InitReq, sizeof(InitReq));
    RtlZeroMemory(&InitReply, sizeof(InitReply));
    InitReq.WhoInit = MPT_WHOINIT_HOST_DRIVER;
    InitReq.Function = MPT_FUNC_IOC_INIT;
    InitReq.MaxDevices = Facts.MaxDevices;
    InitReq.MaxBuses = 1;
    InitReq.MsgContext = 0xD00FD00F;
    InitReq.ReplyFrameSize = MPT_REPLY_SIZE;
    InitReq.HostMfaHiAddr = (ULONG)(Ext->MemPa >> 32);
    InitReq.SenseBufferHiAddr = (ULONG)(Ext->MemPa >> 32);
    InitReq.MsgVersionMaj = 0x01;
    InitReq.MsgVersionMin = 0x02;
    InitReq.HdrVersionUnit = 0x0D;
    if (!MptHandshakeSend(Ext, (PULONG)&InitReq, sizeof(InitReq) / sizeof(ULONG)) ||
        !MptHandshakeRecv(Ext, (PULONG)&InitReply, sizeof(InitReply) / sizeof(ULONG)))
    {
        DbgPrint("mptsas: IOC init failed\n");
        return FALSE;
    }
    if ((InitReply.IocStatus & MPT_IOCSTATUS_MASK) != MPT_IOCSTATUS_SUCCESS ||
        !MptWait(Ext, MPT_REG_DOORBELL, MPT_DB_STATE, MPT_DB_STATE_OPER, TRUE, MPT_WAIT_NORMAL))
    {
        DbgPrint("mptsas: IOC init status %x, not operational\n", InitReply.IocStatus);
        return FALSE;
    }

    for (i = 0; i < Ext->NumReplies; i++)
        MptPostReply(Ext, i);

    if (!MptInternalRequest(Ext, MPT_FUNC_PORT_FACTS, MPT_CTX_PORTFACTS, MPT_WAIT_NORMAL, &Reply))
    {
        DbgPrint("mptsas: port facts failed\n");
        return FALSE;
    }
    if (!MptInternalRequest(Ext, MPT_FUNC_PORT_ENABLE, MPT_CTX_PORTENABLE, MPT_WAIT_PORT_ENABLE, &Reply))
    {
        DbgPrint("mptsas: port enable failed\n");
        return FALSE;
    }

    DbgPrint("mptsas: started: request frame %lu bytes, %lu requests, %lu reply frames, %lu targets, memory at %I64x\n",
             Ext->FrameBytes, Ext->NumReqs, Ext->NumReplies, Ext->MaxTargets, Ext->MemPa);
    for (i = 0; i < MPT_MAX_REQS; i++)
        Ext->Slots[i].Srb = NULL;
    for (i = 0; i < Ext->NumReqs; i++)
        Ext->FreeStack[i] = (UCHAR)(Ext->NumReqs - 1 - i);
    Ext->FreeCount = Ext->NumReqs;
    Ext->Throttled = FALSE;
    return TRUE;
}

static VOID
MptCompleteSrb(PMPT_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb, UCHAR Status)
{
    Srb->SrbStatus = Status;
    ScsiPortNotification(RequestComplete, Ext, Srb);
}

static UCHAR
MptStatusFromIoc(PSCSI_REQUEST_BLOCK Srb, ULONG IocStatus, ULONG TransferCount)
{
    switch (IocStatus)
    {
        case MPT_IOCSTATUS_SUCCESS:
        case MPT_IOCSTATUS_RECOVERED:
            return SRB_STATUS_SUCCESS;

        case MPT_IOCSTATUS_UNDERRUN:
            if (TransferCount < Srb->DataTransferLength)
                Srb->DataTransferLength = TransferCount;
            return SRB_STATUS_DATA_OVERRUN;

        case MPT_IOCSTATUS_INVALID_BUS:
        case MPT_IOCSTATUS_INVALID_TID:
        case MPT_IOCSTATUS_NOT_THERE:
            return SRB_STATUS_SELECTION_TIMEOUT;

        case MPT_IOCSTATUS_BUSY:
        case MPT_IOCSTATUS_INSUFF_RES:
            return SRB_STATUS_BUSY;

        case MPT_IOCSTATUS_TASK_TERM:
        case MPT_IOCSTATUS_IOC_TERM:
        case MPT_IOCSTATUS_EXT_TERM:
            return SRB_STATUS_BUS_RESET;

        default:
            return SRB_STATUS_ERROR;
    }
}

/* One value from the reply queue. Contexts and indices come from the device: never trust them. */
static VOID
MptHandleReply(PMPT_EXTENSION Ext, ULONG Reg)
{
    ULONG Context, Index, FrameIndex = MPT_MAX_REPLIES;
    MPT_REPLY Reply;
    BOOLEAN HaveReply = FALSE;
    PSCSI_REQUEST_BLOCK Srb;
    UCHAR Status;

    RtlZeroMemory(&Reply, sizeof(Reply));

    if (Reg & MPT_REPLY_ADDRESS)
    {
        FrameIndex = MptReplyIndex(Ext, Reg);
        if (FrameIndex >= MPT_MAX_REPLIES)
        {
            DbgPrint("mptsas: reply address %lx is not one of the reply frames, ignored\n", Reg);
            return;
        }
        RtlCopyMemory(&Reply, Ext->Mem + MPT_OFF_REPLIES + FrameIndex * MPT_REPLY_SIZE, sizeof(Reply));
        MptPostReply(Ext, FrameIndex);
        if (Reply.Function != MPT_FUNC_SCSI_IO)
            return;                         /* not a reply to one of the I/O requests: nothing waits for it */
        Context = Reply.MsgContext;
        HaveReply = TRUE;
    }
    else
    {
        if ((Reg & MPT_REPLY_TYPE_MASK) != MPT_REPLY_TYPE_INIT)
            return;
        Context = Reg & MPT_REPLY_CONTEXT_MASK;
    }

    Index = Context & 0xFF;
    if (Index >= Ext->NumReqs || Ext->Slots[Index].Srb == NULL ||
        Ext->Slots[Index].Generation != ((Context >> 8) & 0xFFFFF))
    {
        DbgPrint("mptsas: completion for unknown request %lx ignored\n", Context);
        return;
    }

    Srb = Ext->Slots[Index].Srb;
    Ext->Slots[Index].Srb = NULL;
    Ext->FreeStack[Ext->FreeCount++] = (UCHAR)Index;

    if (!HaveReply)
    {
        Srb->ScsiStatus = SCSISTAT_GOOD;
        Status = SRB_STATUS_SUCCESS;
    }
    else
    {
        ULONG IocStatus = Reply.IocStatus & MPT_IOCSTATUS_MASK;

        Status = MptStatusFromIoc(Srb, IocStatus, Reply.TransferCount);
        Srb->ScsiStatus = Reply.ScsiStatus;
        if (Reply.ScsiState & MPT_STATE_NO_SCSI_STATUS)
        {
            /* the command ended without a SCSI status (terminated by the controller) */
            if (Status == SRB_STATUS_SUCCESS || Status == SRB_STATUS_DATA_OVERRUN)
                Status = SRB_STATUS_ERROR;
        }
        else if (Reply.ScsiStatus == SCSISTAT_QUEUE_FULL || Reply.ScsiStatus == SCSISTAT_BUSY)
            Status = SRB_STATUS_BUSY;
        else if ((Status == SRB_STATUS_SUCCESS || Status == SRB_STATUS_DATA_OVERRUN) &&
                 Reply.ScsiStatus != SCSISTAT_GOOD)
            Status = SRB_STATUS_ERROR;

        if (Reply.ScsiStatus == SCSISTAT_CHECK_CONDITION && (Reply.ScsiState & MPT_STATE_AUTOSENSE_VALID) &&
            Reply.SenseCount != 0 && Srb->SenseInfoBuffer != NULL && !(Srb->SrbFlags & SRB_FLAGS_DISABLE_AUTOSENSE))
        {
            ULONG Copy = min(Reply.SenseCount, MPT_SENSE_SLOT);

            Copy = min(Copy, Srb->SenseInfoBufferLength);
            RtlCopyMemory(Srb->SenseInfoBuffer, MptBundle(Ext, Index) + MPT_OFF_SENSE, Copy);
            Srb->SenseInfoBufferLength = (UCHAR)Copy;
            Status |= SRB_STATUS_AUTOSENSE_VALID;
        }
    }

    MptCompleteSrb(Ext, Srb, Status);
}

/* Handle what the device has put in the reply queue. The number of values taken is bounded. */
static VOID
MptProcessReplies(PMPT_EXTENSION Ext)
{
    ULONG Budget;

    for (Budget = 0; Budget < 2 * (MPT_MAX_REPLIES + MPT_MAX_REQS); Budget++)
    {
        ULONG Reg = MptRead(Ext, MPT_REG_REPLY_QUEUE);

        if (Reg == MPT_REPLY_EMPTY)
            break;
        MptHandleReply(Ext, Reg);
    }

    if (Ext->Throttled && Ext->FreeCount != 0)
    {
        Ext->Throttled = FALSE;
        ScsiPortNotification(NextRequest, Ext, NULL);
    }
}

/* Build the scatter/gather list of the request in its bundle. Returns FALSE when the buffer does not fit. */
static BOOLEAN
MptBuildSgl(PMPT_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb, ULONG Index, PMPT_SCSI_IO Io)
{
    PMPT_SGE Sgl = (PMPT_SGE)(MptBundle(Ext, Index) + sizeof(MPT_SCSI_IO));
    ULONGLONG Addr[MPT_MAX_SEGS];
    ULONG Len[MPT_MAX_SEGS];
    PUCHAR Va = Srb->DataBuffer;
    ULONG Remaining = Srb->DataTransferLength;
    ULONG Count = 0, i, Flags, First = Ext->FirstSgl;

    if (Remaining == 0)
    {
        Sgl[0].Hdr = MPT_SGE_TYPE_SIMPLE | MPT_SGE_LAST | MPT_SGE_EOB | MPT_SGE_EOL;
        return TRUE;
    }

    while (Remaining != 0)
    {
        ULONG Chunk = 0;
        SCSI_PHYSICAL_ADDRESS Pa = ScsiPortGetPhysicalAddress(Ext, Srb, Va, &Chunk);

        if (Chunk == 0 || Pa.QuadPart == (LONGLONG)SP_UNINITIALIZED_VALUE)
            return FALSE;
        Chunk = min(Chunk, Remaining);

        if (Count != 0 && Addr[Count - 1] + Len[Count - 1] == (ULONGLONG)Pa.QuadPart &&
            (ULONGLONG)Len[Count - 1] + Chunk <= 0xFFFFFF)
        {
            Len[Count - 1] += Chunk;
        }
        else
        {
            if (Count == MPT_MAX_SEGS)
                return FALSE;
            Addr[Count] = (ULONGLONG)Pa.QuadPart;
            Len[Count] = Chunk;
            Count++;
        }
        Va += Chunk;
        Remaining -= Chunk;
    }

    Flags = MPT_SGE_TYPE_SIMPLE | MPT_SGE_SIZE_64;
    if (Srb->SrbFlags & SRB_FLAGS_DATA_OUT)
        Flags |= MPT_SGE_DIR_OUT;

    if (Count <= First)
    {
        /* everything fits in the request frame */
        for (i = 0; i < Count; i++)
        {
            Sgl[i].Hdr = Flags | Len[i];
            Sgl[i].AddrLo = (ULONG)Addr[i];
            Sgl[i].AddrHi = (ULONG)(Addr[i] >> 32);
        }
        Sgl[Count - 1].Hdr |= MPT_SGE_LAST | MPT_SGE_EOB | MPT_SGE_EOL;
    }
    else
    {
        /* the last element of the frame is a chain element that points at the rest, which follows in the bundle */
        ULONG InFrame = First - 1;
        ULONG Rest = Count - InFrame;
        ULONGLONG ChainPa = MptBundlePa(Ext, Index) + sizeof(MPT_SCSI_IO) + First * sizeof(MPT_SGE);

        for (i = 0; i < InFrame; i++)
        {
            Sgl[i].Hdr = Flags | Len[i];
            Sgl[i].AddrLo = (ULONG)Addr[i];
            Sgl[i].AddrHi = (ULONG)(Addr[i] >> 32);
        }
        Sgl[InFrame - 1].Hdr |= MPT_SGE_LAST;

        if (!Ext->ChainReported)
        {
            Ext->ChainReported = TRUE;
            DbgPrint("mptsas: first request with a chained scatter/gather list (%lu elements, %lu in the frame)\n", Count, InFrame);
        }

        Sgl[InFrame].Hdr = MPT_SGE_TYPE_CHAIN | MPT_SGE_SIZE_64 | (Rest * sizeof(MPT_SGE));
        Sgl[InFrame].AddrLo = (ULONG)ChainPa;
        Sgl[InFrame].AddrHi = (ULONG)(ChainPa >> 32);
        Io->ChainOffset = (UCHAR)((sizeof(MPT_SCSI_IO) + InFrame * sizeof(MPT_SGE)) / sizeof(ULONG));

        for (i = 0; i < Rest; i++)
        {
            PMPT_SGE E = &Sgl[First + i];

            E->Hdr = Flags | Len[InFrame + i];
            E->AddrLo = (ULONG)Addr[InFrame + i];
            E->AddrHi = (ULONG)(Addr[InFrame + i] >> 32);
        }
        Sgl[First + Rest - 1].Hdr |= MPT_SGE_LAST | MPT_SGE_EOB | MPT_SGE_EOL;
    }
    return TRUE;
}

static BOOLEAN
MptExecuteScsi(PMPT_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb)
{
    PMPT_SCSI_IO Io;
    ULONG Index, Generation;

    if (Srb->PathId != 0 || Srb->TargetId >= Ext->MaxTargets || Srb->Lun != 0)
    {
        MptCompleteSrb(Ext, Srb, SRB_STATUS_NO_DEVICE);
        goto Next;
    }
    if (Srb->CdbLength == 0 || Srb->CdbLength > sizeof(Io->Cdb))
    {
        MptCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
        goto Next;
    }
    if (Ext->FreeCount == 0)
    {
        /* The port should not send more than it was told to: ask for a retry and stop the flow */
        Ext->Throttled = TRUE;
        MptCompleteSrb(Ext, Srb, SRB_STATUS_BUSY);
        return TRUE;
    }

    Index = Ext->FreeStack[Ext->FreeCount - 1];
    Io = (PMPT_SCSI_IO)MptBundle(Ext, Index);
    RtlZeroMemory(Io, sizeof(*Io));

    if (!MptBuildSgl(Ext, Srb, Index, Io))
    {
        MptCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
        goto Next;
    }

    if (Srb->DataTransferLength != 0 && (Srb->SrbFlags & SRB_FLAGS_DATA_IN))
        Io->Direction = MPT_SCSIIO_DIR_READ;
    else if (Srb->DataTransferLength != 0 && (Srb->SrbFlags & SRB_FLAGS_DATA_OUT))
        Io->Direction = MPT_SCSIIO_DIR_WRITE;
    else
        Io->Direction = MPT_SCSIIO_DIR_NONE;

    Ext->FreeCount--;
    Generation = (Ext->Slots[Index].Generation + 1) & 0xFFFFF;
    Ext->Slots[Index].Generation = Generation;
    Ext->Slots[Index].Srb = Srb;

    Io->TargetId = Srb->TargetId;
    Io->Bus = 0;
    Io->Function = MPT_FUNC_SCSI_IO;
    Io->CdbLength = Srb->CdbLength;
    Io->SenseBufLen = MPT_SENSE_SLOT;
    Io->MsgFlags = MPT_SCSIIO_SENSE_ADDR_64;
    Io->MsgContext = (Generation << 8) | Index;
    Io->Lun[0] = (USHORT)(((Srb->Lun & 0xFF) << 8) | (Srb->Lun >> 8));
    Io->Tagging = MPT_SCSIIO_ATTR_SIMPLE_Q;
    RtlCopyMemory(Io->Cdb, Srb->Cdb, Srb->CdbLength);
    Io->DataLength = Srb->DataTransferLength;
    Io->SenseBufLowAddr = (ULONG)(MptBundlePa(Ext, Index) + MPT_OFF_SENSE);

    KeMemoryBarrier();
    MptWrite(Ext, MPT_REG_REQ_QUEUE, (ULONG)MptBundlePa(Ext, Index));

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
MptReinitialize(PMPT_EXTENSION Ext, ULONG PathId)
{
    ULONG Index;
    BOOLEAN Ok;

    ScsiPortCompleteRequest(Ext, (UCHAR)PathId, SP_UNTAGGED, SP_UNTAGGED, SRB_STATUS_BUS_RESET);
    for (Index = 0; Index < MPT_MAX_REQS; Index++)
    {
        /* whatever the device still reports for the old requests is ignored: the generation no longer matches */
        Ext->Slots[Index].Srb = NULL;
        Ext->Slots[Index].Generation++;
    }
    Ok = MptStartAdapter(Ext);
    if (Ok)
        MptWrite(Ext, MPT_REG_INTR_MASK, MPT_INTR_DOORBELL);
    return Ok;
}

static BOOLEAN NTAPI
MptStartIo(PVOID HwDeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
    PMPT_EXTENSION Ext = HwDeviceExtension;

    switch (Srb->Function)
    {
        case SRB_FUNCTION_EXECUTE_SCSI:
            return MptExecuteScsi(Ext, Srb);

        case SRB_FUNCTION_RESET_DEVICE:
            /* the controller is started again: that ends every command of the device, and of the others */
            MptReinitialize(Ext, Srb->PathId);
            MptCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;

        case SRB_FUNCTION_ABORT_COMMAND:
            /* no abort by tag here: the port escalates to a bus reset */
            MptCompleteSrb(Ext, Srb, SRB_STATUS_ABORT_FAILED);
            break;

        case SRB_FUNCTION_FLUSH:
        case SRB_FUNCTION_SHUTDOWN:
            /* nothing is cached in the adapter; the disk's cache is flushed by SYNCHRONIZE CACHE */
            MptCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;

        default:
            MptCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
            break;
    }

    ScsiPortNotification(NextRequest, Ext, NULL);
    return TRUE;
}

static BOOLEAN NTAPI
MptInterrupt(PVOID HwDeviceExtension)
{
    PMPT_EXTENSION Ext = HwDeviceExtension;
    ULONG Status = MptRead(Ext, MPT_REG_INTR_STATUS);

    if (Status == 0xFFFFFFFFUL || (Status & MPT_INTR_REPLY) == 0)
        return FALSE;

    MptProcessReplies(Ext);
    return TRUE;
}

static BOOLEAN NTAPI
MptResetBus(PVOID HwDeviceExtension, ULONG PathId)
{
    return MptReinitialize(HwDeviceExtension, PathId);
}

static BOOLEAN NTAPI
MptInitialize(PVOID HwDeviceExtension)
{
    /* the controller was started in HwFindAdapter; the interrupt is connected by now */
    MptWrite(HwDeviceExtension, MPT_REG_INTR_MASK, MPT_INTR_DOORBELL);
    return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS NTAPI
MptAdapterControl(PVOID HwDeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
{
    PMPT_EXTENSION Ext = HwDeviceExtension;

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
            MptWrite(Ext, MPT_REG_INTR_MASK, MPT_INTR_REPLY | MPT_INTR_DOORBELL);
            if (!MptResetSoft(Ext))
                MptResetHard(Ext);
            return ScsiAdapterControlSuccess;

        case ScsiRestartAdapter:
            if (!MptStartAdapter(Ext))
                return ScsiAdapterControlUnsuccessful;
            MptWrite(Ext, MPT_REG_INTR_MASK, MPT_INTR_DOORBELL);
            return ScsiAdapterControlSuccess;

        default:
            return ScsiAdapterControlUnsuccessful;
    }
}

static ULONG NTAPI
MptFindAdapter(
    IN PVOID HwDeviceExtension,
    IN PVOID Context,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again)
{
    PMPT_EXTENSION Ext = HwDeviceExtension;
    PACCESS_RANGE Range = NULL;
    SCSI_PHYSICAL_ADDRESS Pa;
    ULONG Length = 0;
    ULONG i;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);

    *Again = FALSE;

    /* The registers are in the first memory BAR (16 KB); the first BAR is I/O ports and the third one the diagnostic memory */
    for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
    {
        if ((*ConfigInfo->AccessRanges)[i].RangeInMemory && (*ConfigInfo->AccessRanges)[i].RangeLength != 0)
        {
            Range = &(*ConfigInfo->AccessRanges)[i];
            break;
        }
    }
    if (Range == NULL || Range->RangeLength < MPT_REGS_LENGTH)
        return SP_RETURN_NOT_FOUND;

    if (!ScsiPortValidateRange(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                               Range->RangeStart, Range->RangeLength, FALSE))
        return SP_RETURN_BAD_CONFIG;

    Ext->Regs = ScsiPortGetDeviceBase(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                                      Range->RangeStart, Range->RangeLength, FALSE);
    if (Ext->Regs == NULL)
        return SP_RETURN_ERROR;

    ConfigInfo->NumberOfBuses = 1;
    ConfigInfo->MaximumNumberOfTargets = MPT_MAX_TARGETS;
    ConfigInfo->MaximumNumberOfLogicalUnits = 1;
    ConfigInfo->MaximumTransferLength = MPT_MAX_SEGS * PAGE_SIZE - PAGE_SIZE;
    ConfigInfo->NumberOfPhysicalBreaks = MPT_MAX_SEGS - 1;
    ConfigInfo->ScatterGather = TRUE;
    ConfigInfo->Master = TRUE;
    ConfigInfo->NeedPhysicalAddresses = TRUE;
    ConfigInfo->Dma32BitAddresses = TRUE;
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;     /* the data elements and the frames take 64-bit addresses */
    ConfigInfo->TaggedQueuing = TRUE;
    ConfigInfo->MultipleRequestPerLu = TRUE;
    ConfigInfo->AlignmentMask = 0;
    ConfigInfo->InterruptMode = LevelSensitive;
    ConfigInfo->WmiDataProvider = FALSE;

    Ext->Mem = ScsiPortGetUncachedExtension(Ext, ConfigInfo, MPT_MEM_SIZE);
    if (Ext->Mem == NULL)
        return SP_RETURN_ERROR;

    /* the block must be contiguous, and must not cross a 4 GB boundary: the controller is told one high half for all of it */
    Pa = ScsiPortGetPhysicalAddress(Ext, NULL, Ext->Mem, &Length);
    if (Length < MPT_MEM_SIZE || (Pa.QuadPart & (PAGE_SIZE - 1)) != 0 ||
        ((ULONGLONG)Pa.QuadPart >> 32) != ((ULONGLONG)Pa.QuadPart + MPT_MEM_SIZE - 1) >> 32)
        return SP_RETURN_ERROR;
    Ext->MemPa = (ULONGLONG)Pa.QuadPart;

    if (!MptStartAdapter(Ext))
        return SP_RETURN_ERROR;

    ConfigInfo->MaximumNumberOfTargets = (UCHAR)Ext->MaxTargets;

    /* *Again stays FALSE: the port crashes in its second pass for a miniport that asks for another adapter (known),
       so only the first controller of a machine is driven */
    return SP_RETURN_FOUND;
}

NTSTATUS NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    HW_INITIALIZATION_DATA Init;
    UCHAR VendorId[4] = { '1', '0', '0', '0' };
    UCHAR DeviceId[4] = { '0', '0', '5', '4' };

    RtlZeroMemory(&Init, sizeof(Init));
    Init.HwInitializationDataSize = sizeof(Init);
    Init.HwInitialize = MptInitialize;
    Init.HwStartIo = MptStartIo;
    Init.HwInterrupt = MptInterrupt;
    Init.HwFindAdapter = MptFindAdapter;
    Init.HwResetBus = MptResetBus;
    Init.HwAdapterControl = MptAdapterControl;
    Init.AdapterInterfaceType = PCIBus;
    Init.VendorId = VendorId;
    Init.VendorIdLength = sizeof(VendorId);
    Init.DeviceId = DeviceId;
    Init.DeviceIdLength = sizeof(DeviceId);
    Init.NumberOfAccessRanges = 3;
    Init.DeviceExtensionSize = sizeof(MPT_EXTENSION);
    Init.SrbExtensionSize = 0;
    Init.NeedPhysicalAddresses = TRUE;
    Init.TaggedQueuing = TRUE;
    Init.MultipleRequestPerLu = TRUE;
    Init.AutoRequestSense = TRUE;

    return ScsiPortInitialize(DriverObject, RegistryPath, &Init, NULL);
}
