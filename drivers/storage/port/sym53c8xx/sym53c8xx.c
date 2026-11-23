/*
 * PROJECT:     ReactOS Symbios/LSI 53C8xx SCSI miniport driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SCSI port miniport for the LSI Logic 53C895A (PCI 1000:0012) and 53C810 (PCI 1000:0001) SCSI
 *              processors, as emulated by QEMU (lsi53c895a, lsi53c810) and offered by Proxmox VE and VMware
 *              as the "LSI Logic Parallel" family
 * COPYRIGHT:   Copyright 2026 ReactOS Project contributors
 *
 * The register offsets and bit names below describe the 53C8xx SCSI processors. They were taken from the
 * OpenBSD driver siop(4), sys/dev/ic/siopreg.h, and the chip set-up and the interrupt handling follow
 * sys/dev/ic/siop_common.c and sys/dev/ic/siop.c (revision 1.90). The SCRIPTS program that the chip runs is
 * in sym53c8xx.ss (derived from sys/dev/microcode/siop/siop.ss, see the header of that file) and its assembled
 * form is in sym53c8xx_script.h. The OpenBSD files carry this notice:
 *
 *   Copyright (c) 2000 Manuel Bouyer.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *   IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *   THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The driver code itself is new. It uses the legacy SCSI port interface like the BusLogic and other
 * miniports: one bus, 8 targets, one logical unit each, INTx interrupts. It runs one command at a time (no
 * tagged queueing): the port is told about the next request when the current one has completed. Transfers
 * are asynchronous and narrow. A target that disconnects is waited for (reselection); a disconnect in the
 * middle of a data transfer (the data pointer would have to be restored) is not supported and fails the
 * command. The chip is the only thing that writes values the driver has to trust: the interrupt status,
 * the script interrupt code, the address registers, the status and message bytes; each is checked before it is
 * used, and the driver never waits for the chip in a loop that is not bounded.
 */

#include <ntddk.h>
#include <srb.h>
#include <scsi.h>

/* Registers (the memory BAR, 1 KB; the I/O BAR is not used) */
#define SYM_SCNTL0          0x00
#define SYM_SCNTL1          0x01
#define SYM_SCNTL2          0x02
#define SYM_SCNTL3          0x03
#define SYM_SCID            0x04
#define SYM_SXFER           0x05
#define SYM_SSID            0x0A
#define SYM_DSTAT           0x0C
#define SYM_SSTAT1          0x0E
#define SYM_DSA             0x10
#define SYM_ISTAT           0x14
#define SYM_CTEST3          0x1B
#define SYM_CTEST5          0x22
#define SYM_DBC             0x24
#define SYM_DSP             0x2C
#define SYM_DSPS            0x30
#define SYM_SCRATCHA        0x34
#define SYM_DIEN            0x39
#define SYM_DCNTL           0x3B
#define SYM_SIEN0           0x40
#define SYM_SIEN1           0x41
#define SYM_SIST0           0x42
#define SYM_SIST1           0x43
#define SYM_STIME0          0x48
#define SYM_RESPID0         0x4A
#define SYM_STEST3          0x4F
#define SYM_REGS_LENGTH     0x80

#define SCNTL0_ARB_MASK     0xC0
#define SCNTL0_EPC          0x08
#define SCNTL0_AAP          0x02
#define SCNTL1_RST          0x08
#define SCID_RRE            0x40
#define ISTAT_ABRT          0x80
#define ISTAT_SRST          0x40
#define ISTAT_INTF          0x04
#define ISTAT_SIP           0x02
#define ISTAT_DIP           0x01
#define CTEST3_CLF          0x04
#define CTEST5_DFS          0x20
#define DCNTL_COM           0x01
#define STEST3_TE           0x80

#define DSTAT_DFE           0x80
#define DSTAT_SIR           0x04
#define SIST0_MA            0x80
#define SIST0_SGE           0x08
#define SIST0_UDC           0x04
#define SIST0_RST           0x02
#define SIST0_PAR           0x01
#define SIST1_STO           0x04
#define SIEN0_CMP           0x40
#define SIEN0_SEL           0x20
#define SIEN0_RSL           0x10
#define SIEN1_HTH           0x01
#define SIEN1_GEN           0x02

#define SSTAT1_PHASE_MASK   0x07
#define SSTAT1_PHASE_DATAIN 0x01
#define SSTAT1_PHASE_STATUS 0x03
#define SSTAT1_PHASE_MSGIN  0x07

#define SYM_HOST_ID         7
#define SYM_CLOCK_DIV       0x03

#include "sym53c8xx_script.h"

/* Driver layout */
#define SYM_MAX_SEGS        33                  /* data elements per request */
#define SYM_MAX_TARGETS     8
#define SYM_SCRIPT_BYTES    (SYM_SCRIPT_WORDS * sizeof(ULONG))
#define SYM_OFF_XFER        0x300               /* the command block follows the script */
#define SYM_BOUNCE_BYTES    ((SYM_MAX_SEGS - 1) * PAGE_SIZE)   /* the largest transfer the port will send */

#include <pshpack1.h>

typedef struct _SYM_ENTRY
{
    ULONG Count;
    ULONG Addr;
} SYM_ENTRY;

/* The command block the script works on (the DSA register points at it): the offsets are the ones of
   sym53c8xx.ss */
typedef struct _SYM_XFER
{
    ULONG Id;                                   /* 0: SCNTL3, SCSI id and SXFER for the selection */
    ULONG Pad;
    SYM_ENTRY MsgOut;                           /* 8 */
    SYM_ENTRY Cmd;                              /* 16 */
    SYM_ENTRY Status;                           /* 24 */
    SYM_ENTRY MsgIn;                            /* 32 */
    SYM_ENTRY Data[SYM_MAX_SEGS + 1];           /* 40: the data elements and one empty element */
    UCHAR MsgOutBuf[8];
    UCHAR MsgInBuf[8];
    UCHAR StatusBuf[8];
    UCHAR Cdb[16];
} SYM_XFER, *PSYM_XFER;

#include <poppack.h>

C_ASSERT(FIELD_OFFSET(SYM_XFER, MsgOut) == 8);
C_ASSERT(FIELD_OFFSET(SYM_XFER, Cmd) == 16);
C_ASSERT(FIELD_OFFSET(SYM_XFER, Status) == 24);
C_ASSERT(FIELD_OFFSET(SYM_XFER, MsgIn) == 32);
C_ASSERT(FIELD_OFFSET(SYM_XFER, Data) == 40);
C_ASSERT(SYM_OFF_XFER >= SYM_SCRIPT_BYTES);
C_ASSERT(SYM_OFF_XFER + sizeof(SYM_XFER) <= PAGE_SIZE);

typedef enum _SYM_STATE
{
    SymIdle,
    SymActive,                                  /* a command is on the bus or being set up by the script */
    SymDisconnected                             /* the target disconnected: waiting for it to reselect */
} SYM_STATE;

typedef struct _SYM_EXTENSION
{
    PUCHAR Regs;
    PUCHAR Mem;
    ULONG MemPa;
    BOOLEAN Is895A;
    SYM_STATE State;
    PSCSI_REQUEST_BLOCK Srb;
    ULONG Segs;
    ULONG Total;                                /* bytes of the data elements */
    ULONG Residual;                             /* bytes the target did not transfer */
    BOOLEAN DataIn;
    PUCHAR Bounce;                              /* a buffer below 4 GB for requests whose pages are above it */
    ULONG BouncePa;
    BOOLEAN Bounced;                            /* the current request goes through it */
    BOOLEAN BounceReported;
    BOOLEAN ShortReported;
    BOOLEAN OwnReset;                           /* the driver pulsed the bus reset line: the interrupt for it is expected */
    UCHAR UaTargets;                            /* targets whose next command may report the unit attention that a bus reset leaves */
    BOOLEAN UaReported;
} SYM_EXTENSION, *PSYM_EXTENSION;

static UCHAR
SymRead8(PSYM_EXTENSION Ext, ULONG Reg)
{
    return ScsiPortReadRegisterUchar(Ext->Regs + Reg);
}

static VOID
SymWrite8(PSYM_EXTENSION Ext, ULONG Reg, UCHAR Value)
{
    ScsiPortWriteRegisterUchar(Ext->Regs + Reg, Value);
}

static ULONG
SymRead32(PSYM_EXTENSION Ext, ULONG Reg)
{
    return ScsiPortReadRegisterUlong((PULONG)(Ext->Regs + Reg));
}

static VOID
SymWrite32(PSYM_EXTENSION Ext, ULONG Reg, ULONG Value)
{
    ScsiPortWriteRegisterUlong((PULONG)(Ext->Regs + Reg), Value);
}

static PSYM_XFER
SymXfer(PSYM_EXTENSION Ext)
{
    return (PSYM_XFER)(Ext->Mem + SYM_OFF_XFER);
}

static ULONG
SymXferPa(PSYM_EXTENSION Ext)
{
    return Ext->MemPa + SYM_OFF_XFER;
}

/* Start the script at an entry point */
static VOID
SymRunScript(PSYM_EXTENSION Ext, ULONG Entry)
{
    KeMemoryBarrier();
    SymWrite32(Ext, SYM_DSP, Ext->MemPa + Entry);
}

/* Reset the chip and program it (the register set-up of the OpenBSD driver); optionally reset the SCSI bus too */
static VOID
SymResetChip(PSYM_EXTENSION Ext, BOOLEAN ResetBus)
{
    SymWrite8(Ext, SYM_ISTAT, ISTAT_SRST);
    ScsiPortStallExecution(1000);
    SymWrite8(Ext, SYM_ISTAT, 0);

    SymWrite8(Ext, SYM_SCNTL0, SCNTL0_ARB_MASK | SCNTL0_EPC | SCNTL0_AAP);
    SymWrite8(Ext, SYM_SCNTL1, 0);
    SymWrite8(Ext, SYM_SCNTL3, SYM_CLOCK_DIV);
    SymWrite8(Ext, SYM_SXFER, 0);
    SymWrite8(Ext, SYM_DIEN, 0xFF);
    SymWrite8(Ext, SYM_SIEN0, (UCHAR)(0xFF & ~(SIEN0_CMP | SIEN0_SEL | SIEN0_RSL)));
    SymWrite8(Ext, SYM_SIEN1, (UCHAR)(0xFF & ~(SIEN1_HTH | SIEN1_GEN)));
    SymWrite8(Ext, SYM_STEST3, STEST3_TE);
    SymWrite8(Ext, SYM_STIME0, 0x0B);
    SymWrite8(Ext, SYM_SCID, SYM_HOST_ID | SCID_RRE);
    SymWrite8(Ext, SYM_RESPID0, 1 << SYM_HOST_ID);
    SymWrite8(Ext, SYM_DCNTL, DCNTL_COM);
    if (Ext->Is895A)
        SymWrite8(Ext, SYM_CTEST5, SymRead8(Ext, SYM_CTEST5) | CTEST5_DFS);

    if (ResetBus)
    {
        Ext->OwnReset = TRUE;
        Ext->UaTargets = (UCHAR)~(1 << SYM_HOST_ID);   /* every target reports a unit attention to its next command */
        SymWrite8(Ext, SYM_SCNTL1, SCNTL1_RST);
        ScsiPortStallExecution(100);            /* at least 25 microseconds */
        SymWrite8(Ext, SYM_SCNTL1, 0);
    }
}

/* Empty the DMA FIFO, bounded */
static VOID
SymClearFifo(PSYM_EXTENSION Ext)
{
    ULONG Waited;

    SymWrite8(Ext, SYM_CTEST3, SymRead8(Ext, SYM_CTEST3) | CTEST3_CLF);
    for (Waited = 0; Waited < 1000 && (SymRead8(Ext, SYM_CTEST3) & CTEST3_CLF); Waited++)
        ScsiPortStallExecution(1);
}

/* Complete the current request (if any) and let the port send the next one */
static VOID
SymFinish(PSYM_EXTENSION Ext, UCHAR Status)
{
    PSCSI_REQUEST_BLOCK Srb = Ext->Srb;

    Ext->Srb = NULL;
    Ext->State = SymIdle;
    if (Srb != NULL)
    {
        Srb->SrbStatus = Status;
        ScsiPortNotification(RequestComplete, Ext, Srb);
    }
    ScsiPortNotification(NextRequest, Ext, NULL);
}

/* Something the driver cannot continue from: fail the command and reset the chip and the bus */
static VOID
SymFatal(PSYM_EXTENSION Ext, PCCH Why, ULONG Value)
{
    DbgPrint("sym53c8xx: %s (%lx), resetting the bus\n", Why, Value);
    SymResetChip(Ext, TRUE);
    SymFinish(Ext, SRB_STATUS_ERROR);
}

/* Build the command block for a request. Returns FALSE (with the status set) when the request does not fit. */
static BOOLEAN
SymSetup(PSYM_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb, PUCHAR Status)
{
    PSYM_XFER Xfer = SymXfer(Ext);
    ULONG XferPa = SymXferPa(Ext);
    PUCHAR Va = Srb->DataBuffer;
    ULONG Remaining = Srb->DataTransferLength;
    ULONG Count = 0;

    RtlZeroMemory(Xfer, sizeof(*Xfer));
    Ext->Bounced = FALSE;

    /* The chip addresses 32 bits. The port gives the physical pages of the buffer as they are (the adapter says it handles
       64-bit addresses, so the HAL does not double-buffer): a request that has a page above 4 GB goes through the buffer
       below 4 GB instead. */
    while (Remaining != 0)
    {
        ULONG Chunk = 0;
        SCSI_PHYSICAL_ADDRESS Pa = ScsiPortGetPhysicalAddress(Ext, Srb, Va, &Chunk);

        if (Chunk == 0 || Pa.QuadPart == (LONGLONG)SP_UNINITIALIZED_VALUE)
        {
            *Status = SRB_STATUS_INVALID_REQUEST;
            return FALSE;
        }
        Chunk = min(Chunk, Remaining);

        if (Pa.HighPart != 0 || Pa.LowPart + Chunk < Pa.LowPart)
        {
            if (Ext->Bounce == NULL || Srb->DataTransferLength > SYM_BOUNCE_BYTES || Srb->DataBuffer == NULL)
            {
                *Status = SRB_STATUS_INVALID_REQUEST;
                return FALSE;
            }
            if (!Ext->BounceReported)
            {
                Ext->BounceReported = TRUE;
                DbgPrint("sym53c8xx: first request with a buffer above 4 GB, going through the buffer below it (%lu bytes)\n", Srb->DataTransferLength);
            }
            Ext->Bounced = TRUE;
            Count = 1;
            Xfer->Data[0].Count = Srb->DataTransferLength;
            Xfer->Data[0].Addr = Ext->BouncePa;
            if (Srb->SrbFlags & SRB_FLAGS_DATA_OUT)
                RtlCopyMemory(Ext->Bounce, Srb->DataBuffer, Srb->DataTransferLength);
            break;
        }

        if (Count != 0 && Xfer->Data[Count - 1].Addr + Xfer->Data[Count - 1].Count == Pa.LowPart &&
            (ULONGLONG)Xfer->Data[Count - 1].Count + Chunk <= 0xFFFFFF)
        {
            Xfer->Data[Count - 1].Count += Chunk;
        }
        else
        {
            if (Count == SYM_MAX_SEGS || Chunk > 0xFFFFFF)
            {
                *Status = SRB_STATUS_INVALID_REQUEST;
                return FALSE;
            }
            Xfer->Data[Count].Count = Chunk;
            Xfer->Data[Count].Addr = Pa.LowPart;
            Count++;
        }
        Va += Chunk;
        Remaining -= Chunk;
    }

    Xfer->Id = ((ULONG)SYM_CLOCK_DIV << 24) | ((ULONG)Srb->TargetId << 16);
    Xfer->MsgOutBuf[0] = (UCHAR)(0xC0 | (Srb->Lun & 7));        /* identify, disconnect allowed */
    Xfer->MsgOut.Count = 1;
    Xfer->MsgOut.Addr = XferPa + FIELD_OFFSET(SYM_XFER, MsgOutBuf);
    RtlCopyMemory(Xfer->Cdb, Srb->Cdb, Srb->CdbLength);
    Xfer->Cmd.Count = Srb->CdbLength;
    Xfer->Cmd.Addr = XferPa + FIELD_OFFSET(SYM_XFER, Cdb);
    Xfer->StatusBuf[0] = 0xFF;
    Xfer->Status.Count = 1;
    Xfer->Status.Addr = XferPa + FIELD_OFFSET(SYM_XFER, StatusBuf);
    Xfer->MsgIn.Count = 1;
    Xfer->MsgIn.Addr = XferPa + FIELD_OFFSET(SYM_XFER, MsgInBuf);

    Ext->Segs = Count;
    Ext->Total = Srb->DataTransferLength;
    Ext->Residual = 0;
    Ext->DataIn = (Srb->SrbFlags & SRB_FLAGS_DATA_IN) != 0;
    return TRUE;
}

static UCHAR
SymStatusFromScsi(PSCSI_REQUEST_BLOCK Srb, UCHAR Scsi)
{
    Srb->ScsiStatus = Scsi;
    switch (Scsi)
    {
        case SCSISTAT_GOOD:
        case SCSISTAT_CONDITION_MET:
            return SRB_STATUS_SUCCESS;
        case SCSISTAT_BUSY:
        case SCSISTAT_QUEUE_FULL:
            return SRB_STATUS_BUSY;
        default:
            return SRB_STATUS_ERROR;        /* check condition: the port asks for the sense data itself */
    }
}

/* The script reported the end of the command */
static VOID
SymDone(PSYM_EXTENSION Ext)
{
    PSCSI_REQUEST_BLOCK Srb = Ext->Srb;
    UCHAR Status;
    UCHAR TargetBit;
    BOOLEAN Ua;

    if (Srb == NULL || Ext->State != SymActive)
    {
        SymFatal(Ext, "command complete without a command", Ext->State);
        return;
    }

    /* After a bus reset the first command to every target is answered with CHECK CONDITION (unit attention: "power on, reset
       or bus device reset occurred"). The reset is ours, so the command is simply issued again, once: the port would give the
       failure to the class driver, which counts it against the few retries a request has. */
    TargetBit = (UCHAR)(1 << (Srb->TargetId & 7));
    Ua = (Ext->UaTargets & TargetBit) != 0;
    Ext->UaTargets &= (UCHAR)~TargetBit;
    if (Ua && SymXfer(Ext)->StatusBuf[0] == SCSISTAT_CHECK_CONDITION)
    {
        if (!Ext->UaReported)
        {
            Ext->UaReported = TRUE;
            DbgPrint("sym53c8xx: first command after a bus reset answered with CHECK CONDITION, issued again\n");
        }
        SymXfer(Ext)->StatusBuf[0] = 0xFF;
        Ext->Residual = 0;
        SymWrite32(Ext, SYM_DSA, SymXferPa(Ext));
        SymRunScript(Ext, SYM_ENT_START);
        return;
    }

    Status = SymStatusFromScsi(Srb, SymXfer(Ext)->StatusBuf[0]);
    if (Ext->Bounced && Ext->DataIn && Srb->DataBuffer != NULL && Ext->Residual <= Ext->Total)
        RtlCopyMemory(Srb->DataBuffer, Ext->Bounce, Ext->Total - Ext->Residual);
    if (Status == SRB_STATUS_SUCCESS && Ext->Residual != 0)
    {
        /* the target had less data than the request asked for */
        Srb->DataTransferLength = Ext->Total - Ext->Residual;
        Status = SRB_STATUS_DATA_OVERRUN;
    }
    SymFinish(Ext, Status);
}

/* Phase mismatch: the target ended a data phase early. Work out how much was moved and carry on at the next phase. */
static VOID
SymPhaseMismatch(PSYM_EXTENSION Ext)
{
    PSYM_XFER Xfer = SymXfer(Ext);
    ULONG XferPa = SymXferPa(Ext);
    ULONG Dsa = SymRead32(Ext, SYM_DSA);
    UCHAR Phase = SymRead8(Ext, SYM_SSTAT1) & SSTAT1_PHASE_MASK;
    UCHAR Flags = SymRead8(Ext, SYM_SCRATCHA);
    ULONG Index, Dbc, Remaining, i;

    if (Ext->State != SymActive || Ext->Srb == NULL || !(Flags & SYM_A_FLAG_DATA) || !Ext->DataIn)
    {
        SymFatal(Ext, "unexpected phase mismatch", Phase);
        return;
    }
    if (Phase != SSTAT1_PHASE_STATUS && Phase != SSTAT1_PHASE_MSGIN)
    {
        SymFatal(Ext, "phase mismatch to an unexpected phase", Phase);
        return;
    }

    /* the data element being moved is the one DSA points at; the script walks DSA along the table */
    if (Dsa < XferPa || ((Dsa - XferPa) & 7) != 0 || (Dsa - XferPa) / 8 >= Ext->Segs)
    {
        SymFatal(Ext, "data pointer outside the table", Dsa);
        return;
    }
    Index = (Dsa - XferPa) / 8;
    SymClearFifo(Ext);
    Dbc = SymRead32(Ext, SYM_DBC) & 0xFFFFFF;
    if (Dbc > Xfer->Data[Index].Count)
    {
        SymFatal(Ext, "byte count larger than the element", Dbc);
        return;
    }
    Remaining = Dbc;
    for (i = Index + 1; i < Ext->Segs; i++)
        Remaining += Xfer->Data[i].Count;
    if (Remaining > Ext->Total)
    {
        SymFatal(Ext, "residual larger than the transfer", Remaining);
        return;
    }
    Ext->Residual = Remaining;
    if (!Ext->ShortReported)
    {
        Ext->ShortReported = TRUE;
        DbgPrint("sym53c8xx: first transfer that ended early (%lu of %lu bytes not moved)\n", Remaining, Ext->Total);
    }

    SymWrite32(Ext, SYM_DSA, XferPa);
    SymRunScript(Ext, SYM_ENT_WAITPHASE);
}

/* A script interrupt (INT instruction): DSPS holds the code */
static VOID
SymScriptInterrupt(PSYM_EXTENSION Ext)
{
    ULONG Code = SymRead32(Ext, SYM_DSPS);

    switch (Code)
    {
        case SYM_A_INT_DONE:
            SymDone(Ext);
            break;

        case SYM_A_INT_DISC:
            if (Ext->State != SymActive || Ext->Srb == NULL)
            {
                SymFatal(Ext, "disconnect without a command", Ext->State);
                break;
            }
            if (SymRead8(Ext, SYM_SCRATCHA) & SYM_A_FLAG_DATA)
            {
                /* the data pointer would have to be restored after the reselection */
                SymFatal(Ext, "disconnect in the middle of a data transfer", 0);
                break;
            }
            Ext->State = SymDisconnected;
            SymRunScript(Ext, SYM_ENT_RESELECT);
            break;

        case SYM_A_INT_RESEL:
        {
            UCHAR Ssid = SymRead8(Ext, SYM_SSID);
            UCHAR Msg = SymXfer(Ext)->MsgInBuf[0];

            /* who reselected, and with which identify message: both come from the bus */
            if (Ext->State != SymDisconnected || Ext->Srb == NULL || !(Ssid & 0x80) ||
                (Ssid & 0x0F) != Ext->Srb->TargetId || (Msg & 0xC0) != 0x80 || (Msg & 7) != (Ext->Srb->Lun & 7))
            {
                SymFatal(Ext, "reselection that does not belong to the command", ((ULONG)Ssid << 8) | Msg);
                break;
            }
            Ext->State = SymActive;
            SymWrite8(Ext, SYM_SCRATCHA, 0);
            SymRunScript(Ext, SYM_ENT_MSGIN_ACK);
            break;
        }

        case SYM_A_INT_MSGIN:
            SymFatal(Ext, "message from the target that is not handled", SymXfer(Ext)->MsgInBuf[0]);
            break;

        default:
            SymFatal(Ext, "script error", Code);
            break;
    }
}

static BOOLEAN NTAPI
SymInterrupt(PVOID HwDeviceExtension)
{
    PSYM_EXTENSION Ext = HwDeviceExtension;
    UCHAR Istat = SymRead8(Ext, SYM_ISTAT);
    UCHAR Dstat = 0, Sist0 = 0, Sist1 = 0;

    if (Istat == 0xFF || (Istat & (ISTAT_DIP | ISTAT_SIP | ISTAT_INTF)) == 0)
        return FALSE;

    if (Istat & ISTAT_INTF)
        SymWrite8(Ext, SYM_ISTAT, ISTAT_INTF);

    if (Istat & ISTAT_SIP)
    {
        Sist0 = SymRead8(Ext, SYM_SIST0);
        Sist1 = SymRead8(Ext, SYM_SIST1);
    }
    if (Istat & ISTAT_DIP)
        Dstat = SymRead8(Ext, SYM_DSTAT);

    if (Sist0 & SIST0_RST)
    {
        if (Ext->OwnReset)
        {
            /* the reset the driver asked for: it has been dealt with where it was asked for */
            Ext->OwnReset = FALSE;
            return TRUE;
        }
        /* the bus was reset by a target or the chip: whatever was running is gone */
        SymResetChip(Ext, FALSE);
        SymFinish(Ext, SRB_STATUS_BUS_RESET);
        return TRUE;
    }
    if (Dstat & ~(DSTAT_DFE | DSTAT_SIR))
    {
        SymFatal(Ext, "DMA error", Dstat);
        return TRUE;
    }
    if (Sist0 & (SIST0_SGE | SIST0_PAR))
    {
        SymFatal(Ext, "SCSI gross or parity error", Sist0);
        return TRUE;
    }
    if (Sist0 & SIST0_MA)
    {
        if (!(Dstat & DSTAT_DFE))
            SymClearFifo(Ext);
        SymPhaseMismatch(Ext);
        return TRUE;
    }
    if (Sist1 & SIST1_STO)
    {
        /* nothing answered the selection */
        if (Ext->State != SymActive || Ext->Srb == NULL)
            SymFatal(Ext, "selection timeout without a command", Ext->State);
        else
            SymFinish(Ext, SRB_STATUS_SELECTION_TIMEOUT);
        return TRUE;
    }
    if (Sist0 & SIST0_UDC)
    {
        /* the target dropped off the bus: the command is lost */
        SymFatal(Ext, "unexpected disconnect", Sist0);
        return TRUE;
    }
    if ((Sist0 | Sist1) != 0)
    {
        SymFatal(Ext, "unhandled SCSI interrupt", ((ULONG)Sist1 << 8) | Sist0);
        return TRUE;
    }
    if (Dstat & DSTAT_SIR)
        SymScriptInterrupt(Ext);
    return TRUE;
}

static BOOLEAN
SymExecuteScsi(PSYM_EXTENSION Ext, PSCSI_REQUEST_BLOCK Srb)
{
    UCHAR Status;

    if (Srb->PathId != 0 || Srb->TargetId >= SYM_MAX_TARGETS || Srb->TargetId == SYM_HOST_ID || Srb->Lun != 0)
    {
        Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        ScsiPortNotification(RequestComplete, Ext, Srb);
        ScsiPortNotification(NextRequest, Ext, NULL);
        return TRUE;
    }
    if (Srb->CdbLength == 0 || Srb->CdbLength > 16)
    {
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        ScsiPortNotification(RequestComplete, Ext, Srb);
        ScsiPortNotification(NextRequest, Ext, NULL);
        return TRUE;
    }
    if (Ext->State != SymIdle)
    {
        /* the port waits for NextRequest: this should not happen; ask for a retry */
        Srb->SrbStatus = SRB_STATUS_BUSY;
        ScsiPortNotification(RequestComplete, Ext, Srb);
        return TRUE;
    }
    if (!SymSetup(Ext, Srb, &Status))
    {
        Srb->SrbStatus = Status;
        ScsiPortNotification(RequestComplete, Ext, Srb);
        ScsiPortNotification(NextRequest, Ext, NULL);
        return TRUE;
    }

    Ext->Srb = Srb;
    Ext->State = SymActive;
    SymWrite32(Ext, SYM_DSA, SymXferPa(Ext));
    SymRunScript(Ext, SYM_ENT_START);
    return TRUE;
}

/* The one recovery the driver has: reset the chip and the bus, fail what was running */
static BOOLEAN
SymReset(PSYM_EXTENSION Ext, ULONG PathId)
{
    PSCSI_REQUEST_BLOCK Srb = Ext->Srb;

    /* The command that was on the bus is lost with the reset (the data of a write is simply sent again). Failing it with
       BUS_RESET hands it back to the class driver, which gives a request up after 4 retries; a disk that stalls for 90 s
       costs the same request 6 resets, so the file system saw a failed write (the journal commit of a lone request) and
       stopped writing. BUSY makes the port start the same request again after the bus settle time, up to 20 times
       (a request that never gets an answer fails then); commands that bypass the queue keep BUS_RESET.
       The request is completed through the notification, not through ScsiPortCompleteRequest: that one sets the transfer
       length to 0, and the port starts the request again as it stands (a read with a length of 0 and a data phase). */
    if (Srb != NULL && Srb->Function == SRB_FUNCTION_EXECUTE_SCSI && !(Srb->SrbFlags & SRB_FLAGS_BYPASS_FROZEN_QUEUE))
    {
        Srb->SrbStatus = SRB_STATUS_BUSY;
        Srb->ScsiStatus = 0;
        ScsiPortNotification(RequestComplete, Ext, Srb);
    }
    else
    {
        ScsiPortCompleteRequest(Ext, (UCHAR)PathId, SP_UNTAGGED, SP_UNTAGGED, SRB_STATUS_BUS_RESET);
    }
    Ext->Srb = NULL;
    Ext->State = SymIdle;
    DbgPrint("sym53c8xx: reset of the bus, the chip was started again\n");
    SymResetChip(Ext, TRUE);
    ScsiPortNotification(NextRequest, Ext, NULL);       /* the port waits for it to send the next request */
    return TRUE;
}

static BOOLEAN NTAPI
SymStartIo(PVOID HwDeviceExtension, PSCSI_REQUEST_BLOCK Srb)
{
    PSYM_EXTENSION Ext = HwDeviceExtension;

    switch (Srb->Function)
    {
        case SRB_FUNCTION_EXECUTE_SCSI:
            return SymExecuteScsi(Ext, Srb);

        case SRB_FUNCTION_RESET_DEVICE:
            SymReset(Ext, Srb->PathId);
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        case SRB_FUNCTION_ABORT_COMMAND:
            /* no abort of a single command: the port escalates to a bus reset */
            Srb->SrbStatus = SRB_STATUS_ABORT_FAILED;
            break;

        case SRB_FUNCTION_FLUSH:
        case SRB_FUNCTION_SHUTDOWN:
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
            break;

        default:
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
    }

    ScsiPortNotification(RequestComplete, Ext, Srb);
    ScsiPortNotification(NextRequest, Ext, NULL);
    return TRUE;
}

static BOOLEAN NTAPI
SymResetBus(PVOID HwDeviceExtension, ULONG PathId)
{
    return SymReset(HwDeviceExtension, PathId);
}

static BOOLEAN NTAPI
SymInitialize(PVOID HwDeviceExtension)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    return TRUE;
}

static SCSI_ADAPTER_CONTROL_STATUS NTAPI
SymAdapterControl(PVOID HwDeviceExtension, SCSI_ADAPTER_CONTROL_TYPE ControlType, PVOID Parameters)
{
    PSYM_EXTENSION Ext = HwDeviceExtension;

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
            SymWrite8(Ext, SYM_ISTAT, ISTAT_SRST);      /* the chip stops and loses its interrupt enables */
            ScsiPortStallExecution(1000);
            SymWrite8(Ext, SYM_ISTAT, 0);
            return ScsiAdapterControlSuccess;

        case ScsiRestartAdapter:
            SymResetChip(Ext, FALSE);
            Ext->State = SymIdle;
            Ext->Srb = NULL;
            return ScsiAdapterControlSuccess;

        default:
            return ScsiAdapterControlUnsuccessful;
    }
}

/* Make sure the controller decodes its registers and may master the bus: a firmware that has no driver for the device (UEFI
   boots without a driver for the chip) leaves the decode and bus master bits off. */
static VOID
SymEnableDevice(PVOID Ext, PPORT_CONFIGURATION_INFORMATION ConfigInfo)
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

static ULONG NTAPI
SymFindAdapter(
    IN PVOID HwDeviceExtension,
    IN PVOID Context,
    IN PVOID BusInformation,
    IN PCHAR ArgumentString,
    IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    OUT PBOOLEAN Again)
{
    PSYM_EXTENSION Ext = HwDeviceExtension;
    PACCESS_RANGE Range = NULL;
    SCSI_PHYSICAL_ADDRESS Pa;
    ULONG Length = 0;
    ULONG i;

    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);

    *Again = FALSE;
    Ext->Is895A = (Context != NULL);
    SymEnableDevice(Ext, ConfigInfo);

    /* The registers are in the first memory BAR that is large enough (the I/O port BAR and the script RAM BAR are not used) */
    for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
    {
        PACCESS_RANGE R = &(*ConfigInfo->AccessRanges)[i];

        if (R->RangeInMemory && R->RangeLength >= SYM_REGS_LENGTH && R->RangeLength <= 0x1000)
        {
            Range = R;
            break;
        }
    }
    if (Range == NULL)
    {
        DbgPrint("sym53c8xx: no register range among %lu\n", ConfigInfo->NumberOfAccessRanges);
        return SP_RETURN_NOT_FOUND;
    }

    if (!ScsiPortValidateRange(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                               Range->RangeStart, Range->RangeLength, FALSE))
        return SP_RETURN_BAD_CONFIG;

    Ext->Regs = ScsiPortGetDeviceBase(Ext, ConfigInfo->AdapterInterfaceType, ConfigInfo->SystemIoBusNumber,
                                      Range->RangeStart, Range->RangeLength, FALSE);
    if (Ext->Regs == NULL)
    {
        DbgPrint("sym53c8xx: cannot map the registers\n");
        return SP_RETURN_ERROR;
    }
    if (SymRead8(Ext, SYM_ISTAT) == 0xFF)
        return SP_RETURN_NOT_FOUND;                 /* nothing answers at the registers */

    ConfigInfo->NumberOfBuses = 1;
    ConfigInfo->MaximumNumberOfTargets = SYM_MAX_TARGETS;
    ConfigInfo->MaximumNumberOfLogicalUnits = 1;
    ConfigInfo->MaximumTransferLength = (SYM_MAX_SEGS - 1) * PAGE_SIZE;
    ConfigInfo->NumberOfPhysicalBreaks = SYM_MAX_SEGS - 1;
    ConfigInfo->ScatterGather = TRUE;
    ConfigInfo->Master = TRUE;
    ConfigInfo->NeedPhysicalAddresses = TRUE;
    ConfigInfo->Dma32BitAddresses = TRUE;
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;     /* the miniport takes care of buffers above 4 GB */
    ConfigInfo->TaggedQueuing = FALSE;
    ConfigInfo->MultipleRequestPerLu = FALSE;
    ConfigInfo->AutoRequestSense = FALSE;
    ConfigInfo->AlignmentMask = 0;
    ConfigInfo->InterruptMode = LevelSensitive;
    ConfigInfo->InitiatorBusId[0] = SYM_HOST_ID;
    ConfigInfo->WmiDataProvider = FALSE;

    /* The script and the command block must be contiguous and below 4 GB. The port's common buffer is asked for first
       (it also makes the adapter object); when it is above 4 GB the driver takes a page of its own. */
    Ext->Mem = ScsiPortGetUncachedExtension(Ext, ConfigInfo, PAGE_SIZE);
    if (Ext->Mem == NULL)
        return SP_RETURN_ERROR;
    Pa = ScsiPortGetPhysicalAddress(Ext, NULL, Ext->Mem, &Length);
    if (Length < PAGE_SIZE || (Pa.QuadPart & (PAGE_SIZE - 1)) != 0)
        return SP_RETURN_ERROR;
    if (Pa.HighPart != 0)
    {
        PHYSICAL_ADDRESS Limit;

        Limit.QuadPart = 0xFFFFFFFFULL;
        Ext->Mem = MmAllocateContiguousMemory(PAGE_SIZE, Limit);
        if (Ext->Mem == NULL)
            return SP_RETURN_ERROR;
        Pa = MmGetPhysicalAddress(Ext->Mem);
        if (Pa.HighPart != 0)
            return SP_RETURN_ERROR;
    }
    Ext->MemPa = Pa.LowPart;

    {
        PHYSICAL_ADDRESS Limit, BouncePa;

        Limit.QuadPart = 0xFFFFFFFFULL;
        Ext->Bounce = MmAllocateContiguousMemory(SYM_BOUNCE_BYTES, Limit);
        if (Ext->Bounce == NULL)
            return SP_RETURN_ERROR;
        BouncePa = MmGetPhysicalAddress(Ext->Bounce);
        if (BouncePa.HighPart != 0 || BouncePa.LowPart + SYM_BOUNCE_BYTES < BouncePa.LowPart)
            return SP_RETURN_ERROR;
        Ext->BouncePa = BouncePa.LowPart;
    }

    RtlZeroMemory(Ext->Mem, PAGE_SIZE);
    RtlCopyMemory(Ext->Mem, SymScript, SYM_SCRIPT_BYTES);
    Ext->State = SymIdle;
    SymResetChip(Ext, FALSE);

    /* Ask to be called again: the port looks for the next controller of this kind on the bus */
    *Again = TRUE;
    return SP_RETURN_FOUND;
}

static NTSTATUS
SymInitialization(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath, PUCHAR DeviceId, PVOID HwContext)
{
    HW_INITIALIZATION_DATA Init;
    UCHAR VendorId[4] = { '1', '0', '0', '0' };

    RtlZeroMemory(&Init, sizeof(Init));
    Init.HwInitializationDataSize = sizeof(Init);
    Init.HwInitialize = SymInitialize;
    Init.HwStartIo = SymStartIo;
    Init.HwInterrupt = SymInterrupt;
    Init.HwFindAdapter = SymFindAdapter;
    Init.HwResetBus = SymResetBus;
    Init.HwAdapterControl = SymAdapterControl;
    Init.AdapterInterfaceType = PCIBus;
    Init.VendorId = VendorId;
    Init.VendorIdLength = sizeof(VendorId);
    Init.DeviceId = DeviceId;
    Init.DeviceIdLength = 4;
    Init.NumberOfAccessRanges = 3;
    Init.DeviceExtensionSize = sizeof(SYM_EXTENSION);
    Init.SrbExtensionSize = 0;
    Init.NeedPhysicalAddresses = TRUE;
    Init.MapBuffers = TRUE;                     /* the buffer of a request is mapped: the bounce buffer is filled and emptied by the driver */
    Init.TaggedQueuing = FALSE;
    Init.MultipleRequestPerLu = FALSE;
    Init.AutoRequestSense = FALSE;

    return ScsiPortInitialize(DriverObject, RegistryPath, &Init, HwContext);
}

NTSTATUS NTAPI
DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UCHAR Id895A[4] = { '0', '0', '1', '2' };
    UCHAR Id810[4] = { '0', '0', '0', '1' };
    NTSTATUS Status1, Status2;

    /* One pass per chip: the 895A has the larger DMA FIFO */
    Status1 = SymInitialization(DriverObject, RegistryPath, Id895A, (PVOID)1);
    Status2 = SymInitialization(DriverObject, RegistryPath, Id810, NULL);

    return NT_SUCCESS(Status1) ? Status1 : Status2;
}
