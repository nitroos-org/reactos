/*
 * PROJECT:         ReactOS NVMe Storport Miniport Driver
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Driver-private definitions
 * COPYRIGHT:       Copyright 2026 Tomas Srnka
 *
 * Written from the public NVM Express Base Specification (revision 1.4) and the
 * NVM Express SCSI Translation Reference (revision 1.5). No third-party source
 * code was used.
 */

#pragma once

#include <ntddk.h>
#include <storport.h>

#include "nvme.h"

#define NVME_TAG                    'emvN'

/* Host memory page size used for the controller (CC.MPS = 0) */
#define NVME_PAGE_SHIFT             12
#define NVME_PAGE_SIZE              (1UL << NVME_PAGE_SHIFT)
#define NVME_PAGE_MASK              (NVME_PAGE_SIZE - 1)

#define NVME_ADMIN_QUEUE_DEPTH      32
#define NVME_IO_QUEUE_DEPTH_MAX     256
#define NVME_IO_QUEUE_ID            1

/* Every I/O command slot owns this much DMA memory: its PRP list, or its DSM ranges */
#define NVME_SLOT_DMA_BYTES         1024
#define NVME_PRP_ENTRIES_PER_SLOT   (NVME_SLOT_DMA_BYTES / sizeof(ULONGLONG))
#define NVME_DSM_RANGES_PER_SLOT    (NVME_SLOT_DMA_BYTES / sizeof(NVME_DSM_RANGE))

/*
 * Largest transfer: what one slot's PRP list maps (PRP1 holds the first page, the list
 * the other 128 of an unaligned buffer). The controller's MDTS lowers it.
 */
#define NVME_MAX_TRANSFER_BYTES     (512 * 1024)
C_ASSERT(NVME_MAX_TRANSFER_BYTES <= NVME_PRP_ENTRIES_PER_SLOT * NVME_PAGE_SIZE);

#define NVME_MAX_NAMESPACES         8

/* Watchdog period and command timeouts */
#define NVME_TIMER_PERIOD_US        1000000
#define NVME_DEFAULT_TIMEOUT_S      10
#define NVME_ABORT_GRACE_S          5

typedef enum _NVME_SLOT_KIND
{
    SlotKindSrb = 1,        /* An SRB waits for this command */
    SlotKindSetWce,         /* MODE SELECT changing the volatile write cache; SRB waits */
    SlotKindAbort,          /* Internal Abort command, nobody waits */
    SlotKindPoll            /* Synchronous command, polled by the submitter */
} NVME_SLOT_KIND;

typedef struct _NVME_SLOT
{
    PSCSI_REQUEST_BLOCK Srb;
    ULONG Deadline;         /* in watchdog ticks */
    ULONG Context;
    UCHAR Busy;
    UCHAR Kind;
    UCHAR TimedOut;
    UCHAR AbortSent;
} NVME_SLOT, *PNVME_SLOT;

typedef struct _NVME_QUEUE
{
    USHORT Qid;
    USHORT Depth;           /* entries in the SQ and the CQ */
    USHORT SlotCount;       /* Depth - 1: the SQ can never overflow */
    USHORT SqTail;
    USHORT CqHead;
    UCHAR CqPhase;
    UCHAR Reserved;
    USHORT NextSlot;
    USHORT Outstanding;
    PNVME_COMMAND Sq;
    PNVME_COMPLETION Cq;
    PHYSICAL_ADDRESS SqPa;
    PHYSICAL_ADDRESS CqPa;
    PULONG SqDoorbell;
    PULONG CqDoorbell;
    PNVME_SLOT Slots;
    PUCHAR SlotDma;         /* NVME_SLOT_DMA_BYTES per slot (I/O queue only) */
    PHYSICAL_ADDRESS SlotDmaPa;
} NVME_QUEUE, *PNVME_QUEUE;

typedef struct _NVME_NAMESPACE
{
    ULONG Nsid;
    ULONG BlockShift;
    ULONGLONG BlockCount;
    UCHAR Nguid[16];
    UCHAR Eui64[8];
    UCHAR Dlfeat;
    UCHAR Nsfeat;
} NVME_NAMESPACE, *PNVME_NAMESPACE;

typedef struct _NVME_EXTENSION
{
    PUCHAR Registers;
    ULONG RegistersLength;
    ULONGLONG Cap;
    ULONG Version;
    ULONG DoorbellStride;   /* bytes */
    ULONG ReadyTimeoutMs;

    PUCHAR Uncached;
    PHYSICAL_ADDRESS UncachedPa;
    ULONG UncachedSize;

    NVME_QUEUE AdminQueue;
    NVME_QUEUE IoQueue;
    NVME_SLOT AdminSlots[NVME_ADMIN_QUEUE_DEPTH];
    NVME_SLOT IoSlots[NVME_IO_QUEUE_DEPTH_MAX];

    PUCHAR IdentifyBuffer;
    PHYSICAL_ADDRESS IdentifyPa;

    /* From Identify Controller */
    USHORT Vid;
    USHORT Oncs;
    USHORT Oacs;
    UCHAR Vwc;
    UCHAR Mdts;
    ULONG Nn;
    ULONG Ver;
    ULONG Rtd3e;
    CHAR Sn[20];
    CHAR Mn[40];
    CHAR Fr[8];

    BOOLEAN WriteCacheEnabled;
    ULONG MaxTransferBytes;
    USHORT IoQueueDepth;

    ULONG NamespaceCount;
    NVME_NAMESPACE Namespaces[NVME_MAX_NAMESPACES];

    /* State; changed only with the interrupt lock held, or before the interrupt is connected */
    BOOLEAN Ready;          /* queues live, the ISR may process completions */
    BOOLEAN Failed;         /* the controller could not be (re)initialized */
    BOOLEAN ShutDown;       /* CC.SHN done; the next request re-enables the controller */
    BOOLEAN TimerRunning;
    ULONG Tick;

    /* Result of the synchronous (polled) command */
    BOOLEAN PollDone;
    USHORT PollStatus;
    ULONG PollDw0;

    /* Counters, for the debug log */
    ULONG Flushes;
    ULONG Resets;
    ULONG Timeouts;
    ULONG Interrupts;       /* ISR calls that found completions */
    ULONG PolledTicks;      /* watchdog ticks that found completions the ISR had not taken */
} NVME_EXTENSION, *PNVME_EXTENSION;

/* srb.h's SCSI_SUPPORTED_CONTROL_TYPE_LIST; storport.h does not have it */
typedef struct _NVME_CONTROL_TYPE_LIST
{
    ULONG MaxControlType;
    BOOLEAN SupportedTypeList[ANYSIZE_ARRAY];
} NVME_CONTROL_TYPE_LIST, *PNVME_CONTROL_TYPE_LIST;

typedef struct _NVME_SRB_EXTENSION
{
    /* Storport needs a non-empty SRB extension; nothing per request lives here yet */
    ULONG Reserved[2];
} NVME_SRB_EXTENSION, *PNVME_SRB_EXTENSION;

/* stornvme.c */
BOOLEAN
NvmeSubmitSrbCommand(
    _In_ PNVME_EXTENSION Ext,
    _In_ PNVME_QUEUE Queue,
    _In_ PNVME_COMMAND Command,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ NVME_SLOT_KIND Kind,
    _In_ ULONG Context,
    _In_ BOOLEAN NeedPrp);

BOOLEAN
NvmeSubmitSync(
    _In_ PNVME_EXTENSION Ext,
    _In_ PNVME_QUEUE Queue,
    _Inout_ PNVME_COMMAND Command,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PUSHORT Status,
    _Out_opt_ PULONG Dw0);

BOOLEAN
NvmeShutdownController(
    _In_ PNVME_EXTENSION Ext);

BOOLEAN
NvmeEnsureReady(
    _In_ PNVME_EXTENSION Ext);

/* scsi.c */
VOID
NvmeScsiExecute(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb);

VOID
NvmeScsiFlush(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb);

VOID
NvmeScsiCompleteFromStatus(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ USHORT Status,
    _In_ BOOLEAN TimedOut);

VOID
NvmeScsiSetSense(
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ UCHAR SenseKey,
    _In_ UCHAR Asc,
    _In_ UCHAR Ascq);

FORCEINLINE
VOID
NvmeCompleteSrb(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ UCHAR SrbStatus)
{
    if (SrbStatus != 0xFF)
        Srb->SrbStatus = SrbStatus;
    StorPortNotification(RequestComplete, Ext, Srb);
}
