/*
 * PROJECT:         ReactOS NVMe Storport Miniport Driver
 * LICENSE:         GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:         Controller initialization, queues, interrupt, watchdog
 * COPYRIGHT:       Copyright 2026 Tomas Srnka
 *
 * Written from the public NVM Express Base Specification (revision 1.4) only.
 * No third-party source code was used.
 *
 * Design:
 * - One admin queue pair and one I/O queue pair, legacy INTx (vector 0). Storport here
 *   connects a single line-based interrupt only, so more queues would add nothing.
 * - All queue state is guarded by the interrupt spinlock: HwStartIo takes it through
 *   StorPortAcquireSpinLock(InterruptLock), the ISR runs under it, the watchdog takes it.
 * - The SQ has one more entry than there are command slots, so it can never overflow
 *   and the SQ head reported in completions is not needed.
 * - A 1 s watchdog polls the completion queues (a lost interrupt only costs latency),
 *   sends an NVMe Abort for an expired command, and resets the controller when the abort
 *   does not help; outstanding requests then complete with SRB_STATUS_BUS_RESET or
 *   SRB_STATUS_TIMEOUT and the class driver retries them.
 * - Resets, re-enabling after a shutdown and the shutdown itself run as a state machine
 *   driven by the watchdog (see CONTROLLER below): nothing waits at raised IRQL.
 */

#include "stornvme.h"

#include <debug.h>

#define NvmeLog(...)    StorPortDebugPrint(0, "stornvme: " __VA_ARGS__)

/* REGISTER ACCESS ************************************************************/

static
ULONG
NvmeRead32(
    _In_ PNVME_EXTENSION Ext,
    _In_ ULONG Offset)
{
    return StorPortReadRegisterUlong(Ext, (PULONG)(Ext->Registers + Offset));
}

static
VOID
NvmeWrite32(
    _In_ PNVME_EXTENSION Ext,
    _In_ ULONG Offset,
    _In_ ULONG Value)
{
    StorPortWriteRegisterUlong(Ext, (PULONG)(Ext->Registers + Offset), Value);
}

static
ULONGLONG
NvmeRead64(
    _In_ PNVME_EXTENSION Ext,
    _In_ ULONG Offset)
{
    ULONG Low = NvmeRead32(Ext, Offset);
    ULONG High = NvmeRead32(Ext, Offset + 4);
    return ((ULONGLONG)High << 32) | Low;
}

static
VOID
NvmeWrite64(
    _In_ PNVME_EXTENSION Ext,
    _In_ ULONG Offset,
    _In_ ULONGLONG Value)
{
    NvmeWrite32(Ext, Offset, (ULONG)Value);
    NvmeWrite32(Ext, Offset + 4, (ULONG)(Value >> 32));
}

static
VOID
NvmeLock(
    _In_ PNVME_EXTENSION Ext,
    _Out_ PSTOR_LOCK_HANDLE LockHandle)
{
    StorPortAcquireSpinLock(Ext, InterruptLock, NULL, LockHandle);
}

static
VOID
NvmeUnlock(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSTOR_LOCK_HANDLE LockHandle)
{
    StorPortReleaseSpinLock(Ext, LockHandle);
}

static
VOID
NvmeCopyString(
    _Out_writes_(Length) PCHAR Destination,
    _In_reads_(Length) const UCHAR *Source,
    _In_ ULONG Length)
{
    ULONG i;

    for (i = 0; i < Length; i++)
    {
        UCHAR c = Source[i];
        Destination[i] = (c >= 0x20 && c < 0x7F) ? (CHAR)c : ' ';
    }
}

/* QUEUES *********************************************************************/

static
VOID
NvmeResetQueueState(
    _Inout_ PNVME_QUEUE Queue)
{
    RtlZeroMemory(Queue->Sq, Queue->Depth * sizeof(NVME_COMMAND));
    RtlZeroMemory(Queue->Cq, Queue->Depth * sizeof(NVME_COMPLETION));
    RtlZeroMemory(Queue->Slots, Queue->SlotCount * sizeof(NVME_SLOT));
    Queue->SqTail = 0;
    Queue->CqHead = 0;
    Queue->CqPhase = 1;
    Queue->NextSlot = 0;
    Queue->Outstanding = 0;
}

static
LONG
NvmeAllocateSlot(
    _Inout_ PNVME_QUEUE Queue)
{
    USHORT i, Index;

    for (i = 0; i < Queue->SlotCount; i++)
    {
        Index = (USHORT)((Queue->NextSlot + i) % Queue->SlotCount);
        if (!Queue->Slots[Index].Busy)
        {
            UCHAR Gen = Queue->Slots[Index].Gen;

            RtlZeroMemory(&Queue->Slots[Index], sizeof(NVME_SLOT));
            Queue->Slots[Index].Gen = (UCHAR)(Gen + 1);
            Queue->Slots[Index].Busy = TRUE;
            Queue->NextSlot = (USHORT)((Index + 1) % Queue->SlotCount);
            Queue->Outstanding++;
            return Index;
        }
    }

    return -1;
}

static
VOID
NvmeFreeSlot(
    _Inout_ PNVME_QUEUE Queue,
    _In_ USHORT Index)
{
    Queue->Slots[Index].Busy = FALSE;
    Queue->Slots[Index].Srb = NULL;
    Queue->Outstanding--;
}

static
VOID
NvmeRingSubmission(
    _In_ PNVME_EXTENSION Ext,
    _Inout_ PNVME_QUEUE Queue,
    _In_ PNVME_COMMAND Command)
{
    RtlCopyMemory(&Queue->Sq[Queue->SqTail], Command, sizeof(NVME_COMMAND));
    Queue->SqTail = (USHORT)((Queue->SqTail + 1) % Queue->Depth);

    /* The entry must be in memory before the controller sees the new tail */
    KeMemoryBarrier();
    StorPortWriteRegisterUlong(Ext, Queue->SqDoorbell, Queue->SqTail);
}

/*
 * Fills PRP1/PRP2 of Command from the SRB's scatter/gather list. The PRP list, when one
 * is needed, goes into the slot's DMA area. Returns FALSE when the buffer cannot be
 * described with PRPs (a misaligned element), or is larger than one slot can map.
 */
static
BOOLEAN
NvmeBuildPrps(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ ULONG Length,
    _Inout_ PNVME_COMMAND Command,
    _Out_writes_(NVME_PRP_ENTRIES_PER_SLOT) PULONGLONG PrpList,
    _In_ PHYSICAL_ADDRESS PrpListPa)
{
    PSTOR_SCATTER_GATHER_LIST SgList;
    ULONG Entries = 0;
    ULONG Remaining = Length;
    ULONG Element = 0;
    BOOLEAN First = TRUE;
    ULONGLONG Address = 0;
    ULONG ElementLength = 0;
    ULONG Step;
    PUCHAR VirtualAddress = (PUCHAR)Srb->DataBuffer;

    SgList = StorPortGetScatterGatherList(Ext, Srb);

    while (Remaining > 0)
    {
        /* Fetch the next physically contiguous run */
        if (SgList != NULL)
        {
            if (Element >= SgList->NumberOfElements)
                return FALSE;

            Address = SgList->List[Element].PhysicalAddress.QuadPart;
            ElementLength = SgList->List[Element].Length;
            Element++;
        }
        else
        {
            /* No list from the port driver: translate the (locked, mapped) buffer page by page */
            STOR_PHYSICAL_ADDRESS Pa;
            ULONG Contiguous;

            Pa = StorPortGetPhysicalAddress(Ext, Srb, VirtualAddress, &Contiguous);
            Address = Pa.QuadPart;
            ElementLength = NVME_PAGE_SIZE - (ULONG)((ULONG_PTR)VirtualAddress & NVME_PAGE_MASK);
            VirtualAddress += ElementLength;
        }

        if (ElementLength > Remaining)
            ElementLength = Remaining;
        if (ElementLength == 0)
            continue;

        if (First)
        {
            /* PRP1 may carry an offset, but it must be dword aligned */
            if (Address & 3)
                return FALSE;

            Command->Prp1 = Address;
            Step = NVME_PAGE_SIZE - (ULONG)(Address & NVME_PAGE_MASK);
            if (Step > ElementLength)
                Step = ElementLength;

            Address += Step;
            ElementLength -= Step;
            Remaining -= Step;
            First = FALSE;

            /* The first page must be completed before another run starts */
            if (ElementLength == 0 && Remaining > 0 && (Address & NVME_PAGE_MASK))
                return FALSE;
        }
        else if (Address & NVME_PAGE_MASK)
        {
            /* Every later run must start on a page */
            return FALSE;
        }

        while (ElementLength > 0)
        {
            if (Entries >= NVME_PRP_ENTRIES_PER_SLOT)
                return FALSE;

            PrpList[Entries++] = Address;
            Step = (ElementLength > NVME_PAGE_SIZE) ? NVME_PAGE_SIZE : ElementLength;
            Address += Step;
            ElementLength -= Step;
            Remaining -= Step;

            /* A run that ends inside a page must be the last one */
            if (ElementLength == 0 && Remaining > 0 && (Address & NVME_PAGE_MASK))
                return FALSE;
        }
    }

    if (Entries == 0)
        Command->Prp2 = 0;
    else if (Entries == 1)
        Command->Prp2 = PrpList[0];
    else
        Command->Prp2 = PrpListPa.QuadPart;

    return TRUE;
}

/*
 * Queues a command that completes an SRB. Called with the interrupt lock held.
 * On FALSE the SRB was not queued and the caller completes it.
 */
BOOLEAN
NvmeSubmitSrbCommand(
    _In_ PNVME_EXTENSION Ext,
    _In_ PNVME_QUEUE Queue,
    _In_ PNVME_COMMAND Command,
    _In_ PSCSI_REQUEST_BLOCK Srb,
    _In_ NVME_SLOT_KIND Kind,
    _In_ ULONG Context,
    _In_ BOOLEAN NeedPrp)
{
    LONG Slot;
    ULONG Timeout;

    Slot = NvmeAllocateSlot(Queue);
    if (Slot < 0)
    {
        Srb->SrbStatus = SRB_STATUS_BUSY;
        return FALSE;
    }

    if (NeedPrp)
    {
        PHYSICAL_ADDRESS PrpPa;

        PrpPa.QuadPart = Queue->SlotDmaPa.QuadPart + (ULONGLONG)Slot * NVME_SLOT_DMA_BYTES;
        if (!NvmeBuildPrps(Ext,
                           Srb,
                           Srb->DataTransferLength,
                           Command,
                           (PULONGLONG)(Queue->SlotDma + Slot * NVME_SLOT_DMA_BYTES),
                           PrpPa))
        {
            NvmeLog("cannot map buffer %p length %lu\n", Srb->DataBuffer, Srb->DataTransferLength);
            NvmeFreeSlot(Queue, (USHORT)Slot);
            Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
            return FALSE;
        }
    }

    Timeout = Srb->TimeOutValue ? Srb->TimeOutValue : NVME_DEFAULT_TIMEOUT_S;

    Queue->Slots[Slot].Srb = Srb;
    Queue->Slots[Slot].Kind = (UCHAR)Kind;
    Queue->Slots[Slot].Context = Context;
    Queue->Slots[Slot].Deadline = Ext->NowMs + (Timeout + 1) * 1000;

    Command->CommandId = NVME_CID(Slot, Queue->Slots[Slot].Gen);
    NvmeRingSubmission(Ext, Queue, Command);
    return TRUE;
}

/* Hands an SRB-bound slot back to storport after a reset or a failed controller */
static
VOID
NvmeFailSlot(
    _In_ PNVME_EXTENSION Ext,
    _Inout_ PNVME_QUEUE Queue,
    _In_ USHORT Index,
    _In_ UCHAR SrbStatus)
{
    NVME_SLOT Slot = Queue->Slots[Index];

    NvmeFreeSlot(Queue, Index);

    if (Slot.Kind == SlotKindSrb || Slot.Kind == SlotKindSetWce)
    {
        Slot.Srb->DataTransferLength = 0;
        NvmeCompleteSrb(Ext, Slot.Srb, Slot.TimedOut ? SRB_STATUS_TIMEOUT : SrbStatus);
    }
    else if (Slot.Kind == SlotKindPoll)
    {
        Ext->PollDone = TRUE;
        Ext->PollStatus = (USHORT)(NVME_SC_ABORT_SQ_DELETED << 1);
    }
    else if (Slot.Kind == SlotKindInternal)
    {
        Ext->InternalDone = TRUE;
        Ext->InternalStatus = (USHORT)(NVME_SC_ABORT_SQ_DELETED << 1);
    }
}

static
VOID
NvmeCompleteSlot(
    _In_ PNVME_EXTENSION Ext,
    _Inout_ PNVME_QUEUE Queue,
    _In_ USHORT CommandId,
    _In_ USHORT Status,
    _In_ ULONG Dw0)
{
    NVME_SLOT Slot;
    USHORT Index = NVME_CID_SLOT(CommandId);

    if (Index >= Queue->SlotCount || !Queue->Slots[Index].Busy ||
        Queue->Slots[Index].Gen != NVME_CID_GEN(CommandId))
    {
        NvmeLog("queue %u: completion for idle command 0x%x (status 0x%x)\n",
                Queue->Qid, CommandId, Status);
        return;
    }

    Slot = Queue->Slots[Index];
    NvmeFreeSlot(Queue, Index);

    switch (Slot.Kind)
    {
        case SlotKindSrb:
            NvmeScsiCompleteFromStatus(Ext, Slot.Srb, Status, Slot.TimedOut);
            break;

        case SlotKindSetWce:
            if (NVME_CQE_SC(Status) == NVME_SC_SUCCESS && NVME_CQE_SCT(Status) == NVME_SCT_GENERIC)
                Ext->WriteCacheEnabled = (BOOLEAN)Slot.Context;
            NvmeScsiCompleteFromStatus(Ext, Slot.Srb, Status, Slot.TimedOut);
            break;

        case SlotKindAbort:
            /* Dw0 bit 0 set: the command was not aborted; the watchdog resets then */
            break;

        case SlotKindPoll:
            Ext->PollDone = TRUE;
            Ext->PollStatus = Status;
            Ext->PollDw0 = Dw0;
            break;

        case SlotKindInternal:
            Ext->InternalDone = TRUE;
            Ext->InternalStatus = Status;
            Ext->InternalDw0 = Dw0;
            break;
    }
}

/* Consumes new completion entries. Called with the interrupt lock held (or before the
   interrupt is connected). Returns TRUE if there was at least one. */
static
BOOLEAN
NvmeProcessCompletions(
    _In_ PNVME_EXTENSION Ext,
    _Inout_ PNVME_QUEUE Queue)
{
    BOOLEAN Found = FALSE;

    for (;;)
    {
        volatile NVME_COMPLETION *Entry = &Queue->Cq[Queue->CqHead];
        USHORT Status = Entry->Status;
        USHORT CommandId;
        ULONG Dw0;

        if (NVME_CQE_PHASE(Status) != Queue->CqPhase)
            break;

        /* Read the rest of the entry only after its phase bit */
        KeMemoryBarrier();
        CommandId = Entry->CommandId;
        Dw0 = Entry->Dw0;

        Queue->CqHead++;
        if (Queue->CqHead == Queue->Depth)
        {
            Queue->CqHead = 0;
            Queue->CqPhase ^= 1;
        }

        Found = TRUE;
        NvmeCompleteSlot(Ext, Queue, CommandId, Status, Dw0);
    }

    if (Found)
        StorPortWriteRegisterUlong(Ext, Queue->CqDoorbell, Queue->CqHead);

    return Found;
}

/*
 * Runs one command synchronously by polling its completion queue. HwFindAdapter only:
 * PASSIVE_LEVEL, before the interrupt is connected. Everything later goes through the
 * state machine, which never waits.
 */
BOOLEAN
NvmeSubmitSync(
    _In_ PNVME_EXTENSION Ext,
    _In_ PNVME_QUEUE Queue,
    _Inout_ PNVME_COMMAND Command,
    _In_ ULONG TimeoutMs,
    _Out_opt_ PUSHORT Status,
    _Out_opt_ PULONG Dw0)
{
    LONG Slot;
    ULONG Waited;

    Slot = NvmeAllocateSlot(Queue);
    if (Slot < 0)
        return FALSE;

    Queue->Slots[Slot].Kind = SlotKindPoll;
    Queue->Slots[Slot].Deadline = MAXULONG;

    Ext->PollDone = FALSE;
    Ext->PollStatus = 0;
    Ext->PollDw0 = 0;

    Command->CommandId = NVME_CID(Slot, Queue->Slots[Slot].Gen);
    NvmeRingSubmission(Ext, Queue, Command);

    /* Poll in 10 us steps */
    for (Waited = 0; Waited < TimeoutMs * 100; Waited++)
    {
        NvmeProcessCompletions(Ext, Queue);
        if (Ext->PollDone)
            break;
        StorPortStallExecution(10);
    }

    if (!Ext->PollDone)
    {
        NvmeLog("queue %u: command 0x%02x timed out\n", Queue->Qid, Command->Opcode);
        /* The slot stays busy; the controller is reset before it is reused */
        return FALSE;
    }

    if (Status)
        *Status = Ext->PollStatus;
    if (Dw0)
        *Dw0 = Ext->PollDw0;

    return (NVME_CQE_SC(Ext->PollStatus) == NVME_SC_SUCCESS &&
            NVME_CQE_SCT(Ext->PollStatus) == NVME_SCT_GENERIC);
}

static
BOOLEAN
NvmeIdentifyNamespace(
    _In_ PNVME_EXTENSION Ext,
    _In_ ULONG Nsid,
    _Out_ PNVME_NAMESPACE Namespace)
{
    PNVME_IDENTIFY_NAMESPACE Id = (PNVME_IDENTIFY_NAMESPACE)Ext->IdentifyBuffer;
    NVME_COMMAND Cmd = {0};
    PNVME_LBA_FORMAT Format;

    Cmd.Opcode = NVME_ADMIN_IDENTIFY;
    Cmd.Nsid = Nsid;
    Cmd.Prp1 = Ext->IdentifyPa.QuadPart;
    Cmd.Cdw10 = NVME_CNS_NAMESPACE;

    RtlZeroMemory(Id, sizeof(*Id));
    if (!NvmeSubmitSync(Ext, &Ext->AdminQueue, &Cmd, Ext->ReadyTimeoutMs, NULL, NULL))
        return FALSE;

    /* Inactive namespace */
    if (Id->Nsze == 0)
        return FALSE;

    Format = &Id->Lbaf[NVME_FLBAS_INDEX(Id->Flbas)];

    /* Metadata would need MPTR or an extended LBA; such namespaces are left alone */
    if (Format->Ms != 0)
    {
        NvmeLog("namespace %lu: metadata size %u not supported, skipped\n", Nsid, Format->Ms);
        return FALSE;
    }

    if (Format->Lbads < 9 || Format->Lbads > 12)
    {
        NvmeLog("namespace %lu: LBA size 2^%u not supported, skipped\n", Nsid, Format->Lbads);
        return FALSE;
    }

    RtlZeroMemory(Namespace, sizeof(*Namespace));
    Namespace->Nsid = Nsid;
    Namespace->BlockShift = Format->Lbads;
    Namespace->BlockCount = Id->Nsze;
    Namespace->Dlfeat = Id->Dlfeat;
    Namespace->Nsfeat = Id->Nsfeat;
    RtlCopyMemory(Namespace->Nguid, Id->Nguid, sizeof(Namespace->Nguid));
    RtlCopyMemory(Namespace->Eui64, Id->Eui64, sizeof(Namespace->Eui64));

    return TRUE;
}

static
VOID
NvmeScanNamespaces(
    _In_ PNVME_EXTENSION Ext)
{
    ULONG Nsids[NVME_MAX_NAMESPACES];
    ULONG Count = 0;
    ULONG i;

    /* NVMe 1.1 and later list the active namespaces */
    if (Ext->Version >= 0x00010100)
    {
        NVME_COMMAND Cmd = {0};
        PULONG List = (PULONG)Ext->IdentifyBuffer;

        Cmd.Opcode = NVME_ADMIN_IDENTIFY;
        Cmd.Nsid = 0;
        Cmd.Prp1 = Ext->IdentifyPa.QuadPart;
        Cmd.Cdw10 = NVME_CNS_ACTIVE_NS_LIST;

        RtlZeroMemory(List, NVME_PAGE_SIZE);
        if (NvmeSubmitSync(Ext, &Ext->AdminQueue, &Cmd, Ext->ReadyTimeoutMs, NULL, NULL))
        {
            for (i = 0; i < NVME_PAGE_SIZE / sizeof(ULONG) && List[i] != 0 && Count < NVME_MAX_NAMESPACES; i++)
                Nsids[Count++] = List[i];
        }
    }

    /* NVMe 1.0, or no list: probe the first namespaces */
    if (Count == 0)
    {
        for (i = 1; i <= Ext->Nn && Count < NVME_MAX_NAMESPACES; i++)
            Nsids[Count++] = i;
    }

    Ext->NamespaceCount = 0;
    for (i = 0; i < Count; i++)
    {
        PNVME_NAMESPACE Namespace = &Ext->Namespaces[Ext->NamespaceCount];

        if (NvmeIdentifyNamespace(Ext, Nsids[i], Namespace))
        {
            NvmeLog("namespace %lu: %I64u blocks of %lu bytes\n",
                    Namespace->Nsid, Namespace->BlockCount, 1UL << Namespace->BlockShift);
            Ext->NamespaceCount++;
        }
    }
}

/* The state machine and the dispatcher call each other */
VOID NvmeStartMachine(_In_ PNVME_EXTENSION Ext, _In_ BOOLEAN Shutdown);
VOID NvmeDispatch(_In_ PNVME_EXTENSION Ext, _In_ PSCSI_REQUEST_BLOCK Srb);

/* CONTROLLER *****************************************************************/

/*
 * Nothing below waits at raised IRQL. Bringing the controller up or down takes CAP.TO or
 * RTD3E, seconds, so it runs as a state machine: every step only reads or writes registers
 * or submits one admin command, and the watchdog drives it (every 10 ms while it runs)
 * with the interrupt lock held. HwFindAdapter drives the same machine synchronously at
 * PASSIVE_LEVEL before the interrupt is connected.
 *
 * Requests that come while the controller is not live are parked and dispatched when it
 * is live again (failed if it cannot come back). Outstanding commands are handed back to
 * storport only once CC.EN=0 and CSTS.RDY=0 confirm the controller has stopped; if it does
 * not stop within CAP.TO, bus mastering is turned off in its PCI command register first,
 * so it cannot write into buffers that went back.
 */

static
VOID
NvmeAppendDeferred(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    ((PNVME_SRB_EXTENSION)Srb->SrbExtension)->Next = NULL;
    if (Ext->DeferredTail)
        ((PNVME_SRB_EXTENSION)Ext->DeferredTail->SrbExtension)->Next = Srb;
    else
        Ext->DeferredHead = Srb;
    Ext->DeferredTail = Srb;
}

static
VOID
NvmeCompleteChain(
    _In_ PNVME_EXTENSION Ext,
    _In_opt_ PSCSI_REQUEST_BLOCK Srb,
    _In_ UCHAR SrbStatus)
{
    while (Srb)
    {
        PSCSI_REQUEST_BLOCK Next = ((PNVME_SRB_EXTENSION)Srb->SrbExtension)->Next;
        Srb->DataTransferLength = 0;
        NvmeCompleteSrb(Ext, Srb, SrbStatus);
        Srb = Next;
    }
}

/* Fails every outstanding command back to storport. Only once the controller has stopped
   (or cannot reach memory any more). */
static
VOID
NvmeReleaseOutstanding(
    _In_ PNVME_EXTENSION Ext,
    _In_ UCHAR SrbStatus)
{
    USHORT i;

    for (i = 0; i < Ext->IoQueue.SlotCount; i++)
    {
        if (Ext->IoQueue.Slots[i].Busy)
            NvmeFailSlot(Ext, &Ext->IoQueue, i, SrbStatus);
    }

    for (i = 0; i < Ext->AdminQueue.SlotCount; i++)
    {
        if (Ext->AdminQueue.Slots[i].Busy)
            NvmeFailSlot(Ext, &Ext->AdminQueue, i, SrbStatus);
    }
}

/* Turns bus mastering off (or back on) in the PCI command register. Not at DIRQL. */
static
VOID
NvmeSetBusMaster(
    _In_ PNVME_EXTENSION Ext,
    _In_ BOOLEAN Enable)
{
    UCHAR Config[8];
    USHORT Command;

    if (StorPortGetBusData(Ext, PCIConfiguration, Ext->SystemIoBusNumber, Ext->SlotNumber,
                           Config, sizeof(Config)) < sizeof(Config))
    {
        NvmeLog("cannot read the PCI command register\n");
        return;
    }

    Command = (USHORT)(Config[4] | (Config[5] << 8));
    if (Enable)
        Command |= 0x0004;
    else
        Command &= ~0x0004;

    StorPortSetBusDataByOffset(Ext, PCIConfiguration, Ext->SystemIoBusNumber, Ext->SlotNumber,
                               &Command, 4, sizeof(Command));
    NvmeLog("bus mastering %s\n", Enable ? "back on" : "turned off: the controller did not stop");
}

static
VOID
NvmeParseIdentifyController(
    _In_ PNVME_EXTENSION Ext)
{
    PNVME_IDENTIFY_CONTROLLER Id = (PNVME_IDENTIFY_CONTROLLER)Ext->IdentifyBuffer;

    Ext->Vid = Id->Vid;
    Ext->Oncs = Id->Oncs;
    Ext->Oacs = Id->Oacs;
    Ext->Vwc = Id->Vwc;
    Ext->Mdts = Id->Mdts;
    Ext->Nn = Id->Nn;
    Ext->Ver = Id->Ver;
    Ext->Rtd3e = Id->Rtd3e;
    NvmeCopyString(Ext->Sn, Id->Sn, sizeof(Ext->Sn));
    NvmeCopyString(Ext->Mn, Id->Mn, sizeof(Ext->Mn));
    NvmeCopyString(Ext->Fr, Id->Fr, sizeof(Ext->Fr));

    /* MDTS is in units of the minimum memory page size; 0 means no limit */
    Ext->MaxTransferBytes = NVME_MAX_TRANSFER_BYTES;
    if (Ext->Mdts != 0 && Ext->Mdts < 20)
    {
        ULONGLONG Limit = (ULONGLONG)NVME_PAGE_SIZE << (NVME_CAP_MPSMIN(Ext->Cap) + Ext->Mdts);
        if (Limit < Ext->MaxTransferBytes)
            Ext->MaxTransferBytes = (ULONG)Limit;
    }
}

/*
 * The machine's admin (or flush) command: submitted on the first call, then polled.
 * Returns FALSE while it runs; then TRUE, with *Ok telling whether it succeeded.
 */
static
BOOLEAN
NvmeStepCommand(
    _In_ PNVME_EXTENSION Ext,
    _In_ PNVME_QUEUE Queue,
    _In_ PNVME_COMMAND Command,
    _In_ ULONG TimeoutMs,
    _Out_ PBOOLEAN Ok)
{
    LONG Slot;

    *Ok = FALSE;

    if (!Ext->StepIssued)
    {
        Slot = NvmeAllocateSlot(Queue);
        if (Slot < 0)
            return TRUE;

        Queue->Slots[Slot].Kind = SlotKindInternal;
        Queue->Slots[Slot].Deadline = Ext->NowMs + TimeoutMs;
        Ext->InternalDone = FALSE;
        Ext->InternalStatus = 0;
        Ext->InternalDw0 = 0;
        Ext->StepIssued = TRUE;
        Ext->StepDeadline = Ext->NowMs + TimeoutMs;

        Command->CommandId = NVME_CID(Slot, Queue->Slots[Slot].Gen);
        NvmeRingSubmission(Ext, Queue, Command);
        return FALSE;
    }

    /* The interrupt may be masked: look at the queue ourselves */
    NvmeProcessCompletions(Ext, Queue);

    if (Ext->InternalDone)
    {
        Ext->StepIssued = FALSE;
        *Ok = (NVME_CQE_SC(Ext->InternalStatus) == NVME_SC_SUCCESS &&
               NVME_CQE_SCT(Ext->InternalStatus) == NVME_SCT_GENERIC);
        return TRUE;
    }

    if ((LONG)(Ext->NowMs - Ext->StepDeadline) >= 0)
    {
        /* The slot stays busy until the next disable releases it */
        NvmeLog("queue %u: command 0x%02x timed out\n", Queue->Qid, Command->Opcode);
        Ext->StepIssued = FALSE;
        return TRUE;
    }

    return FALSE;
}

/* Called with the interrupt lock held when the controller is live again */
static
VOID
NvmeMachineLive(
    _In_ PNVME_EXTENSION Ext)
{
    PSCSI_REQUEST_BLOCK Srb, Next;

    Ext->State = NvmeStateLive;
    Ext->Attempts = 0;

    /* HwInitialize opens the interrupt the first time */
    if (Ext->InFindAdapter)
        return;

    Ext->Ready = TRUE;
    NvmeWrite32(Ext, NVME_REG_INTMC, 1);

    Srb = Ext->ResetWaiters;
    Ext->ResetWaiters = NULL;
    NvmeCompleteChain(Ext, Srb, SRB_STATUS_SUCCESS);

    Srb = Ext->DeferredHead;
    Ext->DeferredHead = Ext->DeferredTail = NULL;
    while (Srb && Ext->State == NvmeStateLive)
    {
        Next = ((PNVME_SRB_EXTENSION)Srb->SrbExtension)->Next;
        NvmeDispatch(Ext, Srb);
        Srb = Next;
    }

    /* A shutdown request in the chain started the machine again: park the rest */
    while (Srb)
    {
        Next = ((PNVME_SRB_EXTENSION)Srb->SrbExtension)->Next;
        NvmeAppendDeferred(Ext, Srb);
        Srb = Next;
    }
}

/* The controller cannot be brought up: everything waiting fails */
static
VOID
NvmeMachineGiveUp(
    _In_ PNVME_EXTENSION Ext)
{
    PSCSI_REQUEST_BLOCK Srb;

    NvmeLog("controller failed (reset %lu)\n", Ext->Resets);
    Ext->State = NvmeStateFailed;
    Ext->Ready = FALSE;
    NvmeWrite32(Ext, NVME_REG_INTMS, 1);

    Srb = Ext->ResetWaiters;
    Ext->ResetWaiters = NULL;
    NvmeCompleteChain(Ext, Srb, SRB_STATUS_ERROR);

    Srb = Ext->DeferredHead;
    Ext->DeferredHead = Ext->DeferredTail = NULL;
    NvmeCompleteChain(Ext, Srb, SRB_STATUS_ERROR);

    if (Ext->ShutdownSrb)
    {
        NvmeCompleteSrb(Ext, Ext->ShutdownSrb, SRB_STATUS_ERROR);
        Ext->ShutdownSrb = NULL;
    }
}

/* A step failed after the controller was disabled once: start over, a few times */
static
VOID
NvmeMachineRetry(
    _In_ PNVME_EXTENSION Ext)
{
    if (++Ext->Attempts >= NVME_MACHINE_ATTEMPTS)
    {
        NvmeWrite32(Ext, NVME_REG_CC, NvmeRead32(Ext, NVME_REG_CC) & ~NVME_CC_EN);
        NvmeMachineGiveUp(Ext);
        return;
    }

    Ext->StepIssued = FALSE;
    Ext->Step = StepDisable;
}

/* The shutdown steps are done: report the request, wake the controller if work waits */
static
VOID
NvmeMachineShutdownDone(
    _In_ PNVME_EXTENSION Ext)
{
    PSCSI_REQUEST_BLOCK Srb, Next, Keep = NULL, KeepTail = NULL;

    Ext->State = NvmeStateShutdown;
    Ext->ShutdownSeen = TRUE;

    NvmeLog("shutdown notification %s (flushes %lu, interrupts %lu, polled ticks %lu, timeouts %lu, resets %lu)\n",
            Ext->ShutdownOk ? "complete" : "FAILED", Ext->Flushes,
            Ext->Interrupts, Ext->PolledTicks, Ext->Timeouts, Ext->Resets);

    if (Ext->ShutdownSrb)
    {
        NvmeCompleteSrb(Ext, Ext->ShutdownSrb, Ext->ShutdownOk ? SRB_STATUS_SUCCESS : SRB_STATUS_ERROR);
        Ext->ShutdownSrb = NULL;
    }

    /* Shutdown and flush requests that waited have nothing left to do */
    Srb = Ext->DeferredHead;
    Ext->DeferredHead = Ext->DeferredTail = NULL;
    while (Srb)
    {
        Next = ((PNVME_SRB_EXTENSION)Srb->SrbExtension)->Next;
        if ((Srb->Function == SRB_FUNCTION_SHUTDOWN || Srb->Function == SRB_FUNCTION_FLUSH) && Ext->ShutdownOk)
        {
            NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
        }
        else
        {
            ((PNVME_SRB_EXTENSION)Srb->SrbExtension)->Next = NULL;
            if (KeepTail)
                ((PNVME_SRB_EXTENSION)KeepTail->SrbExtension)->Next = Srb;
            else
                Keep = Srb;
            KeepTail = Srb;
        }
        Srb = Next;
    }
    Ext->DeferredHead = Keep;
    Ext->DeferredTail = KeepTail;

    if (Ext->DeferredHead)
        NvmeStartMachine(Ext, FALSE);
}

/*
 * Starts the machine: a reset (or re-enable) when Shutdown is FALSE, the shutdown steps
 * otherwise. Called with the interrupt lock held.
 */
VOID
NvmeStartMachine(
    _In_ PNVME_EXTENSION Ext,
    _In_ BOOLEAN Shutdown)
{
    if (Ext->State == NvmeStateStopped)
        return;

    if (Ext->State == NvmeStateMachine)
    {
        /* A reset is already under way; a reset beats a shutdown */
        if (!Ext->GoalShutdown || Shutdown)
            return;

        if (Ext->ShutdownSrb)
        {
            NvmeCompleteSrb(Ext, Ext->ShutdownSrb, SRB_STATUS_ERROR);
            Ext->ShutdownSrb = NULL;
        }
    }

    Ext->State = NvmeStateMachine;
    Ext->GoalShutdown = Shutdown;
    Ext->StepIssued = FALSE;
    Ext->NeedBusMasterOff = FALSE;

    if (Shutdown)
    {
        Ext->ShutdownOk = TRUE;
        Ext->FlushIndex = 0;
        Ext->StepDeadline = Ext->NowMs + NVME_DRAIN_TIMEOUT_MS;
        Ext->Step = StepDrain;
    }
    else
    {
        Ext->Resets++;
        NvmeLog("resetting the controller (reset %lu)\n", Ext->Resets);
        Ext->Ready = FALSE;
        NvmeWrite32(Ext, NVME_REG_INTMS, 1);
        Ext->Step = StepDisable;
    }
}

/*
 * Advances the machine as far as it can without waiting. Called with the interrupt lock
 * held (by the watchdog), or by HwFindAdapter before the interrupt is connected.
 */
static
VOID
NvmeMachineStep(
    _In_ PNVME_EXTENSION Ext)
{
    PNVME_QUEUE Admin = &Ext->AdminQueue;
    PNVME_QUEUE Io = &Ext->IoQueue;
    NVME_COMMAND Cmd;
    BOOLEAN Ok;
    ULONG Csts, Cc, Limit;

    while (Ext->State == NvmeStateMachine)
    {
        RtlZeroMemory(&Cmd, sizeof(Cmd));

        switch (Ext->Step)
        {
            case StepDisable:
                Cc = NvmeRead32(Ext, NVME_REG_CC);
                if (Cc & NVME_CC_EN)
                    NvmeWrite32(Ext, NVME_REG_CC, Cc & ~(NVME_CC_EN | NVME_CC_SHN_MASK));
                Ext->StepDeadline = Ext->NowMs + Ext->ReadyTimeoutMs;
                Ext->Step = StepWaitDisabled;
                continue;

            case StepWaitDisabled:
                Csts = NvmeRead32(Ext, NVME_REG_CSTS);
                if (Csts != MAXULONG && !(Csts & NVME_CSTS_RDY))
                {
                    /* Stopped: what it held goes back, the class driver retries */
                    NvmeReleaseOutstanding(Ext, SRB_STATUS_BUS_RESET);
                    Ext->Step = StepEnable;
                    continue;
                }

                if (Csts == MAXULONG || (LONG)(Ext->NowMs - Ext->StepDeadline) >= 0)
                {
                    NvmeLog("controller did not stop (CSTS 0x%lx)\n", Csts);
                    Ext->NeedBusMasterOff = TRUE;
                    Ext->Step = StepWaitBusMaster;
                }
                return;

            case StepWaitBusMaster:
                if (!Ext->BusMasterOff)
                    return;

                /* It cannot reach memory any more, but neither can it be used */
                NvmeReleaseOutstanding(Ext, SRB_STATUS_BUS_RESET);
                NvmeMachineGiveUp(Ext);
                return;

            case StepEnable:
                NvmeResetQueueState(Admin);
                NvmeResetQueueState(Io);
                NvmeWrite32(Ext, NVME_REG_AQA, ((ULONG)(Admin->Depth - 1) << 16) | (Admin->Depth - 1));
                NvmeWrite64(Ext, NVME_REG_ASQ, Admin->SqPa.QuadPart);
                NvmeWrite64(Ext, NVME_REG_ACQ, Admin->CqPa.QuadPart);
                NvmeWrite32(Ext, NVME_REG_CC, NVME_CC_CSS_NVM | NVME_CC_MPS(0) | NVME_CC_AMS_RR |
                                              NVME_CC_IOSQES(6) | NVME_CC_IOCQES(4) | NVME_CC_EN);
                Ext->StepDeadline = Ext->NowMs + Ext->ReadyTimeoutMs;
                Ext->Step = StepWaitEnabled;
                continue;

            case StepWaitEnabled:
                Csts = NvmeRead32(Ext, NVME_REG_CSTS);
                if (Csts == MAXULONG || (Csts & NVME_CSTS_CFS))
                {
                    NvmeLog("controller fatal status while enabling (CSTS 0x%lx)\n", Csts);
                    NvmeMachineRetry(Ext);
                    continue;
                }
                if (Csts & NVME_CSTS_RDY)
                {
                    Ext->Step = Ext->Identify ? StepIdentify : StepNumQueues;
                    continue;
                }
                if ((LONG)(Ext->NowMs - Ext->StepDeadline) >= 0)
                {
                    NvmeLog("timeout waiting for CSTS.RDY=1 (CSTS 0x%lx)\n", Csts);
                    NvmeMachineRetry(Ext);
                    continue;
                }
                return;

            case StepIdentify:
                Cmd.Opcode = NVME_ADMIN_IDENTIFY;
                Cmd.Prp1 = Ext->IdentifyPa.QuadPart;
                Cmd.Cdw10 = NVME_CNS_CONTROLLER;
                if (!Ext->StepIssued)
                    RtlZeroMemory(Ext->IdentifyBuffer, NVME_PAGE_SIZE);
                if (!NvmeStepCommand(Ext, Admin, &Cmd, Ext->ReadyTimeoutMs, &Ok))
                    return;
                if (!Ok)
                {
                    NvmeLog("Identify Controller failed\n");
                    NvmeMachineRetry(Ext);
                    continue;
                }
                NvmeParseIdentifyController(Ext);
                Ext->Step = StepNumQueues;
                continue;

            case StepNumQueues:
                /* One I/O submission and one completion queue (0's based) */
                Cmd.Opcode = NVME_ADMIN_SET_FEATURES;
                Cmd.Cdw10 = NVME_FEAT_NUM_QUEUES;
                if (!NvmeStepCommand(Ext, Admin, &Cmd, Ext->ReadyTimeoutMs, &Ok))
                    return;
                if (!Ok)
                {
                    NvmeLog("Set Features (Number of Queues) failed\n");
                    NvmeMachineRetry(Ext);
                    continue;
                }
                Ext->Step = StepGetVwc;
                continue;

            case StepGetVwc:
                /* Current state of the volatile write cache (a reset restores the default) */
                if (!(Ext->Vwc & NVME_VWC_PRESENT))
                {
                    Ext->WriteCacheEnabled = FALSE;
                    Ext->Step = StepCreateCq;
                    continue;
                }
                Cmd.Opcode = NVME_ADMIN_GET_FEATURES;
                Cmd.Cdw10 = NVME_FEAT_VOLATILE_WC;
                if (!NvmeStepCommand(Ext, Admin, &Cmd, Ext->ReadyTimeoutMs, &Ok))
                    return;
                Ext->WriteCacheEnabled = Ok ? ((Ext->InternalDw0 & 1) ? TRUE : FALSE) : TRUE;
                Ext->Step = StepCreateCq;
                continue;

            case StepCreateCq:
                Cmd.Opcode = NVME_ADMIN_CREATE_CQ;
                Cmd.Prp1 = Io->CqPa.QuadPart;
                Cmd.Cdw10 = ((ULONG)(Io->Depth - 1) << 16) | Io->Qid;
                Cmd.Cdw11 = (0UL << 16) | 0x2 /* IEN */ | 0x1 /* PC */;
                if (!NvmeStepCommand(Ext, Admin, &Cmd, Ext->ReadyTimeoutMs, &Ok))
                    return;
                if (!Ok)
                {
                    NvmeLog("Create I/O Completion Queue failed\n");
                    NvmeMachineRetry(Ext);
                    continue;
                }
                Ext->Step = StepCreateSq;
                continue;

            case StepCreateSq:
                Cmd.Opcode = NVME_ADMIN_CREATE_SQ;
                Cmd.Prp1 = Io->SqPa.QuadPart;
                Cmd.Cdw10 = ((ULONG)(Io->Depth - 1) << 16) | Io->Qid;
                Cmd.Cdw11 = ((ULONG)Io->Qid << 16) | 0x1 /* PC */;
                if (!NvmeStepCommand(Ext, Admin, &Cmd, Ext->ReadyTimeoutMs, &Ok))
                    return;
                if (!Ok)
                {
                    NvmeLog("Create I/O Submission Queue failed\n");
                    NvmeMachineRetry(Ext);
                    continue;
                }
                NvmeMachineLive(Ext);
                return;

            case StepDrain:
                /* Commands already submitted finish first (the ISR still runs) */
                NvmeProcessCompletions(Ext, Admin);
                NvmeProcessCompletions(Ext, Io);
                if (Io->Outstanding == 0 && Admin->Outstanding == 0)
                {
                    Ext->Step = StepFlush;
                    continue;
                }
                if ((LONG)(Ext->NowMs - Ext->StepDeadline) >= 0)
                {
                    NvmeLog("shutdown with %u commands still outstanding\n", Io->Outstanding + Admin->Outstanding);
                    Ext->ShutdownOk = FALSE;
                    Ext->Step = StepFlush;
                    continue;
                }
                return;

            case StepFlush:
                /* Write back the volatile cache of every namespace */
                if (!(Ext->Vwc & NVME_VWC_PRESENT) || Ext->FlushIndex >= Ext->NamespaceCount)
                {
                    Ext->Step = StepShutdownNotify;
                    continue;
                }
                Cmd.Opcode = NVME_CMD_FLUSH;
                Cmd.Nsid = Ext->Namespaces[Ext->FlushIndex].Nsid;
                if (!Ext->StepIssued)
                    Ext->Flushes++;
                if (!NvmeStepCommand(Ext, Io, &Cmd, NVME_FLUSH_TIMEOUT_MS, &Ok))
                    return;
                if (!Ok)
                {
                    NvmeLog("shutdown flush of namespace %lu failed\n", Cmd.Nsid);
                    Ext->ShutdownOk = FALSE;
                }
                Ext->FlushIndex++;
                continue;

            case StepShutdownNotify:
                Ext->Ready = FALSE;
                NvmeWrite32(Ext, NVME_REG_INTMS, 1);
                Cc = NvmeRead32(Ext, NVME_REG_CC);
                NvmeWrite32(Ext, NVME_REG_CC, (Cc & ~NVME_CC_SHN_MASK) | NVME_CC_SHN_NORMAL);

                /* RTD3E (microseconds) says how long the controller may take; wait 1..10 s */
                Limit = Ext->Rtd3e / 1000;
                Limit = max(Limit, 1000);
                Limit = min(Limit, 10000);
                Ext->StepDeadline = Ext->NowMs + Limit;
                Ext->Step = StepWaitShutdown;
                continue;

            case StepWaitShutdown:
                if ((NvmeRead32(Ext, NVME_REG_CSTS) & NVME_CSTS_SHST_MASK) == NVME_CSTS_SHST_COMPLETE)
                {
                    NvmeMachineShutdownDone(Ext);
                    return;
                }
                if ((LONG)(Ext->NowMs - Ext->StepDeadline) >= 0)
                {
                    NvmeLog("shutdown notification timed out\n");
                    Ext->ShutdownOk = FALSE;
                    NvmeMachineShutdownDone(Ext);
                }
                return;
        }
    }
}

/*
 * HwFindAdapter: brings the controller up with the same machine, polling at PASSIVE_LEVEL
 * (no interrupt is connected yet), then identifies the namespaces.
 */
static
BOOLEAN
NvmeBringUpSync(
    _In_ PNVME_EXTENSION Ext)
{
    ULONG Waited;
    ULONG Limit = 4 * Ext->ReadyTimeoutMs * NVME_MACHINE_ATTEMPTS + 10000;

    Ext->InFindAdapter = TRUE;
    Ext->Identify = TRUE;
    Ext->State = NvmeStateMachine;
    Ext->GoalShutdown = FALSE;
    Ext->StepIssued = FALSE;
    Ext->Step = StepDisable;
    NvmeWrite32(Ext, NVME_REG_INTMS, 1);

    for (Waited = 0; Waited < Limit && Ext->State == NvmeStateMachine; Waited++)
    {
        NvmeMachineStep(Ext);
        if (Ext->NeedBusMasterOff)
        {
            Ext->NeedBusMasterOff = FALSE;
            NvmeSetBusMaster(Ext, FALSE);
            Ext->BusMasterOff = TRUE;
            continue;
        }
        if (Ext->State != NvmeStateMachine)
            break;
        StorPortStallExecution(1000);
        Ext->NowMs++;
    }

    Ext->InFindAdapter = FALSE;
    Ext->Identify = FALSE;

    if (Ext->State != NvmeStateLive)
        return FALSE;

    NvmeScanNamespaces(Ext);
    return TRUE;
}

/* Hands a request to the controller. Called with the interrupt lock held, the state live. */
VOID
NvmeDispatch(
    _In_ PNVME_EXTENSION Ext,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    switch (Srb->Function)
    {
        case SRB_FUNCTION_EXECUTE_SCSI:
            NvmeScsiExecute(Ext, Srb);
            break;

        case SRB_FUNCTION_FLUSH:
            NvmeScsiFlush(Ext, Srb);
            break;

        case SRB_FUNCTION_SHUTDOWN:
            /* Drain, write back the cache, CC.SHN; the machine completes the request */
            Ext->ShutdownSrb = Srb;
            NvmeStartMachine(Ext, TRUE);
            break;

        case SRB_FUNCTION_RESET_BUS:
        case SRB_FUNCTION_RESET_DEVICE:
        case SRB_FUNCTION_RESET_LOGICAL_UNIT:
            /* Completed when the controller is back */
            ((PNVME_SRB_EXTENSION)Srb->SrbExtension)->Next = Ext->ResetWaiters;
            Ext->ResetWaiters = Srb;
            NvmeStartMachine(Ext, FALSE);
            break;

        case SRB_FUNCTION_ABORT_COMMAND:
        case SRB_FUNCTION_PNP:
        case SRB_FUNCTION_POWER:
            NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
            break;

        default:
            NvmeCompleteSrb(Ext, Srb, SRB_STATUS_INVALID_REQUEST);
            break;
    }
}

/* WATCHDOG *******************************************************************/

static
VOID
NTAPI
NvmeHwTimer(
    _In_ PVOID DeviceExtension)
{
    PNVME_EXTENSION Ext = (PNVME_EXTENSION)DeviceExtension;
    STOR_LOCK_HANDLE LockHandle;
    BOOLEAN NeedReset = FALSE;
    BOOLEAN BusMasterOff;
    ULONG Period;
    USHORT i;

    NvmeLock(Ext, &LockHandle);

    /* ScsiStopAdapter cancelled the timer; a tick that was already queued ends here */
    if (Ext->State == NvmeStateStopped)
    {
        Ext->TimerRunning = FALSE;
        NvmeUnlock(Ext, &LockHandle);
        return;
    }

    Ext->NowMs += Ext->TimerPeriodUs / 1000;

    if (Ext->State == NvmeStateLive && Ext->Ready)
    {
        /* A lost or late interrupt costs at most one period */
        if (NvmeProcessCompletions(Ext, &Ext->AdminQueue) |
            NvmeProcessCompletions(Ext, &Ext->IoQueue))
        {
            if (Ext->PolledTicks++ == 0)
                NvmeLog("watchdog found completions the interrupt did not deliver\n");
        }

        for (i = 0; i < Ext->IoQueue.SlotCount; i++)
        {
            PNVME_SLOT Slot = &Ext->IoQueue.Slots[i];

            if (!Slot->Busy || Slot->Kind == SlotKindPoll || (LONG)(Ext->NowMs - Slot->Deadline) < 0)
                continue;

            if (!Slot->AbortSent)
            {
                NVME_COMMAND Cmd = {0};
                LONG AbortSlot;

                Ext->Timeouts++;
                NvmeLog("I/O command %u timed out, aborting\n", i);
                Slot->TimedOut = TRUE;
                Slot->AbortSent = TRUE;
                Slot->Deadline = Ext->NowMs + NVME_ABORT_GRACE_S * 1000;

                AbortSlot = NvmeAllocateSlot(&Ext->AdminQueue);
                if (AbortSlot < 0)
                {
                    NeedReset = TRUE;
                    break;
                }

                Ext->AdminQueue.Slots[AbortSlot].Kind = SlotKindAbort;
                Ext->AdminQueue.Slots[AbortSlot].Deadline = Ext->NowMs + NVME_ABORT_GRACE_S * 1000;

                /* The command identifier carries the slot's generation */
                Cmd.Opcode = NVME_ADMIN_ABORT;
                Cmd.Cdw10 = ((ULONG)NVME_CID(i, Slot->Gen) << 16) | Ext->IoQueue.Qid;
                Cmd.CommandId = NVME_CID(AbortSlot, Ext->AdminQueue.Slots[AbortSlot].Gen);
                NvmeRingSubmission(Ext, &Ext->AdminQueue, &Cmd);
            }
            else
            {
                /* The abort did not help */
                NeedReset = TRUE;
                break;
            }
        }

        for (i = 0; !NeedReset && i < Ext->AdminQueue.SlotCount; i++)
        {
            PNVME_SLOT Slot = &Ext->AdminQueue.Slots[i];

            if (Slot->Busy && Slot->Kind != SlotKindPoll && (LONG)(Ext->NowMs - Slot->Deadline) >= 0)
            {
                NvmeLog("admin command %u timed out\n", i);
                Slot->TimedOut = TRUE;
                NeedReset = TRUE;
            }
        }

        if (NeedReset)
            NvmeStartMachine(Ext, FALSE);
    }

    if (Ext->State == NvmeStateMachine)
        NvmeMachineStep(Ext);

    BusMasterOff = Ext->NeedBusMasterOff;
    Ext->NeedBusMasterOff = FALSE;

    Period = (Ext->State == NvmeStateMachine) ? NVME_MACHINE_PERIOD_US : NVME_TIMER_PERIOD_US;
    Ext->TimerPeriodUs = Period;

    NvmeUnlock(Ext, &LockHandle);

    /* PCI configuration space is not written at DIRQL */
    if (BusMasterOff)
    {
        NvmeSetBusMaster(Ext, FALSE);
        NvmeLock(Ext, &LockHandle);
        Ext->BusMasterOff = TRUE;
        NvmeUnlock(Ext, &LockHandle);
    }

    StorPortNotification(RequestTimerCall, Ext, NvmeHwTimer, Period);
}

/* MINIPORT ENTRY POINTS ******************************************************/

static
BOOLEAN
NTAPI
NvmeHwInterrupt(
    _In_ PVOID DeviceExtension)
{
    PNVME_EXTENSION Ext = (PNVME_EXTENSION)DeviceExtension;
    BOOLEAN Claimed;

    /* The line may be shared, and is masked while the driver polls */
    if (!Ext->Ready)
        return FALSE;

    Claimed = NvmeProcessCompletions(Ext, &Ext->IoQueue);
    Claimed |= NvmeProcessCompletions(Ext, &Ext->AdminQueue);
    if (Claimed)
        Ext->Interrupts++;

    return Claimed;
}

static
BOOLEAN
NTAPI
NvmeHwStartIo(
    _In_ PVOID DeviceExtension,
    _In_ PSCSI_REQUEST_BLOCK Srb)
{
    PNVME_EXTENSION Ext = (PNVME_EXTENSION)DeviceExtension;
    STOR_LOCK_HANDLE LockHandle;

    NvmeLock(Ext, &LockHandle);

    switch (Ext->State)
    {
        case NvmeStateLive:
            NvmeDispatch(Ext, Srb);
            break;

        case NvmeStateFailed:
            if (Srb->Function == SRB_FUNCTION_EXECUTE_SCSI)
            {
                NvmeScsiSetSense(Srb, 0x04 /* HARDWARE ERROR */, 0x44, 0x00);
                NvmeCompleteSrb(Ext, Srb, 0xFF);
            }
            else
            {
                NvmeCompleteSrb(Ext, Srb, SRB_STATUS_ERROR);
            }
            break;

        case NvmeStateShutdown:
            /* Already shut down: nothing to write back */
            if (Srb->Function == SRB_FUNCTION_SHUTDOWN)
            {
                NvmeCompleteSrb(Ext, Srb, SRB_STATUS_SUCCESS);
                break;
            }

            /* Anything else wakes the controller up; it waits until then */
            NvmeLog("request after shutdown, re-enabling the controller\n");
            NvmeAppendDeferred(Ext, Srb);
            NvmeStartMachine(Ext, FALSE);
            break;

        default:
            /* Resetting, shutting down, or stopped: dispatched when the controller is live */
            NvmeAppendDeferred(Ext, Srb);
            break;
    }

    NvmeUnlock(Ext, &LockHandle);
    return TRUE;
}

static
BOOLEAN
NTAPI
NvmeHwResetBus(
    _In_ PVOID DeviceExtension,
    _In_ ULONG PathId)
{
    PNVME_EXTENSION Ext = (PNVME_EXTENSION)DeviceExtension;
    STOR_LOCK_HANDLE LockHandle;
    BOOLEAN Result;

    UNREFERENCED_PARAMETER(PathId);

    /* The state machine stops the controller, hands back what it held and brings it up */
    NvmeLock(Ext, &LockHandle);
    if (Ext->State == NvmeStateFailed)
        Ext->Attempts = 0;
    NvmeStartMachine(Ext, FALSE);
    Result = (Ext->State == NvmeStateMachine);
    NvmeUnlock(Ext, &LockHandle);

    return Result;
}

static
SCSI_ADAPTER_CONTROL_STATUS
NTAPI
NvmeHwAdapterControl(
    _In_ PVOID DeviceExtension,
    _In_ SCSI_ADAPTER_CONTROL_TYPE ControlType,
    _In_ PVOID Parameters)
{
    PNVME_EXTENSION Ext = (PNVME_EXTENSION)DeviceExtension;
    STOR_LOCK_HANDLE LockHandle;
    PSCSI_REQUEST_BLOCK Srb;
    ULONG Waited;
    BOOLEAN Stopped;

    switch (ControlType)
    {
        case ScsiQuerySupportedControlTypes:
        {
            PNVME_CONTROL_TYPE_LIST List = (PNVME_CONTROL_TYPE_LIST)Parameters;

            if (List->MaxControlType > ScsiQuerySupportedControlTypes)
                List->SupportedTypeList[ScsiQuerySupportedControlTypes] = TRUE;
            if (List->MaxControlType > ScsiStopAdapter)
                List->SupportedTypeList[ScsiStopAdapter] = TRUE;
            if (List->MaxControlType > ScsiRestartAdapter)
                List->SupportedTypeList[ScsiRestartAdapter] = TRUE;
            return ScsiAdapterControlSuccess;
        }

        case ScsiStopAdapter:
            /* No more ticks, no more interrupts, controller disabled */
            NvmeLock(Ext, &LockHandle);
            Ext->State = NvmeStateStopped;
            Ext->Ready = FALSE;
            NvmeWrite32(Ext, NVME_REG_INTMS, 1);
            NvmeWrite32(Ext, NVME_REG_CC, NvmeRead32(Ext, NVME_REG_CC) & ~(NVME_CC_EN | NVME_CC_SHN_MASK));
            NvmeUnlock(Ext, &LockHandle);

            StorPortNotification(RequestTimerCall, Ext, NvmeHwTimer, 0);

            /* A short, bounded wait outside the lock; past it bus mastering goes off */
            Stopped = FALSE;
            for (Waited = 0; Waited < NVME_STOP_WAIT_US; Waited += 100)
            {
                ULONG Csts = NvmeRead32(Ext, NVME_REG_CSTS);
                if (Csts != MAXULONG && !(Csts & NVME_CSTS_RDY))
                {
                    Stopped = TRUE;
                    break;
                }
                StorPortStallExecution(100);
            }
            if (!Stopped && !Ext->BusMasterOff)
            {
                NvmeSetBusMaster(Ext, FALSE);
                Ext->BusMasterOff = TRUE;
            }

            /* Nothing can reach memory now: everything goes back to storport */
            NvmeLock(Ext, &LockHandle);
            NvmeReleaseOutstanding(Ext, SRB_STATUS_BUS_RESET);
            Srb = Ext->DeferredHead;
            Ext->DeferredHead = Ext->DeferredTail = NULL;
            NvmeCompleteChain(Ext, Srb, SRB_STATUS_BUS_RESET);
            Srb = Ext->ResetWaiters;
            Ext->ResetWaiters = NULL;
            NvmeCompleteChain(Ext, Srb, SRB_STATUS_ERROR);
            if (Ext->ShutdownSrb)
            {
                NvmeCompleteSrb(Ext, Ext->ShutdownSrb, SRB_STATUS_ERROR);
                Ext->ShutdownSrb = NULL;
            }
            NvmeUnlock(Ext, &LockHandle);
            return ScsiAdapterControlSuccess;

        case ScsiRestartAdapter:
            if (Ext->BusMasterOff)
            {
                NvmeSetBusMaster(Ext, TRUE);
                Ext->BusMasterOff = FALSE;
            }

            /* Requests wait until the machine has the controller up */
            NvmeLock(Ext, &LockHandle);
            Ext->State = NvmeStateFailed;
            Ext->Attempts = 0;
            NvmeStartMachine(Ext, FALSE);
            Ext->TimerPeriodUs = NVME_MACHINE_PERIOD_US;
            Ext->TimerRunning = TRUE;
            NvmeUnlock(Ext, &LockHandle);

            StorPortNotification(RequestTimerCall, Ext, NvmeHwTimer, NVME_MACHINE_PERIOD_US);
            return ScsiAdapterControlSuccess;

        default:
            return ScsiAdapterControlUnsuccessful;
    }
}

static
BOOLEAN
NTAPI
NvmeHwInitialize(
    _In_ PVOID DeviceExtension)
{
    PNVME_EXTENSION Ext = (PNVME_EXTENSION)DeviceExtension;

    /* FindAdapter brought the controller up; only open the interrupt and start the watchdog */
    Ext->Ready = TRUE;
    NvmeWrite32(Ext, NVME_REG_INTMC, 1);

    if (!Ext->TimerRunning)
    {
        Ext->TimerRunning = TRUE;
        Ext->TimerPeriodUs = NVME_TIMER_PERIOD_US;
        StorPortNotification(RequestTimerCall, Ext, NvmeHwTimer, NVME_TIMER_PERIOD_US);
    }

    return TRUE;
}

static
ULONG
NTAPI
NvmeHwFindAdapter(
    _In_ PVOID DeviceExtension,
    _In_ PVOID HwContext,
    _In_ PVOID BusInformation,
    _In_ PCHAR ArgumentString,
    _Inout_ PPORT_CONFIGURATION_INFORMATION ConfigInfo,
    _Out_ PBOOLEAN Again)
{
    PNVME_EXTENSION Ext = (PNVME_EXTENSION)DeviceExtension;
    PACCESS_RANGE Range = NULL;
    ULONG i, Offset, Size;
    ULONG IoDepth;
    STOR_PHYSICAL_ADDRESS Pa;
    ULONG Length;

    UNREFERENCED_PARAMETER(HwContext);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);

    *Again = FALSE;

    /* The register file is the first memory BAR */
    for (i = 0; i < ConfigInfo->NumberOfAccessRanges; i++)
    {
        PACCESS_RANGE Candidate = &(*ConfigInfo->AccessRanges)[i];

        if (Candidate->RangeInMemory && Candidate->RangeLength >= 0x2000)
        {
            Range = Candidate;
            break;
        }
    }

    if (Range == NULL)
    {
        NvmeLog("no register BAR\n");
        return SP_RETURN_NOT_FOUND;
    }

    Ext->Registers = StorPortGetDeviceBase(Ext,
                                           ConfigInfo->AdapterInterfaceType,
                                           ConfigInfo->SystemIoBusNumber,
                                           Range->RangeStart,
                                           Range->RangeLength,
                                           FALSE);
    if (Ext->Registers == NULL)
    {
        NvmeLog("cannot map the registers\n");
        return SP_RETURN_ERROR;
    }
    Ext->RegistersLength = Range->RangeLength;

    Ext->Cap = NvmeRead64(Ext, NVME_REG_CAP);
    Ext->Version = NvmeRead32(Ext, NVME_REG_VS);
    if (Ext->Cap == ~0ULL)
    {
        NvmeLog("controller not responding\n");
        return SP_RETURN_NOT_FOUND;
    }

    if (!(NVME_CAP_CSS(Ext->Cap) & NVME_CAP_CSS_NVM) || NVME_CAP_MPSMIN(Ext->Cap) != 0)
    {
        NvmeLog("unsupported controller (CAP 0x%I64x)\n", Ext->Cap);
        return SP_RETURN_NOT_FOUND;
    }

    Ext->DoorbellStride = 4UL << NVME_CAP_DSTRD(Ext->Cap);
    if (NVME_REG_DOORBELL + 4 * Ext->DoorbellStride > Ext->RegistersLength)
    {
        NvmeLog("register BAR too small\n");
        return SP_RETURN_NOT_FOUND;
    }

    Ext->SystemIoBusNumber = ConfigInfo->SystemIoBusNumber;
    Ext->SlotNumber = ConfigInfo->SlotNumber;

    Ext->ReadyTimeoutMs = NVME_CAP_TO(Ext->Cap) * 500;
    if (Ext->ReadyTimeoutMs < 2000)
        Ext->ReadyTimeoutMs = 2000;

    IoDepth = NVME_CAP_MQES(Ext->Cap) + 1;
    if (IoDepth > NVME_IO_QUEUE_DEPTH_MAX)
        IoDepth = NVME_IO_QUEUE_DEPTH_MAX;
    if (IoDepth < 2)
        return SP_RETURN_NOT_FOUND;
    Ext->IoQueueDepth = (USHORT)IoDepth;

    /* Port configuration, needed before the uncached extension (it creates the DMA adapter) */
    ConfigInfo->NumberOfBuses = 1;
    ConfigInfo->MaximumNumberOfTargets = 1;
    ConfigInfo->MaximumNumberOfLogicalUnits = NVME_MAX_NAMESPACES;
    ConfigInfo->ScatterGather = TRUE;
    ConfigInfo->Master = TRUE;
    ConfigInfo->CachesData = TRUE;
    ConfigInfo->NeedPhysicalAddresses = TRUE;
    ConfigInfo->TaggedQueuing = TRUE;
    ConfigInfo->MultipleRequestPerLu = TRUE;
    ConfigInfo->AutoRequestSense = TRUE;
    ConfigInfo->Dma32BitAddresses = TRUE;
    if (ConfigInfo->Dma64BitAddresses & SCSI_DMA64_SYSTEM_SUPPORTED)
        ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_SUPPORTED;
    ConfigInfo->AlignmentMask = 3;
    ConfigInfo->MaximumTransferLength = NVME_MAX_TRANSFER_BYTES;
    ConfigInfo->NumberOfPhysicalBreaks = NVME_MAX_TRANSFER_BYTES / NVME_PAGE_SIZE + 1;
    ConfigInfo->MapBuffers = STOR_MAP_NON_READ_WRITE_BUFFERS;
    ConfigInfo->SynchronizationModel = StorSynchronizeFullDuplex;
    ConfigInfo->ResetTargetSupported = FALSE;
    ConfigInfo->WmiDataProvider = FALSE;
    ConfigInfo->MaxNumberOfIO = IoDepth - 1;
    ConfigInfo->MaxIOsPerLun = IoDepth - 1;
    ConfigInfo->InitialLunQueueDepth = IoDepth - 1;

    /* Queue memory, page aligned pieces of one physically contiguous allocation */
    Offset = 0;
#define NVME_CARVE(var, bytes) do { var = Offset; Offset += ROUND_TO_PAGES(bytes); } while (0)
    {
        ULONG AsqOffset, AcqOffset, IosqOffset, IocqOffset, IdentifyOffset, SlotDmaOffset;

        NVME_CARVE(AsqOffset, NVME_ADMIN_QUEUE_DEPTH * sizeof(NVME_COMMAND));
        NVME_CARVE(AcqOffset, NVME_ADMIN_QUEUE_DEPTH * sizeof(NVME_COMPLETION));
        NVME_CARVE(IosqOffset, IoDepth * sizeof(NVME_COMMAND));
        NVME_CARVE(IocqOffset, IoDepth * sizeof(NVME_COMPLETION));
        NVME_CARVE(IdentifyOffset, NVME_PAGE_SIZE);
        NVME_CARVE(SlotDmaOffset, (IoDepth - 1) * NVME_SLOT_DMA_BYTES);
        Size = Offset;

        Ext->Uncached = StorPortGetUncachedExtension(Ext, ConfigInfo, Size + NVME_PAGE_SIZE);
        if (Ext->Uncached == NULL)
        {
            NvmeLog("cannot allocate %lu bytes of queue memory\n", Size);
            return SP_RETURN_ERROR;
        }

        /* The queues must be page aligned; the allocation has a spare page for that */
        Pa = StorPortGetPhysicalAddress(Ext, NULL, Ext->Uncached, &Length);
        if (Pa.QuadPart & NVME_PAGE_MASK)
        {
            ULONG Skip = NVME_PAGE_SIZE - (ULONG)(Pa.QuadPart & NVME_PAGE_MASK);
            Ext->Uncached += Skip;
            Pa.QuadPart += Skip;
        }
        Ext->UncachedPa = Pa;
        Ext->UncachedSize = Size;
        RtlZeroMemory(Ext->Uncached, Size);

        Ext->AdminQueue.Qid = 0;
        Ext->AdminQueue.Depth = NVME_ADMIN_QUEUE_DEPTH;
        Ext->AdminQueue.SlotCount = NVME_ADMIN_QUEUE_DEPTH - 1;
        Ext->AdminQueue.Sq = (PNVME_COMMAND)(Ext->Uncached + AsqOffset);
        Ext->AdminQueue.SqPa.QuadPart = Pa.QuadPart + AsqOffset;
        Ext->AdminQueue.Cq = (PNVME_COMPLETION)(Ext->Uncached + AcqOffset);
        Ext->AdminQueue.CqPa.QuadPart = Pa.QuadPart + AcqOffset;
        Ext->AdminQueue.Slots = Ext->AdminSlots;

        Ext->IoQueue.Qid = NVME_IO_QUEUE_ID;
        Ext->IoQueue.Depth = (USHORT)IoDepth;
        Ext->IoQueue.SlotCount = (USHORT)(IoDepth - 1);
        Ext->IoQueue.Sq = (PNVME_COMMAND)(Ext->Uncached + IosqOffset);
        Ext->IoQueue.SqPa.QuadPart = Pa.QuadPart + IosqOffset;
        Ext->IoQueue.Cq = (PNVME_COMPLETION)(Ext->Uncached + IocqOffset);
        Ext->IoQueue.CqPa.QuadPart = Pa.QuadPart + IocqOffset;
        Ext->IoQueue.Slots = Ext->IoSlots;
        Ext->IoQueue.SlotDma = Ext->Uncached + SlotDmaOffset;
        Ext->IoQueue.SlotDmaPa.QuadPart = Pa.QuadPart + SlotDmaOffset;

        Ext->IdentifyBuffer = Ext->Uncached + IdentifyOffset;
        Ext->IdentifyPa.QuadPart = Pa.QuadPart + IdentifyOffset;
    }
#undef NVME_CARVE

    Ext->AdminQueue.SqDoorbell = (PULONG)(Ext->Registers + NVME_REG_DOORBELL + 0 * Ext->DoorbellStride);
    Ext->AdminQueue.CqDoorbell = (PULONG)(Ext->Registers + NVME_REG_DOORBELL + 1 * Ext->DoorbellStride);
    Ext->IoQueue.SqDoorbell = (PULONG)(Ext->Registers + NVME_REG_DOORBELL + 2 * NVME_IO_QUEUE_ID * Ext->DoorbellStride);
    Ext->IoQueue.CqDoorbell = (PULONG)(Ext->Registers + NVME_REG_DOORBELL + (2 * NVME_IO_QUEUE_ID + 1) * Ext->DoorbellStride);

    /* Polled bring-up now: no interrupt is connected yet */
    if (!NvmeBringUpSync(Ext))
    {
        NvmeLog("controller initialization failed\n");
        NvmeWrite32(Ext, NVME_REG_CC, NvmeRead32(Ext, NVME_REG_CC) & ~NVME_CC_EN);
        return SP_RETURN_ERROR;
    }

    ConfigInfo->MaximumTransferLength = Ext->MaxTransferBytes;
    ConfigInfo->NumberOfPhysicalBreaks = Ext->MaxTransferBytes / NVME_PAGE_SIZE + 1;

    NvmeLog("%.40s FW %.8s SN %.20s: NVMe %lu.%lu, %lu namespace(s), I/O queue depth %lu, "
            "max transfer %lu KB, VWC %u (enabled %u), ONCS 0x%x, MDTS %u, CAP 0x%I64x\n",
            Ext->Mn, Ext->Fr, Ext->Sn,
            Ext->Version >> 16, (Ext->Version >> 8) & 0xFF,
            Ext->NamespaceCount, IoDepth, Ext->MaxTransferBytes / 1024,
            Ext->Vwc & NVME_VWC_PRESENT, Ext->WriteCacheEnabled, Ext->Oncs, Ext->Mdts, Ext->Cap);

    return SP_RETURN_FOUND;
}

ULONG
NTAPI
DriverEntry(
    _In_ PVOID DriverObject,
    _In_ PVOID RegistryPath)
{
    HW_INITIALIZATION_DATA InitData;

    RtlZeroMemory(&InitData, sizeof(InitData));

    InitData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);
    InitData.AdapterInterfaceType = PCIBus;

    InitData.HwInitialize = NvmeHwInitialize;
    InitData.HwStartIo = NvmeHwStartIo;
    InitData.HwInterrupt = NvmeHwInterrupt;
    InitData.HwFindAdapter = NvmeHwFindAdapter;
    InitData.HwResetBus = NvmeHwResetBus;
    InitData.HwAdapterControl = NvmeHwAdapterControl;

    InitData.DeviceExtensionSize = sizeof(NVME_EXTENSION);
    InitData.SpecificLuExtensionSize = 0;
    InitData.SrbExtensionSize = sizeof(NVME_SRB_EXTENSION);
    InitData.NumberOfAccessRanges = 6;

    InitData.MapBuffers = STOR_MAP_NON_READ_WRITE_BUFFERS;
    InitData.NeedPhysicalAddresses = TRUE;
    InitData.TaggedQueuing = TRUE;
    InitData.AutoRequestSense = TRUE;
    InitData.MultipleRequestPerLu = TRUE;

    return StorPortInitialize(DriverObject, RegistryPath, &InitData, NULL);
}
