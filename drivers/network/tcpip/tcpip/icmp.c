/*
 * PROJECT:     ReactOS TCP/IP protocol driver
 * LICENCE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     ICMP functions implementation
 * COPYRIGHT:   2019 Victor Perevertkin (victor.perevertkin@reactos.org)
 */

#include "precomp.h"
#include <checksum.h>

typedef struct _ICMP_PACKET_CONTEXT
{
    TDI_REQUEST TdiRequest;
    KDPC TimeoutDpc;
    KEVENT InitializationFinishedEvent;
    KEVENT DatagramProcessedEvent;
    FAST_MUTEX ReplyLock;           /* One reply at a time updates the reply buffer and the counters */
    LARGE_INTEGER TimerResolution;
    INT64 StartTicks;
    PIRP Irp;
    PUCHAR CurrentReply;
    UINT32 RemainingSize;
    LONG nReplies;
    PIO_WORKITEM FinishWorker;
    KTIMER TimeoutTimer;
    UINT16 Identifier;
    UINT16 Seq;
    BOOLEAN Wow64;
    BOOLEAN CompleteOnFirstReply;
} ICMP_PACKET_CONTEXT, *PICMP_PACKET_CONTEXT;

/*
 * The reply is written straight into the caller's buffer, so a 32-bit
 * process under WoW64 must get a 28-byte reply (ICMP_ECHO_REPLY_GUEST): its Data and OptionsData
 * are 32-bit pointers and the options start 4 bytes earlier.
 * Address, Status, RoundTripTime, DataSize and Reserved are at the same
 * offsets in both layouts.
 */
#if defined(_WIN64) && defined(BUILD_WOW64_ENABLED)
#define ICMP_SUPPORT_WOW64

/* ICMP_ECHO_REPLY32 of the SDK headers is not 32 bits wide with GCC (POINTER_32 is empty there). */
typedef struct _ICMP_ECHO_REPLY_GUEST
{
    ULONG Address;
    ULONG Status;
    ULONG RoundTripTime;
    USHORT DataSize;
    USHORT Reserved;
    ULONG Data;
    struct
    {
        UCHAR Ttl;
        UCHAR Tos;
        UCHAR Flags;
        UCHAR OptionsSize;
        ULONG OptionsData;
    } Options;
} ICMP_ECHO_REPLY_GUEST, *PICMP_ECHO_REPLY_GUEST;

C_ASSERT(sizeof(ICMP_ECHO_REPLY_GUEST) == 28);
#endif

static
UINT32
IcmpReplySize(
    _In_ BOOLEAN Wow64)
{
#ifdef ICMP_SUPPORT_WOW64
    if (Wow64)
        return sizeof(ICMP_ECHO_REPLY_GUEST);
#endif
    UNREFERENCED_PARAMETER(Wow64);
    return sizeof(ICMP_ECHO_REPLY);
}

static
VOID
IcmpSetReplyData(
    _In_ BOOLEAN Wow64,
    _In_ PICMP_ECHO_REPLY Reply,
    _In_ PUCHAR UserData,
    _In_ UINT16 DataSize)
{
#ifdef ICMP_SUPPORT_WOW64
    if (Wow64)
    {
        ((PICMP_ECHO_REPLY_GUEST)Reply)->Data = (ULONG)(ULONG_PTR)UserData;
        ((PICMP_ECHO_REPLY_GUEST)Reply)->DataSize = DataSize;
        return;
    }
#endif
    UNREFERENCED_PARAMETER(Wow64);
    Reply->Data = UserData;
    Reply->DataSize = DataSize;
}

static
VOID
IcmpSetReplyOptions(
    _In_ BOOLEAN Wow64,
    _In_ PICMP_ECHO_REPLY Reply,
    _In_ PIPv4_HEADER IpHeader,
    _In_ PUCHAR UserOptions,
    _In_ UINT8 OptionsSize)
{
#ifdef ICMP_SUPPORT_WOW64
    if (Wow64)
    {
        PICMP_ECHO_REPLY_GUEST Reply32 = (PICMP_ECHO_REPLY_GUEST)Reply;

        Reply32->Options.Ttl = IpHeader->Ttl;
        Reply32->Options.Tos = IpHeader->Tos;
        Reply32->Options.Flags = IpHeader->FlagsFragOfs >> 13;
        Reply32->Options.OptionsSize = OptionsSize;
        Reply32->Options.OptionsData = (ULONG)(ULONG_PTR)UserOptions;
        return;
    }
#endif
    UNREFERENCED_PARAMETER(Wow64);
    Reply->Options.Ttl = IpHeader->Ttl;
    Reply->Options.Tos = IpHeader->Tos;
    Reply->Options.Flags = IpHeader->FlagsFragOfs >> 13;
    Reply->Options.OptionsSize = OptionsSize;
    Reply->Options.OptionsData = UserOptions;
}

static volatile INT16 IcmpSequence = 0;

static
UINT32
GetReplyStatus(PICMP_HEADER IcmpHeader)
{
    switch (IcmpHeader->Type)
    {
        case ICMP_TYPE_ECHO_REPLY:
            return IP_SUCCESS;
        case ICMP_TYPE_DEST_UNREACH:
            switch (IcmpHeader->Code)
            {
                case ICMP_CODE_DU_NET_UNREACH:
                    return IP_DEST_NET_UNREACHABLE;
                case ICMP_CODE_DU_HOST_UNREACH:
                    return IP_DEST_HOST_UNREACHABLE;
                case ICMP_CODE_DU_PROTOCOL_UNREACH:
                    return IP_DEST_PROT_UNREACHABLE;
                case ICMP_CODE_DU_PORT_UNREACH:
                    return IP_DEST_PORT_UNREACHABLE;
                case ICMP_CODE_DU_FRAG_DF_SET:
                    return IP_DEST_NET_UNREACHABLE;
                case ICMP_CODE_DU_SOURCE_ROUTE_FAILED:
                    return IP_BAD_ROUTE;
                default:
                    return IP_DEST_NET_UNREACHABLE;
            }
        case ICMP_TYPE_SOURCE_QUENCH:
            return IP_SOURCE_QUENCH;
        case ICMP_TYPE_TIME_EXCEEDED:
            if (IcmpHeader->Code == ICMP_CODE_TE_REASSEMBLY)
                return IP_TTL_EXPIRED_REASSEM;
            else
                return IP_TTL_EXPIRED_TRANSIT;
        case ICMP_TYPE_PARAMETER:
            return IP_PARAM_PROBLEM;
        default:
            return IP_REQ_TIMED_OUT;
    }
}

/*
 * Every ICMP packet the host receives is indicated to every open ICMP
 * address file, so take only the messages that answer our own request:
 * an echo reply with our identifier and sequence number, or an error
 * message that quotes our echo request (RFC 792: the IP header and the
 * first 64 bits of the datagram that caused the error).
 */
static
BOOLEAN
IsReplyToRequest(
    _In_ PICMP_PACKET_CONTEXT Context,
    _In_ PICMP_HEADER IcmpHeader,
    _In_reads_bytes_(DataSize) PUCHAR Data,
    _In_ INT32 DataSize)
{
    PIPv4_HEADER OriginalIpHeader;
    PICMP_HEADER OriginalIcmpHeader;
    UINT32 OriginalIpHeaderSize;

    switch (IcmpHeader->Type)
    {
        case ICMP_TYPE_ECHO_REPLY:
            return IcmpHeader->Identifier == Context->Identifier &&
                   IcmpHeader->Seq == Context->Seq;

        case ICMP_TYPE_DEST_UNREACH:
        case ICMP_TYPE_SOURCE_QUENCH:
        case ICMP_TYPE_TIME_EXCEEDED:
        case ICMP_TYPE_PARAMETER:
            if (DataSize < (INT32)sizeof(IPv4_HEADER))
                return FALSE;

            OriginalIpHeader = (PIPv4_HEADER)Data;
            OriginalIpHeaderSize = (OriginalIpHeader->VerIHL & 0x0F) * 4;
            if (OriginalIpHeaderSize < sizeof(IPv4_HEADER) ||
                (UINT32)DataSize < OriginalIpHeaderSize + sizeof(ICMP_HEADER) ||
                OriginalIpHeader->Protocol != IPPROTO_ICMP)
            {
                return FALSE;
            }

            OriginalIcmpHeader = (PICMP_HEADER)(Data + OriginalIpHeaderSize);
            return OriginalIcmpHeader->Type == ICMP_TYPE_ECHO_REQUEST &&
                   OriginalIcmpHeader->Identifier == Context->Identifier &&
                   OriginalIcmpHeader->Seq == Context->Seq;

        default:
            return FALSE;
    }
}

static
VOID
ClearReceiveHandler(
    _In_ PADDRESS_FILE AddrFile)
{
    LockObject(AddrFile);
    AddrFile->RegisteredReceiveDatagramHandler = FALSE;
    UnlockObject(AddrFile);
}

/*
 * After ClearReceiveHandler no new indication starts, but one that began earlier may still run
 * with the request's context: the context is freed only when none is left (the address file counts
 * them from the moment it reads the handler)
 */
static
VOID
WaitForReceiveHandlers(
    _In_ PADDRESS_FILE AddrFile)
{
    LARGE_INTEGER Delay;

    Delay.QuadPart = -10000;
    while (AddrFile->ReceiveHandlersActive != 0)
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
}

IO_WORKITEM_ROUTINE EndRequestHandler;

VOID
NTAPI
EndRequestHandler(
    PDEVICE_OBJECT DeviceObject,
    PVOID _Context)
{
    PICMP_PACKET_CONTEXT Context = (PICMP_PACKET_CONTEXT)_Context;
    PIO_STACK_LOCATION CurrentStack;
    PIRP Irp;
    UINT32 nReplies;
    KIRQL OldIrql;

    ClearReceiveHandler((PADDRESS_FILE)Context->TdiRequest.Handle.AddressHandle);

    /* An indication that is still waiting for the request to be set up must not wait any longer */
    KeSetEvent(&Context->InitializationFinishedEvent, IO_NO_INCREMENT, FALSE);
    WaitForReceiveHandlers((PADDRESS_FILE)Context->TdiRequest.Handle.AddressHandle);

    KeWaitForSingleObject(&Context->DatagramProcessedEvent, Executive, KernelMode, FALSE, NULL);

    TI_DbgPrint(DEBUG_ICMP, ("Finishing request Context: %p\n", Context));

    Irp = Context->Irp;
    CurrentStack = IoGetCurrentIrpStackLocation(Irp);

    if (Context->nReplies > 0)
    {
        ((PICMP_ECHO_REPLY)Irp->AssociatedIrp.SystemBuffer)->Reserved = Context->nReplies;
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = CurrentStack->Parameters.DeviceIoControl.OutputBufferLength;
    }
    else
    {
        PICMP_ECHO_REPLY ReplyBuffer = (PICMP_ECHO_REPLY)Irp->AssociatedIrp.SystemBuffer;
        UINT32 ReplySize = IcmpReplySize(Context->Wow64);

        RtlZeroMemory(ReplyBuffer, ReplySize);
        ReplyBuffer->Status = IP_REQ_TIMED_OUT;

        Irp->IoStatus.Status = STATUS_TIMEOUT;
        Irp->IoStatus.Information = ReplySize;
    }

    // for debugging
    nReplies = ((PICMP_ECHO_REPLY)Irp->AssociatedIrp.SystemBuffer)->Reserved;

    // taken from dispatch.c:IRPFinish
    IoAcquireCancelSpinLock(&OldIrql);
    IoSetCancelRoutine(Irp, NULL);
    IoReleaseCancelSpinLock(OldIrql);
    IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);

    {
        NTSTATUS _Status = FileCloseAddress(&Context->TdiRequest);
        ASSERT(NT_SUCCESS(_Status));
    }

    IoFreeWorkItem(Context->FinishWorker);
    ExFreePoolWithTag(Context, OUT_DATA_TAG);

    TI_DbgPrint(DEBUG_ICMP, ("Leaving, nReplies: %u\n", nReplies));
}

NTSTATUS
NTAPI
ReceiveDatagram(
    _In_opt_ PVOID TdiEventContext,
    _In_ LONG SourceAddressLength,
    _In_reads_bytes_(SourceAddressLength) PVOID SourceAddress,
    _In_ LONG OptionsLength,
    _In_reads_bytes_opt_(OptionsLength) PVOID Options,
    _In_ ULONG ReceiveDatagramFlags,
    _In_ ULONG BytesIndicated,
    _In_ ULONG BytesAvailable,
    _Out_ ULONG *OutBytesTaken,
    _In_ PVOID Tsdu,
    _Out_opt_ PIRP *IoRequestPacket)
{
    PICMP_PACKET_CONTEXT Context = TdiEventContext;
    PIPv4_HEADER IpHeader = Tsdu;
    UINT16 IpHeaderSize = sizeof(IPv4_HEADER) + OptionsLength;
    PICMP_HEADER IcmpHeader = (PICMP_HEADER)((PUCHAR)Tsdu + IpHeaderSize);

    PVOID DataBuffer = (PUCHAR)Tsdu + IpHeaderSize + sizeof(ICMP_HEADER);
    INT32 DataSize = min(BytesAvailable, UINT16_MAX) - IpHeaderSize - sizeof(ICMP_HEADER);

    INT64 CurrentTime;
    UINT32 RoundTripTime;
    UINT32 ReplySize;
    PICMP_ECHO_REPLY CurrentReply;
    PUCHAR CurrentUserBuffer;

    // ignore anything that does not answer this request, echo requests included
    if (DataSize < 0 || !IsReplyToRequest(Context, IcmpHeader, DataBuffer, DataSize))
    {
        return STATUS_SUCCESS;
    }

    KeWaitForSingleObject(&Context->InitializationFinishedEvent, Executive, KernelMode, FALSE, NULL);
    ExAcquireFastMutex(&Context->ReplyLock);
    KeClearEvent(&Context->DatagramProcessedEvent);

    ASSERT(SourceAddressLength == sizeof(IPAddr));
    TI_DbgPrint(DEBUG_ICMP, ("Received datagram Context: 0x%p\n", TdiEventContext));

    CurrentTime = KeQueryPerformanceCounter(NULL).QuadPart;
    RoundTripTime = (CurrentTime - Context->StartTicks) * 1000 / Context->TimerResolution.QuadPart;
    CurrentReply = (PICMP_ECHO_REPLY)Context->CurrentReply;

    ReplySize = IcmpReplySize(Context->Wow64);

    if (Context->RemainingSize < ReplySize)
    {
        /* No room for another reply: the request is about to finish. */
        KeSetEvent(&Context->DatagramProcessedEvent, IO_NO_INCREMENT, FALSE);
        ExReleaseFastMutex(&Context->ReplyLock);
        return STATUS_SUCCESS;
    }

    TI_DbgPrint(DEBUG_ICMP, ("RemainingSize: %u, RoundTripTime: %u\n", Context->RemainingSize, RoundTripTime));

    memcpy(&CurrentReply->Address, SourceAddress, sizeof(CurrentReply->Address));
    CurrentReply->Status = GetReplyStatus(IcmpHeader);
    CurrentReply->RoundTripTime = RoundTripTime;
    CurrentReply->Reserved = 0;

    Context->RemainingSize -= ReplySize;
    Context->CurrentReply += ReplySize;

    CurrentUserBuffer = (PUCHAR)Context->Irp->UserBuffer + (Context->CurrentReply - (PUCHAR)Context->Irp->AssociatedIrp.SystemBuffer);

    /* Data and OptionsData are never NULL in a reply that was received, as on Windows:
     * a caller (.NET's Marshal.Copy) rejects a NULL pointer even for zero bytes.
     * They point just past the reply until there is something to point at. */
    IcmpSetReplyData(Context->Wow64, CurrentReply, CurrentUserBuffer, 0);
    IcmpSetReplyOptions(Context->Wow64, CurrentReply, IpHeader, CurrentUserBuffer, 0);

    /* Only an echo reply returns data; an error message quotes the request header, which Windows does not return. */
    if (IcmpHeader->Type == ICMP_TYPE_ECHO_REPLY && DataSize > 0 && Context->RemainingSize > 0)
    {
        UINT32 _DataSize = min(Context->RemainingSize, DataSize);

        memcpy(Context->CurrentReply + Context->RemainingSize - _DataSize, DataBuffer, _DataSize);
        IcmpSetReplyData(Context->Wow64, CurrentReply, CurrentUserBuffer + Context->RemainingSize - _DataSize, (UINT16)_DataSize);

        Context->RemainingSize -= _DataSize;
    }
    else
    {
        TI_DbgPrint(DEBUG_ICMP, ("RemainingSize: %u, DataSize: %d\n", Context->RemainingSize, DataSize));
    }

    if (OptionsLength > 0 && Context->RemainingSize > 0)
    {
        UINT32 _OptSize = min(Context->RemainingSize, OptionsLength);

        memcpy(Context->CurrentReply + Context->RemainingSize - _OptSize, Options, _OptSize);
        IcmpSetReplyOptions(Context->Wow64, CurrentReply, IpHeader,
                            CurrentUserBuffer + Context->RemainingSize - _OptSize, (UINT8)_OptSize);

        Context->RemainingSize -= _OptSize;
    }
    else
    {
        TI_DbgPrint(DEBUG_ICMP, ("RemainingSize: %u, OptSize: %d\n", Context->RemainingSize, OptionsLength));
    }

    Context->nReplies++;

    /* An echo to a single host is answered once: finish at the first reply, as Windows does,
     * instead of holding the caller until the timeout (Ping.Send would take its whole timeout). */
    if (Context->RemainingSize < ReplySize || Context->CompleteOnFirstReply)
    {
        TI_DbgPrint(DEBUG_ICMP, ("The space is over: %u\n", Context->RemainingSize));

        // if the timer was inserted, that means DPC has not been queued yet
        if (KeCancelTimer(&Context->TimeoutTimer))
        {
            PADDRESS_FILE AddrFile = (PADDRESS_FILE)Context->TdiRequest.Handle.AddressHandle;
            ClearReceiveHandler(AddrFile);

            IoQueueWorkItem(Context->FinishWorker, &EndRequestHandler, DelayedWorkQueue, Context);
        }
    }

    KeSetEvent(&Context->DatagramProcessedEvent, IO_NO_INCREMENT, FALSE);
    ExReleaseFastMutex(&Context->ReplyLock);
    return STATUS_SUCCESS;
}

KDEFERRED_ROUTINE TimeoutHandler;

VOID
NTAPI
TimeoutHandler(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID _Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    PICMP_PACKET_CONTEXT Context = (PICMP_PACKET_CONTEXT)_Context;

    IoQueueWorkItem(Context->FinishWorker, &EndRequestHandler, DelayedWorkQueue, _Context);
}

NTSTATUS
DispEchoRequest(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp)
{
    PICMP_ECHO_REQUEST Request = Irp->AssociatedIrp.SystemBuffer;
    UINT32 OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    UINT32 InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS Status;
    TDI_CONNECTION_INFORMATION ConnectionInfo;
    TA_IP_ADDRESS RemoteAddressTa, LocalAddressTa;
    PADDRESS_FILE AddrFile;
    ULONG DataUsed;
    PUCHAR Buffer;
    UINT16 RequestSize;
    PICMP_PACKET_CONTEXT SendContext;
    LARGE_INTEGER RequestTimeout;
    UINT8 SavedTtl;
    BOOLEAN Wow64;

    TI_DbgPrint(DEBUG_ICMP, ("About to send datagram, OutputBufferLength: %u, SystemBuffer: %p\n", OutputBufferLength, Irp->AssociatedIrp.SystemBuffer));

#ifdef ICMP_SUPPORT_WOW64
    Wow64 = IoIs32bitProcess(Irp);
#else
    Wow64 = FALSE;
#endif

    // check buffers
    if (OutputBufferLength < IcmpReplySize(Wow64) || InputBufferLength < sizeof(ICMP_ECHO_REQUEST))
    {
        return STATUS_INVALID_PARAMETER;
    }

    // check request parameters
    if ((Request->DataSize > UINT16_MAX - sizeof(ICMP_HEADER) - sizeof(IPv4_HEADER)) ||
        ((UINT32)Request->DataOffset + Request->DataSize > InputBufferLength) ||
        ((UINT32)Request->OptionsOffset + Request->OptionsSize > InputBufferLength))
    {
        return STATUS_INVALID_PARAMETER;
    }

    SendContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(*SendContext), OUT_DATA_TAG);
    if (!SendContext)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SendContext->FinishWorker = IoAllocateWorkItem(DeviceObject);
    if (!SendContext->FinishWorker)
    {
        ExFreePoolWithTag(SendContext, OUT_DATA_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&SendContext->TdiRequest, sizeof(SendContext->TdiRequest));
    SendContext->TdiRequest.RequestContext = Irp;

    // setting up everything needed for sending the packet

    RtlZeroMemory(&RemoteAddressTa, sizeof(RemoteAddressTa));
    RtlZeroMemory(&LocalAddressTa, sizeof(LocalAddressTa));
    RtlZeroMemory(&ConnectionInfo, sizeof(ConnectionInfo));

    RemoteAddressTa.TAAddressCount = 1;
    RemoteAddressTa.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    RemoteAddressTa.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    RemoteAddressTa.Address[0].Address[0].in_addr = Request->Address;

    LocalAddressTa.TAAddressCount = 1;
    LocalAddressTa.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    LocalAddressTa.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    /* IcmpSendEcho2Ex: send from this local address (0 lets the stack choose). */
    LocalAddressTa.Address[0].Address[0].in_addr = Request->SourceAddress;

    Status = FileOpenAddress(&SendContext->TdiRequest, &LocalAddressTa, IPPROTO_ICMP, FALSE, NULL);

    if (!NT_SUCCESS(Status))
    {
        TI_DbgPrint(DEBUG_ICMP, ("Failed to open address file status: 0x%x\n", Status));

        IoFreeWorkItem(SendContext->FinishWorker);
        ExFreePoolWithTag(SendContext, OUT_DATA_TAG);

        return Status;
    }

    AddrFile = (PADDRESS_FILE)SendContext->TdiRequest.Handle.AddressHandle;

    // setting up the context

    KeQueryPerformanceCounter(&SendContext->TimerResolution);
    SendContext->Irp = Irp;
    SendContext->Wow64 = Wow64;
    /* Only a broadcast or multicast destination (or x.y.z.255) can have several answers worth waiting for. */
    SendContext->CompleteOnFirstReply = ((Request->Address >> 24) != 0xFF) &&
                                        ((Request->Address & 0xF0) != 0xE0);
    SendContext->CurrentReply = Irp->AssociatedIrp.SystemBuffer;
    SendContext->RemainingSize = OutputBufferLength;
    SendContext->nReplies = 0;
    KeInitializeEvent(&SendContext->InitializationFinishedEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&SendContext->DatagramProcessedEvent, NotificationEvent, TRUE);
    ExInitializeFastMutex(&SendContext->ReplyLock);

    KeInitializeDpc(&SendContext->TimeoutDpc, &TimeoutHandler, SendContext);
    KeInitializeTimerEx(&SendContext->TimeoutTimer, SynchronizationTimer);

    RequestTimeout.QuadPart = (-1LL) * 10 * 1000 * Request->Timeout;

    ConnectionInfo.RemoteAddress = &RemoteAddressTa;
    ConnectionInfo.RemoteAddressLength = sizeof(RemoteAddressTa);

    RequestSize = sizeof(ICMP_HEADER) + Request->DataSize;

    // making up the request packet
    Buffer = ExAllocatePoolWithTag(NonPagedPool, RequestSize, OUT_DATA_TAG);

    if (!Buffer)
    {
        NTSTATUS _Status = FileCloseAddress(&SendContext->TdiRequest);
        ASSERT(NT_SUCCESS(_Status));

        IoFreeWorkItem(SendContext->FinishWorker);
        ExFreePoolWithTag(SendContext, OUT_DATA_TAG);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ((PICMP_HEADER)Buffer)->Type = ICMP_TYPE_ECHO_REQUEST;
    ((PICMP_HEADER)Buffer)->Code = ICMP_TYPE_ECHO_REPLY;
    ((PICMP_HEADER)Buffer)->Checksum = 0;
    SendContext->Identifier = (UINT_PTR)PsGetCurrentProcessId() & UINT16_MAX;
    SendContext->Seq = InterlockedIncrement16(&IcmpSequence);
    ((PICMP_HEADER)Buffer)->Identifier = SendContext->Identifier;
    ((PICMP_HEADER)Buffer)->Seq = SendContext->Seq;
    memcpy(Buffer + sizeof(ICMP_HEADER), (PUCHAR)Request + Request->DataOffset, Request->DataSize);
    ((PICMP_HEADER)Buffer)->Checksum = IPv4Checksum(Buffer, RequestSize, 0);
    /* Without options (IcmpSendEcho with NULL RequestOptions) the TTL is the default, not 0. */
    SavedTtl = Request->HasOptions ? Request->Ttl : 128;

    RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, OutputBufferLength);

    LockObject(AddrFile);

    AddrFile->TTL = SavedTtl;
    AddrFile->ReceiveDatagramHandlerContext = SendContext;
    AddrFile->ReceiveDatagramHandler = ReceiveDatagram;
    AddrFile->RegisteredReceiveDatagramHandler = TRUE;

    UnlockObject(AddrFile);

    Status = AddrFile->Send(AddrFile, &ConnectionInfo, (PCHAR)Buffer, RequestSize, &DataUsed);

    // From this point we may receive a reply packet.
    // But we are not ready for it thus InitializationFinishedEvent is needed (see below)

    SendContext->StartTicks = KeQueryPerformanceCounter(NULL).QuadPart;

    ExFreePoolWithTag(Buffer, OUT_DATA_TAG);

    if (!NT_SUCCESS(Status))
    {
        NTSTATUS _Status;

        ClearReceiveHandler(AddrFile);
        /* A reply that arrived while the send failed is waiting for the request: let it go, then wait for it */
        KeSetEvent(&SendContext->InitializationFinishedEvent, IO_NO_INCREMENT, FALSE);
        WaitForReceiveHandlers(AddrFile);
        _Status = FileCloseAddress(&SendContext->TdiRequest);
        ASSERT(NT_SUCCESS(_Status));

        IoFreeWorkItem(SendContext->FinishWorker);
        ExFreePoolWithTag(SendContext, OUT_DATA_TAG);

        TI_DbgPrint(DEBUG_ICMP, ("Failed to send a datagram: 0x%x\n", Status));
        return Status;
    }

    IoMarkIrpPending(Irp);
    KeSetTimer(&SendContext->TimeoutTimer, RequestTimeout, &SendContext->TimeoutDpc);
    KeSetEvent(&SendContext->InitializationFinishedEvent, IO_NO_INCREMENT, FALSE);

    return STATUS_PENDING;
}
