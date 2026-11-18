/*
 * PROJECT:     NitroOS SMB mini-redirector
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Internal declarations
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#ifndef _MRXSMB_H_
#define _MRXSMB_H_

#include <rx.h>
#include <windef.h>
#include <winerror.h>
#include <ntstrsafe.h>
#include <pseh/pseh2.h>
#include <drivers/smbrdr/smbupcall.h>

/* Exported by the kernel, not declared by the DDK headers of this tree */
NTKERNELAPI
SECURITY_IMPERSONATION_LEVEL
NTAPI
SeTokenImpersonationLevel(_In_ PACCESS_TOKEN Token);

#define TAG_SMB_REQUEST     'qRbS'
#define TAG_SMB_MESSAGE     'mRbS'
#define TAG_SMB_REPLY       'pRbS'
#define TAG_SMB_MISC        'xRbS'

/* The rdbss device: an internal name; MUP makes \Device\LanmanRedirector a link to \Device\Mup\;LanmanRedirector */
#define SMBRDR_DEVICE_NAME  L"\\Device\\NitroSmbRedirector"

/* State of the engine channel */
typedef struct _SMB_ENGINE
{
    KSPIN_LOCK Lock;
    LIST_ENTRY Queue;               /* requests not yet taken by the engine */
    LIST_ENTRY Sent;                /* requests the engine took, waiting for a reply */
    ULONG QueueLength;
    KSEMAPHORE QueueSemaphore;      /* one count per queued request */
    KEVENT DetachEvent;             /* set while no engine is attached */
    PFILE_OBJECT FileObject;        /* the attached engine's handle, NULL if none */
    PEPROCESS Process;              /* its process, referenced */
    ULONG Generation;               /* changes at each attach and detach */
    ULONGLONG NextRequestId;
    LONG ActiveGets;
} SMB_ENGINE, *PSMB_ENGINE;

typedef enum _SMB_REQUEST_STATE
{
    SmbRequestQueued,
    SmbRequestCopying,
    SmbRequestSent,
    SmbRequestCompleted
} SMB_REQUEST_STATE;

typedef struct _SMB_REQUEST
{
    LIST_ENTRY Link;
    volatile LONG RefCount;
    SMB_REQUEST_STATE State;
    KEVENT Done;
    ULONGLONG RequestId;
    ULONG Generation;
    USHORT Opcode;
    BOOLEAN Notification;
    NTSTATUS Status;                /* final status of the exchange (not the operation's) */
    PSMBUP_HEADER Message;          /* paged pool */
    ULONG MessageSize;              /* bytes used */
    ULONG MessageAllocation;        /* bytes allocated */
    PACCESS_TOKEN Token;            /* CONNECT: referenced impersonation token, handed to the engine */
    PSMBUP_HEADER Reply;            /* paged pool copy of the engine's reply, NULL if none */
    ULONG ReplySize;
} SMB_REQUEST, *PSMB_REQUEST;

/* Extensions of the rdbss structures */
typedef struct _SMB_VNETROOT
{
    FAST_MUTEX ConnectLock;
    ULONGLONG ConnectionId;         /* 0 = not connected */
    ULONG Generation;               /* engine generation of ConnectionId */
    ULONG MaxReadSize;
    ULONG MaxWriteSize;
    BOOLEAN ClientContextValid;
    SECURITY_CLIENT_CONTEXT ClientContext;  /* the user who connected, for reconnects */
} SMB_VNETROOT, *PSMB_VNETROOT;

typedef struct _SMB_SRVOPEN
{
    ULONGLONG FileId;
    ULONGLONG ConnectionId;
    ULONG Generation;
    BOOLEAN Open;
} SMB_SRVOPEN, *PSMB_SRVOPEN;

extern SMB_ENGINE SmbEngine;
extern PDEVICE_OBJECT SmbEngineDevice;
extern PRDBSS_DEVICE_OBJECT SmbRdrDevice;

/* upcall.c */
VOID SmbEngineInitialize(VOID);
NTSTATUS SmbEngineDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS SmbEngineCreateDevice(PDRIVER_OBJECT DriverObject);
VOID SmbEngineDeleteDevice(VOID);
BOOLEAN SmbIsEngineProcess(PEPROCESS Process);
ULONG SmbCurrentGeneration(VOID);
NTSTATUS SmbAllocateRequest(USHORT Opcode, ULONG VariableSize, PLUID LogonId, PSMB_REQUEST *Request);
PVOID SmbRequestFixed(PSMB_REQUEST Request);
NTSTATUS SmbRequestPutBytes(PSMB_REQUEST Request, ULONG *Cursor, const VOID *Data, ULONG Length, PSMBUP_STRING String);
NTSTATUS SmbSendRequest(PSMB_REQUEST Request, ULONG TimeoutSeconds);
VOID SmbSendNotification(PSMB_REQUEST Request);
VOID SmbReleaseRequest(PSMB_REQUEST Request);
NTSTATUS SmbReplyStatus(PSMB_REQUEST Request, ULONG MaxDataLength, PVOID *Data, PULONG DataLength);

#endif /* _MRXSMB_H_ */
