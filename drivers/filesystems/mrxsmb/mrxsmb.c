/*
 * PROJECT:     NitroOS SMB mini-redirector
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Mini-redirector on rdbss: every operation that needs the server is an
 *              upcall to the user-mode SMB engine (upcall.c, smbupcall.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/*
 * Shape (measured on Windows 10 22H2 and Server 2022, see the SMB-00 evidence):
 * the provider registers with MUP by device object as \Device\LanmanRedirector,
 * which MUP makes a link to \Device\Mup\;LanmanRedirector. A drive letter of a
 * logon session is a link to \Device\LanmanRedirector\;X:<logon id>\server\share;
 * UNC names come through \??\UNC -> \Device\Mup. Opens through MUP report
 * \Device\Mup\server\share\... as their name.
 *
 * Everything the engine returns is checked here before rdbss or a caller sees it:
 * sizes against what was asked, structures of returned information, statuses.
 */

#include "mrxsmb.h"

#define NDEBUG
#include <debug.h>

#define SMB_CLOSE_TIMEOUT_SECONDS 30

PRDBSS_DEVICE_OBJECT SmbRdrDevice;
static MINIRDR_DISPATCH SmbDispatch;
static HANDLE SmbMupHandle;
static PFILE_OBJECT SmbRdrDeviceFileObject;     /* a device FCB open, for translated prefix claims */
static BOOLEAN SmbLogonCallbackRegistered;

typedef NTSTATUS (NTAPI *PFN_REGISTER_UNC_PROVIDER_EX)(PHANDLE, PUNICODE_STRING, PDEVICE_OBJECT, ULONG);

#define SmbVNetRoot(V) ((PSMB_VNETROOT)((PMRX_V_NET_ROOT)(V))->Context)
#define SmbSrvOpen(S) ((PSMB_SRVOPEN)((PMRX_SRV_OPEN)(S))->Context)

/* Helpers ******************************************************************/

static
PEPROCESS
SmbRequesterProcess(PRX_CONTEXT RxContext)
{
    if (RxContext->CurrentIrp != NULL && RxContext->CurrentIrp->Tail.Overlay.Thread != NULL)
        return IoThreadToProcess(RxContext->CurrentIrp->Tail.Overlay.Thread);
    return IoGetCurrentProcess();
}

/* The engine's own opens of a share would wait for the engine: refuse them */
static
BOOLEAN
SmbIsRecursion(PRX_CONTEXT RxContext)
{
    return SmbIsEngineProcess(SmbRequesterProcess(RxContext));
}

/* "\dir\file" -> "dir\file" */
static
VOID
SmbStripLeadingSeparator(PUNICODE_STRING Name)
{
    if (Name->Length >= sizeof(WCHAR) && Name->Buffer[0] == OBJ_NAME_PATH_SEPARATOR)
    {
        Name->Buffer++;
        Name->Length -= sizeof(WCHAR);
        Name->MaximumLength = Name->Length;
    }
}

static
NTSTATUS
SmbSendAndCheck(PSMB_REQUEST Request, ULONG Timeout)
{
    NTSTATUS Status = SmbSendRequest(Request, Timeout);

    if (!NT_SUCCESS(Status))
        return Status;
    return SmbReplyStatus(Request, 0, NULL, NULL);
}

/* Tree connect (again, after an engine restart) for a virtual net root */
static
NTSTATUS
SmbConnect(PMRX_V_NET_ROOT VNetRoot, PSMB_VNETROOT Ext)
{
    PMRX_NET_ROOT NetRoot = VNetRoot->pNetRoot;
    PMRX_SRV_CALL SrvCall = NetRoot->pSrvCall;
    UNICODE_STRING Server, Share;
    PSMBUP_CONNECT_REQUEST Fixed;
    PSMBUP_CONNECT_REPLY Reply;
    PSMB_REQUEST Request;
    LUID LogonId = VNetRoot->LogonId;
    ULONG Cursor = 0;
    NTSTATUS Status;

    PAGED_CODE();

    /* \server */
    Server = *SrvCall->pSrvCallName;
    SmbStripLeadingSeparator(&Server);

    /* \server\share, or \share */
    Share = *NetRoot->pNetRootName;
    if (Share.Length > SrvCall->pSrvCallName->Length &&
        RtlPrefixUnicodeString(SrvCall->pSrvCallName, &Share, TRUE) &&
        Share.Buffer[SrvCall->pSrvCallName->Length / sizeof(WCHAR)] == OBJ_NAME_PATH_SEPARATOR)
    {
        Share.Buffer += SrvCall->pSrvCallName->Length / sizeof(WCHAR);
        Share.Length -= SrvCall->pSrvCallName->Length;
    }
    SmbStripLeadingSeparator(&Share);

    if (Server.Length == 0 || Share.Length == 0)
        return STATUS_BAD_NETWORK_PATH;
    if (!Ext->ClientContextValid)
        return STATUS_NO_TOKEN;

    Status = SmbAllocateRequest(SmbUpConnect, Server.Length + Share.Length, &LogonId, &Request);
    if (!NT_SUCCESS(Status))
        return Status;

    Fixed = SmbRequestFixed(Request);
    Status = SmbRequestPutBytes(Request, &Cursor, Server.Buffer, Server.Length, &Fixed->Server);
    if (NT_SUCCESS(Status))
        Status = SmbRequestPutBytes(Request, &Cursor, Share.Buffer, Share.Length, &Fixed->Share);
    if (!NT_SUCCESS(Status))
    {
        SmbReleaseRequest(Request);
        return Status;
    }

    /* The engine gets a handle to the user's (copied) token when it takes the request */
    Request->Token = Ext->ClientContext.ClientToken;
    ObReferenceObject(Request->Token);

    Status = SmbSendAndCheck(Request, 0);
    if (NT_SUCCESS(Status))
    {
        Reply = (PSMBUP_CONNECT_REPLY)(Request->Reply + 1);
        if (Reply->ConnectionId == 0 || Reply->ShareType != 1)
        {
            Status = (Reply->ShareType != 1) ? STATUS_BAD_DEVICE_TYPE : STATUS_INVALID_NETWORK_RESPONSE;
        }
        else
        {
            Ext->ConnectionId = Reply->ConnectionId;
            Ext->Generation = Request->Generation;
            Ext->MaxReadSize = min(max(Reply->MaxReadSize, 4096), SMBUP_MAX_IO);
            Ext->MaxWriteSize = min(max(Reply->MaxWriteSize, 4096), SMBUP_MAX_IO);
        }
    }

    DPRINT1("mrxsmb: connect %wZ\\%wZ logon %lx:%lx: %lx\n", &Server, &Share, LogonId.HighPart, LogonId.LowPart, Status);
    SmbReleaseRequest(Request);
    return Status;
}

/* The connection of a virtual net root, reconnecting once after an engine restart */
static
NTSTATUS
SmbGetConnection(PMRX_V_NET_ROOT VNetRoot, PULONGLONG ConnectionId)
{
    PSMB_VNETROOT Ext = SmbVNetRoot(VNetRoot);
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    ExAcquireFastMutex(&Ext->ConnectLock);
    if (Ext->ConnectionId == 0 || Ext->Generation != SmbCurrentGeneration())
    {
        Ext->ConnectionId = 0;
        Status = SmbConnect(VNetRoot, Ext);
    }
    *ConnectionId = Ext->ConnectionId;
    ExReleaseFastMutex(&Ext->ConnectLock);

    return Status;
}

/* The engine's handle of an open; a handle from before an engine restart is gone */
static
NTSTATUS
SmbGetHandle(PMRX_SRV_OPEN SrvOpen, PSMB_SRVOPEN *Out)
{
    PSMB_SRVOPEN Ext;

    if (SrvOpen == NULL || SrvOpen->Context == NULL)
        return STATUS_INVALID_HANDLE;
    Ext = SmbSrvOpen(SrvOpen);
    if (!Ext->Open)
        return STATUS_INVALID_HANDLE;
    if (Ext->Generation != SmbCurrentGeneration())
        return STATUS_CONNECTION_DISCONNECTED;
    *Out = Ext;
    return STATUS_SUCCESS;
}

static
NTSTATUS
SmbAllocateHandleRequest(PRX_CONTEXT RxContext, USHORT Opcode, ULONG VariableSize, PSMB_SRVOPEN *Handle, PSMB_REQUEST *Request)
{
    NTSTATUS Status;
    PMRX_V_NET_ROOT VNetRoot;

    Status = SmbGetHandle(RxContext->pRelevantSrvOpen, Handle);
    if (!NT_SUCCESS(Status))
        return Status;
    VNetRoot = RxContext->pRelevantSrvOpen->pVNetRoot;
    return SmbAllocateRequest(Opcode, VariableSize, &VNetRoot->LogonId, Request);
}

/* Structure checks of returned information ********************************/

/*
 * A chain of variable-size entries (directory or stream information). A last entry
 * whose NextEntryOffset points exactly at the end of the data (a server that pads
 * the last entry) is accepted and its NextEntryOffset set to 0, so that a caller
 * walking the chain stops there.
 */
static
BOOLEAN
SmbCheckEntryChain(PUCHAR Data, ULONG Length, ULONG FixedSize, ULONG NameLengthOffset, ULONG ShortNameOffset)
{
    ULONG Offset = 0, Next, NameLength;

    if (Length == 0)
        return TRUE;
    if (Data == NULL)
        return FALSE;

    for (;;)
    {
        if (Length - Offset < FixedSize)
            return FALSE;
        Next = *(ULONG UNALIGNED *)(Data + Offset);
        NameLength = *(ULONG UNALIGNED *)(Data + Offset + NameLengthOffset);
        if (NameLength > Length - Offset - FixedSize || (NameLength & 1))
            return FALSE;
        if (ShortNameOffset != 0)
        {
            UCHAR ShortLength = Data[Offset + ShortNameOffset];

            if (ShortLength > 12 * sizeof(WCHAR) || (ShortLength & 1))
                return FALSE;
        }
        if (Next == 0)
            return TRUE;
        if (Next < FixedSize + NameLength || (Next % sizeof(LONGLONG)) != 0 || Next > Length - Offset)
            return FALSE;
        if (Next == Length - Offset)
        {
            *(ULONG UNALIGNED *)(Data + Offset) = 0;
            return TRUE;
        }
        Offset += Next;
    }
}

static
BOOLEAN
SmbCheckDirectoryData(FILE_INFORMATION_CLASS Class, PUCHAR Data, ULONG Length)
{
    switch (Class)
    {
        case FileDirectoryInformation:
            return SmbCheckEntryChain(Data, Length, FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName),
                                      FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileNameLength), 0);
        case FileFullDirectoryInformation:
            return SmbCheckEntryChain(Data, Length, FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName),
                                      FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileNameLength), 0);
        case FileBothDirectoryInformation:
            return SmbCheckEntryChain(Data, Length, FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName),
                                      FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileNameLength),
                                      FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, ShortNameLength));
        case FileNamesInformation:
            return SmbCheckEntryChain(Data, Length, FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName),
                                      FIELD_OFFSET(FILE_NAMES_INFORMATION, FileNameLength), 0);
        case FileIdBothDirectoryInformation:
            return SmbCheckEntryChain(Data, Length, FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName),
                                      FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength),
                                      FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, ShortNameLength));
        case FileIdFullDirectoryInformation:
            return SmbCheckEntryChain(Data, Length, FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName),
                                      FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileNameLength), 0);
        default:
            return FALSE;
    }
}

/* Fixed size of a file information class we pass to the engine; 0 = variable, ~0 = not passed */
static
ULONG
SmbFileInfoSize(FILE_INFORMATION_CLASS Class)
{
    switch (Class)
    {
        case FileBasicInformation: return sizeof(FILE_BASIC_INFORMATION);
        case FileStandardInformation: return sizeof(FILE_STANDARD_INFORMATION);
        case FileInternalInformation: return sizeof(FILE_INTERNAL_INFORMATION);
        case FileEaInformation: return sizeof(FILE_EA_INFORMATION);
        case FileNetworkOpenInformation: return sizeof(FILE_NETWORK_OPEN_INFORMATION);
        case FileAttributeTagInformation: return sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);
        case FileStreamInformation: return 0;
        default: return MAXULONG;
    }
}

static
BOOLEAN
SmbCheckVolumeData(FS_INFORMATION_CLASS Class, PUCHAR Data, ULONG Length)
{
    switch (Class)
    {
        case FileFsVolumeInformation:
        {
            PFILE_FS_VOLUME_INFORMATION Info = (PFILE_FS_VOLUME_INFORMATION)Data;

            return Length >= FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) &&
                   Info->VolumeLabelLength <= Length - FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) &&
                   !(Info->VolumeLabelLength & 1);
        }
        case FileFsSizeInformation:
            return Length == sizeof(FILE_FS_SIZE_INFORMATION);
        case FileFsFullSizeInformation:
            return Length == sizeof(FILE_FS_FULL_SIZE_INFORMATION);
        case FileFsAttributeInformation:
        {
            PFILE_FS_ATTRIBUTE_INFORMATION Info = (PFILE_FS_ATTRIBUTE_INFORMATION)Data;

            return Length >= FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) &&
                   Info->FileSystemNameLength <= Length - FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) &&
                   !(Info->FileSystemNameLength & 1);
        }
        default:
            return FALSE;
    }
}

/* Name resolution ***********************************************************/

static
VOID
NTAPI
SmbCreateSrvCallWorker(PVOID Context)
{
    PMRX_SRVCALL_CALLBACK_CONTEXT CallbackContext = Context;
    PMRX_SRVCALLDOWN_STRUCTURE Calldown = CallbackContext->SrvCalldownStructure;
    PMRX_SRV_CALL SrvCall = Calldown->SrvCall;

    /* Nothing to connect yet: the engine connects per (server, share, logon) */
    if (SrvCall->pSrvCallName == NULL || SrvCall->pSrvCallName->Length < 2 * sizeof(WCHAR) ||
        SrvCall->pSrvCallName->Length > 512 * sizeof(WCHAR))
    {
        CallbackContext->Status = STATUS_BAD_NETWORK_PATH;
    }
    else
    {
        CallbackContext->Status = STATUS_SUCCESS;
    }
    CallbackContext->RecommunicateContext = NULL;
    Calldown->CallBack(CallbackContext);
}

static
NTSTATUS
NTAPI
SmbCreateSrvCall(PMRX_SRV_CALL SrvCall, PMRX_SRVCALL_CALLBACK_CONTEXT CallbackContext)
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(SrvCall);

    if (IoGetCurrentProcess() == RxGetRDBSSProcess())
    {
        SmbCreateSrvCallWorker(CallbackContext);
    }
    else
    {
        Status = RxDispatchToWorkerThread(SmbRdrDevice, DelayedWorkQueue, SmbCreateSrvCallWorker, CallbackContext);
        if (!NT_SUCCESS(Status))
        {
            CallbackContext->Status = Status;
            CallbackContext->SrvCalldownStructure->CallBack(CallbackContext);
        }
    }

    /* rdbss waits for the callback */
    return STATUS_PENDING;
}

static
NTSTATUS
NTAPI
SmbSrvCallWinnerNotify(PMRX_SRV_CALL SrvCall, BOOLEAN ThisMinirdrIsTheWinner, PVOID RecommunicateContext)
{
    UNREFERENCED_PARAMETER(ThisMinirdrIsTheWinner);
    UNREFERENCED_PARAMETER(RecommunicateContext);
    SrvCall->Context = NULL;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbCreateVNetRoot(PMRX_CREATENETROOT_CONTEXT Context)
{
    PRX_CONTEXT RxContext = Context->RxContext;
    PMRX_V_NET_ROOT VNetRoot = (PMRX_V_NET_ROOT)Context->pVNetRoot;
    PMRX_NET_ROOT NetRoot = VNetRoot->pNetRoot;
    PSMB_VNETROOT Ext = SmbVNetRoot(VNetRoot);
    SECURITY_QUALITY_OF_SERVICE Qos;
    PIO_SECURITY_CONTEXT SecurityContext;
    NTSTATUS Status;

    PAGED_CODE();

    ExInitializeFastMutex(&Ext->ConnectLock);

    if (NetRoot->Type != NET_ROOT_DISK && NetRoot->Type != NET_ROOT_WILD)
    {
        /* M1: disk shares only (no IPC$ pipes, no printers) */
        Status = STATUS_BAD_DEVICE_TYPE;
        goto Done;
    }

    if (SmbIsRecursion(RxContext))
    {
        Status = STATUS_POSSIBLE_DEADLOCK;
        goto Done;
    }

    SecurityContext = RxContext->Create.NtCreateParameters.SecurityContext;
    if (SecurityContext == NULL || SecurityContext->AccessState == NULL)
    {
        Status = STATUS_ACCESS_DENIED;
        goto Done;
    }

    /* The user who connects: a static copy of the token, at impersonation level, so
     * that the engine can act as this user (and only as this user) for the connection */
    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = SecurityImpersonation;
    Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    Qos.EffectiveOnly = FALSE;
    Status = SeCreateClientSecurityFromSubjectContext(&SecurityContext->AccessState->SubjectSecurityContext,
                                                      &Qos,
                                                      TRUE,
                                                      &Ext->ClientContext);
    if (!NT_SUCCESS(Status))
        goto Done;
    Ext->ClientContextValid = TRUE;

    if (SeTokenImpersonationLevel(Ext->ClientContext.ClientToken) < SecurityImpersonation &&
        SeTokenType(Ext->ClientContext.ClientToken) == TokenImpersonation)
    {
        Status = STATUS_BAD_IMPERSONATION_LEVEL;
        goto Done;
    }

    ExAcquireFastMutex(&Ext->ConnectLock);
    Status = SmbConnect(VNetRoot, Ext);
    ExReleaseFastMutex(&Ext->ConnectLock);

    if (NT_SUCCESS(Status))
    {
        NetRoot->MRxNetRootState = MRX_NET_ROOT_STATE_GOOD;
        NetRoot->DeviceType = FILE_DEVICE_DISK;
    }

Done:
    Context->VirtualNetRootStatus = Status;
    Context->NetRootStatus = Status;
    Context->Callback(Context);

    /* rdbss expects STATUS_PENDING, the result is in the context */
    return STATUS_PENDING;
}

static
VOID
NTAPI
SmbExtractNetRootName(PUNICODE_STRING FilePathName, PMRX_SRV_CALL SrvCall, PUNICODE_STRING NetRootName, PUNICODE_STRING RestOfName)
{
    PWCH Start, End, Limit;

    Limit = (PWCH)((PUCHAR)FilePathName->Buffer + FilePathName->Length);
    Start = FilePathName->Buffer + min(SrvCall->pSrvCallName->Length, FilePathName->Length) / sizeof(WCHAR);

    /* \share up to the next separator */
    for (End = Start; End < Limit; End++)
    {
        if (*End == OBJ_NAME_PATH_SEPARATOR && End != Start)
            break;
    }

    NetRootName->Buffer = Start;
    NetRootName->Length = NetRootName->MaximumLength = (USHORT)((PUCHAR)End - (PUCHAR)Start);
    if (RestOfName != NULL)
    {
        RestOfName->Buffer = End;
        RestOfName->Length = RestOfName->MaximumLength = (USHORT)((PUCHAR)Limit - (PUCHAR)End);
    }
}

static
NTSTATUS
NTAPI
SmbFinalizeSrvCall(PMRX_SRV_CALL SrvCall, BOOLEAN Force)
{
    UNREFERENCED_PARAMETER(SrvCall);
    UNREFERENCED_PARAMETER(Force);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbFinalizeNetRoot(PMRX_NET_ROOT NetRoot, PBOOLEAN Force)
{
    UNREFERENCED_PARAMETER(NetRoot);
    UNREFERENCED_PARAMETER(Force);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbFinalizeVNetRoot(PMRX_V_NET_ROOT VNetRoot, PBOOLEAN Force)
{
    PSMB_VNETROOT Ext = SmbVNetRoot(VNetRoot);
    PSMBUP_DISCONNECT_REQUEST Fixed;
    PSMB_REQUEST Request;

    UNREFERENCED_PARAMETER(Force);
    PAGED_CODE();

    if (Ext == NULL)
        return STATUS_SUCCESS;

    if (Ext->ConnectionId != 0 && Ext->Generation == SmbCurrentGeneration() &&
        NT_SUCCESS(SmbAllocateRequest(SmbUpDisconnect, 0, &VNetRoot->LogonId, &Request)))
    {
        Fixed = SmbRequestFixed(Request);
        Fixed->ConnectionId = Ext->ConnectionId;
        SmbSendAndCheck(Request, SMB_CLOSE_TIMEOUT_SECONDS);
        SmbReleaseRequest(Request);
    }
    Ext->ConnectionId = 0;

    if (Ext->ClientContextValid)
    {
        SeDeleteClientSecurity(&Ext->ClientContext);
        Ext->ClientContextValid = FALSE;
    }
    return STATUS_SUCCESS;
}

/* Opens *********************************************************************/

/* Create options a client may ask of the server (the rest is for local file systems) */
#define SMB_CREATE_OPTIONS_MASK (FILE_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY | \
    FILE_NO_INTERMEDIATE_BUFFERING | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE | \
    FILE_RANDOM_ACCESS | FILE_DELETE_ON_CLOSE | FILE_OPEN_FOR_BACKUP_INTENT | \
    FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL)

static
VOID
SmbCloseRemote(PMRX_V_NET_ROOT VNetRoot, ULONGLONG ConnectionId, ULONGLONG FileId)
{
    PSMBUP_HANDLE_REQUEST Fixed;
    PSMB_REQUEST Request;

    if (!NT_SUCCESS(SmbAllocateRequest(SmbUpClose, 0, &VNetRoot->LogonId, &Request)))
        return;
    Fixed = SmbRequestFixed(Request);
    Fixed->ConnectionId = ConnectionId;
    Fixed->FileId = FileId;
    SmbSendAndCheck(Request, SMB_CLOSE_TIMEOUT_SECONDS);
    SmbReleaseRequest(Request);
}

static
NTSTATUS
NTAPI
SmbCreate(PRX_CONTEXT RxContext)
{
    PNT_CREATE_PARAMETERS Params = &RxContext->Create.NtCreateParameters;
    PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PMRX_FCB Fcb = RxContext->pFcb;
    PMRX_V_NET_ROOT VNetRoot = SrvOpen->pVNetRoot;
    PSMB_SRVOPEN OpenExt = SmbSrvOpen(SrvOpen);
    PSMBUP_CREATE_REQUEST Fixed;
    PSMBUP_CREATE_REPLY Reply;
    PSMB_REQUEST Request;
    UNICODE_STRING Path;
    ULONGLONG ConnectionId;
    FCB_INIT_PACKET InitPacket;
    ULONG NumberOfLinks = 1, Cursor = 0;
    BOOLEAN Directory;
    NTSTATUS Status;

    PAGED_CODE();

    if (SmbIsRecursion(RxContext))
        return STATUS_POSSIBLE_DEADLOCK;
    if (Params->CreateOptions & FILE_OPEN_BY_FILE_ID)
        return STATUS_NOT_SUPPORTED;

    Path = *SrvOpen->pAlreadyPrefixedName;
    SmbStripLeadingSeparator(&Path);
    if (Path.Length > SMBUP_MAX_NAME_BYTES)
        return STATUS_OBJECT_NAME_INVALID;

    Status = SmbGetConnection(VNetRoot, &ConnectionId);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = SmbAllocateRequest(SmbUpCreate, Path.Length, &VNetRoot->LogonId, &Request);
    if (!NT_SUCCESS(Status))
        return Status;

    Fixed = SmbRequestFixed(Request);
    Fixed->ConnectionId = ConnectionId;
    Fixed->DesiredAccess = Params->DesiredAccess;
    Fixed->FileAttributes = Params->FileAttributes & FILE_ATTRIBUTE_VALID_SET_FLAGS;
    Fixed->ShareAccess = Params->ShareAccess & FILE_SHARE_VALID_FLAGS;
    Fixed->CreateDisposition = Params->Disposition;
    Fixed->CreateOptions = Params->CreateOptions & SMB_CREATE_OPTIONS_MASK;
    Status = SmbRequestPutBytes(Request, &Cursor, Path.Buffer, Path.Length, &Fixed->Path);
    if (NT_SUCCESS(Status))
        Status = SmbSendAndCheck(Request, 0);
    if (!NT_SUCCESS(Status))
    {
        SmbReleaseRequest(Request);
        return Status;
    }

    Reply = (PSMBUP_CREATE_REPLY)(Request->Reply + 1);
    Directory = BooleanFlagOn(Reply->Attributes.FileAttributes, FILE_ATTRIBUTE_DIRECTORY);
    if (Reply->FileId == 0 || Reply->CreateAction > FILE_DOES_NOT_EXIST ||
        Reply->Attributes.EndOfFile < 0 || Reply->Attributes.AllocationSize < 0)
    {
        Status = STATUS_INVALID_NETWORK_RESPONSE;
    }
    else if ((Params->CreateOptions & FILE_DIRECTORY_FILE) && !Directory)
    {
        Status = STATUS_NOT_A_DIRECTORY;
    }
    else if ((Params->CreateOptions & FILE_NON_DIRECTORY_FILE) && Directory)
    {
        Status = STATUS_FILE_IS_A_DIRECTORY;
    }
    if (!NT_SUCCESS(Status))
    {
        /* The engine's handle is ours to close */
        if (Reply->FileId != 0)
            SmbCloseRemote(VNetRoot, ConnectionId, Reply->FileId);
        SmbReleaseRequest(Request);
        return Status;
    }

    OpenExt->FileId = Reply->FileId;
    OpenExt->ConnectionId = ConnectionId;
    OpenExt->Generation = Request->Generation;
    OpenExt->Open = TRUE;

    if (!RxIsFcbAcquiredExclusive(Fcb))
    {
        ASSERT(!RxIsFcbAcquiredShared(Fcb));
        RxAcquireExclusiveFcbResourceInMRx(Fcb);
    }

    RxContext->pFobx = RxCreateNetFobx(RxContext, SrvOpen);
    if (RxContext->pFobx == NULL)
    {
        SmbCloseRemote(VNetRoot, ConnectionId, Reply->FileId);
        OpenExt->Open = FALSE;
        SmbReleaseRequest(Request);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (Fcb->OpenCount == 0)
    {
        RxFormInitPacket(InitPacket,
                         &Reply->Attributes.FileAttributes,
                         &NumberOfLinks,
                         (PLARGE_INTEGER)&Reply->Attributes.CreationTime,
                         (PLARGE_INTEGER)&Reply->Attributes.LastAccessTime,
                         (PLARGE_INTEGER)&Reply->Attributes.LastWriteTime,
                         (PLARGE_INTEGER)&Reply->Attributes.ChangeTime,
                         (PLARGE_INTEGER)&Reply->Attributes.AllocationSize,
                         (PLARGE_INTEGER)&Reply->Attributes.EndOfFile,
                         (PLARGE_INTEGER)&Reply->Attributes.EndOfFile);
        RxFinishFcbInitialization(Fcb, RDBSS_STORAGE_NTC(Directory ? FileTypeDirectory : FileTypeFile), &InitPacket);
    }

    /* M1: no local caching; every read and write goes to the server. rdbss turns the
     * buffering state of a file opened without sharing to full caching whatever the
     * mini-redirector asks, so also tell its read and write paths not to use the cache
     * of this open (its cached paths need Cc callbacks rdbss does not implement) */
    SrvOpen->BufferingFlags = FCB_STATE_DISABLE_LOCAL_BUFFERING;
    SrvOpen->Flags |= SRVOPEN_FLAG_DONTUSE_READ_CACHING | SRVOPEN_FLAG_DONTUSE_WRITE_CACHING;

    RxContext->Create.ReturnedCreateInformation = Reply->CreateAction;
    SmbReleaseRequest(Request);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbCollapseOpen(PRX_CONTEXT RxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static
NTSTATUS
NTAPI
SmbShouldTryToCollapseThisOpen(PRX_CONTEXT RxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    /* Every open is its own open on the server */
    return STATUS_MORE_PROCESSING_REQUIRED;
}

static
NTSTATUS
NTAPI
SmbCloseSrvOpen(PRX_CONTEXT RxContext)
{
    PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    PSMB_SRVOPEN Ext = SmbSrvOpen(SrvOpen);

    PAGED_CODE();

    if (Ext->Open && Ext->Generation == SmbCurrentGeneration())
        SmbCloseRemote(SrvOpen->pVNetRoot, Ext->ConnectionId, Ext->FileId);
    Ext->Open = FALSE;

    /* A close does not fail */
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbFlush(PRX_CONTEXT RxContext)
{
    PSMBUP_HANDLE_REQUEST Fixed;
    PSMB_SRVOPEN Handle;
    PSMB_REQUEST Request;
    NTSTATUS Status;

    PAGED_CODE();

    Status = SmbAllocateHandleRequest(RxContext, SmbUpFlush, 0, &Handle, &Request);
    if (!NT_SUCCESS(Status))
        return Status;
    Fixed = SmbRequestFixed(Request);
    Fixed->ConnectionId = Handle->ConnectionId;
    Fixed->FileId = Handle->FileId;
    Status = SmbSendAndCheck(Request, 0);
    SmbReleaseRequest(Request);
    return Status;
}

/* I/O **********************************************************************/

static
NTSTATUS
NTAPI
SmbRead(PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIo = &RxContext->LowIoContext;
    ULONG Count = LowIo->ParamsFor.ReadWrite.ByteCount, Done = 0, Chunk, DataLength;
    LONGLONG Offset = LowIo->ParamsFor.ReadWrite.ByteOffset;
    PSMBUP_IO_REQUEST Fixed;
    PSMB_SRVOPEN Handle;
    PSMB_REQUEST Request;
    PUCHAR Buffer;
    PVOID Data;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    RxContext->IoStatusBlock.Information = 0;
    if (LowIo->ParamsFor.ReadWrite.Buffer == NULL)
        return STATUS_INVALID_USER_BUFFER;
    Buffer = MmGetSystemAddressForMdlSafe(LowIo->ParamsFor.ReadWrite.Buffer, NormalPagePriority);
    if (Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    while (Done < Count)
    {
        Status = SmbAllocateHandleRequest(RxContext, SmbUpRead, 0, &Handle, &Request);
        if (!NT_SUCCESS(Status))
            break;

        Chunk = min(Count - Done, SmbVNetRoot(RxContext->pRelevantSrvOpen->pVNetRoot)->MaxReadSize);
        if (Chunk == 0)
            Chunk = min(Count - Done, SMBUP_MAX_IO);
        Fixed = SmbRequestFixed(Request);
        Fixed->ConnectionId = Handle->ConnectionId;
        Fixed->FileId = Handle->FileId;
        Fixed->Offset = Offset + Done;
        Fixed->Length = Chunk;
        if (BooleanFlagOn(LowIo->ParamsFor.ReadWrite.Flags, LOWIO_READWRITEFLAG_PAGING_IO))
            Request->Message->Flags |= SMBUP_FLAG_PAGING_IO;

        Status = SmbSendRequest(Request, 0);
        if (NT_SUCCESS(Status))
            Status = SmbReplyStatus(Request, Chunk, &Data, &DataLength);
        if (NT_SUCCESS(Status) && DataLength != 0)
            RtlCopyMemory(Buffer + Done, Data, DataLength);
        SmbReleaseRequest(Request);

        if (!NT_SUCCESS(Status))
            break;
        Done += DataLength;
        if (DataLength < Chunk)
            break;
    }

    /* A short read is a success; a read that starts at the end is STATUS_END_OF_FILE */
    if (Done != 0 && (NT_SUCCESS(Status) || Status == STATUS_END_OF_FILE))
        Status = STATUS_SUCCESS;
    else if (Done == 0 && NT_SUCCESS(Status) && Count != 0)
        Status = STATUS_END_OF_FILE;

    RxContext->IoStatusBlock.Information = Done;
    return Status;
}

static
NTSTATUS
NTAPI
SmbWrite(PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIo = &RxContext->LowIoContext;
    ULONG Count = LowIo->ParamsFor.ReadWrite.ByteCount, Done = 0, Chunk, Written, Cursor;
    LONGLONG Offset = LowIo->ParamsFor.ReadWrite.ByteOffset;
    PSMBUP_IO_REQUEST Fixed;
    PSMB_SRVOPEN Handle;
    PSMB_REQUEST Request;
    SMBUP_STRING DataString;
    PUCHAR Buffer;
    NTSTATUS Status = STATUS_SUCCESS;

    PAGED_CODE();

    RxContext->IoStatusBlock.Information = 0;
    if (LowIo->ParamsFor.ReadWrite.Buffer == NULL)
        return STATUS_INVALID_USER_BUFFER;
    Buffer = MmGetSystemAddressForMdlSafe(LowIo->ParamsFor.ReadWrite.Buffer, NormalPagePriority);
    if (Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    while (Done < Count)
    {
        Chunk = min(Count - Done, SmbVNetRoot(RxContext->pRelevantSrvOpen->pVNetRoot)->MaxWriteSize);
        if (Chunk == 0)
            Chunk = min(Count - Done, SMBUP_MAX_IO);

        Status = SmbAllocateHandleRequest(RxContext, SmbUpWrite, Chunk, &Handle, &Request);
        if (!NT_SUCCESS(Status))
            break;

        Fixed = SmbRequestFixed(Request);
        Fixed->ConnectionId = Handle->ConnectionId;
        Fixed->FileId = Handle->FileId;
        Fixed->Offset = Offset + Done;
        Fixed->Length = Chunk;
        if (BooleanFlagOn(LowIo->ParamsFor.ReadWrite.Flags, LOWIO_READWRITEFLAG_PAGING_IO))
            Request->Message->Flags |= SMBUP_FLAG_PAGING_IO;
        Cursor = 0;
        Status = SmbRequestPutBytes(Request, &Cursor, Buffer + Done, Chunk, &DataString);
        Fixed->DataOffset = DataString.Offset;

        if (NT_SUCCESS(Status))
            Status = SmbSendRequest(Request, 0);
        if (NT_SUCCESS(Status))
            Status = SmbReplyStatus(Request, Chunk, NULL, NULL);
        if (NT_SUCCESS(Status))
        {
            /* The count the engine reports, at most what we sent */
            PSMBUP_DATA_REPLY Reply = (PSMBUP_DATA_REPLY)(Request->Reply + 1);

            Written = Reply->Length;
            if (Written > Chunk)
                Status = STATUS_INVALID_NETWORK_RESPONSE;
        }
        SmbReleaseRequest(Request);

        if (!NT_SUCCESS(Status))
            break;
        Done += Written;
        if (Written < Chunk)
            break;
    }

    if (Done != 0 && !NT_SUCCESS(Status) && Status != STATUS_CONNECTION_DISCONNECTED && Status != STATUS_IO_TIMEOUT)
        Status = STATUS_SUCCESS;

    RxContext->IoStatusBlock.Information = Done;
    return Status;
}

static
ULONG
NTAPI
SmbExtendFile(PRX_CONTEXT RxContext, PLARGE_INTEGER NewFileSize, PLARGE_INTEGER NewAllocationSize)
{
    UNREFERENCED_PARAMETER(RxContext);

    /* The server extends the file with the write; allocation follows the size */
    NewAllocationSize->QuadPart = NewFileSize->QuadPart;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbLowIoUnsupported(PRX_CONTEXT RxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    return STATUS_NOT_SUPPORTED;
}

/* Information **************************************************************/

static
NTSTATUS
NTAPI
SmbQueryDirectory(PRX_CONTEXT RxContext)
{
    FILE_INFORMATION_CLASS Class = RxContext->Info.FileInformationClass;
    PUNICODE_STRING Pattern = &RxContext->pFobx->UnicodeQueryTemplate;
    LONG Remaining = RxContext->Info.LengthRemaining;
    PSMBUP_DIRECTORY_REQUEST Fixed;
    PSMB_SRVOPEN Handle;
    PSMB_REQUEST Request;
    ULONG Cursor = 0, DataLength, OutputLength;
    PVOID Data;
    NTSTATUS Status;

    PAGED_CODE();

    if (RxContext->Info.Buffer == NULL || Remaining <= 0)
        return STATUS_INVALID_USER_BUFFER;
    if (!SmbCheckDirectoryData(Class, NULL, 0))
        return STATUS_INVALID_INFO_CLASS;
    if (Pattern->Length > SMBUP_MAX_NAME_BYTES)
        return STATUS_OBJECT_NAME_INVALID;

    OutputLength = min((ULONG)Remaining, SMBUP_MAX_INFO);
    Status = SmbAllocateHandleRequest(RxContext, SmbUpQueryDirectory, Pattern->Length, &Handle, &Request);
    if (!NT_SUCCESS(Status))
        return Status;

    Fixed = SmbRequestFixed(Request);
    Fixed->ConnectionId = Handle->ConnectionId;
    Fixed->FileId = Handle->FileId;
    Fixed->InformationClass = Class;
    Fixed->OutputLength = OutputLength;
    Fixed->FileIndex = RxContext->QueryDirectory.FileIndex;
    if (RxContext->QueryDirectory.RestartScan || RxContext->QueryDirectory.InitialQuery)
        Fixed->Flags |= SMBUP_DIR_RESTART_SCANS;
    if (RxContext->QueryDirectory.ReturnSingleEntry)
        Fixed->Flags |= SMBUP_DIR_RETURN_SINGLE_ENTRY;
    if (RxContext->QueryDirectory.IndexSpecified)
        Fixed->Flags |= SMBUP_DIR_INDEX_SPECIFIED;
    Status = SmbRequestPutBytes(Request, &Cursor, Pattern->Buffer, Pattern->Length, &Fixed->Pattern);

    if (NT_SUCCESS(Status))
        Status = SmbSendRequest(Request, 0);
    if (NT_SUCCESS(Status))
        Status = SmbReplyStatus(Request, OutputLength, &Data, &DataLength);
    if (NT_SUCCESS(Status) && Status != STATUS_NO_MORE_FILES)
    {
        if (Status == STATUS_BUFFER_OVERFLOW || DataLength == 0 ||
            !SmbCheckDirectoryData(Class, Data, DataLength))
        {
            DPRINT1("mrxsmb: directory data refused: class %lu, status %lx, %lu bytes (%08lx %08lx .. %08lx %08lx)\n",
                    (ULONG)Class, Status, DataLength,
                    DataLength >= 8 ? ((PULONG)Data)[0] : 0, DataLength >= 8 ? ((PULONG)Data)[1] : 0,
                    DataLength >= 72 ? ((PULONG)Data)[15] : 0, DataLength >= 72 ? ((PULONG)Data)[17] : 0);
            Status = STATUS_INVALID_NETWORK_RESPONSE;
        }
        else
        {
            RtlCopyMemory(RxContext->Info.Buffer, Data, DataLength);
            RxContext->Info.LengthRemaining -= DataLength;
        }
    }
    SmbReleaseRequest(Request);
    return Status;
}

static
NTSTATUS
NTAPI
SmbQueryVolumeInfo(PRX_CONTEXT RxContext)
{
    FS_INFORMATION_CLASS Class = RxContext->Info.FsInformationClass;
    LONG Remaining = RxContext->Info.LengthRemaining;
    PSMBUP_QUERY_REQUEST Fixed;
    PSMB_SRVOPEN Handle;
    PSMB_REQUEST Request;
    ULONG DataLength, Copy, OutputLength;
    PVOID Data;
    NTSTATUS Status;

    PAGED_CODE();

    if (RxContext->Info.Buffer == NULL || Remaining < 0)
        return STATUS_INVALID_USER_BUFFER;

    if (Class == FileFsDeviceInformation)
    {
        PFILE_FS_DEVICE_INFORMATION Info = RxContext->Info.Buffer;

        /* Measured on Windows: a share is a remote disk */
        if (Remaining < (LONG)sizeof(*Info))
            return STATUS_BUFFER_TOO_SMALL;
        Info->DeviceType = FILE_DEVICE_DISK;
        Info->Characteristics = FILE_REMOTE_DEVICE;
        RxContext->Info.LengthRemaining -= sizeof(*Info);
        return STATUS_SUCCESS;
    }

    if (Class != FileFsVolumeInformation && Class != FileFsSizeInformation &&
        Class != FileFsFullSizeInformation && Class != FileFsAttributeInformation)
    {
        return STATUS_NOT_SUPPORTED;
    }

    /* Ask for at least the fixed part, so the server's answer can be checked */
    OutputLength = min(max((ULONG)Remaining, 64), SMBUP_MAX_INFO);
    Status = SmbAllocateHandleRequest(RxContext, SmbUpQueryVolume, 0, &Handle, &Request);
    if (!NT_SUCCESS(Status))
        return Status;

    Fixed = SmbRequestFixed(Request);
    Fixed->ConnectionId = Handle->ConnectionId;
    Fixed->FileId = Handle->FileId;
    Fixed->InformationClass = Class;
    Fixed->OutputLength = OutputLength;

    Status = SmbSendRequest(Request, 0);
    if (NT_SUCCESS(Status))
        Status = SmbReplyStatus(Request, OutputLength, &Data, &DataLength);
    if (NT_SUCCESS(Status))
    {
        if (Status == STATUS_BUFFER_OVERFLOW ? DataLength == 0 : !SmbCheckVolumeData(Class, Data, DataLength))
        {
            Status = STATUS_INVALID_NETWORK_RESPONSE;
        }
        else
        {
            Copy = min(DataLength, (ULONG)Remaining);
            RtlCopyMemory(RxContext->Info.Buffer, Data, Copy);
            RxContext->Info.LengthRemaining -= Copy;
            if (Copy < DataLength)
                Status = STATUS_BUFFER_OVERFLOW;
        }
    }
    SmbReleaseRequest(Request);
    return Status;
}

static
NTSTATUS
NTAPI
SmbQueryFileInfo(PRX_CONTEXT RxContext)
{
    FILE_INFORMATION_CLASS Class = RxContext->Info.FileInformationClass;
    LONG Remaining = RxContext->Info.LengthRemaining;
    ULONG Size = SmbFileInfoSize(Class), DataLength, Copy, OutputLength;
    PSMBUP_QUERY_REQUEST Fixed;
    PSMB_SRVOPEN Handle;
    PSMB_REQUEST Request;
    PVOID Data;
    NTSTATUS Status;

    PAGED_CODE();

    if (RxContext->Info.Buffer == NULL || Remaining < 0)
        return STATUS_INVALID_USER_BUFFER;
    if (Size == MAXULONG)
        return STATUS_NOT_SUPPORTED;

    OutputLength = Size ? Size : min((ULONG)Remaining, SMBUP_MAX_INFO);
    if (OutputLength == 0)
        return STATUS_BUFFER_OVERFLOW;

    Status = SmbAllocateHandleRequest(RxContext, SmbUpQueryInfo, 0, &Handle, &Request);
    if (!NT_SUCCESS(Status))
        return Status;

    Fixed = SmbRequestFixed(Request);
    Fixed->ConnectionId = Handle->ConnectionId;
    Fixed->FileId = Handle->FileId;
    Fixed->InformationClass = Class;
    Fixed->OutputLength = OutputLength;

    Status = SmbSendRequest(Request, 0);
    if (NT_SUCCESS(Status))
        Status = SmbReplyStatus(Request, OutputLength, &Data, &DataLength);
    if (NT_SUCCESS(Status))
    {
        BOOLEAN Valid;

        if (Size != 0)
            Valid = (Status == STATUS_SUCCESS && DataLength == Size);
        else
            Valid = DataLength != 0 &&
                    (Status == STATUS_BUFFER_OVERFLOW ||
                     SmbCheckEntryChain(Data, DataLength, FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName),
                                        FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamNameLength), 0));
        if (!Valid)
        {
            Status = STATUS_INVALID_NETWORK_RESPONSE;
        }
        else
        {
            Copy = min(DataLength, (ULONG)Remaining);
            RtlCopyMemory(RxContext->Info.Buffer, Data, Copy);
            RxContext->Info.LengthRemaining -= Copy;
            if (Copy < DataLength)
                Status = STATUS_BUFFER_OVERFLOW;
        }
    }
    SmbReleaseRequest(Request);
    return Status;
}

/* Target of a rename, relative to the share root, from what rdbss hands us */
static
NTSTATUS
SmbRenameTarget(PRX_CONTEXT RxContext, PFILE_RENAME_INFORMATION Info, ULONG InfoLength, PUNICODE_STRING Target, PWCHAR *Allocated)
{
    PMRX_NET_ROOT NetRoot = RxContext->pFcb->pNetRoot;
    UNICODE_STRING Name, Parent;
    USHORT i;

    *Allocated = NULL;
    if (InfoLength < FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        Info->FileNameLength > InfoLength - FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName) ||
        Info->FileNameLength == 0 || (Info->FileNameLength & 1) || Info->FileNameLength > SMBUP_MAX_NAME_BYTES)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Name.Buffer = Info->FileName;
    Name.Length = Name.MaximumLength = (USHORT)Info->FileNameLength;

    if (Name.Buffer[0] != OBJ_NAME_PATH_SEPARATOR)
    {
        /* A name in the same directory */
        for (i = 0; i < Name.Length / sizeof(WCHAR); i++)
        {
            if (Name.Buffer[i] == OBJ_NAME_PATH_SEPARATOR)
                return STATUS_OBJECT_NAME_INVALID;
        }
        Parent = *RxContext->pRelevantSrvOpen->pAlreadyPrefixedName;
        SmbStripLeadingSeparator(&Parent);
        while (Parent.Length != 0 && Parent.Buffer[Parent.Length / sizeof(WCHAR) - 1] != OBJ_NAME_PATH_SEPARATOR)
            Parent.Length -= sizeof(WCHAR);

        *Allocated = ExAllocatePoolWithTag(PagedPool, Parent.Length + Name.Length, TAG_SMB_MISC);
        if (*Allocated == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(*Allocated, Parent.Buffer, Parent.Length);
        RtlCopyMemory((PUCHAR)*Allocated + Parent.Length, Name.Buffer, Name.Length);
        Target->Buffer = *Allocated;
        Target->Length = Target->MaximumLength = Parent.Length + Name.Length;
        return STATUS_SUCCESS;
    }

    /* A path: skip a \;X:<id> component, then the net root (\server\share) */
    if (Name.Length >= 2 * sizeof(WCHAR) && Name.Buffer[1] == L';')
    {
        for (i = 1; i < Name.Length / sizeof(WCHAR) && Name.Buffer[i] != OBJ_NAME_PATH_SEPARATOR; i++);
        Name.Buffer += i;
        Name.Length -= i * sizeof(WCHAR);
    }
    if (Name.Length > NetRoot->pNetRootName->Length &&
        RtlPrefixUnicodeString(NetRoot->pNetRootName, &Name, TRUE) &&
        Name.Buffer[NetRoot->pNetRootName->Length / sizeof(WCHAR)] == OBJ_NAME_PATH_SEPARATOR)
    {
        Name.Buffer += NetRoot->pNetRootName->Length / sizeof(WCHAR);
        Name.Length -= NetRoot->pNetRootName->Length;
    }
    SmbStripLeadingSeparator(&Name);
    if (Name.Length == 0)
        return STATUS_OBJECT_NAME_INVALID;

    *Target = Name;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbSetFileInfo(PRX_CONTEXT RxContext)
{
    FILE_INFORMATION_CLASS Class = RxContext->Info.FileInformationClass;
    ULONG Length = (ULONG)max(RxContext->Info.Length, 0), Size, Cursor = 0;
    PSMB_SRVOPEN Handle;
    PSMB_REQUEST Request;
    NTSTATUS Status;

    PAGED_CODE();

    if (RxContext->Info.Buffer == NULL)
        return STATUS_INVALID_USER_BUFFER;

    if (Class == FileRenameInformation)
    {
        PSMBUP_RENAME_REQUEST Fixed;
        UNICODE_STRING Target;
        PWCHAR Allocated;

        Status = SmbRenameTarget(RxContext, RxContext->Info.Buffer, Length, &Target, &Allocated);
        if (!NT_SUCCESS(Status))
            return Status;

        Status = SmbAllocateHandleRequest(RxContext, SmbUpRename, Target.Length, &Handle, &Request);
        if (NT_SUCCESS(Status))
        {
            Fixed = SmbRequestFixed(Request);
            Fixed->ConnectionId = Handle->ConnectionId;
            Fixed->FileId = Handle->FileId;
            Fixed->ReplaceIfExists = ((PFILE_RENAME_INFORMATION)RxContext->Info.Buffer)->ReplaceIfExists ||
                                     RxContext->Info.ReplaceIfExists;
            Status = SmbRequestPutBytes(Request, &Cursor, Target.Buffer, Target.Length, &Fixed->NewName);
            if (NT_SUCCESS(Status))
                Status = SmbSendAndCheck(Request, 0);
            SmbReleaseRequest(Request);
        }
        if (Allocated != NULL)
            ExFreePoolWithTag(Allocated, TAG_SMB_MISC);
        return Status;
    }

    switch (Class)
    {
        case FileBasicInformation: Size = sizeof(FILE_BASIC_INFORMATION); break;
        case FileEndOfFileInformation: Size = sizeof(FILE_END_OF_FILE_INFORMATION); break;
        case FileAllocationInformation: Size = sizeof(FILE_ALLOCATION_INFORMATION); break;
        case FileDispositionInformation: Size = sizeof(FILE_DISPOSITION_INFORMATION); break;
        default: return STATUS_NOT_SUPPORTED;
    }
    if (Length < Size)
        return STATUS_INFO_LENGTH_MISMATCH;

    Status = SmbAllocateHandleRequest(RxContext, SmbUpSetInfo, Size, &Handle, &Request);
    if (NT_SUCCESS(Status))
    {
        PSMBUP_SET_REQUEST Fixed = SmbRequestFixed(Request);
        SMBUP_STRING DataString;

        Fixed->ConnectionId = Handle->ConnectionId;
        Fixed->FileId = Handle->FileId;
        Fixed->InformationClass = Class;
        Fixed->Length = Size;
        Status = SmbRequestPutBytes(Request, &Cursor, RxContext->Info.Buffer, Size, &DataString);
        Fixed->DataOffset = DataString.Offset;
        if (NT_SUCCESS(Status))
            Status = SmbSendAndCheck(Request, 0);
        SmbReleaseRequest(Request);
    }
    return Status;
}

static
NTSTATUS
NTAPI
SmbSetFileInfoAtCleanup(PRX_CONTEXT RxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    /* Times and sizes are the server's */
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbIsValidDirectory(PRX_CONTEXT RxContext, PUNICODE_STRING DirectoryName)
{
    UNREFERENCED_PARAMETER(RxContext);
    UNREFERENCED_PARAMETER(DirectoryName);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbComputeNewBufferingState(PMRX_SRV_OPEN SrvOpen, PVOID MRxContext, PULONG NewBufferingState)
{
    UNREFERENCED_PARAMETER(SrvOpen);
    UNREFERENCED_PARAMETER(MRxContext);
    *NewBufferingState = 0;
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbCompleteBufferingStateChangeRequest(PRX_CONTEXT RxContext, PMRX_SRV_OPEN SrvOpen, PVOID MRxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    UNREFERENCED_PARAMETER(SrvOpen);
    UNREFERENCED_PARAMETER(MRxContext);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbAreFilesAliased(PFCB Fcb1, PFCB Fcb2)
{
    UNREFERENCED_PARAMETER(Fcb1);
    UNREFERENCED_PARAMETER(Fcb2);
    return STATUS_NOT_IMPLEMENTED;
}

static
NTSTATUS
NTAPI
SmbSuccess(PRX_CONTEXT RxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbNotSupported(PRX_CONTEXT RxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    return STATUS_NOT_SUPPORTED;
}

static
NTSTATUS
NTAPI
SmbDeallocateForFcb(PMRX_FCB Fcb)
{
    UNREFERENCED_PARAMETER(Fcb);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbDeallocateForFobx(PMRX_FOBX Fobx)
{
    UNREFERENCED_PARAMETER(Fobx);
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbIsLockRealizable(PMRX_FCB Fcb, PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, ULONG LowIoLockFlags)
{
    UNREFERENCED_PARAMETER(Fcb);
    UNREFERENCED_PARAMETER(ByteOffset);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(LowIoLockFlags);
    /* M1: byte-range locks are not sent to the server */
    return STATUS_NOT_SUPPORTED;
}

/*
 * One connection id for all: connections are told apart by the logon id of their
 * virtual net roots. This fills the whole RX_CONNECTION_ID: rxce sets only the
 * SessionID part when a mini-redirector has no MRxGetConnectionId and compares the
 * whole LUID, so the uninitialized half made every lookup miss (a new virtual net
 * root, and a new connection, for every open).
 */
static
NTSTATUS
NTAPI
SmbGetConnectionId(PRX_CONTEXT RxContext, PRX_CONNECTION_ID UniqueId)
{
    UNREFERENCED_PARAMETER(RxContext);
    RtlZeroMemory(UniqueId, sizeof(*UniqueId));
    return STATUS_SUCCESS;
}

static
NTSTATUS
NTAPI
SmbDevFcbXXXControlFile(PRX_CONTEXT RxContext)
{
    UNREFERENCED_PARAMETER(RxContext);
    return STATUS_INVALID_DEVICE_REQUEST;
}

/* Start, logoff, dispatch ***************************************************/

static
NTSTATUS
NTAPI
SmbStart(PRX_CONTEXT RxContext, PRDBSS_DEVICE_OBJECT RxDeviceObject)
{
    UNICODE_STRING Routine = RTL_CONSTANT_STRING(L"FsRtlRegisterUncProviderEx");
    UNICODE_STRING ProviderName = RTL_CONSTANT_STRING(NITRO_SMBRDR_PROVIDER_NAME);
    PFN_REGISTER_UNC_PROVIDER_EX RegisterEx;

    UNREFERENCED_PARAMETER(RxContext);
    PAGED_CODE();

    /* By device object: MUP makes \Device\LanmanRedirector a link to \Device\Mup\;LanmanRedirector */
    RegisterEx = (PFN_REGISTER_UNC_PROVIDER_EX)MmGetSystemRoutineAddress(&Routine);
    if (RegisterEx == NULL)
        return STATUS_NOT_SUPPORTED;
    return RegisterEx(&SmbMupHandle, &ProviderName, &RxDeviceObject->DeviceObject, 0);
}

static
NTSTATUS
NTAPI
SmbStop(PRX_CONTEXT RxContext, PRDBSS_DEVICE_OBJECT RxDeviceObject)
{
    UNREFERENCED_PARAMETER(RxContext);
    UNREFERENCED_PARAMETER(RxDeviceObject);
    return STATUS_SUCCESS;
}

/* A logon session ended: the engine drops its connections */
static
NTSTATUS
NTAPI
SmbLogonTerminated(PLUID LogonId)
{
    PSMBUP_LOGOFF_REQUEST Fixed;
    PSMB_REQUEST Request;

    if (SmbEngine.FileObject == NULL)
        return STATUS_SUCCESS;
    if (NT_SUCCESS(SmbAllocateRequest(SmbUpLogoff, 0, LogonId, &Request)))
    {
        Fixed = SmbRequestFixed(Request);
        Fixed->LogonIdLow = LogonId->LowPart;
        Fixed->LogonIdHigh = LogonId->HighPart;
        SmbSendNotification(Request);
    }
    return STATUS_SUCCESS;
}

/*
 * MUP asks providers registered by device object with IOCTL_REDIR_QUERY_PATH_EX;
 * rdbss understands IOCTL_REDIR_QUERY_PATH only. Ask rdbss with that on its
 * device FCB, and answer MUP with what it accepted.
 */
static
NTSTATUS
SmbQueryPathEx(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    PQUERY_PATH_REQUEST_EX RequestEx = Stack->Parameters.DeviceIoControl.Type3InputBuffer;
    PQUERY_PATH_RESPONSE Response = Irp->UserBuffer;
    PQUERY_PATH_REQUEST Request;
    IO_STATUS_BLOCK IoStatus;
    PIO_STACK_LOCATION Next;
    KEVENT Event;
    ULONG Size;
    PIRP QueryIrp;
    NTSTATUS Status;

    PAGED_CODE();

    if (Irp->RequestorMode != KernelMode || RequestEx == NULL || Response == NULL ||
        Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(QUERY_PATH_REQUEST_EX) ||
        Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(QUERY_PATH_RESPONSE))
    {
        Status = STATUS_INVALID_DEVICE_REQUEST;
        goto Complete;
    }

    /* Without an engine nothing can be claimed: do not make rdbss build connections */
    if (SmbEngine.FileObject == NULL || SmbRdrDeviceFileObject == NULL ||
        RequestEx->PathName.Length == 0 || RequestEx->PathName.Length >= MAXUSHORT - sizeof(WCHAR) ||
        SmbIsEngineProcess(IoGetCurrentProcess()))
    {
        Status = STATUS_BAD_NETWORK_PATH;
        goto Complete;
    }

    Size = FIELD_OFFSET(QUERY_PATH_REQUEST, FilePathName) + RequestEx->PathName.Length;
    Request = ExAllocatePoolZero(NonPagedPool, max(Size, sizeof(QUERY_PATH_RESPONSE)), TAG_SMB_MISC);
    if (Request == NULL)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Complete;
    }
    Request->PathNameLength = RequestEx->PathName.Length;
    Request->SecurityContext = RequestEx->pSecurityContext;
    RtlCopyMemory(Request->FilePathName, RequestEx->PathName.Buffer, RequestEx->PathName.Length);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    QueryIrp = IoBuildDeviceIoControlRequest(IOCTL_REDIR_QUERY_PATH,
                                             &SmbRdrDevice->DeviceObject,
                                             Request,
                                             Size,
                                             Request,
                                             sizeof(QUERY_PATH_RESPONSE),
                                             FALSE,
                                             &Event,
                                             &IoStatus);
    if (QueryIrp == NULL)
    {
        ExFreePoolWithTag(Request, TAG_SMB_MISC);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Complete;
    }
    Next = IoGetNextIrpStackLocation(QueryIrp);
    Next->FileObject = SmbRdrDeviceFileObject;

    Status = IoCallDriver(&SmbRdrDevice->DeviceObject, QueryIrp);
    if (Status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    if (NT_SUCCESS(Status))
    {
        ULONG Accepted = ((PQUERY_PATH_RESPONSE)Request)->LengthAccepted;

        Response->LengthAccepted = min(Accepted, RequestEx->PathName.Length);
        Status = STATUS_SUCCESS;
    }
    ExFreePoolWithTag(Request, TAG_SMB_MISC);

Complete:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static
NTSTATUS
NTAPI
SmbFsdDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    if (DeviceObject == SmbEngineDevice)
        return SmbEngineDispatch(DeviceObject, Irp);

    if (DeviceObject != &SmbRdrDevice->DeviceObject)
    {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
        Stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_REDIR_QUERY_PATH_EX)
    {
        return SmbQueryPathEx(Irp, Stack);
    }

    return RxFsdDispatch(SmbRdrDevice, Irp);
}

/* Failures other than "not found" go to the debug log, with the class asked for */
#define SMB_TRACED(Name, Function) \
static NTSTATUS NTAPI Name(PRX_CONTEXT RxContext) \
{ \
    NTSTATUS Status = Function(RxContext); \
    if (!NT_SUCCESS(Status) && Status != STATUS_NO_MORE_FILES && Status != STATUS_NO_SUCH_FILE && \
        Status != STATUS_OBJECT_NAME_NOT_FOUND && Status != STATUS_OBJECT_PATH_NOT_FOUND && \
        Status != STATUS_OBJECT_NAME_COLLISION && Status != STATUS_END_OF_FILE) \
        DPRINT1("mrxsmb: " #Function " class %lu: %lx\n", (ULONG)RxContext->Info.FileInformationClass, Status); \
    return Status; \
}
SMB_TRACED(SmbCreateT, SmbCreate)
SMB_TRACED(SmbQueryDirectoryT, SmbQueryDirectory)
SMB_TRACED(SmbQueryVolumeInfoT, SmbQueryVolumeInfo)
SMB_TRACED(SmbQueryFileInfoT, SmbQueryFileInfo)
SMB_TRACED(SmbSetFileInfoT, SmbSetFileInfo)
SMB_TRACED(SmbReadT, SmbRead)
SMB_TRACED(SmbWriteT, SmbWrite)

static
VOID
SmbInitializeDispatch(VOID)
{
    ULONG i;

    ZeroAndInitializeNodeType(&SmbDispatch, RDBSS_NTC_MINIRDR_DISPATCH, sizeof(MINIRDR_DISPATCH));

    SmbDispatch.MRxFlags = RDBSS_MANAGE_V_NET_ROOT_EXTENSION | RDBSS_MANAGE_SRV_OPEN_EXTENSION;
    SmbDispatch.MRxVNetRootSize = sizeof(SMB_VNETROOT);
    SmbDispatch.MRxSrvOpenSize = sizeof(SMB_SRVOPEN);

    SmbDispatch.MRxStart = SmbStart;
    SmbDispatch.MRxStop = SmbStop;
    SmbDispatch.MRxDevFcbXXXControlFile = SmbDevFcbXXXControlFile;

    SmbDispatch.MRxCreateSrvCall = SmbCreateSrvCall;
    SmbDispatch.MRxSrvCallWinnerNotify = SmbSrvCallWinnerNotify;
    SmbDispatch.MRxCreateVNetRoot = SmbCreateVNetRoot;
    SmbDispatch.MRxExtractNetRootName = SmbExtractNetRootName;
    SmbDispatch.MRxFinalizeSrvCall = SmbFinalizeSrvCall;
    SmbDispatch.MRxFinalizeNetRoot = SmbFinalizeNetRoot;
    SmbDispatch.MRxFinalizeVNetRoot = SmbFinalizeVNetRoot;
    SmbDispatch.MRxGetConnectionId = SmbGetConnectionId;

    SmbDispatch.MRxCreate = SmbCreateT;
    SmbDispatch.MRxCollapseOpen = SmbCollapseOpen;
    SmbDispatch.MRxShouldTryToCollapseThisOpen = SmbShouldTryToCollapseThisOpen;
    SmbDispatch.MRxExtendForCache = SmbExtendFile;
    SmbDispatch.MRxExtendForNonCache = SmbExtendFile;
    SmbDispatch.MRxCloseSrvOpen = SmbCloseSrvOpen;
    SmbDispatch.MRxCleanupFobx = SmbSuccess;
    SmbDispatch.MRxFlush = SmbFlush;
    SmbDispatch.MRxDeallocateForFcb = SmbDeallocateForFcb;
    SmbDispatch.MRxDeallocateForFobx = SmbDeallocateForFobx;
    SmbDispatch.MRxIsLockRealizable = SmbIsLockRealizable;

    SmbDispatch.MRxQueryDirectory = SmbQueryDirectoryT;
    SmbDispatch.MRxQueryVolumeInfo = SmbQueryVolumeInfoT;
    SmbDispatch.MRxSetVolumeInfo = SmbNotSupported;
    SmbDispatch.MRxQueryFileInfo = SmbQueryFileInfoT;
    SmbDispatch.MRxSetFileInfo = SmbSetFileInfoT;
    SmbDispatch.MRxSetFileInfoAtCleanup = SmbSetFileInfoAtCleanup;
    SmbDispatch.MRxQueryEaInfo = SmbNotSupported;
    SmbDispatch.MRxSetEaInfo = SmbNotSupported;
    SmbDispatch.MRxQuerySdInfo = SmbNotSupported;
    SmbDispatch.MRxSetSdInfo = SmbNotSupported;
    SmbDispatch.MRxQueryQuotaInfo = SmbNotSupported;
    SmbDispatch.MRxSetQuotaInfo = SmbNotSupported;
    SmbDispatch.MRxIsValidDirectory = SmbIsValidDirectory;

    SmbDispatch.MRxComputeNewBufferingState = SmbComputeNewBufferingState;
    SmbDispatch.MRxCompleteBufferingStateChangeRequest = SmbCompleteBufferingStateChangeRequest;

    for (i = 0; i <= LOWIO_OP_MAXIMUM; i++)
        SmbDispatch.MRxLowIOSubmit[i] = SmbLowIoUnsupported;
    SmbDispatch.MRxLowIOSubmit[LOWIO_OP_READ] = SmbReadT;
    SmbDispatch.MRxLowIOSubmit[LOWIO_OP_WRITE] = SmbWriteT;

    SmbDispatch.MRxTruncate = SmbNotSupported;
    SmbDispatch.MRxZeroExtend = SmbNotSupported;
    SmbDispatch.MRxAreFilesAliased = SmbAreFilesAliased;
}

/* A device FCB open of our own rdbss device, for the translated prefix claims */
static
NTSTATUS
SmbOpenOwnDevice(VOID)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(SMBRDR_DEVICE_NAME);
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Handle;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwCreateFile(&Handle, SYNCHRONIZE, &ObjectAttributes, &IoStatus, NULL, 0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = ObReferenceObjectByHandle(Handle, 0, *IoFileObjectType, KernelMode, (PVOID *)&SmbRdrDeviceFileObject, NULL);
    ZwClose(Handle);
    return Status;
}

/*
 * No DriverUnload: rdbss's stop and unload (RxStopMinirdr, RxpUnregisterMinirdr,
 * RxUnload) are not implemented, and its worker threads and timer run code of this
 * image. The driver is demand-start and stays loaded once a share was used.
 */
NTSTATUS
NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(SMBRDR_DEVICE_NAME);
    PRX_CONTEXT RxContext;
    BOOLEAN Post = FALSE;
    NTSTATUS Status;
    ULONG i;

    SmbEngineInitialize();

    Status = RxDriverEntry(DriverObject, RegistryPath);
    if (!NT_SUCCESS(Status))
        return Status;

    SmbInitializeDispatch();

    Status = RxRegisterMinirdr(&SmbRdrDevice,
                               DriverObject,
                               &SmbDispatch,
                               RX_REGISTERMINI_FLAG_DONT_PROVIDE_UNCS | RX_REGISTERMINI_FLAG_DONT_PROVIDE_MAILSLOTS,
                               &DeviceName,
                               0,
                               FILE_DEVICE_NETWORK_FILE_SYSTEM,
                               FILE_REMOTE_DEVICE);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = SmbEngineCreateDevice(DriverObject);
    if (!NT_SUCCESS(Status))
        return Status;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        DriverObject->MajorFunction[i] = SmbFsdDispatch;

    /* Start right away: registers with MUP and as a file system */
    RxContext = RxCreateRxContext(NULL, SmbRdrDevice, RX_CONTEXT_FLAG_IN_FSP | RX_CONTEXT_FLAG_WAIT);
    if (RxContext == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    Status = RxStartMinirdr(RxContext, &Post);
    RxDereferenceAndDeleteRxContext(RxContext);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("mrxsmb: RxStartMinirdr failed %lx\n", Status);
        return Status;
    }

    Status = SmbOpenOwnDevice();
    if (!NT_SUCCESS(Status))
        DPRINT1("mrxsmb: no device FCB open: %lx (UNC names will not be claimed)\n", Status);

    if (NT_SUCCESS(SeRegisterLogonSessionTerminatedRoutine(SmbLogonTerminated)))
        SmbLogonCallbackRegistered = TRUE;

    DPRINT1("mrxsmb: started\n");
    return STATUS_SUCCESS;
}
