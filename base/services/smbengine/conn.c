/*
 * PROJECT:     NitroOS SMB client engine service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     One (logon id, server, share) connection: its thread, libsmb2 context and requests
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Only the connection's thread touches its libsmb2 context, its file table and its
 * lists (Pending, Backlog, InFlight). Other threads queue requests (Queue, under
 * QueueLock) and wake the thread with one byte on its loopback UDP socket, which it
 * polls together with the SMB socket.
 *
 * The session. The first request that needs the server (CONNECT or CREATE while there
 * is none) connects: libsmb2 context, credentials of the user (single sign-on: the
 * connection's token impersonated around the credential acquisition; libsmb2's SSPI
 * backend impersonates it again around each InitializeSecurityContext), then
 * smb2_connect_share_async (dialects 2.1..3.1.1 as negotiated, signing and encryption as
 * libsmb2 and the server agree). A lost connection (socket error, a request timing out,
 * the server ending the session or tree) is destroyed; every request on it ends with
 * STATUS_CONNECTION_DISCONNECTED, every file opened on it is stale (Epoch) and answers
 * STATUS_CONNECTION_DISCONNECTED until the driver closes it; the next CREATE connects
 * again, with a back-off after failures. The driver's ConnectionId stays valid
 * throughout: it re-sends CONNECT only after an engine restart.
 *
 * libsmb2 details this relies on: replies (and directory data) are only valid inside
 * the callback, so everything is copied there; passthrough mode is on once connected
 * (raw directory and unknown information classes), off while connecting (libsmb2 does
 * not tree-connect in passthrough mode) and off around SET_INFO encoding (its
 * passthrough encoder puts the buffer length and offset into the data); in passthrough
 * mode an interim STATUS_PENDING reply calls the callback once more, which is ignored;
 * a context is never destroyed inside one of its own callbacks.
 */

#include "smbengine.h"
#include <ndk/iofuncs.h>

#define ALIGN8(x) (((x) + 7) & ~7UL)
#define DATA_OFFSET ALIGN8(sizeof(SMBUP_HEADER) + sizeof(SMBUP_DATA_REPLY))
#define MAX_IN_FLIGHT 64

static VOID ConnTake(PSMBENG_CONN Conn, PSMBENG_OP Op, BOOLEAN FromBacklog);
static VOID OpCb(struct smb2_context *smb2, int status, void *command_data, void *private_data);

static
BOOLEAN
TimeReached(DWORD Now, DWORD Start, DWORD Milliseconds)
{
    return (DWORD)(Now - Start) >= Milliseconds;
}

/* Status mapping ************************************************************/

/*
 * The status of a server reply as the driver may get it. The driver passes NT errors
 * through and refuses others (smbupcall.h); some error codes are instructions to
 * rdbss/rxce rather than results (STATUS_RETRY dispatches again, STATUS_MORE_PROCESSING_REQUIRED
 * opens again, STATUS_CONNECTION_ACTIVE uses a net root that is not there): a server must
 * not be able to send those through us, so they become STATUS_UNEXPECTED_NETWORK_ERROR,
 * as do warnings and informational codes the operation does not have.
 */
NTSTATUS
SmbEngMapStatus(USHORT Opcode, uint32_t Status)
{
    if (Status == 0)
        return STATUS_SUCCESS;
    if (Status == SMB2_STATUS_SHUTDOWN)
        return STATUS_CONNECTION_DISCONNECTED;
    switch (Status)
    {
        case (uint32_t)STATUS_RETRY:
        case (uint32_t)STATUS_MORE_PROCESSING_REQUIRED:
        case (uint32_t)STATUS_CANT_WAIT:
        case (uint32_t)STATUS_CONNECTION_ACTIVE:
        case (uint32_t)STATUS_LOCK_NOT_GRANTED:
        case (uint32_t)STATUS_PENDING:
        case (uint32_t)STATUS_REPARSE:
            return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
    if ((Status & 0xC0000000) == 0xC0000000)
        return (NTSTATUS)Status;
    if (Status == (uint32_t)STATUS_BUFFER_OVERFLOW &&
        (Opcode == SmbUpQueryInfo || Opcode == SmbUpQueryVolume || Opcode == SmbUpQueryDirectory))
    {
        return STATUS_BUFFER_OVERFLOW;
    }
    if (Status == (uint32_t)STATUS_NO_MORE_FILES && Opcode == SmbUpQueryDirectory)
        return STATUS_NO_MORE_FILES;
    return STATUS_UNEXPECTED_NETWORK_ERROR;
}

/* A failed connect as an NT status (for the driver) and a Win32 code (for a network provider) */
static
NTSTATUS
ConnectStatus(struct smb2_context *smb2, int Rc, PULONG Win32)
{
    uint32_t Nt = (uint32_t)smb2_get_nterror(smb2);

    if (Rc > 0)
        Rc = -Rc;
    if (Rc == 0)
        Rc = -EIO;
    *Win32 = NitroSmb2ErrorToWin32(smb2, Rc);
    if ((Nt & 0xC0000000) == 0xC0000000)
        return SmbEngMapStatus(SmbUpConnect, Nt);
    switch (*Win32)
    {
        case ERROR_LOGON_FAILURE: return STATUS_LOGON_FAILURE;
        case ERROR_BAD_NETPATH: return STATUS_BAD_NETWORK_PATH;
        case ERROR_NETNAME_DELETED: return STATUS_CONNECTION_DISCONNECTED;
        case ERROR_ACCESS_DENIED: return STATUS_ACCESS_DENIED;
        case 1272: /* ERROR_SMB_GUEST_LOGON_BLOCKED: a guest session was refused here */
            return STATUS_ACCESS_DENIED;
        default: return STATUS_UNEXPECTED_NETWORK_ERROR;
    }
}

/* Files *********************************************************************/

static
PSMBENG_FILE *
FileSlot(PSMBENG_CONN Conn, ULONGLONG Id)
{
    PSMBENG_FILE *Slot = &Conn->Files[(ULONG)(Id * 0x9E3779B97F4A7C15ULL >> 56) % SMBENG_FILE_BUCKETS];

    while (*Slot != NULL && (*Slot)->Id != Id)
        Slot = &(*Slot)->Next;
    return Slot;
}

static
VOID
FreeFile(PSMBENG_CONN Conn, PSMBENG_FILE File)
{
    UNREFERENCED_PARAMETER(Conn);
    free(File);
    InterlockedDecrement(&SmbEng.FilesLive);
}

/* Takes a file out of the table */
static
PSMBENG_FILE
UnlinkFile(PSMBENG_CONN Conn, ULONGLONG Id)
{
    PSMBENG_FILE *Slot = FileSlot(Conn, Id), File = *Slot;

    if (File != NULL)
    {
        *Slot = File->Next;
        File->Next = NULL;
        Conn->FileCount--;
    }
    return File;
}

static
BOOLEAN
FileIsLive(PSMBENG_CONN Conn, PSMBENG_FILE File)
{
    return Conn->State == ConnUp && Conn->Smb2 != NULL && File->Epoch == Conn->Epoch;
}

/* Closes a server handle nobody holds (the driver never got it, or its binding ended); no reply */
static
VOID
CloseOrphan(PSMBENG_CONN Conn, PSMBENG_FILE File)
{
    struct smb2_close_request req;
    PSMBENG_OP Op;
    struct smb2_pdu *pdu;

    if (!FileIsLive(Conn, File) || (Op = calloc(1, sizeof(*Op))) == NULL)
    {
        FreeFile(Conn, File);
        return;
    }
    InterlockedIncrement(&SmbEng.OpsLive);
    Op->Conn = Conn;
    Op->Opcode = SmbUpClose;
    Op->Internal = TRUE;
    Op->File = File;
    memset(&req, 0, sizeof(req));
    memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
    pdu = smb2_cmd_close_async(Conn->Smb2, &req, OpCb, Op);
    if (pdu == NULL)
    {
        Op->File = NULL;
        FreeFile(Conn, File);
        SmbEngFreeOp(Op);
        return;
    }
    smb2_queue_pdu(Conn->Smb2, pdu);
    Op->Pdu = pdu;
    InsertTailList(&Conn->InFlight, &Op->Link);
    Conn->InFlightCount++;
}

/* Replies *******************************************************************/

/* The error answer of a request; a CONNECT that fails leaves no binding behind */
static
VOID
FailOp(PSMBENG_CONN Conn, PSMBENG_OP Op, NTSTATUS Status)
{
    if (Op->Opcode == SmbUpConnect && !Op->Internal && Op->BindingId != 0)
        SmbEngRemoveBinding(Op->BindingId, Op);
    SmbEngAnswerOp(Op, Status, Conn->ReplyEvent);
}

/* Sends Op->Reply (header filled here) and frees the request; undoes what the driver did not get */
static
VOID
SendBuiltReply(PSMBENG_CONN Conn, PSMBENG_OP Op, NTSTATUS Status)
{
    PSMBUP_HEADER r = (PSMBUP_HEADER)Op->Reply;
    BOOL Sent;

    r->Magic = SMBUP_MAGIC;
    r->Version = SMBUP_VERSION;
    r->Opcode = Op->Opcode;
    r->HeaderSize = sizeof(SMBUP_HEADER);
    r->RequestId = Op->Request->RequestId;
    r->Status = Status;
    r->Win32Error = Op->Win32Error;
    r->TotalSize = Op->ReplySize;
    Sent = SmbEngSendReply(Conn->ReplyEvent, Op->Reply, Op->ReplySize);
    SmbEngLog(2, "request %I64u op %u -> %08lx%s", Op->Request->RequestId, Op->Opcode, Status, Sent ? "" : " (not taken)");

    if (!Sent && NT_SUCCESS(Status))
    {
        /* The driver gave up on the request meanwhile: it holds nothing of this */
        if (Op->Opcode == SmbUpCreate)
        {
            PSMBUP_CREATE_REPLY Rep = (PSMBUP_CREATE_REPLY)(r + 1);
            PSMBENG_FILE File = UnlinkFile(Conn, Rep->FileId);

            if (File != NULL)
                CloseOrphan(Conn, File);
        }
        else if (Op->Opcode == SmbUpConnect)
        {
            SmbEngRemoveBinding(Op->BindingId, Op);
        }
    }
    SmbEngFreeOp(Op);
}

static
BOOLEAN
AllocReply(PSMBENG_OP Op, ULONG Size)
{
    Op->Reply = calloc(1, Size);
    if (Op->Reply == NULL)
        return FALSE;
    Op->ReplyAlloc = Size;
    Op->ReplySize = sizeof(SMBUP_HEADER) + SMBUP_REPLY_FIXED_SIZE(Op->Opcode);
    return TRUE;
}

static
VOID
AnswerConnect(PSMBENG_CONN Conn, PSMBENG_OP Op)
{
    PSMBUP_CONNECT_REPLY Rep;

    if (!AllocReply(Op, sizeof(SMBUP_HEADER) + sizeof(SMBUP_CONNECT_REPLY)))
    {
        FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }
    Rep = (PSMBUP_CONNECT_REPLY)(Op->Reply + sizeof(SMBUP_HEADER));
    Rep->ConnectionId = Op->BindingId;
    Rep->MaxReadSize = Conn->MaxRead;
    Rep->MaxWriteSize = Conn->MaxWrite;
    Rep->ShareType = 1;     /* libsmb2 does not report the share type; non-disk names are refused by the driver */
    Rep->Flags = Conn->Explicit ? SMBUP_CONNECT_REPLY_EXPLICIT : 0;
    SendBuiltReply(Conn, Op, STATUS_SUCCESS);
}

/* Fails every request waiting for the session */
static
VOID
FailPending(PSMBENG_CONN Conn, NTSTATUS Status, ULONG Win32)
{
    while (!IsListEmpty(&Conn->Pending))
    {
        PSMBENG_OP Op = CONTAINING_RECORD(RemoveHeadList(&Conn->Pending), SMBENG_OP, Link);

        if (Op->Opcode == SmbUpConnect)
            Op->Win32Error = Win32;
        FailOp(Conn, Op, Status);
    }
}

/* Connection lifetime *******************************************************/

static
VOID
TearDown(PSMBENG_CONN Conn, NTSTATUS Reason, ULONG Win32)
{
    struct smb2_context *smb2 = Conn->Smb2;

    Conn->Dead = FALSE;
    if (smb2 == NULL)
        return;
    Conn->Smb2 = NULL;
    Conn->TeardownStatus = Reason;
    Conn->TeardownWin32 = Win32;
    /* Every request libsmb2 holds is called back now (SHUTDOWN), a connect in progress
     * with CANCELLED: their callbacks answer the driver */
    smb2_destroy_context(smb2);
    if (Conn->State != ConnLoggedOff)
        Conn->State = ConnDown;
    SmbEngLog(1, "connection %S\\%S logon %08lx:%08lx closed (%08lx)", Conn->Server, Conn->Share,
              Conn->LogonId.HighPart, Conn->LogonId.LowPart, Reason);
}

static
VOID
ConnectFailed(PSMBENG_CONN Conn, NTSTATUS Status, ULONG Win32)
{
    /* A LOGOFF that tears down a connect in progress gets here from ConnectCb: the key
     * stays logged off (no reconnect, every later request refused) */
    if (Conn->State == ConnLoggedOff)
    {
        FailPending(Conn, STATUS_USER_SESSION_DELETED, ERROR_NETNAME_DELETED);
        return;
    }
    Conn->State = ConnDown;
    /* A connect refused at once as unreachable (seen for the first connects after boot, while
     * the stack resolves the neighbour) is tried again shortly, before the waiting requests fail */
    /* Only for a server that did not answer: a share the server refused (STATUS_BAD_NETWORK_NAME,
     * Win32 53 too) is an answer, and Windows reports it at once */
    if (Win32 == ERROR_BAD_NETPATH && Status == STATUS_BAD_NETWORK_PATH && Conn->QuickRetries < 10 &&
        !TimeReached(GetTickCount(), Conn->ConnectStart, 2000) && !SmbEng.Stopping)
    {
        Conn->QuickRetries++;
        Conn->RetryTick = GetTickCount();
        SmbEngLog(1, "connect %S\\%S logon %08lx:%08lx: unreachable at once, trying again (%lu)",
                  Conn->Server, Conn->Share, Conn->LogonId.HighPart, Conn->LogonId.LowPart, Conn->QuickRetries);
        return;
    }
    Conn->QuickRetries = 0;
    Conn->LastConnectStatus = Status;
    Conn->LastConnectWin32 = Win32;
    Conn->Backoff = Conn->Backoff ? min(Conn->Backoff * 2, 30) : 1;
    Conn->FailTick = GetTickCount();
    SmbEngLog(1, "connect %S\\%S logon %08lx:%08lx failed: %08lx win32 %lu (next try in %lu s)",
              Conn->Server, Conn->Share, Conn->LogonId.HighPart, Conn->LogonId.LowPart, Status, Win32, Conn->Backoff);
    FailPending(Conn, Status, Win32);
}

static
VOID
ConnectCb(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    PSMBENG_CONN Conn = private_data;
    NTSTATUS Status;
    ULONG Win32;

    UNREFERENCED_PARAMETER(command_data);

    if (Conn->Smb2 == NULL)
    {
        /* TearDown of a connect in progress */
        ConnectFailed(Conn, Conn->TeardownStatus, Conn->TeardownWin32);
        return;
    }
    if (status != 0)
    {
        Status = ConnectStatus(smb2, status, &Win32);
        Conn->Dead = TRUE;
        ConnectFailed(Conn, Status, Win32);
        return;
    }

    Conn->State = ConnUp;
    Conn->Epoch++;
    Conn->Backoff = 0;
    Conn->QuickRetries = 0;
    Conn->MaxRead = min(smb2_get_max_read_size(smb2), SMBUP_MAX_IO);
    Conn->MaxWrite = min(smb2_get_max_write_size(smb2), SMBUP_MAX_IO);
    /* SMB 2.0.2 has no multi-credit requests: libsmb2 then cuts every READ and WRITE to
     * 64 KiB whatever the server's maximum says, and the cut would reach the driver as a
     * short read (an early end of file) or a short write. Offer only what goes out whole. */
    if (smb2_get_dialect(smb2) == SMB2_VERSION_0202)
    {
        Conn->MaxRead = min(Conn->MaxRead, 64 * 1024);
        Conn->MaxWrite = min(Conn->MaxWrite, 64 * 1024);
    }
    if (Conn->MaxRead < 4096 || Conn->MaxWrite < 4096)
    {
        /* A server that cannot move a page per request is not one we talk to */
        Conn->Dead = TRUE;
        ConnectFailed(Conn, STATUS_INVALID_NETWORK_RESPONSE, ERROR_UNEXP_NET_ERR);
        return;
    }
    Conn->LastActivity = GetTickCount();
    smb2_set_passthrough(smb2, 1);
    {
        struct nitro_smb2_auth_info Info;

        memset(&Info, 0, sizeof(Info));
        Info.size = sizeof(Info);
        NitroSmb2GetAuthInfo(smb2, &Info);
        SmbEngLog(1, "connected %S\\%S logon %08lx:%08lx dialect %x spnego %d mic %d max %lu/%lu",
                  Conn->Server, Conn->Share, Conn->LogonId.HighPart, Conn->LogonId.LowPart,
                  smb2_get_dialect(smb2), Info.spnego, Info.server_token_verified, Conn->MaxRead, Conn->MaxWrite);
    }

    /* The requests that waited for the session */
    while (!IsListEmpty(&Conn->Pending))
    {
        PSMBENG_OP Op = CONTAINING_RECORD(RemoveHeadList(&Conn->Pending), SMBENG_OP, Link);

        if (Op->Opcode == SmbUpConnect)
            AnswerConnect(Conn, Op);
        else
            ConnTake(Conn, Op, FALSE);
    }
}

/* Explicit credentials *****************************************************/

static char *ToUtf8(const WCHAR *s, ULONG Bytes);

/* advapi32 RtlEncryptMemory / RtlDecryptMemory (ntsecapi.h; declared here, the NDK headers clash) */
NTSTATUS WINAPI SystemFunction040(PVOID Memory, ULONG Length, ULONG Flags);
NTSTATUS WINAPI SystemFunction041(PVOID Memory, ULONG Length, ULONG Flags);
#define SMBENG_ENCRYPT_BLOCK        8   /* RTL_ENCRYPT_MEMORY_SIZE */
#define SMBENG_ENCRYPT_SAME_PROCESS 0   /* RTL_ENCRYPT_OPTION_SAME_PROCESS */

/* Under SmbEng.Lock (exclusive): the password of Conn becomes Password (Bytes, UTF-16), kept
 * encrypted for this process only; the caller wipes its own copy. FALSE: no memory or the
 * encryption failed (nothing is kept in clear). */
BOOL
SmbEngSetPassword(PSMBENG_CONN Conn, const WCHAR *Password, ULONG Bytes)
{
    ULONG Alloc = ((Bytes / SMBENG_ENCRYPT_BLOCK) + 1) * SMBENG_ENCRYPT_BLOCK;
    PUCHAR New = calloc(1, Alloc), Old;
    ULONG OldAlloc;

    if (New == NULL)
        return FALSE;
    if (Bytes != 0)
        memcpy(New, Password, Bytes);
    if (!NT_SUCCESS(SystemFunction040(New, Alloc, SMBENG_ENCRYPT_SAME_PROCESS)))
    {
        SecureZeroMemory(New, Alloc);
        free(New);
        SmbEngLog(0, "the password could not be encrypted in memory: not kept");
        return FALSE;
    }
    EnterCriticalSection(&Conn->QueueLock);
    Old = Conn->Password;
    OldAlloc = Conn->PasswordAlloc;
    Conn->Password = New;
    Conn->PasswordAlloc = Alloc;
    Conn->PasswordBytes = Bytes;
    LeaveCriticalSection(&Conn->QueueLock);
    if (Old != NULL)
    {
        SecureZeroMemory(Old, OldAlloc);
        free(Old);
    }
    InterlockedExchange(&Conn->CredentialsChanged, 1);
    return TRUE;
}

/* Under SmbEng.Lock: Conn gets the identity of From (a live connection of the same logon session
 * to the same server). The ciphertext is copied as it is (same process). */
BOOL
SmbEngCopyPassword(PSMBENG_CONN Conn, const SMBENG_CONN *From)
{
    PUCHAR New;

    EnterCriticalSection((LPCRITICAL_SECTION)&From->QueueLock);
    New = From->PasswordAlloc ? malloc(From->PasswordAlloc) : NULL;
    if (New != NULL)
        memcpy(New, From->Password, From->PasswordAlloc);
    LeaveCriticalSection((LPCRITICAL_SECTION)&From->QueueLock);
    if (New == NULL)
        return FALSE;
    EnterCriticalSection(&Conn->QueueLock);
    if (Conn->Password != NULL)
    {
        SecureZeroMemory(Conn->Password, Conn->PasswordAlloc);
        free(Conn->Password);
    }
    Conn->Password = New;
    Conn->PasswordAlloc = From->PasswordAlloc;
    Conn->PasswordBytes = From->PasswordBytes;
    LeaveCriticalSection(&Conn->QueueLock);
    InterlockedExchange(&Conn->CredentialsChanged, 1);
    return TRUE;
}

/* Is Password (Bytes, UTF-16) the password Conn keeps? The clear copy lives only for the comparison */
BOOL
SmbEngSamePassword(PSMBENG_CONN Conn, const WCHAR *Password, ULONG Bytes)
{
    PUCHAR Clear = NULL;
    ULONG Alloc = 0, Held = 0;
    BOOL Same = FALSE;

    EnterCriticalSection(&Conn->QueueLock);
    if (Conn->Password != NULL && (Clear = malloc(Conn->PasswordAlloc)) != NULL)
    {
        memcpy(Clear, Conn->Password, Conn->PasswordAlloc);
        Alloc = Conn->PasswordAlloc;
        Held = Conn->PasswordBytes;
    }
    LeaveCriticalSection(&Conn->QueueLock);
    if (Clear == NULL)
        return FALSE;
    if (NT_SUCCESS(SystemFunction041(Clear, Alloc, SMBENG_ENCRYPT_SAME_PROCESS)) && Held == Bytes)
    {
        /* Every byte is looked at whatever the first difference: a credential check (\;#:) can ask
         * this as often as it likes, without the server, so its time must not tell how much fits */
        volatile UCHAR Diff = 0;
        ULONG i;

        for (i = 0; i < Bytes; i++)
            Diff |= Clear[i] ^ ((const UCHAR *)Password)[i];
        Same = (Diff == 0);
    }
    SecureZeroMemory(Clear, Alloc);
    free(Clear);
    return Same;
}

VOID
SmbEngFreeCredentials(PSMBENG_CONN Conn)
{
    if (Conn->Password != NULL)
    {
        SecureZeroMemory(Conn->Password, Conn->PasswordAlloc);
        free(Conn->Password);
        Conn->Password = NULL;
    }
    Conn->PasswordAlloc = Conn->PasswordBytes = 0;
    free(Conn->User);
    free(Conn->Domain);
    Conn->User = Conn->Domain = NULL;
    Conn->Explicit = FALSE;
}

static
VOID
WipeFreeA(char *s)
{
    if (s != NULL)
    {
        SecureZeroMemory(s, strlen(s));
        free(s);
    }
}

/* Connection thread: libsmb2's credentials for an explicit-credential key, acquired as the
 * user's (filtered) token. The clear password exists only for this call. */
static
int
SetExplicitCredentials(PSMBENG_CONN Conn, struct smb2_context *smb2)
{
    char *User = NULL, *Domain = NULL, *Password = NULL;
    PUCHAR Clear = NULL;
    ULONG Alloc = 0, Bytes = 0;
    int Rc = -ENOMEM;

    EnterCriticalSection(&Conn->QueueLock);
    if (Conn->Password != NULL && (Clear = malloc(Conn->PasswordAlloc)) != NULL)
    {
        memcpy(Clear, Conn->Password, Conn->PasswordAlloc);
        Alloc = Conn->PasswordAlloc;
        Bytes = Conn->PasswordBytes;
    }
    LeaveCriticalSection(&Conn->QueueLock);
    if (Clear == NULL)
        return -ENOMEM;
    if (!NT_SUCCESS(SystemFunction041(Clear, Alloc, SMBENG_ENCRYPT_SAME_PROCESS)))
        goto Out;

    User = ToUtf8(Conn->User, (ULONG)wcslen(Conn->User) * sizeof(WCHAR));
    Domain = ToUtf8(Conn->Domain, (ULONG)wcslen(Conn->Domain) * sizeof(WCHAR));
    Password = ToUtf8((const WCHAR *)Clear, Bytes);
    if (User == NULL || Domain == NULL || Password == NULL)
        goto Out;
    Rc = NitroSmb2SetCredentials(smb2, User, Domain[0] ? Domain : NULL, Password, NULL);

Out:
    SecureZeroMemory(Clear, Alloc);
    free(Clear);
    WipeFreeA(Password);
    free(User);
    free(Domain);
    return Rc;
}

/* Starts a connect (no session, a request waits for one); the result comes in ConnectCb */
static
VOID
ConnStart(PSMBENG_CONN Conn)
{
    struct smb2_context *smb2;
    NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
    ULONG Win32 = ERROR_NOT_ENOUGH_MEMORY;
    int Rc;

    if (Conn->Token == NULL)
    {
        ConnectFailed(Conn, STATUS_NO_TOKEN, ERROR_NO_TOKEN);
        return;
    }
    smb2 = smb2_init_context();
    if (smb2 == NULL)
    {
        ConnectFailed(Conn, Status, Win32);
        return;
    }
    smb2_set_version(smb2, SmbEngConfig.Dialect == 0x210 ? SMB2_VERSION_0210 :
                           SmbEngConfig.Dialect == 0x300 ? SMB2_VERSION_0300 :
                           SmbEngConfig.Dialect == 0x302 ? SMB2_VERSION_0302 :
                           SmbEngConfig.Dialect == 0x311 ? SMB2_VERSION_0311 : SMB2_VERSION_ANY);
    smb2_set_timeout(smb2, (int)SmbEngConfig.RequestTimeoutSeconds);

    /* Single sign-on: the credentials of the user's logon session; explicit credentials: those,
     * acquired as the user too (the filtered token of the connecting user) */
    if (!SetThreadToken(NULL, Conn->Token))
    {
        Win32 = GetLastError();
        smb2_destroy_context(smb2);
        ConnectFailed(Conn, STATUS_BAD_IMPERSONATION_LEVEL, Win32);
        return;
    }
    InterlockedExchange(&Conn->CredentialsChanged, 0);
    InterlockedExchange(&Conn->Reauth, 0);
    if (Conn->Explicit)
        Rc = SetExplicitCredentials(Conn, smb2);
    else
        Rc = NitroSmb2SetCredentials(smb2, NULL, NULL, NULL, NULL);
    RevertToSelf();
    if (Rc < 0)
    {
        Status = ConnectStatus(smb2, Rc, &Win32);
        smb2_destroy_context(smb2);
        ConnectFailed(Conn, Status == STATUS_UNEXPECTED_NETWORK_ERROR ? STATUS_LOGON_FAILURE : Status, Win32);
        return;
    }

    Conn->Smb2 = smb2;
    Conn->State = ConnConnecting;
    Conn->ConnectStart = GetTickCount();
    Rc = smb2_connect_share_async(smb2, Conn->ServerA, Conn->ShareA, NULL, ConnectCb, Conn);
    if (Rc < 0)
    {
        Status = ConnectStatus(smb2, Rc, &Win32);
        Conn->Smb2 = NULL;
        smb2_destroy_context(smb2);
        /* A failure before any packet (the name does not resolve) is not the "unreachable at once
         * after boot" case the quick retries are for: report it now (Windows: about 1 s for an
         * unknown name; ten quick retries made it 10 s, and every UNC open of another provider's
         * prefix, a WinFsp volume for one, waited for them in MUP) */
        Conn->QuickRetries = 10;
        ConnectFailed(Conn, Status, Win32);
        Conn->QuickRetries = 0;
        return;
    }
    SmbEngLog(1, "connecting %S\\%S logon %08lx:%08lx", Conn->Server, Conn->Share,
              Conn->LogonId.HighPart, Conn->LogonId.LowPart);
}

/* Operations ****************************************************************/

static
BOOLEAN
Track(PSMBENG_CONN Conn, PSMBENG_OP Op, struct smb2_pdu *pdu)
{
    if (pdu == NULL)
    {
        FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
        return FALSE;
    }
    smb2_queue_pdu(Conn->Smb2, pdu);
    Op->Pdu = pdu;
    InsertTailList(&Conn->InFlight, &Op->Link);
    Conn->InFlightCount++;
    Conn->LastActivity = GetTickCount();
    return TRUE;
}

static
char *
ToUtf8(const WCHAR *s, ULONG Bytes)
{
    int n = Bytes ? WideCharToMultiByte(CP_UTF8, 0, s, Bytes / 2, NULL, 0, NULL, NULL) : 0;
    char *Out = malloc(n + 1);

    if (Out == NULL)
        return NULL;
    if (n)
        WideCharToMultiByte(CP_UTF8, 0, s, Bytes / 2, Out, n, NULL, NULL);
    Out[n] = 0;
    return Out;
}

static
ULONG
ToUtf16(const char *s, WCHAR *Out, ULONG MaxChars)
{
    int n;

    if (s == NULL || MaxChars == 0)
        return 0;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, Out, MaxChars);
    return n > 0 ? (ULONG)(n - 1) : 0;
}

static
VOID
IssueCreate(PSMBENG_CONN Conn, PSMBENG_OP Op)
{
    PSMBUP_HEADER h = Op->Request;
    PSMBUP_CREATE_REQUEST r = (PSMBUP_CREATE_REQUEST)(h + 1);
    struct smb2_create_request req;
    const WCHAR *Path;
    ULONG Bytes;

    if (!SmbEngStringOf(h, sizeof(*h) + sizeof(*r), &r->Path, &Path, &Bytes))
    {
        FailOp(Conn, Op, STATUS_OBJECT_NAME_INVALID);
        return;
    }
    if (Conn->FileCount >= SMBENG_MAX_FILES_PER_CONN)
    {
        FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }
    if (!(Op->Name = ToUtf8(Path, Bytes)) || !AllocReply(Op, sizeof(SMBUP_HEADER) + sizeof(SMBUP_CREATE_REPLY)))
    {
        FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }
    memset(&req, 0, sizeof(req));
    req.requested_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
    req.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
    req.desired_access = r->DesiredAccess;
    req.file_attributes = r->FileAttributes;
    req.share_access = r->ShareAccess;
    req.create_disposition = r->CreateDisposition;
    req.create_options = r->CreateOptions;
    req.name = Op->Name;
    SmbEngLog(2, "request %I64u create \"%s\" access %08lx disposition %lu options %08lx",
              h->RequestId, Op->Name, r->DesiredAccess, r->CreateDisposition, r->CreateOptions);
    Track(Conn, Op, smb2_cmd_create_async(Conn->Smb2, &req, OpCb, Op));
}

static
VOID
IssueHandleOp(PSMBENG_CONN Conn, PSMBENG_OP Op)
{
    PSMBUP_HEADER h = Op->Request;
    PSMBENG_FILE File = Op->File;
    ULONG FixedEnd = sizeof(*h) + SMBUP_REQUEST_FIXED_SIZE(Op->Opcode);

    switch (Op->Opcode)
    {
        case SmbUpClose:
        {
            struct smb2_close_request req;
            struct smb2_pdu *pdu;

            /* The handle is the driver's no more, whatever the server says */
            UnlinkFile(Conn, File->Id);
            memset(&req, 0, sizeof(req));
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            pdu = smb2_cmd_close_async(Conn->Smb2, &req, OpCb, Op);
            if (pdu == NULL)
            {
                /* The server keeps the handle until the session ends */
                Op->File = NULL;
                FreeFile(Conn, File);
                SmbEngAnswerOp(Op, STATUS_SUCCESS, Conn->ReplyEvent);
                return;
            }
            Track(Conn, Op, pdu);
            return;
        }

        case SmbUpFlush:
        {
            struct smb2_flush_request req;

            memset(&req, 0, sizeof(req));
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            Track(Conn, Op, smb2_cmd_flush_async(Conn->Smb2, &req, OpCb, Op));
            return;
        }

        case SmbUpRead:
        {
            PSMBUP_IO_REQUEST r = (PSMBUP_IO_REQUEST)(h + 1);
            struct smb2_read_request req;

            if (r->Length > Conn->MaxRead || r->Offset < 0 || r->Length == 0)
            {
                FailOp(Conn, Op, STATUS_INVALID_PARAMETER);
                return;
            }
            if (!AllocReply(Op, DATA_OFFSET + r->Length))
            {
                FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
                return;
            }
            Op->DataOffset = DATA_OFFSET;
            Op->DataMax = r->Length;
            memset(&req, 0, sizeof(req));
            req.length = r->Length;
            req.offset = (uint64_t)r->Offset;
            req.buf = Op->Reply + DATA_OFFSET;
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            Track(Conn, Op, smb2_cmd_read_async(Conn->Smb2, &req, OpCb, Op));
            return;
        }

        case SmbUpWrite:
        {
            PSMBUP_IO_REQUEST r = (PSMBUP_IO_REQUEST)(h + 1);
            struct smb2_write_request req;

            if (r->Length > Conn->MaxWrite || r->Offset < 0 || r->Length == 0 ||
                !SMBUP_RANGE_VALID(r->DataOffset, r->Length, FixedEnd, h->TotalSize, 1))
            {
                FailOp(Conn, Op, STATUS_INVALID_PARAMETER);
                return;
            }
            if (!AllocReply(Op, DATA_OFFSET))
            {
                FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
                return;
            }
            Op->DataMax = r->Length;
            memset(&req, 0, sizeof(req));
            req.length = r->Length;
            req.offset = (uint64_t)r->Offset;
            req.buf = (const uint8_t *)h + r->DataOffset;
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            Track(Conn, Op, smb2_cmd_write_async(Conn->Smb2, &req, 0, OpCb, Op));
            return;
        }

        case SmbUpQueryInfo:
        case SmbUpQueryVolume:
        {
            PSMBUP_QUERY_REQUEST r = (PSMBUP_QUERY_REQUEST)(h + 1);
            struct smb2_query_info_request req;

            if (r->OutputLength > SMBUP_MAX_INFO || r->OutputLength == 0 || r->InformationClass > 0xFF)
            {
                FailOp(Conn, Op, STATUS_INVALID_PARAMETER);
                return;
            }
            if (!AllocReply(Op, DATA_OFFSET + SMBUP_MAX_INFO))
            {
                FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
                return;
            }
            Op->DataOffset = DATA_OFFSET;
            Op->DataMax = r->OutputLength;
            memset(&req, 0, sizeof(req));
            req.info_type = Op->Opcode == SmbUpQueryVolume ? SMB2_0_INFO_FILESYSTEM : SMB2_0_INFO_FILE;
            req.file_info_class = (uint8_t)r->InformationClass;
            /* Room for the variable part; we cut to the caller's size (STATUS_BUFFER_OVERFLOW) */
            req.output_buffer_length = min(max(r->OutputLength, 4096), SMBUP_MAX_INFO);
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            Track(Conn, Op, smb2_cmd_query_info_async(Conn->Smb2, &req, OpCb, Op));
            return;
        }

        case SmbUpSetInfo:
        {
            PSMBUP_SET_REQUEST r = (PSMBUP_SET_REQUEST)(h + 1);
            struct smb2_set_info_request req;
            const UCHAR *In = (const UCHAR *)h + r->DataOffset;
            struct smb2_pdu *pdu;

            if (r->Length > 64 || !SMBUP_RANGE_VALID(r->DataOffset, r->Length, FixedEnd, h->TotalSize, 1))
            {
                FailOp(Conn, Op, STATUS_INVALID_PARAMETER);
                return;
            }
            memset(&req, 0, sizeof(req));
            req.info_type = SMB2_0_INFO_FILE;
            req.file_info_class = (uint8_t)r->InformationClass;
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            switch (r->InformationClass)
            {
                case SMB2_FILE_BASIC_INFORMATION:
                {
                    FILE_BASIC_INFORMATION Basic;
                    const LONGLONG *Times[4] = { &Basic.CreationTime.QuadPart, &Basic.LastAccessTime.QuadPart,
                                                 &Basic.LastWriteTime.QuadPart, &Basic.ChangeTime.QuadPart };
                    struct smb2_timeval *Tv[4] = { &Op->Set.Basic.creation_time, &Op->Set.Basic.last_access_time,
                                                   &Op->Set.Basic.last_write_time, &Op->Set.Basic.change_time };
                    int i;

                    if (r->Length < sizeof(Basic))
                    {
                        FailOp(Conn, Op, STATUS_INFO_LENGTH_MISMATCH);
                        return;
                    }
                    memcpy(&Basic, In, sizeof(Basic));
                    memset(&Op->Set.Basic, 0, sizeof(Op->Set.Basic));
                    for (i = 0; i < 4; i++)
                    {
                        /* 0 keeps, -1 stops updating (libsmb2's encoding of both) */
                        if (*Times[i] == 0)
                        {
                            Tv[i]->tv_sec = 0;
                            Tv[i]->tv_usec = 0;
                        }
                        else if (*Times[i] < 0)
                        {
                            Tv[i]->tv_sec = (time_t)0xffffffff;
                            Tv[i]->tv_usec = (long)0xffffffff;
                        }
                        else
                        {
                            smb2_win_to_timeval((uint64_t)*Times[i], Tv[i]);
                        }
                    }
                    Op->Set.Basic.file_attributes = Basic.FileAttributes;
                    req.input_data = &Op->Set.Basic;
                    break;
                }
                case SMB2_FILE_DISPOSITION_INFORMATION:
                    if (r->Length < 1)
                    {
                        FailOp(Conn, Op, STATUS_INFO_LENGTH_MISMATCH);
                        return;
                    }
                    Op->Set.Disposition.delete_pending = In[0] ? 1 : 0;
                    req.input_data = &Op->Set.Disposition;
                    break;
                case SMB2_FILE_END_OF_FILE_INFORMATION:
                {
                    LONGLONG Eof;

                    if (r->Length < sizeof(Eof))
                    {
                        FailOp(Conn, Op, STATUS_INFO_LENGTH_MISMATCH);
                        return;
                    }
                    memcpy(&Eof, In, sizeof(Eof));
                    if (Eof < 0)
                    {
                        FailOp(Conn, Op, STATUS_INVALID_PARAMETER);
                        return;
                    }
                    Op->Set.EndOfFile.end_of_file = (uint64_t)Eof;
                    req.input_data = &Op->Set.EndOfFile;
                    break;
                }
                default:
                    /* allocation: libsmb2 has no encoder for it (and rdbss does not send it yet) */
                    FailOp(Conn, Op, STATUS_NOT_SUPPORTED);
                    return;
            }
            /* libsmb2's own encoders (its passthrough encoder of SET_INFO is not usable) */
            smb2_set_passthrough(Conn->Smb2, 0);
            pdu = smb2_cmd_set_info_async(Conn->Smb2, &req, OpCb, Op);
            smb2_set_passthrough(Conn->Smb2, 1);
            Track(Conn, Op, pdu);
            return;
        }

        case SmbUpRename:
        {
            PSMBUP_RENAME_REQUEST r = (PSMBUP_RENAME_REQUEST)(h + 1);
            struct smb2_set_info_request req;
            struct smb2_pdu *pdu;
            const WCHAR *Name;
            ULONG Bytes;

            if (!SmbEngStringOf(h, FixedEnd, &r->NewName, &Name, &Bytes) || Bytes == 0)
            {
                FailOp(Conn, Op, STATUS_OBJECT_NAME_INVALID);
                return;
            }
            if (!(Op->Name = ToUtf8(Name, Bytes)))
            {
                FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
                return;
            }
            Op->Set.Rename.replace_if_exist = r->ReplaceIfExists ? 1 : 0;
            Op->Set.Rename.file_name = (const uint8_t *)Op->Name;
            memset(&req, 0, sizeof(req));
            req.info_type = SMB2_0_INFO_FILE;
            req.file_info_class = SMB2_FILE_RENAME_INFORMATION;
            req.input_data = &Op->Set.Rename;
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            smb2_set_passthrough(Conn->Smb2, 0);
            pdu = smb2_cmd_set_info_async(Conn->Smb2, &req, OpCb, Op);
            smb2_set_passthrough(Conn->Smb2, 1);
            Track(Conn, Op, pdu);
            return;
        }

        case SmbUpQueryDirectory:
        {
            PSMBUP_DIRECTORY_REQUEST r = (PSMBUP_DIRECTORY_REQUEST)(h + 1);
            struct smb2_query_directory_request req;
            const WCHAR *Pattern;
            ULONG Bytes;

            if (!SmbEngStringOf(h, FixedEnd, &r->Pattern, &Pattern, &Bytes) ||
                r->OutputLength > SMBUP_MAX_INFO || r->OutputLength == 0 || r->InformationClass > 0xFF)
            {
                FailOp(Conn, Op, STATUS_INVALID_PARAMETER);
                return;
            }
            Op->Name = Bytes ? ToUtf8(Pattern, Bytes) : _strdup("*");
            if (Op->Name == NULL || !AllocReply(Op, DATA_OFFSET + r->OutputLength))
            {
                FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
                return;
            }
            Op->DataOffset = DATA_OFFSET;
            Op->DataMax = r->OutputLength;
            memset(&req, 0, sizeof(req));
            req.file_information_class = (uint8_t)r->InformationClass;
            req.flags = (r->Flags & SMBUP_DIR_RESTART_SCANS ? SMB2_RESTART_SCANS : 0) |
                        (r->Flags & SMBUP_DIR_RETURN_SINGLE_ENTRY ? SMB2_RETURN_SINGLE_ENTRY : 0) |
                        (r->Flags & SMBUP_DIR_INDEX_SPECIFIED ? SMB2_INDEX_SPECIFIED : 0);
            req.file_index = r->FileIndex;
            req.output_buffer_length = r->OutputLength;
            req.name = Op->Name;
            memcpy(req.file_id, File->FileId, SMB2_FD_SIZE);
            Track(Conn, Op, smb2_cmd_query_directory_async(Conn->Smb2, &req, OpCb, Op));
            return;
        }

        default:
            FailOp(Conn, Op, STATUS_NOT_SUPPORTED);
            return;
    }
}

/* libsmb2 decodes some information classes even in passthrough mode: back to the NT layout */
static
NTSTATUS
EncodeInfo(PSMBENG_OP Op, const struct smb2_query_info_reply *qr, PULONG Length)
{
    PSMBUP_QUERY_REQUEST r = (PSMBUP_QUERY_REQUEST)(Op->Request + 1);
    PUCHAR Out = Op->Reply + Op->DataOffset;
    ULONG Room = Op->ReplyAlloc - Op->DataOffset;       /* SMBUP_MAX_INFO */
    ULONG Len = 0;

    if (qr->output_buffer == NULL)
        return STATUS_INVALID_NETWORK_RESPONSE;

    if (Op->Opcode == SmbUpQueryInfo)
    {
        switch (r->InformationClass)
        {
            case SMB2_FILE_BASIC_INFORMATION:
            {
                const struct smb2_file_basic_info *i = qr->output_buffer;
                FILE_BASIC_INFORMATION o;

                memset(&o, 0, sizeof(o));
                o.CreationTime.QuadPart = (LONGLONG)i->creation_time_raw;
                o.LastAccessTime.QuadPart = (LONGLONG)i->last_access_time_raw;
                o.LastWriteTime.QuadPart = (LONGLONG)i->last_write_time_raw;
                o.ChangeTime.QuadPart = (LONGLONG)i->change_time_raw;
                o.FileAttributes = i->file_attributes;
                memcpy(Out, &o, sizeof(o));
                Len = sizeof(o);
                break;
            }
            case SMB2_FILE_STANDARD_INFORMATION:
            {
                const struct smb2_file_standard_info *i = qr->output_buffer;
                FILE_STANDARD_INFORMATION o;

                memset(&o, 0, sizeof(o));
                o.AllocationSize.QuadPart = (LONGLONG)i->allocation_size;
                o.EndOfFile.QuadPart = (LONGLONG)i->end_of_file;
                o.NumberOfLinks = i->number_of_links;
                o.DeletePending = i->delete_pending ? TRUE : FALSE;
                o.Directory = i->directory ? TRUE : FALSE;
                memcpy(Out, &o, sizeof(o));
                Len = sizeof(o);
                break;
            }
            case SMB2_FILE_NETWORK_OPEN_INFORMATION:
            {
                const struct smb2_file_network_open_info *i = qr->output_buffer;
                FILE_NETWORK_OPEN_INFORMATION o;

                memset(&o, 0, sizeof(o));
                o.CreationTime.QuadPart = (LONGLONG)smb2_timeval_to_win((struct smb2_timeval *)&i->creation_time);
                o.LastAccessTime.QuadPart = (LONGLONG)smb2_timeval_to_win((struct smb2_timeval *)&i->last_access_time);
                o.LastWriteTime.QuadPart = (LONGLONG)smb2_timeval_to_win((struct smb2_timeval *)&i->last_write_time);
                o.ChangeTime.QuadPart = (LONGLONG)smb2_timeval_to_win((struct smb2_timeval *)&i->change_time);
                o.AllocationSize.QuadPart = (LONGLONG)i->allocation_size;
                o.EndOfFile.QuadPart = (LONGLONG)i->end_of_file;
                o.FileAttributes = i->file_attributes;
                memcpy(Out, &o, sizeof(o));
                Len = sizeof(o);
                break;
            }
            case SMB2_FILE_ATTRIBUTE_TAG_INFORMATION:
            {
                const struct smb2_file_attribute_tag_info *i = qr->output_buffer;
                FILE_ATTRIBUTE_TAG_INFORMATION o;

                o.FileAttributes = i->file_attributes;
                o.ReparseTag = i->reparse_tag;
                memcpy(Out, &o, sizeof(o));
                Len = sizeof(o);
                break;
            }
            case SMB2_FILE_STREAM_INFORMATION:
            {
                /* libsmb2 decodes the chain into an array whose last entry has next_entry_offset 0 */
                const struct smb2_file_stream_info *i = qr->output_buffer;
                ULONG Pos = 0, Prev = MAXULONG;

                for (;;)
                {
                    FILE_STREAM_INFORMATION *o = (FILE_STREAM_INFORMATION *)(Out + Pos);
                    ULONG Fixed = FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName);

                    if (Pos + Fixed > r->OutputLength || Pos + Fixed > Room)
                    {
                        Len = r->OutputLength + 1;  /* more than fits: overflow */
                        break;
                    }
                    memset(o, 0, Fixed);
                    o->StreamSize.QuadPart = (LONGLONG)i->stream_size;
                    o->StreamAllocationSize.QuadPart = (LONGLONG)i->stream_allocation_size;
                    o->StreamNameLength = 2 * ToUtf16(i->stream_name, o->StreamName, (Room - Pos - Fixed) / 2);
                    if (Prev != MAXULONG)
                        ((FILE_STREAM_INFORMATION *)(Out + Prev))->NextEntryOffset = Pos - Prev;
                    Prev = Pos;
                    Len = Pos + Fixed + o->StreamNameLength;
                    Pos = ALIGN8(Len);
                    if (i->next_entry_offset == 0 || Pos >= Room)
                        break;
                    i++;
                }
                break;
            }
            case SMB2_FILE_ALL_INFORMATION:
            case SMB2_FILE_NORMALIZED_NAME_INFORMATION:
            case SMB2_FILE_POSITION_INFORMATION:
            case SMB2_FILE_PIPE_INFORMATION:
            case SMB2_FILE_PIPE_LOCAL_INFORMATION:
            case SMB2_FILE_PIPE_REMOTE_INFORMATION:
                /* decoded by libsmb2 into its own structures; not asked by the driver */
                return STATUS_NOT_SUPPORTED;
            default:
                Len = min(qr->output_buffer_length, Room);
                memcpy(Out, qr->output_buffer, Len);
                break;
        }
    }
    else
    {
        switch (r->InformationClass)
        {
            case SMB2_FILE_FS_VOLUME_INFORMATION:
            {
                const struct smb2_file_fs_volume_info *i = qr->output_buffer;
                FILE_FS_VOLUME_INFORMATION *o = (FILE_FS_VOLUME_INFORMATION *)Out;
                ULONG Chars = (Room - FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel)) / 2;

                memset(o, 0, sizeof(*o));
                o->VolumeCreationTime.QuadPart = (LONGLONG)smb2_timeval_to_win((struct smb2_timeval *)&i->creation_time);
                o->VolumeSerialNumber = i->volume_serial_number;
                o->SupportsObjects = i->supports_objects ? TRUE : FALSE;
                o->VolumeLabelLength = 2 * ToUtf16((const char *)i->volume_label, o->VolumeLabel, Chars);
                Len = FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + o->VolumeLabelLength;
                break;
            }
            case SMB2_FILE_FS_SIZE_INFORMATION:
            {
                const struct smb2_file_fs_size_info *i = qr->output_buffer;
                FILE_FS_SIZE_INFORMATION o;

                o.TotalAllocationUnits.QuadPart = (LONGLONG)i->total_allocation_units;
                o.AvailableAllocationUnits.QuadPart = (LONGLONG)i->available_allocation_units;
                o.SectorsPerAllocationUnit = i->sectors_per_allocation_unit;
                o.BytesPerSector = i->bytes_per_sector;
                memcpy(Out, &o, sizeof(o));
                Len = sizeof(o);
                break;
            }
            case SMB2_FILE_FS_ATTRIBUTE_INFORMATION:
            {
                const struct smb2_file_fs_attribute_info *i = qr->output_buffer;
                FILE_FS_ATTRIBUTE_INFORMATION *o = (FILE_FS_ATTRIBUTE_INFORMATION *)Out;
                ULONG Chars = (Room - FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName)) / 2;

                o->FileSystemAttributes = i->filesystem_attributes;
                o->MaximumComponentNameLength = i->maximum_component_name_length;
                o->FileSystemNameLength = 2 * ToUtf16((const char *)i->filesystem_name, o->FileSystemName, Chars);
                Len = FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + o->FileSystemNameLength;
                break;
            }
            case SMB2_FILE_FS_FULL_SIZE_INFORMATION:
            {
                const struct smb2_file_fs_full_size_info *i = qr->output_buffer;
                FILE_FS_FULL_SIZE_INFORMATION o;

                o.TotalAllocationUnits.QuadPart = (LONGLONG)i->total_allocation_units;
                o.CallerAvailableAllocationUnits.QuadPart = (LONGLONG)i->caller_available_allocation_units;
                o.ActualAvailableAllocationUnits.QuadPart = (LONGLONG)i->actual_available_allocation_units;
                o.SectorsPerAllocationUnit = i->sectors_per_allocation_unit;
                o.BytesPerSector = i->bytes_per_sector;
                memcpy(Out, &o, sizeof(o));
                Len = sizeof(o);
                break;
            }
            case SMB2_FILE_FS_DEVICE_INFORMATION:
            case SMB2_FILE_FS_CONTROL_INFORMATION:
            case SMB2_FILE_FS_OBJECT_ID_INFORMATION:
            case SMB2_FILE_FS_SECTOR_SIZE_INFORMATION:
                /* decoded by libsmb2 into its own structures; not asked by the driver */
                return STATUS_NOT_SUPPORTED;
            default:
                Len = min(qr->output_buffer_length, Room);
                memcpy(Out, qr->output_buffer, Len);
                break;
        }
    }

    if (Len > r->OutputLength)
    {
        *Length = r->OutputLength;
        return STATUS_BUFFER_OVERFLOW;
    }
    *Length = Len;
    return STATUS_SUCCESS;
}

/*
 * Whether libsmb2 passed a reply of this status to the callback as an ERROR response
 * (struct smb2_error_reply, smb2_is_error_response in lib/pdu.c) rather than as the
 * command's own reply structure. Local statuses (shutdown, time-out) come without data.
 */
static
BOOLEAN
ErrorReply(uint32_t Wire)
{
    if ((Wire & 0xC0000000) == 0xC0000000)
        return Wire != (uint32_t)STATUS_MORE_PROCESSING_REQUIRED;
    return Wire == (uint32_t)STATUS_STOPPED_ON_SYMLINK;
}

/* Every request libsmb2 had ends here (also at teardown: SHUTDOWN) */
static
VOID
OpCb(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    PSMBENG_OP Op = private_data;
    PSMBENG_CONN Conn = Op->Conn;
    uint32_t Wire = (uint32_t)status;
    PSMBUP_DATA_REPLY Data;
    NTSTATUS Status;
    ULONG Length = 0;

    /* Passthrough mode reports an interim response too: the final one follows */
    if (Wire == SMB2_STATUS_PENDING)
        return;

    RemoveEntryList(&Op->Link);
    Conn->InFlightCount--;
    Op->Pdu = NULL;
    Conn->LastActivity = GetTickCount();

    if (Wire == SMB2_STATUS_SHUTDOWN)
        Status = STATUS_CONNECTION_DISCONNECTED;
    else
        Status = SmbEngMapStatus(Op->Opcode, Wire);

    /* A request that timed out, or a session/tree the server ended: this connection is
     * not usable any more (libsmb2 has no session reconnect); the next CREATE makes a new one */
    if (Wire == (uint32_t)STATUS_IO_TIMEOUT || Wire == (uint32_t)STATUS_USER_SESSION_DELETED ||
        Wire == (uint32_t)STATUS_NETWORK_NAME_DELETED || Wire == (uint32_t)STATUS_NETWORK_SESSION_EXPIRED)
    {
        if (Conn->Smb2 != NULL)
            Conn->Dead = TRUE;
        if (Wire != (uint32_t)STATUS_IO_TIMEOUT)
            Status = STATUS_CONNECTION_DISCONNECTED;
    }

    if (Op->Internal)
    {
        if (Op->File != NULL)
            FreeFile(Conn, Op->File);
        Op->File = NULL;
        SmbEngFreeOp(Op);
        return;
    }

    Data = Op->Reply ? (PSMBUP_DATA_REPLY)(Op->Reply + sizeof(SMBUP_HEADER)) : NULL;

    switch (Op->Opcode)
    {
        case SmbUpCreate:
        {
            const struct smb2_create_reply *cr = command_data;
            PSMBUP_CREATE_REPLY Rep = (PSMBUP_CREATE_REPLY)(Op->Reply + sizeof(SMBUP_HEADER));
            PSMBENG_FILE File;

            if (!NT_SUCCESS(Status))
                break;
            /* The binding ended (its DISCONNECT ran) while the CREATE was at the server: nobody
             * would ever close this handle, and an open file keeps the connection from idling */
            if (cr == NULL || Conn->Smb2 == NULL || !SmbEngBindingLive(Op->BindingId) ||
                (File = calloc(1, sizeof(*File))) == NULL)
            {
                Status = cr == NULL ? STATUS_INVALID_NETWORK_RESPONSE :
                         !SmbEngBindingLive(Op->BindingId) ? STATUS_CONNECTION_DISCONNECTED : STATUS_INSUFFICIENT_RESOURCES;
                if (cr != NULL && Conn->Smb2 != NULL)
                {
                    /* Opened at the server but we cannot keep it: close it again */
                    PSMBENG_FILE Tmp = calloc(1, sizeof(*Tmp));

                    if (Tmp != NULL)
                    {
                        InterlockedIncrement(&SmbEng.FilesLive);
                        memcpy(Tmp->FileId, cr->file_id, SMB2_FD_SIZE);
                        Tmp->Epoch = Conn->Epoch;
                        CloseOrphan(Conn, Tmp);
                    }
                }
                break;
            }
            InterlockedIncrement(&SmbEng.FilesLive);
            File->Id = SmbEngNewId();
            File->BindingId = Op->BindingId;
            File->Epoch = Conn->Epoch;
            memcpy(File->FileId, cr->file_id, SMB2_FD_SIZE);
            *FileSlot(Conn, File->Id) = File;
            Conn->FileCount++;
            Rep->FileId = File->Id;
            Rep->CreateAction = cr->create_action;
            Rep->Attributes.CreationTime = (LONGLONG)cr->creation_time;
            Rep->Attributes.LastAccessTime = (LONGLONG)cr->last_access_time;
            Rep->Attributes.LastWriteTime = (LONGLONG)cr->last_write_time;
            Rep->Attributes.ChangeTime = (LONGLONG)cr->change_time;
            Rep->Attributes.AllocationSize = (LONGLONG)cr->allocation_size;
            Rep->Attributes.EndOfFile = (LONGLONG)cr->end_of_file;
            Rep->Attributes.FileAttributes = cr->file_attributes;
            break;
        }

        case SmbUpClose:
            if (Op->File != NULL)
                FreeFile(Conn, Op->File);
            Op->File = NULL;
            /* The handle is gone either way */
            if (Status == STATUS_CONNECTION_DISCONNECTED || Status == STATUS_FILE_CLOSED)
                Status = STATUS_SUCCESS;
            break;

        case SmbUpRead:
            if (!NT_SUCCESS(Status))
                break;
            if (command_data == NULL ||
                ((const struct smb2_read_reply *)command_data)->data_length > Op->DataMax)
            {
                Status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }
            Data->Length = ((const struct smb2_read_reply *)command_data)->data_length;
            Data->DataOffset = Op->DataOffset;
            Op->ReplySize = Op->DataOffset + Data->Length;
            break;

        case SmbUpWrite:
            if (!NT_SUCCESS(Status))
                break;
            if (command_data == NULL || ((const struct smb2_write_reply *)command_data)->count > Op->DataMax)
            {
                Status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }
            Data->Length = ((const struct smb2_write_reply *)command_data)->count;
            break;

        case SmbUpQueryInfo:
        case SmbUpQueryVolume:
        {
            const struct smb2_query_info_reply *qr = command_data;

            if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
            {
                if (qr == NULL)
                    Status = STATUS_INVALID_NETWORK_RESPONSE;
                else
                {
                    Status = EncodeInfo(Op, qr, &Length);
                    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
                    {
                        Data->Length = Length;
                        Data->DataOffset = Op->DataOffset;
                        Op->ReplySize = Op->DataOffset + Length;
                    }
                }
            }
            /* An error reply's command_data is libsmb2's struct smb2_error_reply, not a query
             * reply: its error_data (same offset as output_buffer) points into the receive
             * buffer when the server sent error data, and is not ours to free. Only a reply
             * libsmb2 decoded as QUERY_INFO (success, a warning but STOPPED_ON_SYMLINK,
             * MORE_PROCESSING_REQUIRED) carries an output buffer it allocated. */
            if (qr != NULL && qr->output_buffer != NULL && !ErrorReply(Wire))
                smb2_free_data(smb2, qr->output_buffer);
            break;
        }

        case SmbUpQueryDirectory:
        {
            const struct smb2_query_directory_reply *qr = command_data;

            if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
                break;
            if (qr == NULL || qr->output_buffer_length > Op->DataMax ||
                (qr->output_buffer == NULL && qr->output_buffer_length != 0))
            {
                Status = STATUS_INVALID_NETWORK_RESPONSE;
                break;
            }
            /* The server's entries as they came; the driver checks the chain */
            if (qr->output_buffer_length)
                memcpy(Op->Reply + Op->DataOffset, qr->output_buffer, qr->output_buffer_length);
            Data->Length = qr->output_buffer_length;
            Data->DataOffset = Op->DataOffset;
            Op->ReplySize = Op->DataOffset + Data->Length;
            break;
        }

        default:
            break;
    }

    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW)
    {
        if (Op->Reply == NULL && !AllocReply(Op, sizeof(SMBUP_HEADER) + SMBUP_REPLY_FIXED_SIZE(Op->Opcode)))
        {
            FailOp(Conn, Op, STATUS_INSUFFICIENT_RESOURCES);
            return;
        }
        SendBuiltReply(Conn, Op, Status);
    }
    else
    {
        FailOp(Conn, Op, Status);
    }
}

static
VOID
CancelCb(struct smb2_context *smb2, int status, void *command_data, void *private_data)
{
    UNREFERENCED_PARAMETER(smb2);
    UNREFERENCED_PARAMETER(status);
    UNREFERENCED_PARAMETER(command_data);
    UNREFERENCED_PARAMETER(private_data);
}

/* Requests from the queue ***************************************************/

static
PSMBENG_OP
FindOp(PLIST_ENTRY List, ULONGLONG RequestId)
{
    PLIST_ENTRY Entry;

    for (Entry = List->Flink; Entry != List; Entry = Entry->Flink)
    {
        PSMBENG_OP Op = CONTAINING_RECORD(Entry, SMBENG_OP, Link);

        if (!Op->Internal && Op->Request != NULL && Op->Request->RequestId == RequestId)
            return Op;
    }
    return NULL;
}

static
VOID
ConnTake(PSMBENG_CONN Conn, PSMBENG_OP Op, BOOLEAN FromBacklog)
{
    PSMBENG_FILE File;

    switch (Op->Opcode)
    {
        case SmbUpLogoff:
            /* The logon session ended: its connection and token go, nothing more for this key */
            SmbEngFreeOp(Op);
            Conn->State = ConnLoggedOff;
            TearDown(Conn, STATUS_USER_SESSION_DELETED, ERROR_NETNAME_DELETED);
            if (Conn->Token != NULL)
            {
                CloseHandle(Conn->Token);
                Conn->Token = NULL;
            }
            FailPending(Conn, STATUS_USER_SESSION_DELETED, ERROR_NETNAME_DELETED);
            while (!IsListEmpty(&Conn->Backlog))
                FailOp(Conn, CONTAINING_RECORD(RemoveHeadList(&Conn->Backlog), SMBENG_OP, Link), STATUS_USER_SESSION_DELETED);
            return;

        case SmbUpCancel:
        {
            ULONGLONG Id = ((PSMBUP_CANCEL_REQUEST)(Op->Request + 1))->RequestId;
            PSMBENG_OP Target;

            SmbEngFreeOp(Op);
            /* Not sent yet: drop it (the driver answered its caller already) */
            if ((Target = FindOp(&Conn->Pending, Id)) != NULL || (Target = FindOp(&Conn->Backlog, Id)) != NULL)
            {
                RemoveEntryList(&Target->Link);
                if (Target->Opcode == SmbUpConnect)
                    SmbEngRemoveBinding(Target->BindingId, Target);
                SmbEngFreeOp(Target);
                return;
            }
            /* At the server: ask it to give up (its reply still comes, and is dropped by the driver) */
            if ((Target = FindOp(&Conn->InFlight, Id)) != NULL && !Target->Cancelled)
            {
                Target->Cancelled = TRUE;
                if (Target->Pdu != NULL && Conn->Smb2 != NULL)
                {
                    struct smb2_pdu *pdu = smb2_cmd_cancel_async(Conn->Smb2,
                                                                 smb2_get_pdu_message_id(Conn->Smb2, Target->Pdu),
                                                                 CancelCb, NULL);
                    if (pdu != NULL)
                        smb2_queue_pdu(Conn->Smb2, pdu);
                }
            }
            return;
        }

        case SmbUpConnect:
            /* The newest token of this logon session is the one to (re)connect with */
            if (Op->Token != NULL)
            {
                if (Conn->Token != NULL)
                    CloseHandle(Conn->Token);
                Conn->Token = Op->Token;
                Op->Token = NULL;
            }
            /* A new identity or password for this key: a new session, not the old one (only while
             * no file of the key is open: those belong to the old session) */
            if (Conn->Reauth && Conn->State == ConnUp && Conn->FileCount == 0 && Conn->InFlightCount == 0)
            {
                InterlockedExchange(&Conn->Reauth, 0);
                TearDown(Conn, STATUS_SUCCESS, 0);
            }
            if (Conn->State == ConnLoggedOff)
                FailOp(Conn, Op, STATUS_USER_SESSION_DELETED);
            else if (Conn->State == ConnUp && Conn->Smb2 != NULL)
                AnswerConnect(Conn, Op);
            else
                InsertTailList(&Conn->Pending, &Op->Link);
            return;

        case SmbUpDisconnect:
        {
            ULONG i;

            /* The binding's files end with it */
            for (i = 0; i < SMBENG_FILE_BUCKETS; i++)
            {
                PSMBENG_FILE *Slot = &Conn->Files[i];

                while (*Slot != NULL)
                {
                    File = *Slot;
                    if (File->BindingId != Op->BindingId)
                    {
                        Slot = &File->Next;
                        continue;
                    }
                    *Slot = File->Next;
                    File->Next = NULL;
                    Conn->FileCount--;
                    CloseOrphan(Conn, File);
                }
            }
            SmbEngLog(2, "binding %I64x of %S\\%S disconnected", Op->BindingId, Conn->Server, Conn->Share);
            SmbEngAnswerOp(Op, STATUS_SUCCESS, Conn->ReplyEvent);
            return;
        }

        default:
            break;
    }

    if (Conn->State == ConnLoggedOff)
    {
        FailOp(Conn, Op, STATUS_USER_SESSION_DELETED);
        return;
    }

    /* Bounded work at the server per connection; the rest waits in order */
    if ((!FromBacklog && !IsListEmpty(&Conn->Backlog)) ||
        (Conn->State == ConnUp && Conn->InFlightCount >= MAX_IN_FLIGHT))
    {
        if (FromBacklog)
            InsertHeadList(&Conn->Backlog, &Op->Link);
        else
            InsertTailList(&Conn->Backlog, &Op->Link);
        return;
    }

    if (Op->Opcode == SmbUpCreate)
    {
        if (Conn->State == ConnUp && Conn->Smb2 != NULL)
            IssueCreate(Conn, Op);
        else
            InsertTailList(&Conn->Pending, &Op->Link);
        return;
    }

    /* A request on an open file: the file of this binding, of the current session */
    {
        ULONGLONG FileId = ((const ULONGLONG UNALIGNED *)(Op->Request + 1))[1];

        File = *FileSlot(Conn, FileId);
        if (File == NULL || FileId == 0 || File->BindingId != Op->BindingId)
        {
            FailOp(Conn, Op, STATUS_INVALID_HANDLE);
            return;
        }
        if (!FileIsLive(Conn, File))
        {
            /* Opened on a connection that is gone: no reconnect for it (no durable handles) */
            if (Op->Opcode == SmbUpClose)
            {
                FreeFile(Conn, UnlinkFile(Conn, FileId));
                SmbEngAnswerOp(Op, STATUS_SUCCESS, Conn->ReplyEvent);
            }
            else
            {
                FailOp(Conn, Op, STATUS_CONNECTION_DISCONNECTED);
            }
            return;
        }
        Op->File = File;
        IssueHandleOp(Conn, Op);
    }
}

/* The thread ****************************************************************/

/* Leaves the table if nothing refers to this connection any more (or on stop) */
static
BOOLEAN
TryLeave(PSMBENG_CONN Conn, BOOLEAN Stop)
{
    BOOLEAN Empty;
    ULONG i;

    if (!Stop && (!IsListEmpty(&Conn->Pending) || !IsListEmpty(&Conn->Backlog) || Conn->InFlightCount != 0))
        return FALSE;

    AcquireSRWLockExclusive(&SmbEng.Lock);
    EnterCriticalSection(&Conn->QueueLock);
    Empty = IsListEmpty(&Conn->Queue);
    LeaveCriticalSection(&Conn->QueueLock);
    if (!Stop && (Conn->Bindings != 0 || !Empty))
    {
        ReleaseSRWLockExclusive(&SmbEng.Lock);
        return FALSE;
    }
    Conn->Closing = TRUE;
    RemoveEntryList(&Conn->Link);
    SmbEng.ConnCount--;
    if (Conn->Bindings != 0)
    {
        /* Stopping: the bindings go with the connection */
        for (i = 0; i < SMBENG_BINDING_BUCKETS; i++)
        {
            PSMBENG_BINDING *Slot = &SmbEng.Bindings[i];

            while (*Slot != NULL)
            {
                PSMBENG_BINDING Binding = *Slot;

                if (Binding->Conn != Conn)
                {
                    Slot = &Binding->Next;
                    continue;
                }
                *Slot = Binding->Next;
                SmbEng.BindingCount--;
                free(Binding);
            }
        }
        Conn->Bindings = 0;
        Conn->Shared = NULL;
    }
    ReleaseSRWLockExclusive(&SmbEng.Lock);
    return TRUE;
}

static
VOID
FreeConn(PSMBENG_CONN Conn)
{
    ULONG i;

    /* Nothing can queue any more (Closing, out of the table): answer what is left */
    while (!IsListEmpty(&Conn->Queue))
    {
        PSMBENG_OP Op = CONTAINING_RECORD(RemoveHeadList(&Conn->Queue), SMBENG_OP, Link);

        if (Op->Internal)
            SmbEngFreeOp(Op);
        else
            FailOp(Conn, Op, STATUS_CONNECTION_DISCONNECTED);
    }
    TearDown(Conn, STATUS_CONNECTION_DISCONNECTED, ERROR_NETNAME_DELETED);
    FailPending(Conn, STATUS_CONNECTION_DISCONNECTED, ERROR_NETNAME_DELETED);
    while (!IsListEmpty(&Conn->Backlog))
        FailOp(Conn, CONTAINING_RECORD(RemoveHeadList(&Conn->Backlog), SMBENG_OP, Link), STATUS_CONNECTION_DISCONNECTED);
    for (i = 0; i < SMBENG_FILE_BUCKETS; i++)
    {
        while (Conn->Files[i] != NULL)
        {
            PSMBENG_FILE File = Conn->Files[i];

            Conn->Files[i] = File->Next;
            FreeFile(Conn, File);
        }
    }
    SmbEngLog(1, "connection %S\\%S logon %08lx:%08lx ended", Conn->Server, Conn->Share,
              Conn->LogonId.HighPart, Conn->LogonId.LowPart);
    if (Conn->Token != NULL)
        CloseHandle(Conn->Token);
    if (Conn->WakeSocket != INVALID_SOCKET)
        closesocket(Conn->WakeSocket);
    if (Conn->ReplyEvent != NULL)
        CloseHandle(Conn->ReplyEvent);
    if (Conn->Thread != NULL)
        CloseHandle(Conn->Thread);
    SmbEngFreeCredentials(Conn);
    DeleteCriticalSection(&Conn->QueueLock);
    free(Conn->Server);
    free(Conn->Share);
    free(Conn->ServerA);
    free(Conn->ShareA);
    free(Conn);
}

static
VOID
Poll(PSMBENG_CONN Conn)
{
    WSAPOLLFD Fds[2];
    ULONG n = 0, SmbIndex = MAXULONG, WakeIndex = MAXULONG;
    int Rc, Revents = 0;
    char Drain[64];

    if (Conn->Smb2 != NULL)
    {
        t_socket Fd = smb2_get_fd(Conn->Smb2);

        if (Fd != INVALID_SOCKET)
        {
            Fds[n].fd = Fd;
            Fds[n].events = (SHORT)smb2_which_events(Conn->Smb2);
            Fds[n].revents = 0;
            SmbIndex = n++;
        }
        else if (Conn->State == ConnUp)
        {
            /* libsmb2 closed the socket itself (e.g. a reply that failed its signature check) */
            Conn->Dead = TRUE;
            return;
        }
    }
    if (Conn->WakeSocket != INVALID_SOCKET)
    {
        Fds[n].fd = Conn->WakeSocket;
        Fds[n].events = POLLIN;
        Fds[n].revents = 0;
        WakeIndex = n++;
    }

    if (n == 0)
    {
        Sleep(20);
        Rc = 0;
    }
    else
    {
        Rc = WSAPoll(Fds, n, Conn->WakeSocket != INVALID_SOCKET ? 1000 : 20);
    }
    if (Rc < 0)
    {
        SmbEngLog(1, "poll failed %d", WSAGetLastError());
        if (Conn->Smb2 != NULL)
            Conn->Dead = TRUE;
        Sleep(20);
        return;
    }
    if (WakeIndex != MAXULONG && (Fds[WakeIndex].revents & POLLIN))
    {
        while (recv(Conn->WakeSocket, Drain, sizeof(Drain), 0) > 0)
            ;
    }
    if (Conn->Smb2 != NULL)
    {
        if (SmbIndex != MAXULONG && Rc > 0)
            Revents = Fds[SmbIndex].revents;
        /* Also without events: libsmb2 checks its request timeouts in smb2_service */
        if (smb2_service(Conn->Smb2, Revents) < 0)
        {
            if (Conn->Smb2 != NULL && !Conn->Dead)
                SmbEngLog(1, "connection %S\\%S lost: %s", Conn->Server, Conn->Share, smb2_get_error(Conn->Smb2));
            if (Conn->Smb2 != NULL)
                Conn->Dead = TRUE;
        }
    }
}

static
DWORD
WINAPI
ConnThread(LPVOID Parameter)
{
    PSMBENG_CONN Conn = Parameter;
    BOOLEAN Stop = FALSE;

    for (;;)
    {
        LIST_ENTRY Work;
        DWORD Now;

        InitializeListHead(&Work);
        EnterCriticalSection(&Conn->QueueLock);
        if (!IsListEmpty(&Conn->Queue))
        {
            Work = Conn->Queue;
            Work.Flink->Blink = &Work;
            Work.Blink->Flink = &Work;
            InitializeListHead(&Conn->Queue);
        }
        Stop = Conn->StopRequested;
        LeaveCriticalSection(&Conn->QueueLock);

        while (!IsListEmpty(&Work))
            ConnTake(Conn, CONTAINING_RECORD(RemoveHeadList(&Work), SMBENG_OP, Link), FALSE);

        if (Conn->Dead)
            TearDown(Conn, STATUS_CONNECTION_DISCONNECTED, ERROR_NETNAME_DELETED);
        if (Stop)
            break;

        /* Work the bounded backlog */
        while (!IsListEmpty(&Conn->Backlog) && (Conn->State != ConnUp || Conn->InFlightCount < MAX_IN_FLIGHT))
            ConnTake(Conn, CONTAINING_RECORD(RemoveHeadList(&Conn->Backlog), SMBENG_OP, Link), TRUE);

        Now = GetTickCount();
        if (Conn->State == ConnDown && !IsListEmpty(&Conn->Pending))
        {
            /* New credentials (a user typing the password again) end the back-off of a failed connect */
            if (Conn->CredentialsChanged && Conn->Backoff != 0)
                Conn->Backoff = 0;
            if (Conn->QuickRetries != 0 && !TimeReached(Now, Conn->RetryTick, 300))
                ;   /* a quick retry is due shortly (the poll below wakes in time) */
            else if (Conn->Backoff != 0 && !TimeReached(Now, Conn->FailTick, Conn->Backoff * 1000))
                FailPending(Conn, Conn->LastConnectStatus, Conn->LastConnectWin32);
            else
                ConnStart(Conn);
        }
        if (Conn->State == ConnConnecting &&
            TimeReached(Now, Conn->ConnectStart, SmbEngConfig.RequestTimeoutSeconds * 1000))
        {
            TearDown(Conn, STATUS_BAD_NETWORK_PATH, ERROR_BAD_NETPATH);
        }

        /* Idle: no open file, nothing at the server, nothing waiting. A key with explicit
         * credentials that the driver no longer holds (net use /delete, the last use gone) is not
         * kept for the idle time: its session, the credentials acquired for it and its password
         * go now (FreeConn wipes them when the key leaves below) */
        if (Conn->State == ConnUp && Conn->FileCount == 0 && Conn->InFlightCount == 0 &&
            IsListEmpty(&Conn->Pending) && IsListEmpty(&Conn->Backlog) &&
            (TimeReached(Now, Conn->LastActivity, SmbEngConfig.IdleSeconds * 1000) ||
             (Conn->Explicit && *(volatile LONG *)&Conn->Bindings == 0)))
        {
            SmbEngLog(1, "connection %S\\%S %s", Conn->Server, Conn->Share,
                      Conn->Explicit && *(volatile LONG *)&Conn->Bindings == 0 ? "with explicit credentials no longer held" : "idle");
            TearDown(Conn, STATUS_SUCCESS, 0);
        }
        /* A key in back-off stays (without bindings too), so that repeated CONNECTs fail at once
         * with the last status instead of each opening a new TCP connection */
        if (Conn->State != ConnUp && Conn->State != ConnConnecting && Conn->QuickRetries == 0 &&
            (Conn->Backoff == 0 || TimeReached(Now, Conn->FailTick, Conn->Backoff * 1000)) &&
            TryLeave(Conn, FALSE))
        {
            FreeConn(Conn);
            return 0;
        }

        Poll(Conn);
        if (Conn->Dead)
            TearDown(Conn, STATUS_CONNECTION_DISCONNECTED, ERROR_NETNAME_DELETED);
    }

    TryLeave(Conn, TRUE);
    FreeConn(Conn);
    return 0;
}

/* Creation, queueing, waking ************************************************/

VOID
SmbEngQueueOp(PSMBENG_CONN Conn, PSMBENG_OP Op)
{
    Op->Conn = Conn;
    EnterCriticalSection(&Conn->QueueLock);
    InsertTailList(&Conn->Queue, &Op->Link);
    LeaveCriticalSection(&Conn->QueueLock);
}

VOID
SmbEngWakeConn(PSMBENG_CONN Conn)
{
    if (Conn->WakeSocket != INVALID_SOCKET)
        sendto(Conn->WakeSocket, "w", 1, 0, (const struct sockaddr *)&Conn->WakeAddr, sizeof(Conn->WakeAddr));
}

static
WCHAR *
CopyName(const WCHAR *s, ULONG Bytes)
{
    WCHAR *Out = malloc(Bytes + sizeof(WCHAR));

    if (Out != NULL)
    {
        memcpy(Out, s, Bytes);
        Out[Bytes / 2] = 0;
    }
    return Out;
}

/* \\2001-db8--1.ipv6-literal.net\share: the address, for libsmb2, as [2001:db8::1] */
static
char *
ServerForLibsmb2(const WCHAR *Server)
{
    static const char Suffix[] = ".ipv6-literal.net";
    char *s = ToUtf8(Server, (ULONG)wcslen(Server) * sizeof(WCHAR)), *Lit;
    size_t n, i, k = 0, sl = sizeof(Suffix) - 1;

    if (s == NULL)
        return NULL;
    n = strlen(s);
    if (n <= sl || _stricmp(s + n - sl, Suffix) != 0)
        return s;
    Lit = malloc(n + 3);
    if (Lit == NULL)
    {
        free(s);
        return NULL;
    }
    Lit[k++] = '[';
    for (i = 0; i < n - sl; i++)
        Lit[k++] = s[i] == '-' ? ':' : (s[i] == 's' || s[i] == 'S') ? '%' : s[i];
    Lit[k++] = ']';
    Lit[k] = 0;
    free(s);
    return Lit;
}

/* Called with SmbEng.Lock held exclusively; the caller inserts it into the table */
PSMBENG_CONN
SmbEngCreateConn(const SMBUP_HEADER *Header, const WCHAR *Server, ULONG ServerBytes,
                 const WCHAR *Share, ULONG ShareBytes)
{
    PSMBENG_CONN Conn = calloc(1, sizeof(*Conn));
    int Len;

    if (Conn == NULL)
        return NULL;
    Conn->WakeSocket = INVALID_SOCKET;
    Conn->LogonId.LowPart = Header->LogonIdLow;
    Conn->LogonId.HighPart = Header->LogonIdHigh;
    InitializeCriticalSection(&Conn->QueueLock);
    InitializeListHead(&Conn->Queue);
    InitializeListHead(&Conn->Pending);
    InitializeListHead(&Conn->Backlog);
    InitializeListHead(&Conn->InFlight);
    Conn->State = ConnDown;
    Conn->Server = CopyName(Server, ServerBytes);
    Conn->Share = CopyName(Share, ShareBytes);
    Conn->ServerA = Conn->Server ? ServerForLibsmb2(Conn->Server) : NULL;
    Conn->ShareA = Conn->Share ? ToUtf8(Conn->Share, ShareBytes) : NULL;
    Conn->ReplyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!Conn->Server || !Conn->Share || !Conn->ServerA || !Conn->ShareA || !Conn->ReplyEvent)
        goto Fail;

    /* The wake-up socket: loopback UDP, non-blocking */
    Conn->WakeSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Conn->WakeSocket != INVALID_SOCKET)
    {
        u_long NonBlocking = 1;

        ZeroMemory(&Conn->WakeAddr, sizeof(Conn->WakeAddr));
        Conn->WakeAddr.sin_family = AF_INET;
        Conn->WakeAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        Len = sizeof(Conn->WakeAddr);
        if (bind(Conn->WakeSocket, (struct sockaddr *)&Conn->WakeAddr, sizeof(Conn->WakeAddr)) != 0 ||
            getsockname(Conn->WakeSocket, (struct sockaddr *)&Conn->WakeAddr, &Len) != 0 ||
            ioctlsocket(Conn->WakeSocket, FIONBIO, &NonBlocking) != 0)
        {
            SmbEngLog(0, "no wake-up socket (%d): polling", WSAGetLastError());
            closesocket(Conn->WakeSocket);
            Conn->WakeSocket = INVALID_SOCKET;
        }
        else
        {
            /* It must actually deliver (a filter could drop loopback datagrams): one byte to itself */
            WSAPOLLFD Fd;
            char Byte;

            Fd.fd = Conn->WakeSocket;
            Fd.events = POLLIN;
            Fd.revents = 0;
            if (sendto(Conn->WakeSocket, "t", 1, 0, (const struct sockaddr *)&Conn->WakeAddr, sizeof(Conn->WakeAddr)) != 1 ||
                WSAPoll(&Fd, 1, 500) != 1 || recv(Conn->WakeSocket, &Byte, 1, 0) != 1)
            {
                SmbEngLog(0, "wake-up socket does not deliver (%d): polling", WSAGetLastError());
                closesocket(Conn->WakeSocket);
                Conn->WakeSocket = INVALID_SOCKET;
            }
        }
    }

    Conn->Thread = CreateThread(NULL, 0, ConnThread, Conn, 0, NULL);
    if (Conn->Thread == NULL)
        goto Fail;
    return Conn;

Fail:
    if (Conn->WakeSocket != INVALID_SOCKET)
        closesocket(Conn->WakeSocket);
    if (Conn->ReplyEvent)
        CloseHandle(Conn->ReplyEvent);
    DeleteCriticalSection(&Conn->QueueLock);
    free(Conn->Server);
    free(Conn->Share);
    free(Conn->ServerA);
    free(Conn->ShareA);
    free(Conn);
    return NULL;
}
