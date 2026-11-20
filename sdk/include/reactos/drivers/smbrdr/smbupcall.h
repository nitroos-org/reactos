/*
 * PROJECT:     NitroOS SMB redirector
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Upcall protocol between the SMB mini-redirector (mrxsmb.sys) and
 *              the user-mode SMB engine
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/*
 * The mini-redirector does not speak SMB. Every operation that needs the server
 * is sent as a request message to the user-mode engine, which answers with a
 * reply message. This header is the whole contract between the two; it carries
 * no SMB code and no third-party code.
 *
 * Channel. The engine opens \Device\NitroSmbEngine (NITRO_SMBRDR_ENGINE_DEVICE),
 * attaches with IOCTL_SMBRDR_ENGINE_ATTACH (one engine at a time; the caller
 * needs SeImpersonatePrivilege and the device admits SYSTEM, LocalService and
 * administrators only), then loops:
 *   IOCTL_SMBRDR_ENGINE_GET     (output: one request message, blocks until one is
 *                                queued, or the engine is detached; the wait is
 *                                alertable, so the thread can be terminated, but
 *                                CancelIoEx does not end it)
 *   IOCTL_SMBRDR_ENGINE_REPLY   (input: one reply message for a request it got)
 * Both are METHOD_BUFFERED: the I/O manager captures each message once, so a
 * message cannot change while the other side checks it.
 *
 * Trust. The engine parses network data and holds users' tokens; it is not
 * trusted by the driver. The driver checks every reply field (magic, version,
 * sizes, offsets, the opcode and request id of a request it sent, every length
 * against what it asked for, the structure of returned directory and
 * information buffers) and maps any status it does not accept to
 * STATUS_INVALID_NETWORK_RESPONSE. A malformed reply fails that one request; it
 * never reaches the caller's buffer unchecked. When the engine's handle is
 * closed (it exits or crashes), every queued and pending request completes with
 * STATUS_CONNECTION_DISCONNECTED; new requests fail with
 * STATUS_REDIRECTOR_NOT_STARTED until an engine attaches again. Each request has
 * a time limit (NITRO_SMBRDR_REQUEST_TIMEOUT_SECONDS): nothing waits forever. A
 * request sent for a caller's IRP also ends (STATUS_CANCELLED, with a CANCEL
 * notification) when that IRP is cancelled or its thread is terminating.
 * The engine likewise checks every request (it must not trust the sizes either:
 * a different driver build could be loaded).
 *
 * Identity. A CONNECT request carries a handle, valid in the engine's process,
 * to an impersonation token of the user who opened the share (impersonation
 * level SecurityImpersonation, access TOKEN_QUERY | TOKEN_IMPERSONATE only: the
 * engine can act as that user, it cannot change the token, raise its level or
 * make it primary). The engine closes it. Credentials given with the tree
 * connect (an EA from the network provider) are passed in the CONNECT payload
 * once and must be wiped by the engine after use. The logon id (LUID) of every
 * request is filled by the driver from the caller's token, never by the engine.
 *
 * Wire format. All integers are little endian, all structures naturally aligned
 * and of fixed size on 32 and 64 bit (no pointers, no SIZE_T). A message is
 * SMBUP_HEADER, the fixed part for its opcode, then variable data. Variable
 * data is addressed by (Offset, Length) pairs relative to the start of the
 * message: Offset >= sizeof(SMBUP_HEADER) + sizeof(fixed part), Offset + Length
 * <= TotalSize, UTF-16 strings at even offsets, no terminating NUL counted.
 */

#ifndef _NITRO_SMBUPCALL_H_
#define _NITRO_SMBUPCALL_H_

#define NITRO_SMBRDR_ENGINE_DEVICE      L"\\Device\\NitroSmbEngine"
#define NITRO_SMBRDR_ENGINE_DOS_NAME    L"\\\\.\\GLOBALROOT\\Device\\NitroSmbEngine"
#define NITRO_SMBRDR_PROVIDER_NAME      L"\\Device\\LanmanRedirector"

#define SMBUP_MAGIC                     0x50554253UL    /* "SBUP" */
#define SMBUP_VERSION                   2       /* 2: explicit credentials, CONNECT reply flags */

/* Size limits, both sides */
#define SMBUP_MAX_IO                    (1024 * 1024)   /* READ/WRITE data per request */
#define SMBUP_MAX_INFO                  (64 * 1024)     /* query/set information data */
#define SMBUP_MAX_NAME_BYTES            (32767 * 2)     /* one UTF-16 path */
#define SMBUP_MAX_MESSAGE               (SMBUP_MAX_IO + 4096)
#define NITRO_SMBRDR_REQUEST_TIMEOUT_SECONDS  120

#define SMBUP_CTL_CODE(f, m) CTL_CODE(FILE_DEVICE_NETWORK_REDIRECTOR, 0xA00 | (f), (m), FILE_ANY_ACCESS)

#define IOCTL_SMBRDR_ENGINE_ATTACH      SMBUP_CTL_CODE(1, METHOD_BUFFERED)  /* in: SMBUP_ATTACH */
/* out: request message. Direct I/O: the message goes straight into the engine's buffer, so that no
 * kernel copy of a CONNECT (it may carry a password) is left in pool for the I/O manager to free */
#define IOCTL_SMBRDR_ENGINE_GET         SMBUP_CTL_CODE(2, METHOD_OUT_DIRECT)
#define IOCTL_SMBRDR_ENGINE_REPLY       SMBUP_CTL_CODE(3, METHOD_BUFFERED)  /* in: reply message */
#define IOCTL_SMBRDR_ENGINE_DETACH      SMBUP_CTL_CODE(4, METHOD_BUFFERED)

/* Opcodes (M1) */
typedef enum _SMBUP_OPCODE
{
    SmbUpInvalid = 0,
    SmbUpConnect = 1,           /* tree connect for (server, share, logon id) */
    SmbUpDisconnect = 2,        /* tree disconnect of a connection */
    SmbUpCreate = 3,
    SmbUpClose = 4,
    SmbUpRead = 5,
    SmbUpWrite = 6,
    SmbUpQueryInfo = 7,         /* file information class */
    SmbUpSetInfo = 8,           /* file information class (not rename) */
    SmbUpQueryDirectory = 9,
    SmbUpQueryVolume = 10,      /* fs information class */
    SmbUpFlush = 11,
    SmbUpRename = 12,
    SmbUpLock = 13,             /* M1: not sent; the engine answers STATUS_NOT_SUPPORTED */
    SmbUpLogoff = 14,           /* notification: the logon session ended, drop its connections */
    SmbUpCancel = 15,           /* notification: give up on RequestId (no reply) */
    SmbUpMaximumOpcode
} SMBUP_OPCODE;

/* SMBUP_HEADER.Flags */
#define SMBUP_FLAG_NOTIFICATION         0x00000001  /* request without a reply (LOGOFF, CANCEL) */
#define SMBUP_FLAG_PAGING_IO            0x00000002  /* READ/WRITE for the memory manager */

typedef struct _SMBUP_HEADER
{
    ULONG Magic;                /* SMBUP_MAGIC */
    USHORT Version;             /* SMBUP_VERSION */
    USHORT Opcode;              /* SMBUP_OPCODE; a reply repeats the request's */
    ULONG HeaderSize;           /* sizeof(SMBUP_HEADER) */
    ULONG TotalSize;            /* header + fixed part + variable data */
    ULONGLONG RequestId;        /* chosen by the driver, unique; a reply repeats it */
    ULONG LogonIdLow;           /* request: the caller's logon session (driver) */
    LONG LogonIdHigh;
    ULONG ProcessId;            /* request: the caller's process, for logs only */
    ULONG Flags;
    LONG Status;                /* reply: NTSTATUS of the operation */
    ULONG Win32Error;           /* reply to CONNECT: the Win32 code for a network provider (0 otherwise) */
} SMBUP_HEADER, *PSMBUP_HEADER;

typedef struct _SMBUP_ATTACH
{
    ULONG Magic;
    USHORT Version;             /* the engine's protocol version: must equal the driver's */
    USHORT Reserved;
    ULONG MaxMessageSize;       /* the engine's GET buffer size, >= SMBUP_MAX_MESSAGE */
    ULONG Reserved2;
} SMBUP_ATTACH, *PSMBUP_ATTACH;

typedef struct _SMBUP_STRING
{
    ULONG Offset;
    ULONG Length;               /* bytes */
} SMBUP_STRING, *PSMBUP_STRING;

/*
 * CONNECT
 *
 * Credentials. One logon session has one identity per server (as typed) at a time, as on
 * Windows (ERROR_SESSION_CREDENTIAL_CONFLICT, 1219):
 * - SMBUP_CONNECT_EXPLICIT_CREDENTIALS: UserName (non-empty), Domain (may be empty) and
 *   Password (may be empty) are the identity. If another connection of this logon session to
 *   the same server is in use with a different identity (single sign-on, or another user or
 *   domain), the answer is STATUS_NETWORK_CREDENTIAL_CONFLICT. The engine keeps the password
 *   (encrypted for its own process) while a connection of that identity lives, for reconnects,
 *   and wipes every other copy at once.
 * - SMBUP_CONNECT_REQUIRE_EXPLICIT (no strings): a reconnect of a connection that used explicit
 *   credentials; the engine uses those of a live connection of this logon session to the
 *   server, or fails with STATUS_LOGON_FAILURE (after an engine restart the password is gone:
 *   the user connects again). It never falls back to single sign-on.
 * - neither: the identity of a live connection of this logon session to the server if there
 *   is one (so a UNC open after "net use \\server\share /user:..." uses that user, as on
 *   Windows), else single sign-on.
 * The reply says in Flags which identity the connection got (SMBUP_CONNECT_REPLY_EXPLICIT).
 *
 * Measured on Windows Server 2022 as a client (evidence of ticket SMB-07), and so done here:
 * - the identity is held by "uses" (connections made by a tree connect: net use, a mapped drive),
 *   SMBUP_CONNECT_USE; a plain UNC open does not hold it (after "dir \\server\share" a "net use"
 *   with other credentials to that server succeeds);
 * - the same user with another password is another identity (1219);
 * - an explicit CONNECT for a key no driver connection holds any more is authenticated again
 *   (a wrong password right after "net use /delete" fails with 86, it does not reuse the session).
 */
#define SMBUP_CONNECT_EXPLICIT_CREDENTIALS 0x00000001
#define SMBUP_CONNECT_REQUIRE_EXPLICIT     0x00000002
#define SMBUP_CONNECT_USE                  0x00000004
typedef struct _SMBUP_CONNECT_REQUEST
{
    SMBUP_STRING Server;        /* as typed: name, IPv4, ipv6-literal.net name or [IPv6] */
    SMBUP_STRING Share;
    SMBUP_STRING UserName;      /* only with SMBUP_CONNECT_EXPLICIT_CREDENTIALS */
    SMBUP_STRING Domain;
    SMBUP_STRING Password;      /* the engine wipes it after use; the driver wipes its message */
    ULONGLONG TokenHandle;      /* handle in the engine's process (TOKEN_QUERY|TOKEN_IMPERSONATE); 0 if none */
    ULONG Flags;
    ULONG Reserved;
} SMBUP_CONNECT_REQUEST, *PSMBUP_CONNECT_REQUEST;

typedef struct _SMBUP_CONNECT_REPLY
{
    ULONGLONG ConnectionId;     /* engine-chosen, nonzero */
    ULONG MaxReadSize;
    ULONG MaxWriteSize;
    ULONG ShareType;            /* 1 = disk; anything else is refused by the driver in M1 */
    ULONG ShareFlags;
    ULONG Flags;                /* SMBUP_CONNECT_REPLY_* */
    ULONG Reserved;
} SMBUP_CONNECT_REPLY, *PSMBUP_CONNECT_REPLY;

#define SMBUP_CONNECT_REPLY_EXPLICIT    0x00000001  /* explicit credentials (given, or of another connection) */

#define SMBUP_DISCONNECT_USE            0x00000001  /* the connection was a use (SMBUP_CONNECT_USE) */
typedef struct _SMBUP_DISCONNECT_REQUEST
{
    ULONGLONG ConnectionId;
    ULONG Flags;
    ULONG Reserved;
} SMBUP_DISCONNECT_REQUEST, *PSMBUP_DISCONNECT_REQUEST;

/* CREATE: Path is relative to the share root, without a leading backslash ("" = the root) */
typedef struct _SMBUP_CREATE_REQUEST
{
    ULONGLONG ConnectionId;
    ULONG DesiredAccess;
    ULONG FileAttributes;
    ULONG ShareAccess;
    ULONG CreateDisposition;
    ULONG CreateOptions;
    ULONG Reserved;
    SMBUP_STRING Path;
} SMBUP_CREATE_REQUEST, *PSMBUP_CREATE_REQUEST;

typedef struct _SMBUP_FILE_ATTRIBUTES
{
    LONGLONG CreationTime;
    LONGLONG LastAccessTime;
    LONGLONG LastWriteTime;
    LONGLONG ChangeTime;
    LONGLONG AllocationSize;
    LONGLONG EndOfFile;
    ULONG FileAttributes;
    ULONG Reserved;
} SMBUP_FILE_ATTRIBUTES, *PSMBUP_FILE_ATTRIBUTES;

typedef struct _SMBUP_CREATE_REPLY
{
    ULONGLONG FileId;           /* engine-chosen, nonzero */
    ULONG CreateAction;         /* FILE_SUPERSEDED .. FILE_DOES_NOT_EXIST */
    ULONG Reserved;
    SMBUP_FILE_ATTRIBUTES Attributes;
} SMBUP_CREATE_REPLY, *PSMBUP_CREATE_REPLY;

/* CLOSE, FLUSH */
typedef struct _SMBUP_HANDLE_REQUEST
{
    ULONGLONG ConnectionId;
    ULONGLONG FileId;
} SMBUP_HANDLE_REQUEST, *PSMBUP_HANDLE_REQUEST;

/* READ (reply: SMBUP_DATA_REPLY + data), WRITE (request: + data, reply: SMBUP_DATA_REPLY) */
typedef struct _SMBUP_IO_REQUEST
{
    ULONGLONG ConnectionId;
    ULONGLONG FileId;
    LONGLONG Offset;
    ULONG Length;               /* <= SMBUP_MAX_IO */
    ULONG DataOffset;           /* WRITE: data at this offset, Length bytes */
} SMBUP_IO_REQUEST, *PSMBUP_IO_REQUEST;

typedef struct _SMBUP_DATA_REPLY
{
    ULONG Length;               /* READ/QUERY: bytes of data at DataOffset; WRITE: bytes written */
    ULONG DataOffset;
} SMBUP_DATA_REPLY, *PSMBUP_DATA_REPLY;

/* QUERY_INFO, QUERY_VOLUME (reply: SMBUP_DATA_REPLY + data in the NT layout of the class) */
typedef struct _SMBUP_QUERY_REQUEST
{
    ULONGLONG ConnectionId;
    ULONGLONG FileId;
    ULONG InformationClass;
    ULONG OutputLength;         /* <= SMBUP_MAX_INFO */
} SMBUP_QUERY_REQUEST, *PSMBUP_QUERY_REQUEST;

/* SET_INFO: data in the NT layout of the class (basic, end of file, allocation, disposition) */
typedef struct _SMBUP_SET_REQUEST
{
    ULONGLONG ConnectionId;
    ULONGLONG FileId;
    ULONG InformationClass;
    ULONG Length;
    ULONG DataOffset;
    ULONG Reserved;
} SMBUP_SET_REQUEST, *PSMBUP_SET_REQUEST;

/* QUERY_DIRECTORY (reply: SMBUP_DATA_REPLY + entries of the class, NT layout) */
#define SMBUP_DIR_RESTART_SCANS         0x01
#define SMBUP_DIR_RETURN_SINGLE_ENTRY   0x02
#define SMBUP_DIR_INDEX_SPECIFIED       0x04
typedef struct _SMBUP_DIRECTORY_REQUEST
{
    ULONGLONG ConnectionId;
    ULONGLONG FileId;
    ULONG InformationClass;
    ULONG OutputLength;         /* <= SMBUP_MAX_INFO */
    ULONG Flags;
    ULONG FileIndex;
    SMBUP_STRING Pattern;       /* empty = "*" */
} SMBUP_DIRECTORY_REQUEST, *PSMBUP_DIRECTORY_REQUEST;

/* RENAME: NewName relative to the share root, no leading backslash */
typedef struct _SMBUP_RENAME_REQUEST
{
    ULONGLONG ConnectionId;
    ULONGLONG FileId;
    ULONG ReplaceIfExists;
    ULONG Reserved;
    SMBUP_STRING NewName;
} SMBUP_RENAME_REQUEST, *PSMBUP_RENAME_REQUEST;

/* LOGOFF notification */
typedef struct _SMBUP_LOGOFF_REQUEST
{
    ULONG LogonIdLow;
    LONG LogonIdHigh;
} SMBUP_LOGOFF_REQUEST, *PSMBUP_LOGOFF_REQUEST;

/* CANCEL notification */
typedef struct _SMBUP_CANCEL_REQUEST
{
    ULONGLONG RequestId;
} SMBUP_CANCEL_REQUEST, *PSMBUP_CANCEL_REQUEST;

/* On the engine device (\Device\NitroSmbEngine, so for its admitted callers only), for
 * test tools: IOCTL_SMBRDR_QUERY_STATE answers whether an engine is attached (output:
 * ULONG 0/1). */
#define IOCTL_SMBRDR_QUERY_STATE        SMBUP_CTL_CODE(16, METHOD_BUFFERED)

/* On the engine device, for the service that starts the engine (the Workstation service,
 * SYSTEM): IOCTL_SMBRDR_WAIT_ENGINE_NEEDED completes (STATUS_SUCCESS) when a user's request
 * needs an engine and none is attached (STATUS_ALREADY_REGISTERED if one attached meanwhile); the
 * caller then starts the engine service. Otherwise it waits, alertably (the waiting thread can be
 * woken by an APC or terminated; the IRP has no cancel routine), at most 5 minutes
 * (STATUS_IO_TIMEOUT). Several waiters are allowed; each need wakes one of them. */
#define IOCTL_SMBRDR_WAIT_ENGINE_NEEDED SMBUP_CTL_CODE(17, METHOD_BUFFERED)
/* From the starter: it could not start an engine (input: ULONG Win32 error) or is going away. Requests
 * that wait for an engine fail at once, and requests that arrive in the next
 * NITRO_SMBRDR_ENGINE_FAIL_CACHE_SECONDS fail without asking the starter again. Without a waiting or busy
 * starter (the Workstation service stopped) requests that need an engine fail at once too. */
#define IOCTL_SMBRDR_ENGINE_START_FAILED SMBUP_CTL_CODE(18, METHOD_BUFFERED)
/* How long a request waits for an engine to attach after asking for one */
#define NITRO_SMBRDR_ENGINE_START_WAIT_SECONDS 10
/* How long requests fail at once after a start of the engine failed */
#define NITRO_SMBRDR_ENGINE_FAIL_CACHE_SECONDS 30

#ifdef __cplusplus
#define SMBUP_STATIC_ASSERT(e, m) static_assert(e, #m)
#else
#define SMBUP_STATIC_ASSERT(e, m) typedef char smbup_assert_##m[(e) ? 1 : -1]
#endif
SMBUP_STATIC_ASSERT(sizeof(SMBUP_HEADER) == 48, header_size);
SMBUP_STATIC_ASSERT(sizeof(SMBUP_CONNECT_REQUEST) == 56, connect_size);
SMBUP_STATIC_ASSERT(sizeof(SMBUP_CONNECT_REPLY) == 32, connect_reply_size);
SMBUP_STATIC_ASSERT(sizeof(SMBUP_CREATE_REQUEST) == 40, create_size);
SMBUP_STATIC_ASSERT(sizeof(SMBUP_CREATE_REPLY) == 72, create_reply_size);
SMBUP_STATIC_ASSERT(sizeof(SMBUP_IO_REQUEST) == 32, io_size);
SMBUP_STATIC_ASSERT(sizeof(SMBUP_DIRECTORY_REQUEST) == 40, dir_size);
SMBUP_STATIC_ASSERT(sizeof(SMBUP_RENAME_REQUEST) == 32, rename_size);

/* Fixed-part sizes, both directions; the driver and the engine use these to check messages */
#define SMBUP_REQUEST_FIXED_SIZE(op) \
    ((op) == SmbUpConnect ? sizeof(SMBUP_CONNECT_REQUEST) : \
     (op) == SmbUpDisconnect ? sizeof(SMBUP_DISCONNECT_REQUEST) : \
     (op) == SmbUpCreate ? sizeof(SMBUP_CREATE_REQUEST) : \
     (op) == SmbUpClose || (op) == SmbUpFlush ? sizeof(SMBUP_HANDLE_REQUEST) : \
     (op) == SmbUpRead || (op) == SmbUpWrite || (op) == SmbUpLock ? sizeof(SMBUP_IO_REQUEST) : \
     (op) == SmbUpQueryInfo || (op) == SmbUpQueryVolume ? sizeof(SMBUP_QUERY_REQUEST) : \
     (op) == SmbUpSetInfo ? sizeof(SMBUP_SET_REQUEST) : \
     (op) == SmbUpQueryDirectory ? sizeof(SMBUP_DIRECTORY_REQUEST) : \
     (op) == SmbUpRename ? sizeof(SMBUP_RENAME_REQUEST) : \
     (op) == SmbUpLogoff ? sizeof(SMBUP_LOGOFF_REQUEST) : \
     (op) == SmbUpCancel ? sizeof(SMBUP_CANCEL_REQUEST) : 0)

#define SMBUP_REPLY_FIXED_SIZE(op) \
    ((op) == SmbUpConnect ? sizeof(SMBUP_CONNECT_REPLY) : \
     (op) == SmbUpCreate ? sizeof(SMBUP_CREATE_REPLY) : \
     (op) == SmbUpRead || (op) == SmbUpWrite || (op) == SmbUpQueryInfo || \
     (op) == SmbUpQueryVolume || (op) == SmbUpQueryDirectory ? sizeof(SMBUP_DATA_REPLY) : 0)

/*
 * Checks a (Offset, Length) pair against a message of TotalSize bytes whose fixed
 * part ends at FixedEnd. Lengths of zero are valid with any offset.
 */
#define SMBUP_RANGE_VALID(Offset, Length, FixedEnd, TotalSize, Align) \
    ((Length) == 0 || \
     ((ULONGLONG)(Offset) >= (ULONGLONG)(FixedEnd) && \
      (ULONGLONG)(Offset) + (ULONGLONG)(Length) <= (ULONGLONG)(TotalSize) && \
      ((Offset) % (Align)) == 0 && ((Length) % (Align)) == 0))

#endif /* _NITRO_SMBUPCALL_H_ */
