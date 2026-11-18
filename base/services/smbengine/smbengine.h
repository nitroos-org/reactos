/*
 * PROJECT:     NitroOS SMB client engine service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Shared definitions of the engine service
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _SMBENGINE_H_
#define _SMBENGINE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#define NTOS_MODE_USER
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ntstatus.h>

/* smb2.h has its own copies of these two (same values) */
#undef FILE_DEVICE_CD_ROM
#undef FILE_DEVICE_DISK
#include <smb2.h>
#include <libsmb2.h>
#include <libsmb2-raw.h>
#include <libsmb2-nitro.h>

#include <drivers/smbrdr/smbupcall.h>

#ifndef FILE_DEVICE_NETWORK_REDIRECTOR
#define FILE_DEVICE_NETWORK_REDIRECTOR 0x00000028
#endif

#define SMBENG_SERVICE_NAME     L"smbengine"
#define SMBENG_PARAMETERS_KEY   L"SYSTEM\\CurrentControlSet\\Services\\smbengine\\Parameters"

/* Engine-side bounds (the driver bounds what it sends; these bound what we hold) */
#define SMBENG_MAX_GET_THREADS  16
#define SMBENG_BINDING_BUCKETS  256
#define SMBENG_FILE_BUCKETS     256
#define SMBENG_MAX_FILES_PER_CONN 16384

typedef struct _SMBENG_CONFIG
{
    DWORD DebugLevel;           /* 0 errors, 1 connections, 2 every request (no data, no secrets) */
    DWORD IdleSeconds;          /* a connection without open files and without requests is closed after this */
    DWORD RequestTimeoutSeconds;/* libsmb2 per-request limit, below the driver's */
    DWORD GetThreads;           /* threads waiting for requests of the driver */
    DWORD MaxConnections;       /* (logon id, server, share) keys at a time */
    DWORD MaxConnectionsPerLogon; /* of those, for one logon session (one user cannot take them all) */
    DWORD StatsSeconds;         /* period of the statistics line (DebugLevel >= 1), 0 = off */
    DWORD Dialect;              /* 0 = negotiate 2.0.2..3.1.1; 0x210, 0x300, 0x302, 0x311 = only that one (tests) */
} SMBENG_CONFIG;

extern SMBENG_CONFIG SmbEngConfig;

/* A request of the driver, held until it is answered */
typedef struct _SMBENG_OP
{
    LIST_ENTRY Link;            /* connection's queue, then its in-flight list */
    struct _SMBENG_CONN *Conn;
    PSMBUP_HEADER Request;      /* our own copy, checked */
    ULONG RequestSize;
    ULONGLONG BindingId;        /* the ConnectionId the driver used */
    USHORT Opcode;
    BOOLEAN Internal;           /* engine-made (a close of an orphaned handle): no reply */
    BOOLEAN Cancelled;          /* the driver gave up on it (CANCEL notification) */
    struct smb2_pdu *Pdu;       /* while the server has it */
    ULONG Win32Error;
    HANDLE Token;               /* CONNECT: the user's token handle, until the connection takes it */
    char *Name;                 /* UTF-8 path, pattern or new name */
    struct _SMBENG_FILE *File;
    union
    {
        struct smb2_file_basic_info Basic;
        struct smb2_file_disposition_info Disposition;
        struct smb2_file_end_of_file_info EndOfFile;
        struct smb2_file_rename_info Rename;
    } Set;
    PUCHAR Reply;               /* reply message being built (READ data lands here) */
    ULONG ReplyAlloc;
    ULONG ReplySize;
    ULONG DataOffset;           /* of the data in Reply */
    ULONG DataMax;
} SMBENG_OP, *PSMBENG_OP;

/* An open file of a connection; only its connection thread touches it */
typedef struct _SMBENG_FILE
{
    struct _SMBENG_FILE *Next;
    ULONGLONG Id;               /* what the driver holds */
    ULONGLONG BindingId;        /* only the binding that opened it may use it */
    ULONG Epoch;                /* the connection's session it belongs to */
    smb2_file_id FileId;
} SMBENG_FILE, *PSMBENG_FILE;

typedef enum _SMBENG_CONN_STATE
{
    ConnDown,                   /* no session; the next request connects */
    ConnConnecting,
    ConnUp,
    ConnLoggedOff,              /* the logon session ended: nothing more for this key */
} SMBENG_CONN_STATE;

/*
 * One (logon id, server, share) key: one libsmb2 context (TCP connection, session,
 * tree) owned by one thread. Other threads only queue requests to it and wake it.
 */
typedef struct _SMBENG_CONN
{
    LIST_ENTRY Link;            /* SmbEng.Conns, under SmbEng.Lock */
    LUID LogonId;               /* from the driver's header, never from a client */
    WCHAR *Server;              /* as the driver sent it */
    WCHAR *Share;
    char *ServerA;              /* for libsmb2 (an ipv6-literal.net name as [address]) */
    char *ShareA;
    LONG Bindings;              /* references of driver CONNECTs on this key (under SmbEng.Lock) */
    struct _SMBENG_BINDING *Shared; /* the binding every CONNECT of this key gets (under SmbEng.Lock) */
    BOOLEAN Closing;            /* leaving the table (under SmbEng.Lock) */
    volatile LONG LoggedOff;    /* the logon session ended (set by the LOGOFF notification) */

    CRITICAL_SECTION QueueLock; /* Queue and Wake only, never held across I/O */
    LIST_ENTRY Queue;
    BOOLEAN StopRequested;

    HANDLE Thread;
    SOCKET WakeSocket;          /* loopback UDP: a byte wakes the thread's poll */
    struct sockaddr_in WakeAddr;

    /* Connection thread only below */
    SMBENG_CONN_STATE State;
    struct smb2_context *Smb2;
    BOOLEAN Dead;               /* lost or failed: destroy outside libsmb2's callbacks */
    HANDLE Token;               /* the user's impersonation token (query + impersonate) */
    ULONG Epoch;                /* session number: files of older sessions are gone */
    LIST_ENTRY Pending;         /* requests waiting for the session */
    LIST_ENTRY Backlog;         /* requests over the in-flight bound, in order */
    LIST_ENTRY InFlight;
    ULONG InFlightCount;
    PSMBENG_FILE Files[SMBENG_FILE_BUCKETS];
    ULONG FileCount;
    ULONG MaxRead, MaxWrite;
    DWORD LastActivity;         /* GetTickCount */
    DWORD ConnectStart;
    DWORD FailTick;             /* last failed connect: back-off from here */
    ULONG Backoff;              /* seconds */
    ULONG QuickRetries;         /* connects refused at once as unreachable, tried again shortly */
    DWORD RetryTick;
    NTSTATUS LastConnectStatus;
    ULONG LastConnectWin32;
    NTSTATUS TeardownStatus;    /* why a connect in progress was abandoned */
    ULONG TeardownWin32;
    HANDLE ReplyEvent;
} SMBENG_CONN, *PSMBENG_CONN;

typedef struct _SMBENG_BINDING
{
    struct _SMBENG_BINDING *Next;
    ULONGLONG Id;
    PSMBENG_CONN Conn;
    LONG Refs;                  /* driver CONNECTs of this key not yet disconnected */
} SMBENG_BINDING, *PSMBENG_BINDING;

typedef struct _SMBENG_GLOBAL
{
    HANDLE Device;              /* \Device\NitroSmbEngine, overlapped */
    SRWLOCK Lock;               /* Conns, Bindings, Conn->Bindings/Closing */
    LIST_ENTRY Conns;
    ULONG ConnCount;
    PSMBENG_BINDING Bindings[SMBENG_BINDING_BUCKETS];
    ULONG BindingCount;
    volatile LONG64 NextId;
    volatile LONG Stopping;
    volatile LONG OpsLive;
    volatile LONG FilesLive;
    volatile LONG Taken;        /* requests taken from the driver (statistics) */
    HANDLE StopEvent;
} SMBENG_GLOBAL;

extern SMBENG_GLOBAL SmbEng;

/* smbengine.c */
VOID SmbEngLog(DWORD Level, const char *Format, ...);
ULONGLONG SmbEngNewId(VOID);
BOOL SmbEngSendReply(HANDLE Event, PVOID Message, ULONG Size);
VOID SmbEngRemoveBinding(ULONGLONG Id);
VOID SmbEngFreeOp(PSMBENG_OP Op);

/* conn.c */
PSMBENG_CONN SmbEngCreateConn(const SMBUP_HEADER *Header, const WCHAR *Server, ULONG ServerBytes,
                              const WCHAR *Share, ULONG ShareBytes);
VOID SmbEngQueueOp(PSMBENG_CONN Conn, PSMBENG_OP Op);
VOID SmbEngWakeConn(PSMBENG_CONN Conn);
NTSTATUS SmbEngMapStatus(USHORT Opcode, uint32_t Status);
VOID SmbEngAnswerOp(PSMBENG_OP Op, NTSTATUS Status, HANDLE Event);
BOOL SmbEngStringOf(const SMBUP_HEADER *h, ULONG FixedEnd, const SMBUP_STRING *s, const WCHAR **Out, ULONG *Bytes);

#endif /* _SMBENGINE_H_ */
