/*
 * PROJECT:     ReactOS HTTP Server API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Private definitions of the in-process HTTP/1.1 server behind httpapi.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#ifndef _HTTPAPIP_H
#define _HTTPAPIP_H

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <http.h>

WINBASEAPI BOOL WINAPI CancelIoEx(HANDLE, LPOVERLAPPED);

/* Queues of http.sys hand out structures laid out by the Microsoft compilers: 64-bit members are
 * 8-byte aligned on x86 as well, which gcc does not do by itself. */
#ifdef __GNUC__
typedef unsigned long long HPI_U64 __attribute__((aligned(8)));
#else
typedef unsigned __int64 HPI_U64;
#endif

typedef struct _HPI_DATA_CHUNK
{
    ULONG DataChunkType;
    union
    {
        struct { void *pBuffer; ULONG BufferLength; } FromMemory;
        struct { HPI_U64 StartingOffset; HPI_U64 Length; HANDLE FileHandle; } FromFileHandle;
        struct { USHORT FragmentNameLength; const WCHAR *pFragmentName; } FromFragmentCache;
    } u;
} HPI_DATA_CHUNK;

typedef struct _HPI_REQUEST_V1
{
    ULONG Flags;
    HPI_U64 ConnectionId;
    HPI_U64 RequestId;
    HPI_U64 UrlContext;
    HTTP_VERSION Version;
    ULONG Verb;
    USHORT UnknownVerbLength;
    USHORT RawUrlLength;
    const char *pUnknownVerb;
    const char *pRawUrl;
    HTTP_COOKED_URL CookedUrl;
    HTTP_TRANSPORT_ADDRESS Address;
    HTTP_REQUEST_HEADERS Headers;
    HPI_U64 BytesReceived;
    USHORT EntityChunkCount;
    HPI_DATA_CHUNK *pEntityChunks;
    HPI_U64 RawConnectionId;
    HTTP_SSL_INFO *pSslInfo;
} HPI_REQUEST_V1;

typedef struct _HPI_REQUEST_V2
{
    HPI_REQUEST_V1 s;
    USHORT RequestInfoCount;
    HTTP_REQUEST_INFO *pRequestInfo;
} HPI_REQUEST_V2;

typedef struct _HPI_MULTIPLE_KNOWN_HEADERS
{
    ULONG HeaderId;
    ULONG Flags;
    USHORT KnownHeaderCount;
    HTTP_KNOWN_HEADER *KnownHeaders;
} HPI_MULTIPLE_KNOWN_HEADERS;

#ifdef _WIN64
C_ASSERT(sizeof(HPI_REQUEST_V1) == 848);
C_ASSERT(sizeof(HPI_REQUEST_V2) == 864);
C_ASSERT(sizeof(HPI_DATA_CHUNK) == 32);
#else
C_ASSERT(sizeof(HPI_REQUEST_V1) == 464);
C_ASSERT(sizeof(HPI_REQUEST_V2) == 472);
C_ASSERT(sizeof(HPI_DATA_CHUNK) == 32);
#endif

/* Intrusive doubly linked list */
typedef struct _HL { struct _HL *Next, *Prev; } HL;
#define HL_INIT(h)      ((h)->Next = (h)->Prev = (h))
#define HL_EMPTY(h)     ((h)->Next == (h))
#define HL_ADD(h, e)    do { (e)->Next = (h); (e)->Prev = (h)->Prev; (h)->Prev->Next = (e); (h)->Prev = (e); } while (0)
#define HL_DEL(e)       do { (e)->Prev->Next = (e)->Next; (e)->Next->Prev = (e)->Prev; (e)->Next = (e)->Prev = (e); } while (0)
#define HL_ENTRY(p, type, field) ((type *)((PUCHAR)(p) - FIELD_OFFSET(type, field)))

#define HPI_MAX_HEAD        65536
#define HPI_MAX_BUFFERED    (256 * 1024)
#define HPI_IDLE_TIMEOUT    120000

typedef struct _RQ RQ;
typedef struct _CONN CONN;
typedef struct _REQ REQ;
typedef struct _URLREG URLREG;
typedef struct _LISTENER LISTENER;
typedef struct _SESSION SESSION;
typedef struct _GROUP UGROUP;

struct _SESSION
{
    HL Link;
    HL Groups;
};

struct _GROUP
{
    HL Link;
    HL SessionLink;
    SESSION *Session;
    RQ *Queue;
    HL Urls;
};

struct _URLREG
{
    HL Link;            /* global list */
    HL GroupLink;       /* group or queue list */
    UGROUP *Group;
    RQ *Queue;          /* version 1 registrations point straight at a queue */
    USHORT Port;
    int HostKind;       /* 0 name or address, 1 strong wildcard, 2 weak wildcard */
    WCHAR *Host;        /* lower case, no port */
    BOOL HostIsIp;
    SOCKADDR_STORAGE Ip;
    WCHAR *Path;
    ULONG PathLen;
    WCHAR *Full;
    ULONGLONG Context;
};

struct _LISTENER
{
    HL Link;
    USHORT Port;
    SOCKADDR_STORAGE Addr;
    int AddrLen;
    SOCKET Sock;
    HANDLE hSockEvt;
    HANDLE hStop;
    BOOL Stop;
};

/* Pending HttpReceiveHttpRequest */
typedef struct _WAITER
{
    HL Link;
    OVERLAPPED *Ovl;
    HANDLE hDone;
    HPI_U64 WantId;
    ULONG Flags;
    void *Buf;
    ULONG Size;
    ULONG *RetSize;
    ULONG Result;       /* sync callers */
    ULONG Bytes;
    BOOL Done;
} WAITER;

struct _RQ
{
    HL Link;
    LONG Closed;
    BOOL Shutdown;
    BOOL V2;
    HANDLE hA;          /* the handle given out; bound by the caller to its completion port */
    HANDLE hB;          /* our end: writing to it completes the reads queued on hA */
    CRITICAL_SECTION PostLock;
    PUCHAR Scratch;
    SIZE_T ScratchSize;
    HL Reqs;            /* every request of this queue that has not finished */
    HL Waiters;
    HL Urls;            /* version 1 registrations */
};

#define REQ_READY       0
#define REQ_PEEKED      1
#define REQ_DELIVERED   2

#define BODY_NONE       0
#define BODY_LENGTH     1
#define BODY_CHUNKED    2

#define CS_SIZE         0
#define CS_DATA         1
#define CS_DATACRLF     2
#define CS_TRAILER      3
#define CS_DONE         4

typedef struct _KNOWNV { char *Value; USHORT Len; } KNOWNV;

struct _REQ
{
    HL Link;
    CONN *Conn;
    RQ *Queue;
    ULONGLONG Id;
    ULONGLONG UrlContext;
    int State;
    LONG Pins;
    BOOL RespStarted, RespDone, CloseAfter, Head, Unframed, KeepAliveHdr, Aborted;
    ULONG Verb;
    USHORT VerMajor, VerMinor;
    char *UnknownVerb;
    ULONG UnknownVerbLen;
    char *RawUrl;
    ULONG RawUrlLen;
    WCHAR *Full;
    ULONG FullChars, HostChars, HostOff, PathChars, PathOff, QueryChars, QueryOff;
    WCHAR *HostName;    /* host without the port, for matching */
    KNOWNV Known[HttpHeaderRequestMaximum];
    HTTP_UNKNOWN_HEADER *Unk;
    ULONG UnkCount;
    ULONGLONG BytesRecv;
    int BodyKind;
    ULONGLONG BodyRemain;
    int CState;
    BOOL BodyDone, BodyErr;
    PUCHAR Arena;
    ULONG ArenaUsed, ArenaCap;
};

#define CMD_BODY    0
#define CMD_DISC    1

typedef struct _CMD
{
    HL Link;
    int Kind;
    RQ *Queue;
    REQ *Req;
    OVERLAPPED *Ovl;
    HANDLE hDone;
    PUCHAR Buf;
    ULONG Size, Flags, Got;
    ULONG Result;
    BOOL Done;
} CMD;

struct _CONN
{
    HL Link;
    SOCKET Sock;
    ULONGLONG Id;
    SOCKADDR_STORAGE Local, Remote;
    HANDLE hSockEvt, hCmdEvt, hThread;
    PUCHAR Buf;
    ULONG Len, Pos, Cap;
    USHORT LPort;
    BOOL PeerClosed, Abort, Dead, SendBroken;
    REQ *Cur;
    HL Cmds;
    CRITICAL_SECTION SendLock;
};

/* iocp.c */
#define POST_OK     0
#define POST_MORE   1   /* ERROR_MORE_DATA, Bytes is the size needed */
#define POST_CANCEL 2   /* ERROR_OPERATION_ABORTED */

extern CRITICAL_SECTION g_Lock;
extern HL g_Queues, g_Sessions, g_Urls, g_Listeners, g_Conns;
extern LONG g_Init;

BOOL Queue_Create(RQ **Out, BOOL V2, SECURITY_ATTRIBUTES *Sa);
RQ *Queue_Find(HANDLE h);
void Queue_Close(RQ *Q);
void Post_Completion(RQ *Q, OVERLAPPED *Ovl, int Kind, ULONG Bytes);
ULONG Op_Finish(RQ *Q, OVERLAPPED *Ovl, ULONG Status, int Kind, ULONG Bytes, ULONG *Ret);
void Waiter_Complete(RQ *Q, WAITER *W, ULONG Status, int Kind, ULONG Bytes);
ULONGLONG New_Id(void);

/* urls.c */
ULONG Url_Register(UGROUP *G, RQ *Q, const WCHAR *Url, ULONGLONG Ctx);
ULONG Url_Remove(UGROUP *G, RQ *Q, const WCHAR *Url);
void Url_RemoveAll(UGROUP *G, RQ *Q);
BOOL Url_PortListening(USHORT Port);
URLREG *Url_Match(const WCHAR *Host, USHORT Port, const SOCKADDR_STORAGE *Local, const WCHAR *Path, ULONG PathLen);

/* conn.c */
void Conn_New(SOCKET S, const SOCKADDR_STORAGE *Local, const SOCKADDR_STORAGE *Remote);
ULONG Req_Receive(HANDLE Queue, ULONGLONG Id, ULONG Flags, void *Buf, ULONG Size, ULONG *Ret, OVERLAPPED *Ovl);
ULONG Req_Body(HANDLE Queue, ULONGLONG Id, ULONG Flags, void *Buf, ULONG Size, ULONG *Ret, OVERLAPPED *Ovl);
ULONG Req_Send(HANDLE Queue, ULONGLONG Id, ULONG Flags, HTTP_RESPONSE *Resp, ULONG ChunkCount, HPI_DATA_CHUNK *Chunks,
               ULONG *Ret, OVERLAPPED *Ovl, BOOL IsResponse);
ULONG Req_Cancel(HANDLE Queue, ULONGLONG Id, OVERLAPPED *Ovl);
ULONG Req_WaitDisconnect(HANDLE Queue, ULONGLONG ConnId, OVERLAPPED *Ovl);
void Queue_AbortRequests(RQ *Q);
void Conn_RetirePort(USHORT Port);
BOOL Conn_PortBusy(USHORT Port);
void Queue_CancelWaiters(RQ *Q);

#endif
