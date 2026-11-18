/*
 * PROJECT:     NitroOS SMB client engine service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Service control, the channel to the mini-redirector, request routing
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * smbengine is the user-mode half of the SMB client: mrxsmb.sys (the mini-redirector on
 * rdbss) sends every operation that needs the server as a request message
 * (sdk/include/reactos/drivers/smbrdr/smbupcall.h); this service answers it with
 * libsmb2.dll. It runs in its own process as LocalService and treats both sides as
 * untrusted: the network (libsmb2 parses it; this file never sees a PDU) and, for
 * robustness, the driver's messages, which it checks before use.
 *
 * Threads. GetThreads threads wait in IOCTL_SMBRDR_ENGINE_GET; each checks the request,
 * copies it and routes it: CONNECT/DISCONNECT/LOGOFF/CANCEL here, everything else to the
 * connection of its ConnectionId. Each connection ((logon id, server, share) key: one
 * libsmb2 context = TCP connection + session + tree) has one thread that owns the context
 * and runs libsmb2's async API (conn.c). Locks: SmbEng.Lock (the tables) and each
 * connection's queue lock, both held for list operations only, never across I/O.
 *
 * Identity. The logon id of a request is the driver's (rxce takes it from the opener's
 * token). Connections are found by (driver logon id, server, share) only; a client
 * process cannot name another logon session's connection. A CONNECT's token must belong
 * to that logon id. Authentication is single sign-on: the connection thread impersonates
 * the token around credential acquisition and libsmb2's SSPI backend around every
 * InitializeSecurityContext. Nothing secret is logged or stored.
 */

#include "smbengine.h"

SMBENG_CONFIG SmbEngConfig;
SMBENG_GLOBAL SmbEng;

static SERVICE_STATUS_HANDLE ServiceStatusHandle;
static SERVICE_STATUS ServiceStatus;
static HANDLE GetThreadHandles[SMBENG_MAX_GET_THREADS];
static DWORD GetThreadCount;
static HANDLE LogFile = INVALID_HANDLE_VALUE;

/* Debug output, and the log file of Parameters\LogFile when one is set (tests) */
VOID
SmbEngLog(DWORD Level, const char *Format, ...)
{
    char Line[512];
    va_list Args;
    SYSTEMTIME Now;
    DWORD Written;
    int n, Prefix;

    if (Level > SmbEngConfig.DebugLevel)
        return;
    GetSystemTime(&Now);
    Prefix = _snprintf(Line, sizeof(Line) - 2, "%02u:%02u:%02u.%03u ", Now.wHour, Now.wMinute, Now.wSecond, Now.wMilliseconds);
    n = Prefix + _snprintf(Line + Prefix, sizeof(Line) - 2 - Prefix, "smbengine: ");
    va_start(Args, Format);
    n += _vsnprintf(Line + n, sizeof(Line) - 2 - n, Format, Args);
    va_end(Args);
    if (n < 0 || n > (int)sizeof(Line) - 2)
        n = sizeof(Line) - 2;
    Line[n] = '\n';
    Line[n + 1] = 0;
    OutputDebugStringA(Line + Prefix);
    if (LogFile != INVALID_HANDLE_VALUE)
        WriteFile(LogFile, Line, n + 1, &Written, NULL);
}

ULONGLONG
SmbEngNewId(VOID)
{
    return (ULONGLONG)InterlockedIncrement64(&SmbEng.NextId);
}

static
DWORD
ReadDword(HKEY Key, PCWSTR Name, DWORD Default, DWORD Min, DWORD Max)
{
    DWORD Value, Size = sizeof(Value), Type;

    if (Key == NULL ||
        RegQueryValueExW(Key, Name, NULL, &Type, (LPBYTE)&Value, &Size) != ERROR_SUCCESS ||
        Type != REG_DWORD || Size != sizeof(Value))
    {
        return Default;
    }
    return Value < Min ? Min : Value > Max ? Max : Value;
}

static
VOID
ReadConfig(VOID)
{
    HKEY Key = NULL;

    RegOpenKeyExW(HKEY_LOCAL_MACHINE, SMBENG_PARAMETERS_KEY, 0, KEY_QUERY_VALUE, &Key);
    SmbEngConfig.DebugLevel = ReadDword(Key, L"DebugLevel", 0, 0, 2);
    SmbEngConfig.IdleSeconds = ReadDword(Key, L"IdleSeconds", 600, 5, 86400);
    /* below the driver's own limit (NITRO_SMBRDR_REQUEST_TIMEOUT_SECONDS), so that a
     * stuck server ends as our timeout, with the connection dropped, not the driver's */
    SmbEngConfig.RequestTimeoutSeconds = ReadDword(Key, L"RequestTimeoutSeconds", 90, 5,
                                                   NITRO_SMBRDR_REQUEST_TIMEOUT_SECONDS - 10);
    SmbEngConfig.GetThreads = ReadDword(Key, L"GetThreads", 4, 1, SMBENG_MAX_GET_THREADS);
    SmbEngConfig.MaxConnections = ReadDword(Key, L"MaxConnections", 256, 1, 4096);
    SmbEngConfig.MaxConnectionsPerLogon = ReadDword(Key, L"MaxConnectionsPerLogon", 64, 1, 4096);
    SmbEngConfig.StatsSeconds = ReadDword(Key, L"StatsSeconds", 300, 0, 86400);
    SmbEngConfig.Dialect = ReadDword(Key, L"Dialect", 0, 0, 0x311);
    if (Key != NULL)
    {
        WCHAR Path[MAX_PATH];
        DWORD Size = sizeof(Path) - sizeof(WCHAR), Type;

        /* Tests: a file the log is appended to (no secrets are logged at any level) */
        if (RegQueryValueExW(Key, L"LogFile", NULL, &Type, (LPBYTE)Path, &Size) == ERROR_SUCCESS &&
            Type == REG_SZ && Size >= 2 * sizeof(WCHAR))
        {
            Path[Size / sizeof(WCHAR)] = 0;
            LogFile = CreateFileW(Path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        RegCloseKey(Key);
    }
}

/* One DeviceIoControl on the overlapped engine handle, waited for */
static
BOOL
EngineIoctl(HANDLE Event, DWORD Code, PVOID In, DWORD InSize, PVOID Out, DWORD OutSize, PDWORD Returned)
{
    OVERLAPPED Ov;

    ZeroMemory(&Ov, sizeof(Ov));
    Ov.hEvent = Event;
    *Returned = 0;
    if (DeviceIoControl(SmbEng.Device, Code, In, InSize, Out, OutSize, Returned, &Ov))
        return TRUE;
    if (GetLastError() != ERROR_IO_PENDING)
        return FALSE;
    return GetOverlappedResult(SmbEng.Device, &Ov, Returned, TRUE);
}

BOOL
SmbEngSendReply(HANDLE Event, PVOID Message, ULONG Size)
{
    DWORD Returned;

    return EngineIoctl(Event, IOCTL_SMBRDR_ENGINE_REPLY, Message, Size, NULL, 0, &Returned);
}

VOID
SmbEngFreeOp(PSMBENG_OP Op)
{
    if (Op == NULL)
        return;
    if (Op->Token != NULL)
        CloseHandle(Op->Token);
    if (Op->Request != NULL)
    {
        /* CONNECT may carry a password one day: never leave it in freed memory */
        if (Op->Opcode == SmbUpConnect)
            SecureZeroMemory(Op->Request, Op->RequestSize);
        free(Op->Request);
    }
    free(Op->Name);
    free(Op->Reply);
    free(Op);
    InterlockedDecrement(&SmbEng.OpsLive);
}

/* Checks a request message: the engine does not trust the driver's sizes either */
static
BOOL
ValidRequest(const SMBUP_HEADER *h, DWORD Got)
{
    if (Got < sizeof(*h) || h->Magic != SMBUP_MAGIC || h->Version != SMBUP_VERSION ||
        h->HeaderSize != sizeof(*h) || h->TotalSize != Got || Got > SMBUP_MAX_MESSAGE ||
        h->Opcode <= SmbUpInvalid || h->Opcode >= SmbUpMaximumOpcode)
    {
        return FALSE;
    }
    if (Got < sizeof(*h) + SMBUP_REQUEST_FIXED_SIZE(h->Opcode))
        return FALSE;
    /* Notifications and requests are distinct opcodes */
    if (((h->Flags & SMBUP_FLAG_NOTIFICATION) != 0) != (h->Opcode == SmbUpLogoff || h->Opcode == SmbUpCancel))
        return FALSE;
    return TRUE;
}

BOOL
SmbEngStringOf(const SMBUP_HEADER *h, ULONG FixedEnd, const SMBUP_STRING *s, const WCHAR **Out, ULONG *Bytes)
{
    ULONG i;

    *Bytes = 0;
    *Out = L"";
    if (s->Length == 0)
        return TRUE;
    if (!SMBUP_RANGE_VALID(s->Offset, s->Length, FixedEnd, h->TotalSize, 2) || s->Length > SMBUP_MAX_NAME_BYTES)
        return FALSE;
    *Out = (const WCHAR *)((const UCHAR *)h + s->Offset);
    /* Names go to libsmb2 as C strings: an embedded NUL would cut them */
    for (i = 0; i < s->Length / sizeof(WCHAR); i++)
    {
        if ((*Out)[i] == 0)
            return FALSE;
    }
    *Bytes = s->Length;
    return TRUE;
}

static
PSMBENG_BINDING *
BindingSlot(ULONGLONG Id)
{
    PSMBENG_BINDING *Slot = &SmbEng.Bindings[(ULONG)(Id * 0x9E3779B97F4A7C15ULL >> 56) % SMBENG_BINDING_BUCKETS];

    while (*Slot != NULL && (*Slot)->Id != Id)
        Slot = &(*Slot)->Next;
    return Slot;
}

/* The connection of a binding (call with SmbEng.Lock held) */
static
PSMBENG_CONN
LookupBinding(ULONGLONG Id)
{
    PSMBENG_BINDING Binding = Id != 0 ? *BindingSlot(Id) : NULL;

    return Binding != NULL ? Binding->Conn : NULL;
}

/* The connection of a binding, for a request of that binding's logon session only (call with
 * SmbEng.Lock held). The driver sends every request of a virtual net root with the logon id of
 * that net root; a request naming the ConnectionId of another logon session's key is refused. */
static
PSMBENG_CONN
LookupBindingFor(ULONGLONG Id, const SMBUP_HEADER *h)
{
    PSMBENG_CONN Conn = LookupBinding(Id);

    if (Conn != NULL &&
        (Conn->LogonId.LowPart != h->LogonIdLow || Conn->LogonId.HighPart != h->LogonIdHigh))
    {
        SmbEngLog(0, "request %I64u op %u: logon %08lx:%08lx is not the one of its connection",
                  h->RequestId, h->Opcode, h->LogonIdHigh, h->LogonIdLow);
        return NULL;
    }
    return Conn;
}

/*
 * One reference of a binding goes (call with SmbEng.Lock held exclusively). The driver
 * connects a virtual net root per drive letter and UNC prefix, and rxce makes many of
 * them; all CONNECTs of one key share one binding with a reference count, so the table
 * grows with the keys, not with the driver's CONNECTs. Returns the binding when this was
 * its last reference (it is out of the table then; the caller frees it).
 */
static
PSMBENG_BINDING
ReleaseBindingLocked(ULONGLONG Id)
{
    PSMBENG_BINDING *Slot = BindingSlot(Id), Binding = *Slot;

    if (Binding == NULL)
        return NULL;
    Binding->Conn->Bindings--;
    if (--Binding->Refs != 0)
        return NULL;
    *Slot = Binding->Next;
    if (Binding->Conn->Shared == Binding)
        Binding->Conn->Shared = NULL;
    SmbEng.BindingCount--;
    return Binding;
}

/* Whether the driver still holds this binding (any thread; takes the table lock shared) */
BOOL
SmbEngBindingLive(ULONGLONG Id)
{
    BOOL Live;

    AcquireSRWLockShared(&SmbEng.Lock);
    Live = (LookupBinding(Id) != NULL);
    ReleaseSRWLockShared(&SmbEng.Lock);
    return Live;
}

/* Drops one reference the driver will not use (it never got the CONNECT reply, or the connect failed) */
VOID
SmbEngRemoveBinding(ULONGLONG Id)
{
    PSMBENG_BINDING Binding;
    PSMBENG_CONN Conn;

    AcquireSRWLockExclusive(&SmbEng.Lock);
    Conn = LookupBinding(Id);
    Binding = ReleaseBindingLocked(Id);
    if (Conn != NULL)
        SmbEngWakeConn(Conn);
    ReleaseSRWLockExclusive(&SmbEng.Lock);
    free(Binding);
}

/* Builds a header-only (or header + empty fixed part) reply and sends it; frees Op */
VOID
SmbEngAnswerOp(PSMBENG_OP Op, NTSTATUS Status, HANDLE Event)
{
    UCHAR Buffer[sizeof(SMBUP_HEADER) + sizeof(SMBUP_CREATE_REPLY)];
    PSMBUP_HEADER r = (PSMBUP_HEADER)Buffer;
    ULONG Size = sizeof(SMBUP_HEADER);

    if (!Op->Internal)
    {
        ZeroMemory(Buffer, sizeof(Buffer));
        r->Magic = SMBUP_MAGIC;
        r->Version = SMBUP_VERSION;
        r->Opcode = Op->Opcode;
        r->HeaderSize = sizeof(SMBUP_HEADER);
        r->RequestId = Op->Request->RequestId;
        r->Status = Status;
        r->Win32Error = Op->Win32Error;
        /* A success needs the fixed part; an error does not */
        if (NT_SUCCESS(Status))
            Size += SMBUP_REPLY_FIXED_SIZE(Op->Opcode);
        r->TotalSize = Size;
        SmbEngSendReply(Event, Buffer, Size);
        SmbEngLog(2, "request %I64u op %u -> %08lx", r->RequestId, Op->Opcode, Status);
    }
    SmbEngFreeOp(Op);
}

static
BOOL
SameKey(PSMBENG_CONN Conn, const SMBUP_HEADER *h, const WCHAR *Server, ULONG ServerBytes,
        const WCHAR *Share, ULONG ShareBytes)
{
    return Conn->LogonId.LowPart == h->LogonIdLow && Conn->LogonId.HighPart == h->LogonIdHigh &&
           wcslen(Conn->Server) * sizeof(WCHAR) == ServerBytes &&
           wcslen(Conn->Share) * sizeof(WCHAR) == ShareBytes &&
           _wcsnicmp(Conn->Server, Server, ServerBytes / 2) == 0 &&
           _wcsnicmp(Conn->Share, Share, ShareBytes / 2) == 0;
}

/* The token the driver handed over must be an impersonation token of the request's logon session */
static
NTSTATUS
CheckToken(HANDLE Token, const SMBUP_HEADER *h)
{
    TOKEN_STATISTICS Stats;
    DWORD Size;

    if (!GetTokenInformation(Token, TokenStatistics, &Stats, sizeof(Stats), &Size))
        return STATUS_NO_TOKEN;
    if (Stats.TokenType != TokenImpersonation || Stats.ImpersonationLevel < SecurityImpersonation)
        return STATUS_BAD_IMPERSONATION_LEVEL;
    if (Stats.AuthenticationId.LowPart != h->LogonIdLow || Stats.AuthenticationId.HighPart != h->LogonIdHigh)
        return STATUS_ACCESS_DENIED;
    return STATUS_SUCCESS;
}

static
VOID
HandleConnect(PSMBENG_OP Op, HANDLE Event)
{
    PSMBUP_HEADER h = Op->Request;
    PSMBUP_CONNECT_REQUEST r = (PSMBUP_CONNECT_REQUEST)(h + 1);
    ULONG FixedEnd = sizeof(*h) + sizeof(*r), ServerBytes, ShareBytes, Dummy, OfLogon = 0;
    const WCHAR *Server, *Share, *Password;
    PSMBENG_CONN Conn = NULL;
    PSMBENG_BINDING Binding;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    /* The driver created this handle for us when we took the request: ours now */
    Op->Token = (HANDLE)(ULONG_PTR)r->TokenHandle;

    if (!SmbEngStringOf(h, FixedEnd, &r->Server, &Server, &ServerBytes) ||
        !SmbEngStringOf(h, FixedEnd, &r->Share, &Share, &ShareBytes) ||
        ServerBytes == 0 || ShareBytes == 0 || ServerBytes > 512 * sizeof(WCHAR) || ShareBytes > 256 * sizeof(WCHAR))
    {
        SmbEngAnswerOp(Op, STATUS_BAD_NETWORK_PATH, Event);
        return;
    }
    /* libsmb2's connect does not report the share type and the reply says "disk": a tree
     * connect to IPC$ (named pipes) would reach rdbss as a disk share. Disk shares only. */
    if (ShareBytes == 4 * sizeof(WCHAR) && _wcsnicmp(Share, L"IPC$", 4) == 0)
    {
        SmbEngAnswerOp(Op, STATUS_BAD_DEVICE_TYPE, Event);
        return;
    }
    if (r->Flags & SMBUP_CONNECT_EXPLICIT_CREDENTIALS)
    {
        /* Not in this version (the driver does not send them yet): wipe and refuse */
        if (SmbEngStringOf(h, FixedEnd, &r->Password, &Password, &Dummy) && Dummy != 0)
            SecureZeroMemory((PVOID)Password, Dummy);
        SmbEngAnswerOp(Op, STATUS_NOT_SUPPORTED, Event);
        return;
    }
    if (Op->Token == NULL)
    {
        SmbEngAnswerOp(Op, STATUS_NO_TOKEN, Event);
        return;
    }
    Status = CheckToken(Op->Token, h);
    if (!NT_SUCCESS(Status))
    {
        SmbEngLog(0, "connect refused: token does not match the request (%08lx)", Status);
        SmbEngAnswerOp(Op, Status, Event);
        return;
    }

    Binding = calloc(1, sizeof(*Binding));
    if (Binding == NULL)
    {
        SmbEngAnswerOp(Op, STATUS_INSUFFICIENT_RESOURCES, Event);
        return;
    }
    Binding->Id = SmbEngNewId();
    Op->BindingId = Binding->Id;

    AcquireSRWLockExclusive(&SmbEng.Lock);
    for (Entry = SmbEng.Conns.Flink; Entry != &SmbEng.Conns; Entry = Entry->Flink)
    {
        PSMBENG_CONN Candidate = CONTAINING_RECORD(Entry, SMBENG_CONN, Link);

        if (Candidate->LogonId.LowPart == h->LogonIdLow && Candidate->LogonId.HighPart == h->LogonIdHigh)
            OfLogon++;
        if (!Candidate->Closing && !Candidate->LoggedOff &&
            SameKey(Candidate, h, Server, ServerBytes, Share, ShareBytes))
        {
            Conn = Candidate;
            break;
        }
    }
    if (Conn == NULL)
    {
        /* Each key is a thread and (in back-off) stays a while after a failed connect: one
         * logon session naming many servers must not take the keys of every other user */
        if (SmbEng.ConnCount >= SmbEngConfig.MaxConnections || OfLogon >= SmbEngConfig.MaxConnectionsPerLogon ||
            SmbEng.Stopping)
        {
            if (!SmbEng.Stopping)
                SmbEngLog(1, "connect refused: %lu connections, %lu of logon %08lx:%08lx",
                          SmbEng.ConnCount, OfLogon, h->LogonIdHigh, h->LogonIdLow);
            ReleaseSRWLockExclusive(&SmbEng.Lock);
            free(Binding);
            SmbEngAnswerOp(Op, STATUS_INSUFFICIENT_RESOURCES, Event);
            return;
        }
        Conn = SmbEngCreateConn(h, Server, ServerBytes, Share, ShareBytes);
        if (Conn == NULL)
        {
            ReleaseSRWLockExclusive(&SmbEng.Lock);
            free(Binding);
            SmbEngAnswerOp(Op, STATUS_INSUFFICIENT_RESOURCES, Event);
            return;
        }
        InsertTailList(&SmbEng.Conns, &Conn->Link);
        SmbEng.ConnCount++;
    }
    if (Conn->Shared != NULL)
    {
        /* Another CONNECT of this key: one more reference of its binding */
        free(Binding);
        Binding = Conn->Shared;
        Binding->Refs++;
    }
    else
    {
        Binding->Conn = Conn;
        Binding->Refs = 1;
        *BindingSlot(Binding->Id) = Binding;
        Conn->Shared = Binding;
        SmbEng.BindingCount++;
    }
    Op->BindingId = Binding->Id;
    Conn->Bindings++;
    SmbEngQueueOp(Conn, Op);
    SmbEngWakeConn(Conn);
    ReleaseSRWLockExclusive(&SmbEng.Lock);
}

static
VOID
HandleDisconnect(PSMBENG_OP Op, HANDLE Event)
{
    PSMBUP_DISCONNECT_REQUEST r = (PSMBUP_DISCONNECT_REQUEST)(Op->Request + 1);
    PSMBENG_BINDING Binding = NULL;
    PSMBENG_CONN Conn = NULL;
    BOOLEAN Known = FALSE, Last;

    AcquireSRWLockExclusive(&SmbEng.Lock);
    if (r->ConnectionId != 0 && (Conn = LookupBindingFor(r->ConnectionId, Op->Request)) != NULL)
    {
        Known = TRUE;
        Op->BindingId = r->ConnectionId;
        Binding = ReleaseBindingLocked(r->ConnectionId);
        if (Binding != NULL)
        {
            /* The last reference: the connection closes the binding's files and answers */
            SmbEngQueueOp(Conn, Op);
        }
        SmbEngWakeConn(Conn);
    }
    ReleaseSRWLockExclusive(&SmbEng.Lock);
    Last = (Binding != NULL);
    free(Binding);

    if (!Known)
        SmbEngAnswerOp(Op, STATUS_INVALID_HANDLE, Event);
    else if (!Last)
        SmbEngAnswerOp(Op, STATUS_SUCCESS, Event);
}

/* LOGOFF and CANCEL: every connection concerned gets its own copy */
static
VOID
HandleNotification(const SMBUP_HEADER *h)
{
    PLIST_ENTRY Entry;
    LUID LogonId = { 0, 0 };

    if (h->Opcode == SmbUpLogoff)
    {
        const SMBUP_LOGOFF_REQUEST *r = (const SMBUP_LOGOFF_REQUEST *)(h + 1);

        LogonId.LowPart = r->LogonIdLow;
        LogonId.HighPart = r->LogonIdHigh;
        SmbEngLog(1, "logoff %08lx:%08lx", LogonId.HighPart, LogonId.LowPart);
    }

    /* Wakes happen under the lock: a connection leaves the table (and frees itself)
     * only under the exclusive lock, after its queue is empty */
    AcquireSRWLockShared(&SmbEng.Lock);
    for (Entry = SmbEng.Conns.Flink; Entry != &SmbEng.Conns; Entry = Entry->Flink)
    {
        PSMBENG_CONN Conn = CONTAINING_RECORD(Entry, SMBENG_CONN, Link);
        PSMBENG_OP Note;

        if (h->Opcode == SmbUpLogoff)
        {
            if (Conn->LogonId.LowPart != LogonId.LowPart || Conn->LogonId.HighPart != LogonId.HighPart)
                continue;
            /* No new CONNECT finds it any more */
            InterlockedExchange(&Conn->LoggedOff, 1);
        }
        Note = calloc(1, sizeof(*Note));
        if (Note == NULL || !(Note->Request = malloc(h->TotalSize)))
        {
            free(Note);
            continue;
        }
        InterlockedIncrement(&SmbEng.OpsLive);
        memcpy(Note->Request, h, h->TotalSize);
        Note->RequestSize = h->TotalSize;
        Note->Opcode = h->Opcode;
        Note->Internal = TRUE;
        SmbEngQueueOp(Conn, Note);
        SmbEngWakeConn(Conn);
    }
    ReleaseSRWLockShared(&SmbEng.Lock);
}

static
VOID
Dispatch(PUCHAR Buffer, DWORD Got, HANDLE Event)
{
    PSMBUP_HEADER h = (PSMBUP_HEADER)Buffer;
    PSMBENG_OP Op;
    PSMBENG_CONN Conn;
    ULONGLONG ConnectionId;

    if (!ValidRequest(h, Got))
    {
        /* A CONNECT we cannot use may still carry a token handle the driver made for us */
        if (Got >= sizeof(*h) + sizeof(SMBUP_CONNECT_REQUEST) && h->Opcode == SmbUpConnect)
        {
            HANDLE Token = (HANDLE)(ULONG_PTR)((PSMBUP_CONNECT_REQUEST)(h + 1))->TokenHandle;

            if (Token != NULL)
                CloseHandle(Token);
        }
        SmbEngLog(0, "invalid request from the driver (%lu bytes)", Got);
        return;
    }

    if (h->Flags & SMBUP_FLAG_NOTIFICATION)
    {
        HandleNotification(h);
        return;
    }

    Op = calloc(1, sizeof(*Op));
    if (Op != NULL && !(Op->Request = malloc(Got)))
    {
        free(Op);
        Op = NULL;
    }
    if (Op == NULL)
    {
        /* Nothing to answer with: the driver's time limit ends the request */
        if (h->Opcode == SmbUpConnect && ((PSMBUP_CONNECT_REQUEST)(h + 1))->TokenHandle)
            CloseHandle((HANDLE)(ULONG_PTR)((PSMBUP_CONNECT_REQUEST)(h + 1))->TokenHandle);
        return;
    }
    InterlockedIncrement(&SmbEng.OpsLive);
    memcpy(Op->Request, h, Got);
    Op->RequestSize = Got;
    Op->Opcode = h->Opcode;
    if (h->Opcode == SmbUpConnect)
        SecureZeroMemory(Buffer, Got);
    /* From here on only our copy */
    h = Op->Request;

    SmbEngLog(2, "request %I64u op %u logon %08lx:%08lx pid %lu", h->RequestId, h->Opcode,
              h->LogonIdHigh, h->LogonIdLow, h->ProcessId);

    switch (h->Opcode)
    {
        case SmbUpConnect:
            HandleConnect(Op, Event);
            return;
        case SmbUpDisconnect:
            HandleDisconnect(Op, Event);
            return;
        case SmbUpLock:
            SmbEngAnswerOp(Op, STATUS_NOT_SUPPORTED, Event);
            return;
        default:
            break;
    }

    /* Every other request names its connection first (C_ASSERTed layouts) */
    ConnectionId = *(const ULONGLONG UNALIGNED *)(Op->Request + 1);
    Op->BindingId = ConnectionId;
    AcquireSRWLockShared(&SmbEng.Lock);
    Conn = LookupBindingFor(ConnectionId, h);
    if (Conn != NULL)
    {
        SmbEngQueueOp(Conn, Op);
        SmbEngWakeConn(Conn);
    }
    ReleaseSRWLockShared(&SmbEng.Lock);
    if (Conn == NULL)
        SmbEngAnswerOp(Op, STATUS_CONNECTION_DISCONNECTED, Event);
}

static
DWORD
WINAPI
GetThread(LPVOID Parameter)
{
    PUCHAR Buffer = VirtualAlloc(NULL, SMBUP_MAX_MESSAGE, MEM_COMMIT, PAGE_READWRITE);
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    DWORD Got, Error;

    UNREFERENCED_PARAMETER(Parameter);

    if (Buffer == NULL || Event == NULL)
    {
        SetEvent(SmbEng.StopEvent);
        return 1;
    }
    while (!SmbEng.Stopping)
    {
        if (!EngineIoctl(Event, IOCTL_SMBRDR_ENGINE_GET, NULL, 0, Buffer, SMBUP_MAX_MESSAGE, &Got))
        {
            Error = GetLastError();
            if (!SmbEng.Stopping)
            {
                /* Not attached any more (the driver detached us): this process cannot serve.
                 * Stop with an error, so that the service controller's recovery restarts us. */
                SmbEngLog(0, "GET failed %lu: stopping", Error);
                SetEvent(SmbEng.StopEvent);
            }
            break;
        }
        InterlockedIncrement(&SmbEng.Taken);
        Dispatch(Buffer, Got, Event);
    }
    CloseHandle(Event);
    VirtualFree(Buffer, 0, MEM_RELEASE);
    return 0;
}

static
DWORD
Attach(VOID)
{
    SMBUP_ATTACH Attach;
    HANDLE Event;
    DWORD Returned, Error = ERROR_SUCCESS;

    SmbEng.Device = CreateFileW(NITRO_SMBRDR_ENGINE_DOS_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (SmbEng.Device == INVALID_HANDLE_VALUE)
    {
        SmbEng.Device = NULL;
        Error = GetLastError();
        SmbEngLog(0, "cannot open the engine device: %lu", Error);
        return Error;
    }
    ZeroMemory(&Attach, sizeof(Attach));
    Attach.Magic = SMBUP_MAGIC;
    Attach.Version = SMBUP_VERSION;
    Attach.MaxMessageSize = SMBUP_MAX_MESSAGE;
    Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (Event == NULL || !EngineIoctl(Event, IOCTL_SMBRDR_ENGINE_ATTACH, &Attach, sizeof(Attach), NULL, 0, &Returned))
    {
        Error = Event ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY;
        SmbEngLog(0, "attach failed: %lu", Error);
        CloseHandle(SmbEng.Device);
        SmbEng.Device = NULL;
    }
    if (Event != NULL)
        CloseHandle(Event);
    return Error;
}

static
VOID
LogStats(VOID)
{
    VM_COUNTERS Vm;
    DWORD Handles = 0;

    ZeroMemory(&Vm, sizeof(Vm));
    NtQueryInformationProcess(GetCurrentProcess(), ProcessVmCounters, &Vm, sizeof(Vm), NULL);
    GetProcessHandleCount(GetCurrentProcess(), &Handles);
    AcquireSRWLockShared(&SmbEng.Lock);
    SmbEngLog(1, "stats connections=%lu bindings=%lu requests=%ld files=%ld handles=%lu private=%Iu taken=%ld",
              SmbEng.ConnCount, SmbEng.BindingCount, SmbEng.OpsLive, SmbEng.FilesLive, Handles,
              Vm.PagefileUsage, SmbEng.Taken);
    ReleaseSRWLockShared(&SmbEng.Lock);
}

static
VOID
SetState(DWORD State, DWORD ExitCode, DWORD WaitHint)
{
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = State;
    ServiceStatus.dwControlsAccepted = (State == SERVICE_RUNNING) ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    ServiceStatus.dwWin32ExitCode = ExitCode;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = (State == SERVICE_START_PENDING || State == SERVICE_STOP_PENDING) ?
                                 ServiceStatus.dwCheckPoint + 1 : 0;
    ServiceStatus.dwWaitHint = WaitHint;
    SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

static
DWORD
WINAPI
ServiceControlHandler(DWORD Control, DWORD EventType, LPVOID EventData, LPVOID Context)
{
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(Context);

    switch (Control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            SetState(SERVICE_STOP_PENDING, NO_ERROR, 10000);
            SetEvent(SmbEng.StopEvent);
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* Stops everything: the driver first (fails what it has outstanding), then the connections */
static
VOID
Shutdown(VOID)
{
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, NULL);
    PLIST_ENTRY Entry;
    HANDLE Threads[MAXIMUM_WAIT_OBJECTS];
    DWORD Returned, n, i, Round;

    InterlockedExchange(&SmbEng.Stopping, 1);
    if (SmbEng.Device != NULL && Event != NULL)
        EngineIoctl(Event, IOCTL_SMBRDR_ENGINE_DETACH, NULL, 0, NULL, 0, &Returned);
    if (Event != NULL)
        CloseHandle(Event);

    for (i = 0; i < GetThreadCount; i++)
    {
        if (WaitForSingleObject(GetThreadHandles[i], 5000) != WAIT_OBJECT_0)
            SmbEngLog(0, "GET thread %lu did not end", i);
        CloseHandle(GetThreadHandles[i]);
    }

    /* Ask every connection to end; each leaves the table itself (a thread stuck in name
     * resolution is not waited for forever: the process ends anyway) */
    for (Round = 0; Round < 6; Round++)
    {
        n = 0;
        AcquireSRWLockShared(&SmbEng.Lock);
        for (Entry = SmbEng.Conns.Flink; Entry != &SmbEng.Conns && n < RTL_NUMBER_OF(Threads); Entry = Entry->Flink)
        {
            PSMBENG_CONN Conn = CONTAINING_RECORD(Entry, SMBENG_CONN, Link);

            EnterCriticalSection(&Conn->QueueLock);
            Conn->StopRequested = TRUE;
            LeaveCriticalSection(&Conn->QueueLock);
            SmbEngWakeConn(Conn);
            if (DuplicateHandle(GetCurrentProcess(), Conn->Thread, GetCurrentProcess(), &Threads[n], SYNCHRONIZE, FALSE, 0))
                n++;
        }
        ReleaseSRWLockShared(&SmbEng.Lock);
        if (n == 0)
            break;
        WaitForMultipleObjects(n, Threads, TRUE, 10000);
        for (i = 0; i < n; i++)
            CloseHandle(Threads[i]);
    }

    if (SmbEng.Device != NULL)
    {
        CloseHandle(SmbEng.Device);
        SmbEng.Device = NULL;
    }
}

static
VOID
WINAPI
ServiceMain(DWORD Argc, LPWSTR *Argv)
{
    WSADATA Wsa;
    DWORD Error, i, Wait;

    UNREFERENCED_PARAMETER(Argc);
    UNREFERENCED_PARAMETER(Argv);

    ServiceStatusHandle = RegisterServiceCtrlHandlerExW(SMBENG_SERVICE_NAME, ServiceControlHandler, NULL);
    if (ServiceStatusHandle == NULL)
        return;
    SetState(SERVICE_START_PENDING, NO_ERROR, 10000);

    ReadConfig();
    InitializeSRWLock(&SmbEng.Lock);
    InitializeListHead(&SmbEng.Conns);
    SmbEng.NextId = 0x10000;
    SmbEng.StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (SmbEng.StopEvent == NULL || WSAStartup(MAKEWORD(2, 2), &Wsa) != 0)
    {
        SetState(SERVICE_STOPPED, ERROR_NOT_ENOUGH_MEMORY, 0);
        return;
    }

    /* The service controller started mrxsmb for us (DependOnService) */
    Error = Attach();
    if (Error != ERROR_SUCCESS)
    {
        WSACleanup();
        SetState(SERVICE_STOPPED, Error, 0);
        return;
    }

    for (i = 0; i < SmbEngConfig.GetThreads; i++)
    {
        GetThreadHandles[i] = CreateThread(NULL, 0, GetThread, NULL, 0, NULL);
        if (GetThreadHandles[i] == NULL)
            break;
        GetThreadCount++;
    }
    if (GetThreadCount == 0)
    {
        Shutdown();
        WSACleanup();
        SetState(SERVICE_STOPPED, ERROR_NOT_ENOUGH_MEMORY, 0);
        return;
    }

    SmbEngLog(0, "attached (pid %lu, %lu request threads, idle %lu s, request limit %lu s)",
              GetCurrentProcessId(), GetThreadCount, SmbEngConfig.IdleSeconds, SmbEngConfig.RequestTimeoutSeconds);
    SetState(SERVICE_RUNNING, NO_ERROR, 0);

    Wait = SmbEngConfig.StatsSeconds ? SmbEngConfig.StatsSeconds * 1000 : INFINITE;
    while (WaitForSingleObject(SmbEng.StopEvent, Wait) == WAIT_TIMEOUT)
        LogStats();

    Error = (ServiceStatus.dwCurrentState == SERVICE_STOP_PENDING) ? NO_ERROR : ERROR_NETNAME_DELETED;
    SetState(SERVICE_STOP_PENDING, NO_ERROR, 30000);
    Shutdown();
    LogStats();
    WSACleanup();
    SmbEngLog(0, "stopped (%lu)", Error);
    /* An unrequested stop (detached by the driver) is a failure: the service controller's
     * recovery actions restart the engine */
    SetState(SERVICE_STOPPED, Error, 0);
}

int
wmain(int argc, WCHAR *argv[])
{
    SERVICE_TABLE_ENTRYW Table[] =
    {
        { SMBENG_SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if (!StartServiceCtrlDispatcherW(Table))
        return (int)GetLastError();
    return 0;
}
