/*
 * PROJECT:     Authentication Package DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The local call of a same-machine NTLM exchange (ReactOS private messages, see ntlmros.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * When client and server of an NTLM exchange are on this machine, no password-derived response is computed or
 * checked: the server gets a copy of the client's own token. The table of contexts lives here, in the LSA:
 *
 *  - Issue (server, after the NEGOTIATE): a new context with a random id and session key, owned by the calling
 *    process. The LSA keeps a handle of that process with the context: its process id cannot be given to another
 *    process while the handle is open, so "the caller has the issuer's process id" means "the caller is the
 *    issuer". The id goes into the CHALLENGE.
 *  - Bind (client, after the CHALLENGE): the context named by the CHALLENGE gets a copy of the caller's token
 *    (the token its thread impersonates, else that of its process), at most at the impersonation level the client
 *    allows. The caller is judged by its token, never by the content of a message. A context binds once.
 *  - Accept (server, after the empty AUTHENTICATE): only the process that issued the context, and only once a client
 *    bound it, gets the token (a handle in its process) and the session key. The context is gone afterwards.
 *
 * A remote peer can send the messages but cannot call this package, so it cannot bind a context: the empty
 * AUTHENTICATE of a context nobody bound is refused, and a context of another process cannot be accepted.
 *
 * The table is bounded, and no caller can keep it full for others: every message first drops the contexts that
 * expired and those of processes that exited (a context is only good to the process that issued it), and a
 * process, and all the processes of one user together, may hold only part of the table.
 */

#include "../precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntlm);

/* An exchange needs its context from the NEGOTIATE to the AUTHENTICATE; Windows completes it up to about 5 minutes */
#define LOCAL_CALL_LIFETIME     (300LL * 10000000LL)  /* 5 minutes, in 100 ns, as on Windows */
#define LOCAL_CALL_MAX          4096
#define LOCAL_CALL_MAX_PROCESS  1024
#define LOCAL_CALL_MAX_USER     2048    /* all processes of one user together: others always find room */
#define LOCAL_CALL_SWEEP_PERIOD 30000   /* ms: a bound token leaves the LSA at most this long after its expiry */

/* A process that issued contexts: the LSA's own handle of it keeps its process id from being reused */
typedef struct _LOCAL_CALL_ISSUER
{
    LIST_ENTRY ListEntry;
    HANDLE Process;             /* PROCESS_QUERY_INFORMATION, the LSA's */
    ULONG_PTR ProcessId;
    PSID User;                  /* the user of its process token */
    BOOLEAN Exited;
    ULONG Contexts;             /* its contexts in the table; the issuer goes with the last one */
} LOCAL_CALL_ISSUER, *PLOCAL_CALL_ISSUER;

typedef struct _LOCAL_CALL_CONTEXT
{
    LIST_ENTRY ListEntry;
    ULONG64 ContextId;
    PLOCAL_CALL_ISSUER Issuer;
    LARGE_INTEGER Expires;
    UCHAR ServerChallenge[8];
    UCHAR SessionKey[16];
    HANDLE ClientToken;         /* the copy of the client's token, once a client bound the context */
} LOCAL_CALL_CONTEXT, *PLOCAL_CALL_CONTEXT;

static LIST_ENTRY LocalCallList;
static LIST_ENTRY LocalCallIssuers;
static RTL_CRITICAL_SECTION LocalCallLock;
static ULONG LocalCallCount;
static HANDLE LocalCallTimer;
static BOOLEAN LocalCallInitialized = FALSE;

VOID
MsvpInitLocalCall(VOID)
{
    if (LocalCallInitialized)
        return;
    InitializeListHead(&LocalCallList);
    InitializeListHead(&LocalCallIssuers);
    RtlInitializeCriticalSection(&LocalCallLock);
    LocalCallCount = 0;
    LocalCallInitialized = TRUE;
}

static
VOID
ReleaseIssuer(
    _In_ PLOCAL_CALL_ISSUER Issuer)
{
    if (--Issuer->Contexts != 0)
        return;
    RemoveEntryList(&Issuer->ListEntry);
    NtClose(Issuer->Process);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Issuer->User);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Issuer);
}

/* The issuer record of the calling process (made if it has none yet), with one more context counted */
static
PLOCAL_CALL_ISSUER
ReferenceIssuer(
    _In_ HANDLE Process,
    _In_ ULONG_PTR ProcessId,
    _In_ PSID User)
{
    PLOCAL_CALL_ISSUER Issuer;
    PLIST_ENTRY Entry;
    NTSTATUS Status;

    /* the LSA holds a handle of every process in the list: a process with that id is that process */
    for (Entry = LocalCallIssuers.Flink; Entry != &LocalCallIssuers; Entry = Entry->Flink)
    {
        Issuer = CONTAINING_RECORD(Entry, LOCAL_CALL_ISSUER, ListEntry);
        if (Issuer->ProcessId == ProcessId)
        {
            Issuer->Contexts++;
            return Issuer;
        }
    }

    Issuer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Issuer));
    if (Issuer == NULL)
        return NULL;
    Issuer->User = RtlAllocateHeap(RtlGetProcessHeap(), 0, RtlLengthSid(User));
    if (Issuer->User == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Issuer);
        return NULL;
    }
    RtlCopySid(RtlLengthSid(User), Issuer->User, User);
    Status = NtDuplicateObject(NtCurrentProcess(), Process, NtCurrentProcess(), &Issuer->Process,
                               PROCESS_QUERY_INFORMATION, 0, 0);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Issuer->User);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Issuer);
        return NULL;
    }
    Issuer->ProcessId = ProcessId;
    Issuer->Contexts = 1;
    InsertTailList(&LocalCallIssuers, &Issuer->ListEntry);
    return Issuer;
}

static
VOID
FreeLocalCall(
    _In_ PLOCAL_CALL_CONTEXT Context)
{
    RemoveEntryList(&Context->ListEntry);
    LocalCallCount--;
    if (Context->ClientToken != NULL)
        NtClose(Context->ClientToken);
    ReleaseIssuer(Context->Issuer);
    RtlSecureZeroMemory(Context, sizeof(*Context));
    RtlFreeHeap(RtlGetProcessHeap(), 0, Context);
}

/* The contexts nobody completed in time, and those of processes that exited (nobody can complete them) */
static
VOID
SweepLocalCalls(
    _In_ PLARGE_INTEGER Now)
{
    KERNEL_USER_TIMES Times;
    PLIST_ENTRY Entry;

    /* a process that exited has an exit time (its exit code says nothing: a live process may report STILL_ACTIVE) */
    for (Entry = LocalCallIssuers.Flink; Entry != &LocalCallIssuers; Entry = Entry->Flink)
    {
        PLOCAL_CALL_ISSUER Issuer = CONTAINING_RECORD(Entry, LOCAL_CALL_ISSUER, ListEntry);

        if (!Issuer->Exited &&
            NT_SUCCESS(NtQueryInformationProcess(Issuer->Process, ProcessTimes, &Times, sizeof(Times), NULL)) &&
            Times.ExitTime.QuadPart != 0)
        {
            Issuer->Exited = TRUE;
        }
    }

    Entry = LocalCallList.Flink;
    while (Entry != &LocalCallList)
    {
        PLOCAL_CALL_CONTEXT Context = CONTAINING_RECORD(Entry, LOCAL_CALL_CONTEXT, ListEntry);

        Entry = Entry->Flink;
        if (Context->Expires.QuadPart <= Now->QuadPart || Context->Issuer->Exited)
            FreeLocalCall(Context);
    }
}

/* The sweep without a message: a context a client bound holds a copy of its token (and so its logon session) */
static
VOID
NTAPI
LocalCallTimerCallback(
    _In_ PVOID Parameter,
    _In_ BOOLEAN TimerOrWaitFired)
{
    LARGE_INTEGER Now;

    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(TimerOrWaitFired);

    NtQuerySystemTime(&Now);
    RtlEnterCriticalSection(&LocalCallLock);
    SweepLocalCalls(&Now);
    RtlLeaveCriticalSection(&LocalCallLock);
}

static
PLOCAL_CALL_CONTEXT
FindLocalCall(
    _In_ ULONG64 ContextId,
    _In_ PLARGE_INTEGER Now)
{
    PLIST_ENTRY Entry;

    for (Entry = LocalCallList.Flink; Entry != &LocalCallList; Entry = Entry->Flink)
    {
        PLOCAL_CALL_CONTEXT Context = CONTAINING_RECORD(Entry, LOCAL_CALL_CONTEXT, ListEntry);

        if (Context->ContextId == ContextId)
            return Context->Expires.QuadPart > Now->QuadPart ? Context : NULL;
    }
    return NULL;
}

/* The process of the caller (a handle that stays the LSA's) and its id */
static
NTSTATUS
GetCallerProcess(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _Out_opt_ PHANDLE ProcessHandle,
    _Out_ PULONG_PTR ProcessId)
{
    PROCESS_BASIC_INFORMATION Basic;
    HANDLE Process = NULL;
    NTSTATUS Status;

    if (DispatchTable.GetClientProcess == NULL)
        return STATUS_NOT_SUPPORTED;
    Status = DispatchTable.GetClientProcess(ClientRequest, &Process);
    if (!NT_SUCCESS(Status))
        return Status;
    if (Process == NULL)
        return STATUS_INVALID_HANDLE;

    Status = NtQueryInformationProcess(Process, ProcessBasicInformation, &Basic, sizeof(Basic), NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    if (ProcessHandle != NULL)
        *ProcessHandle = Process;
    *ProcessId = Basic.UniqueProcessId;
    return STATUS_SUCCESS;
}

/* The user of the caller's process token (to free from the process heap) */
static
NTSTATUS
GetProcessUser(
    _In_ HANDLE Process,
    _Out_ PSID *User)
{
    PTOKEN_USER UserInfo = NULL;
    HANDLE Token;
    ULONG Size = 0;
    NTSTATUS Status;

    *User = NULL;
    Status = NtOpenProcessToken(Process, TOKEN_QUERY, &Token);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = NtQueryInformationToken(Token, TokenUser, NULL, 0, &Size);
    if (Status == STATUS_BUFFER_TOO_SMALL && Size != 0)
    {
        UserInfo = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (UserInfo == NULL)
            Status = STATUS_INSUFFICIENT_RESOURCES;
        else
            Status = NtQueryInformationToken(Token, TokenUser, UserInfo, Size, &Size);
    }
    else if (NT_SUCCESS(Status))
    {
        Status = STATUS_INTERNAL_ERROR;
    }
    NtClose(Token);
    if (NT_SUCCESS(Status) && !RtlValidSid(UserInfo->User.Sid))
        Status = STATUS_INVALID_SID;
    if (NT_SUCCESS(Status))
    {
        *User = RtlAllocateHeap(RtlGetProcessHeap(), 0, RtlLengthSid(UserInfo->User.Sid));
        if (*User == NULL)
            Status = STATUS_INSUFFICIENT_RESOURCES;
        else
            RtlCopySid(RtlLengthSid(UserInfo->User.Sid), *User, UserInfo->User.Sid);
    }
    if (UserInfo != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, UserInfo);
    return Status;
}

/* The answer in the caller's memory */
static
NTSTATUS
ReturnToClient(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ PVOID Data,
    _In_ ULONG Size,
    _Out_ PVOID *ProtocolReturnBuffer,
    _Out_ PULONG ReturnBufferLength)
{
    NTLM_CLIENT_BUFFER Buffer;
    NTSTATUS Status;

    Status = NtlmAllocateClientBuffer(ClientRequest, Size, &Buffer);
    if (!NT_SUCCESS(Status))
        return Status;
    RtlCopyMemory(Buffer.LocalBuffer, Data, Size);
    Status = NtlmCopyToClientBuffer(ClientRequest, Size, &Buffer);
    RtlSecureZeroMemory(Buffer.LocalBuffer, Size);
    if (NT_SUCCESS(Status))
    {
        *ProtocolReturnBuffer = Buffer.ClientBaseAddress;
        *ReturnBufferLength = Size;
    }
    /* The client's copy stays when all went well */
    NtlmFreeClientBuffer(ClientRequest, !NT_SUCCESS(Status), &Buffer);
    return Status;
}

static
NTSTATUS
MsvpLocalCallIssue(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ PVOID ProtocolSubmitBuffer,
    _In_ ULONG SubmitBufferLength,
    _Out_ PVOID *ProtocolReturnBuffer,
    _Out_ PULONG ReturnBufferLength)
{
    PMSV1_0_ROS_NTLM_LOCAL_ISSUE Request = ProtocolSubmitBuffer;
    MSV1_0_ROS_NTLM_LOCAL_CONTEXT Reply;
    PLOCAL_CALL_CONTEXT Context;
    PLOCAL_CALL_ISSUER Issuer;
    LARGE_INTEGER Now;
    ULONG_PTR ProcessId;
    HANDLE Process;
    PLIST_ENTRY Entry;
    PSID User;
    ULONG Mine = 0, Users = 0;
    NTSTATUS Status;

    if (SubmitBufferLength < sizeof(*Request))
        return STATUS_INVALID_PARAMETER;

    Status = GetCallerProcess(ClientRequest, &Process, &ProcessId);
    if (!NT_SUCCESS(Status))
        return Status;
    Status = GetProcessUser(Process, &User);
    if (!NT_SUCCESS(Status))
        return Status;

    Context = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Context));
    if (Context == NULL)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, User);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(Context->ServerChallenge, Request->ServerChallenge, sizeof(Context->ServerChallenge));
    if (!RtlGenRandom(Context->SessionKey, sizeof(Context->SessionKey)))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Context);
        RtlFreeHeap(RtlGetProcessHeap(), 0, User);
        return STATUS_INTERNAL_ERROR;
    }

    NtQuerySystemTime(&Now);
    Context->Expires.QuadPart = Now.QuadPart + LOCAL_CALL_LIFETIME;

    RtlEnterCriticalSection(&LocalCallLock);
    SweepLocalCalls(&Now);
    /* the record of the caller is that of this process (see ReferenceIssuer) */
    for (Entry = LocalCallIssuers.Flink; Entry != &LocalCallIssuers; Entry = Entry->Flink)
    {
        Issuer = CONTAINING_RECORD(Entry, LOCAL_CALL_ISSUER, ListEntry);
        if (Issuer->ProcessId == ProcessId)
            Mine = Issuer->Contexts;
        if (RtlEqualSid(Issuer->User, User))
            Users += Issuer->Contexts;
    }
    if (LocalCallCount >= LOCAL_CALL_MAX || Mine >= LOCAL_CALL_MAX_PROCESS || Users >= LOCAL_CALL_MAX_USER)
    {
        RtlLeaveCriticalSection(&LocalCallLock);
        RtlSecureZeroMemory(Context, sizeof(*Context));
        RtlFreeHeap(RtlGetProcessHeap(), 0, Context);
        RtlFreeHeap(RtlGetProcessHeap(), 0, User);
        WARN("too many local call contexts (%lu, %lu of the caller, %lu of its user)\n", LocalCallCount, Mine, Users);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* a random id that no context has (and never 0: 0 is "no local call") */
    do
    {
        if (!RtlGenRandom(&Context->ContextId, sizeof(Context->ContextId)))
        {
            RtlLeaveCriticalSection(&LocalCallLock);
            RtlSecureZeroMemory(Context, sizeof(*Context));
            RtlFreeHeap(RtlGetProcessHeap(), 0, Context);
            RtlFreeHeap(RtlGetProcessHeap(), 0, User);
            return STATUS_INTERNAL_ERROR;
        }
    } while (Context->ContextId == 0 || FindLocalCall(Context->ContextId, &Now) != NULL);
    Context->Issuer = ReferenceIssuer(Process, ProcessId, User);
    RtlFreeHeap(RtlGetProcessHeap(), 0, User);
    if (Context->Issuer == NULL)
    {
        RtlLeaveCriticalSection(&LocalCallLock);
        RtlSecureZeroMemory(Context, sizeof(*Context));
        RtlFreeHeap(RtlGetProcessHeap(), 0, Context);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    InsertTailList(&LocalCallList, &Context->ListEntry);
    LocalCallCount++;
    Reply.ContextId = Context->ContextId;
    RtlLeaveCriticalSection(&LocalCallLock);

    Reply.MessageType = MsV1_0RosNtlmLocalIssue;
    Reply.Reserved = 0;
    Status = ReturnToClient(ClientRequest, &Reply, sizeof(Reply), ProtocolReturnBuffer, ReturnBufferLength);
    if (!NT_SUCCESS(Status))
    {
        RtlEnterCriticalSection(&LocalCallLock);
        Context = FindLocalCall(Reply.ContextId, &Now);
        if (Context != NULL)
            FreeLocalCall(Context);
        RtlLeaveCriticalSection(&LocalCallLock);
    }
    return Status;
}

/* A copy of the caller's token for the server, at most at the level the client allows */
static
NTSTATUS
CopyCallerToken(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ SECURITY_IMPERSONATION_LEVEL Level,
    _Out_ PHANDLE Copy)
{
    SECURITY_QUALITY_OF_SERVICE Qos;
    OBJECT_ATTRIBUTES ObjectAttributes;
    SECURITY_IMPERSONATION_LEVEL TokenLevel;
    TOKEN_TYPE Type;
    HANDLE Token = NULL;
    ULONG Size;
    NTSTATUS Status;

    *Copy = NULL;
    if (DispatchTable.OpenClientToken == NULL)
        return STATUS_NOT_SUPPORTED;
    Status = DispatchTable.OpenClientToken(ClientRequest, &Token);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = NtQueryInformationToken(Token, TokenType, &Type, sizeof(Type), &Size);
    if (NT_SUCCESS(Status) && Type == TokenImpersonation)
    {
        /* a thread that only identifies the user (or is anonymous) cannot act as the user towards a server */
        Status = NtQueryInformationToken(Token, TokenImpersonationLevel, &TokenLevel, sizeof(TokenLevel), &Size);
        if (NT_SUCCESS(Status) && TokenLevel < SecurityImpersonation)
            Status = STATUS_BAD_IMPERSONATION_LEVEL;
    }
    if (!NT_SUCCESS(Status))
    {
        NtClose(Token);
        return Status;
    }

    Qos.Length = sizeof(Qos);
    Qos.ImpersonationLevel = Level;
    Qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    Qos.EffectiveOnly = FALSE;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ObjectAttributes.SecurityQualityOfService = &Qos;
    Status = NtDuplicateToken(Token, TOKEN_ALL_ACCESS, &ObjectAttributes, FALSE, TokenImpersonation, Copy);
    NtClose(Token);
    return Status;
}

static
NTSTATUS
MsvpLocalCallBind(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ PVOID ProtocolSubmitBuffer,
    _In_ ULONG SubmitBufferLength,
    _Out_ PVOID *ProtocolReturnBuffer,
    _Out_ PULONG ReturnBufferLength)
{
    PMSV1_0_ROS_NTLM_LOCAL_BIND Request = ProtocolSubmitBuffer;
    MSV1_0_ROS_NTLM_LOCAL_RESPONSE Reply;
    SECURITY_IMPERSONATION_LEVEL Level;
    PLOCAL_CALL_CONTEXT Context;
    LARGE_INTEGER Now;
    HANDLE Copy = NULL;
    NTSTATUS Status;

    if (SubmitBufferLength < sizeof(*Request) || Request->ContextId == 0)
        return STATUS_INVALID_PARAMETER;

    /* NTLM does not delegate: identification when the client asks for it, impersonation otherwise */
    Level = (Request->ImpersonationLevel <= SecurityIdentification) ? SecurityIdentification : SecurityImpersonation;
    Status = CopyCallerToken(ClientRequest, Level, &Copy);
    if (!NT_SUCCESS(Status))
    {
        WARN("no token of the client for the local call (0x%08lx)\n", Status);
        return Status;
    }

    RtlZeroMemory(&Reply, sizeof(Reply));
    NtQuerySystemTime(&Now);
    RtlEnterCriticalSection(&LocalCallLock);
    SweepLocalCalls(&Now);
    Context = FindLocalCall(Request->ContextId, &Now);
    if (Context == NULL || Context->ClientToken != NULL ||
        RtlCompareMemory(Context->ServerChallenge, Request->ServerChallenge, sizeof(Context->ServerChallenge)) !=
            sizeof(Context->ServerChallenge))
    {
        RtlLeaveCriticalSection(&LocalCallLock);
        NtClose(Copy);
        return STATUS_NOT_FOUND;
    }
    Context->ClientToken = Copy;
    RtlCopyMemory(Reply.SessionKey, Context->SessionKey, sizeof(Reply.SessionKey));
    RtlLeaveCriticalSection(&LocalCallLock);

    /* the timer is made outside the lock its callback takes (if it cannot be made, the next message sweeps) */
    if (LocalCallTimer == NULL)
    {
        HANDLE Timer = NULL;

        if (NT_SUCCESS(RtlCreateTimer(NULL, &Timer, LocalCallTimerCallback, NULL, LOCAL_CALL_SWEEP_PERIOD,
                                      LOCAL_CALL_SWEEP_PERIOD, WT_EXECUTEINTIMERTHREAD)) &&
            InterlockedCompareExchangePointer(&LocalCallTimer, Timer, NULL) != NULL)
        {
            RtlDeleteTimer(NULL, Timer, NULL);
        }
    }

    Reply.MessageType = MsV1_0RosNtlmLocalBind;
    Status = ReturnToClient(ClientRequest, &Reply, sizeof(Reply), ProtocolReturnBuffer, ReturnBufferLength);
    RtlSecureZeroMemory(&Reply, sizeof(Reply));
    if (!NT_SUCCESS(Status))
    {
        /* the client does not know the key: the context cannot complete */
        RtlEnterCriticalSection(&LocalCallLock);
        Context = FindLocalCall(Request->ContextId, &Now);
        if (Context != NULL)
            FreeLocalCall(Context);
        RtlLeaveCriticalSection(&LocalCallLock);
    }
    return Status;
}

/*
 * The context the caller issued: NULL for any other (a context of another process looks like none at all).
 * The issuer's process id identifies the process: the LSA holds a handle of the issuer, so no other process can
 * have been given its id, even after the issuer exited.
 */
static
PLOCAL_CALL_CONTEXT
FindOwnLocalCall(
    _In_ ULONG64 ContextId,
    _In_ ULONG_PTR ProcessId,
    _In_ PLARGE_INTEGER Now)
{
    PLOCAL_CALL_CONTEXT Context = FindLocalCall(ContextId, Now);

    if (Context == NULL || Context->Issuer->ProcessId != ProcessId)
        return NULL;
    return Context;
}

static
NTSTATUS
MsvpLocalCallAccept(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ PVOID ProtocolSubmitBuffer,
    _In_ ULONG SubmitBufferLength,
    _Out_ PVOID *ProtocolReturnBuffer,
    _Out_ PULONG ReturnBufferLength)
{
    PMSV1_0_ROS_NTLM_LOCAL_ACCEPT Request = ProtocolSubmitBuffer;
    MSV1_0_ROS_NTLM_LOCAL_RESPONSE Reply;
    PLOCAL_CALL_CONTEXT Context;
    LARGE_INTEGER Now;
    ULONG_PTR ProcessId;
    HANDLE Process = NULL, Token, Remote = NULL;
    NTSTATUS Status;

    if (SubmitBufferLength < sizeof(*Request) || Request->ContextId == 0)
        return STATUS_INVALID_PARAMETER;

    Status = GetCallerProcess(ClientRequest, &Process, &ProcessId);
    if (!NT_SUCCESS(Status))
        return Status;

    RtlZeroMemory(&Reply, sizeof(Reply));
    NtQuerySystemTime(&Now);
    RtlEnterCriticalSection(&LocalCallLock);
    SweepLocalCalls(&Now);
    Context = FindOwnLocalCall(Request->ContextId, ProcessId, &Now);
    if (Context == NULL)
    {
        RtlLeaveCriticalSection(&LocalCallLock);
        return STATUS_NOT_FOUND;
    }
    if (Context->ClientToken == NULL)
    {
        /* no client on this machine answered this CHALLENGE: the AUTHENTICATE came from elsewhere */
        FreeLocalCall(Context);
        RtlLeaveCriticalSection(&LocalCallLock);
        WARN("local call context of no client\n");
        return STATUS_LOGON_FAILURE;
    }
    /* the context completes once: it leaves the table with its token */
    Token = Context->ClientToken;
    Context->ClientToken = NULL;
    RtlCopyMemory(Reply.SessionKey, Context->SessionKey, sizeof(Reply.SessionKey));
    FreeLocalCall(Context);
    RtlLeaveCriticalSection(&LocalCallLock);

    /* the LSA's handle goes whether or not the server gets its own */
    Status = NtDuplicateObject(NtCurrentProcess(), Token, Process, &Remote, 0, 0, DUPLICATE_SAME_ACCESS);
    NtClose(Token);
    if (!NT_SUCCESS(Status))
    {
        RtlSecureZeroMemory(&Reply, sizeof(Reply));
        return Status;
    }

    Reply.MessageType = MsV1_0RosNtlmLocalAccept;
    Reply.TokenHandle = (ULONG64)(ULONG_PTR)Remote;
    Status = ReturnToClient(ClientRequest, &Reply, sizeof(Reply), ProtocolReturnBuffer, ReturnBufferLength);
    RtlSecureZeroMemory(&Reply, sizeof(Reply));
    if (!NT_SUCCESS(Status))
        NtDuplicateObject(Process, Remote, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
    return Status;
}

static
NTSTATUS
MsvpLocalCallDelete(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ PVOID ProtocolSubmitBuffer,
    _In_ ULONG SubmitBufferLength)
{
    PMSV1_0_ROS_NTLM_LOCAL_CONTEXT Request = ProtocolSubmitBuffer;
    PLOCAL_CALL_CONTEXT Context;
    LARGE_INTEGER Now;
    ULONG_PTR ProcessId;
    NTSTATUS Status;

    if (SubmitBufferLength < sizeof(*Request) || Request->ContextId == 0)
        return STATUS_INVALID_PARAMETER;

    Status = GetCallerProcess(ClientRequest, NULL, &ProcessId);
    if (!NT_SUCCESS(Status))
        return Status;

    NtQuerySystemTime(&Now);
    RtlEnterCriticalSection(&LocalCallLock);
    SweepLocalCalls(&Now);
    Context = FindOwnLocalCall(Request->ContextId, ProcessId, &Now);
    if (Context != NULL)
        FreeLocalCall(Context);
    RtlLeaveCriticalSection(&LocalCallLock);
    return Context != NULL ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* The messages of the local call, for any caller (secur32 connects untrusted) */
NTSTATUS
MsvpRosNtlmLocalCall(
    _In_ PLSA_CLIENT_REQUEST ClientRequest,
    _In_ ULONG MessageType,
    _In_ PVOID ProtocolSubmitBuffer,
    _In_ ULONG SubmitBufferLength,
    _Out_ PVOID *ProtocolReturnBuffer,
    _Out_ PULONG ReturnBufferLength,
    _Out_ PNTSTATUS ProtocolStatus)
{
    *ProtocolStatus = STATUS_SUCCESS;
    *ProtocolReturnBuffer = NULL;
    *ReturnBufferLength = 0;

    if (!LocalCallInitialized)
        return STATUS_NOT_SUPPORTED;

    switch (MessageType)
    {
        case MsV1_0RosNtlmLocalIssue:
            return MsvpLocalCallIssue(ClientRequest, ProtocolSubmitBuffer, SubmitBufferLength,
                                      ProtocolReturnBuffer, ReturnBufferLength);
        case MsV1_0RosNtlmLocalBind:
            return MsvpLocalCallBind(ClientRequest, ProtocolSubmitBuffer, SubmitBufferLength,
                                     ProtocolReturnBuffer, ReturnBufferLength);
        case MsV1_0RosNtlmLocalAccept:
            return MsvpLocalCallAccept(ClientRequest, ProtocolSubmitBuffer, SubmitBufferLength,
                                       ProtocolReturnBuffer, ReturnBufferLength);
        case MsV1_0RosNtlmLocalDelete:
            return MsvpLocalCallDelete(ClientRequest, ProtocolSubmitBuffer, SubmitBufferLength);
        default:
            return STATUS_INVALID_PARAMETER;
    }
}
