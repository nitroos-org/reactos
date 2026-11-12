/*
 * PROJECT:     Local Security Authority Server DLL
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dll/win32/lsasrv/authport.c
 * PURPOSE:     LsaAuthenticationPort server routines
 * COPYRIGHT:   Copyright 2009 Eric Kohl
 */

#include "lsasrv.h"

#include <ndk/lpcfuncs.h>

static LIST_ENTRY LsapLogonContextList;

static HANDLE PortThreadHandle = NULL;
static HANDLE AuthPortHandle = NULL;

/*
 * The port context of a connection is an identifier, not the pointer to its LSAP_LOGON_CONTEXT: a
 * message queued for a connection can arrive after its context was freed (LPC_PORT_CLOSED after
 * LsaDeregisterLogonProcess) and the block can already belong to another connection.
 */
static ULONG_PTR LsapNextLogonContextId = 1;


/* FUNCTIONS ***************************************************************/

static
PLSAP_LOGON_CONTEXT
LsapFindLogonContext(
    _In_ PVOID PortContext)
{
    PLIST_ENTRY ListEntry;
    PLSAP_LOGON_CONTEXT Context;

    if (PortContext == NULL)
        return NULL;

    for (ListEntry = LsapLogonContextList.Flink;
         ListEntry != &LsapLogonContextList;
         ListEntry = ListEntry->Flink)
    {
        Context = CONTAINING_RECORD(ListEntry, LSAP_LOGON_CONTEXT, Entry);
        if (Context->ContextId == (ULONG_PTR)PortContext)
            return Context;
    }

    return NULL;
}


/* Releases a connection: its handles and its context. */
static VOID
LsapDestroyLogonContext(PLSAP_LOGON_CONTEXT LogonContext)
{
    RemoveEntryList(&LogonContext->Entry);

    if (LogonContext->ClientProcessHandle != NULL)
        NtClose(LogonContext->ClientProcessHandle);
    if (LogonContext->ConnectionHandle != NULL)
        NtClose(LogonContext->ConnectionHandle);

    RtlFreeHeap(RtlGetProcessHeap(), 0, LogonContext);
}


static NTSTATUS
LsapDeregisterLogonProcess(PLSA_API_MSG RequestMsg,
                           PLSAP_LOGON_CONTEXT LogonContext)
{
    TRACE("LsapDeregisterLogonProcess(%p %p)\n", RequestMsg, LogonContext);

    LsapDestroyLogonContext(LogonContext);

    return STATUS_SUCCESS;
}


static
BOOL
LsapIsTrustedClient(
    _In_ HANDLE ProcessHandle,
    _In_ PCLIENT_ID ClientId)
{
    LUID TcbPrivilege = {SE_TCB_PRIVILEGE, 0};
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ThreadHandle = NULL;
    HANDLE TokenHandle = NULL;
    PTOKEN_PRIVILEGES Privileges = NULL;
    ULONG Size, i;
    BOOL Trusted = FALSE;
    NTSTATUS Status;

    /* As on Windows, a thread that impersonates is judged by the token it impersonates */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenThread(&ThreadHandle,
                          THREAD_QUERY_INFORMATION,
                          &ObjectAttributes,
                          ClientId);
    if (NT_SUCCESS(Status))
    {
        Status = NtOpenThreadTokenEx(ThreadHandle,
                                     TOKEN_QUERY,
                                     TRUE,
                                     0,
                                     &TokenHandle);
        if (!NT_SUCCESS(Status))
            TokenHandle = NULL;
    }

    if (TokenHandle == NULL)
    {
        Status = NtOpenProcessToken(ProcessHandle,
                                    TOKEN_QUERY,
                                    &TokenHandle);
        if (!NT_SUCCESS(Status))
            goto done;
    }

    Status = NtQueryInformationToken(TokenHandle,
                                     TokenPrivileges,
                                     NULL,
                                     0,
                                     &Size);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL)
        goto done;

    Privileges = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (Privileges == NULL)
        goto done;

    Status = NtQueryInformationToken(TokenHandle,
                                     TokenPrivileges,
                                     Privileges,
                                     Size,
                                     &Size);
    if (!NT_SUCCESS(Status))
        goto done;

    for (i = 0; i < Privileges->PrivilegeCount; i++)
    {
        if (RtlEqualLuid(&Privileges->Privileges[i].Luid, &TcbPrivilege))
        {
            Trusted = TRUE;
            break;
        }
    }

done:
    if (Privileges != NULL)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Privileges);

    if (TokenHandle != NULL)
        NtClose(TokenHandle);

    if (ThreadHandle != NULL)
        NtClose(ThreadHandle);

    return Trusted;
}


static NTSTATUS
LsapCheckLogonProcess(PLSA_API_MSG RequestMsg,
                      PLSAP_LOGON_CONTEXT *LogonContext)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ProcessHandle = NULL;
    PLSAP_LOGON_CONTEXT Context = NULL;
    NTSTATUS Status;

    TRACE("LsapCheckLogonProcess(%p)\n", RequestMsg);

    TRACE("Client ID: %p %p\n", RequestMsg->h.ClientId.UniqueProcess, RequestMsg->h.ClientId.UniqueThread);

    InitializeObjectAttributes(&ObjectAttributes,
                               NULL,
                               0,
                               NULL,
                               NULL);

    Status = NtOpenProcess(&ProcessHandle,
                           PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
                           &ObjectAttributes,
                           &RequestMsg->h.ClientId);
    if (!NT_SUCCESS(Status))
    {
        TRACE("NtOpenProcess() failed (Status %lx)\n", Status);
        return Status;
    }

    /* Allocate the logon context */
    Context = RtlAllocateHeap(RtlGetProcessHeap(),
                              HEAP_ZERO_MEMORY,
                              sizeof(LSAP_LOGON_CONTEXT));
    if (Context == NULL)
    {
        NtClose(ProcessHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TRACE("New LogonContext: %p\n", Context);

    Context->ClientProcessHandle = ProcessHandle;
    Context->ContextId = LsapNextLogonContextId++;

    switch (RequestMsg->ConnectInfo.TrustedCaller)
    {
        case NO:
            Context->TrustedCaller = FALSE;
            break;

        /* The client cannot vouch for itself: a claim to be trusted is checked like CHECK */
        case YES:
        case CHECK:
        default:
            Context->TrustedCaller = LsapIsTrustedClient(ProcessHandle, &RequestMsg->h.ClientId);
            break;
    }

    TRACE("TrustedCaller: %u\n", Context->TrustedCaller);

    *LogonContext = Context;

    return STATUS_SUCCESS;
}


static NTSTATUS
LsapHandlePortConnection(PLSA_API_MSG RequestMsg)
{
    PLSAP_LOGON_CONTEXT LogonContext = NULL;
    HANDLE ConnectionHandle = NULL;
    BOOLEAN Accept;
    REMOTE_PORT_VIEW RemotePortView;
    NTSTATUS Status = STATUS_SUCCESS;

    TRACE("LsapHandlePortConnection(%p)\n", RequestMsg);

    TRACE("Logon Process Name: %s\n", RequestMsg->ConnectInfo.LogonProcessNameBuffer);

    if (RequestMsg->ConnectInfo.CreateContext != FALSE)
    {
        Status = LsapCheckLogonProcess(RequestMsg,
                                       &LogonContext);

        RequestMsg->ConnectInfo.OperationalMode = 0x43218765;

        RequestMsg->ConnectInfo.Status = Status;
    }

    if (NT_SUCCESS(Status))
    {
        Accept = TRUE;
    }
    else
    {
        Accept = FALSE;
    }

    RemotePortView.Length = sizeof(REMOTE_PORT_VIEW);
    Status = NtAcceptConnectPort(&ConnectionHandle,
                                 (LogonContext != NULL) ? (PVOID)LogonContext->ContextId : NULL,
                                 &RequestMsg->h,
                                 Accept,
                                 NULL,
                                 &RemotePortView);
    if (!NT_SUCCESS(Status))
    {
        ERR("NtAcceptConnectPort failed (Status 0x%lx)\n", Status);

        /* The connection never existed, release what the check opened */
        if (LogonContext != NULL)
        {
            NtClose(LogonContext->ClientProcessHandle);
            RtlFreeHeap(RtlGetProcessHeap(), 0, LogonContext);
        }
        return Status;
    }

    /* A rejected connection has no handle and no use for the context */
    if (Accept == FALSE && LogonContext != NULL)
    {
        NtClose(LogonContext->ClientProcessHandle);
        RtlFreeHeap(RtlGetProcessHeap(), 0, LogonContext);
        LogonContext = NULL;
    }

    if (Accept != FALSE)
    {
        if (LogonContext != NULL)
        {
            LogonContext->ConnectionHandle = ConnectionHandle;

            InsertHeadList(&LsapLogonContextList,
                           &LogonContext->Entry);
        }

        Status = NtCompleteConnectPort(ConnectionHandle);
        if (!NT_SUCCESS(Status))
        {
            ERR("NtCompleteConnectPort failed (Status 0x%lx)\n", Status);
            return Status;
        }
    }

    return Status;
}


NTSTATUS WINAPI
AuthPortThreadRoutine(PVOID Param)
{
    PLSAP_LOGON_CONTEXT LogonContext;
    PVOID PortContext = NULL;
    PLSA_API_MSG ReplyMsg = NULL;
    LSA_API_MSG RequestMsg;
    NTSTATUS Status;

    TRACE("AuthPortThreadRoutine() called\n");

    Status = STATUS_SUCCESS;

    for (;;)
    {
        TRACE("Reply: %p\n", ReplyMsg);
        Status = NtReplyWaitReceivePort(AuthPortHandle,
                                        &PortContext,
                                        (PPORT_MESSAGE)ReplyMsg,
                                        (PPORT_MESSAGE)&RequestMsg);
        if (!NT_SUCCESS(Status))
        {
            TRACE("NtReplyWaitReceivePort() failed (Status %lx)\n", Status);
            break;
        }

        /* A connection that is gone (or has no context) is not found */
        LogonContext = (RequestMsg.h.u2.s2.Type == LPC_CONNECTION_REQUEST) ?
                       NULL : LsapFindLogonContext(PortContext);

        TRACE("Received message\n");

        switch (RequestMsg.h.u2.s2.Type)
        {
            case LPC_CONNECTION_REQUEST:
                TRACE("Port connection request\n");
                Status = LsapHandlePortConnection(&RequestMsg);
                ReplyMsg = NULL;
                break;

            case LPC_PORT_CLOSED:
                TRACE("Port closed\n");
                /* The client went away without LsaDeregisterLogonProcess */
                if (LogonContext != NULL)
                    LsapDestroyLogonContext(LogonContext);
                ReplyMsg = NULL;
                break;

            case LPC_CLIENT_DIED:
                TRACE("Client died\n");
                if (LogonContext != NULL)
                    LsapDestroyLogonContext(LogonContext);
                ReplyMsg = NULL;
                break;

            default:
                TRACE("Received request (ApiNumber: %lu)\n", RequestMsg.ApiNumber);

                /* These requests need the context of the connection */
                if (LogonContext == NULL &&
                    (RequestMsg.ApiNumber == LSASS_REQUEST_CALL_AUTHENTICATION_PACKAGE ||
                     RequestMsg.ApiNumber == LSASS_REQUEST_LOGON_USER ||
                     RequestMsg.ApiNumber == LSASS_REQUEST_LOOKUP_AUTHENTICATION_PACKAGE ||
                     RequestMsg.ApiNumber == LSASS_REQUEST_DEREGISTER_LOGON_PROCESS))
                {
                    RequestMsg.Status = STATUS_INVALID_HANDLE;
                    ReplyMsg = &RequestMsg;
                    break;
                }

                switch (RequestMsg.ApiNumber)
                {
                    case LSASS_REQUEST_CALL_AUTHENTICATION_PACKAGE:
                        RequestMsg.Status = LsapCallAuthenticationPackage(&RequestMsg,
                                                                          LogonContext);
                        ReplyMsg = &RequestMsg;
                        break;

                    case LSASS_REQUEST_DEREGISTER_LOGON_PROCESS:

                        ReplyMsg = &RequestMsg;
                        RequestMsg.Status = STATUS_SUCCESS;
                        NtReplyPort(AuthPortHandle,
                                    &ReplyMsg->h);

                        LsapDeregisterLogonProcess(&RequestMsg,
                                                   LogonContext);

                        ReplyMsg = NULL;
                        break;

                    case LSASS_REQUEST_LOGON_USER:
                        RequestMsg.Status = LsapLogonUser(&RequestMsg,
                                                          LogonContext);
                        ReplyMsg = &RequestMsg;
                        break;

                    case LSASS_REQUEST_LOOKUP_AUTHENTICATION_PACKAGE:
                        RequestMsg.Status = LsapLookupAuthenticationPackage(&RequestMsg,
                                                                            LogonContext);
                        ReplyMsg = &RequestMsg;
                        break;

                    case LSASS_REQUEST_ENUM_LOGON_SESSIONS:
                        RequestMsg.Status = LsapEnumLogonSessions(&RequestMsg);
                        ReplyMsg = &RequestMsg;
                        break;

                    case LSASS_REQUEST_GET_LOGON_SESSION_DATA:
                        RequestMsg.Status = LsapGetLogonSessionData(&RequestMsg);
                        ReplyMsg = &RequestMsg;
                        break;

                    case LSASS_REQUEST_POLICY_CHANGE_NOTIFY:
                        RequestMsg.Status = LsapRegisterNotification(&RequestMsg);
                        ReplyMsg = &RequestMsg;
                        break;

                    default:
                        RequestMsg.Status = STATUS_INVALID_SYSTEM_SERVICE;
                        ReplyMsg = &RequestMsg;
                        break;
                }

                break;
        }
    }

    return STATUS_SUCCESS;
}


NTSTATUS
StartAuthenticationPort(VOID)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING PortName;
    DWORD ThreadId;
    UNICODE_STRING EventName;
    HANDLE EventHandle;
    NTSTATUS Status;

    TRACE("StartAuthenticationPort()\n");

    /* Initialize the logon context list */
    InitializeListHead(&LsapLogonContextList);

    RtlInitUnicodeString(&PortName,
                         L"\\LsaAuthenticationPort");

    InitializeObjectAttributes(&ObjectAttributes,
                               &PortName,
                               0,
                               NULL,
                               NULL);

    Status = NtCreatePort(&AuthPortHandle,
                          &ObjectAttributes,
                          sizeof(LSA_CONNECTION_INFO),
                          sizeof(LSA_API_MSG),
                          sizeof(LSA_API_MSG) * 32);
    if (!NT_SUCCESS(Status))
    {
        WARN("NtCreatePort() failed (Status %lx)\n", Status);
        return Status;
    }

    RtlInitUnicodeString(&EventName,
                         L"\\SECURITY\\LSA_AUTHENTICATION_INITIALIZED");
    InitializeObjectAttributes(&ObjectAttributes,
                               &EventName,
                               OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
                               NULL,
                               NULL);
    Status = NtOpenEvent(&EventHandle,
                         EVENT_MODIFY_STATE,
                         &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        TRACE("NtOpenEvent failed (Status 0x%08lx)\n", Status);

        Status = NtCreateEvent(&EventHandle,
                               EVENT_MODIFY_STATE,
                               &ObjectAttributes,
                               NotificationEvent,
                               FALSE);
        if (!NT_SUCCESS(Status))
        {
            WARN("NtCreateEvent failed (Status 0x%08lx)\n", Status);
            return Status;
        }
    }

    Status = NtSetEvent(EventHandle, NULL);
    NtClose(EventHandle);
    if (!NT_SUCCESS(Status))
    {
        WARN("NtSetEvent failed (Status 0x%08lx)\n", Status);
        return Status;
    }

    PortThreadHandle = CreateThread(NULL,
                                    0x1000,
                                    (LPTHREAD_START_ROUTINE)AuthPortThreadRoutine,
                                    NULL,
                                    0,
                                    &ThreadId);


    return STATUS_SUCCESS;
}

/* EOF */
