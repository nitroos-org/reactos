/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/session.c
 * PURPOSE:         CSR Server DLL Session Implementation
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES *******************************************************************/

#include "srv.h"

#define NDEBUG
#include <debug.h>

/* DATA ***********************************************************************/

RTL_CRITICAL_SECTION CsrNtSessionLock;
LIST_ENTRY CsrNtSessionList;

const PSB_API_ROUTINE CsrServerSbApiDispatch[SbpMaxApiNumber - SbpCreateSession] =
{
    CsrSbCreateSession,
    CsrSbTerminateSession,
    CsrSbForeignSessionComplete,
    CsrSbCreateProcess,
    CsrSbCreateRemoteProcess
};

#if DBG
const PCSTR CsrServerSbApiName[SbpMaxApiNumber - SbpCreateSession + 1] =
{
    "SbCreateSession",
    "SbTerminateSession",
    "SbForeignSessionComplete",
    "SbCreateProcess",
    "SbCreateRemoteProcess",
    "Unknown CSR Sb Api Number"
};
#endif

/* PRIVATE FUNCTIONS **********************************************************/

/*++
 * @name CsrInitializeNtSessionList
 *
 * The CsrInitializeNtSessionList routine sets up support for CSR Sessions.
 *
 * @param None
 *
 * @return None
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrInitializeNtSessionList(VOID)
{
    /* Initialize the Session List */
    InitializeListHead(&CsrNtSessionList);

    /* Initialize the Session Lock */
    return RtlInitializeCriticalSection(&CsrNtSessionLock);
}

/*++
 * @name CsrAllocateNtSession
 *
 * The CsrAllocateNtSession routine allocates a new CSR NT Session.
 *
 * @param SessionId
 *        Session ID of the CSR NT Session to allocate.
 *
 * @return Pointer to the newly allocated CSR NT Session.
 *
 * @remarks None.
 *
 *--*/
PCSR_NT_SESSION
NTAPI
CsrAllocateNtSession(IN ULONG SessionId)
{
    PCSR_NT_SESSION NtSession;

    /* Allocate an NT Session Object */
    NtSession = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, sizeof(CSR_NT_SESSION));
    if (NtSession)
    {
        /* Setup the Session Object */
        NtSession->SessionId = SessionId;
        NtSession->ReferenceCount = 1;

        /* Insert it into the Session List */
        CsrAcquireNtSessionLock();
        InsertHeadList(&CsrNtSessionList, &NtSession->SessionLink);
        CsrReleaseNtSessionLock();
    }
    else
    {
        ASSERT(NtSession != NULL);
    }

    /* Return the Session (or NULL) */
    return NtSession;
}

/*++
 * @name CsrReferenceNtSession
 *
 * The CsrReferenceNtSession increases the reference count of a CSR NT Session.
 *
 * @param Session
 *        Pointer to the CSR NT Session to reference.
 *
 * @return None.
 *
 * @remarks None.
 *
 *--*/
VOID
NTAPI
CsrReferenceNtSession(IN PCSR_NT_SESSION Session)
{
    /* Acquire the lock */
    CsrAcquireNtSessionLock();

    /* Sanity checks */
    ASSERT(!IsListEmpty(&Session->SessionLink));
    ASSERT(Session->SessionId != 0);
    ASSERT(Session->ReferenceCount != 0);

    /* Increase the reference count */
    Session->ReferenceCount++;

    /* Release the lock */
    CsrReleaseNtSessionLock();
}

/*++
 * @name CsrDereferenceNtSession
 *
 * The CsrDereferenceNtSession decreases the reference count of a
 * CSR NT Session.
 *
 * @param Session
 *        Pointer to the CSR NT Session to reference.
 *
 * @param ExitStatus
 *        If this is the last reference to the session, this argument
 *        specifies the exit status.
 *
 * @return None.
 *
 * @remarks CsrDereferenceNtSession will complete the session if
 *          the last reference to it has been closed.
 *
 *--*/
VOID
NTAPI
CsrDereferenceNtSession(IN PCSR_NT_SESSION Session,
                        IN NTSTATUS ExitStatus)
{
    /* Acquire the lock */
    CsrAcquireNtSessionLock();

    /* Sanity checks */
    ASSERT(!IsListEmpty(&Session->SessionLink));
    ASSERT(Session->SessionId != 0);
    ASSERT(Session->ReferenceCount != 0);

    /* Dereference the Session Object */
    if ((--Session->ReferenceCount) == 0)
    {
        /* Remove it from the list */
        RemoveEntryList(&Session->SessionLink);

        /* Release the lock */
        CsrReleaseNtSessionLock();

        /* Tell SM that we're done here */
        SmSessionComplete(CsrSmApiPort, Session->SessionId, ExitStatus);

        /* Free the Session Object */
        RtlFreeHeap(CsrHeap, 0, Session);
    }
    else
    {
        /* Release the lock, the Session is still active */
        CsrReleaseNtSessionLock();
    }
}

/* SESSION MANAGER FUNCTIONS **************************************************/

/*++
 * @name CsrSbCreateSession
 *
 * The CsrSbCreateSession API is called by the Session Manager whenever a new
 * session is created.
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbCreateSession routine will initialize a new CSR NT
 *          Session and allocate a new CSR Process for the subsystem process.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbCreateSession(IN PSB_API_MSG ApiMessage)
{
    PSB_CREATE_SESSION_MSG CreateSession = &ApiMessage->u.CreateSession;
    HANDLE hProcess, hThread;
    PCSR_PROCESS CsrProcess;
    PCSR_THREAD CsrThread;
    PCSR_SERVER_DLL ServerDll;
    PVOID ProcessData;
    NTSTATUS Status;
    KERNEL_USER_TIMES KernelTimes;
    ULONG i;

    /* Save the Process and Thread Handles */
    hProcess = CreateSession->ProcessInfo.ProcessHandle;
    hThread = CreateSession->ProcessInfo.ThreadHandle;

    /* Lock the Processes */
    CsrAcquireProcessLock();

    /* Allocate a new process */
    CsrProcess = CsrAllocateProcess();
    if (!CsrProcess)
    {
        /* Fail */
        ApiMessage->ReturnValue = STATUS_NO_MEMORY;
        CsrReleaseProcessLock();
        return TRUE;
    }

    /* Set the Exception Port for us */
    Status = NtSetInformationProcess(hProcess,
                                     ProcessExceptionPort,
                                     &CsrApiPort,
                                     sizeof(CsrApiPort));

    /* Check for success */
    if (!NT_SUCCESS(Status))
    {
        /* Fail the request */
        CsrDeallocateProcess(CsrProcess);
        CsrReleaseProcessLock();

        /* Strange as it seems, NTSTATUSes are actually returned */
        return (BOOLEAN)STATUS_NO_MEMORY;
    }

    /* Get the Create Time */
    Status = NtQueryInformationThread(hThread,
                                      ThreadTimes,
                                      &KernelTimes,
                                      sizeof(KernelTimes),
                                      NULL);

    /* Check for success */
    if (!NT_SUCCESS(Status))
    {
        /* Fail the request */
        CsrDeallocateProcess(CsrProcess);
        CsrReleaseProcessLock();

        /* Strange as it seems, NTSTATUSes are actually returned */
        return (BOOLEAN)Status;
    }

    /* Allocate a new Thread */
    CsrThread = CsrAllocateThread(CsrProcess);
    if (!CsrThread)
    {
        /* Fail the request */
        CsrDeallocateProcess(CsrProcess);
        CsrReleaseProcessLock();

        ApiMessage->ReturnValue = STATUS_NO_MEMORY;
        return TRUE;
    }

    /* Setup the Thread Object */
    CsrThread->CreateTime = KernelTimes.CreateTime;
    CsrThread->ClientId = CreateSession->ProcessInfo.ClientId;
    CsrThread->ThreadHandle = hThread;
    ProtectHandle(hThread);
    CsrThread->Flags = 0;

    /* Insert it into the Process List */
    Status = CsrInsertThread(CsrProcess, CsrThread);
    if (!NT_SUCCESS(Status))
    {
        /* Bail out */
        CsrDeallocateProcess(CsrProcess);
        CsrDeallocateThread(CsrThread);
        CsrReleaseProcessLock();

        /* Strange as it seems, NTSTATUSes are actually returned */
        return (BOOLEAN)Status;
    }

    /* Setup Process Data */
    CsrProcess->ClientId = CreateSession->ProcessInfo.ClientId;
    CsrProcess->ProcessHandle = hProcess;
    CsrProcess->NtSession = CsrAllocateNtSession(CreateSession->SessionId);

    /* Set the Process Priority */
    CsrSetBackgroundPriority(CsrProcess);

    /* Get the first data location */
    ProcessData = &CsrProcess->ServerData[CSR_SERVER_DLL_MAX];

    /* Loop every DLL */
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++)
    {
        /* Get the current Server */
        ServerDll = CsrLoadedServerDll[i];

        /* Check if the DLL is loaded and has Process Data */
        if (ServerDll && ServerDll->SizeOfProcessData)
        {
            /* Write the pointer to the data */
            CsrProcess->ServerData[i] = ProcessData;

            /* Move to the next data location */
            ProcessData = (PVOID)((ULONG_PTR)ProcessData +
                                  ServerDll->SizeOfProcessData);
        }
        else
        {
            /* Nothing for this Process */
            CsrProcess->ServerData[i] = NULL;
        }
    }

    /* Insert the Process */
    CsrInsertProcess(NULL, CsrProcess);

    /* Activate the Thread */
    ApiMessage->ReturnValue = NtResumeThread(hThread, NULL);

    /* Release lock and return */
    CsrReleaseProcessLock();
    return TRUE;
}

/*++
 * @name CsrSbForeignSessionComplete
 *
 * The CsrSbForeignSessionComplete API is called by the Session Manager
 * whenever a foreign session is completed (ie: terminated).
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbForeignSessionComplete API is not yet implemented.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbForeignSessionComplete(IN PSB_API_MSG ApiMessage)
{
    /* Deprecated/Unimplemented in NT */
    ApiMessage->ReturnValue = STATUS_NOT_IMPLEMENTED;
    return TRUE;
}

/*++
 * @name CsrSbTerminateSession
 *
 * The CsrSbTerminateSession API is called by the Session Manager
 * whenever a foreign session should be destroyed.
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbTerminateSession API is not yet implemented.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbTerminateSession(IN PSB_API_MSG ApiMessage)
{
    ApiMessage->ReturnValue = STATUS_NOT_IMPLEMENTED;
    return TRUE;
}

/*++
 * @name CsrSbCreateProcess
 *
 * The CsrSbCreateProcess API is called by the Session Manager
 * whenever a foreign session is created and a new process should be started.
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE in case of success, FALSE otherwise.
 *
 * @remarks The CsrSbCreateProcess API is not yet implemented.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbCreateProcess(IN PSB_API_MSG ApiMessage)
{
    ApiMessage->ReturnValue = STATUS_NOT_IMPLEMENTED;
    return TRUE;
}

/* The sender of an Sb message or connection is the Session Manager that started us */
static
BOOLEAN
CsrIsSessionManagerClient(IN PCLIENT_ID Sender)
{
    NTSTATUS Status;
    LARGE_INTEGER Timeout;
    KERNEL_USER_TIMES Times;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE SenderProcess;

    if (!CsrSmssProcess || (Sender->UniqueProcess != CsrSmssProcessId)) return FALSE;

    /* Still alive (we hold a handle, so its pid has not been reused) */
    Timeout.QuadPart = 0;
    if (NtWaitForSingleObject(CsrSmssProcess, FALSE, &Timeout) != STATUS_TIMEOUT) return FALSE;

    /* The sender, by the client id the kernel stamped (its thread waits for the reply) */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenProcess(&SenderProcess, PROCESS_QUERY_INFORMATION, &ObjectAttributes, Sender);
    if (!NT_SUCCESS(Status)) return FALSE;
    Status = NtQueryInformationProcess(SenderProcess, ProcessTimes, &Times, sizeof(Times), NULL);
    NtClose(SenderProcess);
    return NT_SUCCESS(Status) && (Times.CreateTime.QuadPart == CsrSmssCreateTime.QuadPart);
}

/* Removes an NT session that no process used, without telling SMSS (it deletes its own on failure) */
static
VOID
CsrFreeUnusedNtSession(IN PCSR_NT_SESSION NtSession)
{
    CsrAcquireNtSessionLock();
    RemoveEntryList(&NtSession->SessionLink);
    CsrReleaseNtSessionLock();
    RtlFreeHeap(CsrHeap, 0, NtSession);
}

/*
 * Drops a reference on an NT session without telling SMSS when it was the last one. Used by the Sb thread
 * while SMSS waits for its reply to a forwarded registration: SmSessionComplete from here would need a
 * second SMSS API thread, and with forwards in flight there may be none (deadlock). SMSS deletes its
 * session record itself when the registration fails.
 */
static
VOID
CsrDereferenceNtSessionQuietly(IN PCSR_NT_SESSION NtSession)
{
    CsrAcquireNtSessionLock();
    ASSERT(NtSession->ReferenceCount != 0);
    if (--NtSession->ReferenceCount == 0)
    {
        RemoveEntryList(&NtSession->SessionLink);
        CsrReleaseNtSessionLock();
        RtlFreeHeap(CsrHeap, 0, NtSession);
        return;
    }
    CsrReleaseNtSessionLock();
}

/*
 * Registers a process of our session that was created by a process of
 * another session (CreateProcessAsUser from a service, for instance). The
 * request names the process and its first thread by id only. Every check
 * fails closed, and nothing is changed before all of them passed:
 * - the thread belongs to the process;
 * - the process is in our session, as the kernel reports it;
 * - it is not csrss itself and not registered yet.
 */
static
NTSTATUS
CsrCreateRemoteProcess(IN ULONG SmSessionId,
                       IN ULONG MuSessionId,
                       IN PCLIENT_ID ClientId,
                       IN ULONG Flags)
{
    NTSTATUS Status;
    HANDLE hProcess = NULL, hThread = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID OpenCid;
    PROCESS_BASIC_INFORMATION ProcessInfo;
    THREAD_BASIC_INFORMATION ThreadInfo;
    KERNEL_USER_TIMES ProcTimes, ThrTimes, EntryTimes;
    ULONG ProcessSessionId;
    PCSR_NT_SESSION NtSession = NULL, NtSessionHeld;
    PCSR_PROCESS CsrProcess, Entry;
    PCSR_THREAD CsrThread;
    PCSR_SERVER_DLL ServerDll;
    PLIST_ENTRY NextEntry;
    PVOID ProcessData;
    ULONG i;

    /* The request: for this session, with known flags */
    if ((MuSessionId != CsrKernelSessionId) ||
        (Flags & ~SM_REMOTE_PROCESS_VALID_FLAGS) ||
        !ClientId->UniqueProcess ||
        !ClientId->UniqueThread ||
        !SmSessionId)
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Never csrss itself */
    if (ClientId->UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess) return STATUS_ACCESS_DENIED;

    /* Open the process and the thread ourselves; no handle comes with the request */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    OpenCid.UniqueProcess = ClientId->UniqueProcess;
    OpenCid.UniqueThread = NULL;
    Status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &OpenCid);
    if (!NT_SUCCESS(Status)) return Status;
    OpenCid.UniqueProcess = NULL;
    OpenCid.UniqueThread = ClientId->UniqueThread;
    Status = NtOpenThread(&hThread, THREAD_ALL_ACCESS, &ObjectAttributes, &OpenCid);
    if (!NT_SUCCESS(Status)) goto Quit;

    /* The thread must belong to the process */
    Status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                       &ProcessInfo, sizeof(ProcessInfo), NULL);
    if (!NT_SUCCESS(Status)) goto Quit;
    Status = NtQueryInformationThread(hThread, ThreadBasicInformation,
                                      &ThreadInfo, sizeof(ThreadInfo), NULL);
    if (!NT_SUCCESS(Status)) goto Quit;
    if (((HANDLE)ProcessInfo.UniqueProcessId != ClientId->UniqueProcess) ||
        (ThreadInfo.ClientId.UniqueProcess != ClientId->UniqueProcess) ||
        (ThreadInfo.ClientId.UniqueThread != ClientId->UniqueThread))
    {
        Status = STATUS_INVALID_CID;
        goto Quit;
    }

    /* The process must still be alive (its creator may have killed it already) */
    {
        LARGE_INTEGER Timeout;

        Timeout.QuadPart = 0;
        if (NtWaitForSingleObject(hProcess, FALSE, &Timeout) != STATUS_TIMEOUT)
        {
            Status = STATUS_PROCESS_IS_TERMINATING;
            goto Quit;
        }
    }

    /* The process must be in our session (the kernel's view, not its PEB) */
    Status = NtQueryInformationProcess(hProcess, ProcessSessionInformation,
                                       &ProcessSessionId, sizeof(ProcessSessionId), NULL);
    if (!NT_SUCCESS(Status)) goto Quit;
    if (ProcessSessionId != CsrKernelSessionId)
    {
        Status = STATUS_ACCESS_DENIED;
        goto Quit;
    }

    Status = NtQueryInformationProcess(hProcess, ProcessTimes,
                                       &ProcTimes, sizeof(ProcTimes), NULL);
    if (!NT_SUCCESS(Status)) goto Quit;
    Status = NtQueryInformationThread(hThread, ThreadTimes,
                                      &ThrTimes, sizeof(ThrTimes), NULL);
    if (!NT_SUCCESS(Status)) goto Quit;

    NtSession = CsrAllocateNtSession(SmSessionId);
    if (!NtSession)
    {
        Status = STATUS_NO_MEMORY;
        goto Quit;
    }

    CsrAcquireProcessLock();

    /* Not registered yet. A record of a process that died and whose pid or
       tid now names another one does not count: the create times differ */
    for (NextEntry = CsrRootProcess->ListLink.Flink;
         NextEntry != &CsrRootProcess->ListLink;
         NextEntry = NextEntry->Flink)
    {
        Entry = CONTAINING_RECORD(NextEntry, CSR_PROCESS, ListLink);
        if (Entry->ClientId.UniqueProcess != ClientId->UniqueProcess) continue;
        if (!Entry->ProcessHandle ||
            !NT_SUCCESS(NtQueryInformationProcess(Entry->ProcessHandle, ProcessTimes,
                                                  &EntryTimes, sizeof(EntryTimes), NULL)) ||
            (EntryTimes.CreateTime.QuadPart == ProcTimes.CreateTime.QuadPart))
        {
            Status = STATUS_OBJECT_NAME_COLLISION;
            goto QuitLocked;
        }
    }
    CsrThread = CsrLocateThreadByClientId(NULL, ClientId);
    if (CsrThread && (CsrThread->CreateTime.QuadPart == ThrTimes.CreateTime.QuadPart))
    {
        Status = STATUS_OBJECT_NAME_COLLISION;
        goto QuitLocked;
    }

    /* Every check passed: create the records */
    CsrProcess = CsrAllocateProcess();
    if (!CsrProcess)
    {
        Status = STATUS_NO_MEMORY;
        goto QuitLocked;
    }
    CsrThread = CsrAllocateThread(CsrProcess);
    if (!CsrThread)
    {
        CsrDeallocateProcess(CsrProcess);
        Status = STATUS_NO_MEMORY;
        goto QuitLocked;
    }

    /* Exceptions of the process come to our port */
    Status = NtSetInformationProcess(hProcess, ProcessExceptionPort,
                                     &CsrApiPort, sizeof(CsrApiPort));
    if (!NT_SUCCESS(Status))
    {
        CsrDeallocateThread(CsrThread);
        CsrDeallocateProcess(CsrProcess);
        goto QuitLocked;
    }

    CsrThread->CreateTime = ThrTimes.CreateTime;
    CsrThread->ClientId = *ClientId;
    CsrThread->ThreadHandle = hThread;
    CsrThread->Flags = 0;
    Status = CsrInsertThread(CsrProcess, CsrThread);
    if (!NT_SUCCESS(Status))
    {
        CsrDeallocateThread(CsrThread);
        CsrDeallocateProcess(CsrProcess);
        goto QuitLocked;
    }
    ProtectHandle(hThread);
    hThread = NULL;

    CsrProcess->ClientId = *ClientId;
    CsrProcess->ProcessHandle = hProcess;
    hProcess = NULL;
    CsrProcess->NtSession = NtSession;
    NtSession = NULL;
    CsrProcess->ShutdownLevel = 0x280;

    /* No creator in this session: the process leads its own group */
    CsrProcess->ProcessGroupId = HandleToUlong(ClientId->UniqueProcess);
    CsrProcess->ProcessGroupSequence = CsrProcess->SequenceNumber;
    if (Flags & SM_REMOTE_PROCESS_CONSOLE_APP) CsrProcess->Flags |= CsrProcessIsConsoleApp;

    CsrSetBackgroundPriority(CsrProcess);

    /* Per-server data, initialized by the servers' new-process callbacks */
    ProcessData = &CsrProcess->ServerData[CSR_SERVER_DLL_MAX];
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++)
    {
        ServerDll = CsrLoadedServerDll[i];
        if (ServerDll && ServerDll->SizeOfProcessData)
        {
            CsrProcess->ServerData[i] = ProcessData;
            ProcessData = (PVOID)((ULONG_PTR)ProcessData + ServerDll->SizeOfProcessData);
        }
        else
        {
            CsrProcess->ServerData[i] = NULL;
        }
    }

    /*
     * Our own reference on the NT session while we may still destroy the process: if a server's
     * new-process callback fails, the process's reference goes with it, and ours is then dropped
     * without SmSessionComplete (see CsrDereferenceNtSessionQuietly).
     */
    CsrReferenceNtSession(CsrProcess->NtSession);
    NtSessionHeld = CsrProcess->NtSession;

    CsrProcess->InheritStatus = STATUS_SUCCESS;
    CsrInsertProcess(NULL, CsrProcess);
    Status = CsrProcess->InheritStatus;
    CsrReleaseProcessLock();
    if (!NT_SUCCESS(Status)) CsrDestroyProcess(ClientId, Status);
    CsrDereferenceNtSessionQuietly(NtSessionHeld);
    return Status;

QuitLocked:
    CsrReleaseProcessLock();
Quit:
    if (NtSession) CsrFreeUnusedNtSession(NtSession);
    if (hThread) NtClose(hThread);
    if (hProcess) NtClose(hProcess);
    return Status;
}

/*++
 * @name CsrSbCreateRemoteProcess
 *
 * NitroOS. SMSS forwards the registration of a process created into our
 * session from another session (SmForwardProcessRegistration). Only SMSS may
 * send it.
 *
 * @param ApiMessage
 *        Pointer to the Session Manager API Message.
 *
 * @return TRUE, the status is in the message.
 *
 *--*/
BOOLEAN
NTAPI
CsrSbCreateRemoteProcess(IN PSB_API_MSG ApiMessage)
{
    PSB_CREATE_REMOTE_PROCESS_MSG CreateRemote = &ApiMessage->u.CreateRemoteProcess;
    CLIENT_ID ClientId = CreateRemote->ClientId;

    if (!CsrIsSessionManagerClient(&ApiMessage->h.ClientId))
    {
        DPRINT1("CSRSS: SbCreateRemoteProcess refused: %lx.%lx is not the Session Manager\n",
                ApiMessage->h.ClientId.UniqueProcess, ApiMessage->h.ClientId.UniqueThread);
        ApiMessage->ReturnValue = STATUS_ACCESS_DENIED;
        return TRUE;
    }

    ApiMessage->ReturnValue = CsrCreateRemoteProcess(CreateRemote->SessionId,
                                                     CreateRemote->MuSessionId,
                                                     &ClientId,
                                                     CreateRemote->Flags);
    DPRINT1("CSRSS: SbCreateRemoteProcess %lx.%lx in session %lu, Status=%lx\n",
            ClientId.UniqueProcess, ClientId.UniqueThread,
            CreateRemote->MuSessionId, ApiMessage->ReturnValue);
    return TRUE;
}

/*++
 * @name CsrForwardProcessRegistration
 *
 * NitroOS. Called by basesrv for a process the client created into another
 * session: SMSS has the csrss of that session register it.
 *
 * @param ClientId
 *        The process and its first thread.
 *
 * @param MuSessionId
 *        The session the process is in.
 *
 * @param Flags
 *        CsrProcessCreateNewGroup and CsrProcessIsConsoleApp only.
 *
 * @return The status of the registration.
 *
 *--*/
NTSTATUS
NTAPI
CsrForwardProcessRegistration(IN PCLIENT_ID ClientId,
                              IN ULONG MuSessionId,
                              IN ULONG Flags)
{
    ULONG SmFlags = 0;

    if (Flags & ~(CsrProcessCreateNewGroup | CsrProcessIsConsoleApp)) return STATUS_INVALID_PARAMETER;
    if (!CsrSmApiPort) return STATUS_NOT_SUPPORTED;

    if (Flags & CsrProcessCreateNewGroup) SmFlags |= SM_REMOTE_PROCESS_NEW_GROUP;
    if (Flags & CsrProcessIsConsoleApp) SmFlags |= SM_REMOTE_PROCESS_CONSOLE_APP;
    return SmForwardProcessRegistration(CsrSmApiPort, ClientId, MuSessionId, SmFlags);
}

/*++
 * @name CsrSbApiHandleConnectionRequest
 *
 * The CsrSbApiHandleConnectionRequest routine handles and accepts a new
 * connection request to the SM API LPC Port.
 *
 * @param ApiMessage
 *        Pointer to the incoming CSR API Message which contains the
 *        connection request.
 *
 * @return STATUS_SUCCESS in case of success, or status code which caused
 *         the routine to error.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS
NTAPI
CsrSbApiHandleConnectionRequest(IN PSB_API_MSG Message)
{
    NTSTATUS Status;
    REMOTE_PORT_VIEW RemotePortView;
    HANDLE hPort;

    /* Set the Port View Structure Length */
    RemotePortView.Length = sizeof(REMOTE_PORT_VIEW);

    /* Only the Session Manager that started us; everyone else is refused */
    if (!CsrIsSessionManagerClient(&Message->h.ClientId))
    {
        DPRINT1("CSRSS: Sb connection refused: %lx.%lx is not the Session Manager\n",
                Message->h.ClientId.UniqueProcess, Message->h.ClientId.UniqueThread);
        NtAcceptConnectPort(&hPort, NULL, &Message->h, FALSE, NULL, NULL);
        return STATUS_ACCESS_DENIED;
    }

    /* Accept the connection */
    Status = NtAcceptConnectPort(&hPort,
                                 NULL,
                                 &Message->h,
                                 TRUE,
                                 NULL,
                                 &RemotePortView);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: Sb Accept Connection failed %lx\n", Status);
        return Status;
    }

    /* Complete the Connection */
    Status = NtCompleteConnectPort(hPort);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CSRSS: Sb Complete Connection failed %lx\n",Status);
    }

    /* Return status */
    return Status;
}

/**
 * @brief
 * The CsrSbApiRequestThread routine handles incoming messages
 * or connection requests on the SM API LPC Port.
 *
 * @param[in]   Parameter
 * System-default user-defined parameter. Unused.
 *
 * @return
 * The thread exit code, if the thread is terminated.
 **/
ULONG
NTAPI
CsrSbApiRequestThread(
    _In_ PVOID Parameter)
{
    NTSTATUS Status;
    SB_API_MSG ReceiveMsg;
    PSB_API_MSG ReplyMsg = NULL;
    PVOID PortContext;
    ULONG MessageType;

    /* Start the loop */
    while (TRUE)
    {
        /* Wait for a message to come in */
        Status = NtReplyWaitReceivePort(CsrSbApiPort,
                                        &PortContext,
                                        &ReplyMsg->h,
                                        &ReceiveMsg.h);

        /* Check if we didn't get success */
        if (Status != STATUS_SUCCESS)
        {
            /* If we only got a warning, keep going */
            if (NT_SUCCESS(Status)) continue;

            /* We failed big time, so start out fresh */
            ReplyMsg = NULL;
            DPRINT1("CSRSS: ReceivePort failed - Status == %X\n", Status);
            continue;
        }

        /* Save the message type */
        MessageType = ReceiveMsg.h.u2.s2.Type;

        /* Check if this is a connection request */
        if (MessageType == LPC_CONNECTION_REQUEST)
        {
            /* Handle connection request */
            CsrSbApiHandleConnectionRequest(&ReceiveMsg);

            /* Start over */
            ReplyMsg = NULL;
            continue;
        }

        /* Check if the port died */
        if (MessageType == LPC_PORT_CLOSED)
        {
            /* Close the handle if we have one */
            if (PortContext) NtClose((HANDLE)PortContext);

            /* Client died, start over */
            ReplyMsg = NULL;
            continue;
        }
        else if (MessageType == LPC_CLIENT_DIED)
        {
            /* Client died, start over */
            ReplyMsg = NULL;
            continue;
        }

        /* This is an actual API message */
#if DBG
        DPRINT("CSRSS: %s Session Api Request received from %lx.%lx\n",
               CsrServerSbApiName[min(ReceiveMsg.ApiNumber, SbpMaxApiNumber)],
               ReceiveMsg.h.ClientId.UniqueProcess,
               ReceiveMsg.h.ClientId.UniqueThread);
#endif

        /* Reuse the message */
        ReplyMsg = &ReceiveMsg;

        /* Every request comes from the Session Manager (defence in depth: only it can connect) */
        if (!CsrIsSessionManagerClient(&ReceiveMsg.h.ClientId))
        {
            DPRINT1("CSRSS: Sb request refused: %lx.%lx is not the Session Manager\n",
                    ReceiveMsg.h.ClientId.UniqueProcess, ReceiveMsg.h.ClientId.UniqueThread);
            ReplyMsg->ReturnValue = STATUS_ACCESS_DENIED;
        }
        /* Make sure that the API is supported */
        else if (ReceiveMsg.ApiNumber < SbpMaxApiNumber)
        {
            /* Call the API */
            if (!CsrServerSbApiDispatch[ReceiveMsg.ApiNumber](&ReceiveMsg))
            {
#if DBG
                DPRINT1("CSRSS: %s Session Api called and failed\n",
                        CsrServerSbApiName[ReceiveMsg.ApiNumber]);
#endif
                /* It failed, so return nothing */
                ReplyMsg = NULL;
            }
        }
        else
        {
            /* This API number is not supported */
            DPRINT1("CSRSS: Invalid Sb Api Number %lx\n", ReceiveMsg.ApiNumber);
            /* The NT behaviour is to reset it to the Maximum API ID */
            ReceiveMsg.ApiNumber = SbpMaxApiNumber;
            ReplyMsg->ReturnValue = STATUS_NOT_IMPLEMENTED;
        }
    }

    UNREACHABLE;
    return STATUS_UNSUCCESSFUL;
}

/* EOF */
