/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Base API Server DLL
 * FILE:            subsystems/win/basesrv/proc.c
 * PURPOSE:         Process and Thread Management
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "basesrv.h"
#include "vdm.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* User notification procedure to be called when a process is created */
static BASE_PROCESS_CREATE_NOTIFY_ROUTINE UserNotifyProcessCreate = NULL;

/* PUBLIC SERVER APIS *********************************************************/

CSR_API(BaseSrvDebugProcess)
{
    /* Deprecated */
    return STATUS_UNSUCCESSFUL;
}

CSR_API(BaseSrvRegisterThread)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvSxsCreateActivationContext)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvSetTermsrvAppInstallMode)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvSetTermsrvClientTimeZone)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvGetTempFile)
{
    static UINT BaseGetTempFileUnique = 0;
    PBASE_GET_TEMP_FILE GetTempFile = &((PBASE_API_MESSAGE)ApiMessage)->Data.GetTempFileRequest;

    /* Return 16-bits ID */
    GetTempFile->UniqueID = (++BaseGetTempFileUnique & 0xFFFF);

    DPRINT("Returning: %u\n", GetTempFile->UniqueID);

    return GetTempFile->UniqueID;
}

/*
 * The process and thread the request names must be those of the handles the
 * client gave, and the process must be a child the client created (created
 * after it: the parent pid alone could name an earlier process with the same
 * id). Otherwise the client could have csrss register, set the exception port
 * of and later act for a process it only holds a handle to, under ids it
 * chose. kernel32 always sends its own new child with its ids.
 */
static
NTSTATUS
BaseSrvCheckNewProcess(IN PCSR_PROCESS Creator,
                       IN HANDLE ProcessHandle,
                       IN HANDLE ThreadHandle,
                       IN PCLIENT_ID ClientId)
{
    NTSTATUS Status;
    PROCESS_BASIC_INFORMATION ProcessInfo;
    THREAD_BASIC_INFORMATION ThreadInfo;
    KERNEL_USER_TIMES ChildTimes, CreatorTimes;

    Status = NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation,
                                       &ProcessInfo, sizeof(ProcessInfo), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    Status = NtQueryInformationThread(ThreadHandle, ThreadBasicInformation,
                                      &ThreadInfo, sizeof(ThreadInfo), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    if (((HANDLE)ProcessInfo.UniqueProcessId != ClientId->UniqueProcess) ||
        (ThreadInfo.ClientId.UniqueProcess != ClientId->UniqueProcess) ||
        (ThreadInfo.ClientId.UniqueThread != ClientId->UniqueThread))
    {
        return STATUS_INVALID_CID;
    }

    if ((HANDLE)ProcessInfo.InheritedFromUniqueProcessId != Creator->ClientId.UniqueProcess)
        return STATUS_ACCESS_DENIED;
    Status = NtQueryInformationProcess(ProcessHandle, ProcessTimes,
                                       &ChildTimes, sizeof(ChildTimes), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    Status = NtQueryInformationProcess(Creator->ProcessHandle, ProcessTimes,
                                       &CreatorTimes, sizeof(CreatorTimes), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    if (ChildTimes.CreateTime.QuadPart < CreatorTimes.CreateTime.QuadPart)
        return STATUS_ACCESS_DENIED;

    return STATUS_SUCCESS;
}

/*
 * NitroOS sessions design 3.5 (option A). The client created the process into
 * another session (CreateProcessAsUser with a token of that session, which
 * needs SeTcbPrivilege). The process will connect to the csrss of its own
 * session, so that csrss must register it: SMSS has it do so. The ids and the
 * child-of-the-client rule were checked by BaseSrvCheckNewProcess, which also
 * means a create with a parent-process attribute (parent != client) is refused
 * here. Anything of the creator's session (its console handles, a pseudo
 * console, a VDM) cannot follow the process there and is refused.
 *
 * The caller keeps ProcessHandle and ThreadHandle open until this returns:
 * they pin the process and thread ids that SMSS and the target csrss open by
 * id. Do not close them before the forward has returned.
 */
static
NTSTATUS
BaseSrvForwardCreateProcess(IN PBASE_CREATE_PROCESS Request,
                            IN ULONG TargetSessionId,
                            IN ULONG Flags)
{
    CLIENT_ID ClientId;

    if (Request->VdmBinaryType || Request->ConsoleHandleCount || Request->PseudoConsoleProcessId)
        return STATUS_NOT_SUPPORTED;

    ClientId = Request->ClientId;
    return CsrForwardProcessRegistration(&ClientId, TargetSessionId, Flags);
}

CSR_API(BaseSrvCreateProcess)
{
    NTSTATUS Status;
    PBASE_CREATE_PROCESS CreateProcessRequest = &((PBASE_API_MESSAGE)ApiMessage)->Data.CreateProcessRequest;
    HANDLE ProcessHandle, ThreadHandle;
    PCSR_THREAD CsrThread;
    PCSR_PROCESS Process;
    ULONG Flags = 0, DebugFlags = 0, VdmPower = 0;
    ULONG ProcessSessionId, OwnSessionId;

    if (CreateProcessRequest->ConsoleHandleCount &&
        (!CreateProcessRequest->HandleListPresent ||
         !CsrValidateMessageBuffer(ApiMessage,
                                  (PVOID*)&CreateProcessRequest->ConsoleHandleList,
                                  CreateProcessRequest->ConsoleHandleCount,
                                  sizeof(HANDLE))))
        return STATUS_INVALID_PARAMETER;

    /* Get the current client thread */
    CsrThread = CsrGetClientThread();
    ASSERT(CsrThread != NULL);

    Process = CsrThread->Process;

    /* Extract the flags out of the process handle */
    Flags = (ULONG_PTR)CreateProcessRequest->ProcessHandle & 3;
    CreateProcessRequest->ProcessHandle = (HANDLE)((ULONG_PTR)CreateProcessRequest->ProcessHandle & ~3);

    /* Some things should be done if this is a VDM process */
    if (CreateProcessRequest->VdmBinaryType)
    {
        /* We need to set the VDM power later on */
        VdmPower = 1;
    }

    /* Duplicate the process handle */
    Status = NtDuplicateObject(Process->ProcessHandle,
                               CreateProcessRequest->ProcessHandle,
                               NtCurrentProcess(),
                               &ProcessHandle,
                               0,
                               0,
                               DUPLICATE_SAME_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to duplicate process handle: %lx\n", Status);
        return Status;
    }

    /* Duplicate the thread handle */
    Status = NtDuplicateObject(Process->ProcessHandle,
                               CreateProcessRequest->ThreadHandle,
                               NtCurrentProcess(),
                               &ThreadHandle,
                               0,
                               0,
                               DUPLICATE_SAME_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to duplicate thread handle: %lx\n", Status);
        NtClose(ProcessHandle);
        return Status;
    }

    /* The ids are those of the handles, and the process is the client's child */
    Status = BaseSrvCheckNewProcess(Process, ProcessHandle, ThreadHandle,
                                    &CreateProcessRequest->ClientId);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("BASESRV: process %lx.%lx refused: %lx\n",
                CreateProcessRequest->ClientId.UniqueProcess,
                CreateProcessRequest->ClientId.UniqueThread, Status);
        NtClose(ProcessHandle);
        NtClose(ThreadHandle);
        return Status;
    }

    /* A process in another session registers with the csrss of that session */
    Status = NtQueryInformationProcess(ProcessHandle, ProcessSessionInformation,
                                       &ProcessSessionId, sizeof(ProcessSessionId), NULL);
    if (NT_SUCCESS(Status))
    {
        Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessSessionInformation,
                                           &OwnSessionId, sizeof(OwnSessionId), NULL);
    }
    if (!NT_SUCCESS(Status))
    {
        NtClose(ProcessHandle);
        NtClose(ThreadHandle);
        return Status;
    }
    if (ProcessSessionId != OwnSessionId)
    {
        if (CreateProcessRequest->CreationFlags & CREATE_NEW_PROCESS_GROUP) DebugFlags |= CsrProcessCreateNewGroup;
        if ((Flags & 2) == 0) DebugFlags |= CsrProcessIsConsoleApp;
        Status = BaseSrvForwardCreateProcess(CreateProcessRequest, ProcessSessionId, DebugFlags);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("BASESRV: registration of %lx.%lx in session %lu failed: %lx\n",
                    CreateProcessRequest->ClientId.UniqueProcess,
                    CreateProcessRequest->ClientId.UniqueThread,
                    ProcessSessionId, Status);
        }
        /* Only now: the handles pinned the ids during the forward */
        NtClose(ProcessHandle);
        NtClose(ThreadHandle);
        return Status;
    }

    /* If this is a VDM process, request VDM power */
    if (VdmPower)
    {
        Status = NtSetInformationProcess(ProcessHandle,
                                         ProcessWx86Information,
                                         &VdmPower,
                                         sizeof(VdmPower));
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Failed to get VDM powers\n");
            NtClose(ProcessHandle);
            NtClose(ThreadHandle);
            return Status;
        }
    }

    /* Flags conversion. FIXME: More need conversion */
    if (CreateProcessRequest->CreationFlags & CREATE_NEW_PROCESS_GROUP)
    {
        DebugFlags |= CsrProcessCreateNewGroup;
    }
    if ((Flags & 2) == 0)
    {
        /* We are launching a console process */
        DebugFlags |= CsrProcessIsConsoleApp;
    }

    /* FIXME: SxS Stuff */

    /* Call CSRSRV to create the CSR_PROCESS structure and the first CSR_THREAD */
    Status = CsrCreateProcessWithHandleList(ProcessHandle,
                              ThreadHandle,
                              &CreateProcessRequest->ClientId,
                              Process->NtSession,
                              DebugFlags,
                              NULL,
                              CreateProcessRequest->HandleListPresent,
                              CreateProcessRequest->ConsoleHandleList,
                              CreateProcessRequest->ConsoleHandleCount,
                              CreateProcessRequest->PseudoConsoleProcessId);
    if (Status == STATUS_THREAD_IS_TERMINATING)
    {
        DPRINT1("Thread already dead\n");

        /* Set the special reply value so we don't reply this message back */
        *ReplyCode = CsrReplyDeadClient;

        return Status;
    }

    /* Check for other failures */
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to create process/thread structures: %lx\n", Status);
        return Status;
    }

    /* Call the user notification procedure */
    if (UserNotifyProcessCreate)
    {
        UserNotifyProcessCreate(CreateProcessRequest->ClientId.UniqueProcess,
                                Process->ClientId.UniqueThread,
                                0,
                                Flags);
    }

    /* Check if this is a VDM process */
    if (CreateProcessRequest->VdmBinaryType)
    {
        PVDM_CONSOLE_RECORD ConsoleRecord;

        if (CreateProcessRequest->VdmTask != 0)
        {
            /* Get the console record using the task ID */
            Status = GetConsoleRecordBySessionId(CreateProcessRequest->VdmTask,
                                                 &ConsoleRecord);
        }
        else
        {
            /* Get the console record using the console handle */
            Status = BaseSrvGetConsoleRecord(CreateProcessRequest->hVDM,
                                             &ConsoleRecord);
        }

        /* Check if it failed */
        if (!NT_SUCCESS(Status)) return Status;

        /* Store the process ID of the VDM in the console record */
        ConsoleRecord->ProcessId = HandleToUlong(CreateProcessRequest->ClientId.UniqueProcess);
    }

    /* Return the result of this operation */
    return Status;
}

/*
 * The thread the client registers (CreateThread, CreateRemoteThread) must be the thread of the handle it
 * passes: process and thread ids read from the handle (ThreadBasicInformation) must equal the request's.
 * CsrCreateThread stores the request's ids, and a remote registration locks the process the request names,
 * so without this a client could add a thread with ids of its choice to any registered process. A thread of
 * another process is still accepted when the client really holds a handle to it (CreateRemoteThread).
 *
 * ThreadHandle is the server's own duplicate: the client's handle value is fetched once, and the ids are
 * checked on that duplicate, which is also the handle CsrCreateThread keeps (the client can change what
 * its handle value refers to between two fetches).
 */
static
NTSTATUS
BaseSrvCheckNewThread(IN HANDLE ThreadHandle,
                      IN PBASE_CREATE_THREAD Request)
{
    NTSTATUS Status;
    THREAD_BASIC_INFORMATION ThreadInfo;

    Status = NtQueryInformationThread(ThreadHandle, ThreadBasicInformation,
                                      &ThreadInfo, sizeof(ThreadInfo), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    if ((ThreadInfo.ClientId.UniqueProcess != Request->ClientId.UniqueProcess) ||
        (ThreadInfo.ClientId.UniqueThread != Request->ClientId.UniqueThread))
    {
        return STATUS_INVALID_CID;
    }
    return STATUS_SUCCESS;
}

CSR_API(BaseSrvCreateThread)
{
    NTSTATUS Status;
    PBASE_CREATE_THREAD CreateThreadRequest = &((PBASE_API_MESSAGE)ApiMessage)->Data.CreateThreadRequest;
    PCSR_THREAD CurrentThread;
    HANDLE ThreadHandle;
    PCSR_PROCESS CsrProcess;

    /* Get the current CSR thread */
    CurrentThread = CsrGetClientThread();
    if (!CurrentThread)
    {
        DPRINT1("Server Thread TID: [%lx.%lx]\n",
                CreateThreadRequest->ClientId.UniqueProcess,
                CreateThreadRequest->ClientId.UniqueThread);
        return STATUS_SUCCESS; // server-to-server
    }

    /* Duplicate the thread handle so we can own it (the only fetch of the client's handle value) */
    Status = NtDuplicateObject(CurrentThread->Process->ProcessHandle,
                               CreateThreadRequest->ThreadHandle,
                               NtCurrentProcess(),
                               &ThreadHandle,
                               0,
                               0,
                               DUPLICATE_SAME_ACCESS);
    if (!NT_SUCCESS(Status)) return Status;

    /* The ids must be those of the thread this handle names (CsrCreateThread stores them) */
    Status = BaseSrvCheckNewThread(ThreadHandle, CreateThreadRequest);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("BASESRV: thread %lx.%lx refused: %lx\n",
                CreateThreadRequest->ClientId.UniqueProcess,
                CreateThreadRequest->ClientId.UniqueThread, Status);
        NtClose(ThreadHandle);
        return Status;
    }

    /* Get the CSR Process for this request */
    CsrProcess = CurrentThread->Process;
    if (CsrProcess->ClientId.UniqueProcess !=
        CreateThreadRequest->ClientId.UniqueProcess)
    {
        /* This is a remote thread request -- is it within the server itself? */
        if (CreateThreadRequest->ClientId.UniqueProcess == NtCurrentTeb()->ClientId.UniqueProcess)
        {
            /* Accept this without any further work */
            NtClose(ThreadHandle);
            return STATUS_SUCCESS;
        }

        /* Get the real CSR Process for the remote thread's process */
        Status = CsrLockProcessByClientId(CreateThreadRequest->ClientId.UniqueProcess,
                                          &CsrProcess);
        if (!NT_SUCCESS(Status))
        {
            NtClose(ThreadHandle);
            return Status;
        }
    }

    /* Call CSRSRV to tell it about the new thread; it keeps the handle on success only */
    Status = CsrCreateThread(CsrProcess,
                             ThreadHandle,
                             &CreateThreadRequest->ClientId,
                             TRUE);
    if (!NT_SUCCESS(Status)) NtClose(ThreadHandle);

    /* Unlock the process and return */
    if (CsrProcess != CurrentThread->Process) CsrUnlockProcess(CsrProcess);
    return Status;
}

CSR_API(BaseSrvExitProcess)
{
    PCSR_THREAD CsrThread = CsrGetClientThread();
    ASSERT(CsrThread != NULL);

    /* Set the special reply value so we don't reply this message back */
    *ReplyCode = CsrReplyDeadClient;

    /* Remove the CSR_THREADs and CSR_PROCESS */
    return CsrDestroyProcess(&CsrThread->ClientId,
                             (NTSTATUS)((PBASE_API_MESSAGE)ApiMessage)->Data.ExitProcessRequest.uExitCode);
}

CSR_API(BaseSrvGetProcessShutdownParam)
{
    PBASE_GETSET_PROCESS_SHUTDOWN_PARAMS ShutdownParametersRequest = &((PBASE_API_MESSAGE)ApiMessage)->Data.ShutdownParametersRequest;
    PCSR_THREAD CsrThread = CsrGetClientThread();
    ASSERT(CsrThread);

    ShutdownParametersRequest->ShutdownLevel = CsrThread->Process->ShutdownLevel;
    /* Only SHUTDOWN_NORETRY flag is valid for this API. The other private flags are for CSRSRV/WINSRV only. */
    ShutdownParametersRequest->ShutdownFlags = CsrThread->Process->ShutdownFlags & SHUTDOWN_NORETRY;

    return STATUS_SUCCESS;
}

CSR_API(BaseSrvSetProcessShutdownParam)
{
    PBASE_GETSET_PROCESS_SHUTDOWN_PARAMS ShutdownParametersRequest = &((PBASE_API_MESSAGE)ApiMessage)->Data.ShutdownParametersRequest;
    PCSR_THREAD CsrThread = CsrGetClientThread();
    ASSERT(CsrThread);

    /* Only SHUTDOWN_NORETRY flag is valid for this API. The other private flags are for CSRSRV/WINSRV only. */
    if (ShutdownParametersRequest->ShutdownFlags & ~SHUTDOWN_NORETRY)
    {
        /* If there were other flags specified, fail the call */
        return STATUS_INVALID_PARAMETER;
    }

    CsrThread->Process->ShutdownLevel = ShutdownParametersRequest->ShutdownLevel;
    /* Notice that all the possible other private flags are reinitialized here */
    CsrThread->Process->ShutdownFlags = ShutdownParametersRequest->ShutdownFlags;

    return STATUS_SUCCESS;
}

/* PUBLIC API *****************************************************************/

VOID
NTAPI
BaseSetProcessCreateNotify(IN BASE_PROCESS_CREATE_NOTIFY_ROUTINE ProcessCreateNotifyProc)
{
    /* Set the user notification procedure to be called when a process is created */
    UserNotifyProcessCreate = ProcessCreateNotifyProc;
}

/* EOF */
