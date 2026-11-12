/*
 * PROJECT:         ReactOS Windows-Compatible Session Manager
 * LICENSE:         BSD 2-Clause License
 * FILE:            base/system/smss/smloop.c
 * PURPOSE:         Main SMSS Code
 * PROGRAMMERS:     Alex Ionescu
 */

/* INCLUDES *******************************************************************/

#include "smss.h"
#include <ndk/sefuncs.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

typedef struct _SMP_CLIENT_CONTEXT
{
    PSMP_SUBSYSTEM Subsystem;
    HANDLE ProcessHandle;
    HANDLE PortHandle;
    PVOID Reserved;
} SMP_CLIENT_CONTEXT, *PSMP_CLIENT_CONTEXT;

typedef
NTSTATUS
(NTAPI *PSM_API_HANDLER)(
    _In_ PSM_API_MSG SmApiMsg,
    _In_ PSMP_CLIENT_CONTEXT ClientContext,
    _In_ HANDLE SmApiPort);

volatile LONG SmTotalApiThreads;

/* The LPC message type, without the flag bits the kernel adds above it */
#define SMP_LPC_TYPE(Msg) ((Msg)->h.u2.s2.Type & 0xFF)

HANDLE SmUniqueProcessId;

/* Forwarded registrations running now, each on an API thread (see SmpForwardProcessRegistration) */
static volatile LONG SmpForwardsInFlight;

/*
 * Log lines a client can make SMSS print one at a time (a datagram it sends, a request it gets refused):
 * the first few, then every SMP_CLIENT_LOG_EVERY-th with its running number, so a flood is one line in
 * a thousand and not one line each on the serial port.
 */
#define SMP_CLIENT_LOG_FIRST 8
#define SMP_CLIENT_LOG_EVERY 1024
static volatile LONG SmpClientLogCount;

static
LONG
SmpClientLogNumber(VOID)
{
    LONG Number = _InterlockedIncrement(&SmpClientLogCount);

    if ((Number <= SMP_CLIENT_LOG_FIRST) || ((Number % SMP_CLIENT_LOG_EVERY) == 0)) return Number;
    return 0;
}

/* The data length of the one datagram SMSS serves: SmSessionComplete, as smlib sizes it */
#define SMP_SESSION_COMPLETE_DATA_LENGTH \
    (sizeof(SM_SESSION_COMPLETE_MSG) + FIELD_OFFSET(SM_API_MSG, u) - sizeof(PORT_MESSAGE))

/*
 * Security gate S8 (NitroSessions design). \SmApiPort is open to
 * Administrators and SYSTEM (SmpCreateSecurityDescriptors). The APIs below
 * start processes or sessions on the caller's behalf, so they only serve SMSS
 * itself and LocalSystem processes in session 0. The session is the kernel's
 * (ProcessSessionInformation), never the client's PEB. Every in-tree caller
 * is SMSS itself.
 */
static
BOOLEAN
SmpIsSessionZeroSystemClient(
    _In_ PSM_API_MSG SmApiMsg,
    _In_ PSMP_CLIENT_CONTEXT ClientContext)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    NTSTATUS Status;
    HANDLE TokenHandle;
    ULONG SessionId, Length;
    union
    {
        TOKEN_USER User;
        UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } TokenInfo;
    UCHAR SystemSidBuffer[SECURITY_MAX_SID_SIZE];
    PSID SystemSid = (PSID)SystemSidBuffer;
    BOOLEAN IsSystem;

    /* SMSS connected to itself */
    if (SmApiMsg->h.ClientId.UniqueProcess == SmUniqueProcessId) return TRUE;
    if (!ClientContext->ProcessHandle) return FALSE;

    /* Session 0 */
    Status = NtQueryInformationProcess(ClientContext->ProcessHandle,
                                       ProcessSessionInformation,
                                       &SessionId,
                                       sizeof(SessionId),
                                       NULL);
    if (!NT_SUCCESS(Status) || (SessionId != 0)) return FALSE;

    /* LocalSystem */
    Status = NtOpenProcessToken(ClientContext->ProcessHandle, TOKEN_QUERY, &TokenHandle);
    if (!NT_SUCCESS(Status)) return FALSE;
    Status = NtQueryInformationToken(TokenHandle,
                                     TokenUser,
                                     &TokenInfo,
                                     sizeof(TokenInfo),
                                     &Length);
    NtClose(TokenHandle);
    if (!NT_SUCCESS(Status)) return FALSE;

    Status = RtlInitializeSid(SystemSid, &NtAuthority, 1);
    if (!NT_SUCCESS(Status)) return FALSE;
    *RtlSubAuthoritySid(SystemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;
    IsSystem = RtlEqualSid(TokenInfo.User.User.Sid, SystemSid);
    return IsSystem;
}

/* API HANDLERS ***************************************************************/

NTSTATUS
NTAPI
SmpCreateForeignSession(IN PSM_API_MSG SmApiMsg,
                        IN PSMP_CLIENT_CONTEXT ClientContext,
                        IN HANDLE SmApiPort)
{
    DPRINT1("%s is not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SmpSessionComplete(IN PSM_API_MSG SmApiMsg,
                   IN PSMP_CLIENT_CONTEXT ClientContext,
                   IN HANDLE SmApiPort)
{
    /*
     * A subsystem tells SMSS that the last process of one of its sessions is gone: drop the record SMSS
     * allocated for it (one per SbCreateSession and per forwarded registration). Only the subsystem the
     * session was given to may complete it.
     */
    if (!ClientContext->Subsystem) return STATUS_ACCESS_DENIED;
    return SmpCompleteSession(SmApiMsg->u.SessionComplete.SessionId, ClientContext->Subsystem);
}

NTSTATUS
NTAPI
SmpTerminateForeignSession(IN PSM_API_MSG SmApiMsg,
                           IN PSMP_CLIENT_CONTEXT ClientContext,
                           IN HANDLE SmApiPort)
{
    DPRINT1("%s is not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS
NTAPI
SmpExecPgm(IN PSM_API_MSG SmApiMsg,
           IN PSMP_CLIENT_CONTEXT ClientContext,
           IN HANDLE SmApiPort)
{
    HANDLE ProcessHandle;
    NTSTATUS Status;
    PSM_EXEC_PGM_MSG SmExecPgm;
    RTL_USER_PROCESS_INFORMATION ProcessInformation;
    OBJECT_ATTRIBUTES ObjectAttributes;

    /* Open the client process */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenProcess(&ProcessHandle,
                           PROCESS_DUP_HANDLE,
                           &ObjectAttributes,
                           &SmApiMsg->h.ClientId);
    if (!NT_SUCCESS(Status))
    {
        /* Fail */
        DPRINT1("SmExecPgm: NtOpenProcess Failed %lx\n", Status);
        return Status;
    }

    /* Copy the process information out of the message */
    SmExecPgm = &SmApiMsg->u.ExecPgm;
    ProcessInformation = SmExecPgm->ProcessInformation;

    /* Duplicate the process handle */
    Status = NtDuplicateObject(ProcessHandle,
                               SmExecPgm->ProcessInformation.ProcessHandle,
                               NtCurrentProcess(),
                               &ProcessInformation.ProcessHandle,
                               PROCESS_ALL_ACCESS,
                               0,
                               0);
    if (!NT_SUCCESS(Status))
    {
        /* Close the handle and fail */
        NtClose(ProcessHandle);
        DPRINT1("SmExecPgm: NtDuplicateObject (Process) Failed %lx\n", Status);
        return Status;
    }

    /* Duplicate the thread handle */
    Status = NtDuplicateObject(ProcessHandle,
                               SmExecPgm->ProcessInformation.ThreadHandle,
                               NtCurrentProcess(),
                               &ProcessInformation.ThreadHandle,
                               THREAD_ALL_ACCESS,
                               0,
                               0);
    if (!NT_SUCCESS(Status))
    {
        /* Close both handles and fail */
        NtClose(ProcessInformation.ProcessHandle);
        NtClose(ProcessHandle);
        DPRINT1("SmExecPgm: NtDuplicateObject (Thread) Failed %lx\n", Status);
        return Status;
    }

    /* Close the process handle and call the internal client API */
    NtClose(ProcessHandle);
    return SmpSbCreateSession(NULL,
                              NULL,
                              &ProcessInformation,
                              0,
                              SmExecPgm->DebugFlag ? &SmApiMsg->h.ClientId : NULL);
}

NTSTATUS
NTAPI
SmpLoadDeferedSubsystem(
    _In_ PSM_API_MSG SmApiMsg,
    _In_ PSMP_CLIENT_CONTEXT ClientContext,
    _In_ HANDLE SmApiPort)
{
    NTSTATUS Status = STATUS_OBJECT_NAME_NOT_FOUND;
    PSM_LOAD_DEFERED_SUBSYSTEM_MSG SmLoadDefered = &SmApiMsg->u.LoadDefered;
    UNICODE_STRING DeferedSubsystem;
    ULONG MuSessionId;
    PLIST_ENTRY NextEntry;
    PSMP_REGISTRY_VALUE RegEntry;

    /* Validate DeferedSubsystem's length */
    if ((SmLoadDefered->Length <= 0) ||
        (SmLoadDefered->Length > sizeof(SmLoadDefered->Buffer)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    /* Get the name of the subsystem to start */
    DeferedSubsystem.Length = (USHORT)SmLoadDefered->Length;
    DeferedSubsystem.MaximumLength = DeferedSubsystem.Length;
    DeferedSubsystem.Buffer = SmLoadDefered->Buffer;

    /* Find a subsystem responsible for this session */
    SmpGetProcessMuSessionId(ClientContext->ProcessHandle, &MuSessionId);
    if (!SmpCheckDuplicateMuSessionId(MuSessionId))
    {
        DPRINT1("SMSS: Deferred subsystem load (%wZ) for MuSessionId %u, status=0x%x\n",
                &DeferedSubsystem, MuSessionId, Status);
        return Status;
    }

    /* Now process the deferred subsystems list */
    for (NextEntry = SmpSubSystemsToDefer.Flink;
         NextEntry != &SmpSubSystemsToDefer;
         NextEntry = NextEntry->Flink)
    {
        /* Get each entry and check if it's the subsystem we are looking for */
        RegEntry = CONTAINING_RECORD(NextEntry, SMP_REGISTRY_VALUE, Entry);
        if (RtlEqualUnicodeString(&RegEntry->Name, &DeferedSubsystem, TRUE))
        {
            // TODO: One may want to extra-flag the command for
            // specific POSIX or OS2 processing...

            /* Load the deferred subsystem */
            Status = SmpExecuteCommand(&RegEntry->Value,
                                       MuSessionId,
                                       NULL,
                                       SMP_SUBSYSTEM_FLAG);
            if (!NT_SUCCESS(Status))
                DPRINT1("SMSS: Subsystem execute failed (%wZ)\n", &RegEntry->Value);

            break;
        }
    }

    /* Return status */
    return Status;
}

NTSTATUS
NTAPI
SmpStartCsr(IN PSM_API_MSG SmApiMsg,
            IN PSMP_CLIENT_CONTEXT ClientContext,
            IN HANDLE SmApiPort)
{
    PSM_START_CSR_MSG SmStartCsr = &SmApiMsg->u.StartCsr;
    UNICODE_STRING InitialCommand;
    HANDLE InitialCommandProcess, InitialCommandProcessId, WindowsSubSysProcessId;
    NTSTATUS Status;

    /*
     * One session create at a time (NitroSessions design 3.1). SMSS stays
     * attached to the new session until the initial command is started, so
     * the lock covers that too, up to the detach.
     */
    RtlEnterCriticalSection(&SmpMuSessionLock);
    Status = SmpLoadSubSystemsForMuSession(&SmStartCsr->MuSessionId,
                                           &WindowsSubSysProcessId,
                                           &InitialCommand);
    if (!NT_SUCCESS(Status))
    {
        if (SmpNitroSessions) SmpNitroDetach();
        RtlLeaveCriticalSection(&SmpMuSessionLock);
        DPRINT1("SMSS: SmpLoadSubSystemsForMuSession failed with status 0x%08x\n", Status);
        return Status;
    }

    if (SmStartCsr->Length)
    {
        InitialCommand.Length = InitialCommand.MaximumLength = SmStartCsr->Length;
        InitialCommand.Buffer = SmStartCsr->Buffer;
    }

    Status = SmpExecuteInitialCommand(SmStartCsr->MuSessionId,
                                      &InitialCommand,
                                      &InitialCommandProcess,
                                      &InitialCommandProcessId);
    /* A NitroSessions start leaves SMSS in no session; flag 0 is as before */
    if (SmpNitroSessions) SmpNitroDetach();
    RtlLeaveCriticalSection(&SmpMuSessionLock);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: SmpExecuteInitialCommand failed with status 0x%08x\n", Status);
        /* FIXME: undo effects of SmpLoadSubSystemsForMuSession */
        ASSERT(FALSE);
        return Status;
    }

    NtClose(InitialCommandProcess);

    SmStartCsr->WindowsSubSysProcessId = WindowsSubSysProcessId;
    SmStartCsr->SmpInitialCommandProcessId = InitialCommandProcessId;

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
SmpStopCsr(IN PSM_API_MSG SmApiMsg,
           IN PSMP_CLIENT_CONTEXT ClientContext,
           IN HANDLE SmApiPort)
{
    DPRINT1("%s is not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * NitroOS sessions design 3.5 (option A): cross-session CSR registration.
 *
 * When a process is created into another session, the creator's csrss cannot
 * register it: the process will connect to the csrss of its own session. The
 * creator's basesrv asks SMSS instead, and SMSS forwards the request over the
 * Sb port of the target session's csrss, where SMSS is the client. SMSS
 * serves this only for a csrss it started itself, identified by the process
 * object it holds for it: alive, the pid the kernel stamped on the message,
 * and the same create time as the sender. Any other caller, LocalSystem
 * included, gets STATUS_ACCESS_DENIED.
 */
static
NTSTATUS
SmpQueryProcessCreateTime(
    _In_ HANDLE ProcessHandle,
    _Out_ PLARGE_INTEGER CreateTime)
{
    NTSTATUS Status;
    KERNEL_USER_TIMES Times;

    Status = NtQueryInformationProcess(ProcessHandle,
                                       ProcessTimes,
                                       &Times,
                                       sizeof(Times),
                                       NULL);
    if (NT_SUCCESS(Status)) *CreateTime = Times.CreateTime;
    return Status;
}

/* The referenced record of the csrss that sent the message, or NULL */
static
PSMP_SUBSYSTEM
SmpLocateSenderCsr(
    _In_ PSM_API_MSG SmApiMsg,
    _In_ PSMP_CLIENT_CONTEXT ClientContext)
{
    PSMP_SUBSYSTEM Subsystem = NULL, Entry;
    PLIST_ENTRY NextEntry;
    PROCESS_BASIC_INFORMATION BasicInfo;
    LARGE_INTEGER HeldCreateTime, SenderCreateTime, Timeout;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE SenderProcess;
    NTSTATUS Status;

    /* SMSS itself is not a csrss; the connection must belong to a subsystem */
    if (SmApiMsg->h.ClientId.UniqueProcess == SmUniqueProcessId) return NULL;
    if (!ClientContext->Subsystem) return NULL;

    /* The Windows subsystem record of this connection, with the sender's pid */
    RtlEnterCriticalSection(&SmpKnownSubSysLock);
    for (NextEntry = SmpKnownSubSysHead.Flink;
         NextEntry != &SmpKnownSubSysHead;
         NextEntry = NextEntry->Flink)
    {
        Entry = CONTAINING_RECORD(NextEntry, SMP_SUBSYSTEM, Entry);
        if ((Entry == ClientContext->Subsystem) &&
            (Entry->ClientId.UniqueProcess == SmApiMsg->h.ClientId.UniqueProcess) &&
            (Entry->ImageType == IMAGE_SUBSYSTEM_WINDOWS_GUI) &&
            (Entry->ProcessHandle != NULL) &&
            !(Entry->Terminating))
        {
            Entry->ReferenceCount++;
            Subsystem = Entry;
            break;
        }
    }
    RtlLeaveCriticalSection(&SmpKnownSubSysLock);
    if (!Subsystem) return NULL;

    /* The process object SMSS holds: still alive, with the sender's pid */
    Timeout.QuadPart = 0;
    Status = NtWaitForSingleObject(Subsystem->ProcessHandle, FALSE, &Timeout);
    if (Status != STATUS_TIMEOUT) goto Fail;
    Status = NtQueryInformationProcess(Subsystem->ProcessHandle,
                                       ProcessBasicInformation,
                                       &BasicInfo,
                                       sizeof(BasicInfo),
                                       NULL);
    if (!NT_SUCCESS(Status) ||
        ((HANDLE)BasicInfo.UniqueProcessId != SmApiMsg->h.ClientId.UniqueProcess))
    {
        goto Fail;
    }
    Status = SmpQueryProcessCreateTime(Subsystem->ProcessHandle, &HeldCreateTime);
    if (!NT_SUCCESS(Status)) goto Fail;

    /* The sender, by the client id the kernel stamped on the message (its
       thread waits for our reply), must be that same process */
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenProcess(&SenderProcess,
                           PROCESS_QUERY_INFORMATION,
                           &ObjectAttributes,
                           &SmApiMsg->h.ClientId);
    if (!NT_SUCCESS(Status)) goto Fail;
    Status = SmpQueryProcessCreateTime(SenderProcess, &SenderCreateTime);
    NtClose(SenderProcess);
    if (!NT_SUCCESS(Status) || (SenderCreateTime.QuadPart != HeldCreateTime.QuadPart)) goto Fail;

    return Subsystem;

Fail:
    SmpDereferenceSubsystem(Subsystem);
    return NULL;
}

/*
 * SbCreateRemoteProcess to the Windows subsystem of TargetSessionId. The
 * session in the message is the same one except in the SMSS self-test
 * (NitroSessionsTestForward), which checks that the target refuses another.
 */
NTSTATUS
NTAPI
SmpSbCreateRemoteProcessEx(
    _In_ PCLIENT_ID ClientId,
    _In_ ULONG TargetSessionId,
    _In_ ULONG MuSessionId,
    _In_ ULONG Flags)
{
    NTSTATUS Status;
    PSMP_SUBSYSTEM Target;
    ULONG SessionId;
    SB_API_MSG SbApiMsg;
    PSB_CREATE_REMOTE_PROCESS_MSG CreateRemote = &SbApiMsg.u.CreateRemoteProcess;

    /* The Windows subsystem of the target session, connected back to */
    Target = SmpLocateKnownSubSysByType(TargetSessionId, IMAGE_SUBSYSTEM_WINDOWS_GUI);
    if (!Target) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (!Target->SbApiPort)
    {
        SmpDereferenceSubsystem(Target);
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    /* A CSR NT session for the process, as SbCreateSession has one */
    SessionId = SmpAllocateSessionId(Target, NULL);

    RtlZeroMemory(&SbApiMsg, sizeof(SbApiMsg));
    CreateRemote->SessionId = SessionId;
    CreateRemote->MuSessionId = MuSessionId;
    CreateRemote->ClientId = *ClientId;
    CreateRemote->Flags = Flags;
    SbApiMsg.ApiNumber = SbpCreateRemoteProcess;
    SbApiMsg.h.u1.s1.DataLength = sizeof(SB_CREATE_REMOTE_PROCESS_MSG) + 8;
    SbApiMsg.h.u1.s1.TotalLength = sizeof(SbApiMsg);
    Status = NtRequestWaitReplyPort(Target->SbApiPort, &SbApiMsg.h, &SbApiMsg.h);
    if (NT_SUCCESS(Status)) Status = SbApiMsg.ReturnValue;

    if (!NT_SUCCESS(Status)) SmpDeleteSession(SessionId);
    SmpDereferenceSubsystem(Target);
    return Status;
}

NTSTATUS
NTAPI
SmpForwardProcessRegistration(
    _In_ PSM_API_MSG SmApiMsg,
    _In_ PSMP_CLIENT_CONTEXT ClientContext,
    _In_ HANDLE SmApiPort)
{
    PSM_FORWARD_PROCESS_REGISTRATION_MSG Forward = &SmApiMsg->u.ForwardRegistration;
    PSMP_SUBSYSTEM Sender;
    CLIENT_ID ClientId;
    ULONG MuSessionId, Flags, SenderSessionId;
    NTSTATUS Status;

    /* Capture the request */
    ClientId = Forward->ClientId;
    MuSessionId = Forward->MuSessionId;
    Flags = Forward->Flags;

    Sender = SmpLocateSenderCsr(SmApiMsg, ClientContext);
    if (!Sender)
    {
        DPRINT1("SMSS: Forwarded registration refused: %lx.%lx is not a csrss SMSS started\n",
                SmApiMsg->h.ClientId.UniqueProcess, SmApiMsg->h.ClientId.UniqueThread);
        if (SmpNitroSessionsTestForward & SMP_NITRO_TEST_FORWARD_COUNT)
        {
            DPRINT1("SMSS: session records: %lu\n", SmpCountSessions());
        }
        return STATUS_ACCESS_DENIED;
    }
    SenderSessionId = Sender->MuSessionId;
    SmpDereferenceSubsystem(Sender);

    /* Only for another session than the sender's, with known flags */
    if ((Flags & ~SM_REMOTE_PROCESS_VALID_FLAGS) ||
        (MuSessionId == SenderSessionId) ||
        !ClientId.UniqueProcess ||
        !ClientId.UniqueThread)
    {
        DPRINT1("SMSS: Forwarded registration refused: bad request (session %lu from session %lu, flags %lx)\n",
                MuSessionId, SenderSessionId, Flags);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * The forward holds this API thread until the target csrss's Sb thread answers. It cannot deadlock
     * as long as the target answers, because nothing the Sb thread waits for while it answers ever
     * waits for SMSS:
     * - the Sb thread itself never calls SMSS (on failure it drops the NT session quietly, and SMSS
     *   deletes the session record below);
     * - SmSessionComplete, the only SMSS call a csrss makes while it may hold a lock (the last process
     *   of an NT session goes), is a datagram: it is queued, nobody waits for an API thread. It must
     *   never become a waiting request again (see SmpApiLoop and CsrDereferenceNtSession);
     * - the other SMSS call of a running csrss is this forward, from a basesrv API thread that holds no
     *   CSR lock while it waits.
     * So the Sb thread only waits for csrss locks held by threads that make progress, each forward
     * ends, and its API thread comes back.
     *
     * That is no help if the target never answers (its Sb thread stuck on a console lock or a driver,
     * the session going down): the forward has no timeout, and enough of them would take every API
     * thread, and with them every SMSS request of the system (SmExecPgm and SmStartCsr of session 0
     * included). So at most SMP_API_THREADS - 1 forwards run at once and the others get
     * STATUS_DEVICE_BUSY at once, which csrsrv retries for a bounded time and then fails the create
     * with (CsrForwardProcessRegistration). One API thread is always left for everything else; a stuck
     * target costs one SMSS API thread and one csrss API thread, never SMSS.
     */
    if (_InterlockedIncrement(&SmpForwardsInFlight) > (SMP_API_THREADS - 1))
    {
        LONG Number;

        _InterlockedDecrement(&SmpForwardsInFlight);
        Number = SmpClientLogNumber();
        if (Number)
        {
            DPRINT1("SMSS: Forwarded registration of %lx.%lx to session %lu busy: %ld forward(s) in flight (#%ld)\n",
                    ClientId.UniqueProcess, ClientId.UniqueThread, MuSessionId,
                    (LONG)(SMP_API_THREADS - 1), Number);
        }
        return STATUS_DEVICE_BUSY;
    }
    _SEH2_TRY
    {
        if (SmpNitroSessionsTestForwardStall)
        {
            /* Test only: the target csrss that never answers (for a while) */
            LARGE_INTEGER Stall;

            Stall.QuadPart = -10000000LL * SmpNitroSessionsTestForwardStall;
            NtDelayExecution(FALSE, &Stall);
            Status = STATUS_IO_TIMEOUT;
        }
        else
        {
            Status = SmpSbCreateRemoteProcessEx(&ClientId, MuSessionId, MuSessionId, Flags);
        }
    }
    _SEH2_FINALLY
    {
        _InterlockedDecrement(&SmpForwardsInFlight);
    }
    _SEH2_END;
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("SMSS: Forwarded registration of %lx.%lx from session %lu to session %lu failed: %lx\n",
                ClientId.UniqueProcess, ClientId.UniqueThread, SenderSessionId, MuSessionId, Status);
    }
    else
    {
        DPRINT("SMSS: Forwarded registration of %lx.%lx from session %lu to session %lu\n",
               ClientId.UniqueProcess, ClientId.UniqueThread, SenderSessionId, MuSessionId);
    }
    return Status;
}

const PSM_API_HANDLER SmpApiDispatch[SmpMaxApiNumber - SmpCreateForeignSessionApi] =
{
    SmpCreateForeignSession,
    SmpSessionComplete,
    SmpTerminateForeignSession,
    SmpExecPgm,
    SmpLoadDeferedSubsystem,
    SmpStartCsr,
    SmpStopCsr,
    SmpForwardProcessRegistration
};

#if DBG
const PCSTR SmpApiName[SmpMaxApiNumber - SmpCreateForeignSessionApi + 1] =
{
    "SmCreateForeignSession",
    "SmSessionComplete",
    "SmTerminateForeignSession",
    "SmExecPgm",
    "SmLoadDeferedSubsystem",
    "SmStartCsr",
    "SmStopCsr",
    "SmForwardProcessRegistration",
    "Unknown Sm Api Number"
};
#endif

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
SmpHandleConnectionRequest(IN HANDLE SmApiPort,
                           IN PSB_API_MSG SbApiMsg)
{
    BOOLEAN Accept = TRUE;
    HANDLE PortHandle, ProcessHandle;
    ULONG SessionId;
    UNICODE_STRING SubsystemPort;
    PSMP_CLIENT_CONTEXT ClientContext;
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    REMOTE_PORT_VIEW PortView;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    PSMP_SUBSYSTEM CidSubsystem, TypeSubsystem;

    /* Initialize QoS data */
    SecurityQos.ImpersonationLevel = SecurityIdentification;
    SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    SecurityQos.EffectiveOnly = TRUE;

    /* Check if this is SM connecting to itself */
    if (SbApiMsg->h.ClientId.UniqueProcess == SmUniqueProcessId)
    {
        /* No need to get any handle -- assume session 0 */
        ProcessHandle = NULL;
        SessionId = 0;
    }
    else
    {
        /* Reference the foreign process */
        InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
        Status = NtOpenProcess(&ProcessHandle,
                               PROCESS_QUERY_INFORMATION,
                               &ObjectAttributes,
                               &SbApiMsg->h.ClientId);
        if (!NT_SUCCESS(Status)) Accept = FALSE;

        /* Get its session ID */
        SmpGetProcessMuSessionId(ProcessHandle, &SessionId);
    }

    /* See if we already know about the caller's subsystem */
    CidSubsystem = SmpLocateKnownSubSysByCid(&SbApiMsg->h.ClientId);
    if ((CidSubsystem) && (Accept))
    {
        /* Check if we already have a subsystem for this kind of image */
        TypeSubsystem = SmpLocateKnownSubSysByType(SessionId,
                                                   SbApiMsg->ConnectionInfo.SubsystemType);
        if (TypeSubsystem == CidSubsystem)
        {
            /* Someone is trying to take control of an existing subsystem, fail */
            Accept = FALSE;
            DPRINT1("SMSS: Connection from SubSystem rejected\n");
            DPRINT1("SMSS: Image type already being served\n");
        }
        else
        {
            /* Set this image type as the type for this subsystem */
            CidSubsystem->ImageType = SbApiMsg->ConnectionInfo.SubsystemType;
        }

        /* Drop the reference we had acquired */
        if (TypeSubsystem) SmpDereferenceSubsystem(TypeSubsystem);
    }

    /* Check if we'll be accepting the connection */
    if (Accept)
    {
        /* We will, so create a client context for it */
        ClientContext = RtlAllocateHeap(SmpHeap, 0, sizeof(SMP_CLIENT_CONTEXT));
        if (ClientContext)
        {
            ClientContext->ProcessHandle = ProcessHandle;
            ClientContext->Subsystem = CidSubsystem;
            ClientContext->Reserved = NULL;
            ClientContext->PortHandle = NULL;
        }
        else
        {
            /* Failed to allocate a client context, so reject the connection */
            DPRINT1("Rejecting connection due to lack of memory\n");
            Accept = FALSE;
        }
    }
    else
    {
        /* Use a bogus context since we're going to reject the message */
        ClientContext = (PSMP_CLIENT_CONTEXT)SbApiMsg;
    }

    /* Now send the actual accept reply (which could be a rejection) */
    PortView.Length = sizeof(PortView);
    Status = NtAcceptConnectPort(&PortHandle,
                                 ClientContext,
                                 &SbApiMsg->h,
                                 Accept,
                                 NULL,
                                 &PortView);
    if (!(Accept) || !(NT_SUCCESS(Status)))
    {
        /* Close the process handle, reference the subsystem, and exit */
        DPRINT1("Accept failed or rejected: %lx\n", Status);
        if (ClientContext != (PVOID)SbApiMsg) RtlFreeHeap(SmpHeap, 0, ClientContext);
        if (ProcessHandle) NtClose(ProcessHandle);
        if (CidSubsystem) SmpDereferenceSubsystem(CidSubsystem);
        return Status;
    }

    /* Save the port handle now that we've accepted it */
    if (ClientContext) ClientContext->PortHandle = PortHandle;
    if (CidSubsystem) CidSubsystem->PortHandle = PortHandle;

    /* Complete the port connection */
    Status = NtCompleteConnectPort(PortHandle);
    if ((NT_SUCCESS(Status)) && (CidSubsystem))
    {
        /* This was an actual subsystem, so connect back to it */
        SbApiMsg->ConnectionInfo.SbApiPortName[119] = UNICODE_NULL;
        RtlCreateUnicodeString(&SubsystemPort,
                               SbApiMsg->ConnectionInfo.SbApiPortName);
        Status = NtConnectPort(&CidSubsystem->SbApiPort,
                               &SubsystemPort,
                               &SecurityQos,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("SMSS: Connect back to Sb %wZ failed %lx\n", &SubsystemPort, Status);
        }
        RtlFreeUnicodeString(&SubsystemPort);

        /* Now that we're connected, signal the event handle */
        NtSetEvent(CidSubsystem->Event, NULL);
    }
    else if (CidSubsystem)
    {
        /* We failed to complete the connection, so clear the port handle */
        DPRINT1("Completing the connection failed: %lx\n", Status);
        CidSubsystem->PortHandle = NULL;
    }

    /* Dereference the subsystem and return the result */
    if (CidSubsystem) SmpDereferenceSubsystem(CidSubsystem);
    return Status;
}

ULONG
NTAPI
SmpApiLoop(
    _In_ PVOID Parameter)
{
    HANDLE SmApiPort = (HANDLE)Parameter;
    NTSTATUS Status;
    PSMP_CLIENT_CONTEXT ClientContext;
    PSM_API_MSG ReplyMsg = NULL;
    SM_API_MSG RequestMsg;
    PROCESS_BASIC_INFORMATION ProcessInformation;
    LARGE_INTEGER Timeout;

    /* Increase the number of API threads for throttling code for later */
    _InterlockedExchangeAdd(&SmTotalApiThreads, 1);

    /* Mark us critical */
    RtlSetThreadIsCritical(TRUE, NULL, TRUE);

    /* Set the PID of the SM process itself for later checking */
    NtQueryInformationProcess(NtCurrentProcess(),
                              ProcessBasicInformation,
                              &ProcessInformation,
                              sizeof(ProcessInformation),
                              NULL);
    SmUniqueProcessId = (HANDLE)ProcessInformation.UniqueProcessId;

    /* Now process incoming messages */
    while (TRUE)
    {
        /* Begin waiting on a request */
        Status = NtReplyWaitReceivePort(SmApiPort,
                                        (PVOID*)&ClientContext,
                                        &ReplyMsg->h,
                                        &RequestMsg.h);
        if (Status == STATUS_NO_MEMORY)
        {
            /* Ran out of memory, so do a little timeout and try again */
            if (ReplyMsg) DPRINT1("SMSS: Failed to reply to calling thread, retrying.\n");
            Timeout.QuadPart = -50000000;
            NtDelayExecution(FALSE, &Timeout);
            continue;
        }

        /* Check what kind of request we received */
        switch (RequestMsg.h.u2.s2.Type)
        {
            /* A new connection */
            case LPC_CONNECTION_REQUEST:
                /* Create the right structures for it */
                SmpHandleConnectionRequest(SmApiPort, (PSB_API_MSG)&RequestMsg);
                ReplyMsg = NULL;
                break;

            /* A closed connection */
            case LPC_PORT_CLOSED:
                /* Destroy any state we had for this client */
                DPRINT1("Port closed\n");
                //if (ClientContext) SmpPushDeferredClientContext(ClientContext);
                ReplyMsg = NULL;
                break;

            /* An actual API message */
            default:
            {
                if (!ClientContext)
                {
                    ReplyMsg = NULL;
                    break;
                }

                /*
                 * Only a request has a sender waiting for the reply. Replying to anything else fails
                 * (no thread waits for that message id) without receiving, and this loop would serve
                 * the same message again and again. A datagram is accepted for SmSessionComplete only,
                 * which subsystems send without waiting (see SmSessionComplete in smlib). It must never
                 * become a waiting request: csrss sends it with its own locks held (see
                 * CsrDereferenceNtSession).
                 *
                 * The kernel copies only the bytes the sender sent into this thread's reused message
                 * buffer, so the length is checked before ApiNumber or the SessionId are read: a short
                 * datagram would otherwise be read as the stale fields of an earlier message.
                 */
                if (SMP_LPC_TYPE(&RequestMsg) != LPC_REQUEST)
                {
                    LONG Number;

                    ReplyMsg = NULL;
                    if ((SMP_LPC_TYPE(&RequestMsg) != LPC_DATAGRAM) ||
                        (RequestMsg.h.u1.s1.DataLength < SMP_SESSION_COMPLETE_DATA_LENGTH) ||
                        (RequestMsg.h.u1.s1.TotalLength < RequestMsg.h.u1.s1.DataLength + sizeof(PORT_MESSAGE)))
                    {
                        Number = SmpClientLogNumber();
                        if (Number)
                        {
                            DPRINT1("SMSS: Ignoring message type %x, length %u/%u from %lx.%lx (#%ld)\n",
                                    RequestMsg.h.u2.s2.Type,
                                    RequestMsg.h.u1.s1.DataLength, RequestMsg.h.u1.s1.TotalLength,
                                    RequestMsg.h.ClientId.UniqueProcess,
                                    RequestMsg.h.ClientId.UniqueThread, Number);
                        }
                        break;
                    }
                    if (RequestMsg.ApiNumber != SmpSessionCompleteApi)
                    {
                        Number = SmpClientLogNumber();
                        if (Number)
                        {
                            DPRINT1("SMSS: Ignoring datagram, Api %lu from %lx.%lx (#%ld)\n",
                                    RequestMsg.ApiNumber,
                                    RequestMsg.h.ClientId.UniqueProcess,
                                    RequestMsg.h.ClientId.UniqueThread, Number);
                        }
                        break;
                    }
                    _SEH2_TRY
                    {
                        Status = SmpApiDispatch[SmpSessionCompleteApi](&RequestMsg, ClientContext, SmApiPort);
                        if (SmpNitroSessionsTestForward & SMP_NITRO_TEST_FORWARD_COMPLETE)
                        {
                            DPRINT1("SMSS: SmSessionComplete(%lu) from %lx.%lx %s: %lx, session records: %lu\n",
                                    RequestMsg.u.SessionComplete.SessionId,
                                    RequestMsg.h.ClientId.UniqueProcess,
                                    RequestMsg.h.ClientId.UniqueThread,
                                    ClientContext->Subsystem ? "csrss" : "non-csrss", Status,
                                    SmpCountSessions());
                        }
                        else if (!NT_SUCCESS(Status) && (Status != STATUS_NOT_FOUND))
                        {
                            Number = SmpClientLogNumber();
                            if (Number)
                            {
                                DPRINT1("SMSS: SmSessionComplete(%lu) from %lx.%lx: %lx (#%ld)\n",
                                        RequestMsg.u.SessionComplete.SessionId,
                                        RequestMsg.h.ClientId.UniqueProcess,
                                        RequestMsg.h.ClientId.UniqueThread, Status, Number);
                            }
                        }
                    }
                    _SEH2_EXCEPT(SmpUnhandledExceptionFilter(_SEH2_GetExceptionInformation()))
                    {
                        _SEH2_YIELD(break);
                    }
                    _SEH2_END;
                    break;
                }

#if DBG
                DPRINT("SMSS: %s Api Request received from %lx.%lx\n",
                       SmpApiName[min(RequestMsg.ApiNumber, SmpMaxApiNumber)],
                       RequestMsg.h.ClientId.UniqueProcess,
                       RequestMsg.h.ClientId.UniqueThread);
#endif

                RequestMsg.ReturnValue = STATUS_PENDING;

                /* Check if the API is valid */
                if (RequestMsg.ApiNumber >= SmpMaxApiNumber)
                {
                    /* It isn't, fail */
                    DPRINT1("SMSS: Invalid Sm Api Number %lx\n", RequestMsg.ApiNumber);
                    Status = STATUS_NOT_IMPLEMENTED;
                }
                else if ((RequestMsg.ApiNumber <= SmpTerminateForeignSessionApi) &&
                         !(ClientContext->Subsystem))
                {
                    /* It's valid, but doesn't have a subsystem with it */
                    DPRINT1("SMSS: Invalid session API\n");
                    Status = STATUS_INVALID_PARAMETER;
                }
                else if (((RequestMsg.ApiNumber == SmpExecPgmApi) ||
                          (RequestMsg.ApiNumber == SmpStartCsrApi) ||
                          (RequestMsg.ApiNumber == SmpStopCsrApi)) &&
                         !SmpIsSessionZeroSystemClient(&RequestMsg, ClientContext))
                {
                    /* Gate S8: only SMSS and LocalSystem in session 0 */
                    DPRINT1("SMSS: Api %lu refused for %lx.%lx\n",
                            RequestMsg.ApiNumber,
                            RequestMsg.h.ClientId.UniqueProcess,
                            RequestMsg.h.ClientId.UniqueThread);
                    Status = STATUS_ACCESS_DENIED;
                }
                else
                {
                    /* It's totally okay, so call the dispatcher for it */
                    _SEH2_TRY
                    {
                        Status = SmpApiDispatch[RequestMsg.ApiNumber](&RequestMsg,
                                                                      ClientContext,
                                                                      SmApiPort);
                    }
                    _SEH2_EXCEPT(SmpUnhandledExceptionFilter(_SEH2_GetExceptionInformation()))
                    {
                        ReplyMsg = NULL;
                        _SEH2_YIELD(break);
                    }
                    _SEH2_END;
                }

                /* Write the result value and return the message back */
                RequestMsg.ReturnValue = Status;
                ReplyMsg = &RequestMsg;
                break;
            }
        }
    }

    UNREACHABLE;
    return STATUS_UNSUCCESSFUL;
}
