/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS User API Server DLL
 * FILE:            win32ss/user/winsrv/usersrv/register.c
 * PURPOSE:         Register logon window and services process
 * PROGRAMMERS:     Eric Kohl
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/* INCLUDES *******************************************************************/

#include "usersrv.h"

#include <ndk/sefuncs.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

static BOOLEAN ServicesProcessIdValid = FALSE;
ULONG_PTR ServicesProcessId = 0;
ULONG_PTR LogonProcessId = 0;

#if 1 //HACK! See use below
extern HANDLE CsrApiPort;
#endif

/* PRIVATE FUNCTIONS **********************************************************/

/*
 * Only the logon process (winlogon) and the service control manager register
 * with the user server, and both run as LocalSystem. Without this check the
 * first process to send the message took the slot. The caller must run as
 * LocalSystem (its process token, not an impersonation token) and may only
 * register itself.
 */
static NTSTATUS
UserpCheckRegistrationCaller(
    _In_ PCSR_API_MESSAGE ApiMessage,
    _In_ ULONG_PTR ProcessId)
{
    static SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PCSR_THREAD CsrThread = CsrGetClientThread();
    UCHAR Buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    PTOKEN_USER UserInfo = (PTOKEN_USER)Buffer;
    PSID SystemSid = NULL;
    HANDLE Token;
    ULONG Length;
    BOOLEAN IsSystem;
    NTSTATUS Status;

    if (CsrThread == NULL || CsrThread->Process == NULL)
        return STATUS_ACCESS_DENIED;

    if (ProcessId != (ULONG_PTR)ApiMessage->Header.ClientId.UniqueProcess)
    {
        DPRINT1("USERSRV: process 0x%Ix tried to register process 0x%Ix\n",
                (ULONG_PTR)ApiMessage->Header.ClientId.UniqueProcess, ProcessId);
        return STATUS_ACCESS_DENIED;
    }

    Status = NtOpenProcessToken(CsrThread->Process->ProcessHandle, TOKEN_QUERY, &Token);
    if (!NT_SUCCESS(Status))
        return STATUS_ACCESS_DENIED;

    Status = NtQueryInformationToken(Token, TokenUser, UserInfo, sizeof(Buffer), &Length);
    NtClose(Token);
    if (!NT_SUCCESS(Status))
        return STATUS_ACCESS_DENIED;

    Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                         0, 0, 0, 0, 0, 0, 0, &SystemSid);
    if (!NT_SUCCESS(Status))
        return Status;

    IsSystem = RtlEqualSid(UserInfo->User.Sid, SystemSid);
    RtlFreeSid(SystemSid);

    if (!IsSystem)
    {
        DPRINT1("USERSRV: process 0x%Ix is not LocalSystem, registration refused\n", ProcessId);
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

/* PUBLIC SERVER APIS *********************************************************/

/* API_NUMBER: UserpRegisterLogonProcess */
CSR_API(SrvRegisterLogonProcess)
{
    PUSER_REGISTER_LOGON_PROCESS RegisterLogonProcessRequest = &((PUSER_API_MESSAGE)ApiMessage)->Data.RegisterLogonProcessRequest;

    ULONG_PTR ProcessId = RegisterLogonProcessRequest->ProcessId;

    if (RegisterLogonProcessRequest->Register)
    {
        NTSTATUS Status = UserpCheckRegistrationCaller(ApiMessage, ProcessId);
        if (!NT_SUCCESS(Status))
            return Status;

        if (LogonProcessId != 0)
            return STATUS_LOGON_SESSION_EXISTS;

        LogonProcessId = ProcessId;
    }
    else
    {
        if (ApiMessage->Header.ClientId.UniqueProcess != UlongToHandle(LogonProcessId))
        {
            DPRINT1("Current logon process 0x%x, can't deregister from process 0x%x\n",
                    LogonProcessId, ApiMessage->Header.ClientId.UniqueProcess);
            return STATUS_NOT_LOGON_PROCESS;
        }

        LogonProcessId = 0;
    }

#if 1 //HAAAACK. This should be done in UserClientConnect which is never called!

    /* Check if we don't have an API port yet */
    if (CsrApiPort == NULL)
    {
        NTSTATUS Status;

        /* Query the API port and save it globally */
        CsrApiPort = CsrQueryApiPort();

        DPRINT("Giving win32k our api port\n");

        /* Inform win32k about the API port */
        Status = NtUserSetInformationThread(NtCurrentThread(),
                                            UserThreadCsrApiPort,
                                            &CsrApiPort,
                                            sizeof(CsrApiPort));
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }
#endif

    return STATUS_SUCCESS;
}

/* API_NUMBER: UserpRegisterServicesProcess */
CSR_API(SrvRegisterServicesProcess)
{
    PUSER_REGISTER_SERVICES_PROCESS RegisterServicesProcessRequest = &((PUSER_API_MESSAGE)ApiMessage)->Data.RegisterServicesProcessRequest;

    ULONG_PTR ProcessId = RegisterServicesProcessRequest->ProcessId;
    NTSTATUS Status;

    Status = UserpCheckRegistrationCaller(ApiMessage, ProcessId);
    if (!NT_SUCCESS(Status))
        return Status;

    if (ServicesProcessIdValid)
    {
        /* Only accept a single call */
        return STATUS_INVALID_PARAMETER;
    }
    else
    {
        ServicesProcessId = ProcessId;
        ServicesProcessIdValid = TRUE;
        return STATUS_SUCCESS;
    }
}

/* EOF */
