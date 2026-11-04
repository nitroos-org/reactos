/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Process mitigation policies of Windows 8 and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

#define NDEBUG
#include <debug.h>

/*
 * The system enforces none of the policies except DEP, so every policy is reported as not enabled. A request to
 * enable a policy that restricts the process itself is accepted, as it is on Windows, and has no effect; a request
 * that Windows refuses is refused here with the same error. The rules of what is accepted are the ones that
 * Windows 10 gave for the first request of a process; they depend on the flags alone, the system keeps no state.
 */

/* FUNCTIONS ******************************************************************/

static
ULONG
BasepMitigationLength(
    _In_ PROCESS_MITIGATION_POLICY Policy)
{
    return (Policy == ProcessDEPPolicy || Policy == ProcessMitigationOptionsMask) ? 8 : 4;
}

/* The error that Windows gives to a request that sets these flags, ERROR_SUCCESS if it accepts them */
static
ULONG
BasepCheckMitigationFlags(
    _In_ PROCESS_MITIGATION_POLICY Policy,
    _In_ ULONG Flags)
{
    switch (Policy)
    {
        case ProcessASLRPolicy:
            if (Flags & ~0xF)
                return ERROR_INVALID_PARAMETER;
            /* Bottom-up randomization is on and stays on */
            return (Flags & 1) ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;

        case ProcessDynamicCodePolicy:
            if ((Flags & ~0xF) || ((Flags & 6) && !(Flags & 1)))
                return ERROR_INVALID_PARAMETER;
            return ERROR_SUCCESS;

        case ProcessStrictHandleCheckPolicy:
            return (Flags == 0 || Flags == 3) ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;

        case ProcessSystemCallDisablePolicy:
        case ProcessFontDisablePolicy:
        case ProcessRedirectionTrustPolicy:
            return (Flags & ~3) ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;

        case ProcessExtensionPointDisablePolicy:
            return (Flags & ~1) ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;

        case ProcessControlFlowGuardPolicy:
            /* Control flow guard is decided when the image is loaded */
            return (Flags & ~7) ? ERROR_INVALID_PARAMETER : ERROR_ACCESS_DENIED;

        case ProcessSignaturePolicy:
            if ((Flags & ~0x1F) || (Flags & 3) == 3)
                return ERROR_INVALID_PARAMETER;
            /* Store signed images only: not on a system without the store */
            return (Flags & 2) ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;

        case ProcessImageLoadPolicy:
            return (Flags & ~0x1F) ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;

        case ProcessChildProcessPolicy:
            if ((Flags & ~7) || ((Flags & 4) && !(Flags & 1)))
                return ERROR_INVALID_PARAMETER;
            return ERROR_SUCCESS;

        case ProcessSideChannelIsolationPolicy:
            return (Flags & ~0xF) ? ERROR_INVALID_PARAMETER : ERROR_SUCCESS;

        case ProcessUserShadowStackPolicy:
            /* Only a changed request for the strict dynamic API flag is taken; hardware stacks are not there */
            if (Flags & ~0x3FF)
                return ERROR_INVALID_PARAMETER;
            return (Flags == 0x100) ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;

        default:
            /* DEP cannot be changed, the options mask, the system call filter and the payload restrictions cannot be set */
            return ERROR_INVALID_PARAMETER;
    }
}

/*
 * @implemented
 */
BOOL
WINAPI
GetProcessMitigationPolicy(
    _In_ HANDLE hProcess,
    _In_ PROCESS_MITIGATION_POLICY MitigationPolicy,
    _Out_writes_bytes_(nLength) PVOID lpBuffer,
    _In_ SIZE_T nLength)
{
    ULONG ExecuteFlags = 0;
    ULONG Length;
    NTSTATUS Status;

    if ((ULONG)MitigationPolicy > ProcessRedirectionTrustPolicy)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Length = BasepMitigationLength(MitigationPolicy);
    if (MitigationPolicy == ProcessMitigationOptionsMask ? nLength < Length : nLength != Length)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* The right to read the DEP state is the one that reads the process, the others need less */
    Status = BasepCheckHandleType(hProcess,
                                  L"Process",
                                  MitigationPolicy == ProcessDEPPolicy ?
                                      PROCESS_QUERY_INFORMATION :
                                      (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION));
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    if (MitigationPolicy == ProcessDEPPolicy)
    {
        PROCESS_BASIC_INFORMATION BasicInfo;

        /*
         * DEP is the one policy that the system enforces. The kernel tells the execute flags of the calling process,
         * and only through the pseudo handle; the handle of another process is reported as not enabled.
         */
        Status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
        if (NT_SUCCESS(Status) && BasicInfo.UniqueProcessId == (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess)
        {
            Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessExecuteFlags, &ExecuteFlags, sizeof(ExecuteFlags), NULL);
            if (!NT_SUCCESS(Status))
                ExecuteFlags = 0;
        }
    }

    _SEH2_TRY
    {
        if (MitigationPolicy == ProcessDEPPolicy)
        {
            PROCESS_MITIGATION_DEP_POLICY Policy = {{0}};

            if (ExecuteFlags & MEM_EXECUTE_OPTION_DISABLE)
                Policy.Flags |= 1;
            if (ExecuteFlags & MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION)
                Policy.Flags |= 2;
            Policy.Permanent = (ExecuteFlags & MEM_EXECUTE_OPTION_PERMANENT) != 0;

            /* The structure has padding behind the flag that is not written */
            ((PULONG)lpBuffer)[0] = Policy.Flags;
            ((PBOOLEAN)lpBuffer)[4] = Policy.Permanent;
        }
        else if (MitigationPolicy == ProcessMitigationOptionsMask)
        {
            RtlZeroMemory(lpBuffer, nLength);
        }
        else
        {
            *(PULONG)lpBuffer = 0;
        }
        Status = STATUS_SUCCESS;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetProcessMitigationPolicy(
    _In_ PROCESS_MITIGATION_POLICY MitigationPolicy,
    _In_reads_bytes_(nLength) PVOID lpBuffer,
    _In_ SIZE_T nLength)
{
    ULONG Flags = 0, Error;
    NTSTATUS Status = STATUS_SUCCESS;

    if ((ULONG)MitigationPolicy > ProcessRedirectionTrustPolicy)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* DEP of a 64-bit system cannot be changed, whatever the request */
    if (MitigationPolicy == ProcessDEPPolicy)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    if (nLength != BasepMitigationLength(MitigationPolicy))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    _SEH2_TRY
    {
        Flags = *(PULONG)lpBuffer;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = STATUS_ACCESS_VIOLATION;
    }
    _SEH2_END;

    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    Error = BasepCheckMitigationFlags(MitigationPolicy, Flags);
    if (Error != ERROR_SUCCESS)
    {
        SetLastError(Error);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 *
 * The CPU/OS pair of this system has no user mode shadow stacks (CET): not available in any environment.
 */
BOOL
WINAPI
IsUserCetAvailableInEnvironment(
    _In_ DWORD UserCetEnvironment)
{
    return FALSE;
}

#define BASEP_ENCLAVE_TYPE_SGX        0x00000001
#define BASEP_ENCLAVE_TYPE_SGX2       0x00000002
#define BASEP_ENCLAVE_TYPE_VBS        0x00000010
#define BASEP_ENCLAVE_TYPE_VBS_BASIC  0x00000011

/*
 * @implemented
 *
 * No enclave type is supported: there is neither SGX nor virtualization based security. An unknown type is an
 * invalid parameter, a known one is ERROR_NOT_SUPPORTED. (Inferred from the API contract; not measured.)
 */
BOOL
WINAPI
IsEnclaveTypeSupported(
    _In_ DWORD flEnclaveType)
{
    switch (flEnclaveType)
    {
        case BASEP_ENCLAVE_TYPE_SGX:
        case BASEP_ENCLAVE_TYPE_SGX2:
        case BASEP_ENCLAVE_TYPE_VBS:
        case BASEP_ENCLAVE_TYPE_VBS_BASIC:
            SetLastError(ERROR_NOT_SUPPORTED);
            break;

        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            break;
    }

    return FALSE;
}

/* EOF */
