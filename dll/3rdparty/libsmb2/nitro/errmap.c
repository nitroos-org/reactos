/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Win32 error codes for SMB failures, as the Windows SMB client reports them
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Measured on Windows 10 22H2 and Windows Server 2022 as SMB clients
 * (`net use`, evidence smb00-20261117 README rows 17-24):
 *   wire STATUS_LOGON_FAILURE (SESSION_SETUP, wrong password or unknown user)  1326
 *   wire STATUS_BAD_NETWORK_NAME (TREE_CONNECT, unknown share)                 53, not 67
 *   wire STATUS_ACCESS_DENIED (e.g. encrypted share over SMB 2.1)              5
 *   name not resolved                                                          53
 *   host unreachable / no answer (IPv4 and IPv6)                               53
 *   SMB1-only server resets the connection after the SMB2 NEGOTIATE            64
 * Not measured, and why the value:
 *   other wire statuses: RtlNtStatusToDosError (the system's table)
 *   connection lost later (after NEGOTIATE): 64, ERROR_NETNAME_DELETED, as for
 *     the reset above
 *   guest session refused by this client: 1272 ERROR_SMB_GUEST_LOGON_BLOCKED
 *     (the documented code for a blocked insecure guest logon; VERIFY ON a
 *     stock Windows with insecure guest logons disabled)
 *   SSPI failure before the server answered: SEC_E_LOGON_DENIED 1326, other 5
 */

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <stdint.h>
#include <errno.h>

#include "libsmb2-nitro.h"

#ifndef ERROR_SMB_GUEST_LOGON_BLOCKED
#define ERROR_SMB_GUEST_LOGON_BLOCKED 1272
#endif

struct smb2_context;
int smb2_get_nterror(struct smb2_context *smb2);
int smb2_sspi_failure(struct smb2_context *smb2, int *tcp_connected, int *negotiated,
                      int *reason, uint32_t *sspi_status);

ULONG NTAPI RtlNtStatusToDosError(LONG Status);

uint32_t NitroSmb2StatusToWin32(uint32_t status)
{
    if ((status & 0xC0000000) != 0xC0000000 && (status & 0xC0000000) != 0x80000000)
        return ERROR_SUCCESS;   /* success and informational */
    switch (status)
    {
        case 0xC000006D: /* STATUS_LOGON_FAILURE */
            return ERROR_LOGON_FAILURE;          /* 1326, measured */
        case 0xC00000CC: /* STATUS_BAD_NETWORK_NAME */
            return ERROR_BAD_NETPATH;            /* 53, measured (not 67) */
        case 0xC0000022: /* STATUS_ACCESS_DENIED */
            return ERROR_ACCESS_DENIED;          /* 5, measured */
    }
    return RtlNtStatusToDosError((LONG)status);
}

uint32_t NitroSmb2ErrorToWin32(struct smb2_context *smb2, int rc)
{
    int tcp_connected, negotiated, reason;
    uint32_t sspi_status, nt;

    if (rc >= 0)
        return ERROR_SUCCESS;
    if (smb2 == NULL)
        return ERROR_INVALID_PARAMETER;
    smb2_sspi_failure(smb2, &tcp_connected, &negotiated, &reason, &sspi_status);
    if (reason == NITRO_SMB2_REASON_GUEST_REFUSED)
        return ERROR_SMB_GUEST_LOGON_BLOCKED;
    nt = (uint32_t)smb2_get_nterror(smb2);
    if (nt != 0 && NitroSmb2StatusToWin32(nt) != ERROR_SUCCESS)
        return NitroSmb2StatusToWin32(nt);
    if (reason == NITRO_SMB2_REASON_NO_MEMORY)
        return ERROR_NOT_ENOUGH_MEMORY;
    if (reason == NITRO_SMB2_REASON_SSPI || reason == NITRO_SMB2_REASON_MUTUAL_AUTH)
        return sspi_status == (uint32_t)SEC_E_LOGON_DENIED ? ERROR_LOGON_FAILURE : ERROR_ACCESS_DENIED;
    if (!tcp_connected)
        return ERROR_BAD_NETPATH;                /* 53 */
    if (negotiated && rc == -EACCES)
        return ERROR_ACCESS_DENIED;              /* a local refusal: signing or sealing not possible */
    return ERROR_NETNAME_DELETED;                /* 64 */
}
