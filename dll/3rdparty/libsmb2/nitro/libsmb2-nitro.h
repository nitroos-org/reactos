/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     NitroOS additions to the libsmb2 API (exported by libsmb2.dll): SSPI credentials, error mapping
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef NITRO_LIBSMB2_NITRO_H
#define NITRO_LIBSMB2_NITRO_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct smb2_context;

/*
 * Authentication on NitroOS goes through SSPI (package "Negotiate" unless
 * smb2_set_authentication() asked for SMB2_SEC_NTLMSSP = "NTLM" or
 * SMB2_SEC_KRB5 = "Kerberos"). The built-in NTLMSSP of libsmb2 is not built.
 *
 * NitroSmb2SetCredentials() acquires the SSPI credentials at once, in the
 * security context of the calling thread:
 *   user == NULL and password == NULL: the caller's own logon session
 *     (single sign-on). A service impersonates its client around this call;
 *     the credentials stay bound to that logon session afterwards (the
 *     context keeps the impersonation token and impersonates it around
 *     every InitializeSecurityContext call).
 *   otherwise: explicit credentials (user, domain may be NULL, password must
 *     not be NULL; an empty string is an empty password). The library keeps
 *     no copy of the password: the caller may wipe it on return.
 * Call it before smb2_connect_share*(); the credentials are kept by the
 * context (released by smb2_destroy_context()) and reused for every connect.
 * Without this call the first connect acquires credentials itself: explicit
 * from smb2_set_user()/smb2_set_domain()/smb2_set_password() when a password
 * was set (the context's copy of the password is wiped then), otherwise
 * single sign-on in the thread that runs smb2_service().
 * package == NULL selects the package from smb2_set_authentication().
 * Returns 0, or -errno with smb2_get_error() describing the SSPI status.
 */
int NitroSmb2SetCredentials(struct smb2_context *smb2, const char *user, const char *domain,
                            const char *password, const char *package);

/*
 * Win32 error for an NTSTATUS a server sent (wire status), as the Windows
 * SMB client reports it through `net use` / WNetAddConnection2 (measured
 * where the table says so, RtlNtStatusToDosError otherwise). 0 for success.
 */
uint32_t NitroSmb2StatusToWin32(uint32_t status);

/*
 * Win32 error for a failed libsmb2 call on this context (rc < 0), from the
 * wire status if the server sent one, otherwise from where the connection
 * failed: name not resolved, unreachable, refused or timed out = 53,
 * dropped by the server after the TCP connect (e.g. an SMB1-only server
 * resetting on our SMB2 NEGOTIATE) = 64, a guest/anonymous session offered
 * by the server and refused here = 1272, a failed SSPI step = 1326 for
 * SEC_E_LOGON_DENIED, otherwise 5. 0 for rc >= 0.
 */
uint32_t NitroSmb2ErrorToWin32(struct smb2_context *smb2, int rc);

#define NITRO_SMB2_REASON_NONE          0
#define NITRO_SMB2_REASON_SSPI          1  /* an SSPI call failed: see sspi_status */
#define NITRO_SMB2_REASON_GUEST_REFUSED 2  /* server granted a guest or anonymous session */
#define NITRO_SMB2_REASON_MUTUAL_AUTH   3  /* the server's last token was missing or did not verify */
#define NITRO_SMB2_REASON_NO_MEMORY     4

struct nitro_smb2_auth_info
{
    uint32_t size;                /* in: sizeof(struct nitro_smb2_auth_info) */
    int explicit_credentials;     /* 1 explicit user/password, 0 single sign-on */
    int spnego;                   /* 1 the exchange ran in SPNEGO, 0 raw (NTLMSSP) */
    int server_token_verified;    /* 1 the server's last SPNEGO token (mechListMIC) was checked by SSPI */
    int tcp_connected;
    int negotiated;
    int authenticated;
    int reason;                   /* NITRO_SMB2_REASON_* of the last failure */
    uint32_t sspi_status;         /* SECURITY_STATUS of the last failed SSPI call */
    uint16_t session_flags;       /* SESSION_SETUP response SessionFlags */
    uint16_t session_key_length;
    char package[32];             /* the SSPI package asked for */
};

int NitroSmb2GetAuthInfo(struct smb2_context *smb2, struct nitro_smb2_auth_info *info);

#ifdef __cplusplus
}
#endif

#endif /* NITRO_LIBSMB2_NITRO_H */
