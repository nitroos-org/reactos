/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SSPI authentication backend of libsmb2: session setup through the platform's Negotiate package
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * libsmb2 has two authentication backends of its own, the built-in NTLMSSP
 * (lib/ntlmssp.c, needs the plaintext password) and krb5 over GSSAPI. This
 * file is the third, beside them in lib/libsmb2.c (HAVE_SSPI); on NitroOS it
 * is the only one built.
 *
 * Flow (lib/libsmb2.c hooks):
 *   connect_cb             -> smb2_sspi_transport_connected()
 *   negotiate_cb           -> smb2_sspi_negotiate_reply(): credentials (unless
 *                             NitroSmb2SetCredentials() acquired them), keeps
 *                             the server's SPNEGO hint (NEGOTIATE response
 *                             security buffer) for the first ISC call
 *   send_session_setup_request -> smb2_sspi_session_request(): one
 *                             InitializeSecurityContext call per leg; its
 *                             token goes on the wire as is (with the hint the
 *                             Negotiate package produces SPNEGO itself, so
 *                             libsmb2's own SPNEGO wrapping is not used)
 *   session_setup_cb (SUCCESS) -> smb2_sspi_session_complete(): guest and
 *                             anonymous sessions are refused; if the context
 *                             is not complete yet (SPNEGO: the server's
 *                             accept-completed + mechListMIC is in this
 *                             response) the token goes to ISC, which must
 *                             return SEC_E_OK; then SECPKG_ATTR_SESSION_KEY
 *                             becomes smb2->session_key, from which libsmb2
 *                             derives the signing and encryption keys
 *   free_c_data            -> smb2_sspi_free_auth_data(): DeleteSecurityContext
 *   smb2_destroy_context   -> smb2_sspi_destroy(): FreeCredentialsHandle,
 *                             secrets wiped
 * Package: "Negotiate" (SMB2_SEC_UNDEFINED, the default), "NTLM"
 * (SMB2_SEC_NTLMSSP), "Kerberos" (SMB2_SEC_KRB5/IAKERB).
 * Windows measured (evidence spnego-20261117): with the server's hint and
 * explicit credentials the Negotiate client sends a NegTokenInit {NTLM};
 * without a hint explicit credentials run raw NTLM; the caller's own
 * credentials always use SPNEGO.
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "compat.h"

#define SECURITY_WIN32
#include <sspi.h>

#include "slist.h"
#include "smb2.h"
#include "libsmb2.h"
#include "libsmb2-raw.h"
#include "libsmb2-private.h"
#include "nitro-sspi.h"
#include "libsmb2-nitro.h"

#define SSPI_MAX_LEGS 8
#define SSPI_ISC_FLAGS (ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY | ISC_REQ_SEQUENCE_DETECT)

/* Per smb2_context (smb2->sspi) */
struct smb2_sspi_ctx
{
    CredHandle cred;
    int have_cred;
    int cred_failed;            /* NitroSmb2SetCredentials() failed: never fall back to other credentials */
    int explicit_cred;
    HANDLE sso_token;           /* impersonation token of the thread that acquired SSO credentials */
    ULONG max_token;
    char package[32];
    int tcp_connected;
    int negotiated;
    int authenticated;
    int spnego;
    int server_token_verified;
    int reason;
    SECURITY_STATUS sspi_status;
    uint16_t session_flags;
    uint16_t session_key_length;
};

/* Per session setup (c_data->auth_data) */
struct smb2_sspi_auth
{
    struct smb2_sspi_ctx *ctx;
    CtxtHandle h;
    int have_h;
    int complete;
    int legs;
    uint8_t *hint;
    int hint_len;
    uint8_t *out;
    ULONG out_size;
    ULONG out_len;
    WCHAR *target;
};

static struct smb2_sspi_ctx *get_ctx(struct smb2_context *smb2)
{
    if (smb2->sspi == NULL)
        smb2->sspi = calloc(1, sizeof(*smb2->sspi));
    return smb2->sspi;
}

static void wipe_string(const char *s)
{
    if (s)
        SecureZeroMemory((void *)s, strlen(s));
}

/* UTF-8 to a new UTF-16 string; *len = length in WCHARs. NULL on failure. */
static WCHAR *to_utf16(const char *s, unsigned long *len)
{
    int n;
    WCHAR *w;

    if (s == NULL)
        s = "";
    n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    w = calloc((size_t)n, sizeof(WCHAR));
    if (w == NULL)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n)
    {
        free(w);
        return NULL;
    }
    if (len)
        *len = (unsigned long)(n - 1);
    return w;
}

static void free_wipe_w(WCHAR *w, unsigned long len)
{
    if (w)
    {
        SecureZeroMemory(w, (len + 1) * sizeof(WCHAR));
        free(w);
    }
}

static const char *package_for(struct smb2_context *smb2)
{
    switch (smb2->sec)
    {
        case SMB2_SEC_NTLMSSP:
            return "NTLM";
        case SMB2_SEC_KRB5:
        case SMB2_SEC_IAKERB:
            return "Kerberos";
        default:
            return "Negotiate";
    }
}

static void fail(struct smb2_context *smb2, struct smb2_sspi_ctx *ctx, int reason,
                 SECURITY_STATUS status, const char *what)
{
    if (ctx)
    {
        ctx->reason = reason;
        if (reason == NITRO_SMB2_REASON_SSPI || reason == NITRO_SMB2_REASON_MUTUAL_AUTH)
            ctx->sspi_status = status;
    }
    if (status)
        smb2_set_error(smb2, "SSPI: %s (0x%08lx)", what, (unsigned long)status);
    else
        smb2_set_error(smb2, "SSPI: %s", what);
}

static void release_cred(struct smb2_sspi_ctx *ctx)
{
    if (ctx->have_cred)
    {
        FreeCredentialsHandle(&ctx->cred);
        ctx->have_cred = 0;
    }
    if (ctx->sso_token)
    {
        CloseHandle(ctx->sso_token);
        ctx->sso_token = NULL;
    }
}

/* AcquireCredentialsHandle; password is only read here. */
static int acquire(struct smb2_context *smb2, struct smb2_sspi_ctx *ctx, const char *user,
                   const char *domain, const char *password, const char *package)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    WCHAR *wpkg = NULL, *wuser = NULL, *wdomain = NULL, *wpassword = NULL;
    unsigned long lpkg = 0, luser = 0, ldomain = 0, lpassword = 0;
    PSecPkgInfoW info = NULL;
    TimeStamp expiry;
    SECURITY_STATUS status;
    int explicit_cred = (user != NULL || password != NULL);
    int ret = -1;

    if (explicit_cred && (user == NULL || password == NULL))
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, 0, "explicit credentials need a user and a password");
        return -EINVAL;
    }
    if (strlen(package) >= sizeof(ctx->package))
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, 0, "package name too long");
        return -EINVAL;
    }
    wpkg = to_utf16(package, &lpkg);
    if (wpkg == NULL)
        goto nomem;
    if (explicit_cred)
    {
        wuser = to_utf16(user, &luser);
        wdomain = to_utf16(domain, &ldomain);
        wpassword = to_utf16(password, &lpassword);
        if (wuser == NULL || wdomain == NULL || wpassword == NULL)
            goto nomem;
        memset(&id, 0, sizeof(id));
        id.User = (unsigned short *)wuser;
        id.UserLength = luser;
        id.Domain = (unsigned short *)wdomain;
        id.DomainLength = ldomain;
        id.Password = (unsigned short *)wpassword;
        id.PasswordLength = lpassword;
        id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    }

    release_cred(ctx);
    status = AcquireCredentialsHandleW(NULL, wpkg, SECPKG_CRED_OUTBOUND, NULL,
                                       explicit_cred ? &id : NULL, NULL, NULL,
                                       &ctx->cred, &expiry);
    if (explicit_cred)
        SecureZeroMemory(&id, sizeof(id));
    if (status != SEC_E_OK)
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, status, "AcquireCredentialsHandle failed");
        ret = -EACCES;
        goto out;
    }
    ctx->have_cred = 1;
    ctx->explicit_cred = explicit_cred;
    strcpy(ctx->package, package);
    /* Single sign-on acquired while impersonating: keep that token, and
     * impersonate it again around every InitializeSecurityContext call.
     * NitroOS's in-process NTLM takes the default credentials from the token
     * of the thread that calls InitializeSecurityContext, not from the one
     * that acquired the handle (measured: SSO failed with LOGON_FAILURE when
     * the service reverted between the two). With this the documented
     * contract holds either way. */
    if (!explicit_cred &&
        !OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE | TOKEN_QUERY, TRUE, &ctx->sso_token) &&
        !OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE | TOKEN_QUERY, FALSE, &ctx->sso_token))
        ctx->sso_token = NULL;     /* not impersonating: the process's own logon session */

    ctx->max_token = 12000;
    if (QuerySecurityPackageInfoW(wpkg, &info) == SEC_E_OK && info)
    {
        if (info->cbMaxToken > ctx->max_token)
            ctx->max_token = info->cbMaxToken;
        FreeContextBuffer(info);
    }
    if (ctx->max_token > 0xFFFF)
        ctx->max_token = 0xFFFF;
    ret = 0;
    goto out;

nomem:
    fail(smb2, ctx, NITRO_SMB2_REASON_NO_MEMORY, 0, "out of memory or invalid UTF-8 in the credentials");
    ret = -ENOMEM;
out:
    free(wpkg);
    free_wipe_w(wuser, luser);
    free_wipe_w(wdomain, ldomain);
    free_wipe_w(wpassword, lpassword);
    return ret;
}

int NitroSmb2SetCredentials(struct smb2_context *smb2, const char *user, const char *domain,
                            const char *password, const char *package)
{
    struct smb2_sspi_ctx *ctx;
    int ret;

    if (smb2 == NULL)
        return -EINVAL;
    ctx = get_ctx(smb2);
    if (ctx == NULL)
    {
        smb2_set_error(smb2, "SSPI: out of memory");
        return -ENOMEM;
    }
    ret = acquire(smb2, ctx, user, domain, password, package ? package : package_for(smb2));
    ctx->cred_failed = ret < 0;
    /* these credentials replace any password set on the context */
    if (smb2->password)
    {
        wipe_string(smb2->password);
        free((void *)smb2->password);
        smb2->password = NULL;
    }
    return ret;
}

void smb2_sspi_transport_connected(struct smb2_context *smb2)
{
    struct smb2_sspi_ctx *ctx = get_ctx(smb2);

    if (ctx)
        ctx->tcp_connected = 1;
}

void *smb2_sspi_negotiate_reply(struct smb2_context *smb2, const char *server,
                                const uint8_t *hint, int hint_len)
{
    struct smb2_sspi_ctx *ctx = get_ctx(smb2);
    struct smb2_sspi_auth *auth;
    char *spn = NULL;

    if (ctx == NULL)
    {
        smb2_set_error(smb2, "SSPI: out of memory");
        return NULL;
    }
    ctx->negotiated = 1;
    ctx->reason = NITRO_SMB2_REASON_NONE;
    ctx->sspi_status = 0;
    ctx->authenticated = 0;
    ctx->spnego = 0;
    ctx->server_token_verified = 0;
    ctx->session_flags = 0;
    ctx->session_key_length = 0;

    if (!ctx->have_cred && ctx->cred_failed)
    {
        /* the caller's credentials could not be acquired: do not connect
         * with any others (in particular not the service's own) */
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, ctx->sspi_status, "the credentials set for this context could not be acquired");
        return NULL;
    }
    if (!ctx->have_cred)
    {
        int ret;

        if (smb2->password)
        {
            /* explicit, from smb2_set_password(): the context's copy of the
             * password is not needed after this */
            ret = acquire(smb2, ctx, smb2->user ? smb2->user : "", smb2->domain,
                          smb2->password, package_for(smb2));
            wipe_string(smb2->password);
            free((void *)smb2->password);
            smb2->password = NULL;
        }
        else
        {
            /* single sign-on: the logon session of this thread's token */
            ret = acquire(smb2, ctx, NULL, NULL, NULL, package_for(smb2));
        }
        if (ret < 0)
            return NULL;
    }

    auth = calloc(1, sizeof(*auth));
    if (auth == NULL)
        goto nomem;
    auth->ctx = ctx;
    auth->out_size = ctx->max_token;
    auth->out = malloc(auth->out_size);
    if (auth->out == NULL)
        goto nomem;
    if (hint && hint_len > 0 && strcmp(ctx->package, "Negotiate") == 0)
    {
        auth->hint = malloc((size_t)hint_len);
        if (auth->hint == NULL)
            goto nomem;
        memcpy(auth->hint, hint, (size_t)hint_len);
        auth->hint_len = hint_len;
    }
    /* SPN cifs/<server> (only Kerberos uses it) */
    if (server == NULL)
        server = "";
    spn = malloc(strlen(server) + 6);
    if (spn == NULL)
        goto nomem;
    strcpy(spn, "cifs/");
    strcat(spn, server);
    auth->target = to_utf16(spn, NULL);
    free(spn);
    if (auth->target == NULL)
        goto nomem;
    return auth;

nomem:
    fail(smb2, ctx, NITRO_SMB2_REASON_NO_MEMORY, 0, "out of memory");
    smb2_sspi_free_auth_data(auth);
    return NULL;
}

/* One InitializeSecurityContext call with an optional input token. */
static SECURITY_STATUS isc(struct smb2_sspi_auth *auth, const uint8_t *in, int in_len)
{
    SecBuffer inbuf, outbuf;
    SecBufferDesc indesc, outdesc;
    ULONG attr = 0;
    TimeStamp expiry;
    SECURITY_STATUS status;
    HANDLE saved = NULL;

    inbuf.BufferType = SECBUFFER_TOKEN;
    inbuf.cbBuffer = (ULONG)in_len;
    inbuf.pvBuffer = (void *)in;
    indesc.ulVersion = SECBUFFER_VERSION;
    indesc.cBuffers = 1;
    indesc.pBuffers = &inbuf;

    outbuf.BufferType = SECBUFFER_TOKEN;
    outbuf.cbBuffer = auth->out_size;
    outbuf.pvBuffer = auth->out;
    outdesc.ulVersion = SECBUFFER_VERSION;
    outdesc.cBuffers = 1;
    outdesc.pBuffers = &outbuf;

    if (auth->ctx->sso_token)
    {
        /* the caller's own impersonation (if any) is put back afterwards */
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, TRUE, &saved))
            saved = NULL;
        if (!SetThreadToken(NULL, auth->ctx->sso_token))
        {
            if (saved)
                CloseHandle(saved);
            return SEC_E_NO_IMPERSONATION;
        }
    }
    status = InitializeSecurityContextW(&auth->ctx->cred, auth->have_h ? &auth->h : NULL,
                                        auth->target, SSPI_ISC_FLAGS, 0, SECURITY_NATIVE_DREP,
                                        in_len > 0 ? &indesc : NULL, 0, &auth->h, &outdesc,
                                        &attr, &expiry);
    if (auth->ctx->sso_token)
    {
        if (!SetThreadToken(NULL, saved))
            RevertToSelf();
        if (saved)
            CloseHandle(saved);
    }
    if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED ||
        status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
    {
        auth->have_h = 1;
        auth->out_len = outbuf.cbBuffer <= auth->out_size ? outbuf.cbBuffer : 0;
        if (status == SEC_I_COMPLETE_NEEDED || status == SEC_I_COMPLETE_AND_CONTINUE)
        {
            SECURITY_STATUS cs = CompleteAuthToken(&auth->h, &outdesc);

            if (cs != SEC_E_OK)
                return cs;
            status = status == SEC_I_COMPLETE_NEEDED ? SEC_E_OK : SEC_I_CONTINUE_NEEDED;
        }
    }
    else
    {
        auth->out_len = 0;
    }
    return status;
}

int smb2_sspi_session_request(struct smb2_context *smb2, void *auth_data,
                              const uint8_t *in, int in_len,
                              uint8_t **out, uint16_t *out_len)
{
    struct smb2_sspi_auth *auth = auth_data;
    struct smb2_sspi_ctx *ctx = auth->ctx;
    SECURITY_STATUS status;

    if (++auth->legs > SSPI_MAX_LEGS)
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, 0, "too many session setup legs");
        return -1;
    }
    if (auth->complete)
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, 0, "the server asks for more after the exchange completed");
        return -1;
    }
    if (!auth->have_h)
    {
        /* first leg: the server's hint, if any, is the input */
        status = isc(auth, auth->hint, auth->hint_len);
        free(auth->hint);
        auth->hint = NULL;
        auth->hint_len = 0;
    }
    else
    {
        if (in == NULL || in_len <= 0)
        {
            fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, 0, "the server sent no token to continue with");
            return -1;
        }
        status = isc(auth, in, in_len);
    }
    if (status == SEC_E_OK)
        auth->complete = 1;
    else if (status != SEC_I_CONTINUE_NEEDED)
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, status, "InitializeSecurityContext failed");
        return -1;
    }
    if (auth->out_len == 0 || auth->out_len > 0xFFFF)
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_SSPI, 0, "InitializeSecurityContext gave no token to send");
        return -1;
    }
    if (auth->legs == 1)
        ctx->spnego = auth->out[0] == 0x60;  /* GSS InitialContextToken, not "NTLMSSP" */
    *out = auth->out;
    *out_len = (uint16_t)auth->out_len;
    return 0;
}

int smb2_sspi_session_complete(struct smb2_context *smb2, void *auth_data,
                               uint16_t session_flags,
                               const uint8_t *in, int in_len)
{
    struct smb2_sspi_auth *auth = auth_data;
    struct smb2_sspi_ctx *ctx = auth->ctx;
    SecPkgContext_SessionKey key;
    SECURITY_STATUS status;

    ctx->session_flags = session_flags;
    if (session_flags & (SMB2_SESSION_FLAG_IS_GUEST | SMB2_SESSION_FLAG_IS_NULL))
    {
        fail(smb2, ctx, NITRO_SMB2_REASON_GUEST_REFUSED, 0,
             "the server granted a guest or anonymous session; insecure guest logons are disabled");
        return -1;
    }
    if (!auth->complete)
    {
        /* SPNEGO: the server's accept-completed and mechListMIC */
        if (in == NULL || in_len <= 0)
        {
            fail(smb2, ctx, NITRO_SMB2_REASON_MUTUAL_AUTH, 0,
                 "the server ended the session setup without its last authentication token");
            return -1;
        }
        status = isc(auth, in, in_len);
        if (status != SEC_E_OK)
        {
            fail(smb2, ctx, NITRO_SMB2_REASON_MUTUAL_AUTH, status,
                 "the server's last authentication token did not verify");
            return -1;
        }
        if (auth->out_len != 0)
        {
            fail(smb2, ctx, NITRO_SMB2_REASON_MUTUAL_AUTH, 0,
                 "the exchange wants another token after the server's success");
            return -1;
        }
        auth->complete = 1;
        ctx->server_token_verified = 1;
    }
    /* complete already (raw NTLM): a SUCCESS response carries no token we
     * could check; one that is present is not used. */

    memset(&key, 0, sizeof(key));
    status = QueryContextAttributesW(&auth->h, SECPKG_ATTR_SESSION_KEY, &key);
    if (status == SEC_E_OK && key.SessionKey && key.SessionKeyLength > 0)
    {
        uint32_t len = key.SessionKeyLength > 255 ? 255 : key.SessionKeyLength;

        if (smb2->session_key)
        {
            SecureZeroMemory(smb2->session_key, smb2->session_key_size);
            free(smb2->session_key);
        }
        smb2->session_key_size = 0;
        smb2->session_key = malloc(len);
        if (smb2->session_key)
        {
            memcpy(smb2->session_key, key.SessionKey, len);
            smb2->session_key_size = (uint8_t)len;
        }
        SecureZeroMemory(key.SessionKey, key.SessionKeyLength);
        FreeContextBuffer(key.SessionKey);
        if (smb2->session_key == NULL)
        {
            fail(smb2, ctx, NITRO_SMB2_REASON_NO_MEMORY, 0, "out of memory");
            return -1;
        }
        ctx->session_key_length = (uint16_t)len;
    }
    /* No session key: libsmb2 fails the connection if signing or sealing
     * needs one (lib/libsmb2.c session_setup_cb). */
    ctx->authenticated = 1;
    return 0;
}

void smb2_sspi_free_auth_data(void *auth_data)
{
    struct smb2_sspi_auth *auth = auth_data;

    if (auth == NULL)
        return;
    if (auth->have_h)
        DeleteSecurityContext(&auth->h);
    if (auth->out)
    {
        SecureZeroMemory(auth->out, auth->out_size);
        free(auth->out);
    }
    free(auth->hint);
    free(auth->target);
    SecureZeroMemory(auth, sizeof(*auth));
    free(auth);
}

void smb2_sspi_destroy(struct smb2_context *smb2)
{
    if (smb2->sspi)
    {
        release_cred(smb2->sspi);
        SecureZeroMemory(smb2->sspi, sizeof(*smb2->sspi));
        free(smb2->sspi);
        smb2->sspi = NULL;
    }
    wipe_string(smb2->password);
    if (smb2->session_key)
        SecureZeroMemory(smb2->session_key, smb2->session_key_size);
    SecureZeroMemory(smb2->signing_key, sizeof(smb2->signing_key));
    SecureZeroMemory(smb2->application_key, sizeof(smb2->application_key));
    SecureZeroMemory(smb2->serverin_key, sizeof(smb2->serverin_key));
    SecureZeroMemory(smb2->serverout_key, sizeof(smb2->serverout_key));
}

int NitroSmb2GetAuthInfo(struct smb2_context *smb2, struct nitro_smb2_auth_info *info)
{
    struct smb2_sspi_ctx *ctx;

    if (smb2 == NULL || info == NULL || info->size != sizeof(*info))
        return -EINVAL;
    memset(info, 0, sizeof(*info));
    info->size = sizeof(*info);
    ctx = smb2->sspi;
    if (ctx == NULL)
        return 0;
    info->explicit_credentials = ctx->explicit_cred;
    info->spnego = ctx->spnego;
    info->server_token_verified = ctx->server_token_verified;
    info->tcp_connected = ctx->tcp_connected;
    info->negotiated = ctx->negotiated;
    info->authenticated = ctx->authenticated;
    info->reason = ctx->reason;
    info->sspi_status = (uint32_t)ctx->sspi_status;
    info->session_flags = ctx->session_flags;
    info->session_key_length = ctx->session_key_length;
    strcpy(info->package, ctx->package);
    return 0;
}

/* Used by nitro/errmap.c */
int smb2_sspi_failure(struct smb2_context *smb2, int *tcp_connected, int *negotiated,
                      int *reason, uint32_t *sspi_status)
{
    struct smb2_sspi_ctx *ctx = smb2->sspi;

    *tcp_connected = ctx ? ctx->tcp_connected : 0;
    *negotiated = ctx ? ctx->negotiated : 0;
    *reason = ctx ? ctx->reason : 0;
    *sspi_status = ctx ? (uint32_t)ctx->sspi_status : 0;
    return 0;
}
