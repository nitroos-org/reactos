/*
 * Copyright 2005 Kai Blin
 * Copyright 2012 Hans Leidekker for CodeWeavers
 * Copyright 2026 Tomas Srnka
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * This file implements the Negotiate provider: SPNEGO (RFC 4178, [MS-SPNG]) over the NTLM provider, or raw NTLM
 * where Windows uses it.
 */

#include "precomp.h"
#include "spnego_der.h"

#include <wine/debug.h>
WINE_DEFAULT_DEBUG_CHANNEL(secur32);

/***********************************************************************
 *              QueryCredentialsAttributesA
 */
static SECURITY_STATUS SEC_ENTRY nego_QueryCredentialsAttributesA(
    PCredHandle phCredential, ULONG ulAttribute, PVOID pBuffer)
{
    FIXME("%p, %u, %p\n", phCredential, ulAttribute, pBuffer);
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/***********************************************************************
 *              QueryCredentialsAttributesW
 */
static SECURITY_STATUS SEC_ENTRY nego_QueryCredentialsAttributesW(
    PCredHandle phCredential, ULONG ulAttribute, PVOID pBuffer)
{
    FIXME("%p, %u, %p\n", phCredential, ulAttribute, pBuffer);
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/***********************************************************************
 *              AcquireCredentialsHandleW
 */
static SECURITY_STATUS SEC_ENTRY nego_AcquireCredentialsHandleW(
    SEC_WCHAR *pszPrincipal, SEC_WCHAR *pszPackage, ULONG fCredentialUse,
    PLUID pLogonID, PVOID pAuthData, SEC_GET_KEY_FN pGetKeyFn,
    PVOID pGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry )
{
    static SEC_WCHAR ntlmW[] = {'N','T','L','M',0};
    SECURITY_STATUS ret;

    TRACE("%s, %s, 0x%08x, %p, %p, %p, %p, %p, %p\n",
          debugstr_w(pszPrincipal), debugstr_w(pszPackage), fCredentialUse,
          pLogonID, pAuthData, pGetKeyFn, pGetKeyArgument, phCredential, ptsExpiry);

    FIXME("forwarding to NTLM\n");
    ret = ntlm_AcquireCredentialsHandleW( pszPrincipal, ntlmW, fCredentialUse,
                                          pLogonID, pAuthData, pGetKeyFn, pGetKeyArgument,
                                          phCredential, ptsExpiry );
    return ret;
}

/***********************************************************************
 *              AcquireCredentialsHandleA
 */
static SECURITY_STATUS SEC_ENTRY nego_AcquireCredentialsHandleA(
    SEC_CHAR *pszPrincipal, SEC_CHAR *pszPackage, ULONG fCredentialUse,
    PLUID pLogonID, PVOID pAuthData, SEC_GET_KEY_FN pGetKeyFn,
    PVOID pGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry )
{
    SECURITY_STATUS ret = SEC_E_INSUFFICIENT_MEMORY;
    SEC_WCHAR *user = NULL, *domain = NULL, *passwd = NULL, *package = NULL;
    SEC_WINNT_AUTH_IDENTITY_W *identityW = NULL;

    TRACE("%s, %s, 0x%08x, %p, %p, %p, %p, %p, %p\n",
          debugstr_a(pszPrincipal), debugstr_a(pszPackage), fCredentialUse,
          pLogonID, pAuthData, pGetKeyFn, pGetKeyArgument, phCredential, ptsExpiry);

    if (pszPackage)
    {
        int package_len = MultiByteToWideChar( CP_ACP, 0, pszPackage, -1, NULL, 0 );
        package = HeapAlloc( GetProcessHeap(), 0, package_len * sizeof(SEC_WCHAR) );
        if (!package) return SEC_E_INSUFFICIENT_MEMORY;
        MultiByteToWideChar( CP_ACP, 0, pszPackage, -1, package, package_len );
    }
    if (pAuthData)
    {
        SEC_WINNT_AUTH_IDENTITY_A *identity = pAuthData;
        int user_len, domain_len, passwd_len;

        if (identity->Flags == SEC_WINNT_AUTH_IDENTITY_ANSI)
        {
            identityW = HeapAlloc( GetProcessHeap(), 0, sizeof(*identityW) );
            if (!identityW) goto done;

            if (!identity->UserLength) user_len = 0;
            else
            {
                user_len = MultiByteToWideChar( CP_ACP, 0, (LPCSTR)identity->User,
                                                identity->UserLength, NULL, 0 );
                user = HeapAlloc( GetProcessHeap(), 0, user_len * sizeof(SEC_WCHAR) );
                if (!user) goto done;
                MultiByteToWideChar( CP_ACP, 0, (LPCSTR)identity->User, identity->UserLength,
                                     user, user_len );
            }
            if (!identity->DomainLength) domain_len = 0;
            else
            {
                domain_len = MultiByteToWideChar( CP_ACP, 0, (LPCSTR)identity->Domain,
                                                  identity->DomainLength, NULL, 0 );
                domain = HeapAlloc( GetProcessHeap(), 0, domain_len * sizeof(SEC_WCHAR) );
                if (!domain) goto done;
                MultiByteToWideChar( CP_ACP, 0, (LPCSTR)identity->Domain, identity->DomainLength,
                                     domain, domain_len );
            }
            if (!identity->PasswordLength) passwd_len = 0;
            else
            {
                passwd_len = MultiByteToWideChar( CP_ACP, 0, (LPCSTR)identity->Password,
                                                  identity->PasswordLength, NULL, 0 );
                passwd = HeapAlloc( GetProcessHeap(), 0, passwd_len * sizeof(SEC_WCHAR) );
                if (!passwd) goto done;
                MultiByteToWideChar( CP_ACP, 0, (LPCSTR)identity->Password, identity->PasswordLength,
                                     passwd, passwd_len );
            }
            identityW->Flags          = SEC_WINNT_AUTH_IDENTITY_UNICODE;
            identityW->User           = user;
            identityW->UserLength     = user_len;
            identityW->Domain         = domain;
            identityW->DomainLength   = domain_len;
            identityW->Password       = passwd;
            identityW->PasswordLength = passwd_len;
        }
        else identityW = (SEC_WINNT_AUTH_IDENTITY_W *)identity;
    }
    ret = nego_AcquireCredentialsHandleW( NULL, package, fCredentialUse, pLogonID, identityW,
                                          pGetKeyFn, pGetKeyArgument, phCredential, ptsExpiry );
done:
    HeapFree( GetProcessHeap(), 0, package );
    HeapFree( GetProcessHeap(), 0, user );
    HeapFree( GetProcessHeap(), 0, domain );
    HeapFree( GetProcessHeap(), 0, passwd );
    HeapFree( GetProcessHeap(), 0, identityW );
    return ret;
}

/***********************************************************************
 * The SPNEGO layer (RFC 4178, [MS-SPNG]) over the NTLM package. NTLM is the only mechanism today; the mechanism
 * lists are arrays so Kerberos can join later.
 *
 * What Windows does, measured with an SSPI-only probe on Windows Server 2022 and Windows 10 22H2 (the evidence of
 * this change has the token table), and what this layer does in the same cases:
 *  Client (InitializeSecurityContext):
 *   - first call without an input token: the default credentials of the caller send a NegTokenInit (mechTypes,
 *     an optimistic NTLM NEGOTIATE as mechToken, no reqFlags); explicit credentials send the raw NTLM NEGOTIATE (no
 *     SPNEGO at all) and the whole exchange stays raw NTLM.
 *   - first call with the server's NegTokenInit (an SMB NEGOTIATE response carries one): a NegTokenInit, also for
 *     explicit credentials. A hint without NTLM: SEC_E_NO_CREDENTIALS. Input that is not a NegTokenInit is ignored.
 *   - the reply with the CHALLENGE: NegTokenResp { accept-incomplete, AUTHENTICATE, mechListMIC },
 *     SEC_I_CONTINUE_NEEDED; then the server's accept-completed with its mechListMIC: SEC_E_OK, no output.
 *  Server (AcceptSecurityContext):
 *   - no input token: the hint, a NegTokenInit with the mechTypes only (Windows lists NEGOEX and NTLM; NTLM here).
 *   - a raw NTLM NEGOTIATE: the exchange stays raw NTLM (Windows accepts raw NTLM in Negotiate).
 *   - a NegTokenInit: NegTokenResp { accept-incomplete, NTLM, CHALLENGE }; then NegTokenResp { accept-completed,
 *     mechListMIC } and SEC_E_OK once the AUTHENTICATE and the client's mechListMIC check.
 *   - a token that is longer than the data given (its outer DER length says so): kept, SEC_I_CONTINUE_NEEDED with
 *     no output, and completed by the next call (Windows reassembles the client's tokens this way, measured).
 *  The mechListMIC is GSS_GetMIC of the NTLM context over the DER mechTypes of the client's NegTokenInit, and after
 *  the exchange the RC4 states restart from the sealing keys while the sequence numbers go on (measured).
 *
 * Deliberate differences from Windows (on malformed input only; listed in the evidence): no indefinite-length
 * tokens, no reassembly of the server's tokens on the client side, a truncated hint is ignored.
 * ISC_REQ_USE_DCE_STYLE without a hint keeps raw NTLM: rpcrt4 has no alter_context leg for a fourth token.
 */

#define NEGO_CONTEXT_MAGIC  0x4f47454e  /* 'NEGO' */

typedef enum
{
    NEGO_RAW,       /* the exchange is plain NTLM: everything goes to the NTLM context */
    NEGO_SPNEGO
} NegoMode;

typedef enum
{
    NS_CLIENT_WAIT_RESP,    /* client: NegTokenInit sent, the NegTokenResp with the CHALLENGE is due */
    NS_CLIENT_WAIT_FINAL,   /* client: AUTHENTICATE and mechListMIC sent, accept-completed is due */
    NS_SERVER_HINT,         /* server: the hint went out, the client's first token is due */
    NS_SERVER_WAIT_FIRST,   /* server: NTLM chosen without an optimistic token, the NEGOTIATE is due */
    NS_SERVER_WAIT_AUTH,    /* server: CHALLENGE sent, AUTHENTICATE and mechListMIC are due */
    NS_SERVER_DEAD,         /* server: the client gave no mechListMIC; nothing more is accepted */
    NS_DONE
} NegoState;

typedef struct
{
    ULONG magic;
    BOOL server;
    NegoMode mode;
    NegoState state;
    BOOL have_ntlm;             /* ntlm is a live NTLM context */
    CtxtHandle ntlm;
    ULONG req;                  /* the caller's request flags of the last call */
    ULONG ntlm_attr;            /* the attributes of the last NTLM leg */
    BYTE *mech_list;            /* the DER MechTypeList the mechListMIC covers */
    ULONG mech_list_len;
    BYTE *pending;              /* server: the first part of a token that arrives in pieces */
    ULONG pending_len;
    ULONG pending_total;
} NegoContext;

/* the mechanisms this package can negotiate, in the order it offers them */
static const BYTE *const nego_mech_oids[] = { spnego_oid_ntlm };
static const spnego_u32 nego_mech_oid_lens[] = { sizeof(spnego_oid_ntlm) };
#define NEGO_MECH_COUNT ARRAYSIZE(nego_mech_oids)

static NegoContext *nego_get_context(PCtxtHandle phContext)
{
    NegoContext *ctx;

    if (!phContext || !phContext->dwLower) return NULL;
    ctx = (NegoContext *)phContext->dwLower;
    return ctx->magic == NEGO_CONTEXT_MAGIC ? ctx : NULL;
}

static NegoContext *nego_new_context(BOOL server)
{
    NegoContext *ctx = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*ctx));

    if (ctx)
    {
        ctx->magic = NEGO_CONTEXT_MAGIC;
        ctx->server = server;
    }
    return ctx;
}

static void nego_free_context(NegoContext *ctx)
{
    if (!ctx) return;
    if (ctx->have_ntlm) ntlm_DeleteSecurityContext(&ctx->ntlm);
    HeapFree(GetProcessHeap(), 0, ctx->mech_list);
    HeapFree(GetProcessHeap(), 0, ctx->pending);
    ctx->magic = 0;
    HeapFree(GetProcessHeap(), 0, ctx);
}

static void nego_set_handle(PCtxtHandle h, NegoContext *ctx)
{
    h->dwUpper = 1;
    h->dwLower = (ULONG_PTR)ctx;
}

static void nego_set_expiry(PTimeStamp ts)
{
    if (ts) { ts->LowPart = 0xffffffff; ts->HighPart = 0x7fffffff; }
}

/* the token buffer of an input description: TRUE when there is one (its length may be 0) */
static BOOL nego_input_token(PSecBufferDesc input, const BYTE **data, ULONG *len)
{
    ULONG i;

    *data = NULL;
    *len = 0;
    if (!input || !input->pBuffers) return FALSE;
    for (i = 0; i < input->cBuffers; i++)
    {
        if ((input->pBuffers[i].BufferType & ~SECBUFFER_ATTRMASK) == SECBUFFER_TOKEN)
        {
            *data = input->pBuffers[i].pvBuffer;
            *len = *data ? input->pBuffers[i].cbBuffer : 0;
            return TRUE;
        }
    }
    return FALSE;
}

static SecBuffer *nego_output_buffer(PSecBufferDesc output)
{
    ULONG i;

    if (!output || !output->pBuffers) return NULL;
    for (i = 0; i < output->cBuffers; i++)
        if ((output->pBuffers[i].BufferType & ~SECBUFFER_ATTRMASK) == SECBUFFER_TOKEN) return &output->pBuffers[i];
    return NULL;
}

/* hands a token to the caller's output buffer (ISC_REQ_ALLOCATE_MEMORY and ASC_REQ_ALLOCATE_MEMORY are one bit, as
 * are the two ALLOCATED_MEMORY return flags) */
static SECURITY_STATUS nego_put_output(PSecBufferDesc output, ULONG req, ULONG *attr, const BYTE *data, ULONG len)
{
    SecBuffer *buf = nego_output_buffer(output);

    if (!buf) return SEC_E_BUFFER_TOO_SMALL;
    if (req & ISC_REQ_ALLOCATE_MEMORY)
    {
        buf->pvBuffer = HeapAlloc(GetProcessHeap(), 0, len ? len : 1);
        if (!buf->pvBuffer) return SEC_E_INSUFFICIENT_MEMORY;
        *attr |= ISC_RET_ALLOCATED_MEMORY;
    }
    else if (!buf->pvBuffer)
        return SEC_E_INTERNAL_ERROR;
    else if (buf->cbBuffer < len)
        return SEC_E_BUFFER_TOO_SMALL;
    if (len) memcpy(buf->pvBuffer, data, len);
    buf->cbBuffer = len;
    return SEC_E_OK;
}

/* nothing goes back to the peer on this call */
static void nego_no_output(PSecBufferDesc output)
{
    SecBuffer *buf = nego_output_buffer(output);

    if (buf) buf->cbBuffer = 0;
}

/* one leg of the NTLM context with a token of this layer; the NTLM output is allocated (NULL when there is none) */
static SECURITY_STATUS nego_ntlm_leg(NegoContext *ctx, PCredHandle cred, SEC_WCHAR *target, ULONG req,
                                     ULONG data_rep, const BYTE *in, ULONG in_len, BOOL have_in, BYTE **out,
                                     ULONG *out_len, PTimeStamp expiry)
{
    SecBuffer ib, ob;
    SecBufferDesc id, od;
    SECURITY_STATUS ret;
    ULONG attr = 0;
    CtxtHandle *old = ctx->have_ntlm ? &ctx->ntlm : NULL;

    *out = NULL;
    *out_len = 0;
    ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = (void *)in; ib.cbBuffer = in_len;
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = NULL; ob.cbBuffer = 0;
    id.ulVersion = od.ulVersion = SECBUFFER_VERSION;
    id.cBuffers = od.cBuffers = 1;
    id.pBuffers = &ib;
    od.pBuffers = &ob;
    req |= ISC_REQ_ALLOCATE_MEMORY;
    if (ctx->server)
        ret = ntlm_AcceptSecurityContext(cred, old, have_in ? &id : NULL, req, data_rep, &ctx->ntlm, &od, &attr, expiry);
    else
        ret = ntlm_InitializeSecurityContextW(cred, old, target, req, 0, data_rep, have_in ? &id : NULL, 0, &ctx->ntlm,
                                              &od, &attr, expiry);
    if (ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED)
    {
        ctx->have_ntlm = TRUE;
        ctx->ntlm_attr = attr & ~ISC_RET_ALLOCATED_MEMORY;
        if ((attr & ISC_RET_ALLOCATED_MEMORY) && ob.pvBuffer)
        {
            if (ob.cbBuffer)
            {
                *out = ob.pvBuffer;
                *out_len = ob.cbBuffer;
            }
            else
                HeapFree(GetProcessHeap(), 0, ob.pvBuffer);
        }
    }
    return ret;
}

static BOOL nego_save_mech_list(NegoContext *ctx, const BYTE *data, ULONG len)
{
    HeapFree(GetProcessHeap(), 0, ctx->mech_list);
    ctx->mech_list = HeapAlloc(GetProcessHeap(), 0, len);
    if (!ctx->mech_list) return FALSE;
    memcpy(ctx->mech_list, data, len);
    ctx->mech_list_len = len;
    return TRUE;
}

/* the index of NTLM in a mechTypes list, -1 when it is not there */
static int nego_find_ntlm(const spnego_init *init)
{
    ULONG i;

    for (i = 0; i < init->mech_count; i++)
        if (spnego_oid_is(&init->mechs[i], spnego_oid_ntlm, sizeof(spnego_oid_ntlm))) return (int)i;
    return -1;
}

/* the DER MechTypeList this package sends: SEQUENCE OF the OIDs */
static BOOL nego_own_mech_list(NegoContext *ctx)
{
    BYTE buf[2 + NEGO_MECH_COUNT * (2 + SPNEGO_MAX_OID)];
    ULONG i, pos = 2;

    for (i = 0; i < NEGO_MECH_COUNT; i++)
    {
        buf[pos++] = 0x06;
        buf[pos++] = (BYTE)nego_mech_oid_lens[i];
        memcpy(buf + pos, nego_mech_oids[i], nego_mech_oid_lens[i]);
        pos += nego_mech_oid_lens[i];
    }
    buf[0] = 0x30;
    buf[1] = (BYTE)(pos - 2);
    return nego_save_mech_list(ctx, buf, pos);
}

/* encode a NegTokenResp into an allocated buffer */
static SECURITY_STATUS nego_make_resp(int state, BOOL with_mech, const BYTE *tok, ULONG tok_len, const BYTE *mic,
                                      ULONG mic_len, BYTE **out, ULONG *out_len)
{
    ULONG len = spnego_encode_resp(NULL, 0, state, with_mech ? spnego_oid_ntlm : NULL,
                                   with_mech ? sizeof(spnego_oid_ntlm) : 0, tok, tok_len, mic, mic_len);

    *out = NULL;
    *out_len = 0;
    if (!len) return SEC_E_INTERNAL_ERROR;
    *out = HeapAlloc(GetProcessHeap(), 0, len);
    if (!*out) return SEC_E_INSUFFICIENT_MEMORY;
    *out_len = spnego_encode_resp(*out, len, state, with_mech ? spnego_oid_ntlm : NULL,
                                  with_mech ? sizeof(spnego_oid_ntlm) : 0, tok, tok_len, mic, mic_len);
    return *out_len == len ? SEC_E_OK : SEC_E_INTERNAL_ERROR;
}

static SECURITY_STATUS nego_make_init(const BYTE *tok, ULONG tok_len, BYTE **out, ULONG *out_len)
{
    ULONG len = spnego_encode_init(NULL, 0, nego_mech_oids, nego_mech_oid_lens, NEGO_MECH_COUNT, tok, tok_len);

    *out = NULL;
    *out_len = 0;
    if (!len) return SEC_E_INTERNAL_ERROR;
    *out = HeapAlloc(GetProcessHeap(), 0, len);
    if (!*out) return SEC_E_INSUFFICIENT_MEMORY;
    *out_len = spnego_encode_init(*out, len, nego_mech_oids, nego_mech_oid_lens, NEGO_MECH_COUNT, tok, tok_len);
    return *out_len == len ? SEC_E_OK : SEC_E_INTERNAL_ERROR;
}

static BOOL nego_is_raw_ntlm(const BYTE *tok, ULONG len)
{
    static const BYTE sig[8] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };

    return len >= sizeof(sig) && !memcmp(tok, sig, sizeof(sig));
}

/***********************************************************************
 * client
 */
static SECURITY_STATUS nego_client_first(PCredHandle phCredential, SEC_WCHAR *pszTargetName, ULONG fContextReq,
                                         ULONG TargetDataRep, PSecBufferDesc pInput, PCtxtHandle phNewContext,
                                         PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    const BYTE *hint;
    ULONG hint_len, attr = 0, ntlm_len = 0, tok_len = 0;
    BYTE *ntlm_tok = NULL, *tok = NULL;
    BOOL use_spnego = FALSE;
    NegoContext *ctx;
    SECURITY_STATUS ret;

    if (!phCredential || !phCredential->dwLower) return SEC_E_INVALID_HANDLE;
    if (!(ntlm_CredentialsUse(phCredential) & SECPKG_CRED_OUTBOUND)) return SEC_E_INVALID_HANDLE;
    if (!pOutput) return SEC_E_BUFFER_TOO_SMALL;

    /* the server's NegTokenInit, when the protocol delivers one before the client speaks */
    if (nego_input_token(pInput, &hint, &hint_len) && hint_len)
    {
        spnego_init init;
        spnego_u32 used;

        spnego_span oid;

        if (spnego_decode_init(hint, hint_len, &init, &used) == SPNEGO_OK)
        {
            if (nego_find_ntlm(&init) < 0)
            {
                WARN("the server offers no mechanism of this package\n");
                return SEC_E_NO_CREDENTIALS;
            }
            use_spnego = TRUE;
        }
        else if (spnego_gss_mech(hint, hint_len, &oid) == SPNEGO_OK &&
                 !spnego_oid_is(&oid, spnego_oid_spnego, sizeof(spnego_oid_spnego)))
        {
            /* the first token of another GSS mechanism (measured: SEC_E_SECPKG_NOT_FOUND) */
            return SEC_E_SECPKG_NOT_FOUND;
        }
        else
            TRACE("the input is not a NegTokenInit: ignored\n");
    }
    /* without a hint, as Windows: SPNEGO for the caller's own credentials, raw NTLM for explicit ones; and raw NTLM
     * for DCE style (rpcrt4 completes a three-leg exchange only) */
    if (!use_spnego && !ntlm_CredentialsHaveIdentity(phCredential) && !(fContextReq & ISC_REQ_USE_DCE_STYLE))
        use_spnego = TRUE;

    ctx = nego_new_context(FALSE);
    if (!ctx) return SEC_E_INSUFFICIENT_MEMORY;
    ctx->req = fContextReq;

    if (!use_spnego)
    {
        ctx->mode = NEGO_RAW;
        ret = ntlm_InitializeSecurityContextW(phCredential, NULL, pszTargetName, fContextReq, 0, TargetDataRep, NULL,
                                              0, &ctx->ntlm, pOutput, pfContextAttr, ptsExpiry);
        if (ret != SEC_E_OK && ret != SEC_I_CONTINUE_NEEDED)
        {
            nego_free_context(ctx);
            return ret;
        }
        ctx->have_ntlm = TRUE;
        nego_set_handle(phNewContext, ctx);
        return ret;
    }

    ctx->mode = NEGO_SPNEGO;
    /* the NTLM context always signs under SPNEGO: the mechListMIC needs the key (Windows negotiates it too) */
    ret = nego_ntlm_leg(ctx, phCredential, pszTargetName, fContextReq | ISC_REQ_INTEGRITY, TargetDataRep, NULL, 0,
                        FALSE, &ntlm_tok, &ntlm_len, ptsExpiry);
    if (ret == SEC_E_OK) ret = SEC_E_INTERNAL_ERROR;   /* NTLM has a second leg */
    if (ret == SEC_I_CONTINUE_NEEDED && !ntlm_tok) ret = SEC_E_INTERNAL_ERROR;
    if (ret == SEC_I_CONTINUE_NEEDED) ret = nego_own_mech_list(ctx) ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
    if (ret == SEC_E_OK) ret = nego_make_init(ntlm_tok, ntlm_len, &tok, &tok_len);
    if (ret == SEC_E_OK) ret = nego_put_output(pOutput, fContextReq, &attr, tok, tok_len);
    HeapFree(GetProcessHeap(), 0, ntlm_tok);
    HeapFree(GetProcessHeap(), 0, tok);
    if (ret != SEC_E_OK)
    {
        nego_free_context(ctx);
        return ret;
    }
    ctx->state = NS_CLIENT_WAIT_RESP;
    nego_set_handle(phNewContext, ctx);
    if (pfContextAttr) *pfContextAttr = attr | ctx->ntlm_attr | ISC_RET_INTERMEDIATE_RETURN;
    nego_set_expiry(ptsExpiry);
    return SEC_I_CONTINUE_NEEDED;
}

/* the server's NegTokenResp with the CHALLENGE: the AUTHENTICATE and the mechListMIC go back */
static SECURITY_STATUS nego_client_challenge(NegoContext *ctx, PCredHandle phCredential, SEC_WCHAR *pszTargetName,
                                             ULONG fContextReq, ULONG TargetDataRep, const BYTE *in, ULONG in_len,
                                             PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    spnego_resp resp;
    spnego_u32 used;
    BYTE *auth = NULL, *tok = NULL, mic[16];
    ULONG auth_len = 0, tok_len = 0, attr = 0;
    SECURITY_STATUS ret;

    /* bytes behind the token are ignored here (measured) */
    if (spnego_decode_resp(in, in_len, &resp, &used) != SPNEGO_OK) return SEC_E_INVALID_TOKEN;
    if (resp.neg_state == SPNEGO_NEGSTATE_ABSENT) return SEC_E_INVALID_TOKEN;
    if (resp.neg_state == SPNEGO_REJECT) return SEC_E_LOGON_DENIED;
    if (resp.neg_state == SPNEGO_ACCEPT_COMPLETED) return SEC_E_INTERNAL_ERROR;
    if (resp.has_supported_mech && !spnego_oid_is(&resp.supported_mech, spnego_oid_ntlm, sizeof(spnego_oid_ntlm)))
        return SEC_E_INVALID_TOKEN;
    if (!resp.has_response_token) return SEC_E_INVALID_TOKEN;

    ret = nego_ntlm_leg(ctx, phCredential, pszTargetName, fContextReq | ISC_REQ_INTEGRITY, TargetDataRep,
                        resp.response_token.data, resp.response_token.len, TRUE, &auth, &auth_len, ptsExpiry);
    if (ret == SEC_I_CONTINUE_NEEDED) ret = SEC_E_INTERNAL_ERROR;   /* NTLM is done after its second leg */
    if (ret == SEC_E_OK && !auth) ret = SEC_E_INTERNAL_ERROR;
    if (ret == SEC_E_OK) ret = ntlm_SpnegoMakeMic(&ctx->ntlm, ctx->mech_list, ctx->mech_list_len, mic);
    if (ret == SEC_E_OK) ret = nego_make_resp(SPNEGO_ACCEPT_INCOMPLETE, FALSE, auth, auth_len, mic, sizeof(mic),
                                              &tok, &tok_len);
    if (ret == SEC_E_OK) ret = nego_put_output(pOutput, fContextReq, &attr, tok, tok_len);
    HeapFree(GetProcessHeap(), 0, auth);
    HeapFree(GetProcessHeap(), 0, tok);
    if (ret != SEC_E_OK) return ret;
    ctx->state = NS_CLIENT_WAIT_FINAL;
    if (pfContextAttr) *pfContextAttr = attr | ctx->ntlm_attr;
    nego_set_expiry(ptsExpiry);
    return SEC_I_CONTINUE_NEEDED;
}

/* the server's accept-completed */
static SECURITY_STATUS nego_client_final(NegoContext *ctx, const BYTE *in, ULONG in_len, PSecBufferDesc pOutput,
                                         ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    spnego_resp resp;
    spnego_u32 used;
    SECURITY_STATUS ret;

    if (spnego_decode_resp(in, in_len, &resp, &used) != SPNEGO_OK) return SEC_E_INVALID_TOKEN;
    if (resp.neg_state == SPNEGO_REJECT) return SEC_E_LOGON_DENIED;
    if (resp.neg_state != SPNEGO_ACCEPT_COMPLETED) return SEC_E_INVALID_TOKEN;
    /* Windows completes without the server's mechListMIC (measured); with NTLM as the only mechanism offered there
     * is no list to protect. One that is present must be right; a token for the mechanism without one is refused
     * (measured). */
    if (resp.has_response_token && !resp.has_mic) return SEC_E_INVALID_TOKEN;
    if (resp.has_mic)
    {
        ret = ntlm_SpnegoVerifyMic(&ctx->ntlm, ctx->mech_list, ctx->mech_list_len, resp.mic.data, resp.mic.len);
        if (ret != SEC_E_OK) return ret;
    }
    ntlm_SpnegoResetSealing(&ctx->ntlm);
    ctx->state = NS_DONE;
    nego_no_output(pOutput);
    if (pfContextAttr) *pfContextAttr = ctx->ntlm_attr;
    nego_set_expiry(ptsExpiry);
    return SEC_E_OK;
}

/***********************************************************************
 *              InitializeSecurityContextW
 */
static SECURITY_STATUS SEC_ENTRY nego_InitializeSecurityContextW(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR *pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
    PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
    PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry )
{
    NegoContext *ctx;
    const BYTE *in;
    ULONG in_len;
    SECURITY_STATUS ret;

    TRACE("%p, %p, %s, 0x%08x, %u, %u, %p, %u, %p, %p, %p, %p\n",
          phCredential, phContext, debugstr_w(pszTargetName), fContextReq,
          Reserved1, TargetDataRep, pInput, Reserved1, phNewContext, pOutput,
          pfContextAttr, ptsExpiry);

    if (!phNewContext) return SEC_E_INVALID_HANDLE;
    if (!phContext)
        return nego_client_first(phCredential, pszTargetName, fContextReq, TargetDataRep, pInput, phNewContext,
                                 pOutput, pfContextAttr, ptsExpiry);

    ctx = nego_get_context(phContext);
    if (!ctx || ctx->server) return SEC_E_INVALID_HANDLE;
    if (ctx->mode == NEGO_RAW)
    {
        ret = ntlm_InitializeSecurityContextW(phCredential, &ctx->ntlm, pszTargetName, fContextReq, Reserved1,
                                              TargetDataRep, pInput, Reserved2, &ctx->ntlm, pOutput, pfContextAttr,
                                              ptsExpiry);
    }
    else
    {
        if (!nego_input_token(pInput, &in, &in_len) || !in_len) return SEC_E_INVALID_TOKEN;
        ctx->req = fContextReq;
        switch (ctx->state)
        {
        case NS_CLIENT_WAIT_RESP:
            ret = nego_client_challenge(ctx, phCredential, pszTargetName, fContextReq, TargetDataRep, in, in_len,
                                        pOutput, pfContextAttr, ptsExpiry);
            break;
        case NS_CLIENT_WAIT_FINAL:
            ret = nego_client_final(ctx, in, in_len, pOutput, pfContextAttr, ptsExpiry);
            break;
        default:
            return SEC_E_INVALID_HANDLE;
        }
    }
    if ((ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED) && phNewContext != phContext)
        nego_set_handle(phNewContext, ctx);
    return ret;
}

/***********************************************************************
 *              InitializeSecurityContextA
 */
static SECURITY_STATUS SEC_ENTRY nego_InitializeSecurityContextA(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR *pszTargetName,
    ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep,
    PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext,
    PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry )
{
    SECURITY_STATUS ret;
    SEC_WCHAR *target = NULL;

    TRACE("%p, %p, %s, 0x%08x, %u, %u, %p, %u, %p, %p, %p, %p\n",
          phCredential, phContext, debugstr_a(pszTargetName), fContextReq,
          Reserved1, TargetDataRep, pInput, Reserved1, phNewContext, pOutput,
          pfContextAttr, ptsExpiry);

    if (pszTargetName)
    {
        int target_len = MultiByteToWideChar( CP_ACP, 0, pszTargetName, -1, NULL, 0 );
        target = HeapAlloc(GetProcessHeap(), 0, target_len * sizeof(SEC_WCHAR) );
        if (!target) return SEC_E_INSUFFICIENT_MEMORY;
        MultiByteToWideChar( CP_ACP, 0, pszTargetName, -1, target, target_len );
    }
    ret = nego_InitializeSecurityContextW( phCredential, phContext, target, fContextReq,
                                           Reserved1, TargetDataRep, pInput, Reserved2,
                                           phNewContext, pOutput, pfContextAttr, ptsExpiry );
    HeapFree( GetProcessHeap(), 0, target );
    return ret;
}

/***********************************************************************
 * server
 */
/* the client's NegTokenInit */
static SECURITY_STATUS nego_server_init(NegoContext *ctx, PCredHandle phCredential, ULONG fContextReq,
                                        ULONG TargetDataRep, const BYTE *in, ULONG in_len, PSecBufferDesc pOutput,
                                        ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    spnego_init init;
    spnego_u32 used;
    BYTE *chal = NULL, *tok = NULL;
    ULONG chal_len = 0, tok_len = 0, attr = 0;
    SECURITY_STATUS ret;
    int idx;

    /* bytes behind the token are ignored here (measured) */
    if (spnego_decode_init(in, in_len, &init, &used) != SPNEGO_OK) return SEC_E_INVALID_TOKEN;
    idx = nego_find_ntlm(&init);
    if (idx < 0) return SEC_E_INVALID_TOKEN;
    if (!nego_save_mech_list(ctx, init.mech_list.data, init.mech_list.len)) return SEC_E_INSUFFICIENT_MEMORY;

    if (idx == 0 && init.has_mech_token)
    {
        /* the optimistic token is for NTLM: the CHALLENGE goes back with the choice */
        ret = nego_ntlm_leg(ctx, phCredential, NULL, fContextReq, TargetDataRep, init.mech_token.data,
                            init.mech_token.len, TRUE, &chal, &chal_len, ptsExpiry);
        if (ret == SEC_E_OK) ret = SEC_E_INTERNAL_ERROR;
        if (ret == SEC_I_CONTINUE_NEEDED && !chal) ret = SEC_E_INTERNAL_ERROR;
        if (ret != SEC_I_CONTINUE_NEEDED)
        {
            HeapFree(GetProcessHeap(), 0, chal);
            return ret;
        }
        ret = nego_make_resp(SPNEGO_ACCEPT_INCOMPLETE, TRUE, chal, chal_len, NULL, 0, &tok, &tok_len);
        ctx->state = NS_SERVER_WAIT_AUTH;
    }
    else
    {
        /* NTLM is not the client's first choice, or there is no token for it: the choice alone, and the client's
         * first NTLM token comes next (request-mic when NTLM was not the preferred mechanism, as Windows) */
        ret = nego_make_resp(idx == 0 ? SPNEGO_ACCEPT_INCOMPLETE : SPNEGO_REQUEST_MIC, TRUE, NULL, 0, NULL, 0,
                             &tok, &tok_len);
        ctx->state = NS_SERVER_WAIT_FIRST;
    }
    if (ret == SEC_E_OK) ret = nego_put_output(pOutput, fContextReq, &attr, tok, tok_len);
    HeapFree(GetProcessHeap(), 0, chal);
    HeapFree(GetProcessHeap(), 0, tok);
    if (ret != SEC_E_OK) return ret;
    if (pfContextAttr) *pfContextAttr = attr | ctx->ntlm_attr;
    nego_set_expiry(ptsExpiry);
    return SEC_I_CONTINUE_NEEDED;
}

/* the client's first NTLM token in a NegTokenResp (after a NegTokenInit without one) */
static SECURITY_STATUS nego_server_first(NegoContext *ctx, PCredHandle phCredential, ULONG fContextReq,
                                         ULONG TargetDataRep, const BYTE *in, ULONG in_len, PSecBufferDesc pOutput,
                                         ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    spnego_resp resp;
    spnego_u32 used;
    BYTE *chal = NULL, *tok = NULL;
    ULONG chal_len = 0, tok_len = 0, attr = 0;
    SECURITY_STATUS ret;

    if (spnego_decode_resp(in, in_len, &resp, &used) != SPNEGO_OK) return SEC_E_INVALID_TOKEN;
    if (resp.neg_state == SPNEGO_ACCEPT_COMPLETED || resp.neg_state == SPNEGO_REJECT) return SEC_E_INVALID_TOKEN;
    if (!resp.has_response_token) return SEC_E_INVALID_TOKEN;
    ret = nego_ntlm_leg(ctx, phCredential, NULL, fContextReq, TargetDataRep, resp.response_token.data,
                        resp.response_token.len, TRUE, &chal, &chal_len, ptsExpiry);
    if (ret == SEC_E_OK) ret = SEC_E_INTERNAL_ERROR;
    if (ret == SEC_I_CONTINUE_NEEDED && !chal) ret = SEC_E_INTERNAL_ERROR;
    if (ret == SEC_I_CONTINUE_NEEDED) ret = nego_make_resp(SPNEGO_ACCEPT_INCOMPLETE, FALSE, chal, chal_len, NULL, 0,
                                                           &tok, &tok_len);
    if (ret == SEC_E_OK) ret = nego_put_output(pOutput, fContextReq, &attr, tok, tok_len);
    HeapFree(GetProcessHeap(), 0, chal);
    HeapFree(GetProcessHeap(), 0, tok);
    if (ret != SEC_E_OK) return ret;
    ctx->state = NS_SERVER_WAIT_AUTH;
    if (pfContextAttr) *pfContextAttr = attr | ctx->ntlm_attr;
    nego_set_expiry(ptsExpiry);
    return SEC_I_CONTINUE_NEEDED;
}

/* the AUTHENTICATE and the client's mechListMIC */
static SECURITY_STATUS nego_server_auth(NegoContext *ctx, PCredHandle phCredential, ULONG fContextReq,
                                        ULONG TargetDataRep, const BYTE *in, ULONG in_len, PSecBufferDesc pOutput,
                                        ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    spnego_resp resp;
    spnego_u32 used;
    BYTE *none = NULL, *tok = NULL, mic[16];
    ULONG none_len = 0, tok_len = 0, attr = 0;
    SECURITY_STATUS ret;

    if (spnego_decode_resp(in, in_len, &resp, &used) != SPNEGO_OK) return SEC_E_INVALID_TOKEN;
    /* the last token of the client may not carry anything behind it (measured) */
    if (used != in_len) return SEC_E_INVALID_TOKEN;
    if (resp.neg_state == SPNEGO_ACCEPT_COMPLETED) return SEC_E_INVALID_TOKEN;
    if (!resp.has_response_token) return SEC_E_INVALID_TOKEN;
    if (resp.has_mic && resp.mic.len != sizeof(mic)) return SEC_E_INVALID_TOKEN;

    ret = nego_ntlm_leg(ctx, phCredential, NULL, fContextReq, TargetDataRep, resp.response_token.data,
                        resp.response_token.len, TRUE, &none, &none_len, ptsExpiry);
    HeapFree(GetProcessHeap(), 0, none);
    if (ret == SEC_I_CONTINUE_NEEDED) ret = SEC_E_INTERNAL_ERROR;
    if (ret != SEC_E_OK) return ret;

    if (resp.has_mic)
    {
        ret = ntlm_SpnegoVerifyMic(&ctx->ntlm, ctx->mech_list, ctx->mech_list_len, resp.mic.data, resp.mic.len);
        if (ret != SEC_E_OK)
        {
            WARN("mechListMIC refused (0x%08x)\n", ret);
            ctx->state = NS_SERVER_DEAD;
            return ret;
        }
    }
    ret = ntlm_SpnegoMakeMic(&ctx->ntlm, ctx->mech_list, ctx->mech_list_len, mic);
    if (ret != SEC_E_OK) return ret;
    if (!resp.has_mic)
    {
        /* Windows answers with its own mechListMIC, stays incomplete and accepts nothing after it (measured): the
         * client's mechListMIC is required */
        ret = nego_make_resp(SPNEGO_ACCEPT_INCOMPLETE, FALSE, NULL, 0, mic, sizeof(mic), &tok, &tok_len);
        if (ret == SEC_E_OK) ret = nego_put_output(pOutput, fContextReq, &attr, tok, tok_len);
        HeapFree(GetProcessHeap(), 0, tok);
        ctx->state = NS_SERVER_DEAD;
        if (ret != SEC_E_OK) return ret;
        if (pfContextAttr) *pfContextAttr = attr | ctx->ntlm_attr;
        return SEC_I_CONTINUE_NEEDED;
    }
    ntlm_SpnegoResetSealing(&ctx->ntlm);
    ret = nego_make_resp(SPNEGO_ACCEPT_COMPLETED, FALSE, NULL, 0, mic, sizeof(mic), &tok, &tok_len);
    if (ret == SEC_E_OK) ret = nego_put_output(pOutput, fContextReq, &attr, tok, tok_len);
    HeapFree(GetProcessHeap(), 0, tok);
    if (ret != SEC_E_OK) return ret;
    ctx->state = NS_DONE;
    if (pfContextAttr) *pfContextAttr = attr | ctx->ntlm_attr;
    nego_set_expiry(ptsExpiry);
    return SEC_E_OK;
}

/* A client token may arrive in parts (Windows reassembles them, measured): an SPNEGO token whose header is complete,
 * with some content, and whose outer length says there is more, is kept and SEC_I_CONTINUE_NEEDED goes back without
 * output. Returns SEC_E_OK with (*data, *len) = the whole token when it is complete. */
static SECURITY_STATUS nego_server_collect(NegoContext *ctx, const BYTE **data, ULONG *len, BOOL *more)
{
    spnego_u32 total;

    *more = FALSE;
    if (ctx->pending)
    {
        ULONG need = ctx->pending_total - ctx->pending_len;
        ULONG take = *len < need ? *len : need;

        memcpy(ctx->pending + ctx->pending_len, *data, take);
        ctx->pending_len += take;
        if (ctx->pending_len < ctx->pending_total)
        {
            *more = TRUE;
            return SEC_E_OK;
        }
        /* the completing part may not carry bytes behind the token (the parts are only ever one token) */
        if (take < *len) return SEC_E_INVALID_TOKEN;
        *data = ctx->pending;
        *len = ctx->pending_len;
        return SEC_E_OK;
    }
    if (nego_is_raw_ntlm(*data, *len)) return SEC_E_OK;
    if (spnego_outer_length(*data, *len, &total) != SPNEGO_OK) return SEC_E_INVALID_TOKEN;
    if (total <= *len) return SEC_E_OK;
    /* the header and at least one byte of content: the length of the header is total minus the content length */
    {
        ULONG hdr = ((*data)[1] < 0x80) ? 2 : 2 + ((*data)[1] & 0x7f);

        if (*len <= hdr) return SEC_E_INVALID_TOKEN;
    }
    ctx->pending = HeapAlloc(GetProcessHeap(), 0, total);
    if (!ctx->pending) return SEC_E_INSUFFICIENT_MEMORY;
    memcpy(ctx->pending, *data, *len);
    ctx->pending_len = *len;
    ctx->pending_total = total;
    *more = TRUE;
    return SEC_E_OK;
}

static void nego_server_collected(NegoContext *ctx)
{
    HeapFree(GetProcessHeap(), 0, ctx->pending);
    ctx->pending = NULL;
    ctx->pending_len = ctx->pending_total = 0;
}

/***********************************************************************
 *              AcceptSecurityContext
 */
static SECURITY_STATUS SEC_ENTRY nego_AcceptSecurityContext(
    PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput,
    ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext,
    PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    NegoContext *ctx;
    const BYTE *in;
    ULONG in_len, attr = 0;
    BOOL fresh = FALSE, more;
    SECURITY_STATUS ret;

    TRACE("%p, %p, %p, 0x%08x, %u, %p, %p, %p, %p\n", phCredential, phContext,
          pInput, fContextReq, TargetDataRep, phNewContext, pOutput, pfContextAttr,
          ptsExpiry);

    if (!phNewContext) return SEC_E_INVALID_HANDLE;
    nego_input_token(pInput, &in, &in_len);

    if (!phContext)
    {
        if (!phCredential || !phCredential->dwLower) return SEC_E_INVALID_HANDLE;
        if (!(ntlm_CredentialsUse(phCredential) & SECPKG_CRED_INBOUND)) return SEC_E_INVALID_HANDLE;
        ctx = nego_new_context(TRUE);
        if (!ctx) return SEC_E_INSUFFICIENT_MEMORY;
        ctx->mode = NEGO_SPNEGO;
        ctx->state = NS_SERVER_HINT;
        fresh = TRUE;
        if (!in_len)
        {
            /* the server speaks first: its NegTokenInit with the mechanisms it accepts (no mechToken) */
            BYTE *tok = NULL;
            ULONG tok_len = 0;

            ret = nego_make_init(NULL, 0, &tok, &tok_len);
            if (ret == SEC_E_OK) ret = nego_put_output(pOutput, fContextReq, &attr, tok, tok_len);
            HeapFree(GetProcessHeap(), 0, tok);
            if (ret != SEC_E_OK)
            {
                nego_free_context(ctx);
                return ret;
            }
            nego_set_handle(phNewContext, ctx);
            if (pfContextAttr) *pfContextAttr = attr;
            nego_set_expiry(ptsExpiry);
            return SEC_I_CONTINUE_NEEDED;
        }
    }
    else
    {
        ctx = nego_get_context(phContext);
        if (!ctx || !ctx->server) return SEC_E_INVALID_HANDLE;
        if (ctx->mode == NEGO_RAW)
            return ntlm_AcceptSecurityContext(phCredential, &ctx->ntlm, pInput, fContextReq, TargetDataRep,
                                              &ctx->ntlm, pOutput, pfContextAttr, ptsExpiry);
        /* no token on a context that goes on: SEC_E_INVALID_HANDLE (measured) */
        if (!in_len) return SEC_E_INVALID_HANDLE;
    }
    ctx->req = fContextReq;

    switch (ctx->state)
    {
    case NS_SERVER_HINT:
    case NS_SERVER_WAIT_AUTH:
        ret = nego_server_collect(ctx, &in, &in_len, &more);
        if (ret != SEC_E_OK) break;
        if (more)
        {
            nego_no_output(pOutput);
            if (pfContextAttr) *pfContextAttr = 0;
            ret = SEC_I_CONTINUE_NEEDED;
            break;
        }
        if (ctx->state == NS_SERVER_HINT)
        {
            if (nego_is_raw_ntlm(in, in_len))
            {
                /* a raw NTLM NEGOTIATE: the exchange is plain NTLM (Windows accepts it, measured) */
                if (ctx->have_ntlm) { ret = SEC_E_INVALID_TOKEN; break; }
                ctx->mode = NEGO_RAW;
                ret = ntlm_AcceptSecurityContext(phCredential, NULL, pInput, fContextReq, TargetDataRep, &ctx->ntlm,
                                                 pOutput, pfContextAttr, ptsExpiry);
                if (ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED) ctx->have_ntlm = TRUE;
            }
            else
                ret = nego_server_init(ctx, phCredential, fContextReq, TargetDataRep, in, in_len, pOutput,
                                       pfContextAttr, ptsExpiry);
        }
        else
            ret = nego_server_auth(ctx, phCredential, fContextReq, TargetDataRep, in, in_len, pOutput,
                                   pfContextAttr, ptsExpiry);
        nego_server_collected(ctx);
        break;
    case NS_SERVER_WAIT_FIRST:
        ret = nego_server_first(ctx, phCredential, fContextReq, TargetDataRep, in, in_len, pOutput, pfContextAttr,
                                ptsExpiry);
        break;
    case NS_SERVER_DEAD:
        ret = SEC_E_INVALID_TOKEN;
        break;
    default:
        ret = SEC_E_INVALID_HANDLE;
        break;
    }

    if (ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED)
    {
        if (fresh || phNewContext != phContext) nego_set_handle(phNewContext, ctx);
    }
    else if (fresh)
        nego_free_context(ctx);
    return ret;
}

/***********************************************************************
 *              CompleteAuthToken
 */
static SECURITY_STATUS SEC_ENTRY nego_CompleteAuthToken(PCtxtHandle phContext,
 PSecBufferDesc pToken)
{
    SECURITY_STATUS ret;

    TRACE("%p %p\n", phContext, pToken);
    if (phContext)
    {
        ret = SEC_E_UNSUPPORTED_FUNCTION;
    }
    else
    {
        ret = SEC_E_INVALID_HANDLE;
    }
    return ret;
}

/***********************************************************************
 *              DeleteSecurityContext
 */
static SECURITY_STATUS SEC_ENTRY nego_DeleteSecurityContext(PCtxtHandle phContext)
{
    NegoContext *ctx;

    TRACE("%p\n", phContext);
    if (!phContext) return SEC_E_INVALID_HANDLE;
    ctx = nego_get_context(phContext);
    phContext->dwUpper = 0;
    phContext->dwLower = 0;
    if (!ctx) return SEC_E_INVALID_HANDLE;
    nego_free_context(ctx);
    return SEC_E_OK;
}

/***********************************************************************
 *              ApplyControlToken
 */
static SECURITY_STATUS SEC_ENTRY nego_ApplyControlToken(PCtxtHandle phContext,
 PSecBufferDesc pInput)
{
    SECURITY_STATUS ret;

    TRACE("%p %p\n", phContext, pInput);
    if (phContext)
    {
        ret = SEC_E_UNSUPPORTED_FUNCTION;
    }
    else
    {
        ret = SEC_E_INVALID_HANDLE;
    }
    return ret;
}

/* the NTLM context of a finished exchange (raw NTLM: at once), NULL while SPNEGO still negotiates */
static PCtxtHandle nego_finished_ntlm(PCtxtHandle phContext, NegoContext **out)
{
    NegoContext *ctx = nego_get_context(phContext);

    if (out) *out = ctx;
    if (!ctx || !ctx->have_ntlm) return NULL;
    if (ctx->mode == NEGO_RAW || ctx->state == NS_DONE) return &ctx->ntlm;
    return NULL;
}

/* Windows answers these while SPNEGO negotiates (measured): the negotiation info (state optimistic, the NTLM package)
 * and the sizes of the Negotiate package; everything else is SEC_E_UNSUPPORTED_FUNCTION until the exchange is done */
#define NEGO_SIZES_MAX_TOKEN        48256
#define NEGO_SIZES_MAX_SIGNATURE    64
#define NEGO_SIZES_BLOCK            8
#define NEGO_SIZES_TRAILER          64

/***********************************************************************
 *              QueryContextAttributesW
 */
static SECURITY_STATUS SEC_ENTRY nego_QueryContextAttributesW(
    PCtxtHandle phContext, ULONG ulAttribute, void *pBuffer)
{
    NegoContext *ctx;
    PCtxtHandle ntlm;

    TRACE("%p, %u, %p\n", phContext, ulAttribute, pBuffer);

    ntlm = nego_finished_ntlm(phContext, &ctx);
    if (!ctx) return SEC_E_INVALID_HANDLE;
    if (!pBuffer) return SEC_E_INVALID_PARAMETER;

    if (ctx->mode == NEGO_RAW)
    {
        switch (ulAttribute)
        {
        case SECPKG_ATTR_SIZES:
        {
            SecPkgContext_Sizes *sizes = (SecPkgContext_Sizes *)pBuffer;
            sizes->cbMaxToken        = 2888;
            sizes->cbMaxSignature    = 16;
            sizes->cbSecurityTrailer = 16;
            sizes->cbBlockSize       = 0;
            return SEC_E_OK;
        }
        case SECPKG_ATTR_NEGOTIATION_INFO:
        {
            SecPkgContext_NegotiationInfoW *info = (SecPkgContext_NegotiationInfoW *)pBuffer;
            info->PackageInfo      = ntlm_copy_package_infoW();
            info->NegotiationState = SECPKG_NEGOTIATION_COMPLETE;
            return info->PackageInfo ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
        }
        default:
            return ctx->have_ntlm ? ntlm_QueryContextAttributesW( &ctx->ntlm, ulAttribute, pBuffer )
                                  : SEC_E_INVALID_HANDLE;
        }
    }

    switch (ulAttribute)
    {
    case SECPKG_ATTR_NEGOTIATION_INFO:
    {
        SecPkgContext_NegotiationInfoW *info = (SecPkgContext_NegotiationInfoW *)pBuffer;
        info->PackageInfo      = ntlm_copy_package_infoW();
        info->NegotiationState = ntlm ? SECPKG_NEGOTIATION_COMPLETE : SECPKG_NEGOTIATION_OPTIMISTIC;
        return info->PackageInfo ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
    }
    case SECPKG_ATTR_SIZES:
        if (!ntlm)
        {
            SecPkgContext_Sizes *sizes = (SecPkgContext_Sizes *)pBuffer;
            sizes->cbMaxToken        = NEGO_SIZES_MAX_TOKEN;
            sizes->cbMaxSignature    = NEGO_SIZES_MAX_SIGNATURE;
            sizes->cbSecurityTrailer = NEGO_SIZES_TRAILER;
            sizes->cbBlockSize       = NEGO_SIZES_BLOCK;
            return SEC_E_OK;
        }
        break;
    }
    if (!ntlm) return SEC_E_UNSUPPORTED_FUNCTION;
    return ntlm_QueryContextAttributesW( ntlm, ulAttribute, pBuffer );
}

/***********************************************************************
 *              QueryContextAttributesA
 */
static SECURITY_STATUS SEC_ENTRY nego_QueryContextAttributesA(PCtxtHandle phContext,
 ULONG ulAttribute, void *pBuffer)
{
    NegoContext *ctx;
    PCtxtHandle ntlm;

    TRACE("%p, %u, %p\n", phContext, ulAttribute, pBuffer);

    ntlm = nego_finished_ntlm(phContext, &ctx);
    if (!ctx) return SEC_E_INVALID_HANDLE;
    if (!pBuffer) return SEC_E_INVALID_PARAMETER;

    switch (ulAttribute)
    {
    case SECPKG_ATTR_NEGOTIATION_INFO:
    {
        SecPkgContext_NegotiationInfoA *info = (SecPkgContext_NegotiationInfoA *)pBuffer;
        info->PackageInfo      = ntlm_copy_package_infoA();
        info->NegotiationState = (ctx->mode == NEGO_RAW || ntlm) ? SECPKG_NEGOTIATION_COMPLETE
                                                                 : SECPKG_NEGOTIATION_OPTIMISTIC;
        return info->PackageInfo ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
    }
    case SECPKG_ATTR_SIZES:
        if (ctx->mode == NEGO_RAW || !ntlm) return nego_QueryContextAttributesW( phContext, ulAttribute, pBuffer );
        break;
    }
    if (ctx->mode == NEGO_RAW)
        return ctx->have_ntlm ? ntlm_QueryContextAttributesA( &ctx->ntlm, ulAttribute, pBuffer ) : SEC_E_INVALID_HANDLE;
    if (!ntlm) return SEC_E_UNSUPPORTED_FUNCTION;
    return ntlm_QueryContextAttributesA( ntlm, ulAttribute, pBuffer );
}

/***********************************************************************
 *              ImpersonateSecurityContext
 */
static SECURITY_STATUS SEC_ENTRY nego_ImpersonateSecurityContext(PCtxtHandle phContext)
{
    NegoContext *ctx;
    PCtxtHandle ntlm;

    TRACE("%p\n", phContext);

    ntlm = nego_finished_ntlm(phContext, &ctx);
    if (!ctx) return SEC_E_INVALID_HANDLE;
    /* no token before the exchange (and its mechListMIC) is complete */
    if (!ntlm) return SEC_E_NO_IMPERSONATION;
    return ntlm_ImpersonateSecurityContext( ntlm );
}

/***********************************************************************
 *              RevertSecurityContext
 */
static SECURITY_STATUS SEC_ENTRY nego_RevertSecurityContext(PCtxtHandle phContext)
{
    NegoContext *ctx;
    PCtxtHandle ntlm;

    TRACE("%p\n", phContext);

    ntlm = nego_finished_ntlm(phContext, &ctx);
    if (!ctx) return SEC_E_INVALID_HANDLE;
    if (!ntlm) return SEC_E_NO_IMPERSONATION;
    return ntlm_RevertSecurityContext( ntlm );
}

/***********************************************************************
 *              QuerySecurityContextToken
 */
static SECURITY_STATUS SEC_ENTRY nego_QuerySecurityContextToken(PCtxtHandle phContext, HANDLE *phToken)
{
    NegoContext *ctx;
    PCtxtHandle ntlm;

    TRACE("%p %p\n", phContext, phToken);

    ntlm = nego_finished_ntlm(phContext, &ctx);
    if (!ctx || !ntlm) return SEC_E_INVALID_HANDLE;
    return ntlm_QuerySecurityContextToken( ntlm, phToken );
}

/***********************************************************************
 *              MakeSignature
 */
static SECURITY_STATUS SEC_ENTRY nego_MakeSignature(PCtxtHandle phContext,
    ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
    PCtxtHandle ntlm = nego_finished_ntlm(phContext, NULL);

    TRACE("%p, 0x%08x, %p, %u\n", phContext, fQOP, pMessage, MessageSeqNo);
    if (!ntlm) return SEC_E_INVALID_HANDLE;
    return ntlm_MakeSignature( ntlm, fQOP, pMessage, MessageSeqNo );
}

/***********************************************************************
 *              VerifySignature
 */
static SECURITY_STATUS SEC_ENTRY nego_VerifySignature(PCtxtHandle phContext,
    PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
    PCtxtHandle ntlm = nego_finished_ntlm(phContext, NULL);

    TRACE("%p, %p, %u, %p\n", phContext, pMessage, MessageSeqNo, pfQOP);
    if (!ntlm) return SEC_E_INVALID_HANDLE;
    return ntlm_VerifySignature( ntlm, pMessage, MessageSeqNo, pfQOP );
}

/***********************************************************************
 *             FreeCredentialsHandle
 */
static SECURITY_STATUS SEC_ENTRY nego_FreeCredentialsHandle(PCredHandle phCredential)
{
    TRACE("%p\n", phCredential);

    return ntlm_FreeCredentialsHandle( phCredential );
}

/***********************************************************************
 *             EncryptMessage
 */
static SECURITY_STATUS SEC_ENTRY nego_EncryptMessage(PCtxtHandle phContext,
    ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
    PCtxtHandle ntlm = nego_finished_ntlm(phContext, NULL);

    TRACE("%p, 0x%08x, %p, %u\n", phContext, fQOP, pMessage, MessageSeqNo);
    if (!ntlm) return SEC_E_INVALID_HANDLE;
    return ntlm_EncryptMessage( ntlm, fQOP, pMessage, MessageSeqNo );
}

/***********************************************************************
 *             DecryptMessage
 */
static SECURITY_STATUS SEC_ENTRY nego_DecryptMessage(PCtxtHandle phContext,
    PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
    PCtxtHandle ntlm = nego_finished_ntlm(phContext, NULL);

    TRACE("%p, %p, %u, %p\n", phContext, pMessage, MessageSeqNo, pfQOP);
    if (!ntlm) return SEC_E_INVALID_HANDLE;
    return ntlm_DecryptMessage( ntlm, pMessage, MessageSeqNo, pfQOP );
}

static const SecurityFunctionTableA negoTableA = {
    1,
    NULL,                               /* EnumerateSecurityPackagesA */
    nego_QueryCredentialsAttributesA,   /* QueryCredentialsAttributesA */
    nego_AcquireCredentialsHandleA,     /* AcquireCredentialsHandleA */
    nego_FreeCredentialsHandle,         /* FreeCredentialsHandle */
    NULL,                               /* Reserved2 */
    nego_InitializeSecurityContextA,    /* InitializeSecurityContextA */
    nego_AcceptSecurityContext,         /* AcceptSecurityContext */
    nego_CompleteAuthToken,             /* CompleteAuthToken */
    nego_DeleteSecurityContext,         /* DeleteSecurityContext */
    nego_ApplyControlToken,             /* ApplyControlToken */
    nego_QueryContextAttributesA,       /* QueryContextAttributesA */
    nego_ImpersonateSecurityContext,    /* ImpersonateSecurityContext */
    nego_RevertSecurityContext,         /* RevertSecurityContext */
    nego_MakeSignature,                 /* MakeSignature */
    nego_VerifySignature,               /* VerifySignature */
    FreeContextBuffer,                  /* FreeContextBuffer */
    NULL,   /* QuerySecurityPackageInfoA */
    NULL,   /* Reserved3 */
    NULL,   /* Reserved4 */
    NULL,   /* ExportSecurityContext */
    NULL,   /* ImportSecurityContextA */
    NULL,   /* AddCredentialsA */
    NULL,   /* Reserved8 */
    nego_QuerySecurityContextToken,     /* QuerySecurityContextToken */
    nego_EncryptMessage,                /* EncryptMessage */
    nego_DecryptMessage,                /* DecryptMessage */
    NULL,   /* SetContextAttributesA */
};

static const SecurityFunctionTableW negoTableW = {
    1,
    NULL,                               /* EnumerateSecurityPackagesW */
    nego_QueryCredentialsAttributesW,   /* QueryCredentialsAttributesW */
    nego_AcquireCredentialsHandleW,     /* AcquireCredentialsHandleW */
    nego_FreeCredentialsHandle,         /* FreeCredentialsHandle */
    NULL,                               /* Reserved2 */
    nego_InitializeSecurityContextW,    /* InitializeSecurityContextW */
    nego_AcceptSecurityContext,         /* AcceptSecurityContext */
    nego_CompleteAuthToken,             /* CompleteAuthToken */
    nego_DeleteSecurityContext,         /* DeleteSecurityContext */
    nego_ApplyControlToken,             /* ApplyControlToken */
    nego_QueryContextAttributesW,       /* QueryContextAttributesW */
    nego_ImpersonateSecurityContext,    /* ImpersonateSecurityContext */
    nego_RevertSecurityContext,         /* RevertSecurityContext */
    nego_MakeSignature,                 /* MakeSignature */
    nego_VerifySignature,               /* VerifySignature */
    FreeContextBuffer,                  /* FreeContextBuffer */
    NULL,   /* QuerySecurityPackageInfoW */
    NULL,   /* Reserved3 */
    NULL,   /* Reserved4 */
    NULL,   /* ExportSecurityContext */
    NULL,   /* ImportSecurityContextW */
    NULL,   /* AddCredentialsW */
    NULL,   /* Reserved8 */
    nego_QuerySecurityContextToken,     /* QuerySecurityContextToken */
    nego_EncryptMessage,                /* EncryptMessage */
    nego_DecryptMessage,                /* DecryptMessage */
    NULL,   /* SetContextAttributesW */
};

#define NEGO_MAX_TOKEN 12000

static WCHAR nego_name_W[] = {'N','e','g','o','t','i','a','t','e',0};
static char nego_name_A[] = "Negotiate";

static WCHAR negotiate_comment_W[] =
    {'M','i','c','r','o','s','o','f','t',' ','P','a','c','k','a','g','e',' ',
     'N','e','g','o','t','i','a','t','o','r',0};
static CHAR negotiate_comment_A[] = "Microsoft Package Negotiator";

#define CAPS ( \
    SECPKG_FLAG_INTEGRITY  | \
    SECPKG_FLAG_PRIVACY    | \
    SECPKG_FLAG_CONNECTION | \
    SECPKG_FLAG_MULTI_REQUIRED | \
    SECPKG_FLAG_EXTENDED_ERROR | \
    SECPKG_FLAG_IMPERSONATION  | \
    SECPKG_FLAG_ACCEPT_WIN32_NAME | \
    SECPKG_FLAG_NEGOTIABLE        | \
    SECPKG_FLAG_GSS_COMPATIBLE    | \
    SECPKG_FLAG_LOGON             | \
    SECPKG_FLAG_RESTRICTED_TOKENS )

void SECUR32_initNegotiateSP(void)
{
    SecureProvider *provider = SECUR32_addProvider(&negoTableA, &negoTableW, NULL);

    const SecPkgInfoW infoW = {CAPS, 1, RPC_C_AUTHN_GSS_NEGOTIATE, NEGO_MAX_TOKEN,
                               nego_name_W, negotiate_comment_W};
    const SecPkgInfoA infoA = {CAPS, 1, RPC_C_AUTHN_GSS_NEGOTIATE, NEGO_MAX_TOKEN,
                               nego_name_A, negotiate_comment_A};
    SECUR32_addPackages(provider, 1L, &infoA, &infoW);
}
