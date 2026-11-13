/*
 * Copyright 2005, 2006 Kai Blin
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
 * This file implements the NTLM security provider. The message exchange, the
 * NTLMv2 response and the session security (sign and seal) are implemented
 * here from the public protocol description (MS-NLMP). The server side asks
 * the local security authority to check the response and to create the token
 * of the client (a network logon), so the NTLM package needs no external helper.
 */

#include "precomp.h"

#include <assert.h>
#include <stdio.h>
#include <wincred.h>
#include <lm.h>

#include <ndk/lpctypes.h>
#include <ndk/lpcfuncs.h>
#include <ndk/obfuncs.h>
#include <psdk/ntsecapi.h>
#include <ntlmros.h>

#include "hmac_md5.h"

#include <wine/unicode.h>
#include <wine/debug.h>
WINE_DEFAULT_DEBUG_CHANNEL(ntlm);

#define NTLM_MAX_BUF 1904

/* a message that is not what the exchange expects: the trace names the place */
static SECURITY_STATUS invalid_token(int line)
{
    WARN("invalid token (line %d)\n", line);
    return SEC_E_INVALID_TOKEN;
}
#define TOKEN_FAIL() invalid_token(__LINE__)

BOOLEAN WINAPI SystemFunction036(PVOID buffer, ULONG length);

typedef struct
{
    unsigned int buf[4];
    unsigned int i[2];
    unsigned char in[64];
    unsigned char digest[16];
} NTLM_MD4_CTX;

VOID WINAPI MD4Init(NTLM_MD4_CTX *ctx);
VOID WINAPI MD4Update(NTLM_MD4_CTX *ctx, const unsigned char *buf, unsigned int len);
VOID WINAPI MD4Final(NTLM_MD4_CTX *ctx);

/* message types, flags and attribute ids of the protocol */
#define NTLM_NEGOTIATE_MESSAGE      1
#define NTLM_CHALLENGE_MESSAGE      2
#define NTLM_AUTHENTICATE_MESSAGE   3

#define NTLMSSP_NEGOTIATE_IDENTIFY  0x00100000
#define NTLMSSP_NEGOTIATE_ANONYMOUS 0x00000800

#define MSV_AV_EOL              0
#define MSV_AV_NB_COMPUTER_NAME 1
#define MSV_AV_NB_DOMAIN_NAME   2
#define MSV_AV_FLAGS            6
#define MSV_AV_TIMESTAMP        7
#define MSV_AV_FLAG_MIC         0x00000002

/* NEGOTIATE: signature, type, flags, domain, workstation */
#define NEGOTIATE_HEADER_LEN    32
/* CHALLENGE: signature, type, target name, flags, challenge, reserved, target info */
#define CHALLENGE_HEADER_LEN    48
/* AUTHENTICATE: signature, type, 5 fields, session key field, flags, version, mic */
#define AUTH_HEADER_NO_MIC      64
#define AUTH_HEADER_LEN         88
#define AUTH_MIC_OFFSET         72

static const BYTE ntlm_signature[8] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };

/***********************************************************************
 * little helpers for the wire format (all values are little endian)
 */
static void put16(BYTE *p, ULONG v) { p[0] = v; p[1] = v >> 8; }
static void put32(BYTE *p, ULONG v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static ULONG get16(const BYTE *p) { return p[0] | (p[1] << 8); }
static ULONG get32(const BYTE *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((ULONG)p[3] << 24); }

/* the data a security buffer field of a message points to, checked against the message */
static BOOL get_field(const BYTE *msg, ULONG msg_len, ULONG at, const BYTE **data, ULONG *len)
{
    ULONG l, off;

    if (msg_len < at + 8) return FALSE;
    l = get16(msg + at);
    off = get32(msg + at + 4);
    if (l && (off > msg_len || l > msg_len - off)) return FALSE;
    *data = msg + off;
    *len = l;
    return TRUE;
}

typedef struct
{
    BYTE *data;
    ULONG len;
    ULONG alloc;
} MsgBuf;

static BOOL msg_reserve(MsgBuf *m, ULONG more)
{
    if (m->len + more > m->alloc)
    {
        ULONG n = (m->len + more + 255) & ~255;
        BYTE *d = m->data ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, m->data, n)
                          : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
        if (!d) return FALSE;
        m->data = d;
        m->alloc = n;
    }
    return TRUE;
}

/* appends payload and fills the security buffer field at `at` */
static BOOL msg_add_field(MsgBuf *m, ULONG at, const void *data, ULONG len)
{
    if (!msg_reserve(m, len)) return FALSE;
    put16(m->data + at, len);
    put16(m->data + at + 2, len);
    put32(m->data + at + 4, m->len);
    if (len) memcpy(m->data + m->len, data, len);
    m->len += len;
    return TRUE;
}

/***********************************************************************
 * crypto glue
 */
static void upcase_buffer(WCHAR *str, ULONG len)
{
    while (len--)
    {
        *str = RtlUpcaseUnicodeChar(*str);
        str++;
    }
}

static void hmac_md5(const BYTE *key, ULONG key_len, const BYTE *a, ULONG a_len, const BYTE *b, ULONG b_len,
                     const BYTE *c, ULONG c_len, BYTE *digest)
{
    HMAC_MD5_CTX ctx;

    HMACMD5Init(&ctx, key, key_len);
    if (a_len) HMACMD5Update(&ctx, a, a_len);
    if (b_len) HMACMD5Update(&ctx, b, b_len);
    if (c_len) HMACMD5Update(&ctx, c, c_len);
    HMACMD5Final(&ctx, digest);
}

static void nt_owf(const WCHAR *password, BYTE *hash)
{
    NTLM_MD4_CTX ctx;

    MD4Init(&ctx);
    MD4Update(&ctx, (const BYTE *)password, lstrlenW(password) * sizeof(WCHAR));
    MD4Final(&ctx);
    memcpy(hash, ctx.digest, 16);
}

static void rc4_crypt(const BYTE *key, BYTE *data, ULONG len)
{
    arc4_info a4i;

    SECUR32_arc4Init(&a4i, key, 16);
    SECUR32_arc4Process(&a4i, data, len);
    memset(&a4i, 0, sizeof(a4i));
}

/***********************************************************************
 * credentials
 */
static WCHAR *dup_identity_string(const void *str, ULONG len, BOOL unicode)
{
    WCHAR *ret;

    if (!str) len = 0;
    ret = HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
    if (!ret) return NULL;
    if (unicode)
        memcpy(ret, str, len * sizeof(WCHAR));
    else if (len)
        len = MultiByteToWideChar(CP_ACP, 0, str, len, ret, len);
    ret[len] = 0;
    return ret;
}

static void free_credentials(PNtlmCredentials cred)
{
    if (!cred) return;
    SecureZeroMemory(cred->nt_hash, sizeof(cred->nt_hash));
    HeapFree(GetProcessHeap(), 0, cred->username);
    HeapFree(GetProcessHeap(), 0, cred->domain);
    HeapFree(GetProcessHeap(), 0, cred);
}

/***********************************************************************
 *              QueryCredentialsAttributesA
 */
static SECURITY_STATUS SEC_ENTRY ntlm_QueryCredentialsAttributesA(
        PCredHandle phCredential, ULONG ulAttribute, PVOID pBuffer)
{
    TRACE("(%p, %d, %p)\n", phCredential, ulAttribute, pBuffer);
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/***********************************************************************
 *              QueryCredentialsAttributesW
 */
static SECURITY_STATUS SEC_ENTRY ntlm_QueryCredentialsAttributesW(
        PCredHandle phCredential, ULONG ulAttribute, PVOID pBuffer)
{
    TRACE("(%p, %d, %p)\n", phCredential, ulAttribute, pBuffer);
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/***********************************************************************
 *              AcquireCredentialsHandleW
 *
 * The identity (user, domain and password) is kept as the NT hash of the
 * password. Without an identity the credentials of the caller are meant.
 */
SECURITY_STATUS SEC_ENTRY ntlm_AcquireCredentialsHandleW(
 SEC_WCHAR *pszPrincipal, SEC_WCHAR *pszPackage, ULONG fCredentialUse,
 PLUID pvLogonID, PVOID pAuthData, SEC_GET_KEY_FN pGetKeyFn,
 PVOID pGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
    PNtlmCredentials cred;

    TRACE("(%s, %s, 0x%08x, %p, %p, %p, %p, %p, %p)\n",
          debugstr_w(pszPrincipal), debugstr_w(pszPackage), fCredentialUse,
          pvLogonID, pAuthData, pGetKeyFn, pGetKeyArgument, phCredential, ptsExpiry);

    switch (fCredentialUse & SECPKG_CRED_BOTH)
    {
    case SECPKG_CRED_INBOUND:
    case SECPKG_CRED_OUTBOUND:
    case SECPKG_CRED_BOTH:
        break;
    default:
        return SEC_E_UNKNOWN_CREDENTIALS;
    }

    cred = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*cred));
    if (!cred) return SEC_E_INSUFFICIENT_MEMORY;
    cred->use = fCredentialUse & SECPKG_CRED_BOTH;

    if ((cred->use & SECPKG_CRED_OUTBOUND) && pAuthData)
    {
        const SEC_WINNT_AUTH_IDENTITY_W *id = pAuthData;
        BOOL unicode = (id->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE) != 0;
        WCHAR *password;

        cred->has_identity = TRUE;
        cred->username = dup_identity_string(id->User, id->UserLength, unicode);
        cred->domain = dup_identity_string(id->Domain, id->DomainLength, unicode);
        password = dup_identity_string(id->Password, id->PasswordLength, unicode);
        if (!cred->username || !cred->domain || !password)
        {
            HeapFree(GetProcessHeap(), 0, password);
            free_credentials(cred);
            return SEC_E_INSUFFICIENT_MEMORY;
        }
        nt_owf(password, cred->nt_hash);
        SecureZeroMemory(password, lstrlenW(password) * sizeof(WCHAR));
        HeapFree(GetProcessHeap(), 0, password);
    }

    phCredential->dwUpper = 1;
    phCredential->dwLower = (ULONG_PTR)cred;
    if (ptsExpiry)
    {
        ptsExpiry->LowPart = 0xffffffff;
        ptsExpiry->HighPart = 0x7fffffff;
    }
    return SEC_E_OK;
}

/***********************************************************************
 *              AcquireCredentialsHandleA
 */
static SECURITY_STATUS SEC_ENTRY ntlm_AcquireCredentialsHandleA(
 SEC_CHAR *pszPrincipal, SEC_CHAR *pszPackage, ULONG fCredentialUse,
 PLUID pvLogonID, PVOID pAuthData, SEC_GET_KEY_FN pGetKeyFn,
 PVOID pGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;
    int user_sizeW, domain_sizeW, passwd_sizeW;
    SEC_WCHAR *user = NULL, *domain = NULL, *passwd = NULL, *package = NULL;
    SEC_WINNT_AUTH_IDENTITY_W *identityW = NULL;

    TRACE("(%s, %s, 0x%08x, %p, %p, %p, %p, %p, %p)\n",
          debugstr_a(pszPrincipal), debugstr_a(pszPackage), fCredentialUse,
          pvLogonID, pAuthData, pGetKeyFn, pGetKeyArgument, phCredential, ptsExpiry);

    if (pszPackage)
    {
        int package_sizeW = MultiByteToWideChar(CP_ACP, 0, pszPackage, -1, NULL, 0);

        package = HeapAlloc(GetProcessHeap(), 0, package_sizeW * sizeof(SEC_WCHAR));
        if (!package) return SEC_E_INSUFFICIENT_MEMORY;
        MultiByteToWideChar(CP_ACP, 0, pszPackage, -1, package, package_sizeW);
    }

    if (pAuthData)
    {
        PSEC_WINNT_AUTH_IDENTITY_A identity = pAuthData;

        if (identity->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI)
        {
            identityW = HeapAlloc(GetProcessHeap(), 0, sizeof(*identityW));
            if (!identityW)
            {
                ret = SEC_E_INSUFFICIENT_MEMORY;
                goto done;
            }
            user_sizeW = MultiByteToWideChar(CP_ACP, 0, (LPSTR)identity->User, identity->UserLength, NULL, 0);
            domain_sizeW = MultiByteToWideChar(CP_ACP, 0, (LPSTR)identity->Domain, identity->DomainLength, NULL, 0);
            passwd_sizeW = MultiByteToWideChar(CP_ACP, 0, (LPSTR)identity->Password, identity->PasswordLength, NULL, 0);
            user = HeapAlloc(GetProcessHeap(), 0, (user_sizeW + 1) * sizeof(SEC_WCHAR));
            domain = HeapAlloc(GetProcessHeap(), 0, (domain_sizeW + 1) * sizeof(SEC_WCHAR));
            passwd = HeapAlloc(GetProcessHeap(), 0, (passwd_sizeW + 1) * sizeof(SEC_WCHAR));
            if (!user || !domain || !passwd)
            {
                ret = SEC_E_INSUFFICIENT_MEMORY;
                goto done;
            }
            if (identity->User)
                MultiByteToWideChar(CP_ACP, 0, (LPSTR)identity->User, identity->UserLength, user, user_sizeW);
            if (identity->Domain)
                MultiByteToWideChar(CP_ACP, 0, (LPSTR)identity->Domain, identity->DomainLength, domain, domain_sizeW);
            if (identity->Password)
                MultiByteToWideChar(CP_ACP, 0, (LPSTR)identity->Password, identity->PasswordLength, passwd, passwd_sizeW);
            identityW->User = user;
            identityW->UserLength = identity->User ? user_sizeW : 0;
            identityW->Domain = domain;
            identityW->DomainLength = identity->Domain ? domain_sizeW : 0;
            identityW->Password = passwd;
            identityW->PasswordLength = identity->Password ? passwd_sizeW : 0;
            identityW->Flags = (identity->Flags & ~SEC_WINNT_AUTH_IDENTITY_ANSI) | SEC_WINNT_AUTH_IDENTITY_UNICODE;
            pAuthData = identityW;
        }
    }

    ret = ntlm_AcquireCredentialsHandleW(NULL, package, fCredentialUse, pvLogonID, pAuthData,
                                         pGetKeyFn, pGetKeyArgument, phCredential, ptsExpiry);
done:
    if (passwd) SecureZeroMemory(passwd, passwd_sizeW * sizeof(SEC_WCHAR));
    HeapFree(GetProcessHeap(), 0, package);
    HeapFree(GetProcessHeap(), 0, user);
    HeapFree(GetProcessHeap(), 0, domain);
    HeapFree(GetProcessHeap(), 0, passwd);
    HeapFree(GetProcessHeap(), 0, identityW);
    return ret;
}

/***********************************************************************
 *             FreeCredentialsHandle
 */
SECURITY_STATUS SEC_ENTRY ntlm_FreeCredentialsHandle(PCredHandle phCredential)
{
    if (phCredential)
    {
        PNtlmCredentials cred = (PNtlmCredentials)phCredential->dwLower;

        phCredential->dwUpper = 0;
        phCredential->dwLower = 0;
        free_credentials(cred);
    }
    return SEC_E_OK;
}

/*************************************************************************
 *             ntlm_GetTokenBufferIndex
 * Calculates the index of the secbuffer with BufferType == SECBUFFER_TOKEN
 * Returns index if found or -1 if not found.
 */
static int ntlm_GetTokenBufferIndex(PSecBufferDesc pMessage)
{
    UINT i;

    TRACE("%p\n", pMessage);

    for( i = 0; i < pMessage->cBuffers; ++i )
    {
        if(pMessage->pBuffers[i].BufferType == SECBUFFER_TOKEN)
            return i;
    }

    return -1;
}

/*************************************************************************
 *             ntlm_GetDataBufferIndex
 * Calculates the index of the first secbuffer with BufferType == SECBUFFER_DATA
 * Returns index if found or -1 if not found.
 */
static int ntlm_GetDataBufferIndex(PSecBufferDesc pMessage)
{
    UINT i;

    TRACE("%p\n", pMessage);

    for( i = 0; i < pMessage->cBuffers; ++i )
    {
        if(pMessage->pBuffers[i].BufferType == SECBUFFER_DATA)
            return i;
    }

    return -1;
}

/* the token buffer of an input description with its data and size */
static BOOL get_input_token(PSecBufferDesc input, const BYTE **data, ULONG *len)
{
    int idx;

    if (!input || !input->pBuffers) return FALSE;
    if ((idx = ntlm_GetTokenBufferIndex(input)) == -1) return FALSE;
    *data = input->pBuffers[idx].pvBuffer;
    *len = input->pBuffers[idx].cbBuffer;
    return *data && *len;
}

/* hands a finished message to the caller's token buffer */
static SECURITY_STATUS put_output_token(PSecBufferDesc output, ULONG req, ULONG *attr, const BYTE *data, ULONG len)
{
    int idx;
    SecBuffer *buf;

    if (!output || !output->pBuffers || (idx = ntlm_GetTokenBufferIndex(output)) == -1)
        return SEC_E_BUFFER_TOO_SMALL;
    buf = &output->pBuffers[idx];

    if (req & (ISC_REQ_ALLOCATE_MEMORY))
    {
        buf->pvBuffer = HeapAlloc(GetProcessHeap(), 0, len);
        if (!buf->pvBuffer) return SEC_E_INSUFFICIENT_MEMORY;
        *attr |= ISC_RET_ALLOCATED_MEMORY;
    }
    else if (!buf->pvBuffer)
        return SEC_E_INTERNAL_ERROR;
    else if (buf->cbBuffer < len)
        return SEC_E_BUFFER_TOO_SMALL;

    memcpy(buf->pvBuffer, data, len);
    buf->cbBuffer = len;
    return SEC_E_OK;
}

/***********************************************************************
 * contexts
 */
static PNegoHelper ntlm_new_context(HelperMode mode, ULONG req)
{
    PNegoHelper h = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*h));

    if (h)
    {
        h->mode = mode;
        h->req_flags = req;
    }
    return h;
}

static void ntlm_free_context(PNegoHelper h)
{
    if (!h) return;
    SECUR32_arc4Cleanup(h->crypt.ntlm.a4i);
    SECUR32_arc4Cleanup(h->crypt.ntlm2.send_a4i);
    SECUR32_arc4Cleanup(h->crypt.ntlm2.recv_a4i);
    HeapFree(GetProcessHeap(), 0, h->crypt.ntlm2.send_sign_key);
    HeapFree(GetProcessHeap(), 0, h->crypt.ntlm2.send_seal_key);
    HeapFree(GetProcessHeap(), 0, h->crypt.ntlm2.recv_sign_key);
    HeapFree(GetProcessHeap(), 0, h->crypt.ntlm2.recv_seal_key);
    if (h->session_key) SecureZeroMemory(h->session_key, 16);
    HeapFree(GetProcessHeap(), 0, h->session_key);
    HeapFree(GetProcessHeap(), 0, h->negotiate_msg);
    HeapFree(GetProcessHeap(), 0, h->challenge_msg);
    HeapFree(GetProcessHeap(), 0, h->user_name);
    HeapFree(GetProcessHeap(), 0, h->domain_name);
    if (h->cred) free_credentials(h->cred);
    if (h->token) CloseHandle(h->token);
    HeapFree(GetProcessHeap(), 0, h);
}

/* the session is keyed: key schedule of the sign and seal handles */
static void ntlm_setup_session(PNegoHelper h, const BYTE *key)
{
    h->session_key = HeapAlloc(GetProcessHeap(), 0, 16);
    memcpy(h->session_key, key, 16);

    h->crypt.ntlm.a4i = SECUR32_arc4Alloc();
    SECUR32_arc4Init(h->crypt.ntlm.a4i, h->session_key, 16);
    h->crypt.ntlm.seq_num = 0;
    SECUR32_CreateNTLM2SubKeys(h);
    h->crypt.ntlm2.send_a4i = SECUR32_arc4Alloc();
    h->crypt.ntlm2.recv_a4i = SECUR32_arc4Alloc();
    SECUR32_arc4Init(h->crypt.ntlm2.send_a4i, h->crypt.ntlm2.send_seal_key, 16);
    SECUR32_arc4Init(h->crypt.ntlm2.recv_a4i, h->crypt.ntlm2.recv_seal_key, 16);
    h->crypt.ntlm2.send_seq_no = 0;
    h->crypt.ntlm2.recv_seq_no = 0;
}

/* flags of the context the caller gets back */
static ULONG ntlm_ret_flags(const NegoHelper *h, BOOL server)
{
    ULONG ret = server ? ASC_RET_CONNECTION : ISC_RET_CONNECTION;

    if (h->neg_flags & NTLMSSP_NEGOTIATE_SIGN)
        ret |= server ? ASC_RET_INTEGRITY : ISC_RET_INTEGRITY;
    if (h->neg_flags & NTLMSSP_NEGOTIATE_SEAL)
        ret |= server ? ASC_RET_CONFIDENTIALITY : ISC_RET_CONFIDENTIALITY;
    /* ISC_REQ_USE_DCE_STYLE and ASC_REQ_USE_DCE_STYLE are the same bit, as the return flags are */
    return ret | (h->req_flags & ISC_REQ_USE_DCE_STYLE);
}

/* the flags the context asked for in its security buffer sense */
static ULONG ntlm_requested_security(ULONG req)
{
    ULONG flags = 0;

    /* the request flags of the two sides have the same bit values (ISC_REQ_x = ASC_REQ_x) for these */
    if (req & (ISC_REQ_INTEGRITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT)) flags |= NTLMSSP_NEGOTIATE_SIGN;
    if (req & ISC_REQ_CONFIDENTIALITY) flags |= NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL;
    return flags;
}

/***********************************************************************
 * client: NEGOTIATE and AUTHENTICATE messages
 */
static SECURITY_STATUS client_negotiate(PNegoHelper h, ULONG req, MsgBuf *m)
{
    ULONG flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM |
                  NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_NEGOTIATE_NTLM2 | NTLMSSP_NEGOTIATE_128;

    flags |= ntlm_requested_security(req);
    if (flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)) flags |= NTLMSSP_NEGOTIATE_KEY_EXCHANGE;

    if (!msg_reserve(m, NEGOTIATE_HEADER_LEN)) return SEC_E_INSUFFICIENT_MEMORY;
    m->len = NEGOTIATE_HEADER_LEN;
    memcpy(m->data, ntlm_signature, 8);
    put32(m->data + 8, NTLM_NEGOTIATE_MESSAGE);
    put32(m->data + 12, flags);
    /* no domain and no workstation: the offsets point behind the header */
    put32(m->data + 20, NEGOTIATE_HEADER_LEN);
    put32(m->data + 28, NEGOTIATE_HEADER_LEN);
    h->offered_flags = flags;
    return SEC_E_OK;
}

/* the target info with the MIC flag, ready for the blob: no terminator yet */
static BOOL build_client_target_info(const BYTE *info, ULONG info_len, BYTE **out, ULONG *out_len, ULONGLONG *timestamp)
{
    ULONG pos = 0, flags = 0;
    BYTE *buf;
    ULONG len = 0;

    buf = HeapAlloc(GetProcessHeap(), 0, info_len + 16);
    if (!buf) return FALSE;

    while (pos + 4 <= info_len)
    {
        ULONG id = get16(info + pos), l = get16(info + pos + 2);

        if (id == MSV_AV_EOL) break;
        if (l > info_len - pos - 4) break;
        if (id == MSV_AV_FLAGS && l == 4)
            flags = get32(info + pos + 4);
        else
        {
            memcpy(buf + len, info + pos, 4 + l);
            len += 4 + l;
            if (id == MSV_AV_TIMESTAMP && l == 8)
                memcpy(timestamp, info + pos + 4, 8);
        }
        pos += 4 + l;
    }
    put16(buf + len, MSV_AV_FLAGS);
    put16(buf + len + 2, 4);
    put32(buf + len + 4, flags | MSV_AV_FLAG_MIC);
    len += 8;
    *out = buf;
    *out_len = len;
    return TRUE;
}

/* The NTLMv2 proofs of the logon session of the caller, from the MSV1_0 package of the local security authority
 * (the caller gave no credentials). Returns the user and the domain of the logon (to release with HeapFree). */
static SECURITY_STATUS lsa_default_response(const BYTE *server_challenge, const BYTE *client_challenge,
                                            const BYTE *blob, ULONG blob_len, WCHAR **user, WCHAR **domain,
                                            BYTE *nt_proof, BYTE *lm_proof, BYTE *base_key)
{
    static const char package_name[] = MSV1_0_PACKAGE_NAME;
    MSV1_0_ROS_NTLMV2_REQUEST *req;
    MSV1_0_ROS_NTLMV2_RESPONSE *resp = NULL;
    HANDLE lsa = NULL;
    LSA_STRING package;
    ULONG package_id, resp_len = 0, size;
    NTSTATUS status, proto_status = 0;
    SECURITY_STATUS ret = SEC_E_NO_CREDENTIALS;

    *user = *domain = NULL;
    size = sizeof(*req) + blob_len;
    req = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!req) return SEC_E_INSUFFICIENT_MEMORY;
    req->MessageType = MsV1_0RosNtlmV2Response;
    memcpy(req->ServerChallenge, server_challenge, 8);
    memcpy(req->ClientChallenge, client_challenge, 8);
    req->BlobLength = blob_len;
    memcpy(req + 1, blob, blob_len);

    status = LsaConnectUntrusted(&lsa);
    if (!NT_SUCCESS(status)) goto done;
    package.Buffer = (PCHAR)package_name;
    package.Length = sizeof(package_name) - 1;
    package.MaximumLength = sizeof(package_name);
    status = LsaLookupAuthenticationPackage(lsa, &package, &package_id);
    if (!NT_SUCCESS(status)) goto done;
    status = LsaCallAuthenticationPackage(lsa, package_id, req, size, (void **)&resp, &resp_len, &proto_status);
    if (!NT_SUCCESS(status) || !NT_SUCCESS(proto_status) || !resp)
    {
        WARN("no credentials for the logon of the caller (0x%08x 0x%08x)\n", status, proto_status);
        goto done;
    }
    if (resp_len < sizeof(*resp) || resp->MessageType != MsV1_0RosNtlmV2Response ||
        resp->UserNameLength > resp_len - sizeof(*resp) ||
        resp->DomainNameLength > resp_len - sizeof(*resp) - resp->UserNameLength ||
        (resp->UserNameLength & 1) || (resp->DomainNameLength & 1) || !resp->UserNameLength)
        goto done;

    *user = dup_identity_string(resp + 1, resp->UserNameLength / sizeof(WCHAR), TRUE);
    *domain = dup_identity_string((BYTE *)(resp + 1) + resp->UserNameLength, resp->DomainNameLength / sizeof(WCHAR), TRUE);
    if (!*user || !*domain)
    {
        HeapFree(GetProcessHeap(), 0, *user);
        HeapFree(GetProcessHeap(), 0, *domain);
        *user = *domain = NULL;
        ret = SEC_E_INSUFFICIENT_MEMORY;
        goto done;
    }
    memcpy(nt_proof, resp->NtProof, 16);
    memcpy(lm_proof, resp->LmProof, 16);
    memcpy(base_key, resp->SessionBaseKey, 16);
    ret = SEC_E_OK;

done:
    if (resp)
    {
        SecureZeroMemory(resp, resp_len);
        LsaFreeReturnBuffer(resp);
    }
    if (lsa && !NT_SUCCESS(LsaDeregisterLogonProcess(lsa))) NtClose(lsa);
    HeapFree(GetProcessHeap(), 0, req);
    return ret;
}

static SECURITY_STATUS client_authenticate(PNegoHelper h, const BYTE *challenge, ULONG challenge_len, MsgBuf *m)
{
    PNtlmCredentials cred = h->cred;
    const BYTE *target_info = NULL;
    ULONG target_info_len = 0, flags;
    BYTE *av = NULL, *blob = NULL;
    ULONG av_len = 0, blob_len;
    ULONGLONG timestamp = 0;
    BYTE server_challenge[8], client_challenge[8];
    BYTE response_key[16], proof[16], base_key[16], exported[16], enc_key[16];
    BYTE lm_response[24];
    WCHAR workstation[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD ws_len = ARRAYSIZE(workstation);
    SECURITY_STATUS ret = SEC_E_INSUFFICIENT_MEMORY;
    WCHAR *upper, *default_user = NULL, *default_domain = NULL;
    const WCHAR *user_name, *domain_name;
    ULONG ulen, dlen;
    BYTE *nt_response = NULL;
    BOOL key_exch;
    FILETIME ft;

    if (challenge_len < CHALLENGE_HEADER_LEN || memcmp(challenge, ntlm_signature, 8) ||
        get32(challenge + 8) != NTLM_CHALLENGE_MESSAGE)
        return TOKEN_FAIL();
    flags = get32(challenge + 20);
    memcpy(server_challenge, challenge + 24, 8);
    if (!get_field(challenge, challenge_len, 40, &target_info, &target_info_len))
        return TOKEN_FAIL();

    if (!(flags & NTLMSSP_NEGOTIATE_UNICODE) ||
        ((flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)) && !(flags & NTLMSSP_NEGOTIATE_128)))
    {
        FIXME("server does not offer unicode, or 128 bit keys for the session security: 0x%08x\n", flags);
        return SEC_E_UNSUPPORTED_FUNCTION;
    }
    /* what the server did not accept of the sign and seal request is not available */
    if ((h->offered_flags & NTLMSSP_NEGOTIATE_SIGN) && !(flags & NTLMSSP_NEGOTIATE_SIGN))
        return SEC_E_UNSUPPORTED_FUNCTION;
    if ((h->offered_flags & NTLMSSP_NEGOTIATE_SEAL) && !(flags & NTLMSSP_NEGOTIATE_SEAL))
        return SEC_E_UNSUPPORTED_FUNCTION;

    /* what both sides agree on */
    flags &= h->offered_flags & ~NTLMSSP_REQUEST_TARGET;
    key_exch = (flags & NTLMSSP_NEGOTIATE_KEY_EXCHANGE) != 0;

    GetSystemTimeAsFileTime(&ft);
    timestamp = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    if (!build_client_target_info(target_info, target_info_len, &av, &av_len, &timestamp))
        return SEC_E_INSUFFICIENT_MEMORY;

    if (!SystemFunction036(client_challenge, sizeof(client_challenge)))
    {
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }

    /* the blob of the NTLMv2 response */
    blob_len = 28 + av_len + 4 + 4;
    blob = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, blob_len);
    if (!blob) goto done;
    blob[0] = 1;
    blob[1] = 1;
    memcpy(blob + 8, &timestamp, 8);
    memcpy(blob + 16, client_challenge, 8);
    memcpy(blob + 28, av, av_len);
    /* the target info ends in the terminating pair, then four zero bytes */
    put16(blob + 28 + av_len, MSV_AV_EOL);
    put16(blob + 28 + av_len + 2, 0);

    if (cred->has_identity)
    {
        user_name = cred->username;
        domain_name = cred->domain;

        /* ResponseKeyNT = HMAC_MD5(NTOWF, UPPER(user) + domain) */
        ulen = lstrlenW(user_name);
        dlen = lstrlenW(domain_name);
        upper = HeapAlloc(GetProcessHeap(), 0, (ulen + 1) * sizeof(WCHAR));
        if (!upper) goto done;
        memcpy(upper, user_name, (ulen + 1) * sizeof(WCHAR));
        upcase_buffer(upper, ulen);
        hmac_md5(cred->nt_hash, 16, (const BYTE *)upper, ulen * sizeof(WCHAR),
                 (const BYTE *)domain_name, dlen * sizeof(WCHAR), NULL, 0, response_key);
        HeapFree(GetProcessHeap(), 0, upper);

        hmac_md5(response_key, 16, server_challenge, 8, blob, blob_len, NULL, 0, proof);
        hmac_md5(response_key, 16, server_challenge, 8, client_challenge, 8, NULL, 0, lm_response);
        hmac_md5(response_key, 16, proof, 16, NULL, 0, NULL, 0, base_key);
    }
    else
    {
        /* the credentials of the logged on user: the local security authority holds them */
        ret = lsa_default_response(server_challenge, client_challenge, blob, blob_len, &default_user, &default_domain,
                                   proof, lm_response, base_key);
        if (ret != SEC_E_OK) goto done;
        user_name = default_user;
        domain_name = default_domain;
        ulen = lstrlenW(user_name);
        dlen = lstrlenW(domain_name);
    }

    nt_response = HeapAlloc(GetProcessHeap(), 0, 16 + blob_len);
    if (!nt_response) goto done;
    memcpy(nt_response, proof, 16);
    memcpy(nt_response + 16, blob, blob_len);
    memcpy(lm_response + 16, client_challenge, 8);

    if (key_exch)
    {
        if (!SystemFunction036(exported, sizeof(exported))) { ret = SEC_E_INTERNAL_ERROR; goto done; }
        memcpy(enc_key, exported, 16);
        rc4_crypt(base_key, enc_key, 16);
    }
    else
        memcpy(exported, base_key, 16);

    if (!GetComputerNameW(workstation, &ws_len)) ws_len = 0;

    /* AUTHENTICATE */
    if (!msg_reserve(m, AUTH_HEADER_LEN)) goto done;
    m->len = AUTH_HEADER_LEN;
    memcpy(m->data, ntlm_signature, 8);
    put32(m->data + 8, NTLM_AUTHENTICATE_MESSAGE);
    if (!msg_add_field(m, 12, lm_response, sizeof(lm_response)) ||
        !msg_add_field(m, 20, nt_response, 16 + blob_len) ||
        !msg_add_field(m, 28, domain_name, dlen * sizeof(WCHAR)) ||
        !msg_add_field(m, 36, user_name, ulen * sizeof(WCHAR)) ||
        !msg_add_field(m, 44, workstation, ws_len * sizeof(WCHAR)) ||
        !msg_add_field(m, 52, enc_key, key_exch ? 16 : 0))
        goto done;
    put32(m->data + 60, flags);

    /* the MIC covers the three messages, with its own field zero */
    {
        BYTE mic[16];
        HMAC_MD5_CTX ctx;

        HMACMD5Init(&ctx, exported, 16);
        HMACMD5Update(&ctx, h->negotiate_msg, h->negotiate_len);
        HMACMD5Update(&ctx, challenge, challenge_len);
        HMACMD5Update(&ctx, m->data, m->len);
        HMACMD5Final(&ctx, mic);
        memcpy(m->data + AUTH_MIC_OFFSET, mic, 16);
    }

    h->neg_flags = flags;
    ntlm_setup_session(h, exported);
    ret = SEC_E_OK;

done:
    SecureZeroMemory(response_key, sizeof(response_key));
    SecureZeroMemory(base_key, sizeof(base_key));
    SecureZeroMemory(exported, sizeof(exported));
    HeapFree(GetProcessHeap(), 0, av);
    HeapFree(GetProcessHeap(), 0, blob);
    HeapFree(GetProcessHeap(), 0, nt_response);
    HeapFree(GetProcessHeap(), 0, default_user);
    HeapFree(GetProcessHeap(), 0, default_domain);
    return ret;
}

/***********************************************************************
 *              InitializeSecurityContextW
 */
SECURITY_STATUS SEC_ENTRY ntlm_InitializeSecurityContextW(
 PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR *pszTargetName,
 ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput,
 ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput,
 ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;
    PNegoHelper h;
    MsgBuf m = { NULL, 0, 0 };
    ULONG attr = 0;

    TRACE("%p %p %s 0x%08x %d %d %p %d %p %p %p %p\n", phCredential, phContext,
          debugstr_w(pszTargetName), fContextReq, Reserved1, TargetDataRep, pInput,
          Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);

    if (!phNewContext) return SEC_E_INVALID_HANDLE;

    if (!phContext)
    {
        PNtlmCredentials cred;
        const BYTE *unused;
        ULONG unused_len;

        if (!phCredential || !phCredential->dwLower) return SEC_E_INVALID_HANDLE;
        cred = (PNtlmCredentials)phCredential->dwLower;
        if (!(cred->use & SECPKG_CRED_OUTBOUND)) return SEC_E_INVALID_HANDLE;
        if (!pOutput) return SEC_E_BUFFER_TOO_SMALL;
        /* a first call has no input; one that has is a server's message for a context we do not have */
        if (get_input_token(pInput, &unused, &unused_len)) return TOKEN_FAIL();

        h = ntlm_new_context(NTLM_CLIENT, fContextReq);
        if (!h) return SEC_E_INSUFFICIENT_MEMORY;
        h->cred = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*h->cred));
        if (h->cred)
        {
            *h->cred = *cred;
            h->cred->username = dup_identity_string(cred->username, cred->username ? lstrlenW(cred->username) : 0, TRUE);
            h->cred->domain = dup_identity_string(cred->domain, cred->domain ? lstrlenW(cred->domain) : 0, TRUE);
        }
        if (!h->cred || !h->cred->username || !h->cred->domain)
        {
            ntlm_free_context(h);
            return SEC_E_INSUFFICIENT_MEMORY;
        }

        ret = client_negotiate(h, fContextReq, &m);
        if (ret == SEC_E_OK)
        {
            h->negotiate_msg = HeapAlloc(GetProcessHeap(), 0, m.len);
            if (h->negotiate_msg)
            {
                memcpy(h->negotiate_msg, m.data, m.len);
                h->negotiate_len = m.len;
                ret = put_output_token(pOutput, fContextReq, &attr, m.data, m.len);
            }
            else
                ret = SEC_E_INSUFFICIENT_MEMORY;
        }
        if (ret != SEC_E_OK)
        {
            ntlm_free_context(h);
            HeapFree(GetProcessHeap(), 0, m.data);
            return ret;
        }
        phNewContext->dwUpper = 1;
        phNewContext->dwLower = (ULONG_PTR)h;
        HeapFree(GetProcessHeap(), 0, m.data);
        if (pfContextAttr) *pfContextAttr = attr | (fContextReq & ~ISC_REQ_ALLOCATE_MEMORY);
        if (ptsExpiry) { ptsExpiry->LowPart = 0xffffffff; ptsExpiry->HighPart = 0x7fffffff; }
        return SEC_I_CONTINUE_NEEDED;
    }
    else
    {
        const BYTE *token;
        ULONG token_len;

        h = (PNegoHelper)phContext->dwLower;
        if (!h || h->mode != NTLM_CLIENT || h->state != 0) return SEC_E_INVALID_HANDLE;
        if (!get_input_token(pInput, &token, &token_len)) return TOKEN_FAIL();

        ret = client_authenticate(h, token, token_len, &m);
        if (ret == SEC_E_OK)
        {
            ret = put_output_token(pOutput, fContextReq, &attr, m.data, m.len);
        }
        HeapFree(GetProcessHeap(), 0, m.data);
        if (ret != SEC_E_OK) return ret;
        h->state = 1;
        if (phNewContext != phContext)
        {
            phNewContext->dwUpper = phContext->dwUpper;
            phNewContext->dwLower = phContext->dwLower;
        }
        if (pfContextAttr) *pfContextAttr = attr | ntlm_ret_flags(h, FALSE);
        if (ptsExpiry) { ptsExpiry->LowPart = 0xffffffff; ptsExpiry->HighPart = 0x7fffffff; }
        return SEC_E_OK;
    }
}

/***********************************************************************
 *              InitializeSecurityContextA
 */
static SECURITY_STATUS SEC_ENTRY ntlm_InitializeSecurityContextA(
 PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR *pszTargetName,
 ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput,
 ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput,
 ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;
    SEC_WCHAR *target = NULL;

    TRACE("%p %p %s 0x%08x %d %d %p %d %p %p %p %p\n", phCredential, phContext,
          debugstr_a(pszTargetName), fContextReq, Reserved1, TargetDataRep, pInput,
          Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);

    if (pszTargetName)
    {
        int target_size = MultiByteToWideChar(CP_ACP, 0, pszTargetName, -1, NULL, 0);

        target = HeapAlloc(GetProcessHeap(), 0, target_size * sizeof(SEC_WCHAR));
        if (!target) return SEC_E_INSUFFICIENT_MEMORY;
        MultiByteToWideChar(CP_ACP, 0, pszTargetName, -1, target, target_size);
    }

    ret = ntlm_InitializeSecurityContextW(phCredential, phContext, target, fContextReq,
            Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput,
            pfContextAttr, ptsExpiry);

    HeapFree(GetProcessHeap(), 0, target);
    return ret;
}

/***********************************************************************
 * server: CHALLENGE and the check of AUTHENTICATE
 */
static SECURITY_STATUS server_challenge(PNegoHelper h, const BYTE *negotiate, ULONG negotiate_len, MsgBuf *m)
{
    ULONG client_flags, flags;
    WCHAR name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD name_len = ARRAYSIZE(name);
    BYTE av[2 * 4 + 2 * (MAX_COMPUTERNAME_LENGTH * sizeof(WCHAR)) + 12 + 4];
    ULONG av_len = 0, name_bytes;
    FILETIME ft;

    if (negotiate_len < 16 || memcmp(negotiate, ntlm_signature, 8) ||
        get32(negotiate + 8) != NTLM_NEGOTIATE_MESSAGE)
        return TOKEN_FAIL();
    client_flags = get32(negotiate + 12);
    if (!(client_flags & NTLMSSP_NEGOTIATE_UNICODE) || !(client_flags & NTLMSSP_NEGOTIATE_NTLM2) ||
        !(client_flags & NTLMSSP_NEGOTIATE_128))
    {
        FIXME("client does not offer unicode, extended session security and 128 bit keys: 0x%08x\n", client_flags);
        return SEC_E_UNSUPPORTED_FUNCTION;
    }

    flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_NTLM2 |
            NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_TARGET_TYPE_SERVER |
            (client_flags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL |
                             NTLMSSP_NEGOTIATE_KEY_EXCHANGE | NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
                             NTLMSSP_REQUEST_TARGET));

    if (!GetComputerNameW(name, &name_len)) return SEC_E_INTERNAL_ERROR;
    upcase_buffer(name, name_len);
    name_bytes = name_len * sizeof(WCHAR);

    /* the computer is also the domain of a machine that is not a member of one */
    put16(av + av_len, MSV_AV_NB_DOMAIN_NAME); put16(av + av_len + 2, name_bytes);
    memcpy(av + av_len + 4, name, name_bytes); av_len += 4 + name_bytes;
    put16(av + av_len, MSV_AV_NB_COMPUTER_NAME); put16(av + av_len + 2, name_bytes);
    memcpy(av + av_len + 4, name, name_bytes); av_len += 4 + name_bytes;
    GetSystemTimeAsFileTime(&ft);
    put16(av + av_len, MSV_AV_TIMESTAMP); put16(av + av_len + 2, 8);
    put32(av + av_len + 4, ft.dwLowDateTime); put32(av + av_len + 8, ft.dwHighDateTime); av_len += 12;
    put16(av + av_len, MSV_AV_EOL); put16(av + av_len + 2, 0); av_len += 4;

    if (!SystemFunction036(h->server_challenge, sizeof(h->server_challenge))) return SEC_E_INTERNAL_ERROR;

    if (!msg_reserve(m, CHALLENGE_HEADER_LEN)) return SEC_E_INSUFFICIENT_MEMORY;
    m->len = CHALLENGE_HEADER_LEN;
    memcpy(m->data, ntlm_signature, 8);
    put32(m->data + 8, NTLM_CHALLENGE_MESSAGE);
    put32(m->data + 20, flags);
    memcpy(m->data + 24, h->server_challenge, 8);
    if (!msg_add_field(m, 12, (client_flags & NTLMSSP_REQUEST_TARGET) ? (const void *)name : NULL,
                       (client_flags & NTLMSSP_REQUEST_TARGET) ? name_bytes : 0) ||
        !msg_add_field(m, 40, av, av_len))
        return SEC_E_INSUFFICIENT_MEMORY;
    h->offered_flags = flags;
    return SEC_E_OK;
}

static SECURITY_STATUS lsa_status_to_sec(NTSTATUS status)
{
    switch (status)
    {
    case STATUS_INSUFFICIENT_RESOURCES:
    case STATUS_NO_MEMORY:
        return SEC_E_INSUFFICIENT_MEMORY;
    default:
        return SEC_E_LOGON_DENIED;
    }
}

/* a network logon of the user at the local security authority: checks the response and gives the token of the
 * user and the user session key of the response */
static SECURITY_STATUS server_logon(PNegoHelper h, const WCHAR *user, ULONG user_len, const WCHAR *domain,
                                    ULONG domain_len, const WCHAR *workstation, ULONG ws_len,
                                    const BYTE *nt_response, ULONG nt_len, const BYTE *lm_response, ULONG lm_len,
                                    BYTE *session_key)
{
    static const char package_name[] = MSV1_0_PACKAGE_NAME;
    static const char origin_name[] = "NTLMSSP";
    MSV1_0_LM20_LOGON *logon;
    ULONG size, off;
    BYTE *buf;
    HANDLE lsa = NULL, token = NULL;
    LSA_STRING origin, package;
    TOKEN_SOURCE source;
    ULONG package_id;
    void *profile = NULL;
    ULONG profile_len = 0;
    LUID luid;
    QUOTA_LIMITS quotas;
    NTSTATUS status, substatus = 0;
    SECURITY_STATUS ret;

    size = sizeof(*logon) + user_len + domain_len + ws_len + nt_len + lm_len;
    buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!buf) return SEC_E_INSUFFICIENT_MEMORY;
    logon = (MSV1_0_LM20_LOGON *)buf;
    off = sizeof(*logon);

    logon->MessageType = MsV1_0Lm20Logon;
    memcpy(logon->ChallengeToClient, h->server_challenge, 8);
    logon->ParameterControl = MSV1_0_RETURN_PROFILE_PATH;

#define ADD_STR(field, src, len) \
    do { *(void **)&logon->field.Buffer = buf + off; logon->field.Length = logon->field.MaximumLength = (USHORT)(len); \
         memcpy(buf + off, src, len); off += len; } while (0)
    ADD_STR(UserName, user, user_len);
    ADD_STR(LogonDomainName, domain, domain_len);
    ADD_STR(Workstation, workstation, ws_len);
    ADD_STR(CaseSensitiveChallengeResponse, nt_response, nt_len);
    ADD_STR(CaseInsensitiveChallengeResponse, lm_response, lm_len);
#undef ADD_STR

    status = LsaConnectUntrusted(&lsa);
    if (!NT_SUCCESS(status))
    {
        ERR("LsaConnectUntrusted failed with 0x%08x\n", status);
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }
    package.Buffer = (PCHAR)package_name;
    package.Length = sizeof(package_name) - 1;
    package.MaximumLength = sizeof(package_name);
    status = LsaLookupAuthenticationPackage(lsa, &package, &package_id);
    if (!NT_SUCCESS(status))
    {
        ERR("LsaLookupAuthenticationPackage failed with 0x%08x\n", status);
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }

    origin.Buffer = (PCHAR)origin_name;
    origin.Length = sizeof(origin_name) - 1;
    origin.MaximumLength = sizeof(origin_name);
    memcpy(source.SourceName, "NTLMSSP ", 8);
    AllocateLocallyUniqueId(&source.SourceIdentifier);

    status = LsaLogonUser(lsa, &origin, Network, package_id, buf, size, NULL, &source,
                          &profile, &profile_len, &luid, &token, &quotas, &substatus);
    if (!NT_SUCCESS(status))
    {
        WARN("network logon failed with 0x%08x (0x%08x)\n", status, substatus);
        ret = lsa_status_to_sec(status);
        goto done;
    }
    if (!profile || profile_len < sizeof(MSV1_0_LM20_LOGON_PROFILE))
    {
        ERR("no profile for the logon\n");
        CloseHandle(token);
        ret = SEC_E_INTERNAL_ERROR;
        goto done;
    }
    memcpy(session_key, ((MSV1_0_LM20_LOGON_PROFILE *)profile)->UserSessionKey, 16);
    h->token = token;
    ret = SEC_E_OK;

done:
    if (profile) LsaFreeReturnBuffer(profile);
    if (lsa && !NT_SUCCESS(LsaDeregisterLogonProcess(lsa))) NtClose(lsa);
    HeapFree(GetProcessHeap(), 0, buf);
    return ret;
}

static SECURITY_STATUS server_authenticate(PNegoHelper h, const BYTE *msg, ULONG msg_len)
{
    const BYTE *lm, *nt, *domain, *user, *workstation, *enc_key;
    ULONG lm_len, nt_len, domain_len, user_len, ws_len, enc_len;
    ULONG flags, pos, first_payload;
    BYTE session_base[16], exported[16];
    BOOL mic_required = FALSE;
    SECURITY_STATUS ret;
    WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computer_len = ARRAYSIZE(computer);

    if (msg_len < AUTH_HEADER_NO_MIC || memcmp(msg, ntlm_signature, 8) ||
        get32(msg + 8) != NTLM_AUTHENTICATE_MESSAGE)
        return TOKEN_FAIL();
    if (!get_field(msg, msg_len, 12, &lm, &lm_len) || !get_field(msg, msg_len, 20, &nt, &nt_len) ||
        !get_field(msg, msg_len, 28, &domain, &domain_len) || !get_field(msg, msg_len, 36, &user, &user_len) ||
        !get_field(msg, msg_len, 44, &workstation, &ws_len) || !get_field(msg, msg_len, 52, &enc_key, &enc_len))
        return TOKEN_FAIL();
    flags = get32(msg + 60);

    /* the header ends where the first payload starts (the shorter forms have no MIC) */
    first_payload = msg_len;
    for (pos = 12; pos <= 52; pos += 8)
    {
        ULONG l = get16(msg + pos), off = get32(msg + pos + 4);
        if (l && off < first_payload) first_payload = off;
    }

    /* the flags of the exchange must be what the server offered */
    if ((flags & ~(h->offered_flags | NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_TARGET_TYPE_SERVER |
                   NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED |
                   NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED | NTLMSSP_NEGOTIATE_ANONYMOUS |
                   NTLMSSP_NEGOTIATE_IDENTIFY)) ||
        !(flags & NTLMSSP_NEGOTIATE_UNICODE) || !(flags & NTLMSSP_NEGOTIATE_NTLM2))
        return TOKEN_FAIL();

    if (user_len == 0 || nt_len == 0)
    {
        /* an anonymous session is not offered */
        WARN("no user or no response: anonymous logon refused\n");
        return SEC_E_LOGON_DENIED;
    }
    if ((user_len & 1) || (domain_len & 1) || (ws_len & 1)) return TOKEN_FAIL();

    /* the response says whether the client sent a MIC: its target info has the flags pair */
    if (nt_len >= 16 + 28 + 4)
    {
        const BYTE *av = nt + 16 + 28;
        ULONG av_len = nt_len - 16 - 28, p = 0;

        while (p + 4 <= av_len)
        {
            ULONG id = get16(av + p), l = get16(av + p + 2);

            if (id == MSV_AV_EOL || l > av_len - p - 4) break;
            if (id == MSV_AV_FLAGS && l == 4 && (get32(av + p + 4) & MSV_AV_FLAG_MIC))
                mic_required = TRUE;
            p += 4 + l;
        }
    }
    if (mic_required && (first_payload < AUTH_HEADER_LEN || msg_len < AUTH_HEADER_LEN))
        return TOKEN_FAIL();

    if ((flags & NTLMSSP_NEGOTIATE_KEY_EXCHANGE) && enc_len != 16) return TOKEN_FAIL();
    if (!(flags & NTLMSSP_NEGOTIATE_KEY_EXCHANGE) && enc_len != 0) return TOKEN_FAIL();

    ret = server_logon(h, (const WCHAR *)user, user_len, (const WCHAR *)domain, domain_len,
                       (const WCHAR *)workstation, ws_len, nt, nt_len, lm, lm_len, session_base);
    if (ret != SEC_E_OK) return ret;

    if (flags & NTLMSSP_NEGOTIATE_KEY_EXCHANGE)
    {
        memcpy(exported, enc_key, 16);
        rc4_crypt(session_base, exported, 16);
    }
    else
        memcpy(exported, session_base, 16);
    SecureZeroMemory(session_base, sizeof(session_base));

    if (mic_required)
    {
        BYTE mic[16], zero_mic[16] = { 0 };
        HMAC_MD5_CTX ctx;
        BYTE diff = 0;
        ULONG i;

        HMACMD5Init(&ctx, exported, 16);
        HMACMD5Update(&ctx, h->negotiate_msg, h->negotiate_len);
        HMACMD5Update(&ctx, h->challenge_msg, h->challenge_len);
        HMACMD5Update(&ctx, msg, AUTH_MIC_OFFSET);
        HMACMD5Update(&ctx, zero_mic, 16);
        HMACMD5Update(&ctx, msg + AUTH_MIC_OFFSET + 16, msg_len - AUTH_MIC_OFFSET - 16);
        HMACMD5Final(&ctx, mic);
        for (i = 0; i < 16; i++) diff |= mic[i] ^ msg[AUTH_MIC_OFFSET + i];
        if (diff)
        {
            WARN("MIC mismatch\n");
            SecureZeroMemory(exported, sizeof(exported));
            return SEC_E_MESSAGE_ALTERED;
        }
    }

    /* user and domain as the client gave them; the machine's own name stands for an empty or local domain */
    h->user_name = dup_identity_string(user, user_len / sizeof(WCHAR), TRUE);
    if (domain_len == 0 || (domain_len == 2 && ((const WCHAR *)domain)[0] == '.'))
    {
        if (GetComputerNameW(computer, &computer_len))
            h->domain_name = dup_identity_string(computer, computer_len, TRUE);
    }
    else
        h->domain_name = dup_identity_string(domain, domain_len / sizeof(WCHAR), TRUE);
    if (!h->user_name || !h->domain_name)
    {
        SecureZeroMemory(exported, sizeof(exported));
        return SEC_E_INSUFFICIENT_MEMORY;
    }

    h->neg_flags = flags & h->offered_flags;
    ntlm_setup_session(h, exported);
    SecureZeroMemory(exported, sizeof(exported));
    return SEC_E_OK;
}

/***********************************************************************
 *              AcceptSecurityContext
 */
SECURITY_STATUS SEC_ENTRY ntlm_AcceptSecurityContext(
 PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput,
 ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext,
 PSecBufferDesc pOutput, ULONG *pfContextAttr, PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;
    PNegoHelper h;
    const BYTE *token;
    ULONG token_len, attr = 0;

    TRACE("%p %p %p 0x%08x 0x%08x %p %p %p %p\n", phCredential, phContext, pInput,
          fContextReq, TargetDataRep, phNewContext, pOutput, pfContextAttr, ptsExpiry);

    if (!phNewContext) return SEC_E_INVALID_HANDLE;
    if (!phContext && (!phCredential || !phCredential->dwLower)) return SEC_E_INVALID_HANDLE;
    if (!get_input_token(pInput, &token, &token_len)) return TOKEN_FAIL();

    if (!phContext)
    {
        PNtlmCredentials cred = (PNtlmCredentials)phCredential->dwLower;
        MsgBuf m = { NULL, 0, 0 };

        if (!(cred->use & SECPKG_CRED_INBOUND)) return SEC_E_INVALID_HANDLE;
        if (!pOutput) return TOKEN_FAIL();

        h = ntlm_new_context(NTLM_SERVER, fContextReq);
        if (!h) return SEC_E_INSUFFICIENT_MEMORY;

        ret = server_challenge(h, token, token_len, &m);
        if (ret == SEC_E_OK)
        {
            h->negotiate_msg = HeapAlloc(GetProcessHeap(), 0, token_len);
            h->challenge_msg = HeapAlloc(GetProcessHeap(), 0, m.len);
            if (h->negotiate_msg && h->challenge_msg)
            {
                memcpy(h->negotiate_msg, token, token_len);
                h->negotiate_len = token_len;
                memcpy(h->challenge_msg, m.data, m.len);
                h->challenge_len = m.len;
                ret = put_output_token(pOutput, fContextReq, &attr, m.data, m.len);
            }
            else
                ret = SEC_E_INSUFFICIENT_MEMORY;
        }
        HeapFree(GetProcessHeap(), 0, m.data);
        if (ret != SEC_E_OK)
        {
            ntlm_free_context(h);
            return ret;
        }
        phNewContext->dwUpper = 1;
        phNewContext->dwLower = (ULONG_PTR)h;
        if (pfContextAttr) *pfContextAttr = attr | (fContextReq & ~ASC_REQ_ALLOCATE_MEMORY);
        if (ptsExpiry) { ptsExpiry->LowPart = 0xffffffff; ptsExpiry->HighPart = 0x7fffffff; }
        return SEC_I_CONTINUE_NEEDED;
    }

    h = (PNegoHelper)phContext->dwLower;
    if (!h || h->mode != NTLM_SERVER || h->state != 0) return SEC_E_INVALID_HANDLE;

    ret = server_authenticate(h, token, token_len);
    if (ret != SEC_E_OK) return ret;
    h->state = 1;
    if (phNewContext != phContext)
    {
        phNewContext->dwUpper = phContext->dwUpper;
        phNewContext->dwLower = phContext->dwLower;
    }
    /* the exchange is complete: nothing goes back to the client */
    if (pOutput && pOutput->pBuffers)
    {
        int idx = ntlm_GetTokenBufferIndex(pOutput);
        if (idx != -1) pOutput->pBuffers[idx].cbBuffer = 0;
    }
    if (pfContextAttr) *pfContextAttr = ntlm_ret_flags(h, TRUE);
    if (ptsExpiry) { ptsExpiry->LowPart = 0xffffffff; ptsExpiry->HighPart = 0x7fffffff; }
    return SEC_E_OK;
}

/***********************************************************************
 *              CompleteAuthToken
 */
static SECURITY_STATUS SEC_ENTRY ntlm_CompleteAuthToken(PCtxtHandle phContext,
 PSecBufferDesc pToken)
{
    /* We never need to call CompleteAuthToken anyway */
    TRACE("%p %p\n", phContext, pToken);
    if (!phContext)
        return SEC_E_INVALID_HANDLE;

    return SEC_E_OK;
}

/***********************************************************************
 *              DeleteSecurityContext
 */
SECURITY_STATUS SEC_ENTRY ntlm_DeleteSecurityContext(PCtxtHandle phContext)
{
    PNegoHelper helper;

    TRACE("%p\n", phContext);
    if (!phContext)
        return SEC_E_INVALID_HANDLE;

    helper = (PNegoHelper)phContext->dwLower;

    phContext->dwUpper = 0;
    phContext->dwLower = 0;

    ntlm_free_context(helper);
    return SEC_E_OK;
}

/* a string for the caller to release with FreeContextBuffer */
static SECURITY_STATUS alloc_string_w(const WCHAR *src, WCHAR **dst)
{
    *dst = HeapAlloc(GetProcessHeap(), 0, (lstrlenW(src) + 1) * sizeof(WCHAR));
    if (!*dst) return SEC_E_INSUFFICIENT_MEMORY;
    lstrcpyW(*dst, src);
    return SEC_E_OK;
}

/* a copy of the package info for the caller to release with FreeContextBuffer: one block, the strings behind
 * the structure */
SecPkgInfoW *ntlm_copy_package_infoW(void)
{
    ULONG name_size = (lstrlenW(ntlm_package_infoW->Name) + 1) * sizeof(WCHAR);
    ULONG comment_size = (lstrlenW(ntlm_package_infoW->Comment) + 1) * sizeof(WCHAR);
    SecPkgInfoW *info = HeapAlloc(GetProcessHeap(), 0, sizeof(*info) + name_size + comment_size);

    if (!info) return NULL;
    *info = *ntlm_package_infoW;
    info->Name = (SEC_WCHAR *)(info + 1);
    memcpy(info->Name, ntlm_package_infoW->Name, name_size);
    info->Comment = (SEC_WCHAR *)((BYTE *)info->Name + name_size);
    memcpy(info->Comment, ntlm_package_infoW->Comment, comment_size);
    return info;
}

SecPkgInfoA *ntlm_copy_package_infoA(void)
{
    ULONG name_size = lstrlenA(ntlm_package_infoA->Name) + 1;
    ULONG comment_size = lstrlenA(ntlm_package_infoA->Comment) + 1;
    SecPkgInfoA *info = HeapAlloc(GetProcessHeap(), 0, sizeof(*info) + name_size + comment_size);

    if (!info) return NULL;
    *info = *ntlm_package_infoA;
    info->Name = (SEC_CHAR *)(info + 1);
    memcpy(info->Name, ntlm_package_infoA->Name, name_size);
    info->Comment = info->Name + name_size;
    memcpy(info->Comment, ntlm_package_infoA->Comment, comment_size);
    return info;
}

/***********************************************************************
 *              QueryContextAttributesW
 */
SECURITY_STATUS SEC_ENTRY ntlm_QueryContextAttributesW(PCtxtHandle phContext,
 ULONG ulAttribute, void *pBuffer)
{
    PNegoHelper helper;

    TRACE("%p %d %p\n", phContext, ulAttribute, pBuffer);
    if (!phContext)
        return SEC_E_INVALID_HANDLE;
    helper = (PNegoHelper)phContext->dwLower;
    if (!helper)
        return SEC_E_INVALID_HANDLE;

    switch(ulAttribute)
    {
        case SECPKG_ATTR_ACCESS_TOKEN:
        {
            PSecPkgContext_AccessToken spat = pBuffer;

            if (!helper->token) return SEC_E_NO_IMPERSONATION;
            /* the token stays with the context */
            spat->AccessToken = helper->token;
            return SEC_E_OK;
        }
        case SECPKG_ATTR_FLAGS:
        {
            PSecPkgContext_Flags spcf = (PSecPkgContext_Flags)pBuffer;

            spcf->Flags = 0;
            if(helper->neg_flags & NTLMSSP_NEGOTIATE_SIGN)
                spcf->Flags |= ISC_RET_INTEGRITY;
            if(helper->neg_flags & NTLMSSP_NEGOTIATE_SEAL)
                spcf->Flags |= ISC_RET_CONFIDENTIALITY;
            return SEC_E_OK;
        }
        case SECPKG_ATTR_NAMES:
        {
            PSecPkgContext_NamesW names = pBuffer;
            WCHAR *full;
            SECURITY_STATUS ret;

            if (helper->mode != NTLM_SERVER || !helper->user_name || !helper->domain_name)
            {
                if (helper->mode == NTLM_CLIENT && helper->cred && helper->cred->username)
                {
                    /* the user of the credentials */
                    return alloc_string_w(helper->cred->username, &names->sUserName);
                }
                return SEC_E_UNSUPPORTED_FUNCTION;
            }
            full = HeapAlloc(GetProcessHeap(), 0,
                             (lstrlenW(helper->domain_name) + 1 + lstrlenW(helper->user_name) + 1) * sizeof(WCHAR));
            if (!full) return SEC_E_INSUFFICIENT_MEMORY;
            lstrcpyW(full, helper->domain_name);
            lstrcatW(full, L"\\");
            lstrcatW(full, helper->user_name);
            ret = alloc_string_w(full, &names->sUserName);
            HeapFree(GetProcessHeap(), 0, full);
            return ret;
        }
        case SECPKG_ATTR_PACKAGE_INFO:
        {
            PSecPkgContext_PackageInfoW info = pBuffer;

            info->PackageInfo = ntlm_copy_package_infoW();
            return info->PackageInfo ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
        }
        case SECPKG_ATTR_NEGOTIATION_INFO:
        {
            PSecPkgContext_NegotiationInfoW info = pBuffer;

            info->PackageInfo = ntlm_copy_package_infoW();
            info->NegotiationState = SECPKG_NEGOTIATION_COMPLETE;
            return info->PackageInfo ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
        }
        case SECPKG_ATTR_SESSION_KEY:
        {
            PSecPkgContext_SessionKey sk = pBuffer;

            if (!helper->session_key) return SEC_E_INVALID_HANDLE;
            sk->SessionKey = HeapAlloc(GetProcessHeap(), 0, 16);
            if (!sk->SessionKey) return SEC_E_INSUFFICIENT_MEMORY;
            memcpy(sk->SessionKey, helper->session_key, 16);
            sk->SessionKeyLength = 16;
            return SEC_E_OK;
        }
        case SECPKG_ATTR_SIZES:
        {
            PSecPkgContext_Sizes spcs = (PSecPkgContext_Sizes)pBuffer;
            spcs->cbMaxToken = NTLM_MAX_BUF;
            spcs->cbMaxSignature = 16;
            spcs->cbBlockSize = 0;
            spcs->cbSecurityTrailer = 16;
            return SEC_E_OK;
        }
        case SECPKG_ATTR_AUTHORITY:
        case SECPKG_ATTR_DCE_INFO:
        case SECPKG_ATTR_KEY_INFO:
        case SECPKG_ATTR_LIFESPAN:
        case SECPKG_ATTR_NATIVE_NAMES:
        case SECPKG_ATTR_PASSWORD_EXPIRY:
        case SECPKG_ATTR_STREAM_SIZES:
        case SECPKG_ATTR_TARGET_INFORMATION:
            FIXME("attribute %u is not implemented\n", ulAttribute);
            break;
        default:
            TRACE("Unknown value %d passed for ulAttribute\n", ulAttribute);
    }

    return SEC_E_UNSUPPORTED_FUNCTION;
}

/***********************************************************************
 *              QueryContextAttributesA
 */
SECURITY_STATUS SEC_ENTRY ntlm_QueryContextAttributesA(PCtxtHandle phContext,
 ULONG ulAttribute, void *pBuffer)
{
    SECURITY_STATUS ret;

    if (ulAttribute == SECPKG_ATTR_NAMES || ulAttribute == SECPKG_ATTR_PACKAGE_INFO)
    {
        /* the structures of the ANSI forms hold ANSI strings */
        if (ulAttribute == SECPKG_ATTR_NAMES)
        {
            SecPkgContext_NamesW namesW = { NULL };
            SecPkgContext_NamesA *namesA = pBuffer;
            int len;

            ret = ntlm_QueryContextAttributesW(phContext, ulAttribute, &namesW);
            if (ret != SEC_E_OK) return ret;
            len = WideCharToMultiByte(CP_ACP, 0, namesW.sUserName, -1, NULL, 0, NULL, NULL);
            namesA->sUserName = HeapAlloc(GetProcessHeap(), 0, len);
            if (!namesA->sUserName) ret = SEC_E_INSUFFICIENT_MEMORY;
            else WideCharToMultiByte(CP_ACP, 0, namesW.sUserName, -1, namesA->sUserName, len, NULL, NULL);
            HeapFree(GetProcessHeap(), 0, namesW.sUserName);
            return ret;
        }
        else
        {
            PSecPkgContext_PackageInfoA info = pBuffer;

            info->PackageInfo = ntlm_copy_package_infoA();
            return info->PackageInfo ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
        }
    }
    if (ulAttribute == SECPKG_ATTR_NEGOTIATION_INFO)
    {
        PSecPkgContext_NegotiationInfoA info = pBuffer;

        if (!phContext || !phContext->dwLower) return SEC_E_INVALID_HANDLE;
        info->PackageInfo = ntlm_copy_package_infoA();
        info->NegotiationState = SECPKG_NEGOTIATION_COMPLETE;
        return info->PackageInfo ? SEC_E_OK : SEC_E_INSUFFICIENT_MEMORY;
    }
    return ntlm_QueryContextAttributesW(phContext, ulAttribute, pBuffer);
}

/***********************************************************************
 *              ImpersonateSecurityContext
 */
SECURITY_STATUS SEC_ENTRY ntlm_ImpersonateSecurityContext(PCtxtHandle phContext)
{
    PNegoHelper helper;

    TRACE("%p\n", phContext);
    if (!phContext || !phContext->dwLower)
        return SEC_E_INVALID_HANDLE;
    helper = (PNegoHelper)phContext->dwLower;
    /* only the server side of an exchange has the token of the client */
    if (helper->mode != NTLM_SERVER || !helper->token)
        return SEC_E_NO_IMPERSONATION;
    if (!SetThreadToken(NULL, helper->token))
        return SEC_E_INTERNAL_ERROR;
    return SEC_E_OK;
}

/***********************************************************************
 *              RevertSecurityContext
 */
SECURITY_STATUS SEC_ENTRY ntlm_RevertSecurityContext(PCtxtHandle phContext)
{
    PNegoHelper helper;

    TRACE("%p\n", phContext);
    if (!phContext || !phContext->dwLower)
        return SEC_E_INVALID_HANDLE;
    helper = (PNegoHelper)phContext->dwLower;
    if (helper->mode != NTLM_SERVER || !helper->token)
        return SEC_E_NO_IMPERSONATION;
    if (!SetThreadToken(NULL, NULL))
        return SEC_E_INTERNAL_ERROR;
    return SEC_E_OK;
}

/***********************************************************************
 *              QuerySecurityContextToken
 */
SECURITY_STATUS SEC_ENTRY ntlm_QuerySecurityContextToken(PCtxtHandle phContext, HANDLE *Token)
{
    PNegoHelper helper;

    TRACE("%p %p\n", phContext, Token);
    if (!phContext || !phContext->dwLower || !Token)
        return SEC_E_INVALID_HANDLE;
    helper = (PNegoHelper)phContext->dwLower;
    if (helper->mode != NTLM_SERVER || !helper->token)
        return SEC_E_INVALID_HANDLE;
    if (!DuplicateHandle(GetCurrentProcess(), helper->token, GetCurrentProcess(), Token, 0, FALSE,
                         DUPLICATE_SAME_ACCESS))
        return SEC_E_INTERNAL_ERROR;
    return SEC_E_OK;
}

/***********************************************************************
 *             ntlm_CreateSignature
 * As both MakeSignature and VerifySignature need this, but different keys
 * are needed for NTLM2, the logic goes into a helper function.
 * To ensure maximal reusability, we can specify the direction as NTLM_SEND for
 * signing/encrypting and NTLM_RECV for verifying/decrypting. When encrypting,
 * the signature is encrypted after the message was encrypted, so
 * CreateSignature shouldn't do it. In this case, encrypt_sig can be set to
 * false.
 */
static SECURITY_STATUS ntlm_CreateSignature(PNegoHelper helper, PSecBufferDesc pMessage,
        int token_idx, SignDirection direction, BOOL encrypt_sig)
{
    ULONG sign_version = 1;
    UINT i;
    PBYTE sig;
    TRACE("%p, %p, %d, %d, %d\n", helper, pMessage, token_idx, direction,
            encrypt_sig);

    sig = pMessage->pBuffers[token_idx].pvBuffer;

    if(helper->neg_flags & NTLMSSP_NEGOTIATE_NTLM2 &&
            helper->neg_flags & NTLMSSP_NEGOTIATE_SIGN)
    {
        BYTE digest[16];
        BYTE seq_no[4];
        HMAC_MD5_CTX hmac_md5_ctx;

        TRACE("Signing NTLM2 style\n");

        if(direction == NTLM_SEND)
        {
            seq_no[0] = (helper->crypt.ntlm2.send_seq_no >>  0) & 0xff;
            seq_no[1] = (helper->crypt.ntlm2.send_seq_no >>  8) & 0xff;
            seq_no[2] = (helper->crypt.ntlm2.send_seq_no >> 16) & 0xff;
            seq_no[3] = (helper->crypt.ntlm2.send_seq_no >> 24) & 0xff;

            ++(helper->crypt.ntlm2.send_seq_no);

            HMACMD5Init(&hmac_md5_ctx, helper->crypt.ntlm2.send_sign_key, 16);
        }
        else
        {
            seq_no[0] = (helper->crypt.ntlm2.recv_seq_no >>  0) & 0xff;
            seq_no[1] = (helper->crypt.ntlm2.recv_seq_no >>  8) & 0xff;
            seq_no[2] = (helper->crypt.ntlm2.recv_seq_no >> 16) & 0xff;
            seq_no[3] = (helper->crypt.ntlm2.recv_seq_no >> 24) & 0xff;

            ++(helper->crypt.ntlm2.recv_seq_no);

            HMACMD5Init(&hmac_md5_ctx, helper->crypt.ntlm2.recv_sign_key, 16);
        }

        HMACMD5Update(&hmac_md5_ctx, seq_no, 4);
        for( i = 0; i < pMessage->cBuffers; ++i )
        {
            if(pMessage->pBuffers[i].BufferType & SECBUFFER_DATA)
                HMACMD5Update(&hmac_md5_ctx, pMessage->pBuffers[i].pvBuffer,
                        pMessage->pBuffers[i].cbBuffer);
        }

        HMACMD5Final(&hmac_md5_ctx, digest);

        if(encrypt_sig && helper->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCHANGE)
        {
            if(direction == NTLM_SEND)
                SECUR32_arc4Process(helper->crypt.ntlm2.send_a4i, digest, 8);
            else
                SECUR32_arc4Process(helper->crypt.ntlm2.recv_a4i, digest, 8);
        }

        /* The NTLM2 signature is the sign version */
        sig[ 0] = (sign_version >>  0) & 0xff;
        sig[ 1] = (sign_version >>  8) & 0xff;
        sig[ 2] = (sign_version >> 16) & 0xff;
        sig[ 3] = (sign_version >> 24) & 0xff;
        /* The first 8 bytes of the digest */
        memcpy(sig+4, digest, 8);
        /* And the sequence number */
        memcpy(sig+12, seq_no, 4);

        pMessage->pBuffers[token_idx].cbBuffer = 16;

        return SEC_E_OK;
    }
    if(helper->neg_flags & NTLMSSP_NEGOTIATE_SIGN)
    {
        ULONG crc = 0U;
        TRACE("Signing NTLM1 style\n");

        for(i=0; i < pMessage->cBuffers; ++i)
        {
            if(pMessage->pBuffers[i].BufferType & SECBUFFER_DATA)
            {
                crc = ComputeCrc32(pMessage->pBuffers[i].pvBuffer,
                    pMessage->pBuffers[i].cbBuffer, crc);
            }
        }

        sig[ 0] = (sign_version >>  0) & 0xff;
        sig[ 1] = (sign_version >>  8) & 0xff;
        sig[ 2] = (sign_version >> 16) & 0xff;
        sig[ 3] = (sign_version >> 24) & 0xff;
        memset(sig+4, 0, 4);
        sig[ 8] = (crc >>  0) & 0xff;
        sig[ 9] = (crc >>  8) & 0xff;
        sig[10] = (crc >> 16) & 0xff;
        sig[11] = (crc >> 24) & 0xff;
        sig[12] = (helper->crypt.ntlm.seq_num >>  0) & 0xff;
        sig[13] = (helper->crypt.ntlm.seq_num >>  8) & 0xff;
        sig[14] = (helper->crypt.ntlm.seq_num >> 16) & 0xff;
        sig[15] = (helper->crypt.ntlm.seq_num >> 24) & 0xff;

        ++(helper->crypt.ntlm.seq_num);

        if(encrypt_sig)
            SECUR32_arc4Process(helper->crypt.ntlm.a4i, sig+4, 12);
        return SEC_E_OK;
    }

    if(helper->neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN || helper->neg_flags == 0)
    {
        TRACE("Creating a dummy signature.\n");
        /* A dummy signature is 0x01 followed by 15 bytes of 0x00 */
        memset(pMessage->pBuffers[token_idx].pvBuffer, 0, 16);
        memset(pMessage->pBuffers[token_idx].pvBuffer, 0x01, 1);
        pMessage->pBuffers[token_idx].cbBuffer = 16;
        return SEC_E_OK;
    }

    return SEC_E_UNSUPPORTED_FUNCTION;
}

/***********************************************************************
 *              MakeSignature
 */
SECURITY_STATUS SEC_ENTRY ntlm_MakeSignature(PCtxtHandle phContext,
    ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
    PNegoHelper helper;
    int token_idx;

    TRACE("%p %d %p %d\n", phContext, fQOP, pMessage, MessageSeqNo);
    if (!phContext)
        return SEC_E_INVALID_HANDLE;

    if(fQOP)
        FIXME("Ignoring fQOP 0x%08x\n", fQOP);

    if(MessageSeqNo)
        FIXME("Ignoring MessageSeqNo\n");

    if(!pMessage || !pMessage->pBuffers || pMessage->cBuffers < 2)
        return TOKEN_FAIL();

    /* If we didn't find a SECBUFFER_TOKEN type buffer */
    if((token_idx = ntlm_GetTokenBufferIndex(pMessage)) == -1)
        return TOKEN_FAIL();

    if(pMessage->pBuffers[token_idx].cbBuffer < 16)
        return SEC_E_BUFFER_TOO_SMALL;

    helper = (PNegoHelper)phContext->dwLower;
    TRACE("Negotiated flags are: 0x%08x\n", helper->neg_flags);

    return ntlm_CreateSignature(helper, pMessage, token_idx, NTLM_SEND, TRUE);
}

/***********************************************************************
 *              VerifySignature
 */
SECURITY_STATUS SEC_ENTRY ntlm_VerifySignature(PCtxtHandle phContext,
    PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
    PNegoHelper helper;
    UINT i;
    int token_idx;
    SECURITY_STATUS ret;
    SecBufferDesc local_desc;
    PSecBuffer     local_buff;
    BYTE          local_sig[16];

    TRACE("%p %p %d %p\n", phContext, pMessage, MessageSeqNo, pfQOP);
    if(!phContext)
        return SEC_E_INVALID_HANDLE;

    if(!pMessage || !pMessage->pBuffers || pMessage->cBuffers < 2)
        return TOKEN_FAIL();

    if((token_idx = ntlm_GetTokenBufferIndex(pMessage)) == -1)
        return TOKEN_FAIL();

    if(pMessage->pBuffers[token_idx].cbBuffer < 16)
        return SEC_E_BUFFER_TOO_SMALL;

    if(MessageSeqNo)
        FIXME("Ignoring MessageSeqNo\n");

    helper = (PNegoHelper)phContext->dwLower;
    TRACE("Negotiated flags: 0x%08x\n", helper->neg_flags);

    local_buff = HeapAlloc(GetProcessHeap(), 0, pMessage->cBuffers * sizeof(SecBuffer));

    local_desc.ulVersion = SECBUFFER_VERSION;
    local_desc.cBuffers = pMessage->cBuffers;
    local_desc.pBuffers = local_buff;

    for(i=0; i < pMessage->cBuffers; ++i)
    {
        if(pMessage->pBuffers[i].BufferType == SECBUFFER_TOKEN)
        {
            local_buff[i].BufferType = SECBUFFER_TOKEN;
            local_buff[i].cbBuffer = 16;
            local_buff[i].pvBuffer = local_sig;
        }
        else
        {
            local_buff[i].BufferType = pMessage->pBuffers[i].BufferType;
            local_buff[i].cbBuffer = pMessage->pBuffers[i].cbBuffer;
            local_buff[i].pvBuffer = pMessage->pBuffers[i].pvBuffer;
        }
    }

    if((ret = ntlm_CreateSignature(helper, &local_desc, token_idx, NTLM_RECV, TRUE)) != SEC_E_OK)
        return ret;

    if(memcmp(((PBYTE)local_buff[token_idx].pvBuffer) + 8,
                ((PBYTE)pMessage->pBuffers[token_idx].pvBuffer) + 8, 8))
        ret = SEC_E_MESSAGE_ALTERED;
    else
        ret = SEC_E_OK;

    HeapFree(GetProcessHeap(), 0, local_buff);

    return ret;

}

/***********************************************************************
 *             EncryptMessage
 */
SECURITY_STATUS SEC_ENTRY ntlm_EncryptMessage(PCtxtHandle phContext,
    ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
    PNegoHelper helper;
    int token_idx, data_idx;

    TRACE("(%p %d %p %d)\n", phContext, fQOP, pMessage, MessageSeqNo);

    if(!phContext)
        return SEC_E_INVALID_HANDLE;

    if(fQOP)
        FIXME("Ignoring fQOP\n");

    if(MessageSeqNo)
        FIXME("Ignoring MessageSeqNo\n");

    if(!pMessage || !pMessage->pBuffers || pMessage->cBuffers < 2)
        return TOKEN_FAIL();

    if((token_idx = ntlm_GetTokenBufferIndex(pMessage)) == -1)
        return TOKEN_FAIL();

    if((data_idx = ntlm_GetDataBufferIndex(pMessage)) ==-1 )
        return TOKEN_FAIL();

    if(pMessage->pBuffers[token_idx].cbBuffer < 16)
        return SEC_E_BUFFER_TOO_SMALL;

    helper = (PNegoHelper) phContext->dwLower;

    if(helper->neg_flags & NTLMSSP_NEGOTIATE_NTLM2 && 
            helper->neg_flags & NTLMSSP_NEGOTIATE_SEAL)
    { 
        ntlm_CreateSignature(helper, pMessage, token_idx, NTLM_SEND, FALSE);
        SECUR32_arc4Process(helper->crypt.ntlm2.send_a4i,
                pMessage->pBuffers[data_idx].pvBuffer,
                pMessage->pBuffers[data_idx].cbBuffer);

        if(helper->neg_flags & NTLMSSP_NEGOTIATE_KEY_EXCHANGE)
            SECUR32_arc4Process(helper->crypt.ntlm2.send_a4i,
                    ((BYTE *)pMessage->pBuffers[token_idx].pvBuffer)+4, 8);
    }
    else
    {
        PBYTE sig;
        ULONG save_flags;

        /* EncryptMessage always produces real signatures, so make sure
         * NTLMSSP_NEGOTIATE_SIGN is set*/
        save_flags = helper->neg_flags;
        helper->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
        ntlm_CreateSignature(helper, pMessage, token_idx, NTLM_SEND, FALSE);
        helper->neg_flags = save_flags;

        sig = pMessage->pBuffers[token_idx].pvBuffer;

        SECUR32_arc4Process(helper->crypt.ntlm.a4i,
                pMessage->pBuffers[data_idx].pvBuffer,
                pMessage->pBuffers[data_idx].cbBuffer);
        SECUR32_arc4Process(helper->crypt.ntlm.a4i, sig+4, 12);

        if(helper->neg_flags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN || helper->neg_flags == 0)
            memset(sig+4, 0, 4);
    }
    return SEC_E_OK;
}

/***********************************************************************
 *             DecryptMessage
 */
SECURITY_STATUS SEC_ENTRY ntlm_DecryptMessage(PCtxtHandle phContext,
    PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
    SECURITY_STATUS ret;
    ULONG ntlmssp_flags_save;
    PNegoHelper helper;
    int token_idx, data_idx;
    TRACE("(%p %p %d %p)\n", phContext, pMessage, MessageSeqNo, pfQOP);

    if(!phContext)
        return SEC_E_INVALID_HANDLE;

    if(MessageSeqNo)
        FIXME("Ignoring MessageSeqNo\n");

    if(!pMessage || !pMessage->pBuffers || pMessage->cBuffers < 2)
        return TOKEN_FAIL();

    if((token_idx = ntlm_GetTokenBufferIndex(pMessage)) == -1)
        return TOKEN_FAIL();

    if((data_idx = ntlm_GetDataBufferIndex(pMessage)) ==-1)
        return TOKEN_FAIL();

    if(pMessage->pBuffers[token_idx].cbBuffer < 16)
        return SEC_E_BUFFER_TOO_SMALL;

    helper = (PNegoHelper) phContext->dwLower;

    if(helper->neg_flags & NTLMSSP_NEGOTIATE_NTLM2 && helper->neg_flags & NTLMSSP_NEGOTIATE_SEAL)
    {
        SECUR32_arc4Process(helper->crypt.ntlm2.recv_a4i,
                pMessage->pBuffers[data_idx].pvBuffer,
                pMessage->pBuffers[data_idx].cbBuffer);
    }
    else
    {
        SECUR32_arc4Process(helper->crypt.ntlm.a4i,
                pMessage->pBuffers[data_idx].pvBuffer,
                pMessage->pBuffers[data_idx].cbBuffer);
    }

    /* Make sure we use a session key for the signature check, EncryptMessage
     * always does that, even in the dummy case */
    ntlmssp_flags_save = helper->neg_flags;

    helper->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
    ret = ntlm_VerifySignature(phContext, pMessage, MessageSeqNo, pfQOP);

    helper->neg_flags = ntlmssp_flags_save;

    return ret;
}

static const SecurityFunctionTableA ntlmTableA = {
    1,
    NULL,   /* EnumerateSecurityPackagesA */
    ntlm_QueryCredentialsAttributesA,   /* QueryCredentialsAttributesA */
    ntlm_AcquireCredentialsHandleA,     /* AcquireCredentialsHandleA */
    ntlm_FreeCredentialsHandle,         /* FreeCredentialsHandle */
    NULL,   /* Reserved2 */
    ntlm_InitializeSecurityContextA,    /* InitializeSecurityContextA */
    ntlm_AcceptSecurityContext,         /* AcceptSecurityContext */
    ntlm_CompleteAuthToken,             /* CompleteAuthToken */
    ntlm_DeleteSecurityContext,         /* DeleteSecurityContext */
    NULL,  /* ApplyControlToken */
    ntlm_QueryContextAttributesA,       /* QueryContextAttributesA */
    ntlm_ImpersonateSecurityContext,    /* ImpersonateSecurityContext */
    ntlm_RevertSecurityContext,         /* RevertSecurityContext */
    ntlm_MakeSignature,                 /* MakeSignature */
    ntlm_VerifySignature,               /* VerifySignature */
    FreeContextBuffer,                  /* FreeContextBuffer */
    NULL,   /* QuerySecurityPackageInfoA */
    NULL,   /* Reserved3 */
    NULL,   /* Reserved4 */
    NULL,   /* ExportSecurityContext */
    NULL,   /* ImportSecurityContextA */
    NULL,   /* AddCredentialsA */
    NULL,   /* Reserved8 */
    ntlm_QuerySecurityContextToken,     /* QuerySecurityContextToken */
    ntlm_EncryptMessage,                /* EncryptMessage */
    ntlm_DecryptMessage,                /* DecryptMessage */
    NULL,   /* SetContextAttributesA */
};

static const SecurityFunctionTableW ntlmTableW = {
    1,
    NULL,   /* EnumerateSecurityPackagesW */
    ntlm_QueryCredentialsAttributesW,   /* QueryCredentialsAttributesW */
    ntlm_AcquireCredentialsHandleW,     /* AcquireCredentialsHandleW */
    ntlm_FreeCredentialsHandle,         /* FreeCredentialsHandle */
    NULL,   /* Reserved2 */
    ntlm_InitializeSecurityContextW,    /* InitializeSecurityContextW */
    ntlm_AcceptSecurityContext,         /* AcceptSecurityContext */
    ntlm_CompleteAuthToken,             /* CompleteAuthToken */
    ntlm_DeleteSecurityContext,         /* DeleteSecurityContext */
    NULL,  /* ApplyControlToken */
    ntlm_QueryContextAttributesW,       /* QueryContextAttributesW */
    ntlm_ImpersonateSecurityContext,    /* ImpersonateSecurityContext */
    ntlm_RevertSecurityContext,         /* RevertSecurityContext */
    ntlm_MakeSignature,                 /* MakeSignature */
    ntlm_VerifySignature,               /* VerifySignature */
    FreeContextBuffer,                  /* FreeContextBuffer */
    NULL,   /* QuerySecurityPackageInfoW */
    NULL,   /* Reserved3 */
    NULL,   /* Reserved4 */
    NULL,   /* ExportSecurityContext */
    NULL,   /* ImportSecurityContextW */
    NULL,   /* AddCredentialsW */
    NULL,   /* Reserved8 */
    ntlm_QuerySecurityContextToken,     /* QuerySecurityContextToken */
    ntlm_EncryptMessage,                /* EncryptMessage */
    ntlm_DecryptMessage,                /* DecryptMessage */
    NULL,   /* SetContextAttributesW */
};

#define NTLM_COMMENT \
   { 'N', 'T', 'L', 'M', ' ', \
     'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', ' ', \
     'P', 'a', 'c', 'k', 'a', 'g', 'e', 0}

static CHAR ntlm_comment_A[] = NTLM_COMMENT;
static WCHAR ntlm_comment_W[] = NTLM_COMMENT;

#define NTLM_NAME {'N', 'T', 'L', 'M', 0}

static char ntlm_name_A[] = NTLM_NAME;
static WCHAR ntlm_name_W[] = NTLM_NAME;

/* According to Windows, NTLM has the following capabilities.  */
#define CAPS ( \
    SECPKG_FLAG_INTEGRITY  | \
    SECPKG_FLAG_PRIVACY    | \
    SECPKG_FLAG_TOKEN_ONLY | \
    SECPKG_FLAG_CONNECTION | \
    SECPKG_FLAG_MULTI_REQUIRED    | \
    SECPKG_FLAG_IMPERSONATION     | \
    SECPKG_FLAG_ACCEPT_WIN32_NAME | \
    SECPKG_FLAG_NEGOTIABLE        | \
    SECPKG_FLAG_LOGON             | \
    SECPKG_FLAG_RESTRICTED_TOKENS )

static const SecPkgInfoW infoW = {
    CAPS,
    1,
    RPC_C_AUTHN_WINNT,
    NTLM_MAX_BUF,
    ntlm_name_W,
    ntlm_comment_W
};

static const SecPkgInfoA infoA = {
    CAPS,
    1,
    RPC_C_AUTHN_WINNT,
    NTLM_MAX_BUF,
    ntlm_name_A,
    ntlm_comment_A
};

SecPkgInfoA *ntlm_package_infoA = (SecPkgInfoA *)&infoA;
SecPkgInfoW *ntlm_package_infoW = (SecPkgInfoW *)&infoW;

void SECUR32_initNTLMSP(void)
{
    SecureProvider *provider = SECUR32_addProvider(&ntlmTableA, &ntlmTableW, NULL);

    SECUR32_addPackages(provider, 1L, ntlm_package_infoA, ntlm_package_infoW);
}
