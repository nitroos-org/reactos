/*
 * Lightweight mbedTLS-based implementation of the schannel (SSL/TLS) provider.
 *
 * Copyright 2015 Peter Hater
 * Copyright 2015 Ismael Ferreras Morezuelas <swyterzone+ros@gmail.com>
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
 */

#include "config.h"
#include "wine/port.h"

#ifdef __REACTOS__
 #include "precomp.h"
 #include <inaddr.h>
 #include <in6addr.h>
 #include <ip2string.h>
#else
 #include <stdarg.h>
 #include <errno.h>

 #include "windef.h"
 #include "winbase.h"
 #include "sspi.h"
 #include "schannel.h"
 #include "wine/debug.h"
 #include "wine/library.h"
#endif

WINE_DEFAULT_DEBUG_CHANNEL(schannel);

#if defined(SONAME_LIBMBEDTLS) && !defined(HAVE_SECURITY_SECURITY_H) && !defined(SONAME_LIBGNUTLS)

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md_internal.h>
#include <mbedtls/ssl_internal.h>

/* Chain errors that make a server certificate unusable and that the SSL policy of crypt32 does not report */
#define SCHAN_FATAL_CHAIN_ERRORS (CERT_TRUST_IS_NOT_SIGNATURE_VALID | CERT_TRUST_IS_UNTRUSTED_ROOT | \
                                  CERT_TRUST_IS_CYCLIC | CERT_TRUST_IS_PARTIAL_CHAIN | \
                                  CERT_TRUST_INVALID_BASIC_CONSTRAINTS | CERT_TRUST_INVALID_NAME_CONSTRAINTS | \
                                  CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT | \
                                  CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT | \
                                  CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT | \
                                  CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT | CERT_TRUST_INVALID_POLICY_CONSTRAINTS | \
                                  CERT_TRUST_IS_EXPLICIT_DISTRUST)

/* wininet.h values of the chain policy checks */
#define SECURITY_FLAG_IGNORE_REVOCATION      0x00000080
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000

#define ROS_SCHAN_IS_BLOCKING(read_len)          ((read_len & 0xFFF00000) == 0xCCC00000)
#define ROS_SCHAN_IS_BLOCKING_MARSHALL(read_len) ((read_len & 0x000FFFFF) |  0xCCC00000)
#define ROS_SCHAN_IS_BLOCKING_RETRIEVE(read_len)  (read_len & 0x000FFFFF)

#ifndef __REACTOS__
 /* WINE defines the back-end glue in here */
 #include "secur32_priv.h"

 /* in ReactOS we use schannel instead of secur32 */
 WINE_DEFAULT_DEBUG_CHANNEL(secur32);

 /* WINE prefers to keep it optional, disable this to link explicitly */
 #include "schannel_mbedtls_lazyload.h"

 /* WINE does not define this standard win32 macro for some reason */
 #ifndef _countof
  #define _countof(a) (sizeof(a)/sizeof(*(a)))
 #endif
#endif

typedef struct
{
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       conf;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    struct schan_transport  *transport;
    WCHAR                   *target;
    DWORD                    cred_flags;
    BOOL                     manual_validation;
    BOOL                     cert_checked;
    DWORD                    enabled_protocols;
    BOOL                     version_checked;
} MBEDTLS_SESSION, *PMBEDTLS_SESSION;

/* custom `net_recv` callback adapter, mbedTLS uses it in mbedtls_ssl_read for
   pulling data from the underlying win32 net stack */
static int schan_pull_adapter(void *session, unsigned char *buff, size_t buff_len)
{
    MBEDTLS_SESSION *s = session;
    size_t requested = buff_len;
    int status;

    TRACE("MBEDTLS schan_pull_adapter: (%p/%p, %p, %u)\n", s, s->transport, buff, buff_len);

    status = schan_pull(s->transport, buff, &buff_len);

    TRACE("MBEDTLS schan_pull_adapter: (%p/%p, %p, %u) status: %#x\n", s, s->transport, buff, buff_len, status);

    if (status == NO_ERROR)
    {
        /* great, no more data left */
        if (buff_len == 0)
        {
            TRACE("Connection closed\n");
            return 0;
        }
        /* there's still some bytes that need pulling */
        else if (buff_len < requested)
        {
            TRACE("Pulled %u bytes before would block\n", buff_len);
            return ROS_SCHAN_IS_BLOCKING_MARSHALL(buff_len);
        }
        else
        {
            TRACE("Pulled %u bytes\n", buff_len);
            return buff_len;
        }
    }
    else if (status == EAGAIN)
    {
        TRACE("Would block before being able to pull anything, passing buff_len=%u\n", buff_len);
        return ROS_SCHAN_IS_BLOCKING_MARSHALL(buff_len);
    }
    else
    {
        ERR("Unknown status code from schan_pull: %d\n", status);
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    /* this should be unreachable */
    return MBEDTLS_ERR_NET_CONNECT_FAILED;
}

/* custom `net_send` callback adapter, mbedTLS uses it in mbedtls_ssl_write for
   pushing data to the underlying win32 net stack */
static int schan_push_adapter(void *session, const unsigned char *buff, size_t buff_len)
{
    MBEDTLS_SESSION *s = session;
    int status;

    TRACE("MBEDTLS schan_push_adapter: (%p/%p, %p, %u)\n", s, s->transport, buff, buff_len);

    status = schan_push(s->transport, buff, &buff_len);

    TRACE("MBEDTLS schan_push_adapter: (%p/%p, %p, %u) status: %#x\n", s, s->transport, buff, buff_len, status);

    if (status == NO_ERROR)
    {
        TRACE("Pushed %u bytes\n", buff_len);
        return buff_len;
    }
    else if (status == EAGAIN)
    {
        TRACE("Would block before being able to push anything. passing %u\n", buff_len);
        return ROS_SCHAN_IS_BLOCKING_MARSHALL(buff_len);
    }
    else
    {
        ERR("Unknown status code from schan_push: %d\n", status);
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }

    /* this should be unreachable */
    return MBEDTLS_ERR_NET_CONNECT_FAILED;
}

DWORD schan_imp_enabled_protocols(void)
{
    /* NOTE: No support for SSL 2.0 */
    TRACE("MBEDTLS schan_imp_enabled_protocols()\n");

    return 0
#ifdef MBEDTLS_SSL_PROTO_SSL3
        | SP_PROT_SSL3_CLIENT | SP_PROT_SSL3_SERVER
#endif
#ifdef MBEDTLS_SSL_PROTO_TLS1
        | SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_0_SERVER
#endif
#ifdef MBEDTLS_SSL_PROTO_TLS1_1
        | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_1_SERVER
#endif
#ifdef MBEDTLS_SSL_PROTO_TLS1_2
        | SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_2_SERVER
#endif
        ;
}

/* SP_PROT_* (client | server) bits of each mbedTLS minor version, lowest first */
static const struct
{
    int minor;
    DWORD protocols;
} schan_protocol_versions[] =
{
    { MBEDTLS_SSL_MINOR_VERSION_0, SP_PROT_SSL3 },
    { MBEDTLS_SSL_MINOR_VERSION_1, SP_PROT_TLS1_0 },
    { MBEDTLS_SSL_MINOR_VERSION_2, SP_PROT_TLS1_1 },
    { MBEDTLS_SSL_MINOR_VERSION_3, SP_PROT_TLS1_2 },
};

/* Limits the session to the credential's protocols; schan_imp_handshake rejects a version inside the range that
 * the credential does not enable (e.g. TLS 1.1 with only TLS 1.0 and 1.2 enabled) */
static void schan_imp_set_session_protocols(MBEDTLS_SESSION *s, DWORD enabled)
{
    unsigned int i;
    int min = -1, max = -1;

    s->enabled_protocols = enabled;
    for (i = 0; i < sizeof(schan_protocol_versions) / sizeof(schan_protocol_versions[0]); i++)
    {
        if (!(enabled & schan_protocol_versions[i].protocols))
            continue;
        if (min < 0)
            min = schan_protocol_versions[i].minor;
        max = schan_protocol_versions[i].minor;
    }

    /* Credentials without any mbedTLS protocol are refused by AcquireCredentialsHandle; keep the defaults otherwise */
    if (min < 0)
        return;

    TRACE("MBEDTLS protocol versions 3.%d-3.%d (enabled %#x)\n", min, max, enabled);
    mbedtls_ssl_conf_min_version(&s->conf, MBEDTLS_SSL_MAJOR_VERSION_3, min);
    mbedtls_ssl_conf_max_version(&s->conf, MBEDTLS_SSL_MAJOR_VERSION_3, max);
}

static BOOL schan_imp_version_enabled(const MBEDTLS_SESSION *s)
{
    unsigned int i;

    if (!s->enabled_protocols)
        return TRUE;
    for (i = 0; i < sizeof(schan_protocol_versions) / sizeof(schan_protocol_versions[0]); i++)
    {
        if (schan_protocol_versions[i].minor == s->ssl.minor_ver)
            return (s->enabled_protocols & schan_protocol_versions[i].protocols) != 0;
    }
    return FALSE;
}

static void schan_imp_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    WARN("MBEDTLS schan_imp_debug: %s:%04d: %s\n", file, line, str);
}

BOOL schan_imp_create_session(schan_imp_session *session, schan_credentials *cred)
{
    MBEDTLS_SESSION *s = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MBEDTLS_SESSION));

    WARN("MBEDTLS schan_imp_create_session: %p %p %p\n", session, *session, cred);

    if (!(*session = (schan_imp_session)s))
    {
        ERR("Not enough memory to create session\n");
        return FALSE;
    }

    TRACE("MBEDTLS init entropy\n");
    mbedtls_entropy_init(&s->entropy);

    TRACE("MBEDTLS init random - change static entropy private data\n");
    mbedtls_ctr_drbg_init(&s->ctr_drbg);
    mbedtls_ctr_drbg_seed(&s->ctr_drbg, mbedtls_entropy_func, &s->entropy, NULL, 0);

    WARN("MBEDTLS init ssl\n");
    mbedtls_ssl_init(&s->ssl);

    WARN("MBEDTLS init conf\n");
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

    TRACE("MBEDTLS set BIO callbacks\n");
    mbedtls_ssl_set_bio(&s->ssl, s, schan_push_adapter, schan_pull_adapter, NULL);

    TRACE("MBEDTLS set endpoint to %s\n", (cred->credential_use & SECPKG_CRED_INBOUND) ? "server" : "client");
    mbedtls_ssl_conf_endpoint(&s->conf,   (cred->credential_use & SECPKG_CRED_INBOUND) ? MBEDTLS_SSL_IS_SERVER :
                                                                                         MBEDTLS_SSL_IS_CLIENT);

    TRACE("MBEDTLS set authmode\n");
    mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_NONE);

    TRACE("MBEDTLS set rng\n");
    mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random, &s->ctr_drbg);

    TRACE("MBEDTLS set dbg\n");
    mbedtls_ssl_conf_dbg(&s->conf, schan_imp_debug, stdout);

    schan_imp_set_session_protocols(s, cred->enabled_protocols);

    TRACE("MBEDTLS setup\n");
    mbedtls_ssl_setup(&s->ssl, &s->conf);

    TRACE("MBEDTLS schan_imp_create_session END!\n");
    return TRUE;
}

void schan_imp_dispose_session(schan_imp_session session)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;
    WARN("MBEDTLS schan_imp_dispose_session: %p\n", session);

    /* tell the other peer (a server) that we are going away */
    //ssl_close_notify(&s->ssl);

    HeapFree(GetProcessHeap(), 0, s->target);
    mbedtls_ssl_free(&s->ssl);
    mbedtls_ctr_drbg_free(&s->ctr_drbg);
    mbedtls_entropy_free(&s->entropy);
    mbedtls_ssl_config_free(&s->conf);

    /* safely overwrite the freed context with zeroes */
    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, s);
}

void schan_imp_set_session_transport(schan_imp_session session,
                                     struct schan_transport *t)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    TRACE("MBEDTLS schan_imp_set_session_transport: %p %p\n", session, t);

    s->transport = t;
}

/* RFC 6066 forbids an IP address in server_name, and Windows sends none for an address target */
static BOOL schan_is_address_literal(const char *target)
{
    const char *end;
    IN_ADDR addr4;
    IN6_ADDR addr6;

    if (!RtlIpv4StringToAddressA(target, TRUE, &end, &addr4) && !*end)
        return TRUE;
    if (!RtlIpv6StringToAddressA(target, &end, &addr6) && !*end)
        return TRUE;
    return FALSE;
}

void schan_imp_set_session_target(schan_imp_session session, const char *target)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    TRACE("MBEDTLS schan_imp_set_session_target: sess: %p hostname: %s\n", session, target);

    /* FIXME: WINE tests do not pass when we set the hostname because in the test cases
     * contacting 'www.winehq.org' the hostname is defined as 'localhost' so the server
     * sends a non-fatal alert which preemptively forces mbedTLS to close connection. */

    /* The name only feeds SNI: the server certificate is checked against the target by schan_validate_server_chain */
    if (schan_is_address_literal(target))
        return;

    mbedtls_ssl_set_hostname(&s->ssl, target);
}

void schan_imp_set_session_validation(schan_imp_session session, const WCHAR *target, DWORD flags, BOOL manual)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    s->cred_flags = flags;
    s->manual_validation = manual || (flags & SCH_CRED_MANUAL_CRED_VALIDATION);

    if (target)
    {
        SIZE_T size = (lstrlenW(target) + 1) * sizeof(WCHAR);

        s->target = HeapAlloc(GetProcessHeap(), 0, size);
        if (s->target)
            memcpy(s->target, target, size);
    }
}

static SECURITY_STATUS schan_add_peer_chain(const mbedtls_x509_crt *peer_cert, HCERTSTORE store,
                                            PCCERT_CONTEXT *ret);

static SECURITY_STATUS schan_status_from_chain_error(DWORD error)
{
    switch (error)
    {
        case CERT_E_EXPIRED:
            return SEC_E_CERT_EXPIRED;

        case CERT_E_CN_NO_MATCH:
            return SEC_E_WRONG_PRINCIPAL;

        case CERT_E_UNTRUSTEDROOT:
        case CERT_E_UNTRUSTEDTESTROOT:
        case CERT_E_CHAINING:
        case TRUST_E_CERT_SIGNATURE:
            return SEC_E_UNTRUSTED_ROOT;

        default:
            return SEC_E_CERT_UNKNOWN;
    }
}

/* Windows schannel checks the chain of a server itself unless the caller asked to do it */
static BOOL schan_chain_has_offline_source(PCCERT_CHAIN_CONTEXT chain)
{
    DWORD i, j;

    for (i = 0; i < chain->cChain; i++)
        for (j = 0; j < chain->rgpChain[i]->cElement; j++)
        {
            DWORD err = chain->rgpChain[i]->rgpElement[j]->TrustStatus.dwErrorStatus;

            if ((err & CERT_TRUST_IS_OFFLINE_REVOCATION) && !(err & CERT_TRUST_REVOCATION_STATUS_UNKNOWN))
                return TRUE;
        }
    return FALSE;
}

static SECURITY_STATUS schan_validate_server_chain(MBEDTLS_SESSION *s)
{
    static char server_auth_oid[] = szOID_PKIX_KP_SERVER_AUTH;
    char *usages[] = { server_auth_oid };
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_para;
    CERT_CHAIN_POLICY_PARA policy_para;
    CERT_CHAIN_POLICY_STATUS policy_status;
    CERT_CHAIN_PARA chain_para;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    PCCERT_CONTEXT leaf = NULL;
    HCERTSTORE store;
    SECURITY_STATUS status;
    DWORD chain_flags = 0;

    /* Without a target name there is nothing to match, which Windows reports before any chain error */
    if (!s->target && !(s->cred_flags & SCH_CRED_NO_SERVERNAME_CHECK))
        return SEC_E_WRONG_PRINCIPAL;

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!store)
        return SEC_E_INTERNAL_ERROR;

    status = schan_add_peer_chain(s->ssl.session_negotiate ? s->ssl.session_negotiate->peer_cert : NULL, store, &leaf);
    if (status != SEC_E_OK || !leaf)
    {
        CertCloseStore(store, 0);
        return SEC_E_CERT_UNKNOWN;
    }

    memset(&chain_para, 0, sizeof(chain_para));
    chain_para.cbSize = sizeof(chain_para);
    chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chain_para.RequestedUsage.Usage.cUsageIdentifier = 1;
    chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = usages;

    if (s->cred_flags & SCH_CRED_REVOCATION_CHECK_CHAIN_END_CERT)
        chain_flags = CERT_CHAIN_REVOCATION_CHECK_END_CERT;
    else if (s->cred_flags & SCH_CRED_REVOCATION_CHECK_CHAIN)
        chain_flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    else if (s->cred_flags & SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT)
        chain_flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

    if (!CertGetCertificateChain(NULL, leaf, NULL, store, &chain_para, chain_flags, NULL, &chain))
    {
        status = SEC_E_CERT_UNKNOWN;
        goto done;
    }

    memset(&ssl_para, 0, sizeof(ssl_para));
    ssl_para.cbSize = sizeof(ssl_para);
    ssl_para.dwAuthType = AUTHTYPE_SERVER;
    /* The policy would also drop a known revocation, so revocation is judged below from the chain status */
    ssl_para.fdwChecks = SECURITY_FLAG_IGNORE_REVOCATION;
    if (s->cred_flags & SCH_CRED_NO_SERVERNAME_CHECK)
        ssl_para.fdwChecks |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    ssl_para.pwszServerName = s->target;

    memset(&policy_para, 0, sizeof(policy_para));
    policy_para.cbSize = sizeof(policy_para);
    policy_para.pvExtraPolicyPara = &ssl_para;

    memset(&policy_status, 0, sizeof(policy_status));
    policy_status.cbSize = sizeof(policy_status);

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy_para, &policy_status))
    {
        status = SEC_E_CERT_UNKNOWN;
        goto done;
    }

    status = SEC_E_OK;
    if (policy_status.dwError && policy_status.dwError != CERT_E_CN_NO_MATCH)
    {
        /* Windows reports an untrusted or incomplete chain ahead of an expiry: a certificate that is
         * both expired and of an unknown/untrusted issuer is rejected as UNTRUSTED_ROOT, not EXPIRED.
         * Basic-constraint failures stay WRONG_USAGE below, so they are excluded here. (T114) */
        if (policy_status.dwError == CERT_E_EXPIRED &&
            !(chain->TrustStatus.dwErrorStatus & CERT_TRUST_INVALID_BASIC_CONSTRAINTS) &&
            (chain->TrustStatus.dwErrorStatus & SCHAN_FATAL_CHAIN_ERRORS))
            status = SEC_E_UNTRUSTED_ROOT;
        else
        {
            WARN("MBEDTLS server certificate rejected: %#x\n", policy_status.dwError);
            status = schan_status_from_chain_error(policy_status.dwError);
        }
    }
    /* crypt32's SSL policy ignores these, so a missing issuer, a signer that is not a CA or a name constraint pass it */
    else if (chain->TrustStatus.dwErrorStatus & CERT_TRUST_INVALID_BASIC_CONSTRAINTS)
        status = SEC_E_CERT_WRONG_USAGE;
    else if (chain->TrustStatus.dwErrorStatus & SCHAN_FATAL_CHAIN_ERRORS)
        status = SEC_E_UNTRUSTED_ROOT;
    /* Windows reports a name mismatch before any revocation state, so an excused revocation error cannot hide it */
    else if (policy_status.dwError == CERT_E_CN_NO_MATCH)
        status = SEC_E_WRONG_PRINCIPAL;
    else if (chain_flags && (chain->TrustStatus.dwErrorStatus & CERT_TRUST_IS_REVOKED))
        status = CRYPT_E_REVOKED;
    /* A source that was unreachable makes the whole revocation state offline, and only the offline flag may excuse it;
     * crypt32 also sets the offline bit on an element without any revocation information, so look for it per element */
    else if (chain_flags && schan_chain_has_offline_source(chain))
    {
        if (!(s->cred_flags & SCH_CRED_IGNORE_REVOCATION_OFFLINE))
            status = CRYPT_E_REVOCATION_OFFLINE;
    }
    else if (chain_flags && (chain->TrustStatus.dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) &&
             !(s->cred_flags & SCH_CRED_IGNORE_NO_REVOCATION_CHECK))
        status = CRYPT_E_NO_REVOCATION_CHECK;

done:
    if (chain)
        CertFreeCertificateChain(chain);
    CertFreeCertificateContext(leaf);
    CertCloseStore(store, 0);
    return status;
}

SECURITY_STATUS schan_imp_handshake(schan_imp_session session)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;
    int err = 0;

    /* Step through the handshake so the server certificate is checked before the client answers it */
    while (s->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
        /* The negotiated version is known once the ServerHello is parsed */
        if (!s->version_checked && s->conf.endpoint == MBEDTLS_SSL_IS_CLIENT &&
            s->ssl.state > MBEDTLS_SSL_SERVER_HELLO)
        {
            if (!schan_imp_version_enabled(s))
            {
                WARN("MBEDTLS server chose disabled protocol 3.%d\n", s->ssl.minor_ver);
                return SEC_E_ALGORITHM_MISMATCH;
            }
            s->version_checked = TRUE;
        }

        if (!s->cert_checked && s->conf.endpoint == MBEDTLS_SSL_IS_CLIENT &&
            s->ssl.state > MBEDTLS_SSL_SERVER_CERTIFICATE)
        {
            /* Windows answers a rejected server with the status alone, no alert record */
            if (!s->manual_validation)
            {
                SECURITY_STATUS status = schan_validate_server_chain(s);

                if (status != SEC_E_OK)
                    return status;
            }

            /* Mark checked only after the chain validates, so a retried handshake re-validates instead of completing against an unvalidated server */
            s->cert_checked = TRUE;
        }

        err = mbedtls_ssl_handshake_step(&s->ssl);
        if (err != 0)
            break;
    }

    TRACE("MBEDTLS schan_imp_handshake: %p  err: %#x \n", session, err);

    if (ROS_SCHAN_IS_BLOCKING(err))
    {
        TRACE("Received ERR_NET_WANT_READ/WRITE... let's try again!\n");
        return SEC_I_CONTINUE_NEEDED;
    }
    else if (err == MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE)
    {
        ERR("schan_imp_handshake: SSL Feature unavailable...\n");
        return SEC_E_UNSUPPORTED_FUNCTION;
    }
    else if (err == MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION)
    {
        /* The server chose a protocol version the session does not offer */
        WARN("schan_imp_handshake: no common protocol version\n");
        return SEC_E_ALGORITHM_MISMATCH;
    }
    else if (err == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE && s->ssl.in_msg &&
             s->ssl.in_msg[1] == MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION)
    {
        /* The server refused every version offered; Windows reports this alert as SEC_E_UNSUPPORTED_FUNCTION */
        WARN("schan_imp_handshake: server refused the offered protocol versions\n");
        return SEC_E_UNSUPPORTED_FUNCTION;
    }
    else if (err != 0)
    {
        ERR("schan_imp_handshake: Oops! mbedtls_ssl_handshake returned the following error code: -%#x...\n", -err);
        return SEC_E_INTERNAL_ERROR;
    }

    WARN("schan_imp_handshake: Handshake completed!\n");
    WARN("schan_imp_handshake: Protocol is %s, Cipher suite is %s\n", mbedtls_ssl_get_version(&s->ssl),
                                                                      mbedtls_ssl_get_ciphersuite(&s->ssl));
    return SEC_E_OK;
}

static unsigned int schannel_get_cipher_key_size(int ciphersuite_id)
{
    const mbedtls_ssl_ciphersuite_t *ssl_cipher_suite = mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);
    const mbedtls_cipher_info_t          *cipher_info = mbedtls_cipher_info_from_type(ssl_cipher_suite->cipher);

    unsigned int key_bitlen = cipher_info->key_bitlen;

    TRACE("MBEDTLS schannel_get_cipher_key_size: Unknown cipher %#x, returning %u\n", ciphersuite_id, key_bitlen);

    return key_bitlen;
}

static unsigned int schannel_get_mac_key_size(int ciphersuite_id)
{
    const mbedtls_ssl_ciphersuite_t *ssl_cipher_suite = mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);
    const mbedtls_md_info_t                  *md_info = mbedtls_md_info_from_type(ssl_cipher_suite->mac);

    int md_size = md_info->size * CHAR_BIT; /* return the size in bits, as the secur32:schannel winetest shows */

    TRACE("MBEDTLS schannel_get_mac_key_size: returning %i\n", md_size);

    return md_size;
}

static unsigned int schannel_get_kx_key_size(const mbedtls_ssl_context *ssl, const mbedtls_ssl_config *conf, int ciphersuite_id)
{
    const mbedtls_ssl_ciphersuite_t *ssl_ciphersuite = mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);

    /* if we are the server take ca_chain, if we are the client take the proper x509 peer certificate */
    const mbedtls_x509_crt *server_cert = (conf->endpoint == MBEDTLS_SSL_IS_SERVER) ? conf->ca_chain : mbedtls_ssl_get_peer_cert(ssl);

    if (ssl_ciphersuite->key_exchange != MBEDTLS_KEY_EXCHANGE_NONE)
        return mbedtls_pk_get_len(&(server_cert->pk));

    TRACE("MBEDTLS schannel_get_kx_key_size: Unknown kx %#x, returning 0\n", ssl_ciphersuite->key_exchange);

    return 0;
}

static DWORD schannel_get_protocol(const mbedtls_ssl_context *ssl, const mbedtls_ssl_config *conf)
{
    /* FIXME: currently schannel only implements client connections, but
     * there's no reason it couldn't be used for servers as well. The
     * context doesn't tell us which it is, so decide based on ssl endpoint value. */

    switch (ssl->minor_ver)
    {
        case MBEDTLS_SSL_MINOR_VERSION_0:
            return (conf->endpoint == MBEDTLS_SSL_IS_CLIENT) ? SP_PROT_SSL3_CLIENT :
                                                               SP_PROT_SSL3_SERVER;

        case MBEDTLS_SSL_MINOR_VERSION_1:
            return (conf->endpoint == MBEDTLS_SSL_IS_CLIENT) ? SP_PROT_TLS1_0_CLIENT :
                                                               SP_PROT_TLS1_0_SERVER;

        case MBEDTLS_SSL_MINOR_VERSION_2:
            return (conf->endpoint == MBEDTLS_SSL_IS_CLIENT) ? SP_PROT_TLS1_1_CLIENT :
                                                               SP_PROT_TLS1_1_SERVER;

        case MBEDTLS_SSL_MINOR_VERSION_3:
            return (conf->endpoint == MBEDTLS_SSL_IS_CLIENT) ? SP_PROT_TLS1_2_CLIENT :
                                                               SP_PROT_TLS1_2_SERVER;

        default:
        {
            FIXME("MBEDTLS schannel_get_protocol: unknown protocol %d\n", ssl->minor_ver);
            return 0;
        }
    }
}

static ALG_ID schannel_get_cipher_algid(int ciphersuite_id)
{
    const mbedtls_ssl_ciphersuite_t *cipher_suite = mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);

    switch (cipher_suite->cipher)
    {
        case MBEDTLS_CIPHER_NONE:
        case MBEDTLS_CIPHER_NULL:
            return 0;

#ifdef MBEDTLS_ARC4_C
        /* ARC4 */
        case MBEDTLS_CIPHER_ARC4_128:
            return CALG_RC4;
#endif

#ifdef MBEDTLS_CHACHAPOLY_C
        /* ChaCha20-Poly1305 (256-bit key). wincrypt has no CALG_CHACHA20, so, like Camellia
         * below, it is reported as the closest ALG_ID: AES-256, a 256-bit modern AEAD cipher.
         * 0 would read as "no encryption" to callers. dwCipherStrength stays the real 256. */
        case MBEDTLS_CIPHER_CHACHA20_POLY1305:
            return CALG_AES_256;
#endif

#ifdef MBEDTLS_DES_C
        /* DES */
        case MBEDTLS_CIPHER_DES_ECB:
        case MBEDTLS_CIPHER_DES_CBC:
        case MBEDTLS_CIPHER_DES_EDE_ECB:
        case MBEDTLS_CIPHER_DES_EDE_CBC:
            return CALG_DES;

        case MBEDTLS_CIPHER_DES_EDE3_ECB:
        case MBEDTLS_CIPHER_DES_EDE3_CBC:
            return CALG_3DES;
#endif

#ifdef MBEDTLS_BLOWFISH_C
        /* BLOWFISH */
        case MBEDTLS_CIPHER_BLOWFISH_ECB:
        case MBEDTLS_CIPHER_BLOWFISH_CBC:
        case MBEDTLS_CIPHER_BLOWFISH_CFB64:
        case MBEDTLS_CIPHER_BLOWFISH_CTR:
            return CALG_RC4;  // (as schannel does not support it fake it as RC4, which has a
                              //  similar profile of low footprint and medium-high security) CALG_BLOWFISH;
#endif

#ifdef MBEDTLS_CAMELLIA_C
        /* CAMELLIA */
        case MBEDTLS_CIPHER_CAMELLIA_128_ECB:
        case MBEDTLS_CIPHER_CAMELLIA_192_ECB:
        case MBEDTLS_CIPHER_CAMELLIA_256_ECB:
        case MBEDTLS_CIPHER_CAMELLIA_128_CBC:
        case MBEDTLS_CIPHER_CAMELLIA_192_CBC:
        case MBEDTLS_CIPHER_CAMELLIA_256_CBC:
        case MBEDTLS_CIPHER_CAMELLIA_128_CFB128:
        case MBEDTLS_CIPHER_CAMELLIA_192_CFB128:
        case MBEDTLS_CIPHER_CAMELLIA_256_CFB128:
        case MBEDTLS_CIPHER_CAMELLIA_128_CTR:
        case MBEDTLS_CIPHER_CAMELLIA_192_CTR:
        case MBEDTLS_CIPHER_CAMELLIA_256_CTR:
        case MBEDTLS_CIPHER_CAMELLIA_128_GCM:
        case MBEDTLS_CIPHER_CAMELLIA_192_GCM:
        case MBEDTLS_CIPHER_CAMELLIA_256_GCM:
            return CALG_AES_256;  // (as schannel does not support it fake it as AES, which has a
                                  //  similar profile, offering modern high security) CALG_CAMELLIA;
#endif

#ifdef MBEDTLS_AES_C
        /* AES 128 */
        case MBEDTLS_CIPHER_AES_128_ECB:
        case MBEDTLS_CIPHER_AES_128_CBC:
        case MBEDTLS_CIPHER_AES_128_CFB128:
        case MBEDTLS_CIPHER_AES_128_CTR:
        case MBEDTLS_CIPHER_AES_128_GCM:
    #ifdef MBEDTLS_CCM_C
        case MBEDTLS_CIPHER_AES_128_CCM:
    #endif
            return CALG_AES_128;

        case MBEDTLS_CIPHER_AES_192_ECB:
        case MBEDTLS_CIPHER_AES_192_CBC:
        case MBEDTLS_CIPHER_AES_192_CFB128:
        case MBEDTLS_CIPHER_AES_192_CTR:
        case MBEDTLS_CIPHER_AES_192_GCM:
    #ifdef MBEDTLS_CCM_C
        case MBEDTLS_CIPHER_AES_192_CCM:
    #endif
            return CALG_AES_192;

        case MBEDTLS_CIPHER_AES_256_ECB:
        case MBEDTLS_CIPHER_AES_256_CBC:
        case MBEDTLS_CIPHER_AES_256_CFB128:
        case MBEDTLS_CIPHER_AES_256_CTR:
        case MBEDTLS_CIPHER_AES_256_GCM:
    #ifdef MBEDTLS_CCM_C
        case MBEDTLS_CIPHER_AES_256_CCM:
    #endif
            return CALG_AES_256;
#endif

        /* nothing to show? fall through */
        default:
        {
            FIXME("MBEDTLS schannel_get_cipher_algid: unknown algorithm %d\n", ciphersuite_id);
            return 0;
        }
    }
}

static ALG_ID schannel_get_mac_algid(int ciphersuite_id)
{
    const mbedtls_ssl_ciphersuite_t *cipher_suite = mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);

    switch (cipher_suite->mac)
    {
        case MBEDTLS_MD_NONE:      return 0;
        case MBEDTLS_MD_MD2:       return CALG_MD2;
        case MBEDTLS_MD_MD4:       return CALG_MD4;
        case MBEDTLS_MD_MD5:       return CALG_MD5;
        case MBEDTLS_MD_SHA1:      return CALG_SHA1;
        case MBEDTLS_MD_SHA224:    return CALG_SHA;
        case MBEDTLS_MD_SHA256:    return CALG_SHA_256;
        case MBEDTLS_MD_SHA384:    return CALG_SHA_384;
        case MBEDTLS_MD_SHA512:    return CALG_SHA_512;
        case MBEDTLS_MD_RIPEMD160: return (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_RIPEMD160); /* there's no CALG_RIPEMD or CALG_RIPEMD160 defined in <wincrypt.h> yet */

        default:
        {
            FIXME("MBEDTLS schannel_get_mac_algid: unknown algorithm %d\n", cipher_suite->mac);
            return 0;
        }
    }
}

static ALG_ID schannel_get_kx_algid(int ciphersuite_id)
{
    const mbedtls_ssl_ciphersuite_t *cipher_suite = mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);

    switch (cipher_suite->key_exchange)
    {
        case MBEDTLS_KEY_EXCHANGE_NONE:
        case MBEDTLS_KEY_EXCHANGE_PSK: /* the original implementation does not support    */
            return 0;                  /* any PSK, and does not define any `CALG_PSK` :)  */

        case MBEDTLS_KEY_EXCHANGE_RSA:
        case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
            return CALG_RSA_KEYX;

        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
            return CALG_DH_EPHEM;

        case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
            return CALG_ECDH;

        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            return CALG_ECDH_EPHEM;

        default:
        {
            FIXME("MBEDTLS schannel_get_kx_algid: unknown algorithm %d\n", cipher_suite->key_exchange);
            return 0;
        }
    }
}

unsigned int schan_imp_get_session_cipher_block_size(schan_imp_session session)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    unsigned int cipher_block_size = mbedtls_cipher_get_block_size(&s->ssl.transform->cipher_ctx_enc);

    TRACE("MBEDTLS schan_imp_get_session_cipher_block_size %p returning %u.\n", session, cipher_block_size);

    return cipher_block_size;
}

unsigned int schan_imp_get_max_message_size(schan_imp_session session)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    unsigned int max_frag_len = mbedtls_ssl_get_max_frag_len(&s->ssl);

    TRACE("MBEDTLS schan_imp_get_max_message_size %p returning %u.\n", session, max_frag_len);

    return max_frag_len;
}

SECURITY_STATUS schan_imp_get_connection_info(schan_imp_session session,
                                              SecPkgContext_ConnectionInfo *info)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    int ciphersuite_id = mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(&s->ssl));

    TRACE("MBEDTLS schan_imp_get_connection_info %p %p.\n", session, info);

    info->dwProtocol       = schannel_get_protocol(&s->ssl, &s->conf);
    info->aiCipher         = schannel_get_cipher_algid(ciphersuite_id);
    info->dwCipherStrength = schannel_get_cipher_key_size(ciphersuite_id);
    info->aiHash           = schannel_get_mac_algid(ciphersuite_id);
    info->dwHashStrength   = schannel_get_mac_key_size(ciphersuite_id);
    info->aiExch           = schannel_get_kx_algid(ciphersuite_id);
    info->dwExchStrength   = schannel_get_kx_key_size(&s->ssl, &s->conf, ciphersuite_id);

    return SEC_E_OK;
}

static SECURITY_STATUS schan_add_peer_chain(const mbedtls_x509_crt *peer_cert, HCERTSTORE store,
                                            PCCERT_CONTEXT *ret)
{
    PCCERT_CONTEXT cert_context = NULL;
    const mbedtls_x509_crt *next_cert;

    if (!peer_cert)
        return SEC_E_INTERNAL_ERROR;

    for (next_cert = peer_cert; next_cert != NULL; next_cert = next_cert->next)
    {
        if (!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, next_cert->raw.p, next_cert->raw.len,
            CERT_STORE_ADD_REPLACE_EXISTING, (next_cert != peer_cert) ? NULL : &cert_context))
        {
            if (next_cert != peer_cert)
                CertFreeCertificateContext(cert_context);
            return GetLastError();
        }
    }

    *ret = cert_context;
    return SEC_E_OK;
}

SECURITY_STATUS schan_imp_get_session_peer_certificate(schan_imp_session session, HCERTSTORE store,
                                                       PCCERT_CONTEXT *ret)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    TRACE("MBEDTLS schan_imp_get_session_peer_certificate %p %p %p %p.\n", session, store, ret, ret != NULL ? *ret : NULL);

    return schan_add_peer_chain(mbedtls_ssl_get_peer_cert(&s->ssl), store, ret);
}

/* tls-unique (RFC 5929): the first Finished message of the handshake, which for a client that did not resume
 * a session is the one it sent. size is the room on input and the length on output. */
SECURITY_STATUS schan_imp_get_unique_binding(schan_imp_session session, BYTE *data, DWORD *size)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;

    TRACE("MBEDTLS schan_imp_get_unique_binding %p.\n", session);

    if (s->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
        return SEC_E_INVALID_HANDLE;
    if (!s->ssl.verify_data_len || s->ssl.verify_data_len > *size)
        return SEC_E_INTERNAL_ERROR;

    memcpy(data, s->ssl.own_verify_data, s->ssl.verify_data_len);
    *size = s->ssl.verify_data_len;
    return SEC_E_OK;
}

SECURITY_STATUS schan_imp_send(schan_imp_session session, const void *buffer,
                               SIZE_T *length)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;
    int ret;

    /* Fail-closed: a client context whose server certificate (or protocol version) was never validated
       must not be advanced to a completed handshake through the data path; mbedtls_ssl_write would otherwise
       finish the handshake without re-entering schan_validate_server_chain */
    if (s->conf.endpoint == MBEDTLS_SSL_IS_CLIENT &&
        (!s->version_checked || (!s->manual_validation && !s->cert_checked)))
        return SEC_E_CONTEXT_EXPIRED;

    ret = mbedtls_ssl_write(&s->ssl, (unsigned char *)buffer, *length);

    TRACE("MBEDTLS schan_imp_send: (%p, %p, %p/%lu)\n", s, buffer, length, *length);

    if (ret >= 0)
    {
        TRACE("MBEDTLS schan_imp_send: ret=%i.\n", ret);

        *length = ret;
    }
    else if (ROS_SCHAN_IS_BLOCKING(ret))
    {
        *length = ROS_SCHAN_IS_BLOCKING_RETRIEVE(ret);

        if (!*length)
        {
            TRACE("MBEDTLS schan_imp_send: ret=MBEDTLS_ERR_NET_WANT_WRITE -> SEC_I_CONTINUE_NEEDED; len=%lu", *length);
            return SEC_I_CONTINUE_NEEDED;
        }
        else
        {
            TRACE("MBEDTLS schan_imp_send: ret=MBEDTLS_ERR_NET_WANT_WRITE -> SEC_E_OK; len=%lu", *length);
            return SEC_E_OK;
        }
    }
    else
    {
        ERR("MBEDTLS schan_imp_send: mbedtls_ssl_write failed with -%x\n", -ret);
        return SEC_E_INTERNAL_ERROR;
    }

    return SEC_E_OK;
}

SECURITY_STATUS schan_imp_recv(schan_imp_session session, void *buffer,
                               SIZE_T *length)
{
    PMBEDTLS_SESSION s = (PMBEDTLS_SESSION)session;
    int ret;

    /* Fail-closed: a client context whose server certificate (or protocol version) was never validated
       must not be advanced to a completed handshake through the data path; mbedtls_ssl_read would otherwise
       finish the handshake without re-entering schan_validate_server_chain */
    if (s->conf.endpoint == MBEDTLS_SSL_IS_CLIENT &&
        (!s->version_checked || (!s->manual_validation && !s->cert_checked)))
        return SEC_E_CONTEXT_EXPIRED;

    TRACE("MBEDTLS schan_imp_recv: (%p, %p, %p/%lu)\n", s, buffer, length, *length);

    ret = mbedtls_ssl_read(&s->ssl, (unsigned char *)buffer, *length);

    TRACE("MBEDTLS schan_imp_recv: (%p, %p, %p/%lu) ret= %#x\n", s, buffer, length, *length, ret);

    if (ret >= 0)
    {
        TRACE("MBEDTLS schan_imp_recv: ret == %i.\n", ret);

        *length = ret;
    }
    else if (ROS_SCHAN_IS_BLOCKING(ret))
    {
        *length = ROS_SCHAN_IS_BLOCKING_RETRIEVE(ret);

        if (!*length)
        {
            TRACE("MBEDTLS schan_imp_recv: ret=MBEDTLS_ERR_NET_WANT_WRITE -> SEC_I_CONTINUE_NEEDED; len=%lu", *length);
            return SEC_I_CONTINUE_NEEDED;
        }
        else
        {
            TRACE("MBEDTLS schan_imp_recv: ret=MBEDTLS_ERR_NET_WANT_WRITE -> SEC_E_OK; len=%lu", *length);
            return SEC_E_OK;
        }
    }
    else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    {
        *length = 0;
        TRACE("MBEDTLS schan_imp_recv: ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY -> SEC_E_OK\n");
        return SEC_E_OK;
    }
    else
    {
        ERR("MBEDTLS schan_imp_recv: mbedtls_ssl_read failed with -%x\n", -ret);
        return SEC_E_INTERNAL_ERROR;
    }

    return SEC_E_OK;
}

/* ApplyControlToken: SCHANNEL_SHUTDOWN (close_notify) or SCHANNEL_ALERT; level and description are the TLS values */
SECURITY_STATUS schan_imp_send_alert(schan_imp_session session, DWORD level, DWORD description)
{
    MBEDTLS_SESSION *s = (MBEDTLS_SESSION *)session;
    int ret;

    TRACE("MBEDTLS schan_imp_send_alert: %p level %u description %u\n", session, level, description);

    /* mbedtls_ssl_write_record appends the record to the unsent output (out_left). When an earlier call stopped
     * because the caller's output buffer was too small, that record is still queued, so building the alert again
     * would send it twice: only flush what is pending. */
    if (s->ssl.out_left != 0)
        ret = mbedtls_ssl_flush_output(&s->ssl);
    else
        ret = mbedtls_ssl_send_alert_message(&s->ssl, (unsigned char)level, (unsigned char)description);
    if (ret == 0)
        return SEC_E_OK;
    if (ROS_SCHAN_IS_BLOCKING(ret))
        return SEC_E_BUFFER_TOO_SMALL;

    ERR("MBEDTLS schan_imp_send_alert: mbedtls_ssl_send_alert_message failed with -%x\n", -ret);
    return SEC_E_INTERNAL_ERROR;
}

BOOL schan_imp_allocate_certificate_credentials(schan_credentials *c)
{
    TRACE("MBEDTLS schan_imp_allocate_certificate_credentials %p %p %d\n", c, c->credentials, c->credential_use);

    /* in our case credentials aren't really used for anything, so just stub them */
    c->credentials = NULL;
    return TRUE;
}

void schan_imp_free_certificate_credentials(schan_credentials *c)
{
    TRACE("MBEDTLS schan_imp_free_certificate_credentials %p %p %d\n", c, c->credentials, c->credential_use);
}

BOOL schan_imp_init(void)
{
    TRACE("Schannel MBEDTLS schan_imp_init\n");
    return TRUE;
}

void schan_imp_deinit(void)
{
    WARN("Schannel MBEDTLS schan_imp_deinit\n");
}

#endif /* SONAME_LIBMBEDTLS && !HAVE_SECURITY_SECURITY_H && !SONAME_LIBGNUTLS */
