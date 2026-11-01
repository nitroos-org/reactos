/*
 * PFXImportCertStore, PFXExportCertStoreEx and PFXVerifyPassword
 *
 * Copyright 2019 Hans Leidekker for CodeWeavers
 * Copyright 2026 Tomas Srnka
 *
 * The PKCS #12 parser and writer (reactos/pkcs12.c) is self-contained; this file maps its results
 * onto CryptoAPI containers, certificate contexts and Windows error codes. The original Wine
 * implementation needed the gnutls based unix library, which does not exist here.
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

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincrypt.h"
#include "bcrypt.h"
#include "ncrypt.h"
#include "snmp.h"
#include "crypt32_private.h"
#include "reactos/pkcs12.h"
#include "reactos/cmsenv.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(crypt);

#ifndef PKCS12_IMPORT_SILENT
#define PKCS12_IMPORT_SILENT                    0x00000040
#endif
#ifndef PKCS12_PREFER_CNG_KSP
#define PKCS12_PREFER_CNG_KSP                   0x00000100
#endif
#ifndef PKCS12_ALWAYS_CNG_KSP
#define PKCS12_ALWAYS_CNG_KSP                   0x00000200
#endif
#ifndef PKCS12_ONLY_CERTIFICATES
#define PKCS12_ONLY_CERTIFICATES                0x00000400
#endif
#ifndef PKCS12_ONLY_NOT_ENCRYPTED_CERTIFICATES
#define PKCS12_ONLY_NOT_ENCRYPTED_CERTIFICATES  0x00000800
#endif
#ifndef PKCS12_ALLOW_OVERWRITE_KEY
#define PKCS12_ALLOW_OVERWRITE_KEY              0x00004000
#endif
#ifndef PKCS12_NO_PERSIST_KEY
#define PKCS12_NO_PERSIST_KEY                   0x00008000
#endif
#ifndef PKCS12_VIRTUAL_ISOLATION_KEY
#define PKCS12_VIRTUAL_ISOLATION_KEY            0x00010000
#endif
#ifndef PKCS12_INCLUDE_EXTENDED_PROPERTIES
#define PKCS12_INCLUDE_EXTENDED_PROPERTIES      0x00000010
#endif
#ifndef REPORT_NO_PRIVATE_KEY
#define REPORT_NO_PRIVATE_KEY                   0x00000001
#endif
#ifndef REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
#define REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY   0x00000002
#endif
#ifndef EXPORT_PRIVATE_KEYS
#define EXPORT_PRIVATE_KEYS                     0x00000004
#endif
#ifndef PKCS12_PROTECT_TO_DOMAIN_SIDS
#define PKCS12_PROTECT_TO_DOMAIN_SIDS           0x00000020
#endif
#ifndef PKCS12_EXPORT_SILENT
#define PKCS12_EXPORT_SILENT                    0x00000040
#endif
#ifndef PKCS12_EXPORT_PBES2_PARAMS
#define PKCS12_EXPORT_PBES2_PARAMS              0x00000080
#endif
#ifndef PKCS12_DISABLE_ENCRYPT_CERTIFICATES
#define PKCS12_DISABLE_ENCRYPT_CERTIFICATES     0x00000100
#endif
#ifndef PKCS12_ENCRYPT_CERTIFICATES
#define PKCS12_ENCRYPT_CERTIFICATES             0x00000200
#endif

#define PFX_IMPORT_FLAGS (CRYPT_EXPORTABLE | CRYPT_USER_PROTECTED | CRYPT_MACHINE_KEYSET | CRYPT_USER_KEYSET | \
                          PKCS12_INCLUDE_EXTENDED_PROPERTIES | PKCS12_IMPORT_SILENT | PKCS12_PREFER_CNG_KSP | \
                          PKCS12_ALWAYS_CNG_KSP | PKCS12_ONLY_CERTIFICATES | PKCS12_ONLY_NOT_ENCRYPTED_CERTIFICATES | \
                          PKCS12_ALLOW_OVERWRITE_KEY | PKCS12_NO_PERSIST_KEY | PKCS12_VIRTUAL_ISOLATION_KEY)
#define PFX_EXPORT_FLAGS (REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | EXPORT_PRIVATE_KEYS | \
                          PKCS12_INCLUDE_EXTENDED_PROPERTIES | PKCS12_PROTECT_TO_DOMAIN_SIDS | PKCS12_EXPORT_SILENT | \
                          PKCS12_EXPORT_PBES2_PARAMS | PKCS12_DISABLE_ENCRYPT_CERTIFICATES | PKCS12_ENCRYPT_CERTIFICATES)

#ifndef CERT_NCRYPT_KEY_SPEC
#define CERT_NCRYPT_KEY_SPEC 0xffffffff
#endif

#ifndef ERROR_INVALID_PASSWORD
#define ERROR_INVALID_PASSWORD 86
#endif

/* what the Windows implementation reports */
static DWORD p12_error_to_win32( int err )
{
    switch (err)
    {
    case P12_ERR_PASSWORD:    return ERROR_INVALID_PASSWORD;
    case P12_ERR_DECRYPT:     return NTE_BAD_DATA;
    case P12_ERR_NOMEM:       return ERROR_OUTOFMEMORY;
    case P12_ERR_UNSUPPORTED:
    case P12_ERR_RANDOM:      return NTE_FAIL;
    default:                  return CRYPT_E_BAD_ENCODE;    /* includes an iteration count over the limit */
    }
}

int p12_random( uint8_t *buf, size_t len )
{
    return BCryptGenRandom( NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG ) ? 1 : 0;
}

static const uint16_t *pfx_password( const WCHAR *password )
{
    return (const uint16_t *)password;
}

/* ------------------------------------------------------------------------------------------ */
/* import                                                                                     */
/* ------------------------------------------------------------------------------------------ */

static void make_container_name( WCHAR *name )
{
    static const WCHAR hex[] = L"0123456789ABCDEF";
    uint8_t r[16];
    unsigned i, o = 0;

    if (p12_random( r, sizeof(r) )) GetSystemTimeAsFileTime( (FILETIME *)r );
    name[o++] = '{';
    for (i = 0; i < 16; i++)
    {
        if (i == 4 || i == 6 || i == 8 || i == 10) name[o++] = '-';
        name[o++] = hex[r[i] >> 4];
        name[o++] = hex[r[i] & 15];
    }
    name[o++] = '}';
    name[o] = 0;
}

struct imported_key
{
    BYTE *blob;             /* CryptoAPI PRIVATEKEYBLOB, NULL if the key is not an RSA key */
    DWORD blob_len;
    WCHAR container[40];    /* persisted keys */
    BOOL  persisted;
};

static void delete_container( const WCHAR *container, DWORD flags )
{
    HCRYPTPROV prov;
    CryptAcquireContextW( &prov, container, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                          CRYPT_DELETEKEYSET | (flags & CRYPT_MACHINE_KEYSET) );
}

/* Imports the key into a new container (persisted) or an ephemeral provider. */
static HCRYPTPROV import_key( struct imported_key *key, DWORD flags )
{
    HCRYPTPROV prov = 0;
    HCRYPTKEY cryptkey;
    BOOL persist = !(flags & PKCS12_NO_PERSIST_KEY);
    DWORD acquire_flags = CRYPT_VERIFYCONTEXT;

    if (persist)
    {
        make_container_name( key->container );
        acquire_flags = CRYPT_NEWKEYSET | (flags & CRYPT_MACHINE_KEYSET);
    }
    if (!CryptAcquireContextW( &prov, persist ? key->container : NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES,
                               acquire_flags ))
    {
        WARN( "CryptAcquireContextW failed %08lx\n", GetLastError() );
        return 0;
    }
    if (!CryptImportKey( prov, key->blob, key->blob_len, 0, flags & CRYPT_EXPORTABLE, &cryptkey ))
    {
        DWORD err = GetLastError();
        WARN( "CryptImportKey failed %08lx\n", err );
        CryptReleaseContext( prov, 0 );
        if (persist) delete_container( key->container, flags );
        SetLastError( err );
        return 0;
    }
    CryptDestroyKey( cryptkey );
    if (persist) key->persisted = TRUE;
    return prov;
}

/* An ephemeral key asked for with the CNG key storage flags becomes an NCrypt key the certificate
 * owns (CERT_NCRYPT_KEY_HANDLE_PROP_ID), as on Windows: .NET reaches EphemeralKeySet keys that way. */
static BOOL set_ncrypt_key( const void *ctx, const BYTE *pkcs8, DWORD len, DWORD flags )
{
    NCRYPT_PROV_HANDLE prov;
    NCRYPT_KEY_HANDLE key;
    /* as on Windows an exportable key can be exported by PFXExportCertStoreEx, not in plaintext */
    DWORD policy = (flags & CRYPT_EXPORTABLE) ? NCRYPT_ALLOW_EXPORT_FLAG : 0;
    SECURITY_STATUS status;

    if ((status = NCryptOpenStorageProvider( &prov, MS_KEY_STORAGE_PROVIDER, 0 ))) return FALSE;
    status = NCryptImportKey( prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &key, (BYTE *)pkcs8, len,
                              NCRYPT_DO_NOT_FINALIZE_FLAG );
    NCryptFreeObject( prov );
    if (status)
    {
        WARN( "NCryptImportKey failed %08lx\n", status );
        return FALSE;
    }
    if (NCryptSetProperty( key, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE *)&policy, sizeof(policy), 0 ) ||
        NCryptFinalizeKey( key, 0 ) ||
        !CertSetCertificateContextProperty( ctx, CERT_NCRYPT_KEY_HANDLE_PROP_ID, 0, (void *)key ))
    {
        NCryptFreeObject( key );
        return FALSE;
    }
    return TRUE;
}

static BOOL set_key_context( const void *ctx, HCRYPTPROV prov )
{
    CERT_KEY_CONTEXT key_ctx;
    key_ctx.cbSize     = sizeof(key_ctx);
    key_ctx.hCryptProv = prov;
    key_ctx.dwKeySpec  = AT_KEYEXCHANGE;
    return CertSetCertificateContextProperty( ctx, CERT_KEY_CONTEXT_PROP_ID, 0, &key_ctx );
}

static BOOL set_key_prov_info( const void *ctx, const WCHAR *container, DWORD flags )
{
    CRYPT_KEY_PROV_INFO info;

    memset( &info, 0, sizeof(info) );
    info.pwszContainerName = (WCHAR *)container;
    info.pwszProvName      = (WCHAR *)MS_ENH_RSA_AES_PROV_W;
    info.dwProvType        = PROV_RSA_AES;
    info.dwFlags           = flags & CRYPT_MACHINE_KEYSET;
    info.dwKeySpec         = AT_KEYEXCHANGE;
    return CertSetCertificateContextProperty( ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, &info );
}

static BOOL id_equal( const struct p12_item *a, const struct p12_item *b )
{
    return a->id && b->id && a->id_len == b->id_len && !memcmp( a->id, b->id, a->id_len );
}

/* index of the key that belongs to the certificate: localKeyId first, then the public key */
static int find_key_for_cert( const struct p12_contents *c, const struct p12_item *cert )
{
    const BYTE *cert_mod, *key_mod;
    size_t cert_mod_len, key_mod_len, i;
    BOOL have_mod = !p12_cert_modulus( cert->data, cert->len, &cert_mod, &cert_mod_len );

    for (i = 0; i < c->nkeys; i++)
    {
        if (!id_equal( cert, &c->keys[i] )) continue;
        /* a localKeyId that matches a key of another certificate is not trusted blindly */
        if (!have_mod || (!p12_pkcs8_modulus( c->keys[i].data, c->keys[i].len, &key_mod, &key_mod_len ) &&
                          key_mod_len == cert_mod_len && !memcmp( key_mod, cert_mod, key_mod_len )))
            return i;
    }
    if (!have_mod) return -1;
    for (i = 0; i < c->nkeys; i++)
    {
        if (!p12_pkcs8_modulus( c->keys[i].data, c->keys[i].len, &key_mod, &key_mod_len ) &&
            key_mod_len == cert_mod_len && !memcmp( key_mod, cert_mod, key_mod_len ))
            return i;
    }
    return -1;
}

HCERTSTORE WINAPI PFXImportCertStore( CRYPT_DATA_BLOB *pfx, const WCHAR *password, DWORD flags )
{
    struct p12_contents contents;
    struct imported_key *keys = NULL;
    HCERTSTORE store = NULL;
    DWORD err = 0;
    size_t i;
    int r;

    if (!pfx)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return NULL;
    }
    if (flags & ~PFX_IMPORT_FLAGS)
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return NULL;
    }
    if (!pfx->pbData || !pfx->cbData)
    {
        SetLastError( CRYPT_E_BAD_ENCODE );
        return NULL;
    }
    /* There is no persisted CNG key storage: persisted RSA keys go to a CryptoAPI container (ephemeral
     * keys asked for with the CNG flags become NCrypt keys, see set_ncrypt_key). Windows uses the type 1 enhanced provider here, but that one cannot
     * sign with SHA-2, which is what callers that reach the key through the CSP interface (.NET
     * falling back from CNG) need; the AES provider is the same key store with the hashes. */
    if (flags & (PKCS12_PREFER_CNG_KSP | PKCS12_ALWAYS_CNG_KSP))
        TRACE( "CNG key storage requested (%08lx), using CryptoAPI\n", flags );

    if ((r = p12_parse( pfx->pbData, pfx->cbData, pfx_password( password ), &contents )))
    {
        SetLastError( p12_error_to_win32( r ) );
        return NULL;
    }
    if (!(keys = CryptMemAlloc( (contents.nkeys + 1) * sizeof(*keys) )))
    {
        err = ERROR_OUTOFMEMORY;
        goto done;
    }
    memset( keys, 0, (contents.nkeys + 1) * sizeof(*keys) );
    if (!(store = CertOpenStore( CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL )))
    {
        err = GetLastError();
        goto done;
    }
    err = 0;

    if (!(flags & PKCS12_ONLY_CERTIFICATES))
    {
        for (i = 0; i < contents.nkeys; i++)
        {
            size_t blob_len = 0;
            /* only RSA keys can be held by the CryptoAPI providers */
            if (p12_pkcs8_to_rsa_blob( contents.keys[i].data, contents.keys[i].len, &keys[i].blob, &blob_len ))
                keys[i].blob = NULL;
            keys[i].blob_len = blob_len;
        }
    }
    for (i = 0; i < contents.ncerts && !err; i++)
    {
        const struct p12_item *item = &contents.certs[i];
        PCCERT_CONTEXT ctx;
        int k = (flags & PKCS12_ONLY_CERTIFICATES) ? -1 : find_key_for_cert( &contents, item );
        BOOL ok = TRUE;

        if (!(ctx = CertCreateCertificateContext( X509_ASN_ENCODING, item->data, item->len )))
        {
            err = GetLastError();
            break;
        }
        if (item->name)
        {
            CRYPT_DATA_BLOB name;
            size_t len = 0;
            while (item->name[len]) len++;
            name.pbData = (BYTE *)item->name;
            name.cbData = (len + 1) * sizeof(WCHAR);
            CertSetCertificateContextProperty( ctx, CERT_FRIENDLY_NAME_PROP_ID, 0, &name );
        }
        /* the key goes on the context of the store: an NCrypt key is not copied with a context */
        {
            PCCERT_CONTEXT added;

            if (!CertAddCertificateContextToStore( store, ctx, CERT_STORE_ADD_ALWAYS, &added ))
            {
                err = GetLastError();
                CertFreeCertificateContext( ctx );
                break;
            }
            CertFreeCertificateContext( ctx );
            ctx = added;
        }
        if (k >= 0 && (flags & PKCS12_NO_PERSIST_KEY) && (flags & (PKCS12_PREFER_CNG_KSP | PKCS12_ALWAYS_CNG_KSP)) &&
            set_ncrypt_key( ctx, contents.keys[k].data, contents.keys[k].len, flags ))
            ;
        else if (k >= 0 && keys[k].blob)
        {
            if (flags & PKCS12_NO_PERSIST_KEY)
            {
                HCRYPTPROV prov = import_key( &keys[k], flags );
                if (!prov) ok = FALSE;
                else if (!set_key_context( ctx, prov ))
                {
                    CryptReleaseContext( prov, 0 );
                    ok = FALSE;
                }
            }
            else
            {
                if (!keys[k].persisted)
                {
                    HCRYPTPROV prov = import_key( &keys[k], flags );
                    if (!prov) ok = FALSE;
                    else CryptReleaseContext( prov, 0 );
                }
                if (ok) ok = set_key_prov_info( ctx, keys[k].container, flags );
            }
            if (!ok) err = GetLastError();
        }
        else if (k >= 0) WARN( "key of certificate %Iu is not an RSA key, importing the certificate only\n", i );
        CertFreeCertificateContext( ctx );
    }

done:
    if (err || !store)
    {
        if (!err) err = ERROR_INVALID_DATA;
        /* undo what was persisted */
        for (i = 0; keys && i < contents.nkeys; i++)
            if (keys[i].persisted) delete_container( keys[i].container, flags );
        if (store) CertCloseStore( store, 0 );
        store = NULL;
    }
    for (i = 0; keys && i < contents.nkeys; i++)
    {
        if (keys[i].blob) { SecureZeroMemory( keys[i].blob, keys[i].blob_len ); p12_free( keys[i].blob ); }
    }
    CryptMemFree( keys );
    p12_free_contents( &contents );
    if (err) SetLastError( err );
    return store;
}

BOOL WINAPI PFXVerifyPassword( CRYPT_DATA_BLOB *pfx, const WCHAR *password, DWORD flags )
{
    TRACE( "(%p, %p, %08lx)\n", pfx, password, flags );

    if (!pfx || !pfx->pbData || !pfx->cbData) return FALSE;
    return !p12_verify_password( pfx->pbData, pfx->cbData, pfx_password( password ) );
}

/* ------------------------------------------------------------------------------------------ */
/* export                                                                                     */
/* ------------------------------------------------------------------------------------------ */

typedef LONG (WINAPI *PNCryptOpenStorageProvider)( ULONG_PTR *, LPCWSTR, DWORD );
typedef LONG (WINAPI *PNCryptOpenKey)( ULONG_PTR, ULONG_PTR *, LPCWSTR, DWORD, DWORD );
typedef LONG (WINAPI *PNCryptExportKey)( ULONG_PTR, ULONG_PTR, LPCWSTR, void *, BYTE *, DWORD, DWORD *, DWORD );
typedef LONG (WINAPI *PNCryptFreeObject)( ULONG_PTR );
typedef LONG (WINAPI *PNCryptGetProperty)( ULONG_PTR, LPCWSTR, BYTE *, DWORD, DWORD *, DWORD );
typedef LONG (WINAPI *PNCryptSetProperty)( ULONG_PTR, LPCWSTR, BYTE *, DWORD, DWORD );

/* PKCS #8 PrivateKeyInfo of a CNG key, from a key handle or a provider/key name */
static BOOL export_cng_key( ULONG_PTR key, const WCHAR *prov_name, const WCHAR *key_name, DWORD flags,
                            BYTE **pkcs8, DWORD *len )
{
    HMODULE mod = CMSEnv_LoadNcrypt();
    PNCryptOpenStorageProvider open_provider;
    PNCryptOpenKey open_key;
    PNCryptExportKey export_key;
    PNCryptFreeObject free_object;
    PNCryptGetProperty get_property;
    PNCryptSetProperty set_property;
    ULONG_PTR provider = 0, opened = 0;
    DWORD policy = 0, size, raised = FALSE;
    BOOL ret = FALSE;

    if (!mod) return FALSE;
    open_provider = (PNCryptOpenStorageProvider)GetProcAddress( mod, "NCryptOpenStorageProvider" );
    open_key = (PNCryptOpenKey)GetProcAddress( mod, "NCryptOpenKey" );
    export_key = (PNCryptExportKey)GetProcAddress( mod, "NCryptExportKey" );
    free_object = (PNCryptFreeObject)GetProcAddress( mod, "NCryptFreeObject" );
    get_property = (PNCryptGetProperty)GetProcAddress( mod, "NCryptGetProperty" );
    set_property = (PNCryptSetProperty)GetProcAddress( mod, "NCryptSetProperty" );
    if (!open_provider || !open_key || !export_key || !free_object || !get_property || !set_property) goto done;

    if (!key)
    {
        if (open_provider( &provider, prov_name, 0 ) || open_key( provider, &opened, key_name, 0, flags & CRYPT_MACHINE_KEYSET ? 0x20 : 0 ))
            goto done;
        key = opened;
    }
    /* A key that may be exported is read here for the PFX, whatever it allows an application to do with it:
     * the plaintext export right is added for the time of the export. */
    if (!get_property( key, L"Export Policy", (BYTE *)&policy, sizeof(policy), &size, 0 ) && (policy & 1) &&
        !(policy & 2))
        raised = !set_property( key, L"Export Policy", (BYTE *)&(DWORD){ policy | 2 }, sizeof(DWORD), 0 );
    *len = 0;
    if (export_key( key, 0, L"PKCS8_PRIVATEKEY", NULL, NULL, 0, len, 0 ) || !*len) goto done;
    if (!(*pkcs8 = CryptMemAlloc( *len ))) goto done;
    if (export_key( key, 0, L"PKCS8_PRIVATEKEY", NULL, *pkcs8, *len, len, 0 ))
    {
        SecureZeroMemory( *pkcs8, *len );
        CryptMemFree( *pkcs8 );
        *pkcs8 = NULL;
        goto done;
    }
    ret = TRUE;
done:
    if (raised) set_property( key, L"Export Policy", (BYTE *)&policy, sizeof(policy), 0 );
    if (opened) free_object( opened );
    if (provider) free_object( provider );
    FreeLibrary( mod );
    return ret;
}

static BOOL export_capi_key( HCRYPTPROV prov, DWORD keyspec, BYTE **pkcs8, DWORD *len )
{
    HCRYPTKEY key;
    DWORD blob_len = 0;
    BYTE *blob = NULL;
    size_t out_len;
    BOOL ret = FALSE;

    if (!CryptGetUserKey( prov, keyspec ? keyspec : AT_KEYEXCHANGE, &key )) return FALSE;
    if (CryptExportKey( key, 0, PRIVATEKEYBLOB, 0, NULL, &blob_len ) && (blob = CryptMemAlloc( blob_len )))
    {
        if (CryptExportKey( key, 0, PRIVATEKEYBLOB, 0, blob, &blob_len ) &&
            !p12_rsa_blob_to_pkcs8( blob, blob_len, pkcs8, &out_len ))
        {
            *len = out_len;
            ret = TRUE;
        }
        SecureZeroMemory( blob, blob_len );
    }
    CryptMemFree( blob );
    CryptDestroyKey( key );
    return ret;
}

enum key_result { KEY_NONE, KEY_OK, KEY_NOT_EXPORTABLE, KEY_MISSING };

/* Finds the private key of the certificate and returns it as PKCS #8. The memory is from CryptMemAlloc. */
static enum key_result get_private_key( PCCERT_CONTEXT ctx, BYTE **pkcs8, DWORD *len, DWORD *err )
{
    BYTE buf[sizeof(CERT_KEY_CONTEXT) + 64];
    CRYPT_KEY_PROV_INFO *info = NULL;
    DWORD size = 0;
    enum key_result result = KEY_NONE;
    ULONG_PTR ncrypt = 0;

    *pkcs8 = NULL;
    *err = 0;

    size = sizeof(buf);
    if (CertGetCertificateContextProperty( ctx, CERT_NCRYPT_KEY_HANDLE_PROP_ID, buf, &size ) && size >= sizeof(ncrypt))
    {
        memcpy( &ncrypt, buf, sizeof(ncrypt) );
        if (export_cng_key( ncrypt, NULL, NULL, 0, pkcs8, len )) return KEY_OK;
        *err = NTE_BAD_KEY_STATE;
        return KEY_NOT_EXPORTABLE;
    }

    size = sizeof(buf);
    if (CertGetCertificateContextProperty( ctx, CERT_KEY_CONTEXT_PROP_ID, buf, &size ) && size >= sizeof(CERT_KEY_CONTEXT))
    {
        CERT_KEY_CONTEXT *kc = (CERT_KEY_CONTEXT *)buf;
        if (kc->dwKeySpec == CERT_NCRYPT_KEY_SPEC)
        {
            if (export_cng_key( (ULONG_PTR)kc->hCryptProv, NULL, NULL, 0, pkcs8, len )) return KEY_OK;
        }
        else if (kc->hCryptProv)
        {
            if (export_capi_key( kc->hCryptProv, kc->dwKeySpec, pkcs8, len )) return KEY_OK;
        }
        *err = NTE_BAD_KEY_STATE;
        return KEY_NOT_EXPORTABLE;
    }

    size = 0;
    if (CertGetCertificateContextProperty( ctx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &size ) && (info = CryptMemAlloc( size )))
    {
        if (CertGetCertificateContextProperty( ctx, CERT_KEY_PROV_INFO_PROP_ID, info, &size ))
        {
            if (!info->dwProvType)
            {
                if (export_cng_key( 0, info->pwszProvName, info->pwszContainerName, info->dwFlags, pkcs8, len ))
                    result = KEY_OK;
                else
                {
                    result = KEY_NOT_EXPORTABLE;
                    *err = NTE_BAD_KEY_STATE;
                }
            }
            else
            {
                HCRYPTPROV prov;
                if (!CryptAcquireContextW( &prov, info->pwszContainerName, info->pwszProvName, info->dwProvType,
                                           CRYPT_SILENT | (info->dwFlags & CRYPT_MACHINE_KEYSET) ))
                {
                    *err = GetLastError();
                    result = KEY_MISSING;
                }
                else
                {
                    if (export_capi_key( prov, info->dwKeySpec, pkcs8, len )) result = KEY_OK;
                    else
                    {
                        result = KEY_NOT_EXPORTABLE;
                        *err = NTE_BAD_KEY_STATE;
                    }
                    CryptReleaseContext( prov, 0 );
                }
            }
        }
        CryptMemFree( info );
    }
    return result;
}

struct export_cert
{
    PCCERT_CONTEXT ctx;
    BYTE          *pkcs8;
    DWORD          pkcs8_len;
    uint8_t        id[4];
    WCHAR         *name;
};

struct pbes2_export_params
{
    DWORD  dwSize;
    void  *hNcryptDescriptor;
    WCHAR *pwszPbes2Alg;
};

BOOL WINAPI PFXExportCertStore( HCERTSTORE store, CRYPT_DATA_BLOB *pfx, const WCHAR *password, DWORD flags )
{
    return PFXExportCertStoreEx( store, pfx, password, NULL, flags );
}

BOOL WINAPI PFXExportCertStoreEx( HCERTSTORE store, CRYPT_DATA_BLOB *pfx, const WCHAR *password, void *reserved,
                                  DWORD flags )
{
    struct export_cert *certs = NULL;
    struct p12_item *items = NULL, *keys = NULL;
    struct p12_write_params params = { 0, 0 };
    PCCERT_CONTEXT ctx = NULL;
    size_t count = 0, cap = 0, nkeys = 0, i;
    uint8_t *out = NULL;
    size_t out_len = 0;
    DWORD err = 0;
    BOOL ret = FALSE, zero_error = FALSE;
    int r;

    TRACE( "(%p, %p, %p, %p, %08lx)\n", store, pfx, password, reserved, flags );

    if (!store || !pfx || (flags & ~PFX_EXPORT_FLAGS))
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    if (flags & PKCS12_PROTECT_TO_DOMAIN_SIDS)
    {
        SetLastError( ERROR_NOT_SUPPORTED );
        return FALSE;
    }
    if ((flags & PKCS12_EXPORT_PBES2_PARAMS) && reserved)
    {
        const struct pbes2_export_params *p = reserved;
        if (p->dwSize < sizeof(*p) || p->hNcryptDescriptor)
        {
            SetLastError( p->dwSize < sizeof(*p) ? ERROR_INVALID_PARAMETER : NTE_NOT_SUPPORTED );
            return FALSE;
        }
        params.flags |= P12_WRITE_PBES2;
    }
    if (flags & PKCS12_DISABLE_ENCRYPT_CERTIFICATES) params.flags |= P12_WRITE_PLAIN_CERTS;

    while ((ctx = CertEnumCertificatesInStore( store, ctx )))
    {
        struct export_cert *ec;
        DWORD size = 0;

        if (count == cap)
        {
            struct export_cert *n = CryptMemAlloc( (cap ? cap * 2 : 8) * sizeof(*n) );
            if (!n) { err = ERROR_OUTOFMEMORY; CertFreeCertificateContext( ctx ); break; }
            if (count) memcpy( n, certs, count * sizeof(*n) );
            CryptMemFree( certs );
            certs = n;
            cap = cap ? cap * 2 : 8;
        }
        ec = &certs[count];
        memset( ec, 0, sizeof(*ec) );
        ec->ctx = CertDuplicateCertificateContext( ctx );
        count++;

        if (CertGetCertificateContextProperty( ctx, CERT_FRIENDLY_NAME_PROP_ID, NULL, &size ) && size >= sizeof(WCHAR) &&
            (ec->name = CryptMemAlloc( size + sizeof(WCHAR) )))
        {
            if (CertGetCertificateContextProperty( ctx, CERT_FRIENDLY_NAME_PROP_ID, ec->name, &size ))
                ec->name[size / sizeof(WCHAR)] = 0;
            else
            {
                CryptMemFree( ec->name );
                ec->name = NULL;
            }
        }
        if (flags & EXPORT_PRIVATE_KEYS)
        {
            DWORD key_err;
            switch (get_private_key( ctx, &ec->pkcs8, &ec->pkcs8_len, &key_err ))
            {
            case KEY_OK:
                nkeys++;
                ec->id[0] = (uint8_t)nkeys; ec->id[1] = (uint8_t)(nkeys >> 8);
                ec->id[2] = (uint8_t)(nkeys >> 16); ec->id[3] = (uint8_t)(nkeys >> 24);
                break;
            case KEY_NOT_EXPORTABLE:
                if (flags & REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY) err = key_err;
                break;
            case KEY_MISSING:
                if (flags & REPORT_NO_PRIVATE_KEY) err = key_err;
                break;
            default:
                break;
            }
            if (err) { CertFreeCertificateContext( ctx ); break; }
        }
    }
    if (err) goto done;

    items = CryptMemAlloc( (count + 1) * sizeof(*items) );
    keys = CryptMemAlloc( (nkeys + 1) * sizeof(*keys) );
    if (!items || !keys) { err = ERROR_OUTOFMEMORY; goto done; }
    memset( items, 0, (count + 1) * sizeof(*items) );
    memset( keys, 0, (nkeys + 1) * sizeof(*keys) );
    for (i = 0, nkeys = 0; i < count; i++)
    {
        struct export_cert *ec = &certs[i];
        items[i].data = ec->ctx->pbCertEncoded;
        items[i].len = ec->ctx->cbCertEncoded;
        items[i].name = (uint16_t *)ec->name;
        if (ec->pkcs8)
        {
            /* the key and its certificate are tied together by a localKeyId, as Windows writes it */
            items[i].id = ec->id;
            items[i].id_len = 4;
            keys[nkeys].data = ec->pkcs8;
            keys[nkeys].len = ec->pkcs8_len;
            keys[nkeys].id = ec->id;
            keys[nkeys].id_len = 4;
            keys[nkeys].name = (uint16_t *)ec->name;
            nkeys++;
        }
    }

    if ((r = p12_write( items, count, keys, nkeys, pfx_password( password ), &params, &out, &out_len )))
    {
        err = p12_error_to_win32( r );
        goto done;
    }
    if (!pfx->pbData) { pfx->cbData = out_len; ret = TRUE; }
    else if (pfx->cbData < out_len)
    {
        /* the size is reported, but Windows fails without an error code here */
        pfx->cbData = out_len;
        zero_error = TRUE;
    }
    else
    {
        memcpy( pfx->pbData, out, out_len );
        pfx->cbData = out_len;
        ret = TRUE;
    }

done:
    if (out) { SecureZeroMemory( out, out_len ); p12_free( out ); }
    for (i = 0; i < count; i++)
    {
        if (certs[i].pkcs8)
        {
            SecureZeroMemory( certs[i].pkcs8, certs[i].pkcs8_len );
            CryptMemFree( certs[i].pkcs8 );
        }
        CryptMemFree( certs[i].name );
        CertFreeCertificateContext( certs[i].ctx );
    }
    CryptMemFree( certs );
    CryptMemFree( items );
    CryptMemFree( keys );
    if (!ret) SetLastError( err || zero_error ? err : ERROR_INVALID_DATA );
    return ret;
}
