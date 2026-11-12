/*
 * MSSIGN32 implementation
 *
 * Copyright 2009 Austin English
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
#include <stdlib.h>

#include "windef.h"
#include "winbase.h"
#include "wincrypt.h"
#include "wintrust.h"
#include "mssip.h"
#include "imagehlp.h"

#include "wine/debug.h"
#include "wine/mssign.h"

WINE_DEFAULT_DEBUG_CHANNEL(mssign);

HRESULT WINAPI PvkGetCryptProv(HWND hwnd, LPCWSTR pwszCaption, LPCWSTR pwszCapiProvider,
                    DWORD dwProviderType, LPCWSTR pwszPvkFile, LPCWSTR pwszKeyContainerName,
                    DWORD *pdwKeySpec, LPWSTR *ppwszTmpContainer, HCRYPTPROV *phCryptProv)
{
    FIXME("%p %s %s %ld %s %s %p %p %p stub\n", hwnd, debugstr_w(pwszCaption), debugstr_w(pwszCapiProvider),
                    dwProviderType, debugstr_w(pwszPvkFile), debugstr_w(pwszKeyContainerName),
                    pdwKeySpec, ppwszTmpContainer, phCryptProv);

    return E_FAIL;
}

BOOL WINAPI PvkPrivateKeyAcquireContextFromMemory(LPCWSTR pwszProvName, DWORD dwProvType,
                    BYTE *pbData, DWORD cbData, HWND hwndOwner, LPCWSTR pwszKeyName,
                    DWORD *pdwKeySpec, HCRYPTPROV *phCryptProv, LPWSTR *ppwszTmpContainer)
{
    FIXME("%s %ld %p %ld %p %s %p %p %p stub\n", debugstr_w(pwszProvName), dwProvType,
                    pbData, cbData, hwndOwner, debugstr_w(pwszKeyName), pdwKeySpec,
                    phCryptProv, ppwszTmpContainer);

    return FALSE;
}

void WINAPI PvkFreeCryptProv(HCRYPTPROV hProv, LPCWSTR pwszCapiProvider, DWORD dwProviderType,
                    LPWSTR pwszTmpContainer)
{
    FIXME("%08Ix %s %ld %s stub\n", hProv, debugstr_w(pwszCapiProvider), dwProviderType,
                    debugstr_w(pwszTmpContainer));
}


#define SIGNER_SUBJECT_FILE 1
#define SIGNER_SUBJECT_BLOB 2
#define PVK_TYPE_KEYCONTAINER 2
#define SIGNER_PE_FLAGS_MASK (SPC_INC_PE_PAGE_HASHES_FLAG | SPC_EXC_PE_PAGE_HASHES_FLAG | SPC_INC_PE_RESOURCES_FLAG | \
                              SPC_INC_PE_DEBUG_INFO_FLAG | SPC_INC_PE_IMPORT_ADDR_TABLE_FLAG)
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define MAX_ATTRS 16

struct buf
{
    BYTE *data;
    DWORD len;
};

static void buf_free(struct buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

/* DER: tag, length, then the parts one after another */
static BOOL der_wrap(struct buf *out, BYTE tag, const struct buf *parts, unsigned int count)
{
    DWORD len = 0, ll, i;
    BYTE *p;

    for (i = 0; i < count; i++) len += parts[i].len;
    ll = len < 0x80 ? 1 : len < 0x100 ? 2 : len < 0x10000 ? 3 : 4;
    if (!(p = malloc(1 + ll + len))) return FALSE;
    out->data = p;
    out->len = 1 + ll + len;
    *p++ = tag;
    if (ll == 1) *p++ = len;
    else
    {
        *p++ = 0x80 | (ll - 1);
        if (ll == 4) *p++ = len >> 16;
        if (ll >= 3) *p++ = len >> 8;
        *p++ = len;
    }
    for (i = 0; i < count; i++)
    {
        memcpy(p, parts[i].data, parts[i].len);
        p += parts[i].len;
    }
    return TRUE;
}

/* DER of an OBJECT IDENTIFIER from its dotted string (crypt32 has no encoder for it) */
static BOOL der_oid(const char *oid, BYTE **out, DWORD *out_len)
{
    BYTE body[64], *p = body;
    DWORD arcs[16], n = 0, i;
    const char *s = oid;
    BYTE *ret;

    while (*s && n < ARRAYSIZE(arcs))
    {
        char *end;
        arcs[n++] = strtoul(s, &end, 10);
        if (end == s) return FALSE;
        s = *end == '.' ? end + 1 : end;
        if (!*end) break;
    }
    if (n < 2 || arcs[0] > 2) return FALSE;
    arcs[1] += arcs[0] * 40;
    for (i = 1; i < n; i++)
    {
        DWORD v = arcs[i], shift = 28;

        if (p - body > 48) return FALSE;
        while (shift && !(v >> shift)) shift -= 7;
        for (; shift; shift -= 7) *p++ = 0x80 | ((v >> shift) & 0x7f);
        *p++ = v & 0x7f;
    }
    if (!(ret = malloc(2 + (p - body)))) return FALSE;
    ret[0] = 6;
    ret[1] = p - body;
    memcpy(ret + 2, body, p - body);
    *out = ret;
    *out_len = 2 + (p - body);
    return TRUE;
}

static BOOL encode_oid(const char *oid, struct buf *out)
{
    return der_oid(oid, &out->data, &out->len);
}

static BOOL encode(LPCSTR type, const void *data, struct buf *out)
{
    BYTE *p = NULL;
    DWORD len = 0;

    if (!CryptEncodeObjectEx(ENCODING, type, data, CRYPT_ENCODE_ALLOC_FLAG, NULL, &p, &len)) return FALSE;
    out->data = malloc(len);
    if (out->data)
    {
        memcpy(out->data, p, len);
        out->len = len;
    }
    LocalFree(p);
    return !!out->data;
}

static HRESULT hr_last(void)
{
    DWORD err = GetLastError();
    return err ? HRESULT_FROM_WIN32(err) : E_FAIL;
}

struct signer
{
    HCRYPTPROV prov;
    DWORD keyspec;
    BOOL free_prov;
    const CERT_CONTEXT *cert;
    HCERTSTORE store;
    DWORD policy;
};

static void signer_free(struct signer *s)
{
    if (s->free_prov && s->prov) CryptReleaseContext(s->prov, 0);
    if (s->cert) CertFreeCertificateContext(s->cert);
    if (s->store) CertCloseStore(s->store, 0);
    memset(s, 0, sizeof(*s));
}

/* The signing certificate and its key. The certificate comes from the caller (or an SPC file); without a provider the
 * key is the one the certificate is linked to, with one it is the named key container. */
static HRESULT signer_open(const SIGNER_CERT *sc, const SIGNER_PROVIDER_INFO *provider, struct signer *s)
{
    memset(s, 0, sizeof(*s));
    switch (sc->dwCertChoice)
    {
    case SIGNER_CERT_STORE:
    {
        const SIGNER_CERT_STORE_INFO *info = sc->pCertStoreInfo;

        if (!info || info->cbSize < sizeof(*info) || !info->pSigningCert) return E_INVALIDARG;
        s->cert = CertDuplicateCertificateContext(info->pSigningCert);
        s->policy = info->dwCertPolicy;
        if (info->hCertStore) s->store = CertDuplicateStore(info->hCertStore);
        break;
    }
    case SIGNER_CERT_SPC_FILE:
    case SIGNER_CERT_SPC_CHAIN:
    {
        const WCHAR *file = sc->dwCertChoice == SIGNER_CERT_SPC_FILE ? sc->pwszSpcFile
                                                                     : sc->pSpcChainInfo ? sc->pSpcChainInfo->pwszSpcFile : NULL;

        if (!file || !provider) return E_INVALIDARG;
        s->policy = sc->dwCertChoice == SIGNER_CERT_SPC_CHAIN ? sc->pSpcChainInfo->dwCertPolicy : SIGNER_CERT_POLICY_STORE;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, file, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
                              CERT_QUERY_CONTENT_FLAG_CERT | CERT_QUERY_CONTENT_FLAG_SERIALIZED_STORE,
                              CERT_QUERY_FORMAT_FLAG_ALL, 0, NULL, NULL, NULL, &s->store, NULL, NULL))
            return hr_last();
        break;
    }
    default:
        return E_INVALIDARG;
    }

    if (provider)
    {
        const WCHAR *container = provider->dwPvkChoice == PVK_TYPE_KEYCONTAINER ? provider->pwszKeyContainer : NULL;

        if (!container) { signer_free(s); return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED); }
        if (!CryptAcquireContextW(&s->prov, container, provider->pwszProviderName, provider->dwProviderType, 0))
        {
            HRESULT hr = hr_last();
            signer_free(s);
            return hr;
        }
        s->free_prov = TRUE;
        s->keyspec = provider->dwKeySpec ? provider->dwKeySpec : AT_SIGNATURE;
        if (!s->cert)
        {
            /* the certificate of the file whose public key is the container's */
            CERT_PUBLIC_KEY_INFO *pub = NULL;
            DWORD size = 0;

            if (CryptExportPublicKeyInfo(s->prov, s->keyspec, ENCODING, NULL, &size) && (pub = malloc(size)) &&
                CryptExportPublicKeyInfo(s->prov, s->keyspec, ENCODING, pub, &size))
                s->cert = CertFindCertificateInStore(s->store, ENCODING, 0, CERT_FIND_PUBLIC_KEY, pub, NULL);
            free(pub);
            if (!s->cert) { signer_free(s); return CRYPT_E_NOT_FOUND; }
        }
    }
    else
    {
        BOOL must_free = FALSE;

        if (!CryptAcquireCertificatePrivateKey(s->cert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG | CRYPT_ACQUIRE_SILENT_FLAG, NULL, &s->prov, &s->keyspec,
                                               &must_free))
        {
            HRESULT hr = hr_last();
            signer_free(s);
            return hr;
        }
        s->free_prov = must_free;
    }
    return S_OK;
}

/* [0] IMPLICIT SET OF certificate: the signer's, plus its chain and/or the whole store as the policy says */
static HRESULT signer_certs(struct signer *s, struct buf *out)
{
    struct buf *list = NULL;
    DWORD count = 0, cap = 0, i;
    const CERT_CONTEXT *c, *prev = NULL;
    HRESULT hr = S_OK;

#define ADD_CERT(ctx) do { \
        const CERT_CONTEXT *add_ = (ctx); \
        BOOL dup_ = FALSE; \
        for (i = 0; i < count; i++) \
            if (list[i].len == add_->cbCertEncoded && !memcmp(list[i].data, add_->pbCertEncoded, list[i].len)) dup_ = TRUE; \
        if (!dup_) \
        { \
            if (count == cap) \
            { \
                struct buf *n_ = realloc(list, (cap += 8) * sizeof(*list)); \
                if (!n_) { hr = E_OUTOFMEMORY; goto done; } \
                list = n_; \
            } \
            if (!(list[count].data = malloc(add_->cbCertEncoded))) { hr = E_OUTOFMEMORY; goto done; } \
            memcpy(list[count].data, add_->pbCertEncoded, add_->cbCertEncoded); \
            list[count++].len = add_->cbCertEncoded; \
        } \
    } while (0)

    ADD_CERT(s->cert);
    if (s->policy & (SIGNER_CERT_POLICY_CHAIN | SIGNER_CERT_POLICY_CHAIN_NO_ROOT))
    {
        CERT_CHAIN_PARA para = { sizeof(para) };
        const CERT_CHAIN_CONTEXT *chain;

        if (CertGetCertificateChain(NULL, s->cert, NULL, s->store, &para, 0, NULL, &chain))
        {
            if (chain->cChain)
            {
                CERT_SIMPLE_CHAIN *simple = chain->rgpChain[0];

                for (i = 1; i < simple->cElement; i++)
                {
                    c = simple->rgpElement[i]->pCertContext;
                    if ((s->policy & SIGNER_CERT_POLICY_CHAIN_NO_ROOT) && i == simple->cElement - 1 &&
                        CertCompareCertificateName(ENCODING, &c->pCertInfo->Subject, &c->pCertInfo->Issuer))
                        continue;
                    ADD_CERT(c);
                }
            }
            CertFreeCertificateChain(chain);
        }
    }
    if ((s->policy & SIGNER_CERT_POLICY_STORE) && s->store)
    {
        while ((c = CertEnumCertificatesInStore(s->store, prev)))
        {
            ADD_CERT(c);
            prev = c;
        }
    }
#undef ADD_CERT
    if (!der_wrap(out, 0xa0, list, count)) hr = E_OUTOFMEMORY;

done:
    for (i = 0; i < count; i++) free(list[i].data);
    free(list);
    return hr;
}

static BOOL set_attr(CRYPT_ATTRIBUTE *attr, CRYPT_ATTR_BLOB *blob, const char *oid, const struct buf *value)
{
    blob->cbData = value->len;
    blob->pbData = value->data;
    attr->pszObjId = (char *)oid;
    attr->cValue = 1;
    attr->rgValue = blob;
    return TRUE;
}

static HRESULT replace_signature(HANDLE file, const WCHAR *name, DWORD flags, const GUID *guid, const SIP_DISPATCH_INFO *sip,
                                 const struct buf *msg, DWORD *index)
{
    SIP_SUBJECTINFO info = { sizeof(info) };
    DWORD count = 0;

    info.pgSubjectType = (GUID *)guid;
    info.hFile = file;
    info.pwsFileName = name;
    info.dwEncodingType = ENCODING;
    info.dwFlags = flags;
    /* signing a signed file replaces its signature */
    if (ImageEnumerateCertificates(file, CERT_SECTION_TYPE_ANY, &count, NULL, 0))
        while (count--) sip->pfRemove(&info, count);
    *index = 0;
    if (!sip->pfPut(&info, ENCODING, index, msg->len, msg->data)) return hr_last();
    return S_OK;
}

static HRESULT sign_file(DWORD flags, SIGNER_SUBJECT_INFO *subject, SIGNER_CERT *signer_cert,
                         SIGNER_SIGNATURE_INFO *sig_info, SIGNER_PROVIDER_INFO *provider, SIGNER_CONTEXT **context)
{
    static const BYTE null_params[] = { 5, 0 };
    SIGNER_FILE_INFO *file_info;
    struct signer signer;
    SIP_SUBJECTINFO sip_info = { sizeof(sip_info) };
    SIP_DISPATCH_INFO sip = { sizeof(sip) };
    SIP_INDIRECT_DATA *indirect = NULL;
    struct buf content = { 0 }, md = { 0 }, ct = { 0 }, opus = { 0 }, stmt = { 0 }, attr_set = { 0 }, signer_info = { 0 },
               certs = { 0 }, msg = { 0 };
    CRYPT_ATTRIBUTE attrs[MAX_ATTRS];
    CRYPT_ATTR_BLOB blobs[MAX_ATTRS];
    CRYPT_ATTRIBUTES attr_list;
    CMSG_SIGNER_INFO si = { 0 };
    DWORD indirect_size = 0, content_off, i, sig_len = 0, index, hash_size, n_attrs = 0;
    HCRYPTPROV hp = 0;
    HCRYPTHASH hash = 0;
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE digest[64], *sig = NULL;
    CRYPT_HASH_BLOB digest_blob;
    ALG_ID alg;
    const char *alg_oid;
    char *oid_ptr;
    HRESULT hr;
    GUID guid;
    BOOL opened = FALSE;

    if (!subject || !signer_cert || !sig_info || subject->cbSize < sizeof(*subject) ||
        signer_cert->cbSize < sizeof(*signer_cert) || sig_info->cbSize < sizeof(*sig_info))
        return E_INVALIDARG;
    if (subject->dwSubjectChoice == SIGNER_SUBJECT_BLOB) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    if (subject->dwSubjectChoice != SIGNER_SUBJECT_FILE || !(file_info = subject->pSignerFileInfo) ||
        file_info->cbSize < sizeof(*file_info) || (!file_info->pwszFileName && !file_info->hFile))
        return E_INVALIDARG;

    alg = sig_info->algidHash ? sig_info->algidHash : CALG_SHA1;
    if (!(alg_oid = CertAlgIdToOID(alg))) return NTE_BAD_ALGID;
    if (FAILED(hr = signer_open(signer_cert, provider, &signer))) return hr;

    if (file_info->hFile && file_info->hFile != INVALID_HANDLE_VALUE) file = file_info->hFile;
    else
    {
        file = CreateFileW(file_info->pwszFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, 0, NULL);
        opened = TRUE;
    }
    if (file == INVALID_HANDLE_VALUE) { hr = hr_last(); goto done; }

    /* the subject's SIP builds the SpcIndirectDataContent: what is signed and the digest of the subject */
    if (!CryptSIPRetrieveSubjectGuid(file_info->pwszFileName, file, &guid) || !CryptSIPLoad(&guid, 0, &sip))
    {
        hr = hr_last();
        if (hr == S_OK || hr == E_FAIL) hr = TRUST_E_SUBJECT_FORM_UNKNOWN;
        goto done;
    }
    sip_info.pgSubjectType = &guid;
    sip_info.hFile = file;
    sip_info.pwsFileName = file_info->pwszFileName;
    sip_info.DigestAlgorithm.pszObjId = (char *)alg_oid;
    sip_info.dwFlags = flags & SIGNER_PE_FLAGS_MASK;
    sip_info.dwEncodingType = ENCODING;
    sip_info.hProv = signer.prov;
    if (!sip.pfCreate(&sip_info, &indirect_size, NULL) || !(indirect = calloc(1, indirect_size)))
    {
        hr = hr_last();
        goto done;
    }
    if (!sip.pfCreate(&sip_info, &indirect_size, indirect)) { hr = hr_last(); goto done; }
    if (!encode(SPC_INDIRECT_DATA_CONTENT_STRUCT, indirect, &content)) { hr = hr_last(); goto done; }

    /* the message digest attribute covers the content octets of that SEQUENCE, not its tag and length */
    content_off = 1 + (content.data[1] < 0x80 ? 1 : 1 + (content.data[1] & 0x7f));
    if (!CryptAcquireContextW(&hp, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(hp, alg, 0, 0, &hash) ||
        !CryptHashData(hash, content.data + content_off, content.len - content_off, 0))
    {
        hr = hr_last();
        goto done;
    }
    hash_size = sizeof(digest);
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &hash_size, 0)) { hr = hr_last(); goto done; }
    digest_blob.cbData = hash_size;
    digest_blob.pbData = digest;
    if (!encode(X509_OCTET_STRING, &digest_blob, &md)) { hr = hr_last(); goto done; }
    oid_ptr = (char *)SPC_INDIRECT_DATA_OBJID;
    if (!encode_oid(oid_ptr, &ct)) { hr = hr_last(); goto done; }

    set_attr(&attrs[n_attrs], &blobs[n_attrs], szOID_RSA_contentType, &ct);
    n_attrs++;
    if (sig_info->dwAttrChoice == SIGNER_AUTHCODE_ATTR && sig_info->pAttrAuthcode)
    {
        SIGNER_ATTR_AUTHCODE *ac = sig_info->pAttrAuthcode;
        SPC_SP_OPUS_INFO info = { 0 };
        SPC_LINK more = { SPC_URL_LINK_CHOICE };
        char *purpose_oids[1];

        if (ac->cbSize < sizeof(*ac)) { hr = E_INVALIDARG; goto done; }
        info.pwszProgramName = (WCHAR *)ac->pwszName;
        if (ac->pwszInfo)
        {
            more.pwszUrl = (WCHAR *)ac->pwszInfo;
            info.pMoreInfo = &more;
        }
        if (!encode(SPC_SP_OPUS_INFO_STRUCT, &info, &opus)) { hr = hr_last(); goto done; }
        set_attr(&attrs[n_attrs], &blobs[n_attrs], SPC_SP_OPUS_INFO_OBJID, &opus);
        n_attrs++;
        if (ac->fCommercial || ac->fIndividual)
        {
            /* SpcStatementType: the key purpose the signature is for */
            CERT_ENHKEY_USAGE usage = { 1, purpose_oids };

            purpose_oids[0] = (char *)(ac->fCommercial ? SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID
                                                       : SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
            if (!encode(X509_ENHANCED_KEY_USAGE, &usage, &stmt)) { hr = hr_last(); goto done; }
            set_attr(&attrs[n_attrs], &blobs[n_attrs], SPC_STATEMENT_TYPE_OBJID, &stmt);
            n_attrs++;
        }
    }
    if (sig_info->psAuthenticated)
    {
        for (i = 0; i < sig_info->psAuthenticated->cAttr; i++)
        {
            if (n_attrs >= MAX_ATTRS) { hr = E_INVALIDARG; goto done; }
            attrs[n_attrs++] = sig_info->psAuthenticated->rgAttr[i];
        }
    }
    set_attr(&attrs[n_attrs], &blobs[n_attrs], szOID_RSA_messageDigest, &md);
    n_attrs++;

    /* DER wants the members of a SET OF in the order of their encodings; the signature covers the SET and the
     * signerInfo carries the same bytes as [0] */
    {
        struct { CRYPT_ATTRIBUTE a; struct buf enc; } items[MAX_ATTRS], t;
        DWORD j;

        for (i = 0; i < n_attrs; i++)
        {
            items[i].a = attrs[i];
            if (!encode(PKCS_ATTRIBUTE, &attrs[i], &items[i].enc))
            {
                while (i--) buf_free(&items[i].enc);
                hr = hr_last();
                goto done;
            }
        }
        for (i = 1; i < n_attrs; i++)
            for (j = i; j > 0; j--)
            {
                int c = memcmp(items[j - 1].enc.data, items[j].enc.data, min(items[j - 1].enc.len, items[j].enc.len));
                if (c < 0 || (!c && items[j - 1].enc.len <= items[j].enc.len)) break;
                t = items[j - 1]; items[j - 1] = items[j]; items[j] = t;
            }
        for (i = 0; i < n_attrs; i++)
        {
            attrs[i] = items[i].a;
            buf_free(&items[i].enc);
        }
    }
    attr_list.cAttr = n_attrs;
    attr_list.rgAttr = attrs;
    if (!encode(PKCS_ATTRIBUTES, &attr_list, &attr_set)) { hr = hr_last(); goto done; }

    {
        HCRYPTHASH sh;
        if (!CryptCreateHash(signer.prov, alg, 0, 0, &sh)) { hr = hr_last(); goto done; }
        if (!CryptHashData(sh, attr_set.data, attr_set.len, 0) || !CryptSignHashW(sh, signer.keyspec, NULL, 0, NULL, &sig_len) ||
            !(sig = malloc(sig_len)) || !CryptSignHashW(sh, signer.keyspec, NULL, 0, sig, &sig_len))
        {
            hr = hr_last();
            CryptDestroyHash(sh);
            goto done;
        }
        CryptDestroyHash(sh);
    }
    /* CryptoAPI returns the signature little endian */
    for (i = 0; i < sig_len / 2; i++)
    {
        BYTE t = sig[i];
        sig[i] = sig[sig_len - 1 - i];
        sig[sig_len - 1 - i] = t;
    }

    si.dwVersion = 1;
    si.Issuer = signer.cert->pCertInfo->Issuer;
    si.SerialNumber = signer.cert->pCertInfo->SerialNumber;
    si.HashAlgorithm.pszObjId = (char *)alg_oid;
    si.HashAlgorithm.Parameters.cbData = sizeof(null_params);
    si.HashAlgorithm.Parameters.pbData = (BYTE *)null_params;
    si.HashEncryptionAlgorithm.pszObjId = (char *)szOID_RSA_RSA;
    si.HashEncryptionAlgorithm.Parameters = si.HashAlgorithm.Parameters;
    si.EncryptedHash.cbData = sig_len;
    si.EncryptedHash.pbData = sig;
    si.AuthAttrs = attr_list;
    if (sig_info->psUnauthenticated) si.UnauthAttrs = *sig_info->psUnauthenticated;
    if (!encode(PKCS7_SIGNER_INFO, &si, &signer_info)) { hr = hr_last(); goto done; }
    /* the encoder has to have written the attributes the way they were signed */
    {
        DWORD k, found = 0;

        for (k = 0; k + attr_set.len <= signer_info.len; k++)
            if (signer_info.data[k] == 0xa0 && !memcmp(signer_info.data + k + 1, attr_set.data + 1, attr_set.len - 1))
            { found = 1; break; }
        if (!found) { hr = NTE_BAD_DATA; goto done; }
    }

    /* ContentInfo { signedData, [0] SignedData { 1, { digestAlgorithm }, { spcIndirectData, [0] content }, [0] certs,
     * { signerInfo } } } */
    if (FAILED(hr = signer_certs(&signer, &certs))) goto done;
    {
        struct buf version = { (BYTE *)"\x02\x01\x01", 3 }, algid = { 0 }, algset = { 0 }, oid_sd = { 0 }, oid_spc = { 0 },
                   wrapped = { 0 }, inner = { 0 }, sd = { 0 }, explicit_sd = { 0 }, ci_parts[2];
        char *sd_oid = (char *)szOID_RSA_signedData;
        struct buf alg_oid_enc = { 0 }, null_enc = { (BYTE *)null_params, sizeof(null_params) }, alg_parts[2];
        char *alg_oid_ptr = (char *)alg_oid;
        BOOL ok;

        ok = encode_oid(alg_oid_ptr, &alg_oid_enc);
        alg_parts[0] = alg_oid_enc;
        alg_parts[1] = null_enc;
        ok = ok && der_wrap(&algid, 0x30, alg_parts, 2) && der_wrap(&algset, 0x31, &algid, 1) &&
             encode_oid(sd_oid, &oid_sd) && encode_oid(oid_ptr, &oid_spc);
        if (ok)
        {
            struct buf cp[2] = { oid_spc, { 0 } };
            ok = der_wrap(&wrapped, 0xa0, &content, 1);
            cp[1] = wrapped;
            ok = ok && der_wrap(&inner, 0x30, cp, 2);
        }
        if (ok)
        {
            struct buf sp[5];
            struct buf signers = { 0 };

            ok = der_wrap(&signers, 0x31, &signer_info, 1);
            sp[0] = version; sp[1] = algset; sp[2] = inner; sp[3] = certs; sp[4] = signers;
            ok = ok && der_wrap(&sd, 0x30, sp, 5);
            buf_free(&signers);
        }
        ok = ok && der_wrap(&explicit_sd, 0xa0, &sd, 1);
        if (ok)
        {
            ci_parts[0] = oid_sd;
            ci_parts[1] = explicit_sd;
            ok = der_wrap(&msg, 0x30, ci_parts, 2);
        }
        buf_free(&alg_oid_enc); buf_free(&algid); buf_free(&algset); buf_free(&oid_sd); buf_free(&oid_spc); buf_free(&wrapped);
        buf_free(&inner); buf_free(&sd); buf_free(&explicit_sd);
        if (!ok) { hr = E_OUTOFMEMORY; goto done; }
    }

    if (FAILED(hr = replace_signature(file, file_info->pwszFileName, sip_info.dwFlags, &guid, &sip, &msg, &index))) goto done;
    if (subject->pdwIndex) *subject->pdwIndex = index;
    if (context)
    {
        SIGNER_CONTEXT *ctx = calloc(1, sizeof(*ctx));

        if (!ctx || !(ctx->pbBlob = malloc(msg.len))) { free(ctx); hr = E_OUTOFMEMORY; goto done; }
        ctx->cbSize = sizeof(*ctx);
        ctx->cbBlob = msg.len;
        memcpy(ctx->pbBlob, msg.data, msg.len);
        *context = ctx;
    }
    hr = S_OK;

done:
    if (hash) CryptDestroyHash(hash);
    if (hp) CryptReleaseContext(hp, 0);
    if (sip.hSIP) FreeLibrary(sip.hSIP);
    if (opened && file != INVALID_HANDLE_VALUE) CloseHandle(file);
    free(indirect);
    free(sig);
    buf_free(&content); buf_free(&md); buf_free(&ct); buf_free(&opus); buf_free(&stmt); buf_free(&attr_set);
    buf_free(&signer_info); buf_free(&certs); buf_free(&msg);
    signer_free(&signer);
    return hr;
}

HRESULT WINAPI SignerSign(SIGNER_SUBJECT_INFO *subject, SIGNER_CERT *cert, SIGNER_SIGNATURE_INFO *signature,
        SIGNER_PROVIDER_INFO *provider, const WCHAR *timestamp, CRYPT_ATTRIBUTES *attrs, void *sip_data)
{
    TRACE("%p %p %p %p %s %p %p\n", subject, cert, signature, provider, debugstr_w(timestamp), attrs, sip_data);

    /* a time stamp needs an Internet time stamp authority: not done here */
    if (timestamp && *timestamp) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    return sign_file(0, subject, cert, signature, provider, NULL);
}

HRESULT WINAPI SignerSignEx(DWORD flags, SIGNER_SUBJECT_INFO *subject_info, SIGNER_CERT *signer_cert,
                            SIGNER_SIGNATURE_INFO *signature_info, SIGNER_PROVIDER_INFO *provider_info,
                            const WCHAR *http_time_stamp, CRYPT_ATTRIBUTES *request, void *sip_data,
                            SIGNER_CONTEXT **signer_context)
{
    TRACE("%lx %p %p %p %p %s %p %p %p\n", flags, subject_info, signer_cert, signature_info, provider_info,
          debugstr_w(http_time_stamp), request, sip_data, signer_context);

    if (signer_context) *signer_context = NULL;
    if (http_time_stamp && *http_time_stamp) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    return sign_file(flags, subject_info, signer_cert, signature_info, provider_info, signer_context);
}

HRESULT WINAPI SignerSignEx2(DWORD flags, SIGNER_SUBJECT_INFO *subject_info, SIGNER_CERT *signer_cert,
                             SIGNER_SIGNATURE_INFO *signature_info, SIGNER_PROVIDER_INFO *provider_info,
                             DWORD timestamp_flags, const char *timestamp_alg_oid, const WCHAR *http_time_stamp,
                             CRYPT_ATTRIBUTES *request, void *sip_data, SIGNER_CONTEXT **signer_context,
                             void *crypto_policy, void *reserved)
{
    TRACE("%lx %p %p %p %p %lx %s %s %p %p %p %p %p\n", flags, subject_info, signer_cert, signature_info,
          provider_info, timestamp_flags, debugstr_a(timestamp_alg_oid), debugstr_w(http_time_stamp), request,
          sip_data, signer_context, crypto_policy, reserved);

    if (signer_context) *signer_context = NULL;
    if (http_time_stamp && *http_time_stamp) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    return sign_file(flags, subject_info, signer_cert, signature_info, provider_info, signer_context);
}

HRESULT WINAPI SignerFreeSignerContext(SIGNER_CONTEXT *signer_context)
{
    if (signer_context)
    {
        free(signer_context->pbBlob);
        free(signer_context);
    }
    return S_OK;
}
