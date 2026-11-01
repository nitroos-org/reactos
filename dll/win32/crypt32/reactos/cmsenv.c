/*
 * PROJECT:     ReactOS crypt32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CMS EnvelopedData (RFC 5652 section 6) reader, writer and content cipher for msg.c
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * Specifications: RFC 5652 (CMS), RFC 8017 (PKCS #1: RSAES-PKCS1-v1_5, RSAES-OAEP), RFC 3370 and RFC 3565
 * (algorithm identifiers and parameters of 3DES, RC2 and AES in CMS), RFC 2268 (RC2).
 * The message is untrusted input: every length is checked against the bytes that are left, the reader
 * never follows indefinite lengths, and the number of recipients and certificates is bounded by the size
 * of the message.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windef.h>
#include <winbase.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <wine/debug.h>
#include <crypt32_private.h>
#include "pkcs12.h"
#include "cmsenv.h"

WINE_DEFAULT_DEBUG_CHANNEL(crypt);

#ifndef CERT_NCRYPT_KEY_SPEC
#define CERT_NCRYPT_KEY_SPEC 0xffffffff
#endif
#ifndef NCRYPT_PAD_PKCS1_FLAG
#define NCRYPT_PAD_PKCS1_FLAG 0x00000002
#endif
#ifndef NCRYPT_PAD_OAEP_FLAG
#define NCRYPT_PAD_OAEP_FLAG  0x00000004
#endif
#ifndef NTE_BAD_DATA
#define NTE_BAD_DATA ((HRESULT)0x80090005)
#endif
#ifndef NTE_BAD_ALGID
#define NTE_BAD_ALGID ((HRESULT)0x80090008)
#endif
#ifndef NTE_NOT_SUPPORTED
#define NTE_NOT_SUPPORTED ((HRESULT)0x80090029)
#endif
#ifndef NTE_INVALID_PARAMETER
#define NTE_INVALID_PARAMETER ((HRESULT)0x80090027)
#endif
#ifndef NTE_INTERNAL_ERROR
#define NTE_INTERNAL_ERROR ((HRESULT)0x8009002D)
#endif
#ifndef CRYPT_E_UNEXPECTED_ENCODING
#define CRYPT_E_UNEXPECTED_ENCODING ((HRESULT)0x80091005)
#endif
#ifndef NTE_FAIL
#define NTE_FAIL ((HRESULT)0x80090020)
#endif
#ifndef CRYPT_E_BAD_ENCODE
#define CRYPT_E_BAD_ENCODE ((HRESULT)0x80092002)
#endif
#ifndef CRYPT_E_ATTRIBUTES_MISSING
#define CRYPT_E_ATTRIBUTES_MISSING ((HRESULT)0x8009100F)
#endif

#define CMS_MAX_RECIPIENTS 100000
#define CMS_MAX_RSA_BYTES  2048     /* 16384 bit */
#define CMS_MAX_LABEL      4096

/* ------------------------------------------------------------------------------------------ */
/* DER reading                                                                                */
/* ------------------------------------------------------------------------------------------ */

typedef struct { const BYTE *p; DWORD n; } span;

#define BER_MAX_DEPTH 16

static BOOL der_read_d(span *s, BYTE *tag, span *val, span *whole, int depth);

/* s starts after the header of an indefinite length element: finds its end of contents marker */
static BOOL ber_content_len(span s, DWORD *len, int depth)
{
    span p = s;

    for (;;)
    {
        if (p.n < 2) { SetLastError(CRYPT_E_ASN1_EOD); return FALSE; }
        if (!p.p[0] && !p.p[1]) { *len = s.n - p.n; return TRUE; }
        if (!der_read_d(&p, NULL, NULL, NULL, depth + 1)) return FALSE;
    }
}

/* Reads one element from s. tag, val (content) and whole (header and content) may be NULL. Indefinite
 * lengths (BER) are accepted for constructed elements; val and whole then leave out and include the
 * end of contents marker respectively. */
static BOOL der_read_d(span *s, BYTE *tag, span *val, span *whole, int depth)
{
    DWORD hl, len, nb, i, eoc = 0;
    BYTE b;

    if (depth > BER_MAX_DEPTH) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    if (s->n < 2) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    if ((s->p[0] & 0x1f) == 0x1f) { SetLastError(CRYPT_E_ASN1_BADTAG); return FALSE; }
    b = s->p[1];
    if (b < 0x80) { len = b; hl = 2; }
    else if (b == 0x80)
    {
        span rest;

        if (!(s->p[0] & 0x20)) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
        rest.p = s->p + 2;
        rest.n = s->n - 2;
        if (!ber_content_len(rest, &len, depth)) return FALSE;
        hl = 2;
        eoc = 2;
    }
    else
    {
        nb = b & 0x7f;
        if (nb > 4) { SetLastError(CRYPT_E_ASN1_LARGE); return FALSE; }
        if (s->n < 2 + nb) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
        for (len = 0, i = 0; i < nb; i++) len = (len << 8) | s->p[2 + i];
        hl = 2 + nb;
    }
    if (len > s->n - hl || eoc > s->n - hl - len) { SetLastError(CRYPT_E_ASN1_EOD); return FALSE; }
    if (tag) *tag = s->p[0];
    if (val) { val->p = s->p + hl; val->n = len; }
    if (whole) { whole->p = s->p; whole->n = hl + len + eoc; }
    s->p += hl + len + eoc;
    s->n -= hl + len + eoc;
    return TRUE;
}

static BOOL der_read(span *s, BYTE *tag, span *val, span *whole)
{
    return der_read_d(s, tag, val, whole, 0);
}

static BOOL der_expect(span *s, BYTE want, span *val, span *whole)
{
    BYTE tag;

    if (!der_read(s, &tag, val, whole)) return FALSE;
    if (tag != want) { SetLastError(CRYPT_E_ASN1_BADTAG); return FALSE; }
    return TRUE;
}

static BOOL der_peek(const span *s, BYTE *tag)
{
    if (!s->n) return FALSE;
    *tag = s->p[0];
    return TRUE;
}

static BOOL der_uint(span v, DWORD *out)
{
    DWORD i, r = 0;

    if (!v.n || (v.p[0] & 0x80)) return FALSE;
    while (v.n > 1 && !v.p[0]) { v.p++; v.n--; }
    if (v.n > 4) return FALSE;
    for (i = 0; i < v.n; i++) r = (r << 8) | v.p[i];
    *out = r;
    return TRUE;
}

/* Windows reports the version of a message as it is, whatever its value; a negative number wraps */
static BOOL der_version(span v, DWORD *out)
{
    DWORD i, r = 0;

    if (!v.n || v.n > 4) return FALSE;
    if (v.p[0] & 0x80) r = 0xffffffff;
    for (i = 0; i < v.n; i++) r = (r << 8) | v.p[i];
    *out = r;
    return TRUE;
}

/* DER OBJECT IDENTIFIER content to dotted decimal. Returns a CryptMemAlloc'd string or NULL. */
static char *oid_to_string(span v)
{
    char buf[160], *o = buf;
    DWORD i = 0;
    ULONGLONG arc;
    BOOL first = TRUE;

    if (!v.n || (v.p[v.n - 1] & 0x80)) return NULL;
    while (i < v.n)
    {
        arc = 0;
        do
        {
            if (arc >> 56) return NULL;
            arc = (arc << 7) | (v.p[i] & 0x7f);
        } while (v.p[i++] & 0x80);
        if (arc > 0xffffffffull + 80) return NULL;
        if (o - buf > (int)sizeof(buf) - 24) return NULL;
        if (first)
        {
            DWORD a = arc >= 80 ? 2 : (DWORD)(arc / 40);
            o += sprintf(o, "%lu.%lu", a, (DWORD)(arc - a * 40));
            first = FALSE;
        }
        else
            o += sprintf(o, ".%lu", (DWORD)arc);
    }
    o = CryptMemAlloc(o - buf + 1);
    if (o) strcpy(o, buf);
    return o;
}

static BOOL der_oid_string(span *s, char **oid)
{
    span v;

    if (!der_expect(s, 0x06, &v, NULL)) return FALSE;
    if (!(*oid = oid_to_string(v))) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    return TRUE;
}

/* AlgorithmIdentifier content (what follows the SEQUENCE header). NULL parameters are reported as empty. */
static BOOL der_algid(span seq, char **oid, CRYPT_DATA_BLOB *params)
{
    span whole;
    BYTE tag;

    params->cbData = 0;
    params->pbData = NULL;
    if (!der_oid_string(&seq, oid)) return FALSE;
    if (seq.n)
    {
        if (!der_read(&seq, &tag, NULL, &whole)) { CryptMemFree(*oid); *oid = NULL; return FALSE; }
        if (!(tag == 0x05 && whole.n == 2))
        {
            params->cbData = whole.n;
            params->pbData = (BYTE *)whole.p;
        }
        if (seq.n) { CryptMemFree(*oid); *oid = NULL; SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    }
    return TRUE;
}

/* ------------------------------------------------------------------------------------------ */
/* DER writing                                                                                */
/* ------------------------------------------------------------------------------------------ */

/* n * size bytes (at least one), failing with ERROR_OUTOFMEMORY if that does not fit */
static void *alloc_array(DWORD n, DWORD size)
{
    if (size && n > CMS_MAX_CONTENT / size) { SetLastError(ERROR_OUTOFMEMORY); return NULL; }
    size *= n;
    return CryptMemAlloc(size ? size : 1);
}

struct wbuf { BYTE *p; DWORD n, cap; BOOL err; };

static void w_free(struct wbuf *b)
{
    if (b->p) { SecureZeroMemory(b->p, b->cap); CryptMemFree(b->p); }
    memset(b, 0, sizeof(*b));
}

static void w_add(struct wbuf *b, const void *d, DWORD n)
{
    if (b->err) return;
    if (n > 0x7fffffff - b->n) { b->err = TRUE; return; }
    if (b->n + n > b->cap)
    {
        DWORD nc = b->cap ? b->cap : 128;
        BYTE *np;

        while (nc < b->n + n) nc *= 2;
        if (!(np = CryptMemAlloc(nc))) { b->err = TRUE; return; }
        if (b->n) memcpy(np, b->p, b->n);
        if (b->p) { SecureZeroMemory(b->p, b->cap); CryptMemFree(b->p); }
        b->p = np;
        b->cap = nc;
    }
    if (n) memcpy(b->p + b->n, d, n);
    b->n += n;
}

static void w_header(struct wbuf *b, BYTE tag, DWORD len)
{
    BYTE h[6];
    DWORD n = 0;

    h[n++] = tag;
    if (len < 0x80) h[n++] = (BYTE)len;
    else if (len < 0x100) { h[n++] = 0x81; h[n++] = (BYTE)len; }
    else if (len < 0x10000) { h[n++] = 0x82; h[n++] = len >> 8; h[n++] = (BYTE)len; }
    else if (len < 0x1000000) { h[n++] = 0x83; h[n++] = len >> 16; h[n++] = len >> 8; h[n++] = (BYTE)len; }
    else { h[n++] = 0x84; h[n++] = len >> 24; h[n++] = len >> 16; h[n++] = len >> 8; h[n++] = (BYTE)len; }
    w_add(b, h, n);
}

static void w_tlv(struct wbuf *b, BYTE tag, const void *v, DWORD n)
{
    w_header(b, tag, n);
    w_add(b, v, n);
}

/* wraps the content of inner (which is consumed) */
static void w_wrap(struct wbuf *b, BYTE tag, struct wbuf *inner)
{
    if (inner->err) b->err = TRUE;
    w_tlv(b, tag, inner->p, inner->n);
    w_free(inner);
}

static void w_uint(struct wbuf *b, DWORD v)
{
    BYTE t[5];
    DWORD n = 0, i;

    for (i = 0; i < 4; i++) if (v >> (24 - 8 * i) || n) t[n++] = (BYTE)(v >> (24 - 8 * i));
    if (!n) t[n++] = 0;
    if (t[0] & 0x80) { memmove(t + 1, t, n); t[0] = 0; n++; }
    w_tlv(b, 0x02, t, n);
}

/* INTEGER from the little endian form used by CRYPT_INTEGER_BLOB */
static void w_integer_le(struct wbuf *b, const BYTE *le, DWORD n)
{
    struct wbuf t = { 0 };
    DWORD i;

    while (n > 1 && !le[n - 1]) n--;            /* redundant leading zeros */
    if (!n) { BYTE z = 0; w_tlv(b, 0x02, &z, 1); return; }
    if (le[n - 1] & 0x80) { BYTE z = 0; w_add(&t, &z, 1); }
    for (i = n; i > 0; i--) w_add(&t, &le[i - 1], 1);
    if (t.err) b->err = TRUE;
    else w_tlv(b, 0x02, t.p, t.n);
    w_free(&t);
}

static BOOL oid_to_der(const char *oid, struct wbuf *b)
{
    BYTE out[64];
    DWORD n = 0, a, c, arcs[24], na = 0, i;
    const char *p = oid;

    if (!oid) return FALSE;
    for (;;)
    {
        char *e;
        unsigned long v;

        if (*p < '0' || *p > '9' || na >= ARRAY_SIZE(arcs)) return FALSE;
        v = strtoul(p, &e, 10);
        if (e == p || v > 0xffffffffUL) return FALSE;
        arcs[na++] = (DWORD)v;
        if (!*e) break;
        if (*e != '.') return FALSE;
        p = e + 1;
    }
    if (na < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40)) return FALSE;
    for (i = 1; i < na; i++)
    {
        BYTE tmp[6];
        DWORD tn = 0;

        a = i == 1 ? arcs[0] * 40 + arcs[1] : arcs[i];
        if (i == 1 && arcs[1] > 0xffffffffu - arcs[0] * 40) return FALSE;
        do { tmp[tn++] = a & 0x7f; a >>= 7; } while (a);
        if (n + tn > sizeof(out)) return FALSE;
        for (c = tn; c > 0; c--) out[n++] = tmp[c - 1] | (c > 1 ? 0x80 : 0);
    }
    w_tlv(b, 0x06, out, n);
    return TRUE;
}

/* AlgorithmIdentifier; params is a complete DER element or empty, in which case NULL is written
 * when null_params is set. */
static BOOL w_algid(struct wbuf *b, const char *oid, const BYTE *params, DWORD nparams, BOOL null_params)
{
    struct wbuf in = { 0 };

    if (!oid_to_der(oid, &in)) { w_free(&in); return FALSE; }
    if (nparams) w_add(&in, params, nparams);
    else if (null_params) w_tlv(&in, 0x05, NULL, 0);
    w_wrap(b, 0x30, &in);
    return !b->err;
}

static int cmp_der(const void *a, const void *b)
{
    const CRYPT_DATA_BLOB *x = a, *y = b;
    DWORD n = x->cbData < y->cbData ? x->cbData : y->cbData;
    int c = memcmp(x->pbData, y->pbData, n);

    if (c) return c;
    return x->cbData < y->cbData ? -1 : x->cbData > y->cbData;
}

/* ------------------------------------------------------------------------------------------ */
/* algorithms                                                                                 */
/* ------------------------------------------------------------------------------------------ */

#define OID_RSA_ENCRYPTION "1.2.840.113549.1.1.1"
#define OID_RSAES_OAEP     "1.2.840.113549.1.1.7"
#define OID_MGF1           "1.2.840.113549.1.1.8"
#define OID_PSPECIFIED     "1.2.840.113549.1.1.9"

/* CMSG_RC2_AUX_INFO and CMSG_RC4_AUX_INFO */
struct cms_rc_aux { DWORD cbSize; DWORD dwBitLen; };

struct cms_cipher
{
    int kind;           /* P12_CIPHER_* */
    DWORD keylen;       /* bytes of key material, 0: any (RC2, RC4: from the key) */
    DWORD ivlen;
    unsigned rc2bits;
    BYTE iv[16];
    BYTE salt[16];      /* RC4: bytes that follow the key, as CryptoAPI "salt" of keys shorter than 128 bits */
    DWORD salt_len;
    ALG_ID capi_alg;
};

struct cipher_def { const char *oid; int kind; DWORD keylen, ivlen; ALG_ID capi; };
static const struct cipher_def ciphers[] =
{
    { "2.16.840.1.101.3.4.1.2",  P12_CIPHER_AES,  16, 16, CALG_AES_128 },
    { "2.16.840.1.101.3.4.1.22", P12_CIPHER_AES,  24, 16, CALG_AES_192 },
    { "2.16.840.1.101.3.4.1.42", P12_CIPHER_AES,  32, 16, CALG_AES_256 },
    { "1.2.840.113549.3.7",      P12_CIPHER_3DES, 24, 8,  CALG_3DES },
    { "1.3.14.3.2.7",            P12_CIPHER_DES,  8,  8,  CALG_DES },
    { "1.2.840.113549.3.2",      P12_CIPHER_RC2,  0,  8,  CALG_RC2 },
    { "1.2.840.113549.3.4",      P12_CIPHER_RC4,  0,  0,  CALG_RC4 },
};

static const struct cipher_def *find_cipher(const char *oid)
{
    DWORD i;

    if (oid)
        for (i = 0; i < ARRAY_SIZE(ciphers); i++)
            if (!strcmp(oid, ciphers[i].oid)) return &ciphers[i];
    return NULL;
}

/* rc2ParameterVersion as written by Windows for the key sizes it offers */
static const struct { DWORD version, bits; } rc2_versions[] = { { 160, 40 }, { 52, 56 }, { 120, 64 }, { 58, 128 } };

static unsigned rc2_bits_from_version(DWORD v)
{
    DWORD i;

    for (i = 0; i < ARRAY_SIZE(rc2_versions); i++) if (rc2_versions[i].version == v) return rc2_versions[i].bits;
    return 0;
}

BOOL CMSEnv_CheckContentAlg(const char *oid)
{
    if (find_cipher(oid)) return TRUE;
    SetLastError(CRYPT_E_UNKNOWN_ALGO);
    return FALSE;
}

/* Reads the cipher and its parameters from an AlgorithmIdentifier of a message. */
static BOOL cipher_from_alg(const char *oid, const CRYPT_DATA_BLOB *params, struct cms_cipher *c)
{
    const struct cipher_def *d = find_cipher(oid);
    span s, v;
    BYTE tag;

    memset(c, 0, sizeof(*c));
    if (!d) { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    c->kind = d->kind;
    c->keylen = d->keylen;
    c->ivlen = d->ivlen;
    c->capi_alg = d->capi;
    if (d->kind == P12_CIPHER_RC4)
    {
        if (params->cbData)
        {
            s.p = params->pbData;
            s.n = params->cbData;
            if (!der_expect(&s, 0x04, &v, NULL) || s.n || v.n > sizeof(c->salt)) goto bad;
            memcpy(c->salt, v.p, v.n);
            c->salt_len = v.n;
        }
        return TRUE;
    }
    s.p = params->pbData;
    s.n = params->cbData;
    if (d->kind == P12_CIPHER_RC2)
    {
        span seq;
        DWORD version;

        if (!s.n || !der_expect(&s, 0x30, &seq, NULL) || !der_expect(&seq, 0x02, &v, NULL) || !der_uint(v, &version) ||
            !der_expect(&seq, 0x04, &v, NULL) || seq.n || s.n)
            goto bad;
        if (!(c->rc2bits = rc2_bits_from_version(version))) { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    }
    else if (!s.n || !der_expect(&s, 0x04, &v, NULL) || s.n)
        goto bad;
    if (v.n != d->ivlen) goto bad;
    memcpy(c->iv, v.p, v.n);
    (void)tag;
    return TRUE;
bad:
    SetLastError(CRYPT_E_BAD_ENCODE);
    return FALSE;
}

#define STATUS_INVALID_PARAMETER_E  ((HRESULT)0xc000000d)
#define STATUS_DATA_ERROR_E         ((HRESULT)0xc000003e)
#define STATUS_INVALID_BUFFER_SIZE_E ((HRESULT)0xc0000206)

/* Windows lets the NTSTATUS of its CNG calls through as the error of CryptMsgControl; so do we */
static BOOL cipher_run(const struct cms_cipher *c, const BYTE *key, DWORD keylen, BOOL encrypt,
                       const BYTE *in, DWORD inlen, BYTE **out, DWORD *outlen)
{
    BYTE k16[32];
    uint8_t *res = NULL;
    size_t reslen = 0;
    int r;
    BOOL key_ok;

    switch (c->kind)
    {
    case P12_CIPHER_AES: key_ok = keylen == 16 || keylen == 24 || keylen == 32; break;  /* the OID's size is not enforced */
    case P12_CIPHER_RC2: key_ok = keylen && keylen <= 16; break;
    case P12_CIPHER_RC4: key_ok = keylen && keylen <= 16 && keylen + c->salt_len <= sizeof(k16); break;
    default: key_ok = keylen == c->keylen;
    }
    if (!key_ok) { SetLastError(STATUS_INVALID_PARAMETER_E); return FALSE; }
    /* the padded size, and the DWORD the result length goes through, must not wrap */
    if (inlen > CMS_MAX_CONTENT) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
    if (c->kind == P12_CIPHER_RC4)
    {
        /* the key is followed by the salt of the algorithm parameters */
        memcpy(k16, key, keylen);
        memcpy(k16 + keylen, c->salt, c->salt_len);
        key = k16;
        keylen += c->salt_len;
    }
    if (!encrypt && c->ivlen && inlen % c->ivlen) { SetLastError(STATUS_INVALID_BUFFER_SIZE_E); return FALSE; }
    if (!encrypt && c->ivlen && !inlen) { SetLastError(STATUS_DATA_ERROR_E); return FALSE; }
    r = p12_cms_crypt(c->kind, key, keylen, c->rc2bits, c->iv, encrypt, in, inlen, &res, &reslen);
    SecureZeroMemory(k16, sizeof(k16));
    if (r)
    {
        SetLastError(r == P12_ERR_NOMEM ? ERROR_OUTOFMEMORY : r == P12_ERR_DECRYPT ? STATUS_DATA_ERROR_E : NTE_BAD_ALGID);
        return FALSE;
    }
    *out = CryptMemAlloc(reslen ? reslen : 1);
    if (*out) { memcpy(*out, res, reslen); *outlen = (DWORD)reslen; }
    SecureZeroMemory(res, reslen);
    p12_free(res);
    if (!*out) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
    return TRUE;
}

/* ------------------------------------------------------------------------------------------ */
/* RSAES-OAEP parameters                                                                      */
/* ------------------------------------------------------------------------------------------ */

struct oaep
{
    const WCHAR *hash;      /* BCrypt algorithm id */
    const BYTE *label;
    DWORD label_len;
};

static const struct { const char *oid; const WCHAR *bcrypt; } hashes[] =
{
    { "1.3.14.3.2.26",          L"SHA1" },
    { "2.16.840.1.101.3.4.2.1", L"SHA256" },
    { "2.16.840.1.101.3.4.2.2", L"SHA384" },
    { "2.16.840.1.101.3.4.2.3", L"SHA512" },
};

static const WCHAR *hash_from_oid(const char *oid)
{
    DWORD i;

    for (i = 0; oid && i < ARRAY_SIZE(hashes); i++) if (!strcmp(oid, hashes[i].oid)) return hashes[i].bcrypt;
    return NULL;
}

static const char *oid_from_hash(const char *oid)
{
    DWORD i;

    for (i = 0; oid && i < ARRAY_SIZE(hashes); i++) if (!strcmp(oid, hashes[i].oid)) return hashes[i].oid;
    return NULL;
}

/* RSAES-OAEP-params, empty params means the defaults: SHA-1, MGF1 with SHA-1, empty label.
 * BCrypt takes one hash for both the label hash and MGF1, so anything else is unsupported. */
static BOOL parse_oaep(const CRYPT_DATA_BLOB *params, struct oaep *o)
{
    span s, seq, el, v, alg;
    BYTE tag;
    char *oid, *hoid = NULL;
    CRYPT_DATA_BLOB pb;
    BOOL ok = FALSE;

    o->hash = L"SHA1";
    o->label = NULL;
    o->label_len = 0;
    if (!params->cbData) return TRUE;
    s.p = params->pbData;
    s.n = params->cbData;
    if (!der_expect(&s, 0x30, &seq, NULL)) return FALSE;
    if (s.n) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    if (der_peek(&seq, &tag) && tag == 0xa0)
    {
        if (!der_read(&seq, NULL, &el, NULL) || !der_expect(&el, 0x30, &alg, NULL) || el.n) goto fail;
        if (!der_algid(alg, &hoid, &pb)) return FALSE;
        if (!hash_from_oid(hoid)) { SetLastError(CRYPT_E_UNKNOWN_ALGO); goto done; }
        o->hash = hash_from_oid(hoid);
    }
    if (der_peek(&seq, &tag) && tag == 0xa1)
    {
        char *moid = NULL, *mhash = NULL;
        span mseq;
        BOOL same;

        if (!der_read(&seq, NULL, &el, NULL) || !der_expect(&el, 0x30, &alg, NULL) || el.n) goto fail;
        if (!der_oid_string(&alg, &moid)) goto done;
        if (strcmp(moid, OID_MGF1) || !der_expect(&alg, 0x30, &mseq, NULL) || alg.n) { CryptMemFree(moid); SetLastError(CRYPT_E_UNKNOWN_ALGO); goto done; }
        CryptMemFree(moid);
        if (!der_algid(mseq, &mhash, &pb)) goto done;
        same = hoid ? !strcmp(mhash, hoid) : !strcmp(mhash, hashes[0].oid);
        if (!hash_from_oid(mhash) || !same) { CryptMemFree(mhash); SetLastError(CRYPT_E_UNKNOWN_ALGO); goto done; }
        CryptMemFree(mhash);
    }
    else if (hoid && strcmp(hoid, hashes[0].oid))
    {
        /* a hash other than SHA-1 with the default MGF1 (SHA-1) */
        SetLastError(CRYPT_E_UNKNOWN_ALGO);
        goto done;
    }
    if (der_peek(&seq, &tag) && tag == 0xa2)
    {
        if (!der_read(&seq, NULL, &el, NULL) || !der_expect(&el, 0x30, &alg, NULL) || el.n) goto fail;
        if (!der_oid_string(&alg, &oid)) goto done;
        if (strcmp(oid, OID_PSPECIFIED) || !der_expect(&alg, 0x04, &v, NULL) || alg.n) { CryptMemFree(oid); SetLastError(CRYPT_E_UNKNOWN_ALGO); goto done; }
        CryptMemFree(oid);
        if (v.n > CMS_MAX_LABEL) { SetLastError(CRYPT_E_ASN1_LARGE); goto done; }
        o->label = v.p;
        o->label_len = v.n;
    }
    if (seq.n) goto fail;
    ok = TRUE;
    goto done;
fail:
    SetLastError(CRYPT_E_ASN1_CORRUPT);
done:
    CryptMemFree(hoid);
    return ok;
}

/* RSAES-OAEP-params of an application supplied CRYPT_RSAES_OAEP_PARAMETERS */
static BOOL build_oaep(const CMS_RSAES_OAEP_PARAMETERS *p, struct wbuf *out)
{
    struct wbuf in = { 0 }, a = { 0 }, b = { 0 };
    const char *hash = p->HashAlgorithm.pszObjId, *mgf_hash = p->MaskGenAlgorithm.HashAlgorithm.pszObjId;

    if (!hash) hash = hashes[0].oid;
    if (!mgf_hash) mgf_hash = hashes[0].oid;
    if (!oid_from_hash(hash) || !oid_from_hash(mgf_hash)) { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    if (p->MaskGenAlgorithm.pszObjId && strcmp(p->MaskGenAlgorithm.pszObjId, OID_MGF1)) { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    if (p->PSourceAlgorithm.pszObjId && strcmp(p->PSourceAlgorithm.pszObjId, OID_PSPECIFIED)) { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    if (strcmp(hash, hashes[0].oid))
    {
        w_algid(&a, hash, NULL, 0, TRUE);
        w_wrap(&in, 0xa0, &a);
    }
    if (strcmp(mgf_hash, hashes[0].oid))
    {
        struct wbuf m = { 0 };

        w_algid(&m, mgf_hash, NULL, 0, TRUE);
        oid_to_der(OID_MGF1, &b);
        w_add(&b, m.p, m.n);
        w_free(&m);
        w_wrap(&a, 0x30, &b);
        w_wrap(&in, 0xa1, &a);
    }
    if (p->PSourceAlgorithm.EncodingParameters.cbData)
    {
        struct wbuf l = { 0 };

        oid_to_der(OID_PSPECIFIED, &b);
        w_tlv(&b, 0x04, p->PSourceAlgorithm.EncodingParameters.pbData, p->PSourceAlgorithm.EncodingParameters.cbData);
        w_wrap(&l, 0x30, &b);
        w_wrap(&in, 0xa2, &l);
    }
    w_wrap(out, 0x30, &in);
    w_free(&a);
    w_free(&b);
    return !out->err;
}

/* ------------------------------------------------------------------------------------------ */
/* RSA key transport                                                                          */
/* ------------------------------------------------------------------------------------------ */

HMODULE CMSEnv_LoadNcrypt(void)
{
    static const WCHAR name[] = L"\\ncrypt.dll";
    WCHAR path[MAX_PATH + ARRAY_SIZE(name)];
    UINT n = GetSystemDirectoryW(path, MAX_PATH);

    if (!n || n >= MAX_PATH) { SetLastError(ERROR_PATH_NOT_FOUND); return NULL; }
    memcpy(path + n, name, sizeof(name));
    return LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
}

typedef LONG (WINAPI *PFN_NCryptDecrypt)(ULONG_PTR key, BYTE *in, DWORD inlen, void *pad, BYTE *out, DWORD outlen,
                                         DWORD *res, DWORD flags);

static BOOL ncrypt_unwrap(ULONG_PTR key, const BYTE *enc, DWORD enc_len, BOOL oaep, const struct oaep *o,
                          BYTE **cek, DWORD *cek_len)
{
    HMODULE mod;
    PFN_NCryptDecrypt decrypt;
    BCRYPT_OAEP_PADDING_INFO pad;
    BYTE *buf, *in;
    DWORD res = 0;
    LONG status;

    if (!(mod = CMSEnv_LoadNcrypt())) return FALSE;
    if (!(decrypt = (PFN_NCryptDecrypt)GetProcAddress(mod, "NCryptDecrypt")))
    {
        FreeLibrary(mod);
        SetLastError(NTE_NOT_SUPPORTED);
        return FALSE;
    }
    in = CryptMemAlloc(enc_len ? enc_len : 1);
    buf = CryptMemAlloc(enc_len + 16);
    if (!in || !buf)
    {
        CryptMemFree(in); CryptMemFree(buf);
        FreeLibrary(mod);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }
    memcpy(in, enc, enc_len);
    pad.pszAlgId = o->hash;
    pad.pbLabel = (PUCHAR)o->label;
    pad.cbLabel = o->label_len;
    status = decrypt(key, in, enc_len, oaep ? (void *)&pad : NULL, buf, enc_len + 16, &res,
                     oaep ? NCRYPT_PAD_OAEP_FLAG : NCRYPT_PAD_PKCS1_FLAG);
    CryptMemFree(in);
    FreeLibrary(mod);
    if (status || res > enc_len + 16)
    {
        SecureZeroMemory(buf, enc_len + 16);
        CryptMemFree(buf);
        /* the RSA padding check failed: Windows reports NTE_INVALID_PARAMETER, our CNG says "internal error" */
        if (status == NTE_INTERNAL_ERROR) status = NTE_INVALID_PARAMETER;
        SetLastError(status ? status : NTE_BAD_DATA);
        return FALSE;
    }
    *cek = buf;
    *cek_len = res;
    return TRUE;
}

/* CryptoAPI key: the exchange key decrypts the wrapped content key itself (CryptDecrypt takes the block
 * little endian; CRYPT_OAEP for RSAES-OAEP with SHA-1). The content key is not exported or imported
 * through the provider, so it works for non-exportable keys, for providers that do not know the content
 * cipher, and for OAEP. */
static BOOL capi_unwrap(HCRYPTPROV prov, DWORD keyspec, const BYTE *enc, DWORD enc_len, BOOL oaep,
                        BYTE **cek, DWORD *cek_len)
{
    HCRYPTKEY xkey;
    BYTE *buf;
    DWORD i, len = enc_len, err;
    BOOL ok;

    if (!CryptGetUserKey(prov, keyspec ? keyspec : AT_KEYEXCHANGE, &xkey)) return FALSE;
    if (!(buf = CryptMemAlloc(enc_len))) { CryptDestroyKey(xkey); SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
    for (i = 0; i < enc_len; i++) buf[enc_len - 1 - i] = enc[i];
    SetLastError(0);
    ok = CryptDecrypt(xkey, 0, TRUE, oaep ? CRYPT_OAEP : 0, buf, &len);
    err = GetLastError();
    CryptDestroyKey(xkey);
    if (ok && (!len || len > enc_len)) { ok = FALSE; err = NTE_BAD_DATA; }
    if (!ok)
    {
        SecureZeroMemory(buf, enc_len);
        CryptMemFree(buf);
        SetLastError(err ? err : NTE_BAD_DATA);
        return FALSE;
    }
    SecureZeroMemory(buf + len, enc_len - len);        /* no key residue behind the key */
    *cek = buf;
    *cek_len = len;
    return TRUE;
}

BOOL CMSEnv_Decrypt(const struct cms_env *env, const struct cms_recip *recip,
                    const CMSG_KEY_TRANS_RECIPIENT_INFO *ktri, ULONG_PTR key, DWORD keyspec,
                    const BYTE *content, DWORD content_len, BYTE **out, DWORD *out_len)
{
    const char *key_oid;
    const BYTE *enc;
    DWORD enc_len, cek_len = 0;
    CRYPT_DATA_BLOB params;
    struct cms_cipher cipher;
    struct oaep oaep;
    BYTE *cek = NULL;
    BOOL is_oaep, ret;

    if (ktri)
    {
        key_oid = ktri->KeyEncryptionAlgorithm.pszObjId;
        params = ktri->KeyEncryptionAlgorithm.Parameters;
        enc = ktri->EncryptedKey.pbData;
        enc_len = ktri->EncryptedKey.cbData;
        if (params.cbData == 2 && params.pbData && params.pbData[0] == 0x05 && !params.pbData[1]) params.cbData = 0;
    }
    else
    {
        key_oid = recip->alg_oid;
        params = recip->alg_params;
        enc = recip->enc_key.pbData;
        enc_len = recip->enc_key.cbData;
    }
    if (!cipher_from_alg(env->alg_oid, &env->alg_params, &cipher)) return FALSE;
    /* like Windows, anything but RSAES-OAEP is taken as RSAES-PKCS1-v1_5, whatever the identifier says */
    is_oaep = key_oid && !strcmp(key_oid, OID_RSAES_OAEP);
    if (is_oaep) { if (!parse_oaep(&params, &oaep)) return FALSE; }
    else memset(&oaep, 0, sizeof(oaep));
    if (!enc || !enc_len || enc_len > CMS_MAX_RSA_BYTES) { SetLastError(NTE_BAD_DATA); return FALSE; }

    if (keyspec == CERT_NCRYPT_KEY_SPEC)
        ret = ncrypt_unwrap(key, enc, enc_len, is_oaep, &oaep, &cek, &cek_len);
    else if (is_oaep && (wcscmp(oaep.hash, L"SHA1") || oaep.label_len))
    {
        /* a CryptoAPI provider does OAEP with SHA-1 and an empty label only */
        SetLastError(NTE_BAD_ALGID);
        ret = FALSE;
    }
    else
        ret = capi_unwrap((HCRYPTPROV)key, keyspec, enc, enc_len, is_oaep, &cek, &cek_len);
    if (!ret) return FALSE;
    ret = cipher_run(&cipher, cek, cek_len, FALSE, content, content_len, out, out_len);
    SecureZeroMemory(cek, cek_len);
    CryptMemFree(cek);
    return ret;
}

/* RSAES-PKCS1-v1_5 or RSAES-OAEP encryption of the content key to an RSAPublicKey */
static BOOL rsa_wrap(const CRYPT_BIT_BLOB *pub, BOOL oaep, const struct oaep *o, const BYTE *cek, DWORD cek_len,
                     BYTE **out, DWORD *out_len)
{
    span s, seq, n, e;
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_RSAKEY_BLOB *kb;
    BCRYPT_OAEP_PADDING_INFO pad;
    BYTE *blob = NULL, *res = NULL;
    DWORD blob_len, res_len = 0;
    NTSTATUS st;
    BOOL ret = FALSE;

    if (pub->cUnusedBits || !pub->cbData) { SetLastError(CRYPT_E_ASN1_BADTAG); return FALSE; }
    s.p = pub->pbData;
    s.n = pub->cbData;
    if (!der_expect(&s, 0x30, &seq, NULL) || !der_expect(&seq, 0x02, &n, NULL) || !der_expect(&seq, 0x02, &e, NULL) || seq.n)
    {
        SetLastError(CRYPT_E_ASN1_BADTAG);
        return FALSE;
    }
    while (n.n > 1 && !n.p[0]) { n.p++; n.n--; }
    while (e.n > 1 && !e.p[0]) { e.p++; e.n--; }
    if (n.n < 64 || n.n > CMS_MAX_RSA_BYTES || !e.n || e.n > 8) { SetLastError(NTE_BAD_DATA); return FALSE; }
    blob_len = sizeof(*kb) + e.n + n.n;
    if (!(blob = CryptMemAlloc(blob_len))) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
    kb = (BCRYPT_RSAKEY_BLOB *)blob;
    kb->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    kb->BitLength = n.n * 8;
    kb->cbPublicExp = e.n;
    kb->cbModulus = n.n;
    kb->cbPrime1 = kb->cbPrime2 = 0;
    memcpy(blob + sizeof(*kb), e.p, e.n);
    memcpy(blob + sizeof(*kb) + e.n, n.p, n.n);
    if ((st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0))) goto fail;
    if ((st = BCryptImportKeyPair(alg, NULL, BCRYPT_RSAPUBLIC_BLOB, &key, blob, blob_len, 0))) goto fail;
    res_len = n.n;
    if (!(res = CryptMemAlloc(res_len))) { st = ERROR_OUTOFMEMORY; goto fail; }
    if (oaep)
    {
        pad.pszAlgId = o->hash;
        pad.pbLabel = (PUCHAR)o->label;
        pad.cbLabel = o->label_len;
        st = BCryptEncrypt(key, (PUCHAR)cek, cek_len, &pad, NULL, 0, res, res_len, &res_len, BCRYPT_PAD_OAEP);
    }
    else
        st = BCryptEncrypt(key, (PUCHAR)cek, cek_len, NULL, NULL, 0, res, res_len, &res_len, BCRYPT_PAD_PKCS1);
    if (st) goto fail;
    *out = res;
    *out_len = res_len;
    res = NULL;
    ret = TRUE;
    goto done;
fail:
    SetLastError(st == ERROR_OUTOFMEMORY ? ERROR_OUTOFMEMORY : NTE_BAD_DATA);
done:
    CryptMemFree(res);
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CryptMemFree(blob);
    return ret;
}

/* ------------------------------------------------------------------------------------------ */
/* decoding                                                                                   */
/* ------------------------------------------------------------------------------------------ */

void CMSEnv_Free(struct cms_env *env)
{
    DWORD i;

    if (!env) return;
    for (i = 0; i < env->n_recip; i++)
    {
        CryptMemFree(env->recip[i].serial_le);
        CryptMemFree(env->recip[i].synth_issuer);
        CryptMemFree(env->recip[i].alg_oid);
    }
    CryptMemFree(env->recip);
    CryptMemFree(env->ktri_index);
    CryptMemFree(env->certs);
    CryptMemFree(env->crls);
    CryptMemFree(env->content_type);
    CryptMemFree(env->alg_oid);
    CryptMemFree(env->content_buf);
    CryptMemFree(env->raw);
    CryptMemFree(env);
}

static const BYTE keyid_rdn_oid[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x0a, 0x07, 0x01 };

static BOOL parse_ktri(struct cms_recip *r, span s)
{
    span v, whole, alg;
    BYTE tag;
    DWORD i;

    r->choice = CMSG_KEY_TRANS_RECIPIENT;
    if (!der_expect(&s, 0x02, &v, NULL)) return FALSE;
    if (!der_version(v, &r->version)) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    if (!der_peek(&s, &tag)) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    if (tag == 0x30)
    {
        span ias, ser;

        if (!der_expect(&s, 0x30, &ias, NULL)) return FALSE;
        if (!der_expect(&ias, 0x30, NULL, &whole)) return FALSE;
        r->id.dwIdChoice = CERT_ID_ISSUER_SERIAL_NUMBER;
        r->id.IssuerSerialNumber.Issuer.cbData = whole.n;
        r->id.IssuerSerialNumber.Issuer.pbData = (BYTE *)whole.p;
        if (!der_expect(&ias, 0x02, &ser, NULL) || ias.n) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
        if (!ser.n) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
        if (!(r->serial_le = CryptMemAlloc(ser.n))) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
        for (i = 0; i < ser.n; i++) r->serial_le[i] = ser.p[ser.n - 1 - i];
        r->id.IssuerSerialNumber.SerialNumber.cbData = ser.n;
        r->id.IssuerSerialNumber.SerialNumber.pbData = r->serial_le;
        r->legacy_issuer = r->id.IssuerSerialNumber.Issuer;
        r->legacy_serial = r->id.IssuerSerialNumber.SerialNumber;
    }
    else if (tag == 0x80)
    {
        struct wbuf w = { 0 }, a = { 0 }, b = { 0 };

        if (!der_read(&s, NULL, &v, NULL)) return FALSE;
        r->id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
        r->id.KeyId.cbData = v.n;
        r->id.KeyId.pbData = (BYTE *)v.p;
        /* the legacy view of a recipient without issuer: a name holding the key id, serial number 0 */
        w_tlv(&a, 0x06, keyid_rdn_oid, sizeof(keyid_rdn_oid));
        w_tlv(&a, 0x04, v.p, v.n);
        w_wrap(&b, 0x30, &a);
        w_wrap(&a, 0x31, &b);
        w_wrap(&w, 0x30, &a);
        if (w.err || !(r->synth_issuer = CryptMemAlloc(w.n)) || !(r->serial_le = CryptMemAlloc(1)))
        {
            w_free(&w);
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
        memcpy(r->synth_issuer, w.p, w.n);
        r->legacy_issuer.pbData = r->synth_issuer;
        r->legacy_issuer.cbData = w.n;
        w_free(&w);
        r->serial_le[0] = 0;
        r->legacy_serial.pbData = r->serial_le;
        r->legacy_serial.cbData = 1;
    }
    else { SetLastError(CRYPT_E_ASN1_BADTAG); return FALSE; }
    if (!der_expect(&s, 0x30, &alg, NULL)) return FALSE;
    if (!der_algid(alg, &r->alg_oid, &r->alg_params)) return FALSE;
    if (!der_expect(&s, 0x04, &v, NULL)) return FALSE;
    r->enc_key.cbData = v.n;
    r->enc_key.pbData = (BYTE *)v.p;
    if (s.n) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    return TRUE;
}

/* the segments of a constructed OCTET STRING, back to back */
static BOOL collect_octets(span s, struct wbuf *w, int depth)
{
    span v;
    BYTE tag;

    if (depth > BER_MAX_DEPTH) { SetLastError(CRYPT_E_ASN1_CORRUPT); return FALSE; }
    while (s.n)
    {
        if (!der_read(&s, &tag, &v, NULL)) return FALSE;
        if (tag == 0x04) w_add(w, v.p, v.n);
        else if (tag == 0x24) { if (!collect_octets(v, w, depth + 1)) return FALSE; }
        else { SetLastError(CRYPT_E_ASN1_BADTAG); return FALSE; }
        if (w->err) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
    }
    return TRUE;
}

BOOL CMSEnv_Decode(const BYTE *pb, DWORD cb, struct cms_env **out)
{
    struct cms_env *env;
    span s, seq, v, whole, rset, eci, alg;
    BYTE tag;
    DWORD i, n;
    BOOL ok = FALSE;

    *out = NULL;
    if (!(env = CryptMemAlloc(sizeof(*env)))) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
    memset(env, 0, sizeof(*env));
    if (!(env->raw = CryptMemAlloc(cb ? cb : 1))) { SetLastError(ERROR_OUTOFMEMORY); goto done; }
    memcpy(env->raw, pb, cb);
    env->raw_len = cb;
    s.p = env->raw;
    s.n = cb;
    if (!der_expect(&s, 0x30, &seq, NULL)) goto done;
    if (!der_expect(&seq, 0x02, &v, NULL)) goto done;
    if (!der_version(v, &env->version)) { SetLastError(CRYPT_E_ASN1_CORRUPT); goto done; }
    if (!der_peek(&seq, &tag)) { SetLastError(CRYPT_E_ASN1_CORRUPT); goto done; }
    if (tag == 0xa0)
    {
        span orig, el;

        if (!der_read(&seq, NULL, &orig, NULL)) goto done;
        while (orig.n)
        {
            span set;
            CRYPT_DATA_BLOB **arr;
            DWORD *cnt;

            if (!der_read(&orig, &tag, &set, NULL)) goto done;
            if (tag == 0xa0) { arr = &env->certs; cnt = &env->n_cert; }
            else if (tag == 0xa1) { arr = &env->crls; cnt = &env->n_crl; }
            else { SetLastError(CRYPT_E_ASN1_BADTAG); goto done; }
            if (*arr) { SetLastError(CRYPT_E_ASN1_CORRUPT); goto done; }
            for (n = 0, el = set; el.n; n++) if (!der_read(&el, NULL, NULL, NULL)) goto done;
            if (!n) continue;
            if (!(*arr = alloc_array(n, sizeof(**arr)))) { SetLastError(ERROR_OUTOFMEMORY); goto done; }
            for (el = set; el.n;)
            {
                if (!der_read(&el, &tag, NULL, &whole)) goto done;
                if (tag != 0x30) continue;  /* attribute certificates and other formats */
                (*arr)[*cnt].cbData = whole.n;
                (*arr)[*cnt].pbData = (BYTE *)whole.p;
                (*cnt)++;
            }
        }
    }
    if (!der_expect(&seq, 0x31, &rset, NULL)) goto done;
    for (n = 0, v = rset; v.n; n++) if (!der_read(&v, NULL, NULL, NULL)) goto done;
    if (n > CMS_MAX_RECIPIENTS) { SetLastError(CRYPT_E_ASN1_LARGE); goto done; }
    if (n)
    {
        if (!(env->recip = alloc_array(n, sizeof(*env->recip))) || !(env->ktri_index = alloc_array(n, sizeof(DWORD))))
        { SetLastError(ERROR_OUTOFMEMORY); goto done; }
        memset(env->recip, 0, n * sizeof(*env->recip));
    }
    env->n_recip = n;
    for (i = 0, v = rset; i < n; i++)
    {
        span ri;

        if (!der_read(&v, &tag, &ri, NULL)) goto done;
        switch (tag)
        {
        case 0x30:
            if (!parse_ktri(&env->recip[i], ri)) goto done;
            env->ktri_index[env->n_ktri++] = i;
            break;
        case 0xa1: env->recip[i].choice = CMSG_KEY_AGREE_RECIPIENT; break;
        case 0xa2: env->recip[i].choice = CMSG_MAIL_LIST_RECIPIENT; break;
        case 0xa3:
        case 0xa4: env->recip[i].choice = 0; break;
        default: SetLastError(CRYPT_E_ASN1_BADTAG); goto done;
        }
    }
    if (!der_expect(&seq, 0x30, &eci, NULL)) goto done;
    if (!der_oid_string(&eci, &env->content_type)) goto done;
    if (!der_expect(&eci, 0x30, &alg, NULL)) goto done;
    if (!der_algid(alg, &env->alg_oid, &env->alg_params)) goto done;
    if (eci.n)
    {
        if (!der_peek(&eci, &tag) || (tag != 0x80 && tag != 0xa0)) { SetLastError(CRYPT_E_ASN1_BADTAG); goto done; }
        if (!der_read(&eci, NULL, &v, NULL) || eci.n) { if (eci.n) SetLastError(CRYPT_E_ASN1_CORRUPT); goto done; }
        env->has_content = TRUE;
        if (tag == 0xa0)
        {
            /* BER: the content in segments */
            struct wbuf w = { 0 };

            if (!collect_octets(v, &w, 0)) { w_free(&w); goto done; }
            env->content_buf = w.p;
            env->content.cbData = w.n;
            env->content.pbData = w.p;
            if (!w.n) { env->content_buf = NULL; w_free(&w); env->content.pbData = NULL; }
        }
        else
        {
            env->content.cbData = v.n;
            env->content.pbData = (BYTE *)v.p;
        }
    }
    if (seq.n)
    {
        if (!der_peek(&seq, &tag) || tag != 0xa1) { SetLastError(CRYPT_E_ASN1_BADTAG); goto done; }
        if (!der_read(&seq, NULL, NULL, &whole)) goto done;
        env->has_attrs = TRUE;
        env->attrs.cbData = whole.n;
        env->attrs.pbData = (BYTE *)whole.p;
    }
    ok = TRUE;
done:
    if (ok) *out = env;
    else CMSEnv_Free(env);
    return ok;
}

static BYTE *w_steal(struct wbuf *w, DWORD *len);

/* ------------------------------------------------------------------------------------------ */
/* GetParam helpers                                                                           */
/* ------------------------------------------------------------------------------------------ */

#define ALIGN8(x) (((x) + 7) & ~(DWORD)7)

/* Windows hands decrypted content of a type other than data back as a SEQUENCE around the content octets */
BYTE *CMSEnv_WrapContent(const BYTE *content, DWORD len, DWORD *out_len)
{
    struct wbuf w = { 0 };

    w_tlv(&w, 0x30, content, len);
    return w_steal(&w, out_len);
}

BOOL CMSEnv_CopyAlgorithm(const struct cms_env *env, void *pv, DWORD *pcb)
{
    DWORD oid_len = strlen(env->alg_oid) + 1, need = ALIGN8(sizeof(CRYPT_ALGORITHM_IDENTIFIER)) + ALIGN8(oid_len) + env->alg_params.cbData;
    CRYPT_ALGORITHM_IDENTIFIER *a = pv;
    BYTE *next;

    if (!pv) { *pcb = need; return TRUE; }
    if (*pcb < need) { *pcb = need; SetLastError(ERROR_MORE_DATA); return FALSE; }
    next = (BYTE *)pv + ALIGN8(sizeof(*a));
    a->pszObjId = (char *)next;
    memcpy(next, env->alg_oid, oid_len);
    next += ALIGN8(oid_len);
    a->Parameters.cbData = env->alg_params.cbData;
    a->Parameters.pbData = env->alg_params.cbData ? next : NULL;
    if (env->alg_params.cbData) memcpy(next, env->alg_params.pbData, env->alg_params.cbData);
    *pcb = need;
    return TRUE;
}

BOOL CMSEnv_CopyCmsRecipient(const struct cms_recip *r, void *pv, DWORD *pcb)
{
    DWORD oid_len, need, a = ALIGN8(sizeof(CMSG_CMS_RECIPIENT_INFO)), b = ALIGN8(sizeof(CMSG_KEY_TRANS_RECIPIENT_INFO));
    CMSG_CMS_RECIPIENT_INFO *info = pv;
    CMSG_KEY_TRANS_RECIPIENT_INFO *kt;
    BYTE *next;

    if (r->choice != CMSG_KEY_TRANS_RECIPIENT) { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    oid_len = strlen(r->alg_oid) + 1;
    need = a + b + ALIGN8(oid_len) + ALIGN8(r->alg_params.cbData) + r->enc_key.cbData;
    if (r->id.dwIdChoice == CERT_ID_KEY_IDENTIFIER) need += r->id.KeyId.cbData;
    else need += ALIGN8(r->id.IssuerSerialNumber.Issuer.cbData) + r->id.IssuerSerialNumber.SerialNumber.cbData;
    if (!pv) { *pcb = need; return TRUE; }
    if (*pcb < need) { *pcb = need; SetLastError(ERROR_MORE_DATA); return FALSE; }
    memset(pv, 0, need);
    info->dwRecipientChoice = CMSG_KEY_TRANS_RECIPIENT;
    kt = (CMSG_KEY_TRANS_RECIPIENT_INFO *)((BYTE *)pv + a);
    info->pKeyTrans = kt;
    next = (BYTE *)pv + a + b;
    kt->dwVersion = r->version;
    kt->RecipientId.dwIdChoice = r->id.dwIdChoice;
    kt->KeyEncryptionAlgorithm.pszObjId = (char *)next;
    memcpy(next, r->alg_oid, oid_len);
    next += ALIGN8(oid_len);
    if (r->alg_params.cbData)
    {
        kt->KeyEncryptionAlgorithm.Parameters.cbData = r->alg_params.cbData;
        kt->KeyEncryptionAlgorithm.Parameters.pbData = next;
        memcpy(next, r->alg_params.pbData, r->alg_params.cbData);
        next += ALIGN8(r->alg_params.cbData);
    }
    if (r->id.dwIdChoice == CERT_ID_KEY_IDENTIFIER)
    {
        kt->RecipientId.KeyId.cbData = r->id.KeyId.cbData;
        kt->RecipientId.KeyId.pbData = next;
        memcpy(next, r->id.KeyId.pbData, r->id.KeyId.cbData);
        next += r->id.KeyId.cbData;
    }
    else
    {
        kt->RecipientId.IssuerSerialNumber.Issuer.cbData = r->id.IssuerSerialNumber.Issuer.cbData;
        kt->RecipientId.IssuerSerialNumber.Issuer.pbData = next;
        memcpy(next, r->id.IssuerSerialNumber.Issuer.pbData, r->id.IssuerSerialNumber.Issuer.cbData);
        next += ALIGN8(r->id.IssuerSerialNumber.Issuer.cbData);
        kt->RecipientId.IssuerSerialNumber.SerialNumber.cbData = r->id.IssuerSerialNumber.SerialNumber.cbData;
        kt->RecipientId.IssuerSerialNumber.SerialNumber.pbData = next;
        memcpy(next, r->id.IssuerSerialNumber.SerialNumber.pbData, r->id.IssuerSerialNumber.SerialNumber.cbData);
        next += r->id.IssuerSerialNumber.SerialNumber.cbData;
    }
    kt->EncryptedKey.cbData = r->enc_key.cbData;
    kt->EncryptedKey.pbData = next;
    memcpy(next, r->enc_key.pbData, r->enc_key.cbData);
    *pcb = need;
    return TRUE;
}

/* ------------------------------------------------------------------------------------------ */
/* encoding                                                                                   */
/* ------------------------------------------------------------------------------------------ */

struct cms_enc
{
    struct cms_cipher cipher;
    BYTE key[32];
    DWORD keylen;
    char *content_type;
    BYTE *alg_der;              /* the content encryption AlgorithmIdentifier */
    DWORD alg_der_len;
    DWORD n_recip;
    CRYPT_DATA_BLOB *recip;     /* RecipientInfo elements, sorted */
    BYTE *orig;                 /* originatorInfo [0] element */
    DWORD orig_len;
    BYTE *attrs;                /* unprotectedAttrs [1] element */
    DWORD attrs_len;
    DWORD version;
    BYTE *ct;
    DWORD ct_len;
    BOOL has_ct;
    BOOL encoded_input;         /* pszInnerContentObjID was given: the data to encrypt are an encoded value */
};

void CMSEnv_EncFree(struct cms_enc *e)
{
    DWORD i;

    if (!e) return;
    SecureZeroMemory(e->key, sizeof(e->key));
    for (i = 0; i < e->n_recip; i++) CryptMemFree(e->recip[i].pbData);
    CryptMemFree(e->recip);
    CryptMemFree(e->content_type);
    CryptMemFree(e->alg_der);
    CryptMemFree(e->orig);
    CryptMemFree(e->attrs);
    CryptMemFree(e->ct);
    CryptMemFree(e);
}

static BYTE *w_steal(struct wbuf *w, DWORD *len)
{
    BYTE *r;

    if (w->err || !(r = CryptMemAlloc(w->n ? w->n : 1))) { w_free(w); return NULL; }
    memcpy(r, w->p, w->n);
    *len = w->n;
    w_free(w);
    return r;
}

static BOOL is_null_params(const CRYPT_DATA_BLOB *p)
{
    return p->cbData == 2 && p->pbData && p->pbData[0] == 0x05 && !p->pbData[1];
}

/* settles key size, IV and the AlgorithmIdentifier of the content encryption */
static BOOL enc_setup_cipher(struct cms_enc *e, const char *oid, const CRYPT_DATA_BLOB *params, const void *aux)
{
    const struct cipher_def *d = find_cipher(oid);
    struct wbuf w = { 0 };
    CRYPT_DATA_BLOB iv_given = { 0, NULL };
    DWORD bits = 0, i;
    BOOL no_salt = FALSE;

    if (!d) { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    memset(&e->cipher, 0, sizeof(e->cipher));
    e->cipher.kind = d->kind;
    e->cipher.ivlen = d->ivlen;
    e->cipher.keylen = d->keylen;
    e->keylen = d->keylen;
    if (d->kind == P12_CIPHER_RC2 || d->kind == P12_CIPHER_RC4)
    {
        if (aux)
        {
            const struct cms_rc_aux *a = aux;

            if (a->cbSize != sizeof(*a)) { SetLastError(E_INVALIDARG); return FALSE; }
            bits = a->dwBitLen & 0xffff;
            no_salt = !!(a->dwBitLen & 0x40000000);
            if (a->dwBitLen & 0x80000000) FIXME("CMSG_SP3_COMPATIBLE_ENCRYPT_FLAG is not supported\n");
        }
        if (d->kind == P12_CIPHER_RC2)
        {
            if (!bits) bits = 40;
            for (i = 0; i < ARRAY_SIZE(rc2_versions) && rc2_versions[i].bits != bits; i++) ;
            if (i == ARRAY_SIZE(rc2_versions)) { SetLastError(E_INVALIDARG); return FALSE; }
            e->cipher.rc2bits = bits;
        }
        else if (!bits) bits = 128;
        if (bits % 8 || bits < 40 || bits > 128) { SetLastError(E_INVALIDARG); return FALSE; }
        e->keylen = bits / 8;
        if (d->kind == P12_CIPHER_RC4 && e->keylen < 16 && !no_salt)
            e->cipher.salt_len = 16 - e->keylen;
    }
    if (params && params->cbData && !is_null_params(params) && d->kind != P12_CIPHER_RC4)
    {
        struct cms_cipher given;

        if (!cipher_from_alg(oid, params, &given)) { SetLastError(E_INVALIDARG); return FALSE; }
        memcpy(e->cipher.iv, given.iv, given.ivlen);
        if (d->kind == P12_CIPHER_RC2) e->cipher.rc2bits = given.rc2bits;
        iv_given.cbData = 1;
    }
    if (d->ivlen && !iv_given.cbData && p12_random(e->cipher.iv, d->ivlen)) { SetLastError(NTE_FAIL); return FALSE; }
    if (d->kind == P12_CIPHER_RC2 && e->cipher.rc2bits != 0)
    {
        for (i = 0; i < ARRAY_SIZE(rc2_versions) && rc2_versions[i].bits != e->cipher.rc2bits; i++) ;
        if (i == ARRAY_SIZE(rc2_versions)) { SetLastError(E_INVALIDARG); return FALSE; }
        e->keylen = e->cipher.rc2bits / 8;
    }
    /* the key size is settled now: the random key must fill all of it */
    if (p12_random(e->key, e->keylen) || (e->cipher.salt_len && p12_random(e->cipher.salt, e->cipher.salt_len)))
    {
        SetLastError(NTE_FAIL);
        return FALSE;
    }

    /* AlgorithmIdentifier */
    {
        struct wbuf p = { 0 };

        switch (d->kind)
        {
        case P12_CIPHER_RC2:
        {
            struct wbuf q = { 0 };

            for (i = 0; rc2_versions[i].bits != e->cipher.rc2bits; i++) ;
            w_uint(&q, rc2_versions[i].version);
            w_tlv(&q, 0x04, e->cipher.iv, 8);
            w_wrap(&p, 0x30, &q);
            break;
        }
        case P12_CIPHER_RC4:
            if (e->cipher.salt_len) w_tlv(&p, 0x04, e->cipher.salt, e->cipher.salt_len);
            break;
        default:
            w_tlv(&p, 0x04, e->cipher.iv, d->ivlen);
        }
        w_algid(&w, oid, p.p, p.n, TRUE);
        w_free(&p);
    }
    if (!(e->alg_der = w_steal(&w, &e->alg_der_len))) { SetLastError(ERROR_OUTOFMEMORY); return FALSE; }
    return TRUE;
}

static BOOL enc_recipient(struct cms_enc *e, const struct cms_enc_recip *r, struct wbuf *out)
{
    struct wbuf ri = { 0 }, rid = { 0 }, alg = { 0 }, oaepder = { 0 };
    struct oaep oaep;
    const char *kalg = r->key_alg ? r->key_alg : OID_RSA_ENCRYPTION;
    BOOL is_oaep, ret = FALSE;
    BYTE *wrapped = NULL;
    DWORD wrapped_len = 0, version;
    CRYPT_DATA_BLOB params = { 0, NULL };

    if (!strcmp(kalg, OID_RSAES_OAEP)) is_oaep = TRUE;
    else if (!strcmp(kalg, OID_RSA_ENCRYPTION)) is_oaep = FALSE;
    else { SetLastError(CRYPT_E_UNKNOWN_ALGO); return FALSE; }
    if (is_oaep)
    {
        if (r->key_alg_params.cbData && !is_null_params(&r->key_alg_params)) params = r->key_alg_params;
        else if (r->oaep)
        {
            if (!build_oaep(r->oaep, &oaepder)) { w_free(&oaepder); return FALSE; }
            params.cbData = oaepder.n;
            params.pbData = oaepder.p;
        }
        else
        {
            static const BYTE empty[] = { 0x30, 0x00 };
            params.cbData = sizeof(empty);
            params.pbData = (BYTE *)empty;
        }
        if (!parse_oaep(&params, &oaep)) goto done;
    }
    if (!rsa_wrap(&r->public_key, is_oaep, &oaep, e->key, e->keylen, &wrapped, &wrapped_len)) goto done;

    if (r->id_choice == CERT_ID_KEY_IDENTIFIER)
    {
        if (!r->key_id.cbData) { SetLastError(E_INVALIDARG); goto done; }
        version = 2;
        w_tlv(&rid, 0x80, r->key_id.pbData, r->key_id.cbData);
    }
    else if (r->id_choice == CERT_ID_ISSUER_SERIAL_NUMBER)
    {
        struct wbuf in = { 0 };
        span chk;

        chk.p = r->issuer.pbData;
        chk.n = r->issuer.cbData;
        if (!r->issuer.cbData || !der_expect(&chk, 0x30, NULL, NULL) || chk.n) { SetLastError(E_INVALIDARG); goto done; }
        version = 0;
        w_add(&in, r->issuer.pbData, r->issuer.cbData);
        w_integer_le(&in, r->serial_le.pbData, r->serial_le.cbData);
        w_wrap(&rid, 0x30, &in);
    }
    else { SetLastError(E_INVALIDARG); goto done; }

    w_uint(&ri, version);
    w_add(&ri, rid.p, rid.n);
    w_algid(&alg, kalg, is_oaep ? params.pbData : NULL, is_oaep ? params.cbData : 0, !is_oaep);
    w_add(&ri, alg.p, alg.n);
    w_tlv(&ri, 0x04, wrapped, wrapped_len);
    if (version != 0) e->version = 2;
    w_wrap(out, 0x30, &ri);
    ret = !out->err;
    if (!ret) SetLastError(ERROR_OUTOFMEMORY);
done:
    CryptMemFree(wrapped);
    w_free(&ri); w_free(&rid); w_free(&alg); w_free(&oaepder);
    return ret;
}

struct cms_enc *CMSEnv_EncNew(const char *content_type, const char *content_alg, const CRYPT_DATA_BLOB *alg_params,
                              const void *aux, DWORD n_recip, const struct cms_enc_recip *recip,
                              DWORD n_cert, const CERT_BLOB *certs, DWORD n_crl, const CRL_BLOB *crls,
                              DWORD n_attr, const CRYPT_ATTRIBUTE *attrs)
{
    struct cms_enc *e = CryptMemAlloc(sizeof(*e));
    DWORD i;

    if (!e) { SetLastError(ERROR_OUTOFMEMORY); return NULL; }
    memset(e, 0, sizeof(*e));
    e->encoded_input = content_type != NULL;
    if (content_type && !strcmp(content_type, szOID_RSA_data)) content_type = NULL;
    if (content_type)
    {
        struct wbuf chk = { 0 };
        BOOL valid = oid_to_der(content_type, &chk);

        w_free(&chk);
        if (!valid) { SetLastError(E_INVALIDARG); goto fail; }
        if (!(e->content_type = CryptMemAlloc(strlen(content_type) + 1))) { SetLastError(ERROR_OUTOFMEMORY); goto fail; }
        strcpy(e->content_type, content_type);
    }
    if (!enc_setup_cipher(e, content_alg, alg_params, aux)) goto fail;
    if (n_recip && !(e->recip = alloc_array(n_recip, sizeof(*e->recip)))) { SetLastError(ERROR_OUTOFMEMORY); goto fail; }
    if (n_recip) memset(e->recip, 0, n_recip * sizeof(*e->recip));
    for (i = 0; i < n_recip; i++)
    {
        struct wbuf w = { 0 };

        if (!enc_recipient(e, &recip[i], &w)) { w_free(&w); goto fail; }
        e->recip[i].pbData = w_steal(&w, &e->recip[i].cbData);
        if (!e->recip[i].pbData) { SetLastError(ERROR_OUTOFMEMORY); goto fail; }
        e->n_recip = i + 1;
    }
    if (e->n_recip > 1) qsort(e->recip, e->n_recip, sizeof(*e->recip), cmp_der);
    if (n_cert || n_crl)
    {
        struct wbuf o = { 0 }, set = { 0 };
        CRYPT_DATA_BLOB *sorted;
        DWORD n = n_cert > n_crl ? n_cert : n_crl;

        if (!(sorted = alloc_array(n, sizeof(*sorted)))) { SetLastError(ERROR_OUTOFMEMORY); goto fail; }
        if (n_cert)
        {
            for (i = 0; i < n_cert; i++) { sorted[i].cbData = certs[i].cbData; sorted[i].pbData = certs[i].pbData; }
            qsort(sorted, n_cert, sizeof(*sorted), cmp_der);
            for (i = 0; i < n_cert; i++) w_add(&set, sorted[i].pbData, sorted[i].cbData);
            w_wrap(&o, 0xa0, &set);
        }
        if (n_crl)
        {
            for (i = 0; i < n_crl; i++) { sorted[i].cbData = crls[i].cbData; sorted[i].pbData = crls[i].pbData; }
            qsort(sorted, n_crl, sizeof(*sorted), cmp_der);
            for (i = 0; i < n_crl; i++) w_add(&set, sorted[i].pbData, sorted[i].cbData);
            w_wrap(&o, 0xa1, &set);
        }
        CryptMemFree(sorted);
        {
            struct wbuf all = { 0 };

            w_wrap(&all, 0xa0, &o);
            if (!(e->orig = w_steal(&all, &e->orig_len))) { SetLastError(ERROR_OUTOFMEMORY); goto fail; }
        }
        e->version = 2;
    }
    if (n_attr)
    {
        CRYPT_ATTRIBUTES set;
        DWORD size = 0;

        set.cAttr = n_attr;
        set.rgAttr = (CRYPT_ATTRIBUTE *)attrs;
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_ATTRIBUTES, &set, CRYPT_ENCODE_ALLOC_FLAG,
                                 NULL, &e->attrs, &size)) goto fail;
        /* a SET OF becomes the [1] IMPLICIT unprotectedAttrs: same content, other tag. Keep it in
         * CryptMemAlloc memory */
        {
            BYTE *copy = CryptMemAlloc(size);

            if (!copy) { LocalFree(e->attrs); e->attrs = NULL; SetLastError(ERROR_OUTOFMEMORY); goto fail; }
            memcpy(copy, e->attrs, size);
            LocalFree(e->attrs);
            copy[0] = 0xa1;
            e->attrs = copy;
            e->attrs_len = size;
        }
        e->version = 2;
    }
    return e;
fail:
    {
        DWORD err = GetLastError();

        CMSEnv_EncFree(e);
        SetLastError(err);
    }
    return NULL;
}

BOOL CMSEnv_EncContent(struct cms_enc *e, const BYTE *data, DWORD len)
{
    BYTE *ct;
    DWORD ct_len;

    if (e->encoded_input)
    {
        /* With an inner content type given, Windows takes the data as an encoded value (an OCTET STRING for
         * data) and encrypts what is inside it: the content octets without tag and length. */
        span s, v;

        s.p = data;
        s.n = len;
        if (!der_read(&s, NULL, &v, NULL) || s.n)
        {
            SetLastError(CRYPT_E_UNEXPECTED_ENCODING);
            return FALSE;
        }
        data = v.p;
        len = v.n;
    }
    if (!cipher_run(&e->cipher, e->key, e->keylen, TRUE, data, len, &ct, &ct_len)) return FALSE;
    CryptMemFree(e->ct);
    e->ct = ct;
    e->ct_len = ct_len;
    e->has_ct = TRUE;
    return TRUE;
}

BOOL CMSEnv_EncGetBare(const struct cms_enc *e, void *pv, DWORD *pcb)
{
    struct wbuf out = { 0 }, body = { 0 }, set = { 0 }, eci = { 0 };
    DWORD i;
    BOOL ret = FALSE;

    w_uint(&body, e->version);
    if (e->orig) w_add(&body, e->orig, e->orig_len);
    for (i = 0; i < e->n_recip; i++) w_add(&set, e->recip[i].pbData, e->recip[i].cbData);
    w_wrap(&body, 0x31, &set);
    if (!oid_to_der(e->content_type ? e->content_type : szOID_RSA_data, &eci)) { w_free(&eci); SetLastError(E_INVALIDARG); goto done; }
    w_add(&eci, e->alg_der, e->alg_der_len);
    w_tlv(&eci, 0x80, e->has_ct ? e->ct : NULL, e->has_ct ? e->ct_len : 0);
    w_wrap(&body, 0x30, &eci);
    if (e->attrs) w_add(&body, e->attrs, e->attrs_len);
    w_wrap(&out, 0x30, &body);
    if (out.err) { SetLastError(ERROR_OUTOFMEMORY); goto done; }
    if (!pv) { *pcb = out.n; ret = TRUE; }
    else if (*pcb < out.n) { *pcb = out.n; SetLastError(ERROR_MORE_DATA); }
    else { memcpy(pv, out.p, out.n); *pcb = out.n; ret = TRUE; }
done:
    w_free(&out); w_free(&body); w_free(&set);
    return ret;
}

/* ------------------------------------------------------------------------------------------ */
/* streamed encoding                                                                          */
/* ------------------------------------------------------------------------------------------ */

#define STREAM_MAX_LEN 0xfffffff0u

static ULONGLONG hdr_size(ULONGLONG len)
{
    return 1 + (len < 0x80 ? 1 : len < 0x100 ? 2 : len < 0x10000 ? 3 : len < 0x1000000 ? 4 : 5);
}

/* the length of the encoded value's content octets, given the length of the whole encoded value */
static ULONGLONG inner_len(ULONGLONG total)
{
    ULONGLONG h;

    for (h = 2; h <= 6 && h < total; h++) if (hdr_size(total - h) == h) return total - h;
    return total;
}

static BOOL stream_emit(cms_emit_fn emit, void *ctx, const BYTE *pb, DWORD cb, BOOL final)
{
    static const BYTE none = 0;

    return !emit || emit(ctx, cb ? pb : &none, cb, final);
}

/* the header up to the opening of the encrypted content: with a definite length every enclosing length is
 * known from the declared content size, with an indefinite length every enclosing element is open ended */
BOOL CMSEnv_EncStreamStart(struct cms_enc *e, BOOL indefinite, DWORD cb_content, cms_emit_fn emit, void *ctx)
{
    struct wbuf pre = { 0 }, set = { 0 }, env_oid = { 0 }, ct_oid = { 0 }, out = { 0 };
    ULONGLONG L = 0, eci_len, body_len, a0_len, ci_len;
    BOOL ret = FALSE;

    w_uint(&pre, e->version);
    if (e->orig) w_add(&pre, e->orig, e->orig_len);
    {
        DWORD i;

        for (i = 0; i < e->n_recip; i++) w_add(&set, e->recip[i].pbData, e->recip[i].cbData);
    }
    w_wrap(&pre, 0x31, &set);
    if (!oid_to_der(szOID_RSA_envelopedData, &env_oid) ||
        !oid_to_der(e->content_type ? e->content_type : szOID_RSA_data, &ct_oid))
    {
        SetLastError(E_INVALIDARG);
        goto done;
    }
    if (pre.err || env_oid.err || ct_oid.err) { SetLastError(ERROR_OUTOFMEMORY); goto done; }
    if (indefinite)
    {
        static const BYTE open_seq[] = { 0x30, 0x80 }, open_ctx[] = { 0xa0, 0x80 };

        w_add(&out, open_seq, 2);
        w_add(&out, env_oid.p, env_oid.n);
        w_add(&out, open_ctx, 2);
        w_add(&out, open_seq, 2);
        w_add(&out, pre.p, pre.n);
        w_add(&out, open_seq, 2);
        w_add(&out, ct_oid.p, ct_oid.n);
        w_add(&out, e->alg_der, e->alg_der_len);
        w_add(&out, open_ctx, 2);
    }
    else
    {
        ULONGLONG n = cb_content;

        if (e->encoded_input && n) n = inner_len(n);
        if (n) L = (e->cipher.ivlen ? (n / e->cipher.ivlen + 1) * e->cipher.ivlen : n);
        eci_len = ct_oid.n + (ULONGLONG)e->alg_der_len + hdr_size(L) + L;
        body_len = pre.n + hdr_size(eci_len) + eci_len + (e->attrs ? e->attrs_len : 0);
        a0_len = hdr_size(body_len) + body_len;
        ci_len = env_oid.n + hdr_size(a0_len) + a0_len;
        if (ci_len > STREAM_MAX_LEN) { SetLastError(ERROR_OUTOFMEMORY); goto done; }
        w_header(&out, 0x30, (DWORD)ci_len);
        w_add(&out, env_oid.p, env_oid.n);
        w_header(&out, 0xa0, (DWORD)a0_len);
        w_header(&out, 0x30, (DWORD)body_len);
        w_add(&out, pre.p, pre.n);
        w_header(&out, 0x30, (DWORD)eci_len);
        w_add(&out, ct_oid.p, ct_oid.n);
        w_add(&out, e->alg_der, e->alg_der_len);
        w_header(&out, 0x80, (DWORD)L);
    }
    if (out.err) { SetLastError(ERROR_OUTOFMEMORY); goto done; }
    ret = stream_emit(emit, ctx, out.p, out.n, FALSE);
done:
    w_free(&pre); w_free(&env_oid); w_free(&ct_oid); w_free(&out);
    return ret;
}

/* encrypts everything the application streamed in and sends the rest of the message. No data at all
 * gives an empty encrypted content, without a padding block. */
BOOL CMSEnv_EncStreamFinish(struct cms_enc *e, BOOL indefinite, const BYTE *data, DWORD len,
                            cms_emit_fn emit, void *ctx)
{
    static const BYTE eoc[6] = { 0 };
    const BYTE *ct = NULL;
    DWORD ct_len = 0;

    if (len)
    {
        if (!CMSEnv_EncContent(e, data, len)) return FALSE;
        ct = e->ct;
        ct_len = e->ct_len;
    }
    if (!indefinite)
    {
        if (!stream_emit(emit, ctx, ct, ct_len, !e->attrs)) return FALSE;
        return !e->attrs || stream_emit(emit, ctx, e->attrs, e->attrs_len, TRUE);
    }
    if (ct_len)
    {
        struct wbuf h = { 0 };
        BOOL ok;

        w_header(&h, 0x04, ct_len);
        ok = !h.err && stream_emit(emit, ctx, h.p, h.n, FALSE);
        w_free(&h);
        if (!ok || !stream_emit(emit, ctx, ct, ct_len, FALSE)) return FALSE;
    }
    if (!stream_emit(emit, ctx, eoc, 4, FALSE)) return FALSE;
    if (e->attrs && !stream_emit(emit, ctx, e->attrs, e->attrs_len, FALSE)) return FALSE;
    return stream_emit(emit, ctx, eoc, 6, TRUE);
}
