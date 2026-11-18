/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The NTLM server (AcceptSecurityContext, packages NTLM and Negotiate) takes a valid NTLMv2 AUTHENTICATE
 *              as the clients of the network level authentication of remote desktop (CredSSP) send it: NEGOTIATE_56 set
 *              though not offered, an empty domain, a zero LM response, MsvAvFlags with a MIC, the timestamp, an all
 *              zero MsvAvChannelBindings, MsvAvTargetName. The client side is written here from [MS-NLMP] (MD4, MD5,
 *              HMAC-MD5, RC4, NTOWFv2, the NTLMv2 response, the key exchange, the MIC) so that every field can be
 *              changed. The application's channel bindings (SECBUFFER_CHANNEL_BINDINGS) are checked when the client
 *              names some and ignored when it does not.
 *              The expected statuses are those of this tree's server; where the one of Windows is not measured the case
 *              says so (VERIFY ON PEER).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdio.h>
#include <math.h>
#include <windef.h>
#include <winbase.h>
#include <lmaccess.h>
#include <lmerr.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define TEST_PASSWORD L"Srv#Auth1pw"
#define MAXT 8192

#ifndef SEC_E_BAD_BINDINGS
#define SEC_E_BAD_BINDINGS ((SECURITY_STATUS)0x80090346)
#endif

/* ---- the primitives (RFC 1320, RFC 1321, RFC 2104, the RC4 stream cipher) ---- */

typedef struct { ULONG a, b, c, d; BYTE buf[64]; ULONG64 bits; ULONG used; } HASH_CTX;

static ULONG rol(ULONG x, int n) { return (x << n) | (x >> (32 - n)); }
static ULONG ld32(const BYTE *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((ULONG)p[3] << 24); }
static void st32(BYTE *p, ULONG v) { p[0] = (BYTE)v; p[1] = (BYTE)(v >> 8); p[2] = (BYTE)(v >> 16); p[3] = (BYTE)(v >> 24); }
static void st16(BYTE *p, ULONG v) { p[0] = (BYTE)v; p[1] = (BYTE)(v >> 8); }

static void md4_block(HASH_CTX *c, const BYTE *p)
{
    ULONG x[16], a = c->a, b = c->b, cc = c->c, d = c->d;
    int i;

    for (i = 0; i < 16; i++) x[i] = ld32(p + 4 * i);
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
    for (i = 0; i < 16; i += 4)
    {
        static const int s[4] = { 3, 7, 11, 19 };
        a = rol(a + F(b, cc, d) + x[i], s[0]);
        d = rol(d + F(a, b, cc) + x[i + 1], s[1]);
        cc = rol(cc + F(d, a, b) + x[i + 2], s[2]);
        b = rol(b + F(cc, d, a) + x[i + 3], s[3]);
    }
    for (i = 0; i < 4; i++)
    {
        static const int s[4] = { 3, 5, 9, 13 };
        a = rol(a + G(b, cc, d) + x[i] + 0x5a827999, s[0]);
        d = rol(d + G(a, b, cc) + x[i + 4] + 0x5a827999, s[1]);
        cc = rol(cc + G(d, a, b) + x[i + 8] + 0x5a827999, s[2]);
        b = rol(b + G(cc, d, a) + x[i + 12] + 0x5a827999, s[3]);
    }
    {
        static const int o[4] = { 0, 2, 1, 3 };
        static const int s[4] = { 3, 9, 11, 15 };
        for (i = 0; i < 4; i++)
        {
            int k = o[i];
            a = rol(a + H(b, cc, d) + x[k] + 0x6ed9eba1, s[0]);
            d = rol(d + H(a, b, cc) + x[k + 8] + 0x6ed9eba1, s[1]);
            cc = rol(cc + H(d, a, b) + x[k + 4] + 0x6ed9eba1, s[2]);
            b = rol(b + H(cc, d, a) + x[k + 12] + 0x6ed9eba1, s[3]);
        }
    }
#undef F
#undef G
#undef H
    c->a += a; c->b += b; c->c += cc; c->d += d;
}

static void md5_block(HASH_CTX *c, const BYTE *p)
{
    static const int sh[64] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                                4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
    static ULONG K[64];
    ULONG m[16], a = c->a, b = c->b, cc = c->c, d = c->d;
    int i;

    if (!K[0])
        for (i = 0; i < 64; i++) K[i] = (ULONG)(fabs(sin((double)(i + 1))) * 4294967296.0);
    for (i = 0; i < 16; i++) m[i] = ld32(p + 4 * i);
    for (i = 0; i < 64; i++)
    {
        ULONG f, t;
        int g;

        if (i < 16) { f = (b & cc) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & cc); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ cc ^ d; g = (3 * i + 5) & 15; }
        else { f = cc ^ (b | ~d); g = (7 * i) & 15; }
        t = d; d = cc; cc = b;
        b = b + rol(a + f + K[i] + m[g], sh[i]);
        a = t;
    }
    c->a += a; c->b += b; c->c += cc; c->d += d;
}

static void h_init(HASH_CTX *c)
{
    memset(c, 0, sizeof(*c));
    c->a = 0x67452301; c->b = 0xefcdab89; c->c = 0x98badcfe; c->d = 0x10325476;
}

static void h_update(HASH_CTX *c, BOOL md5, const void *data, ULONG len)
{
    const BYTE *p = data;

    c->bits += (ULONG64)len * 8;
    while (len)
    {
        ULONG n = 64 - c->used;

        if (n > len) n = len;
        memcpy(c->buf + c->used, p, n);
        c->used += n; p += n; len -= n;
        if (c->used == 64)
        {
            if (md5) md5_block(c, c->buf); else md4_block(c, c->buf);
            c->used = 0;
        }
    }
}

static void h_final(HASH_CTX *c, BOOL md5, BYTE *out)
{
    ULONG64 bits = c->bits;
    BYTE pad[72] = { 0x80 }, len[8];
    ULONG n = (c->used < 56) ? 56 - c->used : 120 - c->used;

    st32(len, (ULONG)bits); st32(len + 4, (ULONG)(bits >> 32));
    h_update(c, md5, pad, n);
    h_update(c, md5, len, 8);
    st32(out, c->a); st32(out + 4, c->b); st32(out + 8, c->c); st32(out + 12, c->d);
}

static void md4(const void *data, ULONG len, BYTE *out)
{
    HASH_CTX c; h_init(&c); h_update(&c, FALSE, data, len); h_final(&c, FALSE, out);
}

static void md5(const void *data, ULONG len, BYTE *out)
{
    HASH_CTX c; h_init(&c); h_update(&c, TRUE, data, len); h_final(&c, TRUE, out);
}

typedef struct { HASH_CTX in; BYTE okey[64]; } HMAC;

static void hmac_init(HMAC *h, const BYTE *key, ULONG key_len)
{
    BYTE k[64] = { 0 }, ik[64];
    int i;

    if (key_len > 64) md5(key, key_len, k); else memcpy(k, key, key_len);
    for (i = 0; i < 64; i++) { ik[i] = k[i] ^ 0x36; h->okey[i] = k[i] ^ 0x5c; }
    h_init(&h->in);
    h_update(&h->in, TRUE, ik, 64);
}

static void hmac_update(HMAC *h, const void *data, ULONG len) { h_update(&h->in, TRUE, data, len); }

static void hmac_final(HMAC *h, BYTE *out)
{
    HASH_CTX o;
    BYTE inner[16];

    h_final(&h->in, TRUE, inner);
    h_init(&o);
    h_update(&o, TRUE, h->okey, 64);
    h_update(&o, TRUE, inner, 16);
    h_final(&o, TRUE, out);
}

static void hmac_md5(const BYTE *key, ULONG key_len, const void *a, ULONG a_len, const void *b, ULONG b_len, BYTE *out)
{
    HMAC h;

    hmac_init(&h, key, key_len);
    hmac_update(&h, a, a_len);
    if (b_len) hmac_update(&h, b, b_len);
    hmac_final(&h, out);
}

static void rc4(const BYTE *key, ULONG key_len, BYTE *data, ULONG len)
{
    BYTE s[256], t;
    ULONG i, j = 0, x = 0, y = 0;

    for (i = 0; i < 256; i++) s[i] = (BYTE)i;
    for (i = 0; i < 256; i++) { j = (j + s[i] + key[i % key_len]) & 255; t = s[i]; s[i] = s[j]; s[j] = t; }
    for (i = 0; i < len; i++)
    {
        x = (x + 1) & 255; y = (y + s[x]) & 255;
        t = s[x]; s[x] = s[y]; s[y] = t;
        data[i] ^= s[(s[x] + s[y]) & 255];
    }
}

/* ---- the client of one exchange ---- */

#define F_UNICODE   0x00000001
#define F_REQTARGET 0x00000004
#define F_SIGN      0x00000010
#define F_SEAL      0x00000020
#define F_LMKEY     0x00000080
#define F_NTLM      0x00000200
#define F_DOMAIN    0x00001000
#define F_WORKST    0x00002000
#define F_ALWAYS    0x00008000
#define F_NTLM2     0x00080000
#define F_TARGETINF 0x00800000
#define F_VERSION   0x02000000
#define F_128       0x20000000
#define F_KEYEXCH   0x40000000
#define F_56        0x80000000

/* the flags the network level authentication client sends (the AUTHENTICATE has 0xe288a235) */
#define NEG_FLAGS   0xe20882b7
#define AUTH_FLAGS  (F_UNICODE | F_REQTARGET | F_SIGN | F_SEAL | F_NTLM | F_WORKST | F_ALWAYS | F_NTLM2 | F_TARGETINF | \
                     F_VERSION | F_128 | F_KEYEXCH | F_56)

enum { DOM_EMPTY, DOM_MACHINE, DOM_DOT };
enum { CB_NONE, CB_ZERO, CB_REAL, CB_WRONG };
enum { TN_NONE, TN_EMPTY, TN_SPN, TN_WRONG };

typedef struct
{
    const char *name;
    int domain;
    BOOL lm_absent;     /* no LM response (else 24 zero bytes) */
    BOOL flag56;
    BOOL av_mic;        /* MsvAvFlags 0x2 and the MIC */
    BOOL av_ts;         /* the timestamp of the server's target info is kept */
    int cb;             /* MsvAvChannelBindings */
    int tn;             /* MsvAvTargetName */
    BOOL extra;         /* an AV pair nobody knows */
    BOOL hdr64;         /* the AUTHENTICATE without version and MIC */
    BOOL trail;         /* zero bytes after the end of the pairs */
    BOOL app_cb;        /* the server application gives channel bindings */
    BOOL wrong_pw;
    BOOL bad_mic;
    SECURITY_STATUS expect;
} CASE;

static WCHAR g_user[32], g_blank[32], g_machine[MAX_COMPUTERNAME_LENGTH + 1];
static const BYTE g_app_data[] = "tls-server-end-point:0123456789abcdef0123456789abcdef";

static BOOL create_user(WCHAR *name, const WCHAR *prefix, const WCHAR *password)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(name, 32, L"%ls%lu", prefix, GetCurrentProcessId() % 100000);
    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = name;
    ui.usri1_password = (LPWSTR)password;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &err);
    if (st != NERR_Success)
    {
        skip("NetUserAdd(%ls) failed (%lu)\n", name, (unsigned long)st);
        return FALSE;
    }
    return TRUE;
}

static ULONG build_negotiate(BYTE *m)
{
    memset(m, 0, 40);
    memcpy(m, "NTLMSSP", 8);
    st32(m + 8, 1);
    st32(m + 12, NEG_FLAGS);
    st32(m + 24, 40); st32(m + 32, 40);     /* the empty domain and workstation at the end */
    m[40 - 8] = 0x0a; m[40 - 6] = 0x67; m[40 - 5] = 0x58; m[40 - 1] = 0x0f;
    return 40;
}

/* the 16 bytes of MsvAvChannelBindings for the application data of g_app_data and no addresses */
static void real_cb_hash(BYTE *hash)
{
    BYTE in[20 + sizeof(g_app_data)] = { 0 };

    st32(in + 16, sizeof(g_app_data));
    memcpy(in + 20, g_app_data, sizeof(g_app_data));
    md5(in, sizeof(in), hash);
}

/* the AUTHENTICATE of the case for the user: out gets the message; the exported session key goes to key */
static ULONG build_authenticate(const CASE *c, const WCHAR *user, const WCHAR *password, const BYTE *neg, ULONG neg_len,
                                const BYTE *chal, ULONG chal_len, BYTE *out, BYTE *key)
{
    BYTE ntowf[16], rk[16], proof[16], base[16], exported[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                                                  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01 };
    BYTE blob[2048], upper[128], dom[128], ws[128], av[1024];
    WCHAR user_up[64];
    const WCHAR *domain = L"";
    ULONG dom_len, ws_len, user_len, blob_len = 0, av_len = 0, hdr, flags, off, lm_len, nt_len, ti_len, p;
    const BYTE *ti;
    BYTE ts[8] = { 0 };
    BOOL have_ts = FALSE;
    ULONG i;

    switch (c->domain)
    {
    case DOM_MACHINE: domain = g_machine; break;
    case DOM_DOT: domain = L"."; break;
    }
    dom_len = (ULONG)wcslen(domain) * 2;
    memcpy(dom, domain, dom_len);
    user_len = (ULONG)wcslen(user) * 2;
    for (i = 0; i <= user_len / 2; i++) user_up[i] = (WCHAR)((user[i] >= 'a' && user[i] <= 'z') ? user[i] - 32 : user[i]);
    ws_len = (ULONG)wcslen(g_machine) * 2;
    memcpy(ws, g_machine, ws_len);

    md4(password, (ULONG)wcslen(password) * 2, ntowf);
    memcpy(upper, user_up, user_len);
    memcpy(upper + user_len, dom, dom_len);
    hmac_md5(ntowf, 16, upper, user_len + dom_len, NULL, 0, rk);

    /* the target info of the CHALLENGE, the pairs the client keeps, and the pairs of the case */
    ti_len = chal[40] | (chal[41] << 8);
    ti = chal + (chal[44] | (chal[45] << 8) | (chal[46] << 16));
    for (p = 0; p + 4 <= ti_len;)
    {
        ULONG id = ti[p] | (ti[p + 1] << 8), l = ti[p + 2] | (ti[p + 3] << 8);

        if (id == 0 || p + 4 + l > ti_len) break;
        if (id == 7)
        {
            memcpy(ts, ti + p + 4, 8);
            have_ts = TRUE;
            if (!c->av_ts) { p += 4 + l; continue; }
        }
        if (id != 6 && id != 10 && id != 9)
        {
            memcpy(av + av_len, ti + p, 4 + l);
            av_len += 4 + l;
        }
        p += 4 + l;
    }
    (void)have_ts;
    if (c->av_mic) { st16(av + av_len, 6); st16(av + av_len + 2, 4); st32(av + av_len + 4, 2); av_len += 8; }
    if (c->cb != CB_NONE)
    {
        st16(av + av_len, 10); st16(av + av_len + 2, 16);
        memset(av + av_len + 4, 0, 16);
        if (c->cb == CB_REAL) real_cb_hash(av + av_len + 4);
        else if (c->cb == CB_WRONG) { real_cb_hash(av + av_len + 4); av[av_len + 4] ^= 0x5a; }
        av_len += 20;
    }
    if (c->tn != TN_NONE)
    {
        WCHAR spn[128];
        ULONG n;

        spn[0] = 0;
        if (c->tn == TN_SPN) _snwprintf(spn, ARRAYSIZE(spn), L"TERMSRV/%s", g_machine);
        else if (c->tn == TN_WRONG) _snwprintf(spn, ARRAYSIZE(spn), L"TERMSRV/not-this-host.example");
        n = (ULONG)wcslen(spn) * 2;
        st16(av + av_len, 9); st16(av + av_len + 2, n);
        memcpy(av + av_len + 4, spn, n);
        av_len += 4 + n;
    }
    if (c->extra) { st16(av + av_len, 0x7e11); st16(av + av_len + 2, 6); memcpy(av + av_len + 4, "\1\2\3\4\5\6", 6); av_len += 10; }
    st16(av + av_len, 0); st16(av + av_len + 2, 0); av_len += 4;

    /* the blob: version, timestamp, client challenge, the pairs */
    memset(blob, 0, 28);
    blob[0] = 1; blob[1] = 1;
    memcpy(blob + 8, ts, 8);
    memcpy(blob + 16, "\xc1\x3f\xcf\x28\xc6\xec\xd7\x04", 8);
    memcpy(blob + 28, av, av_len);
    /* zero bytes after the end of the list (the client of the network level authentication has 12 more) */
    blob_len = 28 + av_len + (c->trail ? 12 : 4);
    memset(blob + 28 + av_len, 0, blob_len - 28 - av_len);

    hmac_md5(rk, 16, chal + 24, 8, blob, blob_len, proof);
    hmac_md5(rk, 16, proof, 16, NULL, 0, base);
    if (c->wrong_pw) proof[0] ^= 1;

    nt_len = 16 + blob_len;
    lm_len = c->lm_absent ? 0 : 24;
    hdr = c->hdr64 ? 64 : 88;
    flags = AUTH_FLAGS;
    if (!c->flag56) flags &= ~F_56;
    if (c->hdr64) flags &= ~F_VERSION;
    if (dom_len) flags |= F_DOMAIN;

    memset(out, 0, hdr);
    memcpy(out, "NTLMSSP", 8);
    st32(out + 8, 3);
    off = hdr;
#define FIELD(at, len) do { st16(out + (at), (len)); st16(out + (at) + 2, (len)); st32(out + (at) + 4, off); } while (0)
    FIELD(28, dom_len); memcpy(out + off, dom, dom_len); off += dom_len;
    FIELD(36, user_len); memcpy(out + off, user, user_len); off += user_len;
    FIELD(44, ws_len); memcpy(out + off, ws, ws_len); off += ws_len;
    FIELD(12, lm_len); memset(out + off, 0, lm_len); off += lm_len;
    FIELD(20, nt_len); memcpy(out + off, proof, 16); memcpy(out + off + 16, blob, blob_len); off += nt_len;
    FIELD(52, 16); memcpy(out + off, exported, 16); rc4(base, 16, out + off, 16); off += 16;
#undef FIELD
    st32(out + 60, flags);
    if (!c->hdr64)
    {
        out[64] = 0x0a; out[66] = 0x67; out[67] = 0x58; out[71] = 0x0f;
        if (c->av_mic)
        {
            HMAC h;

            hmac_init(&h, exported, 16);
            hmac_update(&h, neg, neg_len);
            hmac_update(&h, chal, chal_len);
            hmac_update(&h, out, off);      /* the MIC field is zero */
            hmac_final(&h, out + 72);
            if (c->bad_mic) out[72] ^= 0x80;
        }
    }
    memcpy(key, exported, 16);
    return off;
}

/* ---- the server ---- */

/* the SEC_CHANNEL_BINDINGS of the application: no addresses, the application data g_app_data */
static ULONG build_app_bindings(BYTE *buf)
{
    SEC_CHANNEL_BINDINGS cb;

    memset(&cb, 0, sizeof(cb));
    cb.cbApplicationDataLength = sizeof(g_app_data);
    cb.dwApplicationDataOffset = sizeof(cb);
    memcpy(buf, &cb, sizeof(cb));
    memcpy(buf + sizeof(cb), g_app_data, sizeof(g_app_data));
    return sizeof(cb) + sizeof(g_app_data);
}

static SECURITY_STATUS asc(CredHandle *sc, CtxtHandle *ctx, BOOL first, const BYTE *in, ULONG in_len, BOOL app_cb,
                           BYTE *out, ULONG *out_len)
{
    BYTE cbbuf[128];
    SecBuffer ib[2] = { { in_len, SECBUFFER_TOKEN, (void *)in }, { 0, SECBUFFER_CHANNEL_BINDINGS, cbbuf } };
    SecBuffer ob = { MAXT, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, ib }, od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attr;
    TimeStamp ts;
    SECURITY_STATUS st;

    if (app_cb)
    {
        ib[1].cbBuffer = build_app_bindings(cbbuf);
        id.cBuffers = 2;
    }
    st = AcceptSecurityContext(sc, first ? NULL : ctx, &id, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY | ASC_REQ_CONFIDENTIALITY |
                               ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_EXTENDED_ERROR,
                               SECURITY_NATIVE_DREP, ctx, &od, &attr, &ts);
    *out_len = ob.cbBuffer;
    return st;
}

static void run_case(const WCHAR *pkg, const CASE *c, const WCHAR *user, const WCHAR *password)
{
    CredHandle sc;
    CtxtHandle sctx;
    TimeStamp ts;
    BYTE neg[64], chal[MAXT], auth[MAXT], out[MAXT], key[16];
    ULONG neg_len, chal_len, auth_len, out_len;
    SECURITY_STATUS st;

    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)pkg, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &sc, &ts);
    ok(st == SEC_E_OK, "%ls %s: AcquireCredentialsHandle 0x%08lx\n", pkg, c->name, (unsigned long)st);
    if (st != SEC_E_OK) return;

    neg_len = build_negotiate(neg);
    st = asc(&sc, &sctx, TRUE, neg, neg_len, FALSE, chal, &chal_len);
    ok(st == SEC_I_CONTINUE_NEEDED, "%ls %s: first leg 0x%08lx\n", pkg, c->name, (unsigned long)st);
    if (st == SEC_I_CONTINUE_NEEDED)
    {
        auth_len = build_authenticate(c, user, password, neg, neg_len, chal, chal_len, auth, key);
        st = asc(&sc, &sctx, FALSE, auth, auth_len, c->app_cb, out, &out_len);
        ok(st == c->expect, "%ls %s: AUTHENTICATE gives 0x%08lx, expected 0x%08lx\n", pkg, c->name, (unsigned long)st,
           (unsigned long)c->expect);
        if (st == SEC_E_OK)
        {
            SecPkgContext_NamesW nm;
            HANDLE token = NULL;
            SECURITY_STATUS st2;

            st2 = QuerySecurityContextToken(&sctx, &token);
            ok(st2 == SEC_E_OK && token, "%ls %s: QuerySecurityContextToken 0x%08lx\n", pkg, c->name, (unsigned long)st2);
            if (st2 == SEC_E_OK && token) CloseHandle(token);
            memset(&nm, 0, sizeof(nm));
            st2 = QueryContextAttributesW(&sctx, SECPKG_ATTR_NAMES, &nm);
            ok(st2 == SEC_E_OK, "%ls %s: NAMES 0x%08lx\n", pkg, c->name, (unsigned long)st2);
            if (st2 == SEC_E_OK)
            {
                ok(wcslen(nm.sUserName) > wcslen(user) && !_wcsicmp(nm.sUserName + wcslen(nm.sUserName) - wcslen(user), user),
                   "%ls %s: name %ls\n", pkg, c->name, nm.sUserName);
                FreeContextBuffer(nm.sUserName);
            }
        }
        DeleteSecurityContext(&sctx);
    }
    FreeCredentialsHandle(&sc);
}

#define OK SEC_E_OK
/* name, domain, lm absent, 56, MIC, timestamp, bindings, target name, extra pair, short header, trailing zeros,
 * application bindings, wrong password, wrong MIC, status */
static const CASE cases[] =
{
    { "credssp (empty domain, zero LM, 56, MIC, ts, zero bindings, SPN)",
      DOM_EMPTY, 0, 1, 1, 1, CB_ZERO, TN_SPN, 0, 0, 1, 0, 0, 0, OK },
    { "credssp with application bindings",
      DOM_EMPTY, 0, 1, 1, 1, CB_ZERO, TN_SPN, 0, 0, 1, 1, 0, 0, OK },
    { "plain (machine domain, no 56, no MIC)",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "only 56 added to plain",
      DOM_MACHINE, 0, 1, 0, 1, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "empty domain",
      DOM_EMPTY, 0, 0, 0, 1, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "domain dot",
      DOM_DOT, 0, 0, 0, 1, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "LM response absent",
      DOM_MACHINE, 1, 0, 0, 1, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "MIC, machine domain",
      DOM_MACHINE, 0, 0, 1, 1, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "MIC, no timestamp",
      DOM_MACHINE, 0, 0, 1, 0, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "no timestamp",
      DOM_MACHINE, 0, 0, 0, 0, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "zero bindings",
      DOM_MACHINE, 0, 0, 0, 1, CB_ZERO, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "zero bindings, application bindings",
      DOM_MACHINE, 0, 0, 0, 1, CB_ZERO, TN_NONE, 0, 0, 0, 1, 0, 0, OK },
    { "real bindings, none from the application (ignored)",
      DOM_MACHINE, 0, 0, 0, 1, CB_REAL, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "wrong bindings, none from the application (ignored)",
      DOM_MACHINE, 0, 0, 0, 1, CB_WRONG, TN_NONE, 0, 0, 0, 0, 0, 0, OK },
    { "real bindings, the application's (equal)",
      DOM_MACHINE, 0, 0, 1, 1, CB_REAL, TN_NONE, 0, 0, 0, 1, 0, 0, OK },
    { "wrong bindings, the application's (differ)",
      DOM_MACHINE, 0, 0, 1, 1, CB_WRONG, TN_NONE, 0, 0, 0, 1, 0, 0, SEC_E_BAD_BINDINGS },
    { "no bindings pair, application bindings",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_NONE, 0, 0, 0, 1, 0, 0, OK },
    { "target name empty",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_EMPTY, 0, 0, 0, 0, 0, 0, OK },
    { "target name TERMSRV/host",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_SPN, 0, 0, 0, 0, 0, 0, OK },
    { "target name of another host (not checked: VERIFY ON PEER)",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_WRONG, 0, 0, 0, 0, 0, 0, OK },
    { "unknown AV pair",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_NONE, 1, 0, 0, 0, 0, 0, OK },
    { "zero bytes after the pairs",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_NONE, 0, 0, 1, 0, 0, 0, OK },
    { "header without version and MIC",
      DOM_MACHINE, 0, 0, 0, 1, CB_NONE, TN_NONE, 0, 1, 0, 0, 0, 0, OK },
    { "everything at once",
      DOM_EMPTY, 0, 1, 1, 1, CB_REAL, TN_SPN, 1, 0, 1, 1, 0, 0, OK },
    { "wrong password",
      DOM_EMPTY, 0, 1, 1, 1, CB_ZERO, TN_SPN, 0, 0, 1, 0, 1, 0, SEC_E_LOGON_DENIED },
    { "wrong MIC (credssp shape)",
      DOM_EMPTY, 0, 1, 1, 1, CB_ZERO, TN_SPN, 0, 0, 1, 0, 0, 1, SEC_E_INVALID_TOKEN },
    { "wrong MIC, 56 not set",
      DOM_MACHINE, 0, 0, 1, 1, CB_NONE, TN_NONE, 0, 0, 0, 0, 0, 1, SEC_E_INVALID_TOKEN },
};
#undef OK

static void test_cases(const WCHAR *pkg)
{
    ULONG i;

    for (i = 0; i < ARRAYSIZE(cases); i++)
        run_case(pkg, &cases[i], g_user, TEST_PASSWORD);
}

/* an account with a blank password does not log on over the network (LimitBlankPasswordUse as landed) */
static void test_blank(const WCHAR *pkg)
{
    CASE c = cases[0];

    c.name = "blank password account";
    c.expect = SEC_E_LOGON_DENIED;
    run_case(pkg, &c, g_blank, L"");
}

START_TEST(NtlmServerAuthenticate)
{
    DWORD n = ARRAYSIZE(g_machine);

    if (!GetComputerNameW(g_machine, &n)) return;
    if (!create_user(g_user, L"srvauth", TEST_PASSWORD)) return;
    test_cases(L"NTLM");
    test_cases(L"Negotiate");
    if (create_user(g_blank, L"srvblank", L""))
    {
        test_blank(L"NTLM");
        test_blank(L"Negotiate");
        NetUserDel(NULL, g_blank);
    }
    NetUserDel(NULL, g_user);
}
