/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     SPNEGO in the Negotiate package: a client and a server context of this process exchange the tokens
 *              Windows exchanges (measured on Windows Server 2022 and Windows 10 22H2 with an SSPI-only probe), with the
 *              same statuses, shapes and context attributes; malformed and altered tokens get the statuses Windows
 *              gives them; sign and seal work after the exchange.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <string.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winnls.h>
#include <lmaccess.h>
#include <lmerr.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define TEST_PASSWORD L"Spnego#Test1pw"
#define MAX_TOK 16384   /* every token buffer of this test; the largest constructed token is 12000 bytes */

static WCHAR g_user[32];

static const BYTE OID_NTLM[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
static const BYTE OID_SPNEGO[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
static const BYTE OID_KRB[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };

/* ---------------------------------------------------------------------------------------------------------------- */
/* a small DER walker of this test (independent of the package's codec) */
static BOOL der_next(const BYTE *b, ULONG len, ULONG *pos, BYTE *tag, const BYTE **c, ULONG *cl)
{
    ULONG p = *pos, n;

    if (p + 2 > len) return FALSE;
    *tag = b[p++];
    n = b[p++];
    if (n & 0x80)
    {
        ULONG k = n & 0x7f;
        if (k == 0 || k > 3 || p + k > len) return FALSE;
        n = 0;
        while (k--) n = (n << 8) | b[p++];
    }
    if (n > len - p) return FALSE;
    *c = b + p;
    *cl = n;
    *pos = p + n;
    return TRUE;
}

/* the fields of a NegTokenResp: which tags are present (bit n for [n]) and their contents */
typedef struct
{
    ULONG present;
    int neg_state;
    const BYTE *mech; ULONG mech_len;
    const BYTE *tok; ULONG tok_len;
    const BYTE *mic; ULONG mic_len;
    ULONG total;
} resp_fields;

static BOOL parse_resp(const BYTE *t, ULONG l, resp_fields *f)
{
    ULONG p = 0, q = 0, r;
    BYTE tag, t2;
    const BYTE *c, *s, *o;
    ULONG cl, sl, ol;

    memset(f, 0, sizeof(*f));
    f->neg_state = -1;
    if (!der_next(t, l, &p, &tag, &c, &cl) || tag != 0xa1) return FALSE;
    f->total = p;
    if (!der_next(c, cl, &q, &tag, &s, &sl) || tag != 0x30) return FALSE;
    p = 0;
    while (p < sl)
    {
        if (!der_next(s, sl, &p, &tag, &c, &cl) || tag < 0xa0 || tag > 0xa3) return FALSE;
        f->present |= 1 << (tag - 0xa0);
        r = 0;
        if (!der_next(c, cl, &r, &t2, &o, &ol)) return FALSE;
        switch (tag)
        {
        case 0xa0: if (t2 != 0x0a || ol != 1) return FALSE; f->neg_state = o[0]; break;
        case 0xa1: if (t2 != 0x06) return FALSE; f->mech = o; f->mech_len = ol; break;
        case 0xa2: if (t2 != 0x04) return FALSE; f->tok = o; f->tok_len = ol; break;
        case 0xa3: if (t2 != 0x04) return FALSE; f->mic = o; f->mic_len = ol; break;
        }
    }
    return TRUE;
}

/* a NegTokenInit: the mechanism OIDs (concatenated content), whether reqFlags/mechToken/MIC are present */
typedef struct
{
    ULONG present;
    ULONG mech_count;
    BOOL first_is_ntlm;
    const BYTE *tok; ULONG tok_len;
    const BYTE *mech_list; ULONG mech_list_len;
} init_fields;

static BOOL parse_init(const BYTE *t, ULONG l, init_fields *f)
{
    ULONG p = 0, q, r, z;
    BYTE tag, t2;
    const BYTE *c, *a, *s, *o, *x;
    ULONG cl, al, sl, ol, xl;

    memset(f, 0, sizeof(*f));
    if (!der_next(t, l, &p, &tag, &a, &al) || tag != 0x60 || p != l) return FALSE;
    q = 0;
    if (!der_next(a, al, &q, &tag, &o, &ol) || tag != 0x06 || ol != sizeof(OID_SPNEGO) || memcmp(o, OID_SPNEGO, ol))
        return FALSE;
    if (!der_next(a, al, &q, &tag, &c, &cl) || tag != 0xa0) return FALSE;
    r = 0;
    if (!der_next(c, cl, &r, &tag, &s, &sl) || tag != 0x30) return FALSE;
    p = 0;
    while (p < sl)
    {
        if (!der_next(s, sl, &p, &tag, &c, &cl) || tag < 0xa0 || tag > 0xa4) return FALSE;
        f->present |= 1 << (tag - 0xa0);
        if (tag == 0xa0)
        {
            f->mech_list = c; f->mech_list_len = cl;
            z = 0;
            if (!der_next(c, cl, &z, &t2, &x, &xl) || t2 != 0x30) return FALSE;
            q = 0;
            while (q < xl)
            {
                if (!der_next(x, xl, &q, &t2, &o, &ol) || t2 != 0x06) return FALSE;
                if (f->mech_count == 0) f->first_is_ntlm = ol == sizeof(OID_NTLM) && !memcmp(o, OID_NTLM, ol);
                f->mech_count++;
            }
        }
        else if (tag == 0xa2)
        {
            z = 0;
            if (!der_next(c, cl, &z, &t2, &o, &ol) || t2 != 0x04) return FALSE;
            f->tok = o; f->tok_len = ol;
        }
    }
    return TRUE;
}

/* ---------------------------------------------------------------------------------------------------------------- */
/* token builders for the malformed rows */
static ULONG put(BYTE *out, BYTE tag, const BYTE *c, ULONG l)
{
    ULONG h = 0;
    out[h++] = tag;
    if (l < 0x80) out[h++] = (BYTE)l;
    else if (l < 0x100) { out[h++] = 0x81; out[h++] = (BYTE)l; }
    else { out[h++] = 0x82; out[h++] = (BYTE)(l >> 8); out[h++] = (BYTE)l; }
    memmove(out + h, c, l);
    return h + l;
}

static ULONG put_oid(BYTE *out, const BYTE *oid, ULONG l)
{
    return put(out, 0x06, oid, l);
}

static ULONG mk_resp(BYTE *out, int state, const BYTE *mech, ULONG mech_len, const BYTE *tok, ULONG tl,
                     const BYTE *mic, ULONG ml)
{
    BYTE seq[MAX_TOK], a[MAX_TOK];
    ULONG n = 0, k;

    if (state >= 0) { BYTE e[3] = { 0x0a, 0x01, (BYTE)state }; n += put(seq + n, 0xa0, e, 3); }
    if (mech) { k = put_oid(a, mech, mech_len); n += put(seq + n, 0xa1, a, k); }
    if (tok) { k = put(a, 0x04, tok, tl); n += put(seq + n, 0xa2, a, k); }
    if (mic) { k = put(a, 0x04, mic, ml); n += put(seq + n, 0xa3, a, k); }
    k = put(a, 0x30, seq, n);
    return put(out, 0xa1, a, k);
}

/* NegTokenInit with the given OIDs (pairs of pointer/length, count) and an optional mechToken */
static ULONG mk_init(BYTE *out, const BYTE *const *oids, const ULONG *lens, ULONG count, const BYTE *tok, ULONG tl,
                     const BYTE *this_mech, ULONG this_len)
{
    BYTE list[512], seq[MAX_TOK], a[MAX_TOK], b[MAX_TOK];
    ULONG n = 0, i, k, m = 0;

    for (i = 0; i < count; i++) m += put_oid(list + m, oids[i], lens[i]);
    k = put(a, 0x30, list, m);
    n += put(seq + n, 0xa0, a, k);
    if (tok) { k = put(a, 0x04, tok, tl); n += put(seq + n, 0xa2, a, k); }
    k = put(a, 0x30, seq, n);
    k = put(b, 0xa0, a, k);
    m = put_oid(a, this_mech, this_len);
    memcpy(a + m, b, k);
    return put(out, 0x60, a, m + k);
}

/* ---------------------------------------------------------------------------------------------------------------- */
/* the exchange driver */
typedef ULONG (*mutate_fn)(const BYTE *in, ULONG len, BYTE *out, void *arg);

typedef struct
{
    CredHandle *cc, *sc;
    ULONG creq, sreq;
    BOOL hint;                  /* the server speaks first (its NegTokenInit goes to the client's first call) */
    int mutate_index;           /* the token (in the order of the exchange, the hint is 0) to change, -1: none */
    mutate_fn mutate;
    void *arg;
    BOOL split;                 /* deliver the mutated token in two calls (the first split_at bytes, then the rest) */
    ULONG split_at;
    /* results */
    CtxtHandle cctx, sctx;
    BOOL have_c, have_s;
    SECURITY_STATUS st[8];      /* the status of the call that produced token i (or failed on it) */
    BYTE tok[8][MAX_TOK];
    ULONG len[8];
    ULONG attr[8];
    int n;                      /* tokens produced */
    SECURITY_STATUS mutated_status; /* the status of the side that got the changed token */
    ULONG mutated_out_len;      /* and the length of its output */
    BYTE mutated_out[MAX_TOK];
    SECURITY_STATUS cst, sst;   /* the last status of each side */
} run_t;

static SECURITY_STATUS call(run_t *r, BOOL server, const BYTE *in, ULONG in_len, BOOL with_input, BYTE *out,
                            ULONG *out_len, ULONG *attr)
{
    SecBuffer ib, ob;
    SecBufferDesc id, od;
    TimeStamp ts;
    SECURITY_STATUS st;

    ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = (void *)in; ib.cbBuffer = in_len;
    ob.BufferType = SECBUFFER_TOKEN; ob.pvBuffer = out; ob.cbBuffer = MAX_TOK;
    id.ulVersion = od.ulVersion = SECBUFFER_VERSION;
    id.cBuffers = od.cBuffers = 1;
    id.pBuffers = &ib;
    od.pBuffers = &ob;
    *attr = 0;
    if (server)
    {
        st = AcceptSecurityContext(r->sc, r->have_s ? &r->sctx : NULL, with_input ? &id : NULL, r->sreq,
                                   SECURITY_NATIVE_DREP, &r->sctx, &od, attr, &ts);
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) r->have_s = TRUE;
        r->sst = st;
    }
    else
    {
        st = InitializeSecurityContextW(r->cc, r->have_c ? &r->cctx : NULL, (SEC_WCHAR *)L"cifs/localhost", r->creq,
                                        0, SECURITY_NATIVE_DREP, with_input ? &id : NULL, 0, &r->cctx, &od, attr, &ts);
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) r->have_c = TRUE;
        r->cst = st;
    }
    *out_len = (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) ? ob.cbBuffer : 0;
    return st;
}

static void run_exchange(run_t *r)
{
    BYTE in[MAX_TOK], out[MAX_TOK];
    ULONG in_len = 0, out_len, attr;
    BOOL have_in = FALSE, server = FALSE;
    int leg;
    SECURITY_STATUS st;

    r->n = 0;
    r->have_c = r->have_s = FALSE;
    r->cst = r->sst = SEC_I_CONTINUE_NEEDED;
    r->mutated_status = (SECURITY_STATUS)0xdeadbeef;
    r->mutated_out_len = 0;
    if (r->hint)
    {
        /* the hint comes from a context of its own (as a protocol's NEGOTIATE answer) */
        run_t h = *r;
        st = call(&h, TRUE, NULL, 0, FALSE, out, &out_len, &attr);
        r->st[0] = st; r->attr[0] = attr;
        if (h.have_s) DeleteSecurityContext(&h.sctx);
        if (st != SEC_I_CONTINUE_NEEDED || !out_len) return;
        memcpy(r->tok[0], out, out_len); r->len[0] = out_len; r->n = 1;
        memcpy(in, out, out_len); in_len = out_len; have_in = TRUE;
    }
    for (leg = 0; leg < 7; leg++)
    {
        BOOL mutated = FALSE;

        if (have_in && r->mutate_index == r->n - 1 && r->mutate)
        {
            BYTE m[MAX_TOK];
            ULONG ml = r->mutate(in, in_len, m, r->arg);
            memcpy(in, m, ml);
            in_len = ml;
            mutated = TRUE;
        }
        if (mutated && r->split && r->split_at < in_len)
        {
            st = call(r, server, in, r->split_at, TRUE, out, &out_len, &attr);
            if (st != SEC_I_CONTINUE_NEEDED || out_len)
            {
                r->mutated_status = st; r->mutated_out_len = out_len;
                return;
            }
            st = call(r, server, in + r->split_at, in_len - r->split_at, TRUE, out, &out_len, &attr);
        }
        else
            st = call(r, server, have_in ? in : NULL, in_len, have_in, out, &out_len, &attr);
        if (mutated)
        {
            r->mutated_status = st;
            r->mutated_out_len = out_len;
            if (out_len) memcpy(r->mutated_out, out, out_len);
        }
        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) return;
        if (out_len)
        {
            if (r->n < 8) { memcpy(r->tok[r->n], out, out_len); r->len[r->n] = out_len; r->st[r->n] = st; r->attr[r->n] = attr; r->n++; }
            memcpy(in, out, out_len); in_len = out_len; have_in = TRUE;
        }
        else
        {
            have_in = FALSE;
            if (st == SEC_E_OK) return;     /* nothing to send: done */
            if (mutated) return;            /* waiting for more of the changed token */
        }
        if (st == SEC_E_OK && ((server && r->cst == SEC_E_OK) || (!server && r->sst == SEC_E_OK))) return;
        server = !server;
    }
}

static void run_free(run_t *r)
{
    if (r->have_c) DeleteSecurityContext(&r->cctx);
    if (r->have_s) DeleteSecurityContext(&r->sctx);
    r->have_c = r->have_s = FALSE;
}

/* ---------------------------------------------------------------------------------------------------------------- */
static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"spnegot%lu", GetCurrentProcessId() % 100000);
    memset(&ui, 0, sizeof(ui));
    ui.usri1_name = g_user;
    ui.usri1_password = (LPWSTR)TEST_PASSWORD;
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    st = NetUserAdd(NULL, 1, (LPBYTE)&ui, &err);
    if (st != NERR_Success)
    {
        skip("NetUserAdd failed (%lu)\n", (unsigned long)st);
        return FALSE;
    }
    return TRUE;
}

static BOOL acquire(CredHandle *cc, CredHandle *sc, BOOL explicit_cred)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    TimeStamp ts;
    SECURITY_STATUS st;

    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)g_user; id.UserLength = (ULONG)wcslen(g_user);
    id.Domain = (unsigned short *)L"."; id.DomainLength = 1;
    id.Password = (unsigned short *)TEST_PASSWORD; id.PasswordLength = (ULONG)wcslen(TEST_PASSWORD);
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_OUTBOUND, NULL,
                                   explicit_cred ? &id : NULL, NULL, NULL, cc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) return FALSE;
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, sc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st != SEC_E_OK) { FreeCredentialsHandle(cc); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------------------------------------------------------- */
static void check_messages(CtxtHandle *a, CtxtHandle *b, BOOL seal, const char *what)
{
    BYTE data[48], plain[48], sig[16];
    SecBuffer bufs[2];
    SecBufferDesc d = { SECBUFFER_VERSION, 2, bufs };
    SECURITY_STATUS st;
    ULONG qop, i;

    for (i = 0; i < 3; i++)
    {
        memset(data, 'a' + i, sizeof(data));
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = data; bufs[0].cbBuffer = sizeof(data);
        bufs[1].BufferType = SECBUFFER_TOKEN; bufs[1].pvBuffer = sig; bufs[1].cbBuffer = sizeof(sig);
        st = MakeSignature(a, 0, &d, 0);
        ok(st == SEC_E_OK, "%s: MakeSignature %lu: 0x%08lx\n", what, i, (unsigned long)st);
        /* the mechListMIC took sequence number 0 of each direction (measured): the first message has 1 */
        if (i == 0)
            ok(sig[12] == 1 && !sig[13] && !sig[14] && !sig[15] && sig[0] == 1, "%s: first signature %02x.. seq %02x%02x%02x%02x\n",
               what, sig[0], sig[12], sig[13], sig[14], sig[15]);
        st = VerifySignature(b, &d, 0, &qop);
        ok(st == SEC_E_OK, "%s: VerifySignature %lu: 0x%08lx\n", what, i, (unsigned long)st);
    }
    data[0] ^= 1;
    st = MakeSignature(a, 0, &d, 0);
    data[1] ^= 1;
    st = VerifySignature(b, &d, 0, &qop);
    ok(st == SEC_E_MESSAGE_ALTERED, "%s: altered message: 0x%08lx\n", what, (unsigned long)st);
    if (!seal) return;
    for (i = 0; i < 3; i++)
    {
        memset(data, 'A' + i, sizeof(data));
        memcpy(plain, data, sizeof(data));
        bufs[0].BufferType = SECBUFFER_DATA; bufs[0].pvBuffer = data; bufs[0].cbBuffer = sizeof(data);
        bufs[1].BufferType = SECBUFFER_TOKEN; bufs[1].pvBuffer = sig; bufs[1].cbBuffer = sizeof(sig);
        st = EncryptMessage(a, 0, &d, 0);
        ok(st == SEC_E_OK, "%s: EncryptMessage %lu: 0x%08lx\n", what, i, (unsigned long)st);
        ok(memcmp(data, plain, sizeof(data)) != 0, "%s: not encrypted\n", what);
        st = DecryptMessage(b, &d, 0, &qop);
        ok(st == SEC_E_OK, "%s: DecryptMessage %lu: 0x%08lx\n", what, i, (unsigned long)st);
        ok(!memcmp(data, plain, sizeof(data)), "%s: not restored\n", what);
    }
}

static void check_in_progress(CtxtHandle *ctx, const char *what)
{
    SecPkgContext_NegotiationInfoW ni;
    SecPkgContext_Sizes sz;
    SecPkgContext_PackageInfoW pi;
    SecPkgContext_SessionKey sk;
    SecPkgContext_NamesW nm;
    SECURITY_STATUS st;

    memset(&ni, 0, sizeof(ni));
    st = QueryContextAttributesW(ctx, SECPKG_ATTR_NEGOTIATION_INFO, &ni);
    ok(st == SEC_E_OK, "%s: NEGOTIATION_INFO 0x%08lx\n", what, (unsigned long)st);
    if (st == SEC_E_OK && ni.PackageInfo)
    {
        ok(ni.NegotiationState == SECPKG_NEGOTIATION_OPTIMISTIC, "%s: state %lu\n", what, ni.NegotiationState);
        ok(!wcscmp(ni.PackageInfo->Name, L"NTLM"), "%s: package %ls\n", what, ni.PackageInfo->Name);
        FreeContextBuffer(ni.PackageInfo);
    }
    st = QueryContextAttributesW(ctx, SECPKG_ATTR_SIZES, &sz);
    ok(st == SEC_E_OK, "%s: SIZES 0x%08lx\n", what, (unsigned long)st);
    if (st == SEC_E_OK)
        ok(sz.cbMaxToken == 48256 && sz.cbMaxSignature == 64 && sz.cbBlockSize == 8 && sz.cbSecurityTrailer == 64,
           "%s: sizes %lu %lu %lu %lu\n", what, sz.cbMaxToken, sz.cbMaxSignature, sz.cbBlockSize, sz.cbSecurityTrailer);
    st = QueryContextAttributesW(ctx, SECPKG_ATTR_PACKAGE_INFO, &pi);
    ok(st == SEC_E_UNSUPPORTED_FUNCTION, "%s: PACKAGE_INFO 0x%08lx\n", what, (unsigned long)st);
    st = QueryContextAttributesW(ctx, SECPKG_ATTR_SESSION_KEY, &sk);
    ok(st == SEC_E_UNSUPPORTED_FUNCTION, "%s: SESSION_KEY 0x%08lx\n", what, (unsigned long)st);
    st = QueryContextAttributesW(ctx, SECPKG_ATTR_NAMES, &nm);
    ok(st == SEC_E_UNSUPPORTED_FUNCTION, "%s: NAMES 0x%08lx\n", what, (unsigned long)st);
}

static void check_complete(run_t *r, const char *what)
{
    SecPkgContext_NegotiationInfoW ni;
    SecPkgContext_SessionKey kc, ks;
    SecPkgContext_NamesW nm;
    SecPkgContext_PackageInfoW pi;
    SECURITY_STATUS st;
    HANDLE token = NULL;

    memset(&ni, 0, sizeof(ni));
    st = QueryContextAttributesW(&r->cctx, SECPKG_ATTR_NEGOTIATION_INFO, &ni);
    ok(st == SEC_E_OK && ni.NegotiationState == SECPKG_NEGOTIATION_COMPLETE, "%s: client state 0x%08lx %lu\n", what,
       (unsigned long)st, ni.NegotiationState);
    if (st == SEC_E_OK) FreeContextBuffer(ni.PackageInfo);
    memset(&ni, 0, sizeof(ni));
    st = QueryContextAttributesW(&r->sctx, SECPKG_ATTR_NEGOTIATION_INFO, &ni);
    ok(st == SEC_E_OK && ni.NegotiationState == SECPKG_NEGOTIATION_COMPLETE, "%s: server state 0x%08lx %lu\n", what,
       (unsigned long)st, ni.NegotiationState);
    if (st == SEC_E_OK) FreeContextBuffer(ni.PackageInfo);
    st = QueryContextAttributesW(&r->sctx, SECPKG_ATTR_PACKAGE_INFO, &pi);
    ok(st == SEC_E_OK, "%s: PACKAGE_INFO 0x%08lx\n", what, (unsigned long)st);
    if (st == SEC_E_OK)
    {
        ok(!wcscmp(pi.PackageInfo->Name, L"NTLM"), "%s: package %ls\n", what, pi.PackageInfo->Name);
        FreeContextBuffer(pi.PackageInfo);
    }
    memset(&kc, 0, sizeof(kc)); memset(&ks, 0, sizeof(ks));
    st = QueryContextAttributesW(&r->cctx, SECPKG_ATTR_SESSION_KEY, &kc);
    ok(st == SEC_E_OK, "%s: client SESSION_KEY 0x%08lx\n", what, (unsigned long)st);
    st = QueryContextAttributesW(&r->sctx, SECPKG_ATTR_SESSION_KEY, &ks);
    ok(st == SEC_E_OK, "%s: server SESSION_KEY 0x%08lx\n", what, (unsigned long)st);
    if (kc.SessionKey && ks.SessionKey)
        ok(kc.SessionKeyLength == 16 && ks.SessionKeyLength == 16 && !memcmp(kc.SessionKey, ks.SessionKey, 16),
           "%s: session keys differ\n", what);
    if (kc.SessionKey) FreeContextBuffer(kc.SessionKey);
    if (ks.SessionKey) FreeContextBuffer(ks.SessionKey);
    st = QueryContextAttributesW(&r->sctx, SECPKG_ATTR_NAMES, &nm);
    ok(st == SEC_E_OK, "%s: server NAMES 0x%08lx\n", what, (unsigned long)st);
    if (st == SEC_E_OK) FreeContextBuffer(nm.sUserName);
    st = QuerySecurityContextToken(&r->sctx, &token);
    ok(st == SEC_E_OK && token, "%s: QuerySecurityContextToken 0x%08lx\n", what, (unsigned long)st);
    if (token) CloseHandle(token);
    st = ImpersonateSecurityContext(&r->sctx);
    ok(st == SEC_E_OK, "%s: ImpersonateSecurityContext 0x%08lx\n", what, (unsigned long)st);
    st = RevertSecurityContext(&r->sctx);
    ok(st == SEC_E_OK, "%s: RevertSecurityContext 0x%08lx\n", what, (unsigned long)st);
}

/* the exchange Windows makes with the server's hint (explicit credentials) or the caller's own credentials */
static void test_exchange(CredHandle *cc, CredHandle *sc, BOOL hint, ULONG creq, ULONG sreq, BOOL seal)
{
    run_t *r = calloc(1, sizeof(*r));
    init_fields fi;
    resp_fields fr;
    char what[64];
    int b = hint ? 1 : 0;

    sprintf(what, "%s 0x%lx", hint ? "hint" : "nohint", creq);
    r->cc = cc; r->sc = sc; r->creq = creq; r->sreq = sreq; r->hint = hint; r->mutate_index = -1;
    run_exchange(r);
    ok(r->cst == SEC_E_OK && r->sst == SEC_E_OK, "%s: client 0x%08lx server 0x%08lx\n", what,
       (unsigned long)r->cst, (unsigned long)r->sst);
    ok(r->n == b + 4, "%s: %d tokens\n", what, r->n);
    if (r->n != b + 4) goto done;

    if (hint)
    {
        /* the hint: a NegTokenInit with the mechanism list only */
        ok(parse_init(r->tok[0], r->len[0], &fi), "%s: hint shape\n", what);
        ok(fi.present == 1 && fi.mech_count >= 1, "%s: hint fields 0x%lx mechs %lu\n", what, fi.present, fi.mech_count);
    }
    /* client: NegTokenInit { mechTypes NTLM, mechToken NEGOTIATE }, no reqFlags, no MIC */
    ok(r->st[b] == SEC_I_CONTINUE_NEEDED, "%s: client leg 1 0x%08lx\n", what, (unsigned long)r->st[b]);
    ok(r->attr[b] & ISC_RET_INTERMEDIATE_RETURN, "%s: client attr 0x%08lx\n", what, r->attr[b]);
    ok(parse_init(r->tok[b], r->len[b], &fi), "%s: init shape\n", what);
    ok(fi.present == ((1 << 0) | (1 << 2)), "%s: init fields 0x%lx\n", what, fi.present);
    ok(fi.mech_count == 1 && fi.first_is_ntlm, "%s: init mechs %lu\n", what, fi.mech_count);
    ok(fi.tok_len >= 32 && !memcmp(fi.tok, "NTLMSSP\0\1\0\0\0", 12), "%s: init mechToken\n", what);
    /* server: NegTokenResp { accept-incomplete, NTLM, CHALLENGE } */
    ok(r->st[b + 1] == SEC_I_CONTINUE_NEEDED, "%s: server leg 1 0x%08lx\n", what, (unsigned long)r->st[b + 1]);
    ok(parse_resp(r->tok[b + 1], r->len[b + 1], &fr), "%s: resp shape\n", what);
    ok(fr.present == 7 && fr.neg_state == 1, "%s: resp fields 0x%lx state %d\n", what, fr.present, fr.neg_state);
    ok(fr.mech_len == sizeof(OID_NTLM) && !memcmp(fr.mech, OID_NTLM, sizeof(OID_NTLM)), "%s: supportedMech\n", what);
    ok(fr.tok_len >= 32 && !memcmp(fr.tok, "NTLMSSP\0\2\0\0\0", 12), "%s: CHALLENGE\n", what);
    /* client: NegTokenResp { accept-incomplete, AUTHENTICATE, mechListMIC (version 1, sequence 0) } */
    ok(r->st[b + 2] == SEC_I_CONTINUE_NEEDED, "%s: client leg 2 0x%08lx\n", what, (unsigned long)r->st[b + 2]);
    ok(parse_resp(r->tok[b + 2], r->len[b + 2], &fr), "%s: final shape\n", what);
    ok(fr.present == ((1 << 0) | (1 << 2) | (1 << 3)) && fr.neg_state == 1, "%s: final fields 0x%lx state %d\n", what,
       fr.present, fr.neg_state);
    ok(fr.tok_len >= 32 && !memcmp(fr.tok, "NTLMSSP\0\3\0\0\0", 12), "%s: AUTHENTICATE\n", what);
    ok(fr.mic_len == 16 && fr.mic[0] == 1 && !fr.mic[1] && !fr.mic[12] && !fr.mic[13], "%s: client mechListMIC\n", what);
    /* server: NegTokenResp { accept-completed, mechListMIC } and SEC_E_OK */
    ok(r->st[b + 3] == SEC_E_OK, "%s: server leg 2 0x%08lx\n", what, (unsigned long)r->st[b + 3]);
    ok(parse_resp(r->tok[b + 3], r->len[b + 3], &fr), "%s: server final shape\n", what);
    ok(fr.present == ((1 << 0) | (1 << 3)) && fr.neg_state == 0 && fr.mic_len == 16, "%s: server final 0x%lx %d\n", what,
       fr.present, fr.neg_state);
    check_complete(r, what);
    check_messages(&r->cctx, &r->sctx, seal, what);
    check_messages(&r->sctx, &r->cctx, seal, what);
done:
    run_free(r);
    free(r);
}

/* raw NTLM where Windows uses it: explicit credentials without a hint; and DCE style (rpcrt4) here */
static void test_raw(CredHandle *cc, CredHandle *sc, ULONG creq, ULONG sreq, const char *what)
{
    run_t *r = calloc(1, sizeof(*r));
    SecPkgContext_NegotiationInfoW ni;
    SECURITY_STATUS st;

    r->cc = cc; r->sc = sc; r->creq = creq; r->sreq = sreq; r->mutate_index = -1;
    run_exchange(r);
    ok(r->cst == SEC_E_OK && r->sst == SEC_E_OK, "%s: client 0x%08lx server 0x%08lx\n", what, (unsigned long)r->cst,
       (unsigned long)r->sst);
    ok(r->n == 3, "%s: %d tokens\n", what, r->n);
    if (r->n >= 1) ok(!memcmp(r->tok[0], "NTLMSSP\0\1", 9), "%s: first token is not a raw NEGOTIATE\n", what);
    if (r->n >= 2) ok(!memcmp(r->tok[1], "NTLMSSP\0\2", 9), "%s: second token is not a raw CHALLENGE\n", what);
    if (r->n >= 3) ok(!memcmp(r->tok[2], "NTLMSSP\0\3", 9), "%s: third token is not a raw AUTHENTICATE\n", what);
    memset(&ni, 0, sizeof(ni));
    st = QueryContextAttributesW(&r->cctx, SECPKG_ATTR_NEGOTIATION_INFO, &ni);
    ok(st == SEC_E_OK && ni.NegotiationState == SECPKG_NEGOTIATION_COMPLETE, "%s: state 0x%08lx %lu\n", what,
       (unsigned long)st, ni.NegotiationState);
    if (st == SEC_E_OK) FreeContextBuffer(ni.PackageInfo);
    run_free(r);
    free(r);
}

/* the attributes while SPNEGO negotiates (measured on Windows) */
static void test_in_progress(CredHandle *cc, CredHandle *sc)
{
    run_t *r = calloc(1, sizeof(*r));
    BYTE a[MAX_TOK], b[MAX_TOK];
    ULONG al = 0, bl = 0, attr;
    SECURITY_STATUS st;

    r->cc = cc; r->sc = sc; r->creq = ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY;
    r->sreq = ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY; r->mutate_index = -1;
    st = call(r, TRUE, NULL, 0, FALSE, a, &al, &attr);                   /* hint */
    ok(st == SEC_I_CONTINUE_NEEDED && al, "hint: 0x%08lx\n", (unsigned long)st);
    if (r->have_s) { DeleteSecurityContext(&r->sctx); r->have_s = FALSE; }
    st = call(r, FALSE, a, al, TRUE, b, &bl, &attr);                     /* NegTokenInit */
    ok(st == SEC_I_CONTINUE_NEEDED, "init: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_I_CONTINUE_NEEDED) goto done;
    check_in_progress(&r->cctx, "client after its first token");
    st = call(r, TRUE, b, bl, TRUE, a, &al, &attr);                      /* CHALLENGE */
    ok(st == SEC_I_CONTINUE_NEEDED, "resp: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_I_CONTINUE_NEEDED) goto done;
    check_in_progress(&r->sctx, "server after the challenge");
    st = call(r, FALSE, a, al, TRUE, b, &bl, &attr);                     /* AUTHENTICATE + MIC */
    ok(st == SEC_I_CONTINUE_NEEDED, "final: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_I_CONTINUE_NEEDED) goto done;
    check_in_progress(&r->cctx, "client before the server's MIC");
    st = MakeSignature(&r->cctx, 0, NULL, 0);
    ok(st == SEC_E_INVALID_HANDLE, "MakeSignature before completion: 0x%08lx\n", (unsigned long)st);
done:
    run_free(r);
    free(r);
}

/* ---------------------------------------------------------------------------------------------------------------- */
/* malformed and altered tokens: the statuses Windows gives (the measured table) */
typedef struct { int kind; ULONG arg; } mut_arg;
enum { M_REPLACE, M_TRUNC, M_TRAILING, M_FLIP, M_OUTER_TAG, M_FIN_NOMIC, M_FIN_MICFLIP, M_FIN_MICSEQ, M_FIN_MIC15,
       M_FIN_COMPLETED, M_FIN_RAW, M_SF_NOMIC, M_SF_MICFLIP, M_SF_INCOMPLETE, M_SF_REJECT, M_RESP_REJECT,
       M_RESP_KRB, M_RESP_NOTOKEN, M_RESP_NONEG, M_RESP_COMPLETED, M_RESP_RAW, M_HUGE_LEN, M_FIN_MICVERSION,
       M_SF_TOKEN_NOMIC, M_SF_TOKEN_MIC, M_RESP_STATE7, M_EMPTY, M_FIN_MICPARTS, M_SF_MICPARTS };

/* the parts of a mechListMIC that M_FIN_MICPARTS and M_SF_MICPARTS change (arg is a mask of them) */
#define MIC_VERSION     1
#define MIC_CHECKSUM    2
#define MIC_SEQUENCE    4

/* The status of a mechListMIC with several parts wrong at once. One part alone is in the measured table above (version
 * SEC_E_INVALID_TOKEN, checksum SEC_E_MESSAGE_ALTERED, sequence SEC_E_OUT_OF_SEQUENCE). Several at once: the order
 * measured on Windows Server 2022 for the same NTLM signature check in VerifySignature, each part flipped alone and
 * together (version first, then checksum, then sequence). The mechListMIC with several parts wrong was not measured
 * itself: VERIFY ON PEER (probe: a server mechListMIC with the version and the checksum, the checksum and the sequence
 * changed, in the last call of a Negotiate client; the same for the client's MIC in the server's last call). */
static const struct { ULONG parts; SECURITY_STATUS st; } mic_order[] =
{
    { MIC_VERSION | MIC_CHECKSUM,                SEC_E_INVALID_TOKEN },
    { MIC_VERSION | MIC_SEQUENCE,                SEC_E_INVALID_TOKEN },
    { MIC_CHECKSUM | MIC_SEQUENCE,               SEC_E_MESSAGE_ALTERED },
    { MIC_VERSION | MIC_CHECKSUM | MIC_SEQUENCE, SEC_E_INVALID_TOKEN },
};

static const BYTE *g_replace;
static ULONG g_replace_len;

static ULONG mutate(const BYTE *in, ULONG len, BYTE *out, void *argp)
{
    mut_arg *a = argp;
    resp_fields f;
    BYTE mic[16];

    parse_resp(in, len, &f);
    if (f.mic && f.mic_len == 16) memcpy(mic, f.mic, 16);
    switch (a->kind)
    {
    case M_REPLACE:
        if (g_replace_len > MAX_TOK) return 0;
        memcpy(out, g_replace, g_replace_len);
        return g_replace_len;
    case M_TRUNC: memcpy(out, in, len); return len > a->arg ? len - a->arg : 0;
    case M_TRAILING: if (len >= MAX_TOK) return 0; memcpy(out, in, len); out[len] = 0; return len + 1;
    case M_FLIP: memcpy(out, in, len); if (a->arg < len) out[a->arg] ^= 0xff; return len;
    case M_OUTER_TAG: memcpy(out, in, len); out[0] ^= 1; return len;
    case M_HUGE_LEN: out[0] = in[0]; out[1] = 0x84; out[2] = out[3] = out[4] = out[5] = 0xff;
                     { ULONG h = (in[1] & 0x80) ? 2 + (in[1] & 0x7f) : 2; memcpy(out + 6, in + h, len - h); return 6 + len - h; }
    case M_FIN_NOMIC: return mk_resp(out, 1, NULL, 0, f.tok, f.tok_len, NULL, 0);
    case M_FIN_MICFLIP: mic[4] ^= 1; return mk_resp(out, 1, NULL, 0, f.tok, f.tok_len, mic, 16);
    case M_FIN_MICSEQ: mic[12] = 1; return mk_resp(out, 1, NULL, 0, f.tok, f.tok_len, mic, 16);
    case M_FIN_MIC15: return mk_resp(out, 1, NULL, 0, f.tok, f.tok_len, mic, 15);
    case M_FIN_MICVERSION: mic[0] ^= 1; return mk_resp(out, 1, NULL, 0, f.tok, f.tok_len, mic, 16);
    case M_FIN_MICPARTS:
    case M_SF_MICPARTS:
        if (a->arg & MIC_VERSION) mic[0] ^= 1;
        if (a->arg & MIC_CHECKSUM) mic[4] ^= 1;
        if (a->arg & MIC_SEQUENCE) mic[12] = 1;
        if (a->kind == M_FIN_MICPARTS) return mk_resp(out, 1, NULL, 0, f.tok, f.tok_len, mic, 16);
        return mk_resp(out, 0, NULL, 0, NULL, 0, mic, 16);
    case M_SF_TOKEN_NOMIC: return mk_resp(out, 0, NULL, 0, mic, 16, NULL, 0);
    case M_SF_TOKEN_MIC: { static const BYTE x[4] = { 1, 2, 3, 4 }; return mk_resp(out, 0, NULL, 0, x, 4, mic, 16); }
    case M_RESP_STATE7: return mk_resp(out, 7, OID_NTLM, sizeof(OID_NTLM), f.tok, f.tok_len, NULL, 0);
    case M_EMPTY: return 0;
    case M_FIN_COMPLETED: return mk_resp(out, 0, NULL, 0, f.tok, f.tok_len, mic, 16);
    case M_FIN_RAW: memcpy(out, f.tok, f.tok_len); return f.tok_len;
    case M_SF_NOMIC: return mk_resp(out, 0, NULL, 0, NULL, 0, NULL, 0);
    case M_SF_MICFLIP: mic[4] ^= 1; return mk_resp(out, 0, NULL, 0, NULL, 0, mic, 16);
    case M_SF_INCOMPLETE: return mk_resp(out, 1, NULL, 0, NULL, 0, mic, 16);
    case M_SF_REJECT: return mk_resp(out, 2, NULL, 0, NULL, 0, NULL, 0);
    case M_RESP_REJECT: return mk_resp(out, 2, NULL, 0, NULL, 0, NULL, 0);
    case M_RESP_KRB: return mk_resp(out, 1, OID_KRB, sizeof(OID_KRB), f.tok, f.tok_len, NULL, 0);
    case M_RESP_NOTOKEN: return mk_resp(out, 1, OID_NTLM, sizeof(OID_NTLM), NULL, 0, NULL, 0);
    case M_RESP_NONEG: return mk_resp(out, -1, OID_NTLM, sizeof(OID_NTLM), f.tok, f.tok_len, NULL, 0);
    case M_RESP_COMPLETED: return mk_resp(out, 0, OID_NTLM, sizeof(OID_NTLM), f.tok, f.tok_len, NULL, 0);
    case M_RESP_RAW: memcpy(out, f.tok, f.tok_len); return f.tok_len;
    }
    return 0;
}

static run_t *mal_run(CredHandle *cc, CredHandle *sc, int index, int kind, ULONG arg, BOOL split, ULONG split_at)
{
    static mut_arg a;
    run_t *r = calloc(1, sizeof(*r));

    a.kind = kind; a.arg = arg;
    r->cc = cc; r->sc = sc; r->hint = TRUE;
    r->creq = ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY; r->sreq = ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY;
    r->mutate_index = index; r->mutate = mutate; r->arg = &a; r->split = split; r->split_at = split_at;
    run_exchange(r);
    return r;
}

static void mal(CredHandle *cc, CredHandle *sc, const char *name, int index, int kind, ULONG arg, SECURITY_STATUS expect)
{
    run_t *r = mal_run(cc, sc, index, kind, arg, FALSE, 0);

    ok(r->mutated_status == expect, "%s (token %d): 0x%08lx, expected 0x%08lx\n", name, index,
       (unsigned long)r->mutated_status, (unsigned long)expect);
    run_free(r);
    free(r);
}

static void mal_replace(CredHandle *cc, CredHandle *sc, const char *name, int index, const BYTE *tok, ULONG len,
                        SECURITY_STATUS expect, const BYTE *expect_out, ULONG expect_out_len)
{
    run_t *r;

    g_replace = tok; g_replace_len = len;
    r = mal_run(cc, sc, index, M_REPLACE, 0, FALSE, 0);
    ok(r->mutated_status == expect, "%s (token %d): 0x%08lx, expected 0x%08lx\n", name, index,
       (unsigned long)r->mutated_status, (unsigned long)expect);
    if (expect_out)
        ok(r->mutated_out_len == expect_out_len && !memcmp(r->mutated_out, expect_out, expect_out_len),
           "%s: output differs (%lu bytes)\n", name, r->mutated_out_len);
    run_free(r);
    free(r);
}

static void test_malformed(CredHandle *cc, CredHandle *sc)
{
    BYTE tok[MAX_TOK], ntlm_neg[MAX_TOK];
    ULONG l, neg_len = 0;
    const BYTE *oids[3];
    ULONG lens[3];
    run_t *r;
    init_fields fi;

    /* a client NEGOTIATE to put into the constructed tokens */
    r = mal_run(cc, sc, -1, 0, 0, FALSE, 0);
    ok(r->n == 5, "malformed: the unchanged exchange has %d tokens\n", r->n);
    if (r->n >= 2 && parse_init(r->tok[1], r->len[1], &fi) && fi.tok_len < sizeof(ntlm_neg))
    {
        memcpy(ntlm_neg, fi.tok, fi.tok_len);
        neg_len = fi.tok_len;
    }
    run_free(r);
    free(r);
    if (!neg_len) return;

    /* the client's NegTokenInit, to the server (token 1) */
    {
        BYTE two[2] = { 0x60, 0x48 };
        mal_replace(cc, sc, "init: header only", 1, two, 2, SEC_E_INVALID_TOKEN, NULL, 0);
    }
    mal(cc, sc, "init: wrong outer tag", 1, M_OUTER_TAG, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "init: length 0xffffffff", 1, M_HUGE_LEN, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "init: a byte behind the token (accepted)", 1, M_TRAILING, 0, SEC_I_CONTINUE_NEEDED);
    mal(cc, sc, "init: the last byte missing (more is awaited)", 1, M_TRUNC, 1, SEC_I_CONTINUE_NEEDED);
    oids[0] = OID_KRB; lens[0] = sizeof(OID_KRB);
    l = mk_init(tok, oids, lens, 1, ntlm_neg, neg_len, OID_SPNEGO, sizeof(OID_SPNEGO));
    mal_replace(cc, sc, "init: Kerberos only", 1, tok, l, SEC_E_INVALID_TOKEN, NULL, 0);
    l = mk_init(tok, oids, lens, 0, ntlm_neg, neg_len, OID_SPNEGO, sizeof(OID_SPNEGO));
    mal_replace(cc, sc, "init: no mechanisms", 1, tok, l, SEC_E_INVALID_TOKEN, NULL, 0);
    oids[0] = OID_NTLM; lens[0] = sizeof(OID_NTLM);
    l = mk_init(tok, oids, lens, 1, ntlm_neg, neg_len, OID_KRB, sizeof(OID_KRB));
    mal_replace(cc, sc, "init: thisMech is not SPNEGO", 1, tok, l, SEC_E_INVALID_TOKEN, NULL, 0);
    {
        /* Kerberos first with an optimistic token: NTLM is chosen with request-mic and no token (measured bytes) */
        static const BYTE reqmic[] = { 0xa1, 0x15, 0x30, 0x13, 0xa0, 0x03, 0x0a, 0x01, 0x03, 0xa1, 0x0c, 0x06, 0x0a,
                                       0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
        static const BYTE incomplete[] = { 0xa1, 0x15, 0x30, 0x13, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1, 0x0c, 0x06,
                                           0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
        oids[0] = OID_KRB; lens[0] = sizeof(OID_KRB); oids[1] = OID_NTLM; lens[1] = sizeof(OID_NTLM);
        l = mk_init(tok, oids, lens, 2, ntlm_neg, neg_len, OID_SPNEGO, sizeof(OID_SPNEGO));
        mal_replace(cc, sc, "init: Kerberos, NTLM", 1, tok, l, SEC_I_CONTINUE_NEEDED, reqmic, sizeof(reqmic));
        oids[0] = OID_NTLM; lens[0] = sizeof(OID_NTLM);
        l = mk_init(tok, oids, lens, 1, NULL, 0, OID_SPNEGO, sizeof(OID_SPNEGO));
        mal_replace(cc, sc, "init: NTLM without a token", 1, tok, l, SEC_I_CONTINUE_NEEDED, incomplete,
                    sizeof(incomplete));
    }
    l = mk_resp(tok, -1, NULL, 0, ntlm_neg, neg_len, NULL, 0);
    mal_replace(cc, sc, "init: a NegTokenResp", 1, tok, l, SEC_E_INVALID_TOKEN, NULL, 0);
    {
        /* 2000 nested SEQUENCEs: refused without recursion */
        ULONG depth = 2000, k, pos = 0;
        BYTE *deep = malloc(depth * 6);
        for (k = 0; k < depth; k++)
        {
            ULONG rem = depth * 6 - pos - 6;
            deep[pos++] = k ? 0x30 : 0x60;
            deep[pos++] = 0x84; deep[pos++] = (BYTE)(rem >> 24); deep[pos++] = (BYTE)(rem >> 16);
            deep[pos++] = (BYTE)(rem >> 8); deep[pos++] = (BYTE)rem;
        }
        mal_replace(cc, sc, "init: 2000 levels of nesting", 1, deep, pos, SEC_E_INVALID_TOKEN, NULL, 0);
        deep[0] = 0xa1;
        mal_replace(cc, sc, "resp: 2000 levels of nesting", 2, deep, pos, SEC_E_INVALID_TOKEN, NULL, 0);
        free(deep);
    }
    /* the init in two calls: reassembled (measured) */
    r = mal_run(cc, sc, 1, M_TRUNC, 0, TRUE, 20);
    ok(r->mutated_status == SEC_I_CONTINUE_NEEDED && r->mutated_out_len > 0, "init in two calls: 0x%08lx %lu\n",
       (unsigned long)r->mutated_status, r->mutated_out_len);
    ok(r->cst == SEC_E_OK && r->sst == SEC_E_OK, "init in two calls: client 0x%08lx server 0x%08lx\n",
       (unsigned long)r->cst, (unsigned long)r->sst);
    run_free(r); free(r);

    /* the server's first NegTokenResp, to the client (token 2) */
    mal(cc, sc, "resp: reject", 2, M_RESP_REJECT, 0, SEC_E_LOGON_DENIED);
    mal(cc, sc, "resp: supportedMech Kerberos", 2, M_RESP_KRB, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "resp: no responseToken", 2, M_RESP_NOTOKEN, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "resp: no negState", 2, M_RESP_NONEG, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "resp: accept-completed with the challenge", 2, M_RESP_COMPLETED, 0, SEC_E_INTERNAL_ERROR);
    mal(cc, sc, "resp: the raw CHALLENGE", 2, M_RESP_RAW, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "resp: truncated", 2, M_TRUNC, 1, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "resp: a byte behind the token (accepted)", 2, M_TRAILING, 0, SEC_I_CONTINUE_NEEDED);
    mal(cc, sc, "resp: negState 7 (accepted)", 2, M_RESP_STATE7, 0, SEC_I_CONTINUE_NEEDED);

    /* the client's last token, to the server (token 3) */
    mal(cc, sc, "final: no mechListMIC", 3, M_FIN_NOMIC, 0, SEC_I_CONTINUE_NEEDED);
    mal(cc, sc, "final: mechListMIC altered", 3, M_FIN_MICFLIP, 0, SEC_E_MESSAGE_ALTERED);
    mal(cc, sc, "final: mechListMIC with sequence 1", 3, M_FIN_MICSEQ, 0, SEC_E_OUT_OF_SEQUENCE);
    mal(cc, sc, "final: mechListMIC of 15 bytes", 3, M_FIN_MIC15, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "final: mechListMIC of another version", 3, M_FIN_MICVERSION, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "final: an empty token on the context", 3, M_EMPTY, 0, SEC_E_INVALID_HANDLE);
    mal(cc, sc, "final: negState accept-completed", 3, M_FIN_COMPLETED, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "final: the raw AUTHENTICATE", 3, M_FIN_RAW, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "final: a byte behind the token", 3, M_TRAILING, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "final: the last byte missing (more is awaited)", 3, M_TRUNC, 1, SEC_I_CONTINUE_NEEDED);
    r = mal_run(cc, sc, 3, M_TRUNC, 0, TRUE, 100);
    ok(r->mutated_status == SEC_E_OK, "final in two calls: 0x%08lx\n", (unsigned long)r->mutated_status);
    run_free(r); free(r);
    {
        /* no mechListMIC: the server answers with its own and accepts nothing more; no token for the caller */
        SECURITY_STATUS st;
        HANDLE token = NULL;
        r = mal_run(cc, sc, 3, M_FIN_NOMIC, 0, FALSE, 0);
        ok(r->mutated_status == SEC_I_CONTINUE_NEEDED && r->mutated_out_len > 0, "final without MIC: 0x%08lx\n",
           (unsigned long)r->mutated_status);
        if (r->have_s)
        {
            st = ImpersonateSecurityContext(&r->sctx);
            ok(st == SEC_E_NO_IMPERSONATION, "impersonation before the MIC: 0x%08lx\n", (unsigned long)st);
            if (st == SEC_E_OK) RevertSecurityContext(&r->sctx);
            st = QuerySecurityContextToken(&r->sctx, &token);
            ok(st != SEC_E_OK, "token before the MIC: 0x%08lx\n", (unsigned long)st);
            if (token) CloseHandle(token);
        }
        run_free(r); free(r);
    }

    /* the server's last token, to the client (token 4) */
    mal(cc, sc, "server final: no mechListMIC (accepted)", 4, M_SF_NOMIC, 0, SEC_E_OK);
    mal(cc, sc, "server final: mechListMIC altered", 4, M_SF_MICFLIP, 0, SEC_E_MESSAGE_ALTERED);
    mal(cc, sc, "server final: accept-incomplete", 4, M_SF_INCOMPLETE, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "server final: reject", 4, M_SF_REJECT, 0, SEC_E_LOGON_DENIED);
    mal(cc, sc, "server final: a responseToken without mechListMIC", 4, M_SF_TOKEN_NOMIC, 0, SEC_E_INVALID_TOKEN);
    mal(cc, sc, "server final: a responseToken with the mechListMIC (accepted)", 4, M_SF_TOKEN_MIC, 0, SEC_E_OK);
    mal(cc, sc, "server final: truncated", 4, M_TRUNC, 1, SEC_E_INVALID_TOKEN);

    /* the mechListMIC with several parts wrong (see mic_order), in both directions */
    {
        ULONG i;
        char name[80];

        for (i = 0; i < ARRAYSIZE(mic_order); i++)
        {
            sprintf(name, "final: mechListMIC with parts 0x%lx wrong", mic_order[i].parts);
            mal(cc, sc, name, 3, M_FIN_MICPARTS, mic_order[i].parts, mic_order[i].st);
            sprintf(name, "server final: mechListMIC with parts 0x%lx wrong", mic_order[i].parts);
            mal(cc, sc, name, 4, M_SF_MICPARTS, mic_order[i].parts, mic_order[i].st);
        }
    }

    /* the hint, to the client (token 0) */
    oids[0] = OID_KRB; lens[0] = sizeof(OID_KRB);
    l = mk_init(tok, oids, lens, 1, NULL, 0, OID_SPNEGO, sizeof(OID_SPNEGO));
    mal_replace(cc, sc, "hint: Kerberos only", 0, tok, l, SEC_E_NO_CREDENTIALS, NULL, 0);
    {
        /* the first token of another GSS mechanism */
        static const BYTE other[] = { 0x60, 0x07, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x05, 0x00 };
        mal_replace(cc, sc, "hint: another mechanism", 0, other, sizeof(other), SEC_E_SECPKG_NOT_FOUND, NULL, 0);
    }
    {
        static const BYTE garbage[] = { 1, 2, 3, 4 };
        g_replace = garbage; g_replace_len = sizeof(garbage);
        r = mal_run(cc, sc, 0, M_REPLACE, 0, FALSE, 0);
        ok(r->mutated_status == SEC_I_CONTINUE_NEEDED && r->mutated_out_len >= 8 &&
           !memcmp(r->mutated_out, "NTLMSSP", 8), "hint: garbage is ignored (raw NTLM for explicit credentials)\n");
        run_free(r); free(r);
    }
}

/* the server's hint followed by a raw NTLM client on the same context, and the default credentials of the caller */
static void test_mixed(CredHandle *sc)
{
    CredHandle ncc;
    TimeStamp ts;
    SECURITY_STATUS st;
    SEC_WINNT_AUTH_IDENTITY_W id;
    run_t *r = calloc(1, sizeof(*r));

    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)g_user; id.UserLength = (ULONG)wcslen(g_user);
    id.Domain = (unsigned short *)L"."; id.DomainLength = 1;
    id.Password = (unsigned short *)TEST_PASSWORD; id.PasswordLength = (ULONG)wcslen(TEST_PASSWORD);
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    /* an NTLM client against the Negotiate server */
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &ncc, &ts);
    ok_eq_hex(st, SEC_E_OK);
    if (st == SEC_E_OK)
    {
        r->cc = &ncc; r->sc = sc; r->creq = ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY;
        r->sreq = ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY; r->mutate_index = -1;
        run_exchange(r);
        ok(r->cst == SEC_E_OK && r->sst == SEC_E_OK, "NTLM client, Negotiate server: 0x%08lx 0x%08lx\n",
           (unsigned long)r->cst, (unsigned long)r->sst);
        run_free(r);
        FreeCredentialsHandle(&ncc);
    }
    free(r);
}

START_TEST(NegotiateSpnego)
{
    CredHandle cc, sc, dc, dsc;
    static const ULONG flags[][3] =
    {
        /* ISC, ASC, seal */
        { ISC_REQ_CONNECTION, ASC_REQ_CONNECTION, 0 },
        { ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT,
          ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT, 0 },
        { ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT,
          ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT, 1 },
        { ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_MUTUAL_AUTH, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY, 0 },
        { ISC_REQ_CONNECTION | ISC_REQ_MUTUAL_AUTH, ASC_REQ_CONNECTION, 0 },
    };
    ULONG i;

    if (!create_user()) return;
    if (acquire(&cc, &sc, TRUE))
    {
        for (i = 0; i < ARRAYSIZE(flags); i++)
            test_exchange(&cc, &sc, TRUE, flags[i][0], flags[i][1], flags[i][2]);
        test_raw(&cc, &sc, ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY, ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY,
                 "explicit credentials without a hint");
        test_in_progress(&cc, &sc);
        test_malformed(&cc, &sc);
        test_mixed(&sc);
        FreeCredentialsHandle(&cc);
        FreeCredentialsHandle(&sc);
    }
    /* the caller's own credentials: SPNEGO without a hint (Windows does) */
    if (acquire(&dc, &dsc, FALSE))
    {
        for (i = 0; i < ARRAYSIZE(flags); i++)
            test_exchange(&dc, &dsc, FALSE, flags[i][0], flags[i][1], flags[i][2]);
        test_raw(&dc, &dsc, ISC_REQ_CONNECTION | ISC_REQ_USE_DCE_STYLE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_INTEGRITY,
                 ASC_REQ_CONNECTION | ASC_REQ_USE_DCE_STYLE | ASC_REQ_INTEGRITY, "DCE style, own credentials");
        FreeCredentialsHandle(&dc);
        FreeCredentialsHandle(&dsc);
    }
    NetUserDel(NULL, g_user);
}
