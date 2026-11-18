/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The Negotiate server reassembles a client token that arrives in pieces (Windows does, measured: an SPNEGO
 *              token whose header is complete and has some content is kept, SEC_I_CONTINUE_NEEDED goes back without
 *              output, the next call completes it). A raw NTLM token carries no length: it is never kept, so the
 *              layer below always sees the whole token or the exchange fails at once. Rows for every split point of a
 *              raw NTLM NEGOTIATE and of an SPNEGO NegTokenInit with a short and with a long length field.
 *
 *              What Windows does with a raw NTLM token in pieces, and with a piece that ends inside the header, was not
 *              measured: those rows are marked VERIFY ON PEER and their expected values are isolated in one table.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <string.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define MAXT 8192

/* the expected statuses that were not measured on Windows (VERIFY ON PEER): the first call with a raw NTLM prefix of
 * 1..7 bytes, and the first call with a piece that does not even contain one byte of SPNEGO content */
static const SECURITY_STATUS VOP_RAW_PREFIX_STATUS = SEC_E_INVALID_TOKEN;
static const SECURITY_STATUS VOP_HEADER_ONLY_STATUS = SEC_E_INVALID_TOKEN;

static const BYTE OID_NTLM[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
static const BYTE OID_SPNEGO[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

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

/* NegTokenInit { mechTypes {NTLM}, mechToken } */
static ULONG mk_init(BYTE *out, const BYTE *tok, ULONG tl)
{
    BYTE list[32], seq[MAXT], a[MAXT], b[MAXT];
    ULONG n = 0, k, m;

    k = put(list, 0x06, OID_NTLM, sizeof(OID_NTLM));
    k = put(a, 0x30, list, k);
    n += put(seq + n, 0xa0, a, k);
    k = put(a, 0x04, tok, tl);
    n += put(seq + n, 0xa2, a, k);
    k = put(a, 0x30, seq, n);
    k = put(b, 0xa0, a, k);
    m = put(a, 0x06, OID_SPNEGO, sizeof(OID_SPNEGO));
    memcpy(a + m, b, k);
    return put(out, 0x60, a, m + k);
}

typedef struct
{
    CredHandle sc;
    BOOL have_sc;
    BYTE neg[MAXT];             /* a raw NTLM NEGOTIATE */
    ULONG neg_len;
    BYTE neg_long[MAXT];        /* the same with 300 bytes of domain name (an SPNEGO token of more than 255 bytes) */
    ULONG neg_long_len;
} env_t;

/* a raw NTLM NEGOTIATE from the NTLM package (explicit credentials: no logon is needed for it) */
static BOOL make_negotiate(env_t *e)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    CredHandle cc;
    CtxtHandle cx;
    TimeStamp ts;
    SecBuffer ob = { MAXT, SECBUFFER_TOKEN, e->neg };
    SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attr, i;
    SECURITY_STATUS st;

    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)L"nobody"; id.UserLength = 6;
    id.Domain = (unsigned short *)L"."; id.DomainLength = 1;
    id.Password = (unsigned short *)L"pw"; id.PasswordLength = 2;
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &cc, &ts);
    ok(st == SEC_E_OK, "NTLM credentials: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_E_OK) return FALSE;
    st = InitializeSecurityContextW(&cc, NULL, NULL, ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, NULL, 0, &cx, &od,
                                    &attr, &ts);
    ok(st == SEC_I_CONTINUE_NEEDED, "NTLM first leg: 0x%08lx\n", (unsigned long)st);
    if (st == SEC_I_CONTINUE_NEEDED) DeleteSecurityContext(&cx);
    FreeCredentialsHandle(&cc);
    if (st != SEC_I_CONTINUE_NEEDED) return FALSE;
    e->neg_len = ob.cbBuffer;
    ok(e->neg_len >= 32 && !memcmp(e->neg, "NTLMSSP\0\1\0\0\0", 12), "not a NEGOTIATE (%lu bytes)\n", e->neg_len);
    if (e->neg_len < 32 || e->neg_len > 200) return FALSE;

    /* 300 bytes of domain name behind the header: the same message, a token that needs a two-byte length field */
    memcpy(e->neg_long, e->neg, e->neg_len);
    for (i = 0; i < 300; i++) e->neg_long[e->neg_len + i] = 'D';
    e->neg_long[12] |= 0x00;
    e->neg_long[13] |= 0x10;                    /* NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED (0x1000) */
    e->neg_long[16] = (BYTE)(300 & 0xff); e->neg_long[17] = (BYTE)(300 >> 8);        /* domain: length, max */
    e->neg_long[18] = (BYTE)(300 & 0xff); e->neg_long[19] = (BYTE)(300 >> 8);
    e->neg_long[20] = (BYTE)e->neg_len; e->neg_long[21] = 0; e->neg_long[22] = e->neg_long[23] = 0;
    e->neg_long_len = e->neg_len + 300;
    return TRUE;
}

static SECURITY_STATUS asc(env_t *e, CtxtHandle *ctx, BOOL *have, const BYTE *in, ULONG in_len, BYTE *out,
                           ULONG *out_len)
{
    SecBuffer ib = { in_len, SECBUFFER_TOKEN, (void *)in }, ob = { MAXT, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    TimeStamp ts;
    ULONG attr = 0;
    SECURITY_STATUS st;

    st = AcceptSecurityContext(&e->sc, *have ? ctx : NULL, &id, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, ctx, &od,
                               &attr, &ts);
    if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) *have = TRUE;
    *out_len = (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) ? ob.cbBuffer : 0;
    return st;
}

static void test_raw_whole(env_t *e)
{
    CtxtHandle ctx;
    BOOL have = FALSE;
    BYTE out[MAXT];
    ULONG ol;
    SECURITY_STATUS st = asc(e, &ctx, &have, e->neg, e->neg_len, out, &ol);

    ok(st == SEC_I_CONTINUE_NEEDED, "raw NEGOTIATE in one piece: 0x%08lx\n", (unsigned long)st);
    ok(ol > 12 && !memcmp(out, "NTLMSSP\0\2\0\0\0", 12), "raw NEGOTIATE in one piece: no raw CHALLENGE (%lu bytes)\n", ol);
    if (have) DeleteSecurityContext(&ctx);
}

/* a raw NTLM NEGOTIATE cut at every point: the first piece of 1..7 bytes is not a whole NTLM signature. The package
 * must not keep it (a raw token has no length to wait for) and then hand the layer below only the last piece. */
static void test_raw_split(env_t *e)
{
    ULONG k;

    for (k = 1; k < e->neg_len; k++)
    {
        CtxtHandle ctx;
        BOOL have = FALSE;
        BYTE out[MAXT];
        ULONG ol;
        SECURITY_STATUS st1, st2;

        st1 = asc(e, &ctx, &have, e->neg, k, out, &ol);
        if (k < 8)
        {
            ok(st1 == VOP_RAW_PREFIX_STATUS, "raw NEGOTIATE, first piece %lu bytes: 0x%08lx, expected 0x%08lx\n", k,
               (unsigned long)st1, (unsigned long)VOP_RAW_PREFIX_STATUS);
            ok(!have, "raw NEGOTIATE, first piece %lu bytes: a context was returned\n", k);
            ok(!ol, "raw NEGOTIATE, first piece %lu bytes: %lu bytes of output\n", k, ol);
        }
        if (have)
        {
            /* the rest of the token reaches a context that took the first piece: it must not complete anything */
            st2 = asc(e, &ctx, &have, e->neg + k, e->neg_len - k, out, &ol);
            if (k < 8) trace("raw NEGOTIATE split at %lu: first piece 0x%08lx, rest 0x%08lx\n", k, (unsigned long)st1,
                             (unsigned long)st2);
            ok(st2 != SEC_E_OK, "raw NEGOTIATE split at %lu: the second piece completed the exchange\n", k);
            DeleteSecurityContext(&ctx);
        }
        ok(st1 != SEC_E_OK, "raw NEGOTIATE split at %lu: the first piece completed the exchange\n", k);
    }
}

static void check_challenge_token(const BYTE *out, ULONG ol, const char *what, ULONG k)
{
    ULONG i;
    BOOL found = FALSE;

    ok(ol > 20 && out[0] == 0xa1, "%s split at %lu: output is not a NegTokenResp (%lu bytes)\n", what, k, ol);
    for (i = 0; i + 12 <= ol && !found; i++)
        found = !memcmp(out + i, "NTLMSSP\0\2\0\0\0", 12);
    ok(found, "%s split at %lu: no CHALLENGE in the output\n", what, k);
}

/* an SPNEGO NegTokenInit cut at every point */
static void test_spnego_split(env_t *e, const BYTE *neg, ULONG neg_len, const char *what)
{
    BYTE tok[MAXT], tail[MAXT];
    ULONG len = mk_init(tok, neg, neg_len), hdr = tok[1] < 0x80 ? 2 : 2 + (tok[1] & 0x7f), k;
    CtxtHandle ctx;
    BOOL have;
    BYTE out[MAXT];
    ULONG ol;
    SECURITY_STATUS st;

    have = FALSE;
    st = asc(e, &ctx, &have, tok, len, out, &ol);
    ok(st == SEC_I_CONTINUE_NEEDED, "%s in one piece: 0x%08lx\n", what, (unsigned long)st);
    if (st == SEC_I_CONTINUE_NEEDED) check_challenge_token(out, ol, what, 0);
    if (have) DeleteSecurityContext(&ctx);

    for (k = 1; k < len; k++)
    {
        have = FALSE;
        st = asc(e, &ctx, &have, tok, k, out, &ol);
        if (k < hdr)
        {
            /* the piece ends inside the length field (not measured) */
            ok(st == VOP_HEADER_ONLY_STATUS, "%s, piece of %lu bytes inside the %lu-byte header: 0x%08lx, expected 0x%08lx\n",
               what, k, hdr, (unsigned long)st, (unsigned long)VOP_HEADER_ONLY_STATUS);
            ok(!have, "%s, piece of %lu bytes inside the header: a context was returned\n", what, k);
        }
        else if (k == hdr)
        {
            ok(st == VOP_HEADER_ONLY_STATUS, "%s, the header alone (%lu bytes): 0x%08lx, expected 0x%08lx\n", what, k,
               (unsigned long)st, (unsigned long)VOP_HEADER_ONLY_STATUS);
            ok(!have, "%s, the header alone: a context was returned\n", what);
        }
        else
        {
            /* the header and some content: kept (measured) */
            ok(st == SEC_I_CONTINUE_NEEDED, "%s split at %lu: first piece 0x%08lx\n", what, k, (unsigned long)st);
            ok(!ol, "%s split at %lu: first piece gave %lu bytes of output\n", what, k, ol);
            if (st == SEC_I_CONTINUE_NEEDED)
            {
                st = asc(e, &ctx, &have, tok + k, len - k, out, &ol);
                ok(st == SEC_I_CONTINUE_NEEDED, "%s split at %lu: second piece 0x%08lx\n", what, k, (unsigned long)st);
                if (st == SEC_I_CONTINUE_NEEDED) check_challenge_token(out, ol, what, k);
            }
        }
        if (have) DeleteSecurityContext(&ctx);
    }

    /* three pieces, and a piece that carries more than the token needs */
    if (len > hdr + 4)
    {
        ULONG a = hdr + 1, b = len - 1;

        have = FALSE;
        st = asc(e, &ctx, &have, tok, a, out, &ol);
        ok(st == SEC_I_CONTINUE_NEEDED && !ol, "%s in three pieces: first 0x%08lx\n", what, (unsigned long)st);
        st = asc(e, &ctx, &have, tok + a, b - a, out, &ol);
        ok(st == SEC_I_CONTINUE_NEEDED && !ol, "%s in three pieces: second 0x%08lx\n", what, (unsigned long)st);
        st = asc(e, &ctx, &have, tok + b, len - b, out, &ol);
        ok(st == SEC_I_CONTINUE_NEEDED, "%s in three pieces: third 0x%08lx\n", what, (unsigned long)st);
        if (st == SEC_I_CONTINUE_NEEDED) check_challenge_token(out, ol, what, a);
        if (have) DeleteSecurityContext(&ctx);

        memcpy(tail, tok + a, len - a);
        memset(tail + len - a, 0, 5);
        have = FALSE;
        st = asc(e, &ctx, &have, tok, a, out, &ol);
        ok(st == SEC_I_CONTINUE_NEEDED, "%s: first piece 0x%08lx\n", what, (unsigned long)st);
        if (st == SEC_I_CONTINUE_NEEDED)
        {
            st = asc(e, &ctx, &have, tail, len - a + 5, out, &ol);
            ok(st == SEC_E_INVALID_TOKEN, "%s: last piece with 5 bytes behind the token: 0x%08lx\n", what,
               (unsigned long)st);
        }
        if (have) DeleteSecurityContext(&ctx);
    }
}

START_TEST(NegotiateReassembly)
{
    env_t *e = calloc(1, sizeof(*e));
    TimeStamp ts;
    SECURITY_STATUS st;

    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &e->sc,
                                   &ts);
    ok(st == SEC_E_OK, "inbound credentials: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_E_OK) { free(e); return; }
    if (make_negotiate(e))
    {
        test_raw_whole(e);
        test_raw_split(e);
        test_spnego_split(e, e->neg, e->neg_len, "NegTokenInit (short length field)");
        test_spnego_split(e, e->neg_long, e->neg_long_len, "NegTokenInit (two-byte length field)");
    }
    FreeCredentialsHandle(&e->sc);
    free(e);
}
