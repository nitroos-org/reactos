/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     What an unauthenticated peer can make the Negotiate server hold. A token that arrives in pieces is kept
 *              until it is complete (NegotiateReassembly); the kept part grows with the bytes the peer really sent, up to
 *              the length the token's own outer header announces, and not to the 48256-byte limit of the package
 *              (the cbMaxToken measured on Windows) the moment the header is read. A token that announces more than the
 *              limit fails at once with SEC_E_INVALID_TOKEN (the status measured for an outer length of 0xffffffff).
 *              The kept part is released on every failure, and by DeleteSecurityContext.
 *
 *              Rows: 2000 contexts that announce 48000 bytes and sent 16 hold no more than 2000 that announced 64
 *              (private bytes of the process); the same after the completing piece was refused; 10000 abandoned
 *              contexts deleted one by one leave the private bytes flat; the statuses of the announced lengths at and
 *              above the limit; a token delivered a byte at a time still completes.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <windef.h>
#include <winbase.h>
#include <ndk/rtlfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/pstypes.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define MAXT 8192
#define HOLD 2000               /* contexts held at once */
#define ABANDON 10000           /* contexts created and deleted in turn */
#define LIMIT 48256             /* the cbMaxToken of the package (measured on Windows) */

static const BYTE OID_NTLM[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
static const BYTE OID_SPNEGO[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

static CredHandle g_sc;

static SIZE_T private_bytes(void)
{
    VM_COUNTERS_EX vm;
    NTSTATUS status;

    memset(&vm, 0, sizeof(vm));
    status = NtQueryInformationProcess(NtCurrentProcess(), ProcessVmCounters, &vm, sizeof(vm), NULL);
    return NT_SUCCESS(status) ? vm.PrivateUsage : 0;
}

static BOOL page_heap_on(void)
{
    return !!(NtCurrentPeb()->NtGlobalFlag & 0x02000000);   /* FLG_HEAP_PAGE_ALLOCS */
}

static SECURITY_STATUS asc(CtxtHandle *ctx, BOOL *have, const BYTE *in, ULONG in_len, BYTE *out, ULONG *out_len)
{
    SecBuffer ib = { in_len, SECBUFFER_TOKEN, (void *)in }, ob = { MAXT, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    TimeStamp ts;
    ULONG attr = 0;
    SECURITY_STATUS st;

    st = AcceptSecurityContext(&g_sc, *have ? ctx : NULL, &id, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, ctx, &od,
                               &attr, &ts);
    if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) *have = TRUE;
    if (out_len) *out_len = (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) ? ob.cbBuffer : 0;
    return st;
}

/* the start of a NegTokenInit that is `total` bytes long (4-byte header, 0x82 length): header and `content` bytes */
static ULONG header_and(BYTE *out, ULONG total, ULONG content)
{
    ULONG clen = total - 4;

    out[0] = 0x60; out[1] = 0x82; out[2] = (BYTE)(clen >> 8); out[3] = (BYTE)clen;
    memset(out + 4, 0x30, content);
    return 4 + content;
}

typedef struct { CtxtHandle ctx; BOOL have; } slot_t;

/* n contexts that announced `total` bytes and sent `sent`; the private bytes they cost */
static SIZE_T fill(slot_t *slots, int n, ULONG total, ULONG sent, int *failed)
{
    SIZE_T before = private_bytes();
    BYTE in[64], out[MAXT];
    ULONG len = header_and(in, total, sent), ol;
    int i;

    *failed = 0;
    for (i = 0; i < n; i++)
    {
        slots[i].have = FALSE;
        if (asc(&slots[i].ctx, &slots[i].have, in, len, out, &ol) != SEC_I_CONTINUE_NEEDED) (*failed)++;
    }
    return private_bytes() - before;
}

static void drop(slot_t *slots, int n)
{
    int i;

    for (i = 0; i < n; i++)
        if (slots[i].have) { DeleteSecurityContext(&slots[i].ctx); slots[i].have = FALSE; }
}

static void test_hold(void)
{
    slot_t *slots = calloc(HOLD, sizeof(*slots));
    SIZE_T ctl, big;
    int failed;

    /* the cost of a context that announced little: the control */
    ctl = fill(slots, HOLD, 64, 16, &failed);
    ok(failed == 0, "%d of %d contexts refused the first piece\n", failed, HOLD);
    drop(slots, HOLD);

    big = fill(slots, HOLD, 48000, 16, &failed);
    ok(failed == 0, "%d of %d contexts refused the first piece (48000 announced)\n", failed, HOLD);
    trace("%d contexts, 16 bytes sent: announced 64 -> %lu KB, announced 48000 -> %lu KB\n", HOLD,
          (unsigned long)(ctl >> 10), (unsigned long)(big >> 10));
    ok(big <= ctl + HOLD * 512 + (2 << 20),
       "%d contexts that announced 48000 bytes and sent 16 hold %lu KB, those that announced 64 hold %lu KB\n", HOLD,
       (unsigned long)(big >> 10), (unsigned long)(ctl >> 10));
    if (!page_heap_on())
        ok(big <= (SIZE_T)HOLD * 4096 + (2 << 20), "%lu KB held for %d contexts that sent 16 bytes each\n",
           (unsigned long)(big >> 10), HOLD);

    drop(slots, HOLD);
    free(slots);
}

/* the held bytes after the completing piece was refused, measured against the control without a refusal */
static void test_refused_frees(void)
{
    slot_t *slots = calloc(HOLD, sizeof(*slots));
    SIZE_T base, held;
    int failed, i;
    BYTE out[MAXT];
    BYTE *more = malloc(LIMIT);
    ULONG ol;

    memset(more, 0x30, LIMIT);
    base = private_bytes();
    fill(slots, HOLD, 48000, 16, &failed);
    for (i = 0; i < HOLD; i++)
        if (slots[i].have) asc(&slots[i].ctx, &slots[i].have, more, 48000, out, &ol);       /* refused: too much */
    held = private_bytes() - base;
    trace("%d contexts after a refused completion: %lu KB\n", HOLD, (unsigned long)(held >> 10));
    if (!page_heap_on())
        ok(held <= (SIZE_T)HOLD * 4096 + (2 << 20), "%lu KB still held by %d contexts whose completing piece was refused\n",
           (unsigned long)(held >> 10), HOLD);
    else
        ok(held <= (SIZE_T)HOLD * 40000, "%lu KB still held by %d contexts whose completing piece was refused\n",
           (unsigned long)(held >> 10), HOLD);
    drop(slots, HOLD);
    free(more);
    free(slots);
}

static void test_abandon(void)
{
    BYTE in[64], out[MAXT];
    ULONG len = header_and(in, 48000, 16), ol;
    SIZE_T before, after;
    int i;

    for (i = 0; i < 300; i++)       /* warm up: heap growth, wrapper tables */
    {
        CtxtHandle c;
        BOOL have = FALSE;

        asc(&c, &have, in, len, out, &ol);
        if (have) DeleteSecurityContext(&c);
    }
    before = private_bytes();
    for (i = 0; i < ABANDON; i++)
    {
        CtxtHandle c;
        BOOL have = FALSE;
        SECURITY_STATUS st = asc(&c, &have, in, len, out, &ol);

        if (st != SEC_I_CONTINUE_NEEDED) { ok(0, "abandoned context %d: 0x%08lx\n", i, (unsigned long)st); break; }
        DeleteSecurityContext(&c);
    }
    after = private_bytes();
    trace("%d abandoned contexts deleted: private bytes %lu -> %lu KB\n", ABANDON, (unsigned long)(before >> 10),
          (unsigned long)(after >> 10));
    ok(after <= before + (page_heap_on() ? (8 << 20) : (512 << 10)),
       "private bytes grew from %lu KB to %lu KB over %d abandoned contexts\n", (unsigned long)(before >> 10),
       (unsigned long)(after >> 10), ABANDON);
}

static void test_limit(void)
{
    BYTE in[64], out[MAXT];
    static const struct { ULONG total; SECURITY_STATUS st; const char *what; } rows[] =
    {
        { LIMIT, SEC_I_CONTINUE_NEEDED, "an outer length that makes the token exactly the limit" },
        { LIMIT - 1, SEC_I_CONTINUE_NEEDED, "one byte below the limit" },
        { LIMIT + 1, SEC_E_INVALID_TOKEN, "one byte above the limit" },
        { LIMIT + 5000, SEC_E_INVALID_TOKEN, "5000 bytes above the limit" },
        { 0x00ffffff, SEC_E_INVALID_TOKEN, "16 MB" },
    };
    ULONG i, len, ol;

    for (i = 0; i < ARRAYSIZE(rows); i++)
    {
        CtxtHandle c;
        BOOL have = FALSE;
        SECURITY_STATUS st;

        if (rows[i].total > 0xffff)
        {
            /* a 0x83 or 0x84 length field */
            ULONG clen = rows[i].total - 5;
            in[0] = 0x60; in[1] = 0x84; in[2] = (BYTE)(clen >> 24); in[3] = (BYTE)(clen >> 16); in[4] = (BYTE)(clen >> 8);
            in[5] = (BYTE)clen;
            memset(in + 6, 0x30, 10);
            len = 16;
        }
        else
            len = header_and(in, rows[i].total, 16);
        st = asc(&c, &have, in, len, out, &ol);
        ok(st == rows[i].st, "%s: 0x%08lx, expected 0x%08lx\n", rows[i].what, (unsigned long)st,
           (unsigned long)rows[i].st);
        if (rows[i].st == SEC_E_INVALID_TOKEN) ok(!have && !ol, "%s: a context or output came back\n", rows[i].what);
        if (have) DeleteSecurityContext(&c);
    }

    /* 0xffffffff as in the measured row, in the 4-byte form */
    {
        CtxtHandle c;
        BOOL have = FALSE;
        SECURITY_STATUS st;

        in[0] = 0x60; in[1] = 0x84; in[2] = in[3] = in[4] = in[5] = 0xff;
        memset(in + 6, 0x30, 10);
        st = asc(&c, &have, in, 16, out, &ol);
        ok(st == SEC_E_INVALID_TOKEN && !have, "outer length 0xffffffff: 0x%08lx\n", (unsigned long)st);
        if (have) DeleteSecurityContext(&c);
    }

    /* the same on a context that went on: after the server's own NegTokenInit */
    {
        CtxtHandle c;
        BOOL have = FALSE;
        SECURITY_STATUS st = asc(&c, &have, (const BYTE *)"", 0, out, &ol);

        ok(st == SEC_I_CONTINUE_NEEDED, "hint: 0x%08lx\n", (unsigned long)st);
        if (have)
        {
            len = header_and(in, LIMIT + 1, 16);
            st = asc(&c, &have, in, len, out, &ol);
            ok(st == SEC_E_INVALID_TOKEN, "above the limit on a context that sent its hint: 0x%08lx\n", (unsigned long)st);
            len = header_and(in, 48000, 16);
            st = asc(&c, &have, in, len, out, &ol);
            ok(st == SEC_I_CONTINUE_NEEDED, "a usable token after the refusal: 0x%08lx\n", (unsigned long)st);
            DeleteSecurityContext(&c);
        }
    }
}

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

/* a raw NTLM NEGOTIATE from the NTLM package, wrapped in a NegTokenInit with 400 bytes of padding in the domain name */
static ULONG make_init(BYTE *out)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    CredHandle cc;
    CtxtHandle cx;
    TimeStamp ts;
    BYTE neg[MAXT], list[32], seq[MAXT], a[MAXT], b[MAXT];
    SecBuffer ob = { MAXT, SECBUFFER_TOKEN, neg };
    SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
    ULONG attr, n = 0, k, m, nl, i;
    SECURITY_STATUS st;

    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)L"nobody"; id.UserLength = 6;
    id.Domain = (unsigned short *)L"."; id.DomainLength = 1;
    id.Password = (unsigned short *)L"pw"; id.PasswordLength = 2;
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    if (AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"NTLM", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &cc, &ts))
        return 0;
    st = InitializeSecurityContextW(&cc, NULL, NULL, ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, NULL, 0, &cx, &od,
                                    &attr, &ts);
    FreeCredentialsHandle(&cc);
    if (st != SEC_I_CONTINUE_NEEDED) return 0;
    DeleteSecurityContext(&cx);
    nl = ob.cbBuffer;
    if (nl < 32 || nl > 200) return 0;
    for (i = 0; i < 400; i++) neg[nl + i] = 'D';
    neg[13] |= 0x10;
    neg[16] = (BYTE)(400 & 0xff); neg[17] = (BYTE)(400 >> 8);
    neg[18] = (BYTE)(400 & 0xff); neg[19] = (BYTE)(400 >> 8);
    neg[20] = (BYTE)nl; neg[21] = neg[22] = neg[23] = 0;
    nl += 400;

    k = put(list, 0x06, OID_NTLM, sizeof(OID_NTLM));
    k = put(a, 0x30, list, k);
    n += put(seq + n, 0xa0, a, k);
    k = put(a, 0x04, neg, nl);
    n += put(seq + n, 0xa2, a, k);
    k = put(a, 0x30, seq, n);
    k = put(b, 0xa0, a, k);
    m = put(a, 0x06, OID_SPNEGO, sizeof(OID_SPNEGO));
    memcpy(a + m, b, k);
    return put(out, 0x60, a, m + k);
}

/* a token delivered a byte at a time still completes (the buffer grows with what arrives) */
static void test_bytewise(void)
{
    BYTE tok[MAXT], out[MAXT];
    ULONG len = make_init(tok), i, ol;
    CtxtHandle c;
    BOOL have = FALSE;
    SECURITY_STATUS st = SEC_E_OK;

    ok(len > 400, "no token\n");
    if (len <= 400) return;
    for (i = 5; i <= len; i++)
    {
        if (i == 5) st = asc(&c, &have, tok, 5, out, &ol);
        else st = asc(&c, &have, tok + i - 1, 1, out, &ol);
        if (i < len)
        {
            if (st != SEC_I_CONTINUE_NEEDED || ol) { ok(0, "byte %lu of %lu: 0x%08lx, %lu bytes of output\n", i, len, (unsigned long)st, ol); break; }
        }
    }
    ok(st == SEC_I_CONTINUE_NEEDED && ol > 20 && out[0] == 0xa1, "the last byte: 0x%08lx, %lu bytes of output\n",
       (unsigned long)st, ol);
    if (have) DeleteSecurityContext(&c);
}

START_TEST(NegotiatePending)
{
    TimeStamp ts;
    SECURITY_STATUS st;

    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &g_sc,
                                   &ts);
    ok(st == SEC_E_OK, "inbound credentials: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_E_OK) return;
    test_limit();
    test_bytewise();
    test_hold();
    test_refused_frees();
    test_abandon();
    FreeCredentialsHandle(&g_sc);
}
