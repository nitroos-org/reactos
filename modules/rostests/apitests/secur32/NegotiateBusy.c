/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     One Negotiate context used from several threads at once. SSPI wants calls on one context serialised,
 *              so this is a caller's mistake; the package must still fail safely: no crash, no memory corruption, no
 *              two calls inside one context together. A call that finds the context busy fails with
 *              SEC_E_INVALID_HANDLE. What Windows returns for it was not measured: VERIFY ON PEER (the value is
 *              isolated in BUSY_STATUS below, the rows accept it as the only failure of a call that lost the race).
 *
 *              Rows: 4 threads for a few seconds (SECUR32_STRESS_SECONDS in the environment sets the time: the gate
 *              runs 60 s under page heap) on (a) the server context of a finished SPNEGO exchange and of a finished raw
 *              NTLM exchange: signing and sealing take unique sequence numbers, verification of random signatures
 *              never succeeds, every other call ends in a status of its own or the busy status; (b) a server context
 *              in the middle of reassembling a token: pieces and whole tokens from all threads.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windef.h>
#include <winbase.h>
#include <lmaccess.h>
#include <lmerr.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <security.h>

#define TEST_PASSWORD L"Busy#Test1pw"
#define MAXT 8192
#define THREADS 4
#define SEQ_SLOTS (1 << 20)

/* the status of a call that found the context in use by another call (not measured on Windows: VERIFY ON PEER) */
static const SECURITY_STATUS BUSY_STATUS = SEC_E_INVALID_HANDLE;

static WCHAR g_user[32];

static BOOL create_user(void)
{
    USER_INFO_1 ui;
    DWORD err;
    NET_API_STATUS st;

    _snwprintf(g_user, ARRAYSIZE(g_user), L"busy%lu", GetCurrentProcessId() % 100000);
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

typedef struct
{
    CredHandle cc, sc;
    CtxtHandle cctx, sctx;
    BOOL hc, hs, hcred;
} pair_t;

static void pair_free(pair_t *p)
{
    if (p->hc) DeleteSecurityContext(&p->cctx);
    if (p->hs) DeleteSecurityContext(&p->sctx);
    if (p->hcred)
    {
        FreeCredentialsHandle(&p->cc);
        FreeCredentialsHandle(&p->sc);
    }
    memset(p, 0, sizeof(*p));
}

static SECURITY_STATUS leg(pair_t *p, BOOL server, const BYTE *in, ULONG in_len, BOOL with_in, BYTE *out, ULONG *out_len)
{
    SecBuffer ib = { in_len, SECBUFFER_TOKEN, (void *)in }, ob = { MAXT, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    TimeStamp ts;
    ULONG attr;
    SECURITY_STATUS st;

    if (server)
    {
        st = AcceptSecurityContext(&p->sc, p->hs ? &p->sctx : NULL, with_in ? &id : NULL,
                                   ASC_REQ_CONNECTION | ASC_REQ_INTEGRITY | ASC_REQ_CONFIDENTIALITY,
                                   SECURITY_NATIVE_DREP, &p->sctx, &od, &attr, &ts);
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) p->hs = TRUE;
    }
    else
    {
        st = InitializeSecurityContextW(&p->cc, p->hc ? &p->cctx : NULL, (SEC_WCHAR *)L"cifs/localhost",
                                        ISC_REQ_CONNECTION | ISC_REQ_INTEGRITY | ISC_REQ_CONFIDENTIALITY, 0,
                                        SECURITY_NATIVE_DREP, with_in ? &id : NULL, 0, &p->cctx, &od, &attr, &ts);
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) p->hc = TRUE;
    }
    *out_len = (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) ? ob.cbBuffer : 0;
    return st;
}

/* a finished exchange: with the server's hint SPNEGO, without it raw NTLM (explicit credentials) */
static BOOL pair_make(BOOL spnego, pair_t *p)
{
    SEC_WINNT_AUTH_IDENTITY_W id;
    TimeStamp ts;
    BYTE a[MAXT], b[MAXT];
    ULONG al = 0, bl = 0, i;
    SECURITY_STATUS cs = SEC_I_CONTINUE_NEEDED, ss = SEC_I_CONTINUE_NEEDED;
    BOOL have_in = FALSE, server = FALSE;

    memset(p, 0, sizeof(*p));
    memset(&id, 0, sizeof(id));
    id.User = (unsigned short *)g_user; id.UserLength = (ULONG)wcslen(g_user);
    id.Domain = (unsigned short *)L"."; id.DomainLength = 1;
    id.Password = (unsigned short *)TEST_PASSWORD; id.PasswordLength = (ULONG)wcslen(TEST_PASSWORD);
    id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    if (AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_OUTBOUND, NULL, &id, NULL, NULL, &p->cc, &ts))
        return FALSE;
    if (AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &p->sc, &ts))
    {
        FreeCredentialsHandle(&p->cc);
        return FALSE;
    }
    p->hcred = TRUE;
    if (spnego)
    {
        pair_t h = *p;

        h.hs = FALSE;
        ss = leg(&h, TRUE, NULL, 0, FALSE, a, &al);                   /* the hint comes from a context of its own */
        if (h.hs) DeleteSecurityContext(&h.sctx);
        if (ss != SEC_I_CONTINUE_NEEDED || !al) return FALSE;
        have_in = TRUE;
        ss = SEC_I_CONTINUE_NEEDED;
    }
    for (i = 0; i < 8 && !(cs == SEC_E_OK && ss == SEC_E_OK); i++)
    {
        SECURITY_STATUS st;

        if (server)
            st = leg(p, TRUE, a, al, have_in, b, &bl);
        else
            st = leg(p, FALSE, a, al, have_in, b, &bl);
        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) return FALSE;
        if (server) ss = st; else cs = st;
        memcpy(a, b, bl); al = bl; have_in = bl != 0;
        server = !server;
    }
    return cs == SEC_E_OK && ss == SEC_E_OK;
}

/* ---------------------------------------------------------------------------------------------------------------- */
static volatile LONG g_stop;
static volatile LONG g_seq_seen[SEQ_SLOTS];
static volatile LONG g_dups, g_bad_status, g_signed;
static ULONGLONG g_busy, g_calls;       /* summed from the threads' own counters when they are done */

typedef struct
{
    CtxtHandle *ctx;
    CredHandle *cred;
    BOOL server;
    ULONGLONG calls, busy;      /* the thread's own counts (a minute of calls is more than 2^31) */
    int id;
    int mode;                   /* 0: a finished exchange, 1: a context that reassembles tokens */
    const BYTE *tok;            /* mode 1: a token and its length */
    ULONG tok_len;
} worker_t;

static ULONG rnd(ULONG *s)
{
    *s = *s * 1664525u + 1013904223u;
    return *s >> 8;
}

#define note(st, allowed, n, what) note_(w, st, allowed, n, what)

static void note_(worker_t *w, SECURITY_STATUS st, const SECURITY_STATUS *allowed, int n, const char *what)
{
    int i;

    w->calls++;
    if (st == BUSY_STATUS) w->busy++;
    for (i = 0; i < n; i++)
        if (st == allowed[i]) return;
    if (st == BUSY_STATUS) return;
    InterlockedIncrement(&g_bad_status);
    if (g_bad_status < 10) trace("%s: unexpected status 0x%08lx\n", what, (unsigned long)st);
}

static void record_sequence(const BYTE *sig)
{
    ULONG seq = sig[12] | (sig[13] << 8) | (sig[14] << 16) | ((ULONG)sig[15] << 24);

    InterlockedIncrement(&g_signed);
    if (seq < SEQ_SLOTS && InterlockedExchange(&g_seq_seen[seq], 1)) InterlockedIncrement(&g_dups);
}

static DWORD WINAPI finished_worker(void *arg)
{
    worker_t *w = arg;
    ULONG seed = 12345 + w->id * 7919, n;
    static const SECURITY_STATUS ok_only[] = { SEC_E_OK };
    static const SECURITY_STATUS verify_fail[] = { SEC_E_INVALID_TOKEN, SEC_E_MESSAGE_ALTERED, SEC_E_OUT_OF_SEQUENCE };
    static const SECURITY_STATUS any_asc[] = { SEC_E_INVALID_TOKEN, SEC_E_OUT_OF_SEQUENCE, SEC_E_INVALID_HANDLE,
                                               SEC_E_UNSUPPORTED_FUNCTION, SEC_E_NO_IMPERSONATION };

    while (!g_stop)
    {
        BYTE data[40], sig[64];
        SecBuffer b[2];
        SecBufferDesc d = { SECBUFFER_VERSION, 2, b };
        SECURITY_STATUS st;
        ULONG qop = 0;

        n = rnd(&seed) % 9;
        memset(data, 'a' + w->id, sizeof(data));
        b[0].BufferType = SECBUFFER_DATA; b[0].pvBuffer = data; b[0].cbBuffer = sizeof(data);
        b[1].BufferType = SECBUFFER_TOKEN; b[1].pvBuffer = sig; b[1].cbBuffer = sizeof(sig);
        switch (n)
        {
        case 0:
        case 1:
            memset(sig, 0, sizeof(sig));
            st = MakeSignature(w->ctx, 0, &d, 0);
            note(st, ok_only, 1, "MakeSignature");
            if (st == SEC_E_OK) record_sequence(sig);
            break;
        case 2:
            memset(sig, 0, sizeof(sig));
            st = EncryptMessage(w->ctx, 0, &d, 0);
            note(st, ok_only, 1, "EncryptMessage");
            if (st == SEC_E_OK) record_sequence(b[1].pvBuffer);
            break;
        case 3:
        {
            ULONG k;

            for (k = 0; k < 16; k++) sig[k] = (BYTE)rnd(&seed);
            sig[0] = 1; sig[1] = sig[2] = sig[3] = 0;
            b[1].cbBuffer = 16;
            st = VerifySignature(w->ctx, &d, 0, &qop);
            note(st, verify_fail, 3, "VerifySignature");
            break;
        }
        case 4:
        {
            ULONG k;

            for (k = 0; k < 16; k++) sig[k] = (BYTE)rnd(&seed);
            sig[0] = 1; sig[1] = sig[2] = sig[3] = 0;
            b[1].cbBuffer = 16;
            st = DecryptMessage(w->ctx, &d, 0, &qop);
            note(st, verify_fail, 3, "DecryptMessage");
            break;
        }
        case 5:
        {
            SecPkgContext_Sizes sz;

            st = QueryContextAttributesW(w->ctx, SECPKG_ATTR_SIZES, &sz);
            note(st, ok_only, 1, "QueryContextAttributes(SIZES)");
            break;
        }
        case 6:
        {
            SecPkgContext_NegotiationInfoW ni;

            st = QueryContextAttributesW(w->ctx, SECPKG_ATTR_NEGOTIATION_INFO, &ni);
            note(st, ok_only, 1, "QueryContextAttributes(NEGOTIATION_INFO)");
            if (st == SEC_E_OK) FreeContextBuffer(ni.PackageInfo);
            break;
        }
        case 7:
        {
            if (w->server)
            {
                st = ImpersonateSecurityContext(w->ctx);
                note(st, ok_only, 1, "ImpersonateSecurityContext");
                if (st == SEC_E_OK)
                {
                    /* RevertSecurityContext may find the context busy: the thread must not stay the user */
                    if (RevertSecurityContext(w->ctx) != SEC_E_OK) RevertToSelf();
                }
            }
            else
            {
                SecPkgContext_SessionKey sk;

                st = QueryContextAttributesW(w->ctx, SECPKG_ATTR_SESSION_KEY, &sk);
                note(st, ok_only, 1, "QueryContextAttributes(SESSION_KEY)");
                if (st == SEC_E_OK) FreeContextBuffer(sk.SessionKey);
            }
            break;
        }
        default:
        {
            /* a token on a context whose exchange is over */
            BYTE junk[64], out[256];
            SecBuffer ib = { sizeof(junk), SECBUFFER_TOKEN, junk }, ob = { sizeof(out), SECBUFFER_TOKEN, out };
            SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
            TimeStamp ts;
            ULONG attr;

            memset(junk, 0x41, sizeof(junk));
            if (w->server)
                st = AcceptSecurityContext(w->cred, w->ctx, &id, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, w->ctx, &od,
                                           &attr, &ts);
            else
                st = InitializeSecurityContextW(w->cred, w->ctx, (SEC_WCHAR *)L"cifs/localhost", ISC_REQ_CONNECTION, 0,
                                                SECURITY_NATIVE_DREP, &id, 0, w->ctx, &od, &attr, &ts);
            note(st, any_asc, 5, "token after the exchange");
            break;
        }
        }
    }
    return 0;
}

/* a server context that reassembles: pieces of a NegTokenInit header, whole tokens, garbage; all threads on the one
 * context (the busy status or a status of the token, never a crash) */
static DWORD WINAPI pending_worker(void *arg)
{
    worker_t *w = arg;
    ULONG seed = 777 + w->id * 104729, n;
    static const SECURITY_STATUS any[] = { SEC_E_INVALID_TOKEN, SEC_I_CONTINUE_NEEDED, SEC_E_INVALID_HANDLE,
                                           SEC_E_OUT_OF_SEQUENCE, SEC_E_LOGON_DENIED, SEC_E_INTERNAL_ERROR,
                                           SEC_E_OK };
    BYTE big[MAXT], out[MAXT];

    memset(big, 0x5a, sizeof(big));
    while (!g_stop)
    {
        const BYTE *in;
        ULONG len;
        SecBuffer ib, ob = { MAXT, SECBUFFER_TOKEN, out };
        SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
        TimeStamp ts;
        ULONG attr;
        SECURITY_STATUS st;

        n = rnd(&seed) % 6;
        if (n == 0) { in = w->tok; len = w->tok_len; }                                  /* the whole token */
        else if (n == 1) { in = w->tok; len = 3 + rnd(&seed) % (w->tok_len - 3); }      /* the first piece */
        else if (n == 2) { in = w->tok + 20; len = 1 + rnd(&seed) % (w->tok_len - 20); } /* a middle piece */
        else if (n == 3)
        {
            /* a header that announces much, with a little content */
            big[0] = 0x60; big[1] = 0x82; big[2] = 0xbb; big[3] = 0x00;
            in = big; len = 4 + rnd(&seed) % 200;
        }
        else if (n == 4) { in = big + 4; len = 1 + rnd(&seed) % 4000; }                 /* bytes of any token */
        else { in = w->tok + 4; len = 1 + rnd(&seed) % 8; }
        ib.BufferType = SECBUFFER_TOKEN; ib.pvBuffer = (void *)in; ib.cbBuffer = len;
        ob.cbBuffer = MAXT;
        st = AcceptSecurityContext(w->cred, w->ctx, &id, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, w->ctx, &od, &attr, &ts);
        note(st, any, 7, "AcceptSecurityContext (pieces)");
    }
    return 0;
}

/* a fault in the middle of a run (page heap stops at the first bad access): say where, with the phase */
static const char *g_phase = "start";
static char g_phase_buf[96];

static LONG WINAPI fault_filter(EXCEPTION_POINTERS *e)
{
    printf("NegotiateBusy: EXCEPTION 0x%08lx at %p, information %p %p, phase: %s\n",
           (unsigned long)e->ExceptionRecord->ExceptionCode, e->ExceptionRecord->ExceptionAddress,
           (void *)e->ExceptionRecord->ExceptionInformation[0], (void *)e->ExceptionRecord->ExceptionInformation[1],
           g_phase);
    fflush(stdout);
    return EXCEPTION_CONTINUE_SEARCH;
}

static ULONG stress_seconds(void)
{
    char buf[16];
    DWORD n = GetEnvironmentVariableA("SECUR32_STRESS_SECONDS", buf, sizeof(buf));

    if (n && n < sizeof(buf)) return (ULONG)strtoul(buf, NULL, 10);
    return 3;
}

static void run_threads(worker_t *w, LPTHREAD_START_ROUTINE fn, ULONG seconds)
{
    HANDLE th[THREADS];
    int i;

    g_stop = 0;
    for (i = 0; i < THREADS; i++)
    {
        w[i].id = i;
        th[i] = CreateThread(NULL, 0, fn, &w[i], 0, NULL);
        ok(th[i] != NULL, "CreateThread %d\n", i);
    }
    Sleep(seconds * 1000);
    g_stop = 1;
    g_calls = g_busy = 0;
    for (i = 0; i < THREADS; i++)
        if (th[i])
        {
            WaitForSingleObject(th[i], INFINITE);
            CloseHandle(th[i]);
            g_calls += w[i].calls;
            g_busy += w[i].busy;
        }
}

static void test_finished(BOOL spnego, BOOL server_side, ULONG seconds)
{
    pair_t p;
    worker_t w[THREADS];
    CtxtHandle *target;
    BYTE data[40], sig[64];
    SecBuffer b[2];
    SecBufferDesc d = { SECBUFFER_VERSION, 2, b };
    SECURITY_STATUS st;
    ULONG seq, i;
    const char *what = spnego ? (server_side ? "SPNEGO server" : "SPNEGO client")
                              : (server_side ? "raw NTLM server" : "raw NTLM client");

    if (!pair_make(spnego, &p))
    {
        ok(0, "%s: the exchange did not finish\n", what);
        pair_free(&p);
        return;
    }
    target = server_side ? &p.sctx : &p.cctx;
    for (i = 0; i < SEQ_SLOTS; i++) g_seq_seen[i] = 0;
    g_dups = g_bad_status = g_signed = 0;
    memset(w, 0, sizeof(w));
    for (i = 0; i < THREADS; i++)
    {
        w[i].ctx = target;
        w[i].cred = server_side ? &p.sc : &p.cc;
        w[i].server = server_side;
        w[i].mode = 0;
    }
    sprintf(g_phase_buf, "%s: the threads", what);
    g_phase = g_phase_buf;
    run_threads(w, finished_worker, seconds);
    sprintf(g_phase_buf, "%s: after the threads", what);
    trace("%s: %I64u calls, %ld signed or sealed, %I64u found the context busy\n", what, g_calls, g_signed, g_busy);
    ok(g_calls > 0, "%s: no call ran\n", what);
    ok(g_dups == 0, "%s: %ld sequence numbers used twice\n", what, g_dups);
    ok(g_bad_status == 0, "%s: %ld calls with a status that is neither the call's own nor the busy status\n", what,
       g_bad_status);

    /* the context is still whole: the next signature carries the next sequence number, in step with the peer */
    memset(data, 'z', sizeof(data));
    b[0].BufferType = SECBUFFER_DATA; b[0].pvBuffer = data; b[0].cbBuffer = sizeof(data);
    b[1].BufferType = SECBUFFER_TOKEN; b[1].pvBuffer = sig; b[1].cbBuffer = sizeof(sig);
    st = MakeSignature(target, 0, &d, 0);
    ok(st == SEC_E_OK, "%s: MakeSignature after the threads: 0x%08lx\n", what, (unsigned long)st);
    if (st == SEC_E_OK && g_signed < SEQ_SLOTS - 2)
    {
        seq = sig[12] | (sig[13] << 8) | (sig[14] << 16) | ((ULONG)sig[15] << 24);
        ok(seq >= (ULONG)g_signed, "%s: sequence %lu after %ld signed or sealed messages\n", what, seq, g_signed);
    }
    sprintf(g_phase_buf, "%s: DeleteSecurityContext", what);
    pair_free(&p);
}

/* NegTokenInit with a 300-byte mechToken of zeros (a token that is kept in pieces and then refused by NTLM) */
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

static ULONG mk_token(BYTE *out)
{
    static const BYTE oid_ntlm[] = { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
    static const BYTE oid_spnego[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
    BYTE list[32], seq[600], a[600], b[600], ntlm[296];
    ULONG n = 0, k, m;

    memset(ntlm, 0, sizeof(ntlm));
    memcpy(ntlm, "NTLMSSP\0\1\0\0\0", 12);
    k = put(list, 0x06, oid_ntlm, sizeof(oid_ntlm));
    k = put(a, 0x30, list, k);
    n += put(seq + n, 0xa0, a, k);
    k = put(a, 0x04, ntlm, sizeof(ntlm));
    n += put(seq + n, 0xa2, a, k);
    k = put(a, 0x30, seq, n);
    k = put(b, 0xa0, a, k);
    m = put(a, 0x06, oid_spnego, sizeof(oid_spnego));
    memcpy(a + m, b, k);
    return put(out, 0x60, a, m + k);
}

static void test_pending(ULONG seconds)
{
    CredHandle sc;
    CtxtHandle ctx;
    TimeStamp ts;
    BYTE tok[1024], out[MAXT];
    ULONG len = mk_token(tok), attr, i;
    SecBuffer ib = { 4, SECBUFFER_TOKEN, tok }, ob = { MAXT, SECBUFFER_TOKEN, out };
    SecBufferDesc id = { SECBUFFER_VERSION, 1, &ib }, od = { SECBUFFER_VERSION, 1, &ob };
    SECURITY_STATUS st;
    worker_t w[THREADS];

    st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR *)L"Negotiate", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &sc, &ts);
    ok(st == SEC_E_OK, "inbound credentials: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_E_OK) return;
    /* the first four bytes of the token: a header and one byte of content: the context keeps them */
    ib.cbBuffer = 5;
    st = AcceptSecurityContext(&sc, NULL, &id, ASC_REQ_CONNECTION, SECURITY_NATIVE_DREP, &ctx, &od, &attr, &ts);
    ok(st == SEC_I_CONTINUE_NEEDED, "first piece: 0x%08lx\n", (unsigned long)st);
    if (st != SEC_I_CONTINUE_NEEDED) { FreeCredentialsHandle(&sc); return; }

    g_dups = g_bad_status = g_signed = 0;
    memset(w, 0, sizeof(w));
    for (i = 0; i < THREADS; i++)
    {
        w[i].ctx = &ctx;
        w[i].cred = &sc;
        w[i].server = TRUE;
        w[i].mode = 1;
        w[i].tok = tok;
        w[i].tok_len = len;
    }
    g_phase = "pending context: the threads";
    run_threads(w, pending_worker, seconds);
    g_phase = "pending context: after the threads";
    trace("pending context: %I64u calls, %I64u found the context busy\n", g_calls, g_busy);
    ok(g_calls > 0, "pending context: no call ran\n");
    ok(g_bad_status == 0, "pending context: %ld calls with an unexpected status\n", g_bad_status);
    DeleteSecurityContext(&ctx);
    FreeCredentialsHandle(&sc);
}

START_TEST(NegotiateBusy)
{
    ULONG seconds = stress_seconds();

    SetUnhandledExceptionFilter(fault_filter);
    if (!create_user()) return;
    test_finished(TRUE, TRUE, seconds);
    test_finished(TRUE, FALSE, seconds);
    test_finished(FALSE, TRUE, seconds);
    test_finished(FALSE, FALSE, seconds);
    test_pending(seconds);
    NetUserDel(NULL, g_user);
}
