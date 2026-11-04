/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     proto
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * PROJECT:     ReactOS test infrastructure
 * PURPOSE:     rosdev: wire format. A message is one text line "VERB key=value ...\n" with
 *              percent-encoded values, optionally followed by len=N raw body bytes.
 */
#include "rosdev.h"

/* Fills the buffer when empty; FALSE on close, error or a silence longer than waitMs. */
static BOOL Fill(CONN *c, DWORD waitMs)
{
    fd_set rf;
    struct timeval tv;
    int r;

    if (c->pos < c->len) return TRUE;
    if (c->dead) return FALSE;
    FD_ZERO(&rf);
    FD_SET(c->s, &rf);
    tv.tv_sec = waitMs / 1000;
    tv.tv_usec = (waitMs % 1000) * 1000;
    r = select(0, &rf, NULL, NULL, &tv);
    if (r <= 0) { c->dead = TRUE; return FALSE; }
    r = recv(c->s, (char *)c->buf, sizeof(c->buf), 0);
    if (r <= 0) { c->dead = TRUE; return FALSE; }
    c->pos = 0;
    c->len = r;
    return TRUE;
}

BOOL ConnReadSome(CONN *c, void *dst, int max, int *got, DWORD waitMs)
{
    int n;
    if (!Fill(c, waitMs)) return FALSE;
    n = c->len - c->pos;
    if (n > max) n = max;
    memcpy(dst, c->buf + c->pos, n);
    c->pos += n;
    *got = n;
    return TRUE;
}

BOOL ConnRead(CONN *c, void *dst, int n, DWORD waitMs)
{
    BYTE *p = dst;
    while (n > 0)
    {
        int got;
        if (!ConnReadSome(c, p, n, &got, waitMs)) return FALSE;
        p += got; n -= got;
    }
    return TRUE;
}

BOOL ConnWrite(CONN *c, const void *p, int n)
{
    const char *b = p;
    while (n > 0)
    {
        int r = send(c->s, b, n > 32768 ? 32768 : n, 0);
        if (r <= 0) { c->dead = TRUE; return FALSE; }
        b += r; n -= r;
    }
    return TRUE;
}

static int Hex1(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static void Unescape(char *s)
{
    char *o = s;
    while (*s)
    {
        if (s[0] == '%' && Hex1(s[1]) >= 0 && Hex1(s[2]) >= 0) { *o++ = (char)(Hex1(s[1]) << 4 | Hex1(s[2])); s += 3; }
        else *o++ = *s++;
    }
    *o = 0;
}

BOOL RecvMsg(CONN *c, RMSG *m, DWORD waitMs)
{
    int n = 0;
    char *p, *tok;

    for (;;)
    {
        char ch;
        if (!ConnRead(c, &ch, 1, waitMs)) return FALSE;
        if (ch == '\n') break;
        if (n >= MAX_HDR - 1) { c->dead = TRUE; return FALSE; }
        m->raw[n++] = ch;
    }
    m->raw[n] = 0;
    m->n = 0;
    p = m->raw;
    tok = p;
    while (*p && *p != ' ') p++;
    if (*p) *p++ = 0;
    if (strlen(tok) >= sizeof(m->verb)) { c->dead = TRUE; return FALSE; }
    strcpy(m->verb, tok);
    while (*p)
    {
        char *eq;
        tok = p;
        while (*p && *p != ' ') p++;
        if (*p) *p++ = 0;
        eq = strchr(tok, '=');
        if (!eq || m->n >= MAX_KV) continue;
        *eq = 0;
        m->kv[m->n].key = tok;
        m->kv[m->n].val = eq + 1;
        Unescape(eq + 1);
        m->n++;
    }
    return TRUE;
}

const char *MsgGet(const RMSG *m, const char *key)
{
    int i;
    for (i = 0; i < m->n; i++)
        if (!strcmp(m->kv[i].key, key)) return m->kv[i].val;
    return NULL;
}

/* Strict decimal parse: FALSE when the key is missing, empty, not a number or does not fit in 64 bits. */
BOOL MsgGetU64Ex(const RMSG *m, const char *key, UINT64 *out)
{
    const char *v = MsgGet(m, key);
    UINT64 r = 0;
    if (!v || !*v) return FALSE;
    for (; *v; v++)
    {
        UINT d;
        if (*v < '0' || *v > '9') return FALSE;
        d = (UINT)(*v - '0');
        if (r > (~(UINT64)0 - d) / 10) return FALSE;
        r = r * 10 + d;
    }
    *out = r;
    return TRUE;
}

UINT64 MsgGetU64(const RMSG *m, const char *key, UINT64 def)
{
    UINT64 r;
    return MsgGetU64Ex(m, key, &r) ? r : def;
}

static void Put(REPLY *r, const char *s)
{
    int n = (int)strlen(s);
    if (r->len + n >= (int)sizeof(r->buf) - 2) { r->over = TRUE; return; }
    memcpy(r->buf + r->len, s, n);
    r->len += n;
}

void ReplyInit(REPLY *r, const char *verb)
{
    r->len = 0;
    r->over = FALSE;
    Put(r, verb);
}

void ReplyStr(REPLY *r, const char *key, const char *val)
{
    char tmp[4];
    Put(r, " ");
    Put(r, key);
    Put(r, "=");
    for (; *val; val++)
    {
        BYTE b = (BYTE)*val;
        if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
            b == '.' || b == '_' || b == '~' || b == '-')
        {
            tmp[0] = (char)b; tmp[1] = 0;
        }
        else _snprintf(tmp, sizeof(tmp), "%%%02X", b);
        Put(r, tmp);
    }
}

void ReplyU64(REPLY *r, const char *key, UINT64 v)
{
    char tmp[32];
    _snprintf(tmp, sizeof(tmp), "%I64u", v);
    ReplyStr(r, key, tmp);
}

void ReplyWide(REPLY *r, const char *key, const WCHAR *w)
{
    char *u = WideToUtf8(w);
    ReplyStr(r, key, u ? u : "");
    if (u) HeapFree(GetProcessHeap(), 0, u);
}

BOOL ReplySend(CONN *c, REPLY *r)
{
    if (r->over) return FALSE;
    r->buf[r->len++] = '\n';
    return ConnWrite(c, r->buf, r->len);
}

char *WideToUtf8(const WCHAR *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s;
    if (n <= 0) return NULL;
    s = HeapAlloc(GetProcessHeap(), 0, n);
    if (s) WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

WCHAR *Utf8ToWide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR *w;
    if (n <= 0) return NULL;
    w = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}
