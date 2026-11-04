/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     jobs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * PROJECT:     ReactOS test infrastructure
 * PURPOSE:     rosdev: the job handlers. One job at a time; every job ends in one RESULT message.
 */
#include "rosdev.h"
#include <tlhelp32.h>

#define XFER_BLOCK      65536
#define MAX_CAPTURE     (16 * 1024 * 1024)

BOOL g_Quit;
BOOL g_PowerPending;
WCHAR g_Args[512];
static UINT KillTree(DWORD pid, UINT *failed, int depth);
static WCHAR g_LogPath[MAX_PATH];

typedef struct { char *p; SIZE_T len, cap; BOOL failed; DWORD err; } BUF;

static void BufAppend(BUF *b, const void *data, SIZE_T n)
{
    if (b->len + n + 1 > b->cap)
    {
        SIZE_T cap = b->cap ? b->cap : 4096;
        char *np;
        while (cap < b->len + n + 1) cap *= 2;
        np = b->p ? HeapReAlloc(GetProcessHeap(), 0, b->p, cap) : HeapAlloc(GetProcessHeap(), 0, cap);
        if (!np) { b->failed = TRUE; return; }
        b->p = np;
        b->cap = cap;
    }
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = 0;
}

static void BufStr(BUF *b, const char *s) { BufAppend(b, s, strlen(s)); }

static void BufWide(BUF *b, const WCHAR *w)
{
    char *u = WideToUtf8(w);
    if (!u) { b->failed = TRUE; return; }   /* conversion or allocation failed: the text must not come back short */
    BufStr(b, u);
    HeapFree(GetProcessHeap(), 0, u);
}

static void BufPrintf(BUF *b, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(tmp, sizeof(tmp) - 1, fmt, ap);
    va_end(ap);
    tmp[sizeof(tmp) - 1] = 0;
    BufStr(b, tmp);
}

/* The listing cannot be complete: the job ends in an error result instead of returning a prefix. */
static void BufFail(BUF *b, DWORD e)
{
    b->failed = TRUE;
    if (!b->err) b->err = e ? e : ERROR_GEN_FAILURE;
}

static void BufFree(BUF *b)
{
    if (b->p) HeapFree(GetProcessHeap(), 0, b->p);
    b->p = NULL; b->len = b->cap = 0;
}

void LogLine(const char *fmt, ...)
{
    char line[600], ts[40], out[700];
    SYSTEMTIME st;
    va_list ap;
    HANDLE h;
    DWORD w;
    LARGE_INTEGER sz;

    va_start(ap, fmt);
    _vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 1] = 0;
    GetSystemTime(&st);
    _snprintf(ts, sizeof(ts), "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    _snprintf(out, sizeof(out), "%s %s\r\n", ts, line);
    OutputDebugStringA("rosdev: ");
    OutputDebugStringA(out);
    if (!g_LogPath[0])
    {
        WCHAR *slash;
        if (!GetModuleFileNameW(NULL, g_LogPath, MAX_PATH)) return;
        slash = wcsrchr(g_LogPath, L'\\');
        if (!slash) { g_LogPath[0] = 0; return; }
        wcscpy(slash + 1, L"rosdev.log");
    }
    h = CreateFileW(g_LogPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 1024 * 1024) SetEndOfFile(h);
    else SetFilePointer(h, 0, NULL, FILE_END);
    WriteFile(h, out, (DWORD)strlen(out), &w, NULL);
    CloseHandle(h);
}

/* ---- result helpers ---- */

static void ResultErr(REPLY *r, UINT64 id, DWORD code, const char *what)
{
    ReplyInit(r, "RESULT");
    ReplyU64(r, "id", id);
    ReplyStr(r, "status", "err");
    ReplyU64(r, "code", code);
    ReplyStr(r, "msg", what);
}

static void ResultOk(REPLY *r, UINT64 id)
{
    ReplyInit(r, "RESULT");
    ReplyU64(r, "id", id);
    ReplyStr(r, "status", "ok");
}

/* Sends the header (len=total body size), the body in up to two parts, then waits for the host's ACK. */
static BOOL Finish2(CONN *c, REPLY *r, const void *body1, UINT64 len1, const void *body2, UINT64 len2)
{
    RMSG ack;
    if (len1 + len2) ReplyU64(r, "len", len1 + len2);
    if (!ReplySend(c, r)) return FALSE;
    if (len1 && !ConnWrite(c, body1, (int)len1)) return FALSE;
    if (len2 && !ConnWrite(c, body2, (int)len2)) return FALSE;
    return RecvMsg(c, &ack, IO_WAIT) && !strcmp(ack.verb, "ACK");
}

static BOOL Finish(CONN *c, REPLY *r, const void *body, UINT64 bodyLen)
{
    return Finish2(c, r, body, bodyLen, NULL, 0);
}

static BOOL FinishErr(CONN *c, UINT64 id, DWORD code, const char *what);

/* A text result: an allocation failure while building it is an error, never a silently short text. */
static BOOL FinishText(CONN *c, UINT64 id, REPLY *r, const BUF *b)
{
    if (b->failed) return FinishErr(c, id, b->err ? b->err : ERROR_OUTOFMEMORY, "the output could not be built completely (out of memory or enumeration error)");
    return Finish(c, r, b->p, b->len);
}

static BOOL FinishErr(CONN *c, UINT64 id, DWORD code, const char *what)
{
    REPLY r;
    ResultErr(&r, id, code, what);
    return Finish(c, &r, NULL, 0);
}

static void ToHex(const BYTE *d, char *out) { HexEncode(d, 32, out); }

static void MakeDirs(WCHAR *path)
{
    WCHAR *p;
    if (!path[0]) return;
    for (p = path + 1; *p; p++)
    {
        if (*p != L'\\' && *p != L'/') continue;
        if (p[-1] == L':') continue;
        *p = 0;
        CreateDirectoryW(path, NULL);
        *p = L'\\';
    }
}

/* ---- put ---- */

static BOOL DoPut(CONN *c, const RMSG *j, UINT64 id)
{
    const char *path = MsgGet(j, "path"), *want = MsgGet(j, "sha256"), *mode = MsgGet(j, "mode");
    UINT64 len = 0, left, total = 0;
    BOOL stage = mode && !strcmp(mode, "stage");
    WCHAR *wpath, *tmp = NULL;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD err = 0;
    const char *what = NULL;
    SHA256_STATE sha;
    BYTE digest[32];
    char hex[65];
    BYTE *blk = HeapAlloc(GetProcessHeap(), 0, XFER_BLOCK);
    REPLY r;
    const char *how = "replaced";
    BOOL ok = TRUE;

    /* without a valid length the body size is unknown, so the connection cannot be kept in step */
    if (!MsgGetU64Ex(j, "len", &len) || !blk)
    {
        if (blk) HeapFree(GetProcessHeap(), 0, blk);
        return FALSE;
    }
    left = len;
    wpath = path && *path ? Utf8ToWide(path) : NULL;
    Sha256Init(&sha);
    if (!wpath || !wpath[0] || !want || wcslen(wpath) > MAX_PATH - 20)
    {
        err = ERROR_INVALID_PARAMETER; what = "bad path or sha256";
    }
    else if (!(tmp = HeapAlloc(GetProcessHeap(), 0, (wcslen(wpath) + 16) * sizeof(WCHAR))))
    {
        err = ERROR_OUTOFMEMORY; what = "out of memory";
    }
    else
    {
        wcscpy(tmp, wpath);
        wcscat(tmp, L".rosdev-tmp");
        MakeDirs(wpath);
        h = CreateFileW(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) { err = GetLastError(); what = "cannot create the temporary file"; }
    }

    /* the whole body is always consumed so the stream stays in step */
    while (left)
    {
        int got;
        if (!ConnReadSome(c, blk, left > XFER_BLOCK ? XFER_BLOCK : (int)left, &got, IO_WAIT))
        {
            ok = FALSE;
            break;
        }
        left -= got;
        total += got;
        Sha256Update(&sha, blk, got);
        if (h != INVALID_HANDLE_VALUE)
        {
            DWORD w;
            if (!WriteFile(h, blk, got, &w, NULL) || w != (DWORD)got)
            {
                err = GetLastError(); what = "write failed";
                CloseHandle(h); h = INVALID_HANDLE_VALUE;
            }
        }
    }
    if (h != INVALID_HANDLE_VALUE)
    {
        if (ok && !FlushFileBuffers(h) && !what) { err = GetLastError(); what = "flush failed"; }
        CloseHandle(h);
    }
    if (!ok)
    {
        if (tmp) DeleteFileW(tmp);
        goto fail;
    }
    Sha256Final(&sha, digest);
    ToHex(digest, hex);
    if (!what && _stricmp(hex, want))
    {
        err = ERROR_CRC; what = "sha256 mismatch";
    }
    if (!what)
    {
        if (stage)
        {
            WCHAR *staged = HeapAlloc(GetProcessHeap(), 0, (wcslen(wpath) + 16) * sizeof(WCHAR));
            if (!staged) { err = ERROR_OUTOFMEMORY; what = "out of memory"; }
            else
            {
            wcscpy(staged, wpath);
            wcscat(staged, L".rosdev-new");
            if (!MoveFileExW(tmp, staged, MOVEFILE_REPLACE_EXISTING)) { err = GetLastError(); what = "cannot name the staged file"; }
            else if (!MoveFileExW(staged, wpath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT))
            { err = GetLastError(); what = "cannot queue the replacement for reboot"; }
            else how = "staged-for-reboot";
            HeapFree(GetProcessHeap(), 0, staged);
            }
        }
        else if (!MoveFileExW(tmp, wpath, MOVEFILE_REPLACE_EXISTING))
        {
            DWORD e1 = GetLastError();
            if (e1 == ERROR_SHARING_VIOLATION || e1 == ERROR_ACCESS_DENIED || e1 == ERROR_USER_MAPPED_FILE)
            {
                /* a mapped image cannot be overwritten, but it can often be renamed */
                WCHAR *aside = HeapAlloc(GetProcessHeap(), 0, (wcslen(wpath) + 24) * sizeof(WCHAR));
                int n;
                BOOL moved = FALSE;
                for (n = 0; aside && n < 20 && !moved; n++)
                {
                    wcscpy(aside, wpath);
                    wcscat(aside, L".rosdev-old");
                    if (n) _snwprintf(aside + wcslen(aside), 4, L"%d", n);
                    DeleteFileW(aside);
                    if (!MoveFileExW(wpath, aside, 0)) continue;
                    if (MoveFileExW(tmp, wpath, 0)) moved = TRUE;
                    else MoveFileExW(aside, wpath, 0);
                    break;
                }
                if (moved)
                {
                    how = "renamed-aside";
                    if (!DeleteFileW(aside)) MoveFileExW(aside, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                }
                else { err = e1; what = "target is in use and cannot be renamed (try --stage)"; }
                if (aside) HeapFree(GetProcessHeap(), 0, aside);
            }
            else { err = e1; what = "cannot move the file into place"; }
        }
    }
    if (what)
    {
        if (tmp) DeleteFileW(tmp);
        goto fail;
    }
    ResultOk(&r, id);
    ReplyStr(&r, "how", how);
    ReplyU64(&r, "size", total);
    ReplyStr(&r, "sha256", hex);
    ok = Finish(c, &r, NULL, 0);
    goto done;
fail:
    if (ok) ok = FinishErr(c, id, err, what ? what : "transfer failed");
done:
    if (wpath) HeapFree(GetProcessHeap(), 0, wpath);
    if (tmp) HeapFree(GetProcessHeap(), 0, tmp);
    if (blk) HeapFree(GetProcessHeap(), 0, blk);
    return ok;
}

/* ---- get ---- */

static BOOL DoGet(CONN *c, const RMSG *j, UINT64 id)
{
    const char *path = MsgGet(j, "path");
    WCHAR *wpath = path ? Utf8ToWide(path) : NULL;
    HANDLE h;
    LARGE_INTEGER sz;
    SHA256_STATE sha;
    BYTE digest[32];
    char hex[65];
    BYTE *blk;
    DWORD got;
    UINT64 left;
    REPLY r;
    BOOL ok = TRUE;
    RMSG ack;

    if (!wpath) return FinishErr(c, id, ERROR_INVALID_PARAMETER, "bad path");
    h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HeapFree(GetProcessHeap(), 0, wpath);
    if (h == INVALID_HANDLE_VALUE) return FinishErr(c, id, GetLastError(), "cannot open the file");
    if (!GetFileSizeEx(h, &sz)) { DWORD e = GetLastError(); CloseHandle(h); return FinishErr(c, id, e, "cannot get the size"); }
    blk = HeapAlloc(GetProcessHeap(), 0, XFER_BLOCK);
    if (!blk) { CloseHandle(h); return FinishErr(c, id, ERROR_OUTOFMEMORY, "out of memory"); }

    /* pass 1: hash and verified size; pass 2: stream exactly that many bytes */
    Sha256Init(&sha);
    left = 0;
    for (;;)
    {
        if (!ReadFile(h, blk, XFER_BLOCK, &got, NULL))
        {
            DWORD e = GetLastError();
            CloseHandle(h);
            HeapFree(GetProcessHeap(), 0, blk);
            return FinishErr(c, id, e, "read error while hashing");
        }
        if (!got) break;
        Sha256Update(&sha, blk, got);
        left += got;
    }
    Sha256Final(&sha, digest);
    ToHex(digest, hex);
    if (SetFilePointer(h, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
    {
        DWORD e = GetLastError();
        CloseHandle(h);
        HeapFree(GetProcessHeap(), 0, blk);
        return FinishErr(c, id, e, "cannot rewind the file");
    }
    ResultOk(&r, id);
    ReplyStr(&r, "sha256", hex);
    ReplyU64(&r, "size", left);
    ReplyU64(&r, "len", left);
    if (!ReplySend(c, &r)) ok = FALSE;
    while (ok && left)
    {
        DWORD want = left > XFER_BLOCK ? XFER_BLOCK : (DWORD)left;
        if (!ReadFile(h, blk, want, &got, NULL) || got != want || !ConnWrite(c, blk, (int)want))
        {
            ok = FALSE;     /* the file changed under us: drop the connection, the host sees a short body */
            break;
        }
        left -= want;
    }
    CloseHandle(h);
    HeapFree(GetProcessHeap(), 0, blk);
    return ok && RecvMsg(c, &ack, IO_WAIT) && !strcmp(ack.verb, "ACK");
}

/* ---- run ---- */

/* Reads at most maxBytes from each pipe without blocking; TRUE if anything was read. */
static BOOL DrainPipes(HANDLE pipes[2], BUF *dst[2], BOOL *trunc, DWORD maxBytes)
{
    BOOL did = FALSE;
    int i;

    for (i = 0; i < 2; i++)
    {
        DWORD budget = maxBytes, avail;
        while (budget && PeekNamedPipe(pipes[i], NULL, 0, NULL, &avail, NULL) && avail)
        {
            char tmp[4096];
            DWORD got;
            if (!ReadFile(pipes[i], tmp, budget < sizeof(tmp) ? budget : sizeof(tmp), &got, NULL) || !got) break;
            did = TRUE;
            budget -= got;
            if (dst[i]->len + got <= MAX_CAPTURE && !dst[i]->failed) BufAppend(dst[i], tmp, got);
            else *trunc = TRUE;
            if (dst[i]->failed) *trunc = TRUE;
        }
    }
    return did;
}


static BOOL DoRun(CONN *c, const RMSG *j, UINT64 id)
{
    const char *cmd = MsgGet(j, "cmd"), *cwd = MsgGet(j, "cwd");
    DWORD timeoutS = (DWORD)MsgGetU64(j, "timeout", 60);
    BOOL shell = MsgGetU64(j, "shell", 0) != 0, detach = MsgGetU64(j, "detach", 0) != 0;
    WCHAR *wcmd = cmd ? Utf8ToWide(cmd) : NULL, *wcwd = cwd && *cwd ? Utf8ToWide(cwd) : NULL, *line;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE outR = NULL, outW = NULL, errR = NULL, errW = NULL, in = INVALID_HANDLE_VALUE;
    BUF out = { 0 }, err = { 0 };
    DWORD exitCode = 0, start = GetTickCount(), code = 0;
    BOOL timedOut = FALSE, trunc = FALSE, ok = TRUE, created;
    REPLY r;
    SIZE_T n;

    if (!wcmd) { if (wcwd) HeapFree(GetProcessHeap(), 0, wcwd); return FinishErr(c, id, ERROR_INVALID_PARAMETER, "no command"); }
    n = wcslen(wcmd) + 32;
    line = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR));
    if (!line)
    {
        HeapFree(GetProcessHeap(), 0, wcmd);
        if (wcwd) HeapFree(GetProcessHeap(), 0, wcwd);
        return FinishErr(c, id, ERROR_OUTOFMEMORY, "out of memory");
    }
    if (shell) { wcscpy(line, L"cmd.exe /c "); wcscat(line, wcmd); }
    else wcscpy(line, wcmd);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!detach)
    {
        if (!CreatePipe(&outR, &outW, &sa, 0) || !CreatePipe(&errR, &errW, &sa, 0))
        {
            code = GetLastError();
            goto fail;
        }
        SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(errR, HANDLE_FLAG_INHERIT, 0);
        in = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = in;
        si.hStdOutput = outW;
        si.hStdError = errW;
    }
    created = CreateProcessW(NULL, line, NULL, NULL, !detach, detach ? 0 : CREATE_NO_WINDOW, NULL, wcwd, &si, &pi);
    if (!created) { code = GetLastError(); goto fail; }
    if (outW) { CloseHandle(outW); outW = NULL; }
    if (errW) { CloseHandle(errW); errW = NULL; }
    if (in != INVALID_HANDLE_VALUE) { CloseHandle(in); in = INVALID_HANDLE_VALUE; }

    if (detach)
    {
        ResultOk(&r, id);
        ReplyU64(&r, "pid", pi.dwProcessId);
        ReplyStr(&r, "detached", "1");
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        ok = Finish(c, &r, NULL, 0);
        goto done;
    }

    /* poll both pipes without threads: a grandchild that keeps a pipe open cannot hang the job,
       and a chatty child cannot starve the timeout check (each pass reads a bounded amount) */
    for (;;)
    {
        HANDLE pipes[2] = { outR, errR };
        BUF *dst[2] = { &out, &err };
        BOOL did = DrainPipes(pipes, dst, &trunc, 65536);
        DWORD wait;

        if (timeoutS && GetTickCount() - start > timeoutS * 1000)
        {
            UINT failedKills = 0;
            KillTree(pi.dwProcessId, &failedKills, 0);
            timedOut = TRUE;
            WaitForSingleObject(pi.hProcess, 5000);
            break;
        }
        wait = WaitForSingleObject(pi.hProcess, did ? 0 : 20);
        if (wait == WAIT_OBJECT_0) break;
    }
    {
        /* what the process wrote before it ended, at most 1 MiB more */
        HANDLE pipes[2] = { outR, errR };
        BUF *dst[2] = { &out, &err };
        int pass;
        for (pass = 0; pass < 16; pass++)
            if (!DrainPipes(pipes, dst, &trunc, 65536)) break;
    }
    GetExitCodeProcess(pi.hProcess, &exitCode);
    ResultOk(&r, id);
    ReplyU64(&r, "pid", pi.dwProcessId);
    ReplyU64(&r, "exit", exitCode);
    ReplyU64(&r, "timedout", timedOut);
    ReplyU64(&r, "truncated", trunc || out.failed || err.failed);
    ReplyU64(&r, "ms", GetTickCount() - start);
    ReplyU64(&r, "outlen", out.len);
    ReplyU64(&r, "errlen", err.len);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ok = Finish2(c, &r, out.p, out.len, err.p, err.len);
    goto done;
fail:
    ok = FinishErr(c, id, code, "CreateProcess or pipe setup failed");
done:
    if (outR) CloseHandle(outR);
    if (errR) CloseHandle(errR);
    if (outW) CloseHandle(outW);
    if (errW) CloseHandle(errW);
    if (in != INVALID_HANDLE_VALUE) CloseHandle(in);
    BufFree(&out);
    BufFree(&err);
    HeapFree(GetProcessHeap(), 0, wcmd);
    HeapFree(GetProcessHeap(), 0, line);
    if (wcwd) HeapFree(GetProcessHeap(), 0, wcwd);
    return ok;
}

/* ---- kill and ps ---- */

/* Terminates pid and its descendants (children first); pids are re-read from a fresh snapshot. */
static UINT KillTree(DWORD pid, UINT *failed, int depth)
{
    HANDLE snap = depth < 16 ? CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) : INVALID_HANDLE_VALUE;
    PROCESSENTRY32W pe;
    UINT killed = 0;
    HANDLE p;

    if (snap != INVALID_HANDLE_VALUE)
    {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe))
        {
            do
            {
                if (pe.th32ParentProcessID == pid && pe.th32ProcessID != pid && pe.th32ProcessID != GetCurrentProcessId())
                    killed += KillTree(pe.th32ProcessID, failed, depth + 1);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (p && TerminateProcess(p, 1)) killed++; else (*failed)++;
    if (p) CloseHandle(p);
    return killed;
}

static BOOL DoKill(CONN *c, const RMSG *j, UINT64 id)
{
    DWORD pid = (DWORD)MsgGetU64(j, "pid", 0), self = GetCurrentProcessId();
    const char *name = MsgGet(j, "name");
    WCHAR *wname = name && *name ? Utf8ToWide(name) : NULL;
    HANDLE snap;
    PROCESSENTRY32W pe;
    UINT killed = 0, failed = 0;
    BOOL tree = MsgGetU64(j, "tree", 0) != 0;
    REPLY r;

    if (!pid && !wname) return FinishErr(c, id, ERROR_INVALID_PARAMETER, "need pid or name");
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { if (wname) HeapFree(GetProcessHeap(), 0, wname); return FinishErr(c, id, GetLastError(), "snapshot failed"); }
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            HANDLE p;
            if (pe.th32ProcessID == self) continue;
            if (pid ? pe.th32ProcessID != pid : _wcsicmp(pe.szExeFile, wname)) continue;
            if (tree)
            {
                killed += KillTree(pe.th32ProcessID, &failed, 0);
                continue;
            }
            p = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (p && TerminateProcess(p, 1)) killed++; else failed++;
            if (p) CloseHandle(p);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (wname) HeapFree(GetProcessHeap(), 0, wname);
    ResultOk(&r, id);
    ReplyU64(&r, "killed", killed);
    ReplyU64(&r, "failed", failed);
    return Finish(c, &r, NULL, 0);
}

static BOOL DoPs(CONN *c, UINT64 id)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    BUF b = { 0 };
    REPLY r;
    BOOL ok;

    if (snap == INVALID_HANDLE_VALUE) return FinishErr(c, id, GetLastError(), "snapshot failed");
    pe.dwSize = sizeof(pe);
    BufStr(&b, "pid\tppid\tthreads\timage\n");
    if (Process32FirstW(snap, &pe))
    {
        do
        {
            BufPrintf(&b, "%u\t%u\t%u\t", pe.th32ProcessID, pe.th32ParentProcessID, pe.cntThreads);
            BufWide(&b, pe.szExeFile);
            BufStr(&b, "\n");
        } while (Process32NextW(snap, &pe));
        if (GetLastError() != ERROR_NO_MORE_FILES) BufFail(&b, GetLastError());
    }
    else BufFail(&b, GetLastError());
    CloseHandle(snap);
    ResultOk(&r, id);
    ok = FinishText(c, id, &r, &b);
    BufFree(&b);
    return ok;
}


static BOOL DoModules(CONN *c, const RMSG *j, UINT64 id)
{
    DWORD pid = (DWORD)MsgGetU64(j, "pid", 0);
    const char *name = MsgGet(j, "name");
    HANDLE snap;
    MODULEENTRY32W me;
    BUF b = { 0 };
    REPLY r;
    BOOL ok;

    if (!pid && name && *name)
    {
        WCHAR *wname = Utf8ToWide(name);
        PROCESSENTRY32W pe;
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pe.dwSize = sizeof(pe);
        if (wname && snap != INVALID_HANDLE_VALUE && Process32FirstW(snap, &pe))
        {
            do { if (!_wcsicmp(pe.szExeFile, wname)) { pid = pe.th32ProcessID; break; } } while (Process32NextW(snap, &pe));
        }
        if (snap != INVALID_HANDLE_VALUE) CloseHandle(snap);
        if (wname) HeapFree(GetProcessHeap(), 0, wname);
    }
    if (!pid) return FinishErr(c, id, ERROR_NOT_FOUND, "no such process");
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return FinishErr(c, id, GetLastError(), "module snapshot failed");
    me.dwSize = sizeof(me);
    BufPrintf(&b, "# pid %u\n", pid);
    if (Module32FirstW(snap, &me))
    {
        do
        {
            BufPrintf(&b, "%p\t%lu\t", me.modBaseAddr, me.modBaseSize);
            BufWide(&b, me.szExePath);
            BufStr(&b, "\n");
        } while (Module32NextW(snap, &me));
        if (GetLastError() != ERROR_NO_MORE_FILES) BufFail(&b, GetLastError());
    }
    else BufFail(&b, GetLastError());
    CloseHandle(snap);
    ResultOk(&r, id);
    ok = FinishText(c, id, &r, &b);
    BufFree(&b);
    return ok;
}


/* Starts a new copy of this executable (it waits for our mutex), then ends this one. */
static BOOL DoRestart(CONN *c, UINT64 id)
{
    WCHAR exe[MAX_PATH], line[MAX_PATH + 600];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    REPLY r;

    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return FinishErr(c, id, GetLastError(), "no module name");
    /* same arguments as this start (port and token overrides included), plus /wait */
    _snwprintf(line, MAX_PATH + 599, L"\"%s\" %s /wait", exe, g_Args);
    line[MAX_PATH + 599] = 0;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, line, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        return FinishErr(c, id, GetLastError(), "cannot start the new agent");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ResultOk(&r, id);
    g_Quit = TRUE;
    return Finish(c, &r, NULL, 0);
}

/* ---- power ---- */

static BOOL DoPower(CONN *c, const RMSG *j, UINT64 id)
{
    const char *mode = MsgGet(j, "mode");
    UINT flags;
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    REPLY r;
    BOOL ok;

    if (mode && !strcmp(mode, "reboot")) flags = EWX_REBOOT | EWX_FORCE;
    else if (mode && !strcmp(mode, "shutdown")) flags = EWX_POWEROFF | EWX_FORCE;
    else return FinishErr(c, id, ERROR_INVALID_PARAMETER, "mode must be reboot or shutdown");
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return FinishErr(c, id, GetLastError(), "OpenProcessToken failed");
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid) ||
        !AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL) || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        DWORD e = GetLastError();
        CloseHandle(tok);
        return FinishErr(c, id, e, "SeShutdownPrivilege not available");
    }
    CloseHandle(tok);
    ResultOk(&r, id);
    ReplyStr(&r, "mode", mode);
    ok = Finish(c, &r, NULL, 0);
    if (ok)
    {
        LogLine("power %s", mode);
        if (ExitWindowsEx(flags, 0x00040000 /* SHTDN_REASON_FLAG_PLANNED */))
            g_PowerPending = TRUE;
        else
            LogLine("ExitWindowsEx failed: %lu", GetLastError());
    }
    return ok;
}

/* ---- screenshot ---- */

static BOOL DoShot(CONN *c, UINT64 id)
{
    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    HDC scr, mem;
    HBITMAP bm, old;
    BITMAPINFOHEADER bi;
    BITMAPFILEHEADER fh;
    SIZE_T stride, pix, total;
    BYTE *buf;
    REPLY r;
    BOOL ok;
    DWORD err = 0;

    if (w <= 0 || h <= 0) return FinishErr(c, id, ERROR_INVALID_PARAMETER, "no screen metrics");
    stride = ((SIZE_T)w * 3 + 3) & ~(SIZE_T)3;
    pix = stride * h;
    total = sizeof(fh) + sizeof(bi) + pix;
    buf = HeapAlloc(GetProcessHeap(), 0, total);
    if (!buf) return FinishErr(c, id, ERROR_OUTOFMEMORY, "out of memory");
    scr = GetDC(NULL);
    mem = CreateCompatibleDC(scr);
    bm = CreateCompatibleBitmap(scr, w, h);
    old = SelectObject(mem, bm);
    if (!BitBlt(mem, 0, 0, w, h, scr, 0, 0, SRCCOPY)) err = GetLastError();
    SelectObject(mem, old);
    ZeroMemory(&bi, sizeof(bi));
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = (DWORD)pix;
    if (!err && !GetDIBits(mem, bm, 0, h, buf + sizeof(fh) + sizeof(bi), (BITMAPINFO *)&bi, DIB_RGB_COLORS))
        err = GetLastError() ? GetLastError() : ERROR_GEN_FAILURE;
    DeleteObject(bm);
    DeleteDC(mem);
    ReleaseDC(NULL, scr);
    if (err) { HeapFree(GetProcessHeap(), 0, buf); return FinishErr(c, id, err, "screen capture failed"); }
    ZeroMemory(&fh, sizeof(fh));
    fh.bfType = 0x4D42;
    fh.bfSize = (DWORD)total;
    fh.bfOffBits = sizeof(fh) + sizeof(bi);
    memcpy(buf, &fh, sizeof(fh));
    memcpy(buf + sizeof(fh), &bi, sizeof(bi));
    ResultOk(&r, id);
    ReplyU64(&r, "width", w);
    ReplyU64(&r, "height", h);
    ok = Finish(c, &r, buf, total);
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

/* ---- event log ---- */

static void FormatTime(DWORD t, char *out, int cap)
{
    UINT64 days = t / 86400, secs = t % 86400, z = days + 719468, era = z / 146097, doe = z - era * 146097;
    UINT64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365, doy, mp, d, m, y;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    _snprintf(out, cap, "%04u-%02u-%02uT%02u:%02u:%02uZ", (UINT)y, (UINT)m, (UINT)d, (UINT)(secs / 3600), (UINT)(secs / 60 % 60), (UINT)(secs % 60));
}

static BOOL DoEvents(CONN *c, const RMSG *j, UINT64 id)
{
    const char *log = MsgGet(j, "log"), *src = MsgGet(j, "source");
    UINT64 want = MsgGetU64(j, "count", 20), have = 0;
    WCHAR *wlog = Utf8ToWide(log && *log ? log : "Application"), *wsrc = src && *src ? Utf8ToWide(src) : NULL;
    HANDLE h = NULL;
    DWORD rbSize = 65536;
    BYTE *rb = HeapAlloc(GetProcessHeap(), 0, rbSize);
    BUF b = { 0 };
    REPLY r;
    BOOL ok, more = TRUE;
    DWORD err = 0;

    /* a dropped source filter would return unrelated records as success */
    if (!wlog || (src && *src && !wsrc) || !rb) { err = ERROR_OUTOFMEMORY; goto fail; }
    h = OpenEventLogW(NULL, wlog);
    if (h == NULL) { err = GetLastError(); goto fail; }
    while (more && have < want)
    {
        DWORD read = 0, need = 0;
        BYTE *p;
        if (!ReadEventLogW(h, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, rb, rbSize, &read, &need))
        {
            err = GetLastError();
            if (err == ERROR_INSUFFICIENT_BUFFER && need > rbSize && need <= 16 * 1024 * 1024)
            {
                BYTE *nb = HeapReAlloc(GetProcessHeap(), 0, rb, need);
                if (nb) { rb = nb; rbSize = need; err = 0; continue; }
                err = ERROR_OUTOFMEMORY;
            }
            if (err == ERROR_HANDLE_EOF) err = 0;
            break;
        }
        for (p = rb; p < rb + read && have < want; p += ((EVENTLOGRECORD *)p)->Length)
        {
            EVENTLOGRECORD *rec = (EVENTLOGRECORD *)p;
            WCHAR *source = (WCHAR *)(p + sizeof(EVENTLOGRECORD)), *s;
            const char *type;
            char ts[40];
            WORD i;

            if (rec->Length < sizeof(EVENTLOGRECORD)) { more = FALSE; break; }
            if (wsrc && !wcsstr(source, wsrc)) continue;
            switch (rec->EventType)
            {
                case EVENTLOG_ERROR_TYPE: type = "error"; break;
                case EVENTLOG_WARNING_TYPE: type = "warning"; break;
                case EVENTLOG_INFORMATION_TYPE: type = "info"; break;
                default: type = "other";
            }
            FormatTime(rec->TimeGenerated, ts, sizeof(ts));
            BufPrintf(&b, "rec=%u time=%s type=%s id=%u cat=%u src=", rec->RecordNumber, ts, type, rec->EventID & 0xFFFF, rec->EventCategory);
            BufWide(&b, source);
            s = (WCHAR *)(p + rec->StringOffset);
            for (i = 0; i < rec->NumStrings; i++)
            {
                BufStr(&b, i ? " | " : " :: ");
                BufWide(&b, s);
                s += wcslen(s) + 1;
            }
            BufStr(&b, "\n");
            have++;
        }
    }
    if (err) goto fail;
    ResultOk(&r, id);
    ReplyU64(&r, "records", have);
    ok = FinishText(c, id, &r, &b);
    goto done;
fail:
    ok = FinishErr(c, id, err, "event log read failed");
done:
    if (h) CloseEventLog(h);
    if (rb) HeapFree(GetProcessHeap(), 0, rb);
    if (wlog) HeapFree(GetProcessHeap(), 0, wlog);
    if (wsrc) HeapFree(GetProcessHeap(), 0, wsrc);
    BufFree(&b);
    return ok;
}

/* ---- crash dump directories ---- */

static void ListDir(BUF *b, const WCHAR *dir)
{
    WCHAR pat[MAX_PATH + 4];
    WIN32_FIND_DATAW fd;
    HANDLE f;

    BufStr(b, "# ");
    BufWide(b, dir);
    BufStr(b, "\n");
    _snwprintf(pat, MAX_PATH, L"%s\\*", dir);
    pat[MAX_PATH - 1] = 0;
    f = FindFirstFileW(pat, &fd);
    if (f == INVALID_HANDLE_VALUE)
    {
        DWORD e = GetLastError();
        /* a missing directory is an ordinary answer and is listed as such; running out of memory is not */
        if (e == ERROR_NOT_ENOUGH_MEMORY || e == ERROR_OUTOFMEMORY || e == ERROR_NO_SYSTEM_RESOURCES) BufFail(b, e);
        else BufPrintf(b, "# error %lu\n", e);
        return;
    }
    do
    {
        FILETIME ft = fd.ftLastWriteTime;
        UINT64 t = ((UINT64)ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 10000000ULL - 11644473600ULL;
        char ts[40];
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        FormatTime((DWORD)t, ts, sizeof(ts));
        BufPrintf(b, "%I64u\t%s\t", (unsigned __int64)((UINT64)fd.nFileSizeHigh << 32 | fd.nFileSizeLow), ts);
        BufWide(b, dir);
        BufStr(b, "\\");
        BufWide(b, fd.cFileName);
        BufStr(b, "\n");
    } while (FindNextFileW(f, &fd));
    if (GetLastError() != ERROR_NO_MORE_FILES) BufFail(b, GetLastError());
    FindClose(f);
}

/* Expands %VAR% into out[MAX_PATH]; FALSE when it does not fit or fails. */
static BOOL ExpandPath(const WCHAR *in, WCHAR *out)
{
    DWORD n = ExpandEnvironmentStringsW(in, out, MAX_PATH);
    if (!n || n > MAX_PATH) return FALSE;
    out[MAX_PATH - 1] = 0;
    return TRUE;
}

static BOOL DoDumps(CONN *c, const RMSG *j, UINT64 id)
{
    const char *dir = MsgGet(j, "dir");
    BUF b = { 0 };
    REPLY r;
    BOOL ok;
    WCHAR path[MAX_PATH], tmp[MAX_PATH];

    if (dir && *dir)
    {
        WCHAR *w = Utf8ToWide(dir);
        if (!w) return FinishErr(c, id, ERROR_OUTOFMEMORY, "cannot convert the directory name");
        ListDir(&b, w);
        HeapFree(GetProcessHeap(), 0, w);
    }
    else
    {
        HKEY k;
        DWORD type, cb = sizeof(tmp);
        /* LocalDumps (DumpFolder), then the per-user default, then the legacy system directory */
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", 0, KEY_READ, &k) == ERROR_SUCCESS)
        {
            if (RegQueryValueExW(k, L"DumpFolder", NULL, &type, (BYTE *)tmp, &cb) == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
            {
                tmp[MAX_PATH - 1] = 0;
                if (ExpandPath(tmp, path)) ListDir(&b, path);
            }
            RegCloseKey(k);
        }
        if (ExpandPath(L"%LOCALAPPDATA%\\CrashDumps", path) && !wcschr(path, L'%')) ListDir(&b, path);
        if (ExpandPath(L"%SystemRoot%\\Minidump", path)) ListDir(&b, path);
        if (ExpandPath(L"%SystemRoot%", path)) ListDir(&b, path);
    }
    ResultOk(&r, id);
    ok = FinishText(c, id, &r, &b);
    BufFree(&b);
    return ok;
}

/* ---- info ---- */

void LocalInfo(char *out, int cap)
{
    OSVERSIONINFOW vi;
    WCHAR comp[64] = L"", user[64] = L"", exe[MAX_PATH] = L"", cwd[MAX_PATH] = L"", root[MAX_PATH] = L"";
    DWORD n, sess = 0;
    MEMORYSTATUSEX ms;
    char *ucomp, *uuser, *uexe, *ucwd, *uroot;

    ZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    GetVersionExW(&vi);
    n = 64; GetComputerNameW(comp, &n);
    n = 64; GetUserNameW(user, &n);
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    GetCurrentDirectoryW(MAX_PATH, cwd);
    GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    ProcessIdToSessionId(GetCurrentProcessId(), &sess);
    ZeroMemory(&ms, sizeof(ms));
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    ucomp = WideToUtf8(comp); uuser = WideToUtf8(user); uexe = WideToUtf8(exe); ucwd = WideToUtf8(cwd); uroot = WideToUtf8(root);
    _snprintf(out, cap - 1,
              "agent=%s\narch=%s\nos=%lu.%lu.%lu\ncomputer=%s\nuser=%s\nsession=%lu\npid=%lu\nexe=%s\ncwd=%s\n"
              "systemroot=%s\nscreen=%dx%d\nuptime_ms=%lu\nmem_total_mb=%I64u\nmem_free_mb=%I64u\n",
              ROSDEV_VERSION,
#ifdef _WIN64
              "x64",
#else
              "x86",
#endif
              vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber,
              ucomp ? ucomp : "", uuser ? uuser : "", sess, GetCurrentProcessId(), uexe ? uexe : "", ucwd ? ucwd : "",
              uroot ? uroot : "", GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), GetTickCount(),
              (unsigned __int64)(ms.ullTotalPhys >> 20), (unsigned __int64)(ms.ullAvailPhys >> 20));
    out[cap - 1] = 0;
    if (ucomp) HeapFree(GetProcessHeap(), 0, ucomp);
    if (uuser) HeapFree(GetProcessHeap(), 0, uuser);
    if (uexe) HeapFree(GetProcessHeap(), 0, uexe);
    if (ucwd) HeapFree(GetProcessHeap(), 0, ucwd);
    if (uroot) HeapFree(GetProcessHeap(), 0, uroot);
}

static BOOL DoInfo(CONN *c, UINT64 id)
{
    char txt[2048];
    REPLY r;
    LocalInfo(txt, sizeof(txt));
    ResultOk(&r, id);
    return Finish(c, &r, txt, strlen(txt));
}

BOOL RunJob(CONN *c, RMSG *j)
{
    const char *op = MsgGet(j, "op");
    UINT64 id = MsgGetU64(j, "id", 0);

    if (!op) return FinishErr(c, id, ERROR_INVALID_PARAMETER, "no op");
    LogLine("job %I64u %s", (unsigned __int64)id, op);
    if (!strcmp(op, "put")) return DoPut(c, j, id);
    if (!strcmp(op, "get")) return DoGet(c, j, id);
    if (!strcmp(op, "run")) return DoRun(c, j, id);
    if (!strcmp(op, "kill")) return DoKill(c, j, id);
    if (!strcmp(op, "ps")) return DoPs(c, id);
    if (!strcmp(op, "modules")) return DoModules(c, j, id);
    if (!strcmp(op, "power")) return DoPower(c, j, id);
    if (!strcmp(op, "shot")) return DoShot(c, id);
    if (!strcmp(op, "events")) return DoEvents(c, j, id);
    if (!strcmp(op, "dumps")) return DoDumps(c, j, id);
    if (!strcmp(op, "info")) return DoInfo(c, id);
    if (!strcmp(op, "restart")) return DoRestart(c, id);
    if (!strcmp(op, "quit"))
    {
        REPLY r;
        ResultOk(&r, id);
        g_Quit = TRUE;
        return Finish(c, &r, NULL, 0);
    }
    return FinishErr(c, id, ERROR_CALL_NOT_IMPLEMENTED, "unknown op");
}
