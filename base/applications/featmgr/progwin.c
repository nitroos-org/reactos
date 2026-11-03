/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The "Installing additional components" window. Modelled on the progress window Windows shows while
 *              "Turn Windows features on or off" applies a change (Searching for required files, Downloading required
 *              files, Applying changes, completed), plus a "Show details" expander with one row per component
 *              (step, MB done/total, status) and a live log. Shared by the features tree (OK) and the first-boot
 *              installer; the engine does the work on a worker thread and reports through the FmOp* sink.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <commctrl.h>
#include <strsafe.h>
#include <stdarg.h>

#define IDC_HEAD     2001
#define IDC_STEP0    2002      /* 2002..2005 */
#define IDC_BAR      2006
#define IDC_PCT      2007
#define IDC_ERR      2008
#define IDC_TOGGLE   2009
#define IDC_LIST     2010
#define IDC_LOG      2011
#define IDC_RETRY    2012
#define IDC_CANCELB  2013
#define IDC_RESTART  2014
#define IDT_TICK     1
#define IDT_AUTOCLOSE 2
#define WM_APP_DONE  (WM_APP + 21)
#define WM_APP_TICK  (WM_APP + 22)

enum { ST_PENDING, ST_RUNNING, ST_DONE, ST_FAILED, ST_CANCELLED, ST_SKIPPED };
enum { SG_NONE, SG_SEARCH, SG_DOWNLOAD, SG_VERIFY, SG_APPLY };

typedef struct _ROW
{
    FM_JOB    job;
    int       status;
    int       stage;
    ULONGLONG done, total;
    WCHAR     err[512];
    DWORD     applyStart;
    /* last text pushed into the list, to touch the ListView only on a change */
    WCHAR     shownStep[40], shownProg[64], shownStatus[24];
} ROW;

#define LOGBUF_CCH 12000
static struct
{
    CRITICAL_SECTION cs;
    BOOL     csInit;
    HWND     hwnd, owner;
    ROW     *rows;
    int      n, cur, phase;
    BOOL     running, finished, expanded, closed, tickPending, reboot, autoclose, cancelAsked;
    int      ok, failed, cancelled;
    DWORD    flags;
    WCHAR    logFile[MAX_PATH];
    WCHAR    pendLog[LOGBUF_CCH];        /* text the worker added, not yet in the log pane */
    WCHAR    firstError[512];
    HANDLE   thread;
    HFONT    font, bold, head;
    HWND     hHead, hStep[4], hBar, hPct, hErr, hToggle, hList, hLog, hRetry, hCancel, hRestart;
    int      shownPct;
    int      shownPhase;
    BOOL     shownRunning;
} U;

static LPCWSTR const g_stepText[4] =
{
    L"Searching for required files",
    L"Downloading required files",
    L"Applying changes",
    L"NitroOS completed the requested changes"
};

/* ---- log ---------------------------------------------------------------------------------------------------- */

static void LogAdd(LPCWSTR text)       /* worker or UI thread; caller does not hold the lock */
{
    SYSTEMTIME st;
    WCHAR line[700];
    size_t cur;

    GetSystemTime(&st);
    StringCchPrintfW(line, ARRAYSIZE(line), L"[%02u:%02u:%02u] %s\r\n", st.wHour, st.wMinute, st.wSecond, text);
    EnterCriticalSection(&U.cs);
    cur = wcslen(U.pendLog);
    if (cur + wcslen(line) + 1 < LOGBUF_CCH)
        StringCchCatW(U.pendLog, LOGBUF_CCH, line);
    LeaveCriticalSection(&U.cs);
    if (U.logFile[0])
        FmLogLine(U.logFile, L"%s", text);
}

static void Fmt(LPWSTR out, size_t cch, LPCWSTR fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(out, cch - 1, fmt, ap);
    va_end(ap);
    out[cch - 1] = L'\0';
}

/* ---- the engine's progress sink (worker thread) -------------------------------------------------------------- */

static void Sink(FM_PROG_KIND kind, LPCWSTR text, void *ctx)
{
    BOOL post = FALSE;
    (void)ctx;
    switch (kind)
    {
        case FM_PROG_PHASE:
        {
            int p = _wtoi(text);
            EnterCriticalSection(&U.cs);
            U.phase = p;
            if (U.cur >= 0 && U.cur < U.n)
            {
                ROW *r = &U.rows[U.cur];
                r->stage = p == FM_PHASE_DOWNLOAD ? SG_DOWNLOAD : p == FM_PHASE_APPLY ? SG_APPLY : SG_SEARCH;
                if (p == FM_PHASE_APPLY) r->applyStart = GetTickCount();
            }
            post = !U.tickPending; U.tickPending = TRUE;
            LeaveCriticalSection(&U.cs);
            break;
        }
        case FM_PROG_BYTES:
        {
            ULONGLONG d = 0, t = 0;
            WCHAR *e;
            d = _wcstoui64(text, &e, 10);
            if (e && *e) t = _wcstoui64(e, NULL, 10);
            EnterCriticalSection(&U.cs);
            if (U.cur >= 0 && U.cur < U.n) { U.rows[U.cur].done = d; U.rows[U.cur].total = t; }
            post = !U.tickPending; U.tickPending = TRUE;
            LeaveCriticalSection(&U.cs);
            break;
        }
        case FM_PROG_STEP:
            EnterCriticalSection(&U.cs);
            if (U.cur >= 0 && U.cur < U.n && !wcsncmp(text, L"Verifying", 9))
                U.rows[U.cur].stage = SG_VERIFY;
            post = !U.tickPending; U.tickPending = TRUE;
            LeaveCriticalSection(&U.cs);
            LogAdd(text);
            break;
        case FM_PROG_OUTPUT:
        {
            WCHAR t[300];
            StringCchPrintfW(t, ARRAYSIZE(t), L"    %s", text);
            LogAdd(t);
            break;
        }
    }
    if (post && U.hwnd) PostMessageW(U.hwnd, WM_APP_TICK, 0, 0);
}

/* ---- worker ----------------------------------------------------------------------------------------------- */

static void SetStage(int i, int status, int stage)
{
    EnterCriticalSection(&U.cs);
    U.cur = i;
    U.rows[i].status = status;
    U.rows[i].stage = stage;
    U.rows[i].done = U.rows[i].total = 0;
    U.phase = FM_PHASE_SEARCH;
    LeaveCriticalSection(&U.cs);
}

static DWORD WINAPI Worker(LPVOID param)
{
    int i;
    (void)param;
    for (i = 0; i < U.n; i++)
    {
        HRESULT hr;
        WCHAR msg[1024], line[300];
        ROW *r = &U.rows[i];

        if (r->status == ST_DONE) continue;
        if (FmOpCancelled())
        {
            EnterCriticalSection(&U.cs);
            r->status = ST_SKIPPED;
            LeaveCriticalSection(&U.cs);
            continue;
        }
        SetStage(i, ST_RUNNING, SG_SEARCH);
        Fmt(line, ARRAYSIZE(line), L"%s %s", r->job.action == FM_JOB_INSTALL ? L"Installing" : L"Removing", r->job.name);
        LogAdd(line);
        if (r->job.action == FM_JOB_INSTALL)
            hr = FmEnable(r->job.id, NULL);
        else
        {
            FmOpPhase(FM_PHASE_APPLY);
            hr = FmDisable(r->job.id, NULL);
            if (hr == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED)) { hr = S_OK; InterlockedExchange((LONG *)&U.reboot, 1); }
        }
        if (SUCCEEDED(hr))
        {
            EnterCriticalSection(&U.cs);
            r->status = ST_DONE;
            r->done = r->total;
            LeaveCriticalSection(&U.cs);
            Fmt(line, ARRAYSIZE(line), L"%s: done", r->job.name);
            LogAdd(line);
        }
        else
        {
            BOOL cancelled = hr == HRESULT_FROM_WIN32(ERROR_CANCELLED) || FmOpCancelled();
            FmGetLastMessage(msg, ARRAYSIZE(msg));
            if (!msg[0])
                Fmt(msg, ARRAYSIZE(msg), cancelled ? L"The operation was cancelled." : L"The change failed (error 0x%08lx).", (DWORD)hr);
            EnterCriticalSection(&U.cs);
            r->status = cancelled ? ST_CANCELLED : ST_FAILED;
            StringCchCopyW(r->err, ARRAYSIZE(r->err), msg);
            LeaveCriticalSection(&U.cs);
            Fmt(line, ARRAYSIZE(line), L"%s: %s", r->job.name, cancelled ? L"cancelled" : L"FAILED");
            LogAdd(line);
            LogAdd(msg);
        }
        if (FmTakeRebootNeeded()) InterlockedExchange((LONG *)&U.reboot, 1);
    }
    if (U.hwnd) PostMessageW(U.hwnd, WM_APP_DONE, 0, 0);
    return 0;
}

static void StartWorker(void)
{
    int i;
    U.running = TRUE;
    U.finished = FALSE;
    U.cancelAsked = FALSE;
    for (i = 0; i < U.n; i++)
        if (U.rows[i].status != ST_DONE) { U.rows[i].status = ST_PENDING; U.rows[i].err[0] = L'\0'; U.rows[i].stage = SG_NONE; }
    U.cur = -1;
    U.phase = 0;
    FmOpBegin(Sink, NULL);
    U.thread = CreateThread(NULL, 0, Worker, NULL, 0, NULL);
    if (!U.thread) Worker(NULL);     /* no thread: run inline; the posted message ends it */
}

/* ---- layout and refresh (UI thread) --------------------------------------------------------------------------- */

#define CLIENT_W 540

static void Layout(void)
{
    int bottom = 232, y, btnY, h;
    RECT rc, wr;
    DWORD style = (DWORD)GetWindowLongW(U.hwnd, GWL_STYLE), ex = (DWORD)GetWindowLongW(U.hwnd, GWL_EXSTYLE);

    ShowWindow(U.hList, U.expanded ? SW_SHOW : SW_HIDE);
    ShowWindow(U.hLog, U.expanded ? SW_SHOW : SW_HIDE);
    y = 232;
    if (U.expanded)
    {
        MoveWindow(U.hList, 16, y, CLIENT_W - 32, 74, TRUE);
        MoveWindow(U.hLog, 16, y + 80, CLIENT_W - 32, 112, TRUE);
        y += 80 + 112 + 8;
    }
    btnY = y;
    bottom = btnY + 28 + 14;
    MoveWindow(U.hToggle, 16, btnY, 128, 26, TRUE);
    MoveWindow(U.hCancel, CLIENT_W - 16 - 96, btnY, 96, 26, TRUE);
    MoveWindow(U.hRetry, CLIENT_W - 16 - 96 - 6 - 96, btnY, 96, 26, TRUE);
    MoveWindow(U.hRestart, CLIENT_W - 16 - 96 - 6 - 96 - 6 - 110, btnY, 110, 26, TRUE);
    SetRect(&rc, 0, 0, CLIENT_W, bottom);
    AdjustWindowRectEx(&rc, style, FALSE, ex);
    GetWindowRect(U.hwnd, &wr);
    h = rc.bottom - rc.top;
    {
        /* keep the whole window on the work area (an 800x600 screen), growing downwards from where it is */
        RECT wa;
        int top = wr.top;
        if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0))
        {
            if (top + h > wa.bottom) top = wa.bottom - h;
            if (top < wa.top) top = wa.top;
        }
        SetWindowPos(U.hwnd, NULL, wr.left, top, rc.right - rc.left, h, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    SetWindowTextW(U.hToggle, U.expanded ? L"Hide &details" : L"Show &details");
}

static void ShortMB(ULONGLONG d, WCHAR *out, size_t cch)
{
    Fmt(out, cch, L"%I64u.%I64u", d >> 20, ((d & 0xFFFFF) * 10) >> 20);
}

static void SetItemTextIfChanged(int row, int col, WCHAR *shown, size_t shownCch, LPCWSTR text)
{
    if (!wcscmp(shown, text)) return;
    StringCchCopyW(shown, shownCch, text);
    ListView_SetItemText(U.hList, row, col, (LPWSTR)text);
}

static int OverallPermille(void)
{
    double acc = 0;
    int i;
    DWORD now = GetTickCount();
    if (U.n == 0) return 1000;
    for (i = 0; i < U.n; i++)
    {
        ROW *r = &U.rows[i];
        double p = 0;
        switch (r->status)
        {
            case ST_DONE: p = 1.0; break;
            case ST_RUNNING:
                switch (r->stage)
                {
                    case SG_SEARCH: p = 0.02; break;
                    case SG_DOWNLOAD:
                        p = 0.05 + 0.50 * (r->total ? (double)r->done / (double)r->total : 0.0);
                        break;
                    case SG_VERIFY: p = 0.56; break;
                    case SG_APPLY:
                    {
                        double t = (now - r->applyStart) / 1000.0;      /* the installer reports no progress: creep towards 97% */
                        p = 0.60 + 0.37 * (1.0 - 1.0 / (1.0 + t / 90.0));
                        break;
                    }
                }
                break;
            default: break;
        }
        acc += p;
    }
    return (int)(acc * 1000.0 / U.n);
}

static void Refresh(void)
{
    int i, perm, phase, shownStep;
    WCHAR t[200], pend[LOGBUF_CCH];
    BOOL running;
    int cur;

    EnterCriticalSection(&U.cs);
    U.tickPending = FALSE;
    StringCchCopyW(pend, LOGBUF_CCH, U.pendLog);
    U.pendLog[0] = L'\0';
    running = U.running;
    cur = U.cur;
    perm = OverallPermille();
    phase = (cur >= 0 && cur < U.n) ? U.rows[cur].stage : SG_NONE;
    for (i = 0; i < U.n; i++)
    {
        ROW *r = &U.rows[i];
        WCHAR step[40], prog[64], status[24];
        LPCWSTR st;
        switch (r->stage)
        {
            case SG_SEARCH:   st = L"Searching"; break;
            case SG_DOWNLOAD: st = L"Downloading"; break;
            case SG_VERIFY:   st = L"Verifying"; break;
            case SG_APPLY:    st = r->job.action == FM_JOB_REMOVE ? L"Removing" : L"Installing"; break;
            default:          st = L""; break;
        }
        StringCchCopyW(step, ARRAYSIZE(step), r->status == ST_RUNNING || r->status == ST_FAILED ? st : L"");
        prog[0] = L'\0';
        if ((r->stage == SG_DOWNLOAD || r->stage == SG_VERIFY || r->status == ST_DONE) && r->total)
        {
            WCHAR a[24], b[24];
            ShortMB(r->status == ST_DONE ? r->total : r->done, a, ARRAYSIZE(a));
            ShortMB(r->total, b, ARRAYSIZE(b));
            Fmt(prog, ARRAYSIZE(prog), L"%s / %s MB", a, b);
        }
        switch (r->status)
        {
            case ST_RUNNING:   StringCchCopyW(status, ARRAYSIZE(status), L"In progress"); break;
            case ST_DONE:      StringCchCopyW(status, ARRAYSIZE(status), L"Done"); break;
            case ST_FAILED:    StringCchCopyW(status, ARRAYSIZE(status), L"Failed"); break;
            case ST_CANCELLED: StringCchCopyW(status, ARRAYSIZE(status), L"Cancelled"); break;
            case ST_SKIPPED:   StringCchCopyW(status, ARRAYSIZE(status), L"Not started"); break;
            default:           StringCchCopyW(status, ARRAYSIZE(status), L"Waiting"); break;
        }
        SetItemTextIfChanged(i, 1, r->shownStep, ARRAYSIZE(r->shownStep), step);
        SetItemTextIfChanged(i, 2, r->shownProg, ARRAYSIZE(r->shownProg), prog);
        SetItemTextIfChanged(i, 3, r->shownStatus, ARRAYSIZE(r->shownStatus), status);
    }
    LeaveCriticalSection(&U.cs);

    if (pend[0])
    {
        int len = GetWindowTextLengthW(U.hLog);
        SendMessageW(U.hLog, EM_SETSEL, len, len);
        SendMessageW(U.hLog, EM_REPLACESEL, FALSE, (LPARAM)pend);
        SendMessageW(U.hLog, EM_SCROLLCARET, 0, 0);
    }

    /* the four steps: done / current / waiting */
    if (U.finished && U.failed == 0 && U.cancelled == 0) shownStep = 4;
    else if (phase == SG_DOWNLOAD || phase == SG_VERIFY) shownStep = 1;
    else if (phase == SG_APPLY) shownStep = 2;
    else shownStep = 0;
    if (U.finished && (U.failed || U.cancelled)) shownStep = -1;
    if (shownStep != U.shownPhase || running != U.shownRunning)
    {
        for (i = 0; i < 4; i++)
        {
            WCHAR s[96];
            LPCWSTR mark = shownStep < 0 ? L"    " : i < shownStep ? L"OK  " : i == shownStep ? L" >  " : L"    ";
            if (shownStep == 4 && i == 3) mark = L"OK  ";
            Fmt(s, ARRAYSIZE(s), L"%s%s%s", mark, g_stepText[i], (i == shownStep && shownStep < 3) ? L"..." : L"");
            SetWindowTextW(U.hStep[i], s);
            SendMessageW(U.hStep[i], WM_SETFONT, (WPARAM)(i == shownStep ? U.bold : U.font), TRUE);
        }
        U.shownPhase = shownStep;
        U.shownRunning = running;
    }
    if (perm / 10 != U.shownPct)
    {
        U.shownPct = perm / 10;
        SendMessageW(U.hBar, PBM_SETPOS, perm, 0);
        Fmt(t, ARRAYSIZE(t), L"%d%%", perm / 10);
        SetWindowTextW(U.hPct, t);
    }
}

/* the end of a run: counts, the error text, the buttons */
static void Finish(void)
{
    int i;
    WCHAR t[900];

    if (U.thread) { WaitForSingleObject(U.thread, 5000); CloseHandle(U.thread); U.thread = NULL; }
    FmOpEnd();
    EnterCriticalSection(&U.cs);
    U.ok = U.failed = U.cancelled = 0;
    U.firstError[0] = L'\0';
    for (i = 0; i < U.n; i++)
    {
        ROW *r = &U.rows[i];
        if (r->status == ST_DONE) U.ok++;
        else if (r->status == ST_FAILED)
        {
            U.failed++;
            if (!U.firstError[0]) Fmt(U.firstError, ARRAYSIZE(U.firstError), L"%s: %s", r->job.name, r->err);
        }
        else if (r->status == ST_CANCELLED || r->status == ST_SKIPPED) U.cancelled++;
    }
    LeaveCriticalSection(&U.cs);
    U.running = FALSE;
    U.finished = TRUE;

    if (U.failed)
    {
        Fmt(t, ARRAYSIZE(t), L"The changes could not be completed.\r\n%s", U.firstError);
        U.expanded = TRUE;
        Layout();
    }
    else if (U.cancelled)
        StringCchCopyW(t, ARRAYSIZE(t), L"The changes were cancelled. Anything that was stopped part-way was not recorded as installed; "
                                        L"you can try again.");
    else if (U.reboot)
        StringCchCopyW(t, ARRAYSIZE(t), L"A restart is required to finish these changes.");
    else
        t[0] = L'\0';
    SetWindowTextW(U.hErr, t);
    ShowWindow(U.hErr, t[0] ? SW_SHOW : SW_HIDE);
    InvalidateRect(U.hErr, NULL, TRUE);

    SetWindowTextW(U.hCancel, L"&Close");
    EnableWindow(U.hCancel, TRUE);
    ShowWindow(U.hRetry, (U.failed || U.cancelled) ? SW_SHOW : SW_HIDE);
    ShowWindow(U.hRestart, (!U.failed && !U.cancelled && U.reboot) ? SW_SHOW : SW_HIDE);
    if (U.failed || U.cancelled) SetFocus(U.hRetry); else SetFocus(U.hCancel);
    Refresh();
    if (!U.failed && !U.cancelled)
    {
        SendMessageW(U.hBar, PBM_SETPOS, 1000, 0);
        SetWindowTextW(U.hPct, L"100%");
        if (U.autoclose && !U.reboot) SetTimer(U.hwnd, IDT_AUTOCLOSE, 6000, NULL);
    }
    LogAdd(U.failed ? L"Finished with errors." : U.cancelled ? L"Cancelled." : L"Finished: all requested changes were applied.");
}

static void AddControls(HWND hwnd)
{
    LVCOLUMNW col;
    int i;
    NONCLIENTMETRICSW ncm;
    LOGFONTW lf;

    ZeroMemory(&ncm, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
    {
        U.font = CreateFontIndirectW(&ncm.lfMessageFont);
        lf = ncm.lfMessageFont;
        lf.lfWeight = FW_BOLD;
        U.bold = CreateFontIndirectW(&lf);
        lf = ncm.lfMessageFont;
        lf.lfHeight = lf.lfHeight * 14 / 10;
        U.head = CreateFontIndirectW(&lf);
    }
    if (!U.font) U.font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    if (!U.bold) U.bold = U.font;
    if (!U.head) U.head = U.font;

    U.hHead = CreateWindowExW(0, L"STATIC", L"Installing additional components", WS_CHILD | WS_VISIBLE,
                              16, 14, CLIENT_W - 32, 26, hwnd, (HMENU)(INT_PTR)IDC_HEAD, NULL, NULL);
    for (i = 0; i < 4; i++)
        U.hStep[i] = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 24, 52 + i * 22, CLIENT_W - 48, 18,
                                     hwnd, (HMENU)(INT_PTR)(IDC_STEP0 + i), NULL, NULL);
    U.hBar = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 16, 148, CLIENT_W - 32 - 48, 18,
                             hwnd, (HMENU)(INT_PTR)IDC_BAR, NULL, NULL);
    SendMessageW(U.hBar, PBM_SETRANGE32, 0, 1000);
    U.hPct = CreateWindowExW(0, L"STATIC", L"0%", WS_CHILD | WS_VISIBLE | SS_RIGHT, CLIENT_W - 16 - 44, 149, 44, 18, hwnd,
                             (HMENU)(INT_PTR)IDC_PCT, NULL, NULL);
    U.hErr = CreateWindowExW(0, L"STATIC", L"", WS_CHILD, 16, 174, CLIENT_W - 32, 56, hwnd, (HMENU)(INT_PTR)IDC_ERR, NULL, NULL);
    U.hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_NOSORTHEADER |
                              LVS_SHOWSELALWAYS, 16, 232, CLIENT_W - 32, 104, hwnd, (HMENU)(INT_PTR)IDC_LIST, NULL, NULL);
    ListView_SetExtendedListViewStyle(U.hList, LVS_EX_FULLROWSELECT);
    ZeroMemory(&col, sizeof(col));
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.pszText = (LPWSTR)L"Component"; col.cx = 200; ListView_InsertColumn(U.hList, 0, &col);
    col.pszText = (LPWSTR)L"Step";      col.cx = 85;  ListView_InsertColumn(U.hList, 1, &col);
    col.pszText = (LPWSTR)L"Progress";  col.cx = 120; ListView_InsertColumn(U.hList, 2, &col);
    col.pszText = (LPWSTR)L"Status";    col.cx = 85;  ListView_InsertColumn(U.hList, 3, &col);
    U.hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                             16, 342, CLIENT_W - 32, 150, hwnd, (HMENU)(INT_PTR)IDC_LOG, NULL, NULL);
    SendMessageW(U.hLog, EM_LIMITTEXT, 200000, 0);
    U.hToggle = CreateWindowExW(0, L"BUTTON", L"Show &details", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 16, 232, 128, 26, hwnd,
                                (HMENU)(INT_PTR)IDC_TOGGLE, NULL, NULL);
    U.hRestart = CreateWindowExW(0, L"BUTTON", L"&Restart now", WS_CHILD | WS_TABSTOP, 0, 0, 110, 26, hwnd,
                                 (HMENU)(INT_PTR)IDC_RESTART, NULL, NULL);
    U.hRetry = CreateWindowExW(0, L"BUTTON", L"&Try again", WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 96, 26, hwnd,
                               (HMENU)(INT_PTR)IDC_RETRY, NULL, NULL);
    U.hCancel = CreateWindowExW(0, L"BUTTON", L"&Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 96, 26, hwnd,
                                (HMENU)(INT_PTR)IDC_CANCELB, NULL, NULL);
    {
        HWND c;
        for (c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
            SendMessageW(c, WM_SETFONT, (WPARAM)U.font, TRUE);
        SendMessageW(U.hHead, WM_SETFONT, (WPARAM)U.head, TRUE);
    }
    for (i = 0; i < U.n; i++)
    {
        LVITEMW it;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = i;
        it.pszText = U.rows[i].job.name;
        ListView_InsertItem(U.hList, &it);
    }
}

static LRESULT CALLBACK ProgProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_CREATE:
            U.hwnd = hwnd;
            AddControls(hwnd);
            Layout();
            Refresh();
            return 0;
        case WM_CTLCOLORSTATIC:
            if ((HWND)lp == U.hErr && U.failed)
            {
                SetTextColor((HDC)wp, RGB(170, 0, 0));
                SetBkMode((HDC)wp, TRANSPARENT);
                return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
            }
            break;
        case WM_TIMER:
            if (wp == IDT_TICK) Refresh();
            else if (wp == IDT_AUTOCLOSE) { KillTimer(hwnd, IDT_AUTOCLOSE); DestroyWindow(hwnd); }
            return 0;
        case WM_APP_TICK:
            Refresh();
            return 0;
        case WM_APP_DONE:
            Finish();
            return 0;
        case WM_COMMAND:
            switch (LOWORD(wp))
            {
                case IDC_TOGGLE:
                    U.expanded = !U.expanded;
                    Layout();
                    return 0;
                case IDC_RETRY:
                    ShowWindow(U.hRetry, SW_HIDE);
                    ShowWindow(U.hErr, SW_HIDE);
                    U.failed = U.cancelled = 0;
                    SetWindowTextW(U.hCancel, L"&Cancel");
                    LogAdd(L"Trying again.");
                    StartWorker();
                    Refresh();
                    return 0;
                case IDC_RESTART:
                    {
                        HANDLE tok;
                        TOKEN_PRIVILEGES tp;
                        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
                        {
                            LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
                            tp.PrivilegeCount = 1;
                            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                            AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
                            CloseHandle(tok);
                        }
                        ExitWindowsEx(EWX_REBOOT, 0);
                    }
                    return 0;
                case IDC_CANCELB:
                    if (U.running)
                    {
                        if (!U.cancelAsked &&
                            MessageBoxW(hwnd, L"Cancel the installation?\r\n\r\nA download stops at once and the partial file is deleted. "
                                        L"An installer that is already running is stopped.", L"Installing additional components",
                                        MB_YESNO | MB_ICONQUESTION) == IDYES && U.running)
                        {
                            U.cancelAsked = TRUE;
                            EnableWindow(U.hCancel, FALSE);
                            LogAdd(L"Cancel requested.");
                            SetWindowTextW(U.hErr, L"Cancelling: stopping the download or installer...");
                            ShowWindow(U.hErr, SW_SHOW);
                            FmOpCancel();
                        }
                    }
                    else
                        DestroyWindow(hwnd);
                    return 0;
            }
            break;
        case WM_CLOSE:
            if (U.running)
            {
                if (!U.cancelAsked &&
                    MessageBoxW(hwnd, L"Cancel the installation and close this window?", L"Installing additional components",
                                MB_YESNO | MB_ICONQUESTION) == IDYES && U.running)
                {
                    U.cancelAsked = TRUE;
                    EnableWindow(U.hCancel, FALSE);
                    FmOpCancel();
                }
                return 0;
            }
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd, IDT_TICK);
            KillTimer(hwnd, IDT_AUTOCLOSE);
            U.hwnd = NULL;
            U.closed = TRUE;
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int FmRunJobsUI(HWND owner, const FM_JOB *jobs, int n, DWORD flags, LPCWSTR logFile, FM_UIRESULT *res)
{
    static BOOL registered;
    WNDCLASSEXW wc;
    MSG m;
    RECT wa;
    int i, rc;
    HWND hwnd;
    INITCOMMONCONTROLSEX icc;

    if (n <= 0)
    {
        if (res) ZeroMemory(res, sizeof(*res));
        return 0;
    }
    if (!U.csInit) { InitializeCriticalSection(&U.cs); U.csInit = TRUE; }
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    U.rows = (ROW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * sizeof(ROW));
    if (!U.rows) return 1;
    U.n = n;
    for (i = 0; i < n; i++) U.rows[i].job = jobs[i];
    U.owner = owner;
    U.flags = flags;
    U.autoclose = (flags & FM_UI_AUTOCLOSE) != 0;
    U.closed = U.finished = U.running = U.expanded = U.reboot = FALSE;
    U.ok = U.failed = U.cancelled = 0;
    U.shownPct = -1; U.shownPhase = -2; U.shownRunning = TRUE;
    U.pendLog[0] = L'\0';
    U.logFile[0] = L'\0';
    if (logFile) StringCchCopyW(U.logFile, ARRAYSIZE(U.logFile), logFile);

    if (!registered)
    {
        ZeroMemory(&wc, sizeof(wc));
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = ProgProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"NitroComponentsProgress";
        wc.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
        RegisterClassExW(&wc);
        registered = TRUE;
    }
    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0))
        SetRect(&wa, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME | (owner ? 0 : WS_EX_APPWINDOW), L"NitroComponentsProgress",
                           L"Installing additional components", WS_POPUP | WS_CAPTION | WS_SYSMENU,
                           wa.left + ((wa.right - wa.left) - CLIENT_W) / 2, wa.top + ((wa.bottom - wa.top) - 300) / 2,
                           CLIENT_W + 8, 300, owner, NULL, GetModuleHandleW(NULL), NULL);
    if (!hwnd)
    {
        HeapFree(GetProcessHeap(), 0, U.rows);
        U.rows = NULL;
        return 1;
    }
    if (owner) EnableWindow(owner, FALSE);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);
    SetTimer(hwnd, IDT_TICK, 250, NULL);
    LogAdd(L"Installing additional components");
    StartWorker();
    Refresh();

    while (!U.closed)
    {
        int g = GetMessageW(&m, NULL, 0, 0);
        if (g <= 0)
        {
            if (g == 0) PostQuitMessage((int)m.wParam);     /* leave the outer loop its WM_QUIT */
            break;
        }
        if (U.hwnd && IsDialogMessageW(U.hwnd, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (U.running)                       /* the loop ended under a running worker: stop it, then wait */
    {
        FmOpCancel();
        if (U.thread) { WaitForSingleObject(U.thread, 60000); CloseHandle(U.thread); U.thread = NULL; }
        FmOpEnd();
        U.running = FALSE;
    }
    if (owner) { EnableWindow(owner, TRUE); SetForegroundWindow(owner); }

    {
        int okc = 0, failc = 0, canc = 0;
        FM_UIRESULT r;
        ZeroMemory(&r, sizeof(r));
        for (i = 0; i < n; i++)
        {
            if (U.rows[i].status == ST_DONE) okc++;
            else if (U.rows[i].status == ST_FAILED)
            {
                failc++;
                if (!r.firstError[0]) StringCchCopyW(r.firstError, ARRAYSIZE(r.firstError), U.rows[i].err);
            }
            else canc++;
        }
        r.ok = okc; r.failed = failc; r.cancelled = canc; r.reboot = U.reboot;
        if (res) *res = r;
        rc = failc ? 1 : canc ? 2 : 0;
    }
    DeleteObject(U.bold != U.font ? U.bold : NULL);
    DeleteObject(U.head != U.font ? U.head : NULL);
    if (U.font && U.font != GetStockObject(DEFAULT_GUI_FONT)) DeleteObject(U.font);
    U.font = U.bold = U.head = NULL;
    HeapFree(GetProcessHeap(), 0, U.rows);
    U.rows = NULL;
    U.n = 0;
    return rc;
}
