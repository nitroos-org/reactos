/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager (FEATMGMT-01)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     optfeatures.exe - "Optional Features" applet.
 *              OS-features tier uses a Windows-native "Turn Windows features on
 *              or off" look: a checkbox list committed with OK/Apply/Cancel.
 *              Software tier uses a "Programs and Features" look (list with
 *              Install / Change / Uninstall verbs). Both are reachable from
 *              Control Panel (the appwiz.cpl applet, optionalfeatures.exe, and the task link in Programs and Features).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <reactos/buildno.h>
#include <commctrl.h>
#include <strsafe.h>
#include "resource.h"

#define IDC_LIST       1001
#define IDC_INSTALL    1002
#define IDC_UNINSTALL  1003
#define IDC_REFRESH    1004
#define IDC_CLOSE      1005
#define IDC_DESC       1006
#define IDC_TAB        1007
#define IDC_ENABLE     1008
#define IDC_DISABLE    1009
#define IDC_OK         1010
#define IDC_CANCEL     1011
#define IDC_APPLY      1012
#define IDC_INSTR      1013
#define IDC_IMPORT     1014
#define IDC_IMPORTSC   1015
#define IDC_SOURCE     1016
#define IDC_SRCLABEL   1017
#define IDC_UPDATE     1018
#define IDC_ADDBUCKET  1019
#define IDC_SEARCH     1020
#define IDC_SRCHLABEL  1021
#define IDC_OPCANCEL   1022  /* "Cancel operation": shown while a background op runs */
#define IDC_PROGRESS   1023  /* marquee bar: shown while a background op runs */
#define IDC_CATEGORY   1024  /* Software tab: category filter */
#define IDT_SEARCH     1     /* debounce timer: filter the list shortly after the last keystroke */
#define IDT_ELAPSED    2     /* once a second while busy: refresh the elapsed time in the status text */

/* A long software-tier install (download + run installer) must not run on the UI
 * thread or the dialog freezes. The op runs on a worker thread that posts this
 * message back with the heap OPCTX result when it finishes. */
#define WM_APP_OPDONE  (WM_APP + 1)
/* The engine reports progress ON THE WORKER THREAD; the sink only stores the text and posts this. */
#define WM_APP_PROGRESS (WM_APP + 2)

static HWND g_hTab, g_hList, g_hDesc, g_hInstr;
static HWND g_hInstall, g_hEnable, g_hDisable, g_hUninstall, g_hImport, g_hImportSc;
static HWND g_hSource, g_hSrcLabel, g_hUpdate, g_hAddBucket, g_hSearch, g_hSrchLabel, g_hCat;
static WCHAR g_catFilter[48];     /* Software tab category filter ("" = all categories) */
static WCHAR g_selectId[FM_MAX_ID]; /* command line /select:<id>: select that entry on the first fill (screenshots) */
static WCHAR g_search[64];        /* Software tab search text (name + description, case-insensitive) */
static WCHAR g_srcFilter[32];     /* Software tab source filter ("" = all sources) */
static BOOL g_startSoftware;      /* command line /software: open on the Software tab */
static BOOL g_openAddBucket;      /* command line /addbucket: open the Add bucket dialog at start (screenshots) */
static HWND g_hOK, g_hCancel, g_hApply, g_hRefresh, g_hClose;
static HFONT g_hFont = NULL;
static FM_FEATURE *g_arr = NULL;
static int g_count = 0;
static int g_tier = FM_TIER_OS;   /* selected tab: 0 = OS features, 1 = Software */
static BOOL g_populating = FALSE;  /* ignore list state notifications while (re)filling */
static BOOL g_reverting = FALSE;   /* re-entrancy guard for check-state reverts */
static HWND g_hwndMain = NULL;     /* top-level window, for the worker thread's PostMessage */
static HANDLE g_opThread = NULL;   /* in-flight background op, NULL when idle */
static BOOL g_busy = FALSE;        /* a background op is running; the UI is locked */
static HWND g_hProgress, g_hOpCancel;
static BOOL g_cancelling = FALSE;       /* Cancel was requested; waiting for the worker to stop its child */
static BOOL g_closeAfterOp = FALSE;     /* the window was closed while busy: close once the op has stopped */
static DWORD g_opStartTick;
static CRITICAL_SECTION g_progCs;       /* guards g_stepText / g_detailText / g_progPending (worker -> UI) */
static WCHAR g_stepText[512];           /* current step: "Downloading <url> (n MB), then running its installer" */
static WCHAR g_detailText[256];         /* newest line the child printed */
static BOOL g_progPending = FALSE;      /* a WM_APP_PROGRESS is already queued (coalesce) */

/* Windows "Windows Features" instruction banner (OS tier). */
static const WCHAR szOsInstr[] =
    L"To turn a feature on, select its check box. To turn a feature off, clear "
    L"its check box. A shaded box means that only part of a feature is turned on.";
static const WCHAR szSwInstr[] =
    L"To change or uninstall an installed program, select it and then click "
    L"Change or Uninstall.";

/* Why a feature cannot be disabled/uninstalled right now, mirroring the engine
 * guards (CheckRemovable / FmGetDependents). Returns 0 if allowed; otherwise
 * ERROR_ACCESS_DENIED (base component) or ERROR_DEPENDENT_SERVICES_RUNNING,
 * with the enabled dependents (comma separated) in dep. */
static DWORD RemoveGuard(const FM_FEATURE *f, LPWSTR dep, DWORD cch)
{
    if (cch) dep[0] = L'\0';
    if (!f->Removable) return ERROR_ACCESS_DENIED;
    if (FmGetDependentsIn(g_arr, g_count, f->Id, dep, cch)) return ERROR_DEPENDENT_SERVICES_RUNNING;
    return 0;
}

static void UpdateTabLabels(void)
{
    int i, n[2] = { 0, 0 }, t;
    WCHAR lbl[64];
    TCITEMW ti;
    for (i = 0; i < g_count; i++) n[g_arr[i].Tier == FM_TIER_SOFTWARE ? 1 : 0]++;
    for (t = 0; t < 2; t++)
    {
        StringCchPrintfW(lbl, ARRAYSIZE(lbl), L"%s (%d)",
                         t ? L"Software" : L"OS features", n[t]);
        ZeroMemory(&ti, sizeof(ti));
        ti.mask = TCIF_TEXT;
        ti.pszText = lbl;
        TabCtrl_SetItem(g_hTab, t, &ti);
    }
}

/* Index into g_arr of the selected row (row lParam), or -1. */
static int SelectedIndex(void)
{
    LVITEMW it;
    int sel = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);
    if (sel < 0) return -1;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_PARAM;
    it.iItem = sel;
    if (!ListView_GetItem(g_hList, &it)) return -1;
    return (int)it.lParam;
}

static void UpdateButtons(void);

/* Fill the list with the features of the selected tier (g_arr already loaded).
 * On the OS tier the list carries checkboxes whose checked state mirrors the
 * persisted Enabled state (Windows "Windows Features" dialog). */
static void Populate(LPCWSTR keepId)
{
    int i, row = 0, reselect = -1;
    BOOL os = (g_tier == FM_TIER_OS);
    LVITEMW it;

    g_populating = TRUE;
    SendMessageW(g_hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hList);
    ListView_SetExtendedListViewStyleEx(g_hList, LVS_EX_CHECKBOXES,
                                        os ? LVS_EX_CHECKBOXES : 0);

    for (i = 0; i < g_count; i++)
    {
        WCHAR buf[FM_MAX_DEPS * 2 + 64];
        if ((g_arr[i].Tier == FM_TIER_SOFTWARE ? 1 : 0) != g_tier) continue;
        if (!os && g_srcFilter[0] && _wcsicmp(g_arr[i].Source, g_srcFilter)) continue;
        if (!os && g_catFilter[0] && _wcsicmp(g_arr[i].Group, g_catFilter)) continue;
        if (!os && g_search[0] && !FmMatchSearch(&g_arr[i], g_search)) continue;

        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = row;
        it.pszText = g_arr[i].Name;
        it.lParam = i;
        ListView_InsertItem(g_hList, &it);

        StringCchPrintfW(buf, ARRAYSIZE(buf), L"%s%s", FmStateStr(g_arr[i].State),
                         g_arr[i].PayloadAvailable ? L"" : g_arr[i].Unavailable[0] ? L" (not available)" : L" (deferred)");
        ListView_SetItemText(g_hList, row, 1, buf);
        ListView_SetItemText(g_hList, row, 2, g_arr[i].Version);
        ListView_SetItemText(g_hList, row, 3, g_arr[i].InstalledVersion);
        ListView_SetItemText(g_hList, row, 4, g_arr[i].InstallDate);
        ListView_SetItemText(g_hList, row, 5, g_arr[i].Source);

        buf[0] = L'\0';
        if (g_arr[i].BuiltIn)
            StringCchCatW(buf, ARRAYSIZE(buf), L"Included in this image");
        else if (!g_arr[i].Removable)
            StringCchCatW(buf, ARRAYSIZE(buf), L"Base component");
        else if (g_arr[i].State != FM_STATE_NOT_INSTALLED)
        {
            WCHAR dep[FM_MAX_DEPS * 2];
            if (FmGetDependentsIn(g_arr, g_count, g_arr[i].Id, dep, ARRAYSIZE(dep)))
                StringCchPrintfW(buf, ARRAYSIZE(buf), L"Required by: %s", dep);
        }
        if (g_arr[i].UpdateAvailable)
        {
            WCHAR u[64];
            StringCchPrintfW(u, ARRAYSIZE(u), L"%sUpdate available: %s", buf[0] ? L"; " : L"", g_arr[i].Version);
            StringCchCatW(buf, ARRAYSIZE(buf), u);
        }
        if (g_arr[i].PendingReboot)
            StringCchCatW(buf, ARRAYSIZE(buf), buf[0] ? L"; Reboot pending" : L"Reboot pending");
        ListView_SetItemText(g_hList, row, 6, buf);

        if (os)
            ListView_SetCheckState(g_hList, row, g_arr[i].State == FM_STATE_ENABLED);

        if (keepId && !_wcsicmp(keepId, g_arr[i].Id)) reselect = row;
        row++;
    }
    if (reselect >= 0)
        ListView_SetItemState(g_hList, reselect, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
    SendMessageW(g_hList, WM_SETREDRAW, TRUE, 0);
    g_populating = FALSE;
    if (!os)
    {
        WCHAR t[256];
        int total = 0;
        for (i = 0; i < g_count; i++) if (g_arr[i].Tier == FM_TIER_SOFTWARE) total++;
        StringCchPrintfW(t, ARRAYSIZE(t), L"%s Showing %d of %d.", szSwInstr, row, total);
        SetWindowTextW(g_hInstr, t);
    }
    UpdateButtons();
}

/* Source dropdown: "All sources" + every distinct software source in the catalog (rapps,
 * command, scoop/main, scoop/extras ...), so buckets are listed as they appear. */
static void RebuildSources(void)
{
    int i, j, sel = 0, n = 0;
    WCHAR seen[32][32];

    SendMessageW(g_hSource, CB_RESETCONTENT, 0, 0);
    SendMessageW(g_hSource, CB_ADDSTRING, 0, (LPARAM)L"All sources");
    for (i = 0; i < g_count; i++)
    {
        BOOL dup = FALSE;
        if (g_arr[i].Tier != FM_TIER_SOFTWARE || !g_arr[i].Source[0]) continue;
        for (j = 0; j < n; j++) if (!_wcsicmp(seen[j], g_arr[i].Source)) { dup = TRUE; break; }
        if (dup || n >= 32) continue;
        StringCchCopyW(seen[n++], 32, g_arr[i].Source);
        SendMessageW(g_hSource, CB_ADDSTRING, 0, (LPARAM)g_arr[i].Source);
        if (g_srcFilter[0] && !_wcsicmp(g_srcFilter, g_arr[i].Source)) sel = n;
    }
    if (g_srcFilter[0] && !sel) g_srcFilter[0] = L'\0';   /* that source is gone */
    SendMessageW(g_hSource, CB_SETCURSEL, sel, 0);
}

/* Category dropdown: "All categories" + every distinct Group of the software entries (the RAPPS categories: Internet, Office,
 * Development ...; the hand-written entries' own groups). */
static void RebuildCategories(void)
{
    int i, j, sel = 0, n = 0;
    WCHAR seen[40][48];

    SendMessageW(g_hCat, CB_RESETCONTENT, 0, 0);
    SendMessageW(g_hCat, CB_ADDSTRING, 0, (LPARAM)L"All categories");
    for (i = 0; i < g_count; i++)
    {
        BOOL dup = FALSE;
        if (g_arr[i].Tier != FM_TIER_SOFTWARE || !g_arr[i].Group[0]) continue;
        for (j = 0; j < n; j++) if (!_wcsicmp(seen[j], g_arr[i].Group)) { dup = TRUE; break; }
        if (dup || n >= 40) continue;
        StringCchCopyW(seen[n++], 48, g_arr[i].Group);
        SendMessageW(g_hCat, CB_ADDSTRING, 0, (LPARAM)g_arr[i].Group);
        if (g_catFilter[0] && !_wcsicmp(g_catFilter, g_arr[i].Group)) sel = n;
    }
    if (g_catFilter[0] && !sel) g_catFilter[0] = L'\0';
    SendMessageW(g_hCat, CB_SETCURSEL, sel, 0);
}

static void FillList(void)
{
    WCHAR keep[FM_MAX_ID];
    int i = (g_arr ? SelectedIndex() : -1);
    keep[0] = L'\0';
    if (i >= 0 && i < g_count) StringCchCopyW(keep, ARRAYSIZE(keep), g_arr[i].Id);
    else if (g_selectId[0]) { StringCchCopyW(keep, ARRAYSIZE(keep), g_selectId); g_selectId[0] = L'\0'; }
    DWORD t0 = GetTickCount(), t1;
    WCHAR tf[MAX_PATH];
    ListView_DeleteAllItems(g_hList);   /* rows hold indexes into the old array */
    if (g_arr) { FmFree(g_arr); g_arr = NULL; }
    g_count = FmEnumFeatures(&g_arr);
    t1 = GetTickCount();
    UpdateTabLabels();
    RebuildSources();
    RebuildCategories();
    Populate(keep);
    /* test hook: FEATMGR_TIMING_FILE=<path> appends how long the enumeration and the list fill took */
    if (GetEnvironmentVariableW(L"FEATMGR_TIMING_FILE", tf, MAX_PATH))
    {
        FILE *f = _wfopen(tf, L"a");
        if (f)
        {
            fwprintf(f, L"gui-fill entries=%d enumerate_ms=%lu populate_ms=%lu\n", g_count, t1 - t0, GetTickCount() - t1);
            fclose(f);
        }
    }
}

static void UpdateButtons(void)
{
    int i = SelectedIndex();
    BOOL os = (g_tier == FM_TIER_OS);
    BOOL canInstall = FALSE, canEnable = FALSE, canDisable = FALSE, canUninstall = FALSE, canUpdate = FALSE;
    WCHAR text[FM_MAX_DESC + FM_MAX_DEPS * 2 + 256];

    /* While an op runs, SetBusy owns the buttons and the "Working..." text: a selection change
     * must neither re-enable a verb nor hide that the window is busy (it then looks hung). */
    if (g_busy)
        return;

    if (i >= 0 && i < g_count)
    {
        const FM_FEATURE *f = &g_arr[i];
        WCHAR dep[FM_MAX_DEPS * 2];
        DWORD guard = RemoveGuard(f, dep, ARRAYSIZE(dep));

        /* Install/Uninstall change presence; Enable/Disable toggle an installed feature. */
        canInstall   = f->State == FM_STATE_NOT_INSTALLED && f->PayloadAvailable;
        canEnable    = f->State == FM_STATE_DISABLED && f->PayloadAvailable;
        canDisable   = f->State == FM_STATE_ENABLED && !guard;
        canUninstall = f->State != FM_STATE_NOT_INSTALLED && !guard;
        canUpdate    = f->State == FM_STATE_ENABLED && f->UpdateAvailable && f->PayloadAvailable;

        StringCchPrintfW(text, ARRAYSIZE(text), L"%s", f->Description);
        if (!_wcsicmp(f->Provider, L"scoop"))
        {
            StringCchPrintfW(text + wcslen(text), ARRAYSIZE(text) - wcslen(text), L"\r\nSource: %s", f->Source);
            if (f->Homepage[0]) StringCchPrintfW(text + wcslen(text), ARRAYSIZE(text) - wcslen(text), L"   Homepage: %s", f->Homepage);
            if (f->License[0]) StringCchPrintfW(text + wcslen(text), ARRAYSIZE(text) - wcslen(text), L"   License: %s", f->License);
        }
        if (f->InstalledVersion[0])
            StringCchPrintfW(text + wcslen(text), ARRAYSIZE(text) - wcslen(text), L"\r\nInstalled version: %s%s%s",
                             f->InstalledVersion, f->UpdateAvailable ? L"   Update available: " : L"",
                             f->UpdateAvailable ? f->Version : L"");
        if (f->InstallDate[0])
            StringCchPrintfW(text + wcslen(text), ARRAYSIZE(text) - wcslen(text),
                             L"\r\nInstalled: %s", f->InstallDate);
        if (f->PendingReboot)
            StringCchCatW(text, ARRAYSIZE(text), L"\r\nA reboot is pending to finish removing this feature.");
        if (f->State != FM_STATE_NOT_INSTALLED && guard == ERROR_ACCESS_DENIED)
            StringCchCatW(text, ARRAYSIZE(text),
                L"\r\nBase component of the system: it cannot be turned off or uninstalled.");
        else if (f->State != FM_STATE_NOT_INSTALLED && guard == ERROR_DEPENDENT_SERVICES_RUNNING)
        {
            StringCchCatW(text, ARRAYSIZE(text), L"\r\nCannot be turned off or uninstalled while enabled features depend on it: ");
            StringCchCatW(text, ARRAYSIZE(text), dep);
        }
        if (!f->PayloadAvailable && f->State != FM_STATE_ENABLED && f->Unavailable[0])
        {
            StringCchCatW(text, ARRAYSIZE(text), L"\r\n");
            StringCchCatW(text, ARRAYSIZE(text), f->Unavailable);
        }
        else if (!f->PayloadAvailable && f->State != FM_STATE_ENABLED)
            StringCchCatW(text, ARRAYSIZE(text), L"\r\nPayload not staged on this system (deferred).");
        else if (f->Hosted && f->State != FM_STATE_ENABLED)
            StringCchPrintfW(text + wcslen(text), ARRAYSIZE(text) - wcslen(text),
                             L"\r\nDownloaded when turned on (%I64u MB, SHA-256 checked).",
                             (FmHostedDownloadSize(f->ManifestPath) + (1u << 20) - 1) >> 20);
        SetWindowTextW(g_hDesc, text);
    }
    else
    {
        BOOL scoopListed = FALSE;
        int k;
        for (k = 0; k < g_count; k++)
            if (!_wcsicmp(g_arr[k].Id, L"scoop")) { scoopListed = TRUE; break; }
        SetWindowTextW(g_hDesc, ListView_GetItemCount(g_hList) ?
            ((g_tier == FM_TIER_SOFTWARE && scoopListed) ?
                L"Select a feature to see its description.\r\nTip: install Scoop from the Scoop entry here (this system has no UAC split token, "
                L"so Scoop's own one-liner refuses to run as administrator), or run: iex \"&& {$(irm get.scoop.sh)} -RunAsAdmin\"" :
                L"Select a feature to see its description.") :
            (g_tier == FM_TIER_SOFTWARE ?
                L"No software entries yet. Click \"Update catalog\" to download the RAPPS catalog (needs the network)." :
                L"No OS features in the catalog."));
    }

    /* OS tier commits through OK/Apply; the per-row verbs belong to Software. */
    if (!os)
    {
        EnableWindow(g_hInstall, canInstall);
        EnableWindow(g_hEnable, canEnable);
        EnableWindow(g_hDisable, canDisable);
        EnableWindow(g_hUninstall, canUninstall);
        EnableWindow(g_hUpdate, canUpdate);
    }
}

typedef enum { ACT_INSTALL, ACT_ENABLE, ACT_DISABLE, ACT_UNINSTALL, ACT_UPDATE } ACTION;

#define OP_IMPORT 100   /* OPCTX.op value for the "Import from RAPPS" action */
#define OP_IMPORT_SCOOP 101
#define OP_ADD_BUCKET 102
#define OP_COMMIT_OS 103   /* OK / Apply on the OS tab: the checked rows, applied on the worker */

/* One OS-tab row, copied on the UI thread so the worker never touches the ListView or g_arr. */
typedef struct _OSROW
{
    WCHAR id[FM_MAX_ID];
    WCHAR name[FM_MAX_NAME];
    BOOL  checked;
    BOOL  payload;       /* PayloadAvailable */
    BOOL  wasEnabled;    /* state when the rows were copied */
} OSROW;


/* Work item handed to the background thread. Carries its own copies of the id /
 * name so the UI may free + reload g_arr while the op runs. */
typedef struct _OPCTX
{
    int     op;                  /* ACTION (install/enable/disable/uninstall) or OP_IMPORT */
    WCHAR   id[FM_MAX_ID];
    WCHAR   name[FM_MAX_NAME];
    HRESULT hr;
    int     importWritten;
    int     importSkipped;
    OSROW  *rows;                /* OP_COMMIT_OS */
    int     nrows;
    BOOL    closeAfter;
    int     failed;
    BOOL    cancelled;
    WCHAR   summary[1024];
} OPCTX;

static void LayoutProgressRow(HWND hwnd);

static void FreeOp(OPCTX *c)
{
    if (c->rows) HeapFree(GetProcessHeap(), 0, c->rows);
    HeapFree(GetProcessHeap(), 0, c);
}

/* The status text of a running op, in the description box: the current step, then the child's
 * newest output line and the time elapsed. UI thread only. */
static WCHAR g_lastStatus[1024];

/* Keep one status line on one line of the description box: cut it with "..." past n characters. */
static void Clip(LPWSTR t, size_t n)
{
    if (wcslen(t) > n)
    {
        t[n - 3] = L'.'; t[n - 2] = L'.'; t[n - 1] = L'.'; t[n] = L'\0';
    }
}

static void ShowStatus(void)
{
    WCHAR step[512], detail[256], l1[512], l2[512], text[1100];
    DWORD s = (GetTickCount() - g_opStartTick) / 1000;

    EnterCriticalSection(&g_progCs);
    StringCchCopyW(step, ARRAYSIZE(step), g_stepText);
    StringCchCopyW(detail, ARRAYSIZE(detail), g_detailText);
    LeaveCriticalSection(&g_progCs);
    if (g_cancelling)
        StringCchCopyW(l1, ARRAYSIZE(l1), L"Cancelling: stopping the running installer or script...");
    else
        StringCchCopyW(l1, ARRAYSIZE(l1), step[0] ? step : L"Working... a download or install can take a while.");
    Clip(l1, 120);
    StringCchPrintfW(l2, ARRAYSIZE(l2), L"[%lu:%02lu]  %s", s / 60, s % 60, detail);
    Clip(l2, 120);
    StringCchPrintfW(text, ARRAYSIZE(text), L"%s\r\n%s", l1, l2);
    if (wcscmp(text, g_lastStatus))
    {
        StringCchCopyW(g_lastStatus, ARRAYSIZE(g_lastStatus), text);
        SetWindowTextW(g_hDesc, text);
    }
}

/* The engine's progress sink: called ON THE WORKER THREAD. Stores the text and posts one
 * WM_APP_PROGRESS (coalesced), never touches a window directly. */
static void ProgressSink(FM_PROG_KIND kind, LPCWSTR text, void *ctx)
{
    BOOL post;
    (void)ctx;
    if (kind != FM_PROG_STEP && kind != FM_PROG_OUTPUT) return;   /* phase / byte counts are for the components window */
    EnterCriticalSection(&g_progCs);
    if (kind == FM_PROG_STEP)
    {
        StringCchCopyW(g_stepText, ARRAYSIZE(g_stepText), text);
        g_detailText[0] = L'\0';
    }
    else
        StringCchCopyW(g_detailText, ARRAYSIZE(g_detailText), text);
    post = !g_progPending;
    g_progPending = TRUE;
    LeaveCriticalSection(&g_progCs);
    if (post && g_hwndMain)
        PostMessageW(g_hwndMain, WM_APP_PROGRESS, 0, 0);
}

/* Lock / unlock every button while a background op runs; show the progress bar and the Cancel
 * button instead. The caption bar close box stays live: WM_CLOSE asks whether to cancel the op. */
static void SetBusy(HWND hwnd, BOOL busy)
{
    g_busy = busy;
    EnableWindow(g_hInstall, !busy);
    EnableWindow(g_hEnable, !busy);
    EnableWindow(g_hDisable, !busy);
    EnableWindow(g_hUninstall, !busy);
    EnableWindow(g_hUpdate, !busy);
    EnableWindow(g_hAddBucket, !busy);
    EnableWindow(g_hSearch, !busy);
    EnableWindow(g_hImport, !busy);
    EnableWindow(g_hImportSc, !busy);
    EnableWindow(g_hSource, !busy);
    EnableWindow(g_hRefresh, !busy);
    EnableWindow(g_hClose, !busy);
    EnableWindow(g_hOK, !busy);
    EnableWindow(g_hCancel, !busy);
    EnableWindow(g_hApply, !busy);
    EnableWindow(g_hTab, !busy);
    EnableWindow(g_hOpCancel, busy);
    if (busy)
    {
        g_cancelling = FALSE;
        g_lastStatus[0] = L'\0';
        g_opStartTick = GetTickCount();
        EnterCriticalSection(&g_progCs);
        g_stepText[0] = g_detailText[0] = L'\0';
        LeaveCriticalSection(&g_progCs);
        SetTimer(hwnd, IDT_ELAPSED, 1000, NULL);
    }
    else
        KillTimer(hwnd, IDT_ELAPSED);
    ShowWindow(g_hProgress, busy ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hOpCancel, busy ? SW_SHOW : SW_HIDE);
    SendMessageW(g_hProgress, PBM_SETMARQUEE, busy, 30);
    LayoutProgressRow(hwnd);
    if (busy)
    {
        /* the focused verb button was just disabled: put the focus on the list, so the keyboard stays usable
         * (Alt+O reaches Cancel operation; with the focus ON that button its own mnemonic is not delivered) */
        SetFocus(g_hList);
        ShowStatus();
    }
}

/* Stop the running op: the engine ends the child process tree by its own handle and the op
 * returns ERROR_CANCELLED; the worker then posts WM_APP_OPDONE as usual. */
static void BeginCancel(void)
{
    g_cancelling = TRUE;
    EnableWindow(g_hOpCancel, FALSE);
    FmOpCancel();
    ShowStatus();
}

/* Apply the checkbox selection (worker thread). Enables happen first; disables run in repeated
 * passes so that a dependent unchecked in the same batch is turned off before the feature it
 * depends on (the engine refuses an in-use disable). Fills c->failed / c->summary; c->cancelled
 * when Cancel stopped it (what was already applied stays applied, the list is reloaded after). */
static void ApplyOsRows(OPCTX *c)
{
    int i, done = 0, failed = 0, pass;
    WCHAR line[256];
    HRESULT hr;

    c->summary[0] = L'\0';

    /* Pass 1: enable everything newly checked (install-on-check for NotInstalled). */
    for (i = 0; i < c->nrows; i++)
    {
        const OSROW *r = &c->rows[i];
        if (!r->checked || r->wasEnabled) continue;
        if (!r->payload) { failed++; continue; }
        if (FmOpCancelled()) { c->cancelled = TRUE; goto out; }
        FmOpStep(L"Turning on %s", r->name);
        hr = FmEnable(r->id, NULL);
        if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) { c->cancelled = TRUE; goto out; }
        if (SUCCEEDED(hr)) done++;
        else failed++;
    }

    /* Passes 2..N: disable everything newly unchecked, retrying blocked ones so
     * dependents (also unchecked) clear first. Stop when a pass makes no change. */
    for (pass = 0; pass < c->nrows + 1; pass++)
    {
        int progress = 0;
        for (i = 0; i < c->nrows; i++)
        {
            const OSROW *r = &c->rows[i];
            if (r->checked) continue;
            if (FmGetState(r->id) != FM_STATE_ENABLED) continue;  /* already off */
            if (FmOpCancelled()) { c->cancelled = TRUE; goto out; }
            FmOpStep(L"Turning off %s", r->name);
            hr = FmDisable(r->id, NULL);
            if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED)) { c->cancelled = TRUE; goto out; }
            if (SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED))
            {
                done++; progress++;
            }
        }
        if (!progress) break;
    }

    /* Anything still enabled but unchecked, or unchecked+enabled that refused. */
    for (i = 0; i < c->nrows; i++)
    {
        const OSROW *r = &c->rows[i];
        if (r->checked) continue;
        if (FmGetState(r->id) == FM_STATE_ENABLED)
        {
            failed++;
            StringCchPrintfW(line, ARRAYSIZE(line), L"\r\n  %s could not be turned off.", r->name);
            StringCchCatW(c->summary, ARRAYSIZE(c->summary), line);
        }
    }
out:
    c->failed = failed;
    (void)done;
}

/* Runs on the worker thread: performs the (possibly slow) engine op, then posts
 * the result back to the UI thread. Never touches the ListView / g_arr. */
static DWORD WINAPI OpThreadProc(LPVOID param)
{
    OPCTX *c = (OPCTX *)param;
    switch (c->op)
    {
        case ACT_INSTALL:
        case ACT_ENABLE:    c->hr = FmEnable(c->id, NULL); break;
        case ACT_DISABLE:   c->hr = FmDisable(c->id, NULL); break;
        case ACT_UNINSTALL: c->hr = FmUninstall(c->id, NULL); break;
        case ACT_UPDATE:    c->hr = FmUpdate(c->id, NULL); break;
        case OP_ADD_BUCKET: c->hr = FmScoopAddBucket(c->name, NULL, 0, NULL); break;
        case OP_COMMIT_OS:  ApplyOsRows(c); c->hr = S_OK; break;
        case OP_IMPORT:
            FmOpStep(L"Updating the RAPPS catalog");
            FmSetLastMessage(L"");
            c->importWritten = FmImportRapps(NULL, FM_IMPORT_CLEAN | FM_IMPORT_REFETCH, &c->importSkipped, NULL);
            c->hr = (c->importWritten < 0) ? E_FAIL : S_OK;
            break;
        case OP_IMPORT_SCOOP:
            FmOpStep(L"Importing the Scoop buckets");
            FmSetLastMessage(L"");
            c->importWritten = FmImportScoop(NULL, NULL, 0, 0, &c->importSkipped, NULL);
            c->hr = (c->importWritten < 0) ? E_FAIL : S_OK;
            break;
        default:            c->hr = E_FAIL; break;
    }
    if (g_hwndMain)
        PostMessageW(g_hwndMain, WM_APP_OPDONE, 0, (LPARAM)c);
    else
        FreeOp(c);
    return 0;
}

/* Start one op on the worker thread (UI stays responsive). Takes ownership of c. */
static void StartOp(HWND hwnd, OPCTX *c)
{
    if (g_busy) { FreeOp(c); return; }
    g_closeAfterOp = FALSE;
    FmOpBegin(ProgressSink, NULL);      /* arm cancel + progress before the worker exists */
    SetBusy(hwnd, TRUE);
    g_opThread = CreateThread(NULL, 0, OpThreadProc, c, 0, NULL);
    if (!g_opThread)
    {
        /* no thread: run inline, the posted message is handled when we return */
        OpThreadProc(c);
    }
}

static void DoAction(HWND hwnd, ACTION act)
{
    int i = SelectedIndex();
    OPCTX *c;
    if (g_busy) return;
    if (i < 0 || i >= g_count) return;

    if (act == ACT_UNINSTALL)
    {
        WCHAR msg[768];
        StringCchPrintfW(msg, ARRAYSIZE(msg),
            L"Uninstall '%s'?\n\nIt will be turned off and its record removed; "
            L"it returns to Not installed.%s", g_arr[i].Name,
            !_wcsicmp(g_arr[i].Id, L"scoop") ?
                L"\n\nThis also removes Scoop's apps and their persisted data (C:\\scoop)." : L"");
        if (MessageBoxW(hwnd, msg, BRAND_PRODUCT_NAME_W L" Features", MB_YESNO | MB_ICONQUESTION) != IDYES)
            return;
    }

    if ((act == ACT_INSTALL || act == ACT_ENABLE) && g_arr[i].Notice[0] && g_arr[i].State != FM_STATE_ENABLED)
    {
        WCHAR msg[1024];
        StringCchPrintfW(msg, ARRAYSIZE(msg), L"%s\n\nTurn on '%s'?", g_arr[i].Notice, g_arr[i].Name);
        if (MessageBoxW(hwnd, msg, g_arr[i].Name, MB_OKCANCEL | MB_ICONINFORMATION) != IDOK)
            return;
    }

    c = (OPCTX *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
    if (!c) return;
    c->op = act;
    StringCchCopyW(c->id, ARRAYSIZE(c->id), g_arr[i].Id);
    StringCchCopyW(c->name, ARRAYSIZE(c->name), g_arr[i].Name);
    StartOp(hwnd, c);
}

/* "Update catalog": download the RAPPS online catalog (featmgr's own fetch) and rebuild the Software entries from it. */
static void DoImport(HWND hwnd)
{
    OPCTX *c;
    if (g_busy) return;
    c = (OPCTX *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
    if (!c) return;
    c->op = OP_IMPORT;
    StartOp(hwnd, c);
}

/* "Import Scoop": official buckets that Scoop already has on disk -> Software tab entries. */
static void DoImportScoop(HWND hwnd)
{
    OPCTX *c;
    if (g_busy) return;
    c = (OPCTX *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
    if (!c) return;
    c->op = OP_IMPORT_SCOOP;
    StartOp(hwnd, c);
}

/* "Add bucket...": Scoop's own list of known buckets, nothing else. The checkbox is the explicit
 * confirmation. Any other bucket (an arbitrary URL) is command-line only: featmgr /add-bucket <name> <url> /trust. */
static FM_BUCKET g_kb[FM_BUCKET_MAX];
static int g_nkb;
static WCHAR g_pickedBucket[24];

static void AddBucketShowUrl(HWND dlg)
{
    int sel = (int)SendDlgItemMessageW(dlg, IDC_AB_COMBO, CB_GETCURSEL, 0, 0);
    WCHAR t[256], nm[24];
    int i;
    t[0] = L'\0';
    if (sel >= 0)
    {
        SendDlgItemMessageW(dlg, IDC_AB_COMBO, CB_GETLBTEXT, sel, (LPARAM)nm);
        for (i = 0; i < g_nkb; i++)
            if (!_wcsicmp(g_kb[i].Name, nm))
                StringCchPrintfW(t, ARRAYSIZE(t), L"%s", g_kb[i].Url[0] ? g_kb[i].Url : L"(address from Scoop's list)");
    }
    SetDlgItemTextW(dlg, IDC_AB_URL, t);
}

static INT_PTR CALLBACK AddBucketProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            int i;
            g_nkb = FmScoopKnownBuckets(g_kb, FM_BUCKET_MAX);
            for (i = 0; i < g_nkb; i++)
                if (!g_kb[i].Added)
                    SendDlgItemMessageW(dlg, IDC_AB_COMBO, CB_ADDSTRING, 0, (LPARAM)g_kb[i].Name);
            SendDlgItemMessageW(dlg, IDC_AB_COMBO, CB_SETCURSEL, 0, 0);
            AddBucketShowUrl(dlg);
            return TRUE;
        }
        case WM_COMMAND:
            switch (LOWORD(wp))
            {
                case IDC_AB_COMBO:
                    if (HIWORD(wp) == CBN_SELCHANGE) AddBucketShowUrl(dlg);
                    return TRUE;
                case IDC_AB_TRUST:
                    EnableWindow(GetDlgItem(dlg, IDOK),
                        IsDlgButtonChecked(dlg, IDC_AB_TRUST) == BST_CHECKED
                        && SendDlgItemMessageW(dlg, IDC_AB_COMBO, CB_GETCURSEL, 0, 0) >= 0);
                    return TRUE;
                case IDOK:
                {
                    int sel = (int)SendDlgItemMessageW(dlg, IDC_AB_COMBO, CB_GETCURSEL, 0, 0);
                    if (sel < 0 || IsDlgButtonChecked(dlg, IDC_AB_TRUST) != BST_CHECKED) return TRUE;
                    SendDlgItemMessageW(dlg, IDC_AB_COMBO, CB_GETLBTEXT, sel, (LPARAM)g_pickedBucket);
                    EndDialog(dlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(dlg, IDCANCEL);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

static void DoAddBucket(HWND hwnd)
{
    OPCTX *c;
    if (g_busy) return;
    if (!FmScoopAppInstalled(L"scoop"))
    {
        MessageBoxW(hwnd, L"Scoop is not installed. Select the 'scoop' entry and click Install first.",
                    L"Add Scoop bucket", MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_ADDBUCKET), hwnd, AddBucketProc, 0) != IDOK)
        return;
    c = (OPCTX *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
    if (!c) return;
    c->op = OP_ADD_BUCKET;
    StringCchCopyW(c->name, ARRAYSIZE(c->name), g_pickedBucket);
    StartOp(hwnd, c);
}

/* UI-thread completion handler for a background op (WM_APP_OPDONE). */
static void OnOpDone(HWND hwnd, OPCTX *c)
{
    WCHAR msg[2400];
    UINT icon = MB_ICONINFORMATION;
    LPCWSTR caption = BRAND_PRODUCT_NAME_W L" Features";

    BOOL cancelled;

    if (g_opThread) { CloseHandle(g_opThread); g_opThread = NULL; }
    cancelled = c->cancelled || (FAILED(c->hr) && (c->hr == HRESULT_FROM_WIN32(ERROR_CANCELLED) || FmOpCancelled()));
    FmOpEnd();
    g_cancelling = FALSE;
    SetBusy(hwnd, FALSE);

    if (g_closeAfterOp)
    {
        /* the window was closed while the op ran and the user chose to cancel and close */
        FreeOp(c);
        DestroyWindow(hwnd);
        return;
    }

    if (cancelled)
    {
        /* the engine says what it did (stopped the child at once; or let a Windows Installer package finish
         * and removed it again, because a package killed part-way is not rolled back) */
        WCHAR why[1024];
        FmGetLastMessage(why, ARRAYSIZE(why));
        StringCchPrintfW(msg, ARRAYSIZE(msg),
            L"%s\n\nNothing was recorded as installed or removed by the step that was stopped; the list shows "
            L"the current state. Run the action again to retry.",
            why[0] ? why : L"The operation was cancelled.");
        icon = MB_ICONWARNING;
        if (c->op == OP_COMMIT_OS)
            StringCchCatW(msg, ARRAYSIZE(msg), L"\n\nChanges that finished before Cancel stay applied.");
    }
    else if (c->op == OP_COMMIT_OS)
    {
        caption = BRAND_PRODUCT_NAME_W L" Features";
        if (c->failed)
        {
            StringCchPrintfW(msg, ARRAYSIZE(msg),
                L"Some features could not be changed. Base components cannot be turned "
                L"off, deferred payloads cannot be turned on, and a feature in use by "
                L"another enabled feature stays on.%s", c->summary);
            icon = MB_ICONWARNING;
            c->closeAfter = FALSE;   /* keep the dialog open so the user sees the corrected state */
        }
        else
            StringCchCopyW(msg, ARRAYSIZE(msg), BRAND_PRODUCT_NAME_W L" has applied the requested changes.");
        FmTakePathChange(NULL, 0);      /* the system-features summary has no PATH hint: drop a stale flag */
    }
    else if (c->op == OP_IMPORT)
    {
        caption = L"Update catalog";
        if (SUCCEEDED(c->hr))
        {
            WCHAR why[1024];
            FmGetLastMessage(why, ARRAYSIZE(why));
            StringCchPrintfW(msg, ARRAYSIZE(msg),
                L"The Software tab now lists %d program(s) from the RAPPS catalog (%d entries were not offered: "
                L"no checksum, another Windows version, or replaced by a built-in entry).", c->importWritten, c->importSkipped);
            if (why[0])     /* the download failed but an earlier catalog was there: say so */
            {
                StringCchCatW(msg, ARRAYSIZE(msg), L"\n\nThe online catalog could not be downloaded, so this list comes from the last "
                              L"download:\n");
                StringCchCatW(msg, ARRAYSIZE(msg), why);
                icon = MB_ICONWARNING;
            }
        }
        else
        {
            WCHAR why[1024];
            FmGetLastMessage(why, ARRAYSIZE(why));
            StringCchPrintfW(msg, ARRAYSIZE(msg),
                L"Could not update the catalog. The online RAPPS catalog could not be downloaded: check the network "
                L"connection, then try again.%s%s", why[0] ? L"\n\n" : L"", why);
            icon = MB_ICONWARNING;
        }
    }
    else if (c->op == OP_ADD_BUCKET)
    {
        caption = L"Add Scoop bucket";
        if (SUCCEEDED(c->hr))
            StringCchPrintfW(msg, ARRAYSIZE(msg), L"Bucket '%s' was added to Scoop and its apps were imported into the "
                             L"Software tab (filter by Source: scoop/%s).", c->name, c->name);
        else
        {
            WCHAR why[1024];
            FmGetLastMessage(why, ARRAYSIZE(why));
            StringCchPrintfW(msg, ARRAYSIZE(msg), L"Could not add bucket '%s'.\n\n%s\n\nScoop adds buckets with git: "
                             L"if git is missing, install the 'git' entry first.", c->name, why);
            icon = MB_ICONWARNING;
        }
    }
    else if (c->op == OP_IMPORT_SCOOP)
    {
        caption = L"Import Scoop";
        if (SUCCEEDED(c->hr))
            StringCchPrintfW(msg, ARRAYSIZE(msg),
                L"Imported %d Scoop app(s) into the Software tab (%d skipped: no download for "
                L"this machine, or no hash to verify it against). Install runs 'scoop install'; "
                L"Scoop checks every download against its manifest hash.", c->importWritten, c->importSkipped);
        else
        {
            WCHAR why[1024];
            FmGetLastMessage(why, ARRAYSIZE(why));
            StringCchPrintfW(msg, ARRAYSIZE(msg), L"Could not import Scoop apps.\n\n%s",
                             why[0] ? why : L"Scoop is not installed. Select the 'scoop' entry and click Install first.");
            icon = MB_ICONWARNING;
        }
    }
    else
    {
        ACTION act = (ACTION)c->op;
        HRESULT hr = c->hr;
        WCHAR pathName[128];
        if (hr == HRESULT_FROM_WIN32(ERROR_SUCCESS_REBOOT_REQUIRED))
            StringCchPrintfW(msg, ARRAYSIZE(msg), L"'%s' was turned off, but some components "
                             L"are removed at the next reboot. It stays listed until then.", c->name);
        else if (SUCCEEDED(hr))
        {
            static const LPCWSTR done[] = { L"installed and enabled", L"enabled",
                                            L"disabled and reverted", L"uninstalled", L"updated" };
            FM_FEATURE nf;
            if (act == ACT_UPDATE && FmFindFeature(c->id, &nf) && nf.InstalledVersion[0])
                StringCchPrintfW(msg, ARRAYSIZE(msg), L"'%s' is now at version %s.", c->name, nf.InstalledVersion);
            else
                StringCchPrintfW(msg, ARRAYSIZE(msg), L"'%s' %s.", c->name, done[act]);
            if ((act == ACT_INSTALL || act == ACT_ENABLE) && FmTakePathChange(pathName, ARRAYSIZE(pathName)))
                StringCchCatW(msg, ARRAYSIZE(msg), FmRefreshEnvAvailable() ?
                    L"\n\nIt changed the PATH. Terminal windows that are already open keep the old one: "
                    L"open a new terminal, or type  refreshenv  in an open one."
                    : L"\n\nIt changed the PATH. Terminal windows that are already open keep the old one: "
                    L"open a new terminal (or sign out and in) to use it.");
        }
        else if (hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED) &&
                 (act == ACT_DISABLE || act == ACT_UNINSTALL))
        {
            StringCchPrintfW(msg, ARRAYSIZE(msg), L"'%s' is a base component of the system "
                             L"and cannot be disabled or removed.", c->name);
            icon = MB_ICONWARNING;
        }
        else if (hr == HRESULT_FROM_WIN32(ERROR_DEPENDENT_SERVICES_RUNNING))
        {
            WCHAR dep[FM_MAX_DEPS * 2];
            FmGetDependents(c->id, dep, ARRAYSIZE(dep));
            StringCchPrintfW(msg, ARRAYSIZE(msg), L"'%s' cannot be turned off while other enabled "
                             L"features depend on it (%s). Turn those off first.", c->name, dep);
            icon = MB_ICONWARNING;
        }
        else
        {
            WCHAR why[1024];
            FmGetLastMessage(why, ARRAYSIZE(why));
            if (why[0])
                StringCchPrintfW(msg, ARRAYSIZE(msg), L"'%s': operation failed (0x%08lx).\n\n%s", c->name, hr, why);
            else
                StringCchPrintfW(msg, ARRAYSIZE(msg), L"Operation failed (0x%08lx).\n\n"
                                 L"For a software item the download or installer may have failed; "
                                 L"for a deferred OS feature the payload is not staged on this system yet.", hr);
            icon = MB_ICONWARNING;
        }
    }

    if (cancelled && c->op == OP_COMMIT_OS) caption = BRAND_PRODUCT_NAME_W L" Features";
    {
        BOOL closeAfter = c->closeAfter && !cancelled;
        FreeOp(c);
        FillList();   /* reloads state + re-enables the per-row verbs */
        SetFocus(g_hList);
        MessageBoxW(hwnd, msg, caption, MB_OK | icon);
        if (closeAfter) DestroyWindow(hwnd);
    }
}

/* --- OS tier: commit the checkbox selection, Windows "Windows Features" style --- */

/* TRUE if any checkbox differs from the persisted state. */
static BOOL OsHasPendingChanges(void)
{
    int row, n = ListView_GetItemCount(g_hList);
    LVITEMW it;
    if (g_tier != FM_TIER_OS) return FALSE;
    for (row = 0; row < n; row++)
    {
        BOOL checked = ListView_GetCheckState(g_hList, row);
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_PARAM; it.iItem = row;
        if (!ListView_GetItem(g_hList, &it)) continue;
        if ((int)it.lParam < g_count &&
            checked != (g_arr[it.lParam].State == FM_STATE_ENABLED))
            return TRUE;
    }
    return FALSE;
}

/* OK / Apply: copy the rows on the UI thread, apply them on the worker (a feature's files, registry and
 * services can take a while, and nothing here may stall the message loop). */
static void CommitOs(HWND hwnd, BOOL closeAfter)
{
    int row, n, k = 0;
    OPCTX *c;
    OSROW *rows;
    LVITEMW it;

    if (!OsHasPendingChanges())
    {
        if (closeAfter) DestroyWindow(hwnd);
        return;
    }
    n = ListView_GetItemCount(g_hList);
    c = (OPCTX *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
    rows = (OSROW *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n ? n : 1) * sizeof(OSROW));
    if (!c || !rows)
    {
        if (c) HeapFree(GetProcessHeap(), 0, c);
        if (rows) HeapFree(GetProcessHeap(), 0, rows);
        return;
    }
    for (row = 0; row < n; row++)
    {
        const FM_FEATURE *f;
        ZeroMemory(&it, sizeof(it)); it.mask = LVIF_PARAM; it.iItem = row;
        if (!ListView_GetItem(g_hList, &it) || (int)it.lParam >= g_count) continue;
        f = &g_arr[it.lParam];
        StringCchCopyW(rows[k].id, ARRAYSIZE(rows[k].id), f->Id);
        StringCchCopyW(rows[k].name, ARRAYSIZE(rows[k].name), f->Name);
        rows[k].checked = ListView_GetCheckState(g_hList, row);
        rows[k].payload = f->PayloadAvailable;
        rows[k].wasEnabled = (f->State == FM_STATE_ENABLED);
        k++;
    }
    c->op = OP_COMMIT_OS;
    c->rows = rows;
    c->nrows = k;
    c->closeAfter = closeAfter;
    StartOp(hwnd, c);
}

/* Reject check-state changes the engine would refuse outright, so the dialog
 * never shows an illegal pending selection (Windows greys / snaps these back). */
static void OnOsCheck(int row, BOOL nowChecked)
{
    LVITEMW it;
    const FM_FEATURE *f;
    LPCWSTR why = NULL;

    ZeroMemory(&it, sizeof(it)); it.mask = LVIF_PARAM; it.iItem = row;
    if (!ListView_GetItem(g_hList, &it) || (int)it.lParam >= g_count) return;
    f = &g_arr[it.lParam];

    if (!nowChecked && f->State == FM_STATE_ENABLED && !f->Removable)
        why = f->BuiltIn ? L"is included in this NitroOS image and cannot be turned off here."
                         : L"is a base component of the system and cannot be turned off.";
    else if (nowChecked && f->State != FM_STATE_ENABLED && !f->PayloadAvailable)
        why = f->Unavailable[0] ? f->Unavailable : L"has a deferred payload that is not staged on this system yet.";

    if (why)
    {
        WCHAR msg[512];
        StringCchPrintfW(msg, ARRAYSIZE(msg), (why == f->Unavailable) ? L"'%s': %s" : L"'%s' %s", f->Name, why);
        g_reverting = TRUE;
        ListView_SetCheckState(g_hList, row, !nowChecked);  /* snap back */
        g_reverting = FALSE;
        SetWindowTextW(g_hDesc, msg);
    }
}

/* The description box and the busy row under it. While busy the box's bottom 22 px become the
 * progress bar and the Cancel operation button; the rest of the window does not move (a full
 * LayoutButtons per op would repaint the whole tab area and leave the Search box half drawn). */
static void LayoutProgressRow(HWND hwnd)
{
    RECT rc;
    int rowH = 22, cw = 132, descH = 62, bh = 26, y, descY;
    GetClientRect(hwnd, &rc);
    y = rc.bottom - bh - 12;
    descY = y - 8 - descH;
    MoveWindow(g_hDesc, 12, descY, rc.right - 24, g_busy ? descH - rowH - 2 : descH, TRUE);
    MoveWindow(g_hProgress, 12, descY + descH - rowH, rc.right - 24 - cw - 6, rowH, TRUE);
    MoveWindow(g_hOpCancel, rc.right - 12 - cw, descY + descH - rowH, cw, rowH, TRUE);
}

/* Position the per-tab button rows. The OS tier reads like "Windows Features"
 * (OK / Cancel / Apply, with an Uninstall for the forget-record verb); the
 * Software tier reads like "Programs and Features" (Install / Change / verbs). */
static void LayoutButtons(HWND hwnd)
{
    BOOL os = (g_tier == FM_TIER_OS);
    RECT rc;
    int y, right, bw = 92, bh = 26, gap = 6;
    GetClientRect(hwnd, &rc);
    y = rc.bottom - bh - 12;
    right = rc.right - 12;

    ShowWindow(g_hOK,       os ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hCancel,   os ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hApply,    os ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hInstall,  os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hEnable,   os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hDisable,  os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hClose,    os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hImport,   os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hImportSc, os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hUpdate,   os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hAddBucket, os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hSource,   os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hCat,      os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hSrcLabel, os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hSearch,   os ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hSrchLabel, os ? SW_HIDE : SW_SHOW);

    /* the main controls follow the client size (the window is wider than M1: ten verbs + a search box) */
    {
        /* the desc box keeps its place; while busy its bottom 22 px become the progress row */
        int descH = 62, tabY = 64, descY = y - 8 - descH, tabH = descY - 8 - tabY;
        MoveWindow(g_hInstr, 12, 30, rc.right - 24, 30, TRUE);
        MoveWindow(g_hTab, 12, tabY, rc.right - 24, tabH, TRUE);
        MoveWindow(g_hList, 18, tabY + 30, rc.right - 36, tabH - 38, TRUE);
        LayoutProgressRow(hwnd);
        MoveWindow(g_hSrchLabel, 262, tabY + 5, 46, 18, TRUE);
        MoveWindow(g_hSearch, 310, tabY + 1, 170, 22, TRUE);
        MoveWindow(g_hSource, rc.right - 12 - 222, tabY + 1, 222, 200, TRUE);
        MoveWindow(g_hCat, 490, tabY + 1, 140, 200, TRUE);
        MoveWindow(g_hSrcLabel, rc.right - 12 - 222 - 50, tabY + 5, 46, 18, TRUE);
    }

    if (os)
    {
        MoveWindow(g_hApply,  right - bw,               y, bw, bh, TRUE);
        MoveWindow(g_hCancel, right - 2 * bw - gap,     y, bw, bh, TRUE);
        MoveWindow(g_hOK,     right - 3 * bw - 2 * gap, y, bw, bh, TRUE);
        MoveWindow(g_hUninstall, 12,                    y, bw, bh, TRUE);
        MoveWindow(g_hRefresh,   12 + bw + gap,         y, bw, bh, TRUE);
    }
    else
    {
        bw = 80; gap = 4;       /* ten verbs in one row (the catalog button is one and a half wide) */
        if (10 * bw + bw / 2 + 9 * gap > rc.right - 24) bw = (rc.right - 24 - 9 * gap) * 2 / 21;
        {
            int cw = bw + bw / 2;       /* "Update catalog" is longer than the other verbs */
            MoveWindow(g_hInstall,   12,                    y, bw, bh, TRUE);
            MoveWindow(g_hEnable,    12 + (bw + gap),       y, bw, bh, TRUE);
            MoveWindow(g_hDisable,   12 + 2 * (bw + gap),   y, bw, bh, TRUE);
            MoveWindow(g_hUninstall, 12 + 3 * (bw + gap),   y, bw, bh, TRUE);
            MoveWindow(g_hUpdate,    12 + 4 * (bw + gap),   y, bw, bh, TRUE);
            MoveWindow(g_hImport,    12 + 5 * (bw + gap),   y, cw, bh, TRUE);
            MoveWindow(g_hImportSc,  12 + 5 * (bw + gap) + cw + gap,            y, bw, bh, TRUE);
            MoveWindow(g_hAddBucket, 12 + 6 * (bw + gap) + cw + gap,            y, bw, bh, TRUE);
        }
        MoveWindow(g_hClose,  right - bw,               y, bw, bh, TRUE);
        MoveWindow(g_hRefresh, right - 2 * bw - gap,    y, bw, bh, TRUE);
    }
    SetWindowTextW(g_hInstr, os ? szOsInstr : szSwInstr);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            LVCOLUMNW col;
            TCITEMW ti;
            NONCLIENTMETRICSW ncm;
            HWND hHdr;

            /* Authentic dialog typeface (Tahoma/Segoe per theme), not the old
             * bitmap DEFAULT_GUI_FONT - this is what makes it read as native. */
            ZeroMemory(&ncm, sizeof(ncm));
            ncm.cbSize = sizeof(ncm);
            if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
                g_hFont = CreateFontIndirectW(&ncm.lfMessageFont);
            if (!g_hFont)
                g_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            hHdr = CreateWindowExW(0, L"STATIC", L"Turn " BRAND_PRODUCT_NAME_W L" features on or off",
                WS_CHILD | WS_VISIBLE, 12, 10, 708, 18, hwnd, NULL, NULL, NULL);
            g_hInstr = CreateWindowExW(0, L"STATIC", szOsInstr,
                WS_CHILD | WS_VISIBLE, 12, 30, 708, 30, hwnd,
                (HMENU)(INT_PTR)IDC_INSTR, NULL, NULL);

            /* two tiers = two tabs; one list shows the selected tier's features */
            g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"",
                WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP,
                12, 64, 716, 300, hwnd, (HMENU)(INT_PTR)IDC_TAB, NULL, NULL);
            ZeroMemory(&ti, sizeof(ti));
            ti.mask = TCIF_TEXT;
            ti.pszText = (LPWSTR)L"OS features";
            TabCtrl_InsertItem(g_hTab, 0, &ti);
            ti.pszText = (LPWSTR)L"Software";
            TabCtrl_InsertItem(g_hTab, 1, &ti);

            g_hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                18, 94, 704, 262, hwnd, (HMENU)(INT_PTR)IDC_LIST, NULL, NULL);
            ListView_SetExtendedListViewStyle(g_hList,
                LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES);

            ZeroMemory(&col, sizeof(col));
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.pszText = (LPWSTR)L"Feature";   col.cx = 165; ListView_InsertColumn(g_hList, 0, &col);
            col.pszText = (LPWSTR)L"State";     col.cx = 95;  ListView_InsertColumn(g_hList, 1, &col);
            col.pszText = (LPWSTR)L"Version";   col.cx = 80;  ListView_InsertColumn(g_hList, 2, &col);
            col.pszText = (LPWSTR)L"Installed version"; col.cx = 110; ListView_InsertColumn(g_hList, 3, &col);
            col.pszText = (LPWSTR)L"Installed (UTC)"; col.cx = 120; ListView_InsertColumn(g_hList, 4, &col);
            col.pszText = (LPWSTR)L"Source";    col.cx = 90;  ListView_InsertColumn(g_hList, 5, &col);
            col.pszText = (LPWSTR)L"Notes";     col.cx = 190; ListView_InsertColumn(g_hList, 6, &col);

            g_hDesc = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC",
                L"Select a feature to see its description.",
                WS_CHILD | WS_VISIBLE, 12, 372, 716, 62, hwnd, (HMENU)(INT_PTR)IDC_DESC, NULL, NULL);

            /* shown only while a background op runs: marquee bar + Cancel operation */
            g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, L"",
                WS_CHILD | PBS_MARQUEE, 12, 400, 560, 22, hwnd, (HMENU)(INT_PTR)IDC_PROGRESS, NULL, NULL);
            g_hOpCancel = CreateWindowExW(0, L"BUTTON", L"Cancel &operation",
                WS_CHILD | WS_TABSTOP, 0, 0, 132, 22, hwnd, (HMENU)(INT_PTR)IDC_OPCANCEL, NULL, NULL);

            /* OS-tier commit row (Windows "Windows Features" style). */
            g_hOK = CreateWindowExW(0, L"BUTTON", L"OK",
                WS_CHILD | WS_TABSTOP | BS_DEFPUSHBUTTON, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_OK, NULL, NULL);
            g_hCancel = CreateWindowExW(0, L"BUTTON", L"Cancel",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_CANCEL, NULL, NULL);
            g_hApply = CreateWindowExW(0, L"BUTTON", L"&Apply",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_APPLY, NULL, NULL);

            /* Software-tier verb row ("Programs and Features" style). */
            g_hInstall = CreateWindowExW(0, L"BUTTON", L"&Install",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_INSTALL, NULL, NULL);
            g_hEnable = CreateWindowExW(0, L"BUTTON", L"&Enable",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_ENABLE, NULL, NULL);
            g_hDisable = CreateWindowExW(0, L"BUTTON", L"&Disable",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_DISABLE, NULL, NULL);
            g_hUninstall = CreateWindowExW(0, L"BUTTON", L"&Uninstall",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_UNINSTALL, NULL, NULL);
            g_hRefresh = CreateWindowExW(0, L"BUTTON", L"Re&fresh",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_REFRESH, NULL, NULL);
            g_hClose = CreateWindowExW(0, L"BUTTON", L"&Close",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_CLOSE, NULL, NULL);
            /* Software-tier: populate the tab from the RAPPS database on demand. */
            g_hImport = CreateWindowExW(0, L"BUTTON", L"Update &catalog",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_IMPORT, NULL, NULL);

            /* Software-tier: Scoop import + the source filter (rapps / command / scoop buckets). */
            g_hImportSc = CreateWindowExW(0, L"BUTTON", L"Import &Scoop",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_IMPORTSC, NULL, NULL);
            g_hUpdate = CreateWindowExW(0, L"BUTTON", L"U&pdate",
                WS_CHILD | WS_TABSTOP | WS_DISABLED, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_UPDATE, NULL, NULL);
            g_hAddBucket = CreateWindowExW(0, L"BUTTON", L"Add &bucket...",
                WS_CHILD | WS_TABSTOP, 0, 0, 90, 26, hwnd,
                (HMENU)(INT_PTR)IDC_ADDBUCKET, NULL, NULL);
            g_hSrchLabel = CreateWindowExW(0, L"STATIC", L"Search:",
                WS_CHILD, 262, 69, 46, 18, hwnd, (HMENU)(INT_PTR)IDC_SRCHLABEL, NULL, NULL);
            g_hSearch = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_search,
                WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 310, 65, 170, 22, hwnd,
                (HMENU)(INT_PTR)IDC_SEARCH, NULL, NULL);
            SendMessageW(g_hSearch, EM_LIMITTEXT, ARRAYSIZE(g_search) - 1, 0);
            g_hSrcLabel = CreateWindowExW(0, L"STATIC", L"Source:",
                WS_CHILD, 452, 69, 44, 18, hwnd, (HMENU)(INT_PTR)IDC_SRCLABEL, NULL, NULL);
            g_hSource = CreateWindowExW(0, L"COMBOBOX", L"",
                WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
                498, 65, 222, 200, hwnd, (HMENU)(INT_PTR)IDC_SOURCE, NULL, NULL);
            SetWindowPos(g_hSource, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            g_hCat = CreateWindowExW(0, L"COMBOBOX", L"",
                WS_CHILD | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST,
                490, 65, 140, 200, hwnd, (HMENU)(INT_PTR)IDC_CATEGORY, NULL, NULL);
            SetWindowPos(g_hCat, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            /* the tab repaints over its siblings below it when an op disables and re-enables it: keep the
             * labels and the search box above it too (they vanished after every op) */
            SetWindowPos(g_hSrcLabel, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            SetWindowPos(g_hSrchLabel, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            SetWindowPos(g_hSearch, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

            {
                HWND c;
                for (c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
                    SendMessageW(c, WM_SETFONT, (WPARAM)g_hFont, TRUE);
                UNREFERENCED_PARAMETER(hHdr);
            }

            g_hwndMain = hwnd;
            if (g_startSoftware)
            {
                g_tier = FM_TIER_SOFTWARE;
                TabCtrl_SetCurSel(g_hTab, 1);
            }
            LayoutButtons(hwnd);
            FillList();          /* fills for g_tier (the Software tab when started with /software) */
            return 0;
        }
        case WM_NOTIFY:
        {
            LPNMHDR nh = (LPNMHDR)lp;
            if (nh->idFrom == IDC_TAB && nh->code == TCN_SELCHANGE)
            {
                g_tier = TabCtrl_GetCurSel(g_hTab) == 1 ? FM_TIER_SOFTWARE : FM_TIER_OS;
                LayoutButtons(hwnd);
                Populate(NULL);
            }
            else if (nh->idFrom == IDC_LIST && nh->code == LVN_ITEMCHANGED)
            {
                LPNMLISTVIEW nlv = (LPNMLISTVIEW)lp;
                /* checkbox toggle on the OS tier: validate, then refresh verbs */
                if (!g_populating && !g_reverting && g_tier == FM_TIER_OS &&
                    (nlv->uChanged & LVIF_STATE) &&
                    (nlv->uNewState & LVIS_STATEIMAGEMASK) !=
                    (nlv->uOldState & LVIS_STATEIMAGEMASK) &&
                    (nlv->uOldState & LVIS_STATEIMAGEMASK) != 0)
                {
                    BOOL nowChecked =
                        ((nlv->uNewState & LVIS_STATEIMAGEMASK) >> 12) == 2;
                    OnOsCheck(nlv->iItem, nowChecked);
                }
                UpdateButtons();
            }
            else if (nh->idFrom == IDC_LIST && nh->code == NM_CLICK)
                UpdateButtons();
            return 0;
        }

        case WM_COMMAND:
            if (LOWORD(wp) == IDC_OPCANCEL)
            {
                if (g_busy && !g_cancelling &&
                    MessageBoxW(hwnd, FmOpMayBeMsi() ?
                        L"Cancel the running operation?\n\nA download is stopped at once. A Windows Installer package "
                        L"that is already installing cannot be rolled back, so it is allowed to finish and is then "
                        L"removed again; this can take a little while." :
                        L"Cancel the running operation?\n\nThe running installer or script is stopped at once.",
                        BRAND_PRODUCT_NAME_W L" Features", MB_YESNO | MB_ICONQUESTION) == IDYES && g_busy)
                    BeginCancel();
                return 0;
            }
            if (g_busy) return 0;   /* a background op is running; ignore new commands */
            switch (LOWORD(wp))
            {
                case IDC_INSTALL:   DoAction(hwnd, ACT_INSTALL);   break;
                case IDC_ENABLE:    DoAction(hwnd, ACT_ENABLE);    break;
                case IDC_DISABLE:   DoAction(hwnd, ACT_DISABLE);   break;
                case IDC_UNINSTALL: DoAction(hwnd, ACT_UNINSTALL); break;
                case IDC_UPDATE:    DoAction(hwnd, ACT_UPDATE); break;
                case IDC_ADDBUCKET: DoAddBucket(hwnd); break;
                case IDC_SEARCH:
                    if (HIWORD(wp) == EN_CHANGE && !g_populating)
                        SetTimer(hwnd, IDT_SEARCH, 250, NULL);       /* filter after the typing pauses */
                    break;
                case IDC_IMPORT:    DoImport(hwnd); break;
                case IDC_IMPORTSC:  DoImportScoop(hwnd); break;
                case IDC_SOURCE:
                    if (HIWORD(wp) == CBN_SELCHANGE)
                    {
                        int sel = (int)SendMessageW(g_hSource, CB_GETCURSEL, 0, 0);
                        g_srcFilter[0] = L'\0';
                        if (sel > 0)
                            SendMessageW(g_hSource, CB_GETLBTEXT, sel, (LPARAM)g_srcFilter);
                        Populate(NULL);
                    }
                    break;
                case IDC_CATEGORY:
                    if (HIWORD(wp) == CBN_SELCHANGE)
                    {
                        int sel = (int)SendMessageW(g_hCat, CB_GETCURSEL, 0, 0);
                        g_catFilter[0] = L'\0';
                        if (sel > 0)
                            SendMessageW(g_hCat, CB_GETLBTEXT, sel, (LPARAM)g_catFilter);
                        Populate(NULL);
                    }
                    break;
                case IDC_REFRESH:   FillList(); break;
                case IDC_OK:        CommitOs(hwnd, TRUE); break;
                case IDC_APPLY:     CommitOs(hwnd, FALSE); break;
                case IDC_CANCEL:
                case IDC_CLOSE:     DestroyWindow(hwnd); break;
            }
            return 0;
        case WM_APP_OPDONE:
            OnOpDone(hwnd, (OPCTX *)lp);
            return 0;
        case WM_APP_PROGRESS:
            EnterCriticalSection(&g_progCs);
            g_progPending = FALSE;
            LeaveCriticalSection(&g_progCs);
            if (g_busy) ShowStatus();
            return 0;
        case WM_TIMER:
            if (wp == IDT_ELAPSED)
            {
                if (g_busy) ShowStatus();
                return 0;
            }
            if (wp == IDT_SEARCH)
            {
                KillTimer(hwnd, IDT_SEARCH);
                GetWindowTextW(g_hSearch, g_search, ARRAYSIZE(g_search));
                Populate(NULL);
            }
            return 0;
        case WM_CLOSE:
            if (g_busy)
            {
                /* never tear down under a running worker, and never ignore the user: ask, then stop the op
                 * (the child process tree is ended) and close when the worker has reported back */
                if (g_cancelling)
                {
                    g_closeAfterOp = TRUE;      /* already stopping: close as soon as it has */
                    return 0;
                }
                if (MessageBoxW(hwnd, L"An operation is running: cancel it and close?", BRAND_PRODUCT_NAME_W L" Features",
                                MB_YESNO | MB_ICONQUESTION) != IDYES)
                    return 0;
                if (g_busy)
                {
                    g_closeAfterOp = TRUE;
                    BeginCancel();
                    return 0;
                }
            }
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd, IDT_SEARCH);
            KillTimer(hwnd, IDT_ELAPSED);
            if (g_arr) { FmFree(g_arr); g_arr = NULL; }
            if (g_opThread) { CloseHandle(g_opThread); g_opThread = NULL; }
            if (g_hFont && g_hFont != GetStockObject(DEFAULT_GUI_FONT))
                DeleteObject(g_hFont);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmd, int nShow)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG m;
    INITCOMMONCONTROLSEX icc;

    UNREFERENCED_PARAMETER(hPrev);

    /* optfeatures /firstboot: the first-boot component installer (Run value NitroComponents) */
    if (lpCmd && wcsstr(lpCmd, L"/firstboot"))
        return FmFirstBootMain(hInst, lpCmd);
    /* no switch of the classic list: "Turn NitroOS features on or off", the tree of features */
    if (!(lpCmd && (wcsstr(lpCmd, L"/software") || wcsstr(lpCmd, L"/addbucket") || wcsstr(lpCmd, L"/classic") ||
                    wcsstr(lpCmd, L"/select:") || wcsstr(lpCmd, L"/search:") || wcsstr(lpCmd, L"/source:") || wcsstr(lpCmd, L"/category:"))))
        return FmFeatTreeMain(hInst, lpCmd, nShow);

    /* optfeatures /software [/source:<source>] [/category:<name>] [/search:<text>] : open on the Software tab, optionally filtered */
    if (lpCmd && wcsstr(lpCmd, L"/software")) g_startSoftware = TRUE;
    if (lpCmd && wcsstr(lpCmd, L"/addbucket")) { g_startSoftware = TRUE; g_openAddBucket = TRUE; }
    if (lpCmd)
    {
        LPCWSTR sp = wcsstr(lpCmd, L"/source:");
        if (sp)
        {
            size_t n = wcscspn(sp + 8, L" \t");
            if (n && n < ARRAYSIZE(g_srcFilter))
            {
                wcsncpy(g_srcFilter, sp + 8, n);
                g_srcFilter[n] = L'\0';
            }
        }
    }

    if (lpCmd)
    {
        LPCWSTR sp = wcsstr(lpCmd, L"/category:");
        if (sp)
        {
            size_t n = wcscspn(sp + 10, L" \t");
            if (n && n < ARRAYSIZE(g_catFilter))
            {
                wcsncpy(g_catFilter, sp + 10, n);
                g_catFilter[n] = L'\0';
            }
        }
    }

    if (lpCmd)
    {
        LPCWSTR sp = wcsstr(lpCmd, L"/search:");
        if (sp)
        {
            size_t n = wcscspn(sp + 8, L" \t");
            if (n && n < ARRAYSIZE(g_search))
            {
                wcsncpy(g_search, sp + 8, n);
                g_search[n] = L'\0';
            }
        }
    }

    if (lpCmd)
    {
        LPCWSTR sp = wcsstr(lpCmd, L"/select:");
        if (sp)
        {
            size_t n = wcscspn(sp + 8, L" \t");
            if (n && n < ARRAYSIZE(g_selectId))
            {
                wcsncpy(g_selectId, sp + 8, n);
                g_selectId[n] = L'\0';
            }
        }
    }

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);
    InitializeCriticalSection(&g_progCs);

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"NitroOptionalFeatures";
    wc.hIcon = LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_FEATMGR));
    RegisterClassExW(&wc);

    /* Centre on the work area (CW_USEDEFAULT cascades from a fixed point and
     * pushed the 760x520 window off the bottom/right of an 800x600 desktop,
     * hiding the OK/Apply row). Clamp so the caption and buttons stay reachable. */
    {
        RECT wa;
        int w = 940, h = 540, x, y;
        if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0))
            SetRect(&wa, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        if (w > wa.right - wa.left) w = wa.right - wa.left;
        if (h > wa.bottom - wa.top) h = wa.bottom - wa.top;
        x = wa.left + ((wa.right - wa.left) - w) / 2;
        y = wa.top + ((wa.bottom - wa.top) - h) / 2;
        hwnd = CreateWindowExW(0, wc.lpszClassName, BRAND_PRODUCT_NAME_W L" Features",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            x, y, w, h, NULL, NULL, hInst, NULL);
    }
    if (!hwnd) return 1;

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    if (g_openAddBucket) PostMessageW(hwnd, WM_COMMAND, IDC_ADDBUCKET, 0);

    while (GetMessageW(&m, NULL, 0, 0) > 0)
    {
        if (IsDialogMessageW(hwnd, &m)) continue;  /* Tab/Esc/default-button nav */
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}
