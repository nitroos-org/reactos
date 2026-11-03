/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     "Turn NitroOS features on or off": a tree of the catalog's features with check boxes (a parent is
 *              partly checked when only some of its features are on), a description of the selected item, and
 *              OK / Cancel that apply the difference through the "Installing additional components" window.
 *              Modelled on Windows' optionalfeatures.exe ("Turn Windows features on or off").
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <commctrl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <windowsx.h>

#define IDC_TREE   3001
#define IDC_DESC   3002
#define IDC_SWLIST 3003
#define IDC_HEAD   3004
#define IDC_INSTR  3005

#define SI_BLANK 0
#define SI_OFF   1
#define SI_ON    2
#define SI_PART  3

typedef struct _NODE
{
    BOOL      group;
    int       feat;          /* index into g_arr for a leaf */
    HTREEITEM h;
    int       parent;        /* index of the group node (leaf) or -1 */
    BOOL      checked;       /* leaf: wanted state */
    BOOL      initial;       /* leaf: state when the tree was filled */
    WCHAR     name[FM_MAX_NAME];
} NODE;

static HWND g_hwnd, g_hTree, g_hDesc, g_hOK, g_hCancel, g_hSw, g_hHead, g_hInstr;
static HFONT g_font, g_headFont;
static FM_FEATURE *g_arr;
static int g_count;
static NODE *g_nodes;
static int g_nn, g_ncap;
static BOOL g_filling;
static WCHAR g_note[512];       /* "Also turned on: ..." after a toggle, shown above the description */

/* ---- tree contents ------------------------------------------------------------------------------------------ */

static BOOL Curated(const FM_FEATURE *f)
{
    /* imported RAPPS / Scoop entries (thousands) live in Catalog\Software and belong to the Software list */
    return !StrStrIW(f->ManifestPath, L"\\Catalog\\Software\\");
}

static LPCWSTR GroupOf(const FM_FEATURE *f)
{
    if (f->Group[0]) return f->Group;
    return f->Tier == FM_TIER_OS ? L"System features" : L"Software";
}

static int AddNode(const NODE *n)
{
    if (g_nn == g_ncap)
    {
        int nc = g_ncap ? g_ncap * 2 : 32;
        NODE *nn = g_nodes ? (NODE *)HeapReAlloc(GetProcessHeap(), 0, g_nodes, nc * sizeof(NODE))
                           : (NODE *)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(NODE));
        if (!nn) return -1;
        g_nodes = nn;
        g_ncap = nc;
    }
    g_nodes[g_nn] = *n;
    return g_nn++;
}

static void SetStateImage(HTREEITEM h, int idx)
{
    TVITEMW tv;
    ZeroMemory(&tv, sizeof(tv));
    tv.mask = TVIF_STATE;
    tv.hItem = h;
    tv.stateMask = TVIS_STATEIMAGEMASK;
    tv.state = INDEXTOSTATEIMAGEMASK(idx);
    TreeView_SetItem(g_hTree, &tv);
}

static HTREEITEM Insert(HTREEITEM parent, LPCWSTR text, int nodeIdx, int image)
{
    TVINSERTSTRUCTW is;
    ZeroMemory(&is, sizeof(is));
    is.hParent = parent;
    is.hInsertAfter = TVI_SORT;
    is.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    is.item.pszText = (LPWSTR)text;
    is.item.lParam = nodeIdx;
    is.item.iImage = is.item.iSelectedImage = image;
    return TreeView_InsertItem(g_hTree, &is);
}

static int FindLeaf(LPCWSTR id)
{
    int i;
    for (i = 0; i < g_nn; i++)
        if (!g_nodes[i].group && !_wcsicmp(g_arr[g_nodes[i].feat].Id, id)) return i;
    return -1;
}

static void RefreshGroups(void)
{
    int g, i;
    for (g = 0; g < g_nn; g++)
    {
        int on = 0, all = 0;
        if (!g_nodes[g].group) continue;
        for (i = 0; i < g_nn; i++)
            if (!g_nodes[i].group && g_nodes[i].parent == g) { all++; if (g_nodes[i].checked) on++; }
        SetStateImage(g_nodes[g].h, !all || !on ? SI_OFF : on == all ? SI_ON : SI_PART);
    }
}

static int FolderIcon(void)
{
    SHFILEINFOW sfi;
    HIMAGELIST sys;
    ZeroMemory(&sfi, sizeof(sfi));
    sys = (HIMAGELIST)SHGetFileInfoW(L"C:\\", FILE_ATTRIBUTE_DIRECTORY, &sfi, sizeof(sfi),
                                     SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
    if (sys)
    {
        TreeView_SetImageList(g_hTree, sys, TVSIL_NORMAL);
        return sfi.iIcon;
    }
    return 0;
}

static void ExpandAll(void)
{
    int i;
    for (i = 0; i < g_nn; i++)
        if (g_nodes[i].group) TreeView_Expand(g_hTree, g_nodes[i].h, TVE_EXPAND);
}

static void FillTree(void)
{
    int i, icon, ngroups = 0;
    WCHAR groups[24][48];

    g_filling = TRUE;
    TreeView_DeleteAllItems(g_hTree);
    g_nn = 0;
    if (g_arr) { FmFree(g_arr); g_arr = NULL; }
    g_count = FmEnumFeatures(&g_arr);
    icon = FolderIcon();

    /* the parents first: one per group name */
    for (i = 0; i < g_count; i++)
    {
        int k;
        BOOL have = FALSE;
        if (!Curated(&g_arr[i])) continue;
        for (k = 0; k < ngroups; k++)
            if (!_wcsicmp(groups[k], GroupOf(&g_arr[i]))) { have = TRUE; break; }
        if (!have && ngroups < 24)
        {
            NODE n;
            ZeroMemory(&n, sizeof(n));
            n.group = TRUE;
            n.parent = -1;
            StringCchCopyW(n.name, ARRAYSIZE(n.name), GroupOf(&g_arr[i]));
            StringCchCopyW(groups[ngroups], 48, GroupOf(&g_arr[i]));
            k = AddNode(&n);
            ngroups++;
            if (k >= 0) g_nodes[k].h = Insert(TVI_ROOT, n.name, k, icon);
        }
    }
    for (i = 0; i < g_count; i++)
    {
        NODE n;
        int k, idx, g = -1;
        if (!Curated(&g_arr[i])) continue;
        for (k = 0; k < g_nn; k++)
            if (g_nodes[k].group && !_wcsicmp(g_nodes[k].name, GroupOf(&g_arr[i]))) { g = k; break; }
        if (g < 0) continue;
        ZeroMemory(&n, sizeof(n));
        n.feat = i;
        n.parent = g;
        n.initial = n.checked = (g_arr[i].State == FM_STATE_ENABLED);
        StringCchCopyW(n.name, ARRAYSIZE(n.name), g_arr[i].Name);
        idx = AddNode(&n);
        if (idx < 0) continue;
        g_nodes[idx].h = Insert(g_nodes[g].h, n.name, idx, icon);
        SetStateImage(g_nodes[idx].h, n.checked ? SI_ON : SI_OFF);
    }
    RefreshGroups();
    ExpandAll();
    if (g_nn) TreeView_SelectItem(g_hTree, g_nodes[0].h);
    TreeView_EnsureVisible(g_hTree, g_nn ? g_nodes[0].h : NULL);
    g_filling = FALSE;
}

/* ---- description pane --------------------------------------------------------------------------------------- */

static void DepNames(const NODE *n, BOOL needs, WCHAR *out, size_t cch)
{
    const FM_FEATURE *f = &g_arr[n->feat];
    int i;
    out[0] = L'\0';
    for (i = 0; i < g_nn; i++)
    {
        const FM_FEATURE *o;
        WCHAR tmp[FM_MAX_DEPS], *tok, *ctx = NULL;
        BOOL hit = FALSE;
        if (g_nodes[i].group || g_nodes + i == n) continue;
        o = &g_arr[g_nodes[i].feat];
        StringCchCopyW(tmp, ARRAYSIZE(tmp), needs ? f->Dependencies : o->Dependencies);
        for (tok = wcstok_s(tmp, L",; ", &ctx); tok; tok = wcstok_s(NULL, L",; ", &ctx))
            if (!_wcsicmp(tok, needs ? o->Id : f->Id)) { hit = TRUE; break; }
        if (hit)
        {
            if (out[0]) StringCchCatW(out, cch, L", ");
            StringCchCatW(out, cch, o->Name);
        }
    }
}

static void ShowDesc(HTREEITEM h)
{
    TVITEMW tv;
    WCHAR text[3000], tmp[512];
    const NODE *n;

    ZeroMemory(&tv, sizeof(tv));
    tv.mask = TVIF_PARAM;
    tv.hItem = h;
    if (!h || !TreeView_GetItem(g_hTree, &tv) || tv.lParam < 0 || tv.lParam >= g_nn) { SetWindowTextW(g_hDesc, g_note); return; }
    n = &g_nodes[tv.lParam];
    text[0] = L'\0';
    if (g_note[0]) { StringCchCopyW(text, ARRAYSIZE(text), g_note); StringCchCatW(text, ARRAYSIZE(text), L"\r\n\r\n"); }
    if (n->group)
    {
        int i, on = 0, all = 0;
        for (i = 0; i < g_nn; i++)
            if (!g_nodes[i].group && g_nodes[i].parent == (int)tv.lParam) { all++; if (g_nodes[i].checked) on++; }
        StringCchPrintfW(tmp, ARRAYSIZE(tmp), L"%s\r\n%d of %d features turned on.", n->name, on, all);
        StringCchCatW(text, ARRAYSIZE(text), tmp);
    }
    else
    {
        const FM_FEATURE *f = &g_arr[n->feat];
        FM_COMPONENT c;
        StringCchCatW(text, ARRAYSIZE(text), f->Name);
        StringCchCatW(text, ARRAYSIZE(text), L"\r\n");
        StringCchCatW(text, ARRAYSIZE(text), f->Description);
        StringCchPrintfW(tmp, ARRAYSIZE(tmp), L"\r\nVersion %s.", f->Version);
        StringCchCatW(text, ARRAYSIZE(text), tmp);
        if (f->InstalledVersion[0])
        {
            StringCchPrintfW(tmp, ARRAYSIZE(tmp), L" Installed version %s.", f->InstalledVersion);
            StringCchCatW(text, ARRAYSIZE(text), tmp);
        }
        if (!_wcsicmp(f->Provider, L"component") && FmCompLoad(f->Id, &c) && c.Size && f->State != FM_STATE_ENABLED)
        {
            StringCchPrintfW(tmp, ARRAYSIZE(tmp), L" Download: %I64u MB.", (c.Size + (1u << 20) - 1) >> 20);
            StringCchCatW(text, ARRAYSIZE(text), tmp);
        }
        DepNames(n, TRUE, tmp, ARRAYSIZE(tmp));
        if (tmp[0]) { StringCchCatW(text, ARRAYSIZE(text), L"\r\nNeeds: "); StringCchCatW(text, ARRAYSIZE(text), tmp); }
        DepNames(n, FALSE, tmp, ARRAYSIZE(tmp));
        if (tmp[0]) { StringCchCatW(text, ARRAYSIZE(text), L"\r\nNeeded by: "); StringCchCatW(text, ARRAYSIZE(text), tmp); }
        if (!f->Removable && f->State == FM_STATE_ENABLED)
            StringCchCatW(text, ARRAYSIZE(text), L"\r\nA base component of the system: it cannot be turned off.");
        else if (!f->PayloadAvailable && f->State != FM_STATE_ENABLED)
            StringCchCatW(text, ARRAYSIZE(text), L"\r\nNot available on this system (its payload is not staged).");
    }
    SetWindowTextW(g_hDesc, text);
}

/* ---- toggling ----------------------------------------------------------------------------------------------- */

static void AppendNote(LPCWSTR prefix, LPCWSTR name)
{
    size_t l = wcslen(g_note);
    if (!g_note[0]) StringCchPrintfW(g_note, ARRAYSIZE(g_note), L"%s%s", prefix, name);
    else if (l + wcslen(name) + 4 < ARRAYSIZE(g_note)) { StringCchCatW(g_note, ARRAYSIZE(g_note), L", "); StringCchCatW(g_note, ARRAYSIZE(g_note), name); }
}

/* may this leaf be changed to `want`? message in g_note when not */
static BOOL CanSet(int idx, BOOL want)
{
    const FM_FEATURE *f = &g_arr[g_nodes[idx].feat];
    if (!want && f->State == FM_STATE_ENABLED && !f->Removable)
    {
        StringCchPrintfW(g_note, ARRAYSIZE(g_note), L"%s is a base component of the system and cannot be turned off.", f->Name);
        return FALSE;
    }
    if (want && f->State != FM_STATE_ENABLED && !f->PayloadAvailable)
    {
        StringCchPrintfW(g_note, ARRAYSIZE(g_note), L"%s is not available on this system yet.", f->Name);
        return FALSE;
    }
    return TRUE;
}

static void SetLeaf(int idx, BOOL want, int depth)
{
    FM_FEATURE *f = &g_arr[g_nodes[idx].feat];
    WCHAR tmp[FM_MAX_DEPS], *tok, *ctx = NULL;
    int i;

    if (g_nodes[idx].checked == want || depth > 8) return;
    if (!CanSet(idx, want)) return;
    g_nodes[idx].checked = want;
    SetStateImage(g_nodes[idx].h, want ? SI_ON : SI_OFF);
    if (want)
    {
        /* what it needs comes along */
        StringCchCopyW(tmp, ARRAYSIZE(tmp), f->Dependencies);
        for (tok = wcstok_s(tmp, L",; ", &ctx); tok; tok = wcstok_s(NULL, L",; ", &ctx))
        {
            int d = FindLeaf(tok);
            if (d >= 0 && !g_nodes[d].checked)
            {
                SetLeaf(d, TRUE, depth + 1);
                if (g_nodes[d].checked) AppendNote(L"Also turned on, because it is needed: ", g_nodes[d].name);
            }
        }
    }
    else
    {
        /* what needs it goes with it */
        for (i = 0; i < g_nn; i++)
        {
            WCHAR t2[FM_MAX_DEPS], *k2, *c2 = NULL;
            if (g_nodes[i].group || !g_nodes[i].checked || i == idx) continue;
            StringCchCopyW(t2, ARRAYSIZE(t2), g_arr[g_nodes[i].feat].Dependencies);
            for (k2 = wcstok_s(t2, L",; ", &c2); k2; k2 = wcstok_s(NULL, L",; ", &c2))
                if (!_wcsicmp(k2, f->Id))
                {
                    SetLeaf(i, FALSE, depth + 1);
                    if (!g_nodes[i].checked) AppendNote(L"Also turned off, because it needs this one: ", g_nodes[i].name);
                    break;
                }
        }
    }
}

static void Toggle(HTREEITEM h)
{
    TVITEMW tv;
    NODE *n;
    int idx, i;

    ZeroMemory(&tv, sizeof(tv));
    tv.mask = TVIF_PARAM;
    tv.hItem = h;
    if (!TreeView_GetItem(g_hTree, &tv) || tv.lParam < 0 || tv.lParam >= g_nn) return;
    idx = (int)tv.lParam;
    n = &g_nodes[idx];
    g_note[0] = L'\0';
    if (n->group)
    {
        /* a parent: all of its features on, unless they already are (then all off) */
        BOOL allOn = TRUE, any = FALSE;
        for (i = 0; i < g_nn; i++)
            if (!g_nodes[i].group && g_nodes[i].parent == idx) { any = TRUE; if (!g_nodes[i].checked) allOn = FALSE; }
        if (!any) return;
        for (i = 0; i < g_nn; i++)
            if (!g_nodes[i].group && g_nodes[i].parent == idx) SetLeaf(i, !allOn, 0);
    }
    else
        SetLeaf(idx, !n->checked, 0);
    RefreshGroups();
    ShowDesc(TreeView_GetSelection(g_hTree));
}

/* ---- OK: the difference --------------------------------------------------------------------------------------- */

static BOOL DependsOn(const FM_FEATURE *a, const FM_FEATURE *b)
{
    WCHAR tmp[FM_MAX_DEPS], *tok, *ctx = NULL;
    StringCchCopyW(tmp, ARRAYSIZE(tmp), a->Dependencies);
    for (tok = wcstok_s(tmp, L",; ", &ctx); tok; tok = wcstok_s(NULL, L",; ", &ctx))
        if (!_wcsicmp(tok, b->Id)) return TRUE;
    return FALSE;
}

static int BuildJobs(FM_JOB **pjobs)
{
    FM_JOB *jobs;
    int i, n = 0, k, pass;
    BOOL *used;

    *pjobs = NULL;
    jobs = (FM_JOB *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (g_nn + 1) * sizeof(FM_JOB));
    used = (BOOL *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (g_nn + 1) * sizeof(BOOL));
    if (!jobs || !used) { if (jobs) HeapFree(GetProcessHeap(), 0, jobs); if (used) HeapFree(GetProcessHeap(), 0, used); return 0; }
    /* turn on: needs-first is the engine's job (it enables dependencies itself) */
    for (i = 0; i < g_nn; i++)
        if (!g_nodes[i].group && g_nodes[i].checked && !g_nodes[i].initial)
        {
            StringCchCopyW(jobs[n].id, FM_MAX_ID, g_arr[g_nodes[i].feat].Id);
            StringCchCopyW(jobs[n].name, FM_MAX_NAME, g_nodes[i].name);
            jobs[n].action = FM_JOB_INSTALL;
            n++;
        }
    /* turn off: a feature that needs another is removed before it */
    for (pass = 0; pass < g_nn; pass++)
    {
        BOOL progress = FALSE;
        for (i = 0; i < g_nn; i++)
        {
            BOOL blocked = FALSE;
            if (g_nodes[i].group || used[i] || g_nodes[i].checked || !g_nodes[i].initial) continue;
            for (k = 0; k < g_nn; k++)
                if (!g_nodes[k].group && !used[k] && k != i && !g_nodes[k].checked && g_nodes[k].initial &&
                    DependsOn(&g_arr[g_nodes[k].feat], &g_arr[g_nodes[i].feat]))
                    { blocked = TRUE; break; }
            if (blocked) continue;
            used[i] = TRUE;
            StringCchCopyW(jobs[n].id, FM_MAX_ID, g_arr[g_nodes[i].feat].Id);
            StringCchCopyW(jobs[n].name, FM_MAX_NAME, g_nodes[i].name);
            jobs[n].action = FM_JOB_REMOVE;
            n++;
            progress = TRUE;
        }
        if (!progress) break;
    }
    HeapFree(GetProcessHeap(), 0, used);
    *pjobs = jobs;
    return n;
}

static void DoApply(void)
{
    FM_JOB *jobs;
    int n = BuildJobs(&jobs), rc;
    FM_UIRESULT res;
    WCHAR log[MAX_PATH];

    if (!n)
    {
        if (jobs) HeapFree(GetProcessHeap(), 0, jobs);
        DestroyWindow(g_hwnd);
        return;
    }
    log[0] = L'\0';
    if (FmGetLogDir(log, ARRAYSIZE(log))) StringCchCatW(log, ARRAYSIZE(log), L"\\components.log");
    rc = FmRunJobsUI(g_hwnd, jobs, n, 0, log[0] ? log : NULL, &res);
    HeapFree(GetProcessHeap(), 0, jobs);
    g_note[0] = L'\0';
    FillTree();                      /* the tree shows what is really on now */
    SetFocus(g_hTree);               /* the modal window took the focus away with it */
    ShowDesc(TreeView_GetSelection(g_hTree));
    FmTakePathChange(NULL, 0);
    if (rc == 0) DestroyWindow(g_hwnd);
}

/* ---- window ----------------------------------------------------------------------------------------------- */

static HIMAGELIST MakeStateImages(void)
{
    int cx = 16, cy = 16, i;
    HDC hdc = GetDC(NULL), mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, cx * 4, cy), old;
    HIMAGELIST himl;
    RECT all = { 0, 0, cx * 4, cy };

    old = (HBITMAP)SelectObject(mem, bmp);
    FillRect(mem, &all, GetSysColorBrush(COLOR_WINDOW));
    for (i = 1; i < 4; i++)
    {
        RECT r = { i * cx + 1, 1, i * cx + 14, 14 };
        UINT st = DFCS_BUTTONCHECK | (i == SI_ON ? DFCS_CHECKED : 0);
        DrawFrameControl(mem, &r, DFC_BUTTON, st);
        if (i == SI_PART)
        {
            RECT in = { i * cx + 4, 4, i * cx + 11, 11 };
            FillRect(mem, &in, GetSysColorBrush(COLOR_WINDOWTEXT));
        }
    }
    SelectObject(mem, old);
    himl = ImageList_Create(cx, cy, ILC_COLOR24, 4, 0);
    if (himl) ImageList_Add(himl, bmp, NULL);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    return himl;
}

static void OpenSoftwareList(void)
{
    WCHAR exe[MAX_PATH], cl[MAX_PATH + 32];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    if (!GetModuleFileNameW(NULL, exe, MAX_PATH)) return;
    StringCchPrintfW(cl, ARRAYSIZE(cl), L"\"%s\" /software", exe);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (CreateProcessW(NULL, cl, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

static LRESULT CALLBACK TreeProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            NONCLIENTMETRICSW ncm;
            HWND c;
            ZeroMemory(&ncm, sizeof(ncm));
            ncm.cbSize = sizeof(ncm);
            if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
            {
                LOGFONTW lf = ncm.lfMessageFont;
                g_font = CreateFontIndirectW(&ncm.lfMessageFont);
                lf.lfHeight = lf.lfHeight * 14 / 10;
                g_headFont = CreateFontIndirectW(&lf);
            }
            if (!g_font) g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            if (!g_headFont) g_headFont = g_font;
            g_hwnd = hwnd;
            g_hHead = CreateWindowExW(0, L"STATIC", L"Turn NitroOS features on or off", WS_CHILD | WS_VISIBLE,
                                      16, 12, 428, 24, hwnd, (HMENU)(INT_PTR)IDC_HEAD, NULL, NULL);
            g_hInstr = CreateWindowExW(0, L"STATIC",
                L"To turn a feature on, select its check box. To turn a feature off, clear its check box. "
                L"A filled box means that only part of a feature is turned on.", WS_CHILD | WS_VISIBLE,
                16, 42, 428, 36, hwnd, (HMENU)(INT_PTR)IDC_INSTR, NULL, NULL);
            g_hTree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS | TVS_DISABLEDRAGDROP | TVS_INFOTIP,
                16, 84, 428, 238, hwnd, (HMENU)(INT_PTR)IDC_TREE, NULL, NULL);
            {
                HIMAGELIST st = MakeStateImages();
                if (st) TreeView_SetImageList(g_hTree, st, TVSIL_STATE);
            }
            g_hDesc = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                                      16, 330, 428, 76, hwnd, (HMENU)(INT_PTR)IDC_DESC, NULL, NULL);
            g_hSw = CreateWindowExW(0, L"BUTTON", L"&Software list...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                    16, 416, 116, 26, hwnd, (HMENU)(INT_PTR)IDC_SWLIST, NULL, NULL);
            g_hOK = CreateWindowExW(0, L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                    274, 416, 82, 26, hwnd, (HMENU)(INT_PTR)IDOK, NULL, NULL);
            g_hCancel = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                        362, 416, 82, 26, hwnd, (HMENU)(INT_PTR)IDCANCEL, NULL, NULL);
            for (c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
                SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
            SendMessageW(g_hHead, WM_SETFONT, (WPARAM)g_headFont, TRUE);
            FillTree();
            ShowDesc(TreeView_GetSelection(g_hTree));
            return 0;
        }
        case WM_SETFOCUS:
            SetFocus(g_hTree);
            return 0;
        case WM_CTLCOLORSTATIC:
            if ((HWND)lp == g_hHead)
            {
                SetTextColor((HDC)wp, RGB(0, 51, 153));
                SetBkMode((HDC)wp, TRANSPARENT);
                return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
            }
            break;
        case WM_NOTIFY:
        {
            LPNMHDR nh = (LPNMHDR)lp;
            if (nh->idFrom != IDC_TREE) break;
            if (nh->code == NM_CLICK && !g_filling)
            {
                TVHITTESTINFO ht;
                DWORD pos = GetMessagePos();
                ZeroMemory(&ht, sizeof(ht));
                ht.pt.x = GET_X_LPARAM(pos);
                ht.pt.y = GET_Y_LPARAM(pos);
                ScreenToClient(g_hTree, &ht.pt);
                TreeView_HitTest(g_hTree, &ht);
                if (ht.hItem && (ht.flags & TVHT_ONITEMSTATEICON))
                {
                    TreeView_SelectItem(g_hTree, ht.hItem);
                    Toggle(ht.hItem);
                }
            }
            else if (nh->code == TVN_KEYDOWN)
            {
                LPNMTVKEYDOWN kd = (LPNMTVKEYDOWN)lp;
                if (kd->wVKey == VK_SPACE)
                {
                    HTREEITEM h = TreeView_GetSelection(g_hTree);
                    if (h) Toggle(h);
                    return 1;
                }
            }
            else if (nh->code == TVN_SELCHANGEDW && !g_filling)
            {
                g_note[0] = L'\0';
                ShowDesc(((LPNMTREEVIEWW)lp)->itemNew.hItem);
            }
            else if (nh->code == TVN_GETINFOTIPW)
            {
                LPNMTVGETINFOTIPW tip = (LPNMTVGETINFOTIPW)lp;
                if (tip->lParam >= 0 && tip->lParam < g_nn && !g_nodes[tip->lParam].group)
                    StringCchCopyW(tip->pszText, tip->cchTextMax, g_arr[g_nodes[tip->lParam].feat].Description);
            }
            return 0;
        }
        case WM_COMMAND:
            switch (LOWORD(wp))
            {
                case IDOK:     DoApply(); return 0;
                case IDCANCEL: DestroyWindow(hwnd); return 0;
                case IDC_SWLIST: OpenSoftwareList(); return 0;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            if (g_arr) { FmFree(g_arr); g_arr = NULL; }
            if (g_nodes) { HeapFree(GetProcessHeap(), 0, g_nodes); g_nodes = NULL; g_nn = g_ncap = 0; }
            if (g_font && g_font != GetStockObject(DEFAULT_GUI_FONT)) DeleteObject(g_font);
            if (g_headFont && g_headFont != g_font) DeleteObject(g_headFont);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int FmFeatTreeMain(HINSTANCE hInst, LPCWSTR cmd, int nShow)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG m;
    RECT wa, rc;
    INITCOMMONCONTROLSEX icc;
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;

    (void)cmd;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_TREEVIEW_CLASSES | ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = TreeProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"NitroFeatureTree";
    wc.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    RegisterClassExW(&wc);

    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0))
        SetRect(&wa, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    SetRect(&rc, 0, 0, 460, 456);
    AdjustWindowRectEx(&rc, style, FALSE, 0);
    hwnd = CreateWindowExW(0, wc.lpszClassName, L"NitroOS Features", style,
                           wa.left + ((wa.right - wa.left) - (rc.right - rc.left)) / 2,
                           wa.top + ((wa.bottom - wa.top) - (rc.bottom - rc.top)) / 2,
                           rc.right - rc.left, rc.bottom - rc.top, NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);
    while (GetMessageW(&m, NULL, 0, 0) > 0)
    {
        if (IsDialogMessageW(hwnd, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return 0;
}
