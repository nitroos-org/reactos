/*
 * PROJECT:     NitroOS Firewall with Advanced Security (wf.msc)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Main window: console tree, rule lists, actions pane. Reads and writes the rule store (fwstore),
 *              the same registry data INetFwPolicy2, mpssvc and netsh advfirewall use.
 *              Layout follows the Windows 10 firewall console as seen on a reference machine (read-only
 *              observation); the product name reads NitroOS.
 */
#include "wfadv.h"

#define WM_REFRESHRULES (WM_APP + 1)
#define IDT_WATCH       1

enum { NODE_ROOT, NODE_INBOUND, NODE_OUTBOUND, NODE_CSR, NODE_MON, NODE_COUNT };

HINSTANCE g_hInst;

static HWND g_hMain, g_hTree, g_hList, g_hActions, g_hHdrCenter, g_hHdrActions, g_hText, g_hPropLink, g_hStatus;
static HTREEITEM g_hNode[NODE_COUNT];
static INT g_Node = NODE_ROOT;
static FW_RULESET g_Rules;
static INT g_SortCol, g_SortDir = 1;
static INT g_Busy;
static HANDLE g_hWatchEvt;
static HKEY g_hWatchKey;
static HBRUSH g_hHdrBrush;
static HFONT g_hBoldFont;
static HIMAGELIST g_hRuleImages;

/* ------------------------------------------------------------------ helpers */

PCWSTR Str(UINT id)
{
    static WCHAR bufs[16][700];
    static int n;
    PWSTR b = bufs[n++ & 15];
    b[0] = 0;
    LoadStringW(g_hInst, id, b, 700);
    return b;
}

VOID ShowStoreError(HWND hWnd, DWORD err)
{
    WCHAR msg[400];
    StringCchPrintfW(msg, ARRAYSIZE(msg), Str(IDS_ERR_STORE), err);
    MessageBoxW(hWnd, msg, Str(IDS_APPNAME), MB_OK | MB_ICONERROR);
}

VOID NotifyMainRefresh(VOID)
{
    if (g_hMain) PostMessageW(g_hMain, WM_REFRESHRULES, 0, 0);
}

/* the text of one cell of the rule list */
static VOID CellText(const FW_RULE *r, INT col, PWSTR out, SIZE_T cch)
{
    out[0] = 0;
    switch (col)
    {
        case 0: StringCchCopyW(out, cch, r->Name ? r->Name : L""); break;
        case 1: StringCchCopyW(out, cch, r->Group ? r->Group : L""); break;
        case 2: FormatProfiles(r->Profiles, out, cch); break;
        case 3: StringCchCopyW(out, cch, Str(r->Enabled ? IDS_YES : IDS_NO)); break;
        case 4: StringCchCopyW(out, cch, Str(r->Action ? IDS_ALLOW : IDS_BLOCK)); break;
        case 5: StringCchCopyW(out, cch, AnyIfEmpty(r->App)); break;
        case 6: StringCchCopyW(out, cch, AnyIfEmpty(r->LAddr)); break;
        case 7: StringCchCopyW(out, cch, AnyIfEmpty(r->RAddr)); break;
        case 8: FormatProtocol(r->Protocol, out, cch); break;
        case 9: StringCchCopyW(out, cch, AnyIfEmpty(r->LPorts)); break;
        case 10: StringCchCopyW(out, cch, AnyIfEmpty(r->RPorts)); break;
    }
}

static HIMAGELIST MakeRuleImages(VOID)
{
    HIMAGELIST il = ImageList_Create(16, 16, ILC_COLOR24 | ILC_MASK, 3, 1);
    HDC hdc = GetDC(NULL), mem = CreateCompatibleDC(hdc);
    static const COLORREF col[3] = { RGB(40, 160, 60), RGB(200, 40, 40), RGB(150, 150, 150) };
    INT i;
    for (i = 0; i < 3; i++)
    {
        HBITMAP bmp = CreateCompatibleBitmap(hdc, 16, 16), old;
        HBRUSH bg = CreateSolidBrush(RGB(255, 0, 255)), fg = CreateSolidBrush(col[i]);
        HPEN white = CreatePen(PS_SOLID, 2, RGB(255, 255, 255)), oldpen;
        RECT rc = { 0, 0, 16, 16 };
        HGDIOBJ oldbr;
        old = SelectObject(mem, bmp);
        FillRect(mem, &rc, bg);
        oldbr = SelectObject(mem, fg);
        SelectObject(mem, GetStockObject(NULL_PEN));
        Ellipse(mem, 0, 0, 16, 16);
        SelectObject(mem, oldbr);
        oldpen = SelectObject(mem, white);
        if (i == 0)
        {
            MoveToEx(mem, 4, 8, NULL); LineTo(mem, 7, 11); LineTo(mem, 12, 5);
        }
        else if (i == 1)
        {
            MoveToEx(mem, 4, 4, NULL); LineTo(mem, 12, 12);
            MoveToEx(mem, 12, 4, NULL); LineTo(mem, 4, 12);
        }
        SelectObject(mem, oldpen);
        SelectObject(mem, old);
        ImageList_AddMasked(il, bmp, RGB(255, 0, 255));
        DeleteObject(white); DeleteObject(fg); DeleteObject(bg); DeleteObject(bmp);
    }
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    return il;
}

/* ------------------------------------------------------------------ rule list */

static int CALLBACK SortCmp(LPARAM a, LPARAM b, LPARAM unused)
{
    WCHAR sa[700], sb[700];
    UNREFERENCED_PARAMETER(unused);
    CellText(&g_Rules.R[a], g_SortCol, sa, ARRAYSIZE(sa));
    CellText(&g_Rules.R[b], g_SortCol, sb, ARRAYSIZE(sb));
    return g_SortDir * lstrcmpiW(sa, sb);
}

static INT SelectedRules(INT *idx, INT max)
{
    INT n = 0, i = -1;
    while (n < max && (i = ListView_GetNextItem(g_hList, i, LVNI_SELECTED)) >= 0)
    {
        LVITEMW it;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_PARAM; it.iItem = i;
        if (ListView_GetItem(g_hList, &it) && it.lParam >= 0 && (ULONG)it.lParam < g_Rules.N)
            idx[n++] = (INT)it.lParam;
    }
    return n;
}

static VOID UpdateActions(VOID);

static VOID FillList(VOID)
{
    ULONG i;
    INT count = 0;
    WCHAR keep[80] = L"", st[200];
    LONG dir = g_Node == NODE_OUTBOUND ? 2 : 1;
    INT sel[1];
    if (SelectedRules(sel, 1) == 1 && g_Rules.R[sel[0]].Id)
        StringCchCopyW(keep, ARRAYSIZE(keep), g_Rules.R[sel[0]].Id);
    SendMessageW(g_hList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hList);
    if (g_Node == NODE_INBOUND || g_Node == NODE_OUTBOUND)
    {
        for (i = 0; i < g_Rules.N; i++)
        {
            LVITEMW it;
            if (g_Rules.R[i].Dir != dir) continue;
            ZeroMemory(&it, sizeof(it));
            it.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
            it.iItem = count;
            it.pszText = LPSTR_TEXTCALLBACKW;
            it.iImage = I_IMAGECALLBACK;
            it.lParam = (LPARAM)i;
            ListView_InsertItem(g_hList, &it);
            count++;
        }
        ListView_SortItems(g_hList, SortCmp, 0);
        if (keep[0])
        {
            INT n = ListView_GetItemCount(g_hList), k;
            for (k = 0; k < n; k++)
            {
                LVITEMW it;
                ZeroMemory(&it, sizeof(it));
                it.mask = LVIF_PARAM; it.iItem = k;
                ListView_GetItem(g_hList, &it);
                if (g_Rules.R[it.lParam].Id && !wcscmp(g_Rules.R[it.lParam].Id, keep))
                {
                    ListView_SetItemState(g_hList, k, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    break;
                }
            }
        }
    }
    SendMessageW(g_hList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hList, NULL, TRUE);
    StringCchPrintfW(st, ARRAYSIZE(st), Str(IDS_RULES_COUNT), count);
    SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)(g_Node == NODE_INBOUND || g_Node == NODE_OUTBOUND ? st : L""));
}

/* ------------------------------------------------------------------ text pages */

static VOID ProfileLines(PWSTR out, SIZE_T cch, ULONG bit, UINT titleId, BOOL active)
{
    FW_PROFILE p;
    WCHAR line[400];
    FwProfileLoad(bit, &p);
    StringCchCatW(out, cch, Str(titleId));
    if (active) StringCchCatW(out, cch, Str(IDS_ACTIVE_SUFFIX));
    StringCchCatW(out, cch, L"\r\n");
    StringCchPrintfW(line, ARRAYSIZE(line), L"    %s\r\n", Str(p.Enable ? IDS_FW_ON : IDS_FW_OFF));
    StringCchCatW(out, cch, line);
    StringCchPrintfW(line, ARRAYSIZE(line), L"    %s\r\n",
                     Str(p.DefaultInbound ? (p.DoNotAllowExceptions ? IDS_IN_BLOCKALL : IDS_IN_BLOCK) : IDS_IN_ALLOW));
    StringCchCatW(out, cch, line);
    StringCchPrintfW(line, ARRAYSIZE(line), L"    %s\r\n\r\n", Str(p.DefaultOutbound ? IDS_OUT_BLOCK : IDS_OUT_ALLOW));
    StringCchCatW(out, cch, line);
}

static VOID BuildOverview(PWSTR out, SIZE_T cch)
{
    ULONG cur = FwCurrentProfiles();
    out[0] = 0;
    StringCchCatW(out, cch, Str(IDS_OVERVIEW));
    StringCchCatW(out, cch, L"\r\n\r\n");
    ProfileLines(out, cch, FWP_DOMAIN, IDS_PROFTITLE_DOM, cur == FWP_DOMAIN);
    ProfileLines(out, cch, FWP_PRIVATE, IDS_PROFTITLE_PRI, cur == FWP_PRIVATE);
    ProfileLines(out, cch, FWP_PUBLIC, IDS_PROFTITLE_PUB, cur == FWP_PUBLIC);
}

static VOID BuildMonitoring(PWSTR out, SIZE_T cch)
{
    ULONG cur = FwCurrentProfiles(), i, in = 0, outb = 0;
    WCHAR line[500];
    FW_PROFILE p;
    out[0] = 0;
    StringCchCatW(out, cch, Str(IDS_MON_TEXT));
    StringCchCatW(out, cch, L"\r\n\r\n");
    FwProfileLoad(cur, &p);
    for (i = 0; i < g_Rules.N; i++)
        if (g_Rules.R[i].Enabled) { if (g_Rules.R[i].Dir == 2) outb++; else in++; }
    StringCchPrintfW(line, ARRAYSIZE(line), L"%s: %s\r\n", Str(cur == FWP_DOMAIN ? IDS_PROF_DOMAIN : cur == FWP_PUBLIC ? IDS_PROF_PUBLIC : IDS_PROF_PRIVATE),
                     Str(p.Enable ? IDS_FW_ON : IDS_FW_OFF));
    StringCchCatW(out, cch, line);
    StringCchPrintfW(line, ARRAYSIZE(line), L"%s\r\n", Str(p.DefaultInbound ? (p.DoNotAllowExceptions ? IDS_IN_BLOCKALL : IDS_IN_BLOCK) : IDS_IN_ALLOW));
    StringCchCatW(out, cch, line);
    StringCchPrintfW(line, ARRAYSIZE(line), L"%s\r\n\r\n", Str(p.DefaultOutbound ? IDS_OUT_BLOCK : IDS_OUT_ALLOW));
    StringCchCatW(out, cch, line);
    StringCchPrintfW(line, ARRAYSIZE(line), L"%s: %lu\r\n%s: %lu\r\n\r\n", Str(IDS_INBOUND), in, Str(IDS_OUTBOUND), outb);
    StringCchCatW(out, cch, line);
    StringCchPrintfW(line, ARRAYSIZE(line), L"%s\r\n%s\r\n", Str(p.LogDropped ? IDS_LOG_DROPPED : IDS_LOG_NOTDROPPED), p.LogFile);
    StringCchCatW(out, cch, line);
}

/* ------------------------------------------------------------------ actions pane */

static VOID AddAction(UINT cmd, PCWSTR text)
{
    INT n = (INT)SendMessageW(g_hActions, LB_ADDSTRING, 0, (LPARAM)text);
    SendMessageW(g_hActions, LB_SETITEMDATA, n, cmd);
}

static VOID UpdateActions(VOID)
{
    INT sel[64], n = 0;
    INT i;
    BOOL anyOn = FALSE, anyOff = FALSE;
    SendMessageW(g_hActions, WM_SETREDRAW, FALSE, 0);
    SendMessageW(g_hActions, LB_RESETCONTENT, 0, 0);
    if (g_Node == NODE_ROOT)
    {
        AddAction(IDM_IMPORT, Str(IDS_ACT_IMPORT));
        AddAction(IDM_EXPORT, Str(IDS_ACT_EXPORT));
        AddAction(IDM_RESTORE, Str(IDS_ACT_RESTORE));
        AddAction(IDM_REFRESH, Str(IDS_ACT_REFRESH));
        AddAction(IDM_PROFPROPS, Str(IDS_ACT_PROPS));
    }
    else if (g_Node == NODE_INBOUND || g_Node == NODE_OUTBOUND)
    {
        AddAction(IDM_NEWRULE, Str(IDS_ACT_NEWRULE));
        AddAction(IDM_PROFPROPS, Str(IDS_ACT_PROPS));
        AddAction(IDM_REFRESH, Str(IDS_ACT_REFRESH));
        n = SelectedRules(sel, ARRAYSIZE(sel));
        if (n > 0)
        {
            AddAction(0, L"");
            AddAction(0, n == 1 ? (g_Rules.R[sel[0]].Name ? g_Rules.R[sel[0]].Name : L"") : Str(IDS_ACT_SELRULE));
            for (i = 0; i < n; i++)
            {
                if (g_Rules.R[sel[i]].Enabled) anyOn = TRUE; else anyOff = TRUE;
            }
            if (anyOn) AddAction(IDM_DISABLE, Str(IDS_ACT_DISABLE));
            if (anyOff) AddAction(IDM_ENABLE, Str(IDS_ACT_ENABLE));
            AddAction(IDM_DELETE, Str(IDS_ACT_DELETE));
            if (n == 1) AddAction(IDM_RULEPROPS, Str(IDS_ACT_RULEPROPS));
        }
    }
    else
    {
        AddAction(IDM_PROFPROPS, Str(IDS_ACT_PROPS));
        AddAction(IDM_REFRESH, Str(IDS_ACT_REFRESH));
    }
    SendMessageW(g_hActions, LB_SETCURSEL, (WPARAM)-1, 0);
    SendMessageW(g_hActions, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hActions, NULL, TRUE);
}

/* ------------------------------------------------------------------ node switching and layout */

static VOID Layout(VOID)
{
    RECT rc;
    INT w, h, sbh, treeW = 230, actW = 220, hdrH = 22, cx, cw, top, bh;
    BOOL rules = (g_Node == NODE_INBOUND || g_Node == NODE_OUTBOUND);
    GetClientRect(g_hMain, &rc);
    w = rc.right; h = rc.bottom;
    SendMessageW(g_hStatus, WM_SIZE, 0, 0);
    GetWindowRect(g_hStatus, &rc);
    sbh = rc.bottom - rc.top;
    bh = h - sbh;
    if (w < treeW + actW + 100) actW = max(0, w - treeW - 100);
    cx = treeW + 2; cw = w - treeW - actW - 4;
    top = hdrH;
    MoveWindow(g_hTree, 0, 0, treeW, bh, TRUE);
    MoveWindow(g_hHdrCenter, cx, 0, cw, hdrH, TRUE);
    MoveWindow(g_hList, cx, top, cw, bh - top, TRUE);
    MoveWindow(g_hText, cx, top, cw, bh - top - 34, TRUE);
    MoveWindow(g_hPropLink, cx + 8, bh - 30, 230, 24, TRUE);
    MoveWindow(g_hHdrActions, w - actW, 0, actW, hdrH, TRUE);
    MoveWindow(g_hActions, w - actW, top, actW, bh - top, TRUE);
    ShowWindow(g_hList, rules ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hText, rules ? SW_HIDE : SW_SHOW);
    ShowWindow(g_hPropLink, g_Node == NODE_ROOT ? SW_SHOW : SW_HIDE);
}

static VOID ShowNode(VOID)
{
    WCHAR txt[3000];
    UINT titleId = g_Node == NODE_ROOT ? IDS_ROOT : g_Node == NODE_INBOUND ? IDS_INBOUND :
                   g_Node == NODE_OUTBOUND ? IDS_OUTBOUND : g_Node == NODE_CSR ? IDS_CSR : IDS_MONITORING;
    SetWindowTextW(g_hHdrCenter, Str(titleId));
    if (g_Node == NODE_ROOT) { BuildOverview(txt, ARRAYSIZE(txt)); SetWindowTextW(g_hText, txt); }
    else if (g_Node == NODE_CSR) SetWindowTextW(g_hText, Str(IDS_CSR_TEXT));
    else if (g_Node == NODE_MON) { BuildMonitoring(txt, ARRAYSIZE(txt)); SetWindowTextW(g_hText, txt); }
    Layout();
    FillList();
    UpdateActions();
}

static VOID ReloadRules(VOID)
{
    FW_RULESET rs;
    DWORD err = FwStoreLoad(&rs);
    if (err) { ShowStoreError(g_hMain, err); return; }
    FwRuleSetFree(&g_Rules);
    g_Rules = rs;
    ShowNode();
}

/* ------------------------------------------------------------------ commands */

static VOID CmdSetEnabled(BOOL enable)
{
    INT sel[64], n, i;
    n = SelectedRules(sel, ARRAYSIZE(sel));
    for (i = 0; i < n; i++)
    {
        FW_RULE *r = &g_Rules.R[sel[i]];
        DWORD err;
        if (!r->Id || (r->Enabled != 0) == (enable != 0)) continue;
        r->Enabled = enable;
        err = FwStoreUpdate(r);
        if (err) { ShowStoreError(g_hMain, err); break; }
    }
}

static VOID CmdDelete(VOID)
{
    INT sel[64], n, i;
    n = SelectedRules(sel, ARRAYSIZE(sel));
    if (!n) return;
    if (MessageBoxW(g_hMain, Str(IDS_CONFIRM_DELETE), Str(IDS_APPNAME), MB_YESNO | MB_ICONQUESTION) != IDYES)
        return;
    for (i = 0; i < n; i++)
    {
        DWORD err;
        if (!g_Rules.R[sel[i]].Id) continue;
        err = FwStoreDelete(g_Rules.R[sel[i]].Id);
        if (err && err != ERROR_FILE_NOT_FOUND) { ShowStoreError(g_hMain, err); break; }
    }
}

static VOID CmdRuleProps(VOID)
{
    INT sel[1];
    FW_RULE copy;
    if (SelectedRules(sel, 1) != 1) return;
    FwRuleInit(&copy);
    if (!FwRuleCopy(&copy, &g_Rules.R[sel[0]])) { FwRuleFree(&copy); return; }
    EditRuleProperties(g_hMain, &copy);
    FwRuleFree(&copy);
}

static VOID DoCommand(UINT cmd)
{
    if (!cmd) return;
    g_Busy++;
    switch (cmd)
    {
        case IDM_EXIT: DestroyWindow(g_hMain); g_Busy--; return;
        case IDM_NEWRULE:
            if (g_Node == NODE_INBOUND || g_Node == NODE_OUTBOUND)
                RunNewRuleWizard(g_hMain, g_Node == NODE_OUTBOUND ? 2 : 1);
            break;
        case IDM_ENABLE: CmdSetEnabled(TRUE); break;
        case IDM_DISABLE: CmdSetEnabled(FALSE); break;
        case IDM_DELETE: CmdDelete(); break;
        case IDM_RULEPROPS: CmdRuleProps(); break;
        case IDM_PROFPROPS: ShowProfileProperties(g_hMain); break;
        case IDM_IMPORT: DoImportPolicy(g_hMain); break;
        case IDM_EXPORT: DoExportPolicy(g_hMain); break;
        case IDM_RESTORE: DoRestorePolicy(g_hMain); break;
        case IDM_REFRESH: break;
        case IDM_ABOUT:
            MessageBoxW(g_hMain, Str(IDS_ABOUT), Str(IDS_APPNAME), MB_OK | MB_ICONINFORMATION);
            break;
    }
    g_Busy--;
    ReloadRules();
}

static VOID ShowRuleMenu(INT x, INT y)
{
    INT sel[64], n = SelectedRules(sel, ARRAYSIZE(sel)), i;
    BOOL anyOn = FALSE, anyOff = FALSE;
    HMENU m;
    if (!n) return;
    m = CreatePopupMenu();
    for (i = 0; i < n; i++) { if (g_Rules.R[sel[i]].Enabled) anyOn = TRUE; else anyOff = TRUE; }
    if (anyOn) AppendMenuW(m, MF_STRING, IDM_DISABLE, Str(IDS_ACT_DISABLE));
    if (anyOff) AppendMenuW(m, MF_STRING, IDM_ENABLE, Str(IDS_ACT_ENABLE));
    AppendMenuW(m, MF_STRING, IDM_DELETE, Str(IDS_ACT_DELETE));
    if (n == 1) AppendMenuW(m, MF_STRING, IDM_RULEPROPS, Str(IDS_ACT_RULEPROPS));
    TrackPopupMenu(m, TPM_LEFTALIGN | TPM_RIGHTBUTTON, x, y, 0, g_hMain, NULL);
    DestroyMenu(m);
}

static VOID UpdateMenus(HMENU hMenu)
{
    INT sel[2], n = 0;
    BOOL rules = (g_Node == NODE_INBOUND || g_Node == NODE_OUTBOUND);
    if (rules) n = SelectedRules(sel, 2);
    EnableMenuItem(hMenu, IDM_NEWRULE, MF_BYCOMMAND | (rules ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(hMenu, IDM_ENABLE, MF_BYCOMMAND | (n ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(hMenu, IDM_DISABLE, MF_BYCOMMAND | (n ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(hMenu, IDM_DELETE, MF_BYCOMMAND | (n ? MF_ENABLED : MF_GRAYED));
    EnableMenuItem(hMenu, IDM_RULEPROPS, MF_BYCOMMAND | (n == 1 ? MF_ENABLED : MF_GRAYED));
}

/* ------------------------------------------------------------------ window */

static HTREEITEM AddNode(HTREEITEM parent, UINT strId)
{
    TVINSERTSTRUCTW tvi;
    ZeroMemory(&tvi, sizeof(tvi));
    tvi.hParent = parent;
    tvi.hInsertAfter = TVI_LAST;
    tvi.item.mask = TVIF_TEXT;
    tvi.item.pszText = (PWSTR)Str(strId);
    return TreeView_InsertItem(g_hTree, &tvi);
}

static VOID AddColumns(VOID)
{
    static const struct { UINT str; INT w; } cols[] = {
        { IDS_COL_NAME, 220 }, { IDS_COL_GROUP, 150 }, { IDS_COL_PROFILE, 80 }, { IDS_COL_ENABLED, 60 },
        { IDS_COL_ACTION, 60 }, { IDS_COL_PROGRAM, 160 }, { IDS_COL_LADDR, 100 }, { IDS_COL_RADDR, 100 },
        { IDS_COL_PROTOCOL, 70 }, { IDS_COL_LPORT, 90 }, { IDS_COL_RPORT, 90 },
    };
    INT i;
    for (i = 0; i < (INT)ARRAYSIZE(cols); i++)
    {
        LVCOLUMNW c;
        ZeroMemory(&c, sizeof(c));
        c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        c.pszText = (PWSTR)Str(cols[i].str);
        c.cx = cols[i].w;
        c.iSubItem = i;
        ListView_InsertColumn(g_hList, i, &c);
    }
}

static BOOL OnCreate(HWND hWnd)
{
    HFONT hf = GetStockObject(DEFAULT_GUI_FONT);
    NONCLIENTMETRICSW ncm;
    HWND kids[9];
    INT i;
    g_hMain = hWnd;
    g_hStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hWnd, (HMENU)IDC_STATUS, g_hInst, NULL);
    g_hTree = CreateWindowExW(WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | TVS_HASBUTTONS | TVS_SHOWSELALWAYS | TVS_DISABLEDRAGDROP,
                              0, 0, 0, 0, hWnd, (HMENU)IDC_TREE, g_hInst, NULL);
    g_hHdrCenter = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, hWnd, (HMENU)IDC_HDR_CENTER, g_hInst, NULL);
    g_hHdrActions = CreateWindowExW(0, L"STATIC", Str(IDS_ACTIONS), WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, hWnd, (HMENU)IDC_HDR_ACTIONS, g_hInst, NULL);
    g_hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHAREIMAGELISTS | LVS_SHOWSELALWAYS,
                              0, 0, 0, 0, hWnd, (HMENU)IDC_LIST, g_hInst, NULL);
    g_hText = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, hWnd, (HMENU)IDC_TEXT, g_hInst, NULL);
    g_hPropLink = CreateWindowExW(0, L"BUTTON", Str(IDS_PROPLINK), WS_CHILD | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)IDC_PROPLINK, g_hInst, NULL);
    g_hActions = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
                                 0, 0, 0, 0, hWnd, (HMENU)IDC_ACTIONS, g_hInst, NULL);
    kids[0] = g_hStatus; kids[1] = g_hTree; kids[2] = g_hHdrCenter; kids[3] = g_hHdrActions; kids[4] = g_hList;
    kids[5] = g_hText; kids[6] = g_hPropLink; kids[7] = g_hActions; kids[8] = NULL;
    ZeroMemory(&ncm, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
    {
        hf = CreateFontIndirectW(&ncm.lfMessageFont);
        ncm.lfMessageFont.lfWeight = FW_BOLD;
        g_hBoldFont = CreateFontIndirectW(&ncm.lfMessageFont);
    }
    for (i = 0; kids[i]; i++) SendMessageW(kids[i], WM_SETFONT, (WPARAM)hf, TRUE);
    if (g_hBoldFont)
    {
        SendMessageW(g_hHdrCenter, WM_SETFONT, (WPARAM)g_hBoldFont, TRUE);
        SendMessageW(g_hHdrActions, WM_SETFONT, (WPARAM)g_hBoldFont, TRUE);
    }
    g_hHdrBrush = CreateSolidBrush(RGB(109, 109, 109));
    ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP);
    g_hRuleImages = MakeRuleImages();
    ListView_SetImageList(g_hList, g_hRuleImages, LVSIL_SMALL);
    AddColumns();
    g_hNode[NODE_ROOT] = AddNode(TVI_ROOT, IDS_ROOT);
    g_hNode[NODE_INBOUND] = AddNode(g_hNode[NODE_ROOT], IDS_INBOUND);
    g_hNode[NODE_OUTBOUND] = AddNode(g_hNode[NODE_ROOT], IDS_OUTBOUND);
    g_hNode[NODE_CSR] = AddNode(g_hNode[NODE_ROOT], IDS_CSR);
    g_hNode[NODE_MON] = AddNode(g_hNode[NODE_ROOT], IDS_MONITORING);
    TreeView_Expand(g_hTree, g_hNode[NODE_ROOT], TVE_EXPAND);
    TreeView_SelectItem(g_hTree, g_hNode[NODE_ROOT]);
    g_Node = NODE_ROOT;
    if (FwWatchOpen(&g_hWatchKey) == 0)
    {
        g_hWatchEvt = CreateEventW(NULL, FALSE, FALSE, NULL);
        RegNotifyChangeKeyValue(g_hWatchKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, g_hWatchEvt, TRUE);
        SetTimer(hWnd, IDT_WATCH, 1000, NULL);
    }
    ReloadRules();
    return TRUE;
}

static LRESULT CALLBACK MainProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_CREATE:
            return OnCreate(hWnd) ? 0 : -1;
        case WM_SIZE:
            if (g_hTree) Layout();
            return 0;
        case WM_GETMINMAXINFO:
            ((MINMAXINFO *)lParam)->ptMinTrackSize.x = 640;
            ((MINMAXINFO *)lParam)->ptMinTrackSize.y = 360;
            return 0;
        case WM_CTLCOLORSTATIC:
        {
            HWND c = (HWND)lParam;
            if (c == g_hHdrCenter || c == g_hHdrActions)
            {
                SetTextColor((HDC)wParam, RGB(255, 255, 255));
                SetBkColor((HDC)wParam, RGB(109, 109, 109));
                return (LRESULT)g_hHdrBrush;
            }
            break;
        }
        case WM_INITMENUPOPUP:
            if (!HIWORD(lParam)) UpdateMenus((HMENU)wParam);
            return 0;
        case WM_ACTIVATE:
            if (LOWORD(wParam) != WA_INACTIVE && !g_Busy && g_hTree) ReloadRules();
            return 0;
        case WM_TIMER:
            if (wParam == IDT_WATCH && g_hWatchEvt && WaitForSingleObject(g_hWatchEvt, 0) == WAIT_OBJECT_0)
            {
                RegNotifyChangeKeyValue(g_hWatchKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, g_hWatchEvt, TRUE);
                if (!g_Busy) ReloadRules();
            }
            return 0;
        case WM_REFRESHRULES:
            if (!g_Busy) ReloadRules();
            return 0;
        case WM_COMMAND:
        {
            UINT id = LOWORD(wParam);
            if (id == IDC_ACTIONS)
            {
                if (HIWORD(wParam) == LBN_SELCHANGE)
                {
                    INT s = (INT)SendMessageW(g_hActions, LB_GETCURSEL, 0, 0);
                    if (s >= 0)
                    {
                        UINT cmd = (UINT)SendMessageW(g_hActions, LB_GETITEMDATA, s, 0);
                        SendMessageW(g_hActions, LB_SETCURSEL, (WPARAM)-1, 0);
                        DoCommand(cmd);
                    }
                }
                return 0;
            }
            if (id == IDC_PROPLINK) { DoCommand(IDM_PROFPROPS); return 0; }
            if (id >= IDM_EXIT && id <= IDM_ABOUT) { DoCommand(id); return 0; }
            break;
        }
        case WM_NOTIFY:
        {
            NMHDR *nm = (NMHDR *)lParam;
            if (nm->idFrom == IDC_TREE && nm->code == TVN_SELCHANGEDW)
            {
                NMTREEVIEWW *tv = (NMTREEVIEWW *)lParam;
                INT i;
                for (i = 0; i < NODE_COUNT; i++)
                    if (g_hNode[i] == tv->itemNew.hItem) g_Node = i;
                ShowNode();
                return 0;
            }
            if (nm->idFrom == IDC_LIST)
            {
                switch (nm->code)
                {
                    case LVN_GETDISPINFOW:
                    {
                        NMLVDISPINFOW *di = (NMLVDISPINFOW *)lParam;
                        ULONG idx = (ULONG)di->item.lParam;
                        if (idx < g_Rules.N)
                        {
                            const FW_RULE *r = &g_Rules.R[idx];
                            if (di->item.mask & LVIF_TEXT)
                                CellText(r, di->item.iSubItem, di->item.pszText, di->item.cchTextMax);
                            if ((di->item.mask & LVIF_IMAGE) && di->item.iSubItem == 0)
                                di->item.iImage = !r->Enabled ? 2 : (r->Action ? 0 : 1);
                        }
                        return 0;
                    }
                    case LVN_COLUMNCLICK:
                    {
                        NMLISTVIEW *lv = (NMLISTVIEW *)lParam;
                        if (g_SortCol == lv->iSubItem) g_SortDir = -g_SortDir; else { g_SortCol = lv->iSubItem; g_SortDir = 1; }
                        ListView_SortItems(g_hList, SortCmp, 0);
                        return 0;
                    }
                    case LVN_ITEMCHANGED:
                    {
                        NMLISTVIEW *lv = (NMLISTVIEW *)lParam;
                        if (lv->uChanged & LVIF_STATE) UpdateActions();
                        return 0;
                    }
                    case LVN_KEYDOWN:
                        if (((NMLVKEYDOWN *)lParam)->wVKey == VK_DELETE) DoCommand(IDM_DELETE);
                        else if (((NMLVKEYDOWN *)lParam)->wVKey == VK_RETURN) DoCommand(IDM_RULEPROPS);
                        return 0;
                    case NM_DBLCLK:
                        DoCommand(IDM_RULEPROPS);
                        return 0;
                    case NM_RCLICK:
                    {
                        POINT pt;
                        GetCursorPos(&pt);
                        ShowRuleMenu(pt.x, pt.y);
                        return 0;
                    }
                }
            }
            break;
        }
        case WM_DESTROY:
            KillTimer(hWnd, IDT_WATCH);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

INT WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, INT show)
{
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES };
    WNDCLASSEXW wc;
    MSG msg;
    HACCEL hAcc;
    ACCEL acc[1] = { { FVIRTKEY, VK_F5, IDM_REFRESH } };
    HWND hWnd;
    INT ix, iy, iw, ih;
    UNREFERENCED_PARAMETER(hPrev);
    UNREFERENCED_PARAMETER(cmd);
    g_hInst = hInst;
    InitCommonControlsEx(&icc);
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MainProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"NitroWfAdvWnd";
    wc.hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(IDI_WFADV));
    wc.hIconSm = (HICON)LoadImageW(hInst, MAKEINTRESOURCEW(IDI_WFADV), IMAGE_ICON, 16, 16, 0);
    RegisterClassExW(&wc);
    {
        RECT wa;
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
        wa.right -= wa.left; wa.bottom -= wa.top;
        iw = min(1000, wa.right); ih = min(640, wa.bottom);
        ix = wa.left + (wa.right - iw) / 2; iy = wa.top + (wa.bottom - ih) / 2;
    }
    hWnd = CreateWindowExW(0, wc.lpszClassName, Str(IDS_APPNAME), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           ix, iy, iw, ih, NULL, LoadMenuW(hInst, MAKEINTRESOURCEW(IDR_MAINMENU)), hInst, NULL);
    if (!hWnd) return 1;
    ShowWindow(hWnd, show);
    hAcc = CreateAcceleratorTableW(acc, 1);
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        if (!TranslateAcceleratorW(hWnd, hAcc, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    DestroyAcceleratorTable(hAcc);
    FwRuleSetFree(&g_Rules);
    return (INT)msg.wParam;
}
