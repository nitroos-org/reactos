/*
 * PROJECT:     NitroOS Firewall with Advanced Security (wf.msc)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     New Rule wizard: Program, Port, Predefined, Custom
 */
#include "wfadv.h"

/* Predefined rules offered by the wizard. Rules the store already holds in the same group are used first. */
typedef struct _PDRULE { PCWSTR Group, Name, Desc; LONG Proto; PCWSTR LPort, RPort; } PDRULE;

static const PDRULE g_Predef[] = {
    { L"File and Printer Sharing", L"File and Printer Sharing (SMB-In)", L"Inbound rule for File and Printer Sharing to allow Server Message Block transmission and reception via Named Pipes.", 6, L"445", NULL },
    { L"File and Printer Sharing", L"File and Printer Sharing (NB-Session-In)", L"Inbound rule for File and Printer Sharing to allow NetBIOS Session Service connections.", 6, L"139", NULL },
    { L"File and Printer Sharing", L"File and Printer Sharing (NB-Name-In)", L"Inbound rule for File and Printer Sharing to allow NetBIOS Name Resolution.", 17, L"137", NULL },
    { L"File and Printer Sharing", L"File and Printer Sharing (NB-Datagram-In)", L"Inbound rule for File and Printer Sharing to allow NetBIOS Datagram transmission and reception.", 17, L"138", NULL },
    { L"Remote Desktop", L"Remote Desktop (TCP-In)", L"Inbound rule for the Remote Desktop service to allow RDP traffic.", 6, L"3389", NULL },
    { L"Remote Desktop", L"Remote Desktop (UDP-In)", L"Inbound rule for the Remote Desktop service to allow RDP traffic.", 17, L"3389", NULL },
    { L"World Wide Web Services (HTTP)", L"World Wide Web Services (HTTP Traffic-In)", L"An inbound rule to allow HTTP traffic for Internet Information Services (IIS) [TCP 80]", 6, L"80", NULL },
    { L"Secure World Wide Web Services (HTTPS)", L"Secure World Wide Web Services (HTTPS Traffic-In)", L"An inbound rule to allow HTTPS traffic for Internet Information Services (IIS) [TCP 443]", 6, L"443", NULL },
};

typedef struct _WZ
{
    HWND hDlg;
    LONG Dir;
    INT Seq[WP_COUNT];
    INT NSeq, Pos;
    INT Type;              /* WT_* chosen on page 0 */
    INT PortsFor;          /* WT_* the protocol combo was filled for (-1: not yet) */
    FW_RULESET Store;
    PWSTR *Groups;         /* combo index -> group name */
    ULONG NGroups;
    INT PredefGroup;       /* combo index the list shows (-1: none) */
    BOOL Done;
    HFONT hBold;
} WZ;

static VOID BuildSeq(WZ *w)
{
    static const INT prog[] = { WP_TYPE, WP_PROGRAM, WP_ACTION, WP_PROFILE, WP_NAME };
    static const INT port[] = { WP_TYPE, WP_PORTS, WP_ACTION, WP_PROFILE, WP_NAME };
    static const INT pre[] = { WP_TYPE, WP_PREDEF, WP_ACTION };
    static const INT cust[] = { WP_TYPE, WP_PROGRAM, WP_PORTS, WP_SCOPE, WP_ACTION, WP_PROFILE, WP_NAME };
    const INT *s; INT n;
    switch (w->Type)
    {
        case WT_PORT: s = port; n = ARRAYSIZE(port); break;
        case WT_PREDEF: s = pre; n = ARRAYSIZE(pre); break;
        case WT_CUSTOM: s = cust; n = ARRAYSIZE(cust); break;
        default: s = prog; n = ARRAYSIZE(prog); break;
    }
    memcpy(w->Seq, s, n * sizeof(INT));
    w->NSeq = n;
}

static VOID ShowPageControls(WZ *w, INT page)
{
    HWND c;
    for (c = GetWindow(w->hDlg, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
    {
        INT id = GetDlgCtrlID(c);
        if (id >= IDC_W_BASE && id < IDC_W_BASE + WP_COUNT * 100)
            ShowWindow(c, ((id - IDC_W_BASE) / 100 == page) ? SW_SHOW : SW_HIDE);
    }
}

static VOID FillPredefList(WZ *w)
{
    HWND hl = GetDlgItem(w->hDlg, IDC_W(WP_PREDEF, WN_RULES));
    HWND hc = GetDlgItem(w->hDlg, IDC_W(WP_PREDEF, WN_GROUP));
    INT sel = (INT)SendMessageW(hc, CB_GETCURSEL, 0, 0);
    ULONG i;
    if (sel < 0 || sel == w->PredefGroup) return;
    w->PredefGroup = sel;
    ListView_DeleteAllItems(hl);
    /* store rules of the group first (they carry the real definitions), then the catalog entries not in the store */
    for (i = 0; i < w->Store.N; i++)
    {
        LVITEMW it;
        if (!w->Store.R[i].Group || _wcsicmp(w->Store.R[i].Group, w->Groups[sel])) continue;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = ListView_GetItemCount(hl);
        it.pszText = w->Store.R[i].Name ? w->Store.R[i].Name : L"";
        it.lParam = (LPARAM)(i + 1);
        ListView_InsertItem(hl, &it);
        ListView_SetCheckState(hl, it.iItem, TRUE);
    }
    for (i = 0; i < ARRAYSIZE(g_Predef); i++)
    {
        LVITEMW it;
        ULONG j; BOOL have = FALSE;
        if (_wcsicmp(g_Predef[i].Group, w->Groups[sel])) continue;
        /* a group the store already defines (the default policy ships several) is listed from the store only */
        for (j = 0; j < w->Store.N; j++)
            if (w->Store.R[j].Group && !_wcsicmp(w->Store.R[j].Group, g_Predef[i].Group)) have = TRUE;
        if (have) continue;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = ListView_GetItemCount(hl);
        it.pszText = (PWSTR)g_Predef[i].Name;
        it.lParam = -(LPARAM)(i + 1);
        ListView_InsertItem(hl, &it);
        ListView_SetCheckState(hl, it.iItem, TRUE);
    }
}

static VOID InitPredef(WZ *w)
{
    HWND hc = GetDlgItem(w->hDlg, IDC_W(WP_PREDEF, WN_GROUP));
    HWND hl = GetDlgItem(w->hDlg, IDC_W(WP_PREDEF, WN_RULES));
    ULONG i, j, cap = ARRAYSIZE(g_Predef) + w->Store.N;
    LVCOLUMNW col;
    RECT rc;
    w->Groups = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(PWSTR));
    ListView_SetExtendedListViewStyle(hl, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);
    GetClientRect(hl, &rc);
    ZeroMemory(&col, sizeof(col));
    col.mask = LVCF_WIDTH;
    col.cx = rc.right - GetSystemMetrics(SM_CXVSCROLL) - 2;
    ListView_InsertColumn(hl, 0, &col);
    if (!w->Groups) return;
    for (i = 0; i < ARRAYSIZE(g_Predef) + w->Store.N; i++)
    {
        PCWSTR g = i < ARRAYSIZE(g_Predef) ? g_Predef[i].Group : w->Store.R[i - ARRAYSIZE(g_Predef)].Group;
        BOOL dup = FALSE;
        if (!g || !*g) continue;
        for (j = 0; j < w->NGroups; j++) if (!_wcsicmp(w->Groups[j], g)) dup = TRUE;
        if (dup) continue;
        w->Groups[w->NGroups] = HeapAlloc(GetProcessHeap(), 0, (wcslen(g) + 1) * sizeof(WCHAR));
        if (!w->Groups[w->NGroups]) continue;
        wcscpy(w->Groups[w->NGroups], g);
        SendMessageW(hc, CB_ADDSTRING, 0, (LPARAM)g);
        w->NGroups++;
    }
    w->PredefGroup = -1;
    SendMessageW(hc, CB_SETCURSEL, 0, 0);
    FillPredefList(w);
}

static VOID PortsEnable(HWND hDlg)
{
    BOOL ports;
    LONG proto = 256;
    EnableProtoControls(hDlg, IDC_W(WP_PORTS, WN_PROTO), IDC_W(WP_PORTS, WN_PROTONUM), 0, 0, 0);
    GetProtocolCombo(hDlg, IDC_W(WP_PORTS, WN_PROTO), IDC_W(WP_PORTS, WN_PROTONUM), &proto);
    ports = (proto == 6 || proto == 17);
    EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PORTS, WN_LALL)), ports);
    EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PORTS, WN_LSEL)), ports);
    EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PORTS, WN_RALL)), ports);
    EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PORTS, WN_RSEL)), ports);
    EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PORTS, WN_LPORT)), ports && IsDlgButtonChecked(hDlg, IDC_W(WP_PORTS, WN_LSEL)) == BST_CHECKED);
    EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PORTS, WN_RPORT)), ports && IsDlgButtonChecked(hDlg, IDC_W(WP_PORTS, WN_RSEL)) == BST_CHECKED);
}

static VOID EnterPage(WZ *w)
{
    INT p = w->Seq[w->Pos];
    BOOL last = (w->Pos == w->NSeq - 1);
    static const UINT titles[WP_COUNT] = { IDS_WIZ_PG_TYPE, IDS_WIZ_PG_PROGRAM, IDS_WIZ_PG_PORTS, IDS_WIZ_PG_PREDEF, IDS_WIZ_PG_SCOPE, IDS_WIZ_PG_ACTION, IDS_WIZ_PG_PROFILE, IDS_WIZ_PG_NAME };
    static const UINT subs[WP_COUNT] = { IDS_WIZ_SUB_TYPE, IDS_WIZ_SUB_PROGRAM, IDS_WIZ_SUB_PORTS, IDS_WIZ_SUB_PREDEF, IDS_WIZ_SUB_SCOPE, IDS_WIZ_SUB_ACTION, IDS_WIZ_SUB_PROFILE, IDS_WIZ_SUB_NAME };
    SetDlgItemTextW(w->hDlg, IDC_W_TITLE, Str(titles[p]));
    SetDlgItemTextW(w->hDlg, IDC_W_SUBTITLE, Str(subs[p]));
    if (p == WP_PORTS && w->PortsFor != w->Type)
    {
        HWND hc = GetDlgItem(w->hDlg, IDC_W(WP_PORTS, WN_PROTO));
        FillProtocolCombo(hc, w->Type == WT_PORT);
        SetProtocolCombo(w->hDlg, IDC_W(WP_PORTS, WN_PROTO), IDC_W(WP_PORTS, WN_PROTONUM), w->Type == WT_PORT ? 6 : 256);
        if (w->Type == WT_PORT)
            CheckRadioButton(w->hDlg, IDC_W(WP_PORTS, WN_LALL), IDC_W(WP_PORTS, WN_LSEL), IDC_W(WP_PORTS, WN_LSEL));
        PortsEnable(w->hDlg);
        w->PortsFor = w->Type;
    }
    ShowPageControls(w, p);
    EnableWindow(GetDlgItem(w->hDlg, IDC_W_BACK), w->Pos > 0);
    SetDlgItemTextW(w->hDlg, IDC_W_NEXT, Str(last ? IDS_WIZ_FINISH : IDS_WIZ_NEXT));
}

static BOOL Warn(WZ *w, UINT msg, UINT focusId)
{
    MessageBoxW(w->hDlg, Str(msg), Str(IDS_WIZ_TITLE), MB_OK | MB_ICONWARNING);
    if (focusId) SetFocus(GetDlgItem(w->hDlg, focusId));
    return FALSE;
}

static BOOL ValidatePage(WZ *w)
{
    WCHAR a[600], b[600];
    switch (w->Seq[w->Pos])
    {
        case WP_TYPE:
        {
            INT t = IsDlgButtonChecked(w->hDlg, IDC_W(WP_TYPE, WT_PORT)) == BST_CHECKED ? WT_PORT :
                    IsDlgButtonChecked(w->hDlg, IDC_W(WP_TYPE, WT_PREDEF)) == BST_CHECKED ? WT_PREDEF :
                    IsDlgButtonChecked(w->hDlg, IDC_W(WP_TYPE, WT_CUSTOM)) == BST_CHECKED ? WT_CUSTOM : WT_PROGRAM;
            if (t != w->Type) { w->Type = t; BuildSeq(w); }
            return TRUE;
        }
        case WP_PROGRAM:
            if (IsDlgButtonChecked(w->hDlg, IDC_W(WP_PROGRAM, WN_THISPROG)) == BST_CHECKED)
            {
                GetEditText(w->hDlg, IDC_W(WP_PROGRAM, WN_PATH), a, ARRAYSIZE(a));
                if (!a[0]) return Warn(w, IDS_ERR_PATH, IDC_W(WP_PROGRAM, WN_PATH));
            }
            return TRUE;
        case WP_PORTS:
        {
            LONG proto;
            if (!GetProtocolCombo(w->hDlg, IDC_W(WP_PORTS, WN_PROTO), IDC_W(WP_PORTS, WN_PROTONUM), &proto))
                return Warn(w, IDS_ERR_PROTO, IDC_W(WP_PORTS, WN_PROTONUM));
            if (!GetRadioEdit(w->hDlg, IDC_W(WP_PORTS, WN_LALL), IDC_W(WP_PORTS, WN_LSEL), IDC_W(WP_PORTS, WN_LPORT), a, ARRAYSIZE(a)) ||
                !GetRadioEdit(w->hDlg, IDC_W(WP_PORTS, WN_RALL), IDC_W(WP_PORTS, WN_RSEL), IDC_W(WP_PORTS, WN_RPORT), b, ARRAYSIZE(b)) ||
                FwCheckPorts(a) || FwCheckPorts(b))
                return Warn(w, IDS_ERR_PORTS, IDC_W(WP_PORTS, WN_LPORT));
            return TRUE;
        }
        case WP_SCOPE:
            if (!GetRadioEdit(w->hDlg, IDC_W(WP_SCOPE, WN_LANY), IDC_W(WP_SCOPE, WN_LTHESE), IDC_W(WP_SCOPE, WN_LADDR), a, ARRAYSIZE(a)) ||
                !GetRadioEdit(w->hDlg, IDC_W(WP_SCOPE, WN_RANY), IDC_W(WP_SCOPE, WN_RTHESE), IDC_W(WP_SCOPE, WN_RADDR), b, ARRAYSIZE(b)) ||
                FwCheckAddrs(a) || FwCheckAddrs(b))
                return Warn(w, IDS_ERR_ADDRS, IDC_W(WP_SCOPE, WN_LADDR));
            return TRUE;
        case WP_NAME:
            GetEditText(w->hDlg, IDC_W(WP_NAME, WN_NAME), a, ARRAYSIZE(a));
            if (!a[0]) return Warn(w, IDS_ERR_NONAME, IDC_W(WP_NAME, WN_NAME));
            return TRUE;
        case WP_PREDEF:
        {
            HWND hl = GetDlgItem(w->hDlg, IDC_W(WP_PREDEF, WN_RULES));
            INT i, n = ListView_GetItemCount(hl);
            for (i = 0; i < n; i++) if (ListView_GetCheckState(hl, i)) return TRUE;
            return Warn(w, IDS_WIZ_ERR_PROG, IDC_W(WP_PREDEF, WN_RULES));
        }
    }
    return TRUE;
}

static BOOL Write(WZ *w, FW_RULE *r, BOOL update)
{
    DWORD err = update ? FwStoreUpdate(r) : FwStoreAdd(r);
    if (err) { ShowStoreError(w->hDlg, err); return FALSE; }
    return TRUE;
}

static BOOL FinishPredef(WZ *w)
{
    HWND hl = GetDlgItem(w->hDlg, IDC_W(WP_PREDEF, WN_RULES));
    INT i, n = ListView_GetItemCount(hl);
    LONG action = IsDlgButtonChecked(w->hDlg, IDC_W(WP_ACTION, WN_ALLOW)) == BST_CHECKED ? 1 : 0;
    for (i = 0; i < n; i++)
    {
        LVITEMW it;
        FW_RULE r;
        BOOL ok;
        if (!ListView_GetCheckState(hl, i)) continue;
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_PARAM; it.iItem = i;
        ListView_GetItem(hl, &it);
        if (it.lParam > 0)
        {
            /* a rule of the store: enable it and set the action */
            FwRuleInit(&r);
            if (!FwRuleCopy(&r, &w->Store.R[it.lParam - 1])) { FwRuleFree(&r); continue; }
            r.Enabled = TRUE; r.Action = action;
            ok = Write(w, &r, TRUE);
        }
        else
        {
            const PDRULE *p = &g_Predef[-it.lParam - 1];
            FwRuleInit(&r);
            FwRuleSetStr(&r.Name, p->Name); FwRuleSetStr(&r.Desc, p->Desc); FwRuleSetStr(&r.Group, p->Group);
            r.Enabled = TRUE; r.Action = action; r.Dir = 1; r.Protocol = p->Proto;
            FwRuleSetStr(&r.LPorts, p->LPort); FwRuleSetStr(&r.RPorts, p->RPort);
            ok = Write(w, &r, FALSE);
        }
        FwRuleFree(&r);
        if (!ok) return FALSE;
    }
    return TRUE;
}

static BOOL Finish(WZ *w)
{
    FW_RULE r;
    WCHAR a[600], b[600], name[300], desc[600], path[MAX_PATH];
    LONG proto = 256, m = 0;
    BOOL ok;
    if (w->Type == WT_PREDEF)
        return FinishPredef(w);
    FwRuleInit(&r);
    r.Enabled = TRUE;
    r.Dir = w->Dir;
    r.Action = IsDlgButtonChecked(w->hDlg, IDC_W(WP_ACTION, WN_ALLOW)) == BST_CHECKED ? 1 : 0;
    if (w->Type == WT_PROGRAM || w->Type == WT_CUSTOM)
    {
        if (IsDlgButtonChecked(w->hDlg, IDC_W(WP_PROGRAM, WN_THISPROG)) == BST_CHECKED)
        {
            GetEditText(w->hDlg, IDC_W(WP_PROGRAM, WN_PATH), path, ARRAYSIZE(path));
            FwRuleSetStr(&r.App, path);
        }
    }
    if (w->Type == WT_PORT || w->Type == WT_CUSTOM)
    {
        GetProtocolCombo(w->hDlg, IDC_W(WP_PORTS, WN_PROTO), IDC_W(WP_PORTS, WN_PROTONUM), &proto);
        r.Protocol = proto;
        if (proto == 6 || proto == 17)
        {
            GetRadioEdit(w->hDlg, IDC_W(WP_PORTS, WN_LALL), IDC_W(WP_PORTS, WN_LSEL), IDC_W(WP_PORTS, WN_LPORT), a, ARRAYSIZE(a));
            GetRadioEdit(w->hDlg, IDC_W(WP_PORTS, WN_RALL), IDC_W(WP_PORTS, WN_RSEL), IDC_W(WP_PORTS, WN_RPORT), b, ARRAYSIZE(b));
            FwRuleSetStr(&r.LPorts, a);
            FwRuleSetStr(&r.RPorts, b);
        }
    }
    if (w->Type == WT_CUSTOM)
    {
        GetRadioEdit(w->hDlg, IDC_W(WP_SCOPE, WN_LANY), IDC_W(WP_SCOPE, WN_LTHESE), IDC_W(WP_SCOPE, WN_LADDR), a, ARRAYSIZE(a));
        GetRadioEdit(w->hDlg, IDC_W(WP_SCOPE, WN_RANY), IDC_W(WP_SCOPE, WN_RTHESE), IDC_W(WP_SCOPE, WN_RADDR), b, ARRAYSIZE(b));
        FwRuleSetStr(&r.LAddr, a);
        FwRuleSetStr(&r.RAddr, b);
    }
    if (IsDlgButtonChecked(w->hDlg, IDC_W(WP_PROFILE, WN_DOMAIN)) == BST_CHECKED) m |= FWP_DOMAIN;
    if (IsDlgButtonChecked(w->hDlg, IDC_W(WP_PROFILE, WN_PRIVATE)) == BST_CHECKED) m |= FWP_PRIVATE;
    if (IsDlgButtonChecked(w->hDlg, IDC_W(WP_PROFILE, WN_PUBLIC)) == BST_CHECKED) m |= FWP_PUBLIC;
    r.Profiles = (m == 0 || m == FWP_ALL) ? FWP_ANY_COM : m;
    GetEditText(w->hDlg, IDC_W(WP_NAME, WN_NAME), name, ARRAYSIZE(name));
    GetDlgItemTextW(w->hDlg, IDC_W(WP_NAME, WN_DESC), desc, ARRAYSIZE(desc));
    FwRuleSetStr(&r.Name, name);
    FwRuleSetStr(&r.Desc, desc);
    ok = Write(w, &r, FALSE);
    FwRuleFree(&r);
    return ok;
}

static VOID InitControls(WZ *w)
{
    HWND d = w->hDlg;
    CheckRadioButton(d, IDC_W(WP_TYPE, WT_PROGRAM), IDC_W(WP_TYPE, WT_CUSTOM), IDC_W(WP_TYPE, WT_PROGRAM));
    CheckRadioButton(d, IDC_W(WP_PROGRAM, WN_ALLPROGS), IDC_W(WP_PROGRAM, WN_THISPROG), IDC_W(WP_PROGRAM, WN_ALLPROGS));
    EnableWindow(GetDlgItem(d, IDC_W(WP_PROGRAM, WN_PATH)), FALSE);
    EnableWindow(GetDlgItem(d, IDC_W(WP_PROGRAM, WN_BROWSE)), FALSE);
    SetRadioEdit(d, IDC_W(WP_PORTS, WN_LALL), IDC_W(WP_PORTS, WN_LSEL), IDC_W(WP_PORTS, WN_LPORT), NULL);
    SetRadioEdit(d, IDC_W(WP_PORTS, WN_RALL), IDC_W(WP_PORTS, WN_RSEL), IDC_W(WP_PORTS, WN_RPORT), NULL);
    SetRadioEdit(d, IDC_W(WP_SCOPE, WN_LANY), IDC_W(WP_SCOPE, WN_LTHESE), IDC_W(WP_SCOPE, WN_LADDR), NULL);
    SetRadioEdit(d, IDC_W(WP_SCOPE, WN_RANY), IDC_W(WP_SCOPE, WN_RTHESE), IDC_W(WP_SCOPE, WN_RADDR), NULL);
    CheckRadioButton(d, IDC_W(WP_ACTION, WN_ALLOW), IDC_W(WP_ACTION, WN_BLOCK), IDC_W(WP_ACTION, WN_ALLOW));
    CheckDlgButton(d, IDC_W(WP_PROFILE, WN_DOMAIN), BST_CHECKED);
    CheckDlgButton(d, IDC_W(WP_PROFILE, WN_PRIVATE), BST_CHECKED);
    CheckDlgButton(d, IDC_W(WP_PROFILE, WN_PUBLIC), BST_CHECKED);
    FwStoreLoad(&w->Store);
    InitPredef(w);
    w->PortsFor = -1;
    w->Type = WT_PROGRAM;
    BuildSeq(w);
    w->Pos = 0;
    EnterPage(w);
}

static INT_PTR CALLBACK WizardProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    WZ *w = (WZ *)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (msg)
    {
        case WM_INITDIALOG:
            w = (WZ *)lParam;
            w->hDlg = hDlg;
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)w);
            SendMessageW(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_WFADV), IMAGE_ICON, 16, 16, 0));
            SetWindowTextW(hDlg, Str(w->Dir == 2 ? IDS_WIZ_TITLE_OUT : IDS_WIZ_TITLE));
            {
                NONCLIENTMETRICSW ncm;
                ZeroMemory(&ncm, sizeof(ncm));
                ncm.cbSize = sizeof(ncm);
                if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
                {
                    ncm.lfMessageFont.lfWeight = FW_BOLD;
                    w->hBold = CreateFontIndirectW(&ncm.lfMessageFont);
                    if (w->hBold) SendDlgItemMessageW(hDlg, IDC_W_TITLE, WM_SETFONT, (WPARAM)w->hBold, TRUE);
                }
            }
            InitControls(w);
            return TRUE;
        case WM_COMMAND:
        {
            UINT id = LOWORD(wParam);
            if (HIWORD(wParam) == BN_CLICKED)
            {
                static const UINT grp[][2] = {
                    { IDC_W(WP_TYPE, WT_PROGRAM), IDC_W(WP_TYPE, WT_CUSTOM) },
                    { IDC_W(WP_PROGRAM, WN_ALLPROGS), IDC_W(WP_PROGRAM, WN_THISPROG) },
                    { IDC_W(WP_PORTS, WN_LALL), IDC_W(WP_PORTS, WN_LSEL) },
                    { IDC_W(WP_PORTS, WN_RALL), IDC_W(WP_PORTS, WN_RSEL) },
                    { IDC_W(WP_SCOPE, WN_LANY), IDC_W(WP_SCOPE, WN_LTHESE) },
                    { IDC_W(WP_SCOPE, WN_RANY), IDC_W(WP_SCOPE, WN_RTHESE) },
                    { IDC_W(WP_ACTION, WN_ALLOW), IDC_W(WP_ACTION, WN_BLOCK) },
                };
                INT gi;
                for (gi = 0; gi < (INT)ARRAYSIZE(grp); gi++)
                    if (id >= grp[gi][0] && id <= grp[gi][1])
                        CheckRadioButton(hDlg, grp[gi][0], grp[gi][1], id);
            }
            if (id == IDCANCEL) { EndDialog(hDlg, 0); return TRUE; }
            if (id == IDC_W_BACK && w->Pos > 0) { w->Pos--; EnterPage(w); return TRUE; }
            if (id == IDC_W_NEXT)
            {
                if (!ValidatePage(w)) return TRUE;
                if (w->Pos == w->NSeq - 1)
                {
                    if (Finish(w)) { w->Done = TRUE; EndDialog(hDlg, 1); }
                    return TRUE;
                }
                w->Pos++;
                EnterPage(w);
                return TRUE;
            }
            if (id == IDC_W(WP_PROGRAM, WN_ALLPROGS) || id == IDC_W(WP_PROGRAM, WN_THISPROG))
            {
                BOOL on = IsDlgButtonChecked(hDlg, IDC_W(WP_PROGRAM, WN_THISPROG)) == BST_CHECKED;
                EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PROGRAM, WN_PATH)), on);
                EnableWindow(GetDlgItem(hDlg, IDC_W(WP_PROGRAM, WN_BROWSE)), on);
            }
            else if (id == IDC_W(WP_PROGRAM, WN_BROWSE))
                BrowseForProgram(hDlg, IDC_W(WP_PROGRAM, WN_PATH));
            else if (id == IDC_W(WP_PORTS, WN_LALL) || id == IDC_W(WP_PORTS, WN_LSEL))
                UpdateRadioEdit(hDlg, IDC_W(WP_PORTS, WN_LALL), IDC_W(WP_PORTS, WN_LSEL), IDC_W(WP_PORTS, WN_LPORT));
            else if (id == IDC_W(WP_PORTS, WN_RALL) || id == IDC_W(WP_PORTS, WN_RSEL))
                UpdateRadioEdit(hDlg, IDC_W(WP_PORTS, WN_RALL), IDC_W(WP_PORTS, WN_RSEL), IDC_W(WP_PORTS, WN_RPORT));
            else if (id == IDC_W(WP_SCOPE, WN_LANY) || id == IDC_W(WP_SCOPE, WN_LTHESE))
                UpdateRadioEdit(hDlg, IDC_W(WP_SCOPE, WN_LANY), IDC_W(WP_SCOPE, WN_LTHESE), IDC_W(WP_SCOPE, WN_LADDR));
            else if (id == IDC_W(WP_SCOPE, WN_RANY) || id == IDC_W(WP_SCOPE, WN_RTHESE))
                UpdateRadioEdit(hDlg, IDC_W(WP_SCOPE, WN_RANY), IDC_W(WP_SCOPE, WN_RTHESE), IDC_W(WP_SCOPE, WN_RADDR));
            else if ((id == IDC_W(WP_PORTS, WN_PROTO) && HIWORD(wParam) == CBN_SELCHANGE) ||
                     (id == IDC_W(WP_PORTS, WN_PROTONUM) && HIWORD(wParam) == EN_CHANGE))
                PortsEnable(hDlg);
            else if (id == IDC_W(WP_PREDEF, WN_GROUP) && HIWORD(wParam) == CBN_SELCHANGE)
                FillPredefList(w);
            return TRUE;
        }
    }
    return FALSE;
}

BOOL RunNewRuleWizard(HWND hOwner, LONG dir)
{
    WZ w;
    ULONG i;
    ZeroMemory(&w, sizeof(w));
    w.Dir = dir;
    DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_WIZARD), hOwner, WizardProc, (LPARAM)&w);
    if (w.hBold) DeleteObject(w.hBold);
    for (i = 0; i < w.NGroups; i++) HeapFree(GetProcessHeap(), 0, w.Groups[i]);
    if (w.Groups) HeapFree(GetProcessHeap(), 0, w.Groups);
    FwRuleSetFree(&w.Store);
    return w.Done;
}
