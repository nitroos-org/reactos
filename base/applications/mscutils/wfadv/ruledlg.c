/*
 * PROJECT:     NitroOS Firewall with Advanced Security (wf.msc)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Rule properties: General, Programs and Services, Protocols and Ports, Scope, Advanced
 */
#include "wfadv.h"

typedef struct _RPCTX
{
    FW_RULE Work;       /* working copy, Id = the stored rule */
    BOOL Saved;
} RPCTX;

static BOOL Commit(RPCTX *c, HWND hDlg)
{
    DWORD err = FwStoreUpdate(&c->Work);
    if (err)
    {
        ShowStoreError(hDlg, err);
        return FALSE;
    }
    c->Saved = TRUE;
    NotifyMainRefresh();
    return TRUE;
}

static VOID Reject(HWND hDlg, UINT idMsg, UINT idFocus)
{
    MessageBoxW(hDlg, Str(idMsg), Str(IDS_APPNAME), MB_OK | MB_ICONWARNING);
    if (idFocus) SetFocus(GetDlgItem(hDlg, idFocus));
    SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
}

/* ---- General ---- */
static INT_PTR CALLBACK GeneralProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RPCTX *c;
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            PROPSHEETPAGEW *psp = (PROPSHEETPAGEW *)lParam;
            c = (RPCTX *)psp->lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)c);
            SetDlgItemTextW(hDlg, IDC_RP_NAME, c->Work.Name ? c->Work.Name : L"");
            SetDlgItemTextW(hDlg, IDC_RP_DESC, c->Work.Desc ? c->Work.Desc : L"");
            SetDlgItemTextW(hDlg, IDC_RP_GROUP, c->Work.Group ? c->Work.Group : L"");
            CheckDlgButton(hDlg, IDC_RP_ENABLED, c->Work.Enabled ? BST_CHECKED : BST_UNCHECKED);
            CheckRadioButton(hDlg, IDC_RP_ALLOW, IDC_RP_BLOCK, c->Work.Action ? IDC_RP_ALLOW : IDC_RP_BLOCK);
            return TRUE;
        }
        case WM_COMMAND:
            if (HIWORD(wParam) == BN_CLICKED && (LOWORD(wParam) == IDC_RP_ALLOW || LOWORD(wParam) == IDC_RP_BLOCK))
                CheckRadioButton(hDlg, IDC_RP_ALLOW, IDC_RP_BLOCK, LOWORD(wParam));
            if (HIWORD(wParam) == EN_CHANGE || HIWORD(wParam) == BN_CLICKED)
                PropSheet_Changed(GetParent(hDlg), hDlg);
            break;
        case WM_NOTIFY:
            if (((NMHDR *)lParam)->code == PSN_APPLY)
            {
                WCHAR name[300], desc[600];
                c = (RPCTX *)GetWindowLongPtrW(hDlg, DWLP_USER);
                GetEditText(hDlg, IDC_RP_NAME, name, ARRAYSIZE(name));
                if (!name[0]) { Reject(hDlg, IDS_ERR_NONAME, IDC_RP_NAME); return TRUE; }
                GetDlgItemTextW(hDlg, IDC_RP_DESC, desc, ARRAYSIZE(desc));
                FwRuleSetStr(&c->Work.Name, name);
                FwRuleSetStr(&c->Work.Desc, desc);
                c->Work.Enabled = IsDlgButtonChecked(hDlg, IDC_RP_ENABLED) == BST_CHECKED;
                c->Work.Action = IsDlgButtonChecked(hDlg, IDC_RP_ALLOW) == BST_CHECKED ? 1 : 0;
                if (!Commit(c, hDlg)) SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

/* ---- Programs and Services ---- */
static INT_PTR CALLBACK ProgramsProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RPCTX *c;
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            BOOL has;
            c = (RPCTX *)((PROPSHEETPAGEW *)lParam)->lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)c);
            has = c->Work.App && *c->Work.App && _wcsicmp(c->Work.App, L"*");
            CheckRadioButton(hDlg, IDC_RP_ALLPROGS, IDC_RP_THISPROG, has ? IDC_RP_THISPROG : IDC_RP_ALLPROGS);
            SetDlgItemTextW(hDlg, IDC_RP_PROGPATH, has ? c->Work.App : L"");
            EnableWindow(GetDlgItem(hDlg, IDC_RP_PROGPATH), has);
            EnableWindow(GetDlgItem(hDlg, IDC_RP_BROWSE), has);
            SetDlgItemTextW(hDlg, IDC_RP_SERVICE, c->Work.Svc && _wcsicmp(c->Work.Svc, L"*") ? c->Work.Svc : L"");
            return TRUE;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_RP_ALLPROGS:
                case IDC_RP_THISPROG:
                {
                    BOOL on;
                    CheckRadioButton(hDlg, IDC_RP_ALLPROGS, IDC_RP_THISPROG, LOWORD(wParam));
                    on = IsDlgButtonChecked(hDlg, IDC_RP_THISPROG) == BST_CHECKED;
                    EnableWindow(GetDlgItem(hDlg, IDC_RP_PROGPATH), on);
                    EnableWindow(GetDlgItem(hDlg, IDC_RP_BROWSE), on);
                    PropSheet_Changed(GetParent(hDlg), hDlg);
                    break;
                }
                case IDC_RP_BROWSE:
                    if (BrowseForProgram(hDlg, IDC_RP_PROGPATH))
                        PropSheet_Changed(GetParent(hDlg), hDlg);
                    break;
                case IDC_RP_PROGPATH:
                case IDC_RP_SERVICE:
                    if (HIWORD(wParam) == EN_CHANGE)
                        PropSheet_Changed(GetParent(hDlg), hDlg);
                    break;
            }
            break;
        case WM_NOTIFY:
            if (((NMHDR *)lParam)->code == PSN_APPLY)
            {
                WCHAR path[MAX_PATH], svc[256];
                c = (RPCTX *)GetWindowLongPtrW(hDlg, DWLP_USER);
                if (IsDlgButtonChecked(hDlg, IDC_RP_THISPROG) == BST_CHECKED)
                {
                    GetEditText(hDlg, IDC_RP_PROGPATH, path, ARRAYSIZE(path));
                    if (!path[0]) { Reject(hDlg, IDS_ERR_PATH, IDC_RP_PROGPATH); return TRUE; }
                }
                else
                    path[0] = 0;
                GetEditText(hDlg, IDC_RP_SERVICE, svc, ARRAYSIZE(svc));
                FwRuleSetStr(&c->Work.App, path);
                FwRuleSetStr(&c->Work.Svc, svc);
                if (!Commit(c, hDlg)) SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

/* ---- Protocols and Ports ---- */
static INT_PTR CALLBACK PortsProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RPCTX *c;
    switch (msg)
    {
        case WM_INITDIALOG:
            c = (RPCTX *)((PROPSHEETPAGEW *)lParam)->lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)c);
            FillProtocolCombo(GetDlgItem(hDlg, IDC_RP_PROTO), FALSE);
            SetProtocolCombo(hDlg, IDC_RP_PROTO, IDC_RP_PROTONUM, c->Work.Protocol);
            SetDlgItemTextW(hDlg, IDC_RP_LPORT, c->Work.LPorts && wcscmp(c->Work.LPorts, L"*") ? c->Work.LPorts : L"");
            SetDlgItemTextW(hDlg, IDC_RP_RPORT, c->Work.RPorts && wcscmp(c->Work.RPorts, L"*") ? c->Work.RPorts : L"");
            SetDlgItemTextW(hDlg, IDC_RP_ICMP, c->Work.Icmp && wcscmp(c->Work.Icmp, L"*") ? c->Work.Icmp : L"");
            EnableProtoControls(hDlg, IDC_RP_PROTO, IDC_RP_PROTONUM, IDC_RP_LPORT, IDC_RP_RPORT, IDC_RP_ICMP);
            return TRUE;
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_RP_PROTO:
                    if (HIWORD(wParam) == CBN_SELCHANGE)
                    {
                        EnableProtoControls(hDlg, IDC_RP_PROTO, IDC_RP_PROTONUM, IDC_RP_LPORT, IDC_RP_RPORT, IDC_RP_ICMP);
                        PropSheet_Changed(GetParent(hDlg), hDlg);
                    }
                    break;
                case IDC_RP_PROTONUM:
                    if (HIWORD(wParam) == EN_CHANGE)
                    {
                        EnableProtoControls(hDlg, IDC_RP_PROTO, IDC_RP_PROTONUM, IDC_RP_LPORT, IDC_RP_RPORT, IDC_RP_ICMP);
                        PropSheet_Changed(GetParent(hDlg), hDlg);
                    }
                    break;
                case IDC_RP_LPORT:
                case IDC_RP_RPORT:
                case IDC_RP_ICMP:
                    if (HIWORD(wParam) == EN_CHANGE)
                        PropSheet_Changed(GetParent(hDlg), hDlg);
                    break;
            }
            break;
        case WM_NOTIFY:
            if (((NMHDR *)lParam)->code == PSN_APPLY)
            {
                LONG proto;
                WCHAR lp[300], rp[300], icmp[100];
                BOOL ports;
                c = (RPCTX *)GetWindowLongPtrW(hDlg, DWLP_USER);
                if (!GetProtocolCombo(hDlg, IDC_RP_PROTO, IDC_RP_PROTONUM, &proto))
                { Reject(hDlg, IDS_ERR_PROTO, IDC_RP_PROTONUM); return TRUE; }
                ports = (proto == 6 || proto == 17);
                GetEditText(hDlg, IDC_RP_LPORT, lp, ARRAYSIZE(lp));
                GetEditText(hDlg, IDC_RP_RPORT, rp, ARRAYSIZE(rp));
                GetEditText(hDlg, IDC_RP_ICMP, icmp, ARRAYSIZE(icmp));
                if (!ports) { lp[0] = 0; rp[0] = 0; }
                if (proto != 1 && proto != 58) icmp[0] = 0;
                if (FwCheckPorts(lp) || FwCheckPorts(rp))
                { Reject(hDlg, IDS_ERR_PORTS, IDC_RP_LPORT); return TRUE; }
                c->Work.Protocol = proto;
                FwRuleSetStr(&c->Work.LPorts, lp);
                FwRuleSetStr(&c->Work.RPorts, rp);
                FwRuleSetStr(&c->Work.Icmp, icmp);
                if (!Commit(c, hDlg)) SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

/* ---- Scope ---- */
static INT_PTR CALLBACK ScopeProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RPCTX *c;
    switch (msg)
    {
        case WM_INITDIALOG:
            c = (RPCTX *)((PROPSHEETPAGEW *)lParam)->lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)c);
            SetRadioEdit(hDlg, IDC_RP_LADDR_ANY, IDC_RP_LADDR_SEL, IDC_RP_LADDR, c->Work.LAddr);
            SetRadioEdit(hDlg, IDC_RP_RADDR_ANY, IDC_RP_RADDR_SEL, IDC_RP_RADDR, c->Work.RAddr);
            return TRUE;
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_RP_LADDR_ANY:
                case IDC_RP_LADDR_SEL:
                    CheckRadioButton(hDlg, IDC_RP_LADDR_ANY, IDC_RP_LADDR_SEL, LOWORD(wParam));
                    UpdateRadioEdit(hDlg, IDC_RP_LADDR_ANY, IDC_RP_LADDR_SEL, IDC_RP_LADDR);
                    PropSheet_Changed(GetParent(hDlg), hDlg);
                    break;
                case IDC_RP_RADDR_ANY:
                case IDC_RP_RADDR_SEL:
                    CheckRadioButton(hDlg, IDC_RP_RADDR_ANY, IDC_RP_RADDR_SEL, LOWORD(wParam));
                    UpdateRadioEdit(hDlg, IDC_RP_RADDR_ANY, IDC_RP_RADDR_SEL, IDC_RP_RADDR);
                    PropSheet_Changed(GetParent(hDlg), hDlg);
                    break;
                case IDC_RP_LADDR:
                case IDC_RP_RADDR:
                    if (HIWORD(wParam) == EN_CHANGE)
                        PropSheet_Changed(GetParent(hDlg), hDlg);
                    break;
            }
            break;
        case WM_NOTIFY:
            if (((NMHDR *)lParam)->code == PSN_APPLY)
            {
                WCHAR la[600], ra[600];
                c = (RPCTX *)GetWindowLongPtrW(hDlg, DWLP_USER);
                if (!GetRadioEdit(hDlg, IDC_RP_LADDR_ANY, IDC_RP_LADDR_SEL, IDC_RP_LADDR, la, ARRAYSIZE(la)) ||
                    !GetRadioEdit(hDlg, IDC_RP_RADDR_ANY, IDC_RP_RADDR_SEL, IDC_RP_RADDR, ra, ARRAYSIZE(ra)) ||
                    FwCheckAddrs(la) || FwCheckAddrs(ra))
                { Reject(hDlg, IDS_ERR_ADDRS, IDC_RP_LADDR); return TRUE; }
                FwRuleSetStr(&c->Work.LAddr, la);
                FwRuleSetStr(&c->Work.RAddr, ra);
                if (!Commit(c, hDlg)) SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

/* ---- Advanced ---- */
static BOOL HasIfType(PCWSTR list, PCWSTR kind)
{
    WCHAR *copy, *tok;
    BOOL r = FALSE;
    if (!list || !*list || !_wcsicmp(list, L"All")) return TRUE;
    copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(list) + 1) * sizeof(WCHAR));
    if (!copy) return TRUE;
    wcscpy(copy, list);
    for (tok = wcstok(copy, L","); tok; tok = wcstok(NULL, L","))
        if (!_wcsicmp(tok, kind)) r = TRUE;
    HeapFree(GetProcessHeap(), 0, copy);
    return r;
}

static INT_PTR CALLBACK AdvancedProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    RPCTX *c;
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            LONG m;
            c = (RPCTX *)((PROPSHEETPAGEW *)lParam)->lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)c);
            m = c->Work.Profiles;
            if (m == FWP_ANY_COM) m = FWP_ALL;
            CheckDlgButton(hDlg, IDC_RP_DOMAIN, (m & FWP_DOMAIN) ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_RP_PRIVATE, (m & FWP_PRIVATE) ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_RP_PUBLIC, (m & FWP_PUBLIC) ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_RP_IF_LAN, HasIfType(c->Work.IfTypes, L"Lan") ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_RP_IF_RAS, HasIfType(c->Work.IfTypes, L"RemoteAccess") ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_RP_IF_WIFI, HasIfType(c->Work.IfTypes, L"Wireless") ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_RP_EDGE, c->Work.Edge ? BST_CHECKED : BST_UNCHECKED);
            return TRUE;
        }
        case WM_COMMAND:
            if (HIWORD(wParam) == BN_CLICKED)
                PropSheet_Changed(GetParent(hDlg), hDlg);
            break;
        case WM_NOTIFY:
            if (((NMHDR *)lParam)->code == PSN_APPLY)
            {
                LONG m = 0;
                BOOL lan, ras, wifi;
                WCHAR ift[64];
                c = (RPCTX *)GetWindowLongPtrW(hDlg, DWLP_USER);
                if (IsDlgButtonChecked(hDlg, IDC_RP_DOMAIN) == BST_CHECKED) m |= FWP_DOMAIN;
                if (IsDlgButtonChecked(hDlg, IDC_RP_PRIVATE) == BST_CHECKED) m |= FWP_PRIVATE;
                if (IsDlgButtonChecked(hDlg, IDC_RP_PUBLIC) == BST_CHECKED) m |= FWP_PUBLIC;
                if (!m) m = FWP_ALL;
                c->Work.Profiles = (m == FWP_ALL) ? FWP_ANY_COM : m;
                lan = IsDlgButtonChecked(hDlg, IDC_RP_IF_LAN) == BST_CHECKED;
                ras = IsDlgButtonChecked(hDlg, IDC_RP_IF_RAS) == BST_CHECKED;
                wifi = IsDlgButtonChecked(hDlg, IDC_RP_IF_WIFI) == BST_CHECKED;
                ift[0] = 0;
                if ((lan && ras && wifi) || (!lan && !ras && !wifi))
                    wcscpy(ift, L"All");
                else
                {
                    if (lan) wcscat(ift, L"Lan");
                    if (wifi) { if (ift[0]) wcscat(ift, L","); wcscat(ift, L"Wireless"); }
                    if (ras) { if (ift[0]) wcscat(ift, L","); wcscat(ift, L"RemoteAccess"); }
                }
                FwRuleSetStr(&c->Work.IfTypes, ift);
                c->Work.Edge = IsDlgButtonChecked(hDlg, IDC_RP_EDGE) == BST_CHECKED;
                if (!Commit(c, hDlg)) SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

BOOL EditRuleProperties(HWND hOwner, const FW_RULE *rule)
{
    RPCTX ctx;
    PROPSHEETPAGEW psp[5];
    PROPSHEETHEADERW psh;
    WCHAR title[400];
    static const struct { UINT dlg; UINT str; DLGPROC proc; } pages[5] = {
        { IDD_RP_GENERAL,  IDS_RP_GENERAL,  GeneralProc },
        { IDD_RP_PROGRAMS, IDS_RP_PROGRAMS, ProgramsProc },
        { IDD_RP_PORTS,    IDS_RP_PORTS,    PortsProc },
        { IDD_RP_SCOPE,    IDS_RP_SCOPE,    ScopeProc },
        { IDD_RP_ADVANCED, IDS_RP_ADVANCED, AdvancedProc },
    };
    INT i;

    ZeroMemory(&ctx, sizeof(ctx));
    FwRuleInit(&ctx.Work);
    if (!FwRuleCopy(&ctx.Work, rule))
        return FALSE;
    for (i = 0; i < 5; i++)
    {
        ZeroMemory(&psp[i], sizeof(psp[i]));
        psp[i].dwSize = sizeof(psp[i]);
        psp[i].dwFlags = PSP_USETITLE;
        psp[i].hInstance = g_hInst;
        psp[i].pszTemplate = MAKEINTRESOURCEW(pages[i].dlg);
        psp[i].pszTitle = Str(pages[i].str);
        psp[i].pfnDlgProc = pages[i].proc;
        psp[i].lParam = (LPARAM)&ctx;
    }
    StringCchPrintfW(title, ARRAYSIZE(title), Str(IDS_RULEDLG_FMT), rule->Name ? rule->Name : L"");
    ZeroMemory(&psh, sizeof(psh));
    psh.dwSize = sizeof(psh);
    psh.dwFlags = PSH_PROPSHEETPAGE | PSH_NOCONTEXTHELP | PSH_USEICONID;
    psh.hwndParent = hOwner;
    psh.hInstance = g_hInst;
    psh.pszIcon = MAKEINTRESOURCEW(IDI_WFADV);
    psh.pszCaption = title;
    psh.nPages = 5;
    psh.ppsp = psp;
    PropertySheetW(&psh);
    FwRuleFree(&ctx.Work);
    return ctx.Saved;
}
