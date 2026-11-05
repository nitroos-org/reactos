/*
 * PROJECT:     NitroOS Firewall with Advanced Security (wf.msc)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Profile properties (state, default actions, notifications, logging) and policy import/export/restore
 */
#include "wfadv.h"

static const ULONG g_Bit[3] = { FWP_DOMAIN, FWP_PRIVATE, FWP_PUBLIC };
static const UINT g_TabStr[3] = { IDS_PROF_TAB_DOM, IDS_PROF_TAB_PRI, IDS_PROF_TAB_PUB };

typedef struct _PCTX
{
    FW_PROFILE Orig[3], Work[3];
    INT Cur;
    BOOL Applied;
} PCTX;

/* ---- Customize: notifications ---- */
static INT_PTR CALLBACK SettingsProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    FW_PROFILE *p;
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            HWND hc = GetDlgItem(hDlg, IDC_PS_NOTIFY);
            SetWindowLongPtrW(hDlg, DWLP_USER, lParam);
            p = (FW_PROFILE *)lParam;
            SendMessageW(hc, CB_ADDSTRING, 0, (LPARAM)Str(IDS_NOTIF_YES));
            SendMessageW(hc, CB_ADDSTRING, 0, (LPARAM)Str(IDS_NOTIF_NO));
            SendMessageW(hc, CB_SETCURSEL, p->DisableNotifications ? 1 : 0, 0);
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK)
            {
                p = (FW_PROFILE *)GetWindowLongPtrW(hDlg, DWLP_USER);
                p->DisableNotifications = SendDlgItemMessageW(hDlg, IDC_PS_NOTIFY, CB_GETCURSEL, 0, 0) == 1;
                EndDialog(hDlg, IDOK);
                return TRUE;
            }
            if (LOWORD(wParam) == IDCANCEL) { EndDialog(hDlg, IDCANCEL); return TRUE; }
            break;
    }
    return FALSE;
}

/* ---- Customize: logging ---- */
static VOID FillYesNo(HWND hDlg, UINT id, BOOL yes)
{
    HWND hc = GetDlgItem(hDlg, id);
    SendMessageW(hc, CB_ADDSTRING, 0, (LPARAM)Str(IDS_YES));
    SendMessageW(hc, CB_ADDSTRING, 0, (LPARAM)Str(IDS_NO));
    SendMessageW(hc, CB_SETCURSEL, yes ? 0 : 1, 0);
}

static INT_PTR CALLBACK LoggingProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    FW_PROFILE *p;
    switch (msg)
    {
        case WM_INITDIALOG:
            SetWindowLongPtrW(hDlg, DWLP_USER, lParam);
            p = (FW_PROFILE *)lParam;
            SetDlgItemTextW(hDlg, IDC_PL_PATH, p->LogFile);
            SetDlgItemInt(hDlg, IDC_PL_SIZE, p->LogFileSize, FALSE);
            FillYesNo(hDlg, IDC_PL_DROPPED, p->LogDropped != 0);
            FillYesNo(hDlg, IDC_PL_SUCCESS, p->LogSuccess != 0);
            return TRUE;
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK)
            {
                BOOL ok;
                UINT size;
                WCHAR path[MAX_PATH];
                p = (FW_PROFILE *)GetWindowLongPtrW(hDlg, DWLP_USER);
                GetEditText(hDlg, IDC_PL_PATH, path, ARRAYSIZE(path));
                if (!path[0])
                {
                    MessageBoxW(hDlg, Str(IDS_ERR_LOGPATH), Str(IDS_APPNAME), MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(hDlg, IDC_PL_PATH));
                    return TRUE;
                }
                size = GetDlgItemInt(hDlg, IDC_PL_SIZE, &ok, FALSE);
                if (!ok || size < 1 || size > 32767)
                {
                    MessageBoxW(hDlg, Str(IDS_ERR_LOGSIZE), Str(IDS_APPNAME), MB_OK | MB_ICONWARNING);
                    SetFocus(GetDlgItem(hDlg, IDC_PL_SIZE));
                    return TRUE;
                }
                StringCchCopyW(p->LogFile, ARRAYSIZE(p->LogFile), path);
                p->LogFileSize = size;
                p->LogDropped = SendDlgItemMessageW(hDlg, IDC_PL_DROPPED, CB_GETCURSEL, 0, 0) == 0;
                p->LogSuccess = SendDlgItemMessageW(hDlg, IDC_PL_SUCCESS, CB_GETCURSEL, 0, 0) == 0;
                EndDialog(hDlg, IDOK);
                return TRUE;
            }
            if (LOWORD(wParam) == IDCANCEL) { EndDialog(hDlg, IDCANCEL); return TRUE; }
            break;
    }
    return FALSE;
}

/* ---- profile properties ---- */
static VOID SummaryText(HWND hDlg, const FW_PROFILE *p)
{
    WCHAR t[300];
    StringCchPrintfW(t, ARRAYSIZE(t), L"%s", p->DisableNotifications ? Str(IDS_NOTIF_NO) : Str(IDS_NOTIF_YES));
    SetDlgItemTextW(hDlg, IDC_P_NOTIFYTXT, t);
    SetDlgItemTextW(hDlg, IDC_P_LOGTXT, p->LogDropped ? Str(IDS_LOG_DROPPED) : Str(IDS_LOG_NOTDROPPED));
}

static VOID LoadTab(HWND hDlg, PCTX *c)
{
    FW_PROFILE *p = &c->Work[c->Cur];
    SendDlgItemMessageW(hDlg, IDC_P_STATE, CB_SETCURSEL, p->Enable ? 0 : 1, 0);
    SendDlgItemMessageW(hDlg, IDC_P_INBOUND, CB_SETCURSEL, p->DefaultInbound ? (p->DoNotAllowExceptions ? 1 : 0) : 2, 0);
    SendDlgItemMessageW(hDlg, IDC_P_OUTBOUND, CB_SETCURSEL, p->DefaultOutbound ? 1 : 0, 0);
    SummaryText(hDlg, p);
}

static VOID SaveTab(HWND hDlg, PCTX *c)
{
    FW_PROFILE *p = &c->Work[c->Cur];
    INT in = (INT)SendDlgItemMessageW(hDlg, IDC_P_INBOUND, CB_GETCURSEL, 0, 0);
    p->Enable = SendDlgItemMessageW(hDlg, IDC_P_STATE, CB_GETCURSEL, 0, 0) == 0;
    p->DefaultInbound = (in == 2) ? 0 : 1;
    p->DoNotAllowExceptions = (in == 1) ? 1 : 0;
    p->DefaultOutbound = SendDlgItemMessageW(hDlg, IDC_P_OUTBOUND, CB_GETCURSEL, 0, 0) == 1;
}

static DWORD CommitProfiles(PCTX *c)
{
    INT i;
    DWORD err = 0;
    for (i = 0; i < 3 && !err; i++)
    {
        const FW_PROFILE *o = &c->Orig[i], *n = &c->Work[i];
        ULONG b = g_Bit[i];
        if (n->Enable != o->Enable) err = FwProfileSetDword(b, L"EnableFirewall", n->Enable, FALSE);
        if (!err && n->DoNotAllowExceptions != o->DoNotAllowExceptions) err = FwProfileSetDword(b, L"DoNotAllowExceptions", n->DoNotAllowExceptions, FALSE);
        if (!err && n->DisableNotifications != o->DisableNotifications) err = FwProfileSetDword(b, L"DisableNotifications", n->DisableNotifications, FALSE);
        if (!err && n->DefaultInbound != o->DefaultInbound) err = FwProfileSetDword(b, L"DefaultInboundAction", n->DefaultInbound, FALSE);
        if (!err && n->DefaultOutbound != o->DefaultOutbound) err = FwProfileSetDword(b, L"DefaultOutboundAction", n->DefaultOutbound, FALSE);
        if (!err && n->LogFileSize != o->LogFileSize) err = FwProfileSetDword(b, L"LogFileSize", n->LogFileSize, TRUE);
        if (!err && n->LogDropped != o->LogDropped) err = FwProfileSetDword(b, L"LogDroppedPackets", n->LogDropped, TRUE);
        if (!err && n->LogSuccess != o->LogSuccess) err = FwProfileSetDword(b, L"LogSuccessfulConnections", n->LogSuccess, TRUE);
        if (!err && wcscmp(n->LogFile, o->LogFile)) err = FwProfileSetString(b, L"LogFilePath", n->LogFile, TRUE);
        if (!err) c->Orig[i] = c->Work[i];
    }
    return err;
}

static BOOL ApplyAll(HWND hDlg, PCTX *c)
{
    DWORD err;
    SaveTab(hDlg, c);
    err = CommitProfiles(c);
    if (err) { ShowStoreError(hDlg, err); return FALSE; }
    c->Applied = TRUE;
    NotifyMainRefresh();
    EnableWindow(GetDlgItem(hDlg, IDC_P_APPLY), FALSE);
    return TRUE;
}

static INT_PTR CALLBACK ProfileProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    PCTX *c = (PCTX *)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            HWND tab = GetDlgItem(hDlg, IDC_P_TAB);
            INT i;
            ULONG cur = FwCurrentProfiles();
            c = (PCTX *)lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, lParam);
            SendMessageW(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_WFADV), IMAGE_ICON, 16, 16, 0));
            for (i = 0; i < 3; i++)
            {
                TCITEMW ti;
                ZeroMemory(&ti, sizeof(ti));
                ti.mask = TCIF_TEXT;
                ti.pszText = (PWSTR)Str(g_TabStr[i]);
                TabCtrl_InsertItem(tab, i, &ti);
                FwProfileLoad(g_Bit[i], &c->Orig[i]);
                c->Work[i] = c->Orig[i];
                if (g_Bit[i] == cur) c->Cur = i;
            }
            SendDlgItemMessageW(hDlg, IDC_P_STATE, CB_ADDSTRING, 0, (LPARAM)Str(IDS_FIREWALL_ON));
            SendDlgItemMessageW(hDlg, IDC_P_STATE, CB_ADDSTRING, 0, (LPARAM)Str(IDS_FIREWALL_OFF));
            SendDlgItemMessageW(hDlg, IDC_P_INBOUND, CB_ADDSTRING, 0, (LPARAM)Str(IDS_CMB_IN_BLOCK));
            SendDlgItemMessageW(hDlg, IDC_P_INBOUND, CB_ADDSTRING, 0, (LPARAM)Str(IDS_CMB_IN_BLOCKALL));
            SendDlgItemMessageW(hDlg, IDC_P_INBOUND, CB_ADDSTRING, 0, (LPARAM)Str(IDS_CMB_IN_ALLOW));
            SendDlgItemMessageW(hDlg, IDC_P_OUTBOUND, CB_ADDSTRING, 0, (LPARAM)Str(IDS_CMB_OUT_ALLOW));
            SendDlgItemMessageW(hDlg, IDC_P_OUTBOUND, CB_ADDSTRING, 0, (LPARAM)Str(IDS_CMB_OUT_BLOCK));
            TabCtrl_SetCurSel(tab, c->Cur);
            LoadTab(hDlg, c);
            EnableWindow(GetDlgItem(hDlg, IDC_P_APPLY), FALSE);
            return TRUE;
        }
        case WM_NOTIFY:
        {
            NMHDR *nm = (NMHDR *)lParam;
            if (nm->idFrom == IDC_P_TAB)
            {
                if (nm->code == TCN_SELCHANGING)
                    SaveTab(hDlg, c);
                else if (nm->code == TCN_SELCHANGE)
                {
                    c->Cur = TabCtrl_GetCurSel(nm->hwndFrom);
                    LoadTab(hDlg, c);
                }
            }
            break;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_P_STATE:
                case IDC_P_INBOUND:
                case IDC_P_OUTBOUND:
                    if (HIWORD(wParam) == CBN_SELCHANGE)
                        EnableWindow(GetDlgItem(hDlg, IDC_P_APPLY), TRUE);
                    break;
                case IDC_P_SETTINGS:
                    if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_PROF_SETTINGS), hDlg, SettingsProc, (LPARAM)&c->Work[c->Cur]) == IDOK)
                    {
                        SummaryText(hDlg, &c->Work[c->Cur]);
                        EnableWindow(GetDlgItem(hDlg, IDC_P_APPLY), TRUE);
                    }
                    return TRUE;
                case IDC_P_LOGGING:
                    if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_PROF_LOGGING), hDlg, LoggingProc, (LPARAM)&c->Work[c->Cur]) == IDOK)
                    {
                        SummaryText(hDlg, &c->Work[c->Cur]);
                        EnableWindow(GetDlgItem(hDlg, IDC_P_APPLY), TRUE);
                    }
                    return TRUE;
                case IDC_P_APPLY:
                    ApplyAll(hDlg, c);
                    return TRUE;
                case IDOK:
                    if (ApplyAll(hDlg, c)) EndDialog(hDlg, IDOK);
                    return TRUE;
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

VOID ShowProfileProperties(HWND hOwner)
{
    PCTX *c = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
    if (!c) return;
    DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_PROFILE), hOwner, ProfileProc, (LPARAM)c);
    HeapFree(GetProcessHeap(), 0, c);
}

/* ---- policy files: UTF-16 text, one line per profile and per rule ---- */
#define POLICY_MAGIC L"NitroOS-Firewall-Policy|1"

static BOOL AskFile(HWND hOwner, BOOL save, PWSTR path, DWORD cch)
{
    OPENFILENAMEW ofn;
    WCHAR filter[200];
    PWSTR p;
    StringCchPrintfW(filter, ARRAYSIZE(filter), L"%s|*.wfw|%s|*.*|", Str(IDS_FILTER_POLICY), Str(IDS_FILTER_ALL));
    for (p = filter; *p; p++) if (*p == L'|') *p = 0;
    path[0] = 0;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hOwner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = path;
    ofn.nMaxFile = cch;
    ofn.lpstrDefExt = L"wfw";
    ofn.lpstrTitle = Str(save ? IDS_EXPORT_TITLE : IDS_IMPORT_TITLE);
    ofn.Flags = OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    return save ? GetSaveFileNameW(&ofn) : GetOpenFileNameW(&ofn);
}

typedef struct { PWSTR Buf; SIZE_T Len, Cap; } SB;

static BOOL SbAdd(SB *s, PCWSTR t)
{
    SIZE_T n = wcslen(t);
    if (s->Len + n + 1 > s->Cap)
    {
        SIZE_T nc = (s->Cap ? s->Cap * 2 : 4096);
        PWSTR nb;
        while (nc < s->Len + n + 1) nc *= 2;
        nb = HeapAlloc(GetProcessHeap(), 0, nc * sizeof(WCHAR));
        if (!nb) return FALSE;
        if (s->Buf) { memcpy(nb, s->Buf, s->Len * sizeof(WCHAR)); HeapFree(GetProcessHeap(), 0, s->Buf); }
        s->Buf = nb; s->Cap = nc;
    }
    memcpy(s->Buf + s->Len, t, (n + 1) * sizeof(WCHAR));
    s->Len += n;
    return TRUE;
}

VOID DoExportPolicy(HWND hOwner)
{
    WCHAR path[MAX_PATH], line[700];
    SB sb = { 0 };
    FW_RULESET rs;
    ULONG i;
    INT p;
    DWORD err;
    HANDLE h;
    BOOL ok = TRUE;
    if (!AskFile(hOwner, TRUE, path, ARRAYSIZE(path))) return;
    err = FwStoreLoad(&rs);
    if (err) { ShowStoreError(hOwner, err); return; }
    ok = SbAdd(&sb, POLICY_MAGIC L"\r\n");
    for (p = 0; p < 3 && ok; p++)
    {
        FW_PROFILE f;
        FwProfileLoad(g_Bit[p], &f);
        StringCchPrintfW(line, ARRAYSIZE(line), L"PROFILE|%u|%u|%u|%u|%u|%u|%u|%u|%u|%s\r\n", g_Bit[p], f.Enable,
                         f.DoNotAllowExceptions, f.DisableNotifications, f.DefaultInbound, f.DefaultOutbound,
                         f.LogFileSize, f.LogDropped, f.LogSuccess, f.LogFile);
        ok = SbAdd(&sb, line);
    }
    for (i = 0; i < rs.N && ok; i++)
    {
        FWR raw;
        PWSTR s;
        if (!rs.R[i].Id || !FwRuleToRaw(&rs.R[i], &raw)) continue;
        s = FwrFormat(&raw);
        FwrFree(&raw);
        if (!s) { ok = FALSE; break; }
        ok = SbAdd(&sb, L"RULE|") && SbAdd(&sb, rs.R[i].Id) && SbAdd(&sb, L"|") && SbAdd(&sb, s) && SbAdd(&sb, L"\r\n");
        FwFree(s);
    }
    FwRuleSetFree(&rs);
    if (ok)
    {
        h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) err = GetLastError();
        else
        {
            DWORD wr; WCHAR bom = 0xFEFF;
            WriteFile(h, &bom, sizeof(bom), &wr, NULL);
            if (!WriteFile(h, sb.Buf, (DWORD)(sb.Len * sizeof(WCHAR)), &wr, NULL)) err = GetLastError();
            else err = 0;
            CloseHandle(h);
        }
        if (err)
        {
            WCHAR m[300];
            StringCchPrintfW(m, ARRAYSIZE(m), Str(IDS_ERR_FILE), err);
            MessageBoxW(hOwner, m, Str(IDS_APPNAME), MB_OK | MB_ICONERROR);
        }
        else
            MessageBoxW(hOwner, Str(IDS_EXPORTED), Str(IDS_APPNAME), MB_OK | MB_ICONINFORMATION);
    }
    if (sb.Buf) HeapFree(GetProcessHeap(), 0, sb.Buf);
}

typedef struct { ULONG Bit; FW_PROFILE P; } IMPPROF;

VOID DoImportPolicy(HWND hOwner)
{
    WCHAR path[MAX_PATH];
    HANDLE h;
    DWORD size, rd, err = 0;
    PWSTR buf = NULL, p, eol;
    IMPPROF prof[3];
    ULONG nprof = 0, nrules = 0, i, cap = 0;
    FW_RULE *rules = NULL;
    BOOL bad = FALSE;
    if (!AskFile(hOwner, FALSE, path, ARRAYSIZE(path))) return;
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        WCHAR m[300];
        StringCchPrintfW(m, ARRAYSIZE(m), Str(IDS_ERR_FILE), GetLastError());
        MessageBoxW(hOwner, m, Str(IDS_APPNAME), MB_OK | MB_ICONERROR);
        return;
    }
    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size > 64 * 1024 * 1024 || size < 4) bad = TRUE;
    else
    {
        buf = HeapAlloc(GetProcessHeap(), 0, size + 4);
        if (!buf || !ReadFile(h, buf, size, &rd, NULL) || rd != size) bad = TRUE;
        else { buf[size / 2] = 0; }
    }
    CloseHandle(h);
    if (!bad && buf[0] == 0xFEFF) p = buf + 1; else p = buf;
    if (!bad && _wcsnicmp(p, POLICY_MAGIC, wcslen(POLICY_MAGIC))) bad = TRUE;
    while (!bad && p && *p)
    {
        eol = wcsstr(p, L"\r\n");
        if (eol) *eol = 0;
        if (!_wcsnicmp(p, L"PROFILE|", 8))
        {
            IMPPROF *ip = &prof[nprof];
            ULONG v[9];
            WCHAR *q = p + 8, *e;
            INT k;
            if (nprof >= 3) { bad = TRUE; break; }
            for (k = 0; k < 9; k++)
            {
                v[k] = wcstoul(q, &e, 10);
                if (e == q || (k < 8 && *e != L'|')) { bad = TRUE; break; }
                q = (k < 8) ? e + 1 : e;
            }
            if (!bad && *e == L'|' && (v[0] == FWP_DOMAIN || v[0] == FWP_PRIVATE || v[0] == FWP_PUBLIC))
            {
                ZeroMemory(ip, sizeof(*ip));
                ip->Bit = v[0]; ip->P.Enable = v[1]; ip->P.DoNotAllowExceptions = v[2]; ip->P.DisableNotifications = v[3];
                ip->P.DefaultInbound = v[4]; ip->P.DefaultOutbound = v[5]; ip->P.LogFileSize = v[6];
                ip->P.LogDropped = v[7]; ip->P.LogSuccess = v[8];
                StringCchCopyW(ip->P.LogFile, ARRAYSIZE(ip->P.LogFile), e + 1);
                nprof++;
            }
            else bad = TRUE;
        }
        else if (!_wcsnicmp(p, L"RULE|", 5))
        {
            WCHAR *bar = wcschr(p + 5, L'|');
            FWR raw;
            if (!bar) { bad = TRUE; break; }
            *bar = 0;
            if (nrules >= cap)
            {
                FW_RULE *nr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (cap ? cap * 2 : 64) * sizeof(FW_RULE));
                if (!nr) { bad = TRUE; break; }
                if (rules) { memcpy(nr, rules, nrules * sizeof(FW_RULE)); HeapFree(GetProcessHeap(), 0, rules); }
                rules = nr; cap = cap ? cap * 2 : 64;
            }
            if (!FwrParse(&raw, p + 5, bar + 1)) { FwrFree(&raw); bad = TRUE; break; }
            if (!FwRuleFromRaw(&rules[nrules], &raw)) { FwrFree(&raw); bad = TRUE; break; }
            FwrFree(&raw);
            nrules++;
        }
        p = eol ? eol + 2 : NULL;
    }
    if (buf) HeapFree(GetProcessHeap(), 0, buf);
    if (bad)
        MessageBoxW(hOwner, Str(IDS_ERR_BADFILE), Str(IDS_APPNAME), MB_OK | MB_ICONERROR);
    else if (MessageBoxW(hOwner, Str(IDS_CONFIRM_IMPORT), Str(IDS_APPNAME), MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES)
    {
        FwStoreDeleteAll();
        for (i = 0; i < nprof && !err; i++)
        {
            ULONG b = prof[i].Bit;
            const FW_PROFILE *f = &prof[i].P;
            err = FwProfileReset(b);
            if (!err) err = FwProfileSetDword(b, L"EnableFirewall", f->Enable, FALSE);
            if (!err) err = FwProfileSetDword(b, L"DoNotAllowExceptions", f->DoNotAllowExceptions, FALSE);
            if (!err) err = FwProfileSetDword(b, L"DisableNotifications", f->DisableNotifications, FALSE);
            if (!err) err = FwProfileSetDword(b, L"DefaultInboundAction", f->DefaultInbound, FALSE);
            if (!err) err = FwProfileSetDword(b, L"DefaultOutboundAction", f->DefaultOutbound, FALSE);
            if (!err) err = FwProfileSetDword(b, L"LogFileSize", f->LogFileSize, TRUE);
            if (!err) err = FwProfileSetDword(b, L"LogDroppedPackets", f->LogDropped, TRUE);
            if (!err) err = FwProfileSetDword(b, L"LogSuccessfulConnections", f->LogSuccess, TRUE);
            if (!err && f->LogFile[0]) err = FwProfileSetString(b, L"LogFilePath", f->LogFile, TRUE);
        }
        for (i = 0; i < nrules && !err; i++)
            err = FwStoreAdd(&rules[i]);
        if (err) ShowStoreError(hOwner, err);
        else MessageBoxW(hOwner, Str(IDS_IMPORTED), Str(IDS_APPNAME), MB_OK | MB_ICONINFORMATION);
        NotifyMainRefresh();
    }
    for (i = 0; i < nrules; i++) FwRuleFree(&rules[i]);
    if (rules) HeapFree(GetProcessHeap(), 0, rules);
}

VOID DoRestorePolicy(HWND hOwner)
{
    DWORD err;
    if (MessageBoxW(hOwner, Str(IDS_CONFIRM_RESTORE), Str(IDS_APPNAME), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
        return;
    err = FwResetAll();
    NotifyMainRefresh();
    if (err) ShowStoreError(hOwner, err);
    else MessageBoxW(hOwner, Str(IDS_RESTORED), Str(IDS_APPNAME), MB_OK | MB_ICONINFORMATION);
}
