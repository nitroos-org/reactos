/*
 * PROJECT:     NitroOS Firewall with Advanced Security (wf.msc)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Rule field formatting and controls shared by the properties dialog and the wizard
 */
#include "wfadv.h"

PCWSTR AnyIfEmpty(PCWSTR s)
{
    return (!s || !*s || !wcscmp(s, L"*")) ? Str(IDS_ANY) : s;
}

VOID FormatProfiles(LONG mask, PWSTR out, SIZE_T cch)
{
    out[0] = 0;
    if (mask == FWP_ANY_COM || (mask & FWP_ALL) == FWP_ALL)
    {
        StringCchCopyW(out, cch, Str(IDS_ALLPROF));
        return;
    }
    if (mask & FWP_DOMAIN)
        StringCchCatW(out, cch, Str(IDS_PROF_DOMAIN));
    if (mask & FWP_PRIVATE)
    {
        if (out[0]) StringCchCatW(out, cch, L", ");
        StringCchCatW(out, cch, Str(IDS_PROF_PRIVATE));
    }
    if (mask & FWP_PUBLIC)
    {
        if (out[0]) StringCchCatW(out, cch, L", ");
        StringCchCatW(out, cch, Str(IDS_PROF_PUBLIC));
    }
}

VOID FormatProtocol(LONG proto, PWSTR out, SIZE_T cch)
{
    switch (proto)
    {
        case 256: StringCchCopyW(out, cch, Str(IDS_PROTO_ANY)); break;
        case 6:   StringCchCopyW(out, cch, Str(IDS_PROTO_TCP)); break;
        case 17:  StringCchCopyW(out, cch, Str(IDS_PROTO_UDP)); break;
        case 1:   StringCchCopyW(out, cch, Str(IDS_PROTO_ICMP4)); break;
        case 58:  StringCchCopyW(out, cch, Str(IDS_PROTO_ICMP6)); break;
        case 2:   StringCchCopyW(out, cch, Str(IDS_PROTO_IGMP)); break;
        default:  StringCchPrintfW(out, cch, L"%d", proto); break;
    }
}

/* combo order: Any, TCP, UDP, ICMPv4, ICMPv6, IGMP, Custom */
static const LONG g_ProtoVal[] = { 256, 6, 17, 1, 58, 2, -1 };
static const UINT g_ProtoStr[] = { IDS_PROTO_ANY, IDS_PROTO_TCP, IDS_PROTO_UDP, IDS_PROTO_ICMP4, IDS_PROTO_ICMP6, IDS_PROTO_IGMP, IDS_PROTO_CUSTOM };

VOID FillProtocolCombo(HWND hCombo, BOOL portsOnly)
{
    INT i;
    SendMessageW(hCombo, CB_RESETCONTENT, 0, 0);
    for (i = 0; i < (INT)ARRAYSIZE(g_ProtoVal); i++)
    {
        INT n;
        if (portsOnly && g_ProtoVal[i] != 6 && g_ProtoVal[i] != 17) continue;
        n = (INT)SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)Str(g_ProtoStr[i]));
        SendMessageW(hCombo, CB_SETITEMDATA, n, g_ProtoVal[i]);
    }
}

VOID SetProtocolCombo(HWND hDlg, UINT idCombo, UINT idNum, LONG proto)
{
    HWND hc = GetDlgItem(hDlg, idCombo);
    INT i, n = (INT)SendMessageW(hc, CB_GETCOUNT, 0, 0), custom = -1, sel = -1;
    for (i = 0; i < n; i++)
    {
        LONG v = (LONG)SendMessageW(hc, CB_GETITEMDATA, i, 0);
        if (v == proto) sel = i;
        if (v == -1) custom = i;
    }
    if (sel < 0 && custom >= 0)
    {
        WCHAR num[16];
        sel = custom;
        StringCchPrintfW(num, ARRAYSIZE(num), L"%d", proto);
        SetDlgItemTextW(hDlg, idNum, num);
    }
    else
        SetDlgItemTextW(hDlg, idNum, L"");
    SendMessageW(hc, CB_SETCURSEL, sel < 0 ? 0 : sel, 0);
}

BOOL GetProtocolCombo(HWND hDlg, UINT idCombo, UINT idNum, LONG *pProto)
{
    HWND hc = GetDlgItem(hDlg, idCombo);
    INT sel = (INT)SendMessageW(hc, CB_GETCURSEL, 0, 0);
    LONG v = sel < 0 ? 256 : (LONG)SendMessageW(hc, CB_GETITEMDATA, sel, 0);
    if (v == -1)
    {
        WCHAR num[16], *e;
        long n;
        GetEditText(hDlg, idNum, num, ARRAYSIZE(num));
        n = wcstol(num, &e, 10);
        if (!num[0] || *e || n < 0 || n > 255)
            return FALSE;
        v = n;
    }
    *pProto = v;
    return TRUE;
}

VOID EnableProtoControls(HWND hDlg, UINT idCombo, UINT idNum, UINT idLPort, UINT idRPort, UINT idIcmp)
{
    HWND hc = GetDlgItem(hDlg, idCombo);
    INT sel = (INT)SendMessageW(hc, CB_GETCURSEL, 0, 0);
    LONG v = sel < 0 ? 256 : (LONG)SendMessageW(hc, CB_GETITEMDATA, sel, 0);
    BOOL ports;
    if (v == -1)
    {
        WCHAR num[16];
        GetEditText(hDlg, idNum, num, ARRAYSIZE(num));
        v = _wtoi(num);
    }
    ports = (v == 6 || v == 17);
    EnableWindow(GetDlgItem(hDlg, idNum), (SendMessageW(hc, CB_GETITEMDATA, sel < 0 ? 0 : sel, 0) == -1));
    if (idLPort) EnableWindow(GetDlgItem(hDlg, idLPort), ports);
    if (idRPort) EnableWindow(GetDlgItem(hDlg, idRPort), ports);
    if (idIcmp) EnableWindow(GetDlgItem(hDlg, idIcmp), v == 1 || v == 58);
}

VOID GetEditText(HWND hDlg, UINT id, PWSTR out, SIZE_T cch)
{
    GetDlgItemTextW(hDlg, id, out, (int)cch);
    /* trim */
    {
        PWSTR p = out;
        SIZE_T len;
        while (*p == L' ' || *p == L'\t') p++;
        if (p != out) memmove(out, p, (wcslen(p) + 1) * sizeof(WCHAR));
        len = wcslen(out);
        while (len && (out[len - 1] == L' ' || out[len - 1] == L'\t')) out[--len] = 0;
    }
}

/* "Any" / "These ..." radio pair with an edit box */
VOID SetRadioEdit(HWND hDlg, UINT idAny, UINT idSel, UINT idEdit, PCWSTR value)
{
    BOOL any = (!value || !*value || !wcscmp(value, L"*"));
    CheckRadioButton(hDlg, idAny, idSel, any ? idAny : idSel);
    SetDlgItemTextW(hDlg, idEdit, any ? L"" : value);
    EnableWindow(GetDlgItem(hDlg, idEdit), !any);
}

VOID UpdateRadioEdit(HWND hDlg, UINT idAny, UINT idSel, UINT idEdit)
{
    EnableWindow(GetDlgItem(hDlg, idEdit), IsDlgButtonChecked(hDlg, idSel) == BST_CHECKED);
    UNREFERENCED_PARAMETER(idAny);
}

/* returns FALSE when "These" is selected with an empty edit */
BOOL GetRadioEdit(HWND hDlg, UINT idAny, UINT idSel, UINT idEdit, PWSTR out, SIZE_T cch)
{
    out[0] = 0;
    UNREFERENCED_PARAMETER(idAny);
    if (IsDlgButtonChecked(hDlg, idSel) != BST_CHECKED)
        return TRUE;
    GetEditText(hDlg, idEdit, out, cch);
    return out[0] != 0;
}

BOOL BrowseForProgram(HWND hDlg, UINT idEdit)
{
    OPENFILENAMEW ofn;
    WCHAR path[MAX_PATH] = L"", filter[200];
    PWSTR p;
    StringCchPrintfW(filter, ARRAYSIZE(filter), L"%s|*.exe|%s|*.*|", Str(IDS_FILTER_EXE), Str(IDS_FILTER_ALL));
    for (p = filter; *p; p++) if (*p == L'|') *p = 0;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hDlg;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = path;
    ofn.nMaxFile = ARRAYSIZE(path);
    ofn.lpstrTitle = Str(IDS_BROWSE_TITLE);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn))
        return FALSE;
    SetDlgItemTextW(hDlg, idEdit, path);
    return TRUE;
}

BOOL ValidatePortsAddrs(HWND hDlg, PCWSTR lport, PCWSTR rport, PCWSTR laddr, PCWSTR raddr)
{
    if (FwCheckPorts(lport) || FwCheckPorts(rport))
    {
        MessageBoxW(hDlg, Str(IDS_ERR_PORTS), Str(IDS_APPNAME), MB_OK | MB_ICONWARNING);
        return FALSE;
    }
    if (FwCheckAddrs(laddr) || FwCheckAddrs(raddr))
    {
        MessageBoxW(hDlg, Str(IDS_ERR_ADDRS), Str(IDS_APPNAME), MB_OK | MB_ICONWARNING);
        return FALSE;
    }
    return TRUE;
}
