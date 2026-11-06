/*
 * PROJECT:     NitroOS Firewall control panel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     firewall.cpl: per-profile status and on/off, the allowed apps list, notification
 *              setting and restore defaults. Reads and writes the rule store (fwstore) directly,
 *              the same registry data INetFwPolicy2, mpssvc and netsh advfirewall use.
 *              Layout and wording follow the Windows 10 firewall control panel as seen on a
 *              reference machine; the product name reads NitroOS Firewall.
 */

#define WIN32_NO_STATUS
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cpl.h>
#include <strsafe.h>
#include <fwstore.h>

#include "resource.h"

#define NPROF 3
static const ULONG g_ProfBit[NPROF] = { FWP_DOMAIN, FWP_PRIVATE, FWP_PUBLIC };

static HINSTANCE g_hInst;

/* ------------------------------------------------------------------ helpers */

static PCWSTR Str(UINT id)
{
    static WCHAR bufs[8][600];
    static int n;
    PWSTR b = bufs[n++ & 7];
    b[0] = 0;
    LoadStringW(g_hInst, id, b, 600);
    return b;
}

static VOID SetItemTextId(HWND hDlg, UINT item, UINT strId)
{
    SetDlgItemTextW(hDlg, item, Str(strId));
}

static VOID PlaceDlu(HWND hDlg, UINT id, INT x, INT y, INT w, INT h, BOOL show)
{
    RECT rc;
    HWND hc = GetDlgItem(hDlg, id);
    if (!hc) return;
    rc.left = x; rc.top = y; rc.right = x + w; rc.bottom = y + h;
    MapDialogRect(hDlg, &rc);
    MoveWindow(hc, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, TRUE);
    ShowWindow(hc, show ? SW_SHOW : SW_HIDE);
}

static VOID ReportError(HWND hDlg, UINT fmtId, DWORD err)
{
    WCHAR msg[700];
    StringCchPrintfW(msg, ARRAYSIZE(msg), Str(fmtId), err);
    MessageBoxW(hDlg, msg, Str(IDS_CPLNAME), MB_OK | MB_ICONERROR);
}

/* The Domain section only exists when the machine is joined to a domain, as in Windows. */
static BOOL g_DomainKnown, g_DomainJoined;

static BOOL DomainJoined(VOID)
{
    typedef DWORD (WINAPI *PFN_GETJOIN)(LPCWSTR, LPWSTR *, PVOID);
    typedef DWORD (WINAPI *PFN_FREE)(PVOID);
    HMODULE h;
    PFN_GETJOIN pGet;
    PFN_FREE pFree;
    LPWSTR name = NULL;
    DWORD status = 0;   /* NETSETUP_JOIN_STATUS: 3 = NetSetupDomainName */

    if (g_DomainKnown) return g_DomainJoined;
    g_DomainKnown = TRUE;
    h = LoadLibraryW(L"netapi32.dll");
    if (!h) return FALSE;
    pGet = (PFN_GETJOIN)GetProcAddress(h, "NetGetJoinInformation");
    pFree = (PFN_FREE)GetProcAddress(h, "NetApiBufferFree");
    if (pGet && pFree && pGet(NULL, &name, &status) == 0)
    {
        g_DomainJoined = (status == 3);
        pFree(name);
    }
    FreeLibrary(h);
    return g_DomainJoined;
}

static BOOL ProfVisible(INT p)
{
    return p != 0 || DomainJoined();
}

static INT ProfIndex(ULONG bit)
{
    return bit == FWP_DOMAIN ? 0 : (bit == FWP_PRIVATE ? 1 : 2);
}

static COLORREF g_Blue = RGB(0, 51, 153), g_Green = RGB(40, 160, 60), g_Red = RGB(200, 40, 40);
static HBRUSH g_hGreen, g_hRed;
static HFONT g_hTitleFont, g_hBoldFont;

static VOID MakeFonts(VOID)
{
    NONCLIENTMETRICS ncm;
    LOGFONT lf;
    if (g_hTitleFont) return;
    ZeroMemory(&ncm, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (!SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
        return;
    lf = ncm.lfMessageFont;
    lf.lfHeight = lf.lfHeight * 3 / 2;
    g_hTitleFont = CreateFontIndirectW(&lf);
    lf = ncm.lfMessageFont;
    lf.lfWeight = FW_BOLD;
    g_hBoldFont = CreateFontIndirectW(&lf);
    g_hGreen = CreateSolidBrush(g_Green);
    g_hRed = CreateSolidBrush(g_Red);
}

/* ------------------------------------------------------------------ main page */

static INT g_Expanded = 1;   /* the profile whose details are shown (accordion) */

static VOID MainLayout(HWND hDlg)
{
    INT y = 50, p;
    for (p = 0; p < NPROF; p++)
    {
        BOOL ex = (p == g_Expanded);
        if (!ProfVisible(p))
        {
            INT k;
            for (k = 0; k < 20; k++)
                ShowWindow(GetDlgItem(hDlg, IDC_SEC(p, k)), SW_HIDE);
            continue;
        }
        PlaceDlu(hDlg, IDC_SEC(p, SEC_BAR), 128, y, 6, 16, TRUE);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_TITLE), 142, y + 3, 190, 10, TRUE);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_STATUS), 372, y + 3, 82, 10, TRUE);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_CHEVRON), 458, y + 2, 14, 12, TRUE);
        SetDlgItemTextW(hDlg, IDC_SEC(p, SEC_CHEVRON), ex ? L"^" : L"v");
        PlaceDlu(hDlg, IDC_SEC(p, SEC_DESC), 142, y + 22, 326, 10, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_LBL_STATE), 142, y + 38, 106, 10, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_VAL_STATE), 252, y + 38, 216, 10, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_LBL_INC), 142, y + 50, 106, 10, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_VAL_INC), 252, y + 50, 216, 20, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_LBL_ACTIVE), 142, y + 72, 106, 10, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_VAL_ACTIVE), 252, y + 72, 216, 10, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_LBL_NOTIF), 142, y + 84, 106, 10, ex);
        PlaceDlu(hDlg, IDC_SEC(p, SEC_VAL_NOTIF), 252, y + 84, 216, 20, ex);
        y += ex ? 112 : 26;
    }
    InvalidateRect(hDlg, NULL, TRUE);
}

static VOID MainRefresh(HWND hDlg)
{
    ULONG active = FwCurrentProfiles();
    INT p;
    for (p = 0; p < NPROF; p++)
    {
        FW_PROFILE pr;
        BOOL isActive = (active == g_ProfBit[p]);
        FwProfileLoad(g_ProfBit[p], &pr);
        SetItemTextId(hDlg, IDC_SEC(p, SEC_TITLE), IDS_NET_DOMAIN + p);
        SetItemTextId(hDlg, IDC_SEC(p, SEC_DESC), IDS_NETDESC_DOMAIN + p);
        SetItemTextId(hDlg, IDC_SEC(p, SEC_STATUS), isActive ? IDS_CONNECTED : IDS_NOTCONNECTED);
        SetItemTextId(hDlg, IDC_SEC(p, SEC_VAL_STATE), pr.Enable ? IDS_ON : IDS_OFF);
        SetItemTextId(hDlg, IDC_SEC(p, SEC_VAL_INC),
                      pr.DoNotAllowExceptions ? IDS_INC_BLOCKALL : (pr.DefaultInbound ? IDS_INC_BLOCK : IDS_INC_ALLOW));
        SetItemTextId(hDlg, IDC_SEC(p, SEC_LBL_ACTIVE), IDS_ACTIVE_DOMAIN + p);
        SetItemTextId(hDlg, IDC_SEC(p, SEC_VAL_ACTIVE), isActive ? IDS_NETNAME : IDS_NONE);
        SetItemTextId(hDlg, IDC_SEC(p, SEC_VAL_NOTIF), pr.DisableNotifications ? IDS_NOTIF_OFF : IDS_NOTIF_ON);
        InvalidateRect(GetDlgItem(hDlg, IDC_SEC(p, SEC_BAR)), NULL, TRUE);
    }
}

static VOID ShowAdvanced(HWND hDlg)
{
    WCHAR path[MAX_PATH];
    SHELLEXECUTEINFOW sei;

    /* wf.msc is the Windows Firewall with Advanced Security console; until the system has it, show the netsh help */
    if (GetSystemDirectoryW(path, ARRAYSIZE(path)) &&
        SUCCEEDED(StringCchCatW(path, ARRAYSIZE(path), L"\\wf.msc")) &&
        GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
    {
        ZeroMemory(&sei, sizeof(sei));
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_FLAG_NO_UI;
        sei.hwnd = hDlg;
        sei.lpVerb = L"open";
        sei.lpFile = path;
        sei.nShow = SW_SHOWNORMAL;
        if (ShellExecuteExW(&sei))
            return;
    }
    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_FLAG_NO_UI;
    sei.hwnd = hDlg;
    sei.lpVerb = L"open";
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = L"/k netsh advfirewall /?";
    sei.nShow = SW_SHOWNORMAL;
    ShellExecuteExW(&sei);
}

static INT_PTR CALLBACK CustomizeDlgProc(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK AllowedDlgProc(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK RestoreDlgProc(HWND, UINT, WPARAM, LPARAM);

static INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            INT p;
            MakeFonts();
            SendDlgItemMessageW(hDlg, IDC_M_TITLE, WM_SETFONT, (WPARAM)g_hTitleFont, TRUE);
            for (p = 0; p < NPROF; p++)
                SendDlgItemMessageW(hDlg, IDC_SEC(p, SEC_TITLE), WM_SETFONT, (WPARAM)g_hBoldFont, TRUE);
            g_Expanded = ProfIndex(FwCurrentProfiles());
            SendMessageW(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_CPLICON), IMAGE_ICON, 16, 16, 0));
            MainRefresh(hDlg);
            MainLayout(hDlg);
            return TRUE;
        }

        case WM_ACTIVATE:
            if (LOWORD(wParam) != WA_INACTIVE)
                MainRefresh(hDlg);
            break;

        case WM_CTLCOLORSTATIC:
        {
            HDC hdc = (HDC)wParam;
            UINT id = GetDlgCtrlID((HWND)lParam);
            INT p;
            if (id == IDC_M_TITLE)
            {
                SetTextColor(hdc, g_Blue);
                SetBkMode(hdc, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_3DFACE);
            }
            for (p = 0; p < NPROF; p++)
            {
                if (id == (UINT)IDC_SEC(p, SEC_BAR))
                {
                    FW_PROFILE pr;
                    FwProfileLoad(g_ProfBit[p], &pr);
                    return (INT_PTR)(pr.Enable ? g_hGreen : g_hRed);
                }
                if (id == (UINT)IDC_SEC(p, SEC_STATUS) || id == (UINT)IDC_SEC(p, SEC_TITLE))
                {
                    SetTextColor(hdc, g_Blue);
                    SetBkMode(hdc, TRANSPARENT);
                    return (INT_PTR)GetSysColorBrush(COLOR_3DFACE);
                }
            }
            break;
        }

        case WM_NOTIFY:
        {
            LPNMHDR nm = (LPNMHDR)lParam;
            if (nm->code == NM_CLICK || nm->code == NM_RETURN)
            {
                switch (nm->idFrom)
                {
                    case IDC_M_LINK_ALLOW:
                        DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_ALLOWED), hDlg, AllowedDlgProc, 0);
                        MainRefresh(hDlg);
                        break;
                    case IDC_M_LINK_NOTIFY:
                    case IDC_M_LINK_ONOFF:
                        DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_CUSTOMIZE), hDlg, CustomizeDlgProc, 0);
                        MainRefresh(hDlg);
                        break;
                    case IDC_M_LINK_RESTORE:
                        DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_RESTORE), hDlg, RestoreDlgProc, 0);
                        MainRefresh(hDlg);
                        break;
                    case IDC_M_LINK_ADV:
                        ShowAdvanced(hDlg);
                        break;
                }
            }
            break;
        }

        case WM_COMMAND:
        {
            UINT id = LOWORD(wParam);
            INT p;
            if (id == IDC_M_CLOSE || id == IDCANCEL)
            {
                EndDialog(hDlg, 0);
                return TRUE;
            }
            for (p = 0; p < NPROF; p++)
            {
                if (id == (UINT)IDC_SEC(p, SEC_CHEVRON) && HIWORD(wParam) == BN_CLICKED)
                {
                    g_Expanded = (g_Expanded == p) ? -1 : p;
                    MainLayout(hDlg);
                    return TRUE;
                }
            }
            break;
        }

        case WM_CLOSE:
            EndDialog(hDlg, 0);
            return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ customize settings */

typedef struct { FW_PROFILE Orig[NPROF]; } CUSTOMIZE;

/* Not joined: drop the Domain block (controls 0..7 of profile 0, 72 DLU tall) and close the gap. */
static VOID CustomizeHideDomain(HWND hDlg)
{
    RECT rcStep = { 0, 0, 0, 72 }, rcWin;
    INT dy, k;
    HWND hc;
    POINT pt;

    MapDialogRect(hDlg, &rcStep);
    dy = rcStep.bottom;
    for (k = 0; k < 10; k++)
        ShowWindow(GetDlgItem(hDlg, IDC_CS(0, k)), SW_HIDE);
    for (hc = GetWindow(hDlg, GW_CHILD); hc; hc = GetWindow(hc, GW_HWNDNEXT))
    {
        UINT id = (UINT)GetDlgCtrlID(hc);
        RECT rc;
        if (id >= IDC_CS(0, 0) && id < IDC_CS(1, 0)) continue;
        GetWindowRect(hc, &rc);
        pt.x = rc.left; pt.y = rc.top;
        ScreenToClient(hDlg, &pt);
        if (id == IDC_C_TITLE || id == IDC_C_SUB) continue;
        SetWindowPos(hc, NULL, pt.x, pt.y - dy, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    GetWindowRect(hDlg, &rcWin);
    SetWindowPos(hDlg, NULL, rcWin.left, rcWin.top + dy / 2, rcWin.right - rcWin.left,
                 rcWin.bottom - rcWin.top - dy, SWP_NOZORDER | SWP_NOACTIVATE);
}

static VOID CustomizeEnable(HWND hDlg, INT p)
{
    BOOL on = IsDlgButtonChecked(hDlg, IDC_CS(p, CS_ON)) == BST_CHECKED;
    EnableWindow(GetDlgItem(hDlg, IDC_CS(p, CS_BLOCK)), on);
    EnableWindow(GetDlgItem(hDlg, IDC_CS(p, CS_NOTIFY)), on);
}

static INT_PTR CALLBACK CustomizeDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    CUSTOMIZE *c = (CUSTOMIZE *)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            INT p;
            c = (CUSTOMIZE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*c));
            if (!c) { EndDialog(hDlg, IDCANCEL); return TRUE; }
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)c);
            MakeFonts();
            SendDlgItemMessageW(hDlg, IDC_C_TITLE, WM_SETFONT, (WPARAM)g_hTitleFont, TRUE);
            for (p = 0; p < NPROF; p++)
            {
                FwProfileLoad(g_ProfBit[p], &c->Orig[p]);
                CheckDlgButton(hDlg, IDC_CS(p, CS_ON), c->Orig[p].Enable ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(hDlg, IDC_CS(p, CS_OFF), c->Orig[p].Enable ? BST_UNCHECKED : BST_CHECKED);
                CheckDlgButton(hDlg, IDC_CS(p, CS_BLOCK), c->Orig[p].DoNotAllowExceptions ? BST_CHECKED : BST_UNCHECKED);
                CheckDlgButton(hDlg, IDC_CS(p, CS_NOTIFY), c->Orig[p].DisableNotifications ? BST_UNCHECKED : BST_CHECKED);
                CustomizeEnable(hDlg, p);
            }
            if (!ProfVisible(0))
                CustomizeHideDomain(hDlg);
            return TRUE;
        }

        case WM_CTLCOLORSTATIC:
        {
            UINT id = GetDlgCtrlID((HWND)lParam);
            HDC hdc = (HDC)wParam;
            INT p;
            if (id == IDC_C_TITLE)
            {
                SetTextColor(hdc, g_Blue);
                SetBkMode(hdc, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_3DFACE);
            }
            for (p = 0; p < NPROF; p++)
            {
                if (id == (UINT)IDC_CS(p, CS_GREEN)) return (INT_PTR)g_hGreen;
                if (id == (UINT)IDC_CS(p, CS_RED)) return (INT_PTR)g_hRed;
                if (id == (UINT)IDC_CS(p, CS_HEADER))
                {
                    SetTextColor(hdc, g_Blue);
                    SetBkMode(hdc, TRANSPARENT);
                    return (INT_PTR)GetSysColorBrush(COLOR_3DFACE);
                }
            }
            break;
        }

        case WM_COMMAND:
        {
            UINT id = LOWORD(wParam);
            INT p;
            if (HIWORD(wParam) == BN_CLICKED)
            {
                for (p = 0; p < NPROF; p++)
                {
                    if (id == (UINT)IDC_CS(p, CS_ON) || id == (UINT)IDC_CS(p, CS_OFF))
                    {
                        /* exactly one of the pair, whatever the dialog manager's grouping does */
                        CheckDlgButton(hDlg, IDC_CS(p, CS_ON), id == (UINT)IDC_CS(p, CS_ON) ? BST_CHECKED : BST_UNCHECKED);
                        CheckDlgButton(hDlg, IDC_CS(p, CS_OFF), id == (UINT)IDC_CS(p, CS_OFF) ? BST_CHECKED : BST_UNCHECKED);
                        CustomizeEnable(hDlg, p);
                    }
                }
            }
            if (id == IDOK)
            {
                DWORD err = 0;
                for (p = 0; p < NPROF && !err; p++)
                {
                    DWORD en = IsDlgButtonChecked(hDlg, IDC_CS(p, CS_ON)) == BST_CHECKED;
                    DWORD blk = IsDlgButtonChecked(hDlg, IDC_CS(p, CS_BLOCK)) == BST_CHECKED;
                    DWORD dis = IsDlgButtonChecked(hDlg, IDC_CS(p, CS_NOTIFY)) != BST_CHECKED;
                    if (en != (c->Orig[p].Enable != 0))
                        err = FwProfileSetDword(g_ProfBit[p], L"EnableFirewall", en, FALSE);
                    if (!err && blk != (c->Orig[p].DoNotAllowExceptions != 0))
                        err = FwProfileSetDword(g_ProfBit[p], L"DoNotAllowExceptions", blk, FALSE);
                    if (!err && dis != (c->Orig[p].DisableNotifications != 0))
                        err = FwProfileSetDword(g_ProfBit[p], L"DisableNotifications", dis, FALSE);
                }
                if (err)
                {
                    ReportError(hDlg, IDS_ERR_SAVE, err);
                    return TRUE;
                }
                EndDialog(hDlg, IDOK);
                return TRUE;
            }
            if (id == IDCANCEL)
            {
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            break;
        }

        case WM_CLOSE:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;

        case WM_NCDESTROY:
            if (c)
            {
                HeapFree(GetProcessHeap(), 0, c);
                SetWindowLongPtrW(hDlg, DWLP_USER, 0);
            }
            break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ restore defaults */

static INT_PTR CALLBACK RestoreDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
            MakeFonts();
            SendDlgItemMessageW(hDlg, IDC_R_TITLE, WM_SETFONT, (WPARAM)g_hTitleFont, TRUE);
            return TRUE;

        case WM_CTLCOLORSTATIC:
            if (GetDlgCtrlID((HWND)lParam) == IDC_R_TITLE)
            {
                SetTextColor((HDC)wParam, g_Blue);
                SetBkMode((HDC)wParam, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_3DFACE);
            }
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_R_RESTORE)
            {
                if (MessageBoxW(hDlg, Str(IDS_CONFIRM_RESTORE), Str(IDS_CPLNAME), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES)
                {
                    DWORD err = FwResetAll();
                    if (err)
                        ReportError(hDlg, IDS_ERR_RESTORE, err);
                    else
                    {
                        MessageBoxW(hDlg, Str(IDS_RESTORED), Str(IDS_CPLNAME), MB_OK | MB_ICONINFORMATION);
                        EndDialog(hDlg, IDOK);
                    }
                }
                return TRUE;
            }
            if (LOWORD(wParam) == IDCANCEL)
            {
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            break;

        case WM_CLOSE:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ allowed apps */

/* One row: a rule group (several rules) or an ungrouped program rule (one app, TCP and UDP rules merged). */
typedef struct _ENTRY
{
    WCHAR Name[256];
    WCHAR App[MAX_PATH];
    BOOL IsGroup, IsNew, Removed;
    PWSTR *Ids;                 /* rule ids in the store */
    ULONG NIds, CapIds;
    BOOL En0, Pr0, Pu0, Dom0;   /* as stored */
    BOOL En, Pr, Pu;            /* as edited */
} ENTRY;

typedef struct _ALLOWED
{
    ENTRY *E;
    ULONG N, Cap;
    HWND hList;
    BOOL Loading;
} ALLOWED;

static BOOL AddId(ENTRY *e, PCWSTR id)
{
    if (e->NIds == e->CapIds)
    {
        ULONG cap = e->CapIds ? e->CapIds * 2 : 4;
        PWSTR *n = e->Ids ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, e->Ids, cap * sizeof(PWSTR))
                          : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(PWSTR));
        if (!n) return FALSE;
        e->Ids = n; e->CapIds = cap;
    }
    e->Ids[e->NIds] = HeapAlloc(GetProcessHeap(), 0, (wcslen(id) + 1) * sizeof(WCHAR));
    if (!e->Ids[e->NIds]) return FALSE;
    wcscpy(e->Ids[e->NIds], id);
    e->NIds++;
    return TRUE;
}

static VOID FreeAllowed(ALLOWED *a)
{
    ULONG i, j;
    for (i = 0; i < a->N; i++)
    {
        for (j = 0; j < a->E[i].NIds; j++) HeapFree(GetProcessHeap(), 0, a->E[i].Ids[j]);
        if (a->E[i].Ids) HeapFree(GetProcessHeap(), 0, a->E[i].Ids);
    }
    if (a->E) HeapFree(GetProcessHeap(), 0, a->E);
    a->E = NULL; a->N = a->Cap = 0;
}

static ENTRY *NewEntry(ALLOWED *a)
{
    ENTRY *e;
    if (a->N == a->Cap)
    {
        ULONG cap = a->Cap ? a->Cap * 2 : 32;
        ENTRY *n = a->E ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, a->E, cap * sizeof(ENTRY))
                        : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap * sizeof(ENTRY));
        if (!n) return NULL;
        a->E = n; a->Cap = cap;
    }
    e = &a->E[a->N++];
    ZeroMemory(e, sizeof(*e));
    return e;
}

static ULONG EffProfiles(LONG p)
{
    return (p == FWP_ANY_COM) ? FWP_ALL : ((ULONG)p & FWP_ALL);
}

/* Inbound allow rules: a rule group, or an ungrouped rule that names a program. */
static BOOL LoadAllowed(ALLOWED *a)
{
    FW_RULESET rs;
    ULONG i, j;
    DWORD err = FwStoreLoad(&rs);
    if (err) return FALSE;
    for (i = 0; i < rs.N; i++)
    {
        const FW_RULE *r = &rs.R[i];
        ENTRY *e = NULL;
        BOOL grouped = r->Group && r->Group[0];
        PCWSTR key;
        if (r->Dir != 1 || r->Action != 1 || !r->Id) continue;
        if (grouped) key = r->Group;
        else if (r->App && r->App[0]) key = r->App;
        else continue;
        for (j = 0; j < a->N; j++)
        {
            ENTRY *x = &a->E[j];
            if (x->IsGroup == grouped && !_wcsicmp(grouped ? x->Name : x->App, key)) { e = x; break; }
        }
        if (!e)
        {
            e = NewEntry(a);
            if (!e) break;
            e->IsGroup = grouped;
            if (grouped) StringCchCopyW(e->Name, ARRAYSIZE(e->Name), r->Group);
            else
            {
                StringCchCopyW(e->Name, ARRAYSIZE(e->Name), r->Name ? r->Name : r->App);
                StringCchCopyW(e->App, ARRAYSIZE(e->App), r->App);
            }
        }
        AddId(e, r->Id);
        if (r->Enabled) e->En0 = TRUE;
        if (EffProfiles(r->Profiles) & FWP_PRIVATE) e->Pr0 = TRUE;
        if (EffProfiles(r->Profiles) & FWP_PUBLIC) e->Pu0 = TRUE;
        if (EffProfiles(r->Profiles) & FWP_DOMAIN) e->Dom0 = TRUE;
    }
    FwRuleSetFree(&rs);
    for (i = 0; i < a->N; i++)
    {
        a->E[i].En = a->E[i].En0; a->E[i].Pr = a->E[i].Pr0; a->E[i].Pu = a->E[i].Pu0;
    }
    return TRUE;
}

static INT __cdecl CmpEntry(const void *x, const void *y)
{
    return _wcsicmp(((const ENTRY *)x)->Name, ((const ENTRY *)y)->Name);
}

static BOOL PrDisp(const ENTRY *e) { return e->En && e->Pr; }
static BOOL PuDisp(const ENTRY *e) { return e->En && e->Pu; }

static VOID RowUpdate(ALLOWED *a, INT item)
{
    LVITEMW lvi;
    ENTRY *e;
    ZeroMemory(&lvi, sizeof(lvi));
    lvi.mask = LVIF_PARAM; lvi.iItem = item;
    if (!SendMessageW(a->hList, LVM_GETITEMW, 0, (LPARAM)&lvi)) return;
    e = &a->E[lvi.lParam];
    a->Loading = TRUE;
    ListView_SetCheckState(a->hList, item, e->En);
    a->Loading = FALSE;
    ListView_RedrawItems(a->hList, item, item);
}

static INT AddRow(ALLOWED *a, ULONG idx)
{
    LVITEMW lvi;
    INT item;
    ZeroMemory(&lvi, sizeof(lvi));
    lvi.mask = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem = 0x7FFFFFFF;
    lvi.pszText = a->E[idx].Name;
    lvi.lParam = idx;
    a->Loading = TRUE;
    item = (INT)SendMessageW(a->hList, LVM_INSERTITEMW, 0, (LPARAM)&lvi);
    ListView_SetCheckState(a->hList, item, a->E[idx].En);
    a->Loading = FALSE;
    return item;
}

static ENTRY *SelectedEntry(ALLOWED *a, INT *pItem)
{
    INT item = ListView_GetNextItem(a->hList, -1, LVNI_SELECTED);
    LVITEMW lvi;
    if (item < 0) return NULL;
    ZeroMemory(&lvi, sizeof(lvi));
    lvi.mask = LVIF_PARAM; lvi.iItem = item;
    if (!SendMessageW(a->hList, LVM_GETITEMW, 0, (LPARAM)&lvi)) return NULL;
    if (pItem) *pItem = item;
    return &a->E[lvi.lParam];
}

static VOID AllowedButtons(HWND hDlg, ALLOWED *a)
{
    ENTRY *e = SelectedEntry(a, NULL);
    EnableWindow(GetDlgItem(hDlg, IDC_A_DETAILS), e != NULL);
    EnableWindow(GetDlgItem(hDlg, IDC_A_REMOVE), e && !e->IsGroup);
}

/* Windows does not let the predefined groups be removed; entries the user added can be */
static VOID ToggleBit(ENTRY *e, BOOL priv)
{
    BOOL *bit = priv ? &e->Pr : &e->Pu;
    BOOL *other = priv ? &e->Pu : &e->Pr;
    if (priv ? PrDisp(e) : PuDisp(e))
    {
        *bit = FALSE;
        if (!*other && !e->Dom0) e->En = FALSE;
    }
    else
    {
        if (!e->En) { *other = FALSE; e->En = TRUE; }
        *bit = TRUE;
    }
}

static VOID ToggleName(ENTRY *e, BOOL on)
{
    e->En = on;
    if (on && !e->Pr && !e->Pu && !e->Dom0) e->Pr = TRUE;
}

static VOID AppendProfiles(PWSTR out, SIZE_T cch, ULONG prof)
{
    BOOL first = TRUE;
    ULONG p = EffProfiles((LONG)prof);
    if (p & FWP_DOMAIN) { StringCchCatW(out, cch, Str(IDS_DOM_ONLY)); first = FALSE; }
    if (p & FWP_PRIVATE) { if (!first) StringCchCatW(out, cch, L", "); StringCchCatW(out, cch, Str(IDS_COL_PRIVATE)); first = FALSE; }
    if (p & FWP_PUBLIC) { if (!first) StringCchCatW(out, cch, L", "); StringCchCatW(out, cch, Str(IDS_COL_PUBLIC)); }
}

static VOID ShowDetails(HWND hDlg, const ENTRY *e)
{
    FW_RULESET rs;
    WCHAR text[3000], line[600];
    ULONG i, j;
    text[0] = 0;
    StringCchPrintfW(line, ARRAYSIZE(line), Str(IDS_DET_NAME), e->Name);
    StringCchCatW(text, ARRAYSIZE(text), line);
    StringCchCatW(text, ARRAYSIZE(text), L"\n");
    if (e->IsNew)
    {
        StringCchPrintfW(line, ARRAYSIZE(line), Str(IDS_DET_PROGRAM), e->App);
        StringCchCatW(text, ARRAYSIZE(text), line);
    }
    else if (FwStoreLoad(&rs) == 0)
    {
        for (j = 0; j < e->NIds; j++)
        {
            for (i = 0; i < rs.N; i++)
            {
                const FW_RULE *r = &rs.R[i];
                if (!r->Id || _wcsicmp(r->Id, e->Ids[j])) continue;
                StringCchCatW(text, ARRAYSIZE(text), L"\n");
                StringCchPrintfW(line, ARRAYSIZE(line), Str(IDS_DET_RULE), r->Name ? r->Name : L"");
                StringCchCatW(text, ARRAYSIZE(text), line);
                if (!r->Enabled) { StringCchCatW(text, ARRAYSIZE(text), L" "); StringCchCatW(text, ARRAYSIZE(text), Str(IDS_DET_DISABLED)); }
                if (r->Desc && r->Desc[0] && r->Desc[0] != L'@')
                {
                    StringCchCatW(text, ARRAYSIZE(text), L"\n");
                    StringCchPrintfW(line, ARRAYSIZE(line), Str(IDS_DET_DESC), r->Desc);
                    StringCchCatW(text, ARRAYSIZE(text), line);
                }
                if (r->App && r->App[0])
                {
                    StringCchCatW(text, ARRAYSIZE(text), L"\n");
                    StringCchPrintfW(line, ARRAYSIZE(line), Str(IDS_DET_PROGRAM), r->App);
                    StringCchCatW(text, ARRAYSIZE(text), line);
                }
                if (r->LPorts && r->LPorts[0] && wcscmp(r->LPorts, L"*"))
                {
                    StringCchCatW(text, ARRAYSIZE(text), L"\n");
                    StringCchPrintfW(line, ARRAYSIZE(line), Str(IDS_DET_PORTS), r->LPorts);
                    StringCchCatW(text, ARRAYSIZE(text), line);
                }
                line[0] = 0;
                AppendProfiles(line, ARRAYSIZE(line), (ULONG)r->Profiles);
                {
                    WCHAR l2[700];
                    StringCchPrintfW(l2, ARRAYSIZE(l2), Str(IDS_DET_PROFILES), line);
                    StringCchCatW(text, ARRAYSIZE(text), L"\n");
                    StringCchCatW(text, ARRAYSIZE(text), l2);
                }
                StringCchCatW(text, ARRAYSIZE(text), L"\n");
            }
        }
        FwRuleSetFree(&rs);
    }
    MessageBoxW(hDlg, text, Str(IDS_DETAILS_TITLE), MB_OK | MB_ICONINFORMATION);
}

static DWORD ApplyAllowed(ALLOWED *a)
{
    DWORD err = 0;
    FW_RULESET rs;
    ULONG i, j, k;
    err = FwStoreLoad(&rs);
    if (err) return err;
    for (i = 0; i < a->N && !err; i++)
    {
        ENTRY *e = &a->E[i];
        if (e->IsNew && e->Removed) continue;
        if (e->Removed)
        {
            for (j = 0; j < e->NIds && !err; j++) err = FwStoreDelete(e->Ids[j]);
            continue;
        }
        if (e->IsNew)
        {
            FW_RULE r;
            FwRuleInit(&r);
            FwRuleSetStr(&r.Name, e->Name);
            FwRuleSetStr(&r.App, e->App);
            r.Enabled = TRUE; r.Dir = 1; r.Action = 1; r.Protocol = 256;
            r.Profiles = (e->Pr ? FWP_PRIVATE : 0) | (e->Pu ? FWP_PUBLIC : 0);
            if (r.Profiles == FWP_ALL) r.Profiles = FWP_ANY_COM;
            err = FwStoreAdd(&r);
            FwRuleFree(&r);
            continue;
        }
        if (e->En == e->En0 && e->Pr == e->Pr0 && e->Pu == e->Pu0) continue;
        for (j = 0; j < e->NIds && !err; j++)
        {
            for (k = 0; k < rs.N; k++)
            {
                FW_RULE *r = &rs.R[k];
                ULONG prof;
                if (!r->Id || _wcsicmp(r->Id, e->Ids[j])) continue;
                prof = EffProfiles(r->Profiles);
                if (e->Pr != e->Pr0) prof = e->Pr ? (prof | FWP_PRIVATE) : (prof & ~FWP_PRIVATE);
                if (e->Pu != e->Pu0) prof = e->Pu ? (prof | FWP_PUBLIC) : (prof & ~FWP_PUBLIC);
                if (!(prof & FWP_ALL))
                    r->Enabled = FALSE;     /* no network type left: keep the stored types, switch the rule off */
                else
                {
                    r->Profiles = (prof == FWP_ALL) ? FWP_ANY_COM : (LONG)prof;
                    r->Enabled = e->En;
                }
                err = FwStoreUpdate(r);
                break;
            }
        }
    }
    FwRuleSetFree(&rs);
    return err;
}

typedef struct { WCHAR Path[MAX_PATH]; WCHAR Name[128]; BOOL Pr, Pu; } ADDAPP;

static INT_PTR CALLBACK AddAppDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    ADDAPP *d = (ADDAPP *)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (uMsg)
    {
        case WM_INITDIALOG:
            SetWindowLongPtrW(hDlg, DWLP_USER, lParam);
            CheckDlgButton(hDlg, IDC_AA_PRIVATE, BST_CHECKED);
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_AA_BROWSE:
                {
                    OPENFILENAMEW ofn;
                    WCHAR file[MAX_PATH], filter[160];
                    PWSTR f = filter;
                    SIZE_T cch = ARRAYSIZE(filter), n;
                    file[0] = 0;
                    n = wcslen(Str(IDS_FILTER_EXE)) + 1;
                    StringCchCopyW(f, cch, Str(IDS_FILTER_EXE)); f += n; cch -= n;
                    StringCchCopyW(f, cch, L"*.exe;*.com"); f += wcslen(f) + 1; cch -= 12;
                    n = wcslen(Str(IDS_FILTER_ALL)) + 1;
                    StringCchCopyW(f, cch, Str(IDS_FILTER_ALL)); f += n; cch -= n;
                    StringCchCopyW(f, cch, L"*.*"); f += wcslen(f) + 1;
                    *f = 0;
                    ZeroMemory(&ofn, sizeof(ofn));
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hDlg;
                    ofn.lpstrFilter = filter;
                    ofn.lpstrFile = file;
                    ofn.nMaxFile = ARRAYSIZE(file);
                    ofn.lpstrTitle = Str(IDS_BROWSE_TITLE);
                    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
                    if (GetOpenFileNameW(&ofn))
                    {
                        PCWSTR base = wcsrchr(file, L'\\');
                        WCHAR nm[128], cur[8];
                        PWSTR dot;
                        SetDlgItemTextW(hDlg, IDC_AA_PATH, file);
                        GetDlgItemTextW(hDlg, IDC_AA_NAME, cur, ARRAYSIZE(cur));
                        if (!cur[0])
                        {
                            StringCchCopyW(nm, ARRAYSIZE(nm), base ? base + 1 : file);
                            dot = wcsrchr(nm, L'.');
                            if (dot) *dot = 0;
                            SetDlgItemTextW(hDlg, IDC_AA_NAME, nm);
                        }
                    }
                    return TRUE;
                }
                case IDOK:
                {
                    DWORD attr;
                    GetDlgItemTextW(hDlg, IDC_AA_PATH, d->Path, ARRAYSIZE(d->Path));
                    GetDlgItemTextW(hDlg, IDC_AA_NAME, d->Name, ARRAYSIZE(d->Name));
                    attr = GetFileAttributesW(d->Path);
                    if (!d->Path[0] || attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
                    {
                        MessageBoxW(hDlg, Str(IDS_ERR_ADDPATH), Str(IDS_CPLNAME), MB_OK | MB_ICONWARNING);
                        return TRUE;
                    }
                    d->Pr = IsDlgButtonChecked(hDlg, IDC_AA_PRIVATE) == BST_CHECKED;
                    d->Pu = IsDlgButtonChecked(hDlg, IDC_AA_PUBLIC) == BST_CHECKED;
                    if (!d->Pr && !d->Pu)
                    {
                        MessageBoxW(hDlg, Str(IDS_ERR_ADDNET), Str(IDS_CPLNAME), MB_OK | MB_ICONWARNING);
                        return TRUE;
                    }
                    if (!d->Name[0])
                    {
                        PCWSTR base = wcsrchr(d->Path, L'\\');
                        PWSTR dot;
                        StringCchCopyW(d->Name, ARRAYSIZE(d->Name), base ? base + 1 : d->Path);
                        dot = wcsrchr(d->Name, L'.');
                        if (dot) *dot = 0;
                    }
                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            break;

        case WM_CLOSE:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
    }
    return FALSE;
}

static VOID AllowedAddApp(HWND hDlg, ALLOWED *a)
{
    ADDAPP d;
    ULONG i;
    ZeroMemory(&d, sizeof(d));
    if (DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_ADDAPP), hDlg, AddAppDlgProc, (LPARAM)&d) != IDOK)
        return;
    for (i = 0; i < a->N; i++)
    {
        ENTRY *e = &a->E[i];
        if (!e->IsGroup && !e->Removed && !_wcsicmp(e->App, d.Path))
        {
            LVFINDINFOW fi;
            INT item;
            if (!e->En) { e->Pr = e->Pu = FALSE; }
            e->En = TRUE;
            if (d.Pr) e->Pr = TRUE;
            if (d.Pu) e->Pu = TRUE;
            ZeroMemory(&fi, sizeof(fi));
            fi.flags = LVFI_PARAM; fi.lParam = i;
            item = (INT)SendMessageW(a->hList, LVM_FINDITEMW, (WPARAM)-1, (LPARAM)&fi);
            if (item >= 0)
            {
                RowUpdate(a, item);
                ListView_SetItemState(a->hList, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                ListView_EnsureVisible(a->hList, item, FALSE);
            }
            return;
        }
    }
    {
        ENTRY *e = NewEntry(a);
        INT item;
        if (!e) return;
        e->IsNew = TRUE;
        StringCchCopyW(e->Name, ARRAYSIZE(e->Name), d.Name);
        StringCchCopyW(e->App, ARRAYSIZE(e->App), d.Path);
        e->En = TRUE; e->Pr = d.Pr; e->Pu = d.Pu;
        item = AddRow(a, a->N - 1);
        ListView_SetItemState(a->hList, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(a->hList, item, FALSE);
        SetFocus(a->hList);
    }
}

static VOID DrawCheckCell(HDC hdc, const RECT *cell, BOOL checked, BOOL selected, BOOL focusRow)
{
    RECT box;
    INT sz = 13;
    UNREFERENCED_PARAMETER(focusRow);
    FillRect(hdc, cell, GetSysColorBrush(selected ? COLOR_HIGHLIGHT : COLOR_WINDOW));
    box.left = cell->left + (cell->right - cell->left - sz) / 2;
    box.top = cell->top + (cell->bottom - cell->top - sz) / 2;
    box.right = box.left + sz; box.bottom = box.top + sz;
    DrawFrameControl(hdc, &box, DFC_BUTTON, DFCS_BUTTONCHECK | (checked ? DFCS_CHECKED : 0));
}

static INT_PTR CALLBACK AllowedDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    ALLOWED *a = (ALLOWED *)GetWindowLongPtrW(hDlg, DWLP_USER);
    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            LVCOLUMNW col;
            RECT rc;
            ULONG i;
            INT cxCol;
            a = (ALLOWED *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*a));
            if (!a) { EndDialog(hDlg, IDCANCEL); return TRUE; }
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)a);
            MakeFonts();
            SendDlgItemMessageW(hDlg, IDC_A_TITLE, WM_SETFONT, (WPARAM)g_hTitleFont, TRUE);
            a->hList = GetDlgItem(hDlg, IDC_A_LIST);
            ListView_SetExtendedListViewStyle(a->hList, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            GetClientRect(a->hList, &rc);
            cxCol = 56;
            ZeroMemory(&col, sizeof(col));
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.pszText = (PWSTR)Str(IDS_COL_NAME);
            col.cx = rc.right - 2 * cxCol - GetSystemMetrics(SM_CXVSCROLL) - 2;
            SendMessageW(a->hList, LVM_INSERTCOLUMNW, 0, (LPARAM)&col);
            col.pszText = (PWSTR)Str(IDS_COL_PRIVATE); col.cx = cxCol;
            SendMessageW(a->hList, LVM_INSERTCOLUMNW, 1, (LPARAM)&col);
            col.pszText = (PWSTR)Str(IDS_COL_PUBLIC);
            SendMessageW(a->hList, LVM_INSERTCOLUMNW, 2, (LPARAM)&col);
            if (!LoadAllowed(a))
                ReportError(hDlg, IDS_ERR_SAVE, GetLastError());
            qsort(a->E, a->N, sizeof(ENTRY), CmpEntry);
            for (i = 0; i < a->N; i++) AddRow(a, i);
            if (a->N) ListView_SetItemState(a->hList, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            AllowedButtons(hDlg, a);
            return TRUE;
        }

        case WM_CTLCOLORSTATIC:
            if (GetDlgCtrlID((HWND)lParam) == IDC_A_TITLE)
            {
                SetTextColor((HDC)wParam, g_Blue);
                SetBkMode((HDC)wParam, TRANSPARENT);
                return (INT_PTR)GetSysColorBrush(COLOR_3DFACE);
            }
            break;

        case WM_NOTIFY:
        {
            LPNMHDR nm = (LPNMHDR)lParam;
            if (nm->idFrom != IDC_A_LIST || !a) break;
            switch (nm->code)
            {
                case LVN_ITEMCHANGED:
                {
                    LPNMLISTVIEW lv = (LPNMLISTVIEW)lParam;
                    if (a->Loading) break;
                    if ((lv->uChanged & LVIF_STATE) && ((lv->uNewState ^ lv->uOldState) & LVIS_SELECTED))
                        AllowedButtons(hDlg, a);
                    if ((lv->uChanged & LVIF_STATE) && ((lv->uNewState ^ lv->uOldState) & LVIS_STATEIMAGEMASK) && lv->iItem >= 0)
                    {
                        BOOL on = ListView_GetCheckState(a->hList, lv->iItem) != 0;
                        LVITEMW lvi;
                        ZeroMemory(&lvi, sizeof(lvi));
                        lvi.mask = LVIF_PARAM; lvi.iItem = lv->iItem;
                        if (SendMessageW(a->hList, LVM_GETITEMW, 0, (LPARAM)&lvi))
                        {
                            ToggleName(&a->E[lvi.lParam], on);
                            RowUpdate(a, lv->iItem);
                        }
                    }
                    break;
                }
                case NM_CLICK:
                {
                    LPNMITEMACTIVATE ia = (LPNMITEMACTIVATE)lParam;
                    LVHITTESTINFO ht;
                    ZeroMemory(&ht, sizeof(ht));
                    ht.pt = ia->ptAction;
                    if (ListView_SubItemHitTest(a->hList, &ht) >= 0 && ht.iItem >= 0 && (ht.iSubItem == 1 || ht.iSubItem == 2))
                    {
                        LVITEMW lvi;
                        ZeroMemory(&lvi, sizeof(lvi));
                        lvi.mask = LVIF_PARAM; lvi.iItem = ht.iItem;
                        if (SendMessageW(a->hList, LVM_GETITEMW, 0, (LPARAM)&lvi))
                        {
                            ToggleBit(&a->E[lvi.lParam], ht.iSubItem == 1);
                            RowUpdate(a, ht.iItem);
                            ListView_RedrawItems(a->hList, ht.iItem, ht.iItem);
                        }
                    }
                    break;
                }
                case NM_CUSTOMDRAW:
                {
                    LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lParam;
                    LONG_PTR r = CDRF_DODEFAULT;
                    if (cd->nmcd.dwDrawStage == CDDS_PREPAINT)
                        r = CDRF_NOTIFYITEMDRAW;
                    else if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
                        r = CDRF_NOTIFYSUBITEMDRAW;
                    else if (cd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM) && (cd->iSubItem == 1 || cd->iSubItem == 2))
                    {
                        RECT rc;
                        LVITEMW lvi;
                        INT item = (INT)cd->nmcd.dwItemSpec;
                        ZeroMemory(&lvi, sizeof(lvi));
                        lvi.mask = LVIF_PARAM; lvi.iItem = item;
                        rc.top = cd->iSubItem; rc.left = LVIR_BOUNDS;
                        if (SendMessageW(a->hList, LVM_GETITEMW, 0, (LPARAM)&lvi) &&
                            SendMessageW(a->hList, LVM_GETSUBITEMRECT, item, (LPARAM)&rc))
                        {
                            ENTRY *e = &a->E[lvi.lParam];
                            BOOL sel = (ListView_GetItemState(a->hList, item, LVIS_SELECTED) & LVIS_SELECTED) != 0;
                            DrawCheckCell(cd->nmcd.hdc, &rc, cd->iSubItem == 1 ? PrDisp(e) : PuDisp(e), sel, FALSE);
                            r = CDRF_SKIPDEFAULT;
                        }
                    }
                    SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, r);
                    return TRUE;
                }
            }
            break;
        }

        case WM_COMMAND:
        {
            UINT id = LOWORD(wParam);
            if (!a) break;
            switch (id)
            {
                case IDC_A_DETAILS:
                {
                    ENTRY *e = SelectedEntry(a, NULL);
                    if (e) ShowDetails(hDlg, e);
                    return TRUE;
                }
                case IDC_A_REMOVE:
                {
                    INT item;
                    ENTRY *e = SelectedEntry(a, &item);
                    if (e && !e->IsGroup)
                    {
                        WCHAR msg[700];
                        StringCchPrintfW(msg, ARRAYSIZE(msg), Str(IDS_CONFIRM_REMOVE), e->Name);
                        if (MessageBoxW(hDlg, msg, Str(IDS_CPLNAME), MB_YESNO | MB_ICONQUESTION) == IDYES)
                        {
                            e->Removed = TRUE;
                            ListView_DeleteItem(a->hList, item);
                            AllowedButtons(hDlg, a);
                        }
                    }
                    return TRUE;
                }
                case IDC_A_ADD:
                    AllowedAddApp(hDlg, a);
                    AllowedButtons(hDlg, a);
                    return TRUE;
                case IDOK:
                {
                    DWORD err = ApplyAllowed(a);
                    if (err)
                    {
                        ReportError(hDlg, IDS_ERR_SAVE, err);
                        return TRUE;
                    }
                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            break;
        }

        case WM_CLOSE:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;

        case WM_NCDESTROY:
            if (a)
            {
                FreeAllowed(a);
                HeapFree(GetProcessHeap(), 0, a);
                SetWindowLongPtrW(hDlg, DWLP_USER, 0);
            }
            break;
    }
    return FALSE;
}

/* ------------------------------------------------------------------ CPL entry */

LONG APIENTRY CPlApplet(HWND hwndCpl, UINT uMsg, LPARAM lParam1, LPARAM lParam2)
{
    switch (uMsg)
    {
        case CPL_INIT:
        {
            INITCOMMONCONTROLSEX icc;
            icc.dwSize = sizeof(icc);
            icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_LINK_CLASS | ICC_STANDARD_CLASSES;
            InitCommonControlsEx(&icc);
            return TRUE;
        }

        case CPL_GETCOUNT:
            return 1;

        case CPL_INQUIRE:
        {
            CPLINFO *info = (CPLINFO *)lParam2;
            info->lData = 0;
            info->idIcon = IDI_CPLICON;
            info->idName = IDS_CPLNAME;
            info->idInfo = IDS_CPLDESCRIPTION;
            return TRUE;
        }

        case CPL_DBLCLK:
            DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_MAIN), hwndCpl, MainDlgProc, 0);
            return TRUE;
    }
    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_hInst = hinst;
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}
