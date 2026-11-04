/*
 * PROJECT:     ReactOS Software Control Panel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     "Programs and Features": the installed programs (the Uninstall registry keys) with Uninstall /
 *              Change, and the "Turn features on or off" link to the feature manager. It replaces rapps.exe /appwiz.
 *              Like Windows 10 it has no software catalog: browsing and installing software is the feature
 *              manager's job (optfeatures.exe).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "appwiz.h"

#include <wingdi.h>
#include <winuser.h>

#include <commctrl.h>
#include <shellapi.h>
#include <strsafe.h>

#define UNINSTALL_SUBKEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

#define IDC_PLIST    3001
#define IDC_PUNINST  3002
#define IDC_PCHANGE  3003
#define IDC_PREFRESH 3004
#define IDC_PFEAT    3005
#define IDC_PCLOSE   3006
#define IDC_PHEAD    3007

typedef struct _PROG
{
    WCHAR key[256];                       /* a registry key name is at most 255 characters */
    WCHAR name[160];
    WCHAR publisher[96];
    WCHAR version[48];
    WCHAR date[24];
    BOOL  user;
    BOOL  wow32;
    BOOL  view64;                         /* read through KEY_WOW64_64KEY (this is a 32-bit appwiz) */
    BOOL  msi;
    BOOL  canModify;
} PROG;

static PROG *g_prog;
static int g_nprog, g_cprog;
static HWND g_hList, g_hUninst, g_hChange, g_hWnd;
static HFONT g_font;

/* a string of the string table (en-US text when the language has none) */
static LPCWSTR Str(UINT id)
{
    static WCHAR buf[8][256];
    static int n;
    WCHAR *b = buf[n++ & 7];
    if (!LoadStringW(hApplet, id, b, 256)) b[0] = L'\0';
    return b;
}

static BOOL QueryStr(HKEY k, LPCWSTR name, LPWSTR out, DWORD cch)
{
    DWORD type, cb = (cch - 1) * sizeof(WCHAR);
    out[0] = L'\0';
    if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)out, &cb) != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        out[0] = L'\0';
        return FALSE;
    }
    out[cb / sizeof(WCHAR) < cch ? cb / sizeof(WCHAR) : cch - 1] = L'\0';
    return out[0] != L'\0';
}

static DWORD QueryDword(HKEY k, LPCWSTR name)
{
    DWORD type, v = 0, cb = sizeof(v);
    if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)&v, &cb) != ERROR_SUCCESS || type != REG_DWORD) return 0;
    return v;
}

/* "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}": the only key name msiexec /x or /i is given */
static BOOL IsGuidKey(LPCWSTR k)
{
    static const WCHAR pat[] = L"{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}";
    size_t i;
    if (wcslen(k) != ARRAYSIZE(pat) - 1) return FALSE;
    for (i = 0; pat[i]; i++)
    {
        if (pat[i] == L'x') { if (!((k[i] >= L'0' && k[i] <= L'9') || (k[i] >= L'a' && k[i] <= L'f') || (k[i] >= L'A' && k[i] <= L'F'))) return FALSE; }
        else if (k[i] != pat[i]) return FALSE;
    }
    return TRUE;
}

static void AddRoot(HKEY root, BOOL user, BOOL wow32, REGSAM view)
{
    HKEY hk;
    DWORD i, maxKey = 0;
    WCHAR *kn;
    REGSAM sam = KEY_READ | (wow32 ? KEY_WOW64_32KEY : 0) | view;

    if (RegOpenKeyExW(root, UNINSTALL_SUBKEY, 0, sam, &hk) != ERROR_SUCCESS) return;
    /* the enumeration buffer is as long as the longest subkey name: a long name must not end the list */
    if (RegQueryInfoKeyW(hk, NULL, NULL, NULL, NULL, &maxKey, NULL, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS || maxKey < 255)
        maxKey = 255;
    kn = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (maxKey + 1) * sizeof(WCHAR));
    if (!kn) { RegCloseKey(hk); return; }
    for (i = 0; ; i++)
    {
        DWORD cch = maxKey + 1;
        HKEY sk;
        PROG p;
        WCHAR d[24], tmp[160];
        int j;
        BOOL dup = FALSE;
        LONG er = RegEnumKeyExW(hk, i, kn, &cch, NULL, NULL, NULL, NULL);

        if (er == ERROR_MORE_DATA) continue;               /* a name longer than the buffer (added since RegQueryInfoKey): skip it */
        if (er != ERROR_SUCCESS) break;                    /* NO_MORE_ITEMS, or an error that will not go away */
        if (cch >= ARRAYSIZE(p.key)) continue;
        if (RegOpenKeyExW(hk, kn, 0, sam, &sk) != ERROR_SUCCESS) continue;
        ZeroMemory(&p, sizeof(p));
        StringCchCopyW(p.key, ARRAYSIZE(p.key), kn);
        if (!QueryStr(sk, L"DisplayName", p.name, ARRAYSIZE(p.name)) || QueryDword(sk, L"SystemComponent") == 1 ||
            QueryStr(sk, L"ParentKeyName", tmp, ARRAYSIZE(tmp)))
        {
            RegCloseKey(sk);
            continue;                         /* no name, a system component, or an update of another program */
        }
        QueryStr(sk, L"Publisher", p.publisher, ARRAYSIZE(p.publisher));
        QueryStr(sk, L"DisplayVersion", p.version, ARRAYSIZE(p.version));
        if (QueryStr(sk, L"InstallDate", d, ARRAYSIZE(d)) && wcslen(d) == 8)
            StringCchPrintfW(p.date, ARRAYSIZE(p.date), L"%.4s-%.2s-%.2s", d, d + 4, d + 6);
        p.msi = QueryDword(sk, L"WindowsInstaller") != 0 && IsGuidKey(kn);     /* msiexec only gets a product code */
        p.canModify = !QueryDword(sk, L"NoModify") && (QueryStr(sk, L"ModifyPath", tmp, ARRAYSIZE(tmp)) || p.msi);
        if (!p.msi && !QueryStr(sk, L"UninstallString", tmp, ARRAYSIZE(tmp)) && !QueryStr(sk, L"QuietUninstallString", tmp, ARRAYSIZE(tmp)))
        {
            RegCloseKey(sk);
            continue;                         /* nothing to run to remove it */
        }
        RegCloseKey(sk);
        p.user = user;
        p.wow32 = wow32;
        p.view64 = (view & KEY_WOW64_64KEY) != 0;
        for (j = 0; j < g_nprog; j++)         /* the same program seen through two registry views */
            if (!_wcsicmp(g_prog[j].key, p.key) && !_wcsicmp(g_prog[j].name, p.name)) { dup = TRUE; break; }
        if (dup) continue;
        if (g_nprog == g_cprog)
        {
            int nc = g_cprog ? g_cprog * 2 : 128;
            PROG *n = g_prog ? (PROG *)HeapReAlloc(GetProcessHeap(), 0, g_prog, nc * sizeof(PROG))
                             : (PROG *)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(PROG));
            if (!n) break;
            g_prog = n; g_cprog = nc;
        }
        g_prog[g_nprog++] = p;
    }
    HeapFree(GetProcessHeap(), 0, kn);
    RegCloseKey(hk);
}

static void Fill(void)
{
    int i;
    LVITEMW it;

    g_nprog = 0;
    AddRoot(HKEY_CURRENT_USER, TRUE, FALSE, 0);
    AddRoot(HKEY_LOCAL_MACHINE, FALSE, FALSE, 0);
#ifdef _WIN64
    AddRoot(HKEY_LOCAL_MACHINE, FALSE, TRUE, 0);
#else
    /* a 32-bit appwiz (WoW64) lists the 64-bit programs too: KEY_WOW64_64KEY is ignored on a 32-bit system, where the pass finds
     * the same keys again and the duplicate check drops them */
    AddRoot(HKEY_LOCAL_MACHINE, FALSE, FALSE, KEY_WOW64_64KEY);
#endif
    ListView_DeleteAllItems(g_hList);
    for (i = 0; i < g_nprog; i++)
    {
        ZeroMemory(&it, sizeof(it));
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = i;
        it.pszText = g_prog[i].name;
        it.lParam = i;
        ListView_InsertItem(g_hList, &it);
        ListView_SetItemText(g_hList, i, 1, g_prog[i].publisher);
        ListView_SetItemText(g_hList, i, 2, g_prog[i].version);
        ListView_SetItemText(g_hList, i, 3, g_prog[i].date);
    }
    EnableWindow(g_hUninst, FALSE);
    EnableWindow(g_hChange, FALSE);
}

static int Selected(void)
{
    LVITEMW it;
    int sel = ListView_GetNextItem(g_hList, -1, LVNI_SELECTED);
    if (sel < 0) return -1;
    ZeroMemory(&it, sizeof(it));
    it.mask = LVIF_PARAM;
    it.iItem = sel;
    return ListView_GetItem(g_hList, &it) ? (int)it.lParam : -1;
}

/* Run a command line and wait for it while the window keeps painting (disabled, so nothing else can start). */
static void RunAndRefresh(LPWSTR cmd)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    MSG msg;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        WCHAR t[300];
        StringCchPrintfW(t, ARRAYSIZE(t), Str(IDS_PROG_STARTFAIL), GetLastError(), cmd);
        MessageBoxW(g_hWnd, t, Str(IDS_PROG_TITLE), MB_OK | MB_ICONERROR);
        return;
    }
    CloseHandle(pi.hThread);
    EnableWindow(g_hWnd, FALSE);
    for (;;)
    {
        DWORD r = MsgWaitForMultipleObjects(1, &pi.hProcess, FALSE, INFINITE, QS_ALLINPUT);
        if (r == WAIT_OBJECT_0) break;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    CloseHandle(pi.hProcess);
    EnableWindow(g_hWnd, TRUE);
    SetForegroundWindow(g_hWnd);
    Fill();
}

static void DoUninstall(BOOL modify)
{
    int i = Selected();
    HKEY hk;
    WCHAR cmd[1200], raw[1100], path[320];
    REGSAM sam = KEY_READ | (i >= 0 && g_prog[i].wow32 ? KEY_WOW64_32KEY : 0) | (i >= 0 && g_prog[i].view64 ? KEY_WOW64_64KEY : 0);

    if (i < 0) return;
    if (!modify)
    {
        WCHAR t[400];
        StringCchPrintfW(t, ARRAYSIZE(t), Str(IDS_PROG_CONFIRM), g_prog[i].name);
        if (MessageBoxW(g_hWnd, t, Str(IDS_PROG_TITLE), MB_YESNO | MB_ICONQUESTION) != IDYES) return;
    }
    if (g_prog[i].msi)
    {
        StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"msiexec.exe /%c%s", modify ? L'i' : L'x', g_prog[i].key);
        RunAndRefresh(cmd);
        return;
    }
    StringCchPrintfW(path, ARRAYSIZE(path), UNINSTALL_SUBKEY L"\\%s", g_prog[i].key);
    if (RegOpenKeyExW(g_prog[i].user ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE, path, 0, sam, &hk) != ERROR_SUCCESS) return;
    if (!QueryStr(hk, modify ? L"ModifyPath" : L"UninstallString", raw, ARRAYSIZE(raw)) && !modify)
        QueryStr(hk, L"QuietUninstallString", raw, ARRAYSIZE(raw));
    RegCloseKey(hk);
    if (!raw[0]) return;
    if (!modify && StrStrIW(raw, L"rapps.exe"))
    {
        /* an app the old Applications Manager unpacked: its record names rapps.exe, which is gone; the feature manager
         * reads the same record */
        StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"featmgr.exe /nat-uninstall \"%s\" \"%s\" \"-\"", g_prog[i].key, g_prog[i].name);
        RunAndRefresh(cmd);
        return;
    }
    if (!ExpandEnvironmentStringsW(raw, cmd, ARRAYSIZE(cmd))) StringCchCopyW(cmd, ARRAYSIZE(cmd), raw);
    RunAndRefresh(cmd);
}

static void OpenFeatures(void)
{
    ShellExecuteW(g_hWnd, L"open", L"optfeatures.exe", NULL, NULL, SW_SHOWNORMAL);
}

static LRESULT CALLBACK ProgWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            LVCOLUMNW col;
            HWND c, head;

            g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
            g_hWnd = hwnd;
            head = CreateWindowExW(0, L"STATIC", Str(IDS_PROG_HEADER), WS_CHILD | WS_VISIBLE, 12, 10, 740, 32, hwnd, (HMENU)IDC_PHEAD, NULL, NULL);
            g_hList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                      12, 46, 740, 340, hwnd, (HMENU)IDC_PLIST, NULL, NULL);
            ListView_SetExtendedListViewStyle(g_hList, LVS_EX_FULLROWSELECT);
            ZeroMemory(&col, sizeof(col));
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.pszText = (LPWSTR)Str(IDS_PROG_COL_NAME);           col.cx = 300; ListView_InsertColumn(g_hList, 0, &col);
            col.pszText = (LPWSTR)Str(IDS_PROG_COL_PUBLISHER);      col.cx = 190; ListView_InsertColumn(g_hList, 1, &col);
            col.pszText = (LPWSTR)Str(IDS_PROG_COL_VERSION);        col.cx = 110; ListView_InsertColumn(g_hList, 2, &col);
            col.pszText = (LPWSTR)Str(IDS_PROG_COL_DATE);   col.cx = 100; ListView_InsertColumn(g_hList, 3, &col);
            g_hUninst = CreateWindowExW(0, L"BUTTON", Str(IDS_PROG_UNINSTALL), WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED, 12, 396, 90, 26, hwnd, (HMENU)IDC_PUNINST, NULL, NULL);
            g_hChange = CreateWindowExW(0, L"BUTTON", Str(IDS_PROG_CHANGE), WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED, 108, 396, 90, 26, hwnd, (HMENU)IDC_PCHANGE, NULL, NULL);
            CreateWindowExW(0, L"BUTTON", Str(IDS_PROG_REFRESH), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 204, 396, 90, 26, hwnd, (HMENU)IDC_PREFRESH, NULL, NULL);
            CreateWindowExW(0, L"BUTTON", Str(IDS_PROG_FEATURES), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 330, 396, 200, 26, hwnd, (HMENU)IDC_PFEAT, NULL, NULL);
            CreateWindowExW(0, L"BUTTON", Str(IDS_PROG_CLOSE), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 662, 396, 90, 26, hwnd, (HMENU)IDC_PCLOSE, NULL, NULL);
            for (c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
            (void)head;
            Fill();
            return 0;
        }
        case WM_NOTIFY:
            if (((LPNMHDR)lp)->idFrom == IDC_PLIST)
            {
                if (((LPNMHDR)lp)->code == LVN_ITEMCHANGED || ((LPNMHDR)lp)->code == NM_CLICK)
                {
                    int i = Selected();
                    EnableWindow(g_hUninst, i >= 0);
                    EnableWindow(g_hChange, i >= 0 && g_prog[i].canModify);
                }
                else if (((LPNMHDR)lp)->code == NM_DBLCLK && Selected() >= 0)
                    DoUninstall(FALSE);
            }
            return 0;
        case WM_COMMAND:
            switch (LOWORD(wp))
            {
                case IDC_PUNINST:  DoUninstall(FALSE); break;
                case IDC_PCHANGE:  DoUninstall(TRUE); break;
                case IDC_PREFRESH: Fill(); break;
                case IDC_PFEAT:    OpenFeatures(); break;
                case IDC_PCLOSE:   DestroyWindow(hwnd); break;
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

/* the "Programs and Features" window; returns when it is closed */
void ShowProgramsAndFeatures(HWND hwndParent)
{
    WNDCLASSEXW wc;
    INITCOMMONCONTROLSEX icc;
    HWND hwnd;
    MSG m;
    RECT wa;
    int w = 790, h = 480, x, y;

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = ProgWndProc;
    wc.hInstance = hApplet;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"NitroProgramsAndFeatures";
    wc.hIcon = LoadIconW(hApplet, MAKEINTRESOURCEW(IDI_CPLSYSTEM));
    RegisterClassExW(&wc);
    if (!SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0)) SetRect(&wa, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    if (w > wa.right - wa.left) w = wa.right - wa.left;
    if (h > wa.bottom - wa.top) h = wa.bottom - wa.top;
    x = wa.left + ((wa.right - wa.left) - w) / 2;
    y = wa.top + ((wa.bottom - wa.top) - h) / 2;
    hwnd = CreateWindowExW(0, wc.lpszClassName, Str(IDS_PROG_TITLE), WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                           x, y, w, h, hwndParent, NULL, hApplet, NULL);
    if (!hwnd) return;
    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);
    while (GetMessageW(&m, NULL, 0, 0) > 0)
    {
        if (IsDialogMessageW(hwnd, &m)) continue;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    if (g_prog) { HeapFree(GetProcessHeap(), 0, g_prog); g_prog = NULL; g_nprog = g_cprog = 0; }
    UnregisterClassW(wc.lpszClassName, hApplet);
}
