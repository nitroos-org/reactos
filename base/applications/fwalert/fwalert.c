/*
 * PROJECT:     NitroOS Firewall block prompt
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     "NitroOS Firewall has blocked some features of this app": the dialog mpssvc starts in the
 *              interactive user's session (base/services/mpssvc/prompt.c).
 *
 *   fwalert.exe /prompt PRESELECT "C:\path\to\app.exe"
 *
 * PRESELECT is the profile bitmask (1 domain, 2 private, 4 public) of the checkboxes that start checked.
 * The result is the process exit code: 0 = Cancel (or the dialog was closed), otherwise
 * FWALERT_ALLOW | mask of the checked profiles. The dialog changes nothing itself: it runs as the user and has
 * no right to the rule store. mpssvc, which started it and holds the program path it was started for,
 * validates the answer and writes the rule.
 */
#include <windows.h>
#include <shellapi.h>
#include <stdlib.h>
#include <wchar.h>

#include "resource.h"

#define FWALERT_ALLOW  0x100

static WCHAR g_Path[MAX_PATH];
static WCHAR g_Name[MAX_PATH];
static ULONG g_Pre = 0x2;

static VOID DisplayName(VOID)
{
    DWORD size, handle = 0;
    PVOID data;
    PWSTR base, dot;

    size = GetFileVersionInfoSizeW(g_Path, &handle);
    if (size && (data = HeapAlloc(GetProcessHeap(), 0, size)) != NULL)
    {
        if (GetFileVersionInfoW(g_Path, 0, size, data))
        {
            struct { WORD Lang, CodePage; } *tr = NULL;
            UINT len = 0;
            if (VerQueryValueW(data, L"\\VarFileInfo\\Translation", (PVOID *)&tr, &len) && tr && len >= 4)
            {
                WCHAR key[64]; PWSTR desc = NULL;
                wsprintfW(key, L"\\StringFileInfo\\%04x%04x\\FileDescription", tr->Lang, tr->CodePage);
                if (VerQueryValueW(data, key, (PVOID *)&desc, &len) && desc && *desc)
                    lstrcpynW(g_Name, desc, ARRAYSIZE(g_Name));
            }
        }
        HeapFree(GetProcessHeap(), 0, data);
    }
    if (g_Name[0]) return;
    base = wcsrchr(g_Path, L'\\');
    lstrcpynW(g_Name, base ? base + 1 : g_Path, ARRAYSIZE(g_Name));
    dot = wcsrchr(g_Name, L'.');
    if (dot && dot != g_Name) *dot = 0;
}

static VOID SetFormatted(HWND hDlg, UINT ctl, UINT fmtId)
{
    WCHAR fmt[256], out[512]; PWSTR args[1];
    LoadStringW(NULL, fmtId, fmt, ARRAYSIZE(fmt));
    args[0] = g_Name;
    if (!FormatMessageW(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, fmt, 0, 0, out, ARRAYSIZE(out), (va_list *)args))
        lstrcpynW(out, fmt, ARRAYSIZE(out));
    SetDlgItemTextW(hDlg, ctl, out);
}

static ULONG Checked(HWND hDlg)
{
    return (IsDlgButtonChecked(hDlg, IDC_DOMAIN) ? 1 : 0) | (IsDlgButtonChecked(hDlg, IDC_PRIVATE) ? 2 : 0) |
           (IsDlgButtonChecked(hDlg, IDC_PUBLIC) ? 4 : 0);
}

static INT_PTR CALLBACK AlertProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            WCHAR unk[32];
            HFONT hf = (HFONT)SendDlgItemMessageW(hDlg, IDC_HEAD, WM_GETFONT, 0, 0);
            LOGFONTW lf;
            if (hf && GetObjectW(hf, sizeof(lf), &lf))
            {
                lf.lfWeight = FW_BOLD;
                hf = CreateFontIndirectW(&lf);
                if (hf) SendDlgItemMessageW(hDlg, IDC_HEAD, WM_SETFONT, (WPARAM)hf, FALSE);
            }
            SendDlgItemMessageW(hDlg, IDC_ALERTICON, STM_SETICON, (WPARAM)LoadIconW(NULL, (PCWSTR)IDI_WARNING), 0);
            DisplayName();
            SetFormatted(hDlg, IDC_BODY, IDS_BODY);
            SetFormatted(hDlg, IDC_ALLOW_TEXT, IDS_ALLOW_TEXT);
            LoadStringW(NULL, IDS_UNKNOWN, unk, ARRAYSIZE(unk));
            SetDlgItemTextW(hDlg, IDC_VAL_NAME, g_Name);
            SetDlgItemTextW(hDlg, IDC_VAL_PUB, unk);
            SetDlgItemTextW(hDlg, IDC_VAL_PATH, g_Path);
            CheckDlgButton(hDlg, IDC_DOMAIN, (g_Pre & 1) ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_PRIVATE, (g_Pre & 2) ? BST_CHECKED : BST_UNCHECKED);
            CheckDlgButton(hDlg, IDC_PUBLIC, (g_Pre & 4) ? BST_CHECKED : BST_UNCHECKED);
            EnableWindow(GetDlgItem(hDlg, IDC_ALLOW), Checked(hDlg) != 0);
            SetForegroundWindow(hDlg);
            return TRUE;
        }
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_DOMAIN:
                case IDC_PRIVATE:
                case IDC_PUBLIC:
                    EnableWindow(GetDlgItem(hDlg, IDC_ALLOW), Checked(hDlg) != 0);
                    return TRUE;
                case IDC_ALLOW:
                    EndDialog(hDlg, FWALERT_ALLOW | Checked(hDlg));
                    return TRUE;
                case IDCANCEL:
                    EndDialog(hDlg, 0);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmd, int show)
{
    int argc = 0;
    PWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    INT_PTR r;

    if (!argv || argc < 4 || _wcsicmp(argv[1], L"/prompt"))
        return 0;
    g_Pre = (ULONG)wcstoul(argv[2], NULL, 10) & 7;
    lstrcpynW(g_Path, argv[3], ARRAYSIZE(g_Path));
    r = DialogBoxParamW(hInst, MAKEINTRESOURCEW(IDD_ALERT), NULL, AlertProc, 0);
    return r > 0 ? (int)r : 0;
}
