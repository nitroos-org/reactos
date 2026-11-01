/*
 * PROJECT:     Dr. Watson crash reporter
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The "has stopped working" dialog shown after a crash is reported
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <winreg.h>
#include <winnls.h>
#include <wingdi.h>
#include <winuser.h>
#include <shellapi.h>
#include <strsafe.h>
#include <algorithm>
#include "resource.h"

/*
 * Laid out like the Windows 7 dialog with buttons: main instruction, content,
 * the expander on the left and the buttons on the right of the bottom row,
 * the problem details below when expanded. Pixel sizes are for 96 DPI and
 * scaled by the dialog font.
 */

#define WER_KEY        L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"
#define WER_POLICY_KEY L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting"

#define CHECK_PROCESS_TIMER 1

struct CrashDialogData
{
    DumpData* Data;
    const ProblemSignature* Signature;
    LPCWSTR DumpPath;
    LPCWSTR ReportPath;
    bool OfferDebug;
    std::wstring ProgramName;
    std::wstring Instruction;
    std::wstring Content;
    std::wstring Details;
    HFONT BoldFont;
    HICON SmallIcon;
    HICON LargeIcon;
    bool Expanded;
    int CollapsedHeight;
    int ExpandedHeight;
};

/* Windows honours DontShowUI in the machine key and in its policy key, not in the user's key */
static bool IsUiDisabled()
{
    static const LPCWSTR Keys[] = { WER_POLICY_KEY, WER_KEY };
    for (size_t n = 0; n < _countof(Keys); ++n)
    {
        HKEY hKey;
        DWORD Type, Value = 0, Size = sizeof(Value);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Keys[n], 0, KEY_QUERY_VALUE | WER_REG_VIEW, &hKey) != ERROR_SUCCESS)
            continue;
        LONG Error = RegQueryValueExW(hKey, L"DontShowUI", NULL, &Type, (LPBYTE)&Value, &Size);
        RegCloseKey(hKey);
        if (Error == ERROR_SUCCESS && Type == REG_DWORD && Value != 0)
            return true;
    }
    return false;
}

/* No one could answer a dialog on a window station without a display (services) */
static bool IsInteractive()
{
    USEROBJECTFLAGS Flags;
    HWINSTA hWinSta = GetProcessWindowStation();
    return hWinSta &&
           GetUserObjectInformationW(hWinSta, UOI_FLAGS, &Flags, sizeof(Flags), NULL) &&
           (Flags.dwFlags & WSF_VISIBLE);
}

/* Whether a dialog could be answered: not turned off, and a window station with a display */
bool CanShowUi()
{
    return !IsUiDisabled() && IsInteractive();
}

/* The file description of the program, as Windows names it, else its file name */
static std::wstring GetProgramName(const DumpData& data)
{
    struct LANGANDCODEPAGE
    {
        WORD Language;
        WORD CodePage;
    } *Translations;
    DWORD Handle, Size;
    UINT Length;
    std::wstring Name = data.ProcessName;

    Size = GetFileVersionInfoSizeW(data.ProcessPath.c_str(), &Handle);
    if (!Size)
        return Name;
    std::vector<BYTE> Info(Size);
    if (!GetFileVersionInfoW(data.ProcessPath.c_str(), 0, Size, &Info[0]) ||
        !VerQueryValueW(&Info[0], L"\\VarFileInfo\\Translation", (LPVOID*)&Translations, &Length) ||
        Length < sizeof(*Translations))
    {
        return Name;
    }

    WCHAR Query[64];
    LPWSTR Description;
    StringCchPrintfW(Query, _countof(Query), L"\\StringFileInfo\\%04x%04x\\FileDescription",
                     Translations[0].Language, Translations[0].CodePage);
    if (VerQueryValueW(&Info[0], Query, (LPVOID*)&Description, &Length) && Length > 1 && Description[0])
        Name = Description;
    return Name;
}

static std::wstring LoadResString(UINT Id)
{
    LPCWSTR Text;
    int Length = LoadStringW(GetModuleHandleW(NULL), Id, (LPWSTR)&Text, 0);
    return Length > 0 ? std::wstring(Text, Length) : std::wstring();
}

static std::wstring FormatResString(UINT Id, ...)
{
    std::wstring Format = LoadResString(Id);
    LPWSTR Buffer = NULL;
    va_list Args;

    va_start(Args, Id);
    DWORD Length = FormatMessageW(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                                  Format.c_str(), 0, 0, (LPWSTR)&Buffer, 0, &Args);
    va_end(Args);
    if (!Length || !Buffer)
        return Format;
    std::wstring Result(Buffer, Length);
    LocalFree(Buffer);
    return Result;
}

/* Major.minor.build.platform.service pack major.minor.suite mask.product type, as Windows 7 writes it */
static std::wstring GetOsVersionString()
{
    typedef BOOL (WINAPI *PFN_GETPRODUCTINFO)(DWORD, DWORD, DWORD, DWORD, PDWORD);
    OSVERSIONINFOEXW Version = { sizeof(Version) };
    DWORD Product = 0;
    WCHAR Buffer[64];

    if (!GetVersionExW((LPOSVERSIONINFOW)&Version))
        return std::wstring(L"0.0.0.0.0.0.0.0");
    PFN_GETPRODUCTINFO pGetProductInfo =
        (PFN_GETPRODUCTINFO)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProductInfo");
    if (pGetProductInfo)
        pGetProductInfo(Version.dwMajorVersion, Version.dwMinorVersion, Version.wServicePackMajor,
                        Version.wServicePackMinor, &Product);
    StringCchPrintfW(Buffer, _countof(Buffer), L"%lu.%lu.%lu.%lu.%u.%u.%u.%lu",
                     Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber, Version.dwPlatformId,
                     Version.wServicePackMajor, Version.wServicePackMinor, Version.wSuiteMask, Product);
    return std::wstring(Buffer);
}

static void BuildTexts(CrashDialogData* Dlg)
{
    const DumpData& data = *Dlg->Data;
    const ProblemSignature& Sig = *Dlg->Signature;
    WCHAR Locale[16];

    Dlg->ProgramName = GetProgramName(data);
    Dlg->Instruction = FormatResString(IDS_CRASH_INSTRUCTION, Dlg->ProgramName.c_str());
    Dlg->Content = LoadResString(IDS_CRASH_CONTENT);

    StringCchPrintfW(Locale, _countof(Locale), L"%lu", GetUserDefaultLCID());
    std::wstring OsVersion = GetOsVersionString();
    Dlg->Details = FormatResString(IDS_CRASH_SIGNATURE,
                                   data.ProcessName.c_str(), Sig.AppVersion, Sig.AppTimeStamp,
                                   Sig.ModuleName.c_str(), Sig.ModuleVersion, Sig.ModuleTimeStamp,
                                   Sig.Code, Sig.Offset, OsVersion.c_str(), Locale);

    /* The files this report wrote (LocalDumps) */
    if (Dlg->DumpPath[0] || Dlg->ReportPath[0])
    {
        Dlg->Details += L"\r\n\r\n";
        Dlg->Details += LoadResString(IDS_CRASH_FILES);
        if (Dlg->DumpPath[0])
        {
            Dlg->Details += L"\r\n  ";
            Dlg->Details += Dlg->DumpPath;
        }
        if (Dlg->ReportPath[0])
        {
            Dlg->Details += L"\r\n  ";
            Dlg->Details += Dlg->ReportPath;
        }
    }
}

static int TextHeight(HWND hCtrl, HFONT hFont, LPCWSTR Text, int Width)
{
    RECT rc = { 0, 0, Width, 0 };
    HDC hdc = GetDC(hCtrl);
    HGDIOBJ Old = SelectObject(hdc, hFont);
    DrawTextW(hdc, Text, -1, &rc, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX | DT_EDITCONTROL);
    SelectObject(hdc, Old);
    ReleaseDC(hCtrl, hdc);
    return rc.bottom;
}

static int TextWidth(HWND hCtrl, HFONT hFont, LPCWSTR Text)
{
    RECT rc = { 0, 0, 0, 0 };
    HDC hdc = GetDC(hCtrl);
    HGDIOBJ Old = SelectObject(hdc, hFont);
    DrawTextW(hdc, Text, -1, &rc, DT_CALCRECT | DT_SINGLELINE);
    SelectObject(hdc, Old);
    ReleaseDC(hCtrl, hdc);
    return rc.right;
}

static void SetExpanded(HWND hDlg, CrashDialogData* Dlg, bool Expanded)
{
    RECT rc;

    Dlg->Expanded = Expanded;
    SetDlgItemTextW(hDlg, IDC_CRASH_EXPANDER_LABEL,
                    LoadResString(Expanded ? IDS_CRASH_HIDE_DETAILS : IDS_CRASH_SHOW_DETAILS).c_str());
    ShowWindow(GetDlgItem(hDlg, IDC_CRASH_DETAILS), Expanded ? SW_SHOW : SW_HIDE);
    InvalidateRect(GetDlgItem(hDlg, IDC_CRASH_EXPANDER), NULL, TRUE);

    GetWindowRect(hDlg, &rc);
    SetWindowPos(hDlg, NULL, 0, 0, rc.right - rc.left,
                 Expanded ? Dlg->ExpandedHeight : Dlg->CollapsedHeight,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
}

static void Layout(HWND hDlg, CrashDialogData* Dlg)
{
    HFONT hFont = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
    RECT Units = { 4, 8, 0, 0 };
    MapDialogRect(hDlg, &Units);

    /* 96 DPI pixels, scaled by the height of the dialog font (13 pixels for 8 point Tahoma) */
    const int Base = Units.top;
#define PX(n) MulDiv((n), Base, 13)
    const int Margin = PX(10), ClientWidth = PX(356), TextWidthPx = ClientWidth - 2 * Margin;
    const int ButtonHeight = PX(23), ButtonGap = PX(7), ButtonPad = PX(12), MinButton = PX(75);
    const int Expander = PX(19);

    HWND hInstruction = GetDlgItem(hDlg, IDC_CRASH_INSTRUCTION);
    HWND hContent = GetDlgItem(hDlg, IDC_CRASH_CONTENT);
    int y = Margin + PX(4);

    int h = TextHeight(hInstruction, Dlg->BoldFont, Dlg->Instruction.c_str(), TextWidthPx);
    SetWindowPos(hInstruction, NULL, Margin, y, TextWidthPx, h, SWP_NOZORDER);
    y += h + PX(12);

    h = TextHeight(hContent, hFont, Dlg->Content.c_str(), TextWidthPx);
    SetWindowPos(hContent, NULL, Margin, y, TextWidthPx, h, SWP_NOZORDER);
    y += h + PX(22);

    /* Buttons on the right, from the right edge */
    int x = ClientWidth - Margin;
    static const UINT Buttons[] = { IDC_CRASH_CLOSE, IDC_CRASH_DEBUG };
    for (size_t n = 0; n < _countof(Buttons); ++n)
    {
        HWND hButton = GetDlgItem(hDlg, Buttons[n]);
        /* The dialog itself is not visible yet */
        if (!(GetWindowLongW(hButton, GWL_STYLE) & WS_VISIBLE))
            continue;
        WCHAR Text[64];
        GetWindowTextW(hButton, Text, _countof(Text));
        int w = std::max(MinButton, TextWidth(hButton, hFont, Text) + 2 * ButtonPad);
        x -= w;
        SetWindowPos(hButton, NULL, x, y, w, ButtonHeight, SWP_NOZORDER);
        x -= ButtonGap;
    }

    /* The expander and its label on the left of the same row */
    HWND hExpander = GetDlgItem(hDlg, IDC_CRASH_EXPANDER);
    HWND hLabel = GetDlgItem(hDlg, IDC_CRASH_EXPANDER_LABEL);
    int LabelWidth = std::max(TextWidth(hLabel, hFont, LoadResString(IDS_CRASH_SHOW_DETAILS).c_str()),
                              TextWidth(hLabel, hFont, LoadResString(IDS_CRASH_HIDE_DETAILS).c_str())) + PX(4);
    int LabelHeight = TextHeight(hLabel, hFont, L"X", LabelWidth);
    SetWindowPos(hExpander, NULL, Margin, y + (ButtonHeight - Expander) / 2, Expander, Expander, SWP_NOZORDER);
    SetWindowPos(hLabel, NULL, Margin + Expander + PX(6), y + (ButtonHeight - LabelHeight) / 2,
                 LabelWidth, LabelHeight, SWP_NOZORDER);
    y += ButtonHeight + Margin;
    int Collapsed = y;

    /* The details below */
    int DetailsHeight = PX(176);
    SetWindowPos(GetDlgItem(hDlg, IDC_CRASH_DETAILS), NULL, Margin, y, TextWidthPx, DetailsHeight, SWP_NOZORDER);
    int Expanded = y + DetailsHeight + Margin;
#undef PX

    /* Window sizes for the two client heights */
    DWORD Style = GetWindowLongW(hDlg, GWL_STYLE), ExStyle = GetWindowLongW(hDlg, GWL_EXSTYLE);
    RECT rc = { 0, 0, ClientWidth, Collapsed };
    AdjustWindowRectEx(&rc, Style, FALSE, ExStyle);
    Dlg->CollapsedHeight = rc.bottom - rc.top;
    SetRect(&rc, 0, 0, ClientWidth, Expanded);
    AdjustWindowRectEx(&rc, Style, FALSE, ExStyle);
    Dlg->ExpandedHeight = rc.bottom - rc.top;

    SetWindowPos(hDlg, NULL, 0, 0, rc.right - rc.left, Dlg->CollapsedHeight, SWP_NOMOVE | SWP_NOZORDER);
}

static void CenterOnWorkArea(HWND hDlg)
{
    RECT Work, rc;
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &Work, 0);
    GetWindowRect(hDlg, &rc);
    SetWindowPos(hDlg, NULL,
                 Work.left + ((Work.right - Work.left) - (rc.right - rc.left)) / 2,
                 Work.top + ((Work.bottom - Work.top) - (rc.bottom - rc.top)) / 3,
                 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

/* Ctrl+C copies the dialog as text, like a Windows task dialog */
static void CopyToClipboard(HWND hDlg, CrashDialogData* Dlg)
{
    std::wstring Text = L"[Window Title]\r\n" + Dlg->ProgramName +
                        L"\r\n\r\n[Main Instruction]\r\n" + Dlg->Instruction +
                        L"\r\n\r\n[Content]\r\n" + Dlg->Content + L"\r\n\r\n";
    if (Dlg->Expanded)
        Text += L"[Expanded Information]\r\n" + Dlg->Details + L"\r\n\r\n";
    Text += Dlg->Expanded ? L"[^] " : L"[V] ";
    Text += LoadResString(Dlg->Expanded ? IDS_CRASH_HIDE_DETAILS : IDS_CRASH_SHOW_DETAILS) + L" ";
    static const UINT Buttons[] = { IDC_CRASH_DEBUG, IDC_CRASH_CLOSE };
    for (size_t n = 0; n < _countof(Buttons); ++n)
    {
        HWND hButton = GetDlgItem(hDlg, Buttons[n]);
        WCHAR Label[64], Plain[64];
        size_t k = 0;
        if (!(GetWindowLongW(hButton, GWL_STYLE) & WS_VISIBLE))
            continue;
        GetWindowTextW(hButton, Label, _countof(Label));
        for (size_t i = 0; Label[i] && k + 1 < _countof(Plain); ++i)
        {
            if (Label[i] == L'&' && Label[i + 1] != L'&')
                continue;
            Plain[k++] = Label[i];
        }
        Plain[k] = UNICODE_NULL;
        Text += L" [";
        Text += Plain;
        Text += L"]";
    }

    if (!OpenClipboard(hDlg))
        return;
    EmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (Text.size() + 1) * sizeof(WCHAR));
    LPWSTR Buffer = hMem ? (LPWSTR)GlobalLock(hMem) : NULL;
    if (Buffer)
    {
        memcpy(Buffer, Text.c_str(), (Text.size() + 1) * sizeof(WCHAR));
        GlobalUnlock(hMem);
        if (!SetClipboardData(CF_UNICODETEXT, hMem))
            GlobalFree(hMem);
    }
    else if (hMem)
    {
        GlobalFree(hMem);
    }
    CloseClipboard();
}

static void DrawExpander(const DRAWITEMSTRUCT* Item, const CrashDialogData* Dlg)
{
    UINT State = Dlg->Expanded ? DFCS_SCROLLUP : DFCS_SCROLLDOWN;
    if (Item->itemState & ODS_SELECTED)
        State |= DFCS_PUSHED;
    RECT rc = Item->rcItem;
    DrawFrameControl(Item->hDC, &rc, DFC_SCROLL, State);
    if (Item->itemState & ODS_FOCUS)
    {
        InflateRect(&rc, -3, -3);
        DrawFocusRect(Item->hDC, &rc);
    }
}

static HWND CrashDialog;

static LRESULT CALLBACK CopyKeyHook(int Code, WPARAM wParam, LPARAM lParam)
{
    MSG* Msg = (MSG*)lParam;
    if (Code == MSGF_DIALOGBOX && CrashDialog && Msg->message == WM_KEYDOWN && Msg->wParam == 'C' &&
        (GetKeyState(VK_CONTROL) & 0x8000) && (Msg->hwnd == CrashDialog || IsChild(CrashDialog, Msg->hwnd)))
    {
        /* The details box copies its own selection */
        if (Msg->hwnd != GetDlgItem(CrashDialog, IDC_CRASH_DETAILS))
        {
            SendMessageW(CrashDialog, WM_COMMAND, IDC_CRASH_COPY, 0);
            return TRUE;
        }
    }
    return CallNextHookEx(NULL, Code, wParam, lParam);
}

static INT_PTR CALLBACK CrashDialogProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    CrashDialogData* Dlg = (CrashDialogData*)GetWindowLongPtrW(hDlg, DWLP_USER);

    switch (Msg)
    {
        case WM_INITDIALOG:
        {
            Dlg = (CrashDialogData*)lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, (LONG_PTR)Dlg);
            CrashDialog = hDlg;

            LOGFONTW lf;
            HFONT hFont = (HFONT)SendMessageW(hDlg, WM_GETFONT, 0, 0);
            GetObjectW(hFont, sizeof(lf), &lf);
            lf.lfWeight = FW_BOLD;
            Dlg->BoldFont = CreateFontIndirectW(&lf);

            SetWindowTextW(hDlg, Dlg->ProgramName.c_str());
            SetDlgItemTextW(hDlg, IDC_CRASH_INSTRUCTION, Dlg->Instruction.c_str());
            SendDlgItemMessageW(hDlg, IDC_CRASH_INSTRUCTION, WM_SETFONT, (WPARAM)Dlg->BoldFont, FALSE);
            SetDlgItemTextW(hDlg, IDC_CRASH_CONTENT, Dlg->Content.c_str());
            SetDlgItemTextW(hDlg, IDC_CRASH_DETAILS, Dlg->Details.c_str());
            {
                /* Values line up after the longest label */
                INT TabStop = 100;
                SendDlgItemMessageW(hDlg, IDC_CRASH_DETAILS, EM_SETTABSTOPS, 1, (LPARAM)&TabStop);
            }

            if (ExtractIconExW(Dlg->Data->ProcessPath.c_str(), 0, &Dlg->LargeIcon, &Dlg->SmallIcon, 1) == 0)
            {
                Dlg->LargeIcon = NULL;
                Dlg->SmallIcon = NULL;
            }
            SendMessageW(hDlg, WM_SETICON, ICON_BIG,
                         (LPARAM)(Dlg->LargeIcon ? Dlg->LargeIcon : LoadIconW(NULL, IDI_APPLICATION)));
            SendMessageW(hDlg, WM_SETICON, ICON_SMALL,
                         (LPARAM)(Dlg->SmallIcon ? Dlg->SmallIcon : LoadIconW(NULL, IDI_APPLICATION)));

            /* Close program is the default, as in the Windows 7 dialogs with this text */
            HWND hDefault = GetDlgItem(hDlg, IDC_CRASH_CLOSE);
            if (!Dlg->OfferDebug)
            {
                ShowWindow(GetDlgItem(hDlg, IDC_CRASH_DEBUG), SW_HIDE);
                EnableWindow(GetDlgItem(hDlg, IDC_CRASH_DEBUG), FALSE);
            }
            SendMessageW(hDlg, DM_SETDEFID, GetDlgCtrlID(hDefault), 0);
            SendMessageW(hDefault, BM_SETSTYLE, BS_DEFPUSHBUTTON, TRUE);

            Layout(hDlg, Dlg);
            SetExpanded(hDlg, Dlg, false);
            CenterOnWorkArea(hDlg);

            /* Nothing to answer once the program is gone, for example ended from Task Manager */
            SetTimer(hDlg, CHECK_PROCESS_TIMER, 500, NULL);

            SetForegroundWindow(hDlg);
            PostMessageW(hDlg, WM_NEXTDLGCTL, (WPARAM)hDefault, TRUE);
            return FALSE;
        }

        case WM_TIMER:
            if (wParam == CHECK_PROCESS_TIMER &&
                WaitForSingleObject(Dlg->Data->ProcessHandle, 0) == WAIT_OBJECT_0)
            {
                EndDialog(hDlg, CRASH_REPORTER_CLOSE);
            }
            return TRUE;

        case WM_DRAWITEM:
            if (wParam == IDC_CRASH_EXPANDER)
            {
                DrawExpander((const DRAWITEMSTRUCT*)lParam, Dlg);
                return TRUE;
            }
            break;

        case WM_CTLCOLORSTATIC:
            /* The read-only details box stays white, as on Windows */
            if ((HWND)lParam == GetDlgItem(hDlg, IDC_CRASH_DETAILS))
            {
                SetBkColor((HDC)wParam, GetSysColor(COLOR_WINDOW));
                SetTextColor((HDC)wParam, GetSysColor(COLOR_WINDOWTEXT));
                return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);
            }
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_CRASH_EXPANDER:
                case IDC_CRASH_EXPANDER_LABEL:
                    if (HIWORD(wParam) == BN_CLICKED || HIWORD(wParam) == STN_CLICKED)
                        SetExpanded(hDlg, Dlg, !Dlg->Expanded);
                    return TRUE;

                case IDC_CRASH_DEBUG:
                    if (Dlg->OfferDebug)
                        EndDialog(hDlg, CRASH_REPORTER_DEBUG);
                    return TRUE;

                case IDC_CRASH_CLOSE:
                case IDCANCEL:
                    EndDialog(hDlg, CRASH_REPORTER_CLOSE);
                    return TRUE;

                case IDC_CRASH_COPY:
                    CopyToClipboard(hDlg, Dlg);
                    return TRUE;
            }
            break;

        case WM_DESTROY:
            KillTimer(hDlg, CHECK_PROCESS_TIMER);
            CrashDialog = NULL;
            break;
    }
    return FALSE;
}

/*
 * Returns CRASH_REPORTER_CLOSE or CRASH_REPORTER_DEBUG, or another value when
 * no dialog could be shown, so that kernel32 falls back to the hard error box.
 */
int ShowCrashDialog(DumpData& data, const ProblemSignature& Signature, LPCWSTR DumpPath, LPCWSTR ReportPath,
                    bool OfferDebug)
{
    /* As on Windows, without a dialog the program is closed and no debugger is offered */
    if (!CanShowUi())
        return CRASH_REPORTER_CLOSE;

    CrashDialogData Dlg;
    Dlg.Data = &data;
    Dlg.Signature = &Signature;
    Dlg.DumpPath = DumpPath;
    Dlg.ReportPath = ReportPath;
    Dlg.OfferDebug = OfferDebug;
    Dlg.BoldFont = NULL;
    Dlg.SmallIcon = NULL;
    Dlg.LargeIcon = NULL;
    Dlg.Expanded = false;
    Dlg.CollapsedHeight = Dlg.ExpandedHeight = 0;
    BuildTexts(&Dlg);

    /* Ctrl+C reaches the focused control, not the dialog: watch the dialog's message loop */
    HHOOK hHook = SetWindowsHookExW(WH_MSGFILTER, CopyKeyHook, NULL, GetCurrentThreadId());
    INT_PTR Result = DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_CRASH), NULL,
                                     CrashDialogProc, (LPARAM)&Dlg);
    if (hHook)
        UnhookWindowsHookEx(hHook);
    if (Result != CRASH_REPORTER_CLOSE && Result != CRASH_REPORTER_DEBUG)
        Result = 5;

    if (Dlg.BoldFont)
        DeleteObject(Dlg.BoldFont);
    if (Dlg.SmallIcon)
        DestroyIcon(Dlg.SmallIcon);
    if (Dlg.LargeIcon)
        DestroyIcon(Dlg.LargeIcon);
    return (int)Result;
}
