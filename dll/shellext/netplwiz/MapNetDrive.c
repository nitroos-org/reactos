/*
 * PROJECT:     NitroOS Shell
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The Map Network Drive dialog (WNetConnectionDialog)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "netplwiz.h"
#include <wincred.h>
#include <wine/debug.h>

WINE_DEFAULT_DEBUG_CHANNEL(netplwiz);

typedef DWORD (WINAPI *PFN_CREDUI_PROMPT)(PCREDUI_INFOW, PCWSTR, PVOID, DWORD, PWSTR, ULONG, PWSTR, ULONG, BOOL *, DWORD);

typedef struct _MAP_CONTEXT
{
    LPCWSTR InitialRemote;
    WCHAR Connected[3];
} MAP_CONTEXT, *PMAP_CONTEXT;

static VOID
FillDrives(HWND hDlg)
{
    HWND hCombo = GetDlgItem(hDlg, IDC_MAPDRIVE);
    DWORD Used = GetLogicalDrives();
    WCHAR Name[3] = L"?:";
    INT Letter;

    /* Free letters from Z: down, the first one selected (as Windows offers them) */
    for (Letter = 'Z'; Letter >= 'D'; Letter--)
    {
        if (Used & (1UL << (Letter - 'A')))
            continue;
        Name[0] = (WCHAR)Letter;
        SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)Name);
    }
    SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
}

static VOID
ShowError(HWND hDlg, LPCWSTR Folder, DWORD Error)
{
    WCHAR Caption[64], Text[1024];
    PWSTR Message = NULL;

    LoadStringW(hInstance, IDS_MAP_CAPTION, Caption, _countof(Caption));
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                   Error, 0, (LPWSTR)&Message, 0, NULL);
    StringCchPrintfW(Text, _countof(Text), L"%s\n\n%s", Folder, Message ? Message : L"");
    MessageBoxW(hDlg, Text, Caption, MB_OK | MB_ICONERROR);
    if (Message)
        LocalFree(Message);
}

static BOOL
Connect(HWND hDlg, PMAP_CONTEXT Context)
{
    WCHAR Drive[3], Folder[MAX_PATH], User[CREDUI_MAX_USERNAME_LENGTH + 1], Password[CREDUI_MAX_PASSWORD_LENGTH + 1];
    BOOL Reconnect, OtherCredentials, Save = FALSE;
    NETRESOURCEW Resource;
    DWORD Flags, Error;
    INT Index;

    Index = (INT)SendDlgItemMessageW(hDlg, IDC_MAPDRIVE, CB_GETCURSEL, 0, 0);
    if (Index == CB_ERR || SendDlgItemMessageW(hDlg, IDC_MAPDRIVE, CB_GETLBTEXT, Index, (LPARAM)Drive) == CB_ERR)
        return FALSE;
    GetDlgItemTextW(hDlg, IDC_MAPFOLDER, Folder, _countof(Folder));
    if (Folder[0] != L'\\' || Folder[1] != L'\\' || !Folder[2])
    {
        ShowError(hDlg, Folder, ERROR_BAD_NET_NAME);
        return FALSE;
    }
    Reconnect = IsDlgButtonChecked(hDlg, IDC_MAPRECONNECT) == BST_CHECKED;
    OtherCredentials = IsDlgButtonChecked(hDlg, IDC_MAPCREDS) == BST_CHECKED;

    User[0] = 0;
    Password[0] = 0;
    if (OtherCredentials)
    {
        HMODULE hCredUI = LoadLibraryW(L"credui.dll");
        PFN_CREDUI_PROMPT Prompt = hCredUI ? (PFN_CREDUI_PROMPT)GetProcAddress(hCredUI, "CredUIPromptForCredentialsW") : NULL;
        CREDUI_INFOW Info;
        WCHAR Server[MAX_PATH];
        PWCHAR p;
        DWORD r = ERROR_CANCELLED;

        StringCchCopyW(Server, _countof(Server), Folder + 2);
        p = wcschr(Server, L'\\');
        if (p)
            *p = 0;
        ZeroMemory(&Info, sizeof(Info));
        Info.cbSize = sizeof(Info);
        Info.hwndParent = hDlg;
        if (Prompt)
            r = Prompt(&Info, Server, NULL, 0, User, _countof(User), Password, _countof(Password), &Save,
                       CREDUI_FLAGS_DO_NOT_PERSIST | CREDUI_FLAGS_EXCLUDE_CERTIFICATES);
        if (hCredUI)
            FreeLibrary(hCredUI);
        if (r != NO_ERROR)
        {
            SecureZeroMemory(Password, sizeof(Password));
            if (r != ERROR_CANCELLED)
                ShowError(hDlg, Folder, r);
            return FALSE;
        }
    }

    ZeroMemory(&Resource, sizeof(Resource));
    Resource.dwType = RESOURCETYPE_DISK;
    Resource.lpLocalName = Drive;
    Resource.lpRemoteName = Folder;
    /* CONNECT_INTERACTIVE: mpr asks for other credentials when these are refused */
    Flags = CONNECT_INTERACTIVE | (Reconnect ? CONNECT_UPDATE_PROFILE : 0);
    SetCursor(LoadCursorW(NULL, (LPCWSTR)IDC_WAIT));
    Error = WNetUseConnectionW(hDlg, &Resource, OtherCredentials ? Password : NULL, OtherCredentials ? User : NULL,
                               Flags, NULL, NULL, NULL);
    SetCursor(LoadCursorW(NULL, (LPCWSTR)IDC_ARROW));
    SecureZeroMemory(Password, sizeof(Password));
    if (Error != NO_ERROR)
    {
        if (Error != ERROR_CANCELLED)
            ShowError(hDlg, Folder, Error);
        return FALSE;
    }
    StringCchCopyW(Context->Connected, _countof(Context->Connected), Drive);
    return TRUE;
}

static INT_PTR CALLBACK
MapDlgProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    PMAP_CONTEXT Context = (PMAP_CONTEXT)GetWindowLongPtrW(hDlg, DWLP_USER);

    switch (Msg)
    {
        case WM_INITDIALOG:
            Context = (PMAP_CONTEXT)lParam;
            SetWindowLongPtrW(hDlg, DWLP_USER, lParam);
            FillDrives(hDlg);
            SendDlgItemMessageW(hDlg, IDC_MAPFOLDER, EM_LIMITTEXT, MAX_PATH - 1, 0);
            if (Context->InitialRemote)
                SetDlgItemTextW(hDlg, IDC_MAPFOLDER, Context->InitialRemote);
            CheckDlgButton(hDlg, IDC_MAPRECONNECT, BST_CHECKED);
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    if (Connect(hDlg, Context))
                        EndDialog(hDlg, IDOK);
                    return TRUE;
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
            }
            break;
    }
    return FALSE;
}

/*
 * The dialog of WNetConnectionDialog/WNetConnectionDialog1 (mpr calls it): WN_SUCCESS and the
 * connected drive opened in a window, or (DWORD)-1 when the user cancels.
 */
DWORD WINAPI
NitroMapNetworkDriveDialog(HWND hwndOwner, LPCWSTR lpRemoteName, LPWSTR lpDrive, DWORD cchDrive)
{
    MAP_CONTEXT Context;
    INT_PTR Result;

    ZeroMemory(&Context, sizeof(Context));
    Context.InitialRemote = lpRemoteName;
    Result = DialogBoxParamW(hInstance, MAKEINTRESOURCEW(IDD_MAPNETDRIVE), hwndOwner, MapDlgProc, (LPARAM)&Context);
    if (Result != IDOK)
        return (DWORD)-1;
    if (lpDrive && cchDrive)
        StringCchCopyW(lpDrive, cchDrive, Context.Connected);
    return NO_ERROR;
}
