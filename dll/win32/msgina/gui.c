/*
 * PROJECT:         ReactOS msgina.dll
 * FILE:            dll/win32/msgina/gui.c
 * PURPOSE:         ReactOS Logon GINA DLL
 * PROGRAMMERS:     Hervé Poussineau (hpoussin@reactos.org)
 *                  Katayama Hirofumi MZ (katayama.hirofumi.mz@gmail.com)
 */

#include "msgina.h"

#include <wingdi.h>
#include <winnls.h>
#include <ndk/exfuncs.h>
#include <reactos/rosbrand.h>

typedef struct _DISPLAYSTATUSMSG
{
    PGINA_CONTEXT Context;
    HDESK hDesktop;
    DWORD dwOptions;
    PWSTR pTitle;
    PWSTR pMessage;
    HANDLE StartupEvent;
} DISPLAYSTATUSMSG, *PDISPLAYSTATUSMSG;

typedef struct _LEGALNOTICEDATA
{
    LPWSTR pszCaption;
    LPWSTR pszText;
} LEGALNOTICEDATA, *PLEGALNOTICEDATA;

// Timer ID for the animated dialog bar.
#define IDT_BAR 1

#define ISKEYDOWN(x) (GetKeyState(x) & 0x8000)

typedef struct _DLG_DATA
{
    PGINA_CONTEXT pgContext;
    HWND hWndBarCtrl;
    DWORD BarCounter;
} DLG_DATA, *PDLG_DATA;

HBITMAP hBanner = NULL;
HBITMAP hBannerLine = NULL;

static PDLG_DATA
DlgData_Create(HWND hwndDlg, PGINA_CONTEXT pgContext)
{
    PDLG_DATA pDlgData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*pDlgData));
    if (pDlgData)
    {
        pDlgData->pgContext = pgContext;
        SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)pDlgData);
    }
    return pDlgData;
}

static VOID
DlgData_Destroy(_Inout_ HWND hwndDlg)
{
    PDLG_DATA pDlgData;

    pDlgData = (PDLG_DATA)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);
    if (!pDlgData)
    {
        return;
    }

    SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)NULL);

    HeapFree(GetProcessHeap(), 0, pDlgData);
}

static VOID
LoadBrandingBitmaps(VOID)
{
    HMODULE hBrand = LoadLibraryExW(L"rosbrand.dll", NULL, LOAD_LIBRARY_AS_DATAFILE);

    if (!hBrand)
        return;

    hBanner = LoadImageW(hBrand,
                         MAKEINTRESOURCEW(IDB_BRAND_BANNER),
                         IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);

    hBannerLine = LoadImageW(hBrand,
                             MAKEINTRESOURCEW(IDB_BRAND_BANNERLINE),
                             IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);

    FreeLibrary(hBrand);
}

BOOL
DrawBrandingBitmap(
    _Inout_ LPDRAWITEMSTRUCT DrawItem,
    _Inout_ HBITMAP *BitmapHandle)
{
    HGDIOBJ hOld;
    HDC hdcMem;
    BITMAP bm;

    if (!*BitmapHandle)
    {
        LoadBrandingBitmaps();
        if (!*BitmapHandle)
            return FALSE;
    }

    hdcMem = CreateCompatibleDC(DrawItem->hDC);
    if (!hdcMem)
        return FALSE;

    GetObject(*BitmapHandle, sizeof(bm), &bm);
    hOld = SelectObject(hdcMem, *BitmapHandle);
    BitBlt(DrawItem->hDC, 0, 0, bm.bmWidth, bm.bmHeight, hdcMem, 0, 0, SRCCOPY);
    SelectObject(hdcMem, hOld);
    DeleteDC(hdcMem);
    return TRUE;
}

BOOL
DrawScrollingBrandingBitmap(
    _Inout_ LPDRAWITEMSTRUCT DrawItem,
    _Inout_ HBITMAP *BitmapHandle,
    _In_ PDWORD ScrollCounter
)
{
    HGDIOBJ hOld;
    HDC hdcMem;
    BITMAP bm;

    if (!*BitmapHandle)
    {
        LoadBrandingBitmaps();
        if (!*BitmapHandle)
            return FALSE;
    }

    if (GetObject(*BitmapHandle, sizeof(bm), &bm) != sizeof(bm))
        return FALSE;

    hdcMem = CreateCompatibleDC(DrawItem->hDC);
    if (!hdcMem)
        return FALSE;

    *ScrollCounter %= bm.bmWidth;
    hOld = SelectObject(hdcMem, *BitmapHandle);
    BitBlt(DrawItem->hDC, *ScrollCounter, 0, bm.bmWidth - *ScrollCounter, bm.bmHeight, hdcMem, 0, 0, SRCCOPY);
    BitBlt(DrawItem->hDC, 0, 0, *ScrollCounter, bm.bmHeight, hdcMem, bm.bmWidth - *ScrollCounter, 0, SRCCOPY);
    SelectObject(hdcMem, hOld);
    DeleteDC(hdcMem);
    return TRUE;
}

static BOOL
GUIInitialize(
    IN OUT PGINA_CONTEXT pgContext)
{
    TRACE("GUIInitialize(%p)\n", pgContext);
    return TRUE;
}

static
VOID
SetWelcomeText(HWND hWnd)
{
    PWCHAR pBuffer = NULL, p;
    HKEY hKey;
    DWORD BufSize, dwType, dwWelcomeSize, dwTitleLength;
    LONG rc;

    /* Open the Winlogon key */
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                       0,
                       KEY_QUERY_VALUE,
                       &hKey);
    if (rc != ERROR_SUCCESS)
    {
        WARN("RegOpenKeyExW() failed with error %lu\n", rc);
        return;
    }

    /* Get the size of the Welcome value */
    dwWelcomeSize = 0;
    rc = RegQueryValueExW(hKey,
                          L"Welcome",
                          NULL,
                          &dwType,
                          NULL,
                          &dwWelcomeSize);
    if (rc == ERROR_FILE_NOT_FOUND || dwWelcomeSize == 0 || dwType != REG_SZ)
        goto done;

    dwTitleLength = GetWindowTextLengthW(hWnd);
    BufSize = dwWelcomeSize + ((dwTitleLength + 1) * sizeof(WCHAR));

    pBuffer = HeapAlloc(GetProcessHeap(), 0, BufSize);
    if (pBuffer == NULL)
        goto done;

    GetWindowTextW(hWnd, pBuffer, BufSize / sizeof(WCHAR));
    wcscat(pBuffer, L" ");
    p = &pBuffer[dwTitleLength + 1];

    RegQueryValueExW(hKey,
                     L"Welcome",
                     NULL,
                     &dwType,
                     (PBYTE)p,
                     &dwWelcomeSize);

    SetWindowText(hWnd, pBuffer);

done:
    if (pBuffer != NULL)
        HeapFree(GetProcessHeap(), 0, pBuffer);

    RegCloseKey(hKey);
}

static VOID
AdjustStatusMessageWindow(HWND hwndDlg)
{
    INT xOld, yOld, cxOld, cyOld;
    INT xNew, yNew, cxNew, cyNew;
    INT cxLabel, cyLabel, dyLabel;
    RECT rc, rcBar, rcLabel, rcWnd;
    BITMAP bmLogo, bmBar;
    DWORD style, exstyle;
    HWND hwndLogo = GetDlgItem(hwndDlg, IDC_ROSLOGO);
    HWND hwndBar = GetDlgItem(hwndDlg, IDC_BAR);
    HWND hwndLabel = GetDlgItem(hwndDlg, IDC_STATUS_MESSAGE);

    /* This adjustment is for CJK only */
    switch (PRIMARYLANGID(GetUserDefaultLangID()))
    {
        case LANG_CHINESE:
        case LANG_JAPANESE:
        case LANG_KOREAN:
            break;

        default:
            return;
    }

    if (!GetObjectW(hBanner, sizeof(BITMAP), &bmLogo) ||
        !GetObjectW(hBannerLine, sizeof(BITMAP), &bmBar))
    {
        return;
    }

    GetWindowRect(hwndBar, &rcBar);
    MapWindowPoints(NULL, hwndDlg, (LPPOINT)&rcBar, 2);
    dyLabel = bmLogo.bmHeight - rcBar.top;

    GetWindowRect(hwndLabel, &rcLabel);
    MapWindowPoints(NULL, hwndDlg, (LPPOINT)&rcLabel, 2);
    cxLabel = rcLabel.right - rcLabel.left;
    cyLabel = rcLabel.bottom - rcLabel.top;

    MoveWindow(hwndLogo, 0, 0, bmLogo.bmWidth, bmLogo.bmHeight, TRUE);
    MoveWindow(hwndBar, 0, bmLogo.bmHeight, bmLogo.bmWidth, bmBar.bmHeight, TRUE);
    MoveWindow(hwndLabel, rcLabel.left, rcLabel.top + dyLabel, cxLabel, cyLabel, TRUE);

    GetWindowRect(hwndDlg, &rcWnd);
    xOld = rcWnd.left;
    yOld = rcWnd.top;
    cxOld = rcWnd.right - rcWnd.left;
    cyOld = rcWnd.bottom - rcWnd.top;

    GetClientRect(hwndDlg, &rc);
    SetRect(&rc, 0, 0, bmLogo.bmWidth, rc.bottom - rc.top); /* new client size */

    style = (DWORD)GetWindowLongPtrW(hwndDlg, GWL_STYLE);
    exstyle = (DWORD)GetWindowLongPtrW(hwndDlg, GWL_EXSTYLE);
    AdjustWindowRectEx(&rc, style, FALSE, exstyle);

    cxNew = rc.right - rc.left;
    cyNew = (rc.bottom - rc.top) + dyLabel;
    xNew = xOld - (cxNew - cxOld) / 2;
    yNew = yOld - (cyNew - cyOld) / 2;
    MoveWindow(hwndDlg, xNew, yNew, cxNew, cyNew, TRUE);
}

static INT_PTR CALLBACK
StatusDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    PDLG_DATA pDlgData;
    UNREFERENCED_PARAMETER(wParam);

    pDlgData = (PDLG_DATA)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            PDISPLAYSTATUSMSG msg = (PDISPLAYSTATUSMSG)lParam;
            if (!msg)
                return FALSE;

            msg->Context->hStatusWindow = hwndDlg;

            if (msg->pTitle)
                SetWindowTextW(hwndDlg, msg->pTitle);
            SetDlgItemTextW(hwndDlg, IDC_STATUS_MESSAGE, msg->pMessage);
            SetEvent(msg->StartupEvent);

            pDlgData = DlgData_Create(hwndDlg, msg->Context);
            if (pDlgData == NULL)
                return FALSE;

            if (hBannerLine)
            {
                if (SetTimer(hwndDlg, IDT_BAR, 20, NULL) == 0)
                {
                    ERR("SetTimer(IDT_BAR) failed: %d\n", GetLastError());
                }
                else
                {
                    /* Get the animation bar control */
                    pDlgData->hWndBarCtrl = GetDlgItem(hwndDlg, IDC_BAR);
                }
            }

            AdjustStatusMessageWindow(hwndDlg);
            return TRUE;
        }

        case WM_TIMER:
        {
            if (pDlgData && hBannerLine)
            {
                /*
                 * Default rotation bar image width is 413 (same as logo)
                 * We can divide 413 by 7 without remainder
                 * DrawScrollingBrandingBitmap() mods BarCounter to image width
                 */
                pDlgData->BarCounter += 7;
                InvalidateRect(pDlgData->hWndBarCtrl, NULL, FALSE);
                UpdateWindow(pDlgData->hWndBarCtrl);
            }
            return TRUE;
        }

        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
            {
                return DrawBrandingBitmap(lpDis, &hBanner);
            }
            if (lpDis->CtlID == IDC_BAR)
            {
                return DrawScrollingBrandingBitmap(lpDis,
                                                   &hBannerLine,
                                                   &(pDlgData->BarCounter));
            }
            return FALSE;
        }

        case WM_DESTROY:
        {
            if (pDlgData && hBannerLine)
            {
                KillTimer(hwndDlg, IDT_BAR);
            }
            DlgData_Destroy(hwndDlg);
            return TRUE;
        }
    }
    return FALSE;
}

static DWORD WINAPI
StartupWindowThread(LPVOID lpParam)
{
    PDISPLAYSTATUSMSG msg = (PDISPLAYSTATUSMSG)lpParam;

    /* SetThreadDesktop neither closes the handle it is given nor takes ownership of it, and
       the desktop handles of Winlogon live as long as Winlogon runs, so the thread uses the
       handle it is passed. (A duplicate of it was never closed: three handles leaked for
       every logon and logoff, one for each status window thread.) */
    if(!SetThreadDesktop(msg->hDesktop))
    {
        ERR("Setting thread desktop failed!\n");
        HeapFree(GetProcessHeap(), 0, lpParam);
        return FALSE;
    }

    DialogBoxParamW(
        hDllInstance,
        MAKEINTRESOURCEW(IDD_STATUS),
        GetDesktopWindow(),
        StatusDialogProc,
        (LPARAM)lpParam);

    HeapFree(GetProcessHeap(), 0, lpParam);
    return TRUE;
}

static BOOL
GUIDisplayStatusMessage(
    IN PGINA_CONTEXT pgContext,
    IN HDESK hDesktop,
    IN DWORD dwOptions,
    IN PWSTR pTitle,
    IN PWSTR pMessage)
{
    PDISPLAYSTATUSMSG msg;
    HANDLE Thread;
    DWORD ThreadId;

    TRACE("GUIDisplayStatusMessage(%ws)\n", pMessage);

    if (!pgContext->hStatusWindow)
    {
        /*
         * If everything goes correctly, 'msg' is freed
         * by the 'StartupWindowThread' thread.
         */
        msg = (PDISPLAYSTATUSMSG)HeapAlloc(GetProcessHeap(),
                                           HEAP_ZERO_MEMORY,
                                           sizeof(*msg));
        if(!msg)
            return FALSE;

        msg->Context = pgContext;
        msg->dwOptions = dwOptions;
        msg->pTitle = pTitle;
        msg->pMessage = pMessage;
        msg->hDesktop = hDesktop;

        msg->StartupEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

        if (!msg->StartupEvent)
        {
            HeapFree(GetProcessHeap(), 0, msg);
            return FALSE;
        }

        Thread = CreateThread(NULL,
                              0,
                              StartupWindowThread,
                              (PVOID)msg,
                              0,
                              &ThreadId);
        if (Thread)
        {
            /* 'msg' will be freed by 'StartupWindowThread' */

            CloseHandle(Thread);
            WaitForSingleObject(msg->StartupEvent, INFINITE);
            CloseHandle(msg->StartupEvent);
            return TRUE;
        }
        else
        {
            /*
             * The 'StartupWindowThread' thread couldn't be created,
             * so we need to free the allocated 'msg'.
             */
            HeapFree(GetProcessHeap(), 0, msg);
        }

        return FALSE;
    }

    if (pTitle)
        SetWindowTextW(pgContext->hStatusWindow, pTitle);

    SetDlgItemTextW(pgContext->hStatusWindow, IDC_STATUS_MESSAGE, pMessage);

    return TRUE;
}

static BOOL
GUIRemoveStatusMessage(
    IN PGINA_CONTEXT pgContext)
{
    if (pgContext->hStatusWindow)
    {
        EndDialog(pgContext->hStatusWindow, 0);
        pgContext->hStatusWindow = NULL;
    }

    return TRUE;
}

static INT_PTR CALLBACK
WelcomeDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
            return TRUE;
        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            if (lpDis->CtlID == IDC_BAR)
                return DrawBrandingBitmap(lpDis, &hBannerLine);
            return FALSE;
        }
        case WM_DESTROY:
            return TRUE;
    }
    return FALSE;
}

static VOID
GUIDisplaySASNotice(
    IN OUT PGINA_CONTEXT pgContext)
{
    /* Display the notice window */
    pgContext->pWlxFuncs->WlxDialogBoxParam(pgContext->hWlx,
                                            pgContext->hDllInstance,
                                            MAKEINTRESOURCEW(IDD_WELCOME),
                                            GetDesktopWindow(),
                                            WelcomeDialogProc,
                                            (LPARAM)pgContext);
}

/* Get the text contained in a textbox. Allocates memory in pText
 * to contain the text. Returns TRUE in case of success */
static BOOL
GetTextboxText(
    IN HWND hwndDlg,
    IN INT TextboxId,
    OUT LPWSTR *pText)
{
    LPWSTR Text;
    int Count;

    Count = GetWindowTextLength(GetDlgItem(hwndDlg, TextboxId));
    Text = HeapAlloc(GetProcessHeap(), 0, (Count + 1) * sizeof(WCHAR));
    if (!Text)
        return FALSE;
    if (Count != GetWindowTextW(GetDlgItem(hwndDlg, TextboxId), Text, Count + 1))
    {
        HeapFree(GetProcessHeap(), 0, Text);
        return FALSE;
    }
    *pText = Text;
    return TRUE;
}


static
INT
ResourceMessageBox(
    IN PGINA_CONTEXT pgContext,
    IN HWND hwnd,
    IN UINT uType,
    IN UINT uCaption,
    IN UINT uText)
{
    WCHAR szCaption[256];
    WCHAR szText[256];

    LoadStringW(pgContext->hDllInstance, uCaption, szCaption, _countof(szCaption));
    LoadStringW(pgContext->hDllInstance, uText, szText, _countof(szText));

    return pgContext->pWlxFuncs->WlxMessageBox(pgContext->hWlx,
                                               hwnd,
                                               szText,
                                               szCaption,
                                               uType);
}


static
BOOL
DoChangePassword(
    IN PGINA_CONTEXT pgContext,
    IN HWND hwndDlg)
{
    WCHAR UserName[256];
    WCHAR Domain[256];
    WCHAR OldPassword[256];
    WCHAR NewPassword1[256];
    WCHAR NewPassword2[256];
    PMSV1_0_CHANGEPASSWORD_REQUEST RequestBuffer = NULL;
    PMSV1_0_CHANGEPASSWORD_RESPONSE ResponseBuffer = NULL;
    ULONG RequestBufferSize;
    ULONG ResponseBufferSize = 0;
    LPWSTR Ptr;
    BOOL res = FALSE;
    NTSTATUS ProtocolStatus;
    NTSTATUS Status;

    GetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_USERNAME, UserName, _countof(UserName));
    GetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_DOMAIN, Domain, _countof(Domain));
    GetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_OLDPWD, OldPassword, _countof(OldPassword));
    GetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_NEWPWD1, NewPassword1, _countof(NewPassword1));
    GetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_NEWPWD2, NewPassword2, _countof(NewPassword2));

    /* Compare the two passwords and fail if they do not match */
    if (wcscmp(NewPassword1, NewPassword2) != 0)
    {
        ResourceMessageBox(pgContext,
                           hwndDlg,
                           MB_OK | MB_ICONEXCLAMATION,
                           IDS_CHANGEPWDTITLE,
                           IDS_NONMATCHINGPASSWORDS);
        goto done;
    }

    /* Calculate the request buffer size */
    RequestBufferSize = sizeof(MSV1_0_CHANGEPASSWORD_REQUEST) +
                        ((wcslen(Domain) + 1) * sizeof(WCHAR)) +
                        ((wcslen(UserName) + 1) * sizeof(WCHAR)) +
                        ((wcslen(OldPassword) + 1) * sizeof(WCHAR)) +
                        ((wcslen(NewPassword1) + 1) * sizeof(WCHAR));

    /* Allocate the request buffer */
    RequestBuffer = HeapAlloc(GetProcessHeap(),
                              HEAP_ZERO_MEMORY,
                              RequestBufferSize);
    if (RequestBuffer == NULL)
    {
        ERR("HeapAlloc failed\n");
        goto done;
    }

    /* Initialize the request buffer */
    RequestBuffer->MessageType = MsV1_0ChangePassword;
    RequestBuffer->Impersonating = TRUE;

    Ptr = (LPWSTR)((ULONG_PTR)RequestBuffer + sizeof(MSV1_0_CHANGEPASSWORD_REQUEST));

    /* Pack the domain name */
    RequestBuffer->DomainName.Length = (USHORT)wcslen(Domain) * sizeof(WCHAR);
    RequestBuffer->DomainName.MaximumLength = RequestBuffer->DomainName.Length + sizeof(WCHAR);
    RequestBuffer->DomainName.Buffer = Ptr;

    RtlCopyMemory(RequestBuffer->DomainName.Buffer,
                  Domain,
                  RequestBuffer->DomainName.MaximumLength);

    Ptr = (LPWSTR)((ULONG_PTR)Ptr + RequestBuffer->DomainName.MaximumLength);

    /* Pack the user name */
    RequestBuffer->AccountName.Length = (USHORT)wcslen(UserName) * sizeof(WCHAR);
    RequestBuffer->AccountName.MaximumLength = RequestBuffer->AccountName.Length + sizeof(WCHAR);
    RequestBuffer->AccountName.Buffer = Ptr;

    RtlCopyMemory(RequestBuffer->AccountName.Buffer,
                  UserName,
                  RequestBuffer->AccountName.MaximumLength);

    Ptr = (LPWSTR)((ULONG_PTR)Ptr + RequestBuffer->AccountName.MaximumLength);

    /* Pack the old password */
    RequestBuffer->OldPassword.Length = (USHORT)wcslen(OldPassword) * sizeof(WCHAR);
    RequestBuffer->OldPassword.MaximumLength = RequestBuffer->OldPassword.Length + sizeof(WCHAR);
    RequestBuffer->OldPassword.Buffer = Ptr;

    RtlCopyMemory(RequestBuffer->OldPassword.Buffer,
                  OldPassword,
                  RequestBuffer->OldPassword.MaximumLength);

    Ptr = (LPWSTR)((ULONG_PTR)Ptr + RequestBuffer->OldPassword.MaximumLength);

    /* Pack the new password */
    RequestBuffer->NewPassword.Length = (USHORT)wcslen(NewPassword1) * sizeof(WCHAR);
    RequestBuffer->NewPassword.MaximumLength = RequestBuffer->NewPassword.Length + sizeof(WCHAR);
    RequestBuffer->NewPassword.Buffer = Ptr;

    RtlCopyMemory(RequestBuffer->NewPassword.Buffer,
                  NewPassword1,
                  RequestBuffer->NewPassword.MaximumLength);

    /* Connect to the LSA server */
    if (ConnectToLsa(pgContext) != ERROR_SUCCESS)
    {
        ERR("ConnectToLsa() failed\n");
        goto done;
    }

    /* Call the authentication package */
    Status = LsaCallAuthenticationPackage(pgContext->LsaHandle,
                                          pgContext->AuthenticationPackage,
                                          RequestBuffer,
                                          RequestBufferSize,
                                          (PVOID*)&ResponseBuffer,
                                          &ResponseBufferSize,
                                          &ProtocolStatus);
    if (!NT_SUCCESS(Status))
    {
        ERR("LsaCallAuthenticationPackage failed (Status 0x%08lx)\n", Status);
        goto done;
    }

    if (!NT_SUCCESS(ProtocolStatus))
    {
        TRACE("LsaCallAuthenticationPackage failed (ProtocolStatus 0x%08lx)\n", ProtocolStatus);
        goto done;
    }

    res = TRUE;

    ResourceMessageBox(pgContext,
                       hwndDlg,
                       MB_OK | MB_ICONINFORMATION,
                       IDS_CHANGEPWDTITLE,
                       IDS_PASSWORDCHANGED);

    /* The password change of a logon in progress (the password has expired): the logon is retried with the new one.
       No password is kept for a logged-on session */
    if (pgContext->bLogonInProgress &&
        (wcscmp(UserName, pgContext->UserName) == 0) &&
        (wcscmp(Domain, pgContext->DomainName) == 0) &&
        (wcscmp(OldPassword, pgContext->Password) == 0))
    {
        SecureZeroMemory(pgContext->Password, sizeof(pgContext->Password));
        StringCchCopyW(pgContext->Password, _countof(pgContext->Password), NewPassword1);
    }

done:
    /* Zero out the password buffers */
    SecureZeroMemory(&OldPassword, sizeof(OldPassword));
    SecureZeroMemory(&NewPassword1, sizeof(NewPassword1));
    SecureZeroMemory(&NewPassword2, sizeof(NewPassword2));

    if (RequestBuffer != NULL)
    {
        /* Zero out the password buffers before freeing them */
        SecureZeroMemory(RequestBuffer->OldPassword.Buffer,
                         RequestBuffer->OldPassword.MaximumLength);
        SecureZeroMemory(&RequestBuffer->OldPassword, sizeof(RequestBuffer->OldPassword));
        SecureZeroMemory(RequestBuffer->NewPassword.Buffer,
                         RequestBuffer->NewPassword.MaximumLength);
        SecureZeroMemory(&RequestBuffer->NewPassword, sizeof(RequestBuffer->NewPassword));
        HeapFree(GetProcessHeap(), 0, RequestBuffer);
    }

    if (ResponseBuffer != NULL)
        LsaFreeReturnBuffer(ResponseBuffer);

    return res;
}


static INT_PTR CALLBACK
ChangePasswordDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    PGINA_CONTEXT pgContext;

    pgContext = (PGINA_CONTEXT)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            pgContext = (PGINA_CONTEXT)lParam;
            SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)pgContext);

            SetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_USERNAME, pgContext->UserName);
            SendDlgItemMessageW(hwndDlg, IDC_CHANGEPWD_DOMAIN, CB_ADDSTRING, 0, (LPARAM)pgContext->DomainName);
            SendDlgItemMessageW(hwndDlg, IDC_CHANGEPWD_DOMAIN, CB_SETCURSEL, 0, 0);
            SetFocus(GetDlgItem(hwndDlg, IDC_CHANGEPWD_OLDPWD));
            return FALSE; // Default focus is changed.
        }

        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            /* This dialog doesn't have IDC_BAR */
            return FALSE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    if (DoChangePassword(pgContext, hwndDlg))
                    {
                        EndDialog(hwndDlg, TRUE);
                    }
                    else
                    {
                        SetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_OLDPWD, NULL);
                        SetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_NEWPWD1, NULL);
                        SetDlgItemTextW(hwndDlg, IDC_CHANGEPWD_NEWPWD2, NULL);
                        SendMessageW(hwndDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hwndDlg, IDC_CHANGEPWD_OLDPWD), TRUE);
                    }
                    return TRUE;

                case IDCANCEL:
                    EndDialog(hwndDlg, FALSE);
                    return TRUE;
            }
            break;

        case WM_CLOSE:
            EndDialog(hwndDlg, FALSE);
            return TRUE;
    }

    return FALSE;
}


static VOID
OnInitSecurityDlg(
    _In_ HWND hwnd,
    _In_ PGINA_CONTEXT pgContext)
{
    HKEY hKeyCurrentUser, hKey;
    DWORD dwValue;
    LONG lRet;

    WCHAR Buffer1[256];
    WCHAR Buffer2[256];
    WCHAR Buffer3[256];
    WCHAR Buffer4[512];

    LoadStringW(pgContext->hDllInstance, IDS_LOGONMSG, Buffer1, _countof(Buffer1));

    wsprintfW(Buffer2, L"%s\\%s", pgContext->DomainName, pgContext->UserName);
    wsprintfW(Buffer4, Buffer1, Buffer2);

    SetDlgItemTextW(hwnd, IDC_SECURITY_MESSAGE, Buffer4);

    LoadStringW(pgContext->hDllInstance, IDS_LOGONDATE, Buffer1, _countof(Buffer1));

    GetDateFormatW(LOCALE_USER_DEFAULT, DATE_SHORTDATE,
                   (SYSTEMTIME*)&pgContext->LogonTime, NULL, Buffer2, _countof(Buffer2));

    GetTimeFormatW(LOCALE_USER_DEFAULT, 0,
                   (SYSTEMTIME*)&pgContext->LogonTime, NULL, Buffer3, _countof(Buffer3));

    wsprintfW(Buffer4, Buffer1, Buffer2, Buffer3);

    SetDlgItemTextW(hwnd, IDC_SECURITY_LOGONDATE, Buffer4);

    lRet = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                         0,
                         KEY_QUERY_VALUE, &hKey);
    if (lRet == ERROR_SUCCESS)
    {
        lRet = ReadRegDwordValue(hKey, L"DisableLockWorkstation", &dwValue);
        if ((lRet == ERROR_SUCCESS) && !!dwValue)
            EnableWindow(GetDlgItem(hwnd, IDC_SECURITY_LOCK), FALSE);

        RegCloseKey(hKey);
    }

    /* Open the per-user registry key */
    lRet = RegOpenLoggedOnHKCU(pgContext->UserToken,
                               KEY_QUERY_VALUE,
                               &hKeyCurrentUser);
    if (lRet != ERROR_SUCCESS)
    {
        /* We couldn't, bail out */
        return;
    }

    lRet = RegOpenKeyExW(hKeyCurrentUser,
                         L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                         0,
                         KEY_QUERY_VALUE, &hKey);
    if (lRet == ERROR_SUCCESS)
    {
        lRet = ReadRegDwordValue(hKey, L"DisableLockWorkstation", &dwValue);
        if ((lRet == ERROR_SUCCESS) && !!dwValue)
            EnableWindow(GetDlgItem(hwnd, IDC_SECURITY_LOCK), FALSE);

        lRet = ReadRegDwordValue(hKey, L"DisableChangePassword", &dwValue);
        if ((lRet == ERROR_SUCCESS) && !!dwValue)
            EnableWindow(GetDlgItem(hwnd, IDC_SECURITY_CHANGEPWD), FALSE);

        lRet = ReadRegDwordValue(hKey, L"DisableTaskMgr", &dwValue);
        if ((lRet == ERROR_SUCCESS) && !!dwValue)
            EnableWindow(GetDlgItem(hwnd, IDC_SECURITY_TASKMGR), FALSE);

        RegCloseKey(hKey);
    }

    lRet = RegOpenKeyExW(hKeyCurrentUser,
                         L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                         0,
                         KEY_QUERY_VALUE, &hKey);
    if (lRet == ERROR_SUCCESS)
    {
        lRet = ReadRegDwordValue(hKey, L"NoLogoff", &dwValue);
        if ((lRet == ERROR_SUCCESS) && !!dwValue)
            EnableWindow(GetDlgItem(hwnd, IDC_SECURITY_LOGOFF), FALSE);

        // TODO: Disable also if "NoDisconnect" on Terminal Services
        /* Disable the "Shutdown" button if the user doesn't have shutdown privilege */
        lRet = ReadRegDwordValue(hKey, L"NoClose", &dwValue);
        if (((lRet == ERROR_SUCCESS) && !!dwValue) ||
            !TestTokenPrivilege(pgContext->UserToken, SE_SHUTDOWN_PRIVILEGE))
        {
            EnableWindow(GetDlgItem(hwnd, IDC_SECURITY_SHUTDOWN), FALSE);
        }

        RegCloseKey(hKey);
    }

    RegCloseKey(hKeyCurrentUser);
}


static BOOL
OnChangePassword(
    IN HWND hwnd,
    IN PGINA_CONTEXT pgContext)
{
    INT res;

    TRACE("OnChangePassword()\n");

    res = pgContext->pWlxFuncs->WlxDialogBoxParam(
        pgContext->hWlx,
        pgContext->hDllInstance,
        MAKEINTRESOURCEW(IDD_CHANGEPWD),
        hwnd,
        ChangePasswordDialogProc,
        (LPARAM)pgContext);

    TRACE("Result: %x\n", res);

    return FALSE;
}


static INT_PTR CALLBACK
LogOffDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
            return TRUE;

        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            if (lpDis->CtlID == IDC_BAR)
                return DrawBrandingBitmap(lpDis, &hBannerLine);
            return FALSE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                case IDCANCEL:
                    EndDialog(hwndDlg, LOWORD(wParam));
                    return TRUE;
            }
            break;

        case WM_CLOSE:
            EndDialog(hwndDlg, IDCANCEL);
            return TRUE;
    }

    return FALSE;
}


static
INT
OnLogOff(
    IN HWND hwndDlg,
    IN PGINA_CONTEXT pgContext)
{
    return pgContext->pWlxFuncs->WlxDialogBoxParam(
        pgContext->hWlx,
        pgContext->hDllInstance,
        MAKEINTRESOURCEW(IDD_LOGOFF),
        hwndDlg,
        LogOffDialogProc,
        (LPARAM)pgContext);
}


static
INT
OnShutDown(
    _In_ HWND hwndDlg,
    _In_ PGINA_CONTEXT pgContext,
    _In_ DWORD dwExcludeOptions)
{
    HKEY hKeyCurrentUser = NULL;
    DWORD ShutdownOptions = 0;
    INT ret;

    /* Open the per-user registry key */
    if (RegOpenLoggedOnHKCU(pgContext->UserToken,
                            KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY | KEY_SET_VALUE,
                            &hKeyCurrentUser) != ERROR_SUCCESS)
    {
        ERR("RegOpenLoggedOnHKCU() failed with error %ld\n", GetLastError());
    }
    pgContext->nShutdownAction = 0;
    if (hKeyCurrentUser)
    {
        ShutdownOptions = GetAllowedShutdownOptions(hKeyCurrentUser, pgContext->UserToken);
        pgContext->nShutdownAction = LoadShutdownSelState(hKeyCurrentUser);
    }
    ShutdownOptions &= ~dwExcludeOptions;

    ret = ShutdownDialog(hwndDlg, ShutdownOptions, pgContext);

    if ((ret == IDOK) && hKeyCurrentUser)
        SaveShutdownSelState(hKeyCurrentUser, pgContext->nShutdownAction);

    if (hKeyCurrentUser)
        RegCloseKey(hKeyCurrentUser);

    return ret;
}


static INT_PTR CALLBACK
SecurityDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    PGINA_CONTEXT pgContext;

    pgContext = (PGINA_CONTEXT)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            pgContext = (PGINA_CONTEXT)lParam;
            SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)pgContext);

            SetWelcomeText(hwndDlg);

            OnInitSecurityDlg(hwndDlg, (PGINA_CONTEXT)lParam);
            return TRUE;
        }
        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            /* This dialog doesn't have IDC_BAR */
            return FALSE;
        }
        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case IDC_SECURITY_LOCK:
                    EndDialog(hwndDlg, WLX_SAS_ACTION_LOCK_WKSTA);
                    return TRUE;
                case IDC_SECURITY_LOGOFF:
                    if (ISKEYDOWN(VK_CONTROL))
                    {
                        if (ResourceMessageBox(pgContext,
                                               hwndDlg,
                                               MB_OKCANCEL | MB_ICONSTOP,
                                               IDS_EMERGENCYLOGOFFTITLE,
                                               IDS_EMERGENCYLOGOFF) == IDOK)
                        {
                            EndDialog(hwndDlg, WLX_SAS_ACTION_FORCE_LOGOFF);
                        }
                    }
                    else if (OnLogOff(hwndDlg, pgContext) == IDOK)
                    {
                        EndDialog(hwndDlg, WLX_SAS_ACTION_LOGOFF);
                    }
                    return TRUE;
                case IDC_SECURITY_SHUTDOWN:
                    /* Emergency restart feature */
                    if (ISKEYDOWN(VK_CONTROL))
                    {
                        if (ResourceMessageBox(pgContext,
                                               hwndDlg,
                                               MB_OKCANCEL | MB_ICONSTOP,
                                               IDS_EMERGENCYRESTARTTITLE,
                                               IDS_EMERGENCYRESTART) == IDOK)
                        {
                            BOOLEAN Old;

                            ERR("Emergency restarting NT...\n");
                            RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &Old);
                            NtShutdownSystem(ShutdownReboot);
                            RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, Old, FALSE, &Old);
                        }
                    }
                    else if (OnShutDown(hwndDlg, pgContext, 0) == IDOK)
                    {
                        EndDialog(hwndDlg, pgContext->nShutdownAction);
                    }
                    return TRUE;
                case IDC_SECURITY_CHANGEPWD:
                    if (OnChangePassword(hwndDlg, pgContext))
                        EndDialog(hwndDlg, WLX_SAS_ACTION_PWD_CHANGED);
                    return TRUE;
                case IDC_SECURITY_TASKMGR:
                    EndDialog(hwndDlg, WLX_SAS_ACTION_TASKLIST);
                    return TRUE;
                case IDCANCEL:
                    EndDialog(hwndDlg, WLX_SAS_ACTION_NONE);
                    return TRUE;
            }
            break;
        }
        case WM_CLOSE:
        {
            EndDialog(hwndDlg, WLX_SAS_ACTION_NONE);
            return TRUE;
        }
    }

    return FALSE;
}

static INT
GUILoggedOnSAS(
    IN OUT PGINA_CONTEXT pgContext,
    IN DWORD dwSasType)
{
    INT result;

    if (dwSasType != WLX_SAS_TYPE_CTRL_ALT_DEL)
    {
        /* Nothing to do for WLX_SAS_TYPE_TIMEOUT; the dialog will
         * close itself thanks to the use of WlxDialogBoxParam */
        return WLX_SAS_ACTION_NONE;
    }

    result = pgContext->pWlxFuncs->WlxDialogBoxParam(
        pgContext->hWlx,
        pgContext->hDllInstance,
        MAKEINTRESOURCEW(IDD_SECURITY),
        GetDesktopWindow(),
        SecurityDialogProc,
        (LPARAM)pgContext);

    if (result < WLX_SAS_ACTION_LOGON ||
        result > WLX_SAS_ACTION_SWITCH_CONSOLE)
    {
        result = WLX_SAS_ACTION_NONE;
    }

    return result;
}


static
BOOL
DoLogon(
    IN HWND hwndDlg,
    IN OUT PGINA_CONTEXT pgContext)
{
    LPWSTR UserName = NULL;
    LPWSTR Password = NULL;
    LPWSTR Domain = NULL;
    BOOL result = FALSE;
    NTSTATUS Status, SubStatus = STATUS_SUCCESS;

    pgContext->bLogonInProgress = TRUE;

    if (GetTextboxText(hwndDlg, IDC_LOGON_USERNAME, &UserName) && *UserName == '\0')
        goto done;

    if (GetTextboxText(hwndDlg, IDC_LOGON_DOMAIN, &Domain) && *Domain == '\0')
        goto done;

    if (!GetTextboxText(hwndDlg, IDC_LOGON_PASSWORD, &Password))
        goto done;

    /*
     * An automatic logon with a count is used up by the attempt, whatever its outcome: a stored password that
     * does not work is tried as many times as the count says and then deleted, never at every start (an
     * account lock-out policy would count each try). The password is in memory (Password) already.
     */
    if (pgContext->bAutoAdminLogon)
        ConsumeAutoLogon();

    Status = DoLoginTasks(pgContext, UserName, Domain, Password, &SubStatus);
    if (Status == STATUS_LOGON_FAILURE)
    {
        ResourceMessageBox(pgContext,
                           hwndDlg,
                           MB_OK | MB_ICONEXCLAMATION,
                           IDS_LOGONTITLE,
                           IDS_LOGONWRONGUSERORPWD);
        goto done;
    }
    else if (Status == STATUS_ACCOUNT_LOCKED_OUT)
    {
        /* The account lockout policy locked the account (the LSA returns this status itself, as on Windows):
           the system message of ERROR_ACCOUNT_LOCKED_OUT */
        WCHAR szCaption[256];
        WCHAR szText[512];

        TRACE("Account locked out\n");
        LoadStringW(pgContext->hDllInstance, IDS_LOGONTITLE, szCaption, _countof(szCaption));
        if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                            NULL,
                            ERROR_ACCOUNT_LOCKED_OUT,
                            0,
                            szText,
                            _countof(szText),
                            NULL))
        {
            LoadStringW(pgContext->hDllInstance, IDS_ACCOUNTLOCKED, szText, _countof(szText));
        }

        pgContext->pWlxFuncs->WlxMessageBox(pgContext->hWlx,
                                            hwndDlg,
                                            szText,
                                            szCaption,
                                            MB_OK | MB_ICONERROR);
        goto done;
    }
    else if (Status == STATUS_ACCOUNT_RESTRICTION)
    {
        TRACE("DoLoginTasks failed! Status 0x%08lx  SubStatus 0x%08lx\n", Status, SubStatus);

        if (SubStatus == STATUS_ACCOUNT_DISABLED)
        {
            ResourceMessageBox(pgContext,
                               hwndDlg,
                               MB_OK | MB_ICONEXCLAMATION,
                               IDS_LOGONTITLE,
                               IDS_LOGONUSERDISABLED);
            goto done;
        }
        else if (SubStatus == STATUS_ACCOUNT_LOCKED_OUT)
        {
            TRACE("Account locked!\n");
            ResourceMessageBox(pgContext,
                               hwndDlg,
                               MB_OK | MB_ICONERROR,
                               IDS_LOGONTITLE,
                               IDS_ACCOUNTLOCKED);
            goto done;
        }
        else if ((SubStatus == STATUS_PASSWORD_MUST_CHANGE) ||
                 (SubStatus == STATUS_PASSWORD_EXPIRED))
        {
            if (SubStatus == STATUS_PASSWORD_MUST_CHANGE)
            {
                ResourceMessageBox(pgContext,
                                   hwndDlg,
                                   MB_OK | MB_ICONSTOP,
                                   IDS_LOGONTITLE,
                                   IDS_PASSWORDMUSTCHANGE);
            }
            else
            {
                ResourceMessageBox(pgContext,
                                   hwndDlg,
                                   MB_OK | MB_ICONSTOP,
                                   IDS_LOGONTITLE,
                                   IDS_PASSWORDEXPIRED);
            }

            if (!OnChangePassword(hwndDlg, pgContext))
                goto done;

            Status = DoLoginTasks(pgContext,
                                  pgContext->UserName,
                                  pgContext->DomainName,
                                  pgContext->Password,
                                  &SubStatus);
            if (!NT_SUCCESS(Status))
            {
                TRACE("Login after password change failed! (Status 0x%08lx)\n", Status);
                goto done;
            }
        }
        else if (SubStatus == STATUS_ACCOUNT_EXPIRED)
        {
            ResourceMessageBox(pgContext,
                               hwndDlg,
                               MB_OK | MB_ICONEXCLAMATION,
                               IDS_LOGONTITLE,
                               IDS_ACCOUNTEXPIRED);
        }
        else if (SubStatus == STATUS_INVALID_LOGON_HOURS)
        {
            ResourceMessageBox(pgContext,
                               hwndDlg,
                               MB_OK | MB_ICONERROR,
                               IDS_LOGONTITLE,
                               IDS_INVALIDLOGONHOURS);
            goto done;
        }
        else if (SubStatus == STATUS_INVALID_WORKSTATION)
        {
            ResourceMessageBox(pgContext,
                               hwndDlg,
                               MB_OK | MB_ICONERROR,
                               IDS_LOGONTITLE,
                               IDS_INVALIDWORKSTATION);
            goto done;
        }
        else
        {
            TRACE("Other error!\n");
            ResourceMessageBox(pgContext,
                               hwndDlg,
                               MB_OK | MB_ICONERROR,
                               IDS_LOGONTITLE,
                               IDS_ACCOUNTRESTRICTION);
            goto done;
        }
    }
    else if (Status == STATUS_LOGON_TYPE_NOT_GRANTED)
    {
        /* The account has no right to log on this way (or it is denied): the system message of ERROR_LOGON_TYPE_NOT_GRANTED */
        WCHAR szCaption[256];
        WCHAR szText[512];

        LoadStringW(pgContext->hDllInstance, IDS_LOGONTITLE, szCaption, _countof(szCaption));
        if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                            NULL,
                            ERROR_LOGON_TYPE_NOT_GRANTED,
                            0,
                            szText,
                            _countof(szText),
                            NULL))
        {
            StringCchPrintfW(szText, _countof(szText), L"Error %lu", (ULONG)ERROR_LOGON_TYPE_NOT_GRANTED);
        }

        pgContext->pWlxFuncs->WlxMessageBox(pgContext->hWlx,
                                            hwndDlg,
                                            szText,
                                            szCaption,
                                            MB_OK | MB_ICONERROR);
        goto done;
    }
    else if (!NT_SUCCESS(Status))
    {
        TRACE("DoLoginTasks failed! Status 0x%08lx\n", Status);
        goto done;
    }

    if (!CreateProfile(pgContext, UserName, Domain, Password))
    {
        ERR("Failed to create the profile!\n");
        goto done;
    }

    result = TRUE;

done:
    pgContext->bAutoAdminLogon = FALSE;

    /* The logon attempt is over: no password stays in the context (a stored automatic logon password that was read
       into it, or the one a password change put there) */
    SecureZeroMemory(pgContext->Password, sizeof(pgContext->Password));
    pgContext->bLogonInProgress = FALSE;

    if (UserName != NULL)
        HeapFree(GetProcessHeap(), 0, UserName);

    if (Password != NULL)
    {
        /* Zero out the password buffer before freeing it */
        SIZE_T pwdLen = (wcslen(Password) + 1) * sizeof(WCHAR);
        SecureZeroMemory(Password, pwdLen);
        HeapFree(GetProcessHeap(), 0, Password);
    }

    if (Domain != NULL)
        HeapFree(GetProcessHeap(), 0, Domain);

    return result;
}


static
VOID
SetDomainComboBox(
    HWND hwndDomainComboBox,
    PGINA_CONTEXT pgContext)
{
    WCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD dwComputerNameLength;
    LONG lIndex = 0;
    LONG lFindIndex;

    SendMessageW(hwndDomainComboBox, CB_RESETCONTENT, 0, 0);

    dwComputerNameLength = _countof(szComputerName);
    if (GetComputerNameW(szComputerName, &dwComputerNameLength))
    {
        lIndex = SendMessageW(hwndDomainComboBox, CB_ADDSTRING, 0, (LPARAM)szComputerName);
    }

    if (pgContext->DomainName[0])
    {
        lFindIndex = SendMessageW(hwndDomainComboBox, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)pgContext->DomainName);
        if (lFindIndex == CB_ERR)
        {
            lIndex = SendMessageW(hwndDomainComboBox, CB_ADDSTRING, 0, (LPARAM)pgContext->DomainName);
        }
        else
        {
            lIndex = lFindIndex;
        }
    }

    SendMessageW(hwndDomainComboBox, CB_SETCURSEL, lIndex, 0);
}


static INT_PTR CALLBACK
LogonDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    PGINA_CONTEXT pgContext;

    pgContext = (PGINA_CONTEXT)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            /* FIXME: take care of NoDomainUI */
            pgContext = (PGINA_CONTEXT)lParam;
            SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)pgContext);

            SetWelcomeText(hwndDlg);

            if (pgContext->bAutoAdminLogon ||
                !pgContext->bDontDisplayLastUserName)
            {
                SetDlgItemTextW(hwndDlg, IDC_LOGON_USERNAME, pgContext->UserName);
            }

            if (pgContext->bAutoAdminLogon)
                SetDlgItemTextW(hwndDlg, IDC_LOGON_PASSWORD, pgContext->Password);

            SetDomainComboBox(GetDlgItem(hwndDlg, IDC_LOGON_DOMAIN), pgContext);

            if (pgContext->bDisableCAD)
                EnableWindow(GetDlgItem(hwndDlg, IDCANCEL), FALSE);

            if (!pgContext->bShutdownWithoutLogon)
                EnableWindow(GetDlgItem(hwndDlg, IDC_LOGON_SHUTDOWN), FALSE);

            SetFocus(GetDlgItem(hwndDlg, pgContext->bDontDisplayLastUserName ? IDC_LOGON_USERNAME : IDC_LOGON_PASSWORD));

            if (pgContext->bAutoAdminLogon)
                PostMessage(GetDlgItem(hwndDlg, IDOK), BM_CLICK, 0, 0);

            return FALSE; // Default focus is changed.
        }

        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            if (lpDis->CtlID == IDC_BAR)
                return DrawBrandingBitmap(lpDis, &hBannerLine);
            return FALSE;
        }

        case WM_DESTROY:
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    if (DoLogon(hwndDlg, pgContext))
                    {
                        EndDialog(hwndDlg, WLX_SAS_ACTION_LOGON);
                    }
                    else
                    {
                        SetDlgItemTextW(hwndDlg, IDC_LOGON_PASSWORD, NULL);
                        SendMessageW(hwndDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hwndDlg, IDC_LOGON_PASSWORD), TRUE);
                    }
                    return TRUE;

                case IDCANCEL:
                    EndDialog(hwndDlg, WLX_SAS_ACTION_NONE);
                    return TRUE;

                case IDC_LOGON_SHUTDOWN:
                    if (OnShutDown(hwndDlg, pgContext,
                                   WLX_SHUTDOWN_STATE_DISCONNECT | WLX_SHUTDOWN_STATE_LOGOFF) == IDOK)
                    {
                        EndDialog(hwndDlg, pgContext->nShutdownAction);
                    }
                    return TRUE;
            }
            break;
    }

    return FALSE;
}


static
INT_PTR
CALLBACK
LegalNoticeDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    PLEGALNOTICEDATA pLegalNotice;

    switch (uMsg)
    {
        case WM_INITDIALOG:
            pLegalNotice = (PLEGALNOTICEDATA)lParam;
            SetWindowTextW(hwndDlg, pLegalNotice->pszCaption);
            SetDlgItemTextW(hwndDlg, IDC_LEGALNOTICE_TEXT, pLegalNotice->pszText);
            return TRUE;

        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            if (lpDis->CtlID == IDC_BAR)
                return DrawBrandingBitmap(lpDis, &hBannerLine);
            return FALSE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                case IDCANCEL:
                    EndDialog(hwndDlg, 0);
                    return TRUE;
            }
            break;
    }

    return FALSE;
}


static INT
GUILoggedOutSAS(
    IN OUT PGINA_CONTEXT pgContext)
{
    LEGALNOTICEDATA LegalNotice = {NULL, NULL};
    HKEY hKey = NULL;
    LONG rc;
    int result;

    TRACE("GUILoggedOutSAS()\n");

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                       0,
                       KEY_QUERY_VALUE,
                       &hKey);
    if (rc == ERROR_SUCCESS)
    {
        ReadRegSzValue(hKey,
                       L"LegalNoticeCaption",
                       &LegalNotice.pszCaption);

        ReadRegSzValue(hKey,
                       L"LegalNoticeText",
                       &LegalNotice.pszText);

        RegCloseKey(hKey);
    }

    if (LegalNotice.pszCaption != NULL && LegalNotice.pszCaption[0] &&
        LegalNotice.pszText != NULL && LegalNotice.pszText[0])
    {
        pgContext->pWlxFuncs->WlxDialogBoxParam(pgContext->hWlx,
                                                pgContext->hDllInstance,
                                                MAKEINTRESOURCEW(IDD_LEGALNOTICE),
                                                GetDesktopWindow(),
                                                LegalNoticeDialogProc,
                                                (LPARAM)&LegalNotice);
    }

    if (LegalNotice.pszCaption != NULL)
        HeapFree(GetProcessHeap(), 0, LegalNotice.pszCaption);

    if (LegalNotice.pszText != NULL)
        HeapFree(GetProcessHeap(), 0, LegalNotice.pszText);

    result = pgContext->pWlxFuncs->WlxDialogBoxParam(
        pgContext->hWlx,
        pgContext->hDllInstance,
        MAKEINTRESOURCEW(IDD_LOGON),
        GetDesktopWindow(),
        LogonDialogProc,
        (LPARAM)pgContext);
    if (result >= WLX_SAS_ACTION_LOGON &&
        result <= WLX_SAS_ACTION_SWITCH_CONSOLE)
    {
        WARN("WlxLoggedOutSAS() returns 0x%x\n", result);
        return result;
    }

    WARN("WlxDialogBoxParam() failed (0x%x)\n", result);
    return WLX_SAS_ACTION_NONE;
}


static VOID
SetLockMessage(HWND hwnd,
               INT nDlgItem,
               PGINA_CONTEXT pgContext)
{
    WCHAR Buffer1[256];
    WCHAR Buffer2[256];
    WCHAR Buffer3[512];

    LoadStringW(pgContext->hDllInstance, IDS_LOCKMSG, Buffer1, _countof(Buffer1));

    wsprintfW(Buffer2, L"%s\\%s", pgContext->DomainName, pgContext->UserName);
    wsprintfW(Buffer3, Buffer1, Buffer2);

    SetDlgItemTextW(hwnd, nDlgItem, Buffer3);
}


static
BOOL
DoUnlock(
    IN HWND hwndDlg,
    IN PGINA_CONTEXT pgContext,
    OUT LPINT Action)
{
    WCHAR Buffer1[256];
    WCHAR Buffer2[512];
    LPWSTR UserName = NULL;
    LPWSTR Password = NULL;
    BOOL res = FALSE;
    BOOL IsSessionUser = FALSE, IsAdmin = FALSE;
    NTSTATUS Status, SubStatus = STATUS_SUCCESS;

    if (GetTextboxText(hwndDlg, IDC_UNLOCK_USERNAME, &UserName) && *UserName == '\0')
    {
        HeapFree(GetProcessHeap(), 0, UserName);
        return FALSE;
    }

    if (GetTextboxText(hwndDlg, IDC_UNLOCK_PASSWORD, &Password) && UserName != NULL && Password != NULL)
    {
        /* The LSA checks the password: the session's user or an administrator unlocks. A wrong password is
           counted by the account lockout and a locked out account does not unlock */
        Status = DoUnlockLogon(pgContext, UserName, Password, &IsSessionUser, &IsAdmin, &SubStatus);
        if (NT_SUCCESS(Status) && IsSessionUser)
        {
            *Action = WLX_SAS_ACTION_UNLOCK_WKSTA;
            res = TRUE;
        }
        else if (NT_SUCCESS(Status) && IsAdmin)
        {
            /* An administrator's unlock logs the user of the session off (the contract of WlxWkstaLockedSAS) */
            *Action = WLX_SAS_ACTION_FORCE_LOGOFF;
            res = TRUE;
        }
        else if (Status == STATUS_ACCOUNT_LOCKED_OUT ||
                 (Status == STATUS_ACCOUNT_RESTRICTION && SubStatus == STATUS_ACCOUNT_LOCKED_OUT))
        {
            /* The system message of ERROR_ACCOUNT_LOCKED_OUT */
            LoadStringW(pgContext->hDllInstance, IDS_COMPUTERLOCKED, Buffer1, _countof(Buffer1));
            if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                NULL,
                                ERROR_ACCOUNT_LOCKED_OUT,
                                0,
                                Buffer2,
                                _countof(Buffer2),
                                NULL))
            {
                LoadStringW(pgContext->hDllInstance, IDS_ACCOUNTLOCKED, Buffer2, _countof(Buffer2));
            }
            MessageBoxW(hwndDlg, Buffer2, Buffer1, MB_OK | MB_ICONERROR);
        }
        else if (Status == STATUS_ACCOUNT_RESTRICTION &&
                 (SubStatus == STATUS_PASSWORD_EXPIRED || SubStatus == STATUS_PASSWORD_MUST_CHANGE) &&
                 _wcsicmp(UserName, pgContext->UserName) == 0)
        {
            /* The password of the session's user is right but has expired meanwhile: say so and offer the
               change (the logon dialog does the same); the new password is then typed here */
            ResourceMessageBox(pgContext,
                               hwndDlg,
                               MB_OK | MB_ICONSTOP,
                               IDS_COMPUTERLOCKED,
                               (SubStatus == STATUS_PASSWORD_MUST_CHANGE) ? IDS_PASSWORDMUSTCHANGE : IDS_PASSWORDEXPIRED);
            OnChangePassword(hwndDlg, pgContext);
        }
        else if (!NT_SUCCESS(Status) && _wcsicmp(UserName, pgContext->UserName) == 0)
        {
            /* Wrong Password */
            LoadStringW(pgContext->hDllInstance, IDS_LOCKEDWRONGPASSWORD, Buffer2, _countof(Buffer2));
            LoadStringW(pgContext->hDllInstance, IDS_COMPUTERLOCKED, Buffer1, _countof(Buffer1));
            MessageBoxW(hwndDlg, Buffer2, Buffer1, MB_OK | MB_ICONERROR);
        }
        else
        {
            /* Wrong user name (or a user who is neither the session's user nor an administrator) */
            LoadStringW(pgContext->hDllInstance, IDS_LOCKEDWRONGUSER, Buffer1, _countof(Buffer1));
            wsprintfW(Buffer2, Buffer1, pgContext->DomainName, pgContext->UserName);
            LoadStringW(pgContext->hDllInstance, IDS_COMPUTERLOCKED, Buffer1, _countof(Buffer1));
            MessageBoxW(hwndDlg, Buffer2, Buffer1, MB_OK | MB_ICONERROR);
        }
    }

    if (UserName != NULL)
        HeapFree(GetProcessHeap(), 0, UserName);

    if (Password != NULL)
    {
        /* Zero out the password buffer before freeing it */
        SIZE_T pwdLen = (wcslen(Password) + 1) * sizeof(WCHAR);
        SecureZeroMemory(Password, pwdLen);
        HeapFree(GetProcessHeap(), 0, Password);
    }

    return res;
}


static
INT_PTR
CALLBACK
UnlockDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    PGINA_CONTEXT pgContext;
    INT result = WLX_SAS_ACTION_NONE;

    pgContext = (PGINA_CONTEXT)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            pgContext = (PGINA_CONTEXT)lParam;
            SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)pgContext);
            SetWelcomeText(hwndDlg);

            SetLockMessage(hwndDlg, IDC_UNLOCK_MESSAGE, pgContext);
            SetDlgItemTextW(hwndDlg, IDC_UNLOCK_USERNAME, pgContext->UserName);

            if (pgContext->bDisableCAD)
                EnableWindow(GetDlgItem(hwndDlg, IDCANCEL), FALSE);

            SetFocus(GetDlgItem(hwndDlg, IDC_UNLOCK_PASSWORD));
            return FALSE; // Default focus is changed.
        }

        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            /* This dialog doesn't have IDC_BAR */
            return FALSE;
        }

        case WM_DESTROY:
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    if (DoUnlock(hwndDlg, pgContext, &result))
                    {
                        EndDialog(hwndDlg, result);
                    }
                    else
                    {
                        SetDlgItemTextW(hwndDlg, IDC_UNLOCK_PASSWORD, NULL);
                        SendMessageW(hwndDlg, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(hwndDlg, IDC_UNLOCK_PASSWORD), TRUE);
                    }
                    return TRUE;

                case IDCANCEL:
                    EndDialog(hwndDlg, WLX_SAS_ACTION_NONE);
                    return TRUE;
            }
            break;
    }

    return FALSE;
}


static INT
GUILockedSAS(
    IN OUT PGINA_CONTEXT pgContext)
{
    int result;

    TRACE("GUILockedSAS()\n");

    result = pgContext->pWlxFuncs->WlxDialogBoxParam(
        pgContext->hWlx,
        pgContext->hDllInstance,
        MAKEINTRESOURCEW(IDD_UNLOCK),
        GetDesktopWindow(),
        UnlockDialogProc,
        (LPARAM)pgContext);
    if (result >= WLX_SAS_ACTION_LOGON &&
        result <= WLX_SAS_ACTION_SWITCH_CONSOLE)
    {
        WARN("GUILockedSAS() returns 0x%x\n", result);
        return result;
    }

    WARN("GUILockedSAS() failed (0x%x)\n", result);
    return WLX_SAS_ACTION_NONE;
}


static INT_PTR CALLBACK
LockedDialogProc(
    IN HWND hwndDlg,
    IN UINT uMsg,
    IN WPARAM wParam,
    IN LPARAM lParam)
{
    PGINA_CONTEXT pgContext;

    pgContext = (PGINA_CONTEXT)GetWindowLongPtrW(hwndDlg, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            pgContext = (PGINA_CONTEXT)lParam;
            SetWindowLongPtrW(hwndDlg, GWLP_USERDATA, (LONG_PTR)pgContext);

            SetWelcomeText(hwndDlg);

            SetLockMessage(hwndDlg, IDC_LOCKED_MESSAGE, pgContext);
            return TRUE;
        }
        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDis = (LPDRAWITEMSTRUCT)lParam;
            if (lpDis->CtlID == IDC_ROSLOGO)
                return DrawBrandingBitmap(lpDis, &hBanner);
            /* This dialog doesn't have IDC_BAR */
            return FALSE;
        }
        case WM_DESTROY:
        {
            return TRUE;
        }
    }

    return FALSE;
}


static VOID
GUIDisplayLockedNotice(
    IN OUT PGINA_CONTEXT pgContext)
{
    pgContext->pWlxFuncs->WlxDialogBoxParam(
        pgContext->hWlx,
        pgContext->hDllInstance,
        MAKEINTRESOURCEW(IDD_LOCKED),
        GetDesktopWindow(),
        LockedDialogProc,
        (LPARAM)pgContext);
}

GINA_UI GinaGraphicalUI = {
    GUIInitialize,
    GUIDisplayStatusMessage,
    GUIRemoveStatusMessage,
    GUIDisplaySASNotice,
    GUILoggedOnSAS,
    GUILoggedOutSAS,
    GUILockedSAS,
    GUIDisplayLockedNotice,
};
