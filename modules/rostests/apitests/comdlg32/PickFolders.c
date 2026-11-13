/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the folder picker (IFileOpenDialog with FOS_PICKFOLDERS), driven with keyboard input
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The dialog is shown in this process and driven with SendInput from a second thread, which needs an
 * interactive desktop. Expected behaviour is what Windows 10 does (measured in an interactive session):
 * - Open with an empty name box returns the folder the dialog shows.
 * - Open with the name of a folder that was selected in the list returns it.
 * - Open with a typed existing folder (absolute, with a trailing backslash, or relative) goes into the
 *   folder and shows its name in the name box; the dialog stays, the next Open returns the folder.
 * - Open with a typed path that does not exist, or that is a file, shows a message box titled like the
 *   dialog and the dialog stays.
 */

#define COBJMACROS
#include <apitest.h>
#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <strsafe.h>

#if DLL_EXPORT_VERSION >= 0x600 /* uses NT6 exports */

typedef enum
{
    HOW_TYPE_ENTER,     /* type the text into the name box, press Enter */
    HOW_TYPE_CLICK,     /* the same, then press the Open button (IDOK) */
    HOW_SELECT_CLICK,   /* select the folder 'out' of the list by typing its first letters, press the Open button */
    HOW_EMPTY_ENTER,    /* clear the name box, press Enter */
    HOW_EMPTY_CLICK,    /* clear the name box, press the Open button */
    HOW_UNTOUCHED_CLICK /* press the Open button; the name box was never touched */
} HOW;

typedef enum
{
    EXPECT_RETURN,      /* the dialog closes and returns Want */
    EXPECT_ENTER,       /* the dialog goes into Want, shows Leaf in the name box and stays; the next Open returns Want */
    EXPECT_NOTEXIST,    /* a message box about a path that does not exist, the dialog stays in the base folder */
    EXPECT_NOTVALID     /* a message box about an invalid folder name, the dialog stays in the base folder */
} EXPECT;

typedef struct
{
    PCSTR Name;
    HOW How;
    PCWSTR Text;        /* '@' stands for the base folder */
    EXPECT Expect;
    PCWSTR Want;        /* '@' stands for the base folder */
    PCWSTR Leaf;        /* name box after entering a folder, and the name in the message of a message box */
} CASE;

typedef struct
{
    BOOL Found;         /* the dialog window was found */
    BOOL ClosedAfterFirst;
    BOOL ClosedAfterSecond;
    BOOL BoxFound;
    BOOL BoxIconKnown, BoxIconWarning;
    WCHAR BoxTitle[128];
    WCHAR BoxText[256];
    WCHAR DialogTitle[128];
    WCHAR NameAfterFirst[MAX_PATH];
    WCHAR FolderAfterFirst[MAX_PATH];
    WCHAR NameBeforeOpen[MAX_PATH];
    WCHAR Failure[256];
    HRESULT hr;
    WCHAR Path[MAX_PATH];
} OUTCOME;

static const CASE *s_Case;
static OUTCOME s_Out;
static IFileDialog *s_pfd;
static WCHAR s_Base[MAX_PATH];
static WCHAR s_CurFolder[MAX_PATH];
static CRITICAL_SECTION s_Lock;
static volatile LONG s_Closed;

static void Expand(PWSTR pszOut, SIZE_T cchOut, PCWSTR pszIn)
{
    pszOut[0] = UNICODE_NULL;
    for (; *pszIn; pszIn++)
    {
        if (*pszIn == L'@')
            StringCchCatW(pszOut, cchOut, s_Base);
        else
            StringCchCatNW(pszOut, cchOut, pszIn, 1);
    }
}

static void GetItemPath(IShellItem *psi, PWSTR pszOut, SIZE_T cchOut)
{
    PWSTR pszName = NULL;

    pszOut[0] = UNICODE_NULL;
    if (SUCCEEDED(IShellItem_GetDisplayName(psi, SIGDN_FILESYSPATH, &pszName)))
    {
        StringCchCopyW(pszOut, cchOut, pszName);
        CoTaskMemFree(pszName);
    }
}

/* Runs on the thread of the dialog: the dialog object belongs to its apartment */
static VOID CALLBACK PollFolderProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
    WCHAR szPath[MAX_PATH];
    IShellItem *psi;

    if (!s_pfd || FAILED(IFileDialog_GetFolder(s_pfd, &psi)))
        return;
    GetItemPath(psi, szPath, _countof(szPath));
    IShellItem_Release(psi);
    EnterCriticalSection(&s_Lock);
    StringCchCopyW(s_CurFolder, _countof(s_CurFolder), szPath);
    LeaveCriticalSection(&s_Lock);
}

static void GetCurFolder(PWSTR pszOut, SIZE_T cchOut)
{
    EnterCriticalSection(&s_Lock);
    StringCchCopyW(pszOut, cchOut, s_CurFolder);
    LeaveCriticalSection(&s_Lock);
}

/* ---- keyboard ---- */

static void SendKey(WORD vk, DWORD dwFlags)
{
    INPUT Input = { INPUT_KEYBOARD };

    Input.ki.wVk = vk;
    Input.ki.wScan = (WORD)MapVirtualKeyW(vk, MAPVK_VK_TO_VSC);
    Input.ki.dwFlags = dwFlags;
    SendInput(1, &Input, sizeof(Input));
}

static void PressKey(WORD vk, BOOL bShift)
{
    if (bShift)
        SendKey(VK_SHIFT, 0);
    SendKey(vk, 0);
    SendKey(vk, KEYEVENTF_KEYUP);
    if (bShift)
        SendKey(VK_SHIFT, KEYEVENTF_KEYUP);
    Sleep(40);
}

static void TypeText(PCWSTR psz)
{
    for (; *psz; psz++)
    {
        SHORT s = VkKeyScanW(*psz);

        if (s != -1 && LOBYTE(s) != 0xff)
        {
            PressKey(LOBYTE(s), HIBYTE(s) & 1);
        }
        else
        {
            INPUT Input[2] = { { INPUT_KEYBOARD }, { INPUT_KEYBOARD } };

            Input[0].ki.wScan = Input[1].ki.wScan = *psz;
            Input[0].ki.dwFlags = KEYEVENTF_UNICODE;
            Input[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            SendInput(2, Input, sizeof(INPUT));
        }
        Sleep(30);
    }
}

/* ---- windows ---- */

typedef struct
{
    HWND hwndSkip;
    HWND hwndFound;
} FIND_TOP;

static BOOL CALLBACK FindTopProc(HWND hwnd, LPARAM lParam)
{
    FIND_TOP *pFind = (FIND_TOP *)lParam;
    WCHAR szClass[16];
    DWORD dwPid;

    GetWindowThreadProcessId(hwnd, &dwPid);
    if (dwPid != GetCurrentProcessId() || hwnd == pFind->hwndSkip || !IsWindowVisible(hwnd))
        return TRUE;
    if (GetClassNameW(hwnd, szClass, _countof(szClass)) && !wcscmp(szClass, L"#32770"))
    {
        pFind->hwndFound = hwnd;
        return FALSE;
    }
    return TRUE;
}

/* A visible dialog of this process other than hwndSkip */
static HWND FindTopDialog(HWND hwndSkip)
{
    FIND_TOP Find = { hwndSkip, NULL };

    EnumWindows(FindTopProc, (LPARAM)&Find);
    return Find.hwndFound;
}

typedef struct
{
    PCWSTR Class;
    HWND hwnd;
} FIND_CLASS;

static BOOL CALLBACK FindClassProc(HWND hwnd, LPARAM lParam)
{
    FIND_CLASS *pFind = (FIND_CLASS *)lParam;
    WCHAR szClass[64];

    if (IsWindowVisible(hwnd) && GetClassNameW(hwnd, szClass, _countof(szClass)) && !_wcsicmp(szClass, pFind->Class))
    {
        pFind->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND FindChildOfClass(HWND hwndParent, PCWSTR pszClass)
{
    FIND_CLASS Find = { pszClass, NULL };

    EnumChildWindows(hwndParent, FindClassProc, (LPARAM)&Find);
    return Find.hwnd;
}

static HWND FindNameBox(HWND hwndDlg)
{
    HWND hwnd = GetDlgItem(hwndDlg, edt1);

    return hwnd ? hwnd : FindChildOfClass(hwndDlg, L"Edit");
}

static void GetText(HWND hwnd, PWSTR pszOut, SIZE_T cchOut)
{
    pszOut[0] = UNICODE_NULL;
    if (hwnd)
        SendMessageTimeoutW(hwnd, WM_GETTEXT, cchOut, (LPARAM)pszOut, SMTO_ABORTIFHUNG, 1000, NULL);
}

static BOOL CALLBACK BoxChildProc(HWND hwnd, LPARAM lParam)
{
    WCHAR szClass[16], szText[256];
    LONG_PTR id = GetDlgCtrlID(hwnd);

    if (!GetClassNameW(hwnd, szClass, _countof(szClass)) || _wcsicmp(szClass, L"Static"))
        return TRUE;
    GetText(hwnd, szText, _countof(szText));
    if (id == 0xFFFF && szText[0])
        StringCchCopyW(s_Out.BoxText, _countof(s_Out.BoxText), szText);
    else if (id == 0x440 /* the icon of a classic message box */)
    {
        HICON hIcon = (HICON)SendMessageW(hwnd, STM_GETICON, 0, 0);

        if (hIcon)
        {
            s_Out.BoxIconKnown = TRUE;
            s_Out.BoxIconWarning = (hIcon == LoadIconW(NULL, (PCWSTR)IDI_EXCLAMATION));
        }
    }
    return TRUE;
}

static void MakeForeground(HWND hwnd)
{
    int i;

    for (i = 0; i < 20; i++)
    {
        DWORD dwPid = 0;
        HWND hwndFg = GetForegroundWindow();

        if (hwndFg)
            GetWindowThreadProcessId(hwndFg, &dwPid);
        if (dwPid == GetCurrentProcessId())
            break;
        SendKey(VK_MENU, 0);
        SendKey(VK_MENU, KEYEVENTF_KEYUP);
        SetForegroundWindow(hwnd);
        BringWindowToTop(hwnd);
        Sleep(150);
    }
}

static void FocusWindow(HWND hwndDlg, HWND hwnd)
{
    DWORD dwThis = GetCurrentThreadId(), dwDlg = GetWindowThreadProcessId(hwndDlg, NULL);

    AttachThreadInput(dwThis, dwDlg, TRUE);
    SetFocus(hwnd);
    AttachThreadInput(dwThis, dwDlg, FALSE);
}

static BOOL CALLBACK FindViewProc(HWND hwnd, LPARAM lParam)
{
    WCHAR szClass[32];

    if (GetClassNameW(hwnd, szClass, _countof(szClass)) && !wcscmp(szClass, L"SHELLDLL_DefView"))
    {
        *(HWND *)lParam = hwnd;
        return FALSE;
    }
    return TRUE;
}

static void PressOpen(HWND hwndDlg)
{
    PostMessageW(hwndDlg, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), (LPARAM)GetDlgItem(hwndDlg, IDOK));
}

static BOOL WaitClosed(DWORD dwMs)
{
    DWORD dwStart = GetTickCount();

    while (!s_Closed && GetTickCount() - dwStart < dwMs)
        Sleep(50);
    return s_Closed != 0;
}

static void CancelDialog(HWND hwndDlg)
{
    HWND hwndBox;

    /* a message box that is still there blocks the dialog */
    while (!s_Closed && (hwndBox = FindTopDialog(hwndDlg)) != NULL)
    {
        PostMessageW(hwndBox, WM_COMMAND, IDOK, 0);
        Sleep(300);
        if (IsWindow(hwndBox) && IsWindowVisible(hwndBox))
            PostMessageW(hwndBox, WM_CLOSE, 0, 0);
        Sleep(300);
    }
    PostMessageW(hwndDlg, WM_COMMAND, IDCANCEL, 0);
    if (!WaitClosed(5000))
    {
        MakeForeground(hwndDlg);
        PressKey(VK_ESCAPE, FALSE);
        WaitClosed(5000);
    }
}

static DWORD WINAPI DriverThread(LPVOID pParam)
{
    const CASE *pCase = s_Case;
    WCHAR szWantFolder[MAX_PATH], szText[MAX_PATH * 2], szCur[MAX_PATH];
    HWND hwndDlg = NULL, hwndEdit, hwndBox;
    DWORD dwStart, dwStep;

    /* Wait for the dialog, and for it to be in the base folder with a populated list */
    dwStart = GetTickCount();
    while (GetTickCount() - dwStart < 30000)
    {
        hwndDlg = FindTopDialog(NULL);
        GetCurFolder(szCur, _countof(szCur));
        if (hwndDlg && !_wcsicmp(szCur, s_Base))
            break;
        hwndDlg = NULL;
        Sleep(100);
    }
    if (!hwndDlg)
    {
        StringCchCopyW(s_Out.Failure, _countof(s_Out.Failure), L"the dialog did not show up in the base folder in 30 s");
        hwndDlg = FindTopDialog(NULL);
        if (hwndDlg)
            CancelDialog(hwndDlg);
        return 1;
    }
    s_Out.Found = TRUE;
    Sleep(2500);
    GetText(hwndDlg, s_Out.DialogTitle, _countof(s_Out.DialogTitle));
    MakeForeground(hwndDlg);
    hwndEdit = FindNameBox(hwndDlg);
    if (!hwndEdit)
    {
        StringCchCopyW(s_Out.Failure, _countof(s_Out.Failure), L"no name box");
        CancelDialog(hwndDlg);
        return 1;
    }
    FocusWindow(hwndDlg, hwndEdit);
    Sleep(200);

    /* first Open */
    switch (pCase->How)
    {
        case HOW_TYPE_ENTER:
        case HOW_TYPE_CLICK:
            Expand(szText, _countof(szText), pCase->Text);
            SendMessageW(hwndEdit, EM_SETSEL, 0, -1);
            TypeText(szText);
            Sleep(300);
            break;
        case HOW_SELECT_CLICK:
        {
            HWND hwndView = NULL, hwndList;

            EnumChildWindows(hwndDlg, FindViewProc, (LPARAM)&hwndView);
            hwndList = hwndView ? GetWindow(hwndView, GW_CHILD) : NULL;
            if (!hwndList)
            {
                StringCchCopyW(s_Out.Failure, _countof(s_Out.Failure), L"no list view");
                CancelDialog(hwndDlg);
                return 1;
            }
            FocusWindow(hwndDlg, hwndList);
            Sleep(300);
            TypeText(L"ou");    /* 'other' and 'out' both start with 'o' */
            for (dwStep = 0; dwStep < 60; dwStep++)
            {
                GetText(hwndEdit, szText, _countof(szText));
                if (!wcscmp(szText, L"out"))
                    break;
                Sleep(50);
            }
            break;
        }
        case HOW_EMPTY_ENTER:
        case HOW_EMPTY_CLICK:
            SendMessageW(hwndEdit, EM_SETSEL, 0, -1);
            PressKey(VK_DELETE, FALSE);
            Sleep(300);
            break;
        case HOW_UNTOUCHED_CLICK:
            break;
    }
    GetText(hwndEdit, s_Out.NameBeforeOpen, _countof(s_Out.NameBeforeOpen));

    if (pCase->How == HOW_TYPE_ENTER || pCase->How == HOW_EMPTY_ENTER)
        PressKey(VK_RETURN, FALSE);
    else
        PressOpen(hwndDlg);

    /* what happened: closed, went into a folder, or a message box */
    if (pCase->Expect == EXPECT_ENTER)
        Expand(szWantFolder, _countof(szWantFolder), pCase->Want);
    for (dwStep = 0; dwStep < 100 && !s_Closed; dwStep++)
    {
        if (pCase->Expect == EXPECT_ENTER)
        {
            GetCurFolder(szCur, _countof(szCur));
            if (!_wcsicmp(szCur, szWantFolder))
                break;
        }
        if (FindTopDialog(hwndDlg))
            break;
        Sleep(50);
    }
    if (pCase->Expect == EXPECT_ENTER)
        Sleep(700);     /* the name box follows the folder */
    else if (!s_Closed)
        Sleep(300);
    if (s_Closed)
    {
        s_Out.ClosedAfterFirst = TRUE;
        return 0;
    }
    GetText(hwndEdit, s_Out.NameAfterFirst, _countof(s_Out.NameAfterFirst));
    GetCurFolder(s_Out.FolderAfterFirst, _countof(s_Out.FolderAfterFirst));
    hwndBox = FindTopDialog(hwndDlg);
    if (hwndBox)
    {
        s_Out.BoxFound = TRUE;
        GetText(hwndBox, s_Out.BoxTitle, _countof(s_Out.BoxTitle));
        EnumChildWindows(hwndBox, BoxChildProc, 0);
        MakeForeground(hwndBox);
        PressKey(VK_RETURN, FALSE);
        Sleep(700);
        if (IsWindow(hwndBox) && IsWindowVisible(hwndBox))
            PostMessageW(hwndBox, WM_COMMAND, IDOK, 0);
        Sleep(500);
        CancelDialog(hwndDlg);
        return 0;
    }

    if (pCase->Expect == EXPECT_ENTER)
    {
        /* second Open */
        PressOpen(hwndDlg);
        if (WaitClosed(5000))
        {
            s_Out.ClosedAfterSecond = TRUE;
            return 0;
        }
    }
    CancelDialog(hwndDlg);
    return 0;
}

static void RunCase(const CASE *pCase)
{
    IShellItem *psiFolder = NULL, *psiResult = NULL;
    HANDLE hThread;
    UINT_PTR idTimer;
    HRESULT hr;
    DWORD dwOptions = 0;

    ZeroMemory(&s_Out, sizeof(s_Out));
    s_Case = pCase;
    s_Closed = 0;
    s_CurFolder[0] = UNICODE_NULL;

    hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &IID_IFileDialog, (void **)&s_pfd);
    ok(hr == S_OK, "CoCreateInstance failed: 0x%08lx\n", hr);
    if (FAILED(hr))
        return;
    IFileDialog_GetOptions(s_pfd, &dwOptions);
    IFileDialog_SetOptions(s_pfd, dwOptions | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    hr = SHCreateItemFromParsingName(s_Base, NULL, &IID_IShellItem, (void **)&psiFolder);
    ok(hr == S_OK, "SHCreateItemFromParsingName(%S) failed: 0x%08lx\n", s_Base, hr);
    if (SUCCEEDED(hr))
    {
        IFileDialog_SetFolder(s_pfd, psiFolder);
        IShellItem_Release(psiFolder);
    }

    hThread = CreateThread(NULL, 0, DriverThread, NULL, 0, NULL);
    ok(hThread != NULL, "CreateThread failed: %lu\n", GetLastError());
    idTimer = SetTimer(NULL, 0, 50, PollFolderProc);
    s_Out.hr = IFileDialog_Show(s_pfd, NULL);
    InterlockedExchange(&s_Closed, 1);
    KillTimer(NULL, idTimer);
    if (hThread)
    {
        ok(WaitForSingleObject(hThread, 60000) == WAIT_OBJECT_0, "%s: the driver did not finish\n", pCase->Name);
        CloseHandle(hThread);
    }
    if (SUCCEEDED(s_Out.hr) && SUCCEEDED(IFileDialog_GetResult(s_pfd, &psiResult)))
    {
        GetItemPath(psiResult, s_Out.Path, _countof(s_Out.Path));
        IShellItem_Release(psiResult);
    }
    IFileDialog_Release(s_pfd);
    s_pfd = NULL;
}

static void CheckMessage(const CASE *pCase)
{
    WCHAR szWant[256], szSentence[128];

    ok(s_Out.BoxFound, "%s: no message box\n", pCase->Name);
    if (!s_Out.BoxFound)
        return;
    ok(!wcscmp(s_Out.BoxTitle, s_Out.DialogTitle), "%s: message box title '%S', expected the dialog's '%S'\n",
       pCase->Name, s_Out.BoxTitle, s_Out.DialogTitle);
    ok(!wcscmp(s_Out.BoxTitle, L"Select Folder"), "%s: message box title '%S'\n", pCase->Name, s_Out.BoxTitle);
    /* a task dialog of Windows has no text a program can read; the one of ReactOS does */
    if (s_Out.BoxText[0])
    {
        if (pCase->Expect == EXPECT_NOTEXIST)
            StringCchCopyW(szSentence, _countof(szSentence), L"Path does not exist.\nCheck the path and try again.");
        else
            StringCchCopyW(szSentence, _countof(szSentence), L"The folder name is not valid.");
        StringCchPrintfW(szWant, _countof(szWant), L"%s\n%s", pCase->Leaf, szSentence);
        ok(!wcscmp(s_Out.BoxText, szWant), "%s: message '%S', expected '%S'\n", pCase->Name, s_Out.BoxText, szWant);
    }
    if (s_Out.BoxIconKnown)
        ok(s_Out.BoxIconWarning, "%s: the message box has no warning icon\n", pCase->Name);
}

static void CheckCase(const CASE *pCase)
{
    WCHAR szWant[MAX_PATH];

    ok(!s_Out.Failure[0], "%s: the dialog could not be driven: %S\n", pCase->Name, s_Out.Failure);
    if (!s_Out.Found)
        return;

    switch (pCase->Expect)
    {
        case EXPECT_RETURN:
            Expand(szWant, _countof(szWant), pCase->Want);
            ok(s_Out.ClosedAfterFirst, "%s: the dialog stayed open\n", pCase->Name);
            ok(s_Out.hr == S_OK, "%s: Show returned 0x%08lx\n", pCase->Name, s_Out.hr);
            ok(!_wcsicmp(s_Out.Path, szWant), "%s: result '%S', expected '%S'\n", pCase->Name, s_Out.Path, szWant);
            ok(!s_Out.BoxFound, "%s: unexpected message box\n", pCase->Name);
            break;

        case EXPECT_ENTER:
            Expand(szWant, _countof(szWant), pCase->Want);
            ok(!s_Out.ClosedAfterFirst, "%s: the dialog closed at the first Open (result '%S')\n", pCase->Name, s_Out.Path);
            ok(!s_Out.BoxFound, "%s: unexpected message box '%S'\n", pCase->Name, s_Out.BoxText);
            if (s_Out.ClosedAfterFirst)
                break;
            ok(!_wcsicmp(s_Out.FolderAfterFirst, szWant), "%s: the dialog shows '%S', expected '%S'\n", pCase->Name,
               s_Out.FolderAfterFirst, szWant);
            ok(!wcscmp(s_Out.NameAfterFirst, pCase->Leaf), "%s: name box '%S', expected '%S'\n", pCase->Name,
               s_Out.NameAfterFirst, pCase->Leaf);
            ok(s_Out.ClosedAfterSecond, "%s: the second Open did not close the dialog\n", pCase->Name);
            ok(s_Out.hr == S_OK, "%s: Show returned 0x%08lx\n", pCase->Name, s_Out.hr);
            ok(!_wcsicmp(s_Out.Path, szWant), "%s: result '%S', expected '%S'\n", pCase->Name, s_Out.Path, szWant);
            break;

        case EXPECT_NOTEXIST:
        case EXPECT_NOTVALID:
            ok(!s_Out.ClosedAfterFirst, "%s: the dialog closed (result '%S')\n", pCase->Name, s_Out.Path);
            if (s_Out.ClosedAfterFirst)
                break;
            CheckMessage(pCase);
            ok(!_wcsicmp(s_Out.FolderAfterFirst, s_Base), "%s: the dialog shows '%S', expected '%S'\n", pCase->Name,
               s_Out.FolderAfterFirst, s_Base);
            ok(s_Out.hr == HRESULT_FROM_WIN32(ERROR_CANCELLED), "%s: Show returned 0x%08lx\n", pCase->Name, s_Out.hr);
            break;
    }
}

static BOOL IsInteractive(void)
{
    USEROBJECTFLAGS Flags;
    DWORD cb;

    return GetUserObjectInformationW(GetProcessWindowStation(), UOI_FLAGS, &Flags, sizeof(Flags), &cb) &&
           (Flags.dwFlags & WSF_VISIBLE);
}

START_TEST(PickFolders)
{
    static const CASE Cases[] =
    {
        { "typed path, Enter", HOW_TYPE_ENTER, L"@\\out", EXPECT_ENTER, L"@\\out", L"out" },
        { "typed path, Open", HOW_TYPE_CLICK, L"@\\out", EXPECT_ENTER, L"@\\out", L"out" },
        { "typed path with backslash, Enter", HOW_TYPE_ENTER, L"@\\out\\", EXPECT_ENTER, L"@\\out", L"out" },
        { "typed path with backslash, Open", HOW_TYPE_CLICK, L"@\\out\\", EXPECT_ENTER, L"@\\out", L"out" },
        { "typed relative name, Enter", HOW_TYPE_ENTER, L"out", EXPECT_ENTER, L"@\\out", L"out" },
        { "typed relative name, Open", HOW_TYPE_CLICK, L"out", EXPECT_ENTER, L"@\\out", L"out" },
        { "selected folder, Open", HOW_SELECT_CLICK, NULL, EXPECT_RETURN, L"@\\out", NULL },
        { "empty name, Enter", HOW_EMPTY_ENTER, NULL, EXPECT_RETURN, L"@", NULL },
        { "empty name, Open", HOW_EMPTY_CLICK, NULL, EXPECT_RETURN, L"@", NULL },
        { "untouched name, Open", HOW_UNTOUCHED_CLICK, NULL, EXPECT_RETURN, L"@", NULL },
        { "typed missing path", HOW_TYPE_ENTER, L"@\\nonesuch", EXPECT_NOTEXIST, NULL, L"nonesuch" },
        { "typed missing path, Open", HOW_TYPE_CLICK, L"@\\nonesuch", EXPECT_NOTEXIST, NULL, L"nonesuch" },
        { "typed file", HOW_TYPE_ENTER, L"@\\afile.txt", EXPECT_NOTVALID, NULL, L"afile.txt" },
        { "typed file, Open", HOW_TYPE_CLICK, L"@\\afile.txt", EXPECT_NOTVALID, NULL, L"afile.txt" },
    };
    WCHAR szTemp[MAX_PATH], szPath[MAX_PATH];
    HANDLE hFile;
    HRESULT hr;
    UINT i;

    if (!IsInteractive())
    {
        skip("Not an interactive window station\n");
        return;
    }

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok(SUCCEEDED(hr), "CoInitializeEx failed: 0x%08lx\n", hr);

    {
        IFileDialog *pfd = NULL;
        IExplorerBrowser *peb = NULL;

        hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &IID_IFileDialog, (void **)&pfd);
        if (hr == REGDB_E_CLASSNOTREG)
        {
            skip("The item dialogs are not registered\n");
            CoUninitialize();
            return;
        }
        if (pfd)
            IFileDialog_Release(pfd);
        hr = CoCreateInstance(&CLSID_ExplorerBrowser, NULL, CLSCTX_INPROC_SERVER, &IID_IExplorerBrowser, (void **)&peb);
        if (FAILED(hr))
        {
            skip("No ExplorerBrowser: the item dialogs cannot finish\n");
            CoUninitialize();
            return;
        }
        IExplorerBrowser_Release(peb);
    }

    InitializeCriticalSection(&s_Lock);

    /* The dialog returns long names */
    GetTempPathW(_countof(szTemp), szTemp);
    GetLongPathNameW(szTemp, szTemp, _countof(szTemp));
    StringCchPrintfW(s_Base, _countof(s_Base), L"%spickfld-%lu", szTemp, GetTickCount());
    ok(CreateDirectoryW(s_Base, NULL), "CreateDirectoryW(%S) failed: %lu\n", s_Base, GetLastError());
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\out", s_Base);
    ok(CreateDirectoryW(szPath, NULL), "CreateDirectoryW(%S) failed: %lu\n", szPath, GetLastError());
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\out\\sub", s_Base);
    ok(CreateDirectoryW(szPath, NULL), "CreateDirectoryW(%S) failed: %lu\n", szPath, GetLastError());
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\other", s_Base);
    ok(CreateDirectoryW(szPath, NULL), "CreateDirectoryW(%S) failed: %lu\n", szPath, GetLastError());
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\afile.txt", s_Base);
    hFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "CreateFileW(%S) failed: %lu\n", szPath, GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    for (i = 0; i < _countof(Cases); i++)
    {
        RunCase(&Cases[i]);
        CheckCase(&Cases[i]);
    }

    DeleteFileW(szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\out\\sub", s_Base);
    RemoveDirectoryW(szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\out", s_Base);
    RemoveDirectoryW(szPath);
    StringCchPrintfW(szPath, _countof(szPath), L"%s\\other", s_Base);
    RemoveDirectoryW(szPath);
    RemoveDirectoryW(s_Base);
    DeleteCriticalSection(&s_Lock);
    CoUninitialize();
}

#else

START_TEST(PickFolders)
{
    skip("PickFolders needs the NT6 exports\n");
}

#endif
