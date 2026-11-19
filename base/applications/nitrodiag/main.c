/*
 * PROJECT:     NitroOS compatibility log tool
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Command line, program choice, report file, dialogs
 */

#include "nitrodiag.h"

#include <shellapi.h>
#include <commdlg.h>
#include <objbase.h>
#include <shobjidl.h>
#include <shlguid.h>

#include "minizip/ioapi.h"
#include "minizip/iowin32.h"
#include "minizip/zip.h"

ND_OPTIONS g_Opt;

static HWND g_hStatus;
static volatile BOOL g_Finish;
static WCHAR g_SavedPath[MAX_PATH];
static WCHAR g_Verdict[600];

static void Say(const WCHAR *fmt, ...)
{
    WCHAR buf[2048];
    char out[4096];
    va_list ap;
    DWORD w;
    va_start(ap, fmt);
    StringCchVPrintfW(buf, _countof(buf), fmt, ap);
    va_end(ap);
    WideCharToMultiByte(GetConsoleOutputCP(), 0, buf, -1, out, sizeof(out), NULL, NULL);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), out, (DWORD)strlen(out), &w, NULL);
}

static void Usage(void)
{
    Say(L"nitrodiag - run a program under a small tracer and save ONE report you can send to us.\r\n\r\n"
        L"  nitrodiag [options] program [arguments]\r\n"
        L"  nitrodiag /attach <process id> [options]\r\n"
        L"  nitrodiag /pick                      ask which program to run\r\n\r\n"
        L"Options (they come before the program; \"--\" ends them):\r\n"
        L"  /out <folder>     where the report .zip goes (default: the Desktop)\r\n"
        L"  /zip <file>       the exact file name of the report .zip\r\n"
        L"  /quiet            no dialogs; print the report path\r\n"
        L"  /gui              dialogs instead of console text (used by the Explorer verb and the Start menu entry)\r\n"
        L"  /nodump           no minidump when the program crashes\r\n"
        L"  /timeout <sec>    stop watching after this long and add a snapshot (modules + thread stacks) of what still runs\r\n"
        L"  /attach <pid>     report on a process that already runs (or hangs)\r\n"
        L"  /imports          always check the imports of the program against the files on disk\r\n"
        L"  /screenshot       add a screenshot of the screen to the report (off by default)\r\n"
        L"  /nosnaps          do not switch on the loader's debug text in the program\r\n"
        L"  /raw              also list thread events\r\n\r\n"
        L"The report contains file paths, your user name and the command line. Nothing is uploaded.\r\n");
}

/* ---- command line ---- */

static const WCHAR *SkipSpace(const WCHAR *p)
{
    while (*p == L' ' || *p == L'\t')
        p++;
    return p;
}

/* one token (quotes removed) into buf, returns the position after it */
static const WCHAR *Token(const WCHAR *p, WCHAR *buf, size_t cch)
{
    size_t n = 0;
    BOOL q = FALSE;
    p = SkipSpace(p);
    while (*p && (q || (*p != L' ' && *p != L'\t')))
    {
        if (*p == L'"')
            q = !q;
        else if (n + 1 < cch)
            buf[n++] = *p;
        p++;
    }
    buf[n] = 0;
    return p;
}

static BOOL ParseCommandLine(void)
{
    const WCHAR *cl = GetCommandLineW();
    const WCHAR *p = cl;
    WCHAR tok[MAX_PATH];

    /* the name of this program */
    p = SkipSpace(p);
    if (*p == L'"')
    {
        p++;
        while (*p && *p != L'"')
            p++;
        if (*p)
            p++;
    }
    else
        while (*p && *p != L' ' && *p != L'\t')
            p++;

    for (;;)
    {
        const WCHAR *start = SkipSpace(p);
        const WCHAR *next;
        if (*start != L'/' && *start != L'-')
            break;
        next = Token(start, tok, _countof(tok));
        if (!wcscmp(tok, L"--"))
        {
            p = next;
            break;
        }
        if (!_wcsicmp(tok, L"/?") || !_wcsicmp(tok, L"-?") || !_wcsicmp(tok, L"/help") || !_wcsicmp(tok, L"--help"))
            return FALSE;
        if (!_wcsicmp(tok, L"/quiet"))
            g_Opt.Quiet = TRUE;
        else if (!_wcsicmp(tok, L"/nodump"))
            g_Opt.NoDump = TRUE;
        else if (!_wcsicmp(tok, L"/nosnaps"))
            g_Opt.NoSnaps = TRUE;
        else if (!_wcsicmp(tok, L"/screenshot"))
            g_Opt.Screenshot = TRUE;
        else if (!_wcsicmp(tok, L"/raw"))
            g_Opt.Raw = TRUE;
        else if (!_wcsicmp(tok, L"/pick"))
            g_Opt.Pick = TRUE;
        else if (!_wcsicmp(tok, L"/gui"))
            g_Opt.Gui = TRUE;       /* dialogs instead of console text (the Explorer verb and the Start menu pass it) */
        else if (!_wcsicmp(tok, L"/imports"))
            g_Opt.Imports = TRUE;
        else if (!_wcsicmp(tok, L"/out") || !_wcsicmp(tok, L"/zip") || !_wcsicmp(tok, L"/timeout") || !_wcsicmp(tok, L"/attach"))
        {
            WCHAR val[MAX_PATH];
            next = Token(next, val, _countof(val));
            if (!val[0])
                return FALSE;
            if (!_wcsicmp(tok, L"/out"))
                StringCchCopyW(g_Opt.OutDir, _countof(g_Opt.OutDir), val);
            else if (!_wcsicmp(tok, L"/zip"))
                StringCchCopyW(g_Opt.OutZip, _countof(g_Opt.OutZip), val);
            else if (!_wcsicmp(tok, L"/timeout"))
                g_Opt.TimeoutSec = (DWORD)_wtoi(val);
            else
                g_Opt.AttachPid = (DWORD)_wtoi(val);
        }
        else
        {
            Say(L"unknown option %s (nitrodiag /? lists them)\r\n", tok);
            return FALSE;
        }
        p = next;
    }

    p = SkipSpace(p);
    if (*p)
    {
        /* the rest, exactly as typed: the program and its arguments */
        g_Opt.CmdLine = _wcsdup(p);
        Token(p, g_Opt.Target, _countof(g_Opt.Target));
    }
    return g_Opt.CmdLine || g_Opt.AttachPid || g_Opt.Pick;
}

/* ---- a .lnk as the program ---- */

static BOOL ResolveLnk(const WCHAR *lnk, WCHAR *cmd, size_t cchCmd, WCHAR *target, WCHAR *workdir)
{
    IShellLinkW *sl = NULL;
    IPersistFile *pf = NULL;
    WCHAR args[2048], raw[MAX_PATH], exp[MAX_PATH];
    BOOL ok = FALSE;
    HRESULT hr;

    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl);
    if (FAILED(hr))
        return FALSE;
    hr = IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf);
    if (SUCCEEDED(hr) && SUCCEEDED(IPersistFile_Load(pf, lnk, STGM_READ)))
    {
        IShellLinkW_Resolve(sl, NULL, SLR_NO_UI | SLR_NOUPDATE | SLR_NOSEARCH);
        raw[0] = 0;
        args[0] = 0;
        workdir[0] = 0;
        if (SUCCEEDED(IShellLinkW_GetPath(sl, raw, _countof(raw), NULL, SLGP_RAWPATH)) && raw[0])
        {
            ExpandEnvironmentStringsW(raw, exp, _countof(exp));
            IShellLinkW_GetArguments(sl, args, _countof(args));
            IShellLinkW_GetWorkingDirectory(sl, raw, _countof(raw));
            ExpandEnvironmentStringsW(raw, workdir, MAX_PATH);
            StringCchCopyW(target, MAX_PATH, exp);
            StringCchPrintfW(cmd, cchCmd, L"\"%s\"%s%s", exp, args[0] ? L" " : L"", args);
            ok = TRUE;
        }
    }
    if (pf)
        IPersistFile_Release(pf);
    IShellLinkW_Release(sl);
    return ok;
}

/* ---- dialogs ---- */

static INT_PTR CALLBACK StatusProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            WCHAR t[MAX_PATH + 200];
            StringCchPrintfW(t, _countof(t), L"Collecting the compatibility log for:\r\n%s\r\n\r\nUse the program as you normally would. When it has closed the report is saved by itself. "
                             L"If it hangs, press \"Save report now\".", g_Opt.Target[0] ? g_Opt.Target : L"(program)");
            SetDlgItemTextW(hwnd, IDC_STATUSTEXT, t);
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDC_FINISH || LOWORD(wp) == IDCANCEL)
            {
                g_Finish = TRUE;
                return TRUE;
            }
            break;
        case WM_CLOSE:
            g_Finish = TRUE;
            return TRUE;
    }
    return FALSE;
}

void ShowStatusWindow(BOOL show)
{
    if (show && !g_hStatus)
    {
        g_hStatus = CreateDialogParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_STATUS), NULL, StatusProc, 0);
        if (g_hStatus)
            ShowWindow(g_hStatus, SW_SHOWNORMAL);
    }
    else if (!show && g_hStatus)
    {
        DestroyWindow(g_hStatus);
        g_hStatus = NULL;
    }
}

/* FALSE when the user asked to finish */
BOOL PumpStatusWindow(void)
{
    MSG msg;
    if (!g_hStatus)
        return TRUE;
    while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
    {
        if (!IsDialogMessageW(g_hStatus, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return !g_Finish;
}

static INT_PTR CALLBACK DoneProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_INITDIALOG:
        {
            WCHAR t[1600];
            StringCchPrintfW(t, _countof(t), L"%s\r\n\r\nReport saved to:\r\n%s\r\n\r\nThe report contains file paths, your user name and the command line you typed. "
                             L"Nothing was uploaded: send the file yourself if you want us to look at it.", g_Verdict, g_SavedPath);
            SetDlgItemTextW(hwnd, IDC_DONETEXT, t);
            return TRUE;
        }
        case WM_COMMAND:
            if (LOWORD(wp) == IDC_OPENFOLDER)
            {
                WCHAR arg[MAX_PATH + 20];
                StringCchPrintfW(arg, _countof(arg), L"/select,\"%s\"", g_SavedPath);
                ShellExecuteW(hwnd, L"open", L"explorer.exe", arg, NULL, SW_SHOWNORMAL);
                EndDialog(hwnd, IDC_OPENFOLDER);
                return TRUE;
            }
            if (LOWORD(wp) == IDCANCEL || LOWORD(wp) == IDOK)
            {
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

static INT_PTR CALLBACK PickProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_INITDIALOG:
            return TRUE;
        case WM_COMMAND:
            if (LOWORD(wp) == IDC_BROWSE)
            {
                OPENFILENAMEW ofn;
                WCHAR file[MAX_PATH] = L"";
                ZeroMemory(&ofn, sizeof(ofn));
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFilter = L"Programs (*.exe;*.lnk;*.bat;*.cmd)\0*.exe;*.lnk;*.bat;*.cmd\0All files (*.*)\0*.*\0\0";
                ofn.lpstrFile = file;
                ofn.nMaxFile = _countof(file);
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NODEREFERENCELINKS;
                if (GetOpenFileNameW(&ofn))
                    SetDlgItemTextW(hwnd, IDC_PICKPATH, file);
                return TRUE;
            }
            if (LOWORD(wp) == IDOK)
            {
                WCHAR path[MAX_PATH], args[1024], cmd[MAX_PATH + 1100];
                GetDlgItemTextW(hwnd, IDC_PICKPATH, path, _countof(path));
                GetDlgItemTextW(hwnd, IDC_PICKARGS, args, _countof(args));
                if (!path[0])
                    return TRUE;
                /* the path may have been typed with its own quotes */
                if (path[0] == L'"')
                {
                    size_t n = wcslen(path);
                    memmove(path, path + 1, n * sizeof(WCHAR));
                    n = wcslen(path);
                    if (n && path[n - 1] == L'"')
                        path[n - 1] = 0;
                }
                StringCchPrintfW(cmd, _countof(cmd), L"\"%s\"%s%s", path, args[0] ? L" " : L"", args);
                g_Opt.CmdLine = _wcsdup(cmd);
                StringCchCopyW(g_Opt.Target, _countof(g_Opt.Target), path);
                EndDialog(hwnd, IDOK);
                return TRUE;
            }
            if (LOWORD(wp) == IDCANCEL)
            {
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}

/* ---- screenshot ---- */

BOOL TakeScreenshot(const WCHAR *file)
{
    int w = GetSystemMetrics(SM_CXSCREEN), h = GetSystemMetrics(SM_CYSCREEN);
    HDC sdc = GetDC(NULL), mdc;
    HBITMAP bmp, old;
    BITMAPINFO bi;
    BITMAPFILEHEADER bfh;
    BYTE *bits = NULL;
    DWORD bytes, wr;
    HANDLE hf;
    BOOL ok = FALSE;

    if (!sdc || w <= 0 || h <= 0)
        return FALSE;
    mdc = CreateCompatibleDC(sdc);
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    bi.bmiHeader.biCompression = BI_RGB;
    bmp = CreateDIBSection(sdc, &bi, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
    if (bmp && bits)
    {
        old = SelectObject(mdc, bmp);
        BitBlt(mdc, 0, 0, w, h, sdc, 0, 0, SRCCOPY);
        SelectObject(mdc, old);
        bytes = ((w * 3 + 3) & ~3) * h;
        ZeroMemory(&bfh, sizeof(bfh));
        bfh.bfType = 0x4D42;
        bfh.bfOffBits = sizeof(bfh) + sizeof(BITMAPINFOHEADER);
        bfh.bfSize = bfh.bfOffBits + bytes;
        hf = CreateFileW(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE)
        {
            ok = WriteFile(hf, &bfh, sizeof(bfh), &wr, NULL) && WriteFile(hf, &bi.bmiHeader, sizeof(BITMAPINFOHEADER), &wr, NULL) &&
                 WriteFile(hf, bits, bytes, &wr, NULL);
            CloseHandle(hf);
        }
    }
    if (bmp)
        DeleteObject(bmp);
    DeleteDC(mdc);
    ReleaseDC(NULL, sdc);
    return ok;
}

/* ---- the zip ---- */

static BOOL ZipAddBuffer(zipFile zf, const char *name, const BYTE *data, DWORD len)
{
    zip_fileinfo zi;
    SYSTEMTIME st;
    ZeroMemory(&zi, sizeof(zi));
    GetLocalTime(&st);
    zi.tmz_date.tm_year = st.wYear;
    zi.tmz_date.tm_mon = st.wMonth - 1;
    zi.tmz_date.tm_mday = st.wDay;
    zi.tmz_date.tm_hour = st.wHour;
    zi.tmz_date.tm_min = st.wMinute;
    zi.tmz_date.tm_sec = st.wSecond;
    if (zipOpenNewFileInZip(zf, name, &zi, NULL, 0, NULL, 0, NULL, Z_DEFLATED, Z_DEFAULT_COMPRESSION) != ZIP_OK)
        return FALSE;
    if (len && zipWriteInFileInZip(zf, data, len) != ZIP_OK)
    {
        zipCloseFileInZip(zf);
        return FALSE;
    }
    return zipCloseFileInZip(zf) == ZIP_OK;
}

static BOOL ZipAddFile(zipFile zf, const char *name, const WCHAR *path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD size, got;
    BYTE *buf;
    BOOL ok = FALSE;
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    size = GetFileSize(h, NULL);
    buf = HeapAlloc(GetProcessHeap(), 0, size ? size : 1);
    if (buf && ReadFile(h, buf, size, &got, NULL) && got == size)
        ok = ZipAddBuffer(zf, name, buf, size);
    if (buf)
        HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(h);
    return ok;
}

BOOL SaveZip(const WCHAR *zipPath, const BYTE *report, DWORD reportLen)
{
    zlib_filefunc64_def ff;
    zipFile zf;
    BOOL ok;
    int i;
    WCHAR shot[MAX_PATH];

    fill_win32_filefunc64W(&ff);
    zf = zipOpen2_64(zipPath, APPEND_STATUS_CREATE, NULL, &ff);
    if (!zf)
        return FALSE;
    ok = ZipAddBuffer(zf, "report.txt", report, reportLen);
    for (i = 0; i < g_Res.nDumps; i++)
    {
        char nm[64];
        const WCHAR *n = NULL;
        int c;
        for (c = 0; c < g_Res.nCrash; c++)
            if (g_Res.Crash[c].DumpName[0] && wcsstr(g_Res.DumpFiles[i], L"") )
                n = g_Res.Crash[c].DumpName;
        if (n)
            StringCchPrintfA(nm, sizeof(nm), "%S", n);
        else
            StringCchPrintfA(nm, sizeof(nm), "crash-%d.dmp", i);
        ZipAddFile(zf, nm, g_Res.DumpFiles[i]);
    }
    if (g_Opt.Screenshot)
    {
        GetTempPathW(_countof(shot), shot);
        StringCchCatW(shot, _countof(shot), L"nitrodiag-screen.bmp");
        if (TakeScreenshot(shot))
        {
            ZipAddFile(zf, "screenshot.bmp", shot);
            DeleteFileW(shot);
        }
    }
    return zipClose(zf, NULL) == ZIP_OK && ok;
}

void MakeReportName(WCHAR *out, size_t cch)
{
    SYSTEMTIME st;
    WCHAR base[MAX_PATH], dir[MAX_PATH];
    WCHAR *dot;
    if (g_Opt.OutZip[0])
    {
        StringCchCopyW(out, cch, g_Opt.OutZip);
        return;
    }
    const WCHAR *src = g_Opt.AttachPid ? L"process" : g_Opt.Target;
    const WCHAR *slash = wcsrchr(src, L'\\');

    StringCchCopyW(base, _countof(base), slash ? slash + 1 : src);
    dot = wcsrchr(base, L'.');
    if (dot)
        *dot = 0;
    /* only characters safe in a file name */
    for (dot = base; *dot; dot++)
        if (!iswalnum(*dot) && *dot != L'-' && *dot != L'_')
            *dot = L'_';
    if (g_Opt.OutDir[0])
        StringCchCopyW(dir, _countof(dir), g_Opt.OutDir);
    else if (FAILED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, dir)))
        GetTempPathW(_countof(dir), dir);
    GetLocalTime(&st);
    StringCchPrintfW(out, cch, L"%s\\NitroDiag-%s-%04u%02u%02u-%02u%02u%02u.zip", dir, base[0] ? base : L"report",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/* ---- main ---- */

static BOOL LoaderishExit(DWORD c)
{
    return c == 0xC0000135 || c == ND_STATUS_ENTRYPOINT_NOT_FOUND || c == ND_STATUS_ORDINAL_NOT_FOUND ||
           c == ND_STATUS_INVALID_IMAGE_FORMAT || c == ND_STATUS_DLL_INIT_FAILED || (c & 0xFFFF0000) == 0xC0150000;
}

static int AppMain(void)
{
    WBUF report = {0};
    char *utf8;
    int u8len;
    WCHAR zipPath[MAX_PATH];
    BYTE *buf;
    ND_PROC *root = NULL;
    int i;
    BOOL runImports;

    if (g_Opt.Pick)
    {
        if (DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_PICK), NULL, PickProc, 0) != IDOK || !g_Opt.CmdLine)
            return 2;
    }

    if (g_Opt.AttachPid)
    {
        StringCchPrintfW(g_Opt.Target, _countof(g_Opt.Target), L"process %lu", g_Opt.AttachPid);
    }
    else
    {
        WCHAR found[MAX_PATH], full[MAX_PATH], *part;
        const WCHAR *ext = wcsrchr(g_Opt.Target, L'.');

        if (ext && !_wcsicmp(ext, L".lnk"))
        {
            WCHAR cmd[MAX_PATH + 2300], tgt[MAX_PATH];
            if (GetFullPathNameW(g_Opt.Target, _countof(full), full, &part) && ResolveLnk(full, cmd, _countof(cmd), tgt, g_Opt.WorkDir))
            {
                free(g_Opt.CmdLine);
                g_Opt.CmdLine = _wcsdup(cmd);
                StringCchCopyW(g_Opt.Target, _countof(g_Opt.Target), tgt);
            }
        }
        if (SearchPathW(NULL, g_Opt.Target, L".exe", _countof(found), found, NULL))
            StringCchCopyW(g_Opt.Target, _countof(g_Opt.Target), found);
        else if (GetFullPathNameW(g_Opt.Target, _countof(full), full, &part))
            StringCchCopyW(g_Opt.Target, _countof(g_Opt.Target), full);
    }

    if (g_Opt.Gui && !g_Opt.Quiet)
        ShowStatusWindow(TRUE);

    TraceRun();
    ShowStatusWindow(FALSE);

    for (i = 0; i < g_nProcs; i++)
        if (g_Procs[i].IsRoot)
            root = &g_Procs[i];
    if (!root && g_nProcs)
        root = &g_Procs[0];

    runImports = g_Opt.Imports || g_Res.nLdrErr || (root && root->Exited && LoaderishExit(root->ExitCode)) ||
                 (g_Res.CreateFailed && g_Res.CreateError == ERROR_BAD_EXE_FORMAT);
    if (runImports && !g_Opt.AttachPid && g_Opt.Target[0] && GetFileAttributesW(g_Opt.Target) != INVALID_FILE_ATTRIBUTES)
    {
        WORD mach = 0;
        BOOL is32 = FALSE;
        int problems = 0;
        if (PeMachine(g_Opt.Target, &mach))
            is32 = (mach == IMAGE_FILE_MACHINE_I386);
        else
        {
#ifdef _M_AMD64
            is32 = FALSE;
#else
            is32 = TRUE;
#endif
        }
        ImportsCheck(g_Opt.Target, is32, &g_Res.ImportReport, &problems);
    }

    BuildReport(&report);
    /* the first line, for the dialog */
    {
        WCHAR *eol = wcschr(report.p, L'\r');
        size_t n = eol ? (size_t)(eol - report.p) : wcslen(report.p);
        if (n >= _countof(g_Verdict))
            n = _countof(g_Verdict) - 1;
        memcpy(g_Verdict, report.p, n * sizeof(WCHAR));
        g_Verdict[n] = 0;
    }

    u8len = WideCharToMultiByte(CP_UTF8, 0, report.p, (int)report.len, NULL, 0, NULL, NULL);
    utf8 = HeapAlloc(GetProcessHeap(), 0, u8len + 4);
    buf = (BYTE *)utf8;
    buf[0] = 0xEF; buf[1] = 0xBB; buf[2] = 0xBF;
    WideCharToMultiByte(CP_UTF8, 0, report.p, (int)report.len, utf8 + 3, u8len, NULL, NULL);

    MakeReportName(zipPath, _countof(zipPath));
    if (g_Opt.OutDir[0] && !g_Opt.OutZip[0])
        CreateDirectoryW(g_Opt.OutDir, NULL);
    if (!SaveZip(zipPath, buf, u8len + 3))
    {
        /* no zip: leave the files side by side in a folder */
        WCHAR dir[MAX_PATH], f[MAX_PATH];
        HANDLE h;
        DWORD w;
        StringCchCopyW(dir, _countof(dir), zipPath);
        dir[wcslen(dir) - 4] = 0;
        CreateDirectoryW(dir, NULL);
        StringCchPrintfW(f, _countof(f), L"%s\\report.txt", dir);
        h = CreateFileW(f, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            WriteFile(h, buf, u8len + 3, &w, NULL);
            CloseHandle(h);
        }
        for (i = 0; i < g_Res.nDumps; i++)
        {
            StringCchPrintfW(f, _countof(f), L"%s\\crash-%d.dmp", dir, i);
            CopyFileW(g_Res.DumpFiles[i], f, FALSE);
        }
        StringCchCopyW(zipPath, _countof(zipPath), dir);
    }
    for (i = 0; i < g_Res.nDumps; i++)
        DeleteFileW(g_Res.DumpFiles[i]);
    StringCchCopyW(g_SavedPath, _countof(g_SavedPath), zipPath);
    HeapFree(GetProcessHeap(), 0, utf8);

    if (g_Opt.Gui && !g_Opt.Quiet)
        DialogBoxParamW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDD_DONE), NULL, DoneProc, 0);
    else
    {
        /* the first ten lines of the report are the verdict */
        {
            const WCHAR *l = report.p;
            int n;
            for (n = 0; n < 10 && l && *l; n++)
            {
                const WCHAR *e = wcschr(l, L'\r');
                Say(L"%.*s\r\n", e ? (int)(e - l) : (int)wcslen(l), l);
                l = e ? e + 2 : NULL;
            }
        }
        Say(L"Report saved to %s\r\n", zipPath);
    }
    return 0;
}

int wmain(int argc, WCHAR **argv)
{
    DWORD pl[4];
    int rc;

    (void)argc; (void)argv;
    CoInitialize(NULL);

    if (!ParseCommandLine())
    {
        Usage();
        return 1;
    }
    /* started from Explorer or the Start menu (no console of the caller): no console window, dialogs instead */
    if (g_Opt.Gui || GetConsoleProcessList(pl, _countof(pl)) == 1)
    {
        g_Opt.Gui = TRUE;
        FreeConsole();
    }
    if (g_Opt.Pick)
        g_Opt.Gui = TRUE;

    rc = AppMain();
    CoUninitialize();
    return rc;
}
