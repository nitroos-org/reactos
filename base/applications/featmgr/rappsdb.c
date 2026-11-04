/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The RAPPS online catalog, fetched by featmgr itself (rapps.exe is gone): download rappmgr2.cab from
 *              the address rapps used (certificate-pinned), extract its entries (*.txt) with the Cabinet FDI API
 *              into %SystemRoot%\Featmgr\RappsDb\appdb. Entry names are checked (no path, no "..") and files are
 *              created with CREATE_NEW in a fresh directory that replaces the old catalog only when complete.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <fdi.h>
#include <fcntl.h>

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

#define DB_MAX_FILES   100000
#define DB_MAX_BYTES   (256ull * 1024 * 1024)
#define DB_MAX_CAB     (64ull * 1024 * 1024)

BOOL FmGetRappsDbDir(LPWSTR buf, DWORD cch)
{
    WCHAR root[MAX_PATH];
    if (!FmGetRootDir(root, MAX_PATH)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(buf, cch, L"%s\\RappsDb\\appdb", root));
}

/* Delete a directory tree; a reparse point is removed, never entered. */
BOOL FmDeleteTree(LPCWSTR dir)
{
    WCHAR pat[MAX_PATH], p[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    DWORD a = GetFileAttributesW(dir);

    if (a == INVALID_FILE_ATTRIBUTES) return TRUE;
    if (!(a & FILE_ATTRIBUTE_DIRECTORY)) return DeleteFileW(dir);
    if (!(a & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        StringCchPrintfW(pat, MAX_PATH, L"%s\\*", dir);
        h = FindFirstFileW(pat, &fd);
        if (h != INVALID_HANDLE_VALUE)
        {
            do
            {
                if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
                StringCchPrintfW(p, MAX_PATH, L"%s\\%s", dir, fd.cFileName);
                if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                    FmDeleteTree(p);
                else
                {
                    SetFileAttributesW(p, FILE_ATTRIBUTE_NORMAL);
                    if (!DeleteFileW(p)) RemoveDirectoryW(p);
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
    SetFileAttributesW(dir, FILE_ATTRIBUTE_NORMAL);
    return RemoveDirectoryW(dir);
}

/* ---- FDI (cabinet.dll is loaded at run time, as rapps did: it takes narrow paths, we hand it UTF-8) ---------- */

typedef struct
{
    WCHAR   outDir[MAX_PATH];
    BOOL    tree;     /* keep sub-directories (an archive to install) instead of top-level *.txt only (the catalog) */
    int     files;
    ULONGLONG bytes;
    BOOL    failed;
} EXTRACTCTX;

static void Utf8ToWide(LPCSTR s, UINT cp, LPWSTR out, int cch)
{
    out[0] = L'\0';
    if (MultiByteToWideChar(cp, 0, s, -1, out, cch) <= 0) out[0] = L'\0';
}

FNALLOC(fnAlloc) { return HeapAlloc(GetProcessHeap(), 0, cb); }
FNFREE(fnFree) { HeapFree(GetProcessHeap(), 0, pv); }

FNOPEN(fnOpen)
{
    WCHAR w[MAX_PATH];
    DWORD acc = GENERIC_READ, disp = OPEN_EXISTING;
    HANDLE h;
    UNREFERENCED_PARAMETER(pmode);
    if (oflag & _O_RDWR) acc = GENERIC_READ | GENERIC_WRITE;
    else if (oflag & _O_WRONLY) acc = GENERIC_WRITE;
    if (oflag & _O_CREAT) disp = CREATE_NEW;          /* never replace or follow what is already there */
    Utf8ToWide(pszFile, CP_UTF8, w, MAX_PATH);
    h = CreateFileW(w, acc, FILE_SHARE_READ, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
    return h == INVALID_HANDLE_VALUE ? -1 : (INT_PTR)h;
}

FNREAD(fnRead)
{
    DWORD n = 0;
    return ReadFile((HANDLE)hf, pv, cb, &n, NULL) ? n : (UINT)-1;
}

FNWRITE(fnWrite)
{
    DWORD n = 0;
    return WriteFile((HANDLE)hf, pv, cb, &n, NULL) ? n : (UINT)-1;
}

FNCLOSE(fnClose) { return CloseHandle((HANDLE)hf) ? 0 : -1; }

FNSEEK(fnSeek) { return SetFilePointer((HANDLE)hf, dist, NULL, seektype); }

/* A catalog entry is a top-level "<name>.txt": no directory part, no stream, no device name. */
static BOOL SafeEntryName(LPWSTR name)
{
    size_t n = wcslen(name), i;
    if (!n || n > 100 || name[0] == L'.') return FALSE;
    if (n < 5 || _wcsicmp(name + n - 4, L".txt")) return FALSE;
    for (i = 0; i < n; i++)
        if (name[i] < 32 || wcschr(L"\\/:*?\"<>|", name[i])) return FALSE;
    return TRUE;
}

/* a relative path inside an archive: no drive, no stream, no ".." and no leading separator; '/' becomes '\\' */
BOOL FmSafeTreeName(LPWSTR name)
{
    WCHAR *p, *comp;
    size_t n = wcslen(name);

    if (!n || n > 220) return FALSE;
    for (p = name; *p; p++)
    {
        if (*p == L'/') *p = L'\\';
        if (*p < 32 || wcschr(L":*?\"<>|", *p)) return FALSE;
    }
    if (name[0] == L'\\') return FALSE;
    for (comp = name; ; )
    {
        size_t l = wcscspn(comp, L"\\");
        if (l == 0 || (l == 1 && comp[0] == L'.') || (l == 2 && comp[0] == L'.' && comp[1] == L'.')) return FALSE;
        /* Windows drops a trailing space or dot ("App " and "App." are "App"): such a name would alias another one */
        if (comp[l - 1] == L' ' || comp[l - 1] == L'.') return FALSE;
        if (!comp[l]) break;
        comp += l + 1;
        if (!*comp) return FALSE;
    }
    return TRUE;
}

/* create the directories above file (below base, which exists) */
BOOL FmMakeParents(LPCWSTR base, LPCWSTR rel)
{
    WCHAR p[MAX_PATH];
    size_t bl = wcslen(base), i;

    if (FAILED(StringCchPrintfW(p, MAX_PATH, L"%s\\%s", base, rel))) return FALSE;
    for (i = bl + 1; p[i]; i++)
    {
        if (p[i] == L'\\')
        {
            p[i] = L'\0';
            if (!CreateDirectoryW(p, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) return FALSE;
            p[i] = L'\\';
        }
    }
    return TRUE;
}

FNFDINOTIFY(fnNotify)
{
    EXTRACTCTX *x = (EXTRACTCTX *)pfdin->pv;

    switch (fdint)
    {
        case fdintCOPY_FILE:
        {
            WCHAR name[MAX_PATH], full[MAX_PATH];
            char u8[MAX_PATH * 3];
            UINT cp = (pfdin->attribs & _A_NAME_IS_UTF) ? CP_UTF8 : CP_ACP;
            Utf8ToWide(pfdin->psz1, cp, name, MAX_PATH);
            if (x->tree ? !FmSafeTreeName(name) : !SafeEntryName(name)) return 0;   /* the catalog: icons, screenshots, anything else is skipped */
            if (x->tree && !FmMakeParents(x->outDir, name)) return 0;
            if (x->files >= DB_MAX_FILES || x->bytes + pfdin->cb > DB_MAX_BYTES) { x->failed = TRUE; return -1; }
            StringCchPrintfW(full, MAX_PATH, L"%s\\%s", x->outDir, name);
            if (WideCharToMultiByte(CP_UTF8, 0, full, -1, u8, sizeof(u8), NULL, NULL) <= 0) return 0;
            {
                INT_PTR h = fnOpen(u8, _O_WRONLY | _O_CREAT, 0);
                if (h == -1) return 0;                           /* a duplicate name: the first one stays */
                x->files++;
                x->bytes += pfdin->cb;
                return h;
            }
        }
        case fdintCLOSE_FILE_INFO:
            return fnClose(pfdin->hf) == 0;
        case fdintNEXT_CABINET:
            return pfdin->fdie != FDIERROR_NONE ? -1 : 0;
        case fdintPARTIAL_FILE:
        case fdintCABINET_INFO:
        case fdintENUMERATE:
            return 0;
        default:
            return -1;
    }
}

typedef HFDI (*PFN_FDICreate)(PFNALLOC, PFNFREE, PFNOPEN, PFNREAD, PFNWRITE, PFNCLOSE, PFNSEEK, int, PERF);
typedef BOOL (*PFN_FDICopy)(HFDI, LPSTR, LPSTR, INT, PFNFDINOTIFY, PFNFDIDECRYPT, void *);
typedef BOOL (*PFN_FDIDestroy)(HFDI);

BOOL FmExtractCab(LPCWSTR cabFile, LPCWSTR outDir, BOOL tree, int *count)
{
    HMODULE hCab = LoadLibraryW(L"cabinet.dll");
    PFN_FDICreate pCreate;
    PFN_FDICopy pCopy;
    PFN_FDIDestroy pDestroy;
    HFDI fdi;
    ERF erf;
    EXTRACTCTX x;
    WCHAR dir[MAX_PATH];
    char cabName[MAX_PATH * 3], cabDir[MAX_PATH * 3];
    LPCWSTR slash = wcsrchr(cabFile, L'\\');
    BOOL ok = FALSE;

    *count = 0;
    if (!hCab || !slash) return FALSE;
    pCreate = (PFN_FDICreate)GetProcAddress(hCab, "FDICreate");
    pCopy = (PFN_FDICopy)GetProcAddress(hCab, "FDICopy");
    pDestroy = (PFN_FDIDestroy)GetProcAddress(hCab, "FDIDestroy");
    if (!pCreate || !pCopy || !pDestroy) { FreeLibrary(hCab); return FALSE; }
    ZeroMemory(&x, sizeof(x));
    StringCchCopyW(x.outDir, MAX_PATH, outDir);
    x.tree = tree;
    StringCchCopyNW(dir, MAX_PATH, cabFile, (size_t)(slash - cabFile));
    cabName[0] = '\\';
    if (WideCharToMultiByte(CP_UTF8, 0, slash + 1, -1, cabName + 1, sizeof(cabName) - 1, NULL, NULL) <= 0 ||
        WideCharToMultiByte(CP_UTF8, 0, dir, -1, cabDir, sizeof(cabDir), NULL, NULL) <= 0)
    { FreeLibrary(hCab); return FALSE; }
    fdi = pCreate(fnAlloc, fnFree, fnOpen, fnRead, fnWrite, fnClose, fnSeek, cpuUNKNOWN, &erf);
    if (fdi)
    {
        ok = pCopy(fdi, cabName, cabDir, 0, fnNotify, NULL, &x) && !x.failed;
        pDestroy(fdi);
    }
    FreeLibrary(hCab);
    *count = x.files;
    return ok;
}

static BOOL EnsureDir(LPCWSTR d)
{
    return CreateDirectoryW(d, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

/* Download (or take from a local file) the catalog cab and make it the current catalog. urlOverride NULL: the official address,
 * or FEATMGR_RAPPS_DB (a LOCAL cab path, never an address) when that variable is set - the tests use it. */
HRESULT FmRappsFetchDb(LPCWSTR urlOverride, FILE *log)
{
    WCHAR root[MAX_PATH], base[MAX_PATH], cab[MAX_PATH], tmpDir[MAX_PATH], dbDir[MAX_PATH], oldDir[MAX_PATH], env[MAX_PATH * 2];
    LPCWSTR url = urlOverride;
    HRESULT hr;
    int count = 0;
    BOOL local;

    if (!url || !url[0])
    {
        /* FEATMGR_RAPPS_DB: a catalog cab that is already on this disk (the tests use it). Never an address. */
        if (GetEnvironmentVariableW(L"FEATMGR_RAPPS_DB", env, ARRAYSIZE(env)) && env[0]) url = env;
        else url = FM_RAPPS_DB_URL;
    }
    /* The catalog carries every download address and hash, so whoever supplies it decides what runs as administrator: it comes
     * only from the official address over https with the certificate pin, or from a local file. Any other address is refused. */
    if (!_wcsnicmp(url, L"http:", 5) || !_wcsnicmp(url, L"https:", 6) || !_wcsnicmp(url, L"ftp:", 4) || !_wcsnicmp(url, L"file:", 5))
    {
        if (_wcsicmp(url, FM_RAPPS_DB_URL))
        {
            FmSetLastMessage(L"Refused: the RAPPS catalog is only downloaded from %s (https, certificate pinned); %s is not accepted. "
                             L"A local cab file can be given instead.", FM_RAPPS_DB_URL, url);
            LOGF(log, L"error: catalog address %s refused (only the official address, or a local file)\n", url);
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        }
    }
    /* a local catalog is a file on a local drive letter ("X:\..."): no UNC or device path, which would be read over SMB */
    if (_wcsnicmp(url, L"https://", 8) && !(((url[0] | 0x20) >= L'a' && (url[0] | 0x20) <= L'z') && url[1] == L':' && (url[2] == L'\\' || url[2] == L'/')))
    {
        FmSetLastMessage(L"Refused: a local RAPPS catalog must be a file on a drive letter (X:\\...); %s is not accepted.", url);
        LOGF(log, L"error: catalog path %s refused (not a drive-letter path)\n", url);
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }
    if (!FmGetRootDir(root, MAX_PATH)) return E_FAIL;
    StringCchPrintfW(base, MAX_PATH, L"%s\\RappsDb", root);
    StringCchPrintfW(cab, MAX_PATH, L"%s\\rappmgr2.cab", base);
    StringCchPrintfW(tmpDir, MAX_PATH, L"%s\\appdb.new", base);
    StringCchPrintfW(oldDir, MAX_PATH, L"%s\\appdb.old", base);
    StringCchPrintfW(dbDir, MAX_PATH, L"%s\\appdb", base);
    if (!EnsureDir(root) || !EnsureDir(base))
    {
        FmSetLastMessage(L"Cannot create %s (error %lu).", base, GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    local = _wcsnicmp(url, L"https://", 8) != 0;
    FmOpStep(L"Downloading the RAPPS catalog from %s", local ? L"a local file" : url);
    if (local)
    {
        if (!CopyFileW(url, cab, FALSE))
        {
            FmSetLastMessage(L"Cannot read the catalog file %s (error %lu).", url, GetLastError());
            return HRESULT_FROM_WIN32(GetLastError());
        }
        hr = S_OK;
    }
    else
        hr = FmDownloadFile(url, cab, TRUE, DB_MAX_CAB, log);
    if (FAILED(hr)) return hr;

    if (FmOpCancelled()) { DeleteFileW(cab); FmSetLastMessage(L"The operation was cancelled."); return HRESULT_FROM_WIN32(ERROR_CANCELLED); }
    FmOpStep(L"Unpacking the RAPPS catalog");
    FmDeleteTree(tmpDir);
    if (!CreateDirectoryW(tmpDir, NULL))
    {
        FmSetLastMessage(L"Cannot create %s (error %lu).", tmpDir, GetLastError());
        DeleteFileW(cab);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (!FmExtractCab(cab, tmpDir, FALSE, &count) || count < 1)
    {
        FmSetLastMessage(L"The downloaded RAPPS catalog could not be unpacked (%d entries read). The old catalog was kept.", count);
        LOGF(log, L"error: the RAPPS catalog cab could not be unpacked (%d entries)\n", count);
        FmDeleteTree(tmpDir);
        DeleteFileW(cab);
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }
    DeleteFileW(cab);
    /* swap in: the old catalog is moved aside first, so a failure leaves one of the two in place */
    FmDeleteTree(oldDir);
    if (GetFileAttributesW(dbDir) != INVALID_FILE_ATTRIBUTES && !MoveFileW(dbDir, oldDir))
    {
        FmSetLastMessage(L"Cannot replace the old catalog (error %lu).", GetLastError());
        FmDeleteTree(tmpDir);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    if (!MoveFileW(tmpDir, dbDir))
    {
        DWORD e = GetLastError();
        MoveFileW(oldDir, dbDir);
        FmSetLastMessage(L"Cannot put the new catalog in place (error %lu).", e);
        return HRESULT_FROM_WIN32(e);
    }
    FmDeleteTree(oldDir);
    LOGF(log, L"RAPPS catalog: %d entries in %s\n", count, dbDir);
    return S_OK;
}
