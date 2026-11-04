/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Component list (components.ini): detect rule, verified download (wininet + SHA-256), install line.
 *              Shared by the engine (Provider=component), the "Installing additional components" window and the
 *              first-boot installer. Nothing from Microsoft is bundled: the files are fetched at install time.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "featmgr.h"
#include <wininet.h>
#include <wincrypt.h>
#include <shlwapi.h>
#include <strsafe.h>

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

/* ---- the data file ------------------------------------------------------- */

static BOOL CompFile(LPWSTR out, DWORD cch)
{
    WCHAR root[MAX_PATH];
    if (GetEnvironmentVariableW(L"FEATMGR_COMPONENTS", out, cch) && out[0])
        return TRUE;
    if (!FmGetRootDir(root, MAX_PATH)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\Catalog\\components.ini", root));
}

static void ReadKey(LPCWSTR file, LPCWSTR sec, LPCWSTR key, LPWSTR out, DWORD cch)
{
    GetPrivateProfileStringW(sec, key, L"", out, cch, file);
}

/* "x86,amd64" lists this build's architecture (no Arch= = every architecture; i386 is a synonym of x86) */
BOOL FmArchListed(LPCWSTR list)
{
#ifdef _WIN64
    static const WCHAR me[] = L"amd64";
#else
    static const WCHAR me[] = L"x86";
#endif
    WCHAR tmp[64], *tok, *ctx = NULL;
    if (!list[0]) return TRUE;
    StringCchCopyW(tmp, ARRAYSIZE(tmp), list);
    for (tok = wcstok_s(tmp, L", ", &ctx); tok; tok = wcstok_s(NULL, L", ", &ctx))
    {
        if (!_wcsicmp(tok, me)) return TRUE;
#ifndef _WIN64
        if (!_wcsicmp(tok, L"i386")) return TRUE;
#endif
    }
    return FALSE;
}

static BOOL LoadSection(LPCWSTR file, LPCWSTR id, FM_COMPONENT *c)
{
    WCHAR tmp[512];

    ZeroMemory(c, sizeof(*c));
    ReadKey(file, id, L"Name", c->Name, ARRAYSIZE(c->Name));
    ReadKey(file, id, L"Url", c->Url, ARRAYSIZE(c->Url));
    if (!c->Name[0] && !c->Url[0]) return FALSE;                 /* no such section */
    StringCchCopyW(c->Id, ARRAYSIZE(c->Id), id);
    if (!c->Name[0]) StringCchCopyW(c->Name, ARRAYSIZE(c->Name), id);
    ReadKey(file, id, L"Sha256", c->Sha256, ARRAYSIZE(c->Sha256));
    ReadKey(file, id, L"FileName", c->FileName, ARRAYSIZE(c->FileName));
    if (!c->FileName[0]) StringCchPrintfW(c->FileName, ARRAYSIZE(c->FileName), L"%s.bin", id);
    ReadKey(file, id, L"DetectReg", c->DetectReg, ARRAYSIZE(c->DetectReg));
    ReadKey(file, id, L"DetectFile", c->DetectFile, ARRAYSIZE(c->DetectFile));
    ReadKey(file, id, L"Install", c->Install, ARRAYSIZE(c->Install));
#ifdef _WIN64
    ReadKey(file, id, L"Uninstall.amd64", c->Uninstall, ARRAYSIZE(c->Uninstall));
#else
    ReadKey(file, id, L"Uninstall.x86", c->Uninstall, ARRAYSIZE(c->Uninstall));
#endif
    if (!c->Uninstall[0]) ReadKey(file, id, L"Uninstall", c->Uninstall, ARRAYSIZE(c->Uninstall));
    ReadKey(file, id, L"SizeBytes", tmp, ARRAYSIZE(tmp));
    c->Size = tmp[0] ? _wcstoui64(tmp, NULL, 10) : 0;
    ReadKey(file, id, L"Default", tmp, ARRAYSIZE(tmp));
    c->Default = _wtoi(tmp) != 0;
    ReadKey(file, id, L"Arch", tmp, ARRAYSIZE(tmp));
    c->ArchOk = FmArchListed(tmp);
    return TRUE;
}

BOOL FmCompLoad(LPCWSTR id, FM_COMPONENT *c)
{
    WCHAR file[MAX_PATH];
    if (!id || !id[0] || wcspbrk(id, L"[]=\r\n")) return FALSE;
    if (!CompFile(file, ARRAYSIZE(file)) || GetFileAttributesW(file) == INVALID_FILE_ATTRIBUTES) return FALSE;
    return LoadSection(file, id, c);
}

int FmCompEnum(FM_COMPONENT **outArr)
{
    WCHAR file[MAX_PATH];
    WCHAR *names, *p;
    DWORD cch = 16384, n;
    FM_COMPONENT *arr;
    int count = 0;

    *outArr = NULL;
    if (!CompFile(file, ARRAYSIZE(file)) || GetFileAttributesW(file) == INVALID_FILE_ATTRIBUTES) return 0;
    for (;;)
    {
        names = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, cch * sizeof(WCHAR));
        if (!names) return 0;
        n = GetPrivateProfileSectionNamesW(names, cch, file);
        if (n < cch - 2) break;
        HeapFree(GetProcessHeap(), 0, names);
        if (cch >= 1024 * 1024) return 0;
        cch *= 4;
    }
    arr = (FM_COMPONENT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32 * sizeof(FM_COMPONENT));
    if (!arr) { HeapFree(GetProcessHeap(), 0, names); return 0; }
    for (p = names; *p && count < 32; p += wcslen(p) + 1)
        if (LoadSection(file, p, &arr[count])) count++;
    HeapFree(GetProcessHeap(), 0, names);
    *outArr = arr;
    return count;
}

void FmCompFree(FM_COMPONENT *arr)
{
    if (arr) HeapFree(GetProcessHeap(), 0, arr);
}

/* ---- detect rule --------------------------------------------------------- */

static BOOL DetectRegRule(LPCWSTR rule)
{
    WCHAR tmp[320], *key, *val, *cmp, *ctx = NULL, *sub;
    HKEY hk;
    DWORD type, data = 0, cb = sizeof(data);
    LONG rc;
    BOOL ok = FALSE;
    REGSAM sam = KEY_QUERY_VALUE;

    if (!rule[0]) return FALSE;
    StringCchCopyW(tmp, ARRAYSIZE(tmp), rule);
    key = wcstok_s(tmp, L"|", &ctx);
    val = wcstok_s(NULL, L"|", &ctx);
    cmp = wcstok_s(NULL, L"|", &ctx);
    if (!key || !val) return FALSE;
    if (_wcsnicmp(key, L"HKLM\\", 5)) return FALSE;              /* machine-wide components only */
    sub = key + 5;
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, sam, &hk);
    if (rc != ERROR_SUCCESS) return FALSE;
    if (!cmp)
    {
        ok = RegQueryValueExW(hk, val, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
    }
    else if (RegQueryValueExW(hk, val, NULL, &type, (LPBYTE)&data, &cb) == ERROR_SUCCESS && type == REG_DWORD)
    {
        if (!wcsncmp(cmp, L">=", 2)) ok = data >= (DWORD)wcstoul(cmp + 2, NULL, 10);
        else if (!wcsncmp(cmp, L"=", 1)) ok = data == (DWORD)wcstoul(cmp + 1, NULL, 10);
    }
    RegCloseKey(hk);
    return ok;
}

BOOL FmCompDetect(const FM_COMPONENT *c)
{
    WCHAR p[MAX_PATH];
    if (DetectRegRule(c->DetectReg)) return TRUE;
    if (c->DetectFile[0] && ExpandEnvironmentStringsW(c->DetectFile, p, ARRAYSIZE(p)) &&
        GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    return FALSE;
}

void FmCompInstallLine(const FM_COMPONENT *c, LPCWSTR file, LPWSTR out, DWORD cch)
{
    WCHAR quoted[MAX_PATH + 4], raw[1024];
    const WCHAR *p = c->Install;
    size_t n = 0;

    StringCchPrintfW(quoted, ARRAYSIZE(quoted), L"\"%s\"", file);
    raw[0] = L'\0';
    while (*p && n + 2 < ARRAYSIZE(raw))
    {
        if (!_wcsnicmp(p, L"%FILE%", 6))
        {
            size_t l = wcslen(quoted);
            if (n + l + 2 >= ARRAYSIZE(raw)) break;
            memcpy(raw + n, quoted, l * sizeof(WCHAR));
            n += l;
            p += 6;
        }
        else
            raw[n++] = *p++;
    }
    raw[n] = L'\0';
    if (!ExpandEnvironmentStringsW(raw, out, cch))
        StringCchCopyW(out, cch, raw);
}

/* ---- SHA-256 -------------------------------------------------------------- */

typedef struct { HCRYPTPROV prov; HCRYPTHASH hash; } SHA256_CTX_;

static BOOL ShaBegin(SHA256_CTX_ *s)
{
    s->prov = 0; s->hash = 0;
    if (!CryptAcquireContextW(&s->prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if (!CryptCreateHash(s->prov, CALG_SHA_256, 0, 0, &s->hash))
    {
        CryptReleaseContext(s->prov, 0);
        s->prov = 0;
        return FALSE;
    }
    return TRUE;
}

static void ShaAbort(SHA256_CTX_ *s)
{
    if (s->hash) CryptDestroyHash(s->hash);
    if (s->prov) CryptReleaseContext(s->prov, 0);
    s->hash = 0; s->prov = 0;
}

static BOOL ShaEnd(SHA256_CTX_ *s, WCHAR hex[65])
{
    BYTE d[32];
    DWORD cb = sizeof(d), i;
    BOOL ok = CryptGetHashParam(s->hash, HP_HASHVAL, d, &cb, 0) && cb == sizeof(d);
    if (ok)
        for (i = 0; i < sizeof(d); i++) StringCchPrintfW(hex + 2 * i, 3, L"%02x", d[i]);
    ShaAbort(s);
    return ok;
}

BOOL FmFileSha256(LPCWSTR path, WCHAR hex[65])
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SHA256_CTX_ s;
    static BYTE buf[64 * 1024];            /* one hasher at a time: callers run on one thread */
    DWORD got;
    BOOL ok = TRUE;

    if (f == INVALID_HANDLE_VALUE) return FALSE;
    if (!ShaBegin(&s)) { CloseHandle(f); return FALSE; }
    for (;;)
    {
        if (!ReadFile(f, buf, sizeof(buf), &got, NULL)) { ok = FALSE; break; }
        if (!got) break;
        if (!CryptHashData(s.hash, buf, got, 0)) { ok = FALSE; break; }
        if (FmOpCancelled()) { ok = FALSE; break; }
    }
    CloseHandle(f);
    if (!ok) { ShaAbort(&s); return FALSE; }
    return ShaEnd(&s, hex);
}

/* ---- wininet ---------------------------------------------------------------- */

/* no KEEP_CONNECTION: closing the request then drops the connection at once; with it wininet reads the rest of a
 * big response before the handle closes, and Cancel on a 1 GB download took 15 s to take effect */
#define DL_FLAGS (INTERNET_FLAG_DONT_CACHE | INTERNET_FLAG_PRAGMA_NOCACHE)
#define DL_ATTEMPTS 3
#define READ_TIMEOUT_MS 3000     /* one wait for data: Cancel is looked at between waits */
#define STALL_LIMIT 15           /* consecutive empty waits (45 s) before the download is given up */

static HINTERNET OpenNet(DWORD timeoutMs)
{
    HINTERNET h = InternetOpenW(L"NitroOS-featmgr/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (h)
    {
        InternetSetOptionW(h, INTERNET_OPTION_CONNECT_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
        InternetSetOptionW(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
        InternetSetOptionW(h, INTERNET_OPTION_SEND_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
    }
    return h;
}

BOOL FmNetProbe(LPCWSTR url, DWORD timeoutMs)
{
    HINTERNET h = OpenNet(timeoutMs), f;
    DWORD status = 0, cb = sizeof(status);
    BOOL up = FALSE;

    if (!h) return FALSE;
    f = InternetOpenUrlW(h, url, NULL, 0, DL_FLAGS | INTERNET_FLAG_RELOAD, 0);
    if (f)
    {
        if (HttpQueryInfoW(f, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &cb, NULL))
            up = status >= 200 && status < 400;
        InternetCloseHandle(f);
    }
    InternetCloseHandle(h);
    return up;
}

/* Closing a wininet request that still has a big body to come makes wininet read the rest first (19 s for the last 700 MB of
 * a 1 GB file at 35 MB/s): Cancel must not wait for that. The close runs on a thread of its own, which the process
 * does not wait for. */
typedef struct { HINTERNET url, net; } CLOSEARGS;
static DWORD WINAPI CloseThread(LPVOID p)
{
    CLOSEARGS *a = (CLOSEARGS *)p;
    if (a->url) InternetCloseHandle(a->url);
    if (a->net) InternetCloseHandle(a->net);
    HeapFree(GetProcessHeap(), 0, a);
    return 0;
}

static void CloseNetLater(HINTERNET url, HINTERNET net)
{
    CLOSEARGS *a = (CLOSEARGS *)HeapAlloc(GetProcessHeap(), 0, sizeof(*a));
    HANDLE t;
    if (a)
    {
        a->url = url; a->net = net;
        t = CreateThread(NULL, 0, CloseThread, a, 0, NULL);
        if (t) { CloseHandle(t); return; }
        HeapFree(GetProcessHeap(), 0, a);
    }
    if (url) InternetCloseHandle(url);
    if (net) InternetCloseHandle(net);
}

static BOOL TransientStatus(DWORD status)
{
    return status == 408 || status == 429 || status == 500 || status == 502 || status == 503 || status == 504;
}

static BOOL MakeDir(LPCWSTR dir)
{
    return CreateDirectoryW(dir, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

HRESULT FmCompDownload(const FM_COMPONENT *c, LPWSTR path, DWORD cch, FILE *log)
{
    WCHAR root[MAX_PATH], dir[MAX_PATH], part[MAX_PATH + 8], want[72], got[72];
    HINTERNET hNet = NULL, hUrl = NULL;
    HANDLE out = INVALID_HANDLE_VALUE;
    SHA256_CTX_ sha;
    static BYTE buf[64 * 1024];
    DWORD attempt, status = 0, cb, nread, nwritten, lastTick = 0, err = 0, stalls = 0;
    ULONGLONG total = 0, done = 0;
    HRESULT hr = E_FAIL;
    BOOL shaOn = FALSE;
    size_t i;

    if (!c->Url[0] || _wcsnicmp(c->Url, L"https://", 8))
    {
        FmSetLastMessage(L"The download address of '%s' is not an https address; featmgr only downloads over https.", c->Name);
        return E_INVALIDARG;
    }
    /* no checksum, no download: a verified download is the rule for every component */
    for (i = 0; c->Sha256[i]; i++)
        if (!iswxdigit(c->Sha256[i])) break;
    if (i != 64 || c->Sha256[i])
    {
        FmSetLastMessage(L"The component list has no valid SHA-256 for '%s', so it is not downloaded.", c->Name);
        return E_INVALIDARG;
    }
    if (wcspbrk(c->FileName, L"\\/:*?\"<>|"))
    {
        FmSetLastMessage(L"The component list gives '%s' an invalid file name.", c->Name);
        return E_INVALIDARG;
    }
    StringCchCopyW(want, ARRAYSIZE(want), c->Sha256);
    CharLowerW(want);
    if (!FmGetRootDir(root, MAX_PATH)) return E_FAIL;
    StringCchPrintfW(dir, ARRAYSIZE(dir), L"%s\\Downloads", root);
    if (!MakeDir(root) || !MakeDir(dir))
    {
        FmSetLastMessage(L"Cannot create %s (error %lu).", dir, GetLastError());
        return HRESULT_FROM_WIN32(GetLastError());
    }
    StringCchPrintfW(path, cch, L"%s\\%s", dir, c->FileName);
    StringCchPrintfW(part, ARRAYSIZE(part), L"%s.part", path);

    FmOpPhase(FM_PHASE_SEARCH);
    /* a verified copy from an earlier attempt is reused */
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
    {
        FmOpStep(L"Found a downloaded copy of %s, checking it", c->Name);
        if (FmFileSha256(path, got) && !_wcsicmp(got, want))
        {
            LOGF(log, L"  using the verified copy %s\n", path);
            return S_OK;
        }
        if (FmOpCancelled())
        {
            FmSetLastMessage(L"The operation was cancelled.");
            return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }
        DeleteFileW(path);
    }
    DeleteFileW(part);

    FmOpPhase(FM_PHASE_DOWNLOAD);
    if (c->Size)
        FmOpStep(L"Downloading %s (%I64u MB) from %s", c->Name, (c->Size + (1u << 20) - 1) >> 20, c->Url);
    else
        FmOpStep(L"Downloading %s from %s", c->Name, c->Url);
    FmOpBytes(0, c->Size);

    hNet = OpenNet(30000);
    if (hNet)
    {
        DWORD rt = READ_TIMEOUT_MS;
        InternetSetOptionW(hNet, INTERNET_OPTION_RECEIVE_TIMEOUT, &rt, sizeof(rt));
    }
    if (!hNet)
    {
        err = GetLastError();
        FmSetLastMessage(L"Cannot start the network stack (error %lu).", err);
        return HRESULT_FROM_WIN32(err);
    }
    for (attempt = 1; ; attempt++)
    {
        DWORD w;
        err = 0; status = 0;
        hUrl = InternetOpenUrlW(hNet, c->Url, NULL, 0, DL_FLAGS, 0);
        if (hUrl)
        {
            cb = sizeof(status);
            if (!HttpQueryInfoW(hUrl, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &cb, NULL))
                err = GetLastError();
            else if (status == HTTP_STATUS_OK)
                break;
        }
        else
            err = GetLastError();
        if (FmOpCancelled())
        {
            FmSetLastMessage(L"The download was cancelled. Nothing was installed.");
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            goto fail;
        }
        if (hUrl) { InternetCloseHandle(hUrl); hUrl = NULL; }
        if (attempt >= DL_ATTEMPTS || (status && !TransientStatus(status)))
        {
            if (status)
                FmSetLastMessage(L"The server answered HTTP %lu for %s. Check the network connection and try again.", status, c->Url);
            else
                FmSetLastMessage(L"Cannot reach %s (error %lu). Check the network connection and try again.", c->Url, err);
            hr = HRESULT_FROM_WIN32(err ? err : ERROR_INTERNET_CANNOT_CONNECT);
            goto fail;
        }
        FmOpStep(L"The server did not answer (attempt %lu of %lu), trying again", attempt, (DWORD)DL_ATTEMPTS);
        for (w = 0; w < attempt * 3000 && !FmOpCancelled(); w += 100) Sleep(100);
    }
    cb = sizeof(status);
    {
        WCHAR len[40];                    /* as text: a DWORD would cut a file over 4 GB */
        cb = sizeof(len);
        len[0] = L'\0';
        if (HttpQueryInfoW(hUrl, HTTP_QUERY_CONTENT_LENGTH, len, &cb, NULL) && len[0])
            total = _wcstoui64(len, NULL, 10);
        if (!total) total = c->Size;
    }
    if (c->MaxSize && total > c->MaxSize)
    {
        FmSetLastMessage(L"The server announced %I64u bytes for %s, more than its pinned size of %I64u bytes, so it was not downloaded.",
                         total, c->Name, c->MaxSize);
        hr = HRESULT_FROM_WIN32(ERROR_CRC);
        goto fail;
    }
    FmOpBytes(0, total);

    out = CreateFileW(part, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        FmSetLastMessage(L"Cannot create %s (error %lu).", part, err);
        hr = HRESULT_FROM_WIN32(err);
        goto fail;
    }
    if (!ShaBegin(&sha))
    {
        FmSetLastMessage(L"No cryptographic provider is available, so the download cannot be verified and is not made.");
        hr = E_FAIL;
        goto fail;
    }
    shaOn = TRUE;
    for (;;)
    {
        if (FmOpCancelled())
        {
            FmSetLastMessage(L"The download was cancelled; the partial file was deleted. Nothing was installed.");
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            goto fail;
        }
        if (!InternetReadFile(hUrl, buf, sizeof(buf), &nread))
        {
            err = GetLastError();
            if (err == ERROR_INTERNET_TIMEOUT && stalls < STALL_LIMIT)
            {
                /* nothing arrived for READ_TIMEOUT_MS: look at Cancel, then wait on (a stalled link must not hang the window) */
                stalls++;
                FmOpStep(L"Waiting for data from the server (%lu s without data)", stalls * (READ_TIMEOUT_MS / 1000));
                continue;
            }
            FmSetLastMessage(L"The download was interrupted after %I64u MB (error %lu). Check the network connection and try again.",
                             done >> 20, err);
            hr = HRESULT_FROM_WIN32(err ? err : ERROR_INTERNET_CONNECTION_RESET);
            goto fail;
        }
        stalls = 0;
        if (!nread) break;
        if (c->MaxSize && done + nread > c->MaxSize)
        {
            /* longer than the pinned size: it cannot match its checksum, so stop before it fills the disk */
            LOGF(log, L"  ERROR: %s is longer than its pinned size of %I64u bytes; download aborted\n", c->Url, c->MaxSize);
            FmSetLastMessage(L"The file downloaded for %s is larger than its pinned size (%I64u bytes), so the download was stopped "
                             L"and nothing was installed.", c->Name, c->MaxSize);
            hr = HRESULT_FROM_WIN32(ERROR_CRC);
            goto fail;
        }
        if (!WriteFile(out, buf, nread, &nwritten, NULL) || nwritten != nread)
        {
            err = GetLastError();
            FmSetLastMessage(L"Cannot write %s (error %lu): the disk may be full.", part, err);
            hr = HRESULT_FROM_WIN32(err ? err : ERROR_DISK_FULL);
            goto fail;
        }
        if (!CryptHashData(sha.hash, buf, nread, 0))
        {
            FmSetLastMessage(L"Hashing the download failed.");
            hr = E_FAIL;
            goto fail;
        }
        done += nread;
        if (GetTickCount() - lastTick >= 150)
        {
            lastTick = GetTickCount();
            FmOpBytes(done, total);
        }
    }
    FmOpBytes(done, total ? total : done);
    CloseHandle(out); out = INVALID_HANDLE_VALUE;
    InternetCloseHandle(hUrl); hUrl = NULL;
    InternetCloseHandle(hNet); hNet = NULL;

    FmOpStep(L"Verifying the download of %s", c->Name);
    shaOn = FALSE;
    if (!ShaEnd(&sha, got))
    {
        FmSetLastMessage(L"Hashing the download failed.");
        hr = E_FAIL;
        goto fail;
    }
    if (total && done != total)
    {
        FmSetLastMessage(L"The download of %s ended early (%I64u of %I64u bytes). Try again.", c->Name, done, total);
        hr = HRESULT_FROM_WIN32(ERROR_INTERNET_CONNECTION_RESET);
        goto fail;
    }
    if (_wcsicmp(got, want))
    {
        LOGF(log, L"  ERROR: SHA-256 mismatch for %s: expected %s, got %s\n", c->Url, want, got);
        FmOpStep(L"SHA-256 expected %s, got %s", want, got);
        FmSetLastMessage(L"The file downloaded for %s does not match its expected SHA-256 checksum, so it was deleted and "
                         L"nothing was installed. (The expected and the actual checksum are in the log.)", c->Name);
        hr = HRESULT_FROM_WIN32(ERROR_CRC);
        goto fail;
    }
    DeleteFileW(path);
    if (!MoveFileExW(part, path, MOVEFILE_REPLACE_EXISTING))
    {
        err = GetLastError();
        FmSetLastMessage(L"Cannot move the download into place (error %lu).", err);
        hr = HRESULT_FROM_WIN32(err);
        goto fail;
    }
    LOGF(log, L"  downloaded and verified %s (%I64u bytes, sha256 %s)\n", path, done, got);
    return S_OK;

fail:
    if (shaOn) ShaAbort(&sha);
    if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
    DeleteFileW(part);
    if (hUrl || hNet) CloseNetLater(hUrl, hNet);
    path[0] = L'\0';
    return hr;
}
