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

/* key.amd64 / key.x86 of this build wins over key (Install, DetectReg, DetectFile: a 32-bit package on a 64-bit system
 * installs into SysWOW64 through the 32-bit msiexec) */
static void ReadKeyArch(LPCWSTR file, LPCWSTR sec, LPCWSTR key, LPWSTR out, DWORD cch)
{
    WCHAR k[48];
#ifdef _WIN64
    StringCchPrintfW(k, ARRAYSIZE(k), L"%s.amd64", key);
#else
    StringCchPrintfW(k, ARRAYSIZE(k), L"%s.x86", key);
#endif
    ReadKey(file, sec, k, out, cch);
    if (!out[0]) ReadKey(file, sec, key, out, cch);
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
    ReadKey(file, id, L"Sha1", c->Sha1, ARRAYSIZE(c->Sha1));     /* optional, checked in addition to the SHA-256 */
    ReadKey(file, id, L"FileName", c->FileName, ARRAYSIZE(c->FileName));
    if (!c->FileName[0]) StringCchPrintfW(c->FileName, ARRAYSIZE(c->FileName), L"%s.bin", id);
    ReadKeyArch(file, id, L"DetectReg", c->DetectReg, ARRAYSIZE(c->DetectReg));
    ReadKeyArch(file, id, L"DetectFile", c->DetectFile, ARRAYSIZE(c->DetectFile));
    ReadKeyArch(file, id, L"Install", c->Install, ARRAYSIZE(c->Install));
    ReadKeyArch(file, id, L"Cleanup", c->Cleanup, ARRAYSIZE(c->Cleanup));
    ReadKey(file, id, L"Also", c->Also, ARRAYSIZE(c->Also));
    if (wcspbrk(c->Also, L"[]=\r\n")) c->Also[0] = L'\0';
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

BOOL FmCompDetectOne(const FM_COMPONENT *c)
{
    WCHAR p[MAX_PATH];
    if (DetectRegRule(c->DetectReg)) return TRUE;
    if (c->DetectFile[0] && ExpandEnvironmentStringsW(c->DetectFile, p, ARRAYSIZE(p)) &&
        GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    return FALSE;
}

/* a chain is short and never loops: the hop count is capped (an Also= cycle in a damaged list ends there) */
#define COMP_MAX_PIECES 4

BOOL FmCompNext(const FM_COMPONENT *c, FM_COMPONENT *next)
{
    if (!c->Also[0] || !FmCompLoad(c->Also, next)) return FALSE;
    if (!next->ArchOk || !next->Install[0] || (!next->DetectReg[0] && !next->DetectFile[0])) return FALSE;
    return TRUE;
}

BOOL FmCompDetect(const FM_COMPONENT *c)
{
    FM_COMPONENT piece, nxt;
    int n;
    if (!FmCompDetectOne(c)) return FALSE;
    piece = *c;
    for (n = 1; n < COMP_MAX_PIECES && FmCompNext(&piece, &nxt); n++)
    {
        if (!FmCompDetectOne(&nxt)) return FALSE;
        piece = nxt;
    }
    return TRUE;
}

ULONGLONG FmCompTotalSize(const FM_COMPONENT *c)
{
    FM_COMPONENT piece, nxt;
    ULONGLONG total = c->Size;
    int n;
    piece = *c;
    for (n = 1; n < COMP_MAX_PIECES && FmCompNext(&piece, &nxt); n++)
    {
        total += nxt.Size;
        piece = nxt;
    }
    return total;
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

/* ---- hashing: SHA-256 and/or SHA-1 over one pass ---------------------------------------------------------- */

typedef struct { HCRYPTPROV prov; HCRYPTHASH hash; HCRYPTHASH hash1; } SHA256_CTX_;   /* hash = SHA-256 (0: off), hash1 = SHA-1 (0: off) */

static BOOL ShaBeginEx(SHA256_CTX_ *s, BOOL want256, BOOL want1)
{
    s->prov = 0; s->hash = 0; s->hash1 = 0;
    if (!CryptAcquireContextW(&s->prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return FALSE;
    if ((want256 && !CryptCreateHash(s->prov, CALG_SHA_256, 0, 0, &s->hash)) ||
        (want1 && !CryptCreateHash(s->prov, CALG_SHA1, 0, 0, &s->hash1)))
    {
        if (s->hash) CryptDestroyHash(s->hash);
        if (s->hash1) CryptDestroyHash(s->hash1);
        CryptReleaseContext(s->prov, 0);
        s->prov = 0; s->hash = 0; s->hash1 = 0;
        return FALSE;
    }
    return TRUE;
}

static BOOL ShaData(SHA256_CTX_ *s, const BYTE *b, DWORD n)
{
    return (!s->hash || CryptHashData(s->hash, b, n, 0)) && (!s->hash1 || CryptHashData(s->hash1, b, n, 0));
}

static void ShaAbort(SHA256_CTX_ *s)
{
    if (s->hash) CryptDestroyHash(s->hash);
    if (s->hash1) CryptDestroyHash(s->hash1);
    if (s->prov) CryptReleaseContext(s->prov, 0);
    s->hash = 0; s->hash1 = 0; s->prov = 0;
}

static BOOL HexOf(HCRYPTHASH h, DWORD len, WCHAR *hex)
{
    BYTE d[32];
    DWORD cb = sizeof(d), i;
    if (!CryptGetHashParam(h, HP_HASHVAL, d, &cb, 0) || cb != len) return FALSE;
    for (i = 0; i < len; i++) StringCchPrintfW(hex + 2 * i, 3, L"%02x", d[i]);
    return TRUE;
}

/* hex256 / hex1 (may be NULL) receive the digests of the hashes that were on */
static BOOL ShaEndEx(SHA256_CTX_ *s, WCHAR hex256[65], WCHAR hex1[41])
{
    BOOL ok = TRUE;
    if (s->hash) ok = HexOf(s->hash, 32, hex256);
    if (ok && s->hash1) ok = HexOf(s->hash1, 20, hex1);
    ShaAbort(s);
    return ok;
}

static BOOL HexValid(LPCWSTR s, size_t n)
{
    size_t i;
    for (i = 0; s[i]; i++)
        if (!iswxdigit(s[i])) return FALSE;
    return i == n;
}

static BOOL FileHashes(LPCWSTR path, BOOL want256, BOOL want1, WCHAR hex256[65], WCHAR hex1[41])
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SHA256_CTX_ s;
    static BYTE buf[64 * 1024];            /* one hasher at a time: callers run on one thread */
    DWORD got;
    BOOL ok = TRUE;

    if (f == INVALID_HANDLE_VALUE) return FALSE;
    if (!ShaBeginEx(&s, want256, want1)) { CloseHandle(f); return FALSE; }
    for (;;)
    {
        if (!ReadFile(f, buf, sizeof(buf), &got, NULL)) { ok = FALSE; break; }
        if (!got) break;
        if (!ShaData(&s, buf, got)) { ok = FALSE; break; }
        if (FmOpCancelled()) { ok = FALSE; break; }
    }
    CloseHandle(f);
    if (!ok) { ShaAbort(&s); return FALSE; }
    return ShaEndEx(&s, hex256, hex1);
}

BOOL FmFileSha256(LPCWSTR path, WCHAR hex[65])
{
    return FileHashes(path, TRUE, FALSE, hex, NULL);
}

BOOL FmFileHashHex(LPCWSTR path, ALG_ID alg, WCHAR *hex, DWORD cch)
{
    WCHAR h256[65], h1[41];
    if (alg == CALG_SHA_256)
        return cch >= 65 && FileHashes(path, TRUE, FALSE, h256, NULL) && SUCCEEDED(StringCchCopyW(hex, cch, h256));
    if (alg == CALG_SHA1)
        return cch >= 41 && FileHashes(path, FALSE, TRUE, NULL, h1) && SUCCEEDED(StringCchCopyW(hex, cch, h1));
    return FALSE;
}

/* the file matches every hash the component declares */
static BOOL FileMatches(LPCWSTR path, const FM_COMPONENT *c, WCHAR got256[65], WCHAR got1[41])
{
    BOOL w256 = c->Sha256[0] != 0, w1 = c->Sha1[0] != 0;
    got256[0] = got1[0] = L'\0';
    if (!FileHashes(path, w256, w1, got256, got1)) return FALSE;
    return (!w256 || !_wcsicmp(got256, c->Sha256)) && (!w1 || !_wcsicmp(got1, c->Sha1));
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
    WCHAR root[MAX_PATH], dir[MAX_PATH], part[MAX_PATH + 8], want[72], got[72], want1[48], got1[48];
    HINTERNET hNet = NULL, hUrl = NULL;
    HANDLE out = INVALID_HANDLE_VALUE;
    SHA256_CTX_ sha;
    static BYTE buf[64 * 1024];
    DWORD attempt, status = 0, cb, nread, nwritten, lastTick = 0, err = 0, stalls = 0;
    ULONGLONG total = 0, done = 0;
    HRESULT hr = E_FAIL;
    BOOL shaOn = FALSE, has256, has1;

    if (!c->Url[0] || (_wcsnicmp(c->Url, L"https://", 8) && !(c->AllowHttp && !_wcsnicmp(c->Url, L"http://", 7))))
    {
        FmSetLastMessage(L"The download address of '%s' is not an https address; featmgr only downloads over https.", c->Name);
        return E_INVALIDARG;
    }
    /* no checksum, no download: a verified download is the rule for every component */
    has256 = HexValid(c->Sha256, 64);
    has1 = HexValid(c->Sha1, 40);
    if ((c->Sha256[0] && !has256) || (c->Sha1[0] && !has1) || (!has256 && !has1))
    {
        FmSetLastMessage(L"The catalog has no valid SHA-256 (or SHA-1) checksum for '%s', so it is not downloaded.", c->Name);
        return E_INVALIDARG;
    }
    if (wcspbrk(c->FileName, L"\\/:*?\"<>|"))
    {
        FmSetLastMessage(L"The component list gives '%s' an invalid file name.", c->Name);
        return E_INVALIDARG;
    }
    StringCchCopyW(want, ARRAYSIZE(want), c->Sha256);
    CharLowerW(want);
    StringCchCopyW(want1, ARRAYSIZE(want1), c->Sha1);
    CharLowerW(want1);
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
    /* local-first: a file the image already carries (the PowerShell 7 MSI) is used, once its hash matches, with no download */
    if (c->LocalFile[0] && GetFileAttributesW(c->LocalFile) != INVALID_FILE_ATTRIBUTES)
    {
        FmOpStep(L"Found %s on this system, checking it", c->LocalFile);
        if (FileMatches(c->LocalFile, c, got, got1))
        {
            LOGF(log, L"  using the local copy %s (hash verified, no download)\n", c->LocalFile);
            return StringCchCopyW(path, cch, c->LocalFile);
        }
        if (FmOpCancelled())
        {
            FmSetLastMessage(L"The operation was cancelled.");
            return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        }
        LOGF(log, L"  the local copy %s does not match its hash; downloading instead\n", c->LocalFile);
    }
    /* a verified copy from an earlier attempt is reused */
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
    {
        FmOpStep(L"Found a downloaded copy of %s, checking it", c->Name);
        if (FileMatches(path, c, got, got1))
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
    if (!ShaBeginEx(&sha, has256, has1))
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
        if (!ShaData(&sha, buf, nread))
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
    if (!ShaEndEx(&sha, got, got1))
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
    if ((has256 && _wcsicmp(got, want)) || (has1 && _wcsicmp(got1, want1)))
    {
        LOGF(log, L"  ERROR: checksum mismatch for %s: expected %s %s, got %s\n", c->Url, has256 ? L"SHA-256" : L"SHA-1",
             has256 ? want : want1, has256 ? got : got1);
        FmOpStep(L"%s expected %s, got %s", has256 ? L"SHA-256" : L"SHA-1", has256 ? want : want1, has256 ? got : got1);
        FmSetLastMessage(L"The file downloaded for %s does not match its expected %s checksum, so it was deleted and "
                         L"nothing was installed. (The expected and the actual checksum are in the log.)", c->Name,
                         has256 ? L"SHA-256" : L"SHA-1");
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
    LOGF(log, L"  downloaded and verified %s (%I64u bytes, %s %s)\n", path, done, has256 ? L"sha256" : L"sha1", has256 ? got : got1);
    return S_OK;

fail:
    if (shaOn) ShaAbort(&sha);
    if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
    DeleteFileW(part);
    if (hUrl || hNet) CloseNetLater(hUrl, hNet);
    path[0] = L'\0';
    return hr;
}

/* ---- plain file download with an optional certificate pin (the RAPPS catalog) ------------------------------------ */

/* SHA-256 of the root certificates the official RAPPS server's chain must end in (Let's Encrypt, https://letsencrypt.org/certificates/):
 * ISRG Root X1 and X2. The same two pins rapps.exe used for its database download. */
static const WCHAR *g_PinnedRoots[] = {
    L"96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6",
    L"69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470",
};

static BOOL ChainPinned(HINTERNET hFile)
{
    PCCERT_CHAIN_CONTEXT cc = NULL;
    DWORD cb = sizeof(cc), n, i;
    BYTE hash[32];
    WCHAR hex[65];
    BOOL ok = FALSE;

    if (!InternetQueryOptionA(hFile, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &cc, &cb) || !cc) return FALSE;
    if (cc->cChain >= 1 && cc->rgpChain[0]->cElement >= 2)
    {
        CERT_SIMPLE_CHAIN *chain = cc->rgpChain[0];
        PCCERT_CONTEXT root = chain->rgpElement[chain->cElement - 1]->pCertContext;
        n = sizeof(hash);
        if (CryptHashCertificate(0, CALG_SHA_256, 0, root->pbCertEncoded, root->cbCertEncoded, hash, &n) && n == sizeof(hash))
        {
            for (i = 0; i < n; i++) StringCchPrintfW(hex + 2 * i, 3, L"%02x", hash[i]);
            for (i = 0; i < ARRAYSIZE(g_PinnedRoots); i++)
                if (!_wcsicmp(hex, g_PinnedRoots[i])) ok = TRUE;
        }
    }
    CertFreeCertificateChain(cc);
    return ok;
}

HRESULT FmDownloadFile(LPCWSTR url, LPCWSTR dest, BOOL pinned, ULONGLONG maxBytes, FILE *log)
{
    WCHAR part[MAX_PATH + 8];
    HINTERNET hNet = NULL, hUrl = NULL;
    HANDLE out = INVALID_HANDLE_VALUE;
    static BYTE buf[64 * 1024];
    DWORD attempt, status = 0, cb, nread, nwritten, err = 0, stalls = 0;
    ULONGLONG done = 0, total = 0;
    HRESULT hr = E_FAIL;

    (void)pinned;      /* the catalog carries every download address and hash: never over plain http, pinned or not */
    if (_wcsnicmp(url, L"https://", 8))
    {
        FmSetLastMessage(L"Refusing to download from %s: not an https address.", url);
        return E_INVALIDARG;
    }
    StringCchPrintfW(part, ARRAYSIZE(part), L"%s.part", dest);
    DeleteFileW(part);
    hNet = OpenNet(30000);
    if (!hNet)
    {
        err = GetLastError();
        FmSetLastMessage(L"Cannot start the network stack (error %lu).", err);
        return HRESULT_FROM_WIN32(err);
    }
    {
        DWORD rt = READ_TIMEOUT_MS;
        InternetSetOptionW(hNet, INTERNET_OPTION_RECEIVE_TIMEOUT, &rt, sizeof(rt));
    }
    for (attempt = 1; ; attempt++)
    {
        DWORD w;
        err = 0; status = 0;
        hUrl = InternetOpenUrlW(hNet, url, NULL, 0, DL_FLAGS, 0);
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
        if (FmOpCancelled()) { FmSetLastMessage(L"The operation was cancelled."); hr = HRESULT_FROM_WIN32(ERROR_CANCELLED); goto fail; }
        if (hUrl) { InternetCloseHandle(hUrl); hUrl = NULL; }
        if (attempt >= DL_ATTEMPTS || (status && !TransientStatus(status)))
        {
            if (status)
                FmSetLastMessage(L"The server answered HTTP %lu for %s. Check the network connection and try again.", status, url);
            else
                FmSetLastMessage(L"Cannot reach %s (error %lu). Check the network connection and try again.", url, err);
            hr = HRESULT_FROM_WIN32(err ? err : ERROR_INTERNET_CANNOT_CONNECT);
            goto fail;
        }
        for (w = 0; w < attempt * 3000 && !FmOpCancelled(); w += 100) Sleep(100);
    }
    if (pinned && !ChainPinned(hUrl))
    {
        LOGF(log, L"  ERROR: the certificate chain of %s does not end in a pinned root; not downloading\n", url);
        FmSetLastMessage(L"The server certificate of %s is not the expected one (certificate pin mismatch), so nothing was downloaded.", url);
        hr = HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        goto fail;
    }
    {
        WCHAR len[40];
        cb = sizeof(len);
        len[0] = L'\0';
        if (HttpQueryInfoW(hUrl, HTTP_QUERY_CONTENT_LENGTH, len, &cb, NULL) && len[0]) total = _wcstoui64(len, NULL, 10);
        FmOpBytes(0, total);
    }
    out = CreateFileW(part, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        FmSetLastMessage(L"Cannot create %s (error %lu).", part, err);
        hr = HRESULT_FROM_WIN32(err);
        goto fail;
    }
    for (;;)
    {
        if (FmOpCancelled()) { FmSetLastMessage(L"The download was cancelled."); hr = HRESULT_FROM_WIN32(ERROR_CANCELLED); goto fail; }
        if (!InternetReadFile(hUrl, buf, sizeof(buf), &nread))
        {
            err = GetLastError();
            if (err == ERROR_INTERNET_TIMEOUT && stalls < STALL_LIMIT) { stalls++; continue; }
            FmSetLastMessage(L"The download was interrupted (error %lu).", err);
            hr = HRESULT_FROM_WIN32(err ? err : ERROR_INTERNET_CONNECTION_RESET);
            goto fail;
        }
        stalls = 0;
        if (!nread) break;
        done += nread;
        if (maxBytes && done > maxBytes)
        {
            FmSetLastMessage(L"The download from %s is larger than the %I64u MB limit; stopped.", url, maxBytes >> 20);
            hr = HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
            goto fail;
        }
        if (!WriteFile(out, buf, nread, &nwritten, NULL) || nwritten != nread)
        {
            err = GetLastError();
            FmSetLastMessage(L"Cannot write %s (error %lu): the disk may be full.", part, err);
            hr = HRESULT_FROM_WIN32(err ? err : ERROR_DISK_FULL);
            goto fail;
        }
        FmOpBytes(done, total);
    }
    CloseHandle(out); out = INVALID_HANDLE_VALUE;
    InternetCloseHandle(hUrl); hUrl = NULL;
    InternetCloseHandle(hNet); hNet = NULL;
    if (total && done != total)
    {
        FmSetLastMessage(L"The download ended early (%I64u of %I64u bytes). Try again.", done, total);
        hr = HRESULT_FROM_WIN32(ERROR_INTERNET_CONNECTION_RESET);
        goto fail;
    }
    if (!MoveFileExW(part, dest, MOVEFILE_REPLACE_EXISTING))
    {
        err = GetLastError();
        FmSetLastMessage(L"Cannot move the download into place (error %lu).", err);
        hr = HRESULT_FROM_WIN32(err);
        goto fail;
    }
    LOGF(log, L"  downloaded %s (%I64u bytes)\n", url, done);
    return S_OK;
fail:
    if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
    DeleteFileW(part);
    if (hUrl || hNet) CloseNetLater(hUrl, hNet);
    return hr;
}
