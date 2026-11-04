/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Native install path for RAPPS-format software entries (Provider=native; "rapps" is accepted as
 *              the old spelling): what rapps.exe used to do for featmgr. Download plan (URL, SHA-256 else SHA-1,
 *              local-first file), the silent installer command line (MSI properties, Inno / NSIS switches, the
 *              entry's own SilentParameters), the installed-programs lookup and the uninstall of an installed
 *              program (registry Uninstall key; the apps this code unpacked itself, see natgen.c, are removed
 *              from the record it kept). Nothing is bundled: every file is downloaded and hash-verified.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#define COBJMACROS
#include "featmgr.h"
#include <shlwapi.h>
#include <shlobj.h>
#include <strsafe.h>

#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

#define UNINSTALL_SUBKEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
#define GENERATE_ARPSUBKEY L"RApps"          /* the record the generated (unpacked) installs keep; same name rapps used */

BOOL FmNativeIsProvider(LPCWSTR provider)
{
    return !_wcsicmp(provider, L"native") || !_wcsicmp(provider, L"rapps");
}

BOOL FmFeatmgrExePath(LPWSTR out, DWORD cch)
{
    WCHAR sys[MAX_PATH];
    if (!GetSystemDirectoryW(sys, MAX_PATH)) return FALSE;
    return SUCCEEDED(StringCchPrintfW(out, cch, L"%s\\featmgr.exe", sys));
}

/* ---- installed programs (the Uninstall keys), read once per enumeration ---------------------------------- */

typedef struct _UNENT
{
    WCHAR key[128];
    WCHAR name[128];
    BYTE  root;       /* 0 = HKCU, 1 = HKLM */
    BYTE  wow32;      /* opened with KEY_WOW64_32KEY */
} UNENT;

static UNENT *g_un;
static int    g_nun, g_cun;
static BOOL   g_unValid;

void FmNativeInvalidate(void)
{
    g_unValid = FALSE;
}

static void SnapRoot(HKEY root, BYTE rootId, BOOL wow32)
{
    HKEY hk;
    DWORD i;
    REGSAM sam = KEY_READ | (wow32 ? KEY_WOW64_32KEY : 0);

    if (RegOpenKeyExW(root, UNINSTALL_SUBKEY, 0, sam, &hk) != ERROR_SUCCESS) return;
    for (i = 0; ; i++)
    {
        WCHAR kn[128];
        DWORD cch = ARRAYSIZE(kn), type, cb, sc = 0;
        HKEY sk;
        UNENT e;

        if (RegEnumKeyExW(hk, i, kn, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (RegOpenKeyExW(hk, kn, 0, sam, &sk) != ERROR_SUCCESS) continue;
        ZeroMemory(&e, sizeof(e));
        StringCchCopyW(e.key, ARRAYSIZE(e.key), kn);
        cb = sizeof(e.name) - sizeof(WCHAR);
        if (RegQueryValueExW(sk, L"DisplayName", NULL, &type, (LPBYTE)e.name, &cb) != ERROR_SUCCESS || type != REG_SZ)
            e.name[0] = L'\0';
        e.name[ARRAYSIZE(e.name) - 1] = L'\0';
        cb = sizeof(sc);
        if (RegQueryValueExW(sk, L"SystemComponent", NULL, &type, (LPBYTE)&sc, &cb) == ERROR_SUCCESS && type == REG_DWORD && sc == 1)
        {
            RegCloseKey(sk);
            continue;
        }
        RegCloseKey(sk);
        e.root = rootId;
        e.wow32 = wow32;
        if (g_nun == g_cun)
        {
            int nc = g_cun ? g_cun * 2 : 256;
            UNENT *n = g_un ? (UNENT *)HeapReAlloc(GetProcessHeap(), 0, g_un, nc * sizeof(UNENT))
                            : (UNENT *)HeapAlloc(GetProcessHeap(), 0, nc * sizeof(UNENT));
            if (!n) break;
            g_un = n; g_cun = nc;
        }
        g_un[g_nun++] = e;
    }
    RegCloseKey(hk);
}

static void Snapshot(void)
{
    if (g_unValid) return;
    g_nun = 0;
    SnapRoot(HKEY_CURRENT_USER, 0, FALSE);
    SnapRoot(HKEY_LOCAL_MACHINE, 1, FALSE);
#ifdef _WIN64
    SnapRoot(HKEY_LOCAL_MACHINE, 1, TRUE);
#endif
    g_unValid = TRUE;
}

/* RAPPS rule: the Uninstall key is named RegName, or named like the program, or the program's DisplayName matches. */
static const UNENT *FindInstalled(LPCWSTR regName, LPCWSTR name)
{
    int i;
    Snapshot();
    for (i = 0; i < g_nun; i++)
    {
        const UNENT *e = &g_un[i];
        if (regName && regName[0] && (!_wcsicmp(e->key, regName) || (e->name[0] && !_wcsicmp(e->name, regName)))) return e;
        if (name && name[0] && (!_wcsicmp(e->key, name) || (e->name[0] && !_wcsicmp(e->name, name)))) return e;
    }
    return NULL;
}

BOOL FmNativeIsInstalled(LPCWSTR regName, LPCWSTR name)
{
    return FindInstalled(regName, name) != NULL;
}

/* ---- the download plan ---------------------------------------------------------------------------------------- */

static void Rk(const FM_FEATURE *f, LPCWSTR sec, LPCWSTR key, LPWSTR out, DWORD cch)
{
    GetPrivateProfileStringW(sec, key, L"", out, cch, f->ManifestPath);
}

static BOOL ArchListed(LPCWSTR list)
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
        if (!_wcsicmp(tok, me)) return TRUE;
    return FALSE;
}

/* a file name for the downloaded file: <id>-<SaveAs or the URL's last path part>, with nothing a path could use */
static void MakeFileName(const FM_FEATURE *f, LPCWSTR url, LPCWSTR saveAs, LPWSTR out, DWORD cch)
{
    WCHAR tail[96];
    LPCWSTR p = saveAs[0] ? saveAs : NULL;
    size_t n = 0, i;
    WCHAR *q;

    if (!p)
    {
        p = wcsrchr(url, L'/');
        p = p ? p + 1 : L"";
    }
    for (i = 0; p[i] && p[i] != L'?' && p[i] != L'#' && n + 1 < ARRAYSIZE(tail) - 1; i++)
        tail[n++] = (p[i] < 32 || wcschr(L"\\/:*?\"<>|%", p[i])) ? L'_' : p[i];
    tail[n] = L'\0';
    if (!tail[0]) StringCchCopyW(tail, ARRAYSIZE(tail), L"download.bin");
    if (tail[0] == L'.') tail[0] = L'_';
    StringCchPrintfW(out, cch, L"%.40s-%s", f->Id, tail);
    for (q = out; *q; q++) if (*q == L' ') *q = L'_';
}

/* The component record of a native entry: where to download, which hash to check, what is already on disk. */
BOOL FmNativePlan(const FM_FEATURE *f, FM_COMPONENT *c)
{
    WCHAR tmp[512], saveAs[128], local[128], arch[32];

    ZeroMemory(c, sizeof(*c));
    StringCchCopyW(c->Id, ARRAYSIZE(c->Id), f->Id);
    StringCchCopyW(c->Name, ARRAYSIZE(c->Name), f->Name);
    Rk(f, L"Source", L"Artifact", c->Url, ARRAYSIZE(c->Url));
    Rk(f, L"Source", L"ArtifactSHA256", c->Sha256, ARRAYSIZE(c->Sha256));
    Rk(f, L"Source", L"ArtifactSHA1", c->Sha1, ARRAYSIZE(c->Sha1));
    Rk(f, L"Source", L"SizeBytes", tmp, ARRAYSIZE(tmp));
    c->Size = tmp[0] ? _wcstoui64(tmp, NULL, 10) : 0;
    Rk(f, L"Source", L"Arch", arch, ARRAYSIZE(arch));
    c->ArchOk = ArchListed(arch);
    c->AllowHttp = TRUE;                       /* the checksum, not the transport, is what makes a RAPPS download trustworthy */
    StringCchCopyW(c->Install, ARRAYSIZE(c->Install), L"(native)");
    Rk(f, L"Rapps", L"SaveAs", saveAs, ARRAYSIZE(saveAs));
    MakeFileName(f, c->Url, saveAs, c->FileName, ARRAYSIZE(c->FileName));
    Rk(f, L"Rapps", L"LocalInstaller", local, ARRAYSIZE(local));
    if (local[0] && !wcspbrk(local, L"\\/:\"\r\n"))
    {
        WCHAR dir[MAX_PATH];
        if (FmGetPayloadDir(f->Id, dir, MAX_PATH))
            StringCchPrintfW(c->LocalFile, ARRAYSIZE(c->LocalFile), L"%s\\%s", dir, local);
    }
    return c->Url[0] != L'\0';
}

/* Can the install be attempted on this system: an address, a checksum, this architecture. */
BOOL FmNativeAvailable(const FM_FEATURE *f)
{
    FM_COMPONENT c;
    if (!FmNativePlan(f, &c) || !c.ArchOk) return FALSE;
    return c.Sha256[0] || c.Sha1[0];
}

/* ---- the installer command line ------------------------------------------------------------------------------- */

typedef int FILEKIND;
#define FK_NONE FM_FK_NONE
#define FK_MSI  FM_FK_MSI
#define FK_EXE  FM_FK_EXE
#define FK_CAB  FM_FK_CAB
#define FK_ZIP  FM_FK_ZIP

static BOOL ReadAt(HANDLE h, ULONGLONG off, void *buf, DWORD n)
{
    LARGE_INTEGER li;
    DWORD got;
    li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) return FALSE;
    return ReadFile(h, buf, n, &got, NULL) && got == n;
}

int FmNativeFileKind(LPCWSTR path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    BYTE b[8];
    FILEKIND k = FK_NONE;

    if (h == INVALID_HANDLE_VALUE) return k;
    if (ReadAt(h, 0, b, sizeof(b)))
    {
        if (b[0] == 0xD0 && b[1] == 0xCF && b[2] == 0x11 && b[3] == 0xE0) k = FK_MSI;
        else if (b[0] == 'M' && b[1] == 'Z') k = FK_EXE;
        else if (b[0] == 'M' && b[1] == 'S' && b[2] == 'C' && b[3] == 'F') k = FK_CAB;
        else if (b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4) k = FK_ZIP;
    }
    CloseHandle(h);
    return k;
}

/* Inno Setup (<= 5.1.4 header signature, or the SETUPLDR resource) and NSIS (1.6+ firstheader) detection, as rapps did. */
typedef int INSTTYPE;
#define IT_UNKNOWN 0
#define IT_INNO 1
#define IT_NSIS 2

int FmNativeGuessInstaller(LPCWSTR path)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    BYTE buf[0x30 + 12];
    INSTTYPE it = IT_UNKNOWN;
    UINT sig[3];
    UINT nsis[6];
    ULONGLONG off;
    HMODULE hMod;
    LARGE_INTEGER sz;

    if (h == INVALID_HANDLE_VALUE) return it;
    if (!ReadAt(h, 0, buf, sizeof(buf)) || buf[0] != 'M' || buf[1] != 'Z') goto done;
    memcpy(sig, buf + 0x30, sizeof(sig));
    if (sig[0] == 0x6F6E6E49 && sig[1] == ~sig[2]) { it = IT_INNO; goto done; }
    if (!GetFileSizeEx(h, &sz)) sz.QuadPart = 0;
    for (off = 512 * 20; off < 1024 * 1024 * 50 && off + sizeof(nsis) <= (ULONGLONG)sz.QuadPart; off += 512)
    {
        if (ReadAt(h, off, nsis, sizeof(nsis)) && nsis[1] == 0xDEADBEEF &&
            nsis[2] == 0x6C6C754E && nsis[3] == 0x74666F73 && nsis[4] == 0x74736E49)
        {
            it = IT_NSIS;
            goto done;
        }
    }
    CloseHandle(h);
    h = INVALID_HANDLE_VALUE;
    hMod = LoadLibraryExW(path, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hMod)
    {
        HRSRC r = FindResourceW(hMod, MAKEINTRESOURCEW(11111), (LPCWSTR)RT_RCDATA);   /* Inno's RCDATA 11111 */
        HGLOBAL g;
        if (r && (g = LoadResource(hMod, r)) != NULL)
        {
            const BYTE *p = (const BYTE *)LockResource(g);
            if (p && p[0] == 'r' && p[1] == 'D' && p[2] == 'l' && p[3] == 'P' && p[4] == 't' && p[5] == 'S') it = IT_INNO;
        }
        FreeLibrary(hMod);
    }
done:
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return it;
}

static INSTTYPE TypeFromString(LPCWSTR s)
{
    if (!_wcsicmp(s, L"Inno")) return IT_INNO;
    if (!_wcsicmp(s, L"NSIS")) return IT_NSIS;
    return IT_UNKNOWN;
}

/* Silent switches by installer type; ExtraInfo of rapps (old Inno without /SUPPRESSMSGBOXES) is not kept: every
 * Inno since 5.5 (2012) has it, and an old one just ignores an unknown switch. */
LPCWSTR FmNativeSilentSwitches(int type)
{
    return type == IT_INNO ? L"/SILENT /VERYSILENT /SP- /SUPPRESSMSGBOXES /NORESTART" : type == IT_NSIS ? L"/S" : L"";
}

/* The command that installs the downloaded file silently. Archive installers (Generate / ExeInZip) run in a
 * featmgr child (natgen.c) so that the engine keeps its one way of running, timing out and cancelling a child. */
HRESULT FmNativeInstallLine(const FM_FEATURE *f, LPCWSTR file, LPWSTR out, DWORD cch)
{
    WCHAR inst[64], args[512], props[1024], fm[MAX_PATH];
    FILEKIND k;
    INSTTYPE it;

    Rk(f, L"Rapps", L"Installer", inst, ARRAYSIZE(inst));
    Rk(f, L"Rapps", L"SilentParameters", args, ARRAYSIZE(args));
    Rk(f, L"Rapps", L"MsiProperties", props, ARRAYSIZE(props));
    if (wcspbrk(file, L"\"\r\n") || wcspbrk(args, L"\r\n") || wcspbrk(props, L"\r\n"))
        return E_INVALIDARG;
    if (!_wcsicmp(inst, L"Generate") || !_wcsicmp(inst, L"ExeInZip"))
    {
        if (!FmFeatmgrExePath(fm, MAX_PATH)) return E_FAIL;
        return StringCchPrintfW(out, cch, L"\"%s\" /nat-install \"%s\" \"%s\"", fm, f->Id, file);
    }
    k = FmNativeFileKind(file);
    if (k == FK_MSI)
    {
        /* msiexec /i <msi> /qn /norestart <PROPERTY=value ...>; the entry's SilentParameters replace /qn /norestart */
        return StringCchPrintfW(out, cch, L"msiexec.exe /i \"%s\" %s %s", file, args[0] ? args : L"/qn /norestart", props);
    }
    it = TypeFromString(inst);
    if (it == IT_UNKNOWN && !args[0] && k == FK_EXE) it = (INSTTYPE)FmNativeGuessInstaller(file);
    return StringCchPrintfW(out, cch, L"\"%s\" %s", file, args[0] ? args : FmNativeSilentSwitches(it));
}

/* The command that removes the app again, recorded when the install succeeded: a featmgr child that finds the
 * program's Uninstall key at that time (so it also works after the app updated itself or left the catalog). */
BOOL FmNativeUninstallLine(const FM_FEATURE *f, LPWSTR out, DWORD cch)
{
    WCHAR reg[128], uname[128], inst[64], fm[MAX_PATH];
    LPCWSTR tag = L"-";

    Rk(f, L"Rapps", L"RegName", reg, ARRAYSIZE(reg));
    Rk(f, L"Rapps", L"UninstallName", uname, ARRAYSIZE(uname));
    Rk(f, L"Rapps", L"Installer", inst, ARRAYSIZE(inst));
    if (!uname[0]) StringCchCopyW(uname, ARRAYSIZE(uname), f->Name);
    if (wcspbrk(reg, L"\"\r\n") || wcspbrk(uname, L"\"\r\n") || !FmFeatmgrExePath(fm, MAX_PATH)) return FALSE;
    if (!_wcsicmp(inst, L"Inno")) tag = L"inno";
    else if (!_wcsicmp(inst, L"NSIS")) tag = L"nsis";
    return SUCCEEDED(StringCchPrintfW(out, cch, L"\"%s\" /nat-uninstall \"%s\" \"%s\" \"%s\"", fm, reg[0] ? reg : L"-", uname, tag));
}

/* ---- uninstalling an installed program (featmgr /nat-uninstall <regname|-> <name> <tag>) ------------------------ */

static HKEY RootOf(const UNENT *e) { return e->root ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER; }
static REGSAM SamOf(const UNENT *e) { return e->wow32 ? KEY_WOW64_32KEY : 0; }

static BOOL RegStr(HKEY k, LPCWSTR name, LPWSTR out, DWORD cch)
{
    DWORD type, cb = (cch - 1) * sizeof(WCHAR);
    WCHAR tmp[2048];
    out[0] = L'\0';
    if (RegQueryValueExW(k, name, NULL, &type, (LPBYTE)out, &cb) != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        out[0] = L'\0';
        return FALSE;
    }
    out[cb / sizeof(WCHAR) < cch ? cb / sizeof(WCHAR) : cch - 1] = L'\0';
    if (type == REG_EXPAND_SZ || wcschr(out, L'%'))
    {
        DWORD n = ExpandEnvironmentStringsW(out, tmp, ARRAYSIZE(tmp));
        if (n && n <= ARRAYSIZE(tmp)) StringCchCopyW(out, cch, tmp);
    }
    return out[0] != L'\0';
}

static DWORD RunWait(LPWSTR cmd, DWORD timeoutMs)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = (DWORD)-1;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        wprintf(L"error: cannot start %s (%lu)\n", cmd, GetLastError());
        return (DWORD)-1;
    }
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, timeoutMs) != WAIT_OBJECT_0)
    {
        wprintf(L"error: the uninstaller did not finish in time\n");
        TerminateProcess(pi.hProcess, 1);
    }
    else
        GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return code;
}

static HKEY HiveOf(LPCWSTR s)
{
    if (!_wcsnicmp(s, L"HKCR", 4)) return HKEY_CLASSES_ROOT;
    if (!_wcsnicmp(s, L"HKCU", 4)) return HKEY_CURRENT_USER;
    if (!_wcsnicmp(s, L"HKLM", 4)) return HKEY_LOCAL_MACHINE;
    return NULL;
}

static BOOL KeyHasContent(HKEY root, LPCWSTR sub, REGSAM sam)
{
    HKEY k;
    DWORD ns = 0, nv = 0;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | sam, &k) != ERROR_SUCCESS) return FALSE;
    RegQueryInfoKeyW(k, NULL, NULL, NULL, &ns, NULL, NULL, &nv, NULL, NULL, NULL, NULL);
    RegCloseKey(k);
    return ns || nv;
}

/* ---- what a generated install may delete -------------------------------------------------------------------------------
 * The install record (a registry subkey) and the catalog entry's Del* lists decide what uninstall deletes, so both are held
 * to the same rules: a relative path stays inside the app's own install directory (no ".", "..", drive, or the root itself),
 * an absolute path is only a Start menu shortcut, a registry key is the app's own key under HKCU\Software or HKLM\SOFTWARE. */

static BOOL SamePathNoSlash(LPCWSTR a, LPCWSTR b)
{
    size_t la = wcslen(a), lb = wcslen(b);
    while (la && a[la - 1] == L'\\') la--;
    while (lb && b[lb - 1] == L'\\') lb--;
    return la == lb && !_wcsnicmp(a, b, la);
}

/* dir is the same as, or an ancestor of, prot */
static BOOL IsOrAbove(LPCWSTR dir, LPCWSTR prot)
{
    size_t l = wcslen(dir);
    while (l && dir[l - 1] == L'\\') l--;
    if (!prot[0] || !l) return FALSE;
    return !_wcsnicmp(dir, prot, l) && (prot[l] == L'\0' || prot[l] == L'\\');
}

/* The canonical form of a drive-letter path, so that one folder has one spelling before it is compared: '/' -> '\', no doubled
 * separators, no trailing separator, "." / ".." and names ending in a space or a dot refused (Windows strips those, so "App."
 * would alias "App"), GetFullPathNameW, then GetLongPathNameW on the longest part that exists (8.3 names such as PROGRA~1 become
 * the long name). FALSE: not a plain "X:\..." path (UNC, device, relative), or a refused name. */
BOOL FmCanonPath(LPCWSTR in, LPWSTR out, DWORD cch)
{
    WCHAR t[MAX_PATH], full[MAX_PATH], head[MAX_PATH], lng[MAX_PATH];
    size_t n = 0, i, cut;
    LPCWSTR p;
    DWORD r;

    if (!in || !(((in[0] | 0x20) >= L'a' && (in[0] | 0x20) <= L'z') && in[1] == L':' && (in[2] == L'\\' || in[2] == L'/')))
        return FALSE;
    for (p = in; *p; p++)
    {
        WCHAR c = *p == L'/' ? L'\\' : *p;
        if (c < 32 || wcschr(L"\"*?<>|", c) || (c == L':' && p != in + 1)) return FALSE;
        if (c == L'\\' && n && t[n - 1] == L'\\') continue;               /* doubled separator */
        if (n + 1 >= ARRAYSIZE(t)) return FALSE;
        t[n++] = c;
    }
    while (n > 3 && t[n - 1] == L'\\') n--;
    t[n] = L'\0';
    for (i = 3; i < n; )
    {
        size_t l = wcscspn(t + i, L"\\");
        if ((l == 1 && t[i] == L'.') || (l == 2 && t[i] == L'.' && t[i + 1] == L'.')) return FALSE;
        if (l && (t[i + l - 1] == L' ' || t[i + l - 1] == L'.')) return FALSE;
        i += l + 1;
    }
    r = GetFullPathNameW(t, ARRAYSIZE(full), full, NULL);
    if (!r || r >= ARRAYSIZE(full)) return FALSE;
    /* the longest existing head gets its long name; the rest does not exist yet and is kept as written */
    StringCchCopyW(head, ARRAYSIZE(head), full);
    for (;;)
    {
        r = GetLongPathNameW(head, lng, ARRAYSIZE(lng));
        if (r && r < ARRAYSIZE(lng)) break;
        cut = wcslen(head);
        while (cut > 3 && head[cut - 1] != L'\\') cut--;
        if (cut <= 3) { lng[0] = L'\0'; break; }
        head[cut - 1] = L'\0';
    }
    if (lng[0] && _wcsnicmp(lng, L"\\\\", 2))
    {
        size_t hl = wcslen(head);
        if (FAILED(StringCchPrintfW(out, cch, L"%s%s", lng, full + hl))) return FALSE;
    }
    else if (FAILED(StringCchCopyW(out, cch, full))) return FALSE;
    n = wcslen(out);
    while (n > 3 && out[n - 1] == L'\\') out[--n] = L'\0';
    return TRUE;
}

static BOOL CanonFolder(int csidl, LPCWSTR sub, LPWSTR out)
{
    WCHAR p[MAX_PATH];
    p[0] = L'\0';
    if (SHGetFolderPathW(NULL, csidl, NULL, 0, p) != S_OK || !p[0]) return FALSE;
    if (sub && FAILED(StringCchCatW(p, MAX_PATH, sub))) return FALSE;
    return FmCanonPath(p, out, MAX_PATH);
}

/* TRUE: dir must not be an install directory (a system or profile folder, an ancestor of one, a drive root, or has "..") */
BOOL FmBadInstallRoot(LPCWSTR dir)
{
    static const int csidls[] = { CSIDL_PROGRAM_FILES, CSIDL_PROGRAM_FILESX86, CSIDL_WINDOWS, CSIDL_SYSTEM, CSIDL_PROFILE,
                                  CSIDL_LOCAL_APPDATA, CSIDL_APPDATA, CSIDL_COMMON_APPDATA, CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS,
                                  CSIDL_DESKTOPDIRECTORY, CSIDL_COMMON_DESKTOPDIRECTORY, CSIDL_PROGRAM_FILES_COMMON };
    WCHAR c[MAX_PATH], p[MAX_PATH];
    size_t i;

    if (!FmCanonPath(dir, c, MAX_PATH) || wcslen(c) < 4) return TRUE;
    for (i = 0; i < ARRAYSIZE(csidls); i++)
        if (CanonFolder(csidls[i], NULL, p) && IsOrAbove(c, p)) return TRUE;
    if (CanonFolder(CSIDL_LOCAL_APPDATA, L"\\Programs", p) && SamePathNoSlash(c, p)) return TRUE;
    return FALSE;
}

/* The install directory of a generated install: canonical (FmCanonPath), strictly BELOW Program Files, Program Files (x86) or
 * %LOCALAPPDATA%\Programs (the bases of the RAPPS [Generate] Dir rules), and not a protected folder (FmBadInstallRoot).
 * canon receives the canonical form (MAX_PATH), which is what gets created and recorded. */
BOOL FmInstallDirOk(LPCWSTR dir, LPWSTR canon)
{
    static const struct { int csidl; LPCWSTR sub; } bases[] = {
        { CSIDL_PROGRAM_FILES, NULL }, { CSIDL_PROGRAM_FILESX86, NULL }, { CSIDL_LOCAL_APPDATA, L"\\Programs" } };
    WCHAR c[MAX_PATH], b[MAX_PATH];
    size_t i;

    if (!FmCanonPath(dir, c, MAX_PATH) || FmBadInstallRoot(c)) return FALSE;
    for (i = 0; i < ARRAYSIZE(bases); i++)
    {
        size_t l;
        if (!CanonFolder(bases[i].csidl, bases[i].sub, b)) continue;
        l = wcslen(b);
        if (!_wcsnicmp(c, b, l) && c[l] == L'\\' && c[l + 1])
        {
            if (canon) StringCchCopyW(canon, MAX_PATH, c);
            return TRUE;
        }
    }
    return FALSE;
}

/* TRUE: path is below the Start menu Programs folder (user or all users), not the folder itself */
static BOOL UnderStartMenu(LPCWSTR path)
{
    static const int ids[] = { CSIDL_PROGRAMS, CSIDL_COMMON_PROGRAMS };
    WCHAR p[MAX_PATH];
    int i;
    if (wcsstr(path, L"..")) return FALSE;
    for (i = 0; i < 2; i++)
    {
        size_t l;
        if (SHGetFolderPathW(NULL, ids[i], NULL, 0, p) != S_OK) continue;
        l = wcslen(p);
        if (!_wcsnicmp(path, p, l) && path[l] == L'\\' && path[l + 1]) return TRUE;
    }
    return FALSE;
}

/* TRUE: path is a shortcut (.lnk) whose target lies inside dir: a Start menu entry the install itself made (natgen.c records the
 * exact path of the shortcut it saved, pointing at the app's main program); another app's shortcut, or a file that is not a
 * shortcut, is never deleted on the strength of the record alone */
static BOOL OwnShortcut(LPCWSTR path, LPCWSTR dir, LPWSTR found, DWORD cchFound)
{
    IShellLinkW *sl = NULL;
    IPersistFile *pf = NULL;
    WCHAR target[MAX_PATH], c[MAX_PATH];
    size_t n = wcslen(path), l = wcslen(dir);
    HRESULT hrInit, hr;
    BOOL ok = FALSE;

    if (found && cchFound) found[0] = L'\0';
    if (n < 5 || _wcsicmp(path + n - 4, L".lnk")) return FALSE;
    hrInit = CoInitialize(NULL);
    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl);
    if (SUCCEEDED(hr)) hr = IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf);
    if (SUCCEEDED(hr)) hr = IPersistFile_Load(pf, path, STGM_READ);
    target[0] = L'\0';
    if (SUCCEEDED(hr)) hr = IShellLinkW_GetPath(sl, target, MAX_PATH, NULL, 0);
    if (FAILED(hr) || !target[0])
    {
        /* no resolved path: the link's raw path as it was saved */
        target[0] = L'\0';
        if (sl && pf) hr = IShellLinkW_GetPath(sl, target, MAX_PATH, NULL, SLGP_RAWPATH);
    }
    if (found && cchFound) StringCchCopyW(found, cchFound, target);
    if (SUCCEEDED(hr) && target[0] && FmCanonPath(target, c, MAX_PATH))
        ok = !_wcsnicmp(c, dir, l) && c[l] == L'\\' && c[l + 1];
    if (pf) IPersistFile_Release(pf);
    if (sl) IShellLinkW_Release(sl);
    if (SUCCEEDED(hrInit)) CoUninitialize();
    return ok;
}

/* key is pre or below it ("Software\ReactOS" covers "Software\ReactOS\Nitro", not "Software\ReactOSFoo") */
static BOOL PrefixKey(LPCWSTR key, LPCWSTR pre)
{
    size_t l = wcslen(pre);
    return !_wcsnicmp(key, pre, l) && (key[l] == L'\0' || key[l] == L'\\');
}

/* "HKCU\Software\Vendor\App" / "HKLM64\SOFTWARE\..." : tree = the key is deleted with everything below it.
 * Never: Windows / Classes / Policies / Wow6432Node, the system's Cryptography key, the ReactOS keys (featmgr's own state). */
BOOL FmGenRegOk(LPCWSTR spec, BOOL tree)
{
    LPCWSTR sub;
    int depth = 0;
    LPCWSTR p;

    if (_wcsnicmp(spec, L"HKCU", 4) && _wcsnicmp(spec, L"HKLM", 4)) return FALSE;
    sub = spec + 4;
    if ((sub[0] == L'6' && sub[1] == L'4') || (sub[0] == L'3' && sub[1] == L'2')) sub += 2;
    if (*sub != L'\\') return FALSE;
    sub++;
    if (_wcsnicmp(sub, L"Software\\", 9) || wcsstr(sub, L"..") || wcsstr(sub, L"\\\\")) return FALSE;
    if (sub[wcslen(sub) - 1] == L'\\') return FALSE;
    for (p = sub; *p; p++) if (*p == L'\\') depth++;
    depth++;
    /* a per-user ProgID of the app itself ("HKCU\Software\Classes\Autoruns.Logfile.1", as the Sysinternals entries name it):
     * one key, a dotted name that is not an extension; nothing else under Classes (CLSID, exefile, "*", ...) */
    if (!_wcsnicmp(sub, L"Software\\Classes\\", 17))
    {
        LPCWSTR id = sub + 17;
        return tree && !_wcsnicmp(spec, L"HKCU", 4) && depth == 3 && id[0] != L'.' && wcschr(id, L'.') && !wcschr(id, L'*');
    }
    if (!_wcsnicmp(sub, L"Software\\Microsoft\\Windows", 26) || PrefixKey(sub, L"Software\\Classes") ||
        PrefixKey(sub, L"Software\\Policies") || PrefixKey(sub, L"Software\\Wow6432Node") ||
        PrefixKey(sub, L"Software\\Microsoft\\Cryptography") || PrefixKey(sub, L"Software\\ReactOS")) return FALSE;
    return tree ? depth >= 3 : depth >= 2;
}

/* a relative record path ("\sub\file"): nothing but names below the install directory */
static BOOL RelOk(LPCWSTR data)
{
    WCHAR t[MAX_PATH * 2];
    if (data[0] != L'\\' || !data[1]) return FALSE;
    StringCchCopyW(t, ARRAYSIZE(t), data + 1);
    return FmSafeTreeName(t);
}

/* Remove what a generated install recorded (its "RApps" subkey: F file, D dir tree, d empty dir, K key tree, k empty key). */
static int UninstallGenerated(const UNENT *e, HKEY arp)
{
    HKEY ent;
    WCHAR loc[MAX_PATH], raw[MAX_PATH];
    DWORD stage, vi, n = 0;
    int rc = 0;
    BOOL parentEmpty = FALSE;

    if (RegOpenKeyExW(arp, GENERATE_ARPSUBKEY, 0, KEY_READ, &ent) != ERROR_SUCCESS) return 1;
    RegStr(arp, L"InstallLocation", raw, ARRAYSIZE(raw));
    /* the record decides what is deleted: its install location must pass the same rule as at install time (canonical, strictly
     * below Program Files, Program Files (x86) or %LOCALAPPDATA%\Programs, not a protected folder); otherwise nothing is deleted */
    if (!FmInstallDirOk(raw, loc))
    {
        wprintf(L"error: the install record names no usable install location ('%s'); nothing was deleted\n", raw);
        RegCloseKey(ent);
        return 1;
    }
    for (stage = 0; stage < 3; stage++)
    {
        for (vi = 0; ; vi++)
        {
            WCHAR val[MAX_PATH], data[MAX_PATH * 2], path[MAX_PATH * 2];
            DWORD vsz = ARRAYSIZE(val), dsz = sizeof(data) - sizeof(WCHAR), rt;
            LONG r;
            WCHAR op;

            data[ARRAYSIZE(data) - 1] = L'\0';
            r = RegEnumValueW(ent, vi, val, &vsz, NULL, &rt, (LPBYTE)data, &dsz);
            if (r != ERROR_SUCCESS) break;
            if (rt != REG_SZ || !data[0]) continue;
            data[dsz / sizeof(WCHAR) < ARRAYSIZE(data) ? dsz / sizeof(WCHAR) : ARRAYSIZE(data) - 1] = L'\0';
            op = val[0];
            if (op == L'd' && !wcscmp(data, L"\\.."))
            {
                parentEmpty = TRUE;                 /* DelDirEmpty ".." (the vendor folder): handled last, see below */
                continue;
            }
            if (wcsstr(data, L"..\\") || wcsstr(data, L"\\.."))
                continue;
            /* stage 0: the absolute (Start menu shortcut) F entries, judged while the files they point at still exist;
             * stage 1: the other F entries and K; stage 2: d, D, k. Each entry is judged in the stage that acts on it. */
            if (!((stage == 0 && op == L'F' && data[0] != L'\\') || (stage == 1 && ((op == L'F' && data[0] == L'\\') || op == L'K')) ||
                  (stage == 2 && (op == L'd' || op == L'D' || op == L'k'))))
                continue;
            /* the record is data: hold every entry to the confinement rules before it deletes anything */
            if (op == L'K' || op == L'k')
            {
                if (!FmGenRegOk(data, op == L'K')) { wprintf(L"refused record entry %s: not the app's own registry key\n", val); continue; }
            }
            else if (op == L'F' || op == L'D' || op == L'd')
            {
                BOOL ok;
                WCHAR found[MAX_PATH];
                found[0] = L'\0';
                if (data[0] == L'\\') ok = (op == L'd' && !data[1]) || RelOk(data);          /* "\" alone = the root, only if empty */
                else if (op == L'F')
                {
                    ok = UnderStartMenu(data) && OwnShortcut(data, loc, found, ARRAYSIZE(found));   /* the app's own Start menu shortcut */
                    if (!ok && UnderStartMenu(data))
                    {
                        wprintf(L"refused record entry %s: '%s' is not a shortcut to a file of this install (target '%s')\n", val, data, found);
                        continue;
                    }
                }
                else ok = op == L'd' && UnderStartMenu(data);                                /* its Start menu folder, if empty */
                if (!ok) { wprintf(L"refused record entry %s: '%s' is outside the install directory\n", val, data); continue; }
            }
            {
                if (op == L'K' || op == L'k')
                {
                    HKEY hive = HiveOf(data);
                    REGSAM sam = 0;
                    LPCWSTR sub = data + 4;
                    if (!hive) continue;
                    if (sub[0] == L'6' && sub[1] == L'4') { sam = KEY_WOW64_64KEY; sub += 2; }
                    else if (sub[0] == L'3' && sub[1] == L'2') { sam = KEY_WOW64_32KEY; sub += 2; }
                    if (*sub != L'\\' || !sub[1]) continue;
                    sub++;
                    if (op == L'K')
                    {
                        HKEY pk;
                        WCHAR par[MAX_PATH], *leaf;
                        StringCchCopyW(par, MAX_PATH, sub);
                        leaf = wcsrchr(par, L'\\');
                        if (!leaf) continue;
                        *leaf++ = L'\0';
                        if (RegOpenKeyExW(hive, par, 0, DELETE | KEY_READ | sam, &pk) == ERROR_SUCCESS)
                        {
                            SHDeleteKeyW(pk, leaf);
                            RegCloseKey(pk);
                        }
                    }
                    else if (!KeyHasContent(hive, sub, sam))
                    {
                        HKEY pk;
                        WCHAR par[MAX_PATH], *leaf;
                        StringCchCopyW(par, MAX_PATH, sub);
                        leaf = wcsrchr(par, L'\\');
                        if (!leaf) continue;
                        *leaf++ = L'\0';
                        if (RegOpenKeyExW(hive, par, 0, DELETE | KEY_READ | sam, &pk) == ERROR_SUCCESS)
                        {
                            RegDeleteKeyW(pk, leaf);
                            RegCloseKey(pk);
                        }
                    }
                    continue;
                }
                if (data[0] == L'\\')
                    StringCchPrintfW(path, ARRAYSIZE(path), L"%s%s", loc, data);
                else
                    StringCchCopyW(path, ARRAYSIZE(path), data);
                if (op == L'F')
                {
                    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
                    if (!DeleteFileW(path))
                    {
                        DWORD er = GetLastError();
                        if (er != ERROR_FILE_NOT_FOUND && er != ERROR_PATH_NOT_FOUND)
                        {
                            wprintf(L"error: cannot delete %s (%lu)\n", path, er);
                            rc = 1;
                        }
                    }
                }
                else if (op == L'D')
                    FmDeleteTree(path);
                else
                    RemoveDirectoryW(path);
                n++;
            }
        }
    }
    RegCloseKey(ent);
    if (parentEmpty)
    {
        /* the parent of the install directory, removed only if empty, and only if it is itself a folder an install could own
         * (strictly below Program Files / Program Files (x86) / LocalAppData\Programs, not protected, not a link) */
        WCHAR par[MAX_PATH], cp[MAX_PATH];
        DWORD a;
        StringCchCopyW(par, MAX_PATH, loc);
        PathRemoveFileSpecW(par);
        a = GetFileAttributesW(par);
        if (!FmInstallDirOk(par, cp) || (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT)))
            wprintf(L"refused record entry '\\..': the parent folder '%s' is a protected folder; it was kept\n", par);
        else if (RemoveDirectoryW(cp))
            n++;
    }
    wprintf(L"removed %lu recorded item(s)\n", n);
    UNREFERENCED_PARAMETER(e);
    return rc;
}

static void DeleteArpKey(const UNENT *e)
{
    HKEY un;
    if (RegOpenKeyExW(RootOf(e), UNINSTALL_SUBKEY, 0, KEY_READ | DELETE | SamOf(e), &un) == ERROR_SUCCESS)
    {
        SHDeleteKeyW(un, e->key);
        RegCloseKey(un);
    }
}

int FmNativeUninstallMain(int argc, WCHAR **argv)
{
    /* argv: featmgr /nat-uninstall <regname|-> <name> [<tag>] */
    LPCWSTR reg = argc > 2 ? argv[2] : L"-", name = argc > 3 ? argv[3] : L"", tag = argc > 4 ? argv[4] : L"-";
    const UNENT *e;
    UNENT ent;
    HKEY hk;
    WCHAR cmd[2048], tmp[2048], keyPath[300];
    DWORD wi = 0, type, cb = sizeof(wi), code;
    BOOL isGen = FALSE, nsisSync = FALSE;
    WCHAR nsisExe[MAX_PATH];

    nsisExe[0] = L'\0';
    FmNativeInvalidate();
    e = FindInstalled(!wcscmp(reg, L"-") ? L"" : reg, name);
    if (!e)
    {
        wprintf(L"'%s' is not in the installed programs list; nothing to uninstall\n", name);
        return 0;
    }
    ent = *e;
    StringCchPrintfW(keyPath, ARRAYSIZE(keyPath), UNINSTALL_SUBKEY L"\\%s", ent.key);
    if (RegOpenKeyExW(RootOf(&ent), keyPath, 0, KEY_READ | SamOf(&ent), &hk) != ERROR_SUCCESS)
    {
        wprintf(L"error: cannot open the Uninstall key of '%s'\n", ent.key);
        return 1;
    }
    {
        HKEY gk;
        if (RegOpenKeyExW(hk, GENERATE_ARPSUBKEY, 0, KEY_READ, &gk) == ERROR_SUCCESS) { isGen = TRUE; RegCloseKey(gk); }
    }
    if (isGen)
    {
        int rc = UninstallGenerated(&ent, hk);
        RegCloseKey(hk);
        if (rc == 0) DeleteArpKey(&ent);
        return rc;
    }
    if (RegQueryValueExW(hk, L"WindowsInstaller", NULL, &type, (LPBYTE)&wi, &cb) == ERROR_SUCCESS && type == REG_DWORD && wi)
        StringCchPrintfW(cmd, ARRAYSIZE(cmd), L"msiexec.exe /x%s /qn /norestart", ent.key);
    else
    {
        BOOL quiet = RegStr(hk, L"QuietUninstallString", cmd, ARRAYSIZE(cmd));
        int type;
        WCHAR d[MAX_PATH];

        if (!quiet && !RegStr(hk, L"UninstallString", cmd, ARRAYSIZE(cmd)))
        {
            wprintf(L"error: '%s' has no uninstall command\n", ent.key);
            RegCloseKey(hk);
            return 1;
        }
        /* the program's own uninstaller asks questions unless it is told to be silent: which switches depends on what built it */
        if (cmd[0] == L'"')
        {
            LPCWSTR q = wcschr(cmd + 1, L'"');
            StringCchCopyNW(nsisExe, MAX_PATH, cmd + 1, q ? (size_t)(q - cmd - 1) : MAX_PATH - 1);
        }
        else
        {
            LPCWSTR x = StrStrIW(cmd, L".exe");
            StringCchCopyNW(nsisExe, MAX_PATH, cmd, x ? (size_t)(x - cmd) + 4 : MAX_PATH - 1);
        }
        type = !_wcsicmp(tag, L"inno") ? 1 : !_wcsicmp(tag, L"nsis") ? 2 : 0;
        if (!type)
        {
            type = FmNativeGuessInstaller(nsisExe);
            if (!type && StrStrIW(nsisExe, L"\\unins")) type = 1;
        }
        if (type == 1 && !quiet) StringCchCatW(cmd, ARRAYSIZE(cmd), L" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART");
        else if (type == 2)
        {
            /* An NSIS uninstaller copies itself to %TEMP% and returns at once, so the files are still there when we look
             * (a QuietUninstallString of /S does the same). "_?=<its folder>" makes it uninstall in place and wait; it then
             * cannot delete itself, so we do. */
            StringCchCopyW(d, MAX_PATH, nsisExe);
            PathRemoveFileSpecW(d);
            if (!quiet) StringCchCatW(cmd, ARRAYSIZE(cmd), L" /S");
            if (!StrStrIW(cmd, L"_?="))
            {
                StringCchCatW(cmd, ARRAYSIZE(cmd), L" _?=");
                StringCchCatW(cmd, ARRAYSIZE(cmd), d);
                nsisSync = TRUE;
            }
        }
    }
    RegCloseKey(hk);
    StringCchCopyW(tmp, ARRAYSIZE(tmp), cmd);
    wprintf(L"running: %s\n", tmp);
    code = RunWait(tmp, 60u * 60u * 1000u);
    wprintf(L"exit code: %lu\n", code);
    if (code == 0 && !wi)
    {
        /* some uninstallers hand the work to a copy of themselves and return at once: wait (up to a minute) for the program's
         * Uninstall key to go, which they remove last, before the caller looks at the result */
        int w;
        for (w = 0; w < 120; w++)
        {
            HKEY k;
            if (RegOpenKeyExW(RootOf(&ent), keyPath, 0, KEY_READ | SamOf(&ent), &k) != ERROR_SUCCESS) break;
            RegCloseKey(k);
            if (w == 0) wprintf(L"waiting for the uninstaller to finish\n");
            Sleep(500);
        }
        if (w == 120) wprintf(L"note: the Uninstall key of '%s' is still there after a minute\n", ent.key);
    }
    if (nsisSync && code == 0 && nsisExe[0])
    {
        WCHAR d[MAX_PATH];
        StringCchCopyW(d, MAX_PATH, nsisExe);
        PathRemoveFileSpecW(d);
        SetFileAttributesW(nsisExe, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(nsisExe);
        RemoveDirectoryW(d);                 /* only when empty */
    }
    return (code == 0 || code == 3010 || code == 1641) ? 0 : 1;
}
