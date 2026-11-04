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

#include "featmgr.h"
#include <shlwapi.h>
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

/* Remove what a generated install recorded (its "RApps" subkey: F file, D dir tree, d empty dir, K key tree, k empty key). */
static int UninstallGenerated(const UNENT *e, HKEY arp)
{
    HKEY ent;
    WCHAR loc[MAX_PATH], win[MAX_PATH];
    DWORD stage, vi, n = 0;
    int rc = 0;

    if (RegOpenKeyExW(arp, GENERATE_ARPSUBKEY, 0, KEY_READ, &ent) != ERROR_SUCCESS) return 1;
    RegStr(arp, L"InstallLocation", loc, ARRAYSIZE(loc));
    GetWindowsDirectoryW(win, MAX_PATH);
    PathRemoveBackslashW(loc);
    /* the record decides what is deleted: refuse one whose install location is empty, a drive root or the system */
    if (wcslen(loc) < 4 || !_wcsicmp(loc, win) || StrStrIW(win, loc) == win)
    {
        wprintf(L"error: the install record names no usable install location ('%s'); nothing was deleted\n", loc);
        RegCloseKey(ent);
        return 1;
    }
    for (stage = 0; stage < 2; stage++)
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
            if (wcsstr(data, L"..\\") || wcsstr(data, L"\\.."))
                continue;
            if ((stage == 0 && (op == L'F' || op == L'K')) || (stage == 1 && (op == L'd' || op == L'D' || op == L'k')))
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
