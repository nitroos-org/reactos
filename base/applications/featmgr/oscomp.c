/*
 * PROJECT:     ReactOS-Nitro Optional Features / Addon Manager
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Operating system components that setup left out (the record under
 *              HKLM\SOFTWARE\ReactOS\Nitro\Components): list them as features and add them
 *              later from the installation medium (a drive or a folder, "/source:").
 *
 *              What a component is comes from components.inf of the medium (the same file setup
 *              used): its file patterns, what it needs, the registry lines it owns. The files come
 *              out of the cabinet of the medium, the registry lines out of registry.inf, the Start
 *              menu entries from shortcuts.inf. A file that belongs to a component that is still
 *              left out (SysWOW64\calc.exe: wow64 and accessories) is not copied, as at setup.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#define COBJMACROS
#include "featmgr.h"
#include <setupapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>

#define COMPONENTS_KEY  L"SOFTWARE\\ReactOS\\Nitro\\Components"
#define LOGF(log, ...) do { if (log) { fwprintf((log), __VA_ARGS__); fflush(log); } } while (0)

#ifdef _WIN64
#define MEDIUM_ARCH_DIR L"amd64"
#else
#define MEDIUM_ARCH_DIR L"i386"
#endif

static WCHAR g_source[MAX_PATH];

void FmOsCompSetSource(LPCWSTR source)
{
    g_source[0] = L'\0';
    if (source && source[0])
        StringCchCopyW(g_source, ARRAYSIZE(g_source), source);
}

/* /force: add from a medium that is not the one the system was installed from (see CheckMedium) */
static BOOL g_force;

void FmOsCompSetForce(BOOL force)
{
    g_force = force;
}

/* A path from the medium (the cabinet inf of a disc or folder that anybody can have made) that stays inside the system
 * folder: no ".." element, no drive or stream colon, not rooted, no empty element. */
static BOOL RelPathOk(LPCWSTR rel)
{
    LPCWSTR p = rel;

    if (!*p || *p == L'\\' || *p == L'/') return FALSE;
    while (*p)
    {
        LPCWSTR e = p;
        size_t n;

        while (*e && *e != L'\\' && *e != L'/') e++;
        n = (size_t)(e - p);
        if (!n) return FALSE;
        if (n == 2 && p[0] == L'.' && p[1] == L'.') return FALSE;
        if (n == 1 && p[0] == L'.') return FALSE;
        for (; p < e; p++)
            if (*p == L':') return FALSE;
        p = *e ? e + 1 : e;
    }
    return TRUE;
}

/* ---- the record ---------------------------------------------------------- */

static BOOL IdOk(LPCWSTR id)
{
    size_t n = wcslen(id), i;
    if (!n || n >= 32) return FALSE;
    for (i = 0; i < n; i++)
        if (!(iswalnum(id[i]) || id[i] == L'-' || id[i] == L'_')) return FALSE;
    return TRUE;
}

/* TRUE when setup recorded the component; installed / name from the record */
static BOOL RecordGet(LPCWSTR id, DWORD *installed, LPWSTR name, DWORD cchName)
{
    WCHAR key[160];
    HKEY hk;
    DWORD cb, type, v = 1;

    if (!IdOk(id)) return FALSE;
    StringCchPrintfW(key, ARRAYSIZE(key), COMPONENTS_KEY L"\\%s", id);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_QUERY_VALUE, &hk) != ERROR_SUCCESS) return FALSE;
    cb = sizeof(v);
    if (RegQueryValueExW(hk, L"Installed", NULL, &type, (LPBYTE)&v, &cb) != ERROR_SUCCESS || type != REG_DWORD) v = 1;
    if (installed) *installed = v;
    if (name && cchName)
    {
        cb = (cchName - 1) * sizeof(WCHAR);
        name[0] = L'\0';
        if (RegQueryValueExW(hk, L"Name", NULL, &type, (LPBYTE)name, &cb) != ERROR_SUCCESS || type != REG_SZ) name[0] = L'\0';
        else name[cb / sizeof(WCHAR)] = L'\0';
    }
    RegCloseKey(hk);
    return TRUE;
}

BOOL FmOsCompIsComponent(LPCWSTR id)
{
    return RecordGet(id, NULL, NULL, 0);
}

static void FillFeature(LPCWSTR id, FM_FEATURE *f)
{
    DWORD installed = 1;
    WCHAR name[FM_MAX_NAME];

    ZeroMemory(f, sizeof(*f));
    RecordGet(id, &installed, name, ARRAYSIZE(name));
    StringCchCopyW(f->Id, ARRAYSIZE(f->Id), id);
    StringCchCopyW(f->Name, ARRAYSIZE(f->Name), name[0] ? name : id);
    f->Tier = FM_TIER_OS;
    f->Removable = FALSE;
    f->PayloadAvailable = TRUE;
    f->BuiltIn = installed != 0;
    f->State = installed ? FM_STATE_ENABLED : FM_STATE_NOT_INSTALLED;
    StringCchCopyW(f->Group, ARRAYSIZE(f->Group), L"Components");
    if (installed)
        StringCchCopyW(f->Description, ARRAYSIZE(f->Description),
                       L"An operating system component that is part of this installation.");
    else
        StringCchCopyW(f->Description, ARRAYSIZE(f->Description),
                       L"Left out when this system was installed. Turning it on copies it from the installation "
                       L"medium (the disc, or a folder given with /source:).");
}

BOOL FmOsCompFind(LPCWSTR id, FM_FEATURE *out)
{
    if (!FmOsCompIsComponent(id)) return FALSE;
    FillFeature(id, out);
    return TRUE;
}

int FmOsCompList(FM_FEATURE *out, int max)
{
    HKEY hk;
    int n = 0;
    DWORD i;
    WCHAR id[64];

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, COMPONENTS_KEY, 0, KEY_READ, &hk) != ERROR_SUCCESS) return 0;
    for (i = 0; n < max; i++)
    {
        DWORD cch = ARRAYSIZE(id);
        if (RegEnumKeyExW(hk, i, id, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (!IdOk(id)) continue;
        FillFeature(id, &out[n++]);
    }
    RegCloseKey(hk);
    return n;
}

/* ---- patterns ----------------------------------------------------------- */

/* Case-insensitive wildcard match: '*' = any run (also '\'), '?' = one character. The same rule as setup's
 * ComponentGlobMatch (base/setup/lib/components.c): a path is the same component file at setup and here. */
static BOOL Glob(LPCWSTR pat, LPCWSTR s)
{
    LPCWSTR sp = NULL, ss = NULL;

    while (*s)
    {
        if (*pat == L'*') { sp = ++pat; ss = s; }
        else if (*pat == L'?' || (*pat && towupper(*pat) == towupper(*s))) { pat++; s++; }
        else if (sp) { pat = sp; s = ++ss; }
        else return FALSE;
    }
    while (*pat == L'*') pat++;
    return *pat == L'\0';
}

typedef struct _PATLIST
{
    WCHAR **p;
    int n, cap;
} PATLIST;

static void PatAdd(PATLIST *l, LPCWSTR s)
{
    if (l->n == l->cap)
    {
        int nc = l->cap ? l->cap * 2 : 32;
        WCHAR **np = l->p ? HeapReAlloc(GetProcessHeap(), 0, l->p, nc * sizeof(WCHAR *)) : HeapAlloc(GetProcessHeap(), 0, nc * sizeof(WCHAR *));
        if (!np) return;
        l->p = np; l->cap = nc;
    }
    l->p[l->n] = StrDupW(s);
    if (l->p[l->n]) l->n++;
}

static void PatFree(PATLIST *l)
{
    int i;
    for (i = 0; i < l->n; i++) LocalFree(l->p[i]);
    if (l->p) HeapFree(GetProcessHeap(), 0, l->p);
    ZeroMemory(l, sizeof(*l));
}

static BOOL PatAny(const PATLIST *l, LPCWSTR s)
{
    int i;
    for (i = 0; i < l->n; i++)
        if (Glob(l->p[i], s)) return TRUE;
    return FALSE;
}

/* every value (field 1 on) of Key in Section of the components.inf of the medium (the [Strings] tokens are expanded) */
static void ReadFields(HINF inf, LPCWSTR section, LPCWSTR key, PATLIST *out)
{
    INFCONTEXT c;
    DWORD i, n;
    WCHAR v[512];

    if (!SetupFindFirstLineW(inf, section, key, &c)) return;
    n = SetupGetFieldCount(&c);
    for (i = 1; i <= n; i++)
        if (SetupGetStringFieldW(&c, i, v, ARRAYSIZE(v), NULL) && v[0])
            PatAdd(out, v);
}

/* ---- the medium ---------------------------------------------------------- */

static BOOL FileThere(LPCWSTR dir, LPCWSTR name)
{
    WCHAR p[MAX_PATH];
    StringCchPrintfW(p, ARRAYSIZE(p), L"%s\\%s", dir, name);
    return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES;
}

static BOOL IsMediumDir(LPCWSTR dir)
{
    return FileThere(dir, L"components.inf") && FileThere(dir, L"txtsetup.sif") && FileThere(dir, L"reactos.inf");
}

/* The folder of the medium that holds components.inf: the given path itself or its amd64/i386 folder; else the
 * root of every CD-ROM drive. */
static BOOL FindMedium(LPWSTR dir, DWORD cch, FILE *log)
{
    WCHAR cand[MAX_PATH], drives[256], *d;
    LPCWSTR given = g_source;

    if (given[0])
    {
        StringCchCopyW(cand, ARRAYSIZE(cand), given);
        PathRemoveBackslashW(cand);
        if (IsMediumDir(cand)) { StringCchCopyW(dir, cch, cand); return TRUE; }
        StringCchPrintfW(cand, ARRAYSIZE(cand), L"%s\\" MEDIUM_ARCH_DIR, given);
        if (IsMediumDir(cand)) { StringCchCopyW(dir, cch, cand); return TRUE; }
        LOGF(log, L"error: %s is not an installation medium (no components.inf, txtsetup.sif and reactos.inf there or in its " MEDIUM_ARCH_DIR L" folder)\n", given);
        FmSetLastMessage(L"%s is not an installation medium for this system. Give the folder or drive that holds the " MEDIUM_ARCH_DIR L" folder of the installation disc.", given);
        return FALSE;
    }
    if (GetLogicalDriveStringsW(ARRAYSIZE(drives) - 1, drives))
    {
        for (d = drives; *d; d += wcslen(d) + 1)
        {
            if (GetDriveTypeW(d) != DRIVE_CDROM) continue;
            StringCchPrintfW(cand, ARRAYSIZE(cand), L"%s" MEDIUM_ARCH_DIR, d);
            if (IsMediumDir(cand)) { StringCchCopyW(dir, cch, cand); return TRUE; }
        }
    }
    LOGF(log, L"error: no installation disc with this system's files was found in a CD/DVD drive; use /source:<folder or drive>\n");
    FmSetLastMessage(L"The installation disc was not found. Put the disc this system was installed from in the drive, or run: featmgr /enable <component> /source:<folder or drive>");
    return FALSE;
}

/* Identity of a medium: size, number of files and set id of its reactos.cab (CFHEADER), as setup recorded it (MediumId of the record) */
static BOOL MediumIdOf(LPCWSTR medium, LPWSTR id, size_t cch)
{
    WCHAR p[MAX_PATH];
    BYTE h[36];
    DWORD got = 0;
    HANDLE f;
    BOOL ok;

    StringCchPrintfW(p, ARRAYSIZE(p), L"%s\\reactos.cab", medium);
    f = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    ok = ReadFile(f, h, sizeof(h), &got, NULL) && got == sizeof(h) && h[0] == 'M' && h[1] == 'S' && h[2] == 'C' && h[3] == 'F';
    CloseHandle(f);
    if (!ok) return FALSE;
    StringCchPrintfW(id, cch, L"%08lx-%04x-%04x", *(DWORD *)&h[8], (unsigned)*(WORD *)&h[28], (unsigned)*(WORD *)&h[32]);
    return TRUE;
}

/* Is this the medium the system was installed from? A record without MediumId (an older setup) is not checked. */
static BOOL CheckMedium(LPCWSTR medium, FILE *log)
{
    HKEY hk;
    WCHAR rec[40], have[40] = L"";
    DWORD cb = sizeof(rec) - sizeof(WCHAR), type;
    BOOL has = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, COMPONENTS_KEY, 0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS)
    {
        has = RegQueryValueExW(hk, L"MediumId", NULL, &type, (LPBYTE)rec, &cb) == ERROR_SUCCESS && type == REG_SZ && cb >= sizeof(WCHAR);
        RegCloseKey(hk);
    }
    if (!has)
    {
        LOGF(log, L"note: the record of this system does not say which medium it was installed from: the medium is not checked\n");
        return TRUE;
    }
    rec[cb / sizeof(WCHAR)] = L'\0';
    rec[ARRAYSIZE(rec) - 1] = L'\0';
    if (MediumIdOf(medium, have, ARRAYSIZE(have)) && !_wcsicmp(have, rec)) return TRUE;
    if (g_force)
    {
        LOGF(log, L"warn: this medium is not the one the system was installed from (%s, recorded %s): added anyway (/force)\n", have, rec);
        return TRUE;
    }
    LOGF(log, L"error: this medium is not the one the system was installed from (its reactos.cab is not the recorded %s); use /force to add from it anyway\n", rec);
    FmSetLastMessage(L"This is not the installation disc this system was installed from (another build). Put the matching disc in the drive. Files of two builds should not be mixed.");
    return FALSE;
}

/* ---- file map ------------------------------------------------------------ */

typedef struct _MAPENTRY
{
    WCHAR *name;    /* name in the cabinet */
    WCHAR *rel;     /* destination relative to the Windows directory */
    BOOL used;
} MAPENTRY;

typedef struct _FILEMAP
{
    MAPENTRY *e;
    int n, cap;
    ULONGLONG bytes;
    PATLIST installed;      /* full paths that were added, for the Start menu entries */
} FILEMAP;

static void MapAdd(FILEMAP *m, LPCWSTR name, LPCWSTR rel)
{
    if (m->n == m->cap)
    {
        int nc = m->cap ? m->cap * 2 : 256;
        MAPENTRY *ne = m->e ? HeapReAlloc(GetProcessHeap(), 0, m->e, nc * sizeof(MAPENTRY)) : HeapAlloc(GetProcessHeap(), 0, nc * sizeof(MAPENTRY));
        if (!ne) return;
        m->e = ne; m->cap = nc;
    }
    m->e[m->n].name = StrDupW(name);
    m->e[m->n].rel = StrDupW(rel);
    m->e[m->n].used = FALSE;
    if (m->e[m->n].name && m->e[m->n].rel) m->n++;
}

static void MapFree(FILEMAP *m)
{
    int i;
    for (i = 0; i < m->n; i++) { LocalFree(m->e[i].name); LocalFree(m->e[i].rel); }
    if (m->e) HeapFree(GetProcessHeap(), 0, m->e);
    PatFree(&m->installed);
    ZeroMemory(m, sizeof(*m));
}

/* The files of the cabinets of the medium that belong to `mine` and to no pattern of `others`. */
static BOOL BuildMap(LPCWSTR medium, const PATLIST *mine, const PATLIST *others, FILEMAP *m, FILE *log)
{
    WCHAR path[MAX_PATH], cab[MAX_PATH], *dot;
    HINF txt, inf;
    INFCONTEXT c, fc, dc;
    UINT err;

    StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\txtsetup.sif", medium);
    txt = SetupOpenInfFileW(path, NULL, INF_STYLE_WIN4, &err);
    if (txt == INVALID_HANDLE_VALUE) { LOGF(log, L"error: cannot read %s (%lu)\n", path, GetLastError()); return FALSE; }
    if (!SetupFindFirstLineW(txt, L"Cabinets", NULL, &c))
    {
        SetupCloseInfFile(txt);
        LOGF(log, L"error: %s lists no cabinet\n", path);
        return FALSE;
    }
    do
    {
        WCHAR dirId[32], dirv[MAX_PATH], src[MAX_PATH], tgt[MAX_PATH], rel[MAX_PATH], sizeText[32];
        LPCWSTR d;

        if (!SetupGetStringFieldW(&c, 1, cab, ARRAYSIZE(cab), NULL)) continue;
        StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\%s", medium, cab);
        dot = wcsrchr(path, L'.');
        if (dot) *dot = L'\0';
        {
            /* the copy of the inf with the sizes (reactos.sizes) when the medium has it, else the plain inf */
            WCHAR p2[MAX_PATH];
            StringCchPrintfW(p2, ARRAYSIZE(p2), L"%s.sizes", path);
            inf = SetupOpenInfFileW(p2, NULL, INF_STYLE_WIN4, &err);
            if (inf == INVALID_HANDLE_VALUE)
            {
                StringCchPrintfW(p2, ARRAYSIZE(p2), L"%s.inf", path);
                inf = SetupOpenInfFileW(p2, NULL, INF_STYLE_WIN4, &err);
            }
        }
        if (inf == INVALID_HANDLE_VALUE) { LOGF(log, L"error: cannot read the file list of %s\n", cab); SetupCloseInfFile(txt); return FALSE; }
        if (SetupFindFirstLineW(inf, L"SourceFiles", NULL, &fc))
        {
            do
            {
                if (!SetupGetStringFieldW(&fc, 0, src, ARRAYSIZE(src), NULL) ||
                    !SetupGetStringFieldW(&fc, 1, dirId, ARRAYSIZE(dirId), NULL)) continue;
                if (!SetupGetStringFieldW(&fc, 2, tgt, ARRAYSIZE(tgt), NULL)) tgt[0] = L'\0';
                if (!SetupFindFirstLineW(inf, L"Directories", dirId, &dc) || !SetupGetStringFieldW(&dc, 1, dirv, ARRAYSIZE(dirv), NULL))
                    continue;
                d = dirv;
                while (*d == L'\\') d++;
                if (*d) StringCchPrintfW(rel, ARRAYSIZE(rel), L"%s\\%s", d, tgt[0] ? tgt : src);
                else StringCchCopyW(rel, ARRAYSIZE(rel), tgt[0] ? tgt : src);

                if (!PatAny(mine, rel) || PatAny(others, rel)) continue;
                if (!RelPathOk(rel))
                {
                    LOGF(log, L"warn: ignored, its destination leaves the system folder: %s\n", rel);
                    continue;
                }
                MapAdd(m, src, rel);
                if (SetupGetStringFieldW(&fc, 3, sizeText, ARRAYSIZE(sizeText), NULL))
                    m->bytes += _wcstoui64(sizeText, NULL, 10);
            } while (SetupFindNextLine(&fc, &fc));
        }
        SetupCloseInfFile(inf);
    } while (SetupFindNextLine(&c, &c));
    SetupCloseInfFile(txt);
    return m->n > 0;
}

typedef struct _EXTRACT
{
    FILEMAP *map;
    WCHAR windir[MAX_PATH];
    FILE *log;
    int done;
    int total;
    DWORD error;
    ULONGLONG doneBytes;
} EXTRACT;

static UINT CALLBACK CabCallback(PVOID ctx, UINT notif, UINT_PTR p1, UINT_PTR p2)
{
    EXTRACT *x = ctx;

    (void)p2;
    switch (notif)
    {
        case SPFILENOTIFY_FILEINCABINET:
        {
            FILE_IN_CABINET_INFO_W *fi = (FILE_IN_CABINET_INFO_W *)p1;
            int i;
            for (i = 0; i < x->map->n; i++)
            {
                MAPENTRY *e = &x->map->e[i];
                WCHAR dir[MAX_PATH];

                if (e->used || _wcsicmp(e->name, fi->NameInCabinet)) continue;
                e->used = TRUE;
                StringCchPrintfW(fi->FullTargetName, MAX_PATH, L"%s\\%s", x->windir, e->rel);
                StringCchCopyW(dir, ARRAYSIZE(dir), fi->FullTargetName);
                PathRemoveFileSpecW(dir);
                SHCreateDirectoryExW(NULL, dir, NULL);
                SetFileAttributesW(fi->FullTargetName, FILE_ATTRIBUTE_NORMAL);   /* an old read-only copy */
                return FILEOP_DOIT;
            }
            return FILEOP_SKIP;
        }
        case SPFILENOTIFY_FILEEXTRACTED:
        {
            FILEPATHS_W *fp = (FILEPATHS_W *)p1;
            if (fp->Win32Error != NO_ERROR)
            {
                x->error = fp->Win32Error;
                LOGF(x->log, L"  error %lu: %s\n", fp->Win32Error, fp->Target);
            }
            else
            {
                x->done++;
                PatAdd(&x->map->installed, fp->Target);
            }
            return NO_ERROR;
        }
        case SPFILENOTIFY_NEEDNEWCABINET:
            return ERROR_FILE_NOT_FOUND;
    }
    return NO_ERROR;
}

/* ---- registry lines ------------------------------------------------------ */

/* Split one INF line into fields: commas outside quotes, quotes removed ("" is a quote). Returns the count. */
static int SplitLine(WCHAR *line, WCHAR **fields, int max)
{
    int n = 0;
    WCHAR *r = line, *w;

    while (*r && n < max)
    {
        while (*r == L' ' || *r == L'\t') r++;
        fields[n++] = w = r;
        if (*r == L'"')
        {
            r++;
            for (;;)
            {
                if (!*r) break;
                if (*r == L'"' && r[1] == L'"') { *w++ = L'"'; r += 2; continue; }
                if (*r == L'"') { r++; break; }
                *w++ = *r++;
            }
            while (*r && *r != L',') r++;
        }
        else
        {
            WCHAR *start = r;
            while (*r && *r != L',') { *w++ = *r++; }
            /* trailing blanks */
            while (w > start && (w[-1] == L' ' || w[-1] == L'\t')) w--;
        }
        if (*r == L',') r++;
        *w = L'\0';
    }
    return n;
}

static HKEY RootOf(LPCWSTR s)
{
    if (!_wcsicmp(s, L"HKLM")) return HKEY_LOCAL_MACHINE;
    if (!_wcsicmp(s, L"HKCR")) return HKEY_CLASSES_ROOT;
    if (!_wcsicmp(s, L"HKCU")) return HKEY_CURRENT_USER;
    return NULL;
}

/* One AddReg line of registry.inf (fields: root, key, value name, flags, data...). */
static BOOL ApplyRegLine(WCHAR **f, int n, FILE *log)
{
    HKEY root = RootOf(f[0]), hk;
    DWORD flags = 0, type = REG_SZ, cb;
    BYTE *data = NULL, tmp[16];
    LONG rc;
    int i;

    if (!root || n < 2) return FALSE;
    if (n > 3 && f[3][0]) flags = wcstoul(f[3], NULL, 0);
    if (flags & 0x4) return TRUE;                    /* delete value: not an add */
    rc = RegCreateKeyExW(root, f[1], 0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL);
    if (rc != ERROR_SUCCESS)
    {
        LOGF(log, L"  warn: cannot create %s\\%s (%ld)\n", f[0], f[1], rc);
        return FALSE;
    }
    if (flags & 0x10) { RegCloseKey(hk); return TRUE; }   /* key only */

    switch (flags & 0xFFFF0001)
    {
        case 0x00000000: type = REG_SZ; break;
        case 0x00010000: type = REG_MULTI_SZ; break;
        case 0x00020000: type = REG_EXPAND_SZ; break;
        case 0x00000001: type = REG_BINARY; break;
        case 0x00010001: type = REG_DWORD; break;
        case 0x00020001: type = REG_NONE; break;
        default: type = flags >> 16; break;
    }
    if (type == REG_DWORD)
    {
        DWORD v = (n > 4) ? wcstoul(f[4], NULL, 0) : 0;
        CopyMemory(tmp, &v, sizeof(v));
        rc = RegSetValueExW(hk, n > 2 ? f[2] : L"", 0, type, tmp, sizeof(v));
    }
    else if (type == REG_BINARY || type == REG_NONE)
    {
        BYTE *buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n + 1);
        for (cb = 0, i = 4; i < n; i++) if (f[i][0]) buf[cb++] = (BYTE)wcstoul(f[i], NULL, 16);
        rc = RegSetValueExW(hk, n > 2 ? f[2] : L"", 0, type, buf, cb);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    else if (type == REG_MULTI_SZ)
    {
        size_t total = 1;
        WCHAR *buf, *w;
        for (i = 4; i < n; i++) total += wcslen(f[i]) + 1;
        buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (total + 1) * sizeof(WCHAR));
        for (w = buf, i = 4; i < n; i++) { StringCchCopyW(w, total, f[i]); w += wcslen(f[i]) + 1; }
        rc = RegSetValueExW(hk, n > 2 ? f[2] : L"", 0, type, (BYTE *)buf, (DWORD)((w - buf + 1) * sizeof(WCHAR)));
        HeapFree(GetProcessHeap(), 0, buf);
    }
    else
    {
        LPCWSTR s = (n > 4) ? f[4] : L"";
        rc = RegSetValueExW(hk, n > 2 ? f[2] : L"", 0, type, (const BYTE *)s, (DWORD)((wcslen(s) + 1) * sizeof(WCHAR)));
    }
    RegCloseKey(hk);
    (void)data;
    if (rc != ERROR_SUCCESS)
        LOGF(log, L"  warn: cannot set a value of %s\\%s (%ld)\n", f[0], f[1], rc);
    return rc == ERROR_SUCCESS;
}

/* The AddReg lines of registry.inf of the medium that a component being added owns (and no left-out one does). */
static int AddRegistryLines(LPCWSTR medium, const PATLIST *mine, const PATLIST *others, FILE *log)
{
    WCHAR path[MAX_PATH];
    HANDLE h;
    DWORD size, got;
    char *raw;
    WCHAR *text, *line, *next;
    int count = 0, wideLen;

    if (!mine->n) return 0;
    StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\registry.inf", medium);
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { LOGF(log, L"warn: no registry.inf on the medium: the registry lines of the component were not added\n"); return 0; }
    size = GetFileSize(h, NULL);
    raw = HeapAlloc(GetProcessHeap(), 0, size + 2);
    if (!raw || !ReadFile(h, raw, size, &got, NULL)) { CloseHandle(h); if (raw) HeapFree(GetProcessHeap(), 0, raw); return 0; }
    CloseHandle(h);
    raw[got] = '\0';
    raw[got + 1] = '\0';
    if (got >= 2 && (BYTE)raw[0] == 0xFF && (BYTE)raw[1] == 0xFE)
    {
        /* registry.inf of the medium is UTF-16 (the build converts the hive files) */
        wideLen = (int)(got / sizeof(WCHAR));
        text = HeapAlloc(GetProcessHeap(), 0, (wideLen + 1) * sizeof(WCHAR));
        if (!text) { HeapFree(GetProcessHeap(), 0, raw); return 0; }
        CopyMemory(text, raw + 2, (wideLen - 1) * sizeof(WCHAR));
        text[wideLen - 1] = L'\0';
    }
    else
    {
        const char *src = raw;
        if (got >= 3 && (BYTE)raw[0] == 0xEF && (BYTE)raw[1] == 0xBB && (BYTE)raw[2] == 0xBF) src += 3;
        wideLen = MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
        text = HeapAlloc(GetProcessHeap(), 0, (wideLen + 1) * sizeof(WCHAR));
        if (!text) { HeapFree(GetProcessHeap(), 0, raw); return 0; }
        MultiByteToWideChar(CP_UTF8, 0, src, -1, text, wideLen);
    }
    HeapFree(GetProcessHeap(), 0, raw);

    for (line = text; *line; line = next)
    {
        WCHAR *e = line, *fields[64], logical[4096];
        size_t used = 0;
        int nf;
        WCHAR keyPath[MAX_PATH + 8], valPath[MAX_PATH * 2 + 8];

        /* one logical line: a trailing backslash continues it */
        logical[0] = L'\0';
        for (;;)
        {
            e = line;
            while (*e && *e != L'\r' && *e != L'\n') e++;
            {
                size_t len = (size_t)(e - line);
                BOOL cont = len && line[len - 1] == L'\\';
                if (cont) len--;
                if (used + len < ARRAYSIZE(logical) - 1) { CopyMemory(logical + used, line, len * sizeof(WCHAR)); used += len; logical[used] = L'\0'; }
                next = e;
                while (*next == L'\r' || *next == L'\n') next++;
                if (!cont || !*next) break;
                line = next;
                while (*line == L' ' || *line == L'\t') line++;
            }
        }
        if (!(logical[0] == L'H' && logical[1] == L'K')) continue;
        nf = SplitLine(logical, fields, ARRAYSIZE(fields));
        if (nf < 2 || !RootOf(fields[0])) continue;
        StringCchPrintfW(keyPath, ARRAYSIZE(keyPath), L"%s\\%s", fields[0], fields[1]);
        StringCchPrintfW(valPath, ARRAYSIZE(valPath), L"%s|%s", keyPath, nf > 2 ? fields[2] : L"");
        if (!(PatAny(mine, keyPath) || (nf > 2 && fields[2][0] && PatAny(mine, valPath)))) continue;
        if (PatAny(others, keyPath) || (nf > 2 && fields[2][0] && PatAny(others, valPath))) continue;
        if (ApplyRegLine(fields, nf, log)) count++;
    }
    HeapFree(GetProcessHeap(), 0, text);
    return count;
}

/* ---- Start menu ----------------------------------------------------------- */

static BOOL MakeLink(LPCWSTR folder, LPCWSTR name, LPCWSTR command, LPCWSTR desc, int icon, LPCWSTR dir, LPCWSTR args)
{
    IShellLinkW *sl = NULL;
    IPersistFile *pf = NULL;
    WCHAR lnk[MAX_PATH], wd[MAX_PATH];
    HRESULT hr;

    StringCchPrintfW(lnk, ARRAYSIZE(lnk), L"%s\\%s.lnk", folder, name);
    if (GetFileAttributesW(lnk) != INVALID_FILE_ATTRIBUTES) return TRUE;
    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&sl);
    if (FAILED(hr)) return FALSE;
    IShellLinkW_SetPath(sl, command);
    if (desc[0]) IShellLinkW_SetDescription(sl, desc);
    if (args[0]) IShellLinkW_SetArguments(sl, args);
    if (dir[0]) StringCchCopyW(wd, ARRAYSIZE(wd), dir);
    else { StringCchCopyW(wd, ARRAYSIZE(wd), command); PathRemoveFileSpecW(wd); }
    IShellLinkW_SetWorkingDirectory(sl, wd);
    if (icon != -1) IShellLinkW_SetIconLocation(sl, command, icon);
    hr = IShellLinkW_QueryInterface(sl, &IID_IPersistFile, (void **)&pf);
    if (SUCCEEDED(hr)) { hr = IPersistFile_Save(pf, lnk, TRUE); IPersistFile_Release(pf); }
    IShellLinkW_Release(sl);
    return SUCCEEDED(hr);
}

/* The Start menu / desktop entries of shortcuts.inf whose program was just copied are made (Default User, as at
 * setup, and the user who runs this); entries that exist are left as they are. */
static int AddShortcuts(const FILEMAP *m, FILE *log)
{
    WCHAR infPath[MAX_PATH], win[MAX_PATH];
    HINF inf;
    INFCONTEXT fc;
    int made = 0;
    HRESULT co;

    if (!m->installed.n || !GetWindowsDirectoryW(win, ARRAYSIZE(win))) return 0;
    StringCchPrintfW(infPath, ARRAYSIZE(infPath), L"%s\\inf\\shortcuts.inf", win);
    inf = SetupOpenInfFileW(infPath, NULL, INF_STYLE_WIN4, NULL);
    if (inf == INVALID_HANDLE_VALUE) return 0;
    co = CoInitialize(NULL);

    if (SetupFindFirstLineW(inf, L"ShortcutFolders", NULL, &fc))
    {
        do
        {
            WCHAR section[MAX_PATH], sub[MAX_PATH];
            INFCONTEXT ic;
            INT csidl;

            if (SetupGetFieldCount(&fc) < 2) continue;
            if (!SetupGetStringFieldW(&fc, 0, section, ARRAYSIZE(section), NULL) || !SetupGetIntField(&fc, 1, &csidl)) continue;
            if (!SetupGetStringFieldW(&fc, 2, sub, ARRAYSIZE(sub), NULL)) sub[0] = L'\0';
            if (!SetupFindFirstLineW(inf, section, NULL, &ic)) continue;
            do
            {
                WCHAR cmd[MAX_PATH], expanded[MAX_PATH], name[MAX_PATH], desc[MAX_PATH], dir[MAX_PATH], args[MAX_PATH], dirx[MAX_PATH];
                WCHAR folder[MAX_PATH];
                DWORD cnt = SetupGetFieldCount(&ic);
                INT icon = -1;
                int k;

                if (cnt < 3) continue;
                if (!SetupGetStringFieldW(&ic, 1, cmd, ARRAYSIZE(cmd), NULL) || !SetupGetStringFieldW(&ic, 2, name, ARRAYSIZE(name), NULL)) continue;
                if (!SetupGetStringFieldW(&ic, 3, desc, ARRAYSIZE(desc), NULL)) desc[0] = L'\0';
                if (cnt < 4 || !SetupGetIntField(&ic, 4, &icon)) icon = -1;
                if (cnt < 5 || !SetupGetStringFieldW(&ic, 5, dir, ARRAYSIZE(dir), NULL)) dir[0] = L'\0';
                if (cnt < 6 || !SetupGetStringFieldW(&ic, 6, args, ARRAYSIZE(args), NULL)) args[0] = L'\0';
                ExpandEnvironmentStringsW(cmd, expanded, ARRAYSIZE(expanded));
                if (!PatAny(&m->installed, expanded)) continue;      /* not one of the programs just added */
                ExpandEnvironmentStringsW(dir, dirx, ARRAYSIZE(dirx));
                for (k = 0; k < 2; k++)
                {
                    HRESULT hr = SHGetFolderPathAndSubDirW(NULL, csidl | CSIDL_FLAG_CREATE, k == 0 ? (HANDLE)-1 : NULL,
                                                           k == 0 ? SHGFP_TYPE_DEFAULT : SHGFP_TYPE_CURRENT, sub, folder);
                    if (SUCCEEDED(hr) && MakeLink(folder, name, expanded, desc, icon, dirx, args))
                    {
                        made++;
                        LOGF(log, L"  Start menu entry: %s\\%s\n", folder, name);
                    }
                }
            } while (SetupFindNextLine(&ic, &ic));
        } while (SetupFindNextLine(&fc, &fc));
    }
    if (SUCCEEDED(co)) CoUninitialize();
    SetupCloseInfFile(inf);
    return made;
}

/* ---- record update ------------------------------------------------------- */

static void SetInstalled(LPCWSTR id, DWORD v)
{
    WCHAR key[160];
    HKEY hk;
    StringCchPrintfW(key, ARRAYSIZE(key), COMPONENTS_KEY L"\\%s", id);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS)
    {
        RegSetValueExW(hk, L"Installed", 0, REG_DWORD, (const BYTE *)&v, sizeof(v));
        RegCloseKey(hk);
    }
}

/* AnyOff of the record, and Panther\components.txt: [Installed] and [Omitted] from the record */
static void RewriteRecord(LPCWSTR added, FILE *log)
{
    HKEY hk;
    DWORD anyOff = 0, v;
    WCHAR win[MAX_PATH], path[MAX_PATH];
    FM_FEATURE *list;
    int n, k;
    char *out, *old = NULL, *p;
    size_t cap = 65536, len = 0;
    HANDLE h;
    DWORD got, size;
    SYSTEMTIME st;
    BOOL inList = FALSE;

    list = HeapAlloc(GetProcessHeap(), 0, 32 * sizeof(FM_FEATURE));
    if (!list) return;
    n = FmOsCompList(list, 32);
    for (k = 0; k < n; k++)
    {
        DWORD inst = 1;
        RecordGet(list[k].Id, &inst, NULL, 0);
        if (!inst) anyOff = 1;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, COMPONENTS_KEY, 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS)
    {
        RegSetValueExW(hk, L"AnyOff", 0, REG_DWORD, (const BYTE *)&anyOff, sizeof(anyOff));
        RegCloseKey(hk);
    }

    if (!GetWindowsDirectoryW(win, ARRAYSIZE(win))) { HeapFree(GetProcessHeap(), 0, list); return; }
    StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\Panther\\components.txt", win);
    out = HeapAlloc(GetProcessHeap(), 0, cap);
    if (!out) { HeapFree(GetProcessHeap(), 0, list); return; }
    h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        size = GetFileSize(h, NULL);
        if (size < 60000 && (old = HeapAlloc(GetProcessHeap(), 0, size + 1)) != NULL)
        {
            if (!ReadFile(h, old, size, &got, NULL)) got = 0;
            old[got] = '\0';
        }
        CloseHandle(h);
    }
    /* the lines of the old file except the lists */
    for (p = old; p && *p; )
    {
        char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) + 1 : strlen(p);
        if (*p == '[')
            inList = !_strnicmp(p, "[Installed]", 11) || !_strnicmp(p, "[Omitted]", 9);
        if (!inList && len + l < cap - 1024) { memcpy(out + len, p, l); len += l; }
        p += l;
    }
    GetSystemTime(&st);
    /* _snprintf returns -1 when the text does not fit: never add that to the length */
#define APPEND(...) do { int w_ = _snprintf(out + len, cap - len, __VA_ARGS__); if (w_ > 0) len += (size_t)w_; } while (0)
    APPEND("\r\n; added later (featmgr): %ws at %04u-%02u-%02uT%02u:%02uZ\r\n", added, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    for (v = 0; v < 2; v++)
    {
        APPEND("\r\n[%s]\r\n", v == 0 ? "Installed" : "Omitted");
        for (k = 0; k < n; k++)
        {
            DWORD inst = 1;
            WCHAR nm[FM_MAX_NAME];
            RecordGet(list[k].Id, &inst, nm, ARRAYSIZE(nm));
            if ((v == 0) != (inst != 0)) continue;
            APPEND("%ws=%ws\r\n", list[k].Id, nm[0] ? nm : list[k].Id);
        }
    }
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        WriteFile(h, out, (DWORD)len, &got, NULL);
        CloseHandle(h);
    }
    else
        LOGF(log, L"warn: cannot update %s\n", path);
    if (old) HeapFree(GetProcessHeap(), 0, old);
    HeapFree(GetProcessHeap(), 0, out);
    HeapFree(GetProcessHeap(), 0, list);
}

/* ---- adding -------------------------------------------------------------- */

/* the components that are not installed and that `id` needs, id last */
static BOOL CollectNeeds(HINF inf, LPCWSTR id, WCHAR order[][32], int *n, int depth, FILE *log)
{
    PATLIST deps = {0}, arch = {0};
    DWORD installed = 1;
    int i;

    for (i = 0; i < *n; i++)
        if (!_wcsicmp(order[i], id)) return TRUE;
    if (depth > 8) return FALSE;
    if (!RecordGet(id, &installed, NULL, 0))
    {
        LOGF(log, L"error: component '%s' is not part of this system's component list\n", id);
        return FALSE;
    }
    if (installed) return TRUE;
    ReadFields(inf, id, L"Arch", &arch);
    if (arch.n && _wcsicmp(arch.p[0], L"any") && _wcsicmp(arch.p[0], MEDIUM_ARCH_DIR))
    {
        LOGF(log, L"error: '%s' does not exist in this edition\n", id);
        PatFree(&arch);
        return FALSE;
    }
    PatFree(&arch);
    ReadFields(inf, id, L"Depends", &deps);
    for (i = 0; i < deps.n; i++)
    {
        if (!CollectNeeds(inf, deps.p[i], order, n, depth + 1, log)) { PatFree(&deps); return FALSE; }
    }
    PatFree(&deps);
    if (*n < 16)
        StringCchCopyW(order[(*n)++], 32, id);
    return TRUE;
}

HRESULT FmOsCompEnable(LPCWSTR id, FILE *log)
{
    WCHAR medium[MAX_PATH], path[MAX_PATH], cab[MAX_PATH], win[MAX_PATH], order[16][32];
    HINF cinf, txt;
    PATLIST mine = {0}, others = {0}, myReg = {0}, otherReg = {0};
    FILEMAP map;
    EXTRACT x;
    INFCONTEXT c;
    int n = 0, i, regLines, links;
    DWORD installed = 1;
    UINT err;
    HRESULT hr = S_OK;
    ULARGE_INTEGER avail, total, freeAll;

    ZeroMemory(&map, sizeof(map));
    if (!IdOk(id) || !RecordGet(id, &installed, NULL, 0))
    {
        LOGF(log, L"error: unknown component '%s'\n", id);
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }
    if (installed)
    {
        LOGF(log, L"component '%s' is already installed\n", id);
        return S_OK;
    }
    if (!FindMedium(medium, ARRAYSIZE(medium), log))
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    if (!CheckMedium(medium, log))
        return HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
    LOGF(log, L"adding component '%s' from %s\n", id, medium);
    FmOpPhase(FM_PHASE_APPLY);
    FmOpStep(L"Reading the component list of the installation medium");

    StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\components.inf", medium);
    cinf = SetupOpenInfFileW(path, NULL, INF_STYLE_WIN4, &err);
    if (cinf == INVALID_HANDLE_VALUE)
    {
        LOGF(log, L"error: cannot read %s (%lu)\n", path, GetLastError());
        FmSetLastMessage(L"The installation medium has no readable component list.");
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }
    if (!CollectNeeds(cinf, id, order, &n, 0, log) || !n)
    {
        SetupCloseInfFile(cinf);
        FmSetLastMessage(L"The component '%s' cannot be added: it needs something this system or this medium does not have.", id);
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }
    if (n > 1)
    {
        LOGF(log, L"it needs:");
        for (i = 0; i < n - 1; i++) LOGF(log, L" %s", order[i]);
        LOGF(log, L" (added first)\n");
    }

    /* patterns of what is added, and of the components that stay left out (their files are not copied) */
    for (i = 0; i < n; i++)
    {
        ReadFields(cinf, order[i], L"Files", &mine);
        ReadFields(cinf, order[i], L"Registry", &myReg);
    }
    {
        HKEY hk;
        DWORD k;
        WCHAR other[64];

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, COMPONENTS_KEY, 0, KEY_READ, &hk) == ERROR_SUCCESS)
        {
            for (k = 0; ; k++)
            {
                DWORD cch = ARRAYSIZE(other), inst = 1;
                BOOL adding = FALSE;
                if (RegEnumKeyExW(hk, k, other, &cch, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
                for (i = 0; i < n; i++) if (!_wcsicmp(order[i], other)) adding = TRUE;
                if (adding || !IdOk(other)) continue;
                RecordGet(other, &inst, NULL, 0);
                if (!inst)
                {
                    ReadFields(cinf, other, L"Files", &others);
                    ReadFields(cinf, other, L"Registry", &otherReg);
                }
            }
            RegCloseKey(hk);
        }
    }

    FmOpStep(L"Looking for the files of the component");
    if (!BuildMap(medium, &mine, &others, &map, log))
    {
        LOGF(log, L"error: the medium has no files for '%s'\n", id);
        FmSetLastMessage(L"The installation medium has no files for the component '%s'. It may be a different version from this system.", id);
        hr = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        goto done;
    }
    GetWindowsDirectoryW(win, ARRAYSIZE(win));
    LOGF(log, L"%d files, %I64u MB\n", map.n, map.bytes >> 20);
    if (GetDiskFreeSpaceExW(win, &avail, &total, &freeAll) && map.bytes && avail.QuadPart < map.bytes + (64ULL << 20))
    {
        LOGF(log, L"error: not enough disk space: %I64u MB free, about %I64u MB needed\n", avail.QuadPart >> 20, (map.bytes + (64ULL << 20)) >> 20);
        FmSetLastMessage(L"Not enough disk space to add the component '%s': about %I64u MB are needed. Nothing was changed.", id, (map.bytes + (64ULL << 20)) >> 20);
        hr = HRESULT_FROM_WIN32(ERROR_DISK_FULL);
        goto done;
    }

    /* the files, out of the cabinets */
    ZeroMemory(&x, sizeof(x));
    x.map = &map; x.log = log; x.total = map.n;
    StringCchCopyW(x.windir, ARRAYSIZE(x.windir), win);
    StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\txtsetup.sif", medium);
    txt = SetupOpenInfFileW(path, NULL, INF_STYLE_WIN4, &err);
    if (txt == INVALID_HANDLE_VALUE) { hr = E_FAIL; goto done; }
    if (SetupFindFirstLineW(txt, L"Cabinets", NULL, &c))
    {
        do
        {
            if (!SetupGetStringFieldW(&c, 1, cab, ARRAYSIZE(cab), NULL)) continue;
            StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\%s", medium, cab);
            FmOpStep(L"Copying files from %s", cab);
            if (!SetupIterateCabinetW(path, 0, CabCallback, &x))
            {
                LOGF(log, L"error: cannot read the cabinet %s (%lu)\n", path, GetLastError());
                x.error = x.error ? x.error : GetLastError();
            }
        } while (SetupFindNextLine(&c, &c));
    }
    SetupCloseInfFile(txt);
    LOGF(log, L"copied %d of %d files\n", x.done, map.n);
    if (x.error || x.done < map.n)
    {
        FmSetLastMessage(L"Not every file of the component '%s' could be copied (%d of %d). The component was not marked as installed.", id, x.done, map.n);
        hr = HRESULT_FROM_WIN32(x.error ? x.error : ERROR_FILE_CORRUPT);
        goto done;
    }

    FmOpStep(L"Registering the component");
    regLines = AddRegistryLines(medium, &myReg, &otherReg, log);
    LOGF(log, L"%d registry lines added\n", regLines);
    links = AddShortcuts(&map, log);
    LOGF(log, L"%d Start menu entries made\n", links);

    for (i = 0; i < n; i++)
        SetInstalled(order[i], 1);
    RewriteRecord(id, log);
    LOGF(log, L"component '%s' installed\n", id);

done:
    MapFree(&map);
    PatFree(&mine);
    PatFree(&others);
    PatFree(&myReg);
    PatFree(&otherReg);
    SetupCloseInfFile(cinf);
    return hr;
}
