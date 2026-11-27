/*
 * Robust File Copy
 *
 * Copyright 2021 Florian Eder (stub)
 * Copyright 2026 Tomas Srnka (implementation)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define WIN32_LEAN_AND_MEAN
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(robocopy);

/* Exit code bits, as documented for the Windows tool. */
#define RC_COPIED    1
#define RC_EXTRA     2
#define RC_MISMATCH  4
#define RC_FAILED    8
#define RC_FATAL     16

/* /COPY and /DCOPY flags */
#define CP_D 0x01
#define CP_A 0x02
#define CP_T 0x04
#define CP_S 0x08
#define CP_O 0x10
#define CP_U 0x20

#define ATTR_COPY_MASK (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | \
                        FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE)

#define MAX_PATH_LEN 32000
#define COPY_BUFFER_SIZE (256 * 1024)

typedef struct
{
    WCHAR **v;
    int count, cap;
} strlist;

static struct
{
    BOOL subdirs, empty, move_files, move_dirs, purge, list_only;
    BOOL nfl, ndl, njh, njs, np, nc, ns, fp, tee, is, it, xo, xn, xc, nocopy, fft;
    BOOL xjd, xjf;
    DWORD copy, dcopy;
    LONG retries;
    DWORD wait;
    int level;
    WCHAR *log;
    BOOL log_append;
    strlist patterns, xd, xf;
} opt = { .copy = CP_D | CP_A | CP_T, .dcopy = CP_D | CP_A, .retries = 1000000, .wait = 30 };

typedef struct
{
    ULONGLONG copied, skipped, mismatch, failed, extras;
} counters;

static counters dirs, files, bytes;
static DWORD exit_bits;

static HANDLE out_handle, log_handle;
static BOOL out_console;
static UINT out_cp;
static WCHAR *root_dst;
static BYTE *copy_buffer;

typedef struct
{
    WIN32_FIND_DATAW fd;
} entry;

typedef struct
{
    entry *e;
    int count;
} dirlist;

/* ---------------------------------------------------------------- output */

static void emit(const WCHAR *s, int len)
{
    char *mb;
    int n;
    DWORD written;

    if (!len) return;
    if (!opt.log || opt.tee)
    {
        if (out_console) WriteConsoleW(out_handle, s, len, &written, NULL);
        else
        {
            n = WideCharToMultiByte(out_cp, 0, s, len, NULL, 0, NULL, NULL);
            if ((mb = HeapAlloc(GetProcessHeap(), 0, n + 1)))
            {
                WideCharToMultiByte(out_cp, 0, s, len, mb, n, NULL, NULL);
                WriteFile(out_handle, mb, n, &written, NULL);
                HeapFree(GetProcessHeap(), 0, mb);
            }
        }
    }
    if (log_handle != INVALID_HANDLE_VALUE)
    {
        n = WideCharToMultiByte(out_cp, 0, s, len, NULL, 0, NULL, NULL);
        if ((mb = HeapAlloc(GetProcessHeap(), 0, n + 1)))
        {
            WideCharToMultiByte(out_cp, 0, s, len, mb, n, NULL, NULL);
            WriteFile(log_handle, mb, n, &written, NULL);
            HeapFree(GetProcessHeap(), 0, mb);
        }
    }
}

static void out_printf(const WCHAR *fmt, ...)
{
    static WCHAR buf[MAX_PATH_LEN * 2 + 4096];
    va_list args;
    int len;

    va_start(args, fmt);
    len = _vsnwprintf(buf, ARRAY_SIZE(buf) - 1, fmt, args);
    va_end(args);
    if (len < 0) len = ARRAY_SIZE(buf) - 1;
    emit(buf, len);
}

static void out_error(DWORD err)
{
    WCHAR *msg = NULL;

    if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, 0, (WCHAR *)&msg, 0, NULL) && msg)
    {
        size_t len = wcslen(msg);
        while (len && (msg[len - 1] == '\r' || msg[len - 1] == '\n' || msg[len - 1] == ' ')) msg[--len] = 0;
        out_printf(L"%ls\n", msg);
        LocalFree(msg);
    }
    else out_printf(L"Unknown error %lu\n", err);
}

static void out_now(const WCHAR *label)
{
    WCHAR date[128], time[64];

    GetDateFormatW(LOCALE_USER_DEFAULT, DATE_LONGDATE, NULL, NULL, date, ARRAY_SIZE(date));
    GetTimeFormatW(LOCALE_USER_DEFAULT, 0, NULL, NULL, time, ARRAY_SIZE(time));
    out_printf(L"%ls : %ls %ls\n", label, date, time);
}

static const WCHAR rule[] =
    L"-------------------------------------------------------------------------------\n";

/* ----------------------------------------------------------------- utils */

static void *xalloc(SIZE_T size)
{
    void *p = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size ? size : 1);
    if (!p)
    {
        out_printf(L"ERROR : Insufficient memory.\n");
        ExitProcess(RC_FATAL);
    }
    return p;
}

static WCHAR *xstrdup(const WCHAR *s)
{
    WCHAR *r = xalloc((wcslen(s) + 1) * sizeof(WCHAR));
    wcscpy(r, s);
    return r;
}

static void list_add(strlist *l, WCHAR *s)
{
    if (l->count == l->cap)
    {
        int cap = l->cap ? l->cap * 2 : 8;
        WCHAR **v = xalloc(cap * sizeof(*v));
        if (l->count) memcpy(v, l->v, l->count * sizeof(*v));
        if (l->v) HeapFree(GetProcessHeap(), 0, l->v);
        l->v = v;
        l->cap = cap;
    }
    l->v[l->count++] = s;
}

static WCHAR *path_join(const WCHAR *dir, const WCHAR *name)
{
    size_t dl = wcslen(dir);
    WCHAR *r = xalloc((dl + wcslen(name) + 2) * sizeof(WCHAR));

    wcscpy(r, dir);
    if (dl && dir[dl - 1] != '\\') r[dl++] = '\\';
    wcscpy(r + dl, name);
    return r;
}

/* Paths are kept in the \\?\ form so that deep trees work; strip it for display. */
static const WCHAR *disp(const WCHAR *p)
{
    static WCHAR *ring[4];
    static int slot;
    WCHAR *r;

    if (!wcsncmp(p, L"\\\\?\\UNC\\", 8))
    {
        slot = (slot + 1) % ARRAY_SIZE(ring);
        if (ring[slot]) HeapFree(GetProcessHeap(), 0, ring[slot]);
        r = ring[slot] = xalloc((wcslen(p) + 2) * sizeof(WCHAR));
        r[0] = r[1] = '\\';
        wcscpy(r + 2, p + 8);
        return r;
    }
    if (!wcsncmp(p, L"\\\\?\\", 4)) return p + 4;
    return p;
}

/* Directory name for display: always with a trailing backslash. */
static const WCHAR *disp_dir(const WCHAR *p)
{
    static WCHAR *buf;
    const WCHAR *d = disp(p);
    size_t len = wcslen(d);

    if (buf) HeapFree(GetProcessHeap(), 0, buf);
    buf = xalloc((len + 2) * sizeof(WCHAR));
    wcscpy(buf, d);
    if (len && buf[len - 1] != '\\') buf[len] = '\\';
    return buf;
}

static WCHAR *make_root(const WCHAR *arg)
{
    DWORD n = GetFullPathNameW(arg, 0, NULL, NULL);
    WCHAR *full, *r;
    size_t len;

    if (!n) return NULL;
    full = xalloc((n + 1) * sizeof(WCHAR));
    if (!GetFullPathNameW(arg, n + 1, full, NULL))
    {
        HeapFree(GetProcessHeap(), 0, full);
        return NULL;
    }
    r = xalloc((wcslen(full) + 16) * sizeof(WCHAR));
    if (!wcsncmp(full, L"\\\\?\\", 4)) wcscpy(r, full);
    else if (!wcsncmp(full, L"\\\\", 2))
    {
        wcscpy(r, L"\\\\?\\UNC\\");
        wcscat(r, full + 2);
    }
    else
    {
        wcscpy(r, L"\\\\?\\");
        wcscat(r, full);
    }
    HeapFree(GetProcessHeap(), 0, full);
    len = wcslen(r);
    while (len > 7 && r[len - 1] == '\\') r[--len] = 0;
    return r;
}

static BOOL wild_match(const WCHAR *pat, const WCHAR *s)
{
    while (*pat)
    {
        if (*pat == '*')
        {
            while (*pat == '*') pat++;
            if (!*pat) return TRUE;
            for (; *s; s++) if (wild_match(pat, s)) return TRUE;
            return wild_match(pat, s);
        }
        if (!*s) return FALSE;
        if (*pat != '?' && towupper(*pat) != towupper(*s)) return FALSE;
        pat++;
        s++;
    }
    return !*s;
}

static BOOL name_matches(const WCHAR *pat, const WCHAR *name)
{
    if (!wcscmp(pat, L"*.*")) return TRUE;
    return wild_match(pat, name);
}

static BOOL list_matches(const strlist *l, const WCHAR *name, const WCHAR *fullpath)
{
    int i;
    for (i = 0; i < l->count; i++)
        if (wild_match(l->v[i], name) || wild_match(l->v[i], disp(fullpath))) return TRUE;
    return FALSE;
}

static BOOL file_selected(const WCHAR *name)
{
    int i;
    if (!opt.patterns.count) return TRUE;
    for (i = 0; i < opt.patterns.count; i++)
        if (name_matches(opt.patterns.v[i], name)) return TRUE;
    return FALSE;
}

static ULONGLONG fsize(const WIN32_FIND_DATAW *fd)
{
    return ((ULONGLONG)fd->nFileSizeHigh << 32) | fd->nFileSizeLow;
}

static int cmp_time(const FILETIME *a, const FILETIME *b)
{
    LONGLONG x = ((LONGLONG)a->dwHighDateTime << 32) | a->dwLowDateTime;
    LONGLONG y = ((LONGLONG)b->dwHighDateTime << 32) | b->dwLowDateTime;
    LONGLONG tol = opt.fft ? 20000000 : 0;

    if (x - y > tol) return 1;
    if (y - x > tol) return -1;
    return 0;
}

static int cmp_entry(const void *a, const void *b)
{
    return _wcsicmp(((const entry *)a)->fd.cFileName, ((const entry *)b)->fd.cFileName);
}

static void free_list(dirlist *l)
{
    if (l->e) HeapFree(GetProcessHeap(), 0, l->e);
    l->e = NULL;
    l->count = 0;
}

/* Returns 0 or a Win32 error. */
static DWORD read_dir(const WCHAR *dir, dirlist *l)
{
    WCHAR *pat = path_join(dir, L"*");
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int cap = 64;

    l->e = xalloc(cap * sizeof(entry));
    l->count = 0;
    h = FindFirstFileW(pat, &fd);
    HeapFree(GetProcessHeap(), 0, pat);
    if (h == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND) return 0;
        free_list(l);
        return err;
    }
    do
    {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        if (l->count == cap)
        {
            entry *n = xalloc(cap * 2 * sizeof(entry));
            memcpy(n, l->e, l->count * sizeof(entry));
            HeapFree(GetProcessHeap(), 0, l->e);
            l->e = n;
            cap *= 2;
        }
        l->e[l->count++].fd = fd;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (l->count > 1) qsort(l->e, l->count, sizeof(entry), cmp_entry);
    return 0;
}

static entry *find_entry(const dirlist *l, const WCHAR *name)
{
    int lo = 0, hi = l->count - 1;

    while (lo <= hi)
    {
        int mid = (lo + hi) / 2;
        int c = _wcsicmp(name, l->e[mid].fd.cFileName);
        if (!c) return &l->e[mid];
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return NULL;
}

static DWORD mkdir_p(const WCHAR *path)
{
    DWORD err;
    WCHAR *parent, *sep;

    if (CreateDirectoryW(path, NULL)) return 0;
    err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS)
    {
        DWORD a = GetFileAttributesW(path);
        return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) ? 0 : ERROR_ALREADY_EXISTS;
    }
    if (err != ERROR_PATH_NOT_FOUND) return err;
    parent = xstrdup(path);
    sep = wcsrchr(parent, '\\');
    if (!sep || sep - parent < 7)
    {
        HeapFree(GetProcessHeap(), 0, parent);
        return err;
    }
    *sep = 0;
    err = mkdir_p(parent);
    HeapFree(GetProcessHeap(), 0, parent);
    if (err) return err;
    if (CreateDirectoryW(path, NULL)) return 0;
    return GetLastError();
}

static BOOL delete_file_force(const WCHAR *path)
{
    if (DeleteFileW(path)) return TRUE;
    if (GetLastError() == ERROR_ACCESS_DENIED)
    {
        SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
        if (DeleteFileW(path)) return TRUE;
    }
    return FALSE;
}

static BOOL remove_dir_force(const WCHAR *path)
{
    if (RemoveDirectoryW(path)) return TRUE;
    if (GetLastError() == ERROR_ACCESS_DENIED)
    {
        SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
        if (RemoveDirectoryW(path)) return TRUE;
    }
    return FALSE;
}

static void set_dir_info(const WCHAR *dst, const WIN32_FILE_ATTRIBUTE_DATA *src)
{
    HANDLE h;

    /* the Windows tool carries directory timestamps even without T in /DCOPY */
    h = CreateFileW(dst, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        SetFileTime(h, &src->ftCreationTime, &src->ftLastAccessTime, &src->ftLastWriteTime);
        CloseHandle(h);
    }
    if (opt.dcopy & CP_A)
    {
        DWORD a = src->dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_READONLY);
        if (a) SetFileAttributesW(dst, a | FILE_ATTRIBUTE_DIRECTORY);
    }
}

/* ------------------------------------------------------------- file copy */

/*
 * Enable a privilege the caller holds (nothing happens if it does not). Windows' robocopy copies the
 * owner of a file to one its caller may not otherwise assign (a file owned by SYSTEM, /COPY:O) also
 * when the caller's SeRestorePrivilege is disabled, as it is in an elevated administrator's token by
 * default (Windows Server 2022, measured): it enables the privilege itself.
 */
static void enable_privilege(const WCHAR *name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) return;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(token);
}

static DWORD copy_security(const WCHAR *src, const WCHAR *dst)
{
    SECURITY_INFORMATION si = 0;
    SECURITY_DESCRIPTOR *sd;
    DWORD len = 0, err = 0;

    if (opt.copy & CP_S) si |= DACL_SECURITY_INFORMATION;
    if (opt.copy & CP_O) si |= OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    if (!si) return 0;
    GetFileSecurityW(src, si, NULL, 0, &len);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return GetLastError();
    sd = xalloc(len);
    if (!GetFileSecurityW(src, si, sd, len, &len) || !SetFileSecurityW(dst, si, sd)) err = GetLastError();
    HeapFree(GetProcessHeap(), 0, sd);
    return err;
}

static DWORD copy_one(const WCHAR *src, const WCHAR *dst, const WIN32_FIND_DATAW *sfd, BOOL dst_exists)
{
    HANDLE hs, hd;
    DWORD n, w, err = 0;
    DWORD da = GetFileAttributesW(dst);

    hs = CreateFileW(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                     FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hs == INVALID_HANDLE_VALUE) return GetLastError();
    if (dst_exists && da != INVALID_FILE_ATTRIBUTES &&
        (da & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)))
        SetFileAttributesW(dst, FILE_ATTRIBUTE_NORMAL);
    hd = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hd == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        CloseHandle(hs);
        return err;
    }
    if (!copy_buffer) copy_buffer = xalloc(COPY_BUFFER_SIZE);
    for (;;)
    {
        if (!ReadFile(hs, copy_buffer, COPY_BUFFER_SIZE, &n, NULL)) { err = GetLastError(); break; }
        if (!n) break;
        if (!WriteFile(hd, copy_buffer, n, &w, NULL) || w != n)
        {
            err = GetLastError();
            if (!err) err = ERROR_DISK_FULL;
            break;
        }
    }
    /* the Windows tool carries the timestamps with the data, whatever /COPY says */
    if (!err && !SetFileTime(hd, &sfd->ftCreationTime, &sfd->ftLastAccessTime, &sfd->ftLastWriteTime))
        err = GetLastError();
    CloseHandle(hs);
    CloseHandle(hd);
    if (!err && (opt.copy & (CP_S | CP_O))) err = copy_security(src, dst);
    if (!err)
    {
        /* without A the archive bit is set on top of the source attributes */
        DWORD a = sfd->dwFileAttributes & ATTR_COPY_MASK;
        if (!(opt.copy & CP_A)) a |= FILE_ATTRIBUTE_ARCHIVE;
        if (!a) a = FILE_ATTRIBUTE_NORMAL;
        if (!SetFileAttributesW(dst, a)) err = GetLastError();
    }
    if (err)
    {
        SetFileAttributesW(dst, FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(dst);
    }
    return err;
}

static BOOL copy_retry(const WCHAR *src, const WCHAR *dst, const WIN32_FIND_DATAW *sfd, BOOL dst_exists)
{
    LONG tries = 0;
    DWORD err;

    for (;;)
    {
        err = copy_one(src, dst, sfd, dst_exists);
        if (!err) return TRUE;
        out_printf(L"ERROR %lu (0x%08lX) Copying File %ls\n", err, err, disp(src));
        out_error(err);
        if (tries++ >= opt.retries)
        {
            out_printf(L"ERROR: RETRY LIMIT EXCEEDED.\n\n");
            return FALSE;
        }
        out_printf(L"Waiting %lu seconds... Retrying...\n", opt.wait);
        Sleep(opt.wait * 1000);
    }
}

/* ------------------------------------------------------------- the walk */

typedef struct dctx
{
    const WCHAR *src, *dst;
    struct dctx *parent;
    BOOL existed, made;
    BOOL via_link; /* reached through a reparse point in the source: never delete from it */
    DWORD err;
} dctx;

static BOOL ensure_dir(dctx *c)
{
    if (c->made) return TRUE;
    if (c->parent && !ensure_dir(c->parent)) return FALSE;
    if (!opt.list_only)
    {
        c->err = mkdir_p(c->dst);
        if (c->err)
        {
            out_printf(L"ERROR %lu (0x%08lX) Creating Destination Directory %ls\n", c->err, c->err, disp_dir(c->dst));
            out_error(c->err);
            return FALSE;
        }
    }
    if (!c->existed) dirs.copied++;
    return c->made = TRUE;
}

static void file_line(const WCHAR *cls, const WIN32_FIND_DATAW *fd, const WCHAR *path, BOOL copying)
{
    if (opt.nfl) return;
    out_printf(L"\t");
    if (!opt.nc) out_printf(L"%-12ls", cls);
    out_printf(L"\t");
    if (!opt.ns) out_printf(L"%10I64u", fsize(fd));
    /* without the directory lines the names carry their full path, as in the Windows tool */
    out_printf(L"\t%ls%ls\n", (opt.fp || opt.ndl) ? disp(path) : fd->cFileName,
               (copying && !opt.np) ? L"100%  " : L"");
}

static void extra_item(const WCHAR *path, const WIN32_FIND_DATAW *fd, BOOL recurse_dirs);

static BOOL delete_tree(const WCHAR *path)
{
    dirlist l = {0};
    BOOL ok = TRUE;
    DWORD ra = GetFileAttributesW(path);
    int i;

    /* A junction or symlink directory is removed as a link: never walk its target.
     * Safety over parity for a destructive operation, whatever the Windows tool does. */
    if (ra != INVALID_FILE_ATTRIBUTES && (ra & FILE_ATTRIBUTE_REPARSE_POINT))
        return remove_dir_force(path);
    if (read_dir(path, &l)) return FALSE;
    for (i = 0; i < l.count; i++)
    {
        WCHAR *p = path_join(path, l.e[i].fd.cFileName);
        DWORD a = l.e[i].fd.dwFileAttributes;

        if ((a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT))
            ok &= delete_tree(p);
        else if (a & FILE_ATTRIBUTE_DIRECTORY) ok &= remove_dir_force(p);
        else ok &= delete_file_force(p);
        HeapFree(GetProcessHeap(), 0, p);
    }
    free_list(&l);
    return remove_dir_force(path) && ok;
}

/* An item that exists only in the destination. */
static void extra_item(const WCHAR *path, const WIN32_FIND_DATAW *fd, BOOL recurse_dirs)
{
    if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        dirlist l = {0};
        int i;

        dirs.extras++;
        if (!opt.ndl) out_printf(L"\t*EXTRA Dir  %10ls\t%ls\n", L"", disp_dir(path));
        if (recurse_dirs && !(fd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && !read_dir(path, &l))
        {
            for (i = 0; i < l.count; i++)
            {
                WCHAR *p = path_join(path, l.e[i].fd.cFileName);
                extra_item(p, &l.e[i].fd, TRUE);
                HeapFree(GetProcessHeap(), 0, p);
            }
            free_list(&l);
        }
        /* delete_tree() removes a reparse point as a link without traversing it */
        if (opt.purge && !opt.list_only && !delete_tree(path))
        {
            dirs.failed++;
            out_printf(L"ERROR : Deleting Extra Directory %ls\n", disp_dir(path));
        }
    }
    else
    {
        files.extras++;
        bytes.extras += fsize(fd);
        file_line(L"*EXTRA File", fd, path, FALSE);
        if (opt.purge && !opt.list_only && !delete_file_force(path))
        {
            DWORD err = GetLastError();
            files.failed++;
            out_printf(L"ERROR %lu (0x%08lX) Deleting Extra File %ls\n", err, err, disp(path));
            out_error(err);
        }
    }
}

static BOOL is_within(const WCHAR *path, const WCHAR *root)
{
    size_t n = wcslen(root);
    return !_wcsnicmp(path, root, n) && (!path[n] || path[n] == '\\');
}

static void process_dir(dctx *c, int depth)
{
    dirlist sl = {0}, dl = {0};
    DWORD err, dattr;
    int i, nsel = 0;
    BOOL recurse = opt.subdirs || opt.empty;
    BOOL dst_there;
    WIN32_FILE_ATTRIBUTE_DATA sdata;

    err = read_dir(c->src, &sl);
    if (err)
    {
        out_printf(L"ERROR %lu (0x%08lX) Scanning Source Directory %ls\n", err, err, disp_dir(c->src));
        out_error(err);
        dirs.failed++;
        return;
    }
    dattr = GetFileAttributesW(c->dst);
    dst_there = dattr != INVALID_FILE_ATTRIBUTES && (dattr & FILE_ATTRIBUTE_DIRECTORY);
    if (dst_there && read_dir(c->dst, &dl)) dst_there = FALSE;
    if (!GetFileAttributesExW(c->src, GetFileExInfoStandard, &sdata)) memset(&sdata, 0, sizeof(sdata));

    for (i = 0; i < sl.count; i++)
    {
        const WIN32_FIND_DATAW *fd = &sl.e[i].fd;
        if (!(fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && file_selected(fd->cFileName)) nsel++;
    }
    if (!opt.ndl && (opt.empty || nsel))
    {
        if (!dst_there) out_printf(L"\t  New Dir  %10d\t%ls\n", nsel, disp_dir(c->src));
        else out_printf(L"\t%12ls%10d\t%ls\n", L"", nsel, disp_dir(c->src));
    }
    if (opt.empty) ensure_dir(c);

    /* files */
    for (i = 0; i < sl.count; i++)
    {
        const WIN32_FIND_DATAW *fd = &sl.e[i].fd;
        WCHAR *sp, *dp;
        entry *de;
        const WCHAR *cls = NULL;
        BOOL exists = FALSE, copy = FALSE;
        int tc;

        if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (!file_selected(fd->cFileName)) continue;
        sp = path_join(c->src, fd->cFileName);
        dp = path_join(c->dst, fd->cFileName);
        if (list_matches(&opt.xf, fd->cFileName, sp) ||
            ((fd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && opt.xjf))
        {
            files.skipped++;
            bytes.skipped += fsize(fd);
            goto next;
        }
        de = dl.count ? find_entry(&dl, fd->cFileName) : NULL;
        if (de && (de->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            files.mismatch++;
            bytes.mismatch += fsize(fd);
            file_line(L"!! mismatch", fd, sp, FALSE);
            goto next;
        }
        if (!de)
        {
            cls = L"New File";
            copy = TRUE;
        }
        else
        {
            exists = TRUE;
            tc = cmp_time(&fd->ftLastWriteTime, &de->fd.ftLastWriteTime);
            if (!tc && fsize(fd) == fsize(&de->fd))
            {
                BOOL tweaked = ((fd->dwFileAttributes ^ de->fd.dwFileAttributes) & ATTR_COPY_MASK &
                                ~FILE_ATTRIBUTE_ARCHIVE) != 0;
                cls = tweaked ? L"tweaked" : L"same";
                copy = tweaked ? opt.it : opt.is;
            }
            else if (tc > 0) { cls = L"Newer"; copy = !opt.xn; }
            else if (tc < 0) { cls = L"Older"; copy = !opt.xo; }
            else { cls = L"Changed"; copy = !opt.xc; }
        }
        if (!copy || opt.nocopy)
        {
            files.skipped++;
            bytes.skipped += fsize(fd);
            file_line(cls, fd, sp, FALSE);
            goto next;
        }
        file_line(cls, fd, sp, !opt.list_only);
        if (opt.list_only)
        {
            files.copied++;
            bytes.copied += fsize(fd);
            goto next;
        }
        if (!ensure_dir(c) || !copy_retry(sp, dp, fd, exists))
        {
            files.failed++;
            bytes.failed += fsize(fd);
            goto next;
        }
        files.copied++;
        bytes.copied += fsize(fd);
        if (opt.move_files && !c->via_link && !delete_file_force(sp))
        {
            DWORD e = GetLastError();
            files.failed++;
            out_printf(L"ERROR %lu (0x%08lX) Deleting Source File %ls\n", e, e, disp(sp));
            out_error(e);
        }
    next:
        HeapFree(GetProcessHeap(), 0, sp);
        HeapFree(GetProcessHeap(), 0, dp);
    }

    /* subdirectories */
    if (recurse && (opt.level <= 0 || depth + 1 < opt.level))
    {
        for (i = 0; i < sl.count; i++)
        {
            const WIN32_FIND_DATAW *fd = &sl.e[i].fd;
            WCHAR *sp, *dp;
            entry *de;
            dctx sub;

            if (!(fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            sp = path_join(c->src, fd->cFileName);
            dp = path_join(c->dst, fd->cFileName);
            de = dl.count ? find_entry(&dl, fd->cFileName) : NULL;
            if (list_matches(&opt.xd, fd->cFileName, sp) ||
                ((fd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && opt.xjd) ||
                (root_dst && !_wcsicmp(sp, root_dst)))
            {
                dirs.skipped++;
            }
            else if (de && !(de->fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                dirs.mismatch++;
                if (!opt.ndl) out_printf(L"\t!! mismatch %ls\n", disp_dir(sp));
            }
            else if (wcslen(sp) > MAX_PATH_LEN || wcslen(dp) > MAX_PATH_LEN)
            {
                dirs.failed++;
                out_printf(L"ERROR : Path too long %ls\n", disp(sp));
            }
            else
            {
                sub.src = sp;
                sub.dst = dp;
                sub.parent = c;
                sub.existed = sub.made = (de != NULL);
                sub.err = 0;
                sub.via_link = c->via_link || (fd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                process_dir(&sub, depth + 1);
                /* /MOVE: remove an emptied directory, or a source link itself; files and
                 * directories reached through a link are copied but never deleted from its target */
                if (opt.move_dirs && !opt.list_only &&
                    (!sub.via_link || (fd->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)))
                    remove_dir_force(sp);
            }
            HeapFree(GetProcessHeap(), 0, sp);
            HeapFree(GetProcessHeap(), 0, dp);
        }
    }

    /* items that exist only in the destination */
    for (i = 0; i < dl.count; i++)
    {
        const WIN32_FIND_DATAW *fd = &dl.e[i].fd;
        WCHAR *dp;

        if (find_entry(&sl, fd->cFileName)) continue;
        dp = path_join(c->dst, fd->cFileName);
        if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (recurse && !list_matches(&opt.xd, fd->cFileName, dp)) extra_item(dp, fd, TRUE);
        }
        else if (file_selected(fd->cFileName) && !list_matches(&opt.xf, fd->cFileName, dp))
            extra_item(dp, fd, TRUE);
        HeapFree(GetProcessHeap(), 0, dp);
    }

    if (c->made && !opt.list_only && sdata.dwFileAttributes)
        set_dir_info(c->dst, &sdata);
    if (c->existed || !c->made) dirs.skipped++;
    free_list(&sl);
    free_list(&dl);
}

/* --------------------------------------------------------------- options */

static void usage(void)
{
    out_printf(
        L"Usage :: ROBOCOPY source destination [file [file]...] [options]\n\n"
        L"            source :: Source Directory (drive:\\path or \\\\server\\share\\path).\n"
        L"       destination :: Destination Dir  (drive:\\path or \\\\server\\share\\path).\n"
        L"              file :: File(s) to copy  (names/wildcards: default is \"*.*\").\n\n"
        L"::\n:: Copy options :\n::\n"
        L"                /S :: copy Subdirectories, but not empty ones.\n"
        L"                /E :: copy subdirectories, including Empty ones.\n"
        L"          /LEV:n :: only copy the top n LEVels of the source directory tree.\n"
        L"          /COPY:copyflag[s] :: what to COPY for files (default is /COPY:DAT).\n"
        L"                (copyflags : D=Data, A=Attributes, T=Timestamps, S=Security=NTFS ACLs,\n"
        L"                 O=Owner info, U=aUditing info (ignored)).\n"
        L"        /DCOPY:copyflag[s] :: what to COPY for directories (default is /DCOPY:DA).\n"
        L"                (copyflags : D=Data, A=Attributes, T=Timestamps).\n"
        L"          /COPYALL :: COPY ALL file info (equivalent to /COPY:DATSOU).\n"
        L"          /NOCOPY :: COPY NO file info (useful with /PURGE).\n"
        L"           /SEC :: copy files with SECurity (equivalent to /COPY:DATS).\n"
        L"          /PURGE :: delete dest files/dirs that no longer exist in source.\n"
        L"             /MIR :: MIRror a directory tree (equivalent to /E plus /PURGE).\n"
        L"            /MOV :: MOVe files (delete from source after copying).\n"
        L"           /MOVE :: MOVE files AND dirs (delete from source after copying).\n\n"
        L"::\n:: File Selection Options :\n::\n"
        L"                /XF file [file]... :: eXclude Files matching given names/paths/wildcards.\n"
        L"                /XD dir [dir]... :: eXclude Directories matching given names/paths.\n"
        L"                /XC /XN /XO :: eXclude Changed / Newer / Older files.\n"
        L"                /IS /IT :: Include Same / Tweaked files.\n"
        L"                /XJ /XJD /XJF :: eXclude Junction points (all / for directories / for files).\n"
        L"                /FFT :: assume FAT File Times (2-second granularity).\n\n"
        L"::\n:: Retry Options :\n::\n"
        L"               /R:n :: number of Retries on failed copies: default 1 million.\n"
        L"               /W:n :: Wait time between retries: default is 30 seconds.\n\n"
        L"::\n:: Logging Options :\n::\n"
        L"                 /L :: List only - don't copy, timestamp or delete any files.\n"
        L"               /NFL :: No File List - don't log file names.\n"
        L"               /NDL :: No Directory List - don't log directory names.\n"
        L"               /NJH :: No Job Header.\n"
        L"               /NJS :: No Job Summary.\n"
        L"                /NP :: No Progress - don't display percentage copied.\n"
        L"                /NC :: No Class - don't log file classes.\n"
        L"                /NS :: No Size - don't log file sizes.\n"
        L"                /FP :: include Full Pathname of files in the output.\n"
        L"         /LOG:file :: output status to LOG file (overwrite existing log).\n"
        L"        /LOG+:file :: output status to LOG file (append to existing log).\n"
        L"              /TEE :: output to console window, as well as the log file.\n\n"
        L"Accepted and ignored: /Z /B /ZB /J /MT[:n] /IPG:n /NOOFFLOAD /V /TS /BYTES /ETA /X /DST.\n");
}

static BOOL parse_flags(const WCHAR *s, DWORD *flags, BOOL allow_so)
{
    DWORD f = 0;

    for (; *s; s++)
    {
        switch (towupper(*s))
        {
        case 'D': f |= CP_D; break;
        case 'A': f |= CP_A; break;
        case 'T': f |= CP_T; break;
        case 'S': if (!allow_so) return FALSE; f |= CP_S; break;
        case 'O': if (!allow_so) return FALSE; f |= CP_O; break;
        case 'U': if (!allow_so) return FALSE; f |= CP_U; break;
        case 'E': case 'X': if (allow_so) return FALSE; break;
        default: return FALSE;
        }
    }
    *flags = f;
    return TRUE;
}

static BOOL parse_num(const WCHAR *s, LONG max, LONG *out)
{
    WCHAR *end;
    LONG v;

    if (!*s) return FALSE;
    v = wcstol(s, &end, 10);
    if (*end || v < 0 || v > max) return FALSE;
    *out = v;
    return TRUE;
}

static BOOL parse_args(int argc, WCHAR **argv, WCHAR **src, WCHAR **dst, int *bad)
{
    int i, npos = 0;

    for (i = 1; i < argc; i++)
    {
        WCHAR *a = argv[i], name[16];
        const WCHAR *val = NULL;
        WCHAR *colon;
        size_t nl;
        LONG v;

        if (a[0] != '/')
        {
            if (npos == 0) *src = a;
            else if (npos == 1) *dst = a;
            else list_add(&opt.patterns, a);
            npos++;
            continue;
        }
        colon = wcschr(a + 1, ':');
        nl = colon ? (size_t)(colon - (a + 1)) : wcslen(a + 1);
        if (colon) val = colon + 1;
        if (!nl || nl >= ARRAY_SIZE(name)) goto invalid;
        memcpy(name, a + 1, nl * sizeof(WCHAR));
        name[nl] = 0;

#define IS(x) (!_wcsicmp(name, L##x))
        if (IS("S")) opt.subdirs = TRUE;
        else if (IS("E")) opt.empty = TRUE;
        else if (IS("MOVE")) opt.move_files = opt.move_dirs = TRUE;
        else if (IS("MOV")) opt.move_files = TRUE;
        else if (IS("MIR")) opt.empty = opt.purge = TRUE;
        else if (IS("PURGE")) opt.purge = TRUE;
        else if (IS("L")) opt.list_only = TRUE;
        else if (IS("NFL")) opt.nfl = TRUE;
        else if (IS("NDL")) opt.ndl = TRUE;
        else if (IS("NJH")) opt.njh = TRUE;
        else if (IS("NJS")) opt.njs = TRUE;
        else if (IS("NC")) opt.nc = TRUE;
        else if (IS("NS")) opt.ns = TRUE;
        else if (IS("FP")) opt.fp = TRUE;
        else if (IS("TEE")) opt.tee = TRUE;
        else if (IS("IS")) opt.is = TRUE;
        else if (IS("IT")) opt.it = TRUE;
        else if (IS("XO")) opt.xo = TRUE;
        else if (IS("XN")) opt.xn = TRUE;
        else if (IS("XC")) opt.xc = TRUE;
        else if (IS("XJ")) opt.xjd = opt.xjf = TRUE;
        else if (IS("XJD")) opt.xjd = TRUE;
        else if (IS("XJF")) opt.xjf = TRUE;
        else if (IS("NOCOPY")) opt.nocopy = TRUE;
        else if (IS("FFT")) opt.fft = TRUE;
        else if (IS("COPYALL")) opt.copy = CP_D | CP_A | CP_T | CP_S | CP_O | CP_U;
        else if (IS("SEC")) opt.copy = CP_D | CP_A | CP_T | CP_S;
        else if (IS("NP")) opt.np = TRUE;
        else if (IS("Z") || IS("B") || IS("ZB") || IS("J") || IS("MT") || IS("IPG") ||
                 IS("NOOFFLOAD") || IS("V") || IS("TS") || IS("BYTES") || IS("ETA") || IS("X") ||
                 IS("DST"))
            FIXME("option %s is accepted but has no effect\n", debugstr_w(a));
        else if (IS("R"))
        {
            if (!val || !parse_num(val, 1000000, &v)) goto invalid;
            opt.retries = v;
        }
        else if (IS("W"))
        {
            if (!val || !parse_num(val, 30000, &v)) goto invalid;
            opt.wait = v;
        }
        else if (IS("LEV"))
        {
            if (!val || !parse_num(val, 1000000, &v)) goto invalid;
            opt.level = v;
        }
        else if (IS("COPY"))
        {
            if (!val || !parse_flags(val, &opt.copy, TRUE)) goto invalid;
        }
        else if (IS("DCOPY"))
        {
            if (!val || !parse_flags(val, &opt.dcopy, FALSE)) goto invalid;
        }
        else if (IS("LOG") || IS("LOG+"))
        {
            if (!val || !*val) goto invalid;
            opt.log = (WCHAR *)val;
            opt.log_append = IS("LOG+");
        }
        else if (IS("XD") || IS("XF"))
        {
            strlist *l = IS("XD") ? &opt.xd : &opt.xf;
            BOOL got = FALSE;

            while (i + 1 < argc && argv[i + 1][0] != '/')
            {
                list_add(l, argv[++i]);
                got = TRUE;
            }
            if (!got) goto invalid;
        }
        else goto invalid;
#undef IS
        continue;
    invalid:
        *bad = i;
        return FALSE;
    }
    return TRUE;
}

static void fmt_duration(WCHAR *buf, ULONGLONG ms)
{
    ULONGLONG s = ms / 1000;
    _snwprintf(buf, 32, L"%I64u:%02u:%02u", s / 3600, (unsigned)(s / 60 % 60), (unsigned)(s % 60));
}

/* a column of the Bytes row: plain below 1 k, then k, m, g with one decimal */
static void out_size(ULONGLONG v)
{
    static const WCHAR unit[] = L" kmg";
    double d = (double)v;
    int u = 0;

    while (d >= 1024.0 && u < 3) { d /= 1024.0; u++; }
    if (!u) out_printf(L"%10I64u", v);
    else out_printf(L"%7.1f %lc", d, unit[u]);
}

static void summary(DWORD start)
{
    WCHAR el[32], z[32];
    ULONGLONG ms = GetTickCount() - start;
    ULONGLONG sec = ms ? ms : 1;

    fmt_duration(el, ms);
    fmt_duration(z, 0);
    out_printf(L"\n%ls\n", rule);
    out_printf(L"               Total    Copied   Skipped  Mismatch    FAILED    Extras\n");
#define ROW(label, c) \
    out_printf(L"%ls :%10I64u%10I64u%10I64u%10I64u%10I64u%10I64u\n", label, \
               (c).copied + (c).skipped + (c).mismatch + (c).failed, (c).copied, (c).skipped, \
               (c).mismatch, (c).failed, (c).extras)
    ROW(L"    Dirs", dirs);
    ROW(L"   Files", files);
    out_printf(L"   Bytes :");
    out_size(bytes.copied + bytes.skipped + bytes.mismatch + bytes.failed);
    out_size(bytes.copied);
    out_size(bytes.skipped);
    out_size(bytes.mismatch);
    out_size(bytes.failed);
    out_size(bytes.extras);
    out_printf(L"\n");
#undef ROW
    out_printf(L"   Times : %9ls%10ls%10ls%10ls%10ls\n\n", el, el, L"", z, z);
    out_printf(L"   Speed : %17I64u Bytes/sec.\n", bytes.copied * 1000 / sec);
    out_printf(L"   Speed : %17.3f MegaBytes/min.\n", (double)bytes.copied * 60000.0 / sec / 1048576.0);
    out_now(L"   Ended");
    out_printf(L"\n");
}

int __cdecl wmain(int argc, WCHAR *argv[])
{
    WCHAR *src_arg = NULL, *dst_arg = NULL, *root_src;
    int bad = 0, i;
    DWORD start = GetTickCount();
    dctx top;
    DWORD sattr, err;

    out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    out_console = GetFileType(out_handle) == FILE_TYPE_CHAR;
    {
        DWORD mode;
        out_console = out_console && GetConsoleMode(out_handle, &mode);
    }
    out_cp = GetConsoleOutputCP();
    if (!out_cp) out_cp = GetOEMCP();
    log_handle = INVALID_HANDLE_VALUE;

    for (i = 1; i < argc; i++)
        if (!wcscmp(argv[i], L"/?") || !wcscmp(argv[i], L"-?"))
        {
            usage();
            return RC_FATAL;
        }

    if (!parse_args(argc, argv, &src_arg, &dst_arg, &bad))
    {
        out_printf(L"\n%ls   ROBOCOPY     ::     Robust File Copy for ReactOS\n%ls\n", rule, rule);
        out_printf(L"ERROR : Invalid Parameter #%d : \"%ls\"\n\n", bad, argv[bad]);
        usage();
        return RC_FATAL;
    }
    if (opt.log)
    {
        log_handle = CreateFileW(opt.log, opt.log_append ? FILE_APPEND_DATA : GENERIC_WRITE, FILE_SHARE_READ,
                                 NULL, opt.log_append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (log_handle == INVALID_HANDLE_VALUE)
        {
            out_printf(L"ERROR : Cannot open log file %ls\n", opt.log);
            opt.log = NULL;
            return RC_FATAL;
        }
        if (opt.log_append) SetFilePointer(log_handle, 0, NULL, FILE_END);
    }
    if (!src_arg || !dst_arg)
    {
        out_printf(L"\n%ls   ROBOCOPY     ::     Robust File Copy for ReactOS\n%ls\n", rule, rule);
        out_printf(L"ERROR : No %ls Directory Specified.\n\n", src_arg ? L"Destination" : L"Source");
        usage();
        return RC_FATAL;
    }
    /* Copying the owner sets one the caller may not assign without it (see enable_privilege) */
    if (opt.copy & CP_O) enable_privilege(L"SeRestorePrivilege");

    root_src = make_root(src_arg);
    root_dst = make_root(dst_arg);
    if (!root_src || !root_dst)
    {
        out_printf(L"ERROR : Invalid path.\n");
        return RC_FATAL;
    }

    if (!opt.njh)
    {
        out_printf(L"\n%ls   ROBOCOPY     ::     Robust File Copy for ReactOS\n%ls\n", rule, rule);
        out_now(L"  Started");
        out_printf(L"   Source : %ls\n     Dest : %ls\n\n", disp_dir(root_src), disp_dir(root_dst));
        out_printf(L"    Files : ");
        if (!opt.patterns.count) out_printf(L"*.*");
        for (i = 0; i < opt.patterns.count; i++) out_printf(L"%ls ", opt.patterns.v[i]);
        out_printf(L"\n");
        for (i = 0; i < opt.xf.count; i++) out_printf(L"%ls%ls", i ? L" " : L"\n Exc Files : ", opt.xf.v[i]);
        for (i = 0; i < opt.xd.count; i++) out_printf(L"%ls%ls", i ? L" " : L"\n  Exc Dirs : ", opt.xd.v[i]);
        out_printf(L"\n\n  Options : ");
        if (!opt.patterns.count) out_printf(L"*.* ");
        if (opt.subdirs) out_printf(L"/S ");
        if (opt.empty) out_printf(L"/E ");
        if (opt.purge) out_printf(L"/PURGE ");
        if (opt.move_dirs) out_printf(L"/MOVE ");
        else if (opt.move_files) out_printf(L"/MOV ");
        if (opt.list_only) out_printf(L"/L ");
        out_printf(L"/DCOPY:%ls%ls%ls /COPY:%ls%ls%ls%ls%ls%ls /R:%ld /W:%lu\n\n",
                   opt.dcopy & CP_D ? L"D" : L"", opt.dcopy & CP_A ? L"A" : L"", opt.dcopy & CP_T ? L"T" : L"",
                   opt.copy & CP_D ? L"D" : L"", opt.copy & CP_A ? L"A" : L"", opt.copy & CP_T ? L"T" : L"",
                   opt.copy & CP_S ? L"S" : L"", opt.copy & CP_O ? L"O" : L"", opt.copy & CP_U ? L"U" : L"",
                   opt.retries, opt.wait);
        out_printf(L"%ls\n", rule);
    }

    sattr = GetFileAttributesW(root_src);
    if (sattr == INVALID_FILE_ATTRIBUTES || !(sattr & FILE_ATTRIBUTE_DIRECTORY))
    {
        err = sattr == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_DIRECTORY;
        out_printf(L"ERROR %lu (0x%08lX) Accessing Source Directory %ls\n", err, err, disp_dir(root_src));
        out_error(err);
        return RC_FATAL;
    }
    if (!_wcsicmp(root_src, root_dst))
    {
        out_printf(L"Source and destination are the same directory, nothing to do.\n");
        return 0;
    }
    sattr = GetFileAttributesW(root_dst);
    if (sattr != INVALID_FILE_ATTRIBUTES && !(sattr & FILE_ATTRIBUTE_DIRECTORY))
    {
        out_printf(L"ERROR %d (0x%08lX) Creating Destination Directory %ls\n", ERROR_ALREADY_EXISTS,
                   (DWORD)ERROR_ALREADY_EXISTS, disp_dir(root_dst));
        return RC_FATAL;
    }
    top.src = root_src;
    top.dst = root_dst;
    top.parent = NULL;
    top.existed = top.made = sattr != INVALID_FILE_ATTRIBUTES;
    top.err = 0;
    top.via_link = FALSE;
    if (!top.existed && !ensure_dir(&top)) return RC_FATAL;
    /* a destination inside the source must not be walked */
    if (!is_within(root_dst, root_src)) root_dst = NULL;
    process_dir(&top, 0);
    if (opt.move_dirs && !opt.list_only) remove_dir_force(root_src);

    if (!opt.njs) summary(start);
    if (files.copied) exit_bits |= RC_COPIED;
    if (files.extras || dirs.extras) exit_bits |= RC_EXTRA;
    if (files.mismatch || dirs.mismatch) exit_bits |= RC_MISMATCH;
    if (files.failed || dirs.failed) exit_bits |= RC_FAILED;
    if (log_handle != INVALID_HANDLE_VALUE) CloseHandle(log_handle);
    return exit_bits;
}
