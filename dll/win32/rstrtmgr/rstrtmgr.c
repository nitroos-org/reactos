/*
 * Restart Manager (rstrtmgr.dll)
 *
 * Copyright 2026 the reactos-nitro authors
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

/*
 * A session collects files, applications and services. RmGetList reports the
 * processes that use them: a process that has a registered file mapped as a
 * module or open through a handle, a registered application, a registered
 * service and the running services that depend on it. The answers (error
 * codes, ordering of the checks, application type and name rules) follow
 * measurements on Windows 10 22H2. Not implemented: sessions shared between
 * processes (RmJoinSession), restarting the stopped applications (needs the
 * RegisterApplicationRestart data), the filter list.
 */

#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <winuser.h>
#include <winsvc.h>
#include <winver.h>
#include <string.h>
#include <tlhelp32.h>
#define NTOS_MODE_USER
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <restartmanager.h>

#define NDEBUG
#include <debug.h>

#define MAX_SESSIONS 64
#define STATUS_FILE_TYPE_UNKNOWN 0xffff

#define RM_STATUS_RUNNING        0x01
#define RM_STATUS_STOPPED        0x02
#define RM_STATUS_STOPPED_OTHER  0x04
#define RM_STATUS_ERROR_ON_STOP  0x10
#define RM_STATUS_SHUTDOWN_MASK  0x40

#define RM_FORCE_SHUTDOWN        0x01
#define RM_SHUTDOWN_ONLY_REG     0x10

#ifndef TH32CS_SNAPMODULE32
#define TH32CS_SNAPMODULE32 0x00000010
#endif

typedef struct
{
    LPWSTR module;
    DWORD pid;
    LPWSTR service;
    RM_FILTER_ACTION action;
} FILTER;

typedef struct
{
    BOOL used;
    WCHAR key[CCH_RM_SESSION_KEY + 1];
    LPWSTR *files;
    UINT nfiles;
    RM_UNIQUE_PROCESS *apps;
    UINT napps;
    LPWSTR *services;
    UINT nservices;
    DWORD *stopped;     /* pids shut down by RmShutdown */
    UINT nstopped;
    FILTER *filters;
    UINT nfilters;
} SESSION;

static CRITICAL_SECTION session_cs;
static CRITICAL_SECTION_DEBUG session_cs_debug =
{
    0, 0, &session_cs,
    { &session_cs_debug.ProcessLocksList, &session_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": session_cs") }
};
static CRITICAL_SECTION session_cs = { &session_cs_debug, -1, 0, 0, 0, 0 };
static SESSION sessions[MAX_SESSIONS];

BOOLEAN WINAPI SystemFunction036(PVOID buffer, ULONG length); /* RtlGenRandom */

static LPWSTR dup_string(LPCWSTR s)
{
    SIZE_T len = (lstrlenW(s) + 1) * sizeof(WCHAR);
    LPWSTR ret = HeapAlloc(GetProcessHeap(), 0, len);
    if (ret) memcpy(ret, s, len);
    return ret;
}

static void free_string_array(LPWSTR *a, UINT n)
{
    UINT i;
    for (i = 0; i < n; i++) HeapFree(GetProcessHeap(), 0, a[i]);
    HeapFree(GetProcessHeap(), 0, a);
}

static void free_session(SESSION *s)
{
    UINT i;

    free_string_array(s->files, s->nfiles);
    free_string_array(s->services, s->nservices);
    for (i = 0; i < s->nfilters; i++)
    {
        HeapFree(GetProcessHeap(), 0, s->filters[i].module);
        HeapFree(GetProcessHeap(), 0, s->filters[i].service);
    }
    HeapFree(GetProcessHeap(), 0, s->filters);
    HeapFree(GetProcessHeap(), 0, s->apps);
    HeapFree(GetProcessHeap(), 0, s->stopped);
    memset(s, 0, sizeof(*s));
}

/* Must be called with session_cs held. */
static SESSION *get_session(DWORD handle)
{
    if (handle >= MAX_SESSIONS || !sessions[handle].used) return NULL;
    return &sessions[handle];
}

/* Append to a growing array of 'size'-byte elements. */
static BOOL array_append(void **array, UINT *count, UINT *capacity, UINT size, const void *elem)
{
    if (*count >= *capacity)
    {
        UINT ncap = *capacity ? *capacity * 2 : 8;
        void *n = *array ? HeapReAlloc(GetProcessHeap(), 0, *array, (SIZE_T)ncap * size)
                         : HeapAlloc(GetProcessHeap(), 0, (SIZE_T)ncap * size);
        if (!n) return FALSE;
        *array = n;
        *capacity = ncap;
    }
    memcpy((char *)*array + (SIZE_T)*count * size, elem, size);
    (*count)++;
    return TRUE;
}

/***********************************************************************
 * RmStartSession (rstrtmgr.@)
 */
DWORD WINAPI RmStartSession(DWORD *handle, DWORD flags, WCHAR key[])
{
    static const WCHAR hex[] = L"0123456789abcdef";
    BYTE guid[RM_SESSION_KEY_LEN];
    DWORD i, ret = ERROR_MAX_SESSIONS_REACHED;

    DPRINT("%p, %lu, %p\n", handle, flags, key);

    if (!handle || !key) return ERROR_BAD_ARGUMENTS;

    if (!SystemFunction036(guid, sizeof(guid)))
        return ERROR_OUTOFMEMORY;

    EnterCriticalSection(&session_cs);
    for (i = 0; i < MAX_SESSIONS; i++)
    {
        UINT j;

        if (sessions[i].used) continue;
        memset(&sessions[i], 0, sizeof(sessions[i]));
        sessions[i].used = TRUE;
        for (j = 0; j < sizeof(guid); j++)
        {
            sessions[i].key[2 * j] = hex[guid[j] >> 4];
            sessions[i].key[2 * j + 1] = hex[guid[j] & 15];
        }
        memcpy(key, sessions[i].key, sizeof(sessions[i].key));
        *handle = i;
        ret = ERROR_SUCCESS;
        break;
    }
    LeaveCriticalSection(&session_cs);
    return ret;
}

/***********************************************************************
 * RmEndSession (rstrtmgr.@)
 */
DWORD WINAPI RmEndSession(DWORD handle)
{
    SESSION *s;
    DWORD ret = ERROR_INVALID_HANDLE;

    DPRINT("%lu\n", handle);

    EnterCriticalSection(&session_cs);
    if ((s = get_session(handle)))
    {
        free_session(s);
        ret = ERROR_SUCCESS;
    }
    LeaveCriticalSection(&session_cs);
    return ret;
}

/***********************************************************************
 * RmRegisterResources (rstrtmgr.@)
 */
DWORD WINAPI RmRegisterResources(DWORD handle, UINT nfiles, LPCWSTR files[], UINT napps,
                                 RM_UNIQUE_PROCESS apps[], UINT nservices, LPCWSTR services[])
{
    SESSION *s;
    UINT i, cap;
    DWORD ret = ERROR_SUCCESS;

    DPRINT("%lu, %u, %p, %u, %p, %u, %p\n", handle, nfiles, files, napps, apps, nservices, services);

    EnterCriticalSection(&session_cs);
    if (!(s = get_session(handle)))
    {
        ret = ERROR_INVALID_HANDLE;
        goto done;
    }
    if ((nfiles && !files) || (napps && !apps) || (nservices && !services))
    {
        ret = ERROR_BAD_ARGUMENTS;
        goto done;
    }

    cap = s->nfiles;
    for (i = 0; i < nfiles; i++)
    {
        LPWSTR copy;

        if (!files[i] || !files[i][0]) continue;
        if (!(copy = dup_string(files[i])) ||
            !array_append((void **)&s->files, &s->nfiles, &cap, sizeof(LPWSTR), &copy))
        {
            HeapFree(GetProcessHeap(), 0, copy);
            ret = ERROR_OUTOFMEMORY;
            goto done;
        }
    }

    cap = s->napps;
    for (i = 0; i < napps; i++)
    {
        if (!array_append((void **)&s->apps, &s->napps, &cap, sizeof(RM_UNIQUE_PROCESS), &apps[i]))
        {
            ret = ERROR_OUTOFMEMORY;
            goto done;
        }
    }

    cap = s->nservices;
    for (i = 0; i < nservices; i++)
    {
        LPWSTR copy;

        if (!services[i] || !services[i][0]) continue;
        if (!(copy = dup_string(services[i])) ||
            !array_append((void **)&s->services, &s->nservices, &cap, sizeof(LPWSTR), &copy))
        {
            HeapFree(GetProcessHeap(), 0, copy);
            ret = ERROR_OUTOFMEMORY;
            goto done;
        }
    }

done:
    LeaveCriticalSection(&session_cs);
    return ret;
}

/* ------------------------------------------------------------------ */
/* the list of affected applications */

typedef struct
{
    RM_PROCESS_INFO *info;
    UINT count, capacity;
    DWORD reasons;
} AFFECTED;

typedef struct
{
    LPWSTR dos;         /* normalised DOS path, for module comparison */
    BOOL have_id;
    DWORD volume;       /* volume serial and file index, for handle comparison: the name of an open file */
    DWORD index_high;   /* object is the name it was opened with, not the normalised one */
    DWORD index_low;
} TARGET;

static BOOL affected_has_pid(const AFFECTED *a, DWORD pid)
{
    UINT i;
    for (i = 0; i < a->count; i++)
        if (a->info[i].Process.dwProcessId == pid && a->info[i].ApplicationType != RmService) return TRUE;
    return FALSE;
}

/* The registered name must be an absolute path (a relative name never matches). */
static BOOL is_absolute_path(LPCWSTR p)
{
    if (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
        return TRUE;
    return (p[0] == '\\' || p[0] == '/') && (p[1] == '\\' || p[1] == '/');
}

static LPWSTR query_nt_name(HANDLE file)
{
    BYTE stackbuf[sizeof(OBJECT_NAME_INFORMATION) + 520 * sizeof(WCHAR)];
    OBJECT_NAME_INFORMATION *oni = (OBJECT_NAME_INFORMATION *)stackbuf;
    ULONG len;
    LPWSTR ret;

    if (!NT_SUCCESS(NtQueryObject(file, ObjectNameInformation, oni, sizeof(stackbuf), &len)) || !oni->Name.Buffer)
        return NULL;
    if (!(ret = HeapAlloc(GetProcessHeap(), 0, oni->Name.Length + sizeof(WCHAR)))) return NULL;
    memcpy(ret, oni->Name.Buffer, oni->Name.Length);
    ret[oni->Name.Length / sizeof(WCHAR)] = 0;
    return ret;
}

/*
 * The name an open file reports is the real one, after the WoW64 file system
 * redirection of the caller (System32 became SysWOW64); the registered name is
 * not. Convert it back to a DOS path so that it compares with module paths.
 */
static BOOL nt_name_to_dos(LPCWSTR nt, LPWSTR dos, DWORD size)
{
    WCHAR drive[3] = L"A:", target[MAX_PATH];
    UINT i;

    for (i = 0; i < 26; i++)
    {
        DWORD len;

        drive[0] = 'A' + i;
        if (!QueryDosDeviceW(drive, target, ARRAYSIZE(target))) continue;
        len = lstrlenW(target);
        if (!len || _wcsnicmp(nt, target, len) || (nt[len] && nt[len] != '\\')) continue;
        if (lstrlenW(nt + len) + 3 > (int)size) return FALSE;
        dos[0] = drive[0];
        dos[1] = ':';
        lstrcpyW(dos + 2, nt + len);
        return TRUE;
    }
    return FALSE;
}

static void free_targets(TARGET *t, UINT n)
{
    UINT i;
    for (i = 0; i < n; i++)
    {
        HeapFree(GetProcessHeap(), 0, t[i].dos);
    }
    HeapFree(GetProcessHeap(), 0, t);
}

/*
 * Resolve the registered files. Returns ERROR_ACCESS_DENIED for a directory,
 * which is what Windows 10 reports from RmGetList.
 */
static DWORD resolve_targets(LPWSTR *files, UINT nfiles, TARGET **out, UINT *nout, HANDLE *probe)
{
    TARGET *t;
    UINT i, n = 0;

    *out = NULL; *nout = 0; *probe = INVALID_HANDLE_VALUE;
    if (!nfiles) return ERROR_SUCCESS;
    if (!(t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nfiles * sizeof(*t)))) return ERROR_OUTOFMEMORY;

    for (i = 0; i < nfiles; i++)
    {
        WCHAR full[MAX_PATH], lng[MAX_PATH];
        LPCWSTR path = files[i];
        DWORD attrs, len;
        HANDLE h;

        if (!is_absolute_path(path)) continue;
        if (path[0] == '\\' && path[1] == '\\' && path[2] == '?' && path[3] == '\\') path += 4;
        len = GetFullPathNameW(path, MAX_PATH, full, NULL);
        if (!len || len >= MAX_PATH) continue;
        len = GetLongPathNameW(full, lng, MAX_PATH);
        if (len && len < MAX_PATH) lstrcpyW(full, lng);

        attrs = GetFileAttributesW(full);
        if (attrs == INVALID_FILE_ATTRIBUTES) continue;
        if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        {
            free_targets(t, n);
            if (*probe != INVALID_HANDLE_VALUE) CloseHandle(*probe);
            *probe = INVALID_HANDLE_VALUE;
            return ERROR_ACCESS_DENIED;
        }

        h = CreateFileW(full, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            BY_HANDLE_FILE_INFORMATION bhfi;
            LPWSTR nt = query_nt_name(h);
            WCHAR real[MAX_PATH];

            if (nt && nt_name_to_dos(nt, real, MAX_PATH))
            {
                len = GetLongPathNameW(real, lng, MAX_PATH);
                lstrcpyW(full, len && len < MAX_PATH ? lng : real);
            }
            HeapFree(GetProcessHeap(), 0, nt);

            if (GetFileInformationByHandle(h, &bhfi))
            {
                t[n].have_id = TRUE;
                t[n].volume = bhfi.dwVolumeSerialNumber;
                t[n].index_high = bhfi.nFileIndexHigh;
                t[n].index_low = bhfi.nFileIndexLow;
            }
            t[n].dos = dup_string(full);
            if (*probe == INVALID_HANDLE_VALUE) *probe = h; else CloseHandle(h);
        }
        else
            t[n].dos = dup_string(full);
        n++;
    }
    *out = t;
    *nout = n;
    return ERROR_SUCCESS;
}

static WORD file_type_index(HANDLE probe, const SYSTEM_HANDLE_INFORMATION_EX *info)
{
    ULONG_PTR i, me = GetCurrentProcessId();

    for (i = 0; i < info->NumberOfHandles; i++)
        if (info->Handles[i].UniqueProcessId == me && info->Handles[i].HandleValue == (ULONG_PTR)probe)
            return info->Handles[i].ObjectTypeIndex;
    return STATUS_FILE_TYPE_UNKNOWN;
}

static BOOL module_match(DWORD pid, TARGET *t, UINT nt)
{
    MODULEENTRY32W me;
    HANDLE snap;
    BOOL found = FALSE, ok;
    UINT i;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    me.dwSize = sizeof(me);
    for (ok = Module32FirstW(snap, &me); ok && !found; ok = Module32NextW(snap, &me))
        for (i = 0; i < nt; i++)
            if (t[i].dos && !lstrcmpiW(me.szExePath, t[i].dos)) { found = TRUE; break; }
    CloseHandle(snap);
    return found;
}

/* Handles: a registered file that a process holds open (not mapped). */
static void handle_scan(TARGET *t, UINT nt, HANDLE probe, DWORD **hits, UINT *nhits, UINT *hcap)
{
    SYSTEM_HANDLE_INFORMATION_EX *info = NULL;
    ULONG size = 0x40000, needed;
    NTSTATUS status;
    ULONG_PTR i;
    WORD file_type;
    DWORD cur = 0, self = GetCurrentProcessId();
    HANDLE proc = NULL;

    for (;;)
    {
        info = HeapAlloc(GetProcessHeap(), 0, size);
        if (!info) return;
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, info, size, &needed);
        if (status != STATUS_INFO_LENGTH_MISMATCH) break;
        HeapFree(GetProcessHeap(), 0, info);
        size = needed + 0x10000;
    }
    if (!NT_SUCCESS(status)) goto done;
    if ((file_type = file_type_index(probe, info)) == STATUS_FILE_TYPE_UNKNOWN) goto done;

    for (i = 0; i < info->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *e = &info->Handles[i];
        DWORD pid = (DWORD)e->UniqueProcessId, k;
        HANDLE dup = NULL;
        BY_HANDLE_FILE_INFORMATION bhfi;
        BOOL hit = FALSE;

        if (e->ObjectTypeIndex != file_type || pid <= 4) continue;
        if (pid == self && e->HandleValue == (ULONG_PTR)probe) continue;
        for (k = 0; k < *nhits; k++) if ((*hits)[k] == pid) break;
        if (k < *nhits) continue;

        if (pid != self && pid != cur)
        {
            if (proc) CloseHandle(proc);
            cur = pid;
            proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        }
        if (pid != self && !proc) continue;

        if (!NT_SUCCESS(NtDuplicateObject(pid == self ? NtCurrentProcess() : proc, (HANDLE)e->HandleValue,
                                          NtCurrentProcess(), &dup, FILE_READ_ATTRIBUTES, 0, 0)))
            continue;
        if (GetFileType(dup) == FILE_TYPE_DISK && GetFileInformationByHandle(dup, &bhfi))
        {
            for (k = 0; k < nt && !hit; k++)
                if (t[k].have_id && t[k].volume == bhfi.dwVolumeSerialNumber &&
                    t[k].index_high == bhfi.nFileIndexHigh && t[k].index_low == bhfi.nFileIndexLow) hit = TRUE;
        }
        NtClose(dup);
        if (hit) array_append((void **)hits, nhits, hcap, sizeof(DWORD), &pid);
    }
done:
    if (proc) CloseHandle(proc);
    HeapFree(GetProcessHeap(), 0, info);
}

static BOOL get_image_path(DWORD pid, LPWSTR path, DWORD size)
{
    MODULEENTRY32W me;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    BOOL ret = FALSE;

    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me) && lstrlenW(me.szExePath) < (int)size)
    {
        lstrcpyW(path, me.szExePath);
        ret = TRUE;
    }
    CloseHandle(snap);
    return ret;
}

static void file_description(LPCWSTR path, LPWSTR out, UINT size)
{
    DWORD handle, len = GetFileVersionInfoSizeW(path, &handle);
    BYTE *data;
    struct { WORD lang, cp; } *tr;
    UINT trlen, dlen;
    WCHAR sub[64];
    LPCWSTR desc;

    out[0] = 0;
    if (!len || !(data = HeapAlloc(GetProcessHeap(), 0, len))) return;
    if (GetFileVersionInfoW(path, 0, len, data) &&
        VerQueryValueW(data, L"\\VarFileInfo\\Translation", (void **)&tr, &trlen) && trlen >= 4)
    {
        wsprintfW(sub, L"\\StringFileInfo\\%04x%04x\\FileDescription", tr[0].lang, tr[0].cp);
        if (VerQueryValueW(data, sub, (void **)&desc, &dlen) && dlen > 1 && desc[0])
            lstrcpynW(out, desc, size);
    }
    HeapFree(GetProcessHeap(), 0, data);
}

typedef struct { DWORD pid; BOOL found; } WINDOW_SEARCH;

static BOOL CALLBACK window_proc(HWND hwnd, LPARAM lparam)
{
    WINDOW_SEARCH *ws = (WINDOW_SEARCH *)lparam;
    DWORD pid;

    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == ws->pid && IsWindowVisible(hwnd) && !GetWindow(hwnd, GW_OWNER))
    {
        ws->found = TRUE;
        return FALSE;
    }
    return TRUE;
}

static BOOL is_console_image(LPCWSTR path)
{
    BYTE buf[4096];
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS32 *nt;
    DWORD read = 0;
    BOOL ret = FALSE;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (ReadFile(h, buf, sizeof(buf), &read, NULL) && read > sizeof(*dos) && dos->e_magic == IMAGE_DOS_SIGNATURE &&
        dos->e_lfanew > 0 && (DWORD)dos->e_lfanew + sizeof(*nt) <= read)
    {
        nt = (IMAGE_NT_HEADERS32 *)(buf + dos->e_lfanew);
        ret = nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
    }
    CloseHandle(h);
    return ret;
}

static BOOL is_critical_name(LPCWSTR base)
{
    static const WCHAR *names[] = { L"csrss.exe", L"smss.exe", L"wininit.exe", L"winlogon.exe", L"lsass.exe",
                                    L"services.exe", L"System" };
    UINT i;
    for (i = 0; i < ARRAYSIZE(names); i++) if (!lstrcmpiW(base, names[i])) return TRUE;
    return FALSE;
}

static LPCWSTR base_name(LPCWSTR path)
{
    LPCWSTR p = wcsrchr(path, '\\');
    return p ? p + 1 : path;
}

static BOOL is_stopped(const SESSION *s, DWORD pid)
{
    UINT i;
    for (i = 0; i < s->nstopped; i++) if (s->stopped[i] == pid) return TRUE;
    return FALSE;
}

static BOOL filter_matches(const SESSION *s, DWORD pid, LPCWSTR base, RM_FILTER_ACTION action)
{
    UINT i;
    for (i = 0; i < s->nfilters; i++)
    {
        const FILTER *f = &s->filters[i];
        if (!(f->action & action)) continue;
        if (f->pid && f->pid == pid) return TRUE;
        if (f->module && base && !lstrcmpiW(f->module, base)) return TRUE;
    }
    return FALSE;
}

static void fill_process(AFFECTED *a, UINT *cap, const SESSION *s, DWORD pid, const FILETIME *start_hint)
{
    RM_PROCESS_INFO info;
    WCHAR path[MAX_PATH];
    WINDOW_SEARCH ws;
    FILETIME c, e, k, u;
    HANDLE proc;
    DWORD sid;
    BOOL have_path;

    memset(&info, 0, sizeof(info));
    info.Process.dwProcessId = pid;
    if (start_hint) info.Process.ProcessStartTime = *start_hint;
    info.TSSessionId = ~0u;
    info.AppStatus = RM_STATUS_STOPPED_OTHER;
    info.ApplicationType = RmUnknownApp;

    proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (proc)
    {
        if (GetProcessTimes(proc, &c, &e, &k, &u)) info.Process.ProcessStartTime = c;
        if (ProcessIdToSessionId(pid, &sid)) info.TSSessionId = sid;
        info.AppStatus = RM_STATUS_RUNNING;
        CloseHandle(proc);
    }
    else if (pid == GetCurrentProcessId())
        info.AppStatus = RM_STATUS_RUNNING;
    else
    {
        /* a registered application that is gone: no name, session -1 */
        array_append((void **)&a->info, &a->count, cap, sizeof(info), &info);
        return;
    }

    have_path = get_image_path(pid, path, MAX_PATH);
    if (have_path)
    {
        file_description(path, info.strAppName, ARRAYSIZE(info.strAppName));
        if (!info.strAppName[0]) lstrcpynW(info.strAppName, base_name(path), ARRAYSIZE(info.strAppName));
    }

    ws.pid = pid; ws.found = FALSE;
    EnumWindows(window_proc, (LPARAM)&ws);

    if (pid == GetCurrentProcessId())
    {
        info.ApplicationType = RmCritical;
        a->reasons |= RmRebootReasonDetectedSelf;
    }
    else if (pid <= 4 || (have_path && is_critical_name(base_name(path))))
    {
        info.ApplicationType = RmCritical;
        a->reasons |= RmRebootReasonCriticalProcess;
    }
    else if (have_path && !lstrcmpiW(base_name(path), L"explorer.exe"))
        info.ApplicationType = RmExplorer;
    else if (ws.found)
    {
        info.ApplicationType = RmMainWindow;
        info.bRestartable = TRUE;
    }
    else if (have_path && is_console_image(path))
        info.ApplicationType = RmConsole;

    if (have_path && filter_matches(s, pid, base_name(path), RmNoShutdown))
        info.AppStatus |= RM_STATUS_SHUTDOWN_MASK;
    if (is_stopped(s, pid)) info.AppStatus = RM_STATUS_STOPPED;

    array_append((void **)&a->info, &a->count, cap, sizeof(info), &info);
}

/* Entry for a running or missing service. */
static void fill_service(AFFECTED *a, UINT *cap, SC_HANDLE scm, LPCWSTR name, SC_HANDLE svc, DWORD pid)
{
    RM_PROCESS_INFO info;
    DWORD len = 0;

    memset(&info, 0, sizeof(info));
    info.Process.dwProcessId = pid;
    info.ApplicationType = RmService;
    info.bRestartable = TRUE;
    info.TSSessionId = 0;
    info.AppStatus = pid ? RM_STATUS_RUNNING : RM_STATUS_STOPPED_OTHER;
    lstrcpynW(info.strServiceShortName, name, ARRAYSIZE(info.strServiceShortName));
    if (pid)
    {
        FILETIME c, e, k, u;
        HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (proc)
        {
            if (GetProcessTimes(proc, &c, &e, &k, &u)) info.Process.ProcessStartTime = c;
            CloseHandle(proc);
        }
        len = ARRAYSIZE(info.strAppName);
        if (!GetServiceDisplayNameW(scm, name, info.strAppName, &len)) lstrcpynW(info.strAppName, name, ARRAYSIZE(info.strAppName));
    }
    array_append((void **)&a->info, &a->count, cap, sizeof(info), &info);
}

static BOOL affected_has_service(const AFFECTED *a, LPCWSTR name)
{
    UINT i;
    for (i = 0; i < a->count; i++)
        if (a->info[i].ApplicationType == RmService && !lstrcmpiW(a->info[i].strServiceShortName, name)) return TRUE;
    return FALSE;
}

static void add_service_and_dependents(AFFECTED *a, UINT *cap, SC_HANDLE scm, LPCWSTR name)
{
    SC_HANDLE svc;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed, count = 0, i;
    ENUM_SERVICE_STATUSW *deps = NULL;

    if (affected_has_service(a, name)) return;
    svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (!svc)
    {
        fill_service(a, cap, scm, name, NULL, 0);   /* a missing service is listed as stopped */
        return;
    }
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (BYTE *)&ssp, sizeof(ssp), &needed) ||
        ssp.dwCurrentState == SERVICE_STOPPED)
    {
        CloseServiceHandle(svc);
        return;
    }
    fill_service(a, cap, scm, name, svc, ssp.dwProcessId);

    if (!EnumDependentServicesW(svc, SERVICE_ACTIVE, NULL, 0, &needed, &count) && GetLastError() == ERROR_MORE_DATA &&
        (deps = HeapAlloc(GetProcessHeap(), 0, needed)))
    {
        if (EnumDependentServicesW(svc, SERVICE_ACTIVE, deps, needed, &needed, &count))
            for (i = 0; i < count; i++) add_service_and_dependents(a, cap, scm, deps[i].lpServiceName);
        HeapFree(GetProcessHeap(), 0, deps);
    }
    CloseServiceHandle(svc);
}

/* Services that run inside the process pid. */
static void add_hosted_services(AFFECTED *a, UINT *cap, SC_HANDLE scm, DWORD pid)
{
    ENUM_SERVICE_STATUS_PROCESSW *list;
    DWORD needed = 0, count = 0, resume = 0, i;

    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, NULL, 0, &needed, &count,
                               &resume, NULL) && GetLastError() == ERROR_MORE_DATA &&
        (list = HeapAlloc(GetProcessHeap(), 0, needed)))
    {
        resume = 0;
        if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, (BYTE *)list, needed,
                                  &needed, &count, &resume, NULL))
        {
            for (i = 0; i < count; i++)
                if (list[i].ServiceStatusProcess.dwProcessId == pid)
                    add_service_and_dependents(a, cap, scm, list[i].lpServiceName);
        }
        HeapFree(GetProcessHeap(), 0, list);
    }
}

static DWORD build_list(SESSION *s, AFFECTED *a)
{
    LPWSTR *files = NULL, *services = NULL;
    RM_UNIQUE_PROCESS *apps = NULL;
    UINT nfiles = 0, napps = 0, nservices = 0, i, cap = 0, ntargets = 0;
    TARGET *targets = NULL;
    HANDLE probe = INVALID_HANDLE_VALUE;
    DWORD ret = ERROR_SUCCESS, *hits = NULL;
    UINT nhits = 0, hcap = 0;
    SC_HANDLE scm = NULL;
    SESSION snap;

    memset(a, 0, sizeof(*a));
    memset(&snap, 0, sizeof(snap));

    /* work on copies: the scan below runs without the session lock */
    EnterCriticalSection(&session_cs);
    nfiles = s->nfiles; napps = s->napps; nservices = s->nservices;
    files = nfiles ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nfiles * sizeof(LPWSTR)) : NULL;
    services = nservices ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nservices * sizeof(LPWSTR)) : NULL;
    apps = napps ? HeapAlloc(GetProcessHeap(), 0, napps * sizeof(*apps)) : NULL;
    if ((nfiles && !files) || (nservices && !services) || (napps && !apps)) ret = ERROR_OUTOFMEMORY;
    else
    {
        for (i = 0; i < nfiles; i++) files[i] = dup_string(s->files[i]);
        for (i = 0; i < nservices; i++) services[i] = dup_string(s->services[i]);
        if (napps) memcpy(apps, s->apps, napps * sizeof(*apps));
        snap = *s;  /* shallow: only nstopped/stopped/filters are read, copied below */
        if (s->nstopped)
        {
            snap.stopped = HeapAlloc(GetProcessHeap(), 0, s->nstopped * sizeof(DWORD));
            if (snap.stopped) memcpy(snap.stopped, s->stopped, s->nstopped * sizeof(DWORD)); else snap.nstopped = 0;
        }
        if (s->nfilters)
        {
            snap.filters = HeapAlloc(GetProcessHeap(), 0, s->nfilters * sizeof(FILTER));
            if (snap.filters)
            {
                memcpy(snap.filters, s->filters, s->nfilters * sizeof(FILTER));
                for (i = 0; i < s->nfilters; i++)
                {
                    snap.filters[i].module = s->filters[i].module ? dup_string(s->filters[i].module) : NULL;
                    snap.filters[i].service = NULL;
                }
            }
            else snap.nfilters = 0;
        }
    }
    LeaveCriticalSection(&session_cs);
    if (ret != ERROR_SUCCESS) goto cleanup;

    for (i = 0; i < napps; i++)
        if (!affected_has_pid(a, apps[i].dwProcessId)) fill_process(a, &cap, &snap, apps[i].dwProcessId, &apps[i].ProcessStartTime);

    if (nservices)
    {
        scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (scm)
            for (i = 0; i < nservices; i++) add_service_and_dependents(a, &cap, scm, services[i]);
    }

    if (nfiles)
    {
        SYSTEM_PROCESS_INFORMATION *procs = NULL, *p;
        ULONG size = 0x20000, needed;
        NTSTATUS status;

        ret = resolve_targets(files, nfiles, &targets, &ntargets, &probe);
        if (ret != ERROR_SUCCESS || !ntargets) goto services_done;

        if (probe != INVALID_HANDLE_VALUE)
            handle_scan(targets, ntargets, probe, &hits, &nhits, &hcap);

        for (;;)
        {
            procs = HeapAlloc(GetProcessHeap(), 0, size);
            if (!procs) break;
            status = NtQuerySystemInformation(SystemProcessInformation, procs, size, &needed);
            if (status != STATUS_INFO_LENGTH_MISMATCH) break;
            HeapFree(GetProcessHeap(), 0, procs);
            procs = NULL;
            size = needed + 0x10000;
        }
        if (procs && NT_SUCCESS(status))
        {
            for (p = procs;; p = (SYSTEM_PROCESS_INFORMATION *)((BYTE *)p + p->NextEntryOffset))
            {
                DWORD pid = HandleToUlong(p->UniqueProcessId), k;
                BOOL hit = FALSE;

                if (pid)
                {
                    for (k = 0; k < nhits; k++) if (hits[k] == pid) hit = TRUE;
                    if (!hit) hit = module_match(pid, targets, ntargets);
                    if (hit && !affected_has_pid(a, pid))
                    {
                        UINT before = a->count;
                        fill_process(a, &cap, &snap, pid, NULL);
                        if (a->count > before && !scm)
                            scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
                        if (scm && a->count > before && a->info[before].ApplicationType != RmCritical)
                            add_hosted_services(a, &cap, scm, pid);
                    }
                }
                if (!p->NextEntryOffset) break;
            }
        }
        HeapFree(GetProcessHeap(), 0, procs);
    }
services_done:
cleanup:
    if (probe != INVALID_HANDLE_VALUE) CloseHandle(probe);
    if (scm) CloseServiceHandle(scm);
    free_targets(targets, ntargets);
    HeapFree(GetProcessHeap(), 0, hits);
    free_string_array(files, nfiles);
    free_string_array(services, nservices);
    HeapFree(GetProcessHeap(), 0, apps);
    HeapFree(GetProcessHeap(), 0, snap.stopped);
    if (snap.filters)
    {
        for (i = 0; i < snap.nfilters; i++) HeapFree(GetProcessHeap(), 0, snap.filters[i].module);
        HeapFree(GetProcessHeap(), 0, snap.filters);
    }
    if (ret != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, a->info);
        memset(a, 0, sizeof(*a));
    }
    return ret;
}

/***********************************************************************
 * RmGetList (rstrtmgr.@)
 */
DWORD WINAPI RmGetList(DWORD handle, UINT *needed, UINT *count, RM_PROCESS_INFO apps[], LPDWORD reasons)
{
    SESSION *s;
    AFFECTED a;
    DWORD ret;
    UINT n;

    DPRINT("%lu, %p, %p, %p, %p\n", handle, needed, count, apps, reasons);

    EnterCriticalSection(&session_cs);
    s = get_session(handle);
    LeaveCriticalSection(&session_cs);
    if (!s) return ERROR_INVALID_HANDLE;
    if (!needed || !count || !reasons || (*count && !apps)) return ERROR_BAD_ARGUMENTS;

    if ((ret = build_list(s, &a)) != ERROR_SUCCESS) return ret;

    *needed = a.count;
    *reasons = a.reasons;
    if (*count >= a.count)
    {
        n = a.count;
        ret = ERROR_SUCCESS;
    }
    else
    {
        n = *count;
        ret = ERROR_MORE_DATA;
    }
    if (n) memcpy(apps, a.info, n * sizeof(*apps));
    *count = n;
    HeapFree(GetProcessHeap(), 0, a.info);
    return ret;
}

static void mark_stopped(DWORD handle, DWORD pid)
{
    SESSION *s;
    UINT cap;

    EnterCriticalSection(&session_cs);
    if ((s = get_session(handle)))
    {
        cap = s->nstopped;
        array_append((void **)&s->stopped, &s->nstopped, &cap, sizeof(DWORD), &pid);
    }
    LeaveCriticalSection(&session_cs);
}

typedef struct { DWORD pid; } CLOSE_CTX;

static BOOL CALLBACK close_window_proc(HWND hwnd, LPARAM lparam)
{
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == ((CLOSE_CTX *)lparam)->pid && IsWindowVisible(hwnd) && !GetWindow(hwnd, GW_OWNER))
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    return TRUE;
}

static BOOL stop_service(LPCWSTR name)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS st;
    BOOL ok = FALSE;
    UINT i;

    if (!(scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT))) return FALSE;
    if ((svc = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)))
    {
        if (ControlService(svc, SERVICE_CONTROL_STOP, &st) || GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
        {
            for (i = 0; i < 100; i++)
            {
                if (!QueryServiceStatus(svc, &st) || st.dwCurrentState == SERVICE_STOPPED) { ok = TRUE; break; }
                Sleep(100);
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return ok;
}

/***********************************************************************
 * RmShutdown (rstrtmgr.@)
 */
DWORD WINAPI RmShutdown(DWORD handle, ULONG flags, RM_WRITE_STATUS_CALLBACK status)
{
    SESSION *s;
    AFFECTED a;
    DWORD ret;
    UINT i;
    BOOL failed = FALSE;

    DPRINT("%lu, 0x%08lx, %p\n", handle, flags, status);

    EnterCriticalSection(&session_cs);
    s = get_session(handle);
    LeaveCriticalSection(&session_cs);
    if (!s) return ERROR_INVALID_HANDLE;

    if ((ret = build_list(s, &a)) != ERROR_SUCCESS) return ret;
    if (status) status(0);

    for (i = 0; i < a.count; i++)
    {
        RM_PROCESS_INFO *info = &a.info[i];
        DWORD pid = info->Process.dwProcessId;
        HANDLE proc;

        if (!(info->AppStatus & RM_STATUS_RUNNING) || (info->AppStatus & RM_STATUS_SHUTDOWN_MASK)) continue;
        if (info->ApplicationType == RmCritical)
        {
            failed = TRUE;
            continue;
        }
        if (info->ApplicationType == RmService)
        {
            if (stop_service(info->strServiceShortName)) mark_stopped(handle, pid);
            else failed = TRUE;
            continue;
        }

        proc = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, pid);
        if (!proc) { failed = TRUE; continue; }
        if (info->ApplicationType == RmMainWindow || info->ApplicationType == RmOtherWindow)
        {
            CLOSE_CTX ctx;
            ctx.pid = pid;
            EnumWindows(close_window_proc, (LPARAM)&ctx);
        }
        if (WaitForSingleObject(proc, 5000) != WAIT_OBJECT_0 && (flags & RM_FORCE_SHUTDOWN))
        {
            TerminateProcess(proc, 1);
            WaitForSingleObject(proc, 5000);
        }
        if (WaitForSingleObject(proc, 0) == WAIT_OBJECT_0) mark_stopped(handle, pid);
        else failed = TRUE;
        CloseHandle(proc);
    }
    HeapFree(GetProcessHeap(), 0, a.info);
    if (status) status(100);
    return failed ? ERROR_FAIL_SHUTDOWN : ERROR_SUCCESS;
}

/***********************************************************************
 * RmRestart (rstrtmgr.@)
 *
 * Nothing is restarted: the applications did not register restart commands
 * (RegisterApplicationRestart is not tracked).
 */
DWORD WINAPI RmRestart(DWORD handle, DWORD flags, RM_WRITE_STATUS_CALLBACK status)
{
    SESSION *s;
    DWORD ret = ERROR_SUCCESS;

    DPRINT("%lu, 0x%08lx, %p\n", handle, flags, status);

    EnterCriticalSection(&session_cs);
    if (!(s = get_session(handle))) ret = ERROR_INVALID_HANDLE;
    else
    {
        HeapFree(GetProcessHeap(), 0, s->stopped);
        s->stopped = NULL;
        s->nstopped = 0;
    }
    LeaveCriticalSection(&session_cs);
    if (ret == ERROR_SUCCESS && status)
    {
        status(0);
        status(100);
    }
    return ret;
}

/***********************************************************************
 * RmCancelCurrentTask (rstrtmgr.@)
 */
DWORD WINAPI RmCancelCurrentTask(DWORD handle)
{
    DWORD ret;

    DPRINT("%lu\n", handle);

    EnterCriticalSection(&session_cs);
    ret = get_session(handle) ? ERROR_SUCCESS : ERROR_INVALID_HANDLE;
    LeaveCriticalSection(&session_cs);
    return ret;
}

/***********************************************************************
 * RmAddFilter (rstrtmgr.@)
 */
DWORD WINAPI RmAddFilter(DWORD handle, LPCWSTR module, RM_UNIQUE_PROCESS *process, LPCWSTR service,
                         RM_FILTER_ACTION action)
{
    SESSION *s;
    FILTER f;
    UINT cap;
    DWORD ret = ERROR_SUCCESS;

    DPRINT("%lu, %S, %p, %S, 0x%08x\n", handle, module, process, service, action);

    EnterCriticalSection(&session_cs);
    if (!(s = get_session(handle))) ret = ERROR_INVALID_HANDLE;
    else if ((!module && !process && !service) || (action != RmNoRestart && action != RmNoShutdown))
        ret = ERROR_BAD_ARGUMENTS;
    else
    {
        memset(&f, 0, sizeof(f));
        f.action = action;
        if (module) f.module = dup_string(module);
        if (service) f.service = dup_string(service);
        if (process) f.pid = process->dwProcessId;
        cap = s->nfilters;
        if ((module && !f.module) || (service && !f.service) ||
            !array_append((void **)&s->filters, &s->nfilters, &cap, sizeof(f), &f))
        {
            HeapFree(GetProcessHeap(), 0, f.module);
            HeapFree(GetProcessHeap(), 0, f.service);
            ret = ERROR_OUTOFMEMORY;
        }
    }
    LeaveCriticalSection(&session_cs);
    return ret;
}

/***********************************************************************
 * RmRemoveFilter (rstrtmgr.@)
 */
DWORD WINAPI RmRemoveFilter(DWORD handle, LPCWSTR module, RM_UNIQUE_PROCESS *process, LPCWSTR service)
{
    SESSION *s;
    UINT i;
    DWORD ret = ERROR_SUCCESS;

    DPRINT("%lu, %S, %p, %S\n", handle, module, process, service);

    EnterCriticalSection(&session_cs);
    if (!(s = get_session(handle))) ret = ERROR_INVALID_HANDLE;
    else if (!module && !process && !service) ret = ERROR_BAD_ARGUMENTS;
    else
    {
        ret = ERROR_FILE_NOT_FOUND;
        for (i = 0; i < s->nfilters; i++)
        {
            FILTER *f = &s->filters[i];
            if ((module && (!f->module || lstrcmpiW(module, f->module))) ||
                (process && f->pid != process->dwProcessId) ||
                (service && (!f->service || lstrcmpiW(service, f->service)))) continue;
            HeapFree(GetProcessHeap(), 0, f->module);
            HeapFree(GetProcessHeap(), 0, f->service);
            memmove(f, f + 1, (s->nfilters - i - 1) * sizeof(*f));
            s->nfilters--;
            ret = ERROR_SUCCESS;
            break;
        }
    }
    LeaveCriticalSection(&session_cs);
    return ret;
}
