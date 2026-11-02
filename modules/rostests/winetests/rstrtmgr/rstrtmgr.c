/*
 * Unit test suite for the Restart Manager (rstrtmgr.dll)
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

#include <stdarg.h>
#include <stdio.h>

#include "windef.h"
#include "winbase.h"
#ifdef RM_ORACLE_BUILD
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#endif
#include "winerror.h"
#include "winuser.h"
#include "restartmanager.h"

#ifdef RM_ORACLE_BUILD
#include "shim.h"
#else
#include "wine/test.h"
#endif

#define KEYLEN (CCH_RM_SESSION_KEY + 1)

static void test_session(void)
{
    WCHAR key[KEYLEN], key2[KEYLEN];
    DWORD h, h2, ret;
    UINT i;

    h = 0xdeadbeef;
    memset(key, 0xcc, sizeof(key));
    ret = RmStartSession(&h, 0, key);
    ok(ret == ERROR_SUCCESS, "RmStartSession returned %lu\n", ret);
    if (ret != ERROR_SUCCESS) return;
    ok(h != 0xdeadbeef, "no session handle returned\n");
    ok(lstrlenW(key) == CCH_RM_SESSION_KEY, "key length %d\n", lstrlenW(key));
    for (i = 0; i < CCH_RM_SESSION_KEY; i++)
        ok((key[i] >= '0' && key[i] <= '9') || (key[i] >= 'A' && key[i] <= 'F') || (key[i] >= 'a' && key[i] <= 'f'),
           "key[%u] = %#x is not a hex digit\n", i, key[i]);

    ret = RmStartSession(&h2, 0, key2);
    ok(ret == ERROR_SUCCESS, "second RmStartSession returned %lu\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        ok(h2 != h, "two sessions got the same handle %lu\n", h);
        ok(lstrcmpW(key, key2), "two sessions got the same key\n");
        ret = RmEndSession(h2);
        ok(ret == ERROR_SUCCESS, "RmEndSession returned %lu\n", ret);
    }

    ret = RmEndSession(h);
    ok(ret == ERROR_SUCCESS, "RmEndSession returned %lu\n", ret);
    ret = RmEndSession(h);
    ok(ret == ERROR_INVALID_HANDLE, "RmEndSession of an ended session returned %lu\n", ret);
    ret = RmEndSession(0xdeadbeef);
    ok(ret == ERROR_INVALID_HANDLE, "RmEndSession of a bogus handle returned %lu\n", ret);

    ret = RmGetList(h, NULL, NULL, NULL, NULL);
    ok(ret == ERROR_INVALID_HANDLE, "RmGetList of an ended session returned %lu\n", ret);
    ret = RmRegisterResources(h, 0, NULL, 0, NULL, 0, NULL);
    ok(ret == ERROR_INVALID_HANDLE, "RmRegisterResources of an ended session returned %lu\n", ret);
    ret = RmShutdown(h, 0, NULL);
    ok(ret == ERROR_INVALID_HANDLE, "RmShutdown of an ended session returned %lu\n", ret);
    ret = RmRestart(h, 0, NULL);
    ok(ret == ERROR_INVALID_HANDLE, "RmRestart of an ended session returned %lu\n", ret);
    ret = RmAddFilter(h, L"a.exe", NULL, NULL, RmNoRestart);
    ok(ret == ERROR_INVALID_HANDLE, "RmAddFilter of an ended session returned %lu\n", ret);
}

static void test_sessions_many(void)
{
    WCHAR key[KEYLEN];
    DWORD h[80], ret;
    int n = 0, i;

    for (i = 0; i < 80; i++)
    {
        ret = RmStartSession(&h[n], 0, key);
        if (ret != ERROR_SUCCESS) break;
        n++;
    }
    trace("%d sessions started, then %lu\n", n, ret);
    ok(n == 64 && ret == ERROR_MAX_SESSIONS_REACHED, "started %d sessions, last error %lu\n", n, ret);
    for (i = 0; i < n; i++) RmEndSession(h[i]);
    ret = RmStartSession(&h[0], 0, key);
    ok(ret == ERROR_SUCCESS, "RmStartSession after releasing the sessions returned %lu\n", ret);
    RmEndSession(h[0]);
}

static void test_getlist_empty(void)
{
    WCHAR key[KEYLEN];
    UINT needed, count;
    DWORD h, reasons, ret;
    RM_PROCESS_INFO info[4];

    ret = RmStartSession(&h, 0, key);
    ok(ret == ERROR_SUCCESS, "RmStartSession returned %lu\n", ret);
    if (ret != ERROR_SUCCESS) return;

    needed = 0xdead; count = 0; reasons = 0xdead;
    ret = RmGetList(h, &needed, &count, NULL, &reasons);
    ok(ret == ERROR_SUCCESS, "RmGetList of an empty session returned %lu\n", ret);
    ok(needed == 0, "needed = %u\n", needed);
    ok(count == 0, "count = %u\n", count);
    ok(reasons == RmRebootReasonNone, "reasons = %#lx\n", reasons);

    needed = 0xdead; count = 4; reasons = 0xdead;
    ret = RmGetList(h, &needed, &count, info, &reasons);
    ok(ret == ERROR_SUCCESS, "RmGetList returned %lu\n", ret);
    ok(needed == 0 && count == 0, "needed %u count %u\n", needed, count);

    ret = RmRegisterResources(h, 0, NULL, 0, NULL, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources with nothing returned %lu\n", ret);

    ret = RmShutdown(h, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmShutdown of an empty session returned %lu\n", ret);
    ret = RmRestart(h, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRestart of an empty session returned %lu\n", ret);
    ret = RmAddFilter(h, L"a.exe", NULL, NULL, RmNoRestart);
    ok(ret == ERROR_SUCCESS, "RmAddFilter returned %lu\n", ret);
    ret = RmRemoveFilter(h, L"a.exe", NULL, NULL);
    ok(ret == ERROR_SUCCESS, "RmRemoveFilter returned %lu\n", ret);

    RmEndSession(h);
}

static BOOL start_child(PROCESS_INFORMATION *pi, WCHAR *path, DWORD path_size);

static void test_nonexistent_file(void)
{
    static const WCHAR *files[] = { L"C:\\nonexistent-rstrtmgr-test\\file.dll" };
    WCHAR key[KEYLEN];
    UINT needed, count;
    DWORD h, reasons, ret;

    ret = RmStartSession(&h, 0, key);
    if (ret != ERROR_SUCCESS) return;
    ret = RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources of a missing file returned %lu\n", ret);
    needed = 0xdead; count = 0; reasons = 0xdead;
    ret = RmGetList(h, &needed, &count, NULL, &reasons);
    ok(ret == ERROR_SUCCESS, "RmGetList returned %lu\n", ret);
    ok(needed == 0, "needed = %u\n", needed);
    ok(reasons == RmRebootReasonNone, "reasons = %#lx\n", reasons);
    RmEndSession(h);
}

static BOOL start_child(PROCESS_INFORMATION *pi, WCHAR *path, DWORD path_size)
{
    WCHAR cmd[MAX_PATH + 40], dir[MAX_PATH];
    STARTUPINFOW si = { sizeof(si) };

    GetSystemDirectoryW(dir, MAX_PATH);
    lstrcpyW(path, dir);
    lstrcatW(path, L"\\ping.exe");
    lstrcpyW(cmd, L"\"");
    lstrcatW(cmd, path);
    lstrcatW(cmd, L"\" -n 30 127.0.0.1");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    return CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, pi);
}

static void test_module_in_use(void)
{
    WCHAR key[KEYLEN], path[MAX_PATH], selfpath[MAX_PATH];
    PROCESS_INFORMATION pi;
    RM_PROCESS_INFO info[8];
    const WCHAR *files[1];
    UINT needed, count, i;
    DWORD h, reasons, ret;
    BOOL found;

    if (!start_child(&pi, path, MAX_PATH))
    {
        skip("cannot start ping.exe: %lu\n", GetLastError());
        return;
    }
    Sleep(1000);

    ret = RmStartSession(&h, 0, key);
    ok(ret == ERROR_SUCCESS, "RmStartSession returned %lu\n", ret);
    if (ret != ERROR_SUCCESS) goto done;

    files[0] = path;
    ret = RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);

    needed = 0; count = 0; reasons = 0xdead;
    ret = RmGetList(h, &needed, &count, NULL, &reasons);
    ok(ret == ERROR_MORE_DATA, "RmGetList with no buffer returned %lu\n", ret);
    ok(needed >= 1, "needed = %u\n", needed);
    trace("needed %u reasons %#lx\n", needed, reasons);

    if (ret == ERROR_MORE_DATA && needed >= 1 && needed <= ARRAY_SIZE(info))
    {
        count = needed - 1;
        ret = RmGetList(h, &needed, &count, info, &reasons);
        if (needed > 1)
            ok(ret == ERROR_MORE_DATA, "RmGetList with a small buffer returned %lu\n", ret);

        count = needed;
        memset(info, 0xcc, sizeof(info));
        ret = RmGetList(h, &needed, &count, info, &reasons);
        ok(ret == ERROR_SUCCESS, "RmGetList returned %lu\n", ret);
        ok(count == needed, "count %u needed %u\n", count, needed);
        found = FALSE;
        for (i = 0; i < count; i++)
        {
            trace("[%u] pid %lu '%ls' svc '%ls' type %d status %#lx session %lu restartable %d\n", i,
                  info[i].Process.dwProcessId, info[i].strAppName, info[i].strServiceShortName,
                  info[i].ApplicationType, info[i].AppStatus, info[i].TSSessionId, info[i].bRestartable);
            if (info[i].Process.dwProcessId == pi.dwProcessId)
            {
                FILETIME c, e, k, u;
                found = TRUE;
                GetProcessTimes(pi.hProcess, &c, &e, &k, &u);
                ok(info[i].Process.ProcessStartTime.dwLowDateTime == c.dwLowDateTime &&
                   info[i].Process.ProcessStartTime.dwHighDateTime == c.dwHighDateTime,
                   "start time mismatch\n");
                ok(info[i].strAppName[0], "empty app name\n");
                ok(info[i].AppStatus == RmStatusRunning, "AppStatus %#lx\n", info[i].AppStatus);
                ok(info[i].ApplicationType == RmConsole, "type %d\n", info[i].ApplicationType);
            }
        }
        ok(found, "the process %lu that runs %ls was not listed\n", pi.dwProcessId, path);
    }

    /* the calling process is not in the list of the registered child */
    if (GetModuleFileNameW(NULL, selfpath, MAX_PATH))
    {
        files[0] = selfpath;
        ret = RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
        ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
        needed = 0; count = 0; reasons = 0;
        ret = RmGetList(h, &needed, &count, NULL, &reasons);
        ok(ret == ERROR_MORE_DATA, "RmGetList returned %lu\n", ret);
        ok(needed == 2, "needed = %u (the child and this process)\n", needed);
        ok(reasons & RmRebootReasonDetectedSelf, "reasons = %#lx\n", reasons);
    }

    RmEndSession(h);
done:
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

static void test_application(void)
{
    WCHAR key[KEYLEN], path[MAX_PATH];
    PROCESS_INFORMATION pi;
    RM_UNIQUE_PROCESS app;
    RM_PROCESS_INFO info[8];
    FILETIME c, e, k, u;
    UINT needed, count;
    DWORD h, reasons, ret;

    if (!start_child(&pi, path, MAX_PATH))
    {
        skip("cannot start ping.exe: %lu\n", GetLastError());
        return;
    }
    Sleep(500);
    GetProcessTimes(pi.hProcess, &c, &e, &k, &u);
    app.dwProcessId = pi.dwProcessId;
    app.ProcessStartTime = c;

    ret = RmStartSession(&h, 0, key);
    ok(ret == ERROR_SUCCESS, "RmStartSession returned %lu\n", ret);
    if (ret != ERROR_SUCCESS) goto done;

    ret = RmRegisterResources(h, 0, NULL, 1, &app, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
    needed = 0; count = 0; reasons = 0xdead;
    ret = RmGetList(h, &needed, &count, NULL, &reasons);
    ok(ret == ERROR_MORE_DATA, "RmGetList returned %lu\n", ret);
    ok(needed == 1, "needed = %u\n", needed);
    if (ret == ERROR_MORE_DATA && needed == 1)
    {
        count = 1;
        memset(info, 0, sizeof(info));
        ret = RmGetList(h, &needed, &count, info, &reasons);
        ok(ret == ERROR_SUCCESS, "RmGetList returned %lu\n", ret);
        ok(info[0].Process.dwProcessId == pi.dwProcessId, "pid %lu\n", info[0].Process.dwProcessId);
        ok(info[0].strAppName[0], "empty app name\n");
        ok(info[0].ApplicationType == RmConsole, "type %d\n", info[0].ApplicationType);
        ok(info[0].AppStatus == RmStatusRunning, "status %#lx\n", info[0].AppStatus);
        ok(!info[0].bRestartable, "restartable\n");
        trace("app: '%ls' type %d status %#lx restartable %d\n", info[0].strAppName,
              info[0].ApplicationType, info[0].AppStatus, info[0].bRestartable);
    }
    RmEndSession(h);

    /* Windows 10 does not compare the start time: a changed one is still listed */
    ret = RmStartSession(&h, 0, key);
    if (ret == ERROR_SUCCESS)
    {
        app.ProcessStartTime.dwHighDateTime ^= 1;
        ret = RmRegisterResources(h, 0, NULL, 1, &app, 0, NULL);
        ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
        needed = 0; count = 0;
        ret = RmGetList(h, &needed, &count, NULL, &reasons);
        ok(ret == ERROR_MORE_DATA && needed == 1, "stale start time: RmGetList returned %lu, needed %u\n", ret, needed);
        RmEndSession(h);
    }
done:
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

static void test_args(void)
{
    WCHAR key[KEYLEN];
    DWORD h, ret, reasons;
    UINT needed, count;
    RM_PROCESS_INFO info;
    RM_UNIQUE_PROCESS app;

    ret = RmStartSession(NULL, 0, key);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmStartSession(NULL handle) returned %lu\n", ret);
    ret = RmStartSession(&h, 0, NULL);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmStartSession(NULL key) returned %lu\n", ret);
    ret = RmStartSession(&h, 1, key);
    ok(ret == ERROR_SUCCESS, "RmStartSession(flags 1) returned %lu\n", ret);
    if (!ret) RmEndSession(h);

    /* the handle is checked before the other arguments */
    ret = RmRegisterResources(0x1234, 1, NULL, 0, NULL, 0, NULL);
    ok(ret == ERROR_INVALID_HANDLE, "RmRegisterResources returned %lu\n", ret);
    ret = RmGetList(0x1234, NULL, NULL, NULL, NULL);
    ok(ret == ERROR_INVALID_HANDLE, "RmGetList returned %lu\n", ret);
    ret = RmAddFilter(0x1234, NULL, NULL, NULL, RmNoRestart);
    ok(ret == ERROR_INVALID_HANDLE, "RmAddFilter returned %lu\n", ret);

    ret = RmStartSession(&h, 0, key);
    if (ret != ERROR_SUCCESS) return;
    ret = RmRegisterResources(h, 1, NULL, 0, NULL, 0, NULL);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmRegisterResources(1 file, NULL array) returned %lu\n", ret);
    ret = RmRegisterResources(h, 0, NULL, 1, NULL, 0, NULL);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmRegisterResources(1 app, NULL array) returned %lu\n", ret);
    ret = RmRegisterResources(h, 0, NULL, 0, NULL, 1, NULL);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmRegisterResources(1 service, NULL array) returned %lu\n", ret);
    ret = RmRegisterResources(h, 1, (const WCHAR *[]){ NULL }, 0, NULL, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources(NULL file name) returned %lu\n", ret);
    ret = RmRegisterResources(h, 1, (const WCHAR *[]){ L"" }, 0, NULL, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources(empty file name) returned %lu\n", ret);

    needed = count = 0;
    ret = RmGetList(h, NULL, &count, NULL, &reasons);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmGetList(NULL needed) returned %lu\n", ret);
    ret = RmGetList(h, &needed, NULL, NULL, &reasons);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmGetList(NULL count) returned %lu\n", ret);
    ret = RmGetList(h, &needed, &count, NULL, NULL);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmGetList(NULL reasons) returned %lu\n", ret);
    count = 1;
    ret = RmGetList(h, &needed, &count, NULL, &reasons);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmGetList(count 1, NULL array) returned %lu\n", ret);
    ret = RmGetList(h, NULL, NULL, NULL, NULL);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmGetList(all NULL) returned %lu\n", ret);

    ret = RmShutdown(h, 0x80, NULL);
    ok(ret == ERROR_SUCCESS, "RmShutdown(bad flags) returned %lu\n", ret);
    ret = RmRestart(h, 1, NULL);
    ok(ret == ERROR_SUCCESS, "RmRestart(flags 1) returned %lu\n", ret);

    ret = RmAddFilter(h, NULL, NULL, NULL, RmNoRestart);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmAddFilter(nothing) returned %lu\n", ret);
    ret = RmAddFilter(h, L"a.exe", NULL, NULL, RmInvalidFilterAction);
    ok(ret == ERROR_BAD_ARGUMENTS, "RmAddFilter(invalid action) returned %lu\n", ret);
    ret = RmRemoveFilter(h, L"a.exe", NULL, NULL);
    ok(ret == ERROR_FILE_NOT_FOUND, "RmRemoveFilter of a missing filter returned %lu\n", ret);
    ret = RmAddFilter(h, L"a.exe", NULL, NULL, RmNoRestart);
    ok(ret == ERROR_SUCCESS, "RmAddFilter returned %lu\n", ret);
    ret = RmRemoveFilter(h, L"a.exe", NULL, NULL);
    ok(ret == ERROR_SUCCESS, "RmRemoveFilter returned %lu\n", ret);
    ret = RmRemoveFilter(h, L"a.exe", NULL, NULL);
    ok(ret == ERROR_FILE_NOT_FOUND, "RmRemoveFilter of a removed filter returned %lu\n", ret);

    /* an application that does not exist is listed, with no name and no session */
    memset(&app, 0, sizeof(app));
    app.dwProcessId = 0x7ff0;
    RmEndSession(h);
    ret = RmStartSession(&h, 0, key);
    if (ret != ERROR_SUCCESS) return;
    ret = RmRegisterResources(h, 0, NULL, 1, &app, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
    needed = 0; count = 1;
    memset(&info, 0xcc, sizeof(info));
    ret = RmGetList(h, &needed, &count, &info, &reasons);
    ok(ret == ERROR_SUCCESS && needed == 1 && count == 1, "RmGetList returned %lu, needed %u count %u\n", ret, needed, count);
    if (ret == ERROR_SUCCESS && count == 1)
    {
        ok(info.Process.dwProcessId == 0x7ff0, "pid %lu\n", info.Process.dwProcessId);
        ok(!info.strAppName[0], "name '%ls'\n", info.strAppName);
        ok(info.ApplicationType == RmUnknownApp, "type %d\n", info.ApplicationType);
        ok(info.AppStatus == RmStatusStoppedOther, "status %#lx\n", info.AppStatus);
        ok(info.TSSessionId == ~0u, "session %lu\n", info.TSSessionId);
        ok(!info.bRestartable, "restartable\n");
    }
    RmEndSession(h);
}

static void test_path_forms(void)
{
    WCHAR key[KEYLEN], path[MAX_PATH], alt[MAX_PATH], shortp[MAX_PATH];
    PROCESS_INFORMATION pi;
    const WCHAR *files[1];
    UINT needed, count, i;
    DWORD h, reasons, ret;

    if (!start_child(&pi, path, MAX_PATH))
    {
        skip("cannot start ping.exe: %lu\n", GetLastError());
        return;
    }
    Sleep(1000);

    /* upper case, forward slashes and the short name find the same process */
    lstrcpyW(alt, path);
    CharUpperW(alt);
    for (i = 0; i < 3; i++)
    {
        if (i == 1)
        {
            lstrcpyW(alt, path);
            for (count = 0; alt[count]; count++) if (alt[count] == '\\') alt[count] = '/';
        }
        else if (i == 2)
        {
            if (!GetShortPathNameW(path, shortp, MAX_PATH)) break;
            lstrcpyW(alt, shortp);
        }
        ret = RmStartSession(&h, 0, key);
        ok(ret == ERROR_SUCCESS, "RmStartSession returned %lu\n", ret);
        if (ret != ERROR_SUCCESS) break;
        files[0] = alt;
        ret = RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
        ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
        needed = 0; count = 0;
        ret = RmGetList(h, &needed, &count, NULL, &reasons);
        ok(ret == ERROR_MORE_DATA && needed == 1, "form %u (%ls): RmGetList returned %lu, needed %u\n", i, alt, ret, needed);
        RmEndSession(h);
    }

    /* a relative name never matches */
    ret = RmStartSession(&h, 0, key);
    if (ret == ERROR_SUCCESS)
    {
        files[0] = L"ping.exe";
        ret = RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
        ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
        needed = 0xdead; count = 0;
        ret = RmGetList(h, &needed, &count, NULL, &reasons);
        ok(ret == ERROR_SUCCESS && needed == 0, "relative name: RmGetList returned %lu, needed %u\n", ret, needed);
        RmEndSession(h);
    }

    /* a directory cannot be queried */
    ret = RmStartSession(&h, 0, key);
    if (ret == ERROR_SUCCESS)
    {
        GetSystemDirectoryW(alt, MAX_PATH);
        files[0] = alt;
        ret = RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
        ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
        needed = 0; count = 0;
        ret = RmGetList(h, &needed, &count, NULL, &reasons);
        ok(ret == ERROR_ACCESS_DENIED, "directory: RmGetList returned %lu\n", ret);
        RmEndSession(h);
    }

    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

/* WoW64 callers of ReactOS get STATUS_NOT_SUPPORTED for the class */
static BOOL handle_info_supported(void)
{
    LONG (WINAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    ULONG len;
    char buf[64];
    LONG status;

    pNtQuerySystemInformation = (void *)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQuerySystemInformation) return FALSE;
    status = pNtQuerySystemInformation(64 /* SystemExtendedHandleInformation */, buf, sizeof(buf), &len);
    return status == 0 || status == (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */;
}

static void test_open_handle(void)
{
    WCHAR key[KEYLEN], path[MAX_PATH];
    RM_PROCESS_INFO info[4];
    const WCHAR *files[1];
    UINT needed, count, i;
    DWORD h, reasons, ret;
    HANDLE file;
    BOOL found;

    if (!handle_info_supported())
    {
        skip("the open handles of the system cannot be listed\n");
        return;
    }

    GetTempPathW(MAX_PATH, path);
    lstrcatW(path, L"rmtest.tmp");
    file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "CreateFile failed: %lu\n", GetLastError());
    if (file == INVALID_HANDLE_VALUE) return;

    ret = RmStartSession(&h, 0, key);
    ok(ret == ERROR_SUCCESS, "RmStartSession returned %lu\n", ret);
    if (ret != ERROR_SUCCESS) goto done;
    files[0] = path;
    ret = RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
    needed = 0; count = 0; reasons = 0;
    ret = RmGetList(h, &needed, &count, NULL, &reasons);
    ok(ret == ERROR_MORE_DATA, "RmGetList returned %lu\n", ret);
    ok(needed == 1, "needed = %u\n", needed);
    ok(reasons == RmRebootReasonDetectedSelf, "reasons = %#lx\n", reasons);
    if (ret == ERROR_MORE_DATA && needed == 1)
    {
        count = 4;
        ret = RmGetList(h, &needed, &count, info, &reasons);
        ok(ret == ERROR_SUCCESS && count == 1, "RmGetList returned %lu, count %u\n", ret, count);
        found = FALSE;
        for (i = 0; i < count; i++)
            if (info[i].Process.dwProcessId == GetCurrentProcessId())
            {
                found = TRUE;
                /* the calling process is reported as critical: it cannot be restarted */
                ok(info[i].ApplicationType == RmCritical, "type %d\n", info[i].ApplicationType);
                ok(info[i].AppStatus == RmStatusRunning, "status %#lx\n", info[i].AppStatus);
                ok(!info[i].bRestartable, "restartable\n");
            }
        ok(found, "the process that holds the file was not listed\n");
    }
    RmEndSession(h);

    /* the file is released: nobody holds it */
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    ret = RmStartSession(&h, 0, key);
    if (ret == ERROR_SUCCESS)
    {
        RmRegisterResources(h, 1, files, 0, NULL, 0, NULL);
        needed = 0xdead; count = 0;
        ret = RmGetList(h, &needed, &count, NULL, &reasons);
        ok(ret == ERROR_SUCCESS && needed == 0, "RmGetList of a closed file returned %lu, needed %u\n", ret, needed);
        RmEndSession(h);
    }
done:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    DeleteFileW(path);
}

static void test_service(void)
{
    static const WCHAR *missing[] = { L"NoSuchSvcXyz" };
    WCHAR key[KEYLEN];
    RM_PROCESS_INFO info;
    UINT needed, count;
    DWORD h, reasons, ret;

    ret = RmStartSession(&h, 0, key);
    if (ret != ERROR_SUCCESS) return;
    ret = RmRegisterResources(h, 0, NULL, 0, NULL, 1, missing);
    ok(ret == ERROR_SUCCESS, "RmRegisterResources returned %lu\n", ret);
    needed = 0; count = 1;
    memset(&info, 0, sizeof(info));
    ret = RmGetList(h, &needed, &count, &info, &reasons);
    ok(ret == ERROR_SUCCESS && needed == 1 && count == 1, "RmGetList returned %lu, needed %u count %u\n", ret, needed, count);
    if (ret == ERROR_SUCCESS && count == 1)
    {
        ok(info.ApplicationType == RmService, "type %d\n", info.ApplicationType);
        ok(!lstrcmpW(info.strServiceShortName, L"NoSuchSvcXyz"), "service '%ls'\n", info.strServiceShortName);
        ok(info.Process.dwProcessId == 0, "pid %lu\n", info.Process.dwProcessId);
        ok(info.AppStatus == RmStatusStoppedOther, "status %#lx\n", info.AppStatus);
        ok(info.bRestartable, "not restartable\n");
    }
    RmEndSession(h);
}

START_TEST(rstrtmgr)
{
    test_session();
    test_sessions_many();
    test_getlist_empty();
    test_nonexistent_file();
    test_module_in_use();
    test_application();
    test_args();
    test_path_forms();
    test_open_handle();
    test_service();
#ifdef RM_ORACLE_BUILD
    printf("ok %d fail %d skip %d\n", g_ok, g_fail, g_skip);
    return g_fail != 0;
#endif
}
