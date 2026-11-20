/* Avrt dll implementation
 *
 * Copyright (C) 2009 Maarten Lankhorst
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winerror.h"
#include "winnls.h"
#include "wine/debug.h"
#include "avrt.h"

WINE_DEFAULT_DEBUG_CHANNEL(avrt);

static inline WCHAR *strdupAW(const char *src)
{
    int len;
    WCHAR *dst;
    if (!src) return NULL;
    len = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if ((dst = malloc(len * sizeof(*dst)))) MultiByteToWideChar(CP_ACP, 0, src, -1, dst, len);
    return dst;
}

HANDLE WINAPI AvSetMmThreadCharacteristicsA(const char *name, DWORD *index)
{
    WCHAR *nameW = NULL;
    HANDLE ret;

    if (name && !(nameW = strdupAW(name)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    ret = AvSetMmThreadCharacteristicsW(nameW, index);

    free(nameW);
    return ret;
}

/*
 * The multimedia class scheduler, as far as a process can do it alone. Windows runs a service (MMCSS) that keeps the
 * task table and raises the priorities. We have no such service: the task table is the registry (the defaults are
 * written at installation), the registrations of a process are kept by this DLL, and only what a process can do for
 * its own thread is real. What is real and what is bookkeeping:
 *   real:        the task names, the validation of their registry values, the error codes, the task indexes (a counter
 *                of this process, Windows has one for the whole system), the handles, the revert of a thread's priority,
 *                AvQuerySystemResponsiveness (the registry value), the priority of a thread of a Low category task
 *                (AvSetMmThreadPriority sets it, revert restores it).
 *   bookkeeping: tasks of the Medium and High categories are accepted and counted but the thread keeps its priority:
 *                their priorities (16 and above) need a raise of the base priority above what SetThreadPriority does.
 * https://learn.microsoft.com/windows/win32/procthread/multimedia-class-scheduler-service
 */

#define TASKS_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile"

enum { CATEGORY_LOW, CATEGORY_MEDIUM, CATEGORY_HIGH };

typedef struct _TASK
{
    struct _TASK *Next;
    HANDLE Handle;
    DWORD ThreadId;
    HANDLE Thread;
    DWORD Index;
    WCHAR Name[MAX_PATH];
    int Category;
    DWORD Priority;
    int SavedPriority;
    BOOL Changed;
} TASK;

static CRITICAL_SECTION g_lock;
static TASK *g_tasks;
static DWORD g_next_index = 1;
static DWORD g_count;
#define REAP_AT 1024
static ULONG_PTR g_next_handle = 0x1000;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(instance);
        InitializeCriticalSection(&g_lock);
        break;
    case DLL_PROCESS_DETACH:
        if (!reserved)
            DeleteCriticalSection(&g_lock);
        break;
    }
    return TRUE;
}

/* The task of that name from the registry; FALSE when there is none or its values are not valid */
static BOOL read_task(const WCHAR *name, int *category, DWORD *priority)
{
    WCHAR path[MAX_PATH + 128];
    WCHAR text[32];
    HKEY key;
    DWORD type, size;

    if (!name || !name[0] || wcschr(name, L'\\') || wcslen(name) >= MAX_PATH)
        return FALSE;

    wcscpy(path, TASKS_KEY L"\\Tasks\\");
    wcscat(path, name);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &key))
        return FALSE;

    /* no category is the lowest one, no priority is 1 */
    *category = CATEGORY_LOW;
    size = sizeof(text) - sizeof(WCHAR);
    if (!RegQueryValueExW(key, L"Scheduling Category", NULL, &type, (BYTE *)text, &size))
    {
        if (type != REG_SZ)
        {
            RegCloseKey(key);
            return FALSE;
        }
        text[size / sizeof(WCHAR)] = 0;
        if (!_wcsicmp(text, L"High")) *category = CATEGORY_HIGH;
        else if (!_wcsicmp(text, L"Medium")) *category = CATEGORY_MEDIUM;
        else if (_wcsicmp(text, L"Low"))
        {
            RegCloseKey(key);
            return FALSE;
        }
    }

    *priority = 1;
    size = sizeof(DWORD);
    if (!RegQueryValueExW(key, L"Priority", NULL, &type, (BYTE *)priority, &size) && type != REG_DWORD)
        *priority = 0;
    RegCloseKey(key);

    return *priority >= 1 && *priority <= 8;
}

static TASK *find_by_handle(HANDLE handle)
{
    TASK *task;
    for (task = g_tasks; task; task = task->Next)
        if (task->Handle == handle) return task;
    return NULL;
}

static TASK *find_by_thread(DWORD thread_id)
{
    TASK *task;
    for (task = g_tasks; task; task = task->Next)
        if (task->ThreadId == thread_id) return task;
    return NULL;
}

/*
 * A thread that ends without a revert leaves its registration behind (Windows keeps the handle valid, the registration
 * is gone with the thread). A program that starts threads without ever reverting would grow this list for ever, so
 * once it is long the registrations of ended threads are dropped (a handle of theirs is then no longer known, which is
 * all the thread can still want from it). The caller holds g_lock.
 */
static void reap_ended(void)
{
    TASK **link = &g_tasks, *task;

    while ((task = *link) != NULL)
    {
        if (WaitForSingleObject(task->Thread, 0) == WAIT_OBJECT_0)
        {
            *link = task->Next;
            CloseHandle(task->Thread);
            free(task);
            g_count--;
        }
        else
            link = &task->Next;
    }
}

static HANDLE join_tasks(const WCHAR *name1, const WCHAR *name2, DWORD *index)
{
    int category1, category2, category;
    DWORD priority1, priority2, priority;
    const WCHAR *name;
    TASK *task, *existing, *member;
    DWORD shared_index = 0;
    DWORD thread_id = GetCurrentThreadId();

    if (!name1 || !index)
    {
        SetLastError(name1 ? ERROR_INVALID_PARAMETER : ERROR_INVALID_TASK_NAME);
        return NULL;
    }

    if (!read_task(name1, &category1, &priority1) || (name2 && !read_task(name2, &category2, &priority2)))
    {
        SetLastError(ERROR_INVALID_TASK_NAME);
        return NULL;
    }

    /* of two tasks the thread takes the one with the higher priority */
    name = name1;
    category = category1;
    priority = priority1;
    if (name2 && (category2 > category1 || (category2 == category1 && priority2 > priority1)))
    {
        name = name2;
        category = category2;
        priority = priority2;
    }

    EnterCriticalSection(&g_lock);
    existing = find_by_thread(thread_id);
    if (existing && WaitForSingleObject(existing->Thread, 0) == WAIT_OBJECT_0)
    {
        /* the thread that joined has ended without a revert (its handle stays valid until it is reverted, as in Windows)
         * and this thread has the identifier it left: not in a task */
        existing->ThreadId = 0;
        existing = NULL;
    }
    if (existing)
    {
        /* a thread is in one task at a time: asking again for the task it is in is refused as such, any other index is not its own */
        SetLastError((*index == 0 || (*index == existing->Index && !_wcsicmp(name1, existing->Name)))
                     ? ERROR_THREAD_ALREADY_IN_TASK : ERROR_INVALID_TASK_INDEX);
        LeaveCriticalSection(&g_lock);
        return NULL;
    }
    if (*index != 0)
    {
        /* a thread joins the task another thread is in by giving the index of that task and the name it was made with */
        for (member = g_tasks; member; member = member->Next)
            if (member->Index == *index && !_wcsicmp(member->Name, name) && WaitForSingleObject(member->Thread, 0) == WAIT_TIMEOUT)
                break;
        if (!member)
        {
            SetLastError(ERROR_INVALID_TASK_INDEX);
            LeaveCriticalSection(&g_lock);
            return NULL;
        }
        shared_index = member->Index; /* (the list may be trimmed below) */
    }

    if (g_count >= REAP_AT)
        reap_ended();
    task = calloc(1, sizeof(*task));
    if (task)
        task->Thread = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, thread_id);
    if (!task || !task->Thread)
    {
        if (task) free(task);
        SetLastError(ERROR_OUTOFMEMORY);
        LeaveCriticalSection(&g_lock);
        return NULL;
    }
    task->ThreadId = thread_id;
    task->Index = shared_index ? shared_index : g_next_index++;
    task->Handle = (HANDLE)g_next_handle;
    g_next_handle += 4;
    wcscpy(task->Name, name);
    task->Category = category;
    task->Priority = priority;
    task->SavedPriority = GetThreadPriority(task->Thread);
    task->Next = g_tasks;
    g_tasks = task;
    g_count++;
    *index = task->Index;
    LeaveCriticalSection(&g_lock);
    return task->Handle;
}

HANDLE WINAPI AvSetMmThreadCharacteristicsW(const WCHAR *name, DWORD *index)
{
    return join_tasks(name, NULL, index);
}

BOOL WINAPI AvQuerySystemResponsiveness(HANDLE AvrtHandle, ULONG *value)
{
    DWORD data = 20, size = sizeof(data), type;
    HKEY key;
    BOOL known;

    EnterCriticalSection(&g_lock);
    known = find_by_handle(AvrtHandle) != NULL;
    LeaveCriticalSection(&g_lock);
    if (!known)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    if (!value)
    {
        SetLastError(ERROR_NOACCESS);
        return FALSE;
    }

    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, TASKS_KEY, 0, KEY_QUERY_VALUE, &key))
    {
        if (RegQueryValueExW(key, L"SystemResponsiveness", NULL, &type, (BYTE *)&data, &size) || type != REG_DWORD)
            data = 20;
        RegCloseKey(key);
    }
    *value = data;
    return TRUE;
}

BOOL WINAPI AvRevertMmThreadCharacteristics(HANDLE AvrtHandle)
{
    TASK **link, *task = NULL;

    EnterCriticalSection(&g_lock);
    for (link = &g_tasks; *link; link = &(*link)->Next)
    {
        if ((*link)->Handle == AvrtHandle)
        {
            task = *link;
            *link = task->Next;
            g_count--;
            break;
        }
    }
    LeaveCriticalSection(&g_lock);

    if (!task)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (task->Changed)
        SetThreadPriority(task->Thread, task->SavedPriority);
    CloseHandle(task->Thread);
    free(task);
    return TRUE;
}

BOOL WINAPI AvSetMmThreadPriority(HANDLE AvrtHandle, AVRT_PRIORITY prio)
{
    TASK *task;
    BOOL ret = TRUE;

    EnterCriticalSection(&g_lock);
    task = find_by_handle(AvrtHandle);
    if (!task)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        ret = FALSE;
    }
    else if (prio < AVRT_PRIORITY_VERYLOW || prio > AVRT_PRIORITY_CRITICAL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        ret = FALSE;
    }
    else if (task->Category == CATEGORY_LOW)
    {
        /* a thread of a Low task runs at the requested priority relative to its process; the one it had is restored on revert */
        if (SetThreadPriority(task->Thread, (int)prio))
            task->Changed = TRUE;
    }
    LeaveCriticalSection(&g_lock);
    return ret;
}

HANDLE WINAPI AvSetMmMaxThreadCharacteristicsA(const char *task1, const char *task2, DWORD *index)
{
    WCHAR *task1W = NULL, *task2W = NULL;
    HANDLE ret;

    if (task1 && !(task1W = strdupAW(task1)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    if (task2 && !(task2W = strdupAW(task2)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    ret = AvSetMmMaxThreadCharacteristicsW(task1W, task2W, index);

    free(task2W);
    free(task1W);
    return ret;
}

HANDLE WINAPI AvSetMmMaxThreadCharacteristicsW(const WCHAR *task1, const WCHAR *task2, DWORD *index)
{
    return join_tasks(task1, task2, index);
}

/*
 * The thread ordering groups need the scheduler service. Windows Server 2022 refuses every call of them with
 * ERROR_SERVICE_DISABLED, whether the service runs or not (measured); they are not stubs that stop the process.
 */
BOOL WINAPI AvRtCreateThreadOrderingGroup(PHANDLE context, PLARGE_INTEGER period, GUID *guid, PLARGE_INTEGER timeout)
{
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
}

BOOL WINAPI AvRtCreateThreadOrderingGroupExA(PHANDLE context, PLARGE_INTEGER period, GUID *guid, PLARGE_INTEGER timeout, LPCSTR name)
{
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
}

BOOL WINAPI AvRtCreateThreadOrderingGroupExW(PHANDLE context, PLARGE_INTEGER period, GUID *guid, PLARGE_INTEGER timeout, LPCWSTR name)
{
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
}

BOOL WINAPI AvRtJoinThreadOrderingGroup(PHANDLE context, GUID *guid, BOOL before)
{
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
}

BOOL WINAPI AvRtWaitOnThreadOrderingGroup(HANDLE context)
{
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
}

BOOL WINAPI AvRtLeaveThreadOrderingGroup(HANDLE context)
{
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
}

BOOL WINAPI AvRtDeleteThreadOrderingGroup(HANDLE context)
{
    SetLastError(ERROR_SERVICE_DISABLED);
    return FALSE;
}
