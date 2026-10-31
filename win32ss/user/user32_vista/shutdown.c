/*
 * PROJECT:     ReactOS user32 - shutdown block reasons
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy and ShutdownBlockReasonQuery
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The reason of a window is kept in this process, in a list that is trimmed of destroyed
 * windows whenever one of the functions runs; nothing else on this system reads the reasons,
 * so a reason that is set only shows up in a query for the same window from this process.
 * Everything else was measured on Windows 10 22H2 (build 19045), x64 and x86:
 *  - an invalid window (also NULL) is ERROR_INVALID_WINDOW_HANDLE.
 *  - a reason can be set for a top-level window of this process, from any of its threads; a
 *    child window, a NULL reason and a reason of more than 256 characters are
 *    ERROR_INVALID_PARAMETER; an empty reason is a reason. A new reason replaces the old one.
 *  - for a window of another process (the desktop window is one) Create and Destroy do nothing
 *    and return 5 (the value of ERROR_ACCESS_DENIED) without setting an error.
 *  - Destroy and Query of a window without a reason are ERROR_INVALID_PARAMETER.
 *  - Query takes the size of the buffer in characters in *pcchBuff and returns the length of the
 *    reason with its terminator there, also when the buffer was too small: the text is then cut
 *    and still terminated (one character of buffer gives an empty string, zero is
 *    ERROR_INVALID_PARAMETER). Without a buffer the length is all that is returned, whatever
 *    the size says.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>

#define NDEBUG
#include <debug.h>

#define MAX_BLOCK_REASON 256

typedef struct _BLOCK_REASON
{
    struct _BLOCK_REASON *Next;
    HWND hWnd;
    DWORD Length;
    WCHAR Text[ANYSIZE_ARRAY];
} BLOCK_REASON, *PBLOCK_REASON;

static PBLOCK_REASON g_Reasons;
static CRITICAL_SECTION g_ReasonsLock;
static CRITICAL_SECTION_DEBUG g_ReasonsLockDebug =
{
    0, 0, &g_ReasonsLock,
    { &g_ReasonsLockDebug.ProcessLocksList, &g_ReasonsLockDebug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": g_ReasonsLock") }
};
static CRITICAL_SECTION g_ReasonsLock = { &g_ReasonsLockDebug, -1, 0, 0, 0, 0 };

/* Called with the lock held: drops the reasons of windows that are gone and returns the list
 * of the dropped ones, which the caller frees once the lock is released */
static PBLOCK_REASON
TrimReasons(VOID)
{
    PBLOCK_REASON *Link = &g_Reasons, Entry, Dead = NULL;

    while ((Entry = *Link) != NULL)
    {
        if (!IsWindow(Entry->hWnd))
        {
            *Link = Entry->Next;
            Entry->Next = Dead;
            Dead = Entry;
        }
        else
        {
            Link = &Entry->Next;
        }
    }
    return Dead;
}

static VOID
FreeReasons(PBLOCK_REASON List)
{
    PBLOCK_REASON Entry;

    while ((Entry = List) != NULL)
    {
        List = Entry->Next;
        HeapFree(GetProcessHeap(), 0, Entry);
    }
}

static PBLOCK_REASON *
FindReason(HWND hWnd)
{
    PBLOCK_REASON *Link;

    for (Link = &g_Reasons; *Link; Link = &(*Link)->Next)
    {
        if ((*Link)->hWnd == hWnd)
            return Link;
    }
    return NULL;
}

static BOOL
IsForeignWindow(HWND hWnd)
{
    DWORD Pid;

    GetWindowThreadProcessId(hWnd, &Pid);
    return hWnd == GetDesktopWindow() || Pid != GetCurrentProcessId();
}

BOOL
WINAPI
ShutdownBlockReasonCreate(
    _In_ HWND hWnd,
    _In_ LPCWSTR pwszReason)
{
    PBLOCK_REASON New, *Link, Old, Dead;
    DWORD Length = 0, Error;

    if (!IsWindow(hWnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }

    if (IsForeignWindow(hWnd))
        return (BOOL)ERROR_ACCESS_DENIED;

    if (!pwszReason || IsBadStringPtrW(pwszReason, MAX_BLOCK_REASON + 1) ||
        GetAncestor(hWnd, GA_PARENT) != GetDesktopWindow() ||
        (Length = lstrlenW(pwszReason)) > MAX_BLOCK_REASON)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    New = HeapAlloc(GetProcessHeap(), 0, sizeof(*New) + Length * sizeof(WCHAR));
    if (!New)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
    New->hWnd = hWnd;
    New->Length = Length;
    CopyMemory(New->Text, pwszReason, Length * sizeof(WCHAR));
    New->Text[Length] = UNICODE_NULL;

    Error = GetLastError();
    EnterCriticalSection(&g_ReasonsLock);
    Dead = TrimReasons();
    Link = FindReason(hWnd);
    if (Link)
    {
        Old = *Link;
        New->Next = Old->Next;
        *Link = New;
        Old->Next = Dead;
        Dead = Old;
    }
    else
    {
        New->Next = g_Reasons;
        g_Reasons = New;
    }
    LeaveCriticalSection(&g_ReasonsLock);
    FreeReasons(Dead);
    SetLastError(Error);
    return TRUE;
}

BOOL
WINAPI
ShutdownBlockReasonDestroy(
    _In_ HWND hWnd)
{
    PBLOCK_REASON *Link, Dead;
    DWORD Error;
    BOOL Found = FALSE;

    if (!IsWindow(hWnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }
    if (IsForeignWindow(hWnd))
        return (BOOL)ERROR_ACCESS_DENIED;

    Error = GetLastError();
    EnterCriticalSection(&g_ReasonsLock);
    Dead = TrimReasons();
    Link = FindReason(hWnd);
    if (Link)
    {
        PBLOCK_REASON Entry = *Link;

        *Link = Entry->Next;
        Entry->Next = Dead;
        Dead = Entry;
        Found = TRUE;
    }
    LeaveCriticalSection(&g_ReasonsLock);
    FreeReasons(Dead);

    if (!Found)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    SetLastError(Error);
    return TRUE;
}

BOOL
WINAPI
ShutdownBlockReasonQuery(
    _In_ HWND hWnd,
    _Out_writes_opt_(*pcchBuff) LPWSTR pwszBuff,
    _Inout_ DWORD *pcchBuff)
{
    PBLOCK_REASON *Link, Dead;
    DWORD Error, Size, Length = 0, Copy;
    BOOL Ret = FALSE;

    if (!pcchBuff || IsBadWritePtr(pcchBuff, sizeof(*pcchBuff)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!IsWindow(hWnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }

    Size = *pcchBuff;
    if (pwszBuff && (Size == 0 || IsBadWritePtr(pwszBuff, (Size < MAX_BLOCK_REASON + 1 ? Size : MAX_BLOCK_REASON + 1) * sizeof(WCHAR))))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Error = GetLastError();
    EnterCriticalSection(&g_ReasonsLock);
    Dead = TrimReasons();
    Link = FindReason(hWnd);
    if (Link)
    {
        Length = (*Link)->Length;
        if (pwszBuff)
        {
            Copy = Length < Size - 1 ? Length : Size - 1;
            CopyMemory(pwszBuff, (*Link)->Text, Copy * sizeof(WCHAR));
            pwszBuff[Copy] = UNICODE_NULL;
        }
        Ret = TRUE;
    }
    LeaveCriticalSection(&g_ReasonsLock);
    FreeReasons(Dead);

    if (!Ret)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *pcchBuff = Length + 1;
    SetLastError(Error);
    return TRUE;
}
