/*
 * PROJECT:     ReactOS Kernel - Vista+ APIs
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DPI functions for user32 and user32_vista.
 * COPYRIGHT:   Copyright 2024 Carl Bialorucki <cbialo2@outlook.com>
 *              Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The values of the awareness contexts and the way a thread and a process hold one follow
 * Wine's win32u (dlls/win32u/sysparams.c, window.c: Copyright 1994 Alexandre Julliard,
 * 2019 Zhiyi Zhang for CodeWeavers, 2021 Jacek Caban for CodeWeavers; LGPL-2.1-or-later).
 * Where Windows 10 answers differently, the answers were measured on Windows 10 22H2.
 *
 * ReactOS has one DPI for the whole system and does not scale for a process. The awareness
 * is therefore only state: it is kept in user mode, per process and per thread, and nothing
 * rescales on it. Every function returns the DPI that the display driver gives GDI, also for
 * a DPI-unaware process (Windows would say 96), so that these functions agree with
 * GetDeviceCaps. The awareness of another process and the awareness of a window that another
 * process created are not known here.
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

HDC APIENTRY
NtUserGetDC(HWND hWnd);

#define USER_DEFAULT_SCREEN_DPI_ 96
#define STATUS_BUFFER_TOO_SMALL_ ((LONG)0xC0000023)

/* A context as Windows hands it out: awareness in bits 0-3, version in bits 4-7, DPI in bits 8-16 */
#define DPICTX_AWARENESS(ctx)   ((ctx) & 0x0f)
#define DPICTX_VERSION(ctx)     (((ctx) & 0xf0) >> 4)
#define DPICTX_DPI(ctx)         (((ctx) & 0x1ff00) >> 8)
#define DPICTX_FLAGS(ctx)       ((ctx) & 0xfffe0000)
#define DPICTX_FLAG_GDISCALED   0x40000000
#define DPICTX_FLAG_PROCESS     0x80000000
#define DPICTX_FLAGS_VALID      (DPICTX_FLAG_PROCESS | DPICTX_FLAG_GDISCALED)
#define MAKE_DPICTX(awareness, version, dpi, flags) ((awareness) | ((version) << 4) | ((dpi) << 8) | (flags))

#define DPICTX_UNAWARE          MAKE_DPICTX(DPI_AWARENESS_UNAWARE, 1, USER_DEFAULT_SCREEN_DPI_, 0)
#define DPICTX_SYSTEM_AWARE(d)  MAKE_DPICTX(DPI_AWARENESS_SYSTEM_AWARE, 1, (d), 0)
#define DPICTX_PER_MONITOR      MAKE_DPICTX(DPI_AWARENESS_PER_MONITOR_AWARE, 1, 0, 0)
#define DPICTX_PER_MONITOR_V2   MAKE_DPICTX(DPI_AWARENESS_PER_MONITOR_AWARE, 2, 0, 0)
#define DPICTX_UNAWARE_GDI      MAKE_DPICTX(DPI_AWARENESS_UNAWARE, 1, USER_DEFAULT_SCREEN_DPI_, DPICTX_FLAG_GDISCALED)

#define DPI_HOSTING_BEHAVIOR_INVALID_ (-1)
#define DPI_HOSTING_BEHAVIOR_DEFAULT_ 0
#define DPI_HOSTING_BEHAVIOR_MIXED_   1

int WINAPI GetThreadDpiHostingBehavior(VOID);

/* The awareness of the process: 0 until it is set (or read from the manifest) */
static LONG g_ProcessContext;
static LONG g_ManifestRead;
/* The slot (plus one) of the context that a thread set for itself, and of its hosting behaviour */
static LONG g_ThreadSlot;
static LONG g_HostingSlot;
static LONG g_SystemDpi;

static UINT
GetSystemDpiValue(VOID)
{
    LONG Dpi = g_SystemDpi;

    if (!Dpi)
    {
        DWORD Error = GetLastError();
        HDC hDC = NtUserGetDC(NULL);

        if (hDC)
        {
            Dpi = GetDeviceCaps(hDC, LOGPIXELSY);
            ReleaseDC(NULL, hDC);
        }
        SetLastError(Error);
        if (Dpi <= 0)
            return USER_DEFAULT_SCREEN_DPI_;
        g_SystemDpi = Dpi;
    }
    return Dpi;
}

/* A pseudo handle (-1 to -5) or a value that one of these functions returned. The DPI of a
 * system-aware context is not checked here, Windows does not check it either */
static BOOL
DpiContextFromHandle(DPI_AWARENESS_CONTEXT Handle, PULONG Context)
{
    ULONG_PTR Value = (ULONG_PTR)Handle;
    ULONG Ctx;

    switch ((INT_PTR)Value)
    {
        case -1: *Context = DPICTX_UNAWARE; return TRUE;
        case -2: *Context = DPICTX_SYSTEM_AWARE(GetSystemDpiValue()); return TRUE;
        case -3: *Context = DPICTX_PER_MONITOR; return TRUE;
        case -4: *Context = DPICTX_PER_MONITOR_V2; return TRUE;
        case -5: *Context = DPICTX_UNAWARE_GDI; return TRUE;
    }

    /* A 32-bit value as a pointer, zero-extended or sign-extended (LongToHandle) */
    if ((Value >> 16 >> 16) != 0 && (Value >> 16 >> 16) != 0xffffffffu)
        return FALSE;
    Ctx = (ULONG)Value;

    switch (DPICTX_AWARENESS(Ctx))
    {
        case DPI_AWARENESS_UNAWARE:
            if (DPICTX_FLAGS(Ctx) & ~DPICTX_FLAGS_VALID) return FALSE;
            if (DPICTX_VERSION(Ctx) != 1) return FALSE;
            if (DPICTX_DPI(Ctx) != USER_DEFAULT_SCREEN_DPI_) return FALSE;
            break;
        case DPI_AWARENESS_SYSTEM_AWARE:
            if (DPICTX_FLAGS(Ctx) & ~DPICTX_FLAGS_VALID) return FALSE;
            if (DPICTX_FLAGS(Ctx) & DPICTX_FLAG_GDISCALED) return FALSE;
            if (DPICTX_VERSION(Ctx) != 1) return FALSE;
            break;
        case DPI_AWARENESS_PER_MONITOR_AWARE:
            if (DPICTX_FLAGS(Ctx) & ~DPICTX_FLAGS_VALID) return FALSE;
            if (DPICTX_FLAGS(Ctx) & DPICTX_FLAG_GDISCALED) return FALSE;
            if (DPICTX_VERSION(Ctx) != 1 && DPICTX_VERSION(Ctx) != 2) return FALSE;
            if (DPICTX_DPI(Ctx)) return FALSE;
            break;
        default:
            return FALSE;
    }

    *Context = Ctx;
    return TRUE;
}

/* The same, for a context that is to be set: a system-aware one has to carry the DPI of the system */
static BOOL
DpiContextToSet(DPI_AWARENESS_CONTEXT Handle, PULONG Context, PBOOL DpiMismatch)
{
    *DpiMismatch = FALSE;
    if (!DpiContextFromHandle(Handle, Context))
        return FALSE;
    if (DPICTX_AWARENESS(*Context) == DPI_AWARENESS_SYSTEM_AWARE && DPICTX_DPI(*Context) != GetSystemDpiValue())
    {
        *DpiMismatch = TRUE;
        return FALSE;
    }
    return TRUE;
}

#if defined(DLL_EXPORT_VERSION) && DLL_EXPORT_VERSION >= 0x600
static BOOL
WideEqualsNoCase(PCWSTR Text, SIZE_T Length, PCWSTR Word)
{
    SIZE_T i;

    for (i = 0; i < Length; i++)
    {
        WCHAR c = Text[i];
        if (c >= L'A' && c <= L'Z')
            c += L'a' - L'A';
        if (!Word[i] || c != Word[i])
            return FALSE;
    }
    return Word[Length] == UNICODE_NULL;
}

NTSYSAPI LONG NTAPI
RtlQueryActivationContextApplicationSettings(DWORD, HANDLE, PCWSTR, PCWSTR, PWSTR, SIZE_T, PSIZE_T);

/* The text of a setting of the manifest of the process, in memory that the caller frees with HeapFree */
static PWSTR
QueryManifestSetting(PCWSTR Namespace, PCWSTR Name)
{
    WCHAR Small[64];
    PWSTR Value = Small;
    SIZE_T Written = 0;
    /* The function counts the size without the terminator, so a buffer is given one less than it holds */
    LONG Status = RtlQueryActivationContextApplicationSettings(0, NULL, Namespace, Name, Small, ARRAYSIZE(Small) - 1, &Written);

    if (Status == STATUS_BUFFER_TOO_SMALL_ && Written > ARRAYSIZE(Small) - 1)
    {
        Value = HeapAlloc(GetProcessHeap(), 0, (Written + 2) * sizeof(WCHAR));
        if (!Value)
            return NULL;
        Status = RtlQueryActivationContextApplicationSettings(0, NULL, Namespace, Name, Value, Written + 1, &Written);
        if (Status)
        {
            HeapFree(GetProcessHeap(), 0, Value);
            return NULL;
        }
        return Value;
    }
    if (Status)
        return NULL;

    Value = HeapAlloc(GetProcessHeap(), 0, (lstrlenW(Small) + 1) * sizeof(WCHAR));
    if (Value)
        lstrcpyW(Value, Small);
    return Value;
}

/* The awareness that the manifest of the process asks for, 0 if it asks for none. A dpiAware
 * element locks the awareness whatever it says, a dpiAwareness list that holds no known entry
 * is ignored (both as measured on Windows 10) */
static ULONG
ReadManifestContext(VOID)
{
    static const WCHAR Ns2005[] = L"http://schemas.microsoft.com/SMI/2005/WindowsSettings";
    static const WCHAR Ns2016[] = L"http://schemas.microsoft.com/SMI/2016/WindowsSettings";
    PWSTR Value;
    SIZE_T Start, End;
    ULONG Result = 0;

    /* dpiAwareness is a list; the first entry that is known counts */
    Value = QueryManifestSetting(Ns2016, L"dpiAwareness");
    if (Value)
    {
        for (Start = 0; Value[Start] && !Result; Start = End)
        {
            while (Value[Start] == L' ' || Value[Start] == L',' || Value[Start] == L'\t')
                Start++;
            for (End = Start; Value[End] && Value[End] != L' ' && Value[End] != L',' && Value[End] != L'\t'; End++)
                ;
            if (End == Start)
                break;
            if (WideEqualsNoCase(Value + Start, End - Start, L"permonitorv2"))
                Result = DPICTX_PER_MONITOR_V2;
            else if (WideEqualsNoCase(Value + Start, End - Start, L"permonitor"))
                Result = DPICTX_PER_MONITOR;
            else if (WideEqualsNoCase(Value + Start, End - Start, L"system"))
                Result = DPICTX_SYSTEM_AWARE(GetSystemDpiValue());
            else if (WideEqualsNoCase(Value + Start, End - Start, L"unaware"))
                Result = DPICTX_UNAWARE;
        }
        HeapFree(GetProcessHeap(), 0, Value);
        if (Result)
            return Result;
    }

    Value = QueryManifestSetting(Ns2005, L"dpiAware");
    if (Value)
    {
        SIZE_T Length = lstrlenW(Value);

        if (WideEqualsNoCase(Value, Length, L"true"))
            Result = DPICTX_SYSTEM_AWARE(GetSystemDpiValue());
        else if (WideEqualsNoCase(Value, Length, L"true/pm") || WideEqualsNoCase(Value, Length, L"per monitor"))
            Result = DPICTX_PER_MONITOR;
        else
            Result = DPICTX_UNAWARE;
        HeapFree(GetProcessHeap(), 0, Value);
    }
    return Result;
}
#else
/* A system that has no manifest settings in its ntdll has no awareness from a manifest */
static ULONG
ReadManifestContext(VOID)
{
    return 0;
}
#endif

/* A manifest decides the awareness before any call can; later calls to set it are refused. The
 * manifest does not change, so a thread that finds the work not done does it itself and does not
 * wait for another thread (that may hold a lock that the work needs) */
static VOID
ApplyManifest(VOID)
{
    ULONG Ctx;
    DWORD Error;

    if (g_ManifestRead)
        return;
    Error = GetLastError();
    Ctx = ReadManifestContext();
    SetLastError(Error);
    if (Ctx)
        InterlockedCompareExchange(&g_ProcessContext, Ctx, 0);
    InterlockedExchange(&g_ManifestRead, 1);
}

static ULONG
GetProcessContextValue(VOID)
{
    ULONG Ctx;

    ApplyManifest();
    Ctx = g_ProcessContext;
    return Ctx ? Ctx : DPICTX_UNAWARE;
}

/* TlsGetValue sets the last error to success, a call here must leave it alone */
static PVOID
TlsGetValueKeepError(DWORD Slot)
{
    DWORD Error = GetLastError();
    PVOID Value = TlsGetValue(Slot);

    SetLastError(Error);
    return Value;
}

static DWORD
GetThreadSlot(BOOL Create)
{
    LONG Slot = g_ThreadSlot;
    DWORD New;

    if (Slot || !Create)
        return Slot ? Slot - 1 : TLS_OUT_OF_INDEXES;
    New = TlsAlloc();
    if (New == TLS_OUT_OF_INDEXES)
        return New;
    Slot = InterlockedCompareExchange(&g_ThreadSlot, New + 1, 0);
    if (Slot)
    {
        TlsFree(New);
        return Slot - 1;
    }
    return New;
}

/* The context a thread set for itself, or 0 while it follows the process */
static ULONG
GetThreadOwnContext(VOID)
{
    DWORD Slot = GetThreadSlot(FALSE);
    if (Slot == TLS_OUT_OF_INDEXES)
        return 0;
    return (ULONG)(ULONG_PTR)TlsGetValueKeepError(Slot);
}

static ULONG
GetThreadContextValue(VOID)
{
    ULONG Ctx = GetThreadOwnContext();
    return Ctx ? Ctx : GetProcessContextValue();
}

UINT
WINAPI
GetDpiForSystem(VOID)
{
    return GetSystemDpiValue();
}

/* The system DPI of a process; on Windows 10 the handle needs PROCESS_QUERY_LIMITED_INFORMATION, NULL
 * stands for the calling process, and every failure is an invalid parameter (measured on build 19045) */
UINT
WINAPI
GetSystemDpiForProcess(
    _In_opt_ HANDLE hProcess)
{
    if (hProcess && !GetProcessId(hProcess))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    return GetSystemDpiValue();
}

UINT
WINAPI
GetDpiForWindow(
    _In_ HWND hWnd)
{
    if (!IsWindow(hWnd))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    return GetSystemDpiValue();
}

/* As on Windows, what these two report is the awareness of the calling thread */
BOOL
WINAPI
IsProcessDPIAware(VOID)
{
    return DPICTX_AWARENESS(GetThreadContextValue()) != DPI_AWARENESS_UNAWARE;
}

static BOOL
SetProcessContextValue(ULONG Ctx)
{
    ApplyManifest();
    if (InterlockedCompareExchange(&g_ProcessContext, Ctx, 0))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return TRUE;
}

/* Succeeds also when the awareness was set already; then it changes nothing */
BOOL
WINAPI
SetProcessDPIAware(VOID)
{
    ApplyManifest();
    InterlockedCompareExchange(&g_ProcessContext, DPICTX_SYSTEM_AWARE(GetSystemDpiValue()), 0);
    return TRUE;
}

BOOL
WINAPI
SetProcessDpiAwarenessContext(
    _In_ DPI_AWARENESS_CONTEXT context)
{
    ULONG Ctx;
    BOOL Mismatch;

    if (!DpiContextToSet(context, &Ctx, &Mismatch))
    {
        SetLastError(Mismatch ? ERROR_ACCESS_DENIED : ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return SetProcessContextValue(Ctx);
}

/* 1 for this process, 0 for another, -1 for a handle that is none */
static int
ClassifyProcessHandle(HANDLE Process)
{
    DWORD Error, Pid;

    if (!Process || Process == GetCurrentProcess())
        return 1;
    Error = GetLastError();
    Pid = GetProcessId(Process);
    SetLastError(Error);
    if (!Pid)
        return -1;
    return Pid == GetCurrentProcessId() ? 1 : 0;
}

BOOL
WINAPI
GetProcessDpiAwarenessInternal(
    _In_  HANDLE process,
    _Out_ DPI_AWARENESS *awareness)
{
    int Kind = ClassifyProcessHandle(process);

    if (Kind < 0)
    {
        *awareness = DPI_AWARENESS_INVALID;
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* The awareness of another process is not kept anywhere that this process can read */
    if (!Kind)
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    *awareness = (DPI_AWARENESS)DPICTX_AWARENESS(GetThreadContextValue());
    return TRUE;
}

BOOL
WINAPI
SetProcessDpiAwarenessInternal(
    _In_ DPI_AWARENESS awareness)
{
    switch (awareness)
    {
        case DPI_AWARENESS_UNAWARE:
            return SetProcessContextValue(DPICTX_UNAWARE);
        case DPI_AWARENESS_SYSTEM_AWARE:
            return SetProcessContextValue(DPICTX_SYSTEM_AWARE(GetSystemDpiValue()));
        case DPI_AWARENESS_PER_MONITOR_AWARE:
            return SetProcessContextValue(DPICTX_PER_MONITOR);
        default:
            break;
    }
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

DPI_AWARENESS_CONTEXT
WINAPI
GetDpiAwarenessContextForProcess(
    _In_ HANDLE process)
{
    int Kind = ClassifyProcessHandle(process);

    if (Kind <= 0)
    {
        SetLastError(Kind < 0 ? ERROR_INVALID_PARAMETER : ERROR_NOT_SUPPORTED);
        return NULL;
    }
    return (DPI_AWARENESS_CONTEXT)(ULONG_PTR)GetThreadContextValue();
}

DPI_AWARENESS_CONTEXT
WINAPI
GetThreadDpiAwarenessContext(VOID)
{
    return (DPI_AWARENESS_CONTEXT)(ULONG_PTR)GetThreadContextValue();
}

DPI_AWARENESS_CONTEXT
WINAPI
SetThreadDpiAwarenessContext(
    _In_ DPI_AWARENESS_CONTEXT context)
{
    ULONG Ctx, Prev;
    DWORD Slot;
    BOOL Mismatch;

    if (!DpiContextToSet(context, &Ctx, &Mismatch))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    Slot = GetThreadSlot(TRUE);
    if (Slot == TLS_OUT_OF_INDEXES)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    Prev = GetThreadOwnContext();
    if (!Prev)
        Prev = GetProcessContextValue() | DPICTX_FLAG_PROCESS;

    /* A context with the process flag hands the thread back to the process */
    if (!TlsSetValue(Slot, (DPICTX_FLAGS(Ctx) & DPICTX_FLAG_PROCESS) ? NULL : (PVOID)(ULONG_PTR)Ctx))
        return NULL;
    return (DPI_AWARENESS_CONTEXT)(ULONG_PTR)Prev;
}

DPI_AWARENESS
WINAPI
GetAwarenessFromDpiAwarenessContext(
    _In_ DPI_AWARENESS_CONTEXT context)
{
    ULONG Ctx;

    if (!DpiContextFromHandle(context, &Ctx))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return DPI_AWARENESS_INVALID;
    }
    return (DPI_AWARENESS)DPICTX_AWARENESS(Ctx);
}

UINT
WINAPI
GetDpiFromDpiAwarenessContext(
    _In_ DPI_AWARENESS_CONTEXT context)
{
    ULONG Ctx;

    if (!DpiContextFromHandle(context, &Ctx))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    return DPICTX_DPI(Ctx);
}

BOOL
WINAPI
IsValidDpiAwarenessContext(
    _In_ DPI_AWARENESS_CONTEXT context)
{
    ULONG Ctx;

    if (!DpiContextFromHandle(context, &Ctx))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

BOOL
WINAPI
AreDpiAwarenessContextsEqual(
    _In_ DPI_AWARENESS_CONTEXT context1,
    _In_ DPI_AWARENESS_CONTEXT context2)
{
    ULONG Ctx1, Ctx2;

    if (!DpiContextFromHandle(context1, &Ctx1) || !DpiContextFromHandle(context2, &Ctx2))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return (Ctx1 & ~DPICTX_FLAG_PROCESS) == (Ctx2 & ~DPICTX_FLAG_PROCESS);
}

BOOL
WINAPI
GetDpiForMonitorInternal(
    _In_  HMONITOR monitor,
    _In_  UINT type,
    _Out_ UINT *x,
    _Out_ UINT *y)
{
    MONITORINFO Info;

    if (!x || !y)
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }
    if (type > 2)
    {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return FALSE;
    }
    Info.cbSize = sizeof(Info);
    if (!monitor || !GetMonitorInfoW(monitor, &Info))
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    /* The physical size of the screen is not known; Windows answers the same without EDID data */
    if (type == 2)
    {
        *x = *y = 0;
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    *x = *y = GetSystemDpiValue();
    return TRUE;
}

/* The context that a window was created under, for the windows that this process created */
#define DPI_WINDOW_BUCKETS 128

typedef struct _DPI_WINDOW
{
    struct _DPI_WINDOW *Next;
    HWND hWnd;
    DWORD ThreadId;
    ULONG Context;
    int Hosting;
} DPI_WINDOW;

static DPI_WINDOW *g_DpiWindows[DPI_WINDOW_BUCKETS];
static CRITICAL_SECTION g_DpiWindowsLock;
static CRITICAL_SECTION_DEBUG g_DpiWindowsLockDebug =
{
    0, 0, &g_DpiWindowsLock,
    { &g_DpiWindowsLockDebug.ProcessLocksList, &g_DpiWindowsLockDebug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": g_DpiWindowsLock") }
};
static CRITICAL_SECTION g_DpiWindowsLock = { &g_DpiWindowsLockDebug, -1, 0, 0, 0, 0 };

static VOID
DpiWindowsLock(VOID)
{
    EnterCriticalSection(&g_DpiWindowsLock);
}

static VOID
DpiWindowsUnlock(VOID)
{
    LeaveCriticalSection(&g_DpiWindowsLock);
}

static BOOL GetWindowContextValue(HWND hWnd, PULONG Context, PBOOL Created);

/* The window that is being created on a thread has no handle yet. What it will have is worked out
 * before the creation and kept in a node (a stack of the creations of the thread, which a window
 * procedure may nest), so that nothing a window procedure does to the context of the thread
 * during the creation changes it. A node of a creation that an exception left is dropped by the
 * end of the creation around it; one at the top stays and is only used for windows that have no
 * entry */
static LONG g_CreationSlot;

static DPI_WINDOW *
GetCreation(VOID)
{
    LONG Slot = g_CreationSlot;
    return Slot ? TlsGetValueKeepError(Slot - 1) : NULL;
}

PVOID
DpiBeginWindow(HWND hWndParent, DWORD Style)
{
    DPI_WINDOW *Node = HeapAlloc(GetProcessHeap(), 0, sizeof(*Node));
    ULONG Ctx;
    BOOL Created;
    LONG Slot = g_CreationSlot;

    if (!Node)
        return NULL;

    /* A child window has the context of its parent, whatever the thread does; any other window,
     * also one that has an owner, has the context of the thread that creates it (measured on Windows 10) */
    Node->hWnd = NULL;
    Node->ThreadId = GetCurrentThreadId();
    Node->Hosting = GetThreadDpiHostingBehavior();
    Node->Context = 0;
    if ((Style & WS_CHILD) && hWndParent && hWndParent != GetDesktopWindow() && GetWindowContextValue(hWndParent, &Ctx, &Created))
        Node->Context = Ctx;
    if (!Node->Context)
        Node->Context = GetThreadContextValue();

    if (!Slot)
    {
        DWORD New = TlsAlloc();

        if (New != TLS_OUT_OF_INDEXES)
        {
            Slot = InterlockedCompareExchange(&g_CreationSlot, New + 1, 0);
            if (Slot)
                TlsFree(New);
            else
                Slot = New + 1;
        }
    }
    Node->Next = Slot ? TlsGetValueKeepError(Slot - 1) : NULL;
    if (Slot && !TlsSetValue(Slot - 1, Node))
        Node->Next = NULL;
    return Node;
}

/* The entries of destroyed windows are removed when their bucket is next used, so that
 * nothing has to hear about the destruction of a window */
VOID
DpiEndWindow(HWND hWnd, PVOID Creation)
{
    DPI_WINDOW *Entry, **Link, *Retired = NULL, *New = Creation;
    ULONG_PTR Bucket;
    DWORD Error = GetLastError();

    if (!New)
        return;
    if (g_CreationSlot && GetCreation() == New)
        TlsSetValue(g_CreationSlot - 1, New->Next);
    if (!hWnd)
    {
        HeapFree(GetProcessHeap(), 0, New);
        SetLastError(Error);
        return;
    }

    Bucket = ((ULONG_PTR)hWnd >> 2) % DPI_WINDOW_BUCKETS;
    New->hWnd = hWnd;

    DpiWindowsLock();
    for (Link = &g_DpiWindows[Bucket]; (Entry = *Link) != NULL; )
    {
        if (Entry->hWnd == hWnd || !IsWindow(Entry->hWnd))
        {
            *Link = Entry->Next;
            Entry->Next = Retired;
            Retired = Entry;
        }
        else
        {
            Link = &Entry->Next;
        }
    }
    New->Next = g_DpiWindows[Bucket];
    g_DpiWindows[Bucket] = New;
    DpiWindowsUnlock();

    /* The heap has its own lock, so nothing is freed while the table is locked */
    while ((Entry = Retired) != NULL)
    {
        Retired = Entry->Next;
        HeapFree(GetProcessHeap(), 0, Entry);
    }
    SetLastError(Error);
}

/* Sets Created when the window has an entry, that is when it was created and recorded */
static BOOL
GetWindowEntry(HWND hWnd, PULONG Context, PBOOL Created, int *Hosting)
{
    DPI_WINDOW *Entry;
    DWORD Pid, Tid;
    ULONG Ctx = 0;
    int Behavior = 0;

    *Created = FALSE;
    if (!IsWindow(hWnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }

    Tid = GetWindowThreadProcessId(hWnd, &Pid);
    if (Pid != GetCurrentProcessId())
    {
        /* What another process created under is not known; the desktop window of Windows reports
         * per-monitor awareness, and nothing of what this system shows is scaled for a window */
        *Context = DPICTX_PER_MONITOR;
        if (Hosting)
            *Hosting = 0;
        return TRUE;
    }

    DpiWindowsLock();
    for (Entry = g_DpiWindows[((ULONG_PTR)hWnd >> 2) % DPI_WINDOW_BUCKETS]; Entry; Entry = Entry->Next)
    {
        if (Entry->hWnd == hWnd && Entry->ThreadId == Tid)
        {
            Ctx = Entry->Context;
            Behavior = Entry->Hosting;
            break;
        }
    }
    DpiWindowsUnlock();

    /* A window that is still being created has no entry yet and has the context that its thread
     * gives it; a window that this process did not create follows the process */
    *Created = Ctx != 0;
    if (!Ctx)
    {
        if (Tid == GetCurrentThreadId())
        {
            DPI_WINDOW *Creation = GetCreation();

            Behavior = Creation ? Creation->Hosting : GetThreadDpiHostingBehavior();
            Ctx = Creation ? Creation->Context : GetThreadContextValue();
        }
        else
        {
            Ctx = GetProcessContextValue();
        }
    }
    *Context = Ctx;
    if (Hosting)
        *Hosting = Behavior;
    return TRUE;
}

static BOOL
GetWindowContextValue(HWND hWnd, PULONG Context, PBOOL Created)
{
    return GetWindowEntry(hWnd, Context, Created, NULL);
}

DPI_AWARENESS_CONTEXT
WINAPI
GetWindowDpiAwarenessContext(
    _In_ HWND hwnd)
{
    ULONG Ctx;
    BOOL Created;

    if (!GetWindowContextValue(hwnd, &Ctx, &Created))
        return NULL;
    return (DPI_AWARENESS_CONTEXT)(ULONG_PTR)Ctx;
}

/* True while the window is made, for a top-level window of a per-monitor-aware thread: in the
 * message WM_NCCREATE Windows lets such a window ask for the scaling of its non-client area,
 * which has nothing to scale here */
BOOL
WINAPI
EnableNonClientDpiScaling(
    _In_ HWND hwnd)
{
    ULONG Ctx;
    BOOL Created;

    if (!GetWindowContextValue(hwnd, &Ctx, &Created))
        return FALSE;
    if (Created || (GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD))
        return FALSE;
    if (GetWindowThreadProcessId(hwnd, NULL) != GetCurrentThreadId())
        return FALSE;
    return DPICTX_AWARENESS(Ctx) == DPI_AWARENESS_PER_MONITOR_AWARE;
}

int
WINAPI
GetThreadDpiHostingBehavior(VOID)
{
    LONG Slot = g_HostingSlot;
    return Slot ? (int)(ULONG_PTR)TlsGetValueKeepError(Slot - 1) : DPI_HOSTING_BEHAVIOR_DEFAULT_;
}

int
WINAPI
SetThreadDpiHostingBehavior(
    _In_ int value)
{
    LONG Slot = g_HostingSlot;
    int Prev;

    if (value != DPI_HOSTING_BEHAVIOR_DEFAULT_ && value != DPI_HOSTING_BEHAVIOR_MIXED_)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return DPI_HOSTING_BEHAVIOR_INVALID_;
    }

    if (!Slot)
    {
        DWORD New;

        if (value == DPI_HOSTING_BEHAVIOR_DEFAULT_)
            return DPI_HOSTING_BEHAVIOR_DEFAULT_;
        New = TlsAlloc();
        if (New == TLS_OUT_OF_INDEXES)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return DPI_HOSTING_BEHAVIOR_INVALID_;
        }
        Slot = InterlockedCompareExchange(&g_HostingSlot, New + 1, 0);
        if (Slot)
            TlsFree(New);
        else
            Slot = New + 1;
    }

    Prev = (int)(ULONG_PTR)TlsGetValueKeepError(Slot - 1);
    if (!TlsSetValue(Slot - 1, (PVOID)(ULONG_PTR)value))
        return DPI_HOSTING_BEHAVIOR_INVALID_;
    return Prev;
}

int
WINAPI
GetWindowDpiHostingBehavior(
    _In_ HWND hwnd)
{
    ULONG Ctx;
    BOOL Created;
    int Hosting;

    if (!IsWindow(hwnd))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return DPI_HOSTING_BEHAVIOR_INVALID_;
    }
    if (!GetWindowEntry(hwnd, &Ctx, &Created, &Hosting))
        return DPI_HOSTING_BEHAVIOR_INVALID_;
    return Hosting;
}

/* One DPI for every monitor and every window: logical and physical points are the same, but a
 * point has to be in the window (its right and bottom edges included) and a window of NULL is
 * accepted, as on Windows 10 */
static BOOL
MapPointForWindow(HWND hwnd, POINT *point)
{
    DWORD Error = GetLastError();
    RECT Rect;

    if (hwnd && !IsWindow(hwnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return FALSE;
    }
    if (!point)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (hwnd)
    {
        if (!GetWindowRect(hwnd, &Rect))
            return FALSE;
        SetLastError(Error);
        if (point->x < Rect.left || point->x > Rect.right || point->y < Rect.top || point->y > Rect.bottom)
            return FALSE;
    }
    return TRUE;
}

BOOL
WINAPI
LogicalToPhysicalPointForPerMonitorDPI(
    _In_opt_ HWND hwnd,
    _Inout_ POINT *point)
{
    return MapPointForWindow(hwnd, point);
}

BOOL
WINAPI
PhysicalToLogicalPointForPerMonitorDPI(
    _In_opt_ HWND hwnd,
    _Inout_ POINT *point)
{
    return MapPointForWindow(hwnd, point);
}

static int
ScaleToDpi(int Value, UINT Dpi, UINT FromDpi)
{
    return MulDiv(Value, Dpi, FromDpi);
}

static VOID
ScaleLogFont(LOGFONTW *Font, UINT Dpi, UINT FromDpi)
{
    Font->lfHeight = ScaleToDpi(Font->lfHeight, Dpi, FromDpi);
    Font->lfWidth = ScaleToDpi(Font->lfWidth, Dpi, FromDpi);
}

/* The non-client metrics of the system, scaled to a DPI, in the structure of Windows Vista and later */
typedef struct _NCM_VISTA
{
    NONCLIENTMETRICSW Ncm;
    int iPaddedBorderWidth;
} NCM_VISTA;

static BOOL
GetScaledNonClientMetrics(NCM_VISTA *Out, UINT Dpi)
{
    UINT SystemDpi = GetSystemDpiValue();
    NCM_VISTA Base;
    NONCLIENTMETRICSW *Ncm = &Out->Ncm;

    /* The buffer is as large as win32k may write, whatever structure it was built with */
    Base.Ncm.cbSize = sizeof(Base);
    if (!SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(Base), &Base, 0))
        return FALSE;

    *Ncm = Base.Ncm;
    Ncm->cbSize = sizeof(*Out);
    Ncm->iBorderWidth = ScaleToDpi(Base.Ncm.iBorderWidth, Dpi, SystemDpi);
    Ncm->iScrollWidth = ScaleToDpi(Base.Ncm.iScrollWidth, Dpi, SystemDpi);
    Ncm->iScrollHeight = ScaleToDpi(Base.Ncm.iScrollHeight, Dpi, SystemDpi);
    Ncm->iCaptionWidth = ScaleToDpi(Base.Ncm.iCaptionWidth, Dpi, SystemDpi);
    Ncm->iCaptionHeight = ScaleToDpi(Base.Ncm.iCaptionHeight, Dpi, SystemDpi);
    Ncm->iSmCaptionWidth = ScaleToDpi(Base.Ncm.iSmCaptionWidth, Dpi, SystemDpi);
    Ncm->iSmCaptionHeight = ScaleToDpi(Base.Ncm.iSmCaptionHeight, Dpi, SystemDpi);
    Ncm->iMenuWidth = ScaleToDpi(Base.Ncm.iMenuWidth, Dpi, SystemDpi);
    Ncm->iMenuHeight = ScaleToDpi(Base.Ncm.iMenuHeight, Dpi, SystemDpi);
    ScaleLogFont(&Ncm->lfCaptionFont, Dpi, SystemDpi);
    ScaleLogFont(&Ncm->lfSmCaptionFont, Dpi, SystemDpi);
    ScaleLogFont(&Ncm->lfMenuFont, Dpi, SystemDpi);
    ScaleLogFont(&Ncm->lfStatusFont, Dpi, SystemDpi);
    ScaleLogFont(&Ncm->lfMessageFont, Dpi, SystemDpi);
    /* The padded border is part of the frame of a window, which ReactOS draws with none (see MetricsForDpi) */
    Out->iPaddedBorderWidth = ScaleToDpi(GetSystemMetrics(92), Dpi, SystemDpi);
    return TRUE;
}

static BOOL
SpiForDpi(UINT action, UINT val, PVOID ptr, UINT fWinIni, UINT dpi)
{
    UINT SystemDpi = GetSystemDpiValue();

    /* Without a DPI this is SystemParametersInfo */
    if (!dpi)
        return SystemParametersInfoW(action, val, ptr, fWinIni);

    switch (action)
    {
        case SPI_GETICONTITLELOGFONT:
        {
            LOGFONTW *Font = ptr;

            if (!ptr || val != sizeof(*Font) || !SystemParametersInfoW(action, val, ptr, fWinIni))
                break;
            ScaleLogFont(Font, dpi, SystemDpi);
            return TRUE;
        }

        case SPI_GETNONCLIENTMETRICS:
        {
            NCM_VISTA Scaled;
            NONCLIENTMETRICSW *Caller = ptr;

            /* The structure of Windows Vista and later only */
            if (!ptr || val != sizeof(NCM_VISTA) || Caller->cbSize != sizeof(NCM_VISTA))
                break;
            if (!GetScaledNonClientMetrics(&Scaled, dpi))
                return FALSE;
            *(NCM_VISTA *)ptr = Scaled;
            return TRUE;
        }

        case SPI_GETICONMETRICS:
        {
            ICONMETRICSW *Im = ptr;

            if (!ptr || val != sizeof(*Im) || Im->cbSize != sizeof(*Im) || !SystemParametersInfoW(action, val, ptr, fWinIni))
                break;
            Im->iHorzSpacing = ScaleToDpi(Im->iHorzSpacing, dpi, SystemDpi);
            Im->iVertSpacing = ScaleToDpi(Im->iVertSpacing, dpi, SystemDpi);
            ScaleLogFont(&Im->lfFont, dpi, SystemDpi);
            return TRUE;
        }
    }

    /* Nothing else depends on the DPI */
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

/* A call that succeeds leaves the last error as it was, whatever the calls inside it did to it */
BOOL
WINAPI
SystemParametersInfoForDpi(
    _In_ UINT action,
    _In_ UINT val,
    _Pre_maybenull_ _Post_valid_ PVOID ptr,
    _In_ UINT fWinIni,
    _In_ UINT dpi)
{
    DWORD Error = GetLastError();
    BOOL Ret = SpiForDpi(action, val, ptr, fWinIni, dpi);

    if (Ret)
        SetLastError(Error);
    return Ret;
}

static int
MetricsForDpi(int index, UINT dpi)
{
    UINT SystemDpi = GetSystemDpiValue();
    NCM_VISTA Ncm;
    ICONMETRICSW Im;
    int Value;

    /* The frame of a ReactOS window has no padded border: the metric is the one of GetSystemMetrics, which
     * programs add to SM_CXFRAME to get the width of the frame of a window */
    if (index == 92)
        return ScaleToDpi(GetSystemMetrics(index), dpi, SystemDpi);

    /* The icons and cursors have one size in ReactOS whatever the DPI, so they are scaled also at the DPI of the system */
    if (dpi == SystemDpi && index != SM_CXICON && index != SM_CYICON && index != SM_CXSMICON && index != SM_CYSMICON &&
        index != SM_CXCURSOR && index != SM_CYCURSOR)
        return GetSystemMetrics(index);

    switch (index)
    {
        case SM_CXVSCROLL:
        case SM_CYHSCROLL:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? max(Ncm.Ncm.iScrollWidth, 8) : 0;

        case SM_CYVTHUMB:
        case SM_CXHTHUMB:
        case SM_CYVSCROLL:
        case SM_CXHSCROLL:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? max(Ncm.Ncm.iScrollHeight, 8) : 0;

        case SM_CYCAPTION:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iCaptionHeight + 1 : 0;

        case SM_CXSIZE:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? max(Ncm.Ncm.iCaptionWidth, 8) : 0;

        case SM_CYSIZE:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iCaptionHeight : 0;

        case SM_CYMENU:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iMenuHeight + 1 : 0;

        case SM_CXFRAME:
        case SM_CYFRAME:
            if (!GetScaledNonClientMetrics(&Ncm, dpi))
                return 0;
            return GetSystemMetrics(SM_CXDLGFRAME) + max(Ncm.Ncm.iBorderWidth, 1);

        case SM_CYSMCAPTION:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iSmCaptionHeight + 1 : 0;

        case SM_CXSMSIZE:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iSmCaptionWidth : 0;

        case SM_CYSMSIZE:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iSmCaptionHeight : 0;

        case SM_CXMENUSIZE:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iMenuWidth : 0;

        case SM_CYMENUSIZE:
            return GetScaledNonClientMetrics(&Ncm, dpi) ? Ncm.Ncm.iMenuHeight : 0;

        case SM_CXICONSPACING:
        case SM_CYICONSPACING:
            Im.cbSize = sizeof(Im);
            if (!SystemParametersInfoW(SPI_GETICONMETRICS, sizeof(Im), &Im, 0))
                return 0;
            return ScaleToDpi(index == SM_CXICONSPACING ? Im.iHorzSpacing : Im.iVertSpacing, dpi, SystemDpi);

        case SM_CXICON:
        case SM_CYICON:
            return ScaleToDpi(32, dpi, USER_DEFAULT_SCREEN_DPI_);

        case SM_CXCURSOR:
        case SM_CYCURSOR:
            /* Whole sixteens, at least 32 and at most 128 */
            Value = ScaleToDpi(32, dpi, USER_DEFAULT_SCREEN_DPI_) / 16 * 16;
            return Value > 128 ? 128 : max(Value, 32);

        case SM_CXSMICON:
        case SM_CYSMICON:
            return ScaleToDpi(16, dpi, USER_DEFAULT_SCREEN_DPI_) & ~1;

        /* The check mark of a menu has the size of the text of the menu font */
        case SM_CXMENUCHECK:
        case SM_CYMENUCHECK:
        {
            TEXTMETRICW Metrics;
            HDC hDC;
            HFONT hFont, hOld;
            BOOL Done = FALSE;

            if (!GetScaledNonClientMetrics(&Ncm, dpi))
                return 0;
            hDC = NtUserGetDC(NULL);
            hFont = CreateFontIndirectW(&Ncm.Ncm.lfMenuFont);
            if (hDC && hFont)
            {
                hOld = SelectObject(hDC, hFont);
                Done = GetTextMetricsW(hDC, &Metrics);
                SelectObject(hDC, hOld);
            }
            if (hFont)
                DeleteObject(hFont);
            if (hDC)
                ReleaseDC(NULL, hDC);
            if (!Done || Metrics.tmHeight <= 0)
                return 13;
            return (Metrics.tmHeight + Metrics.tmExternalLeading - 1) | 1;
        }

        /* The minimum sizes of a window are made of the buttons of the caption, the border and the icon;
         * they are scaled as a whole */
        case SM_CXMIN:
        case SM_CYMIN:
        case SM_CXMINTRACK:
        case SM_CYMINTRACK:
            return ScaleToDpi(GetSystemMetrics(index), dpi, SystemDpi);
    }

    return GetSystemMetrics(index);
}

int
WINAPI
GetSystemMetricsForDpi(
    _In_ int index,
    _In_ UINT dpi)
{
    DWORD Error = GetLastError();
    int Value;

    if (!dpi)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    Value = MetricsForDpi(index, dpi);
    SetLastError(Error);
    return Value;
}

/* LogicalToPhysicalPoint and PhysicalToLogicalPoint are in physical.c */
