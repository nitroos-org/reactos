/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NotifyServiceStatusChangeA/W: asynchronous service state notifications
 *
 * The notification is implemented in the client: a registration records the
 * service handle, the state mask and the calling thread; one worker thread
 * observes the registered services with QueryServiceStatusEx and queues the
 * callback as a user APC to the registering thread when the state of the
 * service is one of the requested states (also when it already is at the time
 * of the call, unless that same registration - handle, structure and mask - was
 * already queued in that state: Wine's service test and the documentation say it
 * then waits for the next change). Closing the service handle cancels its
 * registrations.
 *
 * The caller's notification structure is written by the APC, on the calling
 * thread, just before the callback runs: the worker never touches it, so a
 * thread that exits (and frees the structure on its stack) with a notification
 * pending cannot make the worker write to freed memory. As on Windows, the
 * small block of a notification that is never delivered is lost with the thread.
 *
 * Limits: Windows alternates when one registration is repeated again and again in an unchanged state (measured:
 * queued, not queued, queued, ...); here it is queued once and then waits for a change; the state is polled (100 ms), so a state that lasts less than that
 * can be missed; the notifications of the service control manager handle
 * (SERVICE_NOTIFY_CREATED, SERVICE_NOTIFY_DELETED) and SERVICE_NOTIFY_DELETE_PENDING
 * report ERROR_CALL_NOT_IMPLEMENTED; a service marked for deletion is not
 * detected. When the service cannot be queried any more (the service control
 * manager is gone) the callback is queued with that error in dwNotificationStatus.
 */

#include <advapi32.h>
WINE_DEFAULT_DEBUG_CHANNEL(advapi);

#define NOTIFY_STATE_MASK       0x7f    /* SERVICE_NOTIFY_STOPPED .. SERVICE_NOTIFY_PAUSED */
#define NOTIFY_SCM_MASK         (SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED)
#define NOTIFY_ALL_MASK         0x3ff
#define NOTIFY_POLL_MS          100

typedef struct _SVC_NOTIFY_REG
{
    struct _SVC_NOTIFY_REG *Next;
    ULONG Id;                   /* never reused: the worker finds its registration again by it */
    SC_HANDLE hService;
    DWORD dwMask;
    DWORD dwSeen;               /* the state last seen for this registration: it fires on a change into a requested state */
    HANDLE hThread;
    PSERVICE_NOTIFY_2W Notify;
} SVC_NOTIFY_REG;

/* The state in which a registration (handle, structure, mask) was last queued */
typedef struct _SVC_NOTIFY_LAST
{
    struct _SVC_NOTIFY_LAST *Next;
    SC_HANDLE hService;
    PSERVICE_NOTIFY_2W Notify;
    DWORD dwMask;
    DWORD dwState;
} SVC_NOTIFY_LAST;

/* What the APC needs: allocated by the one who queues it, freed by the APC */
typedef struct _SVC_NOTIFY_DELIVERY
{
    PSERVICE_NOTIFY_2W Notify;
    SERVICE_STATUS_PROCESS Status;
    DWORD dwTriggered;
    DWORD dwNotificationStatus;
} SVC_NOTIFY_DELIVERY;

typedef struct _SVC_NOTIFY_SNAP
{
    ULONG Id;
    SC_HANDLE hService;
    SERVICE_STATUS_PROCESS Status;
    DWORD dwError;
} SVC_NOTIFY_SNAP;

static volatile LONG g_NotifyLock;     /* a spin lock: needs no initialization and no Vista-only import. Never held across an RPC. */
static SVC_NOTIFY_REG *g_NotifyList;
static SVC_NOTIFY_LAST *g_NotifyLastList;
static BOOL g_NotifyWorker;
static volatile LONG g_NotifyNextId;

static VOID
NotifyLock(VOID)
{
    while (InterlockedCompareExchange(&g_NotifyLock, 1, 0) != 0)
        Sleep(1);
}

static VOID
NotifyUnlock(VOID)
{
    InterlockedExchange(&g_NotifyLock, 0);
}

static DWORD
StateToNotifyBit(DWORD dwState)
{
    switch (dwState)
    {
        case SERVICE_STOPPED: return SERVICE_NOTIFY_STOPPED;
        case SERVICE_START_PENDING: return SERVICE_NOTIFY_START_PENDING;
        case SERVICE_STOP_PENDING: return SERVICE_NOTIFY_STOP_PENDING;
        case SERVICE_RUNNING: return SERVICE_NOTIFY_RUNNING;
        case SERVICE_CONTINUE_PENDING: return SERVICE_NOTIFY_CONTINUE_PENDING;
        case SERVICE_PAUSE_PENDING: return SERVICE_NOTIFY_PAUSE_PENDING;
        case SERVICE_PAUSED: return SERVICE_NOTIFY_PAUSED;
    }
    return 0;
}

/* Called with the lock held. Notes that the registration was queued in this state. */
static VOID
NotifySetLast(SC_HANDLE hService, PSERVICE_NOTIFY_2W Notify, DWORD dwMask, DWORD dwState)
{
    SVC_NOTIFY_LAST *Last;

    for (Last = g_NotifyLastList; Last; Last = Last->Next)
    {
        if (Last->hService == hService && Last->Notify == Notify && Last->dwMask == dwMask)
        {
            Last->dwState = dwState;
            return;
        }
    }

    Last = HeapAlloc(GetProcessHeap(), 0, sizeof(*Last));
    if (Last == NULL)
        return;     /* it is then queued again in the same state */
    Last->hService = hService;
    Last->Notify = Notify;
    Last->dwMask = dwMask;
    Last->dwState = dwState;
    Last->Next = g_NotifyLastList;
    g_NotifyLastList = Last;
}

/* Called with the lock held. */
static BOOL
NotifyWasQueuedIn(SC_HANDLE hService, PSERVICE_NOTIFY_2W Notify, DWORD dwMask, DWORD dwState)
{
    SVC_NOTIFY_LAST *Last;

    for (Last = g_NotifyLastList; Last; Last = Last->Next)
    {
        if (Last->hService == hService && Last->Notify == Notify && Last->dwMask == dwMask)
            return Last->dwState == dwState;
    }
    return FALSE;
}

/* Runs on the registering thread, in its alertable wait */
static VOID WINAPI
NotifyApc(ULONG_PTR Parameter)
{
    SVC_NOTIFY_DELIVERY *Delivery = (SVC_NOTIFY_DELIVERY *)Parameter;
    PSERVICE_NOTIFY_2W Notify = Delivery->Notify;

    Notify->dwNotificationStatus = Delivery->dwNotificationStatus;
    if (Delivery->dwNotificationStatus == ERROR_SUCCESS)
    {
        Notify->ServiceStatus = Delivery->Status;
        if (Notify->dwVersion >= SERVICE_NOTIFY_STATUS_CHANGE_2)
        {
            Notify->dwNotificationTriggered = Delivery->dwTriggered;
            Notify->pszServiceNames = NULL;
        }
    }
    HeapFree(GetProcessHeap(), 0, Delivery);

    Notify->pfnNotifyCallback(Notify);
}

/* Queues the callback of a notification. Returns the error, ERROR_SUCCESS when queued. */
static DWORD
QueueNotification(HANDLE hThread,
                  PSERVICE_NOTIFY_2W Notify,
                  const SERVICE_STATUS_PROCESS *Status,
                  DWORD dwTriggered,
                  DWORD dwNotificationStatus)
{
    SVC_NOTIFY_DELIVERY *Delivery;
    DWORD dwError;

    Delivery = HeapAlloc(GetProcessHeap(), 0, sizeof(*Delivery));
    if (Delivery == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Delivery->Notify = Notify;
    if (Status)
        Delivery->Status = *Status;
    else
        RtlZeroMemory(&Delivery->Status, sizeof(Delivery->Status));
    Delivery->dwTriggered = dwTriggered;
    Delivery->dwNotificationStatus = dwNotificationStatus;

    if (QueueUserAPC(NotifyApc, hThread, (ULONG_PTR)Delivery))
        return ERROR_SUCCESS;

    dwError = GetLastError();
    HeapFree(GetProcessHeap(), 0, Delivery);
    return dwError;
}

static VOID
NotifyDropReg(SVC_NOTIFY_REG **pp)
{
    SVC_NOTIFY_REG *Reg = *pp;

    *pp = Reg->Next;
    CloseHandle(Reg->hThread);
    HeapFree(GetProcessHeap(), 0, Reg);
}

static DWORD WINAPI
NotifyWorkerThread(PVOID Context)
{
    for (;;)
    {
        SVC_NOTIFY_SNAP *Snap = NULL;
        SVC_NOTIFY_REG *Reg;
        ULONG Count = 0, i, j;

        Sleep(NOTIFY_POLL_MS);

        /* Take a copy of what to look at: the service control manager is asked without the lock */
        NotifyLock();
        for (Reg = g_NotifyList; Reg; Reg = Reg->Next)
            Count++;
        if (Count == 0)
        {
            g_NotifyWorker = FALSE;
            NotifyUnlock();
            return 0;
        }
        NotifyUnlock();

        Snap = HeapAlloc(GetProcessHeap(), 0, Count * sizeof(*Snap));
        if (Snap == NULL)
            continue;

        NotifyLock();
        for (Reg = g_NotifyList, i = 0; Reg && i < Count; Reg = Reg->Next, i++)
        {
            Snap[i].Id = Reg->Id;
            Snap[i].hService = Reg->hService;
        }
        Count = i;
        NotifyUnlock();

        for (i = 0; i < Count; i++)
        {
            DWORD cbNeeded;

            /* one question per service handle */
            for (j = 0; j < i; j++)
            {
                if (Snap[j].hService == Snap[i].hService)
                {
                    Snap[i].Status = Snap[j].Status;
                    Snap[i].dwError = Snap[j].dwError;
                    break;
                }
            }
            if (j < i)
                continue;

            Snap[i].dwError = ERROR_SUCCESS;
            if (!QueryServiceStatusEx(Snap[i].hService, SC_STATUS_PROCESS_INFO,
                                      (LPBYTE)&Snap[i].Status, sizeof(Snap[i].Status), &cbNeeded))
            {
                Snap[i].dwError = GetLastError();
            }
        }

        NotifyLock();
        for (i = 0; i < Count; i++)
        {
            SVC_NOTIFY_REG **pp = &g_NotifyList;

            while (*pp && (*pp)->Id != Snap[i].Id)
                pp = &(*pp)->Next;
            Reg = *pp;
            if (Reg == NULL)
                continue;       /* cancelled while the service control manager was asked */

            if (Snap[i].dwError != ERROR_SUCCESS)
            {
                /* The service cannot be observed any more: say so instead of never answering */
                QueueNotification(Reg->hThread, Reg->Notify, NULL, 0, Snap[i].dwError);
                NotifyDropReg(pp);
            }
            else if (Snap[i].Status.dwCurrentState != Reg->dwSeen)
            {
                DWORD dwBit = StateToNotifyBit(Snap[i].Status.dwCurrentState);

                Reg->dwSeen = Snap[i].Status.dwCurrentState;
                if (dwBit & Reg->dwMask)
                {
                    NotifySetLast(Reg->hService, Reg->Notify, Reg->dwMask, Snap[i].Status.dwCurrentState);
                    QueueNotification(Reg->hThread, Reg->Notify, &Snap[i].Status, dwBit, ERROR_SUCCESS);
                    NotifyDropReg(pp);
                }
            }
        }
        NotifyUnlock();

        HeapFree(GetProcessHeap(), 0, Snap);
    }
}

/* Called by CloseServiceHandle: cancels the registrations of the handle. */
VOID
ScmCancelServiceNotifications(SC_HANDLE hService)
{
    SVC_NOTIFY_REG **pp;
    SVC_NOTIFY_LAST **ppLast;

    NotifyLock();
    pp = &g_NotifyList;
    while (*pp)
    {
        if ((*pp)->hService == hService)
            NotifyDropReg(pp);
        else
            pp = &(*pp)->Next;
    }


    ppLast = &g_NotifyLastList;
    while (*ppLast)
    {
        SVC_NOTIFY_LAST *Last = *ppLast;

        if (Last->hService == hService)
        {
            *ppLast = Last->Next;
            HeapFree(GetProcessHeap(), 0, Last);
        }
        else
        {
            ppLast = &Last->Next;
        }
    }
    NotifyUnlock();
}

static DWORD
NotifyServiceStatusChange(SC_HANDLE hService,
                          DWORD dwNotifyMask,
                          PSERVICE_NOTIFY_2W Notify)
{
    SERVICE_STATUS_PROCESS Status;
    SVC_NOTIFY_REG *Reg;
    HANDLE hThread;
    DWORD cbNeeded, dwBit, dwError;

    if (hService == NULL || Notify == NULL || dwNotifyMask == 0 ||
        (dwNotifyMask & ~NOTIFY_ALL_MASK) != 0 ||
        Notify->dwVersion < SERVICE_NOTIFY_STATUS_CHANGE_1 ||
        Notify->dwVersion > SERVICE_NOTIFY_STATUS_CHANGE_2 ||
        Notify->pfnNotifyCallback == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /* The created/deleted notifications cannot be combined with the others. */
    if ((dwNotifyMask & NOTIFY_SCM_MASK) && (dwNotifyMask & ~NOTIFY_SCM_MASK))
        return ERROR_INVALID_PARAMETER;

    /* Only a service handle can be observed: this reports access and handle errors. */
    if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&Status, sizeof(Status), &cbNeeded))
    {
        dwError = GetLastError();

        if (dwError == ERROR_INVALID_HANDLE && (dwNotifyMask & ~NOTIFY_SCM_MASK) == 0)
        {
            /* The handle of the service control manager, asking for created/deleted services */
            return ERROR_CALL_NOT_IMPLEMENTED;
        }
        return dwError;
    }

    if (dwNotifyMask & NOTIFY_SCM_MASK)
        return ERROR_INVALID_HANDLE;

    if ((dwNotifyMask & ~NOTIFY_STATE_MASK) == SERVICE_NOTIFY_DELETE_PENDING)
        return ERROR_CALL_NOT_IMPLEMENTED;

    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                         &hThread, THREAD_SET_CONTEXT, FALSE, 0))
        return GetLastError();

    /* The registration clears the status of the structure (measured); the other fields are written when it fires */
    Notify->dwNotificationStatus = ERROR_SUCCESS;

    /*
     * The service is already in a requested state: notify at once, unless this registration was queued in that
     * state before and the state has not changed since: it then waits for the next time the service enters it.
     */
    dwBit = StateToNotifyBit(Status.dwCurrentState);
    if (dwBit & dwNotifyMask)
    {
        NotifyLock();
        if (!NotifyWasQueuedIn(hService, Notify, dwNotifyMask, Status.dwCurrentState))
        {
            NotifySetLast(hService, Notify, dwNotifyMask, Status.dwCurrentState);
            NotifyUnlock();

            dwError = QueueNotification(hThread, Notify, &Status, dwBit, ERROR_SUCCESS);
            CloseHandle(hThread);
            return dwError;
        }
        NotifyUnlock();
    }

    Reg = HeapAlloc(GetProcessHeap(), 0, sizeof(*Reg));
    if (Reg == NULL)
    {
        CloseHandle(hThread);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    Reg->Id = (ULONG)InterlockedIncrement(&g_NotifyNextId);
    Reg->hService = hService;
    Reg->dwMask = dwNotifyMask;
    Reg->dwSeen = Status.dwCurrentState;
    Reg->hThread = hThread;
    Reg->Notify = Notify;

    NotifyLock();
    Reg->Next = g_NotifyList;
    g_NotifyList = Reg;
    if (!g_NotifyWorker)
    {
        HANDLE hWorker = CreateThread(NULL, 0, NotifyWorkerThread, NULL, 0, NULL);

        if (hWorker == NULL)
        {
            dwError = GetLastError();

            g_NotifyList = Reg->Next;
            NotifyUnlock();
            CloseHandle(hThread);
            HeapFree(GetProcessHeap(), 0, Reg);
            return dwError;
        }
        CloseHandle(hWorker);
        g_NotifyWorker = TRUE;
    }
    NotifyUnlock();

    return ERROR_SUCCESS;
}

/**********************************************************************
 *  NotifyServiceStatusChangeW
 *
 * @implemented
 */
DWORD WINAPI
NotifyServiceStatusChangeW(SC_HANDLE hService,
                           DWORD dwNotifyMask,
                           PSERVICE_NOTIFYW pNotifyBuffer)
{
    return NotifyServiceStatusChange(hService, dwNotifyMask, pNotifyBuffer);
}

/**********************************************************************
 *  NotifyServiceStatusChangeA
 *
 * @implemented
 *
 * The ANSI and Unicode structures have the same layout: no service names are
 * ever returned, so no string conversion takes place.
 */
DWORD WINAPI
NotifyServiceStatusChangeA(SC_HANDLE hService,
                           DWORD dwNotifyMask,
                           PSERVICE_NOTIFYA pNotifyBuffer)
{
    return NotifyServiceStatusChange(hService, dwNotifyMask, (PSERVICE_NOTIFY_2W)pNotifyBuffer);
}
