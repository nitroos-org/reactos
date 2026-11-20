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
 * of the call). Closing the service handle cancels its registrations.
 *
 * Not implemented: notifications of the service control manager handle
 * (SERVICE_NOTIFY_CREATED, SERVICE_NOTIFY_DELETED) and of
 * SERVICE_NOTIFY_DELETE_PENDING; they report ERROR_CALL_NOT_IMPLEMENTED.
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
    SC_HANDLE hService;
    DWORD dwMask;
    HANDLE hThread;
    PSERVICE_NOTIFY_2W Notify;
} SVC_NOTIFY_REG;

static volatile LONG g_NotifyLock;     /* a spin lock: needs no initialization and no Vista-only import */
static SVC_NOTIFY_REG *g_NotifyList;
static BOOL g_NotifyWorker;

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

/* Fills the notification and queues the callback. Returns FALSE when the thread is gone. */
static BOOL
FireNotification(HANDLE hThread,
                 PSERVICE_NOTIFY_2W Notify,
                 const SERVICE_STATUS_PROCESS *Status,
                 DWORD dwTriggered)
{
    Notify->dwNotificationStatus = ERROR_SUCCESS;
    Notify->ServiceStatus = *Status;
    if (Notify->dwVersion >= SERVICE_NOTIFY_STATUS_CHANGE_2)
    {
        Notify->dwNotificationTriggered = dwTriggered;
        Notify->pszServiceNames = NULL;
    }
    return QueueUserAPC((PAPCFUNC)Notify->pfnNotifyCallback, hThread, (ULONG_PTR)Notify) != 0;
}

static DWORD WINAPI
NotifyWorkerThread(PVOID Context)
{
    for (;;)
    {
        SVC_NOTIFY_REG **pp;

        Sleep(NOTIFY_POLL_MS);

        NotifyLock();
        pp = &g_NotifyList;
        while (*pp)
        {
            SVC_NOTIFY_REG *Reg = *pp;
            SERVICE_STATUS_PROCESS Status;
            DWORD cbNeeded, dwBit;
            BOOL bDone = FALSE;

            if (!QueryServiceStatusEx(Reg->hService, SC_STATUS_PROCESS_INFO,
                                      (LPBYTE)&Status, sizeof(Status), &cbNeeded))
            {
                /* The handle is not usable any more: drop the registration. */
                bDone = TRUE;
            }
            else
            {
                dwBit = StateToNotifyBit(Status.dwCurrentState);
                if (dwBit & Reg->dwMask)
                {
                    FireNotification(Reg->hThread, Reg->Notify, &Status, dwBit);
                    bDone = TRUE;
                }
            }

            if (bDone)
            {
                *pp = Reg->Next;
                CloseHandle(Reg->hThread);
                HeapFree(GetProcessHeap(), 0, Reg);
            }
            else
            {
                pp = &Reg->Next;
            }
        }

        if (!g_NotifyList)
        {
            g_NotifyWorker = FALSE;
            NotifyUnlock();
            return 0;
        }
        NotifyUnlock();
    }
}

/* Called by CloseServiceHandle: cancels the registrations of the handle. */
VOID
ScmCancelServiceNotifications(SC_HANDLE hService)
{
    SVC_NOTIFY_REG **pp;

    NotifyLock();
    pp = &g_NotifyList;
    while (*pp)
    {
        SVC_NOTIFY_REG *Reg = *pp;

        if (Reg->hService == hService)
        {
            *pp = Reg->Next;
            CloseHandle(Reg->hThread);
            HeapFree(GetProcessHeap(), 0, Reg);
        }
        else
        {
            pp = &Reg->Next;
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
    DWORD cbNeeded, dwBit;

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
        DWORD dwError = GetLastError();

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

    /* The service is already in a requested state: notify at once. */
    dwBit = StateToNotifyBit(Status.dwCurrentState);
    if (dwBit & dwNotifyMask)
    {
        BOOL bOk = FireNotification(hThread, Notify, &Status, dwBit);
        DWORD dwError = bOk ? ERROR_SUCCESS : GetLastError();

        CloseHandle(hThread);
        return dwError;
    }

    Reg = HeapAlloc(GetProcessHeap(), 0, sizeof(*Reg));
    if (Reg == NULL)
    {
        CloseHandle(hThread);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    /* The registration clears the status of the structure (measured); the other fields are written when it fires */
    Notify->dwNotificationStatus = ERROR_SUCCESS;

    Reg->hService = hService;
    Reg->dwMask = dwNotifyMask;
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
            DWORD dwError = GetLastError();

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
