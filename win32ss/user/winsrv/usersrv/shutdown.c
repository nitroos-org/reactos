/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS User API Server DLL
 * FILE:            win32ss/user/winsrv/usersrv/shutdown.c
 * PURPOSE:         Logout/shutdown
 * PROGRAMMERS:
 */

/* INCLUDES *******************************************************************/

#include "usersrv.h"

#include <commctrl.h>
#include <psapi.h>

#include "resource.h"

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

// Those flags (that are used for CsrProcess->ShutdownFlags) are named
// in accordance to the only public one: SHUTDOWN_NORETRY used for the
// SetProcessShutdownParameters API.
#if !defined(SHUTDOWN_SYSTEMCONTEXT) && !defined(SHUTDOWN_OTHERCONTEXT)
#define SHUTDOWN_SYSTEMCONTEXT  CsrShutdownSystem
#define SHUTDOWN_OTHERCONTEXT   CsrShutdownOther
#endif

// The DPRINTs that need to really be removed as soon as everything works.
#define MY_DPRINT  DPRINT1
#define MY_DPRINT2 DPRINT

typedef struct tagNOTIFY_CONTEXT
{
    UINT Msg;
    WPARAM wParam;
    LPARAM lParam;
    // HDESK Desktop;
    // HDESK OldDesktop;
    DWORD StartTime;
    DWORD QueryResult;
    HWND Dlg;
    DWORD EndNowResult;
    BOOL ShowUI;
    HANDLE UIThread;
    HWND WndClient;
    PSHUTDOWN_SETTINGS ShutdownSettings;
} NOTIFY_CONTEXT, *PNOTIFY_CONTEXT;

#define QUERY_RESULT_ABORT    0
#define QUERY_RESULT_CONTINUE 1
#define QUERY_RESULT_TIMEOUT  2
#define QUERY_RESULT_ERROR    3
#define QUERY_RESULT_FORCE    4

typedef void (WINAPI *INITCOMMONCONTROLS_PROC)(void);

typedef struct tagMESSAGE_CONTEXT
{
    HWND Wnd;
    UINT Msg;
    WPARAM wParam;
    LPARAM lParam;
    DWORD Timeout;
} MESSAGE_CONTEXT, *PMESSAGE_CONTEXT;


/* FUNCTIONS ******************************************************************/

static HMODULE hComCtl32Lib = NULL;

static VOID
CallInitCommonControls(VOID)
{
    static BOOL Initialized = FALSE;
    INITCOMMONCONTROLS_PROC InitProc;

    if (Initialized) return;

    hComCtl32Lib = LoadLibraryW(L"COMCTL32.DLL");
    if (hComCtl32Lib == NULL) return;

    InitProc = (INITCOMMONCONTROLS_PROC)GetProcAddress(hComCtl32Lib, "InitCommonControls");
    if (InitProc == NULL) return;

    (*InitProc)();

    Initialized = TRUE;
}

static VOID FASTCALL
UpdateProgressBar(HWND ProgressBar, PNOTIFY_CONTEXT NotifyContext)
{
    DWORD Passed;

    Passed = GetTickCount() - NotifyContext->StartTime;
    Passed -= NotifyContext->ShutdownSettings->HungAppTimeout;
    if (NotifyContext->ShutdownSettings->WaitToKillAppTimeout < Passed)
    {
        Passed = NotifyContext->ShutdownSettings->WaitToKillAppTimeout;
    }
    SendMessageW(ProgressBar, PBM_SETPOS, Passed / 2, 0);
}

static INT_PTR CALLBACK
EndNowDlgProc(HWND Dlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    INT_PTR Result;
    PNOTIFY_CONTEXT NotifyContext;
    HWND ProgressBar;
    DWORD TitleLength;
    int Len;
    LPWSTR Title;

    switch(Msg)
    {
    case WM_INITDIALOG:
        NotifyContext = (PNOTIFY_CONTEXT)lParam;
        NotifyContext->EndNowResult = QUERY_RESULT_ABORT;
        SetWindowLongPtrW(Dlg, DWLP_USER, (LONG_PTR)lParam);
        TitleLength = SendMessageW(NotifyContext->WndClient, WM_GETTEXTLENGTH,
                                   0, 0) +
                      GetWindowTextLengthW(Dlg);
        Title = HeapAlloc(UserServerHeap, 0, (TitleLength + 1) * sizeof(WCHAR));
        if (Title)
        {
            Len = GetWindowTextW(Dlg, Title, TitleLength + 1);
            SendMessageW(NotifyContext->WndClient, WM_GETTEXT,
                         TitleLength + 1 - Len, (LPARAM)(Title + Len));
            SetWindowTextW(Dlg, Title);
            HeapFree(UserServerHeap, 0, Title);
        }
        ProgressBar = GetDlgItem(Dlg, IDC_PROGRESS);
        SendMessageW(ProgressBar, PBM_SETRANGE32, 0,
                     NotifyContext->ShutdownSettings->WaitToKillAppTimeout / 2);
        UpdateProgressBar(ProgressBar, NotifyContext);
        SetTimer(Dlg, 0, 200, NULL);
        Result = FALSE;
        break;

    case WM_TIMER:
        NotifyContext = (PNOTIFY_CONTEXT)GetWindowLongPtrW(Dlg, DWLP_USER);
        ProgressBar = GetDlgItem(Dlg, IDC_PROGRESS);
        UpdateProgressBar(ProgressBar, NotifyContext);
        Result = TRUE;
        break;

    case WM_COMMAND:
        if (BN_CLICKED == HIWORD(wParam) && IDC_END_NOW == LOWORD(wParam))
        {
            NotifyContext = (PNOTIFY_CONTEXT)GetWindowLongPtrW(Dlg, DWLP_USER);
            NotifyContext->EndNowResult = QUERY_RESULT_FORCE;
            MY_DPRINT("Closing progress dlg by hand\n");
            SendMessageW(Dlg, WM_CLOSE, 0, 0);
            Result = TRUE;
        }
        else
        {
            Result = FALSE;
        }
        break;

    case WM_CLOSE:
        MY_DPRINT("WM_CLOSE\n");
        DestroyWindow(Dlg);
        Result = TRUE;
        break;

    case WM_DESTROY:
        MY_DPRINT("WM_DESTROY\n");
        NotifyContext = (PNOTIFY_CONTEXT)GetWindowLongPtrW(Dlg, DWLP_USER);
        NotifyContext->Dlg = NULL;
        KillTimer(Dlg, 0);
        PostQuitMessage(NotifyContext->EndNowResult);
        Result = TRUE;
        break;

    default:
        Result = FALSE;
        break;
    }

    return Result;
}

static DWORD WINAPI
EndNowThreadProc(LPVOID Parameter)
{
    PNOTIFY_CONTEXT NotifyContext = (PNOTIFY_CONTEXT)Parameter;
    MSG Msg;

#if 0
    SetThreadDesktop(NotifyContext->Desktop);
    SwitchDesktop(NotifyContext->Desktop);
#else
    /* For now show the end task dialog in the active desktop */
    NtUserSetInformationThread(NtCurrentThread(),
                               UserThreadUseActiveDesktop,
                               NULL,
                               0);
#endif

    CallInitCommonControls();
    NotifyContext->Dlg = CreateDialogParam(UserServerDllInstance,
                                           MAKEINTRESOURCE(IDD_END_NOW), NULL,
                                           EndNowDlgProc, (LPARAM)NotifyContext);
    if (NotifyContext->Dlg == NULL)
        return 0;

    ShowWindow(NotifyContext->Dlg, SW_SHOWNORMAL);

    while (GetMessageW(&Msg, NULL, 0, 0))
    {
        if (!IsDialogMessage(NotifyContext->Dlg, &Msg))
        {
            TranslateMessage(&Msg);
            DispatchMessageW(&Msg);
        }
    }

    return Msg.wParam;
}

static DWORD WINAPI
SendClientShutdown(LPVOID Parameter)
{
    PMESSAGE_CONTEXT Context = (PMESSAGE_CONTEXT)Parameter;
    DWORD_PTR Result;

    /* If the shutdown is aborted, just notify the process, there is no need to wait */
    if ((Context->wParam & (MCS_QUERYENDSESSION | MCS_ENDSESSION)) == 0)
    {
        DPRINT("Called WM_CLIENTSHUTDOWN with wParam == 0 ...\n");
        SendNotifyMessageW(Context->Wnd, WM_CLIENTSHUTDOWN,
                           Context->wParam, Context->lParam);
        return QUERY_RESULT_CONTINUE;
    }

    if (SendMessageTimeoutW(Context->Wnd, WM_CLIENTSHUTDOWN,
                            Context->wParam, Context->lParam,
                            SMTO_NORMAL, Context->Timeout, &Result))
    {
        DWORD Ret;

        if (Context->wParam & MCS_QUERYENDSESSION)
        {
            /* WM_QUERYENDSESSION case */
            switch (Result)
            {
                case MCSR_DONOTSHUTDOWN:
                    Ret = QUERY_RESULT_ABORT;
                    break;

                case MCSR_GOODFORSHUTDOWN:
                case MCSR_SHUTDOWNFINISHED:
                default:
                    Ret = QUERY_RESULT_CONTINUE;
            }
        }
        else
        {
            /* WM_ENDSESSION case */
            Ret = QUERY_RESULT_CONTINUE;
        }

        DPRINT("SendClientShutdown -- Return == %s\n",
                  Ret == QUERY_RESULT_CONTINUE ? "Continue" : "Abort");
        return Ret;
    }

    DPRINT1("SendClientShutdown -- Error == %s\n",
              GetLastError() == 0 ? "Timeout" : "error");

    return (GetLastError() == 0 ? QUERY_RESULT_TIMEOUT : QUERY_RESULT_ERROR);
}

static BOOL
NotifyTopLevelWindow(HWND Wnd, PNOTIFY_CONTEXT NotifyContext)
{
    MESSAGE_CONTEXT MessageContext;
    DWORD Now, Passed;
    DWORD Timeout, WaitStatus;
    HANDLE MessageThread;
    HANDLE Threads[2];

    SetForegroundWindow(Wnd);

    Now = GetTickCount();
    if (NotifyContext->StartTime == 0)
        NotifyContext->StartTime = Now;

    /*
     * Note: Passed is computed correctly even when GetTickCount()
     * wraps due to unsigned arithmetic.
     */
    Passed = Now - NotifyContext->StartTime;
    MessageContext.Wnd = Wnd;
    MessageContext.Msg = NotifyContext->Msg;
    MessageContext.wParam = NotifyContext->wParam;
    MessageContext.lParam = NotifyContext->lParam;
    MessageContext.Timeout = NotifyContext->ShutdownSettings->HungAppTimeout;
    if (!NotifyContext->ShutdownSettings->AutoEndTasks)
    {
        MessageContext.Timeout += NotifyContext->ShutdownSettings->WaitToKillAppTimeout;
    }
    if (Passed < MessageContext.Timeout)
    {
        MessageContext.Timeout -= Passed;
        MessageThread = CreateThread(NULL, 0, SendClientShutdown,
                                     (LPVOID)&MessageContext, 0, NULL);
        if (MessageThread == NULL)
        {
            NotifyContext->QueryResult = QUERY_RESULT_ERROR;
            return FALSE;
        }
        Timeout = NotifyContext->ShutdownSettings->HungAppTimeout;
        if (Passed < Timeout)
        {
            Timeout -= Passed;
            WaitStatus = WaitForSingleObjectEx(MessageThread, Timeout, FALSE);
        }
        else
        {
            WaitStatus = WAIT_TIMEOUT;
        }
        if (WAIT_TIMEOUT == WaitStatus)
        {
            NotifyContext->WndClient = Wnd;
            if (NotifyContext->UIThread == NULL && NotifyContext->ShowUI)
            {
                NotifyContext->UIThread = CreateThread(NULL, 0,
                                                       EndNowThreadProc,
                                                       (LPVOID)NotifyContext,
                                                       0, NULL);
            }
            Threads[0] = MessageThread;
            Threads[1] = NotifyContext->UIThread;
            WaitStatus = WaitForMultipleObjectsEx(NotifyContext->UIThread == NULL ?
                                                  1 : 2,
                                                  Threads, FALSE, INFINITE,
                                                  FALSE);
            if (WaitStatus == WAIT_OBJECT_0)
            {
                if (!GetExitCodeThread(MessageThread, &NotifyContext->QueryResult))
                {
                    NotifyContext->QueryResult = QUERY_RESULT_ERROR;
                }
            }
            else if (WaitStatus == WAIT_OBJECT_0 + 1)
            {
                if (!GetExitCodeThread(NotifyContext->UIThread,
                                       &NotifyContext->QueryResult))
                {
                    NotifyContext->QueryResult = QUERY_RESULT_ERROR;
                }
            }
            else
            {
                NotifyContext->QueryResult = QUERY_RESULT_ERROR;
            }
            if (WaitStatus != WAIT_OBJECT_0)
            {
                TerminateThread(MessageThread, QUERY_RESULT_TIMEOUT);
            }
        }
        else if (WaitStatus == WAIT_OBJECT_0)
        {
            if (!GetExitCodeThread(MessageThread,
                                   &NotifyContext->QueryResult))
            {
                NotifyContext->QueryResult = QUERY_RESULT_ERROR;
            }
        }
        else
        {
            NotifyContext->QueryResult = QUERY_RESULT_ERROR;
        }
        CloseHandle(MessageThread);
    }
    else
    {
        NotifyContext->QueryResult = QUERY_RESULT_TIMEOUT;
    }

    DPRINT("NotifyContext->QueryResult == %d\n", NotifyContext->QueryResult);
    return (NotifyContext->QueryResult == QUERY_RESULT_CONTINUE);
}

static BOOLEAN
IsConsoleMode(VOID)
{
    return (BOOLEAN)NtUserCallNoParam(NOPARAM_ROUTINE_ISCONSOLEMODE);
}

/************************************************/


#define MAX_TOPLEVEL_WINDOWS 128

typedef struct tagTOPLEVEL_LIST
{
    ULONG Count;
    HWND Windows[MAX_TOPLEVEL_WINDOWS];
} TOPLEVEL_LIST, *PTOPLEVEL_LIST;

static BOOL CALLBACK
CollectTopLevelWnd(IN HWND hWnd, IN LPARAM lParam)
{
    PTOPLEVEL_LIST List = (PTOPLEVEL_LIST)lParam;

    /* Unowned windows only, as FindTopLevelWnd does */
    if (GetWindow(hWnd, GW_OWNER) == NULL && List->Count < MAX_TOPLEVEL_WINDOWS)
        List->Windows[List->Count++] = hWnd;
    return TRUE;
}

/*
 * Windows sends the end-session messages to EVERY top-level window of the
 * thread (a program's visible window, its hidden helper windows, ...), not
 * only to the first one found. Programs such as Firefox rely on this: the
 * window that handles WM_QUERYENDSESSION/WM_ENDSESSION is not necessarily the
 * first top-level window in z-order.
 */
static BOOL
ThreadShutdownNotify(IN PCSR_THREAD CsrThread,
                     IN ULONG Flags,
                     IN ULONG Flags2,
                     IN PNOTIFY_CONTEXT Context)
{
    PTOPLEVEL_LIST List;
    ULONG i;
    BOOL Notified = FALSE;

    List = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*List));
    if (!List)
        return FALSE;
    List->Count = 0;

    EnumThreadWindows(HandleToUlong(CsrThread->ClientId.UniqueThread),
                      CollectTopLevelWnd, (LPARAM)List);

    Context->wParam = Flags2;
    Context->lParam = (0 != (Flags & EWX_CALLER_WINLOGON_LOGOFF) ?
                       ENDSESSION_LOGOFF : 0);
    Context->ShowUI = !IsConsoleMode() && (Flags2 & (MCS_QUERYENDSESSION | MCS_ENDSESSION));

    for (i = 0; i < List->Count; i++)
    {
        HWND TopWnd = List->Windows[i];

        /* The window may have been destroyed by a previous message */
        if (!IsWindow(TopWnd))
            continue;
        Notified = TRUE;

        /* Each window gets its own timeouts */
        Context->StartTime = 0;
        Context->UIThread = NULL;
        Context->Dlg = NULL;
        Context->QueryResult = QUERY_RESULT_CONTINUE;

        NotifyTopLevelWindow(TopWnd, Context);

/******************************************************************************/
#if 1
    if (Context->UIThread)
    {
        MY_DPRINT("Context->UIThread != NULL\n");
        if (Context->Dlg)
        {
            MY_DPRINT("Sending WM_CLOSE because Dlg is != NULL\n");
            SendMessageW(Context->Dlg, WM_CLOSE, 0, 0);
        }
        else
        {
            MY_DPRINT("Terminating UIThread thread with QUERY_RESULT_ERROR\n");
            TerminateThread(Context->UIThread, QUERY_RESULT_ERROR);
        }
        CloseHandle(Context->UIThread);
        /**/Context->UIThread = NULL;/**/
        /**/Context->Dlg = NULL;/**/
    }
#endif
/******************************************************************************/

#if 0
    MY_DPRINT("Switch back to old desktop 0x%x\n", Context->OldDesktop);
    SwitchDesktop(Context->OldDesktop);
    MY_DPRINT("Switched back ok\n");
#endif


        /*
         * Stop on an abort, or when the thread did not answer (timeout, error,
         * forced end): its other windows cannot answer either.
         */
        if (Context->QueryResult != QUERY_RESULT_CONTINUE)
            break;
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, List);
    return Notified;
}

static ULONG
NotifyUserProcessForShutdown(PCSR_PROCESS CsrProcess,
                             PSHUTDOWN_SETTINGS ShutdownSettings,
                             UINT Flags)
{
    DWORD QueryResult = QUERY_RESULT_CONTINUE;
    PCSR_PROCESS Process;
    PCSR_THREAD Thread;
    PLIST_ENTRY NextEntry;
    NOTIFY_CONTEXT Context;
    BOOL FoundWindows = FALSE;

    /* In case we make a forced shutdown, just kill the process */
    if (Flags & EWX_FORCE)
        return CsrShutdownCsrProcess;

    Context.ShutdownSettings = ShutdownSettings;
    Context.QueryResult = QUERY_RESULT_CONTINUE; // We continue shutdown by default.

    /* Lock the process */
    CsrLockProcessByClientId(CsrProcess->ClientId.UniqueProcess, &Process);

    /* Send first the QUERYENDSESSION messages to all the threads of the process */
    MY_DPRINT2("Sending the QUERYENDSESSION messages...\n");

    NextEntry = CsrProcess->ThreadList.Flink;
    while (NextEntry != &CsrProcess->ThreadList)
    {
        /* Get the current thread entry */
        Thread = CONTAINING_RECORD(NextEntry, CSR_THREAD, Link);

        /* If the thread is being terminated, just skip it */
        if (Thread->Flags & CsrThreadTerminated)
        {
            NextEntry = NextEntry->Flink;
            continue;
        }

        /* Reference the thread and temporarily unlock the process */
        CsrReferenceThread(Thread);
        CsrUnlockProcess(Process);

        Context.QueryResult = QUERY_RESULT_CONTINUE;
        if (ThreadShutdownNotify(Thread, Flags, MCS_QUERYENDSESSION, &Context))
        {
            FoundWindows = TRUE;
        }

        /* Lock the process again */
        CsrLockProcessByClientId(CsrProcess->ClientId.UniqueProcess, &Process);

        /*
         * Other threads of the process come and go while it is unlocked, so the next
         * entry is only known now: the referenced thread is still in the list.
         */
        NextEntry = Thread->Link.Flink;
        CsrDereferenceThread(Thread);

        // FIXME: Analyze Context.QueryResult !!
        /**/if (Context.QueryResult == QUERY_RESULT_ABORT) goto Quit;/**/
    }

    if (!FoundWindows)
    {
        /* We looped all threads but no top level window was found so we didn't send any message */
        /* Let the console server run the generic process shutdown handler */
        CsrUnlockProcess(Process);
        return CsrShutdownNonCsrProcess;
    }

    QueryResult = Context.QueryResult;
    MY_DPRINT2("QueryResult = %s\n",
               QueryResult == QUERY_RESULT_ABORT ? "Abort" : "Continue");

    /* Now send the ENDSESSION messages to the threads */
    MY_DPRINT2("Now sending the ENDSESSION messages...\n");

    NextEntry = CsrProcess->ThreadList.Flink;
    while (NextEntry != &CsrProcess->ThreadList)
    {
        /* Get the current thread entry */
        Thread = CONTAINING_RECORD(NextEntry, CSR_THREAD, Link);

        /* If the thread is being terminated, just skip it */
        if (Thread->Flags & CsrThreadTerminated)
        {
            NextEntry = NextEntry->Flink;
            continue;
        }

        /* Reference the thread and temporarily unlock the process */
        CsrReferenceThread(Thread);
        CsrUnlockProcess(Process);

        Context.QueryResult = QUERY_RESULT_CONTINUE;
        ThreadShutdownNotify(Thread, Flags,
                             (QUERY_RESULT_ABORT != QueryResult) ? MCS_ENDSESSION : 0,
                             &Context);

        /* Lock the process again; the next entry is only known now, see above */
        CsrLockProcessByClientId(CsrProcess->ClientId.UniqueProcess, &Process);
        NextEntry = Thread->Link.Flink;
        CsrDereferenceThread(Thread);
    }

Quit:
    /* Unlock the process */
    CsrUnlockProcess(Process);

#if 0
    if (Context.UIThread)
    {
        if (Context.Dlg)
        {
            SendMessageW(Context.Dlg, WM_CLOSE, 0, 0);
        }
        else
        {
            TerminateThread(Context.UIThread, QUERY_RESULT_ERROR);
        }
        CloseHandle(Context.UIThread);
    }
#endif

    /* Kill the process unless we abort shutdown */
    if (QueryResult == QUERY_RESULT_ABORT)
        return CsrShutdownCancelled;

    return CsrShutdownCsrProcess;
}

static NTSTATUS FASTCALL
UserExitReactOS(PCSR_THREAD CsrThread, UINT Flags)
{
    NTSTATUS Status;
    LUID CallerLuid;

    DWORD ProcessId = HandleToUlong(CsrThread->ClientId.UniqueProcess);
    DWORD ThreadId  = HandleToUlong(CsrThread->ClientId.UniqueThread);

    DPRINT1("SrvExitWindowsEx(ClientId: %lx.%lx, Flags: 0x%x)\n",
            ProcessId, ThreadId, Flags);

    /*
     * Check for flags validity
     */

    if (Flags & EWX_CALLER_WINLOGON)
    {
        /* Only Winlogon can call this */
        if (ProcessId != LogonProcessId)
        {
            DPRINT1("SrvExitWindowsEx call not from Winlogon\n");
            return STATUS_ACCESS_DENIED;
        }
    }

    /* Implicitely add the shutdown flag when we poweroff or reboot */
    if (Flags & (EWX_POWEROFF | EWX_REBOOT))
        Flags |= EWX_SHUTDOWN;

    /*
     * Impersonate and retrieve the caller's LUID so that
     * we can only shutdown processes in its context.
     */
    if (!CsrImpersonateClient(NULL))
        return STATUS_BAD_IMPERSONATION_LEVEL;

    Status = CsrGetProcessLuid(NULL, &CallerLuid);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Unable to get caller LUID, Status = 0x%08x\n", Status);
        goto Quit;
    }

    DPRINT("Caller LUID is: %lx.%lx\n", CallerLuid.HighPart, CallerLuid.LowPart);

    /* Shutdown loop */
    while (TRUE)
    {
        /* Notify Win32k and potentially Winlogon of the shutdown */
        Status = NtUserSetInformationThread(CsrThread->ThreadHandle,
                                            UserThreadInitiateShutdown,
                                            &Flags, sizeof(Flags));
        DPRINT("Win32k says: %lx\n", Status);
        switch (Status)
        {
            /* We cannot wait here, the caller should start a new thread */
            case STATUS_CANT_WAIT:
                DPRINT1("NtUserSetInformationThread returned STATUS_CANT_WAIT\n");
                goto Quit;

            /* Shutdown is in progress */
            case STATUS_PENDING:
                DPRINT1("NtUserSetInformationThread returned STATUS_PENDING\n");
                goto Quit;

            /* Abort */
            case STATUS_RETRY:
            {
                DPRINT1("NtUserSetInformationThread returned STATUS_RETRY\n");
                UNIMPLEMENTED;
                continue;
            }

            default:
            {
                if (!NT_SUCCESS(Status))
                {
                    // FIXME: Use some UserSetLastNTError or SetLastNtError
                    // that we have defined for user32 or win32k usage only...
                    SetLastError(RtlNtStatusToDosError(Status));
                    goto Quit;
                }
            }
        }

        /* All good */
        break;
    }

    /*
     * OK we can continue. Now magic happens:
     *
     * Terminate all Win32 processes, stop if we find one kicking
     * and screaming it doesn't want to die.
     *
     * This function calls the ShutdownProcessCallback callback of
     * each CSR server for each Win32 process.
     */
    Status = CsrShutdownProcesses(&CallerLuid, Flags);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to shutdown processes, Status = 0x%08x\n", Status);
    }

    // FIXME: If Status == STATUS_CANCELLED, call RecordShutdownReason

    /* Tell Win32k and potentially Winlogon that we're done */
    NtUserSetInformationThread(CsrThread->ThreadHandle,
                               UserThreadEndShutdown,
                               &Status, sizeof(Status));

    DPRINT("SrvExitWindowsEx returned 0x%08x\n", Status);

Quit:
    /* We are done */
    CsrRevertToSelf();
    return Status;
}


ULONG
NTAPI
UserClientShutdown(IN PCSR_PROCESS CsrProcess,
                   IN ULONG Flags,
                   IN BOOLEAN FirstPhase)
{
    ULONG result;

    DPRINT("UserClientShutdown(0x%p, 0x%x, %s) - [0x%x, 0x%x], ShutdownFlags: %lu\n",
            CsrProcess, Flags, FirstPhase ? "FirstPhase" : "LastPhase",
            CsrProcess->ClientId.UniqueProcess, CsrProcess->ClientId.UniqueThread,
            CsrProcess->ShutdownFlags);

    /*
     * Check for process validity
     */

    /* Do not kill system processes when a user is logging off */
    if ((Flags & EWX_SHUTDOWN) == EWX_LOGOFF &&
        (CsrProcess->ShutdownFlags & (SHUTDOWN_OTHERCONTEXT | SHUTDOWN_SYSTEMCONTEXT)))
    {
        DPRINT("Do not kill a system process in a logoff request!\n");
        return CsrShutdownNonCsrProcess;
    }

    /* Do not kill Winlogon */
    if (CsrProcess->ClientId.UniqueProcess == UlongToHandle(LogonProcessId))
    {
        DPRINT("Not killing Winlogon; CsrProcess->ShutdownFlags = %lu\n",
               CsrProcess->ShutdownFlags);

        /* Returning CsrShutdownCsrProcess means that we handled this process by doing nothing */
        /* This will mark winlogon as processed so consrv won't be notified again for it */
        CsrDereferenceProcess(CsrProcess);
        return CsrShutdownCsrProcess;
    }

    /* Notify the process for shutdown if needed */
    result = NotifyUserProcessForShutdown(CsrProcess, &ShutdownSettings, Flags);
    if (result == CsrShutdownCancelled || result == CsrShutdownNonCsrProcess)
    {
        if (result == CsrShutdownCancelled)
            DPRINT1("Process 0x%x aborted shutdown\n", CsrProcess->ClientId.UniqueProcess);
        return result;
    }

    /* Terminate this process */
#if DBG
    {
        WCHAR buffer[MAX_PATH];
        if (!GetProcessImageFileNameW(CsrProcess->ProcessHandle, buffer, ARRAYSIZE(buffer)))
        {
            DPRINT1("Terminating process %x\n", CsrProcess->ClientId.UniqueProcess);
        }
        else
        {
            DPRINT1("Terminating process %x (%S)\n", CsrProcess->ClientId.UniqueProcess, buffer);
        }
    }
#endif
    NtTerminateProcess(CsrProcess->ProcessHandle, 0);
    WaitForSingleObject(CsrProcess->ProcessHandle, ShutdownSettings.ProcessTerminateTimeout);

    /* We are done */
    CsrDereferenceProcess(CsrProcess);
    return CsrShutdownCsrProcess;
}


/* PUBLIC SERVER APIS *********************************************************/

/* API_NUMBER: UserpExitWindowsEx */
CSR_API(SrvExitWindowsEx)
{
    NTSTATUS Status;
    PUSER_EXIT_REACTOS ExitReactOSRequest = &((PUSER_API_MESSAGE)ApiMessage)->Data.ExitReactOSRequest;

    Status = NtUserSetInformationThread(NtCurrentThread(),
                                        UserThreadUseActiveDesktop,
                                        NULL,
                                        0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to set thread desktop!\n");
        return Status;
    }

    Status = UserExitReactOS(CsrGetClientThread(), ExitReactOSRequest->Flags);
    ExitReactOSRequest->Success   = NT_SUCCESS(Status);
    ExitReactOSRequest->LastError = GetLastError();

    NtUserSetInformationThread(NtCurrentThread(), UserThreadRestoreDesktop, NULL, 0);

    return Status;
}

/*
 * Whether the process that owns the window may be ended on behalf of the caller. A window that
 * is invalid, is owned by csrss, or lives in another session is refused like an invalid handle
 * (Windows 10: FALSE, ERROR_INVALID_HANDLE). A window of the caller's own process is not
 * refused, and neither is a window of a process of a higher integrity level: measured, a Low
 * caller can end the window of a High process.
 */
static BOOL
EndTaskIsTargetValid(
    IN PCSR_THREAD CsrThread,
    IN HWND hWnd,
    OUT PDWORD ProcessId)
{
    ULONG_PTR TargetPid;
    HANDLE hTarget;
    PROCESS_SESSION_INFORMATION TargetSession, CallerSession;
    NTSTATUS Status;

    TargetPid = NtUserQueryWindow(hWnd, QUERY_WINDOW_UNIQUE_PROCESS_ID);
    if (TargetPid == 0 ||
        TargetPid == HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess))
    {
        return FALSE;
    }

    *ProcessId = (DWORD)TargetPid;
    hTarget = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, *ProcessId);
    if (!hTarget)
        return FALSE;

    Status = NtQueryInformationProcess(hTarget,
                                       ProcessSessionInformation,
                                       &TargetSession,
                                       sizeof(TargetSession),
                                       NULL);
    CloseHandle(hTarget);
    if (!NT_SUCCESS(Status))
        return FALSE;

    Status = NtQueryInformationProcess(CsrThread->Process->ProcessHandle,
                                       ProcessSessionInformation,
                                       &CallerSession,
                                       sizeof(CallerSession),
                                       NULL);
    if (!NT_SUCCESS(Status))
        return FALSE;

    return TargetSession.SessionId == CallerSession.SessionId;
}

/*
 * With fForce the process of the window is ended at once, without WM_CLOSE (Windows 10: TRUE,
 * exit code 0, 0 ms, whatever the window does). The caller must be allowed to terminate it,
 * which is checked by opening the process while impersonating the caller.
 */
static BOOL
EndTaskTerminate(
    IN PCSR_THREAD CsrThread,
    IN DWORD ProcessId,
    OUT PDWORD LastError)
{
    HANDLE hTarget;
    BOOL Ret = FALSE;

    if (!CsrImpersonateClient(CsrThread))
    {
        *LastError = ERROR_ACCESS_DENIED;
        return FALSE;
    }
    hTarget = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessId);
    *LastError = hTarget ? ERROR_SUCCESS : GetLastError();
    CsrRevertToSelf();

    if (hTarget)
    {
        Ret = TerminateProcess(hTarget, 0);
        if (!Ret)
            *LastError = GetLastError();
        CloseHandle(hTarget);
    }
    return Ret;
}

/*
 * EndTask without fForce on a window that does not go away. Measured on Windows 10 22H2: the
 * call keeps waiting, and after about five seconds (the hung-app timeout) a dialog "End
 * Program - <window title>" ("This program is not responding", End Now / Cancel) appears,
 * whether the window does not pump messages or pumps them and ignores WM_CLOSE. The call
 * returns TRUE once the window is gone, also when something else ended its process.
 * The dialog runs on its own thread, so the waiting thread never depends on it, and it never
 * sends a message to the window (the title is read with InternalGetWindowText). The two
 * threads share END_TASK_UI by reference count: whichever lets go last frees it.
 */
typedef struct _END_TASK_UI
{
    LONG Refs;
    HWND hWndTarget;
    HANDLE hReady;          /* set once the dialog exists, or could not be created */
    BOOL Shown;             /* the dialog was created */
    volatile LONG Choice;   /* 0 = none yet, IDC_END_NOW, IDCANCEL */
    volatile LONG Cancelled;/* the waiting thread no longer wants the dialog */
} END_TASK_UI, *PEND_TASK_UI;

static VOID
EndTaskUiRelease(PEND_TASK_UI Ui)
{
    if (InterlockedDecrement(&Ui->Refs) == 0)
    {
        CloseHandle(Ui->hReady);
        RtlFreeHeap(UserServerHeap, 0, Ui);
    }
}

static INT_PTR CALLBACK
NotRespondingDlgProc(HWND Dlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    PEND_TASK_UI Ui;

    switch (Msg)
    {
    case WM_INITDIALOG:
    {
        WCHAR Title[256];
        int Len;

        Ui = (PEND_TASK_UI)lParam;
        SetWindowLongPtrW(Dlg, DWLP_USER, (LONG_PTR)Ui);
        Len = GetWindowTextW(Dlg, Title, ARRAYSIZE(Title));
        if (Len >= 0 && Len < (int)ARRAYSIZE(Title) - 1)
        {
            InternalGetWindowText(Ui->hWndTarget, Title + Len, ARRAYSIZE(Title) - Len);
            SetWindowTextW(Dlg, Title);
        }
        return TRUE;
    }

    case WM_COMMAND:
        if (HIWORD(wParam) == BN_CLICKED &&
            (LOWORD(wParam) == IDC_END_NOW || LOWORD(wParam) == IDCANCEL))
        {
            Ui = (PEND_TASK_UI)GetWindowLongPtrW(Dlg, DWLP_USER);
            InterlockedCompareExchange(&Ui->Choice, LOWORD(wParam), 0);
            DestroyWindow(Dlg);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        /* The close box answers Cancel */
        Ui = (PEND_TASK_UI)GetWindowLongPtrW(Dlg, DWLP_USER);
        InterlockedCompareExchange(&Ui->Choice, IDCANCEL, 0);
        DestroyWindow(Dlg);
        return TRUE;

    case WM_DESTROY:
        PostQuitMessage(0);
        return TRUE;
    }
    return FALSE;
}

/* The dialog thread. It ends when the dialog is answered, or when the waiting thread posts it
 * WM_QUIT (the window went away); either way it destroys its own dialog. */
static DWORD WINAPI
NotRespondingThreadProc(LPVOID Parameter)
{
    PEND_TASK_UI Ui = (PEND_TASK_UI)Parameter;
    HWND Dlg = NULL;
    MSG Msg;

    if (NT_SUCCESS(NtUserSetInformationThread(NtCurrentThread(), UserThreadUseActiveDesktop, NULL, 0)))
    {
        /* The queue must exist before Cancelled is checked (win32k already made it in the call
         * above; this makes sure): a WM_QUIT the waiting thread posts after setting Cancelled
         * then reaches this thread, and one it posted earlier finds Cancelled set below. Keep
         * both Cancelled checks. */
        PeekMessageW(&Msg, NULL, 0, 0, PM_NOREMOVE);
        if (!Ui->Cancelled)
            Dlg = CreateDialogParamW(UserServerDllInstance, MAKEINTRESOURCEW(IDD_NOT_RESPONDING),
                                     NULL, NotRespondingDlgProc, (LPARAM)Ui);
        Ui->Shown = (Dlg != NULL);
        SetEvent(Ui->hReady);
        if (Dlg && !Ui->Cancelled)
        {
            ShowWindow(Dlg, SW_SHOWNORMAL);
            SetForegroundWindow(Dlg);
            while (GetMessageW(&Msg, NULL, 0, 0) > 0)
            {
                if (!IsDialogMessageW(Dlg, &Msg))
                {
                    TranslateMessage(&Msg);
                    DispatchMessageW(&Msg);
                }
            }
        }
        if (Dlg && IsWindow(Dlg))
            DestroyWindow(Dlg);
        NtUserSetInformationThread(NtCurrentThread(), UserThreadRestoreDesktop, NULL, 0);
    }
    else
    {
        SetEvent(Ui->hReady);
    }

    EndTaskUiRelease(Ui);
    return 0;
}

/* Start the not-responding dialog; NULL when it cannot be shown */
static HANDLE
EndTaskStartUi(HWND hWnd, PEND_TASK_UI *pUi, PDWORD ThreadId)
{
    PEND_TASK_UI Ui;
    HANDLE hThread;

    *pUi = NULL;
    Ui = RtlAllocateHeap(UserServerHeap, HEAP_ZERO_MEMORY, sizeof(*Ui));
    if (!Ui)
        return NULL;
    Ui->hWndTarget = hWnd;
    Ui->Refs = 2;   /* the waiting thread and the dialog thread */
    Ui->hReady = CreateEventW(NULL, TRUE, FALSE, NULL);
    hThread = Ui->hReady ? CreateThread(NULL, 0, NotRespondingThreadProc, Ui, 0, ThreadId) : NULL;
    if (!hThread)
    {
        if (Ui->hReady)
            CloseHandle(Ui->hReady);
        RtlFreeHeap(UserServerHeap, 0, Ui);
        return NULL;
    }
    *pUi = Ui;
    return hThread;
}

/*
 * Wait until the window is gone (TRUE), the caller has ended (FALSE), or the user answered the
 * not-responding dialog (End Now: the process is ended as with fForce; Cancel: FALSE). When the
 * dialog cannot be shown the wait for the window goes on, as without it. Every wait here is
 * bounded; the dialog thread is never waited for without a timeout.
 */
static BOOL
EndTaskWaitForWindow(
    IN PCSR_THREAD CsrThread,
    IN HWND hWnd,
    IN DWORD ProcessId,
    OUT PDWORD LastError)
{
    PEND_TASK_UI Ui = NULL;
    HANDLE hUiThread = NULL;
    DWORD UiThreadId = 0;
    DWORD Start = GetTickCount();
    BOOL Tried = FALSE, Ret = FALSE;
    HANDLE Waits[2];
    DWORD Wait;

    Waits[0] = CsrThread->ThreadHandle;
    Waits[1] = CsrThread->Process->ProcessHandle;
    *LastError = ERROR_SUCCESS;
    for (;;)
    {
        if (!IsWindow(hWnd))
        {
            Ret = TRUE;
            break;
        }
        /* Give up when the calling thread or its process has ended (should the thread handle
         * not allow a wait, watch the process alone) */
        Wait = WaitForMultipleObjects(2, Waits, FALSE, 50);
        if (Wait == WAIT_FAILED)
            Wait = WaitForSingleObject(Waits[1], 50);
        if (Wait == WAIT_OBJECT_0 || Wait == WAIT_OBJECT_0 + 1)
            break;

        if (!Tried && GetTickCount() - Start >= ShutdownSettings.HungAppTimeout)
        {
            Tried = TRUE;
            hUiThread = EndTaskStartUi(hWnd, &Ui, &UiThreadId);
        }

        if (hUiThread && WaitForSingleObject(hUiThread, 0) == WAIT_OBJECT_0)
        {
            if (!Ui->Shown)
            {
                /* No dialog: keep waiting for the window */
                CloseHandle(hUiThread);
                hUiThread = NULL;
                EndTaskUiRelease(Ui);
                Ui = NULL;
                continue;
            }
            if (Ui->Choice == IDC_END_NOW)
            {
                Ret = EndTaskTerminate(CsrThread, ProcessId, LastError);
            }
            else
            {
                /* Cancel, the close box, or the dialog went away otherwise: the call gives up
                 * (not measured on Windows) */
                *LastError = ERROR_CANCELLED;
            }
            break;
        }
    }

    if (hUiThread)
    {
        /* Take the dialog down when the window went away (or the caller ended) while it was
         * up, or keep it from coming up: ask its thread, which owns the dialog, rather than a
         * window handle. A WM_QUIT posted before that thread has a queue is lost, so Cancelled
         * is set first and the thread checks it once its queue exists. */
        InterlockedExchange(&Ui->Cancelled, TRUE);
        PostThreadMessageW(UiThreadId, WM_QUIT, 0, 0);
        if (WaitForSingleObject(Ui->hReady, 5000) == WAIT_OBJECT_0)
            PostThreadMessageW(UiThreadId, WM_QUIT, 0, 0);
        if (WaitForSingleObject(hUiThread, 5000) != WAIT_OBJECT_0)
            DPRINT1("EndTask: the not-responding dialog did not close\n");
        CloseHandle(hUiThread);
    }
    if (Ui)
        EndTaskUiRelease(Ui);
    return Ret;
}

/* API_NUMBER: UserpEndTask */
CSR_API(SrvEndTask)
{
    PUSER_END_TASK EndTaskRequest = &((PUSER_API_MESSAGE)ApiMessage)->Data.EndTaskRequest;
    PCSR_THREAD CsrThread = CsrGetClientThread();
    HWND hWnd = EndTaskRequest->WndHandle;
    GUITHREADINFO GuiInfo;
    DWORD ProcessId;
    NTSTATUS Status;

    EndTaskRequest->Success   = FALSE;
    EndTaskRequest->LastError = ERROR_INVALID_HANDLE;

    Status = NtUserSetInformationThread(NtCurrentThread(),
                                        UserThreadUseActiveDesktop,
                                        NULL,
                                        0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to set thread desktop!\n");
        return Status;
    }

    /* Windows 10: a thread that has not made any user32 call yet (it is not a GUI thread) gets
     * FALSE and ERROR_INVALID_HANDLE, whatever the window. */
    GuiInfo.cbSize = sizeof(GuiInfo);
    if (!GetGUIThreadInfo(HandleToUlong(CsrThread->ClientId.UniqueThread), &GuiInfo))
        goto Quit;

    if (!EndTaskIsTargetValid(CsrThread, hWnd, &ProcessId))
        goto Quit;

    if (EndTaskRequest->Force)
    {
        DWORD LastError;

        EndTaskRequest->Success   = EndTaskTerminate(CsrThread, ProcessId, &LastError);
        EndTaskRequest->LastError = LastError;
    }
    else
    {
        DWORD LastError;

        /* Ask the window to close without waiting for it to answer: a window whose thread does
         * not pump messages must not hold this server thread (a plain SendMessage waited for
         * ever, and so did the caller, with no way out). The message stays queued until the
         * window's thread reads it. Then wait, like Windows, until the window is gone. */
        SendNotifyMessageW(hWnd, WM_CLOSE, 0, 0);
        EndTaskRequest->Success   = EndTaskWaitForWindow(CsrThread, hWnd, ProcessId, &LastError);
        EndTaskRequest->LastError = LastError;
    }

Quit:
    NtUserSetInformationThread(NtCurrentThread(), UserThreadRestoreDesktop, NULL, 0);

    return STATUS_SUCCESS;
}

/* API_NUMBER: UserpRecordShutdownReason */
CSR_API(SrvRecordShutdownReason)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

/* EOF */
