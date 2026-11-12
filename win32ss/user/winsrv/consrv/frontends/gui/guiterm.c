/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Console Server DLL
 * FILE:            win32ss/user/winsrv/consrv/frontends/gui/guiterm.c
 * PURPOSE:         GUI Terminal Front-End
 * PROGRAMMERS:     Gé van Geldorp
 *                  Johannes Anderwald
 *                  Jeffrey Morlan
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/* INCLUDES *******************************************************************/

#include <consrv.h>

#define NDEBUG
#include <debug.h>

#include "concfg/font.h"
#include "guiterm.h"
#include "resource.h"

#define PM_CREATE_CONSOLE     (WM_APP + 1)
#define PM_DESTROY_CONSOLE    (WM_APP + 2)


/* GLOBALS ********************************************************************/

typedef struct _GUI_INIT_INFO
{
    HANDLE GuiThreadStartupEvent;
    ULONG_PTR InputThreadId;
    HWINSTA WinSta;
    HDESK Desktop;
    HICON hIcon;
    HICON hIconSm;
    BOOLEAN IsWindowVisible;
    GUI_CONSOLE_INFO TermInfo;
} GUI_INIT_INFO, *PGUI_INIT_INFO;

static BOOL ConsInitialized = FALSE;

extern HICON   ghDefaultIcon;
extern HICON   ghDefaultIconSm;
extern HCURSOR ghDefaultCursor;

BOOLEAN
RegisterConWndClass(IN HINSTANCE hInstance);
BOOLEAN
UnRegisterConWndClass(HINSTANCE hInstance);

/* FUNCTIONS ******************************************************************/

VOID
GuiConsoleMoveWindow(PGUI_CONSOLE_DATA GuiData)
{
    /* Move the window if needed (not positioned by the system) */
    if (!GuiData->GuiInfo.AutoPosition)
    {
        SetWindowPos(GuiData->hWindow,
                     NULL,
                     GuiData->GuiInfo.WindowOrigin.x,
                     GuiData->GuiInfo.WindowOrigin.y,
                     0, 0,
                     SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
    }
}

/*
 * Locking
 *
 * Order: the console lock (Console->Lock), then the terminal lock
 * (GuiData->Lock), then USER. A thread holding the terminal lock never takes
 * the console lock and never calls USER, and no thread calls USER or waits for
 * another thread while it holds the console lock, except as listed below.
 *
 * - Writers and the frontend callbacks run with the console locked, on any
 *   thread. They only record what the window needs in GuiData (and move the
 *   view to the cursor, GuiShowCursorInView) and wake the console input
 *   thread through its wake event, a kernel event (GuiRequestWork).
 * - The console input thread owns the console windows of its desktop and
 *   their timers. It copies the recorded work and the buffer geometry under
 *   the console lock, releases it, and then calls USER (GuiProcessWork).
 *   WM_PAINT takes the console lock (and the terminal lock just to read the
 *   active buffer), composes the framebuffer, and releases the console lock
 *   before copying the framebuffer to the screen.
 * - GuiData->ActiveBuffer changes only with both locks held, and a screen
 *   buffer is destroyed only with the console locked, so a buffer read under
 *   the console lock stays valid until that lock is released.
 *
 * Exceptions: GuiChangeIcon, GuiGetLargestConsoleWindowSize and GuiSetCodePage
 * return a result computed by USER, RealizePalette on the
 * framebuffer (a memory DC) goes through USER, and the input thread's keyboard,
 * mouse, selection and sizing handlers act on their own window, all with the
 * console locked. None of them sends a message to another thread, so they wait
 * only for the USER lock, whose owner never waits for a console lock. The
 * clipboard is used with the console unlocked. Known limit: the full-screen
 * switch (Alt+Enter, SetConsoleDisplayMode) runs in the input thread with the
 * console locked, and ChangeDisplaySettings sends WM_DISPLAYCHANGE to every
 * top-level window with a 100 ms timeout each.
 */

/* Work that GuiProcessAllWork may defer: it repaints the whole view */
#define GUI_WORK_DEFERRABLE (GUI_WORK_UPDATE | GUI_WORK_RESIZE)

/*
 * Record work for the window thread and wake it. Never calls USER.
 * Other work wakes the thread even if a repaint is pending, because a
 * pending repaint may be deferred (see GuiProcessAllWork).
 */
VOID
GuiRequestWork(PGUI_CONSOLE_DATA GuiData, LONG Work)
{
    LONG Old = InterlockedOr(&GuiData->PendingWork, Work);

    if ((Old == 0 || (Work & ~Old & ~GUI_WORK_DEFERRABLE)) && GuiData->hWakeEvent)
        NtSetEvent(GuiData->hWakeEvent, NULL);
}

/* The console must be locked */
static VOID
DrawRegion(PGUI_CONSOLE_DATA GuiData,
           SMALL_RECT* Region)
{
    PSMALL_RECT Dirty = &GuiData->DirtyRegion;

    if (!GuiData->DirtyCells)
    {
        *Dirty = *Region;
        GuiData->DirtyCells = TRUE;
    }
    else
    {
        Dirty->Left   = min(Dirty->Left  , Region->Left  );
        Dirty->Top    = min(Dirty->Top   , Region->Top   );
        Dirty->Right  = max(Dirty->Right , Region->Right );
        Dirty->Bottom = max(Dirty->Bottom, Region->Bottom);
    }
    GuiRequestWork(GuiData, GUI_WORK_UPDATE);
}

/*
 * Bring the cursor into the view after output or SetConsoleCursorPosition
 * moved it out, as the console does when it moves the cursor. The view
 * origin is part of the screen buffer state that GetConsoleScreenBufferInfo
 * reports, so it moves here, under the console lock, together with the
 * cursor, also when the window is hidden; the window thread only moves the
 * scroll bars and repaints. A direction scrolls only if it has a scroll bar.
 * The console must be locked.
 */
static VOID
GuiShowCursorInView(PGUI_CONSOLE_DATA GuiData, PCONSOLE_SCREEN_BUFFER Buff)
{
    COORD Origin = Buff->ViewOrigin;

    if ((Buff->ScreenBufferSize.X > Buff->ViewSize.X) &&
        ((Buff->CursorPosition.X < Origin.X) ||
         (Buff->CursorPosition.X >= Origin.X + Buff->ViewSize.X)))
    {
        if (Buff->CursorPosition.X >= Buff->ViewSize.X)
            Origin.X = Buff->CursorPosition.X - Buff->ViewSize.X + 1;
        else
            Origin.X = 0;
    }
    if ((Buff->ScreenBufferSize.Y > Buff->ViewSize.Y) &&
        ((Buff->CursorPosition.Y < Origin.Y) ||
         (Buff->CursorPosition.Y >= Origin.Y + Buff->ViewSize.Y)))
    {
        if (Buff->CursorPosition.Y >= Buff->ViewSize.Y)
            Origin.Y = Buff->CursorPosition.Y - Buff->ViewSize.Y + 1;
        else
            Origin.Y = 0;
    }

    if ((Origin.X != Buff->ViewOrigin.X) || (Origin.Y != Buff->ViewOrigin.Y))
    {
        Buff->ViewOrigin = Origin;
        if (!GuiData->IsWindowVisible) return;
        GuiData->DirtyView = TRUE;
        GuiData->ViewMoved = TRUE;
        GuiRequestWork(GuiData, GUI_WORK_UPDATE);
    }
}

static VOID
InvalidateCell(PGUI_CONSOLE_DATA GuiData,
               SHORT x, SHORT y)
{
    SMALL_RECT CellRect = { x, y, x, y };
    DrawRegion(GuiData, &CellRect);
}


/******************************************************************************
 *                        GUI Terminal Initialization                         *
 ******************************************************************************/

// FIXME: HACK: Potential HACK for CORE-8129; see revision 63595.
VOID
CreateSysMenu(HWND hWnd);

/*
 * Run the recorded work of every console window of this thread.
 *
 * While output streams, every pass repaints the whole view, and copying the
 * framebuffer to the screen can take tens of milliseconds (about 20 ms per
 * repaint on i386 in QEMU). Run back to back, the repaints took most of the
 * processor, and on one processor the programs writing to the console, and
 * the server threads that serve them, advanced slowly. When a window has
 * only a repaint of the whole view pending (output scrolled or moved the
 * view, or the buffer was switched or resized) and its last paint ended less
 * than three times that paint's duration ago, its work therefore waits:
 * painting then takes at most about a quarter of the time. The work waits at
 * most GUI_PAINT_MAX_DEFER ms from when it was first deferred. Repaints of a
 * few cells (typing, the caret) and any other work (title, display mode,
 * ...) run at once. Writers are not affected: they only record the work.
 *
 * DirtyView is read without the console lock, as a hint: a stale value only
 * runs a pass early or defers it within the same bound.
 *
 * Returns TRUE and the time at which to run again in *Deadline when a
 * window's work was deferred; its PendingWork stays set, so the writers do
 * not set the wake event for another repaint.
 */
#define GUI_PAINT_MAX_DEFER 100

static BOOLEAN
GuiProcessAllWork(PLIST_ENTRY WindowList, PDWORD Deadline)
{
    PLIST_ENTRY Entry;
    BOOLEAN Deferred = FALSE;
    DWORD Now = GetTickCount();

    for (Entry = WindowList->Flink; Entry != WindowList; Entry = Entry->Flink)
    {
        PGUI_CONSOLE_DATA GuiData = CONTAINING_RECORD(Entry, GUI_CONSOLE_DATA, InputThreadLink);
        LONG Work = GuiData->PendingWork;
        DWORD Rest = min(3 * GuiData->PaintCost, GUI_PAINT_MAX_DEFER);

        if (!Work)
        {
            GuiData->WorkDeferred = FALSE;
            continue;
        }

        if (!(Work & ~GUI_WORK_DEFERRABLE) &&
            ((Work & GUI_WORK_RESIZE) || GuiData->DirtyView) &&
            (Now - GuiData->PaintEndTick) < Rest)
        {
            DWORD Due = GuiData->PaintEndTick + Rest;

            if (!GuiData->WorkDeferred)
            {
                GuiData->WorkDeferred = TRUE;
                GuiData->DeferredSince = Now;
            }
            if ((LONG)(Due - (GuiData->DeferredSince + GUI_PAINT_MAX_DEFER)) > 0)
                Due = GuiData->DeferredSince + GUI_PAINT_MAX_DEFER;

            if ((LONG)(Now - Due) < 0)
            {
                if (!Deferred || (LONG)(Due - *Deadline) < 0)
                    *Deadline = Due;
                Deferred = TRUE;
                continue;
            }
        }

        GuiData->WorkDeferred = FALSE;
        GuiProcessWork(GuiData, FALSE);
    }

    return Deferred;
}

static ULONG NTAPI
GuiConsoleInputThread(PVOID Param)
{
    NTSTATUS Status;
    PCSR_THREAD pcsrt = NULL;
    PGUI_INIT_INFO GuiInitInfo = (PGUI_INIT_INFO)Param;
    DESKTOP_CONSOLE_THREAD DesktopConsoleThreadInfo;
    ULONG_PTR InputThreadId = HandleToUlong(NtCurrentTeb()->ClientId.UniqueThread);
    HANDLE hThread = NULL;
    HANDLE hWakeEvent = NULL;
    LIST_ENTRY WindowList;
    BOOLEAN Deferred = FALSE;
    DWORD Deadline = 0;

    LONG WindowCount = 0;
    MSG msg;

    /*
     * This thread dispatches all the console notifications to the
     * notification window. It is common for all the console windows
     * in a given desktop in a window station.
     */

    InitializeListHead(&WindowList);

    /*
     * Writers set this event when they record work for one of our windows.
     * Without it the windows still update from their blink timer.
     */
    if (!NT_SUCCESS(NtCreateEvent(&hWakeEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE)))
        hWakeEvent = NULL;

    /* Assign this console input thread to this desktop */
    DesktopConsoleThreadInfo.DesktopHandle = GuiInitInfo->Desktop; // Duplicated desktop handle
    DesktopConsoleThreadInfo.ThreadId = InputThreadId;
    Status = NtUserConsoleControl(ConsoleCtrlDesktopConsoleThread,
                                  &DesktopConsoleThreadInfo,
                                  sizeof(DesktopConsoleThreadInfo));
    if (!NT_SUCCESS(Status)) goto Quit;

    /* Connect this CSR thread to the USER subsystem */
    pcsrt = CsrConnectToUser();
    if (pcsrt == NULL) goto Quit;
    hThread = pcsrt->ThreadHandle;

    /* Assign the desktop to this thread */
    if (!SetThreadDesktop(DesktopConsoleThreadInfo.DesktopHandle)) goto Quit;

    /* The thread has been initialized, set the event */
    NtSetEvent(GuiInitInfo->GuiThreadStartupEvent, NULL);
    Status = STATUS_SUCCESS;

    for (;;)
    {
        if (!PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            DWORD Timeout = INFINITE, Result;

            /* Deferred work runs at its deadline (see GuiProcessAllWork) */
            if (Deferred)
            {
                LONG Left = (LONG)(Deadline - GetTickCount());
                Timeout = (Left > 0) ? (DWORD)Left : 0;
            }

            /* Wait for a message or for work recorded by a writer */
            Result = MsgWaitForMultipleObjectsEx(hWakeEvent ? 1 : 0, &hWakeEvent, Timeout,
                                                 QS_ALLINPUT, MWMO_INPUTAVAILABLE);
            if ((Result == WAIT_OBJECT_0 && hWakeEvent) || Result == WAIT_TIMEOUT)
                Deferred = GuiProcessAllWork(&WindowList, &Deadline);
            continue;
        }

        if (msg.message == WM_QUIT) break;

        /* Do not let a stream of messages delay the output */
        if ((hWakeEvent && WaitForSingleObject(hWakeEvent, 0) == WAIT_OBJECT_0) ||
            (Deferred && (LONG)(GetTickCount() - Deadline) >= 0))
        {
            Deferred = GuiProcessAllWork(&WindowList, &Deadline);
        }

        switch (msg.message)
        {
            case PM_CREATE_CONSOLE:
            {
                PGUI_CONSOLE_DATA GuiData = (PGUI_CONSOLE_DATA)msg.lParam;
                PCONSRV_CONSOLE Console = GuiData->Console;
                HWND NewWindow;
                RECT rcWnd;

                DPRINT("PM_CREATE_CONSOLE -- creating window\n");

                GuiData->hWakeEvent = hWakeEvent;

                NewWindow = CreateWindowExW(WS_EX_CLIENTEDGE,
                                            GUI_CONWND_CLASS,
                                            Console->Title.Buffer,
                                            WS_OVERLAPPEDWINDOW,
                                            CW_USEDEFAULT,
                                            CW_USEDEFAULT,
                                            CW_USEDEFAULT,
                                            CW_USEDEFAULT,
                                            GuiData->IsWindowVisible ? HWND_DESKTOP : HWND_MESSAGE,
                                            NULL,
                                            ConSrvDllInstance,
                                            (PVOID)GuiData);
                if (NewWindow == NULL)
                {
                    DPRINT1("Failed to create a new console window\n");
                    /* GuiInitFrontEnd waits for this and then sees hWindow == NULL */
                    GuiData->hWindow = NULL;
                    GuiData->hWakeEvent = NULL;
                    if (!GuiData->InitEventSet)
                    {
                        GuiData->InitEventSet = TRUE;
                        NtSetEvent(GuiData->hGuiInitEvent, NULL);
                    }
                    continue;
                }

                ASSERT(NewWindow == GuiData->hWindow);

                _InterlockedIncrement(&WindowCount);
                InsertTailList(&WindowList, &GuiData->InputThreadLink);

                //
                // FIXME: TODO: Move everything there into conwnd.c!OnNcCreate()
                //

                /* Retrieve our real position */
                // See conwnd.c!OnMove()
                GetWindowRect(GuiData->hWindow, &rcWnd);
                GuiData->GuiInfo.WindowOrigin.x = rcWnd.left;
                GuiData->GuiInfo.WindowOrigin.y = rcWnd.top;

                if (GuiData->IsWindowVisible)
                {
                    /* Move and resize the window to the user's values */
                    /* CAN WE DEADLOCK ?? */
                    GuiConsoleMoveWindow(GuiData); // FIXME: This MUST be done via the CreateWindowExW call.
                    SendMessageW(GuiData->hWindow, PM_RESIZE_TERMINAL, 0, 0);
                }

                // FIXME: HACK: Potential HACK for CORE-8129; see revision 63595.
                CreateSysMenu(GuiData->hWindow);

                if (GuiData->IsWindowVisible)
                {
                    /* Switch to full-screen mode if necessary */
                    // FIXME: Move elsewhere, it cause misdrawings of the window.
                    if (GuiData->GuiInfo.FullScreen) SwitchFullScreen(GuiData, TRUE);

                    DPRINT("PM_CREATE_CONSOLE -- showing window\n");
                    ShowWindowAsync(NewWindow, (int)GuiData->GuiInfo.ShowWindow);
                }
                else
                {
                    DPRINT("PM_CREATE_CONSOLE -- hidden window\n");
                    ShowWindowAsync(NewWindow, SW_HIDE);
                }

                continue;
            }

            case PM_DESTROY_CONSOLE:
            {
                PGUI_CONSOLE_DATA GuiData = (PGUI_CONSOLE_DATA)msg.lParam;

                /* Exit the full screen mode if it was already set */
                // LeaveFullScreen(GuiData);

                /*
                 * PM_CREATE_CONSOLE for this console was handled before:
                 * GuiInitFrontEnd waits for it. Do not empty the queue here:
                 * DispatchMessage drops thread messages, so the creation or
                 * destruction of another console would be lost and its
                 * caller would wait forever.
                 */
                if (GuiData->hWindow == NULL)
                {
                    NtSetEvent(GuiData->hGuiTermEvent, NULL);
                    continue;
                }

                RemoveEntryList(&GuiData->InputThreadLink);
                InitializeListHead(&GuiData->InputThreadLink);

                DestroyWindow(GuiData->hWindow);

                GuiData->hWakeEvent = NULL;
                NtSetEvent(GuiData->hGuiTermEvent, NULL);

                if (_InterlockedDecrement(&WindowCount) == 0)
                {
                    DPRINT("CONSRV: Going to quit the Input Thread 0x%p\n", InputThreadId);
                    goto Quit;
                }

                continue;
            }
        }

        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

Quit:
    DPRINT("CONSRV: Quit the Input Thread 0x%p, Status = 0x%08lx\n", InputThreadId, Status);

    /* Remove this console input thread from this desktop */
    // DesktopConsoleThreadInfo.DesktopHandle;
    DesktopConsoleThreadInfo.ThreadId = 0;
    NtUserConsoleControl(ConsoleCtrlDesktopConsoleThread,
                         &DesktopConsoleThreadInfo,
                         sizeof(DesktopConsoleThreadInfo));

    /*
     * Close the duplicated desktop handle. A thread cannot close the desktop
     * handle it is assigned to (win32k refuses it: the handle would be left
     * open in CSRSS for every console input thread that ever ran), so detach
     * this thread from its desktop first. Its windows are all gone by now.
     * If the detach fails (the thread still owns a window), the close below
     * is refused as well and the handle is left, as before.
     */
    if (DesktopConsoleThreadInfo.DesktopHandle)
    {
        if (!SetThreadDesktop(NULL))
            DPRINT1("CONSRV: Input thread 0x%p cannot leave its desktop, error %lu\n", InputThreadId, GetLastError());
        CloseDesktop(DesktopConsoleThreadInfo.DesktopHandle); // NtUserCloseDesktop
    }

    /* Cleanup CSR thread */
    if (pcsrt)
    {
        if (hThread != pcsrt->ThreadHandle)
            DPRINT1("WARNING!! hThread (0x%p) != pcsrt->ThreadHandle (0x%p), you may expect crashes soon!!\n", hThread, pcsrt->ThreadHandle);

        CsrDereferenceThread(pcsrt);
    }

    if (hWakeEvent) NtClose(hWakeEvent);

    /* Exit the thread */
    RtlExitUserThread(Status);
    return 0;
}

// FIXME: Maybe return a NTSTATUS
static BOOL
GuiInit(IN PCONSOLE_INIT_INFO ConsoleInitInfo,
        IN HANDLE ConsoleLeaderProcessHandle,
        IN OUT PGUI_INIT_INFO GuiInitInfo)
{
    BOOL Success = TRUE;
    UNICODE_STRING DesktopPath;
    DESKTOP_CONSOLE_THREAD DesktopConsoleThreadInfo;
    HWINSTA hWinSta;
    HDESK hDesk;

    NTSTATUS Status;
    HANDLE hInputThread;
    CLIENT_ID ClientId;

    /* Perform one-time initialization */
    if (!ConsInitialized)
    {
        /* Initialize and register the console window class */
        if (!RegisterConWndClass(ConSrvDllInstance)) return FALSE;

        /* Initialize the font support -- additional TrueType font cache */
        InitTTFontCache();

        ConsInitialized = TRUE;
    }

    /*
     * Set-up the console input thread. We have
     * one console input thread per desktop.
     */

    if (!CsrImpersonateClient(NULL))
        // return STATUS_BAD_IMPERSONATION_LEVEL;
        return FALSE;

    if (ConsoleInitInfo->DesktopLength)
    {
        DesktopPath.MaximumLength = ConsoleInitInfo->DesktopLength;
        DesktopPath.Length = DesktopPath.MaximumLength - sizeof(UNICODE_NULL);
        DesktopPath.Buffer = ConsoleInitInfo->Desktop;
    }
    else
    {
        RtlInitUnicodeString(&DesktopPath, L"Default");
    }

    hDesk = NtUserResolveDesktop(ConsoleLeaderProcessHandle,
                                 &DesktopPath,
                                 FALSE,
                                 &hWinSta);
    DPRINT("NtUserResolveDesktop(DesktopPath = '%wZ') returned hDesk = 0x%p; hWinSta = 0x%p\n",
           &DesktopPath, hDesk, hWinSta);

    CsrRevertToSelf();

    if (hDesk == NULL) return FALSE;

    /*
     * We need to see whether we need to create a
     * new console input thread for this desktop.
     */
    DesktopConsoleThreadInfo.DesktopHandle = hDesk;
    DesktopConsoleThreadInfo.ThreadId = (ULONG_PTR)INVALID_HANDLE_VALUE; // Special value to say we just want to retrieve the thread ID.
    NtUserConsoleControl(ConsoleCtrlDesktopConsoleThread,
                         &DesktopConsoleThreadInfo,
                         sizeof(DesktopConsoleThreadInfo));
    DPRINT("NtUserConsoleControl returned ThreadId = 0x%p\n", DesktopConsoleThreadInfo.ThreadId);

    /*
     * Save the opened window station and desktop handles in the initialization
     * structure. They will be used later on, and released, by the GUI frontend.
     */
    GuiInitInfo->WinSta  = hWinSta;
    GuiInitInfo->Desktop = hDesk;

    /* Here GuiInitInfo contains original handles */

    /* If we already have a console input thread on this desktop... */
    if (DesktopConsoleThreadInfo.ThreadId != 0)
    {
        /* ... just use it... */
        DPRINT("Using input thread InputThreadId = 0x%p\n", DesktopConsoleThreadInfo.ThreadId);
        GuiInitInfo->InputThreadId = DesktopConsoleThreadInfo.ThreadId;
        goto Quit;
    }

    /* ... otherwise create a new one. */

    /* Initialize a startup event for the thread to signal it */
    Status = NtCreateEvent(&GuiInitInfo->GuiThreadStartupEvent, EVENT_ALL_ACCESS,
                           NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
    {
        Success = FALSE;
        goto Quit;
    }

    /*
     * Duplicate the desktop handle for the console input thread internal needs.
     * If it happens to need also a window station handle in the future, then
     * it is there that you also need to duplicate the window station handle!
     *
     * Note also that we are going to temporarily overwrite the stored handles
     * in GuiInitInfo because it happens that we use also this structure to give
     * the duplicated handles to the input thread that is going to initialize.
     * After the input thread finishes its initialization, we restore the handles
     * in GuiInitInfo to their old values.
     */
    Status = NtDuplicateObject(NtCurrentProcess(),
                               hDesk,
                               NtCurrentProcess(),
                               (PHANDLE)&GuiInitInfo->Desktop,
                               0, 0, DUPLICATE_SAME_ACCESS);
    if (!NT_SUCCESS(Status))
    {
        Success = FALSE;
        goto Quit;
    }

    /* Here GuiInitInfo contains duplicated handles */

    Status = RtlCreateUserThread(NtCurrentProcess(),
                                 NULL,
                                 TRUE, // Start the thread in suspended state
                                 0,
                                 0,
                                 0,
                                 (PVOID)GuiConsoleInputThread,
                                 (PVOID)GuiInitInfo,
                                 &hInputThread,
                                 &ClientId);
    if (NT_SUCCESS(Status))
    {
        /* Add it as a static server thread and resume it */
        CsrAddStaticServerThread(hInputThread, &ClientId, 0);
        Status = NtResumeThread(hInputThread, NULL);
    }
    DPRINT("Thread creation hInputThread = 0x%p, InputThreadId = 0x%p, Status = 0x%08lx\n",
           hInputThread, ClientId.UniqueThread, Status);

    if (!NT_SUCCESS(Status) || hInputThread == NULL)
    {
        /* Close the thread's handle */
        if (hInputThread) NtClose(hInputThread);

        /* We need to close here the duplicated desktop handle */
        CloseDesktop(GuiInitInfo->Desktop); // NtUserCloseDesktop

        /* Close the startup event and bail out */
        NtClose(GuiInitInfo->GuiThreadStartupEvent);

        DPRINT1("CONSRV: Failed to create graphics console thread.\n");
        Success = FALSE;
        goto Quit;
    }

    /* No need to close hInputThread, this is done by CSR automatically */

    /* Wait for the thread to finish its initialization, and close the startup event */
    NtWaitForSingleObject(GuiInitInfo->GuiThreadStartupEvent, FALSE, NULL);
    NtClose(GuiInitInfo->GuiThreadStartupEvent);

    /*
     * Save the input thread ID for later use, and restore the original handles.
     * The copies are held by the console input thread.
     */
    GuiInitInfo->InputThreadId = (ULONG_PTR)ClientId.UniqueThread;
    GuiInitInfo->WinSta  = hWinSta;
    GuiInitInfo->Desktop = hDesk;

    /* Here GuiInitInfo contains again original handles */

Quit:
    if (!Success)
    {
        /*
         * Close the original handles. Do not use the copies in GuiInitInfo
         * because we may have failed in the middle of the duplicate operation
         * and the handles stored in GuiInitInfo may have changed.
         */
        CloseDesktop(hDesk); // NtUserCloseDesktop
        CloseWindowStation(hWinSta); // NtUserCloseWindowStation
    }

    return Success;
}


/******************************************************************************
 *                             GUI Console Driver                             *
 ******************************************************************************/

static VOID NTAPI
GuiDeinitFrontEnd(IN OUT PFRONTEND This);

static NTSTATUS NTAPI
GuiInitFrontEnd(IN OUT PFRONTEND This,
                IN PCONSRV_CONSOLE Console)
{
    PGUI_INIT_INFO GuiInitInfo;
    PGUI_CONSOLE_DATA GuiData;

    if (This == NULL || Console == NULL || This->Context2 == NULL)
        return STATUS_INVALID_PARAMETER;

    ASSERT(This->Console == Console);

    GuiInitInfo = This->Context2;

    /* Terminal data allocation */
    GuiData = ConsoleAllocHeap(HEAP_ZERO_MEMORY, sizeof(*GuiData));
    if (!GuiData)
    {
        DPRINT1("CONSRV: Failed to create GUI_CONSOLE_DATA\n");
        return STATUS_UNSUCCESSFUL;
    }
    /// /* HACK */ Console->FrontEndIFace.Context = (PVOID)GuiData; /* HACK */
    GuiData->Console      = Console;
    GuiData->ActiveBuffer = Console->ActiveBuffer;
    GuiData->hWindow = NULL;
    GuiData->IsWindowVisible = GuiInitInfo->IsWindowVisible;

    /* The console can be resized */
    Console->FixedSize = FALSE;

    InitializeCriticalSection(&GuiData->Lock);
    InitializeListHead(&GuiData->InputThreadLink);

    /*
     * Set up GUI data
     */
    RtlCopyMemory(&GuiData->GuiInfo, &GuiInitInfo->TermInfo, sizeof(GuiInitInfo->TermInfo));

    /* Initialize the icon handles */
    if (GuiInitInfo->hIcon != NULL)
        GuiData->hIcon = GuiInitInfo->hIcon;
    else
        GuiData->hIcon = ghDefaultIcon;

    if (GuiInitInfo->hIconSm != NULL)
        GuiData->hIconSm = GuiInitInfo->hIconSm;
    else
        GuiData->hIconSm = ghDefaultIconSm;

    ASSERT(GuiData->hIcon && GuiData->hIconSm);

    /* Mouse is shown by default with its default cursor shape */
    GuiData->hCursor = ghDefaultCursor;
    GuiData->MouseCursorRefCount = 0;

    /* A priori don't ignore mouse events */
    GuiData->IgnoreNextMouseEvent = FALSE;
    /* Initialize HACK FOR CORE-8394. See conwnd.c!OnMouse for more details. */
    GuiData->HackCORE8394IgnoreNextMove = FALSE;

    /* Close button and the corresponding system menu item are enabled by default */
    GuiData->IsCloseButtonEnabled = TRUE;

    /* There is no user-reserved menu id range by default */
    GuiData->CmdIdLow = GuiData->CmdIdHigh = 0;

    /* Initialize the selection */
    RtlZeroMemory(&GuiData->Selection, sizeof(GuiData->Selection));
    GuiData->Selection.dwFlags = CONSOLE_NO_SELECTION;
    RtlZeroMemory(&GuiData->dwSelectionCursor, sizeof(GuiData->dwSelectionCursor));
    GuiData->LineSelection = FALSE; // Default to block selection
    // TODO: Retrieve the selection mode via the registry.

    GuiData->InputThreadId = GuiInitInfo->InputThreadId;
    GuiData->WinSta  = GuiInitInfo->WinSta;
    GuiData->Desktop = GuiInitInfo->Desktop;

    /* Finally, finish to initialize the frontend structure */
    This->Context  = GuiData;
    ConsoleFreeHeap(This->Context2);
    This->Context2 = NULL;

    /*
     * We need to wait until the GUI has been fully initialized
     * to retrieve custom settings i.e. WindowSize etc...
     * Ideally we could use SendNotifyMessage for this but its not
     * yet implemented.
     */
    NtCreateEvent(&GuiData->hGuiInitEvent, EVENT_ALL_ACCESS,
                  NULL, SynchronizationEvent, FALSE);
    NtCreateEvent(&GuiData->hGuiTermEvent, EVENT_ALL_ACCESS,
                  NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(NtCreateEvent(&GuiData->hDisplayModeEvent, EVENT_ALL_ACCESS,
                                  NULL, SynchronizationEvent, FALSE)))
    {
        GuiData->hDisplayModeEvent = NULL;
    }

    DPRINT("GUI - Checkpoint\n");

    /* Create the terminal window; the input thread sets hGuiInitEvent */
    if (PostThreadMessageW(GuiData->InputThreadId, PM_CREATE_CONSOLE, 0, (LPARAM)GuiData))
    {
        /* Wait until initialization has finished */
        NtWaitForSingleObject(GuiData->hGuiInitEvent, FALSE, NULL);
        DPRINT("OK we created the console window\n");
    }
    else
    {
        DPRINT1("CONSRV: Cannot post PM_CREATE_CONSOLE to the input thread, error %lu\n", GetLastError());
        GuiData->hWindow = NULL;
    }
    NtClose(GuiData->hGuiInitEvent);
    GuiData->hGuiInitEvent = NULL;

    /* Check whether we really succeeded in initializing the terminal window */
    if (GuiData->hWindow == NULL)
    {
        DPRINT("GuiInitConsole - We failed at creating a new terminal window\n");
        GuiDeinitFrontEnd(This);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static VOID NTAPI
GuiDeinitFrontEnd(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    DPRINT("Send PM_DESTROY_CONSOLE message and wait on hGuiTermEvent...\n");
    if (PostThreadMessageW(GuiData->InputThreadId, PM_DESTROY_CONSOLE, 0, (LPARAM)GuiData))
    {
        NtWaitForSingleObject(GuiData->hGuiTermEvent, FALSE, NULL);
        DPRINT("hGuiTermEvent set\n");
    }
    else
    {
        DPRINT1("CONSRV: Cannot post PM_DESTROY_CONSOLE to the input thread, error %lu\n", GetLastError());
    }
    NtClose(GuiData->hGuiTermEvent);
    GuiData->hGuiTermEvent = NULL;
    if (GuiData->hDisplayModeEvent) NtClose(GuiData->hDisplayModeEvent);
    GuiData->hDisplayModeEvent = NULL;

    CloseDesktop(GuiData->Desktop); // NtUserCloseDesktop
    CloseWindowStation(GuiData->WinSta); // NtUserCloseWindowStation

    DPRINT("Destroying icons !! - GuiData->hIcon = 0x%p ; ghDefaultIcon = 0x%p ; GuiData->hIconSm = 0x%p ; ghDefaultIconSm = 0x%p\n",
            GuiData->hIcon, ghDefaultIcon, GuiData->hIconSm, ghDefaultIconSm);
    if (GuiData->hIcon != NULL && GuiData->hIcon != ghDefaultIcon)
    {
        DPRINT("Destroy hIcon\n");
        DestroyIcon(GuiData->hIcon);
    }
    if (GuiData->hIconSm != NULL && GuiData->hIconSm != ghDefaultIconSm)
    {
        DPRINT("Destroy hIconSm\n");
        DestroyIcon(GuiData->hIconSm);
    }

    This->Context = NULL;
    DeleteCriticalSection(&GuiData->Lock);
    ConsoleFreeHeap(GuiData);

    DPRINT("Quit GuiDeinitFrontEnd\n");
}

static VOID NTAPI
GuiDrawRegion(IN OUT PFRONTEND This,
              SMALL_RECT* Region)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /* Do nothing if the window is hidden */
    if (!GuiData->IsWindowVisible) return;

    DrawRegion(GuiData, Region);
}

static VOID NTAPI
GuiWriteStream(IN OUT PFRONTEND This,
               SMALL_RECT* Region,
               SHORT CursorStartX,
               SHORT CursorStartY,
               UINT ScrolledLines,
               PWCHAR Buffer,
               UINT Length)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    PCONSOLE_SCREEN_BUFFER Buff;
    SHORT CursorEndX, CursorEndY;

    if (NULL == GuiData || NULL == GuiData->hWindow) return;

    Buff = GuiData->ActiveBuffer;
    if (Buff == NULL || GetType(Buff) != TEXTMODE_BUFFER) return;

    /* The view follows the cursor even if the window is hidden */
    GuiShowCursorInView(GuiData, Buff);

    /* Nothing more to do if the window is hidden */
    if (!GuiData->IsWindowVisible) return;

    /* Repaint the view instead of copying its pixels in the writer's thread */
    if (0 != ScrolledLines)
        GuiData->DirtyView = TRUE;

    DrawRegion(GuiData, Region);

    if (CursorStartX < Region->Left || Region->Right < CursorStartX
            || CursorStartY < Region->Top || Region->Bottom < CursorStartY)
    {
        InvalidateCell(GuiData, CursorStartX, CursorStartY);
    }

    CursorEndX = Buff->CursorPosition.X;
    CursorEndY = Buff->CursorPosition.Y;
    if ((CursorEndX < Region->Left || Region->Right < CursorEndX
            || CursorEndY < Region->Top || Region->Bottom < CursorEndY)
            && (CursorEndX != CursorStartX || CursorEndY != CursorStartY))
    {
        InvalidateCell(GuiData, CursorEndX, CursorEndY);
    }

    /* Show the caret at once and restart its blink (see GuiProcessWork) */
    Buff->CursorBlinkOn = TRUE;
    GuiData->ShowCaret = TRUE;
    GuiRequestWork(GuiData, GUI_WORK_UPDATE);
}

/* static */ VOID NTAPI
GuiRingBell(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /* Emit an error beep sound */
    GuiRequestWork(GuiData, GUI_WORK_BEEP);
}

static BOOL NTAPI
GuiSetCursorInfo(IN OUT PFRONTEND This,
                 PCONSOLE_SCREEN_BUFFER Buff)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /* Do nothing if the window is hidden */
    if (!GuiData->IsWindowVisible) return TRUE;

    if (GuiData->ActiveBuffer == Buff)
    {
        InvalidateCell(GuiData, Buff->CursorPosition.X, Buff->CursorPosition.Y);
    }

    return TRUE;
}

static BOOL NTAPI
GuiSetScreenInfo(IN OUT PFRONTEND This,
                 PCONSOLE_SCREEN_BUFFER Buff,
                 SHORT OldCursorX,
                 SHORT OldCursorY)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /* The view follows the cursor even if the window is hidden */
    if (GuiData->ActiveBuffer == Buff && GetType(Buff) == TEXTMODE_BUFFER)
        GuiShowCursorInView(GuiData, Buff);

    /* Nothing more to do if the window is hidden */
    if (!GuiData->IsWindowVisible) return TRUE;

    if (GuiData->ActiveBuffer == Buff)
    {
        /* Redraw char at old position (remove cursor) */
        InvalidateCell(GuiData, OldCursorX, OldCursorY);
        /* Redraw char at new position (show cursor) */
        InvalidateCell(GuiData, Buff->CursorPosition.X, Buff->CursorPosition.Y);
    }

    return TRUE;
}

static VOID NTAPI
GuiResizeTerminal(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /* Resize the window to the user's values */
    GuiRequestWork(GuiData, GUI_WORK_RESIZE);
}

/* Called with the console locked */
static VOID NTAPI
GuiSetActiveScreenBuffer(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    PCONSOLE_SCREEN_BUFFER ActiveBuffer;
    HPALETTE hPalette;

    EnterCriticalSection(&GuiData->Lock);
    ActiveBuffer = ConDrvGetActiveScreenBuffer((PCONSOLE)GuiData->Console);
    InterlockedExchangePointer((PVOID*)&GuiData->ActiveBuffer, ActiveBuffer);
    LeaveCriticalSection(&GuiData->Lock);

    /* Change the current palette */
    if (ActiveBuffer->PaletteHandle == NULL)
        hPalette = GuiData->hSysPalette;
    else
        hPalette = ActiveBuffer->PaletteHandle;

    DPRINT("GuiSetActiveScreenBuffer using palette 0x%p\n", hPalette);

    /* Set the new palette for the framebuffer */
    SelectPalette(GuiData->hMemDC, hPalette, FALSE);

    /* Specify the use of the system palette for the framebuffer */
    SetSystemPaletteUse(GuiData->hMemDC, ActiveBuffer->PaletteUsage);

    /* Realize the (logical) palette */
    RealizePalette(GuiData->hMemDC);

    /*
     * Output and cursor moves in a buffer that was not active did not move
     * its view (only the active buffer's view follows its cursor): bring its
     * cursor into the view now that it is shown.
     */
    if (GetType(ActiveBuffer) == TEXTMODE_BUFFER)
        GuiShowCursorInView(GuiData, ActiveBuffer);

    /* Show the whole new buffer, not only what changes next */
    GuiData->DirtyView = TRUE;
    GuiRequestWork(GuiData, GUI_WORK_RESIZE | GUI_WORK_UPDATE);
}

static VOID NTAPI
GuiReleaseScreenBuffer(IN OUT PFRONTEND This,
                       IN PCONSOLE_SCREEN_BUFFER ScreenBuffer)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /*
     * If we were notified to release a screen buffer that is not actually
     * ours, then just ignore the notification...
     */
    if (ScreenBuffer != GuiData->ActiveBuffer) return;

    /*
     * ... else, we must release our active buffer. Two cases are present:
     * - If ScreenBuffer (== GuiData->ActiveBuffer) IS NOT the console
     *   active screen buffer, then we can safely switch to it.
     * - If ScreenBuffer IS the console active screen buffer, we must release
     *   it ONLY.
     */

    /* Release the old active palette and set the default one */
    if (GetCurrentObject(GuiData->hMemDC, OBJ_PAL) == ScreenBuffer->PaletteHandle)
    {
        /* Set the new palette */
        SelectPalette(GuiData->hMemDC, GuiData->hSysPalette, FALSE);
    }

    /* Set the adequate active screen buffer */
    if (ScreenBuffer != GuiData->Console->ActiveBuffer)
    {
        GuiSetActiveScreenBuffer(This);
    }
    else
    {
        EnterCriticalSection(&GuiData->Lock);
        InterlockedExchangePointer((PVOID*)&GuiData->ActiveBuffer, NULL);
        LeaveCriticalSection(&GuiData->Lock);
    }
}

static BOOL NTAPI
GuiSetMouseCursor(IN OUT PFRONTEND This,
                  HCURSOR CursorHandle);

static VOID NTAPI
GuiRefreshInternalInfo(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /* Update the console leader information held by the window */
    GuiRequestWork(GuiData, GUI_WORK_LEADER);

    /*
     * HACK:
     * We reset the cursor here so that, when a console app quits, we reset
     * the cursor to the default one. It's quite a hack since it doesn't proceed
     * per - console process... This must be fixed.
     *
     * See GuiInitConsole(...) for more information.
     */

    /* Mouse is shown by default with its default cursor shape */
    GuiData->MouseCursorRefCount = 0; // Reinitialize the reference counter
    GuiSetMouseCursor(This, NULL);
}

static VOID NTAPI
GuiChangeTitle(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    GuiRequestWork(GuiData, GUI_WORK_TITLE);
}

static BOOL NTAPI
GuiChangeIcon(IN OUT PFRONTEND This,
              HICON IconHandle)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    HICON hIcon, hIconSm;

    if (IconHandle == NULL)
    {
        hIcon   = ghDefaultIcon;
        hIconSm = ghDefaultIconSm;
    }
    else
    {
        hIcon   = CopyIcon(IconHandle);
        hIconSm = CopyIcon(IconHandle);
    }

    if (hIcon == NULL)
        return FALSE;

    if (hIcon != GuiData->hIcon)
    {
        if (GuiData->hIcon != NULL && GuiData->hIcon != ghDefaultIcon)
        {
            DestroyIcon(GuiData->hIcon);
        }
        if (GuiData->hIconSm != NULL && GuiData->hIconSm != ghDefaultIconSm)
        {
            DestroyIcon(GuiData->hIconSm);
        }

        GuiData->hIcon   = hIcon;
        GuiData->hIconSm = hIconSm;

        DPRINT("Set icons in GuiChangeIcon\n");
        PostMessageW(GuiData->hWindow, WM_SETICON, ICON_BIG  , (LPARAM)GuiData->hIcon  );
        PostMessageW(GuiData->hWindow, WM_SETICON, ICON_SMALL, (LPARAM)GuiData->hIconSm);
    }

    return TRUE;
}

static HDESK NTAPI
GuiGetThreadConsoleDesktop(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    return GuiData->Desktop;
}

static HWND NTAPI
GuiGetConsoleWindowHandle(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    return GuiData->hWindow;
}

static VOID NTAPI
GuiGetLargestConsoleWindowSize(IN OUT PFRONTEND This,
                               PCOORD pSize)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    PCONSOLE_SCREEN_BUFFER ActiveBuffer;
    HMONITOR hMonitor;
    MONITORINFO MonitorInfo;
    LONG Width, Height;
    UINT WidthUnit, HeightUnit;

    if (!pSize) return;

    /*
     * A console without a visible window (CREATE_NO_WINDOW, as the headless
     * host of a pseudoconsole) has no monitor to fit on: do not derive a limit
     * from the display or the font, the caller (ConDrv) still bounds the window
     * by the screen buffer size. Visible consoles keep the monitor-derived limit.
     */
    if (!GuiData->IsWindowVisible)
    {
        pSize->X = pSize->Y = 0x7FFF;
        return;
    }

    /*
     * Retrieve the monitor that is mostly covered by the current console window;
     * default to primary monitor otherwise.
     */
    MonitorInfo.cbSize = sizeof(MonitorInfo);
    hMonitor = MonitorFromWindow(GuiData->hWindow, MONITOR_DEFAULTTOPRIMARY);
    if (hMonitor && GetMonitorInfoW(hMonitor, &MonitorInfo))
    {
        /* Retrieve the width and height of the client area of this monitor */
        Width  = MonitorInfo.rcWork.right - MonitorInfo.rcWork.left;
        Height = MonitorInfo.rcWork.bottom - MonitorInfo.rcWork.top;
    }
    else
    {
        /*
         * Retrieve the width and height of the client area for a full-screen
         * window on the primary display monitor.
         */
        Width  = GetSystemMetrics(SM_CXFULLSCREEN);
        Height = GetSystemMetrics(SM_CYFULLSCREEN);

        // RECT WorkArea;
        // SystemParametersInfoW(SPI_GETWORKAREA, 0, &WorkArea, 0);
        // Width  = WorkArea.right;
        // Height = WorkArea.bottom;
    }

    ActiveBuffer = GuiData->ActiveBuffer;
#if 0
    // NOTE: This would be surprising if we wouldn't have an associated buffer...
    if (ActiveBuffer)
#endif
        GetScreenBufferSizeUnits(ActiveBuffer, GuiData, &WidthUnit, &HeightUnit);
#if 0
    else
        /* Default: graphics mode */
        WidthUnit = HeightUnit = 1;
#endif

    Width  -= (2 * (GetSystemMetrics(SM_CXFRAME) + GetSystemMetrics(SM_CXEDGE)));
    Height -= (2 * (GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CYEDGE)) + GetSystemMetrics(SM_CYCAPTION));

    if (Width  < 0) Width  = 0;
    if (Height < 0) Height = 0;

    pSize->X = (SHORT)(Width  / (int)WidthUnit ) /* HACK */ + 2;
    pSize->Y = (SHORT)(Height / (int)HeightUnit) /* HACK */ + 1;
}

static BOOL NTAPI
GuiGetSelectionInfo(IN OUT PFRONTEND This,
                    PCONSOLE_SELECTION_INFO pSelectionInfo)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    if (pSelectionInfo == NULL) return FALSE;

    ZeroMemory(pSelectionInfo, sizeof(*pSelectionInfo));
    if (GuiData->Selection.dwFlags != CONSOLE_NO_SELECTION)
        RtlCopyMemory(pSelectionInfo, &GuiData->Selection, sizeof(*pSelectionInfo));

    return TRUE;
}

static BOOL NTAPI
GuiSetPalette(IN OUT PFRONTEND This,
              HPALETTE PaletteHandle,
              UINT PaletteUsage)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    HPALETTE OldPalette;

    // if (GetType(GuiData->ActiveBuffer) != GRAPHICS_BUFFER) return FALSE;
    if (PaletteHandle == NULL) return FALSE;

    /* Set the new palette for the framebuffer */
    OldPalette = SelectPalette(GuiData->hMemDC, PaletteHandle, FALSE);
    if (OldPalette == NULL) return FALSE;

    /* Specify the use of the system palette for the framebuffer */
    SetSystemPaletteUse(GuiData->hMemDC, PaletteUsage);

    /* Realize the (logical) palette */
    RealizePalette(GuiData->hMemDC);

    /* Save the original system palette handle */
    if (GuiData->hSysPalette == NULL) GuiData->hSysPalette = OldPalette;

    return TRUE;
}

static BOOL NTAPI
GuiSetCodePage(IN OUT PFRONTEND This,
               UINT CodePage)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /*
     * Attempt to reinitialize the current font for the new code page,
     * trying to keep the current font with the same characteristics.
     * If the current font does not support the new code page, switch
     * to a different font supporting the code page but having similar
     * characteristics.
     * If no font can be found for this code page, stay using the
     * original font and refuse changing the code page.
     */
    if (!InitFonts(GuiData,
                   GuiData->GuiInfo.FaceName,
                   GuiData->GuiInfo.FontWeight,
                   GuiData->GuiInfo.FontFamily,
                   GuiData->GuiInfo.FontSize,
                   CodePage, FALSE))
    {
        DPRINT1("Failed to initialize font '%S' for code page %d - Refuse CP change\n",
                GuiData->GuiInfo.FaceName, CodePage);
        return FALSE;
    }

    return TRUE;
}

static ULONG NTAPI
GuiGetDisplayMode(IN OUT PFRONTEND This)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    ULONG DisplayMode = 0;

    if (GuiData->GuiInfo.FullScreen)
        DisplayMode |= CONSOLE_FULLSCREEN_HARDWARE; // CONSOLE_FULLSCREEN
    else
        DisplayMode |= CONSOLE_WINDOWED;

    return DisplayMode;
}

static BOOL NTAPI
GuiSetDisplayMode(IN OUT PFRONTEND This,
                  ULONG NewMode)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;
    PCONSRV_CONSOLE Console = GuiData->Console;
    LARGE_INTEGER Timeout;
    BOOL FullScreen;
    LONG Request, LockCount, i;

    if (NewMode & ~(CONSOLE_FULLSCREEN_MODE | CONSOLE_WINDOWED_MODE))
        return FALSE;

    /* Do nothing if the window is hidden */
    if (!GuiData->IsWindowVisible) return TRUE;

    FullScreen = ((NewMode & CONSOLE_FULLSCREEN_MODE) != 0);

    /*
     * The switch sends messages to the window: let its thread do it,
     * because that thread may be waiting for the console lock we hold.
     */
    GuiData->RequestedFullScreen = FullScreen;
    Request = InterlockedIncrement(&GuiData->DisplayModeRequest);
    GuiRequestWork(GuiData, GUI_WORK_DISPLAY_MODE);

    /*
     * Return only once the mode is set, waiting with the console unlocked
     * (the caller holds it, maybe twice), as GuiInitFrontEnd waits for the
     * window. The caller holds a console reference, which keeps GuiData.
     */
    /* Not done when it cannot wait or the wait ends first: the caller fails */
    if (!GuiData->hDisplayModeEvent ||
        Console->Lock.OwningThread != NtCurrentTeb()->ClientId.UniqueThread)
    {
        return FALSE;
    }
    Timeout.QuadPart = -5000000LL; /* 500 ms */
    LockCount = Console->Lock.RecursionCount;
    for (i = 0; i < LockCount; i++) LeaveCriticalSection(&Console->Lock);
    /* The blink timer runs the work even in a modal loop, so this ends */
    for (i = 0; i < 20 && (LONG)(GuiData->DisplayModeDone - Request) < 0; i++)
        NtWaitForSingleObject(GuiData->hDisplayModeEvent, FALSE, &Timeout);
    for (i = 0; i < LockCount; i++) EnterCriticalSection(&Console->Lock);

    return ((LONG)(GuiData->DisplayModeDone - Request) >= 0);
}

static INT NTAPI
GuiShowMouseCursor(IN OUT PFRONTEND This,
                   BOOL Show)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    if (GuiData->IsWindowVisible)
    {
        /* Set the reference count */
        if (Show) ++GuiData->MouseCursorRefCount;
        else      --GuiData->MouseCursorRefCount;

        /* Effectively show (or hide) the cursor */
        GuiRequestWork(GuiData, GUI_WORK_CURSOR);
    }

    return GuiData->MouseCursorRefCount;
}

static BOOL NTAPI
GuiSetMouseCursor(IN OUT PFRONTEND This,
                  HCURSOR CursorHandle)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    /* Do nothing if the window is hidden */
    if (!GuiData->IsWindowVisible) return TRUE;

    /*
     * Set the cursor's handle. If the given handle is NULL,
     * then restore the default cursor.
     */
    GuiData->hCursor = (CursorHandle ? CursorHandle : ghDefaultCursor);

    /* Effectively modify the shape of the cursor */
    GuiRequestWork(GuiData, GUI_WORK_CURSOR);

    return TRUE;
}

static HMENU NTAPI
GuiMenuControl(IN OUT PFRONTEND This,
               UINT CmdIdLow,
               UINT CmdIdHigh)
{
    PGUI_CONSOLE_DATA GuiData = This->Context;

    GuiData->CmdIdLow  = CmdIdLow ;
    GuiData->CmdIdHigh = CmdIdHigh;

    return GuiData->hSysMenu;
}

static BOOL NTAPI
GuiSetMenuClose(IN OUT PFRONTEND This,
                BOOL Enable)
{
    /*
     * NOTE: See http://www.mail-archive.com/harbour@harbour-project.org/msg27509.html
     * or http://harbour-devel.1590103.n2.nabble.com/Question-about-hb-gt-win-CtrlHandler-usage-td4670862i20.html (DEAD_LINK)
     * for more information.
     */

    PGUI_CONSOLE_DATA GuiData = This->Context;

    if (GuiData->hSysMenu == NULL) return FALSE;

    /* EnableMenuItem can redraw the caption, a send to the window thread */
    GuiData->IsCloseButtonEnabled = Enable;
    GuiRequestWork(GuiData, GUI_WORK_CLOSE_MENU);

    return TRUE;
}

static FRONTEND_VTBL GuiVtbl =
{
    GuiInitFrontEnd,
    GuiDeinitFrontEnd,
    GuiDrawRegion,
    GuiWriteStream,
    GuiRingBell,
    GuiSetCursorInfo,
    GuiSetScreenInfo,
    GuiResizeTerminal,
    GuiSetActiveScreenBuffer,
    GuiReleaseScreenBuffer,
    GuiRefreshInternalInfo,
    GuiChangeTitle,
    GuiChangeIcon,
    GuiGetThreadConsoleDesktop,
    GuiGetConsoleWindowHandle,
    GuiGetLargestConsoleWindowSize,
    GuiGetSelectionInfo,
    GuiSetPalette,
    GuiSetCodePage,
    GuiGetDisplayMode,
    GuiSetDisplayMode,
    GuiShowMouseCursor,
    GuiSetMouseCursor,
    GuiMenuControl,
    GuiSetMenuClose,
};


NTSTATUS NTAPI
GuiLoadFrontEnd(IN OUT PFRONTEND FrontEnd,
                IN OUT PCONSOLE_STATE_INFO ConsoleInfo,
                IN OUT PCONSOLE_INIT_INFO ConsoleInitInfo,
                IN HANDLE ConsoleLeaderProcessHandle)
{
    PCONSOLE_START_INFO ConsoleStartInfo;
    PGUI_INIT_INFO GuiInitInfo;
    USEROBJECTFLAGS UserObjectFlags;

    if (FrontEnd == NULL || ConsoleInfo == NULL || ConsoleInitInfo == NULL)
        return STATUS_INVALID_PARAMETER;

    ConsoleStartInfo = ConsoleInitInfo->ConsoleStartInfo;

    /*
     * Initialize a private initialization info structure for later use.
     * It must be freed by a call to GuiUnloadFrontEnd or GuiInitFrontEnd.
     */
    GuiInitInfo = ConsoleAllocHeap(HEAP_ZERO_MEMORY, sizeof(*GuiInitInfo));
    if (GuiInitInfo == NULL) return STATUS_NO_MEMORY;

    /* Initialize GUI terminal emulator common functionalities */
    if (!GuiInit(ConsoleInitInfo, ConsoleLeaderProcessHandle, GuiInitInfo))
    {
        ConsoleFreeHeap(GuiInitInfo);
        return STATUS_UNSUCCESSFUL;
    }

    GuiInitInfo->IsWindowVisible = ConsoleInitInfo->IsWindowVisible;
    if (GuiInitInfo->IsWindowVisible)
    {
        /* Don't show the console if the window station is not interactive */
        if (GetUserObjectInformationW(GuiInitInfo->WinSta,
                                      UOI_FLAGS,
                                      &UserObjectFlags,
                                      sizeof(UserObjectFlags),
                                      NULL))
        {
            if (!(UserObjectFlags.dwFlags & WSF_VISIBLE))
                GuiInitInfo->IsWindowVisible = FALSE;
        }
    }

    /*
     * Load terminal settings
     */
#if 0
    /* Impersonate the caller in order to retrieve settings in its context */
    // if (!CsrImpersonateClient(NULL))
        // return STATUS_UNSUCCESSFUL;
    CsrImpersonateClient(NULL);

    /* 1. Load the default settings */
    GuiConsoleGetDefaultSettings(&GuiInitInfo->TermInfo);
#endif

    GuiInitInfo->TermInfo.ShowWindow = SW_SHOWNORMAL;

    if (GuiInitInfo->IsWindowVisible)
    {
        /* 2. Load the remaining console settings via the registry */
        if ((ConsoleStartInfo->dwStartupFlags & STARTF_TITLEISLINKNAME) == 0)
        {
#if 0
            /* Load the terminal information from the registry */
            GuiConsoleReadUserSettings(&GuiInitInfo->TermInfo);
#endif

            /*
             * Now, update them with the properties the user might gave to us
             * via the STARTUPINFO structure before calling CreateProcess
             * (and which was transmitted via the ConsoleStartInfo structure).
             * We therefore overwrite the values read in the registry.
             */
            if (ConsoleStartInfo->dwStartupFlags & STARTF_USESHOWWINDOW)
            {
                GuiInitInfo->TermInfo.ShowWindow = ConsoleStartInfo->wShowWindow;
            }
            if (ConsoleStartInfo->dwStartupFlags & STARTF_USEPOSITION)
            {
                ConsoleInfo->AutoPosition = FALSE;
                ConsoleInfo->WindowPosition.x = ConsoleStartInfo->dwWindowOrigin.X;
                ConsoleInfo->WindowPosition.y = ConsoleStartInfo->dwWindowOrigin.Y;
            }
            if (ConsoleStartInfo->dwStartupFlags & STARTF_RUNFULLSCREEN)
            {
                ConsoleInfo->FullScreen = TRUE;
            }
        }
    }

#if 0
    /* Revert impersonation */
    CsrRevertToSelf();
#endif

    // Font data
    StringCchCopyNW(GuiInitInfo->TermInfo.FaceName, ARRAYSIZE(GuiInitInfo->TermInfo.FaceName),
                    ConsoleInfo->FaceName, ARRAYSIZE(ConsoleInfo->FaceName));
    GuiInitInfo->TermInfo.FontFamily = ConsoleInfo->FontFamily;
    GuiInitInfo->TermInfo.FontSize   = ConsoleInfo->FontSize;
    GuiInitInfo->TermInfo.FontWeight = ConsoleInfo->FontWeight;

    // Display
    GuiInitInfo->TermInfo.FullScreen   = ConsoleInfo->FullScreen;
    GuiInitInfo->TermInfo.AutoPosition = ConsoleInfo->AutoPosition;
    GuiInitInfo->TermInfo.WindowOrigin = ConsoleInfo->WindowPosition;

    /* Initialize the icon handles */
    // if (ConsoleStartInfo->hIcon != NULL)
        GuiInitInfo->hIcon = ConsoleStartInfo->hIcon;
    // else
        // GuiInitInfo->hIcon = ghDefaultIcon;

    // if (ConsoleStartInfo->hIconSm != NULL)
        GuiInitInfo->hIconSm = ConsoleStartInfo->hIconSm;
    // else
        // GuiInitInfo->hIconSm = ghDefaultIconSm;

    // ASSERT(GuiInitInfo->hIcon && GuiInitInfo->hIconSm);

    /* Finally, initialize the frontend structure */
    FrontEnd->Vtbl     = &GuiVtbl;
    FrontEnd->Context  = NULL;
    FrontEnd->Context2 = GuiInitInfo;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI
GuiUnloadFrontEnd(IN OUT PFRONTEND FrontEnd)
{
    if (FrontEnd == NULL) return STATUS_INVALID_PARAMETER;

    if (FrontEnd->Context ) GuiDeinitFrontEnd(FrontEnd);
    if (FrontEnd->Context2)
    {
        /*
         * The frontend was loaded but never (or not successfully) initialised:
         * the window station and desktop handles GuiInit opened are still
         * owned by the initialisation structure.
         */
        PGUI_INIT_INFO GuiInitInfo = FrontEnd->Context2;
        if (GuiInitInfo->Desktop) CloseDesktop(GuiInitInfo->Desktop); // NtUserCloseDesktop
        if (GuiInitInfo->WinSta)  CloseWindowStation(GuiInitInfo->WinSta); // NtUserCloseWindowStation
        ConsoleFreeHeap(FrontEnd->Context2);
    }

    return STATUS_SUCCESS;
}

/* EOF */
