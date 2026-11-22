/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the enforcement of job object UI restrictions (JOB_OBJECT_UILIMIT_*)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A child process is put into a job with UI restrictions and makes the USER
 * calls that each JOB_OBJECT_UILIMIT_* flag is documented to prevent (MSDN:
 * JOBOBJECT_BASIC_UI_RESTRICTIONS, UserHandleGrantAccess, Nested Jobs,
 * AssignProcessToJobObject). Every child checks every row, so each flag is
 * also seen not to restrict what belongs to the others.
 *
 * The documentation names the prevented functions but not how they fail. The
 * error codes checked here (ERROR_ACCESS_DENIED, and DISP_CHANGE_FAILED for
 * ChangeDisplaySettings) are those of this implementation; they are still to
 * be measured on Windows.
 *
 * Without enforcement the child of the EXITWINDOWS row would log the session
 * off, so that row only runs once the other restrictions were seen to work.
 */

#include "precomp.h"

#include <strsafe.h>

#define TEST_CLASS          L"JobUIRestrictionsClass"
#define PARENT_ATOM         L"JobUIRestrictions parent atom"
#define CHILD_ATOM          L"JobUIRestrictions child atom"
#define CLIP_TEXT           L"JobUIRestrictions"
#define TEST_DESKTOP        L"JobUIRestrictionsDesktop"
#define GO_EVENT            L"user32_apitest_JobUIRestrictions_go"
#define DONE_EVENT          L"user32_apitest_JobUIRestrictions_done"

#define UI_ALL_BUT_EXIT     (JOB_OBJECT_UILIMIT_ALL & ~JOB_OBJECT_UILIMIT_EXITWINDOWS)

/* What the child does: check the rows, or check them twice with a pause between */
#define CHILD_ROWS          0
#define CHILD_TWO_ROUNDS    1
#define CHILD_EXITWINDOWS   2
#define CHILD_GRANT         3
#define CHILD_PROBE         4

static HWND g_hWnd;
static BOOL g_bEnforced = FALSE;

/* ---------------------------------------------------------------- child --- */

static
void
CheckRows(
    _In_ DWORD Restricted,
    _In_ HWND hOuter)
{
    BOOL bHandles = !!(Restricted & JOB_OBJECT_UILIMIT_HANDLES);
    BOOL bRead = !!(Restricted & JOB_OBJECT_UILIMIT_READCLIPBOARD);
    BOOL bWrite = !!(Restricted & JOB_OBJECT_UILIMIT_WRITECLIPBOARD);
    BOOL bSpi = !!(Restricted & JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS);
    BOOL bDisplay = !!(Restricted & JOB_OBJECT_UILIMIT_DISPLAYSETTINGS);
    BOOL bAtoms = !!(Restricted & JOB_OBJECT_UILIMIT_GLOBALATOMS);
    BOOL bDesktop = !!(Restricted & JOB_OBJECT_UILIMIT_DESKTOP);
    BOOL bResult, bBeep = FALSE;
    DEVMODEW DevMode;
    HDESK hDesk;
    HANDLE hData;
    ATOM Atom;
    LONG lResult;

    /* JOB_OBJECT_UILIMIT_HANDLES: the window of the parent is out of reach,
       the desktop window is not */
    ok(IsWindow(hOuter) == !bHandles, "0x%02lx: IsWindow(outer) gave %d\n",
       Restricted, IsWindow(hOuter));
    SetLastError(0xdeadbeef);
    bResult = PostMessageW(hOuter, WM_NULL, 0, 0);
    ok(bResult == !bHandles, "0x%02lx: PostMessage(outer) gave %d\n", Restricted, bResult);
    if (bHandles)
        ok(GetLastError() == ERROR_INVALID_WINDOW_HANDLE, "0x%02lx: PostMessage error %lu\n",
           Restricted, GetLastError());
    ok(IsWindow(GetDesktopWindow()), "0x%02lx: the desktop window is not a window\n", Restricted);

    /* JOB_OBJECT_UILIMIT_READCLIPBOARD / WRITECLIPBOARD */
    ok(IsClipboardFormatAvailable(CF_UNICODETEXT), "0x%02lx: no text on the clipboard\n", Restricted);
    bResult = OpenClipboard(NULL);
    ok(bResult, "0x%02lx: OpenClipboard failed with %lu\n", Restricted, GetLastError());
    if (bResult)
    {
        SetLastError(0xdeadbeef);
        hData = GetClipboardData(CF_UNICODETEXT);
        ok((hData != NULL) == !bRead, "0x%02lx: GetClipboardData gave %p\n", Restricted, hData);
        if (bRead)
            ok(GetLastError() == ERROR_ACCESS_DENIED, "0x%02lx: GetClipboardData error %lu\n",
               Restricted, GetLastError());

        SetLastError(0xdeadbeef);
        bResult = EmptyClipboard();
        ok(bResult == !bWrite, "0x%02lx: EmptyClipboard gave %d\n", Restricted, bResult);
        if (bWrite)
        {
            ok(GetLastError() == ERROR_ACCESS_DENIED, "0x%02lx: EmptyClipboard error %lu\n",
               Restricted, GetLastError());

            hData = GlobalAlloc(GMEM_MOVEABLE, sizeof(CLIP_TEXT));
            if (hData)
            {
                PWSTR pText = GlobalLock(hData);
                StringCbCopyW(pText, sizeof(CLIP_TEXT), CLIP_TEXT);
                GlobalUnlock(hData);
                SetLastError(0xdeadbeef);
                ok(SetClipboardData(CF_UNICODETEXT, hData) == NULL,
                   "0x%02lx: SetClipboardData succeeded\n", Restricted);
                ok(GetLastError() == ERROR_ACCESS_DENIED, "0x%02lx: SetClipboardData error %lu\n",
                   Restricted, GetLastError());
                GlobalFree(hData);
            }
            /* What the parent put there is still there */
            ok(IsClipboardFormatAvailable(CF_UNICODETEXT), "0x%02lx: the text is gone\n", Restricted);
        }
        CloseClipboard();
    }

    /* JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS: reading stays allowed */
    ok(SystemParametersInfoW(SPI_GETBEEP, 0, &bBeep, 0), "0x%02lx: SPI_GETBEEP failed\n", Restricted);
    SetLastError(0xdeadbeef);
    bResult = SystemParametersInfoW(SPI_SETBEEP, bBeep, NULL, 0);
    ok(bResult == !bSpi, "0x%02lx: SPI_SETBEEP gave %d\n", Restricted, bResult);
    if (bSpi)
        ok(GetLastError() == ERROR_ACCESS_DENIED, "0x%02lx: SPI_SETBEEP error %lu\n",
           Restricted, GetLastError());

    /* JOB_OBJECT_UILIMIT_DISPLAYSETTINGS: also a test of the current mode */
    ZeroMemory(&DevMode, sizeof(DevMode));
    DevMode.dmSize = sizeof(DevMode);
    ok(EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &DevMode),
       "0x%02lx: EnumDisplaySettings failed\n", Restricted);
    lResult = ChangeDisplaySettingsW(&DevMode, CDS_TEST);
    ok(lResult == (bDisplay ? DISP_CHANGE_FAILED : DISP_CHANGE_SUCCESSFUL),
       "0x%02lx: ChangeDisplaySettings(CDS_TEST) gave %ld\n", Restricted, lResult);

    /* JOB_OBJECT_UILIMIT_GLOBALATOMS: the job has a table of its own */
    Atom = GlobalFindAtomW(PARENT_ATOM);
    ok((Atom != 0) == !bAtoms, "0x%02lx: GlobalFindAtom(parent) gave 0x%x\n", Restricted, Atom);
    Atom = GlobalAddAtomW(CHILD_ATOM);
    ok(Atom != 0, "0x%02lx: GlobalAddAtom failed with %lu\n", Restricted, GetLastError());
    ok(GlobalFindAtomW(CHILD_ATOM) == Atom, "0x%02lx: GlobalFindAtom(child) did not find it\n", Restricted);

    /* JOB_OBJECT_UILIMIT_DESKTOP: neither creating nor switching */
    SetLastError(0xdeadbeef);
    hDesk = CreateDesktopW(TEST_DESKTOP, NULL, NULL, 0, GENERIC_ALL, NULL);
    ok((hDesk != NULL) == !bDesktop, "0x%02lx: CreateDesktop gave %p\n", Restricted, hDesk);
    if (bDesktop)
        ok(GetLastError() == ERROR_ACCESS_DENIED, "0x%02lx: CreateDesktop error %lu\n",
           Restricted, GetLastError());
    if (hDesk)
        CloseDesktop(hDesk);
    hDesk = OpenInputDesktop(0, FALSE, DESKTOP_SWITCHDESKTOP);
    if (hDesk)
    {
        /* To the desktop that already is the input desktop: nothing changes either way */
        SetLastError(0xdeadbeef);
        bResult = SwitchDesktop(hDesk);
        ok(bResult == !bDesktop, "0x%02lx: SwitchDesktop gave %d\n", Restricted, bResult);
        if (bDesktop)
            ok(GetLastError() == ERROR_ACCESS_DENIED, "0x%02lx: SwitchDesktop error %lu\n",
               Restricted, GetLastError());
        CloseDesktop(hDesk);
    }
}

static
void
RunChild(
    _In_ int argc,
    _In_ char **argv)
{
    DWORD Mode = strtoul(argv[3], NULL, 16);
    DWORD Restricted = strtoul(argv[4], NULL, 16);
    HWND hOuter = (HWND)(ULONG_PTR)strtoull(argv[5], NULL, 16);

    switch (Mode)
    {
        case CHILD_ROWS:
            CheckRows(Restricted, hOuter);
            break;

        case CHILD_TWO_ROUNDS:
        {
            /* Restricted as argv says, then by what the parent changed meanwhile */
            HANDLE hGo = OpenEventW(SYNCHRONIZE, FALSE, GO_EVENT);
            HANDLE hDone = OpenEventW(EVENT_MODIFY_STATE, FALSE, DONE_EVENT);
            ok(hGo != NULL && hDone != NULL, "Events missing\n");
            if (!hGo || !hDone)
                break;
            CheckRows(Restricted, hOuter);
            SetEvent(hDone);
            ok(WaitForSingleObject(hGo, 30000) == WAIT_OBJECT_0, "The parent did not go on\n");
            CheckRows(strtoul(argv[6], NULL, 16), hOuter);
            CloseHandle(hGo);
            CloseHandle(hDone);
            break;
        }

        case CHILD_GRANT:
        {
            HANDLE hJob;
            BOOL bResult;
            HWND hOwn;

            /* Granted to the job by the parent */
            ok(IsWindow(hOuter), "The granted window is not a window\n");
            ok(PostMessageW(hOuter, WM_NULL, 0, 0), "PostMessage(granted) failed with %lu\n", GetLastError());

            /* MSDN (UserHandleGrantAccess): not from a process of the job, and
               not for a handle that a process of the job owns */
            hOwn = CreateWindowExW(0, L"STATIC", L"own", WS_POPUP, 0, 0, 10, 10, NULL, NULL, NULL, NULL);
            ok(hOwn != NULL, "CreateWindowEx failed with %lu\n", GetLastError());

            /* The parent's handle of the job, inherited */
            hJob = (HANDLE)(ULONG_PTR)strtoull(argv[6], NULL, 16);
            if (hJob && hOwn)
            {
                SetLastError(0xdeadbeef);
                bResult = UserHandleGrantAccess(hOwn, hJob, TRUE);
                ok(bResult == FALSE, "A process of the job granted its job a handle\n");
                ok(GetLastError() == ERROR_ACCESS_DENIED, "UserHandleGrantAccess error %lu\n", GetLastError());
            }
            if (hOwn)
                DestroyWindow(hOwn);
            break;
        }

        case CHILD_PROBE:
        {
            /* Silent: exit code 0 when changing a parameter is refused */
            BOOL bBeep = FALSE;
            SystemParametersInfoW(SPI_GETBEEP, 0, &bBeep, 0);
            ExitProcess(SystemParametersInfoW(SPI_SETBEEP, bBeep, NULL, 0) ? 1 : 0);
        }

        case CHILD_EXITWINDOWS:
        {
            BOOL bResult;
            SetLastError(0xdeadbeef);
            bResult = ExitWindowsEx(EWX_LOGOFF, 0);
            ok(bResult == FALSE, "ExitWindowsEx(EWX_LOGOFF) succeeded in the job\n");
            ok(GetLastError() == ERROR_ACCESS_DENIED, "ExitWindowsEx error %lu\n", GetLastError());
            break;
        }
    }
}

/* --------------------------------------------------------------- parent --- */

static
void
PutText(void)
{
    HGLOBAL hData = GlobalAlloc(GMEM_MOVEABLE, sizeof(CLIP_TEXT));
    PWSTR pText;

    if (!hData)
        return;
    pText = GlobalLock(hData);
    StringCbCopyW(pText, sizeof(CLIP_TEXT), CLIP_TEXT);
    GlobalUnlock(hData);
    if (OpenClipboard(g_hWnd))
    {
        EmptyClipboard();
        if (!SetClipboardData(CF_UNICODETEXT, hData))
            GlobalFree(hData);
        CloseClipboard();
    }
    else
    {
        GlobalFree(hData);
    }
}

static
HANDLE
MakeJob(
    _In_ BOOL bInherit,
    _In_ DWORD UiRestrictions)
{
    JOBOBJECT_BASIC_UI_RESTRICTIONS Ui;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, bInherit };
    HANDLE hJob = CreateJobObjectW(&sa, NULL);

    ok(hJob != NULL, "CreateJobObject failed with %lu\n", GetLastError());
    if (hJob && UiRestrictions)
    {
        Ui.UIRestrictionsClass = UiRestrictions;
        ok(SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &Ui, sizeof(Ui)),
           "Setting UI restrictions 0x%lx failed with %lu\n", UiRestrictions, GetLastError());
    }
    return hJob;
}

/* Starts the child suspended; the caller puts it into its jobs and resumes it */
static
BOOL
StartChild(
    _In_ DWORD Mode,
    _In_ DWORD Restricted,
    _In_ ULONG_PTR Extra,
    _Out_ PROCESS_INFORMATION *pi)
{
    WCHAR FileName[MAX_PATH];
    WCHAR CommandLine[MAX_PATH + 160];
    STARTUPINFOW si;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" JobUIRestrictions child %lx %lx %Ix %Ix",
                    FileName, Mode, Restricted, (ULONG_PTR)g_hWnd, Extra);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, pi))
    {
        skip("CreateProcess failed with %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

/* Assigns, or says why the test cannot (the test itself runs in a job) */
static
BOOL
Assign(
    _In_ HANDLE hJob,
    _In_ PROCESS_INFORMATION *pi)
{
    if (AssignProcessToJobObject(hJob, pi->hProcess))
        return TRUE;

    skip("AssignProcessToJobObject failed with %lu (in a job already?)\n", GetLastError());
    TerminateProcess(pi->hProcess, 0);
    CloseHandle(pi->hProcess);
    CloseHandle(pi->hThread);
    return FALSE;
}

/* Waits with the window of the parent served: it owns the clipboard, and a child
   that empties it sends WM_DESTROYCLIPBOARD there and waits for the answer */
static
DWORD
WaitPumping(
    _In_ HANDLE hObject,
    _In_ DWORD Timeout)
{
    DWORD Start = GetTickCount();

    for (;;)
    {
        DWORD Elapsed = GetTickCount() - Start, Wait;
        MSG msg;

        if (Elapsed >= Timeout)
            return WAIT_TIMEOUT;
        Wait = MsgWaitForMultipleObjects(1, &hObject, FALSE, Timeout - Elapsed, QS_ALLINPUT);
        if (Wait != WAIT_OBJECT_0 + 1)
            return Wait;
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
            DispatchMessageW(&msg);
    }
}

static
void
Finish(
    _In_ PROCESS_INFORMATION *pi)
{
    DWORD Wait = WaitPumping(pi->hProcess, 60000);

    ok(Wait == WAIT_OBJECT_0, "The child did not exit, wait gave %lu\n", Wait);
    if (Wait != WAIT_OBJECT_0)
        TerminateProcess(pi->hProcess, 1);
    winetest_wait_child_process(pi->hProcess);
    CloseHandle(pi->hProcess);
    CloseHandle(pi->hThread);
}

/* One child in a job restricted by FLAGS checks every row */
static
BOOL
RunRows(
    _In_ DWORD Flags)
{
    PROCESS_INFORMATION pi;
    HANDLE hJob;
    BOOL bRan = FALSE;

    PutText();
    hJob = MakeJob(FALSE,Flags);
    if (!hJob)
        return FALSE;
    if (StartChild(CHILD_ROWS, Flags, 0, &pi) && Assign(hJob, &pi))
    {
        ResumeThread(pi.hThread);
        Finish(&pi);
        bRan = TRUE;

        /* What the child added to the job's atom table is not in the global one */
        if (Flags & JOB_OBJECT_UILIMIT_GLOBALATOMS)
        {
            ok(GlobalFindAtomW(CHILD_ATOM) == 0, "0x%02lx: the atom of the job is global\n", Flags);
        }
        else
        {
            ATOM Atom = GlobalFindAtomW(CHILD_ATOM);
            ok(Atom != 0, "0x%02lx: the atom of the child is not global\n", Flags);
            while (Atom && GlobalDeleteAtom(Atom) == 0 && GlobalFindAtomW(CHILD_ATOM))
                ;
        }
    }
    CloseHandle(hJob);
    return bRan;
}

/* The limits are read when a call is made: set after the child started, and cleared again */
static
void
RunLateAndCleared(void)
{
    PROCESS_INFORMATION pi;
    JOBOBJECT_BASIC_UI_RESTRICTIONS Ui;
    HANDLE hJob, hGo, hDone;

    hGo = CreateEventW(NULL, TRUE, FALSE, GO_EVENT);
    hDone = CreateEventW(NULL, TRUE, FALSE, DONE_EVENT);
    hJob = MakeJob(FALSE,UI_ALL_BUT_EXIT);
    if (!hGo || !hDone || !hJob)
        goto Cleanup;

    PutText();
    if (StartChild(CHILD_TWO_ROUNDS, UI_ALL_BUT_EXIT, 0, &pi) && Assign(hJob, &pi))
    {
        ResumeThread(pi.hThread);
        ok(WaitPumping(hDone, 30000) == WAIT_OBJECT_0, "The child did not check its rows\n");
        Ui.UIRestrictionsClass = 0;
        ok(SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &Ui, sizeof(Ui)),
           "Clearing the restrictions failed with %lu\n", GetLastError());
        PutText();
        SetEvent(hGo);
        Finish(&pi);
        {
            ATOM Atom = GlobalFindAtomW(CHILD_ATOM);
            while (Atom && GlobalDeleteAtom(Atom) == 0 && GlobalFindAtomW(CHILD_ATOM))
                ;
        }
    }

Cleanup:
    if (hJob) CloseHandle(hJob);
    if (hGo) CloseHandle(hGo);
    if (hDone) CloseHandle(hDone);
}

/* Nested jobs: a job with UI limits does not take a process that is in a job
   already; limits set later on the outer job of a nest apply to the inner one */
static
void
RunNested(void)
{
    PROCESS_INFORMATION pi;
    JOBOBJECT_BASIC_UI_RESTRICTIONS Ui;
    HANDLE hOuter, hInner, hLimited, hGo, hDone;

    hGo = CreateEventW(NULL, TRUE, FALSE, GO_EVENT);
    hDone = CreateEventW(NULL, TRUE, FALSE, DONE_EVENT);
    hOuter = MakeJob(FALSE,0);
    hInner = MakeJob(FALSE,0);
    hLimited = MakeJob(FALSE,JOB_OBJECT_UILIMIT_READCLIPBOARD);
    if (!hGo || !hDone || !hOuter || !hInner || !hLimited)
        goto Cleanup;

    PutText();
    if (StartChild(CHILD_TWO_ROUNDS, 0, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, &pi) && Assign(hOuter, &pi))
    {
        BOOL bResult;

        /* Unrestricted jobs nest */
        ok(AssignProcessToJobObject(hInner, pi.hProcess), "Nesting failed with %lu\n", GetLastError());

        /* MSDN (AssignProcessToJobObject): a process in a job cannot join a job with UI limits */
        SetLastError(0xdeadbeef);
        bResult = AssignProcessToJobObject(hLimited, pi.hProcess);
        ok(bResult == FALSE, "A job with UI limits took a process of another job\n");
        ok(GetLastError() == ERROR_ACCESS_DENIED, "AssignProcessToJobObject error %lu\n", GetLastError());

        ResumeThread(pi.hThread);
        ok(WaitPumping(hDone, 30000) == WAIT_OBJECT_0, "The child did not check its rows\n");

        /* Limits of the outer job apply to the process of the inner one */
        Ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
        ok(SetInformationJobObject(hOuter, JobObjectBasicUIRestrictions, &Ui, sizeof(Ui)),
           "Restricting the outer job failed with %lu\n", GetLastError());
        PutText();
        SetEvent(hGo);
        Finish(&pi);
        {
            ATOM Atom = GlobalFindAtomW(CHILD_ATOM);
            while (Atom && GlobalDeleteAtom(Atom) == 0 && GlobalFindAtomW(CHILD_ATOM))
                ;
        }
    }

Cleanup:
    if (hLimited) CloseHandle(hLimited);
    if (hInner) CloseHandle(hInner);
    if (hOuter) CloseHandle(hOuter);
    if (hGo) CloseHandle(hGo);
    if (hDone) CloseHandle(hDone);
}

/* UserHandleGrantAccess: a granted window is usable from the job */
static
void
RunGrant(void)
{
    PROCESS_INFORMATION pi;
    HANDLE hJob;

    /* Inherited: the child gets the same handle value */
    hJob = MakeJob(TRUE, JOB_OBJECT_UILIMIT_HANDLES);
    if (!hJob)
        return;

    ok(UserHandleGrantAccess(g_hWnd, hJob, TRUE), "UserHandleGrantAccess failed with %lu\n", GetLastError());
    if (StartChild(CHILD_GRANT, JOB_OBJECT_UILIMIT_HANDLES, (ULONG_PTR)hJob, &pi) && Assign(hJob, &pi))
    {
        ResumeThread(pi.hThread);
        Finish(&pi);
    }
    UserHandleGrantAccess(g_hWnd, hJob, FALSE);
    CloseHandle(hJob);
}

static
void
RunExitWindows(void)
{
    PROCESS_INFORMATION pi;
    HANDLE hJob;

    hJob = MakeJob(FALSE,JOB_OBJECT_UILIMIT_EXITWINDOWS);
    if (!hJob)
        return;
    if (StartChild(CHILD_EXITWINDOWS, JOB_OBJECT_UILIMIT_EXITWINDOWS, 0, &pi) && Assign(hJob, &pi))
    {
        ResumeThread(pi.hThread);
        Finish(&pi);
    }
    CloseHandle(hJob);
}

START_TEST(JobUIRestrictions)
{
    static const DWORD Single[] =
    {
        JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
        JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_DESKTOP
    };
    WNDCLASSW wc;
    ATOM ParentAtom;
    char **argv;
    int argc;
    ULONG i;

    argc = winetest_get_mainargs(&argv);
    if (argc >= 6 && !strcmp(argv[2], "child"))
    {
        RunChild(argc, argv);
        return;
    }

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = TEST_CLASS;
    RegisterClassW(&wc);
    g_hWnd = CreateWindowExW(0, TEST_CLASS, L"outer", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, NULL, NULL);
    ok(g_hWnd != NULL, "CreateWindowEx failed with %lu\n", GetLastError());
    if (!g_hWnd)
        return;
    ParentAtom = GlobalAddAtomW(PARENT_ATOM);

    /* Unrestricted first: every row is allowed */
    if (!RunRows(0))
        goto Cleanup;

    /* One row per flag, then all of them but EXITWINDOWS */
    for (i = 0; i < _countof(Single); i++)
        RunRows(Single[i]);
    RunRows(UI_ALL_BUT_EXIT);

    RunLateAndCleared();
    RunNested();
    RunGrant();

    /* Only once the system was seen to enforce the restrictions: without
       that the child would log the session off */
    {
        PROCESS_INFORMATION pi;
        HANDLE hJob = MakeJob(FALSE,JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS);

        /* A probe: a child that tries to change a parameter in such a job */
        if (hJob && StartChild(CHILD_PROBE, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, 0, &pi) && Assign(hJob, &pi))
        {
            DWORD ExitCode = 1;
            ResumeThread(pi.hThread);
            WaitPumping(pi.hProcess, 60000);
            GetExitCodeProcess(pi.hProcess, &ExitCode);
            g_bEnforced = (ExitCode == 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        if (hJob)
            CloseHandle(hJob);
    }
    if (g_bEnforced)
        RunExitWindows();
    else
        skip("UI restrictions are not enforced: ExitWindowsEx in the job would log the session off\n");

Cleanup:
    if (ParentAtom)
        GlobalDeleteAtom(ParentAtom);
    DestroyWindow(g_hWnd);
    UnregisterClassW(TEST_CLASS, GetModuleHandleW(NULL));
}
