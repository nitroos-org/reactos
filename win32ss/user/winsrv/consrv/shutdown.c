/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Console Server DLL
 * FILE:            win32ss/user/winsrv/consrv/shutdown.c
 * PURPOSE:         Processes Shutdown
 * PROGRAMMERS:     Alex Ionescu
 */

/* INCLUDES *******************************************************************/

#include "consrv.h"
#include <psapi.h>

#define NDEBUG
#include <debug.h>

/* A reboot and a power-off are shutdowns, as Windows sends CTRL_SHUTDOWN_EVENT for them too.
 * USERSRV adds EWX_SHUTDOWN to both before the processes are notified; do not depend on it. */
#define EWX_SHUTDOWN_MASK   (EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF)

/* FUNCTIONS ******************************************************************/

static void
NotifyConsoleProcessForShutdown(IN PCSR_PROCESS CsrProcess,
                                IN PCONSOLE_PROCESS_DATA ProcessData,
                                IN ULONG Flags)
{
    ULONG CtrlEvent;

    DPRINT1("ConsoleClientShutdown(0x%p, 0x%x) - Console process [0x%x, 0x%x]\n",
             CsrProcess, Flags, CsrProcess->ClientId.UniqueProcess, CsrProcess->ClientId.UniqueThread);

    /*
     * A shutdown, reboot or power-off sends CTRL_SHUTDOWN_EVENT, a logoff CTRL_LOGOFF_EVENT.
     * A process of the system or of another logon context is a service: it is
     * not ended for a handler that took the event (see console.c). A logoff
     * does not get here for such a process (see ConsoleClientShutdown).
     */
    CtrlEvent = (Flags & EWX_SHUTDOWN_MASK) ? CTRL_SHUTDOWN_EVENT : CTRL_LOGOFF_EVENT;

    if (CsrProcess->ShutdownFlags & (CsrShutdownSystem | CsrShutdownOther))
        CtrlEvent |= 0x80000000UL; /* CTRL_EVENT_SERVICE_FLAG */

    ConSrvConsoleCtrlEventTimeout(CtrlEvent, ProcessData,
                                  ShutdownSettings.WaitToKillAppTimeout);
}

static BOOL
NotifyGenericProcessForShutdown(IN PCSR_PROCESS CsrProcess,
                                IN ULONG Flags)
{
    /* FIXME: Implement the generic process shutdown handler */
    UNIMPLEMENTED_ONCE;

    return TRUE;
}

ULONG
NTAPI
NonConsoleProcessShutdown(IN PCSR_PROCESS Process,
                          IN ULONG Flags)
{
    if (NotifyGenericProcessForShutdown(Process, Flags))
    {
        /* Terminate this process */
#if DBG
        WCHAR buffer[MAX_PATH];
        if (!GetProcessImageFileNameW(Process->ProcessHandle, buffer, ARRAYSIZE(buffer)))
        {
            DPRINT1("Terminating process %x\n", Process->ClientId.UniqueProcess);
        }
        else
        {
            DPRINT1("Terminating process %x (%S)\n", Process->ClientId.UniqueProcess, buffer);
        }
#endif
        NtTerminateProcess(Process->ProcessHandle, 0);
        WaitForSingleObject(Process->ProcessHandle, ShutdownSettings.ProcessTerminateTimeout);
    }

    CsrDereferenceProcess(Process);
    return CsrShutdownCsrProcess;
}

static BOOL CALLBACK
FindUnownedTopLevelWnd(IN HWND hWnd, IN LPARAM lParam)
{
    if (GetWindow(hWnd, GW_OWNER) == NULL)
    {
        *(PBOOL)lParam = TRUE;
        return FALSE; /* one is enough */
    }
    return TRUE;
}

/*
 * Whether a thread of the process owns a top-level window. A program linked as a console
 * program that creates windows (a managed WinForms program built without /target:winexe, a
 * Python or Tcl program with a window, ...) is a Windows application for the end of the session:
 * documented for SetConsoleCtrlHandler, CTRL_LOGOFF_EVENT and CTRL_SHUTDOWN_EVENT are not sent to
 * a process that loaded user32 or gdi32, its windows get WM_QUERYENDSESSION and WM_ENDSESSION.
 */
static BOOL
ProcessHasTopLevelWindows(IN PCSR_PROCESS CsrProcess)
{
    PCSR_PROCESS Process;
    PLIST_ENTRY NextEntry;
    HANDLE ThreadIds[128];
    ULONG Count = 0, i;
    BOOL Found = FALSE;

    if (!NT_SUCCESS(CsrLockProcessByClientId(CsrProcess->ClientId.UniqueProcess, &Process)))
        return FALSE;

    for (NextEntry = CsrProcess->ThreadList.Flink;
         NextEntry != &CsrProcess->ThreadList && Count < RTL_NUMBER_OF(ThreadIds);
         NextEntry = NextEntry->Flink)
    {
        PCSR_THREAD Thread = CONTAINING_RECORD(NextEntry, CSR_THREAD, Link);

        if (!(Thread->Flags & CsrThreadTerminated))
            ThreadIds[Count++] = Thread->ClientId.UniqueThread;
    }
    CsrUnlockProcess(Process);

    for (i = 0; i < Count && !Found; i++)
        EnumThreadWindows(HandleToUlong(ThreadIds[i]), FindUnownedTopLevelWnd, (LPARAM)&Found);

    return Found;
}

// NOTE: See https://web.archive.org/web/20150629001832/http://blogs.msdn.com/b/ntdebugging/archive/2007/06/09/how-windows-shuts-down.aspx
ULONG
NTAPI
ConsoleClientShutdown(IN PCSR_PROCESS CsrProcess,
                      IN ULONG Flags,
                      IN BOOLEAN FirstPhase)
{
    PCONSOLE_PROCESS_DATA ProcessData = ConsoleGetPerProcessData(CsrProcess);

    /* Do not kill system processes when a user is logging off */
    if ((Flags & EWX_SHUTDOWN_MASK) == EWX_LOGOFF &&
        (CsrProcess->ShutdownFlags & (CsrShutdownSystem | CsrShutdownOther)))
    {
        DPRINT("Do not kill a system process in a logoff request!\n");
        return CsrShutdownNonCsrProcess;
    }

    /* Is it a console process? */
    if ( ProcessData->ConsoleHandle != NULL ||
         ProcessData->HandleTable   != NULL )
    {
        /*
         * On the first pass a program of the user that owns top-level windows is left to the GUI server,
         * which sends the end-session messages to the windows. A system or other-context process is a
         * service and keeps the console control event. When the GUI server finds nothing to notify,
         * the second pass comes back here and the program is handled as a console process.
         */
        if (FirstPhase &&
            !(CsrProcess->ShutdownFlags & (CsrShutdownSystem | CsrShutdownOther)) &&
            ProcessHasTopLevelWindows(CsrProcess))
        {
            return CsrShutdownNonCsrProcess;
        }

        NotifyConsoleProcessForShutdown(CsrProcess, ProcessData, Flags);

        /* We are done with the process itself */
        CsrDereferenceProcess(CsrProcess);
        return CsrShutdownCsrProcess;
    }
    else
    {
        DPRINT("ConsoleClientShutdown(0x%p, 0x%x, %s) - Non-console process [0x%x, 0x%x]\n",
                CsrProcess, Flags, FirstPhase ? "FirstPhase" : "LastPhase",
                CsrProcess->ClientId.UniqueProcess, CsrProcess->ClientId.UniqueThread);

        /* On first pass, let the gui server terminate all the processes that it owns */
        if (FirstPhase) return CsrShutdownNonCsrProcess;

        /* Use the generic handler since this isn't a gui process */
        return NonConsoleProcessShutdown(CsrProcess, Flags);
    }

    return CsrShutdownNonCsrProcess;
}

/* EOF */
