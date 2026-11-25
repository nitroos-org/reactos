/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * PURPOSE:          GUI state check
 * FILE:             win32ss/user/ntuser/guicheck.c
 * PROGRAMER:        Casper S. Hornstrup (chorns@users.sourceforge.net)
 * NOTES:            The GuiCheck() function performs a few delayed operations:
 *                   1) A GUI process is assigned a window station
 *                   2) A message queue is created for a GUI thread before use
 *                   3) The system window classes are registered for a process
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserMisc);

/* GLOBALS *******************************************************************/

static LONG NrGuiAppsRunning = 0;

/* FUNCTIONS *****************************************************************/

static BOOL FASTCALL
co_AddGuiApp(PPROCESSINFO W32Data)
{
    W32Data->W32PF_flags |= W32PF_CREATEDWINORDC;
    if (InterlockedIncrement(&NrGuiAppsRunning) == 1)
    {
        BOOL Initialized;

        Initialized = co_IntInitializeDesktopGraphics();

        if (!Initialized)
        {
            W32Data->W32PF_flags &= ~W32PF_CREATEDWINORDC;
            InterlockedDecrement(&NrGuiAppsRunning);
            return FALSE;
        }
    }
    return TRUE;
}

static void FASTCALL
RemoveGuiApp(PPROCESSINFO W32Data)
{
    W32Data->W32PF_flags &= ~W32PF_CREATEDWINORDC;
    if (InterlockedDecrement(&NrGuiAppsRunning) == 0)
    {
        IntEndDesktopGraphics();
    }
}

/*
 * A session that does not own the console (session 0, the services) draws into memory. Its display was
 * set up only while one of its programs held a window or a device context: a session running services
 * only could have none, and then a console or an icon that a service asked for found no display (an
 * assertion in csrss on a checked build). The display of such a session is set up when its interactive
 * window station gets its first input desktop and is kept for as long as the session lives: one
 * reference that no program owns.
 */
VOID FASTCALL
co_IntHoldHeadlessDisplay(VOID)
{
    static BOOL Held = FALSE;

    if (!gbHeadlessSession || Held)
        return;

    if (InterlockedIncrement(&NrGuiAppsRunning) == 1)
    {
        if (!co_IntInitializeDesktopGraphics())
        {
            ERR("The memory display of the session cannot be set up\n");
            InterlockedDecrement(&NrGuiAppsRunning);
            return;
        }
    }
    Held = TRUE;
}

BOOL FASTCALL
co_IntGraphicsCheck(BOOL Create)
{
    PPROCESSINFO W32Data;

    W32Data = PsGetCurrentProcessWin32Process();
    if (Create)
    {
        if (!(W32Data->W32PF_flags & W32PF_CREATEDWINORDC) && !(W32Data->W32PF_flags & W32PF_MANUALGUICHECK))
        {
            return co_AddGuiApp(W32Data);
        }
    }
    else
    {
        if ((W32Data->W32PF_flags & W32PF_CREATEDWINORDC) && !(W32Data->W32PF_flags & W32PF_MANUALGUICHECK))
        {
            RemoveGuiApp(W32Data);
        }
    }

    return TRUE;
}

VOID
FASTCALL
co_IntUserManualGuiCheck(BOOL Create)
{
    PPROCESSINFO W32Data = (PPROCESSINFO)PsGetCurrentProcessWin32Process();
    W32Data->W32PF_flags |= W32PF_MANUALGUICHECK;

    if (Create)
    {
        co_AddGuiApp(W32Data);
    }
    else
    {
        RemoveGuiApp(W32Data);
    }
}

/* EOF */
