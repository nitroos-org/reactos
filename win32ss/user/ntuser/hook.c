/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * PURPOSE:          Window hooks
 * PROGRAMER:        Casper S. Hornstrup <chorns@users.sourceforge.net>
 *                   James Tabor <james.tabor@reactos.org>
 *                   Rafal Harabien <rafalh@reactos.org>
  * NOTE:            Most of this code was adapted from Wine,
 *                   Copyright (C) 2002 Alexandre Julliard
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserHook);

typedef struct _HOOKPACK
{
  PHOOK pHk;
  LPARAM lParam;
  PVOID pHookStructs;
} HOOKPACK, *PHOOKPACK;

UNICODE_STRING strUahModule;
UNICODE_STRING strUahInitFunc;
PPROCESSINFO ppiUahServer;

/* PRIVATE FUNCTIONS *********************************************************/

/* A hook pack belongs to the sent message that carries it until the receiver runs the
   hook (co_CallHook frees it); a message dropped without being dispatched frees it here */
VOID
FASTCALL
IntFreeHookPack(PVOID Pack)
{
    PHOOKPACK pHP = Pack;

    /* The pack holds a reference on its hook (taken in co_IntCallLowLevelHook): the hook may be
       unhooked while the call is still queued, and the receiver reads it when it dispatches */
    if (pHP->pHk) UserDereferenceObject(pHP->pHk);
    if (pHP->pHookStructs) ExFreePoolWithTag(pHP->pHookStructs, TAG_HOOK);
    ExFreePoolWithTag(pHP, TAG_HOOK);
}

/* Calls ClientLoadLibrary in user32 in order to load or unload a module */
BOOL
IntLoadHookModule(int iHookID, HHOOK hHook, BOOL Unload)
{
   PPROCESSINFO ppi;
   BOOL bResult;

   ppi = PsGetCurrentProcessWin32Process();

   TRACE("IntLoadHookModule. Client PID: %p\n", PsGetProcessId(ppi->peProcess));

    /* Check if this is the api hook */
    if(iHookID == WH_APIHOOK)
    {
        /* An unload callback of this process is running: no load or second unload until it returns */
        if (ppi->W32PF_flags & W32PF_APIHOOKUNLOADING)
            return Unload;

        if(!Unload && !(ppi->W32PF_flags & W32PF_APIHOOKLOADED))
        {
            /* A load message sent at registration can arrive after the hook was unregistered */
            if (!(gpsi->dwSRVIFlags & SRVINFO_APIHOOK))
                return FALSE;

            /* A callback in user mode can trigger UserLoadApiHook to be called and
               as a result IntLoadHookModule will be called recursively.
               To solve this we set the flag that means that the application has
               loaded the api hook before the callback and in case of error we remove it */
            ppi->W32PF_flags |= W32PF_APIHOOKLOADED;

            /* Call ClientLoadLibrary in user32 */
            bResult = co_IntClientLoadLibrary(&strUahModule, &strUahInitFunc, Unload, TRUE);
            TRACE("co_IntClientLoadLibrary returned %d\n", bResult );
            if (!bResult)
            {
                /* Remove the flag we set before */
                ppi->W32PF_flags &= ~W32PF_APIHOOKLOADED;
            }
            return bResult;
        }
        else if(Unload && (ppi->W32PF_flags & W32PF_APIHOOKLOADED))
        {
            /* Every thread of the process gets its own unload message, and the callback
               leaves the user lock: clear the flag first, so that only one thread unloads */
            ppi->W32PF_flags &= ~W32PF_APIHOOKLOADED;
            ppi->W32PF_flags |= W32PF_APIHOOKUNLOADING;

            /* Call ClientLoadLibrary in user32 */
            bResult = co_IntClientLoadLibrary(NULL, NULL, Unload, TRUE);
            ppi->W32PF_flags &= ~W32PF_APIHOOKUNLOADING;
            if (!bResult)
            {
                /* The module was not unloaded: keep the process marked as loaded */
                ppi->W32PF_flags |= W32PF_APIHOOKLOADED;
            }
            return bResult;
        }

        return TRUE;
    }

    STUB;

    return FALSE;
}

/*
IntHookModuleUnloaded:
Sends a internal message to all threads of the requested desktop
and notifies them that a global hook was destroyed
and an injected module must be unloaded.
As a result, IntLoadHookModule will be called for all the threads that
will receive the special purpose internal message.
*/
BOOL
IntHookModuleUnloaded(PDESKTOP pdesk, int iHookID, HHOOK hHook)
{
    PTHREADINFO ptiCurrent;
    PLIST_ENTRY ListEntry;
    PPROCESSINFO ppiCsr;

    TRACE("IntHookModuleUnloaded: iHookID=%d\n", iHookID);

    ppiCsr = PsGetProcessWin32Process(gpepCSRSS);

    ListEntry = pdesk->PtiList.Flink;
    while(ListEntry != &pdesk->PtiList)
    {
        ptiCurrent = CONTAINING_RECORD(ListEntry, THREADINFO, PtiLink);

        /* FIXME: Do some more security checks here */

        /* FIXME: HACK: The first check is a reactos specific hack for system threads */
        if(!PsIsSystemProcess(ptiCurrent->ppi->peProcess) &&
           ptiCurrent->ppi != ppiCsr)
        {
            if(ptiCurrent->ppi->W32PF_flags & W32PF_APIHOOKLOADED)
            {
                TRACE("IntHookModuleUnloaded: sending message to PID %p, ppi=%p\n", PsGetProcessId(ptiCurrent->ppi->peProcess), ptiCurrent->ppi);
                co_MsqSendMessageAsync( ptiCurrent,
                                        0,
                                        iHookID,
                                        TRUE,
                                        (LPARAM)hHook,
                                        NULL,
                                        0,
                                        FALSE,
                                        MSQ_INJECTMODULE);
            }
        }
        ListEntry = ListEntry->Flink;
    }

    return TRUE;
}

BOOL
FASTCALL
UserLoadApiHook(VOID)
{
    return IntLoadHookModule(WH_APIHOOK, 0, FALSE);
}

BOOL
FASTCALL
UserRegisterUserApiHook(
    PUNICODE_STRING pstrDllName,
    PUNICODE_STRING pstrFuncName)
{
    PTHREADINFO pti, ptiCurrent;
    HWND *List;
    PWND DesktopWindow, pwndCurrent;
    ULONG i;
    PPROCESSINFO ppiCsr;

    pti = PsGetCurrentThreadWin32Thread();
    ppiCsr = PsGetProcessWin32Process(gpepCSRSS);

    /* Fail if the api hook is already registered */
    if(gpsi->dwSRVIFlags & SRVINFO_APIHOOK)
    {
        return FALSE;
    }

    TRACE("UserRegisterUserApiHook. Server PID: %p\n", PsGetProcessId(pti->ppi->peProcess));

    /* Register the api hook */
    gpsi->dwSRVIFlags |= SRVINFO_APIHOOK;

    strUahModule = *pstrDllName;
    strUahInitFunc = *pstrFuncName;
    ppiUahServer = pti->ppi;

    /* Broadcast an internal message to every top level window */
    DesktopWindow = UserGetWindowObject(IntGetDesktopWindow());
    List = IntWinListChildren(DesktopWindow);

    if (List != NULL)
    {
        for (i = 0; List[i]; i++)
        {
            pwndCurrent = UserGetWindowObject(List[i]);
            if(pwndCurrent == NULL)
            {
                continue;
            }
            ptiCurrent = pwndCurrent->head.pti;

           /* FIXME: The first check is a reactos specific hack for system threads */
            if(PsIsSystemProcess(ptiCurrent->ppi->peProcess) ||
                ptiCurrent->ppi == ppiCsr)
            {
                continue;
            }

            co_MsqSendMessageAsync( ptiCurrent,
                                    0,
                                    WH_APIHOOK,
                                    FALSE,   /* Load the module */
                                    0,
                                    NULL,
                                    0,
                                    FALSE,
                                    MSQ_INJECTMODULE);
        }
        ExFreePoolWithTag(List, USERTAG_WINDOWLIST);
    }

    return TRUE;
}

BOOL
FASTCALL
UserUnregisterUserApiHook(VOID)
{
    PTHREADINFO pti;

    pti = PsGetCurrentThreadWin32Thread();

    /* Fail if the api hook is not registered */
    if(!(gpsi->dwSRVIFlags & SRVINFO_APIHOOK))
    {
        return FALSE;
    }

    /* Only the process that registered the api hook can uregister it */
    if(ppiUahServer != PsGetCurrentProcessWin32Process())
    {
        return FALSE;
    }

    TRACE("UserUnregisterUserApiHook. Server PID: %p\n", PsGetProcessId(pti->ppi->peProcess));

    /* Unregister the api hook */
    gpsi->dwSRVIFlags &= ~SRVINFO_APIHOOK;
    ppiUahServer = NULL;
    ReleaseCapturedUnicodeString(&strUahModule, UserMode);
    ReleaseCapturedUnicodeString(&strUahInitFunc, UserMode);

    /* Notify all applications that the api hook module must be unloaded */
    return IntHookModuleUnloaded(pti->rpdesk, WH_APIHOOK, 0);
}

static
LRESULT
FASTCALL
co_IntCallLowLevelHook(PHOOK Hook,
                     INT Code,
                     WPARAM wParam,
                     LPARAM lParam)
{
    NTSTATUS Status;
    PTHREADINFO pti;
    PHOOKPACK pHP;
    INT Size = 0;
    UINT uTimeout = 300;
    BOOL Block = FALSE;
    ULONG_PTR uResult = 0;

    if (Hook->ptiHooked)
       pti = Hook->ptiHooked;
    else
       pti = Hook->head.pti;

    pHP = ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOKPACK), TAG_HOOK);
    if (!pHP) return 0;

    pHP->pHk = Hook;
    UserReferenceObject(Hook);
    pHP->lParam = lParam;
    pHP->pHookStructs = NULL;

// This prevents stack corruption from the caller.
    switch(Hook->HookId)
    {
       case WH_JOURNALPLAYBACK:
       case WH_JOURNALRECORD:
          uTimeout = 0;
          Size = sizeof(EVENTMSG);
          break;
       case WH_KEYBOARD_LL:
          Size = sizeof(KBDLLHOOKSTRUCT);
          break;
       case WH_MOUSE_LL:
          Size = sizeof(MSLLHOOKSTRUCT);
          break;
       case WH_MOUSE:
          uTimeout = 200;
          Block = TRUE;
          Size = sizeof(MOUSEHOOKSTRUCTEX);
          break;
       case WH_KEYBOARD:
          uTimeout = 200;
          Block = TRUE;
          break;
    }

    if (Size)
    {
       pHP->pHookStructs = ExAllocatePoolWithTag(NonPagedPool, Size, TAG_HOOK);
       if (!pHP->pHookStructs)
       {
          IntFreeHookPack(pHP);
          return 0;
       }
       /* the buffer goes to user mode: padding included, nothing stale */
       RtlZeroMemory(pHP->pHookStructs, Size);
       RtlCopyMemory(pHP->pHookStructs, (PVOID)lParam, Size);
    }

    /* FIXME: Should get timeout from
     * HKEY_CURRENT_USER\Control Panel\Desktop\LowLevelHooksTimeout */
    Status = co_MsqSendMessage( pti,
                                IntToPtr(Code), // hWnd
                                Hook->HookId,   // Msg
                                wParam,
                               (LPARAM)pHP,
                                uTimeout,
                                Block,
                                MSQ_ISHOOK,
                               &uResult);
    if (!NT_SUCCESS(Status))
    {
       /* Failures come before the message is queued: the pack is still ours. Once queued
          (also on a timeout, STATUS_TIMEOUT is a success code) the message owns it. */
       ERR("Error Hook Call SendMsg. %d Status: 0x%x\n", Hook->HookId, Status);
       IntFreeHookPack(pHP);
    }
    return NT_SUCCESS(Status) ? uResult : 0;
}


//
// Dispatch MsgQueue Hook Call processor!
//
LRESULT
APIENTRY
co_CallHook( INT HookId,
             INT Code,
             WPARAM wParam,
             LPARAM lParam)
{
    LRESULT Result = 0;
    PHOOK phk;
    PHOOKPACK pHP = (PHOOKPACK)lParam;

    phk = pHP->pHk;
    lParam = pHP->lParam;

    switch(HookId)
    {
       case WH_JOURNALPLAYBACK:
       case WH_JOURNALRECORD:
       case WH_KEYBOARD_LL:
       case WH_MOUSE_LL:
       case WH_MOUSE:
          lParam = (LPARAM)pHP->pHookStructs;
       case WH_KEYBOARD:
          break;
    }

    if (!UserObjectInDestroy(UserHMGetHandle(phk))) //// Fix CORE-10549.
    {
    /* The odds are high for this to be a Global call. */
    Result = co_IntCallHookProc( HookId,
                                 Code,
                                 wParam,
                                 lParam,
                                 phk->Proc,
                                 phk->ihmod,
                                 phk->offPfn,
                                 phk->Ansi,
                                &phk->ModuleName);
    }
    /* The odds so high, no one is waiting for the results. */
    IntFreeHookPack(pHP);
    return Result;
}

BOOL
FASTCALL
co_HOOK_DebugBlocks(PTHREADINFO pti,
                    PDESKTOP pdo,
                    PHOOK Hook,
                    INT HookId,
                    INT Code,
                    WPARAM wParam,
                    LPARAM lParam);

/*
 * Calls the hook reached through CallNextHookEx. lParam is what the hook gets: a kernel copy of the record or a plain
 * value. The WH_DEBUG hooks see this call as they see the first one of a chain; if they block it *pBlocked is set
 * and the hook is not called, the caller goes on with the hook after it.
 */
static
LRESULT
APIENTRY
co_HOOK_CallHookNext( PHOOK Hook,
                      INT Code,
                      WPARAM wParam,
                      LPARAM lParam,
                      PBOOL pBlocked)
{
    TRACE("Calling Next HOOK %d\n", Hook->HookId);

    if (pBlocked)
    {
        PTHREADINFO pti = PsGetCurrentThreadWin32Thread();

        if (pti && pti->rpdesk && pti->rpdesk->pDeskInfo &&
            co_HOOK_DebugBlocks(pti, pti->rpdesk, Hook, Hook->HookId, Code, wParam, lParam))
        {
            *pBlocked = TRUE;
            return 0;
        }
    }

    return co_IntCallHookProc( Hook->HookId,
                               Code,
                               wParam,
                               lParam,
                               Hook->Proc,
                               Hook->ihmod,
                               Hook->offPfn,
                               Hook->Ansi,
                              &Hook->ModuleName);
}

static
LRESULT
FASTCALL
co_IntCallDebugHook(PHOOK Hook,
                  int Code,
                  WPARAM wParam,
                  LPARAM lParam,
                  BOOL Ansi)
{
    LRESULT lResult = 0;
    ULONG Size;
    DEBUGHOOKINFO Debug;
    PVOID HooklParam = NULL;
    BOOL BadChk = FALSE;

    if (lParam)
    {
        _SEH2_TRY
        {
            ProbeForRead((PVOID)lParam,
                         sizeof(DEBUGHOOKINFO),
                         1);

            RtlCopyMemory(&Debug,
                          (PVOID)lParam,
                          sizeof(DEBUGHOOKINFO));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            BadChk = TRUE;
        }
        _SEH2_END;

        if (BadChk)
        {
            ERR("HOOK WH_DEBUG read from lParam ERROR!\n");
            return lResult;
        }
    }
    else
        return lResult; /* Need lParam! */

    switch (wParam)
    {
        case WH_CBT:
        {
            switch (Debug.code)
            {
                case HCBT_CLICKSKIPPED:
                    Size = sizeof(MOUSEHOOKSTRUCTEX);
                    break;

                case HCBT_MOVESIZE:
                    Size = sizeof(RECT);
                    break;

                case HCBT_ACTIVATE:
                    Size = sizeof(CBTACTIVATESTRUCT);
                    break;

                case HCBT_CREATEWND: /* Handle ANSI? */
                    Size = sizeof(CBT_CREATEWND);
                    /* What shall we do? Size += sizeof(HOOKPROC_CBT_CREATEWND_EXTRA_ARGUMENTS); same as CREATESTRUCTEX */
                    break;

                default:
                    Size = sizeof(LPARAM);
            }
        }
        break;

        case WH_MOUSE:
            Size = sizeof(MOUSEHOOKSTRUCTEX);
            break;

        case WH_MOUSE_LL:
            Size = sizeof(MSLLHOOKSTRUCT);
            break;

        case WH_KEYBOARD_LL:
            Size = sizeof(KBDLLHOOKSTRUCT);
            break;

        case WH_MSGFILTER:
        case WH_SYSMSGFILTER:
        case WH_GETMESSAGE:
            Size = sizeof(MSG);
            break;

        case WH_JOURNALPLAYBACK:
        case WH_JOURNALRECORD:
            Size = sizeof(EVENTMSG);
            break;

        case WH_FOREGROUNDIDLE:
        case WH_KEYBOARD:
        case WH_SHELL:
        default:
            Size = sizeof(LPARAM);
    }

    if (Size > sizeof(LPARAM))
        HooklParam = ExAllocatePoolWithTag(NonPagedPool, Size, TAG_HOOK);

    if (HooklParam)
    {
        _SEH2_TRY
        {
            ProbeForRead((PVOID)Debug.lParam,
                         Size,
                         1);

            RtlCopyMemory(HooklParam,
                          (PVOID)Debug.lParam,
                          Size);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            BadChk = TRUE;
        }
        _SEH2_END;

        if (BadChk)
        {
            ERR("HOOK WH_DEBUG read from Debug.lParam ERROR!\n");
            ExFreePoolWithTag(HooklParam, TAG_HOOK);
            return lResult;
        }
    }

    if (HooklParam) Debug.lParam = (LPARAM)HooklParam;
    lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)&Debug, NULL);
    if (HooklParam) ExFreePoolWithTag(HooklParam, TAG_HOOK);

    return lResult;
}

static
LRESULT
APIENTRY
co_UserCallNextHookEx(PHOOK Hook,
                    int Code,
                    WPARAM wParam,
                    LPARAM lParam,
                    BOOL Ansi,
                    PBOOL pBlocked)
{
    LRESULT lResult = 0;
    BOOL BadChk = FALSE;

    /* Handle this one first. */
    if ((Hook->HookId == WH_MOUSE) ||
        (Hook->HookId == WH_CBT && Code == HCBT_CLICKSKIPPED))
    {
        MOUSEHOOKSTRUCTEX Mouse;

        RtlZeroMemory(&Mouse, sizeof(Mouse));
        if (lParam)
        {
            /* A hook procedure may pass the plain structure; mouseData stays zero then */
            _SEH2_TRY
            {
                ProbeForRead((PVOID)lParam,
                             sizeof(MOUSEHOOKSTRUCTEX),
                             1);

                RtlCopyMemory(&Mouse,
                              (PVOID)lParam,
                              sizeof(MOUSEHOOKSTRUCTEX));
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                _SEH2_TRY
                {
                    ProbeForRead((PVOID)lParam,
                                 sizeof(MOUSEHOOKSTRUCT),
                                 1);

                    RtlCopyMemory(&Mouse,
                                  (PVOID)lParam,
                                  sizeof(MOUSEHOOKSTRUCT));
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    BadChk = TRUE;
                }
                _SEH2_END;
            }
            _SEH2_END;

            if (BadChk)
            {
                ERR("HOOK WH_MOUSE read from lParam ERROR!\n");
            }
        }

        if (!BadChk)
        {
            lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)&Mouse, pBlocked);
        }

        return lResult;
    }

    switch(Hook->HookId)
    {
        case WH_MOUSE_LL:
        {
            MSLLHOOKSTRUCT Mouse;

            /* SECURITY (Astra #8): when lParam==0 this struct is passed to the
               hook procedure uninitialized -> kernel-stack info-leak. Zero it. */
            RtlZeroMemory(&Mouse, sizeof(Mouse));

            if (lParam)
            {
                _SEH2_TRY
                {
                    ProbeForRead((PVOID)lParam,
                                 sizeof(MSLLHOOKSTRUCT),
                                 1);

                    RtlCopyMemory(&Mouse,
                                  (PVOID)lParam,
                                  sizeof(MSLLHOOKSTRUCT));
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    BadChk = TRUE;
                }
                _SEH2_END;

                if (BadChk)
                {
                    ERR("HOOK WH_MOUSE_LL read from lParam ERROR!\n");
                }
            }

            if (!BadChk)
            {
                lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)&Mouse, pBlocked);
            }
            break;
        }

        case WH_KEYBOARD_LL:
        {
            KBDLLHOOKSTRUCT Keyboard;

            /* SECURITY (Astra #8): avoid kernel-stack info-leak when lParam==0. */
            RtlZeroMemory(&Keyboard, sizeof(Keyboard));

            if (lParam)
            {
                _SEH2_TRY
                {
                    ProbeForRead((PVOID)lParam,
                                 sizeof(KBDLLHOOKSTRUCT),
                                 1);

                    RtlCopyMemory(&Keyboard,
                                  (PVOID)lParam,
                                  sizeof(KBDLLHOOKSTRUCT));
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    BadChk = TRUE;
                }
                _SEH2_END;

                if (BadChk)
                {
                    ERR("HOOK WH_KEYBORD_LL read from lParam ERROR!\n");
                }
            }

            if (!BadChk)
            {
                lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)&Keyboard, pBlocked);
            }
            break;
        }

        case WH_MSGFILTER:
        case WH_SYSMSGFILTER:
        case WH_GETMESSAGE:
        {
            MSG Msg;

            /* SECURITY (Astra #8): avoid kernel-stack info-leak when lParam==0. */
            RtlZeroMemory(&Msg, sizeof(Msg));

            if (lParam)
            {
                _SEH2_TRY
                {
                    ProbeForRead((PVOID)lParam,
                                 sizeof(MSG),
                                 1);

                    RtlCopyMemory(&Msg,
                                  (PVOID)lParam,
                                  sizeof(MSG));
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    BadChk = TRUE;
                }
                _SEH2_END;

                if (BadChk)
                {
                    ERR("HOOK WH_XMESSAGEX read from lParam ERROR!\n");
                }
            }

            if (!BadChk)
            {
                lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)&Msg, pBlocked);

                /* SECURITY (ASTRA-hook-nexthook-uaf): this reads Hook after the
                 * user-mode callback, which may have unhooked it. Safe because
                 * the sole caller (NtUserCallNextHookEx) holds a co_ reference on
                 * Hook across this whole function. */
                if (lParam && (Hook->HookId == WH_GETMESSAGE))
                {
                    _SEH2_TRY
                    {
                        ProbeForWrite((PVOID)lParam,
                                      sizeof(MSG),
                                      1);

                        RtlCopyMemory((PVOID)lParam,
                                      &Msg,
                                      sizeof(MSG));
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        BadChk = TRUE;
                    }
                    _SEH2_END;

                    if (BadChk)
                    {
                        ERR("HOOK WH_GETMESSAGE write to lParam ERROR!\n");
                    }
                }
            }
            break;
        }

        case WH_CBT:
            TRACE("HOOK WH_CBT!\n");
            switch (Code)
            {
                case HCBT_CREATEWND:
                {
                    LPCBT_CREATEWNDW pcbtcww = (LPCBT_CREATEWNDW)lParam;

                    TRACE("HOOK HCBT_CREATEWND\n");
                    _SEH2_TRY
                    {
                        if (Ansi)
                        {
                            ProbeForRead( pcbtcww,
                                          sizeof(CBT_CREATEWNDA),
                                          1);
                            ProbeForWrite(pcbtcww->lpcs,
                                          sizeof(CREATESTRUCTA),
                                          1);
                            ProbeForRead( pcbtcww->lpcs->lpszName,
                                          sizeof(CHAR),
                                          1);

                            if (!IS_ATOM(pcbtcww->lpcs->lpszClass))
                            {
                                _Analysis_assume_(pcbtcww->lpcs->lpszClass != NULL);
                                ProbeForRead(pcbtcww->lpcs->lpszClass,
                                             sizeof(CHAR),
                                             1);
                            }
                        }
                        else
                        {
                            ProbeForRead( pcbtcww,
                                          sizeof(CBT_CREATEWNDW),
                                          1);
                            ProbeForWrite(pcbtcww->lpcs,
                                          sizeof(CREATESTRUCTW),
                                          1);
                            ProbeForRead( pcbtcww->lpcs->lpszName,
                                          sizeof(WCHAR),
                                          1);

                            if (!IS_ATOM(pcbtcww->lpcs->lpszClass))
                            {
                                _Analysis_assume_(pcbtcww->lpcs->lpszClass != NULL);
                                ProbeForRead(pcbtcww->lpcs->lpszClass,
                                             sizeof(WCHAR),
                                             1);
                            }
                        }
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        BadChk = TRUE;
                    }
                    _SEH2_END;

                    if (BadChk)
                    {
                        ERR("HOOK HCBT_CREATEWND write ERROR!\n");
                    }
                    /* The next call handles the structures. */
                    if (!BadChk && Hook->Proc)
                    {
                       lResult = co_HOOK_CallHookNext(Hook, Code, wParam, lParam, pBlocked);
                    }
                    break;
                }

                case HCBT_MOVESIZE:
                {
                    RECTL rt;

                    /* SECURITY (Astra #8): avoid kernel-stack info-leak when lParam==0. */
                    RtlZeroMemory(&rt, sizeof(rt));

                    TRACE("HOOK HCBT_MOVESIZE\n");

                    if (lParam)
                    {
                        _SEH2_TRY
                        {
                            ProbeForRead((PVOID)lParam,
                                         sizeof(RECT),
                                         1);

                            RtlCopyMemory(&rt,
                                          (PVOID)lParam,
                                          sizeof(RECT));
                        }
                        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                        {
                            BadChk = TRUE;
                        }
                        _SEH2_END;

                        if (BadChk)
                        {
                            ERR("HOOK HCBT_MOVESIZE read from lParam ERROR!\n");
                        }
                    }

                    if (!BadChk)
                    {
                        lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)&rt, pBlocked);
                    }
                    break;
                }

                case HCBT_ACTIVATE:
                {
                    CBTACTIVATESTRUCT CbAs;

                    /* SECURITY (Astra #8): avoid kernel-stack info-leak when lParam==0. */
                    RtlZeroMemory(&CbAs, sizeof(CbAs));

                    TRACE("HOOK HCBT_ACTIVATE\n");
                    if (lParam)
                    {
                        _SEH2_TRY
                        {
                            ProbeForRead((PVOID)lParam,
                                         sizeof(CBTACTIVATESTRUCT),
                                         1);

                            RtlCopyMemory(&CbAs,
                                          (PVOID)lParam,
                                          sizeof(CBTACTIVATESTRUCT));
                        }
                        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                        {
                            BadChk = TRUE;
                        }
                        _SEH2_END;

                        if (BadChk)
                        {
                            ERR("HOOK HCBT_ACTIVATE read from lParam ERROR!\n");
                        }
                    }

                    if (!BadChk)
                    {
                        lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)&CbAs, pBlocked);
                    }
                    break;
                }

                /* The rest just use default. */
                default:
                    TRACE("HOOK HCBT_ %d\n",Code);
                    lResult = co_HOOK_CallHookNext(Hook, Code, wParam, lParam, pBlocked);
                    break;
            }
            break;
/*
 Note WH_JOURNALPLAYBACK,
    "To have the system wait before processing the message, the return value
     must be the amount of time, in clock ticks, that the system should wait."
 */
        case WH_JOURNALPLAYBACK:
        case WH_JOURNALRECORD:
        {
            EVENTMSG EventMsg;

            if (lParam)
            {
                _SEH2_TRY
                {
                    ProbeForRead((PVOID)lParam,
                                 sizeof(EVENTMSG),
                                 1);

                    RtlCopyMemory(&EventMsg,
                                  (PVOID)lParam,
                                  sizeof(EVENTMSG));
                }
                _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                {
                    BadChk = TRUE;
                }
                _SEH2_END;

                if (BadChk)
                {
                    ERR("HOOK WH_JOURNAL read from lParam ERROR!\n");
                }
            }

            if (!BadChk)
            {
                lResult = co_HOOK_CallHookNext(Hook, Code, wParam, (LPARAM)(lParam ? &EventMsg : NULL), pBlocked);

                if (lParam)
                {
                    _SEH2_TRY
                    {
                        ProbeForWrite((PVOID)lParam,
                                      sizeof(EVENTMSG),
                                      1);

                        RtlCopyMemory((PVOID)lParam,
                                      &EventMsg,
                                      sizeof(EVENTMSG));
                    }
                    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
                    {
                        BadChk = TRUE;
                    }
                    _SEH2_END;

                    if (BadChk)
                    {
                        ERR("HOOK WH_JOURNAL write to lParam ERROR!\n");
                    }
                }
            }
            break;
        }

        case WH_DEBUG:
            lResult = co_IntCallDebugHook(Hook, Code, wParam, lParam, Ansi);
            break;

        /*
         * Default the rest like, WH_FOREGROUNDIDLE, WH_KEYBOARD and WH_SHELL.
         */
        case WH_FOREGROUNDIDLE:
        case WH_KEYBOARD:
        case WH_SHELL:
            lResult = co_HOOK_CallHookNext(Hook, Code, wParam, lParam, pBlocked);
            break;

        default:
            ERR("Unsupported HOOK Id -> %d\n",Hook->HookId);
            break;
    }
    return lResult;
}

PHOOK
FASTCALL
IntGetHookObject(HHOOK hHook)
{
    PHOOK Hook;

    if (!hHook)
    {
       EngSetLastError(ERROR_INVALID_HOOK_HANDLE);
       return NULL;
    }

    Hook = (PHOOK)UserGetObject(gHandleTable, hHook, TYPE_HOOK);
    if (!Hook)
    {
       EngSetLastError(ERROR_INVALID_HOOK_HANDLE);
       return NULL;
    }

    UserReferenceObject(Hook);

    return Hook;
}

static
HHOOK*
FASTCALL
IntGetGlobalHookHandles(PDESKTOP pdo, int HookId)
{
    PLIST_ENTRY pLastHead, pElem;
    unsigned i = 0;
    unsigned cHooks = 0;
    HHOOK *pList;
    PHOOK pHook;

    pLastHead = &pdo->pDeskInfo->aphkStart[HOOKID_TO_INDEX(HookId)];
    for (pElem = pLastHead->Flink; pElem != pLastHead; pElem = pElem->Flink)
      ++cHooks;

    pList = ExAllocatePoolWithTag(PagedPool, (cHooks + 1) * sizeof(HHOOK), TAG_HOOK);
    if (!pList)
    {
        EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    for (pElem = pLastHead->Flink; pElem != pLastHead; pElem = pElem->Flink)
    {
        pHook = CONTAINING_RECORD(pElem, HOOK, Chain);
        NT_ASSERT(i < cHooks);
        pList[i++] = UserHMGetHandle(pHook);
    }
    pList[i] = NULL;

    return pList;
}

/* Find the next hook in the chain  */
PHOOK
FASTCALL
IntGetNextHook(PHOOK Hook)
{
    int HookId = Hook->HookId;
    PLIST_ENTRY pLastHead, pElem;
    PTHREADINFO pti;

    if (Hook->ptiHooked)
    {
       pti = Hook->ptiHooked;
       pLastHead = &pti->aphkStart[HOOKID_TO_INDEX(HookId)];
    }
    else
    {
       pti = PsGetCurrentThreadWin32Thread();
       pLastHead = &pti->rpdesk->pDeskInfo->aphkStart[HOOKID_TO_INDEX(HookId)];
    }

    pElem = Hook->Chain.Flink;
    if (pElem != pLastHead)
    {
       PHOOK next = CONTAINING_RECORD(pElem, HOOK, Chain);
       /* SECURITY (ASTRA-hook-nexthook-uaf): never hand back a hook that is being
        * torn down. Removed hooks are unlinked from the live chain, so this
        * should not normally trigger, but it keeps the walk from ever returning
        * a hook whose storage is about to go away. */
       if (next->flags & HOOK_FLAG_REMOVED)
          return NULL;
       return next;
    }
    return NULL;
}

/* Pick the next hook to dispatch after Hook during a CallNextHookEx walk, safe
 * against Hook (or its immediate successor) having been unhooked mid-walk.
 *
 * SECURITY (ASTRA-hook-nexthook-uaf): Hook is the hook whose proc is driving the
 * walk; the dispatching frame holds a reference on Hook AND on its cached
 * successor, so both are guaranteed allocated here (even under a concurrent or
 * self unhook). If Hook is still linked we read the live chain. If Hook was
 * removed (self-unhook, cross-thread unhook, or a nested-dispatch restore) its
 * Chain links are stale, so we fall back to the successor snapshot captured in
 * phkNext when Hook was dispatched. We never follow a chain of removed hooks:
 * only the immediate successor is guaranteed referenced, so if it too was
 * removed we stop the walk rather than dereference an unreferenced (possibly
 * freed) pointer. */
PHOOK
FASTCALL
IntGetNextHookToCall(PHOOK Hook)
{
    PHOOK next;

    if (Hook->flags & HOOK_FLAG_REMOVED)
       next = Hook->phkNext;     /* Chain links are stale; use the snapshot. */
    else
       next = IntGetNextHook(Hook);

    if (next && (next->flags & HOOK_FLAG_REMOVED))
       next = NULL;

    return next;
}

/* Free a hook, removing it from its chain */
static
VOID
FASTCALL
IntFreeHook(PHOOK Hook)
{
    /* SECURITY (ASTRA-hook-nexthook-uaf): mark the hook removed BEFORE unlinking
     * it, so an in-progress CallNextHookEx walk (which may be keeping this hook
     * alive by a reference held across a user-mode callback, on this or another
     * thread) can detect it and fall back to the successor snapshot in phkNext
     * instead of following now-stale Chain links.
     *
     * We deliberately do NOT clear pti->sphkCurrent / ClientInfo->phkCurrent or
     * Hook->phkNext here: a hook proc that unhooks itself and then calls
     * CallNextHookEx must still run the rest of the chain (clearing sphkCurrent
     * would truncate it), and phkNext is the snapshot the walk falls back to. */
    Hook->flags |= HOOK_FLAG_REMOVED;

    RemoveEntryList(&Hook->Chain);
    if (Hook->ModuleName.Buffer)
    {
       ExFreePoolWithTag(Hook->ModuleName.Buffer, TAG_HOOK);
       Hook->ModuleName.Buffer = NULL;
    }
    /* Close handle */
    UserDeleteObject(UserHMGetHandle(Hook), TYPE_HOOK);
}

/* Remove a hook, freeing it from the chain */
BOOLEAN
IntRemoveHook(PVOID Object)
{
    INT HookId;
    PTHREADINFO ptiHook, pti;
    PDESKTOP pdo;
    PHOOK Hook = Object;

    NT_ASSERT(UserIsEnteredExclusive());

    HookId = Hook->HookId;
    pti = PsGetCurrentThreadWin32Thread();

    if (Hook->ptiHooked) // Local
    {
        ptiHook = Hook->ptiHooked;

        IntFreeHook(Hook);

        if (IsListEmpty(&ptiHook->aphkStart[HOOKID_TO_INDEX(HookId)]))
        {
            BOOL bOtherProcess;
            KAPC_STATE ApcState;

            ptiHook->fsHooks &= ~HOOKID_TO_FLAG(HookId);
            bOtherProcess = (ptiHook->ppi != pti->ppi);

            if (bOtherProcess)
                KeStackAttachProcess(&ptiHook->ppi->peProcess->Pcb, &ApcState);

            _SEH2_TRY
            {
                ptiHook->pClientInfo->fsHooks = ptiHook->fsHooks;
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
            {
                /* Do nothing */
                (void)0;
            }
            _SEH2_END;

            if (bOtherProcess)
                KeUnstackDetachProcess(&ApcState);
       }
    }
    else // Global
    {
        /* A global hook is in the list of the desktop it was set on (SetWindowsHookEx
           links it into ptiHook->rpdesk), not necessarily the input desktop */
        pdo = Hook->rpdesk;

        IntFreeHook(Hook);

        if (pdo &&
             pdo->pDeskInfo &&
             IsListEmpty(&pdo->pDeskInfo->aphkStart[HOOKID_TO_INDEX(HookId)]))
        {
            pdo->pDeskInfo->fsHooks &= ~HOOKID_TO_FLAG(HookId);
        }
    }

    return TRUE;
}

/*
 * The WH_DEBUG hooks run before every other hook: wParam is the id of the hook that is about to run and lParam
 * points to a DEBUGHOOKINFO with the code, wParam and lParam it gets. A nonzero result keeps that hook from running.
 * Windows does not call them for the low-level and journal hooks, nor for themselves. The record lParam points to
 * (and the plain lParams) is marshaled by co_IntCallHookProc.
 */
BOOL
FASTCALL
co_HOOK_DebugBlocks(PTHREADINFO pti,
                    PDESKTOP pdo,
                    PHOOK Hook,
                    INT HookId,
                    INT Code,
                    WPARAM wParam,
                    LPARAM lParam)
{
    DEBUGHOOKINFO Debug;
    PTHREADINFO ptiHook;

    switch (HookId)
    {
        case WH_DEBUG:
        case WH_KEYBOARD_LL:
        case WH_MOUSE_LL:
        case WH_JOURNALRECORD:
        case WH_JOURNALPLAYBACK:
            return FALSE;
    }

    if (!(pti->fsHooks & HOOKID_TO_FLAG(WH_DEBUG)) &&
        !(pdo->pDeskInfo->fsHooks & HOOKID_TO_FLAG(WH_DEBUG)))
        return FALSE;

    /* A debug hook procedure that causes hooks of its own is not debugged again */
    if (pti->sphkCurrent && pti->sphkCurrent->HookId == WH_DEBUG)
        return FALSE;

    ptiHook = Hook->ptiHooked ? Hook->ptiHooked : Hook->head.pti;
    if (!ptiHook || !ptiHook->pEThread)
        ptiHook = pti;

    RtlZeroMemory(&Debug, sizeof(Debug));
    Debug.idThread = PtrToUint(ptiHook->pEThread->Cid.UniqueThread);
    Debug.idThreadInstaller = 0; /* as Windows, for the hooks of a thread */
    Debug.lParam = lParam;
    Debug.wParam = wParam;
    Debug.code = Code;

    return co_HOOK_CallHooks(WH_DEBUG, HC_ACTION, (WPARAM)(INT_PTR)HookId, (LPARAM)&Debug) != 0;
}

/*
  Win32k Kernel Space Hook Caller.
 */
LRESULT
APIENTRY
co_HOOK_CallHooks( INT HookId,
                   INT Code,
                   WPARAM wParam,
                   LPARAM lParam)
{
    PHOOK Hook, SaveHook, NextHook = NULL;
    PTHREADINFO pti;
    PCLIENTINFO ClientInfo;
    PLIST_ENTRY pLastHead;
    PDESKTOP pdo;
    BOOL Local = FALSE, Global = FALSE;
    LRESULT Result = 0;
    USER_REFERENCE_ENTRY Ref, RefNext;

    ASSERT(WH_MINHOOK <= HookId && HookId <= WH_MAXHOOK);

    pti = PsGetCurrentThreadWin32Thread();
    if (!pti || !pti->rpdesk || !pti->rpdesk->pDeskInfo)
    {
       pdo = IntGetActiveDesktop();
    /* If KeyboardThread|MouseThread|(RawInputThread or RIT) aka system threads,
       pti->fsHooks most likely, is zero. So process KbT & MsT to "send" the message.
     */
       if ( !pti || !pdo || (!(HookId == WH_KEYBOARD_LL) && !(HookId == WH_MOUSE_LL)) )
       {
          TRACE("No PDO %d\n", HookId);
          goto Exit;
       }
    }
    else
    {
       pdo = pti->rpdesk;
    }

    if ( pti->TIF_flags & (TIF_INCLEANUP|TIF_DISABLEHOOKS))
    {
       TRACE("Hook Thread dead %d\n", HookId);
       goto Exit;
    }

    if ( ISITHOOKED(HookId) )
    {
       TRACE("Local Hooker %d\n", HookId);
       Local = TRUE;
    }

    if ( pdo->pDeskInfo->fsHooks & HOOKID_TO_FLAG(HookId) )
    {
       TRACE("Global Hooker %d\n", HookId);
       Global = TRUE;
    }

    if ( !Local && !Global ) goto Exit; // No work!

    Hook = NULL;

    /* SetWindowHookEx sorts out the Thread issue by placing the Hook to
       the correct Thread if not NULL.
     */
    if ( Local )
    {
       PHOOK NextToTry;

       pLastHead = &pti->aphkStart[HOOKID_TO_INDEX(HookId)];
       if (IsListEmpty(pLastHead))
       {
          ERR("No Local Hook Found!\n");
          goto Exit;
       }

       Hook = CONTAINING_RECORD(pLastHead->Flink, HOOK, Chain);
       ObReferenceObject(pti->pEThread);
       IntReferenceThreadInfo(pti);

       ClientInfo = pti->pClientInfo;
       SaveHook = pti->sphkCurrent;

       for (;;)
       {
          BOOL Blocked = FALSE;
          PHOOK SavePhkNext;

          UserRefObjectCo(Hook, &Ref);
          /* The same hook can be running further out (its proc caused this call): its
             successor snapshot is theirs, put it back when this call is done */
          SavePhkNext = Hook->phkNext;

          /* Note: Setting pti->sphkCurrent will also lock the next hook to this
           *       hook ID. So, the CallNextHookEx will only call to that hook ID
           *       chain anyway. For Thread Hooks....
           */

          /* Load it for the next call. */
          pti->sphkCurrent = Hook;
          Hook->phkNext = IntGetNextHook(Hook);
          /* SECURITY (ASTRA-hook-nexthook-uaf): keep both this hook and its cached
           * successor alive across the user-mode callback. The hook proc may call
           * CallNextHookEx (which reads sphkCurrent and its phkNext snapshot) and
           * may unhook this hook or the next one; the references guarantee neither
           * pointer is dangling when the walk inspects it. */
          NextHook = Hook->phkNext;
          if (NextHook)
             UserRefObjectCo(NextHook, &RefNext);
          if (ClientInfo)
          {
             _SEH2_TRY
             {
                ClientInfo->phkCurrent = Hook;
             }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
             {
                ClientInfo = NULL; // Don't bother next run.
             }
             _SEH2_END;
          }
          if (co_HOOK_DebugBlocks(pti, pdo, Hook, HookId, Code, wParam, lParam))
          {
             /* A debug hook keeps this hook from running: the next hook of the chain is tried, and debugged */
             Blocked = TRUE;
             Result = 0;
          }
          else
             Result = co_IntCallHookProc( HookId,
                                          Code,
                                          wParam,
                                          lParam,
                                          Hook->Proc,
                                          Hook->ihmod,
                                          Hook->offPfn,
                                          Hook->Ansi,
                                         &Hook->ModuleName);
          if (ClientInfo)
          {
             _SEH2_TRY
             {
                ClientInfo->phkCurrent = SaveHook;
             }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
             {
                 /* Do nothing */
                 (void)0;
             }
             _SEH2_END;
          }
          pti->sphkCurrent = SaveHook;
          /* The user lock is held from here to the next hook: the releases below cannot free NextToTry */
          NextToTry = Blocked ? IntGetNextHookToCall(Hook) : NULL;
          Hook->phkNext = SavePhkNext;
          /* Release in reverse order of acquisition (UserDerefObjectCo is LIFO). */
          if (NextHook)
             UserDerefObjectCo(NextHook);
          UserDerefObjectCo(Hook);

          if (!Blocked || !NextToTry)
             break;
          Hook = NextToTry;
       }

       IntDereferenceThreadInfo(pti);
       ObDereferenceObject(pti->pEThread);
    }

    if ( Global )
    {
       PTHREADINFO ptiHook;
       HHOOK *pHookHandles;
       unsigned i;

       /* Keep hooks in array because hooks can be destroyed in user world */
       pHookHandles = IntGetGlobalHookHandles(pdo, HookId);
       if(!pHookHandles)
          goto Exit;

      /* Performance goes down the drain. If more hooks are associated to this
       * hook ID, this will have to post to each of the thread message queues
       * or make a direct call.
       */
       for(i = 0; pHookHandles[i]; ++i)
       {
          Hook = (PHOOK)UserGetObject(gHandleTable, pHookHandles[i], TYPE_HOOK);
          if(!Hook)
          {
              ERR("Invalid hook!\n");
              continue;
          }

         /* Hook->Thread is null, we hax around this with Hook->head.pti. */
          ptiHook = Hook->head.pti;

          if ( (pti->TIF_flags & TIF_DISABLEHOOKS) || (ptiHook->TIF_flags & TIF_INCLEANUP))
          {
             TRACE("Next Hook %p, %p\n", ptiHook->rpdesk, pdo);
             continue;
          }
          UserRefObjectCo(Hook, &Ref);

          if (ptiHook != pti )
          {
                                                  // Block | TimeOut
             if ( HookId == WH_JOURNALPLAYBACK || //   1   |    0
                  HookId == WH_JOURNALRECORD   || //   1   |    0
                  HookId == WH_KEYBOARD        || //   1   |   200
                  HookId == WH_MOUSE           || //   1   |   200
                  HookId == WH_KEYBOARD_LL     || //   0   |   300
                  HookId == WH_MOUSE_LL )         //   0   |   300
             {
                TRACE("\nGlobal Hook posting to another Thread! %d\n",HookId );
                if (co_HOOK_DebugBlocks(pti, pdo, Hook, HookId, Code, wParam, lParam))
                   Result = 0;
                else
                   Result = co_IntCallLowLevelHook(Hook, Code, wParam, lParam);
             }
             else if (ptiHook->ppi == pti->ppi)
             {
                TRACE("\nGlobal Hook calling to another Thread! %d\n",HookId );
                ObReferenceObject(ptiHook->pEThread);
                IntReferenceThreadInfo(ptiHook);
                if (co_HOOK_DebugBlocks(pti, pdo, Hook, HookId, Code, wParam, lParam))
                   Result = 0;
                else
                   Result = co_IntCallHookProc( HookId,
                                                Code,
                                                wParam,
                                                lParam,
                                                Hook->Proc,
                                                Hook->ihmod,
                                                Hook->offPfn,
                                                Hook->Ansi,
                                               &Hook->ModuleName);
                IntDereferenceThreadInfo(ptiHook);
                ObDereferenceObject(ptiHook->pEThread);
             }
          }
          else
          { /* Make the direct call. */
             TRACE("Global going Local Hook calling to Thread! %d\n",HookId );
             ObReferenceObject(pti->pEThread);
             IntReferenceThreadInfo(pti);
             if (co_HOOK_DebugBlocks(pti, pdo, Hook, HookId, Code, wParam, lParam))
                Result = 0;
             else
                Result = co_IntCallHookProc( HookId,
                                             Code,
                                             wParam,
                                             lParam,
                                             Hook->Proc,
                                             Hook->ihmod,
                                             Hook->offPfn,
                                             Hook->Ansi,
                                            &Hook->ModuleName);
             IntDereferenceThreadInfo(pti);
             ObDereferenceObject(pti->pEThread);
          }
          UserDerefObjectCo(Hook);
       }
       ExFreePoolWithTag(pHookHandles, TAG_HOOK);
       TRACE("Ret: Global HookId %d Result 0x%x\n", HookId,Result);
    }
Exit:
    return Result;
}

BOOL
FASTCALL
IntUnhookWindowsHook(int HookId, HOOKPROC pfnFilterProc)
{
    PHOOK Hook;
    PLIST_ENTRY pLastHead, pElement;
    PTHREADINFO pti = PsGetCurrentThreadWin32Thread();

    if (HookId < WH_MINHOOK || WH_MAXHOOK < HookId )
    {
       EngSetLastError(ERROR_INVALID_HOOK_FILTER);
       return FALSE;
    }

    if (pti->fsHooks)
    {
       pLastHead = &pti->aphkStart[HOOKID_TO_INDEX(HookId)];

       pElement = pLastHead->Flink;
       while (pElement != pLastHead)
       {
          Hook = CONTAINING_RECORD(pElement, HOOK, Chain);

          /* Get the next element now, we might free the hook in what follows */
          pElement = Hook->Chain.Flink;

          if (Hook->Proc == pfnFilterProc)
          {
             if (Hook->head.pti == pti)
             {
                IntRemoveHook(Hook);
                return TRUE;
             }
             else
             {
                EngSetLastError(ERROR_ACCESS_DENIED);
                return FALSE;
             }
          }
       }
    }
    return FALSE;
}

/*
 *  Support for compatibility only? Global hooks are processed in kernel space.
 *  This is very thread specific! Never seeing applications with more than one
 *  hook per thread installed. Most of the applications are Global hookers and
 *  associated with just one hook Id. Maybe it's for diagnostic testing or a
 *  throw back to 3.11?
 */
LRESULT
APIENTRY
NtUserCallNextHookEx( int Code,
                      WPARAM wParam,
                      LPARAM lParam,
                      BOOL Ansi)
{
    PTHREADINFO pti;
    PHOOK HookObj, NextObj, SaveHook, NextNext;
    PCLIENTINFO ClientInfo;
    LRESULT lResult = 0;

    TRACE("Enter NtUserCallNextHookEx\n");
    UserEnterExclusive();

    pti = GetW32ThreadInfo();

    HookObj = pti->sphkCurrent;

    if (!HookObj)
       goto Exit; // Return 0

    /* SECURITY (ASTRA-hook-nexthook-uaf): HookObj is the hook whose proc is
     * calling us. The dispatching frame (co_HOOK_CallHooks for the first hook,
     * or an outer NtUserCallNextHookEx for a later one) holds a reference on
     * HookObj and on its cached successor, so both are guaranteed allocated here
     * even if HookObj (or its successor) was just unhooked -- by this proc or by
     * another thread while the user lock was dropped for the callback.
     *
     * Derive the successor with IntGetNextHookToCall(): the live chain when
     * HookObj is still linked, else the phkNext snapshot captured when HookObj
     * was dispatched. We do NOT return 0 just because HookObj was unhooked: a
     * hook that unhooks itself and then calls CallNextHookEx must still run the
     * rest of the chain, matching Windows/base behaviour. */
    NextObj = IntGetNextHookToCall(HookObj);

    SaveHook = pti->sphkCurrent;
    pti->sphkCurrent = NextObj;
    ClientInfo = pti->pClientInfo;
    _SEH2_TRY
    {
       ClientInfo->phkCurrent = NextObj;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
       ClientInfo = NULL;
    }
    _SEH2_END;

    /* Now in List run down. A hook the debug hooks block is skipped: the one after it is tried, and debugged */
    while (ClientInfo && NextObj)
    {
       USER_REFERENCE_ENTRY Ref, RefNext;
       BOOL Blocked = FALSE;
       PHOOK Following, SavePhkNext;

       /* Snapshot the hook after NextObj, and keep BOTH NextObj and that
        * successor alive across the user-mode callback. co_UserCallNextHookEx
        * dereferences NextObj after the callback (e.g. Hook->HookId on the
        * WH_GETMESSAGE path), and a nested CallNextHookEx will fall back to this
        * snapshot if NextObj unhooks itself -- neither pointer may dangle. */
       SavePhkNext = NextObj->phkNext;
       NextObj->phkNext = IntGetNextHook(NextObj);
       NextNext = NextObj->phkNext;
       UserRefObjectCo(NextObj, &Ref);
       if (NextNext)
          UserRefObjectCo(NextNext, &RefNext);

       lResult = co_UserCallNextHookEx( NextObj, Code, wParam, lParam, NextObj->Ansi, &Blocked);

       /* Under the user lock until the references are released: Following cannot be freed meanwhile */
       Following = Blocked ? IntGetNextHookToCall(NextObj) : NULL;

       /* The snapshot is only good while NextNext is referenced: leave what was there before
          (a snapshot of an outer dispatch of this hook, which holds its own reference), not a
          pointer that is about to be released */
       NextObj->phkNext = SavePhkNext;

       /* Release in reverse order of acquisition (UserDerefObjectCo is LIFO). */
       if (NextNext)
          UserDerefObjectCo(NextNext);
       UserDerefObjectCo(NextObj);

       if (!Blocked)
          break;

       lResult = 0;
       NextObj = Following;
       if (NextObj)
       {
          pti->sphkCurrent = NextObj;
          _SEH2_TRY
          {
             ClientInfo->phkCurrent = NextObj;
          }
          _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
          {
             ClientInfo = NULL;
          }
          _SEH2_END;
       }
    }

    /* SECURITY (ASTRA-hook-nexthook-uaf): restore sphkCurrent / phkCurrent so
     * that, after this hop returns, they again name this proc's (still
     * referenced) hook rather than a deeper hook that is about to be
     * dereferenced and freed. Without this a second CallNextHookEx from the same
     * proc would read a dangling sphkCurrent. */
    pti->sphkCurrent = SaveHook;
    _SEH2_TRY
    {
       if (pti->pClientInfo)
          pti->pClientInfo->phkCurrent = SaveHook;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
       /* Do nothing */
       (void)0;
    }
    _SEH2_END;

Exit:
    TRACE("Leave NtUserCallNextHookEx, ret=%i\n", lResult);
    UserLeave();
    return lResult;
}

HHOOK
APIENTRY
NtUserSetWindowsHookAW( int idHook,
                        HOOKPROC lpfn,
                        BOOL Ansi)
{
    DWORD ThreadId;
    UNICODE_STRING USModuleName;

    RtlInitUnicodeString(&USModuleName, NULL);
    ThreadId = PtrToUint(NtCurrentTeb()->ClientId.UniqueThread);

    return NtUserSetWindowsHookEx( NULL,
                                  &USModuleName,
                                   ThreadId,
                                   idHook,
                                   lpfn,
                                   Ansi);
}

HHOOK
APIENTRY
NtUserSetWindowsHookEx( HINSTANCE Mod,
                        PUNICODE_STRING UnsafeModuleName,
                        DWORD ThreadId,
                        int HookId,
                        HOOKPROC HookProc,
                        BOOL Ansi)
{
    PWINSTATION_OBJECT WinStaObj;
    PHOOK Hook = NULL;
    UNICODE_STRING ModuleName;
    NTSTATUS Status;
    HHOOK Handle;
    PTHREADINFO pti, ptiHook = NULL;
    HHOOK Ret = NULL;

    TRACE("Enter NtUserSetWindowsHookEx\n");
    UserEnterExclusive();

    pti = PsGetCurrentThreadWin32Thread();

    if (HookId < WH_MINHOOK || WH_MAXHOOK < HookId )
    {
        EngSetLastError(ERROR_INVALID_HOOK_FILTER);
        goto Cleanup; // Return NULL
    }

    if (!HookProc)
    {
        EngSetLastError(ERROR_INVALID_FILTER_PROC);
        goto Cleanup; // Return NULL
    }

    if (ThreadId)  /* thread-local hook */
    {
       if ( HookId == WH_JOURNALRECORD ||
            HookId == WH_JOURNALPLAYBACK ||
            HookId == WH_KEYBOARD_LL ||
            HookId == WH_MOUSE_LL ||
            HookId == WH_SYSMSGFILTER)
       {
           TRACE("Local hook installing Global HookId: %d\n",HookId);
           /* these can only be global */
           EngSetLastError(ERROR_GLOBAL_ONLY_HOOK);
           goto Cleanup; // Return NULL
       }

       if ( !(ptiHook = IntTID2PTI( UlongToHandle(ThreadId) )))
       {
          ERR("Invalid thread id 0x%x\n", ThreadId);
          EngSetLastError(ERROR_INVALID_PARAMETER);
          goto Cleanup; // Return NULL
       }

       if ( ptiHook->rpdesk != pti->rpdesk) // gptiCurrent->rpdesk)
       {
          ERR("Local hook wrong desktop HookId: %d\n",HookId);
          EngSetLastError(ERROR_ACCESS_DENIED);
          goto Cleanup; // Return NULL
       }

       if (ptiHook->ppi != pti->ppi)
       {
          if ( !Mod &&
              (HookId == WH_GETMESSAGE ||
               HookId == WH_CALLWNDPROC ||
               HookId == WH_CBT ||
               HookId == WH_HARDWARE ||
               HookId == WH_DEBUG ||
               HookId == WH_SHELL ||
               HookId == WH_FOREGROUNDIDLE ||
               HookId == WH_CALLWNDPROCRET) )
          {
             ERR("Local hook needs hMod HookId: %d\n",HookId);
             EngSetLastError(ERROR_HOOK_NEEDS_HMOD);
             goto Cleanup; // Return NULL
          }

          if ( (ptiHook->TIF_flags & (TIF_CSRSSTHREAD|TIF_SYSTEMTHREAD)) &&
               (HookId == WH_GETMESSAGE ||
                HookId == WH_CALLWNDPROC ||
                HookId == WH_CBT ||
                HookId == WH_HARDWARE ||
                HookId == WH_DEBUG ||
                HookId == WH_SHELL ||
                HookId == WH_FOREGROUNDIDLE ||
                HookId == WH_CALLWNDPROCRET) )
          {
             EngSetLastError(ERROR_HOOK_TYPE_NOT_ALLOWED);
             goto Cleanup; // Return NULL
          }
       }
    }
    else  /* System-global hook */
    {
       ptiHook = pti; // gptiCurrent;
       /* The hook is linked into the chains of the thread's desktop: without one there is nothing to link it to */
       if (!ptiHook->rpdesk || !ptiHook->rpdesk->pDeskInfo)
       {
          ERR("Global hook without a desktop HookId: %d\n",HookId);
          EngSetLastError(ERROR_ACCESS_DENIED);
          goto Cleanup; // Return NULL
       }
       if ( !Mod &&
            (HookId == WH_GETMESSAGE ||
             HookId == WH_CALLWNDPROC ||
             HookId == WH_CBT ||
             HookId == WH_SYSMSGFILTER ||
             HookId == WH_HARDWARE ||
             HookId == WH_DEBUG ||
             HookId == WH_SHELL ||
             HookId == WH_FOREGROUNDIDLE ||
             HookId == WH_CALLWNDPROCRET) )
       {
          ERR("Global hook needs hMod HookId: %d\n",HookId);
          EngSetLastError(ERROR_HOOK_NEEDS_HMOD);
          goto Cleanup; // Return NULL
       }
    }

    Status = IntValidateWindowStationHandle( PsGetCurrentProcess()->Win32WindowStation,
                                             UserMode,
                                             0,
                                            &WinStaObj,
                                             0);

    if (!NT_SUCCESS(Status))
    {
       SetLastNtError(Status);
       goto Cleanup; // Return NULL
    }
    ObDereferenceObject(WinStaObj);

    /* The desktop handle of the calling thread has to grant DESKTOP_HOOKCONTROL for any hook:
       Windows 10 answers ERROR_ACCESS_DENIED without it, for thread hooks too (measured) */
    if (pti->hdesk)
    {
       PDESKTOP pdeskCheck;

       Status = IntValidateDesktopHandle(pti->hdesk, UserMode, DESKTOP_HOOKCONTROL, &pdeskCheck);
       if (!NT_SUCCESS(Status))
       {
          /* the last error is set */
          goto Cleanup; // Return NULL
       }
       ObDereferenceObject(pdeskCheck);
    }

    Hook = UserCreateObject(gHandleTable, NULL, ptiHook, (PHANDLE)&Handle, TYPE_HOOK, sizeof(HOOK));

    if (!Hook)
    {
       goto Cleanup; // Return NULL
    }

    Hook->ihmod   = (INT_PTR)Mod; // Module Index from atom table, Do this for now.
    Hook->HookId  = HookId;
    Hook->rpdesk  = ptiHook->rpdesk;
    Hook->phkNext = NULL; /* Dont use as a chain! Use link lists for chaining. */
    Hook->Proc    = HookProc;
    Hook->Ansi    = Ansi;

    TRACE("Set Hook Desk %p DeskInfo %p Handle Desk %p\n", pti->rpdesk, pti->pDeskInfo, Hook->head.rpdesk);

    if (ThreadId)  /* Thread-local hook */
    {
       InsertHeadList(&ptiHook->aphkStart[HOOKID_TO_INDEX(HookId)], &Hook->Chain);
       ptiHook->sphkCurrent = NULL;
       Hook->ptiHooked = ptiHook;
       ptiHook->fsHooks |= HOOKID_TO_FLAG(HookId);

       if (ptiHook->pClientInfo)
       {
          if ( ptiHook->ppi == pti->ppi) /* gptiCurrent->ppi) */
          {
             _SEH2_TRY
             {
                ptiHook->pClientInfo->fsHooks = ptiHook->fsHooks;
                ptiHook->pClientInfo->phkCurrent = NULL;
             }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
             {
                ERR("Problem writing to Local ClientInfo!\n");
             }
             _SEH2_END;
          }
          else
          {
             KAPC_STATE ApcState;

             KeStackAttachProcess(&ptiHook->ppi->peProcess->Pcb, &ApcState);
             _SEH2_TRY
             {
                ptiHook->pClientInfo->fsHooks = ptiHook->fsHooks;
                ptiHook->pClientInfo->phkCurrent = NULL;
             }
             _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
             {
                ERR("Problem writing to Remote ClientInfo!\n");
             }
             _SEH2_END;
             KeUnstackDetachProcess(&ApcState);
          }
       }
    }
    else
    {
       InsertHeadList(&ptiHook->rpdesk->pDeskInfo->aphkStart[HOOKID_TO_INDEX(HookId)], &Hook->Chain);
       Hook->ptiHooked = NULL;
       //gptiCurrent->pDeskInfo->fsHooks |= HOOKID_TO_FLAG(HookId);
       ptiHook->rpdesk->pDeskInfo->fsHooks |= HOOKID_TO_FLAG(HookId);
       ptiHook->sphkCurrent = NULL;
       /* The client info is user memory (the TEB): it may be absent, and writing it may fault */
       if (ptiHook->pClientInfo)
       {
          _SEH2_TRY
          {
             ptiHook->pClientInfo->phkCurrent = NULL;
          }
          _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
          {
             ERR("Problem writing to ClientInfo!\n");
          }
          _SEH2_END;
       }
    }

    RtlInitUnicodeString(&Hook->ModuleName, NULL);

    if (Mod)
    {
       Status = MmCopyFromCaller(&ModuleName,
                                  UnsafeModuleName,
                                  sizeof(UNICODE_STRING));
       if (!NT_SUCCESS(Status))
       {
          IntRemoveHook(Hook);
          SetLastNtError(Status);
          goto Cleanup; // Return NULL
       }

       /* The captured counted string is fully caller-controlled. We allocate
        * and copy exactly MaximumLength bytes below, so a Length greater than
        * MaximumLength would make Hook->ModuleName.Length exceed its backing
        * buffer and cause later counted-string uses to over-read kernel pool
        * (up to ~64KB). Reject such a descriptor. */
       if (ModuleName.Length > ModuleName.MaximumLength)
       {
          IntRemoveHook(Hook);
          EngSetLastError(ERROR_INVALID_PARAMETER);
          goto Cleanup; // Return NULL
       }

       /* The module name is later copied into the fixed-size ModuleName[]
        * array of HOOKPROC_CALLBACK_ARGUMENTS (see co_IntCallHookProc).
        * Reject names that do not fit there together with a terminating
        * NUL, otherwise that copy overflows the callback allocation. */
       if (ModuleName.Length > sizeof(((PHOOKPROC_CALLBACK_ARGUMENTS)0)->ModuleName) - sizeof(WCHAR))
       {
          IntRemoveHook(Hook);
          EngSetLastError(ERROR_INVALID_PARAMETER);
          goto Cleanup; // Return NULL
       }

       Hook->ModuleName.Buffer = ExAllocatePoolWithTag( PagedPool,
                                                        ModuleName.MaximumLength,
                                                        TAG_HOOK);
       if (NULL == Hook->ModuleName.Buffer)
       {
          IntRemoveHook(Hook);
          EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
          goto Cleanup; // Return NULL
       }

       Hook->ModuleName.MaximumLength = ModuleName.MaximumLength;
       Status = MmCopyFromCaller( Hook->ModuleName.Buffer,
                                  ModuleName.Buffer,
                                  ModuleName.MaximumLength);
       if (!NT_SUCCESS(Status))
       {
          ExFreePoolWithTag(Hook->ModuleName.Buffer, TAG_HOOK);
          Hook->ModuleName.Buffer = NULL;
          IntRemoveHook(Hook);
          SetLastNtError(Status);
          goto Cleanup; // Return NULL
       }

       Hook->ModuleName.Length = ModuleName.Length;
       //// FIXME: Need to load from user32 to verify hMod before calling hook with hMod set!!!!
       //// Mod + offPfn == new HookProc Justin Case module is from another process.
       FIXME("NtUserSetWindowsHookEx Setting process hMod instance addressing.\n");
       /* Make proc relative to the module base */
       Hook->offPfn = (ULONG_PTR)((char *)HookProc - (char *)Mod);
    }
    else
       Hook->offPfn = 0;

    TRACE("Installing: HookId %d Global %s\n", HookId, !ThreadId ? "TRUE" : "FALSE");
    Ret = Handle;

Cleanup:
    if (Hook)
        UserDereferenceObject(Hook);
    TRACE("Leave NtUserSetWindowsHookEx, ret=%p\n", Ret);
    UserLeave();
    return Ret;
}

BOOL
APIENTRY
NtUserUnhookWindowsHookEx(HHOOK Hook)
{
    PHOOK HookObj;
    BOOL Ret = FALSE;

    TRACE("Enter NtUserUnhookWindowsHookEx\n");
    UserEnterExclusive();

    if (!(HookObj = IntGetHookObject(Hook)))
    {
        ERR("Invalid handle passed to NtUserUnhookWindowsHookEx\n");
        /* SetLastNtError(Status); */
        goto Exit; // Return FALSE
    }

    ASSERT(Hook == UserHMGetHandle(HookObj));

    IntRemoveHook(HookObj);

    UserDereferenceObject(HookObj);

    Ret = TRUE;

Exit:
    TRACE("Leave NtUserUnhookWindowsHookEx, ret=%i\n", Ret);
    UserLeave();
    return Ret;
}

BOOL
APIENTRY
NtUserRegisterUserApiHook(
    PUNICODE_STRING m_dllname1,
    PUNICODE_STRING m_funname1,
    DWORD dwUnknown3,
    DWORD dwUnknown4)
{
    BOOL ret;
    UNICODE_STRING strDllNameSafe;
    UNICODE_STRING strFuncNameSafe;
    NTSTATUS Status;

    /* SECURITY (Astra #8): registering a user-api hook makes win32k inject the
       named module (MSQ_INJECTMODULE) into every non-system, non-CSRSS process
       on the current desktop. That is a privileged, desktop-wide operation; on
       Windows it is driven by the trusted theme/console server, never by an
       ordinary process. With no gate, any caller could force a DLL into other
       processes -> cross-process code injection / EoP. Require SeTcbPrivilege,
       which the LocalSystem theme service (the legitimate caller) holds and
       unprivileged user processes do not. */
    if (!SeSinglePrivilegeCheck(RtlConvertLongToLuid(SE_TCB_PRIVILEGE), UserMode))
    {
        ERR("NtUserRegisterUserApiHook: caller lacks SeTcbPrivilege, denying\n");
        EngSetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    /* Probe and capture parameters */
    Status = ProbeAndCaptureUnicodeString(&strDllNameSafe, UserMode, m_dllname1);
    if(!NT_SUCCESS(Status))
    {
        EngSetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    Status = ProbeAndCaptureUnicodeString(&strFuncNameSafe, UserMode, m_funname1);
    if(!NT_SUCCESS(Status))
    {
        ReleaseCapturedUnicodeString(&strDllNameSafe, UserMode);
        EngSetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    UserEnterExclusive();

    /* Call internal function */
    ret = UserRegisterUserApiHook(&strDllNameSafe, &strFuncNameSafe);

    UserLeave();

    /* Cleanup only in case of failure */
    if(ret == FALSE)
    {
        ReleaseCapturedUnicodeString(&strDllNameSafe, UserMode);
        ReleaseCapturedUnicodeString(&strFuncNameSafe, UserMode);
    }

    return ret;
}

BOOL
APIENTRY
NtUserUnregisterUserApiHook(VOID)
{
    BOOL ret;

    UserEnterExclusive();
    ret = UserUnregisterUserApiHook();
    UserLeave();

    return ret;
}

/* EOF */
