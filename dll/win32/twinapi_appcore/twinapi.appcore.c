/*
 * PROJECT:     ReactOS twinapi.appcore
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     App state change notifications (appnotify.h) for desktop processes
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * RegisterAppStateChangeNotification takes a routine that Windows calls when the process
 * is suspended or resumed (the Process Lifetime Manager of packaged apps). A desktop process
 * is never suspended, so the routine is never called here either. Measured on Windows 10
 * 22H2 (build 19045), desktop process, no package: the call returns S_OK and gives a
 * registration (a non-NULL pointer), also for a NULL routine; UnregisterAppStateChangeNotification
 * takes it back. The WebView2 runtime (msedge.dll) imports both from twinapi.appcore.dll with
 * delay loading, so that without this module the first call raises an exception.
 */

#include <windef.h>
#include <winbase.h>
#include <winerror.h>

typedef VOID (CALLBACK *PAPPSTATE_CHANGE_ROUTINE)(BOOLEAN Quiesced, PVOID Context);

typedef struct _APPSTATE_REGISTRATION
{
    PAPPSTATE_CHANGE_ROUTINE Routine;
    PVOID Context;
} APPSTATE_REGISTRATION, *PAPPSTATE_REGISTRATION;

HRESULT
WINAPI
RegisterAppStateChangeNotification(
    _In_opt_ PAPPSTATE_CHANGE_ROUTINE Routine,
    _In_opt_ PVOID Context,
    _Out_ PAPPSTATE_REGISTRATION *Registration)
{
    PAPPSTATE_REGISTRATION Reg;

    /* Windows 10 does not tell what it does with a NULL output pointer: refuse it */
    if (!Registration)
        return E_INVALIDARG;

    *Registration = NULL;
    Reg = HeapAlloc(GetProcessHeap(), 0, sizeof(*Reg));
    if (!Reg)
        return E_OUTOFMEMORY;

    Reg->Routine = Routine;
    Reg->Context = Context;
    *Registration = Reg;
    return S_OK;
}

VOID
WINAPI
UnregisterAppStateChangeNotification(
    _In_ PAPPSTATE_REGISTRATION Registration)
{
    if (Registration)
        HeapFree(GetProcessHeap(), 0, Registration);
}
