/*
 * PROJECT:     ReactOS Secondary Logon Service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Secondary Logon service RPC server
 * COPYRIGHT:   Eric Kohl 2022 <eric.kohl@reactos.org>
 */

#ifndef _SECLOGON_PCH_
#define _SECLOGON_PCH_

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsvc.h>
#include <winuser.h>
#include <svc.h>
#include <userenv.h>

#define NTOS_MODE_USER
#include <ndk/rtlfuncs.h>

#include <wine/debug.h>

extern HINSTANCE hDllInstance;
extern PSVCHOST_GLOBAL_DATA lpServiceGlobals;

typedef struct _SECL_DESKTOP_ACCESS SECL_DESKTOP_ACCESS;

/* desktop.c */
VOID
SeclInitDesktopAccess(VOID);

DWORD
SeclGrantDesktopAccess(
    _In_ HANDLE hToken,
    _In_opt_ PCWSTR pszDesktop,
    _Out_ SECL_DESKTOP_ACCESS **ppAccess,
    _Out_ PWSTR *ppszDesktopName);

VOID
SeclRevokeDesktopAccess(
    _In_opt_ SECL_DESKTOP_ACCESS *Access);

DWORD
StartRpcServer(VOID);

DWORD
StopRpcServer(VOID);

#endif /* _SECLOGON_PCH_ */
