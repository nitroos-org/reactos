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

PSID
SeclGetLogonSid(
    _In_ HANDLE hToken);

BOOL
SeclValidDesktopName(
    _In_opt_ PCWSTR pszDesktop);

/* logon.c */
typedef struct _SECL_NAMESPACE_ACCESS SECL_NAMESPACE_ACCESS;

BOOL
SeclStartLogonWait(
    _In_opt_ SECL_DESKTOP_ACCESS *Access,
    _In_opt_ SECL_NAMESPACE_ACCESS *Namespace,
    _In_ HANDLE hToken,
    _In_opt_ HANDLE hProfile,
    _In_ HANDLE hProcess,
    _In_ DWORD ClientSessionId,
    _In_opt_ PCWSTR ClientDesktop);

VOID
SeclWaitForLogonProcesses(
    _In_ PSID LogonSid);

VOID
SeclRevokeClientDesktop(
    _In_ DWORD SessionId,
    _In_ PSID LogonSid,
    _In_ PCWSTR Desktop);

BOOL
SeclGrantClientDesktop(
    _In_ DWORD SessionId,
    _In_ DWORD CallerProcessId,
    _In_ PSID LogonSid,
    _In_ PCWSTR Desktop);

/* namespace.c */
VOID
SeclSweepNamespaceAccess(VOID);


VOID
SeclInitNamespaceAccess(VOID);

DWORD
SeclGrantNamespaceAccess(
    _In_ HANDLE hToken,
    _In_ DWORD SessionId,
    _Out_ SECL_NAMESPACE_ACCESS **ppAccess);

VOID
SeclRevokeNamespaceAccess(
    _In_opt_ SECL_NAMESPACE_ACCESS *Access);

DWORD
StartRpcServer(VOID);

DWORD
StopRpcServer(VOID);

#endif /* _SECLOGON_PCH_ */
