/*
 * newdevp.h
 *
 * Private header for newdev.dll
 *
 */

#ifndef __NEWDEVP__H
#define __NEWDEVP__H

#ifdef __cplusplus
extern "C" {
#endif

/* UI mode umpnpmgr passes on the install pipe to ClientSideInstallW and drvinst.exe
   (the ReactOS-specific value after the event name) */
#define NEWDEV_UI_HIDDEN        0   /* install without UI */
#define NEWDEV_UI_WIZARD        1   /* install, with the wizard if no driver is found */
#define NEWDEV_UI_RESTART_PAGE  2   /* no install: the device was installed service-side
                                       and needs a restart; show the wizard's restart page */

BOOL
WINAPI
DevInstallW(
    IN HWND hWndParent,
    IN HINSTANCE hInstance,
    IN LPCWSTR InstanceId,
    IN INT Show);

BOOL
WINAPI
InstallDevInst(
    IN HWND hWndParent,
    IN LPCWSTR InstanceId,
    IN BOOL bUpdate,
    OUT LPDWORD lpReboot);

BOOL
WINAPI
InstallDevInstEx(
    IN HWND hWndParent,
    IN LPCWSTR InstanceId,
    IN BOOL bUpdate,
    OUT LPDWORD lpReboot,
    IN DWORD Unknown);

#ifdef __cplusplus
}
#endif

#endif /* __NEWDEVP__H */
