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
#define NEWDEV_UI_INSTALL_INF   3   /* drvinst.exe only: install the driver an administrator
                                       picked, from the INF path that follows on the pipe */

/*
 * Install request pipe of the Plug and Play service (umpnpmgr). A process that is not
 * SYSTEM (the newdev wizard, Device Manager's Update Driver, UpdateDriverForPlugAndPlayDevices)
 * only picks the driver. It sends the device and the INF of that driver here, and the service
 * runs the install in drvinst.exe as SYSTEM, as Windows hands it to DrvInst.exe. Only
 * administrators and SYSTEM can open the pipe, and the service checks the caller's token again.
 *
 * Request: PNP_INSTALL_REQUEST, then DeviceIdBytes of device instance ID and InfPathBytes of
 * full INF path, both UTF-16 and NUL-terminated (the counts include the NUL).
 *
 * The INF is never read from where the user picked it (a UNC path, a mapped drive, a folder
 * other users can write): the requester copies the driver package (the INF, every file it
 * copies, its catalog) into a protected per-request directory under %SystemRoot%\PnpStage that
 * only SYSTEM and Administrators can write, and sends the path of the INF in that copy. The
 * service refuses any other INF path (except an INF already in %SystemRoot%\inf) and installs
 * from the copy only. The requester removes the copy when the install is done; the service
 * removes leftovers when it starts.
 * Reply: PNP_INSTALL_REPLY. Error is a Win32 error code; NeedRestart is TRUE when the install
 * succeeded and the device needs a restart.
 */
#define PNP_INSTALL_REQUEST_PIPE        L"\\\\.\\pipe\\PNP_Device_Install_Request"
#define PNP_INSTALL_REQUEST_MAGIC       0x52494E50  /* "PNIR" */
#define PNP_INSTALL_REPLY_MAGIC         0x50524E50  /* "PNRP" */
#define PNP_INSTALL_REQUEST_VERSION     1

/* One limit for the device instance ID everywhere (requester, service, drvinst): the
   bytes including the NUL; MAX_DEVICE_ID_LEN counts the NUL */
#define PNP_INSTALL_MAX_DEVICE_ID_BYTES (200 * sizeof(WCHAR))

/* Staging: %SystemRoot%\PnpStage\<request directory>\<name>.inf. The directories are created
   with this DACL (no inheritance from the parent): SYSTEM and Administrators only */
#define PNP_INSTALL_STAGE_ROOT          L"PnpStage"
#define PNP_INSTALL_STAGE_SDDL          L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"

/* PNP_INSTALL_REQUEST.Origin: who asked, for the device install log */
#define PNP_INSTALL_ORIGIN_WIZARD       1   /* the newdev wizard (new device, Update Driver) */
#define PNP_INSTALL_ORIGIN_UPDATEDRIVER 2   /* UpdateDriverForPlugAndPlayDevices */
#define PNP_INSTALL_ORIGIN_DEVINSTALL   3   /* DevInstallW in a process that is not SYSTEM */
#define PNP_INSTALL_ORIGIN_MAX          3

typedef struct _PNP_INSTALL_REQUEST
{
    DWORD Magic;
    DWORD Version;
    DWORD Origin;
    DWORD Flags;            /* reserved, must be 0 */
    DWORD DeviceIdBytes;
    DWORD InfPathBytes;
} PNP_INSTALL_REQUEST, *PPNP_INSTALL_REQUEST;

typedef struct _PNP_INSTALL_REPLY
{
    DWORD Magic;
    DWORD Error;
    DWORD NeedRestart;
} PNP_INSTALL_REPLY, *PPNP_INSTALL_REPLY;

BOOL
WINAPI
DevInstallW(
    IN HWND hWndParent,
    IN HINSTANCE hInstance,
    IN LPCWSTR InstanceId,
    IN INT Show);

/* drvinst.exe only: installs the best driver of the INF at InfPath on the device, in the
   caller's (SYSTEM) context, without UI. Flags must be 0. On success the last error is
   ERROR_SUCCESS_REBOOT_REQUIRED when the device needs a restart. */
BOOL
WINAPI
DevInstallFromInfW(
    IN LPCWSTR InstanceId,
    IN LPCWSTR InfPath,
    IN DWORD Flags);

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
