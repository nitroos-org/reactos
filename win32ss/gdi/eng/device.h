
#pragma once

#define TAG_GDEV 'gdev'

/* NitroSessions: a session without the console draws into memory (headless.c) */
extern BOOLEAN gbHeadlessSession;
extern PGRAPHICS_DEVICE gpHeadlessGraphicsDevice;

BOOL
APIENTRY
HeadlessEnableDriver(
    _In_ ULONG iEngineVersion,
    _In_ ULONG cj,
    _Inout_bytecount_(cj) PDRVENABLEDATA pded);

VOID
HeadlessFillMode(
    _Out_ PDEVMODEW pdm);

VOID
NTAPI
PDEVOBJ_vRefreshModeList(
    PPDEVOBJ ppdev);

VOID
APIENTRY
EngFileWrite(
    _In_ PFILE_OBJECT pFileObject,
    _In_reads_(nLength) PVOID lpBuffer,
    _In_ SIZE_T nLength,
    _Out_ PSIZE_T lpBytesWritten);

NTSTATUS
NTAPI
EngpUpdateMonitorDevices(
    _In_ PGRAPHICS_DEVICE pGraphicsDevice);

BOOLEAN
NTAPI
EngpGetMonitorDevice(
    _In_ PGRAPHICS_DEVICE pGraphicsDevice,
    _In_ ULONG iMonitor,
    _Out_ PDEVICE_OBJECT *ppdo,
    _Out_ PULONG pulFlags);

PGRAPHICS_DEVICE
NTAPI
EngpFindGraphicsDevice(
    _In_opt_ PUNICODE_STRING pustrDevice,
    _In_ ULONG iDevNum);

PGRAPHICS_DEVICE
NTAPI
EngpRegisterGraphicsDevice(
    _In_ PUNICODE_STRING pustrDeviceName,
    _In_ PUNICODE_STRING pustrDiplayDrivers,
    _In_ PUNICODE_STRING pustrDescription);

NTSTATUS
EngpUpdateGraphicsDeviceList(VOID);

/* Read configuration of a graphics card from registry:
 * - pGraphicsDevice: instance of the graphics card
 * - pdm: on output, contains the values read in registry
 * Return value: a STATUS_* value
 * Assume that pdm has already been zero-filled.
 * Note that dmFields is not updated. */
NTSTATUS
EngpGetDisplayDriverParameters(
    _In_ PGRAPHICS_DEVICE pGraphicsDevice,
    _Out_ PDEVMODEW pdm);

/* Read acceleration level of a graphics card from registry
 * - pGraphicsDevice: instance of the graphics card
 * - Return value: acceleration level stored in registry */
DWORD
EngpGetDisplayDriverAccelerationLevel(
    _In_ PGRAPHICS_DEVICE pGraphicsDevice);

CODE_SEG("INIT")
NTSTATUS
NTAPI
InitDeviceImpl(VOID);

