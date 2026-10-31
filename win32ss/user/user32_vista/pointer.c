/*
 * PROJECT:     ReactOS user32 - Windows 8 and later pointer input APIs
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Pointer (touch, pen, mouse) query and device functions in user mode
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *              The mouse-in-pointer switch and the rule that pointer 1 is the mouse follow the
 *              Wine implementation (dlls/win32u/input.c, Copyright 2021 Rémi Bernon for
 *              CodeWeavers). Error codes and parameter order of every function were measured
 *              on Windows 10 (build 19045) with a machine that has no touch screen or pen.
 *
 * ReactOS sends no pointer messages (WM_POINTER*), so no pointer is ever in flight: every query
 * for pointer data fails the way Windows fails outside a pointer message. There is no touch
 * screen, pen or touchpad, so the device list is empty.
 */

#include "win8user.h"
#include <pseh/pseh2.h>

#define NDEBUG
#include <debug.h>

#define MOUSE_POINTER_ID 1

static volatile LONG s_MouseInPointer = -1;

static BOOL
Fail(DWORD Error)
{
    SetLastError(Error);
    return FALSE;
}

/*
 * A pointer query that cannot succeed reports a count or transform buffer it cannot write as an
 * access error. For the buffers of pointer data Windows 10 x64 does the same, but the 32-bit
 * version looks at the pointer id first and reports an id error.
 */
static BOOL
PointerQueryFailure(
    PVOID Count1, PVOID Count2,
    PVOID Data, SIZE_T DataSize)
{
    if ((Count1 && IsBadWritePtr(Count1, sizeof(UINT32))) ||
        (Count2 && IsBadWritePtr(Count2, sizeof(UINT32))))
        return Fail(ERROR_NOACCESS);

#ifdef _WIN64
    if (Data && IsBadWritePtr(Data, DataSize))
        return Fail(ERROR_NOACCESS);
#else
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(DataSize);
#endif
    return Fail(ERROR_INVALID_PARAMETER);
}

BOOL
WINAPI
EnableMouseInPointer(BOOL fEnable)
{
    LONG Wanted, Previous;

    if (fEnable != FALSE && fEnable != TRUE)
        return Fail(ERROR_INVALID_PARAMETER);

    Wanted = fEnable ? 1 : 0;
    Previous = InterlockedCompareExchange(&s_MouseInPointer, Wanted, -1);
    if (Previous != -1 && Previous != Wanted)
        return Fail(ERROR_ACCESS_DENIED);

    return TRUE;
}

BOOL
WINAPI
IsMouseInPointerEnabled(VOID)
{
    return s_MouseInPointer == 1;
}

BOOL
WINAPI
GetPointerType(
    _In_ UINT32 pointerId,
    _Out_ POINTER_INPUT_TYPE *pointerType)
{
    if (!pointerType || pointerId != MOUSE_POINTER_ID)
        return Fail(ERROR_INVALID_PARAMETER);

    _SEH2_TRY
    {
        *pointerType = PT_MOUSE;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        _SEH2_YIELD(return Fail(ERROR_INVALID_ADDRESS));
    }
    _SEH2_END;

    return TRUE;
}

BOOL
WINAPI
GetPointerCursorId(
    _In_ UINT32 pointerId,
    _Out_ UINT32 *cursorId)
{
    UNREFERENCED_PARAMETER(pointerId);
    UNREFERENCED_PARAMETER(cursorId);
    return Fail(ERROR_INVALID_PARAMETER);
}

BOOL
WINAPI
GetPointerInfo(
    _In_ UINT32 pointerId,
    _Out_ WIN8_POINTER_INFO *pointerInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(NULL, NULL, pointerInfo, sizeof(*pointerInfo));
}

BOOL
WINAPI
GetPointerInfoHistory(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *entriesCount,
    _Out_opt_ WIN8_POINTER_INFO *pointerInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(entriesCount, NULL, pointerInfo, sizeof(*pointerInfo));
}

BOOL
WINAPI
GetPointerFrameInfo(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *pointerCount,
    _Out_opt_ WIN8_POINTER_INFO *pointerInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(pointerCount, NULL, pointerInfo, sizeof(*pointerInfo));
}

BOOL
WINAPI
GetPointerFrameInfoHistory(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *entriesCount,
    _Inout_ UINT32 *pointerCount,
    _Out_opt_ WIN8_POINTER_INFO *pointerInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(entriesCount, pointerCount, pointerInfo, sizeof(*pointerInfo));
}

BOOL
WINAPI
GetPointerTouchInfo(
    _In_ UINT32 pointerId,
    _Out_ WIN8_POINTER_TOUCH_INFO *touchInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(NULL, NULL, touchInfo, sizeof(*touchInfo));
}

BOOL
WINAPI
GetPointerTouchInfoHistory(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *entriesCount,
    _Out_opt_ WIN8_POINTER_TOUCH_INFO *touchInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(entriesCount, NULL, touchInfo, sizeof(*touchInfo));
}

BOOL
WINAPI
GetPointerFrameTouchInfo(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *pointerCount,
    _Out_opt_ WIN8_POINTER_TOUCH_INFO *touchInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(pointerCount, NULL, touchInfo, sizeof(*touchInfo));
}

BOOL
WINAPI
GetPointerFrameTouchInfoHistory(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *entriesCount,
    _Inout_ UINT32 *pointerCount,
    _Out_opt_ WIN8_POINTER_TOUCH_INFO *touchInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(entriesCount, pointerCount, touchInfo, sizeof(*touchInfo));
}

BOOL
WINAPI
GetPointerPenInfo(
    _In_ UINT32 pointerId,
    _Out_ WIN8_POINTER_PEN_INFO *penInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(NULL, NULL, penInfo, sizeof(*penInfo));
}

BOOL
WINAPI
GetPointerPenInfoHistory(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *entriesCount,
    _Out_opt_ WIN8_POINTER_PEN_INFO *penInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(entriesCount, NULL, penInfo, sizeof(*penInfo));
}

BOOL
WINAPI
GetPointerFramePenInfo(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *pointerCount,
    _Out_opt_ WIN8_POINTER_PEN_INFO *penInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(pointerCount, NULL, penInfo, sizeof(*penInfo));
}

BOOL
WINAPI
GetPointerFramePenInfoHistory(
    _In_ UINT32 pointerId,
    _Inout_ UINT32 *entriesCount,
    _Inout_ UINT32 *pointerCount,
    _Out_opt_ WIN8_POINTER_PEN_INFO *penInfo)
{
    UNREFERENCED_PARAMETER(pointerId);
    return PointerQueryFailure(entriesCount, pointerCount, penInfo, sizeof(*penInfo));
}

BOOL
WINAPI
GetPointerInputTransform(
    _In_ UINT32 pointerId,
    _In_ UINT32 historyCount,
    _Out_ WIN8_INPUT_TRANSFORM *inputTransform)
{
    UNREFERENCED_PARAMETER(pointerId);
    UNREFERENCED_PARAMETER(historyCount);
    if (inputTransform && IsBadWritePtr(inputTransform, sizeof(*inputTransform)))
        return Fail(ERROR_NOACCESS);
    return Fail(ERROR_INVALID_PARAMETER);
}

BOOL
WINAPI
GetRawPointerDeviceData(
    _In_ UINT32 pointerId,
    _In_ UINT32 historyCount,
    _In_ UINT32 propertiesCount,
    _In_ WIN8_POINTER_DEVICE_PROPERTY *pProperties,
    _Out_ LONG *pValues)
{
    UNREFERENCED_PARAMETER(pointerId);
    UNREFERENCED_PARAMETER(historyCount);
    UNREFERENCED_PARAMETER(propertiesCount);
    UNREFERENCED_PARAMETER(pProperties);
    UNREFERENCED_PARAMETER(pValues);
    return Fail(ERROR_INVALID_PARAMETER);
}

BOOL
WINAPI
SkipPointerFrameMessages(_In_ UINT32 pointerId)
{
    return Fail(pointerId == MOUSE_POINTER_ID ? ERROR_ACCESS_DENIED : ERROR_INVALID_PARAMETER);
}

/* Without a pointer device there is no handle that these could be asked about: Windows 10
 * answers ERROR_INVALID_HANDLE whatever the arguments are */
BOOL
WINAPI
GetPointerDeviceOrientation(
    _In_ HANDLE device,
    _Out_ PVOID orientation)
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(orientation);
    return Fail(ERROR_INVALID_HANDLE);
}

BOOL
WINAPI
GetPointerDeviceInputSpace(
    _In_ HANDLE device,
    _Out_ PVOID inputSpace)
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputSpace);
    return Fail(ERROR_INVALID_HANDLE);
}

BOOL
WINAPI
GetPointerDevices(
    _Inout_ UINT32 *deviceCount,
    _Out_opt_ WIN8_POINTER_DEVICE_INFO *pointerDevices)
{
    if (!deviceCount)
        return Fail(ERROR_INVALID_PARAMETER);

    if (IsBadWritePtr(deviceCount, sizeof(*deviceCount)))
        return Fail(ERROR_NOACCESS);

    if (pointerDevices)
        return Fail(ERROR_SYSTEM_DEVICE_NOT_FOUND);

    *deviceCount = 0;
    return TRUE;
}

BOOL
WINAPI
GetPointerDevice(
    _In_ HANDLE device,
    _Out_ WIN8_POINTER_DEVICE_INFO *pointerDevice)
{
    return Fail((device && pointerDevice) ? ERROR_INVALID_HANDLE : ERROR_INVALID_PARAMETER);
}

BOOL
WINAPI
GetPointerDeviceProperties(
    _In_ HANDLE device,
    _Inout_ UINT32 *propertyCount,
    _Out_opt_ WIN8_POINTER_DEVICE_PROPERTY *pointerProperties)
{
    UNREFERENCED_PARAMETER(pointerProperties);
    return Fail((device && propertyCount) ? ERROR_INVALID_HANDLE : ERROR_INVALID_PARAMETER);
}

BOOL
WINAPI
GetPointerDeviceRects(
    _In_ HANDLE device,
    _Out_ RECT *pointerDeviceRect,
    _Out_ RECT *displayRect)
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(pointerDeviceRect);
    UNREFERENCED_PARAMETER(displayRect);
    return Fail(ERROR_INVALID_PARAMETER);
}

BOOL
WINAPI
GetPointerDeviceCursors(
    _In_ HANDLE device,
    _Inout_ UINT32 *cursorCount,
    _Out_opt_ WIN8_POINTER_DEVICE_CURSOR_INFO *deviceCursors)
{
    UNREFERENCED_PARAMETER(deviceCursors);
    return Fail((device && cursorCount) ? ERROR_INVALID_HANDLE : ERROR_INVALID_PARAMETER);
}
