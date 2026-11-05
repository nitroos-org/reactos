/*
 * PROJECT:     ReactOS user32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     RegisterPowerSettingNotification and UnregisterPowerSettingNotification (Vista and later)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (interactive session, a probe that registers a hidden window for each setting and
 * pumps its messages): every registration answers a handle, also for a NULL or the desktop window and for flags
 * that are not DEVICE_NOTIFY_WINDOW_HANDLE; a window of the process gets, once per registration and after the call
 * has returned (it is a notification, not a call inside the registration), WM_POWERBROADCAST with
 * PBT_POWERSETTINGCHANGE and the present value of the setting for these settings:
 *   GUID_ACDC_POWER_SOURCE (4 bytes, 0 is AC), GUID_POWERSCHEME_PERSONALITY (the 16-byte GUID of the scheme type),
 *   GUID_MONITOR_POWER_ON, GUID_CONSOLE_DISPLAY_STATE and GUID_SESSION_DISPLAY_STATUS (4 bytes, 1 is on),
 *   GUID_SESSION_USER_PRESENCE and GUID_GLOBAL_USER_PRESENCE (4 bytes: 0 present, 1 not present, 2 inactive) and
 *   GUID_POWER_SAVING_STATUS (4 bytes, 0 is off).
 * Settings that only report a change (the battery level of a system without a battery, away mode, the lid), and
 * settings this does not know, send nothing at the registration. Registering the same setting again, or after
 * the first registration was ended, sends the value again. Two further settings answered at the registration of
 * Windows (515c31d8-f734-163d-a0fd-11a08c91e8f1: 0x1f94, 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469: 5) are not
 * known well enough to answer.
 * The value of the user presence is "present": the oracle answered "inactive" because nobody used it.
 * Nothing here changes later: this system has no power setting that changes, so only the first value is sent.
 */

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>

#define NDEBUG
#include <debug.h>

typedef PVOID HPOWERNOTIFY;

#ifndef PBT_POWERSETTINGCHANGE
#define PBT_POWERSETTINGCHANGE 0x8013
#endif

typedef struct _PWR_BROADCAST_SETTING
{
    GUID PowerSetting;
    DWORD DataLength;
    UCHAR Data[16];
} PWR_BROADCAST_SETTING;

typedef struct _POWER_SETTING_NOTIFY
{
    struct _POWER_SETTING_NOTIFY *Next;
    HANDLE Recipient;
    DWORD Flags;
    GUID Setting;
} POWER_SETTING_NOTIFY, *PPOWER_SETTING_NOTIFY;

static const GUID GuidAcDcPowerSource = { 0x5d3e9a59, 0xe9d5, 0x4b00, { 0xa6, 0xbd, 0xff, 0x34, 0xff, 0x51, 0x65, 0x48 } };
static const GUID GuidPowerSchemePersonality = { 0x245d8541, 0x3943, 0x4422, { 0xb0, 0x25, 0x13, 0xa7, 0x84, 0xf6, 0x79, 0xb7 } };
static const GUID GuidTypicalPowerSavings = { 0x381b4222, 0xf694, 0x41f0, { 0x96, 0x85, 0xff, 0x5b, 0xb2, 0x60, 0xdf, 0x2e } };
static const GUID GuidMonitorPowerOn = { 0x02731015, 0x4510, 0x4526, { 0x99, 0xe6, 0xe5, 0xa1, 0x7e, 0xbd, 0x1a, 0xea } };
static const GUID GuidConsoleDisplayState = { 0x6fe69556, 0x704a, 0x47a0, { 0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47 } };
static const GUID GuidSessionDisplayStatus = { 0x2b84c20e, 0xad23, 0x4ddf, { 0x93, 0xdb, 0x05, 0xff, 0xbd, 0x7e, 0xfc, 0xa5 } };
static const GUID GuidSessionUserPresence = { 0x3c0f4548, 0xc03f, 0x4c4d, { 0xb9, 0xf2, 0x23, 0x7e, 0xde, 0x68, 0x63, 0x76 } };
static const GUID GuidGlobalUserPresence = { 0x786e8a1d, 0xb427, 0x4344, { 0x92, 0x07, 0x09, 0xe7, 0x0b, 0xdc, 0xbe, 0xa9 } };
static const GUID GuidPowerSavingStatus = { 0xe00958c0, 0xc213, 0x4ace, { 0xac, 0x77, 0xfe, 0xcc, 0xed, 0x2e, 0xee, 0xa5 } };

static PPOWER_SETTING_NOTIFY NotifyList;
static CRITICAL_SECTION NotifyLock;
static CRITICAL_SECTION_DEBUG NotifyLockDebug =
{
    0, 0, &NotifyLock,
    { &NotifyLockDebug.ProcessLocksList, &NotifyLockDebug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": NotifyLock") }
};
static CRITICAL_SECTION NotifyLock = { &NotifyLockDebug, -1, 0, 0, 0, 0 };

/* The message is posted and carries a pointer, and nothing tells when the window is done with it: the
   notifications go through a ring of buffers that is long enough for every one that can be waiting. */
#define SLOT_COUNT 64
static PWR_BROADCAST_SETTING Slots[SLOT_COUNT];
static LONG SlotIndex;

static
BOOL
GetInitialValue(
    _In_ const GUID *Setting,
    _Out_ PWR_BROADCAST_SETTING *Value)
{
    DWORD Data = 0;

    RtlZeroMemory(Value, sizeof(*Value));
    Value->PowerSetting = *Setting;
    Value->DataLength = sizeof(DWORD);

    if (IsEqualGUID(Setting, &GuidAcDcPowerSource))
    {
        SYSTEM_POWER_STATUS Status;
        /* 0 AC, 1 DC; a system that cannot tell is on AC, as a desktop is */
        if (GetSystemPowerStatus(&Status) && Status.ACLineStatus == 0)
            Data = 1;
    }
    else if (IsEqualGUID(Setting, &GuidPowerSchemePersonality))
    {
        Value->DataLength = sizeof(GUID);
        RtlCopyMemory(Value->Data, &GuidTypicalPowerSavings, sizeof(GUID));
        return TRUE;
    }
    else if (IsEqualGUID(Setting, &GuidMonitorPowerOn) ||
             IsEqualGUID(Setting, &GuidConsoleDisplayState) ||
             IsEqualGUID(Setting, &GuidSessionDisplayStatus))
    {
        Data = 1;
    }
    else if (IsEqualGUID(Setting, &GuidSessionUserPresence) ||
             IsEqualGUID(Setting, &GuidGlobalUserPresence) ||
             IsEqualGUID(Setting, &GuidPowerSavingStatus))
    {
        Data = 0;
    }
    else
    {
        return FALSE;
    }

    RtlCopyMemory(Value->Data, &Data, sizeof(Data));
    return TRUE;
}

static
VOID
SendInitialValue(
    _In_ HANDLE Recipient,
    _In_ const GUID *Setting)
{
    PWR_BROADCAST_SETTING *Slot;
    DWORD ProcessId = 0;
    HWND Window = (HWND)Recipient;

    /* Only a window of this process is told: the buffer is ours */
    if (!Window || !IsWindow(Window) || !GetWindowThreadProcessId(Window, &ProcessId) ||
        ProcessId != GetCurrentProcessId())
        return;

    Slot = &Slots[(DWORD)InterlockedIncrement(&SlotIndex) % SLOT_COUNT];
    if (!GetInitialValue(Setting, Slot))
        return;

    PostMessageW(Window, WM_POWERBROADCAST, PBT_POWERSETTINGCHANGE, (LPARAM)Slot);
}

HPOWERNOTIFY
WINAPI
RegisterPowerSettingNotification(
    _In_ HANDLE hRecipient,
    _In_ const GUID *PowerSettingGuid,
    _In_ DWORD Flags)
{
    PPOWER_SETTING_NOTIFY Notify;

    if (!PowerSettingGuid)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    Notify = HeapAlloc(GetProcessHeap(), 0, sizeof(*Notify));
    if (!Notify)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    Notify->Recipient = hRecipient;
    Notify->Flags = Flags;
    Notify->Setting = *PowerSettingGuid;

    EnterCriticalSection(&NotifyLock);
    Notify->Next = NotifyList;
    NotifyList = Notify;
    LeaveCriticalSection(&NotifyLock);

    /* DEVICE_NOTIFY_SERVICE_HANDLE (1): the recipient is a service status handle, not a window */
    if (!(Flags & 1))
        SendInitialValue(hRecipient, PowerSettingGuid);

    return (HPOWERNOTIFY)Notify;
}

BOOL
WINAPI
UnregisterPowerSettingNotification(
    _In_ HPOWERNOTIFY Handle)
{
    PPOWER_SETTING_NOTIFY *Link, Notify = NULL;

    EnterCriticalSection(&NotifyLock);
    for (Link = &NotifyList; *Link; Link = &(*Link)->Next)
    {
        if (*Link == (PPOWER_SETTING_NOTIFY)Handle)
        {
            Notify = *Link;
            *Link = Notify->Next;
            break;
        }
    }
    LeaveCriticalSection(&NotifyLock);

    if (!Notify)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    HeapFree(GetProcessHeap(), 0, Notify);
    return TRUE;
}
