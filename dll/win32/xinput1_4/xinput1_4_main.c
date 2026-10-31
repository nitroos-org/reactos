/*
 * The Wine project - Xinput Joystick Library (xinput1_4)
 * Copyright 2008 Andrew Fenn
 *
 * Adapted for ReactOS from the Wine xinput1_3 code: no controller is ever
 * connected, so every query reports ERROR_DEVICE_NOT_CONNECTED, as Windows
 * does without a gamepad. The functions that xinput1_4.dll adds over
 * xinput1_3.dll (XInputGetAudioDeviceIds and the ordinal-only 101-104, 108)
 * are provided as well.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <config.h>

#include <wine/debug.h>
#include <winbase.h>

#include <xinput.h>

WINE_DEFAULT_DEBUG_CHANNEL(xinput);

/* No controller is connected. Windows validates the user index first. */
static DWORD check_index(DWORD index)
{
    if (index >= XUSER_MAX_COUNT)
        return ERROR_BAD_ARGUMENTS;
    return ERROR_DEVICE_NOT_CONNECTED;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(inst);
        break;
    }
    return TRUE;
}

void WINAPI DECLSPEC_HOTPATCH XInputEnable(BOOL enable)
{
    TRACE("(enable %d)\n", enable);
}

DWORD WINAPI XInputSetState(DWORD index, XINPUT_VIBRATION *vibration)
{
    TRACE("(index %lu, vibration %p)\n", index, vibration);
    return check_index(index);
}

DWORD WINAPI DECLSPEC_HOTPATCH XInputGetState(DWORD index, XINPUT_STATE *state)
{
    TRACE("(index %lu, state %p)\n", index, state);
    return check_index(index);
}

DWORD WINAPI DECLSPEC_HOTPATCH XInputGetStateEx(DWORD index, XINPUT_STATE_EX *state_ex)
{
    TRACE("(index %lu, state %p)\n", index, state_ex);
    return check_index(index);
}

DWORD WINAPI XInputGetKeystroke(DWORD index, DWORD reserved, PXINPUT_KEYSTROKE keystroke)
{
    TRACE("(index %lu, reserved %lu, keystroke %p)\n", index, reserved, keystroke);
    return check_index(index);
}

DWORD WINAPI XInputGetCapabilities(DWORD index, DWORD flags, XINPUT_CAPABILITIES *capabilities)
{
    TRACE("(index %lu, flags 0x%lx, capabilities %p)\n", index, flags, capabilities);
    return check_index(index);
}

DWORD WINAPI XInputGetCapabilitiesEx(DWORD unk, DWORD index, DWORD flags, void *capabilities)
{
    TRACE("(unk %lu, index %lu, flags 0x%lx, capabilities %p)\n", unk, index, flags, capabilities);
    return check_index(index);
}

DWORD WINAPI XInputGetAudioDeviceIds(DWORD index, LPWSTR render_id, UINT *render_count,
                                     LPWSTR capture_id, UINT *capture_count)
{
    TRACE("(index %lu, render %p %p, capture %p %p)\n", index, render_id, render_count, capture_id, capture_count);
    return check_index(index);
}

DWORD WINAPI XInputGetBatteryInformation(DWORD index, BYTE type, XINPUT_BATTERY_INFORMATION *battery)
{
    TRACE("(index %lu, type %u, battery %p)\n", index, type, battery);
    return check_index(index);
}

DWORD WINAPI XInputWaitForGuideButton(DWORD index, DWORD flag, void *unknown)
{
    TRACE("(index %lu, flag %lu, unknown %p)\n", index, flag, unknown);
    return check_index(index);
}

DWORD WINAPI XInputCancelGuideButtonWait(DWORD index)
{
    TRACE("(index %lu)\n", index);
    return check_index(index);
}

DWORD WINAPI XInputPowerOffController(DWORD index)
{
    TRACE("(index %lu)\n", index);
    return check_index(index);
}

DWORD WINAPI XInputGetBaseBusInformation(DWORD index, void *info)
{
    TRACE("(index %lu, info %p)\n", index, info);
    return check_index(index);
}
