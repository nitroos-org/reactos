/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The function device of an HD Audio codec needs no driver and raises no New Hardware wizard
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * hdaudbus creates a function device HDAUDIO\FUNC_01&VEN_...&DEV_... for every audio codec and offers
 * HDAUDIO\FUNC_01 as its compatible ID. There is no function driver, so machine.inf binds that ID to
 * "no driver needed", as it does for the other devices of virtual machines: the device is installed, has
 * no problem code, and the PnP manager has nothing left to ask the user about.
 */

#include <apitest.h>

#include <winreg.h>
#include <cfgmgr32.h>
#include <winuser.h>
#include <setupapi.h>

/* machine.inf lists HDAUDIO\FUNC_01 with the install section NO_DRV in a [Manufacturer] model section */
static
BOOL
InfBindsFunctionDevice(void)
{
    WCHAR Path[MAX_PATH];
    HINF Inf;
    INFCONTEXT Context;
    WCHAR Section[64], Id[128];
    BOOL Found = FALSE, More;
    UINT Length;

    Length = GetWindowsDirectoryW(Path, MAX_PATH);
    if (!Length)
        return FALSE;
    lstrcatW(Path, L"\\inf\\machine.inf");
    Inf = SetupOpenInfFileW(Path, NULL, INF_STYLE_WIN4, NULL);
    ok(Inf != INVALID_HANDLE_VALUE, "SetupOpenInfFile(%ls) failed with %lu\n", Path, GetLastError());
    if (Inf == INVALID_HANDLE_VALUE)
        return FALSE;

    /* every model section named by [Manufacturer] is a place for the line; the one that holds it is enough */
    More = SetupFindFirstLineW(Inf, L"Manufacturer", NULL, &Context);
    while (More && !Found)
    {
        INFCONTEXT Line;
        WCHAR Model[64];
        BOOL MoreLines;

        if (SetupGetStringFieldW(&Context, 1, Model, ARRAYSIZE(Model), NULL))
        {
            MoreLines = SetupFindFirstLineW(Inf, Model, NULL, &Line);
            while (MoreLines)
            {
                /* %description% = install section,hardware ID */
                if (SetupGetStringFieldW(&Line, 1, Section, ARRAYSIZE(Section), NULL) &&
                    SetupGetStringFieldW(&Line, 2, Id, ARRAYSIZE(Id), NULL) &&
                    !lstrcmpiW(Id, L"HDAUDIO\\FUNC_01") && !lstrcmpiW(Section, L"NO_DRV"))
                {
                    Found = TRUE;
                    break;
                }
                MoreLines = SetupFindNextLine(&Line, &Line);
            }
        }
        More = SetupFindNextLine(&Context, &Context);
    }

    SetupCloseInfFile(Inf);
    return Found;
}

START_TEST(HdaFunctionDevice)
{
    HDEVINFO Set;
    SP_DEVINFO_DATA Data;
    DWORD Index, Status, Problem, Count = 0;
    WCHAR InstanceId[MAX_DEVICE_ID_LEN];

    ok(InfBindsFunctionDevice(), "machine.inf does not bind HDAUDIO\\FUNC_01 to NO_DRV\n");

    /* Every function device present (a machine with an HD Audio codec) is installed and has no problem */
    Set = SetupDiGetClassDevsW(NULL, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
    ok(Set != INVALID_HANDLE_VALUE, "SetupDiGetClassDevs failed with %lu\n", GetLastError());
    if (Set == INVALID_HANDLE_VALUE)
        return;

    Data.cbSize = sizeof(Data);
    for (Index = 0; SetupDiEnumDeviceInfo(Set, Index, &Data); Index++)
    {
        if (!SetupDiGetDeviceInstanceIdW(Set, &Data, InstanceId, ARRAYSIZE(InstanceId), NULL) ||
            _wcsnicmp(InstanceId, L"HDAUDIO\\FUNC_", 13) != 0)
            continue;

        Count++;
        ok(CM_Get_DevNode_Status(&Status, &Problem, Data.DevInst, 0) == CR_SUCCESS,
           "CM_Get_DevNode_Status(%ls) failed\n", InstanceId);
        ok(!(Status & DN_HAS_PROBLEM), "%ls has the problem code %lu (status 0x%lx)\n", InstanceId, Problem, Status);
        ok(!(Status & DN_NEED_RESTART), "%ls needs a restart (status 0x%lx)\n", InstanceId, Status);
        trace("%ls: status 0x%lx problem %lu\n", InstanceId, Status, Problem);
    }
    if (Count == 0)
        skip("no HD Audio function device on this machine\n");

    SetupDiDestroyDeviceInfoList(Set);
}
