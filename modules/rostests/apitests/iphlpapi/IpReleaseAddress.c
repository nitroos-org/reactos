/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IpReleaseAddress / IpRenewAddress with the adapter map of GetInterfaceInfo
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdlib.h>
#include <string.h>

static const WCHAR DevicePrefix[] = L"\\DEVICE\\TCPIP_";

START_TEST(IpReleaseAddress)
{
    PIP_INTERFACE_INFO Info;
    ULONG Size = 0, i;
    DWORD Error;
    BOOL Tested = FALSE;

    ok(IpReleaseAddress(NULL) == ERROR_INVALID_PARAMETER, "IpReleaseAddress(NULL) returned %lu\n", IpReleaseAddress(NULL));
    ok(IpRenewAddress(NULL) == ERROR_INVALID_PARAMETER, "IpRenewAddress(NULL) returned %lu\n", IpRenewAddress(NULL));

    Error = GetInterfaceInfo(NULL, &Size);
    ok(Error == ERROR_INSUFFICIENT_BUFFER, "GetInterfaceInfo size query returned %lu\n", Error);
    if (Error != ERROR_INSUFFICIENT_BUFFER)
        return;
    Info = malloc(Size);
    Error = GetInterfaceInfo(Info, &Size);
    ok(Error == NO_ERROR, "GetInterfaceInfo returned %lu\n", Error);
    if (Error != NO_ERROR)
    {
        free(Info);
        return;
    }

    for (i = 0; i < (ULONG)Info->NumAdapters; i++)
    {
        IP_ADAPTER_INDEX_MAP Bare, Full;
        DWORD RenewBare, RenewFull, Release;

        Full = Info->Adapter[i];
        ok(!_wcsnicmp(Full.Name, DevicePrefix, wcslen(DevicePrefix)), "adapter %lu: name %ls\n", i, Full.Name);
        if (_wcsnicmp(Full.Name, DevicePrefix, wcslen(DevicePrefix)))
            continue;

        /* the name the DHCP client API knows: the bare {GUID} */
        Bare = Full;
        wcscpy(Bare.Name, Full.Name + wcslen(DevicePrefix));

        RenewBare = IpRenewAddress(&Bare);
        if (RenewBare == ERROR_PROC_NOT_FOUND)
        {
            skip("the DHCP client service is not available\n");
            break;
        }
        if (RenewBare == ERROR_FILE_NOT_FOUND)
        {
            skip("adapter %ls is not known to the DHCP client (static or disconnected)\n", Bare.Name);
            continue;
        }

        /* Windows: the map from GetInterfaceInfo is what these functions take */
        RenewFull = IpRenewAddress(&Full);
        ok(RenewFull == RenewBare, "adapter %ls: IpRenewAddress(map) returned %lu, with the bare name %lu\n",
           Bare.Name, RenewFull, RenewBare);
        ok(RenewFull != ERROR_FILE_NOT_FOUND, "adapter %ls: IpRenewAddress(map) returned ERROR_FILE_NOT_FOUND\n", Bare.Name);

        Release = IpReleaseAddress(&Full);
        ok(Release != ERROR_FILE_NOT_FOUND, "adapter %ls: IpReleaseAddress(map) returned ERROR_FILE_NOT_FOUND\n", Bare.Name);
        /* give the adapter its configuration back */
        IpRenewAddress(&Full);
        Tested = TRUE;
    }

    free(Info);
    if (!Tested)
        skip("no adapter with a DHCP client entry\n");
}
