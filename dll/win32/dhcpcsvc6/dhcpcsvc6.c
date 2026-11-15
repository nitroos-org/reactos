/*
 * PROJECT:     ReactOS DHCPv6 client API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     dhcpcsvc6.dll: Dhcpv6CApiInitialize/Cleanup, Dhcpv6RequestParams, prefix delegation stubs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * The DHCPv6 client lives in the DHCP service (base/services/dhcpcsvc/dhcp6.c). This library answers
 * Dhcpv6RequestParams from what the service keeps for each interface: the options of the last Reply (the
 * Dhcpv6Options value, dhcp6.h). With forceNewInform it asks the service for a new Information-Request first
 * (a named event only SYSTEM and administrators can open) and waits a few seconds for the Reply count to change.
 * Prefix delegation is not implemented: the three prefix calls return ERROR_NOT_SUPPORTED.
 */

#include <stdarg.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winerror.h>
#include <winnls.h>
#include <dhcpv6csdk.h>

#include <dhcp6.h>

#define API_VERSION         2
#define FORCE_WAIT_MS       5000
#define FORCE_POLL_MS       100

static LONG InitCount;

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD Reason, LPVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hInstance);
    return TRUE;
}

DWORD WINAPI Dhcpv6CApiInitialize(LPDWORD Version)
{
    if (!Version)
        return ERROR_INVALID_PARAMETER;
    InterlockedIncrement(&InitCount);
    *Version = API_VERSION;
    return ERROR_SUCCESS;
}

VOID WINAPI Dhcpv6CApiCleanup(VOID)
{
    if (InterlockedDecrement(&InitCount) < 0)
        InterlockedExchange(&InitCount, 0);
}

/* The options of the last Reply for an adapter (GUID name with braces), or for the first interface that has some
   when no name is given. The caller frees *Options with HeapFree. */
static BOOL ReadOptions(PCWSTR AdapterName, PBYTE *Options, DWORD *Length, DWORD *Replies)
{
    HKEY Parent, Key;
    DWORD Index;
    CHAR Name[128];

    *Options = NULL;
    *Length = 0;
    *Replies = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, DHCP6_INTERFACES_KEY, 0, KEY_READ, &Parent) != ERROR_SUCCESS)
        return FALSE;

    for (Index = 0; ; Index++)
    {
        DWORD Size = sizeof(Name), Type, DataSize = 0, Count = 0, CountSize = sizeof(Count);
        PBYTE Data;

        if (RegEnumKeyExA(Parent, Index, Name, &Size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        if (AdapterName && AdapterName[0])
        {
            CHAR Wanted[128];

            if (!WideCharToMultiByte(CP_ACP, 0, AdapterName, -1, Wanted, sizeof(Wanted), NULL, NULL) ||
                lstrcmpiA(Wanted, Name) != 0)
                continue;
        }
        if (RegOpenKeyExA(Parent, Name, 0, KEY_READ, &Key) != ERROR_SUCCESS)
            continue;
        if (RegQueryValueExA(Key, DHCP6_VALUE_OPTIONS, NULL, &Type, NULL, &DataSize) == ERROR_SUCCESS &&
            Type == REG_BINARY && DataSize != 0 && (Data = HeapAlloc(GetProcessHeap(), 0, DataSize)) != NULL)
        {
            if (RegQueryValueExA(Key, DHCP6_VALUE_OPTIONS, NULL, &Type, Data, &DataSize) == ERROR_SUCCESS)
            {
                RegQueryValueExA(Key, DHCP6_VALUE_REPLIES, NULL, &Type, (LPBYTE)&Count, &CountSize);
                *Options = Data;
                *Length = DataSize;
                *Replies = Count;
                RegCloseKey(Key);
                RegCloseKey(Parent);
                return TRUE;
            }
            HeapFree(GetProcessHeap(), 0, Data);
        }
        RegCloseKey(Key);
        if (AdapterName && AdapterName[0])
            break;
    }
    RegCloseKey(Parent);
    return FALSE;
}

/* The data of option Id in a DHCPv6 options area (code, length, data, ...); FALSE when absent or malformed */
static BOOL FindOption(const BYTE *Options, DWORD Length, ULONG Id, const BYTE **Data, DWORD *DataLength)
{
    DWORD Pos = 0;

    while (Length - Pos >= 4)
    {
        ULONG Code = (Options[Pos] << 8) | Options[Pos + 1];
        DWORD OptLength = (Options[Pos + 2] << 8) | Options[Pos + 3];

        Pos += 4;
        if (OptLength > Length - Pos)
            return FALSE;
        if (Code == Id)
        {
            *Data = Options + Pos;
            *DataLength = OptLength;
            return TRUE;
        }
        Pos += OptLength;
    }
    return FALSE;
}

/* Asks the service for a new Information-Request and waits for its Reply count to change */
static DWORD ForceInformation(PCWSTR AdapterName)
{
    HANDLE Event = OpenEventW(EVENT_MODIFY_STATE, FALSE, DHCP6_FORCE_EVENT_NAME);
    PBYTE Old;
    DWORD OldLength, Before, Waited;

    if (!Event)
        return GetLastError() == ERROR_ACCESS_DENIED ? ERROR_ACCESS_DENIED : ERROR_SUCCESS; /* no client: use the cache */

    if (ReadOptions(AdapterName, &Old, &OldLength, &Before))
        HeapFree(GetProcessHeap(), 0, Old);
    SetEvent(Event);
    CloseHandle(Event);

    for (Waited = 0; Waited < FORCE_WAIT_MS; Waited += FORCE_POLL_MS)
    {
        DWORD After;

        Sleep(FORCE_POLL_MS);
        if (ReadOptions(AdapterName, &Old, &OldLength, &After))
        {
            HeapFree(GetProcessHeap(), 0, Old);
            if (After != Before)
                break;
        }
    }
    return ERROR_SUCCESS;
}

DWORD WINAPI
Dhcpv6RequestParams(
    BOOL forceNewInform,
    LPVOID reserved,
    LPWSTR adapterName,
    LPDHCPV6CAPI_CLASSID classId,
    DHCPV6CAPI_PARAMS_ARRAY recdParams,
    LPBYTE buffer,
    LPDWORD pSize)
{
    PBYTE Options = NULL;
    DWORD Length = 0, Replies, Needed = 0, Used = 0, Error;
    ULONG i;

    if (!pSize || (recdParams.nParams && !recdParams.Params) || (*pSize && !buffer))
        return ERROR_INVALID_PARAMETER;

    if (forceNewInform)
    {
        Error = ForceInformation(adapterName);
        if (Error != ERROR_SUCCESS)
            return Error;
    }

    ReadOptions(adapterName, &Options, &Length, &Replies);

    /* the room the answers need (each one aligned to 4 bytes) */
    for (i = 0; i < recdParams.nParams; i++)
    {
        const BYTE *Data;
        DWORD DataLength;

        if (!recdParams.Params[i].IsVendor && Options && FindOption(Options, Length, recdParams.Params[i].OptionId, &Data, &DataLength))
            Needed += (DataLength + 3) & ~3UL;
    }
    if (Needed > *pSize)
    {
        *pSize = Needed;
        if (Options)
            HeapFree(GetProcessHeap(), 0, Options);
        return ERROR_MORE_DATA;
    }

    for (i = 0; i < recdParams.nParams; i++)
    {
        const BYTE *Data;
        DWORD DataLength;
        PDHCPV6CAPI_PARAMS Param = &recdParams.Params[i];

        if (!Param->IsVendor && Options && FindOption(Options, Length, Param->OptionId, &Data, &DataLength))
        {
            CopyMemory(buffer + Used, Data, DataLength);
            Param->Data = buffer + Used;
            Param->nBytesData = DataLength;
            Used += (DataLength + 3) & ~3UL;
        }
        else
        {
            Param->Data = NULL;
            Param->nBytesData = 0;
        }
    }
    *pSize = Used;
    if (Options)
        HeapFree(GetProcessHeap(), 0, Options);
    return ERROR_SUCCESS;
}

/* Prefix delegation (IA_PD) is not implemented */
DWORD WINAPI
Dhcpv6RequestPrefix(LPWSTR adapterName, LPDHCPV6CAPI_CLASSID classId, LPDHCPV6PrefixLeaseInfo prefixleaseInfo,
                    DWORD *pdwTimeToWait)
{
    return ERROR_NOT_SUPPORTED;
}

DWORD WINAPI
Dhcpv6RenewPrefix(LPWSTR adapterName, LPDHCPV6CAPI_CLASSID pclassId, LPDHCPV6PrefixLeaseInfo prefixleaseInfo,
                  DWORD *pdwTimeToWait, DWORD bValidatePrefix)
{
    return ERROR_NOT_SUPPORTED;
}

DWORD WINAPI
Dhcpv6ReleasePrefix(LPWSTR adapterName, LPDHCPV6CAPI_CLASSID classId, LPDHCPV6PrefixLeaseInfo leaseInfo)
{
    return ERROR_NOT_SUPPORTED;
}
