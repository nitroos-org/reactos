/*
 * PROJECT:    NitroOS IF Monitor DLL
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    LAN connections (name, state) and their administrative state, for "interface set/show interface"
 * COPYRIGHT:  Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A LAN connection is a subkey of the network class key (Control\Network\{4D36E972-...}\{GUID}\Connection: Name, the
 * connection's friendly name, and PnpInstanceID, its device). The administrative state is the state of the device:
 * "disabled" is the PnP problem CM_PROB_DISABLED, set and cleared through DIF_PROPERTYCHANGE (what Device Manager and
 * Windows' own netsh do). A disabled adapter has no interface in the stack, so its addresses and routes go; enabling it
 * starts the adapter again and they come back through the usual configuration (DHCP, router advertisements, static).
 */

#include "precomp.h"

#include <setupapi.h>
#include <cfgmgr32.h>

#define NDEBUG
#include <debug.h>

#include "adapter.h"

#define NET_CLASS_KEY L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

static const GUID NetClassGuid =
    {0x4d36e972, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};

static
BOOL
ReadConnectionString(
    _In_ HKEY hKey,
    _In_ PCWSTR ValueName,
    _Out_writes_(Count) PWSTR Buffer,
    _In_ ULONG Count)
{
    DWORD Type, Size = (Count - 1) * sizeof(WCHAR);

    if (RegQueryValueExW(hKey, ValueName, NULL, &Type, (PBYTE)Buffer, &Size) != ERROR_SUCCESS || Type != REG_SZ)
        return FALSE;
    Buffer[Size / sizeof(WCHAR)] = UNICODE_NULL;
    return Buffer[0] != UNICODE_NULL;
}

static
BOOL
IsDeviceDisabled(
    _In_ DEVINST Dev)
{
    ULONG Status = 0, Problem = 0;

    return CM_Get_DevNode_Status(&Status, &Problem, Dev, 0) == CR_SUCCESS &&
           (Status & DN_HAS_PROBLEM) && Problem == CM_PROB_DISABLED;
}

/* The adapters the stack has an interface for, that are operationally up (by connection GUID text) */
static
VOID
MarkConnected(
    _Inout_updates_(Count) PIF_CONN List,
    _In_ ULONG Count)
{
    PIP_ADAPTER_ADDRESSES Buffer = NULL, Adapter;
    ULONG Size = 16384, Error = ERROR_BUFFER_OVERFLOW, i, Try;

    for (Try = 0; Try < 4 && Error == ERROR_BUFFER_OVERFLOW; Try++)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
        if (Buffer == NULL)
            return;
        Error = GetAdaptersAddresses(AF_UNSPEC,
                                     GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                     GAA_FLAG_SKIP_DNS_SERVER,
                                     NULL, Buffer, &Size);
        if (Error != ERROR_SUCCESS)
        {
            HeapFree(GetProcessHeap(), 0, Buffer);
            Buffer = NULL;
        }
    }
    if (Buffer == NULL)
        return;

    for (Adapter = Buffer; Adapter != NULL; Adapter = Adapter->Next)
    {
        WCHAR Guid[64];

        if (Adapter->AdapterName == NULL || Adapter->OperStatus != IfOperStatusUp)
            continue;
        if (MultiByteToWideChar(CP_ACP, 0, Adapter->AdapterName, -1, Guid, ARRAYSIZE(Guid)) == 0)
            continue;
        for (i = 0; i < Count; i++)
        {
            if (!List[i].Disabled && _wcsicmp(List[i].Guid, Guid) == 0)
                List[i].Connected = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
}

DWORD
IfEnumConnections(
    _Out_ PIF_CONN *ppList,
    _Out_ PULONG pCount)
{
    HKEY hClass;
    PIF_CONN List = NULL, New;
    ULONG Count = 0, Capacity = 0, Index;
    DWORD Error;

    *ppList = NULL;
    *pCount = 0;

    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, NET_CLASS_KEY, 0, KEY_READ, &hClass);
    if (Error != ERROR_SUCCESS)
        return ERROR_SUCCESS;       /* no network class key: no connections */

    for (Index = 0; ; Index++)
    {
        WCHAR Guid[64];
        DWORD GuidSize = ARRAYSIZE(Guid);
        HKEY hAdapter, hConn;
        IF_CONN Entry;
        DEVINST Dev;

        Error = RegEnumKeyExW(hClass, Index, Guid, &GuidSize, NULL, NULL, NULL, NULL);
        if (Error != ERROR_SUCCESS)
            break;
        if (Guid[0] != L'{')
            continue;

        if (RegOpenKeyExW(hClass, Guid, 0, KEY_READ, &hAdapter) != ERROR_SUCCESS)
            continue;
        if (RegOpenKeyExW(hAdapter, L"Connection", 0, KEY_READ, &hConn) != ERROR_SUCCESS)
        {
            RegCloseKey(hAdapter);
            continue;
        }

        ZeroMemory(&Entry, sizeof(Entry));
        StringCchCopyW(Entry.Guid, ARRAYSIZE(Entry.Guid), Guid);
        if (ReadConnectionString(hConn, L"Name", Entry.Name, ARRAYSIZE(Entry.Name)) &&
            ReadConnectionString(hConn, L"PnpInstanceID", Entry.PnpId, ARRAYSIZE(Entry.PnpId)) &&
            CM_Locate_DevNodeW(&Dev, Entry.PnpId, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
        {
            Entry.Disabled = IsDeviceDisabled(Dev);

            if (Count == Capacity)
            {
                Capacity = Capacity ? Capacity * 2 : 8;
                New = List ? HeapReAlloc(GetProcessHeap(), 0, List, Capacity * sizeof(*List))
                           : HeapAlloc(GetProcessHeap(), 0, Capacity * sizeof(*List));
                if (New == NULL)
                {
                    RegCloseKey(hConn);
                    RegCloseKey(hAdapter);
                    RegCloseKey(hClass);
                    if (List)
                        HeapFree(GetProcessHeap(), 0, List);
                    return ERROR_NOT_ENOUGH_MEMORY;
                }
                List = New;
            }
            List[Count++] = Entry;
        }

        RegCloseKey(hConn);
        RegCloseKey(hAdapter);
    }
    RegCloseKey(hClass);

    if (Count != 0)
        MarkConnected(List, Count);

    *ppList = List;
    *pCount = Count;
    return ERROR_SUCCESS;
}

VOID
IfFreeConnections(
    _In_opt_ PIF_CONN List)
{
    if (List)
        HeapFree(GetProcessHeap(), 0, List);
}

DWORD
IfSetAdminState(
    _In_ const IF_CONN *Conn,
    _In_ BOOL Enable)
{
    HDEVINFO Set;
    SP_DEVINFO_DATA Data;
    SP_PROPCHANGE_PARAMS Params;
    DWORD Error = ERROR_SUCCESS;

    /* already so: nothing to do, and no error, as on Windows */
    if (Conn->Disabled == !Enable)
        return ERROR_SUCCESS;

    Set = SetupDiCreateDeviceInfoList(&NetClassGuid, NULL);
    if (Set == INVALID_HANDLE_VALUE)
        return GetLastError();

    ZeroMemory(&Data, sizeof(Data));
    Data.cbSize = sizeof(Data);
    if (!SetupDiOpenDeviceInfoW(Set, Conn->PnpId, NULL, 0, &Data))
    {
        Error = GetLastError();
        SetupDiDestroyDeviceInfoList(Set);
        return Error;
    }

    ZeroMemory(&Params, sizeof(Params));
    Params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    Params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    Params.StateChange = Enable ? DICS_ENABLE : DICS_DISABLE;
    Params.Scope = DICS_FLAG_GLOBAL;
    Params.HwProfile = 0;

    if (!SetupDiSetClassInstallParamsW(Set, &Data, &Params.ClassInstallHeader, sizeof(Params)) ||
        !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, Set, &Data))
    {
        Error = GetLastError();
        if (Error == ERROR_SUCCESS)
            Error = ERROR_GEN_FAILURE;
    }
    SetupDiDestroyDeviceInfoList(Set);
    return Error;
}

/* The caller is a member of the Administrators group. The connection names are machine-wide, and the network
   connections folder (netshell) offers Rename to administrators only */
BOOL
IfCallerIsAdmin(VOID)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID AdminSid;
    BOOL IsMember = FALSE;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &AdminSid))
        return FALSE;
    if (!CheckTokenMembership(NULL, AdminSid, &IsMember))
        IsMember = FALSE;
    FreeSid(AdminSid);
    return IsMember;
}

DWORD
IfRenameConnection(
    _In_ const IF_CONN *Conn,
    _In_ PCWSTR NewName)
{
    WCHAR Path[160];
    HKEY hConn;
    DWORD Error;

    if (FAILED(StringCchPrintfW(Path, ARRAYSIZE(Path), NET_CLASS_KEY L"\\%s\\Connection", Conn->Guid)))
        return ERROR_BUFFER_OVERFLOW;
    Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_SET_VALUE, &hConn);
    if (Error != ERROR_SUCCESS)
        return Error;
    Error = RegSetValueExW(hConn, L"Name", 0, REG_SZ, (const BYTE *)NewName,
                           (DWORD)((wcslen(NewName) + 1) * sizeof(WCHAR)));
    RegCloseKey(hConn);
    return Error;
}
