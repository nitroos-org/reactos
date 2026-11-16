/*
 * PROJECT:    ReactOS IF Monitor DLL
 * LICENSE:    GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:    NetSh Helper interface context functions
 * COPYRIGHT:  Copyright 2025 Eric Kohl <eric.kohl@reactos.org>
 */

#include "precomp.h"

#include <guiddef.h>

#define NDEBUG
#include <debug.h>

#include "guid.h"
#include "resource.h"
#include "adapter.h"

static FN_HANDLE_CMD InterfaceSetInterface;
static FN_HANDLE_CMD InterfaceShowInterface;

static
CMD_ENTRY
InterfaceShowCommands[] = 
{
    {L"interface", InterfaceShowInterface, IDS_HLP_INTERFACE_SHOW_INTERFACE, IDS_HLP_INTERFACE_SHOW_INTERFACE_EX, 0}
};

static
CMD_ENTRY
InterfaceSetCommands[] =
{
    {L"interface", InterfaceSetInterface, IDS_HLP_INTERFACE_SET_INTERFACE, IDS_HLP_INTERFACE_SET_INTERFACE_EX, 0}
};

static
CMD_GROUP_ENTRY
InterfaceGroups[] = 
{
    {L"set", IDS_HLP_INTERFACE_SET, sizeof(InterfaceSetCommands) / sizeof(CMD_ENTRY), 0, InterfaceSetCommands, NULL},
    {L"show", IDS_HLP_INTERFACE_SHOW, sizeof(InterfaceShowCommands) / sizeof(CMD_ENTRY), 0, InterfaceShowCommands, NULL},
};


/* The connection with this name (case-insensitive, whole name) */
static
PIF_CONN
FindConnection(
    _In_ PIF_CONN List,
    _In_ ULONG Count,
    _In_ PCWSTR Name)
{
    ULONG i;

    for (i = 0; i < Count; i++)
    {
        if (_wcsicmp(List[i].Name, Name) == 0)
            return &List[i];
    }
    return NULL;
}

/* Matches the tags of the command line; Values[i] is the value of tag i or NULL */
static
DWORD
ParseInterfaceTags(
    _In_ LPWSTR *argv,
    _In_ DWORD dwCurrentIndex,
    _In_ DWORD dwArgCount,
    _In_ TAG_TYPE *Tags,
    _In_ DWORD TagCount,
    _Out_writes_(TagCount) PWSTR *Values)
{
    PDWORD Types;
    DWORD i, Error;

    for (i = 0; i < TagCount; i++)
        Values[i] = NULL;
    if (dwArgCount <= dwCurrentIndex)
        return ERROR_SUCCESS;

    Types = HeapAlloc(GetProcessHeap(), 0, (dwArgCount - dwCurrentIndex) * sizeof(DWORD));
    if (Types == NULL)
        return ERROR_NOT_ENOUGH_MEMORY;

    Error = MatchTagsInCmdLine(hDllInstance, argv, dwCurrentIndex, dwArgCount, Tags, TagCount, Types);
    for (i = 0; Error == ERROR_SUCCESS && i < dwArgCount - dwCurrentIndex; i++)
    {
        if (Types[i] >= TagCount)
            Error = ERROR_INVALID_SYNTAX;
        else
            Values[Types[i]] = argv[dwCurrentIndex + i];
    }
    HeapFree(GetProcessHeap(), 0, Types);
    return Error;
}

static
DWORD
WINAPI
InterfaceSetInterface(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"name", NS_REQ_ZERO, FALSE},
                       {L"admin", NS_REQ_ZERO, FALSE},
                       {L"connect", NS_REQ_ZERO, FALSE},
                       {L"newname", NS_REQ_ZERO, FALSE}};
    TOKEN_VALUE AdminValues[] = {{L"enabled", 1}, {L"disabled", 0}};
    TOKEN_VALUE ConnectValues[] = {{L"connected", 1}, {L"disconnected", 0}};
    PWSTR Values[ARRAYSIZE(Tags)];
    PIF_CONN List = NULL, Conn;
    ULONG Count = 0, Enable = 0, Connect = 0;
    BOOL HaveAdmin = FALSE;
    DWORD Error;

    Error = ParseInterfaceTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    /* a name and at least one more option */
    if (Values[0] == NULL || (Values[1] == NULL && Values[2] == NULL && Values[3] == NULL))
    {
        PrintMessageFromModule(hDllInstance, IDS_ERROR_MISSING_PARAMETERS);
        return ERROR_INVALID_SYNTAX;
    }

    if (Values[1] != NULL)
    {
        if (MatchEnumTag(hDllInstance, Values[1], ARRAYSIZE(AdminValues), AdminValues, &Enable) != ERROR_SUCCESS)
        {
            PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Values[1], L"admin");
            return ERROR_INVALID_PARAMETER;
        }
        HaveAdmin = TRUE;
    }
    if (Values[2] != NULL)
    {
        if (MatchEnumTag(hDllInstance, Values[2], ARRAYSIZE(ConnectValues), ConnectValues, &Connect) != ERROR_SUCCESS)
        {
            PrintMessageFromModule(hDllInstance, IDS_ERROR_BAD_VALUE, Values[2], L"connect");
            return ERROR_INVALID_PARAMETER;
        }
        /* connect=connected enables the interface, as the usage says; for a LAN connection nothing else
           (connect is for the others) */
        if (Connect)
        {
            Enable = 1;
            HaveAdmin = TRUE;
        }
    }

    Error = IfEnumConnections(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;

    /* Windows: "No more data is available." (ERROR_NO_MORE_ITEMS) for a name no connection has */
    Conn = FindConnection(List, Count, Values[0]);
    if (Conn == NULL)
    {
        IfFreeConnections(List);
        return ERROR_NO_MORE_ITEMS;
    }

    if (Values[3] != NULL && _wcsicmp(Values[3], Conn->Name) != 0 && FindConnection(List, Count, Values[3]) != NULL)
        Error = ERROR_ALREADY_EXISTS;

    /* The administrative state first, then the name: the device keeps its connection either way */
    if (Error == ERROR_SUCCESS && HaveAdmin)
        Error = IfSetAdminState(Conn, Enable != 0);
    if (Error == ERROR_SUCCESS && Values[3] != NULL)
        Error = IfRenameConnection(Conn, Values[3]);

    IfFreeConnections(List);
    return Error;
}


static
DWORD
WINAPI
InterfaceShowInterface(
    LPCWSTR pwszMachine,
    LPWSTR *argv,
    DWORD dwCurrentIndex,
    DWORD dwArgCount,
    DWORD dwFlags,
    LPCVOID pvData,
    BOOL *pbDone)
{
    TAG_TYPE Tags[] = {{L"name", NS_REQ_ZERO, FALSE}};
    PWSTR Values[ARRAYSIZE(Tags)];
    PIF_CONN List = NULL;
    ULONG Count = 0, i;
    DWORD Error;

    Error = ParseInterfaceTags(argv, dwCurrentIndex, dwArgCount, Tags, ARRAYSIZE(Tags), Values);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = IfEnumConnections(&List, &Count);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (Values[0] != NULL)
    {
        PIF_CONN Conn = FindConnection(List, Count, Values[0]);

        if (Conn == NULL)
        {
            IfFreeConnections(List);
            PrintMessageFromModule(hDllInstance, IDS_ERROR_NO_SUCH_INTERFACE);
            return ERROR_SUPPRESS_OUTPUT;
        }
        PrintMessageFromModule(hDllInstance, IDS_INTERFACE_SHOW_ONE,
                               Conn->Name,
                               L"Dedicated",
                               Conn->Disabled ? L"Disabled" : L"Enabled",
                               Conn->Connected ? L"Connected" : L"Disconnected");
    }
    else
    {
        PrintMessageFromModule(hDllInstance, IDS_INTERFACE_SHOW_HEADER);
        for (i = 0; i < Count; i++)
        {
            PrintMessageFromModule(hDllInstance, IDS_INTERFACE_SHOW_ROW,
                                   List[i].Disabled ? L"Disabled" : L"Enabled",
                                   List[i].Connected ? L"Connected" : L"Disconnected",
                                   L"Dedicated",
                                   List[i].Name);
        }
    }

    IfFreeConnections(List);
    return ERROR_SUCCESS;
}


static
DWORD
WINAPI
InterfaceDumpFn(
    _In_ LPCWSTR pwszRouter,
    _In_ LPWSTR *ppwcArguments,
    _In_ DWORD dwArgCount,
    _In_ LPCVOID pvData)
{
    DPRINT("InterfaceDumpFn(%S %p %lu %p)\n", pwszRouter, ppwcArguments, dwArgCount, pvData);

    PrintMessageFromModule(hDllInstance, IDS_DUMP_HEADERLINE);
    PrintMessage(L"# Interface Configuration\n");
    PrintMessageFromModule(hDllInstance, IDS_DUMP_HEADERLINE);
    PrintMessage(L"pushd interface\n");
    PrintMessageFromModule(hDllInstance, IDS_DUMP_NEWLINE);

    PrintMessageFromModule(hDllInstance, IDS_DUMP_NEWLINE);
    PrintMessage(L"popd\n");
    PrintMessage(L"# End of Interface Configuration\n");
    PrintMessageFromModule(hDllInstance, IDS_DUMP_NEWLINE);

    return ERROR_SUCCESS;
}


static
DWORD
WINAPI
InterfaceConnect(
    _In_ LPCWSTR pwszMachine)
{
    /* shown when the context is entered, as Windows does */
    PrintMessageFromModule(hDllInstance, IDS_INTERFACE_BANNER);
    return ERROR_SUCCESS;
}


DWORD
WINAPI
InterfaceStart(
    _In_ const GUID *pguidParent,
    _In_ DWORD dwVersion)
{
    NS_CONTEXT_ATTRIBUTES ContextAttributes;

    DPRINT("InterfaceStart()\n");

    ZeroMemory(&ContextAttributes, sizeof(ContextAttributes));
    ContextAttributes.dwVersion = 1;
    ContextAttributes.pwszContext = L"interface";
    ContextAttributes.guidHelper = GUID_IFMON_INTERFACE;

    ContextAttributes.ulNumTopCmds = 0;
    ContextAttributes.pTopCmds = NULL;

    ContextAttributes.ulNumGroups = sizeof(InterfaceGroups) / sizeof(CMD_GROUP_ENTRY);
    ContextAttributes.pCmdGroups = InterfaceGroups;

    ContextAttributes.pfnDumpFn = InterfaceDumpFn;
    ContextAttributes.pfnConnectFn = InterfaceConnect;

    RegisterContext(&ContextAttributes);

    return ERROR_SUCCESS;
}


DWORD
WINAPI
RegisterInterfaceHelper(VOID)
{
    NS_HELPER_ATTRIBUTES HelperAttributes;

    DPRINT("RegisterInterfaceHelper()\n");

    ZeroMemory(&HelperAttributes, sizeof(HelperAttributes));
    HelperAttributes.dwVersion = 1;
    HelperAttributes.guidHelper = GUID_IFMON_INTERFACE;
    HelperAttributes.pfnStart = InterfaceStart;
    HelperAttributes.pfnStop = NULL;
    RegisterHelper(NULL, &HelperAttributes);

    return ERROR_SUCCESS;
}
