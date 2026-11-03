/*
 * PROJECT:     ReactOS Net IO Helper DLL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     netsh "interface portproxy" context. The configuration lives where Windows keeps it:
 *              HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\<v4tov4|v4tov6|v6tov4|v6tov6>\tcp,
 *              value name "listenaddress/listenport", data "connectaddress/connectport".
 *              The iphlpsvc service watches that key and relays the connections.
 */

#define INITGUID
#include "precomp.h"

#include <guiddef.h>

#define NDEBUG
#include <debug.h>

#define PP_KEY_FMT L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\%s\\tcp"
#define MAX_ENTRY 280

DEFINE_GUID(GUID_NETIOHLP_PORTPROXY, 0x6c3a8cd2, 0x1b5e, 0x4f43, 0x9e, 0x0a, 0x2d, 0x61, 0x77, 0x91, 0x4c, 0xb5);
DEFINE_GUID(GUID_IFMON_INTERFACE_PARENT, 0x0705eca1, 0x7aac, 0x11d2, 0x89, 0xdc, 0x00, 0x60, 0x08, 0xb0, 0xe5, 0xb9);

typedef struct _PP_TYPE
{
    PCWSTR Name;
    BOOL ListenV6;
    BOOL ConnectV6;
    DWORD HdrId;
    DWORD ColsId;
    DWORD UnderId;
} PP_TYPE;

static const PP_TYPE g_Types[4] =
{
    {L"v4tov4", FALSE, FALSE, IDS_SHOW_HDR_V4TOV4, IDS_SHOW_COLS_V4, IDS_SHOW_UNDER_V4},
    {L"v4tov6", FALSE, TRUE,  IDS_SHOW_HDR_V4TOV6, IDS_SHOW_COLS_V4, IDS_SHOW_UNDER_V4},
    {L"v6tov4", TRUE,  FALSE, IDS_SHOW_HDR_V6TOV4, IDS_SHOW_COLS_V6, IDS_SHOW_UNDER_V6},
    {L"v6tov6", TRUE,  TRUE,  IDS_SHOW_HDR_V6TOV6, IDS_SHOW_COLS_V6, IDS_SHOW_UNDER_V6},
};

enum { TAG_LISTENPORT, TAG_CONNECTADDRESS, TAG_CONNECTPORT, TAG_LISTENADDRESS, TAG_PROTOCOL, TAG_COUNT };

static FN_HANDLE_CMD PpAdd4to4, PpAdd4to6, PpAdd6to4, PpAdd6to6;
static FN_HANDLE_CMD PpSet4to4, PpSet4to6, PpSet6to4, PpSet6to6;
static FN_HANDLE_CMD PpDel4to4, PpDel4to6, PpDel6to4, PpDel6to6;
static FN_HANDLE_CMD PpShowAll, PpShow4to4, PpShow4to6, PpShow6to4, PpShow6to6;
static FN_HANDLE_CMD PpReset;

static
CMD_ENTRY
PpAddCommands[] =
{
    {L"v4tov4", PpAdd4to4, IDS_HLP_ADD_V4TOV4, IDS_HLP_ADD_V4TOV4_EX, 0, NULL},
    {L"v4tov6", PpAdd4to6, IDS_HLP_ADD_V4TOV6, IDS_HLP_ADD_V4TOV6_EX, 0, NULL},
    {L"v6tov4", PpAdd6to4, IDS_HLP_ADD_V6TOV4, IDS_HLP_ADD_V6TOV4_EX, 0, NULL},
    {L"v6tov6", PpAdd6to6, IDS_HLP_ADD_V6TOV6, IDS_HLP_ADD_V6TOV6_EX, 0, NULL},
};

static
CMD_ENTRY
PpDeleteCommands[] =
{
    {L"v4tov4", PpDel4to4, IDS_HLP_DELETE_V4TOV4, IDS_HLP_DELETE_V4TOV4_EX, 0, NULL},
    {L"v4tov6", PpDel4to6, IDS_HLP_DELETE_V4TOV6, IDS_HLP_DELETE_V4TOV6_EX, 0, NULL},
    {L"v6tov4", PpDel6to4, IDS_HLP_DELETE_V6TOV4, IDS_HLP_DELETE_V6TOV4_EX, 0, NULL},
    {L"v6tov6", PpDel6to6, IDS_HLP_DELETE_V6TOV6, IDS_HLP_DELETE_V6TOV6_EX, 0, NULL},
};

static
CMD_ENTRY
PpSetCommands[] =
{
    {L"v4tov4", PpSet4to4, IDS_HLP_SET_V4TOV4, IDS_HLP_SET_V4TOV4_EX, 0, NULL},
    {L"v4tov6", PpSet4to6, IDS_HLP_SET_V4TOV6, IDS_HLP_SET_V4TOV6_EX, 0, NULL},
    {L"v6tov4", PpSet6to4, IDS_HLP_SET_V6TOV4, IDS_HLP_SET_V6TOV4_EX, 0, NULL},
    {L"v6tov6", PpSet6to6, IDS_HLP_SET_V6TOV6, IDS_HLP_SET_V6TOV6_EX, 0, NULL},
};

static
CMD_ENTRY
PpShowCommands[] =
{
    {L"all",    PpShowAll,  IDS_HLP_SHOW_ALL,    IDS_HLP_SHOW_ALL_EX,    0, NULL},
    {L"v4tov4", PpShow4to4, IDS_HLP_SHOW_V4TOV4, IDS_HLP_SHOW_V4TOV4_EX, 0, NULL},
    {L"v4tov6", PpShow4to6, IDS_HLP_SHOW_V4TOV6, IDS_HLP_SHOW_V4TOV6_EX, 0, NULL},
    {L"v6tov4", PpShow6to4, IDS_HLP_SHOW_V6TOV4, IDS_HLP_SHOW_V6TOV4_EX, 0, NULL},
    {L"v6tov6", PpShow6to6, IDS_HLP_SHOW_V6TOV6, IDS_HLP_SHOW_V6TOV6_EX, 0, NULL},
};

static
CMD_GROUP_ENTRY
PpGroups[] =
{
    {L"add",    IDS_HLP_ADD,    _countof(PpAddCommands),    0, PpAddCommands,    NULL},
    {L"delete", IDS_HLP_DELETE, _countof(PpDeleteCommands), 0, PpDeleteCommands, NULL},
    {L"show",   IDS_HLP_SHOW,   _countof(PpShowCommands),   0, PpShowCommands,   NULL},
    {L"set",    IDS_HLP_SET,    _countof(PpSetCommands),    0, PpSetCommands,    NULL},
};

static
CMD_ENTRY
PpTopCommands[] =
{
    {L"reset", PpReset, IDS_HLP_RESET, IDS_HLP_RESET_EX, 0, NULL},
};

/* ---- helpers -------------------------------------------------------------------- */

/*
 * Like Windows, netsh stores the values as typed (port numbers and service names, addresses and host
 * names); the iphlpsvc service resolves them when it starts to listen.
 */

typedef struct _PP_ARGS
{
    WCHAR ListenAddr[MAX_ENTRY];
    WCHAR ListenPort[MAX_ENTRY];
    WCHAR ConnectAddr[MAX_ENTRY];
    WCHAR ConnectPort[MAX_ENTRY];
} PP_ARGS;

static
DWORD
OpenTypeKey(DWORD t, BOOL bCreate, REGSAM sam, PHKEY phKey)
{
    WCHAR key[160];
    StringCchPrintfW(key, _countof(key), PP_KEY_FMT, g_Types[t].Name);
    if (bCreate)
        return RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, sam, NULL, phKey, NULL);
    return RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, sam, phKey);
}

/* mode: 0 add, 1 set, 2 delete */
static
DWORD
ParseArgs(DWORD t, int mode, LPWSTR *argv, DWORD idx, DWORD argc, PP_ARGS *pa)
{
    /* the tags in the order of the usage line, which is also the order of untagged arguments */
    TAG_TYPE tags[TAG_COUNT] =
    {
        {L"listenport",     NS_REQ_PRESENT, FALSE},
        {L"connectaddress", NS_REQ_ZERO, FALSE},
        {L"connectport",    NS_REQ_ZERO, FALSE},
        {L"listenaddress",  NS_REQ_ZERO, FALSE},
        {L"protocol",       NS_REQ_ZERO, FALSE},
    };
    DWORD tagType[TAG_COUNT + 8];
    DWORD dwError, i, ntags = TAG_COUNT;
    PCWSTR pszTagName;

    ZeroMemory(pa, sizeof(*pa));

    if (mode == 2)
    {
        /* delete: listenport, listenaddress, protocol */
        tags[1].pwszTag = L"listenaddress";
        tags[2].pwszTag = L"protocol";
        ntags = 3;
    }
    else if (mode == 0 || mode == 1)
    {
        /* connectaddress is only optional towards IPv6 */
        if (!g_Types[t].ListenV6 && !g_Types[t].ConnectV6)
            tags[TAG_CONNECTADDRESS].dwRequired = NS_REQ_PRESENT;
        if (g_Types[t].ListenV6 && g_Types[t].ConnectV6)
            tags[TAG_CONNECTADDRESS].dwRequired = NS_REQ_PRESENT;
    }

    if (argc - idx > ntags)
        return ERROR_INVALID_SYNTAX;

    dwError = PreprocessCommand(hDllInstance, argv, idx, argc, tags, ntags, 1, ntags, tagType);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    for (i = 0; i < argc - idx; i++)
    {
        PCWSTR v = argv[idx + i];

        if (tagType[i] == (DWORD)-1)
            return ERROR_INVALID_SYNTAX;
        pszTagName = tags[tagType[i]].pwszTag;

        if (*v == 0)
            continue;

        if (!_wcsicmp(pszTagName, L"listenport"))
            StringCchCopyW(pa->ListenPort, MAX_ENTRY, v);
        else if (!_wcsicmp(pszTagName, L"connectaddress"))
            StringCchCopyW(pa->ConnectAddr, MAX_ENTRY, v);
        else if (!_wcsicmp(pszTagName, L"connectport"))
            StringCchCopyW(pa->ConnectPort, MAX_ENTRY, v);
        else if (!_wcsicmp(pszTagName, L"listenaddress"))
            StringCchCopyW(pa->ListenAddr, MAX_ENTRY, v);
        else if (!_wcsicmp(pszTagName, L"protocol"))
        {
            if (_wcsicmp(v, L"tcp") != 0)
                return ERROR_INVALID_PARAMETER;
        }
    }

    if (!pa->ListenAddr[0])
        StringCchCopyW(pa->ListenAddr, MAX_ENTRY, L"*");
    if (mode != 2)
    {
        if (!pa->ConnectAddr[0])
            StringCchCopyW(pa->ConnectAddr, MAX_ENTRY, L"localhost");
        if (!pa->ConnectPort[0])
            StringCchCopyW(pa->ConnectPort, MAX_ENTRY, pa->ListenPort);
    }
    return ERROR_SUCCESS;
}

static
DWORD
DoAddSet(DWORD t, int mode, LPWSTR *argv, DWORD idx, DWORD argc)
{
    PP_ARGS a;
    HKEY hKey;
    WCHAR name[2 * MAX_ENTRY], data[2 * MAX_ENTRY];
    DWORD dwError;

    dwError = ParseArgs(t, mode, argv, idx, argc, &a);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    StringCchPrintfW(name, _countof(name), L"%s/%s", a.ListenAddr, a.ListenPort);
    StringCchPrintfW(data, _countof(data), L"%s/%s", a.ConnectAddr, a.ConnectPort);

    dwError = OpenTypeKey(t, TRUE, KEY_WRITE, &hKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;
    dwError = RegSetValueExW(hKey, name, 0, REG_SZ, (LPBYTE)data, (DWORD)((wcslen(data) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);
    return dwError;
}

static
DWORD
DoDelete(DWORD t, LPWSTR *argv, DWORD idx, DWORD argc)
{
    PP_ARGS a;
    HKEY hKey;
    WCHAR name[2 * MAX_ENTRY];
    DWORD dwError;

    dwError = ParseArgs(t, 2, argv, idx, argc, &a);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    StringCchPrintfW(name, _countof(name), L"%s/%s", a.ListenAddr, a.ListenPort);
    dwError = OpenTypeKey(t, FALSE, KEY_WRITE, &hKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;
    dwError = RegDeleteValueW(hKey, name);
    RegCloseKey(hKey);
    return dwError;
}

/* Reads one value; returns FALSE when there is no value i */
static
BOOL
EnumEntry(HKEY hKey, DWORD i, PWSTR name, PWSTR data)
{
    DWORD cchName = MAX_ENTRY - 1, cbData = (MAX_ENTRY - 1) * sizeof(WCHAR), type;

    if (RegEnumValueW(hKey, i, name, &cchName, NULL, &type, (LPBYTE)data, &cbData) != ERROR_SUCCESS)
        return FALSE;
    name[cchName] = 0;
    if (type != REG_SZ)
        data[0] = 0;
    else
        data[cbData / sizeof(WCHAR)] = 0;
    return TRUE;
}

static
VOID
SplitEntry(PWSTR psz, PWSTR *ppPort)
{
    PWSTR sl = wcsrchr(psz, L'/');
    if (sl)
    {
        *sl = 0;
        *ppPort = sl + 1;
    }
    else
        *ppPort = psz + wcslen(psz);
}

static
VOID
ShowType(DWORD t)
{
    HKEY hKey;
    DWORD i, count = 0;
    WCHAR name[MAX_ENTRY], data[MAX_ENTRY];
    const PP_TYPE *pt = &g_Types[t];

    if (OpenTypeKey(t, FALSE, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    for (i = 0; EnumEntry(hKey, i, name, data); i++)
    {
        PWSTR lport, cport;

        if (count++ == 0)
        {
            PrintMessage(L"\n");
            PrintMessageFromModule(hDllInstance, pt->HdrId);
            PrintMessageFromModule(hDllInstance, pt->ColsId);
            PrintMessageFromModule(hDllInstance, pt->UnderId);
        }

        SplitEntry(name, &lport);
        SplitEntry(data, &cport);
        PrintMessage(L"%-15s %-10s  %-15s %s\n", name, lport, data, cport);
    }
    RegCloseKey(hKey);
}

static
DWORD
WINAPI
PpShowAll(LPCWSTR pwszMachine, LPWSTR *argv, DWORD idx, DWORD argc, DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    DWORD t;
    for (t = 0; t < 4; t++)
        ShowType(t);
    return ERROR_SUCCESS;
}

#define ADD_SET_DEL(n, t) \
    static DWORD WINAPI PpAdd##n(LPCWSTR m, LPWSTR *argv, DWORD i, DWORD c, DWORD f, LPCVOID d, BOOL *b) { return DoAddSet(t, 0, argv, i, c); } \
    static DWORD WINAPI PpSet##n(LPCWSTR m, LPWSTR *argv, DWORD i, DWORD c, DWORD f, LPCVOID d, BOOL *b) { return DoAddSet(t, 1, argv, i, c); } \
    static DWORD WINAPI PpDel##n(LPCWSTR m, LPWSTR *argv, DWORD i, DWORD c, DWORD f, LPCVOID d, BOOL *b) { return DoDelete(t, argv, i, c); } \
    static DWORD WINAPI PpShow##n(LPCWSTR m, LPWSTR *argv, DWORD i, DWORD c, DWORD f, LPCVOID d, BOOL *b) \
    { ShowType(t); return ERROR_SUCCESS; }

ADD_SET_DEL(4to4, 0)
ADD_SET_DEL(4to6, 1)
ADD_SET_DEL(6to4, 2)
ADD_SET_DEL(6to6, 3)

static
DWORD
WINAPI
PpReset(LPCWSTR pwszMachine, LPWSTR *argv, DWORD idx, DWORD argc, DWORD dwFlags, LPCVOID pvData, BOOL *pbDone)
{
    DWORD t;
    WCHAR key[160];
    HKEY hKey;

    /* the tcp keys go, the entries with them (the service notices the change) */
    for (t = 0; t < 4; t++)
    {
        StringCchPrintfW(key, _countof(key), L"SYSTEM\\CurrentControlSet\\Services\\PortProxy\\%s", g_Types[t].Name);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_WRITE | DELETE, &hKey) != ERROR_SUCCESS)
            continue;
        RegDeleteKeyW(hKey, L"tcp");
        RegCloseKey(hKey);
    }
    return ERROR_SUCCESS;
}

static
DWORD
WINAPI
PpDumpFn(LPCWSTR pwszRouter, LPWSTR *ppwcArguments, DWORD dwArgCount, LPCVOID pvData)
{
    DWORD t, i;
    HKEY hKey;
    WCHAR name[MAX_ENTRY], data[MAX_ENTRY];

    PrintMessageFromModule(hDllInstance, IDS_DUMP_HEADER);
    PrintMessage(L"pushd interface portproxy\n\nreset\n");
    for (t = 0; t < 4; t++)
    {
        if (OpenTypeKey(t, FALSE, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;
        for (i = 0; EnumEntry(hKey, i, name, data); i++)
        {
            PWSTR lport, cport;
            SplitEntry(name, &lport);
            SplitEntry(data, &cport);
            PrintMessage(L"add %s listenport=%s connectaddress=%s connectport=%s\n",
                         g_Types[t].Name, lport, data, cport);
        }
        RegCloseKey(hKey);
    }
    PrintMessage(L"\n\npopd\n");
    PrintMessageFromModule(hDllInstance, IDS_DUMP_FOOTER);
    return ERROR_SUCCESS;
}

/* ---- registration --------------------------------------------------------------- */

static
DWORD
WINAPI
PpStart(const GUID *pguidParent, DWORD dwVersion)
{
    NS_CONTEXT_ATTRIBUTES ca;

    ZeroMemory(&ca, sizeof(ca));
    ca.dwVersion = 1;
    ca.pwszContext = L"portproxy";
    ca.guidHelper = GUID_NETIOHLP_PORTPROXY;
    ca.ulNumTopCmds = _countof(PpTopCommands);
    ca.pTopCmds = PpTopCommands;
    ca.ulNumGroups = _countof(PpGroups);
    ca.pCmdGroups = PpGroups;
    ca.pfnDumpFn = PpDumpFn;
    RegisterContext(&ca);
    return ERROR_SUCCESS;
}

DWORD
WINAPI
RegisterPortProxyHelper(VOID)
{
    NS_HELPER_ATTRIBUTES ha;
    GUID parent = GUID_IFMON_INTERFACE_PARENT;

    ZeroMemory(&ha, sizeof(ha));
    ha.dwVersion = 1;
    ha.guidHelper = GUID_NETIOHLP_PORTPROXY;
    ha.pfnStart = PpStart;
    ha.pfnStop = NULL;
    RegisterHelper(&parent, &ha);
    return ERROR_SUCCESS;
}
