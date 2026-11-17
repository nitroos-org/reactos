/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The protocol components of a connection (INetCfg): one TCP/IPv4 and one TCP/IPv6, and the page of
 *              TCP/IPv6 applying through the stores netsh uses. The page is driven the way a user does: its controls
 *              are filled and OK is pressed, then INetCfg::Apply makes the change
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <apitest.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wine/netioapi.h>
#include <objbase.h>
#include <commctrl.h>
#include <netcfgx.h>
#include <netcfgn.h>
#include <shlobj.h>
#include <devguid.h>

/* The control ids of the page (netcfgx resource.h) */
#define ID_AUTOADDR     1100
#define ID_STATICADDR   1101
#define ID_ADDRESS      1102
#define ID_PREFIX       1103
#define ID_GATEWAY      1104
#define ID_AUTODNS      1105
#define ID_STATICDNS    1106
#define ID_DNS1         1107
#define ID_DNS2         1108
#define ID_VALIDATE     1109
/* the component list of the connection's General page (netshell resource.h) */
#define ID_COMPONENTS   1002

#define TEST_ADDRESS    L"2001:db8:6a77::50"
#define TEST_ADDRESS2   L"2001:db8:6a77::51"       /* a second manual address, made the way netsh makes one */
#define TEST_LINKLOCAL  L"fe80::6a77:50"
#define TEST_GATEWAY    L"2001:db8:6a77::1"
#define TEST_DNS1       L"2001:db8:6a77::53"
#define TEST_DNS2       L"2001:db8:6a77::54"
#define PAGE_NAME       L"Internet Protocol Version 6 (TCP/IPv6)"
#define PAGE_TITLE      PAGE_NAME L" Properties"                    /* the caption of the sheet, as on Windows (English) */
#define NETTRANS_KEY    L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E975-E325-11CE-BFC1-08002BE10318}"

typedef DWORD (WINAPI *PFN_GET_TABLE)(USHORT, PVOID *);
typedef VOID (WINAPI *PFN_FREE_TABLE)(PVOID);
typedef DWORD (WINAPI *PFN_GUID_TO_LUID)(const GUID *, NET_LUID *);
typedef DWORD (WINAPI *PFN_LUID_TO_INDEX)(const NET_LUID *, PULONG);

static PFN_GET_TABLE pGetUnicastIpAddressTable, pGetIpForwardTable2;
static PFN_FREE_TABLE pFreeMibTable;
static PFN_GUID_TO_LUID pConvertInterfaceGuidToLuid;
static PFN_LUID_TO_INDEX pConvertInterfaceLuidToIndex;

/* ---- the context the connection UI hands to the page: it knows the adapter ---- */

typedef struct
{
    const INetLanConnectionUiInfoVtbl *lpVtbl;
    GUID Adapter;
} FAKE_UI;

static HRESULT WINAPI FakeUi_QueryInterface(INetLanConnectionUiInfo *iface, REFIID riid, void **ppv)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_INetLanConnectionUiInfo))
    {
        *ppv = iface;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI FakeUi_AddRef(INetLanConnectionUiInfo *iface)
{
    return 2;
}

static ULONG WINAPI FakeUi_Release(INetLanConnectionUiInfo *iface)
{
    return 1;
}

static HRESULT WINAPI FakeUi_GetDeviceGuid(INetLanConnectionUiInfo *iface, GUID *pGuid)
{
    *pGuid = ((FAKE_UI *)iface)->Adapter;
    return S_OK;
}

static const INetLanConnectionUiInfoVtbl FakeUiVtbl =
{
    FakeUi_QueryInterface, FakeUi_AddRef, FakeUi_Release, FakeUi_GetDeviceGuid
};

/* ---- the user: a thread that works the page while the test's thread is inside the modal property sheet ---- */

typedef enum { StepFill, StepAuto, StepRead, StepInvalid, StepLinkLocal, StepOk } STEP;

typedef struct
{
    STEP Step;
    BOOL Found;
    WCHAR Seen[6][80];      /* what the fields held when StepRead looked: address, prefix, gateway, dns1, dns2, radios */
    BOOL InvalidWasRefused;
    WCHAR Title[200];       /* the caption of the sheet */
    BOOL ValidateVisible;   /* "Validate settings upon exit" is shown */
} DRIVER;

static DRIVER Driver;

/*
 * Screenshots: with TCPIP6_TEST_SHOTS set, the test writes "SHOT:<name>" to COM2 when the screen shows something
 * worth a picture and waits for the host to take it. Nothing happens without the variable.
 */
static void Shot(const char *Name)
{
    char Line[100];
    HANDLE Port;
    DWORD Written;

    if (!GetEnvironmentVariableA("TCPIP6_TEST_SHOTS", Line, sizeof(Line)))
        return;
    Port = CreateFileA("\\\\.\\COM2", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (Port != INVALID_HANDLE_VALUE)
    {
        wsprintfA(Line, "\r\nSHOT:%s\r\n", Name);
        WriteFile(Port, Line, lstrlenA(Line), &Written, NULL);
        CloseHandle(Port);
    }
    Sleep(6000);
}

typedef struct { int Id; HWND Found; } FIND_CTL;

static BOOL CALLBACK FindControlProc(HWND hwnd, LPARAM lParam)
{
    FIND_CTL *Find = (FIND_CTL *)lParam;

    if (GetDlgCtrlID(hwnd) == Find->Id)
    {
        Find->Found = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND Control(HWND Sheet, int Id)
{
    FIND_CTL Find;

    Find.Id = Id;
    Find.Found = NULL;
    EnumChildWindows(Sheet, FindControlProc, (LPARAM)&Find);
    return Find.Found;
}

typedef struct { HWND Sheet; } FIND_WND;

static BOOL CALLBACK FindSheetProc(HWND hwnd, LPARAM lParam)
{
    WCHAR Title[100];

    GetWindowTextW(hwnd, Title, ARRAYSIZE(Title));
    if (IsWindowVisible(hwnd) && wcsstr(Title, PAGE_NAME) && wcscmp(Title, PAGE_NAME))
    {
        ((FIND_WND *)lParam)->Sheet = hwnd;
        return FALSE;
    }
    return TRUE;
}

static HWND WaitForWindow(const WCHAR *Title, int Milliseconds)
{
    int i;
    HWND hwnd;

    for (i = 0; i < Milliseconds / 100; i++)
    {
        if (Title == NULL)
        {
            FIND_WND Find = { NULL };

            EnumWindows(FindSheetProc, (LPARAM)&Find);
            if (Find.Sheet)
                return Find.Sheet;
        }
        else
        {
            hwnd = FindWindowW(L"#32770", Title);
            if (hwnd && IsWindowVisible(hwnd))
                return hwnd;
        }
        Sleep(100);
    }
    return NULL;
}

static void Press(HWND Sheet, int Id)
{
    HWND Button = Control(Sheet, Id);

    if (Button)
        SendMessageW(Button, BM_CLICK, 0, 0);
}

static void SetField(HWND Sheet, int Id, const WCHAR *Text)
{
    HWND Field = Control(Sheet, Id);

    if (Field)
        SendMessageW(Field, WM_SETTEXT, 0, (LPARAM)Text);
}

/* what is on the screen when the sheet did not go away at once (a message box of the page, say) */
static BOOL CALLBACK DumpWindowProc(HWND hwnd, LPARAM lParam)
{
    WCHAR Title[100], Text[200] = L"";
    HWND Child;

    if (!IsWindowVisible(hwnd))
        return TRUE;
    GetWindowTextW(hwnd, Title, ARRAYSIZE(Title));
    Child = FindWindowExW(hwnd, NULL, L"Static", NULL);
    if (Child)
        GetWindowTextW(Child, Text, ARRAYSIZE(Text));
    if (Title[0] || Text[0])
        trace("window \"%ls\" text \"%ls\"\n", Title, Text);
    return TRUE;
}

static DWORD WINAPI DriverThread(LPVOID Context)
{
    HWND Sheet = WaitForWindow(NULL, 30000), Box;
    int i;

    if (!Sheet)
        return 1;
    Driver.Found = TRUE;
    Sleep(300);
    GetWindowTextW(Sheet, Driver.Title, ARRAYSIZE(Driver.Title));
    Driver.ValidateVisible = Control(Sheet, ID_VALIDATE) && IsWindowVisible(Control(Sheet, ID_VALIDATE));

    switch (Driver.Step)
    {
        case StepFill:
            Press(Sheet, ID_STATICADDR);
            SetField(Sheet, ID_ADDRESS, TEST_ADDRESS);
            SetField(Sheet, ID_PREFIX, L"64");
            SetField(Sheet, ID_GATEWAY, TEST_GATEWAY);
            SetField(Sheet, ID_DNS1, TEST_DNS1);
            SetField(Sheet, ID_DNS2, TEST_DNS2);
            Shot("v6-page-filled");
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_OK, 0);
            break;

        case StepAuto:
            Press(Sheet, ID_AUTOADDR);
            Press(Sheet, ID_AUTODNS);
            Shot("v6-page-auto");
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_OK, 0);
            break;

        case StepOk:
            /* OK of the page as it opened */
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_OK, 0);
            break;

        case StepLinkLocal:
            Press(Sheet, ID_STATICADDR);
            SetField(Sheet, ID_ADDRESS, TEST_LINKLOCAL);
            SetField(Sheet, ID_PREFIX, L"64");
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_OK, 0);
            Box = WaitForWindow(PAGE_NAME, 5000);
            if (Box)
            {
                Shot("v6-page-linklocal-refused");
                Driver.InvalidWasRefused = TRUE;
                PostMessageW(Box, WM_COMMAND, IDOK, 0);
                Sleep(300);
            }
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_CANCEL, 0);
            break;

        case StepRead:
        {
            static const int Ids[5] = { ID_ADDRESS, ID_PREFIX, ID_GATEWAY, ID_DNS1, ID_DNS2 };

            for (i = 0; i < 5; i++)
                GetWindowTextW(Control(Sheet, Ids[i]), Driver.Seen[i], 80);
            wsprintfW(Driver.Seen[5], L"%d%d%d%d",
                      (int)SendMessageW(Control(Sheet, ID_AUTOADDR), BM_GETCHECK, 0, 0) == BST_CHECKED,
                      (int)SendMessageW(Control(Sheet, ID_STATICADDR), BM_GETCHECK, 0, 0) == BST_CHECKED,
                      (int)SendMessageW(Control(Sheet, ID_AUTODNS), BM_GETCHECK, 0, 0) == BST_CHECKED,
                      (int)SendMessageW(Control(Sheet, ID_STATICDNS), BM_GETCHECK, 0, 0) == BST_CHECKED);
            Shot("v6-page-read");
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_CANCEL, 0);
            break;
        }

        case StepInvalid:
            Press(Sheet, ID_STATICADDR);
            SetField(Sheet, ID_ADDRESS, L"2001:db8::zz");
            SetField(Sheet, ID_PREFIX, L"64");
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_OK, 0);
            /* the page refuses with a message box that names the address */
            Box = WaitForWindow(PAGE_NAME, 5000);
            if (Box)
            {
                Shot("v6-page-invalid-refused");
                Driver.InvalidWasRefused = TRUE;
                PostMessageW(Box, WM_COMMAND, IDOK, 0);
                Sleep(300);
            }
            PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_CANCEL, 0);
            break;
    }

    /* the sheet is modal and the test's thread is in it: a sheet that is still there is cancelled */
    for (i = 0; i < 150 && IsWindow(Sheet); i++)
    {
        if (i == 10)
            EnumWindows(DumpWindowProc, 0);
        Sleep(100);
    }
    if (IsWindow(Sheet))
        PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_CANCEL, 0);
    return 0;
}

/* ---- the connection: INetCfg ---- */

typedef struct
{
    INetCfg *Cfg;
    INetCfgLock *Lock;
    INetCfgComponent *Tcpip6;
    WCHAR AdapterGuid[64];
    ULONG IfIndex;
} CONNECTION;

static BOOL OpenNetCfg(CONNECTION *C)
{
    HRESULT hr;
    LPWSTR Holder = NULL;

    memset(C, 0, sizeof(*C));
    hr = CoCreateInstance(&CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, &IID_INetCfg, (void **)&C->Cfg);
    if (FAILED(hr))
        return FALSE;
    hr = INetCfg_QueryInterface(C->Cfg, &IID_INetCfgLock, (void **)&C->Lock);
    if (SUCCEEDED(hr))
        INetCfgLock_AcquireWriteLock(C->Lock, 100, L"apitest", &Holder);
    if (Holder)
        CoTaskMemFree(Holder);
    hr = INetCfg_Initialize(C->Cfg, NULL);
    if (FAILED(hr))
    {
        skip("INetCfg::Initialize failed: 0x%08lx\n", hr);
        return FALSE;
    }
    return TRUE;
}

static void CloseNetCfg(CONNECTION *C)
{
    if (C->Tcpip6)
        INetCfgComponent_Release(C->Tcpip6);
    if (C->Cfg)
        INetCfg_Uninitialize(C->Cfg);
    if (C->Lock)
    {
        INetCfgLock_ReleaseWriteLock(C->Lock);
        INetCfgLock_Release(C->Lock);
    }
    if (C->Cfg)
        INetCfg_Release(C->Cfg);
}

static void TestInstances(CONNECTION *C)
{
    IEnumNetCfgComponent *Enum;
    INetCfgComponent *Comp;
    ULONG Fetched;
    int Tcpip = 0, Tcpip6 = 0;
    HKEY hClass;
    DWORD Index;
    int RegTcpip = 0, RegTcpip6 = 0;
    WCHAR Name[80], Id[80];
    HRESULT hr;

    hr = INetCfg_EnumComponents(C->Cfg, &GUID_DEVCLASS_NETTRANS, &Enum);
    ok(hr == S_OK, "EnumComponents(NetTrans) returned 0x%08lx\n", hr);
    if (hr != S_OK)
        return;

    while (IEnumNetCfgComponent_Next(Enum, 1, &Comp, &Fetched) == S_OK)
    {
        LPWSTR ComponentId = NULL;

        if (INetCfgComponent_GetId(Comp, &ComponentId) == S_OK && ComponentId)
        {
            if (!_wcsicmp(ComponentId, L"MS_TCPIP"))
                Tcpip++;
            else if (!_wcsicmp(ComponentId, L"MS_TCPIP6"))
                Tcpip6++;
            CoTaskMemFree(ComponentId);
        }
        INetCfgComponent_Release(Comp);
    }
    IEnumNetCfgComponent_Release(Enum);
    ok(Tcpip == 1, "INetCfg lists MS_TCPIP %d times\n", Tcpip);
    ok(Tcpip6 == 1, "INetCfg lists MS_TCPIP6 %d times\n", Tcpip6);

    /* the registry has the one instance too (INetCfg shows an older duplicate once) */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NETTRANS_KEY, 0, KEY_READ, &hClass) == ERROR_SUCCESS)
    {
        for (Index = 0; ; Index++)
        {
            HKEY hInstance;
            DWORD Size = ARRAYSIZE(Name), IdSize = sizeof(Id) - sizeof(WCHAR), Type;

            if (RegEnumKeyExW(hClass, Index, Name, &Size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                break;
            if (RegOpenKeyExW(hClass, Name, 0, KEY_READ, &hInstance) != ERROR_SUCCESS)
                continue;
            memset(Id, 0, sizeof(Id));
            if (RegQueryValueExW(hInstance, L"ComponentId", NULL, &Type, (LPBYTE)Id, &IdSize) == ERROR_SUCCESS)
            {
                if (!_wcsicmp(Id, L"MS_TCPIP"))
                    RegTcpip++;
                else if (!_wcsicmp(Id, L"MS_TCPIP6"))
                    RegTcpip6++;
            }
            RegCloseKey(hInstance);
        }
        RegCloseKey(hClass);
        ok(RegTcpip == 1, "the registry has %d instances of MS_TCPIP\n", RegTcpip);
        ok(RegTcpip6 == 1, "the registry has %d instances of MS_TCPIP6\n", RegTcpip6);
    }

    hr = INetCfg_FindComponent(C->Cfg, L"MS_TCPIP6", &C->Tcpip6);
    ok(hr == S_OK && C->Tcpip6, "FindComponent(MS_TCPIP6) returned 0x%08lx\n", hr);
}

static void TestTexts(CONNECTION *C)
{
    LPWSTR Name = NULL, Help = NULL;

    if (!C->Tcpip6)
        return;
    if (PRIMARYLANGID(GetUserDefaultUILanguage()) != LANG_ENGLISH)
    {
        skip("the texts are checked in English\n");
        return;
    }
    ok(INetCfgComponent_GetDisplayName(C->Tcpip6, &Name) == S_OK && Name &&
       !wcscmp(Name, L"Internet Protocol Version 6 (TCP/IPv6)"), "display name %ls\n", Name ? Name : L"(none)");
    ok(INetCfgComponent_GetHelpText(C->Tcpip6, &Help) == S_OK && Help &&
       !wcscmp(Help, L"TCP/IP version 6. The latest version of the internet protocol that provides communication "
                     L"across diverse interconnected networks."), "help text %ls\n", Help ? Help : L"(none)");
    CoTaskMemFree(Name);
    CoTaskMemFree(Help);
}

/* The adapter the page is tried on: the first connection that has an IPv6 interface */
static BOOL StackProtocols(const GUID *Adapter, int *Ipv4, int *Ipv6);

static BOOL FindAdapter(CONNECTION *C, FAKE_UI *Ui)
{
    IEnumNetCfgComponent *Enum;
    INetCfgComponent *Comp;
    ULONG Fetched;
    BOOL Found = FALSE;
    int Stack4, Stack6;

    if (FAILED(INetCfg_EnumComponents(C->Cfg, &GUID_DEVCLASS_NET, &Enum)))
        return FALSE;
    while (!Found && IEnumNetCfgComponent_Next(Enum, 1, &Comp, &Fetched) == S_OK)
    {
        LPWSTR BindName = NULL;
        NET_LUID Luid;
        ULONG Index = 0;
        GUID Guid;

        if (INetCfgComponent_GetBindName(Comp, &BindName) == S_OK && BindName &&
            CLSIDFromString(BindName, &Guid) == S_OK && wcslen(BindName) < ARRAYSIZE(C->AdapterGuid) &&
            pConvertInterfaceGuidToLuid(&Guid, &Luid) == NO_ERROR &&
            pConvertInterfaceLuidToIndex(&Luid, &Index) == NO_ERROR && Index != 0 &&
            StackProtocols(&Guid, &Stack4, &Stack6) && Stack6)
        {
            wcscpy(C->AdapterGuid, BindName);
            C->IfIndex = Index;
            Ui->Adapter = Guid;
            Found = TRUE;
        }
        CoTaskMemFree(BindName);
        INetCfgComponent_Release(Comp);
    }
    IEnumNetCfgComponent_Release(Enum);
    return Found;
}

/* The page of TCP/IPv6, with the thread that works it; then INetCfg::Apply */
static void RunPage(CONNECTION *C, FAKE_UI *Ui, STEP Step, BOOL Apply)
{
    HANDLE Thread;
    HRESULT hr;

    memset(&Driver, 0, sizeof(Driver));
    Driver.Step = Step;
    Thread = CreateThread(NULL, 0, DriverThread, NULL, 0, NULL);

    hr = INetCfgComponent_RaisePropertyUi(C->Tcpip6, NULL, NCRP_QUERY_PROPERTY_UI, (IUnknown *)Ui);
    ok(hr == S_OK, "RaisePropertyUi(query) returned 0x%08lx\n", hr);
    hr = INetCfgComponent_RaisePropertyUi(C->Tcpip6, NULL, NCRP_SHOW_PROPERTY_UI, (IUnknown *)Ui);
    trace("RaisePropertyUi(show) returned 0x%08lx\n", hr);

    WaitForSingleObject(Thread, 20000);
    CloseHandle(Thread);
    ok(Driver.Found, "the page did not appear\n");

    if (Apply)
    {
        hr = INetCfg_Apply(C->Cfg);
        ok(hr == S_OK, "INetCfg::Apply returned 0x%08lx\n", hr);
    }
}

static BOOL AddressIs(const SOCKADDR_INET *Address, const WCHAR *Text)
{
    typedef LONG (NTAPI *PFN_PARSE)(PCWSTR, PCWSTR *, PVOID);
    PFN_PARSE pParse = (PFN_PARSE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlIpv6StringToAddressW");
    PCWSTR End;
    IN6_ADDR Parsed;

    return pParse && pParse(Text, &End, &Parsed) == 0 && Address->si_family == AF_INET6 &&
           !memcmp(&Address->Ipv6.sin6_addr, &Parsed, sizeof(Parsed));
}

/* The manual address of the interface in GetUnicastIpAddressTable: its prefix length, or 0 */
static ULONG ManualAddressPrefix(ULONG IfIndex, const WCHAR *Text)
{
    PMIB_UNICASTIPADDRESS_TABLE Table = NULL;
    ULONG i, Length = 0;

    if (pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return 0;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const MIB_UNICASTIPADDRESS_ROW *Row = &Table->Table[i];

        if (Row->InterfaceIndex == IfIndex && AddressIs(&Row->Address, Text) &&
            Row->PrefixOrigin == IpPrefixOriginManual && Row->SuffixOrigin == IpSuffixOriginManual)
            Length = Row->OnLinkPrefixLength;
    }
    pFreeMibTable(Table);
    return Length;
}

static BOOL HasDefaultRoute(ULONG IfIndex, const WCHAR *Gateway)
{
    PMIB_IPFORWARD_TABLE2 Table = NULL;
    ULONG i;
    BOOL Found = FALSE;

    if (pGetIpForwardTable2(AF_INET6, (PVOID *)&Table) != NO_ERROR || !Table)
        return FALSE;
    for (i = 0; i < Table->NumEntries; i++)
    {
        const MIB_IPFORWARD_ROW2 *Row = &Table->Table[i];

        if (Row->InterfaceIndex == IfIndex && Row->DestinationPrefix.PrefixLength == 0 &&
            AddressIs(&Row->NextHop, Gateway))
            Found = TRUE;
    }
    pFreeMibTable(Table);
    return Found;
}

static BOOL ReadNameServer(const WCHAR *Adapter, WCHAR *Value, DWORD Count)
{
    WCHAR Path[200];
    HKEY hKey;
    DWORD Size = (Count - 1) * sizeof(WCHAR), Type;
    BOOL Have = FALSE;

    wcscpy(Path, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\");
    wcscat(Path, Adapter);
    memset(Value, 0, Count * sizeof(WCHAR));
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        Have = RegQueryValueExW(hKey, L"NameServer", NULL, &Type, (LPBYTE)Value, &Size) == ERROR_SUCCESS &&
               Type == REG_SZ && Value[0] != UNICODE_NULL;
        RegCloseKey(hKey);
    }
    return Have;
}

static void RemoveTestConfiguration(CONNECTION *C)
{
    /* the page's own way: automatic again, the DNS servers removed */
    WCHAR Path[200];
    HKEY hKey;
    PMIB_UNICASTIPADDRESS_TABLE Table = NULL;
    ULONG i;
    typedef DWORD (WINAPI *PFN_CONFIGURE_ADDRESS)(ULONG, BOOL, const MIB_UNICASTIPADDRESS_ROW *);
    PFN_CONFIGURE_ADDRESS pConfigure = (PFN_CONFIGURE_ADDRESS)GetProcAddress(GetModuleHandleW(L"iphlpapi.dll"),
                                                                             "NitroConfigureIpv6Address");

    if (pConfigure && pGetUnicastIpAddressTable(AF_INET6, (PVOID *)&Table) == NO_ERROR && Table)
    {
        for (i = 0; i < Table->NumEntries; i++)
        {
            if (Table->Table[i].InterfaceIndex == C->IfIndex &&
                (AddressIs(&Table->Table[i].Address, TEST_ADDRESS) || AddressIs(&Table->Table[i].Address, TEST_ADDRESS2)))
                pConfigure(3 /* NITRO_IPV6_DELETE */, TRUE, &Table->Table[i]);
        }
        pFreeMibTable(Table);
    }
    wcscpy(Path, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\");
    wcscat(Path, C->AdapterGuid);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS)
    {
        RegDeleteValueW(hKey, L"NameServer");
        RegCloseKey(hKey);
    }
}

/* A second manual address on the interface, persistent, the way netsh interface ipv6 add address makes it */
static DWORD AddNetshAddress(CONNECTION *C, const WCHAR *Text)
{
    typedef LONG (NTAPI *PFN_PARSE)(PCWSTR, PCWSTR *, PVOID);
    typedef VOID (WINAPI *PFN_INIT_ROW)(PMIB_UNICASTIPADDRESS_ROW);
    typedef DWORD (WINAPI *PFN_CONFIGURE_ADDRESS)(ULONG, BOOL, const MIB_UNICASTIPADDRESS_ROW *);
    HMODULE Iphlpapi = GetModuleHandleW(L"iphlpapi.dll");
    PFN_PARSE pParse = (PFN_PARSE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlIpv6StringToAddressW");
    PFN_INIT_ROW pInit = (PFN_INIT_ROW)GetProcAddress(Iphlpapi, "InitializeUnicastIpAddressEntry");
    PFN_CONFIGURE_ADDRESS pConfigure = (PFN_CONFIGURE_ADDRESS)GetProcAddress(Iphlpapi, "NitroConfigureIpv6Address");
    MIB_UNICASTIPADDRESS_ROW Row;
    PCWSTR End;

    if (!pParse || !pInit || !pConfigure)
        return ERROR_PROC_NOT_FOUND;
    pInit(&Row);
    Row.Address.si_family = AF_INET6;
    if (pParse(Text, &End, &Row.Address.Ipv6.sin6_addr) != 0)
        return ERROR_INVALID_PARAMETER;
    Row.InterfaceIndex = C->IfIndex;
    Row.OnLinkPrefixLength = 64;
    Row.ValidLifetime = Row.PreferredLifetime = 0xffffffff;
    Row.PrefixOrigin = IpPrefixOriginManual;
    Row.SuffixOrigin = IpSuffixOriginManual;
    return pConfigure(1 /* NITRO_IPV6_CREATE */, TRUE, &Row);
}

static void TestPage(CONNECTION *C)
{
    FAKE_UI Ui;
    WCHAR Servers[200];
    DWORD Error;
    HRESULT hr;

    if (!C->Tcpip6)
        return;
    Ui.lpVtbl = &FakeUiVtbl;
    if (!FindAdapter(C, &Ui))
    {
        skip("no connection with an IPv6 interface\n");
        return;
    }
    if (!pGetUnicastIpAddressTable || !pGetIpForwardTable2 || !pFreeMibTable)
    {
        skip("the table functions are not exported\n");
        return;
    }
    RemoveTestConfiguration(C);

    /* a page that refuses what was typed changes nothing */
    RunPage(C, &Ui, StepInvalid, TRUE);
    ok(Driver.InvalidWasRefused, "the page took an invalid address\n");
    ok(ManualAddressPrefix(C->IfIndex, TEST_ADDRESS) == 0, "an address was configured by the refused page\n");
    /* the sheet is "<component> Properties" (English), and has no "Validate settings upon exit" box that does nothing */
    if (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_ENGLISH)
        ok(!wcscmp(Driver.Title, PAGE_TITLE), "sheet title \"%ls\"\n", Driver.Title);
    ok(!Driver.ValidateVisible, "\"Validate settings upon exit\" is shown\n");

    /* the link-local address is the stack's: the page does not make a manual one */
    RunPage(C, &Ui, StepLinkLocal, TRUE);
    ok(Driver.InvalidWasRefused, "the page took a link-local address\n");
    ok(ManualAddressPrefix(C->IfIndex, TEST_LINKLOCAL) == 0, "a manual link-local address was configured\n");

    /* a manual address, gateway and DNS servers: made by INetCfg::Apply, not by OK of the page; the page opened again
       before Apply shows what OK took */
    RunPage(C, &Ui, StepFill, FALSE);
    ok(ManualAddressPrefix(C->IfIndex, TEST_ADDRESS) == 0, "OK of the page configured the address before INetCfg::Apply\n");
    RunPage(C, &Ui, StepRead, FALSE);
    ok(!wcscmp(Driver.Seen[0], TEST_ADDRESS), "the page opened again before Apply shows address \"%ls\"\n", Driver.Seen[0]);
    ok(!wcscmp(Driver.Seen[5], L"0101"), "the page opened again before Apply shows radio buttons %ls\n", Driver.Seen[5]);
    hr = INetCfg_Apply(C->Cfg);
    ok(hr == S_OK, "INetCfg::Apply returned 0x%08lx\n", hr);
    ok(ManualAddressPrefix(C->IfIndex, TEST_ADDRESS) == 64,
       "GetUnicastIpAddressTable: manual address with prefix length %lu, expected 64\n",
       ManualAddressPrefix(C->IfIndex, TEST_ADDRESS));
    ok(HasDefaultRoute(C->IfIndex, TEST_GATEWAY), "the default route through the gateway is not in the table\n");
    ok(ReadNameServer(C->AdapterGuid, Servers, ARRAYSIZE(Servers)) &&
       !wcscmp(Servers, TEST_DNS1 L"," TEST_DNS2), "NameServer is \"%ls\"\n", Servers);

    /* the page shows what is configured */
    RunPage(C, &Ui, StepRead, FALSE);
    ok(!wcscmp(Driver.Seen[0], TEST_ADDRESS), "address field \"%ls\"\n", Driver.Seen[0]);
    ok(!wcscmp(Driver.Seen[1], L"64"), "prefix field \"%ls\"\n", Driver.Seen[1]);
    ok(!wcscmp(Driver.Seen[2], TEST_GATEWAY), "gateway field \"%ls\"\n", Driver.Seen[2]);
    ok(!wcscmp(Driver.Seen[3], TEST_DNS1), "preferred DNS field \"%ls\"\n", Driver.Seen[3]);
    ok(!wcscmp(Driver.Seen[4], TEST_DNS2), "alternate DNS field \"%ls\"\n", Driver.Seen[4]);
    ok(!wcscmp(Driver.Seen[5], L"0101"), "radio buttons %ls (auto/static address, auto/static DNS)\n", Driver.Seen[5]);

    /* OK of the page as it opened changes nothing: a second manual address netsh made (the page shows one) stays.
       Both addresses are made here, whatever the steps above left */
    if (ManualAddressPrefix(C->IfIndex, TEST_ADDRESS) == 0)
        AddNetshAddress(C, TEST_ADDRESS);
    Error = AddNetshAddress(C, TEST_ADDRESS2);
    ok(Error == NO_ERROR, "the second manual address could not be made: %lu\n", Error);
    if (Error == NO_ERROR)
    {
        RunPage(C, &Ui, StepOk, TRUE);
        ok(ManualAddressPrefix(C->IfIndex, TEST_ADDRESS2) == 64, "OK of an unchanged page removed the second manual address\n");
        ok(ManualAddressPrefix(C->IfIndex, TEST_ADDRESS) == 64, "OK of an unchanged page removed the manual address\n");
    }

    /* automatic again: the addresses, route and servers are gone */
    RunPage(C, &Ui, StepAuto, TRUE);
    ok(ManualAddressPrefix(C->IfIndex, TEST_ADDRESS) == 0, "the manual address is still configured\n");
    ok(ManualAddressPrefix(C->IfIndex, TEST_ADDRESS2) == 0, "the second manual address is still configured\n");
    ok(!HasDefaultRoute(C->IfIndex, TEST_GATEWAY), "the default route is still in the table\n");
    ok(!ReadNameServer(C->AdapterGuid, Servers, ARRAYSIZE(Servers)), "NameServer is still \"%ls\"\n", Servers);

    RunPage(C, &Ui, StepRead, FALSE);
    ok(!wcscmp(Driver.Seen[5], L"1010"), "radio buttons after automatic %ls\n", Driver.Seen[5]);
    ok(Driver.Seen[0][0] == UNICODE_NULL, "address field \"%ls\" after automatic\n", Driver.Seen[0]);

    RemoveTestConfiguration(C);
}

/* ---- the connection's own sheet (netshell): the TCP/IPv4 and TCP/IPv6 boxes show the stack and cannot be changed ---- */

typedef struct
{
    BOOL Found;
    int Ipv4, Ipv6;             /* the boxes as the sheet opened: 1 checked, 0 not, -1 no such row */
    int Ipv4After, Ipv6After;   /* after the user's attempt to change them */
    WCHAR Title[200];
} LAN_DRIVER;

static LAN_DRIVER LanDriver;

static int FindRow(HWND List, const WCHAR *Name)
{
    int i, Count = (int)SendMessageW(List, LVM_GETITEMCOUNT, 0, 0);
    WCHAR Text[200];
    LVITEMW Item;

    for (i = 0; i < Count; i++)
    {
        memset(&Item, 0, sizeof(Item));
        Item.iSubItem = 0;
        Item.pszText = Text;
        Item.cchTextMax = ARRAYSIZE(Text);
        Text[0] = UNICODE_NULL;
        SendMessageW(List, LVM_GETITEMTEXTW, i, (LPARAM)&Item);
        if (!wcscmp(Text, Name))
            return i;
    }
    return -1;
}

static int BoxState(HWND List, int Row)
{
    if (Row < 0)
        return -1;
    return (((UINT)SendMessageW(List, LVM_GETITEMSTATE, Row, LVIS_STATEIMAGEMASK) >> 12) - 1) == 1;
}

/* What a click on the box does to the list: the state image of the row flips (the list asks its page first) */
static void FlipBox(HWND List, int Row)
{
    LVITEMW Item;

    if (Row < 0)
        return;
    memset(&Item, 0, sizeof(Item));
    Item.stateMask = LVIS_STATEIMAGEMASK;
    Item.state = INDEXTOSTATEIMAGEMASK(BoxState(List, Row) ? 1 : 2);
    SendMessageW(List, LVM_SETITEMSTATE, Row, (LPARAM)&Item);
}

/* The connection's sheet: the visible top-level window that has the component list */
static BOOL CALLBACK FindLanSheetProc(HWND hwnd, LPARAM lParam)
{
    HWND List;
    WCHAR Class[40];

    if (!IsWindowVisible(hwnd))
        return TRUE;
    List = Control(hwnd, ID_COMPONENTS);
    if (List && GetClassNameW(List, Class, ARRAYSIZE(Class)) && !_wcsicmp(Class, WC_LISTVIEWW))
    {
        *(HWND *)lParam = hwnd;
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI LanDriverThread(LPVOID Context)
{
    HWND Sheet = NULL, List;
    int Row4, Row6, i;

    for (i = 0; i < 300 && !Sheet; i++)
    {
        EnumWindows(FindLanSheetProc, (LPARAM)&Sheet);
        if (!Sheet)
            Sleep(100);
    }
    if (!Sheet)
        return 1;
    GetWindowTextW(Sheet, LanDriver.Title, ARRAYSIZE(LanDriver.Title));
    Sleep(1000);
    List = Control(Sheet, ID_COMPONENTS);
    if (List)
    {
        LanDriver.Found = TRUE;
        Row4 = FindRow(List, L"Internet Protocol Version 4 (TCP/IPv4)");
        Row6 = FindRow(List, L"Internet Protocol Version 6 (TCP/IPv6)");
        LanDriver.Ipv4 = BoxState(List, Row4);
        LanDriver.Ipv6 = BoxState(List, Row6);
        if (Row6 >= 0)
            SendMessageW(List, LVM_ENSUREVISIBLE, Row6, FALSE);
        Shot("lan-sheet-before");
        FlipBox(List, Row6);
        FlipBox(List, Row4);
        LanDriver.Ipv4After = BoxState(List, Row4);
        LanDriver.Ipv6After = BoxState(List, Row6);
        Shot("lan-sheet-after-click");
    }
    /* OK: what the sheet applies (nothing, for these two) */
    PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_OK, 0);
    for (i = 0; i < 150 && IsWindow(Sheet); i++)
        Sleep(100);
    if (IsWindow(Sheet))
        PostMessageW(Sheet, PSM_PRESSBUTTON, PSBTN_CANCEL, 0);
    return 0;
}

/* The stack's view of the adapter: an interface (TCP/IPv4 bound) and IPv6 on it */
static BOOL StackProtocols(const GUID *Adapter, int *Ipv4, int *Ipv6)
{
    typedef ULONG (WINAPI *PFN_GAA)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
    PFN_GAA pGetAdaptersAddresses = (PFN_GAA)GetProcAddress(GetModuleHandleW(L"iphlpapi.dll"), "GetAdaptersAddresses");
    PIP_ADAPTER_ADDRESSES List, Entry;
    ULONG Size = 64 * 1024;
    WCHAR GuidW[40];
    char Guid[40];
    BOOL Found = FALSE;

    *Ipv4 = *Ipv6 = 0;
    if (!pGetAdaptersAddresses || !StringFromGUID2(Adapter, GuidW, ARRAYSIZE(GuidW)))
        return FALSE;
    WideCharToMultiByte(CP_ACP, 0, GuidW, -1, Guid, sizeof(Guid), NULL, NULL);
    List = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!List)
        return FALSE;
    if (pGetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                              NULL, List, &Size) == NO_ERROR)
    {
        for (Entry = List; Entry; Entry = Entry->Next)
        {
            if (Entry->AdapterName && !lstrcmpiA(Entry->AdapterName, Guid))
            {
                *Ipv4 = 1;
                *Ipv6 = (Entry->Flags & IP_ADAPTER_IPV6_ENABLED) ? 1 : 0;
                Found = TRUE;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, List);
    return Found;
}

static BOOL ReadLinkage(const WCHAR *Service, BYTE *Data, DWORD *Size)
{
    WCHAR Path[200];
    HKEY hKey;
    LONG Error;

    wsprintfW(Path, L"SYSTEM\\CurrentControlSet\\Services\\%s\\Linkage", Service);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, Path, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    Error = RegQueryValueExW(hKey, L"Bind", NULL, NULL, Data, Size);
    RegCloseKey(hKey);
    return Error == ERROR_SUCCESS;
}

/*
 * The sheet a user opens: Network Connections, the connection, Properties (the folder's "properties" verb, which shows
 * the sheet modally in this thread). Adapter: the connection's adapter (the machine has one).
 */
static void TestConnectionSheet(const GUID *Adapter)
{
    IShellFolder *Desktop = NULL, *Folder = NULL;
    IEnumIDList *Items = NULL;
    IContextMenu *Menu = NULL;
    LPITEMIDLIST FolderPidl = NULL, Item = NULL;
    CMINVOKECOMMANDINFO Invoke;
    HANDLE Thread;
    ULONG Fetched;
    BYTE Bind4[4096], Bind6[4096], Bind4After[4096], Bind6After[4096];
    DWORD Size4 = sizeof(Bind4), Size6 = sizeof(Bind6), Size4After = sizeof(Bind4After), Size6After = sizeof(Bind6After);
    BOOL Have4, Have6;
    int Stack4, Stack6;
    HRESULT hr;

    if (PRIMARYLANGID(GetUserDefaultUILanguage()) != LANG_ENGLISH)
    {
        skip("the rows of the connection sheet are found by their English names\n");
        return;
    }
    hr = SHGetSpecialFolderLocation(NULL, CSIDL_CONNECTIONS, &FolderPidl);
    ok(hr == S_OK, "SHGetSpecialFolderLocation(CSIDL_CONNECTIONS) returned 0x%08lx\n", hr);
    if (SUCCEEDED(hr))
        hr = SHGetDesktopFolder(&Desktop);
    if (SUCCEEDED(hr))
        hr = IShellFolder_BindToObject(Desktop, FolderPidl, NULL, &IID_IShellFolder, (void **)&Folder);
    if (SUCCEEDED(hr))
        hr = IShellFolder_EnumObjects(Folder, NULL, SHCONTF_NONFOLDERS, &Items);
    if (SUCCEEDED(hr) && Items && IEnumIDList_Next(Items, 1, &Item, &Fetched) == S_OK)
        hr = IShellFolder_GetUIObjectOf(Folder, NULL, 1, (LPCITEMIDLIST *)&Item, &IID_IContextMenu, NULL, (void **)&Menu);
    else
        hr = E_FAIL;
    ok(hr == S_OK && Menu, "no connection in the Network Connections folder: 0x%08lx\n", hr);

    if (Menu)
    {
        Have4 = ReadLinkage(L"Tcpip", Bind4, &Size4);
        Have6 = ReadLinkage(L"Tcpip6", Bind6, &Size6);

        memset(&LanDriver, 0, sizeof(LanDriver));
        Thread = CreateThread(NULL, 0, LanDriverThread, NULL, 0, NULL);
        memset(&Invoke, 0, sizeof(Invoke));
        Invoke.cbSize = sizeof(Invoke);
        Invoke.lpVerb = "properties";
        Invoke.nShow = SW_SHOWNORMAL;
        hr = IContextMenu_InvokeCommand(Menu, &Invoke);
        trace("InvokeCommand(properties) returned 0x%08lx\n", hr);
        WaitForSingleObject(Thread, 60000);
        CloseHandle(Thread);
        trace("the sheet: \"%ls\"\n", LanDriver.Title);

        ok(LanDriver.Found, "the component list of the connection sheet was not found\n");
        if (LanDriver.Found)
        {
            ok(LanDriver.Ipv4 >= 0, "no TCP/IPv4 row\n");
            ok(LanDriver.Ipv6 >= 0, "no TCP/IPv6 row\n");
            if (Adapter && StackProtocols(Adapter, &Stack4, &Stack6))
            {
                ok(LanDriver.Ipv4 == Stack4, "TCP/IPv4 box %d, the stack %d\n", LanDriver.Ipv4, Stack4);
                ok(LanDriver.Ipv6 == Stack6, "TCP/IPv6 box %d, the stack %d (IP_ADAPTER_IPV6_ENABLED)\n", LanDriver.Ipv6, Stack6);
                trace("the stack: TCP/IPv4 %d, TCP/IPv6 %d on the connection\n", Stack4, Stack6);
            }
            else
            {
                skip("the stack has no interface for the connection\n");
            }
            ok(LanDriver.Ipv4After == LanDriver.Ipv4, "the TCP/IPv4 box changed from %d to %d\n", LanDriver.Ipv4, LanDriver.Ipv4After);
            ok(LanDriver.Ipv6After == LanDriver.Ipv6, "the TCP/IPv6 box changed from %d to %d\n", LanDriver.Ipv6, LanDriver.Ipv6After);
        }

        /* OK of the sheet wrote no binding of the two */
        ok(ReadLinkage(L"Tcpip", Bind4After, &Size4After) == Have4 && (!Have4 || (Size4After == Size4 && !memcmp(Bind4, Bind4After, Size4))),
           "Tcpip\\Linkage\\Bind changed\n");
        ok(ReadLinkage(L"Tcpip6", Bind6After, &Size6After) == Have6 && (!Have6 || (Size6After == Size6 && !memcmp(Bind6, Bind6After, Size6))),
           "Tcpip6\\Linkage\\Bind changed\n");
        IContextMenu_Release(Menu);
    }

    if (Item)
        CoTaskMemFree(Item);
    if (Items)
        IEnumIDList_Release(Items);
    if (Folder)
        IShellFolder_Release(Folder);
    if (Desktop)
        IShellFolder_Release(Desktop);
    if (FolderPidl)
        CoTaskMemFree(FolderPidl);
}

/* The first adapter with an interface in the stack (the connection the sheet is opened for) */
static BOOL FirstAdapter(CONNECTION *C, GUID *Adapter)
{
    IEnumNetCfgComponent *Enum;
    INetCfgComponent *Comp;
    ULONG Fetched;
    BOOL Found = FALSE;

    if (FAILED(INetCfg_EnumComponents(C->Cfg, &GUID_DEVCLASS_NET, &Enum)))
        return FALSE;
    while (!Found && IEnumNetCfgComponent_Next(Enum, 1, &Comp, &Fetched) == S_OK)
    {
        LPWSTR BindName = NULL;
        NET_LUID Luid;
        ULONG Index = 0;

        if (INetCfgComponent_GetBindName(Comp, &BindName) == S_OK && BindName &&
            CLSIDFromString(BindName, Adapter) == S_OK &&
            pConvertInterfaceGuidToLuid(Adapter, &Luid) == NO_ERROR &&
            pConvertInterfaceLuidToIndex(&Luid, &Index) == NO_ERROR && Index != 0)
            Found = TRUE;
        CoTaskMemFree(BindName);
        INetCfgComponent_Release(Comp);
    }
    IEnumNetCfgComponent_Release(Enum);
    return Found;
}

START_TEST(Tcpip6Component)
{
    HMODULE hIphlpapi = LoadLibraryW(L"iphlpapi.dll");
    CONNECTION C;
    HRESULT hr;
    GUID Adapter;
    BOOL HaveAdapter = FALSE;

    if (!hIphlpapi)
    {
        skip("no iphlpapi\n");
        return;
    }
    pGetUnicastIpAddressTable = (PFN_GET_TABLE)GetProcAddress(hIphlpapi, "GetUnicastIpAddressTable");
    pGetIpForwardTable2 = (PFN_GET_TABLE)GetProcAddress(hIphlpapi, "GetIpForwardTable2");
    pFreeMibTable = (PFN_FREE_TABLE)GetProcAddress(hIphlpapi, "FreeMibTable");
    pConvertInterfaceGuidToLuid = (PFN_GUID_TO_LUID)GetProcAddress(hIphlpapi, "ConvertInterfaceGuidToLuid");
    pConvertInterfaceLuidToIndex = (PFN_LUID_TO_INDEX)GetProcAddress(hIphlpapi, "ConvertInterfaceLuidToIndex");
    if (!pConvertInterfaceGuidToLuid || !pConvertInterfaceLuidToIndex)
    {
        skip("no interface conversion functions\n");
        return;
    }

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        skip("CoInitializeEx failed\n");
        return;
    }

    if (OpenNetCfg(&C))
    {
        HaveAdapter = FirstAdapter(&C, &Adapter);
        TestInstances(&C);
        TestTexts(&C);
        TestPage(&C);
        CloseNetCfg(&C);
    }
    else
    {
        skip("INetCfg is not available\n");
        CloseNetCfg(&C);
    }
    /* the connection sheet takes the INetCfg write lock itself */
    TestConnectionSheet(HaveAdapter ? &Adapter : NULL);
    CoUninitialize();
}
