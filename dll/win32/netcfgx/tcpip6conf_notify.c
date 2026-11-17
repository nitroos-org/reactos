/*
 * PROJECT:     ReactOS Network Configuration
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The properties page of "Internet Protocol Version 6 (TCP/IPv6)" in a connection's property list
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The notify object of the MS_TCPIP6 component (Ndi\ClsId in nettcpip.inf). Its page has the controls of the page of
 * Windows: obtain the IPv6 address automatically, or use the following address (address, subnet prefix length, default
 * gateway); obtain the DNS server address automatically, or use the following addresses (preferred, alternate).
 *
 * It changes the configuration the way netsh interface ipv6 and Set-NetIPAddress do: the manual address and the default
 * route are entries of the persistent store (iphlpapi's NitroConfigureIpv6Address and NitroConfigureIpv6Route with
 * Persistent TRUE: in force now, and applied again whenever the adapter starts) and the DNS servers are the NameServer
 * value of Tcpip6\Parameters\Interfaces\{adapter GUID}. The page only collects what the user entered (OK of the page);
 * INetCfg::Apply, when OK of the connection's dialog is pressed, makes the changes, as it does for TCP/IPv4.
 *
 * Automatic means no manual address and no manual default route on the connection, and no static DNS server (the
 * addresses and the routers of the router advertisements, DHCPv6 and the advertised DNS servers stay in force).
 */

#include "precomp.h"

/* Not iphlpapi.h: at this Windows version it brings the netioapi.h of the SDK, which wine/netioapi.h (the rows of the
   unicast address and route tables, and the private exports) declares again */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iptypes.h>
#include <wine/netioapi.h>
typedef LONG NTSTATUS;  /* ip2string.h wants it; WIN32_NO_STATUS keeps the header that has it out */
#include <ip2string.h>
#include <iphlpapi_nitro.h>

#define IPV6_INTERFACES_KEY     L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\"
#define V6_INFINITE_LIFETIME    0xffffffff
#define V6_DEFAULT_METRIC       256
#define V6_MAX_TEXT             64
#define V6_MAX_DNS              16
#define V6_NAMESERVER_MAX_CHARS 510

typedef struct
{
    BOOL bStaticAddress;                /* a manual address (and route) rather than automatic */
    WCHAR szAddress[V6_MAX_TEXT];
    ULONG PrefixLength;
    WCHAR szGateway[V6_MAX_TEXT];
    BOOL bStaticDns;
    WCHAR szDns1[V6_MAX_TEXT];
    WCHAR szDns2[V6_MAX_TEXT];
} V6_SETTINGS;

typedef struct
{
    const INetCfgComponentControl *lpVtbl;
    const INetCfgComponentPropertyUi *lpVtblCompPropertyUi;
    LONG ref;
    INetCfg *pNCfg;
    INetCfgComponent *pNComp;

    WCHAR szAdapter[V6_MAX_TEXT];       /* {GUID} of the connection the page is shown for */
    V6_SETTINGS Current;                /* what the connection has now, read when the page is made */
    V6_SETTINGS Entered;                /* what OK of the page took */
    BOOL bEntered;                      /* Entered is to be made on Apply */
} Tcpip6ConfNotifyImpl;

static __inline Tcpip6ConfNotifyImpl *impl_from_INetCfgComponentPropertyUi(INetCfgComponentPropertyUi *iface)
{
    return (Tcpip6ConfNotifyImpl *)((char *)iface - FIELD_OFFSET(Tcpip6ConfNotifyImpl, lpVtblCompPropertyUi));
}

/***************************************************************
 * Reading and making the configuration
 */

static
BOOL
ParseIpv6(
    _In_ PCWSTR pszText,
    _Out_ IN6_ADDR *pAddress)
{
    PCWSTR pszEnd;
    WCHAR szCopy[V6_MAX_TEXT], *pPercent;

    if (wcslen(pszText) >= ARRAYSIZE(szCopy))
        return FALSE;
    wcscpy(szCopy, pszText);
    pPercent = wcschr(szCopy, L'%');
    if (pPercent)
        *pPercent = UNICODE_NULL;
    return RtlIpv6StringToAddressW(szCopy, &pszEnd, pAddress) == 0 && *pszEnd == UNICODE_NULL;
}

static
BOOL
IsUnspecified(
    _In_ const IN6_ADDR *pAddress)
{
    static const IN6_ADDR Zero;

    return memcmp(pAddress, &Zero, sizeof(Zero)) == 0;
}

/* The interface index of the connection (its adapter GUID), 0 when the stack has no interface for it */
static
ULONG
AdapterIndex(
    _In_ PCWSTR pszAdapter)
{
    GUID Guid;
    NET_LUID Luid;
    NET_IFINDEX Index = 0;

    if (FAILED(CLSIDFromString((LPOLESTR)pszAdapter, &Guid)) ||
        ConvertInterfaceGuidToLuid(&Guid, &Luid) != NO_ERROR ||
        ConvertInterfaceLuidToIndex(&Luid, &Index) != NO_ERROR)
        return 0;
    return Index;
}

/* A manual unicast address of the interface (the first one, or the one that is Match when Match is given) */
static
BOOL
IsManualAddress(
    _In_ const MIB_UNICASTIPADDRESS_ROW *Row,
    _In_ ULONG IfIndex)
{
    const UCHAR *Bytes = Row->Address.Ipv6.sin6_addr.u.Byte;

    return Row->Address.si_family == AF_INET6 && Row->InterfaceIndex == IfIndex &&
           Row->PrefixOrigin == IpPrefixOriginManual && Row->SuffixOrigin == IpSuffixOriginManual &&
           !(Bytes[0] == 0xfe && (Bytes[1] & 0xc0) == 0x80);   /* not a link-local address */
}

static
BOOL
IsManualDefaultRoute(
    _In_ const MIB_IPFORWARD_ROW2 *Row,
    _In_ ULONG IfIndex)
{
    return Row->DestinationPrefix.Prefix.si_family == AF_INET6 && Row->InterfaceIndex == IfIndex &&
           Row->DestinationPrefix.PrefixLength == 0 && Row->Origin == NlroManual &&
           IsUnspecified(&Row->DestinationPrefix.Prefix.Ipv6.sin6_addr) &&
           !IsUnspecified(&Row->NextHop.Ipv6.sin6_addr);
}

/* The NameServer value of the adapter: the static DNS servers, in order */
static
VOID
ReadDnsServers(
    _In_ PCWSTR pszAdapter,
    _Out_ V6_SETTINGS *pSettings)
{
    WCHAR szPath[200], szValue[V6_NAMESERVER_MAX_CHARS + 2], *pToken, *pContext = NULL;
    HKEY hKey;
    DWORD dwType, dwSize = sizeof(szValue) - 2 * sizeof(WCHAR);
    ULONG Count = 0;

    pSettings->szDns1[0] = pSettings->szDns2[0] = UNICODE_NULL;
    pSettings->bStaticDns = FALSE;
    if (wcslen(pszAdapter) > 60)
        return;
    wcscpy(szPath, IPV6_INTERFACES_KEY);
    wcscat(szPath, pszAdapter);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szPath, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return;
    ZeroMemory(szValue, sizeof(szValue));
    if (RegQueryValueExW(hKey, L"NameServer", NULL, &dwType, (LPBYTE)szValue, &dwSize) != ERROR_SUCCESS || dwType != REG_SZ)
        szValue[0] = UNICODE_NULL;
    RegCloseKey(hKey);

    for (pToken = wcstok_s(szValue, L",; ", &pContext); pToken && Count < 2; pToken = wcstok_s(NULL, L",; ", &pContext))
    {
        if (wcslen(pToken) >= V6_MAX_TEXT)
            continue;
        wcscpy(Count == 0 ? pSettings->szDns1 : pSettings->szDns2, pToken);
        Count++;
    }
    pSettings->bStaticDns = (Count != 0);
}

static
VOID
ReadSettings(
    _In_ PCWSTR pszAdapter,
    _Out_ V6_SETTINGS *pSettings)
{
    ULONG IfIndex = AdapterIndex(pszAdapter), i;
    PMIB_UNICASTIPADDRESS_TABLE pAddresses = NULL;
    PMIB_IPFORWARD_TABLE2 pRoutes = NULL;

    ZeroMemory(pSettings, sizeof(*pSettings));
    pSettings->PrefixLength = 64;
    ReadDnsServers(pszAdapter, pSettings);
    if (IfIndex == 0)
        return;

    if (GetUnicastIpAddressTable(AF_INET6, &pAddresses) == NO_ERROR && pAddresses)
    {
        for (i = 0; i < pAddresses->NumEntries; i++)
        {
            const MIB_UNICASTIPADDRESS_ROW *Row = &pAddresses->Table[i];

            if (!IsManualAddress(Row, IfIndex))
                continue;
            RtlIpv6AddressToStringW(&Row->Address.Ipv6.sin6_addr, pSettings->szAddress);
            pSettings->PrefixLength = Row->OnLinkPrefixLength;
            pSettings->bStaticAddress = TRUE;
            break;
        }
        FreeMibTable(pAddresses);
    }

    if (GetIpForwardTable2(AF_INET6, &pRoutes) == NO_ERROR && pRoutes)
    {
        for (i = 0; i < pRoutes->NumEntries; i++)
        {
            if (IsManualDefaultRoute(&pRoutes->Table[i], IfIndex))
            {
                RtlIpv6AddressToStringW(&pRoutes->Table[i].NextHop.Ipv6.sin6_addr, pSettings->szGateway);
                break;
            }
        }
        FreeMibTable(pRoutes);
    }
}

static
VOID
InitAddressRow(
    _Out_ PMIB_UNICASTIPADDRESS_ROW Row,
    _In_ ULONG IfIndex,
    _In_ const IN6_ADDR *pAddress,
    _In_ ULONG Length)
{
    InitializeUnicastIpAddressEntry(Row);
    Row->Address.si_family = AF_INET6;
    Row->Address.Ipv6.sin6_addr = *pAddress;
    Row->InterfaceIndex = IfIndex;
    Row->OnLinkPrefixLength = (UINT8)Length;
    Row->ValidLifetime = V6_INFINITE_LIFETIME;
    Row->PreferredLifetime = V6_INFINITE_LIFETIME;
    Row->PrefixOrigin = IpPrefixOriginManual;
    Row->SuffixOrigin = IpSuffixOriginManual;
}

static
VOID
InitRouteRow(
    _Out_ PMIB_IPFORWARD_ROW2 Row,
    _In_ ULONG IfIndex,
    _In_ const IN6_ADDR *pNextHop)
{
    InitializeIpForwardEntry(Row);
    Row->InterfaceIndex = IfIndex;
    Row->DestinationPrefix.Prefix.si_family = AF_INET6;
    Row->DestinationPrefix.PrefixLength = 0;
    Row->NextHop.si_family = AF_INET6;
    Row->NextHop.Ipv6.sin6_addr = *pNextHop;
    Row->Metric = V6_DEFAULT_METRIC;
    Row->ValidLifetime = V6_INFINITE_LIFETIME;
    Row->PreferredLifetime = V6_INFINITE_LIFETIME;
}

/* The manual addresses and default routes of the interface that are not the wanted ones are taken out of both stores
   (a DELETE with Persistent TRUE does that); with no wanted ones, all of them */
static
DWORD
RemoveOtherManualEntries(
    _In_ ULONG IfIndex,
    _In_opt_ const IN6_ADDR *pAddress,
    _In_opt_ const IN6_ADDR *pGateway)
{
    PMIB_UNICASTIPADDRESS_TABLE pAddresses = NULL;
    PMIB_IPFORWARD_TABLE2 pRoutes = NULL;
    ULONG i;
    DWORD dwError, dwResult = NO_ERROR;

    if (GetIpForwardTable2(AF_INET6, &pRoutes) == NO_ERROR && pRoutes)
    {
        for (i = 0; i < pRoutes->NumEntries; i++)
        {
            MIB_IPFORWARD_ROW2 *Row = &pRoutes->Table[i];

            if (!IsManualDefaultRoute(Row, IfIndex))
                continue;
            if (pGateway && memcmp(&Row->NextHop.Ipv6.sin6_addr, pGateway, sizeof(*pGateway)) == 0)
                continue;
            dwError = NitroConfigureIpv6Route(NITRO_IPV6_DELETE, TRUE, Row);
            if (dwError != NO_ERROR && dwError != ERROR_NOT_FOUND)
                dwResult = dwError;
        }
        FreeMibTable(pRoutes);
    }

    if (GetUnicastIpAddressTable(AF_INET6, &pAddresses) == NO_ERROR && pAddresses)
    {
        for (i = 0; i < pAddresses->NumEntries; i++)
        {
            MIB_UNICASTIPADDRESS_ROW *Row = &pAddresses->Table[i];

            if (!IsManualAddress(Row, IfIndex))
                continue;
            if (pAddress && memcmp(&Row->Address.Ipv6.sin6_addr, pAddress, sizeof(*pAddress)) == 0)
                continue;
            dwError = NitroConfigureIpv6Address(NITRO_IPV6_DELETE, TRUE, Row);
            if (dwError != NO_ERROR && dwError != ERROR_NOT_FOUND)
                dwResult = dwError;
        }
        FreeMibTable(pAddresses);
    }
    return dwResult;
}

static
DWORD
WriteDnsServers(
    _In_ PCWSTR pszAdapter,
    _In_ const V6_SETTINGS *pSettings)
{
    WCHAR szPath[200], szValue[2 * V6_MAX_TEXT + 2];
    HKEY hKey;
    DWORD dwError;

    if (wcslen(pszAdapter) > 60)
        return ERROR_INVALID_PARAMETER;
    wcscpy(szPath, IPV6_INTERFACES_KEY);
    wcscat(szPath, pszAdapter);

    szValue[0] = UNICODE_NULL;
    if (pSettings->bStaticDns)
    {
        if (pSettings->szDns1[0])
            wcscpy(szValue, pSettings->szDns1);
        if (pSettings->szDns2[0])
        {
            if (szValue[0])
                wcscat(szValue, L",");
            wcscat(szValue, pSettings->szDns2);
        }
    }

    dwError = RegCreateKeyExW(HKEY_LOCAL_MACHINE, szPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (dwError != ERROR_SUCCESS)
        return dwError;
    if (szValue[0] == UNICODE_NULL)
    {
        dwError = RegDeleteValueW(hKey, L"NameServer");
        if (dwError == ERROR_FILE_NOT_FOUND)
            dwError = ERROR_SUCCESS;
    }
    else
    {
        dwError = RegSetValueExW(hKey, L"NameServer", 0, REG_SZ, (const BYTE *)szValue,
                                 (DWORD)((wcslen(szValue) + 1) * sizeof(WCHAR)));
    }
    RegCloseKey(hKey);
    return dwError;
}

/* Makes the configuration the page took: the persistent address and default route (or none), and the DNS servers */
static
DWORD
MakeSettings(
    _In_ PCWSTR pszAdapter,
    _In_ const V6_SETTINGS *pSettings)
{
    ULONG IfIndex = AdapterIndex(pszAdapter);
    DWORD dwError, dwResult = NO_ERROR;
    IN6_ADDR Address, Gateway;
    BOOL bGateway = FALSE;

    if (IfIndex == 0)
    {
        /* no interface (the adapter is not started): only the DNS servers can be stored */
        if (pSettings->bStaticAddress)
            dwResult = ERROR_NOT_FOUND;
    }
    else if (!pSettings->bStaticAddress)
    {
        dwResult = RemoveOtherManualEntries(IfIndex, NULL, NULL);
    }
    else
    {
        MIB_UNICASTIPADDRESS_ROW AddressRow;
        MIB_IPFORWARD_ROW2 RouteRow;

        if (!ParseIpv6(pSettings->szAddress, &Address))
            return ERROR_INVALID_PARAMETER;
        bGateway = pSettings->szGateway[0] != UNICODE_NULL;
        if (bGateway && !ParseIpv6(pSettings->szGateway, &Gateway))
            return ERROR_INVALID_PARAMETER;

        dwResult = RemoveOtherManualEntries(IfIndex, &Address, bGateway ? &Gateway : NULL);

        InitAddressRow(&AddressRow, IfIndex, &Address, pSettings->PrefixLength);
        dwError = NitroConfigureIpv6Address(NITRO_IPV6_CREATE, TRUE, &AddressRow);
        if (dwError == ERROR_OBJECT_ALREADY_EXISTS)
            dwError = NitroConfigureIpv6Address(NITRO_IPV6_SET, TRUE, &AddressRow);
        if (dwError != NO_ERROR)
            dwResult = dwError;

        if (bGateway)
        {
            InitRouteRow(&RouteRow, IfIndex, &Gateway);
            dwError = NitroConfigureIpv6Route(NITRO_IPV6_CREATE, TRUE, &RouteRow);
            if (dwError != NO_ERROR && dwError != ERROR_OBJECT_ALREADY_EXISTS)
                dwResult = dwError;
        }
    }

    dwError = WriteDnsServers(pszAdapter, pSettings);
    if (dwError != ERROR_SUCCESS)
        dwResult = dwError;
    return dwResult;
}

/***************************************************************
 * The page
 */

static
VOID
ShowError(
    _In_ HWND hwndDlg,
    _In_ UINT uText,
    _In_opt_ PCWSTR pszArg,
    _In_ PCWSTR pszFallback)
{
    WCHAR szFormat[200], szText[300], szTitle[100];

    if (!LoadStringW(netcfgx_hInstance, uText, szFormat, ARRAYSIZE(szFormat)))
        wcscpy(szFormat, pszFallback);
    if (!LoadStringW(netcfgx_hInstance, IDS_V6_TITLE, szTitle, ARRAYSIZE(szTitle)))
        wcscpy(szTitle, L"Internet Protocol Version 6 (TCP/IPv6)");
    if (pszArg)
        _snwprintf(szText, ARRAYSIZE(szText) - 1, szFormat, pszArg);
    else
        wcscpy(szText, szFormat);
    szText[ARRAYSIZE(szText) - 1] = UNICODE_NULL;
    MessageBoxW(hwndDlg, szText, szTitle, MB_ICONEXCLAMATION | MB_OK);
}

/* The controls follow the radio buttons: a manual address enables the address fields and takes DNS to manual too (Windows
   greys the automatic DNS choice then, since the connection has no router to learn a server from) */
static
VOID
UpdateControls(
    _In_ HWND hwndDlg)
{
    BOOL bStaticAddress = IsDlgButtonChecked(hwndDlg, IDC_V6_STATICADDR) == BST_CHECKED;
    BOOL bStaticDns = IsDlgButtonChecked(hwndDlg, IDC_V6_STATICDNS) == BST_CHECKED;

    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_ADDRESS), bStaticAddress);
    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_PREFIX), bStaticAddress);
    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_GATEWAY), bStaticAddress);
    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_AUTODNS), !bStaticAddress);
    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_DNS1), bStaticDns);
    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_DNS2), bStaticDns);
    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_VALIDATE), bStaticAddress);
    if (!bStaticAddress)
        CheckDlgButton(hwndDlg, IDC_V6_VALIDATE, BST_UNCHECKED);
}

static
VOID
InitializeDialog(
    _In_ HWND hwndDlg,
    _In_ const V6_SETTINGS *pSettings)
{
    WCHAR szPrefix[8];

    SendDlgItemMessageW(hwndDlg, IDC_V6_ADDRESS, EM_LIMITTEXT, V6_MAX_TEXT - 1, 0);
    SendDlgItemMessageW(hwndDlg, IDC_V6_PREFIX, EM_LIMITTEXT, 3, 0);
    SendDlgItemMessageW(hwndDlg, IDC_V6_GATEWAY, EM_LIMITTEXT, V6_MAX_TEXT - 1, 0);
    SendDlgItemMessageW(hwndDlg, IDC_V6_DNS1, EM_LIMITTEXT, V6_MAX_TEXT - 1, 0);
    SendDlgItemMessageW(hwndDlg, IDC_V6_DNS2, EM_LIMITTEXT, V6_MAX_TEXT - 1, 0);

    CheckRadioButton(hwndDlg, IDC_V6_AUTOADDR, IDC_V6_STATICADDR,
                     pSettings->bStaticAddress ? IDC_V6_STATICADDR : IDC_V6_AUTOADDR);
    /* a manual address has manual DNS servers (possibly none) */
    CheckRadioButton(hwndDlg, IDC_V6_AUTODNS, IDC_V6_STATICDNS,
                     (pSettings->bStaticAddress || pSettings->bStaticDns) ? IDC_V6_STATICDNS : IDC_V6_AUTODNS);

    if (pSettings->bStaticAddress)
    {
        _snwprintf(szPrefix, ARRAYSIZE(szPrefix) - 1, L"%lu", pSettings->PrefixLength);
        szPrefix[ARRAYSIZE(szPrefix) - 1] = UNICODE_NULL;
        SetDlgItemTextW(hwndDlg, IDC_V6_ADDRESS, pSettings->szAddress);
        SetDlgItemTextW(hwndDlg, IDC_V6_PREFIX, szPrefix);
        SetDlgItemTextW(hwndDlg, IDC_V6_GATEWAY, pSettings->szGateway);
    }
    SetDlgItemTextW(hwndDlg, IDC_V6_DNS1, pSettings->szDns1);
    SetDlgItemTextW(hwndDlg, IDC_V6_DNS2, pSettings->szDns2);
    UpdateControls(hwndDlg);

    /* the Advanced dialog (several addresses and gateways, metric, DNS suffix) is not there yet */
    EnableWindow(GetDlgItem(hwndDlg, IDC_V6_ADVANCED), FALSE);
}

/* What the fields hold, checked. FALSE: an error was shown and the page stays */
static
BOOL
TakeDialog(
    _In_ HWND hwndDlg,
    _Out_ V6_SETTINGS *pSettings)
{
    WCHAR szText[V6_MAX_TEXT], *pEnd;
    IN6_ADDR Address;
    ULONG Prefix;

    ZeroMemory(pSettings, sizeof(*pSettings));
    pSettings->PrefixLength = 64;
    pSettings->bStaticAddress = IsDlgButtonChecked(hwndDlg, IDC_V6_STATICADDR) == BST_CHECKED;
    pSettings->bStaticDns = IsDlgButtonChecked(hwndDlg, IDC_V6_STATICDNS) == BST_CHECKED;

    if (pSettings->bStaticAddress)
    {
        GetDlgItemTextW(hwndDlg, IDC_V6_ADDRESS, pSettings->szAddress, ARRAYSIZE(pSettings->szAddress));
        if (pSettings->szAddress[0] == UNICODE_NULL)
        {
            ShowError(hwndDlg, IDS_V6_NOADDRESS, NULL, L"Enter an IPv6 address.");
            SetFocus(GetDlgItem(hwndDlg, IDC_V6_ADDRESS));
            return FALSE;
        }
        /* an address that is not an address, the unspecified one, or a multicast one cannot be assigned to a connection */
        if (!ParseIpv6(pSettings->szAddress, &Address) || IsUnspecified(&Address) || Address.u.Byte[0] == 0xff)
        {
            ShowError(hwndDlg, IDS_V6_BADADDRESS, pSettings->szAddress, L"\"%s\" is not a valid IPv6 address.");
            SetFocus(GetDlgItem(hwndDlg, IDC_V6_ADDRESS));
            return FALSE;
        }

        GetDlgItemTextW(hwndDlg, IDC_V6_PREFIX, szText, ARRAYSIZE(szText));
        Prefix = szText[0] ? wcstoul(szText, &pEnd, 10) : 0;
        if (szText[0] == UNICODE_NULL || *pEnd != UNICODE_NULL || Prefix < 1 || Prefix > 128)
        {
            ShowError(hwndDlg, IDS_V6_BADPREFIX, NULL, L"The subnet prefix length must be a number from 1 to 128.");
            SetFocus(GetDlgItem(hwndDlg, IDC_V6_PREFIX));
            return FALSE;
        }
        pSettings->PrefixLength = Prefix;

        GetDlgItemTextW(hwndDlg, IDC_V6_GATEWAY, pSettings->szGateway, ARRAYSIZE(pSettings->szGateway));
        if (pSettings->szGateway[0] && (!ParseIpv6(pSettings->szGateway, &Address) || IsUnspecified(&Address)))
        {
            ShowError(hwndDlg, IDS_V6_BADADDRESS, pSettings->szGateway, L"\"%s\" is not a valid IPv6 address.");
            SetFocus(GetDlgItem(hwndDlg, IDC_V6_GATEWAY));
            return FALSE;
        }
    }

    if (pSettings->bStaticDns)
    {
        GetDlgItemTextW(hwndDlg, IDC_V6_DNS1, pSettings->szDns1, ARRAYSIZE(pSettings->szDns1));
        GetDlgItemTextW(hwndDlg, IDC_V6_DNS2, pSettings->szDns2, ARRAYSIZE(pSettings->szDns2));
        if (pSettings->szDns1[0] && (!ParseIpv6(pSettings->szDns1, &Address) || IsUnspecified(&Address)))
        {
            ShowError(hwndDlg, IDS_V6_BADADDRESS, pSettings->szDns1, L"\"%s\" is not a valid IPv6 address.");
            SetFocus(GetDlgItem(hwndDlg, IDC_V6_DNS1));
            return FALSE;
        }
        if (pSettings->szDns2[0] && (!ParseIpv6(pSettings->szDns2, &Address) || IsUnspecified(&Address)))
        {
            ShowError(hwndDlg, IDS_V6_BADADDRESS, pSettings->szDns2, L"\"%s\" is not a valid IPv6 address.");
            SetFocus(GetDlgItem(hwndDlg, IDC_V6_DNS2));
            return FALSE;
        }
        /* a lone alternate server is the preferred one */
        if (!pSettings->szDns1[0] && pSettings->szDns2[0])
        {
            wcscpy(pSettings->szDns1, pSettings->szDns2);
            pSettings->szDns2[0] = UNICODE_NULL;
        }
    }
    return TRUE;
}

static
INT_PTR
CALLBACK
Tcpip6Dlg(
    HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
    Tcpip6ConfNotifyImpl *This;
    LPPSHNOTIFY lppsn;
    V6_SETTINGS Settings;
    WCHAR szPrefix[8];

    switch (uMsg)
    {
        case WM_INITDIALOG:
            This = (Tcpip6ConfNotifyImpl *)((LPPROPSHEETPAGE)lParam)->lParam;
            SetWindowLongPtrW(hwndDlg, DWLP_USER, (LONG_PTR)This);
            InitializeDialog(hwndDlg, &This->Current);
            return TRUE;

        case WM_NOTIFY:
            lppsn = (LPPSHNOTIFY)lParam;
            if (lppsn->hdr.code == PSN_APPLY)
            {
                This = (Tcpip6ConfNotifyImpl *)GetWindowLongPtrW(hwndDlg, DWLP_USER);
                if (TakeDialog(hwndDlg, &Settings))
                {
                    This->Entered = Settings;
                    This->bEntered = TRUE;
                    SetWindowLongPtrW(hwndDlg, DWLP_MSGRESULT, PSNRET_NOERROR);
                }
                else
                {
                    SetWindowLongPtrW(hwndDlg, DWLP_MSGRESULT, PSNRET_INVALID_NOCHANGEPAGE);
                }
                return TRUE;
            }
            break;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_V6_AUTOADDR:
                case IDC_V6_STATICADDR:
                case IDC_V6_AUTODNS:
                case IDC_V6_STATICDNS:
                    if (HIWORD(wParam) != BN_CLICKED)
                        break;
                    PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
                    switch (LOWORD(wParam))
                    {
                        case IDC_V6_AUTOADDR:
                            SetDlgItemTextW(hwndDlg, IDC_V6_ADDRESS, L"");
                            SetDlgItemTextW(hwndDlg, IDC_V6_PREFIX, L"");
                            SetDlgItemTextW(hwndDlg, IDC_V6_GATEWAY, L"");
                            break;
                        case IDC_V6_STATICADDR:
                            GetDlgItemTextW(hwndDlg, IDC_V6_PREFIX, szPrefix, ARRAYSIZE(szPrefix));
                            if (szPrefix[0] == UNICODE_NULL)
                                SetDlgItemTextW(hwndDlg, IDC_V6_PREFIX, L"64");
                            /* manual address: the DNS servers are manual too */
                            CheckRadioButton(hwndDlg, IDC_V6_AUTODNS, IDC_V6_STATICDNS, IDC_V6_STATICDNS);
                            break;
                        case IDC_V6_AUTODNS:
                            SetDlgItemTextW(hwndDlg, IDC_V6_DNS1, L"");
                            SetDlgItemTextW(hwndDlg, IDC_V6_DNS2, L"");
                            break;
                    }
                    UpdateControls(hwndDlg);
                    break;

                case IDC_V6_VALIDATE:
                    if (HIWORD(wParam) == BN_CLICKED)
                        PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
                    break;

                case IDC_V6_ADDRESS:
                case IDC_V6_PREFIX:
                case IDC_V6_GATEWAY:
                case IDC_V6_DNS1:
                case IDC_V6_DNS2:
                    if (HIWORD(wParam) == EN_CHANGE)
                        PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
                    break;
            }
            break;
    }
    return FALSE;
}

/***************************************************************
 * INetCfgComponentPropertyUi
 */

HRESULT
WINAPI
Tcpip6PropertyUi_fnQueryInterface(
    INetCfgComponentPropertyUi *iface,
    REFIID iid,
    LPVOID *ppvObj)
{
    Tcpip6ConfNotifyImpl *This = impl_from_INetCfgComponentPropertyUi(iface);

    return INetCfgComponentControl_QueryInterface((INetCfgComponentControl *)This, iid, ppvObj);
}

ULONG
WINAPI
Tcpip6PropertyUi_fnAddRef(
    INetCfgComponentPropertyUi *iface)
{
    Tcpip6ConfNotifyImpl *This = impl_from_INetCfgComponentPropertyUi(iface);

    return INetCfgComponentControl_AddRef((INetCfgComponentControl *)This);
}

ULONG
WINAPI
Tcpip6PropertyUi_fnRelease(
    INetCfgComponentPropertyUi *iface)
{
    Tcpip6ConfNotifyImpl *This = impl_from_INetCfgComponentPropertyUi(iface);

    return INetCfgComponentControl_Release((INetCfgComponentControl *)This);
}

HRESULT
WINAPI
Tcpip6PropertyUi_fnQueryPropertyUi(
    INetCfgComponentPropertyUi *iface,
    IUnknown *pUnkReserved)
{
    return S_OK;
}

/* The connection the page is for (the context is the connection UI, which knows the adapter's GUID) */
HRESULT
WINAPI
Tcpip6PropertyUi_fnSetContext(
    INetCfgComponentPropertyUi *iface,
    IUnknown *pUnkReserved)
{
    Tcpip6ConfNotifyImpl *This = impl_from_INetCfgComponentPropertyUi(iface);
    INetLanConnectionUiInfo *pLanInfo;
    GUID Guid;
    LPOLESTR pszGuid = NULL;
    HRESULT hr;

    /* RaisePropertyUi takes the context away when the sheet is done, before INetCfg::Apply makes what the page took:
       the adapter stays until the next context */
    if (!pUnkReserved)
        return S_OK;

    hr = IUnknown_QueryInterface(pUnkReserved, &IID_INetLanConnectionUiInfo, (LPVOID *)&pLanInfo);
    if (FAILED(hr))
        return hr;

    hr = INetLanConnectionUiInfo_GetDeviceGuid(pLanInfo, &Guid);
    INetLanConnectionUiInfo_Release(pLanInfo);
    if (FAILED(hr))
        return hr;

    hr = StringFromCLSID(&Guid, &pszGuid);
    if (FAILED(hr))
        return hr;
    if (wcslen(pszGuid) >= ARRAYSIZE(This->szAdapter))
    {
        CoTaskMemFree(pszGuid);
        return E_INVALIDARG;
    }
    wcscpy(This->szAdapter, pszGuid);
    CoTaskMemFree(pszGuid);

    ReadSettings(This->szAdapter, &This->Current);
    This->bEntered = FALSE;
    return S_OK;
}

HRESULT
WINAPI
Tcpip6PropertyUi_fnMergePropPages(
    INetCfgComponentPropertyUi *iface,
    DWORD *pdwDefPages,
    BYTE **pahpspPrivate,
    UINT *pcPages,
    HWND hwndParent,
    LPCWSTR *pszStartPage)
{
    Tcpip6ConfNotifyImpl *This = impl_from_INetCfgComponentPropertyUi(iface);
    PROPSHEETPAGEW Page;
    HPROPSHEETPAGE *hppages;

    if (This->szAdapter[0] == UNICODE_NULL)
        return E_UNEXPECTED;

    hppages = CoTaskMemAlloc(sizeof(HPROPSHEETPAGE));
    if (!hppages)
        return E_OUTOFMEMORY;

    ZeroMemory(&Page, sizeof(Page));
    Page.dwSize = sizeof(Page);
    Page.dwFlags = PSP_DEFAULT;
    Page.hInstance = netcfgx_hInstance;
    Page.u.pszTemplate = MAKEINTRESOURCEW(IDD_TCPIP6_DLG);
    Page.pfnDlgProc = Tcpip6Dlg;
    Page.lParam = (LPARAM)This;
    hppages[0] = CreatePropertySheetPageW(&Page);
    if (!hppages[0])
    {
        CoTaskMemFree(hppages);
        return E_FAIL;
    }

    *pahpspPrivate = (BYTE *)hppages;
    *pcPages = 1;
    return S_OK;
}

HRESULT
WINAPI
Tcpip6PropertyUi_fnValidateProperties(
    INetCfgComponentPropertyUi *iface,
    HWND hwndDlg)
{
    return S_OK;
}

/* S_OK tells INetCfgComponent::RaisePropertyUi that there is something to store on Apply */
HRESULT
WINAPI
Tcpip6PropertyUi_fnApplyProperties(
    INetCfgComponentPropertyUi *iface)
{
    Tcpip6ConfNotifyImpl *This = impl_from_INetCfgComponentPropertyUi(iface);

    return This->bEntered ? S_OK : S_FALSE;
}

HRESULT
WINAPI
Tcpip6PropertyUi_fnCancelProperties(
    INetCfgComponentPropertyUi *iface)
{
    Tcpip6ConfNotifyImpl *This = impl_from_INetCfgComponentPropertyUi(iface);

    This->bEntered = FALSE;
    return S_OK;
}

static const INetCfgComponentPropertyUiVtbl vt_Tcpip6PropertyUi =
{
    Tcpip6PropertyUi_fnQueryInterface,
    Tcpip6PropertyUi_fnAddRef,
    Tcpip6PropertyUi_fnRelease,
    Tcpip6PropertyUi_fnQueryPropertyUi,
    Tcpip6PropertyUi_fnSetContext,
    Tcpip6PropertyUi_fnMergePropPages,
    Tcpip6PropertyUi_fnValidateProperties,
    Tcpip6PropertyUi_fnApplyProperties,
    Tcpip6PropertyUi_fnCancelProperties
};

/***************************************************************
 * INetCfgComponentControl
 */

HRESULT
WINAPI
Tcpip6Control_fnQueryInterface(
    INetCfgComponentControl *iface,
    REFIID iid,
    LPVOID *ppvObj)
{
    Tcpip6ConfNotifyImpl *This = (Tcpip6ConfNotifyImpl *)iface;

    *ppvObj = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_INetCfgComponentControl))
    {
        *ppvObj = This;
    }
    else if (IsEqualIID(iid, &IID_INetCfgComponentPropertyUi))
    {
        *ppvObj = (LPVOID)&This->lpVtblCompPropertyUi;
    }
    else
    {
        return E_NOINTERFACE;
    }
    INetCfgComponentControl_AddRef(iface);
    return S_OK;
}

ULONG
WINAPI
Tcpip6Control_fnAddRef(
    INetCfgComponentControl *iface)
{
    Tcpip6ConfNotifyImpl *This = (Tcpip6ConfNotifyImpl *)iface;

    return InterlockedIncrement(&This->ref);
}

ULONG
WINAPI
Tcpip6Control_fnRelease(
    INetCfgComponentControl *iface)
{
    Tcpip6ConfNotifyImpl *This = (Tcpip6ConfNotifyImpl *)iface;
    ULONG refCount = InterlockedDecrement(&This->ref);

    if (!refCount)
        CoTaskMemFree(This);
    return refCount;
}

HRESULT
WINAPI
Tcpip6Control_fnInitialize(
    INetCfgComponentControl *iface,
    INetCfgComponent *pIComp,
    INetCfg *pINetCfg,
    BOOL fInstalling)
{
    Tcpip6ConfNotifyImpl *This = (Tcpip6ConfNotifyImpl *)iface;

    This->pNCfg = pINetCfg;
    This->pNComp = pIComp;
    return S_OK;
}

/* INetCfg::Apply: what OK of the page took goes into the configuration */
HRESULT
WINAPI
Tcpip6Control_fnApplyRegistryChanges(
    INetCfgComponentControl *iface)
{
    Tcpip6ConfNotifyImpl *This = (Tcpip6ConfNotifyImpl *)iface;
    DWORD dwError;

    if (!This->bEntered || This->szAdapter[0] == UNICODE_NULL)
        return S_OK;

    This->bEntered = FALSE;
    dwError = MakeSettings(This->szAdapter, &This->Entered);
    if (dwError != NO_ERROR)
    {
        WCHAR szCode[16];

        ERR("The IPv6 settings could not be made (error %lu)\n", dwError);
        _snwprintf(szCode, ARRAYSIZE(szCode) - 1, L"%lu", dwError);
        szCode[ARRAYSIZE(szCode) - 1] = UNICODE_NULL;
        ShowError(GetActiveWindow(), IDS_V6_APPLYFAILED, szCode, L"The IPv6 settings could not be applied (error %s).");
    }
    return S_OK;
}

HRESULT
WINAPI
Tcpip6Control_fnApplyPnpChanges(
    INetCfgComponentControl *iface,
    INetCfgPnpReconfigCallback *pICallback)
{
    return S_OK;
}

HRESULT
WINAPI
Tcpip6Control_fnCancelChanges(
    INetCfgComponentControl *iface)
{
    Tcpip6ConfNotifyImpl *This = (Tcpip6ConfNotifyImpl *)iface;

    This->bEntered = FALSE;
    return S_OK;
}

static const INetCfgComponentControlVtbl vt_Tcpip6Control =
{
    Tcpip6Control_fnQueryInterface,
    Tcpip6Control_fnAddRef,
    Tcpip6Control_fnRelease,
    Tcpip6Control_fnInitialize,
    Tcpip6Control_fnApplyRegistryChanges,
    Tcpip6Control_fnApplyPnpChanges,
    Tcpip6Control_fnCancelChanges
};

HRESULT
WINAPI
Tcpip6ConfigNotify_Constructor(
    IUnknown *pUnkOuter,
    REFIID riid,
    LPVOID *ppv)
{
    Tcpip6ConfNotifyImpl *This;

    if (!ppv)
        return E_POINTER;

    This = CoTaskMemAlloc(sizeof(*This));
    if (!This)
        return E_OUTOFMEMORY;

    ZeroMemory(This, sizeof(*This));
    This->ref = 1;
    This->lpVtbl = (const INetCfgComponentControl *)&vt_Tcpip6Control;
    This->lpVtblCompPropertyUi = (const INetCfgComponentPropertyUi *)&vt_Tcpip6PropertyUi;

    if (FAILED(INetCfgComponentControl_QueryInterface((INetCfgComponentControl *)This, riid, ppv)))
    {
        INetCfgComponentControl_Release((INetCfgComponentControl *)This);
        return E_NOINTERFACE;
    }

    INetCfgComponentControl_Release((INetCfgComponentControl *)This);
    return S_OK;
}
