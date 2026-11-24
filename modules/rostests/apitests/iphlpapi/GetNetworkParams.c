/*
 * PROJECT:         ReactOS API Tests
 * LICENSE:         LGPLv2.1+ - See COPYING.LIB in the top level directory
 * PURPOSE:         Tests for GetNetworkParams function
 * PROGRAMMERS:     Peter Hater
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <iphlpapi.h>
#include <winreg.h>

#define ROSTESTDHCPHOST "testdhcproshost"
#define ROSTESTDHCPDOMAIN "testrosdomain"

static
INT
ReadRegistryValue(PCHAR ValueName, PCHAR Value)
{
    INT ErrorCode;
    HKEY ParametersKey;
    DWORD RegType;
    DWORD RegSize = 0;

    /* Open the database path key */
    ErrorCode = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                              "System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                              0,
                              KEY_READ,
                              &ParametersKey);
    if (ErrorCode == NO_ERROR)
    {
        /* Read the actual path */
        ErrorCode = RegQueryValueExA(ParametersKey,
                                     ValueName,
                                     NULL,
                                     &RegType,
                                     NULL,
                                     &RegSize);
        if (RegSize)
        {
            /* Read the actual path */
            ErrorCode = RegQueryValueExA(ParametersKey,
                                         ValueName,
                                         NULL,
                                         &RegType,
                                         (LPBYTE)Value,
                                         &RegSize);
        }

        /* Close the key */
        RegCloseKey(ParametersKey);
    }
    return ErrorCode;
}

static
INT
WriteRegistryValue(PCHAR ValueName, PCHAR Value)
{
    INT ErrorCode;
    HKEY ParametersKey;

    /* Open the database path key */
    ErrorCode = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                              "System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                              0,
                              KEY_WRITE,
                              &ParametersKey);
    if (ErrorCode == NO_ERROR)
    {
        /* Read the actual path */
        ErrorCode = RegSetValueExA(ParametersKey,
                                   ValueName,
                                   0,
                                   REG_SZ,
                                   (LPBYTE)Value,
                                   lstrlenA(Value) + 1);

        /* Close the key */
        RegCloseKey(ParametersKey);
    }
    return ErrorCode;
}

static
INT
DeleteRegistryValue(PCHAR ValueName)
{
    INT ErrorCode;
    HKEY ParametersKey;

    /* Open the database path key */
    ErrorCode = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                              "System\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                              0,
                              KEY_WRITE,
                              &ParametersKey);
    if (ErrorCode == NO_ERROR)
    {
        /* Read the actual path */
        ErrorCode = RegDeleteValueA(ParametersKey, ValueName);

        /* Close the key */
        RegCloseKey(ParametersKey);
    }
    return ErrorCode;
}

static
VOID
test_GetNetworkParams(VOID)
{
    DWORD len = 0;
    INT ErrorCode;
    CHAR OrigHostname[128];
    CHAR OrigDomainName[128];
    CHAR OrigDhcpHostname[128];
    CHAR OrigDhcpDomainName[128];
    BOOL OrigHostnameExists;
    BOOL OrigDomainNameExists;
    BOOL OrigDhcpHostnameExists;
    BOOL OrigDhcpDomainNameExists;
    PFIXED_INFO FixedInfo;
    DWORD ApiReturn;

    memset(OrigHostname, 0, sizeof(OrigHostname));
    memset(OrigDomainName, 0, sizeof(OrigDomainName));
    memset(OrigDhcpHostname, 0, sizeof(OrigDhcpHostname));
    memset(OrigDhcpDomainName, 0, sizeof(OrigDhcpDomainName));
    /* read current registry values */
    ErrorCode = ReadRegistryValue("Hostname", OrigHostname);
    ok(ErrorCode == ERROR_SUCCESS, "Failed to read registry key Hostname %d\n", ErrorCode);
    OrigHostnameExists = ErrorCode == NO_ERROR;
    ErrorCode = ReadRegistryValue("Domain", OrigDomainName);
    ok(ErrorCode == ERROR_SUCCESS || ErrorCode == ERROR_FILE_NOT_FOUND, "Failed to read registry key DomainName %d\n", ErrorCode);
    OrigDomainNameExists = ErrorCode == NO_ERROR;
    ErrorCode = ReadRegistryValue("DhcpHostname", OrigDhcpHostname);
    ok(ErrorCode == ERROR_SUCCESS || ErrorCode == ERROR_FILE_NOT_FOUND, "Failed to read registry key DhcpHostname %d\n", ErrorCode);
    OrigDhcpHostnameExists = ErrorCode == NO_ERROR;
    ErrorCode = ReadRegistryValue("DhcpDomain", OrigDhcpDomainName);
    ok(ErrorCode == ERROR_SUCCESS || ErrorCode == ERROR_FILE_NOT_FOUND, "Failed to read registry key DhcpDomainName %d\n", ErrorCode);
    OrigDhcpDomainNameExists = ErrorCode == NO_ERROR;

    trace("Starting values:\n");
    trace("Hostname: %s, exists %s\n", OrigHostname, OrigHostnameExists ? "yes" : "no");
    trace("Domain: %s, exists %s\n", OrigDomainName, OrigDomainNameExists ? "yes" : "no");
    trace("DhcpHostname: %s, exists %s\n", OrigDhcpHostnameExists ? OrigDhcpHostname : "", OrigDhcpHostnameExists ? "yes" : "no");
    trace("DhcpDomain: %s, exists %s\n", OrigDhcpDomainNameExists ? OrigDhcpDomainName : "", OrigDhcpDomainNameExists ? "yes" : "no");

    ApiReturn = GetNetworkParams(NULL, &len);
    ok(ApiReturn == ERROR_BUFFER_OVERFLOW,
        "GetNetworkParams returned %ld, expected ERROR_BUFFER_OVERFLOW\n",
        ApiReturn);
    if (ApiReturn != ERROR_BUFFER_OVERFLOW)
        skip("Can't determine size of FIXED_INFO. Can't proceed\n");
    FixedInfo = HeapAlloc(GetProcessHeap(), 0, len);
    if (FixedInfo == NULL)
        skip("FixedInfo is NULL. Can't proceed\n");

    ApiReturn = GetNetworkParams(FixedInfo, &len);
    ok(ApiReturn == NO_ERROR,
        "GetNetworkParams(buf, &dwSize) returned %ld, expected NO_ERROR\n",
        ApiReturn);
    if (ApiReturn != NO_ERROR)
    {
        HeapFree(GetProcessHeap(), 0, FixedInfo);
        skip("GetNetworkParams failed. Can't proceed\n");
    }

    if (OrigDhcpHostnameExists)
    {
        /* Windows doesn't honor DHCP option 12 even if RFC requires it if it is returned by DHCP server! */
        //ok(strcmp(FixedInfo->HostName, OrigDhcpHostname) == 0, "FixedInfo->HostName is wrong '%s' != '%s'\n", FixedInfo->HostName, OrigDhcpHostname);
    }
    else
        ok(strcmp(FixedInfo->HostName, OrigHostname) == 0, "FixedInfo->HostName is wrong '%s' != '%s'\n", FixedInfo->HostName, OrigHostname);

    ok(strcmp(FixedInfo->DomainName, OrigDomainName) == 0, "FixedInfo->DomainName is wrong '%s' != '%s'\n", FixedInfo->DomainName, OrigDomainName);
    if (!OrigDhcpHostnameExists)
    {
        ErrorCode = WriteRegistryValue("DhcpHostname", ROSTESTDHCPHOST);
        ok(ErrorCode == NO_ERROR, "Failed to write registry key DhcpHostname %d\n", ErrorCode);
    }
    else
    {
        ErrorCode = DeleteRegistryValue("DhcpHostname");
        ok(ErrorCode == NO_ERROR, "Failed to remove registry key DhcpHostname %d\n", ErrorCode);
    }
    if (!OrigDhcpDomainNameExists)
    {
        ErrorCode = WriteRegistryValue("DhcpDomain", ROSTESTDHCPDOMAIN);
        ok(ErrorCode == NO_ERROR, "Failed to write registry key DhcpDomainName %d\n", ErrorCode);
    }
    else
    {
        ErrorCode = DeleteRegistryValue("DhcpDomain");
        ok(ErrorCode == NO_ERROR, "Failed to remove registry key DhcpDomainName %d\n", ErrorCode);
    }

    HeapFree(GetProcessHeap(), 0, FixedInfo);
    len = 0;
    ApiReturn = GetNetworkParams(NULL, &len);
    ok(ApiReturn == ERROR_BUFFER_OVERFLOW,
        "GetNetworkParams returned %ld, expected ERROR_BUFFER_OVERFLOW\n",
        ApiReturn);
    if (ApiReturn != ERROR_BUFFER_OVERFLOW)
        skip("Can't determine size of FIXED_INFO. Can't proceed\n");
    FixedInfo = HeapAlloc(GetProcessHeap(), 0, len);
    if (FixedInfo == NULL)
        skip("FixedInfo is NULL. Can't proceed\n");
    ApiReturn = GetNetworkParams(FixedInfo, &len);
    ok(ApiReturn == NO_ERROR,
        "GetNetworkParams(buf, &dwSize) returned %ld, expected NO_ERROR\n",
        ApiReturn);
    if (ApiReturn != NO_ERROR)
    {
        HeapFree(GetProcessHeap(), 0, FixedInfo);
        skip("GetNetworkParams failed. Can't proceed\n");
    }

    /* restore registry values */
    if (OrigDhcpHostnameExists)
        ErrorCode = WriteRegistryValue("DhcpHostname", OrigDhcpHostname);
    else
        ErrorCode = DeleteRegistryValue("DhcpHostname");
    ok(ErrorCode == NO_ERROR, "Failed to restore registry key DhcpHostname %d\n", ErrorCode);
    if (OrigDhcpDomainNameExists)
        ErrorCode = WriteRegistryValue("DhcpDomain", OrigDhcpDomainName);
    else
        ErrorCode = DeleteRegistryValue("DhcpDomain");
    ok(ErrorCode == NO_ERROR, "Failed to restore registry key DhcpDomainName %d\n", ErrorCode);

    ok(ApiReturn == NO_ERROR,
        "GetNetworkParams(buf, &dwSize) returned %ld, expected NO_ERROR\n",
        ApiReturn);

    if (!OrigDhcpHostnameExists)
    {
        /* Windows doesn't honor DHCP option 12 even if RFC requires it if it is returned by DHCP server! */
        //ok(strcmp(FixedInfo->HostName, ROSTESTDHCPHOST) == 0, "FixedInfo->HostName is wrong '%s' != '%s'\n", FixedInfo->HostName, ROSTESTDHCPHOST);
    }
    else
        ok(strcmp(FixedInfo->HostName, OrigHostname) == 0, "FixedInfo->HostName is wrong '%s' != '%s'\n", FixedInfo->HostName, OrigHostname);
    if (!OrigDhcpDomainNameExists)
        ok(strcmp(FixedInfo->DomainName, ROSTESTDHCPDOMAIN) == 0, "FixedInfo->DomainName is wrong '%s' != '%s'\n", FixedInfo->DomainName, ROSTESTDHCPDOMAIN);
    else
        ok(strcmp(FixedInfo->DomainName, OrigDomainName) == 0, "FixedInfo->DomainName is wrong '%s' != '%s'\n", FixedInfo->DomainName, OrigDomainName);

    HeapFree(GetProcessHeap(), 0, FixedInfo);
}

/*
 * The Interfaces key keeps a subkey for every adapter the system has ever had. The name servers of a
 * subkey that no adapter has (a removed or replaced NIC) are not the ones of the computer: nslookup asked
 * such a server first.
 */
#define STALE_INTERFACE_KEY "System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{0BADC0DE-0000-4000-8000-000000000042}"
#define STALE_NAME_SERVER "192.0.2.42"

static
VOID
test_GetNetworkParamsStaleInterface(VOID)
{
    HKEY Key;
    LONG Error;
    DWORD Len = 0, Dhcp = 0, Count = 0;
    DWORD ApiReturn;
    PFIXED_INFO FixedInfo;
    PIP_ADDR_STRING Server;

    Error = RegCreateKeyExA(HKEY_LOCAL_MACHINE, STALE_INTERFACE_KEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL);
    if (Error != ERROR_SUCCESS)
    {
        skip("Cannot create the interface key (%ld)\n", Error);
        return;
    }
    RegSetValueExA(Key, "NameServer", 0, REG_SZ, (const BYTE *)STALE_NAME_SERVER, sizeof(STALE_NAME_SERVER));
    RegSetValueExA(Key, "EnableDHCP", 0, REG_DWORD, (const BYTE *)&Dhcp, sizeof(Dhcp));
    RegCloseKey(Key);

    ApiReturn = GetNetworkParams(NULL, &Len);
    ok(ApiReturn == ERROR_BUFFER_OVERFLOW, "GetNetworkParams returned %lu\n", ApiReturn);
    FixedInfo = HeapAlloc(GetProcessHeap(), 0, Len);
    if (FixedInfo && ApiReturn == ERROR_BUFFER_OVERFLOW)
    {
        ApiReturn = GetNetworkParams(FixedInfo, &Len);
        ok(ApiReturn == NO_ERROR, "GetNetworkParams returned %lu\n", ApiReturn);
        if (ApiReturn == NO_ERROR)
        {
            for (Server = &FixedInfo->DnsServerList; Server; Server = Server->Next)
            {
                ok(strcmp(Server->IpAddress.String, STALE_NAME_SERVER) != 0,
                   "GetNetworkParams lists the name server of an interface that no adapter has\n");
                if (Server->IpAddress.String[0] != '\0')
                    Count++;
            }
            trace("%lu name servers of the adapters\n", Count);
        }
    }
    HeapFree(GetProcessHeap(), 0, FixedInfo);

    Error = RegDeleteKeyA(HKEY_LOCAL_MACHINE, STALE_INTERFACE_KEY);
    ok(Error == ERROR_SUCCESS, "Failed to delete the interface key: %ld\n", Error);
}

START_TEST(GetNetworkParams)
{
    test_GetNetworkParams();
    test_GetNetworkParamsStaleInterface();
}
