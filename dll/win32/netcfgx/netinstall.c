/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Network configuration
 * FILE:              dll/win32/netcfgx/netinstall.c
 * PROGRAMER:         Eric Kohl
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"
#include <rpc.h>


typedef struct _COMPONENT_INFO
{
    PWSTR pszFullInfPath;
    PWSTR pszInfPath;
    PWSTR pszInfSection;
    PWSTR pszComponentId;
    PWSTR pszDescription;
    PWSTR pszClassGuid;
    DWORD dwCharacteristics;
} COMPONENT_INFO, *PCOMPONENT_INFO;


/* GLOBALS ******************************************************************/


/* FUNCTIONS ****************************************************************/

static
BOOL
InstallInfSections(
    _In_ HWND hWnd,
    _In_ HKEY hKey,
    _In_ LPCWSTR InfFile,
    _In_ LPCWSTR InfSection)
{
    WCHAR Buffer[MAX_PATH];
    HINF hInf = INVALID_HANDLE_VALUE;
    UINT BufferSize;
    PVOID Context = NULL;
    BOOL ret = FALSE;

    TRACE("InstallInfSections()\n");

    if (InfSection == NULL)
        return FALSE;

    /* Get Windows directory */
    BufferSize = ARRAYSIZE(Buffer) - 5 - wcslen(InfFile);
    if (GetWindowsDirectoryW(Buffer, BufferSize) > BufferSize)
    {
        /* Function failed */
        SetLastError(ERROR_GEN_FAILURE);
        goto cleanup;
    }

    /* We have enough space to add some information in the buffer */
    if (Buffer[wcslen(Buffer) - 1] != '\\')
        wcscat(Buffer, L"\\");
    wcscat(Buffer, L"Inf\\");
    wcscat(Buffer, InfFile);

    /* Install specified section */
    hInf = SetupOpenInfFileW(Buffer, NULL, INF_STYLE_WIN4, NULL);
    if (hInf == INVALID_HANDLE_VALUE)
        goto cleanup;

    Context = SetupInitDefaultQueueCallback(hWnd);
    if (Context == NULL)
        goto cleanup;

    ret = SetupInstallFromInfSectionW(
                hWnd, hInf,
                InfSection, SPINST_ALL,
                hKey, NULL, SP_COPY_NEWER,
                SetupDefaultQueueCallbackW, Context,
                NULL, NULL);
    if (ret == FALSE)
    {
        ERR("SetupInstallFromInfSectionW(%S) failed (Error %lx)\n", InfSection, GetLastError());
        goto cleanup;
    }

    wcscpy(Buffer, InfSection);
    wcscat(Buffer, L".Services");

    /* A component without a service of its own (TCP/IPv6 is part of the stack that TCP/IPv4 installs) has no .Services section */
    if (SetupGetLineCountW(hInf, Buffer) == -1)
    {
        ret = TRUE;
        goto cleanup;
    }

    ret = SetupInstallServicesFromInfSectionW(hInf, Buffer, 0);
    if (ret == FALSE)
    {
        ERR("SetupInstallServicesFromInfSectionW(%S) failed (Error %lx)\n", Buffer, GetLastError());
        goto cleanup;
    }

cleanup:
    if (Context)
        SetupTermDefaultQueueCallback(Context);

    if (hInf != INVALID_HANDLE_VALUE)
        SetupCloseInfFile(hInf);

    TRACE("InstallInfSections() done %u\n", ret);

    return ret;
}


static
BOOL
CreateInstanceKey(
    _In_ PCOMPONENT_INFO pComponentInfo,
    _Out_ PHKEY pInstanceKey)
{
    WCHAR szKeyBuffer[128];
    LPWSTR UuidString = NULL;
    UUID Uuid;
    RPC_STATUS RpcStatus;
    HKEY hInstanceKey;
    DWORD rc;
    BOOL ret = FALSE;

    TRACE("CreateInstanceKey()\n");

    *pInstanceKey = NULL;

    wcscpy(szKeyBuffer, L"SYSTEM\\CurrentControlSet\\Control\\Network\\");
    wcscat(szKeyBuffer, pComponentInfo->pszClassGuid);
    wcscat(szKeyBuffer, L"\\{");

    /* Create a new UUID */
    RpcStatus = UuidCreate(&Uuid);
    if (RpcStatus != RPC_S_OK && RpcStatus != RPC_S_UUID_LOCAL_ONLY)
    {
        ERR("UuidCreate() failed with RPC status 0x%lx\n", RpcStatus);
        goto done;
    }

    RpcStatus = UuidToStringW(&Uuid, &UuidString);
    if (RpcStatus != RPC_S_OK)
    {
        ERR("UuidToStringW() failed with RPC status 0x%lx\n", RpcStatus);
        goto done;
    }

    wcscat(szKeyBuffer, UuidString);
    wcscat(szKeyBuffer, L"}");

    RpcStringFreeW(&UuidString);

    TRACE("szKeyBuffer %S\n", szKeyBuffer);

    rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                         szKeyBuffer,
                         0,
                         NULL,
                         REG_OPTION_NON_VOLATILE,
                         KEY_CREATE_SUB_KEY | KEY_SET_VALUE,
                         NULL,
                         &hInstanceKey,
                         NULL);
    if (rc != ERROR_SUCCESS)
    {
        ERR("RegCreateKeyExW() failed with error 0x%lx\n", rc);
        goto done;
    }

    rc = RegSetValueExW(hInstanceKey,
                        L"Characteristics",
                        0,
                        REG_DWORD,
                        (LPBYTE)&pComponentInfo->dwCharacteristics,
                        sizeof(DWORD));
    if (rc != ERROR_SUCCESS)
    {
        ERR("RegSetValueExW() failed with error 0x%lx\n", rc);
        goto done;
    }

    rc = RegSetValueExW(hInstanceKey,
                        L"ComponentId",
                        0,
                        REG_SZ,
                        (LPBYTE)pComponentInfo->pszComponentId,
                        (wcslen(pComponentInfo->pszComponentId) + 1) * sizeof(WCHAR));
    if (rc != ERROR_SUCCESS)
    {
        ERR("RegSetValueExW() failed with error 0x%lx\n", rc);
        goto done;
    }

    rc = RegSetValueExW(hInstanceKey,
                        L"Description",
                        0,
                        REG_SZ,
                        (LPBYTE)pComponentInfo->pszDescription,
                        (wcslen(pComponentInfo->pszDescription) + 1) * sizeof(WCHAR));
    if (rc != ERROR_SUCCESS)
    {
        ERR("RegSetValueExW() failed with error 0x%lx\n", rc);
        goto done;
    }

    rc = RegSetValueExW(hInstanceKey,
                        L"InfPath",
                        0,
                        REG_SZ,
                        (LPBYTE)pComponentInfo->pszInfPath,
                        (wcslen(pComponentInfo->pszInfPath) + 1) * sizeof(WCHAR));
    if (rc != ERROR_SUCCESS)
    {
        ERR("RegSetValueExW() failed with error 0x%lx\n", rc);
        goto done;
    }

    rc = RegSetValueExW(hInstanceKey,
                        L"InfSection",
                        0,
                        REG_SZ,
                        (LPBYTE)pComponentInfo->pszInfSection,
                        (wcslen(pComponentInfo->pszInfSection) + 1) * sizeof(WCHAR));
    if (rc != ERROR_SUCCESS)
    {
        ERR("RegSetValueExW() failed with error 0x%lx\n", rc);
        goto done;
    }

    *pInstanceKey = hInstanceKey;
    ret = TRUE;

done:
    if (ret == FALSE)
        RegCloseKey(hInstanceKey);

    TRACE("CreateInstanceKey() done %u\n", ret);

    return ret;
}


static
BOOL
CheckInfFile(
    _In_ PWSTR pszFullInfName,
    _In_ PCWSTR pszComponentId,
    _In_ PCOMPONENT_INFO pComponentInfo)
{
    WCHAR szLineBuffer[MAX_PATH];
    HINF hInf = INVALID_HANDLE_VALUE;
    INFCONTEXT MfgContext, DevContext, MiscContext;
    DWORD dwLength;

    hInf = SetupOpenInfFileW(pszFullInfName,
                             NULL,
                             INF_STYLE_WIN4,
                             NULL);
    if (hInf == INVALID_HANDLE_VALUE)
    {
        ERR("\n");
        return FALSE;
    }

    if (!SetupFindFirstLineW(hInf,
                             L"Manufacturer",
                             NULL,
                             &MfgContext))
    {
        ERR("No Manufacurer section found!\n");
        goto done;
    }

    for (;;)
    {
        if (!SetupGetStringFieldW(&MfgContext,
                                  1,
                                  szLineBuffer,
                                  MAX_PATH,
                                  NULL))
            break;

        TRACE("Manufacturer: %S\n", szLineBuffer);
        if (!SetupFindFirstLineW(hInf,
                                 szLineBuffer,
                                 NULL,
                                 &DevContext))
            break;

        for (;;)
        {
            if (!SetupGetStringFieldW(&DevContext,
                                      2,
                                      szLineBuffer,
                                      MAX_PATH,
                                      NULL))
                break;

            TRACE("Device: %S\n", szLineBuffer);
            if (_wcsicmp(szLineBuffer, pszComponentId) == 0)
            {
                TRACE("Found it!\n");

                /* Get the section name*/
                SetupGetStringFieldW(&DevContext,
                                     1,
                                     NULL,
                                     0,
                                     &dwLength);

                pComponentInfo->pszInfSection = HeapAlloc(GetProcessHeap(),
                                                          0,
                                                          dwLength * sizeof(WCHAR));
                if (pComponentInfo->pszInfSection)
                {
                    SetupGetStringFieldW(&DevContext,
                                         1,
                                         pComponentInfo->pszInfSection,
                                         dwLength,
                                         &dwLength);
                }

                /* Get the description*/
                SetupGetStringFieldW(&DevContext,
                                     0,
                                     NULL,
                                     0,
                                     &dwLength);

                pComponentInfo->pszDescription = HeapAlloc(GetProcessHeap(),
                                                           0,
                                                           dwLength * sizeof(WCHAR));
                if (pComponentInfo->pszDescription)
                {
                    SetupGetStringFieldW(&DevContext,
                                         0,
                                         pComponentInfo->pszDescription,
                                         dwLength,
                                         &dwLength);
                }

                /* Get the class GUID */
                if (SetupFindFirstLineW(hInf,
                                        L"Version",
                                        L"ClassGuid",
                                        &MiscContext))
                {
                    SetupGetStringFieldW(&MiscContext,
                                         1,
                                         NULL,
                                         0,
                                         &dwLength);

                    pComponentInfo->pszClassGuid = HeapAlloc(GetProcessHeap(),
                                                             0,
                                                             dwLength * sizeof(WCHAR));
                    if (pComponentInfo->pszInfSection)
                    {
                        SetupGetStringFieldW(&MiscContext,
                                             1,
                                             pComponentInfo->pszClassGuid,
                                             dwLength,
                                             &dwLength);
                    }
                }

                /* Get the Characteristics value */
                if (SetupFindFirstLineW(hInf,
                                        pComponentInfo->pszInfSection,
                                        L"Characteristics",
                                        &MiscContext))
                {
                    SetupGetIntField(&MiscContext,
                                     1,
                                     (PINT)&pComponentInfo->dwCharacteristics);
                }

                SetupCloseInfFile(hInf);
                return TRUE;
            }

            if (!SetupFindNextLine(&DevContext, &DevContext))
                break;
        }

        if (!SetupFindNextLine(&MfgContext, &MfgContext))
            break;
    }

done:
    if (hInf != INVALID_HANDLE_VALUE)
        SetupCloseInfFile(hInf);

    return FALSE;
}


static
BOOL
ScanForInfFile(
    _In_ PCWSTR pszComponentId,
    _In_ PCOMPONENT_INFO pComponentInfo)
{
    WCHAR szInfPath[MAX_PATH];
    WCHAR szFullInfName[MAX_PATH];
    WCHAR szPathBuffer[MAX_PATH];
    WIN32_FIND_DATAW fdw;
    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    BOOL bFound = FALSE;

    GetWindowsDirectoryW(szInfPath, MAX_PATH);
    wcscat(szInfPath, L"\\inf");

    wcscpy(szPathBuffer, szInfPath);
    wcscat(szPathBuffer, L"\\*.inf");

    hFindFile = FindFirstFileW(szPathBuffer, &fdw);
    if (hFindFile == INVALID_HANDLE_VALUE)
        return FALSE;

    for (;;)
    {
        if (wcscmp(fdw.cFileName, L".") == 0 ||
            wcscmp(fdw.cFileName, L"..") == 0)
            continue;

        TRACE("FileName: %S\n", fdw.cFileName);

        wcscpy(szFullInfName, szInfPath);
        wcscat(szFullInfName, L"\\");
        wcscat(szFullInfName, fdw.cFileName);

        TRACE("Full Inf Name: %S\n", szFullInfName);
        if (CheckInfFile(szFullInfName,
                         pszComponentId,
                         pComponentInfo))
        {
            pComponentInfo->pszFullInfPath = HeapAlloc(GetProcessHeap(),
                                                       0,
                                                       (wcslen(szFullInfName) + 1) * sizeof(WCHAR));
            if (pComponentInfo->pszFullInfPath)
                wcscpy(pComponentInfo->pszFullInfPath, szFullInfName);

            pComponentInfo->pszInfPath = HeapAlloc(GetProcessHeap(),
                                                   0,
                                                   (wcslen(fdw.cFileName) + 1) * sizeof(WCHAR));
            if (pComponentInfo->pszInfPath)
                wcscpy(pComponentInfo->pszInfPath, fdw.cFileName);

            pComponentInfo->pszComponentId = HeapAlloc(GetProcessHeap(),
                                                       0,
                                                       (wcslen(pszComponentId) + 1) * sizeof(WCHAR));
            if (pComponentInfo->pszComponentId)
                wcscpy(pComponentInfo->pszComponentId, pszComponentId);

            bFound = TRUE;
            break;
        }

        if (!FindNextFileW(hFindFile, &fdw))
            break;
    }

    if (hFindFile != INVALID_HANDLE_VALUE)
        FindClose(hFindFile);

    return bFound;
}

static
VOID
StartNetworkServices(
    _In_ PCOMPONENT_INFO pComponentInfo)
{
    WCHAR szServiceName[64];
    HINF hInf = INVALID_HANDLE_VALUE;
    INFCONTEXT Context;
    PWSTR pServiceSection = NULL;

    SC_HANDLE hManager = NULL;
    SC_HANDLE hService = NULL;

    hManager = OpenSCManagerW(NULL,
                              NULL,
                              SC_MANAGER_ALL_ACCESS);
    if (hManager == NULL)
    {
        ERR("\n");
        goto done;
    }

    hInf = SetupOpenInfFileW(pComponentInfo->pszFullInfPath,
                             NULL,
                             INF_STYLE_WIN4,
                             NULL);
    if (hInf == INVALID_HANDLE_VALUE)
    {
        ERR("\n");
        goto done;
    }

    pServiceSection = HeapAlloc(GetProcessHeap(), 0,
                                (wcslen(pComponentInfo->pszInfSection) + wcslen(L".Service") + 1) * sizeof(WCHAR));
    if (pServiceSection == NULL)
    {
        ERR("\n");
        goto done;
    }

    wcscpy(pServiceSection, pComponentInfo->pszInfSection);
    wcscat(pServiceSection, L".Service");

    TRACE("ServiceSection: %S\n", pServiceSection);

    if (!SetupFindFirstLineW(hInf,
                             pServiceSection,
                             L"AddService",
                             &Context))
    {
        ERR("\n");
        goto done;
    }

    for (;;)
    {
        SetupGetStringFieldW(&Context,
                             1,
                             szServiceName,
                             64,
                             NULL);

        hService = OpenServiceW(hManager,
                                szServiceName,
                                SERVICE_START);
        if (hService)
        {
            if (!StartService(hService, 0, NULL))
            {
                ERR("StartService() %S failed %lu\n", szServiceName, GetLastError());
            }

            CloseServiceHandle(hService);
        }

        if (!SetupFindNextLine(&Context, &Context))
            break;
    }

done:
    if (pServiceSection)
        HeapFree(GetProcessHeap(), 0, pServiceSection);

    if (hInf != INVALID_HANDLE_VALUE)
        SetupCloseInfFile(hInf);

    if (hManager != NULL)
        CloseServiceHandle(hManager);
}


/* ---- one instance per component, the Linkage lists, and the upgrade of an install that predates a component ---- */

#define NETWORK_KEY             L"SYSTEM\\CurrentControlSet\\Control\\Network\\"
#define SERVICES_KEY            L"SYSTEM\\CurrentControlSet\\Services\\"
#define NETTRANS_CLASS          L"{4D36E975-E325-11CE-BFC1-08002BE10318}"
#define TCPIP6_CLSID_KEY        L"SOFTWARE\\Classes\\CLSID\\{F3152BFE-301B-4830-981B-D8F31ED16005}"
#define MAX_SEEN_COMPONENTS     64

/* The strings of a multi-sz list without the entry (compared without regard to case), and the entry at the end when
   bPresent. A CoTaskMemAlloc block that ends with an empty string (the list of nothing is two characters), or NULL */
LPWSTR
MultiSzWithEntry(
    _In_opt_ LPCWSTR pszList,
    _In_ LPCWSTR pszEntry,
    _In_ BOOL bPresent)
{
    SIZE_T cchTotal = 1, cchEntry = wcslen(pszEntry);
    LPCWSTR p;
    LPWSTR pszNew, q;

    for (p = pszList; p && *p; p += wcslen(p) + 1)
    {
        if (_wcsicmp(p, pszEntry))
            cchTotal += wcslen(p) + 1;
    }
    if (bPresent)
        cchTotal += cchEntry + 1;

    /* the list of nothing is the terminating character alone (AppendStringToMultiSZ of installer.c appends over it) */
    pszNew = CoTaskMemAlloc(cchTotal * sizeof(WCHAR));
    if (!pszNew)
        return NULL;
    ZeroMemory(pszNew, cchTotal * sizeof(WCHAR));

    q = pszNew;
    for (p = pszList; p && *p; p += wcslen(p) + 1)
    {
        if (_wcsicmp(p, pszEntry))
        {
            wcscpy(q, p);
            q += wcslen(p) + 1;
        }
    }
    if (bPresent)
        wcscpy(q, pszEntry);
    return pszNew;
}

/* A multi-sz value (CoTaskMemAlloc, double-terminated), or NULL when there is none */
static
LPWSTR
ReadMultiSz(
    _In_ HKEY hKey,
    _In_ LPCWSTR pszValue)
{
    DWORD dwType, dwSize = 0;
    LPWSTR pszList;

    if (RegQueryValueExW(hKey, pszValue, NULL, &dwType, NULL, &dwSize) != ERROR_SUCCESS ||
        (dwType != REG_MULTI_SZ && dwType != REG_SZ) || dwSize == 0 || dwSize > 0x10000)
        return NULL;

    pszList = CoTaskMemAlloc(dwSize + 2 * sizeof(WCHAR));
    if (!pszList)
        return NULL;
    ZeroMemory(pszList, dwSize + 2 * sizeof(WCHAR));
    if (RegQueryValueExW(hKey, pszValue, NULL, &dwType, (LPBYTE)pszList, &dwSize) != ERROR_SUCCESS)
    {
        CoTaskMemFree(pszList);
        return NULL;
    }
    return pszList;
}

static
DWORD
WriteMultiSz(
    _In_ HKEY hKey,
    _In_ LPCWSTR pszValue,
    _In_ LPCWSTR pszList)
{
    SIZE_T cch = 0;
    LPCWSTR p;

    for (p = pszList; *p; p += wcslen(p) + 1)
        cch += wcslen(p) + 1;
    cch++;
    return RegSetValueExW(hKey, pszValue, 0, REG_MULTI_SZ, (const BYTE *)pszList, (DWORD)(cch * sizeof(WCHAR)));
}

/* Adds the entry to a list value of the key, or takes it out (the value is made when it was not there) */
static
VOID
UpdateLinkageValue(
    _In_ HKEY hKey,
    _In_ LPCWSTR pszValue,
    _In_ LPCWSTR pszEntry,
    _In_ BOOL bPresent)
{
    LPWSTR pszOld = ReadMultiSz(hKey, pszValue);
    LPWSTR pszNew = MultiSzWithEntry(pszOld, pszEntry, bPresent);

    if (pszNew)
        WriteMultiSz(hKey, pszValue, pszNew);
    CoTaskMemFree(pszOld);
    CoTaskMemFree(pszNew);
}

/* Writes the bindings that INetCfgComponentBindings::BindTo and UnbindFrom recorded: the adapter goes into or out of the
   Bind (\Device\<adapter>), Export (\Device\<service>_<adapter>) and Route (<adapter>) lists of the service's Linkage key */
VOID
WriteBindingChanges(
    _In_ const NetCfgComponentItem *pItem)
{
    WCHAR szKey[128], szDevice[128], szExport[160];
    LPCWSTR p;
    HKEY hKey;

    if (!pItem->szBindName || !pItem->pszBindChanges || wcslen(pItem->szBindName) > 40)
        return;

    _swprintf(szKey, SERVICES_KEY L"%s\\Linkage", pItem->szBindName);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return;

    for (p = pItem->pszBindChanges; *p; p += wcslen(p) + 1)
    {
        BOOL bBound = (*p == L'+');
        LPCWSTR pszAdapter = p + 1;

        if (wcslen(pszAdapter) > 60)
            continue;
        _swprintf(szDevice, L"\\Device\\%s", pszAdapter);
        _swprintf(szExport, L"\\Device\\%s_%s", pItem->szBindName, pszAdapter);
        UpdateLinkageValue(hKey, L"Bind", szDevice, bBound);
        UpdateLinkageValue(hKey, L"Export", szExport, bBound);
        UpdateLinkageValue(hKey, L"Route", pszAdapter, bBound);
    }
    RegCloseKey(hKey);
}

/*
 * Does the class have a complete instance of the component (an instance key with Ndi\Service)? An instance of it
 * without one is what an install that failed half way leaves: removed when bRepair, so that the install is made again.
 */
static
BOOL
FindInstanceKey(
    _In_ LPCWSTR pszClassGuid,
    _In_ LPCWSTR pszComponentId,
    _In_ BOOL bRepair)
{
    WCHAR szPath[160], szName[64], szId[128];
    HKEY hClass, hInstance, hNdi;
    DWORD dwIndex = 0, dwSize, dwType;
    BOOL bFound = FALSE;

    if (wcslen(pszClassGuid) > 60)
        return FALSE;
    _swprintf(szPath, NETWORK_KEY L"%s", pszClassGuid);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szPath, 0, KEY_READ | KEY_WRITE, &hClass) != ERROR_SUCCESS)
        return FALSE;

    for (;;)
    {
        BOOL bMatch = FALSE, bComplete = FALSE;

        dwSize = ARRAYSIZE(szName);
        if (RegEnumKeyExW(hClass, dwIndex, szName, &dwSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        if (RegOpenKeyExW(hClass, szName, 0, KEY_READ, &hInstance) == ERROR_SUCCESS)
        {
            dwSize = sizeof(szId) - sizeof(WCHAR);
            ZeroMemory(szId, sizeof(szId));
            if (RegQueryValueExW(hInstance, L"ComponentId", NULL, &dwType, (LPBYTE)szId, &dwSize) == ERROR_SUCCESS &&
                dwType == REG_SZ && !_wcsicmp(szId, pszComponentId))
            {
                bMatch = TRUE;
                if (RegOpenKeyExW(hInstance, L"Ndi", 0, KEY_READ, &hNdi) == ERROR_SUCCESS)
                {
                    bComplete = (RegQueryValueExW(hNdi, L"Service", NULL, NULL, NULL, NULL) == ERROR_SUCCESS);
                    RegCloseKey(hNdi);
                }
            }
            RegCloseKey(hInstance);
        }

        if (bMatch && bComplete)
        {
            bFound = TRUE;
            break;
        }
        if (bMatch && bRepair && RegDeleteTreeW(hClass, szName) == ERROR_SUCCESS)
            continue;   /* the next key has this index now */
        dwIndex++;
    }

    RegCloseKey(hClass);
    return bFound;
}

/* The second and later instances of one component in the class are removed (the first one in key order stays, the
   one the property list shows): what the install of TCP/IPv4 by both the setup and its network step left */
static
VOID
RemoveDuplicateInstances(
    _In_ LPCWSTR pszClassGuid)
{
    WCHAR szPath[160], szName[64], szId[128];
    WCHAR (*Seen)[100];
    HKEY hClass, hInstance;
    DWORD dwIndex = 0, dwSize, dwType, cSeen = 0, i;

    if (wcslen(pszClassGuid) > 60)
        return;
    _swprintf(szPath, NETWORK_KEY L"%s", pszClassGuid);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szPath, 0, KEY_READ | KEY_WRITE, &hClass) != ERROR_SUCCESS)
        return;

    Seen = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_SEEN_COMPONENTS * sizeof(*Seen));
    if (!Seen)
    {
        RegCloseKey(hClass);
        return;
    }

    for (;;)
    {
        BOOL bDuplicate = FALSE;

        dwSize = ARRAYSIZE(szName);
        if (RegEnumKeyExW(hClass, dwIndex, szName, &dwSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        if (RegOpenKeyExW(hClass, szName, 0, KEY_READ, &hInstance) == ERROR_SUCCESS)
        {
            dwSize = sizeof(szId) - sizeof(WCHAR);
            ZeroMemory(szId, sizeof(szId));
            if (RegQueryValueExW(hInstance, L"ComponentId", NULL, &dwType, (LPBYTE)szId, &dwSize) == ERROR_SUCCESS &&
                dwType == REG_SZ && szId[0] && wcslen(szId) < ARRAYSIZE(Seen[0]))
            {
                for (i = 0; i < cSeen; i++)
                {
                    if (!_wcsicmp(Seen[i], szId))
                    {
                        bDuplicate = TRUE;
                        break;
                    }
                }
                if (!bDuplicate && cSeen < MAX_SEEN_COMPONENTS)
                    wcscpy(Seen[cSeen++], szId);
            }
            RegCloseKey(hInstance);
        }

        if (bDuplicate && RegDeleteTreeW(hClass, szName) == ERROR_SUCCESS)
            continue;
        dwIndex++;
    }

    HeapFree(GetProcessHeap(), 0, Seen);
    RegCloseKey(hClass);
}

/* The Linkage lists of TCP/IPv6 start as the adapters TCP/IPv4 is bound to; it is bound to every adapter that is installed
   afterwards (installer.c). The lists are not touched once there: an adapter taken out by the user stays out */
static
VOID
EnsureTcpip6Linkage(VOID)
{
    HKEY hSource = NULL, hLinkage = NULL;
    LPWSTR pszBind = NULL, pszNewBind = NULL, pszExport = NULL, pszRoute = NULL;
    LPCWSTR p;
    WCHAR szExport[160];

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, SERVICES_KEY L"Tcpip6\\Linkage", 0, NULL, REG_OPTION_NON_VOLATILE,
                        KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &hLinkage, NULL) != ERROR_SUCCESS)
        return;

    if (RegQueryValueExW(hLinkage, L"Bind", NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        goto done;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SERVICES_KEY L"Tcpip\\Linkage", 0, KEY_QUERY_VALUE, &hSource) == ERROR_SUCCESS)
        pszBind = ReadMultiSz(hSource, L"Bind");

    for (p = pszBind; p && *p; p += wcslen(p) + 1)
    {
        LPWSTR pszTemp;

        if (wcslen(p) <= 8 || wcslen(p) > 60)
            continue;   /* \Device\<adapter> */

        pszTemp = MultiSzWithEntry(pszNewBind, p, TRUE);
        CoTaskMemFree(pszNewBind);
        pszNewBind = pszTemp;
        _swprintf(szExport, L"\\Device\\Tcpip6_%s", p + 8);
        pszTemp = MultiSzWithEntry(pszExport, szExport, TRUE);
        CoTaskMemFree(pszExport);
        pszExport = pszTemp;
        pszTemp = MultiSzWithEntry(pszRoute, p + 8, TRUE);
        CoTaskMemFree(pszRoute);
        pszRoute = pszTemp;
    }

    /* The lists are there, empty or not: that is what tells installer.c that the component is installed */
    if (!pszNewBind)
        pszNewBind = MultiSzWithEntry(NULL, L"", FALSE);
    if (!pszExport)
        pszExport = MultiSzWithEntry(NULL, L"", FALSE);
    if (!pszRoute)
        pszRoute = MultiSzWithEntry(NULL, L"", FALSE);
    if (pszNewBind && pszExport && pszRoute)
    {
        WriteMultiSz(hLinkage, L"Export", pszExport);
        WriteMultiSz(hLinkage, L"Route", pszRoute);
        WriteMultiSz(hLinkage, L"Bind", pszNewBind);
    }

done:
    CoTaskMemFree(pszBind);
    CoTaskMemFree(pszNewBind);
    CoTaskMemFree(pszExport);
    CoTaskMemFree(pszRoute);
    if (hSource)
        RegCloseKey(hSource);
    RegCloseKey(hLinkage);
}

static
VOID
EnsureComponentLinkage(
    _In_ LPCWSTR pszComponentId)
{
    if (!_wcsicmp(pszComponentId, L"MS_TCPIP6"))
        EnsureTcpip6Linkage();
}

/* The notify object of TCP/IPv6 is in the CLASSES hive of a new install (hivecls.inf); an install that predates it gets
   the same keys here */
static
DWORD
RegisterTcpip6NotifyObject(VOID)
{
    HKEY hKey, hServer;
    DWORD dwError;
    static const WCHAR szName[] = L"TCP/IPv6 Configuration Notify Object";
    static const WCHAR szServer[] = L"netcfgx.dll";
    static const WCHAR szModel[] = L"Both";

    dwError = RegCreateKeyExW(HKEY_LOCAL_MACHINE, TCPIP6_CLSID_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                              KEY_CREATE_SUB_KEY | KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &hKey, NULL);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    if (RegQueryValueExW(hKey, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
        dwError = RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE *)szName, sizeof(szName));

    if (dwError == ERROR_SUCCESS)
        dwError = RegCreateKeyExW(hKey, L"InProcServer32", 0, NULL, REG_OPTION_NON_VOLATILE,
                                  KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &hServer, NULL);
    if (dwError == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(hServer, NULL, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            dwError = RegSetValueExW(hServer, NULL, 0, REG_SZ, (const BYTE *)szServer, sizeof(szServer));
        if (dwError == ERROR_SUCCESS && RegQueryValueExW(hServer, L"ThreadingModel", NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            dwError = RegSetValueExW(hServer, L"ThreadingModel", 0, REG_SZ, (const BYTE *)szModel, sizeof(szModel));
        RegCloseKey(hServer);
    }
    RegCloseKey(hKey);
    return dwError;
}

/*
 * What winlogon runs (through userenv, netupgrade.c) at the start after the INF changed: one instance of every
 * component (the duplicates an older install made are removed) and the TCP/IPv6 component, with its notify object
 * and its Linkage lists, on an install that has none. Idempotent. Returns a Win32 error, ERROR_SUCCESS when settled.
 */
DWORD
UpgradeNetworkComponents(VOID)
{
    DWORD dwError;

    RemoveDuplicateInstances(NETTRANS_CLASS);

    dwError = RegisterTcpip6NotifyObject();
    if (dwError != ERROR_SUCCESS)
        return dwError;

    if (!InstallNetworkComponent(L"MS_TCPIP6"))
    {
        dwError = GetLastError();
        return dwError != ERROR_SUCCESS ? dwError : ERROR_GEN_FAILURE;
    }
    EnsureTcpip6Linkage();
    return ERROR_SUCCESS;
}

BOOL
WINAPI
NitroUpgradeNetworkComponents(VOID)
{
    DWORD dwError = UpgradeNetworkComponents();

    SetLastError(dwError);
    return dwError == ERROR_SUCCESS;
}

BOOL
InstallNetworkComponent(
    _In_ PCWSTR pszComponentId)
{
    COMPONENT_INFO ComponentInfo;
    HKEY hInstanceKey = NULL;
    BOOL bResult = FALSE;

    TRACE("InstallNetworkComponent(%S)\n", pszComponentId);

    ZeroMemory(&ComponentInfo, sizeof(COMPONENT_INFO));

    if (!ScanForInfFile(pszComponentId, &ComponentInfo))
        goto done;

    TRACE("Characteristics: 0x%lx\n", ComponentInfo.dwCharacteristics);
    TRACE("ComponentId: %S\n", ComponentInfo.pszComponentId);
    TRACE("Description: %S\n", ComponentInfo.pszDescription);
    TRACE("InfPath: %S\n", ComponentInfo.pszInfPath);
    TRACE("InfSection: %S\n", ComponentInfo.pszInfSection);
    TRACE("ClassGuid: %S\n", ComponentInfo.pszClassGuid);

    /* One instance per component: a second install of one (the setup and its network step both install TCP/IPv4) is
       a no-op, not a second row in every connection's property list */
    if (FindInstanceKey(ComponentInfo.pszClassGuid, ComponentInfo.pszComponentId, TRUE))
    {
        TRACE("%S is installed already\n", ComponentInfo.pszComponentId);
        bResult = TRUE;
        EnsureComponentLinkage(ComponentInfo.pszComponentId);
        goto done;
    }

    if (!CreateInstanceKey(&ComponentInfo,
                           &hInstanceKey))
    {
        ERR("CreateInstanceKey() failed (Error %lx)\n", GetLastError());
        goto done;
    }

    if (!InstallInfSections(NULL,
                            hInstanceKey,
                            ComponentInfo.pszInfPath,
                            ComponentInfo.pszInfSection))
    {
        ERR("InstallInfSections() failed (Error %lx)\n", GetLastError());
        goto done;
    }

    bResult = TRUE;

    StartNetworkServices(&ComponentInfo);

done:
    if (hInstanceKey != NULL)
        RegCloseKey(hInstanceKey);

    if (ComponentInfo.pszFullInfPath)
        HeapFree(GetProcessHeap(), 0, ComponentInfo.pszFullInfPath);

    if (ComponentInfo.pszInfPath)
        HeapFree(GetProcessHeap(), 0, ComponentInfo.pszInfPath);

    if (ComponentInfo.pszInfSection)
        HeapFree(GetProcessHeap(), 0, ComponentInfo.pszInfSection);

    if (ComponentInfo.pszComponentId)
        HeapFree(GetProcessHeap(), 0, ComponentInfo.pszComponentId);

    if (ComponentInfo.pszDescription)
        HeapFree(GetProcessHeap(), 0, ComponentInfo.pszDescription);

    if (ComponentInfo.pszClassGuid)
        HeapFree(GetProcessHeap(), 0, ComponentInfo.pszClassGuid);

    return bResult;
}

/* EOF */
