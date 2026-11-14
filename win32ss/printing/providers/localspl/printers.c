/*
 * PROJECT:     ReactOS Local Spooler
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Functions related to Printers and printing
 * COPYRIGHT:   Copyright 2015-2017 Colin Finck (colin@reactos.org)
 */

#include "precomp.h"

// Global Variables
SKIPLIST PrinterList;

// Serializes deleting a printer with creating jobs for it.
CRITICAL_SECTION PrinterDeletionSection;

// Forward Declarations
static void _LocalGetPrinterLevel0(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_STRESS* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel1(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_1W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel2(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_2W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel3(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_3* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel4(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_4W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel5(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_5W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel6(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_6* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel7(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_7W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel8(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_8W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);
static void _LocalGetPrinterLevel9(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_9W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName);

// Local Constants
typedef void (*PLocalGetPrinterLevelFunc)(PLOCAL_PRINTER, PVOID, PBYTE*, PDWORD, DWORD, PCWSTR);

static const PLocalGetPrinterLevelFunc pfnGetPrinterLevels[] = {
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel0,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel1,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel2,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel3,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel4,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel5,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel6,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel7,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel8,
    (PLocalGetPrinterLevelFunc)&_LocalGetPrinterLevel9
};

static DWORD dwPrinterInfo0Offsets[] = {
    FIELD_OFFSET(PRINTER_INFO_STRESS, pPrinterName),
    MAXDWORD
};

static DWORD dwPrinterInfo1Offsets[] = {
    FIELD_OFFSET(PRINTER_INFO_1W, pName),
    FIELD_OFFSET(PRINTER_INFO_1W, pComment),
    FIELD_OFFSET(PRINTER_INFO_1W, pDescription),
    MAXDWORD
};

static DWORD dwPrinterInfo2Offsets[] = {
    FIELD_OFFSET(PRINTER_INFO_2W, pPrinterName),
    FIELD_OFFSET(PRINTER_INFO_2W, pShareName),
    FIELD_OFFSET(PRINTER_INFO_2W, pPortName),
    FIELD_OFFSET(PRINTER_INFO_2W, pDriverName),
    FIELD_OFFSET(PRINTER_INFO_2W, pComment),
    FIELD_OFFSET(PRINTER_INFO_2W, pLocation),
    FIELD_OFFSET(PRINTER_INFO_2W, pSepFile),
    FIELD_OFFSET(PRINTER_INFO_2W, pPrintProcessor),
    FIELD_OFFSET(PRINTER_INFO_2W, pDatatype),
    FIELD_OFFSET(PRINTER_INFO_2W, pParameters),
    MAXDWORD
};

static DWORD dwPrinterInfo4Offsets[] = {
    FIELD_OFFSET(PRINTER_INFO_4W, pPrinterName),
    MAXDWORD
};

static DWORD dwPrinterInfo5Offsets[] = {
    FIELD_OFFSET(PRINTER_INFO_5W, pPrinterName),
    FIELD_OFFSET(PRINTER_INFO_5W, pPortName),
    MAXDWORD
};

/** These values serve no purpose anymore, but are still used in PRINTER_INFO_5 and
    HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts */
static const DWORD dwDeviceNotSelectedTimeout = 15000;
static const DWORD dwTransmissionRetryTimeout = 45000;


/**
 * @name _PrinterListCompareRoutine
 *
 * SKIPLIST_COMPARE_ROUTINE for the Printer List.
 * Does a case-insensitive comparison, because e.g. LocalOpenPrinter doesn't match the case when looking for Printers.
 */
static int WINAPI
_PrinterListCompareRoutine(PVOID FirstStruct, PVOID SecondStruct)
{
    PLOCAL_PRINTER A = (PLOCAL_PRINTER)FirstStruct;
    PLOCAL_PRINTER B = (PLOCAL_PRINTER)SecondStruct;

    return _wcsicmp(A->pwszPrinterName, B->pwszPrinterName);
}

/**
 * @name InitializePrinterList
 *
 * Initializes a list of locally available Printers.
 * The list is searchable by name and returns information about the printers, including their job queues.
 * During this process, the job queues are also initialized.
 */
BOOL
InitializePrinterList(VOID)
{
    DWORD cbData;
    DWORD cchPrinterName;
    DWORD dwErrorCode;
    DWORD dwSubKeys;
    DWORD i;
    HKEY hSubKey = NULL;
    PLOCAL_PORT pPort;
    PLOCAL_PRINTER pPrinter = NULL;
    PLOCAL_PRINT_PROCESSOR pPrintProcessor;
    PWSTR pwszPort = NULL;
    PWSTR pwszPrintProcessor = NULL;
    WCHAR wszPrinterName[MAX_PRINTER_NAME + 1];

    TRACE("InitializePrinterList()\n");

    // Initialize an empty list for our printers.
    InitializeSkiplist(&PrinterList, DllAllocSplMem, _PrinterListCompareRoutine, (PSKIPLIST_FREE_ROUTINE)DllFreeSplMem);
    InitializeCriticalSection(&PrinterDeletionSection);

    // Get the number of subkeys of the printers registry key. Each subkey is a local printer there.
    dwErrorCode = (DWORD)RegQueryInfoKeyW(hPrintersKey, NULL, NULL, NULL, &dwSubKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (dwErrorCode != ERROR_SUCCESS)
    {
        ERR("RegQueryInfoKeyW failed with status %lu!\n", dwErrorCode);
        goto Cleanup;
    }

    // Loop through all available local printers.
    for (i = 0; i < dwSubKeys; i++)
    {
        // Cleanup tasks from the previous run
        if (hSubKey)
        {
            RegCloseKey(hSubKey);
            hSubKey = NULL;
        }

        if (pPrinter)
        {
            if (pPrinter->pDefaultDevMode)
                DllFreeSplMem(pPrinter->pDefaultDevMode);

            if (pPrinter->pwszDefaultDatatype)
                DllFreeSplStr(pPrinter->pwszDefaultDatatype);

            if (pPrinter->pwszDescription)
                DllFreeSplStr(pPrinter->pwszDescription);

            if (pPrinter->pwszPrinterDriver)
                DllFreeSplStr(pPrinter->pwszPrinterDriver);

            if (pPrinter->pwszPrinterName)
                DllFreeSplStr(pPrinter->pwszPrinterName);

            DllFreeSplMem(pPrinter);
            pPrinter = NULL;
        }

        if (pwszPrintProcessor)
        {
            DllFreeSplStr(pwszPrintProcessor);
            pwszPrintProcessor = NULL;
        }

        // Get the name of this printer.
        cchPrinterName = _countof(wszPrinterName);
        dwErrorCode = (DWORD)RegEnumKeyExW(hPrintersKey, i, wszPrinterName, &cchPrinterName, NULL, NULL, NULL, NULL);
        if (dwErrorCode == ERROR_MORE_DATA)
        {
            // This printer name exceeds the maximum length and is invalid.
            continue;
        }
        else if (dwErrorCode != ERROR_SUCCESS)
        {
            ERR("RegEnumKeyExW failed for iteration %lu with status %lu!\n", i, dwErrorCode);
            continue;
        }

        // Open this Printer's registry key.
        dwErrorCode = (DWORD)RegOpenKeyExW(hPrintersKey, wszPrinterName, 0, KEY_READ, &hSubKey);
        if (dwErrorCode != ERROR_SUCCESS)
        {
            ERR("RegOpenKeyExW failed for Printer \"%S\" with status %lu!\n", wszPrinterName, dwErrorCode);
            continue;
        }

        // Get the Print Processor.
        pwszPrintProcessor = AllocAndRegQueryWSZ(hSubKey, L"Print Processor");
        if (!pwszPrintProcessor)
            continue;

        // Try to find it in the Print Processor List.
        pPrintProcessor = FindPrintProcessor(pwszPrintProcessor);
        if (!pPrintProcessor)
        {
            ERR("Invalid Print Processor \"%S\" for Printer \"%S\"!\n", pwszPrintProcessor, wszPrinterName);
            continue;
        }

        // Get the Port.
        pwszPort = AllocAndRegQueryWSZ(hSubKey, L"Port");
        if (!pwszPort)
            continue;

        // Try to find it in the Port List.
        pPort = FindPort(pwszPort);
        if (!pPort)
        {
            ERR("Invalid Port \"%S\" for Printer \"%S\"!\n", pwszPort, wszPrinterName);
            continue;
        }

        // Create a new LOCAL_PRINTER structure for it.
        pPrinter = DllAllocSplMem(sizeof(LOCAL_PRINTER));
        if (!pPrinter)
        {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            ERR("DllAllocSplMem failed!\n");
            goto Cleanup;
        }

        pPrinter->pwszPrinterName = AllocSplStr(wszPrinterName);
        pPrinter->pPrintProcessor = pPrintProcessor;
        pPrinter->pPort = pPort;
        InitializePrinterJobList(pPrinter);

        // Get the location.
        pPrinter->pwszLocation = AllocAndRegQueryWSZ(hSubKey, L"Location");
        if (!pPrinter->pwszLocation)
            continue;

        // Get the printer driver.
        pPrinter->pwszPrinterDriver = AllocAndRegQueryWSZ(hSubKey, L"Printer Driver");
        if (!pPrinter->pwszPrinterDriver)
            continue;

        // Get the description.
        pPrinter->pwszDescription = AllocAndRegQueryWSZ(hSubKey, L"Description");
        if (!pPrinter->pwszDescription)
            continue;

        // Get the default datatype.
        pPrinter->pwszDefaultDatatype = AllocAndRegQueryWSZ(hSubKey, L"Datatype");
        if (!pPrinter->pwszDefaultDatatype)
            continue;

        // Verify that it's valid.
        if (!FindDatatype(pPrintProcessor, pPrinter->pwszDefaultDatatype))
        {
            ERR("Invalid default datatype \"%S\" for Printer \"%S\"!\n", pPrinter->pwszDefaultDatatype, wszPrinterName);
            continue;
        }

        // Determine the size of the DevMode.
        dwErrorCode = (DWORD)RegQueryValueExW(hSubKey, L"Default DevMode", NULL, NULL, NULL, &cbData);
        if (dwErrorCode != ERROR_SUCCESS)
        {
            ERR("Couldn't query the size of the DevMode for Printer \"%S\", status is %lu, cbData is %lu!\n", wszPrinterName, dwErrorCode, cbData);
            continue;
        }

        // Allocate enough memory for the DevMode.
        pPrinter->pDefaultDevMode = DllAllocSplMem(cbData);
        if (!pPrinter->pDefaultDevMode)
        {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            ERR("DllAllocSplMem failed!\n");
            goto Cleanup;
        }

        // Get the default DevMode.
        dwErrorCode = (DWORD)RegQueryValueExW(hSubKey, L"Default DevMode", NULL, NULL, (PBYTE)pPrinter->pDefaultDevMode, &cbData);
        if (dwErrorCode != ERROR_SUCCESS)
        {
            ERR("Couldn't query a DevMode for Printer \"%S\", status is %lu, cbData is %lu!\n", wszPrinterName, dwErrorCode, cbData);
            continue;
        }

        // Get the Attributes.
        cbData = sizeof(DWORD);
        dwErrorCode = (DWORD)RegQueryValueExW(hSubKey, L"Attributes", NULL, NULL, (PBYTE)&pPrinter->dwAttributes, &cbData);
        if (dwErrorCode != ERROR_SUCCESS)
        {
            ERR("Couldn't query Attributes for Printer \"%S\", status is %lu!\n", wszPrinterName, dwErrorCode);
            continue;
        }

        // Get the Status.
        cbData = sizeof(DWORD);
        dwErrorCode = (DWORD)RegQueryValueExW(hSubKey, L"Status", NULL, NULL, (PBYTE)&pPrinter->dwStatus, &cbData);
        if (dwErrorCode != ERROR_SUCCESS)
        {
            ERR("Couldn't query Status for Printer \"%S\", status is %lu!\n", wszPrinterName, dwErrorCode);
            continue;
        }

        // Add this printer to the printer list.
        if (!InsertElementSkiplist(&PrinterList, pPrinter))
        {
            ERR("InsertElementSkiplist failed for Printer \"%S\"!\n", pPrinter->pwszPrinterName);
            goto Cleanup;
        }

        // Don't let the cleanup routines free this.
        pPrinter = NULL;
    }

    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    // Inside the loop
    if (hSubKey)
        RegCloseKey(hSubKey);

    if (pPrinter)
    {
        if (pPrinter->pDefaultDevMode)
            DllFreeSplMem(pPrinter->pDefaultDevMode);

        if (pPrinter->pwszDefaultDatatype)
            DllFreeSplStr(pPrinter->pwszDefaultDatatype);

        if (pPrinter->pwszDescription)
            DllFreeSplStr(pPrinter->pwszDescription);

        if (pPrinter->pwszPrinterDriver)
            DllFreeSplStr(pPrinter->pwszPrinterDriver);

        if (pPrinter->pwszPrinterName)
            DllFreeSplStr(pPrinter->pwszPrinterName);

        DllFreeSplMem(pPrinter);
    }

    if (pwszPrintProcessor)
        DllFreeSplStr(pwszPrintProcessor);

    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

VOID
BroadcastChange(PLOCAL_HANDLE pHandle)
{
    PLOCAL_PRINTER pPrinter;
    PSKIPLIST_NODE pNode;
    DWORD cchMachineName = 0;
    WCHAR wszMachineName[MAX_PATH] = {0}; // if not local, use Machine Name then Printer Name... pPrinter->pJob->pwszMachineName?

    for (pNode = PrinterList.Head.Next[0]; pNode; pNode = pNode->Next[0])
    {
        pPrinter = (PLOCAL_PRINTER)pNode->Element;

        StringCchCopyW( &wszMachineName[cchMachineName], sizeof(wszMachineName), pPrinter->pwszPrinterName );

        PostMessageW( HWND_BROADCAST, WM_DEVMODECHANGE, 0, (LPARAM)&wszMachineName );
    }
}

/**
 * @name _LocalEnumPrintersCheckName
 *
 * Checks the Name parameter supplied to a call to EnumPrinters.
 *
 * @param Flags
 * Flags parameter of EnumPrinters.
 *
 * @param Name
 * Name parameter of EnumPrinters to check.
 *
 * @param pwszComputerName
 * Pointer to a string able to hold 2 + MAX_COMPUTERNAME_LENGTH + 1 + 1 characters.
 * On return, it may contain a computer name to prepend in EnumPrinters depending on the case.
 *
 * @param pcchComputerName
 * If a string to prepend is returned, this pointer receives its length in characters.
 *
 * @return
 * ERROR_SUCCESS if processing in EnumPrinters can be continued.
 * ERROR_INVALID_NAME if the Name parameter is invalid for the given flags and this Print Provider.
 * Any other error code if GetComputerNameW fails. Error codes indicating failure should then be returned by EnumPrinters.
 */
static DWORD
_LocalEnumPrintersCheckName(DWORD Flags, PCWSTR Name, PWSTR pwszComputerName, PDWORD pcchComputerName)
{
    PCWSTR pName;
    PCWSTR pComputerName;

    // If there is no Name parameter to check, we can just continue in EnumPrinters.
    if (!Name)
        return ERROR_SUCCESS;

    // Check if Name does not begin with two backslashes (required for specifying Computer Names).
    if (Name[0] != L'\\' || Name[1] != L'\\')
    {
        if (Flags & PRINTER_ENUM_NAME)
        {
            // If PRINTER_ENUM_NAME is specified, any given Name parameter may only contain the
            // Print Provider Name or the local Computer Name.

            // Compare with the Print Provider Name.
            if (_wcsicmp(Name, wszPrintProviderInfo[0]) == 0)
                return ERROR_SUCCESS;

            // Dismiss anything else.
            return ERROR_INVALID_NAME;
        }
        else
        {
            // If PRINTER_ENUM_NAME is not specified, we just ignore anything that is not a Computer Name.
            return ERROR_SUCCESS;
        }
    }

    // Prepend the backslashes to the output computer name.
    pwszComputerName[0] = L'\\';
    pwszComputerName[1] = L'\\';

    // Get the local computer name for comparison.
    *pcchComputerName = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(&pwszComputerName[2], pcchComputerName))
    {
        ERR("GetComputerNameW failed with error %lu!\n", GetLastError());
        return GetLastError();
    }

    // Add the leading slashes to the total length.
    *pcchComputerName += 2;

    // Compare both names.
    pComputerName = &pwszComputerName[2];
    pName = &Name[2];
    for (;;)
    {
        // Are we at the end of the local Computer Name string?
        if (!*pComputerName)
        {
            // Are we also at the end of the supplied Name parameter?
            // A terminating NUL character and a backslash are both treated as the end, but they are treated differently.
            if (!*pName)
            {
                // If both names match and Name ends with a NUL character, the computer name will be prepended in EnumPrinters.
                // Add a trailing backslash for that.
                pwszComputerName[(*pcchComputerName)++] = L'\\';
                pwszComputerName[*pcchComputerName] = 0;
                return ERROR_SUCCESS;
            }
            else if (*pName == L'\\')
            {
                if (Flags & PRINTER_ENUM_NAME)
                {
                    // If PRINTER_ENUM_NAME is specified and a Name parameter is given, it must be exactly the local
                    // Computer Name with two backslashes prepended. Anything else (like "\\COMPUTERNAME\") is dismissed.
                    return ERROR_INVALID_NAME;
                }
                else
                {
                    // If PRINTER_ENUM_NAME is not specified and a Name parameter is given, it may also end with a backslash.
                    // Only the Computer Name between the backslashes is checked then.
                    // This is largely undocumented, but verified by tests (see winspool_apitest).
                    // In this case, no computer name is prepended in EnumPrinters though.
                    *pwszComputerName = 0;
                    *pcchComputerName = 0;
                    return ERROR_SUCCESS;
                }
            }
        }

        // Compare both Computer Names case-insensitively and reject with ERROR_INVALID_NAME if they don't match.
        if (towlower(*pName) != towlower(*pComputerName))
            return ERROR_INVALID_NAME;

        pName++;
        pComputerName++;
    }
}

static DWORD
_DumpLevel1PrintProviderInformation(PBYTE pPrinterEnum, DWORD cbBuf, PDWORD pcbNeeded, PDWORD pcReturned)
{
    int i;

    // Count the needed bytes for Print Provider information.
    *pcbNeeded = sizeof(PRINTER_INFO_1W);

    for (i = 0; i < 3; i++)
        *pcbNeeded += (wcslen(wszPrintProviderInfo[i]) + 1) * sizeof(WCHAR);

    // Check if the supplied buffer is large enough.
    if (cbBuf < *pcbNeeded)
        return ERROR_INSUFFICIENT_BUFFER;

    // Copy over the Print Provider information.
    ((PPRINTER_INFO_1W)pPrinterEnum)->Flags = 0;
    PackStrings(wszPrintProviderInfo, pPrinterEnum, dwPrinterInfo1Offsets, &pPrinterEnum[*pcbNeeded]);
    *pcReturned = 1;

    return ERROR_SUCCESS;
}

static void
_LocalGetPrinterLevel0(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_STRESS* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    size_t cbName;
    PWSTR p, Allocation;
    PCWSTR pwszStrings[1];
    SYSTEM_INFO SystemInfo;

    // Calculate the string lengths.
    cbName = (cchComputerName + wcslen(pPrinter->pwszPrinterName) + 1) * sizeof(WCHAR);

    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_STRESS) + cbName;
        return;
    }

    // Set the general fields.
    ZeroMemory(*ppPrinterInfo, sizeof(PRINTER_INFO_STRESS));
    (*ppPrinterInfo)->cJobs = pPrinter->JobList.NodeCount;
    (*ppPrinterInfo)->dwGetVersion = GetVersion();
    (*ppPrinterInfo)->Status = pPrinter->dwStatus;

#if !DBG
    (*ppPrinterInfo)->fFreeBuild = 1;
#endif

    GetSystemInfo(&SystemInfo);
    (*ppPrinterInfo)->dwNumberOfProcessors = SystemInfo.dwNumberOfProcessors;
    (*ppPrinterInfo)->dwProcessorType = SystemInfo.dwProcessorType;
    (*ppPrinterInfo)->wProcessorArchitecture = SystemInfo.wProcessorArchitecture;
    (*ppPrinterInfo)->wProcessorLevel = SystemInfo.wProcessorLevel;

    // Copy the Printer Name.
    p = Allocation = DllAllocSplMem(cbName);
    pwszStrings[0] = Allocation;
    StringCbCopyExW(p, cbName, wszComputerName, &p, &cbName, 0);
    StringCbCopyExW(p, cbName, pPrinter->pwszPrinterName, &p, &cbName, 0);

    // Finally copy the structure and advance to the next one in the output buffer.
    *ppPrinterInfoEnd = PackStrings(pwszStrings, (PBYTE)(*ppPrinterInfo), dwPrinterInfo0Offsets, *ppPrinterInfoEnd);
    (*ppPrinterInfo)++;

    // Free the memory for temporary strings.
    DllFreeSplMem(Allocation);
}

static void
_LocalGetPrinterLevel1(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_1W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    const WCHAR wszComma[] = L",";

    size_t cbName;
    size_t cbComment;
    size_t cbDescription;
    PWSTR p, Allocation1, Allocation2;
    PCWSTR pwszStrings[3];

    // Calculate the string lengths.
    // Attention: pComment equals the "Description" registry value while pDescription is concatenated out of several strings.
    // On top of this, the computer name is prepended to the printer name if the user supplied the local computer name during the query.
    cbName = (cchComputerName + wcslen(pPrinter->pwszPrinterName) + 1) * sizeof(WCHAR);
    cbComment = (wcslen(pPrinter->pwszDescription) + 1) * sizeof(WCHAR);
    cbDescription = cbName + (wcslen(pPrinter->pwszPrinterDriver) + 1 + wcslen(pPrinter->pwszLocation) + 1) * sizeof(WCHAR);

    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_1W) + cbName + cbComment + cbDescription;
        return;
    }

    // Indicate that this is a Printer.
    (*ppPrinterInfo)->Flags = PRINTER_ENUM_ICON8;

    // Copy the Printer Name.
    p = Allocation1 = DllAllocSplMem(cbName);
    pwszStrings[0] = Allocation1;
    StringCbCopyExW(p, cbName, wszComputerName, &p, &cbName, 0);
    StringCbCopyExW(p, cbName, pPrinter->pwszPrinterName, &p, &cbName, 0);

    // Copy the Printer comment (equals the "Description" registry value).
    pwszStrings[1] = pPrinter->pwszDescription;

    // Copy the description, which for PRINTER_INFO_1W has the form "Name,Printer Driver,Location"
    p = Allocation2 = DllAllocSplMem(cbDescription);
    pwszStrings[2] = Allocation2;
    StringCbCopyExW(p, cbDescription, wszComputerName, &p, &cbDescription, 0);
    StringCbCopyExW(p, cbDescription, pPrinter->pwszPrinterName, &p, &cbDescription, 0);
    StringCbCopyExW(p, cbDescription, wszComma, &p, &cbDescription, 0);
    StringCbCopyExW(p, cbDescription, pPrinter->pwszPrinterDriver, &p, &cbDescription, 0);
    StringCbCopyExW(p, cbDescription, wszComma, &p, &cbDescription, 0);
    StringCbCopyExW(p, cbDescription, pPrinter->pwszLocation, &p, &cbDescription, 0);

    // Finally copy the structure and advance to the next one in the output buffer.
    *ppPrinterInfoEnd = PackStrings(pwszStrings, (PBYTE)(*ppPrinterInfo), dwPrinterInfo1Offsets, *ppPrinterInfoEnd);
    (*ppPrinterInfo)++;

    // Free the memory for temporary strings.
    DllFreeSplMem(Allocation1);
    DllFreeSplMem(Allocation2);
}

static void
_LocalGetPrinterLevel2(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_2W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    WCHAR wszEmpty[] = L"";

    size_t cbDevMode;
    size_t cbPrinterName;
    size_t cbShareName;
    size_t cbPortName;
    size_t cbDriverName;
    size_t cbComment;
    size_t cbLocation;
    size_t cbSepFile;
    size_t cbPrintProcessor;
    size_t cbDatatype;
    size_t cbParameters;
    PWSTR p, Allocation;
    PCWSTR pwszStrings[10];
    FIXME("LocalGetPrinterLevel2\n");
    // Calculate the string lengths.
    cbDevMode = pPrinter->pDefaultDevMode->dmSize + pPrinter->pDefaultDevMode->dmDriverExtra;
    cbPrinterName = (cchComputerName + wcslen(pPrinter->pwszPrinterName) + 1) * sizeof(WCHAR);

    if (!ppPrinterInfo)
    {
        // Attention: pComment equals the "Description" registry value.
        cbShareName = sizeof(wszEmpty);
        cbPortName = (wcslen(pPrinter->pPort->pwszName) + 1) * sizeof(WCHAR);
        cbDriverName = (wcslen(pPrinter->pwszPrinterDriver) + 1) * sizeof(WCHAR);
        cbComment = (wcslen(pPrinter->pwszDescription) + 1) * sizeof(WCHAR);
        cbLocation = (wcslen(pPrinter->pwszLocation) + 1) * sizeof(WCHAR);
        cbSepFile = sizeof(wszEmpty);
        cbPrintProcessor = (wcslen(pPrinter->pPrintProcessor->pwszName) + 1) * sizeof(WCHAR);
        cbDatatype = (wcslen(pPrinter->pwszDefaultDatatype) + 1) * sizeof(WCHAR);
        cbParameters = sizeof(wszEmpty);

        *pcbNeeded += sizeof(PRINTER_INFO_2W) + cbDevMode + cbPrinterName + cbShareName + cbPortName + cbDriverName + cbComment + cbLocation + cbSepFile + cbPrintProcessor + cbDatatype + cbParameters;
        FIXME("LocalGetPrinterLevel2 Needed %d\n",*pcbNeeded);
        return;
    }

    // Set the general fields.
    ZeroMemory(*ppPrinterInfo, sizeof(PRINTER_INFO_2W));
    (*ppPrinterInfo)->Attributes = pPrinter->dwAttributes;
    (*ppPrinterInfo)->cJobs = pPrinter->JobList.NodeCount;
    (*ppPrinterInfo)->Status = pPrinter->dwStatus;

    // Set the pDevMode field (and copy the DevMode).
    *ppPrinterInfoEnd -= cbDevMode;
    CopyMemory(*ppPrinterInfoEnd, pPrinter->pDefaultDevMode, cbDevMode);
    (*ppPrinterInfo)->pDevMode = (PDEVMODEW)(*ppPrinterInfoEnd);

    // Set the pPrinterName field.
    p = Allocation = DllAllocSplMem(cbPrinterName);
    pwszStrings[0] = Allocation;
    StringCbCopyExW(p, cbPrinterName, wszComputerName, &p, &cbPrinterName, 0);
    StringCbCopyExW(p, cbPrinterName, pPrinter->pwszPrinterName, &p, &cbPrinterName, 0);

    // Set the pShareName field.
    pwszStrings[1] = wszEmpty;

    // Set the pPortName field.
    pwszStrings[2] = pPrinter->pPort->pwszName;

    // Set the pDriverName field.
    pwszStrings[3] = pPrinter->pwszPrinterDriver;

    // Set the pComment field ((equals the "Description" registry value).
    pwszStrings[4] = pPrinter->pwszDescription;

    // Set the pLocation field.
    pwszStrings[5] = pPrinter->pwszLocation;

    // Set the pSepFile field.
    pwszStrings[6] = wszEmpty;

    // Set the pPrintProcessor field.
    pwszStrings[7] = pPrinter->pPrintProcessor->pwszName;

    // Set the pDatatype field.
    pwszStrings[8] = pPrinter->pwszDefaultDatatype;

    // Set the pParameters field.
    pwszStrings[9] = wszEmpty;

    // Finally copy the structure and advance to the next one in the output buffer.
    *ppPrinterInfoEnd = PackStrings(pwszStrings, (PBYTE)(*ppPrinterInfo), dwPrinterInfo2Offsets, *ppPrinterInfoEnd);
    (*ppPrinterInfo)++;

    // Free the memory for temporary strings.
    DllFreeSplMem(Allocation);
}

static void
_LocalGetPrinterLevel3(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_3* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    SECURITY_DESCRIPTOR SecurityDescriptor = { 0 };

    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_3) + sizeof(SECURITY_DESCRIPTOR);
        return;
    }

    FIXME("Return a valid security descriptor for PRINTER_INFO_3\n");

    // Set the pSecurityDescriptor field (and copy the Security Descriptor).
    *ppPrinterInfoEnd -= sizeof(SECURITY_DESCRIPTOR);
    CopyMemory(*ppPrinterInfoEnd, &SecurityDescriptor, sizeof(SECURITY_DESCRIPTOR));
    (*ppPrinterInfo)->pSecurityDescriptor = (PSECURITY_DESCRIPTOR)(*ppPrinterInfoEnd);

    // Advance to the next structure.
    (*ppPrinterInfo)++;
}

static void
_LocalGetPrinterLevel4(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_4W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    size_t cbPrinterName;
    PWSTR p, Allocation;
    PCWSTR pwszStrings[1];

    // Calculate the string lengths.
    cbPrinterName = (cchComputerName + wcslen(pPrinter->pwszPrinterName) + 1) * sizeof(WCHAR);

    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_4W) + cbPrinterName;
        return;
    }

    // Set the general fields.
    (*ppPrinterInfo)->pServerName = NULL;
    (*ppPrinterInfo)->Attributes = pPrinter->dwAttributes;

    // Set the pPrinterName field.
    p = Allocation = DllAllocSplMem(cbPrinterName);
    pwszStrings[0] = Allocation;
    StringCbCopyExW(p, cbPrinterName, wszComputerName, &p, &cbPrinterName, 0);
    StringCbCopyExW(p, cbPrinterName, pPrinter->pwszPrinterName, &p, &cbPrinterName, 0);

    // Finally copy the structure and advance to the next one in the output buffer.
    *ppPrinterInfoEnd = PackStrings(pwszStrings, (PBYTE)(*ppPrinterInfo), dwPrinterInfo4Offsets, *ppPrinterInfoEnd);
    (*ppPrinterInfo)++;

    // Free the memory for temporary strings.
    DllFreeSplMem(Allocation);
}

static void
_LocalGetPrinterLevel5(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_5W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    size_t cbPrinterName;
    size_t cbPortName;
    PWSTR p, Allocation;
    PCWSTR pwszStrings[2];

    // Calculate the string lengths.
    cbPrinterName = (cchComputerName + wcslen(pPrinter->pwszPrinterName) + 1) * sizeof(WCHAR);

    if (!ppPrinterInfo)
    {
        cbPortName = (wcslen(pPrinter->pPort->pwszName) + 1) * sizeof(WCHAR);

        *pcbNeeded += sizeof(PRINTER_INFO_5W) + cbPrinterName + cbPortName;
        return;
    }

    // Set the general fields.
    (*ppPrinterInfo)->Attributes = pPrinter->dwAttributes;
    (*ppPrinterInfo)->DeviceNotSelectedTimeout = dwDeviceNotSelectedTimeout;
    (*ppPrinterInfo)->TransmissionRetryTimeout = dwTransmissionRetryTimeout;

    // Set the pPrinterName field.
    p = Allocation = DllAllocSplMem(cbPrinterName);
    pwszStrings[0] = Allocation;
    StringCbCopyExW(p, cbPrinterName, wszComputerName, &p, &cbPrinterName, 0);
    StringCbCopyExW(p, cbPrinterName, pPrinter->pwszPrinterName, &p, &cbPrinterName, 0);

    // Set the pPortName field.
    pwszStrings[1] = pPrinter->pPort->pwszName;

    // Finally copy the structure and advance to the next one in the output buffer.
    *ppPrinterInfoEnd = PackStrings(pwszStrings, (PBYTE)(*ppPrinterInfo), dwPrinterInfo5Offsets, *ppPrinterInfoEnd);
    (*ppPrinterInfo)++;

    // Free the memory for temporary strings.
    DllFreeSplMem(Allocation);
}

static void
_LocalGetPrinterLevel6(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_6* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_6);
        return;
    }

    // Set the general fields.
    (*ppPrinterInfo)->dwStatus = pPrinter->dwStatus;

    // Advance to the next structure.
    (*ppPrinterInfo)++;
}

static void
_LocalGetPrinterLevel7(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_7W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_7W);
        return;
    }

    FIXME("No Directory Support, returning DSPRINT_UNPUBLISH for PRINTER_INFO_7 all the time!\n");

    // Set the general fields.
    (*ppPrinterInfo)->dwAction = DSPRINT_UNPUBLISH;
    (*ppPrinterInfo)->pszObjectGUID = NULL;

    // Advance to the next structure.
    (*ppPrinterInfo)++;
}

static void
_LocalGetPrinterLevel8(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_8W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    DWORD cbDevMode;

    // Calculate the string lengths.
    cbDevMode = pPrinter->pDefaultDevMode->dmSize + pPrinter->pDefaultDevMode->dmDriverExtra;

    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_8W) + cbDevMode;
        return;
    }

    // Set the pDevMode field (and copy the DevMode).
    *ppPrinterInfoEnd -= cbDevMode;
    CopyMemory(*ppPrinterInfoEnd, pPrinter->pDefaultDevMode, cbDevMode);
    (*ppPrinterInfo)->pDevMode = (PDEVMODEW)(*ppPrinterInfoEnd);

    // Advance to the next structure.
    (*ppPrinterInfo)++;
}

static void
_LocalGetPrinterLevel9(PLOCAL_PRINTER pPrinter, PPRINTER_INFO_9W* ppPrinterInfo, PBYTE* ppPrinterInfoEnd, PDWORD pcbNeeded, DWORD cchComputerName, PCWSTR wszComputerName)
{
    DWORD cbDevMode;

    // Calculate the string lengths.
    cbDevMode = pPrinter->pDefaultDevMode->dmSize + pPrinter->pDefaultDevMode->dmDriverExtra;

    if (!ppPrinterInfo)
    {
        *pcbNeeded += sizeof(PRINTER_INFO_9W) + cbDevMode;
        return;
    }

    FIXME("Per-user settings are not yet implemented, returning the global DevMode for PRINTER_INFO_9!\n");

    // Set the pDevMode field (and copy the DevMode).
    *ppPrinterInfoEnd -= cbDevMode;
    CopyMemory(*ppPrinterInfoEnd, pPrinter->pDefaultDevMode, cbDevMode);
    (*ppPrinterInfo)->pDevMode = (PDEVMODEW)(*ppPrinterInfoEnd);

    // Advance to the next structure.
    (*ppPrinterInfo)++;
}

static DWORD _LocalOpenPrinterHandle(PWSTR pwszPrinterName, PWSTR pwszJobParameter, PHANDLE phPrinter, PPRINTER_DEFAULTSW pDefault);

static DWORD
_LocalSetPrinterRegString(HKEY hKey, PCWSTR pwszName, PCWSTR pwszValue)
{
    return (DWORD)RegSetValueExW(hKey, pwszName, 0, REG_SZ, (const BYTE*)pwszValue, (wcslen(pwszValue) + 1) * sizeof(WCHAR));
}

/**
 * @name LocalAddPrinter
 *
 * Adds a printer: a registry key below the Printers key, like the ones of the default printers in the hive,
 * and an entry in the printer list. Only level 2 is supported. There is no driver store, so the driver
 * name is not checked; the printer drivers that are enumerated are the ones that printers refer to.
 * The returned handle is open for administering the printer.
 */
HANDLE WINAPI
LocalAddPrinter(PWSTR pName, DWORD Level, PBYTE pPrinter)
{
    DWORD dwErrorCode;
    DWORD dwAttributes;
    DWORD dwStatus = 0;
    HANDLE hPrinter = NULL;
    HKEY hSubKey = NULL;
    PCWSTR pwszDatatype;
    PCWSTR pwszPrintProcessor;
    PLOCAL_PORT pPort;
    PLOCAL_PRINTER pPrinter2 = NULL;
    PLOCAL_PRINTER pExisting;
    PLOCAL_PRINT_PROCESSOR pPrintProcessor;
    PPRINTER_INFO_2W pi2 = (PPRINTER_INFO_2W)pPrinter;
    PRINTER_DEFAULTSW Defaults;
    PWSTR pwszPort = NULL;
    PDEVMODEW pDevMode = NULL;
    DEVMODEW DefaultDevMode;
    DWORD cbDevMode;
    BOOL bKeyCreated = FALSE;
    BOOL bInserted = FALSE;
    SIZE_T cchName;

    TRACE("LocalAddPrinter(%S, %lu, %p)\n", pName, Level, pPrinter);

    if (Level != 2)
    {
        dwErrorCode = ERROR_INVALID_LEVEL;
        goto Cleanup;
    }

    if (!pi2 || !pi2->pPrinterName || !pi2->pPortName || !pi2->pDriverName)
    {
        dwErrorCode = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    // A print server name other than the local one is for another Print Provider.
    if (pName && *pName)
    {
        dwErrorCode = ERROR_INVALID_NAME;
        goto Cleanup;
    }

    // The name becomes a registry key name and the name of a printer in the printer list.
    cchName = wcslen(pi2->pPrinterName);
    if (cchName == 0 || cchName > MAX_PRINTER_NAME || wcschr(pi2->pPrinterName, L'\\') || wcschr(pi2->pPrinterName, L','))
    {
        dwErrorCode = ERROR_INVALID_PRINTER_NAME;
        goto Cleanup;
    }

    if (!*pi2->pDriverName)
    {
        dwErrorCode = ERROR_UNKNOWN_PRINTER_DRIVER;
        goto Cleanup;
    }

    // The port: a list of ports is possible in Windows, we take the first one.
    pwszPort = AllocSplStr(pi2->pPortName);
    if (!pwszPort)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }
    if (wcschr(pwszPort, L','))
        *wcschr(pwszPort, L',') = 0;

    pPort = FindPort(pwszPort);
    if (!pPort)
    {
        dwErrorCode = ERROR_UNKNOWN_PORT;
        goto Cleanup;
    }

    pwszPrintProcessor = (pi2->pPrintProcessor && *pi2->pPrintProcessor) ? pi2->pPrintProcessor : L"winprint";
    pPrintProcessor = FindPrintProcessor(pwszPrintProcessor);
    if (!pPrintProcessor)
    {
        dwErrorCode = ERROR_UNKNOWN_PRINTPROCESSOR;
        goto Cleanup;
    }

    pwszDatatype = (pi2->pDatatype && *pi2->pDatatype) ? pi2->pDatatype : L"RAW";
    if (!FindDatatype(pPrintProcessor, pwszDatatype))
    {
        dwErrorCode = ERROR_INVALID_DATATYPE;
        goto Cleanup;
    }

    // Use the DevMode of the caller if it is valid, otherwise an empty one (as the default printers have).
    if (pi2->pDevMode && pi2->pDevMode->dmSize >= FIELD_OFFSET(DEVMODEW, dmFields))
    {
        pDevMode = DuplicateDevMode(pi2->pDevMode);
        if (!pDevMode)
        {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Cleanup;
        }
    }
    else
    {
        ZeroMemory(&DefaultDevMode, sizeof(DefaultDevMode));
        DefaultDevMode.dmSpecVersion = DM_SPECVERSION;
        DefaultDevMode.dmSize = sizeof(DEVMODEW);
        wcsncpy(DefaultDevMode.dmDeviceName, pi2->pPrinterName, _countof(DefaultDevMode.dmDeviceName) - 1);
        pDevMode = DuplicateDevMode(&DefaultDevMode);
        if (!pDevMode)
        {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Cleanup;
        }
    }
    cbDevMode = pDevMode->dmSize + pDevMode->dmDriverExtra;

    EnterCriticalSection(&PrinterDeletionSection);

    pExisting = LookupElementSkiplist(&PrinterList, &pi2->pPrinterName, NULL);
    if (pExisting)
    {
        // A deleted printer stays in the list until the spooler restarts.
        dwErrorCode = (pExisting->dwStatus & PRINTER_STATUS_PENDING_DELETION) ? ERROR_PRINTER_DELETED : ERROR_PRINTER_ALREADY_EXISTS;
        LeaveCriticalSection(&PrinterDeletionSection);
        goto Cleanup;
    }

    dwAttributes = pi2->Attributes | PRINTER_ATTRIBUTE_LOCAL;

    // Make the printer persistent: the same values as InitializePrinterList reads.
    dwErrorCode = (DWORD)RegCreateKeyExW(hPrintersKey, pi2->pPrinterName, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hSubKey, NULL);
    if (dwErrorCode != ERROR_SUCCESS)
    {
        ERR("RegCreateKeyExW failed for Printer \"%S\" with status %lu!\n", pi2->pPrinterName, dwErrorCode);
        LeaveCriticalSection(&PrinterDeletionSection);
        goto Cleanup;
    }
    bKeyCreated = TRUE;

    dwErrorCode = _LocalSetPrinterRegString(hSubKey, L"Datatype", pwszDatatype);
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = _LocalSetPrinterRegString(hSubKey, L"Description", pi2->pComment ? pi2->pComment : L"");
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = _LocalSetPrinterRegString(hSubKey, L"Location", pi2->pLocation ? pi2->pLocation : L"");
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = _LocalSetPrinterRegString(hSubKey, L"Name", pi2->pPrinterName);
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = _LocalSetPrinterRegString(hSubKey, L"Port", pwszPort);
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = _LocalSetPrinterRegString(hSubKey, L"Print Processor", pwszPrintProcessor);
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = _LocalSetPrinterRegString(hSubKey, L"Printer Driver", pi2->pDriverName);
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = (DWORD)RegSetValueExW(hSubKey, L"Attributes", 0, REG_DWORD, (const BYTE*)&dwAttributes, sizeof(DWORD));
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = (DWORD)RegSetValueExW(hSubKey, L"Status", 0, REG_DWORD, (const BYTE*)&dwStatus, sizeof(DWORD));
    if (dwErrorCode == ERROR_SUCCESS)
        dwErrorCode = (DWORD)RegSetValueExW(hSubKey, L"Default DevMode", 0, REG_BINARY, (const BYTE*)pDevMode, cbDevMode);
    if (dwErrorCode != ERROR_SUCCESS)
    {
        ERR("Writing the registry values of Printer \"%S\" failed with status %lu!\n", pi2->pPrinterName, dwErrorCode);
        LeaveCriticalSection(&PrinterDeletionSection);
        goto Cleanup;
    }

    // Add it to the printer list.
    pPrinter2 = DllAllocSplMem(sizeof(LOCAL_PRINTER));
    if (!pPrinter2)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        LeaveCriticalSection(&PrinterDeletionSection);
        goto Cleanup;
    }

    pPrinter2->pwszPrinterName = AllocSplStr(pi2->pPrinterName);
    pPrinter2->pwszLocation = AllocSplStr(pi2->pLocation ? pi2->pLocation : L"");
    pPrinter2->pwszPrinterDriver = AllocSplStr(pi2->pDriverName);
    pPrinter2->pwszDescription = AllocSplStr(pi2->pComment ? pi2->pComment : L"");
    pPrinter2->pwszDefaultDatatype = AllocSplStr(pwszDatatype);
    pPrinter2->pDefaultDevMode = pDevMode;
    pPrinter2->pPrintProcessor = pPrintProcessor;
    pPrinter2->pPort = pPort;
    pPrinter2->dwAttributes = dwAttributes;
    pPrinter2->dwStatus = dwStatus;
    InitializePrinterJobList(pPrinter2);
    pDevMode = NULL;

    if (!pPrinter2->pwszPrinterName || !pPrinter2->pwszLocation || !pPrinter2->pwszPrinterDriver ||
        !pPrinter2->pwszDescription || !pPrinter2->pwszDefaultDatatype)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        LeaveCriticalSection(&PrinterDeletionSection);
        goto Cleanup;
    }

    if (!InsertElementSkiplist(&PrinterList, pPrinter2))
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        ERR("InsertElementSkiplist failed for Printer \"%S\"!\n", pPrinter2->pwszPrinterName);
        LeaveCriticalSection(&PrinterDeletionSection);
        goto Cleanup;
    }
    bInserted = TRUE;

    LeaveCriticalSection(&PrinterDeletionSection);

    // The caller may delete the printer it has added.
    ZeroMemory(&Defaults, sizeof(Defaults));
    Defaults.DesiredAccess = PRINTER_ALL_ACCESS;
    dwErrorCode = _LocalOpenPrinterHandle(pi2->pPrinterName, NULL, &hPrinter, &Defaults);

Cleanup:
    if (hSubKey)
        RegCloseKey(hSubKey);

    if (dwErrorCode != ERROR_SUCCESS && bKeyCreated && !bInserted)
        RegDeleteTreeW(hPrintersKey, pi2->pPrinterName);

    if (!bInserted)
    {
        if (pPrinter2)
        {
            if (pPrinter2->pwszPrinterName)
                DllFreeSplStr(pPrinter2->pwszPrinterName);
            if (pPrinter2->pwszLocation)
                DllFreeSplStr(pPrinter2->pwszLocation);
            if (pPrinter2->pwszPrinterDriver)
                DllFreeSplStr(pPrinter2->pwszPrinterDriver);
            if (pPrinter2->pwszDescription)
                DllFreeSplStr(pPrinter2->pwszDescription);
            if (pPrinter2->pwszDefaultDatatype)
                DllFreeSplStr(pPrinter2->pwszDefaultDatatype);
            if (pPrinter2->pDefaultDevMode)
                DllFreeSplMem(pPrinter2->pDefaultDevMode);
            DllFreeSplMem(pPrinter2);
        }
        if (pDevMode)
            DllFreeSplMem(pDevMode);
    }

    if (pwszPort)
        DllFreeSplStr(pwszPort);

    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS) ? hPrinter : NULL;
}

BOOL WINAPI
LocalDeletePrinter(HANDLE hPrinter)
{
    DWORD dwErrorCode;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PRINTER pPrinter;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;

    TRACE("LocalDeletePrinter(%p)\n", hPrinter);

    // Sanity checks.
    if (!pHandle || pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;
    pPrinter = pPrinterHandle->pPrinter;

    // Deleting a printer needs a handle opened for administering it.
    if (!(pPrinterHandle->DesiredAccess & (DELETE | PRINTER_ACCESS_ADMINISTER | GENERIC_ALL)))
    {
        dwErrorCode = ERROR_ACCESS_DENIED;
        goto Cleanup;
    }

    EnterCriticalSection(&PrinterDeletionSection);

    if (pPrinter->dwStatus & PRINTER_STATUS_PENDING_DELETION)
    {
        // It has been deleted through another handle already.
        dwErrorCode = ERROR_PRINTER_DELETED;
    }
    else if (pPrinter->lJobCount)
    {
        // A printer is only deleted without jobs: nothing would delete it once its jobs are done.
        // The count also covers a job that a failed priority change left out of the JobList.
        dwErrorCode = ERROR_PRINTER_HAS_JOBS_QUEUED;
    }
    else
    {
        // Remove the printer from the registry, so that it is gone after a restart.
        dwErrorCode = (DWORD)RegDeleteTreeW(hPrintersKey, pPrinter->pwszPrinterName);
        if (dwErrorCode == ERROR_SUCCESS)
        {
            // From now on, the printer is neither enumerated nor opened, and accepts no jobs.
            // It stays in the printer list until the spooler restarts, because open handles still refer to it.
            pPrinter->dwStatus |= PRINTER_STATUS_PENDING_DELETION;
        }
        else
        {
            ERR("Deleting the registry key of printer \"%S\" failed with status %lu!\n", pPrinter->pwszPrinterName, dwErrorCode);
        }
    }

    LeaveCriticalSection(&PrinterDeletionSection);

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

BOOL WINAPI
LocalEnumPrinters(DWORD Flags, LPWSTR Name, DWORD Level, LPBYTE pPrinterEnum, DWORD cbBuf, LPDWORD pcbNeeded, LPDWORD pcReturned)
{
    DWORD cchComputerName = 0;
    DWORD dwErrorCode;
    PBYTE pPrinterInfoEnd;
    PSKIPLIST_NODE pNode;
    WCHAR wszComputerName[2 + MAX_COMPUTERNAME_LENGTH + 1 + 1] = { 0 };
    PLOCAL_PRINTER pPrinter;

    FIXME("LocalEnumPrinters(%lu, %S, %lu, %p, %lu, %p, %p)\n", Flags, Name, Level, pPrinterEnum, cbBuf, pcbNeeded, pcReturned);

    // Do no sanity checks or assertions for pcbNeeded and pcReturned here.
    // This is verified and required by localspl_apitest!

    // Begin counting.
    *pcbNeeded = 0;
    *pcReturned = 0;

    if (Flags & PRINTER_ENUM_CONNECTIONS || Flags & PRINTER_ENUM_REMOTE || Flags & PRINTER_ENUM_NETWORK)
    {
        // If the flags for the Network Print Provider are given, bail out with ERROR_INVALID_NAME.
        // This is the internal way for a Print Provider to signal that it doesn't handle this request.
        dwErrorCode = ERROR_INVALID_NAME;
        goto Cleanup;
    }

    if (!(Flags & PRINTER_ENUM_LOCAL || Flags & PRINTER_ENUM_NAME))
    {
        // The Local Print Provider is the right destination for the request, but without any of these flags,
        // there is no information that can be returned.
        // So just signal a successful request.
        dwErrorCode = ERROR_SUCCESS;
        goto Cleanup;
    }

    if (Level == 3 || Level > 5)
    {
        // The caller supplied an invalid level for EnumPrinters.
        dwErrorCode = ERROR_INVALID_LEVEL;
        goto Cleanup;
    }

    if (Level == 1 && Flags & PRINTER_ENUM_NAME && !Name)
    {
        // The caller wants information about this Print Provider.
        // spoolss packs this into an array of information about all Print Providers.
        dwErrorCode = _DumpLevel1PrintProviderInformation(pPrinterEnum, cbBuf, pcbNeeded, pcReturned);
        goto Cleanup;
    }

    // Check the supplied Name parameter (if any).
    // This may return a Computer Name string we later prepend to the output.
    dwErrorCode = _LocalEnumPrintersCheckName(Flags, Name, wszComputerName, &cchComputerName);
    if (dwErrorCode != ERROR_SUCCESS)
        goto Cleanup;

    // Count the required buffer size and the number of printers.
    for (pNode = PrinterList.Head.Next[0]; pNode; pNode = pNode->Next[0])
    {
        pPrinter = (PLOCAL_PRINTER)pNode->Element;

        // A deleted printer is not listed anymore.
        if (pPrinter->dwStatus & PRINTER_STATUS_PENDING_DELETION)
            continue;

        // TODO: If PRINTER_ENUM_SHARED is given, add this Printer if it's shared instead of just ignoring it.
        if (Flags & PRINTER_ENUM_SHARED)
        {
            FIXME("Printer Sharing is not supported yet, returning no printers!\n");
            continue;
        }

        pfnGetPrinterLevels[Level](pPrinter, NULL, NULL, pcbNeeded, cchComputerName, wszComputerName);
    }

    // Check if the supplied buffer is large enough.
    if (cbBuf < *pcbNeeded)
    {
        dwErrorCode = ERROR_INSUFFICIENT_BUFFER;
        goto Cleanup;
    }

    // Copy over the Printer information.
    pPrinterInfoEnd = &pPrinterEnum[*pcbNeeded];

    for (pNode = PrinterList.Head.Next[0]; pNode; pNode = pNode->Next[0])
    {
        pPrinter = (PLOCAL_PRINTER)pNode->Element;

        // The printer may have been deleted since it was counted.
        if (pPrinter->dwStatus & PRINTER_STATUS_PENDING_DELETION)
            continue;

        // TODO: If PRINTER_ENUM_SHARED is given, add this Printer if it's shared instead of just ignoring it.
        if (Flags & PRINTER_ENUM_SHARED)
            continue;

        pfnGetPrinterLevels[Level](pPrinter, &pPrinterEnum, &pPrinterInfoEnd, NULL, cchComputerName, wszComputerName);
        (*pcReturned)++;
    }

    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

BOOL WINAPI
LocalGetPrinter(HANDLE hPrinter, DWORD Level, LPBYTE pPrinter, DWORD cbBuf, LPDWORD pcbNeeded)
{
    // We never prepend a Computer Name to the output, but need to provide an empty string,
    // because this variable is passed to StringCbCopyExW.
    const WCHAR wszDummyComputerName[] = L"";

    DWORD dwErrorCode;
    PBYTE pPrinterEnd;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;

    TRACE("LocalGetPrinter(%p, %lu, %p, %lu, %p)\n", hPrinter, Level, pPrinter, cbBuf, pcbNeeded);

    // Sanity checks.
    if (!pHandle)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    // Check if this is a printer handle.
    if (pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;

    if (Level > 9)
    {
        // The caller supplied an invalid level for GetPrinter.
        dwErrorCode = ERROR_INVALID_LEVEL;
        goto Cleanup;
    }

    // Count the required buffer size.
    *pcbNeeded = 0;
    pfnGetPrinterLevels[Level](pPrinterHandle->pPrinter, NULL, NULL, pcbNeeded, 0, wszDummyComputerName);

    // Check if the supplied buffer is large enough.
    if (cbBuf < *pcbNeeded)
    {
        dwErrorCode = ERROR_INSUFFICIENT_BUFFER;
        goto Cleanup;
    }

    // Copy over the Printer information.
    pPrinterEnd = &pPrinter[*pcbNeeded];
    pfnGetPrinterLevels[Level](pPrinterHandle->pPrinter, &pPrinter, &pPrinterEnd, NULL, 0, wszDummyComputerName);
    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

static DWORD
_LocalOpenPortHandle(PWSTR pwszPortName, PHANDLE phPrinter)
{
    BOOL bReturnValue;
    DWORD dwErrorCode;
    HANDLE hPort;
    PLOCAL_HANDLE pHandle = NULL;
    PLOCAL_PORT pPort;
    PLOCAL_PORT_HANDLE pPortHandle = NULL;
    PLOCAL_PRINT_MONITOR pPrintMonitor;

    // Look for this port in our Print Monitor Port list.
    pPort = FindPort(pwszPortName);
    if (!pPort)
    {
        // The supplied port is unknown to all our Print Monitors.
        dwErrorCode = ERROR_INVALID_NAME;
        goto Failure;
    }

    pPrintMonitor = pPort->pPrintMonitor;

    // Call the monitor's OpenPort function.
    if (pPrintMonitor->bIsLevel2)
        bReturnValue = ((PMONITOR2)pPrintMonitor->pMonitor)->pfnOpenPort(pPrintMonitor->hMonitor, pwszPortName, &hPort);
    else
        bReturnValue = ((LPMONITOREX)pPrintMonitor->pMonitor)->Monitor.pfnOpenPort(pwszPortName, &hPort);

    if (!bReturnValue)
    {
        // The OpenPort function failed. Return its last error.
        dwErrorCode = GetLastError();
        goto Failure;
    }

    // Create a new generic handle.
    pHandle = DllAllocSplMem(sizeof(LOCAL_HANDLE));
    if (!pHandle)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        ERR("DllAllocSplMem failed!\n");
        goto Failure;
    }

    // Create a new LOCAL_PORT_HANDLE.
    pPortHandle = DllAllocSplMem(sizeof(LOCAL_PORT_HANDLE));
    if (!pPortHandle)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        ERR("DllAllocSplMem failed!\n");
        goto Failure;
    }

    pPortHandle->hPort = hPort;
    pPortHandle->pPort = pPort;

    // Make the generic handle a Port handle.
    pHandle->HandleType = HandleType_Port;
    pHandle->pSpecificHandle = pPortHandle;

    // Return it.
    *phPrinter = (HANDLE)pHandle;
    return ERROR_SUCCESS;

Failure:
    if (pHandle)
        DllFreeSplMem(pHandle);

    if (pPortHandle)
        DllFreeSplMem(pPortHandle);

    return dwErrorCode;
}

static DWORD
_LocalOpenPrinterHandle(PWSTR pwszPrinterName, PWSTR pwszJobParameter, PHANDLE phPrinter, PPRINTER_DEFAULTSW pDefault)
{
    DWORD dwErrorCode;
    DWORD dwJobID;
    PLOCAL_HANDLE pHandle = NULL;
    PLOCAL_JOB pJob;
    PLOCAL_PRINTER pPrinter;
    PLOCAL_PRINTER_HANDLE pPrinterHandle = NULL;
    WCHAR wszFullPath[MAX_PATH];

    // Retrieve the printer from the list. A deleted printer cannot be opened anymore.
    pPrinter = LookupElementSkiplist(&PrinterList, &pwszPrinterName, NULL);
    if (!pPrinter || (pPrinter->dwStatus & PRINTER_STATUS_PENDING_DELETION))
    {
        // The printer does not exist.
        dwErrorCode = ERROR_INVALID_NAME;
        goto Failure;
    }

    // Create a new generic handle.
    pHandle = DllAllocSplMem(sizeof(LOCAL_HANDLE));
    if (!pHandle)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        ERR("DllAllocSplMem failed!\n");
        goto Failure;
    }

    // Create a new LOCAL_PRINTER_HANDLE.
    pPrinterHandle = DllAllocSplMem(sizeof(LOCAL_PRINTER_HANDLE));
    if (!pPrinterHandle)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        ERR("DllAllocSplMem failed!\n");
        goto Failure;
    }

    pPrinterHandle->hSPLFile = INVALID_HANDLE_VALUE;
    pPrinterHandle->hSPLWriteFile = INVALID_HANDLE_VALUE;
    pPrinterHandle->pPrinter = pPrinter;

    // Check if a datatype was given.
    if (pDefault && pDefault->pDatatype)
    {
        // Use the datatype if it's valid.
        if (!FindDatatype(pPrinter->pPrintProcessor, pDefault->pDatatype))
        {
            dwErrorCode = ERROR_INVALID_DATATYPE;
            goto Failure;
        }

        pPrinterHandle->pwszDatatype = AllocSplStr(pDefault->pDatatype);
    }
    else
    {
        // Use the default datatype.
        pPrinterHandle->pwszDatatype = AllocSplStr(pPrinter->pwszDefaultDatatype);
    }

    // Check if a DevMode was given, otherwise use the default.
    if (pDefault && pDefault->pDevMode)
        pPrinterHandle->pDevMode = DuplicateDevMode(pDefault->pDevMode);
    else
        pPrinterHandle->pDevMode = DuplicateDevMode(pPrinter->pDefaultDevMode);

    // Remember the requested access for operations that need more than printing.
    pPrinterHandle->DesiredAccess = pDefault ? pDefault->DesiredAccess : 0;

    // Check if the caller wants a handle to an existing Print Job.
    if (pwszJobParameter)
    {
        // The "Job " string has to follow now.
        if (wcsncmp(pwszJobParameter, L"Job ", 4) != 0)
        {
            dwErrorCode = ERROR_INVALID_NAME;
            goto Failure;
        }

        // Skip the "Job " string.
        pwszJobParameter += 4;

        // Skip even more whitespace.
        while (*pwszJobParameter == ' ')
            ++pwszJobParameter;

        // Finally extract the desired Job ID.
        dwJobID = wcstoul(pwszJobParameter, NULL, 10);
        if (!IS_VALID_JOB_ID(dwJobID))
        {
            // The user supplied an invalid Job ID.
            dwErrorCode = ERROR_INVALID_NAME;
            goto Failure;
        }

        // Look for this job in the Global Job List.
        pJob = LookupElementSkiplist(&GlobalJobList, &dwJobID, NULL);
        if (!pJob || pJob->pPrinter != pPrinter)
        {
            // The user supplied a non-existing Job ID or the Job ID does not belong to the supplied printer name.
            dwErrorCode = ERROR_INVALID_PRINTER_NAME;
            goto Failure;
        }

        // Try to open its SPL file.
        GetJobFilePath(L"SPL", dwJobID, wszFullPath);
        pPrinterHandle->hSPLFile = CreateFileW(wszFullPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (pPrinterHandle->hSPLFile == INVALID_HANDLE_VALUE)
        {
            dwErrorCode = GetLastError();
            ERR("CreateFileW failed with error %lu for \"%S\"!\n", dwErrorCode, wszFullPath);
            goto Failure;
        }

        // Associate the job to our Printer Handle, but don't set bStartedDoc.
        // This prevents the caller from doing further StartDocPrinter, WritePrinter, etc. calls on it.
        pPrinterHandle->pJob = pJob;
    }

    // Make the generic handle a Printer handle.
    pHandle->HandleType = HandleType_Printer;
    pHandle->pSpecificHandle = pPrinterHandle;

    // Return it.
    *phPrinter = (HANDLE)pHandle;
    return ERROR_SUCCESS;

Failure:
    if (pHandle)
        DllFreeSplMem(pHandle);

    if (pPrinterHandle)
    {
        if (pPrinterHandle->pwszDatatype)
            DllFreeSplStr(pPrinterHandle->pwszDatatype);

        if (pPrinterHandle->pDevMode)
            DllFreeSplMem(pPrinterHandle->pDevMode);

        DllFreeSplMem(pPrinterHandle);
    }

    return dwErrorCode;
}

static DWORD
_LocalOpenPrintServerHandle(PHANDLE phPrinter)
{
    PLOCAL_HANDLE pHandle;

    // Create a new generic handle.
    pHandle = DllAllocSplMem(sizeof(LOCAL_HANDLE));
    if (!pHandle)
    {
        ERR("DllAllocSplMem failed!\n");
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // Make the generic handle a Print Server handle.
    pHandle->HandleType = HandleType_PrintServer;
    pHandle->pSpecificHandle = NULL;

    // Return it.
    *phPrinter = (HANDLE)pHandle;
    return ERROR_SUCCESS;
}

static DWORD
_LocalOpenXcvHandle(PWSTR pwszParameter, PHANDLE phPrinter)
{
    BOOL bReturnValue;
    DWORD dwErrorCode;
    HANDLE hXcv;
    PLOCAL_HANDLE pHandle = NULL;
    PLOCAL_PORT pPort;
    PLOCAL_PRINT_MONITOR pPrintMonitor;
    PLOCAL_XCV_HANDLE pXcvHandle = NULL;

    // Skip the "Xcv" string.
    pwszParameter += 3;

    // Is XcvMonitor or XcvPort requested?
    if (wcsncmp(pwszParameter, L"Monitor ", 8) == 0)
    {
        // Skip the "Monitor " string.
        pwszParameter += 8;

        // Look for this monitor in our Print Monitor list.
        pPrintMonitor = FindPrintMonitor(pwszParameter);
        if (!pPrintMonitor)
        {
            // The caller supplied a non-existing Monitor name.
            dwErrorCode = ERROR_INVALID_NAME;
            ERR("OpenXcvHandle failed on Monitor name! %lu\n", dwErrorCode);
            goto Failure;
        }
    }
    else if (wcsncmp(pwszParameter, L"Port ", 5) == 0)
    {
        // Skip the "Port " string.
        pwszParameter += 5;

        // Look for this port in our Print Monitor Port list.
        pPort = FindPort(pwszParameter);
        if (!pPort)
        {
            // The supplied port is unknown to all our Print Monitors.
            dwErrorCode = ERROR_INVALID_NAME;
            ERR("OpenXcvHandle failed on Port name! %lu\n", dwErrorCode);
            goto Failure;
        }

        pPrintMonitor = pPort->pPrintMonitor;
    }
    else
    {
        dwErrorCode = ERROR_INVALID_NAME;
        ERR("OpenXcvHandle failed on bad name! %lu\n", dwErrorCode);
        goto Failure;
    }

    // Call the monitor's XcvOpenPort function.
    if (pPrintMonitor->bIsLevel2)
        bReturnValue = ((PMONITOR2)pPrintMonitor->pMonitor)->pfnXcvOpenPort(pPrintMonitor->hMonitor, pwszParameter, SERVER_EXECUTE, &hXcv);
    else
        bReturnValue = ((LPMONITOREX)pPrintMonitor->pMonitor)->Monitor.pfnXcvOpenPort(pwszParameter, SERVER_EXECUTE, &hXcv);

    if (!bReturnValue)
    {
        // The XcvOpenPort function failed. Return its last error.
        dwErrorCode = GetLastError();
        ERR("XcvOpenPort function failed! %lu\n", dwErrorCode);
        goto Failure;
    }

    // Create a new generic handle.
    pHandle = DllAllocSplMem(sizeof(LOCAL_HANDLE));
    if (!pHandle)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        ERR("DllAllocSplMem failed!\n");
        goto Failure;
    }

    // Create a new LOCAL_XCV_HANDLE.
    pXcvHandle = DllAllocSplMem(sizeof(LOCAL_XCV_HANDLE));
    if (!pXcvHandle)
    {
        dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
        ERR("DllAllocSplMem failed!\n");
        goto Failure;
    }

    pXcvHandle->hXcv = hXcv;
    pXcvHandle->pPrintMonitor = pPrintMonitor;

    // Make the generic handle a Xcv handle.
    pHandle->HandleType = HandleType_Xcv;
    pHandle->pSpecificHandle = pXcvHandle;

    // Return it.
    *phPrinter = (HANDLE)pHandle;
    ERR("OpenXcvHandle Success! %p\n", pXcvHandle);
    return ERROR_SUCCESS;

Failure:
    if (pHandle)
        DllFreeSplMem(pHandle);

    if (pXcvHandle)
        DllFreeSplMem(pXcvHandle);

    return dwErrorCode;
}

//
// Dead API
//
DWORD WINAPI
LocalPrinterMessageBox(HANDLE hPrinter, DWORD Error, HWND hWnd, LPWSTR pText, LPWSTR pCaption, DWORD dwType)
{
    SetLastError(ERROR_INVALID_HANDLE); // Yes....
    return 0;
}

BOOL WINAPI
LocalOpenPrinter(PWSTR lpPrinterName, HANDLE* phPrinter, PPRINTER_DEFAULTSW pDefault)
{
    DWORD cchComputerName;
    DWORD cchFirstParameter;
    DWORD dwErrorCode;
    PWSTR p = lpPrinterName;
    PWSTR pwszFirstParameter = NULL;
    PWSTR pwszSecondParameter;
    WCHAR wszComputerName[MAX_COMPUTERNAME_LENGTH + 1];

    TRACE("LocalOpenPrinter(%S, %p, %p)\n", lpPrinterName, phPrinter, pDefault);

    ASSERT(phPrinter);
    *phPrinter = NULL;

    if (!lpPrinterName)
    {
        // The caller wants a Print Server handle and provided a NULL string.
        dwErrorCode = _LocalOpenPrintServerHandle(phPrinter);
        goto Cleanup;
    }

    // Skip any server name in the first parameter.
    // Does lpPrinterName begin with two backslashes to indicate a server name?
    if (lpPrinterName[0] == L'\\' && lpPrinterName[1] == L'\\')
    {
        // Skip these two backslashes.
        lpPrinterName += 2;

        // Look for the terminating null character or closing backslash.
        p = lpPrinterName;
        while (*p != L'\0' && *p != L'\\')
            p++;

        // Get the local computer name for comparison.
        cchComputerName = _countof(wszComputerName);
        if (!GetComputerNameW(wszComputerName, &cchComputerName))
        {
            dwErrorCode = GetLastError();
            ERR("GetComputerNameW failed with error %lu!\n", dwErrorCode);
            goto Cleanup;
        }

        // Now compare this string excerpt with the local computer name.
        // The input parameter may not be writable, so we can't null-terminate the input string at this point.
        // This print provider only supports local printers, so both strings have to match.
        if (p - lpPrinterName != cchComputerName || _wcsnicmp(lpPrinterName, wszComputerName, cchComputerName) != 0)
        {
            dwErrorCode = ERROR_INVALID_NAME;
            goto Cleanup;
        }

        // If lpPrinterName is only "\\COMPUTERNAME" with nothing more, the caller wants a handle to the local Print Server.
        if (!*p)
        {
            // The caller wants a Print Server handle and provided a string like:
            //    "\\COMPUTERNAME"
            dwErrorCode = _LocalOpenPrintServerHandle(phPrinter);
            goto Cleanup;
        }

        // We have checked the server name and don't need it anymore.
        lpPrinterName = p + 1;
    }

    // Look for a comma. If it exists, it indicates the end of the first parameter.
    pwszSecondParameter = wcschr(lpPrinterName, L',');
    if (pwszSecondParameter)
        cchFirstParameter = pwszSecondParameter - p;
    else
        cchFirstParameter = wcslen(lpPrinterName);

    // We must have at least one parameter.
    if (!cchFirstParameter && !pwszSecondParameter)
    {
        dwErrorCode = ERROR_INVALID_NAME;
        goto Cleanup;
    }

    // Do we have a first parameter?
    if (cchFirstParameter)
    {
        // Yes, extract it.
        // No null-termination is necessary here, because DllAllocSplMem returns a zero-initialized buffer.
        pwszFirstParameter = DllAllocSplMem((cchFirstParameter + 1) * sizeof(WCHAR));
        CopyMemory(pwszFirstParameter, lpPrinterName, cchFirstParameter * sizeof(WCHAR));
    }

    // Do we have a second parameter?
    if (pwszSecondParameter)
    {
        // Yes, skip the comma at the beginning.
        ++pwszSecondParameter;

        // Skip whitespace as well.
        while (*pwszSecondParameter == L' ')
            ++pwszSecondParameter;
    }

    // Now we can finally check the type of handle actually requested.
    if (pwszFirstParameter && pwszSecondParameter && wcsncmp(pwszSecondParameter, L"Port", 4) == 0)
    {
        // The caller wants a port handle and provided a string like:
        //    "LPT1:, Port"
        //    "\\COMPUTERNAME\LPT1:, Port"
        dwErrorCode = _LocalOpenPortHandle(pwszFirstParameter, phPrinter);
    }
    else if (!pwszFirstParameter && pwszSecondParameter && wcsncmp(pwszSecondParameter, L"Xcv", 3) == 0)
    {
        // The caller wants an Xcv handle and provided a string like:
        //    ", XcvMonitor Local Port"
        //    "\\COMPUTERNAME\, XcvMonitor Local Port"
        //    ", XcvPort LPT1:"
        //    "\\COMPUTERNAME\, XcvPort LPT1:"
        FIXME("OpenXcvHandle : %S\n",pwszSecondParameter);
        dwErrorCode = _LocalOpenXcvHandle(pwszSecondParameter, phPrinter);
    }
    else
    {
        // The caller wants a Printer or Printer Job handle and provided a string like:
        //    "HP DeskJet"
        //    "\\COMPUTERNAME\HP DeskJet"
        //    "HP DeskJet, Job 5"
        //    "\\COMPUTERNAME\HP DeskJet, Job 5"
        dwErrorCode = _LocalOpenPrinterHandle(pwszFirstParameter, pwszSecondParameter, phPrinter, pDefault);
    }

Cleanup:
    if (pwszFirstParameter)
        DllFreeSplMem(pwszFirstParameter);

    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

BOOL WINAPI
LocalReadPrinter(HANDLE hPrinter, PVOID pBuf, DWORD cbBuf, PDWORD pNoBytesRead)
{
    BOOL bReturnValue;
    DWORD dwErrorCode;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PORT_HANDLE pPortHandle;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;

    TRACE("LocalReadPrinter(%p, %p, %lu, %p)\n", hPrinter, pBuf, cbBuf, pNoBytesRead);

    // Sanity checks.
    if (!pHandle)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    // Port handles are an entirely different thing.
    if (pHandle->HandleType == HandleType_Port)
    {
        pPortHandle = (PLOCAL_PORT_HANDLE)pHandle->pSpecificHandle;

        // Call the monitor's ReadPort function.
        if (pPortHandle->pPort->pPrintMonitor->bIsLevel2)
            bReturnValue = ((PMONITOR2)pPortHandle->pPort->pPrintMonitor->pMonitor)->pfnReadPort(pPortHandle->hPort, pBuf, cbBuf, pNoBytesRead);
        else
            bReturnValue = ((LPMONITOREX)pPortHandle->pPort->pPrintMonitor->pMonitor)->Monitor.pfnReadPort(pPortHandle->hPort, pBuf, cbBuf, pNoBytesRead);

        if (!bReturnValue)
        {
            // The ReadPort function failed. Return its last error.
            dwErrorCode = GetLastError();
            goto Cleanup;
        }

        // We were successful!
        dwErrorCode = ERROR_SUCCESS;
        goto Cleanup;
    }

    // The remaining function deals with Printer handles only.
    if (pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;

    // ReadPrinter needs an opened SPL file to work.
    // This only works if a Printer Job Handle was requested in OpenPrinter.
    if (pPrinterHandle->hSPLFile == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    // Pass the parameters to ReadFile.
    if (!ReadFile(pPrinterHandle->hSPLFile, pBuf, cbBuf, pNoBytesRead, NULL))
    {
        dwErrorCode = GetLastError();
        ERR("ReadFile failed with error %lu!\n", dwErrorCode);
        goto Cleanup;
    }

    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

DWORD WINAPI
LocalStartDocPrinter(HANDLE hPrinter, DWORD Level, PBYTE pDocInfo)
{
    BOOL bReturnValue;
    DWORD dwErrorCode;
    DWORD dwReturnValue = 0;
    PDOC_INFO_1W pDocInfo1 = (PDOC_INFO_1W)pDocInfo;
    PLOCAL_JOB pJob;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PORT_HANDLE pPortHandle;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;
    WCHAR wszFullPath[MAX_PATH];

    TRACE("LocalStartDocPrinter(%p, %lu, %p)\n", hPrinter, Level, pDocInfo);

    // Sanity checks.
    if (!pHandle)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    // Port handles are an entirely different thing.
    if (pHandle->HandleType == HandleType_Port)
    {
        pPortHandle = (PLOCAL_PORT_HANDLE)pHandle->pSpecificHandle;

        // This call should come from a Print Processor and the job this port is going to print was assigned to us before opening the Print Processor.
        // Only the printing thread, which runs the Print Processor, may claim it, exclusively for this port handle.
        if (pPortHandle->pPort->dwPrintingThreadId != GetCurrentThreadId() || !pPortHandle->pPort->pNextJobToProcess)
        {
            dwErrorCode = ERROR_ACCESS_DENIED;
            ERR("No job was handed over to port %S for this thread!\n", pPortHandle->pPort->pwszName);
            goto Cleanup;
        }

        pJob = pPortHandle->pPort->pNextJobToProcess;
        pPortHandle->pPort->pNextJobToProcess = NULL;

        // The output file of a job is opened with the identity of the user who submitted the job.
        if (pJob->hToken && !SetThreadToken(NULL, pJob->hToken))
        {
            dwErrorCode = GetLastError();
            ERR("SetThreadToken failed with error %lu!\n", dwErrorCode);
            goto Cleanup;
        }

        // Call the monitor's StartDocPort function.
        if (pPortHandle->pPort->pPrintMonitor->bIsLevel2)
            bReturnValue = ((PMONITOR2)pPortHandle->pPort->pPrintMonitor->pMonitor)->pfnStartDocPort(pPortHandle->hPort, pJob->pPrinter->pwszPrinterName, pJob->dwJobID, Level, pDocInfo);
        else
            bReturnValue = ((LPMONITOREX)pPortHandle->pPort->pPrintMonitor->pMonitor)->Monitor.pfnStartDocPort(pPortHandle->hPort, pJob->pPrinter->pwszPrinterName, pJob->dwJobID, Level, pDocInfo);

        // The StartDocPort function may have failed. Keep its last error.
        dwErrorCode = bReturnValue ? ERROR_SUCCESS : GetLastError();

        if (pJob->hToken)
            SetThreadToken(NULL, NULL);

        if (dwErrorCode == ERROR_SUCCESS)
            dwReturnValue = pJob->dwJobID;

        goto Cleanup;
    }

    // The remaining function deals with Printer handles only.
    if (pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    if (!pDocInfo1)
    {
        dwErrorCode = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;

    // pJob may already be occupied if this is a Print Job handle. In this case, StartDocPrinter has to fail.
    if (pPrinterHandle->pJob)
    {
        dwErrorCode = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    // Check the validity of the datatype if we got one.
    if (pDocInfo1->pDatatype && !FindDatatype(pPrinterHandle->pPrinter->pPrintProcessor, pDocInfo1->pDatatype))
    {
        dwErrorCode = ERROR_INVALID_DATATYPE;
        goto Cleanup;
    }

    // Check if this is the right document information level.
    if (Level != 1)
    {
        dwErrorCode = ERROR_INVALID_LEVEL;
        goto Cleanup;
    }

    // Direct printing is not implemented: WritePrinter could not pass the document to the port.
    if (pPrinterHandle->pPrinter->dwAttributes & PRINTER_ATTRIBUTE_DIRECT)
    {
        dwErrorCode = ERROR_NOT_SUPPORTED;
        FIXME("Direct printing is not implemented!\n");
        goto Cleanup;
    }

    // All requirements are met - create a new job.
    dwErrorCode = CreateJob(pPrinterHandle);
    if (dwErrorCode != ERROR_SUCCESS)
        goto Cleanup;

    pJob = pPrinterHandle->pJob;

    // Use any given datatype, document name and output file.
    if (pDocInfo1->pDatatype)
    {
        ReallocSplStr(&pJob->pwszDatatype, pDocInfo1->pDatatype);
        if (!pJob->pwszDatatype)
        {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto JobFailure;
        }
    }

    if (pDocInfo1->pDocName)
    {
        ReallocSplStr(&pJob->pwszDocumentName, pDocInfo1->pDocName);
        if (!pJob->pwszDocumentName)
        {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto JobFailure;
        }
    }

    if (pDocInfo1->pOutputFile && *pDocInfo1->pOutputFile)
    {
        ReallocSplStr(&pJob->pwszOutputFile, pDocInfo1->pOutputFile);
        if (!pJob->pwszOutputFile)
        {
            dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto JobFailure;
        }

        // Keep the identity of the caller for opening the output file.
        // There is no token when the caller is not impersonated, so the file is opened with our own identity.
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE | TOKEN_QUERY, TRUE, &pJob->hToken))
        {
            pJob->hToken = NULL;
            dwErrorCode = GetLastError();
            if (dwErrorCode != ERROR_NO_TOKEN)
            {
                ERR("OpenThreadToken failed with error %lu!\n", dwErrorCode);
                goto JobFailure;
            }
        }
    }

    // WritePrinter writes the document into the job's spool file.
    GetJobFilePath(L"SPL", pJob->dwJobID, wszFullPath);
    pPrinterHandle->hSPLWriteFile = CreateFileW(wszFullPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (pPrinterHandle->hSPLWriteFile == INVALID_HANDLE_VALUE)
    {
        dwErrorCode = GetLastError();
        ERR("CreateFileW failed with error %lu for \"%S\"!\n", dwErrorCode, wszFullPath);
        goto JobFailure;
    }

    // We were successful!
    dwErrorCode = ERROR_SUCCESS;
    dwReturnValue = pJob->dwJobID;
    goto Cleanup;

JobFailure:
    // Undo the job creation.
    ERR("Starting job %lu failed with error %lu!\n", pJob->dwJobID, dwErrorCode);
    FreeJob(pJob);
    pPrinterHandle->pJob = NULL;
    pPrinterHandle->bStartedDoc = FALSE;

Cleanup:
    SetLastError(dwErrorCode);
    return dwReturnValue;
}

BOOL WINAPI
LocalStartPagePrinter(HANDLE hPrinter)
{
    DWORD dwErrorCode;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;

    TRACE("LocalStartPagePrinter(%p)\n", hPrinter);

    // Sanity checks.
    if (!pHandle || pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;

    // We require StartDocPrinter or AddJob to be called first.
    if (!pPrinterHandle->bStartedDoc)
    {
        dwErrorCode = ERROR_SPL_NO_STARTDOC;
        goto Cleanup;
    }

    // Increase the page count.
    ++pPrinterHandle->pJob->dwTotalPages;
    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

BOOL WINAPI
LocalWritePrinter(HANDLE hPrinter, PVOID pBuf, DWORD cbBuf, PDWORD pcWritten)
{
    BOOL bReturnValue;
    DWORD dwErrorCode;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PORT_HANDLE pPortHandle;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;

    TRACE("LocalWritePrinter(%p, %p, %lu, %p)\n", hPrinter, pBuf, cbBuf, pcWritten);

    // Sanity checks.
    if (!pHandle)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    // Port handles are an entirely different thing.
    if (pHandle->HandleType == HandleType_Port)
    {
        pPortHandle = (PLOCAL_PORT_HANDLE)pHandle->pSpecificHandle;

        // Call the monitor's WritePort function.
        if (pPortHandle->pPort->pPrintMonitor->bIsLevel2)
            bReturnValue = ((PMONITOR2)pPortHandle->pPort->pPrintMonitor->pMonitor)->pfnWritePort(pPortHandle->hPort, pBuf, cbBuf, pcWritten);
        else
            bReturnValue = ((LPMONITOREX)pPortHandle->pPort->pPrintMonitor->pMonitor)->Monitor.pfnWritePort(pPortHandle->hPort, pBuf, cbBuf, pcWritten);

        if (!bReturnValue)
        {
            // The WritePort function failed. Return its last error.
            dwErrorCode = GetLastError();
            goto Cleanup;
        }

        // We were successful!
        dwErrorCode = ERROR_SUCCESS;
        goto Cleanup;
    }

    // The remaining function deals with Printer handles only.
    if (pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;

    // We require StartDocPrinter or AddJob to be called first.
    if (!pPrinterHandle->bStartedDoc)
    {
        dwErrorCode = ERROR_SPL_NO_STARTDOC;
        goto Cleanup;
    }

    // A spooled job started through StartDocPrinter is written into its spool file.
    if (pPrinterHandle->hSPLWriteFile != INVALID_HANDLE_VALUE)
    {
        if (!WriteFile(pPrinterHandle->hSPLWriteFile, pBuf, cbBuf, pcWritten, NULL))
        {
            dwErrorCode = GetLastError();
            ERR("WriteFile failed with error %lu!\n", dwErrorCode);
            goto Cleanup;
        }

        dwErrorCode = ERROR_SUCCESS;
        goto Cleanup;
    }

    // TODO: This function is only called when doing non-spooled printing.
    // This needs to be investigated further. We can't just use pPrinterHandle->hSPLFile here, because that's currently reserved for Printer Job handles (see LocalReadPrinter).
#if 0
    // Pass the parameters to WriteFile.
    if (!WriteFile(SOME_SPOOL_FILE_HANDLE, pBuf, cbBuf, pcWritten, NULL))
    {
        dwErrorCode = GetLastError();
        ERR("WriteFile failed with error %lu!\n", GetLastError());
        goto Cleanup;
    }
#endif

    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

BOOL WINAPI
LocalEndPagePrinter(HANDLE hPrinter)
{
    DWORD dwErrorCode;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;

    TRACE("LocalEndPagePrinter(%p)\n", hPrinter);

    // Sanity checks.
    if (!pHandle || pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    // This function doesn't do anything else for now.
    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

BOOL WINAPI
LocalEndDocPrinter(HANDLE hPrinter)
{
    BOOL bReturnValue;
    DWORD dwErrorCode;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PORT_HANDLE pPortHandle;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;

    TRACE("LocalEndDocPrinter(%p)\n", hPrinter);

    // Sanity checks.
    if (!pHandle)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    // Port handles are an entirely different thing.
    if (pHandle->HandleType == HandleType_Port)
    {
        pPortHandle = (PLOCAL_PORT_HANDLE)pHandle->pSpecificHandle;

        // Call the monitor's EndDocPort function.
        if (pPortHandle->pPort->pPrintMonitor->bIsLevel2)
            bReturnValue = ((PMONITOR2)pPortHandle->pPort->pPrintMonitor->pMonitor)->pfnEndDocPort(pPortHandle->hPort);
        else
            bReturnValue = ((LPMONITOREX)pPortHandle->pPort->pPrintMonitor->pMonitor)->Monitor.pfnEndDocPort(pPortHandle->hPort);

        if (!bReturnValue)
        {
            // The EndDocPort function failed. Return its last error.
            dwErrorCode = GetLastError();
            goto Cleanup;
        }

        // We were successful!
        dwErrorCode = ERROR_SUCCESS;
        goto Cleanup;
    }

    // The remaining function deals with Printer handles only.
    if (pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;

    // We require StartDocPrinter or AddJob to be called first.
    if (!pPrinterHandle->bStartedDoc)
    {
        dwErrorCode = ERROR_SPL_NO_STARTDOC;
        goto Cleanup;
    }

    dwErrorCode = ERROR_SUCCESS;

    // A spooled job started through StartDocPrinter is complete now: print it.
    if (pPrinterHandle->hSPLWriteFile != INVALID_HANDLE_VALUE)
    {
        // A job deleted while it was spooled is discarded instead of printed.
        BOOL bDeleted = !EndJobSpooling(pPrinterHandle->pJob);

        CloseHandle(pPrinterHandle->hSPLWriteFile);
        pPrinterHandle->hSPLWriteFile = INVALID_HANDLE_VALUE;

        if (!bDeleted)
            dwErrorCode = StartJobPrinting(pPrinterHandle->pJob);

        if (bDeleted || dwErrorCode != ERROR_SUCCESS)
        {
            // The job is not printed: discard it.
            WCHAR wszFullPath[MAX_PATH];

            GetJobFilePath(L"SPL", pPrinterHandle->pJob->dwJobID, wszFullPath);
            DeleteFileW(wszFullPath);
            FreeJob(pPrinterHandle->pJob);
        }
    }

    // Finish the job.
    pPrinterHandle->bStartedDoc = FALSE;
    pPrinterHandle->pJob = NULL;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

BOOL WINAPI
LocalAbortPrinter(HANDLE hPrinter)
{
    DWORD dwErrorCode;
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;
    PLOCAL_PRINTER_HANDLE pPrinterHandle;
    WCHAR wszFullPath[MAX_PATH];

    TRACE("LocalAbortPrinter(%p)\n", hPrinter);

    // Only a document of a Printer handle can be aborted.
    if (!pHandle || pHandle->HandleType != HandleType_Printer)
    {
        dwErrorCode = ERROR_INVALID_HANDLE;
        goto Cleanup;
    }

    pPrinterHandle = (PLOCAL_PRINTER_HANDLE)pHandle->pSpecificHandle;

    // The document must have been started on this handle through StartDocPrinter and not been ended.
    // A job added through AddJob is no started document here, as on Windows: SetJob deletes it.
    if (!pPrinterHandle->bStartedDoc || !pPrinterHandle->pJob || pPrinterHandle->pJob->bAddedJob)
    {
        dwErrorCode = ERROR_SPL_NO_STARTDOC;
        goto Cleanup;
    }

    if (pPrinterHandle->hSPLWriteFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(pPrinterHandle->hSPLWriteFile);
        pPrinterHandle->hSPLWriteFile = INVALID_HANDLE_VALUE;
    }

    // Discard the job with its spool file.
    GetJobFilePath(L"SPL", pPrinterHandle->pJob->dwJobID, wszFullPath);
    DeleteFileW(wszFullPath);
    FreeJob(pPrinterHandle->pJob);

    pPrinterHandle->pJob = NULL;
    pPrinterHandle->bStartedDoc = FALSE;
    dwErrorCode = ERROR_SUCCESS;

Cleanup:
    SetLastError(dwErrorCode);
    return (dwErrorCode == ERROR_SUCCESS);
}

static void
_LocalClosePortHandle(PLOCAL_PORT_HANDLE pPortHandle)
{
    FIXME("LocalClosePortHandle\n");
    // Call the monitor's ClosePort function.
    if (pPortHandle->pPort->pPrintMonitor->bIsLevel2)
        ((PMONITOR2)pPortHandle->pPort->pPrintMonitor->pMonitor)->pfnClosePort(pPortHandle->hPort);
    else
        ((LPMONITOREX)pPortHandle->pPort->pPrintMonitor->pMonitor)->Monitor.pfnClosePort(pPortHandle->hPort);
}

static void
_LocalClosePrinterHandle(PLOCAL_PRINTER_HANDLE pPrinterHandle)
{
    FIXME("LocalClosePrinterHandle\n");

    // Close the spool file of a Printer Job handle.
    if (pPrinterHandle->hSPLFile != INVALID_HANDLE_VALUE)
        CloseHandle(pPrinterHandle->hSPLFile);

    // A document started through StartDocPrinter was not finished: discard its spool file.
    if (pPrinterHandle->hSPLWriteFile != INVALID_HANDLE_VALUE)
    {
        WCHAR wszFullPath[MAX_PATH];

        CloseHandle(pPrinterHandle->hSPLWriteFile);
        if (pPrinterHandle->pJob)
        {
            GetJobFilePath(L"SPL", pPrinterHandle->pJob->dwJobID, wszFullPath);
            DeleteFileW(wszFullPath);
        }
    }

    // Terminate a job started on this handle and not ended.
    // A Printer Job handle does not own its job: the job is freed when it has been sent to the printer.
    if (pPrinterHandle->pJob && pPrinterHandle->bStartedDoc)
        FreeJob(pPrinterHandle->pJob);

    // Free memory for the fields.
    DllFreeSplMem(pPrinterHandle->pDevMode);
    DllFreeSplStr(pPrinterHandle->pwszDatatype);
}

static void
_LocalCloseXcvHandle(PLOCAL_XCV_HANDLE pXcvHandle)
{
    // Call the monitor's XcvClosePort function.
    if (pXcvHandle->pPrintMonitor->bIsLevel2)
        ((PMONITOR2)pXcvHandle->pPrintMonitor->pMonitor)->pfnXcvClosePort(pXcvHandle->hXcv);
    else
        ((LPMONITOREX)pXcvHandle->pPrintMonitor->pMonitor)->Monitor.pfnXcvClosePort(pXcvHandle->hXcv);
}

BOOL WINAPI
LocalClosePrinter(HANDLE hPrinter)
{
    PLOCAL_HANDLE pHandle = (PLOCAL_HANDLE)hPrinter;

    FIXME("LocalClosePrinter(%p)\n", hPrinter);

    if (!pHandle)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (pHandle->HandleType == HandleType_Port)
    {
        _LocalClosePortHandle(pHandle->pSpecificHandle);
    }
    else if (pHandle->HandleType == HandleType_Printer)
    {
        _LocalClosePrinterHandle(pHandle->pSpecificHandle);
    }
    else if (pHandle->HandleType == HandleType_PrintServer)
    {
        // Nothing to do.
    }
    else if (pHandle->HandleType == HandleType_Xcv)
    {
        _LocalCloseXcvHandle(pHandle->pSpecificHandle);
    }
    FIXME("LocalClosePrinter 1\n");
    // Free memory for the handle and the specific handle (if any).
    if (pHandle->pSpecificHandle)
        DllFreeSplMem(pHandle->pSpecificHandle);
    FIXME("LocalClosePrinter 2\n");
    DllFreeSplMem(pHandle);
    FIXME("LocalClosePrinter 3\n");
    return TRUE;
}
