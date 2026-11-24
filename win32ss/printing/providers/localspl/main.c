/*
 * PROJECT:     ReactOS Local Spooler
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Main functions
 * COPYRIGHT:   Copyright 2015-2017 Colin Finck (colin@reactos.org)
 */

#include "precomp.h"

#include <aclapi.h>
#include <sddl.h>

// Global Variables
HKEY hPrintKey = NULL;
HKEY hPrintersKey = NULL;
WCHAR wszJobDirectory[MAX_PATH];
DWORD cchJobDirectory;
WCHAR wszSpoolDirectory[MAX_PATH];
DWORD cchSpoolDirectory;

// Global Constants
#include <prtprocenv.h>

/** This is what the Spooler of Windows Server 2003 returns (for example using GetPrinterDataExW, SPLREG_MAJOR_VERSION/SPLREG_MINOR_VERSION) */
const DWORD dwSpoolerMajorVersion = 3;
const DWORD dwSpoolerMinorVersion = 0;

const WCHAR wszDefaultDocumentName[] = L"Local Downlevel Document";

PCWSTR wszPrintProviderInfo[3] = {
    L"Windows NT Local Print Providor",     // Name
    L"Locally connected Printers",          // Comment
    L"Windows NT Local Printers"            // Description
};

// Local Constants
static const PRINTPROVIDOR _PrintProviderFunctions = {
    LocalOpenPrinter,                           // fpOpenPrinter
    LocalSetJob,                                // fpSetJob
    LocalGetJob,                                // fpGetJob
    LocalEnumJobs,                              // fpEnumJobs
    LocalAddPrinter,                            // fpAddPrinter
    LocalDeletePrinter,                         // fpDeletePrinter
    NULL,                                       // fpSetPrinter
    LocalGetPrinter,                            // fpGetPrinter
    LocalEnumPrinters,                          // fpEnumPrinters
    LocalAddPrinterDriver,                      // fpAddPrinterDriver
    LocalEnumPrinterDrivers,                    // fpEnumPrinterDrivers
    LocalGetPrinterDriver,                      // fpGetPrinterDriver
    LocalGetPrinterDriverDirectory,             // fpGetPrinterDriverDirectory
    NULL,                                       // fpDeletePrinterDriver
    NULL,                                       // fpAddPrintProcessor
    LocalEnumPrintProcessors,                   // fpEnumPrintProcessors
    LocalGetPrintProcessorDirectory,            // fpGetPrintProcessorDirectory
    NULL,                                       // fpDeletePrintProcessor
    LocalEnumPrintProcessorDatatypes,           // fpEnumPrintProcessorDatatypes
    LocalStartDocPrinter,                       // fpStartDocPrinter
    LocalStartPagePrinter,                      // fpStartPagePrinter
    LocalWritePrinter,                          // fpWritePrinter
    LocalEndPagePrinter,                        // fpEndPagePrinter
    LocalAbortPrinter,                          // fpAbortPrinter
    LocalReadPrinter,                           // fpReadPrinter
    LocalEndDocPrinter,                         // fpEndDocPrinter
    LocalAddJob,                                // fpAddJob
    LocalScheduleJob,                           // fpScheduleJob
    LocalGetPrinterData,                        // fpGetPrinterData
    LocalSetPrinterData,                        // fpSetPrinterData
    NULL,                                       // fpWaitForPrinterChange
    LocalClosePrinter,                          // fpClosePrinter
    LocalAddForm,                               // fpAddForm
    LocalDeleteForm,                            // fpDeleteForm
    LocalGetForm,                               // fpGetForm
    LocalSetForm,                               // fpSetForm
    LocalEnumForms,                             // fpEnumForms
    LocalEnumMonitors,                          // fpEnumMonitors
    LocalEnumPorts,                             // fpEnumPorts
    LocalAddPort,                               // fpAddPort
    LocalConfigurePort,                         // fpConfigurePort
    LocalDeletePort,                            // fpDeletePort
    NULL,                                       // fpCreatePrinterIC
    NULL,                                       // fpPlayGdiScriptOnPrinterIC
    NULL,                                       // fpDeletePrinterIC
    NULL,                                       // fpAddPrinterConnection
    NULL,                                       // fpDeletePrinterConnection
    LocalPrinterMessageBox,                     // fpPrinterMessageBox
    LocalAddMonitor,                            // fpAddMonitor
    LocalDeleteMonitor,                         // fpDeleteMonitor
    NULL,                                       // fpResetPrinter
    LocalGetPrinterDriverEx,                    // fpGetPrinterDriverEx
    NULL,                                       // fpFindFirstPrinterChangeNotification
    NULL,                                       // fpFindClosePrinterChangeNotification
    LocalAddPortEx,                             // fpAddPortEx
    NULL,                                       // fpShutDown
    NULL,                                       // fpRefreshPrinterChangeNotification
    NULL,                                       // fpOpenPrinterEx
    NULL,                                       // fpAddPrinterEx
    LocalSetPort,                               // fpSetPort
    NULL,                                       // fpEnumPrinterData
    NULL,                                       // fpDeletePrinterData
    NULL,                                       // fpClusterSplOpen
    NULL,                                       // fpClusterSplClose
    NULL,                                       // fpClusterSplIsAlive
    LocalSetPrinterDataEx,                      // fpSetPrinterDataEx
    LocalGetPrinterDataEx,                      // fpGetPrinterDataEx
    NULL,                                       // fpEnumPrinterDataEx
    NULL,                                       // fpEnumPrinterKey
    NULL,                                       // fpDeletePrinterDataEx
    NULL,                                       // fpDeletePrinterKey
    NULL,                                       // fpSeekPrinter
    NULL,                                       // fpDeletePrinterDriverEx
    NULL,                                       // fpAddPerMachineConnection
    NULL,                                       // fpDeletePerMachineConnection
    NULL,                                       // fpEnumPerMachineConnections
    LocalXcvData,                               // fpXcvData
    LocalAddPrinterDriverEx,                    // fpAddPrinterDriverEx
    NULL,                                       // fpSplReadPrinter
    NULL,                                       // fpDriverUnloadComplete
    LocalGetSpoolFileInfo,                      // fpGetSpoolFileInfo
    LocalCommitSpoolData,                       // fpCommitSpoolData
    LocalCloseSpoolFileHandle,                  // fpCloseSpoolFileHandle
    NULL,                                       // fpFlushPrinter
    NULL,                                       // fpSendRecvBidiData
    NULL,                                       // fpAddDriverCatalog
};

/**
 * Gives the default job directory (spool\PRINTERS) the descriptor it has on Windows (measured on Windows Server 2022):
 * system, administrators and the creator of a file may do everything but execute, and the users may create files and
 * folders there and read their attributes (so that a standard user can spool a job and cannot read the jobs of others).
 * Without that the directory only inherits the read access of the users from spool\ and a standard user cannot print.
 * The descriptor is applied once: only to a directory whose DACL is not protected yet (the one the installation made).
 */
static void
_SecureDefaultJobDirectory(void)
{
    static const WCHAR wszPrintersPath[] = L"\\PRINTERS";
    static const WCHAR wszDescriptor[] = L"D:P(A;OICIIO;0x1f01df;;;CO)(A;OICI;0x1f01df;;;SY)(A;OICI;0x1f01df;;;BA)(A;CI;0x10008e;;;BU)";
    WCHAR wszDefaultDirectory[MAX_PATH];
    PSECURITY_DESCRIPTOR pCurrentSD = NULL;
    PSECURITY_DESCRIPTOR pNewSD = NULL;
    SECURITY_DESCRIPTOR_CONTROL Control;
    DWORD dwRevision;
    PACL pAcl;
    BOOL bPresent, bDefaulted;

    // Only the default directory: a directory the administrator chose keeps what the administrator set.
    if (cchSpoolDirectory + _countof(wszPrintersPath) > _countof(wszDefaultDirectory))
        return;
    CopyMemory(wszDefaultDirectory, wszSpoolDirectory, cchSpoolDirectory * sizeof(WCHAR));
    CopyMemory(&wszDefaultDirectory[cchSpoolDirectory], wszPrintersPath, sizeof(wszPrintersPath));
    if (_wcsicmp(wszDefaultDirectory, wszJobDirectory) != 0)
        return;

    if (GetNamedSecurityInfoW(wszJobDirectory, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pCurrentSD) != ERROR_SUCCESS)
        return;

    if (GetSecurityDescriptorControl(pCurrentSD, &Control, &dwRevision) && !(Control & SE_DACL_PROTECTED) &&
        ConvertStringSecurityDescriptorToSecurityDescriptorW(wszDescriptor, SDDL_REVISION_1, &pNewSD, NULL))
    {
        if (GetSecurityDescriptorDacl(pNewSD, &bPresent, &pAcl, &bDefaulted) && bPresent)
        {
            DWORD dwErrorCode = SetNamedSecurityInfoW(wszJobDirectory, SE_FILE_OBJECT,
                                                      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                                      NULL, NULL, pAcl, NULL);
            if (dwErrorCode != ERROR_SUCCESS)
                ERR("SetNamedSecurityInfoW failed for the job directory with error %lu!\n", dwErrorCode);
        }
        LocalFree(pNewSD);
    }

    LocalFree(pCurrentSD);
}

static BOOL
_InitializeLocalSpooler(void)
{
    const WCHAR wszPrintersPath[] = L"\\PRINTERS";
    const DWORD cchPrintersPath = _countof(wszPrintersPath) - 1;
    const WCHAR wszSpoolPath[] = L"\\spool";
    const DWORD cchSpoolPath = _countof(wszSpoolPath) - 1;
    const WCHAR wszSymbolicLinkValue[] = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers";
    const DWORD cbSymbolicLinkValue = sizeof(wszSymbolicLinkValue) - sizeof(WCHAR);

    BOOL bReturnValue = FALSE;
    DWORD cbData;
    DWORD dwErrorCode;
    HKEY hKey = NULL;

    // On startup, always create a volatile symbolic link in the registry if it doesn't exist yet.
    //   "SYSTEM\CurrentControlSet\Control\Print\Printers" -> "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers"
    //
    // According to https://learn.microsoft.com/en-us/archive/msdn-technet-forums/a683ab54-c43c-4ebe-af8f-1f7a65af2a51
    // this is needed when having >900 printers to work around a size limit of the SYSTEM registry hive.
    dwErrorCode = (DWORD)RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Printers", 0, NULL, REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK, KEY_CREATE_LINK | KEY_SET_VALUE, NULL, &hKey, NULL);
    if (dwErrorCode == ERROR_SUCCESS)
    {
        // Note that wszSymbolicLink has to be stored WITHOUT the terminating null character for the symbolic link to work!
        // See cbSymbolicLinkValue above.
        dwErrorCode = (DWORD)RegSetValueExW(hKey, L"SymbolicLinkValue", 0, REG_LINK, (PBYTE)wszSymbolicLinkValue, cbSymbolicLinkValue);
        if (dwErrorCode != ERROR_SUCCESS)
        {
            ERR("RegSetValueExW failed for the Printers symlink with error %lu!\n", dwErrorCode);
            goto Cleanup;
        }
    }
    else if (dwErrorCode != ERROR_ALREADY_EXISTS)
    {
        ERR("RegCreateKeyExW failed for the Printers symlink with error %lu!\n", dwErrorCode);
        goto Cleanup;
    }

    // Open some registry keys and leave them open. We need them multiple times throughout the Local Spooler.
    dwErrorCode = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print", 0, KEY_ALL_ACCESS, &hPrintKey);
    if (dwErrorCode != ERROR_SUCCESS)
    {
        ERR("RegOpenKeyExW failed for \"Print\" with error %lu!\n", dwErrorCode);
        goto Cleanup;
    }

    dwErrorCode = (DWORD)RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers", 0, KEY_ALL_ACCESS, &hPrintersKey);
    if (dwErrorCode != ERROR_SUCCESS)
    {
        ERR("RegOpenKeyExW failed for \"Printers\" with error %lu!\n", dwErrorCode);
        goto Cleanup;
    }

    // Construct the path to "%SystemRoot%\system32\spool".
    // Forget about length checks here. If this doesn't fit into MAX_PATH, our OS has more serious problems...
    cchSpoolDirectory = GetSystemDirectoryW(wszSpoolDirectory, MAX_PATH);
    CopyMemory(&wszSpoolDirectory[cchSpoolDirectory], wszSpoolPath, (cchSpoolPath + 1) * sizeof(WCHAR));
    cchSpoolDirectory += cchSpoolPath;

    // Query the job directory.
    cbData = sizeof(wszJobDirectory);
    dwErrorCode = (DWORD)RegQueryValueExW(hPrintersKey, SPLREG_DEFAULT_SPOOL_DIRECTORY, NULL, NULL, (PBYTE)wszJobDirectory, &cbData);
    if (dwErrorCode == ERROR_SUCCESS)
    {
        cchJobDirectory = cbData / sizeof(WCHAR) - 1;
    }
    else if (dwErrorCode == ERROR_FILE_NOT_FOUND)
    {
        // Use the default "%SystemRoot%\system32\spool\PRINTERS".
        CopyMemory(wszJobDirectory, wszSpoolDirectory, cchSpoolDirectory * sizeof(WCHAR));
        CopyMemory(&wszJobDirectory[cchSpoolDirectory], wszPrintersPath, (cchPrintersPath + 1) * sizeof(WCHAR));
        cchJobDirectory = cchSpoolDirectory + cchPrintersPath;

        // Save this for next time.
        RegSetValueExW(hPrintersKey, SPLREG_DEFAULT_SPOOL_DIRECTORY, 0, REG_SZ, (PBYTE)wszJobDirectory, (cchJobDirectory + 1) * sizeof(WCHAR));
    }
    else
    {
        ERR("RegQueryValueExW failed for \"%S\" with error %lu!\n", SPLREG_DEFAULT_SPOOL_DIRECTORY, dwErrorCode);
        goto Cleanup;
    }

    _SecureDefaultJobDirectory();

    // Initialize all lists.
    if (!InitializePrintMonitorList())
        goto Cleanup;

    if (!InitializePortList())
        goto Cleanup;

    if (!InitializePrintProcessorList())
        goto Cleanup;

    if (!InitializePrinterList())
        goto Cleanup;

    if (!InitializeGlobalJobList())
        goto Cleanup;

    if (!InitializeFormList())
        goto Cleanup;

    if (!InitializePrinterDrivers())
        goto Cleanup;

    // Local Spooler Initialization finished successfully!
    bReturnValue = TRUE;

Cleanup:
    if (hKey)
        RegCloseKey(hKey);

    return bReturnValue;
}

BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            return _InitializeLocalSpooler();

        default:
            return TRUE;
    }
}

BOOL WINAPI
InitializePrintProvidor(LPPRINTPROVIDOR pPrintProvidor, DWORD cbPrintProvidor, LPWSTR pFullRegistryPath)
{
    TRACE("InitializePrintProvidor(%p, %lu, %S)\n", pPrintProvidor, cbPrintProvidor, pFullRegistryPath);

    CopyMemory(pPrintProvidor, &_PrintProviderFunctions, min(cbPrintProvidor, sizeof(PRINTPROVIDOR)));

    SetLastError(ERROR_SUCCESS);
    return TRUE;
}
