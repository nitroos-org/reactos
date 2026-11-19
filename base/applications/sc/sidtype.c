/*
 * PROJECT:     ReactOS Services
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/applications/sc/sidtype.c
 * PURPOSE:     sidtype, qsidtype and showsid: the service SID type of a service and its SID
 */

#include "sc.h"

#include <winreg.h>
#include <svcsid.h>

/* the PSDK header of this tree does not have the structure of SERVICE_CONFIG_SERVICE_SID_INFO */
typedef struct _SERVICE_SID_INFO
{
    DWORD dwServiceSidType;
} SERVICE_SID_INFO, *LPSERVICE_SID_INFO;

static LPCTSTR
SidTypeName(DWORD dwType)
{
    switch (dwType)
    {
        case SERVICE_SID_TYPE_NONE:         return _T("NONE");
        case SERVICE_SID_TYPE_UNRESTRICTED: return _T("UNRESTRICTED");
        case SERVICE_SID_TYPE_RESTRICTED:   return _T("RESTRICTED");
    }
    return _T("UNKNOWN");
}


/* sc sidtype <service> <none | unrestricted | restricted> */
DWORD
SetSidType(LPCTSTR ServiceName,
           LPCTSTR Type)
{
    SC_HANDLE hManager, hService;
    SERVICE_SID_INFO Info;
    DWORD dwError;

    if (!lstrcmpi(Type, _T("none")))
        Info.dwServiceSidType = SERVICE_SID_TYPE_NONE;
    else if (!lstrcmpi(Type, _T("unrestricted")))
        Info.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
    else if (!lstrcmpi(Type, _T("restricted")))
        Info.dwServiceSidType = SERVICE_SID_TYPE_RESTRICTED;
    else
    {
        /* Windows Server 2022: the usage and the exit code 0 */
        SetSidTypeUsage();
        return ERROR_SUCCESS;
    }

    dwError = OpenServiceForConfig(ServiceName, SERVICE_CHANGE_CONFIG, &hManager, &hService);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_SERVICE_SID_INFO, &Info))
    {
        dwError = GetLastError();
        ReportApiFailure(_T("ChangeServiceConfig2"), dwError);
    }
    else
    {
        /* wording verify on oracle */
        _tprintf(_T("[SC] ChangeServiceConfig2 SUCCESS\n"));
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hManager);
    return dwError;
}


/* sc qsidtype <service> */
DWORD
QuerySidType(LPCTSTR ServiceName)
{
    SC_HANDLE hManager, hService;
    SERVICE_SID_INFO Info;
    DWORD dwNeeded = 0, dwError;

    dwError = OpenServiceForConfig(ServiceName, SERVICE_QUERY_CONFIG, &hManager, &hService);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    if (!QueryServiceConfig2(hService, SERVICE_CONFIG_SERVICE_SID_INFO, (LPBYTE)&Info, sizeof(Info), &dwNeeded))
    {
        dwError = GetLastError();
        ReportApiFailure(_T("QueryServiceConfig2"), dwError);
    }
    else
    {
        /* the lines of Windows Server 2022: the type follows the colon after two spaces */
        _tprintf(_T("[SC] QueryServiceConfig2 SUCCESS\n\n"));
        _tprintf(_T("SERVICE_NAME: %s\n"), ServiceName);
        _tprintf(_T("SERVICE_SID_TYPE:  %s\n"), SidTypeName(Info.dwServiceSidType));
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hManager);
    return dwError;
}


/*
 * sc showsid <service>: the SID the service controller gives the service (computed from the name with the helper
 * the SCM, the LSA and MSV1_0 share), and whether the service has it (STATUS Active: ServiceSidType is not NONE).
 * The layout of the output is to be verified on the oracle.
 */
DWORD
ShowSid(LPCTSTR ServiceName)
{
    SC_HANDLE hManager, hService;
    SERVICE_SID_INFO Info;
    ULONG SubAuthorities[5];
    BYTE SidBuffer[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID pSid = (PSID)SidBuffer;
    LPTSTR pszSid = NULL;
    DWORD dwNeeded, dwError = ERROR_SUCCESS, i;
    BOOL bActive = FALSE;

    if (!LsapServiceNameToSubAuthorities(ServiceName, (ULONG)_tcslen(ServiceName), SubAuthorities))
    {
        ReportApiFailure(_T("ShowSid"), ERROR_INVALID_NAME);
        return ERROR_INVALID_NAME;
    }

    RtlInitializeSid(pSid, &NtAuthority, LSAP_SERVICE_SID_SUBAUTHS);
    *RtlSubAuthoritySid(pSid, 0) = SECURITY_SERVICE_ID_BASE_RID;
    for (i = 0; i < 5; i++)
        *RtlSubAuthoritySid(pSid, i + 1) = SubAuthorities[i];

    if (!ConvertSidToStringSid(pSid, &pszSid))
    {
        dwError = GetLastError();
        ReportApiFailure(_T("ConvertSidToStringSid"), dwError);
        return dwError;
    }

    if (OpenServiceForConfig(ServiceName, SERVICE_QUERY_CONFIG, &hManager, &hService) == ERROR_SUCCESS)
    {
        if (QueryServiceConfig2(hService, SERVICE_CONFIG_SERVICE_SID_INFO, (LPBYTE)&Info, sizeof(Info), &dwNeeded))
            bActive = (Info.dwServiceSidType != SERVICE_SID_TYPE_NONE);
        CloseServiceHandle(hService);
        CloseServiceHandle(hManager);
    }

    _tprintf(_T("\nNAME: %s\n"), ServiceName);
    _tprintf(_T("SERVICE SID: %s\n"), pszSid);
    _tprintf(_T("STATUS: %s\n"), bActive ? _T("Active") : _T("Inactive"));

    LocalFree(pszSid);
    return dwError;
}


VOID
SetSidTypeUsage(VOID)
{
    _tprintf(_T("DESCRIPTION:\n")
             _T("        Changes the service SID type of a service. The service SID is\n")
             _T("        added to the token of the service process when the service starts.\n")
             _T("USAGE:\n")
             _T("        sc <server> sidtype [service name] [type]\n")
             _T("\n")
             _T("OPTIONS:\n")
             _T("        type = <none | unrestricted | restricted>\n"));
}

VOID
QuerySidTypeUsage(VOID)
{
    _tprintf(_T("DESCRIPTION:\n")
             _T("        Queries the service SID type of a service.\n")
             _T("USAGE:\n")
             _T("        sc <server> qsidtype [service name]\n"));
}

VOID
ShowSidUsage(VOID)
{
    _tprintf(_T("DESCRIPTION:\n")
             _T("        Displays the service SID string corresponding to the input service name.\n")
             _T("        The service SID is derived from the name; it is in the token of the\n")
             _T("        service process only when the service SID type is not NONE.\n")
             _T("USAGE:\n")
             _T("        sc <server> showsid [service name]\n"));
}
