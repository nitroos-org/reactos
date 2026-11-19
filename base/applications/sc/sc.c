/*
 * PROJECT:     ReactOS Services
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/applications/sc/sc.c
 * PURPOSE:     parse command line
 * COPYRIGHT:   Copyright 2005 - 2006 Ged Murphy <gedmurphy@gmail.com>
 *
 */

#include "sc.h"

SC_HANDLE hSCManager;

/* The error a failed command reported: sc exits with it, as on Windows (e.g. 5 for access denied) */
static DWORD dwReportedError = ERROR_SUCCESS;

VOID
ReportLastError(VOID)
{
    LPVOID lpMsgBuf;
    DWORD RetVal;

    DWORD ErrorCode = GetLastError();
    if (ErrorCode != ERROR_SUCCESS)
    {
        dwReportedError = ErrorCode;

        RetVal = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                               FORMAT_MESSAGE_FROM_SYSTEM |
                               FORMAT_MESSAGE_IGNORE_INSERTS,
                               NULL,
                               ErrorCode,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
                               (LPTSTR) &lpMsgBuf,
                               0,
                               NULL );

        if (RetVal != 0)
        {
            _tprintf(_T("%s"), (LPTSTR)lpMsgBuf);
            LocalFree(lpMsgBuf);
        }
    }
}


static INT
ScControl(LPCTSTR Server,       // remote machine name
          LPCTSTR Command,      // sc command
          LPCTSTR *ServiceArgs, // any options
          DWORD ArgCount)       // argument counter
{
    LPCTSTR ServiceName = NULL;
    INT nResult = 0;
    BOOL bResult = TRUE;

    if (Server)
    {
        _tprintf(_T("Remote service control is not yet implemented\n"));
        return 2;
    }

    if (!lstrcmpi(Command, _T("query")))
    {
        bResult = Query(ServiceArgs,
                        ArgCount,
                        FALSE);
    }
    else if (!lstrcmpi(Command, _T("queryex")))
    {
        bResult = Query(ServiceArgs,
                        ArgCount,
                        TRUE);
    }
    else if (!lstrcmpi(Command, _T("start")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = Start(ServiceName,
                            ServiceArgs,
                            ArgCount);
        }
        else
            StartUsage();
    }
    else if (!lstrcmpi(Command, _T("pause")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = Control(SERVICE_CONTROL_PAUSE,
                    ServiceName,
                    ServiceArgs,
                    ArgCount);
        }
        else
            PauseUsage();
    }
    else if (!lstrcmpi(Command, _T("interrogate")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = Control(SERVICE_CONTROL_INTERROGATE,
                    ServiceName,
                    ServiceArgs,
                    ArgCount);
        }
        else
            InterrogateUsage();
    }
    else if (!lstrcmpi(Command, _T("stop")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = Control(SERVICE_CONTROL_STOP,
                    ServiceName,
                    ServiceArgs,
                    ArgCount);
        }
        else
            StopUsage();
    }
    else if (!lstrcmpi(Command, _T("continue")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = Control(SERVICE_CONTROL_CONTINUE,
                    ServiceName,
                    ServiceArgs,
                    ArgCount);
        }
        else
            ContinueUsage();
    }
    else if (!lstrcmpi(Command, _T("delete")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = Delete(ServiceName);
        }
        else
            DeleteUsage();
    }
    else if (!lstrcmpi(Command, _T("create")))
    {
        bResult = Create(ServiceArgs, ArgCount);
    }
    else if (!lstrcmpi(Command, _T("control")))
    {
        INT ControlCode = 0;

        if (ArgCount > 1)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            if (!lstrcmpi(ServiceArgs[0], _T("paramchange")))
                ControlCode = SERVICE_CONTROL_PARAMCHANGE;
            else if (!lstrcmpi(ServiceArgs[0], _T("netbindadd")))
                ControlCode = SERVICE_CONTROL_NETBINDADD;
            else if (!lstrcmpi(ServiceArgs[0], _T("netbindremove")))
                ControlCode = SERVICE_CONTROL_NETBINDREMOVE;
            else if (!lstrcmpi(ServiceArgs[0], _T("netbindenable")))
                ControlCode = SERVICE_CONTROL_NETBINDENABLE;
            else if (!lstrcmpi(ServiceArgs[0], _T("netbinddisable")))
                ControlCode = SERVICE_CONTROL_NETBINDDISABLE;
            else
            {
                ControlCode = _ttoi(ServiceArgs[0]);
                if ((ControlCode < 128) || (ControlCode > 255))
                    ControlCode = 0;
            }

            ServiceArgs++;
            ArgCount--;

            if (ControlCode != 0)
                bResult = Control(ControlCode,
                        ServiceName,
                        ServiceArgs,
                        ArgCount);
            else
                ControlUsage();
        }
        else
            ControlUsage();
    }
    else if (!lstrcmpi(Command, _T("sdshow")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = SdShow(ServiceName);
        }
        else
            SdShowUsage();
    }
    else if (!lstrcmpi(Command, _T("sdset")))
    {
        LPCTSTR SecurityDescriptor;

        if (ArgCount > 1)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            SecurityDescriptor = *ServiceArgs++;
            ArgCount--;

            bResult = SdSet(ServiceName, SecurityDescriptor);
        }
        else
            SdSetUsage();
    }
    else if (!lstrcmpi(Command, _T("qc")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = QueryConfig(ServiceName);
        }
        else
            QueryConfigUsage();
    }
    else if (!lstrcmpi(Command, _T("qdescription")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = QueryDescription(ServiceName);
        }
        else
            QueryDescriptionUsage();
    }
    else if (!lstrcmpi(Command, _T("qfailure")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = QueryFailure(ServiceName);
        }
        else
            QueryFailureUsage();
    }
    else if (!lstrcmpi(Command, _T("description")))
    {
        LPCTSTR Description = NULL;

        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            if (ArgCount > 0)
            {
                Description = *ServiceArgs++;
                ArgCount--;
            }

            bResult = SetDescription(ServiceName, Description);
        }
        else
            SetDescriptionUsage();
    }
    else if (!lstrcmpi(Command, _T("config")))
    {
        bResult = SetConfig(ServiceArgs, ArgCount);
    }
    else if (!lstrcmpi(Command, _T("failure")))
    {
        bResult = SetFailure(ServiceArgs, ArgCount);
    }
    else if (!lstrcmpi(Command, _T("GetDisplayName")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = GetDisplayName(ServiceName);
        }
        else
            GetDisplayNameUsage();
    }
    else if (!lstrcmpi(Command, _T("GetKeyName")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = GetKeyName(ServiceName);
        }
        else
            GetKeyNameUsage();
    }
    else if (!lstrcmpi(Command, _T("EnumDepend")))
    {
        if (ArgCount > 0)
        {
            ServiceName = *ServiceArgs++;
            ArgCount--;

            bResult = EnumDepend(ServiceName);
        }
        else
            EnumDependUsage();
    }
    else if (!lstrcmpi(Command, _T("privs")))
    {
        if (ArgCount > 1)
            nResult = (INT)SetPrivileges(ServiceArgs[0], ServiceArgs[1]);
        else
            SetPrivilegesUsage();
    }
    else if (!lstrcmpi(Command, _T("qprivs")))
    {
        if (ArgCount > 0)
            nResult = (INT)QueryPrivileges(ServiceArgs[0], (ArgCount > 1) ? ServiceArgs[1] : NULL);
        else
            QueryPrivilegesUsage();
    }
    else if (!lstrcmpi(Command, _T("sidtype")))
    {
        if (ArgCount > 1)
            nResult = (INT)SetSidType(ServiceArgs[0], ServiceArgs[1]);
        else
        {
            /* Windows Server 2022 prints the usage and exits with 0 */
            SetSidTypeUsage();
        }
    }
    else if (!lstrcmpi(Command, _T("qsidtype")))
    {
        if (ArgCount > 0)
            nResult = (INT)QuerySidType(ServiceArgs[0]);
        else
        {
            /* Windows Server 2022 prints the usage and exits with 0 */
            QuerySidTypeUsage();
        }
    }
    else if (!lstrcmpi(Command, _T("showsid")))
    {
        if (ArgCount > 0)
            nResult = (INT)ShowSid(ServiceArgs[0]);
        else
        {
            ShowSidUsage();
            nResult = ERROR_INVALID_COMMAND_LINE;
        }
    }
    else if (!lstrcmpi(Command, _T("triggerinfo")))
    {
        if (ArgCount > 1)
        {
            nResult = (INT)SetTriggerInfo(ServiceArgs[0], ServiceArgs + 1, ArgCount - 1);
        }
        else
        {
            SetTriggerInfoUsage();
            nResult = ERROR_INVALID_COMMAND_LINE;
        }
    }
    else if (!lstrcmpi(Command, _T("qtriggerinfo")))
    {
        if (ArgCount > 0)
        {
            nResult = (INT)QueryTriggerInfo(ServiceArgs[0], (ArgCount > 1) ? ServiceArgs[1] : NULL);
        }
        else
        {
            QueryTriggerInfoUsage();
            nResult = ERROR_INVALID_COMMAND_LINE;
        }
    }
    else
    {
        /* an unknown command: the error line of Windows Server 2022, the usage, no prompt, ERROR_INVALID_COMMAND_LINE */
        _tprintf(_T("ERROR:  Unrecognized command\n"));
        MainUsage(FALSE);
        nResult = ERROR_INVALID_COMMAND_LINE;
    }

    /* A command that failed exits with its error, not 0 (Windows Server 2022: "sc start" of a service the
       user may not start exits with 5) */
    if (!bResult && nResult == 0)
    {
        nResult = (INT)dwReportedError;
        if (nResult == 0)
            nResult = (INT)GetLastError();
        if (nResult == 0)
            nResult = 1;
    }

    return nResult;
}

int _tmain(int argc, LPCTSTR argv[])
{
    LPCTSTR Server = NULL;   // remote machine
    LPCTSTR Command = NULL;  // sc command
    LPCTSTR *Args = NULL;    // Any remaining args

    if (argc < 2)
    {
        MainUsage(TRUE);
        return -1;
    }

    /* get server name */
    if ((argv[1][0] == '\\') && (argv[1][1] == '\\'))
    {
        if (argc < 3)
        {
            MainUsage(TRUE);
            return -1;
        }

        Server = argv[1];
        Command = argv[2];
        if (argc > 3)
            Args = &argv[3];

        return ScControl(Server,
                         Command,
                         Args,
                         argc-3);
    }
    else
    {
        Command = argv[1];
        if (argc > 2)
            Args = &argv[2];

        return ScControl(Server,
                         Command,
                         Args,
                         argc-2);
    }
}
