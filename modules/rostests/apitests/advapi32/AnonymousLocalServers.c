/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A local client that impersonates the anonymous logon gets no event log and no print server
 *              (measured on Windows Server 2022: OpenEventLog of Application, System and Security fails with 5,
 *              EnumPrinters of the local printers fails with 16385, OpenPrinter fails with 5).
 *              Documentation: ImpersonateAnonymousToken, OpenEventLog, EnumPrinters, OpenPrinter.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Clearing a log is not tested: it needs an open log, which the anonymous caller does not get.
 */

#include "precomp.h"

typedef BOOL (WINAPI *PENUMPRINTERSW)(DWORD, LPWSTR, DWORD, LPBYTE, DWORD, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *POPENPRINTERW)(LPWSTR, LPHANDLE, LPVOID);
typedef BOOL (WINAPI *PCLOSEPRINTER)(HANDLE);

START_TEST(AnonymousLocalServers)
{
    static const PCWSTR Logs[] = { L"Application", L"System", L"Security" };
    HMODULE hSpool = LoadLibraryW(L"winspool.drv");
    PENUMPRINTERSW pEnumPrintersW = hSpool ? (PENUMPRINTERSW)GetProcAddress(hSpool, "EnumPrintersW") : NULL;
    POPENPRINTERW pOpenPrinterW = hSpool ? (POPENPRINTERW)GetProcAddress(hSpool, "OpenPrinterW") : NULL;
    HANDLE hLog, hPrinter;
    DWORD Needed, Returned, Error;
    BOOL Ret;
    UINT i;

    /* Reference: the caller itself reads the Application log (the test needs an administrator) */
    hLog = OpenEventLogW(NULL, L"Application");
    ok(hLog != NULL, "OpenEventLog(Application) as the caller failed with %lu\n", GetLastError());
    if (hLog)
        CloseEventLog(hLog);

    if (!ImpersonateAnonymousToken(GetCurrentThread()))
    {
        skip("ImpersonateAnonymousToken failed with %lu\n", GetLastError());
        return;
    }

    for (i = 0; i < _countof(Logs); i++)
    {
        SetLastError(0xDEADBEEF);
        hLog = OpenEventLogW(NULL, Logs[i]);
        Error = GetLastError();
        ok(hLog == NULL, "OpenEventLog(%ls) as anonymous succeeded\n", Logs[i]);
        ok(Error == ERROR_ACCESS_DENIED, "OpenEventLog(%ls) as anonymous: error %lu, expected 5\n", Logs[i], Error);
        if (hLog)
            CloseEventLog(hLog);
    }

    SetLastError(0xDEADBEEF);
    hLog = RegisterEventSourceW(NULL, L"Application");
    Error = GetLastError();
    ok(hLog == NULL, "RegisterEventSource as anonymous succeeded\n");
    ok(Error == ERROR_ACCESS_DENIED, "RegisterEventSource as anonymous: error %lu, expected 5\n", Error);
    if (hLog)
        DeregisterEventSource(hLog);

    /* The file does not exist: the anonymous caller is refused before it is looked at */
    SetLastError(0xDEADBEEF);
    hLog = OpenBackupEventLogW(NULL, L"C:\\nonexistent-anonymous-test.evt");
    Error = GetLastError();
    ok(hLog == NULL, "OpenBackupEventLog as anonymous succeeded\n");
    ok(Error == ERROR_ACCESS_DENIED, "OpenBackupEventLog as anonymous: error %lu, expected 5\n", Error);
    if (hLog)
        CloseEventLog(hLog);

    /* The ANSI entry points take the ANSI RPC calls of the server */
    SetLastError(0xDEADBEEF);
    hLog = OpenEventLogA(NULL, "Application");
    Error = GetLastError();
    ok(hLog == NULL, "OpenEventLogA as anonymous succeeded\n");
    ok(Error == ERROR_ACCESS_DENIED, "OpenEventLogA as anonymous: error %lu, expected 5\n", Error);
    if (hLog)
        CloseEventLog(hLog);

    SetLastError(0xDEADBEEF);
    hLog = RegisterEventSourceA(NULL, "Application");
    Error = GetLastError();
    ok(hLog == NULL, "RegisterEventSourceA as anonymous succeeded\n");
    ok(Error == ERROR_ACCESS_DENIED, "RegisterEventSourceA as anonymous: error %lu, expected 5\n", Error);
    if (hLog)
        DeregisterEventSource(hLog);

    SetLastError(0xDEADBEEF);
    hLog = OpenBackupEventLogA(NULL, "C:\\nonexistent-anonymous-test.evt");
    Error = GetLastError();
    ok(hLog == NULL, "OpenBackupEventLogA as anonymous succeeded\n");
    ok(Error == ERROR_ACCESS_DENIED, "OpenBackupEventLogA as anonymous: error %lu, expected 5\n", Error);
    if (hLog)
        CloseEventLog(hLog);

    if (pEnumPrintersW)
    {
        Needed = Returned = 0;
        SetLastError(0xDEADBEEF);
        Ret = pEnumPrintersW(2 /* PRINTER_ENUM_LOCAL */, NULL, 2, NULL, 0, &Needed, &Returned);
        Error = GetLastError();
        ok(Ret == FALSE, "EnumPrinters as anonymous succeeded\n");
        ok(Error == 16385, "EnumPrinters as anonymous: error %lu, expected 16385\n", Error);
    }

    if (pOpenPrinterW)
    {
        hPrinter = NULL;
        SetLastError(0xDEADBEEF);
        Ret = pOpenPrinterW(NULL, &hPrinter, NULL);
        Error = GetLastError();
        ok(Ret == FALSE, "OpenPrinter(NULL) as anonymous succeeded\n");
        ok(Error == ERROR_ACCESS_DENIED, "OpenPrinter(NULL) as anonymous: error %lu, expected 5\n", Error);
        if (Ret)
            ((PCLOSEPRINTER)GetProcAddress(hSpool, "ClosePrinter"))(hPrinter);
    }

    RevertToSelf();

    /* After the revert the caller is served again */
    hLog = OpenEventLogW(NULL, L"Application");
    ok(hLog != NULL, "OpenEventLog(Application) after the revert failed with %lu\n", GetLastError());
    if (hLog)
        CloseEventLog(hLog);
}
