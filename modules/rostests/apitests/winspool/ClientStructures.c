/*
 * PROJECT:     ReactOS Print Spooler DLL API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The information structures a client gets from the spooler: the strings point into the buffer
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * The calls that hang a 32-bit program on a 64-bit system when the spooler hands it structures in its own pointer
 * size (a pointer built from half of a 64-bit offset is dereferenced by the next call: GetPrinterDriver, then
 * DocumentProperties): every call must return, and the strings of what it returns must lie in the buffer the
 * caller gave. Without a printer the printer rows are skipped; the rows that do not need one still run.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <winspool.h>

static BOOL InBuffer(const BYTE *pBase, DWORD cbBuffer, const void *pPointer)
{
    return (const BYTE *)pPointer >= pBase && (const BYTE *)pPointer < pBase + cbBuffer;
}

/* A string pointer of a returned structure: NULL is allowed when bOptional, else it must lie inside the buffer */
static void CheckString(const char *pszWhat, DWORD dwLevel, const BYTE *pBase, DWORD cbBuffer, LPCWSTR pwszString, BOOL bOptional)
{
    if (!pwszString)
    {
        ok(bOptional, "%s level %lu: a string is NULL\n", pszWhat, dwLevel);
        return;
    }
    ok(InBuffer(pBase, cbBuffer, pwszString), "%s level %lu: a string pointer %p is outside the buffer %p (%lu bytes)\n",
       pszWhat, dwLevel, pwszString, pBase, cbBuffer);
}

static BYTE *CallEnumPrinters(DWORD dwLevel, DWORD *pcbBuffer, DWORD *pcReturned)
{
    DWORD cbNeeded = 0, cReturned = 0;
    BYTE *pBuffer;
    BOOL bResult;

    SetLastError(0xdeadbeef);
    bResult = EnumPrintersW(PRINTER_ENUM_LOCAL, NULL, dwLevel, NULL, 0, &cbNeeded, &cReturned);
    if (bResult)
    {
        /* nothing to return */
        *pcbBuffer = 0;
        *pcReturned = 0;
        return NULL;
    }
    ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "EnumPrintersW level %lu: error %lu\n", dwLevel, GetLastError());
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !cbNeeded)
        return NULL;

    pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNeeded);
    bResult = EnumPrintersW(PRINTER_ENUM_LOCAL, NULL, dwLevel, pBuffer, cbNeeded, &cbNeeded, &cReturned);
    ok(bResult, "EnumPrintersW level %lu with the size it asked for failed: %lu\n", dwLevel, GetLastError());
    if (!bResult)
    {
        HeapFree(GetProcessHeap(), 0, pBuffer);
        return NULL;
    }
    *pcbBuffer = cbNeeded;
    *pcReturned = cReturned;
    return pBuffer;
}

static void TestEnumPrinters(WCHAR *pwszPrinter, DWORD cchPrinter)
{
    DWORD cb, c, i;
    BYTE *pBuffer;

    pBuffer = CallEnumPrinters(1, &cb, &c);
    if (pBuffer)
    {
        PRINTER_INFO_1W *p = (PRINTER_INFO_1W *)pBuffer;
        for (i = 0; i < c; i++)
        {
            CheckString("EnumPrinters", 1, pBuffer, cb, p[i].pName, FALSE);
            CheckString("EnumPrinters", 1, pBuffer, cb, p[i].pDescription, TRUE);
            CheckString("EnumPrinters", 1, pBuffer, cb, p[i].pComment, TRUE);
        }
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    pBuffer = CallEnumPrinters(2, &cb, &c);
    if (pBuffer)
    {
        PRINTER_INFO_2W *p = (PRINTER_INFO_2W *)pBuffer;
        for (i = 0; i < c; i++)
        {
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pPrinterName, FALSE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pPortName, FALSE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pDriverName, FALSE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pServerName, TRUE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pShareName, TRUE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pComment, TRUE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pLocation, TRUE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pSepFile, TRUE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pPrintProcessor, FALSE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pDatatype, FALSE);
            CheckString("EnumPrinters", 2, pBuffer, cb, p[i].pParameters, TRUE);
            if (p[i].pDevMode)
                ok(InBuffer(pBuffer, cb, p[i].pDevMode), "EnumPrinters level 2: pDevMode %p is outside the buffer\n", p[i].pDevMode);
        }
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    pBuffer = CallEnumPrinters(4, &cb, &c);
    if (pBuffer)
    {
        PRINTER_INFO_4W *p = (PRINTER_INFO_4W *)pBuffer;
        for (i = 0; i < c; i++)
            CheckString("EnumPrinters", 4, pBuffer, cb, p[i].pPrinterName, FALSE);
        if (c && !pwszPrinter[0])
            lstrcpynW(pwszPrinter, p[0].pPrinterName, cchPrinter);
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    pBuffer = CallEnumPrinters(5, &cb, &c);
    if (pBuffer)
    {
        PRINTER_INFO_5W *p = (PRINTER_INFO_5W *)pBuffer;
        for (i = 0; i < c; i++)
        {
            CheckString("EnumPrinters", 5, pBuffer, cb, p[i].pPrinterName, FALSE);
            CheckString("EnumPrinters", 5, pBuffer, cb, p[i].pPortName, FALSE);
        }
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }
}

static void TestPrinter(LPWSTR pwszPrinter)
{
    HANDLE hPrinter = NULL;
    DWORD cb, cbBuffer, dwLevel;
    BYTE *pBuffer;
    LONG lSize;

    if (!OpenPrinterW(pwszPrinter, &hPrinter, NULL))
    {
        skip("OpenPrinterW(%ls) failed: %lu\n", pwszPrinter, GetLastError());
        return;
    }

    /* GetPrinter: the strings of the information about the printer */
    for (dwLevel = 1; dwLevel <= 2; dwLevel++)
    {
        cb = 0;
        SetLastError(0xdeadbeef);
        ok(!GetPrinterW(hPrinter, dwLevel, NULL, 0, &cb), "GetPrinterW level %lu without a buffer succeeded\n", dwLevel);
        ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "GetPrinterW level %lu: error %lu\n", dwLevel, GetLastError());
        if (!cb)
            continue;
        cbBuffer = cb;
        pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer);
        if (GetPrinterW(hPrinter, dwLevel, pBuffer, cbBuffer, &cb))
        {
            if (dwLevel == 1)
            {
                PRINTER_INFO_1W *p = (PRINTER_INFO_1W *)pBuffer;
                CheckString("GetPrinter", 1, pBuffer, cbBuffer, p->pName, FALSE);
            }
            else
            {
                PRINTER_INFO_2W *p = (PRINTER_INFO_2W *)pBuffer;
                CheckString("GetPrinter", 2, pBuffer, cbBuffer, p->pPrinterName, FALSE);
                CheckString("GetPrinter", 2, pBuffer, cbBuffer, p->pPortName, FALSE);
                CheckString("GetPrinter", 2, pBuffer, cbBuffer, p->pDriverName, FALSE);
                CheckString("GetPrinter", 2, pBuffer, cbBuffer, p->pPrintProcessor, FALSE);
                CheckString("GetPrinter", 2, pBuffer, cbBuffer, p->pDatatype, FALSE);
            }
        }
        else
            ok(0, "GetPrinterW level %lu failed: %lu\n", dwLevel, GetLastError());
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    /* GetPrinterDriver: the driver's files, then (what hangs) the call that loads the configuration file */
    for (dwLevel = 2; dwLevel <= 3; dwLevel++)
    {
        cb = 0;
        SetLastError(0xdeadbeef);
        GetPrinterDriverW(hPrinter, NULL, dwLevel, NULL, 0, &cb);
        ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "GetPrinterDriverW level %lu: error %lu\n", dwLevel, GetLastError());
        if (!cb)
            continue;
        cbBuffer = cb;
        pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer);
        if (GetPrinterDriverW(hPrinter, NULL, dwLevel, pBuffer, cbBuffer, &cb))
        {
            DRIVER_INFO_3W *p = (DRIVER_INFO_3W *)pBuffer;     /* levels 2 and 3 start alike */
            CheckString("GetPrinterDriver", dwLevel, pBuffer, cbBuffer, p->pName, FALSE);
            CheckString("GetPrinterDriver", dwLevel, pBuffer, cbBuffer, p->pEnvironment, FALSE);
            CheckString("GetPrinterDriver", dwLevel, pBuffer, cbBuffer, p->pDriverPath, FALSE);
            CheckString("GetPrinterDriver", dwLevel, pBuffer, cbBuffer, p->pDataFile, FALSE);
            CheckString("GetPrinterDriver", dwLevel, pBuffer, cbBuffer, p->pConfigFile, FALSE);
        }
        else
            ok(0, "GetPrinterDriverW level %lu failed: %lu\n", dwLevel, GetLastError());
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    lSize = DocumentPropertiesW(NULL, hPrinter, pwszPrinter, NULL, NULL, 0);
    ok(lSize >= (LONG)sizeof(DEVMODEW), "DocumentPropertiesW size query returned %ld (error %lu)\n", lSize, GetLastError());
    if (lSize >= (LONG)sizeof(DEVMODEW))
    {
        DEVMODEW *pDevMode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lSize);
        LONG lResult = DocumentPropertiesW(NULL, hPrinter, pwszPrinter, pDevMode, NULL, DM_OUT_BUFFER);
        ok(lResult > 0, "DocumentPropertiesW(DM_OUT_BUFFER) returned %ld (error %lu)\n", lResult, GetLastError());
        ok(pDevMode->dmSize >= FIELD_OFFSET(DEVMODEW, dmFields) && pDevMode->dmSize + pDevMode->dmDriverExtra <= lSize,
           "DEVMODE of %u + %u bytes in a buffer of %ld\n", pDevMode->dmSize, pDevMode->dmDriverExtra, lSize);
        HeapFree(GetProcessHeap(), 0, pDevMode);
    }

    /* EnumForms: the names of the forms */
    {
        DWORD c = 0, i;

        cb = 0;
        SetLastError(0xdeadbeef);
        EnumFormsW(hPrinter, 1, NULL, 0, &cb, &c);
        ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "EnumFormsW: error %lu\n", GetLastError());
        if (cb)
        {
            pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
            if (EnumFormsW(hPrinter, 1, pBuffer, cb, &cb, &c))
            {
                FORM_INFO_1W *p = (FORM_INFO_1W *)pBuffer;
                ok(c > 0, "EnumFormsW returned no forms\n");
                for (i = 0; i < c; i++)
                    CheckString("EnumForms", 1, pBuffer, cb, p[i].pName, FALSE);
            }
            else
                ok(0, "EnumFormsW failed: %lu\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, pBuffer);
        }
    }

    ClosePrinter(hPrinter);
}

static void TestPortsAndMonitors(void)
{
    DWORD cb, c, i, dwLevel;
    BYTE *pBuffer;

    for (dwLevel = 1; dwLevel <= 2; dwLevel++)
    {
        cb = c = 0;
        SetLastError(0xdeadbeef);
        EnumPortsW(NULL, dwLevel, NULL, 0, &cb, &c);
        ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "EnumPortsW level %lu: error %lu\n", dwLevel, GetLastError());
        if (cb)
        {
            pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
            if (EnumPortsW(NULL, dwLevel, pBuffer, cb, &cb, &c))
            {
                for (i = 0; i < c; i++)
                {
                    LPCWSTR pwszName = dwLevel == 1 ? ((PORT_INFO_1W *)pBuffer)[i].pName : ((PORT_INFO_2W *)pBuffer)[i].pPortName;
                    CheckString("EnumPorts", dwLevel, pBuffer, cb, pwszName, FALSE);
                }
            }
            else
                ok(0, "EnumPortsW level %lu failed: %lu\n", dwLevel, GetLastError());
            HeapFree(GetProcessHeap(), 0, pBuffer);
        }

        cb = c = 0;
        SetLastError(0xdeadbeef);
        EnumMonitorsW(NULL, dwLevel, NULL, 0, &cb, &c);
        ok(GetLastError() == ERROR_INSUFFICIENT_BUFFER, "EnumMonitorsW level %lu: error %lu\n", dwLevel, GetLastError());
        if (cb)
        {
            pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
            if (EnumMonitorsW(NULL, dwLevel, pBuffer, cb, &cb, &c))
            {
                for (i = 0; i < c; i++)
                {
                    LPCWSTR pwszName = dwLevel == 1 ? ((MONITOR_INFO_1W *)pBuffer)[i].pName : ((MONITOR_INFO_2W *)pBuffer)[i].pName;
                    CheckString("EnumMonitors", dwLevel, pBuffer, cb, pwszName, FALSE);
                }
            }
            else
                ok(0, "EnumMonitorsW level %lu failed: %lu\n", dwLevel, GetLastError());
            HeapFree(GetProcessHeap(), 0, pBuffer);
        }
    }
}

START_TEST(ClientStructures)
{
    WCHAR wszPrinter[MAX_PATH] = L"";

    TestEnumPrinters(wszPrinter, ARRAYSIZE(wszPrinter));
    if (wszPrinter[0])
        TestPrinter(wszPrinter);
    else
        skip("There is no printer: the rows of GetPrinter, GetPrinterDriver and DocumentProperties are skipped\n");
    TestPortsAndMonitors();
}
