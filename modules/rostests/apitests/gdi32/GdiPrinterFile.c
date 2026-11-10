/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test printing a document to a file
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

START_TEST(GdiPrinterFile)
{
    WCHAR output[MAX_PATH];
    static const WCHAR text[] = L"GDI printer contract";
    DOCINFOW document = { sizeof(document), L"GDI printer contract", NULL, NULL, 0 };
    HDC printer;
    HANDLE file;
    DWORD size;
    unsigned int attempt;
    WCHAR printer_name[256];

    size = GetEnvironmentVariableW(L"GDI_TEST_PRINTER", printer_name,
                                   ARRAYSIZE(printer_name));
    if (size == 0)
        lstrcpyW(printer_name, L"Dummy Printer On LPT1");
    else if (size >= ARRAYSIZE(printer_name))
    {
        skip("GDI_TEST_PRINTER is too long\n");
        return;
    }

    /* The job goes to a file in the temporary directory */
    size = GetTempPathW(ARRAYSIZE(output), output);
    if (size == 0 || size + 20 >= ARRAYSIZE(output))
    {
        skip("No temporary directory\n");
        return;
    }
    lstrcatW(output, L"gdi-printer.prn");
    document.lpszOutput = output;
    DeleteFileW(output);
    printer = CreateDCW(L"WINSPOOL", printer_name, NULL, NULL);
    if (!printer)
    {
        skip("Printer %s is unavailable: %lu\n",
             wine_dbgstr_w(printer_name), GetLastError());
        return;
    }

    if (StartDocW(printer, &document) <= 0)
    {
        ok(0, "StartDocW failed: %lu\n", GetLastError());
        DeleteDC(printer);
        return;
    }

    ok(StartPage(printer) > 0, "StartPage failed: %lu\n", GetLastError());
    ok(TextOutW(printer, 120, 120, text, ARRAYSIZE(text) - 1),
       "TextOutW failed: %lu\n", GetLastError());
    ok(EndPage(printer) > 0, "EndPage failed: %lu\n", GetLastError());
    ok(EndDoc(printer) > 0, "EndDoc failed: %lu\n", GetLastError());
    DeleteDC(printer);

    for (attempt = 0; attempt < 50; attempt++)
    {
        file = CreateFileW(output, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE)
            break;
        Sleep(100);
    }
    ok(file != INVALID_HANDLE_VALUE, "Printed output was not written to the file\n");
    if (file != INVALID_HANDLE_VALUE)
    {
        size = GetFileSize(file, NULL);
        ok(size != INVALID_FILE_SIZE && size != 0, "Printed file is empty\n");
        CloseHandle(file);
    }
    DeleteFileW(output);
}
