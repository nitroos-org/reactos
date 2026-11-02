/*
 * PROJECT:     ReactOS system ICU (icu.dll)
 * LICENSE:     MIT (https://spdx.org/licenses/MIT.html)
 * PURPOSE:     Maps the system ICU data file and hands it to ICU as its common data
 *
 * Windows 10 keeps the ICU data package in %SystemRoot%\Globalization\ICU\icudtl.dat. ICU itself would look
 * for "icudt64l.dat" in a data directory, so the file is mapped here and given to ICU with udata_setCommonData().
 * The mapping stays for the life of the process (ICU hands out pointers into it).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "unicode/utypes.h"
#include "unicode/udata.h"

static void
MapSystemIcuData(void)
{
    WCHAR szPath[MAX_PATH];
    HANDLE hFile, hMapping;
    const void *pData;
    UErrorCode status = U_ZERO_ERROR;
    UINT cch;

    cch = GetSystemWindowsDirectoryW(szPath, ARRAYSIZE(szPath));
    if (cch == 0 || cch + 32 >= ARRAYSIZE(szPath))
        return;
    lstrcpyW(szPath + cch, L"\\Globalization\\ICU\\icudtl.dat");

    hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMapping)
        return;

    pData = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);
    if (!pData)
        return;

    udata_setCommonData(pData, &status);
    if (U_FAILURE(status))
        UnmapViewOfFile(pData);
}

extern "C" BOOL WINAPI
DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(lpReserved);

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInstDll);
        MapSystemIcuData();
    }
    return TRUE;
}
