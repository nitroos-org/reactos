/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPL - See COPYING in the top level directory
 * PURPOSE:         Test for AddFontResource
 * PROGRAMMERS:     Timo Kreuzer
 */

#include "precomp.h"

#define COUNT 26

void Test_AddFontResourceA()
{
    CHAR szCurrentDir[MAX_PATH];
    CHAR szFileNameFont1[MAX_PATH];
    CHAR szFileNameFont2[MAX_PATH];
    CHAR szFileName[MAX_PATH*2 + 3];
    int result;

    GetCurrentDirectoryA(MAX_PATH, szCurrentDir);

    snprintf(szFileNameFont1, MAX_PATH, "%s\\testdata\\test.ttf", szCurrentDir);
    snprintf(szFileNameFont2, MAX_PATH, "%s\\testdata\\test.otf", szCurrentDir);

    //RtlZeroMemory(szFileNameA, sizeof(szFileNameA));

    /* Testing NULL pointer */
    SetLastError(ERROR_SUCCESS);
    result = AddFontResourceA(NULL);
    ok(result == 0, "AddFontResourceA succeeded, result=%d\n", result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());

    /* Testing -1 pointer */
    SetLastError(ERROR_SUCCESS);
    result = AddFontResourceA((CHAR*)-1);
    ok(result == 0, "AddFontResourceA succeeded, result=%d\n", result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());

    /* Testing address 1 pointer */
    SetLastError(ERROR_SUCCESS);
    result = AddFontResourceA((CHAR*)1);
    ok(result == 0, "AddFontResourceA succeeded, result=%d\n", result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());

    /* Testing address empty string */
    SetLastError(ERROR_SUCCESS);
    result = AddFontResourceA("");
    ok(result == 0, "AddFontResourceA succeeded, result=%d\n", result);
    ok(GetLastError() == ERROR_INVALID_PARAMETER, "GetLastError()=%ld\n", GetLastError());

    /* Testing one ttf font */
    SetLastError(ERROR_SUCCESS);
    result = AddFontResourceA(szFileNameFont1);
    ok(result == 1, "AddFontResourceA(\"%s\") failed, result=%d\n", szFileNameFont1, result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());
    RemoveFontResourceA(szFileNameFont1);

    /* Testing one otf font */
    SetLastError(ERROR_SUCCESS);
    result = AddFontResourceA(szFileNameFont2);
    ok(result == 1, "AddFontResourceA failed, result=%d\n", result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());
    RemoveFontResourceA(szFileNameFont2);

    /* Testing two fonts */
    SetLastError(ERROR_SUCCESS);
    sprintf(szFileName,"%s|%s",szFileNameFont1, szFileNameFont2);
    result = AddFontResourceA(szFileName);
    ok(result == 0, "AddFontResourceA succeeded, result=%d\n", result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());

    SetLastError(ERROR_SUCCESS);
    sprintf(szFileName,"%s |%s",szFileNameFont1, szFileNameFont2);
    result = AddFontResourceA(szFileName);
    ok(result == 0, "AddFontResourceA succeeded, result=%d\n", result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());

    SetLastError(ERROR_SUCCESS);
    sprintf(szFileName,"%s | %s",szFileNameFont1, szFileNameFont2);
    result = AddFontResourceA(szFileName);
    ok(result == 0, "AddFontResourceA succeeded, result=%d\n", result);
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "GetLastError()=%ld\n", GetLastError());

    snprintf(szFileNameFont1, MAX_PATH, "%s\\testdata\\test.pfm", szCurrentDir);
    snprintf(szFileNameFont2, MAX_PATH, "%s\\testdata\\test.pfb", szCurrentDir);

    SetLastError(ERROR_SUCCESS);

    sprintf(szFileName,"%s|%s", szFileNameFont1, szFileNameFont2);
    result = AddFontResourceA(szFileName);
    ok(result == 1, "AddFontResourceA(\"%s|%s\") failed, result=%d\n",
                    szFileNameFont1, szFileNameFont2, result);
    ok(GetLastError() == ERROR_SUCCESS, "GetLastError()=%ld\n", GetLastError());
    RemoveFontResourceA(szFileName);

    sprintf(szFileName,"%s | %s", szFileNameFont1, szFileNameFont2);
    result = AddFontResourceA(szFileName);
    ok(result == 0, "AddFontResourceA(\"%s | %s\") succeeded, result=%d\n",
                    szFileNameFont1, szFileNameFont2, result);
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "GetLastError()=%ld\n", GetLastError());
    RemoveFontResourceA(szFileName);

    sprintf(szFileName,"%s|%s", szFileNameFont2, szFileNameFont1);
    result = AddFontResourceA(szFileName);
    ok(result == 0, "AddFontResourceA(\"%s|%s\") succeeded, result=%d\n",
                    szFileNameFont2, szFileNameFont1, result);
    ok(GetLastError() == ERROR_FILE_NOT_FOUND, "GetLastError()=%ld\n", GetLastError());
}

/*
 * The file of a loaded font stays open (shared for reading only) while the font is loaded, so an installer
 * cannot overwrite or delete it and has to schedule the replacement for the next boot. RemoveFontResource
 * releases it.
 */
static void Test_FontFileInUse(void)
{
    CHAR szCurrentDir[MAX_PATH], szSource[MAX_PATH], szTemp[MAX_PATH], szCopy[MAX_PATH];
    HANDLE hFile;
    DWORD dwError;
    int result;
    BOOL ret;

    GetCurrentDirectoryA(MAX_PATH, szCurrentDir);
    snprintf(szSource, MAX_PATH, "%s\\testdata\\test.ttf", szCurrentDir);
    GetTempPathA(MAX_PATH, szTemp);
    snprintf(szCopy, MAX_PATH, "%sfontinuse.ttf", szTemp);

    ret = CopyFileA(szSource, szCopy, FALSE);
    ok(ret, "CopyFile failed, error %lu\n", GetLastError());
    if (!ret)
        return;

    result = AddFontResourceA(szCopy);
    ok(result == 1, "AddFontResourceA failed, result=%d\n", result);

    /* Reading is possible */
    hFile = CreateFileA(szCopy, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "Reading a loaded font file failed, error %lu\n", GetLastError());
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    /* Overwriting is not */
    SetLastError(0xdeadbeef);
    hFile = CreateFileA(szCopy, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, CREATE_ALWAYS, 0, NULL);
    dwError = GetLastError();
    ok(hFile == INVALID_HANDLE_VALUE, "Overwriting a loaded font file succeeded\n");
    ok(dwError == ERROR_SHARING_VIOLATION, "Error %lu\n", dwError);
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);

    SetLastError(0xdeadbeef);
    ret = CopyFileA(szSource, szCopy, FALSE);
    ok(!ret, "CopyFile over a loaded font file succeeded\n");

    SetLastError(0xdeadbeef);
    ret = DeleteFileA(szCopy);
    ok(!ret, "DeleteFile of a loaded font file succeeded\n");

    /* Unloaded, it is free */
    ret = RemoveFontResourceA(szCopy);
    ok(ret, "RemoveFontResourceA failed, error %lu\n", GetLastError());
    ret = DeleteFileA(szCopy);
    ok(ret, "DeleteFile after RemoveFontResource failed, error %lu\n", GetLastError());
}

START_TEST(AddFontResource)
{
    Test_AddFontResourceA();
    Test_FontFileInUse();
}

