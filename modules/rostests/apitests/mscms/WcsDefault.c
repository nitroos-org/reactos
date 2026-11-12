/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for the Wcs default-profile queries of mscms.dll and for the default sRGB profile
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <icm.h>

/*
 * GIMP (libgimpwidgets) asks WcsGetDefaultColorProfileSize / WcsGetDefaultColorProfile for the profile of the
 * monitor it is drawing on, and went down in the unimplemented-function exception of the Wcs stubs. The values
 * below were measured on Windows 10 22H2 (build 19045), a machine with no display association list, by a
 * read-only probe (2026-11-12): nothing is associated, so a query for a default profile is answered with
 * ERROR_FILE_NOT_FOUND (no profile), a query that makes no sense with ERROR_INVALID_PARAMETER.
 */

typedef BOOL (WINAPI *PFN_SIZE)(WCS_PROFILE_MANAGEMENT_SCOPE, PCWSTR, COLORPROFILETYPE, COLORPROFILESUBTYPE, DWORD, PDWORD);
typedef BOOL (WINAPI *PFN_GET)(WCS_PROFILE_MANAGEMENT_SCOPE, PCWSTR, COLORPROFILETYPE, COLORPROFILESUBTYPE, DWORD, DWORD, LPWSTR);
typedef BOOL (WINAPI *PFN_INTENT)(WCS_PROFILE_MANAGEMENT_SCOPE, PDWORD);
typedef BOOL (WINAPI *PFN_PERUSER)(PCWSTR, DWORD, BOOL *);
typedef BOOL (WINAPI *PFN_BOOLP)(BOOL *);
typedef BOOL (WINAPI *PFN_ENUMSIZE)(WCS_PROFILE_MANAGEMENT_SCOPE, ENUMTYPEW *, DWORD *);
typedef BOOL (WINAPI *PFN_STDPROFILE)(PCWSTR, DWORD, PWSTR, PDWORD);

static PFN_SIZE pWcsGetDefaultColorProfileSize;
static PFN_GET pWcsGetDefaultColorProfile;
static PFN_INTENT pWcsGetDefaultRenderingIntent;
static PFN_PERUSER pWcsGetUsePerUserProfiles;
static PFN_BOOLP pWcsGetCalibrationManagementState;
static PFN_ENUMSIZE pWcsEnumColorProfilesSize;
static PFN_STDPROFILE pGetStandardColorSpaceProfileW;

#define SUB_NONE CPST_NONE

static void
test_one_default(WCS_PROFILE_MANAGEMENT_SCOPE scope, PCWSTR device, COLORPROFILETYPE type, COLORPROFILESUBTYPE sub,
                 BOOL expectOk, DWORD expectErr, const char *what)
{
    DWORD size = 0xdead;
    WCHAR buf[MAX_PATH];
    BOOL ret;

    SetLastError(0xdeadbeef);
    ret = pWcsGetDefaultColorProfileSize(scope, device, type, sub, 0, &size);
    if (expectOk)
    {
        ok(ret, "%s: size query failed (%lu)\n", what, GetLastError());
        if (ret)
        {
            ok(size >= sizeof(WCHAR), "%s: size %lu\n", what, size);
            SetLastError(0xdeadbeef);
            ret = pWcsGetDefaultColorProfile(scope, device, type, sub, 0, size, buf);
            ok(ret, "%s: get failed (%lu)\n", what, GetLastError());
            if (ret) ok(lstrlenW(buf) == (int)(size / sizeof(WCHAR)) - 1, "%s: size %lu, name length %d\n", what, size, lstrlenW(buf));
            SetLastError(0xdeadbeef);
            ret = pWcsGetDefaultColorProfile(scope, device, type, sub, 0, size - sizeof(WCHAR), buf);
            ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "%s: small buffer: %d, %lu\n", what, ret, GetLastError());
        }
    }
    else
    {
        ok(!ret, "%s: size query succeeded\n", what);
        ok(GetLastError() == expectErr, "%s: error %lu, expected %lu\n", what, GetLastError(), expectErr);
        ok(size == 0xdead, "%s: size changed to %lu\n", what, size);
        SetLastError(0xdeadbeef);
        buf[0] = 0x4141;
        ret = pWcsGetDefaultColorProfile(scope, device, type, sub, 0, sizeof(buf), buf);
        ok(!ret, "%s: get succeeded\n", what);
        ok(GetLastError() == expectErr, "%s: get error %lu, expected %lu\n", what, GetLastError(), expectErr);
    }
}

static void
test_defaults(WCS_PROFILE_MANAGEMENT_SCOPE scope)
{
    static const WCHAR *devices[] = { L"\\\\.\\DISPLAY1", L"NoSuchDevice-xyz" };
    DWORD size = 0xdead, i, t, s;
    WCHAR buf[MAX_PATH];
    BOOL ret;

    /* no output pointer */
    SetLastError(0xdeadbeef);
    ret = pWcsGetDefaultColorProfileSize(scope, NULL, CPT_ICC, CPST_NONE, 0, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "NULL size: %d, %lu\n", ret, GetLastError());
    SetLastError(0xdeadbeef);
    ret = pWcsGetDefaultColorProfile(scope, NULL, CPT_ICC, CPST_NONE, 0, sizeof(buf), NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "NULL buffer: %d, %lu\n", ret, GetLastError());

    /* system default, working spaces: nothing associated */
    test_one_default(scope, NULL, CPT_ICC, CPST_RGB_WORKING_SPACE, FALSE, ERROR_FILE_NOT_FOUND, "ICC RGB working space");
    test_one_default(scope, NULL, CPT_ICC, CPST_CUSTOM_WORKING_SPACE, FALSE, ERROR_FILE_NOT_FOUND, "ICC custom working space");
    /* system default, without a device the rendering intents, DMP and GMMP are not valid */
    for (s = CPST_PERCEPTUAL; s <= CPST_NONE; s++)
        test_one_default(scope, NULL, CPT_ICC, s, FALSE, ERROR_INVALID_PARAMETER, "ICC intent without device");
    test_one_default(scope, NULL, CPT_DMP, CPST_NONE, FALSE, ERROR_INVALID_PARAMETER, "DMP");
    test_one_default(scope, NULL, CPT_GMMP, CPST_NONE, FALSE, ERROR_INVALID_PARAMETER, "GMMP");

    /* the default colour appearance model: Windows names D65.camp (18 bytes); it only is a profile when its file is there */
    SetLastError(0xdeadbeef);
    ret = pWcsGetDefaultColorProfileSize(scope, NULL, CPT_CAMP, CPST_NONE, 0, &size);
    if (ret)
    {
        ok(size == 18, "CAMP size %lu\n", size);
        ret = pWcsGetDefaultColorProfile(scope, NULL, CPT_CAMP, CPST_NONE, 0, size, buf);
        ok(ret && !lstrcmpiW(buf, L"D65.camp"), "CAMP: %d\n", ret);
    }
    else
        ok(GetLastError() == ERROR_FILE_NOT_FOUND, "CAMP: %lu\n", GetLastError());

    /* a device that has no association: no profile, whatever is asked */
    for (i = 0; i < ARRAYSIZE(devices); i++)
        for (t = CPT_ICC; t <= CPT_GMMP; t++)
            for (s = CPST_PERCEPTUAL; s <= CPST_CUSTOM_WORKING_SPACE; s++)
                test_one_default(scope, devices[i], t, s, FALSE, ERROR_FILE_NOT_FOUND, "device");
}

static void
test_other_queries(void)
{
    DWORD intent, size = 0xdead, i;
    BOOL ret, flag;
    ENUMTYPEW record = { sizeof(record), ENUM_TYPE_VERSION };

    for (i = 0; i <= 1; i++)
    {
        intent = 0xdead;
        SetLastError(0xdeadbeef);
        ret = pWcsGetDefaultRenderingIntent(i, &intent);
        ok(ret, "intent scope %lu: %lu\n", i, GetLastError());
        ok(intent == INTENT_PERCEPTUAL, "intent scope %lu: %lu\n", i, intent);
    }
    SetLastError(0xdeadbeef);
    ret = pWcsGetDefaultRenderingIntent(0, NULL);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "intent NULL: %d, %lu\n", ret, GetLastError());

    flag = 0xdead;
    SetLastError(0xdeadbeef);
    ret = pWcsGetUsePerUserProfiles(L"\\\\.\\DISPLAY1", 'mntr', &flag);
    ok(ret && flag == FALSE, "per user: %d, %d\n", ret, flag);
    SetLastError(0xdeadbeef);
    ret = pWcsGetUsePerUserProfiles(NULL, 'mntr', &flag);
    ok(!ret && GetLastError() == ERROR_INVALID_PARAMETER, "per user NULL device: %d, %lu\n", ret, GetLastError());

    if (pWcsGetCalibrationManagementState)
    {
        flag = 0xdead;
        ret = pWcsGetCalibrationManagementState(&flag);
        ok(ret && flag == FALSE, "calibration: %d, %d\n", ret, flag);
    }

    /* every profile, either scope: the call works and counts the list. Windows 10 answered 268 bytes (a few profile
     * names); ReactOS answers with the one it can read: its mscms is built without lcms2 and cannot open a profile
     * to read the header, so the list may come back empty (1) there. */
    for (i = 0; i <= 1; i++)
    {
        size = 0xdead;
        SetLastError(0xdeadbeef);
        ret = pWcsEnumColorProfilesSize(i, &record, &size);
        ok(ret, "enum size scope %lu: %lu\n", i, GetLastError());
        ok(size != 0xdead && size >= 1, "enum size scope %lu: %lu\n", i, size);
    }
}

static void
test_srgb_profile(void)
{
    WCHAR path[MAX_PATH];
    DWORD size, len, got = 0;
    BYTE header[128];
    HANDLE file;
    BOOL ret;

    size = sizeof(path);
    ret = pGetStandardColorSpaceProfileW(NULL, LCS_sRGB, path, &size);
    ok(ret, "sRGB: %lu\n", GetLastError());
    if (!ret) return;
    len = lstrlenW(path);
    ok(len > 28 && !lstrcmpiW(path + len - 28, L"sRGB Color Space Profile.icm"), "name %ls\n", path);

    /* too small: the size needed comes back, in bytes with the terminating null */
    size = 10;
    SetLastError(0xdeadbeef);
    ret = pGetStandardColorSpaceProfileW(NULL, LCS_sRGB, path, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "small: %d, %lu\n", ret, GetLastError());
    ok(size == (len + 1) * sizeof(WCHAR), "small: size %lu, expected %lu\n", size, (len + 1) * (DWORD)sizeof(WCHAR));
    size = 0;
    SetLastError(0xdeadbeef);
    ret = pGetStandardColorSpaceProfileW(NULL, LCS_sRGB, NULL, &size);
    ok(!ret && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "NULL: %d, %lu\n", ret, GetLastError());
    ok(size == (len + 1) * sizeof(WCHAR), "NULL: size %lu\n", size);

    /* the file is there and is a display profile of an RGB device with the XYZ connection space */
    size = sizeof(path);
    pGetStandardColorSpaceProfileW(NULL, LCS_sRGB, path, &size);
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(file != INVALID_HANDLE_VALUE, "open: %lu\n", GetLastError());
    if (file == INVALID_HANDLE_VALUE) return;
    ret = ReadFile(file, header, sizeof(header), &got, NULL);
    ok(ret && got == sizeof(header), "read: %d, %lu\n", ret, got);
    ok(GetFileSize(file, NULL) == (DWORD)((header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3]), "size in header\n");
    CloseHandle(file);
    ok(!memcmp(header + 36, "acsp", 4), "signature\n");
    ok(!memcmp(header + 12, "mntr", 4), "class\n");
    ok(!memcmp(header + 16, "RGB ", 4), "colour space\n");
    ok(!memcmp(header + 20, "XYZ ", 4), "connection space\n");
    ok(header[8] == 2 || header[8] == 4, "version %u\n", header[8]);
}

START_TEST(WcsDefault)
{
    HMODULE mscms = LoadLibraryA("mscms.dll");

    if (!mscms)
    {
        skip("mscms.dll not available\n");
        return;
    }
    pWcsGetDefaultColorProfileSize = (PFN_SIZE)GetProcAddress(mscms, "WcsGetDefaultColorProfileSize");
    pWcsGetDefaultColorProfile = (PFN_GET)GetProcAddress(mscms, "WcsGetDefaultColorProfile");
    pWcsGetDefaultRenderingIntent = (PFN_INTENT)GetProcAddress(mscms, "WcsGetDefaultRenderingIntent");
    pWcsGetUsePerUserProfiles = (PFN_PERUSER)GetProcAddress(mscms, "WcsGetUsePerUserProfiles");
    pWcsGetCalibrationManagementState = (PFN_BOOLP)GetProcAddress(mscms, "WcsGetCalibrationManagementState");
    pWcsEnumColorProfilesSize = (PFN_ENUMSIZE)GetProcAddress(mscms, "WcsEnumColorProfilesSize");
    pGetStandardColorSpaceProfileW = (PFN_STDPROFILE)GetProcAddress(mscms, "GetStandardColorSpaceProfileW");

    if (!pWcsGetDefaultColorProfileSize || !pWcsGetDefaultColorProfile || !pWcsGetDefaultRenderingIntent ||
        !pWcsGetUsePerUserProfiles || !pWcsEnumColorProfilesSize || !pGetStandardColorSpaceProfileW)
    {
        skip("Wcs default-profile exports not available\n");
        return;
    }

    test_defaults(WCS_PROFILE_MANAGEMENT_SCOPE_SYSTEM_WIDE);
    test_defaults(WCS_PROFILE_MANAGEMENT_SCOPE_CURRENT_USER);
    test_other_queries();
    test_srgb_profile();
}
