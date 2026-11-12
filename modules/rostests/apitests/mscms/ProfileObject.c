/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for mscms profile objects (OpenColorProfile, header and tag access, colour transforms)
 *              on the shipped sRGB profile; needs the profile engine (Little CMS) behind mscms.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <icm.h>
#include <stdio.h>

#ifndef CLASS_MONITOR
#define CLASS_MONITOR 0x6d6e7472 /* mntr */
#endif
#ifndef NORMAL_MODE
#define NORMAL_MODE 2
#endif
#ifndef USE_RELATIVE_COLORIMETRIC
#define USE_RELATIVE_COLORIMETRIC 0x00020000
#endif

static BOOL OpenStd(HPROFILE *phProfile, WCHAR *path, DWORD cchPath)
{
    DWORD cb = cchPath * sizeof(WCHAR);
    PROFILE prof;

    if (!GetStandardColorSpaceProfileW(NULL, LCS_sRGB, path, &cb))
    {
        skip("GetStandardColorSpaceProfileW failed (%lu)\n", GetLastError());
        return FALSE;
    }
    prof.dwType = PROFILE_FILENAME;
    prof.pProfileData = path;
    prof.cbDataSize = (lstrlenW(path) + 1) * sizeof(WCHAR);
    *phProfile = OpenColorProfileW(&prof, PROFILE_READ, FILE_SHARE_READ, OPEN_EXISTING);
    ok(*phProfile != NULL, "OpenColorProfileW failed (%lu)\n", GetLastError());
    return *phProfile != NULL;
}

static void test_open_header_tags(void)
{
    WCHAR path[MAX_PATH];
    HPROFILE hProfile;
    PROFILEHEADER hdr;
    DWORD count, size, i;
    BOOL ret, present, ref;
    TAGTYPE tag;
    BYTE buf[256];
    HANDLE hFile;

    if (!OpenStd(&hProfile, path, MAX_PATH))
        return;

    memset(&hdr, 0, sizeof(hdr));
    ret = GetColorProfileHeader(hProfile, &hdr);
    ok(ret, "GetColorProfileHeader failed (%lu)\n", GetLastError());
    if (ret)
    {
        ok(hdr.phClass == CLASS_MONITOR, "phClass = %08lx\n", hdr.phClass);
        ok(hdr.phDataColorSpace == SPACE_RGB, "phDataColorSpace = %08lx\n", hdr.phDataColorSpace);
        ok(hdr.phConnectionSpace == SPACE_XYZ, "phConnectionSpace = %08lx\n", hdr.phConnectionSpace);
        ok(hdr.phSize > sizeof(hdr), "phSize = %lu\n", hdr.phSize);
        ok(hdr.phVersion >= 0x02000000 && hdr.phVersion < 0x05000000, "phVersion = %08lx\n", hdr.phVersion);
    }

    count = 0;
    ret = GetCountColorProfileElements(hProfile, &count);
    ok(ret, "GetCountColorProfileElements failed (%lu)\n", GetLastError());
    ok(count >= 3, "only %lu elements\n", count);

    /* every RGB matrix/TRC display profile has the three colorant tags and rXYZ is 20 bytes (sig, reserved, 3 x s15Fixed16) */
    ret = IsColorProfileTagPresent(hProfile, 0x7258595a /* rXYZ */, &present);
    ok(ret && present, "rXYZ present: ret %d present %d (%lu)\n", ret, present, GetLastError());
    ret = IsColorProfileTagPresent(hProfile, 0x4d4d4d4d /* nonsense */, &present);
    ok(ret && !present, "nonsense tag: ret %d present %d\n", ret, present);

    ret = GetColorProfileElementTag(hProfile, 1, &tag);
    ok(ret, "GetColorProfileElementTag failed (%lu)\n", GetLastError());

    size = 0;
    ret = GetColorProfileElement(hProfile, 0x7258595a, 0, &size, NULL, &ref);
    ok(!ret, "size query with no buffer succeeded\n");
    ok(size == 20, "rXYZ element size %lu\n", size);
    if (size && size <= sizeof(buf))
    {
        ret = GetColorProfileElement(hProfile, 0x7258595a, 0, &size, buf, &ref);
        ok(ret, "GetColorProfileElement failed (%lu)\n", GetLastError());
        ok(!memcmp(buf, "XYZ ", 4), "rXYZ signature %.4s\n", buf);
    }
    for (i = 1; i <= count && i <= 3; i++)
    {
        ret = GetColorProfileElementTag(hProfile, i, &tag);
        ok(ret && tag != 0, "element %lu: ret %d tag %08lx\n", i, ret, tag);
    }

    /* the file is opened for reading only: a write access needs a profile opened for it */
    ret = SetColorProfileHeader(hProfile, &hdr);
    ok(!ret, "SetColorProfileHeader succeeded on a read-only profile\n");

    ok(CloseColorProfile(hProfile), "CloseColorProfile failed\n");

    /* a memory profile: the same bytes read from the file */
    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "cannot read the profile file\n");
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD cb = GetFileSize(hFile, NULL), got = 0;
        BYTE *mem = HeapAlloc(GetProcessHeap(), 0, cb);
        PROFILE prof;

        ok(ReadFile(hFile, mem, cb, &got, NULL) && got == cb, "ReadFile\n");
        CloseHandle(hFile);
        prof.dwType = PROFILE_MEMBUFFER;
        prof.pProfileData = mem;
        prof.cbDataSize = cb;
        hProfile = OpenColorProfileW(&prof, PROFILE_READ, FILE_SHARE_READ, OPEN_EXISTING);
        ok(hProfile != NULL, "OpenColorProfileW(memory) failed (%lu)\n", GetLastError());
        if (hProfile)
        {
            memset(&hdr, 0, sizeof(hdr));
            ok(GetColorProfileHeader(hProfile, &hdr) && hdr.phClass == CLASS_MONITOR, "memory profile header\n");
            CloseColorProfile(hProfile);
        }
        HeapFree(GetProcessHeap(), 0, mem);
    }
}

static void test_transform(void)
{
    WCHAR path[MAX_PATH];
    HPROFILE hProfile, profs[2];
    HTRANSFORM hXform;
    DWORD intents[2] = { INTENT_PERCEPTUAL, INTENT_PERCEPTUAL };
    COLOR in[4], out[4];
    BOOL ret;
    int i;
    static const WORD vals[4][3] = { {0,0,0}, {65535,65535,65535}, {32768,32768,32768}, {65535,0,0} };

    if (!OpenStd(&hProfile, path, MAX_PATH))
        return;

    profs[0] = profs[1] = hProfile;
    hXform = CreateMultiProfileTransform(profs, 2, intents, 2, NORMAL_MODE | USE_RELATIVE_COLORIMETRIC, 0);
    ok(hXform != NULL, "CreateMultiProfileTransform failed (%lu)\n", GetLastError());
    if (hXform)
    {
        for (i = 0; i < 4; i++)
        {
            in[i].rgb.red = vals[i][0];
            in[i].rgb.green = vals[i][1];
            in[i].rgb.blue = vals[i][2];
        }
        memset(out, 0, sizeof(out));
        ret = TranslateColors(hXform, in, 4, COLOR_RGB, out, COLOR_RGB);
        ok(ret, "TranslateColors failed (%lu)\n", GetLastError());
        if (ret)
        {
            for (i = 0; i < 4; i++)
            {
                int dr = (int)out[i].rgb.red - (int)in[i].rgb.red;
                int dg = (int)out[i].rgb.green - (int)in[i].rgb.green;
                int db = (int)out[i].rgb.blue - (int)in[i].rgb.blue;
                /* sRGB to sRGB is the identity, give the 16 bit pipeline a little slack */
                ok(abs(dr) < 600 && abs(dg) < 600 && abs(db) < 600,
                   "colour %d: in %u,%u,%u out %u,%u,%u\n", i, in[i].rgb.red, in[i].rgb.green, in[i].rgb.blue,
                   out[i].rgb.red, out[i].rgb.green, out[i].rgb.blue);
            }
        }
        ok(DeleteColorTransform(hXform), "DeleteColorTransform failed\n");
    }
    CloseColorProfile(hProfile);
}

START_TEST(ProfileObject)
{
    test_open_header_tags();
    test_transform();
}
