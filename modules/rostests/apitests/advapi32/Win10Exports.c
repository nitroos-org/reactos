/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the small exports of advapi32 of Windows 10: IsValidRelativeSecurityDescriptor,
 *              RegDisablePredefinedCacheEx, TreeSetNamedSecurityInfoA, EventWriteStartScenario,
 *              EventWriteEndScenario and FreeEncryptedFileMetadata
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The results are those of Windows 10 22H2 (x64 and x86).
 */

#include "precomp.h"
#include <sddl.h>

typedef BOOL (WINAPI *FN_VALID)(PSECURITY_DESCRIPTOR, DWORD, SECURITY_INFORMATION);
typedef LONG (WINAPI *FN_RDPCE)(void);
typedef DWORD (WINAPI *FN_TSNI)(PSTR, DWORD, SECURITY_INFORMATION, PSID, PSID, PACL, PACL, DWORD, PVOID, DWORD, PVOID);
typedef ULONG (WINAPI *FN_SCENARIO)(ULONGLONG, const VOID *, ULONG, const VOID *);
typedef VOID (WINAPI *FN_FREEMETA)(PBYTE);

#define PENDING 0xdeadf00d

static void TestRelative(HMODULE hAdvapi32)
{
    FN_VALID pValid = (FN_VALID)GetProcAddress(hAdvapi32, "IsValidRelativeSecurityDescriptor");
    PSECURITY_DESCRIPTOR Sd = NULL;
    ULONG Length = 0;
    BYTE Bad[20] = { 0 };
    BOOL Ret;

    if (!pValid)
    {
        ok(!is_reactos(), "IsValidRelativeSecurityDescriptor is not exported\n");
        skip("IsValidRelativeSecurityDescriptor is not available\n");
        return;
    }
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:(A;;GA;;;WD)", SDDL_REVISION_1, &Sd, &Length),
       "conversion failed: %lu\n", GetLastError());
    if (!Sd)
        return;

    SetLastError(PENDING);
    Ret = pValid(Sd, Length, 0);
    ok(Ret == TRUE, "valid descriptor: %d\n", Ret);
    ok(GetLastError() == PENDING, "valid descriptor: last error %lu\n", GetLastError());
    Ret = pValid(Sd, Length, OWNER_SECURITY_INFORMATION);
    ok(Ret == TRUE, "owner required: %d\n", Ret);
    Ret = pValid(Sd, Length, SACL_SECURITY_INFORMATION);
    ok(Ret == TRUE, "SACL required, none present: %d\n", Ret);

    SetLastError(PENDING);
    Ret = pValid(Sd, 4, 0);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_SECURITY_DESCR, "4 bytes: %d, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pValid(Sd, Length - 1, 0);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_SECURITY_DESCR, "one byte short: %d, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pValid(Sd, 0, 0);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_SECURITY_DESCR, "no bytes: %d, error %lu\n", Ret, GetLastError());
    SetLastError(PENDING);
    Ret = pValid(Bad, sizeof(Bad), 0);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_SECURITY_DESCR, "zeros: %d, error %lu\n", Ret, GetLastError());
    Bad[0] = 1;
    SetLastError(PENDING);
    Ret = pValid(Bad, sizeof(Bad), 0);
    ok(Ret == FALSE && GetLastError() == ERROR_INVALID_SECURITY_DESCR, "revision 1, not relative: %d, error %lu\n", Ret, GetLastError());
    LocalFree(Sd);
}

static void TestMisc(HMODULE hAdvapi32)
{
    FN_RDPCE pDisable = (FN_RDPCE)GetProcAddress(hAdvapi32, "RegDisablePredefinedCacheEx");
    FN_TSNI pTree = (FN_TSNI)GetProcAddress(hAdvapi32, "TreeSetNamedSecurityInfoA");
    FN_FREEMETA pFree = (FN_FREEMETA)GetProcAddress(hAdvapi32, "FreeEncryptedFileMetadata");
    LONG Ret;
    DWORD Result;
    ULONG i;

    if (pDisable)
    {
        for (i = 0; i < 3; i++)
        {
            SetLastError(PENDING);
            Ret = pDisable();
            ok(Ret == ERROR_SUCCESS, "RegDisablePredefinedCacheEx %lu: %ld\n", i, Ret);
            ok(GetLastError() == PENDING, "RegDisablePredefinedCacheEx %lu: last error %lu\n", i, GetLastError());
        }
    }
    else
    {
        ok(!is_reactos(), "RegDisablePredefinedCacheEx is not exported\n");
    }

    if (pTree)
    {
        /* Not implemented on Windows 10 either: whatever it is given */
        SetLastError(PENDING);
        Result = pTree(NULL, 0, 0, NULL, NULL, NULL, NULL, 0, NULL, 0, NULL);
        ok(Result == ERROR_CALL_NOT_IMPLEMENTED, "TreeSetNamedSecurityInfoA(NULL): %lu\n", Result);
        ok(GetLastError() == PENDING, "TreeSetNamedSecurityInfoA(NULL): last error %lu\n", GetLastError());
        Result = pTree((PSTR)"C:\\Windows\\nosuch", 1, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, 0, NULL, 0, NULL);
        ok(Result == ERROR_CALL_NOT_IMPLEMENTED, "TreeSetNamedSecurityInfoA(path): %lu\n", Result);
    }
    else
    {
        ok(!is_reactos(), "TreeSetNamedSecurityInfoA is not exported\n");
    }

    if (pFree)
        pFree(NULL);
    else
        ok(!is_reactos(), "FreeEncryptedFileMetadata is not exported\n");
}

static void TestScenario(HMODULE hAdvapi32)
{
    FN_SCENARIO pStart = (FN_SCENARIO)GetProcAddress(hAdvapi32, "EventWriteStartScenario");
    FN_SCENARIO pEnd = (FN_SCENARIO)GetProcAddress(hAdvapi32, "EventWriteEndScenario");
    BYTE Descriptor[16] = { 0 };
    ULONG Result;

    if (!pStart || !pEnd)
    {
        ok(!is_reactos(), "EventWriteStart/EndScenario are not exported\n");
        skip("EventWriteStartScenario is not available\n");
        return;
    }

    /* A descriptor with a handle that is none, or with one that this provider cannot use, is an invalid handle */
    Result = pStart(0, Descriptor, 0, NULL);
    ok(Result == ERROR_INVALID_HANDLE, "start, handle 0: %lu\n", Result);
    Result = pEnd(0, Descriptor, 0, NULL);
    ok(Result == ERROR_INVALID_HANDLE, "end, handle 0: %lu\n", Result);
    Result = pStart(0x1234, Descriptor, 0, NULL);
    ok(Result == ERROR_INVALID_HANDLE, "start, bad handle: %lu\n", Result);
    Result = pEnd(0x1234, Descriptor, 0, NULL);
    ok(Result == ERROR_INVALID_HANDLE, "end, bad handle: %lu\n", Result);
    /* ... and with no descriptor, whatever the handle, an invalid parameter */
    Result = pStart(0, NULL, 0, NULL);
    ok(Result == ERROR_INVALID_PARAMETER, "start, no descriptor: %lu\n", Result);
    Result = pEnd(0x1234, NULL, 0, NULL);
    ok(Result == ERROR_INVALID_PARAMETER, "end, no descriptor: %lu\n", Result);
}

START_TEST(Win10Exports)
{
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");

    TestRelative(hAdvapi32);
    TestMisc(hAdvapi32);
    TestScenario(hAdvapi32);
}
