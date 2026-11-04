/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for slc.dll: the SL* client API forwards to sppc.dll, SLGetWindowsInformation lives in slc
 *
 * msedgewebview2.exe delay-loads SLC.dll!SLGetWindowsInformation; the missing module made the WebView2
 * browser process die with 0xC06D007E.
 */

#include <apitest.h>

#include <windef.h>
#include <winbase.h>
#include <slpublic.h>

typedef HRESULT (WINAPI *PFN_GETWININFO)(PCWSTR, SLDATATYPE *, UINT *, PBYTE *);
typedef HRESULT (WINAPI *PFN_GETWININFODWORD)(PCWSTR, DWORD *);

START_TEST(slc)
{
    static const char *Forwarded[] =
    {
        "SLOpen", "SLClose", "SLInstallLicense", "SLUninstallLicense", "SLGetLicense", "SLGetSLIDList",
        "SLGetLicensingStatusInformation", "SLGetWindowsInformationDWORD", "SLGetPolicyInformationDWORD",
        "SLConsumeRight", "SLInstallProofOfPurchase",
    };
    HMODULE hSlc = LoadLibraryW(L"slc.dll");
    HMODULE hSppc = LoadLibraryW(L"sppc.dll");
    PFN_GETWININFO pGetWindowsInformation;
    PFN_GETWININFODWORD pGetWindowsInformationDWORD;
    SLDATATYPE Type = SL_DATA_DWORD;
    UINT cb = 0x1234;
    PBYTE pb = (PBYTE)(ULONG_PTR)0x1234;
    DWORD dw = 0x1234;
    HRESULT hr;
    UINT i;

    ok(hSlc != NULL, "slc.dll did not load, error %lu\n", GetLastError());
    ok(hSppc != NULL, "sppc.dll did not load\n");
    if (!hSlc || !hSppc)
        return;

    for (i = 0; i < ARRAYSIZE(Forwarded); i++)
    {
        FARPROC p1 = GetProcAddress(hSlc, Forwarded[i]);
        FARPROC p2 = GetProcAddress(hSppc, Forwarded[i]);

        ok(p1 != NULL, "slc does not export %s\n", Forwarded[i]);
        ok(p1 == p2, "%s: slc %p is not the sppc function %p\n", Forwarded[i], p1, p2);
    }

    pGetWindowsInformation = (PFN_GETWININFO)GetProcAddress(hSlc, "SLGetWindowsInformation");
    ok(pGetWindowsInformation != NULL, "slc does not export SLGetWindowsInformation\n");
    if (!pGetWindowsInformation)
        return;

    hr = pGetWindowsInformation(L"Kernel-NoSuchValue", &Type, &cb, &pb);
    ok(hr == SL_E_VALUE_NOT_FOUND, "SLGetWindowsInformation unknown value = 0x%08lx\n", (ULONG)hr);
    ok(cb == 0 && pb == NULL, "unknown value left cb %u pb %p\n", cb, pb);

    cb = 0x1234;
    pb = (PBYTE)(ULONG_PTR)0x1234;
    hr = pGetWindowsInformation(L"Kernel-NoSuchValue", NULL, &cb, &pb);
    ok(hr == SL_E_VALUE_NOT_FOUND, "SLGetWindowsInformation without type = 0x%08lx\n", (ULONG)hr);

    hr = pGetWindowsInformation(NULL, &Type, &cb, &pb);
    ok(hr == E_INVALIDARG, "SLGetWindowsInformation(NULL name) = 0x%08lx\n", (ULONG)hr);
    hr = pGetWindowsInformation(L"x", &Type, NULL, &pb);
    ok(hr == E_INVALIDARG, "SLGetWindowsInformation(NULL size) = 0x%08lx\n", (ULONG)hr);
    hr = pGetWindowsInformation(L"x", &Type, &cb, NULL);
    ok(hr == E_INVALIDARG, "SLGetWindowsInformation(NULL data) = 0x%08lx\n", (ULONG)hr);

    pGetWindowsInformationDWORD = (PFN_GETWININFODWORD)GetProcAddress(hSlc, "SLGetWindowsInformationDWORD");
    hr = pGetWindowsInformationDWORD(L"Kernel-NoSuchValue", &dw);
    ok(hr == SL_E_VALUE_NOT_FOUND, "SLGetWindowsInformationDWORD unknown value = 0x%08lx\n", (ULONG)hr);
}
