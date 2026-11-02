/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IApplicationAssociationRegistration
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expectations were measured on Windows Server 2008 R2 (6.1.7601). Windows 8 and later answer
 * most queries differently (QueryAppIsDefault says yes to everything), so those parts only run on
 * versions below 6.2; ReactOS reports 5.2 and runs everything.
 */

#include "shelltest.h"
#include <shellutils.h>

#define HKLM HKEY_LOCAL_MACHINE
#define HKCU HKEY_CURRENT_USER

#define APP         L"RosAarTestApp"
#define PROTO       L"rosaartestproto"
#define PROTO_EXP   L"rosaartestproto2"
#define PROTO_NOCMD L"rosaartestproto3"
#define PROTO_NOURL L"rosaartestproto4"
#define EXT         L".rosaartestext"
#define MIMETYPE    L"rosaartest/type"
#define CLIENTTYPE  L"RosAarTestClient"
#define HANDLER     L"RosAarTest.Handler"
#define HANDLER2    L"RosAarTest.Handler2"
#define MACHINEPROG L"RosAarTest.MachineProg"
#define EXT2        L".rosaartestext2"
#define MIME2       L"rosaartest/type2"
#define CLASSA      L"RosAarTest.ClassA"
#define CLASSB      L"RosAarTest.ClassB"
#define CLASSC      L"RosAarTest.ClassC"
#define MACHINECMD  L"C:\\rosaartest\\a.exe %1"
#define USERAPP     L"RosAarTestUserApp"

#define CLASSES     L"SOFTWARE\\Classes\\"
#define USERASSOC   L"Software\\Microsoft\\Windows\\Shell\\Associations"
#define FILEEXTS    L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts"
#define CLIENTS     L"Software\\Clients"
#define BACKUP      L"Software\\RosAarTestBackup"

enum
{
    HR_NOASSOC = HRESULT_FROM_WIN32(ERROR_NO_ASSOCIATION),
    HR_NOTREG = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND),
    HR_UNSUPPORTED = HRESULT_FROM_WIN32(ERROR_UNSUPPORTED_TYPE),
    HR_MISMATCH = HRESULT_FROM_WIN32(ERROR_DATATYPE_MISMATCH),
    AL_ALL_MACHINE = AL_MACHINE,
};

static BOOL IsWindows8OrNewer(void)
{
    typedef LONG (WINAPI *RTLGETVERSION)(OSVERSIONINFOW *);
    RTLGETVERSION pfn = (RTLGETVERSION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    OSVERSIONINFOW osvi = { sizeof(osvi) };
    if (!pfn || pfn(&osvi))
        return FALSE;
    return osvi.dwMajorVersion > 6 || (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 2);
}

static void SetStr(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszName, LPCWSTR pszData, DWORD dwType = REG_SZ)
{
    HKEY hKey;
    LONG err = RegCreateKeyExW(hRoot, pszKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (err == ERROR_SUCCESS)
    {
        err = RegSetValueExW(hKey, pszName, 0, dwType, (const BYTE *)pszData, (lstrlenW(pszData) + 1) * sizeof(WCHAR));
        RegCloseKey(hKey);
    }
    ok(err == ERROR_SUCCESS, "Setting %ls failed with %ld\n", pszKey, err);
}

static void SetDword(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszName, DWORD dwData)
{
    HKEY hKey;
    LONG err = RegCreateKeyExW(hRoot, pszKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (err == ERROR_SUCCESS)
    {
        err = RegSetValueExW(hKey, pszName, 0, REG_DWORD, (const BYTE *)&dwData, sizeof(dwData));
        RegCloseKey(hKey);
    }
    ok(err == ERROR_SUCCESS, "Setting %ls failed with %ld\n", pszKey, err);
}

static void DelKey(HKEY hRoot, LPCWSTR pszKey)
{
    SHDeleteKeyW(hRoot, pszKey);
}

static void DelValue(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszName)
{
    SHDeleteValueW(hRoot, pszKey, pszName);
}

static BOOL KeyExists(HKEY hRoot, LPCWSTR pszKey)
{
    HKEY hKey;
    if (RegOpenKeyExW(hRoot, pszKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(hKey);
    return TRUE;
}

static BOOL ValueExists(HKEY hRoot, LPCWSTR pszKey, LPCWSTR pszName)
{
    HKEY hKey;
    BOOL bResult;
    if (RegOpenKeyExW(hRoot, pszKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    bResult = RegQueryValueExW(hKey, pszName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS;
    RegCloseKey(hKey);
    return bResult;
}

static void UserChoice(ASSOCIATIONTYPE type, LPCWSTR pszQuery, LPCWSTR pszProgId)
{
    WCHAR szKey[260];
    switch (type)
    {
        case AT_URLPROTOCOL:
            wsprintfW(szKey, USERASSOC L"\\UrlAssociations\\%ls\\UserChoice", pszQuery);
            break;
        case AT_MIMETYPE:
            wsprintfW(szKey, USERASSOC L"\\MIMEAssociations\\%ls\\UserChoice", pszQuery);
            break;
        case AT_FILEEXTENSION:
            wsprintfW(szKey, FILEEXTS L"\\%ls\\UserChoice", pszQuery);
            break;
        default:
            wsprintfW(szKey, CLIENTS L"\\%ls", pszQuery);
            SetStr(HKCU, szKey, NULL, pszProgId);
            return;
    }
    SetStr(HKCU, szKey, L"Progid", pszProgId);
}

static void ClearUserChoice(ASSOCIATIONTYPE type, LPCWSTR pszQuery)
{
    WCHAR szKey[260];
    switch (type)
    {
        case AT_URLPROTOCOL:
            wsprintfW(szKey, USERASSOC L"\\UrlAssociations\\%ls", pszQuery);
            break;
        case AT_MIMETYPE:
            wsprintfW(szKey, USERASSOC L"\\MIMEAssociations\\%ls", pszQuery);
            break;
        case AT_FILEEXTENSION:
            wsprintfW(szKey, FILEEXTS L"\\%ls\\UserChoice", pszQuery);
            break;
        default:
            wsprintfW(szKey, CLIENTS L"\\%ls", pszQuery);
            DelValue(HKCU, szKey, NULL);
            return;
    }
    DelKey(HKCU, szKey);
}

static void Cleanup(void)
{
    DelKey(HKLM, CLASSES PROTO);
    DelKey(HKLM, CLASSES PROTO_EXP);
    DelKey(HKLM, CLASSES PROTO_NOCMD);
    DelKey(HKLM, CLASSES PROTO_NOURL);
    DelKey(HKLM, CLASSES HANDLER);
    DelKey(HKLM, CLASSES HANDLER2);
    DelKey(HKLM, CLASSES EXT);
    DelKey(HKLM, CLASSES EXT2);
    DelKey(HKLM, CLASSES CLASSA);
    DelKey(HKLM, CLASSES CLASSB);
    DelKey(HKLM, CLASSES CLASSC);
    DelKey(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIME2);
    DelKey(HKCU, L"Software\\Classes\\" EXT);
    DelKey(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIMETYPE);
    DelKey(HKLM, L"SOFTWARE\\Clients\\" CLIENTTYPE);
    DelKey(HKLM, L"SOFTWARE\\" APP);
    DelValue(HKLM, L"SOFTWARE\\RegisteredApplications", APP);
    DelKey(HKCU, L"Software\\" USERAPP);
    DelValue(HKCU, L"Software\\RegisteredApplications", USERAPP);
    ClearUserChoice(AT_URLPROTOCOL, PROTO);
    ClearUserChoice(AT_URLPROTOCOL, PROTO_EXP);
    ClearUserChoice(AT_FILEEXTENSION, EXT);
    ClearUserChoice(AT_FILEEXTENSION, EXT2);
    DelKey(HKCU, FILEEXTS L"\\" EXT);
    ClearUserChoice(AT_MIMETYPE, MIMETYPE);
    ClearUserChoice(AT_STARTMENUCLIENT, CLIENTTYPE);
    DelKey(HKCU, CLIENTS L"\\" CLIENTTYPE);
}

static void CheckQuery(int line, IApplicationAssociationRegistration *pAAR, LPCWSTR pszQuery,
                       ASSOCIATIONTYPE type, ASSOCIATIONLEVEL level, HRESULT hrExpected, LPCWSTR pszExpected)
{
    LPWSTR psz = (LPWSTR)(ULONG_PTR)0x1234;
    HRESULT hr = pAAR->QueryCurrentDefault(pszQuery, type, level, &psz);
    ok(hr == hrExpected, "%d: QueryCurrentDefault(%ls, %d, %d) returned 0x%lx, expected 0x%lx\n",
       line, pszQuery, type, level, hr, hrExpected);
    if (hr == S_OK && hrExpected == S_OK)
    {
        ok(psz && !lstrcmpW(psz, pszExpected), "%d: QueryCurrentDefault(%ls, %d, %d) returned '%ls', expected '%ls'\n",
           line, pszQuery, type, level, psz ? psz : L"(null)", pszExpected);
    }
    else
    {
        ok(psz == NULL, "%d: output is %p\n", line, psz);
        psz = NULL;
    }
    if (psz && psz != (LPWSTR)(ULONG_PTR)0x1234)
        CoTaskMemFree(psz);
}

static void CheckIsDefault(int line, IApplicationAssociationRegistration *pAAR, LPCWSTR pszQuery,
                           ASSOCIATIONTYPE type, ASSOCIATIONLEVEL level, HRESULT hrExpected, BOOL fExpected)
{
    BOOL fDefault = 0x55;
    HRESULT hr = pAAR->QueryAppIsDefault(pszQuery, type, level, APP, &fDefault);
    ok(hr == hrExpected, "%d: QueryAppIsDefault(%ls, %d, %d) returned 0x%lx, expected 0x%lx\n",
       line, pszQuery, type, level, hr, hrExpected);
    ok(fDefault == fExpected, "%d: QueryAppIsDefault(%ls, %d, %d) gave %d, expected %d\n",
       line, pszQuery, type, level, fDefault, fExpected);
}

static void CheckIsDefaultAll(int line, IApplicationAssociationRegistration *pAAR, LPCWSTR pszApp,
                              ASSOCIATIONLEVEL level, HRESULT hrExpected, BOOL fExpected)
{
    BOOL fDefault = 0x55;
    HRESULT hr = pAAR->QueryAppIsDefaultAll(level, pszApp, &fDefault);
    ok(hr == hrExpected, "%d: QueryAppIsDefaultAll(%d) returned 0x%lx, expected 0x%lx\n", line, level, hr, hrExpected);
    ok(fDefault == fExpected, "%d: QueryAppIsDefaultAll(%d) gave %d, expected %d\n", line, level, fDefault, fExpected);
}

static void TestCreate(void)
{
    CComPtr<IApplicationAssociationRegistration> pAAR, pAAR2;
    CComPtr<IUnknown> pUnk;
    CComPtr<IClassFactory> pCF;
    CComPtr<IQueryAssociations> pQA;
    HRESULT hr;

    hr = CoCreateInstance(CLSID_ApplicationAssociationRegistration, NULL, CLSCTX_INPROC_SERVER,
                          IID_PPV_ARG(IApplicationAssociationRegistration, &pAAR));
    ok(hr == S_OK, "CoCreateInstance returned 0x%lx\n", hr);
    if (!pAAR)
        return;

    hr = pAAR->QueryInterface(IID_PPV_ARG(IUnknown, &pUnk));
    ok(hr == S_OK, "QueryInterface(IUnknown) returned 0x%lx\n", hr);
    ok(pUnk == (IUnknown *)(IApplicationAssociationRegistration *)pAAR, "IUnknown identity\n");

    hr = pAAR->QueryInterface(IID_PPV_ARG(IQueryAssociations, &pQA));
    ok(hr == E_NOINTERFACE, "QueryInterface(IQueryAssociations) returned 0x%lx\n", hr);
    ok(pQA == NULL, "pQA is %p\n", (void *)pQA);

    pUnk.Release();
    hr = CoCreateInstance(CLSID_ApplicationAssociationRegistration, (IUnknown *)(void *)&pAAR, CLSCTX_INPROC_SERVER,
                          IID_PPV_ARG(IUnknown, &pUnk));
    ok(hr == CLASS_E_NOAGGREGATION, "aggregated CoCreateInstance returned 0x%lx\n", hr);
    ok(pUnk == NULL, "pUnk is %p\n", (void *)pUnk);

    hr = CoGetClassObject(CLSID_ApplicationAssociationRegistration, CLSCTX_INPROC_SERVER, NULL,
                          IID_PPV_ARG(IClassFactory, &pCF));
    ok(hr == S_OK, "CoGetClassObject returned 0x%lx\n", hr);

    typedef HRESULT (WINAPI *SHCREATE)(REFIID, void **);
    SHCREATE pfnCreate = (SHCREATE)GetProcAddress(GetModuleHandleW(L"shell32.dll"), "SHCreateAssociationRegistration");
    if (!pfnCreate)
    {
        skip("SHCreateAssociationRegistration is not exported\n");
        return;
    }
    hr = pfnCreate(IID_IApplicationAssociationRegistration, (void **)&pAAR2);
    ok(hr == S_OK, "SHCreateAssociationRegistration returned 0x%lx\n", hr);
}

struct CROSSAPARTMENT { HRESULT hrCreate, hrQuery; };

static DWORD WINAPI CrossApartmentProc(LPVOID pParam)
{
    CROSSAPARTMENT *pResult = (CROSSAPARTMENT *)pParam;
    CComPtr<IApplicationAssociationRegistration> pAAR;
    LPWSTR psz = NULL;

    HRESULT hrInit = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    pResult->hrCreate = CoCreateInstance(CLSID_ApplicationAssociationRegistration, NULL, CLSCTX_INPROC_SERVER,
                                         IID_PPV_ARG(IApplicationAssociationRegistration, &pAAR));
    pResult->hrQuery = E_FAIL;
    if (pAAR)
        pResult->hrQuery = pAAR->QueryCurrentDefault(L"", AT_MIMETYPE, AL_EFFECTIVE, &psz);
    pAAR.Release();
    if (SUCCEEDED(hrInit))
        CoUninitialize();
    return 0;
}

// Firefox creates the object on a thread of the multithreaded apartment; shell32 has no proxy for the interface here
static void TestOtherApartment(void)
{
    // the result outlives a worker that does not finish
    CROSSAPARTMENT *pResult = new CROSSAPARTMENT;
    pResult->hrCreate = pResult->hrQuery = E_FAIL;
    HANDLE hThread = CreateThread(NULL, 0, CrossApartmentProc, pResult, 0, NULL);
    ok(hThread != NULL, "CreateThread failed\n");
    if (!hThread)
    {
        delete pResult;
        return;
    }
    if (WaitForSingleObject(hThread, 30000) != WAIT_OBJECT_0)
    {
        ok(0, "the thread did not finish\n");
        CloseHandle(hThread);
        return;
    }
    CloseHandle(hThread);
    ok(pResult->hrCreate == S_OK, "CoCreateInstance in the multithreaded apartment returned 0x%lx\n", pResult->hrCreate);
    ok(pResult->hrQuery == HR_NOASSOC, "QueryCurrentDefault in the multithreaded apartment returned 0x%lx\n", pResult->hrQuery);
    delete pResult;
}

static void TestArguments(IApplicationAssociationRegistration *pAAR, BOOL bStrict)
{
    LPWSTR psz = (LPWSTR)(ULONG_PTR)0x1234;
    BOOL fDefault = 0x55;
    HRESULT hr;

    hr = pAAR->QueryCurrentDefault(L"http", AT_URLPROTOCOL, AL_EFFECTIVE, NULL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->QueryCurrentDefault(NULL, AT_URLPROTOCOL, AL_EFFECTIVE, &psz);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);

    CheckQuery(__LINE__, pAAR, L"", AT_URLPROTOCOL, AL_EFFECTIVE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, L"", AT_FILEEXTENSION, AL_EFFECTIVE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, L"", AT_STARTMENUCLIENT, AL_EFFECTIVE, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, L"", AT_MIMETYPE, AL_EFFECTIVE, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, L"http", AT_URLPROTOCOL, (ASSOCIATIONLEVEL)3, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, L"http", AT_URLPROTOCOL, (ASSOCIATIONLEVEL)7, E_INVALIDARG, NULL);
    if (!bStrict)
        return;

    CheckQuery(__LINE__, pAAR, L"http", (ASSOCIATIONTYPE)4, AL_EFFECTIVE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, L"http", (ASSOCIATIONTYPE)7, AL_EFFECTIVE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, L"txt", AT_FILEEXTENSION, AL_EFFECTIVE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, L" .txt", AT_FILEEXTENSION, AL_EFFECTIVE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, L".txt ", AT_FILEEXTENSION, AL_EFFECTIVE, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, L".", AT_FILEEXTENSION, AL_EFFECTIVE, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, L"http:", AT_URLPROTOCOL, AL_EFFECTIVE, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, L"http\\shell", AT_URLPROTOCOL, AL_EFFECTIVE, E_INVALIDARG, NULL);

    hr = pAAR->QueryAppIsDefault(L"http", AT_URLPROTOCOL, AL_EFFECTIVE, APP, NULL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->QueryAppIsDefault(L"http", AT_URLPROTOCOL, AL_EFFECTIVE, NULL, &fDefault);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    ok(fDefault == 0x55, "flag written for a NULL application: %d\n", fDefault);
    hr = pAAR->QueryAppIsDefaultAll(AL_EFFECTIVE, APP, NULL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->QueryAppIsDefaultAll(AL_EFFECTIVE, NULL, &fDefault);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    ok(fDefault == 0x55, "flag written for a NULL application: %d\n", fDefault);
    hr = pAAR->SetAppAsDefault(NULL, L"http", AT_URLPROTOCOL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, NULL, AT_URLPROTOCOL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefaultAll(NULL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
}

static void TestMachineAndUser(IApplicationAssociationRegistration *pAAR)
{
    WCHAR szExpanded[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\rosaartest.exe \"%1\"", szExpanded, _countof(szExpanded));

    // URL protocol: the machine level is the command line of the open verb of the class under HKLM
    SetStr(HKLM, CLASSES PROTO, NULL, L"URL:RosAarTest");
    SetStr(HKLM, CLASSES PROTO, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, MACHINECMD);
    SetStr(HKLM, CLASSES PROTO_EXP, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO_EXP L"\\shell\\open\\command", NULL, L"%SystemRoot%\\rosaartest.exe \"%1\"", REG_EXPAND_SZ);
    SetStr(HKLM, CLASSES PROTO_NOCMD, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO_NOURL, NULL, L"no URL Protocol value");
    SetStr(HKLM, CLASSES PROTO_NOURL L"\\shell\\open\\command", NULL, L"C:\\x.exe");

    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, MACHINECMD);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, MACHINECMD);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, L"ROSAARTESTPROTO", AT_URLPROTOCOL, AL_MACHINE, S_OK, MACHINECMD);
    CheckQuery(__LINE__, pAAR, PROTO_EXP, AT_URLPROTOCOL, AL_MACHINE, S_OK, szExpanded);
    CheckQuery(__LINE__, pAAR, PROTO_NOCMD, AT_URLPROTOCOL, AL_MACHINE, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, PROTO_NOURL, AT_URLPROTOCOL, AL_MACHINE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, PROTO_NOURL, AT_URLPROTOCOL, AL_EFFECTIVE, E_INVALIDARG, NULL);
    CheckQuery(__LINE__, pAAR, PROTO_NOURL, AT_URLPROTOCOL, AL_USER, HR_NOASSOC, NULL);
    CheckQuery(__LINE__, pAAR, L"rosaartestnosuchproto", AT_URLPROTOCOL, AL_EFFECTIVE, HR_NOASSOC, NULL);

    UserChoice(AT_URLPROTOCOL, PROTO, HANDLER);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, MACHINECMD);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, HANDLER);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, S_OK, HANDLER);
    ClearUserChoice(AT_URLPROTOCOL, PROTO);

    // file extension: machine = HKLM class default, effective = user choice, else the merged class default
    SetStr(HKLM, CLASSES EXT, NULL, MACHINEPROG);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_MACHINE, S_OK, MACHINEPROG);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, MACHINEPROG);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, HR_NOASSOC, NULL);
    SetStr(HKCU, L"Software\\Classes\\" EXT, NULL, L"RosAarTest.UserProg");
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_MACHINE, S_OK, MACHINEPROG);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, L"RosAarTest.UserProg");
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, HR_NOASSOC, NULL);
    UserChoice(AT_FILEEXTENSION, EXT, L"RosAarTest.Chosen");
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_MACHINE, S_OK, MACHINEPROG);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, L"RosAarTest.Chosen");
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, S_OK, L"RosAarTest.Chosen");
    CheckQuery(__LINE__, pAAR, L".ROSAARTESTEXT", AT_FILEEXTENSION, AL_USER, S_OK, L"RosAarTest.Chosen");
    UserChoice(AT_FILEEXTENSION, EXT, L"");
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, L"");
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, S_OK, L"");
    SetDword(HKCU, FILEEXTS L"\\" EXT L"\\UserChoice", L"Progid", 5);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, HR_MISMATCH, NULL);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, HR_MISMATCH, NULL);
    ClearUserChoice(AT_FILEEXTENSION, EXT);
    DelKey(HKCU, L"Software\\Classes\\" EXT);
    DelKey(HKLM, CLASSES EXT);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, HR_NOASSOC, NULL);

    // MIME type: the content type database, and the user choice
    SetStr(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIMETYPE, L"CLSID", L"{11111111-2222-3333-4444-555555555555}");
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_MACHINE, S_OK, L"{11111111-2222-3333-4444-555555555555}");
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_EFFECTIVE, S_OK, L"{11111111-2222-3333-4444-555555555555}");
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_USER, HR_NOASSOC, NULL);
    UserChoice(AT_MIMETYPE, MIMETYPE, HANDLER);
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_MACHINE, S_OK, L"{11111111-2222-3333-4444-555555555555}");
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_EFFECTIVE, S_OK, HANDLER);
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_USER, S_OK, HANDLER);
    ClearUserChoice(AT_MIMETYPE, MIMETYPE);
    DelKey(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIMETYPE);
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_EFFECTIVE, HR_NOASSOC, NULL);

    // client types: HKLM\Software\Clients\<type>, overridden per user
    SetStr(HKLM, L"SOFTWARE\\Clients\\" CLIENTTYPE, NULL, L"RosAarMachineClient");
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_MACHINE, S_OK, L"RosAarMachineClient");
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_EFFECTIVE, S_OK, L"RosAarMachineClient");
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_USER, HR_NOASSOC, NULL);
    UserChoice(AT_STARTMENUCLIENT, CLIENTTYPE, L"RosAarUserClient");
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_MACHINE, S_OK, L"RosAarMachineClient");
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_EFFECTIVE, S_OK, L"RosAarUserClient");
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_USER, S_OK, L"RosAarUserClient");
    ClearUserChoice(AT_STARTMENUCLIENT, CLIENTTYPE);
    DelKey(HKLM, L"SOFTWARE\\Clients\\" CLIENTTYPE);
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_EFFECTIVE, HR_NOASSOC, NULL);

    DelKey(HKLM, CLASSES PROTO);
    DelKey(HKLM, CLASSES PROTO_EXP);
    DelKey(HKLM, CLASSES PROTO_NOCMD);
    DelKey(HKLM, CLASSES PROTO_NOURL);
}

static void RegisterApp(void)
{
    SetStr(HKLM, L"SOFTWARE\\RegisteredApplications", APP, L"SOFTWARE\\" APP L"\\Capabilities");
    SetStr(HKLM, L"SOFTWARE\\" APP L"\\Capabilities", L"ApplicationName", L"Test application");
    SetStr(HKLM, L"SOFTWARE\\" APP L"\\Capabilities\\UrlAssociations", PROTO, HANDLER);
    SetStr(HKLM, L"SOFTWARE\\" APP L"\\Capabilities\\FileAssociations", EXT, HANDLER);
    SetStr(HKLM, L"SOFTWARE\\" APP L"\\Capabilities\\MIMEAssociations", MIMETYPE, HANDLER);
    SetStr(HKLM, L"SOFTWARE\\" APP L"\\Capabilities\\Startmenu", CLIENTTYPE, L"RosAarMachineClient");
    SetStr(HKLM, CLASSES HANDLER, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES HANDLER L"\\shell\\open\\command", NULL, MACHINECMD);
}

static void TestAppIsDefault(IApplicationAssociationRegistration *pAAR)
{
    BOOL fDefault;
    HRESULT hr;

    RegisterApp();

    // an application that is not registered, one whose capabilities are missing, and a query it does not declare
    hr = pAAR->QueryAppIsDefault(PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, L"RosAarTestNoSuchApp", &fDefault);
    ok(hr == HR_NOTREG, "got 0x%lx\n", hr);
    hr = pAAR->QueryAppIsDefault(PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, L"", &fDefault);
    ok(hr == HR_NOTREG, "got 0x%lx\n", hr);
    CheckIsDefault(__LINE__, pAAR, L"rosaartestother", AT_URLPROTOCOL, AL_EFFECTIVE, E_INVALIDARG, FALSE);
    CheckIsDefault(__LINE__, pAAR, L".rosaartestother", AT_FILEEXTENSION, AL_USER, E_INVALIDARG, FALSE);
    CheckIsDefault(__LINE__, pAAR, L"", AT_URLPROTOCOL, AL_EFFECTIVE, E_INVALIDARG, FALSE);
    CheckIsDefault(__LINE__, pAAR, L"rosaartestext", AT_FILEEXTENSION, AL_EFFECTIVE, E_INVALIDARG, FALSE);
    CheckIsDefault(__LINE__, pAAR, PROTO, (ASSOCIATIONTYPE)4, AL_EFFECTIVE, E_INVALIDARG, FALSE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, (ASSOCIATIONLEVEL)7, E_INVALIDARG, FALSE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, HR_NOASSOC, FALSE);

    // URL protocol: at machine level the handler class must have the very command of the protocol class
    SetStr(HKLM, CLASSES PROTO, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\b.exe %1");
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, HR_NOASSOC, FALSE);
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, MACHINECMD);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, HR_NOASSOC, FALSE);
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, L"C:\\ROSAARTEST\\A.EXE %1");
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, TRUE);
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\a.exe %1 -x");
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, FALSE);
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\b.exe %1");
    UserChoice(AT_URLPROTOCOL, PROTO, L"rosaartest.handler");
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, S_OK, TRUE);
    UserChoice(AT_URLPROTOCOL, PROTO, HANDLER2);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, S_OK, FALSE);
    ClearUserChoice(AT_URLPROTOCOL, PROTO);
    DelKey(HKLM, CLASSES PROTO);

    // file extension
    SetStr(HKLM, CLASSES EXT, NULL, HANDLER);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_MACHINE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, HR_NOASSOC, FALSE);
    SetStr(HKLM, CLASSES EXT, NULL, MACHINEPROG);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_MACHINE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, FALSE);
    UserChoice(AT_FILEEXTENSION, EXT, L"rosaartest.handler");
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_MACHINE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, S_OK, TRUE);
    ClearUserChoice(AT_FILEEXTENSION, EXT);
    DelKey(HKLM, CLASSES EXT);


    // different progids are the same association when their open commands are the same; not at user level
    SetStr(HKLM, L"SOFTWARE\\" APP L"\\Capabilities\\FileAssociations", EXT2, CLASSB);
    SetStr(HKLM, CLASSES EXT2, NULL, CLASSA);
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_MACHINE, S_OK, FALSE);
    SetStr(HKLM, CLASSES CLASSA L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\c.exe %1");
    SetStr(HKLM, CLASSES CLASSB L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\c.exe %1");
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_MACHINE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, TRUE);
    SetStr(HKLM, CLASSES CLASSA L"\\shell\\open\\command", NULL, L"C:\\ROSAARTEST\\C.EXE %1");
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_MACHINE, S_OK, TRUE);
    SetStr(HKLM, CLASSES CLASSB L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\d.exe %1");
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_MACHINE, S_OK, FALSE);
    DelKey(HKLM, CLASSES CLASSA);
    SetStr(HKLM, CLASSES CLASSA, NULL, L"a class without verbs");
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_MACHINE, S_OK, FALSE);
    SetStr(HKLM, CLASSES CLASSA L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\d.exe %1");
    SetStr(HKLM, CLASSES CLASSC L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\d.exe %1");
    UserChoice(AT_FILEEXTENSION, EXT2, CLASSC);
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_USER, S_OK, FALSE);
    UserChoice(AT_FILEEXTENSION, EXT2, L"RosAarTest.NoClass");
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, EXT2, AT_FILEEXTENSION, AL_USER, S_OK, FALSE);
    ClearUserChoice(AT_FILEEXTENSION, EXT2);
    DelKey(HKLM, CLASSES EXT2);

    // MIME type at machine level: the progid class carries the CLSID of the content type database
    SetStr(HKLM, L"SOFTWARE\\" APP L"\\Capabilities\\MIMEAssociations", MIME2, CLASSB);
    SetStr(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIME2, L"CLSID", L"{11111111-2222-3333-4444-555555555555}");
    SetStr(HKLM, CLASSES CLASSB L"\\CLSID", NULL, L"{99999999-2222-3333-4444-555555555555}");
    CheckIsDefault(__LINE__, pAAR, MIME2, AT_MIMETYPE, AL_MACHINE, S_OK, FALSE);
    SetStr(HKLM, CLASSES CLASSB L"\\CLSID", NULL, L"{11111111-2222-3333-4444-555555555555}");
    CheckIsDefault(__LINE__, pAAR, MIME2, AT_MIMETYPE, AL_MACHINE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, MIME2, AT_MIMETYPE, AL_EFFECTIVE, S_OK, TRUE);
    DelKey(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIME2);
    CheckIsDefault(__LINE__, pAAR, MIME2, AT_MIMETYPE, AL_MACHINE, HR_NOASSOC, FALSE);

    // MIME type and client type
    SetStr(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIMETYPE, L"CLSID", L"{11111111-2222-3333-4444-555555555555}");
    CheckIsDefault(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_EFFECTIVE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_USER, HR_NOASSOC, FALSE);
    UserChoice(AT_MIMETYPE, MIMETYPE, HANDLER);
    CheckIsDefault(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_MACHINE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_USER, S_OK, TRUE);
    ClearUserChoice(AT_MIMETYPE, MIMETYPE);
    DelKey(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIMETYPE);

    SetStr(HKLM, L"SOFTWARE\\Clients\\" CLIENTTYPE, NULL, L"RosAarMachineClient");
    CheckIsDefault(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_MACHINE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_USER, HR_NOASSOC, FALSE);
    UserChoice(AT_STARTMENUCLIENT, CLIENTTYPE, L"RosAarOtherClient");
    CheckIsDefault(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_EFFECTIVE, S_OK, FALSE);
    CheckIsDefault(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_USER, S_OK, FALSE);
    ClearUserChoice(AT_STARTMENUCLIENT, CLIENTTYPE);
    DelKey(HKLM, L"SOFTWARE\\Clients\\" CLIENTTYPE);
}

static void TestIsDefaultAll(IApplicationAssociationRegistration *pAAR)
{
    BOOL fDefault = 0x55;
    HRESULT hr;

    hr = pAAR->QueryAppIsDefaultAll(AL_EFFECTIVE, L"RosAarTestNoSuchApp", &fDefault);
    ok(hr == HR_NOTREG, "got 0x%lx\n", hr);
    ok(fDefault == FALSE, "got %d\n", fDefault);
    hr = pAAR->QueryAppIsDefaultAll((ASSOCIATIONLEVEL)3, L"RosAarTestNoSuchApp", &fDefault);
    ok(hr == HR_NOTREG, "the application is looked up before the level is checked: 0x%lx\n", hr);
    RegisterApp();
    hr = pAAR->QueryAppIsDefaultAll((ASSOCIATIONLEVEL)3, APP, &fDefault);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);

    // an application without associations owns all of them
    SetStr(HKLM, L"SOFTWARE\\RegisteredApplications", L"RosAarTestEmpty", L"SOFTWARE\\RosAarTestEmpty\\Capabilities");
    SetStr(HKLM, L"SOFTWARE\\RosAarTestEmpty\\Capabilities", L"ApplicationName", L"Empty");
    CheckIsDefaultAll(__LINE__, pAAR, L"RosAarTestEmpty", AL_MACHINE, S_OK, TRUE);
    CheckIsDefaultAll(__LINE__, pAAR, L"RosAarTestEmpty", AL_USER, S_OK, TRUE);
    hr = pAAR->SetAppAsDefaultAll(L"RosAarTestEmpty");
    ok(hr == S_OK, "got 0x%lx\n", hr);
    DelValue(HKLM, L"SOFTWARE\\RegisteredApplications", L"RosAarTestEmpty");
    DelKey(HKLM, L"SOFTWARE\\RosAarTestEmpty");

    // registered, but the capabilities key does not exist
    SetStr(HKLM, L"SOFTWARE\\RegisteredApplications", L"RosAarTestNoCaps", L"SOFTWARE\\RosAarTestNoCaps\\Capabilities");
    CheckIsDefaultAll(__LINE__, pAAR, L"RosAarTestNoCaps", AL_EFFECTIVE, HR_NOTREG, FALSE);
    hr = pAAR->SetAppAsDefaultAll(L"RosAarTestNoCaps");
    ok(hr == HR_NOTREG, "got 0x%lx\n", hr);
    DelValue(HKLM, L"SOFTWARE\\RegisteredApplications", L"RosAarTestNoCaps");

    RegisterApp();
    SetStr(HKLM, CLASSES PROTO, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, MACHINECMD);
    SetStr(HKLM, CLASSES EXT, NULL, HANDLER);
    SetStr(HKLM, CLASSES L"MIME\\Database\\Content Type\\" MIMETYPE, L"CLSID", L"{11111111-2222-3333-4444-555555555555}");
    SetStr(HKLM, L"SOFTWARE\\Clients\\" CLIENTTYPE, NULL, L"RosAarMachineClient");

    // the machine level compares the MIME type's CLSID with the application's progid, which differ
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_MACHINE, S_OK, FALSE);
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_EFFECTIVE, S_OK, FALSE);
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_USER, HR_NOASSOC, FALSE);

    hr = pAAR->SetAppAsDefaultAll(APP);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_EFFECTIVE, S_OK, TRUE);
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_USER, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_USER, S_OK, TRUE);
    CheckIsDefault(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_USER, S_OK, TRUE);

    // one association that belongs to someone else makes the answer no, without an error
    SetStr(HKLM, L"SOFTWARE\\RegisteredApplications", APP L"2", L"SOFTWARE\\" APP L"2\\Capabilities");
    SetStr(HKLM, L"SOFTWARE\\" APP L"2\\Capabilities\\FileAssociations", EXT, HANDLER2);
    hr = pAAR->SetAppAsDefault(APP L"2", EXT, AT_FILEEXTENSION);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_USER, S_OK, FALSE);
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_EFFECTIVE, S_OK, FALSE);
    DelValue(HKLM, L"SOFTWARE\\RegisteredApplications", APP L"2");
    DelKey(HKLM, L"SOFTWARE\\" APP L"2");

    // a missing choice at user level is an error
    pAAR->ClearUserAssociations();
    CheckIsDefaultAll(__LINE__, pAAR, APP, AL_USER, HR_NOASSOC, FALSE);
}

// An application of the user alone (a per-user install: Chrome's, Firefox's own) is registered under HKCU
static void TestUserRegisteredApp(IApplicationAssociationRegistration *pAAR)
{
    HRESULT hr;
    BOOL fDefault = 123;

    SetStr(HKLM, CLASSES PROTO, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, MACHINECMD);
    SetStr(HKCU, L"Software\\RegisteredApplications", USERAPP, L"Software\\" USERAPP L"\\Capabilities");
    SetStr(HKCU, L"Software\\" USERAPP L"\\Capabilities\\URLAssociations", PROTO, HANDLER);

    hr = pAAR->QueryAppIsDefault(PROTO, AT_URLPROTOCOL, AL_USER, USERAPP, &fDefault);
    ok(hr == HR_NOASSOC, "got 0x%lx\n", hr);
    ok(fDefault == FALSE, "got %d\n", fDefault);

    hr = pAAR->SetAppAsDefault(USERAPP, PROTO, AT_URLPROTOCOL);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, S_OK, HANDLER);
    fDefault = FALSE;
    hr = pAAR->QueryAppIsDefault(PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, USERAPP, &fDefault);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    ok(fDefault == TRUE, "got %d\n", fDefault);

    // not what the application declares
    hr = pAAR->SetAppAsDefault(USERAPP, L"rosaartestother", AT_URLPROTOCOL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);

    // gone from HKCU: not registered
    DelValue(HKCU, L"Software\\RegisteredApplications", USERAPP);
    hr = pAAR->SetAppAsDefault(USERAPP, PROTO, AT_URLPROTOCOL);
    ok(hr == HR_NOTREG, "got 0x%lx\n", hr);
}

static void TestSet(IApplicationAssociationRegistration *pAAR)
{
    HRESULT hr;
    WCHAR szValue[MAX_PATH];

    RegisterApp();
    SetStr(HKLM, CLASSES PROTO, L"URL Protocol", L"");
    SetStr(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, L"C:\\rosaartest\\b.exe %1");
    SetStr(HKLM, CLASSES EXT, NULL, MACHINEPROG);

    hr = pAAR->SetAppAsDefault(L"RosAarTestNoSuchApp", PROTO, AT_URLPROTOCOL);
    ok(hr == HR_NOTREG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(L"", PROTO, AT_URLPROTOCOL);
    ok(hr == HR_NOTREG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, L"rosaartestother", AT_URLPROTOCOL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, PROTO, AT_FILEEXTENSION);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, EXT, AT_URLPROTOCOL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, L"", AT_URLPROTOCOL);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, PROTO, (ASSOCIATIONTYPE)4);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, PROTO, (ASSOCIATIONTYPE)9);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    hr = pAAR->SetAppAsDefault(APP, L"rosaartestext", AT_FILEEXTENSION);
    ok(hr == E_INVALIDARG, "got 0x%lx\n", hr);
    ok(!ValueExists(HKCU, USERASSOC L"\\UrlAssociations\\" PROTO L"\\UserChoice", L"Progid"), "failed calls wrote a choice\n");

    hr = pAAR->SetAppAsDefault(APP, PROTO, AT_URLPROTOCOL);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_MACHINE, S_OK, L"C:\\rosaartest\\b.exe %1");
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, HANDLER);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, S_OK, HANDLER);
    CheckIsDefault(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_EFFECTIVE, S_OK, TRUE);
    hr = pAAR->SetAppAsDefault(APP, PROTO, AT_URLPROTOCOL);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    UserChoice(AT_URLPROTOCOL, PROTO, L"OtherProg");
    hr = pAAR->SetAppAsDefault(APP, PROTO, AT_URLPROTOCOL);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckQuery(__LINE__, pAAR, PROTO, AT_URLPROTOCOL, AL_USER, S_OK, HANDLER);

    hr = pAAR->SetAppAsDefault(APP, EXT, AT_FILEEXTENSION);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_MACHINE, S_OK, MACHINEPROG);
    CheckQuery(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_USER, S_OK, HANDLER);
    CheckIsDefault(__LINE__, pAAR, EXT, AT_FILEEXTENSION, AL_EFFECTIVE, S_OK, TRUE);

    hr = pAAR->SetAppAsDefault(APP, MIMETYPE, AT_MIMETYPE);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckQuery(__LINE__, pAAR, MIMETYPE, AT_MIMETYPE, AL_USER, S_OK, HANDLER);

    hr = pAAR->SetAppAsDefault(APP, CLIENTTYPE, AT_STARTMENUCLIENT);
    ok(hr == S_OK, "got 0x%lx\n", hr);
    CheckQuery(__LINE__, pAAR, CLIENTTYPE, AT_STARTMENUCLIENT, AL_USER, S_OK, L"RosAarMachineClient");

    // nothing is written outside of HKCU
    ok(!KeyExists(HKCU, L"Software\\Classes\\" PROTO), "class key created in HKCU\n");
    DWORD cb = sizeof(szValue);
    ok(SHGetValueW(HKLM, CLASSES PROTO L"\\shell\\open\\command", NULL, NULL, szValue, &cb) == ERROR_SUCCESS &&
       !lstrcmpW(szValue, L"C:\\rosaartest\\b.exe %1"), "machine command changed\n");
}

static void TestClear(IApplicationAssociationRegistration *pAAR)
{
    HRESULT hr;

    // removed: the choices, every key below FileExts, and the default values of the client keys
    SetStr(HKCU, USERASSOC L"\\UrlAssociations\\" PROTO L"\\UserChoice", L"Progid", HANDLER);
    SetStr(HKCU, USERASSOC L"\\UrlAssociations\\" PROTO, L"Other", L"value");
    SetStr(HKCU, USERASSOC L"\\MIMEAssociations\\" MIMETYPE L"\\UserChoice", L"Progid", HANDLER);
    SetStr(HKCU, USERASSOC L"\\RosAarTestOther\\Sub", L"Keep", L"yes");
    SetStr(HKCU, FILEEXTS L"\\" EXT L"\\UserChoice", L"Progid", HANDLER);
    SetStr(HKCU, FILEEXTS L"\\" EXT L"\\OpenWithProgids", HANDLER, L"");
    SetStr(HKCU, FILEEXTS L"\\.rosaartestkeep\\OpenWithProgids", HANDLER, L"");
    SetStr(HKCU, CLIENTS L"\\" CLIENTTYPE, NULL, L"RosAarUserClient");
    SetStr(HKCU, CLIENTS L"\\" CLIENTTYPE, L"Other", L"value");
    SetStr(HKCU, CLIENTS L"\\" CLIENTTYPE L"\\RosAarUserClient", NULL, L"child");
    SetStr(HKCU, L"Software\\Classes\\" EXT, NULL, L"RosAarTest.UserProg");

    hr = pAAR->ClearUserAssociations();
    ok(hr == S_OK, "got 0x%lx\n", hr);

    ok(KeyExists(HKCU, USERASSOC L"\\UrlAssociations"), "UrlAssociations removed\n");
    ok(KeyExists(HKCU, USERASSOC L"\\MIMEAssociations"), "MIMEAssociations removed\n");
    ok(!KeyExists(HKCU, USERASSOC L"\\UrlAssociations\\" PROTO), "url choice not removed\n");
    ok(!KeyExists(HKCU, USERASSOC L"\\MIMEAssociations\\" MIMETYPE), "mime choice not removed\n");
    ok(ValueExists(HKCU, USERASSOC L"\\RosAarTestOther\\Sub", L"Keep"), "sibling key removed\n");
    ok(!KeyExists(HKCU, FILEEXTS L"\\" EXT), "extension with a choice not removed\n");
    ok(!KeyExists(HKCU, FILEEXTS L"\\.rosaartestkeep"), "extension without a choice not removed\n");
    ok(!ValueExists(HKCU, CLIENTS L"\\" CLIENTTYPE, NULL), "client default not removed\n");
    ok(ValueExists(HKCU, CLIENTS L"\\" CLIENTTYPE, L"Other"), "other client value removed\n");
    ok(KeyExists(HKCU, CLIENTS L"\\" CLIENTTYPE L"\\RosAarUserClient"), "client child key removed\n");
    ok(ValueExists(HKCU, L"Software\\Classes\\" EXT, NULL), "user class removed\n");

    hr = pAAR->ClearUserAssociations();
    ok(hr == S_OK, "got 0x%lx\n", hr);

    DelKey(HKCU, USERASSOC L"\\RosAarTestOther");
    DelKey(HKCU, FILEEXTS L"\\.rosaartestkeep");
}

static const struct { LPCWSTR pszKey, pszName; } s_StateKeys[] =
{
    { USERASSOC, L"Associations" }, { FILEEXTS, L"FileExts" }, { CLIENTS, L"Clients" },
};

// Copies the user's association keys to a backup key, noting the ones that do not exist; FALSE unless all of it worked.
static BOOL SaveState(void)
{
    HKEY hBackup;
    BOOL bOk = TRUE;
    if (KeyExists(HKCU, BACKUP))
        return FALSE;
    if (RegCreateKeyExW(HKCU, BACKUP, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hBackup, NULL) != ERROR_SUCCESS)
        return FALSE;
    for (UINT i = 0; i < _countof(s_StateKeys); ++i)
    {
        HKEY hSrc, hDst;
        LONG err = RegOpenKeyExW(HKCU, s_StateKeys[i].pszKey, 0, KEY_READ, &hSrc);
        if (err != ERROR_SUCCESS && err != ERROR_FILE_NOT_FOUND)
        {
            bOk = FALSE;
            continue;
        }
        if (RegCreateKeyExW(hBackup, s_StateKeys[i].pszName, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hDst, NULL) != ERROR_SUCCESS)
        {
            bOk = FALSE;
            if (err == ERROR_SUCCESS)
                RegCloseKey(hSrc);
            continue;
        }
        if (err == ERROR_FILE_NOT_FOUND)
        {
            // kept in the backup root, away from the copied values
            WCHAR szMarker[64];
            wsprintfW(szMarker, L"%ls.absent", s_StateKeys[i].pszName);
            bOk = RegSetValueExW(hBackup, szMarker, 0, REG_DWORD, (const BYTE *)&err, sizeof(DWORD)) == ERROR_SUCCESS && bOk;
        }
        else
        {
            bOk = SHCopyKeyW(hSrc, NULL, hDst, 0) == ERROR_SUCCESS && bOk;
            RegCloseKey(hSrc);
        }
        RegCloseKey(hDst);
    }
    RegCloseKey(hBackup);
    if (!bOk)
        DelKey(HKCU, BACKUP);
    return bOk;
}

// Puts the keys back, or removes the ones that did not exist; the backup stays when something went wrong.
static void RestoreState(void)
{
    HKEY hBackup;
    BOOL bOk = TRUE;
    if (RegOpenKeyExW(HKCU, BACKUP, 0, KEY_READ, &hBackup) != ERROR_SUCCESS)
    {
        ok(0, "The backup of the user's associations is gone\n");
        return;
    }
    for (UINT i = 0; i < _countof(s_StateKeys); ++i)
    {
        HKEY hSrc, hDst;
        WCHAR szMarker[64];
        wsprintfW(szMarker, L"%ls.absent", s_StateKeys[i].pszName);
        if (RegOpenKeyExW(hBackup, s_StateKeys[i].pszName, 0, KEY_READ, &hSrc) != ERROR_SUCCESS)
        {
            bOk = FALSE;
            continue;
        }
        if (RegQueryValueExW(hBackup, szMarker, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            DelKey(HKCU, s_StateKeys[i].pszKey);
            bOk = !KeyExists(HKCU, s_StateKeys[i].pszKey) && bOk;
        }
        else if (RegCreateKeyExW(HKCU, s_StateKeys[i].pszKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &hDst, NULL) == ERROR_SUCCESS)
        {
            bOk = SHCopyKeyW(hSrc, NULL, hDst, 0) == ERROR_SUCCESS && bOk;
            RegCloseKey(hDst);
        }
        else
        {
            bOk = FALSE;
        }
        RegCloseKey(hSrc);
    }
    RegCloseKey(hBackup);
    ok(bOk, "The user's associations could not be restored, a copy is in HKCU\\%ls\n", BACKUP);
    if (bOk)
        DelKey(HKCU, BACKUP);
}

// The test removes its fixtures afterwards, so it only runs when none of them exists.
static BOOL FixturesFree(void)
{
    static const LPCWSTR s_Hklm[] =
    {
        CLASSES PROTO, CLASSES PROTO_EXP, CLASSES PROTO_NOCMD, CLASSES PROTO_NOURL, CLASSES HANDLER, CLASSES HANDLER2,
        CLASSES EXT, CLASSES EXT2, CLASSES CLASSA, CLASSES CLASSB, CLASSES CLASSC,
        CLASSES L"MIME\\Database\\Content Type\\" MIMETYPE, CLASSES L"MIME\\Database\\Content Type\\" MIME2,
        L"SOFTWARE\\Clients\\" CLIENTTYPE, L"SOFTWARE\\" APP, L"SOFTWARE\\" APP L"2",
        L"SOFTWARE\\RosAarTestEmpty", L"SOFTWARE\\RosAarTestNoCaps", L"SOFTWARE\\RosAarTestProbe",
    };
    for (UINT i = 0; i < _countof(s_Hklm); ++i)
    {
        if (KeyExists(HKLM, s_Hklm[i]))
            return FALSE;
    }
    static const LPCWSTR s_Apps[] = { APP, APP L"2", L"RosAarTestEmpty", L"RosAarTestNoCaps" };
    for (UINT i = 0; i < _countof(s_Apps); ++i)
    {
        if (ValueExists(HKLM, L"SOFTWARE\\RegisteredApplications", s_Apps[i]))
            return FALSE;
    }
    if (KeyExists(HKCU, L"Software\\" USERAPP) || ValueExists(HKCU, L"Software\\RegisteredApplications", USERAPP))
        return FALSE;
    return !KeyExists(HKCU, L"Software\\Classes\\" EXT);
}

START_TEST(IApplicationAssociationRegistration)
{
    CComPtr<IApplicationAssociationRegistration> pAAR;
    HKEY hKey;
    BOOL bStrict = !IsWindows8OrNewer();

    HRESULT hrInit = CoInitialize(NULL);
    TestCreate();
    HRESULT hr = CoCreateInstance(CLSID_ApplicationAssociationRegistration, NULL, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARG(IApplicationAssociationRegistration, &pAAR));
    if (FAILED(hr))
    {
        skip("IApplicationAssociationRegistration is not available\n");
        goto Quit;
    }

    TestArguments(pAAR, bStrict);
    TestOtherApartment();

    if (!bStrict)
    {
        skip("Windows 8 and later differ, the registry tests need Windows 7 or older\n");
        goto Quit;
    }
    if (!FixturesFree())
    {
        skip("Fixtures of an earlier run are still there\n");
        goto Quit;
    }
    if (RegCreateKeyExW(HKLM, L"SOFTWARE\\RosAarTestProbe", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
    {
        skip("Cannot write to HKLM\n");
        goto Quit;
    }
    RegCloseKey(hKey);
    DelKey(HKLM, L"SOFTWARE\\RosAarTestProbe");
    if (!SaveState())
    {
        skip("Cannot back up the user's associations, or a backup of an earlier run exists in HKCU\\%ls\n", BACKUP);
        goto Quit;
    }
    Cleanup();
    TestMachineAndUser(pAAR);
    Cleanup();
    TestAppIsDefault(pAAR);
    Cleanup();
    TestIsDefaultAll(pAAR);
    pAAR->ClearUserAssociations();
    Cleanup();
    TestSet(pAAR);
    pAAR->ClearUserAssociations();
    Cleanup();
    TestUserRegisteredApp(pAAR);
    pAAR->ClearUserAssociations();
    Cleanup();
    TestClear(pAAR);
    Cleanup();
    pAAR->ClearUserAssociations();
    RestoreState();

Quit:
    pAAR.Release();
    if (SUCCEEDED(hrInit))
        CoUninitialize();
}
