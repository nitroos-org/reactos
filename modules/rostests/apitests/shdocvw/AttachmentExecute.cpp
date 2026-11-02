/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IAttachmentExecute (CLSID_AttachmentServices), Mark-of-the-Web
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows 10 22H2 (shdocvw.dll registers the class).
 */

#include <apitest.h>
#include <initguid.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <wine/test.h>

DEFINE_GUID(CLSID_AttachmentServices, 0x4125dd96, 0xe03a, 0x4103, 0x8f, 0x70, 0xe0, 0x59, 0x7d, 0x80, 0x3b, 0x9c);

static const GUID s_guid = { 0x11111111, 0x2222, 0x3333, { 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 } };
static WCHAR s_dir[MAX_PATH];

static HRESULT CreateAE(IAttachmentExecute **pp)
{
    return CoCreateInstance(CLSID_AttachmentServices, NULL, CLSCTX_INPROC_SERVER,
                            IID_IAttachmentExecute, (void **)pp);
}

static void MakeFile(PCWSTR pszName, WCHAR *pszPath)
{
    StringCchPrintfW(pszPath, MAX_PATH, L"%ls\\%ls", s_dir, pszName);
    HANDLE h = CreateFileW(pszPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD cb;
    WriteFile(h, "x", 1, &cb, NULL);
    CloseHandle(h);
}

// Returns the stream as text ("" when there is none; the Win32 error goes to *pErr)
static BOOL ReadStream(PCWSTR pszPath, char *pszBuf, DWORD cbBuf, DWORD *pcb)
{
    WCHAR szStream[MAX_PATH + 32];
    StringCchPrintfW(szStream, _countof(szStream), L"%ls:Zone.Identifier", pszPath);
    HANDLE h = CreateFileW(szStream, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    *pcb = 0;
    ReadFile(h, pszBuf, cbBuf - 1, pcb, NULL);
    pszBuf[*pcb] = 0;
    CloseHandle(h);
    return TRUE;
}

static HRESULT SaveCase(PCWSTR pszName, PCWSTR pszSource, PCWSTR pszReferrer, char *pszStream, BOOL *pbHas)
{
    WCHAR szPath[MAX_PATH];
    MakeFile(pszName, szPath);
    IAttachmentExecute *p = NULL;
    HRESULT hr = CreateAE(&p);
    if (FAILED(hr))
        return hr;
    p->SetClientGuid(s_guid);
    p->SetLocalPath(szPath);
    p->SetFileName(pszName);
    if (pszSource)
        p->SetSource(pszSource);
    if (pszReferrer)
        p->SetReferrer(pszReferrer);
    hr = p->Save();
    p->Release();
    DWORD cb;
    *pbHas = ReadStream(szPath, pszStream, 512, &cb);
    return hr;
}

static void TestRegistration(void)
{
    WCHAR szPath[MAX_PATH] = L"";
    DWORD cb = sizeof(szPath), type = 0;
    HKEY hKey;
    LONG err = RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID\\{4125dd96-e03a-4103-8f70-e0597d803b9c}\\InProcServer32",
                             0, KEY_READ, &hKey);
    ok_long(err, ERROR_SUCCESS);
    if (err == ERROR_SUCCESS)
    {
        err = RegQueryValueExW(hKey, NULL, NULL, &type, (BYTE *)szPath, &cb);
        ok_long(err, ERROR_SUCCESS);
        RegCloseKey(hKey);
    }
    ok(StrStrIW(szPath, L"shdocvw.dll") != NULL, "Path '%ls'\n", szPath);

    IAttachmentExecute *p = NULL;
    HRESULT hr = CreateAE(&p);
    ok_hex(hr, S_OK);
    if (p)
        p->Release();
}

static void TestArguments(void)
{
    IAttachmentExecute *p = NULL;
    if (FAILED(CreateAE(&p)))
        return;
    ok_hex(p->SetClientTitle(NULL), E_INVALIDARG);
    ok_hex(p->SetLocalPath(NULL), E_INVALIDARG);
    ok_hex(p->SetFileName(NULL), E_INVALIDARG);
    ok_hex(p->SetSource(NULL), E_INVALIDARG);
    ok_hex(p->SetReferrer(NULL), E_INVALIDARG);
    ok_hex(p->SetClientTitle(L"title"), S_OK);
    ok_hex(p->SetClientGuid(s_guid), S_OK);
    ok_hex(p->SetClientGuid(s_guid), S_OK);
    ok_hex(p->SetLocalPath(L"C:\\x.exe"), S_OK);
    ok_hex(p->ClearClientState(), S_OK);
    p->Release();

    // Nothing set
    if (SUCCEEDED(CreateAE(&p)))
    {
        ok_hex(p->Save(), E_UNEXPECTED);
        p->Release();
    }

    // Missing file
    if (SUCCEEDED(CreateAE(&p)))
    {
        WCHAR szPath[MAX_PATH];
        StringCchPrintfW(szPath, _countof(szPath), L"%ls\\nofile.exe", s_dir);
        p->SetLocalPath(szPath);
        p->SetSource(L"https://example.com/x.exe");
        ok_hex(p->Save(), HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
        p->Release();
    }

    // Existing file, no source
    WCHAR szPath[MAX_PATH];
    MakeFile(L"nosrc.exe", szPath);
    if (SUCCEEDED(CreateAE(&p)))
    {
        p->SetLocalPath(szPath);
        ok_hex(p->Save(), INET_E_SECURITY_PROBLEM);
        // an existing file without a mark is local (not measured on Windows)
        ok_hex(p->CheckPolicy(), S_OK);
        p->Release();
    }
}

#define EXPECT_STREAM(call, expected) \
    do { \
        char sz[512]; BOOL has; \
        HRESULT hr_ = (call); \
        ok_hex(hr_, S_OK); \
        ok(has, "No stream\n"); \
        ok(!strcmp(sz, expected), "Stream is '%s'\n", sz); \
    } while (0)

static void TestSave(void)
{
    char sz[512];
    BOOL has;
    HRESULT hr;

    hr = SaveCase(L"a1.exe", L"https://example.com/dl/a.exe", L"https://example.com/page", sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, TRUE);
    ok_str(sz, "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/page\r\n"
               "HostUrl=https://example.com/dl/a.exe\r\n");

    hr = SaveCase(L"a2.exe", L"https://example.com/dl/a.exe", NULL, sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, TRUE);
    ok_str(sz, "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/dl/a.exe\r\n");

    hr = SaveCase(L"a4.txt", L"https://example.com/a.txt", L"https://example.com/p", sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, TRUE);
    ok_str(sz, "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/p\r\n"
               "HostUrl=https://example.com/a.txt\r\n");

    // The URLs are stored as given
    hr = SaveCase(L"a10.exe", L"https://user:pw@example.com/a.exe?x=1#frag", L"https://user:pw@example.com/p?y=2#g", sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, TRUE);
    ok_str(sz, "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://user:pw@example.com/p?y=2#g\r\n"
               "HostUrl=https://user:pw@example.com/a.exe?x=1#frag\r\n");

    // "about:internet" is what browsers pass when the source is unknown
    hr = SaveCase(L"a12.exe", L"about:internet", NULL, sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, TRUE);
    ok_str(sz, "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=about:internet\r\n");

    hr = SaveCase(L"a15.exe", L"https://example.com/a.exe", L"about:internet", sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, TRUE);
    ok_str(sz, "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=about:internet\r\n"
               "HostUrl=https://example.com/a.exe\r\n");

    // The file name decides the type, the local path may be a temporary name
    {
        WCHAR szPath[MAX_PATH];
        MakeFile(L"a11.tmp", szPath);
        IAttachmentExecute *p = NULL;
        if (SUCCEEDED(CreateAE(&p)))
        {
            p->SetLocalPath(szPath);
            p->SetFileName(L"real.exe");
            p->SetSource(L"https://example.com/real.exe");
            ok_hex(p->Save(), S_OK);
            DWORD cb;
            ok_int(ReadStream(szPath, sz, sizeof(sz), &cb), TRUE);
            ok_str(sz, "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/real.exe\r\n");
            p->Release();
        }
    }

    // Local, intranet and loopback sources are not marked at all (S_OK)
    hr = SaveCase(L"a6.exe", L"file:///C:/Windows/notepad.exe", NULL, sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, FALSE);
    hr = SaveCase(L"a7.exe", L"\\\\server\\share\\a.exe", NULL, sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, FALSE);
    hr = SaveCase(L"a8.exe", L"http://localhost/a.exe", NULL, sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, FALSE);
    hr = SaveCase(L"a5.exe", L"http://intranetbox/a.exe", NULL, sz, &has);
    ok_hex(hr, S_OK);
    ok_int(has, FALSE);
}

static void TestPolicyAndPrompt(void)
{
    static const struct { PCWSTR name; PCWSTR src; HRESULT hr; } cases[] =
    {
        { L"a.exe", L"https://example.com/x", S_FALSE },
        { L"a.bat", L"https://example.com/x", S_FALSE },
        { L"a.zip", L"https://example.com/x", S_FALSE },
        { L"a.txt", L"https://example.com/x", S_FALSE },
        { L"a",     L"https://example.com/x", S_FALSE },
        { L"a.exe", L"file:///C:/Windows/a.exe", S_OK },
        { L"a.exe", L"http://localhost/a.exe", S_OK },
        { L"a.exe", L"http://intranetbox/a.exe", S_OK },
        { L"a.bat", L"file:///C:/a.bat", S_OK },
        { L"a.zip", L"\\\\server\\share\\a.zip", S_OK },
        { L"a.exe", NULL, INET_E_SECURITY_PROBLEM },
    };
    for (UINT i = 0; i < _countof(cases); ++i)
    {
        IAttachmentExecute *p = NULL;
        if (FAILED(CreateAE(&p)))
            return;
        WCHAR szPath[MAX_PATH];
        StringCchPrintfW(szPath, _countof(szPath), L"%ls\\%ls", s_dir, cases[i].name);
        p->SetClientGuid(s_guid);
        p->SetLocalPath(szPath);
        if (cases[i].src)
            p->SetSource(cases[i].src);
        HRESULT hr = p->CheckPolicy();
        ok(hr == cases[i].hr, "[%u] %ls %ls: got %08lx expected %08lx\n", i, cases[i].name,
           cases[i].src ? cases[i].src : L"(null)", hr, cases[i].hr);
        p->Release();
    }

    // Without a source the Zone.Identifier stream of the file decides (a1.exe was marked by TestSave)
    {
        IAttachmentExecute *p = NULL;
        WCHAR szPath[MAX_PATH];
        if (SUCCEEDED(CreateAE(&p)))
        {
            StringCchPrintfW(szPath, _countof(szPath), L"%ls\\a1.exe", s_dir);
            p->SetLocalPath(szPath);
            ok_hex(p->CheckPolicy(), S_FALSE);
            p->Release();
        }
        if (SUCCEEDED(CreateAE(&p)))
        {
            StringCchPrintfW(szPath, _countof(szPath), L"%ls\\a6.exe", s_dir);
            p->SetLocalPath(szPath);
            ok_hex(p->CheckPolicy(), S_OK);
            p->Release();
        }
    }

    // Prompts that need no dialog: nothing to ask for, so the default action comes back
    struct { PCWSTR name; PCWSTR src; ATTACHMENT_PROMPT prompt; ATTACHMENT_ACTION action; } pcases[] =
    {
        { L"a.exe", L"file:///C:/Windows/a.exe", ATTACHMENT_PROMPT_EXEC, ATTACHMENT_ACTION_EXEC },
        { L"a.exe", L"file:///C:/Windows/a.exe", ATTACHMENT_PROMPT_SAVE, ATTACHMENT_ACTION_SAVE },
        { L"a.txt", L"https://example.com/a.txt", ATTACHMENT_PROMPT_EXEC, ATTACHMENT_ACTION_EXEC },
        { L"a.jpg", L"https://example.com/a.jpg", ATTACHMENT_PROMPT_EXEC_OR_SAVE, ATTACHMENT_ACTION_EXEC },
        { L"a.exe", L"https://example.com/a.exe", ATTACHMENT_PROMPT_NONE, ATTACHMENT_ACTION_SAVE },
    };
    for (UINT i = 0; i < _countof(pcases); ++i)
    {
        IAttachmentExecute *p = NULL;
        if (FAILED(CreateAE(&p)))
            return;
        WCHAR szPath[MAX_PATH];
        StringCchPrintfW(szPath, _countof(szPath), L"%ls\\%ls", s_dir, pcases[i].name);
        p->SetLocalPath(szPath);
        p->SetSource(pcases[i].src);
        ATTACHMENT_ACTION action = (ATTACHMENT_ACTION)-1;
        HRESULT hr = p->Prompt(NULL, pcases[i].prompt, &action);
        ok_hex(hr, S_OK);
        ok(action == pcases[i].action, "[%u] action %d expected %d\n", i, action, pcases[i].action);
        p->Release();
    }
}

START_TEST(AttachmentExecute)
{
    CoInitialize(NULL);
    GetTempPathW(_countof(s_dir), s_dir);
    StringCchCatW(s_dir, _countof(s_dir), L"attexec-apitest");
    CreateDirectoryW(s_dir, NULL);

    TestRegistration();
    TestArguments();
    TestSave();
    TestPolicyAndPrompt();

    // Cleanup
    WCHAR szFrom[MAX_PATH + 2] = {};
    StringCchCopyW(szFrom, _countof(szFrom) - 1, s_dir);
    SHFILEOPSTRUCTW fo = { NULL, FO_DELETE, szFrom, NULL, FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI };
    SHFileOperationW(&fo);
    CoUninitialize();
}
