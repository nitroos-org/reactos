/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for IFileOperation
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expectations were measured on Windows 10 22H2 (build 19045), with the operation flags FOF_NO_UI.
 * Chrome moves a download from its temporary name to the final one with MoveItem on this object; when the class
 * was missing, every download failed with "Download error".
 */

#include "shelltest.h"
#include <shellutils.h>
#include <atlstr.h>
#include <shlwapi.h>
#include <strsafe.h>

// The values the sinks are given (TSF_* flags) and the "done without child items" result
#define COPYENGINE_S_DONT_PROCESS_CHILDREN 0x00270008
#define TSF_COPY_FILE   0x22a
#define TSF_MOVE_FILE   0x232
#define TSF_RENAME_FILE 0x230
#define TSF_OTHER_FILE  0x202

class CSink : public IFileOperationProgressSink
{
public:
    LONG m_ref;
    int m_id;
    CStringA m_log;

    CSink(int id) : m_ref(1), m_id(id) { }

    void Log(const char *pszFormat, ...)
    {
        char sz[512];
        va_list va;
        va_start(va, pszFormat);
        StringCchVPrintfA(sz, _countof(sz), pszFormat, va);
        va_end(va);
        CStringA str;
        str.Format("s%d:%s;", m_id, sz);
        g_Log += str;
    }
    static CStringA g_Log;

    static CStringA Name(IShellItem *psi)
    {
        if (!psi)
            return "(null)";
        LPWSTR psz = NULL;
        CStringA str = "?";
        if (SUCCEEDED(psi->GetDisplayName(SIGDN_NORMALDISPLAY, &psz)))
        {
            str = psz;
            CoTaskMemFree(psz);
        }
        return str;
    }
    static CStringA Str(LPCWSTR psz) { return psz ? CStringA(psz) : CStringA("(null)"); }

    STDMETHODIMP QueryInterface(REFIID riid, void **ppv)
    {
        if (riid == IID_IUnknown || riid == IID_IFileOperationProgressSink)
        {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() { return InterlockedDecrement(&m_ref); }

    STDMETHODIMP StartOperations() { Log("Start"); return S_OK; }
    STDMETHODIMP FinishOperations(HRESULT hr) { Log("Finish(%08lx)", hr); return S_OK; }
    STDMETHODIMP PreRenameItem(DWORD f, IShellItem *i, LPCWSTR n)
    { Log("PreRename(%lx,%s,%s)", f, (PCSTR)Name(i), (PCSTR)Str(n)); return S_OK; }
    STDMETHODIMP PostRenameItem(DWORD f, IShellItem *i, LPCWSTR n, HRESULT hr, IShellItem *nw)
    { Log("PostRename(%lx,%s,%s,%08lx,%s)", f, (PCSTR)Name(i), (PCSTR)Str(n), hr, (PCSTR)Name(nw)); return S_OK; }
    STDMETHODIMP PreMoveItem(DWORD f, IShellItem *i, IShellItem *d, LPCWSTR n)
    { Log("PreMove(%lx,%s,%s,%s)", f, (PCSTR)Name(i), (PCSTR)Name(d), (PCSTR)Str(n)); return S_OK; }
    STDMETHODIMP PostMoveItem(DWORD f, IShellItem *i, IShellItem *d, LPCWSTR n, HRESULT hr, IShellItem *nw)
    { Log("PostMove(%lx,%s,%s,%s,%08lx,%s)", f, (PCSTR)Name(i), (PCSTR)Name(d), (PCSTR)Str(n), hr, (PCSTR)Name(nw)); return S_OK; }
    STDMETHODIMP PreCopyItem(DWORD f, IShellItem *i, IShellItem *d, LPCWSTR n)
    { Log("PreCopy(%lx,%s,%s,%s)", f, (PCSTR)Name(i), (PCSTR)Name(d), (PCSTR)Str(n)); return S_OK; }
    STDMETHODIMP PostCopyItem(DWORD f, IShellItem *i, IShellItem *d, LPCWSTR n, HRESULT hr, IShellItem *nw)
    { Log("PostCopy(%lx,%s,%s,%s,%08lx,%s)", f, (PCSTR)Name(i), (PCSTR)Name(d), (PCSTR)Str(n), hr, (PCSTR)Name(nw)); return S_OK; }
    STDMETHODIMP PreDeleteItem(DWORD f, IShellItem *i)
    { Log("PreDelete(%lx,%s)", f, (PCSTR)Name(i)); return S_OK; }
    STDMETHODIMP PostDeleteItem(DWORD f, IShellItem *i, HRESULT hr, IShellItem *nw)
    { Log("PostDelete(%lx,%s,%08lx,%s)", f, (PCSTR)Name(i), hr, (PCSTR)Name(nw)); return S_OK; }
    STDMETHODIMP PreNewItem(DWORD f, IShellItem *d, LPCWSTR n)
    { Log("PreNew(%lx,%s,%s)", f, (PCSTR)Name(d), (PCSTR)Str(n)); return S_OK; }
    STDMETHODIMP PostNewItem(DWORD f, IShellItem *d, LPCWSTR n, LPCWSTR t, DWORD a, HRESULT hr, IShellItem *nw)
    { Log("PostNew(%lx,%s,%s,%s,%lx,%08lx,%s)", f, (PCSTR)Name(d), (PCSTR)Str(n), (PCSTR)Str(t), a, hr, (PCSTR)Name(nw)); return S_OK; }
    STDMETHODIMP UpdateProgress(UINT, UINT) { return S_OK; }
    STDMETHODIMP ResetTimer() { return S_OK; }
    STDMETHODIMP PauseTimer() { return S_OK; }
    STDMETHODIMP ResumeTimer() { return S_OK; }
};
CStringA CSink::g_Log;

static WCHAR s_szDir[MAX_PATH];

static CStringW PathOf(PCWSTR pszName)
{
    CStringW str = s_szDir;
    str += L"\\";
    str += pszName;
    return str;
}

static void MakeFile(PCWSTR pszName, PCSTR pszContent)
{
    HANDLE hFile = CreateFileW(PathOf(pszName), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    ok(hFile != INVALID_HANDLE_VALUE, "Create %ls: %lu\n", pszName, GetLastError());
    DWORD cb;
    WriteFile(hFile, pszContent, (DWORD)strlen(pszContent), &cb, NULL);
    CloseHandle(hFile);
}

static BOOL Exists(PCWSTR pszName)
{
    return GetFileAttributesW(PathOf(pszName)) != INVALID_FILE_ATTRIBUTES;
}

static CStringA ReadFileA(PCWSTR pszName)
{
    char sz[64] = { 0 };
    HANDLE hFile = CreateFileW(PathOf(pszName), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD cb = 0;
    if (hFile != INVALID_HANDLE_VALUE)
    {
        ReadFile(hFile, sz, sizeof(sz) - 1, &cb, NULL);
        CloseHandle(hFile);
    }
    return sz;
}

static IShellItem *ItemOf(PCWSTR pszName)
{
    IShellItem *psi = NULL;
    HRESULT hr = SHCreateItemFromParsingName(PathOf(pszName), NULL, IID_PPV_ARG(IShellItem, &psi));
    ok_hex(hr, S_OK);
    return psi;
}

static IShellItem *DirItem()
{
    IShellItem *psi = NULL;
    HRESULT hr = SHCreateItemFromParsingName(s_szDir, NULL, IID_PPV_ARG(IShellItem, &psi));
    ok_hex(hr, S_OK);
    return psi;
}

static void CleanDir()
{
    WCHAR sz[MAX_PATH + 2] = { 0 };
    StringCchCopyW(sz, _countof(sz) - 1, s_szDir);
    SHFILEOPSTRUCTW op = { 0 };
    op.wFunc = FO_DELETE;
    op.pFrom = sz;
    op.fFlags = FOF_NO_UI;
    SHFileOperationW(&op);
    CreateDirectoryW(s_szDir, NULL);
}

static IFileOperation *NewOperation(DWORD dwFlags)
{
    IFileOperation *pOp = NULL;
    HRESULT hr = CoCreateInstance(CLSID_FileOperation, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARG(IFileOperation, &pOp));
    ok_hex(hr, S_OK);
    if (pOp)
    {
        hr = pOp->SetOperationFlags(dwFlags);
        ok_hex(hr, S_OK);
    }
    return pOp;
}

static void ExpectLog(PCSTR pszExpected)
{
    ok(CSink::g_Log == pszExpected, "Log is\n  %s\nexpected\n  %s\n", (PCSTR)CSink::g_Log, pszExpected);
    CSink::g_Log.Empty();
}

static void TestObject()
{
    IFileOperation *pOp = NewOperation(FOF_NO_UI);
    if (!pOp)
    {
        skip("No IFileOperation\n");
        return;
    }

    IUnknown *punk = NULL;
    ok_hex(pOp->QueryInterface(IID_PPV_ARG(IUnknown, &punk)), S_OK);
    if (punk)
        punk->Release();

    BOOL bAborted = TRUE;
    ok_hex(pOp->GetAnyOperationsAborted(&bAborted), S_OK);
    ok_int(bAborted, FALSE);

    // nothing is queued
    ok_hex(pOp->PerformOperations(), E_UNEXPECTED);
    ok_hex(pOp->PerformOperations(), E_UNEXPECTED);

    DWORD dwCookie = 123;
    ok_hex(pOp->Advise(NULL, &dwCookie), E_INVALIDARG);
    ok_hex(pOp->Unadvise(12345), E_INVALIDARG);

    CSink *pSink = new CSink(0);
    DWORD dwCookie1 = 0, dwCookie2 = 0;
    ok_hex(pOp->Advise(pSink, &dwCookie1), S_OK);
    ok_hex(pOp->Advise(pSink, &dwCookie2), S_OK);
    ok(dwCookie1 != 0 && dwCookie2 != 0 && dwCookie1 != dwCookie2, "Cookies %lu %lu\n", dwCookie1, dwCookie2);
    ok_hex(pOp->Unadvise(dwCookie1), S_OK);
    ok_hex(pOp->Unadvise(dwCookie1), S_OK);
    ok_hex(pOp->Unadvise(dwCookie2), S_OK);

    ok_hex(pOp->SetOwnerWindow(NULL), S_OK);
    ok_hex(pOp->SetProgressMessage(L"x"), E_NOTIMPL);
    ok_hex(pOp->SetProgressDialog(NULL), E_INVALIDARG);
    ok_hex(pOp->SetProperties(NULL), S_OK);
    pOp->Release();
    pSink->Release();
}

static void TestCopyMove()
{
    CleanDir();
    MakeFile(L"a.txt", "hello");
    CreateDirectoryW(PathOf(L"dst"), NULL);

    IFileOperation *pOp = NewOperation(FOF_NO_UI);
    if (!pOp)
        return;
    CSink *pGlobal = new CSink(1), *pItem = new CSink(2);
    DWORD dwCookie;
    ok_hex(pOp->Advise(pGlobal, &dwCookie), S_OK);
    IShellItem *psiA = ItemOf(L"a.txt"), *psiDst = ItemOf(L"dst");

    // copy under a new name: nothing happens before PerformOperations; the item sink is called inside the global ones
    ok_hex(pOp->CopyItem(psiA, psiDst, L"b.txt", pItem), S_OK);
    ok_int(Exists(L"dst\\b.txt"), FALSE);
    ok_hex(pOp->PerformOperations(), S_OK);
    char sz[512];
    StringCchPrintfA(sz, _countof(sz),
        "s1:Start;s1:PreCopy(%x,a.txt,dst,b.txt);s2:PreCopy(%x,a.txt,dst,b.txt);"
        "s2:PostCopy(%x,a.txt,dst,b.txt,00000000,b.txt);s1:PostCopy(%x,a.txt,dst,b.txt,00000000,b.txt);s1:Finish(00000000);",
        TSF_COPY_FILE, TSF_COPY_FILE, TSF_COPY_FILE, TSF_COPY_FILE);
    ExpectLog(sz);
    ok_int(Exists(L"dst\\b.txt"), TRUE);
    ok_int(Exists(L"a.txt"), TRUE);
    ok_str(ReadFileA(L"dst\\b.txt"), "hello");
    BOOL bAborted = TRUE;
    ok_hex(pOp->GetAnyOperationsAborted(&bAborted), S_OK);
    ok_int(bAborted, FALSE);

    // the queue is empty again, and no sink is called
    ok_hex(pOp->PerformOperations(), E_UNEXPECTED);
    ExpectLog("");

    // move under the same name: the name is empty before and given after
    ok_hex(pOp->MoveItem(psiA, psiDst, NULL, NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);
    StringCchPrintfA(sz, _countof(sz),
        "s1:Start;s1:PreMove(%x,a.txt,dst,);s1:PostMove(%x,a.txt,dst,a.txt,%08lx,a.txt);s1:Finish(00000000);",
        TSF_MOVE_FILE, TSF_MOVE_FILE, (ULONG)COPYENGINE_S_DONT_PROCESS_CHILDREN);
    ExpectLog(sz);
    ok_int(Exists(L"dst\\a.txt"), TRUE);
    ok_int(Exists(L"a.txt"), FALSE);

    psiA->Release();
    psiDst->Release();
    pOp->Release();
    pGlobal->Release();
    pItem->Release();
}

static void TestRenameNewDelete()
{
    CleanDir();
    MakeFile(L"r.txt", "x");
    MakeFile(L"del.txt", "x");

    IFileOperation *pOp = NewOperation(FOF_NO_UI);
    if (!pOp)
        return;
    CSink *pSink = new CSink(1);
    DWORD dwCookie;
    ok_hex(pOp->Advise(pSink, &dwCookie), S_OK);
    IShellItem *psiR = ItemOf(L"r.txt"), *psiDel = ItemOf(L"del.txt"), *psiDir = DirItem();

    ok_hex(pOp->RenameItem(psiR, L"r2.txt", NULL), S_OK);
    ok_hex(pOp->NewItem(psiDir, FILE_ATTRIBUTE_NORMAL, L"new.txt", NULL, NULL), S_OK);
    ok_hex(pOp->NewItem(psiDir, FILE_ATTRIBUTE_DIRECTORY, L"newdir", NULL, NULL), S_OK);
    ok_hex(pOp->DeleteItem(psiDel, NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);

    CStringA strDir = CSink::Name(psiDir);
    CStringA strExpected;
    strExpected.Format("s1:Start;s1:PreRename(%x,r.txt,r2.txt);s1:PostRename(%x,r.txt,r2.txt,%08lx,r2.txt);"
        "s1:PreNew(%x,%s,new.txt);s1:PostNew(%x,%s,new.txt,(null),80,00000000,new.txt);"
        "s1:PreNew(%x,%s,newdir);s1:PostNew(%x,%s,newdir,(null),10,00000000,newdir);"
        "s1:PreDelete(%x,del.txt);s1:PostDelete(%x,del.txt,%08lx,(null));s1:Finish(00000000);",
        TSF_RENAME_FILE, TSF_RENAME_FILE, (ULONG)COPYENGINE_S_DONT_PROCESS_CHILDREN,
        TSF_OTHER_FILE, (PCSTR)strDir, TSF_OTHER_FILE, (PCSTR)strDir,
        TSF_OTHER_FILE, (PCSTR)strDir, TSF_OTHER_FILE, (PCSTR)strDir,
        TSF_OTHER_FILE, TSF_OTHER_FILE, (ULONG)COPYENGINE_S_DONT_PROCESS_CHILDREN);
    ExpectLog(strExpected);

    ok_int(Exists(L"r2.txt"), TRUE);
    ok_int(Exists(L"r.txt"), FALSE);
    ok_int(Exists(L"new.txt"), TRUE);
    ok((GetFileAttributesW(PathOf(L"newdir")) & FILE_ATTRIBUTE_DIRECTORY) != 0, "newdir is not a directory\n");
    ok_int(Exists(L"del.txt"), FALSE);

    psiR->Release();
    psiDel->Release();
    psiDir->Release();
    pOp->Release();
    pSink->Release();
}

static void TestFailures()
{
    CleanDir();
    MakeFile(L"g.txt", "x");
    IShellItem *psiG = ItemOf(L"g.txt"), *psiDir = DirItem();
    DeleteFileW(PathOf(L"g.txt"));
    CStringA strDir = CSink::Name(psiDir);

    // A failing operation is no error of PerformOperations: the sink gets the error, the "aborted" flag is set
    IFileOperation *pOp = NewOperation(FOF_NO_UI);
    if (!pOp)
        return;
    CSink *pSink = new CSink(1);
    DWORD dwCookie;
    ok_hex(pOp->Advise(pSink, &dwCookie), S_OK);
    ok_hex(pOp->MoveItem(psiG, psiDir, L"h.txt", NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);
    CStringA strExpected;
    strExpected.Format("s1:Start;s1:PreMove(%x,g.txt,%s,h.txt);s1:PostMove(%x,g.txt,%s,h.txt,80070002,(null));s1:Finish(00000000);",
                       TSF_MOVE_FILE, (PCSTR)strDir, TSF_MOVE_FILE, (PCSTR)strDir);
    ExpectLog(strExpected);
    BOOL bAborted = FALSE;
    ok_hex(pOp->GetAnyOperationsAborted(&bAborted), S_OK);
    ok_int(bAborted, TRUE);
    pOp->Release();

    pOp = NewOperation(FOF_NO_UI);
    ok_hex(pOp->Advise(pSink, &dwCookie), S_OK);
    ok_hex(pOp->DeleteItem(psiG, NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);
    strExpected.Format("s1:Start;s1:PreDelete(%x,g.txt);s1:PostDelete(%x,g.txt,80070002,(null));s1:Finish(00000000);",
                       TSF_OTHER_FILE, TSF_OTHER_FILE);
    ExpectLog(strExpected);
    bAborted = FALSE;
    ok_hex(pOp->GetAnyOperationsAborted(&bAborted), S_OK);
    ok_int(bAborted, TRUE);
    pOp->Release();

    pOp = NewOperation(FOF_NO_UI);
    ok_hex(pOp->Advise(pSink, &dwCookie), S_OK);
    ok_hex(pOp->RenameItem(psiG, L"z.txt", NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);
    strExpected.Format("s1:Start;s1:PreRename(%x,g.txt,z.txt);s1:PostRename(%x,g.txt,z.txt,80070002,(null));s1:Finish(00000000);",
                       TSF_RENAME_FILE, TSF_RENAME_FILE);
    ExpectLog(strExpected);
    pOp->Release();

    psiG->Release();
    psiDir->Release();
    pSink->Release();
}

static void TestCollisionAndDirectories()
{
    CleanDir();
    CreateDirectoryW(PathOf(L"dst"), NULL);
    MakeFile(L"c.txt", "new");
    MakeFile(L"dst\\c.txt", "old");
    IShellItem *psiC = ItemOf(L"c.txt"), *psiDst = ItemOf(L"dst");

    // FOF_NOCONFIRMATION (part of FOF_NO_UI) overwrites
    IFileOperation *pOp = NewOperation(FOF_NO_UI);
    if (!pOp)
        return;
    ok_hex(pOp->CopyItem(psiC, psiDst, NULL, NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);
    ok_str(ReadFileA(L"dst\\c.txt"), "new");
    pOp->Release();

    // a directory is copied with its content, and moved
    CleanDir();
    CreateDirectoryW(PathOf(L"srcdir"), NULL);
    MakeFile(L"srcdir\\f.txt", "1");
    CreateDirectoryW(PathOf(L"dst"), NULL);
    IShellItem *psiSrcDir = ItemOf(L"srcdir");
    IShellItem *psiDst2 = ItemOf(L"dst");
    pOp = NewOperation(FOF_NO_UI);
    ok_hex(pOp->CopyItem(psiSrcDir, psiDst2, L"copied", NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);
    ok_int(Exists(L"dst\\copied\\f.txt"), TRUE);
    ok_hex(pOp->MoveItem(psiSrcDir, psiDst2, NULL, NULL), S_OK);
    ok_hex(pOp->PerformOperations(), S_OK);
    ok_int(Exists(L"dst\\srcdir\\f.txt"), TRUE);
    ok_int(Exists(L"srcdir"), FALSE);
    pOp->Release();

    // several items at once, as an IShellItemArray
    CleanDir();
    MakeFile(L"m1.txt", "1");
    MakeFile(L"m2.txt", "2");
    CreateDirectoryW(PathOf(L"dst"), NULL);
    PIDLIST_ABSOLUTE pidls[2];
    pidls[0] = ILCreateFromPathW(PathOf(L"m1.txt"));
    pidls[1] = ILCreateFromPathW(PathOf(L"m2.txt"));
    IShellItemArray *psia = NULL;
    HRESULT hr = SHCreateShellItemArrayFromIDLists(2, (PCIDLIST_ABSOLUTE_ARRAY)pidls, &psia);
    ok_hex(hr, S_OK);
    IShellItem *psiDst3 = ItemOf(L"dst");
    pOp = NewOperation(FOF_NO_UI);
    if (psia && pOp)
    {
        ok_hex(pOp->CopyItems(psia, psiDst3), S_OK);
        ok_hex(pOp->PerformOperations(), S_OK);
        ok_int(Exists(L"dst\\m1.txt"), TRUE);
        ok_int(Exists(L"dst\\m2.txt"), TRUE);
        ok_int(Exists(L"m1.txt"), TRUE);
    }
    if (pOp)
        pOp->Release();
    if (psia)
        psia->Release();
    ILFree(pidls[0]);
    ILFree(pidls[1]);
    if (psiC)
        psiC->Release();
    if (psiDst)
        psiDst->Release();
    if (psiSrcDir)
        psiSrcDir->Release();
    if (psiDst2)
        psiDst2->Release();
    if (psiDst3)
        psiDst3->Release();
}

START_TEST(IFileOperation)
{
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ok_hex(hr, S_OK);

    GetTempPathW(_countof(s_szDir), s_szDir);
    StringCchCatW(s_szDir, _countof(s_szDir), L"RosIFileOperationTest");
    CleanDir();

    TestObject();
    TestCopyMove();
    TestRenameNewDelete();
    TestFailures();
    TestCollisionAndDirectories();

    CleanDir();
    RemoveDirectoryW(s_szDir);
    CoUninitialize();
}
