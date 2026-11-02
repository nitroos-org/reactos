/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     winscard.dll without a Smart Card service: the answers measured on Windows 10 22H2
 *              (SCardSvr stopped, no reader attached)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <apitest.h>
#include <windows.h>
#include <winscard.h>

#ifndef SCARD_AUTOALLOCATE
#define SCARD_AUTOALLOCATE ((DWORD)-1)
#endif

#ifndef SCARD_SHARE_SHARED
#define SCARD_SHARE_SHARED 2
#endif

#define E_NO_SERVICE ((LONG)0x8010001D)
#define E_INVALID_PARAMETER ((LONG)0x80100004)
#define E_INVALID_VALUE ((LONG)0x80100011)
#define E_NO_READERS ((LONG)0x8010002E)

static LONG (WINAPI *pSCardEstablishContext)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);
static LONG (WINAPI *pSCardIsValidContext)(SCARDCONTEXT);
static LONG (WINAPI *pSCardReleaseContext)(SCARDCONTEXT);
static LONG (WINAPI *pSCardCancel)(SCARDCONTEXT);
static LONG (WINAPI *pSCardListReadersW)(SCARDCONTEXT, LPCWSTR, LPWSTR, LPDWORD);
static LONG (WINAPI *pSCardListReadersA)(SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD);
static LONG (WINAPI *pSCardListReaderGroupsW)(SCARDCONTEXT, LPWSTR, LPDWORD);
static LONG (WINAPI *pSCardGetStatusChangeW)(SCARDCONTEXT, DWORD, LPSCARD_READERSTATEW, DWORD);
static LONG (WINAPI *pSCardConnectW)(SCARDCONTEXT, LPCWSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD);
static LONG (WINAPI *pSCardFreeMemory)(SCARDCONTEXT, LPCVOID);

static BOOL load_functions(void)
{
    HMODULE module = LoadLibraryA("winscard.dll");

    ok(module != NULL, "LoadLibrary(winscard.dll) failed: %lu\n", GetLastError());
    if (!module)
        return FALSE;
#define LOAD(name) do { p##name = (void *)GetProcAddress(module, #name); \
    ok(p##name != NULL, #name " missing\n"); if (!p##name) return FALSE; } while (0)
    LOAD(SCardEstablishContext);
    LOAD(SCardIsValidContext);
    LOAD(SCardReleaseContext);
    LOAD(SCardCancel);
    LOAD(SCardListReadersW);
    LOAD(SCardListReadersA);
    LOAD(SCardListReaderGroupsW);
    LOAD(SCardGetStatusChangeW);
    LOAD(SCardConnectW);
    LOAD(SCardFreeMemory);
#undef LOAD
    return TRUE;
}

static void test_lists(SCARDCONTEXT context, BOOL service)
{
    WCHAR buffer[16];
    CHAR bufferA[16];
    LPWSTR allocated = NULL;
    DWORD length;
    LONG ret;

    /* No service: the lists are empty, and the call succeeds even without a context. With a
     * service and no reader, the reader list is not available. */
    length = 0xdeadbeef;
    ret = pSCardListReadersW(context, NULL, NULL, &length);
    if (service)
    {
        ok(ret == SCARD_S_SUCCESS || ret == E_NO_READERS, "SCardListReadersW size query: 0x%08lx\n", ret);
    }
    else
    {
        ok(ret == SCARD_S_SUCCESS, "SCardListReadersW size query: 0x%08lx\n", ret);
        ok(length == 1, "length = %lu\n", length);
    }

    if (!service)
    {
        buffer[0] = 0x1234;
        length = ARRAYSIZE(buffer);
        ret = pSCardListReadersW(context, NULL, buffer, &length);
        ok(ret == SCARD_S_SUCCESS, "SCardListReadersW: 0x%08lx\n", ret);
        ok(length == 1, "length = %lu\n", length);
        ok(buffer[0] == 0, "buffer[0] = %x\n", buffer[0]);

        bufferA[0] = 0x12;
        length = ARRAYSIZE(bufferA);
        ret = pSCardListReadersA(context, NULL, bufferA, &length);
        ok(ret == SCARD_S_SUCCESS, "SCardListReadersA: 0x%08lx\n", ret);
        ok(length == 1, "length = %lu\n", length);
        ok(bufferA[0] == 0, "bufferA[0] = %x\n", bufferA[0]);

        length = SCARD_AUTOALLOCATE;
        ret = pSCardListReadersW(context, NULL, (LPWSTR)&allocated, &length);
        ok(ret == SCARD_S_SUCCESS, "SCardListReadersW autoallocate: 0x%08lx\n", ret);
        ok(length == 1, "length = %lu\n", length);
        ok(allocated != NULL, "no buffer\n");
        if (allocated)
        {
            ok(allocated[0] == 0, "allocated[0] = %x\n", allocated[0]);
            ret = pSCardFreeMemory(context, allocated);
            ok(ret == SCARD_S_SUCCESS, "SCardFreeMemory: 0x%08lx\n", ret);
        }

        length = ARRAYSIZE(buffer);
        ret = pSCardListReaderGroupsW(context, buffer, &length);
        ok(ret == SCARD_S_SUCCESS, "SCardListReaderGroupsW: 0x%08lx\n", ret);
        ok(length == 1, "length = %lu\n", length);
    }
}

/* winscard.dll is imported by this test, so the loader found it through the process search path.
 * Its reported path must be inside the directory GetSystemDirectory returns: that is System32 on
 * Windows for a 32-bit process too (the file system redirector selects SysWOW64 behind it).
 * eID Klient's CardAPI checks exactly this and does not continue otherwise. */
static void test_module_path(void)
{
    CHAR System[MAX_PATH], Path[MAX_PATH];
    HMODULE Module = GetModuleHandleA("winscard.dll");
    UINT Length = GetSystemDirectoryA(System, ARRAYSIZE(System));

    /* a reference that keeps the import */
    ok(SCardIsValidContext(0) != SCARD_S_SUCCESS, "SCardIsValidContext(0) succeeded\n");
    ok(Module != NULL, "winscard.dll is not loaded: %lu\n", GetLastError());
    if (!Module || !Length)
        return;
    ok(GetModuleFileNameA(Module, Path, ARRAYSIZE(Path)) != 0, "GetModuleFileNameA failed: %lu\n", GetLastError());
    ok(!_strnicmp(Path, System, Length) && Path[Length] == '\\',
       "module path %s is not in the system directory %s\n", Path, System);
}

START_TEST(NoService)
{
    SCARDCONTEXT context = 0, context2 = 0;
    SCARD_READERSTATEW state;
    SCARDHANDLE card;
    DWORD protocol;
    BOOL service;
    LONG ret;

    test_module_path();

    if (!load_functions())
        return;

    /* The parameters are checked before the service is asked */
    ret = pSCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, NULL);
    ok(ret == E_INVALID_PARAMETER, "SCardEstablishContext(NULL): 0x%08lx\n", ret);
    ret = pSCardEstablishContext(99, NULL, NULL, &context2);
    ok(ret == E_INVALID_VALUE, "SCardEstablishContext(99): 0x%08lx\n", ret);
    ok(context2 == 0, "context = %lx\n", (ULONG)context2);

    ret = pSCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &context);
    service = (ret == SCARD_S_SUCCESS);
    if (!service)
    {
        /* Stopped service (the default on Windows 10 until a reader arrives) */
        ok(ret == E_NO_SERVICE, "SCardEstablishContext: 0x%08lx\n", ret);
        ok(context == 0, "context = %lx\n", (ULONG)context);

        ret = pSCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &context2);
        ok(ret == E_NO_SERVICE, "SCardEstablishContext(SYSTEM): 0x%08lx\n", ret);

        ret = pSCardIsValidContext(context);
        ok(ret == ERROR_INVALID_HANDLE, "SCardIsValidContext: 0x%08lx\n", ret);
        ret = pSCardReleaseContext(context);
        ok(ret == ERROR_INVALID_HANDLE, "SCardReleaseContext: 0x%08lx\n", ret);
        ret = pSCardCancel(context);
        ok(ret == ERROR_INVALID_HANDLE, "SCardCancel: 0x%08lx\n", ret);

        memset(&state, 0, sizeof(state));
        state.szReader = L"\\\\?PnP?\\Notification";
        ret = pSCardGetStatusChangeW(context, 0, &state, 1);
        ok(ret == ERROR_INVALID_HANDLE, "SCardGetStatusChangeW: 0x%08lx\n", ret);
        ok(state.dwEventState == 0, "dwEventState = %lx\n", state.dwEventState);

        card = 0;
        protocol = 0;
        ret = pSCardConnectW(context, L"No such reader", SCARD_SHARE_SHARED,
                            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &protocol);
        ok(ret == ERROR_INVALID_HANDLE, "SCardConnectW: 0x%08lx\n", ret);
    }
    test_lists(context, service);
    if (service)
        pSCardReleaseContext(context);
}
