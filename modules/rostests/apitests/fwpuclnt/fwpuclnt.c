/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for fwpuclnt.dll: engine session, transactions, enumeration, lookups, application identifiers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected values were measured on Windows Server 2022 (build 20348, x64 and WOW64) with the same checks:
 * the test only opens a session, begins and aborts transactions, enumerates and looks up by random keys; it never
 * adds, changes or deletes an object. Rows marked "NitroOS" hold what this DLL decides (the engine holds nothing and the
 * changes are refused); on Windows they are skipped, because the peer's engine has filters and must not be changed.
 * Windows 10 was not measured.
 */

#include <apitest.h>

#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <strsafe.h>
#include <fwpmu.h>

#define STATUS_SESSION_GONE ((DWORD)0x80320010)

#ifndef LUA_TOKEN
#define LUA_TOKEN 0x4
#endif

static BOOL IsAdmin(void)
{
    SID_IDENTIFIER_AUTHORITY Nt = {SECURITY_NT_AUTHORITY};
    PSID Sid;
    BOOL Member = FALSE;

    if (!AllocateAndInitializeSid(&Nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &Sid))
        return FALSE;
    if (!CheckTokenMembership(NULL, Sid, &Member))
        Member = FALSE;
    FreeSid(Sid);
    return Member;
}

typedef DWORD (WINAPI *CREATEFN)(HANDLE, const void *, HANDLE *);
typedef DWORD (WINAPI *ENUMFN)(HANDLE, HANDLE, UINT32, void ***, UINT32 *);
typedef DWORD (WINAPI *DESTROYFN)(HANDLE, HANDLE);

static void TestEnum(HANDLE Engine, PCSTR Name, CREATEFN Create, ENUMFN Enum, DESTROYFN Destroy)
{
    HANDLE EnumHandle = NULL;
    void **Entries;
    UINT32 Count;
    DWORD Status;

    Status = Create(Engine, NULL, &EnumHandle);
    ok(Status == ERROR_SUCCESS, "%s: create enum handle %08lx\n", Name, Status);
    if (Status)
        return;
    Entries = (void **)1;
    Count = 0xdead;
    Status = Enum(Engine, EnumHandle, 1000, &Entries, &Count);
    ok(Status == ERROR_SUCCESS, "%s: enum %08lx\n", Name, Status);
    if (is_reactos())
    {
        ok(Count == 0 && Entries == NULL, "%s: %u entries, array %p\n", Name, Count, Entries);
    }
    else if (!Status && Entries)
    {
        void *P = Entries;

        FwpmFreeMemory0(&P);
        ok(P == NULL, "%s: FwpmFreeMemory0 left the pointer %p\n", Name, P);
    }
    /* the enumeration is at its end after one call that asked for more than there is */
    Entries = (void **)1;
    Count = 0xdead;
    Status = Enum(Engine, EnumHandle, 1000, &Entries, &Count);
    ok(Status == ERROR_SUCCESS && Count == 0, "%s: enum again %08lx, %u entries\n", Name, Status, Count);
    if (!Status && Entries && Entries != (void **)1)
        FwpmFreeMemory0((void **)&Entries);
    Status = Destroy(Engine, EnumHandle);
    ok(Status == ERROR_SUCCESS, "%s: destroy %08lx\n", Name, Status);
    Status = Destroy(Engine, EnumHandle);
    ok(Status == STATUS_SESSION_GONE, "%s: destroy again %08lx\n", Name, Status);
    Status = Destroy(Engine, (HANDLE)(ULONG_PTR)0x5555);
    ok(Status == STATUS_SESSION_GONE, "%s: destroy bogus %08lx\n", Name, Status);
    Status = Enum(Engine, (HANDLE)(ULONG_PTR)0x5555, 10, &Entries, &Count);
    ok(Status == STATUS_SESSION_GONE, "%s: enum bogus %08lx\n", Name, Status);
}

static void TestAppId(void)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH], Expected[MAX_PATH], Device[MAX_PATH];
    FWP_BYTE_BLOB *Blob;
    HANDLE File;
    DWORD Status, Len;
    UINT i;

    GetTempPathW(MAX_PATH, Dir);
    GetLongPathNameW(Dir, Path, MAX_PATH);
    wcscpy(Dir, Path);
    wcscat(Dir, L"FwpAppId.Test.EXE");
    File = CreateFileW(Dir, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE, "create: %lu\n", GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(File);

    /* the NT path in lower case, one allocation: the string follows the blob, its null counted in the size */
    wcsncpy(Path, Dir, 2);
    Path[2] = 0;
    Len = QueryDosDeviceW(Path, Device, MAX_PATH);
    ok(Len != 0, "QueryDosDevice: %lu\n", GetLastError());
    if (Len)
    {
        wcscpy(Expected, Device);
        wcscat(Expected, Dir + 2);
        for (i = 0; Expected[i]; i++)
        {
            if (Expected[i] >= L'A' && Expected[i] <= L'Z')
                Expected[i] += L'a' - L'A';
        }
        Blob = NULL;
        Status = FwpmGetAppIdFromFileName0(Dir, &Blob);
        ok(Status == ERROR_SUCCESS, "app id: %08lx\n", Status);
        if (!Status && Blob)
        {
            ok(Blob->size == (wcslen(Expected) + 1) * sizeof(WCHAR), "size %u, expected %u\n", Blob->size, (UINT)((wcslen(Expected) + 1) * sizeof(WCHAR)));
            ok(Blob->data == (UINT8 *)(Blob + 1), "data %p, blob %p\n", Blob->data, Blob);
            ok(!wcscmp((WCHAR *)Blob->data, Expected), "app id '%ls', expected '%ls'\n", (WCHAR *)Blob->data, Expected);
            FwpmFreeMemory0((void **)&Blob);
            ok(Blob == NULL, "FwpmFreeMemory0 left %p\n", Blob);
        }

        /* the same file by other spellings */
        wcscpy(Path, Dir);
        for (i = 0; Path[i]; i++)
        {
            if (Path[i] == L'\\')
                Path[i] = L'/';
        }
        Blob = NULL;
        Status = FwpmGetAppIdFromFileName0(Path, &Blob);
        ok(Status == ERROR_SUCCESS && Blob && !wcscmp((WCHAR *)Blob->data, Expected), "forward slashes: %08lx\n", Status);
        if (!Status && Blob)
            FwpmFreeMemory0((void **)&Blob);
        StringCchPrintfW(Path, MAX_PATH, L"\\\\?\\%ls", Dir);
        Blob = NULL;
        Status = FwpmGetAppIdFromFileName0(Path, &Blob);
        ok(Status == ERROR_SUCCESS && Blob && !wcscmp((WCHAR *)Blob->data, Expected), "\\\\?\\ prefix: %08lx\n", Status);
        if (!Status && Blob)
            FwpmFreeMemory0((void **)&Blob);
    }

    /* the errors are those of opening the file (the directory is not a file) */
    wcscpy(Path, Dir);
    wcscat(Path, L".missing");
    Blob = (FWP_BYTE_BLOB *)1;
    Status = FwpmGetAppIdFromFileName0(Path, &Blob);
    ok(Status == ERROR_FILE_NOT_FOUND, "missing file: %08lx\n", Status);
    Status = FwpmGetAppIdFromFileName0(L"C:\\nosuchdir_fwpuclnt_apitest\\x.exe", &Blob);
    ok(Status == ERROR_PATH_NOT_FOUND, "missing directory: %08lx\n", Status);
    GetWindowsDirectoryW(Path, MAX_PATH);
    Status = FwpmGetAppIdFromFileName0(Path, &Blob);
    ok(Status == ERROR_ACCESS_DENIED, "a directory: %08lx\n", Status);
    Status = FwpmGetAppIdFromFileName0(NULL, &Blob);
    ok(Status == FWP_E_NULL_POINTER, "NULL name: %08lx\n", Status);
    Status = FwpmGetAppIdFromFileName0(L"", &Blob);
    ok(Status == ERROR_PATH_NOT_FOUND, "empty name: %08lx\n", Status);

    DeleteFileW(Dir);
}

static void TestSession(void)
{
    HANDLE Engine = NULL, Second = (HANDLE)(ULONG_PTR)0x1234, Probe;
    GUID Key = {0x1c2d3e4f, 0x1111, 0x2222, {1, 2, 3, 4, 5, 6, 7, 8}};
    void *Out;
    DWORD Status;
    BOOL Admin = IsAdmin();

    Status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &Engine);
    ok(Status == ERROR_SUCCESS, "open: %08lx\n", Status);
    if (Status || !Engine)
        return;
    /* a second session at the same time, with the default authentication service */
    Status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &Second);
    ok(Status == ERROR_SUCCESS && Second && Second != Engine, "second open: %08lx %p\n", Status, Second);
    if (!Status)
        FwpmEngineClose0(Second);
    /* a server name and other authentication services are not supported */
    Probe = (HANDLE)(ULONG_PTR)0x1234;
    Status = FwpmEngineOpen0(NULL, 0xFFFFFFFE, NULL, NULL, &Probe);
    ok(Status == ERROR_NOT_SUPPORTED && Probe == NULL, "bad authn: %08lx %p\n", Status, Probe);
    Probe = (HANDLE)(ULONG_PTR)0x1234;
    Status = FwpmEngineOpen0(L"nosuchhost.invalid", RPC_C_AUTHN_WINNT, NULL, NULL, &Probe);
    ok(Status == ERROR_NOT_SUPPORTED && Probe == NULL, "server name: %08lx %p\n", Status, Probe);

    if (!Admin)
    {
        skip("the enumeration, transaction and option rows need an administrator\n");
    }
    else
    {
        TestEnum(Engine, "filters", (CREATEFN)FwpmFilterCreateEnumHandle0, (ENUMFN)FwpmFilterEnum0, FwpmFilterDestroyEnumHandle0);
        TestEnum(Engine, "sublayers", (CREATEFN)FwpmSubLayerCreateEnumHandle0, (ENUMFN)FwpmSubLayerEnum0, FwpmSubLayerDestroyEnumHandle0);
        TestEnum(Engine, "providers", (CREATEFN)FwpmProviderCreateEnumHandle0, (ENUMFN)FwpmProviderEnum0, FwpmProviderDestroyEnumHandle0);

        /* transactions: one at a time, aborted, the errors of the engine */
        Status = FwpmTransactionBegin0(Engine, 0);
        ok(Status == ERROR_SUCCESS, "begin: %08lx\n", Status);
        Status = FwpmTransactionBegin0(Engine, 0);
        ok(Status == FWP_E_TXN_IN_PROGRESS, "begin again: %08lx\n", Status);
        Status = FwpmTransactionAbort0(Engine);
        ok(Status == ERROR_SUCCESS, "abort: %08lx\n", Status);
        Status = FwpmTransactionAbort0(Engine);
        ok(Status == FWP_E_NO_TXN_IN_PROGRESS, "abort without transaction: %08lx\n", Status);
        Status = FwpmTransactionCommit0(Engine);
        ok(Status == FWP_E_NO_TXN_IN_PROGRESS, "commit without transaction: %08lx\n", Status);
        Status = FwpmTransactionBegin0(Engine, 1 /* FWPM_TXN_READ_ONLY */);
        ok(Status == ERROR_SUCCESS, "begin read-only: %08lx\n", Status);
        Status = FwpmTransactionAbort0(Engine);
        ok(Status == ERROR_SUCCESS, "abort: %08lx\n", Status);

        /* options 0..5 exist on Windows; 6 and above do not */
        Out = NULL;
        Status = FwpmEngineGetOption0(Engine, (FWPM_ENGINE_OPTION)6, (FWP_VALUE0 **)&Out);
        ok(Status == 0x8032001d, "option 6: %08lx\n", Status);
        Status = FwpmEngineGetOption0(Engine, (FWPM_ENGINE_OPTION)7, (FWP_VALUE0 **)&Out);
        ok(Status == 0x8032001d, "option 7: %08lx\n", Status);
    }

    /* looking an object up needs no right, and a key that no object has is not found */
    Out = (void *)1;
    Status = FwpmFilterGetByKey0(Engine, &Key, (FWPM_FILTER0 **)&Out);
    ok(Status == FWP_E_FILTER_NOT_FOUND, "filter by key: %08lx\n", Status);
    Status = FwpmSubLayerGetByKey0(Engine, &Key, (FWPM_SUBLAYER0 **)&Out);
    ok(Status == FWP_E_SUBLAYER_NOT_FOUND, "sublayer by key: %08lx\n", Status);
    Status = FwpmProviderGetByKey0(Engine, &Key, (FWPM_PROVIDER0 **)&Out);
    ok(Status == FWP_E_PROVIDER_NOT_FOUND, "provider by key: %08lx\n", Status);
    Status = FwpmFilterGetById0(Engine, 0xFFFFFFF0ull, (FWPM_FILTER0 **)&Out);
    ok(Status == FWP_E_FILTER_NOT_FOUND, "filter by id: %08lx\n", Status);

    if (is_reactos())
    {
        FWPM_FILTER0 Filter;
        FWPM_PROVIDER0 Provider;
        FWPM_SUBLAYER0 SubLayer;
        UINT64 Id = 77;

        /* NitroOS: nothing is ever installed, and the caller is told */
        ZeroMemory(&Filter, sizeof(Filter));
        ZeroMemory(&Provider, sizeof(Provider));
        ZeroMemory(&SubLayer, sizeof(SubLayer));
        Status = FwpmFilterAdd0(Engine, &Filter, NULL, &Id);
        ok(Status == (Admin ? ERROR_NOT_SUPPORTED : ERROR_ACCESS_DENIED), "filter add: %08lx\n", Status);
        ok(Id == 0, "filter id %I64u\n", Id);
        Status = FwpmProviderAdd0(Engine, &Provider, NULL);
        ok(Status == (Admin ? ERROR_NOT_SUPPORTED : ERROR_ACCESS_DENIED), "provider add: %08lx\n", Status);
        Status = FwpmSubLayerAdd0(Engine, &SubLayer, NULL);
        ok(Status == (Admin ? ERROR_NOT_SUPPORTED : ERROR_ACCESS_DENIED), "sublayer add: %08lx\n", Status);
        Status = FwpmFilterAdd0(Engine, NULL, NULL, &Id);
        ok(Status == (Admin ? FWP_E_NULL_POINTER : ERROR_ACCESS_DENIED), "filter add NULL: %08lx\n", Status);
        Status = FwpmFilterDeleteByKey0(Engine, &Key);
        ok(Status == (Admin ? FWP_E_FILTER_NOT_FOUND : ERROR_ACCESS_DENIED), "filter delete: %08lx\n", Status);
        Status = FwpmSubLayerDeleteByKey0(Engine, &Key);
        ok(Status == (Admin ? FWP_E_SUBLAYER_NOT_FOUND : ERROR_ACCESS_DENIED), "sublayer delete: %08lx\n", Status);
        Status = FwpmEngineSetOption0(Engine, FWPM_ENGINE_COLLECT_NET_EVENTS, (FWP_VALUE0 *)&Filter);
        ok(Status == (Admin ? ERROR_NOT_SUPPORTED : ERROR_ACCESS_DENIED), "set option: %08lx\n", Status);
    }

    Status = FwpmEngineClose0(Engine);
    ok(Status == ERROR_SUCCESS, "close: %08lx\n", Status);
    if (is_reactos())
    {
        Status = FwpmEngineClose0(Engine);
        ok(Status == ERROR_INVALID_HANDLE, "close again: %08lx (Windows faults the process here)\n", Status);
    }
}

/* the same calls with a token without the Administrators group enabled: access denied where Windows says so */
static void TestNonAdmin(void)
{
    HANDLE Token, Restricted, Impersonation, Engine = NULL, EnumHandle = NULL;
    GUID Key = {0x1c2d3e4f, 0x1111, 0x2222, {1, 2, 3, 4, 5, 6, 7, 8}};
    FWPM_FILTER0 *Out;
    FWP_VALUE0 *Value;
    DWORD Status;

    if (!IsAdmin())
    {
        skip("the process is not an administrator: the plain run is the non-administrator run\n");
        return;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &Token) ||
        !CreateRestrictedToken(Token, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 0, NULL, 0, NULL, 0, NULL, &Restricted))
    {
        skip("no restricted token: %lu\n", GetLastError());
        return;
    }
    if (!DuplicateTokenEx(Restricted, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &Impersonation) ||
        !SetThreadToken(NULL, Impersonation))
    {
        skip("cannot impersonate: %lu\n", GetLastError());
        return;
    }
    ok(!IsAdmin(), "still an administrator\n");

    Status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &Engine);
    ok(Status == ERROR_SUCCESS, "open: %08lx\n", Status);
    if (!Status)
    {
        Status = FwpmFilterCreateEnumHandle0(Engine, NULL, &EnumHandle);
        ok(Status == ERROR_ACCESS_DENIED, "enum: %08lx\n", Status);
        Status = FwpmSubLayerCreateEnumHandle0(Engine, NULL, &EnumHandle);
        ok(Status == ERROR_ACCESS_DENIED, "sublayer enum: %08lx\n", Status);
        Status = FwpmProviderCreateEnumHandle0(Engine, NULL, &EnumHandle);
        ok(Status == ERROR_ACCESS_DENIED, "provider enum: %08lx\n", Status);
        Status = FwpmTransactionBegin0(Engine, 0);
        ok(Status == ERROR_ACCESS_DENIED, "begin: %08lx\n", Status);
        Status = FwpmTransactionAbort0(Engine);
        ok(Status == FWP_E_NO_TXN_IN_PROGRESS, "abort: %08lx\n", Status);
        Status = FwpmEngineGetOption0(Engine, FWPM_ENGINE_COLLECT_NET_EVENTS, &Value);
        ok(Status == ERROR_ACCESS_DENIED, "option: %08lx\n", Status);
        Status = FwpmFilterGetByKey0(Engine, &Key, &Out);
        ok(Status == FWP_E_FILTER_NOT_FOUND, "filter by key: %08lx\n", Status);
        FwpmEngineClose0(Engine);
    }
    RevertToSelf();
    CloseHandle(Impersonation);
    CloseHandle(Restricted);
    CloseHandle(Token);
}

START_TEST(fwpuclnt)
{
    TestSession();
    TestNonAdmin();
    TestAppId();
}
