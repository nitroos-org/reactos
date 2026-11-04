/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the package identity functions: the process without a package, the syntax of names
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <appmodel.h>

#ifndef APPMODEL_ERROR_NO_PACKAGE
#define APPMODEL_ERROR_NO_PACKAGE 15700
#endif
#ifndef APPMODEL_ERROR_NO_APPLICATION
#define APPMODEL_ERROR_NO_APPLICATION 15703
#endif

/* The structures that the package functions fill: the package information is packed to four bytes */
C_ASSERT(sizeof(PACKAGE_ID) == 16 + 4 * sizeof(PVOID));
#ifdef PACKAGE_FILTER_HEAD
C_ASSERT(FIELD_OFFSET(PACKAGE_INFO, packageId) == 8 + 3 * sizeof(PVOID));
C_ASSERT(sizeof(PACKAGE_INFO) == 8 + 3 * sizeof(PVOID) + sizeof(PACKAGE_ID));
C_ASSERT(PACKAGE_PROPERTY_DEVELOPMENT_MODE == 0x00010000);
#endif

typedef LONG (WINAPI *FN_Buffer)(UINT32 *, PVOID);
typedef LONG (WINAPI *FN_ProcessBuffer)(HANDLE, UINT32 *, PVOID);
typedef LONG (WINAPI *FN_Verify)(PCWSTR);
typedef LONG (WINAPI *FN_Text)(PCWSTR, UINT32 *, PVOID);
typedef LONG (WINAPI *FN_VerifyId)(const PACKAGE_ID *);
typedef LONG (WINAPI *FN_Id)(const PACKAGE_ID *, UINT32 *, PVOID);
typedef LONG (WINAPI *FN_IdFromName)(PCWSTR, UINT32, UINT32 *, BYTE *);
typedef LONG (WINAPI *FN_TwoText)(PCWSTR, UINT32 *, PVOID, UINT32 *, PVOID);
typedef LONG (WINAPI *FN_Format)(PCWSTR, PCWSTR, UINT32 *, PVOID);
typedef LONG (WINAPI *FN_Info)(UINT32, UINT32 *, BYTE *, UINT32 *);
typedef LONG (WINAPI *FN_Find)(PCWSTR, UINT32, UINT32 *, PWSTR *, UINT32 *, PWSTR, UINT32 *);
typedef LONG (WINAPI *FN_GetBy)(PCWSTR, UINT32 *, PWSTR *, UINT32 *, PWSTR);
typedef LONG (WINAPI *FN_Open)(PCWSTR, UINT32, PVOID *);
typedef LONG (WINAPI *FN_Close)(PVOID);
typedef LONG (WINAPI *FN_GetInfo)(PVOID, UINT32, UINT32 *, BYTE *, UINT32 *);
typedef LONG (WINAPI *FN_GetApps)(PVOID, UINT32 *, BYTE *, UINT32 *);
typedef LONG (WINAPI *FN_Path)(const PACKAGE_ID *, UINT32, UINT32 *, PWSTR);

static HMODULE hKernel32, hKernelBase;

static FARPROC
GetFunction(const char *Name)
{
    FARPROC Function = GetProcAddress(hKernel32, Name);

    /* The functions that Windows keeps in kernelbase.dll only are in kernel32.dll here */
    if (!Function && hKernelBase)
        Function = GetProcAddress(hKernelBase, Name);

    ok(Function != NULL || !is_reactos(), "%s is not exported\n", Name);
    return Function;
}

#define LOAD(Variable, Type, Name) Type Variable = (Type)GetFunction(Name); if (!Variable) { skip("%s is not available\n", Name); return; }

/* THE PROCESS ****************************************************************/

static void
test_BufferFunction(const char *Name, FN_Buffer Function, LONG Result)
{
    static const UINT32 Lengths[] = { 0, 1, 2, 7, 8, 100, 1000 };
    WCHAR Buffer[200];
    UINT32 Length;
    LONG Ret;
    int i;

    for (i = 0; i < _countof(Lengths); i++)
    {
        RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
        Length = Lengths[i];
        Ret = Function(&Length, Lengths[i] <= 100 ? Buffer : NULL);
        if (Lengths[i] > 100)
        {
            ok(Ret == ERROR_INVALID_PARAMETER, "%s: length %u without a buffer: %ld\n", Name, Lengths[i], Ret);
        }
        else
        {
            ok(Ret == Result, "%s: length %u: %ld, expected %ld\n", Name, Lengths[i], Ret, Result);
            ok(Buffer[0] == 0xcccc, "%s: the buffer was written\n", Name);
        }
        ok(Length == Lengths[i], "%s: the length changed from %u to %u\n", Name, Lengths[i], Length);

        /* No buffer: only for a length of 0 */
        Length = Lengths[i];
        Ret = Function(&Length, NULL);
        ok(Ret == (Lengths[i] == 0 ? Result : ERROR_INVALID_PARAMETER), "%s: length %u, no buffer: %ld\n", Name, Lengths[i], Ret);
    }

    ok(Function(NULL, Buffer) == ERROR_INVALID_PARAMETER, "%s: no length\n", Name);
    ok(Function(NULL, NULL) == ERROR_INVALID_PARAMETER, "%s: no length, no buffer\n", Name);
}

static void
test_ProcessFunction(const char *Name, FN_ProcessBuffer Function, LONG Result)
{
    HANDLE Handles[3], Handle;
    WCHAR Buffer[200];
    UINT32 Length;
    LONG Ret;
    int i;
    static const char *Descriptions[] = { "current process", "query-limited handle", "query handle" };

    Handles[0] = GetCurrentProcess();
    Handles[1] = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    Handles[2] = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    for (i = 0; i < 3; i++)
    {
        if (!Handles[i] && is_reactos() && i == 1)
        {
            skip("The right to query a process a little is not given by the kernel\n");
            continue;
        }
        ok(Handles[i] != NULL, "OpenProcess failed with %lu\n", GetLastError());
        if (!Handles[i])
            continue;

        RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
        Length = 100;
        Ret = Function(Handles[i], &Length, Buffer);
        ok(Ret == Result, "%s, %s: %ld, expected %ld\n", Name, Descriptions[i], Ret, Result);
        ok(Length == 100, "%s, %s: the length changed to %u\n", Name, Descriptions[i], Length);
        ok(Buffer[0] == 0xcccc, "%s, %s: the buffer was written\n", Name, Descriptions[i]);

        Length = 0;
        Ret = Function(Handles[i], &Length, NULL);
        ok(Ret == Result, "%s, %s, no buffer: %ld\n", Name, Descriptions[i], Ret);
    }
    if (Handles[1])
        CloseHandle(Handles[1]);
    if (Handles[2])
        CloseHandle(Handles[2]);

    /* The parameters are checked before the handle */
    Length = 100;
    ok(Function(NULL, &Length, Buffer) == ERROR_INVALID_PARAMETER, "%s: NULL handle\n", Name);
    ok(Function(GetCurrentProcess(), NULL, Buffer) == ERROR_INVALID_PARAMETER, "%s: no length\n", Name);
    ok(Function(GetCurrentProcess(), &Length, NULL) == ERROR_INVALID_PARAMETER, "%s: no buffer\n", Name);
    ok(Function((HANDLE)(ULONG_PTR)0xdeadbee0, NULL, Buffer) == ERROR_INVALID_PARAMETER, "%s: invalid handle, no length\n", Name);
    ok(Function((HANDLE)(ULONG_PTR)0xdeadbee0, &Length, NULL) == ERROR_INVALID_PARAMETER, "%s: invalid handle, no buffer\n", Name);

    /* Then the handle */
    ok(Function((HANDLE)(ULONG_PTR)0xdeadbee0, &Length, Buffer) == ERROR_INVALID_HANDLE, "%s: invalid handle\n", Name);
    ok(Function(GetCurrentThread(), &Length, Buffer) == ERROR_INVALID_HANDLE, "%s: thread handle\n", Name);
    Handle = OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId());
    ok(Handle != NULL, "OpenProcess failed with %lu\n", GetLastError());
    if (Handle)
    {
        ok(Function(Handle, &Length, Buffer) == ERROR_ACCESS_DENIED, "%s: handle without query right\n", Name);
        CloseHandle(Handle);
    }
}

static void
test_TokenFunction(const char *Name, FN_ProcessBuffer Function, LONG Result)
{
    WCHAR Buffer[200];
    UINT32 Length = 100;
    HANDLE Token;

    if (!Function)
        return;

    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token), "OpenProcessToken failed with %lu\n", GetLastError());
    ok(Function(Token, &Length, Buffer) == Result, "%s: process token\n", Name);
    ok(Length == 100, "%s: the length changed to %u\n", Name, Length);
    CloseHandle(Token);
    ok(Function(NULL, &Length, Buffer) == ERROR_INVALID_PARAMETER, "%s: NULL token\n", Name);
    ok(Function(GetCurrentProcess(), &Length, Buffer) == ERROR_INVALID_HANDLE, "%s: process handle\n", Name);
    ok(Function((HANDLE)(LONG_PTR)-4, &Length, Buffer) == Result, "%s: the pseudo handle of the process token\n", Name);
}

static void
test_Process(void)
{
    FN_Info pGetCurrentPackageInfo;
    BYTE Buffer[200];
    UINT32 Length, Count;
    LONG Ret;
    static const UINT32 Flags[] = { 0, 0x10, 0x20, 0x40, 0x80, 0x100, 0x400, 0x110 };
    int i;

    LOAD(pGetCurrentPackageFullName, FN_Buffer, "GetCurrentPackageFullName");
    test_BufferFunction("GetCurrentPackageFullName", pGetCurrentPackageFullName, APPMODEL_ERROR_NO_PACKAGE);
    test_BufferFunction("GetCurrentPackageFamilyName", (FN_Buffer)GetFunction("GetCurrentPackageFamilyName"), APPMODEL_ERROR_NO_PACKAGE);
    test_BufferFunction("GetCurrentPackageId", (FN_Buffer)GetFunction("GetCurrentPackageId"), APPMODEL_ERROR_NO_PACKAGE);
    test_BufferFunction("GetCurrentPackagePath", (FN_Buffer)GetFunction("GetCurrentPackagePath"), APPMODEL_ERROR_NO_PACKAGE);
    test_BufferFunction("GetCurrentApplicationUserModelId", (FN_Buffer)GetFunction("GetCurrentApplicationUserModelId"), APPMODEL_ERROR_NO_APPLICATION);

    test_ProcessFunction("GetPackageFullName", (FN_ProcessBuffer)GetFunction("GetPackageFullName"), APPMODEL_ERROR_NO_PACKAGE);
    test_ProcessFunction("GetPackageFamilyName", (FN_ProcessBuffer)GetFunction("GetPackageFamilyName"), APPMODEL_ERROR_NO_PACKAGE);
    test_ProcessFunction("GetPackageId", (FN_ProcessBuffer)GetFunction("GetPackageId"), APPMODEL_ERROR_NO_PACKAGE);
    test_ProcessFunction("GetApplicationUserModelId", (FN_ProcessBuffer)GetFunction("GetApplicationUserModelId"), APPMODEL_ERROR_NO_APPLICATION);

    test_TokenFunction("GetPackageFullNameFromToken", (FN_ProcessBuffer)GetFunction("GetPackageFullNameFromToken"), APPMODEL_ERROR_NO_PACKAGE);
    test_TokenFunction("GetPackageFamilyNameFromToken", (FN_ProcessBuffer)GetFunction("GetPackageFamilyNameFromToken"), APPMODEL_ERROR_NO_PACKAGE);
    test_TokenFunction("GetApplicationUserModelIdFromToken", (FN_ProcessBuffer)GetFunction("GetApplicationUserModelIdFromToken"), APPMODEL_ERROR_NO_APPLICATION);

    pGetCurrentPackageInfo = (FN_Info)GetFunction("GetCurrentPackageInfo");
    if (!pGetCurrentPackageInfo)
        return;

    /* Nothing is written, whatever the filter says */
    for (i = 0; i < _countof(Flags); i++)
    {
        Length = 100;
        Count = 0x77;
        Ret = pGetCurrentPackageInfo(Flags[i], &Length, Buffer, &Count);
        ok(Ret == APPMODEL_ERROR_NO_PACKAGE, "Flags %x: %ld\n", Flags[i], Ret);
        ok(Length == 100 && Count == 0x77, "Flags %x: length %u, count %u\n", Flags[i], Length, Count);
    }
    Length = 0;
    Count = 0x77;
    ok(pGetCurrentPackageInfo(0x10, &Length, NULL, &Count) == APPMODEL_ERROR_NO_PACKAGE, "No buffer\n");
    ok(pGetCurrentPackageInfo(0x10, NULL, Buffer, &Count) == ERROR_INVALID_PARAMETER, "No length\n");
    Length = 100;
    ok(pGetCurrentPackageInfo(0x10, &Length, Buffer, NULL) == ERROR_INVALID_PARAMETER, "No count\n");
}

/* THE SYNTAX OF NAMES ********************************************************/

static const struct
{
    PCWSTR Name;
    LONG Result;
} FullNames[] =
{
    { L"Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"A_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Ab_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Abc_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxy_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"1abc_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L".abc_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"-abc_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"abc-_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"abc._1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"a..b_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"a..._1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"a b_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"a+b_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"a$b_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"con_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"CON_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"prn_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"aux_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"nul_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"com1_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"COM9_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"lpt1_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"con.x_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"com1.x_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"com0_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"com10_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"conx_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"xcon_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"con-x_1.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_0.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_65535.65535.65535.65535_x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_65536.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_0.0.0.65536_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.2.3.4._x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.-1_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_a.b.c.d_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App__x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_01.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_00001.0.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_000001.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_99999.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1..0.0_x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0._x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_.1.0.0_x64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x86__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_arm__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_arm64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_neutral__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x86a64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_unknown__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_UNKNOWN__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_unknow__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_X64__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_NEUTRAL__8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_ia64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_anycpu__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0___8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_amd64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_arm64ec__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64_en-us_8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x64_EN_8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x64_split.language-de_8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x64_-a_8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x64_a-_8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x64_a._8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64_a b_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_8wekyb3d8bbwe", 0 },
    { L"Contoso.App_1.0.0.0_x64_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__8WEKYB3D8BBWE", 0 },
    { L"Contoso.App_1.0.0.0_x64__0000000000000", 0 },
    { L"Contoso.App_1.0.0.0_x64__zzzzzzzzzzzzz", 0 },
    { L"Contoso.App_1.0.0.0_x64__8wekyb3d8bbw", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__8wekyb3d8bbwee", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__iwekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__lwekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__owekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__uwekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__Iwekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__8wekyb3d8bb-e", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe_x", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L" Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe ", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"", ERROR_INVALID_PARAMETER },
    { L"_____", ERROR_INVALID_PARAMETER },
};

static const struct
{
    PCWSTR Name;
    LONG Result;
} FamilyNames[] =
{
    { L"Contoso.App_8wekyb3d8bbwe", 0 },
    { L"Contoso.App", ERROR_INVALID_PARAMETER },
    { L"Ab_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Abc_8wekyb3d8bbwe", 0 },
    { L"con_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"nul_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"abc._8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"a.b_8wekyb3d8bbwe", 0 },
    { L"Contoso.App_8wekyb3d8bbw", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_8wekyb3d8bbwee", ERROR_INVALID_PARAMETER },
    { L"Contoso_App_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"", ERROR_INVALID_PARAMETER },
};

static const struct
{
    PCWSTR Name;
    LONG Result;
} RelativeIds[] =
{
    { L"App", 0 },
    { L"A", 0 },
    { L"", ERROR_INVALID_PARAMETER },
    { L"A.B", 0 },
    { L"App.", 0 },
    { L".App", 0 },
    { L"A..B", 0 },
    { L".", 0 },
    { L"9app", 0 },
    { L"con", 0 },
    { L"a!b", ERROR_INVALID_PARAMETER },
    { L"App-1", ERROR_INVALID_PARAMETER },
    { L"App_1", ERROR_INVALID_PARAMETER },
    { L"With Space", ERROR_INVALID_PARAMETER },
    { L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0 },
    { L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ERROR_INVALID_PARAMETER },
};

static const struct
{
    PCWSTR Name;
    LONG Result;
} UserModelIds[] =
{
    { L"Contoso.App_8wekyb3d8bbwe!App", 0 },
    { L"Contoso.App_8wekyb3d8bbwe!9", 0 },
    { L"Contoso.App_8wekyb3d8bbwe!", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_8wekyb3d8bbwe", ERROR_INVALID_PARAMETER },
    { L"!App", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_8wekyb3d8bbwe!A!B", ERROR_INVALID_PARAMETER },
    { L"Contoso.App_8wekyb3d8bbw!App", ERROR_INVALID_PARAMETER },
    { L"", ERROR_INVALID_PARAMETER },
};

static void
test_Verify(const char *Name, FN_Verify Function, const void *Table, size_t Count)
{
    const struct { PCWSTR Name; LONG Result; } *Cases = Table;
    size_t i;

    for (i = 0; i < Count; i++)
        ok(Function(Cases[i].Name) == Cases[i].Result, "%s(\"%ls\"): %ld, expected %ld\n", Name, Cases[i].Name, Function(Cases[i].Name), Cases[i].Result);
    ok(Function(NULL) == ERROR_INVALID_PARAMETER, "%s(NULL)\n", Name);
}

static void
test_PackageId(void)
{
    FN_VerifyId pVerifyPackageId = (FN_VerifyId)GetFunction("VerifyPackageId");
    PACKAGE_ID Id;
    int Architecture;
    static const UINT32 Valid[] = { 0, 5, 9, 11, 12, 14, 0xffff };

    if (!pVerifyPackageId)
        return;

    ZeroMemory(&Id, sizeof(Id));
    Id.processorArchitecture = 9;
    Id.version.Version = 0x0001000000000000ULL;
    Id.name = (PWSTR)L"Contoso.App";
    Id.publisherId = (PWSTR)L"8wekyb3d8bbwe";
    ok(pVerifyPackageId(&Id) == 0, "A valid identity\n");

    Id.resourceId = (PWSTR)L"";
    ok(pVerifyPackageId(&Id) == 0, "An empty resource id\n");
    Id.resourceId = (PWSTR)L"en-us";
    ok(pVerifyPackageId(&Id) == 0, "A resource id\n");
    Id.resourceId = (PWSTR)L"a b";
    ok(pVerifyPackageId(&Id) == ERROR_INVALID_PARAMETER, "A bad resource id\n");
    Id.resourceId = NULL;
    Id.publisherId = (PWSTR)L"short";
    ok(pVerifyPackageId(&Id) == ERROR_INVALID_PARAMETER, "A bad publisher id\n");
    Id.publisherId = NULL;
    ok(pVerifyPackageId(&Id) == ERROR_INVALID_PARAMETER, "No publisher id\n");
    Id.publisherId = (PWSTR)L"8wekyb3d8bbwe";
    Id.name = (PWSTR)L"A";
    ok(pVerifyPackageId(&Id) == ERROR_INVALID_PARAMETER, "A short name\n");
    Id.name = NULL;
    ok(pVerifyPackageId(&Id) == ERROR_INVALID_PARAMETER, "No name\n");
    Id.name = (PWSTR)L"Contoso.App";
    Id.reserved = 5;
    Id.publisher = (PWSTR)L"CN=Contoso";
    ok(pVerifyPackageId(&Id) == 0, "The reserved field and the publisher do not matter\n");
    ok(pVerifyPackageId(NULL) == ERROR_INVALID_PARAMETER, "NULL\n");

    for (Architecture = 0; Architecture < 16; Architecture++)
    {
        BOOL Expected = FALSE;
        int i;

        for (i = 0; i < _countof(Valid); i++)
            Expected |= (Valid[i] == (UINT32)Architecture);
        Id.processorArchitecture = Architecture;
        ok(pVerifyPackageId(&Id) == (Expected ? 0 : ERROR_INVALID_PARAMETER), "Architecture %d\n", Architecture);
    }
    Id.processorArchitecture = 0xffff;
    ok(pVerifyPackageId(&Id) == 0, "Architecture 0xffff\n");
    Id.processorArchitecture = 0x10000;
    ok(pVerifyPackageId(&Id) == ERROR_INVALID_PARAMETER, "Architecture 0x10000\n");
}

static void
test_Syntax(void)
{
    LOAD(pVerifyPackageFullName, FN_Verify, "VerifyPackageFullName");
    test_Verify("VerifyPackageFullName", pVerifyPackageFullName, FullNames, _countof(FullNames));
    test_Verify("VerifyPackageFamilyName", (FN_Verify)GetFunction("VerifyPackageFamilyName"), FamilyNames, _countof(FamilyNames));
    test_Verify("VerifyPackageRelativeApplicationId", (FN_Verify)GetFunction("VerifyPackageRelativeApplicationId"), RelativeIds, _countof(RelativeIds));
    test_Verify("VerifyApplicationUserModelId", (FN_Verify)GetFunction("VerifyApplicationUserModelId"), UserModelIds, _countof(UserModelIds));
    test_PackageId();
}

/* THE CONVERSIONS ************************************************************/

static void
test_FamilyNameFromFullName(void)
{
    LOAD(pFromFullName, FN_Text, "PackageFamilyNameFromFullName");
    WCHAR Buffer[100];
    UINT32 Length;
    LONG Ret;
    static const UINT32 Lengths[] = { 0, 10, 41, 42, 43, 100 };
    int i;

    for (i = 0; i < _countof(Lengths); i++)
    {
        wcscpy(Buffer, L"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        Length = Lengths[i];
        Ret = pFromFullName(L"Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe", &Length, Buffer);
        if (Lengths[i] < 42)
        {
            ok(Ret == ERROR_INSUFFICIENT_BUFFER, "Length %u: %ld\n", Lengths[i], Ret);
            ok(Buffer[0] == L'x', "The buffer was written\n");
        }
        else
        {
            ok(Ret == 0, "Length %u: %ld\n", Lengths[i], Ret);
            ok(!wcscmp(Buffer, L"Microsoft.WindowsCalculator_8wekyb3d8bbwe"), "The family name is \"%ls\"\n", Buffer);
        }
        ok(Length == 42, "Length %u: the length is %u\n", Lengths[i], Length);
    }

    /* The other fields do not matter */
    Length = 100;
    ok(pFromFullName(L"Microsoft.WindowsCalculator_11.2.0.0_neutral_split.language-de_8wekyb3d8bbwe", &Length, Buffer) == 0, "A resource package\n");
    ok(!wcscmp(Buffer, L"Microsoft.WindowsCalculator_8wekyb3d8bbwe"), "The family name is \"%ls\"\n", Buffer);
    Length = 100;
    ok(pFromFullName(L"Nope_1.0.0.0_x64__0000000000000", &Length, Buffer) == 0 && !wcscmp(Buffer, L"Nope_0000000000000"), "A short name\n");

    /* An invalid name leaves the length alone */
    Length = 100;
    ok(pFromFullName(L"garbage", &Length, Buffer) == ERROR_INVALID_PARAMETER, "garbage\n");
    ok(Length == 100, "The length changed to %u\n", Length);
    ok(pFromFullName(NULL, &Length, Buffer) == ERROR_INVALID_PARAMETER, "NULL name\n");
    ok(pFromFullName(L"Nope_1.0.0.0_x64__0000000000000", NULL, Buffer) == ERROR_INVALID_PARAMETER, "NULL length\n");
    ok(pFromFullName(L"Nope_1.0.0.0_x64__0000000000000", &Length, NULL) == ERROR_INVALID_PARAMETER, "No buffer\n");
    Length = 0;
    ok(pFromFullName(L"Nope_1.0.0.0_x64__0000000000000", &Length, NULL) == ERROR_INSUFFICIENT_BUFFER && Length == 19, "No buffer, length 0\n");
}

static void
test_IdFromFullName(void)
{
    LOAD(pIdFromFullName, FN_IdFromName, "PackageIdFromFullName");
    BYTE Buffer[400];
    PACKAGE_ID *Id = (PACKAGE_ID *)Buffer;
    UINT32 Length, Expected;
    LONG Ret;
    int i;
    static const struct
    {
        PCWSTR Name;
        UINT32 Architecture;
        UINT64 Version;
        PCWSTR PackageName;
        PCWSTR ResourceId;
        PCWSTR PublisherId;
    } Cases[] =
    {
        { L"Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe", 9, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_x86__8wekyb3d8bbwe", 0, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_arm__8wekyb3d8bbwe", 5, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_arm64__8wekyb3d8bbwe", 12, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_unknown__8wekyb3d8bbwe", 0xffff, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_x86a64__8wekyb3d8bbwe", 14, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_neutral__8wekyb3d8bbwe", 11, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_neutral_split.language-de_8wekyb3d8bbwe", 11, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"split.language-de", L"8wekyb3d8bbwe" },
        { L"Microsoft.WindowsCalculator_11.2.0.0_x64_en-us_8wekyb3d8bbwe", 9, 0x000b000200000000ULL, L"Microsoft.WindowsCalculator", L"en-us", L"8wekyb3d8bbwe" },
        { L"Nope_1.0.0.0_x64__0000000000000", 9, 0x0001000000000000ULL, L"Nope", L"", L"0000000000000" },
        { L"Nope_1.2.3.4_x64__0000000000000", 9, 0x0001000200030004ULL, L"Nope", L"", L"0000000000000" },
        { L"Nope_65535.65535.65535.65535_x64__0000000000000", 9, 0xffffffffffffffffULL, L"Nope", L"", L"0000000000000" },
    };

    for (i = 0; i < _countof(Cases); i++)
    {
        Expected = sizeof(PACKAGE_ID) + (wcslen(Cases[i].PackageName) + 1 + wcslen(Cases[i].ResourceId) + 1 + 14) * sizeof(WCHAR);

        /* The length of the buffer is in bytes, and the buffer holds the structure and its strings */
        Length = 1000;
        RtlFillMemory(Buffer, sizeof(Buffer), 0xcc);
        Ret = pIdFromFullName(Cases[i].Name, 0, &Length, Buffer);
        ok(Ret == 0, "%ls: %ld\n", Cases[i].Name, Ret);
        ok(Length == Expected, "%ls: the length is %u, expected %u\n", Cases[i].Name, Length, Expected);
        if (Ret != 0)
            continue;

        ok(Id->processorArchitecture == Cases[i].Architecture, "%ls: architecture %u\n", Cases[i].Name, Id->processorArchitecture);
        ok(Id->version.Version == Cases[i].Version, "%ls: version %I64x\n", Cases[i].Name, Id->version.Version);
        ok(Id->publisher == NULL, "%ls: publisher %p\n", Cases[i].Name, Id->publisher);
        ok(Id->name && !wcscmp(Id->name, Cases[i].PackageName), "%ls: name \"%ls\"\n", Cases[i].Name, Id->name);
        ok(Id->resourceId && !wcscmp(Id->resourceId, Cases[i].ResourceId), "%ls: resource id \"%ls\"\n", Cases[i].Name, Id->resourceId);
        ok(Id->publisherId && !wcscmp(Id->publisherId, Cases[i].PublisherId), "%ls: publisher id \"%ls\"\n", Cases[i].Name, Id->publisherId);
        ok((BYTE *)Id->name >= Buffer + sizeof(PACKAGE_ID) && (BYTE *)Id->publisherId < Buffer + Expected,
           "%ls: the strings are not in the buffer\n", Cases[i].Name);

        /* One byte less is too little, the exact length is enough, and the flags make no difference */
        Length = Expected - 1;
        ok(pIdFromFullName(Cases[i].Name, 0, &Length, Buffer) == ERROR_INSUFFICIENT_BUFFER && Length == Expected, "%ls: one byte short\n", Cases[i].Name);
        Length = Expected;
        ok(pIdFromFullName(Cases[i].Name, 0x10, &Length, Buffer) == 0, "%ls: the exact length\n", Cases[i].Name);
    }

    Length = 1000;
    ok(pIdFromFullName(L"garbage", 0, &Length, Buffer) == ERROR_INVALID_PARAMETER && Length == 1000, "garbage\n");
    ok(pIdFromFullName(NULL, 0, &Length, Buffer) == ERROR_INVALID_PARAMETER, "NULL name\n");
    ok(pIdFromFullName(L"Nope_1.0.0.0_x64__0000000000000", 0, NULL, Buffer) == ERROR_INVALID_PARAMETER, "NULL length\n");
    ok(pIdFromFullName(L"Nope_1.0.0.0_x64__0000000000000", 0, &Length, NULL) == ERROR_INVALID_PARAMETER, "No buffer\n");
    Length = 0;
    ok(pIdFromFullName(L"Nope_1.0.0.0_x64__0000000000000", 0, &Length, NULL) == ERROR_INSUFFICIENT_BUFFER &&
       Length == sizeof(PACKAGE_ID) + 4 * 2 + 2 + 28 + 2, "No buffer, length 0: %u\n", Length);
}

static void
test_FromId(void)
{
    LOAD(pFullNameFromId, FN_Id, "PackageFullNameFromId");
    LOAD(pFamilyNameFromId, FN_Id, "PackageFamilyNameFromId");
    PACKAGE_ID Id;
    WCHAR Buffer[200];
    UINT32 Length;
    LONG Ret;
    int Architecture;
    static const struct { UINT32 Architecture; PCWSTR Name; } Architectures[] =
    {
        { 0, L"x86" }, { 5, L"arm" }, { 9, L"x64" }, { 11, L"neutral" }, { 12, L"arm64" }, { 14, L"x86a64" }, { 0xffff, L"unknown" },
    };

    ZeroMemory(&Id, sizeof(Id));
    Id.version.Version = 0x0001000200030004ULL;
    Id.name = (PWSTR)L"Contoso.App";
    Id.publisherId = (PWSTR)L"8wekyb3d8bbwe";

    for (Architecture = 0; Architecture < _countof(Architectures); Architecture++)
    {
        WCHAR Expected[100];

        Id.processorArchitecture = Architectures[Architecture].Architecture;
        StringCbPrintfW(Expected, sizeof(Expected), L"Contoso.App_1.2.3.4_%ls__8wekyb3d8bbwe", Architectures[Architecture].Name);
        Length = 200;
        Ret = pFullNameFromId(&Id, &Length, Buffer);
        ok(Ret == 0, "Architecture %u: %ld\n", Id.processorArchitecture, Ret);
        ok(!wcscmp(Buffer, Expected), "Architecture %u: \"%ls\"\n", Id.processorArchitecture, Buffer);
        ok(Length == wcslen(Expected) + 1, "Architecture %u: length %u\n", Id.processorArchitecture, Length);
        Length = (UINT32)wcslen(Expected);
        ok(pFullNameFromId(&Id, &Length, Buffer) == ERROR_INSUFFICIENT_BUFFER && Length == wcslen(Expected) + 1, "Architecture %u: short\n", Id.processorArchitecture);
    }

    Id.processorArchitecture = 9;
    Id.resourceId = (PWSTR)L"de";
    Id.publisher = (PWSTR)L"CN=Contoso";
    Length = 200;
    ok(pFullNameFromId(&Id, &Length, Buffer) == 0 && !wcscmp(Buffer, L"Contoso.App_1.2.3.4_x64_de_8wekyb3d8bbwe"), "A resource id: \"%ls\"\n", Buffer);
    Id.reserved = 7;
    Length = 200;
    ok(pFullNameFromId(&Id, &Length, Buffer) == 0, "The reserved field does not matter\n");

    Id.processorArchitecture = 1;
    Length = 200;
    ok(pFullNameFromId(&Id, &Length, Buffer) == ERROR_INVALID_PARAMETER, "An unknown architecture\n");
    Id.processorArchitecture = 9;
    Id.publisherId = (PWSTR)L"bad";
    ok(pFullNameFromId(&Id, &Length, Buffer) == ERROR_INVALID_PARAMETER, "A bad publisher id\n");
    Id.publisherId = (PWSTR)L"8wekyb3d8bbwe";
    Id.name = (PWSTR)L"A";
    ok(pFullNameFromId(&Id, &Length, Buffer) == ERROR_INVALID_PARAMETER, "A short name\n");
    Id.name = (PWSTR)L"Contoso.App";
    ok(pFullNameFromId(NULL, &Length, Buffer) == ERROR_INVALID_PARAMETER, "NULL identity\n");
    ok(pFullNameFromId(&Id, NULL, Buffer) == ERROR_INVALID_PARAMETER, "NULL length\n");
    ok(pFullNameFromId(&Id, &Length, NULL) == ERROR_INVALID_PARAMETER, "No buffer\n");

    /* The family name takes any architecture and version */
    Id.processorArchitecture = 99;
    Id.version.Version = 0;
    Length = 200;
    ok(pFamilyNameFromId(&Id, &Length, Buffer) == 0 && !wcscmp(Buffer, L"Contoso.App_8wekyb3d8bbwe") && Length == 26, "The family name: \"%ls\"\n", Buffer);
    Length = 10;
    ok(pFamilyNameFromId(&Id, &Length, Buffer) == ERROR_INSUFFICIENT_BUFFER && Length == 26, "A short buffer\n");
    ok(pFamilyNameFromId(NULL, &Length, Buffer) == ERROR_INVALID_PARAMETER, "NULL identity\n");
}

static void
test_NameAndPublisherId(void)
{
    LOAD(pNameAndPublisherId, FN_TwoText, "PackageNameAndPublisherIdFromFamilyName");
    WCHAR Name[100], Publisher[100];
    UINT32 NameLength, PublisherLength;
    LONG Ret;

    NameLength = PublisherLength = 100;
    Ret = pNameAndPublisherId(L"Microsoft.WindowsCalculator_8wekyb3d8bbwe", &NameLength, Name, &PublisherLength, Publisher);
    ok(Ret == 0, "Calculator: %ld\n", Ret);
    ok(NameLength == 28 && PublisherLength == 14, "The lengths are %u and %u\n", NameLength, PublisherLength);
    ok(!wcscmp(Name, L"Microsoft.WindowsCalculator") && !wcscmp(Publisher, L"8wekyb3d8bbwe"), "\"%ls\" \"%ls\"\n", Name, Publisher);

    /* Both lengths are reported when one buffer is too small */
    NameLength = 28;
    PublisherLength = 13;
    ok(pNameAndPublisherId(L"Microsoft.WindowsCalculator_8wekyb3d8bbwe", &NameLength, Name, &PublisherLength, Publisher) == ERROR_INSUFFICIENT_BUFFER, "A short publisher buffer\n");
    ok(NameLength == 28 && PublisherLength == 14, "The lengths are %u and %u\n", NameLength, PublisherLength);
    NameLength = 27;
    PublisherLength = 14;
    ok(pNameAndPublisherId(L"Microsoft.WindowsCalculator_8wekyb3d8bbwe", &NameLength, Name, &PublisherLength, Publisher) == ERROR_INSUFFICIENT_BUFFER, "A short name buffer\n");
    ok(NameLength == 28 && PublisherLength == 14, "The lengths are %u and %u\n", NameLength, PublisherLength);
    NameLength = PublisherLength = 0;
    ok(pNameAndPublisherId(L"Contoso.App_8wekyb3d8bbwe", &NameLength, NULL, &PublisherLength, NULL) == ERROR_INSUFFICIENT_BUFFER, "No buffers\n");
    ok(NameLength == 12 && PublisherLength == 14, "The lengths are %u and %u\n", NameLength, PublisherLength);

    NameLength = PublisherLength = 100;
    ok(pNameAndPublisherId(L"Microsoft.WindowsCalculator", &NameLength, Name, &PublisherLength, Publisher) == ERROR_INVALID_PARAMETER, "No publisher id\n");
    ok(NameLength == 100 && PublisherLength == 100, "The lengths changed\n");
    ok(pNameAndPublisherId(NULL, &NameLength, Name, &PublisherLength, Publisher) == ERROR_INVALID_PARAMETER, "NULL family name\n");
    ok(pNameAndPublisherId(L"Contoso.App_8wekyb3d8bbwe", NULL, Name, &PublisherLength, Publisher) == ERROR_INVALID_PARAMETER, "NULL name length\n");
    ok(pNameAndPublisherId(L"Contoso.App_8wekyb3d8bbwe", &NameLength, Name, NULL, Publisher) == ERROR_INVALID_PARAMETER, "NULL publisher length\n");
    ok(pNameAndPublisherId(L"Contoso.App_8wekyb3d8bbwe", &NameLength, NULL, &PublisherLength, Publisher) == ERROR_INVALID_PARAMETER, "No name buffer\n");
    ok(pNameAndPublisherId(L"Contoso.App_8wekyb3d8bbwe", &NameLength, Name, &PublisherLength, NULL) == ERROR_INVALID_PARAMETER, "No publisher buffer\n");
}

static void
test_UserModelId(void)
{
    LOAD(pParse, FN_TwoText, "ParseApplicationUserModelId");
    LOAD(pFormat, FN_Format, "FormatApplicationUserModelId");
    WCHAR Family[100], Relative[100];
    UINT32 FamilyLength, RelativeLength;
    LONG Ret;

    FamilyLength = RelativeLength = 100;
    Ret = pParse(L"Contoso.App_8wekyb3d8bbwe!App", &FamilyLength, Family, &RelativeLength, Relative);
    ok(Ret == 0, "Parse: %ld\n", Ret);
    ok(FamilyLength == 26 && RelativeLength == 4, "The lengths are %u and %u\n", FamilyLength, RelativeLength);
    ok(!wcscmp(Family, L"Contoso.App_8wekyb3d8bbwe") && !wcscmp(Relative, L"App"), "\"%ls\" \"%ls\"\n", Family, Relative);

    FamilyLength = 26;
    RelativeLength = 3;
    ok(pParse(L"Contoso.App_8wekyb3d8bbwe!App", &FamilyLength, Family, &RelativeLength, Relative) == ERROR_INSUFFICIENT_BUFFER, "A short relative id buffer\n");
    ok(FamilyLength == 26 && RelativeLength == 4, "The lengths are %u and %u\n", FamilyLength, RelativeLength);
    FamilyLength = 25;
    RelativeLength = 4;
    ok(pParse(L"Contoso.App_8wekyb3d8bbwe!App", &FamilyLength, Family, &RelativeLength, Relative) == ERROR_INSUFFICIENT_BUFFER, "A short family buffer\n");
    FamilyLength = RelativeLength = 100;
    ok(pParse(L"Contoso.App_8wekyb3d8bbwe", &FamilyLength, Family, &RelativeLength, Relative) == ERROR_INVALID_PARAMETER, "No relative id\n");
    ok(FamilyLength == 100 && RelativeLength == 100, "The lengths changed\n");
    ok(pParse(NULL, &FamilyLength, Family, &RelativeLength, Relative) == ERROR_INVALID_PARAMETER, "NULL\n");
    ok(pParse(L"Contoso.App_8wekyb3d8bbwe!App", NULL, Family, &RelativeLength, Relative) == ERROR_INVALID_PARAMETER, "NULL family length\n");
    ok(pParse(L"Contoso.App_8wekyb3d8bbwe!App", &FamilyLength, Family, NULL, Relative) == ERROR_INVALID_PARAMETER, "NULL relative length\n");
    ok(pParse(L"Contoso.App_8wekyb3d8bbwe!App", &FamilyLength, NULL, &RelativeLength, Relative) == ERROR_INVALID_PARAMETER, "No family buffer\n");
    ok(pParse(L"Contoso.App_8wekyb3d8bbwe!App", &FamilyLength, Family, &RelativeLength, NULL) == ERROR_INVALID_PARAMETER, "No relative buffer\n");

    FamilyLength = 100;
    Ret = pFormat(L"Contoso.App_8wekyb3d8bbwe", L"App", &FamilyLength, Family);
    ok(Ret == 0 && FamilyLength == 30 && !wcscmp(Family, L"Contoso.App_8wekyb3d8bbwe!App"), "Format: %ld, \"%ls\", %u\n", Ret, Family, FamilyLength);
    FamilyLength = 29;
    ok(pFormat(L"Contoso.App_8wekyb3d8bbwe", L"App", &FamilyLength, Family) == ERROR_INSUFFICIENT_BUFFER && FamilyLength == 30, "A short buffer\n");
    FamilyLength = 0;
    ok(pFormat(L"Contoso.App_8wekyb3d8bbwe", L"App", &FamilyLength, NULL) == ERROR_INSUFFICIENT_BUFFER && FamilyLength == 30, "No buffer, length 0\n");
    FamilyLength = 100;
    ok(pFormat(L"Contoso.App_8wekyb3d8bbwe", L"a!b", &FamilyLength, Family) == ERROR_INVALID_PARAMETER, "A bad relative id\n");
    ok(pFormat(L"Contoso.App_8wekyb3d8bbwe", L"", &FamilyLength, Family) == ERROR_INVALID_PARAMETER, "An empty relative id\n");
    ok(pFormat(L"bad", L"App", &FamilyLength, Family) == ERROR_INVALID_PARAMETER, "A bad family name\n");
    ok(pFormat(NULL, L"App", &FamilyLength, Family) == ERROR_INVALID_PARAMETER, "NULL family name\n");
    ok(pFormat(L"Contoso.App_8wekyb3d8bbwe", NULL, &FamilyLength, Family) == ERROR_INVALID_PARAMETER, "NULL relative id\n");
    ok(pFormat(L"Contoso.App_8wekyb3d8bbwe", L"App", NULL, Family) == ERROR_INVALID_PARAMETER, "NULL length\n");
    ok(pFormat(L"Contoso.App_8wekyb3d8bbwe", L"App", &FamilyLength, NULL) == ERROR_INVALID_PARAMETER, "No buffer\n");
}

/* THE PACKAGES ON THE SYSTEM *************************************************/

static void
test_Packages(void)
{
    FN_Text pPathByFullName = (FN_Text)GetFunction("GetPackagePathByFullName");
    FN_Open pOpen = (FN_Open)GetFunction("OpenPackageInfoByFullName");
    FN_Close pClose = (FN_Close)GetFunction("ClosePackageInfo");
    FN_GetInfo pGetInfo = (FN_GetInfo)GetFunction("GetPackageInfo");
    FN_GetApps pGetApps = (FN_GetApps)GetFunction("GetPackageApplicationIds");
    FN_Find pFind = (FN_Find)GetFunction("FindPackagesByPackageFamily");
    FN_GetBy pGetBy = (FN_GetBy)GetFunction("GetPackagesByPackageFamily");
    FN_Path pPath = (FN_Path)GetFunction("GetPackagePath");
    static const UINT32 Filters[] = { 1, 0x10, 0x20, 0x30, 0x40, 0x80, 0xf0, 0x100, 0xffffffff };
    WCHAR Buffer[200];
    PWSTR Names[4];
    PVOID Info = (PVOID)0x1234;
    PACKAGE_ID Id;
    UINT32 Length, Count, BufferLength;
    BYTE Bytes[100];
    int i;

    /* No package is installed: a package that has a well-formed name is not found */
    if (pPathByFullName)
    {
        Length = 200;
        ok(pPathByFullName(L"Nope_1.0.0.0_x64__0000000000000", &Length, Buffer) == ERROR_NOT_FOUND, "GetPackagePathByFullName\n");
        ok(Length == 200, "The length changed to %u\n", Length);
        Length = 0;
        ok(pPathByFullName(L"Nope_1.0.0.0_x64__0000000000000", &Length, NULL) == ERROR_NOT_FOUND, "GetPackagePathByFullName, no buffer\n");
        Length = 200;
        ok(pPathByFullName(L"garbage", &Length, Buffer) == ERROR_INVALID_PARAMETER, "garbage\n");
        ok(pPathByFullName(NULL, &Length, Buffer) == ERROR_INVALID_PARAMETER, "NULL name\n");
        ok(pPathByFullName(L"Nope_1.0.0.0_x64__0000000000000", NULL, Buffer) == ERROR_INVALID_PARAMETER, "NULL length\n");
        ok(pPathByFullName(L"Nope_1.0.0.0_x64__0000000000000", &Length, NULL) == ERROR_INVALID_PARAMETER, "No buffer\n");
    }
    if (pOpen)
    {
        for (i = 0; i < 5; i++)
        {
            static const UINT32 Reserved[] = { 0, 1, 2, 0x10, 0xffffffff };

            ok(pOpen(L"Nope_1.0.0.0_x64__0000000000000", Reserved[i], &Info) == ERROR_NOT_FOUND, "OpenPackageInfoByFullName, %x\n", Reserved[i]);
        }
        ok(Info == (PVOID)0x1234, "The reference was written\n");
        ok(pOpen(L"garbage", 0, &Info) == ERROR_INVALID_PARAMETER, "garbage\n");
        ok(pOpen(NULL, 0, &Info) == ERROR_INVALID_PARAMETER, "NULL name\n");
        ok(pOpen(L"Nope_1.0.0.0_x64__0000000000000", 0, NULL) == ERROR_INVALID_PARAMETER, "No reference\n");
    }
    if (pClose)
        ok(pClose(NULL) == ERROR_INVALID_PARAMETER, "ClosePackageInfo(NULL)\n");
    if (pGetInfo)
    {
        Length = 100;
        Count = 5;
        ok(pGetInfo(NULL, 0x10, &Length, Bytes, &Count) == ERROR_INVALID_PARAMETER, "GetPackageInfo(NULL)\n");
    }
    /* msedge.dll imports GetPackageApplicationIds: it must exist (no package reference is valid here) */
    ok(pGetApps != NULL, "kernel32 does not export GetPackageApplicationIds\n");
    if (pGetApps)
    {
        Length = 100;
        Count = 5;
        ok(pGetApps(NULL, &Length, Bytes, &Count) == ERROR_INVALID_PARAMETER, "GetPackageApplicationIds(NULL)\n");
    }
    if (pPath)
    {
        ZeroMemory(&Id, sizeof(Id));
        Id.processorArchitecture = 9;
        Id.version.Version = 0x0001000000000000ULL;
        Id.name = (PWSTR)L"Nope";
        Id.publisherId = (PWSTR)L"0000000000000";
        Length = 200;
        ok(pPath(&Id, 0, &Length, Buffer) == ERROR_NOT_FOUND, "GetPackagePath\n");
        ok(pPath(NULL, 0, &Length, Buffer) == ERROR_INVALID_PARAMETER, "GetPackagePath(NULL)\n");
    }

    /* Families: no package of any family */
    if (pFind)
    {
        Count = BufferLength = 0;
        ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", 0x10, &Count, NULL, &BufferLength, NULL, NULL) == 0 && Count == 0 && BufferLength == 0, "FindPackagesByPackageFamily\n");
        for (i = 0; i < _countof(Filters); i++)
        {
            Count = BufferLength = 0;
            ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", Filters[i], &Count, NULL, &BufferLength, NULL, NULL) == 0, "FindPackagesByPackageFamily, filter %x\n", Filters[i]);
        }
        Count = BufferLength = 0;
        ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", 0, &Count, NULL, &BufferLength, NULL, NULL) == ERROR_INVALID_PARAMETER, "No filter\n");
        ok(pFind(L"garbage", 0x10, &Count, NULL, &BufferLength, NULL, NULL) == ERROR_INVALID_PARAMETER, "garbage\n");
        ok(pFind(L"", 0x10, &Count, NULL, &BufferLength, NULL, NULL) == ERROR_FILE_NOT_FOUND, "An empty family\n");
        ok(pFind(NULL, 0x10, &Count, NULL, &BufferLength, NULL, NULL) == ERROR_INVALID_PARAMETER, "NULL family\n");
        ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", 0x10, NULL, NULL, &BufferLength, NULL, NULL) == ERROR_INVALID_PARAMETER, "NULL count\n");
        ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", 0x10, &Count, NULL, NULL, NULL, NULL) == ERROR_INVALID_PARAMETER, "NULL buffer length\n");
        Count = 3;
        BufferLength = 0;
        ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", 0x10, &Count, NULL, &BufferLength, NULL, NULL) == ERROR_INVALID_PARAMETER, "A count and no names\n");
        Count = 0;
        BufferLength = 5;
        ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", 0x10, &Count, NULL, &BufferLength, NULL, NULL) == ERROR_INVALID_PARAMETER, "A buffer length and no buffer\n");
        Count = 3;
        BufferLength = 100;
        ok(pFind(L"Nope.Nope_8wekyb3d8bbwe", 0x10, &Count, Names, &BufferLength, Buffer, NULL) == 0 && Count == 0 && BufferLength == 0, "With buffers\n");
    }
    if (pGetBy)
    {
        Count = BufferLength = 0;
        ok(pGetBy(L"Nope.Nope_8wekyb3d8bbwe", &Count, NULL, &BufferLength, NULL) == 0 && Count == 0 && BufferLength == 0, "GetPackagesByPackageFamily\n");
        ok(pGetBy(L"garbage", &Count, NULL, &BufferLength, NULL) == ERROR_INVALID_PARAMETER, "garbage\n");
        ok(pGetBy(L"", &Count, NULL, &BufferLength, NULL) == ERROR_FILE_NOT_FOUND, "An empty family\n");
        ok(pGetBy(NULL, &Count, NULL, &BufferLength, NULL) == ERROR_INVALID_PARAMETER, "NULL family\n");
        ok(pGetBy(L"Nope.Nope_8wekyb3d8bbwe", NULL, NULL, &BufferLength, NULL) == ERROR_INVALID_PARAMETER, "NULL count\n");
        ok(pGetBy(L"Nope.Nope_8wekyb3d8bbwe", &Count, NULL, NULL, NULL) == ERROR_INVALID_PARAMETER, "NULL buffer length\n");
        Count = 3;
        BufferLength = 0;
        ok(pGetBy(L"Nope.Nope_8wekyb3d8bbwe", &Count, NULL, &BufferLength, NULL) == ERROR_INVALID_PARAMETER, "A count and no names\n");
        Count = 3;
        BufferLength = 100;
        ok(pGetBy(L"Nope.Nope_8wekyb3d8bbwe", &Count, Names, &BufferLength, Buffer) == 0 && Count == 0 && BufferLength == 0, "With buffers\n");
    }
}

START_TEST(AppModel)
{
    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    hKernelBase = GetModuleHandleW(L"kernelbase.dll");

    test_Process();
    test_Syntax();
    test_FamilyNameFromFullName();
    test_IdFromFullName();
    test_FromId();
    test_NameAndPublisherId();
    test_UserModelId();
    test_Packages();
}
