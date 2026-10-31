/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the kernelbase.dll exports that forward to kernel32.dll and ntdll.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows' kernelbase.dll exports names that live in kernel32.dll or ntdll.dll here. Programs that bind them
 * through kernelbase.dll (or an api-ms-win-core-* contract that maps there) must get the very function the
 * target DLL exports. Also covers the names that were hidden below export level 0x602 and are now exported.
 */

#include "precomp.h"
#include <locale.h>
#include <malloc.h>

typedef struct _FWD
{
    PCSTR Name;
    PCWSTR Dll;
    PCSTR Target;
} FWD;

static const FWD Forwarders[] =
{
    {"AddSIDToBoundaryDescriptor", L"kernel32.dll", "AddSIDToBoundaryDescriptor"},
    {"ClosePackageInfo", L"kernel32.dll", "ClosePackageInfo"},
    {"ClosePrivateNamespace", L"kernel32.dll", "ClosePrivateNamespace"},
    {"CopyContext", L"kernel32.dll", "CopyContext"},
    {"CreatePrivateNamespaceW", L"kernel32.dll", "CreatePrivateNamespaceW"},
    {"DeleteBoundaryDescriptor", L"kernel32.dll", "DeleteBoundaryDescriptor"},
    {"DisassociateCurrentThreadFromCallback", L"ntdll.dll", "TpDisassociateCallback"},
    {"EventEnabled", L"ntdll.dll", "EtwEventEnabled"},
    {"EventProviderEnabled", L"ntdll.dll", "EtwEventProviderEnabled"},
    {"EventRegister", L"ntdll.dll", "EtwEventRegister"},
    {"EventSetInformation", L"ntdll.dll", "EtwEventSetInformation"},
    {"EventUnregister", L"ntdll.dll", "EtwEventUnregister"},
    {"EventWrite", L"ntdll.dll", "EtwEventWrite"},
    {"EventWriteString", L"ntdll.dll", "EtwEventWriteString"},
    {"EventWriteTransfer", L"ntdll.dll", "EtwEventWriteTransfer"},
    {"FindNLSStringEx", L"kernel32.dll", "FindNLSStringEx"},
    {"FindPackagesByPackageFamily", L"kernel32.dll", "FindPackagesByPackageFamily"},
    {"FlushProcessWriteBuffers", L"ntdll.dll", "NtFlushProcessWriteBuffers"},
    {"FormatApplicationUserModelId", L"kernel32.dll", "FormatApplicationUserModelId"},
    {"FreeLibraryWhenCallbackReturns", L"ntdll.dll", "TpCallbackUnloadDllOnCompletion"},
    {"GetApplicationRecoveryCallback", L"kernel32.dll", "GetApplicationRecoveryCallback"},
    {"GetApplicationUserModelId", L"kernel32.dll", "GetApplicationUserModelId"},
    {"GetApplicationUserModelIdFromToken", L"kernel32.dll", "GetApplicationUserModelIdFromToken"},
    {"GetConsoleAliasExesA", L"kernel32.dll", "GetConsoleAliasExesA"},
    {"GetConsoleAliasExesW", L"kernel32.dll", "GetConsoleAliasExesW"},
    {"GetConsoleAliasesA", L"kernel32.dll", "GetConsoleAliasesA"},
    {"GetConsoleAliasesW", L"kernel32.dll", "GetConsoleAliasesW"},
    {"GetConsoleHistoryInfo", L"kernel32.dll", "GetConsoleHistoryInfo"},
    {"GetConsoleSelectionInfo", L"kernel32.dll", "GetConsoleSelectionInfo"},
    {"GetCurrentApplicationUserModelId", L"kernel32.dll", "GetCurrentApplicationUserModelId"},
    {"GetEnabledXStateFeatures", L"kernel32.dll", "GetEnabledXStateFeatures"},
    {"GetPackageFamilyNameFromToken", L"kernel32.dll", "GetPackageFamilyNameFromToken"},
    {"GetPackageFullNameFromToken", L"kernel32.dll", "GetPackageFullNameFromToken"},
    {"GetPackageId", L"kernel32.dll", "GetPackageId"},
    {"GetPackageInfo", L"kernel32.dll", "GetPackageInfo"},
    {"GetPackagePath", L"kernel32.dll", "GetPackagePath"},
    {"GetThreadIdealProcessorEx", L"kernel32.dll", "GetThreadIdealProcessorEx"},
    {"GetThreadInformation", L"kernel32.dll", "GetThreadInformation"},
    {"GetTraceEnableFlags", L"ntdll.dll", "EtwGetTraceEnableFlags"},
    {"GetTraceEnableLevel", L"ntdll.dll", "EtwGetTraceEnableLevel"},
    {"GetTraceLoggerHandle", L"ntdll.dll", "EtwGetTraceLoggerHandle"},
    {"GetXStateFeaturesMask", L"kernel32.dll", "GetXStateFeaturesMask"},
    {"IdnToAscii", L"kernel32.dll", "IdnToAscii"},
    {"IdnToNameprepUnicode", L"kernel32.dll", "IdnToNameprepUnicode"},
    {"IdnToUnicode", L"kernel32.dll", "IdnToUnicode"},
    {"InitializeContext", L"kernel32.dll", "InitializeContext"},
    {"InitializeContext2", L"kernel32.dll", "InitializeContext2"},
    {"InterlockedPushListSListEx", L"ntdll.dll", "RtlInterlockedPushListSListEx"},
    {"IsTimeZoneRedirectionEnabled", L"kernel32.dll", "IsTimeZoneRedirectionEnabled"},
    {"LeaveCriticalSectionWhenCallbackReturns", L"ntdll.dll", "TpCallbackLeaveCriticalSectionOnCompletion"},
    {"LocateXStateFeature", L"kernel32.dll", "LocateXStateFeature"},
    {"OpenPackageInfoByFullName", L"kernel32.dll", "OpenPackageInfoByFullName"},
    {"OpenPrivateNamespaceW", L"kernel32.dll", "OpenPrivateNamespaceW"},
    {"PackageFamilyNameFromFullName", L"kernel32.dll", "PackageFamilyNameFromFullName"},
    {"PackageFamilyNameFromId", L"kernel32.dll", "PackageFamilyNameFromId"},
    {"PackageFullNameFromId", L"kernel32.dll", "PackageFullNameFromId"},
    {"PackageNameAndPublisherIdFromFamilyName", L"kernel32.dll", "PackageNameAndPublisherIdFromFamilyName"},
    {"ParseApplicationUserModelId", L"kernel32.dll", "ParseApplicationUserModelId"},
    {"RegisterApplicationRestart", L"kernel32.dll", "RegisterApplicationRestart"},
    {"RegisterTraceGuidsW", L"ntdll.dll", "EtwRegisterTraceGuidsW"},
    {"ReleaseMutexWhenCallbackReturns", L"ntdll.dll", "TpCallbackReleaseMutexOnCompletion"},
    {"ReleaseSemaphoreWhenCallbackReturns", L"ntdll.dll", "TpCallbackReleaseSemaphoreOnCompletion"},
    {"ResolveDelayLoadedAPI", L"kernel32.dll", "ResolveDelayLoadedAPI"},
    {"SetClientTimeZoneInformation", L"kernel32.dll", "SetClientTimeZoneInformation"},
    {"SetConsoleHistoryInfo", L"kernel32.dll", "SetConsoleHistoryInfo"},
    {"SetConsoleNumberOfCommandsA", L"kernel32.dll", "SetConsoleNumberOfCommandsA"},
    {"SetConsoleNumberOfCommandsW", L"kernel32.dll", "SetConsoleNumberOfCommandsW"},
    {"SetEventWhenCallbackReturns", L"ntdll.dll", "TpCallbackSetEventOnCompletion"},
    {"SetThreadIdealProcessorEx", L"kernel32.dll", "SetThreadIdealProcessorEx"},
    {"SetXStateFeaturesMask", L"kernel32.dll", "SetXStateFeaturesMask"},
    {"TraceMessage", L"ntdll.dll", "EtwTraceMessage"},
    {"UnregisterApplicationRestart", L"kernel32.dll", "UnregisterApplicationRestart"},
    {"UnregisterTraceGuids", L"ntdll.dll", "EtwUnregisterTraceGuids"},
    {"VerifyApplicationUserModelId", L"kernel32.dll", "VerifyApplicationUserModelId"},
    {"VerifyPackageFamilyName", L"kernel32.dll", "VerifyPackageFamilyName"},
    {"VerifyPackageFullName", L"kernel32.dll", "VerifyPackageFullName"},
    {"VerifyPackageId", L"kernel32.dll", "VerifyPackageId"},
    {"VerifyPackageRelativeApplicationId", L"kernel32.dll", "VerifyPackageRelativeApplicationId"},
    {"WerRegisterFile", L"kernel32.dll", "WerRegisterFile"},
    {"WerRegisterMemoryBlock", L"kernel32.dll", "WerRegisterMemoryBlock"},
    {"WerUnregisterFile", L"kernel32.dll", "WerUnregisterFile"},
    {"WerUnregisterMemoryBlock", L"kernel32.dll", "WerUnregisterMemoryBlock"},
#ifdef _WIN64
    {"__C_specific_handler", L"ntdll.dll", "__C_specific_handler"},
#endif
#ifdef _WIN64
    {"__chkstk", L"ntdll.dll", "__chkstk"},
#endif
#ifdef _WIN64
    {"_local_unwind", L"ntdll.dll", "_local_unwind"},
#endif
};

static void
test_Forwarders(void)
{
    HMODULE Kernelbase = LoadLibraryW(L"kernelbase.dll");
    ULONG i, Checked = 0;

    if (!Kernelbase)
    {
        skip("kernelbase.dll does not load, error %lu\n", GetLastError());
        return;
    }

    for (i = 0; i < RTL_NUMBER_OF(Forwarders); i++)
    {
        HMODULE Module = LoadLibraryW(Forwarders[i].Dll);
        FARPROC Target = Module ? GetProcAddress(Module, Forwarders[i].Target) : NULL;
        FARPROC Proc;

        if (!Target)
        {
            /* the target is not exported at this export level */
            continue;
        }
        Checked++;
        Proc = GetProcAddress(Kernelbase, Forwarders[i].Name);
        ok(Proc != NULL, "kernelbase!%s is not exported (target %ls!%s)\n",
           Forwarders[i].Name, Forwarders[i].Dll, Forwarders[i].Target);
        ok(Proc == Target, "kernelbase!%s = %p, %ls!%s = %p\n",
           Forwarders[i].Name, Proc, Forwarders[i].Dll, Forwarders[i].Target, Target);
    }
    trace("%lu forwarders checked\n", Checked);
}

static void
test_Calls(void)
{
    HMODULE Kernelbase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    typedef HANDLE (WINAPI *PFN_CreatePrivateNamespaceW)(LPSECURITY_ATTRIBUTES, LPVOID, LPCWSTR);
    typedef HANDLE (WINAPI *PFN_OpenPrivateNamespaceW)(LPVOID, LPCWSTR);
    typedef BOOLEAN (WINAPI *PFN_ClosePrivateNamespace)(HANDLE, ULONG);
    typedef VOID (WINAPI *PFN_DeleteBoundaryDescriptor)(HANDLE);
    typedef BOOL (WINAPI *PFN_AddSIDToBoundaryDescriptor)(HANDLE *, PSID);
    typedef HANDLE (WINAPI *PFN_CreateBoundaryDescriptorW)(LPCWSTR, ULONG);
    typedef ULONG (WINAPI *PFN_EventRegister)(const GUID *, PVOID, PVOID, PULONGLONG);
    typedef ULONG (WINAPI *PFN_EventUnregister)(ULONGLONG);
    typedef LONG (WINAPI *PFN_GetCurrentApplicationUserModelId)(PUINT32, PWSTR);
    typedef BOOL (WINAPI *PFN_GetThreadIdealProcessorEx)(HANDLE, PPROCESSOR_NUMBER);
    typedef VOID (WINAPI *PFN_FlushProcessWriteBuffers)(VOID);
    typedef PSLIST_ENTRY (WINAPI *PFN_InterlockedPushListSListEx)(PSLIST_HEADER, PSLIST_ENTRY, PSLIST_ENTRY, ULONG);
    typedef int (WINAPI *PFN_FindNLSStringEx)(LPCWSTR, DWORD, LPCWSTR, int, LPCWSTR, int, LPINT, LPVOID, LPVOID, LPARAM);

    PFN_CreateBoundaryDescriptorW pCreateBoundaryDescriptorW;
    PFN_AddSIDToBoundaryDescriptor pAddSIDToBoundaryDescriptor;
    PFN_CreatePrivateNamespaceW pCreatePrivateNamespaceW;
    PFN_OpenPrivateNamespaceW pOpenPrivateNamespaceW;
    PFN_ClosePrivateNamespace pClosePrivateNamespace;
    PFN_DeleteBoundaryDescriptor pDeleteBoundaryDescriptor;
    PFN_EventRegister pEventRegister;
    PFN_EventUnregister pEventUnregister;
    PFN_GetCurrentApplicationUserModelId pGetCurrentApplicationUserModelId, pK32GetCurrentApplicationUserModelId;
    PFN_GetThreadIdealProcessorEx pGetThreadIdealProcessorEx;
    PFN_FlushProcessWriteBuffers pFlushProcessWriteBuffers;
    PFN_InterlockedPushListSListEx pInterlockedPushListSListEx;
    PFN_FindNLSStringEx pFindNLSStringEx;

    if (!Kernelbase)
    {
        skip("kernelbase.dll is not loaded\n");
        return;
    }

    pCreateBoundaryDescriptorW = (PVOID)GetProcAddress(Kernel32, "CreateBoundaryDescriptorW");
    pAddSIDToBoundaryDescriptor = (PVOID)GetProcAddress(Kernelbase, "AddSIDToBoundaryDescriptor");
    pCreatePrivateNamespaceW = (PVOID)GetProcAddress(Kernelbase, "CreatePrivateNamespaceW");
    pOpenPrivateNamespaceW = (PVOID)GetProcAddress(Kernelbase, "OpenPrivateNamespaceW");
    pClosePrivateNamespace = (PVOID)GetProcAddress(Kernelbase, "ClosePrivateNamespace");
    pDeleteBoundaryDescriptor = (PVOID)GetProcAddress(Kernelbase, "DeleteBoundaryDescriptor");
    if (pCreateBoundaryDescriptorW && pAddSIDToBoundaryDescriptor && pCreatePrivateNamespaceW &&
        pOpenPrivateNamespaceW && pClosePrivateNamespace && pDeleteBoundaryDescriptor)
    {
        /* S-1-1-0, Everyone */
        BYTE SidBuffer[] = {1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0};
        HANDLE Boundary, Namespace, Opened;

        Boundary = pCreateBoundaryDescriptorW(L"KbFwdBoundary", 0);
        ok(Boundary != NULL, "CreateBoundaryDescriptorW failed, error %lu\n", GetLastError());
        ok(pAddSIDToBoundaryDescriptor(&Boundary, SidBuffer), "AddSIDToBoundaryDescriptor failed, error %lu\n", GetLastError());
        Namespace = pCreatePrivateNamespaceW(NULL, Boundary, L"KbFwdNamespace");
        ok(Namespace != NULL, "CreatePrivateNamespaceW failed, error %lu\n", GetLastError());
        Opened = pOpenPrivateNamespaceW(Boundary, L"KbFwdNamespace");
        ok(Opened != NULL, "OpenPrivateNamespaceW failed, error %lu\n", GetLastError());
        if (Opened)
            pClosePrivateNamespace(Opened, 0);
        if (Namespace)
            ok(pClosePrivateNamespace(Namespace, 0), "ClosePrivateNamespace failed, error %lu\n", GetLastError());
        pDeleteBoundaryDescriptor(Boundary);
    }
    else
    {
        skip("private namespace functions are not available\n");
    }

    pEventRegister = (PVOID)GetProcAddress(Kernelbase, "EventRegister");
    pEventUnregister = (PVOID)GetProcAddress(Kernelbase, "EventUnregister");
    if (pEventRegister && pEventUnregister)
    {
        static const GUID Provider = {0x6a5d1e3b, 0x1c3e, 0x4f61, {0x9a, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
        ULONGLONG Handle = 0;
        ULONG Status = pEventRegister(&Provider, NULL, NULL, &Handle);

        ok(Status == ERROR_SUCCESS, "EventRegister returned %lu\n", Status);
        ok(Handle != 0, "no registration handle\n");
        Status = pEventUnregister(Handle);
        ok(Status == ERROR_SUCCESS, "EventUnregister returned %lu\n", Status);
    }

    pGetCurrentApplicationUserModelId = (PVOID)GetProcAddress(Kernelbase, "GetCurrentApplicationUserModelId");
    pK32GetCurrentApplicationUserModelId = (PVOID)GetProcAddress(Kernel32, "GetCurrentApplicationUserModelId");
    if (pGetCurrentApplicationUserModelId && pK32GetCurrentApplicationUserModelId)
    {
        WCHAR Buffer[256];
        UINT32 Length = RTL_NUMBER_OF(Buffer);
        LONG Result1, Result2;

        Result1 = pGetCurrentApplicationUserModelId(&Length, Buffer);
        Length = RTL_NUMBER_OF(Buffer);
        Result2 = pK32GetCurrentApplicationUserModelId(&Length, Buffer);
        ok(Result1 == Result2, "kernelbase %ld, kernel32 %ld\n", Result1, Result2);
        ok(Result1 == 15703 /* APPMODEL_ERROR_NO_APPLICATION */, "got %ld for an unpackaged process\n", Result1);
    }

    pGetThreadIdealProcessorEx = (PVOID)GetProcAddress(Kernelbase, "GetThreadIdealProcessorEx");
    if (pGetThreadIdealProcessorEx)
    {
        PROCESSOR_NUMBER Number = {0xff, 0xff, 0xff};

        ok(pGetThreadIdealProcessorEx(GetCurrentThread(), &Number), "GetThreadIdealProcessorEx failed, error %lu\n", GetLastError());
        ok(Number.Reserved == 0, "Reserved %u\n", Number.Reserved);
    }

    pFlushProcessWriteBuffers = (PVOID)GetProcAddress(Kernelbase, "FlushProcessWriteBuffers");
    if (pFlushProcessWriteBuffers)
        pFlushProcessWriteBuffers();

    pInterlockedPushListSListEx = (PVOID)GetProcAddress(Kernelbase, "InterlockedPushListSListEx");
    if (pInterlockedPushListSListEx)
    {
        PSLIST_HEADER Head = _aligned_malloc(sizeof(*Head), MEMORY_ALLOCATION_ALIGNMENT);
        PSLIST_ENTRY E1 = _aligned_malloc(sizeof(*E1), MEMORY_ALLOCATION_ALIGNMENT);
        PSLIST_ENTRY E2 = _aligned_malloc(sizeof(*E2), MEMORY_ALLOCATION_ALIGNMENT);
        PSLIST_ENTRY E3 = _aligned_malloc(sizeof(*E3), MEMORY_ALLOCATION_ALIGNMENT);

        InitializeSListHead(Head);
        E1->Next = E2;
        E2->Next = NULL;
        ok(pInterlockedPushListSListEx(Head, E1, E2, 2) == NULL, "first push returned a previous head\n");
        ok(QueryDepthSList(Head) == 2, "depth %u\n", QueryDepthSList(Head));
        E3->Next = NULL;
        ok(pInterlockedPushListSListEx(Head, E3, E3, 1) == E1, "second push did not return the old head\n");
        ok(InterlockedPopEntrySList(Head) == E3, "wrong entry popped\n");
        _aligned_free(Head);
        _aligned_free(E1);
        _aligned_free(E2);
        _aligned_free(E3);
    }

    pFindNLSStringEx = (PVOID)GetProcAddress(Kernelbase, "FindNLSStringEx");
    if (pFindNLSStringEx)
    {
        int Found, Length = 0;

        Found = pFindNLSStringEx(L"en-US", FIND_FROMSTART | NORM_IGNORECASE, L"hello world", -1, L"WORLD", -1, &Length, NULL, NULL, 0);
        ok(Found == 6 && Length == 5, "found %d length %d\n", Found, Length);
    }
}

/* names that were hidden below export level 0x602 although they are implemented */
static void
test_ExportLevel(void)
{
    HMODULE Kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE Msvcrt = LoadLibraryW(L"msvcrt.dll");
    typedef DWORD (WINAPI *PFN_GetFirmwareVariableExW)(LPCWSTR, LPCWSTR, PVOID, DWORD, PDWORD);
    typedef DWORD (WINAPI *PFN_GetFirmwareVariableExA)(LPCSTR, LPCSTR, PVOID, DWORD, PDWORD);
    typedef BOOL (WINAPI *PFN_SetFirmwareVariableExW)(LPCWSTR, LPCWSTR, PVOID, DWORD, DWORD);
    typedef BOOL (WINAPI *PFN_SetFirmwareVariableExA)(LPCSTR, LPCSTR, PVOID, DWORD, DWORD);
    typedef BOOL (NTAPI *PFN_RtlQueryUnbiasedInterruptTime)(PULONGLONG);
    PFN_GetFirmwareVariableExW pGetW = (PVOID)GetProcAddress(Kernel32, "GetFirmwareEnvironmentVariableExW");
    PFN_GetFirmwareVariableExA pGetA = (PVOID)GetProcAddress(Kernel32, "GetFirmwareEnvironmentVariableExA");
    PFN_SetFirmwareVariableExW pSetW = (PVOID)GetProcAddress(Kernel32, "SetFirmwareEnvironmentVariableExW");
    PFN_SetFirmwareVariableExA pSetA = (PVOID)GetProcAddress(Kernel32, "SetFirmwareEnvironmentVariableExA");
    PFN_RtlQueryUnbiasedInterruptTime pRtlQueryUnbiasedInterruptTime =
        (PVOID)GetProcAddress(Ntdll, "RtlQueryUnbiasedInterruptTime");
    BYTE Buffer[16];
    DWORD Attributes, Result;

    ok(pGetW != NULL, "GetFirmwareEnvironmentVariableExW is not exported\n");
    ok(pGetA != NULL, "GetFirmwareEnvironmentVariableExA is not exported\n");
    ok(pSetW != NULL, "SetFirmwareEnvironmentVariableExW is not exported\n");
    ok(pSetA != NULL, "SetFirmwareEnvironmentVariableExA is not exported\n");
    if (pGetW)
    {
        SetLastError(0xdeadbeef);
        Result = pGetW(NULL, L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Buffer, sizeof(Buffer), &Attributes);
        ok(Result == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "NULL name: %lu, error %lu\n", Result, GetLastError());
        SetLastError(0xdeadbeef);
        Result = pGetW(L"BootOrder", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", Buffer, sizeof(Buffer), &Attributes);
        ok(Result == 0 && GetLastError() != 0xdeadbeef, "variable read: %lu, error %lu\n", Result, GetLastError());
    }
    if (pGetA)
    {
        SetLastError(0xdeadbeef);
        Result = pGetA(NULL, NULL, Buffer, sizeof(Buffer), &Attributes);
        ok(Result == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "NULL names: %lu, error %lu\n", Result, GetLastError());
    }
    if (pSetW)
    {
        SetLastError(0xdeadbeef);
        ok(!pSetW(NULL, NULL, Buffer, 1, 0) && GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
    }
    if (pSetA)
    {
        SetLastError(0xdeadbeef);
        ok(!pSetA(NULL, NULL, Buffer, 1, 0) && GetLastError() == ERROR_INVALID_PARAMETER, "error %lu\n", GetLastError());
    }

    ok(pRtlQueryUnbiasedInterruptTime != NULL, "ntdll!RtlQueryUnbiasedInterruptTime is not exported\n");

    ok(Msvcrt != NULL, "msvcrt.dll does not load, error %lu\n", GetLastError());
    if (Msvcrt)
    {
        typedef PVOID (__cdecl *PFN_create_locale)(int, const char *);
        typedef VOID (__cdecl *PFN_free_locale)(PVOID);
        typedef PVOID (__cdecl *PFN_get_current_locale)(VOID);
        typedef int (__cdecl *PFN_isalpha_l)(int, PVOID);
        PFN_create_locale p_create_locale = (PVOID)GetProcAddress(Msvcrt, "_create_locale");
        PFN_free_locale p_free_locale = (PVOID)GetProcAddress(Msvcrt, "_free_locale");
        PFN_get_current_locale p_get_current_locale = (PVOID)GetProcAddress(Msvcrt, "_get_current_locale");
        PFN_isalpha_l p_isalpha_l = (PVOID)GetProcAddress(Msvcrt, "_isalpha_l");

        ok(p_create_locale != NULL, "msvcrt!_create_locale is not exported\n");
        ok(p_free_locale != NULL, "msvcrt!_free_locale is not exported\n");
        ok(p_get_current_locale != NULL, "msvcrt!_get_current_locale is not exported\n");
        if (p_create_locale && p_free_locale && p_get_current_locale)
        {
            PVOID Locale;

            ok(p_get_current_locale() != NULL, "_get_current_locale returned NULL\n");
            Locale = p_create_locale(LC_ALL, "C");
            ok(Locale != NULL, "_create_locale(LC_ALL, \"C\") returned NULL\n");
            if (Locale)
            {
                if (p_isalpha_l)
                {
                    ok(p_isalpha_l('a', Locale) != 0, "'a' is not alpha in the C locale\n");
                    ok(p_isalpha_l('1', Locale) == 0, "'1' is alpha in the C locale\n");
                }
                p_free_locale(Locale);
            }
            ok(p_create_locale(LC_ALL, "xx_bogus_locale") == NULL, "a bogus locale name was accepted\n");
        }
    }
}

START_TEST(KernelBaseForwarders)
{
    test_Forwarders();
    test_Calls();
    test_ExportLevel();
}
