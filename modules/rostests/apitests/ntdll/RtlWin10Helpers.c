/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for small Rtl functions that ntdll exports on Windows 8 and later: RtlIsZeroMemory, RtlCrc32,
 *              RtlIsCurrentProcess, RtlIsCurrentThread, RtlGetNtSystemRoot, RtlGetSuiteMask, RtlGetActiveConsoleId,
 *              RtlIsProcessorFeaturePresent, RtlGetDeviceFamilyInfoEnum, RtlFillMemoryUlonglong (x86) and the
 *              Ethernet address string functions
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define KUSER_NT_SYSTEM_ROOT ((const WCHAR *)0x7ffe0030)
#define KUSER_PROCESSOR_FEATURES ((const BYTE *)0x7ffe0274)
#define KUSER_SUITE_MASK (*(const ULONG *)0x7ffe02d0)
#define KUSER_ACTIVE_CONSOLE_ID (*(const ULONG *)0x7ffe02d8)

static HMODULE Ntdll;

static void *Get(const char *Name)
{
    void *p = GetProcAddress(Ntdll, Name);

    if (!p)
        ok(!is_reactos(), "%s is not exported by ntdll.dll\n", Name);
    return p;
}

static void Test_Memory(void)
{
    BOOLEAN (NTAPI *pIsZeroMemory)(PVOID, SIZE_T) = Get("RtlIsZeroMemory");
    ULONG (NTAPI *pCrc32)(const void *, SIZE_T, ULONG) = Get("RtlCrc32");
    char Zero[16] = { 0 };

    if (pIsZeroMemory)
    {
        ok(pIsZeroMemory(Zero, 16) == TRUE, "zeroes\n");
        Zero[5] = 1;
        ok(pIsZeroMemory(Zero, 16) == FALSE, "a set byte\n");
        ok(pIsZeroMemory(Zero, 5) == TRUE, "the zero part before the set byte\n");
        ok(pIsZeroMemory(Zero, 6) == FALSE, "up to the set byte\n");
        ok(pIsZeroMemory(Zero, 0) == TRUE, "no bytes\n");
    }
    if (pCrc32)
    {
        /* CRC-32C (Castagnoli); the second argument continues a CRC */
        ok(pCrc32("123456789", 9, 0) == 0xe3069283, "crc of 123456789: %08lx\n", pCrc32("123456789", 9, 0));
        ok(pCrc32("123456789", 9, 0x1234) == 0xb4db172b, "crc of 123456789 from 0x1234: %08lx\n", pCrc32("123456789", 9, 0x1234));
        ok(pCrc32("", 0, 0) == 0, "crc of nothing: %08lx\n", pCrc32("", 0, 0));
        ok(pCrc32("a", 1, 0) == 0xc1d04330, "crc of a: %08lx\n", pCrc32("a", 1, 0));
        ok(pCrc32("6789", 4, pCrc32("12345", 5, 0)) == 0xe3069283, "crc in two parts\n");
    }
}

static void Test_Current(void)
{
    BOOLEAN (NTAPI *pIsCurrentProcess)(HANDLE) = Get("RtlIsCurrentProcess");
    BOOLEAN (NTAPI *pIsCurrentThread)(HANDLE) = Get("RtlIsCurrentThread");
    HANDLE Process, Thread, Duplicate = NULL, Other;

    Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
    Thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentThreadId());
    ok(Process != NULL && Thread != NULL, "OpenProcess and OpenThread failed with %lu\n", GetLastError());
    DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &Duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS);

    if (pIsCurrentProcess)
    {
        Other = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
        ok(pIsCurrentProcess((HANDLE)(LONG_PTR)-1) == TRUE, "the pseudo handle\n");
        ok(pIsCurrentProcess((HANDLE)(LONG_PTR)-2) == FALSE, "the thread pseudo handle\n");
        ok(pIsCurrentProcess(Process) == TRUE, "a handle to this process\n");
        ok(pIsCurrentProcess(Duplicate) == TRUE, "a duplicate of the pseudo handle\n");
        ok(pIsCurrentProcess(NULL) == FALSE, "NULL\n");
        ok(pIsCurrentProcess(Thread) == FALSE, "a thread handle\n");
        if (Other)
        {
            ok(pIsCurrentProcess(Other) == FALSE, "another process\n");
            CloseHandle(Other);
        }
    }
    if (pIsCurrentThread)
    {
        ok(pIsCurrentThread((HANDLE)(LONG_PTR)-2) == TRUE, "the pseudo handle\n");
        ok(pIsCurrentThread((HANDLE)(LONG_PTR)-1) == FALSE, "the process pseudo handle\n");
        ok(pIsCurrentThread(Thread) == TRUE, "a handle to this thread\n");
        ok(pIsCurrentThread(Process) == FALSE, "a process handle\n");
        ok(pIsCurrentThread(NULL) == FALSE, "NULL\n");
    }

    if (Duplicate) CloseHandle(Duplicate);
    if (Process) CloseHandle(Process);
    if (Thread) CloseHandle(Thread);
}

static void Test_SharedData(void)
{
    PWSTR (NTAPI *pGetNtSystemRoot)(void) = Get("RtlGetNtSystemRoot");
    ULONG (NTAPI *pGetSuiteMask)(void) = Get("RtlGetSuiteMask");
    ULONG (NTAPI *pGetActiveConsoleId)(void) = Get("RtlGetActiveConsoleId");
    BOOLEAN (NTAPI *pFeature)(ULONG) = Get("RtlIsProcessorFeaturePresent");
    void (NTAPI *pFamily)(ULONGLONG *, ULONG *, ULONG *) = Get("RtlGetDeviceFamilyInfoEnum");
    NTSTATUS (NTAPI *pGetVersion)(RTL_OSVERSIONINFOW *) = Get("RtlGetVersion");
    ULONG i;

    if (pGetNtSystemRoot)
    {
        ok(pGetNtSystemRoot() == KUSER_NT_SYSTEM_ROOT, "RtlGetNtSystemRoot returns %p\n", pGetNtSystemRoot());
        ok(pGetNtSystemRoot()[1] == L':', "the system root is %ls\n", pGetNtSystemRoot());
    }
    if (pGetSuiteMask)
        ok(pGetSuiteMask() == KUSER_SUITE_MASK, "RtlGetSuiteMask %lx, shared data %lx\n", pGetSuiteMask(), KUSER_SUITE_MASK);
    if (pGetActiveConsoleId)
        ok(pGetActiveConsoleId() == KUSER_ACTIVE_CONSOLE_ID, "RtlGetActiveConsoleId %lu, shared data %lu\n", pGetActiveConsoleId(), KUSER_ACTIVE_CONSOLE_ID);
    if (pFeature)
    {
        for (i = 0; i < 64; i++)
            ok(pFeature(i) == (KUSER_PROCESSOR_FEATURES[i] != 0), "feature %lu: %d, shared data %d\n", i, pFeature(i), KUSER_PROCESSOR_FEATURES[i]);
        ok(pFeature(64) == FALSE && pFeature(65) == FALSE && pFeature(0xffff) == FALSE, "features beyond the table\n");
        ok(pFeature(PF_FLOATING_POINT_PRECISION_ERRATA) == (KUSER_PROCESSOR_FEATURES[PF_FLOATING_POINT_PRECISION_ERRATA] != 0), "feature 0\n");
        ok(pFeature(PF_COMPARE_EXCHANGE_DOUBLE) == IsProcessorFeaturePresent(PF_COMPARE_EXCHANGE_DOUBLE), "against IsProcessorFeaturePresent\n");
    }
    if (pFamily && pGetVersion)
    {
        RTL_OSVERSIONINFOW Version = { sizeof(Version) };
        ULONGLONG Info = 7;
        ULONG Family = 7, Form = 7;

        pGetVersion(&Version);
        pFamily(&Info, &Family, &Form);
        ok(Family == 3 && Form == 0, "family %lu form %lu\n", Family, Form);
        ok((Info >> 48) == Version.dwMajorVersion && ((Info >> 32) & 0xffff) == Version.dwMinorVersion &&
           ((Info >> 16) & 0xffff) == (Version.dwBuildNumber & 0xffff),
           "info %I64x for version %lu.%lu.%lu\n", Info, Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber);
        Info = 7;
        pFamily(&Info, NULL, NULL);
        ok(Info != 7, "only the version\n");
        Family = 7;
        pFamily(NULL, &Family, NULL);
        ok(Family == 3, "only the family\n");
        Form = 7;
        pFamily(NULL, NULL, &Form);
        ok(Form == 0, "only the form\n");
        pFamily(NULL, NULL, NULL);
    }
}

#ifndef _WIN64
static void Test_FillUlonglong(void)
{
    VOID (NTAPI *pFill)(PVOID, SIZE_T, ULONGLONG) = Get("RtlFillMemoryUlonglong");
    ULONGLONG Buffer[5];

    if (!pFill)
        return;

    memset(Buffer, 0, sizeof(Buffer));
    pFill(Buffer, 24, 0x1122334455667788ULL);
    ok(Buffer[0] == 0x1122334455667788ULL && Buffer[1] == Buffer[0] && Buffer[2] == Buffer[0] && Buffer[3] == 0, "fill of three: %I64x %I64x %I64x %I64x\n", Buffer[0], Buffer[1], Buffer[2], Buffer[3]);
    memset(Buffer, 0, sizeof(Buffer));
    pFill(Buffer, 20, 0x1122334455667788ULL);
    ok(Buffer[1] == 0x1122334455667788ULL && Buffer[2] == 0x55667788, "a length that is no multiple of eight: %I64x %I64x\n", Buffer[1], Buffer[2]);
}
#endif

typedef struct { UCHAR Byte[6]; } TEST_EUI48;

static void Test_Ethernet(void)
{
    PSTR (NTAPI *pToStringA)(const TEST_EUI48 *, PSTR) = Get("RtlEthernetAddressToStringA");
    PWSTR (NTAPI *pToStringW)(const TEST_EUI48 *, PWSTR) = Get("RtlEthernetAddressToStringW");
    NTSTATUS (NTAPI *pFromStringA)(PCSTR, PCSTR *, TEST_EUI48 *) = Get("RtlEthernetStringToAddressA");
    NTSTATUS (NTAPI *pFromStringW)(PCWSTR, PCWSTR *, TEST_EUI48 *) = Get("RtlEthernetStringToAddressW");
    static const TEST_EUI48 Address = { { 0x00, 0x1a, 0xFF, 0x0b, 0xc4, 0x7e } };
    char Buffer[32];
    WCHAR WideBuffer[32];
    PCSTR End;
    PCWSTR WideEnd;
    TEST_EUI48 Result;
    NTSTATUS Status;
    PSTR Ret;
    PWSTR WideRet;
    ULONG Index;

    if (pToStringA && pToStringW)
    {
        memset(Buffer, 'x', sizeof(Buffer));
        Ret = pToStringA(&Address, Buffer);
        ok(!strcmp(Buffer, "00-1A-FF-0B-C4-7E") && Ret == Buffer + 17, "RtlEthernetAddressToStringA: '%s' %d\n", Buffer, (int)(Ret - Buffer));
        for (Index = 0; Index < 32; Index++)
            WideBuffer[Index] = L'x';
        WideRet = pToStringW(&Address, WideBuffer);
        ok(!wcscmp(WideBuffer, L"00-1A-FF-0B-C4-7E") && WideRet == WideBuffer + 17, "RtlEthernetAddressToStringW: %ls\n", WideBuffer);
    }
    if (pFromStringA)
    {
        memset(&Result, 0xEE, sizeof(Result));
        End = NULL;
        Status = pFromStringA("00-1A-ff-0b-C4-7e", &End, &Result);
        ok(Status == STATUS_SUCCESS && !memcmp(&Result, &Address, 6) && *End == 0, "dashes: %lx\n", Status);
        Status = pFromStringA("00:1a:ff:0b:c4:7e", &End, &Result);
        ok(Status == STATUS_SUCCESS && !memcmp(&Result, &Address, 6), "colons: %lx\n", Status);
        Status = pFromStringA("00-1A:ff-0b-C4-7e", &End, &Result);
        ok(Status == STATUS_SUCCESS, "mixed separators: %lx\n", Status);
        End = NULL;
        Status = pFromStringA("00-1A-ff-0b-C4-7e zz", &End, &Result);
        ok(Status == STATUS_SUCCESS && End != NULL && !strcmp(End, " zz"), "text after the address: %lx '%s'\n", Status, End ? End : "(null)");
        End = NULL;
        Status = pFromStringA("00-1A-ff-0b-C4", &End, &Result);
        ok(Status == STATUS_INVALID_PARAMETER && End != NULL && *End == 0, "five octets: %lx\n", Status);
        Status = pFromStringA("001aff0bc47e", &End, &Result);
        ok(Status == STATUS_INVALID_PARAMETER, "no separators: %lx\n", Status);
        Status = pFromStringA("0-1A-ff-0b-C4-7", &End, &Result);
        ok(Status == STATUS_INVALID_PARAMETER, "one-digit octets: %lx\n", Status);
        Status = pFromStringA("00.1A.ff.0b.C4.7e", &End, &Result);
        ok(Status == STATUS_INVALID_PARAMETER, "dots: %lx\n", Status);
        Status = pFromStringA("001a.ff0b.c47e", &End, &Result);
        ok(Status == STATUS_INVALID_PARAMETER, "groups of four: %lx\n", Status);
    }
    if (pFromStringW)
    {
        memset(&Result, 0xEE, sizeof(Result));
        WideEnd = NULL;
        Status = pFromStringW(L"00-1A-ff-0b-C4-7e", &WideEnd, &Result);
        ok(Status == STATUS_SUCCESS && !memcmp(&Result, &Address, 6) && *WideEnd == 0, "wide, dashes: %lx\n", Status);
        Status = pFromStringW(L"00:1a:ff:0b:c4:7e", &WideEnd, &Result);
        ok(Status == STATUS_SUCCESS && !memcmp(&Result, &Address, 6), "wide, colons: %lx\n", Status);
        Status = pFromStringW(L"00-1A-ff-0b-C4", &WideEnd, &Result);
        ok(Status == STATUS_INVALID_PARAMETER, "wide, five octets: %lx\n", Status);
    }
}


/* RtlWakeAddress*NoFence, RtlAcquireReleaseSRWLockExclusive, RtlWow64GetCurrentMachine, RtlQueryRegistryValuesEx,
   RtlAllocateAndInitializeSidEx */

typedef NTSTATUS (NTAPI *PFN_WaitOnAddress)(PVOID, PVOID, SIZE_T, PLARGE_INTEGER);
typedef VOID (NTAPI *PFN_Wake)(PVOID);

static PFN_WaitOnAddress pRtlWaitOnAddress;
static volatile LONG WakeValue;
static volatile LONG Woken;

static DWORD WINAPI WaitThread(LPVOID Param)
{
    LONG Undesired = 0;

    while (WakeValue == 0)
        pRtlWaitOnAddress((PVOID)&WakeValue, &Undesired, sizeof(Undesired), NULL);
    InterlockedIncrement(&Woken);
    return 0;
}

static void Test_Wake(void)
{
    PFN_Wake pWakeAll = Get("RtlWakeAddressAllNoFence");
    PFN_Wake pWakeSingle = Get("RtlWakeAddressSingleNoFence");
    HANDLE Threads[2];
    ULONG i;

    pRtlWaitOnAddress = Get("RtlWaitOnAddress");
    if (!pWakeAll || !pWakeSingle || !pRtlWaitOnAddress)
        return;

    for (i = 0; i < 2; i++)
    {
        WakeValue = 0;
        Woken = 0;
        Threads[0] = CreateThread(NULL, 0, WaitThread, NULL, 0, NULL);
        Threads[1] = CreateThread(NULL, 0, WaitThread, NULL, 0, NULL);
        Sleep(200);
        ok(Woken == 0, "the waiters left before the wake\n");
        WakeValue = 1;
        if (i == 0)
        {
            pWakeAll((PVOID)&WakeValue);
            ok(WaitForMultipleObjects(2, Threads, TRUE, 5000) == WAIT_OBJECT_0, "RtlWakeAddressAllNoFence did not wake both waiters\n");
        }
        else
        {
            /* the waiters re-check the value before they wait again, so one wake plus a second ends both */
            pWakeSingle((PVOID)&WakeValue);
            pWakeSingle((PVOID)&WakeValue);
            ok(WaitForMultipleObjects(2, Threads, TRUE, 5000) == WAIT_OBJECT_0, "RtlWakeAddressSingleNoFence did not wake the waiters\n");
        }
        ok(Woken == 2, "%ld waiters woke\n", Woken);
        CloseHandle(Threads[0]);
        CloseHandle(Threads[1]);
    }
}

static RTL_SRWLOCK ExclusiveLock;
static volatile LONG AcquireReleaseDone;

static DWORD WINAPI AcquireReleaseThread(LPVOID Param)
{
    VOID (NTAPI *pAcquireRelease)(PRTL_SRWLOCK) = Param;

    pAcquireRelease(&ExclusiveLock);
    AcquireReleaseDone = 1;
    return 0;
}

static void Test_AcquireRelease(void)
{
    VOID (NTAPI *pAcquireRelease)(PRTL_SRWLOCK) = Get("RtlAcquireReleaseSRWLockExclusive");
    VOID (NTAPI *pAcquire)(PRTL_SRWLOCK) = Get("RtlAcquireSRWLockExclusive");
    VOID (NTAPI *pRelease)(PRTL_SRWLOCK) = Get("RtlReleaseSRWLockExclusive");
    BOOLEAN (NTAPI *pTry)(PRTL_SRWLOCK) = Get("RtlTryAcquireSRWLockExclusive");
    HANDLE Thread;

    if (!pAcquireRelease || !pAcquire || !pRelease || !pTry)
        return;

    ExclusiveLock.Ptr = NULL;
    pAcquireRelease(&ExclusiveLock);
    ok(pTry(&ExclusiveLock) == TRUE, "the lock is free after RtlAcquireReleaseSRWLockExclusive\n");
    pRelease(&ExclusiveLock);

    /* it waits for the owner, then leaves the lock free */
    pAcquire(&ExclusiveLock);
    AcquireReleaseDone = 0;
    Thread = CreateThread(NULL, 0, AcquireReleaseThread, pAcquireRelease, 0, NULL);
    Sleep(300);
    ok(AcquireReleaseDone == 0, "RtlAcquireReleaseSRWLockExclusive returned while the lock was owned\n");
    pRelease(&ExclusiveLock);
    ok(WaitForSingleObject(Thread, 5000) == WAIT_OBJECT_0 && AcquireReleaseDone == 1, "RtlAcquireReleaseSRWLockExclusive did not return after the release\n");
    CloseHandle(Thread);
    ok(pTry(&ExclusiveLock) == TRUE, "the lock is free again\n");
    pRelease(&ExclusiveLock);
}

static void Test_MoreMisc(void)
{
    USHORT (NTAPI *pCurrentMachine)(void) = Get("RtlWow64GetCurrentMachine");
    NTSTATUS (NTAPI *pQueryEx)(ULONG, PCWSTR, PVOID, PVOID, PVOID) = Get("RtlQueryRegistryValuesEx");
    NTSTATUS (NTAPI *pQuery)(ULONG, PCWSTR, PVOID, PVOID, PVOID) = Get("RtlQueryRegistryValues");
    NTSTATUS (NTAPI *pAllocSidEx)(PSID_IDENTIFIER_AUTHORITY, UCHAR, PULONG, PSID *) = Get("RtlAllocateAndInitializeSidEx");
    ULONG (NTAPI *pLengthSid)(PSID) = Get("RtlLengthSid");
    PVOID (NTAPI *pFreeSid)(PSID) = Get("RtlFreeSid");

    if (pCurrentMachine)
        ok(pCurrentMachine() == (sizeof(void *) == 8 ? 0x8664 : 0x14c), "RtlWow64GetCurrentMachine: %x\n", pCurrentMachine());

    if (pQueryEx && pQuery)
    {
        struct { PVOID QueryRoutine; ULONG Flags; PWSTR Name; PVOID Context; ULONG Type; PVOID Default; ULONG DefaultLength; } Table[2];
        struct { USHORT Length; USHORT Max; PWSTR Buffer; } Value1 = { 0 }, Value2 = { 0 };
        NTSTATUS Status1, Status2;

        memset(Table, 0, sizeof(Table));
        Table[0].QueryRoutine = NULL;
        Table[0].Flags = 0x20;   /* RTL_QUERY_REGISTRY_DIRECT */
        Table[0].Name = L"CurrentVersion";
        Table[0].Context = &Value1;
        Status1 = pQuery(0, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion", Table, NULL, NULL);
        Table[0].Context = &Value2;
        Status2 = pQueryEx(0, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion", Table, NULL, NULL);
        ok(Status1 == STATUS_SUCCESS, "RtlQueryRegistryValues: %lx\n", Status1);
        ok(Status2 == Status1, "RtlQueryRegistryValuesEx: %lx, RtlQueryRegistryValues %lx\n", Status2, Status1);
        if (Status1 == STATUS_SUCCESS && Status2 == STATUS_SUCCESS)
            ok(Value1.Length == Value2.Length && !memcmp(Value1.Buffer, Value2.Buffer, Value1.Length), "the same value\n");
    }

    if (pAllocSidEx && pLengthSid && pFreeSid)
    {
        SID_IDENTIFIER_AUTHORITY Authority = { { 0, 0, 0, 0, 0, 5 } };
        ULONG SubAuthorities[16] = { 21, 11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 121, 132, 143, 154, 165 };
        static const UCHAR Counts[] = { 0, 1, 3, 8, 15 };
        ULONG i;
        PSID Sid;
        NTSTATUS Status;

        for (i = 0; i < sizeof(Counts); i++)
        {
            Sid = NULL;
            Status = pAllocSidEx(&Authority, Counts[i], SubAuthorities, &Sid);
            ok(Status == STATUS_SUCCESS && Sid != NULL, "RtlAllocateAndInitializeSidEx(%u): %lx\n", Counts[i], Status);
            if (Sid)
            {
                PISID IdSid = Sid;

                ok(IdSid->Revision == 1 && IdSid->SubAuthorityCount == Counts[i] && IdSid->IdentifierAuthority.Value[5] == 5,
                   "the SID of %u: revision %u count %u\n", Counts[i], IdSid->Revision, IdSid->SubAuthorityCount);
                ok(pLengthSid(Sid) == 8 + 4 * Counts[i], "length of the SID of %u: %lu\n", Counts[i], pLengthSid(Sid));
                ok(Counts[i] == 0 || (IdSid->SubAuthority[0] == 21 && IdSid->SubAuthority[Counts[i] - 1] == SubAuthorities[Counts[i] - 1]),
                   "the sub-authorities of %u\n", Counts[i]);
                pFreeSid(Sid);
            }
        }
        Sid = (PSID)(ULONG_PTR)1;
        Status = pAllocSidEx(&Authority, 16, SubAuthorities, &Sid);
        ok(Status == STATUS_INVALID_PARAMETER, "RtlAllocateAndInitializeSidEx(16): %lx\n", Status);
    }
}

START_TEST(RtlWin10Helpers)
{
    Ntdll = GetModuleHandleW(L"ntdll.dll");
    Test_Memory();
    Test_Current();
    Test_SharedData();
#ifndef _WIN64
    Test_FillUlonglong();
#endif
    Test_Ethernet();
    Test_Wake();
    Test_AcquireRelease();
    Test_MoreMisc();
}
