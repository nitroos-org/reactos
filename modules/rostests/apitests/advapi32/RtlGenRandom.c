/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Functional tests of the system random number generator: RtlGenRandom (SystemFunction036),
 *              IOCTL_KSEC_RANDOM_FILL_BUFFER, BCryptGenRandom, ProcessPrng, CryptGenRandom, UuidCreate, CoCreateGuid
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * What is checked: every byte asked for is written and nothing behind it; outputs never repeat (in a process,
 * across threads, across processes); the kernel interface works directly; the user-mode generator keeps working
 * across its reseed points; a statistical smoke test (FIPS 140-2 power-up tests on 20000-bit samples and a byte
 * chi-square), which is a sanity check, not a proof of quality. Lines starting with RNGBOOT, RNGPERF and RNGSTAT
 * are for the harness: RNGBOOT is the first output of the process, compared across boots and machines.
 */

#include "precomp.h"

#include <ntsecapi.h>
#include <wincrypt.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>

#define RNG_IOCTL_FILL_BUFFER   0x390008    /* CTL_CODE(FILE_DEVICE_KSEC, 2, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#define RNG_IOCTL_UNKNOWN       0x3900fc    /* CTL_CODE(FILE_DEVICE_KSEC, 0x3f, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#define RNG_BCRYPT_RNG_ALG_HANDLE ((PVOID)(ULONG_PTR)0x81)
#define RNG_BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#define RNG_CHILDREN 8

typedef LONG (WINAPI *PFN_BCRYPTGENRANDOM)(PVOID, PUCHAR, ULONG, ULONG);
typedef LONG (WINAPI *PFN_BCRYPTOPENALGORITHMPROVIDER)(PVOID *, LPCWSTR, LPCWSTR, ULONG);
typedef LONG (WINAPI *PFN_BCRYPTCLOSEALGORITHMPROVIDER)(PVOID, ULONG);
typedef BOOL (WINAPI *PFN_PROCESSPRNG)(PBYTE, SIZE_T);
typedef LONG (WINAPI *PFN_UUIDCREATE)(GUID *);
typedef HRESULT (WINAPI *PFN_COCREATEGUID)(GUID *);

static PFN_BCRYPTGENRANDOM pBCryptGenRandom;
static PFN_BCRYPTOPENALGORITHMPROVIDER pBCryptOpenAlgorithmProvider;
static PFN_BCRYPTCLOSEALGORITHMPROVIDER pBCryptCloseAlgorithmProvider;
static PFN_PROCESSPRNG pProcessPrng;
static PFN_UUIDCREATE pUuidCreate;
static PFN_COCREATEGUID pCoCreateGuid;

static void
LoadFunctions(void)
{
    HMODULE Module;

    Module = LoadLibraryW(L"bcrypt.dll");
    if (Module)
    {
        pBCryptGenRandom = (PFN_BCRYPTGENRANDOM)GetProcAddress(Module, "BCryptGenRandom");
        pBCryptOpenAlgorithmProvider =
            (PFN_BCRYPTOPENALGORITHMPROVIDER)GetProcAddress(Module, "BCryptOpenAlgorithmProvider");
        pBCryptCloseAlgorithmProvider =
            (PFN_BCRYPTCLOSEALGORITHMPROVIDER)GetProcAddress(Module, "BCryptCloseAlgorithmProvider");
    }
    Module = LoadLibraryW(L"bcryptprimitives.dll");
    if (Module)
        pProcessPrng = (PFN_PROCESSPRNG)GetProcAddress(Module, "ProcessPrng");
    Module = LoadLibraryW(L"rpcrt4.dll");
    if (Module)
        pUuidCreate = (PFN_UUIDCREATE)GetProcAddress(Module, "UuidCreate");
    Module = LoadLibraryW(L"ole32.dll");
    if (Module)
        pCoCreateGuid = (PFN_COCREATEGUID)GetProcAddress(Module, "CoCreateGuid");
}

static void
ToHex(const UCHAR *Data, SIZE_T Length, char *Out)
{
    static const char Digits[] = "0123456789abcdef";
    SIZE_T i;

    for (i = 0; i < Length; i++)
    {
        Out[2 * i] = Digits[Data[i] >> 4];
        Out[2 * i + 1] = Digits[Data[i] & 15];
    }
    Out[2 * Length] = 0;
}

static int __cdecl
Compare16(const void *a, const void *b)
{
    return memcmp(a, b, 16);
}

/* Number of equal neighbours after sorting Count records of 16 bytes */
static ULONG
CountDuplicates16(PUCHAR Records, ULONG Count)
{
    ULONG i, Duplicates = 0;

    qsort(Records, Count, 16, Compare16);
    for (i = 1; i < Count; i++)
    {
        if (!memcmp(Records + 16 * (i - 1), Records + 16 * i, 16))
            Duplicates++;
    }
    return Duplicates;
}

/* Every byte written, nothing behind the buffer, no run of one value */
static void
TestFill(void)
{
    static const ULONG Lengths[] = { 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 1000, 4096,
                                     65535, 65536, 65537, 200000 };
    PUCHAR Buffer;
    ULONG i, j, Same, Guard = 64;
    BOOLEAN Ret;

    Buffer = HeapAlloc(GetProcessHeap(), 0, 200000 + 2 * Guard);
    if (!Buffer)
    {
        skip("no memory\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(Lengths); i++)
    {
        ULONG Length = Lengths[i];
        ULONG Hits[2] = { 0, 0 };
        ULONG Pass;

        /* twice, with two fill patterns: a byte left untouched keeps its pattern in both */
        for (Pass = 0; Pass < 2; Pass++)
        {
            UCHAR Pattern = Pass ? 0x5a : 0xa5;

            memset(Buffer, Pattern, Length + 2 * Guard);
            Ret = RtlGenRandom(Buffer + Guard, Length);
            ok(Ret == TRUE, "RtlGenRandom(%lu) returned %u\n", Length, Ret);
            for (j = 0; j < Guard; j++)
            {
                if (Buffer[j] != Pattern || Buffer[Guard + Length + j] != Pattern)
                    break;
            }
            ok(j == Guard, "RtlGenRandom(%lu) wrote outside the buffer\n", Length);
            for (j = 0; j < Length; j++)
            {
                if (Buffer[Guard + j] == Pattern)
                    Hits[Pass]++;
            }
        }
        /* about Length/256 hits per pass are expected; a byte never written would hit in both */
        ok(Hits[0] <= Length / 64 + 3 && Hits[1] <= Length / 64 + 3,
           "RtlGenRandom(%lu): %lu and %lu bytes kept the fill pattern\n", Length, Hits[0], Hits[1]);

        /* no long run of one byte value */
        for (j = 1, Same = 0; j < Length; j++)
        {
            if (Buffer[Guard + j] == Buffer[Guard + j - 1])
                Same++;
        }
        ok(Same <= Length / 64 + 3, "RtlGenRandom(%lu): %lu equal neighbours\n", Length, Same);
    }

    /* nothing to do: TRUE, as in Windows */
    ok(RtlGenRandom(NULL, 0) == TRUE, "RtlGenRandom(NULL, 0) failed\n");
    ok(RtlGenRandom(Buffer, 0) == TRUE, "RtlGenRandom(buf, 0) failed\n");

    HeapFree(GetProcessHeap(), 0, Buffer);
}

/* 20000 consecutive outputs of 16 bytes, all different */
static void
TestDistinct(void)
{
    const ULONG Count = 20000;
    PUCHAR Records;
    ULONG i;

    Records = HeapAlloc(GetProcessHeap(), 0, Count * 16);
    if (!Records)
    {
        skip("no memory\n");
        return;
    }
    for (i = 0; i < Count; i++)
        ok(RtlGenRandom(Records + 16 * i, 16), "RtlGenRandom failed\n");
    ok(CountDuplicates16(Records, Count) == 0, "repeated 16-byte outputs in one process\n");
    HeapFree(GetProcessHeap(), 0, Records);
}

typedef struct
{
    PUCHAR Records;
    ULONG Count;
    ULONG Failures;
} THREAD_ARGS;

static DWORD WINAPI
GenThread(LPVOID Parameter)
{
    THREAD_ARGS *Args = Parameter;
    ULONG i;

    for (i = 0; i < Args->Count; i++)
    {
        /* mixed sizes: short requests and ones longer than a block */
        if (i % 7 == 0)
        {
            UCHAR Long[300];

            if (!RtlGenRandom(Long, sizeof(Long)))
                Args->Failures++;
            memcpy(Args->Records + 16 * i, Long + 100, 16);
        }
        else if (!RtlGenRandom(Args->Records + 16 * i, 16))
        {
            Args->Failures++;
        }
    }
    return 0;
}

static void
TestThreads(void)
{
    enum { Threads = 8, PerThread = 4000 };
    HANDLE Handles[Threads];
    THREAD_ARGS Args[Threads];
    PUCHAR Records;
    ULONG i, Failures = 0;

    Records = HeapAlloc(GetProcessHeap(), 0, Threads * PerThread * 16);
    if (!Records)
    {
        skip("no memory\n");
        return;
    }
    for (i = 0; i < Threads; i++)
    {
        Args[i].Records = Records + i * PerThread * 16;
        Args[i].Count = PerThread;
        Args[i].Failures = 0;
        Handles[i] = CreateThread(NULL, 0, GenThread, &Args[i], 0, NULL);
        ok(Handles[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
    }
    for (i = 0; i < Threads; i++)
    {
        if (Handles[i])
        {
            WaitForSingleObject(Handles[i], INFINITE);
            CloseHandle(Handles[i]);
        }
        Failures += Args[i].Failures;
    }
    ok(Failures == 0, "%lu failed calls in threads\n", Failures);
    ok(CountDuplicates16(Records, Threads * PerThread) == 0, "repeated outputs across threads\n");
    HeapFree(GetProcessHeap(), 0, Records);
}

/* The kernel interface itself, the way advapi32 uses it */
static void
TestKsecIoctl(void)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\KsecDD");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Device;
    UCHAR First[64], Second[64], Zero[64];
    NTSTATUS Status;
    ULONG Tries, Differ = 0;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Device, FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    memset(Zero, 0, sizeof(Zero));
    for (Tries = 0; Tries < 16; Tries++)
    {
        memset(First, 0, sizeof(First));
        memset(Second, 0, sizeof(Second));
        Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, RNG_IOCTL_FILL_BUFFER, NULL, 0, First,
                                       sizeof(First));
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(Iosb.Information == sizeof(First), "Information %Iu\n", Iosb.Information);
        Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, RNG_IOCTL_FILL_BUFFER, NULL, 0, Second,
                                       sizeof(Second));
        ok_ntstatus(Status, STATUS_SUCCESS);
        ok(memcmp(First, Zero, sizeof(First)) != 0, "kernel output is zero\n");
        if (memcmp(First, Second, sizeof(First)) != 0)
            Differ++;
    }
    ok(Differ == 16, "consecutive kernel outputs equal %lu of 16 times\n", 16 - Differ);

    /* a long request (more than one request key in ksecdd) */
    {
        const ULONG Length = 200000;
        PUCHAR Big = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
        ULONG i, Zeros = 0;

        if (Big)
        {
            Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, RNG_IOCTL_FILL_BUFFER, NULL, 0, Big,
                                           Length);
            ok_ntstatus(Status, STATUS_SUCCESS);
            for (i = 0; i < Length; i++)
                Zeros += (Big[i] == 0);
            ok(Zeros < Length / 64, "%lu zero bytes in %lu from the kernel\n", Zeros, Length);
            /* the 64 KiB pieces are not repeats of each other */
            ok(memcmp(Big, Big + 65536, 4096) != 0 && memcmp(Big + 65536, Big + 131072, 4096) != 0,
               "kernel output repeats at 64 KiB\n");
            HeapFree(GetProcessHeap(), 0, Big);
        }
    }

    NtClose(Device);
}

/* An unknown control code is refused (it used to stop in a kernel breakpoint) */
static void
TestKsecUnknownIoctl(void)
{
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\KsecDD");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Device;
    UCHAR Out[16];
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Device, FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;
    Status = NtDeviceIoControlFile(Device, NULL, NULL, NULL, &Iosb, RNG_IOCTL_UNKNOWN, NULL, 0, Out, sizeof(Out));
    ok_ntstatus(Status, STATUS_INVALID_DEVICE_REQUEST);
    NtClose(Device);
}

static void
TestBCrypt(void)
{
    UCHAR a[32], b[32];
    PVOID Algorithm = NULL;
    LONG Status;
    PUCHAR Big;

    if (!pBCryptGenRandom)
    {
        skip("no BCryptGenRandom\n");
        return;
    }

    Status = pBCryptGenRandom(NULL, a, sizeof(a), RNG_BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = pBCryptGenRandom(NULL, b, sizeof(b), RNG_BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(memcmp(a, b, sizeof(a)) != 0, "BCryptGenRandom repeated itself\n");
    Status = pBCryptGenRandom(NULL, a, sizeof(a), 0);
    ok_ntstatus(Status, STATUS_INVALID_HANDLE);
    Status = pBCryptGenRandom(RNG_BCRYPT_RNG_ALG_HANDLE, a, sizeof(a), 0);
    ok_ntstatus(Status, STATUS_SUCCESS);

    if (pBCryptOpenAlgorithmProvider && pBCryptCloseAlgorithmProvider)
    {
        Status = pBCryptOpenAlgorithmProvider(&Algorithm, L"RNG", NULL, 0);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if (Status == STATUS_SUCCESS)
        {
            Status = pBCryptGenRandom(Algorithm, b, sizeof(b), 0);
            ok_ntstatus(Status, STATUS_SUCCESS);
            ok(memcmp(a, b, sizeof(a)) != 0, "BCryptGenRandom repeated itself\n");
            pBCryptCloseAlgorithmProvider(Algorithm, 0);
        }
    }

    Big = HeapAlloc(GetProcessHeap(), 0, 1 << 20);
    if (Big)
    {
        Status = pBCryptGenRandom(NULL, Big, 1 << 20, RNG_BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        ok_ntstatus(Status, STATUS_SUCCESS);
        HeapFree(GetProcessHeap(), 0, Big);
    }
}

static void
TestConsumers(void)
{
    HCRYPTPROV Provider;
    UCHAR a[32], b[32];
    GUID Guids[2000];
    ULONG i, Bad = 0;

    if (pProcessPrng)
    {
        ok(pProcessPrng(a, sizeof(a)), "ProcessPrng failed\n");
        ok(pProcessPrng(b, sizeof(b)), "ProcessPrng failed\n");
        ok(memcmp(a, b, sizeof(a)) != 0, "ProcessPrng repeated itself\n");
    }
    else
    {
        skip("no ProcessPrng\n");
    }

    if (CryptAcquireContextW(&Provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        ok(CryptGenRandom(Provider, sizeof(a), a), "CryptGenRandom failed: %lu\n", GetLastError());
        ok(CryptGenRandom(Provider, sizeof(b), b), "CryptGenRandom failed: %lu\n", GetLastError());
        ok(memcmp(a, b, sizeof(a)) != 0, "CryptGenRandom repeated itself\n");
        CryptReleaseContext(Provider, 0);
    }
    else
    {
        ok(0, "CryptAcquireContext failed: %lu\n", GetLastError());
    }

    if (pUuidCreate)
    {
        for (i = 0; i < ARRAYSIZE(Guids); i++)
        {
            ok(pUuidCreate(&Guids[i]) == 0, "UuidCreate failed\n");
            /* version 4 (random), RFC 4122 variant */
            if ((Guids[i].Data3 >> 12) != 4 || (Guids[i].Data4[0] & 0xc0) != 0x80)
                Bad++;
        }
        ok(Bad == 0, "%lu GUIDs without version 4 / RFC 4122 variant\n", Bad);
        ok(CountDuplicates16((PUCHAR)Guids, ARRAYSIZE(Guids)) == 0, "UuidCreate repeated a GUID\n");
    }
    if (pCoCreateGuid)
    {
        for (i = 0; i < ARRAYSIZE(Guids); i++)
            ok(pCoCreateGuid(&Guids[i]) == S_OK, "CoCreateGuid failed\n");
        ok(CountDuplicates16((PUCHAR)Guids, ARRAYSIZE(Guids)) == 0, "CoCreateGuid repeated a GUID\n");
    }
}

/* The output across the user-mode generator's reseed points (1 MiB of output, one second) stays valid */
static void
TestReseed(void)
{
    const ULONG Length = 3 << 20;
    PUCHAR Big;
    UCHAR Before[16], After[16];
    ULONG i, Zeros = 0;

    Big = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    if (!Big)
    {
        skip("no memory\n");
        return;
    }
    ok(RtlGenRandom(Big, Length), "RtlGenRandom(3 MiB) failed\n");
    for (i = 0; i < Length; i++)
        Zeros += (Big[i] == 0);
    ok(Zeros < Length / 128, "%lu zero bytes in 3 MiB\n", Zeros);
    ok(RtlGenRandom(Before, sizeof(Before)), "RtlGenRandom failed\n");
    Sleep(1100);
    ok(RtlGenRandom(After, sizeof(After)), "RtlGenRandom after a pause failed\n");
    ok(memcmp(Before, After, sizeof(Before)) != 0, "output repeated across a reseed\n");
    HeapFree(GetProcessHeap(), 0, Big);
}

/* FIPS 140-2 (2001) section 4.9.1 power-up tests on 20000 bits, and a chi-square of the byte counts of 1 MiB.
   A sanity check only: an LCG passes these too; they catch gross failure (stuck bytes, bias, short cycles) */
static void
TestStatistics(void)
{
    UCHAR Sample[2500];
    ULONG Round, i, Ones, Poker[16], Runs[2][7], Run, LongRun, Failures = 0;
    double X, Chi;
    PUCHAR Big;
    ULONG Counts[256];

    for (Round = 0; Round < 16; Round++)
    {
        int Bit, Previous = -1;

        ok(RtlGenRandom(Sample, sizeof(Sample)), "RtlGenRandom failed\n");
        Ones = 0;
        memset(Poker, 0, sizeof(Poker));
        memset(Runs, 0, sizeof(Runs));
        Run = 0;
        LongRun = 0;
        for (i = 0; i < 20000; i++)
        {
            Bit = (Sample[i / 8] >> (7 - i % 8)) & 1;
            Ones += Bit;
            if (Bit == Previous)
            {
                Run++;
            }
            else
            {
                if (Previous >= 0)
                    Runs[Previous][min(Run, 6)]++;
                Run = 1;
                Previous = Bit;
            }
            LongRun = max(LongRun, Run);
        }
        Runs[Previous][min(Run, 6)]++;
        for (i = 0; i < 2500; i++)
        {
            Poker[Sample[i] >> 4]++;
            Poker[Sample[i] & 15]++;
        }
        for (i = 0, X = 0; i < 16; i++)
            X += (double)Poker[i] * Poker[i];
        X = 16.0 / 5000.0 * X - 5000.0;

        /* monobit 9725..10275, poker 2.16..46.17, long run < 26, runs of 1..6+ within the table */
        if (Ones <= 9725 || Ones >= 10275 || X <= 2.16 || X >= 46.17 || LongRun >= 26)
            Failures++;
        else
        {
            static const ULONG Low[7] = { 0, 2315, 1114, 527, 240, 103, 103 };
            static const ULONG High[7] = { 0, 2685, 1386, 723, 384, 209, 209 };
            int b, r;

            for (b = 0; b < 2; b++)
            {
                for (r = 1; r <= 6; r++)
                {
                    if (Runs[b][r] < Low[r] || Runs[b][r] > High[r])
                    {
                        Failures++;
                        b = 2;
                        break;
                    }
                }
            }
        }
        if (Round == 0)
            trace("RNGSTAT fips140-2 sample 0: ones %lu poker %.2f longest run %lu\n", Ones, X, LongRun);
    }
    /* each sample of a good generator fails with a chance of about 1e-4..1e-3: allow one */
    ok(Failures <= 1, "%lu of 16 samples failed the FIPS 140-2 tests\n", Failures);

    Big = HeapAlloc(GetProcessHeap(), 0, 1 << 20);
    if (!Big || !pBCryptGenRandom)
    {
        skip("no memory or no BCryptGenRandom\n");
        if (Big)
            HeapFree(GetProcessHeap(), 0, Big);
        return;
    }
    ok_ntstatus(pBCryptGenRandom(NULL, Big, 1 << 20, RNG_BCRYPT_USE_SYSTEM_PREFERRED_RNG), STATUS_SUCCESS);
    memset(Counts, 0, sizeof(Counts));
    for (i = 0; i < (1 << 20); i++)
        Counts[Big[i]]++;
    for (i = 0, Chi = 0; i < 256; i++)
    {
        X = Counts[i] - 4096.0;
        Chi += X * X / 4096.0;
    }
    /* 255 degrees of freedom: 330 is beyond the 0.999 quantile (about 330.5 is p = 0.001) */
    trace("RNGSTAT chi-square of 1 MiB byte counts: %.1f (255 df)\n", Chi);
    ok(Chi < 340.0, "byte distribution chi-square %.1f\n", Chi);
    HeapFree(GetProcessHeap(), 0, Big);
}

static double
Seconds(LARGE_INTEGER Start, LARGE_INTEGER End, LARGE_INTEGER Frequency)
{
    return (double)(End.QuadPart - Start.QuadPart) / (double)Frequency.QuadPart;
}

/* Throughput for the harness (no assertion) */
static void
TestPerformance(void)
{
    LARGE_INTEGER Frequency, Start, End;
    PUCHAR Big;
    UCHAR Small[16];
    ULONG i, Rounds = 16;
    double Best = 1e9, s;

    QueryPerformanceFrequency(&Frequency);
    Big = HeapAlloc(GetProcessHeap(), 0, 1 << 20);
    if (Big && pBCryptGenRandom)
    {
        for (i = 0; i < Rounds; i++)
        {
            QueryPerformanceCounter(&Start);
            pBCryptGenRandom(NULL, Big, 1 << 20, RNG_BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            QueryPerformanceCounter(&End);
            s = Seconds(Start, End, Frequency);
            Best = min(Best, s);
        }
        trace("RNGPERF BCryptGenRandom 1 MiB: best of %lu %.3f ms (%.1f MB/s)\n", Rounds, Best * 1000.0,
              1.048576 / Best);
    }
    if (Big)
        HeapFree(GetProcessHeap(), 0, Big);

    QueryPerformanceCounter(&Start);
    for (i = 0; i < 100000; i++)
        RtlGenRandom(Small, sizeof(Small));
    QueryPerformanceCounter(&End);
    trace("RNGPERF RtlGenRandom 16 bytes: %.0f ns per call (100000 calls)\n",
          Seconds(Start, End, Frequency) * 1e9 / 100000);
}

/* Child processes, each reporting its first outputs; all must differ from each other and from this process */
static void
TestProcesses(void)
{
    WCHAR Exe[MAX_PATH], CommandLine[MAX_PATH + 64];
    char Lines[RNG_CHILDREN][512];
    char Own[80];
    UCHAR First[32];
    ULONG i, j, Found = 0, Same = 0;

    ok(RtlGenRandom(First, sizeof(First)), "RtlGenRandom failed\n");
    ToHex(First, sizeof(First), Own);

    GetModuleFileNameW(NULL, Exe, ARRAYSIZE(Exe));
    StringCchPrintfW(CommandLine, ARRAYSIZE(CommandLine), L"\"%s\" RtlGenRandomChild", Exe);

    for (i = 0; i < RNG_CHILDREN; i++)
    {
        SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, TRUE };
        STARTUPINFOW Si;
        PROCESS_INFORMATION Pi;
        HANDLE Read, Write;
        char Output[8192];
        DWORD Got, Total = 0;
        char *Line;

        Lines[i][0] = 0;
        if (!CreatePipe(&Read, &Write, &Sa, 0))
        {
            ok(0, "CreatePipe failed: %lu\n", GetLastError());
            continue;
        }
        SetHandleInformation(Read, HANDLE_FLAG_INHERIT, 0);
        ZeroMemory(&Si, sizeof(Si));
        Si.cb = sizeof(Si);
        Si.dwFlags = STARTF_USESTDHANDLES;
        Si.hStdOutput = Write;
        Si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        Si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        if (!CreateProcessW(NULL, CommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &Si, &Pi))
        {
            ok(0, "CreateProcess failed: %lu\n", GetLastError());
            CloseHandle(Read);
            CloseHandle(Write);
            continue;
        }
        CloseHandle(Write);
        while (Total < sizeof(Output) - 1 && ReadFile(Read, Output + Total, sizeof(Output) - 1 - Total, &Got, NULL) &&
               Got)
        {
            Total += Got;
        }
        Output[Total] = 0;
        CloseHandle(Read);
        WaitForSingleObject(Pi.hProcess, 60000);
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);

        Line = strstr(Output, "RNGCHILD ");
        if (Line)
        {
            char *End = strpbrk(Line, "\r\n");

            if (End)
                *End = 0;
            StringCchCopyA(Lines[i], sizeof(Lines[i]), Line + 9);
            Found++;
        }
    }
    ok(Found == RNG_CHILDREN, "%lu of %u children reported\n", Found, RNG_CHILDREN);

    /* each field of each child against the same field of every other child and this process */
    for (i = 0; i < RNG_CHILDREN; i++)
    {
        if (!Lines[i][0])
            continue;
        if (!strncmp(Lines[i], Own, 64))
            Same++;
        for (j = i + 1; j < RNG_CHILDREN; j++)
        {
            char *a = Lines[i], *b = Lines[j];
            int Field;

            for (Field = 0; Field < 5 && a && b; Field++)
            {
                SIZE_T La = strcspn(a, " "), Lb = strcspn(b, " ");

                if (La == Lb && !strncmp(a, b, La) && La > 1)
                    Same++;
                a = strchr(a, ' ');
                b = strchr(b, ' ');
                if (a) a++;
                if (b) b++;
            }
        }
    }
    ok(Same == 0, "%lu equal outputs across processes\n", Same);
    trace("RNGCHILD0 %s\n", Lines[0]);
}

START_TEST(RtlGenRandom)
{
    UCHAR First[32];
    char Hex[80];

    /* the first output of this process, for comparison across boots and machines */
    ok(RtlGenRandom(First, sizeof(First)), "RtlGenRandom failed\n");
    ToHex(First, sizeof(First), Hex);
    trace("RNGBOOT %s\n", Hex);

    LoadFunctions();
    TestFill();
    TestDistinct();
    TestThreads();
    TestKsecIoctl();
    TestBCrypt();
    TestConsumers();
    TestReseed();
    TestStatistics();
    TestProcesses();
    TestPerformance();
}

START_TEST(KsecUnknownIoctl)
{
    TestKsecUnknownIoctl();
}

/* Not a test: the child of TestProcesses. One line: RtlGenRandom 32 bytes, BCryptGenRandom 16, ProcessPrng 16,
   CryptGenRandom 16, UuidCreate */
START_TEST(RtlGenRandomChild)
{
    UCHAR a[32], b[16], c[16], d[16];
    char Ha[80], Hb[40], Hc[40], Hd[40], He[40];
    HCRYPTPROV Provider;
    GUID Guid;

    LoadFunctions();
    memset(b, 0, sizeof(b));
    memset(c, 0, sizeof(c));
    memset(d, 0, sizeof(d));
    memset(&Guid, 0, sizeof(Guid));

    RtlGenRandom(a, sizeof(a));
    if (pBCryptGenRandom)
        pBCryptGenRandom(NULL, b, sizeof(b), RNG_BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (pProcessPrng)
        pProcessPrng(c, sizeof(c));
    if (CryptAcquireContextW(&Provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        CryptGenRandom(Provider, sizeof(d), d);
        CryptReleaseContext(Provider, 0);
    }
    if (pUuidCreate)
        pUuidCreate(&Guid);

    ToHex(a, sizeof(a), Ha);
    ToHex(b, sizeof(b), Hb);
    ToHex(c, sizeof(c), Hc);
    ToHex(d, sizeof(d), Hd);
    ToHex((PUCHAR)&Guid, sizeof(Guid), He);
    printf("RNGCHILD %s %s %s %s %s\n", Ha, Hb, Hc, Hd, He);
    fflush(stdout);
}
