/*
 * PROJECT:     ReactOS Kernel Security Support Provider Interface Driver
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Random number generation and entropy gathering
 * COPYRIGHT:   Copyright 2014-2017 Timo Kreuzer <timo.kreuzer@reactos.org>
 *              Copyright 2026 Tomas Srnka
 *
 * The system random number generator. Everything else draws from it: IOCTL_KSEC_RANDOM_FILL_BUFFER (advapi32
 * RtlGenRandom, and through it ProcessPrng, BCryptGenRandom and CryptGenRandom in user mode), BCryptGenRandom for
 * drivers (exported here, as ksecdd.sys did in Windows Vista, and by cng.sys), and the keys of RtlEncryptMemory.
 *
 * Generator: a 256-bit key K. A request takes one ChaCha20 block (RFC 8439) under K: the first 32 bytes become
 * the new K, the other 32 the key of this request, which ChaCha20 expands into the caller's buffer outside the lock
 * (at most KSEC_RNG_REQUEST_MAX bytes per request key, so a longer request takes several). K is replaced before
 * any output leaves, so a key that leaks later does not give earlier output away (backtracking resistance, the
 * Update step of SP 800-90A CTR_DRBG). The structure follows SP 800-90A CTR_DRBG (instantiate, generate with an
 * update after every request, reseed, a limit per request) with ChaCha20 in place of the block cipher; SP 800-90A
 * does not list ChaCha20, so this is not an approved DRBG in the FIPS sense.
 *
 * Seeding: the sources below are hashed with SHA-256 (FIPS 180-4) into 32 bytes of seed material, and the new K is
 * SHA-256(label, old K, reseed count, material), so a reseed adds to what K has and never replaces it by something
 * weaker:
 *   - RDSEED and RDRAND (x86/x64, when the processor has them): 16 words each; a word that is 0 or all ones counts
 *     as a failure (what broken RDRAND implementations return with success);
 *   - timing jitter: KSEC_RNG_JITTER_SAMPLES cycle counter readings around a performance counter query;
 *   - the time the reseed thread is woken by the clock interrupt (cycle counter and interrupt time);
 *   - system state: system/interrupt/tick time, the performance counter, per-processor interrupt and processor
 *     performance counters, system performance counters (KsecGatherEntropyData);
 *   - the saved seed HKLM\SYSTEM\RNG\Seed (64 bytes), read once when the driver starts.
 * The first seed is made in DriverEntry (ksecdd is a boot driver, so before any other consumer); then the
 * generator reseeds after 1, 2, 4 ... seconds, every KSEC_RNG_MAX_INTERVAL seconds from then on. A new saved seed
 * (64 bytes of output) is written at the first reseed at least KSEC_RNG_SAVE_AFTER seconds after the start (the
 * registry is writable then) and at shutdown (IRP_MJ_SHUTDOWN), so the next start does not begin from the same
 * saved value even after a crash. The key is created with a DACL for SYSTEM and Administrators only.
 *
 * Self-test: the ChaCha20 block of RFC 8439 2.3.2 and SHA-256("abc") are checked before the first seed; when
 * either fails the generator refuses every request (STATUS_INTERNAL_ERROR) instead of producing output.
 */

/* INCLUDES *******************************************************************/

#include "ksecdd.h"
#include <chacha20.h>
#include <sha256.h>

#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64))
#include <immintrin.h>
#endif

#define NDEBUG
#include <debug.h>


/* GLOBALS ********************************************************************/

#define TAG_KSEC_RNG            'RceS'
#define KSEC_RNG_REQUEST_MAX    (64 * 1024)
#define KSEC_RNG_HW_WORDS       16
#define KSEC_RNG_JITTER_SAMPLES 64
#define KSEC_RNG_MAX_INTERVAL   300
#define KSEC_RNG_SAVE_AFTER     60
#define KSEC_RNG_SEED_SIZE      64
#define KSEC_RNG_MAX_CPUS       64
#define KSEC_RNG_LOG_RESEEDS    10

#define KSEC_RNG_KEY_NAME       L"\\Registry\\Machine\\SYSTEM\\RNG"
#define KSEC_RNG_VALUE_NAME     L"Seed"

typedef struct _KSEC_RNG_SOURCES
{
    ULONG RdseedWords;
    ULONG RdrandWords;
    ULONG JitterSamples;
    ULONG JitterDistinct;
    BOOLEAN HaveRdseed;
    BOOLEAN HaveRdrand;
    BOOLEAN SavedSeed;
} KSEC_RNG_SOURCES, *PKSEC_RNG_SOURCES;

static KSPIN_LOCK KsecRngLock;
static UCHAR KsecRngKey[CHACHA20_KEY_SIZE];
static ULONGLONG KsecRngRequests;
static ULONG KsecRngReseeds;
static volatile BOOLEAN KsecRngReady;

static const UCHAR KsecRngNonce[CHACHA20_NONCE_SIZE] = { 0 };

static ULONG KsecRngInterval;
static BOOLEAN KsecRngSeedSaved;
static ULONGLONG KsecRngStartTime;


/* FUNCTIONS ******************************************************************/

static
ULONGLONG
KsecRngCycles(VOID)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    return __rdtsc();
#else
    return (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
#endif
}

#if defined(_M_IX86) || defined(_M_AMD64)
static
BOOLEAN
KsecRngRdrand(PULONG Value)
{
#if defined(__GNUC__) || defined(__clang__)
    UCHAR Ok;

    __asm__ __volatile__("rdrand %0; setc %1" : "=r"(*Value), "=qm"(Ok) : : "cc");
    return Ok != 0;
#else
    unsigned int v;
    int Ok = _rdrand32_step(&v);

    *Value = v;
    return Ok != 0;
#endif
}

static
BOOLEAN
KsecRngRdseed(PULONG Value)
{
#if defined(__GNUC__) || defined(__clang__)
    UCHAR Ok;

    __asm__ __volatile__("rdseed %0; setc %1" : "=r"(*Value), "=qm"(Ok) : : "cc");
    return Ok != 0;
#else
    unsigned int v;
    int Ok = _rdseed32_step(&v);

    *Value = v;
    return Ok != 0;
#endif
}

/* CPUID leaf 7, subleaf 0, EBX bit 18 */
static
BOOLEAN
KsecRngHaveRdseed(VOID)
{
    int Info[4];

    __cpuid(Info, 0);
    if ((ULONG)Info[0] < 7)
        return FALSE;
    __cpuidex(Info, 7, 0);
    return (Info[1] & (1 << 18)) != 0;
}

/* Up to KSEC_RNG_HW_WORDS words from one instruction; Tries attempts per word (RDSEED runs dry under load and
   needs more than RDRAND). Returns how many words were delivered */
static
ULONG
KsecRngHardware(
    PCRYPTLIB_SHA256_CTX Pool,
    BOOLEAN (*Read)(PULONG),
    ULONG Tries)
{
    ULONG i, Try, Value, Words = 0;

    for (i = 0; i < KSEC_RNG_HW_WORDS; i++)
    {
        for (Try = 0; Try < Tries; Try++)
        {
            Value = 0;
            if (Read(&Value) && Value != 0 && Value != 0xFFFFFFFF)
            {
                Sha256Update(Pool, &Value, sizeof(Value));
                Words++;
                break;
            }
            YieldProcessor();
        }
    }
    Value = 0;
    return Words;
}
#endif

/* Cycle counter around performance counter queries (in a virtual machine the query exits to the host, which
   makes the interval vary); every raw reading goes into the pool, the number of distinct intervals is reported */
static
VOID
KsecRngJitter(PCRYPTLIB_SHA256_CTX Pool, PKSEC_RNG_SOURCES Sources)
{
    ULONGLONG Deltas[KSEC_RNG_JITTER_SAMPLES];
    ULONGLONG Before, After;
    LARGE_INTEGER Counter;
    ULONG i, k;

    for (i = 0; i < KSEC_RNG_JITTER_SAMPLES; i++)
    {
        Before = KsecRngCycles();
        Counter = KeQueryPerformanceCounter(NULL);
        After = KsecRngCycles();
        Deltas[i] = After - Before;
        Sha256Update(Pool, &Before, sizeof(Before));
        Sha256Update(Pool, &Counter, sizeof(Counter));
        Sha256Update(Pool, &After, sizeof(After));
    }

    Sources->JitterSamples = KSEC_RNG_JITTER_SAMPLES;
    Sources->JitterDistinct = 0;
    for (i = 0; i < KSEC_RNG_JITTER_SAMPLES; i++)
    {
        for (k = 0; k < i && Deltas[k] != Deltas[i]; k++)
            ;
        if (k == i)
            Sources->JitterDistinct++;
    }
}

/* Per-processor counters (interrupts, DPCs, idle/kernel/user time) */
static
VOID
KsecRngSystemState(PCRYPTLIB_SHA256_CTX Pool)
{
    ULONG Cpus = min((ULONG)KeNumberProcessors, KSEC_RNG_MAX_CPUS);
    ULONG Size, ReturnLength;
    PVOID Buffer;

    Size = max(sizeof(SYSTEM_INTERRUPT_INFORMATION), sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)) * Cpus;
    Size = max(Size, (ULONG)sizeof(SYSTEM_PERFORMANCE_INFORMATION));
    Buffer = ExAllocatePoolWithTag(PagedPool, Size, TAG_KSEC_RNG);
    if (!Buffer)
        return;

    if (NT_SUCCESS(ZwQuerySystemInformation(SystemInterruptInformation, Buffer,
                                            sizeof(SYSTEM_INTERRUPT_INFORMATION) * Cpus, &ReturnLength)))
    {
        Sha256Update(Pool, Buffer, min(ReturnLength, Size));
    }
    if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessorPerformanceInformation, Buffer,
                                            sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * Cpus,
                                            &ReturnLength)))
    {
        Sha256Update(Pool, Buffer, min(ReturnLength, Size));
    }
    if (NT_SUCCESS(ZwQuerySystemInformation(SystemPerformanceInformation, Buffer,
                                            sizeof(SYSTEM_PERFORMANCE_INFORMATION), &ReturnLength)))
    {
        Sha256Update(Pool, Buffer, min(ReturnLength, Size));
    }

    RtlSecureZeroMemory(Buffer, Size);
    ExFreePoolWithTag(Buffer, TAG_KSEC_RNG);
}

/* HKLM\SYSTEM\RNG\Seed into the pool (the first seed only) */
static
BOOLEAN
KsecRngReadSavedSeed(PCRYPTLIB_SHA256_CTX Pool)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(KSEC_RNG_KEY_NAME);
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(KSEC_RNG_VALUE_NAME);
    OBJECT_ATTRIBUTES Attributes;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + KSEC_RNG_SEED_SIZE];
    PKEY_VALUE_PARTIAL_INFORMATION Info = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    HANDLE Key;
    ULONG Length;
    BOOLEAN Found = FALSE;

    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&Key, KEY_QUERY_VALUE, &Attributes)))
        return FALSE;

    if (NT_SUCCESS(ZwQueryValueKey(Key, &ValueName, KeyValuePartialInformation, Info, sizeof(Buffer), &Length)) &&
        Info->Type == REG_BINARY && Info->DataLength == KSEC_RNG_SEED_SIZE)
    {
        Sha256Update(Pool, Info->Data, Info->DataLength);
        Found = TRUE;
    }

    RtlSecureZeroMemory(Buffer, sizeof(Buffer));
    ZwClose(Key);
    return Found;
}

/* Hashes all sources into Material (32 bytes); PASSIVE_LEVEL */
static
VOID
KsecRngCollect(
    _Out_writes_bytes_(SHA256_DIGEST_SIZE) PUCHAR Material,
    _Out_ PKSEC_RNG_SOURCES Sources,
    _In_ BOOLEAN ReadSavedSeed)
{
    CRYPTLIB_SHA256_CTX Pool;
    KSEC_ENTROPY_DATA EntropyData;
    LARGE_INTEGER Time, Frequency;
    ULONGLONG Value;

    /* first the time this runs (for a reseed: when the clock interrupt woke the thread), against the cycle counter */
    Value = KsecRngCycles();
    RtlZeroMemory(Sources, sizeof(*Sources));
    Sha256Init(&Pool);
    Sha256Update(&Pool, "ReactOS ksecdd seed", sizeof("ReactOS ksecdd seed"));
    Sha256Update(&Pool, &Value, sizeof(Value));
    Value = KeQueryInterruptTime();
    Sha256Update(&Pool, &Value, sizeof(Value));

#if defined(_M_IX86) || defined(_M_AMD64)
    Sources->HaveRdseed = KsecRngHaveRdseed();
    if (Sources->HaveRdseed)
        Sources->RdseedWords = KsecRngHardware(&Pool, KsecRngRdseed, 100);
    Sources->HaveRdrand = ExIsProcessorFeaturePresent(PF_RDRAND_INSTRUCTION_AVAILABLE);
    if (Sources->HaveRdrand)
        Sources->RdrandWords = KsecRngHardware(&Pool, KsecRngRdrand, 10);
#endif

    KsecRngJitter(&Pool, Sources);

    KeQuerySystemTime(&Time);
    Sha256Update(&Pool, &Time, sizeof(Time));
    Value = KeQueryInterruptTime();
    Sha256Update(&Pool, &Value, sizeof(Value));
    KeQueryTickCount(&Time);
    Sha256Update(&Pool, &Time, sizeof(Time));
    Time = KeQueryPerformanceCounter(&Frequency);
    Sha256Update(&Pool, &Time, sizeof(Time));
    Sha256Update(&Pool, &Frequency, sizeof(Frequency));

    KsecRngSystemState(&Pool);

    /* Process/thread ids, environment hash, counters; a failing query only leaves its part zero */
    RtlZeroMemory(&EntropyData, sizeof(EntropyData));
    (VOID)KsecGatherEntropyData(&EntropyData);
    Sha256Update(&Pool, &EntropyData, sizeof(EntropyData));
    RtlSecureZeroMemory(&EntropyData, sizeof(EntropyData));

    if (ReadSavedSeed)
        Sources->SavedSeed = KsecRngReadSavedSeed(&Pool);

    Value = KsecRngCycles();
    Sha256Update(&Pool, &Value, sizeof(Value));

    Sha256Final(&Pool, Material);
}

/* K = SHA-256(label, K, reseed count, material) */
static
VOID
KsecRngMix(_In_reads_bytes_(SHA256_DIGEST_SIZE) const UCHAR *Material)
{
    CRYPTLIB_SHA256_CTX Context;
    UCHAR NewKey[SHA256_DIGEST_SIZE];
    KIRQL OldIrql;

    KeAcquireSpinLock(&KsecRngLock, &OldIrql);
    Sha256Init(&Context);
    Sha256Update(&Context, "ReactOS ksecdd reseed", sizeof("ReactOS ksecdd reseed"));
    Sha256Update(&Context, KsecRngKey, sizeof(KsecRngKey));
    Sha256Update(&Context, &KsecRngReseeds, sizeof(KsecRngReseeds));
    Sha256Update(&Context, Material, SHA256_DIGEST_SIZE);
    Sha256Final(&Context, NewKey);
    RtlCopyMemory(KsecRngKey, NewKey, sizeof(KsecRngKey));
    KsecRngReseeds++;
    KsecRngRequests = 0;
    KeReleaseSpinLock(&KsecRngLock, OldIrql);

    RtlSecureZeroMemory(NewKey, sizeof(NewKey));
}

NTSTATUS
NTAPI
KsecGenRandom(
    PVOID Buffer,
    SIZE_T Length)
{
    UCHAR Block[CHACHA20_BLOCK_SIZE];
    PUCHAR Output = Buffer;
    SIZE_T Chunk;
    KIRQL OldIrql;

    if (!KsecRngReady)
        return STATUS_INTERNAL_ERROR;

    while (Length)
    {
        Chunk = min(Length, KSEC_RNG_REQUEST_MAX);

        /* one block: the next K, and the key of this request */
        KeAcquireSpinLock(&KsecRngLock, &OldIrql);
        ChaCha20Block(KsecRngKey, 0, KsecRngNonce, Block);
        RtlCopyMemory(KsecRngKey, Block, CHACHA20_KEY_SIZE);
        KsecRngRequests++;
        KeReleaseSpinLock(&KsecRngLock, OldIrql);

        if (Chunk <= CHACHA20_BLOCK_SIZE - CHACHA20_KEY_SIZE)
            RtlCopyMemory(Output, Block + CHACHA20_KEY_SIZE, Chunk);
        else
            ChaCha20KeyStream(Block + CHACHA20_KEY_SIZE, 0, KsecRngNonce, Output, Chunk);

        Output += Chunk;
        Length -= Chunk;
    }

    RtlSecureZeroMemory(Block, sizeof(Block));
    return STATUS_SUCCESS;
}

/* Kernel-mode BCryptGenRandom (documented for drivers; exported by ksecdd.sys in Windows Vista and by cng.sys):
   the system-preferred RNG, either with a NULL handle and BCRYPT_USE_SYSTEM_PREFERRED_RNG or with the RNG
   pseudo-handle. BCRYPT_RNG_USE_ENTROPY_IN_BUFFER is accepted and ignored, as in Windows 8 and later */
NTSTATUS
NTAPI
BCryptGenRandom(
    _In_opt_ PVOID Algorithm,
    _Out_writes_bytes_(Count) PUCHAR Buffer,
    _In_ ULONG Count,
    _In_ ULONG Flags)
{
    if (Flags & ~(KSEC_BCRYPT_RNG_USE_ENTROPY_IN_BUFFER | KSEC_BCRYPT_USE_SYSTEM_PREFERRED_RNG))
        return STATUS_INVALID_PARAMETER;

    if (Algorithm == NULL)
    {
        if (!(Flags & KSEC_BCRYPT_USE_SYSTEM_PREFERRED_RNG))
            return STATUS_INVALID_HANDLE;
    }
    else if (Algorithm != KSEC_BCRYPT_RNG_ALG_HANDLE || (Flags & KSEC_BCRYPT_USE_SYSTEM_PREFERRED_RNG))
    {
        return STATUS_INVALID_HANDLE;
    }

    if (!Count)
        return STATUS_SUCCESS;
    if (!Buffer)
        return STATUS_INVALID_PARAMETER;

    return KsecGenRandom(Buffer, Count);
}

/* RFC 8439 2.3.2 and FIPS 180-2 B.1 */
static
BOOLEAN
KsecRngSelfTest(VOID)
{
    static const UCHAR Nonce[CHACHA20_NONCE_SIZE] = { 0, 0, 0, 0x09, 0, 0, 0, 0x4a, 0, 0, 0, 0 };
    static const UCHAR ExpectedBlock[CHACHA20_BLOCK_SIZE] =
    {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };
    static const UCHAR ExpectedDigest[SHA256_DIGEST_SIZE] =
    {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    UCHAR Key[CHACHA20_KEY_SIZE];
    UCHAR Output[CHACHA20_BLOCK_SIZE];
    CRYPTLIB_SHA256_CTX Context;
    ULONG i;

    for (i = 0; i < sizeof(Key); i++)
        Key[i] = (UCHAR)i;
    ChaCha20Block(Key, 1, Nonce, Output);
    if (RtlCompareMemory(Output, ExpectedBlock, sizeof(ExpectedBlock)) != sizeof(ExpectedBlock))
        return FALSE;

    Sha256Init(&Context);
    Sha256Update(&Context, "abc", 3);
    Sha256Final(&Context, Output);
    return RtlCompareMemory(Output, ExpectedDigest, sizeof(ExpectedDigest)) == sizeof(ExpectedDigest);
}

/* The DACL of HKLM\SYSTEM\RNG: SYSTEM and Administrators, full access, not inherited from the parent */
static
NTSTATUS
KsecRngMakeSecurity(PSECURITY_DESCRIPTOR Sd, PACL *Dacl)
{
    ULONG Size;
    PACL Acl;
    NTSTATUS Status;

    Size = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) +
           RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid);
    Acl = ExAllocatePoolWithTag(PagedPool, Size, TAG_KSEC_RNG);
    if (!Acl)
        return STATUS_INSUFFICIENT_RESOURCES;

    Status = RtlCreateAcl(Acl, Size, ACL_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAce(Acl, ACL_REVISION, KEY_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAce(Acl, ACL_REVISION, KEY_ALL_ACCESS, SeExports->SeAliasAdminsSid);
    if (NT_SUCCESS(Status))
        Status = RtlCreateSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(Sd, TRUE, Acl, FALSE);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(Acl, TAG_KSEC_RNG);
        return Status;
    }
    ((PISECURITY_DESCRIPTOR)Sd)->Control |= SE_DACL_PROTECTED;
    *Dacl = Acl;
    return STATUS_SUCCESS;
}

/* A new saved seed: 64 bytes of output into HKLM\SYSTEM\RNG\Seed, flushed; PASSIVE_LEVEL */
static
NTSTATUS
KsecRngSaveSeed(VOID)
{
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(KSEC_RNG_KEY_NAME);
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(KSEC_RNG_VALUE_NAME);
    OBJECT_ATTRIBUTES Attributes;
    SECURITY_DESCRIPTOR Sd;
    PACL Dacl = NULL;
    UCHAR Seed[KSEC_RNG_SEED_SIZE];
    HANDLE Key;
    ULONG Disposition;
    NTSTATUS Status;

    Status = KsecRngMakeSecurity(&Sd, &Dacl);
    if (!NT_SUCCESS(Status))
        return Status;

    InitializeObjectAttributes(&Attributes, &KeyName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &Sd);
    Status = ZwCreateKey(&Key, KEY_SET_VALUE, &Attributes, 0, NULL, REG_OPTION_NON_VOLATILE, &Disposition);
    ExFreePoolWithTag(Dacl, TAG_KSEC_RNG);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = KsecGenRandom(Seed, sizeof(Seed));
    if (NT_SUCCESS(Status))
        Status = ZwSetValueKey(Key, &ValueName, 0, REG_BINARY, Seed, sizeof(Seed));
    if (NT_SUCCESS(Status))
        Status = ZwFlushKey(Key);

    RtlSecureZeroMemory(Seed, sizeof(Seed));
    ZwClose(Key);
    return Status;
}

/* The reseed thread: sleeps for the interval, reseeds, doubles the interval up to KSEC_RNG_MAX_INTERVAL; writes
   the saved seed once the start is KSEC_RNG_SAVE_AFTER seconds old */
static
VOID
NTAPI
KsecRngThread(
    _In_ PVOID Context)
{
    UCHAR Material[SHA256_DIGEST_SIZE];
    KSEC_RNG_SOURCES Sources;
    LARGE_INTEGER Delay;
    ULONGLONG Uptime;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Context);

    for (;;)
    {
        Delay.QuadPart = -(LONGLONG)KsecRngInterval * 10000000;
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);

        KsecRngCollect(Material, &Sources, FALSE);
        KsecRngMix(Material);
        RtlSecureZeroMemory(Material, sizeof(Material));

        Uptime = (KeQueryInterruptTime() - KsecRngStartTime) / 10000000;
        if (KsecRngReseeds <= KSEC_RNG_LOG_RESEEDS || !(KsecRngReseeds % 16))
        {
            DbgPrint("KSECDD: RNG reseed %lu at %I64u s (interval %lu s): RDSEED %lu, RDRAND %lu words, %lu of %lu "
                     "timing intervals distinct\n", KsecRngReseeds, Uptime, KsecRngInterval, Sources.RdseedWords,
                     Sources.RdrandWords, Sources.JitterDistinct, Sources.JitterSamples);
        }

        /* the saved seed for the next start, once the registry is writable */
        if (!KsecRngSeedSaved && Uptime >= KSEC_RNG_SAVE_AFTER)
        {
            Status = KsecRngSaveSeed();
            KsecRngSeedSaved = NT_SUCCESS(Status);
            DbgPrint("KSECDD: RNG saved seed replaced after start: 0x%lx\n", Status);
        }

        KsecRngInterval = min(KsecRngInterval * 2, KSEC_RNG_MAX_INTERVAL);
    }
}

/* DriverEntry, PASSIVE_LEVEL: self-test, the first seed, the reseed thread */
NTSTATUS
NTAPI
KsecInitializeRandom(
    _In_ PDEVICE_OBJECT DeviceObject)
{
    UCHAR Material[SHA256_DIGEST_SIZE];
    KSEC_RNG_SOURCES Sources;
    LARGE_INTEGER Start, End, Frequency;
    ULONG Microseconds;
    HANDLE Thread;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    KeInitializeSpinLock(&KsecRngLock);

    if (!KsecRngSelfTest())
    {
        DbgPrint("KSECDD: RNG self-test FAILED, the system random number generator is disabled\n");
        return STATUS_INTERNAL_ERROR;
    }

    Start = KeQueryPerformanceCounter(&Frequency);
    KsecRngStartTime = KeQueryInterruptTime();

    KsecRngCollect(Material, &Sources, TRUE);
    KsecRngMix(Material);
    RtlSecureZeroMemory(Material, sizeof(Material));
    KsecRngReady = TRUE;

    End = KeQueryPerformanceCounter(NULL);
    Microseconds = (ULONG)((End.QuadPart - Start.QuadPart) * 1000000 / max(Frequency.QuadPart, 1));
    DbgPrint("KSECDD: RNG seeded in %lu us: self-test passed, RDSEED %s (%lu of %lu words), RDRAND %s (%lu of %lu "
             "words), %lu of %lu timing intervals distinct, saved seed %s\n", Microseconds,
             Sources.HaveRdseed ? "present" : "absent", Sources.RdseedWords, (ULONG)KSEC_RNG_HW_WORDS,
             Sources.HaveRdrand ? "present" : "absent", Sources.RdrandWords, (ULONG)KSEC_RNG_HW_WORDS,
             Sources.JitterDistinct, Sources.JitterSamples, Sources.SavedSeed ? "read" : "absent");

    /* reseed after 1 s, then doubling up to KSEC_RNG_MAX_INTERVAL */
    KsecRngInterval = 1;
    Status = PsCreateSystemThread(&Thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, KsecRngThread, NULL);
    if (NT_SUCCESS(Status))
        ZwClose(Thread);
    else
        DbgPrint("KSECDD: RNG reseed thread not started: 0x%lx\n", Status);

    return STATUS_SUCCESS;
}

/* IRP_MJ_SHUTDOWN (before the registry is shut down): the saved seed for the next start */
VOID
NTAPI
KsecShutdownRandom(VOID)
{
    NTSTATUS Status;

    if (!KsecRngReady)
        return;

    Status = KsecRngSaveSeed();
    DbgPrint("KSECDD: RNG saved seed written at shutdown: 0x%lx (%lu seedings since the start)\n", Status,
             KsecRngReseeds);
}

VOID
NTAPI
KsecReadMachineSpecificCounters(
    _Out_ PKSEC_MACHINE_SPECIFIC_COUNTERS MachineSpecificCounters)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    /* Check if RDTSC is available */
    if (ExIsProcessorFeaturePresent(PF_RDTSC_INSTRUCTION_AVAILABLE))
    {
        /* Read the TSC value */
        MachineSpecificCounters->Tsc = __rdtsc();
    }
#if 0 // FIXME: investigate what the requirements are for these
    /* Read the CPU event counter MSRs */
    //MachineSpecificCounters->Ctr0 = __readmsr(0x12);
    //MachineSpecificCounters->Ctr1 = __readmsr(0x13);

    /* Check if this is an MMX capable CPU */
    if (ExIsProcessorFeaturePresent(PF_MMX_INSTRUCTIONS_AVAILABLE))
    {
        /* Read the CPU performance counters 0 and 1 */
        MachineSpecificCounters->Pmc0 = __readpmc(0);
        MachineSpecificCounters->Pmc1 = __readpmc(1);
    }
#endif
#elif defined(_M_ARM)
    /* Read the Cycle Counter Register */
    MachineSpecificCounters->Ccr = _MoveFromCoprocessor(CP15_PMCCNTR);
#elif defined(_M_ARM64)
    /* Read the virtual count of the generic timer */
#ifdef _MSC_VER
    MachineSpecificCounters->Cntvct = _ReadStatusReg(ARM64_CNTVCT);
#else
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(MachineSpecificCounters->Cntvct));
#endif
#else
    #error Implement me!
#endif
}

/*!
 *  \see http://blogs.msdn.com/b/michael_howard/archive/2005/01/14/353379.aspx (DEAD_LINK)
 */
NTSTATUS
NTAPI
KsecGatherEntropyData(
    PKSEC_ENTROPY_DATA EntropyData)
{
    MD4_CTX Md4Context;
    PTEB Teb;
    PPEB Peb;
    PWSTR String;
    ULONG ReturnLength;
    NTSTATUS Status;

    /* Query some generic values */
    EntropyData->CurrentProcessId = PsGetCurrentProcessId();
    EntropyData->CurrentThreadId = PsGetCurrentThreadId();
    KeQueryTickCount(&EntropyData->TickCount);
    KeQuerySystemTime(&EntropyData->SystemTime);
    EntropyData->PerformanceCounter = KeQueryPerformanceCounter(
                                            &EntropyData->PerformanceFrequency);

    /* Check if we have a TEB/PEB for the process environment */
    Teb = PsGetCurrentThread()->Tcb.Teb;
    if (Teb != NULL)
    {
        Peb = Teb->ProcessEnvironmentBlock;

        /* Initialize the MD4 context */
        MD4Init(&Md4Context);
        _SEH2_TRY
        {
            /* Get the end of the environment */
            String = Peb->ProcessParameters->Environment;
            while (*String)
            {
                String += wcslen(String) + 1;
            }

            /* Update the MD4 context from the environment data */
            MD4Update(&Md4Context,
                      (PUCHAR)Peb->ProcessParameters->Environment,
                      (ULONG)((PUCHAR)String - (PUCHAR)Peb->ProcessParameters->Environment));
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Simply ignore the exception */
        }
        _SEH2_END;

        /* Finalize and copy the MD4 hash */
        MD4Final(&Md4Context);
        RtlCopyMemory(&EntropyData->EnvironmentHash, Md4Context.digest, 16);
    }

    /* Read some machine specific hardware counters */
    KsecReadMachineSpecificCounters(&EntropyData->MachineSpecificCounters);

    /* Query processor performance information */
    Status = ZwQuerySystemInformation(SystemProcessorPerformanceInformation,
                                      &EntropyData->SystemProcessorPerformanceInformation,
                                      sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION),
                                      &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Query system performance information */
    Status = ZwQuerySystemInformation(SystemPerformanceInformation,
                                      &EntropyData->SystemPerformanceInformation,
                                      sizeof(SYSTEM_PERFORMANCE_INFORMATION),
                                      &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Query exception information */
    Status = ZwQuerySystemInformation(SystemExceptionInformation,
                                      &EntropyData->SystemExceptionInformation,
                                      sizeof(SYSTEM_EXCEPTION_INFORMATION),
                                      &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Query lookaside information */
    Status = ZwQuerySystemInformation(SystemLookasideInformation,
                                      &EntropyData->SystemLookasideInformation,
                                      sizeof(SYSTEM_LOOKASIDE_INFORMATION),
                                      &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Query interrupt information */
    Status = ZwQuerySystemInformation(SystemInterruptInformation,
                                      &EntropyData->SystemInterruptInformation,
                                      sizeof(SYSTEM_INTERRUPT_INFORMATION),
                                      &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Query process information */
    Status = ZwQuerySystemInformation(SystemProcessInformation,
                                      &EntropyData->SystemProcessInformation,
                                      sizeof(SYSTEM_PROCESS_INFORMATION),
                                      &ReturnLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return STATUS_SUCCESS;
}
