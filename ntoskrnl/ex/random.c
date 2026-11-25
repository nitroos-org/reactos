/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Random bytes for the kernel's own secrets (image security cookies, UUID node and sequence,
 *              the registry ACL generation): from the system generator once it is there, else from the processor
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The system generator is in ksecdd.sys, a boot driver. It registers itself here (ExRegisterRandomProvider) after
 * its first seed, so every consumer that runs later draws from it. Before that (the images loaded ahead of it, the
 * first moments of the boot) the bytes come from RDRAND where the processor has it (CPUID bit checked at start-up,
 * a failed or all-zero / all-ones word is dropped), then from the clocks of the machine mixed through splitmix64:
 * the weakest source, kept so that a request never fails.
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

static PEX_RANDOM_PROVIDER ExpRandomProvider;

/* FUNCTIONS ******************************************************************/

#if defined(_M_IX86) || defined(_M_AMD64)
static
BOOLEAN
ExpRdrand(PULONG Value)
{
    UCHAR Ok;
    ULONG Word;
    ULONG Tries;

    if (!(KeFeatureBits & KF_RDRAND))
        return FALSE;

    for (Tries = 0; Tries < 10; Tries++)
    {
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("rdrand %0; setc %1" : "=r"(Word), "=qm"(Ok) : : "cc");
#else
        Ok = (UCHAR)_rdrand32_step(&Word);
#endif
        /* what broken implementations return with success */
        if (Ok && Word != 0 && Word != 0xFFFFFFFF)
        {
            *Value = Word;
            return TRUE;
        }
    }
    return FALSE;
}
#endif

static
ULONG64
ExpSplitMix(ULONG64 Value)
{
    Value += 0x9E3779B97F4A7C15ULL;
    Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ULL;
    Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBULL;
    return Value ^ (Value >> 31);
}

/*
 * Fills Buffer with Length bytes (at most DISPATCH_LEVEL). Never fails; *FromSystem tells whether the bytes came from
 * the system generator (TRUE), or from the processor and the clocks only (FALSE).
 */
VOID
NTAPI
ExpGetRandomBytes(
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _Out_opt_ PBOOLEAN FromSystem)
{
    PEX_RANDOM_PROVIDER Provider = ExpRandomProvider;
    PUCHAR Output = Buffer;
    LARGE_INTEGER Counter, Time;
    ULONG64 State;
    ULONG Word, Done = 0, i;
    static volatile LONG ExpRandomCounter;

    if (FromSystem)
        *FromSystem = FALSE;

    if (Provider != NULL && NT_SUCCESS(Provider(Buffer, Length)))
    {
        if (FromSystem)
            *FromSystem = TRUE;
        return;
    }

    /* the clocks, the address of this request and a counter: the floor under the processor's words */
    Counter = KeQueryPerformanceCounter(NULL);
    KeQuerySystemTime(&Time);
    State = (ULONG64)Counter.QuadPart ^ ((ULONG64)Time.QuadPart << 17) ^ KeQueryInterruptTime() ^
            ((ULONG64)(ULONG_PTR)Buffer << 7) ^ ((ULONG64)InterlockedIncrement(&ExpRandomCounter) << 40);

    while (Done < Length)
    {
        ULONG64 Block;

        State = ExpSplitMix(State);
        Block = State;
#if defined(_M_IX86) || defined(_M_AMD64)
        if (ExpRdrand(&Word))
        {
            Block ^= (ULONG64)Word << 32;
            if (ExpRdrand(&Word))
                Block ^= Word;
        }
#endif
        for (i = 0; i < sizeof(Block) && Done < Length; i++, Done++)
            Output[Done] = (UCHAR)(Block >> (8 * i));
    }
}

/*
 * @implemented
 *
 * The system generator (ksecdd.sys) says here that it can answer; a later call replaces the provider.
 */
VOID
NTAPI
ExRegisterRandomProvider(
    _In_ PEX_RANDOM_PROVIDER Provider)
{
    InterlockedExchangePointer((PVOID *)&ExpRandomProvider, Provider);
}
