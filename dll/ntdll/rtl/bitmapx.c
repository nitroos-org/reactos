/*
 * PROJECT:     ReactOS NT User Mode Library
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Bitmap functions of ntdll on Windows 8 and later that the kernel library does not have
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The behaviour, including the answer of the range counters to a range that does not fit, is measured on
 * Windows 10 22H2.
 */

#include <ntdll.h>

#define NDEBUG
#include <debug.h>

#define BITS_PER_ULONG (sizeof(ULONG) * 8)

/* Sets (Value != 0) or clears the Count (at most 32) bits starting at bit Position, with interlocked operations */
static
VOID
RtlpInterlockedBitRun(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG NumberToSet,
    _In_ BOOLEAN Set)
{
    PLONG Buffer = (PLONG)BitMapHeader->Buffer + (StartingIndex / BITS_PER_ULONG);
    ULONG Bit = StartingIndex % BITS_PER_ULONG;

    while (NumberToSet != 0)
    {
        ULONG InThisWord = min(NumberToSet, BITS_PER_ULONG - Bit);
        ULONG Mask = (InThisWord == BITS_PER_ULONG) ? 0xFFFFFFFF : (((1UL << InThisWord) - 1) << Bit);

        if (Set)
            InterlockedOr(Buffer, Mask);
        else
            InterlockedAnd(Buffer, ~Mask);

        Buffer++;
        NumberToSet -= InThisWord;
        Bit = 0;
    }
}

VOID
NTAPI
RtlInterlockedSetBitRun(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG NumberToSet)
{
    RtlpInterlockedBitRun(BitMapHeader, StartingIndex, NumberToSet, TRUE);
}

VOID
NTAPI
RtlInterlockedClearBitRun(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG NumberToClear)
{
    RtlpInterlockedBitRun(BitMapHeader, StartingIndex, NumberToClear, FALSE);
}

/* Counts the set bits in [StartingIndex, StartingIndex + Length), which must lie within the bitmap */
static
ULONG
RtlpCountSetBitsInRange(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length)
{
    PULONG Buffer = BitMapHeader->Buffer + (StartingIndex / BITS_PER_ULONG);
    ULONG Bit = StartingIndex % BITS_PER_ULONG;
    ULONG Count = 0;

    while (Length != 0)
    {
        ULONG InThisWord = min(Length, BITS_PER_ULONG - Bit);
        ULONG Value = *Buffer++ >> Bit;

        if (InThisWord < BITS_PER_ULONG)
            Value &= (1UL << InThisWord) - 1;

        /* Kernighan's count of the set bits */
        while (Value != 0)
        {
            Value &= Value - 1;
            Count++;
        }

        Length -= InThisWord;
        Bit = 0;
    }

    return Count;
}

ULONG
NTAPI
RtlNumberOfSetBitsInRange(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length)
{
    if (Length == 0 || StartingIndex >= BitMapHeader->SizeOfBitMap ||
        Length > BitMapHeader->SizeOfBitMap - StartingIndex)
    {
        return 0xFFFFFFFF;
    }

    return RtlpCountSetBitsInRange(BitMapHeader, StartingIndex, Length);
}

ULONG
NTAPI
RtlNumberOfClearBitsInRange(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_ ULONG StartingIndex,
    _In_ ULONG Length)
{
    if (Length == 0 || StartingIndex >= BitMapHeader->SizeOfBitMap ||
        Length > BitMapHeader->SizeOfBitMap - StartingIndex)
    {
        return 0xFFFFFFFF;
    }

    return Length - RtlpCountSetBitsInRange(BitMapHeader, StartingIndex, Length);
}

VOID
NTAPI
RtlCopyBitMap(
    _In_ PRTL_BITMAP Source,
    _In_ PRTL_BITMAP Destination,
    _In_ ULONG DestinationBitIndex)
{
    ULONG Count = Source->SizeOfBitMap;
    ULONG Done = 0;

    /* The part of the source that fits; the other bits of the destination are not touched */
    if (DestinationBitIndex >= Destination->SizeOfBitMap)
        return;
    Count = min(Count, Destination->SizeOfBitMap - DestinationBitIndex);

    while (Done < Count)
    {
        ULONG InThisWord = min(Count - Done, BITS_PER_ULONG);
        ULONG Value = Source->Buffer[Done / BITS_PER_ULONG];
        ULONG Position = DestinationBitIndex + Done;
        PULONG Target = Destination->Buffer + (Position / BITS_PER_ULONG);
        ULONG Bit = Position % BITS_PER_ULONG;
        ULONG Mask = (InThisWord == BITS_PER_ULONG) ? 0xFFFFFFFF : ((1UL << InThisWord) - 1);

        Value &= Mask;
        Target[0] = (Target[0] & ~(Mask << Bit)) | (Value << Bit);
        if (Bit != 0 && InThisWord > BITS_PER_ULONG - Bit)
        {
            ULONG Shift = BITS_PER_ULONG - Bit;

            Target[1] = (Target[1] & ~(Mask >> Shift)) | (Value >> Shift);
        }

        Done += InThisWord;
    }
}

/*
 * Copies NumberOfBits bits of Source, from StartingIndex on, to the start of Destination. Measured on Windows 10
 * 22H2: the count is cut to what the destination holds and to what the source has after StartingIndex, so a destination
 * that is too small gets the bits that fit and is not overrun; the bits of the destination after the copied ones are
 * not touched (the rest of the last word too). Nothing is returned.
 */
VOID
NTAPI
RtlExtractBitMap(
    _In_ PRTL_BITMAP Source,
    _In_ PRTL_BITMAP Destination,
    _In_ ULONG StartingIndex,
    _In_ ULONG NumberOfBits)
{
    ULONG Count = NumberOfBits;
    ULONG Done = 0;

    if (StartingIndex >= Source->SizeOfBitMap)
        return;
    Count = min(Count, Source->SizeOfBitMap - StartingIndex);
    Count = min(Count, Destination->SizeOfBitMap);

    while (Done < Count)
    {
        ULONG InThisWord = min(Count - Done, BITS_PER_ULONG);
        ULONG Position = StartingIndex + Done;
        ULONG Bit = Position % BITS_PER_ULONG;
        ULONG Value = Source->Buffer[Position / BITS_PER_ULONG] >> Bit;
        ULONG Mask = (InThisWord == BITS_PER_ULONG) ? 0xFFFFFFFF : ((1UL << InThisWord) - 1);
        PULONG Target = Destination->Buffer + (Done / BITS_PER_ULONG);

        /* The bits that the first source word has left may not be enough: take the rest from the next one */
        if (Bit != 0 && InThisWord > BITS_PER_ULONG - Bit)
            Value |= Source->Buffer[Position / BITS_PER_ULONG + 1] << (BITS_PER_ULONG - Bit);

        /* Done is always a multiple of the word size here, the destination starts at a word boundary */
        Target[0] = (Target[0] & ~Mask) | (Value & Mask);

        Done += InThisWord;
    }
}
