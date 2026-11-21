/*
 * PROJECT:     ReactOS Win32 Base API
 * PURPOSE:     The locale names CompareStringEx and FindNLSStringEx took lately
 *
 * Sorting and searching call CompareStringEx with the same name again and again, and checking a name (the grammar of a
 * tag, the pseudo-locales, the locale table) costs several times the comparison of a short string. A name that was
 * taken is remembered in one of a few slots; the test for a remembered name is inline, so a call that hits pays no
 * more than the hash and the comparison with the slot. Each slot is a seqlock: a reader takes the name only when the
 * counter was even before it compared and unchanged after it, so it never takes a name that is being written.
 */

#pragma once

#if defined(_MSC_VER)
#include <intrin.h>
#endif

/* All the readers (the loads below) stay behind the first and in front of the second read of the counter */
#if defined(__GNUC__)
#define BASEP_NAME_CACHE_BARRIER() __asm__ __volatile__("" : : : "memory")
#else
#define BASEP_NAME_CACHE_BARRIER() _ReadWriteBarrier()
#endif

#define BASEP_NAME_CACHE_SLOTS 32 /* a power of 2 */
#define BASEP_NAME_CACHE_CHARS 85 /* LOCALE_NAME_MAX_LENGTH: 84 characters and the terminator */
/* one more, never written: a terminator at the end of every slot, so the loop below needs no index test */
#define BASEP_NAME_CACHE_WIDTH (BASEP_NAME_CACHE_CHARS + 1)

extern volatile LONG BasepAcceptedSeq[BASEP_NAME_CACHE_SLOTS];
extern WCHAR BasepAcceptedName[BASEP_NAME_CACHE_SLOTS][BASEP_NAME_CACHE_WIDTH];

/* The slot of a name. name[0] is not 0: name[1] can be read, and name[2] and name[3] when the character before is not 0.
   The fourth character tells "en-US" from "en-GB", the first two the language. */
static __inline ULONG
BasepAcceptedNameSlot(
    _In_ LPCWSTR name)
{
    ULONG h = (ULONG)name[0] * 31 + (ULONG)name[1] * 7;

    if (name[1] && name[2])
        h += (ULONG)name[3] * 13;
    return (h ^ (h >> 3)) & (BASEP_NAME_CACHE_SLOTS - 1);
}

/* Whether name (not NULL, not empty) is remembered as taken */
static __inline BOOL
BasepIsAcceptedNameCached(
    _In_ LPCWSTR name)
{
    ULONG slot = BasepAcceptedNameSlot(name), i;
    LONG seq = BasepAcceptedSeq[slot];
    WCHAR c;

    if (seq & 1)
        return FALSE;
#if defined(_M_IX86) || defined(_M_AMD64)
    BASEP_NAME_CACHE_BARRIER();
#else
    /* the full barrier keeps the reads below behind this one */
    (VOID)InterlockedCompareExchange(&BasepAcceptedSeq[slot], seq, seq);
#endif
    /* the slot ends with a terminator that is never overwritten: the loop stops at the latest there, and a name of
       85 characters or more differs from the slot at that index or before */
    i = 0;
#if defined(_M_IX86) || defined(_M_AMD64)
    {
        /* The first two characters in one load: name[0] is not 0, so name[1] is a character or the terminator, and both
           are readable (unaligned loads are fine here) */
        ULONG a, b;

        RtlCopyMemory(&a, &BasepAcceptedName[slot][0], sizeof(a));
        RtlCopyMemory(&b, name, sizeof(b));
        if (a != b)
            return FALSE;
        if (!name[1])
            goto compared; /* a name of one character */
        i = 2;
    }
#endif
    while ((c = BasepAcceptedName[slot][i]) == name[i] && c)
        i++;
    if (c != name[i])
        return FALSE;
#if defined(_M_IX86) || defined(_M_AMD64)
compared:
    /* loads are not reordered with other loads here, the compiler must not either */
    BASEP_NAME_CACHE_BARRIER();
    return BasepAcceptedSeq[slot] == seq;
#else
    /* the full barrier keeps the reads above before this one */
    return InterlockedCompareExchange(&BasepAcceptedSeq[slot], seq, seq) == seq;
#endif
}
