/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for RtlExtractBitMap of ntdll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Every expected value was measured on Windows 10 22H2 (19045), x64 and x86 (WOW64). RtlExtractBitMap(Source,
 * Destination, StartingIndex, NumberOfBits) copies Source bits [StartingIndex, StartingIndex + NumberOfBits) to the
 * start of Destination. The count is cut to the size of the destination and to what the source has after
 * StartingIndex (a destination that is too small gets the bits that fit, nothing is written after its last bit
 * or its last word), and the bits of the destination after the copied ones are not touched.
 */

#include "precomp.h"

typedef struct { ULONG SizeOfBitMap; PULONG Buffer; } TEST_BITMAP;
typedef VOID (NTAPI *PFN_Extract)(TEST_BITMAP *, TEST_BITMAP *, ULONG, ULONG);

/* the source is 96 bits; the destination words start as 0xAAAAAAAA and there are six of them */
static const ULONG Source[3] = { 0x9E3779B9, 0x7F4A7C15, 0xF39CC060 };

static const struct
{
    ULONG DestinationSize;
    ULONG Start;
    ULONG Count;
    ULONG Words[4];
} Rows[] =
{
    {  32,  0,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  0,  7, { 0xaaaaaab9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  0, 32, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  0, 33, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  0, 64, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  0, 70, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  1,  7, { 0xaaaaaadc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  1, 33, { 0xcf1bbcdc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  5, 32, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32,  5, 64, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 31,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 31,  7, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 31, 33, { 0xfe94f82b, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 32,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 32, 33, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 32, 64, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 33,  7, { 0xaaaaaa8a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 33, 64, { 0x3fa53e0a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 64,  1, { 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 64, 32, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  32, 64, 70, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  0,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  0,  7, { 0xaaaaaab9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  0, 32, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  0, 33, { 0x9e3779b9, 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  0, 64, { 0x9e3779b9, 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  0, 70, { 0x9e3779b9, 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  1,  7, { 0xaaaaaadc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  1, 33, { 0xcf1bbcdc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  5, 32, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33,  5, 64, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 31,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 31,  7, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 31, 33, { 0xfe94f82b, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 32,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 32, 33, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 32, 64, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 33,  7, { 0xaaaaaa8a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 33, 64, { 0x3fa53e0a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 64,  1, { 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 64, 32, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  33, 64, 70, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  0,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  0,  7, { 0xaaaaaab9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  0, 32, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  0, 33, { 0x9e3779b9, 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  0, 64, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  0, 70, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  1,  7, { 0xaaaaaadc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  1, 33, { 0xcf1bbcdc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  5, 32, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64,  5, 64, { 0xacf1bbcd, 0x03fa53e0, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 31,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 31,  7, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 31, 33, { 0xfe94f82b, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 32,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 32, 33, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 32, 64, { 0x7f4a7c15, 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 33,  7, { 0xaaaaaa8a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 33, 64, { 0x3fa53e0a, 0xf9ce6030, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 64,  1, { 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 64, 32, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  64, 64, 70, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  0,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  0,  7, { 0xaaaaaab9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  0, 32, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  0, 33, { 0x9e3779b9, 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  0, 64, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  0, 70, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaa0, 0xaaaaaaaa } },
    {  70,  1,  7, { 0xaaaaaadc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  1, 33, { 0xcf1bbcdc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  5, 32, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70,  5, 64, { 0xacf1bbcd, 0x03fa53e0, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 31,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 31,  7, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 31, 33, { 0xfe94f82b, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 32,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 32, 33, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 32, 64, { 0x7f4a7c15, 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 33,  7, { 0xaaaaaa8a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 33, 64, { 0x3fa53e0a, 0xf9ce6030, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 64,  1, { 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 64, 32, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  70, 64, 70, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  0,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  0,  7, { 0xaaaaaab9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  0, 32, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  0, 33, { 0x9e3779b9, 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  0, 64, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  0, 70, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaa0, 0xaaaaaaaa } },
    {  96,  1,  7, { 0xaaaaaadc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  1, 33, { 0xcf1bbcdc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  5, 32, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96,  5, 64, { 0xacf1bbcd, 0x03fa53e0, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 31,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 31,  7, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 31, 33, { 0xfe94f82b, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 32,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 32, 33, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 32, 64, { 0x7f4a7c15, 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 33,  7, { 0xaaaaaa8a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 33, 64, { 0x3fa53e0a, 0xf9ce6030, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 64,  1, { 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 64, 32, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    {  96, 64, 70, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  0,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  0,  7, { 0xaaaaaab9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  0, 32, { 0x9e3779b9, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  0, 33, { 0x9e3779b9, 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  0, 64, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  0, 70, { 0x9e3779b9, 0x7f4a7c15, 0xaaaaaaa0, 0xaaaaaaaa } },
    { 128,  1,  7, { 0xaaaaaadc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  1, 33, { 0xcf1bbcdc, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  5, 32, { 0xacf1bbcd, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128,  5, 64, { 0xacf1bbcd, 0x03fa53e0, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 31,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 31,  7, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 31, 33, { 0xfe94f82b, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 32,  1, { 0xaaaaaaab, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 32, 33, { 0x7f4a7c15, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 32, 64, { 0x7f4a7c15, 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 33,  7, { 0xaaaaaa8a, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 33, 64, { 0x3fa53e0a, 0xf9ce6030, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 64,  1, { 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 64, 32, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
    { 128, 64, 70, { 0xf39cc060, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa } },
};

static void Check(PFN_Extract Extract, ULONG DestinationSize, ULONG Start, ULONG Count, const ULONG *Expected, ULONG ExpectedWords)
{
    ULONG Words[6], i;
    TEST_BITMAP Src = { 96, (PULONG)Source }, Dst = { DestinationSize, Words };

    for (i = 0; i < 6; i++)
        Words[i] = 0xAAAAAAAA;
    Extract(&Src, &Dst, Start, Count);
    ok(Dst.SizeOfBitMap == DestinationSize, "the destination header changed\n");
    for (i = 0; i < 6; i++)
    {
        ULONG Want = i < ExpectedWords ? Expected[i] : 0xAAAAAAAA;

        ok(Words[i] == Want, "dst %lu bits, start %lu, count %lu: word %lu is %08lx, expected %08lx\n",
           DestinationSize, Start, Count, i, Words[i], Want);
    }
}

START_TEST(RtlExtractBitMap)
{
    PFN_Extract Extract = (PFN_Extract)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlExtractBitMap");
    ULONG i;

    if (!Extract)
    {
        ok(!is_reactos(), "RtlExtractBitMap is not exported by ntdll.dll\n");
        skip("RtlExtractBitMap is not exported\n");
        return;
    }

    for (i = 0; i < sizeof(Rows) / sizeof(Rows[0]); i++)
        Check(Extract, Rows[i].DestinationSize, Rows[i].Start, Rows[i].Count, Rows[i].Words, 4);

    /* ones, zeroes, ones: bits 16 to 79 land on bits 0 to 63 */
    {
        static const ULONG Pattern[3] = { 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF };
        ULONG Words[3] = { 0, 0, 0 };
        TEST_BITMAP Src = { 96, (PULONG)Pattern }, Dst = { 96, Words };

        Extract(&Src, &Dst, 16, 64);
        ok(Words[0] == 0x0000FFFF && Words[1] == 0xFFFF0000 && Words[2] == 0, "pattern: %08lx %08lx %08lx\n", Words[0], Words[1], Words[2]);
    }

    /* a range that runs past the end of the source: the bits that exist (80 to 95) */
    {
        ULONG Expected[1] = { 0xAAAAF39C };

        Check(Extract, 192, 80, 32, Expected, 1);
    }

    /* no bits: nothing is written. A start at or after the end of the source is not tested: Windows does not check it
     * and reads past the source buffer (measured: one bit of whatever was there was copied on x86) */
    Check(Extract, 192, 0, 0, NULL, 0);
}
