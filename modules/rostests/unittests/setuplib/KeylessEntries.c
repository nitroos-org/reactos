/*
 * PROJECT:     ReactOS Setup Library - Unit-tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for ResolveKeylessPaths: which partition the boot entries without GUID keys belong to
 */

#include "precomp.h"

#include <utils/osdetect.h>

/*
 * The layouts are the partition tables of the UEFI test disks (GPT, 12 GiB), numbered by position as the
 * loader and Setup number them (1 = EFI system partition):
 *   - "stale":  install 1 was made as partition 3 behind a reserved partition 2; the host deleted partition 2
 *               and added a partition, so install 1 is partition 2 now and the entries still say partition(3)
 *   - "two":    two installations side by side (partitions 2 and 3)
 * A partition holds the installation paths given in Holds (an empty list: nothing there, or not formatted).
 */
typedef struct _TESTPART
{
    BOOLEAN Usable;
    BOOLEAN Claimed;
    const WCHAR *Holds[2];
} TESTPART;

static BOOLEAN NTAPI
TestHolds(
    _In_ PVOID Context,
    _In_ PCWSTR Tail)
{
    const TESTPART *Part = Context;
    ULONG i;

    for (i = 0; i < _countof(Part->Holds) && Part->Holds[i]; ++i)
    {
        if (!_wcsicmp(Part->Holds[i], Tail))
            return TRUE;
    }
    return FALSE;
}

/* Runs the resolver; Stored[i] is the position (index) of the partition that the stored number of path i names */
static void
Resolve(
    TESTPART *Parts,
    ULONG PartCount,
    const WCHAR **Tails,
    const LONG *Stored,
    ULONG PathCount,
    const LONG *Expected,
    const char *Name)
{
    KEYLESS_PART KParts[8];
    KEYLESS_PATH Paths[MAX_KEYLESS_PATHS];
    ULONG i;

    for (i = 0; i < PartCount; ++i)
    {
        KParts[i].Usable = Parts[i].Usable;
        KParts[i].Claimed = Parts[i].Claimed;
        KParts[i].Context = &Parts[i];
    }
    for (i = 0; i < PathCount; ++i)
    {
        Paths[i].Tail = Tails[i];
        Paths[i].Stored = Stored[i];
        Paths[i].Found = -2;
    }
    ResolveKeylessPaths(PathCount, Paths, PartCount, KParts, TestHolds);
    for (i = 0; i < PartCount; ++i)
        Parts[i].Claimed = KParts[i].Claimed;
    for (i = 0; i < PathCount; ++i)
        ok(Paths[i].Found == Expected[i], "%s: path %lu: found %ld, expected %ld\n", Name, i, Paths[i].Found, Expected[i]);
}

/*
 * The partition tables of two disk images of the UEFI rows (sgdisk -p of the disk, numbered by position), as they
 * are when Setup starts its search for the second installation:
 *   "stale": install 1 sits at sectors 444416-6588415 (its reserved partition in front of it was deleted and a
 *            new partition added behind it); the entries of install 1 still say partition(3)
 *   "gone":  install 1's partition was deleted and two new ones made (500 MB, 3000 MB); the entries say partition(3)
 */
typedef struct _IMAGEPART
{
    ULONGLONG First, Last;
    BOOLEAN Usable;
    const WCHAR *Holds;
} IMAGEPART;

static void
ImageLayout(
    const IMAGEPART *Image,
    ULONG Count,
    LONG Stored,
    LONG ExpectedIndex,
    const char *Name)
{
    TESTPART Parts[4];
    KEYLESS_PART KParts[4];
    KEYLESS_PATH Path;
    ULONG i;

    for (i = 0; i < Count; ++i)
    {
        Parts[i].Usable = Image[i].Usable;
        Parts[i].Claimed = FALSE;
        Parts[i].Holds[0] = Image[i].Holds;
        Parts[i].Holds[1] = NULL;
        KParts[i].Usable = Image[i].Usable;
        KParts[i].Claimed = FALSE;
        KParts[i].Context = &Parts[i];
    }
    Path.Tail = L"\\Windows";
    Path.Stored = Stored;
    Path.Found = -2;
    ResolveKeylessPaths(1, &Path, Count, KParts, TestHolds);
    ok(Path.Found == ExpectedIndex, "%s: found %ld, expected %ld\n", Name, Path.Found, ExpectedIndex);
    if (Path.Found >= 0 && ExpectedIndex >= 0)
    {
        ok(Image[Path.Found].First == Image[ExpectedIndex].First && Image[Path.Found].Last == Image[ExpectedIndex].Last,
           "%s: range %I64u-%I64u\n", Name, Image[Path.Found].First, Image[Path.Found].Last);
    }
}

static void
test_image_layouts(void)
{
    static const IMAGEPART Stale[] =
    {
        {    2048,  411647, FALSE, NULL },                  /* EFI system partition */
        {  444416, 6588415, TRUE,  L"\\Windows" },          /* install 1 */
        { 6588416, 12732415, FALSE, NULL },                 /* the new partition, not formatted yet */
    };
    static const IMAGEPART Gone[] =
    {
        {    2048,  411647, FALSE, NULL },
        {  411648, 1435647, FALSE, NULL },                  /* 500 MB */
        { 1435648, 7579647, FALSE, NULL },                  /* 3000 MB, the target of install 2 */
    };

    ImageLayout(Stale, _countof(Stale), 2, 1, "image 'stale'");
    ImageLayout(Gone, _countof(Gone), 2, -1, "image 'gone'");
}

START_TEST(KeylessEntries)
{
    test_image_layouts();

    /* the installation at its stored position (no table change) */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows" } } };
        const WCHAR *Tails[] = { L"\\Windows" };
        LONG Stored[] = { 1 }, Expected[] = { 1 };
        Resolve(Parts, 2, Tails, Stored, 1, Expected, "plain");
        ok(Parts[1].Claimed, "plain: the partition must be claimed\n");
    }

    /* stale: the stored position (3) names a new partition without an installation, install 1 moved to 2 */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows" } }, { FALSE, FALSE, {0} } };
        const WCHAR *Tails[] = { L"\\Windows" };
        LONG Stored[] = { 2 }, Expected[] = { 1 };
        Resolve(Parts, 3, Tails, Stored, 1, Expected, "stale");
    }

    /* stale, the new partition is formatted but holds no installation (a data partition) */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows" } }, { TRUE, FALSE, {0} } };
        const WCHAR *Tails[] = { L"\\Windows" };
        LONG Stored[] = { 2 }, Expected[] = { 1 };
        Resolve(Parts, 3, Tails, Stored, 1, Expected, "stale, formatted data partition");
    }

    /* the partition is gone: nothing holds the installation, the entry is not identified */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, {0} } };
        const WCHAR *Tails[] = { L"\\Windows" };
        LONG Stored[] = { 1 }, Expected[] = { -1 };
        Resolve(Parts, 2, Tails, Stored, 1, Expected, "gone");
    }

    /* the stored position holds another installation of the same path (two installs, table swapped):
     * nothing more can be verified, it is identified as that one (a limit of the design) */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows" } }, { TRUE, FALSE, { L"\\Windows" } } };
        const WCHAR *Tails[] = { L"\\Windows" };
        LONG Stored[] = { 2 }, Expected[] = { 2 };
        Resolve(Parts, 3, Tails, Stored, 1, Expected, "stored position holds another one");
    }

    /* two candidates at the path, none at the stored position: not told apart */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows" } }, { TRUE, FALSE, { L"\\Windows" } },
                             { FALSE, FALSE, {0} } };
        const WCHAR *Tails[] = { L"\\Windows" };
        LONG Stored[] = { 3 }, Expected[] = { -1 };
        Resolve(Parts, 4, Tails, Stored, 1, Expected, "two candidates");
    }

    /* the one candidate is named by an entry with a GUID already: not available */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, TRUE, { L"\\Windows" } }, { FALSE, FALSE, {0} } };
        const WCHAR *Tails[] = { L"\\Windows" };
        LONG Stored[] = { 2 }, Expected[] = { -1 };
        Resolve(Parts, 3, Tails, Stored, 1, Expected, "claimed by GUID");
    }

    /* two paths, two installations: each is found */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows" } }, { TRUE, FALSE, { L"\\Other" } },
                             { FALSE, FALSE, {0} } };
        const WCHAR *Tails[] = { L"\\Windows", L"\\Other" };
        LONG Stored[] = { 3, 3 }, Expected[] = { 1, 2 };
        Resolve(Parts, 4, Tails, Stored, 2, Expected, "two paths");
    }

    /* two paths that both only one partition holds: neither is identified */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows", L"\\Other" } }, { FALSE, FALSE, {0} } };
        const WCHAR *Tails[] = { L"\\Windows", L"\\Other" };
        LONG Stored[] = { 2, 2 }, Expected[] = { -1, -1 };
        Resolve(Parts, 3, Tails, Stored, 2, Expected, "two paths one partition");
    }

    /* a path without a directory, a stored position outside the list */
    {
        TESTPART Parts[] = { { FALSE, FALSE, {0} }, { TRUE, FALSE, { L"\\Windows" } } };
        const WCHAR *Tails[] = { L"" };
        LONG Stored[] = { 5 }, Expected[] = { -1 };
        Resolve(Parts, 2, Tails, Stored, 1, Expected, "no path");
    }
}
