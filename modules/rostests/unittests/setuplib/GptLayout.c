/*
 * PROJECT:     ReactOS Setup Library - Unit-tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the GPT layout rules of gptlayout.c
 */

#include "precomp.h"

#include <utils/gptlayout.h>

static void
test_usable_range(void)
{
    ULONGLONG First, Last;
    BOOLEAN Ret;

    /* 20 GiB, 512-byte sectors: 128 entries take 32 sectors */
    Ret = GptGetUsableRange(41943040ULL, 512, 128, &First, &Last);
    ok(Ret, "20 GiB disk must hold a GPT\n");
    ok(First == 34ULL, "First usable = %I64u, expected 34\n", First);
    ok(Last == 41943040ULL - 34, "Last usable = %I64u, expected %I64u\n", Last, 41943040ULL - 34);

    /* The backup entries end before the backup header in the last sector */
    ok(Last + 1 + GptEntryArraySectors(512, 128) + 1 == 41943040ULL, "layout does not close at the last sector\n");

    /* 3 TiB, 512-byte sectors: more than 2^32 sectors */
    Ret = GptGetUsableRange(6442450944ULL, 512, 128, &First, &Last);
    ok(Ret, "3 TiB disk must hold a GPT\n");
    ok(First == 34ULL, "First usable = %I64u, expected 34\n", First);
    ok(Last == 6442450944ULL - 34, "Last usable = %I64u, expected %I64u\n", Last, 6442450944ULL - 34);
    ok(Last > 0xFFFFFFFFULL, "3 TiB last usable sector must not fit in 32 bits\n");

    /* 4K native sectors: 128 entries take 4 sectors */
    ok(GptEntryArraySectors(4096, 128) == 4, "4Kn entry array sectors\n");
    Ret = GptGetUsableRange(5242880ULL, 4096, 128, &First, &Last);
    ok(Ret, "20 GiB 4Kn disk must hold a GPT\n");
    ok(First == 6ULL, "4Kn first usable = %I64u, expected 6\n", First);
    ok(Last == 5242880ULL - 6, "4Kn last usable = %I64u, expected %I64u\n", Last, 5242880ULL - 6);

    /* 3 TiB with 4K sectors */
    Ret = GptGetUsableRange(805306368ULL, 4096, 128, &First, &Last);
    ok(Ret && First == 6ULL && Last == 805306368ULL - 6, "3 TiB 4Kn: %I64u..%I64u\n", First, Last);

    /* Too small */
    Ret = GptGetUsableRange(66ULL, 512, 128, &First, &Last);
    ok(!Ret, "a 66-sector disk cannot hold a GPT\n");
    ok(First == 0 && Last == 0, "outputs must be cleared on failure\n");
    Ret = GptGetUsableRange(68ULL, 512, 128, &First, &Last);
    ok(Ret && First == 34ULL && Last == 34ULL, "smallest disk: %I64u..%I64u\n", First, Last);
    Ret = GptGetUsableRange(1000ULL, 0, 128, &First, &Last);
    ok(!Ret, "zero sector size must fail\n");
}

static void
test_sizes(void)
{
    /* 1 MiB alignment */
    ok(GptAlignmentSectors(512) == 2048, "512 alignment\n");
    ok(GptAlignmentSectors(4096) == 256, "4K alignment\n");
    ok(GptAlignmentSectors(0) == 1, "0 alignment\n");

    /* Microsoft's documented minimum for the EFI system partition: 200 MB (512), 300 MB (4Kn) */
    ok(GptEspSectors(512) * 512 == 200ULL * 1024 * 1024, "ESP size for 512-byte sectors\n");
    ok(GptEspSectors(4096) * 4096 == 300ULL * 1024 * 1024, "ESP size for 4K sectors\n");
    ok(GptEspSectors(512) % GptAlignmentSectors(512) == 0, "ESP is aligned (512)\n");
    ok(GptEspSectors(4096) % GptAlignmentSectors(4096) == 0, "ESP is aligned (4K)\n");

    /* MSR: 16 MB */
    ok(GptMsrSectors(512) * 512 == 16ULL * 1024 * 1024, "MSR size (512)\n");
    ok(GptMsrSectors(4096) * 4096 == 16ULL * 1024 * 1024, "MSR size (4K)\n");
    ok(GptMsrSectors(512) % GptAlignmentSectors(512) == 0, "MSR is aligned (512)\n");
}

static void
test_protective_mbr(void)
{
    ok(GptProtectiveMbrSectors(0) == 0, "empty\n");
    ok(GptProtectiveMbrSectors(1) == 0, "one sector\n");
    ok(GptProtectiveMbrSectors(41943040ULL) == 41943039UL, "20 GiB\n");
    ok(GptProtectiveMbrSectors(0x100000000ULL) == 0xFFFFFFFFUL, "exactly 2 TiB: size field is the maximum\n");
    ok(GptProtectiveMbrSectors(0x100000001ULL) == 0xFFFFFFFFUL, "above 2 TiB: size field is the maximum\n");
    ok(GptProtectiveMbrSectors(6442450944ULL) == 0xFFFFFFFFUL, "3 TiB\n");
}

static void
test_types(void)
{
    GUID Guid;
    static const GUID Unknown = {0x12345678, 0x1234, 0x1234, {1, 2, 3, 4, 5, 6, 7, 8}};
    static const GUID Esp = {0xC12A7328, 0xF81F, 0x11D2, {0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B}};
    static const GUID Msr = {0xE3C9E316, 0x0B5C, 0x4DB8, {0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE}};
    static const GUID Basic = {0xEBD0A0A2, 0xB9E5, 0x4433, {0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7}};

    ok(GptClassifyPartitionType(&Esp) == GptRoleEsp, "ESP GUID\n");
    ok(GptClassifyPartitionType(&Msr) == GptRoleMsr, "MSR GUID\n");
    ok(GptClassifyPartitionType(&Basic) == GptRoleBasicData, "basic data GUID\n");
    ok(GptClassifyPartitionType(&Unknown) == GptRoleOther, "unknown GUID\n");

    GptGetTypeGuid(GptRoleEsp, &Guid);
    ok(RtlCompareMemory(&Guid, &Esp, sizeof(GUID)) == sizeof(GUID), "GUID of the ESP role\n");
    GptGetTypeGuid(GptRoleMsr, &Guid);
    ok(RtlCompareMemory(&Guid, &Msr, sizeof(GUID)) == sizeof(GUID), "GUID of the MSR role\n");
    GptGetTypeGuid(GptRoleBasicData, &Guid);
    ok(RtlCompareMemory(&Guid, &Basic, sizeof(GUID)) == sizeof(GUID), "GUID of the basic data role\n");
}

START_TEST(GptLayout)
{
    test_usable_range();
    test_sizes();
    test_protective_mbr();
    test_types();
}
