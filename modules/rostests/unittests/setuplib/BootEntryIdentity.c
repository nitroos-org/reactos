/*
 * PROJECT:     ReactOS Setup Library - Unit-tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Tests for the keys that name the system partition of a freeldr.ini
 *              boot entry by GUID (FreeLdrRebaseEntriesInCache, FreeLdrMarkEntriesInCache)
 */

#include "precomp.h"

/* The heap of the INI cache; a DLL of its own sets it up, a test program that links the static library has to */
extern HANDLE ProcessHeap;

#define PART_A  L"{11111111-2222-4333-8444-555555555555}"
#define PART_B  L"{AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE}"
#define DISK_A  L"{99999999-8888-4777-8666-555555555555}"

static const char IniText[] =
    "[FREELOADER]\r\n"
    "DefaultOS=ReactOS\r\n"
    "TimeOut=0\r\n"
    "\r\n"
    "[Operating Systems]\r\n"
    "ReactOS=\"NitroOS\"\r\n"
    "ReactOS_Debug=\"NitroOS (Debug)\"\r\n"
    "ReactOS_1=\"NitroOS 1\"\r\n"
    "Ram=\"RAM disk\"\r\n"
    "Quoted=\"Quoted\"\r\n"
    "Plain=\"No keys\"\r\n"
    "\r\n"
    "[ReactOS]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=multi(0)disk(0)rdisk(0)partition(3)\\ReactOS\r\n"
    "Options=/FASTDETECT\r\n"
    "SystemPathPartitionGuid=" "{11111111-2222-4333-8444-555555555555}" "\r\n"
    "SystemPathDiskGuid=" "{99999999-8888-4777-8666-555555555555}" "\r\n"
    "SystemPathPartitionRange=2048-4095\r\n"
    "\r\n"
    "[ReactOS_Debug]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=multi(0)disk(0)rdisk(0)partition(3)\\ReactOS\r\n"
    "Options=/DEBUG\r\n"
    "SystemPathPartitionGuid=" "{11111111-2222-4333-8444-555555555555}" "\r\n"
    "\r\n"
    "[ReactOS_1]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=multi(0)disk(1)rdisk(0)partition(5)\\Other\r\n"
    "SystemPathPartitionGuid=" "{AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE}" "\r\n"
    "\r\n"
    "[Ram]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=ramdisk(0)\\ReactOS\r\n"
    "\r\n"
    "[Quoted]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=\"multi(0)disk(0)rdisk(0)partition(2)\\ReactOS\"\r\n"
    "\r\n"
    "[Plain]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=multi(0)disk(0)rdisk(0)partition(3)\\ReactOS\r\n";

static PINICACHE
LoadIni(PINI_SECTION* OsSection)
{
    PINICACHE Cache = NULL;
    NTSTATUS Status;

    Status = IniCacheLoadFromMemory(&Cache, (PCHAR)IniText, sizeof(IniText) - 1, FALSE);
    ok(NT_SUCCESS(Status) && Cache, "IniCacheLoadFromMemory returned 0x%08lx\n", Status);
    *OsSection = Cache ? IniGetSection(Cache, L"Operating Systems") : NULL;
    ok(*OsSection != NULL, "no 'Operating Systems' section\n");
    return Cache;
}

static PCWSTR
Get(PINICACHE Cache, PCWSTR Section, PCWSTR Key)
{
    PCWSTR Data = NULL;
    PINI_SECTION Sec = IniGetSection(Cache, Section);

    if (Sec)
        IniGetKey(Sec, Key, &Data);
    return Data;
}

static ULONG
Count(PINICACHE Cache, PCWSTR Section, PCWSTR Key)
{
    PINI_SECTION Sec = IniGetSection(Cache, Section);
    PINICACHEITERATOR It;
    PCWSTR Name, Data;
    ULONG n = 0;

    if (!Sec)
        return 0;
    It = IniFindFirstValue(Sec, &Name, &Data);
    if (!It)
        return 0;
    do
    {
        if (_wcsicmp(Name, Key) == 0)
            n++;
    } while (IniFindNextValue(It, &Name, &Data));
    IniFindClose(It);
    return n;
}

static void
test_rebase(void)
{
    PINI_SECTION Os;
    PINICACHE Cache = LoadIni(&Os);
    PCWSTR Value;
    NTSTATUS Status;

    if (!Cache || !Os)
        return;

    /* The table changed: the partition with the GUID is now number 2 */
    Status = FreeLdrRebaseEntriesInCache(Cache, Os, L"multi(0)disk(0)rdisk(1)partition(2)\\ReactOS", PART_A);
    ok(NT_SUCCESS(Status), "rebase returned 0x%08lx\n", Status);

    Value = Get(Cache, L"ReactOS", L"SystemPath");
    ok(Value && !wcscmp(Value, L"multi(0)disk(0)rdisk(1)partition(2)\\ReactOS"), "entry with the GUID: '%S'\n", Value);
    Value = Get(Cache, L"ReactOS_Debug", L"SystemPath");
    ok(Value && !wcscmp(Value, L"multi(0)disk(0)rdisk(1)partition(2)\\ReactOS"), "second entry with the GUID: '%S'\n", Value);
    ok(Count(Cache, L"ReactOS", L"SystemPath") == 1, "SystemPath was added, not replaced\n");

    /* The entry of another partition keeps everything, also its own rest of the path */
    Value = Get(Cache, L"ReactOS_1", L"SystemPath");
    ok(Value && !wcscmp(Value, L"multi(0)disk(1)rdisk(0)partition(5)\\Other"), "entry of another GUID: '%S'\n", Value);
    /* An entry without the key, a RAM disk and a quoted path are not touched */
    Value = Get(Cache, L"Plain", L"SystemPath");
    ok(Value && !wcscmp(Value, L"multi(0)disk(0)rdisk(0)partition(3)\\ReactOS"), "entry without the key: '%S'\n", Value);
    Value = Get(Cache, L"Ram", L"SystemPath");
    ok(Value && !wcscmp(Value, L"ramdisk(0)\\ReactOS"), "RAM disk entry: '%S'\n", Value);

    /* Other keys of the entry stay */
    Value = Get(Cache, L"ReactOS", L"Options");
    ok(Value && !wcscmp(Value, L"/FASTDETECT"), "Options: '%S'\n", Value);
    Value = Get(Cache, L"ReactOS", L"SystemPathDiskGuid");
    ok(Value && !wcscmp(Value, DISK_A), "SystemPathDiskGuid: '%S'\n", Value);

    /* The GUID text may differ in case */
    Status = FreeLdrRebaseEntriesInCache(Cache, Os, L"multi(0)disk(0)rdisk(0)partition(4)\\ReactOS",
                                         L"{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}");
    ok(NT_SUCCESS(Status), "rebase returned 0x%08lx\n", Status);
    Value = Get(Cache, L"ReactOS_1", L"SystemPath");
    ok(Value && !wcscmp(Value, L"multi(0)disk(0)rdisk(0)partition(4)\\Other"), "case-insensitive GUID: '%S'\n", Value);

    /* Bad parameters */
    ok(FreeLdrRebaseEntriesInCache(Cache, Os, L"ramdisk(0)\\ReactOS", PART_A) == STATUS_INVALID_PARAMETER, "path without a partition\n");
    ok(FreeLdrRebaseEntriesInCache(NULL, Os, L"multi(0)disk(0)rdisk(0)partition(1)\\", PART_A) == STATUS_INVALID_PARAMETER, "no cache\n");

    IniCacheDestroy(Cache);
}

static void
test_mark(void)
{
    PINI_SECTION Os;
    PINICACHE Cache = LoadIni(&Os);
    PCWSTR Value;
    NTSTATUS Status;
    ULONG pass;

    if (!Cache || !Os)
        return;

    /* Twice: the keys are replaced, not added again */
    for (pass = 0; pass < 2; pass++)
    {
        Status = FreeLdrMarkEntriesInCache(Cache, Os, L"multi(0)disk(0)rdisk(0)partition(3)\\ReactOS",
                                           PART_B, DISK_A, L"100-200");
        ok(NT_SUCCESS(Status), "mark returned 0x%08lx\n", Status);
    }

    Value = Get(Cache, L"ReactOS", L"SystemPathPartitionGuid");
    ok(Value && !wcscmp(Value, PART_B), "GUID of the first entry: '%S'\n", Value);
    ok(Count(Cache, L"ReactOS", L"SystemPathPartitionGuid") == 1, "GUID key repeated\n");
    ok(Count(Cache, L"ReactOS", L"SystemPathDiskGuid") == 1, "disk GUID key repeated\n");
    ok(Count(Cache, L"ReactOS", L"SystemPathPartitionRange") == 1, "range key repeated\n");
    Value = Get(Cache, L"ReactOS", L"SystemPathPartitionRange");
    ok(Value && !wcscmp(Value, L"100-200"), "range: '%S'\n", Value);
    Value = Get(Cache, L"ReactOS_Debug", L"SystemPathDiskGuid");
    ok(Value && !wcscmp(Value, DISK_A), "second entry with the path: '%S'\n", Value);
    Value = Get(Cache, L"Plain", L"SystemPathPartitionGuid");
    ok(Value && !wcscmp(Value, PART_B), "third entry with the path: '%S'\n", Value);

    /* Other paths: nothing */
    ok(Get(Cache, L"Ram", L"SystemPathPartitionGuid") == NULL, "RAM disk entry got a key\n");
    ok(Get(Cache, L"Quoted", L"SystemPathPartitionGuid") == NULL, "entry of another path got a key\n");
    Value = Get(Cache, L"ReactOS_1", L"SystemPathPartitionGuid");
    ok(Value && !wcscmp(Value, PART_B), "entry of another path keeps its key: '%S'\n", Value);
    Value = Get(Cache, L"ReactOS_1", L"SystemPath");
    ok(Value && !wcscmp(Value, L"multi(0)disk(1)rdisk(0)partition(5)\\Other"), "its path: '%S'\n", Value);

    /* A quoted SystemPath is the same path */
    Status = FreeLdrMarkEntriesInCache(Cache, Os, L"multi(0)disk(0)rdisk(0)partition(2)\\ReactOS",
                                       PART_A, DISK_A, L"1-2");
    ok(NT_SUCCESS(Status), "mark returned 0x%08lx\n", Status);
    Value = Get(Cache, L"Quoted", L"SystemPathPartitionGuid");
    ok(Value && !wcscmp(Value, PART_A), "quoted path: '%S'\n", Value);

    IniCacheDestroy(Cache);
}

START_TEST(BootEntryIdentity)
{
    ProcessHeap = RtlGetProcessHeap();

    test_rebase();
    test_mark();
}
