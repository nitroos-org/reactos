/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test for GetLogicalProcessorInformationEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <intrin.h>

#define MAX_ENTRIES 512

static BOOL (WINAPI *pGetLogicalProcessorInformation)(PSYSTEM_LOGICAL_PROCESSOR_INFORMATION, PDWORD);
static BOOL (WINAPI *pGetLogicalProcessorInformationEx)(LOGICAL_PROCESSOR_RELATIONSHIP,
                                                        PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
                                                        PDWORD);
static SYSTEM_LOGICAL_PROCESSOR_INFORMATION Info[MAX_ENTRIES];
static BOOL Used[MAX_ENTRIES];
static ULONG InfoCount;
static BYTE Buffer[MAX_ENTRIES * sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)];

static
ULONG
ExpectedSize(
    _In_ LOGICAL_PROCESSOR_RELATIONSHIP Relationship)
{
    switch (Relationship)
    {
        case RelationProcessorCore:
        case RelationProcessorPackage:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor.GroupMask[1]);
        case RelationNumaNode:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, NumaNode) +
                   sizeof(NUMA_NODE_RELATIONSHIP);
        case RelationCache:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Cache) +
                   sizeof(CACHE_RELATIONSHIP);
        case RelationGroup:
            return FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Group.GroupInfo[1]);
        default:
            return 0;
    }
}

static
ULONG
CountBits(
    _In_ ULONG_PTR Mask)
{
    ULONG Count = 0;

    for (; Mask; Mask &= Mask - 1)
        Count++;
    return Count;
}

/* Compare the entries of one relationship, or all, with GetLogicalProcessorInformation */
static
VOID
TestRelationship(
    _In_ LOGICAL_PROCESSOR_RELATIONSHIP Relationship)
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Entry;
    SYSTEM_INFO SystemInfo;
    DWORD Length, Required, Offset, Error;
    ULONG Index, Groups;
    BOOL Success;

    GetSystemInfo(&SystemInfo);

    if (Relationship != RelationAll && Relationship != RelationGroup)
    {
        for (Index = 0; Index < InfoCount; Index++)
        {
            if (Info[Index].Relationship == Relationship)
                break;
        }
        if (Index == InfoCount)
        {
            skip("%d: GetLogicalProcessorInformation has no such entry\n", Relationship);
            return;
        }
    }

    /* Size query */
    Required = 0;
    SetLastError(0xdeadbeef);
    Success = pGetLogicalProcessorInformationEx(Relationship, NULL, &Required);
    Error = GetLastError();
    ok(!Success, "%d: Success = %d\n", Relationship, Success);
    ok(Error == ERROR_INSUFFICIENT_BUFFER, "%d: Error = %lu\n", Relationship, Error);
    ok(Required != 0, "%d: no length\n", Relationship);
    if (Required > sizeof(Buffer))
    {
        skip("%d: %lu bytes\n", Relationship, Required);
        return;
    }

    /* Too small for the first entry */
    Length = 8;
    memset(Buffer, 0x55, sizeof(Buffer));
    SetLastError(0xdeadbeef);
    Success = pGetLogicalProcessorInformationEx(Relationship,
                                                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
                                                &Length);
    Error = GetLastError();
    ok(!Success, "%d: Success = %d\n", Relationship, Success);
    ok(Error == ERROR_INSUFFICIENT_BUFFER, "%d: Error = %lu\n", Relationship, Error);
    ok(Length == Required, "%d: Length = %lu, expected %lu\n", Relationship, Length, Required);
    ok(Buffer[8] == 0x55, "%d: written past the buffer\n", Relationship);

    /* Exactly the size it needs: nothing is written after it */
    if (Required + 16 <= sizeof(Buffer))
    {
        Length = Required;
        memset(Buffer, 0x55, sizeof(Buffer));
        Success = pGetLogicalProcessorInformationEx(Relationship,
                                                    (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
                                                    &Length);
        ok(Success, "%d: Success = %d, error %lu\n", Relationship, Success, GetLastError());
        ok(Length == Required, "%d: Length = %lu, expected %lu\n", Relationship, Length, Required);
        for (Offset = Required; Offset < Required + 16; Offset++)
        {
            if (Buffer[Offset] != 0x55)
                break;
        }
        ok(Offset == Required + 16, "%d: written past the buffer at %lu\n", Relationship, Offset);
    }

    Length = sizeof(Buffer);
    SetLastError(0xdeadbeef);
    Success = pGetLogicalProcessorInformationEx(Relationship,
                                                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
                                                &Length);
    Error = GetLastError();
    ok(Success, "%d: Success = %d, error %lu\n", Relationship, Success, Error);
    ok(Error == 0xdeadbeef, "%d: Error = %lu\n", Relationship, Error);
    ok(Length == Required, "%d: Length = %lu, expected %lu\n", Relationship, Length, Required);
    if (!Success)
        return;

    /*
     * Every entry matches one of GetLogicalProcessorInformation. The order
     * differs between Windows versions and is not compared, nor are the
     * relationships that only newer versions have.
     */
    memset(Used, 0, sizeof(Used));
    Groups = 0;
    for (Offset = 0; Offset < Length; Offset += Entry->Size)
    {
        Entry = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
        ok(Entry->Size != 0 && Offset + Entry->Size <= Length, "%d: entry at %lu: size %lu\n",
           Relationship, Offset, Entry->Size);
        if (Entry->Size == 0 || Offset + Entry->Size > Length)
            break;
        if (Relationship != RelationAll)
            ok(Entry->Relationship == Relationship, "%d: entry at %lu has relationship %d\n",
               Relationship, Offset, Entry->Relationship);
        if (Entry->Relationship > RelationGroup)
            continue;
        ok(Entry->Size == ExpectedSize(Entry->Relationship), "%d: entry at %lu: relationship %d, size %lu\n",
           Relationship, Offset, Entry->Relationship, Entry->Size);

        if (Entry->Relationship == RelationGroup)
        {
            Groups++;
            ok(Entry->Group.MaximumGroupCount >= 1, "MaximumGroupCount = %u\n", Entry->Group.MaximumGroupCount);
            ok(Entry->Group.ActiveGroupCount == 1, "ActiveGroupCount = %u\n", Entry->Group.ActiveGroupCount);
            ok(Entry->Group.GroupInfo[0].ActiveProcessorMask == SystemInfo.dwActiveProcessorMask,
               "ActiveProcessorMask = 0x%Ix, expected 0x%Ix\n",
               Entry->Group.GroupInfo[0].ActiveProcessorMask, SystemInfo.dwActiveProcessorMask);
            ok(Entry->Group.GroupInfo[0].ActiveProcessorCount == SystemInfo.dwNumberOfProcessors,
               "ActiveProcessorCount = %u, expected %lu\n",
               Entry->Group.GroupInfo[0].ActiveProcessorCount, SystemInfo.dwNumberOfProcessors);
            ok(Entry->Group.GroupInfo[0].MaximumProcessorCount >= Entry->Group.GroupInfo[0].ActiveProcessorCount,
               "MaximumProcessorCount = %u\n", Entry->Group.GroupInfo[0].MaximumProcessorCount);
            ok(CountBits(Entry->Group.GroupInfo[0].ActiveProcessorMask) == Entry->Group.GroupInfo[0].ActiveProcessorCount,
               "Mask 0x%Ix for %u processors\n", Entry->Group.GroupInfo[0].ActiveProcessorMask,
               Entry->Group.GroupInfo[0].ActiveProcessorCount);
            continue;
        }

        /* Find an unused entry of GetLogicalProcessorInformation with the same processors */
        for (Index = 0; Index < InfoCount; Index++)
        {
            if (Used[Index] || Info[Index].Relationship != Entry->Relationship)
                continue;
            if (Entry->Relationship == RelationCache)
            {
                if (Entry->Cache.GroupMask.Mask == Info[Index].ProcessorMask &&
                    Entry->Cache.Level == Info[Index].Cache.Level &&
                    Entry->Cache.Type == Info[Index].Cache.Type)
                {
                    break;
                }
            }
            else if (Entry->Relationship == RelationNumaNode)
            {
                if (Entry->NumaNode.GroupMask.Mask == Info[Index].ProcessorMask)
                    break;
            }
            else if (Entry->Processor.GroupMask[0].Mask == Info[Index].ProcessorMask)
            {
                break;
            }
        }
        ok(Index < InfoCount, "%d: entry at %lu, relationship %d: no match in GetLogicalProcessorInformation\n",
           Relationship, Offset, Entry->Relationship);
        if (Index >= InfoCount)
            continue;
        Used[Index] = TRUE;

        switch (Entry->Relationship)
        {
            case RelationProcessorCore:
            case RelationProcessorPackage:
                ok(Entry->Processor.GroupCount == 1, "GroupCount = %u\n", Entry->Processor.GroupCount);
                ok(Entry->Processor.GroupMask[0].Group == 0, "Group = %u\n", Entry->Processor.GroupMask[0].Group);
                if (Entry->Relationship == RelationProcessorCore)
                    ok(Entry->Processor.Flags == Info[Index].ProcessorCore.Flags, "Flags = %u, expected %u\n",
                       Entry->Processor.Flags, Info[Index].ProcessorCore.Flags);
                break;

            case RelationNumaNode:
                ok(Entry->NumaNode.NodeNumber == Info[Index].NumaNode.NodeNumber, "NodeNumber = %lu, expected %lu\n",
                   Entry->NumaNode.NodeNumber, Info[Index].NumaNode.NodeNumber);
                ok(Entry->NumaNode.GroupMask.Group == 0, "Group = %u\n", Entry->NumaNode.GroupMask.Group);
                break;

            case RelationCache:
                ok(Entry->Cache.Associativity == Info[Index].Cache.Associativity, "Associativity = %u\n",
                   Entry->Cache.Associativity);
                ok(Entry->Cache.LineSize == Info[Index].Cache.LineSize, "LineSize = %u\n", Entry->Cache.LineSize);
                ok(Entry->Cache.CacheSize == Info[Index].Cache.Size, "CacheSize = %lu\n", Entry->Cache.CacheSize);
                ok(Entry->Cache.GroupMask.Group == 0, "Group = %u\n", Entry->Cache.GroupMask.Group);
                break;

            default:
                break;
        }
    }
    ok(Offset == Length, "%d: entries end at %lu, length %lu\n", Relationship, Offset, Length);

    /* Every entry of GetLogicalProcessorInformation was returned */
    for (Index = 0; Index < InfoCount; Index++)
    {
        if (Relationship == RelationAll || Info[Index].Relationship == Relationship)
            ok(Used[Index], "%d: entry %lu (relationship %d, mask 0x%Ix) not returned\n",
               Relationship, Index, Info[Index].Relationship, Info[Index].ProcessorMask);
    }

    if (Relationship == RelationAll || Relationship == RelationGroup)
        ok(Groups == 1, "%d: %lu group entries\n", Relationship, Groups);
    else
        ok(Groups == 0, "%d: %lu group entries\n", Relationship, Groups);
}

/* Processor packages: Windows returns at least one, the packages split the active processors, and
 * every core lies in one of them. The Microsoft C++ runtime counts the processors of the package
 * entries for std::thread::hardware_concurrency(), so without them it is 0. */
static
void
TestProcessorPackages(void)
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Entry;
    SYSTEM_INFO SystemInfo;
    KAFFINITY Packages = 0;
    ULONG Index, Index2, PackageCount = 0, Logical = 0;
    DWORD Length, Offset;
    BOOL Success, Inside;

    GetSystemInfo(&SystemInfo);

    for (Index = 0; Index < InfoCount; Index++)
    {
        if (Info[Index].Relationship != RelationProcessorPackage)
            continue;
        PackageCount++;
        ok(Info[Index].ProcessorMask != 0, "package %lu: empty mask\n", Index);
        ok((Packages & Info[Index].ProcessorMask) == 0, "package %lu: mask 0x%Ix overlaps 0x%Ix\n",
           Index, Info[Index].ProcessorMask, Packages);
        Packages |= Info[Index].ProcessorMask;
    }
    ok(PackageCount >= 1, "no processor package entries\n");
    ok(Packages == SystemInfo.dwActiveProcessorMask, "packages cover 0x%Ix, active processors 0x%Ix\n",
       Packages, SystemInfo.dwActiveProcessorMask);

    for (Index = 0; Index < InfoCount; Index++)
    {
        if (Info[Index].Relationship != RelationProcessorCore)
            continue;
        Inside = FALSE;
        for (Index2 = 0; Index2 < InfoCount; Index2++)
        {
            if (Info[Index2].Relationship == RelationProcessorPackage &&
                (Info[Index].ProcessorMask & ~Info[Index2].ProcessorMask) == 0)
            {
                Inside = TRUE;
            }
        }
        ok(Inside, "core mask 0x%Ix is in no package\n", Info[Index].ProcessorMask);
    }

    /* std::thread::hardware_concurrency() */
    Length = sizeof(Buffer);
    Success = pGetLogicalProcessorInformationEx(RelationProcessorPackage,
                                                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
                                                &Length);
    ok(Success, "Success = %d, error %lu\n", Success, GetLastError());
    if (!Success)
        return;
    for (Offset = 0; Offset + FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Processor) < Length; )
    {
        Entry = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
        if (!Entry->Size)
            break;
        for (Index = 0; Index < Entry->Processor.GroupCount; Index++)
            Logical += CountBits(Entry->Processor.GroupMask[Index].Mask);
        Offset += Entry->Size;
    }
    ok(Logical == SystemInfo.dwNumberOfProcessors, "package entries hold %lu processors, expected %lu\n",
       Logical, SystemInfo.dwNumberOfProcessors);
}

#if defined(_M_IX86) || defined(_M_AMD64)
/* The cache descriptions of the processor from CPUID, as the sorted list of Level/Type/Size/LineSize/Ways that
 * the kernel reports as caches. Returns the number of descriptions, 0 when CPUID has none we know. */
typedef struct _CPUID_CACHE
{
    ULONG Level, Type, Size, LineSize, SharingIds;
} CPUID_CACHE;

static
ULONG
GetCpuidCaches(
    _Out_writes_(8) CPUID_CACHE *Caches)
{
    int Regs[4];
    ULONG Leaf = 0, SubLeaf, Count = 0, Type, Ways, Parts, Line, Sets;
    BOOL Amd;

    __cpuid(Regs, 0);
    Amd = Regs[1] == 0x68747541 || Regs[1] == 0x6F677948;
    if (Amd)
    {
        __cpuid(Regs, 0x80000000);
        if ((ULONG)Regs[0] >= 0x8000001D)
        {
            __cpuid(Regs, 0x80000001);
            if (Regs[2] & (1 << 22))
                Leaf = 0x8000001D;
        }
    }
    else if (Regs[0] >= 4)
    {
        Leaf = 4;
    }
    if (!Leaf && Amd)
    {
        /* Without topology extensions: the legacy cache information. Windows reports all of them per core. */
        ULONG Value, Maximum;

        __cpuid(Regs, 0x80000000);
        Maximum = Regs[0];
        if (Maximum >= 0x80000005)
        {
            __cpuid(Regs, 0x80000005);
            for (SubLeaf = 0; SubLeaf < 2; SubLeaf++)
            {
                Value = Regs[SubLeaf ? 3 : 2];
                if (!(Value >> 24))
                    continue;
                Caches[Count].Level = 1;
                Caches[Count].Type = SubLeaf ? CacheInstruction : CacheData;
                Caches[Count].Size = (Value >> 24) * 1024;
                Caches[Count].LineSize = Value & 0xFF;
                Caches[Count].SharingIds = 1;
                Count++;
            }
        }
        if (Maximum >= 0x80000006)
        {
            __cpuid(Regs, 0x80000006);
            Value = Regs[2];
            if ((Value >> 16) && ((Value >> 12) & 0xF))
            {
                Caches[Count].Level = 2;
                Caches[Count].Type = CacheUnified;
                Caches[Count].Size = (Value >> 16) * 1024;
                Caches[Count].LineSize = Value & 0xFF;
                Caches[Count].SharingIds = 1;
                Count++;
            }
            Value = Regs[3];
            if ((Value >> 18) && ((Value >> 12) & 0xF))
            {
                Caches[Count].Level = 3;
                Caches[Count].Type = CacheUnified;
                Caches[Count].Size = (Value >> 18) * 512 * 1024;
                Caches[Count].LineSize = Value & 0xFF;
                Caches[Count].SharingIds = 1;
                Count++;
            }
        }
        return Count;
    }
    if (!Leaf)
        return 0;

    for (SubLeaf = 0; Count < 8; SubLeaf++)
    {
        __cpuidex(Regs, Leaf, SubLeaf);
        Type = Regs[0] & 0x1F;
        if (!Type)
            break;
        if (Type > 3)
            continue;
        Line = (Regs[1] & 0xFFF) + 1;
        Parts = ((Regs[1] >> 12) & 0x3FF) + 1;
        Ways = ((Regs[1] >> 22) & 0x3FF) + 1;
        Sets = (ULONG)Regs[2] + 1;
        Caches[Count].Level = (Regs[0] >> 5) & 7;
        /* In the values of CACHE_DESCRIPTOR: unified 0, instruction 1, data 2 */
        Caches[Count].Type = (Type == 1) ? CacheData : (Type == 2) ? CacheInstruction : CacheUnified;
        Caches[Count].Size = Ways * Parts * Line * Sets;
        Caches[Count].LineSize = Line;
        Caches[Count].SharingIds = ((Regs[0] >> 14) & 0xFFF) + 1;
        Count++;
    }
    return Count;
}
#endif

/* Caches: the entries of the legacy and the Ex function agree, every level has them, their masks are non-empty
 * subsets of the active processors, each processor has a data (or unified) cache of each level that exists, and
 * the sizes are those of CPUID */
static
void
TestCaches(void)
{
    PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Entry;
    SYSTEM_INFO SystemInfo;
    DWORD Length, Offset;
    ULONG Index, Index2, Level, CacheCount = 0, ExCount = 0, Processor, Found, Matches;
    ULONG PerLevel[4] = {0};
    BOOL Success;
    KAFFINITY Active;

    GetSystemInfo(&SystemInfo);
    Active = SystemInfo.dwActiveProcessorMask;

    for (Index = 0; Index < InfoCount; Index++)
    {
        if (Info[Index].Relationship != RelationCache)
            continue;
        CacheCount++;
        ok(Info[Index].ProcessorMask != 0, "cache %lu: empty mask\n", Index);
        ok((Info[Index].ProcessorMask & ~Active) == 0, "cache %lu: mask 0x%Ix outside the processors 0x%Ix\n",
           Index, Info[Index].ProcessorMask, Active);
        ok(Info[Index].Cache.Level >= 1 && Info[Index].Cache.Level <= 3, "cache %lu: level %u\n",
           Index, Info[Index].Cache.Level);
        ok(Info[Index].Cache.Type == CacheUnified || Info[Index].Cache.Type == CacheInstruction ||
           Info[Index].Cache.Type == CacheData, "cache %lu: type %d\n", Index, Info[Index].Cache.Type);
        ok(Info[Index].Cache.Size != 0, "cache %lu: no size\n", Index);
        ok(Info[Index].Cache.LineSize != 0, "cache %lu: no line size\n", Index);
        ok(Info[Index].Cache.Associativity != 0, "cache %lu: no associativity\n", Index);
        if (Info[Index].Cache.Level >= 1 && Info[Index].Cache.Level <= 3)
            PerLevel[Info[Index].Cache.Level]++;

        /* Caches of the same level and type do not overlap in processors unless they are the same cache */
        for (Index2 = 0; Index2 < Index; Index2++)
        {
            if (Info[Index2].Relationship != RelationCache ||
                Info[Index2].Cache.Level != Info[Index].Cache.Level ||
                Info[Index2].Cache.Type != Info[Index].Cache.Type)
                continue;
            ok((Info[Index2].ProcessorMask & Info[Index].ProcessorMask) == 0,
               "caches %lu and %lu of level %u overlap: 0x%Ix 0x%Ix\n", Index2, Index,
               Info[Index].Cache.Level, Info[Index2].ProcessorMask, Info[Index].ProcessorMask);
        }
    }

    if (!CacheCount)
    {
        ok(0, "GetLogicalProcessorInformation returns no cache entries\n");
        return;
    }

    /* Each processor is in one cache of each kind that exists: a data or unified one for every level */
    for (Level = 1; Level <= 3; Level++)
    {
        if (!PerLevel[Level])
            continue;
        for (Processor = 0; Processor < sizeof(KAFFINITY) * 8; Processor++)
        {
            if (!(Active & ((KAFFINITY)1 << Processor)))
                continue;
            Found = 0;
            for (Index = 0; Index < InfoCount; Index++)
            {
                if (Info[Index].Relationship == RelationCache && Info[Index].Cache.Level == Level &&
                    Info[Index].Cache.Type != CacheInstruction &&
                    (Info[Index].ProcessorMask & ((KAFFINITY)1 << Processor)))
                    Found++;
            }
            ok(Found == 1, "processor %lu is in %lu data/unified caches of level %lu\n", Processor, Found, Level);
        }
    }

    /* The Ex function returns the same caches in the same order */
    Length = sizeof(Buffer);
    Success = pGetLogicalProcessorInformationEx(RelationCache,
                                                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
                                                &Length);
    ok(Success, "Success = %d, error %lu\n", Success, GetLastError());
    if (!Success)
        return;
    Index = 0;
    for (Offset = 0; Offset + FIELD_OFFSET(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Cache) < Length; )
    {
        Entry = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(Buffer + Offset);
        if (!Entry->Size)
            break;
        ok(Entry->Relationship == RelationCache, "relationship %d\n", Entry->Relationship);
        ok(Entry->Size == ExpectedSize(RelationCache), "size %lu\n", Entry->Size);
        while (Index < InfoCount && Info[Index].Relationship != RelationCache)
            Index++;
        ok(Index < InfoCount, "more Ex caches than legacy ones\n");
        if (Index < InfoCount)
        {
            ok(Entry->Cache.Level == Info[Index].Cache.Level, "level %u/%u\n",
               Entry->Cache.Level, Info[Index].Cache.Level);
            ok(Entry->Cache.Type == Info[Index].Cache.Type, "type %d/%d\n",
               Entry->Cache.Type, Info[Index].Cache.Type);
            ok(Entry->Cache.CacheSize == Info[Index].Cache.Size, "size %lu/%lu\n",
               Entry->Cache.CacheSize, Info[Index].Cache.Size);
            ok(Entry->Cache.LineSize == Info[Index].Cache.LineSize, "line %u/%u\n",
               Entry->Cache.LineSize, Info[Index].Cache.LineSize);
            ok(Entry->Cache.Associativity == Info[Index].Cache.Associativity, "assoc %u/%u\n",
               Entry->Cache.Associativity, Info[Index].Cache.Associativity);
            ok(Entry->Cache.GroupMask.Group == 0, "group %u\n", Entry->Cache.GroupMask.Group);
            ok(Entry->Cache.GroupMask.Mask == Info[Index].ProcessorMask, "mask 0x%Ix/0x%Ix\n",
               Entry->Cache.GroupMask.Mask, Info[Index].ProcessorMask);
            Index++;
        }
        ExCount++;
        Offset += Entry->Size;
    }
    ok(ExCount == CacheCount, "Ex returns %lu caches, the legacy function %lu\n", ExCount, CacheCount);
    ok(Offset == Length, "entries end at %lu, length %lu\n", Offset, Length);

#if defined(_M_IX86) || defined(_M_AMD64)
    {
        CPUID_CACHE Cpuid[8];
        ULONG CpuidCount = GetCpuidCaches(Cpuid);

        if (!CpuidCount)
        {
            skip("CPUID has no cache parameters\n");
            return;
        }
        /* Every cache of CPUID is reported once per sharing group, with its size */
        for (Index = 0; Index < CpuidCount; Index++)
        {
            Matches = 0;
            for (Index2 = 0; Index2 < InfoCount; Index2++)
            {
                if (Info[Index2].Relationship == RelationCache &&
                    Info[Index2].Cache.Level == Cpuid[Index].Level &&
                    Info[Index2].Cache.Type == Cpuid[Index].Type &&
                    Info[Index2].Cache.Size == Cpuid[Index].Size &&
                    Info[Index2].Cache.LineSize == Cpuid[Index].LineSize)
                    Matches++;
            }
            ok(Matches >= 1, "no cache of level %lu type %lu size %lu line %lu\n",
               Cpuid[Index].Level, Cpuid[Index].Type, Cpuid[Index].Size, Cpuid[Index].LineSize);
            /* The processors a cache covers are at most the ones CPUID says share it */
            for (Index2 = 0; Index2 < InfoCount; Index2++)
            {
                if (Info[Index2].Relationship == RelationCache &&
                    Info[Index2].Cache.Level == Cpuid[Index].Level &&
                    Info[Index2].Cache.Type == Cpuid[Index].Type)
                    ok(CountBits(Info[Index2].ProcessorMask) <= Cpuid[Index].SharingIds,
                       "level %lu cache covers %lu processors, CPUID says %lu\n", Cpuid[Index].Level,
                       CountBits(Info[Index2].ProcessorMask), Cpuid[Index].SharingIds);
            }
        }
        ok(CacheCount >= CpuidCount, "%lu caches, CPUID describes %lu\n", CacheCount, CpuidCount);
    }
#endif
}

START_TEST(GetLogicalProcessorInformationEx)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    DWORD Length, Error;
    BOOL Success;

    pGetLogicalProcessorInformation = (PVOID)GetProcAddress(hKernel32, "GetLogicalProcessorInformation");
    pGetLogicalProcessorInformationEx = (PVOID)GetProcAddress(hKernel32, "GetLogicalProcessorInformationEx");
    if (!pGetLogicalProcessorInformation || !pGetLogicalProcessorInformationEx)
    {
        skip("GetLogicalProcessorInformationEx is not available\n");
        return;
    }

    Length = sizeof(Info);
    Success = pGetLogicalProcessorInformation(Info, &Length);
    ok(Success, "GetLogicalProcessorInformation failed with %lu\n", GetLastError());
    if (!Success)
        return;
    InfoCount = Length / sizeof(Info[0]);

    /* No length */
    SetLastError(0xdeadbeef);
    Success = pGetLogicalProcessorInformationEx(RelationAll,
                                                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
                                                NULL);
    Error = GetLastError();
    ok(!Success, "Success = %d\n", Success);
    ok(Error == ERROR_INVALID_PARAMETER, "Error = %lu\n", Error);

    /* With more than one processor group the old function sees only one */
    Length = sizeof(Buffer);
    Success = pGetLogicalProcessorInformationEx(RelationGroup,
                                                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer,
                                                &Length);
    ok(Success, "Success = %d, error %lu\n", Success, GetLastError());
    if (Success && Length >= ExpectedSize(RelationGroup) &&
        ((PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer)->Group.ActiveGroupCount != 1)
    {
        skip("%u processor groups\n", ((PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)Buffer)->Group.ActiveGroupCount);
        return;
    }

    TestRelationship(RelationProcessorCore);
    TestRelationship(RelationNumaNode);
    TestRelationship(RelationCache);
    TestRelationship(RelationProcessorPackage);
    TestRelationship(RelationGroup);
    TestRelationship(RelationAll);
    TestProcessorPackages();
    TestCaches();
}
