/*
 * PROJECT:     ReactOS cmlib regression tests
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     What the cmlib host tests share: the case tables (the present
 *              one from l_intl.nls, the old one of 6f1f2dbb8bf's parent), the
 *              few kernel functions cmlib calls, a hive "file" that is a memory
 *              buffer, and helpers to make, load and look into a hive.
 */

#include <cmlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "LhHashUpgradeOldCase.h"

/* ---- the case tables ---- */
static USHORT *g_NlsTable;                /* the upcase table of l_intl.nls */
static BOOLEAN g_UseOldTable;
static WCHAR g_OldUpcaseMap[65536];       /* 0 = same as the present table */

static WCHAR NewUpcase(WCHAR Source)
{
    USHORT Offset;

    if (Source < 'a')
        return Source;
    if (Source <= 'z')
        return Source - ('a' - 'A');

    Offset = (Source >> 8) & 0xFF;
    Offset = g_NlsTable[Offset];
    Offset += (Source >> 4) & 0xF;
    Offset = g_NlsTable[Offset];
    Offset += Source & 0xF;
    Offset = g_NlsTable[Offset];
    return Source + (SHORT)Offset;
}

static BOOLEAN LoadTables(const char *Path)
{
    FILE *f = fopen(Path, "rb");
    long Size;
    USHORT *Image;
    size_t i;

    if (!f)
        return FALSE;
    fseek(f, 0, SEEK_END);
    Size = ftell(f);
    fseek(f, 0, SEEK_SET);
    Image = malloc(Size);
    if (!Image || fread(Image, 1, Size, f) != (size_t)Size)
        return FALSE;
    fclose(f);
    g_NlsTable = Image + 2;       /* the upcase table follows the two header words */

    for (i = 0; i < sizeof(g_OldUpcase) / sizeof(g_OldUpcase[0]); i++)
        g_OldUpcaseMap[g_OldUpcase[i].Char] = g_OldUpcase[i].OldUpcase ? g_OldUpcase[i].OldUpcase : 0xFFFF;
    return TRUE;
}

/* A test can stand in for the case table (the boot loader's) */
static WCHAR (*g_UpcaseHook)(WCHAR);

WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR Source)
{
    if (g_UpcaseHook)
        return g_UpcaseHook(Source);
    if (g_UseOldTable && g_OldUpcaseMap[Source])
        return g_OldUpcaseMap[Source];
    return NewUpcase(Source);
}

/* ---- what cmlib wants from the kernel ---- */
VOID NTAPI RtlInitializeBitMap(PRTL_BITMAP Header, PULONG Buffer, ULONG SizeOfBitMap)
{
    Header->SizeOfBitMap = SizeOfBitMap;
    Header->Buffer = Buffer;
}
VOID NTAPI RtlClearAllBits(PRTL_BITMAP Header)
{
    if (Header->Buffer)
        memset(Header->Buffer, 0x00, ((Header->SizeOfBitMap + 31) / 32) * sizeof(ULONG));
}
VOID NTAPI RtlSetAllBits(PRTL_BITMAP Header)
{
    if (Header->Buffer)
        memset(Header->Buffer, 0xFF, ((Header->SizeOfBitMap + 31) / 32) * sizeof(ULONG));
}
VOID NTAPI RtlSetBits(PRTL_BITMAP Header, ULONG Start, ULONG Count)
{
    ULONG i;
    for (i = Start; i < Start + Count; i++)
        Header->Buffer[i / 32] |= 1u << (i % 32);
}
ULONG NTAPI RtlFindSetBits(PRTL_BITMAP Header, ULONG Count, ULONG Hint)
{
    ULONG Pass, i, Run, Start, End;

    /* a run of Count set bits at or after Hint, else (wrapping) from the start */
    for (Pass = 0; Pass < 2; Pass++)
    {
        Start = Pass ? 0 : Hint;
        End = Pass ? Header->SizeOfBitMap : Header->SizeOfBitMap;
        Run = 0;
        for (i = Start; i < End; i++)
        {
            if (Header->Buffer[i / 32] & (1u << (i % 32)))
            {
                if (++Run == Count)
                    return i + 1 - Count;
            }
            else
            {
                Run = 0;
            }
        }
    }
    return 0xFFFFFFFF;
}
VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING String, PCWSTR Source)
{
    size_t n = 0;
    while (Source && Source[n]) n++;
    String->Buffer = (PWSTR)Source;
    String->Length = (USHORT)(n * sizeof(WCHAR));
    String->MaximumLength = String->Length + sizeof(WCHAR);
}
LONG NTAPI RtlCompareUnicodeString(PCUNICODE_STRING s1, PCUNICODE_STRING s2, BOOLEAN CaseInSensitive)
{
    ULONG i, n = min(s1->Length, s2->Length) / sizeof(WCHAR);

    for (i = 0; i < n; i++)
    {
        WCHAR c1 = s1->Buffer[i], c2 = s2->Buffer[i];
        if (c1 != c2 && CaseInSensitive)
        {
            c1 = RtlUpcaseUnicodeChar(c1);
            c2 = RtlUpcaseUnicodeChar(c2);
        }
        if (c1 != c2)
            return (LONG)c1 - (LONG)c2;
    }
    return (LONG)s1->Length - (LONG)s2->Length;
}
VOID NTAPI KeQuerySystemTime(PLARGE_INTEGER CurrentTime)
{
    if (CurrentTime)
        CurrentTime->QuadPart = 0;
}
VOID NTAPI
KeBugCheckEx(ULONG Code, ULONG_PTR P1, ULONG_PTR P2, ULONG_PTR P3, ULONG_PTR P4)
{
    (void)P1; (void)P2; (void)P3; (void)P4;
    fprintf(stderr, "unexpected KeBugCheckEx 0x%lx\n", (unsigned long)Code);
    abort();
}
static LONG g_PoolOut;          /* CmpAllocate calls not yet freed (cmlib's own pool use) */
PVOID NTAPI CmpAllocate(SIZE_T Size, BOOLEAN Paged, ULONG Tag)
{
    (void)Paged; (void)Tag;
    g_PoolOut++;
    return calloc(1, (size_t)Size);
}
VOID NTAPI CmpFree(PVOID Ptr, ULONG Quota)
{
    (void)Quota;
    g_PoolOut--;
    free(Ptr);
}

/* ---- the "file" of a hive: a buffer ---- */
static PUCHAR g_File;
static ULONG g_FileSize;

static BOOLEAN CMAPI FileSetSize(PHHIVE Hive, ULONG Type, ULONG Size, ULONG OldSize)
{
    PUCHAR New;
    (void)Hive; (void)Type; (void)OldSize;
    New = realloc(g_File, Size ? Size : 1);
    if (!New)
        return FALSE;
    if (Size > g_FileSize)
        memset(New + g_FileSize, 0, Size - g_FileSize);
    g_File = New;
    g_FileSize = Size;
    return TRUE;
}
static BOOLEAN CMAPI FileWrite(PHHIVE Hive, ULONG Type, PULONG Offset, PVOID Buffer, SIZE_T Length)
{
    (void)Type;
    if (*Offset + Length > g_FileSize && !FileSetSize(Hive, Type, (ULONG)(*Offset + Length), g_FileSize))
        return FALSE;
    memcpy(g_File + *Offset, Buffer, Length);
    return TRUE;
}
static BOOLEAN CMAPI FileRead(PHHIVE Hive, ULONG Type, PULONG Offset, PVOID Buffer, SIZE_T Length)
{
    (void)Hive; (void)Type;
    if (*Offset + Length > g_FileSize)
        return FALSE;
    memcpy(Buffer, g_File + *Offset, Length);
    return TRUE;
}
static BOOLEAN CMAPI FileFlush(PHHIVE Hive, ULONG Type, PLARGE_INTEGER Offset, ULONG Length)
{
    (void)Hive; (void)Type; (void)Offset; (void)Length;
    return TRUE;
}

static PVOID CMAPI TestAllocate(SIZE_T Size, BOOLEAN Paged, ULONG Tag)
{
    (void)Paged; (void)Tag;
    return calloc(1, (size_t)Size);
}
static VOID CMAPI TestFree(PVOID Ptr, ULONG Quota)
{
    (void)Quota;
    free(Ptr);
}

/* ---- the fixture ---- */
static ULONG g_Errors;
#define CHECK(c, ...) \
    do { if (!(c)) { g_Errors++; if (g_Errors < 30) { printf("FAIL line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static NTSTATUS OpenHive(PCMHIVE CmHive, ULONG Operation)
{
    NTSTATUS Status;

    memset(CmHive, 0, sizeof(*CmHive));
    /* a loaded hive file is read into memory: HINIT_MEMORY on the file image, as a boot hive is */
    Status = HvInitialize(&CmHive->Hive, Operation, 0, HFILE_TYPE_PRIMARY, g_File,
                          TestAllocate, TestFree, FileSetSize, FileWrite, FileRead, FileFlush, 1, NULL);
    if (!NT_SUCCESS(Status))
        printf("HvInitialize(%lu) failed 0x%lx\n", (unsigned long)Operation, (unsigned long)Status);
    return Status;
}

static HCELL_INDEX NewKey(PHHIVE Hive, PCWSTR Text, HCELL_INDEX Parent)
{
    UNICODE_STRING Name;
    HCELL_INDEX Cell;
    PCM_KEY_NODE Node;

    RtlInitUnicodeString(&Name, Text);
    Cell = HvAllocateCell(Hive, FIELD_OFFSET(CM_KEY_NODE, Name) + CmpNameSize(Hive, &Name),
                          Stable, HCELL_NIL);
    if (Cell == HCELL_NIL)
        return Cell;
    Node = (PCM_KEY_NODE)HvGetCell(Hive, Cell);
    RtlZeroMemory(Node, FIELD_OFFSET(CM_KEY_NODE, Name));
    Node->Signature = CM_KEY_NODE_SIGNATURE;
    Node->Parent = Parent;
    Node->SubKeyLists[Stable] = Node->SubKeyLists[Volatile] = HCELL_NIL;
    Node->ValueList.List = HCELL_NIL;
    Node->Security = Node->Class = HCELL_NIL;
    Node->NameLength = CmpCopyName(Hive, Node->Name, &Name);
    if (Node->NameLength < Name.Length)
        Node->Flags |= KEY_COMP_NAME;
    return Cell;
}

static BOOLEAN Add(PHHIVE Hive, HCELL_INDEX Parent, PCWSTR Text)
{
    HCELL_INDEX Child = NewKey(Hive, Text, Parent);

    return Child != HCELL_NIL && CmpAddSubKey(Hive, Parent, Child);
}

static HCELL_INDEX Find(PHHIVE Hive, HCELL_INDEX Parent, PCWSTR Text)
{
    UNICODE_STRING Name;

    RtlInitUnicodeString(&Name, Text);
    return CmpFindSubKeyByName(Hive, (PCM_KEY_NODE)HvGetCell(Hive, Parent), &Name);
}

static void ExpandName(PCM_KEY_NODE N, WCHAR *W, PUNICODE_STRING S)
{
    ULONG k, n = N->NameLength / ((N->Flags & KEY_COMP_NAME) ? 1 : 2);

    for (k = 0; k < n; k++)
        W[k] = (N->Flags & KEY_COMP_NAME) ? ((PUCHAR)N->Name)[k] : N->Name[k];
    S->Buffer = W;
    S->Length = (USHORT)(n * sizeof(WCHAR));
    S->MaximumLength = S->Length;
}
