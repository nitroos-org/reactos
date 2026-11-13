/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (see COPYING.LIB in the top level directory)
 * PURPOSE:     HKEY_PERFORMANCE_DATA: the performance data block and the name tables
 *
 * Windows serves RegQueryValueEx(HKEY_PERFORMANCE_DATA, ...) by calling the collection
 * functions of the performance DLLs that are registered under Services\<name>\Performance.
 * Here the built-in counter sets (Memory, Processor, System, PhysicalDisk, Network Interface
 * and Process, the ones that pdh.dll serves) are collected in process and laid out in the
 * public PERF_DATA_BLOCK format of winperf.h.
 *
 * Value names:
 *   "Global", "" or (ANSI only) NULL   every object
 *   "Costly"                           the costly objects (there are none)
 *   "238 2 ..."                        the objects with these name indices
 *   "Counter [lang]"                   REG_MULTI_SZ, the Perflib counter name table
 *   "Help [lang]", "Explain [lang]"    REG_MULTI_SZ, the Perflib help table
 */

#include <advapi32.h>

#include <winperf.h>
#include <perfdata.h>

#include "reg.h"

WINE_DEFAULT_DEBUG_CHANNEL(reg);

C_ASSERT(sizeof(PERF_DATA_BLOCK) == 88);
C_ASSERT(sizeof(PERF_OBJECT_TYPE) == 64);
C_ASSERT(sizeof(PERF_COUNTER_DEFINITION) == 40);
C_ASSERT(sizeof(PERF_INSTANCE_DEFINITION) == 24);

#define PERF_NAME_INDEX_PROCESSOR   238
#define PERF_NAME_INDEX_MEMORY      4
#define PERF_NAME_INDEX_SYSTEM      2
#define PERF_NAME_INDEX_PROCESS     230
#define PERF_NAME_INDEX_PHYSDISK    234

#define PERF_ALIGN8(x) (((x) + 7) & ~7UL)

#define PERF_COUNTER_PRECISION_SUBTYPE 0x00070000

/* the types of the counters that are followed by a base counter */
#define PERF_TYPE_RAW_BASE_DWORD    0x40030403
#define PERF_TYPE_RAW_BASE_LARGE    0x40030500

typedef enum _PERF_VALUE_KIND
{
    PerfKindGlobal,
    PerfKindCostly,
    PerfKindForeign,
    PerfKindList,
    PerfKindCounterText,
    PerfKindHelpText,
    PerfKindNoLanguage      /* "Counter xyz": no such language */
} PERF_VALUE_KIND;

typedef struct _PERF_BUILDER
{
    PBYTE Data;
    ULONG Size;
    ULONG Capacity;
} PERF_BUILDER;

typedef struct _PERF_SLOT
{
    const struct perf_counter_def *Counter;
    ULONG Type;
    ULONG Size;
    ULONG Offset;
    BOOLEAN IsBase;
} PERF_SLOT;

/* HELPERS ******************************************************************/

/* Appends Length zeroed bytes and returns their offset, or MAXULONG when out of memory */
static ULONG
PerfAppend(PERF_BUILDER *Builder, ULONG Length)
{
    ULONG Offset = Builder->Size;
    ULONG NewSize, NewCapacity;
    PBYTE NewData;

    if (Length > MAXLONG || Offset > MAXLONG - Length)
        return MAXULONG;

    NewSize = Offset + Length;
    if (NewSize > Builder->Capacity)
    {
        NewCapacity = max(Builder->Capacity * 2, 4096);
        if (NewCapacity < NewSize)
            NewCapacity = NewSize;

        if (Builder->Data)
            NewData = RtlReAllocateHeap(RtlGetProcessHeap(), 0, Builder->Data, NewCapacity);
        else
            NewData = RtlAllocateHeap(RtlGetProcessHeap(), 0, NewCapacity);
        if (!NewData)
            return MAXULONG;

        Builder->Data = NewData;
        Builder->Capacity = NewCapacity;
    }

    RtlZeroMemory(Builder->Data + Offset, Length);
    Builder->Size = NewSize;
    return Offset;
}

static BOOLEAN
PerfNeedsBase(ULONG Type)
{
    ULONG Subtype = Type & 0x00070000;  /* PERF_COUNTER_FRACTION or PERF_COUNTER_PRECISION_SUBTYPE */

    return Subtype == PERF_COUNTER_FRACTION || Subtype == PERF_COUNTER_PRECISION_SUBTYPE;
}

static ULONG
PerfSizeOfType(ULONG Type)
{
    return (Type & 0x300) == PERF_SIZE_LARGE ? 8 : 4;
}

static ULONG
PerfBaseType(ULONG Type)
{
    if ((Type & 0x00070000) == PERF_COUNTER_PRECISION_SUBTYPE)
        return PERF_TYPE_RAW_BASE_LARGE;
    return PerfSizeOfType(Type) == 8 ? PERF_TYPE_RAW_BASE_LARGE : PERF_TYPE_RAW_BASE_DWORD;
}

/* Is the decimal number Index one of the blank separated numbers of List? */
static BOOLEAN
PerfIsListed(PCWSTR List, ULONG Index)
{
    while (*List)
    {
        ULONGLONG Value = 0;
        BOOLEAN Digits = FALSE, Valid = TRUE;

        while (*List == L' ')
            List++;
        if (!*List)
            break;

        while (*List && *List != L' ')
        {
            if (*List >= L'0' && *List <= L'9')
            {
                Digits = TRUE;
                if (Value <= MAXULONG)
                    Value = Value * 10 + (*List - L'0');
            }
            else
                Valid = FALSE;
            List++;
        }

        if (Valid && Digits && Value == Index)
            return TRUE;
    }
    return FALSE;
}

static ULONG
PerfDefaultCounter(const struct perf_object_def *Object)
{
    ULONG i, Slot = 0;

    for (i = 0; i < Object->count; i++)
    {
        if (!_wcsicmp(Object->counters[i].name, Object->default_counter))
            return Slot;
        Slot += PerfNeedsBase(Object->counters[i].type) ? 2 : 1;
    }
    return 0;
}

static VOID
PerfStoreValue(PBYTE Block, const PERF_SLOT *Slot, LONGLONG Value)
{
    if (Slot->Size == 8)
        RtlCopyMemory(Block + Slot->Offset, &Value, sizeof(Value));
    else
    {
        ULONG Value32 = (ULONG)Value;
        RtlCopyMemory(Block + Slot->Offset, &Value32, sizeof(Value32));
    }
}

/* OBJECTS ******************************************************************/

/* Appends the PERF_OBJECT_TYPE of Object with its counter definitions and its data */
static BOOLEAN
PerfBuildObject(PERF_BUILDER *Builder, const struct perf_object_def *Object, LONGLONG Now)
{
    PERF_SLOT *Slots;
    PWSTR *Names = NULL;
    ULONG NameCount = 0, SlotCount = 0, i, n, Offset, BlockLength, Cursor, Total;
    ULONG InstancesLength = 0, DefinitionLength;
    BOOLEAN Multi = (Object->kind != INST_NONE), Ok = FALSE;
    PERF_OBJECT_TYPE *Header;
    PERF_COUNTER_DEFINITION *Definition;
    PBYTE Base, Cursor8;

    if (Multi)
    {
        if (perf_get_instances(Object, &Names, &NameCount))
        {
            Names = NULL;
            NameCount = 0;
        }

        /* a name that could not be allocated: no instances at all */
        for (i = 0; i < NameCount; i++)
        {
            if (!Names[i])
            {
                perf_free_instances(Names, NameCount);
                Names = NULL;
                NameCount = 0;
                break;
            }
        }
    }

    for (i = 0; i < Object->count; i++)
        SlotCount += PerfNeedsBase(Object->counters[i].type) ? 2 : 1;

    Slots = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, max(SlotCount, 1) * sizeof(*Slots));
    if (!Slots)
        goto Done;

    /* The layout of a counter block: its length first, then the counters */
    Cursor = sizeof(DWORD);
    for (i = 0, n = 0; i < Object->count; i++)
    {
        const struct perf_counter_def *Counter = &Object->counters[i];

        Slots[n].Counter = Counter;
        Slots[n].Type = Counter->type;
        Slots[n].Size = PerfSizeOfType(Counter->type);
        Cursor = (Cursor + Slots[n].Size - 1) & ~(Slots[n].Size - 1);
        Slots[n].Offset = Cursor;
        Cursor += Slots[n].Size;
        n++;

        if (PerfNeedsBase(Counter->type))
        {
            Slots[n].Counter = Counter;
            Slots[n].Type = PerfBaseType(Counter->type);
            Slots[n].Size = PerfSizeOfType(Slots[n].Type);
            Slots[n].IsBase = TRUE;
            Cursor = (Cursor + Slots[n].Size - 1) & ~(Slots[n].Size - 1);
            Slots[n].Offset = Cursor;
            Cursor += Slots[n].Size;
            n++;
        }
    }
    BlockLength = PERF_ALIGN8(Cursor);

    DefinitionLength = sizeof(PERF_OBJECT_TYPE) + SlotCount * sizeof(PERF_COUNTER_DEFINITION);

    if (Multi)
    {
        for (i = 0; i < NameCount; i++)
            InstancesLength += PERF_ALIGN8(sizeof(PERF_INSTANCE_DEFINITION) + (lstrlenW(Names[i]) + 1) * sizeof(WCHAR)) +
                               BlockLength;
    }
    else
        InstancesLength = BlockLength;

    Total = DefinitionLength + InstancesLength;
    Offset = PerfAppend(Builder, Total);
    if (Offset == MAXULONG)
        goto Done;
    Base = Builder->Data + Offset;

    Header = (PERF_OBJECT_TYPE *)Base;
    Header->TotalByteLength = Total;
    Header->DefinitionLength = DefinitionLength;
    Header->HeaderLength = sizeof(PERF_OBJECT_TYPE);
    Header->ObjectNameTitleIndex = Object->index;
    Header->ObjectHelpTitleIndex = Object->index + 1;
    Header->DetailLevel = PERF_DETAIL_NOVICE;
    Header->NumCounters = SlotCount;
    Header->DefaultCounter = PerfDefaultCounter(Object);
    Header->NumInstances = Multi ? (LONG)NameCount : PERF_NO_INSTANCES;
    Header->CodePage = 0;
    if (Object->index == PERF_NAME_INDEX_SYSTEM || Object->index == PERF_NAME_INDEX_PROCESS)
    {
        /* The elapsed time counters are relative to the time stamp of the object, in 100 ns units */
        Header->PerfTime.QuadPart = Now;
        Header->PerfFreq.QuadPart = PERF_TIME_BASE;
    }

    Definition = (PERF_COUNTER_DEFINITION *)(Base + sizeof(PERF_OBJECT_TYPE));
    for (n = 0; n < SlotCount; n++, Definition++)
    {
        Definition->ByteLength = sizeof(PERF_COUNTER_DEFINITION);
        Definition->CounterNameTitleIndex = Slots[n].Counter->index;
        Definition->CounterHelpTitleIndex = Slots[n].Counter->index + 1;
        Definition->DefaultScale = Slots[n].IsBase ? 0 : Slots[n].Counter->defscale;
        Definition->DetailLevel = Slots[n].Counter->detail;
        Definition->CounterType = Slots[n].Type;
        Definition->CounterSize = Slots[n].Size;
        Definition->CounterOffset = Slots[n].Offset;
    }

    Cursor8 = Base + DefinitionLength;
    for (i = 0; i < (Multi ? NameCount : 1); i++)
    {
        PBYTE Block;

        if (Multi)
        {
            PERF_INSTANCE_DEFINITION *Instance = (PERF_INSTANCE_DEFINITION *)Cursor8;
            ULONG NameBytes = (lstrlenW(Names[i]) + 1) * sizeof(WCHAR);

            Instance->ByteLength = PERF_ALIGN8(sizeof(PERF_INSTANCE_DEFINITION) + NameBytes);
            Instance->ParentObjectTitleIndex = 0;
            Instance->ParentObjectInstance = 0;
            Instance->UniqueID = PERF_NO_UNIQUE_ID;
            Instance->NameOffset = sizeof(PERF_INSTANCE_DEFINITION);
            Instance->NameLength = NameBytes;
            RtlCopyMemory(Cursor8 + sizeof(PERF_INSTANCE_DEFINITION), Names[i], NameBytes);
            Cursor8 += Instance->ByteLength;
        }

        Block = Cursor8;
        ((PERF_COUNTER_BLOCK *)Block)->ByteLength = BlockLength;
        for (n = 0; n < SlotCount; n++)
        {
            LONGLONG First = 0, Second = 0;

            if (Slots[n].IsBase)
                continue;
            if (perf_fetch(Object, Slots[n].Counter, Multi ? Names[i] : NULL, 0, &First, &Second))
                First = Second = 0;
            PerfStoreValue(Block, &Slots[n], First);
            if (n + 1 < SlotCount && Slots[n + 1].IsBase)
                PerfStoreValue(Block, &Slots[n + 1], Second);
        }
        Cursor8 += BlockLength;
    }
    Ok = TRUE;

Done:
    if (Slots)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Slots);
    if (Names)
        perf_free_instances(Names, NameCount);
    return Ok;
}

/* Builds the data of "Global", "Costly", "Foreign" or an object list (List) */
static LONG
PerfBuildDataBlock(PERF_VALUE_KIND Kind, PCWSTR List, PBYTE *Result, ULONG *ResultSize)
{
    PERF_BUILDER Builder = {NULL, 0, 0};
    const struct perf_object_def **Objects = NULL, *Swap;
    PERF_DATA_BLOCK *Header;
    WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD ComputerLength = ARRAYSIZE(ComputerName), i, k, Count = 0, NameBytes;
    ULONG Offset, HeaderLength;
    LARGE_INTEGER Counter, Frequency;
    LONGLONG Now;
    LONG Error = ERROR_NOT_ENOUGH_MEMORY;

    if (!GetComputerNameW(ComputerName, &ComputerLength))
        ComputerName[0] = UNICODE_NULL;
    ComputerName[ARRAYSIZE(ComputerName) - 1] = UNICODE_NULL;
    NameBytes = (lstrlenW(ComputerName) + 1) * sizeof(WCHAR);
    HeaderLength = PERF_ALIGN8(sizeof(PERF_DATA_BLOCK) + NameBytes);

    if (!QueryPerformanceFrequency(&Frequency) || Frequency.QuadPart == 0)
        Frequency.QuadPart = PERF_TIME_BASE;
    if (!QueryPerformanceCounter(&Counter))
        Counter.QuadPart = 0;

    /* One snapshot of the data sources for the whole block */
    perf_next_generation();
    Now = perf_now();

    Offset = PerfAppend(&Builder, HeaderLength);
    if (Offset == MAXULONG)
        goto Fail;

    if (Kind == PerfKindGlobal || Kind == PerfKindList)
    {
        Objects = RtlAllocateHeap(RtlGetProcessHeap(), 0, max(perf_object_count(), 1) * sizeof(*Objects));
        if (!Objects)
            goto Fail;

        for (i = 0; i < perf_object_count(); i++)
        {
            const struct perf_object_def *Object = perf_object(i);

            if (Kind == PerfKindGlobal || PerfIsListed(List, Object->index))
                Objects[Count++] = Object;
        }

        /* ascending by name index */
        for (i = 1; i < Count; i++)
        {
            Swap = Objects[i];
            for (k = i; k > 0 && Objects[k - 1]->index > Swap->index; k--)
                Objects[k] = Objects[k - 1];
            Objects[k] = Swap;
        }

        for (i = 0; i < Count; i++)
        {
            if (!PerfBuildObject(&Builder, Objects[i], Now))
                goto Fail;
        }
    }

    Header = (PERF_DATA_BLOCK *)Builder.Data;
    Header->Signature[0] = L'P';
    Header->Signature[1] = L'E';
    Header->Signature[2] = L'R';
    Header->Signature[3] = L'F';
    Header->LittleEndian = 1;
    Header->Version = PERF_DATA_VERSION;
    Header->Revision = PERF_DATA_REVISION;
    Header->TotalByteLength = Builder.Size;
    Header->HeaderLength = HeaderLength;
    Header->NumObjectTypes = Count;
    Header->DefaultObject = PERF_NAME_INDEX_PROCESSOR;
    GetSystemTime(&Header->SystemTime);
    Header->PerfTime = Counter;
    Header->PerfFreq = Frequency;
    Header->PerfTime100nSec.QuadPart = Now;
    Header->SystemNameLength = NameBytes;
    Header->SystemNameOffset = sizeof(PERF_DATA_BLOCK);
    RtlCopyMemory(Builder.Data + sizeof(PERF_DATA_BLOCK), ComputerName, NameBytes);

    if (Objects)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Objects);
    *Result = Builder.Data;
    *ResultSize = Builder.Size;
    return ERROR_SUCCESS;

Fail:
    if (Objects)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Objects);
    if (Builder.Data)
        RtlFreeHeap(RtlGetProcessHeap(), 0, Builder.Data);
    return Error;
}

/* NAME TABLES **************************************************************/

/*
 * The counter name table is the Perflib\009 "Counter" value, the help table its "Help" value.
 * Where the registry does not have one, the table of the built-in counter sets is used.
 */
static LONG
PerfGetTextTable(BOOLEAN Help, PBYTE *Result, ULONG *ResultSize)
{
    HKEY Key;
    DWORD Type, Size = 0, Read;
    PWSTR Buffer = NULL;
    ULONG Chars;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009",
                      0,
                      KEY_QUERY_VALUE,
                      &Key) == ERROR_SUCCESS)
    {
        if (RegQueryValueExW(Key, Help ? L"Help" : L"Counter", NULL, &Type, NULL, &Size) == ERROR_SUCCESS &&
            Type == REG_MULTI_SZ && Size >= sizeof(WCHAR) && Size < MAXLONG - 4 * sizeof(WCHAR))
        {
            Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size + 2 * sizeof(WCHAR));
            Read = Size;
            if (Buffer &&
                (RegQueryValueExW(Key, Help ? L"Help" : L"Counter", NULL, &Type, (PBYTE)Buffer, &Read) != ERROR_SUCCESS ||
                 Read > Size || Type != REG_MULTI_SZ))
            {
                RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
                Buffer = NULL;
            }
            else if (Buffer)
            {
                /* the list ends with an empty string */
                Chars = Read / sizeof(WCHAR);
                if (Chars < 2 || Buffer[Chars - 1] != UNICODE_NULL || Buffer[Chars - 2] != UNICODE_NULL)
                {
                    Buffer[Chars++] = UNICODE_NULL;
                    Buffer[Chars++] = UNICODE_NULL;
                }
                *Result = (PBYTE)Buffer;
                *ResultSize = Chars * sizeof(WCHAR);
            }
        }
        RegCloseKey(Key);
        if (Buffer)
            return ERROR_SUCCESS;
    }

    Buffer = perf_builtin_names(Help, &Size);
    if (!Buffer)
        return ERROR_NOT_ENOUGH_MEMORY;

    /* the table of the library is released with its own function: copy it to the process heap */
    *Result = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (*Result)
    {
        RtlCopyMemory(*Result, Buffer, Size);
        *ResultSize = Size;
    }
    perf_free_buffer(Buffer);
    return *Result ? ERROR_SUCCESS : ERROR_NOT_ENOUGH_MEMORY;
}

/* Does the language part of "Counter <lang>" name a language that has a table? */
static BOOLEAN
PerfLanguageSupported(PCWSTR Language)
{
    ULONG Length, LangId = 0, i;

    while (*Language == L' ')
        Language++;
    Length = lstrlenW(Language);
    if (Length == 0)
        return TRUE;
    if (!_wcsicmp(Language, L"CurrentLanguage"))
        return TRUE;
    /* text that is not a number is no language identifier: the default table (measured on Windows 10: "Counter wine") */
    for (i = 0; Language[i]; i++)
    {
        WCHAR c = Language[i];

        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')))
            return TRUE;
    }
    if (Length == 3)
        return !wcscmp(Language, L"009");
    if (Length == 4)
    {
        /* a language identifier: any English */
        for (i = 0; i < 4; i++)
        {
            WCHAR c = Language[i];

            if (c >= L'0' && c <= L'9')
                LangId = LangId * 16 + (c - L'0');
            else if (c >= L'a' && c <= L'f')
                LangId = LangId * 16 + (c - L'a' + 10);
            else if (c >= L'A' && c <= L'F')
                LangId = LangId * 16 + (c - L'A' + 10);
            else
                return FALSE;
        }
        return (LangId & 0x3FF) == LANG_ENGLISH;
    }
    return FALSE;
}

static PERF_VALUE_KIND
PerfClassifyName(PCWSTR Name, PCWSTR *Argument)
{
    *Argument = NULL;

    if (!_wcsicmp(Name, L"Global") || !*Name)
        return PerfKindGlobal;
    if (!_wcsicmp(Name, L"Costly"))
        return PerfKindCostly;
    if (!_wcsnicmp(Name, L"Foreign", 7) && (Name[7] == UNICODE_NULL || Name[7] == L' '))
        return PerfKindForeign;
    /*
     * Text glued to the word ("Counterwine", "hElPwine") gets the plain table, as measured on
     * Windows 10 (the Wine advapi32 registry test reads both).
     */
    if (!_wcsnicmp(Name, L"Counter", 7))
    {
        if (Name[7] != UNICODE_NULL && Name[7] != L' ')
            return PerfKindCounterText;
        return PerfLanguageSupported(Name + 7) ? PerfKindCounterText : PerfKindNoLanguage;
    }
    if (!_wcsnicmp(Name, L"Help", 4))
        return PerfKindHelpText;   /* any language gets the table, as on Windows */
    if (!_wcsnicmp(Name, L"Explain", 7))
        return PerfKindHelpText;

    *Argument = Name;
    return PerfKindList;
}

/* ENTRY POINT **************************************************************/

BOOL
RegpIsPerformanceKey(_In_ HKEY hKey)
{
    return hKey == HKEY_PERFORMANCE_DATA ||
           hKey == HKEY_PERFORMANCE_TEXT ||
           hKey == HKEY_PERFORMANCE_NLSTEXT;
}

/*
 * RegQueryValueEx on one of the performance keys. Name is NULL for an ANSI call without a value name.
 * The results follow Windows: the type is always returned; for the data blocks a buffer that is too
 * small gives ERROR_MORE_DATA and leaves the size alone (the size of the block is different on every
 * call), for the name tables it also gives the size that is needed.
 */
LONG
RegpQueryPerformanceValue(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpValueName,
    _In_ BOOL bAnsi,
    _Out_opt_ LPDWORD lpType,
    _Out_opt_ LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData)
{
    PERF_VALUE_KIND Kind;
    PCWSTR Argument;
    PBYTE Buffer = NULL;
    ULONG Size = 0, Capacity;
    LONG Error;
    BOOLEAN Text;

    UNREFERENCED_PARAMETER(hKey);

    Kind = PerfClassifyName(lpValueName ? lpValueName : L"", &Argument);
    Text = (Kind == PerfKindCounterText || Kind == PerfKindHelpText || Kind == PerfKindNoLanguage);

    if (lpType)
        *lpType = Text ? REG_MULTI_SZ : REG_BINARY;

    if (Kind == PerfKindNoLanguage)
        return ERROR_FILE_NOT_FOUND;

    /* a binary block never fits a query for the size: skip collecting it */
    if (!lpData && !Text)
        return ERROR_MORE_DATA;

    if (Text)
        Error = PerfGetTextTable(Kind == PerfKindHelpText, &Buffer, &Size);
    else
        Error = PerfBuildDataBlock(Kind, Argument, &Buffer, &Size);
    if (Error != ERROR_SUCCESS)
        return Error;

    if (Text && bAnsi)
    {
        PBYTE Ansi;
        ULONG AnsiSize;

        if (!NT_SUCCESS(RtlUnicodeToMultiByteSize(&AnsiSize, (PWCHAR)Buffer, Size)) ||
            !(Ansi = RtlAllocateHeap(RtlGetProcessHeap(), 0, max(AnsiSize, 1))))
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        RtlUnicodeToMultiByteN((PCHAR)Ansi, AnsiSize, NULL, (PWCHAR)Buffer, Size);
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        Buffer = Ansi;
        Size = AnsiSize;
    }

    Capacity = (lpData && lpcbData) ? *lpcbData : 0;
    if (!lpData)
    {
        if (lpcbData)
            *lpcbData = Size;
        Error = ERROR_SUCCESS;
    }
    else if (Size > Capacity)
    {
        if (Text && lpcbData)
            *lpcbData = Size;
        Error = ERROR_MORE_DATA;
    }
    else
    {
        RtlCopyMemory(lpData, Buffer, Size);
        *lpcbData = Size;
        Error = ERROR_SUCCESS;
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    return Error;
}
