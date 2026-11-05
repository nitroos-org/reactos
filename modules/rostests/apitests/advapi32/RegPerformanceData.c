/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for HKEY_PERFORMANCE_DATA (RegQueryValueEx)
 *
 * The block layout is the public one of winperf.h. The tests only rely on what the Win32
 * documentation and the Windows system objects guarantee, so that they pass on Windows too.
 */

#include "precomp.h"

#include <winperf.h>

#define PERF_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define INDEX_SYSTEM            2
#define INDEX_MEMORY            4
#define INDEX_PROCESS           230
#define INDEX_PHYSICALDISK      234
#define INDEX_PROCESSOR         238
#define INDEX_NETWORK           510

#define INDEX_PROCESSOR_TIME    6       /* Processor: % Processor Time */
#define INDEX_PAGES_PER_SEC     40      /* Memory: Pages/sec */
#define INDEX_AVAILABLE_BYTES   24      /* Memory: Available Bytes */
#define INDEX_PROCESSES         248     /* System: Processes */
#define INDEX_THREADS           250     /* System: Threads */
#define INDEX_UPTIME            674     /* System: System Up Time */
#define INDEX_ID_PROCESS        784     /* Process: ID Process */

static BYTE *g_Buffer;
static DWORD g_BufferSize;

/* Query a value the way the .NET runtime does: start with a big buffer and double it on ERROR_MORE_DATA */
static
LONG
QueryValue(
    _In_ HKEY Key,
    _In_ PCWSTR Name,
    _Out_ PDWORD Type,
    _Out_ PDWORD Size)
{
    LONG ret;

    for (;;)
    {
        DWORD cb = g_BufferSize;

        *Type = 0x55555555;
        ret = RegQueryValueExW(Key, Name, NULL, Type, g_Buffer, &cb);
        if (ret == ERROR_SUCCESS)
        {
            *Size = cb;
            return ret;
        }
        if (ret != ERROR_MORE_DATA || g_BufferSize >= 64 * 1024 * 1024)
            return ret;

        g_BufferSize *= 2;
        g_Buffer = HeapReAlloc(GetProcessHeap(), 0, g_Buffer, g_BufferSize);
        if (!g_Buffer)
        {
            g_BufferSize = 0;
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
}

/* NAME TABLES ***************************************************************/

/* The text of the entry with the given index in a counter/help table, or NULL */
static
PCWSTR
FindText(
    _In_ const WCHAR *Table,
    _In_ DWORD Size,
    _In_ DWORD Index)
{
    const WCHAR *p = Table;
    const WCHAR *end = Table + Size / sizeof(WCHAR);

    while (p < end && *p)
    {
        const WCHAR *Text = p + lstrlenW(p) + 1;
        DWORD Number = 0;
        const WCHAR *c;

        if (Text >= end)
            return NULL;
        for (c = p; *c >= L'0' && *c <= L'9'; c++)
            Number = Number * 10 + (*c - L'0');
        if (!*c && c != p && Number == Index)
            return Text;
        p = Text + lstrlenW(Text) + 1;
    }
    return NULL;
}

static
DWORD
CountPairs(
    _In_ const WCHAR *Table,
    _In_ DWORD Size,
    _Out_ PBOOL Terminated)
{
    const WCHAR *p = Table;
    const WCHAR *end = Table + Size / sizeof(WCHAR);
    DWORD Count = 0;

    while (p < end && *p)
    {
        p += lstrlenW(p) + 1;
        if (p >= end)
            break;
        p += lstrlenW(p) + 1;
        Count++;
    }
    *Terminated = (p < end && !*p);
    return Count;
}

static
BOOL
IsWow64(VOID)
{
    BOOL Wow64 = FALSE;

    return IsWow64Process(GetCurrentProcess(), &Wow64) && Wow64;
}

static
VOID
test_name_tables(VOID)
{
    static const PCWSTR Names[] = { L"Counter 009", L"Counter", L"counter 009", L"Counter 0409", L"Counter CurrentLanguage" };
    static const PCWSTR Helps[] = { L"Help 009", L"Explain 009", L"Help" };
    DWORD Type, Size, Required, i, cb;
    BOOL Terminated;
    PCWSTR Text;
    WCHAR Small[4];
    LONG ret;

    for (i = 0; i < PERF_ARRAY_SIZE(Names); i++)
    {
        ret = QueryValue(HKEY_PERFORMANCE_DATA, Names[i], &Type, &Size);
        /* Windows 10 does not know "Counter 0409" to a 32-bit process on a 64-bit system */
        if (ret == ERROR_FILE_NOT_FOUND && !lstrcmpW(Names[i], L"Counter 0409") && IsWow64())
        {
            trace("Counter 0409 is not found in a WoW64 process\n");
            continue;
        }
        ok(ret == ERROR_SUCCESS, "%ls: ret = %ld\n", Names[i], ret);
        if (ret != ERROR_SUCCESS)
            continue;
        ok(Type == REG_MULTI_SZ, "%ls: Type = %lu\n", Names[i], Type);
        ok(CountPairs((PWSTR)g_Buffer, Size, &Terminated) > 10, "%ls: too few entries\n", Names[i]);
        ok(Terminated, "%ls: list is not terminated\n", Names[i]);

        Text = FindText((PWSTR)g_Buffer, Size, INDEX_PROCESSOR);
        ok(Text && !lstrcmpW(Text, L"Processor"), "%ls: 238 is %ls\n", Names[i], Text);
        Text = FindText((PWSTR)g_Buffer, Size, INDEX_MEMORY);
        ok(Text && !lstrcmpW(Text, L"Memory"), "%ls: 4 is %ls\n", Names[i], Text);
        Text = FindText((PWSTR)g_Buffer, Size, INDEX_SYSTEM);
        ok(Text && !lstrcmpW(Text, L"System"), "%ls: 2 is %ls\n", Names[i], Text);
        Text = FindText((PWSTR)g_Buffer, Size, INDEX_PROCESS);
        ok(Text && !lstrcmpW(Text, L"Process"), "%ls: 230 is %ls\n", Names[i], Text);
        Text = FindText((PWSTR)g_Buffer, Size, INDEX_PHYSICALDISK);
        ok(Text && !lstrcmpW(Text, L"PhysicalDisk"), "%ls: 234 is %ls\n", Names[i], Text);
        Text = FindText((PWSTR)g_Buffer, Size, INDEX_NETWORK);
        ok(Text && !lstrcmpW(Text, L"Network Interface"), "%ls: 510 is %ls\n", Names[i], Text);
        Text = FindText((PWSTR)g_Buffer, Size, INDEX_PROCESSOR_TIME);
        ok(Text && !lstrcmpW(Text, L"% Processor Time"), "%ls: 6 is %ls\n", Names[i], Text);
    }

    /* the size of a text table is known without a buffer, and returned when the buffer is too small */
    Type = 0x55555555;
    Required = 0;
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"Counter 009", NULL, &Type, NULL, &Required);
    ok(ret == ERROR_SUCCESS, "size query: ret = %ld\n", ret);
    ok(Type == REG_MULTI_SZ, "size query: Type = %lu\n", Type);
    ok(Required > 1000, "size query: Required = %lu\n", Required);

    Type = 0x55555555;
    cb = sizeof(Small);
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"Counter 009", NULL, &Type, (PBYTE)Small, &cb);
    ok(ret == ERROR_MORE_DATA, "small buffer: ret = %ld\n", ret);
    ok(Type == REG_MULTI_SZ, "small buffer: Type = %lu\n", Type);
    ok(cb == Required, "small buffer: cb = %lu, expected %lu\n", cb, Required);

    for (i = 0; i < PERF_ARRAY_SIZE(Helps); i++)
    {
        ret = QueryValue(HKEY_PERFORMANCE_DATA, Helps[i], &Type, &Size);
        ok(ret == ERROR_SUCCESS, "%ls: ret = %ld\n", Helps[i], ret);
        if (ret != ERROR_SUCCESS)
            continue;
        ok(Type == REG_MULTI_SZ, "%ls: Type = %lu\n", Helps[i], Type);
        ok(CountPairs((PWSTR)g_Buffer, Size, &Terminated) > 5, "%ls: too few entries\n", Helps[i]);
        ok(Terminated, "%ls: list is not terminated\n", Helps[i]);
        /* the help of an object has the index after the one of its name */
        Text = FindText((PWSTR)g_Buffer, Size, INDEX_PROCESSOR + 1);
        ok(Text != NULL, "%ls: no help for the Processor object\n", Helps[i]);
    }

    /* a language that has no table */
    Type = 0x55555555;
    cb = g_BufferSize;
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"Counter 000", NULL, &Type, g_Buffer, &cb);
    ok(ret == ERROR_FILE_NOT_FOUND, "Counter 000: ret = %ld\n", ret);

    /* the text keys */
    ret = QueryValue(HKEY_PERFORMANCE_TEXT, L"Counter", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "HKEY_PERFORMANCE_TEXT Counter: ret = %ld\n", ret);
    ok(Type == REG_MULTI_SZ, "HKEY_PERFORMANCE_TEXT Counter: Type = %lu\n", Type);
    Text = ret == ERROR_SUCCESS ? FindText((PWSTR)g_Buffer, Size, INDEX_PROCESSOR) : NULL;
    ok(Text && !lstrcmpW(Text, L"Processor"), "HKEY_PERFORMANCE_TEXT: 238 is %ls\n", Text);

    ret = QueryValue(HKEY_PERFORMANCE_NLSTEXT, L"Counter", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "HKEY_PERFORMANCE_NLSTEXT Counter: ret = %ld\n", ret);
    ok(Type == REG_MULTI_SZ, "HKEY_PERFORMANCE_NLSTEXT Counter: Type = %lu\n", Type);
}

/* DATA BLOCKS ***************************************************************/

static
ULONGLONG
ReadValue(
    _In_ const PERF_COUNTER_BLOCK *Block,
    _In_ const PERF_COUNTER_DEFINITION *Definition)
{
    const BYTE *p = (const BYTE *)Block + Definition->CounterOffset;

    if (Definition->CounterSize == 8)
    {
        ULONGLONG Value;
        memcpy(&Value, p, sizeof(Value));
        return Value;
    }
    else
    {
        DWORD Value;
        memcpy(&Value, p, sizeof(Value));
        return Value;
    }
}

/* The objects that the tests know in detail. Windows has a lot more, with their own conventions. */
static
BOOL
IsCoreObject(
    _In_ DWORD Index)
{
    return Index == INDEX_SYSTEM || Index == INDEX_MEMORY || Index == INDEX_PROCESS ||
           Index == INDEX_PHYSICALDISK || Index == INDEX_PROCESSOR || Index == INDEX_NETWORK;
}

/*
 * Checks the layout of a block and returns the number of objects it has (-1 if it is broken).
 * Every offset and length is checked against the size of the buffer.
 */
static
LONG
ValidateBlock(
    _In_ PCSTR What,
    _In_ const BYTE *Data,
    _In_ DWORD Size)
{
    const PERF_DATA_BLOCK *Header = (const PERF_DATA_BLOCK *)Data;
    const BYTE *End = Data + Size;
    const BYTE *Position;
    DWORD i, c, n;

    if (Size < sizeof(*Header))
    {
        ok(0, "%s: block is only %lu bytes\n", What, Size);
        return -1;
    }

    ok(Header->Signature[0] == L'P' && Header->Signature[1] == L'E' &&
       Header->Signature[2] == L'R' && Header->Signature[3] == L'F', "%s: bad signature\n", What);
    ok(Header->Version == 1, "%s: Version = %lu\n", What, Header->Version);
    ok(Header->Revision == 1, "%s: Revision = %lu\n", What, Header->Revision);
    ok(Header->LittleEndian == 1, "%s: LittleEndian = %lu\n", What, Header->LittleEndian);
    ok(Header->TotalByteLength == Size, "%s: TotalByteLength = %lu, size %lu\n", What, Header->TotalByteLength, Size);
    ok(Header->HeaderLength >= sizeof(*Header) && Header->HeaderLength <= Size && (Header->HeaderLength % 8) == 0,
       "%s: HeaderLength = %lu\n", What, Header->HeaderLength);
    ok(Header->PerfFreq.QuadPart > 0, "%s: PerfFreq = %I64d\n", What, Header->PerfFreq.QuadPart);
    ok(Header->PerfTime.QuadPart > 0, "%s: PerfTime = %I64d\n", What, Header->PerfTime.QuadPart);
    ok(Header->PerfTime100nSec.QuadPart > 0, "%s: PerfTime100nSec = %I64d\n", What, Header->PerfTime100nSec.QuadPart);
    ok(Header->SystemTime.wYear >= 2020, "%s: SystemTime.wYear = %u\n", What, Header->SystemTime.wYear);
    ok(Header->DefaultObject == INDEX_PROCESSOR, "%s: DefaultObject = %ld\n", What, Header->DefaultObject);

    if (Header->SystemNameLength >= sizeof(WCHAR) &&
        Header->SystemNameOffset >= sizeof(*Header) &&
        Header->SystemNameOffset + Header->SystemNameLength <= Header->HeaderLength &&
        Header->HeaderLength <= Size)
    {
        WCHAR Computer[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD cch = PERF_ARRAY_SIZE(Computer);
        const WCHAR *Name = (const WCHAR *)(Data + Header->SystemNameOffset);

        ok(Name[Header->SystemNameLength / sizeof(WCHAR) - 1] == 0, "%s: system name is not terminated\n", What);
        if (GetComputerNameW(Computer, &cch))
            ok(!_wcsnicmp(Name, Computer, cch) && Name[cch] == 0, "%s: system name %ls, computer %ls\n", What, Name, Computer);
    }
    else
        ok(0, "%s: SystemNameOffset = %lu, SystemNameLength = %lu, HeaderLength = %lu\n",
           What, Header->SystemNameOffset, Header->SystemNameLength, Header->HeaderLength);

    if (Header->HeaderLength > Size)
        return -1;

    Position = Data + Header->HeaderLength;
    for (i = 0; i < Header->NumObjectTypes; i++)
    {
        const PERF_OBJECT_TYPE *Object;
        const PERF_COUNTER_DEFINITION *Definition;
        const BYTE *ObjectEnd, *p;
        DWORD BlockLength = 0, Sum;

        if ((SIZE_T)(End - Position) < sizeof(*Object))
        {
            ok(0, "%s: object %lu is cut off\n", What, i);
            return -1;
        }
        Object = (const PERF_OBJECT_TYPE *)Position;
        if (Object->TotalByteLength > (SIZE_T)(End - Position) ||
            Object->HeaderLength != sizeof(*Object) ||
            Object->DefinitionLength < Object->HeaderLength ||
            Object->DefinitionLength > Object->TotalByteLength ||
            0)
        {
            ok(0, "%s: object %lu: total %lu, header %lu, definitions %lu\n", What, i,
               Object->TotalByteLength, Object->HeaderLength, Object->DefinitionLength);
            return -1;
        }
        ObjectEnd = Position + Object->TotalByteLength;

        if (IsCoreObject(Object->ObjectNameTitleIndex))
        {
            ok(Object->ObjectHelpTitleIndex == Object->ObjectNameTitleIndex + 1, "%s: object %lu: help index %lu\n",
               What, Object->ObjectNameTitleIndex, Object->ObjectHelpTitleIndex);
            ok(Object->DefaultCounter >= 0 && (DWORD)Object->DefaultCounter < Object->NumCounters,
               "%s: object %lu: DefaultCounter = %ld of %lu\n", What, Object->ObjectNameTitleIndex,
               Object->DefaultCounter, Object->NumCounters);
        }
        ok(Object->NumInstances >= PERF_NO_INSTANCES, "%s: object %lu: NumInstances = %ld\n", What,
           Object->ObjectNameTitleIndex, Object->NumInstances);

        /* counter definitions */
        p = Position + Object->HeaderLength;
        Sum = Object->HeaderLength;
        for (c = 0; c < Object->NumCounters; c++)
        {
            if ((SIZE_T)(ObjectEnd - p) < sizeof(*Definition))
            {
                ok(0, "%s: object %lu: definition %lu is cut off\n", What, Object->ObjectNameTitleIndex, c);
                return -1;
            }
            Definition = (const PERF_COUNTER_DEFINITION *)p;
            ok(Definition->ByteLength == sizeof(*Definition), "%s: object %lu: definition %lu has length %lu\n",
               What, Object->ObjectNameTitleIndex, c, Definition->ByteLength);
            if (IsCoreObject(Object->ObjectNameTitleIndex))
            {
                ok(Definition->CounterSize == 4 || Definition->CounterSize == 8,
                   "%s: object %lu: counter %lu has size %lu\n", What, Object->ObjectNameTitleIndex,
                   Definition->CounterNameTitleIndex, Definition->CounterSize);
                ok(Definition->CounterSize != 0 && Definition->CounterOffset >= sizeof(DWORD) &&
                   (Definition->CounterOffset % Definition->CounterSize) == 0,
                   "%s: object %lu: counter %lu: offset %lu\n", What, Object->ObjectNameTitleIndex,
                   Definition->CounterNameTitleIndex, Definition->CounterOffset);
            }
            if (Definition->CounterOffset + Definition->CounterSize > BlockLength)
                BlockLength = Definition->CounterOffset + Definition->CounterSize;
            Sum += Definition->ByteLength;
            p += Definition->ByteLength;
            if (Definition->ByteLength == 0)
                return -1;
        }
        ok(Sum == Object->DefinitionLength, "%s: object %lu: definitions are %lu bytes, DefinitionLength %lu\n",
           What, Object->ObjectNameTitleIndex, Sum, Object->DefinitionLength);

        /* instances and counter blocks */
        p = Position + Object->DefinitionLength;
        n = (Object->NumInstances == PERF_NO_INSTANCES) ? 1 : (DWORD)Object->NumInstances;
        for (c = 0; c < n; c++)
        {
            const PERF_COUNTER_BLOCK *Block;

            if (Object->NumInstances != PERF_NO_INSTANCES)
            {
                const PERF_INSTANCE_DEFINITION *Instance;
                const WCHAR *Name;

                if ((SIZE_T)(ObjectEnd - p) < sizeof(*Instance))
                {
                    ok(0, "%s: object %lu: instance %lu is cut off\n", What, Object->ObjectNameTitleIndex, c);
                    return -1;
                }
                Instance = (const PERF_INSTANCE_DEFINITION *)p;
                if (Instance->ByteLength < sizeof(*Instance) + Instance->NameLength ||
                    Instance->ByteLength > (SIZE_T)(ObjectEnd - p) ||
                    Instance->NameOffset < sizeof(*Instance) ||
                    Instance->NameOffset + Instance->NameLength > Instance->ByteLength ||
                    Instance->NameLength < sizeof(WCHAR))
                {
                    ok(0, "%s: object %lu: instance %lu: length %lu, name offset %lu, name length %lu\n", What,
                       Object->ObjectNameTitleIndex, c, Instance->ByteLength, Instance->NameOffset, Instance->NameLength);
                    return -1;
                }
                Name = (const WCHAR *)(p + Instance->NameOffset);
                if (IsCoreObject(Object->ObjectNameTitleIndex))
                {
                    ok(Name[Instance->NameLength / sizeof(WCHAR) - 1] == 0, "%s: object %lu: instance %lu name is not terminated\n",
                       What, Object->ObjectNameTitleIndex, c);
                    ok((Instance->ByteLength % 8) == 0, "%s: object %lu: instance %lu has length %lu\n", What,
                       Object->ObjectNameTitleIndex, c, Instance->ByteLength);
                }
                p += Instance->ByteLength;
            }

            if ((SIZE_T)(ObjectEnd - p) < sizeof(*Block))
            {
                ok(0, "%s: object %lu: counter block %lu is cut off\n", What, Object->ObjectNameTitleIndex, c);
                return -1;
            }
            Block = (const PERF_COUNTER_BLOCK *)p;
            if (Block->ByteLength < BlockLength || Block->ByteLength > (SIZE_T)(ObjectEnd - p))
            {
                ok(0, "%s: object %lu: counter block %lu has length %lu, counters need %lu\n", What,
                   Object->ObjectNameTitleIndex, c, Block->ByteLength, BlockLength);
                return -1;
            }
            p += Block->ByteLength;
        }
        ok(p == ObjectEnd, "%s: object %lu: ends at %lu, TotalByteLength %lu\n", What, Object->ObjectNameTitleIndex,
           (DWORD)(p - Position), Object->TotalByteLength);

        Position = ObjectEnd;
    }
    ok(Position == End, "%s: objects end %ld bytes before the end of the block\n", What, (LONG)(End - Position));
    return (LONG)Header->NumObjectTypes;
}

static
const PERF_OBJECT_TYPE *
FindObject(
    _In_ const BYTE *Data,
    _In_ DWORD Index)
{
    const PERF_DATA_BLOCK *Header = (const PERF_DATA_BLOCK *)Data;
    const BYTE *Position = Data + Header->HeaderLength;
    DWORD i;

    for (i = 0; i < Header->NumObjectTypes; i++)
    {
        const PERF_OBJECT_TYPE *Object = (const PERF_OBJECT_TYPE *)Position;

        if (Object->ObjectNameTitleIndex == Index)
            return Object;
        Position += Object->TotalByteLength;
    }
    return NULL;
}

static
DWORD
CountObjects(
    _In_ const BYTE *Data,
    _In_ DWORD Index)
{
    const PERF_DATA_BLOCK *Header = (const PERF_DATA_BLOCK *)Data;
    const BYTE *Position = Data + Header->HeaderLength;
    DWORD i, Count = 0;

    for (i = 0; i < Header->NumObjectTypes; i++)
    {
        const PERF_OBJECT_TYPE *Object = (const PERF_OBJECT_TYPE *)Position;

        if (Object->ObjectNameTitleIndex == Index)
            Count++;
        Position += Object->TotalByteLength;
    }
    return Count;
}

/* the first definition with this name index (the base counter of a counter comes after it) */
static
const PERF_COUNTER_DEFINITION *
FindCounter(
    _In_ const PERF_OBJECT_TYPE *Object,
    _In_ DWORD Index)
{
    const BYTE *p = (const BYTE *)Object + Object->HeaderLength;
    DWORD i;

    for (i = 0; i < Object->NumCounters; i++)
    {
        const PERF_COUNTER_DEFINITION *Definition = (const PERF_COUNTER_DEFINITION *)p;

        if (Definition->CounterNameTitleIndex == Index)
            return Definition;
        p += Definition->ByteLength;
    }
    return NULL;
}

/* The counter block of an instance (of the only block when the object has no instances) */
static
const PERF_COUNTER_BLOCK *
GetInstance(
    _In_ const PERF_OBJECT_TYPE *Object,
    _In_ LONG Number,
    _Out_opt_ const WCHAR **Name)
{
    const BYTE *p = (const BYTE *)Object + Object->DefinitionLength;
    LONG i;

    if (Name)
        *Name = NULL;
    if (Object->NumInstances == PERF_NO_INSTANCES)
        return Number == 0 ? (const PERF_COUNTER_BLOCK *)p : NULL;

    for (i = 0; i < Object->NumInstances; i++)
    {
        const PERF_INSTANCE_DEFINITION *Instance = (const PERF_INSTANCE_DEFINITION *)p;
        const PERF_COUNTER_BLOCK *Block = (const PERF_COUNTER_BLOCK *)(p + Instance->ByteLength);

        if (i == Number)
        {
            if (Name)
                *Name = (const WCHAR *)(p + Instance->NameOffset);
            return Block;
        }
        p += Instance->ByteLength + Block->ByteLength;
    }
    return NULL;
}

static
VOID
test_binary_semantics(VOID)
{
    DWORD Type, cb;
    BYTE Small[16];
    LONG ret;

    /* no buffer at all: the block is never smaller than what the caller could have given */
    Type = 0x55555555;
    cb = 0;
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"Global", NULL, &Type, NULL, &cb);
    ok(ret == ERROR_MORE_DATA, "Global without buffer: ret = %ld\n", ret);
    ok(Type == REG_BINARY, "Global without buffer: Type = %lu\n", Type);

    Type = 0x55555555;
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"Global", NULL, &Type, NULL, NULL);
    ok(ret == ERROR_MORE_DATA, "Global without buffer and size: ret = %ld\n", ret);

    /* a buffer that is too small: the size is left alone, nothing is written */
    memset(Small, 0xAA, sizeof(Small));
    Type = 0x55555555;
    cb = sizeof(Small);
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"Global", NULL, &Type, Small, &cb);
    ok(ret == ERROR_MORE_DATA, "Global in a small buffer: ret = %ld\n", ret);
    ok(Type == REG_BINARY, "Global in a small buffer: Type = %lu\n", Type);
    ok(cb == sizeof(Small), "Global in a small buffer: cb = %lu\n", cb);

    Type = 0x55555555;
    cb = sizeof(Small);
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"238", NULL, &Type, Small, &cb);
    ok(ret == ERROR_MORE_DATA, "238 in a small buffer: ret = %ld\n", ret);
    ok(cb == sizeof(Small), "238 in a small buffer: cb = %lu\n", cb);

    /* a buffer without a size, and no value name */
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"Global", NULL, &Type, Small, NULL);
    ok(ret == ERROR_INVALID_PARAMETER, "Global with data and no size: ret = %ld\n", ret);
    cb = sizeof(Small);
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, NULL, NULL, &Type, Small, &cb);
    ok(ret == ERROR_INVALID_PARAMETER, "NULL name: ret = %ld\n", ret);

    /* the type is optional */
    cb = g_BufferSize;
    ret = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"238", NULL, NULL, g_Buffer, &cb);
    ok(ret == ERROR_SUCCESS, "238 without type: ret = %ld\n", ret);
}

static
VOID
test_global(VOID)
{
    static const DWORD Expected[] = { INDEX_SYSTEM, INDEX_MEMORY, INDEX_PROCESS, INDEX_PHYSICALDISK, INDEX_PROCESSOR, INDEX_NETWORK };
    DWORD Type, Size, i;
    LONG ret, Count;

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"Global", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Global: ret = %ld\n", ret);
    if (ret != ERROR_SUCCESS)
        return;
    ok(Type == REG_BINARY, "Global: Type = %lu\n", Type);
    Count = ValidateBlock("Global", g_Buffer, Size);
    ok(Count >= (LONG)PERF_ARRAY_SIZE(Expected), "Global: %ld objects\n", Count);
    for (i = 0; i < PERF_ARRAY_SIZE(Expected) && Count > 0; i++)
        ok(FindObject(g_Buffer, Expected[i]) != NULL, "Global: no object %lu\n", Expected[i]);

    /* an empty name is the same as Global */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "empty name: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        Count = ValidateBlock("empty name", g_Buffer, Size);
        ok(Count >= (LONG)PERF_ARRAY_SIZE(Expected), "empty name: %ld objects\n", Count);
    }

    /* the name is not case sensitive */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"global", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "global: ret = %ld\n", ret);

    ret = QueryValue(HKEY_PERFORMANCE_TEXT, L"Global", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "HKEY_PERFORMANCE_TEXT Global: ret = %ld\n", ret);
    ok(Type == REG_BINARY, "HKEY_PERFORMANCE_TEXT Global: Type = %lu\n", Type);
}

static
VOID
test_object_lists(VOID)
{
    DWORD Type, Size;
    LONG ret, Count;

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"238", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "238: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        Count = ValidateBlock("238", g_Buffer, Size);
        ok(Count >= 1, "238: %ld objects\n", Count);
        ok(CountObjects(g_Buffer, INDEX_PROCESSOR) == 1, "238: no Processor object\n");
    }

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"238 2 4", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "238 2 4: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        Count = ValidateBlock("238 2 4", g_Buffer, Size);
        ok(Count >= 3, "238 2 4: %ld objects\n", Count);
        ok(CountObjects(g_Buffer, INDEX_PROCESSOR) == 1, "238 2 4: Processor\n");
        ok(CountObjects(g_Buffer, INDEX_SYSTEM) == 1, "238 2 4: System\n");
        ok(CountObjects(g_Buffer, INDEX_MEMORY) == 1, "238 2 4: Memory\n");
    }

    /* an object is only returned once, and blanks around the list do not matter */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L" 238 238 ", &Type, &Size);
    ok(ret == ERROR_SUCCESS, " 238 238 : ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        ValidateBlock(" 238 238 ", g_Buffer, Size);
        ok(CountObjects(g_Buffer, INDEX_PROCESSOR) == 1, " 238 238 : Processor %lu times\n",
           CountObjects(g_Buffer, INDEX_PROCESSOR));
    }

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"230 234", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "230 234: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        ValidateBlock("230 234", g_Buffer, Size);
        ok(CountObjects(g_Buffer, INDEX_PROCESS) == 1, "230 234: Process\n");
        ok(CountObjects(g_Buffer, INDEX_PHYSICALDISK) == 1, "230 234: PhysicalDisk\n");
        ok(CountObjects(g_Buffer, INDEX_PROCESSOR) == 0, "230 234: Processor is there\n");
    }

    /* text that is not a list of indices: a block without objects */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"abc", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "abc: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
        ok(ValidateBlock("abc", g_Buffer, Size) == 0, "abc: has objects\n");

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"Foreign x", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Foreign x: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
        ok(ValidateBlock("Foreign x", g_Buffer, Size) == 0, "Foreign x: has objects\n");
}

static
VOID
test_objects(VOID)
{
    const PERF_OBJECT_TYPE *Object;
    const PERF_COUNTER_DEFINITION *Definition;
    const PERF_COUNTER_BLOCK *Block;
    const WCHAR *Name;
    SYSTEM_INFO si;
    DWORD Type, Size, i;
    LONG ret;
    ULONGLONG Idle1, Idle2, Time1, Time2, Value;
    PERF_DATA_BLOCK Header1;
    WCHAR Module[MAX_PATH];
    PWSTR Base;
    BOOL FoundSelf;

    GetSystemInfo(&si);

    /* Processor: one instance per processor, then _Total */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"238", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Processor: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS && (Object = FindObject(g_Buffer, INDEX_PROCESSOR)) != NULL)
    {
        ok(Object->NumInstances == (LONG)si.dwNumberOfProcessors + 1, "Processor: %ld instances, %lu processors\n",
           Object->NumInstances, si.dwNumberOfProcessors);
        for (i = 0; i < si.dwNumberOfProcessors && (LONG)i < Object->NumInstances; i++)
        {
            WCHAR Expect[16];
            StringCchPrintfW(Expect, PERF_ARRAY_SIZE(Expect), L"%lu", i);
            GetInstance(Object, i, &Name);
            ok(Name && !lstrcmpW(Name, Expect), "Processor: instance %lu is %ls\n", i, Name);
        }
        Block = Object->NumInstances > 0 ? GetInstance(Object, Object->NumInstances - 1, &Name) : NULL;
        ok(Name && !lstrcmpW(Name, L"_Total"), "Processor: last instance is %ls\n", Name);

        Definition = FindCounter(Object, INDEX_PROCESSOR_TIME);
        ok(Definition != NULL, "Processor: no % Processor Time\n");
        if (Definition && Block)
        {
            ok(Definition->CounterType == PERF_100NSEC_TIMER_INV, "Processor: type %08lx\n", Definition->CounterType);
            ok(Definition->CounterSize == 8, "Processor: size %lu\n", Definition->CounterSize);

            Idle1 = ReadValue(Block, Definition);
            Header1 = *(PERF_DATA_BLOCK *)g_Buffer;
            Time1 = Header1.PerfTime100nSec.QuadPart;
            Sleep(250);

            ret = QueryValue(HKEY_PERFORMANCE_DATA, L"238", &Type, &Size);
            ok(ret == ERROR_SUCCESS, "Processor again: ret = %ld\n", ret);
            Object = ret == ERROR_SUCCESS ? FindObject(g_Buffer, INDEX_PROCESSOR) : NULL;
            if (Object && Object->NumInstances > 0 && (Block = GetInstance(Object, Object->NumInstances - 1, NULL)) != NULL &&
                (Definition = FindCounter(Object, INDEX_PROCESSOR_TIME)) != NULL)
            {
                Idle2 = ReadValue(Block, Definition);
                Time2 = ((PERF_DATA_BLOCK *)g_Buffer)->PerfTime100nSec.QuadPart;
                ok(Time2 > Time1, "time did not advance: %I64u, %I64u\n", Time1, Time2);
                ok(Idle2 >= Idle1, "idle time went back: %I64u, %I64u\n", Idle1, Idle2);
                /* the idle time of a processor can not grow faster than the clock */
                ok(Idle2 - Idle1 <= 2 * (Time2 - Time1), "idle time grew by %I64u in %I64u\n", Idle2 - Idle1, Time2 - Time1);
            }
            else
                ok(0, "Processor: no second sample\n");
        }
    }
    else
        ok(0, "Processor: no object\n");

    /* Memory has no instances */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"4", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Memory: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS && (Object = FindObject(g_Buffer, INDEX_MEMORY)) != NULL)
    {
        ok(Object->NumInstances == PERF_NO_INSTANCES, "Memory: NumInstances = %ld\n", Object->NumInstances);
        Block = GetInstance(Object, 0, NULL);
        Definition = FindCounter(Object, INDEX_AVAILABLE_BYTES);
        ok(Block && Definition, "Memory: no Available Bytes\n");
        if (Block && Definition)
        {
            Value = ReadValue(Block, Definition);
            ok(Value > 0x100000 && Value < 0x10000000000ULL, "Memory: Available Bytes = %I64u\n", Value);
        }
        Definition = FindCounter(Object, INDEX_PAGES_PER_SEC);
        ok(Definition && Definition->CounterType == PERF_COUNTER_COUNTER, "Memory: Pages/sec type %08lx\n",
           Definition ? Definition->CounterType : 0);
    }
    else
        ok(0, "Memory: no object\n");

    /* System: process and thread counts, and the elapsed time of the start of the system */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"2", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "System: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS && (Object = FindObject(g_Buffer, INDEX_SYSTEM)) != NULL)
    {
        const PERF_COUNTER_DEFINITION *Threads, *Uptime;
        ULONGLONG Processes;

        ok(Object->NumInstances == PERF_NO_INSTANCES, "System: NumInstances = %ld\n", Object->NumInstances);
        Block = GetInstance(Object, 0, NULL);
        Definition = FindCounter(Object, INDEX_PROCESSES);
        Threads = FindCounter(Object, INDEX_THREADS);
        Uptime = FindCounter(Object, INDEX_UPTIME);
        ok(Block && Definition && Threads && Uptime, "System: missing counters\n");
        if (Block && Definition && Threads && Uptime)
        {
            Processes = ReadValue(Block, Definition);
            ok(Processes >= 1 && Processes < 100000, "System: %I64u processes\n", Processes);
            ok(ReadValue(Block, Threads) >= Processes, "System: %I64u threads\n", ReadValue(Block, Threads));

            Value = ReadValue(Block, Uptime);
            ok(Uptime->CounterType == PERF_ELAPSED_TIME, "System: Up Time type %08lx\n", Uptime->CounterType);
            ok(Object->PerfFreq.QuadPart > 0, "System: object PerfFreq = %I64d\n", Object->PerfFreq.QuadPart);
            ok((ULONGLONG)Object->PerfTime.QuadPart > Value, "System: start %I64u is after now %I64d\n", Value,
               Object->PerfTime.QuadPart);
            if (Object->PerfFreq.QuadPart > 0 && (ULONGLONG)Object->PerfTime.QuadPart > Value)
            {
                ULONGLONG Seconds = ((ULONGLONG)Object->PerfTime.QuadPart - Value) / Object->PerfFreq.QuadPart;
                ok(Seconds < 10ULL * 365 * 24 * 3600, "System: up for %I64u seconds\n", Seconds);
            }
        }
    }
    else
        ok(0, "System: no object\n");

    /* Process: this process is one of the instances, _Total is the last */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"230", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Process: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS && (Object = FindObject(g_Buffer, INDEX_PROCESS)) != NULL)
    {
        ok(Object->NumInstances >= 2, "Process: %ld instances\n", Object->NumInstances);
        Block = Object->NumInstances > 0 ? GetInstance(Object, Object->NumInstances - 1, &Name) : NULL;
        ok(Name && !lstrcmpW(Name, L"_Total"), "Process: last instance is %ls\n", Name);

        Definition = FindCounter(Object, INDEX_ID_PROCESS);
        ok(Definition != NULL, "Process: no ID Process\n");
        FoundSelf = FALSE;
        if (Definition)
        {
            GetModuleFileNameW(NULL, Module, PERF_ARRAY_SIZE(Module));
            Base = wcsrchr(Module, L'\\');
            Base = Base ? Base + 1 : Module;
            if (lstrlenW(Base) > 4 && !lstrcmpiW(Base + lstrlenW(Base) - 4, L".exe"))
                Base[lstrlenW(Base) - 4] = 0;

            for (i = 0; (LONG)i + 1 < Object->NumInstances; i++)
            {
                Block = GetInstance(Object, i, &Name);
                if (Block && ReadValue(Block, Definition) == GetCurrentProcessId())
                {
                    FoundSelf = TRUE;
                    ok(!_wcsnicmp(Name, Base, 15), "Process: this process is %ls, expected %ls\n", Name, Base);
                    break;
                }
            }
        }
        ok(FoundSelf, "Process: this process (%lu) is not an instance\n", GetCurrentProcessId());
    }
    else
        ok(0, "Process: no object\n");

    /* PhysicalDisk and Network Interface: the objects exist, instances are optional but _Total ends the disks */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"234", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "PhysicalDisk: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS && (Object = FindObject(g_Buffer, INDEX_PHYSICALDISK)) != NULL)
    {
        ok(Object->NumInstances >= 1, "PhysicalDisk: %ld instances\n", Object->NumInstances);
        if (Object->NumInstances >= 1)
        {
            GetInstance(Object, Object->NumInstances - 1, &Name);
            ok(Name && !lstrcmpW(Name, L"_Total"), "PhysicalDisk: last instance is %ls\n", Name);
        }
    }
    else
        ok(0, "PhysicalDisk: no object\n");

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"510", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Network Interface: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        ok(ValidateBlock("510", g_Buffer, Size) >= 1, "Network Interface: no object\n");
        Object = FindObject(g_Buffer, INDEX_NETWORK);
        ok(Object != NULL, "Network Interface: no object\n");
        if (Object)
            ok(Object->NumInstances >= 0, "Network Interface: NumInstances = %ld\n", Object->NumInstances);
    }
}

/* Reads the 238 block into Buffer and returns the _Total raw % Processor Time counter and the 100 ns time of the block */
static
BOOL
SampleProcessorTime(
    _Out_ PULONGLONG Data,
    _Out_ PULONGLONG Time,
    _Out_ PDWORD CounterType)
{
    const PERF_DATA_BLOCK *Header;
    const PERF_OBJECT_TYPE *Object;
    const PERF_COUNTER_DEFINITION *Definition;
    const PERF_COUNTER_BLOCK *Block;
    const WCHAR *Name;
    DWORD Type, Size;
    LONG ret, i;

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"238", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "238: ret = %ld\n", ret);
    if (ret != ERROR_SUCCESS)
        return FALSE;
    Header = (const PERF_DATA_BLOCK *)g_Buffer;
    Object = FindObject(g_Buffer, INDEX_PROCESSOR);
    ok(Object != NULL, "238: no Processor object\n");
    if (!Object)
        return FALSE;
    Definition = FindCounter(Object, INDEX_PROCESSOR_TIME);
    ok(Definition != NULL, "238: no %% Processor Time\n");
    if (!Definition || Definition->CounterSize != 8)
        return FALSE;
    for (i = 0; i < Object->NumInstances; i++)
    {
        Block = GetInstance(Object, i, &Name);
        if (Block && Name && !lstrcmpW(Name, L"_Total"))
        {
            *Data = ReadValue(Block, Definition);
            *Time = Header->PerfTime100nSec.QuadPart;
            *CounterType = Definition->CounterType;
            return TRUE;
        }
    }
    ok(0, "238: no _Total instance\n");
    return FALSE;
}

/*
 * What .NET and PDH do for % Processor Time (PERF_100NSEC_TIMER_INV): two samples, and
 * 100 * (1 - delta idle time / delta time). A counter that does not advance reads 100 %.
 */
static
VOID
test_processor_time(VOID)
{
    ULONGLONG Data1, Time1, Data2, Time2;
    DWORD Type1, Type2;
    double Percent;

    if (!SampleProcessorTime(&Data1, &Time1, &Type1))
        return;
    Sleep(1000);
    if (!SampleProcessorTime(&Data2, &Time2, &Type2))
        return;

    ok(Type1 == 0x21510500 && Type2 == Type1, "%% Processor Time types: 0x%lx, 0x%lx\n", Type1, Type2);
    ok(Time2 > Time1, "PerfTime100nSec did not advance: %I64u, %I64u\n", Time1, Time2);
    ok(Time2 - Time1 > 5000000 && Time2 - Time1 < 100000000, "1 s sleep, but PerfTime100nSec advanced by %I64u\n", Time2 - Time1);
    /* a counter that stays 0 is the failure that matters: 0 and 0 give 100 % */
    ok(Data1 != 0 && Data2 != 0, "_Total idle time is 0: %I64u, %I64u\n", Data1, Data2);
    ok(Data2 >= Data1, "_Total idle time went back: %I64u, %I64u\n", Data1, Data2);
    if (Time2 <= Time1)
        return;

    Percent = 100.0 * (1.0 - (double)(LONGLONG)(Data2 - Data1) / (double)(LONGLONG)(Time2 - Time1));
    trace("%% Processor Time _Total = %.2f (idle %I64u of %I64u)\n", Percent, Data2 - Data1, Time2 - Time1);
    /* The idle time is in ticks and a loaded host can make a guest look busy, so only the range is checked, not that it is low */
    ok(Percent >= -1.0 && Percent <= 100.0, "%% Processor Time _Total = %.2f\n", Percent);
}

static
VOID
test_ansi(VOID)
{
    DWORD Type, cb, Wide;
    LONG ret;

    /* the ANSI function: names are converted, and so is the text of the name tables */
    Type = 0x55555555;
    cb = g_BufferSize;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "238", NULL, &Type, g_Buffer, &cb);
    ok(ret == ERROR_SUCCESS, "A 238: ret = %ld\n", ret);
    ok(Type == REG_BINARY, "A 238: Type = %lu\n", Type);
    if (ret == ERROR_SUCCESS)
        ok(ValidateBlock("A 238", g_Buffer, cb) >= 1, "A 238: no object\n");

    cb = g_BufferSize;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", NULL, &Type, g_Buffer, &cb);
    ok(ret == ERROR_SUCCESS, "A Global: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
        ok(ValidateBlock("A Global", g_Buffer, cb) >= 6, "A Global: too few objects\n");

    /* without a name, the ANSI function returns Global */
    cb = g_BufferSize;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, NULL, NULL, &Type, g_Buffer, &cb);
    ok(ret == ERROR_SUCCESS, "A NULL name: ret = %ld\n", ret);
    ok(Type == REG_BINARY, "A NULL name: Type = %lu\n", Type);

    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"Counter 009", &Type, &Wide);
    ok(ret == ERROR_SUCCESS, "Counter 009: ret = %ld\n", ret);

    Type = 0x55555555;
    cb = 0;
    ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Counter 009", NULL, &Type, NULL, &cb);
    ok(ret == ERROR_SUCCESS, "A Counter 009 size: ret = %ld\n", ret);
    ok(Type == REG_MULTI_SZ, "A Counter 009 size: Type = %lu\n", Type);
    ok(cb > 1000 && cb <= Wide, "A Counter 009 size: cb = %lu, wide %lu\n", cb, Wide);

    {
        BYTE *Ansi = HeapAlloc(GetProcessHeap(), 0, cb ? cb : 1);
        if (Ansi)
        {
            DWORD cb2 = cb;
            ret = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Counter 009", NULL, &Type, Ansi, &cb2);
            ok(ret == ERROR_SUCCESS, "A Counter 009: ret = %ld\n", ret);
            ok(cb2 == cb, "A Counter 009: cb2 = %lu, cb %lu\n", cb2, cb);
            if (ret == ERROR_SUCCESS)
            {
                /* find "238" followed by "Processor" */
                const char *p = (const char *)Ansi, *end = p + cb2;
                BOOL Found = FALSE;
                while (p < end && *p)
                {
                    const char *Text = p + strlen(p) + 1;
                    if (Text >= end)
                        break;
                    if (!strcmp(p, "238") && !strcmp(Text, "Processor"))
                        Found = TRUE;
                    p = Text + strlen(Text) + 1;
                }
                ok(Found, "A Counter 009: 238 is not Processor\n");
            }
            HeapFree(GetProcessHeap(), 0, Ansi);
        }
    }

    /* RegGetValue goes through the same code */
    cb = g_BufferSize;
    ret = RegGetValueW(HKEY_PERFORMANCE_DATA, NULL, L"238", RRF_RT_REG_BINARY, &Type, g_Buffer, &cb);
    ok(ret == ERROR_SUCCESS, "RegGetValueW 238: ret = %ld\n", ret);
    ok(Type == REG_BINARY, "RegGetValueW 238: Type = %lu\n", Type);
    if (ret == ERROR_SUCCESS)
        ok(ValidateBlock("RegGetValueW 238", g_Buffer, cb) >= 1, "RegGetValueW 238: no object\n");
}

static
VOID
test_open(VOID)
{
    HKEY Key = (HKEY)0x1234;
    LONG ret;

    /* the performance data has no keys to open */
    ret = RegOpenKeyExW(HKEY_PERFORMANCE_DATA, L"x", 0, KEY_READ, &Key);
    ok(ret == ERROR_INVALID_HANDLE, "RegOpenKeyExW with a subkey returned %ld\n", ret);
    Key = (HKEY)0x1234;
    ret = RegOpenKeyExW(HKEY_PERFORMANCE_DATA, NULL, 0, KEY_READ, &Key);
    ok(ret == ERROR_INVALID_HANDLE, "RegOpenKeyExW without a subkey returned %ld\n", ret);
}

static
VOID
test_new_objects(VOID)
{
    static const struct { DWORD Index; PCWSTR Name; DWORD Counters; DWORD DefaultName; } Objects[] =
    {
        { 232, L"Thread", 11, 146 },
        { 236, L"LogicalDisk", 23, 200 },
        { 3518, L"Processor Information", 10, 6 },
    };
    const PERF_OBJECT_TYPE *Object;
    const PERF_COUNTER_DEFINITION *Definition;
    DWORD Type, Size, i, k, Slots;
    const WCHAR *Text;
    LONG ret;

    /* the objects of the Global block and of a list by index */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"232 236 3518", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "232 236 3518: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        ValidateBlock("232 236 3518", g_Buffer, Size);
        for (i = 0; i < PERF_ARRAY_SIZE(Objects); i++)
        {
            Object = FindObject(g_Buffer, Objects[i].Index);
            ok(Object != NULL, "%ls: not in the block\n", Objects[i].Name);
            if (!Object)
                continue;
            ok(Object->ObjectHelpTitleIndex == Objects[i].Index + 1, "%ls: help index %lu\n", Objects[i].Name, Object->ObjectHelpTitleIndex);
            ok(Object->NumInstances > 0, "%ls: %ld instances\n", Objects[i].Name, (LONG)Object->NumInstances);
            /* a counter followed by a base counter takes two definitions */
            Slots = Object->NumCounters;
            ok(Slots >= Objects[i].Counters, "%ls: %lu definitions\n", Objects[i].Name, Slots);
            Definition = (const PERF_COUNTER_DEFINITION *)((const BYTE *)Object + Object->HeaderLength);
            for (k = 0; k < Slots; k++)
                ok(Definition[k].CounterHelpTitleIndex == Definition[k].CounterNameTitleIndex + 1, "%ls: counter %lu help %lu\n",
                   Objects[i].Name, Definition[k].CounterNameTitleIndex, Definition[k].CounterHelpTitleIndex);
            ok(Object->DefaultCounter < (LONG)Slots && Definition[Object->DefaultCounter].CounterNameTitleIndex == Objects[i].DefaultName,
               "%ls: default counter %ld is %lu, expected %lu\n", Objects[i].Name, Object->DefaultCounter,
               Object->DefaultCounter < (LONG)Slots ? Definition[Object->DefaultCounter].CounterNameTitleIndex : 0, Objects[i].DefaultName);
        }
        /* the Processor Information counter that has no Processor equivalent */
        Object = FindObject(g_Buffer, 3518);
        if (Object)
            ok(FindCounter(Object, 3572) != NULL, "Processor Information: no % Processor Utility\n");
    }

    /* the names and the explain text of the objects are in the tables */
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"Counter 009", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Counter 009: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        for (i = 0; i < PERF_ARRAY_SIZE(Objects); i++)
        {
            Text = FindText((PWSTR)g_Buffer, Size, Objects[i].Index);
            ok(Text && !lstrcmpW(Text, Objects[i].Name), "%lu: name is %ls\n", Objects[i].Index, Text);
        }
    }
    ret = QueryValue(HKEY_PERFORMANCE_DATA, L"Help 009", &Type, &Size);
    ok(ret == ERROR_SUCCESS, "Help 009: ret = %ld\n", ret);
    if (ret == ERROR_SUCCESS)
    {
        for (i = 0; i < PERF_ARRAY_SIZE(Objects); i++)
        {
            Text = FindText((PWSTR)g_Buffer, Size, Objects[i].Index + 1);
            ok(Text && lstrlenW(Text) > 20, "%lu: help is %ls\n", Objects[i].Index + 1, Text);
        }
    }
}

START_TEST(RegPerformanceData)
{
    LONG ret;

    g_BufferSize = 64000;
    g_Buffer = HeapAlloc(GetProcessHeap(), 0, g_BufferSize);
    if (!g_Buffer)
    {
        skip("No memory\n");
        return;
    }

    test_name_tables();
    test_binary_semantics();
    test_global();
    test_object_lists();
    test_objects();
    test_new_objects();
    test_processor_time();
    test_ansi();
    test_open();

    /* the pseudo handle can be closed any number of times */
    ret = RegCloseKey(HKEY_PERFORMANCE_DATA);
    ok(ret == ERROR_SUCCESS, "RegCloseKey returned %ld\n", ret);

    HeapFree(GetProcessHeap(), 0, g_Buffer);
}
