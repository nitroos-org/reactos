/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Hive files with cells that point where they must not, loaded with
 *              RegLoadKeyW: each is either refused as corrupt or loads repaired,
 *              and then every key, value, class and descriptor reads back, keys
 *              are deleted and created, and the hive unloads.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The hives are made by the test: a small tree is saved with RegSaveKeyW and
 * one recipe at a time changes a field of a cell of the file (no binary files).
 * Each recipe is one kind of hive that crashed or hung the kernel, or could
 * not be unloaded, before the load-time check of every cell (sdk/lib/cmlib/
 * cmcheck.c); the host fuzz test of that check (sdk/lib/cmlib/tests/
 * HiveFuzz.c) found most of them. Needs the backup and restore privileges
 * (an administrator).
 */

#include "precomp.h"
#include <winbase.h>
#include <sddl.h>

#define LOAD_TIMEOUT 30000
#define BASE_KEY L"Software\\ReactOSCraftedHiveBase"
#define MOUNT L"ReactOSCraftedHive"

/* Field offsets in the cells of a hive file (the data of a cell follows its 4-byte size) */
#define NK_FLAGS            0x02
#define NK_PARENT           0x10
#define NK_SUBKEY_COUNT     0x14
#define NK_VOLATILE_COUNT   0x18
#define NK_SUBKEY_LIST      0x1C
#define NK_VOLATILE_LIST    0x20
#define NK_VALUE_COUNT      0x24
#define NK_VALUE_LIST       0x28
#define NK_SECURITY         0x2C
#define NK_CLASS            0x30
#define NK_MAX_NAME         0x34
#define NK_MAX_VALUE_NAME   0x3C
#define NK_NAME_LENGTH      0x48
#define NK_CLASS_LENGTH     0x4A
#define NK_NAME             0x4C
#define VK_NAME_LENGTH      0x02
#define VK_DATA_LENGTH      0x04
#define VK_DATA             0x08
#define VK_NAME             0x14
#define SK_FLINK            0x04
#define SK_BLINK            0x08
#define SK_REFS             0x0C
#define SK_LENGTH           0x10

#define KEY_HIVE_EXIT       0x0002
#define KEY_PREDEF_HANDLE   0x0040

static PBYTE g_Base;
static DWORD g_BaseSize;
static WCHAR g_File[MAX_PATH];

/* Not in the headers of every target version */
static LSTATUS (WINAPI *pRegDeleteTreeW)(HKEY, LPCWSTR);
#define RegDeleteTreeW pRegDeleteTreeW

static BOOL EnablePrivilege(PCWSTR Name)
{
    HANDLE Token;
    TOKEN_PRIVILEGES Privileges;
    BOOL Success;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token))
        return FALSE;
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Success = LookupPrivilegeValueW(NULL, Name, &Privileges.Privileges[0].Luid) &&
              AdjustTokenPrivileges(Token, FALSE, &Privileges, 0, NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(Token);
    return Success;
}

/* ---- the base hive ---- */

static void SetValues(HKEY Key)
{
    static BYTE Binary[64];
    DWORD Data = 0x12345678;

    RegSetValueExW(Key, L"d", 0, REG_DWORD, (PBYTE)&Data, sizeof(Data));
    RegSetValueExW(Key, L"s", 0, REG_SZ, (PBYTE)L"string value", sizeof(L"string value"));
    RegSetValueExW(Key, L"b", 0, REG_BINARY, Binary, sizeof(Binary));
}

static HKEY Create(HKEY Parent, PCWSTR Name, PWSTR Class, PCWSTR Sddl)
{
    HKEY Key = NULL;
    SECURITY_ATTRIBUTES Sa = { sizeof(Sa), NULL, FALSE };
    PSECURITY_DESCRIPTOR Sd = NULL;

    if (Sddl && ConvertStringSecurityDescriptorToSecurityDescriptorW(Sddl, SDDL_REVISION_1, &Sd, NULL))
        Sa.lpSecurityDescriptor = Sd;
    RegCreateKeyExW(Parent, Name, 0, Class, 0, KEY_ALL_ACCESS, &Sa, &Key, NULL);
    if (Sd)
        LocalFree(Sd);
    return Key;
}

/*
 * The tree: A (class, values), B (values), C (values, subkeys C\0..C\2), D (own
 * descriptor), E (the same descriptor as D), Many (600 subkeys: an index root
 * with several leaves).
 */
static BOOL MakeBase(void)
{
    HKEY Base, Key, Sub;
    WCHAR Name[16];
    HANDLE Handle;
    DWORD Read, i;
    LONG Error;
    static const WCHAR Sddl[] = L"D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)";

    RegDeleteTreeW(HKEY_CURRENT_USER, BASE_KEY);
    Base = Create(HKEY_CURRENT_USER, BASE_KEY, NULL, NULL);
    if (!Base)
        return FALSE;
    SetValues(Base);
    Key = Create(Base, L"A", L"ClassOfA", NULL); SetValues(Key); RegCloseKey(Key);
    Key = Create(Base, L"B", NULL, NULL); SetValues(Key); RegCloseKey(Key);
    Key = Create(Base, L"C", NULL, NULL);
    SetValues(Key);
    for (i = 0; i < 3; i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"%lu", i);
        Sub = Create(Key, Name, NULL, NULL);
        SetValues(Sub);
        RegCloseKey(Sub);
    }
    RegCloseKey(Key);
    Key = Create(Base, L"D", NULL, Sddl); RegCloseKey(Key);
    Key = Create(Base, L"E", NULL, Sddl); RegCloseKey(Key);
    Key = Create(Base, L"Many", NULL, NULL);
    for (i = 0; i < 600; i++)
    {
        StringCchPrintfW(Name, _countof(Name), L"m%04lu", i);
        Sub = Create(Key, Name, NULL, NULL);
        RegCloseKey(Sub);
    }
    RegCloseKey(Key);

    DeleteFileW(g_File);
    Error = RegSaveKeyW(Base, g_File, NULL);
    ok(Error == ERROR_SUCCESS, "RegSaveKeyW failed: %ld\n", Error);
    RegCloseKey(Base);
    RegDeleteTreeW(HKEY_CURRENT_USER, BASE_KEY);
    RegDeleteKeyW(HKEY_CURRENT_USER, BASE_KEY);
    if (Error != ERROR_SUCCESS)
        return FALSE;

    Handle = CreateFileW(g_File, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (Handle == INVALID_HANDLE_VALUE)
        return FALSE;
    g_BaseSize = GetFileSize(Handle, NULL);
    g_Base = HeapAlloc(GetProcessHeap(), 0, g_BaseSize);
    if (g_Base && (!ReadFile(Handle, g_Base, g_BaseSize, &Read, NULL) || Read != g_BaseSize))
    {
        HeapFree(GetProcessHeap(), 0, g_Base);
        g_Base = NULL;
    }
    CloseHandle(Handle);
    return g_Base != NULL;
}

/* ---- finding cells in a file image ---- */

#define CELL(Buf, Index) ((Buf) + 0x1000 + (Index) + 4)     /* the data of a cell */
#define D32(p, o) (*(PDWORD)((PBYTE)(p) + (o)))
#define W16(p, o) (*(PWORD)((PBYTE)(p) + (o)))

/* The cell index of the key node named Name (compressed names only: the test's names are ASCII), or -1 */
static DWORD FindKey(PBYTE Buf, DWORD Size, PCSTR Name)
{
    DWORD Off = 0x1000, BinSize, c, Length = (DWORD)strlen(Name);
    LONG CellSize;

    while (Off + 0x20 <= Size && !memcmp(Buf + Off, "hbin", 4))
    {
        BinSize = D32(Buf + Off, 8);
        if (BinSize < 0x1000 || BinSize > Size - Off)
            break;
        for (c = 0x20; c + 8 <= BinSize; c += (DWORD)(CellSize < 0 ? -CellSize : CellSize))
        {
            PBYTE Data = Buf + Off + c + 4;

            CellSize = *(PLONG)(Buf + Off + c);
            if (CellSize == 0 || (DWORD)(CellSize < 0 ? -CellSize : CellSize) > BinSize - c)
                break;
            if (CellSize < -(LONG)(4 + NK_NAME) && !memcmp(Data, "nk", 2) && W16(Data, NK_NAME_LENGTH) == Length &&
                (DWORD)(-CellSize) >= 4 + NK_NAME + Length && !_strnicmp((PCSTR)Data + NK_NAME, Name, Length))
            {
                return Off - 0x1000 + c;
            }
        }
        Off += BinSize;
    }
    return (DWORD)-1;
}

/* The cell index of value Name of the key at Key */
static DWORD FindValue(PBYTE Buf, DWORD Key, PCSTR Name)
{
    PBYTE Node = CELL(Buf, Key);
    DWORD i, Count = D32(Node, NK_VALUE_COUNT);
    PDWORD List = (PDWORD)CELL(Buf, D32(Node, NK_VALUE_LIST));

    for (i = 0; i < Count; i++)
    {
        PBYTE Value = CELL(Buf, List[i]);
        if (W16(Value, VK_NAME_LENGTH) == strlen(Name) && !_strnicmp((PCSTR)Value + VK_NAME, Name, strlen(Name)))
            return List[i];
    }
    return (DWORD)-1;
}

/* ---- the recipes: each changes one copy of the base ---- */

typedef struct _RECIPE
{
    PCSTR Name;
    void (*Apply)(PBYTE Buf, DWORD Size);
    BOOL MustLoad;      /* the damage is repaired at load (or harmless): the hive must load */
} RECIPE;

static DWORD K(PBYTE Buf, DWORD Size, PCSTR Name) { return FindKey(Buf, Size, Name); }

/* A class cell index into the middle of another cell, with its length kept */
static void R_ClassMidCell(PBYTE Buf, DWORD Size)
{
    DWORD A = K(Buf, Size, "A");
    D32(CELL(Buf, A), NK_CLASS) = D32(CELL(Buf, FindValue(Buf, A, "b")), VK_DATA) + 8;
}
/* No class, and a class cell index that is not a cell: deleting the key dirtied it */
static void R_ClassLengthZero(PBYTE Buf, DWORD Size)
{
    DWORD A = K(Buf, Size, "A");
    W16(CELL(Buf, A), NK_CLASS_LENGTH) = 0;
    D32(CELL(Buf, A), NK_CLASS) = 0x7FFFFFF8;
}
/* Two keys share one subkey list: deleting the subkeys of one freed the list of the other */
static void R_SharedSubkeyList(PBYTE Buf, DWORD Size)
{
    DWORD B = K(Buf, Size, "B"), C = K(Buf, Size, "C");
    D32(CELL(Buf, B), NK_SUBKEY_COUNT) = D32(CELL(Buf, C), NK_SUBKEY_COUNT);
    D32(CELL(Buf, B), NK_SUBKEY_LIST) = D32(CELL(Buf, C), NK_SUBKEY_LIST);
}
/* Two keys share one value list */
static void R_SharedValueList(PBYTE Buf, DWORD Size)
{
    DWORD A = K(Buf, Size, "A"), B = K(Buf, Size, "B");
    D32(CELL(Buf, B), NK_VALUE_LIST) = D32(CELL(Buf, A), NK_VALUE_LIST);
}
/* A leaf of an index root with no entry: lookups read the entry before the first */
static void R_EmptyLeafInRoot(PBYTE Buf, DWORD Size)
{
    PBYTE Root = CELL(Buf, D32(CELL(Buf, K(Buf, Size, "Many")), NK_SUBKEY_LIST));
    if (!memcmp(Root, "ri", 2))
        W16(CELL(Buf, D32(Root, 4)), 2) = 0;
}
/* An index root that lists itself as a leaf */
static void R_IndexCycle(PBYTE Buf, DWORD Size)
{
    DWORD List = D32(CELL(Buf, K(Buf, Size, "Many")), NK_SUBKEY_LIST);
    PBYTE Root = CELL(Buf, List);
    if (!memcmp(Root, "ri", 2))
        D32(Root, 4 + 4) = List;
}
/* A subkey entry that names an ancestor (a cycle in the tree) */
static void R_SubkeyIsAncestor(PBYTE Buf, DWORD Size)
{
    DWORD C = K(Buf, Size, "C");
    PBYTE Leaf = CELL(Buf, D32(CELL(Buf, C), NK_SUBKEY_LIST));
    D32(Leaf, 4) = C;
}
/* A file key with volatile subkeys */
static void R_VolatileInFile(PBYTE Buf, DWORD Size)
{
    DWORD A = K(Buf, Size, "A");
    D32(CELL(Buf, A), NK_VOLATILE_COUNT) = 1;
    D32(CELL(Buf, A), NK_VOLATILE_LIST) = D32(CELL(Buf, A), NK_VALUE_LIST);
}
/* Small data longer than the 4 bytes the value cell holds */
static void R_SmallDataTooLong(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, FindValue(Buf, K(Buf, Size, "A"), "d")), VK_DATA_LENGTH) = 0x80000000 | 0x1000;
}
/* Data longer than its cell */
static void R_DataPastCell(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, FindValue(Buf, K(Buf, Size, "A"), "b")), VK_DATA_LENGTH) = 0x10000;
}
/* A value list entry that names a key node */
static void R_ValueIsKey(PBYTE Buf, DWORD Size)
{
    DWORD A = K(Buf, Size, "A");
    ((PDWORD)CELL(Buf, D32(CELL(Buf, A), NK_VALUE_LIST)))[0] = K(Buf, Size, "B");
}
/* A value count past its list cell */
static void R_ValueCountPastList(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, K(Buf, Size, "A")), NK_VALUE_COUNT) = 0x40000001;
}
/* A security cell index into the middle of a cell */
static void R_SecurityMidCell(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, K(Buf, Size, "B")), NK_SECURITY) = K(Buf, Size, "C") + 8;
}
/* An 'sk' cell whose ring loops back to itself without closing through its neighbours */
static void R_SecurityRingLoop(PBYTE Buf, DWORD Size)
{
    DWORD Sk = D32(CELL(Buf, K(Buf, Size, "D")), NK_SECURITY);
    D32(CELL(Buf, D32(CELL(Buf, Sk), SK_FLINK)), SK_FLINK) = D32(CELL(Buf, Sk), SK_FLINK);
}
/* An 'sk' cell counted once, named by several keys: the first delete freed it */
static void R_SecurityUnderCounted(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, D32(CELL(Buf, K(Buf, Size, "D")), NK_SECURITY)), SK_REFS) = 1;
}
/* A descriptor longer than its cell */
static void R_SecurityLengthPastCell(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, D32(CELL(Buf, K(Buf, Size, "D")), NK_SECURITY)), SK_LENGTH) = 0x10000;
}
/* Longest name fields that do not fit the key control block's 16 bits */
static void R_MaxNameTooLarge(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, K(Buf, Size, "C")), NK_MAX_NAME) = 0x12345;
    D32(CELL(Buf, K(Buf, Size, "C")), NK_MAX_VALUE_NAME) = 0x23456;
}
/*
 * The longest value name and class of a key without values or subkeys past 16 bits: RegDeleteTreeW sized its
 * buffer by them (in 32 bits: a tiny buffer on i386) and the heap of the process was damaged (in-guest fuzz)
 */
static void R_MaxFieldsNoValues(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, K(Buf, Size, "E")), NK_MAX_VALUE_NAME) = 0xFFFFFFFE;
    D32(CELL(Buf, K(Buf, Size, "E")), NK_MAX_NAME + 4) = 0xFFFFFFF0;        /* MaxClassLen */
    D32(CELL(Buf, K(Buf, Size, "E")), NK_MAX_VALUE_NAME + 4) = 0xFFFFFFF0;  /* MaxValueDataLen */
}
/* Flags a key of a file cannot have: hive exit (its subkey fields taken for a pointer), predefined handle */
static void R_ExitAndPredefFlags(PBYTE Buf, DWORD Size)
{
    W16(CELL(Buf, K(Buf, Size, "A")), NK_FLAGS) |= KEY_HIVE_EXIT;
    W16(CELL(Buf, K(Buf, Size, "B")), NK_FLAGS) |= KEY_PREDEF_HANDLE;
}
/* A key that names another parent */
static void R_WrongParent(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, K(Buf, Size, "0")), NK_PARENT) = K(Buf, Size, "A");
}
/* Subkeys out of order: lookups by name assume the order */
static void R_OutOfOrder(PBYTE Buf, DWORD Size)
{
    PBYTE Leaf = CELL(Buf, D32(CELL(Buf, K(Buf, Size, "C")), NK_SUBKEY_LIST));
    DWORD Entry = (!memcmp(Leaf, "lf", 2) || !memcmp(Leaf, "lh", 2)) ? 8 : 4, T;
    T = D32(Leaf, 4);
    D32(Leaf, 4) = D32(Leaf, 4 + Entry);
    D32(Leaf, 4 + Entry) = T;
}
/* A subkey count larger than the index holds */
static void R_SubkeyCountTooLarge(PBYTE Buf, DWORD Size)
{
    D32(CELL(Buf, K(Buf, Size, "C")), NK_SUBKEY_COUNT) = 0x7FFFFFFF;
}
/* A Unicode name of an odd number of bytes (the compressed flag cleared): lookups compared lengths and missed it */
static void R_OddNameLength(PBYTE Buf, DWORD Size)
{
    DWORD C = K(Buf, Size, "C");
    W16(CELL(Buf, C), NK_FLAGS) &= ~0x0020;     /* KEY_COMP_NAME; the name "C" is 1 byte */
}
/* A key flagged as a link without a link value: its KCB stayed referenced and the hive did not unload (F13) */
static void R_LinkFlagNoValue(PBYTE Buf, DWORD Size)
{
    W16(CELL(Buf, K(Buf, Size, "B")), NK_FLAGS) |= 0x0010;  /* KEY_SYM_LINK */
}
/* The root key flagged as a link: linking the hive used a key body the open had not made (in-VM fuzz, bugcheck 0x1E) */
static void R_RootIsLink(PBYTE Buf, DWORD Size)
{
    UNREFERENCED_PARAMETER(Size);
    W16(CELL(Buf, D32(Buf, 0x24)), NK_FLAGS) |= 0x0010;    /* the base block's RootCell; KEY_SYM_LINK */
}
/*
 * A subkey name beginning with a NUL: the parser takes it for the end of a path, so no open reaches the key (one by
 * its name opens the parent) and RegDeleteTreeW of the parent emptied the parent again and again until the stack
 * overflowed (in-guest fuzz). The check drops the key at load.
 */
static void R_NulInName(PBYTE Buf, DWORD Size)
{
    CELL(Buf, K(Buf, Size, "0"))[NK_NAME] = 0;     /* C\0 */
}
/*
 * A subkey name with a NUL inside (names are counted; the native API makes such keys): as a C string it names
 * another key, so RegDeleteTreeW of its parent failed (or deleted the other key); it deletes it by its counted name
 */
static void R_NulInsideName(PBYTE Buf, DWORD Size)
{
    CELL(Buf, K(Buf, Size, "m0000"))[NK_NAME + 4] = 0;   /* Many\m0000 -> "m000<NUL>": still first in its index */
}
/* An allocated cell whose size runs past its bin */
static void R_CellPastBin(PBYTE Buf, DWORD Size)
{
    *(PLONG)(CELL(Buf, K(Buf, Size, "B")) - 4) = -0x7FFFFFF8;
}

static const RECIPE g_Recipes[] =
{
    { "class into the middle of a cell", R_ClassMidCell, TRUE },
    { "class length 0, class cell garbage", R_ClassLengthZero, TRUE },
    { "two keys share a subkey list", R_SharedSubkeyList, TRUE },
    { "two keys share a value list", R_SharedValueList, TRUE },
    { "empty leaf in an index root", R_EmptyLeafInRoot, TRUE },
    { "index root lists itself", R_IndexCycle, TRUE },
    { "subkey entry is an ancestor", R_SubkeyIsAncestor, TRUE },
    { "volatile subkeys in a file", R_VolatileInFile, TRUE },
    { "small data longer than 4 bytes", R_SmallDataTooLong, TRUE },
    { "data past its cell", R_DataPastCell, TRUE },
    { "value list entry is a key", R_ValueIsKey, TRUE },
    { "value count past the list", R_ValueCountPastList, TRUE },
    { "security into the middle of a cell", R_SecurityMidCell, TRUE },
    { "security ring loop", R_SecurityRingLoop, TRUE },
    { "security cell under-counted", R_SecurityUnderCounted, TRUE },
    { "descriptor past its cell", R_SecurityLengthPastCell, TRUE },
    { "longest name fields past 16 bits", R_MaxNameTooLarge, TRUE },
    { "longest value name, class, data of a key without values", R_MaxFieldsNoValues, TRUE },
    { "hive exit and predefined handle flags", R_ExitAndPredefFlags, TRUE },
    { "subkey names another parent", R_WrongParent, TRUE },
    { "subkeys out of order", R_OutOfOrder, TRUE },
    { "subkey count larger than the index", R_SubkeyCountTooLarge, TRUE },
    { "Unicode name of an odd length", R_OddNameLength, TRUE },
    { "link flag without a link value", R_LinkFlagNoValue, TRUE },
    { "root flagged as a link", R_RootIsLink, TRUE },
    { "subkey name beginning with a NUL", R_NulInName, TRUE },
    { "subkey name with a NUL inside", R_NulInsideName, TRUE },
    { "cell size past its bin", R_CellPastBin, FALSE },
};

/* ---- loading and using a hive ---- */

typedef struct _LOAD_CONTEXT
{
    WCHAR File[MAX_PATH];
    LONG Result;
} LOAD_CONTEXT, *PLOAD_CONTEXT;

static DWORD WINAPI LoadThread(PVOID Parameter)
{
    PLOAD_CONTEXT Context = Parameter;

    Context->Result = RegLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT, Context->File);
    return 0;
}

static ULONG g_Keys;
static PCSTR g_Recipe = "";

/* Everything a key has, as a program would read it */
static void Walk(HKEY Key, ULONG Depth)
{
    WCHAR Name[300], Class[300];
    BYTE Data[512], Sd[1024];
    DWORD i, NameLength, DataLength, Type, ClassLength, SubKeys, MaxSubKey, Values, MaxValueName, MaxValueData, SdLength;
    LONG Error;
    FILETIME Time;
    HKEY Sub;

    if (Depth > 32 || ++g_Keys > 2000)
        return;
    ClassLength = _countof(Class);
    MaxSubKey = MaxValueName = MaxValueData = 0;
    Error = RegQueryInfoKeyW(Key, Class, &ClassLength, NULL, &SubKeys, &MaxSubKey, NULL, &Values, &MaxValueName,
                             &MaxValueData, NULL, &Time);
    /* What programs size their buffers by is within what a key can hold (and what the hive can) */
    ok(Error != ERROR_SUCCESS || (MaxSubKey <= 0x7FFF && MaxValueName <= 0x7FFF && MaxValueData < 0x1000000),
       "[%s] RegQueryInfoKeyW: longest subkey name %lu, value name %lu, data %lu\n", g_Recipe, MaxSubKey,
       MaxValueName, MaxValueData);
    SdLength = sizeof(Sd);
    RegGetKeySecurity(Key, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      Sd, &SdLength);
    for (i = 0; i < 64; i++)
    {
        NameLength = _countof(Name);
        DataLength = sizeof(Data);
        if (RegEnumValueW(Key, i, Name, &NameLength, NULL, &Type, Data, &DataLength) == ERROR_NO_MORE_ITEMS)
            break;
        DataLength = sizeof(Data);
        RegQueryValueExW(Key, Name, NULL, &Type, Data, &DataLength);
    }
    for (i = 0; i < 700; i++)
    {
        NameLength = _countof(Name);
        ClassLength = _countof(Class);
        if (RegEnumKeyExW(Key, i, Name, &NameLength, NULL, Class, &ClassLength, &Time) == ERROR_NO_MORE_ITEMS)
            break;
        /* What enumeration gives, a lookup by name finds (a link without its value aside, and a name with a NUL
           inside, which as a C string is another name) */
        Error = RegOpenKeyExW(Key, Name, 0, KEY_READ, &Sub);
        ok(Error == ERROR_SUCCESS || (Depth == 0 && !wcscmp(Name, L"B")) || wcslen(Name) != NameLength,
           "[%s] subkey '%ls' enumerated but not opened: %ld\n", g_Recipe, Name, Error);
        if (Error == ERROR_SUCCESS)
        {
            Walk(Sub, Depth + 1);
            RegCloseKey(Sub);
        }
    }
}

/* Load, use, change, unload; then load the file the unload wrote and unload it again */
static void Run(const RECIPE *Recipe)
{
    PLOAD_CONTEXT Context;
    HANDLE Thread, Handle;
    DWORD Wait, Written, Pass, Data = 1;
    PBYTE Buf;
    LONG Error;
    HKEY Root, Key;

    for (Pass = 0; Pass < 2; Pass++)
    {
        if (Pass == 0)
        {
            Buf = HeapAlloc(GetProcessHeap(), 0, g_BaseSize);
            if (!Buf)
                return;
            memcpy(Buf, g_Base, g_BaseSize);
            Recipe->Apply(Buf, g_BaseSize);
            Handle = CreateFileW(g_File, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            ok(Handle != INVALID_HANDLE_VALUE, "[%s] CreateFileW: %lu\n", Recipe->Name, GetLastError());
            if (Handle == INVALID_HANDLE_VALUE)
            {
                HeapFree(GetProcessHeap(), 0, Buf);
                return;
            }
            WriteFile(Handle, Buf, g_BaseSize, &Written, NULL);
            CloseHandle(Handle);
            HeapFree(GetProcessHeap(), 0, Buf);
        }

        /* In another thread: a load that does not return is a failure (the thread is left behind) */
        Context = HeapAlloc(GetProcessHeap(), 0, sizeof(*Context));
        if (!Context)
            return;
        StringCchCopyW(Context->File, _countof(Context->File), g_File);
        Context->Result = -1;
        Thread = CreateThread(NULL, 0, LoadThread, Context, 0, NULL);
        if (!Thread)
            return;
        Wait = WaitForSingleObject(Thread, LOAD_TIMEOUT);
        CloseHandle(Thread);
        ok(Wait == WAIT_OBJECT_0, "[%s] RegLoadKeyW did not return within %u ms\n", Recipe->Name, LOAD_TIMEOUT);
        if (Wait != WAIT_OBJECT_0)
            return;
        Error = Context->Result;
        HeapFree(GetProcessHeap(), 0, Context);

        if (Pass == 0 && Recipe->MustLoad)
            ok(Error == ERROR_SUCCESS, "[%s] RegLoadKeyW: %ld, expected the repaired hive to load\n", Recipe->Name, Error);
        else if (Pass == 0)
            ok(Error == ERROR_SUCCESS || Error == ERROR_BADDB || Error == ERROR_REGISTRY_CORRUPT,
               "[%s] RegLoadKeyW: %ld\n", Recipe->Name, Error);
        else
            ok(Error == ERROR_SUCCESS, "[%s] the file the first load wrote back does not load: %ld\n", Recipe->Name, Error);
        if (Error != ERROR_SUCCESS)
            return;

        Error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, MOUNT, 0, KEY_ALL_ACCESS, &Root);
        ok(Error == ERROR_SUCCESS, "[%s] RegOpenKeyExW: %ld\n", Recipe->Name, Error);
        if (Error == ERROR_SUCCESS)
        {
            g_Keys = 0;
            Walk(Root, 0);
            if (Pass == 0)
            {
                /* Deletes and creates go through the cells the check let in */
                RegDeleteTreeW(Root, L"A");
                RegDeleteKeyW(Root, L"A");
                Error = RegDeleteTreeW(Root, L"C");
                if (Recipe->Apply == R_NulInName)
                    ok(Error == ERROR_SUCCESS, "[%s] RegDeleteTreeW(C): %ld\n", Recipe->Name, Error);
                RegDeleteKeyW(Root, L"C");
                if (Recipe->Apply == R_NulInName)
                {
                    Error = RegOpenKeyExW(Root, L"C", 0, KEY_READ, &Key);
                    ok(Error == ERROR_FILE_NOT_FOUND, "[%s] C after its deletion: %ld\n", Recipe->Name, Error);
                    if (Error == ERROR_SUCCESS)
                        RegCloseKey(Key);
                }
                if (Recipe->Apply == R_NulInsideName)
                {
                    Error = RegDeleteTreeW(Root, L"Many");
                    ok(Error == ERROR_SUCCESS, "[%s] RegDeleteTreeW(Many): %ld\n", Recipe->Name, Error);
                    RegDeleteKeyW(Root, L"Many");
                    Error = RegOpenKeyExW(Root, L"Many", 0, KEY_READ, &Key);
                    ok(Error == ERROR_FILE_NOT_FOUND, "[%s] Many after its deletion: %ld\n", Recipe->Name, Error);
                    if (Error == ERROR_SUCCESS)
                        RegCloseKey(Key);
                }
                RegDeleteKeyW(Root, L"E");
                RegDeleteTreeW(Root, L"Many\\m0001");
                RegDeleteKeyW(Root, L"Many\\m0001");
                if (RegCreateKeyExW(Root, L"B\\New", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &Key, NULL) == ERROR_SUCCESS)
                {
                    RegSetValueExW(Key, L"v", 0, REG_DWORD, (PBYTE)&Data, sizeof(Data));
                    RegCloseKey(Key);
                }
                RegSetValueExW(Root, L"d", 0, REG_DWORD, (PBYTE)&Data, sizeof(Data));
                g_Keys = 0;
                Walk(Root, 0);
                RegFlushKey(Root);
            }
            RegCloseKey(Root);
        }

        /* A hive that loads must unload (review F13) */
        Error = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT);
        ok(Error == ERROR_SUCCESS, "[%s] pass %lu: RegUnLoadKeyW: %ld\n", Recipe->Name, Pass, Error);
        if (Error != ERROR_SUCCESS)
            return;
    }
}

START_TEST(RegLoadCraftedHive)
{
    WCHAR Dir[MAX_PATH];
    ULONG i;

    pRegDeleteTreeW = (PVOID)GetProcAddress(GetModuleHandleW(L"advapi32.dll"), "RegDeleteTreeW");
    if (!pRegDeleteTreeW)
    {
        skip("RegDeleteTreeW is not available\n");
        return;
    }
    if (!EnablePrivilege(L"SeBackupPrivilege") || !EnablePrivilege(L"SeRestorePrivilege"))
    {
        skip("The backup and restore privileges are needed (run as an administrator)\n");
        return;
    }
    GetTempPathW(_countof(Dir), Dir);
    StringCchPrintfW(g_File, _countof(g_File), L"%sRegLoadCraftedHive.hiv", Dir);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, MOUNT);
    if (!MakeBase())
    {
        skip("Could not make the base hive\n");
        return;
    }
    ok(FindKey(g_Base, g_BaseSize, "A") != (DWORD)-1 && FindKey(g_Base, g_BaseSize, "Many") != (DWORD)-1,
       "The base hive does not have its keys\n");

    for (i = 0; i < _countof(g_Recipes); i++)
    {
        trace("recipe %lu: %s\n", i, g_Recipes[i].Name);
        g_Recipe = g_Recipes[i].Name;
        Run(&g_Recipes[i]);
    }

    DeleteFileW(g_File);
    HeapFree(GetProcessHeap(), 0, g_Base);
}
