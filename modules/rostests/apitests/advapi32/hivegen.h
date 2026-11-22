/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A small writer of registry hive files, for tests that need a
 *              hive of a format ReactOS does not write itself (1.5 with big
 *              data values). Portable C: also built on a build host to check
 *              its output against cmlib.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The layout follows the public "Windows registry file format specification"
 * by Maxim Suhanov (github.com/msuhanov/regf): base block, one hive bin, cells
 * with a signed size; 'nk' key nodes, an 'lh' leaf (hash: name in upper case,
 * hash = hash * 37 + character), 'vk' values, an 'sk' cell, and for data
 * longer than 16344 bytes in a 1.4+ hive the 'db' record with its list of
 * segments (16344 bytes each, the last one the rest). The last cell is sized
 * to the rest here, as builds of this kernel before the writer was changed
 * wrote it (a Windows reader drops such a chain; the kernel's own writer now
 * makes full cells): kept so that the reader stays tolerant of it. No byte of
 * it comes from a hive file made by anyone else.
 */

#ifndef HIVEGEN_H
#define HIVEGEN_H

#include <string.h>
#include <stdlib.h>

#define HG_BLOCK        4096u
#define HG_SEGMENT      16344u
#define HG_NIL          0xFFFFFFFFu
#define HG_SMALL        0x80000000u

/* How a value's data is stored */
#define HG_AUTO         0   /* small, one cell, or big data as the format wants */
#define HG_ONE_CELL     1   /* one cell whatever the length (what an older ReactOS wrote into a 1.5 hive) */
#define HG_NO_CELL      2   /* DataLength 0, Data = NIL */

typedef struct _HG_VALUE
{
    const char *Name;
    unsigned Type;          /* REG_SZ data is text, anything else the byte pattern of HgByte */
    unsigned Length;
    unsigned Seed;
    int Form;
} HG_VALUE;

typedef struct _HG_KEY
{
    const char *Name;       /* subkeys of the root, in the order of their upper-case names */
    const HG_VALUE *Values;
    unsigned Count;
} HG_KEY;

/* The data of a value: bytes, or for REG_SZ a NUL-terminated text of Length bytes */
static unsigned char HgByte(unsigned Type, unsigned i, unsigned Length, unsigned Seed)
{
    if (Type == 1 /* REG_SZ */)
    {
        unsigned Char = i / 2;
        unsigned short W = (Char + 1 >= Length / 2) ? 0 : (unsigned short)('a' + (Char + Seed) % 26);
        return (unsigned char)((i & 1) ? (W >> 8) : (W & 0xFF));
    }
    return (unsigned char)(i * 31u + Seed + (i >> 9) * 7u);
}

typedef struct _HG
{
    unsigned char *Bins;    /* the hive bins data; cell indexes are offsets in it */
    unsigned Size, Used;
} HG;

static void HgPut16(unsigned char *P, unsigned V) { P[0] = (unsigned char)V; P[1] = (unsigned char)(V >> 8); }
static void HgPut32(unsigned char *P, unsigned V) { HgPut16(P, V & 0xFFFF); HgPut16(P + 2, V >> 16); }

/* A new allocated cell of DataSize bytes; its index (the offset of its size field) */
static unsigned HgCell(HG *G, unsigned DataSize)
{
    unsigned Size = (DataSize + 4 + 7) & ~7u, Cell;

    while (G->Used + Size > G->Size)
    {
        G->Size = G->Size ? G->Size * 2 : 64 * HG_BLOCK;
        G->Bins = realloc(G->Bins, G->Size);
    }
    Cell = G->Used;
    memset(G->Bins + Cell, 0, Size);
    HgPut32(G->Bins + Cell, 0u - Size);
    G->Used += Size;
    return Cell;
}
#define HG_D(G, Cell) ((G)->Bins + (Cell) + 4)   /* the data of a cell */

static unsigned HgHash(const char *Name)
{
    unsigned Hash = 0;

    for (; *Name; Name++)
        Hash = Hash * 37 + (unsigned)((*Name >= 'a' && *Name <= 'z') ? *Name - 'a' + 'A' : *Name);
    return Hash;
}

/* owner Administrators, group SYSTEM; Administrators and SYSTEM full, Everyone read (self-relative) */
static const unsigned char HgSd[] =
{
    1, 0, 0x04, 0x80, 20, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0,
    1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0,                  /* S-1-5-32-544 */
    1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,                                 /* S-1-5-18 */
    2, 0, 72, 0, 3, 0, 0, 0,                                             /* ACL: 72 bytes, 3 ACEs */
    0, 3, 24, 0, 0x3F, 0, 0x0F, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0,
    0, 3, 20, 0, 0x3F, 0, 0x0F, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
    0, 3, 20, 0, 0x19, 0, 0x02, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,  /* S-1-1-0: KEY_READ */
};

static unsigned HgKeyNode(HG *G, const char *Name, unsigned Parent, unsigned Flags, unsigned Sk)
{
    unsigned Len = (unsigned)strlen(Name), Cell = HgCell(G, 0x4C + Len);
    unsigned char *D = HG_D(G, Cell);

    HgPut16(D, 0x6B6E);                 /* nk */
    HgPut16(D + 0x02, Flags | 0x20);    /* KEY_COMP_NAME */
    HgPut32(D + 0x10, Parent);
    HgPut32(D + 0x1C, HG_NIL);
    HgPut32(D + 0x20, HG_NIL);
    HgPut32(D + 0x28, HG_NIL);
    HgPut32(D + 0x2C, Sk);
    HgPut32(D + 0x30, HG_NIL);
    HgPut16(D + 0x48, Len);
    memcpy(D + 0x4C, Name, Len);
    return Cell;
}

/* Data of Length bytes in one cell, or as big data (segments, list, 'db') */
static unsigned HgData(HG *G, const HG_VALUE *V, int Big)
{
    unsigned Count, i, n, Cell, List, Db, Chunk;

    if (!Big)
    {
        Cell = HgCell(G, V->Length);
        for (n = 0; n < V->Length; n++)
            HG_D(G, Cell)[n] = HgByte(V->Type, n, V->Length, V->Seed);
        return Cell;
    }
    Count = (V->Length + HG_SEGMENT - 1) / HG_SEGMENT;
    Db = HgCell(G, 8);
    List = HgCell(G, Count * 4);
    for (i = 0; i < Count; i++)
    {
        Chunk = V->Length - i * HG_SEGMENT;
        if (Chunk > HG_SEGMENT)
            Chunk = HG_SEGMENT;
        Cell = HgCell(G, Chunk);
        for (n = 0; n < Chunk; n++)
            HG_D(G, Cell)[n] = HgByte(V->Type, i * HG_SEGMENT + n, V->Length, V->Seed);
        HgPut32(HG_D(G, List) + 4 * i, Cell);
    }
    HgPut16(HG_D(G, Db), 0x6264);       /* db */
    HgPut16(HG_D(G, Db) + 2, Count);
    HgPut32(HG_D(G, Db) + 4, List);
    return Db;
}

static unsigned HgValue(HG *G, const HG_VALUE *V, unsigned Minor)
{
    unsigned Len = (unsigned)strlen(V->Name), Cell = HgCell(G, 0x14 + Len), Data = HG_NIL, Length = V->Length;
    unsigned char *D;
    unsigned n;

    if (V->Form == HG_NO_CELL)
    {
        Length = 0;
    }
    else if (V->Length <= 4)
    {
        Data = 0;
        for (n = 0; n < V->Length; n++)
            Data |= (unsigned)HgByte(V->Type, n, V->Length, V->Seed) << (8 * n);
        Length = V->Length | HG_SMALL;
    }
    else
    {
        Data = HgData(G, V, V->Form == HG_AUTO && Minor >= 4 && V->Length > HG_SEGMENT);
    }
    D = HG_D(G, Cell);
    HgPut16(D, 0x6B76);                 /* vk */
    HgPut16(D + 0x02, Len);
    HgPut32(D + 0x04, Length);
    HgPut32(D + 0x08, Data);
    HgPut32(D + 0x0C, V->Type);
    HgPut16(D + 0x10, 1);               /* VALUE_COMP_NAME */
    memcpy(D + 0x14, V->Name, Len);
    return Cell;
}

static void HgValues(HG *G, unsigned Key, const HG_VALUE *Values, unsigned Count, unsigned Minor)
{
    unsigned List, i, MaxName = 0, MaxData = 0;

    if (!Count)
        return;
    List = HgCell(G, Count * 4);
    for (i = 0; i < Count; i++)
    {
        /* the value first: its cells may move the bins (realloc) */
        unsigned Value = HgValue(G, &Values[i], Minor);

        HgPut32(HG_D(G, List) + 4 * i, Value);
        if (strlen(Values[i].Name) * 2 > MaxName)
            MaxName = (unsigned)strlen(Values[i].Name) * 2;
        if (Values[i].Form != HG_NO_CELL && Values[i].Length > MaxData)
            MaxData = Values[i].Length;
    }
    HgPut32(HG_D(G, Key) + 0x24, Count);
    HgPut32(HG_D(G, Key) + 0x28, List);
    HgPut32(HG_D(G, Key) + 0x3C, MaxName);
    HgPut32(HG_D(G, Key) + 0x40, MaxData);
}

/*
 * A hive file of format 1.Minor: a root with Keys[] as subkeys (each with its
 * values) and RootValues. Returns the file (malloc) and its size.
 */
static unsigned char *HgBuild(unsigned Minor, const HG_KEY *Keys, unsigned KeyCount,
                              const HG_VALUE *RootValues, unsigned RootCount, unsigned *FileSize)
{
    HG G = { NULL, 0, 0 };
    unsigned Sk, Root, Leaf, i, BinSize, Sum, MaxName = 0;
    unsigned char *File, *Bin;
    static const char RootName[] = "ReactOSBigDataRoot";

    G.Used = 32;                        /* the bin header */
    Sk = HgCell(&G, 20 + sizeof(HgSd));
    Root = HgKeyNode(&G, RootName, HG_NIL, 0x04 | 0x08 /* HIVE_ENTRY | NO_DELETE */, Sk);
    HgPut16(HG_D(&G, Sk), 0x6B73);      /* sk */
    HgPut32(HG_D(&G, Sk) + 0x04, Sk);
    HgPut32(HG_D(&G, Sk) + 0x08, Sk);
    HgPut32(HG_D(&G, Sk) + 0x0C, 1 + KeyCount);
    HgPut32(HG_D(&G, Sk) + 0x10, sizeof(HgSd));
    memcpy(HG_D(&G, Sk) + 0x14, HgSd, sizeof(HgSd));

    if (KeyCount)
    {
        Leaf = HgCell(&G, 4 + 8 * KeyCount);
        HgPut16(HG_D(&G, Leaf), 0x686C);    /* lh */
        HgPut16(HG_D(&G, Leaf) + 2, KeyCount);
        for (i = 0; i < KeyCount; i++)
        {
            unsigned Key = HgKeyNode(&G, Keys[i].Name, Root, 0, Sk);
            HgPut32(HG_D(&G, Leaf) + 4 + 8 * i, Key);
            HgPut32(HG_D(&G, Leaf) + 8 + 8 * i, HgHash(Keys[i].Name));
            HgValues(&G, Key, Keys[i].Values, Keys[i].Count, Minor);
            if (strlen(Keys[i].Name) * 2 > MaxName)
                MaxName = (unsigned)strlen(Keys[i].Name) * 2;
        }
        HgPut32(HG_D(&G, Root) + 0x14, KeyCount);
        HgPut32(HG_D(&G, Root) + 0x1C, Leaf);
        HgPut32(HG_D(&G, Root) + 0x34, MaxName);
    }
    HgValues(&G, Root, RootValues, RootCount, Minor);

    /* one bin of whole blocks; what is left of it is one free cell */
    BinSize = (G.Used + HG_BLOCK - 1) & ~(HG_BLOCK - 1);
    if (BinSize > G.Size)
    {
        G.Bins = realloc(G.Bins, BinSize);
        G.Size = BinSize;
    }
    if (BinSize > G.Used)
    {
        memset(G.Bins + G.Used, 0, BinSize - G.Used);
        HgPut32(G.Bins + G.Used, BinSize - G.Used);
    }
    Bin = G.Bins;
    memset(Bin, 0, 32);
    HgPut32(Bin, 0x6E696268);           /* hbin */
    HgPut32(Bin + 4, 0);                /* its offset */
    HgPut32(Bin + 8, BinSize);

    File = calloc(1, HG_BLOCK + BinSize);
    HgPut32(File, 0x66676572);          /* regf */
    HgPut32(File + 0x04, 1);            /* sequence numbers */
    HgPut32(File + 0x08, 1);
    HgPut32(File + 0x14, 1);            /* major */
    HgPut32(File + 0x18, Minor);
    HgPut32(File + 0x1C, 0);            /* primary file */
    HgPut32(File + 0x20, 1);            /* direct memory load */
    HgPut32(File + 0x24, Root);
    HgPut32(File + 0x28, BinSize);
    HgPut32(File + 0x2C, 1);            /* clustering factor */
    for (i = 0, Sum = 0; i < 127; i++)
        Sum ^= (unsigned)File[4 * i] | (unsigned)File[4 * i + 1] << 8 |
               (unsigned)File[4 * i + 2] << 16 | (unsigned)File[4 * i + 3] << 24;
    if (Sum == 0xFFFFFFFFu)
        Sum = 0xFFFFFFFEu;
    else if (Sum == 0)
        Sum = 1;
    HgPut32(File + 0x1FC, Sum);
    memcpy(File + HG_BLOCK, Bin, BinSize);
    free(G.Bins);
    *FileSize = HG_BLOCK + BinSize;
    return File;
}

/*
 * The hive of the RegBigData test: big data values of every boundary length
 * (16344 is one cell, 16345 two segments, 32688 two full ones, 32689 three,
 * 65377 and 81720 five), text as big data, small data, no data without a
 * cell, and one long value in one cell as an older ReactOS wrote it.
 */
static const HG_VALUE HgBigDataValues[] =
{
    { "b40000",  3, 40000, 1, HG_AUTO },
    { "b16344",  3, 16344, 2, HG_AUTO },
    { "b16345",  3, 16345, 3, HG_AUTO },
    { "b32688",  3, 32688, 4, HG_AUTO },
    { "b32689",  3, 32689, 5, HG_AUTO },
    { "b81720",  3, 81720, 6, HG_AUTO },
    { "b65377",  3, 65377, 7, HG_AUTO },
    { "sz",      1, 40002, 8, HG_AUTO },     /* REG_SZ: 20000 characters and the NUL */
    { "dw",      4, 4,     9, HG_AUTO },
    { "empty",   3, 0,     0, HG_NO_CELL },
    { "legacy",  3, 30000, 10, HG_ONE_CELL },
    { "b100",    3, 100,   11, HG_AUTO },
};
static const HG_VALUE HgSubValues[] =
{
    { "big",     3, 50000, 12, HG_AUTO },
    { "small",   3, 3,     13, HG_AUTO },
};
static const HG_VALUE HgRootValues[] =
{
    { "rootbig", 3, 20000, 14, HG_AUTO },
};
static const HG_KEY HgBigDataKeys[] =
{
    { "BigData", HgBigDataValues, sizeof(HgBigDataValues) / sizeof(HgBigDataValues[0]) },
    { "Sub",     HgSubValues,     sizeof(HgSubValues) / sizeof(HgSubValues[0]) },
};

static unsigned char *HgBuildBigData(unsigned Minor, unsigned *FileSize)
{
    return HgBuild(Minor, HgBigDataKeys, sizeof(HgBigDataKeys) / sizeof(HgBigDataKeys[0]),
                   HgRootValues, sizeof(HgRootValues) / sizeof(HgRootValues[0]), FileSize);
}

#endif /* HIVEGEN_H */
