/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Animated cursors with chunk sizes and counts that do not fit their data
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define ANI_FLAG_ICON       0x1
#define ANI_FLAG_SEQUENCE   0x2

#define FOURCC(a, b, c, d) ((DWORD)(BYTE)(a) | ((DWORD)(BYTE)(b) << 8) | ((DWORD)(BYTE)(c) << 16) | ((DWORD)(BYTE)(d) << 24))

/* Layout of the valid file made below */
#define OFF_RIFF_SIZE   4
#define OFF_ANIH        12
#define OFF_ANIH_SIZE   16
#define OFF_NUM_FRAMES  (OFF_ANIH + 8 + 4)
#define OFF_NUM_STEPS   (OFF_ANIH + 8 + 8)
#define OFF_RATE        56
#define OFF_RATE_SIZE   60
#define OFF_SEQ         72
#define OFF_SEQ_SIZE    76
#define OFF_LIST        88
#define OFF_LIST_SIZE   92
#define OFF_FRAME1      100
#define OFF_FRAME1_SIZE 104
#define ICON_BYTES      (22 + 40 + 8 + 64 + 64)
#define ANI_BYTES       (OFF_FRAME1 + 2 * (8 + ICON_BYTES))

static BYTE g_Valid[ANI_BYTES];
static BYTE *g_Guarded;     /* the end of the data is the end of the last committed page */
static ULONG g_Seed = 12345;

static ULONG Rand(void)
{
    g_Seed = g_Seed * 1103515245UL + 12345UL;
    return (g_Seed >> 8) & 0xFFFFFF;
}

static void Put32(BYTE *p, DWORD v)
{
    memcpy(p, &v, sizeof(v));
}

static BYTE *PutChunk(BYTE *p, DWORD id, DWORD size)
{
    Put32(p, id);
    Put32(p + 4, size);
    return p + 8;
}

static BYTE *PutIconFile(BYTE *p)
{
    BYTE *start = p;
    UINT i;

    memset(p, 0, ICON_BYTES);
    /* ICONDIR: reserved, type 1 (icon), one entry */
    p[2] = 1;
    p[4] = 1;
    /* ICONDIRENTRY: 16 x 16, 2 colours, 1 plane, 1 bit, size, offset */
    p[6] = 16;
    p[7] = 16;
    p[8] = 2;
    p[10] = 1;
    p[12] = 1;
    Put32(p + 14, 40 + 8 + 64 + 64);
    Put32(p + 18, 22);
    p += 22;
    /* BITMAPINFOHEADER of an icon image: the height holds the XOR and the AND bits */
    Put32(p, 40);
    Put32(p + 4, 16);
    Put32(p + 8, 32);
    Put32(p + 12, 1 | (1 << 16));
    Put32(p + 32, 2);
    /* colours: black, white */
    Put32(p + 40, 0x00000000);
    Put32(p + 44, 0x00FFFFFF);
    for (i = 0; i < 64; i++)
        p[48 + i] = (i & 4) ? 0xAA : 0x55;
    return start + ICON_BYTES;
}

static void MakeValid(void)
{
    BYTE *p = g_Valid;
    UINT i;

    memset(g_Valid, 0, sizeof(g_Valid));
    p = PutChunk(p, FOURCC('R', 'I', 'F', 'F'), ANI_BYTES - 8);
    Put32(p, FOURCC('A', 'C', 'O', 'N'));
    p += 4;
    p = PutChunk(p, FOURCC('a', 'n', 'i', 'h'), 36);
    Put32(p, 36);               /* header size */
    Put32(p + 4, 2);            /* frames */
    Put32(p + 8, 2);            /* steps */
    Put32(p + 28, 5);           /* display rate */
    Put32(p + 32, ANI_FLAG_ICON | ANI_FLAG_SEQUENCE);
    p += 36;
    p = PutChunk(p, FOURCC('r', 'a', 't', 'e'), 8);
    Put32(p, 5);
    Put32(p + 4, 7);
    p += 8;
    p = PutChunk(p, FOURCC('s', 'e', 'q', ' '), 8);
    Put32(p, 1);
    Put32(p + 4, 0);
    p += 8;
    p = PutChunk(p, FOURCC('L', 'I', 'S', 'T'), 4 + 2 * (8 + ICON_BYTES));
    Put32(p, FOURCC('f', 'r', 'a', 'm'));
    p += 4;
    for (i = 0; i < 2; i++)
    {
        p = PutChunk(p, FOURCC('i', 'c', 'o', 'n'), ICON_BYTES);
        p = PutIconFile(p);
    }
    ok(p == g_Valid + ANI_BYTES, "the file is %d bytes, expected %d\n", (int)(p - g_Valid), ANI_BYTES);
}

/* Load the bytes through CreateIconFromResourceEx from a buffer that ends at an inaccessible page.
   Returns 1 when a cursor was made, 0 when it was refused, -1 when the call faulted. */
static int LoadFromMemory(const BYTE *data, DWORD size)
{
    HCURSOR hcur = NULL;
    BYTE *buf = g_Guarded + 4096 - size;
    int ret;

    memcpy(buf, data, size);
    _SEH2_TRY
    {
        hcur = CreateIconFromResourceEx(buf, size, FALSE, 0x00030000, 0, 0, 0);
        ret = hcur != NULL;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ret = -1;
    }
    _SEH2_END;

    if (hcur)
        DestroyCursor(hcur);
    return ret;
}

static int LoadFromFile(const BYTE *data, DWORD size, const WCHAR *path, BOOL useLoadImage)
{
    HANDLE h;
    DWORD written;
    HCURSOR hcur = NULL;
    int ret;

    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    WriteFile(h, data, size, &written, NULL);
    CloseHandle(h);

    _SEH2_TRY
    {
        if (useLoadImage)
            hcur = LoadImageW(NULL, path, IMAGE_CURSOR, 0, 0, LR_LOADFROMFILE);
        else
            hcur = LoadCursorFromFileW(path);
        ret = hcur != NULL;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        ret = -1;
    }
    _SEH2_END;

    if (hcur)
        DestroyCursor(hcur);
    DeleteFileW(path);
    return ret;
}

static void CheckField(const char *what, UINT offset, DWORD value, BOOL expectLoaded)
{
    BYTE data[ANI_BYTES];
    int ret;

    memcpy(data, g_Valid, sizeof(data));
    Put32(data + offset, value);
    ret = LoadFromMemory(data, sizeof(data));
    ok(ret != -1, "%s %#lx: faulted\n", what, value);
    ok(ret == expectLoaded, "%s %#lx: got %d, expected %d\n", what, value, ret, expectLoaded);
}

START_TEST(AniMalformed)
{
    BYTE data[ANI_BYTES];
    WCHAR path[MAX_PATH];
    static const DWORD values[] = { 0, 1, 3, 4, 0x23, 0x24, 0x25, 0x7FFFFFFF, 0x80000000, 0xFFFFFFF0,
                                    0xFFFFFFF8, 0xFFFFFFFE, 0xFFFFFFFF };
    UINT cases = 0, faults = 0, loaded = 0, fileCases = 0, fileFaults = 0;
    UINT off, i, len;
    int ret;
    BYTE *base;
    DWORD oldProtect;

    MakeValid();

    /* A buffer whose last byte is the last byte before an inaccessible page */
    base = VirtualAlloc(NULL, 2 * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(base != NULL, "VirtualAlloc failed, error %lu\n", GetLastError());
    if (!base)
        return;
    ok(VirtualProtect(base + 4096, 4096, PAGE_NOACCESS, &oldProtect), "VirtualProtect failed\n");
    g_Guarded = base;

    GetTempPathW(MAX_PATH, path);
    wcscat(path, L"animalformed.ani");

    /* The file as made is a cursor */
    ret = LoadFromMemory(g_Valid, sizeof(g_Valid));
    ok(ret == 1, "valid file: got %d\n", ret);
    ret = LoadFromFile(g_Valid, sizeof(g_Valid), path, TRUE);
    ok(ret == 1, "valid file, LoadImage: got %d\n", ret);
    ret = LoadFromFile(g_Valid, sizeof(g_Valid), path, FALSE);
    ok(ret == 1, "valid file, LoadCursorFromFile: got %d\n", ret);

    /* Sizes and counts that the data cannot hold are refused */
    CheckField("anih size", OFF_ANIH_SIZE, 0, FALSE);
    CheckField("anih size", OFF_ANIH_SIZE, 8, FALSE);
    CheckField("anih size", OFF_ANIH_SIZE, 35, FALSE);
    CheckField("rate size", OFF_RATE_SIZE, 0, FALSE);
    CheckField("rate size", OFF_RATE_SIZE, 4, FALSE);
    CheckField("seq size", OFF_SEQ_SIZE, 0, FALSE);
    CheckField("seq size", OFF_SEQ_SIZE, 4, FALSE);
    CheckField("frames", OFF_NUM_FRAMES, 0, FALSE);
    CheckField("frames", OFF_NUM_FRAMES, 0xFFFFFFFF, FALSE);
    CheckField("frames", OFF_NUM_FRAMES, 0x20000000, FALSE);
    CheckField("steps", OFF_NUM_STEPS, 0, FALSE);
    CheckField("steps", OFF_NUM_STEPS, 0xFFFFFFFF, FALSE);
    CheckField("steps", OFF_NUM_STEPS, 0x40000000, FALSE);
    /* A parent that claims more than the file holds is no reason to read behind the file */
    CheckField("riff size", OFF_RIFF_SIZE, 0xFFFFFFFF, TRUE);
    CheckField("list size", OFF_LIST_SIZE, 0xFFFFFFFF, TRUE);

    /* Truncated at every length */
    for (len = 0; len < sizeof(g_Valid); len++)
    {
        ret = LoadFromMemory(g_Valid, len);
        cases++;
        if (ret < 0)
            faults++;
        else if (ret > 0)
            loaded++;
        if (ret < 0 && faults < 5)
            ok(0, "truncated to %u bytes: faulted\n", len);
    }

    /* Every size, count and offset field of the file set to a bad value, at every byte position */
    for (off = 0; off + 4 <= sizeof(g_Valid); off++)
    {
        for (i = 0; i < ARRAYSIZE(values) + 2; i++)
        {
            DWORD v = i < ARRAYSIZE(values) ? values[i] : (i == ARRAYSIZE(values) ? sizeof(g_Valid) : sizeof(g_Valid) - off);

            memcpy(data, g_Valid, sizeof(data));
            Put32(data + off, v);
            ret = LoadFromMemory(data, sizeof(data));
            cases++;
            if (ret < 0)
            {
                faults++;
                if (faults < 5)
                    ok(0, "offset %u set to %#lx: faulted\n", off, v);
            }
            else if (ret > 0)
                loaded++;
            /* a quarter of the first group goes through the file loaders as well */
            if ((cases % 16) == 0)
            {
                ret = LoadFromFile(data, sizeof(data), path, (cases % 32) == 0);
                fileCases++;
                if (ret < 0)
                    fileFaults++;
            }
        }
    }

    /* Random bytes changed, and the end cut off */
    for (i = 0; i < 2500; i++)
    {
        UINT n = 1 + Rand() % 4;

        memcpy(data, g_Valid, sizeof(data));
        while (n--)
            data[Rand() % sizeof(data)] = (BYTE)Rand();
        len = (Rand() % 4) ? sizeof(data) : 1 + Rand() % sizeof(data);
        ret = LoadFromMemory(data, len);
        cases++;
        if (ret < 0)
            faults++;
        else if (ret > 0)
            loaded++;
        if ((i % 8) == 0)
        {
            ret = LoadFromFile(data, len, path, (i % 16) == 0);
            fileCases++;
            if (ret < 0)
                fileFaults++;
        }
    }

    trace("%u mutated files: %u faulted, %u loaded; %u through files: %u faulted\n",
          cases, faults, loaded, fileCases, fileFaults);
    ok(cases >= 5000, "only %u cases\n", cases);
    ok(faults == 0, "%u of %u mutated files made the parser fault\n", faults, cases);
    ok(fileFaults == 0, "%u of %u mutated files made the file loaders fault\n", fileFaults, fileCases);

    VirtualFree(base, 0, MEM_RELEASE);
}
