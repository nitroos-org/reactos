/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     PrivateExtractIcons of an animated cursor file: header found by chunk structure,
 *              sizes and frame count as DWORDs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define FOURCC(a, b, c, d) ((DWORD)(BYTE)(a) | ((DWORD)(BYTE)(b) << 8) | ((DWORD)(BYTE)(c) << 16) | ((DWORD)(BYTE)(d) << 24))
#define ICON_BYTES (22 + 40 + 8 + 64 + 64)

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
    UINT i;

    memset(p, 0, ICON_BYTES);
    p[2] = 1;
    p[4] = 1;
    p[6] = 16;
    p[7] = 16;
    p[8] = 2;
    p[10] = 1;
    p[12] = 1;
    Put32(p + 14, 40 + 8 + 64 + 64);
    Put32(p + 18, 22);
    p += 22;
    Put32(p, 40);
    Put32(p + 4, 16);
    Put32(p + 8, 32);
    Put32(p + 12, 1 | (1 << 16));
    Put32(p + 32, 2);
    Put32(p + 40, 0x00000000);
    Put32(p + 44, 0x00FFFFFF);
    for (i = 0; i < 64; i++)
        p[48 + i] = (i & 4) ? 0xAA : 0x55;
    return p + ICON_BYTES - 22;
}

/* A two frame cursor. decoy: a chunk before the header that holds the bytes "anih" and a frame count 7;
   junk: that many bytes of an unrelated chunk between the header and the frames */
static BYTE *MakeAni(DWORD decoy, DWORD junk, DWORD *pSize)
{
    DWORD total = 12 + (decoy ? 8 + 16 : 0) + 8 + 36 + 8 + 8 + 8 + 8 + (junk ? 8 + ((junk + 1) & ~1) : 0) +
                  8 + 4 + 2 * (8 + ICON_BYTES);
    BYTE *buf = calloc(1, total), *p = buf;
    UINT i;

    p = PutChunk(p, FOURCC('R', 'I', 'F', 'F'), total - 8);
    Put32(p, FOURCC('A', 'C', 'O', 'N'));
    p += 4;
    if (decoy)
    {
        p = PutChunk(p, FOURCC('I', 'A', 'R', 'T'), 16);
        Put32(p, FOURCC('a', 'n', 'i', 'h'));
        Put32(p + 12, 7);
        p += 16;
    }
    p = PutChunk(p, FOURCC('a', 'n', 'i', 'h'), 36);
    Put32(p, 36);
    Put32(p + 4, 2);
    Put32(p + 8, 2);
    Put32(p + 28, 5);
    Put32(p + 32, 0x1 | 0x2);
    p += 36;
    p = PutChunk(p, FOURCC('r', 'a', 't', 'e'), 8);
    Put32(p, 5);
    Put32(p + 4, 7);
    p += 8;
    p = PutChunk(p, FOURCC('s', 'e', 'q', ' '), 8);
    Put32(p, 1);
    Put32(p + 4, 0);
    p += 8;
    if (junk)
    {
        p = PutChunk(p, FOURCC('J', 'U', 'N', 'K'), junk);
        p += (junk + 1) & ~1;
    }
    p = PutChunk(p, FOURCC('L', 'I', 'S', 'T'), 4 + 2 * (8 + ICON_BYTES));
    Put32(p, FOURCC('f', 'r', 'a', 'm'));
    p += 4;
    for (i = 0; i < 2; i++)
    {
        p = PutChunk(p, FOURCC('i', 'c', 'o', 'n'), ICON_BYTES);
        p = PutIconFile(p);
    }
    *pSize = total;
    return buf;
}

static BOOL WriteFileBytes(const WCHAR *path, const BYTE *data, DWORD size)
{
    DWORD n;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    WriteFile(h, data, size, &n, NULL);
    CloseHandle(h);
    return n == size;
}

START_TEST(ExtractIconAni)
{
    WCHAR path[MAX_PATH];
    DWORD size;
    BYTE *ani;
    HICON hico;
    UINT ret;

    GetTempPathW(MAX_PATH, path);
    wcscat(path, L"exticonani.ani");

    /* The header is found by the chunk structure: a string "anih" inside an earlier chunk is not it */
    ani = MakeAni(0, 0, &size);
    ok(WriteFileBytes(path, ani, size), "cannot write the file\n");
    free(ani);
    ret = PrivateExtractIconsW(path, 0, 16, 16, NULL, NULL, 1, 0);
    ok(ret == 2, "plain: %u icons, expected 2\n", ret);

    ani = MakeAni(1, 0, &size);
    ok(WriteFileBytes(path, ani, size), "cannot write the file\n");
    free(ani);
    ret = PrivateExtractIconsW(path, 0, 16, 16, NULL, NULL, 1, 0);
    ok(ret == 2, "decoy chunk: %u icons, expected 2\n", ret);

    /* A RIFF size above 64 KB: all of it is the data (the frames lie behind the first 64 KB) */
    ani = MakeAni(0, 70000, &size);
    ok(size > 65536, "file too small\n");
    ok(WriteFileBytes(path, ani, size), "cannot write the file\n");
    free(ani);
    hico = NULL;
    ret = PrivateExtractIconsW(path, 0, 16, 16, &hico, NULL, 1, 0);
    ok(ret == 2 || ret == 1, "big: %u icons\n", ret);
    ok(hico != NULL, "big: no cursor made from a file of %lu bytes\n", size);
    if (hico)
        DestroyIcon(hico);

    DeleteFileW(path);
}
