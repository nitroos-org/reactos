/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Direct2D built-in effects: property defaults and ranges, and DrawImage of effect graphs
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected pixels are those a Windows 10 22H2 (19045) machine renders for the same effect graphs on a 16x16
 * B8G8R8A8 premultiplied target (see the d2deffects evidence), with a tolerance of 2 per channel for the filtering.
 */

#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <d3d11.h>
#include <d2d1_1.h>
#include <d2d1effects.h>
#include <d2d1effects_2.h>

#include "wine/test.h"

#define W 16
#define H 16

static ID2D1DeviceContext *ctx;
static ID3D11Device *d3d;
static ID2D1Device *d2d;
static ID2D1Bitmap1 *target;

static const struct expected_case
{
    const char *name;
    unsigned int count;
    struct { int x, y; DWORD value; } points[10];
}
expected[] =
{
    { "flood red a=.5 (infinite)", 5, { {0, 0, 0x80ff0000}, {15, 0, 0x80ff0000}, {0, 15, 0x80ff0000}, {15, 15, 0x80ff0000}, {7, 7, 0x80ff0000} } },
    { "crop(flood green) rect 4,4,12,12", 10, { {4, 4, 0xff00ff00}, {11, 4, 0xff00ff00}, {4, 11, 0xff00ff00}, {11, 11, 0xff00ff00}, {7, 7, 0xff00ff00}, {3, 4, 0x00000000}, {12, 11, 0x00000000}, {11, 3, 0x00000000}, {4, 12, 0x00000000}, {15, 15, 0x00000000} } },
    { "crop(img) rect 2,2,6,6", 10, { {2, 2, 0xffc84040}, {5, 2, 0x80642050}, {2, 5, 0xffc8a040}, {5, 5, 0x80645050}, {3, 3, 0xffc86060}, {1, 2, 0x00000000}, {6, 5, 0x00000000}, {5, 1, 0x00000000}, {2, 6, 0x00000000}, {15, 15, 0x00000000} } },
    { "offset only: img via 2D affine identity", 5, { {0, 0, 0xff000000}, {15, 0, 0xff000000}, {0, 15, 0xff000000}, {15, 15, 0xff000000}, {7, 7, 0xff000000} } },
    { "affine translate 3,2", 10, { {3, 2, 0xffc80000}, {10, 2, 0x80640070}, {3, 9, 0xffc8e000}, {10, 9, 0x80647070}, {6, 5, 0xffc86060}, {2, 2, 0x00000000}, {11, 9, 0x00000000}, {10, 1, 0x00000000}, {3, 10, 0x00000000}, {15, 15, 0x00000000} } },
    { "affine translate .5,0 linear", 8, { {0, 0, 0x7f640000}, {8, 0, 0x40320038}, {0, 7, 0x7f647000}, {8, 7, 0x40323838}, {4, 3, 0xbf964850}, {9, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "affine translate .5,0 nearest", 9, { {1, 0, 0xffc80020}, {7, 0, 0x80640070}, {1, 7, 0xffc8e020}, {7, 7, 0x80647070}, {4, 3, 0x80643040}, {0, 0, 0x00000000}, {8, 7, 0x00000000}, {1, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "affine scale 2 linear soft", 5, { {0, 0, 0x8f700000}, {15, 0, 0x4838003f}, {0, 15, 0x8f707e00}, {15, 15, 0x48383f3f}, {7, 7, 0xdfaf5b58} } },
    { "affine scale 2 linear hard", 5, { {0, 0, 0xffc80000}, {15, 0, 0x80640070}, {0, 15, 0xffc8e000}, {15, 15, 0x80647070}, {7, 7, 0xdfaf5b58} } },
    { "affine scale 2 nearest", 5, { {0, 0, 0xffc80000}, {15, 0, 0x80640070}, {0, 15, 0xffc8e000}, {15, 15, 0x80647070}, {7, 7, 0xffc86060} } },
    { "affine rot90", 8, { {0, 0, 0xffc8e000}, {7, 0, 0xffc80000}, {0, 7, 0x80647070}, {7, 7, 0x80640070}, {3, 3, 0xffc88060}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "scale 2,2", 5, { {0, 0, 0x8f700000}, {15, 0, 0x4838003f}, {0, 15, 0x8f707e00}, {15, 15, 0x48383f3f}, {7, 7, 0xdfaf5b58} } },
    { "scale .5,.5", 8, { {0, 0, 0xffc81010}, {3, 0, 0x80640868}, {0, 3, 0xffc8d010}, {3, 3, 0x80646868}, {1, 1, 0xffc85050}, {4, 3, 0x00000000}, {0, 4, 0x00000000}, {15, 15, 0x00000000} } },
    { "colormatrix swap rb + bias r .1 premult", 8, { {0, 0, 0xff1a00c8}, {7, 0, 0x807d0064}, {0, 7, 0xff1ae0c8}, {7, 7, 0x807d7064}, {3, 3, 0xff7a60c8}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "colormatrix swap rb + bias r .1 straight", 8, { {0, 0, 0xff1a00c8}, {7, 0, 0x808a0064}, {0, 7, 0xff1ae0c8}, {7, 7, 0x808a7064}, {3, 3, 0xff7a60c8}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "colormatrix half all premult", 8, { {0, 0, 0x80320000}, {7, 0, 0x4019001c}, {0, 7, 0x80323800}, {7, 7, 0x40191c1c}, {3, 3, 0x80321818}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "composite src-over img + affine(img2,2,2)", 8, { {0, 0, 0xffc80000}, {9, 0, 0x00000000}, {0, 9, 0x00000000}, {9, 9, 0x8014505a}, {4, 4, 0xff28a0e6}, {10, 9, 0x00000000}, {0, 10, 0x00000000}, {15, 15, 0x00000000} } },
    { "composite mode 1 (dest-over)", 8, { {0, 0, 0xffc80000}, {9, 0, 0x00000000}, {0, 9, 0x00000000}, {9, 9, 0x8014505a}, {4, 4, 0xff7890b3}, {10, 9, 0x00000000}, {0, 10, 0x00000000}, {15, 15, 0x00000000} } },
    { "composite mode 2 (src-in)", 10, { {2, 2, 0xff28a0fa}, {7, 2, 0x400a2832}, {2, 7, 0xff28a0fa}, {7, 7, 0x400a2832}, {4, 4, 0x80145073}, {1, 2, 0x00000000}, {8, 7, 0x00000000}, {7, 1, 0x00000000}, {2, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "composite mode 9 (plus)", 8, { {0, 0, 0xffc80000}, {9, 0, 0x00000000}, {0, 9, 0x00000000}, {9, 9, 0x8014505a}, {4, 4, 0xff8ce0ff}, {10, 9, 0x00000000}, {0, 10, 0x00000000}, {15, 15, 0x00000000} } },
    { "composite mode 8 (xor)", 8, { {0, 0, 0xffc80000}, {9, 0, 0x00000000}, {0, 9, 0x00000000}, {9, 9, 0x8014505a}, {4, 4, 0x7f145073}, {10, 9, 0x00000000}, {0, 10, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend default (multiply)", 8, { {0, 0, 0xff1f0000}, {7, 0, 0xc044288c}, {0, 7, 0xff1f8d00}, {7, 7, 0xc044838c}, {3, 3, 0xff1f3c53}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend screen", 8, { {0, 0, 0xffd1a0fa}, {7, 0, 0xc07050a2}, {0, 7, 0xffd1f3fa}, {7, 7, 0xc0709da2}, {3, 3, 0xffd1c4e9}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend darken", 8, { {0, 0, 0xff280000}, {7, 0, 0xc0462892}, {0, 7, 0xff28a000}, {7, 7, 0xc0468892}, {3, 3, 0xff286060}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend lighten", 8, { {0, 0, 0xffc8a0fa}, {7, 0, 0xc06e509d}, {0, 7, 0xffc8e0fa}, {7, 7, 0xc06e989d}, {3, 3, 0xffc8a0dc}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend color burn", 8, { {0, 0, 0xff000000}, {7, 0, 0xc03c2899}, {0, 7, 0xff00ce00}, {7, 7, 0xc03c9399}, {3, 3, 0xff000247}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend color dodge", 8, { {0, 0, 0xffed0000}, {7, 0, 0xc07728a5}, {0, 7, 0xffedff00}, {7, 7, 0xc077a0a5}, {3, 3, 0xffedffff}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend linear dodge", 8, { {0, 0, 0xfff0a0fa}, {7, 0, 0xc07850a5}, {0, 7, 0xfff0fffa}, {7, 7, 0xc078a0a5}, {3, 3, 0xfff0ffff}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend overlay", 8, { {0, 0, 0xffa20000}, {7, 0, 0xc06428a0}, {0, 7, 0xffa2e800}, {7, 7, 0xc0649aa0}, {3, 3, 0xffa278a6}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend soft light", 8, { {0, 0, 0xffaa0000}, {7, 0, 0xc066289e}, {0, 7, 0xffaae400}, {7, 7, 0xc066999e}, {3, 3, 0xffaa6f8c}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend hard light", 8, { {0, 0, 0xff3f41f5}, {7, 0, 0xc04b38a0}, {0, 7, 0xff3fe8f5}, {7, 7, 0xc04b9aa0}, {3, 3, 0xff3f89d3}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend difference", 8, { {0, 0, 0xffa0a0fa}, {7, 0, 0xc0645070}, {0, 7, 0xffa040fa}, {7, 7, 0xc0647070}, {3, 3, 0xffa0407c}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend exclusion", 8, { {0, 0, 0xffb1a0fa}, {7, 0, 0xc068507b}, {0, 7, 0xffb167fa}, {7, 7, 0xc0687a7b}, {3, 3, 0xffb18896}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend subtract", 8, { {0, 0, 0xffa00000}, {7, 0, 0xc0642870}, {0, 7, 0xffa04000}, {7, 7, 0xc0647070}, {3, 3, 0xffa00000}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blend division", 8, { {0, 0, 0xffff0000}, {7, 0, 0xc07c28a5}, {0, 7, 0xffffff00}, {7, 7, 0xc07ca0a5}, {3, 3, 0xffff996f}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blur sigma 1 dot(3,3)", 10, { {1, 1, 0x01010101}, {5, 1, 0x01010101}, {1, 5, 0x01010101}, {5, 5, 0x01010101}, {3, 3, 0x29292929}, {0, 1, 0x00000000}, {6, 5, 0x00000000}, {5, 0, 0x00000000}, {1, 6, 0x00000000}, {15, 15, 0x00000000} } },
    { "blur sigma 2", 8, { {0, 0, 0x01010101}, {7, 0, 0x00000000}, {0, 7, 0x00000000}, {7, 7, 0x00000000}, {3, 3, 0x08080808}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "blur sigma 0", 6, { {3, 3, 0xffffffff}, {2, 3, 0x00000000}, {4, 3, 0x00000000}, {3, 2, 0x00000000}, {3, 4, 0x00000000}, {15, 15, 0x00000000} } },
    { "blur sigma 1 img soft", 8, { {0, 0, 0x7d620808}, {10, 0, 0x01000000}, {0, 10, 0x01010100}, {10, 10, 0x00000000}, {5, 5, 0x86695352}, {11, 10, 0x00000000}, {0, 11, 0x00000000}, {15, 15, 0x00000000} } },
    { "blur sigma 1 img hard", 8, { {0, 0, 0xffc80e0e}, {7, 0, 0x80640769}, {0, 7, 0xffc8d20e}, {7, 7, 0x80646969}, {3, 3, 0xd9aa524c}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "shadow sigma 1 black", 10, { {1, 1, 0x01000000}, {5, 1, 0x01000000}, {1, 5, 0x01000000}, {5, 5, 0x01000000}, {3, 3, 0x29000000}, {0, 1, 0x00000000}, {6, 5, 0x00000000}, {5, 0, 0x00000000}, {1, 6, 0x00000000}, {15, 15, 0x00000000} } },
    { "shadow sigma 1 red a=.5", 10, { {1, 1, 0x00000000}, {5, 1, 0x00000000}, {1, 5, 0x00000000}, {5, 5, 0x00000000}, {3, 3, 0x14140000}, {0, 1, 0x00000000}, {6, 5, 0x00000000}, {5, 0, 0x00000000}, {1, 6, 0x00000000}, {15, 15, 0x00000000} } },
    { "shadow sigma 0 red a=.5", 6, { {3, 3, 0x80800000}, {2, 3, 0x00000000}, {4, 3, 0x00000000}, {3, 2, 0x00000000}, {3, 4, 0x00000000}, {15, 15, 0x00000000} } },
    { "shadow sigma 0 img", 8, { {0, 0, 0x80800000}, {7, 0, 0x40400000}, {0, 7, 0x80800000}, {7, 7, 0x40400000}, {3, 3, 0x80800000}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "atlas rect 2,2,6,6", 8, { {0, 0, 0xffc84040}, {3, 0, 0x80642050}, {0, 3, 0xffc8a040}, {3, 3, 0x80645050}, {1, 1, 0xffc86060}, {4, 3, 0x00000000}, {0, 4, 0x00000000}, {15, 15, 0x00000000} } },
    { "tile rect 0,0,3,3", 5, { {0, 0, 0xffc80000}, {15, 0, 0xffc80000}, {0, 15, 0xffc80000}, {15, 15, 0xffc80000}, {7, 7, 0xffc82020} } },
    { "tile rect 2,2,5,6", 5, { {0, 0, 0xffc88060}, {15, 0, 0xffc88060}, {0, 15, 0xffc86060}, {15, 15, 0xffc86060}, {7, 7, 0x80643040} } },
    { "3dtransform translate 3,2", 10, { {3, 2, 0xffc80000}, {10, 2, 0x80640070}, {3, 9, 0xffc8e000}, {10, 9, 0x80647070}, {6, 5, 0xffc86060}, {2, 2, 0x00000000}, {11, 9, 0x00000000}, {10, 1, 0x00000000}, {3, 10, 0x00000000}, {15, 15, 0x00000000} } },
    { "3dtransform scale 2", 5, { {0, 0, 0x8f700000}, {15, 0, 0x4838003f}, {0, 15, 0x8f707e00}, {15, 15, 0x48383f3f}, {7, 7, 0xdfaf5b58} } },
    { "3dtransform perspective m34=.01", 8, { {0, 0, 0xffc80000}, {7, 0, 0x80640070}, {0, 7, 0xffc8e000}, {7, 7, 0x80647070}, {3, 3, 0xffc86060}, {8, 7, 0x00000000}, {0, 8, 0x00000000}, {15, 15, 0x00000000} } },
    { "crop(img) fractional 2.5,2.5,6.5,6.5 soft", 10, { {3, 3, 0xffc86060}, {6, 3, 0x40321830}, {3, 6, 0x80646030}, {6, 6, 0x20191818}, {4, 4, 0x80644040}, {2, 3, 0x00000000}, {7, 6, 0x00000000}, {6, 2, 0x00000000}, {3, 7, 0x00000000}, {15, 15, 0x00000000} } },
    { "crop(img) fractional hard", 10, { {3, 3, 0xffc86060}, {6, 3, 0x80643060}, {3, 6, 0xffc8c060}, {6, 6, 0x80646060}, {4, 4, 0x80644040}, {2, 3, 0x00000000}, {7, 6, 0x00000000}, {6, 2, 0x00000000}, {3, 7, 0x00000000}, {15, 15, 0x00000000} } },
    { "atlas rect 2,2,6,6 padding 1,1,7,7", 8, { {0, 0, 0xffc84040}, {3, 0, 0x80642050}, {0, 3, 0xffc8a040}, {3, 3, 0x80645050}, {1, 1, 0xffc86060}, {4, 3, 0x00000000}, {0, 4, 0x00000000}, {15, 15, 0x00000000} } },
    { "flood default black", 5, { {0, 0, 0xff000000}, {15, 0, 0xff000000}, {0, 15, 0xff000000}, {15, 15, 0xff000000}, {7, 7, 0xff000000} } },
    { "affine identity with draw offset 2.5,1.5", 10, { {2, 1, 0x3f320000}, {10, 1, 0x2019001c}, {2, 9, 0x3f323800}, {10, 9, 0x20191c1c}, {6, 5, 0xbf965450}, {1, 1, 0x00000000}, {11, 9, 0x00000000}, {10, 0, 0x00000000}, {2, 10, 0x00000000}, {15, 15, 0x00000000} } },
};

static unsigned int case_index;

static BOOL near_pixel(DWORD a, DWORD b)
{
    unsigned int s;

    for (s = 0; s < 32; s += 8)
    {
        int d = (int)((a >> s) & 0xff) - (int)((b >> s) & 0xff);
        if (d < -2 || d > 2) return FALSE;
    }
    return TRUE;
}

static void check_target(const char *name)
{
    D2D1_BITMAP_PROPERTIES1 p = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_CANNOT_DRAW | D2D1_BITMAP_OPTIONS_CPU_READ, NULL};
    const struct expected_case *c = &expected[case_index++];
    D2D1_SIZE_U s = {W, H};
    D2D1_MAPPED_RECT m;
    ID2D1Bitmap1 *staging = NULL;
    unsigned int i;
    HRESULT hr;

    ok(!strcmp(c->name, name), "Unexpected case %s, expected %s.\n", name, c->name);

    hr = ID2D1DeviceContext_CreateBitmap(ctx, s, NULL, 0, &p, &staging);
    ok(hr == S_OK, "%s: CreateBitmap failed, hr %#lx.\n", name, hr);
    if (FAILED(hr))
        return;
    hr = ID2D1Bitmap1_CopyFromBitmap(staging, NULL, (ID2D1Bitmap *)target, NULL);
    ok(hr == S_OK, "%s: CopyFromBitmap failed, hr %#lx.\n", name, hr);
    hr = ID2D1Bitmap1_Map(staging, D2D1_MAP_OPTIONS_READ, &m);
    ok(hr == S_OK, "%s: Map failed, hr %#lx.\n", name, hr);
    if (SUCCEEDED(hr))
    {
        for (i = 0; i < c->count; ++i)
        {
            DWORD v = ((DWORD *)(m.bits + c->points[i].y * m.pitch))[c->points[i].x];

            ok(near_pixel(v, c->points[i].value), "%s: pixel (%d, %d) is %08lx, expected %08lx.\n",
                    name, c->points[i].x, c->points[i].y, v, c->points[i].value);
        }
        ID2D1Bitmap1_Unmap(staging);
    }
    ID2D1Bitmap1_Release(staging);
}

static void render(const char *name, ID2D1Effect *e, float ox, float oy)
{
    D2D1_COLOR_F clear = {0.0f, 0.0f, 0.0f, 0.0f};
    D2D1_POINT_2F off = {ox, oy};
    ID2D1Image *out = NULL;
    HRESULT hr;

    ID2D1Effect_GetOutput(e, &out);
    ID2D1DeviceContext_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(ctx, &clear);
    ID2D1DeviceContext_DrawImage(ctx, out, &off, NULL, D2D1_INTERPOLATION_MODE_LINEAR, D2D1_COMPOSITE_MODE_SOURCE_OVER);
    hr = ID2D1DeviceContext_EndDraw(ctx, NULL, NULL);
    ok(hr == S_OK, "%s: EndDraw failed, hr %#lx.\n", name, hr);
    ID2D1Image_Release(out);
    check_target(name);
}

static void ID2D1Effect_SetInputEffect(ID2D1Effect *e, UINT32 i, ID2D1Effect *src, BOOL inv)
{
    ID2D1Image *o = NULL;

    ID2D1Effect_GetOutput(src, &o);
    ID2D1Effect_SetInput(e, i, o, inv);
    ID2D1Image_Release(o);
}

static ID2D1Bitmap1 *mkbmp(unsigned int w, unsigned int h, const DWORD *px)
{
    D2D1_BITMAP_PROPERTIES1 p = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_NONE, NULL};
    ID2D1Bitmap1 *b = NULL;
    D2D1_SIZE_U s = {w, h};
    HRESULT hr = ID2D1DeviceContext_CreateBitmap(ctx, s, px, w * 4, &p, &b);

    ok(hr == S_OK, "CreateBitmap failed, hr %#lx.\n", hr);
    return b;
}

static ID2D1DeviceContext *create_context(void)
{
    static const D3D_DRIVER_TYPE types[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    IDXGIDevice *dxgi_device;
    unsigned int i;
    HRESULT hr = E_FAIL;

    for (i = 0; i < ARRAY_SIZE(types) && FAILED(hr); ++i)
        hr = D3D11CreateDevice(NULL, types[i], NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                D3D11_SDK_VERSION, &d3d, NULL, NULL);
    if (FAILED(hr))
        return NULL;
    hr = ID3D11Device_QueryInterface(d3d, &IID_IDXGIDevice, (void **)&dxgi_device);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx.\n", hr);
    hr = D2D1CreateDevice(dxgi_device, NULL, &d2d);
    IDXGIDevice_Release(dxgi_device);
    if (FAILED(hr))
        return NULL;
    hr = ID2D1Device_CreateDeviceContext(d2d, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &ctx);
    return SUCCEEDED(hr) ? ctx : NULL;
}

static void settarget(void)
{
    D2D1_BITMAP_PROPERTIES1 p = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_TARGET, NULL};
    D2D1_SIZE_U s = {W, H};
    HRESULT hr = ID2D1DeviceContext_CreateBitmap(ctx, s, NULL, 0, &p, &target);

    ok(hr == S_OK, "CreateBitmap failed, hr %#lx.\n", hr);
    ID2D1DeviceContext_SetTarget(ctx, (ID2D1Image *)target);
}

/* 8x8 test image: B = x*32, G = y*32, R = 200, A = 255, except columns 4..7 where alpha = 128 (premultiplied) */
static ID2D1Bitmap1 *testimg(int variant)
{
    DWORD px[64]; unsigned x, y;
    for (y = 0; y < 8; ++y) for (x = 0; x < 8; ++x)
    {
        unsigned a = 255, r = 200, g = y * 32, b = x * 32;
        if (variant == 1) { r = 40; g = 160; b = 250 - x * 10; }
        if (x >= 4) { a = 128; r = r * a / 255; g = g * a / 255; b = b * a / 255; }
        px[y * 8 + x] = (a << 24) | (r << 16) | (g << 8) | b;
    }
    return mkbmp(8, 8, px);
}

static ID2D1Bitmap1 *dot(void)
{
    DWORD px[64] = {0}; px[3 * 8 + 3] = 0xffffffff; return mkbmp(8, 8, px);
}

static void setf(ID2D1Effect *e, UINT32 i, float v) { ID2D1Effect_SetValue(e, i, D2D1_PROPERTY_TYPE_FLOAT, (BYTE *)&v, 4); }
static void setu(ID2D1Effect *e, UINT32 i, UINT32 v) { ID2D1Effect_SetValue(e, i, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&v, 4); }
static void setm32(ID2D1Effect *e, UINT32 i, float a, float b, float c, float d, float tx, float ty)
{ float m[6] = {a,b,c,d,tx,ty}; ID2D1Effect_SetValue(e, i, D2D1_PROPERTY_TYPE_MATRIX_3X2, (BYTE *)m, 24); }

static ID2D1Effect *mk(const CLSID *c) { ID2D1Effect *e = NULL; ID2D1DeviceContext_CreateEffect(ctx, c, &e); return e; }
static void in0(ID2D1Effect *e, UINT32 i, ID2D1Bitmap1 *b) { ID2D1Effect_SetInput(e, i, (ID2D1Image *)b, TRUE); }

static void renders(void)
{
    ID2D1Bitmap1 *img = testimg(0), *img2 = testimg(1), *d = dot();
    ID2D1Effect *e;
    float v4[4];

    e = mk(&CLSID_D2D1Flood); v4[0]=1; v4[1]=0; v4[2]=0; v4[3]=0.5f;
    ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)v4, 16);
    render("flood red a=.5 (infinite)", e, 0, 0); ID2D1Effect_Release(e);

    { ID2D1Effect *fl = mk(&CLSID_D2D1Flood), *cr = mk(&CLSID_D2D1Crop); float r[4] = {4,4,12,12};
      v4[0]=0; v4[1]=1; v4[2]=0; v4[3]=1;
      ID2D1Effect_SetValue(fl, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)v4, 16);
      ID2D1Effect_SetValue(cr, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16);
      ID2D1Effect_SetInputEffect(cr, 0, fl, TRUE);
      render("crop(flood green) rect 4,4,12,12", cr, 0, 0); ID2D1Effect_Release(cr); ID2D1Effect_Release(fl); }

    e = mk(&CLSID_D2D1Crop); { float r[4] = {2,2,6,6}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16); }
    in0(e, 0, img); render("crop(img) rect 2,2,6,6", e, 0, 0); ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Flood); render("offset only: img via 2D affine identity", e, 0, 0); ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D12DAffineTransform); in0(e, 0, img);
    setm32(e, 2, 1,0,0,1, 3,2); render("affine translate 3,2", e, 0, 0);
    setm32(e, 2, 1,0,0,1, 0.5f,0); setu(e, 0, 1); render("affine translate .5,0 linear", e, 0, 0);
    setu(e, 0, 0); render("affine translate .5,0 nearest", e, 0, 0);
    setm32(e, 2, 2,0,0,2, 0,0); setu(e, 0, 1); render("affine scale 2 linear soft", e, 0, 0);
    setu(e, 1, 1); render("affine scale 2 linear hard", e, 0, 0); setu(e, 1, 0);
    setu(e, 0, 0); render("affine scale 2 nearest", e, 0, 0);
    setm32(e, 2, 0,1,-1,0, 8,0); render("affine rot90", e, 0, 0);
    ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Scale); in0(e, 0, img); { float s[2] = {2,2}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR2, (BYTE *)s, 8); }
    render("scale 2,2", e, 0, 0);
    { float s[2] = {0.5f,0.5f}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR2, (BYTE *)s, 8); }
    render("scale .5,.5", e, 0, 0); ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1ColorMatrix); in0(e, 0, img);
    { float m[20] = {0,0,1,0, 0,1,0,0, 1,0,0,0, 0,0,0,1, 0.1f,0,0,0}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_MATRIX_5X4, (BYTE *)m, 80); }
    render("colormatrix swap rb + bias r .1 premult", e, 0, 0);
    setu(e, 1, 2); render("colormatrix swap rb + bias r .1 straight", e, 0, 0);
    { float m[20] = {0.5f,0,0,0, 0,0.5f,0,0, 0,0,0.5f,0, 0,0,0,0.5f, 0,0,0,0}; setu(e, 1, 1); ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_MATRIX_5X4, (BYTE *)m, 80); }
    render("colormatrix half all premult", e, 0, 0); ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Composite); in0(e, 0, img); in0(e, 1, img2);
    { ID2D1Effect *a = mk(&CLSID_D2D12DAffineTransform); in0(a, 0, img2); setm32(a, 2, 1,0,0,1, 2,2); ID2D1Effect_SetInputEffect(e, 1, a, TRUE);
      render("composite src-over img + affine(img2,2,2)", e, 0, 0);
      setu(e, 0, 1); render("composite mode 1 (dest-over)", e, 0, 0);
      setu(e, 0, 2); render("composite mode 2 (src-in)", e, 0, 0);
      setu(e, 0, 9); render("composite mode 9 (plus)", e, 0, 0);
      setu(e, 0, 8); render("composite mode 8 (xor)", e, 0, 0);
      ID2D1Effect_Release(a); }
    ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Blend); in0(e, 0, img); in0(e, 1, img2);
    render("blend default (multiply)", e, 0, 0);
    setu(e, 0, 1); render("blend screen", e, 0, 0);
    setu(e, 0, 2); render("blend darken", e, 0, 0);
    setu(e, 0, 3); render("blend lighten", e, 0, 0);
    setu(e, 0, 5); render("blend color burn", e, 0, 0);
    setu(e, 0, 9); render("blend color dodge", e, 0, 0);
    setu(e, 0, 10); render("blend linear dodge", e, 0, 0);
    setu(e, 0, 11); render("blend overlay", e, 0, 0);
    setu(e, 0, 12); render("blend soft light", e, 0, 0);
    setu(e, 0, 13); render("blend hard light", e, 0, 0);
    setu(e, 0, 18); render("blend difference", e, 0, 0);
    setu(e, 0, 19); render("blend exclusion", e, 0, 0);
    setu(e, 0, 24); render("blend subtract", e, 0, 0);
    setu(e, 0, 25); render("blend division", e, 0, 0);
    ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1GaussianBlur); in0(e, 0, d); setf(e, 0, 1.0f); render("blur sigma 1 dot(3,3)", e, 0, 0);
    setf(e, 0, 2.0f); render("blur sigma 2", e, 0, 0); setf(e, 0, 0.0f); render("blur sigma 0", e, 0, 0);
    in0(e, 0, img); setf(e, 0, 1.0f); render("blur sigma 1 img soft", e, 0, 0); setu(e, 2, 1); render("blur sigma 1 img hard", e, 0, 0);
    ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Shadow); in0(e, 0, d); setf(e, 0, 1.0f); render("shadow sigma 1 black", e, 0, 0);
    v4[0]=1; v4[1]=0; v4[2]=0; v4[3]=0.5f; ID2D1Effect_SetValue(e, 1, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)v4, 16);
    render("shadow sigma 1 red a=.5", e, 0, 0); setf(e, 0, 0.0f); render("shadow sigma 0 red a=.5", e, 0, 0);
    in0(e, 0, img); render("shadow sigma 0 img", e, 0, 0);
    ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Atlas); in0(e, 0, img); { float r[4] = {2,2,6,6}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16); }
    render("atlas rect 2,2,6,6", e, 0, 0); ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Tile); in0(e, 0, img); { float r[4] = {0,0,3,3}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16); }
    render("tile rect 0,0,3,3", e, 0, 0);
    { float r[4] = {2,2,5,6}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16); } render("tile rect 2,2,5,6", e, 0, 0);
    ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D13DTransform); in0(e, 0, img);
    { float m[16] = {1,0,0,0, 0,1,0,0, 0,0,1,0, 3,2,0,1}; ID2D1Effect_SetValue(e, 2, D2D1_PROPERTY_TYPE_MATRIX_4X4, (BYTE *)m, 64); }
    render("3dtransform translate 3,2", e, 0, 0);
    { float m[16] = {2,0,0,0, 0,2,0,0, 0,0,1,0, 0,0,0,1}; ID2D1Effect_SetValue(e, 2, D2D1_PROPERTY_TYPE_MATRIX_4X4, (BYTE *)m, 64); }
    render("3dtransform scale 2", e, 0, 0);
    { float m[16] = {1,0,0,0, 0,1,0,0, 0,0,1,0.01f, 0,0,0,1}; ID2D1Effect_SetValue(e, 2, D2D1_PROPERTY_TYPE_MATRIX_4X4, (BYTE *)m, 64); }
    render("3dtransform perspective m34=.01", e, 0, 0);
    ID2D1Effect_Release(e);

    e = mk(&CLSID_D2D1Crop); in0(e, 0, img); { float r[4] = {2.5f,2.5f,6.5f,6.5f}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16); }
    render("crop(img) fractional 2.5,2.5,6.5,6.5 soft", e, 0, 0); setu(e, 1, 1); render("crop(img) fractional hard", e, 0, 0); ID2D1Effect_Release(e);
    e = mk(&CLSID_D2D1Atlas); in0(e, 0, img); { float r[4] = {2,2,6,6}, q[4] = {1,1,7,7}; ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16); ID2D1Effect_SetValue(e, 1, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)q, 16); }
    render("atlas rect 2,2,6,6 padding 1,1,7,7", e, 0, 0); ID2D1Effect_Release(e);
    e = mk(&CLSID_D2D1Flood); render("flood default black", e, 4, 4); ID2D1Effect_Release(e);
    e = mk(&CLSID_D2D12DAffineTransform); in0(e, 0, img); setm32(e, 2, 1,0,0,1, 0,0); render("affine identity with draw offset 2.5,1.5", e, 2.5f, 1.5f); ID2D1Effect_Release(e);
}


static float getf(ID2D1Effect *e, UINT32 i)
{
    float v = -12345.0f;
    HRESULT hr = ID2D1Effect_GetValue(e, i, D2D1_PROPERTY_TYPE_FLOAT, (BYTE *)&v, sizeof(v));

    ok(hr == S_OK, "GetValue(%u) failed, hr %#lx.\n", i, hr);
    return v;
}

static UINT32 getu(ID2D1Effect *e, UINT32 i)
{
    UINT32 v = 0xdeadbeef;
    HRESULT hr = ID2D1Effect_GetValue(e, i, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&v, sizeof(v));

    ok(hr == S_OK, "GetValue(%u) failed, hr %#lx.\n", i, hr);
    return v;
}

static void getv4(ID2D1Effect *e, UINT32 i, float *v)
{
    HRESULT hr = ID2D1Effect_GetValue(e, i, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)v, 16);

    ok(hr == S_OK, "GetValue(%u) failed, hr %#lx.\n", i, hr);
}

/* Defaults and ranges as reported by Windows 10. */
static void test_properties(void)
{
    ID2D1Effect *e;
    float v[4], f;
    UINT32 u;
    BOOL b;
    HRESULT hr;

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Flood, &e);
    ok(ID2D1Effect_GetPropertyCount(e) == 1, "Got %u properties.\n", ID2D1Effect_GetPropertyCount(e));
    getv4(e, 0, v);
    ok(v[0] == 0.0f && v[1] == 0.0f && v[2] == 0.0f && v[3] == 1.0f, "Got default colour %g,%g,%g,%g.\n", v[0], v[1], v[2], v[3]);
    v[0] = v[1] = v[2] = v[3] = 2.0f;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)v, sizeof(v));
    ok(hr == S_OK, "SetValue failed, hr %#lx.\n", hr);
    getv4(e, 0, v);
    ok(v[0] == 2.0f && v[3] == 2.0f, "Got colour %g,%g,%g,%g.\n", v[0], v[1], v[2], v[3]);
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1GaussianBlur, &e);
    ok(ID2D1Effect_GetPropertyCount(e) == 3, "Got %u properties.\n", ID2D1Effect_GetPropertyCount(e));
    ok(getf(e, 0) == 3.0f, "Got default deviation %g.\n", getf(e, 0));
    ok(getu(e, 1) == 1, "Got default optimization %u.\n", getu(e, 1));
    ok(getu(e, 2) == 0, "Got default border mode %u.\n", getu(e, 2));
    f = -1.0f;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_FLOAT, (BYTE *)&f, sizeof(f));
    ok(hr == S_OK, "SetValue failed, hr %#lx.\n", hr);
    ok(getf(e, 0) == 0.0f, "Got deviation %g.\n", getf(e, 0));
    f = 1e6f;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_FLOAT, (BYTE *)&f, sizeof(f));
    ok(hr == S_OK, "SetValue failed, hr %#lx.\n", hr);
    ok(getf(e, 0) == 250.0f, "Got deviation %g.\n", getf(e, 0));
    u = 3;
    hr = ID2D1Effect_SetValue(e, 1, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    ok(getu(e, 1) == 1, "Got optimization %u.\n", getu(e, 1));
    u = 2;
    hr = ID2D1Effect_SetValue(e, 2, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    u = 1;
    hr = ID2D1Effect_SetValue(e, 2, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ok(getu(e, 2) == 1, "Got border mode %u.\n", getu(e, 2));
    u = 2;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_UINT32, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Shadow, &e);
    ok(getf(e, 0) == 3.0f, "Got default deviation %g.\n", getf(e, 0));
    getv4(e, 1, v);
    ok(v[0] == 0.0f && v[1] == 0.0f && v[2] == 0.0f && v[3] == 1.0f, "Got default colour %g,%g,%g,%g.\n", v[0], v[1], v[2], v[3]);
    ok(getu(e, 2) == 1, "Got default optimization %u.\n", getu(e, 2));
    f = -2.0f;
    ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_FLOAT, (BYTE *)&f, sizeof(f));
    ok(getf(e, 0) == 0.0f, "Got deviation %g.\n", getf(e, 0));
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Crop, &e);
    getv4(e, 0, v);
    ok(v[0] < -1e38f && v[1] < -1e38f && v[2] > 1e38f && v[3] > 1e38f, "Got default rect %g,%g,%g,%g.\n", v[0], v[1], v[2], v[3]);
    ok(getu(e, 1) == 0, "Got default border mode %u.\n", getu(e, 1));
    u = 5;
    hr = ID2D1Effect_SetValue(e, 1, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Blend, &e);
    ok(getu(e, 0) == 0, "Got default mode %u.\n", getu(e, 0));
    u = 25;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    u = 26;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    ok(getu(e, 0) == 25, "Got mode %u.\n", getu(e, 0));
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Composite, &e);
    ok(getu(e, 0) == 0, "Got default mode %u.\n", getu(e, 0));
    u = 12;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    u = 13;
    hr = ID2D1Effect_SetValue(e, 0, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1ColorMatrix, &e);
    ok(ID2D1Effect_GetPropertyCount(e) == 3, "Got %u properties.\n", ID2D1Effect_GetPropertyCount(e));
    ok(getu(e, 1) == 1, "Got default alpha mode %u.\n", getu(e, 1));
    u = 0;
    hr = ID2D1Effect_SetValue(e, 1, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    u = 3;
    hr = ID2D1Effect_SetValue(e, 1, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == E_INVALIDARG, "Got hr %#lx.\n", hr);
    u = 2;
    hr = ID2D1Effect_SetValue(e, 1, D2D1_PROPERTY_TYPE_ENUM, (BYTE *)&u, sizeof(u));
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    b = TRUE;
    hr = ID2D1Effect_SetValue(e, 2, D2D1_PROPERTY_TYPE_BOOL, (BYTE *)&b, sizeof(b));
    ok(hr == S_OK, "Got hr %#lx.\n", hr);
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Atlas, &e);
    getv4(e, 0, v);
    ok(v[0] == 0.0f && v[1] == 0.0f && v[2] > 1e38f && v[3] > 1e38f, "Got default rect %g,%g,%g,%g.\n", v[0], v[1], v[2], v[3]);
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Tile, &e);
    getv4(e, 0, v);
    ok(v[0] == 0.0f && v[1] == 0.0f && v[2] == 100.0f && v[3] == 100.0f, "Got default rect %g,%g,%g,%g.\n", v[0], v[1], v[2], v[3]);
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D12DAffineTransform, &e);
    ok(ID2D1Effect_GetPropertyCount(e) == 4, "Got %u properties.\n", ID2D1Effect_GetPropertyCount(e));
    ok(getu(e, 0) == 1, "Got default interpolation mode %u.\n", getu(e, 0));
    ok(getf(e, 3) == 0.0f, "Got default sharpness %g.\n", getf(e, 3));
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Scale, &e);
    ok(ID2D1Effect_GetPropertyCount(e) == 5, "Got %u properties.\n", ID2D1Effect_GetPropertyCount(e));
    ID2D1Effect_Release(e);

    ID2D1DeviceContext_CreateEffect(ctx, &CLSID_D2D1Saturation, &e);
    ok(ID2D1Effect_GetPropertyCount(e) == 1, "Got %u properties.\n", ID2D1Effect_GetPropertyCount(e));
    ok(getf(e, 0) == 0.5f, "Got default saturation %g.\n", getf(e, 0));
    ID2D1Effect_Release(e);
}

static DWORD read_pixel(int x, int y)
{
    D2D1_BITMAP_PROPERTIES1 p = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_CANNOT_DRAW | D2D1_BITMAP_OPTIONS_CPU_READ, NULL};
    D2D1_SIZE_U size = {W, H};
    ID2D1Bitmap1 *staging = NULL;
    D2D1_MAPPED_RECT m;
    DWORD v = 0xdeadbeef;

    if (FAILED(ID2D1DeviceContext_CreateBitmap(ctx, size, NULL, 0, &p, &staging)))
        return v;
    ID2D1Bitmap1_CopyFromBitmap(staging, NULL, (ID2D1Bitmap *)target, NULL);
    if (SUCCEEDED(ID2D1Bitmap1_Map(staging, D2D1_MAP_OPTIONS_READ, &m)))
    {
        v = ((DWORD *)(m.bits + y * m.pitch))[x];
        ID2D1Bitmap1_Unmap(staging);
    }
    ID2D1Bitmap1_Release(staging);
    return v;
}

/* Composite modes other than source over: DrawImage composites with the target. Mask invert (the text caret of
 * Office) inverts the target where the source is opaque; the exact formula is the documented behaviour, it was not
 * measured. */
static void test_composite_modes(void)
{
    D2D1_COLOR_F white = {1.0f, 1.0f, 1.0f, 1.0f};
    D2D1_POINT_2F off = {0.0f, 0.0f};
    ID2D1Effect *flood, *crop;
    ID2D1Image *out;
    float v[4] = {1.0f, 1.0f, 1.0f, 1.0f}, r[4] = {4.0f, 4.0f, 8.0f, 8.0f};
    HRESULT hr;

    flood = mk(&CLSID_D2D1Flood);
    crop = mk(&CLSID_D2D1Crop);
    ID2D1Effect_SetValue(flood, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)v, 16);
    ID2D1Effect_SetValue(crop, 0, D2D1_PROPERTY_TYPE_VECTOR4, (BYTE *)r, 16);
    ID2D1Effect_SetInputEffect(crop, 0, flood, TRUE);
    ID2D1Effect_GetOutput(crop, &out);

    ID2D1DeviceContext_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(ctx, &white);
    ID2D1DeviceContext_DrawImage(ctx, out, &off, NULL, D2D1_INTERPOLATION_MODE_LINEAR, D2D1_COMPOSITE_MODE_MASK_INVERT);
    hr = ID2D1DeviceContext_EndDraw(ctx, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx.\n", hr);
    ok(near_pixel(read_pixel(5, 5), 0xff000000), "Got %08lx inside the mask.\n", read_pixel(5, 5));
    ok(near_pixel(read_pixel(8, 8), 0xffffffff), "Got %08lx outside the mask.\n", read_pixel(8, 8));
    ok(near_pixel(read_pixel(2, 2), 0xffffffff), "Got %08lx outside the mask.\n", read_pixel(2, 2));

    /* Destination out: the source alpha is removed from the destination. */
    ID2D1DeviceContext_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(ctx, &white);
    ID2D1DeviceContext_DrawImage(ctx, out, &off, NULL, D2D1_INTERPOLATION_MODE_LINEAR, D2D1_COMPOSITE_MODE_DESTINATION_OUT);
    hr = ID2D1DeviceContext_EndDraw(ctx, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx.\n", hr);
    ok(near_pixel(read_pixel(5, 5), 0x00000000), "Got %08lx inside the source.\n", read_pixel(5, 5));
    ok(near_pixel(read_pixel(9, 9), 0xffffffff), "Got %08lx outside the source.\n", read_pixel(9, 9));

    ID2D1Image_Release(out);
    ID2D1Effect_Release(crop);
    ID2D1Effect_Release(flood);
}

START_TEST(d2d1_effect_render)
{
    if (!create_context())
    {
        skip("Cannot create a Direct2D device context.\n");
        return;
    }

    test_properties();

    settarget();
    if (target)
    {
        renders();
        test_composite_modes();
        ok(case_index == ARRAY_SIZE(expected), "Ran %u of %u cases.\n", case_index, (unsigned int)ARRAY_SIZE(expected));
        ID2D1Bitmap1_Release(target);
    }

    ID2D1DeviceContext_Release(ctx);
    ID2D1Device_Release(d2d);
    ID3D11Device_Release(d3d);
}
