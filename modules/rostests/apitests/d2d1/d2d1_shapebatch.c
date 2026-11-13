/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Direct2D fills and strokes of ellipses, rounded rectangles and paths with a solid brush on a DC
 *              render target: held back draws give the same pixels as single draws for opaque shapes, and
 *              the same pixels up to blend rounding for translucent ones
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <math.h>
#include <windows.h>
#include <d2d1.h>

#include "wine/test.h"

#define SIZE 192
#define NUM_SHAPES 300

static ID2D1Factory *factory;

/* mode 0: the shapes follow each other; mode 1: a clip push and pop around each, which ends any held back draw.
 * scene 0: opaque shapes, 1: translucent shapes, 2: translucent shapes, transform and clip in between. */
static BOOL render(int mode, int scene, DWORD *out)
{
    D2D1_RENDER_TARGET_PROPERTIES desc;
    ID2D1DCRenderTarget *rt;
    ID2D1RenderTarget *r;
    ID2D1SolidColorBrush *brush;
    ID2D1PathGeometry *path;
    ID2D1GeometrySink *sink;
    BITMAPINFO bi;
    HBITMAP bitmap;
    DWORD *bits;
    HDC screen, dc;
    RECT rect;
    D2D1_RECT_F full = {0.0f, 0.0f, SIZE, SIZE};
    D2D1_COLOR_F white = {1.0f, 1.0f, 1.0f, 1.0f}, colour;
    D2D1_ELLIPSE ellipse;
    D2D1_ROUNDED_RECT rr;
    D2D1_POINT_2F p;
    D2D1_BEZIER_SEGMENT bz;
    D2D1_MATRIX_3X2_F m;
    HRESULT hr;
    int i;

    memset(&desc, 0, sizeof(desc));
    desc.type = D2D1_RENDER_TARGET_TYPE_DEFAULT;
    desc.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.pixelFormat.alphaMode = D2D1_ALPHA_MODE_IGNORE;
    hr = ID2D1Factory_CreateDCRenderTarget(factory, &desc, &rt);
    if (FAILED(hr))
    {
        skip("Cannot create a DC render target, hr %#lx\n", hr);
        return FALSE;
    }
    r = (ID2D1RenderTarget *)rt;

    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = SIZE;
    bi.bmiHeader.biHeight = -SIZE;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    screen = GetDC(NULL);
    bitmap = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, (void **)&bits, NULL, 0);
    dc = CreateCompatibleDC(screen);
    ReleaseDC(NULL, screen);
    if (!bitmap || !dc)
    {
        skip("Cannot create the DIB\n");
        if (dc) DeleteDC(dc);
        if (bitmap) DeleteObject(bitmap);
        ID2D1DCRenderTarget_Release(rt);
        return FALSE;
    }
    SelectObject(dc, bitmap);
    memset(bits, 0x40, SIZE * SIZE * 4);
    SetRect(&rect, 0, 0, SIZE, SIZE);
    hr = ID2D1DCRenderTarget_BindDC(rt, dc, &rect);
    ok(hr == S_OK, "BindDC failed, hr %#lx\n", hr);

    hr = ID2D1Factory_CreatePathGeometry(factory, &path);
    ok(hr == S_OK, "CreatePathGeometry failed, hr %#lx\n", hr);
    hr = ID2D1PathGeometry_Open(path, &sink);
    ok(hr == S_OK, "Open failed, hr %#lx\n", hr);
    p.x = 0.0f; p.y = 20.0f;
    ID2D1GeometrySink_BeginFigure(sink, p, D2D1_FIGURE_BEGIN_FILLED);
    bz.point1.x = 10.0f; bz.point1.y = -10.0f; bz.point2.x = 30.0f; bz.point2.y = 30.0f; bz.point3.x = 40.0f; bz.point3.y = 0.0f;
    ID2D1GeometrySink_AddBezier(sink, &bz);
    p.x = 40.0f; p.y = 30.0f;
    ID2D1GeometrySink_AddLine(sink, p);
    ID2D1GeometrySink_EndFigure(sink, D2D1_FIGURE_END_CLOSED);
    hr = ID2D1GeometrySink_Close(sink);
    ok(hr == S_OK, "Close failed, hr %#lx\n", hr);
    ID2D1GeometrySink_Release(sink);

    ID2D1RenderTarget_BeginDraw(r);
    ID2D1RenderTarget_Clear(r, &white);
    colour.r = 0.1f; colour.g = 0.5f; colour.b = 0.9f; colour.a = scene ? 0.4f : 1.0f;
    hr = ID2D1RenderTarget_CreateSolidColorBrush(r, &colour, NULL, &brush);
    ok(hr == S_OK, "CreateSolidColorBrush failed, hr %#lx\n", hr);

    for (i = 0; i < NUM_SHAPES; ++i)
    {
        float x = (float)((i * 29) % 150) + 20.0f, y = (float)((i * 17) % 140) + 25.0f;
        float width = 1.0f + (i % 3);

        /* the colour changes now and then, so runs of one colour are held back together */
        if (i % 9 == 0)
        {
            colour.r = (i % 11) / 10.0f; colour.g = (i % 5) / 4.0f; colour.b = 1.0f - (i % 13) / 12.0f;
            colour.a = scene ? 0.25f + (i % 3) * 0.25f : 1.0f;
            ID2D1SolidColorBrush_SetColor(brush, &colour);
        }
        if (scene == 2 && i % 40 == 0)
        {
            float a = (float)(i % 30) * 0.0174533f, c = cosf(a), sn = sinf(a);
            m._11 = c; m._12 = sn; m._21 = -sn; m._22 = c;
            m._31 = 96.0f - 96.0f * c + 96.0f * sn; m._32 = 96.0f - 96.0f * sn - 96.0f * c;
            ID2D1RenderTarget_SetTransform(r, &m);
        }
        if (scene == 2 && i == 150)
        {
            colour.r = colour.g = colour.b = 0.8f; colour.a = 1.0f;
            ID2D1RenderTarget_Clear(r, &colour);
        }
        if (scene == 2 && i % 100 == 50)
        {
            D2D1_RECT_F clip = {30.0f, 30.0f, 160.0f, 160.0f};
            ID2D1RenderTarget_PushAxisAlignedClip(r, &clip, D2D1_ANTIALIAS_MODE_ALIASED);
        }
        if (scene == 2 && i % 100 == 99)
            ID2D1RenderTarget_PopAxisAlignedClip(r);

        if (mode)
            ID2D1RenderTarget_PushAxisAlignedClip(r, &full, D2D1_ANTIALIAS_MODE_ALIASED);

        ellipse.point.x = x; ellipse.point.y = y;
        ellipse.radiusX = 6.0f + (i * 3) % 17; ellipse.radiusY = 5.0f + (i * 5) % 13;
        rr.rect.left = x - 10.0f; rr.rect.top = y - 8.0f; rr.rect.right = x + 8.0f + (i % 5); rr.rect.bottom = y + 9.0f;
        rr.radiusX = 3.0f + (i % 4); rr.radiusY = 2.0f + (i % 3);

        switch (i % 9)
        {
            case 0:
            case 1:
            case 2:
                ID2D1RenderTarget_FillEllipse(r, &ellipse, (ID2D1Brush *)brush);
                break;
            case 3:
                ID2D1RenderTarget_DrawEllipse(r, &ellipse, (ID2D1Brush *)brush, width, NULL);
                break;
            case 4:
                ID2D1RenderTarget_FillRoundedRectangle(r, &rr, (ID2D1Brush *)brush);
                break;
            case 5:
                ID2D1RenderTarget_DrawRoundedRectangle(r, &rr, (ID2D1Brush *)brush, width, NULL);
                break;
            case 6:
                ID2D1RenderTarget_FillRectangle(r, &rr.rect, (ID2D1Brush *)brush);
                break;
            case 7:
                ID2D1RenderTarget_DrawRectangle(r, &rr.rect, (ID2D1Brush *)brush, width, NULL);
                break;
            default:
                ID2D1RenderTarget_GetTransform(r, &m);
                {
                    D2D1_MATRIX_3X2_F t = m;
                    t._31 += x - 20.0f; t._32 += y - 15.0f;
                    ID2D1RenderTarget_SetTransform(r, &t);
                    if (i % 2)
                        ID2D1RenderTarget_FillGeometry(r, (ID2D1Geometry *)path, (ID2D1Brush *)brush, NULL);
                    else
                        ID2D1RenderTarget_DrawGeometry(r, (ID2D1Geometry *)path, (ID2D1Brush *)brush, width, NULL);
                    ID2D1RenderTarget_SetTransform(r, &m);
                }
                break;
        }

        if (mode)
            ID2D1RenderTarget_PopAxisAlignedClip(r);
    }
    ID2D1SolidColorBrush_Release(brush);
    hr = ID2D1RenderTarget_EndDraw(r, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx\n", hr);
    GdiFlush();
    memcpy(out, bits, SIZE * SIZE * 4);

    ID2D1PathGeometry_Release(path);
    DeleteDC(dc);
    DeleteObject(bitmap);
    ID2D1DCRenderTarget_Release(rt);
    return TRUE;
}

static void test_shape_batch(int scene)
{
    static DWORD held[SIZE * SIZE], single[SIZE * SIZE];
    unsigned int i, diff = 0, painted = 0, maxdelta = 0, hash = 2166136261u;

    if (!render(0, scene, held) || !render(1, scene, single))
        return;

    for (i = 0; i < SIZE * SIZE; ++i)
    {
        unsigned int c;

        if (held[i] != single[i])
            diff++;
        for (c = 0; c < 24; c += 8)
        {
            int d = (int)((held[i] >> c) & 0xff) - (int)((single[i] >> c) & 0xff);
            if ((unsigned int)abs(d) > maxdelta)
                maxdelta = abs(d);
        }
        if ((held[i] & 0xffffff) != 0xffffff)
            painted++;
        hash = (hash ^ held[i]) * 16777619u;
    }
    /* the hash lets two builds be compared with WINETEST_DEBUG=2 */
    trace("scene %d: %u painted, %u differ from single draws (max channel delta %u), hash %08x\n",
            scene, painted, diff, maxdelta, hash);
    ok(painted > 2000, "scene %d: only %u pixels were painted\n", scene, painted);
    if (scene == 0)
        ok(diff == 0, "scene %d: %u of %u pixels differ between held back and single draws\n", scene, diff, SIZE * SIZE);
    else
        ok(maxdelta <= 2, "scene %d: held back and single draws differ by up to %u\n", scene, maxdelta);
}

START_TEST(d2d1_shapebatch)
{
    HRESULT hr;

    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory, NULL, (void **)&factory);
    ok(hr == S_OK, "D2D1CreateFactory failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;

    test_shape_batch(0);
    test_shape_batch(1);
    test_shape_batch(2);

    ID2D1Factory_Release(factory);
}
