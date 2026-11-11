/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Direct2D solid fills on a DC render target give the same pixels whether they are
 *              issued one draw at a time or held back and issued together
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <math.h>
#include <windows.h>
#include <d2d1.h>

#include "wine/test.h"

#define SIZE 160
#define NUM_RECTS 400

static ID2D1Factory *factory;

/* mode 0: the fills follow each other; mode 1: a clip push and pop around each, which ends any held back draw */
static BOOL render(int mode, int scene, DWORD *out)
{
    D2D1_RENDER_TARGET_PROPERTIES desc;
    ID2D1DCRenderTarget *rt;
    ID2D1RenderTarget *r;
    ID2D1SolidColorBrush *brush;
    ID2D1RectangleGeometry *geometry;
    BITMAPINFO bi;
    HBITMAP bitmap;
    DWORD *bits;
    HDC screen, dc;
    RECT rect;
    D2D1_RECT_F full = {0.0f, 0.0f, SIZE, SIZE}, rf;
    D2D1_COLOR_F white = {1.0f, 1.0f, 1.0f, 1.0f}, colour;
    D2D1_ELLIPSE ellipse;
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

    ID2D1RenderTarget_BeginDraw(r);
    ID2D1RenderTarget_Clear(r, &white);
    colour.r = 0.1f; colour.g = 0.5f; colour.b = 0.9f; colour.a = 0.4f;
    hr = ID2D1RenderTarget_CreateSolidColorBrush(r, &colour, NULL, &brush);
    ok(hr == S_OK, "CreateSolidColorBrush failed, hr %#lx\n", hr);

    for (i = 0; i < NUM_RECTS; ++i)
    {
        /* overlapping translucent rectangles, the colour and the opacity change now and then */
        if (i % 7 == 0)
        {
            colour.r = (i % 11) / 10.0f; colour.g = (i % 5) / 4.0f; colour.b = 1.0f - (i % 13) / 12.0f;
            colour.a = 0.25f + (i % 3) * 0.25f;
            ID2D1SolidColorBrush_SetColor(brush, &colour);
        }
        if (i % 50 == 25)
            ID2D1SolidColorBrush_SetOpacity(brush, 0.5f + (i % 2) * 0.5f);
        if (scene == 1 && i % 40 == 0)
        {
            /* a transform, a clip and a Clear in the middle of the fills */
            float a = (float)(i % 30) * 0.0174533f, c = cosf(a), sn = sinf(a);
            m._11 = c; m._12 = sn; m._21 = -sn; m._22 = c;
            m._31 = 80.0f - 80.0f * c + 80.0f * sn; m._32 = 80.0f - 80.0f * sn - 80.0f * c;
            ID2D1RenderTarget_SetTransform(r, &m);
        }
        if (scene == 1 && i == 200)
        {
            colour.r = colour.g = colour.b = 0.8f; colour.a = 1.0f;
            ID2D1RenderTarget_Clear(r, &colour);
        }
        if (scene == 1 && i % 100 == 50)
        {
            D2D1_RECT_F clip = {20.0f, 20.0f, 140.0f, 140.0f};
            ID2D1RenderTarget_PushAxisAlignedClip(r, &clip, D2D1_ANTIALIAS_MODE_ALIASED);
        }
        if (scene == 1 && i % 100 == 99)
            ID2D1RenderTarget_PopAxisAlignedClip(r);

        rf.left = (float)((i * 7) % 120) + 0.25f * (i % 4);
        rf.top = (float)((i * 11) % 110) + 0.5f * (i % 3);
        rf.right = rf.left + 10 + (i * 3) % 37;
        rf.bottom = rf.top + 8 + (i * 5) % 41;

        if (mode)
            ID2D1RenderTarget_PushAxisAlignedClip(r, &full, D2D1_ANTIALIAS_MODE_ALIASED);

        if (scene == 1 && i % 9 == 4)
        {
            hr = ID2D1Factory_CreateRectangleGeometry(factory, &rf, &geometry);
            ok(hr == S_OK, "CreateRectangleGeometry failed, hr %#lx\n", hr);
            ID2D1RenderTarget_FillGeometry(r, (ID2D1Geometry *)geometry, (ID2D1Brush *)brush, NULL);
            ID2D1RectangleGeometry_Release(geometry);
        }
        else if (scene == 1 && i % 13 == 6)
        {
            ellipse.point.x = rf.left; ellipse.point.y = rf.top; ellipse.radiusX = 14.0f; ellipse.radiusY = 9.0f;
            ID2D1RenderTarget_FillEllipse(r, &ellipse, (ID2D1Brush *)brush);
        }
        else
            ID2D1RenderTarget_FillRectangle(r, &rf, (ID2D1Brush *)brush);

        if (mode)
            ID2D1RenderTarget_PopAxisAlignedClip(r);
    }
    ID2D1SolidColorBrush_Release(brush);
    hr = ID2D1RenderTarget_EndDraw(r, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx\n", hr);
    GdiFlush();
    memcpy(out, bits, SIZE * SIZE * 4);

    DeleteDC(dc);
    DeleteObject(bitmap);
    ID2D1DCRenderTarget_Release(rt);
    return TRUE;
}

static void test_fill_batch(int scene)
{
    static DWORD held[SIZE * SIZE], single[SIZE * SIZE];
    unsigned int i, diff = 0, painted = 0;

    if (!render(0, scene, held) || !render(1, scene, single))
        return;

    for (i = 0; i < SIZE * SIZE; ++i)
    {
        if (held[i] != single[i])
            diff++;
        if ((held[i] & 0xffffff) != 0xffffff)
            painted++;
    }
    {
        /* the hash lets two builds be compared with WINETEST_DEBUG=2 */
        unsigned int hash = 2166136261u;
        for (i = 0; i < SIZE * SIZE; ++i)
            hash = (hash ^ held[i]) * 16777619u;
        trace("scene %d: %u painted, hash %08x\n", scene, painted, hash);
    }
    ok(painted > 1000, "scene %d: only %u pixels were painted\n", scene, painted);
    ok(diff == 0, "scene %d: %u of %u pixels differ between held back and single fills\n", scene, diff, SIZE * SIZE);
}

START_TEST(d2d1_fillbatch)
{
    HRESULT hr;

    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory, NULL, (void **)&factory);
    ok(hr == S_OK, "D2D1CreateFactory failed, hr %#lx\n", hr);
    if (FAILED(hr))
        return;

    test_fill_batch(0);
    test_fill_batch(1);

    ID2D1Factory_Release(factory);
}
