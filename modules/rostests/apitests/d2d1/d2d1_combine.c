/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ID2D1Geometry::CombineWithGeometry: union, intersect, xor and exclude of rectangles,
 *              rounded rectangles, ellipses, paths, transformed geometries and geometry groups
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <initguid.h>
#include <math.h>
#include <windows.h>
#include <d3d11.h>
#include <d2d1_1.h>

#include "wine/test.h"

static ID2D1Factory *factory;

static const D2D1_MATRIX_3X2_F identity = {{{1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f}}};

static ID2D1PathGeometry *combine(ID2D1Geometry *a, ID2D1Geometry *b, D2D1_COMBINE_MODE mode,
        const D2D1_MATRIX_3X2_F *transform, HRESULT *result)
{
    ID2D1GeometrySink *sink;
    ID2D1PathGeometry *path;
    HRESULT hr;

    hr = ID2D1Factory_CreatePathGeometry(factory, &path);
    ok(hr == S_OK, "CreatePathGeometry failed, hr %#lx.\n", hr);
    hr = ID2D1PathGeometry_Open(path, &sink);
    ok(hr == S_OK, "Open failed, hr %#lx.\n", hr);
    hr = ID2D1Geometry_CombineWithGeometry(a, b, mode, transform, D2D1_DEFAULT_FLATTENING_TOLERANCE,
            (ID2D1SimplifiedGeometrySink *)sink);
    *result = hr;
    ID2D1GeometrySink_Close(sink);
    ID2D1GeometrySink_Release(sink);
    if (FAILED(hr))
    {
        ID2D1PathGeometry_Release(path);
        return NULL;
    }
    return path;
}

/* Area of a geometry in the box [0, 40)^2, by sampling FillContainsPoint on a 0.25 grid. */
static double sampled_area(ID2D1Geometry *g)
{
    unsigned int x, y, count = 0;
    BOOL contains;
    HRESULT hr;

    for (y = 0; y < 160; ++y)
    {
        for (x = 0; x < 160; ++x)
        {
            D2D1_POINT_2F p = {x * 0.25f + 0.125f, y * 0.25f + 0.125f};

            contains = FALSE;
            hr = ID2D1Geometry_FillContainsPoint(g, p, NULL, 0.25f, &contains);
            if (hr != S_OK)
                return -1.0;
            if (contains)
                ++count;
        }
    }
    return count * 0.0625;
}

static BOOL contains_point(ID2D1Geometry *g, float x, float y)
{
    D2D1_POINT_2F p = {x, y};
    BOOL contains = FALSE;

    ID2D1Geometry_FillContainsPoint(g, p, NULL, 0.25f, &contains);
    return contains;
}

static void check_area(ID2D1Geometry *a, ID2D1Geometry *b, D2D1_COMBINE_MODE mode,
        const D2D1_MATRIX_3X2_F *transform, double expected, double tolerance, const char *name)
{
    ID2D1PathGeometry *path;
    HRESULT hr;
    double area;

    path = combine(a, b, mode, transform, &hr);
    ok(hr == S_OK, "%s mode %u: CombineWithGeometry failed, hr %#lx.\n", name, mode, hr);
    if (!path)
        return;
    area = sampled_area((ID2D1Geometry *)path);
    ok(fabs(area - expected) <= tolerance, "%s mode %u: area %.3f, expected %.3f.\n", name, mode, area, expected);
    ID2D1PathGeometry_Release(path);
}

static ID2D1RectangleGeometry *rect_geometry(float l, float t, float r, float b)
{
    D2D1_RECT_F rect = {l, t, r, b};
    ID2D1RectangleGeometry *g;
    HRESULT hr = ID2D1Factory_CreateRectangleGeometry(factory, &rect, &g);

    ok(hr == S_OK, "CreateRectangleGeometry failed, hr %#lx.\n", hr);
    return g;
}

static void test_rectangles(void)
{
    ID2D1RectangleGeometry *a = rect_geometry(0.0f, 0.0f, 10.0f, 10.0f);
    ID2D1RectangleGeometry *b = rect_geometry(5.0f, 5.0f, 15.0f, 15.0f);
    ID2D1RectangleGeometry *inner = rect_geometry(2.0f, 2.0f, 8.0f, 8.0f);
    ID2D1RectangleGeometry *same = rect_geometry(0.0f, 0.0f, 10.0f, 10.0f);
    ID2D1RectangleGeometry *right = rect_geometry(10.0f, 0.0f, 20.0f, 10.0f);
    ID2D1RectangleGeometry *far_away = rect_geometry(25.0f, 25.0f, 30.0f, 30.0f);
    ID2D1RectangleGeometry *shifted = rect_geometry(0.0f, 0.0f, 10.0f, 10.0f);
    ID2D1PathGeometry *path;
    D2D1_MATRIX_3X2_F translate = {{{1.0f, 0.0f, 0.0f, 1.0f, 5.0f, 5.0f}}};
    HRESULT hr;

    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_UNION, NULL, 175.0, 0.01, "overlap");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_INTERSECT, NULL, 25.0, 0.01, "overlap");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_XOR, NULL, 150.0, 0.01, "overlap");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_EXCLUDE, NULL, 75.0, 0.01, "overlap");
    check_area((ID2D1Geometry *)b, (ID2D1Geometry *)a, D2D1_COMBINE_MODE_EXCLUDE, NULL, 75.0, 0.01, "overlap swapped");

    /* What Excel does: a rectangle with the one inside it removed leaves a frame. */
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)inner, D2D1_COMBINE_MODE_EXCLUDE, NULL, 64.0, 0.01, "frame");
    path = combine((ID2D1Geometry *)a, (ID2D1Geometry *)inner, D2D1_COMBINE_MODE_EXCLUDE, NULL, &hr);
    ok(hr == S_OK, "frame: CombineWithGeometry failed, hr %#lx.\n", hr);
    if (path)
    {
        ok(contains_point((ID2D1Geometry *)path, 1.0f, 1.0f), "the frame does not contain (1, 1).\n");
        ok(contains_point((ID2D1Geometry *)path, 9.0f, 5.0f), "the frame does not contain (9, 5).\n");
        ok(!contains_point((ID2D1Geometry *)path, 5.0f, 5.0f), "the frame contains its hole.\n");
        ok(!contains_point((ID2D1Geometry *)path, 12.0f, 5.0f), "the frame contains (12, 5).\n");
        ID2D1PathGeometry_Release(path);
    }
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)inner, D2D1_COMBINE_MODE_UNION, NULL, 100.0, 0.01, "frame");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)inner, D2D1_COMBINE_MODE_INTERSECT, NULL, 36.0, 0.01, "frame");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)inner, D2D1_COMBINE_MODE_XOR, NULL, 64.0, 0.01, "frame");
    check_area((ID2D1Geometry *)inner, (ID2D1Geometry *)a, D2D1_COMBINE_MODE_EXCLUDE, NULL, 0.0, 0.01, "frame swapped");

    /* Identical rectangles: all edges are shared. */
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)same, D2D1_COMBINE_MODE_UNION, NULL, 100.0, 0.01, "same");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)same, D2D1_COMBINE_MODE_INTERSECT, NULL, 100.0, 0.01, "same");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)same, D2D1_COMBINE_MODE_XOR, NULL, 0.0, 0.01, "same");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)same, D2D1_COMBINE_MODE_EXCLUDE, NULL, 0.0, 0.01, "same");

    /* Rectangles that touch along an edge. */
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)right, D2D1_COMBINE_MODE_UNION, NULL, 200.0, 0.01, "touching");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)right, D2D1_COMBINE_MODE_INTERSECT, NULL, 0.0, 0.01, "touching");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)right, D2D1_COMBINE_MODE_XOR, NULL, 200.0, 0.01, "touching");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)right, D2D1_COMBINE_MODE_EXCLUDE, NULL, 100.0, 0.01, "touching");

    /* Disjoint rectangles. */
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)far_away, D2D1_COMBINE_MODE_UNION, NULL, 125.0, 0.01, "disjoint");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)far_away, D2D1_COMBINE_MODE_INTERSECT, NULL, 0.0, 0.01,
            "disjoint");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)far_away, D2D1_COMBINE_MODE_EXCLUDE, NULL, 100.0, 0.01,
            "disjoint");

    /* The matrix applies to the second geometry. */
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)shifted, D2D1_COMBINE_MODE_UNION, &translate, 175.0, 0.01,
            "matrix");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)shifted, D2D1_COMBINE_MODE_INTERSECT, &translate, 25.0, 0.01,
            "matrix");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)shifted, D2D1_COMBINE_MODE_EXCLUDE, &identity, 0.0, 0.01,
            "identity matrix");

    ID2D1RectangleGeometry_Release(shifted);
    ID2D1RectangleGeometry_Release(far_away);
    ID2D1RectangleGeometry_Release(right);
    ID2D1RectangleGeometry_Release(same);
    ID2D1RectangleGeometry_Release(inner);
    ID2D1RectangleGeometry_Release(b);
    ID2D1RectangleGeometry_Release(a);
}

static void test_curves(void)
{
    D2D1_ROUNDED_RECT rr = {{0.0f, 0.0f, 20.0f, 20.0f}, 4.0f, 4.0f};
    D2D1_ELLIPSE ellipse = {{10.0f, 10.0f}, 5.0f, 5.0f};
    ID2D1RoundedRectangleGeometry *rounded;
    ID2D1EllipseGeometry *circle;
    ID2D1RectangleGeometry *half = rect_geometry(0.0f, 0.0f, 10.0f, 20.0f);
    ID2D1RectangleGeometry *whole = rect_geometry(0.0f, 0.0f, 20.0f, 20.0f);
    double pi = 3.14159265358979, circle_area = pi * 25.0, rounded_area = 400.0 - (64.0 - pi * 16.0);
    HRESULT hr;

    hr = ID2D1Factory_CreateEllipseGeometry(factory, &ellipse, &circle);
    ok(hr == S_OK, "CreateEllipseGeometry failed, hr %#lx.\n", hr);
    hr = ID2D1Factory_CreateRoundedRectangleGeometry(factory, &rr, &rounded);
    ok(hr == S_OK, "CreateRoundedRectangleGeometry failed, hr %#lx.\n", hr);

    /* Flattened curves lose a little area. */
    check_area((ID2D1Geometry *)circle, (ID2D1Geometry *)half, D2D1_COMBINE_MODE_INTERSECT, NULL,
            circle_area / 2.0, 3.0, "circle half");
    check_area((ID2D1Geometry *)whole, (ID2D1Geometry *)circle, D2D1_COMBINE_MODE_EXCLUDE, NULL,
            400.0 - circle_area, 3.0, "circle hole");
    check_area((ID2D1Geometry *)rounded, (ID2D1Geometry *)whole, D2D1_COMBINE_MODE_INTERSECT, NULL,
            rounded_area, 3.0, "rounded");
    check_area((ID2D1Geometry *)whole, (ID2D1Geometry *)rounded, D2D1_COMBINE_MODE_EXCLUDE, NULL,
            400.0 - rounded_area, 3.0, "rounded corners");
    check_area((ID2D1Geometry *)rounded, (ID2D1Geometry *)circle, D2D1_COMBINE_MODE_UNION, NULL,
            rounded_area, 3.0, "circle inside rounded");

    ID2D1RectangleGeometry_Release(whole);
    ID2D1RectangleGeometry_Release(half);
    ID2D1RoundedRectangleGeometry_Release(rounded);
    ID2D1EllipseGeometry_Release(circle);
}

static ID2D1PathGeometry *two_nested_squares(D2D1_FILL_MODE mode)
{
    static const D2D1_POINT_2F outer[] = {{10.0f, 0.0f}, {10.0f, 10.0f}, {0.0f, 10.0f}};
    static const D2D1_POINT_2F inner[] = {{8.0f, 2.0f}, {8.0f, 8.0f}, {2.0f, 8.0f}};
    D2D1_POINT_2F start = {0.0f, 0.0f}, start2 = {2.0f, 2.0f};
    ID2D1GeometrySink *sink;
    ID2D1PathGeometry *path;
    HRESULT hr;

    hr = ID2D1Factory_CreatePathGeometry(factory, &path);
    ok(hr == S_OK, "CreatePathGeometry failed, hr %#lx.\n", hr);
    hr = ID2D1PathGeometry_Open(path, &sink);
    ok(hr == S_OK, "Open failed, hr %#lx.\n", hr);
    ID2D1GeometrySink_SetFillMode(sink, mode);
    ID2D1GeometrySink_BeginFigure(sink, start, D2D1_FIGURE_BEGIN_FILLED);
    ID2D1GeometrySink_AddLines(sink, outer, ARRAY_SIZE(outer));
    ID2D1GeometrySink_EndFigure(sink, D2D1_FIGURE_END_CLOSED);
    ID2D1GeometrySink_BeginFigure(sink, start2, D2D1_FIGURE_BEGIN_FILLED);
    ID2D1GeometrySink_AddLines(sink, inner, ARRAY_SIZE(inner));
    ID2D1GeometrySink_EndFigure(sink, D2D1_FIGURE_END_CLOSED);
    hr = ID2D1GeometrySink_Close(sink);
    ok(hr == S_OK, "Close failed, hr %#lx.\n", hr);
    ID2D1GeometrySink_Release(sink);
    return path;
}

static void test_paths_and_groups(void)
{
    ID2D1RectangleGeometry *far_away = rect_geometry(25.0f, 25.0f, 30.0f, 30.0f);
    ID2D1RectangleGeometry *a = rect_geometry(0.0f, 0.0f, 10.0f, 10.0f);
    ID2D1RectangleGeometry *b = rect_geometry(5.0f, 5.0f, 15.0f, 15.0f);
    D2D1_MATRIX_3X2_F scale2 = {{{2.0f, 0.0f, 0.0f, 2.0f, 0.0f, 0.0f}}};
    ID2D1Geometry *sources[2] = {(ID2D1Geometry *)a, (ID2D1Geometry *)far_away};
    ID2D1TransformedGeometry *transformed;
    ID2D1PathGeometry *winding, *alternate;
    ID2D1GeometryGroup *group;
    HRESULT hr;

    /* The fill mode of the path decides what its inner square is. */
    winding = two_nested_squares(D2D1_FILL_MODE_WINDING);
    alternate = two_nested_squares(D2D1_FILL_MODE_ALTERNATE);
    check_area((ID2D1Geometry *)winding, (ID2D1Geometry *)far_away, D2D1_COMBINE_MODE_EXCLUDE, NULL, 100.0, 0.01,
            "winding path");
    check_area((ID2D1Geometry *)alternate, (ID2D1Geometry *)far_away, D2D1_COMBINE_MODE_EXCLUDE, NULL, 64.0, 0.01,
            "alternate path");
    check_area((ID2D1Geometry *)winding, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_INTERSECT, NULL, 25.0, 0.01,
            "winding path");
    check_area((ID2D1Geometry *)alternate, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_INTERSECT, NULL, 16.0, 0.01,
            "alternate path");
    /* As the second geometry: b minus the frame (the part of b inside the frame is 25 - 9). */
    check_area((ID2D1Geometry *)b, (ID2D1Geometry *)alternate, D2D1_COMBINE_MODE_EXCLUDE, NULL, 84.0, 0.01,
            "alternate path second");
    ID2D1PathGeometry_Release(alternate);
    ID2D1PathGeometry_Release(winding);

    /* A geometry group and a transformed geometry. */
    hr = ID2D1Factory_CreateGeometryGroup(factory, D2D1_FILL_MODE_WINDING, sources, ARRAY_SIZE(sources), &group);
    ok(hr == S_OK, "CreateGeometryGroup failed, hr %#lx.\n", hr);
    check_area((ID2D1Geometry *)group, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_UNION, NULL, 175.0 + 25.0, 0.01,
            "group");
    check_area((ID2D1Geometry *)group, (ID2D1Geometry *)b, D2D1_COMBINE_MODE_INTERSECT, NULL, 25.0, 0.01, "group");
    ID2D1GeometryGroup_Release(group);

    hr = ID2D1Factory_CreateTransformedGeometry(factory, (ID2D1Geometry *)a, &scale2, &transformed);
    ok(hr == S_OK, "CreateTransformedGeometry failed, hr %#lx.\n", hr);
    check_area((ID2D1Geometry *)transformed, (ID2D1Geometry *)a, D2D1_COMBINE_MODE_EXCLUDE, NULL, 400.0 - 100.0,
            0.01, "transformed");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)transformed, D2D1_COMBINE_MODE_EXCLUDE, NULL, 0.0, 0.01,
            "transformed second");
    check_area((ID2D1Geometry *)a, (ID2D1Geometry *)transformed, D2D1_COMBINE_MODE_UNION, NULL, 400.0, 0.01,
            "transformed second");
    ID2D1TransformedGeometry_Release(transformed);

    ID2D1RectangleGeometry_Release(b);
    ID2D1RectangleGeometry_Release(a);
    ID2D1RectangleGeometry_Release(far_away);
}


#define SIZE 32

static void test_draw(void)
{
    static const D3D_DRIVER_TYPE types[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    D2D1_BITMAP_PROPERTIES1 target_props = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_TARGET, NULL};
    D2D1_BITMAP_PROPERTIES1 staging_props = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_CANNOT_DRAW | D2D1_BITMAP_OPTIONS_CPU_READ, NULL};
    D2D1_COLOR_F clear = {0.0f, 0.0f, 0.0f, 0.0f}, white = {1.0f, 1.0f, 1.0f, 1.0f};
    D2D1_SIZE_U size = {SIZE, SIZE};
    ID2D1RectangleGeometry *outer, *hole;
    ID2D1Bitmap1 *target, *staging = NULL;
    ID2D1SolidColorBrush *brush;
    ID2D1DeviceContext *context;
    ID3D11Device *d3d_device = NULL;
    ID2D1Factory1 *factory1;
    ID2D1PathGeometry *path;
    D2D1_MAPPED_RECT mapped;
    IDXGIDevice *dxgi_device;
    ID2D1Device *device;
    unsigned int i;
    HRESULT hr = E_FAIL;

    for (i = 0; i < ARRAY_SIZE(types) && FAILED(hr); ++i)
        hr = D3D11CreateDevice(NULL, types[i], NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                D3D11_SDK_VERSION, &d3d_device, NULL, NULL);
    if (FAILED(hr))
    {
        skip("Cannot create a Direct3D 11 device.\n");
        return;
    }
    hr = ID3D11Device_QueryInterface(d3d_device, &IID_IDXGIDevice, (void **)&dxgi_device);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx.\n", hr);
    hr = D2D1CreateDevice(dxgi_device, NULL, &device);
    IDXGIDevice_Release(dxgi_device);
    if (FAILED(hr))
    {
        skip("Cannot create a Direct2D device, hr %#lx.\n", hr);
        ID3D11Device_Release(d3d_device);
        return;
    }
    hr = ID2D1Device_CreateDeviceContext(device, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &context);
    if (FAILED(hr))
    {
        skip("Cannot create a Direct2D device context, hr %#lx.\n", hr);
        ID2D1Device_Release(device);
        ID3D11Device_Release(d3d_device);
        return;
    }
    hr = ID2D1Factory_QueryInterface(factory, &IID_ID2D1Factory1, (void **)&factory1);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx.\n", hr);
    ID2D1Factory1_Release(factory1);

    hr = ID2D1DeviceContext_CreateBitmap(context, size, NULL, 0, &target_props, &target);
    ok(hr == S_OK, "CreateBitmap failed, hr %#lx.\n", hr);
    hr = ID2D1DeviceContext_CreateBitmap(context, size, NULL, 0, &staging_props, &staging);
    ok(hr == S_OK, "CreateBitmap failed, hr %#lx.\n", hr);
    ID2D1DeviceContext_SetTarget(context, (ID2D1Image *)target);
    hr = ID2D1DeviceContext_CreateSolidColorBrush(context, &white, NULL, &brush);
    ok(hr == S_OK, "CreateSolidColorBrush failed, hr %#lx.\n", hr);

    /* A 4 pixel frame: the rectangle (4, 4)-(28, 28) minus (8, 8)-(24, 24). */
    outer = rect_geometry(4.0f, 4.0f, 28.0f, 28.0f);
    hole = rect_geometry(8.0f, 8.0f, 24.0f, 24.0f);
    path = combine((ID2D1Geometry *)outer, (ID2D1Geometry *)hole, D2D1_COMBINE_MODE_EXCLUDE, NULL, &hr);
    ok(hr == S_OK, "CombineWithGeometry failed, hr %#lx.\n", hr);
    if (path && staging)
    {
        ID2D1DeviceContext_BeginDraw(context);
        ID2D1DeviceContext_Clear(context, &clear);
        ID2D1DeviceContext_FillGeometry(context, (ID2D1Geometry *)path, (ID2D1Brush *)brush, NULL);
        hr = ID2D1DeviceContext_EndDraw(context, NULL, NULL);
        ok(hr == S_OK, "EndDraw failed, hr %#lx.\n", hr);

        ID2D1Bitmap1_CopyFromBitmap(staging, NULL, (ID2D1Bitmap *)target, NULL);
        hr = ID2D1Bitmap1_Map(staging, D2D1_MAP_OPTIONS_READ, &mapped);
        ok(hr == S_OK, "Map failed, hr %#lx.\n", hr);
        if (SUCCEEDED(hr))
        {
            static const struct { int x, y; DWORD expected; } tests[] =
            {
                {2, 2, 0x00000000}, {5, 5, 0xffffffff}, {6, 16, 0xffffffff}, {26, 16, 0xffffffff},
                {16, 5, 0xffffffff}, {16, 26, 0xffffffff}, {16, 16, 0x00000000}, {12, 12, 0x00000000},
                {30, 30, 0x00000000},
            };
            unsigned int t;

            for (t = 0; t < ARRAY_SIZE(tests); ++t)
            {
                DWORD value = ((DWORD *)(mapped.bits + tests[t].y * mapped.pitch))[tests[t].x];

                ok(value == tests[t].expected, "pixel (%d, %d) is %08lx, expected %08lx.\n",
                        tests[t].x, tests[t].y, value, tests[t].expected);
            }
            ID2D1Bitmap1_Unmap(staging);
        }
    }
    if (path)
        ID2D1PathGeometry_Release(path);
    ID2D1RectangleGeometry_Release(hole);
    ID2D1RectangleGeometry_Release(outer);
    ID2D1SolidColorBrush_Release(brush);
    if (staging)
        ID2D1Bitmap1_Release(staging);
    ID2D1Bitmap1_Release(target);
    ID2D1DeviceContext_Release(context);
    ID2D1Device_Release(device);
    ID3D11Device_Release(d3d_device);
}

START_TEST(d2d1_combine)
{
    HRESULT hr;

    hr = D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &IID_ID2D1Factory, NULL, (void **)&factory);
    ok(hr == S_OK, "D2D1CreateFactory failed, hr %#lx.\n", hr);
    if (FAILED(hr))
        return;

    test_rectangles();
    test_curves();
    test_paths_and_groups();
    test_draw();

    ID2D1Factory_Release(factory);
}
