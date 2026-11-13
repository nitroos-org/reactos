/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ID2D1DeviceContext5::DrawSvgDocument: path data, fill rules, opacity, viewBox and
 *              preserveAspectRatio, drawn on a bitmap target and through a command list
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The expected pixels follow from the W3C SVG 1.1 maths (path data grammar and arc rules, appendix F;
 * viewBox / preserveAspectRatio, section 7.8; fill-rule and fill-opacity, chapter 11), sampled well inside or
 * outside the shapes so the anti-aliasing does not matter; the tolerance of 2 per channel only covers the
 * rounding of the opacity. Cases that depend on Direct2D behaviour that is not specified by the SVG
 * recommendation are marked "verify on oracle" and have not been measured.
 */

#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <d3d11.h>
#include <d2d1_3.h>
#include <reactos/d2d1_svg.h>
#include <stdlib.h>

#include "wine/test.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define TW 16
#define TH 16

static ID3D11Device *d3d;
static ID2D1Device *d2d;
static ID2D1DeviceContext5 *ctx;
static ID2D1DeviceContext *dc; /* the same object, for the methods of the base interface */

#define RED   0xffff0000
#define GREEN 0xff008000
#define BLUE  0xff0000ff
#define BLACK 0xff000000
/* fully transparent; the 1 keeps an entry with x = y = 0 from looking like the end of the list (tolerance is 2) */
#define NONE  0x00000001

struct point { int x, y; DWORD value; };

struct element
{
    int parent;             /* index in the case, -1 = the root element */
    const WCHAR *tag;
    const WCHAR *attrs;     /* name=value pairs separated by '|' (a value 'pod:...' uses the typed form) */
};

struct svg_case
{
    const char *name;
    float vw, vh;           /* viewport size of the document */
    const WCHAR *root;      /* attributes of the root element */
    struct element elements[4];
    struct point points[12];
};

static BOOL near_pixel(DWORD a, DWORD b, int tolerance)
{
    unsigned int s;

    for (s = 0; s < 32; s += 8)
    {
        int d = (int)((a >> s) & 0xff) - (int)((b >> s) & 0xff);
        if (d < -tolerance || d > tolerance) return FALSE;
    }
    return TRUE;
}

static unsigned int parse_hex(const WCHAR *s, unsigned int digits)
{
    unsigned int v = 0;

    while (digits--)
    {
        v <<= 4;
        v |= *s <= '9' ? *s - '0' : (*s | 0x20) - 'a' + 10;
        ++s;
    }
    return v;
}

static void set_attr(ID2D1SvgElement *e, const WCHAR *name, const WCHAR *value)
{
    HRESULT hr;

    if (!wcsncmp(value, L"pod:", 4))
    {
        const WCHAR *v = value + 4;

        if (!wcscmp(name, L"fill") || !wcscmp(name, L"stroke"))
        {
            D2D1_COLOR_F c;

            c.a = parse_hex(v, 2) / 255.0f;
            c.r = parse_hex(v + 2, 2) / 255.0f;
            c.g = parse_hex(v + 4, 2) / 255.0f;
            c.b = parse_hex(v + 6, 2) / 255.0f;
            hr = ID2D1SvgElement_SetAttributeValuePOD(e, name, D2D1_SVG_ATTRIBUTE_POD_TYPE_COLOR, &c, sizeof(c));
        }
        else if (!wcscmp(name, L"fill-opacity") || !wcscmp(name, L"opacity"))
        {
            float f = wcstod(v, NULL);

            hr = ID2D1SvgElement_SetAttributeValuePOD(e, name, D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT, &f, sizeof(f));
        }
        else if (!wcscmp(name, L"fill-rule") || !wcscmp(name, L"clip-rule"))
        {
            UINT32 m = wcstol(v, NULL, 10); /* D2D1_FILL_MODE: 0 alternate, 1 winding */

            hr = ID2D1SvgElement_SetAttributeValuePOD(e, name, D2D1_SVG_ATTRIBUTE_POD_TYPE_FILL_MODE, &m, sizeof(m));
        }
        else if (!wcscmp(name, L"preserveAspectRatio"))
        {
            UINT32 a[3] = {0, wcstol(v, NULL, 10), wcstol(v + 2, NULL, 10)}; /* defer, align, meet or slice */

            hr = ID2D1SvgElement_SetAttributeValuePOD(e, name, D2D1_SVG_ATTRIBUTE_POD_TYPE_PRESERVE_ASPECT_RATIO,
                    a, sizeof(a));
        }
        else if (!wcscmp(name, L"viewBox"))
        {
            D2D1_SVG_VIEWBOX vb;
            WCHAR *end;

            vb.x = wcstod(v, &end);
            vb.y = wcstod(end + 1, &end);
            vb.width = wcstod(end + 1, &end);
            vb.height = wcstod(end + 1, &end);
            hr = ID2D1SvgElement_SetAttributeValuePOD(e, name, D2D1_SVG_ATTRIBUTE_POD_TYPE_VIEWBOX, &vb, sizeof(vb));
        }
        else
        {
            ok(0, "unknown POD attribute %s\n", wine_dbgstr_w(name));
            return;
        }
    }
    else
        hr = ID2D1SvgElement_SetAttributeValueString(e, name, D2D1_SVG_ATTRIBUTE_STRING_TYPE_SVG, value);
    ok(hr == S_OK, "SetAttributeValue %s failed, hr %#lx.\n", wine_dbgstr_w(name), hr);
}

static void set_attrs(ID2D1SvgElement *e, const WCHAR *attrs)
{
    WCHAR name[64], value[512];
    const WCHAR *p = attrs;

    while (p && *p)
    {
        const WCHAR *eq = wcschr(p, '='), *bar = wcschr(p, '|');
        size_t vlen;

        if (!eq || (bar && bar < eq))
            return;
        if (!bar)
            bar = p + wcslen(p);
        memcpy(name, p, (eq - p) * sizeof(WCHAR));
        name[eq - p] = 0;
        vlen = bar - eq - 1;
        memcpy(value, eq + 1, vlen * sizeof(WCHAR));
        value[vlen] = 0;
        set_attr(e, name, value);
        p = *bar ? bar + 1 : bar;
    }
}

static ID2D1SvgDocument *build_document(const struct svg_case *c)
{
    ID2D1SvgElement *els[5] = {NULL}, *root;
    D2D1_SIZE_F vp = {c->vw, c->vh};
    ID2D1SvgDocument *doc;
    unsigned int i;
    HRESULT hr;

    hr = ID2D1DeviceContext5_CreateSvgDocument(ctx, NULL, vp, &doc);
    ok(hr == S_OK, "%s: CreateSvgDocument failed, hr %#lx.\n", c->name, hr);
    if (FAILED(hr))
        return NULL;
    ID2D1SvgDocument_GetRoot(doc, &root);
    set_attrs(root, c->root);
    for (i = 0; i < ARRAY_SIZE(c->elements) && c->elements[i].tag; ++i)
    {
        ID2D1SvgElement *parent = c->elements[i].parent < 0 ? root : els[c->elements[i].parent];

        hr = ID2D1SvgElement_CreateChild(parent, c->elements[i].tag, &els[i]);
        ok(hr == S_OK, "%s: CreateChild failed, hr %#lx.\n", c->name, hr);
        hr = ID2D1SvgElement_AppendChild(parent, els[i]);
        ok(hr == S_OK || hr == D2DERR_WRONG_STATE || hr == E_INVALIDARG, "%s: AppendChild hr %#lx.\n", c->name, hr);
        set_attrs(els[i], c->elements[i].attrs);
    }
    for (i = 0; i < ARRAY_SIZE(els); ++i)
        if (els[i])
            ID2D1SvgElement_Release(els[i]);
    ID2D1SvgElement_Release(root);
    return doc;
}

static ID2D1Bitmap1 *create_target(void)
{
    D2D1_BITMAP_PROPERTIES1 p = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_TARGET, NULL};
    D2D1_SIZE_U s = {TW, TH};
    ID2D1Bitmap1 *bitmap;
    HRESULT hr;

    hr = ID2D1DeviceContext_CreateBitmap(dc, s, NULL, 0, &p, &bitmap);
    ok(hr == S_OK, "CreateBitmap failed, hr %#lx.\n", hr);
    return SUCCEEDED(hr) ? bitmap : NULL;
}

/* reads the target into pixels[TW * TH] */
static BOOL read_target(ID2D1Bitmap1 *target, DWORD *pixels)
{
    D2D1_BITMAP_PROPERTIES1 p = {{DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED}, 96.0f, 96.0f,
            D2D1_BITMAP_OPTIONS_CANNOT_DRAW | D2D1_BITMAP_OPTIONS_CPU_READ, NULL};
    D2D1_SIZE_U s = {TW, TH};
    ID2D1Bitmap1 *staging;
    D2D1_MAPPED_RECT m;
    unsigned int y;
    HRESULT hr;

    hr = ID2D1DeviceContext_CreateBitmap(dc, s, NULL, 0, &p, &staging);
    ok(hr == S_OK, "CreateBitmap failed, hr %#lx.\n", hr);
    if (FAILED(hr))
        return FALSE;
    hr = ID2D1Bitmap1_CopyFromBitmap(staging, NULL, (ID2D1Bitmap *)target, NULL);
    ok(hr == S_OK, "CopyFromBitmap failed, hr %#lx.\n", hr);
    hr = ID2D1Bitmap1_Map(staging, D2D1_MAP_OPTIONS_READ, &m);
    ok(hr == S_OK, "Map failed, hr %#lx.\n", hr);
    if (SUCCEEDED(hr))
    {
        for (y = 0; y < TH; ++y)
            memcpy(&pixels[y * TW], m.bits + y * m.pitch, TW * sizeof(DWORD));
        ID2D1Bitmap1_Unmap(staging);
    }
    ID2D1Bitmap1_Release(staging);
    return SUCCEEDED(hr);
}

static BOOL render_direct(ID2D1SvgDocument *doc, DWORD *pixels)
{
    D2D1_COLOR_F clear = {0.0f, 0.0f, 0.0f, 0.0f};
    ID2D1Bitmap1 *target = create_target();
    HRESULT hr;
    BOOL ret;

    if (!target)
        return FALSE;
    ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)target);
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(dc, &clear);
    ID2D1DeviceContext5_DrawSvgDocument(ctx, doc);
    hr = ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx.\n", hr);
    ret = read_target(target, pixels);
    ID2D1DeviceContext_SetTarget(dc, NULL);
    ID2D1Bitmap1_Release(target);
    return ret;
}

/* the document is recorded into a command list, which is then drawn on the bitmap */
static BOOL render_list(ID2D1SvgDocument *doc, DWORD *pixels, const D2D1_POINT_2F *offset)
{
    D2D1_COLOR_F clear = {0.0f, 0.0f, 0.0f, 0.0f};
    ID2D1Bitmap1 *target = create_target();
    ID2D1CommandList *list;
    HRESULT hr;
    BOOL ret;

    if (!target)
        return FALSE;
    hr = ID2D1DeviceContext_CreateCommandList(dc, &list);
    ok(hr == S_OK, "CreateCommandList failed, hr %#lx.\n", hr);

    ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)list);
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext5_DrawSvgDocument(ctx, doc);
    hr = ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(hr == S_OK, "EndDraw on a command list target failed, hr %#lx.\n", hr);
    hr = ID2D1CommandList_Close(list);
    ok(hr == S_OK, "Close failed, hr %#lx.\n", hr);

    ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)target);
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(dc, &clear);
    ID2D1DeviceContext_DrawImage(dc, (ID2D1Image *)list, offset, NULL, D2D1_INTERPOLATION_MODE_LINEAR,
            D2D1_COMPOSITE_MODE_SOURCE_OVER);
    hr = ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx.\n", hr);
    ret = read_target(target, pixels);
    ID2D1DeviceContext_SetTarget(dc, NULL);
    ID2D1CommandList_Release(list);
    ID2D1Bitmap1_Release(target);
    return ret;
}

static void check_points(const char *name, const char *how, const DWORD *pixels, const struct point *points)
{
    unsigned int i;

    for (i = 0; i < 12 && (points[i].x || points[i].y || points[i].value); ++i)
        ok(near_pixel(pixels[points[i].y * TW + points[i].x], points[i].value, 2),
                "%s (%s): pixel (%d, %d) is %08lx, expected %08lx.\n", name, how, points[i].x, points[i].y,
                pixels[points[i].y * TW + points[i].x], points[i].value);
}

/* 0,0 is a valid point: an all-zero entry ends the list, so shift such a point to a nonzero value via NONE at (0,0)
 * being written as {0, 0, NONE}: handled by requiring the first entry to be explicit */
#define SQ_2_10 "M2 2 H10 V10 H2 Z"

static const struct svg_case cases[] =
{
    { "absolute square", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10 "|fill=red"} },
        { {5, 5, RED}, {2, 2, RED}, {9, 9, RED}, {0, 0, NONE}, {12, 12, NONE}, {10, 10, NONE}, {1, 5, NONE}, {5, 10, NONE} } },
    { "relative square (m h v z)", 16, 16, L"", { {-1, L"path", L"d=m2 2h8v8h-8z|fill=red"} },
        { {5, 5, RED}, {2, 2, RED}, {9, 9, RED}, {0, 0, NONE}, {12, 12, NONE}, {10, 10, NONE} } },
    { "implicit lineto after moveto, commas", 16, 16, L"", { {-1, L"path", L"d=M2,2 10,2 10,10 2,10z|fill=red"} },
        { {5, 5, RED}, {2, 2, RED}, {9, 9, RED}, {0, 0, NONE}, {12, 12, NONE}, {10, 10, NONE} } },
    { "number forms (leading dot, sign, exponent)", 16, 16, L"", { {-1, L"path", L"d=M.5.5H1e1V+1e1H5e-1z|fill=red"} },
        { {5, 5, RED}, {9, 9, RED}, {0, 12, NONE}, {12, 12, NONE}, {11, 5, NONE} } },
    { "quadratic bezier", 16, 16, L"", { {-1, L"path", L"d=M2 14Q8 -2 14 14Z|fill=red"} },
        { {8, 8, RED}, {8, 13, RED}, {8, 4, NONE}, {1, 8, NONE}, {14, 8, NONE}, {8, 15, NONE} } },
    { "cubic bezier", 16, 16, L"", { {-1, L"path", L"d=M2 14C2 2 14 2 14 14Z|fill=red"} },
        { {8, 8, RED}, {8, 13, RED}, {8, 3, NONE}, {1, 8, NONE}, {14, 8, NONE}, {8, 15, NONE} } },
    { "smooth cubic reflects the control point", 16, 16, L"", { {-1, L"path", L"d=M0 8C0 0 8 0 8 8S16 16 16 8Z|fill=red"} },
        { {4, 4, RED}, {12, 12, RED}, {4, 12, NONE}, {12, 4, NONE}, {8, 14, NONE} } },
    { "smooth quadratic reflects the control point", 16, 16, L"", { {-1, L"path", L"d=M0 8Q4 0 8 8T16 8Z|fill=red"} },
        { {4, 6, RED}, {12, 10, RED}, {12, 5, NONE}, {4, 10, NONE}, {8, 14, NONE} } },
    { "arc, sweep 1 passes over the top", 16, 16, L"", { {-1, L"path", L"d=M2 8A6 6 0 0 1 14 8|fill=red"} },
        { {8, 4, RED}, {8, 12, NONE}, {1, 8, NONE}, {14, 4, NONE} } },
    { "arc, sweep 0 passes below", 16, 16, L"", { {-1, L"path", L"d=M2 8A6 6 0 0 0 14 8|fill=red"} },
        { {8, 12, RED}, {8, 4, NONE}, {1, 8, NONE}, {14, 12, NONE} } },
    { "arc radii too small are scaled up", 16, 16, L"", { {-1, L"path", L"d=M2 8A1 1 0 0 1 14 8|fill=red"} },
        { {8, 4, RED}, {8, 12, NONE}, {4, 6, RED} } },
    { "two arcs make a circle (relative, flags without separators)", 16, 16, L"", { {-1, L"path", L"d=M2 8a6 6 0 1012 0a6 6 0 10-12 0z|fill=red"} },
        { {8, 8, RED}, {8, 3, RED}, {4, 4, RED}, {13, 8, RED}, {3, 3, NONE}, {14, 8, NONE}, {1, 1, NONE}, {8, 15, NONE} } },
    { "arc, large arc flag: the major segment above the chord", 16, 16, L"", { {-1, L"path", L"d=M3 8A6 6 0 1 1 13 8Z|fill=red"} },
        { {8, 4, RED}, {4, 2, RED}, {8, 7, RED}, {8, 10, NONE}, {1, 1, NONE} } },
    { "arc, small arc flag: the minor cap", 16, 16, L"", { {-1, L"path", L"d=M3 8A6 6 0 0 1 13 8Z|fill=red"} },
        { {8, 6, RED}, {8, 4, NONE}, {8, 10, NONE} } },
    { "horizontal and vertical lines", 16, 16, L"", { {-1, L"path", L"d=M2 2H10V10H2V2|fill=red"} },
        { {5, 5, RED}, {9, 9, RED}, {11, 5, NONE}, {5, 11, NONE} } },
    { "closepath then lineto starts at the subpath start", 16, 16, L"", { {-1, L"path", L"d=M2 2H8V8H2zH14V14H8|fill=red"} },
        { {5, 5, RED}, {12, 5, RED}, {13, 13, RED}, {4, 13, NONE}, {1, 5, NONE} } },
    { "error: rendering stops before the bad segment", 16, 16, L"", { {-1, L"path", L"d=M2 2H10V10H x|fill=red"} },
        { {9, 3, RED}, {3, 9, NONE}, {12, 12, NONE} } },
    { "error: a path has to start with a moveto", 16, 16, L"", { {-1, L"path", L"d=L2 2H10V10H2Z|fill=red"} },
        { {5, 5, NONE}, {9, 9, NONE} } },
    { "nonzero fill rule (default)", 16, 16, L"", { {-1, L"path", L"d=M1 1H15V15H1ZM4 4H12V12H4Z|fill=red"} },
        { {8, 8, RED}, {2, 8, RED} } },
    { "evenodd fill rule, string", 16, 16, L"", { {-1, L"path", L"d=M1 1H15V15H1ZM4 4H12V12H4Z|fill=red|fill-rule=evenodd"} },
        { {8, 8, NONE}, {2, 8, RED}, {13, 8, RED} } },
    { "evenodd fill rule, typed (D2D1_FILL_MODE_ALTERNATE)", 16, 16, L"", { {-1, L"path", L"d=M1 1H15V15H1ZM4 4H12V12H4Z|fill=pod:ffff0000|fill-rule=pod:0"} },
        { {8, 8, NONE}, {2, 8, RED} } },
    { "nonzero, typed (D2D1_FILL_MODE_WINDING)", 16, 16, L"", { {-1, L"path", L"d=M1 1H15V15H1ZM4 4H12V12H4Z|fill=pod:ffff0000|fill-rule=pod:1"} },
        { {8, 8, RED}, {2, 8, RED} } },
    { "nonzero: opposite winding cancels", 16, 16, L"", { {-1, L"path", L"d=M1 1H15V15H1ZM4 4V12H12V4Z|fill=red"} },
        { {8, 8, NONE}, {2, 8, RED} } },
    { "default fill is black", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10} },
        { {5, 5, BLACK}, {12, 12, NONE} } },
    { "fill none", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10 "|fill=none"} },
        { {5, 5, NONE}, {0, 0, NONE} } },
    { "typed colour, Word's form", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10 "|fill=pod:ff0000ff|fill-opacity=pod:1"} },
        { {5, 5, BLUE}, {12, 12, NONE} } },
    { "fill-opacity 0.5 (premultiplied)", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10 "|fill=pod:ffff0000|fill-opacity=pod:0.5"} },
        { {5, 5, 0x80800000}, {12, 12, NONE} } },
    { "fill-opacity 0.5, string", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10 "|fill=#0000ff|fill-opacity=0.5"} },
        { {5, 5, 0x80000080}, {12, 12, NONE} } },
    { "colour alpha times fill-opacity", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10 "|fill=pod:80ff0000|fill-opacity=pod:0.5"} },
        { {5, 5, 0x40400000}, {12, 12, NONE} } },
    { "named colour, #rgb and rgb()", 16, 16, L"", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=blue"}, {-1, L"path", L"d=M8 0H16V8H8Z|fill=#f00"}, {-1, L"path", L"d=M0 8H8V16H0Z|fill=rgb(255,0,0)"} },
        { {4, 4, BLUE}, {12, 4, RED}, {4, 12, RED}, {12, 12, NONE} } },
    { "fill inherited from the root element", 16, 16, L"fill=#0000ff", { {-1, L"path", L"d=" SQ_2_10} },
        { {5, 5, BLUE}, {12, 12, NONE} } },
    { "fill inherited through a group, child overrides", 16, 16, L"", { {-1, L"g", L"fill=#0000ff"}, {0, L"path", L"d=M0 0H8V8H0Z"}, {0, L"path", L"d=M8 8H16V16H8Z|fill=#ff0000"} },
        { {4, 4, BLUE}, {12, 12, RED}, {12, 4, NONE}, {4, 12, NONE} } },
    { "display none group is skipped", 16, 16, L"", { {-1, L"g", L"display=none"}, {0, L"path", L"d=" SQ_2_10} },
        { {5, 5, NONE} } },
    { "visibility hidden path is skipped", 16, 16, L"", { {-1, L"path", L"d=" SQ_2_10 "|visibility=hidden"} },
        { {5, 5, NONE} } },
    { "transform translate", 16, 16, L"", { {-1, L"path", L"d=M0 0H4V4H0Z|fill=red|transform=translate(6 6)"} },
        { {7, 7, RED}, {9, 9, RED}, {2, 2, NONE}, {11, 11, NONE} } },
    { "transform scale then translate (list order)", 16, 16, L"", { {-1, L"path", L"d=M0 0H2V2H0Z|fill=red|transform=translate(4 4) scale(2)"} },
        { {5, 5, RED}, {7, 7, RED}, {3, 3, NONE}, {9, 9, NONE} } },
    { "transform rotate 90 about a point", 16, 16, L"", { {-1, L"path", L"d=M0 0H8V4H0Z|fill=red|transform=rotate(90 8 8)"} },
        { {13, 4, RED}, {15, 7, RED}, {10, 4, NONE}, {13, 10, NONE}, {4, 4, NONE} } },
    { "rect element", 16, 16, L"", { {-1, L"rect", L"x=2|y=2|width=8|height=8|fill=red"} },
        { {5, 5, RED}, {12, 12, NONE}, {1, 1, NONE} } },
    { "circle element", 16, 16, L"", { {-1, L"circle", L"cx=8|cy=8|r=6|fill=red"} },
        { {8, 8, RED}, {4, 4, RED}, {3, 3, NONE}, {14, 8, NONE} } },
    { "ellipse element", 16, 16, L"", { {-1, L"ellipse", L"cx=8|cy=8|rx=7|ry=3|fill=red"} },
        { {8, 8, RED}, {13, 8, RED}, {8, 3, NONE}, {1, 1, NONE}, {8, 12, NONE} } },
    { "polygon element", 16, 16, L"", { {-1, L"polygon", L"points=2,2 14,2 14,14|fill=red"} },
        { {12, 4, RED}, {4, 12, NONE}, {2, 14, NONE} } },
    { "unsupported element is ignored", 16, 16, L"", { {-1, L"text", L"fill=red"}, {-1, L"path", L"d=" SQ_2_10 "|fill=red"} },
        { {5, 5, RED}, {12, 12, NONE} } },
    { "viewBox scales the content", 16, 16, L"viewBox=0 0 8 8", { {-1, L"path", L"d=M0 0H4V4H0Z|fill=red"} },
        { {3, 3, RED}, {7, 7, RED}, {9, 9, NONE}, {12, 12, NONE} } },
    { "viewBox with an origin offset", 16, 16, L"viewBox=4 4 8 8", { {-1, L"path", L"d=M4 4H8V8H4Z|fill=red"} },
        { {3, 3, RED}, {7, 7, RED}, {9, 9, NONE}, {12, 12, NONE} } },
    { "viewBox, typed", 16, 16, L"viewBox=pod:0,0,8,8", { {-1, L"path", L"d=M0 0H4V4H0Z|fill=red"} },
        { {3, 3, RED}, {7, 7, RED}, {9, 9, NONE} } },
    { "viewBox with commas", 16, 16, L"viewBox=0,0,8,8", { {-1, L"path", L"d=M0 0H4V4H0Z|fill=red"} },
        { {3, 3, RED}, {7, 7, RED}, {9, 9, NONE} } },
    { "viewBox of zero width disables the drawing", 16, 16, L"viewBox=0 0 0 8", { {-1, L"path", L"d=M0 0H4V4H0Z|fill=red"} },
        { {3, 3, NONE} } },
    { "meet xMidYMid (default) centres", 16, 8, L"viewBox=0 0 8 8", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {8, 4, RED}, {5, 4, RED}, {2, 4, NONE}, {13, 4, NONE} } },
    { "meet xMinYMid", 16, 8, L"viewBox=0 0 8 8|preserveAspectRatio=xMinYMid meet", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {2, 4, RED}, {6, 4, RED}, {10, 4, NONE}, {14, 4, NONE} } },
    { "meet xMaxYMid", 16, 8, L"viewBox=0 0 8 8|preserveAspectRatio=xMaxYMid meet", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {10, 4, RED}, {14, 4, RED}, {2, 4, NONE}, {6, 4, NONE} } },
    { "meet xMidYMin", 8, 16, L"viewBox=0 0 8 8|preserveAspectRatio=xMidYMin meet", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {4, 2, RED}, {4, 6, RED}, {4, 10, NONE}, {4, 14, NONE} } },
    { "meet xMidYMax", 8, 16, L"viewBox=0 0 8 8|preserveAspectRatio=xMidYMax meet", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {4, 10, RED}, {4, 14, RED}, {4, 2, NONE}, {4, 6, NONE} } },
    { "none stretches", 16, 8, L"viewBox=0 0 8 8|preserveAspectRatio=none", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {1, 4, RED}, {8, 1, RED}, {14, 6, RED} } },
    { "none stretches, typed (align 0, meet)", 16, 8, L"viewBox=pod:0,0,8,8|preserveAspectRatio=pod:0 0", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {1, 4, RED}, {14, 6, RED} } },
    { "meet xMinYMin, typed (align 1)", 16, 8, L"viewBox=pod:0,0,8,8|preserveAspectRatio=pod:1 0", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {2, 4, RED}, {10, 4, NONE} } },
    { "slice xMidYMid fills the viewport", 16, 8, L"viewBox=0 0 8 8|preserveAspectRatio=xMidYMid slice", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {1, 4, RED}, {8, 1, RED}, {14, 6, RED} } },
    { "slice xMinYMin: the content is 16x16 from the origin", 16, 8, L"viewBox=0 0 8 8|preserveAspectRatio=xMinYMin slice", { {-1, L"path", L"d=M0 0H4V4H0Z|fill=red"} },
        { {6, 6, RED}, {10, 4, NONE}, {4, 7, RED} } },
    { "slice, typed (align 5, slice)", 16, 8, L"viewBox=pod:0,0,8,8|preserveAspectRatio=pod:5 1", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {1, 4, RED}, {14, 6, RED} } },
    /* verify on oracle: the viewport clips the content (we clip) */
    { "slice clips to the viewport (verify on oracle)", 16, 8, L"viewBox=0 0 8 8|preserveAspectRatio=xMidYMid slice", { {-1, L"path", L"d=M0 0H8V8H0Z|fill=red"} },
        { {8, 12, NONE}, {8, 4, RED} } },
};

static void test_cases(void)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        const struct svg_case *c = &cases[i];
        DWORD direct[TW * TH], listed[TW * TH];
        ID2D1SvgDocument *doc = build_document(c);

        if (!doc)
            continue;
        if (render_direct(doc, direct))
            check_points(c->name, "bitmap target", direct, c->points);
        if (render_list(doc, listed, NULL))
        {
            check_points(c->name, "command list", listed, c->points);
            if (render_direct(doc, direct))
                ok(!memcmp(direct, listed, sizeof(direct)), "%s: command list result differs from the direct drawing.\n",
                        c->name);
        }
        ID2D1SvgDocument_Release(doc);
    }
}

/* the same document twice (drawing does not change the document or the context state) and the context state */
static void test_state(void)
{
    static const struct svg_case c = { "state", 16, 16, L"viewBox=0 0 8 8", { {-1, L"path", L"d=M0 0H4V4H0Z|fill=red"} }, {{0, 0, NONE}} };
    D2D1_MATRIX_3X2_F m = {{{1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f}}}, got;
    DWORD a[TW * TH], b[TW * TH];
    ID2D1SvgDocument *doc = build_document(&c);

    if (!doc)
        return;
    ok(render_direct(doc, a), "render failed\n");
    ok(render_direct(doc, b), "render failed\n");
    ok(!memcmp(a, b, sizeof(a)), "drawing twice gives different results\n");

    /* the transform of the context is applied to the document and restored afterwards */
    m._31 = 4.0f;
    m._32 = 2.0f;
    {
        D2D1_COLOR_F clear = {0.0f, 0.0f, 0.0f, 0.0f};
        ID2D1Bitmap1 *target = create_target();
        DWORD px[TW * TH];

        ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)target);
        ID2D1DeviceContext5_BeginDraw(ctx);
        ID2D1DeviceContext_Clear(dc, &clear);
        ID2D1DeviceContext_SetTransform(dc, &m);
        ID2D1DeviceContext5_DrawSvgDocument(ctx, doc);
        ID2D1DeviceContext_GetTransform(dc, &got);
        ok(got._11 == 1.0f && got._22 == 1.0f && got._31 == 4.0f && got._32 == 2.0f,
                "transform not restored: %.2f %.2f %.2f %.2f %.2f %.2f\n", got._11, got._12, got._21, got._22, got._31, got._32);
        m._31 = m._32 = 0.0f;
        ID2D1DeviceContext_SetTransform(dc, &m);
        ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
        ok(read_target(target, px), "read failed\n");
        /* 16x16 viewport, viewBox 8x8: the square covers 0..8, shifted by (4, 2): x 4..12, y 2..10 */
        ok(near_pixel(px[5 * TW + 6], RED, 2), "pixel (6, 5) is %08lx\n", px[5 * TW + 6]);
        ok(near_pixel(px[1 * TW + 6], NONE, 2), "pixel (6, 1) is %08lx\n", px[1 * TW + 6]);
        ok(near_pixel(px[5 * TW + 2], NONE, 2), "pixel (2, 5) is %08lx\n", px[5 * TW + 2]);
        ID2D1DeviceContext_SetTarget(dc, NULL);
        ID2D1Bitmap1_Release(target);
    }

    /* NULL document: nothing happens */
    ID2D1DeviceContext5_DrawSvgDocument(ctx, NULL);
    ID2D1SvgDocument_Release(doc);
}

/* a command list with plain operations, played back with offset, rectangle and the target transform */
static void test_command_list_playback(void)
{
    D2D1_COLOR_F clear = {0.0f, 0.0f, 0.0f, 0.0f}, red = {1.0f, 0.0f, 0.0f, 1.0f};
    D2D1_RECT_F rect = {2.0f, 2.0f, 6.0f, 6.0f};
    D2D1_POINT_2F offset = {5.0f, 3.0f};
    D2D1_MATRIX_3X2_F scale = {{{2.0f, 0.0f, 0.0f, 2.0f, 0.0f, 0.0f}}};
    ID2D1SolidColorBrush *brush;
    ID2D1CommandList *list;
    ID2D1Bitmap1 *target;
    ID2D1Geometry *geom;
    ID2D1Factory *factory;
    D2D1_RECT_F src = {2.0f, 2.0f, 4.0f, 4.0f};
    DWORD px[TW * TH];
    HRESULT hr;

    ID2D1Device_GetFactory(d2d, &factory);
    hr = ID2D1Factory_CreateRectangleGeometry(factory, &rect, (ID2D1RectangleGeometry **)&geom);
    ok(hr == S_OK, "CreateRectangleGeometry failed, hr %#lx.\n", hr);
    ID2D1Factory_Release(factory);

    hr = ID2D1DeviceContext_CreateSolidColorBrush(dc, &red, NULL, &brush);
    ok(hr == S_OK, "CreateSolidColorBrush failed, hr %#lx.\n", hr);
    hr = ID2D1DeviceContext_CreateCommandList(dc, &list);
    ok(hr == S_OK, "CreateCommandList failed, hr %#lx.\n", hr);

    /* Close before any drawing */
    hr = ID2D1CommandList_Close(list);
    ok(hr == D2DERR_WRONG_STATE || hr == S_OK, "Close of an unused list returned %#lx.\n", hr);
    ID2D1CommandList_Release(list);
    hr = ID2D1DeviceContext_CreateCommandList(dc, &list);
    ok(hr == S_OK, "CreateCommandList failed, hr %#lx.\n", hr);

    ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)list);
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext_FillGeometry(dc, geom, (ID2D1Brush *)brush, NULL);
    hr = ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(hr == S_OK, "EndDraw on a command list target returned %#lx.\n", hr);
    hr = ID2D1CommandList_Close(list);
    ok(hr == S_OK, "Close failed, hr %#lx.\n", hr);
    hr = ID2D1CommandList_Close(list);
    ok(hr == D2DERR_WRONG_STATE, "second Close returned %#lx.\n", hr); /* verify on oracle: the error code */

    target = create_target();
    ID2D1DeviceContext_SetTarget(dc, (ID2D1Image *)target);

    /* plain playback: the square 2..6 */
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(dc, &clear);
    ID2D1DeviceContext_DrawImage(dc, (ID2D1Image *)list, NULL, NULL, D2D1_INTERPOLATION_MODE_LINEAR,
            D2D1_COMPOSITE_MODE_SOURCE_OVER);
    hr = ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(hr == S_OK, "EndDraw failed, hr %#lx.\n", hr);
    ok(read_target(target, px), "read failed\n");
    ok(near_pixel(px[3 * TW + 3], RED, 2), "plain: pixel (3, 3) is %08lx\n", px[3 * TW + 3]);
    ok(near_pixel(px[8 * TW + 8], NONE, 2), "plain: pixel (8, 8) is %08lx\n", px[8 * TW + 8]);
    ok(near_pixel(px[3 * TW + 7], NONE, 2), "plain: pixel (7, 3) is %08lx\n", px[3 * TW + 7]);

    /* target offset (5, 3): the square is at 7..11 x 5..9 */
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(dc, &clear);
    ID2D1DeviceContext_DrawImage(dc, (ID2D1Image *)list, &offset, NULL, D2D1_INTERPOLATION_MODE_LINEAR,
            D2D1_COMPOSITE_MODE_SOURCE_OVER);
    ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(read_target(target, px), "read failed\n");
    ok(near_pixel(px[6 * TW + 8], RED, 2), "offset: pixel (8, 6) is %08lx\n", px[6 * TW + 8]);
    ok(near_pixel(px[3 * TW + 3], NONE, 2), "offset: pixel (3, 3) is %08lx\n", px[3 * TW + 3]);

    /* the target transform applies to the list: scale 2 gives 4..12 */
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(dc, &clear);
    ID2D1DeviceContext_SetTransform(dc, &scale);
    ID2D1DeviceContext_DrawImage(dc, (ID2D1Image *)list, NULL, NULL, D2D1_INTERPOLATION_MODE_LINEAR,
            D2D1_COMPOSITE_MODE_SOURCE_OVER);
    scale._11 = scale._22 = 1.0f;
    ID2D1DeviceContext_SetTransform(dc, &scale);
    ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(read_target(target, px), "read failed\n");
    ok(near_pixel(px[10 * TW + 10], RED, 2), "scaled: pixel (10, 10) is %08lx\n", px[10 * TW + 10]);
    ok(near_pixel(px[3 * TW + 3], NONE, 2), "scaled: pixel (3, 3) is %08lx\n", px[3 * TW + 3]);

    /* image rectangle 2,2,4,4 placed at the origin: only the corner 2..4 of the square, at 0..2 */
    ID2D1DeviceContext5_BeginDraw(ctx);
    ID2D1DeviceContext_Clear(dc, &clear);
    {
        D2D1_POINT_2F origin = {0.0f, 0.0f};

        ID2D1DeviceContext_DrawImage(dc, (ID2D1Image *)list, &origin, &src, D2D1_INTERPOLATION_MODE_LINEAR,
                D2D1_COMPOSITE_MODE_SOURCE_OVER);
    }
    ID2D1DeviceContext_EndDraw(dc, NULL, NULL);
    ok(read_target(target, px), "read failed\n");
    ok(near_pixel(px[1 * TW + 1], RED, 2), "rect: pixel (1, 1) is %08lx\n", px[1 * TW + 1]);
    ok(near_pixel(px[3 * TW + 3], NONE, 2), "rect: pixel (3, 3) is %08lx\n", px[3 * TW + 3]);

    ID2D1DeviceContext_SetTarget(dc, NULL);
    ID2D1Bitmap1_Release(target);
    ID2D1CommandList_Release(list);
    ID2D1SolidColorBrush_Release(brush);
    ID2D1Geometry_Release(geom);
}

START_TEST(d2d1_svgdraw)
{
    static const D3D_DRIVER_TYPE types[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    ID2D1DeviceContext *context = NULL;
    IDXGIDevice *dxgi_device;
    unsigned int i;
    HRESULT hr = E_FAIL;

    for (i = 0; i < 2 && FAILED(hr); ++i)
        hr = D3D11CreateDevice(NULL, types[i], NULL, D3D11_CREATE_DEVICE_BGRA_SUPPORT, NULL, 0,
                D3D11_SDK_VERSION, &d3d, NULL, NULL);
    if (FAILED(hr))
    {
        skip("Cannot create a D3D11 device, hr %#lx\n", hr);
        return;
    }
    hr = ID3D11Device_QueryInterface(d3d, &IID_IDXGIDevice, (void **)&dxgi_device);
    ok(hr == S_OK, "QueryInterface failed, hr %#lx\n", hr);
    hr = D2D1CreateDevice(dxgi_device, NULL, &d2d);
    IDXGIDevice_Release(dxgi_device);
    if (SUCCEEDED(hr))
        hr = ID2D1Device_CreateDeviceContext(d2d, D2D1_DEVICE_CONTEXT_OPTIONS_NONE, &context);
    if (SUCCEEDED(hr))
    {
        hr = ID2D1DeviceContext_QueryInterface(context, &IID_ID2D1DeviceContext5, (void **)&ctx);
        ID2D1DeviceContext_Release(context);
    }
    if (FAILED(hr))
    {
        skip("No Direct2D device context with SVG support, hr %#lx\n", hr);
        return;
    }

    dc = (ID2D1DeviceContext *)ctx;
    test_cases();
    test_state();
    test_command_list_playback();

    ID2D1DeviceContext5_Release(ctx);
    ID2D1Device_Release(d2d);
    ID3D11Device_Release(d3d);
}
