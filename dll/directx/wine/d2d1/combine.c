/*
 * ID2D1Geometry::CombineWithGeometry
 *
 * Own implementation (not derived from Wine, which does not implement it).
 * The geometry boolean operations are in combine_core.c; this file turns the
 * geometries into polygons (curves flattened within the tolerance) and writes
 * the result to the simplified geometry sink as closed polygonal figures.
 */

#include "d2d1_private.h"
#include "combine_core.h"
#include <float.h>
#include <math.h>

WINE_DEFAULT_DEBUG_CHANNEL(d2d);

#define D2D_COMBINE_MAX_POINTS  (1u << 22)

struct d2d_poly_collector
{
    ID2D1SimplifiedGeometrySink ID2D1SimplifiedGeometrySink_iface;

    float *xy;
    size_t point_count, point_size;
    size_t *starts;
    size_t contour_count, starts_size;

    BOOL hollow, failed;
    D2D1_FILL_MODE fill_mode;
};

static inline struct d2d_poly_collector *impl_from_ID2D1SimplifiedGeometrySink(ID2D1SimplifiedGeometrySink *iface)
{
    return CONTAINING_RECORD(iface, struct d2d_poly_collector, ID2D1SimplifiedGeometrySink_iface);
}

static void d2d_poly_collector_add_point(struct d2d_poly_collector *c, float x, float y)
{
    if (c->failed || c->hollow)
        return;
    if (c->point_count >= D2D_COMBINE_MAX_POINTS)
    {
        c->failed = TRUE;
        return;
    }
    if (!d2d_array_reserve((void **)&c->xy, &c->point_size, c->point_count + 1, 2 * sizeof(float)))
    {
        c->failed = TRUE;
        return;
    }
    c->xy[2 * c->point_count] = x;
    c->xy[2 * c->point_count + 1] = y;
    ++c->point_count;
}

static HRESULT STDMETHODCALLTYPE d2d_poly_collector_QueryInterface(ID2D1SimplifiedGeometrySink *iface,
        REFIID iid, void **out)
{
    if (IsEqualGUID(iid, &IID_ID2D1SimplifiedGeometrySink) || IsEqualGUID(iid, &IID_IUnknown))
    {
        *out = iface;
        return S_OK;
    }
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE d2d_poly_collector_AddRef(ID2D1SimplifiedGeometrySink *iface)
{
    return 2;
}

static ULONG STDMETHODCALLTYPE d2d_poly_collector_Release(ID2D1SimplifiedGeometrySink *iface)
{
    return 1;
}

static void STDMETHODCALLTYPE d2d_poly_collector_SetFillMode(ID2D1SimplifiedGeometrySink *iface,
        D2D1_FILL_MODE fill_mode)
{
    impl_from_ID2D1SimplifiedGeometrySink(iface)->fill_mode = fill_mode;
}

static void STDMETHODCALLTYPE d2d_poly_collector_SetSegmentFlags(ID2D1SimplifiedGeometrySink *iface,
        D2D1_PATH_SEGMENT vertex_flags)
{
}

static void STDMETHODCALLTYPE d2d_poly_collector_BeginFigure(ID2D1SimplifiedGeometrySink *iface,
        D2D1_POINT_2F start_point, D2D1_FIGURE_BEGIN figure_begin)
{
    struct d2d_poly_collector *c = impl_from_ID2D1SimplifiedGeometrySink(iface);

    c->hollow = figure_begin == D2D1_FIGURE_BEGIN_HOLLOW;
    if (c->failed || c->hollow)
        return;
    if (!d2d_array_reserve((void **)&c->starts, &c->starts_size, c->contour_count + 1, sizeof(*c->starts)))
    {
        c->failed = TRUE;
        return;
    }
    c->starts[c->contour_count++] = c->point_count;
    d2d_poly_collector_add_point(c, start_point.x, start_point.y);
}

static void STDMETHODCALLTYPE d2d_poly_collector_AddLines(ID2D1SimplifiedGeometrySink *iface,
        const D2D1_POINT_2F *points, UINT32 count)
{
    struct d2d_poly_collector *c = impl_from_ID2D1SimplifiedGeometrySink(iface);
    UINT32 i;

    for (i = 0; i < count; ++i)
        d2d_poly_collector_add_point(c, points[i].x, points[i].y);
}

static void STDMETHODCALLTYPE d2d_poly_collector_AddBeziers(ID2D1SimplifiedGeometrySink *iface,
        const D2D1_BEZIER_SEGMENT *beziers, UINT32 count)
{
    struct d2d_poly_collector *c = impl_from_ID2D1SimplifiedGeometrySink(iface);
    UINT32 i;

    /* Only reached for a geometry that ignores D2D1_GEOMETRY_SIMPLIFICATION_OPTION_LINES. */
    for (i = 0; i < count; ++i)
        d2d_poly_collector_add_point(c, beziers[i].point3.x, beziers[i].point3.y);
}

static void STDMETHODCALLTYPE d2d_poly_collector_EndFigure(ID2D1SimplifiedGeometrySink *iface,
        D2D1_FIGURE_END figure_end)
{
    impl_from_ID2D1SimplifiedGeometrySink(iface)->hollow = FALSE;
}

static HRESULT STDMETHODCALLTYPE d2d_poly_collector_Close(ID2D1SimplifiedGeometrySink *iface)
{
    return S_OK;
}

static const ID2D1SimplifiedGeometrySinkVtbl d2d_poly_collector_vtbl =
{
    d2d_poly_collector_QueryInterface,
    d2d_poly_collector_AddRef,
    d2d_poly_collector_Release,
    d2d_poly_collector_SetFillMode,
    d2d_poly_collector_SetSegmentFlags,
    d2d_poly_collector_BeginFigure,
    d2d_poly_collector_AddLines,
    d2d_poly_collector_AddBeziers,
    d2d_poly_collector_EndFigure,
    d2d_poly_collector_Close,
};

static void d2d_poly_collector_init(struct d2d_poly_collector *c)
{
    memset(c, 0, sizeof(*c));
    c->ID2D1SimplifiedGeometrySink_iface.lpVtbl = &d2d_poly_collector_vtbl;
    c->fill_mode = D2D1_FILL_MODE_WINDING;
}

static void d2d_poly_collector_cleanup(struct d2d_poly_collector *c)
{
    free(c->xy);
    free(c->starts);
}

static void d2d_poly_collector_transform_point(const D2D1_MATRIX_3X2_F *m, float *x, float *y)
{
    D2D1_POINT_2F p;

    if (!m)
        return;
    d2d_point_transform(&p, m, *x, *y);
    *x = p.x;
    *y = p.y;
}

static void d2d_poly_collector_begin(struct d2d_poly_collector *c)
{
    if (c->failed)
        return;
    if (!d2d_array_reserve((void **)&c->starts, &c->starts_size, c->contour_count + 1, sizeof(*c->starts)))
    {
        c->failed = TRUE;
        return;
    }
    c->starts[c->contour_count++] = c->point_count;
}

/* Number of segments of a full ellipse such that a chord deviates by at most the tolerance. */
static unsigned int d2d_combine_arc_segments(float rx, float ry, const D2D1_MATRIX_3X2_F *m, float tolerance)
{
    float sx = 1.0f, sy = 1.0f, r, n, ratio;

    if (m)
    {
        sx = sqrtf(m->_11 * m->_11 + m->_12 * m->_12);
        sy = sqrtf(m->_21 * m->_21 + m->_22 * m->_22);
    }
    /* A polygon inscribed in the curve loses area; a quarter of the tolerance keeps that small. */
    tolerance /= 4.0f;
    r = max(fabsf(rx) * sx, fabsf(ry) * sy);
    if (!(r > tolerance))
        return 8;
    ratio = 1.0f - tolerance / r;
    n = (float)M_PI / acosf(ratio);
    if (!(n < 4096.0f))
        n = 4096.0f;
    return ((unsigned int)ceilf(max(n, 8.0f)) + 3) & ~3u;
}

static void d2d_combine_add_arc(struct d2d_poly_collector *c, const D2D1_MATRIX_3X2_F *m,
        float cx, float cy, float rx, float ry, float a0, float a1, unsigned int segments)
{
    unsigned int i;

    for (i = 0; i <= segments; ++i)
    {
        float a = a0 + (a1 - a0) * i / segments;
        float x = cx + rx * cosf(a), y = cy + ry * sinf(a);

        d2d_poly_collector_transform_point(m, &x, &y);
        d2d_poly_collector_add_point(c, x, y);
    }
}

static HRESULT d2d_combine_collect(ID2D1Geometry *geometry, const D2D1_MATRIX_3X2_F *m, float tolerance,
        struct d2d_poly_collector *c, unsigned int depth)
{
    enum d2d_geometry_kind kind = d2d_geometry_get_kind(geometry);
    struct d2d_geometry *impl;
    HRESULT hr = S_OK;
    unsigned int i;

    if (depth > 64)
        return E_FAIL;

    switch (kind)
    {
        case D2D_GEOMETRY_KIND_RECTANGLE:
        {
            const D2D1_RECT_F *r;
            float x[4], y[4];

            impl = unsafe_impl_from_ID2D1Geometry(geometry);
            r = &impl->u.rectangle.rect;
            x[0] = r->left;  y[0] = r->top;
            x[1] = r->right; y[1] = r->top;
            x[2] = r->right; y[2] = r->bottom;
            x[3] = r->left;  y[3] = r->bottom;
            d2d_poly_collector_begin(c);
            for (i = 0; i < 4; ++i)
            {
                d2d_poly_collector_transform_point(m, &x[i], &y[i]);
                d2d_poly_collector_add_point(c, x[i], y[i]);
            }
            c->fill_mode = D2D1_FILL_MODE_WINDING;
            break;
        }

        case D2D_GEOMETRY_KIND_ELLIPSE:
        {
            const D2D1_ELLIPSE *e;
            unsigned int n;

            impl = unsafe_impl_from_ID2D1Geometry(geometry);
            e = &impl->u.ellipse.ellipse;
            n = d2d_combine_arc_segments(e->radiusX, e->radiusY, m, tolerance);
            d2d_poly_collector_begin(c);
            d2d_combine_add_arc(c, m, e->point.x, e->point.y, e->radiusX, e->radiusY,
                    0.0f, 2.0f * (float)M_PI, n);
            /* Drop the duplicate closing point. */
            if (c->point_count && !c->failed && !c->hollow)
                --c->point_count;
            c->fill_mode = D2D1_FILL_MODE_WINDING;
            break;
        }

        case D2D_GEOMETRY_KIND_ROUNDED_RECTANGLE:
        {
            const D2D1_ROUNDED_RECT *r;
            float rx, ry, hw, hh;
            unsigned int n;

            impl = unsafe_impl_from_ID2D1Geometry(geometry);
            r = &impl->u.rounded_rectangle.rounded_rect;
            hw = fabsf(r->rect.right - r->rect.left) / 2.0f;
            hh = fabsf(r->rect.bottom - r->rect.top) / 2.0f;
            rx = min(fabsf(r->radiusX), hw);
            ry = min(fabsf(r->radiusY), hh);
            n = d2d_combine_arc_segments(rx, ry, m, tolerance) / 4;
            d2d_poly_collector_begin(c);
            d2d_combine_add_arc(c, m, r->rect.right - rx, r->rect.top + ry, rx, ry,
                    -(float)M_PI / 2.0f, 0.0f, n);
            d2d_combine_add_arc(c, m, r->rect.right - rx, r->rect.bottom - ry, rx, ry,
                    0.0f, (float)M_PI / 2.0f, n);
            d2d_combine_add_arc(c, m, r->rect.left + rx, r->rect.bottom - ry, rx, ry,
                    (float)M_PI / 2.0f, (float)M_PI, n);
            d2d_combine_add_arc(c, m, r->rect.left + rx, r->rect.top + ry, rx, ry,
                    (float)M_PI, 3.0f * (float)M_PI / 2.0f, n);
            c->fill_mode = D2D1_FILL_MODE_WINDING;
            break;
        }

        case D2D_GEOMETRY_KIND_PATH:
            /* Flattens the curves, applies the matrix, reports the fill mode and hollow figures. */
            hr = ID2D1Geometry_Simplify(geometry, D2D1_GEOMETRY_SIMPLIFICATION_OPTION_LINES, m, tolerance,
                    &c->ID2D1SimplifiedGeometrySink_iface);
            break;

        case D2D_GEOMETRY_KIND_TRANSFORMED:
        {
            D2D1_MATRIX_3X2_F g;

            impl = unsafe_impl_from_ID2D1Geometry(geometry);
            g = impl->u.transformed.transform;
            if (m)
                d2d_matrix_multiply(&g, m);
            hr = d2d_combine_collect(impl->u.transformed.src_geometry, &g, tolerance, c, depth + 1);
            break;
        }

        case D2D_GEOMETRY_KIND_GROUP:
        {
            D2D1_FILL_MODE fill_mode;

            impl = unsafe_impl_from_ID2D1Geometry(geometry);
            fill_mode = impl->u.group.fill_mode;
            for (i = 0; i < impl->u.group.geometry_count && SUCCEEDED(hr); ++i)
                hr = d2d_combine_collect(impl->u.group.src_geometries[i], m, tolerance, c, depth + 1);
            c->fill_mode = fill_mode;
            break;
        }

        default:
            hr = ID2D1Geometry_Simplify(geometry, D2D1_GEOMETRY_SIMPLIFICATION_OPTION_LINES, m, tolerance,
                    &c->ID2D1SimplifiedGeometrySink_iface);
            break;
    }

    if (SUCCEEDED(hr) && c->failed)
        hr = E_OUTOFMEMORY;
    return hr;
}

HRESULT d2d_geometry_combine(ID2D1Geometry *geometry1, ID2D1Geometry *geometry2, D2D1_COMBINE_MODE mode,
        const D2D1_MATRIX_3X2_F *transform, float tolerance, ID2D1SimplifiedGeometrySink *sink)
{
    struct d2d_poly_collector ca, cb;
    struct d2d_cc_input ia, ib;
    struct d2d_cc_output out;
    HRESULT hr;
    size_t i;

    if (!geometry1 || !geometry2 || !sink || (unsigned int)mode > D2D1_COMBINE_MODE_EXCLUDE)
        return E_INVALIDARG;

    if (!(tolerance > 0.0f))
        tolerance = D2D1_DEFAULT_FLATTENING_TOLERANCE;

    d2d_poly_collector_init(&ca);
    d2d_poly_collector_init(&cb);

    if (FAILED(hr = d2d_combine_collect(geometry1, NULL, tolerance, &ca, 0))
            || FAILED(hr = d2d_combine_collect(geometry2, transform, tolerance, &cb, 0)))
        goto done;

    ia.xy = ca.xy;
    ia.point_count = ca.point_count;
    ia.contour_starts = ca.starts;
    ia.contour_count = ca.contour_count;
    ia.evenodd = ca.fill_mode == D2D1_FILL_MODE_ALTERNATE;
    ib.xy = cb.xy;
    ib.point_count = cb.point_count;
    ib.contour_starts = cb.starts;
    ib.contour_count = cb.contour_count;
    ib.evenodd = cb.fill_mode == D2D1_FILL_MODE_ALTERNATE;

    if (d2d_cc_combine(&ia, &ib, mode, &out))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }

    ID2D1SimplifiedGeometrySink_SetFillMode(sink, D2D1_FILL_MODE_WINDING);
    for (i = 0; i < out.contour_count; ++i)
    {
        size_t first = out.contour_starts[i], count = out.contour_starts[i + 1] - first;
        D2D1_POINT_2F *points = (D2D1_POINT_2F *)&out.xy[2 * first];

        ID2D1SimplifiedGeometrySink_BeginFigure(sink, points[0], D2D1_FIGURE_BEGIN_FILLED);
        ID2D1SimplifiedGeometrySink_AddLines(sink, &points[1], count - 1);
        ID2D1SimplifiedGeometrySink_EndFigure(sink, D2D1_FIGURE_END_CLOSED);
    }
    d2d_cc_output_free(&out);
    hr = S_OK;

done:
    d2d_poly_collector_cleanup(&ca);
    d2d_poly_collector_cleanup(&cb);
    return hr;
}
