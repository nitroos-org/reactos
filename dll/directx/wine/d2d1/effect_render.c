/*
 * Direct2D built-in effect rendering.
 *
 * The effect graph under an ID2D1Image given to DrawImage() is evaluated on the CPU, demand driven for the region
 * that is drawn, into a premultiplied BGRA bitmap, which is then drawn through the existing (D3D backed) bitmap
 * path. Effect semantics (properties, defaults, formulas) follow the public Direct2D effect documentation.
 *
 * Implemented: Flood, Composite, Blend, 2D affine transform, 3D transform, Crop, Scale, Color matrix, Gaussian blur,
 * Shadow, Atlas, Tile. Other built-in effects (and custom effects) draw nothing, as before.
 *
 * Copyright 2026 Tomas Srnka
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "d2d1_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d2d);

#define FX_INF 0x10000000
#define FX_MAX_PIXELS (8u * 1024 * 1024)
#define FX_MAX_DEPTH 64

struct fx_rect
{
    int l, t, r, b;
};

struct fx_image
{
    struct fx_rect rc;
    float *px; /* premultiplied RGBA */
};

struct fx_ctx
{
    struct d2d_device_context *dc;
    float sx, sy; /* pixels per DIP */
    unsigned int depth;
    BOOL failed;
};

static inline int fx_clampi(double v)
{
    if (v >= FX_INF) return FX_INF;
    if (v <= -FX_INF) return -FX_INF;
    return (int)v;
}

static inline BOOL fx_empty(const struct fx_rect *rc)
{
    return rc->r <= rc->l || rc->b <= rc->t;
}

static struct fx_rect fx_intersect(struct fx_rect a, struct fx_rect b)
{
    struct fx_rect rc;

    rc.l = max(a.l, b.l);
    rc.t = max(a.t, b.t);
    rc.r = min(a.r, b.r);
    rc.b = min(a.b, b.b);
    if (fx_empty(&rc))
        rc.l = rc.t = rc.r = rc.b = 0;
    return rc;
}

static struct fx_rect fx_union(struct fx_rect a, struct fx_rect b)
{
    if (fx_empty(&a)) return b;
    if (fx_empty(&b)) return a;
    a.l = min(a.l, b.l);
    a.t = min(a.t, b.t);
    a.r = max(a.r, b.r);
    a.b = max(a.b, b.b);
    return a;
}

static struct fx_rect fx_expand(struct fx_rect rc, int dx, int dy)
{
    if (fx_empty(&rc)) return rc;
    rc.l = fx_clampi((double)rc.l - dx);
    rc.t = fx_clampi((double)rc.t - dy);
    rc.r = fx_clampi((double)rc.r + dx);
    rc.b = fx_clampi((double)rc.b + dy);
    return rc;
}

static struct fx_rect fx_rect_from_dips(const struct fx_ctx *ctx, const float *v)
{
    struct fx_rect rc;

    rc.l = fx_clampi(floor((double)v[0] * ctx->sx + 1e-4));
    rc.t = fx_clampi(floor((double)v[1] * ctx->sy + 1e-4));
    rc.r = fx_clampi(ceil((double)v[2] * ctx->sx - 1e-4));
    rc.b = fx_clampi(ceil((double)v[3] * ctx->sy - 1e-4));
    if (fx_empty(&rc))
        rc.l = rc.t = rc.r = rc.b = 0;
    return rc;
}

static void fx_image_free(struct fx_image *img)
{
    if (!img) return;
    free(img->px);
    free(img);
}

static struct fx_image *fx_image_alloc(struct d2d_device_context *dc, struct fx_rect rc)
{
    struct fx_image *img;
    unsigned long long n;

    if (fx_empty(&rc))
        rc.l = rc.t = rc.r = rc.b = 0;
    n = (unsigned long long)(rc.r - rc.l) * (rc.b - rc.t);
    if (n > FX_MAX_PIXELS)
    {
        WARN("Effect region %dx%d is too large.\n", rc.r - rc.l, rc.b - rc.t);
        return NULL;
    }
    if (!(img = calloc(1, sizeof(*img))))
        return NULL;
    img->rc = rc;
    if (n && !(img->px = calloc((size_t)n, 4 * sizeof(float))))
    {
        free(img);
        return NULL;
    }
    return img;
}

static inline float *fx_px(const struct fx_image *img, int x, int y)
{
    if (x < img->rc.l || x >= img->rc.r || y < img->rc.t || y >= img->rc.b)
        return NULL;
    return &img->px[((size_t)(y - img->rc.t) * (img->rc.r - img->rc.l) + (x - img->rc.l)) * 4];
}

static inline float fx_sat(float v)
{
    return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
}

/* Properties of a built-in effect. */
static BOOL fx_prop(const struct d2d_effect *effect, UINT32 index, void *value, UINT32 size)
{
    return d2d_effect_get_builtin_value(effect, index, value, size);
}

static float fx_prop_float(const struct d2d_effect *effect, UINT32 index, float def)
{
    float v;

    return fx_prop(effect, index, &v, sizeof(v)) ? v : def;
}

static UINT32 fx_prop_uint(const struct d2d_effect *effect, UINT32 index, UINT32 def)
{
    UINT32 v;

    return fx_prop(effect, index, &v, sizeof(v)) ? v : def;
}

/* Reads the pixels of a bitmap. */
static struct fx_image *fx_read_bitmap(struct fx_ctx *ctx, ID2D1Bitmap *iface)
{
    struct d2d_bitmap *bitmap = unsafe_impl_from_ID2D1Bitmap(iface);
    D3D11_TEXTURE2D_DESC desc;
    D3D11_MAPPED_SUBRESOURCE map;
    ID3D11DeviceContext *d3d_context;
    ID3D11Texture2D *src, *staging;
    struct fx_image *img;
    struct fx_rect rc;
    unsigned int x, y;
    HRESULT hr;

    if (!bitmap || FAILED(ID3D11Resource_QueryInterface(bitmap->resource, &IID_ID3D11Texture2D, (void **)&src)))
        return NULL;

    ID3D11Texture2D_GetDesc(src, &desc);
    rc.l = rc.t = 0;
    rc.r = bitmap->pixel_size.width;
    rc.b = bitmap->pixel_size.height;
    if (desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM && desc.Format != DXGI_FORMAT_R8G8B8A8_UNORM
            && desc.Format != DXGI_FORMAT_A8_UNORM)
    {
        FIXME("Unsupported bitmap format %#x as an effect input.\n", desc.Format);
        ID3D11Texture2D_Release(src);
        return fx_image_alloc(ctx->dc, rc);
    }

    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.MiscFlags = 0;
    if (FAILED(hr = ID3D11Device1_CreateTexture2D(ctx->dc->d3d_device, &desc, NULL, &staging)))
    {
        WARN("Failed to create a staging texture, hr %#lx.\n", hr);
        ID3D11Texture2D_Release(src);
        return NULL;
    }

    ID3D11Device1_GetImmediateContext(ctx->dc->d3d_device, &d3d_context);
    ID3D11DeviceContext_CopyResource(d3d_context, (ID3D11Resource *)staging, (ID3D11Resource *)src);
    ID3D11Texture2D_Release(src);

    if (FAILED(hr = ID3D11DeviceContext_Map(d3d_context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &map)))
    {
        WARN("Failed to map the staging texture, hr %#lx.\n", hr);
        ID3D11DeviceContext_Release(d3d_context);
        ID3D11Texture2D_Release(staging);
        return NULL;
    }

    if ((img = fx_image_alloc(ctx->dc, rc)))
    {
        for (y = 0; y < desc.Height; ++y)
        {
            const BYTE *row = (const BYTE *)map.pData + (size_t)y * map.RowPitch;
            float *dst = fx_px(img, 0, y);

            for (x = 0; x < desc.Width; ++x, dst += 4)
            {
                float r, g, b, a;

                if (desc.Format == DXGI_FORMAT_A8_UNORM)
                {
                    r = g = b = 0.0f;
                    a = row[x] / 255.0f;
                }
                else
                {
                    const BYTE *p = row + x * 4;

                    if (desc.Format == DXGI_FORMAT_B8G8R8A8_UNORM)
                    {
                        b = p[0] / 255.0f; g = p[1] / 255.0f; r = p[2] / 255.0f;
                    }
                    else
                    {
                        r = p[0] / 255.0f; g = p[1] / 255.0f; b = p[2] / 255.0f;
                    }
                    a = p[3] / 255.0f;
                    if (bitmap->format.alphaMode == D2D1_ALPHA_MODE_IGNORE)
                    {
                        a = 1.0f;
                    }
                    else if (bitmap->format.alphaMode == D2D1_ALPHA_MODE_STRAIGHT)
                    {
                        r *= a; g *= a; b *= a;
                    }
                }
                dst[0] = r; dst[1] = g; dst[2] = b; dst[3] = a;
            }
        }
    }

    ID3D11DeviceContext_Unmap(d3d_context, (ID3D11Resource *)staging, 0);
    ID3D11DeviceContext_Release(d3d_context);
    ID3D11Texture2D_Release(staging);
    return img;
}

static struct fx_rect fx_bounds(struct fx_ctx *ctx, ID2D1Image *image);
static struct fx_image *fx_eval(struct fx_ctx *ctx, ID2D1Image *image, struct fx_rect roi);

enum fx_kind
{
    FX_NONE,
    FX_FLOOD,
    FX_COMPOSITE,
    FX_BLEND,
    FX_AFFINE,
    FX_3DTRANSFORM,
    FX_CROP,
    FX_SCALE,
    FX_COLORMATRIX,
    FX_BLUR,
    FX_SHADOW,
    FX_ATLAS,
    FX_TILE,
};

static enum fx_kind fx_effect_kind(const struct d2d_effect *effect)
{
    static const struct { const CLSID *id; enum fx_kind kind; } kinds[] =
    {
        { &CLSID_D2D1Flood, FX_FLOOD },
        { &CLSID_D2D1Composite, FX_COMPOSITE },
        { &CLSID_D2D1Blend, FX_BLEND },
        { &CLSID_D2D12DAffineTransform, FX_AFFINE },
        { &CLSID_D2D13DTransform, FX_3DTRANSFORM },
        { &CLSID_D2D1Crop, FX_CROP },
        { &CLSID_D2D1Scale, FX_SCALE },
        { &CLSID_D2D1ColorMatrix, FX_COLORMATRIX },
        { &CLSID_D2D1GaussianBlur, FX_BLUR },
        { &CLSID_D2D1Shadow, FX_SHADOW },
        { &CLSID_D2D1Atlas, FX_ATLAS },
        { &CLSID_D2D1Tile, FX_TILE },
    };
    unsigned int i;

    if (!effect->builtin)
        return FX_NONE;
    for (i = 0; i < ARRAY_SIZE(kinds); ++i)
    {
        if (IsEqualGUID(&effect->id, kinds[i].id))
            return kinds[i].kind;
    }
    return FX_NONE;
}

static ID2D1Image *fx_input(const struct d2d_effect *effect, unsigned int index)
{
    return index < effect->input_count ? effect->inputs[index] : NULL;
}

/* A 3x3 matrix for points (x, y, 1) as rows, m[row][col], x' = x*m00 + y*m10 + m20. */
struct fx_matrix
{
    double m[3][3];
};

static BOOL fx_matrix_invert(const struct fx_matrix *in, struct fx_matrix *out)
{
    const double (*a)[3] = in->m;
    double det, c00, c01, c02;

    c00 = a[1][1] * a[2][2] - a[1][2] * a[2][1];
    c01 = a[1][2] * a[2][0] - a[1][0] * a[2][2];
    c02 = a[1][0] * a[2][1] - a[1][1] * a[2][0];
    det = a[0][0] * c00 + a[0][1] * c01 + a[0][2] * c02;
    if (fabs(det) < 1e-12)
        return FALSE;
    det = 1.0 / det;
    out->m[0][0] = c00 * det;
    out->m[0][1] = (a[0][2] * a[2][1] - a[0][1] * a[2][2]) * det;
    out->m[0][2] = (a[0][1] * a[1][2] - a[0][2] * a[1][1]) * det;
    out->m[1][0] = c01 * det;
    out->m[1][1] = (a[0][0] * a[2][2] - a[0][2] * a[2][0]) * det;
    out->m[1][2] = (a[0][2] * a[1][0] - a[0][0] * a[1][2]) * det;
    out->m[2][0] = c02 * det;
    out->m[2][1] = (a[0][1] * a[2][0] - a[0][0] * a[2][1]) * det;
    out->m[2][2] = (a[0][0] * a[1][1] - a[0][1] * a[1][0]) * det;
    return TRUE;
}

static BOOL fx_matrix_apply(const struct fx_matrix *m, double x, double y, double *ox, double *oy)
{
    double w = x * m->m[0][2] + y * m->m[1][2] + m->m[2][2];

    if (w <= 1e-9)
        return FALSE;
    *ox = (x * m->m[0][0] + y * m->m[1][0] + m->m[2][0]) / w;
    *oy = (x * m->m[0][1] + y * m->m[1][1] + m->m[2][1]) / w;
    return TRUE;
}

/* Bounding box of a rectangle mapped through a matrix; FALSE when it cannot be bounded. With round, the edges are
 * rounded to the nearest pixel (half up), as for nearest neighbour sampling. */
static BOOL fx_matrix_map_rect(const struct fx_matrix *m, struct fx_rect rc, struct fx_rect *out, BOOL round)
{
    double xs[4] = {rc.l, rc.r, rc.l, rc.r}, ys[4] = {rc.t, rc.t, rc.b, rc.b};
    double minx = 1e30, miny = 1e30, maxx = -1e30, maxy = -1e30, x, y;
    unsigned int i;

    for (i = 0; i < 4; ++i)
    {
        if (!fx_matrix_apply(m, xs[i], ys[i], &x, &y))
            return FALSE;
        minx = min(minx, x); maxx = max(maxx, x);
        miny = min(miny, y); maxy = max(maxy, y);
    }
    if (round)
    {
        out->l = fx_clampi(floor(minx + 0.5));
        out->t = fx_clampi(floor(miny + 0.5));
        out->r = fx_clampi(floor(maxx + 0.5));
        out->b = fx_clampi(floor(maxy + 0.5));
        return TRUE;
    }
    out->l = fx_clampi(floor(minx + 1e-6));
    out->t = fx_clampi(floor(miny + 1e-6));
    out->r = fx_clampi(ceil(maxx - 1e-6));
    out->b = fx_clampi(ceil(maxy - 1e-6));
    return TRUE;
}

/* Samples with the source pixel (i, j) covering [i, i + 1) x [j, j + 1). */
static void fx_sample(const struct fx_image *src, double u, double v, BOOL linear, BOOL hard, float out[4])
{
    const struct fx_rect *rc = &src->rc;
    const float *p;
    int i, j;

    out[0] = out[1] = out[2] = out[3] = 0.0f;
    if (fx_empty(rc))
        return;

    if (!linear)
    {
        if ((p = fx_px(src, (int)floor(u), (int)floor(v))))
            memcpy(out, p, 4 * sizeof(float));
        return;
    }

    if (hard && (u < rc->l || u > rc->r || v < rc->t || v > rc->b))
        return;

    {
        double fu = u - 0.5, fv = v - 0.5;
        int i0 = (int)floor(fu), j0 = (int)floor(fv);
        float tx = (float)(fu - i0), ty = (float)(fv - j0);
        float wgt[4] = {(1 - tx) * (1 - ty), tx * (1 - ty), (1 - tx) * ty, tx * ty};
        unsigned int k, c;

        for (k = 0; k < 4; ++k)
        {
            i = i0 + (k & 1);
            j = j0 + (k >> 1);
            if (hard)
            {
                i = min(max(i, rc->l), rc->r - 1);
                j = min(max(j, rc->t), rc->b - 1);
            }
            if (!(p = fx_px(src, i, j)))
                continue;
            for (c = 0; c < 4; ++c)
                out[c] += p[c] * wgt[k];
        }
    }
}

/* Resamples an input through a matrix (source to destination), over roi. */
static struct fx_image *fx_eval_matrix(struct fx_ctx *ctx, ID2D1Image *input, const struct fx_matrix *m,
        struct fx_rect roi, UINT32 interp, BOOL hard, struct fx_rect clip)
{
    struct fx_matrix inv;
    struct fx_rect need, ib;
    struct fx_image *src, *dst;
    BOOL linear = interp != 0;
    int x, y;

    if (!input || !(dst = fx_image_alloc(ctx->dc, roi)))
        return input ? NULL : fx_image_alloc(ctx->dc, roi);
    if (fx_empty(&roi) || !fx_matrix_invert(m, &inv))
        return dst;

    ib = fx_bounds(ctx, input);
    if (!fx_matrix_map_rect(&inv, roi, &need, FALSE))
        need = ib;
    need = fx_expand(need, 2, 2);
    need = fx_intersect(need, ib);
    if (fx_empty(&need) || !(src = fx_eval(ctx, input, need)))
        return dst;

    for (y = max(roi.t, clip.t); y < min(roi.b, clip.b); ++y)
    {
        for (x = max(roi.l, clip.l); x < min(roi.r, clip.r); ++x)
        {
            double u, v;

            if (!fx_matrix_apply(&inv, x + 0.5, y + 0.5, &u, &v))
                continue;
            fx_sample(src, u, v, linear, hard, fx_px(dst, x, y));
        }
    }

    fx_image_free(src);
    return dst;
}

static struct fx_matrix fx_matrix_from_3x2(const struct fx_ctx *ctx, const float *f)
{
    struct fx_matrix m;
    double sx = ctx->sx, sy = ctx->sy;

    /* The linear part is conjugated with the DIP to pixel scale, the translation is scaled. */
    m.m[0][0] = f[0]; m.m[0][1] = f[1] * sy / sx; m.m[0][2] = 0.0;
    m.m[1][0] = f[2] * sx / sy; m.m[1][1] = f[3]; m.m[1][2] = 0.0;
    m.m[2][0] = f[4] * sx; m.m[2][1] = f[5] * sy; m.m[2][2] = 1.0;
    return m;
}

static BOOL fx_get_matrix(struct fx_ctx *ctx, const struct d2d_effect *effect, enum fx_kind kind, struct fx_matrix *m,
        UINT32 *interp, BOOL *hard)
{
    float f[20];

    *interp = 1;
    *hard = FALSE;
    switch (kind)
    {
        case FX_AFFINE:
            if (!fx_prop(effect, D2D1_2DAFFINETRANSFORM_PROP_TRANSFORM_MATRIX, f, 24))
                return FALSE;
            *interp = fx_prop_uint(effect, D2D1_2DAFFINETRANSFORM_PROP_INTERPOLATION_MODE, 1);
            *hard = fx_prop_uint(effect, D2D1_2DAFFINETRANSFORM_PROP_BORDER_MODE, 0) == 1;
            *m = fx_matrix_from_3x2(ctx, f);
            return TRUE;

        case FX_SCALE:
        {
            float s[2] = {1.0f, 1.0f}, c[2] = {0.0f, 0.0f};

            fx_prop(effect, 0, s, sizeof(s));
            fx_prop(effect, 1, c, sizeof(c));
            *interp = fx_prop_uint(effect, 2, 1);
            *hard = fx_prop_uint(effect, 3, 0) == 1;
            f[0] = s[0]; f[1] = 0.0f; f[2] = 0.0f; f[3] = s[1];
            f[4] = c[0] * (1.0f - s[0]);
            f[5] = c[1] * (1.0f - s[1]);
            *m = fx_matrix_from_3x2(ctx, f);
            return TRUE;
        }

        case FX_3DTRANSFORM:
        {
            /* Row vector convention, a point (x, y, 0, 1) of the image plane. */
            double sx = ctx->sx, sy = ctx->sy;

            if (!fx_prop(effect, 2, f, 64))
                return FALSE;
            *interp = fx_prop_uint(effect, 0, 1);
            *hard = fx_prop_uint(effect, 1, 0) == 1;
            m->m[0][0] = f[0];  m->m[0][1] = f[1] * sy / sx;  m->m[0][2] = f[3] / sx;
            m->m[1][0] = f[4] * sx / sy;  m->m[1][1] = f[5];  m->m[1][2] = f[7] / sy;
            m->m[2][0] = f[12] * sx;  m->m[2][1] = f[13] * sy;  m->m[2][2] = f[15];
            return TRUE;
        }

        default:
            return FALSE;
    }
}

/* Porter-Duff factors for the composite modes: result = src * fa + dst * fb. */
static void fx_composite_px(UINT32 mode, const float *s, const float *d, float *out)
{
    float fa, fb, as = s[3], ad = d[3];
    unsigned int c;

    switch (mode)
    {
        case D2D1_COMPOSITE_MODE_DESTINATION_OVER: fa = 1.0f - ad; fb = 1.0f; break;
        case D2D1_COMPOSITE_MODE_SOURCE_IN: fa = ad; fb = 0.0f; break;
        case D2D1_COMPOSITE_MODE_DESTINATION_IN: fa = 0.0f; fb = as; break;
        case D2D1_COMPOSITE_MODE_SOURCE_OUT: fa = 1.0f - ad; fb = 0.0f; break;
        case D2D1_COMPOSITE_MODE_DESTINATION_OUT: fa = 0.0f; fb = 1.0f - as; break;
        case D2D1_COMPOSITE_MODE_SOURCE_ATOP: fa = ad; fb = 1.0f - as; break;
        case D2D1_COMPOSITE_MODE_DESTINATION_ATOP: fa = 1.0f - ad; fb = as; break;
        case D2D1_COMPOSITE_MODE_XOR: fa = 1.0f - ad; fb = 1.0f - as; break;
        case D2D1_COMPOSITE_MODE_PLUS: fa = 1.0f; fb = 1.0f; break;
        case D2D1_COMPOSITE_MODE_SOURCE_COPY:
        case D2D1_COMPOSITE_MODE_BOUNDED_SOURCE_COPY: fa = 1.0f; fb = 0.0f; break;
        case D2D1_COMPOSITE_MODE_MASK_INVERT: fa = 0.0f; fb = 1.0f - as; break;
        case D2D1_COMPOSITE_MODE_SOURCE_OVER:
        default: fa = 1.0f; fb = 1.0f - as; break;
    }
    for (c = 0; c < 4; ++c)
        out[c] = fx_sat(s[c] * fa + d[c] * fb);
}

static float fx_lum(const float *c)
{
    return 0.3f * c[0] + 0.59f * c[1] + 0.11f * c[2];
}

static void fx_clip_color(float *c)
{
    float l = fx_lum(c), n = min(c[0], min(c[1], c[2])), x = max(c[0], max(c[1], c[2]));
    unsigned int i;

    if (n < 0.0f)
    {
        for (i = 0; i < 3; ++i) c[i] = l + (c[i] - l) * l / (l - n);
    }
    if (x > 1.0f)
    {
        for (i = 0; i < 3; ++i) c[i] = l + (c[i] - l) * (1.0f - l) / (x - l);
    }
}

static void fx_set_lum(float *c, float l)
{
    float d = l - fx_lum(c);

    c[0] += d; c[1] += d; c[2] += d;
    fx_clip_color(c);
}

static float fx_sat_of(const float *c)
{
    return max(c[0], max(c[1], c[2])) - min(c[0], min(c[1], c[2]));
}

static void fx_set_sat(float *c, float s)
{
    int mx = 0, mn = 0, md, i;
    float out[3] = {0, 0, 0};

    for (i = 1; i < 3; ++i)
    {
        if (c[i] > c[mx]) mx = i;
        if (c[i] < c[mn]) mn = i;
    }
    if (mx == mn)
    {
        c[0] = c[1] = c[2] = 0.0f;
        return;
    }
    md = 3 - mx - mn;
    out[md] = (c[md] - c[mn]) * s / (c[mx] - c[mn]);
    out[mx] = s;
    c[0] = out[0]; c[1] = out[1]; c[2] = out[2];
}

static float fx_blend_channel(UINT32 mode, float cb, float cs)
{
    switch (mode)
    {
        case D2D1_BLEND_MODE_MULTIPLY: return cb * cs;
        case D2D1_BLEND_MODE_SCREEN: return cb + cs - cb * cs;
        case D2D1_BLEND_MODE_DARKEN: return min(cb, cs);
        case D2D1_BLEND_MODE_LIGHTEN: return max(cb, cs);
        case D2D1_BLEND_MODE_COLOR_BURN:
            if (cb >= 1.0f) return 1.0f;
            if (cs <= 0.0f) return 0.0f;
            return 1.0f - min(1.0f, (1.0f - cb) / cs);
        case D2D1_BLEND_MODE_LINEAR_BURN: return fx_sat(cb + cs - 1.0f);
        case D2D1_BLEND_MODE_COLOR_DODGE:
            if (cb <= 0.0f) return 0.0f;
            if (cs >= 1.0f) return 1.0f;
            return min(1.0f, cb / (1.0f - cs));
        case D2D1_BLEND_MODE_LINEAR_DODGE: return fx_sat(cb + cs);
        case D2D1_BLEND_MODE_OVERLAY: return fx_blend_channel(D2D1_BLEND_MODE_HARD_LIGHT, cs, cb);
        case D2D1_BLEND_MODE_SOFT_LIGHT:
        {
            float d;

            if (cs <= 0.5f)
                return cb - (1.0f - 2.0f * cs) * cb * (1.0f - cb);
            d = cb <= 0.25f ? ((16.0f * cb - 12.0f) * cb + 4.0f) * cb : sqrtf(cb);
            return cb + (2.0f * cs - 1.0f) * (d - cb);
        }
        case D2D1_BLEND_MODE_HARD_LIGHT:
            if (cs <= 0.5f) return cb * 2.0f * cs;
            return fx_blend_channel(D2D1_BLEND_MODE_SCREEN, cb, 2.0f * cs - 1.0f);
        case D2D1_BLEND_MODE_VIVID_LIGHT:
            if (cs < 0.5f) return fx_blend_channel(D2D1_BLEND_MODE_COLOR_BURN, cb, 2.0f * cs);
            return fx_blend_channel(D2D1_BLEND_MODE_COLOR_DODGE, cb, 2.0f * (cs - 0.5f));
        case D2D1_BLEND_MODE_LINEAR_LIGHT: return fx_sat(cb + 2.0f * cs - 1.0f);
        case D2D1_BLEND_MODE_PIN_LIGHT:
            if (cs < 0.5f) return min(cb, 2.0f * cs);
            return max(cb, 2.0f * cs - 1.0f);
        case D2D1_BLEND_MODE_HARD_MIX: return cb + cs >= 1.0f ? 1.0f : 0.0f;
        case D2D1_BLEND_MODE_DIFFERENCE: return fabsf(cb - cs);
        case D2D1_BLEND_MODE_EXCLUSION: return cb + cs - 2.0f * cb * cs;
        case D2D1_BLEND_MODE_SUBTRACT: return fx_sat(cb - cs);
        case D2D1_BLEND_MODE_DIVISION:
            if (cs <= 0.0f) return cb <= 0.0f ? 0.0f : 1.0f;
            return fx_sat(cb / cs);
        default: return cs;
    }
}

/* b is the backdrop (input 0), s the source (input 1). */
static void fx_blend_px(UINT32 mode, const float *b, const float *s, float *out)
{
    float ab = b[3], as = s[3], cb[3], cs[3], res[3];
    unsigned int i;

    for (i = 0; i < 3; ++i)
    {
        cb[i] = ab > 0.0f ? fx_sat(b[i] / ab) : 0.0f;
        cs[i] = as > 0.0f ? fx_sat(s[i] / as) : 0.0f;
    }

    switch (mode)
    {
        case D2D1_BLEND_MODE_DARKER_COLOR:
            memcpy(res, fx_lum(cs) < fx_lum(cb) ? cs : cb, sizeof(res));
            break;
        case D2D1_BLEND_MODE_LIGHTER_COLOR:
            memcpy(res, fx_lum(cs) > fx_lum(cb) ? cs : cb, sizeof(res));
            break;
        case D2D1_BLEND_MODE_HUE:
            memcpy(res, cs, sizeof(res));
            fx_set_sat(res, fx_sat_of(cb));
            fx_set_lum(res, fx_lum(cb));
            break;
        case D2D1_BLEND_MODE_SATURATION:
            memcpy(res, cb, sizeof(res));
            fx_set_sat(res, fx_sat_of(cs));
            fx_set_lum(res, fx_lum(cb));
            break;
        case D2D1_BLEND_MODE_COLOR:
            memcpy(res, cs, sizeof(res));
            fx_set_lum(res, fx_lum(cb));
            break;
        case D2D1_BLEND_MODE_LUMINOSITY:
            memcpy(res, cb, sizeof(res));
            fx_set_lum(res, fx_lum(cs));
            break;
        case D2D1_BLEND_MODE_DISSOLVE: /* random per pixel, drawn as source over */
            for (i = 0; i < 3; ++i) res[i] = cs[i];
            break;
        default:
            for (i = 0; i < 3; ++i) res[i] = fx_blend_channel(mode, cb[i], cs[i]);
            break;
    }

    for (i = 0; i < 3; ++i)
        out[i] = fx_sat((1.0f - ab) * s[i] + (1.0f - as) * b[i] + as * ab * res[i]);
    out[3] = fx_sat(as + ab - as * ab);
}

static int fx_reflect(int i, int l, int r)
{
    int w = r - l, m = (i - l) % (2 * w);

    if (m < 0) m += 2 * w;
    if (m >= w) m = 2 * w - 1 - m;
    return l + m;
}

static struct fx_image *fx_blur(struct fx_ctx *ctx, ID2D1Image *input, struct fx_rect roi, float sigma_dips,
        BOOL hard, BOOL shadow, const float *color)
{
    double sigma = max(sigma_dips, 0.0f) * ctx->sx;
    struct fx_image *src, *tmp, *dst;
    struct fx_rect need, ib;
    int radius, x, y, k;
    double *kernel = NULL, sum;
    unsigned int c;

    if (!(dst = fx_image_alloc(ctx->dc, roi)))
        return NULL;
    if (fx_empty(&roi) || !input)
        return dst;

    radius = sigma < 0.01 ? 0 : (int)ceil(3.0 * sigma);
    ib = fx_bounds(ctx, input);
    /* The hard border mirrors the input at its edges and the result is limited to the input. */
    need = hard ? ib : fx_intersect(fx_expand(roi, radius, radius), ib);
    if (hard)
        roi = fx_intersect(roi, ib);
    if (fx_empty(&need) || fx_empty(&roi) || !(src = fx_eval(ctx, input, need)))
        return dst;

    if (radius && !(kernel = malloc((2 * radius + 1) * sizeof(*kernel))))
    {
        fx_image_free(src);
        return dst;
    }
    if (radius)
    {
        for (sum = 0.0, k = -radius; k <= radius; ++k)
            sum += kernel[k + radius] = exp(-(double)k * k / (2.0 * sigma * sigma));
        for (k = 0; k < 2 * radius + 1; ++k)
            kernel[k] /= sum;
    }

    /* Horizontal pass into tmp over the rows of roi, then vertical into dst. */
    {
        struct fx_rect trc = {roi.l, need.t, roi.r, need.b};

        if (!(tmp = fx_image_alloc(ctx->dc, trc)))
        {
            free(kernel);
            fx_image_free(src);
            return dst;
        }
        for (y = tmp->rc.t; y < tmp->rc.b; ++y)
        {
            for (x = tmp->rc.l; x < tmp->rc.r; ++x)
            {
                float acc[4] = {0, 0, 0, 0}, *o = fx_px(tmp, x, y);

                if (!radius)
                {
                    const float *p = fx_px(src, x, y);
                    if (p) memcpy(acc, p, sizeof(acc));
                }
                else
                {
                    for (k = -radius; k <= radius; ++k)
                    {
                        int xx = x + k;
                        const float *p;

                        if (hard)
                            xx = fx_reflect(xx, src->rc.l, src->rc.r);
                        if (!(p = fx_px(src, xx, y)))
                            continue;
                        for (c = 0; c < 4; ++c)
                            acc[c] += p[c] * (float)kernel[k + radius];
                    }
                }
                memcpy(o, acc, sizeof(acc));
            }
        }
    }

    for (y = roi.t; y < roi.b; ++y)
    {
        for (x = roi.l; x < roi.r; ++x)
        {
            float acc[4] = {0, 0, 0, 0}, *o = fx_px(dst, x, y);

            if (!radius)
            {
                const float *p = fx_px(tmp, x, y);
                if (p) memcpy(acc, p, sizeof(acc));
            }
            else
            {
                for (k = -radius; k <= radius; ++k)
                {
                    int yy = y + k;
                    const float *p;

                    if (hard)
                        yy = fx_reflect(yy, tmp->rc.t, tmp->rc.b);
                    if (!(p = fx_px(tmp, x, yy)))
                        continue;
                    for (c = 0; c < 4; ++c)
                        acc[c] += p[c] * (float)kernel[k + radius];
                }
            }
            if (shadow)
            {
                float a = acc[3] * color[3];

                o[0] = color[0] * a; o[1] = color[1] * a; o[2] = color[2] * a; o[3] = a;
            }
            else
            {
                memcpy(o, acc, sizeof(acc));
            }
        }
    }

    free(kernel);
    fx_image_free(tmp);
    fx_image_free(src);
    return dst;
}

/* The pixel rectangle of a crop: the edges are snapped to the nearest pixel (half up); the right and bottom edges of
 * a soft crop keep their fraction as a coverage of the last pixel. */
static struct fx_rect fx_crop_rect(const struct fx_ctx *ctx, const float *v, BOOL hard)
{
    struct fx_rect rc;

    rc.l = fx_clampi(floor((double)v[0] * ctx->sx + 0.5));
    rc.t = fx_clampi(floor((double)v[1] * ctx->sy + 0.5));
    rc.r = fx_clampi(hard ? floor((double)v[2] * ctx->sx + 0.5) : ceil((double)v[2] * ctx->sx - 1e-4));
    rc.b = fx_clampi(hard ? floor((double)v[3] * ctx->sy + 0.5) : ceil((double)v[3] * ctx->sy - 1e-4));
    if (fx_empty(&rc))
        rc.l = rc.t = rc.r = rc.b = 0;
    return rc;
}

static struct fx_rect fx_bounds(struct fx_ctx *ctx, ID2D1Image *image)
{
    static const struct fx_rect none = {0, 0, 0, 0}, all = {-FX_INF, -FX_INF, FX_INF, FX_INF};
    struct d2d_effect *effect;
    ID2D1Bitmap *bitmap;
    struct fx_rect rc = none, in;
    enum fx_kind kind;

    if (!image || ctx->depth > FX_MAX_DEPTH)
        return none;

    if (SUCCEEDED(ID2D1Image_QueryInterface(image, &IID_ID2D1Bitmap, (void **)&bitmap)))
    {
        D2D1_SIZE_U size = ID2D1Bitmap_GetPixelSize(bitmap);

        ID2D1Bitmap_Release(bitmap);
        rc.r = size.width;
        rc.b = size.height;
        return fx_empty(&rc) ? none : rc;
    }

    if (!(effect = unsafe_impl_from_ID2D1Image(image)))
        return none;

    ++ctx->depth;
    switch ((kind = fx_effect_kind(effect)))
    {
        case FX_FLOOD:
            rc = all;
            break;

        case FX_COMPOSITE:
        case FX_BLEND:
        {
            unsigned int i;

            for (i = 0; i < effect->input_count; ++i)
                rc = fx_union(rc, fx_bounds(ctx, fx_input(effect, i)));
            break;
        }

        case FX_AFFINE:
        case FX_SCALE:
        case FX_3DTRANSFORM:
        {
            struct fx_matrix m;
            UINT32 interp;
            BOOL hard;

            in = fx_bounds(ctx, fx_input(effect, 0));
            if (fx_empty(&in) || !fx_get_matrix(ctx, effect, kind, &m, &interp, &hard))
                break;
            if (!fx_matrix_map_rect(&m, in, &rc, interp == 0))
                rc = none;
            else if (interp != 0 && !hard)
                rc = fx_expand(rc, 1, 1);
            break;
        }

        case FX_CROP:
        {
            float v[4] = {-3.402823e38f, -3.402823e38f, 3.402823e38f, 3.402823e38f};

            fx_prop(effect, D2D1_CROP_PROP_RECT, v, sizeof(v));
            rc = fx_intersect(fx_bounds(ctx, fx_input(effect, 0)), fx_crop_rect(ctx, v, fx_prop_uint(effect, 1, 0) == 1));
            break;
        }

        case FX_COLORMATRIX:
            rc = fx_bounds(ctx, fx_input(effect, 0));
            break;

        case FX_BLUR:
        case FX_SHADOW:
        {
            float sigma = fx_prop_float(effect, 0, 3.0f);
            int r = max(sigma, 0.0f) * ctx->sx < 0.01 ? 0 : (int)ceil(3.0 * sigma * ctx->sx);

            if (kind == FX_BLUR && fx_prop_uint(effect, 2, 0) == 1)
                r = 0;
            rc = fx_expand(fx_bounds(ctx, fx_input(effect, 0)), r, r);
            break;
        }

        case FX_ATLAS:
        {
            float v[4] = {0, 0, 0, 0};

            fx_prop(effect, 0, v, sizeof(v));
            rc = fx_intersect(fx_bounds(ctx, fx_input(effect, 0)), fx_rect_from_dips(ctx, v));
            /* The atlas region is moved to the origin of the rectangle. */
            if (!fx_empty(&rc) && rc.l > -FX_INF && rc.t > -FX_INF && rc.r < FX_INF && rc.b < FX_INF)
            {
                struct fx_rect r = fx_rect_from_dips(ctx, v);

                rc.l -= r.l; rc.r -= r.l; rc.t -= r.t; rc.b -= r.t;
            }
            break;
        }

        case FX_TILE:
            rc = all;
            break;

        default:
            break;
    }
    --ctx->depth;

    return rc;
}

static struct fx_image *fx_eval(struct fx_ctx *ctx, ID2D1Image *image, struct fx_rect roi)
{
    struct d2d_effect *effect;
    ID2D1Bitmap *bitmap;
    struct fx_image *dst = NULL, *a, *b;
    enum fx_kind kind;
    int x, y;

    if (!image || ctx->depth > FX_MAX_DEPTH)
        return fx_image_alloc(ctx->dc, roi);

    if (SUCCEEDED(ID2D1Image_QueryInterface(image, &IID_ID2D1Bitmap, (void **)&bitmap)))
    {
        struct fx_image *full = fx_read_bitmap(ctx, bitmap);

        ID2D1Bitmap_Release(bitmap);
        if (!full)
            return NULL;
        if (!(dst = fx_image_alloc(ctx->dc, roi)))
        {
            fx_image_free(full);
            return NULL;
        }
        for (y = roi.t; y < roi.b; ++y)
        {
            for (x = roi.l; x < roi.r; ++x)
            {
                const float *p = fx_px(full, x, y);

                if (p) memcpy(fx_px(dst, x, y), p, 4 * sizeof(float));
            }
        }
        fx_image_free(full);
        return dst;
    }

    if (!(effect = unsafe_impl_from_ID2D1Image(image)))
        return fx_image_alloc(ctx->dc, roi);

    if (!(dst = fx_image_alloc(ctx->dc, roi)))
        return NULL;
    if (fx_empty(&roi))
        return dst;

    ++ctx->depth;
    switch ((kind = fx_effect_kind(effect)))
    {
        case FX_FLOOD:
        {
            float c[4] = {0.0f, 0.0f, 0.0f, 1.0f};

            fx_prop(effect, 0, c, sizeof(c));
            c[3] = fx_sat(c[3]);
            for (y = roi.t; y < roi.b; ++y)
            {
                for (x = roi.l; x < roi.r; ++x)
                {
                    float *p = fx_px(dst, x, y);

                    /* The colour is used as it is (it is not multiplied by the alpha), as on Windows. */
                    p[0] = fx_sat(c[0]); p[1] = fx_sat(c[1]); p[2] = fx_sat(c[2]); p[3] = c[3];
                }
            }
            break;
        }

        case FX_COMPOSITE:
        case FX_BLEND:
        {
            UINT32 mode = fx_prop_uint(effect, 0, kind == FX_BLEND ? D2D1_BLEND_MODE_MULTIPLY : 0);
            unsigned int i;

            if (!(a = fx_eval(ctx, fx_input(effect, 0), roi)))
                break;
            if (kind == FX_BLEND && effect->input_count < 2)
            {
                fx_image_free(dst);
                dst = a;
                break;
            }
            for (i = 1; i < effect->input_count; ++i)
            {
                if (!(b = fx_eval(ctx, fx_input(effect, i), roi)))
                    break;
                for (y = roi.t; y < roi.b; ++y)
                {
                    for (x = roi.l; x < roi.r; ++x)
                    {
                        float *d = fx_px(a, x, y), *s = fx_px(b, x, y), o[4];

                        if (kind == FX_BLEND)
                            fx_blend_px(mode, d, s, o);
                        else
                            fx_composite_px(mode, s, d, o);
                        memcpy(d, o, sizeof(o));
                    }
                }
                fx_image_free(b);
            }
            fx_image_free(dst);
            dst = a;
            break;
        }

        case FX_AFFINE:
        case FX_SCALE:
        case FX_3DTRANSFORM:
        {
            struct fx_matrix m;
            struct fx_rect clip;
            UINT32 interp;
            BOOL hard;

            if (!fx_get_matrix(ctx, effect, kind, &m, &interp, &hard))
                break;
            fx_image_free(dst);
            ctx->depth--;
            clip = fx_bounds(ctx, image);
            ctx->depth++;
            dst = fx_eval_matrix(ctx, fx_input(effect, 0), &m, roi, interp, hard, clip);
            break;
        }

        case FX_CROP:
        case FX_ATLAS:
        {
            float v[4] = {-3.402823e38f, -3.402823e38f, 3.402823e38f, 3.402823e38f};
            struct fx_rect snap, in;
            BOOL hard = TRUE;
            double cr, cb;
            int dx = 0, dy = 0;

            if (kind == FX_ATLAS)
            {
                v[0] = v[1] = 0.0f;
                fx_prop(effect, 0, v, sizeof(v));
            }
            else
            {
                fx_prop(effect, 0, v, sizeof(v));
                hard = fx_prop_uint(effect, 1, 0) == 1;
            }
            snap = fx_crop_rect(ctx, v, hard);
            cr = (double)v[2] * ctx->sx;
            cb = (double)v[3] * ctx->sy;
            if (kind == FX_ATLAS && snap.l > -FX_INF && snap.t > -FX_INF)
            {
                /* The atlas region is moved to the origin of its rectangle. */
                dx = snap.l;
                dy = snap.t;
            }
            in = fx_intersect((struct fx_rect){roi.l + dx, roi.t + dy, roi.r + dx, roi.b + dy}, snap);
            if (fx_empty(&in) || !(a = fx_eval(ctx, fx_input(effect, 0), in)))
                break;
            for (y = in.t; y < in.b; ++y)
            {
                float cy = (!hard && snap.b < FX_INF && y == snap.b - 1) ? (float)min(1.0, max(0.0, cb - y)) : 1.0f;

                for (x = in.l; x < in.r; ++x)
                {
                    float cx = (!hard && snap.r < FX_INF && x == snap.r - 1) ? (float)min(1.0, max(0.0, cr - x)) : 1.0f;
                    float cov = cx * cy, *s = fx_px(a, x, y), *d = fx_px(dst, x - dx, y - dy);

                    d[0] = s[0] * cov; d[1] = s[1] * cov; d[2] = s[2] * cov; d[3] = s[3] * cov;
                }
            }
            fx_image_free(a);
            break;
        }

        case FX_COLORMATRIX:
        {
            float m[20] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0};
            UINT32 alpha_mode = fx_prop_uint(effect, 1, 1);
            BOOL clamp = fx_prop_uint(effect, 2, 0) != 0;

            fx_prop(effect, 0, m, sizeof(m));
            if (!(a = fx_eval(ctx, fx_input(effect, 0), roi)))
                break;
            for (y = roi.t; y < roi.b; ++y)
            {
                for (x = roi.l; x < roi.r; ++x)
                {
                    const float *s = fx_px(a, x, y);
                    float *d = fx_px(dst, x, y), in[4], o[4];
                    unsigned int i;

                    /* Alpha mode 1 (the default): the matrix is applied to the unpremultiplied colour, the result
                     * is premultiplied. Mode 2: it is applied to the stored values. Measured on Windows. */
                    memcpy(in, s, sizeof(in));
                    if (alpha_mode == 1)
                    {
                        if (in[3] > 0.0f)
                        {
                            in[0] /= in[3]; in[1] /= in[3]; in[2] /= in[3];
                        }
                        else
                        {
                            in[0] = in[1] = in[2] = 0.0f;
                        }
                    }
                    for (i = 0; i < 4; ++i)
                    {
                        o[i] = in[0] * m[i] + in[1] * m[4 + i] + in[2] * m[8 + i] + in[3] * m[12 + i] + m[16 + i];
                        if (clamp) o[i] = fx_sat(o[i]);
                    }
                    if (alpha_mode == 1)
                    {
                        o[3] = fx_sat(o[3]);
                        o[0] *= o[3]; o[1] *= o[3]; o[2] *= o[3];
                    }
                    memcpy(d, o, sizeof(o));
                }
            }
            fx_image_free(a);
            break;
        }

        case FX_BLUR:
            fx_image_free(dst);
            dst = fx_blur(ctx, fx_input(effect, 0), roi, fx_prop_float(effect, 0, 3.0f),
                    fx_prop_uint(effect, 2, 0) == 1, FALSE, NULL);
            break;

        case FX_SHADOW:
        {
            float c[4] = {0.0f, 0.0f, 0.0f, 1.0f};

            fx_prop(effect, 1, c, sizeof(c));
            c[0] = fx_sat(c[0]); c[1] = fx_sat(c[1]); c[2] = fx_sat(c[2]); c[3] = fx_sat(c[3]);
            fx_image_free(dst);
            dst = fx_blur(ctx, fx_input(effect, 0), roi, fx_prop_float(effect, 0, 3.0f),
                    FALSE, TRUE, c);
            break;
        }

        case FX_TILE:
        {
            float v[4] = {0, 0, 0, 0};
            struct fx_rect tile;
            int w, h;

            fx_prop(effect, 0, v, sizeof(v));
            tile = fx_rect_from_dips(ctx, v);
            tile = fx_intersect(tile, fx_bounds(ctx, fx_input(effect, 0)));
            if (fx_empty(&tile) || !(a = fx_eval(ctx, fx_input(effect, 0), tile)))
                break;
            w = tile.r - tile.l;
            h = tile.b - tile.t;
            for (y = roi.t; y < roi.b; ++y)
            {
                int sy = tile.t + (((y - tile.t) % h) + h) % h;

                for (x = roi.l; x < roi.r; ++x)
                {
                    int sx = tile.l + (((x - tile.l) % w) + w) % w;

                    memcpy(fx_px(dst, x, y), fx_px(a, sx, sy), 4 * sizeof(float));
                }
            }
            fx_image_free(a);
            break;
        }

        default:
            if (!ctx->failed)
                FIXME("Drawing of effect %s is not implemented.\n", debugstr_guid(&effect->id));
            ctx->failed = TRUE;
            break;
    }
    --ctx->depth;

    return dst;
}

/* Composites the result with the pixels of the target on the CPU, for the composite modes other than source over.
 * The rectangle of img is placed at (dx, dy) of the target. MASK_INVERT inverts the destination colour where the
 * source is opaque, the destination alpha is kept. */
static BOOL fx_composite_to_target(struct d2d_device_context *context, const struct fx_image *img, int dx, int dy,
        D2D1_COMPOSITE_MODE mode)
{
    struct d2d_bitmap *bitmap = context->target.type == D2D_TARGET_BITMAP ? context->target.bitmap : NULL;
    D3D11_TEXTURE2D_DESC desc;
    D3D11_MAPPED_SUBRESOURCE map;
    ID3D11DeviceContext *d3d_context;
    ID3D11Texture2D *tex, *staging;
    struct fx_rect r;
    D3D11_BOX box;
    BYTE *out;
    int x, y;

    if (!bitmap || FAILED(ID3D11Resource_QueryInterface(bitmap->resource, &IID_ID3D11Texture2D, (void **)&tex)))
        return FALSE;
    ID3D11Texture2D_GetDesc(tex, &desc);
    if (desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || desc.SampleDesc.Count != 1)
    {
        ID3D11Texture2D_Release(tex);
        return FALSE;
    }

    r.l = img->rc.l + dx; r.t = img->rc.t + dy; r.r = img->rc.r + dx; r.b = img->rc.b + dy;
    r = fx_intersect(r, (struct fx_rect){0, 0, desc.Width, desc.Height});
    if (fx_empty(&r))
    {
        ID3D11Texture2D_Release(tex);
        return TRUE;
    }

    desc.Width = r.r - r.l;
    desc.Height = r.b - r.t;
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.MiscFlags = 0;
    if (FAILED(ID3D11Device1_CreateTexture2D(context->d3d_device, &desc, NULL, &staging)))
    {
        ID3D11Texture2D_Release(tex);
        return FALSE;
    }

    ID3D11Device1_GetImmediateContext(context->d3d_device, &d3d_context);
    box.left = r.l; box.top = r.t; box.front = 0; box.right = r.r; box.bottom = r.b; box.back = 1;
    ID3D11DeviceContext_CopySubresourceRegion(d3d_context, (ID3D11Resource *)staging, 0, 0, 0, 0,
            (ID3D11Resource *)tex, 0, &box);
    if (FAILED(ID3D11DeviceContext_Map(d3d_context, (ID3D11Resource *)staging, 0, D3D11_MAP_READ, 0, &map))
            || !(out = malloc((size_t)desc.Width * desc.Height * 4)))
    {
        ID3D11DeviceContext_Release(d3d_context);
        ID3D11Texture2D_Release(staging);
        ID3D11Texture2D_Release(tex);
        return FALSE;
    }

    for (y = 0; y < (int)desc.Height; ++y)
    {
        const BYTE *row = (const BYTE *)map.pData + (size_t)y * map.RowPitch;

        for (x = 0; x < (int)desc.Width; ++x)
        {
            const float *s = fx_px(img, r.l + x - dx, r.t + y - dy);
            float d[4], o[4];
            unsigned int c;

            d[0] = row[x * 4 + 2] / 255.0f; d[1] = row[x * 4 + 1] / 255.0f;
            d[2] = row[x * 4] / 255.0f; d[3] = row[x * 4 + 3] / 255.0f;
            if (!s)
            {
                memcpy(o, d, sizeof(o));
            }
            else if (mode == D2D1_COMPOSITE_MODE_MASK_INVERT)
            {
                for (c = 0; c < 3; ++c)
                    o[c] = fx_sat(d[c] * (1.0f - s[3]) + (d[3] - d[c]) * s[3]);
                o[3] = d[3];
            }
            else if (mode == D2D1_COMPOSITE_MODE_BOUNDED_SOURCE_COPY)
            {
                memcpy(o, s, sizeof(o));
            }
            else
            {
                fx_composite_px(mode, s, d, o);
            }
            out[((size_t)y * desc.Width + x) * 4 + 0] = (BYTE)(fx_sat(o[2]) * 255.0f + 0.5f);
            out[((size_t)y * desc.Width + x) * 4 + 1] = (BYTE)(fx_sat(o[1]) * 255.0f + 0.5f);
            out[((size_t)y * desc.Width + x) * 4 + 2] = (BYTE)(fx_sat(o[0]) * 255.0f + 0.5f);
            out[((size_t)y * desc.Width + x) * 4 + 3] = (BYTE)(fx_sat(o[3]) * 255.0f + 0.5f);
        }
    }
    ID3D11DeviceContext_Unmap(d3d_context, (ID3D11Resource *)staging, 0);
    ID3D11DeviceContext_UpdateSubresource(d3d_context, bitmap->resource, 0, &box, out, desc.Width * 4, 0);
    free(out);
    ID3D11DeviceContext_Release(d3d_context);
    ID3D11Texture2D_Release(staging);
    ID3D11Texture2D_Release(tex);
    return TRUE;
}

/* Draws an effect graph; returns FALSE when image is not an effect. */
BOOL d2d_device_context_draw_effect(struct d2d_device_context *context, ID2D1Image *image,
        const D2D1_POINT_2F *target_offset, const D2D1_RECT_F *image_rect, D2D1_INTERPOLATION_MODE interpolation_mode,
        D2D1_COMPOSITE_MODE composite_mode)
{
    D2D1_BITMAP_PROPERTIES1 props;
    D2D1_POINT_2F offset = {0.0f, 0.0f};
    struct d2d_bitmap *bitmap;
    struct fx_ctx ctx;
    struct fx_rect rc, limit;
    struct fx_image *img;
    BYTE *data;
    D2D1_SIZE_U size;
    size_t i, count;
    float dpi_x, dpi_y;
    HRESULT hr;

    if (!unsafe_impl_from_ID2D1Image(image))
        return FALSE;

    memset(&ctx, 0, sizeof(ctx));
    ctx.dc = context;
    if (context->drawing_state.unitMode == D2D1_UNIT_MODE_PIXELS)
    {
        ctx.sx = ctx.sy = 1.0f;
        dpi_x = dpi_y = 96.0f;
    }
    else
    {
        dpi_x = context->desc.dpiX > 0.0f ? context->desc.dpiX : 96.0f;
        dpi_y = context->desc.dpiY > 0.0f ? context->desc.dpiY : 96.0f;
        ctx.sx = dpi_x / 96.0f;
        ctx.sy = dpi_y / 96.0f;
    }

    if (target_offset)
        offset = *target_offset;

    rc = fx_bounds(&ctx, image);
    if (image_rect && image_rect->left <= image_rect->right && image_rect->top <= image_rect->bottom)
        rc = fx_intersect(rc, fx_rect_from_dips(&ctx, &image_rect->left));

    /* Unbounded results are limited to the target. */
    limit.l = fx_clampi(floor(-(double)offset.x * ctx.sx));
    limit.t = fx_clampi(floor(-(double)offset.y * ctx.sy));
    limit.r = fx_clampi(ceil((context->pixel_size.width - (double)offset.x * ctx.sx)));
    limit.b = fx_clampi(ceil((context->pixel_size.height - (double)offset.y * ctx.sy)));
    if (rc.l <= -FX_INF || rc.t <= -FX_INF || rc.r >= FX_INF || rc.b >= FX_INF)
        rc = fx_intersect(rc, limit);
    if (fx_empty(&rc))
        return TRUE;
    if ((unsigned long long)(rc.r - rc.l) * (rc.b - rc.t) > FX_MAX_PIXELS)
        rc = fx_intersect(rc, limit);
    if (fx_empty(&rc))
        return TRUE;

    ctx.depth = 0;
    if (!(img = fx_eval(&ctx, image, rc)))
        return TRUE;

    if (composite_mode != D2D1_COMPOSITE_MODE_SOURCE_OVER
            && fx_composite_to_target(context, img, (int)floor(offset.x * ctx.sx + 0.5) , (int)floor(offset.y * ctx.sy + 0.5), composite_mode))
    {
        fx_image_free(img);
        return TRUE;
    }
    if (composite_mode != D2D1_COMPOSITE_MODE_SOURCE_OVER)
        FIXME("Unhandled composite mode %#x.\n", composite_mode);

    size.width = rc.r - rc.l;
    size.height = rc.b - rc.t;
    count = (size_t)size.width * size.height;
    if (!(data = malloc(count * 4)))
    {
        fx_image_free(img);
        return TRUE;
    }
    for (i = 0; i < count; ++i)
    {
        const float *p = &img->px[i * 4];
        float a = fx_sat(p[3]);
        unsigned int c;

        for (c = 0; c < 3; ++c)
            data[i * 4 + (2 - c)] = (BYTE)(fx_sat(p[c]) * 255.0f + 0.5f);
        data[i * 4 + 3] = (BYTE)(a * 255.0f + 0.5f);
    }
    fx_image_free(img);

    props.pixelFormat.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    props.pixelFormat.alphaMode = D2D1_ALPHA_MODE_PREMULTIPLIED;
    props.dpiX = dpi_x;
    props.dpiY = dpi_y;
    props.bitmapOptions = D2D1_BITMAP_OPTIONS_NONE;
    props.colorContext = NULL;
    if (SUCCEEDED(hr = d2d_bitmap_create(context, size, data, size.width * 4, &props, &bitmap)))
    {
        D2D1_POINT_2F o;

        o.x = offset.x + rc.l / ctx.sx;
        o.y = offset.y + rc.t / ctx.sy;
        d2d_device_context_draw_bitmap_at(context, (ID2D1Bitmap *)&bitmap->ID2D1Bitmap1_iface, interpolation_mode, &o);
        ID2D1Bitmap1_Release(&bitmap->ID2D1Bitmap1_iface);
    }
    else
    {
        WARN("Failed to create the effect result bitmap, hr %#lx.\n", hr);
    }
    free(data);

    return TRUE;
}

/* The bounds of an effect graph in DIPs; FALSE when image is not an effect. */
BOOL d2d_device_context_get_effect_bounds(struct d2d_device_context *context, ID2D1Image *image, D2D1_RECT_F *bounds)
{
    struct fx_ctx ctx;
    struct fx_rect rc;

    if (!unsafe_impl_from_ID2D1Image(image))
        return FALSE;

    memset(&ctx, 0, sizeof(ctx));
    ctx.dc = context;
    if (context->drawing_state.unitMode == D2D1_UNIT_MODE_PIXELS)
    {
        ctx.sx = ctx.sy = 1.0f;
    }
    else
    {
        ctx.sx = (context->desc.dpiX > 0.0f ? context->desc.dpiX : 96.0f) / 96.0f;
        ctx.sy = (context->desc.dpiY > 0.0f ? context->desc.dpiY : 96.0f) / 96.0f;
    }

    rc = fx_bounds(&ctx, image);
    bounds->left = rc.l <= -FX_INF ? -3.402823e38f : rc.l / ctx.sx;
    bounds->top = rc.t <= -FX_INF ? -3.402823e38f : rc.t / ctx.sy;
    bounds->right = rc.r >= FX_INF ? 3.402823e38f : rc.r / ctx.sx;
    bounds->bottom = rc.b >= FX_INF ? 3.402823e38f : rc.b / ctx.sy;
    return TRUE;
}
