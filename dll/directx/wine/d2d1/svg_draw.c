/*
 * Drawing of ID2D1SvgDocument (ID2D1DeviceContext5::DrawSvgDocument) and the SVG path data parser.
 *
 * Original work for this tree.  The SVG semantics (path data grammar and error handling,
 * elliptical arc conversion, viewBox / preserveAspectRatio mapping, the fill and opacity
 * properties and their inheritance, the transform list) come from the public W3C
 * specifications (SVG 1.1 second edition, chapters 7, 8 and 9 and appendix F, and the
 * CSS colour syntax).  The enum values of the Direct2D attribute types come from
 * microsoft/windows-rs, see sdk/include/reactos/d2d1_svg.h; the aspect ratio enums are in the
 * same file at the same commit (D2D1_SVG_ASPECT_ALIGN: NONE 0, X_MIN_Y_MIN 1, X_MID_Y_MIN 2,
 * X_MAX_Y_MIN 3, X_MIN_Y_MID 4, X_MID_Y_MID 5, X_MAX_Y_MID 6, X_MIN_Y_MAX 7, X_MID_Y_MAX 8,
 * X_MAX_Y_MAX 9; D2D1_SVG_ASPECT_SCALING: MEET 0, SLICE 1; D2D1_SVG_PRESERVE_ASPECT_RATIO =
 * { BOOL defer, align, meetOrSlice }).  What Direct2D itself does beyond that is not known
 * here and is marked "verify on oracle".
 *
 * The drawing uses only the public ID2D1DeviceContext methods, so the same code draws on a
 * bitmap target and records into a command list target.
 *
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation; either version 2.1 of the License, or (at your option) any later version.
 */

#include "d2d1_private.h"
#include "svg_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d2d);

#define SVG_PI 3.14159265358979323846
#define SVG_MAX_DEPTH 64

/* ---------------------------------------------------------------- lexical helpers */

static BOOL svg_is_wsp(WCHAR c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}

static void svg_skip_wsp(const WCHAR **p)
{
    while (svg_is_wsp(**p))
        ++*p;
}

static void svg_skip_comma_wsp(const WCHAR **p)
{
    svg_skip_wsp(p);
    if (**p == ',')
    {
        ++*p;
        svg_skip_wsp(p);
    }
}

/* number ::= sign? (digits ('.' digits?)? | '.' digits) (('e'|'E') sign? digits)? */
static BOOL svg_parse_number(const WCHAR **p, double *out)
{
    const WCHAR *s = *p;
    double mantissa = 0.0, scale = 1.0, value;
    BOOL neg = FALSE, digits = FALSE;
    int exponent = 0;

    if (*s == '+' || *s == '-')
    {
        neg = *s == '-';
        ++s;
    }
    while (*s >= '0' && *s <= '9')
    {
        mantissa = mantissa * 10.0 + (*s - '0');
        digits = TRUE;
        ++s;
    }
    if (*s == '.')
    {
        ++s;
        while (*s >= '0' && *s <= '9')
        {
            mantissa = mantissa * 10.0 + (*s - '0');
            scale *= 10.0;
            digits = TRUE;
            ++s;
        }
    }
    if (!digits)
        return FALSE;

    if (*s == 'e' || *s == 'E')
    {
        const WCHAR *e = s + 1;
        BOOL eneg = FALSE;
        int ev = 0;

        if (*e == '+' || *e == '-')
        {
            eneg = *e == '-';
            ++e;
        }
        if (*e >= '0' && *e <= '9')
        {
            while (*e >= '0' && *e <= '9')
            {
                if (ev < 1000)
                    ev = ev * 10 + (*e - '0');
                ++e;
            }
            exponent = eneg ? -ev : ev;
            s = e;
        }
    }

    value = mantissa / scale;
    while (exponent > 0 && value < 1e300)
    {
        value *= 10.0;
        --exponent;
    }
    while (exponent < 0 && value > 1e-300)
    {
        value /= 10.0;
        ++exponent;
    }
    *out = neg ? -value : value;
    *p = s;
    return TRUE;
}

static BOOL svg_parse_flag(const WCHAR **p, BOOL *out)
{
    if (**p != '0' && **p != '1')
        return FALSE;
    *out = **p == '1';
    ++*p;
    return TRUE;
}

static BOOL svg_is_number_start(WCHAR c)
{
    return (c >= '0' && c <= '9') || c == '.' || c == '+' || c == '-';
}

/* ---------------------------------------------------------------- path data */

struct svg_path
{
    ID2D1GeometrySink *sink;
    BOOL figure_open;
    double cx, cy;      /* current point */
    double sx, sy;      /* start of the current subpath */
    double lx, ly;      /* last control point (for S and T) */
    int last;           /* 'c' after a cubic, 'q' after a quadratic, else 0 */
};

static D2D1_POINT_2F svg_pt(double x, double y)
{
    D2D1_POINT_2F p;

    p.x = x;
    p.y = y;
    return p;
}

static void svg_path_ensure_figure(struct svg_path *path)
{
    if (path->figure_open)
        return;
    ID2D1GeometrySink_BeginFigure(path->sink, svg_pt(path->cx, path->cy), D2D1_FIGURE_BEGIN_FILLED);
    path->figure_open = TRUE;
}

static void svg_path_end_figure(struct svg_path *path, D2D1_FIGURE_END mode)
{
    if (!path->figure_open)
        return;
    ID2D1GeometrySink_EndFigure(path->sink, mode);
    path->figure_open = FALSE;
}

static void svg_path_line(struct svg_path *path, double x, double y)
{
    svg_path_ensure_figure(path);
    ID2D1GeometrySink_AddLine(path->sink, svg_pt(x, y));
    path->cx = x;
    path->cy = y;
    path->last = 0;
}

static void svg_path_cubic(struct svg_path *path, double x1, double y1, double x2, double y2, double x, double y)
{
    D2D1_BEZIER_SEGMENT b;

    svg_path_ensure_figure(path);
    b.point1 = svg_pt(x1, y1);
    b.point2 = svg_pt(x2, y2);
    b.point3 = svg_pt(x, y);
    ID2D1GeometrySink_AddBezier(path->sink, &b);
    path->lx = x2;
    path->ly = y2;
    path->cx = x;
    path->cy = y;
    path->last = 'c';
}

static void svg_path_quad(struct svg_path *path, double x1, double y1, double x, double y)
{
    D2D1_QUADRATIC_BEZIER_SEGMENT q;

    svg_path_ensure_figure(path);
    q.point1 = svg_pt(x1, y1);
    q.point2 = svg_pt(x, y);
    ID2D1GeometrySink_AddQuadraticBezier(path->sink, &q);
    path->lx = x1;
    path->ly = y1;
    path->cx = x;
    path->cy = y;
    path->last = 'q';
}

/* SVG 1.1 F.6: endpoint parameterization to centre parameterization, then cubic pieces of at most 90 degrees */
static void svg_path_arc(struct svg_path *path, double rx, double ry, double rotation, BOOL large, BOOL sweep,
        double x, double y)
{
    double x1 = path->cx, y1 = path->cy;
    double phi, cosp, sinp, dx2, dy2, x1p, y1p, lambda, num, den, coef, cxp, cyp, cx, cy;
    double theta1, dtheta, delta, t;
    int i, n;

    if (x1 == x && y1 == y)
        return; /* the segment is omitted */

    rx = fabs(rx);
    ry = fabs(ry);
    if (rx == 0.0 || ry == 0.0)
    {
        svg_path_line(path, x, y);
        return;
    }

    phi = fmod(rotation, 360.0) * SVG_PI / 180.0;
    cosp = cos(phi);
    sinp = sin(phi);
    dx2 = (x1 - x) / 2.0;
    dy2 = (y1 - y) / 2.0;
    x1p = cosp * dx2 + sinp * dy2;
    y1p = -sinp * dx2 + cosp * dy2;

    lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry);
    if (lambda > 1.0)
    {
        lambda = sqrt(lambda);
        rx *= lambda;
        ry *= lambda;
    }

    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p;
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p;
    coef = den != 0.0 && num > 0.0 ? sqrt(num / den) : 0.0;
    if (large == sweep)
        coef = -coef;
    cxp = coef * rx * y1p / ry;
    cyp = -coef * ry * x1p / rx;
    cx = cosp * cxp - sinp * cyp + (x1 + x) / 2.0;
    cy = sinp * cxp + cosp * cyp + (y1 + y) / 2.0;

    theta1 = atan2((y1p - cyp) / ry, (x1p - cxp) / rx);
    dtheta = atan2((-y1p - cyp) / ry, (-x1p - cxp) / rx) - theta1;
    if (!sweep && dtheta > 0.0)
        dtheta -= 2.0 * SVG_PI;
    else if (sweep && dtheta < 0.0)
        dtheta += 2.0 * SVG_PI;

    n = (int)ceil(fabs(dtheta) / (SVG_PI / 2.0) - 1e-9);
    if (n < 1)
        n = 1;
    delta = dtheta / n;
    t = 4.0 / 3.0 * tan(delta / 4.0);

    for (i = 0; i < n; ++i)
    {
        double a1 = theta1 + i * delta, a2 = a1 + delta;
        double u[6] = {cos(a1) - t * sin(a1), sin(a1) + t * cos(a1), cos(a2) + t * sin(a2), sin(a2) - t * cos(a2),
                cos(a2), sin(a2)};
        double px[3], py[3];
        int k;

        for (k = 0; k < 3; ++k)
        {
            px[k] = cx + rx * u[2 * k] * cosp - ry * u[2 * k + 1] * sinp;
            py[k] = cy + rx * u[2 * k] * sinp + ry * u[2 * k + 1] * cosp;
        }
        if (i == n - 1)
        {
            px[2] = x;
            py[2] = y;
        }
        svg_path_cubic(path, px[0], py[0], px[1], py[1], px[2], py[2]);
    }
    path->last = 0;
}

static unsigned int svg_path_param_count(WCHAR cmd)
{
    switch (cmd)
    {
        case 'M': case 'L': case 'T': return 2;
        case 'H': case 'V': return 1;
        case 'C': return 6;
        case 'S': case 'Q': return 4;
        case 'A': return 7;
        default: return 0;
    }
}

/* Parses the 'd' attribute into the open geometry sink.  On an error the path is rendered up to the
 * last complete segment (SVG 1.1 8.3.9).  Returns the number of parsed segments. */
static unsigned int svg_parse_path_data(const WCHAR *d, ID2D1GeometrySink *sink)
{
    struct svg_path path;
    const WCHAR *p = d;
    WCHAR cmd = 0;
    BOOL first = TRUE;
    unsigned int segments = 0;

    memset(&path, 0, sizeof(path));
    path.sink = sink;

    for (;;)
    {
        WCHAR up;
        BOOL rel;
        double v[7];
        BOOL flag_large = FALSE, flag_sweep = FALSE;
        unsigned int count, i;

        svg_skip_wsp(&p);
        if (!*p)
            break;

        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))
        {
            cmd = *p++;
            svg_skip_wsp(&p);
            up = cmd & ~0x20;
            if (up != 'M' && up != 'L' && up != 'H' && up != 'V' && up != 'C' && up != 'S' && up != 'Q'
                    && up != 'T' && up != 'A' && up != 'Z')
                break;
        }
        else if (cmd && (cmd | 0x20) != 'z' && svg_is_number_start(*p))
        {
            /* implicit repetition; moveto continues as lineto */
            if (cmd == 'M')
                cmd = 'L';
            else if (cmd == 'm')
                cmd = 'l';
        }
        else
            break;

        if (first && cmd != 'M' && cmd != 'm')
            break; /* a path has to start with a moveto */
        first = FALSE;

        up = cmd & ~0x20;
        rel = cmd >= 'a';

        if (up == 'Z')
        {
            svg_path_end_figure(&path, D2D1_FIGURE_END_CLOSED);
            path.cx = path.sx;
            path.cy = path.sy;
            path.last = 0;
            ++segments;
            continue;
        }

        count = svg_path_param_count(up);
        for (i = 0; i < count; ++i)
        {
            if (i)
                svg_skip_comma_wsp(&p);
            if (up == 'A' && (i == 3 || i == 4))
            {
                BOOL f;

                if (!svg_parse_flag(&p, &f))
                    goto done;
                if (i == 3)
                    flag_large = f;
                else
                    flag_sweep = f;
                v[i] = f;
            }
            else if (!svg_parse_number(&p, &v[i]))
                goto done;
        }
        svg_skip_comma_wsp(&p);

        switch (up)
        {
            case 'M':
                svg_path_end_figure(&path, D2D1_FIGURE_END_OPEN);
                path.cx = (rel ? path.cx : 0.0) + v[0];
                path.cy = (rel ? path.cy : 0.0) + v[1];
                path.sx = path.cx;
                path.sy = path.cy;
                path.last = 0;
                break;
            case 'L':
                svg_path_line(&path, (rel ? path.cx : 0.0) + v[0], (rel ? path.cy : 0.0) + v[1]);
                break;
            case 'H':
                svg_path_line(&path, (rel ? path.cx : 0.0) + v[0], path.cy);
                break;
            case 'V':
                svg_path_line(&path, path.cx, (rel ? path.cy : 0.0) + v[0]);
                break;
            case 'C':
            {
                double ox = rel ? path.cx : 0.0, oy = rel ? path.cy : 0.0;

                svg_path_cubic(&path, ox + v[0], oy + v[1], ox + v[2], oy + v[3], ox + v[4], oy + v[5]);
                break;
            }
            case 'S':
            {
                double ox = rel ? path.cx : 0.0, oy = rel ? path.cy : 0.0;
                double x1 = path.cx, y1 = path.cy;

                if (path.last == 'c')
                {
                    x1 = 2.0 * path.cx - path.lx;
                    y1 = 2.0 * path.cy - path.ly;
                }
                svg_path_cubic(&path, x1, y1, ox + v[0], oy + v[1], ox + v[2], oy + v[3]);
                break;
            }
            case 'Q':
            {
                double ox = rel ? path.cx : 0.0, oy = rel ? path.cy : 0.0;

                svg_path_quad(&path, ox + v[0], oy + v[1], ox + v[2], oy + v[3]);
                break;
            }
            case 'T':
            {
                double x1 = path.cx, y1 = path.cy;

                if (path.last == 'q')
                {
                    x1 = 2.0 * path.cx - path.lx;
                    y1 = 2.0 * path.cy - path.ly;
                }
                svg_path_quad(&path, x1, y1, (rel ? path.cx : 0.0) + v[0], (rel ? path.cy : 0.0) + v[1]);
                break;
            }
            case 'A':
                svg_path_arc(&path, v[0], v[1], v[2], flag_large, flag_sweep, (rel ? path.cx : 0.0) + v[5],
                        (rel ? path.cy : 0.0) + v[6]);
                break;
        }
        ++segments;
    }

done:
    svg_path_end_figure(&path, D2D1_FIGURE_END_OPEN);
    return segments;
}

/* ---------------------------------------------------------------- attribute access */

static struct d2d_svg_attr *svg_find_attr(struct d2d_svg_element *element, const WCHAR *name)
{
    struct d2d_svg_attr *attr;

    LIST_FOR_EACH_ENTRY(attr, &element->attributes, struct d2d_svg_attr, entry)
    {
        if (!wcscmp(attr->name, name))
            return attr;
    }
    return NULL;
}

static BOOL svg_attr_is_pod(const struct d2d_svg_attr *attr, D2D1_SVG_ATTRIBUTE_POD_TYPE type, UINT32 size)
{
    return attr->kind == D2D_SVG_ATTR_POD && attr->pod_type == type && attr->pod && attr->pod_size >= size;
}

static BOOL svg_attr_is_string(const struct d2d_svg_attr *attr)
{
    return attr->kind == D2D_SVG_ATTR_STRING && attr->string;
}

static BOOL svg_wcsieq_prefix(const WCHAR *s, const char *lit)
{
    while (*lit)
    {
        WCHAR c = *s++;

        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
        if (c != (unsigned char)*lit++)
            return FALSE;
    }
    return TRUE;
}

static BOOL svg_wcsieq(const WCHAR *s, const char *lit)
{
    return svg_wcsieq_prefix(s, lit) && !s[strlen(lit)];
}

static int svg_hex(WCHAR c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const struct { const char *name; unsigned int rgb; } svg_named_colours[] =
{
    {"black", 0x000000}, {"silver", 0xc0c0c0}, {"gray", 0x808080}, {"grey", 0x808080}, {"white", 0xffffff},
    {"maroon", 0x800000}, {"red", 0xff0000}, {"purple", 0x800080}, {"fuchsia", 0xff00ff}, {"magenta", 0xff00ff},
    {"green", 0x008000}, {"lime", 0x00ff00}, {"olive", 0x808000}, {"yellow", 0xffff00}, {"navy", 0x000080},
    {"blue", 0x0000ff}, {"teal", 0x008080}, {"aqua", 0x00ffff}, {"cyan", 0x00ffff}, {"orange", 0xffa500},
    {"brown", 0xa52a2a}, {"pink", 0xffc0cb}, {"gold", 0xffd700}, {"darkgray", 0xa9a9a9}, {"darkgrey", 0xa9a9a9},
    {"lightgray", 0xd3d3d3}, {"lightgrey", 0xd3d3d3}, {"darkblue", 0x00008b}, {"darkred", 0x8b0000},
    {"darkgreen", 0x006400}, {"transparent", 0x000000},
};

enum svg_paint_kind { SVG_PAINT_INVALID, SVG_PAINT_NONE, SVG_PAINT_COLOR };

/* paint ::= none | currentColor | #rgb | #rgba | #rrggbb | #rrggbbaa | rgb(...) | rgba(...) | named colour */
static enum svg_paint_kind svg_parse_paint(const WCHAR *s, D2D1_COLOR_F *colour)
{
    unsigned int i;

    svg_skip_wsp(&s);
    colour->r = colour->g = colour->b = 0.0f;
    colour->a = 1.0f;

    if (svg_wcsieq_prefix(s, "none"))
        return SVG_PAINT_NONE;
    if (svg_wcsieq_prefix(s, "currentcolor"))
        return SVG_PAINT_COLOR; /* no 'color' property support: black */

    if (*s == '#')
    {
        int h[8], n = 0;

        for (++s; n < 8 && svg_hex(*s) >= 0; ++s)
            h[n++] = svg_hex(*s);
        if (n == 3 || n == 4)
        {
            colour->r = h[0] * 17 / 255.0f;
            colour->g = h[1] * 17 / 255.0f;
            colour->b = h[2] * 17 / 255.0f;
            if (n == 4)
                colour->a = h[3] * 17 / 255.0f;
            return SVG_PAINT_COLOR;
        }
        if (n == 6 || n == 8)
        {
            colour->r = (h[0] * 16 + h[1]) / 255.0f;
            colour->g = (h[2] * 16 + h[3]) / 255.0f;
            colour->b = (h[4] * 16 + h[5]) / 255.0f;
            if (n == 8)
                colour->a = (h[6] * 16 + h[7]) / 255.0f;
            return SVG_PAINT_COLOR;
        }
        return SVG_PAINT_INVALID;
    }

    if (svg_wcsieq_prefix(s, "rgb"))
    {
        double v[4];
        BOOL pct[4] = {FALSE};
        unsigned int n;

        s += 3;
        if (*s == 'a' || *s == 'A')
            ++s;
        svg_skip_wsp(&s);
        if (*s++ != '(')
            return SVG_PAINT_INVALID;
        for (n = 0; n < 4; ++n)
        {
            svg_skip_wsp(&s);
            if (*s == ')')
                break;
            if (!svg_parse_number(&s, &v[n]))
                return SVG_PAINT_INVALID;
            if (*s == '%')
            {
                pct[n] = TRUE;
                ++s;
            }
            svg_skip_wsp(&s);
            if (*s == ',' || *s == '/')
                ++s;
        }
        svg_skip_wsp(&s);
        if (*s != ')' || n < 3)
            return SVG_PAINT_INVALID;
        for (i = 0; i < 3; ++i)
        {
            double c = pct[i] ? v[i] / 100.0 : v[i] / 255.0;

            ((float *)colour)[i] = c < 0.0 ? 0.0f : c > 1.0 ? 1.0f : c;
        }
        if (n == 4)
        {
            double a = pct[3] ? v[3] / 100.0 : v[3];

            colour->a = a < 0.0 ? 0.0f : a > 1.0 ? 1.0f : a;
        }
        return SVG_PAINT_COLOR;
    }

    for (i = 0; i < ARRAY_SIZE(svg_named_colours); ++i)
    {
        if (svg_wcsieq(s, svg_named_colours[i].name))
        {
            unsigned int rgb = svg_named_colours[i].rgb;

            colour->r = ((rgb >> 16) & 0xff) / 255.0f;
            colour->g = ((rgb >> 8) & 0xff) / 255.0f;
            colour->b = (rgb & 0xff) / 255.0f;
            colour->a = i == ARRAY_SIZE(svg_named_colours) - 1 ? 0.0f : 1.0f;
            return SVG_PAINT_COLOR;
        }
    }
    return SVG_PAINT_INVALID;
}

/* returns FALSE when the attribute is not specified (or not understood) */
static BOOL svg_get_paint(struct d2d_svg_element *e, const WCHAR *name, enum svg_paint_kind *kind, D2D1_COLOR_F *c)
{
    struct d2d_svg_attr *attr;

    if (!(attr = svg_find_attr(e, name)))
        return FALSE;
    if (svg_attr_is_pod(attr, D2D1_SVG_ATTRIBUTE_POD_TYPE_COLOR, sizeof(*c)))
    {
        memcpy(c, attr->pod, sizeof(*c));
        *kind = SVG_PAINT_COLOR;
        return TRUE;
    }
    if (svg_attr_is_string(attr))
    {
        if ((*kind = svg_parse_paint(attr->string, c)) == SVG_PAINT_INVALID)
            return FALSE;
        return TRUE;
    }
    return FALSE;
}

static BOOL svg_get_float(struct d2d_svg_element *e, const WCHAR *name, double *out)
{
    struct d2d_svg_attr *attr;
    const WCHAR *s;

    if (!(attr = svg_find_attr(e, name)))
        return FALSE;
    if (svg_attr_is_pod(attr, D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT, sizeof(float)))
    {
        *out = *(const float *)attr->pod;
        return TRUE;
    }
    if (svg_attr_is_string(attr))
    {
        s = attr->string;
        svg_skip_wsp(&s);
        if (!svg_parse_number(&s, out))
            return FALSE;
        if (*s == '%')
            *out /= 100.0;
        return TRUE;
    }
    return FALSE;
}

static double svg_clamp01(double v)
{
    return v < 0.0 ? 0.0 : v > 1.0 ? 1.0 : v;
}

/* A length in user units; percentages are relative to 'reference'. */
static BOOL svg_parse_length_string(const WCHAR *s, double reference, double *out)
{
    double v;

    svg_skip_wsp(&s);
    if (!svg_parse_number(&s, &v))
        return FALSE;
    if (*s == '%')
        v = v * reference / 100.0;
    else if (svg_wcsieq(s, "px") || !*s)
        ;
    else if (svg_wcsieq(s, "pt"))
        v *= 96.0 / 72.0;
    else if (svg_wcsieq(s, "pc"))
        v *= 16.0;
    else if (svg_wcsieq(s, "in"))
        v *= 96.0;
    else if (svg_wcsieq(s, "cm"))
        v *= 96.0 / 2.54;
    else if (svg_wcsieq(s, "mm"))
        v *= 96.0 / 25.4;
    else
        return FALSE; /* em, ex: no font information here */
    *out = v;
    return TRUE;
}

static BOOL svg_get_length(struct d2d_svg_element *e, const WCHAR *name, double reference, double *out)
{
    struct d2d_svg_attr *attr;

    if (!(attr = svg_find_attr(e, name)))
        return FALSE;
    if (svg_attr_is_pod(attr, D2D1_SVG_ATTRIBUTE_POD_TYPE_LENGTH, sizeof(D2D1_SVG_LENGTH)))
    {
        const D2D1_SVG_LENGTH *l = attr->pod;

        *out = l->units == D2D1_SVG_LENGTH_UNITS_PERCENTAGE ? l->value * reference / 100.0 : l->value;
        return TRUE;
    }
    if (svg_attr_is_pod(attr, D2D1_SVG_ATTRIBUTE_POD_TYPE_FLOAT, sizeof(float)))
    {
        *out = *(const float *)attr->pod;
        return TRUE;
    }
    if (svg_attr_is_string(attr))
        return svg_parse_length_string(attr->string, reference, out);
    return FALSE;
}

/* returns 1 when the keyword (or POD value) selects 'second', 0 when 'first', -1 when unspecified */
static int svg_get_enum2(struct d2d_svg_element *e, const WCHAR *name, D2D1_SVG_ATTRIBUTE_POD_TYPE type,
        const char *first, const char *second, const char *second_alt)
{
    struct d2d_svg_attr *attr;

    if (!(attr = svg_find_attr(e, name)))
        return -1;
    if (svg_attr_is_pod(attr, type, sizeof(UINT32)))
        return *(const UINT32 *)attr->pod != 0;
    if (svg_attr_is_string(attr))
    {
        const WCHAR *s = attr->string;

        svg_skip_wsp(&s);
        if (svg_wcsieq_prefix(s, second) || (second_alt && svg_wcsieq_prefix(s, second_alt)))
            return 1;
        if (svg_wcsieq_prefix(s, first))
            return 0;
    }
    return -1;
}

static BOOL svg_get_viewbox(struct d2d_svg_element *e, D2D1_SVG_VIEWBOX *vb)
{
    struct d2d_svg_attr *attr;
    const WCHAR *s;
    double v[4];
    unsigned int i;

    if (!(attr = svg_find_attr(e, L"viewBox")))
        return FALSE;
    if (svg_attr_is_pod(attr, D2D1_SVG_ATTRIBUTE_POD_TYPE_VIEWBOX, sizeof(*vb)))
    {
        memcpy(vb, attr->pod, sizeof(*vb));
        return TRUE;
    }
    if (!svg_attr_is_string(attr))
        return FALSE;
    s = attr->string;
    svg_skip_wsp(&s);
    for (i = 0; i < 4; ++i)
    {
        if (i)
            svg_skip_comma_wsp(&s);
        if (!svg_parse_number(&s, &v[i]))
            return FALSE;
    }
    vb->x = v[0];
    vb->y = v[1];
    vb->width = v[2];
    vb->height = v[3];
    return TRUE;
}

struct svg_aspect
{
    UINT32 defer;
    UINT32 align;       /* D2D1_SVG_ASPECT_ALIGN */
    UINT32 meet_or_slice;
};

static struct svg_aspect svg_get_aspect(struct d2d_svg_element *e)
{
    struct svg_aspect a = {FALSE, 5 /* xMidYMid */, 0 /* meet */};
    struct d2d_svg_attr *attr;

    if (!(attr = svg_find_attr(e, L"preserveAspectRatio")))
        return a;
    if (svg_attr_is_pod(attr, D2D1_SVG_ATTRIBUTE_POD_TYPE_PRESERVE_ASPECT_RATIO, sizeof(a)))
    {
        memcpy(&a, attr->pod, sizeof(a));
        return a;
    }
    if (svg_attr_is_string(attr))
    {
        static const char *const names[] = {"none", "xminymin", "xmidymin", "xmaxymin", "xminymid", "xmidymid",
                "xmaxymid", "xminymax", "xmidymax", "xmaxymax"};
        const WCHAR *s = attr->string;
        unsigned int i;

        svg_skip_wsp(&s);
        if (svg_wcsieq_prefix(s, "defer") && svg_is_wsp(s[5]))
        {
            a.defer = TRUE;
            s += 5;
            svg_skip_wsp(&s);
        }
        for (i = 0; i < ARRAY_SIZE(names); ++i)
        {
            if (svg_wcsieq_prefix(s, names[i]))
            {
                a.align = i;
                s += strlen(names[i]);
                break;
            }
        }
        svg_skip_wsp(&s);
        if (svg_wcsieq_prefix(s, "slice"))
            a.meet_or_slice = 1;
    }
    return a;
}

/* ---------------------------------------------------------------- transforms */

/* row vector convention of Direct2D: p' = p * M, "a then b" = a * b */
static D2D1_MATRIX_3X2_F svg_mul(const D2D1_MATRIX_3X2_F *a, const D2D1_MATRIX_3X2_F *b)
{
    D2D1_MATRIX_3X2_F r;

    r._11 = a->_11 * b->_11 + a->_12 * b->_21;
    r._12 = a->_11 * b->_12 + a->_12 * b->_22;
    r._21 = a->_21 * b->_11 + a->_22 * b->_21;
    r._22 = a->_21 * b->_12 + a->_22 * b->_22;
    r._31 = a->_31 * b->_11 + a->_32 * b->_21 + b->_31;
    r._32 = a->_31 * b->_12 + a->_32 * b->_22 + b->_32;
    return r;
}

static D2D1_MATRIX_3X2_F svg_matrix(double a, double b, double c, double d, double e, double f)
{
    D2D1_MATRIX_3X2_F m;

    m._11 = a; m._12 = b; m._21 = c; m._22 = d; m._31 = e; m._32 = f;
    return m;
}

/* SVG 1.1 7.6 transform list; returns FALSE on a syntax error (the transform is then ignored) */
static BOOL svg_parse_transform_list(const WCHAR *s, D2D1_MATRIX_3X2_F *out)
{
    D2D1_MATRIX_3X2_F acc = svg_matrix(1, 0, 0, 1, 0, 0), m;

    for (;;)
    {
        double v[6];
        unsigned int n = 0, need_min, need_max;
        const char *kind;

        svg_skip_comma_wsp(&s);
        if (!*s)
            break;
        if (svg_wcsieq_prefix(s, kind = "matrix")) { need_min = need_max = 6; }
        else if (svg_wcsieq_prefix(s, kind = "translate")) { need_min = 1; need_max = 2; }
        else if (svg_wcsieq_prefix(s, kind = "scale")) { need_min = 1; need_max = 2; }
        else if (svg_wcsieq_prefix(s, kind = "rotate")) { need_min = 1; need_max = 3; }
        else if (svg_wcsieq_prefix(s, kind = "skewx")) { need_min = need_max = 1; }
        else if (svg_wcsieq_prefix(s, kind = "skewy")) { need_min = need_max = 1; }
        else
            return FALSE;
        s += strlen(kind);
        svg_skip_wsp(&s);
        if (*s++ != '(')
            return FALSE;
        for (;;)
        {
            svg_skip_comma_wsp(&s);
            if (*s == ')')
                break;
            if (n == need_max || !svg_parse_number(&s, &v[n]))
                return FALSE;
            ++n;
        }
        ++s;
        if (n < need_min)
            return FALSE;

        if (!strcmp(kind, "matrix"))
            m = svg_matrix(v[0], v[1], v[2], v[3], v[4], v[5]);
        else if (!strcmp(kind, "translate"))
            m = svg_matrix(1, 0, 0, 1, v[0], n > 1 ? v[1] : 0.0);
        else if (!strcmp(kind, "scale"))
            m = svg_matrix(v[0], 0, 0, n > 1 ? v[1] : v[0], 0, 0);
        else if (!strcmp(kind, "rotate"))
        {
            double r = v[0] * SVG_PI / 180.0, cs = cos(r), sn = sin(r);
            D2D1_MATRIX_3X2_F t1 = svg_matrix(1, 0, 0, 1, n > 1 ? v[1] : 0.0, n > 2 ? v[2] : 0.0);
            D2D1_MATRIX_3X2_F t2 = svg_matrix(1, 0, 0, 1, n > 1 ? -v[1] : 0.0, n > 2 ? -v[2] : 0.0);
            D2D1_MATRIX_3X2_F rot = svg_matrix(cs, sn, -sn, cs, 0, 0);

            /* translate(cx cy) rotate(a) translate(-cx -cy), column form; row form is the reverse order */
            m = svg_mul(&t2, &rot);
            m = svg_mul(&m, &t1);
        }
        else if (!strcmp(kind, "skewx"))
            m = svg_matrix(1, 0, tan(v[0] * SVG_PI / 180.0), 1, 0, 0);
        else
            m = svg_matrix(1, tan(v[0] * SVG_PI / 180.0), 0, 1, 0, 0);

        acc = svg_mul(&m, &acc);
    }
    *out = acc;
    return TRUE;
}

static BOOL svg_get_transform(struct d2d_svg_element *e, D2D1_MATRIX_3X2_F *m)
{
    struct d2d_svg_attr *attr;

    if (!(attr = svg_find_attr(e, L"transform")))
        return FALSE;
    if (svg_attr_is_pod(attr, D2D1_SVG_ATTRIBUTE_POD_TYPE_MATRIX, sizeof(*m)))
    {
        memcpy(m, attr->pod, sizeof(*m));
        return TRUE;
    }
    if (svg_attr_is_string(attr))
        return svg_parse_transform_list(attr->string, m);
    return FALSE;
}

/* ---------------------------------------------------------------- drawing */

struct svg_style
{
    enum svg_paint_kind fill_kind;
    D2D1_COLOR_F fill;
    double fill_opacity;
    D2D1_FILL_MODE fill_rule;
    D2D1_FILL_MODE clip_rule;
    enum svg_paint_kind stroke_kind;
    D2D1_COLOR_F stroke;
    double stroke_opacity;
    double stroke_width;
    double opacity;     /* accumulated 'opacity' of the ancestors (applied per object here) */
    BOOL visible;
};

struct svg_draw
{
    ID2D1DeviceContext *context;
    ID2D1Factory *factory;
    ID2D1SolidColorBrush *brush;
    double ref_w, ref_h;    /* reference for percentages */
};

/* FIXME once per kind (the tables are small and racy on purpose: a duplicate message is harmless) */
static void svg_fixme_once(const char *what, const WCHAR *name)
{
    static WCHAR seen[16][24];
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(seen); ++i)
    {
        if (!seen[i][0])
            break;
        if (!wcsncmp(seen[i], name, ARRAY_SIZE(seen[i]) - 1))
            return;
    }
    if (i < ARRAY_SIZE(seen))
        wcsncpy(seen[i], name, ARRAY_SIZE(seen[i]) - 1);
    FIXME("%s %s is not supported by DrawSvgDocument.\n", what, debugstr_w(name));
}

static void svg_style_apply(struct d2d_svg_element *e, struct svg_style *st)
{
    D2D1_COLOR_F c;
    enum svg_paint_kind kind;
    double v;
    int i;

    if (svg_get_paint(e, L"fill", &kind, &c))
    {
        st->fill_kind = kind;
        st->fill = c;
    }
    if (svg_get_paint(e, L"stroke", &kind, &c))
    {
        st->stroke_kind = kind;
        st->stroke = c;
    }
    if (svg_get_float(e, L"fill-opacity", &v))
        st->fill_opacity = svg_clamp01(v);
    if (svg_get_float(e, L"stroke-opacity", &v))
        st->stroke_opacity = svg_clamp01(v);
    if (svg_get_float(e, L"stroke-width", &v) && v >= 0.0)
        st->stroke_width = v;
    if ((i = svg_get_enum2(e, L"fill-rule", D2D1_SVG_ATTRIBUTE_POD_TYPE_FILL_MODE, "nonzero", "evenodd", NULL)) >= 0)
    {
        /* the POD value is a D2D1_FILL_MODE (ALTERNATE 0, WINDING 1), the keywords are the opposite way round */
        struct d2d_svg_attr *attr = svg_find_attr(e, L"fill-rule");

        if (attr->kind == D2D_SVG_ATTR_POD)
            st->fill_rule = *(const UINT32 *)attr->pod ? D2D1_FILL_MODE_WINDING : D2D1_FILL_MODE_ALTERNATE;
        else
            st->fill_rule = i ? D2D1_FILL_MODE_ALTERNATE : D2D1_FILL_MODE_WINDING;
    }
    if ((i = svg_get_enum2(e, L"clip-rule", D2D1_SVG_ATTRIBUTE_POD_TYPE_FILL_MODE, "nonzero", "evenodd", NULL)) >= 0)
    {
        struct d2d_svg_attr *attr = svg_find_attr(e, L"clip-rule");

        if (attr->kind == D2D_SVG_ATTR_POD)
            st->clip_rule = *(const UINT32 *)attr->pod ? D2D1_FILL_MODE_WINDING : D2D1_FILL_MODE_ALTERNATE;
        else
            st->clip_rule = i ? D2D1_FILL_MODE_ALTERNATE : D2D1_FILL_MODE_WINDING;
    }
    if (svg_get_float(e, L"opacity", &v))
        st->opacity *= svg_clamp01(v);
    if ((i = svg_get_enum2(e, L"visibility", D2D1_SVG_ATTRIBUTE_POD_TYPE_VISIBILITY, "visible", "hidden",
            "collapse")) >= 0)
        st->visible = !i;

    if (svg_find_attr(e, L"stroke-dasharray") || svg_find_attr(e, L"stroke-linecap")
            || svg_find_attr(e, L"stroke-linejoin") || svg_find_attr(e, L"stroke-miterlimit"))
        svg_fixme_once("stroke attribute", L"dash/cap/join/miter");
    if (svg_find_attr(e, L"clip-path") || svg_find_attr(e, L"mask") || svg_find_attr(e, L"filter"))
        svg_fixme_once("attribute", L"clip-path/mask/filter");
}

static void svg_set_world(struct svg_draw *dc, const D2D1_MATRIX_3X2_F *world)
{
    ID2D1DeviceContext_SetTransform(dc->context, world);
}

static void svg_fill_geometry(struct svg_draw *dc, ID2D1Geometry *geometry, const struct svg_style *st)
{
    if (st->fill_kind == SVG_PAINT_COLOR)
    {
        D2D1_COLOR_F c = st->fill;

        c.a *= st->fill_opacity * st->opacity;
        ID2D1SolidColorBrush_SetColor(dc->brush, &c);
        ID2D1SolidColorBrush_SetOpacity(dc->brush, 1.0f);
        ID2D1DeviceContext_FillGeometry(dc->context, geometry, (ID2D1Brush *)dc->brush, NULL);
    }
    if (st->stroke_kind == SVG_PAINT_COLOR && st->stroke_width > 0.0)
    {
        D2D1_COLOR_F c = st->stroke;

        c.a *= st->stroke_opacity * st->opacity;
        ID2D1SolidColorBrush_SetColor(dc->brush, &c);
        ID2D1SolidColorBrush_SetOpacity(dc->brush, 1.0f);
        ID2D1DeviceContext_DrawGeometry(dc->context, geometry, (ID2D1Brush *)dc->brush, st->stroke_width, NULL);
    }
}

static void svg_draw_path_data(struct svg_draw *dc, const WCHAR *d, const struct svg_style *st)
{
    ID2D1PathGeometry *geometry;
    ID2D1GeometrySink *sink;

    if (FAILED(ID2D1Factory_CreatePathGeometry(dc->factory, &geometry)))
        return;
    if (SUCCEEDED(ID2D1PathGeometry_Open(geometry, &sink)))
    {
        ID2D1GeometrySink_SetFillMode(sink, st->fill_rule);
        svg_parse_path_data(d, sink);
        if (SUCCEEDED(ID2D1GeometrySink_Close(sink)))
            svg_fill_geometry(dc, (ID2D1Geometry *)geometry, st);
        ID2D1GeometrySink_Release(sink);
    }
    ID2D1PathGeometry_Release(geometry);
}

static void svg_draw_points(struct svg_draw *dc, struct d2d_svg_element *e, BOOL closed, const struct svg_style *st)
{
    struct d2d_svg_attr *attr = svg_find_attr(e, L"points");
    ID2D1PathGeometry *geometry;
    ID2D1GeometrySink *sink;
    const WCHAR *s;
    unsigned int n = 0;
    double x, y;

    if (!attr || !svg_attr_is_string(attr))
        return;
    if (FAILED(ID2D1Factory_CreatePathGeometry(dc->factory, &geometry)))
        return;
    if (SUCCEEDED(ID2D1PathGeometry_Open(geometry, &sink)))
    {
        ID2D1GeometrySink_SetFillMode(sink, st->fill_rule);
        s = attr->string;
        for (;;)
        {
            svg_skip_comma_wsp(&s);
            if (!svg_parse_number(&s, &x))
                break;
            svg_skip_comma_wsp(&s);
            if (!svg_parse_number(&s, &y))
                break; /* an odd number of values: the last one is dropped */
            if (!n)
                ID2D1GeometrySink_BeginFigure(sink, svg_pt(x, y), D2D1_FIGURE_BEGIN_FILLED);
            else
                ID2D1GeometrySink_AddLine(sink, svg_pt(x, y));
            ++n;
        }
        if (n)
            ID2D1GeometrySink_EndFigure(sink, closed ? D2D1_FIGURE_END_CLOSED : D2D1_FIGURE_END_OPEN);
        if (SUCCEEDED(ID2D1GeometrySink_Close(sink)) && n > 1)
            svg_fill_geometry(dc, (ID2D1Geometry *)geometry, st);
        ID2D1GeometrySink_Release(sink);
    }
    ID2D1PathGeometry_Release(geometry);
}

static void svg_draw_rect(struct svg_draw *dc, struct d2d_svg_element *e, const struct svg_style *st)
{
    double x = 0.0, y = 0.0, w = 0.0, h = 0.0, rx = -1.0, ry = -1.0;
    D2D1_ROUNDED_RECT rr;
    ID2D1Geometry *geometry;

    svg_get_length(e, L"x", dc->ref_w, &x);
    svg_get_length(e, L"y", dc->ref_h, &y);
    if (!svg_get_length(e, L"width", dc->ref_w, &w) || !svg_get_length(e, L"height", dc->ref_h, &h))
        return;
    if (!(w > 0.0) || !(h > 0.0))
        return; /* disables the rendering */
    svg_get_length(e, L"rx", dc->ref_w, &rx);
    svg_get_length(e, L"ry", dc->ref_h, &ry);
    if (rx < 0.0 && ry < 0.0)
        rx = ry = 0.0;
    else if (rx < 0.0)
        rx = ry;
    else if (ry < 0.0)
        ry = rx;
    rx = min(rx, w / 2.0);
    ry = min(ry, h / 2.0);

    rr.rect.left = x;
    rr.rect.top = y;
    rr.rect.right = x + w;
    rr.rect.bottom = y + h;
    rr.radiusX = rx;
    rr.radiusY = ry;
    if (rx > 0.0 && ry > 0.0)
    {
        ID2D1RoundedRectangleGeometry *g;

        if (FAILED(ID2D1Factory_CreateRoundedRectangleGeometry(dc->factory, &rr, &g)))
            return;
        svg_fill_geometry(dc, (ID2D1Geometry *)g, st);
        ID2D1RoundedRectangleGeometry_Release(g);
    }
    else
    {
        ID2D1RectangleGeometry *g;

        if (FAILED(ID2D1Factory_CreateRectangleGeometry(dc->factory, &rr.rect, &g)))
            return;
        geometry = (ID2D1Geometry *)g;
        svg_fill_geometry(dc, geometry, st);
        ID2D1RectangleGeometry_Release(g);
    }
}

static void svg_draw_ellipse(struct svg_draw *dc, struct d2d_svg_element *e, BOOL circle, const struct svg_style *st)
{
    double cx = 0.0, cy = 0.0, rx = 0.0, ry = 0.0, diag;
    ID2D1EllipseGeometry *g;
    D2D1_ELLIPSE ellipse;

    svg_get_length(e, L"cx", dc->ref_w, &cx);
    svg_get_length(e, L"cy", dc->ref_h, &cy);
    if (circle)
    {
        diag = sqrt((dc->ref_w * dc->ref_w + dc->ref_h * dc->ref_h) / 2.0);
        if (!svg_get_length(e, L"r", diag, &rx))
            return;
        ry = rx;
    }
    else if (!svg_get_length(e, L"rx", dc->ref_w, &rx) || !svg_get_length(e, L"ry", dc->ref_h, &ry))
        return;
    if (!(rx > 0.0) || !(ry > 0.0))
        return;

    ellipse.point = svg_pt(cx, cy);
    ellipse.radiusX = rx;
    ellipse.radiusY = ry;
    if (FAILED(ID2D1Factory_CreateEllipseGeometry(dc->factory, &ellipse, &g)))
        return;
    svg_fill_geometry(dc, (ID2D1Geometry *)g, st);
    ID2D1EllipseGeometry_Release(g);
}

static void svg_draw_element(struct svg_draw *dc, struct d2d_svg_element *e, const struct svg_style *parent_style,
        const D2D1_MATRIX_3X2_F *parent_world, unsigned int depth, BOOL is_root)
{
    struct d2d_svg_element *child;
    D2D1_MATRIX_3X2_F world = *parent_world, local;
    struct svg_style st = *parent_style;
    struct d2d_svg_attr *attr;
    int display;

    if (depth > SVG_MAX_DEPTH)
    {
        WARN("Element nesting too deep.\n");
        return;
    }

    if ((display = svg_get_enum2(e, L"display", D2D1_SVG_ATTRIBUTE_POD_TYPE_DISPLAY, "inline", "none", NULL)) > 0)
        return;

    svg_style_apply(e, &st);

    if (!is_root && svg_get_transform(e, &local))
        world = svg_mul(&local, parent_world);

    if (is_root || !wcscmp(e->tag, L"g"))
    {
        LIST_FOR_EACH_ENTRY(child, &e->children, struct d2d_svg_element, sibling_entry)
            svg_draw_element(dc, child, &st, &world, depth + 1, FALSE);
        return;
    }

    if (!wcscmp(e->tag, L"defs") || !wcscmp(e->tag, L"title") || !wcscmp(e->tag, L"desc")
            || !wcscmp(e->tag, L"metadata"))
        return;

    if (!wcscmp(e->tag, L"path") || !wcscmp(e->tag, L"rect") || !wcscmp(e->tag, L"circle")
            || !wcscmp(e->tag, L"ellipse") || !wcscmp(e->tag, L"polygon") || !wcscmp(e->tag, L"polyline"))
    {
        if (!st.visible)
            return;
        svg_set_world(dc, &world);
        if (!wcscmp(e->tag, L"path"))
        {
            if ((attr = svg_find_attr(e, L"d")) && svg_attr_is_string(attr))
                svg_draw_path_data(dc, attr->string, &st);
        }
        else if (!wcscmp(e->tag, L"rect"))
            svg_draw_rect(dc, e, &st);
        else if (!wcscmp(e->tag, L"circle"))
            svg_draw_ellipse(dc, e, TRUE, &st);
        else if (!wcscmp(e->tag, L"ellipse"))
            svg_draw_ellipse(dc, e, FALSE, &st);
        else
            svg_draw_points(dc, e, !wcscmp(e->tag, L"polygon"), &st);
        return;
    }

    if (!wcscmp(e->tag, L"line"))
    {
        /* a line has no area: only a stroke would be drawn */
        if (st.stroke_kind == SVG_PAINT_COLOR && st.stroke_width > 0.0 && st.visible)
        {
            double x1 = 0.0, y1 = 0.0, x2 = 0.0, y2 = 0.0;
            D2D1_COLOR_F c = st.stroke;

            svg_get_length(e, L"x1", dc->ref_w, &x1);
            svg_get_length(e, L"y1", dc->ref_h, &y1);
            svg_get_length(e, L"x2", dc->ref_w, &x2);
            svg_get_length(e, L"y2", dc->ref_h, &y2);
            c.a *= st.stroke_opacity * st.opacity;
            ID2D1SolidColorBrush_SetColor(dc->brush, &c);
            svg_set_world(dc, &world);
            ID2D1DeviceContext_DrawLine(dc->context, svg_pt(x1, y1), svg_pt(x2, y2), (ID2D1Brush *)dc->brush,
                    st.stroke_width, NULL);
        }
        return;
    }

    svg_fixme_once("element", e->tag);
}

/* viewBox to viewport (SVG 1.1 7.8) */
static D2D1_MATRIX_3X2_F svg_viewbox_transform(const D2D1_SVG_VIEWBOX *vb, const struct svg_aspect *a, double w, double h)
{
    double sx = w / vb->width, sy = h / vb->height, s, tx, ty, ax = 0.0, ay = 0.0;

    if (a->align == 0 /* none */)
        return svg_matrix(sx, 0, 0, sy, -vb->x * sx, -vb->y * sy);

    s = a->meet_or_slice == 1 ? max(sx, sy) : min(sx, sy);
    switch (a->align)
    {
        case 2: case 5: case 8: ax = 0.5; break;
        case 3: case 6: case 9: ax = 1.0; break;
    }
    switch (a->align)
    {
        case 4: case 5: case 6: ay = 0.5; break;
        case 7: case 8: case 9: ay = 1.0; break;
    }
    tx = -vb->x * s + ax * (w - vb->width * s);
    ty = -vb->y * s + ay * (h - vb->height * s);
    return svg_matrix(s, 0, 0, s, tx, ty);
}

void d2d_svg_draw_document(struct d2d_svg_document *document, ID2D1DeviceContext *context)
{
    D2D1_MATRIX_3X2_F base, vt = svg_matrix(1, 0, 0, 1, 0, 0), world;
    struct d2d_svg_element *root = document->root;
    D2D1_COLOR_F black = {0.0f, 0.0f, 0.0f, 1.0f};
    struct svg_style style;
    struct svg_draw dc;
    struct svg_aspect aspect;
    D2D1_SVG_VIEWBOX vb;
    D2D1_RECT_F clip;
    double w = document->viewport.width, h = document->viewport.height;

    if (!root)
        return; /* verify on oracle: a document without a root */
    if (!(w > 0.0) || !(h > 0.0))
        return;

    memset(&dc, 0, sizeof(dc));
    dc.context = context;
    dc.factory = document->factory;
    dc.ref_w = w;
    dc.ref_h = h;

    memset(&style, 0, sizeof(style));
    style.fill_kind = SVG_PAINT_COLOR;
    style.fill = black;
    style.fill_opacity = 1.0;
    style.fill_rule = D2D1_FILL_MODE_WINDING;
    style.clip_rule = D2D1_FILL_MODE_WINDING;
    style.stroke_kind = SVG_PAINT_NONE;
    style.stroke_opacity = 1.0;
    style.stroke_width = 1.0;
    style.opacity = 1.0;
    style.visible = TRUE;

    ID2D1DeviceContext_GetTransform(context, &base);

    if (svg_get_viewbox(root, &vb))
    {
        if (!(vb.width > 0.0f) || !(vb.height > 0.0f))
            return; /* a zero or negative viewBox size disables the rendering (SVG 1.1 7.7) */
        dc.ref_w = vb.width;
        dc.ref_h = vb.height;
        aspect = svg_get_aspect(root);
        vt = svg_viewbox_transform(&vb, &aspect, w, h);
    }
    world = svg_mul(&vt, &base);

    if (FAILED(ID2D1DeviceContext_CreateSolidColorBrush(context, &black, NULL, &dc.brush)))
        return;

    /* The viewport clips the content (overflow of the root element is hidden; verify on oracle). */
    clip.left = 0.0f;
    clip.top = 0.0f;
    clip.right = w;
    clip.bottom = h;
    ID2D1DeviceContext_PushAxisAlignedClip(context, &clip, D2D1_ANTIALIAS_MODE_ALIASED);

    svg_draw_element(&dc, root, &style, &world, 0, TRUE);

    ID2D1DeviceContext_PopAxisAlignedClip(context);
    ID2D1DeviceContext_SetTransform(context, &base);
    ID2D1SolidColorBrush_Release(dc.brush);
}
