/*
 * Polygon boolean operations for ID2D1Geometry::CombineWithGeometry.
 *
 * Own implementation (not derived from Wine or any other code).
 *
 * Method: both inputs are polygons (each contour is implicitly closed) with a
 * fill rule. All coordinates are snapped to a fixed-point grid and every edge
 * is split at every point where it meets another edge, so that edges only
 * meet at end points (identical edges are merged, each one remembers by how
 * much it changes the winding number of input A and of input B). The winding
 * numbers of both inputs on either side of each edge follow from a vertical
 * (or, for vertical edges, horizontal) ray cast over the split edges. An edge
 * belongs to the result boundary when the result of the operation differs
 * between its two sides. Those edges are linked into closed contours with the
 * result inside on the left, so the output is a winding-fill region.
 */

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "combine_core.h"

#define CC_SCALE        128
#define CC_LIMIT        ((long long)1 << 20)
#define CC_MAX_PASSES   24

struct cc_point
{
    long long x, y;
};

struct cc_edge
{
    struct cc_point p, q; /* p < q lexicographically */
    int ca, cb;           /* winding change of A and B crossing p->q from right to left */
};

struct cc_edges
{
    struct cc_edge *e;
    size_t count, size;
};

struct cc_split
{
    size_t edge;
    struct cc_point pt;
    long long param;
};

static int cc_point_cmp(const struct cc_point *a, const struct cc_point *b)
{
    if (a->x != b->x)
        return a->x < b->x ? -1 : 1;
    if (a->y != b->y)
        return a->y < b->y ? -1 : 1;
    return 0;
}

static int cc_edge_cmp(const void *a, const void *b)
{
    const struct cc_edge *ea = a, *eb = b;
    int r;

    if ((r = cc_point_cmp(&ea->p, &eb->p)))
        return r;
    return cc_point_cmp(&ea->q, &eb->q);
}

static int cc_split_cmp(const void *a, const void *b)
{
    const struct cc_split *sa = a, *sb = b;

    if (sa->edge != sb->edge)
        return sa->edge < sb->edge ? -1 : 1;
    if (sa->param != sb->param)
        return sa->param < sb->param ? -1 : 1;
    return 0;
}

static int cc_edges_reserve(struct cc_edges *edges, size_t extra)
{
    struct cc_edge *tmp;
    size_t size;

    if (edges->count + extra <= edges->size)
        return 0;
    size = edges->size ? edges->size * 2 : 64;
    while (size < edges->count + extra)
        size *= 2;
    if (!(tmp = realloc(edges->e, size * sizeof(*tmp))))
        return -1;
    edges->e = tmp;
    edges->size = size;
    return 0;
}

static int cc_edges_add(struct cc_edges *edges, struct cc_point p, struct cc_point q, int ca, int cb)
{
    struct cc_edge *e;
    int c = cc_point_cmp(&p, &q);

    if (!c)
        return 0;
    if (cc_edges_reserve(edges, 1))
        return -1;
    e = &edges->e[edges->count++];
    if (c < 0)
    {
        e->p = p;
        e->q = q;
    }
    else
    {
        e->p = q;
        e->q = p;
        ca = -ca;
        cb = -cb;
    }
    e->ca = ca;
    e->cb = cb;
    return 0;
}

/* Sort, merge identical edges, drop edges that change nothing. */
static void cc_edges_normalize(struct cc_edges *edges)
{
    size_t i, out = 0;

    qsort(edges->e, edges->count, sizeof(*edges->e), cc_edge_cmp);
    for (i = 0; i < edges->count; ++i)
    {
        if (out && !cc_edge_cmp(&edges->e[out - 1], &edges->e[i]))
        {
            edges->e[out - 1].ca += edges->e[i].ca;
            edges->e[out - 1].cb += edges->e[i].cb;
            continue;
        }
        edges->e[out++] = edges->e[i];
    }
    edges->count = out;
    for (i = 0, out = 0; i < edges->count; ++i)
    {
        if (!edges->e[i].ca && !edges->e[i].cb)
            continue;
        edges->e[out++] = edges->e[i];
    }
    edges->count = out;
}

static long long cc_cross(const struct cc_point *a, const struct cc_point *b, const struct cc_point *c)
{
    return (b->x - a->x) * (c->y - a->y) - (b->y - a->y) * (c->x - a->x);
}

/* c is on the line a-b (checked by the caller); strictly between a and b? */
static int cc_strictly_between(const struct cc_point *a, const struct cc_point *b, const struct cc_point *c)
{
    if (!cc_point_cmp(c, a) || !cc_point_cmp(c, b))
        return 0;
    /* a < b lexicographically, so c is between them iff a < c < b. */
    return cc_point_cmp(a, c) < 0 && cc_point_cmp(c, b) < 0;
}

static int cc_add_split(struct cc_split **splits, size_t *count, size_t *size, size_t edge,
        const struct cc_edge *e, struct cc_point pt)
{
    struct cc_split *s;

    if (!cc_point_cmp(&pt, &e->p) || !cc_point_cmp(&pt, &e->q))
        return 0;
    if (*count == *size)
    {
        size_t new_size = *size ? *size * 2 : 64;
        struct cc_split *tmp;

        if (!(tmp = realloc(*splits, new_size * sizeof(*tmp))))
            return -1;
        *splits = tmp;
        *size = new_size;
    }
    s = &(*splits)[(*count)++];
    s->edge = edge;
    s->pt = pt;
    s->param = (pt.x - e->p.x) * (e->q.x - e->p.x) + (pt.y - e->p.y) * (e->q.y - e->p.y);
    return 0;
}

/* One pass: find all intersections, split. Returns 1 if something was split, 0 if not, -1 on OOM. */
static int cc_split_pass(struct cc_edges *edges)
{
    struct cc_split *splits = NULL;
    size_t count = 0, size = 0, i, j, k;
    struct cc_edges out = {0};
    int ret = 0;

    for (i = 0; i < edges->count; ++i)
    {
        const struct cc_edge *e = &edges->e[i];

        for (j = i + 1; j < edges->count; ++j)
        {
            const struct cc_edge *f = &edges->e[j];
            long long d1, d2, d3, d4, ymin, ymax;

            if (f->p.x > e->q.x)
                break;

            ymin = e->p.y < e->q.y ? e->p.y : e->q.y;
            ymax = e->p.y < e->q.y ? e->q.y : e->p.y;
            if ((f->p.y < f->q.y ? f->q.y : f->p.y) < ymin || (f->p.y < f->q.y ? f->p.y : f->q.y) > ymax)
                continue;

            d1 = cc_cross(&e->p, &e->q, &f->p);
            d2 = cc_cross(&e->p, &e->q, &f->q);
            d3 = cc_cross(&f->p, &f->q, &e->p);
            d4 = cc_cross(&f->p, &f->q, &e->q);

            if (((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0)) && ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0)))
            {
                struct cc_point x;
                double t = (double)d1 / (double)(d1 - d2);

                x.x = (long long)floor((double)f->p.x + t * (double)(f->q.x - f->p.x) + 0.5);
                x.y = (long long)floor((double)f->p.y + t * (double)(f->q.y - f->p.y) + 0.5);
                if (cc_add_split(&splits, &count, &size, i, e, x)
                        || cc_add_split(&splits, &count, &size, j, f, x))
                    goto oom;
                continue;
            }

            if (!d1 && cc_strictly_between(&e->p, &e->q, &f->p)
                    && cc_add_split(&splits, &count, &size, i, e, f->p))
                goto oom;
            if (!d2 && cc_strictly_between(&e->p, &e->q, &f->q)
                    && cc_add_split(&splits, &count, &size, i, e, f->q))
                goto oom;
            if (!d3 && cc_strictly_between(&f->p, &f->q, &e->p)
                    && cc_add_split(&splits, &count, &size, j, f, e->p))
                goto oom;
            if (!d4 && cc_strictly_between(&f->p, &f->q, &e->q)
                    && cc_add_split(&splits, &count, &size, j, f, e->q))
                goto oom;
        }
    }

    if (!count)
        goto done;

    qsort(splits, count, sizeof(*splits), cc_split_cmp);
    k = 0;
    for (i = 0; i < edges->count; ++i)
    {
        const struct cc_edge *e = &edges->e[i];
        struct cc_point prev = e->p;

        while (k < count && splits[k].edge < i)
            ++k;
        while (k < count && splits[k].edge == i)
        {
            if (cc_point_cmp(&splits[k].pt, &prev))
            {
                if (cc_edges_add(&out, prev, splits[k].pt, e->ca, e->cb))
                    goto oom;
                prev = splits[k].pt;
            }
            ++k;
        }
        if (cc_edges_add(&out, prev, e->q, e->ca, e->cb))
            goto oom;
    }

    free(edges->e);
    *edges = out;
    cc_edges_normalize(edges);
    free(splits);
    return 1;

oom:
    ret = -1;
done:
    free(splits);
    if (ret < 0)
        free(out.e);
    else
        free(out.e);
    return ret;
}

static int cc_inside(int w, int evenodd)
{
    return evenodd ? (w & 1) : w != 0;
}

static int cc_result(int a, int b, int mode)
{
    switch (mode)
    {
        case D2D_CC_UNION: return a || b;
        case D2D_CC_INTERSECT: return a && b;
        case D2D_CC_XOR: return a != b;
        default: return a && !b;
    }
}

/* Winding numbers (A, B) to the left of edge e. */
static void cc_winding_left(const struct cc_edges *edges, size_t index, int *wa, int *wb)
{
    const struct cc_edge *e = &edges->e[index];
    long long mx = e->p.x + e->q.x, my = e->p.y + e->q.y;
    int sa = 0, sb = 0;
    size_t i;

    if (e->p.x != e->q.x)
    {
        /* Ray going down from the middle of e; counts the edges below it. */
        for (i = 0; i < edges->count; ++i)
        {
            const struct cc_edge *f = &edges->e[i];
            long long dx, dy, v;

            if (i == index || f->p.x == f->q.x)
                continue;
            if (2 * f->p.x > mx)
                break;
            if (!(mx < 2 * f->q.x))
                continue;
            dx = f->q.x - f->p.x;
            dy = f->q.y - f->p.y;
            v = (2 * f->p.y - my) * dx + dy * (mx - 2 * f->p.x);
            if (v < 0)
            {
                sa += f->ca;
                sb += f->cb;
            }
        }
        /* Left of p->q (going right) is above. */
        *wa = sa + e->ca;
        *wb = sb + e->cb;
    }
    else
    {
        /* Ray going to -x from the middle of e (vertical, going up). */
        for (i = 0; i < edges->count; ++i)
        {
            const struct cc_edge *f = &edges->e[i];
            long long dx, dy, ylo, yhi;
            int sgn, left;

            if (i == index || f->p.y == f->q.y)
                continue;
            if (2 * f->p.x > mx)
                break;
            ylo = f->p.y < f->q.y ? f->p.y : f->q.y;
            yhi = f->p.y < f->q.y ? f->q.y : f->p.y;
            if (!(2 * ylo <= my && my < 2 * yhi))
                continue;
            dx = f->q.x - f->p.x;
            dy = f->q.y - f->p.y;
            sgn = dy > 0 ? 1 : -1;
            if (!dx)
                left = 2 * f->p.x < mx;
            else
            {
                long long s = (2 * f->p.x - mx) * dy + dx * (my - 2 * f->p.y);

                left = (s < 0 && dy > 0) || (s > 0 && dy < 0);
            }
            if (left)
            {
                sa -= f->ca * sgn;
                sb -= f->cb * sgn;
            }
        }
        *wa = sa;
        *wb = sb;
    }
}

struct cc_dedge
{
    struct cc_point from, to;
    int used;
};

static int cc_dedge_cmp(const void *a, const void *b)
{
    const struct cc_dedge *da = a, *db = b;
    int r;

    if ((r = cc_point_cmp(&da->from, &db->from)))
        return r;
    return cc_point_cmp(&da->to, &db->to);
}

static long long cc_snap(float v)
{
    double d;

    if (!(v == v))
        return 0;
    d = (double)v * CC_SCALE;
    if (d > (double)CC_LIMIT * CC_SCALE)
        d = (double)CC_LIMIT * CC_SCALE;
    if (d < -(double)CC_LIMIT * CC_SCALE)
        d = -(double)CC_LIMIT * CC_SCALE;
    return (long long)floor(d + 0.5);
}

static int cc_add_input(struct cc_edges *edges, const struct d2d_cc_input *in, int is_b)
{
    size_t c;

    for (c = 0; c < in->contour_count; ++c)
    {
        size_t start = in->contour_starts[c];
        size_t end = c + 1 < in->contour_count ? in->contour_starts[c + 1] : in->point_count;
        size_t i, n = end - start;

        if (n < 3)
            continue;
        for (i = 0; i < n; ++i)
        {
            const float *p = &in->xy[2 * (start + i)];
            const float *q = &in->xy[2 * (start + (i + 1) % n)];
            struct cc_point a, b;

            a.x = cc_snap(p[0]);
            a.y = cc_snap(p[1]);
            b.x = cc_snap(q[0]);
            b.y = cc_snap(q[1]);
            if (cc_edges_add(edges, a, b, is_b ? 0 : 1, is_b ? 1 : 0))
                return -1;
        }
    }
    return 0;
}

int d2d_cc_combine(const struct d2d_cc_input *a, const struct d2d_cc_input *b, int mode,
        struct d2d_cc_output *out)
{
    struct cc_edges edges = {0};
    struct cc_dedge *de = NULL;
    size_t de_count = 0, i, passes;
    struct cc_point *pts = NULL;
    size_t pts_count, pts_size = 0, keep_size = 0;
    struct cc_point *keep = NULL;
    int r = -1;

    memset(out, 0, sizeof(*out));

    if (cc_add_input(&edges, a, 0) || cc_add_input(&edges, b, 1))
        goto done;
    cc_edges_normalize(&edges);

    for (passes = 0; passes < CC_MAX_PASSES; ++passes)
    {
        int s = cc_split_pass(&edges);

        if (s < 0)
            goto done;
        if (!s)
            break;
    }

    if (!edges.count)
    {
        r = 0;
        goto done;
    }

    if (!(de = calloc(edges.count, sizeof(*de))))
        goto done;

    for (i = 0; i < edges.count; ++i)
    {
        const struct cc_edge *e = &edges.e[i];
        int wa, wb, la, ra;

        cc_winding_left(&edges, i, &wa, &wb);
        la = cc_result(cc_inside(wa, a->evenodd), cc_inside(wb, b->evenodd), mode);
        ra = cc_result(cc_inside(wa - e->ca, a->evenodd), cc_inside(wb - e->cb, b->evenodd), mode);
        if (la == ra)
            continue;
        if (la)
        {
            de[de_count].from = e->p;
            de[de_count].to = e->q;
        }
        else
        {
            de[de_count].from = e->q;
            de[de_count].to = e->p;
        }
        ++de_count;
    }

    if (!de_count)
    {
        r = 0;
        goto done;
    }

    qsort(de, de_count, sizeof(*de), cc_dedge_cmp);

    {
        size_t *starts = NULL, starts_count = 0, starts_size = 0;
        float *xy = NULL;
        size_t xy_count = 0, xy_size = 0;

        for (i = 0; i < de_count; ++i)
        {
            size_t cur = i, n, k, begin;
            struct cc_point start = de[i].from;

            if (de[i].used)
                continue;

            pts_count = 0;
            for (;;)
            {
                struct cc_point v = de[cur].to;
                size_t lo, hi, next = (size_t)-1;

                de[cur].used = 1;
                if (pts_count == pts_size)
                {
                    struct cc_point *tmp;
                    size_t ns = pts_size ? pts_size * 2 : 64;

                    if (!(tmp = realloc(pts, ns * sizeof(*tmp))))
                        goto cycle_oom;
                    pts = tmp;
                    pts_size = ns;
                }
                pts[pts_count++] = de[cur].from;

                if (!cc_point_cmp(&v, &start))
                    break;

                lo = 0;
                hi = de_count;
                while (lo < hi)
                {
                    size_t mid = (lo + hi) / 2;

                    if (cc_point_cmp(&de[mid].from, &v) < 0)
                        lo = mid + 1;
                    else
                        hi = mid;
                }
                for (k = lo; k < de_count && !cc_point_cmp(&de[k].from, &v); ++k)
                {
                    if (!de[k].used)
                    {
                        next = k;
                        break;
                    }
                }
                if (next == (size_t)-1)
                    break;
                cur = next;
            }

            /* Drop vertices in the middle of straight lines. */
            n = pts_count;
            {
                size_t m = 0;

                if (n > keep_size)
                {
                    struct cc_point *tmp;

                    if (!(tmp = realloc(keep, n * sizeof(*tmp))))
                        goto cycle_oom;
                    keep = tmp;
                    keep_size = n;
                }
                for (k = 0; k < n; ++k)
                {
                    const struct cc_point *prev = &pts[(k + n - 1) % n];
                    const struct cc_point *cur_p = &pts[k];
                    const struct cc_point *nxt = &pts[(k + 1) % n];
                    long long cr = (cur_p->x - prev->x) * (nxt->y - cur_p->y)
                            - (cur_p->y - prev->y) * (nxt->x - cur_p->x);
                    long long dt = (cur_p->x - prev->x) * (nxt->x - cur_p->x)
                            + (cur_p->y - prev->y) * (nxt->y - cur_p->y);

                    if (!cr && dt > 0)
                        continue;
                    keep[m++] = *cur_p;
                }
                memcpy(pts, keep, m * sizeof(*keep));
                n = m;
            }
            if (n < 3)
                continue;

            if (starts_count == starts_size)
            {
                size_t ns = starts_size ? starts_size * 2 : 16;
                size_t *tmp;

                if (!(tmp = realloc(starts, (ns + 1) * sizeof(*tmp))))
                    goto cycle_oom;
                starts = tmp;
                starts_size = ns;
            }
            begin = xy_count;
            starts[starts_count++] = begin;
            if (xy_count + n > xy_size)
            {
                size_t ns = xy_size ? xy_size : 128;
                float *tmp;

                while (ns < xy_count + n)
                    ns *= 2;
                if (!(tmp = realloc(xy, ns * 2 * sizeof(*tmp))))
                    goto cycle_oom;
                xy = tmp;
                xy_size = ns;
            }
            for (k = 0; k < n; ++k)
            {
                xy[2 * xy_count] = (float)((double)pts[k].x / CC_SCALE);
                xy[2 * xy_count + 1] = (float)((double)pts[k].y / CC_SCALE);
                ++xy_count;
            }
            continue;

cycle_oom:
            free(starts);
            free(xy);
            goto done;
        }

        if (starts_count)
        {
            starts[starts_count] = xy_count;
            out->xy = xy;
            out->point_count = xy_count;
            out->contour_starts = starts;
            out->contour_count = starts_count;
        }
        else
        {
            free(starts);
            free(xy);
        }
        r = 0;
    }

done:
    free(keep);
    free(pts);
    free(de);
    free(edges.e);
    return r;
}

void d2d_cc_output_free(struct d2d_cc_output *out)
{
    free(out->xy);
    free(out->contour_starts);
    memset(out, 0, sizeof(*out));
}
