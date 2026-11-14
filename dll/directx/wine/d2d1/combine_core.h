/*
 * Polygon boolean operations for ID2D1Geometry::CombineWithGeometry.
 * Own implementation, see combine_core.c.
 */

#ifndef __D2D1_COMBINE_CORE_H
#define __D2D1_COMBINE_CORE_H

#include <stddef.h>

/* Same values as D2D1_COMBINE_MODE. */
#define D2D_CC_UNION        0
#define D2D_CC_INTERSECT    1
#define D2D_CC_XOR          2
#define D2D_CC_EXCLUDE      3

struct d2d_cc_input
{
    const float *xy;                /* x, y pairs */
    size_t point_count;
    const size_t *contour_starts;   /* index (in points) where each contour starts */
    size_t contour_count;
    int evenodd;                    /* alternate fill rule, else winding */
};

struct d2d_cc_output
{
    float *xy;
    size_t point_count;
    size_t *contour_starts;         /* contour_count + 1 entries, the last one is point_count */
    size_t contour_count;
};

/* Result is a set of closed contours that is to be filled with the winding rule. Returns 0, or -1 when out of memory. */
int d2d_cc_combine(const struct d2d_cc_input *a, const struct d2d_cc_input *b, int mode,
        struct d2d_cc_output *out);
void d2d_cc_output_free(struct d2d_cc_output *out);

#endif
