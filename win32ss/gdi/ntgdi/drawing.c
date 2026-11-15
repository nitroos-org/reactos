/*
App Software Licence
--------------------
This package includes software which is copyright (c) L. Patrick.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. You may not sell this software package.
4. You may include this software in a distribution of other software,
   and you may charge a nominal fee for the media used.
5. You may sell derivative programs, providing that such programs
   simply use this software in a compiled form.
6. You may sell derivative programs which use a compiled, modified
   version of this software, provided that you have attempted as
   best as you can to propagate all modifications made to the source
   code files of this software package back to the original author(s)
   of this package.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS AS IS, AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
*/
/* Copyright (c) L. Patrick

   This file is part of the App cross-platform programming package.
   You may redistribute it and/or modify it under the terms of the
   App Software License. See the file LICENSE.TXT for details.

   http://enchantia.com/software/graphapp/
   http://www.it.usyd.edu.au/~graphapp/
*/
/*
    Modified for ReactOS
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>


#define DEGREES_TO_RADIANS(deg) ((deg)*2*M_PI/360)

typedef struct _Rect
{
    int x, y;		/* Top-left point inside rect */
    int width, height;	/* Width and height of rect */
} Rect, *PRect;

int FASTCALL IntFillRect(DC *dc, INT XLeft, INT YLeft, INT Width, INT Height, PBRUSH pbrush, BOOL Pen);
//int FASTCALL app_fill_rect(DC *dc, Rect r, PBRUSH pbrush, BOOL Pen);
static int NTAPI app_draw_ellipse(DC *g, Rect r, PBRUSH pbrush, int wy);
static int FASTCALL app_fill_ellipse(DC *g, Rect r, PBRUSH pbrush);

static
POINT
NTAPI
app_new_point(int x, int y)
{
    POINT p;
    p.x = x;
    p.y = y;
    return p;
}
#define pt(x,y)       app_new_point((x),(y))

static
Rect
NTAPI
rect(int x, int y, int width, int height)
{
    Rect r;
    r.x = x;
    r.y = y;
    r.width = width;
    r.height = height;
    return r;
}


/*
 *  app_window_fill_rect:
 *
 *  Fill a rectangle with colour, in a window.
 *
 *  This function implements client-side clipping, so that
 *  we never rely on the GDI system to do clipping, except if
 *  the destination is a window which is partially obscured.
 *  In that situation we must rely on the GDI system because there
 *  is no way for the program to know which portions of the
 *  window are currently obscured.
 */
#define app_fill_rect( dc, r, BrushObj, Pen) \
        IntFillRect(dc, r.x, r.y, r.width, r.height, BrushObj, Pen)

/*
 *  Drawing an ellipse with a certain line thickness.
 *  Use an inner and and outer ellipse and fill the spaces between.
 *  The inner ellipse uses all UPPERCASE letters, the outer lowercase.
 *
 *  This algorithm is based on the fill_ellipse algorithm presented
 *  above, but uses two ellipse calculations, and some fix-up code
 *  to avoid pathological cases where the inner ellipse is almost
 *  the same size as the outer (in which case the border of the
 *  elliptical curve might otherwise have appeared broken).
 */
static
int
NTAPI
app_draw_ellipse_small(DC *g, Rect r, PBRUSH pbrush, int wy)
{
    /* Outer ellipse: e(x,y) = b*b*x*x + a*a*y*y - a*a*b*b */

    int a = r.width / 2;
    int b = r.height / 2;
    int x = 0;
    int y = b;
    long a2 = a*a;
    long b2 = b*b;
    long xcrit = (3 * a2 / 4) + 1;
    long ycrit = (3 * b2 / 4) + 1;
    long t = b2 + a2 - 2*a2*b;	/* t = e(x+1,y-1) */
    long dxt = b2*(3+x+x);
    long dyt = a2*(3-y-y);
    int d2xt = b2+b2;
    int d2yt = a2+a2;

    int w = pbrush->lWidth; /* the pen across a vertical line; wy: across a horizontal line */

    /* Inner ellipse: E(X,Y) = B*B*X*X + A*A*Y*Y - A*A*B*B */

    int A = a-w > 0 ? a-w : 0;
    int B = b-wy > 0 ? b-wy : 0;
    int X = 0;
    int Y = B;
    long A2 = A*A;
    long B2 = B*B;
    long XCRIT = (3 * A2 / 4) + 1;
    long YCRIT = (3 * B2 / 4) + 1;
    long T = B2 + A2 - 2*A2*B;	/* T = E(X+1,Y-1) */
    long DXT = B2*(3+X+X);
    long DYT = A2*(3-Y-Y);
    int D2XT = B2+B2;
    int D2YT = A2+A2;

    int movedown, moveout;
    int innerX = 0, prevx, prevy, W;
    Rect r1, r2;
    int result = 1;

    if ((r.width <= 2) || (r.height <= 2))
        return app_fill_rect(g, r, pbrush, TRUE);

    r1.x = r.x + a;
    r1.y = r.y;
    r1.width = r.width & 1; /* i.e. if width is odd */
    r1.height = 1;

    r2 = r1;
    r2.y = r.y + r.height - 1;

    prevx = r1.x;
    prevy = r1.y;

    while (y > 0)
    {
        while (Y == y)
        {
            innerX = X;

            if (T + A2*Y < XCRIT) /* E(X+1,Y-1/2) <= 0 */
            {
                /* Move outwards to encounter edge */
                X += 1;
                T += DXT;
                DXT += D2XT;
            }
            else if (T - B2*X >= YCRIT) /* e(x+1/2,y-1) > 0 */
            {
                /* Drop down one line */
                Y -= 1;
                T += DYT;
                DYT += D2YT;
            }
            else
            {
                /* Drop diagonally down and out */
                X += 1;
                Y -= 1;
                T += DXT + DYT;
                DXT += D2XT;
                DYT += D2YT;
            }
        }

        movedown = moveout = 0;

        W = x - innerX;
        if (r1.x + W < prevx)
            W = prevx - r1.x;
        if (W < w)
            W = w;

        if (t + a2*y < xcrit) /* e(x+1,y-1/2) <= 0 */
        {
            /* Move outwards to encounter edge */
            x += 1;
            t += dxt;
            dxt += d2xt;

            moveout = 1;
        }
        else if (t - b2*x >= ycrit) /* e(x+1/2,y-1) > 0 */
        {
            /* Drop down one line */
            y -= 1;
            t += dyt;
            dyt += d2yt;

            movedown = 1;
        }
        else
        {
            /* Drop diagonally down and out */
            x += 1;
            y -= 1;
            t += dxt + dyt;
            dxt += d2xt;
            dyt += d2yt;

            movedown = 1;
            moveout = 1;
        }

        if (movedown)
        {
            if (r1.width == 0)
            {
                r1.x -= 1;
                r1.width += 2;
                r2.x -= 1;
                r2.width += 2;
                moveout = 0;
            }

            if (r1.x < r.x)
                r1.x = r2.x = r.x;
            if (r1.width > r.width)
                r1.width = r2.width = r.width;
            if (r1.y == r2.y-1)
            {
                r1.x = r2.x = r.x;
                r1.width = r2.width = r.width;
            }

            if ((r1.y < r.y+wy) || (r1.x+W >= r1.x+r1.width-W))
            {
                result &= app_fill_rect(g, r1, pbrush, TRUE);
                result &= app_fill_rect(g, r2, pbrush, TRUE);

                prevx = r1.x;
                prevy = r1.y;
            }
            else if (r1.y+r1.height < r2.y)
            {
                /* Draw distinct rectangles */
                result &= app_fill_rect(g, rect(r1.x,r1.y,
                                                W,1), pbrush, TRUE);
                result &= app_fill_rect(g, rect(
                                            r1.x+r1.width-W,r1.y,W,1), pbrush, TRUE);
                result &= app_fill_rect(g, rect(r2.x,
                                                r2.y,W,1), pbrush, TRUE);
                result &= app_fill_rect(g, rect(
                                            r2.x+r2.width-W,r2.y,W,1), pbrush, TRUE);

                prevx = r1.x;
                prevy = r1.y;
            }

            /* Move down */
            r1.y += 1;
            r2.y -= 1;
        }

        if (moveout)
        {
            /* Move outwards */
            r1.x -= 1;
            r1.width += 2;
            r2.x -= 1;
            r2.width += 2;
        }
    }
    if ((x <= a) && (prevy < r2.y))
    {
        /* Draw final line */
        r1.height = r1.y+r1.height-r2.y;
        r1.y = r2.y;

        W = w;
        if (r.x + W != prevx)
            W = prevx - r.x;
        if (W < w)
            W = w;

        if (W+W >= r.width)
        {
            result &= app_fill_rect(g, rect(r.x, r1.y,
                                            r.width, r1.height), pbrush, TRUE);
            return result;
        }

        result &= app_fill_rect(g, rect(r.x, r1.y, W, r1.height), pbrush, TRUE);
        result &= app_fill_rect(g, rect(r.x+r.width-W, r1.y,
                                        W, r1.height), pbrush, TRUE);
    }
    return result;
}

/*
 *  Draw an arc of an ellipse from start_angle anti-clockwise to
 *  end_angle. If the angles coincide, draw nothing; if they
 *  differ by 360 degrees or more, draw a full ellipse.
 *  The shape is drawn with the current line thickness,
 *  completely within the bounding rectangle. The shape is also
 *  axis-aligned, so that the ellipse would be horizontally and
 *  vertically symmetric is it was complete.
 *
 *  The draw_arc algorithm is based on draw_ellipse, but unlike
 *  that algorithm is not symmetric in the general case, since
 *  an angular portion is clipped from the shape.
 *  This clipping is performed by keeping track of two hypothetical
 *  lines joining the centre point to the enclosing rectangle,
 *  at the angles start_angle and end_angle, using a line-intersection
 *  algorithm. Essentially the algorithm just fills the spaces
 *  which are within the arc and also between the angles, going
 *  in an anti-clockwise direction from start_angle to end_angle.
 *  In the top half of the ellipse, this amounts to drawing
 *  to the left of the start_angle line and to the right of
 *  the end_angle line, while in the bottom half of the ellipse,
 *  it involves drawing to the right of the start_angle and to
 *  the left of the end_angle.
 */

/* x0 + dy * run / rise, rise != 0, in 64 bits and saturated to a LONG: the 32 bit product of two coordinate
   differences overflows for boxes near the limits of the coordinate range (and INT_MIN / -1 is a divide error) */
static
LONG
FASTCALL
app_line_x(LONG x0, LONGLONG dy, LONGLONG run, LONGLONG rise)
{
    LONGLONG q;
    LONGLONG ady = dy < 0 ? -dy : dy;
    LONGLONG arun = run < 0 ? -run : run;
    LONGLONG arise = rise < 0 ? -rise : rise;

    /* the usual case, a box of a few thousand pixels: the 32 bit arithmetic, as it was */
    if (ady < 0x8000 && arun < 0x8000 && arise < 0x8000)
        return x0 + (LONG)dy * (LONG)run / (LONG)rise;

    if (ady != 0 && arun > 0x7FFFFFFFFFFFFFFFLL / ady)
    {
        double d = (double)dy * (double)run / (double)rise;

        if (d > 4294967296.0)
            d = 4294967296.0;
        else if (d < -4294967296.0)
            d = -4294967296.0;
        q = (LONGLONG)d;
    }
    else
    {
        q = dy * run / rise;
    }

    q += x0;
    if (q > 0x7FFFFFFFLL)
        q = 0x7FFFFFFFLL;
    else if (q < -0x7FFFFFFFLL - 1)
        q = -0x7FFFFFFFLL - 1;
    return (LONG)q;
}

/*
 *  Fill a rectangle within an arc, given the centre point p0,
 *  and the two end points of the lines corresponding to the
 *  start_angle and the end_angle. This function takes care of
 *  the logic needed to swap the fill direction below
 *  the central point, and also performs the calculations
 *  needed to intersect the current Y value with each line.
 */
static
int
FASTCALL
app_fill_arc_rect(DC *g,
                  Rect r,   // top, left, width, height
                  POINT p0, // Center
                  POINT p1, // Start
                  POINT p2, // End
                  int start_angle,
                  int end_angle,
                  PBRUSH pbrush,
                  BOOL Pen)
{
    int x1, x2;
    int start_above, end_above;
    LONGLONG rise1, run1, rise2, run2;

    rise1 = (LONGLONG)p1.y - p0.y;
    run1  = (LONGLONG)p1.x - p0.x;
    rise2 = (LONGLONG)p2.y - p0.y;
    run2  = (LONGLONG)p2.x - p0.x;

    if (r.y <= p0.y) //
    {
        /* In top half of arc ellipse */

        if (p1.y <= r.y)
        {
            /* Start_line is in the top half and is */
            /* intersected by the current Y scan line */
            if (rise1 == 0)
                x1 = p1.x;
            else
                x1 = app_line_x(p0.x, (LONGLONG)r.y - p0.y, run1, rise1);
            start_above = 1;
        }
        else if ((start_angle >= 0) && (start_angle <= 180))
        {
            /* Start_line is above middle */
            x1 = p1.x;
            start_above = 1;
        }
        else
        {
            /* Start_line is below middle */
            x1 = r.x + r.width;
            start_above = 0;
        }
        if (x1 < r.x)
            x1 = r.x;
        if (x1 > r.x+r.width)
            x1 = r.x+r.width;

        if (p2.y <= r.y)
        {
            /* end_line is in the top half and is */
            /* intersected by the current Y scan line */
            if (rise2 == 0)
                x2 = p2.x;
            else
                x2 = app_line_x(p0.x, (LONGLONG)r.y - p0.y, run2, rise2);
            end_above = 1;
        }
        else if ((end_angle >= 0) && (end_angle <= 180))
        {
            /* end_line is above middle */
            x2 = p2.x;
            end_above = 1;
        }
        else
        {
            /* end_line is below middle */
            x2 = r.x;
            end_above = 0;
        }

        if (x2 < r.x) x2 = r.x;

        if (x2 > r.x+r.width) x2 = r.x+r.width;

        if (start_above && end_above)
        {
            if (start_angle > end_angle)
            {
                /* Fill outsides of wedge */
                if (! app_fill_rect(g, rect(r.x, r.y,
                                            x1-r.x, r.height), pbrush, Pen))
                    return 0;
                return app_fill_rect(g, rect(x2, r.y,
                                             r.x+r.width-x2, r.height), pbrush, Pen);
            }
            else
            {
                /* Fill inside of wedge */
                r.width = x1-x2;
                r.x = x2;
                return app_fill_rect(g, r, pbrush, Pen);
            }
        }
        else if (start_above)
        {
            /* Fill to the left of the start_line */
            r.width = x1-r.x;
            return app_fill_rect(g, r, pbrush, Pen);
        }
        else if (end_above)
        {
            /* Fill right of end_line */
            r.width = r.x+r.width-x2;
            r.x = x2;
            return app_fill_rect(g, r, pbrush, Pen);
        }
        else
        {
            if (start_angle > end_angle)
                return app_fill_rect(g,r, pbrush, Pen);
            else
                return 1;
        }
    }
    else
    {
        /* In lower half of arc ellipse */

        if (p1.y >= r.y)
        {
            /* start_line is in the lower half and is */
            /* intersected by the current Y scan line */
            if (rise1 == 0)
                x1 = p1.x;
            else
                x1 = app_line_x(p0.x, (LONGLONG)r.y - p0.y, run1, rise1);
            start_above = 0;
        }
        else if ((start_angle >= 180) && (start_angle <= 360))
        {
            /* start_line is below middle */
            x1 = p1.x;
            start_above = 0;
        }
        else
        {
            /* start_line is above middle */
            x1 = r.x;
            start_above = 1;
        }
        if (x1 < r.x)
            x1 = r.x;
        if (x1 > r.x+r.width)
            x1 = r.x+r.width;

        if (p2.y >= r.y)
        {
            /* end_line is in the lower half and is */
            /* intersected by the current Y scan line */
            if (rise2 == 0)
                x2 = p2.x;
            else
                x2 = app_line_x(p0.x, (LONGLONG)r.y - p0.y, run2, rise2);
            end_above = 0;
        }
        else if ((end_angle >= 180) && (end_angle <= 360))
        {
            /* end_line is below middle */
            x2 = p2.x;
            end_above = 0;
        }
        else
        {
            /* end_line is above middle */
            x2 = r.x + r.width;
            end_above = 1;
        }
        if (x2 < r.x)
            x2 = r.x;
        if (x2 > r.x+r.width)
            x2 = r.x+r.width;

        if (start_above && end_above)
        {
            if (start_angle > end_angle)
                return app_fill_rect(g,r, pbrush, Pen);
            else
                return 1;
        }
        else if (start_above)
        {
            /* Fill to the left of end_line */
            r.width = x2-r.x;
            return app_fill_rect(g,r, pbrush, Pen);
        }
        else if (end_above)
        {
            /* Fill right of start_line */
            r.width = r.x+r.width-x1;
            r.x = x1;
            return app_fill_rect(g,r, pbrush, Pen);
        }
        else
        {
            if (start_angle > end_angle)
            {
                /* Fill outsides of wedge */
                if (! app_fill_rect(g, rect(r.x, r.y,
                                            x2-r.x, r.height), pbrush, Pen))
                    return 0;
                return app_fill_rect(g, rect(x1, r.y,
                                             r.x+r.width-x1, r.height), pbrush, Pen);
            }
            else
            {
                /* Fill inside of wedge */
                r.width = x2-x1;
                r.x = x1;
                return app_fill_rect(g, r, pbrush, Pen);
            }
        }
    }
}

/*
 *  To fill an axis-aligned ellipse, we use a scan-line algorithm.
 *  We walk downwards from the top Y co-ordinate, calculating
 *  the width of the ellipse using incremental integer arithmetic.
 *  To save calculation, we observe that the top and bottom halves
 *  of the ellipsoid are mirror-images, therefore we can draw the
 *  top and bottom halves by reflection. As a result, this algorithm
 *  draws rectangles inwards from the top and bottom edges of the
 *  bounding rectangle.
 *
 *  To save rendering time, draw as few rectangles as possible.
 *  Other ellipse-drawing algorithms assume we want to draw each
 *  line, using a draw_pixel operation, or a draw_horizontal_line
 *  operation. This approach is slower than it needs to be in
 *  circumstances where a fill_rect operation is more efficient
 *  (such as in X-Windows, where there is a communication overhead
 *  to the X-Server). For this reason, the algorithm accumulates
 *  rectangles on adjacent lines which have the same width into a
 *  single larger rectangle.
 *
 *  This algorithm forms the basis of the later, more complex,
 *  draw_ellipse algorithm, which renders the rectangular spaces
 *  between an outer and inner ellipse, and also the draw_arc and
 *  fill_arc operations which additionally clip drawing between
 *  a start_angle and an end_angle.
 *
 */
static
int
FASTCALL
app_fill_ellipse_small(DC *g, Rect r, PBRUSH pbrush)
{
    /* e(x,y) = b*b*x*x + a*a*y*y - a*a*b*b */

    int a = r.width / 2;
    int b = r.height / 2;
    int x = 0;
    int y = b;
    long a2 = a*a;
    long b2 = b*b;
    long xcrit = (3 * a2 / 4) + 1;
    long ycrit = (3 * b2 / 4) + 1;
    long t = b2 + a2 - 2*a2*b;	/* t = e(x+1,y-1) */
    long dxt = b2*(3+x+x);
    long dyt = a2*(3-y-y);
    int d2xt = b2+b2;
    int d2yt = a2+a2;
    Rect r1, r2;
    int result = 1;

    if ((r.width <= 2) || (r.height <= 2))
        return app_fill_rect(g, r, pbrush, FALSE);

    r1.x = r.x + a;
    r1.y = r.y;
    r1.width = r.width & 1; /* i.e. if width is odd */
    r1.height = 1;

    r2 = r1;
    r2.y = r.y + r.height - 1;

    while (y > 0)
    {
        if (t + a2*y < xcrit)   /* e(x+1,y-1/2) <= 0 */
        {
            /* Move outwards to encounter edge */
            x += 1;
            t += dxt;
            dxt += d2xt;

            /* Move outwards */
            r1.x -= 1;
            r1.width += 2;
            r2.x -= 1;
            r2.width += 2;
        }
        else if (t - b2*x >= ycrit)   /* e(x+1/2,y-1) > 0 */
        {
            /* Drop down one line */
            y -= 1;
            t += dyt;
            dyt += d2yt;

            /* Enlarge rectangles */
            r1.height += 1;
            r2.height += 1;
            r2.y -= 1;
        }
        else
        {
            /* Drop diagonally down and out */
            x += 1;
            y -= 1;
            t += dxt + dyt;
            dxt += d2xt;
            dyt += d2yt;

            if ((r1.width > 0) && (r1.height > 0))
            {
                /* Draw rectangles first */

                if (r1.y+r1.height < r2.y)
                {
                    /* Distinct rectangles */
                    result &= app_fill_rect(g, r1, pbrush, FALSE);
                    result &= app_fill_rect(g, r2, pbrush, FALSE);
                }

                /* Move down */
                r1.y += r1.height;
                r1.height = 1;
                r2.y -= 1;
                r2.height = 1;
            }
            else
            {
                /* Skipped pixels on initial diagonal */

                /* Enlarge, rather than moving down */
                r1.height += 1;
                r2.height += 1;
                r2.y -= 1;
            }

            /* Move outwards */
            r1.x -= 1;
            r1.width += 2;
            r2.x -= 1;
            r2.width += 2;
        }
    }
    if (r1.y < r2.y)
    {
        /* Overlap */
        r1.x = r.x;
        r1.width = r.width;
        r1.height = r2.y+r2.height-r1.y;
        result &= app_fill_rect(g, r1, pbrush, FALSE);
    }
    else if (x <= a)
    {
        /* Crossover, draw final line */
        r1.x = r.x;
        r1.width = r.width;
        r1.height = r1.y+r1.height-r2.y;
        r1.y = r2.y;
        result &= app_fill_rect(g, r1, pbrush, FALSE);
    }
    return result;
}

/* A double as an int, saturated (the cast of an out of range double is undefined) */
static
int
FASTCALL
app_sat_int(double d)
{
    if (!(d > -2147483648.0))
        return (-0x7FFFFFFF - 1);
    if (d > 2147483647.0)
        return 0x7FFFFFFF;
    return (int)d;
}

static
POINT
FASTCALL
app_boundary_point(Rect r, int angle)
{
    int cx, cy;
    double tangent;

    cx = r.width;
    cx /= 2;
    cx += r.x;

    cy = r.height;
    cy /= 2;
    cy += r.y;

    if (angle == 0)
        return pt(r.x+r.width, cy);
    else if (angle == 45)
        return pt(r.x+r.width, r.y);
    else if (angle == 90)
        return pt(cx, r.y);
    else if (angle == 135)
        return pt(r.x, r.y);
    else if (angle == 180)
        return pt(r.x, cy);
    else if (angle == 225)
        return pt(r.x, r.y+r.height);
    else if (angle == 270)
        return pt(cx, r.y+r.height);
    else if (angle == 315)
        return pt(r.x+r.width, r.y+r.height);

    tangent = tan(DEGREES_TO_RADIANS(angle));

    if ((angle > 45) && (angle < 135))
        return pt(app_sat_int(cx+r.height/tangent/2), r.y);
    else if ((angle > 225) && (angle < 315))
        return pt(app_sat_int(cx-r.height/tangent/2), r.y+r.height);
    else if ((angle > 135) && (angle < 225))
        return pt(r.x, app_sat_int(cy+r.width*tangent/2));
    else
        return pt(r.x+r.width, app_sat_int(cy-r.width*tangent/2));
}

static
int
FASTCALL
app_fill_arc_small(DC *g, Rect r, int start_angle, int end_angle, PBRUSH pbrush, BOOL Chord)
{
    /* e(x,y) = b*b*x*x + a*a*y*y - a*a*b*b */

    int a = r.width / 2;
    int b = r.height / 2;
    int x = 0;
    int y = b;
    long a2 = a*a;
    long b2 = b*b;
    long xcrit = (3 * a2 / 4) + 1;
    long ycrit = (3 * b2 / 4) + 1;
    long t = b2 + a2 - 2*a2*b;	/* t = e(x+1,y-1) */
    long dxt = b2*(3+x+x);
    long dyt = a2*(3-y-y);
    int d2xt = b2+b2;
    int d2yt = a2+a2;
    Rect r1, r2;
    int movedown, moveout;
    int result = 1;

    /* Line descriptions */
    POINT p0, p1, p2;

    /* If angles differ by 360 degrees or more, close the shape */
    if ((start_angle + 360 <= end_angle) ||
            (start_angle - 360 >= end_angle))
    {
        return app_fill_ellipse(g, r, pbrush);
    }

    /* Make start_angle >= 0 and <= 360 */
    while (start_angle < 0)
        start_angle += 360;
    start_angle %= 360;

    /* Make end_angle >= 0 and <= 360 */
    while (end_angle < 0)
        end_angle += 360;
    end_angle %= 360;

    /* Draw nothing if the angles are equal */
    if (start_angle == end_angle)
        return 1;

    /* Find arc wedge line end points */
    p1 = app_boundary_point(r, start_angle);
    p2 = app_boundary_point(r, end_angle);
    if (Chord)
        p0 = pt((p1.x+p2.x)/2,(p1.y+p2.y)/2);
    else
        p0 = pt(r.x + r.width/2, r.y + r.height/2);

    /* Initialise rectangles to be drawn */
    r1.x = r.x + a;
    r1.y = r.y;
    r1.width = r.width & 1; /* i.e. if width is odd */
    r1.height = 1;

    r2 = r1;
    r2.y = r.y + r.height - 1;

    while (y > 0)
    {
        moveout = movedown = 0;

        if (t + a2*y < xcrit)   /* e(x+1,y-1/2) <= 0 */
        {
            /* Move outwards to encounter edge */
            x += 1;
            t += dxt;
            dxt += d2xt;

            moveout = 1;
        }
        else if (t - b2*x >= ycrit)   /* e(x+1/2,y-1) > 0 */
        {
            /* Drop down one line */
            y -= 1;
            t += dyt;
            dyt += d2yt;

            movedown = 1;
        }
        else
        {
            /* Drop diagonally down and out */
            x += 1;
            y -= 1;
            t += dxt + dyt;
            dxt += d2xt;
            dyt += d2yt;

            moveout = 1;
            movedown = 1;
        }

        if (movedown)
        {
            if (r1.width == 0)
            {
                r1.x -= 1;
                r1.width += 2;
                r2.x -= 1;
                r2.width += 2;
                moveout = 0;
            }

            if (r1.x < r.x)
                r1.x = r2.x = r.x;
            if (r1.width > r.width)
                r1.width = r2.width = r.width;
            if (r1.y == r2.y-1)
            {
                r1.x = r2.x = r.x;
                r1.width = r2.width = r.width;
            }

            if ((r1.width > 0) && (r1.y+r1.height < r2.y))
            {
                /* Distinct rectangles */
                result &= app_fill_arc_rect(g, r1,
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrush, FALSE);
                result &= app_fill_arc_rect(g, r2,
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrush, FALSE);
            }

            /* Move down */
            r1.y += 1;
            r2.y -= 1;
        }

        if (moveout)
        {
            /* Move outwards */
            r1.x -= 1;
            r1.width += 2;
            r2.x -= 1;
            r2.width += 2;
        }
    }
    if (r1.y < r2.y)
    {
        /* Overlap */
        r1.x = r.x;
        r1.width = r.width;
        r1.height = r2.y+r2.height-r1.y;
        while (r1.height > 0)
        {
            result &= app_fill_arc_rect(g,
                                        rect(r1.x, r1.y, r1.width, 1),
                                        p0, p1, p2, start_angle, end_angle, pbrush, FALSE);
            r1.y += 1;
            r1.height -= 1;
        }
    }
    else if (x <= a)
    {
        /* Crossover, draw final line */
        r1.x = r.x;
        r1.width = r.width;
        r1.height = r1.y+r1.height-r2.y;
        r1.y = r2.y;
        while (r1.height > 0)
        {
            result &= app_fill_arc_rect(g,
                                        rect(r1.x, r1.y, r1.width, 1),
                                        p0, p1, p2, start_angle, end_angle, pbrush, FALSE);
            r1.y += 1;
            r1.height -= 1;
        }
    }
    return result;
}

static
int
app_draw_arc_small(DC *g, Rect r, int start_angle, int end_angle, PBRUSH pbrushPen, BOOL Chord, int wy)
{
    /* Outer ellipse: e(x,y) = b*b*x*x + a*a*y*y - a*a*b*b */

    int a = r.width / 2;
    int b = r.height / 2;
    int x = 0;
    int y = b;
    long a2 = a*a;
    long b2 = b*b;
    long xcrit = (3 * a2 / 4) + 1;
    long ycrit = (3 * b2 / 4) + 1;
    long t = b2 + a2 - 2*a2*b;	/* t = e(x+1,y-1) */
    long dxt = b2*(3+x+x);
    long dyt = a2*(3-y-y);
    int d2xt = b2+b2;
    int d2yt = a2+a2;

    int w = pbrushPen->lWidth; /* the pen across a vertical line; wy: across a horizontal line */

    /* Inner ellipse: E(X,Y) = B*B*X*X + A*A*Y*Y - A*A*B*B */

    int A = a-w > 0 ? a-w : 0;
    int B = b-wy > 0 ? b-wy : 0;
    int X = 0;
    int Y = B;
    long A2 = A*A;
    long B2 = B*B;
    long XCRIT = (3 * A2 / 4) + 1;
    long YCRIT = (3 * B2 / 4) + 1;
    long T = B2 + A2 - 2*A2*B;	/* T = E(X+1,Y-1) */
    long DXT = B2*(3+X+X);
    long DYT = A2*(3-Y-Y);
    int D2XT = B2+B2;
    int D2YT = A2+A2;

    /* Arc rectangle calculations */
    int movedown, moveout;
    int innerX = 0, prevx, prevy, W;
    Rect r1, r2;
    int result = 1;

    /* Line descriptions */
    POINT p0, p1, p2;

    /* If angles differ by 360 degrees or more, close the shape */
    if ((start_angle + 360 <= end_angle) ||
            (start_angle - 360 >= end_angle))
    {
        return app_draw_ellipse(g, r, pbrushPen, wy);
    }

    /* Make start_angle >= 0 and <= 360 */
    while (start_angle < 0)
        start_angle += 360;
    start_angle %= 360;

    /* Make end_angle >= 0 and <= 360 */
    while (end_angle < 0)
        end_angle += 360;
    end_angle %= 360;

    /* Draw nothing if the angles are equal */
    if (start_angle == end_angle)
        return 1;

    /* Find arc wedge line end points */
    p1 = app_boundary_point(r, start_angle);
    p2 = app_boundary_point(r, end_angle);
    if (Chord)
        p0 = pt((p1.x+p2.x)/2,(p1.y+p2.y)/2);
    else
        p0 = pt(r.x + r.width/2, r.y + r.height/2);

    /* Determine ellipse rectangles */
    r1.x = r.x + a;
    r1.y = r.y;
    r1.width = r.width & 1; /* i.e. if width is odd */
    r1.height = 1;

    r2 = r1;
    r2.y = r.y + r.height - 1;

    prevx = r1.x;
    prevy = r1.y;

    while (y > 0)
    {
        while (Y == y)
        {
            innerX = X;

            if (T + A2*Y < XCRIT) /* E(X+1,Y-1/2) <= 0 */
            {
                /* Move outwards to encounter edge */
                X += 1;
                T += DXT;
                DXT += D2XT;
            }
            else if (T - B2*X >= YCRIT) /* e(x+1/2,y-1) > 0 */
            {
                /* Drop down one line */
                Y -= 1;
                T += DYT;
                DYT += D2YT;
            }
            else
            {
                /* Drop diagonally down and out */
                X += 1;
                Y -= 1;
                T += DXT + DYT;
                DXT += D2XT;
                DYT += D2YT;
            }
        }

        movedown = moveout = 0;

        W = x - innerX;
        if (r1.x + W < prevx)
            W = prevx - r1.x;
        if (W < w)
            W = w;

        if (t + a2*y < xcrit) /* e(x+1,y-1/2) <= 0 */
        {
            /* Move outwards to encounter edge */
            x += 1;
            t += dxt;
            dxt += d2xt;

            moveout = 1;
        }
        else if (t - b2*x >= ycrit) /* e(x+1/2,y-1) > 0 */
        {
            /* Drop down one line */
            y -= 1;
            t += dyt;
            dyt += d2yt;

            movedown = 1;
        }
        else
        {
            /* Drop diagonally down and out */
            x += 1;
            y -= 1;
            t += dxt + dyt;
            dxt += d2xt;
            dyt += d2yt;

            movedown = 1;
            moveout = 1;
        }

        if (movedown)
        {
            if (r1.width == 0)
            {
                r1.x -= 1;
                r1.width += 2;
                r2.x -= 1;
                r2.width += 2;
                moveout = 0;
            }

            if (r1.x < r.x)
                r1.x = r2.x = r.x;
            if (r1.width > r.width)
                r1.width = r2.width = r.width;
            if (r1.y == r2.y-1)
            {
                r1.x = r2.x = r.x;
                r1.width = r2.width = r.width;
            }

            if ((r1.y < r.y+wy) || (r1.x+W >= r1.x+r1.width-W))
            {
                result &= app_fill_arc_rect(g, r1,
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrushPen, TRUE);
                result &= app_fill_arc_rect(g, r2,
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrushPen, TRUE);

                prevx = r1.x;
                prevy = r1.y;
            }
            else if (r1.y+r1.height < r2.y)
            {
                /* Draw distinct rectangles */
                result &= app_fill_arc_rect(g, rect(
                                                r1.x,r1.y,W,1),
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrushPen, TRUE);
                result &= app_fill_arc_rect(g, rect(
                                                r1.x+r1.width-W,r1.y,W,1),
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrushPen, TRUE);
                result &= app_fill_arc_rect(g, rect(
                                                r2.x,r2.y,W,1),
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrushPen, TRUE);
                result &= app_fill_arc_rect(g, rect(
                                                r2.x+r2.width-W,r2.y,W,1),
                                            p0, p1, p2,
                                            start_angle, end_angle, pbrushPen, TRUE);

                prevx = r1.x;
                prevy = r1.y;
            }

            /* Move down */
            r1.y += 1;
            r2.y -= 1;
        }

        if (moveout)
        {
            /* Move outwards */
            r1.x -= 1;
            r1.width += 2;
            r2.x -= 1;
            r2.width += 2;
        }
    }
    if ((x <= a) && (prevy < r2.y))
    {
        /* Draw final lines */
        r1.height = r1.y+r1.height-r2.y;
        r1.y = r2.y;

        W = w;
        if (r.x + W != prevx)
            W = prevx - r.x;
        if (W < w)
            W = w;

        if (W+W >= r.width)
        {
            while (r1.height > 0)
            {
                result &= app_fill_arc_rect(g, rect(r.x,
                                                    r1.y, r.width, 1), p0, p1, p2,
                                            start_angle, end_angle, pbrushPen, TRUE);
                r1.y += 1;
                r1.height -= 1;
            }
            return result;
        }

        while (r1.height > 0)
        {
            result &= app_fill_arc_rect(g, rect(r.x, r1.y,
                                                W, 1), p0, p1, p2,
                                        start_angle, end_angle, pbrushPen, TRUE);
            result &= app_fill_arc_rect(g, rect(r.x+r.width-W,
                                                r1.y, W, 1), p0, p1, p2,
                                        start_angle, end_angle, pbrushPen, TRUE);
            r1.y += 1;
            r1.height -= 1;
        }
    }

    return result;
}


/*
 *  The ring routines above step along the outline of the whole box with 32 bit integers: their intermediate values
 *  (a*a*b and so on) overflow for boxes of about 1800 pixels and more (the shapes come out wrong), and they take time
 *  and fill calls in proportion to the size of the box, not to what is visible (a box of 2^27 pixels stalls the call for
 *  minutes). Boxes where the 32 bit arithmetic holds (and that are not larger than a few screens) go to those routines,
 *  unchanged. Bigger boxes are drawn by app_ring_big: one span per visible row, from the equation of the ellipse in
 *  double precision, so the work is proportional to the visible rows (the clip bounds), whatever the box.
 */
#define APP_RING_MAX_DIM    8192
#define APP_RING_MAX_CUBE   0x19000000LL    /* a*a*b < 4.2e8: no intermediate value of the stepping reaches 2^31 */
#define APP_RING_MAX_COORD  0x40000000LL

static
BOOL
FASTCALL
app_ring_is_small(Rect r)
{
    LONGLONG w = r.width, h = r.height;
    LONGLONG a, b, m1, m2;

    if (w < 0) w = -w;
    if (h < 0) h = -h;
    if (w > APP_RING_MAX_DIM || h > APP_RING_MAX_DIM)
        return FALSE;

    a = w / 2;
    b = h / 2;
    m1 = a * a * b;
    m2 = b * b * a;
    if (m1 > APP_RING_MAX_CUBE || m2 > APP_RING_MAX_CUBE)
        return FALSE;

    /* The box and the rectangles derived from it keep away from the end of the int range */
    if (r.x > APP_RING_MAX_COORD || r.x < -APP_RING_MAX_COORD ||
        r.y > APP_RING_MAX_COORD || r.y < -APP_RING_MAX_COORD ||
        (LONGLONG)r.x + r.width > APP_RING_MAX_COORD || (LONGLONG)r.x + r.width < -APP_RING_MAX_COORD ||
        (LONGLONG)r.y + r.height > APP_RING_MAX_COORD || (LONGLONG)r.y + r.height < -APP_RING_MAX_COORD)
        return FALSE;

    return TRUE;
}

/* What a draw through the clip object of the DC can reach, in the coordinates the shapes are computed in (the DC origin
   is added by IntFillRect). FALSE when there is no surface. */
static
BOOL
FASTCALL
app_visible_window(DC *g, LONGLONG *pl, LONGLONG *pt, LONGLONG *pr, LONGLONG *pb)
{
    RECTL rcl;
    SURFACE *psurf = g->dclevel.pSurface;
    LONGLONG l, t, r, b;

    if (psurf == NULL)
        return FALSE;

    DC_vGetClipLimit(g, CLIPLIM_BITBLT, &rcl);
    l = rcl.left;
    t = rcl.top;
    r = rcl.right;
    b = rcl.bottom;

    /* the surface */
    if (l < 0) l = 0;
    if (t < 0) t = 0;
    if (r > psurf->SurfObj.sizlBitmap.cx) r = psurf->SurfObj.sizlBitmap.cx;
    if (b > psurf->SurfObj.sizlBitmap.cy) b = psurf->SurfObj.sizlBitmap.cy;

    *pl = l - g->ptlDrawShift.x;
    *pt = t - g->ptlDrawShift.y;
    *pr = r - g->ptlDrawShift.x;
    *pb = b - g->ptlDrawShift.y;
    return TRUE;
}

static
int
FASTCALL
app_ring_span(DC *g,
              LONGLONG wl, LONGLONG wr,
              LONGLONG y, LONGLONG x0, LONGLONG x1,   /* pixels x0..x1 inclusive of row y */
              BOOL bArc, POINT p0, POINT p1, POINT p2, int start_angle, int end_angle,
              PBRUSH pbrush, BOOL Pen)
{
    if (x0 < wl) x0 = wl;
    if (x1 > wr - 1) x1 = wr - 1;
    if (x0 > x1)
        return 1;

    if (bArc)
        return app_fill_arc_rect(g, rect((int)x0, (int)y, (int)(x1 - x0 + 1), 1),
                                 p0, p1, p2, start_angle, end_angle, pbrush, Pen);
    return app_fill_rect(g, rect((int)x0, (int)y, (int)(x1 - x0 + 1), 1), pbrush, Pen);
}

/* The span of the pixels whose centres lie inside the ellipse of the semi axes a, b around (cx, cy), on the row of the
   pixels y (centre y + 0.5); FALSE when the row has none */
static
BOOL
FASTCALL
app_ring_extent(double cx, double cy, double a, double b, LONGLONG y, LONGLONG *px0, LONGLONG *px1)
{
    double dy, k, xe, d0, d1;

    if (!(a > 0.0) || !(b > 0.0))
        return FALSE;

    dy = ((double)y + 0.5 - cy) / b;
    k = 1.0 - dy * dy;
    if (k < 0.0)
        return FALSE;
    xe = a * sqrt(k);
    d0 = ceil(cx - xe - 0.5);
    d1 = floor(cx + xe - 0.5);
    if (d0 > d1)
        return FALSE;
    if (d0 < -4611686018427387904.0 || d1 > 4611686018427387904.0)
        return FALSE;
    *px0 = (LONGLONG)d0;
    *px1 = (LONGLONG)d1;
    return TRUE;
}

/* The ring (bDraw: the outline of the pen widths w, wy) or the disc of the ellipse in the box r; for an arc (bArc) the part
   between the radial lines at start_angle and end_angle (the angles as the stepping routines get them). One span per visible
   row. The floating point work is inside a saved FPU state: the ellipse callers hold none. */
static BOOL FASTCALL app_arc_angles(int *pstart, int *pend, BOOL *pbEllipse);
static BOOL FASTCALL app_arc_points(Rect r, int start_angle, int end_angle, BOOL Chord, POINT *pp0, POINT *pp1, POINT *pp2);
static int FASTCALL app_ring_rows(DC *g, Rect r, PBRUSH pbrush, int w, int wy, BOOL bDraw, BOOL bArc,
                                  POINT p0, POINT p1, POINT p2, int start_angle, int end_angle);

static
int
FASTCALL
app_ring_big(DC *g, Rect r, PBRUSH pbrush, int w, int wy, BOOL bDraw, BOOL bArc, BOOL Chord,
             int start_angle, int end_angle)
{
    KFLOATING_SAVE fpsave;
    POINT p0 = {0, 0}, p1 = {0, 0}, p2 = {0, 0};
    BOOL bEllipse = FALSE;
    int result;

    if (!NT_SUCCESS(KeSaveFloatingPointState(&fpsave)))
    {
        EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    if (bArc)
    {
        if (!app_arc_angles(&start_angle, &end_angle, &bEllipse))
        {
            KeRestoreFloatingPointState(&fpsave);
            return 1;
        }
        if (!bEllipse)
            app_arc_points(r, start_angle, end_angle, Chord, &p0, &p1, &p2);
        else
            bArc = FALSE;
    }

    result = app_ring_rows(g, r, pbrush, w, wy, bDraw, bArc, p0, p1, p2, start_angle, end_angle);
    KeRestoreFloatingPointState(&fpsave);
    return result;
}

/* The angles of the arc routines as the stepping routines take them: both in 0..359; FALSE when they coincide (nothing to
   draw) and TRUE with *pbEllipse when the arc is the whole ellipse */
static
BOOL
FASTCALL
app_arc_angles(int *pstart, int *pend, BOOL *pbEllipse)
{
    int start_angle = *pstart, end_angle = *pend;

    *pbEllipse = FALSE;
    if ((start_angle + 360 <= end_angle) || (start_angle - 360 >= end_angle))
    {
        *pbEllipse = TRUE;
        return TRUE;
    }

    while (start_angle < 0)
        start_angle += 360;
    start_angle %= 360;
    while (end_angle < 0)
        end_angle += 360;
    end_angle %= 360;

    *pstart = start_angle;
    *pend = end_angle;
    return start_angle != end_angle;
}

static
BOOL
FASTCALL
app_arc_points(Rect r, int start_angle, int end_angle, BOOL Chord, POINT *pp0, POINT *pp1, POINT *pp2)
{
    *pp1 = app_boundary_point(r, start_angle);
    *pp2 = app_boundary_point(r, end_angle);
    if (Chord)
        *pp0 = pt((int)(((LONGLONG)pp1->x + pp2->x) / 2), (int)(((LONGLONG)pp1->y + pp2->y) / 2));
    else
        *pp0 = pt((int)((LONGLONG)r.x + r.width / 2), (int)((LONGLONG)r.y + r.height / 2));
    return TRUE;
}

static
int
FASTCALL
app_ring_rows(DC *g, Rect r, PBRUSH pbrush, int w, int wy, BOOL bDraw, BOOL bArc,
              POINT p0, POINT p1, POINT p2, int start_angle, int end_angle)
{
    LONGLONG wl, wt, wr, wb, y, y0, y1;
    LONGLONG ox0, ox1, ix0, ix1;
    double cx, cy, a, b, ia, ib;
    int result = 1;

    if (r.width <= 0 || r.height <= 0)
        return 1;

    if (!app_visible_window(g, &wl, &wt, &wr, &wb))
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }

    if ((r.width <= 2) || (r.height <= 2))
    {
        if (!bArc)
        {
            LONGLONG x0 = r.x, x1 = (LONGLONG)r.x + r.width - 1;

            y0 = r.y;
            y1 = (LONGLONG)r.y + r.height - 1;
            if (y0 < wt) y0 = wt;
            if (y1 > wb - 1) y1 = wb - 1;
            for (y = y0; y <= y1; y++)
                result &= app_ring_span(g, wl, wr, y, x0, x1, FALSE, p0, p1, p2, 0, 0, pbrush, bDraw);
            return result;
        }
    }

    a = r.width / 2.0;
    b = r.height / 2.0;
    cx = (double)r.x + a;
    cy = (double)r.y + b;
    ia = a - (double)w;
    ib = b - (double)wy;
    if (ia < 0.0) ia = 0.0;
    if (ib < 0.0) ib = 0.0;

    y0 = r.y;
    y1 = (LONGLONG)r.y + r.height - 1;
    if (y0 < wt) y0 = wt;
    if (y1 > wb - 1) y1 = wb - 1;

    for (y = y0; y <= y1; y++)
    {
        if (!app_ring_extent(cx, cy, a, b, y, &ox0, &ox1))
            continue;

        if (bDraw && app_ring_extent(cx, cy, ia, ib, y, &ix0, &ix1))
        {
            /* The two parts of the ring on either side of the inner ellipse */
            if (ix0 > ox0)
                result &= app_ring_span(g, wl, wr, y, ox0, ix0 - 1, bArc, p0, p1, p2, start_angle, end_angle, pbrush, TRUE);
            if (ix1 < ox1)
                result &= app_ring_span(g, wl, wr, y, ix1 + 1, ox1, bArc, p0, p1, p2, start_angle, end_angle, pbrush, TRUE);
        }
        else
        {
            result &= app_ring_span(g, wl, wr, y, ox0, ox1, bArc, p0, p1, p2, start_angle, end_angle, pbrush, bDraw);
        }
    }

    return result;
}

static
int
NTAPI
app_draw_ellipse(DC *g, Rect r, PBRUSH pbrush, int wy)
{
    if (app_ring_is_small(r))
        return app_draw_ellipse_small(g, r, pbrush, wy);

    return app_ring_big(g, r, pbrush, pbrush->lWidth, wy, TRUE, FALSE, FALSE, 0, 0);
}

static
int
FASTCALL
app_fill_ellipse(DC *g, Rect r, PBRUSH pbrush)
{
    if (app_ring_is_small(r))
        return app_fill_ellipse_small(g, r, pbrush);

    return app_ring_big(g, r, pbrush, 0, 0, FALSE, FALSE, FALSE, 0, 0);
}

int
FASTCALL
app_fill_arc(DC *g, Rect r, int start_angle, int end_angle, PBRUSH pbrush, BOOL Chord)
{
    if (app_ring_is_small(r))
        return app_fill_arc_small(g, r, start_angle, end_angle, pbrush, Chord);

    return app_ring_big(g, r, pbrush, 0, 0, FALSE, TRUE, Chord, start_angle, end_angle);
}

int
app_draw_arc(DC *g, Rect r, int start_angle, int end_angle, PBRUSH pbrushPen, BOOL Chord, int wy)
{
    if (app_ring_is_small(r))
        return app_draw_arc_small(g, r, start_angle, end_angle, pbrushPen, Chord, wy);

    return app_ring_big(g, r, pbrushPen, pbrushPen->lWidth, wy, TRUE, TRUE, Chord, start_angle, end_angle);
}

/* ReactOS Interface *********************************************************/

int
FASTCALL
IntFillRect( DC *dc,
             INT XLeft,
             INT YLeft,
             INT Width,
             INT Height,
             PBRUSH pbrush,
             BOOL Pen)
{
    DWORD ROP = ROP4_FROM_INDEX(R3_OPINDEX_PATCOPY);
    RECTL DestRect;
    SURFACE *psurf;
    POINTL BrushOrigin;
    BOOL Ret = TRUE;
    PDC_ATTR pdcattr;

    ASSERT(pbrush);
    ASSERT_DC_PREPARED(dc);

    psurf = dc->dclevel.pSurface;
    if (psurf == NULL)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }

    if (!(pbrush->flAttrs & BR_IS_NULL))
    {
        pdcattr = dc->pdcattr;

        /* Fix negative spaces */
        if (Width < 0)
        {
            XLeft += Width;
            Width = 0 - Width;
        }
        if (Height < 0)
        {
            YLeft += Height;
            Height = 0 - Height;
        }

        DestRect.left = XLeft;
        DestRect.right = XLeft + Width;

        DestRect.top = YLeft;
        DestRect.bottom = YLeft + Height;

        BrushOrigin.x = pbrush->ptOrigin.x;
        BrushOrigin.y = pbrush->ptOrigin.y;

        /* The arc shapes are computed in the coordinates of the DC without its origin (the same pixels in a window DC
           and in a memory DC); the origin comes in here, with the brush origin the app set, as for any other fill */
        if (dc->ptlDrawShift.x || dc->ptlDrawShift.y)
        {
            DestRect.left += dc->ptlDrawShift.x;
            DestRect.right += dc->ptlDrawShift.x;
            DestRect.top += dc->ptlDrawShift.y;
            DestRect.bottom += dc->ptlDrawShift.y;
            if (!Pen)
            {
                BrushOrigin.x += dc->dclevel.ptlBrushOrigin.x + dc->ptlDrawShift.x;
                BrushOrigin.y += dc->dclevel.ptlBrushOrigin.y + dc->ptlDrawShift.y;
            }
        }

        if (pdcattr->jROP2 == R2_XORPEN)
            ROP = ROP4_FROM_INDEX(R3_OPINDEX_PATINVERT);

        Ret = IntEngBitBlt(
                  &psurf->SurfObj,
                  NULL,
                  NULL,
                  (CLIPOBJ *)&dc->co,
                  NULL,
                  &DestRect,
                  NULL,
                  NULL,
                  Pen ? &dc->eboLine.BrushObject : &dc->eboFill.BrushObject,
                  &BrushOrigin,
                  ROP);
    }

    return (int)Ret;
}

BOOL
FASTCALL
IntFillArc( PDC dc,
            INT XLeft,
            INT YLeft,
            INT Width,
            INT Height,
            double StartArc, // FIXME: don't use floating point!
            double EndArc,
            ARCTYPE arctype)
{
    PDC_ATTR pdcattr;
    PBRUSH pbrush;
    int Start = (int)ceil(StartArc);
    int End   = (int)ceil(EndArc);
    BOOL Chord = (arctype == GdiTypeChord), ret;

    pdcattr = dc->pdcattr;

    pbrush = BRUSH_ShareLockBrush(pdcattr->hbrush);
    if (!pbrush)
    {
        DPRINT1("FillArc Fail\n");
        EngSetLastError(ERROR_INTERNAL_ERROR);
        return FALSE;
    }
    // Sort out alignment here.
    ret = app_fill_arc(dc, rect( XLeft, YLeft, Width, Height),
                       (dc->dclevel.flPath & DCPATH_CLOCKWISE) ? -End : -Start,
                       (dc->dclevel.flPath & DCPATH_CLOCKWISE) ? -Start : -End,
                       pbrush, Chord);

    BRUSH_ShareUnlockBrush(pbrush);
    return ret;
}

BOOL
FASTCALL
IntDrawArc( PDC dc,
            INT XLeft,
            INT YLeft,
            INT Width,
            INT Height,
            double StartArc, // FIXME: don't use floating point!
            double EndArc,
            ARCTYPE arctype,
            PBRUSH pbrush,
            INT wy)
{
    int Start = (int)ceil(StartArc);
    int End   = (int)ceil(EndArc);
    BOOL Chord = (arctype == GdiTypeChord);
    // Sort out alignment here.
    return app_draw_arc(dc, rect( XLeft, YLeft, Width, Height),
                        (dc->dclevel.flPath & DCPATH_CLOCKWISE) ? -End : -Start,
                        (dc->dclevel.flPath & DCPATH_CLOCKWISE) ? -Start : -End,
                        pbrush, Chord, wy);
}

BOOL
FASTCALL
IntDrawEllipse( PDC dc,
                INT XLeft,
                INT YLeft,
                INT Width,
                INT Height,
                PBRUSH pbrush,
                INT wy)
{
    return (BOOL)app_draw_ellipse(dc, rect( XLeft, YLeft, Width, Height), pbrush, wy);
}

BOOL
FASTCALL
IntFillEllipse( PDC dc,
                INT XLeft,
                INT YLeft,
                INT Width,
                INT Height,
                PBRUSH pbrush)
{
    return (BOOL)app_fill_ellipse(dc, rect( XLeft, YLeft, Width, Height), pbrush);
}

BOOL
FASTCALL
IntFillRoundRect( PDC dc,
                  INT Left,
                  INT Top,
                  INT Right,
                  INT Bottom,
                  INT Wellipse,
                  INT Hellipse,
                  PBRUSH pbrush)
{
    Rect r;
    int rx, ry; /* Radius in x and y directions */

    //           x    y          Width          Height
    r = rect( Left, Top, abs(Right-Left), abs(Bottom-Top));
    rx = Wellipse/2;
    ry = Hellipse/2;

    if (Wellipse > r.width)
    {
        if (Hellipse > r.height) // > W > H
            app_fill_ellipse(dc, r, pbrush);
        else // > W < H
        {
            app_fill_arc(dc, rect( r.x, r.y, r.width - 1, Hellipse),
                         0, 180, pbrush,FALSE);
            app_fill_arc(dc, rect(r.x, Bottom - Hellipse - 1, r.width - 1, Hellipse),
                         180, 360, pbrush, FALSE);
        }
    }
    else if(Hellipse > r.height) // < W > H
    {
        app_fill_arc(dc, rect(r.x, r.y, Wellipse, r.height - 1),
                     90, 270, pbrush, FALSE);
        app_fill_arc(dc, rect(Right - Wellipse - 1, r.y, Wellipse, r.height - 1),
                     270, 90, pbrush,FALSE);
    }
    else // < W < H
    {
        app_fill_arc(dc, rect(r.x, r.y, rx+rx, ry+ry),
                     90, 180, pbrush, FALSE);

        app_fill_arc(dc, rect(r.x, r.y+r.height-ry-ry, rx+rx, ry+ry),
                     180, 270, pbrush, FALSE);

        app_fill_arc(dc, rect(r.x+r.width-rx-rx, r.y+r.height-ry-ry, rx+rx, ry+ry),
                     270, 360, pbrush,FALSE);

        app_fill_arc(dc, rect(r.x+r.width-rx-rx, r.y, rx+rx, ry+ry),
                     0, 90, pbrush,FALSE);
    }
    if (Wellipse < r.width)
    {
        app_fill_rect(dc, rect(r.x+rx, r.y, r.width-rx-rx, ry+1), pbrush, FALSE);
        app_fill_rect(dc, rect(r.x+rx, r.y+r.height-ry+1, r.width-rx-rx, ry-1), pbrush, FALSE);
    }
    if (Hellipse < r.height)
    {
        app_fill_rect(dc, rect(r.x, r.y+ry+1, r.width, r.height-ry-ry), pbrush, FALSE);
    }

    return TRUE;
}


BOOL
FASTCALL
IntDrawRoundRect( PDC dc,
                  INT Left,
                  INT Top,
                  INT Right,
                  INT Bottom,
                  INT Wellipse,
                  INT Hellipse,
                  PBRUSH pbrushPen,
                  INT wy)
{
    Rect r;
    int rx, ry; /* Radius in x and y directions */
    int w = pbrushPen->lWidth;

    r = rect( Left, Top, abs(Right-Left), abs(Bottom-Top));
    rx = Wellipse/2;
    ry = Hellipse/2;

    if (Wellipse > r.width)
    {
        if (Hellipse > r.height) // > W > H
            app_draw_ellipse(dc, r, pbrushPen, wy);
        else // > W < H
        {
            app_draw_arc(dc, rect( r.x, r.y, r.width - 1, Hellipse - 1),
                         0, 180, pbrushPen, FALSE, wy);
            app_draw_arc(dc, rect(r.x, Bottom - Hellipse, r.width - 1, Hellipse - 1),
                         180, 360, pbrushPen, FALSE, wy);
        }
    }
    else if(Hellipse > r.height) // < W > H
    {
        app_draw_arc(dc, rect(r.x, r.y, Wellipse - 1, r.height - 1),
                     90, 270, pbrushPen, FALSE, wy);
        app_draw_arc(dc, rect(Right - Wellipse, r.y, Wellipse - 1, r.height - 1),
                     270, 90, pbrushPen, FALSE, wy);
    }
    else // < W < H
    {
        app_draw_arc(dc, rect(r.x, r.y, rx+rx, ry+ry),
                     90, 180, pbrushPen, FALSE, wy);

        app_draw_arc(dc, rect(r.x,r.y+r.height-ry-ry,rx+rx,ry+ry),
                     180, 270, pbrushPen, FALSE, wy);

        app_draw_arc(dc, rect(r.x+r.width-rx-rx, r.y+r.height-ry-ry, rx+rx, ry+ry),
                     270, 360, pbrushPen, FALSE, wy);

        app_draw_arc(dc, rect(r.x+r.width-rx-rx,r.y,rx+rx,ry+ry),
                     0, 90, pbrushPen, FALSE, wy);
    }
    if ( Hellipse < r.height)
    {
        app_fill_rect(dc, rect(r.x, r.y+ry+1, w, r.height-ry-ry), pbrushPen, TRUE);


        app_fill_rect(dc, rect(r.x+r.width-w, r.y+ry+1, w, r.height-ry-ry),
                      pbrushPen, TRUE);
    }
    if ( Wellipse < r.width)
    {
        app_fill_rect(dc, rect(r.x+rx, r.y+r.height-wy, r.width-rx-rx, wy),
                      pbrushPen, TRUE);

        app_fill_rect(dc, rect(r.x+rx, r.y, r.width-rx-rx, wy), pbrushPen, TRUE);
    }
    return TRUE;
}

