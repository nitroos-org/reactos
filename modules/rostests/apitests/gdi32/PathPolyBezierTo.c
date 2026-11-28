/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Test PolyBezierTo in an open path that has no entry yet
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The figure starts at the current position: a MOVETO there, then the control and end points as BEZIERTO.
 * Before the fix the kernel copied one point more than it had (read past its buffer) and the figure started at
 * the first control point.
 */

#include "precomp.h"

START_TEST(PathPolyBezierTo)
{
    static const POINT Curve[6] = { { 20, 5 }, { 40, 60 }, { 50, 30 }, { 60, 5 }, { 70, 60 }, { 90, 40 } };
    POINT Points[16];
    BYTE Types[16];
    HDC hdc;
    HBITMAP hbmp, hbmpOld;
    INT n, i, cCurve;

    hdc = CreateCompatibleDC(NULL);
    ok(hdc != NULL, "CreateCompatibleDC failed\n");
    hbmp = CreateBitmap(100, 100, 1, 1, NULL);
    hbmpOld = SelectObject(hdc, hbmp);

    for (cCurve = 3; cCurve <= 6; cCurve += 3)
    {
        ok(BeginPath(hdc), "BeginPath failed\n");
        ok(MoveToEx(hdc, 10, 10, NULL), "MoveToEx failed\n");
        ok(PolyBezierTo(hdc, Curve, cCurve), "PolyBezierTo failed with %lu\n", GetLastError());
        ok(EndPath(hdc), "EndPath failed\n");

        n = GetPath(hdc, Points, Types, ARRAYSIZE(Points));
        ok(n == cCurve + 1, "%d points, expected %d\n", n, cCurve + 1);
        if (n != cCurve + 1)
            continue;
        ok(Types[0] == PT_MOVETO && Points[0].x == 10 && Points[0].y == 10,
           "first entry %u (%ld,%ld), expected the move to (10,10)\n", Types[0], Points[0].x, Points[0].y);
        for (i = 0; i < cCurve; i++)
        {
            ok(Types[i + 1] == PT_BEZIERTO, "entry %d: type %u\n", i + 1, Types[i + 1]);
            ok(Points[i + 1].x == Curve[i].x && Points[i + 1].y == Curve[i].y,
               "entry %d: (%ld,%ld), expected (%ld,%ld)\n", i + 1, Points[i + 1].x, Points[i + 1].y, Curve[i].x, Curve[i].y);
        }
        AbortPath(hdc);
    }

    SelectObject(hdc, hbmpOld);
    DeleteObject(hbmp);
    DeleteDC(hdc);
}
