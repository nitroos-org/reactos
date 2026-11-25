/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Paths, arcs, styled pens and world transforms with degenerate and hostile inputs: no assertion of a
 *              checked build, no fault, no call that does not come back. A call may fail or draw nothing; what it must
 *              not do is take the system down. The world matrix of the user mode DC_ATTR is writable by the process:
 *              whatever it holds, the calls return.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include "../gditools/gditools.h"

#define DIMS 64
#define SLOW_MS 4000

static HDC g_dc;
static DWORD *g_bits;

static ULONG g_seed = 0x2468ACE1;

static ULONG Rand(void)
{
    g_seed = g_seed * 1103515245 + 12345;
    return g_seed >> 4;
}

static const LONG g_coords[] =
{
    0, 1, -1, 2, 7, 31, 32, 63, 64, 100, -100, 255, 4096, -4096, 0x7FFF, -0x8000, 0xFFFF, 0x10000, 0x7FFFFFF,
    -0x7FFFFFF, 0x8000000, -0x8000000, 0x10000000, 0x3FFFFFFF, 0x7FFFFFFF, (LONG)0x80000000, (LONG)0x80000001,
};

static LONG RC(void)
{
    return g_coords[Rand() % _countof(g_coords)];
}

static const DWORD g_floatbits[] =
{
    0x7FC00000, 0xFFC00000, 0x7F800000, 0xFF800000, 0x00000001, 0x007FFFFF, 0x7F7FFFFF, 0x80000000, 0x00000000,
    0x3F800000, 0xBF800000, 0x4F000000, 0xCF000000, 0x7FFFFFFF, 0x5F800000, 0x3A83126F,
};

static FLOAT FB(void)
{
    DWORD d = g_floatbits[Rand() % _countof(g_floatbits)];
    return *(FLOAT *)&d;
}

static void Clear(void)
{
    int i;

    for (i = 0; i < DIMS * DIMS; i++)
        g_bits[i] = 0xFFFFFF;
}

/* The ways to end a path and use it */
static BOOL g_trace;
static BOOL g_noPoly;   /* PAR_NOPOLY: no Polygon calls (to see what the other calls do where Polygon asserts) */
static int g_nSlow;   /* calls that took more than 15 s */

static void Announce(const char *what, int op);
static void Slow(const char *what, int op, DWORD t);

static void UsePath(HDC hdc, int how)
{
    HRGN rgn;
    DWORD t = GetTickCount();

    Announce("use", how % 9);
    switch (how % 9)
    {
        case 0: FillPath(hdc); break;
        case 1: StrokePath(hdc); break;
        case 2: StrokeAndFillPath(hdc); break;
        case 3: FlattenPath(hdc); break;
        case 4: WidenPath(hdc); break;
        case 5: SelectClipPath(hdc, RGN_COPY); break;
        case 6:
            rgn = PathToRegion(hdc);
            if (rgn)
                DeleteObject(rgn);
            break;
        case 7: GetPath(hdc, NULL, NULL, 0); break;
        default: AbortPath(hdc); break;
    }
    Slow("use", how % 9, t);
}

/* PAR_TRACE=1 in the environment: every call is announced with the state of the generator (it repeats the call)
   on the debug port, and a call that took a second is named */
static void Announce(const char *what, int op)
{
    char buf[80];

    if (!g_trace)
        return;
    StringCchPrintfA(buf, _countof(buf), "PAR %s seed %08lx op %d\n", what, g_seed, op);
    OutputDebugStringA(buf);
}

static void Slow(const char *what, int op, DWORD t)
{
    char buf[80];

    if (GetTickCount() - t > 15000)
        g_nSlow++;
    if (g_trace && GetTickCount() - t > 1000)
    {
        StringCchPrintfA(buf, _countof(buf), "PAR SLOW %s op %d %lu ms\n", what, op, GetTickCount() - t);
        OutputDebugStringA(buf);
    }
}

static void DoPathOp(HDC hdc, int op)
{
    POINT pt[8];
    BYTE types[8];
    int i, n;

    for (i = 0; i < 8; i++)
    {
        pt[i].x = RC();
        pt[i].y = RC();
    }
    if (g_trace)
    {
        char buf[160];

        StringCchPrintfA(buf, _countof(buf), "PAR op %d pts (%ld,%ld) (%ld,%ld) (%ld,%ld) (%ld,%ld)\n", op % 22,
                         pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y);
        OutputDebugStringA(buf);
    }
    switch (op % 22)
    {
        case 0: MoveToEx(hdc, pt[0].x, pt[0].y, NULL); break;
        case 1: LineTo(hdc, pt[0].x, pt[0].y); break;
        case 2: PolyBezierTo(hdc, pt, 3); break;
        case 3: PolyBezier(hdc, pt, 4); break;
        case 4: Arc(hdc, pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y); break;
        case 5: ArcTo(hdc, pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y); break;
        case 6: Pie(hdc, pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y); break;
        case 7: Chord(hdc, pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y, pt[3].x, pt[3].y); break;
        case 8: AngleArc(hdc, pt[0].x, pt[0].y, (DWORD)RC(), FB(), FB()); break;
        case 9: CloseFigure(hdc); break;
        case 10:
            n = 1 + Rand() % 8;
            for (i = 0; i < n; i++)
                types[i] = (BYTE)(Rand() % 4 ? g_coords[Rand() % 5] : Rand());
            PolyDraw(hdc, pt, types, n);
            break;
        case 11: Ellipse(hdc, pt[0].x, pt[0].y, pt[1].x, pt[1].y); break;
        case 12: Rectangle(hdc, pt[0].x, pt[0].y, pt[1].x, pt[1].y); break;
        case 13: RoundRect(hdc, pt[0].x, pt[0].y, pt[1].x, pt[1].y, pt[2].x, pt[2].y); break;
        case 14: Polyline(hdc, pt, 1 + Rand() % 8); break;
        case 15:
            n = 1 + Rand() % 8;
            if (!g_noPoly)
                Polygon(hdc, pt, n);
            break;
        case 16: PolylineTo(hdc, pt, 1 + Rand() % 8); break;
        case 17: TextOutW(hdc, pt[0].x, pt[0].y, L"Path", 4); break;
        case 18: SetArcDirection(hdc, (Rand() & 1) ? AD_CLOCKWISE : AD_COUNTERCLOCKWISE); break;
        case 19: ArcTo(hdc, 0, 0, 0, 0, 0, 0, 0, 0); break;
        case 20: ArcTo(hdc, 10, 10, 10, 50, 10, 10, 10, 50); break;
        default: Arc(hdc, 5, 5, 6, 6, 5, 5, 6, 6); break;
    }
}

static void OnePathOp(HDC hdc, int op)
{
    DWORD t = GetTickCount();

    Announce("op", op);
    DoPathOp(hdc, op);
    Slow("op", op, t);
}

static void test_Paths(HDC hdc, const char *name)
{
    DWORD t = GetTickCount();
    int iter, k, nops;

    for (iter = 0; iter < 250; iter++)
    {
        BeginPath(hdc);
        nops = Rand() % 5;
        for (k = 0; k < nops; k++)
            OnePathOp(hdc, Rand());
        EndPath(hdc);
        UsePath(hdc, Rand());
        /* a path that is still open is aborted */
        if ((Rand() & 7) == 0)
        {
            BeginPath(hdc);
            OnePathOp(hdc, Rand());
            UsePath(hdc, 8);
        }
    }
    trace("%s: the path calls took %lu ms\n", name, GetTickCount() - t);
}

/* Shapes drawn directly, not through a path, with every pen */
static void test_Direct(HDC hdc, const char *name)
{
    DWORD t = GetTickCount();
    int iter;

    for (iter = 0; iter < 600; iter++)
        OnePathOp(hdc, Rand());
    trace("%s: the shape calls took %lu ms\n", name, GetTickCount() - t);
}

static HPEN MakeUserPen(int cnt, int mode, DWORD width, DWORD *pst)
{
    static const DWORD vals[] = { 0, 1, 2, 3, 7, 0x7FFFFFFF, 0x40000000, 0x10000000, 0x80000000, 0xFFFFFFFF };
    LOGBRUSH lb;
    int i;

    for (i = 0; i < cnt; i++)
        pst[i] = (mode == 0) ? 1 + Rand() % 5 : vals[Rand() % _countof(vals)];
    lb.lbStyle = BS_SOLID;
    lb.lbColor = RGB(0, 0, 0);
    lb.lbHatch = 0;
    return ExtCreatePen((width ? PS_GEOMETRIC : PS_COSMETIC) | PS_USERSTYLE | PS_ENDCAP_FLAT, width ? width : 1,
                        &lb, cnt, pst);
}

static void test_Pens(HDC hdc)
{
    DWORD t = GetTickCount();
    int iter, cnt, i;

    for (iter = 0; iter < 100; iter++)
    {
        DWORD st[20];
        DWORD width = (iter & 1) ? 0 : 1 + Rand() % 7;
        HPEN pen, old;

        cnt = 1 + Rand() % 18;
        pen = MakeUserPen(cnt, iter % 3 ? 0 : 1, width, st);
        if (!pen)
            continue;
        old = SelectObject(hdc, pen);
        for (i = 0; i < 6; i++)
            OnePathOp(hdc, Rand());
        MoveToEx(hdc, 3, 3, NULL);
        LineTo(hdc, 60, 61);
        LineTo(hdc, 2, 60);
        LineTo(hdc, 70000, -70000);
        SelectObject(hdc, old);
        DeleteObject(pen);
    }
    /* the dash tables of the cosmetic stock styles, with extreme lines */
    for (iter = PS_DASH; iter <= PS_DASHDOTDOT; iter++)
    {
        HPEN pen = CreatePen(iter, 1, RGB(0, 0, 0)), old = SelectObject(hdc, pen);

        MoveToEx(hdc, 0, 0, NULL);
        LineTo(hdc, 0x7FFFFFFF, 0x7FFFFFFF);
        LineTo(hdc, (LONG)0x80000000, 5);
        SelectObject(hdc, old);
        DeleteObject(pen);
    }
    trace("the pen calls took %lu ms\n", GetTickCount() - t);
}

/* A world transform of any numbers: the calls that use it return. Whether the transform is accepted is not decided
   here (verify on the Windows reference); the DC must stay usable. */
static void test_World(HDC hdc)
{
    DWORD t = GetTickCount();
    int iter, i, j;
    static const DWORD special[] = { 0x7FC00000, 0x7F800000, 0xFF800000 };

    SetGraphicsMode(hdc, GM_ADVANCED);

    /* What a NaN or an infinity in one member does (reported, not decided here: verify on the Windows reference) */
    for (i = 0; i < 3; i++)
    {
        for (j = 0; j < 6; j++)
        {
            FLOAT m[6] = { 1, 0, 0, 1, 0, 0 };
            BOOL ret;

            m[j] = *(const FLOAT *)&special[i];
            ret = SetWorldTransform(hdc, (XFORM *)m);
            trace("SetWorldTransform with %08lx in member %d: %d\n", special[i], j, ret);
            ModifyWorldTransform(hdc, NULL, MWT_IDENTITY);
        }
    }

    for (iter = 0; iter < 100; iter++)
    {
        XFORM x;

        x.eM11 = FB(); x.eM12 = FB(); x.eM21 = FB(); x.eM22 = FB(); x.eDx = FB(); x.eDy = FB();
        if (iter & 1)
            SetWorldTransform(hdc, &x);
        else
            ModifyWorldTransform(hdc, &x, (iter & 2) ? MWT_LEFTMULTIPLY : MWT_RIGHTMULTIPLY);
        for (i = 0; i < 8; i++)
            OnePathOp(hdc, Rand());
        BeginPath(hdc);
        for (i = 0; i < 3; i++)
            OnePathOp(hdc, Rand());
        EndPath(hdc);
        UsePath(hdc, Rand());
        {
            POINT p = { RC(), RC() };

            LPtoDP(hdc, &p, 1);
            DPtoLP(hdc, &p, 1);
        }
        ModifyWorldTransform(hdc, NULL, MWT_IDENTITY);
    }
    trace("the world transform calls took %lu ms\n", GetTickCount() - t);
}

/* The matrices in the user mode DC_ATTR hold any bits */
static void test_GarbageAttr(HDC hdc)
{
    DC_ATTR *pa = GdiGetHandleUserData(hdc);
    DWORD t = GetTickCount();
    int iter, i, j;

    if (!pa)
    {
        skip("no DC_ATTR\n");
        return;
    }
    SetGraphicsMode(hdc, GM_ADVANCED);
    for (iter = 0; iter < 60; iter++)
    {
        DWORD *pm[3];

        pm[0] = (DWORD *)&pa->mxWorldToDevice;
        pm[1] = (DWORD *)&pa->mxDeviceToWorld;
        pm[2] = (DWORD *)&pa->mxWorldToPage;
        for (j = 0; j < 3; j++)
            if (iter % 3 == j || (Rand() & 1))
                for (i = 0; i < (int)(sizeof(MATRIX) / sizeof(DWORD)); i++)
                    pm[j][i] = g_floatbits[Rand() % _countof(g_floatbits)];
        pa->flXform = (iter & 1) ? 0 : (Rand() & 0xFFF);

        for (i = 0; i < 6; i++)
            OnePathOp(hdc, Rand());
        BeginPath(hdc);
        for (i = 0; i < 3; i++)
            OnePathOp(hdc, Rand());
        EndPath(hdc);
        UsePath(hdc, Rand());
        {
            POINT p = { RC(), RC() };

            LPtoDP(hdc, &p, 1);
            DPtoLP(hdc, &p, 1);
        }
        /* the DC is put right again */
        pa->flXform = 0xFFFF;
        SetWorldTransform(hdc, &(XFORM){ 1, 0, 0, 1, 0, 0 });
        ModifyWorldTransform(hdc, NULL, MWT_IDENTITY);
    }
    trace("the calls on garbage matrices took %lu ms\n", GetTickCount() - t);
}

/* A path of many single point strokes (one PT_MOVETO after the other) has more strokes than half its entries: the
   region of the path counted them in a buffer of half the size. (Whether PolyPolyline gets single points into a path
   is up to the calls before it; the random sequences below do reach the overflow on a system without the fix.) */
static void test_SinglePointStrokes(void)
{
    static const DWORD counts[] = { 1, 1, 1, 1, 1, 1, 1, 1, 3 };
    HDC hdc = CreateCompatibleDC(NULL);
    POINT pt[12];
    HRGN rgn;
    int i;

    for (i = 0; i < 12; i++)
    {
        pt[i].x = 3 + i;
        pt[i].y = 2 + (i & 1);
    }
    /* PolyPolyline puts the first point of each polyline in as a PT_MOVETO: eight single points and a line */
    BeginPath(hdc);
    PolyPolyline(hdc, pt, counts, _countof(counts));
    EndPath(hdc);
    rgn = PathToRegion(hdc);
    if (rgn)
        DeleteObject(rgn);
    BeginPath(hdc);
    PolyPolyline(hdc, pt, counts, _countof(counts));
    EndPath(hdc);
    SelectClipPath(hdc, RGN_COPY);
    DeleteDC(hdc);
}

/* A DIB DC of width 64 and the given height, and its pixels */
static HDC MakeDib(int cy, DWORD **ppBits)
{
    BITMAPINFO bi;
    HDC hdc = CreateCompatibleDC(NULL);
    HBITMAP bmp;

    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = DIMS;
    bi.bmiHeader.biHeight = -cy;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    bmp = CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, (void **)ppBits, NULL, 0);
    SelectObject(hdc, bmp);
    return hdc;
}

/* Polygon: points that are 2^32 apart used to overflow the edge stepping (an assertion of a checked build), a polygon
   that reaches 2^27 rows past the surface was stepped through all of them, and the rows that are seen are the same
   whether the rest of the polygon is far above them or not */
static void test_Polygon(void)
{
    static const POINT poly[] = { { 5, 0 }, { 60, 9000 }, { 20, 19990 }, { 50, 5 }, { 2, 19000 }, { 40, 13000 } };
    static const int rows[] = { 0, 100, 5000, 8990, 12990, 19000, 19936 };
    static const POINT huge[][4] =
    {
        { { 255, (LONG)0x80000000 }, { -32768, 0x7FFFFFFF }, { 63, -100 }, { 0x3FFFFFFF, 100 } },
        { { 0, -0x7FFFFFF }, { 63, 0x7FFFFFF }, { 30, 0x7FFFFFF }, { 10, -0x7FFFFFF } },
        { { 0, (LONG)0x80000000 }, { 63, 0x7FFFFFFF }, { 0x7FFFFFFF, 0x7FFFFFFF }, { 0, 0 } },
        { { 10, -0x10000000 }, { 50, 0x10000000 }, { 63, 0x10000010 }, { 0, 10 } },
    };
    DWORD *tall, *small;
    HDC dcTall = MakeDib(20000, &tall), dcSmall = MakeDib(DIMS, &small);
    HBRUSH black = GetStockObject(BLACK_BRUSH);
    HGDIOBJ nullpen = GetStockObject(NULL_PEN);
    int i, r, bad;
    DWORD t;

    if (!tall || !small)
    {
        skip("no DIB\n");
        return;
    }
    SelectObject(dcTall, black);
    SelectObject(dcTall, nullpen);
    SelectObject(dcSmall, black);
    SelectObject(dcSmall, nullpen);

    for (i = 0; i < 20000 * DIMS; i++)
        tall[i] = 0xFFFFFF;
    Polygon(dcTall, poly, _countof(poly));
    GdiFlush();

    for (r = 0; r < (int)_countof(rows); r++)
    {
        for (i = 0; i < DIMS * DIMS; i++)
            small[i] = 0xFFFFFF;
        SetViewportOrgEx(dcSmall, 0, -rows[r], NULL);
        Polygon(dcSmall, poly, _countof(poly));
        GdiFlush();
        bad = 0;
        for (i = 0; i < DIMS * DIMS; i++)
            if ((small[i] & 0xFFFFFF) != (tall[rows[r] * DIMS + i] & 0xFFFFFF))
                bad++;
        ok(bad == 0, "rows %d..%d of the polygon: %d pixels differ from the same rows drawn inside a tall surface\n",
           rows[r], rows[r] + DIMS - 1, bad);
    }
    SetViewportOrgEx(dcSmall, 0, 0, NULL);

    for (r = 0; r < (int)_countof(huge); r++)
    {
        t = GetTickCount();
        Polygon(dcSmall, huge[r], 4);
        SetPolyFillMode(dcSmall, (r & 1) ? WINDING : ALTERNATE);
        Polygon(dcSmall, huge[r], 4);
        ok(GetTickCount() - t < 10000, "polygon %d with far points took %lu ms\n", r, GetTickCount() - t);
    }
    DeleteDC(dcTall);
    DeleteDC(dcSmall);
}

static HDC MakeDC(int kind)
{
    BITMAPINFO bi;
    HBITMAP bmp;
    HDC hdc;

    if (kind == 1)
        return CreateICW(L"DISPLAY", NULL, NULL, NULL);
    hdc = CreateCompatibleDC(NULL);
    if (kind == 2)
        return hdc;   /* the 1 x 1 bitmap of a new memory DC */
    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = DIMS;
    bi.bmiHeader.biHeight = -DIMS;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    bmp = CreateDIBSection(hdc, &bi, DIB_RGB_COLORS, (void **)&g_bits, NULL, 0);
    SelectObject(hdc, bmp);
    return hdc;
}

START_TEST(PathArcRobustness)
{
    static const char *const names[] = { "DIB DC", "information DC", "default bitmap DC" };
    int kind;

    g_trace = GetEnvironmentVariableA("PAR_TRACE", NULL, 0) != 0;
    if (GetEnvironmentVariableA("PAR_SEED", NULL, 0) != 0)
    {
        char buf[16];

        GetEnvironmentVariableA("PAR_SEED", buf, sizeof(buf));
        g_seed = strtoul(buf, NULL, 16);
    }
    test_SinglePointStrokes();
    /* PAR_NOPOLY=1: leave the polygon rows out (to see what the other calls do on a system where they fail) */
    g_noPoly = GetEnvironmentVariableA("PAR_NOPOLY", NULL, 0) != 0;
    if (!g_noPoly)
        test_Polygon();

    for (kind = 0; kind < 3; kind++)
    {
        HDC hdc = MakeDC(kind);
        HPEN pen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0)), pen3 = CreatePen(PS_SOLID, 3, RGB(0, 0, 0));
        HPEN old;

        if (!hdc)
        {
            skip("%s: no DC\n", names[kind]);
            continue;
        }
        g_dc = hdc;
        if (kind == 0)
            Clear();

        old = SelectObject(hdc, pen);
        test_Paths(hdc, names[kind]);
        test_Direct(hdc, names[kind]);
        SelectObject(hdc, pen3);
        test_Paths(hdc, names[kind]);
        test_Direct(hdc, names[kind]);
        SelectObject(hdc, old);

        if (kind == 0)
        {
            test_Pens(hdc);
            test_World(hdc);
            test_GarbageAttr(hdc);
        }
        DeleteDC(hdc);
        DeleteObject(pen);
        DeleteObject(pen3);
    }
    ok(g_nSlow == 0, "%d calls took more than 15 seconds\n", g_nSlow);
}
