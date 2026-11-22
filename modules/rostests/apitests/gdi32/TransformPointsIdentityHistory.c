/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     LPtoDP / DPtoLP with a pointer that cannot be used: gdi32 answers TRUE without looking at it only for a DC
 *              whose transform has never been changed since the DC was made. A change that is undone later still counts
 *              (MM_TEXT -> MM_ANISOTROPIC -> MM_TEXT, an origin set and set back), RestoreDC brings the state back.
 *              The rows are sequences of calls on a new memory DC and the result measured on Windows Server 2022
 *              (10.0.20348, 64 and 32 bit identical, 191,000 sequences of up to 4 calls); letters:
 *                T A I L H  SetMapMode TEXT/ANISOTROPIC/ISOTROPIC/LOMETRIC/HIMETRIC
 *                u  SetWindowExtEx and SetViewportExtEx (1,1)     d  the same (100,100)     k  window 100,100 viewport 200,200
 *                w v  SetWindowOrgEx / SetViewportOrgEx (5,5)      z  both origins (0,0)     p  SetViewportOrgEx (0,0)
 *                O P  OffsetWindowOrgEx / OffsetViewportOrgEx (1,1)  o f  the same (0,0)
 *                s q  ScaleViewportExtEx / ScaleWindowExtEx (1,1,1,1)  e E  the same (2,1,1,1)
 *                G c  SetGraphicsMode ADVANCED / COMPATIBLE
 *                X  SetWorldTransform (translation)  N  SetWorldTransform (identity)  Y  MWT_IDENTITY
 *                M n  ModifyWorldTransform MWT_LEFTMULTIPLY (translation / identity)
 *                l r  SetLayout RTL / 0       S R  SaveDC / RestoreDC(-1)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#define BAD_POINTER ((POINT *)(ULONG_PTR)1)

static void ApplyOp(HDC hDC, char Op)
{
    XFORM Translate = { 1, 0, 0, 1, 3, 4 }, Identity = { 1, 0, 0, 1, 0, 0 };

    switch (Op)
    {
        case 'T': SetMapMode(hDC, MM_TEXT); break;
        case 'A': SetMapMode(hDC, MM_ANISOTROPIC); break;
        case 'I': SetMapMode(hDC, MM_ISOTROPIC); break;
        case 'L': SetMapMode(hDC, MM_LOMETRIC); break;
        case 'H': SetMapMode(hDC, MM_HIMETRIC); break;
        case 'u': SetWindowExtEx(hDC, 1, 1, NULL); SetViewportExtEx(hDC, 1, 1, NULL); break;
        case 'd': SetWindowExtEx(hDC, 100, 100, NULL); SetViewportExtEx(hDC, 100, 100, NULL); break;
        case 'k': SetWindowExtEx(hDC, 100, 100, NULL); SetViewportExtEx(hDC, 200, 200, NULL); break;
        case 'w': SetWindowOrgEx(hDC, 5, 5, NULL); break;
        case 'v': SetViewportOrgEx(hDC, 5, 5, NULL); break;
        case 'z': SetWindowOrgEx(hDC, 0, 0, NULL); SetViewportOrgEx(hDC, 0, 0, NULL); break;
        case 'p': SetViewportOrgEx(hDC, 0, 0, NULL); break;
        case 'O': OffsetWindowOrgEx(hDC, 1, 1, NULL); break;
        case 'P': OffsetViewportOrgEx(hDC, 1, 1, NULL); break;
        case 'o': OffsetWindowOrgEx(hDC, 0, 0, NULL); break;
        case 'f': OffsetViewportOrgEx(hDC, 0, 0, NULL); break;
        case 's': ScaleViewportExtEx(hDC, 1, 1, 1, 1, NULL); break;
        case 'q': ScaleWindowExtEx(hDC, 1, 1, 1, 1, NULL); break;
        case 'e': ScaleViewportExtEx(hDC, 2, 1, 1, 1, NULL); break;
        case 'E': ScaleWindowExtEx(hDC, 2, 1, 1, 1, NULL); break;
        case 'G': SetGraphicsMode(hDC, GM_ADVANCED); break;
        case 'c': SetGraphicsMode(hDC, GM_COMPATIBLE); break;
        case 'X': SetWorldTransform(hDC, &Translate); break;
        case 'N': SetWorldTransform(hDC, &Identity); break;
        case 'Y': ModifyWorldTransform(hDC, NULL, MWT_IDENTITY); break;
        case 'M': ModifyWorldTransform(hDC, &Translate, MWT_LEFTMULTIPLY); break;
        case 'n': ModifyWorldTransform(hDC, &Identity, MWT_LEFTMULTIPLY); break;
        case 'l': SetLayout(hDC, LAYOUT_RTL); break;
        case 'r': SetLayout(hDC, 0); break;
        case 'S': SaveDC(hDC); break;
        case 'R': RestoreDC(hDC, -1); break;
    }
}

START_TEST(TransformPointsIdentityHistory)
{
    /* BOOL results of LPtoDP and DPtoLP with an unusable buffer: TRUE = answered in user mode (never changed) */
    static const char *const True[] =
    {
        "A", "E", "G", "M", "N", "R", "S", "T", "X", "Y", "c", "d", "e", "f", "k", "n", "o", "p", "q", "r", "s",
        "u", "z", "TT", "TA", "Tu", "Ts", "Tz", "TG", "TX", "TR", "TS", "AA", "Au", "Az", "AG", "AX", "AR", "AS",
        "uT", "uA", "uu", "us", "uz", "uG", "uX", "uR", "uS", "sT", "sA", "su", "ss", "sz", "sG", "sX", "sR", "sS",
        "zT", "zA", "zu", "zs", "zz", "zG", "zX", "GT", "GA", "Gu", "Gs", "Gz", "GG", "GR", "GS", "XT", "XA", "Xu",
        "Xs", "Xz", "XG", "XX", "XR", "XS", "RT", "RA", "Ru", "Rs", "RG", "RX", "RR", "RS", "ST", "SA", "Su", "Ss",
        "SG", "SX", "SR", "SS", "AuA", "GSXR", "SGXR", "ASsR", "ASAR", "Gcn", "GcX",
    };
    static const char *const False[] =
    {
        "H", "I", "L", "O", "P", "l", "v", "w", "TI", "Tw", "AT", "AI", "As", "Aw", "IT", "IA", "II", "Iu", "Is",
        "Iw", "Iz", "IG", "IX", "IR", "IS", "uI", "uw", "sI", "sw", "wT", "wA", "wI", "wu", "ws", "ww", "wz", "wG",
        "wX", "wR", "wS", "zI", "zw", "GI", "Gw", "GX", "XI", "Xw", "RI", "Rw", "SI", "Sw", "ATA", "ATu", "ATs",
        "AuT", "AsT", "uAT", "TAT", "TAs", "AAT", "AzT", "wzA", "vwz", "TwzA", "GXRA", "GXSR", "AsSR", "ATAT",
        "AusT", "TAuT", "GXc", "TGXY",
    };
    static const char *const Extra[] = { "Ae", "AE", "Gn" };    /* all FALSE; "Gcn" (compatible mode, no change) is TRUE above */
    ULONG i, j;

    for (i = 0; i < 2; i++)
    {
        const char *const *List = i ? False : True;
        ULONG Count = i ? RTL_NUMBER_OF(False) : RTL_NUMBER_OF(True);

        for (j = 0; j < Count; j++)
        {
            HDC hDC = CreateCompatibleDC(NULL);
            const char *p;
            BOOL bLp, bDp;

            ok(hDC != NULL, "no DC\n");
            if (!hDC)
                return;
            for (p = List[j]; *p; p++)
                ApplyOp(hDC, *p);
            bLp = LPtoDP(hDC, BAD_POINTER, 1);
            bDp = DPtoLP(hDC, BAD_POINTER, 1);
            ok(bLp == (BOOL)!i, "LPtoDP after \"%s\": %d, expected %d\n", List[j], bLp, !i);
            ok(bDp == (BOOL)!i, "DPtoLP after \"%s\": %d, expected %d\n", List[j], bDp, !i);
            DeleteDC(hDC);
        }
    }

    /* scaling the extents by 2:1 in a mode that has them, and a multiplication by the identity in advanced mode, change the DC */
    for (i = 0; i < RTL_NUMBER_OF(Extra); i++)
    {
        HDC hDC = CreateCompatibleDC(NULL);
        const char *p;
        BOOL bLp;

        if (!hDC)
            return;
        for (p = Extra[i]; *p; p++)
            ApplyOp(hDC, *p);
        bLp = LPtoDP(hDC, BAD_POINTER, 1);
        ok(bLp == FALSE, "LPtoDP after \"%s\": %d, expected 0\n", Extra[i], bLp);
        DeleteDC(hDC);
    }
}
