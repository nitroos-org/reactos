/* GDI private buffers used by GUI applications.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64win.h"
#include <ntgdihdl.h>

typedef struct { LONG bmType, bmWidth, bmHeight, bmWidthBytes; WORD bmPlanes, bmBitsPixel; ULONG bmBits; } BITMAP32;
typedef struct { BITMAP32 Bitmap; BITMAPINFOHEADER Header; DWORD Masks[3]; ULONG Section, Offset; } DIBSECTION32;
typedef struct { UINT Style; COLORREF Color; ULONG Hatch; } BRUSH32;
typedef struct { DWORD Style, Width, BrushStyle, Color, Hatch, Count, Entries[16]; } PEN32;
C_ASSERT(sizeof(BITMAP32) == 24);
C_ASSERT(sizeof(DIBSECTION32) == 84);
C_ASSERT(sizeof(BRUSH32) == 12);

static ULONG QueryOutlineMetrics(ULONG *a)
{
    const ULONG Prefix = FIELD_OFFSET(OUTLINETEXTMETRICW, otmpFamilyName);
    const ULONG GuestHeader = 216, Difference = sizeof(OUTLINETEXTMETRICW) - 216;
    OUTLINETEXTMETRICW *Native;
    ULONG Size, Ret = 0, Names[4], i;
    PSTR *NativeNames;
    C_ASSERT(FIELD_OFFSET(OUTLINETEXTMETRICW, otmpFamilyName) == 200);
    C_ASSERT(sizeof(OUTLINETEXTMETRICW) == 232);

    Size = NtGdiGetOutlineTextMetricsInternalW(G(0), 0, NULL, P(3));
    if (Size < sizeof(*Native)) return 0;
    if (!a[2]) return Size - Difference;
    if (a[1] < Size - Difference)
    {
        NtCurrentTeb()->LastErrorValue = ERROR_INSUFFICIENT_BUFFER;
        return 0;
    }
    Native = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!Native)
    {
        NtCurrentTeb()->LastErrorValue = ERROR_NOT_ENOUGH_MEMORY;
        return 0;
    }
    _SEH2_TRY
    {
        Ret = NtGdiGetOutlineTextMetricsInternalW(G(0), Size, Native, P(3));
        if (!Ret) _SEH2_LEAVE;
        if (Ret < sizeof(*Native) || Ret > Size) { Ret = 0; _SEH2_LEAVE; }
        NativeNames = &Native->otmpFamilyName;
        for (i = 0; i < 4; ++i)
        {
            ULONG_PTR Offset = (ULONG_PTR)NativeNames[i];
            if (Offset && (Offset < sizeof(*Native) || Offset >= Ret))
            {
                Ret = 0;
                _SEH2_LEAVE;
            }
            Names[i] = Offset ? Offset - Difference : 0;
        }
        /* The trailing strings are shared data; the four PSTR fields hold
         * byte offsets from the header, not virtual addresses. */
        RtlCopyMemory(P(2), Native, Prefix);
        RtlCopyMemory((BYTE *)P(2) + Prefix, Names, sizeof(Names));
        RtlCopyMemory((BYTE *)P(2) + GuestHeader, Native + 1, Ret - sizeof(*Native));
        Ret -= Difference;
        *(ULONG *)P(2) = Ret;
    }
    _SEH2_FINALLY
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Native);
    }
    _SEH2_END;
    return Ret;
}

static INT QueryObject(ULONG *a)
{
    ULONG Type = GDI_HANDLE_GET_TYPE(G(0));
    INT Ret, Size = a[1];
    if (Type == GDILoObjType_LO_BITMAP_TYPE)
    {
        DIBSECTION Native = {0}; DIBSECTION32 Guest = {0};
        if (a[2] && (UINT)Size < sizeof(BITMAP32)) return 0;
        Ret = NtGdiExtGetObjectW(G(0), (UINT)Size >= sizeof(Guest) ? sizeof(Native) : sizeof(BITMAP), a[2] ? &Native : NULL);
        if (!Ret) return 0;
        if (!a[2]) return sizeof(BITMAP32);
        Guest.Bitmap.bmType = Native.dsBm.bmType; Guest.Bitmap.bmWidth = Native.dsBm.bmWidth;
        Guest.Bitmap.bmHeight = Native.dsBm.bmHeight; Guest.Bitmap.bmWidthBytes = Native.dsBm.bmWidthBytes;
        Guest.Bitmap.bmPlanes = Native.dsBm.bmPlanes; Guest.Bitmap.bmBitsPixel = Native.dsBm.bmBitsPixel;
        /* the bits of a section above 4 GiB have no address a guest could use */
        Guest.Bitmap.bmBits = (ULONG_PTR)Native.dsBm.bmBits > MAXULONG ? 0 : PtrToUlong(Native.dsBm.bmBits);
        if (Ret == sizeof(DIBSECTION))
        {
            Guest.Header = Native.dsBmih; RtlCopyMemory(Guest.Masks, Native.dsBitfields, sizeof(Guest.Masks));
            Guest.Section = HandleToUlong(Native.dshSection); Guest.Offset = Native.dsOffset;
            Ret = sizeof(Guest);
        }
        else Ret = sizeof(BITMAP32);
        RtlCopyMemory(P(2), &Guest, Ret);
        return Ret;
    }
    if (Type == GDILoObjType_LO_BRUSH_TYPE)
    {
        LOGBRUSH Native = {0}; BRUSH32 Guest;
        Ret = NtGdiExtGetObjectW(G(0), sizeof(Native), a[2] ? &Native : NULL);
        if (!Ret) return 0;
        if (!a[2]) return sizeof(Guest);
        Guest.Style = Native.lbStyle; Guest.Color = Native.lbColor; Guest.Hatch = Native.lbHatch;
        Ret = min((UINT)Size, sizeof(Guest)); RtlCopyMemory(P(2), &Guest, Ret); return Ret;
    }
    if (Type == GDILoObjType_LO_EXTPEN_TYPE || (Type == GDILoObjType_LO_PEN_TYPE && Size == 28))
    {
        struct { EXTLOGPEN Pen; DWORD Extra[16]; } Native = {0}; PEN32 Guest = {0}; ULONG i;
        Ret = NtGdiExtGetObjectW(G(0), Size == 28 ? sizeof(EXTLOGPEN) : sizeof(Native), a[2] ? &Native : NULL);
        if (!Ret) return 0;
        if (Ret == sizeof(LOGPEN))
        { if (a[2]) RtlCopyMemory(P(2), &Native, Ret); return Ret; }
        Ret -= sizeof(EXTLOGPEN) - 28;
        if (!a[2]) return Ret;
        if (Size < Ret || Native.Pen.elpNumEntries > 16) return 0;
        Guest.Style = Native.Pen.elpPenStyle; Guest.Width = Native.Pen.elpWidth; Guest.BrushStyle = Native.Pen.elpBrushStyle;
        Guest.Color = Native.Pen.elpColor; Guest.Hatch = Native.Pen.elpHatch; Guest.Count = Native.Pen.elpNumEntries;
        for (i = 0; i < Guest.Count; ++i) Guest.Entries[i] = Native.Pen.elpStyleEntry[i];
        RtlCopyMemory(P(2), &Guest, Ret); return Ret;
    }
    /* LOGFONT/ENUMLOGFONTEXDV, LOGPEN and the palette's WORD are invariant. */
    return NtGdiExtGetObjectW(G(0), Size, P(2));
}

ULONG_PTR Wow64WinGdiService(ULONG Number, ULONG *a)
{
    switch (Number)
    {
    case W64_NtGdiGetOutlineTextMetricsInternalW: return QueryOutlineMetrics(a);
    case W64_NtGdiCreateDIBSection:
    {
        PVOID Bits = NULL; HBITMAP Bitmap;
        Bitmap = NtGdiCreateDIBSection(G(0), H(1), a[2], P(3), a[4], a[5], a[6], a[7], a[8] ? &Bits : NULL);
        if (Bitmap && a[8] && (ULONG_PTR)Bits > MAXULONG)
        {
            /* bits above 4 GiB cannot be named by a guest: no bitmap, rather than a truncated address */
            NtGdiDeleteObjectApp(Bitmap);
            NtCurrentTeb()->LastErrorValue = ERROR_NOT_ENOUGH_MEMORY;
            return 0;
        }
        if (Bitmap && a[8]) *(ULONG *)P(8) = PtrToUlong(Bits);
        return (ULONG_PTR)Bitmap;
    }
    case W64_NtGdiDoPalette: return NtGdiDoPalette(G(0), a[1], a[2], P(3), a[4], a[5]);
    case W64_NtGdiExtCreatePen:
        return (ULONG_PTR)NtGdiExtCreatePen(a[0], a[1], a[2], a[3], a[4], a[5], a[6], P(7), a[8], a[9], G(10));
    case W64_NtGdiExtGetObjectW: return QueryObject(a);
    case W64_NtGdiPolyPolyDraw: return NtGdiPolyPolyDraw(G(0), P(1), P(2), a[3], a[4]);
    case W64_NtGdiStartDoc:
    {
        DOCINFOW Info; ULONG *Guest = P(1);
        if (!Guest || Guest[0] != 20) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return 0; }
        Info.cbSize = sizeof(Info); Info.lpszDocName = P32(Guest[1]); Info.lpszOutput = P32(Guest[2]);
        Info.lpszDatatype = P32(Guest[3]); Info.fwType = Guest[4];
        return NtGdiStartDoc(G(0), &Info, P(2), a[3]);
    }
    default:
        return Wow64WinGdiExtraService(Number, a);
    }
}
