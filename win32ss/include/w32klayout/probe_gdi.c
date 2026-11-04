/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     probe_gdi
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Types whose layout w32klayout.h pins; compiled with the gdi32 flags by regen.sh. */
#include "precomp.h"
#define T(x) x *volatile probe_##x; typedef struct { char c; x t; } probe_al_##x; probe_al_##x *volatile probe_alp_##x;
T(GDI_TABLE_ENTRY) T(GDI_SHARED_HANDLE_TABLE) T(DC_ATTR) T(BRUSH_ATTR) T(RGN_ATTR) T(FONT_ATTR) T(LDC)
T(MATRIX) T(CFONT) T(DEVCAPS) T(GDIBATCHHDR) T(GDIBSPATBLT) T(PATRECT) T(GDIBSPPATBLT) T(GDIBSTEXTOUT) T(GDIBSEXTTEXTOUT)
T(GDIBSSETBRHORG) T(GDIBSEXTSELCLPRGN) T(GDIBSOBJECT) T(GDI_TEB_BATCH) T(WIDTHDATA) T(REALIZATION_INFO)
T(DRIVER_FUNCTIONS) T(EFLOAT_S) T(ENTRY) T(ENUMFONTDATAW) T(GDIHANDLECACHE) T(MATRIX_S) T(NTMW_INTERNAL) T(TMDIFF) T(TMW_INTERNAL) T(UNIVERSAL_FONT_ID) T(gxf_long) T(CHWIDTHINFO)
