/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The Unicode tables of NormalizeString and the nameprep of the Idn functions (normdata.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _NORMDATA_H
#define _NORMDATA_H

#include <windef.h>

/* the string (UTF-16, norm_pool[off .. off + len)) a code point is decomposed or folded to */
typedef struct _NORM_MAP
{
    ULONG cp;
    USHORT off;
    USHORT len;
} NORM_MAP;

/* the canonical combining class of the code points first .. last */
typedef struct _NORM_CCC
{
    ULONG first;
    ULONG last;
    ULONG ccc;
} NORM_CCC;

/* the code point that the canonical pair (first, second) composes to */
typedef struct _NORM_COMP
{
    ULONG first;
    ULONG second;
    ULONG result;
} NORM_COMP;

typedef struct _NORM_RANGE
{
    ULONG first;
    ULONG last;
} NORM_RANGE;

extern const USHORT norm_pool[];
/* the full canonical decomposition of the code points that have one (Hangul syllables not included) */
extern const NORM_MAP norm_canon[];
extern const ULONG norm_canon_count;
/* the full compatibility decomposition of the code points whose decomposition differs from the canonical one */
extern const NORM_MAP norm_compat[];
extern const ULONG norm_compat_count;
/* the case folding (common and full) */
extern const NORM_MAP norm_fold[];
extern const ULONG norm_fold_count;
extern const NORM_CCC norm_ccc[];
extern const ULONG norm_ccc_count;
extern const NORM_COMP norm_comp[];
extern const ULONG norm_comp_count;
/* code points without an assignment (unassigned, private use, the Hangul fillers) */
extern const NORM_RANGE norm_unassigned[];
extern const ULONG norm_unassigned_count;

/* the nameprep helpers of normalize.c */
BOOL NormpIsUnassigned(ULONG cp);
/*
 * Maps one label (or any string) as the form NormalizationIdna of NormalizeString does: no-ops removed, case
 * folded, normalized to NFKC, with the dots of the label separators kept. Returns a heap string (free it with
 * NormpFree) of *result_len units (none for a string that has nothing left). When the string is invalid or has a
 * character that the form refuses, *error_index is the index of that unit (else -1) and the result is the
 * mapping of what comes before it (valid_len units of the source). Returns NULL for no memory. With is_normalized the composition is the
 * restricted one of IsNormalizedString.
 */
WCHAR *NormpIdnaMap(const WCHAR *src, INT srclen, BOOL is_normalized, INT *result_len, INT *error_index, INT *valid_len);
void NormpFree(void *ptr);

#endif /* _NORMDATA_H */
