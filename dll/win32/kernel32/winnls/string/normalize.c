/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     NormalizeString and IsNormalizedString (NFC, NFD, NFKC, NFKD and the nameprep form of
 *              IdnToAscii) with the tables of Unicode 11.0 (normdata.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Everything here was measured on Windows 10 22H2 (x64 and x86 alike):
 *
 *  - The string is processed in order, and the destination is written as it goes: an invalid string (a lone
 *    surrogate, a noncharacter) leaves what came before it in the destination and fails with
 *    ERROR_NO_UNICODE_TRANSLATION; the result is the negative of the index of the unit that was found
 *    invalid (the low half of a pair, the unit after a high surrogate that has no low one). A destination that
 *    is too small is filled up to its length and the result is the negative of an estimate of the length
 *    that is needed (see NormpEstimate), with ERROR_INSUFFICIENT_BUFFER.
 *  - A size of zero (or no destination) asks for the size: the estimate for the whole string, without looking
 *    at it, so an invalid string is not noticed.
 *  - Unassigned code points are not an error. The tables are those of Unicode 11.0.
 *  - A length of -1 includes the terminating NUL in the length of the source and the result.
 *  - The form NormalizationIdna (13) is the mapping of the nameprep (IdnToAscii): see NormpIdnaMap.
 */

#define WIN32_NO_STATUS
#include <wine/unicode.h>

#include "normdata.h"

/* kernel32 does not call its own HeapAlloc and HeapFree, they are the heap functions of ntdll */
NTSYSAPI PVOID NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
NTSYSAPI PVOID NTAPI RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);
NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);

#define NORM_FORM_C     1
#define NORM_FORM_D     2
#define NORM_FORM_KC    5
#define NORM_FORM_KD    6
#define NORM_FORM_IDNA  13

#define HANGUL_SBASE    0xAC00
#define HANGUL_LBASE    0x1100
#define HANGUL_VBASE    0x1161
#define HANGUL_TBASE    0x11A7
#define HANGUL_LCOUNT   19
#define HANGUL_VCOUNT   21
#define HANGUL_TCOUNT   28
#define HANGUL_NCOUNT   (HANGUL_VCOUNT * HANGUL_TCOUNT)
#define HANGUL_SCOUNT   (HANGUL_LCOUNT * HANGUL_NCOUNT)

#define MAX_PIECES      24

/*** tables *******************************************************************************************************/

static const NORM_MAP *NormpFindMap(const NORM_MAP *table, ULONG count, ULONG cp)
{
    ULONG lo = 0, hi = count;

    while (lo < hi)
    {
        ULONG mid = (lo + hi) / 2;

        if (table[mid].cp == cp)
            return &table[mid];
        if (table[mid].cp < cp)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

static ULONG NormpGetCcc(ULONG cp)
{
    ULONG lo = 0, hi = norm_ccc_count;

    if (cp < 0x300)
        return 0;
    while (lo < hi)
    {
        ULONG mid = (lo + hi) / 2;

        if (cp < norm_ccc[mid].first)
            hi = mid;
        else if (cp > norm_ccc[mid].last)
            lo = mid + 1;
        else
            return norm_ccc[mid].ccc;
    }
    return 0;
}

static ULONG NormpCompose(ULONG first, ULONG second)
{
    ULONG lo = 0, hi = norm_comp_count;

    if (first >= HANGUL_LBASE && first < HANGUL_LBASE + HANGUL_LCOUNT &&
        second >= HANGUL_VBASE && second < HANGUL_VBASE + HANGUL_VCOUNT)
    {
        return HANGUL_SBASE + ((first - HANGUL_LBASE) * HANGUL_VCOUNT + (second - HANGUL_VBASE)) * HANGUL_TCOUNT;
    }
    if (first >= HANGUL_SBASE && first < HANGUL_SBASE + HANGUL_SCOUNT && (first - HANGUL_SBASE) % HANGUL_TCOUNT == 0 &&
        second > HANGUL_TBASE && second < HANGUL_TBASE + HANGUL_TCOUNT)
    {
        return first + (second - HANGUL_TBASE);
    }

    while (lo < hi)
    {
        ULONG mid = (lo + hi) / 2;

        if (norm_comp[mid].first == first && norm_comp[mid].second == second)
            return norm_comp[mid].result;
        if (norm_comp[mid].first < first || (norm_comp[mid].first == first && norm_comp[mid].second < second))
            lo = mid + 1;
        else
            hi = mid;
    }
    return 0;
}

static BOOL NormpInRanges(const NORM_RANGE *ranges, ULONG count, ULONG cp)
{
    ULONG lo = 0, hi = count;

    while (lo < hi)
    {
        ULONG mid = (lo + hi) / 2;

        if (cp < ranges[mid].first)
            hi = mid;
        else if (cp > ranges[mid].last)
            lo = mid + 1;
        else
            return TRUE;
    }
    return FALSE;
}

BOOL NormpIsUnassigned(ULONG cp)
{
    return NormpInRanges(norm_unassigned, norm_unassigned_count, cp);
}

/* the noncharacters are invalid in a string to normalize */
static __inline BOOL NormpIsNoncharacter(ULONG cp)
{
    return (cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) == 0xFFFE;
}

static void NormpFromUnits(const USHORT *units, ULONG len, ULONG *cps, ULONG *count)
{
    ULONG i = 0, n = 0;

    while (i < len)
    {
        ULONG u = units[i++];

        if (u >= 0xD800 && u < 0xDC00 && i < len)
        {
            u = 0x10000 + ((u - 0xD800) << 10) + (units[i] - 0xDC00);
            i++;
        }
        cps[n++] = u;
    }
    *count = n;
}

/* the full decomposition of cp: itself when it has none */
static void NormpDecompose(ULONG cp, BOOL compat, ULONG *pieces, ULONG *count)
{
    const NORM_MAP *map = NULL;

    if (cp < 0xA0)
    {
        pieces[0] = cp;
        *count = 1;
        return;
    }
    if (cp >= HANGUL_SBASE && cp < HANGUL_SBASE + HANGUL_SCOUNT)
    {
        ULONG s = cp - HANGUL_SBASE;

        pieces[0] = HANGUL_LBASE + s / HANGUL_NCOUNT;
        pieces[1] = HANGUL_VBASE + (s % HANGUL_NCOUNT) / HANGUL_TCOUNT;
        *count = 2;
        if (s % HANGUL_TCOUNT)
            pieces[(*count)++] = HANGUL_TBASE + s % HANGUL_TCOUNT;
        return;
    }
    if (compat)
        map = NormpFindMap(norm_compat, norm_compat_count, cp);
    if (!map)
        map = NormpFindMap(norm_canon, norm_canon_count, cp);
    if (!map)
    {
        pieces[0] = cp;
        *count = 1;
        return;
    }
    NormpFromUnits(&norm_pool[map->off], map->len, pieces, count);
}

/*
 * The next code point of the source at index i. Returns -1 and the code point and its length in units, or the index that
 * Windows reports for an invalid string: a lone low surrogate, a high one that no low one follows (the index of the
 * unit after it, or its own at the end), a noncharacter (the index of its last unit).
 */
static INT NormpNextCodePoint(const WCHAR *src, INT srclen, INT i, ULONG *cp_out, INT *units_out)
{
    ULONG cp = src[i];
    INT units = 1;

    if (cp >= 0xD800 && cp < 0xDC00)
    {
        if (i + 1 < srclen && src[i + 1] >= 0xDC00 && src[i + 1] < 0xE000)
        {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (src[i + 1] - 0xDC00);
            units = 2;
        }
        else
        {
            return i + 1 < srclen ? i + 1 : i;
        }
    }
    else if (cp >= 0xDC00 && cp < 0xE000)
    {
        return i;
    }
    if (NormpIsNoncharacter(cp))
        return i + units - 1;
    *cp_out = cp;
    *units_out = units;
    return -1;
}

/*** the size estimate ********************************************************************************************/

/*
 * What Windows answers to the size query, and the base of what it answers to a destination that is too small:
 * the length of the source times 3 (18 for the compatibility forms), but not more than the length plus an
 * eighth of it, with 64 as the least of that. (The answer is an upper bound for any string.)
 */
static INT NormpEstimate(BOOL compat, INT n)
{
    ULONGLONG by_factor = (ULONGLONG)n * (compat ? 18 : 3);
    ULONGLONG by_growth = (ULONGLONG)n + n / 8;

    if (by_growth < 64)
        by_growth = 64;
    if (by_factor > by_growth)
        by_factor = by_growth;
    return (INT)by_factor;
}

/*** the engine ***************************************************************************************************/

/* one code point of the output that is not written yet */
typedef struct _NORM_ENTRY
{
    ULONG cp;
    ULONG ccc;
    INT ce;     /* the units of the source that are done once this code point is written */
    INT pce;    /* ...and when it was only written in part (the high half of a pair): -1 for no change */
    INT si;     /* the number of the code point of the source that this one comes from */
} NORM_ENTRY;

enum { NS_OK, NS_OVERFLOW, NS_INVALID, NS_NOMEMORY, NS_MISMATCH };

typedef struct _NORM_CTX
{
    BOOL compat;
    BOOL compose;
    const WCHAR *src;
    INT srclen;

    /* the sink: a destination of dstlen units (a heap string that grows with grow), or the comparison with the source */
    WCHAR *dst;
    INT dstlen;
    INT written;
    BOOL grow;
    BOOL compare;
    BOOL restricted;    /* the composition of IsNormalizedString, see NormpMayCompose */

    INT consumed;       /* the units of the source whose output is written */
    INT error_index;
    INT status;

    /* the cluster: the starter, the marks that stay after the composition, then the marks that wait */
    NORM_ENTRY *ent;
    ULONG count, cap, kept;
    BOOL has_starter;
    INT ids[16], max_id;    /* the code points of the source that are part of the starter */
    ULONG id_count;
    BOOL composed;          /* something was composed into the starter */
    NORM_ENTRY stack[64];
} NORM_CTX;

static void NormpInit(NORM_CTX *ctx, BOOL compat, BOOL compose, const WCHAR *src, INT srclen)
{
    memset(&ctx->dst, 0, FIELD_OFFSET(NORM_CTX, stack) - FIELD_OFFSET(NORM_CTX, dst));
    ctx->compat = compat;
    ctx->compose = compose;
    ctx->src = src;
    ctx->srclen = srclen;
    ctx->ent = ctx->stack;
    ctx->cap = sizeof(ctx->stack) / sizeof(ctx->stack[0]);
}

static void NormpDone(NORM_CTX *ctx)
{
    if (ctx->ent != ctx->stack)
        RtlFreeHeap(GetProcessHeap(), 0, ctx->ent);
    ctx->ent = ctx->stack;
}

/* write one code point to the sink */
static void NormpWrite(NORM_CTX *ctx, const NORM_ENTRY *e)
{
    INT units = e->cp > 0xFFFF ? 2 : 1;
    WCHAR w[2];

    if (units == 2)
    {
        ULONG v = e->cp - 0x10000;

        w[0] = (WCHAR)(0xD800 + (v >> 10));
        w[1] = (WCHAR)(0xDC00 + (v & 0x3FF));
    }
    else
    {
        w[0] = (WCHAR)e->cp;
    }

    if (ctx->compare)
    {
        if (ctx->written + units > ctx->srclen || ctx->src[ctx->written] != w[0] ||
            (units == 2 && ctx->src[ctx->written + 1] != w[1]))
        {
            ctx->status = NS_MISMATCH;
            return;
        }
        ctx->written += units;
        return;
    }

    if (ctx->written + units > ctx->dstlen)
    {
        if (ctx->grow)
        {
            INT cap = ctx->dstlen * 2 + 32;
            WCHAR *p = ctx->dst ? RtlReAllocateHeap(GetProcessHeap(), 0, ctx->dst, cap * sizeof(WCHAR)) :
                                  RtlAllocateHeap(GetProcessHeap(), 0, cap * sizeof(WCHAR));

            if (!p)
            {
                ctx->status = NS_NOMEMORY;
                return;
            }
            ctx->dst = p;
            ctx->dstlen = cap;
        }
        else
        {
            if (units == 2 && ctx->written < ctx->dstlen)
            {
                ctx->dst[ctx->written++] = w[0];
                if (e->pce != -1)
                    ctx->consumed = e->pce;
            }
            ctx->status = NS_OVERFLOW;
            return;
        }
    }
    ctx->dst[ctx->written++] = w[0];
    if (units == 2)
        ctx->dst[ctx->written++] = w[1];
    ctx->consumed = e->ce;
}

static BOOL NormpReserve(NORM_CTX *ctx)
{
    if (ctx->count < ctx->cap)
        return TRUE;
    {
        ULONG cap = ctx->cap * 2;
        NORM_ENTRY *p = RtlAllocateHeap(GetProcessHeap(), 0, cap * sizeof(NORM_ENTRY));

        if (!p)
        {
            ctx->status = NS_NOMEMORY;
            return FALSE;
        }
        memcpy(p, ctx->ent, ctx->count * sizeof(NORM_ENTRY));
        if (ctx->ent != ctx->stack)
            RtlFreeHeap(GetProcessHeap(), 0, ctx->ent);
        ctx->ent = p;
        ctx->cap = cap;
    }
    return TRUE;
}

/*
 * The composition that IsNormalizedString looks for is not all of the composition of NormalizeString. A character
 * that is composed in the source (A with circumflex) has its marks composed back at once, and so has a mark that
 * comes from the same character, but a mark of another character composes into a starter that was composed
 * already only when it is the next character of the source, with nothing in between (Hangul syllables excepted).
 * So A with circumflex, a mark below and a grave accent is normalized for Windows although it is not. (Measured
 * over every pair of 90 characters, over 1260 strings of a starter, a mark and a mark, and 40000 random strings.)
 */
static BOOL NormpMayCompose(const NORM_CTX *ctx, ULONG first, ULONG second, INT si)
{
    ULONG i;

    if (!ctx->restricted || !ctx->composed || si == ctx->max_id + 1)
        return TRUE;
    for (i = 0; i < ctx->id_count && i < 16; i++)
        if (ctx->ids[i] == si)
            return TRUE;
    if (first >= HANGUL_LBASE && first < HANGUL_LBASE + HANGUL_LCOUNT)
        return TRUE;
    if (first >= HANGUL_SBASE && first < HANGUL_SBASE + HANGUL_SCOUNT && (first - HANGUL_SBASE) % HANGUL_TCOUNT == 0)
        return TRUE;
    return FALSE;
}

static void NormpComposed(NORM_CTX *ctx, INT si)
{
    if (ctx->id_count < 16)
        ctx->ids[ctx->id_count] = si;
    ctx->id_count++;
    if (si > ctx->max_id)
        ctx->max_id = si;
    ctx->composed = TRUE;
}

/* the marks that wait (ent[kept .. count)) are put in the order of their combining class and, for the
   composition forms, composed into the starter; what stays is added to the kept marks */
static void NormpSettle(NORM_CTX *ctx)
{
    NORM_ENTRY *run = ctx->ent + ctx->kept;
    ULONG n = ctx->count - ctx->kept, i, j;

    if (!n)
        return;

    if (n > 1)
    {
        if (n <= 32)
        {
            for (i = 1; i < n; i++)
            {
                NORM_ENTRY t = run[i];

                for (j = i; j > 0 && run[j - 1].ccc > t.ccc; j--)
                    run[j] = run[j - 1];
                run[j] = t;
            }
        }
        else
        {
            /* stable counting sort, the combining classes are below 256 */
            ULONG start[257];
            NORM_ENTRY *tmp = RtlAllocateHeap(GetProcessHeap(), 0, n * sizeof(NORM_ENTRY));

            if (!tmp)
            {
                ctx->status = NS_NOMEMORY;
                return;
            }
            memset(start, 0, sizeof(start));
            for (i = 0; i < n; i++)
                start[run[i].ccc + 1]++;
            for (i = 1; i <= 256; i++)
                start[i] += start[i - 1];
            for (i = 0; i < n; i++)
                tmp[start[run[i].ccc]++] = run[i];
            memcpy(run, tmp, n * sizeof(NORM_ENTRY));
            RtlFreeHeap(GetProcessHeap(), 0, tmp);
        }
    }

    if (ctx->compose && ctx->has_starter)
    {
        NORM_ENTRY *starter = &ctx->ent[0];
        ULONG last = ctx->kept > 1 ? ctx->ent[ctx->kept - 1].ccc : 0;
        ULONG kept = ctx->kept;

        for (i = 0; i < n; i++)
        {
            NORM_ENTRY c = run[i];
            ULONG composed = 0;

            if (last < c.ccc || last == 0)
                composed = NormpCompose(starter->cp, c.cp);
            if (composed && !NormpMayCompose(ctx, starter->cp, c.cp, c.si))
                composed = 0;
            if (composed)
            {
                NormpComposed(ctx, c.si);
                starter->cp = composed;
                if (c.ce > starter->ce)
                {
                    starter->ce = c.ce;
                    starter->pce = c.pce;
                }
            }
            else
            {
                ctx->ent[kept++] = c;
                last = c.ccc;
            }
        }
        ctx->kept = ctx->count = kept;
    }
    else
    {
        ctx->kept = ctx->count;
    }
}

/* settle the cluster and write it */
static void NormpFlush(NORM_CTX *ctx)
{
    ULONG i;

    NormpSettle(ctx);
    if (ctx->status != NS_OK)
        return;
    for (i = 0; i < ctx->kept && ctx->status == NS_OK; i++)
        NormpWrite(ctx, &ctx->ent[i]);
    ctx->count = ctx->kept = 0;
    ctx->has_starter = FALSE;
}

static void NormpPush(NORM_CTX *ctx, ULONG cp, INT ce, INT pce, INT si)
{
    ULONG ccc = NormpGetCcc(cp);

    if (!NormpReserve(ctx))
        return;

    if (ccc)
    {
        NORM_ENTRY *e = &ctx->ent[ctx->count++];

        e->cp = cp; e->ccc = ccc; e->ce = ce; e->pce = pce; e->si = si;
        return;
    }

    /* a starter: the marks before it are done; it composes into the starter before it when nothing is between */
    NormpSettle(ctx);
    if (ctx->status != NS_OK)
        return;
    if (ctx->has_starter && ctx->compose && ctx->kept == 1)
    {
        ULONG composed = NormpCompose(ctx->ent[0].cp, cp);

        if (composed && !NormpMayCompose(ctx, ctx->ent[0].cp, cp, si))
            composed = 0;
        if (composed)
        {
            NormpComposed(ctx, si);
            ctx->ent[0].cp = composed;
            ctx->ent[0].ce = ce;
            ctx->ent[0].pce = pce;
            return;
        }
    }
    NormpFlush(ctx);
    if (ctx->status != NS_OK)
        return;
    {
        NORM_ENTRY *e = &ctx->ent[0];

        e->cp = cp; e->ccc = 0; e->ce = ce; e->pce = pce; e->si = si;
        ctx->count = ctx->kept = 1;
        ctx->has_starter = TRUE;
        ctx->ids[0] = si;
        ctx->id_count = 1;
        ctx->max_id = si;
        ctx->composed = FALSE;
    }
}

/* run the engine over the source */
static void NormpRun(NORM_CTX *ctx)
{
    INT i = 0, ordinal = 0;

    while (i < ctx->srclen && ctx->status == NS_OK)
    {
        ULONG cp, pieces[MAX_PIECES], n, k;
        INT units, bad;

        bad = NormpNextCodePoint(ctx->src, ctx->srclen, i, &cp, &units);
        if (bad >= 0)
        {
            /* what came before is written, then the string is invalid */
            NormpFlush(ctx);
            if (ctx->status == NS_OK)
            {
                ctx->status = NS_INVALID;
                ctx->error_index = bad;
            }
            return;
        }

        NormpDecompose(cp, ctx->compat, pieces, &n);
        for (k = 0; k < n && ctx->status == NS_OK; k++)
            NormpPush(ctx, pieces[k], k + 1 == n ? i + units : i, (n == 1 && units == 2) ? i + 1 : -1, ordinal);
        i += units;
        ordinal++;
    }
    if (ctx->status == NS_OK)
        NormpFlush(ctx);
    if (ctx->status == NS_OK && ctx->compare && ctx->written != ctx->srclen)
        ctx->status = NS_MISMATCH;
}

/*** the nameprep form (NormalizationIdna) ************************************************************************/

/* what the form refuses; sorted. The sets are those that Windows 10 refuses (measured for every code point):
   controls, the characters that are invisible or that change the direction or the join of text (the prepended
   concatenation marks, the bidirectional controls, the default ignorable ones that are not removed), the
   noncharacters and tags, the ideographic description characters, the Ogham space mark, and the capital letters
   whose small letter is a later addition that Windows does not map. */
static const NORM_RANGE NormpIdnaDisallowed[] =
{
    { 0x00001, 0x0001F }, { 0x0007F, 0x0009F }, { 0x004C0, 0x004C0 }, { 0x00600, 0x00605 }, { 0x0061C, 0x0061C },
    { 0x006DD, 0x006DD }, { 0x0070F, 0x0070F }, { 0x008E2, 0x008E2 }, { 0x010A0, 0x010C5 }, { 0x01680, 0x01680 },
    { 0x017B4, 0x017B5 }, { 0x01806, 0x01806 }, { 0x0180E, 0x0180E }, { 0x01C90, 0x01CBA }, { 0x01CBD, 0x01CBF },
    { 0x0200E, 0x0200F }, { 0x02028, 0x0202E }, { 0x02061, 0x02063 }, { 0x02066, 0x0206F }, { 0x02132, 0x02132 },
    { 0x02183, 0x02183 }, { 0x02FF0, 0x02FFB }, { 0x03164, 0x03164 }, { 0x0A7B8, 0x0A7B8 }, { 0x0FFA0, 0x0FFA0 },
    { 0x0FFF9, 0x0FFFF }, { 0x110BD, 0x110BD }, { 0x110CD, 0x110CD }, { 0x16E40, 0x16E5F }, { 0x1D173, 0x1D17A },
    { 0x2F868, 0x2F868 }, { 0x2F874, 0x2F874 }, { 0x2F91F, 0x2F91F }, { 0x2F95F, 0x2F95F }, { 0x2F9BF, 0x2F9BF },
    { 0xE0001, 0xE0001 }, { 0xE0020, 0xE007F }
};

/* what the form removes */
static const NORM_RANGE NormpIdnaIgnored[] =
{
    { 0x000AD, 0x000AD }, { 0x0034F, 0x0034F }, { 0x0180B, 0x0180D }, { 0x0200B, 0x0200D }, { 0x02060, 0x02060 },
    { 0x02064, 0x02064 }, { 0x0FE00, 0x0FE0F }, { 0x0FEFF, 0x0FEFF }, { 0x1BCA0, 0x1BCA3 }, { 0xE0100, 0xE01EF }
};

#define ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))

static __inline BOOL NormpIsIdnaSeparator(ULONG cp)
{
    return cp == '.' || cp == 0x3002 || cp == 0xFF0E || cp == 0xFF61;
}

typedef struct _NORM_BUF
{
    WCHAR *p;
    INT len;
    INT cap;
} NORM_BUF;

static BOOL NormpBufUnit(NORM_BUF *b, WCHAR unit)
{
    if (b->len + 1 > b->cap)
    {
        INT cap = b->cap * 2 + 32;
        WCHAR *p = b->p ? RtlReAllocateHeap(GetProcessHeap(), 0, b->p, cap * sizeof(WCHAR)) :
                          RtlAllocateHeap(GetProcessHeap(), 0, cap * sizeof(WCHAR));

        if (!p)
            return FALSE;
        b->p = p;
        b->cap = cap;
    }
    b->p[b->len++] = unit;
    return TRUE;
}

static BOOL NormpBufAdd(NORM_BUF *b, ULONG cp)
{
    if (cp > 0xFFFF)
    {
        cp -= 0x10000;
        return NormpBufUnit(b, (WCHAR)(0xD800 + (cp >> 10))) && NormpBufUnit(b, (WCHAR)(0xDC00 + (cp & 0x3FF)));
    }
    return NormpBufUnit(b, (WCHAR)cp);
}

static BOOL NormpBufAddUnits(NORM_BUF *b, const USHORT *units, ULONG len)
{
    ULONG i;

    for (i = 0; i < len; i++)
        if (!NormpBufUnit(b, units[i]))
            return FALSE;
    return TRUE;
}

void NormpFree(void *ptr)
{
    if (ptr)
        RtlFreeHeap(GetProcessHeap(), 0, ptr);
}

/* NFKC of a string into a heap string */
static BOOL NormpNfkc(const WCHAR *src, INT n, BOOL restricted, NORM_BUF *out)
{
    NORM_CTX ctx;
    BOOL ok;

    NormpInit(&ctx, TRUE, TRUE, src, n);
    ctx.grow = TRUE;
    ctx.restricted = restricted;
    NormpRun(&ctx);
    ok = ctx.status == NS_OK;
    out->p = ctx.dst;
    out->len = ctx.written;
    out->cap = ctx.dstlen;
    NormpDone(&ctx);
    return ok;
}

/* the units of a string, folded to lower case and without the removed ones */
static BOOL NormpFoldString(const WCHAR *src, INT n, NORM_BUF *out)
{
    INT i = 0;

    while (i < n)
    {
        ULONG cp = src[i++];
        const NORM_MAP *map;

        if (cp >= 0xD800 && cp < 0xDC00 && i < n && src[i] >= 0xDC00 && src[i] < 0xE000)
            cp = 0x10000 + ((cp - 0xD800) << 10) + (src[i++] - 0xDC00);
        if (cp < 0x80)
        {
            if (!NormpBufAdd(out, cp >= 'A' && cp <= 'Z' ? cp + 32 : cp))
                return FALSE;
            continue;
        }
        if (NormpInRanges(NormpIdnaIgnored, ARRAY_COUNT(NormpIdnaIgnored), cp))
            continue;
        map = NormpFindMap(norm_fold, norm_fold_count, cp);
        if (map)
        {
            if (!NormpBufAddUnits(out, &norm_pool[map->off], map->len))
                return FALSE;
        }
        else if (!NormpBufAdd(out, cp))
        {
            return FALSE;
        }
    }
    return TRUE;
}

WCHAR *NormpIdnaMap(const WCHAR *src, INT srclen, BOOL is_normalized, INT *result_len, INT *error_index, INT *valid_len)
{
    NORM_BUF b1 = { NULL, 0, 0 }, b2 = { NULL, 0, 0 }, b3 = { NULL, 0, 0 }, b4 = { NULL, 0, 0 };
    INT i = 0, limit;
    WCHAR *copy;

    *error_index = -1;

    /* the first pass: the invalid units and the characters that are refused end the string that is mapped */
    while (i < srclen)
    {
        ULONG cp, pieces[MAX_PIECES], n, k;
        INT units, bad;

        bad = NormpNextCodePoint(src, srclen, i, &cp, &units);
        if (bad < 0)
        {
            if (cp < 0x80)
            {
                /* the controls, and a NUL that is not the last unit */
                if ((cp >= 1 && cp < 0x20) || cp == 0x7F || (!cp && i != srclen - 1))
                    bad = i;
            }
            else if (!NormpInRanges(NormpIdnaIgnored, ARRAY_COUNT(NormpIdnaIgnored), cp))
            {
                if (NormpInRanges(NormpIdnaDisallowed, ARRAY_COUNT(NormpIdnaDisallowed), cp))
                {
                    bad = i + units - 1;
                }
                else if (!NormpIsIdnaSeparator(cp))
                {
                    /* a dot that only comes out of the compatibility mapping of the character is refused */
                    NormpDecompose(cp, TRUE, pieces, &n);
                    for (k = 0; k < n; k++)
                        if (pieces[k] == '.' || pieces[k] == 0x3002)
                            bad = i + units - 1;
                }
            }
        }
        if (bad >= 0)
        {
            *error_index = bad;
            break;
        }
        i += units;
    }
    limit = i;
    if (valid_len)
        *valid_len = limit;

    /* the label separators other than the dot are dots; the case is folded, the result normalized, folded and
       normalized again */
    copy = RtlAllocateHeap(GetProcessHeap(), 0, (limit + 1) * sizeof(WCHAR));
    if (!copy)
        goto fail;
    for (i = 0; i < limit; i++)
        copy[i] = (src[i] == 0x3002 || src[i] == 0xFF0E || src[i] == 0xFF61) ? '.' : src[i];
    if (!NormpFoldString(copy, limit, &b1))
    {
        NormpFree(copy);
        goto fail;
    }
    NormpFree(copy);
    if (!b1.len)
    {
        *result_len = 0;
        if (!NormpBufAdd(&b1, 0))
            goto fail;
        b1.len = 0;
        return b1.p;
    }
    /*
     * Windows decomposes and folds until nothing changes before it reorders and composes: a mark that comes out of
     * a decomposition and folds to a letter (the Greek ypogegrammeni) is a letter at the place of the character.
     */
    {
        INT round;

        for (round = 0; round < 4; round++)
        {
            INT k = 0;

            b2.len = 0;
            while (k < b1.len)
            {
                ULONG cp, pieces[MAX_PIECES], n, m;
                INT units;

                if (NormpNextCodePoint(b1.p, b1.len, k, &cp, &units) >= 0)
                    goto fail;
                NormpDecompose(cp, TRUE, pieces, &n);
                for (m = 0; m < n; m++)
                    if (!NormpBufAdd(&b2, pieces[m]))
                        goto fail;
                k += units;
            }
            b3.len = 0;
            if (!NormpFoldString(b2.p, b2.len, &b3))
                goto fail;
            if (b3.len == b1.len && !memcmp(b3.p, b1.p, b1.len * sizeof(WCHAR)))
                break;
            NormpFree(b1.p);
            b1 = b3;
            b3.p = NULL; b3.len = b3.cap = 0;
        }
    }
    if (!NormpNfkc(b1.p, b1.len, is_normalized, &b4))
        goto fail;
    NormpFree(b1.p);
    NormpFree(b2.p);
    NormpFree(b3.p);
    *result_len = b4.len;
    return b4.p;

fail:
    NormpFree(b1.p);
    NormpFree(b2.p);
    NormpFree(b3.p);
    NormpFree(b4.p);
    *error_index = -1;
    return NULL;
}

/*** the API ******************************************************************************************************/

static BOOL NormpIsForm(INT form)
{
    return form == NORM_FORM_C || form == NORM_FORM_D || form == NORM_FORM_KC || form == NORM_FORM_KD ||
           form == NORM_FORM_IDNA;
}

/* NormalizeString of the form NormalizationIdna: all of it is made on the heap, then written to the destination;
   the string that is invalid at some index is written up to it */
static INT NormpIdna(const WCHAR *src, INT srclen, WCHAR *dst, INT dstlen)
{
    INT len, index, written;
    WCHAR *mapped = NormpIdnaMap(src, srclen, FALSE, &len, &index, NULL);

    if (!mapped)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    if (len > dstlen)
    {
        INT left = srclen - dstlen, e;

        if (left < 0)
            left = 0;
        e = NormpEstimate(TRUE, left);
        memcpy(dst, mapped, dstlen * sizeof(WCHAR));
        NormpFree(mapped);
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return -(dstlen + e + e / 8);
    }
    memcpy(dst, mapped, len * sizeof(WCHAR));
    written = len;
    NormpFree(mapped);
    if (index >= 0)
    {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return -index;
    }
    SetLastError(ERROR_SUCCESS);
    return written;
}

/******************************************************************************
 *           NormalizeString (KERNEL32.@)
 */
INT WINAPI NormalizeString(NORM_FORM NormForm, LPCWSTR lpSrcString, INT cwSrcLength,
                           LPWSTR lpDstString, INT cwDstLength)
{
    INT form = (INT)NormForm;
    NORM_CTX ctx;
    INT ret, left, e;

    if (!NormpIsForm(form) || !lpSrcString || cwSrcLength < -1 || (lpDstString && cwDstLength < 0))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (cwSrcLength == -1)
        cwSrcLength = (INT)strlenW(lpSrcString) + 1;

    if (!lpDstString || !cwDstLength)
    {
        SetLastError(ERROR_SUCCESS);
        return NormpEstimate(form == NORM_FORM_KC || form == NORM_FORM_KD || form == NORM_FORM_IDNA, cwSrcLength);
    }
    if (!cwSrcLength)
    {
        SetLastError(ERROR_SUCCESS);
        return 0;
    }
    if (form == NORM_FORM_IDNA)
        return NormpIdna(lpSrcString, cwSrcLength, lpDstString, cwDstLength);

    NormpInit(&ctx, form == NORM_FORM_KC || form == NORM_FORM_KD, form == NORM_FORM_C || form == NORM_FORM_KC,
              lpSrcString, cwSrcLength);
    ctx.dst = lpDstString;
    ctx.dstlen = cwDstLength;
    NormpRun(&ctx);

    switch (ctx.status)
    {
        case NS_OK:
            SetLastError(ERROR_SUCCESS);
            ret = ctx.written;
            break;
        case NS_OVERFLOW:
            left = cwSrcLength - ctx.consumed;
            e = NormpEstimate(ctx.compat, left);
            ret = -(cwDstLength + e + e / 8);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            break;
        case NS_INVALID:
            ret = -ctx.error_index;
            SetLastError(ERROR_NO_UNICODE_TRANSLATION);
            break;
        default:
            ret = 0;
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
    }
    NormpDone(&ctx);
    return ret;
}

/******************************************************************************
 *           IsNormalizedString (KERNEL32.@)
 */
BOOL WINAPI IsNormalizedString(NORM_FORM NormForm, LPCWSTR lpString, INT cwLength)
{
    INT form = (INT)NormForm;
    NORM_CTX ctx;
    BOOL ret = FALSE;

    if (!NormpIsForm(form) || !lpString || cwLength < -1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (cwLength == -1)
        cwLength = (INT)strlenW(lpString);
    if (!cwLength)
        return TRUE;

    if (form == NORM_FORM_IDNA)
    {
        INT len, index, valid;
        WCHAR *mapped = NormpIdnaMap(lpString, cwLength, TRUE, &len, &index, &valid);

        if (!mapped)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        /* the mapping of what is valid has to be the source; an invalid unit is an error only if it is reached */
        ret = len == valid && !memcmp(mapped, lpString, len * sizeof(WCHAR));
        NormpFree(mapped);
        if (index >= 0)
        {
            if (ret)
                SetLastError(ERROR_NO_UNICODE_TRANSLATION);
            return FALSE;
        }
        return ret;
    }

    NormpInit(&ctx, form == NORM_FORM_KC || form == NORM_FORM_KD, form == NORM_FORM_C || form == NORM_FORM_KC,
              lpString, cwLength);
    ctx.compare = TRUE;
    ctx.restricted = TRUE;
    NormpRun(&ctx);
    switch (ctx.status)
    {
        case NS_OK:
            ret = TRUE;
            break;
        case NS_MISMATCH:
            break;
        case NS_INVALID:
            SetLastError(ERROR_NO_UNICODE_TRANSLATION);
            break;
        default:
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            break;
    }
    NormpDone(&ctx);
    return ret;
}
