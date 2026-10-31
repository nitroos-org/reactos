
#define WIN32_NO_STATUS
#include <wine/unicode.h>

#define NDEBUG
#include <debug.h>

#include "normdata.h"

#ifndef IDN_ALLOW_UNASSIGNED
#define IDN_ALLOW_UNASSIGNED 0x01
#define IDN_USE_STD3_ASCII_RULES 0x02
#endif

/* kernel32 does not call its own HeapAlloc and HeapFree, they are the heap functions of ntdll */
NTSYSAPI PVOID NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
#define HeapAlloc(heap, flags, size) RtlAllocateHeap(heap, flags, size)
#define HeapFree(heap, flags, ptr) RtlFreeHeap(heap, flags, ptr)

/* Taken from Wine kernel32/locale.c */

enum {
    BASE = 36,
    TMIN = 1,
    TMAX = 26,
    SKEW = 38,
    DAMP = 700,
    INIT_BIAS = 72,
    INIT_N = 128
};

static inline INT adapt(INT delta, INT numpoints, BOOL firsttime)
{
    INT k;

    delta /= (firsttime ? DAMP : 2);
    delta += delta/numpoints;

    for(k=0; delta>((BASE-TMIN)*TMAX)/2; k+=BASE)
        delta /= BASE-TMIN;
    return k+((BASE-TMIN+1)*delta)/(delta+SKEW);
}

/* the units of a string as code points: a surrogate pair is one, any other unit is itself */
static INT IdnpToCodePoints(const WCHAR *str, INT len, ULONG *cps)
{
    INT i = 0, n = 0;

    while (i < len)
    {
        ULONG cp = str[i++];

        if (cp >= 0xD800 && cp < 0xDC00 && i < len && str[i] >= 0xDC00 && str[i] < 0xE000)
            cp = 0x10000 + ((cp - 0xD800) << 10) + (str[i++] - 0xDC00);
        cps[n++] = cp;
    }
    return n;
}

/*
 * The nameprep of RFC 3491 as Windows 10 does it (measured for every code point and each flag). A label of ASCII
 * only is not mapped (its case stays unless another label of the string has more than ASCII, then it is folded as
 * well), but a control character is invalid in it. Any other label is mapped by the
 * form NormalizationIdna of NormalizeString (the Unicode 11.0 case folding and NFKC, see normalize.c), then
 *  - what is not assigned in Unicode 11.0 (private use and the Hangul fillers included) is an invalid name,
 *    unless IDN_ALLOW_UNASSIGNED is given (the checks of RFC 3454 for the direction of text are not made),
 *  - in a string that has more than ASCII, a last label of ASCII only (after the mapping) that ends in an at sign is
 *    an invalid name,
 *  - with IDN_USE_STD3_ASCII_RULES the label has letters, digits and hyphens only, and no hyphen at either end.
 * What the mapping refuses or removes altogether (an empty result) is an invalid name.
 */
INT WINAPI IdnpToNameprep(DWORD dwFlags, LPCWSTR lpUnicodeCharStr, INT cchUnicodeChar,
                          LPWSTR lpNameprepCharStr, INT cchNameprepChar)
{
    WCHAR *mapped;
    DWORD i, label_start, label_end, out = 0;
    INT map_len, map_error;
    BOOL ascii_only, any_non_ascii = FALSE, last_label;
    WCHAR ch;

    DPRINT("%x %p %d %p %d\n", dwFlags, lpUnicodeCharStr, cchUnicodeChar,
           lpNameprepCharStr, cchNameprepChar);

    if(dwFlags & ~(IDN_ALLOW_UNASSIGNED|IDN_USE_STD3_ASCII_RULES)) {
        SetLastError(ERROR_INVALID_FLAGS);
        return 0;
    }

    if(!lpUnicodeCharStr || cchUnicodeChar<-1) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if(cchUnicodeChar == -1)
        cchUnicodeChar = (UINT)strlenW(lpUnicodeCharStr)+1;
    if(!cchUnicodeChar || (cchUnicodeChar==1 && lpUnicodeCharStr[0]==0)) {
        SetLastError(ERROR_INVALID_NAME);
        return 0;
    }

    for(i=0; i<(DWORD)cchUnicodeChar; i++)
        if(lpUnicodeCharStr[i] > 0x7f)
            any_non_ascii = TRUE;

    for(label_start=0; label_start<(UINT)cchUnicodeChar;) {
        ascii_only = TRUE;
        for(i=label_start; i<(UINT)cchUnicodeChar; i++) {
            ch = lpUnicodeCharStr[i];

            if(i!=cchUnicodeChar-1 && !ch) {
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }
            /* check if ch is one of label separators defined in RFC3490 */
            if(!ch || ch=='.' || ch==0x3002 || ch==0xff0e || ch==0xff61)
                break;

            if(ch < 0x20 || ch == 0x7f) {
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }

            if(ch > 0x7f) {
                ascii_only = FALSE;
                continue;
            }

            if((dwFlags&IDN_USE_STD3_ASCII_RULES) == 0)
                continue;
            if((ch>='a' && ch<='z') || (ch>='A' && ch<='Z')
                    || (ch>='0' && ch<='9') || ch=='-')
                continue;

            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }
        label_end = i;
        /* last label may be empty */
        if(label_start==label_end && ch) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }

        if((dwFlags&IDN_USE_STD3_ASCII_RULES) && (lpUnicodeCharStr[label_start]=='-' ||
                    lpUnicodeCharStr[label_end-1]=='-')) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }

        last_label = label_end >= (UINT)cchUnicodeChar - (lpUnicodeCharStr[cchUnicodeChar-1] ? 0 : 1);

        if(ascii_only) {
            if(any_non_ascii && last_label && label_end > label_start && lpUnicodeCharStr[label_end-1] == '@') {
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }
            /* maximal label length is 63 characters */
            if(label_end-label_start > 63) {
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }
            if(label_end < (UINT)cchUnicodeChar)
                label_end++;

            if(!lpNameprepCharStr) {
                out += label_end-label_start;
            }else if(out+label_end-label_start <= (UINT)cchNameprepChar) {
                memcpy(lpNameprepCharStr+out, lpUnicodeCharStr+label_start,
                        (label_end-label_start)*sizeof(WCHAR));
                if(any_non_ascii) {
                    /* a string with more than ASCII is mapped as a whole: the case of its ASCII labels is folded too */
                    for(i=0; i<label_end-label_start; i++)
                        if(lpNameprepCharStr[out+i] >= 'A' && lpNameprepCharStr[out+i] <= 'Z')
                            lpNameprepCharStr[out+i] += 'a'-'A';
                }
                if(lpUnicodeCharStr[label_end-1] > 0x7f)
                    lpNameprepCharStr[out+label_end-label_start-1] = '.';
                out += label_end-label_start;
            }else {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }

            label_start = label_end;
            continue;
        }

        mapped = NormpIdnaMap(lpUnicodeCharStr+label_start, label_end-label_start, FALSE, &map_len, &map_error, NULL);
        if(!mapped || map_error >= 0 || !map_len) {
            SetLastError(!mapped ? ERROR_NOT_ENOUGH_MEMORY : ERROR_INVALID_NAME);
            NormpFree(mapped);
            return 0;
        }

        /* the checks of what the label has become */
        for(i=0; i<(DWORD)map_len;) {
            ULONG cp = mapped[i++];

            if(cp >= 0xD800 && cp < 0xDC00 && i < (DWORD)map_len && mapped[i] >= 0xDC00 && mapped[i] < 0xE000)
                cp = 0x10000 + ((cp - 0xD800) << 10) + (mapped[i++] - 0xDC00);
            if(((dwFlags&IDN_ALLOW_UNASSIGNED) == 0 && NormpIsUnassigned(cp)) ||
               (cp < 0x80 && (dwFlags&IDN_USE_STD3_ASCII_RULES) &&
                !((cp>='a' && cp<='z') || (cp>='A' && cp<='Z') || (cp>='0' && cp<='9') || cp=='-'))) {
                NormpFree(mapped);
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }
        }
        if(last_label && mapped[map_len-1] == '@') {
            for(i=0; i<(DWORD)map_len && mapped[i] < 0x80; i++);
            if(i == (DWORD)map_len) {
                NormpFree(mapped);
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }
        }
        if((dwFlags&IDN_USE_STD3_ASCII_RULES) && (mapped[0]=='-' || mapped[map_len-1]=='-')) {
            NormpFree(mapped);
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }

        /* the separator after the label is a dot (or the end of the string) */
        i = map_len;
        if(label_end < (UINT)cchUnicodeChar)
            i++;
        if(!lpNameprepCharStr) {
            out += i;
        }else if(out+i <= (UINT)cchNameprepChar) {
            memcpy(lpNameprepCharStr+out, mapped, map_len*sizeof(WCHAR));
            if(label_end < (UINT)cchUnicodeChar)
                lpNameprepCharStr[out+map_len] = lpUnicodeCharStr[label_end] ? '.' : 0;
            out += i;
        }else {
            NormpFree(mapped);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        NormpFree(mapped);

        if(label_end < (UINT)cchUnicodeChar)
            label_end++;
        label_start = label_end;
    }

    return out;
}

INT WINAPI IdnpToAscii(DWORD dwFlags, LPCWSTR lpUnicodeCharStr, INT cchUnicodeChar,
                       LPWSTR lpASCIICharStr, INT cchASCIIChar)
{
    static const WCHAR prefixW[] = {'x','n','-','-'};

    WCHAR *norm_str;
    ULONG *cps;
    INT i, label_start, label_end, norm_len, ncp, out_label, out = 0;

    DPRINT("%x %p %d %p %d\n", dwFlags, lpUnicodeCharStr, cchUnicodeChar,
           lpASCIICharStr, cchASCIIChar);

    norm_len = IdnpToNameprep(dwFlags, lpUnicodeCharStr, cchUnicodeChar, NULL, 0);
    if(!norm_len)
        return 0;
    norm_str = HeapAlloc(GetProcessHeap(), 0, norm_len*sizeof(WCHAR));
    if(!norm_str) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    norm_len = IdnpToNameprep(dwFlags, lpUnicodeCharStr,
            cchUnicodeChar, norm_str, norm_len);
    if(!norm_len) {
        HeapFree(GetProcessHeap(), 0, norm_str);
        return 0;
    }
    /* the punycode works on code points: a pair of surrogates is one */
    cps = HeapAlloc(GetProcessHeap(), 0, norm_len*sizeof(ULONG));
    if(!cps) {
        HeapFree(GetProcessHeap(), 0, norm_str);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    ncp = IdnpToCodePoints(norm_str, norm_len, cps);
    HeapFree(GetProcessHeap(), 0, norm_str);

    for(label_start=0; label_start<ncp;) {
        INT n = INIT_N, bias = INIT_BIAS;
        INT delta = 0, b = 0, h;

        out_label = out;
        for(i=label_start; i<ncp && cps[i]!='.' &&
                cps[i]!=0x3002 && cps[i]!='\0'; i++)
            if(cps[i] < 0x80)
                b++;
        label_end = i;

        if(b == label_end-label_start) {
            if(label_end < ncp)
                b++;
            if(!lpASCIICharStr) {
                out += b;
            }else if(out+b <= cchASCIIChar) {
                for(i=0; i<b; i++)
                    lpASCIICharStr[out+i] = (WCHAR)cps[label_start+i];
                out += b;
            }else {
                HeapFree(GetProcessHeap(), 0, cps);
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            label_start = label_end+1;
            continue;
        }

        if(!lpASCIICharStr) {
            out += 5+b; /* strlen(xn--...-) */
        }else if(out+5+b <= cchASCIIChar) {
            memcpy(lpASCIICharStr+out, prefixW, sizeof(prefixW));
            out += 4;
            for(i=label_start; i<label_end; i++)
                if(cps[i] < 0x80)
                    lpASCIICharStr[out++] = (WCHAR)cps[i];
            lpASCIICharStr[out++] = '-';
        }else {
            HeapFree(GetProcessHeap(), 0, cps);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        if(!b)
            out--;

        for(h=b; h<label_end-label_start;) {
            INT m = 0x7fffffff, q, k;

            for(i=label_start; i<label_end; i++) {
                if((INT)cps[i]>=n && m>(INT)cps[i])
                    m = (INT)cps[i];
            }
            delta += (m-n)*(h+1);
            n = m;

            for(i=label_start; i<label_end; i++) {
                if((INT)cps[i] < n) {
                    delta++;
                }else if((INT)cps[i] == n) {
                    for(q=delta, k=BASE; ; k+=BASE) {
                        INT t = k<=bias ? TMIN : k>=bias+TMAX ? TMAX : k-bias;
                        INT disp = q<t ? q : t+(q-t)%(BASE-t);
                        if(!lpASCIICharStr) {
                            out++;
                        }else if(out+1 <= cchASCIIChar) {
                            lpASCIICharStr[out++] = disp<='z'-'a' ?
                                'a'+disp : '0'+disp-'z'+'a'-1;
                        }else {
                            HeapFree(GetProcessHeap(), 0, cps);
                            SetLastError(ERROR_INSUFFICIENT_BUFFER);
                            return 0;
                        }
                        if(q < t)
                            break;
                        q = (q-t)/(BASE-t);
                    }
                    bias = adapt(delta, h+1, h==b);
                    delta = 0;
                    h++;
                }
            }
            delta++;
            n++;
        }

        if(out-out_label > 63) {
            HeapFree(GetProcessHeap(), 0, cps);
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }

        if(label_end < ncp) {
            if(!lpASCIICharStr) {
                out++;
            }else if(out+1 <= cchASCIIChar) {
                lpASCIICharStr[out++] = cps[label_end] ? '.' : 0;
            }else {
                HeapFree(GetProcessHeap(), 0, cps);
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
        }
        label_start = label_end+1;
    }

    HeapFree(GetProcessHeap(), 0, cps);
    return out;
}
