
#define WIN32_NO_STATUS
#include <wine/unicode.h>

#define NDEBUG
#include <debug.h>

#include "normdata.h"

#ifndef IDN_ALLOW_UNASSIGNED
#define IDN_ALLOW_UNASSIGNED 0x01
#define IDN_USE_STD3_ASCII_RULES 0x02
#endif

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

INT WINAPI IdnpToUnicode(DWORD dwFlags, LPCWSTR lpASCIICharStr, INT cchASCIIChar,
                         LPWSTR lpUnicodeCharStr, INT cchUnicodeChar)
{
    INT i, label_start, label_end, out = 0;
    WCHAR ch;
    ULONG lab[128];

    DPRINT("%x %p %d %p %d\n", dwFlags, lpASCIICharStr, cchASCIIChar,
           lpUnicodeCharStr, cchUnicodeChar);

    for(label_start=0; label_start<cchASCIIChar;) {
        INT n = INIT_N, pos = 0, old_pos, w, k, bias = INIT_BIAS, delim=0, digit, t, cnt, units;

        for(i=label_start; i<cchASCIIChar; i++) {
            ch = lpASCIICharStr[i];

            if(ch>0x7f || (i!=cchASCIIChar-1 && !ch)) {
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }

            if(!ch || ch=='.')
                break;
            if(ch == '-')
                delim = i;

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

        if((dwFlags&IDN_USE_STD3_ASCII_RULES) && (lpASCIICharStr[label_start]=='-' ||
                    lpASCIICharStr[label_end-1]=='-')) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }
        if(label_end-label_start > 63) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }

        if(label_end-label_start<4 ||
                tolowerW(lpASCIICharStr[label_start])!='x' ||
                tolowerW(lpASCIICharStr[label_start+1])!='n' ||
                lpASCIICharStr[label_start+2]!='-' || lpASCIICharStr[label_start+3]!='-') {
            if(label_end < cchASCIIChar)
                label_end++;

            if(!lpUnicodeCharStr) {
                out += label_end-label_start;
            }else if(out+label_end-label_start <= cchUnicodeChar) {
                memcpy(lpUnicodeCharStr+out, lpASCIICharStr+label_start,
                        (label_end-label_start)*sizeof(WCHAR));
                out += label_end-label_start;
            }else {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }

            label_start = label_end;
            continue;
        }

        if(delim == label_start+3)
            delim++;
        /* the label is built as code points: the basic ones, then the decoded ones inserted at their places */
        cnt = delim-label_start-4;
        if(cnt > 63) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }
        for(i=0; i<cnt; i++)
            lab[i] = lpASCIICharStr[label_start+4+i];
        if(cnt)
            delim++;

        for(i=delim; i<label_end;) {
            old_pos = pos;
            w = 1;
            for(k=BASE; ; k+=BASE) {
                ch = i<label_end ? tolowerW(lpASCIICharStr[i++]) : 0;
                if((ch<'a' || ch>'z') && (ch<'0' || ch>'9')) {
                    SetLastError(ERROR_INVALID_NAME);
                    return 0;
                }
                digit = ch<='9' ? ch-'0'+'z'-'a'+1 : ch-'a';
                if(digit && w > (0x7fffffff-pos)/digit) {
                    SetLastError(ERROR_INVALID_NAME);
                    return 0;
                }
                pos += digit*w;
                t = k<=bias ? TMIN : k>=bias+TMAX ? TMAX : k-bias;
                if(digit < t)
                    break;
                if(w > 0x7fffffff/(BASE-t)) {
                    SetLastError(ERROR_INVALID_NAME);
                    return 0;
                }
                w *= BASE-t;
            }
            bias = adapt(pos-old_pos, cnt+1, old_pos==0);
            n += pos/(cnt+1);
            pos %= cnt+1;

            if(n > 0x10FFFF || (n >= 0xD800 && n < 0xE000) || cnt >= 64 ||
                    ((dwFlags&IDN_ALLOW_UNASSIGNED)==0 && NormpIsUnassigned(n))) {
                SetLastError(ERROR_INVALID_NAME);
                return 0;
            }
            memmove(lab+pos+1, lab+pos, (cnt-pos)*sizeof(ULONG));
            lab[pos] = n;
            cnt++;
            pos++;
        }

        if(cnt > 63) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }

        for(i=0, units=0; i<cnt; i++)
            units += lab[i] > 0xFFFF ? 2 : 1;
        if(!lpUnicodeCharStr) {
            out += units;
        }else if(out+units <= cchUnicodeChar) {
            for(i=0; i<cnt; i++) {
                if(lab[i] > 0xFFFF) {
                    lpUnicodeCharStr[out++] = (WCHAR)(0xD800 + ((lab[i]-0x10000) >> 10));
                    lpUnicodeCharStr[out++] = (WCHAR)(0xDC00 + ((lab[i]-0x10000) & 0x3FF));
                }else {
                    lpUnicodeCharStr[out++] = (WCHAR)lab[i];
                }
            }
        }else {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        if(label_end < cchASCIIChar) {
            if(!lpUnicodeCharStr) {
                out++;
            }else if(out+1 <= cchUnicodeChar) {
                lpUnicodeCharStr[out++] = lpASCIICharStr[label_end];
            }else {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
        }
        label_start = label_end+1;
    }

    return out;
}
