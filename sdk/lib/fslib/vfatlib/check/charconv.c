/* charconv.c

   Copyright (C) 2010 Alexander Korolkov <alexander.korolkov@gmail.com>
   Copyright (C) 2018-2020 Pali Rohár <pali.rohar@gmail.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>.

   The complete text of the GNU General Public License
   can be found in /usr/share/common-licenses/GPL-3 file.
*/

/* ReactOS: derived from dosfstools (fsck.fat), https://github.com/dosfstools/dosfstools
 * Synced to release 4.2 (697f7692c951173c1b732901e13f72bd3182d575) plus later upstream
 * fixes up to commit 289a48b9cb5b3c589391d28aa2515c325c932c7a.
 * License: GPL-3.0-or-later (see COPYING in this directory). The ReactOS adaptation
 * (NT I/O, fmifs output, no exit/stdio) is marked __REACTOS__ or lives in rosglue.h. */

/* ReactOS: only the internal CP850 conversion tables are used (no iconv, no
 * locale); the ReactOS port of the checker never takes input interactively. */
#include "vfatlib.h"

#define NDEBUG
#include <debug.h>

/* CP850 table for 0x80-0xFF range from:
 * http://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/PC/CP850.TXT
 */
static const wchar_t cp850_table[128] = {
    0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7,
    0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5,
    0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
    0x00ff, 0x00d6, 0x00dc, 0x00f8, 0x00a3, 0x00d8, 0x00d7, 0x0192,
    0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba,
    0x00bf, 0x00ae, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00c1, 0x00c2, 0x00c0,
    0x00a9, 0x2563, 0x2551, 0x2557, 0x255d, 0x00a2, 0x00a5, 0x2510,
    0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x00e3, 0x00c3,
    0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x00a4,
    0x00f0, 0x00d0, 0x00ca, 0x00cb, 0x00c8, 0x0131, 0x00cd, 0x00ce,
    0x00cf, 0x2518, 0x250c, 0x2588, 0x2584, 0x00a6, 0x00cc, 0x2580,
    0x00d3, 0x00df, 0x00d4, 0x00d2, 0x00f5, 0x00d5, 0x00b5, 0x00fe,
    0x00de, 0x00da, 0x00db, 0x00d9, 0x00fd, 0x00dd, 0x00af, 0x00b4,
    0x00ad, 0x00b1, 0x2017, 0x00be, 0x00b6, 0x00a7, 0x00f7, 0x00b8,
    0x00b0, 0x00a8, 0x00b7, 0x00b9, 0x00b3, 0x00b2, 0x25a0, 0x00a0,
};

/* CP850 translit table to 7bit ASCII for 0x80-0xFF range */
static const char *const cp850_translit_table[128] = {
    "C",   "u",   "e",  "a",     "a",     "a", "a",   "c",
    "e",   "e",   "e",  "i",     "i",     "i", "A",   "A",
    "E",   "ae",  "AE", "o",     "o",     "o", "u",   "u",
    "y",   "O",   "U",  "o",     "GBP",   "O", "x",   "f",
    "a",   "i",   "o",  "u",     "n",     "N", "a",   "o",
    "?",   "(R)", "!",  " 1/2 ", " 1/4 ", "!", "<<",  ">>",
    "?",   "?",   "?",  "|",     "+",     "A", "A",   "A",
    "(C)", "?",   "?",  "?",     "?",     "c", "JPY", "+",
    "+",   "+",   "+",  "+",     "-",     "+", "a",   "A",
    "?",   "?",   "?",  "?",     "?",     "?", "?",   "?",
    "d",   "D",   "E",  "E",     "E",     "i", "I",   "I",
    "I",   "+",   "+",  "?",     "?",     "|", "I",   "?",
    "O",   "ss",  "O",  "O",     "o",     "O", "u",   "th",
    "TH",  "U",   "U",  "U",     "y",     "Y", "?",   "'",
    "-",   "+-",  "?",  " 3/4 ", "?",     "?", "/",   ",",
    "?",   "?",   ".",  "1",     "3",     "2", "?",   " ",
};

static int wchar_string_to_cp850_string(char *out, const wchar_t *in, unsigned int out_size)
{
    unsigned i, j;
    for (i = 0; i < out_size-1 && in[i]; ++i) {
        if (in[i] > 0 && in[i] < 0x80) {
            out[i] = in[i];
            continue;
        }
        for (j = 0; j < 0x80; ++j) {
            if (in[i] == cp850_table[j]) {
                out[i] = (0x80 | j);
                break;
            }
        }
        if (j == 0x80) {
            fprintf(stderr, "Cannot convert input character 0x%04x to 'CP850': Illegal byte sequence\n", (unsigned int)in[i]);
            return 0;
        }
    }
    if (in[i]) {
        fprintf(stderr, "Cannot convert input string to 'CP850': String is too long\n");
        return 0;
    }
    out[i] = 0;
    return 1;
}

static int cp850_string_to_wchar_string(wchar_t *out, const char *in, unsigned int out_size)
{
    unsigned i;
    for (i = 0; i < out_size-1 && i < 11 && in[i]; ++i) {
        out[i] = (in[i] & 0x80) ? cp850_table[in[i] & 0x7F] : in[i];
    }
    if (i < 11 && in[i]) {
        fprintf(stderr, "Cannot convert input string to 'CP850': String is too long\n");
        return 0;
    }
    out[i] = L'\0';
    return 1;
}

static int cp850_char_to_printable(char **p, unsigned char c, unsigned int out_size)
{
    size_t ret;
    wchar_t wcs[2];
    if (!c)
        return 0;
    wcs[0] = (c & 0x80) ? cp850_table[c & 0x7F] : c;
    wcs[1] = 0;
    ret = wcstombs(*p, wcs, out_size);
    if (ret == 0)
        return 0;
    if (ret != (size_t)-1)
        *p += ret;
    else if (!(c & 0x80))
        *(*p++) = c;
    else {
        ret = strlen(cp850_translit_table[c & 0x7F]);
        if (ret > out_size)
            return 0;
        memcpy(*p, cp850_translit_table[c & 0x7F], ret);
        *p += ret;
    }
    return 1;
}

static int local_string_to_cp850_string(char *out, const char *in, unsigned int out_size)
{
    int ret;
    wchar_t *wcs;
    if (strlen(in) >= out_size) {
        fprintf(stderr, "Cannot convert input string '%s' to 'CP850': String is too long\n", in);
        return 0;
    }
    wcs = calloc(out_size, sizeof(wchar_t));
    if (!wcs) {
        fprintf(stderr, "Cannot convert input string '%s' to 'CP850': Out of memory\n", in);
        return 0;
    }
    if (mbstowcs(wcs, in, out_size) == (size_t)-1) {
        fprintf(stderr, "Cannot convert input string '%s' to 'CP850': Invalid multibyte sequence\n", in);
        free(wcs);
        return 0;
    }
    ret = wchar_string_to_cp850_string(out, wcs, out_size);
    free(wcs);
    return ret;
}

int set_dos_codepage(int codepage)
{
    static int initialized = -1;
    if (initialized < 0) {
        if (codepage < 0)
            codepage = DEFAULT_DOS_CODEPAGE;
        initialized = (codepage == 850) ? 1 : 0;
        if (!initialized)
            fprintf(stderr, "Cannot initialize unsupported codepage %d, only codepage 850 is supported\n", codepage);
    }
    return initialized;
}

int dos_char_to_printable(char **p, unsigned char c, unsigned int out_size)
{
    return cp850_char_to_printable(p, c, out_size);
}

int local_string_to_dos_string(char *out, char *in, unsigned int out_size)
{
    return local_string_to_cp850_string(out, in, out_size);
}

int dos_string_to_wchar_string(wchar_t *out, char *in, unsigned int out_size)
{
    return cp850_string_to_wchar_string(out, in, out_size);
}

int wchar_string_to_dos_string(char *out, wchar_t *in, unsigned int out_size)
{
    return wchar_string_to_cp850_string(out, in, out_size);
}


