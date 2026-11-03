/* common.h - Common functions

   Copyright (C) 1993 Werner Almesberger <werner.almesberger@lrc.di.epfl.ch>
   Copyright (C) 2008-2014 Daniel Baumann <mail@daniel-baumann.ch>

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

#ifndef _COMMON_H
#define _COMMON_H

#include <sys/types.h>

#include <limits.h>
#include <stdint.h>

#ifndef OFF_MAX
	#define OFF_MAX (off_t)((1ULL << (sizeof(off_t) * CHAR_BIT - 1)) - 1)
#endif

#ifndef __REACTOS__
extern int interactive;
extern int write_immed;
extern int atari_format;	/* Use Atari variation of MS-DOS FS format */
#endif

/* program_name used for printing messages; no name will be printed when it is
 * left as NULL */
extern const char *program_name;

#ifndef __REACTOS__
void die(const char *msg, ...)
    __attribute((noreturn, format(printf, 1, 2)));
#else
DECLSPEC_NORETURN // __attribute((noreturn))
void die_func(const char *msg, ...);
#define die(msg, ...)   \
do {                    \
    die_func("DIE! (%s:%d) " msg "\n", __RELFILE__, __LINE__, ##__VA_ARGS__);  \
} while (0)
#endif

/* Displays a prinf-style message and terminates the program. */

#ifndef __REACTOS__
void pdie(const char *msg, ...)
    __attribute((noreturn, format(printf, 1, 2)));
#else
DECLSPEC_NORETURN // __attribute((noreturn))
void pdie_func(const char *msg, ...);
#define pdie(msg, ...)   \
do {                    \
    pdie_func("P-DIE! (%s:%d) " msg "\n", __RELFILE__, __LINE__, ##__VA_ARGS__);  \
} while (0)
#endif

/* Like die, but appends an error message according to the state of errno. */

#ifndef __REACTOS__
void *alloc(int size);
#else
void *vfalloc(int size);
void *vfcalloc(int size, int count);
void vffree(void *ptr);
#endif

/* mallocs SIZE bytes and returns a pointer to the data. Terminates the program
   if malloc fails. */

void *qalloc(void **root, int size);

/* Like alloc, but registers the data area in a list described by ROOT. */

void qfree(void **root);

/* Deallocates all qalloc'ed data areas described by ROOT. */

#ifndef __REACTOS__
int min(int a, int b);
#endif

/* Returns the smaller integer value of a and b. */

int xasprintf(char **strp, const char *fmt, ...)
    __attribute((format(printf, 2, 3)));

/* Runs asprintf() and terminates the program if it fails. */

int get_choice(int noninteractive_result, const char *noninteractive_msg,
	       int choices, ...);

/*
 * Display a numbered list of choices and accept user input to select one. If
 * interactive is false, it will instead print noninteractive_msg and return
 * noninteractive_result. The number of options must be given in choices and
 * must be more than one and less than ten.
 *
 * The variable arguments are choices times <int val, const char *desc>, where
 * val is the value that is returned when the user selects this option and desc
 * is the string describing this option.
 */

char *get_line(const char *prompt, char *dest, size_t length);

#ifdef __REACTOS__
char get_key(const char *valid, const char *prompt);
#endif

/*
 * Display prompt and read a line, placing it in dest with at most length-1
 * characters plus a null byte. This behaves like printing a prompt and fgets()
 * afterwards with the addition of temporarily enabling canonical input mode
 * with echo if needed.
 */

#ifndef __REACTOS__
void check_atari(void);

/*
 * ++roman: On m68k Linux, check if this is an Atari; if yes, turn on Atari
 * variant of MS-DOS filesystem by default.
 */

uint32_t generate_volume_id(void);

/*
 * Generate a 32 bit volume ID
 */
#endif

int validate_volume_label(char *doslabel);

/*
 * Validate volume label
 */

#endif
