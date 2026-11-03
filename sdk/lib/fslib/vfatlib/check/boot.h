/* boot.h - Read and analyze ia PC/MS-DOS boot sector

   Copyright (C) 1993 Werner Almesberger <werner.almesberger@lrc.di.epfl.ch>
   Copyright (C) 2008-2014 Daniel Baumann <mail@daniel-baumann.ch>
   Copyright (C) 2017 Andreas Bombe <aeb@debian.org>

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

#ifndef _BOOT_H
#define _BOOT_H

#include <stdint.h>

void read_boot(DOS_FS * fs);
void write_label(DOS_FS * fs, char *label);
void write_boot_label(DOS_FS * fs, const char *label);
void write_volume_label(DOS_FS * fs, char *label);
void remove_label(DOS_FS *fs);
void write_serial(DOS_FS * fs, uint32_t serial);
off_t find_volume_de(DOS_FS * fs, DIR_ENT * de);
const char *pretty_label(const char *label, char rep);

/* Reads the boot sector from the currently open device and initializes *FS */


off_t alloc_rootdir_entry(DOS_FS * fs, DIR_ENT * de, const char *pattern, int gen_name);

/* Allocate a free slot in the root directory for a new file. If gen_name is
   true, the file name is constructed after 'pattern', which must include a %d
   type format for printf and expand to exactly 11 characters. The name
   actually used is written into the 'de' structure, the rest of *de is cleared.
   The offset returned is to where in the filesystem the entry belongs. */

#endif
