/* check.h - Check and repair a PC/MS-DOS filesystem

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

#ifndef _CHECK_H
#define _CHECK_H

void check_dirty_bits(DOS_FS * fs);

int scan_root(DOS_FS * fs);

/* Scans the root directory and recurses into all subdirectories. See check.c
   for all the details. Returns a non-zero integer if the filesystem has to
   be checked again. */


void check_label(DOS_FS * fs);

/* Checks the volume label from the root directory entry that is valid and
 * matches the label stored in boot sector. */

#endif
