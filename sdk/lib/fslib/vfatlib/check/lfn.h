/* lfn.h - Functions for handling VFAT long filenames

   Copyright (C) 1998 Roman Hodek <Roman.Hodek@informatik.uni-erlangen.de>
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

#ifndef _LFN_H
#define _LFN_H

void lfn_reset(void);
/* Reset the state of the LFN parser. */

void lfn_add_slot(DIR_ENT * de, off_t dir_offset);
/* Process a dir slot that is a VFAT LFN entry. */

char *lfn_get(DIR_ENT * de, off_t * lfn_offset);
/* Retrieve the long name for the proper dir entry. */

void lfn_check_orphaned(void);

void lfn_fix_checksum(off_t from, off_t to, const char *short_name);

#endif
