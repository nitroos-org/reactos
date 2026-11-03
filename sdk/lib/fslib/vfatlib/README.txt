The FAT Checker is taken from dosfstools' fsck.fat
https://github.com/dosfstools/dosfstools
Synced (2026-11-03) with dosfstools 4.2 (tag v4.2, commit 697f7692c951173c1b732901e13f72bd3182d575)
plus the upstream fsck.fat fixes after it, up to commit 289a48b9cb5b3c589391d28aa2515c325c932c7a.
Previous sync: 4.1 (commit 820c2f90726db0468e0a684a5dc500fbde66466f); the old note naming
commit ed4e47b6757c05d4c23a9075b8b68003aa5dbfb8 was stale.

Licence: GPL-3.0-or-later (sdk/lib/fslib/vfatlib/check/COPYING). Keep the code isolated in check/.

ReactOS adaptation layer (keep it when syncing again):
 - check/io.c: device I/O through NT calls (no stdio), sector-aligned access, volume lock/dismount/dirty query
 - check/rosglue.h: printf -> VfatPrint (fmifs callback), flags in FsCheckFlags, no command line options
 - check/common.c: die/pdie end the process, allocation from the process heap, get_choice() never prompts
 - check/charconv.c: internal CP850 table only (no iconv/locale)
 - check/check.c: check_dirty_bits() ignores the dirty state that vfatfs itself sets when mounting a clean
   volume; reads past the end of a file are not reported in read-only mode
 - check/fat.c, check/boot.c: no recovery/free-count changes in read-only mode, backup boot sector dirty byte
 - vfatlib.c: VfatChkdsk() is the fsck.fat main() and maps the result to the fmifs exit status
