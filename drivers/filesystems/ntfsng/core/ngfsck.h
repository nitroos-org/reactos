/* SPDX-License-Identifier: GPL-2.0-or-later */
/* ngfsck.h - the fast mount-time consistency check (ngfsck.c). */
#ifndef NGFSCK_H
#define NGFSCK_H

struct ngc_fsck_res {
	unsigned long long records, inuse, dirs, ientries, clusters, leaked_clusters;
	unsigned int fatal, leaks, dirs_skipped, clusters_skipped, ms;
	unsigned int leaked_records;	/* records marked in $MFT:$BITMAP that are not in use (also counted in leaks) */
	unsigned int pass_ms[3];	/* time of each pass: sequence numbers, records, directory indexes */
	unsigned int fixed_records, repair_errors, repair_refused;
	unsigned long long fixed_clusters;
	unsigned long long ext_records, reparse, sys_clusters, log_clusters, index_clusters;
	/*
	 * Unmarked: an in-use record whose $MFT:$BITMAP bit is clear, a cluster referenced (once) by an in-use record and free
	 * in $Bitmap.  Either can be handed out again; the repair sets the bit, which loses nothing.  Counted here instead of
	 * as damage only when the caller asked for it (NGC_FSCK_MARKS, NGC_FSCK_DEFER_MARKS).
	 */
	unsigned int unmarked_records, marked_records;
	unsigned long long unmarked_clusters, marked_clusters;
	char why[128];		/* the first fatal finding */
};

/* ngc_fsck_ex @fix bits */
#define NGC_FSCK_FIX		1	/* free the leaks and set the bits of what is unmarked (FSCTL check with repair) */
#define NGC_FSCK_MARKS		2	/* set the bits of what is unmarked, leave the leaks */
#define NGC_FSCK_DEFER_MARKS	4	/* count what is unmarked without repairing it and without calling it damage: the caller
					   repairs it once the volume is writable (the mount-time check of the read-only pass) */

/* 0 when the check ran (r->fatal says whether the volume is damaged); a negative errno if it could not run. */
int ngc_fsck(struct ntfs_volume *vol, struct block_device *b, struct ngc_fsck_res *r);

/*
 * As ngc_fsck, with the @fix bits above (the caller holds the volume lock when anything is repaired).  A repair runs only when
 * no damage was found.  Without NGC_FSCK_MARKS / NGC_FSCK_FIX / NGC_FSCK_DEFER_MARKS what is unmarked is damage.
 */
int ngc_fsck_ex(struct ntfs_volume *vol, struct block_device *b, struct ngc_fsck_res *r, int fix);

#endif
