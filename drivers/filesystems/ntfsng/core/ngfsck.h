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
	char why[128];		/* the first fatal finding */
};

/* 0 when the check ran (r->fatal says whether the volume is damaged); a negative errno if it could not run. */
int ngc_fsck(struct ntfs_volume *vol, struct block_device *b, struct ngc_fsck_res *r);

/* As ngc_fsck; with @fix, a check that found no damage then frees its leaks (the caller holds the volume lock). */
int ngc_fsck_ex(struct ntfs_volume *vol, struct block_device *b, struct ngc_fsck_res *r, int fix);

#endif
