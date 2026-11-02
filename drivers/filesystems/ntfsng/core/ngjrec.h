/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef NGJREC_H
#define NGJREC_H

#define NGJ_MAXRUNS 32
enum { NGJ_NONE, NGJ_CLEAN, NGJ_REPAIR, NGJ_UNREAD };

struct ngj_run { s64 vcn, lcn, len; };

struct ngj_vol {
	void *osdev;
	u64 size;
	unsigned int devsec;
	u32 bps, cluster, recsz;
	u64 mft_lcn, mirr_lcn, serial;
	struct kj_ext ext[NGJ_MAXRUNS];
	int next;
	u64 lf_pages;
	struct block_device *bdev;
	u32 replayed;
	int torn, cleared_dirty;
	int pair_pending;	/* read-only view: the $Volume pair is shown repaired, the write pass must write it */
};

int ngj_probe(void *osdev, u64 size, unsigned int devsec, struct ngj_vol *jv);
int ngj_recover(struct ngj_vol *jv, struct block_device *b, int write, u64 *seq);
int ngj_clear_foreign_dirty(void *osdev, u64 size, unsigned int devsec);

#endif
