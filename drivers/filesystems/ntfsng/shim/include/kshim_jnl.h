/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kshim_jnl.h - metadata block journal of the shim.  While active, every device write that is
 * not marked direct (file data) is held in an in-memory overlay; reads see the overlay.  A
 * commit writes the overlay to the journal area (inside $LogFile), flushes (which also makes the
 * file data written since the last commit durable), writes a checksummed header that commits the
 * transaction, flushes, writes it in place, flushes and marks the header applied.  A crash leaves
 * either the last applied state or a committed transaction that the next mount writes in place
 * again.
 */
#ifndef KSHIM_JNL_H
#define KSHIM_JNL_H

#define KJ_PAGE 4096
#define KJ_MAGIC "NTFSNGJ1"
#define KJ_VERSION 2
#define KJ_VERSION_AREA 3		/* a COMMITTED header of a retained transaction (slot areas, see below): an older driver must not replay it */
#define KJ_HDR_PAGE 3			/* $LogFile page of the header: never a power of two */
#define KJ_FIRST_SLOT_PAGE 5

enum { KJ_ST_ACTIVE = 1, KJ_ST_COMMITTED = 2, KJ_ST_UNJOURNALED = 3, KJ_ST_ERRORS = 4 };
/* Header flags: the core reported errors in this session (kept by every later header, COMMITTED included). */
#define KJ_FL_ERRORS 1
#define KJ_FL_KEEP 2	/* the volume was marked dirty on request (fsutil dirty set, a failed check): the flag is real, not the mounted marker */
#define KJ_FL_AREA1 4	/* version KJ_VERSION_AREA: the slots are in the second area, not the first */
/*
 * Retained transactions (see the top of kshim_jnl.c).  A small transaction (at most KJ_RET_MAX pages) is committed into one of
 * two slot areas of KJ_AREA_SLOTS slots (alternating) and its pages are not written in place until a later checkpoint;
 * each such commit carries every page not yet in place, so the newest transaction alone is what replay has to install.
 * The areas start at slot KJ_AREA_BASE and KJ_AREA_BASE + KJ_AREA_SLOTS: (in $LogFile pages) 138.. and 202.., neither crosses
 * a power-of-two page for a transaction of KJ_RET_MAX pages, so one request writes a whole transaction.  An ordinary (not
 * retained) transaction starts at slot 0.
 */
#define KJ_AREA_BASE 128
#define KJ_AREA_SLOTS 64
#define KJ_RET_MAX 32

struct kj_hdr {
	char magic[8];
	u32 version;
	u32 state;
	u64 seq;
	u32 npages;		/* data pages of the committed transaction */
	u32 ndesc;		/* descriptor pages before them */
	u32 payload_crc;	/* CRC-32 over the descriptor and data pages */
	u32 serial_lo, serial_hi;
	u32 page_size;
	u64 hwm;		/* highest slot count ever used */
	/*
	 * Update sequence number of $MFT record 3 ($Volume) on disk before and after the in-place pass
	 * of this transaction.  Equal in a session's ACTIVE header; the ACTIVE header that recovery
	 * writes before it clears the dirty flag names the number before and after that rewrite.
	 * Every driver writes that record when it marks the volume dirty, and every write changes the
	 * number: a different number means another driver changed the volume since this header was
	 * written, and the header must not be acted on.
	 */
	u16 vol_usn_old, vol_usn_new;
	u32 flags;
	u32 hdr_crc;		/* CRC-32 of this structure up to here */
};

struct kj_desc {
	u64 blk;		/* device offset / KJ_PAGE */
	u32 crc;		/* CRC-32 of the data page */
	u8 mask;		/* valid 512-byte sectors */
	u8 pad[3];
};
#define KJ_DESC_PER_PAGE (KJ_PAGE / sizeof(struct kj_desc))

/* One run of the journal file ($LogFile) in KJ_PAGE units. */
struct kj_ext { u64 page; u64 npages; u64 dev; };

struct kshim_jnl;

/* Record in the system event log that the volume stopped accepting writes (err: a negative errno). */
void kshim_log_volume_failed(struct block_device *b, int err);

u32 kj_crc32(u32 crc, const void *p, size_t n);
u64 kj_slot_page(u64 slot);
int kj_rec_usn(const u8 *rec, size_t avail, u16 *usn);
int kj_page_dev(const struct kj_ext *ext, int next, u64 page, u64 *dev);

int kshim_jnl_activate(struct block_device *b, const struct kj_ext *ext, int next, u64 lf_pages,
		u64 serial, u64 seq, u64 vol_rec_off);
int kshim_jnl_retire(struct block_device *b);
void kshim_jnl_set_keep(struct block_device *b, int keep);
int kshim_jnl_retire_pending(struct block_device *b);
int kshim_jnl_failed(struct block_device *b);	/* a write could not be protected: all writes refused */
/* The disk may hold metadata no commit covers: no journal, or it wrote in place or stopped. */
int kshim_jnl_in_place(struct block_device *b);
/* While on (a resize), a commit or overlay write that would go in place fails instead. */
void kshim_jnl_strict(struct block_device *b, int on);
/* During a resize, the journal refused a write fallback: the write errors that follow are refusals. */
int kshim_jnl_refusing(struct block_device *b);
int kshim_jnl_errors_pending(struct block_device *b);	/* errors known, not yet on the medium */
void kshim_jnl_deactivate(struct block_device *b);
/*
 * 1 committed (device flushed), 0 nothing to do, <0 error.  @aux (the caller's free-cluster count): when the call returns
 * without an error, every change made before it is committed, and kshim_jnl_aux_done returns @aux.
 */
int kshim_jnl_commit(struct block_device *b, u64 aux);
/*
 * The commit in three steps, the middle one without the volume lock (see the comment at the top of kshim_jnl.c):
 * kshim_jnl_seal (lock) 1 -> kshim_jnl_io (no lock, same thread) -> kshim_jnl_reap (lock).
 * seal: 0 nothing pending, -EBUSY another commit's I/O is running (kshim_jnl_wait, then again), -ENOSYS use kshim_jnl_commit.
 * @retain_ok: the caller waits for the transaction to be durable (write-through, a flush): a small one may be committed without
 * putting its pages in place (retained, see kshim_jnl.c); 0 (the flusher): the retained pages are put in place, then it commits.
 */
int kshim_jnl_seal(struct block_device *b, u64 aux, int retain_ok);
int kshim_jnl_io(struct block_device *b);
void kshim_jnl_pre_fail(struct block_device *b);	/* the writes in flight with the slot writes failed: the sealed transaction writes nothing more and fails */
int kshim_jnl_slots_start(struct block_device *b);	/* lock held, right after a seal that returned 1: starts the slot writes of a retained transaction (nobufw2) */
void kshim_jnl_reap(struct block_device *b);
int kshim_jnl_busy(struct block_device *b);
void kshim_jnl_wait(struct block_device *b);
void kshim_jnl_settle(struct block_device *b);	/* wait for the I/O in flight and release a finished sealed transaction */
void kshim_jnl_quiesce(struct block_device *b);	/* wait for the I/O in flight */
unsigned long kshim_jnl_unsettled(struct block_device *b);	/* live + sealed pages */
unsigned long kshim_jnl_retained(struct block_device *b);	/* pages committed (durable in the journal) and not in place yet */
u64 kshim_jnl_aux_done(struct block_device *b);
void kshim_jnl_set_aux(struct block_device *b, u64 aux);
void kshim_jnl_mark_errors(struct block_device *b);
unsigned long kshim_jnl_capacity(struct block_device *b);
int kshim_jnl_ro_page(struct block_device *b, u64 blk, u8 mask, const u8 *data);
unsigned long kshim_jnl_pending(struct block_device *b);
void kshim_jnl_report(struct block_device *b);
/* Test only: nonzero stops the machine half way through writing that commit in place. */
#if DBG
extern unsigned long kshim_jnl_fault;
/* Test only: where JournalFault stops the commit: 0 half way through the in-place pass, 1 before the COMMITTED header,
 * 2 right after it, 3 after the in-place pass; and a pause (ms) of the unlocked journal I/O between its phases. */
extern unsigned long kshim_jnl_fault_stage, kshim_jnl_stall_ms;
#else
#define kshim_jnl_fault 0UL   /* fault injection compiled out of release */
#define kshim_jnl_fault_stage 0UL
#endif
/* Test only, for this volume: the in-place pass of its next commit fails half way, as a failing device
 * would (KJ_FAULT_APPLY), or no overlay page can be allocated until the resize ends (KJ_FAULT_CAPTURE). */
enum { KJ_FAULT_APPLY = 1, KJ_FAULT_CAPTURE = 2 };
void kshim_jnl_arm_fault(struct block_device *b, int kind);
/* The overlay failed and metadata goes in place until a commit's in-place pass succeeds. */
int kshim_jnl_degraded(struct block_device *b);

/* Used by kshim_dev_rw. */
int kshim_jnl_capture(struct block_device *b, u64 off, const u8 *buf, size_t len);
int kshim_jnl_degrade(struct block_device *b);
void kshim_jnl_patch(struct block_device *b, int to_overlay, u64 off, u8 *buf, size_t len);
int kshim_jnl_holds(struct block_device *b, u64 off, u64 len);

/* Positive increments of a watched counter (the core's free-cluster count) are counted. */
int kshim_watch_add(atomic64_t *v);
void kshim_watch_del(atomic64_t *v);
unsigned long kshim_watch_count(atomic64_t *v);
void kshim_watch_hit(atomic64_t *v);

#endif
