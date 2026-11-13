// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kshim_jnl.c - the shim's metadata block journal (see kshim_jnl.h).  Callers hold the NT glue's
 * volume lock (CoreLock, always taken exclusive), so the overlay needs no lock of its own.
 *
 * Unlocked commit (kshim_jnl_seal / kshim_jnl_io / kshim_jnl_reap).  A commit used to write its journal
 * pages, header, in-place copy and the flushes (82% of its time) with the volume lock held.  Now:
 *   1. SEAL, under the volume lock: the overlay moves to the "sealed" hash and a new, empty one takes the
 *      writes that follow.  Nothing is written to the device.
 *   2. IO, without the volume lock, by the thread that sealed: the unchanged commit sequence runs on the
 *      sealed pages.  Nobody else touches the sealed entries meanwhile (see below), nobody else writes the
 *      journal area or the header page (every other writer of them first waits for the I/O to end).
 *   3. REAP, under the volume lock, at once or by whoever needs the sealed overlay gone: a finished
 *      transaction is freed (its pages are in place), a failed one is merged back into the live overlay.
 * Rules, all under the volume lock unless said otherwise:
 *   - One sealed transaction at a time.  Seal, the old synchronous commit, retire, degrade, strict mode and
 *     deactivate first wait for the I/O of the sealed one to end (kj_settle).  The I/O needs no lock, so
 *     waiting for it with the volume lock held cannot deadlock.
 *   - Reads (kshim_jnl_patch to the caller's buffer) apply the sealed entries, then the live ones: the live
 *     overlay is newer.  A sealed entry stays until reaped, i.e. also after its pages went in place, so a
 *     device read made before the in-place pass is still patched to the committed value.
 *   - A write of a sector the sealed overlay holds goes to the live overlay (a partial sector starts from
 *     the sealed copy, never from the device, which may not have it yet).  Sealed entries are never
 *     changed while their I/O runs: a direct (file data) write over a sealed sector waits for the I/O first.
 *   - The next transaction cannot be sealed before the previous one is in place, so on the medium the
 *     in-place passes keep their order and a journal slot is never overwritten while it is still needed.
 *   - The caller's "aux" value (the free-cluster count) at the seal becomes aux_done when the transaction
 *     is complete: an allocation that follows a free needs aux_done to have caught up with it.
 *
 * Retained transactions (an unlocked commit of few pages).  The in-place pass, its flush and the ACTIVE header (three of the
 * seven serial device operations of a commit, and the ones a write-through writer waits for without gaining anything: the
 * transaction is durable, and replayable, once its COMMITTED header is) are left to a later checkpoint.  Rules:
 *   - A commit whose pages (the new ones and the retained ones) are at most KJ_RET_MAX is "retained": its transaction is the
 *     union, each page once with its newest bytes, written to the slot area that the retained transaction R is not in
 *     (two areas of KJ_AREA_SLOTS slots, alternating; the header says which, version KJ_VERSION_AREA), then flush, COMMITTED
 *     header, flush: durable.  Its pages are not written in place.  When it ends R is replaced by it: the next commit's slots go
 *     to the other area, so R's slots and header stay valid until the new header is on the medium, and replay of the newest
 *     header installs everything that is not in place.  A failure before the header changes nothing that matters (R and its
 *     header are intact); one at or after it sets j->failed (the header may name the new area; a retry into either area could
 *     overwrite what replay needs) when R exists.
 *   - Retained pages are memory the journal keeps: reads see them (retained, then sealed, then live pages), and the sealed set
 *     of the next commit starts as a copy of them.  A commit that would carry more than KJ_RET_MAX pages (-ENOSYS from the
 *     seal) goes through the synchronous commit, which first puts the retained pages in place.
 *   - kj_checkpoint puts the retained pages in place (sorted, one pass, a flush, the ACTIVE header).  It runs from kj_settle,
 *     i.e. at the quiet flusher pass (ngc_sync), retire, deactivate, degrade, a resize, an allocation that follows a free
 *     (ngc_before_alloc: aux_done follows the checkpoint, not the commit, because replay of retained pages must not land on a
 *     cluster that has been given to file data since), a direct write over retained sectors (kshim_jnl_patch), and a
 *     synchronous commit.  So everything that expects a clean, in-place volume (dismount, the lock holder's direct writes, a
 *     check, shutdown) gets it through ngc_sync.
 *   - The header page belongs to the retained transaction (COMMITTED) until the checkpoint: nobody writes another header over
 *     it before (kshim_jnl_mark_errors waits; the headers of later commits and of the checkpoint carry the errors mark).
 */
#include <kshim.h>
#include <kshim_jnl.h>

#define KJ_BUCKETS 1024
#define KJ_SEGS_PRE 8	/* requests of the slot writes started under the lock (kshim_jnl_slots_start) */
#define KJ_SECT 512
#define KJ_RESV_MAX 256	/* frees (runs) remembered until a commit covers them */

struct kj_ent {
	struct kj_ent *next;
	u64 blk;
	u8 mask;
	u8 *data;
};

struct kshim_jnl {
	struct kj_ent *hash[KJ_BUCKETS];
	unsigned long npages;
	struct kj_ext *ext;
	int next;
	u64 lf_pages;
	u64 capacity;			/* descriptor + data slots */
	u64 seq, hwm;
	u64 serial;
	int degraded;			/* the overlay failed: writes go in place under an UNJOURNALED header */
	int errors;			/* the core reported errors: the header keeps saying so */
	int keep;			/* the dirty flag is a real request (KJ_FL_KEEP): every header says so */
	int readonly;			/* only a replay overlay for a read-only mount: no journal writes */
	int retired;			/* the header page is 0xff: the volume was clean when it was written */
	int failed;			/* a metadata write could not be protected: no write may reach the device */
	int errors_durable;		/* a header with the errors mark has reached the medium */
	int errors_writing;
	int strict;			/* a resize runs: nothing goes in place; a fallback fails instead */
	int refused;			/* strict refused a fallback: write errors follow that are not the device's */
	int apply_fault, capture_fault;	/* test only (kshim_jnl_arm_fault) */
	u64 vol_rec_off;		/* device offset of $MFT record 3 ($Volume) */
	u16 vol_usn;			/* its update sequence number on disk (after the last in-place pass) */
	u8 *hdrpage;
	unsigned long commits, committed_pages, max_tx, fallbacks, dropped, replay_pages;
	unsigned long overflows;	/* transactions larger than the journal, written in place under UNJOURNALED */
	/*
	 * The sealed overlay: the transaction whose journal I/O runs without the volume lock.  Sealing (under
	 * the lock) moves the overlay here and starts an empty one; reads look at the live overlay, then at this
	 * one, then at the device.  See "Unlocked commit" below for the rules.
	 */
	struct kj_ent *shash[KJ_BUCKETS];
	unsigned long snpages;
	int sstate;			/* KJ_S_NONE, KJ_S_RUNNING (I/O in flight), KJ_S_DONE (finished, not yet released) */
	int serr;			/* result of the I/O of the sealed transaction */
	struct kj_ent **sv, **stmp;	/* its entries, sorted by the I/O; allocated at the seal */
	unsigned long ssort_n;
	u16 susn_new;
	u64 saux;			/* the caller's value at the seal (see aux_done) */
	u64 aux_done;			/* the caller's value at the last commit that is complete (all changes before it are committed) */
	/* Clusters freed by transactions not covered by aux_done yet (see kshim_resv_note): the allocator leaves them alone. */
	uintptr_t resv_lock;
	struct { u64 lcn, len, tag; } resv[KJ_RESV_MAX];
	int nresv;
	u64 resv_clusters;		/* sum of the lengths of the entries */
	u64 resv_over;			/* a free did not fit the list: the newest tag among those not recorded, 0 when none */
	struct ngos_ev idle;		/* signalled while no I/O is in flight */
	unsigned long unlocked_commits, io_us;
	/*
	 * The retained transaction R: the newest commit that is durable in a journal slot area but whose pages are not in place
	 * (kj_checkpoint puts them there later).  It carries every page changed since the last checkpoint, so replaying the
	 * newest header alone is enough.  Readers see R's pages (oldest), then the sealed ones, then the live ones.
	 */
	struct block_device *bdev;
	struct kj_ent *rhash[KJ_BUCKETS];
	unsigned long rnpages;
	int rarea;			/* the slot area R is in (0 or 1) */
	u16 rusn_new;			/* $Volume's number once R is in place */
	u64 raux;			/* the caller's value at R's seal: aux_done when R is in place (frees are covered only then) */
	int ret_ok;			/* the journal area holds two slot areas and retention is not switched off */
	int sretain, sarea;		/* the sealed transaction is committed as a retained one, into this slot area */
	int sckpt;			/* the I/O of the sealed (not retained) transaction first puts the retained pages in place */
	int r_applied;			/* that has been done: reap frees the retained pages */
	int cur_area;			/* the slot area of the COMMITTED header being written, -1: not a retained transaction */
	int hdr_tried;			/* the sealed transaction's COMMITTED header may be on the medium */
	unsigned long retained_commits, checkpoints;
	/* The slot writes of the sealed (retained) transaction were started under the lock, in flight with the file data (kshim_jnl_slots_start) */
	int pre_started, pre_fua, pre_err;
	u32 pre_crc;
	u8 *pre_buf;
};

enum { KJ_S_NONE = 0, KJ_S_RUNNING = 1, KJ_S_DONE = 2 };

/* CRC-32 (the usual, reflected 0xedb88320) eight bytes per step: every page of a commit is checksummed twice (descriptor, payload). */
static u32 kj_crc_t[8][256];
static int kj_crc_ready;
int kshim_jnl_noret;		/* registry NoRetainedCommit=1: every commit puts its pages in place before it returns (comparison, fallback) */
#if DBG
unsigned long kshim_jnl_fault;
unsigned long kshim_jnl_fault_stage;	/* where in the commit the fault stops it: 0 half way through the in-place pass, 1 before the COMMITTED header, 2 after it, 3 after the in-place pass */
unsigned long kshim_jnl_stall_ms;	/* the journal I/O of a sealed transaction sleeps this long between its phases */
#endif

static void kj_crc_init(void)
{
	for (u32 i = 0; i < 256; i++) {
		u32 c = i;
		for (int k = 0; k < 8; k++)
			c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
		kj_crc_t[0][i] = c;
	}
	for (u32 i = 0; i < 256; i++)
		for (int k = 1; k < 8; k++)
			kj_crc_t[k][i] = (kj_crc_t[k - 1][i] >> 8) ^ kj_crc_t[0][kj_crc_t[k - 1][i] & 0xff];
	__atomic_store_n(&kj_crc_ready, 1, __ATOMIC_RELEASE);
}

u32 kj_crc32(u32 crc, const void *p, size_t n)
{
	const u8 *s = p;
	if (!__atomic_load_n(&kj_crc_ready, __ATOMIC_ACQUIRE))
		kj_crc_init();
	crc = ~crc;
	while (n >= 8) {
		u32 a, b;
		memcpy(&a, s, 4);
		memcpy(&b, s + 4, 4);
		a ^= crc;
		crc = kj_crc_t[7][a & 0xff] ^ kj_crc_t[6][(a >> 8) & 0xff] ^ kj_crc_t[5][(a >> 16) & 0xff] ^ kj_crc_t[4][a >> 24] ^
		      kj_crc_t[3][b & 0xff] ^ kj_crc_t[2][(b >> 8) & 0xff] ^ kj_crc_t[1][(b >> 16) & 0xff] ^ kj_crc_t[0][b >> 24];
		s += 8;
		n -= 8;
	}
	while (n--)
		crc = kj_crc_t[0][(crc ^ *s++) & 0xff] ^ (crc >> 8);
	return ~crc;
}

/* Journal slots skip every $LogFile page at a power-of-two offset: restart-page scans read those. */
u64 kj_slot_page(u64 slot)
{
	u64 p = KJ_FIRST_SLOT_PAGE + slot;
	for (u64 q = 8; q <= p; q <<= 1)
		p++;
	return p;
}

/*
 * The volume stopped accepting writes (a device write of the journal failed): leave a record in the system event log,
 * once per volume. Not only a debugger message: a Release system has none. err is a negative errno.
 */
void kshim_log_volume_failed(struct block_device *b, int err)
{
	ngos_volume_failed(b->osdev, err);
}

/* The journal's own device I/O: nothing reaches a medium that replaced the volume's. */
static int kj_dev_read(struct block_device *b, u64 off, void *buf, unsigned int len)
{
	return b->kshim_gone || ngos_dev_read(b->osdev, off, buf, len);
}
static int kj_dev_write(struct block_device *b, u64 off, void *buf, unsigned int len)
{
	return b->kshim_gone || b->kshim_frozen || ngos_dev_write(b->osdev, off, buf, len);
}
static int kj_dev_write_fua(struct block_device *b, u64 off, void *buf, unsigned int len)
{
	return b->kshim_gone || b->kshim_frozen || ngos_dev_write_fua(b->osdev, off, buf, len);
}
static int kj_dev_flush(struct block_device *b)
{
	return b->kshim_gone || ngos_dev_flush(b->osdev);
}

int kj_page_dev(const struct kj_ext *ext, int next, u64 page, u64 *dev)
{
	for (int i = 0; i < next; i++)
		if (page >= ext[i].page && page < ext[i].page + ext[i].npages) {
			*dev = ext[i].dev + (page - ext[i].page) * KJ_PAGE;
			return 0;
		}
	return -EIO;
}

/* The update sequence number of an MFT record from its first bytes (the array lies in the first sector). */
int kj_rec_usn(const u8 *rec, size_t avail, u16 *usn)
{
	u16 uo;
	if (avail < 8 || memcmp(rec, "FILE", 4))
		return -EIO;
	uo = rec[4] | rec[5] << 8;
	if ((uo & 1) || (size_t)uo + 2 > avail || uo + 2 > 512)
		return -EIO;
	*usn = rec[uo] | rec[uo + 1] << 8;
	return 0;
}

/* $Volume's number as it is on the device (at activation, before the overlay holds anything). */
/* @buf: KJ_PAGE bytes of scratch (the header page buffer, between header writes): no allocation. */
static int kj_read_vol_usn(struct block_device *b, u64 off, u16 *usn, u8 *buf)
{
	unsigned int bs = b->logical_block_size >= KJ_SECT ? b->logical_block_size : KJ_SECT;
	u64 base = off & ~(u64)(bs - 1);
	if (bs > KJ_PAGE)
		return -EIO;
	return kj_dev_read(b, base, buf, bs) ? -EIO : kj_rec_usn(buf + (off - base), bs - (size_t)(off - base), usn);
}

static struct kj_ent *kj_find(struct kshim_jnl *j, u64 blk);
static void kj_wait_io(struct kshim_jnl *j);
static void kj_settle(struct kshim_jnl *j);
static int kj_checkpoint(struct kshim_jnl *j);

/* $Volume's number once the overlay is in place: from the overlay when it holds the record's first sector. */
static u16 kj_vol_usn_ent(struct kshim_jnl *j, struct kj_ent *e)
{
	size_t in = (size_t)(j->vol_rec_off % KJ_PAGE);
	u16 usn;
	if (e && (e->mask & (1u << (in / KJ_SECT))) && !kj_rec_usn(e->data + in, KJ_SECT - in % KJ_SECT, &usn))
		return usn;
	return j->vol_usn;
}

static u16 kj_vol_usn_after(struct kshim_jnl *j)
{
	return kj_vol_usn_ent(j, kj_find(j, j->vol_rec_off / KJ_PAGE));
}

/*
 * After an in-place pass that did not come from the overlay alone (degraded writes went straight to the
 * device): the number as it is on the medium now.
 */
/* Nonzero: the number on the medium is unknown, so no header may be written that records one. */
static int kj_resync_vol_usn(struct block_device *b, struct kshim_jnl *j)
{
	return kj_read_vol_usn(b, j->vol_rec_off, &j->vol_usn, j->hdrpage);
}

int kshim_jnl_failed(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	if (!j)
		return 0;
	/*
	 * A file-data write that completed later failed (ngos_dev_drain): its initialized size is in the overlay and must never
	 * reach the medium.  Same policy as every other failed device write of the journal: j->failed (no further write until the
	 * next mount) and one event log entry (kshim_log_volume_failed).
	 */
	if (!j->failed && ngos_dev_defer_failed(b->osdev)) {
		kshim_log_volume_failed(b, -EIO);
		j->failed = 1;
	}
	return j->failed;
}

int kshim_jnl_in_place(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	return !j || j->degraded || j->failed;
}

void kshim_jnl_arm_fault(struct block_device *b, int kind)
{
	if (!b->jnl)
		return;
	if (kind == KJ_FAULT_APPLY)
		b->jnl->apply_fault = 1;
	else if (kind == KJ_FAULT_CAPTURE)
		b->jnl->capture_fault = 1;
}

int kshim_jnl_refusing(struct block_device *b)
{
	return b->jnl && b->jnl->strict && b->jnl->refused;
}

int kshim_jnl_degraded(struct block_device *b)
{
	return b->jnl && b->jnl->degraded;
}

void kshim_jnl_strict(struct block_device *b, int on)
{
	if (b->jnl) {
		if (on)
			kj_settle(b->jnl);
		b->jnl->strict = on;
		b->jnl->refused = 0;
		if (!on)
			b->jnl->capture_fault = 0;
	}
}

/* A clean volume whose header is still on the medium: the flusher retires it (an earlier retire failed). */
int kshim_jnl_retire_pending(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	return j && !j->readonly && !j->retired && !j->npages && !j->snpages && !j->rnpages && !j->degraded && !j->errors && !j->failed;
}

static int kj_in_area(struct kshim_jnl *j, u64 off, size_t len)
{
	for (int i = 0; i < j->next; i++) {
		u64 s = j->ext[i].dev, e = s + j->ext[i].npages * KJ_PAGE;
		if (off < e && off + len > s)
			return 1;
	}
	return 0;
}

static struct kj_ent *kj_find(struct kshim_jnl *j, u64 blk)
{
	for (struct kj_ent *e = j->hash[blk % KJ_BUCKETS]; e; e = e->next)
		if (e->blk == blk)
			return e;
	return NULL;
}

static struct kj_ent *kj_find_in(struct kj_ent **hash, u64 blk)
{
	for (struct kj_ent *e = hash[blk % KJ_BUCKETS]; e; e = e->next)
		if (e->blk == blk)
			return e;
	return NULL;
}

/* The newest copy below the live overlay: the sealed page, else the retained one. */
static struct kj_ent *kj_find_s(struct kshim_jnl *j, u64 blk)
{
	struct kj_ent *e = j->snpages ? kj_find_in(j->shash, blk) : NULL;
	return e ? e : j->rnpages ? kj_find_in(j->rhash, blk) : NULL;
}

static void kj_wait_io(struct kshim_jnl *j)
{
	while (__atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING)
		ngos_ev_wait(&j->idle);
}

static void kj_free_h(struct kj_ent **hash)
{
	for (int i = 0; i < KJ_BUCKETS; i++) {
		struct kj_ent *e = hash[i], *n;
		for (; e; e = n) {
			n = e->next;
			kfree(e->data);
			kfree(e);
		}
		hash[i] = NULL;
	}
}

static void kj_free_sealed(struct kshim_jnl *j)
{
	kj_free_h(j->shash);
	j->snpages = 0;
}

static void kj_free_retained(struct kshim_jnl *j)
{
	kj_free_h(j->rhash);
	j->rnpages = 0;
}

/* A copy of every page of @src into @dst (empty); -ENOMEM leaves @dst empty. */
static int kj_copy_h(struct kj_ent **dst, struct kj_ent **src, unsigned long *count)
{
	unsigned long n = 0;
	for (int i = 0; i < KJ_BUCKETS; i++)
		for (struct kj_ent *e = src[i]; e; e = e->next) {
			struct kj_ent *c = kzalloc(sizeof(*c), GFP_NOFS);
			if (c)
				c->data = kmalloc(KJ_PAGE, GFP_NOFS);
			if (!c || !c->data) {
				kfree(c);
				kj_free_h(dst);
				*count = 0;
				return -ENOMEM;
			}
			memcpy(c->data, e->data, KJ_PAGE);
			c->blk = e->blk;
			c->mask = e->mask;
			c->next = dst[e->blk % KJ_BUCKETS];
			dst[e->blk % KJ_BUCKETS] = c;
			n++;
		}
	*count = n;
	return 0;
}

/* A transaction that failed before it was in place: its sectors go back to the live overlay (the live copy is newer). */
static void kj_merge_back(struct kshim_jnl *j)
{
	for (int i = 0; i < KJ_BUCKETS; i++) {
		struct kj_ent *e = j->shash[i], *n;
		for (; e; e = n) {
			struct kj_ent *c = kj_find(j, e->blk);
			n = e->next;
			if (!c) {
				e->next = j->hash[e->blk % KJ_BUCKETS];
				j->hash[e->blk % KJ_BUCKETS] = e;
				j->npages++;
				continue;
			}
			for (int s = 0; s < 8; s++)
				if ((e->mask & (1u << s)) && !(c->mask & (1u << s))) {
					memcpy(c->data + s * KJ_SECT, e->data + s * KJ_SECT, KJ_SECT);
					c->mask |= 1u << s;
				}
			kfree(e->data);
			kfree(e);
		}
		j->shash[i] = NULL;
	}
	j->snpages = 0;
}

/* Under the volume lock, the I/O is not running: a finished sealed transaction is released. */
static void kj_reap(struct kshim_jnl *j)
{
	if (__atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) != KJ_S_DONE)
		return;
	if (j->r_applied) {
		/* The I/O put the retained pages in place before it committed the sealed ones (whatever became of those). */
		kj_free_retained(j);
		j->aux_done = j->raux;
		j->checkpoints++;
		j->r_applied = 0;
	}
	if (!j->serr) {
		j->commits++;
		j->committed_pages += j->snpages;
		if (j->snpages > j->max_tx)
			j->max_tx = j->snpages;
		if (j->sretain) {
			/*
			 * Durable in a slot area, not in place: the sealed pages (which carry the older retained ones too) become the
			 * retained transaction.  The frees it covers count as committed only when it is in place (aux_done, kj_checkpoint):
			 * a cluster freed here must not receive file data while replay could still write old metadata over it.
			 */
			kj_free_retained(j);
			memcpy(j->rhash, j->shash, sizeof(j->rhash));
			memset(j->shash, 0, sizeof(j->shash));
			j->rnpages = j->snpages;
			j->snpages = 0;
			j->rarea = j->sarea;
			j->rusn_new = j->susn_new;
			j->raux = j->saux;
			j->retained_commits++;
		} else {
			j->aux_done = j->saux;
			kj_free_sealed(j);
		}
	} else {
		kj_merge_back(j);
	}
	__atomic_store_n(&j->sstate, KJ_S_NONE, __ATOMIC_RELEASE);
}

/* The I/O of the sealed transaction has ended and a finished one is released; the retained pages stay where they are. */
static void kj_wait_reap(struct kshim_jnl *j)
{
	kj_wait_io(j);
	kj_reap(j);
}

/* Everything committed is in place when this returns (the journal I/O ended, retained pages written) unless a write failed. */
static void kj_settle(struct kshim_jnl *j)
{
	kj_wait_reap(j);
	kj_checkpoint(j);
}

/* Any sector of [off, off+len) held by the entries of @hash. */
static int kj_holds_h(struct kj_ent **hash, u64 off, u64 len)
{
	for (u64 s = off / KJ_SECT * KJ_SECT; s < off + len; s += KJ_SECT) {
		struct kj_ent *e;
		for (e = hash[(s / KJ_PAGE) % KJ_BUCKETS]; e && e->blk != s / KJ_PAGE; e = e->next)
			;
		if (!e) {
			s = (s / KJ_PAGE + 1) * KJ_PAGE - KJ_SECT;	/* next page */
			continue;
		}
		if (e->mask & (1u << ((s % KJ_PAGE) / KJ_SECT)))
			return 1;
	}
	return 0;
}

static void kj_drop_all(struct kshim_jnl *j)
{
	for (int i = 0; i < KJ_BUCKETS; i++) {
		struct kj_ent *e = j->hash[i], *n;
		for (; e; e = n) {
			n = e->next;
			kfree(e->data);
			kfree(e);
		}
		j->hash[i] = NULL;
	}
	j->npages = 0;
}

static int kj_hdr_write(struct block_device *b, struct kshim_jnl *j, u32 state, u32 npages, u32 ndesc,
		u32 pcrc, int flush, u16 usn_new)
{
	struct kj_hdr *h = (struct kj_hdr *)j->hdrpage;
	int ret = state == KJ_ST_COMMITTED && j->cur_area >= 0;	/* a retained transaction: slot area cur_area */
	u64 dev;
	if (j->readonly)
		return -EROFS;
	if (j->errors && state == KJ_ST_ACTIVE)
		state = KJ_ST_ERRORS;
	memset(j->hdrpage, 0, KJ_PAGE);
	memcpy(h->magic, KJ_MAGIC, 8);
	h->version = ret ? KJ_VERSION_AREA : KJ_VERSION;
	h->state = state;
	h->seq = j->seq;
	h->npages = npages;
	h->ndesc = ndesc;
	h->payload_crc = pcrc;
	h->serial_lo = (u32)j->serial;
	h->serial_hi = (u32)(j->serial >> 32);
	h->page_size = KJ_PAGE;
	h->hwm = j->hwm;
	h->vol_usn_old = j->vol_usn;
	h->vol_usn_new = usn_new;
	h->flags = (j->errors ? KJ_FL_ERRORS : 0) | (j->keep ? KJ_FL_KEEP : 0) | (ret && j->cur_area ? KJ_FL_AREA1 : 0);
	h->hdr_crc = kj_crc32(0, h, offsetof(struct kj_hdr, hdr_crc));
	/*
	 * A COMMITTED header that has to be durable goes out with FUA when the device honours it: durable when it
	 * completes, no flush after it.  (What the header needs to be durable before it, the slots and the file
	 * data, is the caller's: kj_tx_commit.  Other headers keep their flush.)
	 */
	if (flush && state == KJ_ST_COMMITTED && b->kshim_fua) {
		if (kj_page_dev(j->ext, j->next, KJ_HDR_PAGE, &dev) || kj_dev_write_fua(b, dev, j->hdrpage, KJ_PAGE))
			return -EIO;
		j->retired = 0;
		return 0;
	}
	if (kj_page_dev(j->ext, j->next, KJ_HDR_PAGE, &dev) || kj_dev_write(b, dev, j->hdrpage, KJ_PAGE))
		return -EIO;
	j->retired = 0;
	if (flush && kj_dev_flush(b))
		return -EIO;
	return 0;
}

/*
 * The volume is clean on disk (VOLUME_IS_DIRTY cleared and committed, nothing held): the header page
 * goes back to 0xff, so no later mount acts on a header older than what another driver may write
 * next.  The next commit writes a header again before anything goes in place.
 */
int kshim_jnl_retire(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	u64 dev;
	if (!j || j->readonly)
		return 0;
	kj_settle(j);
	if (j->retired || j->npages || j->snpages || j->rnpages || j->degraded || j->errors || j->keep || j->failed)
		return 0;
	memset(j->hdrpage, 0xff, KJ_PAGE);
	if (kj_page_dev(j->ext, j->next, KJ_HDR_PAGE, &dev) || kj_dev_write(b, dev, j->hdrpage, KJ_PAGE) ||
	    kj_dev_flush(b))
		return -EIO;
	j->retired = 1;
	return 0;
}

int kshim_jnl_activate(struct block_device *b, const struct kj_ext *ext, int next, u64 lf_pages,
		u64 serial, u64 seq, u64 vol_rec_off)
{
	struct kshim_jnl *j;
	int err;
	if (b->jnl)
		return 0;
	if (lf_pages < 64)
		return -ENOSPC;
	j = kzalloc(sizeof(*j), GFP_KERNEL);
	if (!j)
		return -ENOMEM;
	j->ext = kmalloc_array(next, sizeof(*ext), GFP_KERNEL);
	j->hdrpage = kmalloc(KJ_PAGE, GFP_KERNEL);
	if (!j->ext || !j->hdrpage) {
		kfree(j->ext);
		kfree(j->hdrpage);
		kfree(j);
		return -ENOMEM;
	}
	memcpy(j->ext, ext, next * sizeof(*ext));
	ngos_ev_init(&j->idle, 0, 1);
	j->bdev = b;
	j->next = next;
	j->lf_pages = lf_pages;
	j->serial = serial;
	j->seq = seq;
	j->vol_rec_off = vol_rec_off;
	while (kj_slot_page(j->capacity) < lf_pages)
		j->capacity++;
	/* Two slot areas must fit in $LogFile for retained transactions. */
	j->ret_ok = !kshim_jnl_noret && j->capacity >= KJ_AREA_BASE + 2 * KJ_AREA_SLOTS;
	/*
	 * The volume is clean at activation (recovery cleared the dirty flag, or the mount refused a dirty
	 * one), so no header is left on the medium: the first commit writes one.
	 */
	err = kj_read_vol_usn(b, vol_rec_off, &j->vol_usn, j->hdrpage);
	if (!err) {
		b->jnl = j;
		if (kshim_jnl_retire(b))
			printk(KERN_ERR "journal: could not retire the header at mount; the flusher tries again\n");
		b->jnl = NULL;
	}
	if (err) {
		kfree(j->ext);
		kfree(j->hdrpage);
		kfree(j);
		return err;
	}
	b->jnl = j;
	printk(KERN_WARNING "journal: active, %llu slots in $LogFile (%llu pages), seq %llu\n",
	       (unsigned long long)j->capacity, (unsigned long long)lf_pages, (unsigned long long)seq);
	return 0;
}

void kshim_jnl_deactivate(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	if (!j)
		return;
	kj_settle(j);
	kj_free_sealed(j);
	kj_free_retained(j);
	kj_drop_all(j);
	b->jnl = NULL;
	kfree(j->ext);
	kfree(j->hdrpage);
	kfree(j);
}

/* Pages of the live overlay: what the next commit would write. */
unsigned long kshim_jnl_pending(struct block_device *b)
{
	return b->jnl ? b->jnl->npages : 0;
}

/* Live and sealed pages: changes that are not in place yet. */
unsigned long kshim_jnl_unsettled(struct block_device *b)
{
	return b->jnl ? b->jnl->npages + b->jnl->snpages : 0;
}

/* Pages that are durable in the journal and not in place yet (nothing to commit for them, a checkpoint is due). */
unsigned long kshim_jnl_retained(struct block_device *b)
{
	return b->jnl ? b->jnl->rnpages : 0;
}

/* Waits until no journal I/O is in flight, releases a finished sealed transaction and puts retained pages in place. */
void kshim_jnl_settle(struct block_device *b)
{
	if (b->jnl)
		kj_settle(b->jnl);
}

/* Waits for the journal I/O in flight to end, without releasing anything (the medium goes away, the writes stop). */
void kshim_jnl_quiesce(struct block_device *b)
{
	if (b->jnl)
		kj_wait_io(b->jnl);
}

/* The caller's value at the last complete commit (see kshim_jnl_commit's @aux). */
u64 kshim_jnl_aux_done(struct block_device *b)
{
	return b->jnl ? b->jnl->aux_done : 0;
}

void kshim_jnl_set_aux(struct block_device *b, u64 aux)
{
	if (b->jnl)
		b->jnl->aux_done = aux;
}

/* Holds a metadata write in the overlay; -ENOMEM means the caller writes in place. */
int kshim_jnl_capture(struct block_device *b, u64 off, const u8 *buf, size_t len)
{
	struct kshim_jnl *j = b->jnl;
#if DBG
	if (j->capture_fault && j->strict) {
		if (j->capture_fault++ == 1)
			printk(KERN_ERR "journal: no memory for overlay pages until the resize ends (injected)\n");
		return -ENOMEM;
	}
#endif
	if (j->degraded)
		return -ENOMEM;
	if (kj_in_area(j, off, len)) {
		if (j->dropped++ < 4)
			printk(KERN_ERR "journal: dropped a write into the journal area at %llu len %zu\n",
			       (unsigned long long)off, len);
		return 0;
	}
	while (len) {
		u64 blk = off / KJ_PAGE;
		size_t in = off % KJ_PAGE, n = min_t(size_t, len, KJ_PAGE - in);
		struct kj_ent *e = kj_find(j, blk);
		if (!e) {
			e = kzalloc(sizeof(*e), GFP_NOFS);
			if (e)
				e->data = kzalloc(KJ_PAGE, GFP_NOFS);
			if (!e || !e->data) {
				kfree(e);
				return -ENOMEM;
			}
			e->blk = blk;
			e->next = j->hash[blk % KJ_BUCKETS];
			j->hash[blk % KJ_BUCKETS] = e;
			j->npages++;
		}
		/*
		 * A partial sector not held yet starts from the sealed copy (the device may not have it yet),
		 * else from the device copy; bits change only after that.
		 */
		for (size_t s = in / KJ_SECT * KJ_SECT; s < in + n; s += KJ_SECT) {
			struct kj_ent *se;
			if ((e->mask & (1u << (s / KJ_SECT))) || (s >= in && s + KJ_SECT <= in + n))
				continue;
			se = kj_find_s(j, blk);
			if (se && (se->mask & (1u << (s / KJ_SECT))))
				memcpy(e->data + s, se->data + s, KJ_SECT);
			else if (kj_dev_read(b, blk * KJ_PAGE + s, e->data + s, KJ_SECT))
				return -EIO;
		}
		memcpy(e->data + in, buf, n);
		for (size_t s = in / KJ_SECT * KJ_SECT; s < in + n; s += KJ_SECT)
			e->mask |= 1u << (s / KJ_SECT);
		off += n;
		buf += n;
		len -= n;
	}
	return 0;
}

/* True when the overlay holds any sector of [off, off+len): a write there must go through kshim_dev_rw. */
int kshim_jnl_holds(struct block_device *b, u64 off, u64 len)
{
	struct kshim_jnl *j = b->jnl;
	if (!j || (!j->npages && !j->snpages && !j->rnpages) || !len)
		return 0;
	return (j->npages && kj_holds_h(j->hash, off, len)) || (j->snpages && kj_holds_h(j->shash, off, len)) ||
	       (j->rnpages && kj_holds_h(j->rhash, off, len));
}

/* to_overlay 0: copy held sectors over a buffer read from the device; 1: update held sectors from a direct write. */
void kshim_jnl_patch(struct block_device *b, int to_overlay, u64 off, u8 *buf, size_t len)
{
	struct kshim_jnl *j = b->jnl;
	if (!j || (!j->npages && !j->snpages && !j->rnpages))
		return;
	/*
	 * A direct write over sectors that are durable in the journal but not in place: they go in place first, so that a replay
	 * of the journal can never put older bytes over this write.  (File data and metadata share no sectors unless a cluster
	 * changed owner, which ngc_before_alloc settles first; this is the guard for the rest.)
	 */
	if (to_overlay && j->rnpages && kj_holds_h(j->rhash, off, len))
		kj_settle(j);
	/* A sealed entry is read by the journal I/O until it ends: a write over one of its sectors waits for that. */
	if (to_overlay && j->snpages && __atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING &&
	    kj_holds_h(j->shash, off, len))
		kj_wait_io(j);
	while (len) {
		u64 blk = off / KJ_PAGE;
		size_t in = off % KJ_PAGE, n = min_t(size_t, len, KJ_PAGE - in);
		/* Retained first, then the sealed, then the live overlay, which is newest. */
		struct kj_ent *es[3] = { j->rnpages ? kj_find_in(j->rhash, blk) : NULL,
					 j->snpages ? kj_find_in(j->shash, blk) : NULL,
					 j->npages ? kj_find(j, blk) : NULL };
		for (int k = 0; k < 3; k++) {
			struct kj_ent *e = es[k];
			if (!e)
				continue;
			for (size_t s = in / KJ_SECT * KJ_SECT; s < in + n; s += KJ_SECT) {
				size_t a, z;
				if (!(e->mask & (1u << (s / KJ_SECT))))
					continue;
				a = max_t(size_t, s, in);
				z = min_t(size_t, s + KJ_SECT, in + n);
				if (to_overlay)
					memcpy(e->data + a, buf + (a - in), z - a);
				else
					memcpy(buf + (a - in), e->data + a, z - a);
			}
		}
		off += n;
		buf += n;
		len -= n;
	}
}

static int cmp_ent(const void *a, const void *b)
{
	u64 x = (*(struct kj_ent *const *)a)->blk, y = (*(struct kj_ent *const *)b)->blk;
	return x < y ? -1 : x > y;
}

/*
 * Writes of the journal I/O gathered into requests of up to KJ_BATCH bytes (an ATA command's maximum) to consecutive device
 * offsets, and sent KJ_SEGS requests at a time, all in flight together (a pass of several runs, such as the in-place pass
 * over scattered metadata pages, takes the time of its slowest request, not the sum).  Nothing in a pass depends on the
 * order its requests complete: every pass is followed by a device flush, and the caller waits for the whole pass first.
 * buf NULL: one request per call, one by one (no memory).
 */
#define KJ_BATCH (128 * 1024)
#define KJ_BATCH_BUF (512 * 1024)
#define KJ_SEGS 8
struct kj_batch {
	struct block_device *b;
	u8 *buf;
	size_t cap;			/* bytes of buf */
	size_t used;			/* bytes of buf filled by the segments */
	unsigned int nseg;
	struct { u64 dev; size_t off, len; } seg[KJ_SEGS];
	int err;
	int fua;			/* the transfers go out with FUA (the device honours it) */
};

static void kj_batch_init(struct kj_batch *w, struct block_device *b, unsigned long pages)
{
	size_t want = (size_t)pages * KJ_PAGE, cap = want < KJ_BATCH_BUF ? want : KJ_BATCH_BUF;
	memset(w, 0, sizeof(*w));
	w->b = b;
	if (cap < KJ_BATCH)
		cap = KJ_BATCH;
	w->buf = kmalloc(cap, GFP_NOFS);
	w->cap = w->buf ? cap : 0;
}

static void kj_batch_flush(struct kj_batch *w)
{
	if (w->nseg && !w->err) {
		struct ngos_iov iov[KJ_SEGS];
		for (unsigned int i = 0; i < w->nseg; i++) {
			iov[i].off = w->seg[i].dev;
			iov[i].buf = w->buf + w->seg[i].off;
			iov[i].len = (unsigned int)w->seg[i].len;
		}
		if (w->b->kshim_gone || w->b->kshim_frozen ||
		    (w->fua ? ngos_dev_write_v_fua(w->b->osdev, iov, w->nseg) : ngos_dev_write_v(w->b->osdev, iov, w->nseg)))
			w->err = -EIO;
	}
	w->nseg = 0;
	w->used = 0;
}

static void kj_batch_add(struct kj_batch *w, u64 dev, const void *data, size_t len)
{
	if (w->err)
		return;
	if (!w->buf) {
		if (w->fua ? kj_dev_write_fua(w->b, dev, (void *)data, (unsigned int)len) : kj_dev_write(w->b, dev, (void *)data, (unsigned int)len))
			w->err = -EIO;
		return;
	}
	if (w->nseg && w->seg[w->nseg - 1].dev + w->seg[w->nseg - 1].len == dev &&
	    w->seg[w->nseg - 1].len + len <= KJ_BATCH && w->used + len <= w->cap) {
		memcpy(w->buf + w->used, data, len);
		w->seg[w->nseg - 1].len += len;
		w->used += len;
		return;
	}
	if (w->nseg == KJ_SEGS || w->used + len > w->cap)
		kj_batch_flush(w);
	if (w->err)
		return;
	w->seg[w->nseg].dev = dev;
	w->seg[w->nseg].off = w->used;
	w->seg[w->nseg].len = len;
	w->nseg++;
	memcpy(w->buf + w->used, data, len);
	w->used += len;
}

static void kj_apply_ent(struct kj_batch *w, struct kj_ent *e)
{
	u64 base = e->blk * KJ_PAGE;
	if (e->mask == 0xff) {
		kj_batch_add(w, base, e->data, KJ_PAGE);
		return;
	}
	for (int s = 0; s < 8; s++) {
		int z = s;
		if (!(e->mask & (1u << s)))
			continue;
		while (z + 1 < 8 && (e->mask & (1u << (z + 1))))
			z++;
		kj_batch_add(w, base + s * KJ_SECT, e->data + s * KJ_SECT, (z - s + 1) * KJ_SECT);
		s = z;
	}
}

/* In place, in block order (v sorted), adjacent pages in one transfer. */
static int kj_apply(struct block_device *b, struct kj_ent **v, unsigned long n)
{
	struct kj_batch w;
	kj_batch_init(&w, b, n);
	for (unsigned long i = 0; i < n && !w.err; i++)
		kj_apply_ent(&w, v[i]);
	kj_batch_flush(&w);
	kfree(w.buf);
	return w.err;
}

/* In place without allocating (the out-of-memory fallback). */
static int kj_apply_buckets(struct block_device *b, struct kshim_jnl *j)
{
	struct kj_batch w = { .b = b };
	for (int i = 0; i < KJ_BUCKETS && !w.err; i++)
		for (struct kj_ent *e = j->hash[i]; e && !w.err; e = e->next)
			kj_apply_ent(&w, e);
	return w.err;
}

/* Merge-sort replacement for the shim's insertion sort: a transaction can hold thousands of pages. */
static void kj_sort(struct kj_ent **v, struct kj_ent **tmp, unsigned long n)
{
	if (n < 16) {
		sort(v, n, sizeof(*v), cmp_ent, NULL);
		return;
	}
	unsigned long h = n / 2, i = 0, k = 0, m = h;
	kj_sort(v, tmp, h);
	kj_sort(v + h, tmp, n - h);
	while (i < h && m < n)
		tmp[k++] = v[i]->blk <= v[m]->blk ? v[i++] : v[m++];
	while (i < h)
		tmp[k++] = v[i++];
	while (m < n)
		tmp[k++] = v[m++];
	memcpy(v, tmp, n * sizeof(*v));
}

/* DBG: stops the system here when JournalFault asks for this stage of this commit (kshim_jnl_fault_stage). */
#if DBG
static void kj_fault_at(struct block_device *b, struct kshim_jnl *j, unsigned long stage, struct kj_ent **v,
		unsigned long n)
{
	if (!kshim_jnl_fault || j->commits + 1 < kshim_jnl_fault || n < 2 || kshim_jnl_fault_stage != stage)
		return;
	if (stage == 0)
		kj_apply(b, v, n / 2);
	else if (stage == 3)
		kj_apply(b, v, n);
	kj_dev_flush(b);
	printk(KERN_ERR "journal: fault injected in commit %lu seq %llu stage %lu: %lu of %lu pages in place\n",
	       j->commits + 1, (unsigned long long)j->seq, stage, stage == 0 ? n / 2 : stage == 3 ? n : 0, n);
	ngos_bugcheck("journal fault injection", __FILE__, __LINE__);
}
static void kj_stall(void)
{
	if (kshim_jnl_stall_ms)
		ngos_sleep_ms((unsigned int)kshim_jnl_stall_ms);
}
#else
#define kj_fault_at(b, j, stage, v, n) do { } while (0)
#define kj_stall() do { } while (0)
#endif

/*
 * The journal sequence of one transaction of @n pages (@v, sorted by block): descriptor and data slots, flush,
 * COMMITTED header, flush, in place, flush, ACTIVE header.  Runs with the volume lock (synchronous commit) or
 * without it (kshim_jnl_io); it touches only @v, the journal area, the header page and the volume number, which
 * nobody else touches meanwhile.  0, or an error: before the COMMITTED header nothing was changed on the
 * medium that matters (the caller keeps the pages); after it j->failed is set when the in-place pass fails.
 *
 * Two halves.  kj_tx_commit (slots, flush, COMMITTED header, flush) ends with the transaction durable: replay at the next
 * mount installs it whatever happens after.  kj_tx_apply (in place, flush, ACTIVE header) moves its pages to their places.
 * A retained transaction (the top of this file) runs only the first half, into the slot area @base, and its pages go in place
 * with the next checkpoint (kj_checkpoint, which is kj_tx_apply for the retained pages).
 */
static int kj_tx_commit(struct block_device *b, struct kshim_jnl *j, struct kj_ent **v, unsigned long n,
		unsigned long ndesc, u16 usn_new, u64 base)
{
	struct kj_desc *d;
	u32 crc = 0;
	int err = 0, slot_fua = 0;
	d = kmalloc(KJ_PAGE, GFP_NOFS);
	if (!d)
		return -ENOMEM;
	if (j->pre_started) {
		/* The slot writes were started under the volume lock and waited for with the file data (kshim_jnl_slots_start). */
		crc = j->pre_crc;
		slot_fua = j->pre_fua;
	} else {
		/* Descriptor and data slots, adjacent slots in one transfer. */
		struct kj_batch w;
		kj_batch_init(&w, b, ndesc + n);
		/* Slots with FUA when nothing plain is waiting for a flush anyway (then the flush below can go too). */
		w.fua = b->kshim_fua && ngos_dev_clean(b->osdev);
		slot_fua = w.fua;
		for (unsigned long p = 0; p < ndesc && !w.err; p++) {
			u64 dev;
			memset(d, 0, KJ_PAGE);
			for (unsigned long q = 0; q < KJ_DESC_PER_PAGE && p * KJ_DESC_PER_PAGE + q < n; q++) {
				struct kj_ent *e = v[p * KJ_DESC_PER_PAGE + q];
				d[q].blk = e->blk;
				d[q].mask = e->mask;
				d[q].crc = kj_crc32(0, e->data, KJ_PAGE);
			}
			crc = kj_crc32(crc, d, KJ_PAGE);
			if (kj_page_dev(j->ext, j->next, kj_slot_page(base + p), &dev))
				w.err = -EIO;
			else
				kj_batch_add(&w, dev, d, KJ_PAGE);
		}
		for (unsigned long i = 0; i < n && !w.err; i++) {
			u64 dev;
			crc = kj_crc32(crc, v[i]->data, KJ_PAGE);
			if (kj_page_dev(j->ext, j->next, kj_slot_page(base + ndesc + i), &dev))
				w.err = -EIO;
			else
				kj_batch_add(&w, dev, v[i]->data, KJ_PAGE);
		}
		kj_batch_flush(&w);
		kfree(w.buf);
		err = w.err;
	}
	/*
	 * The file data written in place since the last commit and the slots just written must be on
	 * the medium before the record that makes replay install the metadata pointing at them: a
	 * volatile write cache may otherwise keep the header and lose them.  With FUA (slots written with it,
	 * and no plain write completed since the last flush: the file data of a write-through write went out
	 * with FUA too) they already are, and the flush is not needed; the COMMITTED header then goes out with
	 * FUA as well (kj_hdr_write).
	 */
	if (!err && !(slot_fua && ngos_dev_clean(b->osdev)) && kj_dev_flush(b))
		err = -EIO;
	if (err)
		goto out;
	kj_stall();
	kj_fault_at(b, j, 1, v, n);
	j->seq++;
	if (ndesc + n > j->hwm)
		j->hwm = ndesc + n;
	j->hdr_tried = 1;
	err = kj_hdr_write(b, j, KJ_ST_COMMITTED, (u32)n, (u32)ndesc, crc, 1, usn_new);
out:
	kfree(d);
	return err;
}

/* In place, flush, ACTIVE header: the second half of the sequence (see kj_tx_commit). */
static int kj_tx_apply(struct block_device *b, struct kshim_jnl *j, struct kj_ent **v, unsigned long n, u16 usn_new)
{
	int err = 0;
	kj_stall();
	kj_fault_at(b, j, 2, v, n);
	kj_fault_at(b, j, 0, v, n);
#if DBG
	if (j->apply_fault && n >= 2) {
		j->apply_fault = 0;
		kj_apply(b, v, n / 2);
		kj_dev_flush(b);
		printk(KERN_ERR "journal: in-place write failure injected in seq %llu: %lu of %lu pages in place\n",
		       (unsigned long long)j->seq, n / 2, n);
		err = -EIO;
	} else
#endif
	{
		err = kj_apply(b, v, n);
	}
	if (!err && kj_dev_flush(b))
		err = -EIO;
	if (err) {
		/*
		 * Part of a committed transaction may be in place.  Its COMMITTED header is on the medium,
		 * and its replay at the next mount puts the whole transaction in place: no further write
		 * may reach the device until then (a later commit would overwrite its slots, and a header
		 * saying UNJOURNALED would throw the replay away).
		 */
		if (!j->failed)
			kshim_log_volume_failed(b, err);
		j->failed = 1;
		printk(KERN_ERR "journal: the in-place pass of seq %llu failed: no further writes until the next "
		       "mount, which replays it\n", (unsigned long long)j->seq);
		return err;
	}
	kj_fault_at(b, j, 3, v, n);
	j->vol_usn = usn_new;
	return kj_hdr_write(b, j, KJ_ST_ACTIVE, 0, 0, 0, 0, j->vol_usn);
}

static int kj_run_tx(struct block_device *b, struct kshim_jnl *j, struct kj_ent **v, unsigned long n,
		unsigned long ndesc, u16 usn_new)
{
	int err;
	j->cur_area = -1;	/* not retained: from slot 0, version KJ_VERSION */
	err = kj_tx_commit(b, j, v, n, ndesc, usn_new, 0);
	return err ? err : kj_tx_apply(b, j, v, n, usn_new);
}

/*
 * The retained transaction goes in place: its pages, a flush, the ACTIVE header (kj_ckpt_io: also called by the journal I/O of
 * a sealed transaction, without the volume lock, which leaves freeing the retained pages to kj_reap).  kj_checkpoint, for
 * callers that hold the volume lock with no journal I/O running (kj_settle), frees them and lets the frees they covered count
 * as committed (aux_done).  A failed in-place pass leaves the COMMITTED header on the medium (replay at the next mount
 * finishes it) and j->failed set, the retained pages in memory.
 */
static int kj_ckpt_io(struct kshim_jnl *j)
{
	struct block_device *b = j->bdev;
	struct kj_ent **v = NULL, **tmp = NULL;
	unsigned long n = j->rnpages, k = 0;
	int err;
	v = kmalloc_array(n, sizeof(*v), GFP_NOFS);
	tmp = kmalloc_array(n, sizeof(*v), GFP_NOFS);
	if (v && tmp) {
		for (int i = 0; i < KJ_BUCKETS; i++)
			for (struct kj_ent *e = j->rhash[i]; e; e = e->next)
				v[k++] = e;
		kj_sort(v, tmp, n);
		err = kj_tx_apply(b, j, v, n, j->rusn_new);
	} else {
		/* No memory for the sorted list: the same writes in bucket order, without allocating. */
		struct kj_batch w = { .b = b };
		for (int i = 0; i < KJ_BUCKETS && !w.err; i++)
			for (struct kj_ent *e = j->rhash[i]; e && !w.err; e = e->next)
				kj_apply_ent(&w, e);
		kj_batch_flush(&w);
		err = w.err;
		if (!err && kj_dev_flush(b))
			err = -EIO;
		if (err) {
			if (!j->failed)
				kshim_log_volume_failed(b, err);
			j->failed = 1;
			printk(KERN_ERR "journal: the in-place pass of seq %llu failed: no further writes until the next "
			       "mount, which replays it\n", (unsigned long long)j->seq);
		} else {
			j->vol_usn = j->rusn_new;
			err = kj_hdr_write(b, j, KJ_ST_ACTIVE, 0, 0, 0, 0, j->vol_usn);
		}
	}
	kfree(v);
	kfree(tmp);
	if (j->failed)
		return err ? err : -EIO;
	return 0;	/* in place (a failed ACTIVE header write only leaves a COMMITTED header whose replay is harmless) */
}

static int kj_checkpoint(struct kshim_jnl *j)
{
	int err;
	if (!j->rnpages)
		return 0;
	if (j->failed || j->readonly)
		return j->failed ? -EIO : 0;
	err = kj_ckpt_io(j);
	if (err)
		return err;
	j->aux_done = j->raux;
	kj_free_retained(j);
	j->checkpoints++;
	return 0;
}

/*
 * The synchronous commit, under the volume lock for all of it.  @aux: the caller's value (the free-cluster count)
 * that every change made before this call is covered by when it returns without an error.
 */
int kshim_jnl_commit(struct block_device *b, u64 aux)
{
	struct kshim_jnl *j = b->jnl;
	struct kj_ent **v = NULL, **tmp = NULL;
	unsigned long n, k = 0, ndesc;
	int err = 0;
	u16 usn_new;
	if (j && j->failed)
		return -EIO;
	if (j)
		kj_settle(j);	/* a sealed transaction's I/O finishes first; a failed one is back in the live overlay */
	if (j && j->failed)
		return -EIO;
	if (!j || (!j->npages && !j->degraded)) {
		if (j)
			j->aux_done = aux;
		return 0;	/* nothing written: the caller flushes the device itself */
	}
	n = j->npages;
	usn_new = kj_vol_usn_after(j);
	ndesc = (n + KJ_DESC_PER_PAGE - 1) / KJ_DESC_PER_PAGE;
	if (j->readonly)
		return 0;
	if (n) {
		v = kmalloc_array(n, sizeof(*v), GFP_NOFS);
		tmp = kmalloc_array(n, sizeof(*v), GFP_NOFS);
		if (!v || !tmp) {
			/* No memory to build a transaction: in place, under an UNJOURNALED header. */
			if (j->strict && !j->degraded) {
				j->refused = 1;
				err = -ENOMEM;
				goto out;	/* nothing written: the overlay stays */
			}
			j->fallbacks++;
			err = kj_hdr_write(b, j, KJ_ST_UNJOURNALED, 0, 0, 0, 1, j->vol_usn);
			if (err)
				goto out;	/* nothing went in place: the overlay stays for the next attempt */
			j->degraded = 1;	/* until the whole overlay is in place */
			err = kj_apply_buckets(b, j);
			if (!err && kj_dev_flush(b))
				err = -EIO;
			if (!err)
				err = kj_resync_vol_usn(b, j);	/* failing: stays degraded, the next commit redoes it */
			if (!err) {
				j->degraded = 0;
				err = kj_hdr_write(b, j, KJ_ST_ACTIVE, 0, 0, 0, 1, j->vol_usn);
			}
			goto done;
		}
		for (int i = 0; i < KJ_BUCKETS; i++)
			for (struct kj_ent *e = j->hash[i]; e; e = e->next)
				v[k++] = e;
		kj_sort(v, tmp, n);
	}
	if (j->degraded || ndesc + n > j->capacity) {
		/* Does not fit (or the overlay failed): in place under an UNJOURNALED header. */
		if (j->strict && !j->degraded) {
			j->refused = 1;
			printk(KERN_ERR "journal: %lu pages do not fit (%llu slots): refused during a resize\n",
			       n, (unsigned long long)j->capacity);
			err = -ENOSPC;
			goto out;
		}
		j->fallbacks++;
		if (!j->degraded)
			j->overflows++;	/* e.g. one operation that went far past the hard limit (ngc_commit_hard) */
		printk(KERN_WARNING "journal: %lu pages do not fit (%llu slots) or degraded=%d: writing in place (overflow %lu)\n",
		       n, (unsigned long long)j->capacity, j->degraded, j->overflows);
		err = kj_hdr_write(b, j, KJ_ST_UNJOURNALED, 0, 0, 0, 1, j->vol_usn);
		if (err)
			goto out;
		j->degraded = 1;
		err = kj_apply(b, v, n);
		if (!err && kj_dev_flush(b))
			err = -EIO;
		if (!err)
			err = kj_resync_vol_usn(b, j);
		if (!err) {
			j->degraded = 0;
			err = kj_hdr_write(b, j, KJ_ST_ACTIVE, 0, 0, 0, 1, j->vol_usn);
		}
		goto done;
	}
	j->hdr_tried = 0;
	err = kj_run_tx(b, j, v, n, ndesc, usn_new);
done:
	if (!err) {
		j->commits++;
		j->committed_pages += n;
		if (n > j->max_tx)
			j->max_tx = n;
		kj_drop_all(j);
		j->aux_done = aux;
	}
out:
	if (err)
		printk(KERN_ERR "journal: commit of %lu pages failed %d\n", n, err);
	kfree(v);
	kfree(tmp);
	return err ? err : 1;
}

/*
 * Seals the live overlay for an unlocked commit (under the volume lock).  1: sealed, kshim_jnl_io must follow (without
 * the lock, by this thread) and then kshim_jnl_reap; 0: nothing pending (everything before this call is committed,
 * aux_done is @aux); -EBUSY: the I/O of an earlier sealed transaction is in flight, wait for it (kshim_jnl_wait) and ask
 * again; -ENOSYS: not possible now (degraded, resize running, no memory, does not fit in the journal): use
 * kshim_jnl_commit.
 */
int kshim_jnl_seal(struct block_device *b, u64 aux, int retain_ok)
{
	struct kshim_jnl *j = b->jnl;
	struct kj_ent **v, **tmp;
	unsigned long n, k = 0, total, extra = 0;
	int retain, ckpt = 0;
	if (!j)
		return 0;
	if (j->failed)
		return -EIO;
	if (j->readonly)
		return 0;
	if (__atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING)
		return -EBUSY;
	kj_reap(j);
	if (j->failed)
		return -EIO;
	if (!j->npages && !j->degraded) {
		/* Retained pages are durable: all there is to commit is committed.  Their frees count when they are in place. */
		if (!j->rnpages)
			j->aux_done = aux;
		return 0;
	}
	n = j->npages;
	if (j->degraded || j->strict)
		return -ENOSYS;
	if (j->rnpages) {
		/*
		 * The transaction carries the retained pages too (each page once).  When the caller does not wait for durability
		 * (@retain_ok 0: the flusher) or that is too many, the retained pages go in place first (the I/O of this
		 * transaction does it before its own slots: the sealed set is then only the live pages and is not retained).
		 */
		for (int i = 0; i < KJ_BUCKETS; i++)
			for (struct kj_ent *e = j->hash[i]; e; e = e->next)
				if (!kj_find_in(j->rhash, e->blk))
					extra++;
		total = j->rnpages + extra;
		if (retain_ok && total <= KJ_RET_MAX) {
			retain = 1;
		} else {
			retain = 0;
			ckpt = 1;
			total = n;
		}
	} else {
		total = n;
		retain = retain_ok && j->ret_ok && n <= KJ_RET_MAX;
	}
	if (!retain && (total + (total + KJ_DESC_PER_PAGE - 1) / KJ_DESC_PER_PAGE) > j->capacity)
		return -ENOSYS;
	v = kmalloc_array(total, sizeof(*v), GFP_NOFS);
	tmp = kmalloc_array(total, sizeof(*v), GFP_NOFS);
	if (!v || !tmp) {
		kfree(v);
		kfree(tmp);
		return -ENOSYS;
	}
	j->sarea = retain && j->rnpages ? j->rarea ^ 1 : 0;
	if (retain && j->rnpages && kj_copy_h(j->shash, j->rhash, &j->snpages)) {
		kfree(v);
		kfree(tmp);
		return -ENOSYS;
	}
	/* The live pages move into the sealed set, over the copies of the retained ones (the live ones are newer). */
	for (int i = 0; i < KJ_BUCKETS; i++) {
		struct kj_ent *e = j->hash[i], *nx;
		for (; e; e = nx) {
			struct kj_ent *c = j->snpages ? kj_find_in(j->shash, e->blk) : NULL;
			nx = e->next;
			if (c) {
				for (int s = 0; s < 8; s++)
					if (e->mask & (1u << s))
						memcpy(c->data + s * KJ_SECT, e->data + s * KJ_SECT, KJ_SECT);
				c->mask |= e->mask;
				kfree(e->data);
				kfree(e);
			} else {
				e->next = j->shash[e->blk % KJ_BUCKETS];
				j->shash[e->blk % KJ_BUCKETS] = e;
				j->snpages++;
			}
		}
		j->hash[i] = NULL;
	}
	for (int i = 0; i < KJ_BUCKETS; i++)
		for (struct kj_ent *e = j->shash[i]; e; e = e->next)
			v[k++] = e;
	/* What $Volume's number is once this transaction is in place (from the sealed pages, which hold everything not in place). */
	j->susn_new = kj_vol_usn_ent(j, kj_find_in(j->shash, j->vol_rec_off / KJ_PAGE));
	j->npages = 0;
	j->sv = v;
	j->stmp = tmp;
	j->saux = aux;
	j->serr = 0;
	j->sretain = retain;
	j->sckpt = ckpt;
	j->r_applied = 0;
	j->hdr_tried = 0;
	j->unlocked_commits++;
	ngos_ev_clear(&j->idle);
	__atomic_store_n(&j->sstate, KJ_S_RUNNING, __ATOMIC_RELEASE);
	return 1;
}

/* A sealed transaction's I/O is in flight (under the volume lock: nobody else can start one meanwhile). */
int kshim_jnl_busy(struct block_device *b)
{
	return b->jnl && __atomic_load_n(&b->jnl->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING;
}

/* Waits (without the volume lock, or with: the I/O needs none) until no journal I/O is in flight. */
void kshim_jnl_wait(struct block_device *b)
{
	if (b->jnl)
		kj_wait_io(b->jnl);
}

/*
 * A retained transaction's slot writes, started right after the seal (volume lock held) so that they are in flight together with the
 * file data of the write-through write that is being committed (ngos_dev_write_start); the caller then waits for all of it
 * (ngos_dev_drain) before the lock is let go, and kshim_jnl_io goes on with the flush, the COMMITTED header and the flush.  Same
 * bytes, same slots, same order against the flush and the header as kj_tx_commit writes them; only the data write no longer
 * completes before they are sent.  0: not started (kj_tx_commit writes them as always), 1: started.
 */
int kshim_jnl_slots_start(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	unsigned long n, ndesc;
	u64 base, rdev[KJ_SEGS_PRE];
	size_t rlen[KJ_SEGS_PRE], roff[KJ_SEGS_PRE], bytes;
	unsigned int nr = 0;
	struct kj_desc *d;
	u32 crc = 0;
	u8 *buf;
	int fua;
	if (!j || !j->sretain || j->sckpt || j->pre_started || j->failed || __atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) != KJ_S_RUNNING ||
	    b->kshim_gone || b->kshim_frozen || !j->snpages)
		return 0;
	n = j->snpages;
	ndesc = (n + KJ_DESC_PER_PAGE - 1) / KJ_DESC_PER_PAGE;
	base = KJ_AREA_BASE + (u64)j->sarea * KJ_AREA_SLOTS;
	bytes = (size_t)(ndesc + n) * KJ_PAGE;
	kj_sort(j->sv, j->stmp, n);
	buf = kmalloc(bytes, GFP_NOFS);
	if (!buf)
		return 0;
	d = (struct kj_desc *)buf;
	for (unsigned long p = 0; p < ndesc; p++, d = (struct kj_desc *)((u8 *)d + KJ_PAGE)) {
		memset(d, 0, KJ_PAGE);
		for (unsigned long q = 0; q < KJ_DESC_PER_PAGE && p * KJ_DESC_PER_PAGE + q < n; q++) {
			struct kj_ent *e = j->sv[p * KJ_DESC_PER_PAGE + q];
			d[q].blk = e->blk;
			d[q].mask = e->mask;
			d[q].crc = kj_crc32(0, e->data, KJ_PAGE);
		}
		crc = kj_crc32(crc, d, KJ_PAGE);
	}
	for (unsigned long i = 0; i < n; i++) {
		memcpy(buf + (ndesc + i) * KJ_PAGE, j->sv[i]->data, KJ_PAGE);
		crc = kj_crc32(crc, buf + (ndesc + i) * KJ_PAGE, KJ_PAGE);
	}
	/* The slots' places on the device, adjacent ones in one request (at most KJ_SEGS_PRE requests, else not started). */
	for (unsigned long i = 0; i < ndesc + n; i++) {
		u64 dev;
		if (kj_page_dev(j->ext, j->next, kj_slot_page(base + i), &dev)) {
			kfree(buf);
			return 0;
		}
		if (nr && rdev[nr - 1] + rlen[nr - 1] == dev && rlen[nr - 1] + KJ_PAGE <= KJ_BATCH) {
			rlen[nr - 1] += KJ_PAGE;
			continue;
		}
		if (nr == KJ_SEGS_PRE) {
			kfree(buf);
			return 0;
		}
		rdev[nr] = dev;
		roff[nr] = i * KJ_PAGE;
		rlen[nr] = KJ_PAGE;
		nr++;
	}
	/* FUA for the slots when nothing plain is waiting for a flush anyway (as kj_tx_commit; the file data is accounted when it is waited for). */
	fua = b->kshim_fua && ngos_dev_clean(b->osdev);
	for (unsigned int i = 0; i < nr; i++) {
		if (ngos_dev_write_start(b->osdev, rdev[i], buf + roff[i], (unsigned int)rlen[i], fua, 0)) {
			/* not sent: what was started is waited for and the slots are written as always */
			ngos_dev_drain(b->osdev);
			kfree(buf);
			return 0;
		}
	}
	j->pre_buf = buf;
	j->pre_crc = crc;
	j->pre_fua = fua;
	j->pre_started = 1;
	return 1;
}

/* The writes in flight with the slots failed (the file data, or a slot): this sealed transaction goes no further. */
void kshim_jnl_pre_fail(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	if (j && __atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING)
		j->pre_err = -EIO;
}

/*
 * The journal I/O of the sealed transaction.  NO volume lock: the caller sealed it under the lock, released the lock and
 * returns to it afterwards, and the device, the journal and this struct stay valid meanwhile (the glue counts the
 * thread as an unlocked I/O, so no dismount frees them).  Returns the result; the transaction stays sealed (readable)
 * until kshim_jnl_reap.
 */
int kshim_jnl_io(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	unsigned long n = j->snpages, ndesc = (n + KJ_DESC_PER_PAGE - 1) / KJ_DESC_PER_PAGE;
	unsigned long long t0 = ngos_ticks();
	int err;
	kj_sort(j->sv, j->stmp, n);
	if (j->sckpt) {
		/*
		 * The retained pages first: in place, flush, ACTIVE header.  This transaction's slots (from slot 0) may then overwrite
		 * the slot areas (a crash in between finds the header COMMITTED or ACTIVE: either way the retained transaction is in
		 * place and flushed, and a header whose slots were overwritten is ignored as torn).  They stay readable until kj_reap.
		 */
		err = kj_ckpt_io(j);
		if (!err) {
			j->r_applied = 1;
			/* $Volume's number is what the retained pages made it (j->vol_usn now), unless this transaction changes it again. */
			j->susn_new = kj_vol_usn_ent(j, kj_find_in(j->shash, j->vol_rec_off / KJ_PAGE));
		} else {
			printk(KERN_ERR "journal: the checkpoint before a commit failed %d\n", err);
		}
	} else {
		err = 0;
	}
	if (err) {
		/* nothing of this transaction was written */
	} else if (j->pre_err) {
		err = j->pre_err;	/* the file data or the slots, written in flight with each other, failed: no header */
	} else if (j->sretain) {
		/* Durable in a slot area; the pages stay in memory as the retained transaction (kj_reap) until a checkpoint. */
		j->cur_area = j->sarea;
		err = kj_tx_commit(b, j, j->sv, n, ndesc, j->susn_new, KJ_AREA_BASE + (u64)j->sarea * KJ_AREA_SLOTS);
		if (err && j->hdr_tried && j->rnpages) {
			/*
			 * The header may be on the medium and names this area: a retry into the other area would overwrite the
			 * slots of the retained transaction, which the header page no longer points to.  Nothing more is written
			 * until the next mount, which replays whichever transaction the medium holds.
			 */
			if (!j->failed)
				kshim_log_volume_failed(b, err);
			j->failed = 1;
			printk(KERN_ERR "journal: the commit header of seq %llu may be on the medium but was not made durable: "
			       "no further writes until the next mount, which replays it\n", (unsigned long long)j->seq);
		}
	} else {
		err = kj_run_tx(b, j, j->sv, n, ndesc, j->susn_new);
	}
	if (err)
		printk(KERN_ERR "journal: commit of %lu pages failed %d\n", n, err);
	kfree(j->sv);
	kfree(j->stmp);
	j->sv = j->stmp = NULL;
	kfree(j->pre_buf);
	j->pre_buf = NULL;
	j->pre_started = j->pre_err = 0;
	j->serr = err;
#if DBG
	j->io_us += (unsigned long)((ngos_ticks() - t0) / 2000);	/* ticks are TSC: ~2 GHz, only an estimate */
#else
	(void)t0;
#endif
	/*
	 * DONE before the event, and j is still touched after DONE is visible: a waiter that sees DONE may reap at once.
	 * That is safe only because j (the journal, freed by kshim_jnl_deactivate at the dismount) outlives this thread's
	 * last access: the caller either holds CoreLock for the whole I/O (NgCommit, not at depth 1 or after a dismount
	 * began), or counts in DioActive until it has CoreLock back (NgPinUnlocked .. NgDataIoDone), and the dismount waits
	 * for DioActive 0 under CoreLock before anything is freed.  A caller without that pin must not use kshim_jnl_io.
	 * The event is not set first: a woken waiter that still saw RUNNING would spin on the signalled event without
	 * yielding (kj_wait_io), which on one CPU against a lower-priority I/O thread never ends.
	 */
	__atomic_store_n(&j->sstate, KJ_S_DONE, __ATOMIC_RELEASE);
	ngos_ev_set(&j->idle);	/* the last access to j by this thread */
	return err;
}

/* Under the volume lock, after kshim_jnl_io (or when anyone else needs the sealed overlay gone): releases a finished transaction. */
void kshim_jnl_reap(struct block_device *b)
{
	if (b->jnl)
		kj_reap(b->jnl);
}

void kshim_jnl_report(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	if (!j)
		return;
	printk(KERN_WARNING "journal: %lu commits, %lu pages, largest %lu, %lu in-place fallbacks (%lu overflowed the journal), %lu dropped, seq %llu, pending %lu, %lu unlocked commits, %lu retained, %lu checkpoints\n",
	       j->commits, j->committed_pages, j->max_tx, j->fallbacks, j->overflows, j->dropped, (unsigned long long)j->seq,
	       j->npages + j->snpages + j->rnpages, j->unlocked_commits, j->retained_commits, j->checkpoints);
#if DBG
	printk(KERN_WARNING "journal: unlocked journal I/O about %lu ms in total\n", j->io_us / 1000);
#endif
}

/* ------------------------------------------------------------ clusters freed, not yet committed */
/*
 * File data is written in place.  A cluster freed by a transaction that is not committed (not covered by aux_done) must not
 * receive data of another file before it is: a crash would give the old owner the new data.  The core used to commit before
 * every allocation that followed a free; instead it leaves these clusters out of the allocation (kshim_resv_skip) and waits
 * only when the list is full or the volume has too little other room (kshim_resv_state).  An entry is dropped once aux_done
 * has reached its tag (the free-count after the free), exactly when the old wait would have ended.
 */
static void kj_resv_prune(struct kshim_jnl *j)
{
	u64 done = j->aux_done;
	int i = 0;
	while (i < j->nresv) {
		if (j->resv[i].tag <= done) {
			j->resv_clusters -= j->resv[i].len;
			j->resv[i] = j->resv[--j->nresv];
		} else
			i++;
	}
	if (j->resv_over && j->resv_over <= done)
		j->resv_over = 0;
}

/* A free of @nr clusters at @lcn, counted as free number @tag (called under the volume lock, before the count is raised). */
void kshim_resv_note(struct block_device *b, u64 lcn, u64 nr, u64 tag)
{
	struct kshim_jnl *j = b->jnl;
	unsigned char irql;
	if (!j || !nr)
		return;
	irql = ngos_spin_lock(&j->resv_lock);
	kj_resv_prune(j);
	if (j->nresv && j->resv[j->nresv - 1].tag == tag && j->resv[j->nresv - 1].lcn + j->resv[j->nresv - 1].len == lcn) {
		j->resv[j->nresv - 1].len += nr;
		j->resv_clusters += nr;
	} else if (j->nresv < KJ_RESV_MAX) {
		j->resv[j->nresv].lcn = lcn;
		j->resv[j->nresv].len = nr;
		j->resv[j->nresv].tag = tag;
		j->nresv++;
		j->resv_clusters += nr;
	} else if (tag > j->resv_over)
		j->resv_over = tag;
	ngos_spin_unlock(&j->resv_lock, irql);
}

/*
 * The end of the reserved range that holds @lcn, else @lcn.  *@next is the first cluster at or after which the answer can
 * change (the end of that range, or the start of the next one; ~0 when none), so a caller that goes up one cluster at a
 * time asks again only from there.  Entries are only added under the volume lock the allocator holds.
 */
u64 kshim_resv_skip(struct block_device *b, u64 lcn, u64 *next)
{
	struct kshim_jnl *j = b->jnl;
	unsigned char irql;
	u64 end = lcn, nxt = ~0ULL, done;
	int i;
	*next = ~0ULL;
	if (!j || !j->nresv)
		return lcn;
	irql = ngos_spin_lock(&j->resv_lock);
	done = j->aux_done;
	for (i = 0; i < j->nresv; i++) {
		u64 lo = j->resv[i].lcn, hi = lo + j->resv[i].len;
		if (j->resv[i].tag <= done)
			continue;
		if (lcn >= lo && lcn < hi) {
			if (hi > end)
				end = hi;
		} else if (lo > lcn && lo < nxt)
			nxt = lo;
	}
	ngos_spin_unlock(&j->resv_lock, irql);
	*next = end > lcn ? end : nxt;
	return end;
}

/* Non-zero when some free is noted that no complete commit covers yet. */
int kshim_resv_any(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	unsigned char irql;
	int any = 0, i;
	if (!j || !j->nresv)
		return 0;
	irql = ngos_spin_lock(&j->resv_lock);
	for (i = 0; i < j->nresv; i++)
		if (j->resv[i].tag > j->aux_done) {
			any = 1;
			break;
		}
	ngos_spin_unlock(&j->resv_lock, irql);
	return any;
}

/* Sets in @bits (bit 0 = cluster @first, @nbits bits) the bits of the clusters that are reserved now. */
void kshim_resv_mark(struct block_device *b, u64 first, u64 nbits, u8 *bits)
{
	struct kshim_jnl *j = b->jnl;
	unsigned char irql;
	int i;
	if (!j || !j->nresv)
		return;
	irql = ngos_spin_lock(&j->resv_lock);
	for (i = 0; i < j->nresv; i++) {
		u64 lo = j->resv[i].lcn, hi = lo + j->resv[i].len, c;
		if (j->resv[i].tag <= j->aux_done || hi <= first || lo >= first + nbits)
			continue;
		for (c = lo > first ? lo : first; c < hi && c < first + nbits; c++)
			bits[(c - first) >> 3] |= 1 << ((c - first) & 7);
	}
	ngos_spin_unlock(&j->resv_lock, irql);
}

/* A commit that began when the free count was @tag has been completed: every free numbered up to it is covered, whatever aux_done says. */
void kshim_resv_drop_upto(struct block_device *b, u64 tag)
{
	struct kshim_jnl *j = b->jnl;
	unsigned char irql;
	int i = 0;
	if (!j)
		return;
	irql = ngos_spin_lock(&j->resv_lock);
	while (i < j->nresv) {
		if (j->resv[i].tag <= tag) {
			j->resv_clusters -= j->resv[i].len;
			j->resv[i] = j->resv[--j->nresv];
		} else
			i++;
	}
	if (j->resv_over && j->resv_over <= tag)
		j->resv_over = 0;
	ngos_spin_unlock(&j->resv_lock, irql);
}

/* Clusters the allocator leaves alone now; -1 when the list is not complete (a free was not recorded): the caller must wait for a commit. */
s64 kshim_resv_state(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	unsigned char irql;
	s64 n;
	if (!j)
		return 0;
	irql = ngos_spin_lock(&j->resv_lock);
	kj_resv_prune(j);
	n = j->resv_over ? -1 : (s64)j->resv_clusters;
	ngos_spin_unlock(&j->resv_lock, irql);
	return n;
}

/* ------------------------------------------------------------ watched counters */
#define KSHIM_WATCHES 32
static struct { atomic64_t *v; unsigned long n; } kshim_watch[KSHIM_WATCHES];

int kshim_watch_add(atomic64_t *v)
{
	for (int i = 0; i < KSHIM_WATCHES; i++)
		if (!kshim_watch[i].v) {
			kshim_watch[i].v = v;
			kshim_watch[i].n = 0;
			return 0;
		}
	return -ENOSPC;
}

void kshim_watch_del(atomic64_t *v)
{
	for (int i = 0; i < KSHIM_WATCHES; i++)
		if (kshim_watch[i].v == v)
			kshim_watch[i].v = NULL;
}

unsigned long kshim_watch_count(atomic64_t *v)
{
	for (int i = 0; i < KSHIM_WATCHES; i++)
		if (kshim_watch[i].v == v)
			return kshim_watch[i].n;
	return 0;
}

void kshim_watch_hit(atomic64_t *v)
{
	for (int i = 0; i < KSHIM_WATCHES; i++)
		if (kshim_watch[i].v == v)
			kshim_watch[i].n++;
}

/* The dirty flag is a real request: the headers written from now on say so (until cleared). */
void kshim_jnl_set_keep(struct block_device *b, int keep)
{
	struct kshim_jnl *j = b->jnl;
	if (j && !j->readonly)
		j->keep = keep;
}

/* The core reported errors: the header says so (needs repair) from now on, so no mount clears the dirty flag. */
void kshim_jnl_mark_errors(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	if (!j || j->readonly)
		return;
	if (!__atomic_exchange_n(&j->errors, 1, __ATOMIC_SEQ_CST))
		printk(KERN_ERR "journal: the core reported errors: the volume stays marked for repair\n");
	/*
	 * The header with the mark is written here, except: over a COMMITTED header whose transaction could not be
	 * applied (failed: its replay is what the next mount needs); when the mark is on the medium already; and while
	 * the journal I/O of a sealed transaction owns the header page (it runs without the volume lock; the headers it
	 * writes carry the mark once j->errors is set).  Reached from shared (read) holders too: one writer at a time
	 * (errors_writing).  Until errors_durable is set, kshim_jnl_errors_pending keeps ngc_dirty true, so the flusher
	 * calls this again.
	 */
	if (j->failed || j->errors_durable || j->rnpages || __atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING ||
	    __atomic_exchange_n(&j->errors_writing, 1, __ATOMIC_SEQ_CST))
		return;
	if (!kj_hdr_write(b, j, KJ_ST_ERRORS, 0, 0, 0, 1, j->vol_usn))
		j->errors_durable = 1;
	__atomic_store_n(&j->errors_writing, 0, __ATOMIC_SEQ_CST);
}

int kshim_jnl_errors_pending(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	return j && !j->readonly && j->errors && !j->errors_durable && !j->failed;
}

unsigned long kshim_jnl_capacity(struct block_device *b)
{
	return b->jnl ? (unsigned long)b->jnl->capacity : 0;
}

/* Read-only mount: a committed transaction is shown through the overlay instead of being written. */
int kshim_jnl_ro_page(struct block_device *b, u64 blk, u8 mask, const u8 *data)
{
	struct kshim_jnl *j = b->jnl;
	struct kj_ent *e;
	if (!j) {
		j = kzalloc(sizeof(*j), GFP_KERNEL);
		if (!j)
			return -ENOMEM;
		j->readonly = 1;
		b->jnl = j;
	}
	e = kj_find(j, blk);
	if (!e) {
		e = kzalloc(sizeof(*e), GFP_KERNEL);
		if (e)
			e->data = kmalloc(KJ_PAGE, GFP_KERNEL);
		if (!e || !e->data) {
			kfree(e);
			return -ENOMEM;
		}
		e->blk = blk;
		e->next = j->hash[blk % KJ_BUCKETS];
		j->hash[blk % KJ_BUCKETS] = e;
		j->npages++;
	}
	for (int s = 0; s < 8; s++)
		if (mask & (1u << s)) {
			memcpy(e->data + s * KJ_SECT, data + s * KJ_SECT, KJ_SECT);
			e->mask |= 1u << s;
		}
	return 0;
}

/*
 * The overlay could not take a write: everything goes in place until the next commit, once the
 * UNJOURNALED header is on the medium.  Nonzero: it is not, and the write must fail.
 */
int kshim_jnl_degrade(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	if (j)
		kj_settle(j);
	if (j && j->failed)
		return -EIO;
	if (!j || j->degraded)
		return 0;
	if (j->strict) {
		j->refused = 1;
		return -ENOMEM;
	}
	printk(KERN_ERR "journal: out of memory for the overlay: writing in place until the next commit\n");
	if (kj_hdr_write(b, j, KJ_ST_UNJOURNALED, 0, 0, 0, 1, j->vol_usn))
		return -EIO;
	j->degraded = 1;
	return 0;
}
