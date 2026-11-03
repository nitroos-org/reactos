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
 */
#include <kshim.h>
#include <kshim_jnl.h>

#define KJ_BUCKETS 1024
#define KJ_SECT 512

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
	struct ngos_ev idle;		/* signalled while no I/O is in flight */
	unsigned long unlocked_commits, io_us;
};

enum { KJ_S_NONE = 0, KJ_S_RUNNING = 1, KJ_S_DONE = 2 };

static u32 kj_crc_table[256];
#if DBG
unsigned long kshim_jnl_fault;
unsigned long kshim_jnl_fault_stage;	/* where in the commit the fault stops it: 0 half way through the in-place pass, 1 before the COMMITTED header, 2 after it, 3 after the in-place pass */
unsigned long kshim_jnl_stall_ms;	/* the journal I/O of a sealed transaction sleeps this long between its phases */
#endif

u32 kj_crc32(u32 crc, const void *p, size_t n)
{
	const u8 *s = p;
	if (!kj_crc_table[1]) {
		for (u32 i = 0; i < 256; i++) {
			u32 c = i;
			for (int k = 0; k < 8; k++)
				c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
			kj_crc_table[i] = c;
		}
	}
	crc = ~crc;
	while (n--)
		crc = kj_crc_table[(crc ^ *s++) & 0xff] ^ (crc >> 8);
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

/* The journal's own device I/O: nothing reaches a medium that replaced the volume's. */
static int kj_dev_read(struct block_device *b, u64 off, void *buf, unsigned int len)
{
	return b->kshim_gone || ngos_dev_read(b->osdev, off, buf, len);
}
static int kj_dev_write(struct block_device *b, u64 off, void *buf, unsigned int len)
{
	return b->kshim_gone || b->kshim_frozen || ngos_dev_write(b->osdev, off, buf, len);
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

/* $Volume's number once the overlay is in place: from the overlay when it holds the record's first sector. */
static u16 kj_vol_usn_after(struct kshim_jnl *j)
{
	struct kj_ent *e = kj_find(j, j->vol_rec_off / KJ_PAGE);
	size_t in = (size_t)(j->vol_rec_off % KJ_PAGE);
	u16 usn;
	if (e && (e->mask & (1u << (in / KJ_SECT))) && !kj_rec_usn(e->data + in, KJ_SECT - in % KJ_SECT, &usn))
		return usn;
	return j->vol_usn;
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
	return b->jnl && b->jnl->failed;
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
	return j && !j->readonly && !j->retired && !j->npages && !j->snpages && !j->degraded && !j->errors && !j->failed;
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

static struct kj_ent *kj_find_s(struct kshim_jnl *j, u64 blk)
{
	if (!j->snpages)
		return NULL;
	for (struct kj_ent *e = j->shash[blk % KJ_BUCKETS]; e; e = e->next)
		if (e->blk == blk)
			return e;
	return NULL;
}

static void kj_wait_io(struct kshim_jnl *j)
{
	while (__atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING)
		ngos_ev_wait(&j->idle);
}

static void kj_free_sealed(struct kshim_jnl *j)
{
	for (int i = 0; i < KJ_BUCKETS; i++) {
		struct kj_ent *e = j->shash[i], *n;
		for (; e; e = n) {
			n = e->next;
			kfree(e->data);
			kfree(e);
		}
		j->shash[i] = NULL;
	}
	j->snpages = 0;
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
	if (!j->serr) {
		j->commits++;
		j->committed_pages += j->snpages;
		if (j->snpages > j->max_tx)
			j->max_tx = j->snpages;
		j->aux_done = j->saux;
		kj_free_sealed(j);
	} else {
		kj_merge_back(j);
	}
	__atomic_store_n(&j->sstate, KJ_S_NONE, __ATOMIC_RELEASE);
}

static void kj_settle(struct kshim_jnl *j)
{
	kj_wait_io(j);
	kj_reap(j);
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
	u64 dev;
	if (j->readonly)
		return -EROFS;
	if (j->errors && state == KJ_ST_ACTIVE)
		state = KJ_ST_ERRORS;
	memset(j->hdrpage, 0, KJ_PAGE);
	memcpy(h->magic, KJ_MAGIC, 8);
	h->version = KJ_VERSION;
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
	h->flags = j->errors ? KJ_FL_ERRORS : 0;
	h->hdr_crc = kj_crc32(0, h, offsetof(struct kj_hdr, hdr_crc));
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
	if (j->retired || j->npages || j->snpages || j->degraded || j->errors || j->failed)
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
	j->next = next;
	j->lf_pages = lf_pages;
	j->serial = serial;
	j->seq = seq;
	j->vol_rec_off = vol_rec_off;
	while (kj_slot_page(j->capacity) < lf_pages)
		j->capacity++;
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

/* Waits until no journal I/O is in flight and releases a finished sealed transaction. */
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
	if (!j || (!j->npages && !j->snpages) || !len)
		return 0;
	return (j->npages && kj_holds_h(j->hash, off, len)) || (j->snpages && kj_holds_h(j->shash, off, len));
}

/* to_overlay 0: copy held sectors over a buffer read from the device; 1: update held sectors from a direct write. */
void kshim_jnl_patch(struct block_device *b, int to_overlay, u64 off, u8 *buf, size_t len)
{
	struct kshim_jnl *j = b->jnl;
	if (!j || (!j->npages && !j->snpages))
		return;
	/* A sealed entry is read by the journal I/O until it ends: a write over one of its sectors waits for that. */
	if (to_overlay && j->snpages && __atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING &&
	    kj_holds_h(j->shash, off, len))
		kj_wait_io(j);
	while (len) {
		u64 blk = off / KJ_PAGE;
		size_t in = off % KJ_PAGE, n = min_t(size_t, len, KJ_PAGE - in);
		/* Sealed first, then the live overlay, which is newer. */
		struct kj_ent *es[2] = { kj_find_s(j, blk), j->npages ? kj_find(j, blk) : NULL };
		for (int k = 0; k < 2; k++) {
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

/* Writes to consecutive device offsets in transfers of up to KJ_BATCH bytes, an ATA command's maximum (buf NULL: one by one). */
#define KJ_BATCH (128 * 1024)
struct kj_batch {
	struct block_device *b;
	u8 *buf;
	u64 dev;
	size_t len;
	int err;
};

static void kj_batch_flush(struct kj_batch *w)
{
	if (w->len && !w->err && kj_dev_write(w->b, w->dev, w->buf, (unsigned int)w->len))
		w->err = -EIO;
	w->len = 0;
}

static void kj_batch_add(struct kj_batch *w, u64 dev, const void *data, size_t len)
{
	if (w->err)
		return;
	if (!w->buf) {
		if (kj_dev_write(w->b, dev, (void *)data, (unsigned int)len))
			w->err = -EIO;
		return;
	}
	if (w->len && (w->dev + w->len != dev || w->len + len > KJ_BATCH))
		kj_batch_flush(w);
	if (!w->len)
		w->dev = dev;
	memcpy(w->buf + w->len, data, len);
	w->len += len;
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
	struct kj_batch w = { b, kmalloc(KJ_BATCH, GFP_NOFS), 0, 0, 0 };
	for (unsigned long i = 0; i < n && !w.err; i++)
		kj_apply_ent(&w, v[i]);
	kj_batch_flush(&w);
	kfree(w.buf);
	return w.err;
}

/* In place without allocating (the out-of-memory fallback). */
static int kj_apply_buckets(struct block_device *b, struct kshim_jnl *j)
{
	struct kj_batch w = { b, NULL, 0, 0, 0 };
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
 */
static int kj_run_tx(struct block_device *b, struct kshim_jnl *j, struct kj_ent **v, unsigned long n,
		unsigned long ndesc, u16 usn_new)
{
	struct kj_desc *d;
	u32 crc = 0;
	int err = 0;
	d = kmalloc(KJ_PAGE, GFP_NOFS);
	if (!d)
		return -ENOMEM;
	{
		/* Descriptor and data slots, adjacent slots in one transfer. */
		struct kj_batch w = { b, kmalloc(KJ_BATCH, GFP_NOFS), 0, 0, 0 };
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
			if (kj_page_dev(j->ext, j->next, kj_slot_page(p), &dev))
				w.err = -EIO;
			else
				kj_batch_add(&w, dev, d, KJ_PAGE);
		}
		for (unsigned long i = 0; i < n && !w.err; i++) {
			u64 dev;
			crc = kj_crc32(crc, v[i]->data, KJ_PAGE);
			if (kj_page_dev(j->ext, j->next, kj_slot_page(ndesc + i), &dev))
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
	 * volatile write cache may otherwise keep the header and lose them.
	 */
	if (!err && kj_dev_flush(b))
		err = -EIO;
	if (err)
		goto out;
	kj_stall();
	kj_fault_at(b, j, 1, v, n);
	j->seq++;
	if (ndesc + n > j->hwm)
		j->hwm = ndesc + n;
	err = kj_hdr_write(b, j, KJ_ST_COMMITTED, (u32)n, (u32)ndesc, crc, 1, usn_new);
	if (err)
		goto out;
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
		j->failed = 1;
		printk(KERN_ERR "journal: the in-place pass of seq %llu failed: no further writes until the next "
		       "mount, which replays it\n", (unsigned long long)j->seq);
		goto out;
	}
	kj_fault_at(b, j, 3, v, n);
	j->vol_usn = usn_new;
	err = kj_hdr_write(b, j, KJ_ST_ACTIVE, 0, 0, 0, 0, j->vol_usn);
out:
	kfree(d);
	return err;
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
int kshim_jnl_seal(struct block_device *b, u64 aux)
{
	struct kshim_jnl *j = b->jnl;
	struct kj_ent **v, **tmp;
	unsigned long n, k = 0;
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
		j->aux_done = aux;
		return 0;
	}
	n = j->npages;
	if (j->degraded || j->strict || (n + (n + KJ_DESC_PER_PAGE - 1) / KJ_DESC_PER_PAGE) > j->capacity)
		return -ENOSYS;
	v = kmalloc_array(n, sizeof(*v), GFP_NOFS);
	tmp = kmalloc_array(n, sizeof(*v), GFP_NOFS);
	if (!v || !tmp) {
		kfree(v);
		kfree(tmp);
		return -ENOSYS;
	}
	j->susn_new = kj_vol_usn_after(j);	/* what $Volume's number is once this transaction is in place (before the overlay moves) */
	for (int i = 0; i < KJ_BUCKETS; i++) {
		j->shash[i] = j->hash[i];
		for (struct kj_ent *e = j->hash[i]; e; e = e->next)
			v[k++] = e;
		j->hash[i] = NULL;
	}
	j->snpages = n;
	j->npages = 0;
	j->sv = v;
	j->stmp = tmp;
	j->saux = aux;
	j->serr = 0;
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
	err = kj_run_tx(b, j, j->sv, n, ndesc, j->susn_new);
	if (err)
		printk(KERN_ERR "journal: commit of %lu pages failed %d\n", n, err);
	kfree(j->sv);
	kfree(j->stmp);
	j->sv = j->stmp = NULL;
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
	printk(KERN_WARNING "journal: %lu commits, %lu pages, largest %lu, %lu in-place fallbacks (%lu overflowed the journal), %lu dropped, seq %llu, pending %lu, %lu unlocked commits\n",
	       j->commits, j->committed_pages, j->max_tx, j->fallbacks, j->overflows, j->dropped, (unsigned long long)j->seq,
	       j->npages + j->snpages, j->unlocked_commits);
#if DBG
	printk(KERN_WARNING "journal: unlocked journal I/O about %lu ms in total\n", j->io_us / 1000);
#endif
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
	if (j->failed || j->errors_durable || __atomic_load_n(&j->sstate, __ATOMIC_ACQUIRE) == KJ_S_RUNNING ||
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
