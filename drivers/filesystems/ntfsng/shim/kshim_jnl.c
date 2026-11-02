// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kshim_jnl.c - the shim's metadata block journal (see kshim_jnl.h).  Callers hold the NT glue's
 * volume lock, so the overlay needs no lock of its own.
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
};

static u32 kj_crc_table[256];
#if DBG
unsigned long kshim_jnl_fault;
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
	return j && !j->readonly && !j->retired && !j->npages && !j->degraded && !j->errors && !j->failed;
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
	if (!j || j->readonly || j->retired || j->npages || j->degraded || j->errors || j->failed)
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
	kj_drop_all(j);
	b->jnl = NULL;
	kfree(j->ext);
	kfree(j->hdrpage);
	kfree(j);
}

unsigned long kshim_jnl_pending(struct block_device *b)
{
	return b->jnl ? b->jnl->npages : 0;
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
		/* A partial sector not held yet starts from the device copy; bits change only after that. */
		for (size_t s = in / KJ_SECT * KJ_SECT; s < in + n; s += KJ_SECT)
			if (!(e->mask & (1u << (s / KJ_SECT))) && (s < in || s + KJ_SECT > in + n) &&
			    kj_dev_read(b, blk * KJ_PAGE + s, e->data + s, KJ_SECT))
				return -EIO;
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
	if (!j || !j->npages || !len)
		return 0;
	for (u64 s = off / KJ_SECT * KJ_SECT; s < off + len; s += KJ_SECT) {
		struct kj_ent *e = kj_find(j, s / KJ_PAGE);
		if (!e) {
			s = (s / KJ_PAGE + 1) * KJ_PAGE - KJ_SECT;	/* next page */
			continue;
		}
		if (e->mask & (1u << ((s % KJ_PAGE) / KJ_SECT)))
			return 1;
	}
	return 0;
}

/* to_overlay 0: copy held sectors over a buffer read from the device; 1: update held sectors from a direct write. */
void kshim_jnl_patch(struct block_device *b, int to_overlay, u64 off, u8 *buf, size_t len)
{
	struct kshim_jnl *j = b->jnl;
	if (!j || !j->npages)
		return;
	while (len) {
		u64 blk = off / KJ_PAGE;
		size_t in = off % KJ_PAGE, n = min_t(size_t, len, KJ_PAGE - in);
		struct kj_ent *e = kj_find(j, blk);
		if (e) {
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

int kshim_jnl_commit(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	struct kj_ent **v = NULL, **tmp = NULL;
	struct kj_desc *d = NULL;
	unsigned long n, k = 0, ndesc;
	u32 crc = 0;
	int err = 0;
	u16 usn_new;
	if (j && j->failed)
		return -EIO;
	if (!j || (!j->npages && !j->degraded))
		return 0;	/* nothing written: the caller flushes the device itself */
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
		printk(KERN_WARNING "journal: %lu pages do not fit (%llu slots) or degraded=%d: writing in place\n",
		       n, (unsigned long long)j->capacity, j->degraded);
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
	d = kmalloc(KJ_PAGE, GFP_NOFS);
	if (!d) {
		err = -ENOMEM;
		goto out;
	}
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
	j->seq++;
	if (ndesc + n > j->hwm)
		j->hwm = ndesc + n;
	err = kj_hdr_write(b, j, KJ_ST_COMMITTED, (u32)n, (u32)ndesc, crc, 1, usn_new);
	if (err)
		goto out;
	if (kshim_jnl_fault && j->commits + 1 >= kshim_jnl_fault && n >= 2) {
		kj_apply(b, v, n / 2);
		kj_dev_flush(b);
		printk(KERN_ERR "journal: fault injected in commit %lu seq %llu: %lu of %lu pages in place\n",
		       j->commits + 1, (unsigned long long)j->seq, n / 2, n);
		ngos_bugcheck("journal fault injection", __FILE__, __LINE__);
	}
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
	j->vol_usn = usn_new;
	err = kj_hdr_write(b, j, KJ_ST_ACTIVE, 0, 0, 0, 0, j->vol_usn);
done:
	if (!err) {
		j->commits++;
		j->committed_pages += n;
		if (n > j->max_tx)
			j->max_tx = n;
		kj_drop_all(j);
	}
out:
	if (err)
		printk(KERN_ERR "journal: commit of %lu pages failed %d\n", n, err);
	kfree(d);
	kfree(v);
	kfree(tmp);
	return err ? err : 1;
}

void kshim_jnl_report(struct block_device *b)
{
	struct kshim_jnl *j = b->jnl;
	if (!j)
		return;
	printk(KERN_WARNING "journal: %lu commits, %lu pages, largest %lu, %lu in-place fallbacks, %lu dropped, seq %llu, pending %lu\n",
	       j->commits, j->committed_pages, j->max_tx, j->fallbacks, j->dropped, (unsigned long long)j->seq,
	       j->npages);
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
	 * Not over a COMMITTED header whose transaction could not be applied (failed): its replay is
	 * what the next mount needs.  Reached from shared (read) holders too: one writer at a time,
	 * and tried again (ngc_dirty) until the header is on the medium.
	 */
	if (j->failed || j->errors_durable || __atomic_exchange_n(&j->errors_writing, 1, __ATOMIC_SEQ_CST))
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
