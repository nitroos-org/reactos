// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kshim_wb.c - writeback side of the kernel shim: dirty-folio iteration, inode writeback
 * and the volume sync loop for the core's metadata mappings (iomap writeback itself is in
 * kshim_iomap.c).  All writes are synchronous device writes through kshim_dev_rw.
 * Callers hold the NT glue's volume lock, so there is no concurrent writeback.
 */
#include <kshim.h>

int kshim_dev_rw(struct block_device *b, int write, u64 off, void *buf, size_t len);
int kshim_inodes_snapshot(struct super_block *sb, struct inode ***out);
bool kshim_sb_dirty(struct super_block *sb);
extern unsigned long long kshim_dirty_gen;
bool kshim_sb_dirty_full(struct super_block *sb);

static unsigned long long kshim_dirty_gen_read(void)
{
	return __atomic_load_n(&kshim_dirty_gen, __ATOMIC_SEQ_CST);
}

/* True when nothing was made dirty since a scan of @sb found everything clean. */
static bool kshim_sb_known_clean(struct super_block *sb)
{
	return sb->kshim_clean_valid && sb->kshim_clean_gen == kshim_dirty_gen_read();
}

#if DBG
/*
 * Checked builds: a sync that skips its scan must be right.  Run the scan anyway (kshim_sb_dirty_full, which
 * reads the folios and inode states, not the hints) and require it to find nothing.  Dirt found while the
 * dirty generation is still the recorded one is a dirtying that never announced itself: that is the bug this
 * check exists for (stage NGP_SKIP_WRONG, then BUG).  A short wait lets a dirtier that is between setting the
 * state and bumping finish; if the generation moved, the dirtying was announced after the skip decision:
 * the skip was correct at its linearisation point, counted as NGP_SKIP_RACED.
 */
static void kshim_check_skip(struct super_block *sb)
{
	unsigned long long g = sb->kshim_clean_gen;
	ngos_prof(NGP_SKIP_TAKEN, ngos_ticks(), 0);
	if (!kshim_sb_dirty_full(sb)) {
		ngos_prof(NGP_SKIP_CHECKED, ngos_ticks(), 0);
		return;
	}
	for (int k = 0; k < 100000; k++) {
		if (kshim_dirty_gen_read() != g) {
			ngos_prof(NGP_SKIP_RACED, ngos_ticks(), 0);
			return;
		}
		__asm__ __volatile__("pause" ::: "memory");
	}
	ngos_prof(NGP_SKIP_WRONG, ngos_ticks(), 0);
	printk(KERN_ERR "kshim_sync skipped its scan (generation %llu) but something is dirty: a dirtying did not bump the generation\n", g);
	BUG();
}
#else
#define kshim_check_skip(sb) do { } while (0)
#endif

static int cmp_folio(const void *a, const void *b)
{
	pgoff_t x = (*(struct folio *const *)a)->index, y = (*(struct folio *const *)b)->index;
	return x < y ? -1 : x > y;
}

struct wb_state { struct folio **v; int n; int err; };

/*
 * writeback_iter contract: each dirty folio of @m once, referenced and locked, dirty bit cleared.
 * As in Linux for WB_SYNC_ALL: *e is 0 on the first call, the caller stores each folio's result
 * there, and the walk ends (NULL) with the first error in *e.  A failed allocation ends it at once
 * with -ENOMEM, every folio still dirty.
 */
struct folio *writeback_iter(struct address_space *m, struct writeback_control *w, struct folio *f, int *e)
{
	struct wb_state *st = w->kshim_priv;
	kshim_wb_scope_point();
	if (f) {
		/* The previous folio: the caller unlocked it (or left it locked on error). */
		if (folio_test_locked(f))
			folio_unlock(f);
		folio_put(f);
		if (st && *e && !st->err)
			st->err = *e;
	}
	if (!st) {
		int cap = (int)m->nrpages + 1, b;
		*e = 0;
		st = kzalloc(sizeof(*st), GFP_NOFS);
		if (!st) {
			*e = -ENOMEM;
			return NULL;
		}
		st->v = kmalloc_array(cap, sizeof(*st->v), GFP_NOFS);
		if (!st->v) {
			kfree(st);
			*e = -ENOMEM;
			return NULL;
		}
		/* The cache's own spin lock is not exported; callers serialise on the volume lock. */
		for (b = 0; b < KSHIM_PC_BUCKETS; b++)
			for (struct folio *x = m->pc[b]; x && st->n < cap; x = x->hnext)
				if (folio_test_dirty(x)) {
					folio_get(x);
					st->v[st->n++] = x;
				}
		sort(st->v, st->n, sizeof(*st->v), cmp_folio, NULL);
		w->kshim_priv = st;
		w->kshim_pos = 0;
	}
	while (w->kshim_pos < st->n) {
		struct folio *x = st->v[w->kshim_pos++];
		folio_lock(x);
		if (!folio_test_dirty(x) || x->mapping != m) {
			folio_unlock(x);
			folio_put(x);
			continue;
		}
		clear_bit(PG_dirty, &x->flags);
		return x;
	}
	*e = st->err;
	kfree(st->v);
	kfree(st);
	w->kshim_priv = NULL;
	return NULL;
}

void folio_start_writeback(struct folio *f) { set_bit(PG_writeback, &f->flags); }
void folio_end_writeback(struct folio *f) { clear_bit(PG_writeback, &f->flags); }
void folio_redirty_for_writepage(struct writeback_control *wbc, struct folio *f) { (void)wbc; folio_mark_dirty(f); }

void d_instantiate(struct dentry *d, struct inode *i) { d->d_inode = i; }
void d_instantiate_new(struct dentry *d, struct inode *i) { d->d_inode = i; unlock_new_inode(i); }
struct timespec64 simple_rename_timestamp(struct inode *a, struct dentry *b, struct inode *c, struct dentry *d)
{
	(void)b; (void)c; (void)d;
	return inode_set_ctime_current(a);
}
bool is_subdir(struct dentry *a, struct dentry *b)
{
	for (struct dentry *d = a; ; d = d->d_parent) {
		if (d == b || (d->d_inode && b->d_inode && d->d_inode == b->d_inode))
			return true;
		if (d->d_parent == d)
			return false;
	}
}

/*
 * Whether a folio of @m is dirty.  A folio becomes dirty only through folio_mark_dirty, which sets the hint, so a mapping
 * whose hint is clear has none (the scan below walks every cached folio of the mapping, and the metadata flush asks this
 * of every inode, several times, for each commit); a scan that finds none clears the hint.  Callers hold the volume lock,
 * which also orders the writers of the mapping.
 */
bool kshim_mapping_dirty(struct address_space *m)
{
	if (!m->kshim_dirty_hint)
		return false;
	for (int b = 0; b < KSHIM_PC_BUCKETS; b++)
		for (struct folio *x = m->pc[b]; x; x = x->hnext)
			if (folio_test_dirty(x))
				return true;
	m->kshim_dirty_hint = 0;
	return false;
}

int kshim_mapping_writeback(struct address_space *m)
{
	struct writeback_control wbc = { .sync_mode = WB_SYNC_ALL, .nr_to_write = LONG_MAX, .range_end = LLONG_MAX };
	int err;
	if (!m->a_ops || !m->a_ops->writepages || !kshim_mapping_dirty(m))
		return 0;
	kshim_wb_scope_enter();
	err = m->a_ops->writepages(m, &wbc);
	kshim_wb_scope_exit();
	if (err)
		printk(KERN_ERR "writepages(ino %llu) failed %d\n", (unsigned long long)m->host->i_ino, err);
	return err;
}
int filemap_write_and_wait(struct address_space *m) { return kshim_mapping_writeback(m); }
int filemap_write_and_wait_range(struct address_space *m, loff_t s, loff_t e) { (void)s; (void)e; return kshim_mapping_writeback(m); }

int write_inode_now(struct inode *i, int sync)
{
	struct writeback_control wbc = { .sync_mode = sync ? WB_SYNC_ALL : WB_SYNC_NONE };
	int err = kshim_mapping_writeback(i->i_mapping), e2;
	i->i_state &= ~I_DIRTY_PAGES;
	if (kshim_mapping_dirty(i->i_mapping)) {
		i->i_state |= I_DIRTY_PAGES;
		kshim_dirty_bump();
	}
	if (i->i_state & (I_DIRTY_SYNC | I_DIRTY_DATASYNC)) {
		i->i_state &= ~(I_DIRTY_SYNC | I_DIRTY_DATASYNC);
		if (i->i_sb->s_op->write_inode) {
			kshim_wb_scope_enter();
			e2 = i->i_sb->s_op->write_inode(i, &wbc);
			kshim_wb_scope_exit();
			if (e2) {
				printk(KERN_ERR "write_inode(ino %llu) failed %d\n", (unsigned long long)i->i_ino, e2);
				err = err ? err : e2;
			}
		}
	}
	return err;
}

int kshim_blkdev_writepages(struct address_space *m, struct writeback_control *w)
{
	struct folio *f = NULL;
	int e = 0;
	struct block_device *b = m->host->i_private;
	while ((f = writeback_iter(m, w, f, &e))) {
		int r = kshim_dev_rw(b, 1, (u64)f->index << PAGE_SHIFT, f->data, PAGE_SIZE);
		if (r) {
			e = r;
			folio_mark_dirty(f);
		}
		folio_unlock(f);
	}
	return e;
}

/*
 * The flusher and sync(2) stand-in: write back dirty mappings and dirty inodes of @sb until a
 * pass finds nothing (writing one inode can dirty another: index entries, bitmaps, $MFT).
 * Returns the first writeback error, or -EAGAIN when 8 passes still found work.
 */
unsigned long kshim_counter_syncs, kshim_counter_sync_skips;
int kshim_sync(struct super_block *sb)
{
	int pass, err = 0, any = 1;
	kshim_counter_syncs++;
	if (kshim_sb_known_clean(sb)) {
		kshim_counter_sync_skips++;
		kshim_check_skip(sb);
		return 0;
	}
	for (pass = 0; pass < 8 && any; pass++) {
		struct inode **v;
		unsigned long long gen = kshim_dirty_gen_read();
		int n = kshim_inodes_snapshot(sb, &v);
		any = 0;
		if (n < 0)
			return n;
		for (int k = 0; k < n; k++) {
			struct inode *i = v[k];
			if ((i->i_state & I_DIRTY) || kshim_mapping_dirty(i->i_mapping)) {
				int e = write_inode_now(i, 1);
				any = 1;
				if (e && !err)
					err = e;
			}
		}
		for (int k = 0; k < n; k++)
			iput(v[k]);
		kfree(v);
		if (kshim_mapping_dirty(sb->s_bdev->bd_mapping)) {
			int e = kshim_mapping_writeback(sb->s_bdev->bd_mapping);
			any = 1;
			if (e && !err)
				err = e;
		}
		if (err)
			break;
		if (!any) {
			/* This pass found nothing dirty: so would every sync until something is dirtied again. */
			sb->kshim_clean_gen = gen;
			sb->kshim_clean_valid = 1;
		}
	}
	if (!err && any && kshim_sb_dirty(sb))
		err = -EAGAIN;
	return err;
}

/* True while any inode or mapping of @sb has unwritten changes. */
bool kshim_sb_dirty(struct super_block *sb)
{
	struct inode **v;
	bool d = false;
	unsigned long long gen = kshim_dirty_gen_read();
	int n;
	if (kshim_sb_known_clean(sb)) {
		kshim_check_skip(sb);
		return false;
	}
	n = kshim_inodes_snapshot(sb, &v);
	if (n < 0)
		return true;
	for (int k = 0; k < n; k++)
		if ((v[k]->i_state & I_DIRTY) || kshim_mapping_dirty(v[k]->i_mapping))
			d = true;
	for (int k = 0; k < n; k++)
		iput(v[k]);
	kfree(v);
	d = d || kshim_mapping_dirty(sb->s_bdev->bd_mapping);
	if (!d) {
		sb->kshim_clean_gen = gen;
		sb->kshim_clean_valid = 1;
	}
	return d;
}

void sync_inodes_sb(struct super_block *sb) { kshim_sync(sb); }

/*
 * Reachable from data on disk, so they must not stop the system.  vmap fails, and WOF chunks
 * larger than a page (XPRESS8K/16K, LZX) are decoded through the core's per-chunk buffer;
 * discard and zeroing report that they are not supported.
 */
void *vmap(void *pages, unsigned int count, unsigned long flags, int prot)
{
	(void)pages; (void)count; (void)flags; (void)prot;
	return NULL;
}
void vunmap(const void *addr) { (void)addr; }
int blkdev_issue_discard(struct block_device *b, sector_t s, sector_t n, gfp_t g)
{
	(void)b; (void)s; (void)n; (void)g;
	return -EOPNOTSUPP;
}
int blkdev_issue_zeroout(struct block_device *b, sector_t s, sector_t n, gfp_t g, unsigned f)
{
	(void)b; (void)s; (void)n; (void)g; (void)f;
	return -EOPNOTSUPP;
}
int iomap_zero_range(struct inode *inode, loff_t pos, loff_t len, bool *did_zero, const struct iomap_ops *ops,
		const struct iomap_write_ops *write_ops, void *private)
{
	(void)inode; (void)pos; (void)len; (void)did_zero; (void)ops; (void)write_ops; (void)private;
	return -EOPNOTSUPP;
}

int blkdev_issue_flush(struct block_device *b)
{
	/* As kshim_dev_rw: nothing goes to a replaced medium, not even a flush. */
	if (b->kshim_gone)
		return -EIO;
	return ngos_dev_flush(b->osdev) ? -EIO : 0;
}
