// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ngcore.c - the fs/ntfs side of ngapi.h.  Drives the unmodified core the
 * way Linux's VFS does (fs_context mount, inode_operations->lookup,
 * file_operations->iterate_shared, address_space->read_folio through the
 * shim page cache) and hands the NT glue plain C values.  No NTFS format
 * logic lives here: writes go through the core's own attribute, cluster
 * allocation, index and MFT writeback functions, driven as the VFS would.
 *
 * Locking (the glue's lock order is in nt/write.c).  Every core operation runs under the glue's volume lock, which
 * is exclusive for every caller, so the journal overlay, the page cache and the inode cache need none of their own.
 * Two kinds of device I/O run without that lock, both started by the glue between core operations and both pinning
 * what they need (ngc_dio_begin / ngc_rdio_begin pin a node; the glue counts a commit in DioActive):
 *   - file data transfers (ngc_dio_*), which never touch metadata or the overlay;
 *   - the journal I/O of a commit (ngc_commit_begin / _io / _end).  The overlay is sealed under the lock, and the
 *     I/O reads only the sealed pages and writes only the journal area, the header page and the pages' places.
 *     Every other user of those waits for it with the lock held (the I/O needs none): kshim_jnl_settle before the
 *     synchronous commit, before an allocation that follows a free (ngc_before_alloc), at retire, degrade, strict
 *     mode (a resize), deactivate, and when the medium goes or writes stop (kshim_jnl_quiesce).
 *     A commit of few pages is "retained": durable when it returns (slots, flush, COMMITTED header, flush), its pages not in
 *     place yet; kshim_jnl_settle (and so ngc_sync, retire, an allocation after a free) puts them there (shim/kshim_jnl.c).
 *   - A core operation never starts the unlocked commit and never drops the lock: ngc_mark_dirty past the overlay
 *     threshold only asks the glue (kshim_kick) and commits itself past a hard limit.
 * Frees: a cluster freed by an uncommitted transaction must not receive data before that transaction is in place.
 * The free-cluster count is watched; kshim_jnl_aux_done is its value at the last commit that is complete, so a
 * count that differs means an uncovered free, and an allocation commits (or waits for the commit in flight) first.
 */
#include <kshim.h>
#include "ntfs/ntfs.h"
#include "ntfs/attrib.h"
#include "ntfs/dir.h"
#include "ntfs/inode.h"
#include "ntfs/mft.h"
#include "ntfs/logfile.h"
#include "ntfs/lcnalloc.h"
#include "ntfs/index.h"
#include "ntfs/reparse.h"
#include "ntfs/ea.h"
#include "ntfs/bitmap.h"
#include "ngapi.h"
#include <kshim_jnl.h>
#include "ngjrec.h"
#include "ngfsck.h"

extern initcall_t kshim_module_init;
extern struct file_system_type *kshim_fs_type;
extern struct block_device *kshim_mount_bdev;
struct block_device *kshim_bdev_open(void *osdev, u64 size, unsigned int sector_size);
void kshim_bdev_close(struct block_device *b);
void kshim_mapping_shrink(struct address_space *m);
void kshim_icache_flush(struct super_block *sb, int all);
void kshim_icache_trim(struct super_block *sb);
void kshim_icache_lock(void);
void kshim_icache_unlock(void);
struct inode *kshim_icache_peek(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data);
int kshim_icache_busy(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data);
extern unsigned long kshim_pc_pages, kshim_inodes_live, kshim_counter_reads;
void kshim_dump_allocs(void);
int kshim_dev_rw(struct block_device *b, int write, u64 off, void *buf, size_t len);
int kshim_sync(struct super_block *sb);
bool kshim_sb_dirty(struct super_block *sb);
int kshim_mapping_writeback(struct address_space *m);
bool kshim_mapping_dirty(struct address_space *m);
void kshim_mapping_update(struct address_space *m, loff_t pos, const void *buf, size_t len);
extern unsigned long kshim_counter_writes, kshim_counter_syncs, kshim_counter_dirty;
extern unsigned long long kshim_counter_write_bytes;
extern bool (*kshim_is_data_inode)(struct inode *i);
extern bool (*kshim_icache_ok)(struct inode *i);
extern void (*kshim_icache_evicting)(struct inode *i);
extern void (*kshim_icache_added)(struct inode *i);
unsigned long kshim_pc_soft_limit(void);

#define NGC_SDC_N 16
#define NGC_SDC_MAX 2048
struct ngc_vol {
	struct super_block *sb;
	struct block_device *bdev;
	u8 *bounce;                     /* NGC_BOUNCE bytes of pool: a partial or unaligned device write goes through this copy, an aligned buffer straight to the device (ngc_dev_write) */
	struct ngj_vol *jv;             /* raw $LogFile location while the metadata journal is in use */
	atomic64_t *watched;            /* the core's free-cluster count, watched for frees */
	/* its increments at the last complete commit: kshim_jnl_aux_done (a commit's journal I/O may run without the volume lock) */
	int damaged;                    /* the mount-time check found damage: read-only */
	int checked;                    /* the mount-time consistency check ran to its verdict */
	char why[160];
	int failed;                     /* a consistency point was abandoned for good: every later one fails */
	int label_read;                 /* label holds $VOLUME_NAME as on disk */
	unsigned int label_len;         /* in UTF-16 units */
	unsigned short label[NGC_LABEL_MAX];
	/*
	 * Security descriptors of directories read lately (ngc_get_security): the parent directory of a create is read again for every
	 * create, and a directory whose index grew keeps its descriptor in a non-resident attribute, which costs a device
	 * read of a 4 KB cluster each time.  An entry is keyed by the record number and sequence number of the base record
	 * and dropped when the descriptor is set or the record is unlinked or created again.
	 */
	struct mutex sdc_lock;
	struct ngc_sdc {
		unsigned long long mft_no;
		unsigned short seq_no;
		unsigned int len;
		void *sd;
	} sdc[NGC_SDC_N];
	unsigned int sdc_next;
	/*
	 * What a directory listing shows of files whose inode was evicted (kshim_icache_evicting): the stat of the
	 * file as it was when its inode left the cache, direct-mapped by record number (consecutive numbers use
	 * consecutive slots), ~72 bytes a file instead of the ~2 KB of a cached inode.  Under the inode-cache lock
	 * (the hooks run under it, and so does the listing's look-up).  Void when a new inode for the number is hashed:
	 * the inode in memory is the only writer of the record, so a kept stat is current while there is none.
	 */
	struct ngc_stat *stc;
	unsigned int stc_mask;
	unsigned long stc_hits, stc_stores;
};

static void ngc_sdc_drop(struct ngc_vol *v, unsigned long long mft_no);
static void ngc_stc_evicting(struct inode *i);
static void ngc_stc_added(struct inode *i);
static void ngc_stc_free(struct ngc_vol *v);
static void ngc_sdc_flush(struct ngc_vol *v);

/* Mount-time consistency check: 0 never, 1 after an unclean shutdown or when $MFT is at most 64 MB, 2 always. */
int ngc_check_policy = 1;

/*
 * Runs the consistency check on the read-only mounted volume.  Returns a reason to stay read-only
 * (kept in @v), or NULL.  A check that cannot run (out of memory, an MFT too large) keeps the
 * volume writable, since nothing was found.
 */
static const char *ngc_mount_check(struct ngc_vol *v, struct ntfs_volume *vol, struct block_device *b, int unclean)
{
	struct ngc_fsck_res *r;
	int err;
	if (!ngc_check_policy ||
	    (ngc_check_policy == 1 && !unclean && i_size_read(vol->mft_ino) > (64LL << 20)))
		return NULL;
	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r) {
		printk(KERN_ERR "CHECK: not run (out of memory)\n");
		return NULL;
	}
	err = ngc_fsck(vol, b, r);
	v->checked = !err || r->fatal;
	if (err && !r->fatal) {
		printk(KERN_ERR "CHECK: not run (%d)\n", err);
	} else {
		printk(KERN_WARNING "CHECK: %s: %llu records (%llu in use), %llu directories (%u not walked), "
		       "%llu index entries, %llu clusters%s, %u leaks (%llu clusters), %u errors, %u ms%s\n",
		       r->fatal ? "DAMAGED" : "consistent", r->records, r->inuse, r->dirs, r->dirs_skipped, r->ientries,
		       r->clusters, r->clusters_skipped ? " (cluster map not checked: volume too large)" : "",
		       r->leaks, r->leaked_clusters, r->fatal, r->ms, unclean ? " (after an unclean shutdown)" : "");
		if (r->fatal) {
			v->damaged = 1;
			snprintf(v->why, sizeof(v->why), "the consistency check found %u errors, first: %s", r->fatal, r->why);
		}
	}
	kfree(r);
	return v->damaged ? v->why : NULL;
}

/* Pages held by the journal overlay that make the next operation commit first. */
#define NGC_JNL_COMMIT_PAGES 2048

/* Largest single core allocation when a stream grows. */
#define NGC_GROW_STEP (256LL << 20)
/*
 * Allocation ahead of the end of file.  A stream that grows in small steps (appends, a cached writer that extends the
 * file with every write) allocated clusters, rewrote its mapping pairs and (after a free) committed once per step, all
 * under the volume lock.  From NGC_PREALLOC_MIN bytes on, a step of at most NGC_PREALLOC_STEP bytes allocates up to the
 * next multiple of NGC_PREALLOC_CHUNK instead, and the steps inside it only move the size.  The slack is not visible to
 * NT (ngc_stat reports the allocation that follows the size) and is given back at the last close (ngc_trim_alloc).
 * Only with plenty of free space, so that a nearly full volume keeps its exact out-of-space behaviour.
 */
#define NGC_PREALLOC_MIN (1LL << 20)
#define NGC_PREALLOC_STEP (1LL << 20)
#define NGC_PREALLOC_CHUNK (4LL << 20)
#define NGC_PREALLOC_FREE (256LL << 20)

#define NGC_BOUNCE (64 * 1024)
#define NGC_DIRECT_MAX (1024 * 1024)

static DEFINE_MUTEX(ngc_mount_lock);
static int ngc_inited;

#define NT_EPOCH_DELTA 116444736000000000LL
static long long ts_to_nt(struct timespec64 t)
{
	return t.tv_sec * 10000000LL + t.tv_nsec / 100 + NT_EPOCH_DELTA;
}
static struct timespec64 nt_to_ts(long long nt)
{
	struct timespec64 t;
	long long u = nt - NT_EPOCH_DELTA;
	t.tv_sec = u / 10000000LL;
	t.tv_nsec = (long)(u % 10000000LL) * 100;
	if (t.tv_nsec < 0) {
		t.tv_nsec += 1000000000L;
		t.tv_sec--;
	}
	return t;
}

/* One of the core's error policy values ("remount-ro", "continue"), looked up by name. */
static int ngc_on_errors(const char *name)
{
	for (const struct option_t *o = on_errors_arr; o->str; o++)
		if (!strcmp(o->str, name))
			return o->val;
	return 0;
}

/*
 * The core never checks that $LogFile was shut down cleanly before it empties it on a
 * read-write mount.  A restart area with a log client in use and without
 * RESTART_VOLUME_IS_CLEAN means another driver left transactions behind: stay read-only.
 */
static int ngc_logfile_clean(struct ntfs_volume *vol)
{
	struct restart_page_header *rp = NULL;
	struct restart_area *ra;
	int clean;
	if (!vol->logfile_ino)
		return 0;
	if (!ntfs_check_logfile(vol->logfile_ino, &rp))
		return 0;
	if (!rp)
		return 1;	/* empty log */
	ra = (struct restart_area *)((u8 *)rp + le16_to_cpu(rp->restart_area_offset));
	clean = ra->client_in_use_list == LOGFILE_NO_CLIENT || (ra->flags & RESTART_VOLUME_IS_CLEAN);
	kvfree(rp);
	return clean;
}

/* File data goes in place without the journal: $DATA of anything but the system files. */
static bool ngc_is_data_inode(struct inode *i)
{
	struct ntfs_inode *ni = NTFS_I(i);
	return ni->type == AT_DATA && ni->mft_no >= FILE_first_user;
}

/*
 * Which unused inodes may stay cached: files, directories and their index attributes.  Other
 * attribute inodes are dropped at their last reference: the core removes and adds attributes such
 * as $SECURITY_DESCRIPTOR, $REPARSE_POINT, $EA and named streams without invalidating an attribute
 * inode, so a cached one would describe the removed attribute to the next ntfs_attr_iget.
 */
static bool ngc_icache_ok(struct inode *i)
{
	struct ntfs_inode *ni = NTFS_I(i);
	return !NInoAttr(ni) || ni->type == AT_INDEX_ALLOCATION || ni->type == AT_BITMAP;
}

/*
 * The core's error reports that mean the metadata on disk is (or would be) inconsistent.  They pass
 * through ntfs_error, which with on_errors=continue does nothing, and most of them do not set
 * NVolErrors.  Out-of-space and out-of-memory reports do not match and leave the volume as it is.
 */
static bool ngc_msg_has(const char *msg, const char *const *words, size_t n)
{
	for (const char *p = msg; *p; p++)
		for (size_t w = 0; w < n; w++) {
			size_t k = 0;
			while (words[w][k] && (p[k] >= 'A' && p[k] <= 'Z' ? p[k] + 32 : p[k]) == words[w][k])
				k++;
			if (!words[w][k])
				return true;
		}
	return false;
}

static bool ngc_msg_means_corruption(const char *msg)
{
	/*
	 * Specific phrases rather than words such as "invalid": a caller can make the core print some
	 * reports about data it just supplied ("Invalid reparse point."), which is not damage.
	 */
	static const char *const damage[] = { "inconsisten", "inconstant", "chkdsk", "corrupt", "invalid lcn",
		"invalid lowest_vcn", "invalid empty mapping", "invalid length in mapping", "invalid s64",
		"invalid zero-sized", "invalid index entry", "invalid attribute data size", "stale extent",
		"stale mft reference", "bad runlist", "overflow in mapping", "overflow from index",
		"entries overflow", "out of bounds", "beyond volume boundary", "beyond end of volume",
		"no file magic", "leaf node", "unindexed", "negative vcn", "non-resident $index_root",
		"smaller than the sector size", "restore old mapping pairs" };
	/* Resource failures that some of those reports also print (an inode load that failed for memory). */
	static const char *const resource[] = { "error code -12", "error code -28", "enomem", "enospc",
		"eoverflow", "memory", "collation error" };
	return ngc_msg_has(msg, damage, ARRAY_SIZE(damage)) && !ngc_msg_has(msg, resource, ARRAY_SIZE(resource));
}

static void ngc_core_error(struct super_block *sb, const char *msg)
{
	struct ntfs_volume *vol = NTFS_SB(sb);
	if (!vol || NVolErrors(vol) || !ngc_msg_means_corruption(msg))
		return;
	/* A resize's write refused for lack of memory reads to the core as an I/O error: the resize
	 * fails and ngc_resize_failed decides, the disk holding the last committed state. */
	if (kshim_jnl_refusing(sb->s_bdev))
		return;
	NVolSetErrors(vol);
	kshim_jnl_mark_errors(sb->s_bdev);
}

int ngc_init(void)
{
	int err = 0;
	mutex_lock(&ngc_mount_lock);
	if (!ngc_inited) {
		err = kshim_module_init();
		if (!err)
			ngc_inited = 1;
		kshim_is_data_inode = ngc_is_data_inode;
		kshim_icache_ok = ngc_icache_ok;
		kshim_icache_evicting = ngc_stc_evicting;
		kshim_icache_added = ngc_stc_added;
		kshim_core_error = ngc_core_error;
	}
	mutex_unlock(&ngc_mount_lock);
	return err;
}

void ngc_umount(ngc_vol *v, int discard);

/* Mount passes: read-only, the read-only check of a volume that is to go read-write, the write pass. */
enum { NGC_PASS_RO, NGC_PASS_CHECK, NGC_PASS_WRITE };
#define NGC_NEED_WRITE_PASS 1

/*
 * One mount of the volume.  NGC_PASS_CHECK recovers the journal into the overlay only (nothing is
 * written), mounts read-only and runs the consistency check on that view.  A damaged volume stays
 * mounted read-only; a consistent one goes read-write on the same mount when nothing has to be
 * written first, otherwise the mount is undone and NGC_NEED_WRITE_PASS asks for NGC_PASS_WRITE,
 * which replays in place, clears the dirty flag and goes read-write.
 */
static int ngc_mount_pass(void *osdev, unsigned long long size, unsigned int sector_size, int pass,
		ngc_vol **out, const char **why_ro, int *was_dirty)
{
	struct fs_context *fc;
	struct block_device *b;
	struct ngc_vol *v;
	struct ntfs_volume *vol;
	int err, jrec = NGJ_NONE, want_rw = pass != NGC_PASS_RO, jerr0, big_sectors = 0;
	u64 jseq = 0;

	*out = NULL;
	err = ngc_init();
	if (err)
		return err;
	/* The journal keeps 512-byte sectors (masks, replay, partial-page capture): not on 4Kn disks. */
	if (want_rw && sector_size != 512) {
		want_rw = 0;
		big_sectors = 1;
	}
	v = kzalloc(sizeof(*v), GFP_KERNEL);
	fc = kzalloc(sizeof(*fc), GFP_KERNEL);
	b = kshim_bdev_open(osdev, size, sector_size);
	if (!v || !fc || !b) {
		err = -ENOMEM;
		goto fail;
	}
	/*
	 * Before the core reads anything: a journal left by a crash goes in place first (the write
	 * pass) or is shown through the overlay (read-only and check passes).
	 */
	v->jv = kmalloc(sizeof(*v->jv), GFP_KERNEL);
	jerr0 = v->jv ? ngj_probe(osdev, size, sector_size, v->jv) : -ENOMEM;
	if (!jerr0 && v->jv->lf_pages >= 256) {
		jrec = ngj_recover(v->jv, b, pass == NGC_PASS_WRITE, &jseq);
		if (!want_rw) {
			kfree(v->jv);
			v->jv = NULL;
		} else {
			/* Test only: a mount that had to recover does not inject the fault again. */
#if DBG
			if (v->jv->replayed || v->jv->torn)
				kshim_jnl_fault = 0;
#endif
		}
	} else if (jerr0 == -EIO || jerr0 == -ENOMEM) {
		jrec = NGJ_UNREAD;
		kfree(v->jv);
		v->jv = NULL;
	} else {
		if (want_rw)
			printk(KERN_WARNING "journal: $LogFile not usable for the journal; metadata goes in place\n");
		kfree(v->jv);
		v->jv = NULL;
	}
	/* A foreign dirty flag the check pass cleared for (see foreign below): off the disk before the core reads it. */
	if (pass == NGC_PASS_WRITE && jrec == NGJ_NONE && !jerr0) {
		int e = ngj_clear_foreign_dirty(osdev, size, sector_size);
		if (e && e != -EINVAL)
			printk(KERN_ERR "could not clear the dirty flag (%d); the volume stays read-only\n", e);
		else if (!e)
			printk(KERN_WARNING "dirty flag cleared (set by another system, checked above)\n");
	}
	fc->fs_type = kshim_fs_type;
	fc->sb_flags = SB_RDONLY;
	fc->purpose = FS_CONTEXT_FOR_MOUNT;
	fc->source = "ntfsng";
	err = kshim_fs_type->init_fs_context(fc);
	if (err)
		goto fail;
	vol = fc->s_fs_info;
	/* NT name lookups are case-insensitive; the core defaults to case-sensitive. */
	NVolClearCaseSensitive(vol);
	/* During the mount, errors keep the volume read-only (the core's mount-time checks use this policy). */
	vol->on_errors = ngc_on_errors("remount-ro");
	/* Growing a non-sparse file allocates real clusters, as NTFS does; holes only in sparse files. */
	NVolSetDisableSparse(vol);
	mutex_lock(&ngc_mount_lock);
	kshim_mount_bdev = b;
	err = fc->ops->get_tree(fc);
	kshim_mount_bdev = NULL;
	mutex_unlock(&ngc_mount_lock);
	if (err)
		goto fail_fc;
	v->sb = fc->kshim_sb;
	v->sb->kshim_priv = v;
	v->bdev = b;
	b->bd_super = v->sb;
	v->sb->s_flags |= SB_ACTIVE;
	*why_ro = want_rw ? NULL : big_sectors ? "sectors larger than 512 bytes (the journal needs 512)" : "read-only requested";
	if (want_rw) {
		/* Our journal clears the dirty flag in the write pass: in the check pass it only marks an unclean shutdown. */
		int ours = jrec == NGJ_CLEAN, dirty = !!(vol->vol_flags & VOLUME_IS_DIRTY);
		int need_write = ours && (v->jv->replayed || v->jv->torn || v->jv->pair_pending || dirty);
		/*
		 * The flag is the mounted marker when our journal header accounts for it (a crash of ours): replayed and
		 * cleared.  A flag that came from outside (no header of ours, or a header that says the flag was set on
		 * request) is real, as for Windows: checked, kept for autochk, cleared by it.
		 */
		if (pass == NGC_PASS_CHECK && dirty && (!ours || v->jv->keep))
			*was_dirty = 1;
		/*
		 * A dirty flag with no journal of ours behind it (ntfsresize, a check another system scheduled,
		 * FSCTL_MARK_VOLUME_DIRTY, an ntfs-3g session that ended badly): what Windows' autochk settles
		 * before the volume is written.  It cannot run here, the SYSTEM hive is written long before
		 * smss starts it.  So the flag goes only after the same evidence a clean volume needs: no other
		 * flag that forces read-only, a $LogFile that is empty or marked clean (a log another system left
		 * in use is not ours to replay), and a consistency check that ran and found nothing, whatever the
		 * MountCheck policy says for other volumes.  The write pass then clears the flag before the core
		 * reads the volume.
		 */
		int foreign = jrec == NGJ_NONE && dirty && !jerr0 &&
			      !(vol->vol_flags & VOLUME_MUST_MOUNT_RO_MASK & ~VOLUME_IS_DIRTY);
		if (foreign)
			need_write = 1;
		/* The core's own remount checks run in ntfs_reconfigure; these add what it skips. */
		if (jrec == NGJ_REPAIR)
			*why_ro = "the journal says the volume needs repair (core errors, or metadata written in place without it)";
		else if (jrec == NGJ_UNREAD)
			*why_ro = "the journal could not be read (device error, a damaged $LogFile record, or no memory)";
		else if (NVolErrors(vol))
			*why_ro = "the core found errors at mount (MFTMirr, $LogFile or hibernation)";
		else if ((vol->vol_flags & VOLUME_MUST_MOUNT_RO_MASK & ~((ours || foreign) && pass == NGC_PASS_CHECK ? VOLUME_IS_DIRTY : 0)))
			*why_ro = !(vol->vol_flags & VOLUME_MUST_MOUNT_RO_MASK & ~VOLUME_IS_DIRTY) ? "volume is marked dirty" :
				dirty ? "volume is marked dirty and has flags that only a checker clears (chkdsk/upgrade/resize)" :
				"volume has flags that force read-only (chkdsk/upgrade/resize)";
		else if (!ngc_logfile_clean(vol))
			*why_ro = dirty ? "volume is marked dirty and its $LogFile was not shut down cleanly (needs chkdsk)" :
				"$LogFile was not shut down cleanly";
		else if (foreign && !ngc_check_policy)
			*why_ro = "volume is marked dirty and the mount-time check is disabled (MountCheck=2)";
		else if (pass == NGC_PASS_CHECK)
			*why_ro = ngc_mount_check(v, vol, b, need_write || dirty);
		if (!*why_ro && foreign && pass == NGC_PASS_CHECK) {
			if (!v->checked)
				*why_ro = "volume is marked dirty and the mount-time check could not run";
			else
				printk(KERN_WARNING "dirty flag without a journal of ours: $LogFile clean, consistency check passed, the write pass clears the flag\n");
		}
		/*
		 * The journal demands a repair, or cannot say whether one is needed: read-only for good, as a
		 * volume the check found damaged, so a system volume still boots (read-only, with a notice).
		 */
		if (jrec == NGJ_REPAIR || jrec == NGJ_UNREAD) {
			v->damaged = 1;
			snprintf(v->why, sizeof(v->why), "%s", *why_ro);
			*why_ro = v->why;
		}
		if (*why_ro) {
			/* Read-only from here on: nothing is written, the journal (if any) is only shown. */
			kfree(v->jv);
			v->jv = NULL;
		} else if (pass == NGC_PASS_CHECK && need_write) {
			if (fc->ops->free)
				fc->ops->free(fc);
			kfree(fc);
			ngc_umount(v, 0);
			return NGC_NEED_WRITE_PASS;
		}
		if (!*why_ro) {
			struct fs_context *rc = kzalloc(sizeof(*rc), GFP_KERNEL);
			if (!rc) {
				*why_ro = "out of memory";
			} else {
				rc->ops = fc->ops;
				rc->fs_type = fc->fs_type;
				rc->root = v->sb->s_root;
				rc->purpose = FS_CONTEXT_FOR_RECONFIGURE;
				rc->sb_flags = 0;
				b->kshim_remounting = 1;
				err = fc->ops->reconfigure(rc);
				b->kshim_remounting = 0;
				kfree(rc);
				if (err)
					*why_ro = "the core refused to remount read-write";
				else
					v->sb->s_flags &= ~SB_RDONLY;
			}
		}
	}
	if (!sb_rdonly(v->sb) && v->jv) {
		/* The core's own mount-time writes ($LogFile emptied) go in place before the journal starts. */
		int jerr = kshim_sync(v->sb);
		if (!jerr)
			jerr = blkdev_issue_flush(b);
		if (vol->logfile_ino)
			truncate_inode_pages(vol->logfile_ino->i_mapping, 0);
		if (!jerr)
			jerr = kshim_jnl_activate(b, v->jv->ext, v->jv->next, v->jv->lf_pages, v->jv->serial, jseq + 1,
						  v->jv->mft_lcn * v->jv->cluster + 3 * v->jv->recsz);
		if (jerr) {
			printk(KERN_ERR "journal: not active (%d); metadata goes in place\n", jerr);
		} else if (!kshim_watch_add(&vol->free_clusters)) {
			v->watched = &vol->free_clusters;
			kshim_jnl_set_aux(b, kshim_watch_count(v->watched));
		}
	}
	/*
	 * Once mounted, an error fails the operation and leaves the volume writable, as on Windows:
	 * with remount-ro, running out of space while growing the MFT made the system volume
	 * read-only.  Errors that mean corruption set NVolErrors, which keeps the dirty flag and
	 * makes the journal header demand a repair.
	 */
	if (!sb_rdonly(v->sb))
		vol->on_errors = ngc_on_errors("continue");
	if (!sb_rdonly(v->sb)) {
		v->bounce = kmalloc(NGC_BOUNCE, GFP_KERNEL);
		if (!v->bounce) {
			v->sb->s_flags |= SB_RDONLY;
			*why_ro = "out of memory";
		}
	}
	if (fc->ops->free)
		fc->ops->free(fc);
	kfree(fc);
	/* MFT records are read for every lookup and listing: keep up to 16 MB of them cached (less on small machines). */
	NTFS_SB(v->sb)->mft_ino->i_mapping->kshim_pc_max = min_t(unsigned long, 4096, kshim_pc_soft_limit() / 2);
	*out = v;
	return 0;
fail_fc:
	if (fc->ops && fc->ops->free)
		fc->ops->free(fc);
fail:
	kfree(fc);
	kshim_bdev_close(b);
	if (v)
		kfree(v->jv);
	kfree(v);
	return err;
}

int ngc_mount(void *osdev, unsigned long long size, unsigned int sector_size, int want_rw,
		ngc_vol **out, const char **why_ro)
{
	int err, was_dirty = 0;
	if (!want_rw)
		return ngc_mount_pass(osdev, size, sector_size, NGC_PASS_RO, out, why_ro, &was_dirty);
	err = ngc_mount_pass(osdev, size, sector_size, NGC_PASS_CHECK, out, why_ro, &was_dirty);
	if (err != NGC_NEED_WRITE_PASS)
		return err;
	err = ngc_mount_pass(osdev, size, sector_size, NGC_PASS_WRITE, out, why_ro, &was_dirty);
	/*
	 * A real dirty flag the disk carried (see ngc_mount_pass) is a request for autochk, as on Windows: the checks
	 * above found nothing wrong and the volume goes read-write for the system to boot, but the flag stays (set again
	 * here, after the replay) until a check (autochk, chkdsk /f) clears it.  A crash before it is set again loses
	 * only that request.
	 */
	if (!err && was_dirty && *out && !sb_rdonly((*out)->sb)) {
		int e = ngc_mark_volume_dirty(*out);
		if (e)
			printk(KERN_ERR "could not keep the dirty flag (%d): the mount-time check settled it\n", e);
		else
			printk(KERN_WARNING "dirty flag kept for autochk (it did not come from this driver's own session)\n");
	}
	return err;
}

void ngc_umount(ngc_vol *v, int discard)
{
	struct super_block *sb = v->sb;
	unsigned long wr_failed;
	int errors, clean;
	/* The glue waited for its unlocked writes to end (ngc_dio_end) before the teardown; none starts now. */
	kshim_dio_drain(v->bdev);
	v->bdev->kshim_drain = NULL;
	v->bdev->kshim_kick = NULL;
	if (discard) {
		/* Pending journal pages are dropped and the core sees a read-only volume: put_super writes nothing. */
		kshim_jnl_deactivate(v->bdev);
		sb->s_flags |= SB_RDONLY;
	}
	kshim_icache_flush(sb, 1);
	if (sb->s_root) {
		iput(sb->s_root->d_inode);
		kfree(sb->s_root);
		sb->s_root = NULL;
	}
	/* put_super frees the volume: read its error state first. It clears the dirty flag of a
	 * read-write volume without errors; a read-only volume keeps the flag it had. */
	errors = NVolErrors(NTFS_SB(sb)) || v->failed;
	clean = !errors && !NTFS_SB(sb)->keep_dirty && (!sb_rdonly(sb) || !(NTFS_SB(sb)->vol_flags & VOLUME_IS_DIRTY));
	wr_failed = v->bdev->kshim_wr_failed;
	if (sb->s_op->put_super)
		sb->s_op->put_super(sb);
	/*
	 * put_super drops the results of its writes (and a synchronous bio's error is not latched): a write
	 * that failed in it, or an asynchronous one before it, is missing from the overlay: commit nothing.
	 */
	if (v->bdev->kshim_wb_err || v->bdev->kshim_wr_failed != wr_failed)
		errors = 1;
	if (v->bdev->jnl && !errors && kshim_jnl_commit(v->bdev, 0) >= 0 && clean)
		kshim_jnl_retire(v->bdev);
	if (v->watched)
		kshim_watch_del(v->watched);
	ngc_stc_free(v);
	ngc_sdc_flush(v);
	kfree(v->jv);
	kfree(v->bounce);
	kfree(sb);
	kshim_bdev_close(v->bdev);
	kfree(v);
}

/*
 * A $VOLUME_NAME the label code reads and resizes: resident, unnamed, no flags, and its value after
 * the resident header (the core's own check bounds the value by the record only; a value at offset 0
 * would make a resize move the next attribute over the header it writes).
 */
static bool ngc_label_attr_ok(const struct attr_record *a)
{
	return !a->non_resident && !a->flags && !a->name_length &&
	       le16_to_cpu(a->data.resident.value_offset) >=
	       offsetof(struct attr_record, data.resident.reserved) + sizeof(a->data.resident.reserved);
}

/*
 * Reads $Volume's $VOLUME_NAME as stored (raw UTF-16, so any label Windows writes, unpaired
 * surrogates and NULs included, reads back the same).  A label longer than NGC_LABEL_MAX units,
 * which Windows does not write, is cut there.  The result is kept, unless memory ran out, in
 * which case the next call reads again.
 */
static void ngc_load_label(struct ngc_vol *v)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct ntfs_inode *ni = NTFS_I(vol->vol_ino);
	struct ntfs_attr_search_ctx *ctx;
	int err;

	if (v->label_read)
		return;
	mutex_lock(&ni->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	err = ctx ? ntfs_attr_lookup(AT_VOLUME_NAME, NULL, 0, 0, 0, NULL, 0, ctx) : -ENOMEM;
	v->label_len = 0;
	if (!err && ngc_label_attr_ok(ctx->attr)) {
		u32 n = min_t(u32, le32_to_cpu(ctx->attr->data.resident.value_length) / sizeof(__le16), NGC_LABEL_MAX);
		memcpy(v->label, (u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset), n * sizeof(__le16));
		v->label_len = n;
	}
	v->label_read = err != -ENOMEM;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	mutex_unlock(&ni->mrec_lock);
}

void ngc_volinfo(ngc_vol *v, struct ngc_volinfo *vi)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	s64 fc = atomic64_read(&vol->free_clusters);
	memset(vi, 0, sizeof(*vi));
	vi->total_clusters = vol->nr_clusters;
	vi->free_clusters = fc > 0 ? fc : 0;
	vi->serial = vol->serial_no;
	vi->cluster_size = vol->cluster_size;
	vi->sector_size = vol->sector_size;
	vi->major = vol->major_ver;
	vi->minor = vol->minor_ver;
	vi->read_only = sb_rdonly(v->sb) ? 1 : 0;
	/* What FSCTL_IS_VOLUME_DIRTY says: the flag is on disk while a session has changes in flight (the mounted marker), which is not "dirty". */
	vi->dirty = ((vol->vol_flags & VOLUME_IS_DIRTY) && (vol->keep_dirty || sb_rdonly(v->sb))) || v->damaged || NVolErrors(vol) ? 1 : 0;
	vi->damaged = v->damaged ? 1 : 0;
	ngc_load_label(v);
	memcpy(vi->label, v->label, v->label_len * sizeof(v->label[0]));
	vi->label_len = v->label_len;
	vi->label_valid = v->label_read ? 1 : 0;
}

ngc_node *ngc_root(ngc_vol *v)
{
	return (ngc_node *)igrab(d_inode(v->sb->s_root));
}

/* A dentry for @name (UTF-16) in the shape the core's inode operations expect; @inode may be NULL. */
static struct dentry *ngc_mkdentry(ngc_vol *v, const unsigned short *name, unsigned int len, struct inode *inode)
{
	struct dentry *d;
	u8 *u8name;
	int n;
	if (!len || len > NTFS_MAX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);
	u8name = kmalloc(len * 4 + 1, GFP_NOFS);
	d = kzalloc(sizeof(*d), GFP_NOFS);
	if (!u8name || !d) {
		kfree(u8name);
		kfree(d);
		return ERR_PTR(-ENOMEM);
	}
	n = utf16s_to_utf8s(name, len, UTF16_LITTLE_ENDIAN, u8name, len * 4);
	u8name[n > 0 ? n : 0] = 0;
	d->d_name.name = u8name;
	d->d_name.len = n > 0 ? n : 0;
	d->d_sb = v->sb;
	d->d_parent = d;
	d->d_inode = inode;
	return d;
}

static void ngc_freedentry(struct dentry *d)
{
	if (IS_ERR_OR_NULL(d))
		return;
	kfree(d->d_name.name);
	kfree(d->kshim_ci_name);
	kfree(d);
}

/*
 * The core ORs a reparse point's symlink type into the mode it loaded from a $LXMOD EA, so a
 * junction the core created as a directory loads as S_IFLNK|S_IFDIR: make it the symlink it means.
 */
static void ngc_fix_type(struct inode *vi)
{
	if ((vi->i_mode & S_IFMT) != (S_IFLNK | S_IFDIR))
		return;
	vi->i_mode = (vi->i_mode & ~S_IFMT) | S_IFLNK;
	ntfs_set_vfs_operations(vi, vi->i_mode, 0);
}

static int ngc_lookup_impl(ngc_vol *v, ngc_node *dirn, const unsigned short *name, unsigned int len, ngc_node **out,
		unsigned short *real, unsigned int *real_len)
{
	struct inode *dir = (struct inode *)dirn, *vi;
	struct dentry *d, *r;

	*out = NULL;
	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;
	d = ngc_mkdentry(v, name, len, NULL);
	if (IS_ERR(d))
		return PTR_ERR(d);
	r = dir->i_op->lookup(dir, d, 0);
	if (IS_ERR(r)) {
		ngc_freedentry(d);
		return PTR_ERR(r);
	}
	vi = r ? r->d_inode : d->d_inode;
	if (vi && real && real_len) {
		/* The name as stored: the case-folded match, or exactly what was asked. */
		if (d->kshim_ci_name) {
			int n = utf8s_to_utf16s(d->kshim_ci_name, d->kshim_ci_len, UTF16_LITTLE_ENDIAN,
					real, NTFS_MAX_NAME_LEN);
			*real_len = n > 0 ? n : 0;
		} else {
			memcpy(real, name, len * sizeof(*real));
			*real_len = len;
		}
	}
	ngc_freedentry(d);
	if (!vi)
		return -ENOENT;
	ngc_fix_type(vi);
	*out = (ngc_node *)vi;
	return 0;
}

int ngc_open_stream(ngc_vol *v, ngc_node *basen, const unsigned short *sname, unsigned int len, ngc_node **out)
{
	struct inode *base = (struct inode *)basen, *vi;
	__le16 *uname;
	(void)v;
	*out = NULL;
	if (len > NTFS_MAX_NAME_LEN)
		return -ENAMETOOLONG;
	uname = kmalloc((len + 1) * sizeof(__le16), GFP_NOFS);
	if (!uname)
		return -ENOMEM;
	memcpy(uname, sname, len * sizeof(__le16));
	uname[len] = 0;
	vi = ntfs_attr_iget(base, AT_DATA, uname, len);
	if (IS_ERR(vi) && PTR_ERR(vi) == -ENOENT) {
		/* NT stream names compare without case: look for the stored spelling. */
		struct ntfs_inode *ni = NTFS_I(base);
		struct ntfs_volume *vol = ni->vol;
		struct ntfs_attr_search_ctx *ctx;
		bool found = false;
		mutex_lock(&ni->mrec_lock);
		ctx = ntfs_attr_get_search_ctx(ni, NULL);
		while (ctx && !ntfs_attr_lookup(AT_DATA, NULL, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
			struct attr_record *a = ctx->attr;
			if (a->name_length == len &&
			    ntfs_are_names_equal((__le16 *)((u8 *)a + le16_to_cpu(a->name_offset)), len, uname, len,
						 IGNORE_CASE, vol->upcase, vol->upcase_len)) {
				memcpy(uname, (u8 *)a + le16_to_cpu(a->name_offset), len * sizeof(__le16));
				found = true;
				break;
			}
		}
		if (ctx)
			ntfs_attr_put_search_ctx(ctx);
		mutex_unlock(&ni->mrec_lock);
		if (found)
			vi = ntfs_attr_iget(base, AT_DATA, uname, len);
	}
	kfree(uname);
	if (IS_ERR(vi))
		return PTR_ERR(vi);
	*out = (ngc_node *)vi;
	return 0;
}

/* Adds an empty named $DATA stream to @basen and opens it. */
int ngc_create_stream(ngc_vol *v, ngc_node *basen, const unsigned short *sname, unsigned int len, ngc_node **out)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)basen);
	__le16 *uname;
	int err;
	*out = NULL;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (NInoAttr(ni) || !len || len > NTFS_MAX_NAME_LEN)
		return -EINVAL;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	uname = kmalloc((len + 1) * sizeof(__le16), GFP_NOFS);
	if (!uname)
		return -ENOMEM;
	memcpy(uname, sname, len * sizeof(__le16));
	uname[len] = 0;
	mutex_lock(&ni->mrec_lock);
	err = ntfs_attr_add(ni, AT_DATA, uname, len, NULL, 0);
	mutex_unlock(&ni->mrec_lock);
	kfree(uname);
	if (err)
		return err;
	mark_inode_dirty(VFS_I(ni));
	return ngc_open_stream(v, basen, sname, len, out);
}

/* Removes the named stream @n (an open stream node) from its file. */
int ngc_delete_stream(ngc_vol *v, ngc_node *n)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n), *base;
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (!NInoAttr(ni) || ni->type != AT_DATA || !ni->name_len)
		return -EINVAL;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	base = ni->ext.base_ntfs_ino;
	mutex_lock(&base->mrec_lock);
	err = ntfs_attr_rm(ni);
	mutex_unlock(&base->mrec_lock);
	if (!err)
		mark_inode_dirty(VFS_I(base));
	return err;
}

static int ngc_iget_impl(ngc_vol *v, unsigned long long mft_no, ngc_node **out)
{
	struct inode *vi = ntfs_iget(v->sb, mft_no);
	*out = NULL;
	if (IS_ERR(vi))
		return PTR_ERR(vi);
	ngc_fix_type(vi);
	*out = (ngc_node *)vi;
	return 0;
}

/*
 * An MFT number that comes from a caller (open by file ID): loaded only if it names an in-use base
 * record.  The core treats a record it cannot load (an extension record, a number past the end of
 * $MFT, a free record) as damage and records an error for the volume, which a caller must not be able
 * to cause.
 */
static int ngc_iget_by_id_impl(ngc_vol *v, unsigned long long mft_no, ngc_node **out)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	u32 rs = vol->mft_record_size;
	u64 off = mft_no << vol->mft_record_size_bits;
	struct ntfs_attr na = { .mft_no = mft_no, .type = AT_UNUSED };
	struct inode *vi;
	struct folio *f;
	struct mft_record *m;
	u8 *rec;
	int err = 0;
	*out = NULL;
	/* A cached inode's record is newer than $MFT's page cache, which gets it only at writeback. */
	vi = ilookup5(v->sb, mft_no, ntfs_test_inode, &na);
	if (vi) {
		if (!vi->i_nlink) {
			iput(vi);
			return -ENOENT;
		}
		ngc_fix_type(vi);
		*out = (ngc_node *)vi;
		return 0;
	}
	if (rs > PAGE_SIZE || mft_no >= (u64)(i_size_read(vol->mft_ino) >> vol->mft_record_size_bits))
		return -ENOENT;
	rec = kmalloc(rs, GFP_NOFS);
	if (!rec)
		return -ENOMEM;
	f = read_mapping_folio(vol->mft_ino->i_mapping, (pgoff_t)(off >> PAGE_SHIFT), NULL);
	if (IS_ERR(f)) {
		kfree(rec);
		return PTR_ERR(f);
	}
	memcpy(rec, (u8 *)folio_address(f) + (off & (PAGE_SIZE - 1)), rs);
	folio_put(f);
	m = (struct mft_record *)rec;
	/* No links: the reserved records 12-15 are in use without being files. */
	if (m->magic != magic_FILE || post_read_mst_fixup((struct ntfs_record *)rec, rs) ||
	    !(m->flags & MFT_RECORD_IN_USE) || m->base_mft_record || !m->link_count)
		err = -ENOENT;
	kfree(rec);
	return err ? err : ngc_iget_impl(v, mft_no, out);
}

static void ngc_put_impl(ngc_node *n)
{
	iput((struct inode *)n);
}

/* A junction loads as a symlink inode: its MFT record still says whether it is a directory. */
static int ngc_record_is_dir_locked(struct ntfs_inode *ni)
{
	struct mft_record *m = map_mft_record(ni);
	int dir = 0;
	if (!IS_ERR(m)) {
		dir = !!(m->flags & MFT_RECORD_IS_DIRECTORY);
		unmap_mft_record(ni);
	}
	return dir;
}

static int ngc_record_is_dir(struct ntfs_inode *ni)
{
	int dir;
	mutex_lock(&ni->mrec_lock);
	dir = ngc_record_is_dir_locked(ni);
	mutex_unlock(&ni->mrec_lock);
	return dir;
}

/* A plain non-resident data stream: the only kind that preallocates (sparse, compressed and encrypted ones have their own rules). */
static bool ngc_plain_nonresident(struct ntfs_inode *ni)
{
	return NInoNonResident(ni) && ni->type == AT_DATA && !NInoSparse(ni) && !NInoCompressed(ni) &&
	       !NInoEncrypted(ni) && !NInoWofCompressed(ni) && !NInoAttr(ni) && ni->mft_no >= FILE_first_user;
}

/* The allocation NT sees follows the file size: clusters allocated ahead of it (ngc_prealloc_target) are not shown. */
static u64 ngc_visible_alloc(struct ntfs_inode *ni, loff_t size)
{
	u64 need = round_up((u64)size, ni->vol->cluster_size);
	return NInoNgAhead(ni) && (u64)ni->allocated_size > need ? need : (u64)ni->allocated_size;
}

static void ngc_stat_impl(ngc_node *n, struct ngc_stat *st)
{
	struct inode *vi = (struct inode *)n, *bvi = vi;
	struct ntfs_inode *ni = NTFS_I(vi), *bni = ni;
	unsigned long flags;

	if (NInoAttr(ni)) {
		bni = ni->ext.base_ntfs_ino;
		bvi = VFS_I(bni);
	}
	memset(st, 0, sizeof(*st));
	st->mft_ref = bni->mft_no | ((u64)bni->seq_no << 48);
	read_lock_irqsave(&ni->size_lock, flags);
	st->size = i_size_read(vi);
	if (NInoNonResident(ni)) {
		if (NInoCompressed(ni) || NInoSparse(ni))
			st->alloc = ni->itype.compressed.size;
		else
			st->alloc = ngc_visible_alloc(ni, st->size);
	} else {
		st->alloc = (st->size + 7) & ~7ULL;
	}
	read_unlock_irqrestore(&ni->size_lock, flags);
	st->crtime = ts_to_nt(bni->i_crtime);
	st->atime = ts_to_nt(inode_get_atime(bvi));
	st->mtime = ts_to_nt(inode_get_mtime(bvi));
	st->ctime = ts_to_nt(inode_get_ctime(bvi));
	st->file_attributes = le32_to_cpu(bni->flags) & 0xffff;
	st->nlink = bvi->i_nlink > 1 ? ngc_links((ngc_node *)bvi) : bvi->i_nlink;
	st->is_dir = S_ISDIR(bvi->i_mode) && vi == bvi;
	st->is_link = S_ISLNK(bvi->i_mode);
	if (st->is_link && vi == bvi)
		st->is_dir = ngc_record_is_dir(bni);
	if (NInoCompressed(ni)) st->flags |= NGC_ATTR_COMPRESSED;
	if (NInoSparse(ni)) st->flags |= NGC_ATTR_SPARSE;
	if (NInoEncrypted(ni)) st->flags |= NGC_ATTR_ENCRYPTED;
	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni) || NInoSparse(ni))
		st->flags |= NGC_ATTR_NOWRITE;
}

struct ngc_dirctx {
	struct dir_context ctx;
	ngc_filldir_t fn;
	void *arg;
	u16 *buf;
	int stop, n;
};

static bool ngc_actor(struct dir_context *c, const char *name, int len, loff_t pos, u64 ino, unsigned type)
{
	struct ngc_dirctx *d = container_of(c, struct ngc_dirctx, ctx);
	int ulen = utf8s_to_utf16s((const u8 *)name, len, UTF16_LITTLE_ENDIAN, d->buf, NTFS_MAX_NAME_LEN + 2);
	(void)pos;
	d->n++;
	if (ulen <= 0)
		return true;
	if (d->fn(d->arg, d->buf, ulen, ino, type)) {
		d->stop = 1;
		return false;
	}
	return true;
}

static int ngc_readdir_impl(ngc_vol *v, ngc_node *dirn, ngc_filldir_t fn, void *arg)
{
	struct inode *dir = (struct inode *)dirn;
	struct file *f;
	struct ngc_dirctx *d;
	int err = 0;
	(void)v;

	/* A junction directory (loaded as a symlink) lists as empty. */
	if (S_ISLNK(dir->i_mode) && ngc_record_is_dir(NTFS_I(dir)))
		return 0;
	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;
	f = kzalloc(sizeof(*f), GFP_NOFS);
	d = kzalloc(sizeof(*d), GFP_NOFS);
	if (!f || !d || !(d->buf = kmalloc((NTFS_MAX_NAME_LEN + 2) * sizeof(u16), GFP_NOFS))) {
		if (d) kfree(d->buf);
		kfree(d);
		kfree(f);
		return -ENOMEM;
	}
	f->f_inode = dir;
	f->f_mapping = dir->i_mapping;
	f->f_mode = FMODE_READ;
	d->ctx.actor = ngc_actor;
	d->fn = fn;
	d->arg = arg;
	if (dir->i_fop->open && (err = dir->i_fop->open(dir, f)))
		goto out;
	/* Drive iterate_shared the way getdents() does, until it makes no progress. */
	for (;;) {
		loff_t before = d->ctx.pos;
		int n = d->n;
		err = dir->i_fop->iterate_shared(f, &d->ctx);
		if (err || d->stop || (d->ctx.pos == before && d->n == n))
			break;
	}
	if (dir->i_fop->release)
		dir->i_fop->release(dir, f);
out:
	kfree(d->buf);
	kfree(d);
	kfree(f);
	return err;
}

/*
 * A directory listing in one pass over the $I30 index: the names, the 8.3 names (the DOS
 * entries, paired by file reference) and the values the entries duplicate, which serve only
 * when an inode cannot be read.  Same entries as ngc_readdir, in index order.
 */
/*
 * ngc_stat of an in-memory inode without the record lock, for listings (the caller holds the
 * inode-cache lock): false for what needs the record (a reparse point's tag, a junction's
 * directory bit).  The link count is not filled.
 */
static bool ngc_stat_lite(struct inode *vi, struct ngc_stat *st)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	unsigned long flags;
	if (NInoAttr(ni) || S_ISLNK(vi->i_mode) || (ni->flags & FILE_ATTR_REPARSE_POINT))
		return false;
	st->mft_ref = ni->mft_no | ((u64)ni->seq_no << 48);
	read_lock_irqsave(&ni->size_lock, flags);
	st->size = i_size_read(vi);
	if (NInoNonResident(ni))
		st->alloc = (NInoCompressed(ni) || NInoSparse(ni)) ? ni->itype.compressed.size : ngc_visible_alloc(ni, st->size);
	else
		st->alloc = (st->size + 7) & ~7ULL;
	read_unlock_irqrestore(&ni->size_lock, flags);
	st->crtime = ts_to_nt(ni->i_crtime);
	st->atime = ts_to_nt(inode_get_atime(vi));
	st->mtime = ts_to_nt(inode_get_mtime(vi));
	st->ctime = ts_to_nt(inode_get_ctime(vi));
	st->file_attributes = le32_to_cpu(ni->flags) & 0xffff;
	st->nlink = 1;
	st->is_dir = S_ISDIR(vi->i_mode);
	if (NInoCompressed(ni)) st->flags |= NGC_ATTR_COMPRESSED;
	if (NInoSparse(ni)) st->flags |= NGC_ATTR_SPARSE;
	if (NInoEncrypted(ni)) st->flags |= NGC_ATTR_ENCRYPTED;
	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni) || NInoSparse(ni))
		st->flags |= NGC_ATTR_NOWRITE;
	return true;
}

/* The compact stat cache (struct ngc_vol): slots by record number, a power of two between 16384 and 65536 by memory size. */
static struct ngc_stat *ngc_stc_slot(struct ngc_vol *v, u64 mft_no)
{
	return v->stc ? &v->stc[mft_no & v->stc_mask] : NULL;
}

/* Inode-cache lock held; the inode was taken off the unused list and nothing references it. */
static void ngc_stc_evicting(struct inode *i)
{
	struct ngc_vol *v = i->i_sb->kshim_priv;
	struct ntfs_inode *ni = NTFS_I(i);
	struct ngc_stat *slot;
	struct ngc_stat st;
	if (!v || NInoAttr(ni) || ni->mft_no < FILE_first_user || (i->i_state & I_DIRTY))
		return;
	if (!v->stc) {
		unsigned long n = ngos_physical_pages() / 8;
		n = n > 65536 ? 65536 : n < 16384 ? 16384 : n;
		n = 1UL << ilog2(n);
		v->stc = kvzalloc(n * sizeof(*v->stc), GFP_NOFS);
		if (!v->stc)
			return;
		v->stc_mask = n - 1;
	}
	memset(&st, 0, sizeof(st));
	if (!ngc_stat_lite(i, &st))
		return;
	slot = ngc_stc_slot(v, ni->mft_no);
	*slot = st;
	v->stc_stores++;
}

/* Inode-cache lock held; the number is the one the inode is hashed by (the record number, also of an attribute inode). */
static void ngc_stc_added(struct inode *i)
{
	struct ngc_vol *v = i->i_sb->kshim_priv;
	struct ngc_stat *slot;
	u64 no = (u64)(uintptr_t)i->kshim_test_data;
	if (!v || !v->stc)
		return;
	slot = ngc_stc_slot(v, no);
	if ((slot->mft_ref & 0xffffffffffffULL) == no)
		slot->mft_ref = 0;
}

/* Inode-cache lock held: the kept stat of the file of an index entry (record number and sequence number as in @mref), or false. */
static bool ngc_stc_lookup(struct ngc_vol *v, u64 mref, struct ngc_stat *st)
{
	struct ngc_stat *slot = ngc_stc_slot(v, mref & 0xffffffffffffULL);
	if (!slot || slot->mft_ref != mref)
		return false;
	*st = *slot;
	v->stc_hits++;
	return true;
}

static void ngc_stc_free(struct ngc_vol *v)
{
	struct ngc_stat *t;
	kshim_icache_lock();
	t = v->stc;
	v->stc = NULL;
	v->sb->kshim_priv = NULL;
	kshim_icache_unlock();
	kvfree(t);
}

struct ngc_rawent {
	u64 mref;
	u32 name_off, attrs, tag, dos;
	u8 name_len, name_type;
	s64 times[4];
	u64 size, alloc;
};

static int ngc_dirwalk(struct ntfs_inode *ndir, struct ngc_rawent **out, u16 **names, int *count)
{
	struct ntfs_volume *vol = ndir->vol;
	struct ntfs_index_context *ictx;
	struct ntfs_attr_search_ctx *ctx;
	struct index_root *ir;
	struct index_entry *ie;
	struct ngc_rawent *v = NULL;
	u16 *nb = NULL;
	int n = 0, cap = 0, ncap = 0, nused = 0, err = 0;

	mutex_lock_nested(&ndir->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	ictx = ntfs_index_ctx_get(ndir, I30, 4);
	ctx = ictx ? ntfs_attr_get_search_ctx(ndir, NULL) : NULL;
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}
	if (ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		ntfs_attr_put_search_ctx(ctx);
		err = -EIO;
		goto out;
	}
	ir = (struct index_root *)((u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset));
	ictx->ir = ir;
	ictx->actx = ctx;
	ictx->parent_vcn[ictx->pindex] = VCN_INDEX_ROOT_PARENT;
	ictx->is_in_root = true;
	ictx->parent_pos[ictx->pindex] = 0;
	ictx->block_size = le32_to_cpu(ir->index_block_size);
	if (ictx->block_size < NTFS_BLOCK_SIZE) {
		err = -EIO;
		goto out;
	}
	ictx->vcn_size_bits = vol->cluster_size <= ictx->block_size ? vol->cluster_size_bits : NTFS_BLOCK_SIZE_BITS;
	ictx->cr = ir->collation_rule;
	ie = (struct index_entry *)((u8 *)&ir->index + le32_to_cpu(ir->index.entries_offset));
	if (ie->flags & INDEX_ENTRY_NODE) {
		ictx->ia_ni = ntfs_ia_open(ictx, ictx->idx_ni);
		if (!ictx->ia_ni) {
			err = -EINVAL;
			goto out;
		}
		ie = ntfs_index_walk_down(ie, ictx);
		if (IS_ERR(ie)) {
			err = PTR_ERR(ie);
			goto out;
		}
	}
	if (ie && (ie->flags & INDEX_ENTRY_END))
		ie = ntfs_index_next(ie, ictx);
	while (ie && !IS_ERR(ie)) {
		struct file_name_attr *fn = &ie->key.file_name;
		struct ngc_rawent *r;
		if (n == cap) {
			void *p = krealloc(v, (cap = cap ? cap * 2 : 64) * sizeof(*v), GFP_NOFS);
			if (!p) {
				err = -ENOMEM;
				goto out;
			}
			v = p;
		}
		if (nused + fn->file_name_length > ncap) {
			void *p;
			ncap = max(ncap * 2, nused + 256 + fn->file_name_length);
			p = krealloc(nb, ncap * sizeof(u16), GFP_NOFS);
			if (!p) {
				err = -ENOMEM;
				goto out;
			}
			nb = p;
		}
		r = &v[n++];
		r->mref = le64_to_cpu(ie->data.dir.indexed_file);
		r->name_off = nused;
		r->name_len = fn->file_name_length;
		r->name_type = fn->file_name_type;
		r->attrs = le32_to_cpu(fn->file_attributes);
		r->tag = (r->attrs & FILE_ATTR_REPARSE_POINT) ? le32_to_cpu(fn->type.rp.reparse_point_tag) : 0;
		r->times[0] = le64_to_cpu(fn->creation_time);
		r->times[1] = le64_to_cpu(fn->last_access_time);
		r->times[2] = le64_to_cpu(fn->last_data_change_time);
		r->times[3] = le64_to_cpu(fn->last_mft_change_time);
		r->size = le64_to_cpu(fn->data_size);
		r->alloc = le64_to_cpu(fn->allocated_size);
		r->dos = 0;
		memcpy(nb + nused, fn->file_name, fn->file_name_length * sizeof(u16));
		nused += fn->file_name_length;
		ie = ntfs_index_next(ie, ictx);
	}
	if (IS_ERR(ie))
		err = PTR_ERR(ie);
out:
	if (ictx)
		ntfs_index_ctx_put(ictx);
	mutex_unlock(&ndir->mrec_lock);
	if (err) {
		kfree(v);
		kfree(nb);
		return err;
	}
	*out = v;
	*names = nb;
	*count = n;
	return 0;
}

static int ngc_readdir_full_impl(ngc_vol *v, ngc_node *dirn, ngc_dirent_t fn, void *arg)
{
	struct inode *dir = (struct inode *)dirn;
	struct ntfs_inode *ndir = NTFS_I(dir);
	struct ntfs_volume *vol = ndir->vol;
	struct ngc_rawent *r = NULL;
	struct ngc_dirent e;
	u16 *names = NULL, dot[2] = { '.', '.' };
	unsigned long long t0;
	int n = 0, err, k, j;

	if (S_ISLNK(dir->i_mode) && ngc_record_is_dir(ndir))
		return 0;
	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;
	t0 = ngos_ticks();
	err = ngc_dirwalk(ndir, &r, &names, &n);
	ngos_prof(NGP_DIRWALK, t0, (unsigned long long)n);
	if (err)
		return err;
	/* An 8.3 name is a DOS-namespace entry for the same file as a Win32 entry: pair them by reference. */
	{
		unsigned int hs = 64, *h;
		while (hs < 2 * (unsigned int)n)
			hs <<= 1;
		h = kcalloc(hs, sizeof(*h), GFP_NOFS);
		for (k = 0; h && k < n; k++) {
			if (r[k].name_type != FILE_NAME_WIN32)
				continue;
			for (j = (int)(r[k].mref % hs); h[j]; j = (j + 1) & (hs - 1))
				;
			h[j] = k + 1;
		}
		for (k = 0; k < n; k++) {
			if (r[k].name_type != FILE_NAME_DOS)
				continue;
			if (h) {
				for (j = (int)(r[k].mref % hs); h[j]; j = (j + 1) & (hs - 1))
					if (r[h[j] - 1].mref == r[k].mref && !r[h[j] - 1].dos) {
						r[h[j] - 1].dos = k + 1;
						break;
					}
			} else {
				for (j = 0; j < n; j++)
					if (r[j].mref == r[k].mref && r[j].name_type == FILE_NAME_WIN32 && !r[j].dos) {
						r[j].dos = k + 1;
						break;
					}
			}
		}
		kfree(h);
	}
	memset(&e, 0, sizeof(e));
	e.is_dot = 1;
	for (k = 1; k <= 2; k++) {
		e.name = dot;
		e.len = k;
		if (fn(arg, &e))
			goto done;
	}
	/*
	 * Times, sizes and attributes come from the inode.  The index entries duplicate them, but the core
	 * copies the times into them from the $FILE_NAME attribute, which keeps the values of the file's
	 * creation.  An inode in memory is read under the inode-cache lock without a reference (it cannot
	 * be freed while the lock is held); any other inode is loaded.
	 */
	for (k = 0; k < n; k++) {
		struct ngc_rawent *x = &r[k];
		struct ntfs_attr na;
		struct inode *child;
		ngc_node *cn;
		bool done;
		if (x->name_type == FILE_NAME_DOS || MREF(x->mref) == FILE_root)
			continue;
		if (MREF(x->mref) < FILE_first_user && !NVolShowSystemFiles(vol))
			continue;
		if (!NVolShowHiddenFiles(vol) && (x->attrs & le32_to_cpu(FILE_ATTR_HIDDEN)))
			continue;
		memset(&e, 0, sizeof(e));
		e.name = names + x->name_off;
		e.len = x->name_len;
		if (x->dos) {
			struct ngc_rawent *d = &r[x->dos - 1];
			e.short_len = min_t(unsigned int, d->name_len, 12);
			memcpy(e.short_name, names + d->name_off, e.short_len * sizeof(u16));
		}
		na.mft_no = MREF(x->mref);
		na.type = AT_UNUSED;
		na.name = NULL;
		na.name_len = 0;
		kshim_icache_lock();
		child = kshim_icache_peek(dir->i_sb, na.mft_no, ntfs_test_inode, &na);
		done = child ? ngc_stat_lite(child, &e.st) : ngc_stc_lookup(v, x->mref, &e.st);
		kshim_icache_unlock();
		if (!done && !ngc_iget(v, na.mft_no, &cn)) {
			ngc_stat(cn, &e.st);
			if (e.st.file_attributes & 0x400) {
				void *data;
				unsigned int len;
				if (!ngc_get_reparse(cn, &data, &len)) {
					if (len >= 4)
						e.reparse_tag = *(u32 *)data;
					kfree(data);
				}
			}
			ngc_put(cn);
			done = true;
		}
		if (!done) {
			/* An unreadable inode: what its index entry says. */
			e.st.mft_ref = x->mref;
			e.st.crtime = x->times[0];
			e.st.atime = x->times[1];
			e.st.mtime = x->times[2];
			e.st.ctime = x->times[3];
			e.st.size = x->size;
			e.st.alloc = x->alloc;
			e.st.file_attributes = x->attrs & 0xffff;
			e.st.nlink = 1;
			e.st.is_dir = (x->attrs & le32_to_cpu(FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT)) != 0;
			e.st.is_link = (x->attrs & le32_to_cpu(FILE_ATTR_REPARSE_POINT)) != 0;
			e.reparse_tag = x->tag;
		}
		if (fn(arg, &e))
			break;
	}
done:
	kfree(r);
	kfree(names);
	return 0;
}

int ngc_streams(ngc_node *n, ngc_stream_t fn, void *arg)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_attr_search_ctx *ctx;
	struct mft_record *m;
	int err = 0;

	/* A handle to one stream lists the streams of its file, as on Windows. */
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	m = map_mft_record(ni);
	if (IS_ERR(m))
		return PTR_ERR(m);
	ctx = ntfs_attr_get_search_ctx(ni, m);
	if (!ctx) {
		unmap_mft_record(ni);
		return -ENOMEM;
	}
	/* NULL name means "unnamed" in this driver, so walk all attributes (as file.c does). */
	while (!ntfs_attr_lookup(AT_UNUSED, NULL, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		struct attr_record *a = ctx->attr;
		u64 size, alloc;
		if (a->type != AT_DATA)
			continue;
		if (a->non_resident && a->data.non_resident.lowest_vcn)
			continue;
		if (a->non_resident) {
			size = le64_to_cpu(a->data.non_resident.data_size);
			alloc = le64_to_cpu(a->data.non_resident.allocated_size);
		} else {
			size = le32_to_cpu(a->data.resident.value_length);
			alloc = (size + 7) & ~7ULL;
		}
		if (fn(arg, (const unsigned short *)((u8 *)a + le16_to_cpu(a->name_offset)), a->name_length, size, alloc)) {
			err = 1;
			break;
		}
	}
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ni);
	return err < 0 ? err : 0;
}

static long ngc_read_impl(ngc_node *n, unsigned long long off, unsigned int len, void *buf, int drop_cache)
{
	struct inode *vi = (struct inode *)n;
	loff_t size = i_size_read(vi);
	u8 *out = buf;
	unsigned int done = 0;

	while (done < len) {
		u64 pos = off + done;
		unsigned int in_page = pos & (PAGE_SIZE - 1);
		unsigned int chunk = min_t(unsigned int, PAGE_SIZE - in_page, len - done);
		struct folio *f;
		if ((loff_t)pos >= size) {
			memset(out + done, 0, len - done);
			done = len;
			break;
		}
		f = read_mapping_folio(vi->i_mapping, (pgoff_t)(pos >> PAGE_SHIFT), NULL);
		if (IS_ERR(f))
			return PTR_ERR(f);
		memcpy(out + done, (u8 *)f->data + in_page, chunk);
		folio_put(f);
		done += chunk;
	}
	/* The NT Cache Manager holds file data; keep only a bounded window here. */
	if (drop_cache && vi->i_mapping->nrpages > 256)
		kshim_mapping_shrink(vi->i_mapping);
	return done;
}

/*
 * Non-cached and paging reads of a non-resident, uncompressed stream: straight from its clusters
 * into @buf, one device transfer per run, instead of page by page through the shim page cache.
 * Bytes past the initialized size, holes, and bytes past EOF up to @len read as zeros.  -EAGAIN:
 * the stream needs the page-cache path (resident, compressed, dirty pages, unaligned buffer).
 */
long ngc_read_direct(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, void *buf)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	unsigned int bs = v->bdev->logical_block_size;
	u64 end = off + len, data_end, pos = off;
	struct runlist_element *rl;
	int err;

	if (v->bdev->kshim_gone)
		return -EIO;
	if (!NInoNonResident(ni) || NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni) ||
	    ((uintptr_t)buf & 3) || ((off | len) & (bs - 1)) || kshim_mapping_dirty(vi->i_mapping))
		return -EAGAIN;
	data_end = min_t(u64, end, (u64)min_t(loff_t, ni->initialized_size, i_size_read(vi)));
	mutex_lock(&ni->mrec_lock);
	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	rl = ni->runlist.rl;
	while (!err && pos < data_end) {
		s64 vcn = (s64)(pos >> vol->cluster_size_bits);
		u64 run_end, n, rd;
		while (rl && rl->length && rl->vcn + rl->length <= vcn)
			rl++;
		if (!rl || !rl->length || rl->vcn > vcn) {
			err = -EIO;
			break;
		}
		run_end = (u64)(rl->vcn + rl->length) << vol->cluster_size_bits;
		n = min_t(u64, run_end, data_end) - pos;
		if (rl->lcn == LCN_HOLE) {
			memset((u8 *)buf + (pos - off), 0, n);
		} else if (rl->lcn < 0) {
			err = -EIO;
			break;
		} else {
			/* Whole sectors: the tail past the initialized size is zeroed below. */
			rd = min_t(u64, (n + bs - 1) & ~(u64)(bs - 1), end - pos);
			err = kshim_dev_rw(v->bdev, 0, ((u64)rl->lcn << vol->cluster_size_bits) +
					   (pos - ((u64)rl->vcn << vol->cluster_size_bits)), (u8 *)buf + (pos - off), (size_t)rd);
		}
		pos += n;
	}
	up_write(&ni->runlist.lock);
	mutex_unlock(&ni->mrec_lock);
	if (err)
		return err;
	if (data_end < end)
		memset((u8 *)buf + (max_t(u64, data_end, off) - off), 0, end - max_t(u64, data_end, off));
	return len;
}

void ngc_debug_dump(void)
{
	printk("shim: %lu cache pages, %lu live inodes, %lu device reads\n",
			kshim_pc_pages, kshim_inodes_live, kshim_counter_reads);
	kshim_dump_allocs();
}

/* ------------------------------------------------------------------ write side */

/* Evicts unused cached inodes beyond the cache limits; called between core operations. */
void ngc_icache_trim(ngc_vol *v)
{
	kshim_icache_trim(v->sb);
}

/* The medium was replaced: no device I/O of this volume may happen any more (caller holds the volume lock). */
void ngc_medium_gone(ngc_vol *v)
{
	kshim_dio_drain(v->bdev);
	kshim_jnl_quiesce(v->bdev);	/* the journal I/O of an unlocked commit is device I/O too */
	v->bdev->kshim_gone = 1;
	v->sb->s_flags |= SB_RDONLY;
}

/*
 * The disk was written under the mount (the lock holder's direct writes): from now on neither the core
 * nor the journal writes the device (writeback, commits, the journal's error header); reads go on.
 */
void ngc_stop_writes(ngc_vol *v)
{
	kshim_dio_drain(v->bdev);
	kshim_jnl_quiesce(v->bdev);
	v->bdev->kshim_frozen = 1;
	v->sb->s_flags |= SB_RDONLY;
}

int ngc_is_rw(ngc_vol *v)
{
	return !sb_rdonly(v->sb);
}

int ngc_failed(ngc_vol *v)
{
	return v->failed || kshim_jnl_failed(v->bdev);
}

/*
 * Writeback did not complete, so committing now would publish part of an operation (an MFT record
 * without its bitmap change).  Nothing is committed: the overlay and the dirty pages stay, and the
 * caller's operation fails.  With the journal holding every metadata write the disk then keeps the
 * last committed state; after the journal degraded (UNJOURNALED: metadata goes in place) the pages
 * written before the failure stay on disk, and the header already sends the next mount to repair
 * rather than back to a committed state.  Out of memory
 * (or writeback still finding work after every pass) is retried at the next consistency point.
 * A device error marks the volume as needing repair and stops further changes.
 */
static int ngc_writeback_failed(struct ngc_vol *v, int err)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	int later = err == -ENOMEM || err == -EAGAIN || err == -ENOSPC || err == -EDQUOT;
	printk(KERN_ERR "ngc: writeback failed %d: nothing committed%s\n", err,
	       later ? ", retried later" : "; the volume needs repair and is read-only now");
	if (err == -EAGAIN)
		return -EIO;
	if (!later) {
		/* Sticky: the uncommitted changes can never be committed, so no later flush may succeed. */
		if (!v->failed)
			kshim_log_volume_failed(v->bdev, err);
		v->failed = 1;
		NVolSetErrors(vol);
		kshim_jnl_mark_errors(v->bdev);
		v->sb->s_flags |= SB_RDONLY;
	}
	return err;
}

/*
 * The part of a consistency point before the journal: every dirty mapping and inode is written back (into the live
 * overlay).  Callers hold the volume lock between core operations, so the state written is whole.
 */
static int ngc_commit_prep(struct ngc_vol *v)
{
	unsigned long long t0 = ngos_ticks();
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	int err;
	if (v->failed)
		return -EIO;
	/* Known errors keep VOLUME_IS_DIRTY on disk, so other systems check the volume too. */
	if (NVolErrors(vol) && !(vol->vol_flags & VOLUME_IS_DIRTY) && !sb_rdonly(v->sb)) {
		err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
		if (err)
			return err;
	}
	err = kshim_sync(v->sb);
	for (int k = 0; err == -EAGAIN && k < 4; k++)
		err = kshim_sync(v->sb);
	if (v->bdev->kshim_wb_err) {
		/* An MFT write failed inside writeback: that folio is clean now, so this error wins. */
		err = v->bdev->kshim_wb_err;
		v->bdev->kshim_wb_err = 0;
	}
	ngos_prof(NGP_WRITEBACK, t0, 0);
	if (err)
		return ngc_writeback_failed(v, err);
	if (v->bdev->jnl && NVolErrors(vol))
		kshim_jnl_mark_errors(v->bdev);
	return 0;
}

/* The free-cluster count that a commit sealed or made now covers (see kshim_jnl_commit). */
static u64 ngc_aux(struct ngc_vol *v)
{
	return v->watched ? kshim_watch_count(v->watched) : 0;
}

/*
 * A consistency point: every dirty mapping and inode is written back, then (journal active)
 * the transaction is committed and written in place, or (no journal) the device is flushed.
 * Synchronous: the volume lock is held throughout.  The unlocked variant is ngc_commit_begin / io / end.
 */
static int ngc_commit_impl(struct ngc_vol *v)
{
	unsigned long long t0;
	int err = ngc_commit_prep(v);
	if (err)
		return err;
	if (!v->bdev->jnl)
		return blkdev_issue_flush(v->bdev);
	t0 = ngos_ticks();
	err = kshim_jnl_commit(v->bdev, ngc_aux(v));
	ngos_prof(NGP_JNL_COMMIT, t0, 0);
	if (!err)
		err = blkdev_issue_flush(v->bdev);	/* nothing was committed: data writes still reach the medium */
	if (err > 0)
		err = 0;
	return err;
}

static int ngc_commit(struct ngc_vol *v)
{
	unsigned long long t0 = ngos_ticks();
	int err = ngc_commit_impl(v);
	ngos_prof(NGP_COMMIT, t0, 0);
	return err;
}

/*
 * Unlocked commit, for the NT glue (nt/write.c NgCommit): the journal I/O of a commit (descriptor and data pages, flush,
 * COMMITTED header, flush, in place, flush, ACTIVE header: most of its time) runs without the volume lock.
 *   ngc_commit_begin (lock, between core operations): write back, seal the overlay.  Returns NGC_COMMIT_IO: call
 *       ngc_commit_io without the lock, then ngc_commit_end with it; 0: committed (or nothing to do) already;
 *       NGC_COMMIT_BUSY: another commit's I/O is running: ngc_commit_wait without the lock, then begin again; <0 error.
 *   ngc_commit_io: no lock.  The caller keeps the core alive meanwhile (the glue counts it as an unlocked I/O).
 *   ngc_commit_end (lock): releases the sealed transaction (anyone who needs it gone does that too).
 * While the I/O runs other threads run core operations; their metadata writes go to a new live overlay, and reads see
 * the sealed pages too (kshim_jnl.c).  Never from inside a core operation.
 */
int ngc_unlocked_commit = 1;

/* NoRetainedCommit=1: commits put their pages in place before they return, as before retained transactions (comparison, fallback). */
extern int kshim_jnl_noret;
void ngc_set_no_retain(int off)
{
	kshim_jnl_noret = off;
}

int ngc_commit_begin(ngc_vol *v, int retain)
{
	unsigned long long t0 = ngos_ticks();
	struct block_device *b = v->bdev;
	int err, r;
	if (!ngc_unlocked_commit)
		return ngc_commit_now(v);
	/* As ngc_commit_now. */
	if (NVolErrors(NTFS_SB(v->sb)))
		kshim_jnl_mark_errors(b);
	if (v->failed || kshim_jnl_failed(b))
		return -EIO;
	if (sb_rdonly(v->sb))
		return 0;
	if (kshim_jnl_busy(b))
		return NGC_COMMIT_BUSY;
	err = ngc_commit_prep(v);
	if (err)
		return err;
	if (!b->jnl)
		err = blkdev_issue_flush(b);
	else {
		r = kshim_jnl_seal(b, ngc_aux(v), retain);
		if (r == 1) {
			ngos_prof(NGP_COMMIT, t0, 0);
			return NGC_COMMIT_IO;
		}
		if (r == -EBUSY)
			return NGC_COMMIT_BUSY;
		if (r == -ENOSYS)
			r = kshim_jnl_commit(b, ngc_aux(v));	/* degraded, a resize runs, no memory, too large: as before */
		if (r == 0)
			err = blkdev_issue_flush(b);	/* nothing was committed: data writes still reach the medium */
		else
			err = r > 0 ? 0 : r;
	}
	ngos_prof(NGP_COMMIT, t0, 0);
	return err > 0 ? 0 : err;
}

int ngc_commit_io(ngc_vol *v)
{
	return kshim_jnl_io(v->bdev);
}

void ngc_commit_end(ngc_vol *v)
{
	kshim_jnl_reap(v->bdev);
}

void ngc_commit_wait(ngc_vol *v)
{
	kshim_jnl_wait(v->bdev);
}

/* Overlay pages that make the next operation commit first: half the journal, at most NGC_JNL_COMMIT_PAGES. */
static unsigned long ngc_commit_threshold(struct ngc_vol *v)
{
	return min_t(unsigned long, NGC_JNL_COMMIT_PAGES, kshim_jnl_capacity(v->bdev) / 2);
}

/* Free clusters that no complete commit covers yet. */
static int ngc_frees_pending(struct ngc_vol *v)
{
	return v->bdev->jnl && (!v->watched || kshim_watch_count(v->watched) != kshim_jnl_aux_done(v->bdev));
}

/*
 * The overlay is past the threshold, or (@alloc) a free is not committed yet and an allocation follows: the glue commits
 * (ngc_commit_begin) before its next operation of that kind, without the volume lock for the I/O.  Between core operations.
 */
int ngc_commit_wanted(ngc_vol *v, int alloc)
{
	if (!v->bdev->jnl || sb_rdonly(v->sb) || !ngc_unlocked_commit)
		return 0;
	return kshim_jnl_pending(v->bdev) > ngc_commit_threshold(v) || (alloc && ngc_frees_pending(v));
}

/* Past this many overlay pages a core operation commits at once (with the lock), the threshold commit not having come yet. */
static unsigned long ngc_commit_hard(struct ngc_vol *v)
{
	return min_t(unsigned long, 2 * ngc_commit_threshold(v), kshim_jnl_capacity(v->bdev) / 4 * 3);
}

/*
 * File data is written in place at once, so a cluster freed by an uncommitted transaction
 * must not receive data before that transaction commits: a crash would hand the old owner
 * the new data.  Operations that allocate data clusters commit first when anything was freed.
 */
static int ngc_before_alloc(struct ngc_vol *v)
{
	if (ngc_frees_pending(v)) {
		unsigned long long t0 = ngos_ticks();
		int err;
		/*
		 * A commit whose I/O runs without the lock may cover them: wait for it (it needs no lock).  The glue commits
		 * before a growth when it can (ngc_commit_wanted), so this is the case that it could not, or a free since.
		 */
		kshim_jnl_settle(v->bdev);
		if (!ngc_frees_pending(v))
			return 0;
		err = ngc_commit(v);
		ngos_prof(NGP_COMMIT_ALLOC, t0, 0);
		return err;
	}
	return 0;
}

/*
 * Sets VOLUME_IS_DIRTY before the first change after a clean point, and puts it on disk
 * before the change proceeds, so a crash always leaves it behind (also for another system that
 * mounts the volume).  This is the "mounted, unclean" marker, not a dirty volume: keep_dirty is
 * what makes the flag real (FSCTL_IS_VOLUME_DIRTY and autochk only count it then).  Also commits when the
 * journal overlay has grown large.
 */
int ngc_mark_dirty(ngc_vol *v)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (vol->vol_flags & VOLUME_IS_DIRTY) {
		unsigned long long t0;
		unsigned long pending = kshim_jnl_pending(v->bdev);
		if (pending <= ngc_commit_threshold(v))
			return 0;
		/*
		 * The glue commits at its next safe point without the lock for the I/O (ngc_commit_wanted), and its flusher
		 * is asked to now; the operation goes on, but not too far past the threshold.
		 */
		if (ngc_unlocked_commit && pending <= ngc_commit_hard(v)) {
			if (v->bdev->kshim_kick)
				v->bdev->kshim_kick(v->bdev->kshim_kick_ctx);
			return 0;
		}
		t0 = ngos_ticks();
		err = ngc_commit(v);
		ngos_prof(NGP_COMMIT_FULL, t0, 0);
		return err;
	}
	err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
	if (!err)
		err = write_inode_now(vol->vol_ino, 1);
	if (!err)
		err = ngc_commit(v);
	return err;
}

/* The flag on disk is (or no longer is) a real request: in memory, and in the journal headers. */
static void ngc_set_keep(ngc_vol *v, bool keep)
{
	NTFS_SB(v->sb)->keep_dirty = keep;
	kshim_jnl_set_keep(v->bdev, keep);
}

/*
 * FSCTL_MARK_VOLUME_DIRTY: the flag goes on disk and stays (no quiet flusher pass or unmount clears it) until
 * the next mount's check has run, as a check scheduled with chkdsk or chkntfs.
 */
int ngc_mark_volume_dirty(ngc_vol *v)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (vol->vol_flags & VOLUME_IS_DIRTY) {
		/*
		 * On disk already (the mounted marker): $Volume is rewritten (flag off and on in the same transaction)
		 * so that the commit writes a journal header with the keep mark.
		 */
		vol->keep_dirty = false;
		err = ntfs_clear_volume_flags(vol, VOLUME_IS_DIRTY);
		if (!err)
			err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
		ngc_set_keep(v, true);
		if (!err)
			err = write_inode_now(vol->vol_ino, 1);
		if (!err)
			err = ngc_commit(v);
		if (err)
			ngc_set_keep(v, false);
		return err;
	}
	ngc_set_keep(v, true);
	err = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
	if (!err)
		err = write_inode_now(vol->vol_ino, 1);
	if (!err)
		err = ngc_commit(v);
	if (err)
		ngc_set_keep(v, false);
	return err;
}

/*
 * The flusher: writes back every dirty mapping and inode, then (when nothing is left and the
 * core saw no error) clears VOLUME_IS_DIRTY, so the flag on disk means "unsynced changes".
 */
static int ngc_sync_impl(ngc_vol *v)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	int err;
	if (NVolErrors(vol))
		kshim_jnl_mark_errors(v->bdev);
	if (v->failed || kshim_jnl_failed(v->bdev))
		return -EIO;
	if (sb_rdonly(v->sb))
		return 0;
	err = ngc_commit(v);
	if (!err && !NVolErrors(vol) && (vol->vol_flags & VOLUME_IS_DIRTY) && !kshim_sb_dirty(v->sb)) {
		err = ntfs_clear_volume_flags(vol, VOLUME_IS_DIRTY);
		if (!err)
			err = ngc_commit(v);
	}
	/* Clean on disk: no header stays behind for a later mount to trust after another driver's session. */
	if (!err && !NVolErrors(vol) && !(vol->vol_flags & VOLUME_IS_DIRTY) && !kshim_sb_dirty(v->sb))
		err = kshim_jnl_retire(v->bdev);
	return err;
}

/*
 * A commit of everything changed so far that leaves VOLUME_IS_DIRTY as it is: FlushFileBuffers and the
 * flusher while the volume is busy.  Clearing the flag costs two more commits (clear it, set it again
 * at the next change), so only a quiet flusher pass does that (ngc_sync).
 */
int ngc_commit_now(ngc_vol *v)
{
	if (NVolErrors(NTFS_SB(v->sb)))
		kshim_jnl_mark_errors(v->bdev);
	if (v->failed || kshim_jnl_failed(v->bdev))
		return -EIO;
	if (sb_rdonly(v->sb))
		return 0;
	return ngc_commit(v);
}

/* True when metadata changed since the last commit (VOLUME_IS_DIRTY alone does not count). */
int ngc_changed(ngc_vol *v)
{
	if (sb_rdonly(v->sb))
		return 0;
	return kshim_sb_dirty(v->sb) || kshim_jnl_unsettled(v->bdev);
}

int ngc_dirty(ngc_vol *v)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	if (NVolErrors(vol))
		kshim_jnl_mark_errors(v->bdev);
	if (sb_rdonly(v->sb))
		return 0;
	/* Also errors not yet marked on disk, and a clean volume whose header is still to be retired. */
	return kshim_sb_dirty(v->sb) || ((vol->vol_flags & VOLUME_IS_DIRTY) && !vol->keep_dirty) || kshim_jnl_unsettled(v->bdev) ||
	       kshim_jnl_retained(v->bdev) ||	/* durable in the journal, not in place: the next quiet flusher pass checkpoints it */
	       (NVolErrors(vol) && !(vol->vol_flags & VOLUME_IS_DIRTY)) || kshim_jnl_retire_pending(v->bdev) ||
	       kshim_jnl_errors_pending(v->bdev);
}

void ngc_jnl_report(ngc_vol *v)
{
	kshim_jnl_report(v->bdev);
}

/* Every run of a non-resident stream (-EINVAL while it is resident). */
int ngc_runs(ngc_vol *v, ngc_node *n, ngc_run_t fn, void *ctx)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	struct runlist_element *rl;
	int err;
	(void)v;
	if (!NInoNonResident(ni))
		return -EINVAL;
	mutex_lock(&ni->mrec_lock);
	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	for (rl = ni->runlist.rl; !err && rl && rl->length; rl++)
		err = fn(ctx, rl->vcn, rl->lcn, rl->length);
	up_write(&ni->runlist.lock);
	mutex_unlock(&ni->mrec_lock);
	return err;
}

static int ngc_dev_write(struct ngc_vol *v, u64 off, const u8 *buf, u64 len);

/* A raw write of volume bytes (the boot code): in place, seen by the overlay and the cached device pages. */
int ngc_raw_write(ngc_vol *v, unsigned long long off, const void *buf, unsigned int len)
{
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	err = ngc_dev_write(v, off, buf, len);
	if (!err)
		kshim_mapping_update(v->bdev->bd_mapping, off, buf, len);
	return err;
}

#if DBG
void ngc_set_journal_fault(unsigned long commit_no)
{
	kshim_jnl_fault = commit_no;
}

void ngc_set_journal_fault_stage(unsigned long stage)
{
	kshim_jnl_fault_stage = stage;
}

void ngc_set_journal_stall(unsigned long ms)
{
	kshim_jnl_stall_ms = ms;
}
#endif

static int ngc_dev_write(struct ngc_vol *v, u64 off, const u8 *buf, u64 len)
{
	int err = 0;
	v->bdev->kshim_direct++;
	while (len && !err) {
		size_t n;
		if (buf && !((uintptr_t)buf & 3)) {
			/*
			 * A word-aligned caller buffer goes to the device as it is, up to NGC_DIRECT_MAX per request: the
			 * storage stack splits it at the limit of the adapter and keeps the pieces in flight together,
			 * where a 64 KB bounce made one synchronous round trip per piece.  An unaligned buffer is
			 * bounced below the block layer (kshim_dev_rw).
			 */
			n = (size_t)min_t(u64, len, NGC_DIRECT_MAX);
			err = kshim_dev_rw(v->bdev, 1, off, (void *)buf, n);
		} else {
			n = (size_t)min_t(u64, len, NGC_BOUNCE);
			if (buf)
				memcpy(v->bounce, buf, n);
			else
				memset(v->bounce, 0, n);
			err = kshim_dev_rw(v->bdev, 1, off, v->bounce, n);
		}
		off += n;
		len -= n;
		if (buf)
			buf += n;
	}
	v->bdev->kshim_direct--;
	return err;
}

/* Writes [pos, pos+len) of a non-resident attribute in place; buf NULL writes zeros. */
static int ngc_nr_write(struct ngc_vol *v, struct inode *vi, u64 pos, u64 len, const u8 *buf)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	u32 bits = vol->cluster_size_bits;
	u64 cs = vol->cluster_size;
	while (len) {
		s64 vcn = pos >> bits, lcn = 0, cnt = 0;
		u64 vofs = pos & (cs - 1), n, dev;
		s64 maxc = (s64)((vofs + len + cs - 1) >> bits);
		bool balloc = false;
		int err;
		mutex_lock(&ni->mrec_lock);
		down_write(&ni->runlist.lock);
		err = ntfs_attr_map_cluster(ni, vcn, &lcn, &cnt, maxc, &balloc, true, false);
		up_write(&ni->runlist.lock);
		mutex_unlock(&ni->mrec_lock);
		if (err) {
			printk(KERN_ERR "ngc: map of ino %llu vcn %lld failed %d (size %lld, alloc %lld, init %lld)\n",
			       (unsigned long long)ni->mft_no, (long long)vcn, err, (long long)ni->data_size,
			       (long long)ni->allocated_size, (long long)ni->initialized_size);
			return err;
		}
		if (lcn < 0 || cnt <= 0)
			return -EIO;
		n = min_t(u64, len, ((u64)cnt << bits) - vofs);
		dev = ((u64)lcn << bits) + vofs;
		if (balloc) {
			/* Fresh clusters for a hole: zero what this write does not cover. */
			u64 first = (u64)lcn << bits, end = vofs + n;
			u64 last = (u64)lcn << bits;
			last += (end + cs - 1) & ~(cs - 1);
			if (vofs && (err = ngc_dev_write(v, first, NULL, vofs)))
				return err;
			if (dev + n < last && (err = ngc_dev_write(v, dev + n, NULL, last - (dev + n))))
				return err;
		}
		err = ngc_dev_write(v, dev, buf, n);
		if (err)
			return err;
		pos += n;
		len -= n;
		if (buf)
			buf += n;
	}
	return 0;
}

static int ngc_res_write(struct inode *vi, u64 pos, u64 len, const u8 *buf)
{
	struct ntfs_inode *ni = NTFS_I(vi), *base = NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni;
	struct ntfs_attr_search_ctx *ctx;
	int err;
	mutex_lock(&base->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(base, NULL);
	if (!ctx) {
		mutex_unlock(&base->mrec_lock);
		return -ENOMEM;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len, CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (!err) {
		u8 *val = (u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset);
		u32 vlen = le32_to_cpu(ctx->attr->data.resident.value_length);
		if (ctx->attr->non_resident || pos + len > vlen) {
			err = -EIO;
		} else {
			memcpy(val + pos, buf, len);
			mark_mft_record_dirty(ctx->ntfs_ino);
		}
	}
	ntfs_attr_put_search_ctx(ctx);
	mutex_unlock(&base->mrec_lock);
	return err;
}

/*
 * The NT data path (non-cached and paging writes): in-place write of [off, off+len) clipped to
 * the stream size.  Returns the bytes written (0 past EOF) or <0.
 */
static long ngc_write_impl(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, const void *buf)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	loff_t size = i_size_read(vi);
	u64 end;
	int err;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if ((loff_t)off >= size || !len)
		return 0;
	if (off + len > (u64)size)
		len = (unsigned int)(size - off);
	end = off + len;
	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni))
		return -EOPNOTSUPP;
	err = ngc_mark_dirty(v);
	/* Only a sparse stream can allocate here; other clusters were allocated by set_size, after its own commit. */
	if (!err && NInoSparse(ni))
		err = ngc_before_alloc(v);
	if (err)
		return err;
	if (!NInoNonResident(ni)) {
		err = ngc_res_write(vi, off, len, buf);
	} else {
		loff_t init = ni->initialized_size;
		if ((loff_t)off > init)
			err = ngc_nr_write(v, vi, init, off - init, NULL);
		if (!err)
			err = ngc_nr_write(v, vi, off, len, buf);
		if (!err && (loff_t)end > ni->initialized_size) {
			mutex_lock(&ni->mrec_lock);
			err = ntfs_attr_set_initialized_size(ni, end);
			mutex_unlock(&ni->mrec_lock);
		}
	}
	if (err)
		return err;
	kshim_mapping_update(vi->i_mapping, off, buf, len);
	return len;
}

/*
 * Data writes whose device transfer runs without the volume lock (ngapi.h, ngc_dio_*; the NT glue uses
 * them for paging writes, nt/write.c).  What keeps the unlocked transfer correct:
 *  - The clusters stay the stream's until it ends.  Every cluster free waits for the transfers in flight
 *    first (ntfs_inc_free_clusters -> kshim_dio_drain), and the node is pinned, so not even the eviction
 *    of an unlinked file frees them under it.  ngc_dio_end maps the range again and refuses to publish a
 *    write whose mapping changed (the caller then writes again through ngc_write).
 *  - Nothing else writes those sectors meanwhile: they are data clusters, not held in the journal overlay
 *    (checked here), and the stream's page cache has no dirty page whose writeback could land on them
 *    (checked here).  The glue orders the stream's data writes one at a time (the FCB's paging-write lock)
 *    and keeps size changes out (its paging I/O resource), so no zero fill or truncation overlaps.
 *  - The device stays the volume's: unmount, a medium change, the lock holder's direct writes and a
 *    resize drain the transfers first (ngc_umount, ngc_medium_gone, ngc_stop_writes, ngc_extend/shrink).
 *  - The initialized size moves only in ngc_dio_end, after the data reached the device, and only up, so
 *    no reader sees bytes below it that were not written; a write that would need a zero fill (it starts
 *    past the initialized size) is not taken.
 * Streams this does not cover (resident, compressed, sparse, encrypted), unmapped clusters and writes of
 * more than NGC_DIO_RUNS runs go through ngc_write under the lock as before.
 */
#if DBG
/* Test only: every ngc_dio_fault_every'th unlocked write that passed the checks of ngc_dio_end is reported as changed. */
static unsigned long ngc_dio_fault_every, ngc_dio_fault_seen;
unsigned long ngc_dio_forced;

void ngc_set_dio_fault(unsigned long every)
{
	ngc_dio_fault_every = every;
}

static int ngc_dio_forced_mismatch(void)
{
	if (!ngc_dio_fault_every || ++ngc_dio_fault_seen % ngc_dio_fault_every)
		return 0;
	ngc_dio_forced++;
	return 1;
}
#else
#define ngc_dio_forced_mismatch() 0
#endif

static int ngc_dio_map(struct ngc_vol *v, struct ntfs_inode *ni, u64 off, u32 len, u32 cap, struct ngc_dio *d)
{
	struct ntfs_volume *vol = ni->vol;
	u64 bs = v->bdev->logical_block_size, pos = off, end = off + len;
	struct runlist_element *rl;
	int err;

	d->nruns = 0;
	mutex_lock(&ni->mrec_lock);
	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	rl = ni->runlist.rl;
	while (!err && pos < end) {
		s64 vcn = (s64)(pos >> vol->cluster_size_bits);
		u64 run_end, run_dev_end, n, dev, io;
		while (rl && rl->length && rl->vcn + rl->length <= vcn)
			rl++;
		if (!rl || !rl->length || rl->vcn > vcn || rl->lcn < 0 || d->nruns == NGC_DIO_RUNS) {
			err = -EAGAIN;
			break;
		}
		run_end = (u64)(rl->vcn + rl->length) << vol->cluster_size_bits;
		run_dev_end = (u64)(rl->lcn + rl->length) << vol->cluster_size_bits;
		n = min_t(u64, run_end, end) - pos;
		dev = ((u64)rl->lcn << vol->cluster_size_bits) + (pos - ((u64)rl->vcn << vol->cluster_size_bits));
		/* Whole sectors: a tail short of one is padded from the caller's buffer, inside this cluster. */
		io = (n + bs - 1) & ~(bs - 1);
		if ((dev & (bs - 1)) || ((pos - off) & (bs - 1)) || dev + io > run_dev_end || dev + io > v->bdev->size ||
		    pos - off + io > cap || io > 0x7fffffff || kshim_jnl_holds(v->bdev, dev, io)) {
			err = -EAGAIN;
			break;
		}
		d->run[d->nruns].dev = dev;
		d->run[d->nruns].len = (unsigned int)io;
		d->run[d->nruns].boff = (unsigned int)(pos - off);
		d->nruns++;
		pos += n;
	}
	up_write(&ni->runlist.lock);
	mutex_unlock(&ni->mrec_lock);
	return err;
}

int ngc_dio_begin(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, unsigned int cap, struct ngc_dio *d)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	loff_t size = i_size_read(vi);
	int err;

	d->n = NULL;
	d->zero = 0;
	if (sb_rdonly(v->sb) || !len || (loff_t)off >= size || !v->bdev->kshim_drain)
		return -EAGAIN;
	if (off + len > (u64)size)
		len = (unsigned int)(size - off);
	if (!ngc_is_data_inode(vi) || !NInoNonResident(ni) || NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni) ||
	    NInoSparse(ni) || (loff_t)off > ni->initialized_size || v->bdev->kshim_gone || v->bdev->kshim_frozen ||
	    (v->bdev->jnl && kshim_jnl_failed(v->bdev)))
		return -EAGAIN;
	/* As ngc_write: VOLUME_IS_DIRTY is on the medium before the change (here: the initialized size). */
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	if (sb_rdonly(v->sb) || kshim_mapping_dirty(vi->i_mapping) || ngc_dio_map(v, ni, off, len, cap, d))
		return -EAGAIN;
	if (!igrab(vi))
		return -EAGAIN;
	d->n = n;
	d->off = off;
	d->len = len;
	d->cap = cap;
	return 0;
}

long ngc_dio_end(ngc_vol *v, struct ngc_dio *d, const void *buf, int io_err)
{
	struct inode *vi = (struct inode *)d->n;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ngc_dio now;
	u64 end = d->off + d->len;
	long ret = d->len;
	unsigned int r;

	/* The transfer's device requests count as writes, as those of ngc_write do (CoreLock is held). */
	for (r = 0; r < d->nruns; r++) {
		kshim_counter_writes++;
		kshim_counter_write_bytes += d->run[r].len;
	}
	if (io_err) {
		v->bdev->kshim_wr_failed++;
		ret = -EIO;
	} else if (sb_rdonly(v->sb)) {
		ret = -EROFS;
	} else if (i_size_read(vi) < (loff_t)end || (loff_t)d->off > ni->initialized_size ||
		   ngc_dio_map(v, ni, d->off, d->len, d->cap, &now) ||
		   now.nruns != d->nruns || memcmp(now.run, d->run, d->nruns * sizeof(d->run[0])) ||
		   ngc_dio_forced_mismatch()) {
		/*
		 * The stream changed under the transfer.  Not an error (the caller writes it again through
		 * ngc_write), so a warning: error-level messages feed kshim_errseq_check on this thread.
		 * "off > initialized size" cannot happen while the glue keeps size changes out (PagingIoResource);
		 * it is checked anyway, so a shrink and regrow in the window can never publish a transfer that
		 * left stale clusters in the gap below it.
		 */
		printk(KERN_WARNING "ngc: ino %llu: mapping of %llu+%u changed under an unlocked write: written again\n",
		       (unsigned long long)ni->mft_no, d->off, d->len);
		ret = -EAGAIN;
	} else {
		if ((loff_t)end > ni->initialized_size) {
			/* Again: a quiet flusher pass may have cleared VOLUME_IS_DIRTY during the transfer. */
			int err = ngc_mark_dirty(v);
			if (!err) {
				mutex_lock(&ni->mrec_lock);
				err = ntfs_attr_set_initialized_size(ni, end);
				mutex_unlock(&ni->mrec_lock);
			}
			if (err)
				ret = err;
		}
		if (ret >= 0 && !d->zero)
			kshim_mapping_update(vi->i_mapping, d->off, buf, d->len);
	}
	iput(vi);
	d->n = NULL;
	return ret;
}

/*
 * The zero fill below a write that starts past the initialized size, without the volume lock (what ngc_write does
 * under it, byte for byte, for a stream whose [initialized size, off) is allocated).  One call prepares the next piece
 * of the gap, at most NGC_ZERO_CHUNK bytes, as a dio of zeros: the caller writes zeros to each run (unlocked, as for
 * ngc_dio_begin) and ngc_dio_end raises the initialized size to the end of the piece, so after a power cut the gap is
 * zero below the initialized size that reached the journal and not read at all above it: zeros are on the device
 * before the size that exposes them is published, exactly the order of ngc_write.  Pieces are small so the volume lock
 * and the drain gate are free between them.
 * Returns 0 (a piece is pinned: ngc_dio_end must follow), NGC_ZERO_DONE (nothing left for this to fill: the gap is
 * closed or only a tail shorter than a sector remains; ngc_write finishes that under the lock) or -NGC_EAGAIN
 * (ngc_write does all of it under the lock; what was filled so far stays filled).  An unaligned initialized size is
 * first raised to the next sector under the lock (at most one sector of zeros, written as ngc_write writes them).
 */
int ngc_dio_zero_begin(ngc_vol *v, ngc_node *n, unsigned long long upto, struct ngc_dio *d)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	loff_t size = i_size_read(vi);
	u64 bs = v->bdev->logical_block_size, start, end;
	int err;

	d->n = NULL;
	d->nruns = 0;
	d->zero = 0;
	if ((loff_t)upto <= ni->initialized_size)
		return NGC_ZERO_DONE;
	if (sb_rdonly(v->sb) || (loff_t)upto > size || !v->bdev->kshim_drain)
		return -EAGAIN;
	if (!ngc_is_data_inode(vi) || !NInoNonResident(ni) || NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni) ||
	    NInoSparse(ni) || v->bdev->kshim_gone || v->bdev->kshim_frozen || (v->bdev->jnl && kshim_jnl_failed(v->bdev)))
		return -EAGAIN;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	start = ni->initialized_size;
	if (start & (bs - 1)) {
		u64 head = min_t(u64, upto, round_up(start, bs));
		err = ngc_nr_write(v, vi, start, head - start, NULL);
		if (!err) {
			mutex_lock(&ni->mrec_lock);
			err = ntfs_attr_set_initialized_size(ni, head);
			mutex_unlock(&ni->mrec_lock);
		}
		if (err)
			return err;
		start = head;
	}
	if (start >= upto)
		return NGC_ZERO_DONE;
	end = min_t(u64, upto, start + NGC_ZERO_CHUNK) & ~(bs - 1);
	if (end <= start)
		return NGC_ZERO_DONE;
	if (sb_rdonly(v->sb) || kshim_mapping_dirty(vi->i_mapping) || ngc_dio_map(v, ni, start, end - start, end - start, d))
		return -EAGAIN;
	if (!igrab(vi))
		return -EAGAIN;
	d->n = n;
	d->off = start;
	d->len = (unsigned int)(end - start);
	d->cap = d->len;
	d->zero = 1;
	return 0;
}

/*
 * The read side of the same scheme.  No ngc_dio_end-like check is needed: nothing changes on the volume, and
 * the data returned is what the stream held when the runs were mapped (the read is ordered there).  What keeps
 * it correct while the volume lock is not held:
 *  - The clusters read stay allocated until the transfer ends: every cluster free drains the transfers first
 *    (ntfs_inc_free_clusters -> kshim_dio_drain), so they cannot be reallocated and rewritten under the read,
 *    and the node is pinned so not even the eviction of an unlinked file frees them.  A truncate meanwhile
 *    waits at its free, so the reader gets the stream as it was before the truncate.
 *  - The sectors are data clusters that the journal overlay does not hold (checked here; it cannot start
 *    holding data sectors without a free), and the stream has no dirty shim page (checked here), as for writes.
 *  - Zero fills (holes, past the initialized size, past EOF) come from the same snapshot.
 * Concurrent writes of the same range are not ordered against the read (as on Windows).
 */
int ngc_rdio_begin(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, void *buf, struct ngc_dio *d)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_volume *vol = ni->vol;
	unsigned int bs = v->bdev->logical_block_size;
	u64 end = off + len, data_end, pos = off;
	struct runlist_element *rl;
	int err = 0;

	d->n = NULL;
	d->nruns = 0;
	if (!len || v->bdev->kshim_gone || !v->bdev->kshim_drain)
		return -EAGAIN;
	/* Not the system files ($MFT, $Bitmap, ...): their sectors change through the journal overlay at any commit. */
	if (!ngc_is_data_inode(vi) || !NInoNonResident(ni) || NInoCompressed(ni) || NInoEncrypted(ni) ||
	    NInoWofCompressed(ni) || ((uintptr_t)buf & 3) || ((off | len) & (bs - 1)) || kshim_mapping_dirty(vi->i_mapping))
		return -EAGAIN;
	data_end = min_t(u64, end, (u64)min_t(loff_t, ni->initialized_size, i_size_read(vi)));
	mutex_lock(&ni->mrec_lock);
	down_write(&ni->runlist.lock);
	err = ntfs_attr_map_whole_runlist(ni);
	rl = ni->runlist.rl;
	while (!err && pos < data_end) {
		s64 vcn = (s64)(pos >> vol->cluster_size_bits);
		u64 run_end, run_dev_end, cnt, dev, io;
		struct ngc_dio_run *r = &d->run[d->nruns];
		while (rl && rl->length && rl->vcn + rl->length <= vcn)
			rl++;
		if (!rl || !rl->length || rl->vcn > vcn || rl->lcn == LCN_ENOENT || d->nruns == NGC_DIO_RUNS) {
			err = -EAGAIN;
			break;
		}
		run_end = (u64)(rl->vcn + rl->length) << vol->cluster_size_bits;
		cnt = min_t(u64, run_end, data_end) - pos;
		r->boff = (unsigned int)(pos - off);
		if (rl->lcn == LCN_HOLE) {
			r->dev = NGC_DIO_ZERO;
			r->len = (unsigned int)cnt;
		} else if (rl->lcn < 0) {
			err = -EAGAIN;
			break;
		} else {
			run_dev_end = (u64)(rl->lcn + rl->length) << vol->cluster_size_bits;
			dev = ((u64)rl->lcn << vol->cluster_size_bits) + (pos - ((u64)rl->vcn << vol->cluster_size_bits));
			/* Whole sectors: a tail past the initialized size is zeroed by the run after it. */
			io = min_t(u64, (cnt + bs - 1) & ~(u64)(bs - 1), end - pos);
			if ((dev & (bs - 1)) || dev + io > run_dev_end || dev + io > v->bdev->size || io > 0x7fffffff ||
			    kshim_jnl_holds(v->bdev, dev, io)) {
				err = -EAGAIN;
				break;
			}
			r->dev = dev;
			r->len = (unsigned int)io;
		}
		d->nruns++;
		pos += cnt;
	}
	up_write(&ni->runlist.lock);
	mutex_unlock(&ni->mrec_lock);
	if (!err && data_end < end) {
		struct ngc_dio_run *r = &d->run[d->nruns];
		u64 from = max_t(u64, data_end, off);
		if (d->nruns == NGC_DIO_RUNS)
			err = -EAGAIN;
		else {
			r->dev = NGC_DIO_ZERO;
			r->boff = (unsigned int)(from - off);
			r->len = (unsigned int)(end - from);
			d->nruns++;
		}
	}
	if (err || !igrab(vi))
		return -EAGAIN;
	d->n = n;
	d->off = off;
	d->len = len;
	d->cap = len;
	return 0;
}

void ngc_rdio_end(ngc_vol *v, struct ngc_dio *d)
{
	unsigned int r;

	/* The transfer's device reads count as reads, as those of ngc_read_direct do (CoreLock is held). */
	for (r = 0; r < d->nruns; r++)
		if (d->run[r].dev != NGC_DIO_ZERO)
			kshim_counter_reads++;
	iput((struct inode *)d->n);
	d->n = NULL;
	(void)v;
}

void ngc_set_commit_kick(ngc_vol *v, void (*fn)(void *ctx), void *ctx)
{
	v->bdev->kshim_kick_ctx = ctx;
	v->bdev->kshim_kick = fn;
}

void ngc_set_dio_drain(ngc_vol *v, void (*fn)(void *ctx), void *ctx)
{
	v->bdev->kshim_drain_ctx = ctx;
	v->bdev->kshim_drain = fn;
}

/* The allocation target of a growth step from @cur to @next bytes, 0 for exactly what @next needs (see NGC_PREALLOC_MIN). */
static loff_t ngc_prealloc_target(struct ntfs_inode *ni, loff_t cur, loff_t next)
{
	struct ntfs_volume *vol = ni->vol;
	loff_t target;

	if (!ngc_plain_nonresident(ni) || cur < NGC_PREALLOC_MIN || next - cur > NGC_PREALLOC_STEP)
		return 0;
	if ((atomic64_read(&vol->free_clusters) - atomic64_read(&vol->dirty_clusters)) << vol->cluster_size_bits < NGC_PREALLOC_FREE)
		return 0;
	target = round_up(next, NGC_PREALLOC_CHUNK);
	return target > ni->allocated_size ? target : 0;
}

/* True when growing to @newsize needs clusters the stream does not have yet. */
static bool ngc_grow_allocates(struct ntfs_inode *ni, loff_t newsize)
{
	if (!ngc_plain_nonresident(ni))
		return true;
	return round_up((u64)newsize, ni->vol->cluster_size) > (u64)ni->allocated_size;
}

/*
 * False when growing to @newsize needs more clusters than the volume has free (what the allocator checks for each step,
 * here for the whole growth and before any change is made).  Only a size that certainly needs clusters is judged:
 * a nonresident stream, or a resident one that cannot stay in its MFT record.  True when unsure (the growth then runs
 * and rolls back what it did, as before).
 */
static bool ngc_grow_fits(ngc_vol *v, struct ntfs_inode *ni, loff_t newsize)
{
	struct ntfs_volume *vol = ni->vol;
	s64 need, have, avail;

	if (!ngc_grow_allocates(ni, newsize) || !NVolFreeClusterKnown(vol) || !NVolDisableSparse(vol))
		return true;
	if (NInoNonResident(ni)) {
		if (!ngc_plain_nonresident(ni))
			return true;
		have = (s64)ni->allocated_size >> vol->cluster_size_bits;
	} else {
		if (newsize <= (loff_t)vol->mft_record_size)
			return true;
		have = 0;
	}
	need = (s64)(round_up((u64)newsize, vol->cluster_size) >> vol->cluster_size_bits) - have;
	avail = atomic64_read(&vol->free_clusters) - atomic64_read(&vol->dirty_clusters);
	return need <= avail;
}

/*
 * Gives back the clusters allocated ahead of the size (the last close of the stream).  Nothing to do, and no cost,
 * for a stream that has none.  A failure leaves them: they are an allocation like any other.
 */
static int ngc_trim_alloc_impl(ngc_vol *v, ngc_node *n)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	int err;

	if (!NInoNgAhead(ni))
		return 0;
	if (sb_rdonly(v->sb) || !ngc_plain_nonresident(ni) || (u64)ni->allocated_size <= round_up((u64)i_size_read(vi), ni->vol->cluster_size)) {
		NInoClearNgAhead(ni);
		return 0;
	}
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	mutex_lock(&ni->mrec_lock);
	err = ntfs_attr_trim_alloc(ni);
	mutex_unlock(&ni->mrec_lock);
	if (!err)
		NInoClearNgAhead(ni);
	mark_inode_dirty(vi);
	return err;
}

/* EOF change through the core (resident resize, conversion to non-resident, expand, shrink). */
static int ngc_set_size_impl(ngc_vol *v, ngc_node *n, unsigned long long newsize)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	loff_t old = i_size_read(vi);
	int err;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if ((loff_t)newsize == old)
		return 0;
	if (NInoCompressed(ni) || NInoEncrypted(ni) || NInoWofCompressed(ni))
		return -EOPNOTSUPP;
	/*
	 * A growth that cannot fit in the free clusters fails here, before ngc_mark_dirty and before any step touches the
	 * bitmap, the runlist or an MFT record: it must cost no write (an application that retries a failing extend on a
	 * full volume would otherwise write a journal transaction per attempt).
	 */
	if ((loff_t)newsize > old && !ngc_grow_fits(v, ni, newsize))
		return -ENOSPC;
	err = ngc_mark_dirty(v);
	/* Growth inside the allocation takes no cluster, so nothing a free could hand out (ngc_before_alloc). */
	if (!err && (loff_t)newsize > old && ngc_grow_allocates(ni, newsize))
		err = ngc_before_alloc(v);
	if (err)
		return err;
	if ((loff_t)newsize > old) {
		/*
		 * In steps: one core allocation of more than about 1.9 GB failed with ENOSPC on a
		 * volume whose free space is fragmented, while 256 MB steps reached 8 GB.  A failed
		 * step takes the file back to its old size.
		 */
		loff_t cur = old;
		while (!err && cur < (loff_t)newsize) {
			loff_t next = min_t(loff_t, newsize, cur + NGC_GROW_STEP);
			loff_t ahead = ngc_prealloc_target(ni, cur, next);
			mutex_lock(&ni->mrec_lock);
			err = ntfs_attr_expand(ni, next, ahead);
			if (err == -ENOSPC && ahead)
				err = ntfs_attr_expand(ni, next, 0);	/* the exact size may still fit */
			if (!err && (u64)ni->allocated_size > round_up((u64)next, ni->vol->cluster_size))
				NInoSetNgAhead(ni);
			mutex_unlock(&ni->mrec_lock);
			if (!err)
				cur = next;
		}
		if (err && cur > old) {
			truncate_setsize(vi, old);
			if (ntfs_truncate_vfs(vi, old, cur))
				i_size_write(vi, cur);
		}
	} else {
		truncate_setsize(vi, newsize);
		err = ntfs_truncate_vfs(vi, newsize, old);
		if (err)
			i_size_write(vi, old);
	}
	/* A resident->non-resident conversion left the old value in a dirty page-0 folio. */
	if (kshim_mapping_writeback(vi->i_mapping) && !err)
		err = -EIO;
	mark_inode_dirty(VFS_I(NInoAttr(ni) ? ni->ext.base_ntfs_ino : ni));
	return err;
}

#define NGC_SETTABLE_ATTRS (FILE_ATTR_READONLY | FILE_ATTR_HIDDEN | FILE_ATTR_SYSTEM | FILE_ATTR_ARCHIVE | \
			    FILE_ATTR_TEMPORARY | FILE_ATTR_OFFLINE | FILE_ATTR_NOT_CONTENT_INDEXED)

/*
 * Times (NT format; 0 keeps a time, -1 means "now") and $STANDARD_INFORMATION attributes
 * (attrs_mask selects which settable bits change).  Written back by write_inode.
 */
static int ngc_set_info_impl(ngc_vol *v, ngc_node *n, const long long times[4], unsigned int attrs, unsigned int attrs_mask)
{
	struct inode *vi = (struct inode *)n;
	struct ntfs_inode *ni = NTFS_I(vi);
	struct timespec64 now = current_time(vi), t;
	int err;

	if (NInoAttr(ni)) {
		ni = ni->ext.base_ntfs_ino;
		vi = VFS_I(ni);
	}
	if (sb_rdonly(v->sb))
		return -EROFS;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	if (times) {
#define NGC_T(x) (t = (x) == -1 ? now : nt_to_ts(x))
		if (times[0]) ni->i_crtime = NGC_T(times[0]);
		if (times[1]) inode_set_atime_to_ts(vi, NGC_T(times[1]));
		if (times[2]) inode_set_mtime_to_ts(vi, NGC_T(times[2]));
		if (times[3]) inode_set_ctime_to_ts(vi, NGC_T(times[3]));
#undef NGC_T
	}
	attrs_mask &= le32_to_cpu(NGC_SETTABLE_ATTRS);
	if (attrs_mask)
		ni->flags = (ni->flags & ~cpu_to_le32(attrs_mask)) | cpu_to_le32(attrs & attrs_mask);
	NInoSetFileNameDirty(ni);
	mark_inode_dirty(vi);
	return 0;
}

void ngc_write_stats(unsigned long *writes, unsigned long long *bytes, unsigned long *syncs, unsigned long *dirties)
{
	*writes = kshim_counter_writes;
	*bytes = kshim_counter_write_bytes;
	*syncs = kshim_counter_syncs;
	*dirties = kshim_counter_dirty;
}

/* ------------------------------------------------------------- security descriptors */

/* A $Secure:$SDS entry header, also the data of a $SII index entry. */
struct ngc_sd_hdr {
	__le32 hash;
	__le32 security_id;
	__le64 offset;
	__le32 length;
} __packed;

static __le16 ngc_sii[] = { cpu_to_le16('$'), cpu_to_le16('S'), cpu_to_le16('I'), cpu_to_le16('I'), 0 };
static __le16 ngc_sds[] = { cpu_to_le16('$'), cpu_to_le16('S'), cpu_to_le16('D'), cpu_to_le16('S'), 0 };

/*
 * The self-relative security descriptor of @n (kmalloc'd in *out): the file's own
 * $SECURITY_DESCRIPTOR attribute, or else the $Secure entry its $STANDARD_INFORMATION names.
 * *out stays NULL when the file has neither.
 */
/* Drops the cached descriptor of record @mft_no (every sequence number). */
static void ngc_sdc_drop(ngc_vol *v, unsigned long long mft_no)
{
	unsigned int i;
	mutex_lock(&v->sdc_lock);
	for (i = 0; i < NGC_SDC_N; i++) {
		if (v->sdc[i].sd && v->sdc[i].mft_no == mft_no) {
			kfree(v->sdc[i].sd);
			v->sdc[i].sd = NULL;
		}
	}
	mutex_unlock(&v->sdc_lock);
}

static void ngc_sdc_flush(ngc_vol *v)
{
	unsigned int i;
	for (i = 0; i < NGC_SDC_N; i++) {
		kfree(v->sdc[i].sd);
		v->sdc[i].sd = NULL;
	}
}

static int ngc_get_security_uncached(ngc_vol *v, ngc_node *n, void **out, unsigned int *len);

static int ngc_get_security_impl(ngc_vol *v, ngc_node *n, void **out, unsigned int *len)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	unsigned long long mft_no;
	unsigned short seq;
	unsigned int i;
	int err;

	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	/*
	 * Directories only: a directory is read again for every create and open below it; the descriptor of a file is read
	 * about once per open of that file, and keeping every one of them would only add a lock and two copies to each open.
	 */
	if (!S_ISDIR(VFS_I(ni)->i_mode) && !S_ISLNK(VFS_I(ni)->i_mode))
		return ngc_get_security_uncached(v, n, out, len);
	mft_no = ni->mft_no;
	seq = ni->seq_no;
	mutex_lock(&v->sdc_lock);
	for (i = 0; i < NGC_SDC_N; i++) {
		struct ngc_sdc *e = &v->sdc[i];
		if (e->sd && e->mft_no == mft_no && e->seq_no == seq) {
			void *c = kmalloc(e->len, GFP_NOFS);
			if (c) {
				memcpy(c, e->sd, e->len);
				*out = c;
				*len = e->len;
				mutex_unlock(&v->sdc_lock);
				return 0;
			}
			break;
		}
	}
	mutex_unlock(&v->sdc_lock);
	err = ngc_get_security_uncached(v, n, out, len);
	if (!err && *out && *len && *len <= NGC_SDC_MAX) {
		void *c = kmalloc(*len, GFP_NOFS);
		if (c) {
			struct ngc_sdc *e;
			memcpy(c, *out, *len);
			mutex_lock(&v->sdc_lock);
			/* a copy made meanwhile (another reader) is replaced, not duplicated */
			for (i = 0; i < NGC_SDC_N; i++) {
				if (v->sdc[i].sd && v->sdc[i].mft_no == mft_no) {
					kfree(v->sdc[i].sd);
					v->sdc[i].sd = NULL;
				}
			}
			e = &v->sdc[v->sdc_next++ % NGC_SDC_N];
			kfree(e->sd);
			e->mft_no = mft_no;
			e->seq_no = seq;
			e->len = *len;
			e->sd = c;
			mutex_unlock(&v->sdc_lock);
		}
	}
	return err;
}

static int ngc_get_security_uncached(ngc_vol *v, ngc_node *n, void **out, unsigned int *len)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n), *sni;
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct ntfs_attr_search_ctx *ctx;
	struct ntfs_index_context *icx;
	struct sii_index_key key;
	struct inode *sds;
	u32 secid = 0, l = 0;
	u64 off = 0;
	s64 size;
	void *sd;
	u8 *buf;
	long r;
	int err;

	*out = NULL;
	*len = 0;
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	mutex_lock(&ni->mrec_lock);
	if (ntfs_attr_exist(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0)) {
		sd = ntfs_attr_readall(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0, &size);
		mutex_unlock(&ni->mrec_lock);
		if (IS_ERR(sd))
			return PTR_ERR(sd);
		if (size < 20 || size > 0x10000) {
			kvfree(sd);
			return -EIO;
		}
		*out = sd;
		*len = (unsigned int)size;
		return 0;
	}
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (ctx) {
		if (!ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx) &&
		    !ctx->attr->non_resident && le32_to_cpu(ctx->attr->data.resident.value_length) >= 0x38)
			secid = get_unaligned_le32((u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset) + 0x34);
		ntfs_attr_put_search_ctx(ctx);
	}
	mutex_unlock(&ni->mrec_lock);
	if (!secid || !vol->secure_ino)
		return 0;
	sni = NTFS_I(vol->secure_ino);
	mutex_lock(&sni->mrec_lock);
	icx = ntfs_index_ctx_get(sni, ngc_sii, 4);
	if (!icx) {
		mutex_unlock(&sni->mrec_lock);
		return -ENOMEM;
	}
	key.security_id = cpu_to_le32(secid);
	err = ntfs_index_lookup(&key, sizeof(key), icx);
	if (!err) {
		struct ngc_sd_hdr *h = (struct ngc_sd_hdr *)((u8 *)icx->entry + le16_to_cpu(icx->entry->data.vi.data_offset));
		off = le64_to_cpu(h->offset);
		l = le32_to_cpu(h->length);
	}
	ntfs_index_ctx_put(icx);
	mutex_unlock(&sni->mrec_lock);
	if (err)
		return err == -ENOENT ? 0 : err;
	if (l < sizeof(struct ngc_sd_hdr) + 20 || l > 0x10000)
		return -EIO;
	sds = ntfs_attr_iget(vol->secure_ino, AT_DATA, ngc_sds, 4);
	if (IS_ERR(sds))
		return PTR_ERR(sds);
	buf = kmalloc(l, GFP_NOFS);
	r = buf ? ngc_read((ngc_node *)sds, off, l, buf, 0) : -ENOMEM;
	iput(sds);
	if (r < 0) {
		kfree(buf);
		return (int)r;
	}
	memmove(buf, buf + sizeof(struct ngc_sd_hdr), l - sizeof(struct ngc_sd_hdr));
	*out = buf;
	*len = l - sizeof(struct ngc_sd_hdr);
	return 0;
}

void ngc_free(void *p)
{
	kvfree(p);
}

/*
 * Stores a self-relative security descriptor as the file's own $SECURITY_DESCRIPTOR attribute
 * (the format the core gives new files); a $Secure security_id in $STANDARD_INFORMATION is
 * cleared so that every reader uses the new descriptor.
 */
static int ngc_set_security_impl(ngc_vol *v, ngc_node *n, const void *sd, unsigned int len)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (len < 20 || len > 0x10000)
		return -EINVAL;
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	ngc_sdc_drop(v, ni->mft_no);
	mutex_lock(&ni->mrec_lock);
	if (ntfs_attr_exist(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0))
		err = ntfs_attr_remove(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0);
	if (!err)
		err = ntfs_attr_add(ni, AT_SECURITY_DESCRIPTOR, AT_UNNAMED, 0, (u8 *)sd, len);
	if (!err) {
		/* A $Secure security_id would take precedence elsewhere (ntfs-3g, Windows): drop it. */
		struct ntfs_attr_search_ctx *ctx = ntfs_attr_get_search_ctx(ni, NULL);
		if (ctx && !ntfs_attr_lookup(AT_STANDARD_INFORMATION, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx) &&
		    !ctx->attr->non_resident && le32_to_cpu(ctx->attr->data.resident.value_length) >= 0x38) {
			u8 *val = (u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset);
			if (get_unaligned_le32(val + 0x34)) {
				put_unaligned_le32(0, val + 0x34);
				mark_mft_record_dirty(ctx->ntfs_ino);
			}
		}
		if (ctx)
			ntfs_attr_put_search_ctx(ctx);
	}
	mutex_unlock(&ni->mrec_lock);
	ngc_sdc_drop(v, ni->mft_no);
	if (!err)
		mark_inode_dirty(VFS_I(ni));
	return err;
}

/* ------------------------------------------------------------- volume label */

/*
 * Sets the volume label: the value of $Volume's $VOLUME_NAME, resized and rewritten in place (added
 * when the volume has none), so the change is one MFT record write that the journal commits with
 * the rest of the transaction.  An empty label stays an empty attribute, as format leaves it.  The
 * caller validated @len (at most NGC_LABEL_MAX units); the characters are stored as given.
 */
int ngc_set_label(ngc_vol *v, const unsigned short *label, unsigned int len)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct ntfs_inode *ni = NTFS_I(vol->vol_ino);
	struct ntfs_attr_search_ctx *ctx;
	unsigned char *nls = NULL, *old;
	u32 bytes = len * sizeof(__le16);
	int err;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if (len > NGC_LABEL_MAX)
		return -EINVAL;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	mutex_lock(&ni->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		mutex_unlock(&ni->mrec_lock);
		return -ENOMEM;
	}
	err = ntfs_attr_lookup(AT_VOLUME_NAME, NULL, 0, 0, 0, NULL, 0, ctx);
	if (!err) {
		if (!ngc_label_attr_ok(ctx->attr))
			err = -EUCLEAN;
		else
			err = ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr, bytes);
		if (!err) {
			memcpy((u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset), label, bytes);
			mark_mft_record_dirty(ctx->ntfs_ino);
		}
		ntfs_attr_put_search_ctx(ctx);
	} else {
		ntfs_attr_put_search_ctx(ctx);
		if (err == -ENOENT) {
			err = ntfs_resident_attr_record_add(ni, AT_VOLUME_NAME, AT_UNNAMED, 0, (u8 *)label, bytes, 0);
			if (err > 0)
				err = 0;
		}
	}
	mutex_unlock(&ni->mrec_lock);
	if (err)
		return err;
	memcpy(v->label, label, bytes);
	v->label_len = len;
	v->label_read = 1;
	/* The core's own UTF-8 copy; a label that does not convert leaves it empty. */
	if (len && ntfs_ucstonls(vol, (const __le16 *)label, len, &nls, 0) < 0)
		nls = NULL;
	mutex_lock(&vol->volume_label_lock);
	old = vol->volume_label;
	vol->volume_label = nls;
	mutex_unlock(&vol->volume_label_lock);
	kfree(old);
	return 0;
}

/* ------------------------------------------------------------- volume size */

#if DBG
int ngc_resize_fault;
#endif

/* $Bitmap bytes for @nr clusters: whole 8-byte units, as format writes it. */
static s64 ngc_bmp_bytes(s64 nr)
{
	return ((nr + 63) >> 6) << 3;
}

/* The allocator's per-page free-bit hints, grown for @nr clusters (the counts are redone by ngc_recount_free). */
static int ngc_grow_lcn_hints(struct ntfs_volume *vol, s64 old_nr, s64 nr)
{
	size_t oldp = (size_t)((((old_nr + 7) >> 3) + PAGE_SIZE - 1) >> PAGE_SHIFT);
	size_t newp = (size_t)((((nr + 7) >> 3) + PAGE_SIZE - 1) >> PAGE_SHIFT);
	unsigned int *a, *old;

	if (newp <= oldp)
		return 0;
	a = kvmalloc_array(newp, sizeof(*a), GFP_NOFS);
	if (!a)
		return -ENOMEM;
	memcpy(a, vol->lcn_empty_bits_per_page, oldp * sizeof(*a));
	memset(a + oldp, 0, (newp - oldp) * sizeof(*a));
	down_write(&vol->lcnbmp_lock);
	old = vol->lcn_empty_bits_per_page;
	vol->lcn_empty_bits_per_page = a;
	up_write(&vol->lcnbmp_lock);
	kvfree(old);
	return 0;
}

/* The free-cluster count and the per-page hints, read again from $Bitmap for the current nr_clusters. */
static void ngc_recount_free(struct ntfs_volume *vol)
{
	down_write(&vol->lcnbmp_lock);
	NVolClearFreeClusterKnown(vol);
	get_nr_free_clusters(vol);
	up_write(&vol->lcnbmp_lock);
}

/* Boot sector's sector count (0 if it cannot be read). */
static u64 ngc_boot_sectors(struct ngc_vol *v)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	u8 *buf = kmalloc(vol->sector_size, GFP_NOFS);
	u64 n = 0;

	if (buf && !kshim_dev_rw(v->bdev, 0, 0, buf, vol->sector_size))
		n = le64_to_cpu(((struct ntfs_boot_sector *)buf)->number_of_sectors);
	kfree(buf);
	return n;
}

/*
 * Writes the boot sector with @sectors as its sector count, and its copy in the sector after the
 * volume (where Windows and the core look for it), through the journal like any metadata write.
 */
static int ngc_write_boot(struct ngc_vol *v, u64 sectors, u8 *buf)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	u32 ss = vol->sector_size;
	int err;

	err = kshim_dev_rw(v->bdev, 0, 0, buf, ss);
	if (!err) {
		((struct ntfs_boot_sector *)buf)->number_of_sectors = cpu_to_le64(sectors);
		err = kshim_dev_rw(v->bdev, 1, sectors * ss, buf, ss);
		if (!err) {
			kshim_mapping_update(v->bdev->bd_mapping, sectors * ss, buf, ss);
			err = kshim_dev_rw(v->bdev, 1, 0, buf, ss);
		}
		if (!err)
			kshim_mapping_update(v->bdev->bd_mapping, 0, buf, ss);
	}
	return err;
}

/*
 * A resize failed after it changed metadata in memory: nothing more may be written, whatever the
 * error, so the core stops writing for good (ngc_writeback_failed would retry out-of-space and
 * out-of-memory).  While the journal holds every metadata write, the disk still has the last
 * committed state, as after a power cut, and mounts read-write again: the volume is not marked for
 * repair.  Without the journal, or once it wrote in place or stopped, the disk may hold part of
 * the change, and the volume is marked for repair.
 */
static int ngc_resize_failed(struct ngc_vol *v, int err)
{
	if (kshim_jnl_in_place(v->bdev)) {
		printk(KERN_ERR "ngc: volume resize failed %d; part of it may be on the disk\n", err);
		ngc_writeback_failed(v, -EIO);
		return err;
	}
	printk(KERN_ERR "ngc: volume resize failed %d; the disk keeps the last committed state, "
	       "nothing is written until the next mount\n", err);
	if (!v->failed)
		kshim_log_volume_failed(v->bdev, err);
	v->failed = 1;
	v->sb->s_flags |= SB_RDONLY;
	return err;
}

/* $Bitmap pages one resize step may change: half of what makes a commit, so that the step, its MFT
 * record and the bits of its own clusters fit the journal (0 without the journal: no steps). */
static s64 ngc_step_pages(struct ngc_vol *v)
{
	if (!v->bdev->jnl)
		return 0;
	return max_t(s64, 1, (s64)(ngc_commit_threshold(v) / 2));
}

/*
 * Grows $Bitmap from @from to @to bytes, the new bytes zero, with real clusters below the old end
 * (a sparse $Bitmap is invalid).  With the journal it grows in steps that each fit one commit, and
 * commits after each but the last: one large transaction would not fit the journal and would go to
 * the disk in place.  Every state between the steps is the old size with a larger $Bitmap.
 */
static int ngc_grow_bitmap(struct ngc_vol *v, s64 from, s64 to)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct inode *bvi = vol->lcnbmp_ino;
	struct ntfs_inode *bni = NTFS_I(bvi);
	s64 pages = ngc_step_pages(v), cur = from, end, n = 0, steps;
	int err = 0;

	steps = pages ? (to - from + (pages << PAGE_SHIFT) - 1) / (pages << PAGE_SHIFT) : 1;
	while (cur < to) {
		end = pages ? min_t(s64, to, round_down(cur, PAGE_SIZE) + (pages << PAGE_SHIFT)) : to;
		mutex_lock(&bni->mrec_lock);
		err = ntfs_attr_truncate_i(bni, end, HOLES_NO);
		mutex_unlock(&bni->mrec_lock);
		if (err)
			break;
		i_size_write(bvi, end);
		err = ntfs_attr_set(bni, cur, end - cur, 0);
		if (!err && bni->initialized_size < end) {
			mutex_lock(&bni->mrec_lock);
			err = ntfs_attr_set_initialized_size(bni, end);
			mutex_unlock(&bni->mrec_lock);
		}
		mark_inode_dirty(bvi);
		if (err)
			break;
		cur = end;
		n++;
		if (cur < to && pages) {
			err = ngc_commit(v);
			if (err)
				break;
			printk(KERN_INFO "ngc: extend: $Bitmap step %lld of %lld committed\n", n, steps);
		}
	}
	return err;
}

/* Clears the bits [@from, @to) of $Bitmap, committing after each step but the last (see ngc_grow_bitmap). */
static int ngc_clear_bits_stepped(struct ngc_vol *v, s64 from, s64 to)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	s64 bits = ngc_step_pages(v) << (PAGE_SHIFT + 3), end;
	int err = 0;

	while (from < to) {
		end = bits ? min_t(s64, to, round_down(from, 8LL << PAGE_SHIFT) + bits) : to;
		down_write(&vol->lcnbmp_lock);
		err = ntfs_bitmap_clear_run(vol->lcnbmp_ino, from, end - from);
		up_write(&vol->lcnbmp_lock);
		if (err)
			break;
		from = end;
		if (from < to && bits) {
			err = ngc_commit(v);
			if (err)
				break;
		}
	}
	return err;
}

/*
 * Grows the volume to @sectors sectors on a device now @dev_size bytes long (FSCTL_EXTEND_VOLUME):
 * $Bitmap grows (its clusters come from the old free space, in journal-sized steps), the new
 * clusters are free, the padding bits past the last cluster move to the new end, then the boot
 * sector and its copy.
 */
static int ngc_extend_impl(ngc_vol *v, unsigned long long sectors, unsigned long long dev_size)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct inode *bvi = vol->lcnbmp_ino;
	struct ntfs_inode *bni = NTFS_I(bvi);
	u32 ss = vol->sector_size;
	s64 old_nr = vol->nr_clusters, nr, old_bytes, bytes, pad_end, blk_end;
	u64 old_sectors;
	u8 *boot;
	int err;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if (v->failed)
		return -EIO;
	if (!sectors || sectors > (U64_MAX / ss) - 1 || (sectors + 1) * ss > dev_size)
		return -EINVAL;
	/* A device that large would not mount again, and its page indexes would wrap now. */
	if (dev_size >= NGC_MAX_DEVICE_BYTES)
		return -EFBIG;
	old_sectors = ngc_boot_sectors(v);
	if (!old_sectors)
		return -EIO;
	/* As on Windows: fewer clusters is invalid, the same number changes nothing. */
	nr = (s64)((sectors * ss) >> vol->cluster_size_bits);
	if (nr <= old_nr)
		return nr == old_nr ? 0 : -EINVAL;
	/* Windows' NTFS limit, and the 32-bit cluster numbers of the NT interfaces. */
	if (nr > 0xffffffffLL)
		return -EFBIG;

	/* Everything that can run out of memory comes before the first change. */
	boot = kmalloc(ss, GFP_NOFS);
	if (!boot)
		return -ENOMEM;
	err = ngc_mark_dirty(v);
	if (!err)
		err = ngc_before_alloc(v);
	if (err)
		goto out;
	if (ngc_resize_fault == 5)
		kshim_jnl_degrade(v->bdev);
	/* A degraded journal writes in place: no resize until a commit has made it whole again. */
	if (kshim_jnl_degraded(v->bdev)) {
		err = -ENOMEM;
		goto out;
	}
	/* From here every metadata write goes through the journal or fails: none goes in place. */
	kshim_jnl_strict(v->bdev, 1);
	if (ngc_resize_fault == 6)
		kshim_jnl_arm_fault(v->bdev, KJ_FAULT_CAPTURE);

	/* The partition grew under the mount: device I/O may reach its new end. */
	v->bdev->size = dev_size;
	v->bdev->bd_inode->i_size = dev_size;
	vol->nr_blocks = dev_size >> v->sb->s_blocksize_bits;

	{
		old_bytes = i_size_read(bvi);
		bytes = ngc_bmp_bytes(nr);
		if (bytes > old_bytes) {
			/*
			 * Real clusters (a sparse $Bitmap is invalid), allocated below the old end.  The free
			 * space is checked first, so that a full volume refuses cleanly instead of failing
			 * half way.
			 */
			s64 need = (s64)((round_up((u64)bytes, vol->cluster_size) - (u64)bni->allocated_size)
					 >> vol->cluster_size_bits);
			if (need > 0 && atomic64_read(&vol->free_clusters) - atomic64_read(&vol->dirty_clusters) < need + 16) {
				err = -ENOSPC;
				goto out;
			}
			err = ngc_grow_bitmap(v, old_bytes, bytes);
			if (err)
				goto failed;
		}
		err = ngc_grow_lcn_hints(vol, old_nr, nr);
		if (err)
			goto failed;
		/*
		 * Until the last commit the volume has its old size, so the bits past its last cluster are
		 * padding: set to the end of the 8 KiB $Bitmap block that holds the last cluster (as ntfsck
		 * expects them; the grown bytes there are zero now), zero after it.  Bits past that block
		 * (an oversized $Bitmap that an interrupted extend left) become free clusters now.
		 */
		pad_end = min_t(s64, nr, round_up(old_nr, 64));
		blk_end = round_up(((old_nr - 1) >> 3) + 1, 8192) << 3;
		if (bytes > old_bytes && min_t(s64, bytes << 3, blk_end) > (old_bytes << 3)) {
			down_write(&vol->lcnbmp_lock);
			err = ntfs_bitmap_set_bits_in_run(bvi, old_bytes << 3, min_t(s64, bytes << 3, blk_end) - (old_bytes << 3), 1);
			up_write(&vol->lcnbmp_lock);
			if (err)
				goto failed;
		}
		err = ngc_clear_bits_stepped(v, max_t(s64, pad_end, blk_end), min_t(s64, nr, (s64)old_bytes << 3));
		if (err)
			goto failed;
	}
	if (ngc_resize_fault == 1) {
		err = -EIO;
		goto failed;
	}
	if (ngc_resize_fault == 4)
		kshim_jnl_arm_fault(v->bdev, KJ_FAULT_APPLY);
	/*
	 * $Bitmap first: an interruption after this commit leaves the old size, its padding intact,
	 * with a $Bitmap larger than it needs, which every reader and checker accepts.  The old
	 * padding (at most one 8 KiB block) then becomes free clusters, the new padding word is set
	 * and the boot sector follows, all in the last commit.  Once the clusters are in use in
	 * memory, a failed write leaves the volume read-only.
	 */
	err = ngc_commit(v);
	if (!err && ngc_resize_fault == 2)
		err = -EIO;
	if (!err) {
		down_write(&vol->lcnbmp_lock);
		if (min_t(s64, nr, max_t(s64, pad_end, blk_end)) > old_nr)
			err = ntfs_bitmap_clear_run(bvi, old_nr, min_t(s64, nr, max_t(s64, pad_end, blk_end)) - old_nr);
		if (!err && (nr & 63))
			err = ntfs_bitmap_set_bits_in_run(bvi, nr, 64 - (nr & 63), 1);
		if (!err)
			vol->nr_clusters = nr;
		up_write(&vol->lcnbmp_lock);
		if (!err)
			ngc_recount_free(vol);
	}
	if (!err)
		err = ngc_write_boot(v, sectors, boot);
	if (!err && ngc_resize_fault == 7)
		kshim_jnl_arm_fault(v->bdev, KJ_FAULT_APPLY);
	if (!err)
		err = ngc_commit(v);
	if (!err)
		goto out;
failed:
	err = ngc_resize_failed(v, err);
out:
	kshim_jnl_strict(v->bdev, 0);
	kfree(boot);
	return err;
}

/* A shrink to @sectors sectors leaves fewer clusters, and at least one: 0, else -EINVAL. */
int ngc_shrink_valid(ngc_vol *v, unsigned long long sectors)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	s64 nr;

	if (!sectors || sectors > U64_MAX / vol->sector_size)
		return -EINVAL;
	nr = (s64)((sectors * vol->sector_size) >> vol->cluster_size_bits);
	return nr >= 1 && nr < vol->nr_clusters ? 0 : -EINVAL;
}

/*
 * The shrink check: 0 when every cluster from where a volume of @sectors sectors ends is free,
 * so that ngc_shrink can drop them; -ENOSPC when one is in use; -EINVAL when @sectors does not
 * shrink the volume.  Sets *@first_used to the first cluster in use there (or nr_clusters).
 */
static int ngc_shrink_check_locked(struct ngc_vol *v, u64 sectors, s64 *first_used)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct address_space *mapping = vol->lcnbmp_ino->i_mapping;
	s64 nr, lcn;
	int err;

	*first_used = vol->nr_clusters;
	err = ngc_shrink_valid(v, sectors);
	if (err)
		return err;
	nr = (s64)((sectors * vol->sector_size) >> vol->cluster_size_bits);
	for (lcn = nr; lcn < vol->nr_clusters; ) {
		pgoff_t index = (pgoff_t)(lcn >> (3 + PAGE_SHIFT));
		struct folio *folio = read_mapping_folio(mapping, index, NULL);
		s64 page_end = ((s64)index + 1) << (3 + PAGE_SHIFT);
		u8 *kaddr;

		if (IS_ERR(folio))
			return PTR_ERR(folio);
		kaddr = kmap_local_folio(folio, 0);
		for (; lcn < page_end && lcn < vol->nr_clusters; lcn++) {
			u64 bit = (u64)lcn & ((8ULL << PAGE_SHIFT) - 1);
			if (kaddr[bit >> 3] & (1 << (bit & 7))) {
				*first_used = lcn;
				break;
			}
		}
		kunmap_local(kaddr);
		folio_put(folio);
		if (*first_used != vol->nr_clusters)
			return -ENOSPC;
	}
	return 0;
}

/*
 * Shrinks the volume to @sectors sectors (FSCTL_SHRINK_VOLUME ShrinkCommit) when the clusters past
 * the new end are all free (-ENOSPC otherwise: this driver moves no data): padding bits at the new
 * end, $Bitmap truncated to the new size, then the boot sector and its copy after the new end.
 * The device keeps its size; the caller shrinks the partition afterwards.
 */
static int ngc_shrink_impl(ngc_vol *v, unsigned long long sectors)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct inode *bvi = vol->lcnbmp_ino;
	struct ntfs_inode *bni = NTFS_I(bvi);
	u32 ss = vol->sector_size;
	s64 nr, first, bytes;
	u8 *boot;
	int err;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if (v->failed)
		return -EIO;
	boot = kmalloc(ss, GFP_NOFS);
	if (!boot)
		return -ENOMEM;
	err = ngc_mark_dirty(v);
	if (!err && kshim_jnl_degraded(v->bdev))
		err = -ENOMEM;	/* a degraded journal writes in place: see ngc_extend_impl */
	if (err)
		goto out;
	kshim_jnl_strict(v->bdev, 1);
	nr = (s64)((sectors * ss) >> vol->cluster_size_bits);
	down_write(&vol->lcnbmp_lock);
	err = ngc_shrink_check_locked(v, sectors, &first);
	if (!err) {
		err = ntfs_bitmap_set_bits_in_run(bvi, nr, round_up(nr, 64) - nr, 1);
		if (!err) {
			vol->nr_clusters = nr;
			/* The allocator's zones inside the volume again, the MFT zone halved as at mount. */
			while (vol->mft_zone_end >= nr && vol->mft_zone_end > vol->mft_lcn)
				vol->mft_zone_end = vol->mft_lcn + (vol->mft_zone_end - vol->mft_lcn) / 2;
			if (vol->mft_zone_pos >= vol->mft_zone_end)
				vol->mft_zone_pos = vol->mft_zone_start;
			if (vol->data1_zone_pos >= nr || vol->data1_zone_pos < vol->mft_zone_end)
				vol->data1_zone_pos = vol->mft_zone_end;
			if (vol->data2_zone_pos >= vol->mft_zone_start)
				vol->data2_zone_pos = 0;
		}
	}
	up_write(&vol->lcnbmp_lock);
	if (err)
		goto out;
	/*
	 * In three commits, each leaving a volume every reader mounts (a checker reports the bitmap
	 * bits of the first state and corrects them): the padding bits (at the old size a few free
	 * clusters marked in use), the boot sector (the new size with a $Bitmap larger than it
	 * needs), then the shorter $Bitmap.
	 */
	ngc_recount_free(vol);
	err = ngc_commit(v);
	if (!err && ngc_resize_fault == 3)
		err = -EIO;
	if (!err)
		err = ngc_write_boot(v, sectors, boot);
	if (!err)
		err = ngc_commit(v);
	bytes = ngc_bmp_bytes(nr);
	if (!err && bytes < i_size_read(bvi)) {
		/* The cached pages lose the bytes past the new end: the free count reads whole pages. */
		truncate_setsize(bvi, bytes);
		mutex_lock(&bni->mrec_lock);
		err = ntfs_attr_truncate_i(bni, bytes, HOLES_NO);
		mutex_unlock(&bni->mrec_lock);
		mark_inode_dirty(bvi);
		if (!err) {
			ngc_recount_free(vol);
			err = ngc_commit(v);
		}
	}
	if (err)
		err = ngc_resize_failed(v, err);
out:
	kshim_jnl_strict(v->bdev, 0);
	kfree(boot);
	return err;
}

int ngc_extend(ngc_vol *v, unsigned long long sectors, unsigned long long dev_size)
{
	kshim_dio_drain(v->bdev);
	return ngc_extend_impl(v, sectors, dev_size);
}

int ngc_shrink(ngc_vol *v, unsigned long long sectors)
{
	kshim_dio_drain(v->bdev);
	return ngc_shrink_impl(v, sectors);
}

/* FSCTL_GET_NTFS_VOLUME_DATA's values. */
void ngc_ntfs_data(ngc_vol *v, struct ngc_ntfsdata *d)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	s64 fc = atomic64_read(&vol->free_clusters);

	memset(d, 0, sizeof(*d));
	d->serial = vol->serial_no;
	d->sectors = ngc_boot_sectors(v);
	d->total_clusters = vol->nr_clusters;
	d->free_clusters = fc > 0 ? fc : 0;
	d->bytes_per_sector = vol->sector_size;
	d->bytes_per_cluster = vol->cluster_size;
	d->bytes_per_record = vol->mft_record_size;
	d->mft_valid_data = NTFS_I(vol->mft_ino)->initialized_size;
	d->mft_lcn = vol->mft_lcn;
	d->mft2_lcn = vol->mftmirr_lcn;
	d->mft_zone_start = vol->mft_zone_start;
	d->mft_zone_end = vol->mft_zone_end;
	d->major = vol->major_ver;
	d->minor = vol->minor_ver;
}

/* Copies $Bitmap bytes [@off, @off+@len) (FSCTL_GET_VOLUME_BITMAP); bytes past its end read as zero. */
int ngc_read_bitmap(ngc_vol *v, unsigned long long off, unsigned int len, void *buf)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct address_space *mapping = vol->lcnbmp_ino->i_mapping;
	u64 size = (u64)ngc_bmp_bytes(vol->nr_clusters);
	u8 *out = buf;
	int err = 0;

	memset(buf, 0, len);
	down_read(&vol->lcnbmp_lock);
	while (len && off < size) {
		pgoff_t index = (pgoff_t)(off >> PAGE_SHIFT);
		unsigned int in = (unsigned int)(off & (PAGE_SIZE - 1));
		unsigned int n = (unsigned int)min_t(u64, min_t(u64, PAGE_SIZE - in, len), size - off);
		struct folio *folio = read_mapping_folio(mapping, index, NULL);
		u8 *kaddr;

		if (IS_ERR(folio)) {
			err = PTR_ERR(folio);
			break;
		}
		kaddr = kmap_local_folio(folio, 0);
		memcpy(out, kaddr + in, n);
		kunmap_local(kaddr);
		folio_put(folio);
		off += n;
		out += n;
		len -= n;
	}
	up_read(&vol->lcnbmp_lock);
	return err;
}

/* ------------------------------------------------------------- reparse points */

/* Nonzero if @n (its file) is a reparse point. */
int ngc_is_reparse(ngc_node *n)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	return !!(ni->flags & FILE_ATTR_REPARSE_POINT);
}

/* The raw $REPARSE_POINT value (REPARSE_DATA_BUFFER layout); -ENODATA when there is none. */
int ngc_get_reparse(ngc_node *n, void **out, unsigned int *len)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	void *buf = NULL;
	s64 size = 0;
	*out = NULL;
	*len = 0;
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	mutex_lock(&ni->mrec_lock);
	if ((ni->flags & FILE_ATTR_REPARSE_POINT) && ntfs_attr_exist(ni, AT_REPARSE_POINT, AT_UNNAMED, 0))
		buf = ntfs_attr_readall(ni, AT_REPARSE_POINT, AT_UNNAMED, 0, &size);
	mutex_unlock(&ni->mrec_lock);
	if (!buf)
		return -ENODATA;
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	if (size < 8 || size > 16 * 1024) {
		kvfree(buf);
		return -EIO;
	}
	*out = buf;
	*len = (unsigned int)size;
	return 0;
}

/* $Extend\$Reparse:$R, the index of reparse points by (tag, file reference). */
static struct ntfs_index_context *ngc_reparse_index(struct ntfs_volume *vol)
{
	static __le16 rname[] = { cpu_to_le16('$'), cpu_to_le16('R'), cpu_to_le16('e'), cpu_to_le16('p'),
				  cpu_to_le16('a'), cpu_to_le16('r'), cpu_to_le16('s'), cpu_to_le16('e') };
	struct ntfs_index_context *xr = NULL;
	struct ntfs_name *name = NULL;
	struct inode *dir, *vi;
	u64 mref;

	dir = ntfs_iget(vol->sb, FILE_Extend);
	if (IS_ERR(dir))
		return NULL;
	mutex_lock_nested(&NTFS_I(dir)->mrec_lock, NTFS_EXTEND_MUTEX_PARENT);
	mref = ntfs_lookup_inode_by_name(NTFS_I(dir), rname, 8, &name);
	mutex_unlock(&NTFS_I(dir)->mrec_lock);
	kfree(name);
	iput(dir);
	if (IS_ERR_MREF(mref))
		return NULL;
	vi = ntfs_iget(vol->sb, MREF(mref));
	if (IS_ERR(vi))
		return NULL;
	xr = ntfs_index_ctx_get(NTFS_I(vi), reparse_index_name, 2);
	if (!xr)
		iput(vi);
	return xr;
}

/* Removes the $REPARSE_POINT attribute itself (the index entry is handled by the caller). */
static int ngc_reparse_attr_rm(struct ntfs_inode *ni)
{
	struct inode *rp = ntfs_attr_iget(VFS_I(ni), AT_REPARSE_POINT, AT_UNNAMED, 0);
	int err;
	if (IS_ERR(rp))
		return PTR_ERR(rp);
	err = ntfs_attr_rm(NTFS_I(rp));
	iput(rp);
	return err;
}

/*
 * After a reparse point change: the inode type the core would give the file when it loads it
 * (a junction or symlink loads as a symlink), so lookups and listings match a later reload.
 */
static void ngc_reparse_retype(struct ntfs_inode *ni)
{
	struct inode *vi = VFS_I(ni);
	unsigned int mode = 0;
	if (!(ni->flags & FILE_ATTR_REPARSE_POINT) || ntfs_parse_reparse(ni, &mode) || !mode)
		mode = ngc_record_is_dir_locked(ni) ? S_IFDIR : S_IFREG;
	if ((vi->i_mode & S_IFMT) == mode)
		return;
	vi->i_mode = (vi->i_mode & ~S_IFMT) | mode;
	ntfs_set_vfs_operations(vi, vi->i_mode, 0);
	/* Files the core created carry their mode in a $LXMOD EA, which a reload applies first. */
	if (NInoHasEA(ni))
		ntfs_ea_set_wsl_inode(vi, 0, NULL, NTFS_EA_MODE);
}

/* Removes the $Reparse index entry (tag, file reference) of @ni if there is one. */
static int ngc_reparse_unindex(struct ntfs_inode *ni, struct ntfs_index_context *xr, __le32 tag)
{
	struct reparse_index_key key;
	key.reparse_tag = tag;
	key.file_id = cpu_to_le64(MK_MREF(ni->mft_no, ni->seq_no));
	ntfs_index_ctx_reinit(xr);
	if (ntfs_index_lookup(&key, sizeof(key), xr))
		return 0;
	return ntfs_index_rm(xr);
}

/*
 * Gives @n the reparse data @data (validated by the caller) and indexes it in $Reparse.  An existing
 * reparse point must carry the same tag (-EXDEV otherwise) and is replaced.  Data the core would
 * refuse when it loads the file, or data too large to stay resident, is rolled back (-EINVAL,
 * -EFBIG).  Any failure after the old reparse point is gone leaves the file without one.
 */
int ngc_set_reparse(ngc_vol *v, ngc_node *n, const void *data, unsigned int len)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n), *xrni;
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct ntfs_index_context *xr;
	struct {
		struct index_entry_header header;
		struct reparse_index_key key;
		__le32 filling;
	} __packed ie;
	__le32 tag = ((const struct reparse_point *)data)->reparse_tag;
	struct inode *rp;
	unsigned int mode;
	int err;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if (NInoAttr(ni) || len < 8 || len > 16 * 1024 || ni->mft_no < FILE_first_user)
		return -EINVAL;
	if (vol->major_ver < 3)
		return -EOPNOTSUPP;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	xr = ngc_reparse_index(vol);
	if (!xr)
		return -EIO;
	xrni = xr->idx_ni;
	if (xrni == ni) {
		err = -EINVAL;
		goto put;
	}
	mutex_lock(&ni->mrec_lock);
	mutex_lock_nested(&xrni->mrec_lock, NTFS_EXTEND_MUTEX_PARENT);
	if (ntfs_attr_exist(ni, AT_REPARSE_POINT, AT_UNNAMED, 0)) {
		void *old;
		s64 size = 0;
		__le32 otag;
		old = ntfs_attr_readall(ni, AT_REPARSE_POINT, AT_UNNAMED, 0, &size);
		if (IS_ERR_OR_NULL(old) || size < 4) {
			err = IS_ERR(old) ? PTR_ERR(old) : -EIO;
			if (!IS_ERR_OR_NULL(old))
				kvfree(old);
			goto out;
		}
		otag = ((struct reparse_point *)old)->reparse_tag;
		kvfree(old);
		if (otag != tag) {
			err = -EXDEV;
			goto out;
		}
		err = ngc_reparse_unindex(ni, xr, otag);
		if (!err)
			err = ngc_reparse_attr_rm(ni);
		if (err)
			goto fail;
	}
	err = ntfs_attr_add(ni, AT_REPARSE_POINT, AT_UNNAMED, 0, (u8 *)data, len);
	if (err)
		goto fail;
	rp = ntfs_attr_iget(VFS_I(ni), AT_REPARSE_POINT, AT_UNNAMED, 0);
	if (IS_ERR(rp)) {
		err = PTR_ERR(rp);
		goto fail;
	}
	/* The core reads the tag for the parent's index entry from a resident value only. */
	err = NInoNonResident(NTFS_I(rp)) ? -EFBIG : 0;
	iput(rp);
	if (err)
		goto fail;
	ni->flags |= FILE_ATTR_REPARSE_POINT;
	err = ntfs_parse_reparse(ni, &mode);
	if (err) {
		err = -EINVAL;
		goto fail;
	}
	memset(&ie, 0, sizeof(ie));
	ie.header.data.vi.data_offset = cpu_to_le16(sizeof(struct index_entry_header) + sizeof(ie.key));
	ie.header.length = cpu_to_le16(sizeof(ie));
	ie.header.key_length = cpu_to_le16(sizeof(ie.key));
	ie.key.reparse_tag = tag;
	ie.key.file_id = cpu_to_le64(MK_MREF(ni->mft_no, ni->seq_no));
	ntfs_index_ctx_reinit(xr);
	err = ntfs_ie_add(xr, (struct index_entry *)&ie);
	if (!err)
		goto done;
fail:
	if (ntfs_attr_exist(ni, AT_REPARSE_POINT, AT_UNNAMED, 0))
		ngc_reparse_attr_rm(ni);
	ni->flags &= ~FILE_ATTR_REPARSE_POINT;
done:
	ngc_reparse_retype(ni);
	NInoSetFileNameDirty(ni);
	mark_mft_record_dirty(ni);
	mark_mft_record_dirty(xrni);
out:
	mutex_unlock(&xrni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);
	mark_inode_dirty(VFS_I(ni));
put:
	ntfs_index_ctx_put(xr);
	iput(VFS_I(xrni));
	return err;
}

/* Removes the reparse point of @n if its tag is @tag (-EXDEV otherwise, -ENODATA if none). */
int ngc_delete_reparse(ngc_vol *v, ngc_node *n, unsigned int tag)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	void *old;
	unsigned int len;
	int err;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if (NInoAttr(ni))
		return -EINVAL;
	err = ngc_get_reparse(n, &old, &len);
	if (err)
		return err;
	err = le32_to_cpu(((struct reparse_point *)old)->reparse_tag) == tag ? 0 : -EXDEV;
	kvfree(old);
	if (err)
		return err;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	mutex_lock(&ni->mrec_lock);
	/* Clears the flag only once the index entry is gone. */
	err = ntfs_delete_reparse_index(ni);
	if (err > 0)
		err = 0;
	if (!err)
		err = ngc_reparse_attr_rm(ni);
	ngc_reparse_retype(ni);
	NInoSetFileNameDirty(ni);
	mark_mft_record_dirty(ni);
	mutex_unlock(&ni->mrec_lock);
	mark_inode_dirty(VFS_I(ni));
	return err;
}

/* ------------------------------------------------------------- short (8.3) names */

/* The value of the $FILE_NAME attribute the search context stands on. */
static struct file_name_attr *ngc_fn(struct ntfs_attr_search_ctx *ctx)
{
	return (struct file_name_attr *)((u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset));
}

/* Names that count as links for NT: every $FILE_NAME except the DOS-only ones. */
int ngc_links(ngc_node *n)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	struct ntfs_attr_search_ctx *ctx;
	int links = 0;
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	mutex_lock(&ni->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (ctx) {
		while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx))
			if (!ctx->attr->non_resident && ngc_fn(ctx)->file_name_type != FILE_NAME_DOS)
				links++;
		ntfs_attr_put_search_ctx(ctx);
	}
	mutex_unlock(&ni->mrec_lock);
	return links ? links : 1;
}

/* A name of @n (not a DOS-only one) and its directory's MFT number: for paths from a file ID. */
int ngc_parent_name(ngc_node *n, unsigned long long *parent, unsigned short *out, unsigned int *len)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	struct ntfs_attr_search_ctx *ctx;
	int err = -ENOENT;
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	mutex_lock(&ni->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		mutex_unlock(&ni->mrec_lock);
		return -ENOMEM;
	}
	while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		struct file_name_attr *fn = ngc_fn(ctx);
		if (ctx->attr->non_resident || fn->file_name_type == FILE_NAME_DOS)
			continue;
		memcpy(out, fn->file_name, fn->file_name_length * sizeof(__le16));
		*len = fn->file_name_length;
		*parent = MREF_LE(fn->parent_directory);
		err = 0;
		break;
	}
	ntfs_attr_put_search_ctx(ctx);
	mutex_unlock(&ni->mrec_lock);
	return err;
}

/* The DOS-only name of @n in directory @parent_mref, or *len = 0 when it has none. */
static int ngc_short_name_impl(ngc_node *n, unsigned long long parent_mref, unsigned short *out, unsigned int *len)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n);
	struct ntfs_attr_search_ctx *ctx;
	*len = 0;
	if (NInoAttr(ni))
		ni = ni->ext.base_ntfs_ino;
	mutex_lock(&ni->mrec_lock);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		mutex_unlock(&ni->mrec_lock);
		return -ENOMEM;
	}
	while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		struct file_name_attr *fn = ngc_fn(ctx);
		if (ctx->attr->non_resident || fn->file_name_type != FILE_NAME_DOS || fn->file_name_length > 12 ||
		    MREF_LE(fn->parent_directory) != MREF(parent_mref))
			continue;
		memcpy(out, fn->file_name, fn->file_name_length * sizeof(__le16));
		*len = fn->file_name_length;
		break;
	}
	ntfs_attr_put_search_ctx(ctx);
	mutex_unlock(&ni->mrec_lock);
	return 0;
}

/* Sets the namespace of @lfn's $FILE_NAME in @ni and of its index entry in @dir_ni (caller holds both locks). */
static int ngc_set_fn_type(struct ntfs_inode *ni, struct ntfs_inode *dir_ni, const struct file_name_attr *lfn,
		int lfn_len, u64 mref, u8 type)
{
	struct ntfs_attr_search_ctx *ctx = ntfs_attr_get_search_ctx(ni, NULL);
	struct ntfs_index_context *icx;
	int err = -ENOENT;
	if (!ctx)
		return -ENOMEM;
	while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		struct file_name_attr *fn = ngc_fn(ctx);
		if (ctx->attr->non_resident || fn->parent_directory != lfn->parent_directory ||
		    fn->file_name_length != lfn->file_name_length ||
		    memcmp(fn->file_name, lfn->file_name, lfn->file_name_length * sizeof(__le16)) ||
		    fn->file_name_type == FILE_NAME_DOS)
			continue;
		fn->file_name_type = type;
		mark_mft_record_dirty(ctx->ntfs_ino);
		err = 0;
		break;
	}
	ntfs_attr_put_search_ctx(ctx);
	if (err)
		return err;
	icx = ntfs_index_ctx_get(dir_ni, I30, 4);
	if (!icx)
		return -ENOMEM;
	err = ntfs_index_lookup(lfn, lfn_len, icx);
	if (!err && le64_to_cpu(icx->entry->data.dir.indexed_file) == mref) {
		icx->entry->key.file_name.file_name_type = type;
		ntfs_index_entry_mark_dirty(icx);
	} else if (!err) {
		err = -ENOENT;
	}
	ntfs_index_ctx_put(icx);
	return err;
}

/*
 * Gives the only name @lname of @n (in @dirn) the DOS name @sname, as NTFS on Windows does for a
 * long name that is not a valid 8.3 name: a DOS $FILE_NAME with its own index entry is added
 * (it counts in the MFT record's link count like any name), and then the long name moves from the
 * POSIX to the Win32 namespace in its $FILE_NAME and its index entry, so that the core's unlink
 * removes the pair.  Files with hard links or with a DOS name already get none.  On any failure
 * the file is left as it was.
 */
static int ngc_add_short_name_impl(ngc_vol *v, ngc_node *dirn, ngc_node *n, const unsigned short *lname, unsigned int llen,
		const unsigned short *sname, unsigned int slen)
{
	struct ntfs_inode *ni = NTFS_I((struct inode *)n), *dir_ni = NTFS_I((struct inode *)dirn);
	struct ntfs_attr_search_ctx *ctx;
	struct file_name_attr *lfn = NULL, *dfn = NULL;
	struct mft_record *mrec;
	int lfn_len = 0, dfn_len, names = 0, err;
	bool other = false;
	u64 mref;

	if (sb_rdonly(v->sb))
		return -EROFS;
	if (NInoAttr(ni) || !slen || slen > 12 || !llen || llen > NTFS_MAX_NAME_LEN)
		return -EINVAL;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	mutex_lock_nested(&ni->mrec_lock, NTFS_INODE_MUTEX_NORMAL);
	mutex_lock_nested(&dir_ni->mrec_lock, NTFS_INODE_MUTEX_PARENT);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!ctx) {
		err = -ENOMEM;
		goto out;
	}
	/* Read-only pass: exactly one name, POSIX or Win32, in this directory, with this spelling. */
	while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		struct file_name_attr *fn = ngc_fn(ctx);
		if (ctx->attr->non_resident)
			continue;
		names++;
		if (lfn || fn->file_name_type == FILE_NAME_DOS || fn->file_name_type == FILE_NAME_WIN32_AND_DOS ||
		    MREF_LE(fn->parent_directory) != dir_ni->mft_no || fn->file_name_length != llen ||
		    memcmp(fn->file_name, lname, llen * sizeof(__le16))) {
			other = true;
			continue;
		}
		lfn_len = le32_to_cpu(ctx->attr->data.resident.value_length);
		lfn = kmemdup(fn, lfn_len, GFP_NOFS);
		if (!lfn) {
			err = -ENOMEM;
			break;
		}
	}
	ntfs_attr_put_search_ctx(ctx);
	if (err || !lfn || other || names != 1)
		goto out;	/* hard links, an existing DOS name, or the name is gone: no short name */
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto out;
	}
	mref = MK_MREF(ni->mft_no, le16_to_cpu(mrec->sequence_number));
	unmap_mft_record(ni);
	dfn_len = sizeof(*dfn) + slen * sizeof(__le16);
	dfn = kzalloc(dfn_len, GFP_NOFS);
	if (!dfn) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(dfn, lfn, sizeof(*dfn));
	dfn->file_name_length = slen;
	dfn->file_name_type = FILE_NAME_DOS;
	memcpy(dfn->file_name, sname, slen * sizeof(__le16));
	err = ntfs_index_add_filename(dir_ni, dfn, mref);
	if (err)
		goto out;
	err = ntfs_attr_add(ni, AT_FILE_NAME, AT_UNNAMED, 0, (u8 *)dfn, dfn_len);
	if (err) {
		ntfs_index_remove(dir_ni, dfn, dfn_len);
		goto out;
	}
	mrec = map_mft_record(ni);
	if (!IS_ERR(mrec)) {
		mrec->link_count = cpu_to_le16(le16_to_cpu(mrec->link_count) + 1);
		if (!S_ISDIR(VFS_I(ni)->i_mode))
			inc_nlink(VFS_I(ni));
		mark_mft_record_dirty(ni);
		unmap_mft_record(ni);
	}
	if (lfn->file_name_type != FILE_NAME_WIN32) {
		err = ngc_set_fn_type(ni, dir_ni, lfn, lfn_len, mref, FILE_NAME_WIN32);
		if (err) {
			/* Undo: the long name stays POSIX, the DOS name goes again. */
			struct ntfs_attr_search_ctx *dctx;
			ngc_set_fn_type(ni, dir_ni, lfn, lfn_len, mref, lfn->file_name_type);
			ntfs_index_remove(dir_ni, dfn, dfn_len);
			dctx = ntfs_attr_get_search_ctx(ni, NULL);
			while (dctx && !ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, dctx)) {
				if (!dctx->attr->non_resident && ngc_fn(dctx)->file_name_type == FILE_NAME_DOS) {
					if (!ntfs_attr_record_rm(dctx)) {
						mrec = map_mft_record(ni);
						if (!IS_ERR(mrec)) {
							mrec->link_count = cpu_to_le16(le16_to_cpu(mrec->link_count) - 1);
							if (!S_ISDIR(VFS_I(ni)->i_mode))
								drop_nlink(VFS_I(ni));
							mark_mft_record_dirty(ni);
							unmap_mft_record(ni);
						}
					}
					break;
				}
			}
			if (dctx)
				ntfs_attr_put_search_ctx(dctx);
		}
	}
out:
	kfree(lfn);
	kfree(dfn);
	mutex_unlock(&dir_ni->mrec_lock);
	mutex_unlock(&ni->mrec_lock);
	return err;
}

/* ------------------------------------------------------------- namespace (Tier 2) */

/*
 * A full volume makes the core's index code fail to move an attribute in or out of its MFT
 * record with -EPERM ("cannot be resident/non-resident"); for a name operation that means no
 * space, not access denied.
 */
static int ngc_index_errno(int err)
{
	return err == -EPERM ? -ENOSPC : err;
}

/*
 * The core gives every new file WSL EAs ($LXUID, $LXGID, $LXMOD and $EA_INFORMATION); no option
 * turns that off.  Files created through NT carry none (as on Windows): remove them in the same
 * transaction, with the packed EA size in the $FILE_NAME attributes and the parent's index entries.
 */
static void ngc_strip_wsl_eas(struct inode *vi)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	struct ntfs_attr_search_ctx *ctx;

	mutex_lock(&ni->mrec_lock);
	if (ntfs_attr_exist(ni, AT_EA, AT_UNNAMED, 0))
		ntfs_attr_remove(ni, AT_EA, AT_UNNAMED, 0);
	if (ntfs_attr_exist(ni, AT_EA_INFORMATION, AT_UNNAMED, 0))
		ntfs_attr_remove(ni, AT_EA_INFORMATION, AT_UNNAMED, 0);
	NInoClearHasEA(ni);
	ctx = ntfs_attr_get_search_ctx(ni, NULL);
	if (ctx) {
		while (!ntfs_attr_lookup(AT_FILE_NAME, AT_UNNAMED, 0, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
			struct file_name_attr *fn = (struct file_name_attr *)((u8 *)ctx->attr +
					le16_to_cpu(ctx->attr->data.resident.value_offset));
			if (!ctx->attr->non_resident && fn->type.ea.packed_ea_size) {
				fn->type.ea.packed_ea_size = 0;
				mark_mft_record_dirty(ctx->ntfs_ino);
			}
		}
		ntfs_attr_put_search_ctx(ctx);
	}
	NInoSetFileNameDirty(ni);
	mutex_unlock(&ni->mrec_lock);
	mark_inode_dirty(vi);
}

static int ngc_create_impl(ngc_vol *v, ngc_node *dirn, const unsigned short *name, unsigned int len, int is_dir, ngc_node **out)
{
	struct inode *dir = (struct inode *)dirn;
	struct dentry *d;
	int err;
	*out = NULL;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (!S_ISDIR(dir->i_mode))
		return -ENOTDIR;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	d = ngc_mkdentry(v, name, len, NULL);
	if (IS_ERR(d))
		return PTR_ERR(d);
	if (is_dir) {
		struct dentry *r = dir->i_op->mkdir(&nop_mnt_idmap, dir, d, S_IFDIR | 0755);
		err = IS_ERR(r) ? PTR_ERR(r) : 0;
	} else {
		err = dir->i_op->create(&nop_mnt_idmap, dir, d, S_IFREG | 0644);
	}
	if (!err && !d->d_inode)
		err = -EIO;
	if (!err && d->d_inode)
		ngc_sdc_drop(v, NTFS_I(d->d_inode)->mft_no);
	if (!err) {
		ngc_strip_wsl_eas(d->d_inode);
		*out = (ngc_node *)d->d_inode;	/* the new inode's reference from new_inode() */
	}
	err = ngc_index_errno(err);
	ngc_freedentry(d);
	return err;
}

/* An attribute or extent inode of record @data, as the core's unlink looks them up. */
static int ngc_test_inode_attr(struct inode *vi, void *data)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	return ni->mft_no == (u64)(uintptr_t)data && (NInoAttr(ni) || ni->nr_extents == -1);
}

/*
 * True when removing a name of @vi frees its record (its last name other than a DOS name) while
 * one of its attribute inodes is still referenced (a named stream being opened or still open).
 * The core's unlink would wait for that reference forever under the volume lock.
 */
static bool ngc_unlink_busy(struct inode *vi)
{
	struct ntfs_inode *ni = NTFS_I(vi);
	return ngc_links((ngc_node *)vi) <= 1 &&
	       kshim_icache_busy(vi->i_sb, ni->mft_no, ngc_test_inode_attr, (void *)(uintptr_t)ni->mft_no);
}

static int ngc_unlink_impl(ngc_vol *v, ngc_node *dirn, const unsigned short *name, unsigned int len, ngc_node *n)
{
	struct inode *dir = (struct inode *)dirn, *vi = (struct inode *)n;
	struct dentry *d;
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (ngc_unlink_busy(vi))
		return -EBUSY;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	d = ngc_mkdentry(v, name, len, vi);
	if (IS_ERR(d))
		return PTR_ERR(d);
	err = S_ISDIR(vi->i_mode) ? dir->i_op->rmdir(dir, d) : dir->i_op->unlink(dir, d);
	ngc_freedentry(d);
	ngc_sdc_drop(v, NTFS_I(vi)->mft_no);
	if (!err) {
		/*
		 * A directory with a reparse point is typed as a link (ngc_fix_type), so the core's
		 * unlink dropped the VFS count once per name (Win32 and DOS) from the 1 a directory
		 * gets: it wrapped and the inode was never freed.  The record's own count decides.
		 */
		struct ntfs_inode *ni = NTFS_I(vi);
		struct mft_record *m;
		mutex_lock(&ni->mrec_lock);
		m = map_mft_record(ni);
		if (!IS_ERR(m)) {
			if (!le16_to_cpu(m->link_count))
				clear_nlink(vi);
			else if ((int)vi->i_nlink <= 0)
				set_nlink(vi, 1);
			unmap_mft_record(ni);
		}
		mutex_unlock(&ni->mrec_lock);
	}
	return err;
}

/* Renames (odir, oname) of @n to (ndir, nname); @target is the inode the new name replaces, or NULL. */
static int ngc_rename_impl(ngc_vol *v, ngc_node *odirn, const unsigned short *oname, unsigned int olen, ngc_node *n,
		ngc_node *ndirn, const unsigned short *nname, unsigned int nlen, ngc_node *target)
{
	struct inode *odir = (struct inode *)odirn, *ndir = (struct inode *)ndirn;
	struct dentry *od, *nd;
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (target && ngc_unlink_busy((struct inode *)target))
		return -EBUSY;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	od = ngc_mkdentry(v, oname, olen, (struct inode *)n);
	nd = ngc_mkdentry(v, nname, nlen, (struct inode *)target);
	if (IS_ERR(od) || IS_ERR(nd)) {
		err = IS_ERR(od) ? PTR_ERR(od) : PTR_ERR(nd);
		ngc_freedentry(IS_ERR(od) ? NULL : od);
		ngc_freedentry(IS_ERR(nd) ? NULL : nd);
		return err;
	}
	err = odir->i_op->rename(&nop_mnt_idmap, odir, od, ndir, nd, 0);
	ngc_freedentry(od);
	ngc_freedentry(nd);
	ngc_sdc_drop(v, NTFS_I((struct inode *)n)->mft_no);
	if (target)
		ngc_sdc_drop(v, NTFS_I((struct inode *)target)->mft_no);
	return ngc_index_errno(err);
}

static int ngc_link_impl(ngc_vol *v, ngc_node *n, ngc_node *ndirn, const unsigned short *nname, unsigned int nlen)
{
	struct inode *ndir = (struct inode *)ndirn, *vi = (struct inode *)n;
	struct dentry *od, *nd;
	int err;
	if (sb_rdonly(v->sb))
		return -EROFS;
	if (S_ISDIR(vi->i_mode))
		return -EPERM;
	err = ngc_mark_dirty(v);
	if (err)
		return err;
	od = ngc_mkdentry(v, nname, nlen, vi);
	nd = ngc_mkdentry(v, nname, nlen, NULL);
	if (IS_ERR(od) || IS_ERR(nd)) {
		err = IS_ERR(od) ? PTR_ERR(od) : PTR_ERR(nd);
		ngc_freedentry(IS_ERR(od) ? NULL : od);
		ngc_freedentry(IS_ERR(nd) ? NULL : nd);
		return err;
	}
	err = ngc_index_errno(ndir->i_op->link(od, ndir, nd));
	/* The core took a reference for the new dentry (ihold); our dentries hold none. */
	if (!err)
		iput(vi);
	ngc_freedentry(od);
	ngc_freedentry(nd);
	return err;
}

static int ngc_any_entry(void *ctx, const unsigned short *name, unsigned int len, unsigned long long ino, unsigned int t)
{
	(void)ino; (void)t;
	if ((len == 1 && name[0] == '.') || (len == 2 && name[0] == '.' && name[1] == '.'))
		return 0;
	*(int *)ctx = 1;
	return 1;
}

/* 1 if the directory has no entries besides . and .., 0 if it has, <0 on error. */
static int ngc_dir_empty_impl(ngc_vol *v, ngc_node *dirn)
{
	if (S_ISLNK(((struct inode *)dirn)->i_mode))
		return ngc_record_is_dir(NTFS_I((struct inode *)dirn)) ? 1 : -ENOTDIR;
	int any = 0, err = ngc_readdir(v, dirn, ngc_any_entry, &any);
	return err < 0 ? err : !any;
}

/* $Extend\$Deleted (see ngapi.h). */
static const unsigned short ngc_deleted_name[] = { '$', 'D', 'e', 'l', 'e', 't', 'e', 'd' };

int ngc_deleted_dir(ngc_vol *v, int create, ngc_node **out)
{
	ngc_node *ext, *d = NULL;
	int err;
	*out = NULL;
	err = ngc_iget(v, FILE_Extend, &ext);
	if (err)
		return err;
	if (!S_ISDIR(((struct inode *)ext)->i_mode)) {
		ngc_put(ext);
		return -ENOTDIR;
	}
	err = ngc_lookup(v, ext, ngc_deleted_name, ARRAY_SIZE(ngc_deleted_name), &d, NULL, NULL);
	if (err == -ENOENT && create) {
		err = ngc_create(v, ext, ngc_deleted_name, ARRAY_SIZE(ngc_deleted_name), 1, &d);
		if (!err) {
			void *sd = NULL;
			unsigned int len = 0;
			/* FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM; the descriptor of $Extend. */
			ngc_set_info(v, d, NULL, 0x2 | 0x4, 0x2 | 0x4);
			if (!ngc_get_security(v, ext, &sd, &len) && sd) {
				ngc_set_security(v, d, sd, len);
				ngc_free(sd);
			}
		}
	}
	ngc_put(ext);
	if (!err && !S_ISDIR(((struct inode *)d)->i_mode)) {
		ngc_put(d);
		err = -ENOTDIR;
	}
	if (!err)
		*out = d;
	return err;
}

/*
 * The purge reads the on-disk index of $Deleted, which is untrusted input (another system, a damaged or crafted
 * volume): an entry is removed only if it names a user record (number 24 and up: never a metadata file or one of the
 * reserved records) whose loaded record is that number (the lookup refuses a reference with a stale sequence number,
 * -EIO, so such an entry is left in place; readdir does not pass the sequence number on) and whose first name has $Deleted itself as its parent (a positive check: a legitimate orphan
 * always has, so a record of a subdirectory of $Extend, such as $RmMetadata\$TxfLog\*, is left alone, as is anything
 * else that is not an orphan of a POSIX delete; a directory that is not empty is refused by the unlink itself).  The
 * work is bounded: the entries counted by a first pass, at most NGC_PURGE_MAX, are looked at once each (entries left in
 * place, and entries a lookup does not find although they are still listed, are skipped by position in later passes),
 * so a corrupt index cannot keep the mount looping.
 */
#define NGC_PURGE_BATCH 64
#define NGC_PURGE_MAX 65536
#define NGC_PURGE_FIRST_USER 24
struct ngc_purge_ctx {
	unsigned int n, skip, seen, total, nogo_n;
	unsigned long long mft[NGC_PURGE_BATCH];
	unsigned short len[NGC_PURGE_BATCH];
	unsigned short name[NGC_PURGE_BATCH][NTFS_MAX_NAME_LEN];
	/* names the last pass could not look up (-ENOENT): when one is still listed it is left in place */
	unsigned short nogo_len[NGC_PURGE_BATCH];
	unsigned short nogo[NGC_PURGE_BATCH][NTFS_MAX_NAME_LEN];
};

static int ngc_purge_dot(const unsigned short *name, unsigned int len)
{
	return (len == 1 && name[0] == '.') || (len == 2 && name[0] == '.' && name[1] == '.');
}

static int ngc_purge_count(void *ctx, const unsigned short *name, unsigned int len, unsigned long long ino, unsigned int t)
{
	struct ngc_purge_ctx *c = ctx;
	(void)ino; (void)t;
	if (!ngc_purge_dot(name, len))
		c->total++;
	return c->total >= NGC_PURGE_MAX;
}

static int ngc_purge_collect(void *ctx, const unsigned short *name, unsigned int len, unsigned long long ino, unsigned int t)
{
	struct ngc_purge_ctx *c = ctx;
	unsigned long long no = ino & 0xffffffffffffULL;
	(void)t;
	if (ngc_purge_dot(name, len) || !len || len > NTFS_MAX_NAME_LEN)
		return 0;
	if (c->seen++ < c->skip)
		return 0;	/* left in place by an earlier pass */
	if (no < NGC_PURGE_FIRST_USER) {
		c->skip++;	/* a metadata or reserved record: never removed, counted as left in place */
		printk(KERN_WARNING "deleted: an entry of $Extend\\$Deleted names record %llu, left alone\n", no);
		return 0;
	}
	for (unsigned int i = 0; i < c->nogo_n; i++) {
		if (c->nogo_len[i] == len && !memcmp(c->nogo[i], name, len * sizeof(*name))) {
			c->skip++;	/* listed, but not found by name in the last pass: left in place */
			return 0;
		}
	}
	c->mft[c->n] = no;
	memcpy(c->name[c->n], name, len * sizeof(*name));
	c->len[c->n++] = (unsigned short)len;
	return c->n == NGC_PURGE_BATCH;
}

/* 0 when @n may go: the record @mft_no it was listed as, a user record, its first name in the directory @deleted_no. */
static int ngc_purge_check(ngc_node *n, unsigned long long mft_no, unsigned long long deleted_no)
{
	unsigned short *nm;
	unsigned long long parent = 0;
	unsigned int len = 0;
	int err;
	if (NTFS_I((struct inode *)n)->mft_no != mft_no || mft_no < NGC_PURGE_FIRST_USER)
		return -EINVAL;
	nm = kmalloc(NTFS_MAX_NAME_LEN * sizeof(*nm), GFP_KERNEL);
	if (!nm)
		return -ENOMEM;
	err = ngc_parent_name(n, &parent, nm, &len);
	kfree(nm);
	if (!err && parent != deleted_no)
		err = -EPERM;
	return err;
}

int ngc_purge_deleted(ngc_vol *v, unsigned int *count)
{
	struct ngc_purge_ctx *c;
	ngc_node *d, *n;
	unsigned int i, done = 0, looked = 0;
	unsigned long long deleted_no;
	int err;
	*count = 0;
	if (sb_rdonly(v->sb))
		return 0;
	err = ngc_deleted_dir(v, 0, &d);
	if (err)
		return err == -ENOENT ? 0 : err;
	c = kmalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		ngc_put(d);
		return -ENOMEM;
	}
	memset(c, 0, offsetof(struct ngc_purge_ctx, mft));
	err = ngc_readdir(v, d, ngc_purge_count, c);
	if (err < 0)
		goto out;
	err = 0;
	if (c->total >= NGC_PURGE_MAX)
		printk(KERN_WARNING "deleted: $Extend\\$Deleted lists %u or more entries, only the first %u are looked at\n",
			c->total, NGC_PURGE_MAX);
	deleted_no = NTFS_I((struct inode *)d)->mft_no;
	while (looked < c->total) {
		int e;
		c->n = 0;
		c->seen = 0;
		e = ngc_readdir(v, d, ngc_purge_collect, c);
		if (e < 0) {
			err = e;
			break;
		}
		c->nogo_n = 0;	/* this pass' collection has used the last one's */
		if (!c->n)
			break;
		for (i = 0; i < c->n && looked < c->total; i++, looked++) {
			e = ngc_lookup(v, d, c->name[i], c->len[i], &n, NULL, NULL);
			if (e == -ENOENT) {
				/* Already gone (the other name of a DOS/Win32 pair went with the first), or still listed
				 * although it cannot be found: remembered, so that the next pass leaves it alone if it is */
				c->nogo_len[c->nogo_n] = c->len[i];
				memcpy(c->nogo[c->nogo_n++], c->name[i], c->len[i] * sizeof(c->name[i][0]));
				continue;
			}
			if (!e) {
				e = ngc_purge_check(n, c->mft[i], deleted_no);
				if (!e)
					e = ngc_unlink(v, d, c->name[i], c->len[i], n);
				ngc_put(n);	/* after an unlink the last reference: the record and its clusters are freed */
			}
			if (e) {
				printk(KERN_WARNING "deleted: an entry of $Extend\\$Deleted (record %llu) not removed (%d)\n", c->mft[i], e);
				c->skip++;	/* still listed: the next pass starts after it */
				if (e != -EINVAL && e != -EPERM)
					err = e;
			} else {
				done++;
			}
		}
	}
out:
	kfree(c);
	ngc_put(d);
	*count = done;
	if (done)
		printk(KERN_WARNING "deleted: %u entries left in $Extend\\$Deleted (POSIX deletes still open at a crash) removed\n", done);
	return err;
}

/* ------------------------------------------------------------------ time per stage */

int ngc_lookup(ngc_vol *v, ngc_node *dirn, const unsigned short *name, unsigned int len, ngc_node **out,
		unsigned short *real, unsigned int *real_len)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_lookup_impl(v, dirn, name, len, out, real, real_len);
	ngos_prof(NGP_LOOKUP, t0, 0);
	return r;
}

int ngc_iget(ngc_vol *v, unsigned long long mft_no, ngc_node **out)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_iget_impl(v, mft_no, out);
	ngos_prof(NGP_IGET, t0, 0);
	return r;
}

int ngc_iget_by_id(ngc_vol *v, unsigned long long mft_no, ngc_node **out)
{
	return ngc_iget_by_id_impl(v, mft_no, out);
}

void ngc_put(ngc_node *n)
{
	unsigned long long t0 = ngos_ticks();
	ngc_put_impl(n);
	ngos_prof(NGP_PUT, t0, 0);
}

void ngc_stat(ngc_node *n, struct ngc_stat *st)
{
	unsigned long long t0 = ngos_ticks();
	ngc_stat_impl(n, st);
	ngos_prof(NGP_STAT, t0, 0);
}

int ngc_readdir(ngc_vol *v, ngc_node *dirn, ngc_filldir_t fn, void *arg)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_readdir_impl(v, dirn, fn, arg);
	ngos_prof(NGP_READDIR, t0, 0);
	return r;
}

long ngc_read(ngc_node *n, unsigned long long off, unsigned int len, void *buf, int drop_cache)
{
	unsigned long long t0 = ngos_ticks();
	long r = ngc_read_impl(n, off, len, buf, drop_cache);
	ngos_prof(NGP_READ, t0, 0);
	return r;
}

int ngc_sync(ngc_vol *v)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_sync_impl(v);
	ngos_prof(NGP_SYNC, t0, 0);
	return r;
}

long ngc_write(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, const void *buf)
{
	unsigned long long t0 = ngos_ticks();
	long r = ngc_write_impl(v, n, off, len, buf);
	ngos_prof(NGP_WRITE, t0, 0);
	return r;
}

int ngc_set_size(ngc_vol *v, ngc_node *n, unsigned long long newsize)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_set_size_impl(v, n, newsize);
	ngos_prof(NGP_SET_SIZE, t0, 0);
	return r;
}

int ngc_trim_alloc(ngc_vol *v, ngc_node *n)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_trim_alloc_impl(v, n);
	ngos_prof(NGP_SET_SIZE, t0, 0);
	return r;
}

int ngc_set_info(ngc_vol *v, ngc_node *n, const long long times[4], unsigned int attrs, unsigned int attrs_mask)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_set_info_impl(v, n, times, attrs, attrs_mask);
	ngos_prof(NGP_SET_INFO, t0, 0);
	return r;
}

int ngc_get_security(ngc_vol *v, ngc_node *n, void **out, unsigned int *len)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_get_security_impl(v, n, out, len);
	ngos_prof(NGP_SECURITY, t0, 0);
	return r;
}

int ngc_set_security(ngc_vol *v, ngc_node *n, const void *sd, unsigned int len)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_set_security_impl(v, n, sd, len);
	ngos_prof(NGP_SECURITY, t0, 0);
	return r;
}

int ngc_short_name(ngc_node *n, unsigned long long parent_mref, unsigned short *out, unsigned int *len)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_short_name_impl(n, parent_mref, out, len);
	ngos_prof(NGP_SHORT_NAME, t0, 0);
	return r;
}

int ngc_add_short_name(ngc_vol *v, ngc_node *dirn, ngc_node *n, const unsigned short *lname, unsigned int llen,
		const unsigned short *sname, unsigned int slen)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_add_short_name_impl(v, dirn, n, lname, llen, sname, slen);
	ngos_prof(NGP_ADD_SHORT_NAME, t0, 0);
	return r;
}

int ngc_create(ngc_vol *v, ngc_node *dirn, const unsigned short *name, unsigned int len, int is_dir, ngc_node **out)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_create_impl(v, dirn, name, len, is_dir, out);
	ngos_prof(NGP_CREATE, t0, 0);
	return r;
}

int ngc_unlink(ngc_vol *v, ngc_node *dirn, const unsigned short *name, unsigned int len, ngc_node *n)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_unlink_impl(v, dirn, name, len, n);
	ngos_prof(NGP_UNLINK, t0, 0);
	return r;
}

int ngc_rename(ngc_vol *v, ngc_node *odirn, const unsigned short *oname, unsigned int olen, ngc_node *n,
		ngc_node *ndirn, const unsigned short *nname, unsigned int nlen, ngc_node *target)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_rename_impl(v, odirn, oname, olen, n, ndirn, nname, nlen, target);
	ngos_prof(NGP_RENAME, t0, 0);
	return r;
}

int ngc_link(ngc_vol *v, ngc_node *n, ngc_node *ndirn, const unsigned short *nname, unsigned int nlen)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_link_impl(v, n, ndirn, nname, nlen);
	ngos_prof(NGP_LINK, t0, 0);
	return r;
}

int ngc_dir_empty(ngc_vol *v, ngc_node *dirn)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_dir_empty_impl(v, dirn);
	ngos_prof(NGP_DIR_EMPTY, t0, 0);
	return r;
}

int ngc_readdir_full(ngc_vol *v, ngc_node *dirn, ngc_dirent_t fn, void *arg)
{
	unsigned long long t0 = ngos_ticks();
	int r = ngc_readdir_full_impl(v, dirn, fn, arg);
	ngos_prof(NGP_READDIR, t0, 0);
	return r;
}

/* FSCTL_NG_CHECK (see ngapi.h): the volume lock is held. */
int ngc_check(ngc_vol *v, unsigned int flags, struct ngc_check *out)
{
	struct ntfs_volume *vol = NTFS_SB(v->sb);
	struct ngc_fsck_res *r;
	int err = 0, rw = !sb_rdonly(v->sb), fix = !!(flags & NGC_CHECK_FIX);
	memset(out, 0, sizeof(*out));
	if (!rw)
		out->flags |= NGC_CHK_READONLY;
	if (v->damaged)
		out->flags |= NGC_CHK_DAMAGED;
	if (vol->vol_flags & VOLUME_IS_DIRTY)
		out->flags |= NGC_CHK_DIRTY;
	if (((vol->vol_flags & VOLUME_IS_DIRTY) && (vol->keep_dirty || !rw)) || v->damaged || NVolErrors(vol))
		out->flags |= NGC_CHK_NEEDS_CHECK;
	out->cluster_size = vol->cluster_size;
	if (flags & NGC_CHECK_QUERY)
		return 0;
	if (rw) {
		if (v->failed || kshim_jnl_failed(v->bdev))
			return -EIO;
		err = ngc_commit_prep(v);
		if (err)
			return err;
		kshim_jnl_settle(v->bdev);
	}
	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	err = ngc_fsck_ex(vol, v->bdev, r, fix && rw && !v->damaged && !NVolErrors(vol));
	out->records = r->records;
	out->inuse = r->inuse;
	out->dirs = r->dirs;
	out->ientries = r->ientries;
	out->clusters = r->clusters;
	out->leaked_clusters = r->leaked_clusters;
	out->fixed_clusters = r->fixed_clusters;
	out->fatal = r->fatal;
	out->leaks = r->leaks;
	out->leaked_records = r->leaked_records;
	out->fixed_records = r->fixed_records;
	out->dirs_skipped = r->dirs_skipped;
	out->clusters_skipped = r->clusters_skipped;
	out->ms = r->ms;
	out->repair_errors = r->repair_errors;
	out->ext_records = r->ext_records;
	out->reparse = r->reparse;
	out->sys_clusters = r->sys_clusters;
	out->log_clusters = r->log_clusters;
	out->index_clusters = r->index_clusters;
	out->replayed = v->jv ? v->jv->replayed : 0;
	memcpy(out->pass_ms, r->pass_ms, sizeof(out->pass_ms));
	strscpy(out->why, r->why, sizeof(out->why));
	if (err && !r->fatal) {
		kfree(r);
		return err;
	}
	out->flags |= NGC_CHK_RAN;
	printk(KERN_WARNING "CHECK (requested%s): %s: %llu records (%llu in use), %llu index entries, %u leaks (%llu clusters, %u records), "
	       "%u errors, %u ms\n", fix ? ", with repair" : "", r->fatal ? "DAMAGED" : "consistent", r->records, r->inuse,
	       r->ientries, r->leaks, r->leaked_clusters, r->leaked_records, r->fatal, r->ms);
	if (fix) {
		if (r->fatal || !rw || v->damaged || NVolErrors(vol) || r->repair_refused || r->repair_errors) {
			out->flags |= NGC_CHK_REFUSED;
			if (rw && (r->fatal || r->repair_errors) && !v->damaged) {
				/*
				 * Damage on a volume that is writable: it stays dirty on disk (a later mount checks it again) and
				 * becomes read-only, as a volume the mount-time check found damaged.
				 */
				int e = 0;
				ngc_set_keep(v, true);
				if (!(vol->vol_flags & VOLUME_IS_DIRTY)) {
					e = ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY);
					if (!e)
						e = write_inode_now(vol->vol_ino, 1);
				}
				if (!e)
					e = ngc_commit(v);
				if (e)
					printk(KERN_ERR "CHECK: could not keep the damaged volume dirty (%d)\n", e);
				v->damaged = 1;
				snprintf(v->why, sizeof(v->why), "a requested consistency check found %u errors, first: %s", r->fatal, r->why);
				v->sb->s_flags |= SB_RDONLY;
				out->flags |= NGC_CHK_NOW_READONLY | NGC_CHK_DAMAGED | NGC_CHK_READONLY;
			}
		} else {
			int e = 0;
			if (r->fixed_clusters || r->fixed_records) {
				e = ngc_commit(v);
				if (!e)
					out->flags |= NGC_CHK_REPAIRED;
			}
			/* Nothing wrong that is left: a flag a check was scheduled with (FSCTL_MARK_VOLUME_DIRTY) goes. */
			if (!e) {
				ngc_set_keep(v, false);
				e = ngc_sync_impl(v);
				if (!e && !(vol->vol_flags & VOLUME_IS_DIRTY) && (out->flags & NGC_CHK_DIRTY))
					out->flags |= NGC_CHK_DIRTY_CLEARED;
			}
			if (e) {
				out->flags |= NGC_CHK_REFUSED;
				out->repair_errors++;
			}
		}
	}
	if (rw && !(vol->vol_flags & VOLUME_IS_DIRTY))
		out->flags &= ~NGC_CHK_DIRTY;
	if (vol->vol_flags & VOLUME_IS_DIRTY)
		out->flags |= NGC_CHK_DIRTY;
	{
		s64 fc = atomic64_read(&vol->free_clusters);
		out->total_clusters = vol->nr_clusters;
		out->free_clusters = fc > 0 ? fc : 0;
	}
	kfree(r);
	return 0;
}
