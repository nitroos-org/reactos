/* SPDX-License-Identifier: GPL-2.0-or-later */
/* kshim_vfs.h - kernel-mode stand-ins for VFS, page cache, block and iomap APIs. */
#ifndef KSHIM_VFS_H
#define KSHIM_VFS_H

struct inode; struct super_block; struct address_space; struct folio; struct page;
struct file; struct dentry; struct block_device; struct bio; struct kiocb;
struct iov_iter; struct writeback_control; struct seq_file; struct kstatfs;
struct fs_context; struct fs_parameter; struct nls_table; struct iattr; struct kstat;
struct path; struct mnt_idmap; struct vm_area_struct; struct vm_fault; struct readahead_control;
struct fiemap_extent_info; struct swap_info_struct; struct posix_acl; struct delayed_call;
struct pipe_inode_info; struct file_lock; struct poll_table_struct; struct fid;
struct vm_area_desc; struct folio_batch; struct dax_device; struct fsverity_info;

/* ------------------------------------------------------------- modes */
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)
#define S_IRWXUGO 00777
#define S_IALLUGO 07777
#define S_IRUGO 00444
#define S_IWUGO 00222
#define S_IXUGO 00111
#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100
#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010
#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001
#define S_IMMUTABLE 8
#define S_APPEND 4
#define S_NOATIME 128
#define S_SYNC 1
#define S_DAX 0
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14

/* ------------------------------------------------------------ qstr/dentry */
struct qstr { const unsigned char *name; u32 len; u32 hash; };
#define QSTR_INIT(n, l) { .name = (n), .len = (l) }
struct dentry {
	struct inode *d_inode;
	struct dentry *d_parent;
	struct qstr d_name;
	struct super_block *d_sb;
	unsigned int d_flags;
	unsigned char d_iname[256];
	unsigned char *kshim_ci_name;	/* on-disk name when a lookup matched by case folding (d_add_ci) */
	unsigned int kshim_ci_len;
};
static inline struct inode *d_inode(const struct dentry *d) { return d->d_inode; }
static inline struct inode *d_backing_inode(const struct dentry *d) { return d->d_inode; }
static inline struct inode *d_really_is_positive(const struct dentry *d) { return d->d_inode; }
struct dentry *d_splice_alias(struct inode *i, struct dentry *d);
struct dentry *d_add_ci(struct dentry *d, struct inode *i, struct qstr *n);
void d_add(struct dentry *d, struct inode *i);
void d_instantiate(struct dentry *d, struct inode *i);
void d_instantiate_new(struct dentry *d, struct inode *i);
struct dentry *d_make_root(struct inode *i);
struct dentry *d_obtain_alias(struct inode *i);
struct dentry *dget_parent(struct dentry *d);
void dput(struct dentry *d);
char *dentry_path_raw(const struct dentry *d, char *buf, int len);
bool is_subdir(struct dentry *a, struct dentry *b);
unsigned int full_name_hash(const void *salt, const char *n, unsigned int len);
struct path { struct dentry *dentry; void *mnt; };
struct mnt_idmap { int dummy; };
extern struct mnt_idmap nop_mnt_idmap;

/* ------------------------------------------------------------ folio/page */
#define PG_locked 0
#define PG_uptodate 1
#define PG_dirty 2
#define PG_writeback 3
#define PG_error 4
#define KSHIM_PAGE_FIELDS \
	unsigned long flags; \
	struct address_space *mapping; \
	pgoff_t index; \
	void *data; \
	int refcount; \
	void *private; \
	void *kshim_fill; /* read accounting, kshim_iomap.c */ \
	struct folio *hnext;
struct page { KSHIM_PAGE_FIELDS };
struct folio { union { struct { KSHIM_PAGE_FIELDS }; struct page page; }; };
#define page_folio(p) ((struct folio *)(p))
#define folio_page(f, n) ((struct page *)(f) + 0 * (n))
#define folio_file_page(f, n) folio_page(f, 0)
static inline size_t folio_size(const struct folio *f) { (void)f; return PAGE_SIZE; }
static inline unsigned int folio_shift(const struct folio *f) { (void)f; return PAGE_SHIFT; }
static inline long folio_nr_pages(const struct folio *f) { (void)f; return 1; }
static inline unsigned int folio_order(const struct folio *f) { (void)f; return 0; }
static inline loff_t folio_pos(const struct folio *f) { return (loff_t)f->index << PAGE_SHIFT; }
static inline loff_t folio_next_pos(const struct folio *f) { return folio_pos(f) + PAGE_SIZE; }
static inline pgoff_t folio_next_index(const struct folio *f) { return f->index + 1; }
static inline void *folio_address(const struct folio *f) { return f->data; }
static inline void *page_address(const struct page *p) { return p->data; }
static inline bool folio_contains(const struct folio *f, pgoff_t i) { return f->index == i; }
static inline size_t offset_in_folio(const struct folio *f, loff_t p) { (void)f; return p & (PAGE_SIZE - 1); }
#define offset_in_page(p) ((unsigned long)(p) & ~PAGE_MASK)
static inline loff_t page_offset(const struct page *p) { return (loff_t)p->index << PAGE_SHIFT; }
#define folio_test_uptodate(f) test_bit(PG_uptodate, &(f)->flags)
#define folio_test_locked(f) test_bit(PG_locked, &(f)->flags)
#define folio_test_dirty(f) test_bit(PG_dirty, &(f)->flags)
#define folio_test_writeback(f) test_bit(PG_writeback, &(f)->flags)
#define folio_mark_uptodate(f) set_bit(PG_uptodate, &(f)->flags)
#define folio_clear_uptodate(f) clear_bit(PG_uptodate, &(f)->flags)
void kshim_folio_lock(struct folio *f);
#define folio_lock(f) kshim_folio_lock(f)
#define folio_trylock(f) (!test_and_set_bit(PG_locked, &(f)->flags))
#define folio_unlock(f) clear_bit(PG_locked, &(f)->flags)
#define folio_clear_dirty(f) clear_bit(PG_dirty, &(f)->flags)
#define folio_clear_dirty_for_io(f) test_and_clear_bit(PG_dirty, &(f)->flags)
#define folio_wait_writeback(f) do { } while (0)
#define folio_wait_stable(f) do { } while (0)
#define PageUptodate(p) folio_test_uptodate(page_folio(p))
#define PageDirty(p) folio_test_dirty(page_folio(p))
#define PageLocked(p) folio_test_locked(page_folio(p))
#define SetPageUptodate(p) folio_mark_uptodate(page_folio(p))
#define ClearPageUptodate(p) folio_clear_uptodate(page_folio(p))
#define SetPageError(p) do { } while (0)
#define ClearPageError(p) do { } while (0)
#define lock_page(p) folio_lock(page_folio(p))
#define unlock_page(p) folio_unlock(page_folio(p))
#define get_page(p) folio_get(page_folio(p))
#define put_page(p) folio_put(page_folio(p))
void folio_get(struct folio *f);
void folio_put(struct folio *f);
bool folio_mark_dirty(struct folio *f);
#define set_page_dirty(p) folio_mark_dirty(page_folio(p))
void folio_start_writeback(struct folio *f);
void folio_end_writeback(struct folio *f);
void folio_redirty_for_writepage(struct writeback_control *wbc, struct folio *f);
#define kmap_local_folio(f, o) ((void *)((char *)(f)->data + (o)))
#define kmap_local_page(p) ((p)->data)
#define kmap(p) ((p)->data)
#define kunmap(p) do { (void)(p); } while (0)
#define kmap_atomic(p) ((p)->data)
#define kunmap_atomic(a) do { (void)(a); } while (0)
#define kunmap_local(a) do { (void)(a); } while (0)
#define flush_dcache_folio(f) do { } while (0)
#define flush_dcache_page(p) do { } while (0)
static inline void folio_zero_segments(struct folio *f, size_t s1, size_t e1, size_t s2, size_t e2)
{ if (e1 > s1) memset((char *)f->data + s1, 0, e1 - s1); if (e2 > s2) memset((char *)f->data + s2, 0, e2 - s2); }
static inline void folio_zero_segment(struct folio *f, size_t s, size_t e) { folio_zero_segments(f, s, e, 0, 0); }
static inline void folio_zero_range(struct folio *f, size_t s, size_t l) { folio_zero_segments(f, s, s + l, 0, 0); }
#define zero_user_segments(p, s1, e1, s2, e2) folio_zero_segments(page_folio(p), s1, e1, s2, e2)
#define zero_user_segment(p, s, e) folio_zero_segments(page_folio(p), s, e, 0, 0)
#define zero_user(p, s, l) folio_zero_segments(page_folio(p), s, (s) + (l), 0, 0)
static inline void memzero_page(struct page *p, size_t o, size_t l) { memset((char *)p->data + o, 0, l); }
static inline void memcpy_from_folio(void *to, struct folio *f, size_t o, size_t l) { memcpy(to, (char *)f->data + o, l); }
static inline void memcpy_to_folio(struct folio *f, size_t o, const void *from, size_t l) { memcpy((char *)f->data + o, from, l); }
static inline void memcpy_from_page(void *to, struct page *p, size_t o, size_t l) { memcpy(to, (char *)p->data + o, l); }
static inline void memcpy_to_page(struct page *p, size_t o, const void *from, size_t l) { memcpy((char *)p->data + o, from, l); }
static inline void folio_fill_tail(struct folio *f, size_t o, const char *from, size_t l)
{ memcpy((char *)f->data + o, from, l); memset((char *)f->data + o + l, 0, PAGE_SIZE - o - l); }
struct page *alloc_page(gfp_t g);
void __free_page(struct page *p);
#define __free_pages(p, o) __free_page(p)
struct folio_iter { struct folio *folio; size_t offset; size_t length; };

/* --------------------------------------------------------- address space */
struct address_space_operations {
	int (*read_folio)(struct file *, struct folio *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(void);
	int (*write_end)(void);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	bool (*release_folio)(struct folio *, gfp_t);
	void (*free_folio)(struct folio *);
	ssize_t_ (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migrate_folio)(struct address_space *, struct folio *, struct folio *, int);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_folio)(struct address_space *, struct folio *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
};
#define KSHIM_PC_BUCKETS 64
struct address_space {
	struct inode *host;
	const struct address_space_operations *a_ops;
	struct folio *pc[KSHIM_PC_BUCKETS];
	unsigned long nrpages;
	gfp_t gfp_mask;
	struct rw_semaphore invalidate_lock;
	struct list_head private_list;
	spinlock_t private_lock;
	errseq_t wb_err;
	unsigned long flags;
	unsigned int kshim_eager_wb;	/* write dirty folios back as soon as the mapping is full (block device) */
	unsigned long kshim_pc_max;	/* folios kept before clean ones are dropped; 0: KSHIM_PC_MAX */
	unsigned int kshim_dirty_hint;	/* set when a folio of the mapping was marked dirty; cleared by a scan that finds none (kshim_mapping_dirty) */
};
static inline gfp_t mapping_gfp_mask(struct address_space *m) { return m->gfp_mask; }
static inline void mapping_set_gfp_mask(struct address_space *m, gfp_t g) { m->gfp_mask = g; }
#define mapping_set_large_folios(m) do { } while (0)
#define mapping_set_folio_min_order(m, o) do { } while (0)
#define mapping_set_release_always(m) do { } while (0)
#define mapping_set_error(m, e) do { } while (0)
#define mapping_set_unevictable(m) do { } while (0)
#define mapping_set_exiting(m) do { } while (0)
#define filemap_invalidate_lock(m) down_write(&(m)->invalidate_lock)
#define filemap_invalidate_unlock(m) up_write(&(m)->invalidate_lock)
#define filemap_invalidate_lock_shared(m) down_read(&(m)->invalidate_lock)
#define filemap_invalidate_unlock_shared(m) up_read(&(m)->invalidate_lock)
struct folio *read_mapping_folio(struct address_space *m, pgoff_t idx, struct file *f);
struct page *read_mapping_page(struct address_space *m, pgoff_t idx, struct file *f);
#define FGP_LOCK 1
#define FGP_ACCESSED 2
#define FGP_CREAT 4
#define FGP_WRITE 8
#define FGP_NOFS 16
#define FGP_NOWAIT 32
#define FGP_WRITEBEGIN (FGP_LOCK | FGP_WRITE | FGP_CREAT)
#define fgf_set_order(x) 0
typedef unsigned int fgf_t;
struct folio *__filemap_get_folio(struct address_space *m, pgoff_t idx, fgf_t fgp, gfp_t g);
struct folio *filemap_lock_folio(struct address_space *m, pgoff_t idx);
struct folio *filemap_grab_folio(struct address_space *m, pgoff_t idx);
struct page *grab_cache_page_nowait(struct address_space *m, pgoff_t idx);
struct folio *filemap_get_folio(struct address_space *m, pgoff_t idx);
int filemap_write_and_wait(struct address_space *m);
int filemap_write_and_wait_range(struct address_space *m, loff_t s, loff_t e);
int filemap_fdatawrite(struct address_space *m);
int filemap_fdatawait(struct address_space *m);
int filemap_fdatawrite_range(struct address_space *m, loff_t s, loff_t e);
int filemap_flush(struct address_space *m);
int sync_mapping_buffers(struct address_space *m);
unsigned long invalidate_mapping_pages(struct address_space *m, pgoff_t s, pgoff_t e);
void truncate_inode_pages(struct address_space *m, loff_t l);
void truncate_inode_pages_final(struct address_space *m);
void truncate_pagecache(struct inode *i, loff_t n);
void truncate_setsize(struct inode *i, loff_t n);
void pagecache_isize_extended(struct inode *i, loff_t from, loff_t to);
bool filemap_dirty_folio(struct address_space *m, struct folio *f);
int filemap_migrate_folio(struct address_space *m, struct folio *d, struct folio *s, int mode);
void page_cache_sync_readahead(struct address_space *m, void *ra, struct file *f, pgoff_t i, unsigned long n);
static inline int folio_ref_count(const struct folio *f) { return f->refcount; }

/* ---------------------------------------------------------------- inode */
#define I_NEW (1 << 3)
#define I_DIRTY_SYNC (1 << 0)
#define I_DIRTY_DATASYNC (1 << 1)
#define I_DIRTY_PAGES (1 << 2)
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define I_FREEING (1 << 5)
#define I_WILL_FREE (1 << 4)
#define I_CLEAR (1 << 6)
#define I_CREATING (1 << 8)
#define S_NOSEC 4096
#define I_SYNC (1 << 7)
struct inode_operations;
struct file_operations;
struct inode {
	umode_t i_mode;
	unsigned short i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	u64 i_ino;
	unsigned int i_nlink;
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime, i_mtime, i_ctime;
	spinlock_t i_lock;
	unsigned short i_bytes;
	u8 i_blkbits;
	blkcnt_t i_blocks;
	unsigned long i_state;
	struct rw_semaphore i_rwsem;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	const struct file_operations *i_fop;
	struct address_space i_data;
	u32 i_generation;
	u64 i_version;
	void *i_private;
	struct hlist_node i_hash;
	struct inode *kshim_next, *kshim_prev;	/* sb->kshim_inodes, doubly linked: eviction unlinks in O(1) */
	void *kshim_test_data;
	struct inode *kshim_hnext;		/* hash chain (sb->kshim_ihash) while hashed */
	struct inode *kshim_lru_prev, *kshim_lru_next;	/* unused-inode list while kshim_in_lru */
	unsigned char kshim_hashed, kshim_in_lru;
	unsigned int kshim_lru_bytes;		/* what kshim_icache_cost said it holds when it joined the unused list (void while not kshim_in_lru) */
};
static inline loff_t i_size_read(const struct inode *i) { return i->i_size; }
static inline void i_size_write(struct inode *i, loff_t s) { i->i_size = s; }
static inline u32 i_uid_read(const struct inode *i) { return i->i_uid.val; }
static inline u32 i_gid_read(const struct inode *i) { return i->i_gid.val; }
static inline void i_uid_write(struct inode *i, u32 u) { i->i_uid.val = u; }
static inline void i_gid_write(struct inode *i, u32 g) { i->i_gid.val = g; }
static inline struct timespec64 inode_get_atime(const struct inode *i) { return i->i_atime; }
static inline struct timespec64 inode_get_mtime(const struct inode *i) { return i->i_mtime; }
static inline struct timespec64 inode_get_ctime(const struct inode *i) { return i->i_ctime; }
static inline struct timespec64 inode_set_atime_to_ts(struct inode *i, struct timespec64 t) { i->i_atime = t; return t; }
static inline struct timespec64 inode_set_mtime_to_ts(struct inode *i, struct timespec64 t) { i->i_mtime = t; return t; }
static inline struct timespec64 inode_set_ctime_to_ts(struct inode *i, struct timespec64 t) { i->i_ctime = t; return t; }
struct timespec64 inode_set_ctime_current(struct inode *i);
struct timespec64 current_time(struct inode *i);
static inline time_t inode_get_atime_sec(const struct inode *i) { return i->i_atime.tv_sec; }
static inline time_t inode_get_mtime_sec(const struct inode *i) { return i->i_mtime.tv_sec; }
static inline time_t inode_get_ctime_sec(const struct inode *i) { return i->i_ctime.tv_sec; }
void simple_inode_init_ts(struct inode *i);
#define inode_lock(i) down_write(&(i)->i_rwsem)
#define inode_unlock(i) up_write(&(i)->i_rwsem)
#define inode_lock_shared(i) down_read(&(i)->i_rwsem)
#define inode_unlock_shared(i) up_read(&(i)->i_rwsem)
#define inode_lock_nested(i, c) down_write(&(i)->i_rwsem)
#define inode_trylock(i) (down_write(&(i)->i_rwsem), 1)
#define inode_is_locked(i) rwsem_is_locked(&(i)->i_rwsem)
#define inode_dio_wait(i) do { } while (0)
#define inode_inc_iversion(i) ((i)->i_version++)
#define inode_set_iversion(i, v) ((i)->i_version = (v))
#define inode_query_iversion(i) ((i)->i_version)
static inline unsigned long inode_state_read_once(struct inode *i) { return i->i_state; }
/*
 * kshim_sync skips its scan while the dirty generation (kshim_dirty_bump) is unchanged since a scan found
 * everything clean, so every way of making an inode dirty must bump it.  Setting or clearing any I_DIRTY
 * bit here does, so a caller cannot make FlushFileBuffers skip an inode by going through these helpers
 * (clearing cannot hide dirtiness; it bumps anyway to keep the rule simple).
 */
void kshim_dirty_bump(void);
static inline void inode_state_set(struct inode *i, unsigned long f)
{
	i->i_state |= f;
	if (f & I_DIRTY)
		kshim_dirty_bump();
}
static inline void inode_state_clear(struct inode *i, unsigned long f)
{
	i->i_state &= ~f;
	if (f & I_DIRTY)
		kshim_dirty_bump();
}
static inline bool inode_unhashed(struct inode *i) { (void)i; return false; }
void inode_init_once(struct inode *i);
void inode_init_owner(struct mnt_idmap *idmap, struct inode *i, const struct inode *dir, umode_t mode);
int inode_newsize_ok(const struct inode *i, loff_t n);
void set_nlink(struct inode *i, unsigned int n);
void inc_nlink(struct inode *i);
void drop_nlink(struct inode *i);
void clear_nlink(struct inode *i);
void init_special_inode(struct inode *i, umode_t m, dev_t d);
struct inode *new_inode(struct super_block *sb);
void insert_inode_hash(struct inode *i);
void remove_inode_hash(struct inode *i);
struct inode *iget5_locked(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), int (*set)(struct inode *, void *), void *data);
struct inode *ilookup5(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data);
struct inode *ilookup5_nowait(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data, bool *isnew);
struct inode *find_inode_nowait(struct super_block *sb, unsigned long hashval,
		int (*match)(struct inode *, u64, void *), void *data);
struct inode *iget_locked(struct super_block *sb, unsigned long ino);
struct inode *igrab(struct inode *i);
void ihold(struct inode *i);
void iput(struct inode *i);
void unlock_new_inode(struct inode *i);
void discard_new_inode(struct inode *i);
void iget_failed(struct inode *i);
void clear_inode(struct inode *i);
int generic_delete_inode(struct inode *i);
int inode_generic_drop(struct inode *i);
void __mark_inode_dirty(struct inode *i, int flags);
static inline void mark_inode_dirty(struct inode *i) { __mark_inode_dirty(i, I_DIRTY); }
static inline void mark_inode_dirty_sync(struct inode *i) { __mark_inode_dirty(i, I_DIRTY_SYNC); }
int write_inode_now(struct inode *i, int sync);
int sync_inode_metadata(struct inode *i, int wait);
#define IS_RDONLY(i) ((i)->i_sb && ((i)->i_sb->s_flags & SB_RDONLY))
#define IS_IMMUTABLE(i) ((i)->i_flags & S_IMMUTABLE)
#define IS_APPEND(i) ((i)->i_flags & S_APPEND)
#define IS_SYNC(i) 0
#define IS_DIRSYNC(i) 0
#define IS_NOATIME(i) 1
#define IS_ENCRYPTED(i) 0
#define IS_DAX(i) 0
#define HAS_UNMAPPED_ID(m, i) 0
#define i_blocksize(i) (1U << (i)->i_blkbits)
static inline struct inode *file_inode(const struct file *f);
#define inode_wrong_type(i, m) (((i)->i_mode ^ (m)) & S_IFMT)

/* -------------------------------------------------------------- super */
#define SB_RDONLY (1 << 0)
#define SB_NOSUID (1 << 1)
#define SB_NODEV (1 << 2)
#define SB_NOEXEC (1 << 3)
#define SB_SYNCHRONOUS (1 << 4)
#define SB_POSIXACL (1 << 16)
#define SB_SILENT (1 << 15)
#define SB_NOATIME (1 << 10)
#define SB_NODIRATIME (1 << 11)
#define SB_ACTIVE (1 << 30)
#define SB_FREEZE_WRITE 1
struct super_operations;
struct export_operations;
struct xattr_handler;
struct super_block {
	unsigned long s_blocksize;
	unsigned char s_blocksize_bits;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct export_operations *s_export_op;
	unsigned long s_flags;
	unsigned long s_iflags;
	unsigned long s_magic;
	struct dentry *s_root;
	struct block_device *s_bdev;
	void *s_fs_info;
	u32 s_time_gran;
	s64 s_time_min, s_time_max;
	char s_id[32];
	const struct xattr_handler * const *s_xattr;
	errseq_t s_wb_err;
	struct inode *kshim_inodes;
#define KSHIM_IHASH 1024
	struct inode *kshim_ihash[KSHIM_IHASH];
	struct inode *kshim_lru_head, *kshim_lru_tail;	/* unused inodes, oldest first */
	unsigned long kshim_lru_count;
	unsigned long kshim_lru_bytes;		/* sum of kshim_lru_bytes of the unused inodes */
	int kshim_no_icache;			/* unmounting: evict at the last reference */
	void *kshim_priv;			/* the file system glue's volume (kshim_icache_evicting / kshim_icache_added find it here) */
	unsigned long long kshim_clean_gen;	/* kshim_dirty_gen when a sync last found nothing dirty */
	int kshim_clean_valid;
	const struct dentry_operations *s_d_op;
	struct user_namespace *s_user_ns;
	u8 s_uuid[16];
};
static inline bool sb_rdonly(const struct super_block *sb) { return sb->s_flags & SB_RDONLY; }
int sb_set_blocksize(struct super_block *sb, int size);
int sb_min_blocksize(struct super_block *sb, int size);
#define sb_start_intwrite(sb) do { } while (0)
#define sb_end_intwrite(sb) do { } while (0)
#define sb_start_pagefault(sb) do { } while (0)
#define sb_end_pagefault(sb) do { } while (0)
#define sb_start_write(sb) do { } while (0)
#define sb_end_write(sb) do { } while (0)
int sync_filesystem(struct super_block *sb);
void sync_inodes_sb(struct super_block *sb);
void generic_shutdown_super(struct super_block *sb);
void kill_block_super(struct super_block *sb);
typedef struct { int val[2]; } __kernel_fsid_t;
struct kstatfs {
	long f_type; long f_bsize; u64 f_blocks, f_bfree, f_bavail, f_files, f_ffree;
	__kernel_fsid_t f_fsid; long f_namelen; long f_frsize; long f_flags;
};
static inline __kernel_fsid_t u64_to_fsid(u64 v) { __kernel_fsid_t f = { { (int)v, (int)(v >> 32) } }; return f; }
struct super_operations {
	struct inode *(*alloc_inode)(struct super_block *sb);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int flags);
	int (*write_inode)(struct inode *, struct writeback_control *wbc);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *sb, int wait);
	int (*freeze_fs)(struct super_block *);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	void (*shutdown)(struct super_block *sb);
};
struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	void (*kill_sb)(struct super_block *);
	struct module *owner;
};
#define FS_REQUIRES_DEV 1
#define FS_ALLOW_IDMAP 32
#define FS_MGTIME 64
int register_filesystem(struct file_system_type *t);
int unregister_filesystem(struct file_system_type *t);

/* ---------------------------------------------------------- fs_context */
enum fs_context_purpose { FS_CONTEXT_FOR_MOUNT, FS_CONTEXT_FOR_SUBMOUNT, FS_CONTEXT_FOR_RECONFIGURE };
struct fs_context_operations {
	void (*free)(struct fs_context *fc);
	int (*dup)(struct fs_context *fc, struct fs_context *src_fc);
	int (*parse_param)(struct fs_context *fc, struct fs_parameter *param);
	int (*parse_monolithic)(struct fs_context *fc, void *data);
	int (*get_tree)(struct fs_context *fc);
	int (*reconfigure)(struct fs_context *fc);
};
struct fs_context {
	const struct fs_context_operations *ops;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	enum fs_context_purpose purpose;
	const char *source;
	struct super_block *kshim_sb;
};
int get_tree_bdev(struct fs_context *fc, int (*fill_super)(struct super_block *, struct fs_context *));
enum fs_value_type { fs_value_is_undefined, fs_value_is_flag, fs_value_is_string };
struct fs_parameter { const char *key; enum fs_value_type type; char *string; size_t size; int dirfd; };
struct fs_parse_result { bool negated; union { bool boolean; int int_32; unsigned int uint_32; u64 uint_64; kuid_t uid; kgid_t gid; }; };
struct constant_table { const char *name; int value; };
struct fs_parameter_spec { const char *name; int type; u8 opt; unsigned short flags; const void *data; };
#define fsparam_flag(n, o) { n, 1, o, 0, NULL }
#define fsparam_flag_no(n, o) { n, 1, o, 0, NULL }
#define fsparam_u32(n, o) { n, 2, o, 0, NULL }
#define fsparam_u32oct(n, o) { n, 3, o, 0, NULL }
#define fsparam_s32(n, o) { n, 4, o, 0, NULL }
#define fsparam_u64(n, o) { n, 5, o, 0, NULL }
#define fsparam_string(n, o) { n, 6, o, 0, NULL }
#define fsparam_enum(n, o, t) { n, 7, o, 0, t }
#define fsparam_uid(n, o) { n, 8, o, 0, NULL }
#define fsparam_gid(n, o) { n, 9, o, 0, NULL }
int fs_parse(struct fs_context *fc, const struct fs_parameter_spec *desc, struct fs_parameter *param, struct fs_parse_result *result);
int invalf(struct fs_context *fc, const char *fmt, ...);
int errorf(struct fs_context *fc, const char *fmt, ...);
int warnf(struct fs_context *fc, const char *fmt, ...);
#define infof(fc, fmt, ...) printk(fmt "\n", ##__VA_ARGS__)
#define invalfc(fc, fmt, ...) invalf(fc, fmt, ##__VA_ARGS__)
#define errorfc(fc, fmt, ...) errorf(fc, fmt, ##__VA_ARGS__)
#define warnfc(fc, fmt, ...) warnf(fc, fmt, ##__VA_ARGS__)

/* ----------------------------------------------------------------- file */
#define FMODE_READ 1
#define FMODE_WRITE 2
#define FMODE_LSEEK 4
#define FMODE_NOWAIT 8
#define FMODE_CAN_ODIRECT 16
#define FMODE_32BITHASH 32
#define FMODE_64BITHASH 64
#define FMODE_EXEC 128
#define O_DIRECT_ 040000
struct file_ra_state { unsigned long ra_pages; };
struct file {
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	unsigned int f_flags;
	fmode_t f_mode;
	loff_t f_pos;
	struct address_space *f_mapping;
	void *private_data;
	struct file_ra_state f_ra;
	u64 f_version;
};
static inline struct inode *file_inode(const struct file *f) { return f->f_inode; }
struct dir_context;
typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
struct dir_context { filldir_t actor; loff_t pos; int count; };
static inline bool dir_emit(struct dir_context *ctx, const char *name, int len, u64 ino, unsigned type)
{ return ctx->actor(ctx, name, len, ctx->pos, ino, type); }
bool dir_emit_dots(struct file *f, struct dir_context *ctx);
struct kiocb { struct file *ki_filp; loff_t ki_pos; int ki_flags; void *private; };
#define IOCB_DIRECT 1
#define IOCB_NOWAIT 2
#define IOCB_APPEND 4
#define IOCB_DSYNC 8
#define IOCB_SYNC 16
#define IOCB_DONTCACHE 32
#define IOCB_ATOMIC 64
struct iov_iter { int type; size_t count; void *data; };
static inline size_t iov_iter_count(const struct iov_iter *i) { return i->count; }
size_t copy_folio_from_iter_atomic(struct folio *f, size_t o, size_t b, struct iov_iter *i);
size_t fault_in_iov_iter_readable(const struct iov_iter *i, size_t b);
void iov_iter_revert(struct iov_iter *i, size_t n);
void iov_iter_advance(struct iov_iter *i, size_t n);
size_t copy_page_from_iter_atomic(struct page *p, size_t o, size_t b, struct iov_iter *i);
struct file_operations {
	struct module *owner;
	unsigned int fop_flags;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t_ (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t_ (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t_ (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t_ (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iterate_shared)(struct file *, struct dir_context *);
	long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
	int (*mmap)(struct file *, struct vm_area_struct *);
	int (*mmap_prepare)(struct vm_area_desc *);
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, void *id);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int datasync);
	ssize_t_ (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	ssize_t_ (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	long (*fallocate)(struct file *file, int mode, loff_t offset, loff_t len);
	int (*setlease)(struct file *, int, struct file_lock **, void **);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
};
#define FOP_BUFFER_RASYNC 1
#define FOP_BUFFER_WASYNC 2
#define FOP_DIO_PARALLEL_WRITE 4
#define FOP_UNSIGNED_OFFSET 8
#define FOP_DONTCACHE 16
struct inode_operations {
	struct dentry *(*lookup)(struct inode *, struct dentry *, unsigned int);
	const char *(*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct mnt_idmap *, struct inode *, int);
	struct posix_acl *(*get_inode_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
	int (*create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
	int (*create_)(void);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
	struct dentry *(*mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	int (*getattr)(struct mnt_idmap *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t_ (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64 start, u64 len);
	int (*update_time)(struct inode *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned open_flag, umode_t create_mode);
	int (*tmpfile)(struct mnt_idmap *, struct inode *, struct file *, umode_t);
	struct posix_acl *(*get_acl)(struct mnt_idmap *, struct dentry *, int);
	int (*set_acl)(struct mnt_idmap *, struct dentry *, struct posix_acl *, int);
	int (*fileattr_set)(struct mnt_idmap *idmap, struct dentry *dentry, void *fa);
	int (*fileattr_get)(struct dentry *dentry, void *fa);
};
struct dentry_operations { int (*d_hash)(const struct dentry *, struct qstr *); int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *); };
loff_t generic_file_llseek_size(struct file *f, loff_t o, int w, loff_t max, loff_t eof);
loff_t generic_file_llseek(struct file *f, loff_t o, int w);
loff_t vfs_setpos(struct file *f, loff_t o, loff_t max);
ssize_t_ generic_file_read_iter(struct kiocb *k, struct iov_iter *i);
ssize_t_ generic_write_checks(struct kiocb *k, struct iov_iter *i);
ssize_t_ generic_write_sync(struct kiocb *k, ssize_t_ c);
ssize_t_ filemap_splice_read(struct file *in, loff_t *p, struct pipe_inode_info *pipe, size_t len, unsigned int f);
ssize_t_ iter_file_splice_write(struct pipe_inode_info *pipe, struct file *out, loff_t *p, size_t len, unsigned int f);
int generic_file_open(struct inode *i, struct file *f);
int generic_file_mmap(struct file *f, struct vm_area_struct *v);
ssize_t_ generic_read_dir(struct file *f, char *b, size_t s, loff_t *p);
int file_modified(struct file *f);
int file_update_time(struct file *f);
void file_accessed(struct file *f);
int file_remove_privs(struct file *f);
int file_write_and_wait_range(struct file *f, loff_t s, loff_t e);
int file_fsync(struct file *f, loff_t s, loff_t e, int d);
void file_ra_state_init(struct file_ra_state *ra, struct address_space *m);
int mnt_want_write_file(struct file *f);
void mnt_drop_write_file(struct file *f);
int generic_fillattr(struct mnt_idmap *m, u32 req, struct inode *i, struct kstat *s);
struct kstat { u32 result_mask; umode_t mode; unsigned int nlink; u32 blksize; u64 attributes; u64 attributes_mask; u64 ino; dev_t dev; dev_t rdev; kuid_t uid; kgid_t gid; loff_t size; struct timespec64 atime, mtime, ctime, btime; u64 blocks; u32 dio_mem_align; u32 dio_offset_align; };
#define STATX_BTIME 0x800U
#define STATX_DIOALIGN 0x2000U
#define STATX_ATTR_COMPRESSED 0x4
#define STATX_ATTR_ENCRYPTED 0x800
#define STATX_ATTR_IMMUTABLE 0x10
#define STATX_ATTR_APPEND 0x20
struct iattr { unsigned int ia_valid; umode_t ia_mode; kuid_t ia_uid; kgid_t ia_gid; loff_t ia_size; struct timespec64 ia_atime, ia_mtime, ia_ctime; struct file *ia_file; };
#define ATTR_MODE 1
#define ATTR_UID 2
#define ATTR_GID 4
#define ATTR_SIZE 8
#define ATTR_ATIME 16
#define ATTR_MTIME 32
#define ATTR_CTIME 64
#define ATTR_ATIME_SET 128
#define ATTR_MTIME_SET 256
#define ATTR_FORCE 512
#define ATTR_KILL_SUID 2048
#define ATTR_KILL_SGID 4096
#define ATTR_FILE 8192
#define ATTR_KILL_PRIV 16384
#define ATTR_OPEN 32768
#define ATTR_TIMES_SET 65536
int setattr_prepare(struct mnt_idmap *m, struct dentry *d, struct iattr *a);
void setattr_copy(struct mnt_idmap *m, struct inode *i, const struct iattr *a);
int notify_change(struct mnt_idmap *m, struct dentry *d, struct iattr *a, struct inode **di);
struct timespec64 simple_rename_timestamp(struct inode *a, struct dentry *b, struct inode *c, struct dentry *d);
#undef RENAME_NOREPLACE
#undef RENAME_EXCHANGE
#undef RENAME_WHITEOUT
#define RENAME_NOREPLACE 1
#define RENAME_EXCHANGE 2
#define RENAME_WHITEOUT 4
#define LOOKUP_RCU 1
#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4
#define SEEK_SET_ 0
#define SEEK_DATA 3
#define SEEK_HOLE 4
#define FALLOC_FL_KEEP_SIZE 1
#define FALLOC_FL_PUNCH_HOLE 2
#define FALLOC_FL_COLLAPSE_RANGE 8
#define FALLOC_FL_ZERO_RANGE 16
#define FALLOC_FL_INSERT_RANGE 32
#define FALLOC_FL_ALLOCATE_RANGE 0
#define FALLOC_FL_MODE_MASK 0xff
#define FALLOC_FL_UNSHARE_RANGE 64
#define FS_IOC_GETFLAGS 0x80086601
#define FS_IOC_SETFLAGS 0x40086602
#define FS_IOC_GETFSLABEL 0x81009431
#define FS_IOC_SETFSLABEL 0x41009432
#define FS_IOC_SHUTDOWN 0x8004587d
#define FITRIM 0xc0185879
#define FS_IOC_GETFSUUID 0x80111500
#define FS_LABEL_MAX 256
#define FSLABEL_MAX 256
#define FS_SHUTDOWN_FLAGS_DEFAULT 0
#define FS_SHUTDOWN_FLAGS_LOGFLUSH 1
#define FS_SHUTDOWN_FLAGS_NOLOGFLUSH 2
#define EIOCBQUEUED 529
#define VM_FAULT_SIGBUS 2
#define VM_FAULT_NOPAGE 0x100
#define FS_COMPR_FL 0x4
#define FS_IMMUTABLE_FL 0x10
#define FS_APPEND_FL 0x20
#define FS_NODUMP_FL 0x40
#define FS_NOATIME_FL 0x80
#define FS_ENCRYPT_FL 0x800
#define FS_FL_USER_VISIBLE 0x0003DFFF
struct fstrim_range { u64 start; u64 len; u64 minlen; };
int copy_from_user(void *to, const void *from, unsigned long n);
int copy_to_user(void *to, const void *from, unsigned long n);
#define get_user(x, p) ((x) = *(p), 0)
#define put_user(x, p) (*(p) = (x), 0)
char *strndup_user(const char *s, long n);
static inline void *compat_ptr(unsigned long p) { return (void *)p; }
struct vm_operations_struct { int (*fault)(struct vm_fault *); int (*map_pages)(struct vm_fault *, pgoff_t, pgoff_t); int (*page_mkwrite)(struct vm_fault *); };
struct vm_fault { struct vm_area_struct *vma; struct page *page; };
struct vm_area_struct { struct file *vm_file; unsigned long vm_flags; const struct vm_operations_struct *vm_ops; };
struct vm_area_desc { unsigned long start, end, pgoff; struct file *file; const struct vm_operations_struct *vm_ops; unsigned long vm_flags; };
typedef int vm_fault_t;
int filemap_fault(struct vm_fault *v);
int filemap_map_pages(struct vm_fault *v, pgoff_t s, pgoff_t e);
bool vma_desc_test_all(const struct vm_area_desc *d, ...);
#define VM_SHARED 8
#define VM_MAYWRITE 32
#define VMA_SHARED_BIT 3
#define VMA_MAYWRITE_BIT 5
struct delayed_call { void (*fn)(void *); void *arg; };
static inline void set_delayed_call(struct delayed_call *c, void (*fn)(void *), void *arg) { c->fn = fn; c->arg = arg; }
int page_get_link(void);

/* ------------------------------------------------------------ writeback */
enum writeback_sync_modes { WB_SYNC_NONE, WB_SYNC_ALL };
struct writeback_control { long nr_to_write; long pages_skipped; loff_t range_start; loff_t range_end; enum writeback_sync_modes sync_mode; unsigned for_kupdate:1; unsigned for_background:1; unsigned range_cyclic:1; void *kshim_priv; int kshim_pos; };
struct folio *writeback_iter(struct address_space *m, struct writeback_control *w, struct folio *f, int *e);

/* ---------------------------------------------------------------- block */
struct block_device { void *osdev; u64 size; unsigned int logical_block_size; struct address_space *bd_mapping; struct inode *bd_inode; struct super_block *bd_super;
	int kshim_remounting; /* set by the adapter while the core switches the volume read-write */
	struct kshim_jnl *jnl; /* metadata journal (kshim_jnl.c) while active */
	int kshim_direct; /* nonzero while file data is written: bypasses the journal */
	int kshim_fua; /* the device honours FUA (ngos_dev_fua): the journal's slots and COMMITTED header are written with it, in place of flushes */
	int kshim_defer; /* set by the glue (under the volume lock) around a write-through write: a caller's buffer written directly is sent and waited for later (ngos_dev_drain) */
	int kshim_defer_now; /* kshim_defer, for the one direct write the core is making now (a bounce buffer is never sent that way) */
	int kshim_wt_fua; /* set by the glue (under the volume lock) while a write-through write runs: its file data goes to the device with FUA */
	int kshim_wb_err; /* first failed write of an asynchronous bio (its completion cannot report it) */
	unsigned long kshim_wr_failed; /* device writes that failed, all paths (unmount: commit nothing after one) */
	int kshim_gone; /* the medium was replaced: every device read and write fails */
	int kshim_frozen; /* the disk was written under the mount: every device write fails */
	/* Set by the NT glue: waits until no file-data write the glue issued outside the volume lock is on
	 * its way to the device (nt/write.c, NgDrainDataIoCallback).  Called under the volume lock, before clusters
	 * are freed and before the device stops being the volume's. */
	void (*kshim_drain)(void *ctx);
	void *kshim_drain_ctx;
	/* Set by the NT glue: asks its flusher to commit soon (the journal overlay is past its threshold).  Called under the volume lock; must not block. */
	void (*kshim_kick)(void *ctx);
	void *kshim_kick_ctx; };
/* Waits for the file-data writes in flight outside the volume lock (see kshim_drain). */
static inline void kshim_dio_drain(struct block_device *b) { if (b && b->kshim_drain) b->kshim_drain(b->kshim_drain_ctx); }
static inline u64 bdev_nr_bytes(struct block_device *b) { return b->size; }
static inline unsigned int bdev_logical_block_size(struct block_device *b) { return b->logical_block_size; }
static inline unsigned int bdev_physical_block_size(struct block_device *b) { return b->logical_block_size; }
static inline unsigned int bdev_max_discard_sectors(struct block_device *b) { (void)b; return 0; }
static inline unsigned int bdev_discard_granularity(struct block_device *b) { (void)b; return 0; }
static inline bool bdev_read_only(struct block_device *b) { (void)b; return false; }
int bdev_freeze(struct block_device *b);
int bdev_thaw(struct block_device *b);
int sync_blockdev(struct block_device *b);
int blkdev_issue_flush(struct block_device *b);
int blkdev_issue_discard(struct block_device *b, sector_t s, sector_t n, gfp_t g);
int blkdev_issue_zeroout(struct block_device *b, sector_t s, sector_t n, gfp_t g, unsigned f);
#define BLKDEV_ZERO_NOUNMAP 1
#define REQ_OP_READ 0
#define REQ_OP_WRITE 1
#define REQ_OP_MASK 0xff
#define REQ_META (1 << 8)
#define REQ_SYNC (1 << 9)
#define REQ_PRIO (1 << 10)
#define REQ_FUA (1 << 11)
#define REQ_PREFLUSH (1 << 12)
#define REQ_RAHEAD (1 << 13)
#define BLK_STS_OK 0
#define BLK_STS_IOERR 10
int blk_status_to_errno(blk_status_t s);
int bdev_rw_virt(struct block_device *b, sector_t s, void *data, size_t len, blk_opf_t op);
struct bvec_iter { sector_t bi_sector; unsigned int bi_size; unsigned int bi_idx; unsigned int bi_bvec_done; };
struct bio_vec { struct page *bv_page; unsigned int bv_len; unsigned int bv_offset; };
typedef void (bio_end_io_t)(struct bio *);
struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
	blk_status_t bi_status;
	struct bvec_iter bi_iter;
	bio_end_io_t *bi_end_io;
	void *bi_private;
	unsigned short bi_vcnt;
	unsigned short bi_max_vecs;
	struct bio_vec *bi_io_vec;
	struct bio *kshim_chain;
};
struct bio *bio_alloc(struct block_device *b, unsigned short nr, blk_opf_t op, gfp_t g);
void kshim_wb_scope_enter(void);	/* around a call into core writeback: reserve bios it abandons come back */
void kshim_wb_scope_exit(void);
void kshim_wb_scope_point(void);	/* between folios of a writepages walk */
void bio_put(struct bio *b);
bool bio_add_folio(struct bio *b, struct folio *f, size_t len, size_t off);
void bio_add_folio_nofail(struct bio *b, struct folio *f, size_t len, size_t off);
int bio_add_page(struct bio *b, struct page *p, unsigned int len, unsigned int off);
unsigned int bio_add_vmalloc_chunk(struct bio *b, void *vaddr, unsigned len);
static inline unsigned short bio_max_segs(unsigned int n) { return n > 256 ? 256 : n; }
static inline sector_t bio_end_sector(struct bio *b) { return b->bi_iter.bi_sector + (b->bi_iter.bi_size >> 9); }
void bio_chain(struct bio *b, struct bio *parent);
void submit_bio(struct bio *b);
int submit_bio_wait(struct bio *b);
#define bio_for_each_folio_all(fi, bio) \
	for (unsigned short _i = 0; _i < (bio)->bi_vcnt && \
	     ((fi).folio = page_folio((bio)->bi_io_vec[_i].bv_page), \
	      (fi).offset = (bio)->bi_io_vec[_i].bv_offset, \
	      (fi).length = (bio)->bi_io_vec[_i].bv_len, 1); _i++)
struct blk_plug { int dummy; };
#define blk_start_plug(p) do { } while (0)
#define blk_finish_plug(p) do { } while (0)

/* ------------------------------------------------------------------ nls */
typedef u16 wchar_t_;
typedef u16 kshim_wchar;
struct nls_table {
	const char *charset;
	int (*uni2char)(wchar_t_ uni, unsigned char *out, int boundlen);
	int (*char2uni)(const unsigned char *rawstring, int boundlen, wchar_t_ *uni);
	struct module *owner;
};
struct nls_table *load_nls(const char *charset);
struct nls_table *load_nls_default(void);
void unload_nls(struct nls_table *t);
enum utf16_endian { UTF16_HOST_ENDIAN, UTF16_LITTLE_ENDIAN, UTF16_BIG_ENDIAN };
int utf8s_to_utf16s(const u8 *s, int len, enum utf16_endian e, wchar_t_ *pwcs, int maxlen);
int utf16s_to_utf8s(const wchar_t_ *pwcs, int len, enum utf16_endian e, u8 *s, int maxlen);
#define NLS_MAX_CHARSET_SIZE 6

/* ----------------------------------------------------------- xattr/acl */
struct xattr_handler {
	const char *name; const char *prefix; int flags;
	bool (*list)(struct dentry *dentry);
	int (*get)(const struct xattr_handler *, struct dentry *dentry, struct inode *inode, const char *name, void *buffer, size_t size);
	int (*set)(const struct xattr_handler *, struct mnt_idmap *idmap, struct dentry *dentry, struct inode *inode, const char *name, const void *buffer, size_t size, int flags);
};
#define XATTR_CREATE 1
#define XATTR_REPLACE 2
#define XATTR_NAME_POSIX_ACL_ACCESS "system.posix_acl_access"
#define XATTR_NAME_POSIX_ACL_DEFAULT "system.posix_acl_default"
#define XATTR_SIZE_MAX 65536
#define XATTR_NAME_MAX 255
#define XATTR_LIST_MAX 65536
#define XATTR_USER_PREFIX "user."
#define XATTR_USER_PREFIX_LEN 5
#define XATTR_SYSTEM_PREFIX "system."
#define XATTR_SECURITY_PREFIX "security."
#define XATTR_TRUSTED_PREFIX "trusted."
extern const struct xattr_handler nop_posix_acl_access, nop_posix_acl_default;
const char *xattr_full_name(const struct xattr_handler *h, const char *name);
#define ACL_TYPE_ACCESS 0x8000
#define ACL_TYPE_DEFAULT 0x4000
#define ACL_NOT_CACHED ((void *)(-1))
struct posix_acl { int a_count; };
struct posix_acl *posix_acl_from_xattr(struct user_namespace *ns, const void *v, size_t s);
int posix_acl_to_xattr(struct user_namespace *ns, const struct posix_acl *a, void *b, size_t s);
void *posix_acl_to_xattr_alloc(struct user_namespace *ns, const struct posix_acl *a, size_t *s, gfp_t g);
void posix_acl_release(struct posix_acl *a);
int posix_acl_chmod(struct mnt_idmap *m, struct dentry *d, umode_t mode);
int posix_acl_create(struct inode *dir, umode_t *mode, struct posix_acl **def, struct posix_acl **acl);
int posix_acl_update_mode(struct mnt_idmap *m, struct inode *i, umode_t *mode, struct posix_acl **acl);
int posix_acl_valid(struct user_namespace *ns, const struct posix_acl *a);
void set_cached_acl(struct inode *i, int t, struct posix_acl *a);
void forget_all_cached_acls(struct inode *i);
#define posix_acl_xattr_size(c) (4 + (c) * 8)
size_t posix_acl_xattr_count(size_t s);

/* -------------------------------------------------------------- seq_file */
struct seq_file { char *buf; size_t size, count; };
void seq_printf(struct seq_file *m, const char *fmt, ...);
void seq_puts(struct seq_file *m, const char *s);
#define seq_show_option(m, n, v) seq_printf(m, ",%s=%s", n, v)

/* ------------------------------------------------------------ export */
struct fid { u32 raw[6]; };
struct export_operations {
	int (*encode_fh)(struct inode *inode, u32 *fh, int *max_len, struct inode *parent);
	struct dentry *(*fh_to_dentry)(struct super_block *sb, struct fid *fid, int fh_len, int fh_type);
	struct dentry *(*fh_to_parent)(struct super_block *sb, struct fid *fid, int fh_len, int fh_type);
	struct dentry *(*get_parent)(struct dentry *child);
	int (*commit_metadata)(struct inode *inode);
	unsigned long flags;
};
struct dentry *generic_fh_to_dentry(struct super_block *sb, struct fid *fid, int fh_len, int fh_type, struct inode *(*get_inode)(struct super_block *sb, u64 ino, u32 gen));
struct dentry *generic_fh_to_parent(struct super_block *sb, struct fid *fid, int fh_len, int fh_type, struct inode *(*get_inode)(struct super_block *sb, u64 ino, u32 gen));
#define EXPORT_OP_NOATOMIC_ATTR 1
#define EXPORT_OP_ASYNC_LOCK 2

/* -------------------------------------------------------------- fiemap */
struct fiemap_extent_info { unsigned int fi_flags; };
int fiemap_prep(struct inode *i, struct fiemap_extent_info *f, u64 s, u64 *l, u32 sup);
#define FIEMAP_FLAG_SYNC 1

/* ------------------------------------------------------------- sysctl/proc */
struct ctl_table { const char *procname; void *data; int maxlen; umode_t mode; void *proc_handler; void *extra1, *extra2; };
struct ctl_table_header { int dummy; };
struct ctl_table_header *register_sysctl(const char *p, const struct ctl_table *t);
void unregister_sysctl_table(struct ctl_table_header *h);
int proc_dointvec_minmax(const struct ctl_table *t, int w, void *b, size_t *l, loff_t *p);
#define SYSCTL_ZERO ((void *)0)
#define SYSCTL_ONE ((void *)1)
struct proc_dir_entry { int dummy; };

/* ---------------------------------------------------------------- sort */
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int));

/* ------------------------------------------------------- ratelimit/misc */
struct ratelimit_state { int dummy; };
#define DEFINE_RATELIMIT_STATE(n, i, b) struct ratelimit_state n
#define __ratelimit(r) 1
/* Reached from ntfs_handle_error with on_errors=continue, right after the error message: see kshim_core_error. */
int kshim_errseq_check(errseq_t *e, errseq_t since);
#define errseq_check(e, s) kshim_errseq_check(e, s)
#define errseq_set(e, v) do { } while (0)
#define errseq_sample(e) 0
#define freezable_schedule() do { } while (0)
#define try_to_freeze() 0

#include "kshim_iomap.h"

#endif

struct readahead_control { struct file *file; struct address_space *mapping; pgoff_t _index; unsigned int _nr_pages; };
int generic_error_remove_folio(struct address_space *m, struct folio *f);
int generic_setlease(struct file *f, int a, struct file_lock **l, void **p);
void kfree_link(void *p);
#define alloc_inode_sb(sb, c, g) kmem_cache_alloc(c, g)
int generic_encode_ino32_fh(struct inode *inode, u32 *fh, int *max_len, struct inode *parent);
