/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ngapi.h - the interface between the NT glue (nt/, compiled with NT headers)
 * and the fs/ntfs core plus shim (compiled with Linux-API headers only).
 * Only basic C types cross it.  Errors are negative Linux errno values.
 */
#ifndef NGAPI_H
#define NGAPI_H

typedef struct ngc_vol ngc_vol;      /* a mounted fs/ntfs super_block */
typedef struct ngc_node ngc_node;    /* a referenced fs/ntfs VFS inode */

#define NGC_ENOENT 2
#define NGC_EIO 5
#define NGC_EAGAIN 11
#define NGC_ENOMEM 12
#define NGC_ENOTDIR 20
#define NGC_EISDIR 21
#define NGC_EINVAL 22
#define NGC_EROFS 30
#define NGC_ENAMETOOLONG 36
#define NGC_EOPNOTSUPP 95
#define NGC_EUCLEAN 117
#define NGC_ENOSPC 28
#define NGC_EEXIST 17
#define NGC_ENOTEMPTY 39
#define NGC_EACCES 13
#define NGC_EPERM 1
#define NGC_EFBIG 27
#define NGC_EXDEV 18
#define NGC_ENODATA 61
#define NGC_EBUSY 16

#define NGC_LABEL_MAX 32         /* volume label, UTF-16 units (Windows' limit) */

#define NGC_ATTR_COMPRESSED 1
#define NGC_ATTR_SPARSE 2
#define NGC_ATTR_ENCRYPTED 4
#define NGC_ATTR_NOWRITE 8      /* compressed, encrypted, WOF or sparse: the driver does not write it */

struct ngc_stat {
	unsigned long long mft_ref;      /* MFT number | sequence << 48 */
	unsigned long long size;
	unsigned long long alloc;        /* on-disk allocation (compressed size if compressed) */
	long long crtime, atime, mtime, ctime;  /* NT time, 100 ns since 1601 */
	unsigned int file_attributes;    /* $STANDARD_INFORMATION flags (FILE_ATTRIBUTE_* values) */
	unsigned int nlink;
	unsigned int flags;              /* NGC_ATTR_* of this stream */
	int is_dir;
	int is_link;
};

struct ngc_volinfo {
	unsigned long long total_clusters;
	unsigned long long free_clusters;
	unsigned long long serial;
	unsigned int cluster_size;
	unsigned int sector_size;
	unsigned int label_len;          /* in UTF-16 units */
	unsigned short label[NGC_LABEL_MAX];
	unsigned char major, minor;
	unsigned char read_only;         /* mounted read-only (policy or request) */
	unsigned char dirty;             /* VOLUME_IS_DIRTY currently set */
	unsigned char damaged;           /* the mount-time consistency check found damage (read-only) */
	unsigned char label_valid;       /* label was read (0: reading it ran out of memory, ask again) */
};

/* Mount-time consistency check: 0 never, 1 after an unclean shutdown or for small MFTs, 2 always. */
extern int ngc_check_policy;

typedef int (*ngc_filldir_t)(void *ctx, const unsigned short *name, unsigned int len,
		unsigned long long mft_no, unsigned int dtype);
typedef int (*ngc_stream_t)(void *ctx, const unsigned short *name, unsigned int len,
		unsigned long long size, unsigned long long alloc);

int ngc_init(void);
/* Mounts; with want_rw the volume goes read-write unless policy refuses (*why_ro says why). */
int ngc_mount(void *osdev, unsigned long long size, unsigned int sector_size, int want_rw,
		ngc_vol **out, const char **why_ro);
/* Unmounts; with discard nothing of the mounted state is written (the disk was rewritten behind it). */
void ngc_umount(ngc_vol *v, int discard);
void ngc_volinfo(ngc_vol *v, struct ngc_volinfo *vi);
ngc_node *ngc_root(ngc_vol *v);
/* Looks @name up in @dir; with @real (NTFS_MAX_NAME_LEN units) also returns the name as stored on disk. */
int ngc_lookup(ngc_vol *v, ngc_node *dir, const unsigned short *name, unsigned int len, ngc_node **out,
		unsigned short *real, unsigned int *real_len);
int ngc_open_stream(ngc_vol *v, ngc_node *base, const unsigned short *sname, unsigned int len, ngc_node **out);
int ngc_iget(ngc_vol *v, unsigned long long mft_no, ngc_node **out);
int ngc_iget_by_id(ngc_vol *v, unsigned long long mft_no, ngc_node **out);	/* caller-supplied number */
void ngc_medium_gone(ngc_vol *v);
/* The disk was written under the mount: every later device write of the core is refused (reads go on). */
void ngc_stop_writes(ngc_vol *v);
void ngc_put(ngc_node *n);
void ngc_stat(ngc_node *n, struct ngc_stat *st);
int ngc_readdir(ngc_vol *v, ngc_node *dir, ngc_filldir_t fn, void *ctx);

/* One directory entry with what a directory listing shows (ngc_readdir_full). */
struct ngc_dirent {
	const unsigned short *name;
	unsigned int len;                /* in UTF-16 units */
	int is_dot;                      /* "." or ".." (st not filled) */
	struct ngc_stat st;
	unsigned short short_name[12];   /* the 8.3 name of this link in this directory, if any */
	unsigned int short_len;
	unsigned int reparse_tag;
};
typedef int (*ngc_dirent_t)(void *ctx, const struct ngc_dirent *e);
int ngc_readdir_full(ngc_vol *v, ngc_node *dir, ngc_dirent_t fn, void *ctx);
int ngc_streams(ngc_node *n, ngc_stream_t fn, void *ctx);
/* Reads [off, off+len) through the private page cache; bytes past EOF are zero.  Returns bytes copied or <0. */
long ngc_read(ngc_node *n, unsigned long long off, unsigned int len, void *buf, int drop_cache);
long ngc_read_direct(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, void *buf);
/* Write side (all under the caller's volume lock). */
/* ntfsng mounts no device of this size or more: its page index is 32 bits (2^32 pages of 4 KiB). */
#define NGC_MAX_DEVICE_BYTES (1ULL << 44)
int ngc_is_rw(ngc_vol *v);
/* True when the core stopped writing for good: changes not committed yet are lost. */
int ngc_failed(ngc_vol *v);
int ngc_mark_dirty(ngc_vol *v);
/* The volume stays dirty on disk until a mount-time check clears it (FSCTL_MARK_VOLUME_DIRTY); -EROFS on a read-only volume. */
int ngc_mark_volume_dirty(ngc_vol *v);
int ngc_sync(ngc_vol *v);
int ngc_commit_now(ngc_vol *v);
int ngc_changed(ngc_vol *v);
void ngc_icache_trim(ngc_vol *v);
int ngc_dirty(ngc_vol *v);
void ngc_jnl_report(ngc_vol *v);
#if DBG
void ngc_set_journal_fault(unsigned long commit_no);
/* Test only: report every every'th unlocked write (ngc_dio_end) as "mapping changed", to run the glue's write-again path; 0 = off. */
void ngc_set_dio_fault(unsigned long every);
extern unsigned long ngc_dio_forced;
#endif
typedef int (*ngc_run_t)(void *ctx, unsigned long long vcn, long long lcn, unsigned long long len);
int ngc_runs(ngc_vol *v, ngc_node *n, ngc_run_t fn, void *ctx);
int ngc_raw_write(ngc_vol *v, unsigned long long off, const void *buf, unsigned int len);
int ngc_links(ngc_node *n);
int ngc_parent_name(ngc_node *n, unsigned long long *parent, unsigned short *out, unsigned int *len);
int ngc_get_security(ngc_vol *v, ngc_node *n, void **out, unsigned int *len);
int ngc_set_security(ngc_vol *v, ngc_node *n, const void *sd, unsigned int len);
/* Volume size (under the caller's volume lock).  Sectors are of the volume's sector size. */
struct ngc_ntfsdata {
	unsigned long long serial, sectors, total_clusters, free_clusters;
	unsigned long long mft_valid_data, mft_lcn, mft2_lcn, mft_zone_start, mft_zone_end;
	unsigned int bytes_per_sector, bytes_per_cluster, bytes_per_record;
	unsigned char major, minor;
};
void ngc_ntfs_data(ngc_vol *v, struct ngc_ntfsdata *d);
int ngc_read_bitmap(ngc_vol *v, unsigned long long off, unsigned int len, void *buf);
/* Grows the volume to @sectors on a device of @dev_size bytes (the sector after the volume holds the boot copy). */
int ngc_extend(ngc_vol *v, unsigned long long sectors, unsigned long long dev_size);
/* 0 when @sectors leaves fewer clusters (at least one), else -EINVAL. */
int ngc_shrink_valid(ngc_vol *v, unsigned long long sectors);
/* Shrinks to @sectors when every cluster past them is free (-ENOSPC otherwise; no data moves). */
int ngc_shrink(ngc_vol *v, unsigned long long sectors);
/* Test only (the "ResizeFault" DWORD of the Ntfs service key): the next resize fails at that stage
 * (1: extend after the $Bitmap changes, before any commit; 2: extend after the $Bitmap commit;
 * 3: shrink after the padding-bit commit; 4: the in-place pass of the extend's first commit fails
 * half way; 5: the journal is degraded when the extend starts; 6: no overlay page can be allocated
 * during the extend; 7: the in-place pass of the extend's boot-sector commit fails half way), as a
 * failing device write or allocation would. */
#if DBG
extern int ngc_resize_fault;
#else
#define ngc_resize_fault 0   /* fault injection compiled out of release */
#endif
/* Sets the volume label (@len UTF-16 units, at most NGC_LABEL_MAX; 0 clears it). */
int ngc_set_label(ngc_vol *v, const unsigned short *label, unsigned int len);
void ngc_free(void *p);
int ngc_create_stream(ngc_vol *v, ngc_node *base, const unsigned short *sname, unsigned int len, ngc_node **out);
int ngc_delete_stream(ngc_vol *v, ngc_node *n);
int ngc_is_reparse(ngc_node *n);
int ngc_get_reparse(ngc_node *n, void **out, unsigned int *len);
int ngc_set_reparse(ngc_vol *v, ngc_node *n, const void *data, unsigned int len);
int ngc_delete_reparse(ngc_vol *v, ngc_node *n, unsigned int tag);
int ngc_short_name(ngc_node *n, unsigned long long parent_mref, unsigned short *out, unsigned int *len);
int ngc_add_short_name(ngc_vol *v, ngc_node *dir, ngc_node *n, const unsigned short *lname, unsigned int llen,
		const unsigned short *sname, unsigned int slen);
long ngc_write(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, const void *buf);
/*
 * A data write in three steps, so the device transfer runs without the volume lock (paging writes):
 * ngc_dio_begin (locked) checks the write needs no metadata change other than raising the initialized
 * size, maps its clusters and pins the node; the caller writes each run to the device (unlocked:
 * dev = device offset, len = bytes, boff = offset in the caller's buffer; the last run is rounded up
 * to a whole sector, so the buffer must hold @cap >= that many bytes); ngc_dio_end (locked) checks
 * the mapping still holds, raises the initialized size, updates the page cache and unpins.
 * ngc_dio_begin returns 0 (pinned: ngc_dio_end must follow), -NGC_EAGAIN (use ngc_write instead,
 * nothing changed) or another error.  ngc_dio_end returns the bytes written, -NGC_EAGAIN (the mapping
 * changed under the transfer: write again with ngc_write) or another error.
 */
#define NGC_DIO_RUNS 16
struct ngc_dio_run {
	unsigned long long dev;
	unsigned int len;
	unsigned int boff;
};
struct ngc_dio {
	ngc_node *n;
	unsigned long long off;
	unsigned int len;                /* clipped to the stream size */
	unsigned int cap;
	unsigned int nruns;
	struct ngc_dio_run run[NGC_DIO_RUNS];
};
int ngc_dio_begin(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, unsigned int cap, struct ngc_dio *d);
long ngc_dio_end(ngc_vol *v, struct ngc_dio *d, const void *buf, int io_err);
/*
 * Paging and non-cached reads the same way (ngc_rdio_begin/end, for streams ngc_read_direct handles): begin
 * (locked) maps the clusters of [off, off+len) into runs and pins the node; the caller then fills the
 * buffer without the volume lock: a run with dev == NGC_DIO_ZERO is zeroed (hole, past the initialized size or
 * EOF), any other is read from the device (dev = device offset, len = bytes, boff = offset in the buffer; runs
 * are in buffer order and a later run may overwrite the tail of an earlier one); ngc_rdio_end (locked) unpins.
 * ngc_rdio_begin returns 0 (pinned: ngc_rdio_end must follow) or -NGC_EAGAIN (use ngc_read_direct / ngc_read
 * instead, nothing changed).  The data is what the stream held when ngc_rdio_begin ran (the clusters cannot be
 * freed meanwhile: see the drain below).
 */
#define NGC_DIO_ZERO (~0ULL)
int ngc_rdio_begin(ngc_vol *v, ngc_node *n, unsigned long long off, unsigned int len, void *buf, struct ngc_dio *d);
void ngc_rdio_end(ngc_vol *v, struct ngc_dio *d);
/* Registers the glue's drain (see kshim_drain in kshim_vfs.h); NULL unregisters. */
void ngc_set_dio_drain(ngc_vol *v, void (*fn)(void *ctx), void *ctx);
int ngc_set_size(ngc_vol *v, ngc_node *n, unsigned long long newsize);
int ngc_set_info(ngc_vol *v, ngc_node *n, const long long times[4], unsigned int attrs, unsigned int attrs_mask);
int ngc_create(ngc_vol *v, ngc_node *dir, const unsigned short *name, unsigned int len, int is_dir, ngc_node **out);
int ngc_unlink(ngc_vol *v, ngc_node *dir, const unsigned short *name, unsigned int len, ngc_node *n);
int ngc_rename(ngc_vol *v, ngc_node *odir, const unsigned short *oname, unsigned int olen, ngc_node *n,
		ngc_node *ndir, const unsigned short *nname, unsigned int nlen, ngc_node *target);
int ngc_link(ngc_vol *v, ngc_node *n, ngc_node *ndir, const unsigned short *nname, unsigned int nlen);
int ngc_dir_empty(ngc_vol *v, ngc_node *dir);
void ngc_write_stats(unsigned long *writes, unsigned long long *bytes, unsigned long *syncs, unsigned long *dirties);
/* Prints shim memory accounting (live allocations by call site, cache pages, inodes). */
void ngc_debug_dump(void);

#endif
