// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kshim.c - kernel-mode implementations of the Linux kernel APIs that the
 * fs/ntfs read path calls, ported from the user-mode spike shim.  Memory is
 * nonpaged pool, locks are NT dispatcher objects and spin locks, block I/O
 * is IRP-based, all through ngos.h.  The writeback side (writeback_iter,
 * write_inode_now, the volume sync loop) is in kshim_wb.c, the iomap services
 * in kshim_iomap.c.
 * APIs only reached from mmap, ioctl or VFS paths the NT glue never drives
 * are generated into kshim_stubs.c and stop the system with their name.
 */
#include <kshim.h>
#include <kshim_jnl.h>

struct task_struct kshim_task;
struct user_namespace init_user_ns;
struct mnt_idmap nop_mnt_idmap;
const char hex_asc[] = "0123456789abcdef";
int kshim_verbose;
static uintptr_t kshim_a64_lock;
static uintptr_t kshim_pc_lock;
static DEFINE_MUTEX(kshim_inode_lock);
/* kshim_wb.c */
int kshim_mapping_writeback(struct address_space *m);
bool kshim_mapping_dirty(struct address_space *m);
int kshim_sync(struct super_block *sb);

/* ------------------------------------------------------------- printk */
/*
 * Error-level messages, kept per thread for kshim_errseq_check: the core prints a report and then,
 * on the same thread, reaches errseq_check through ntfs_handle_error.  Other threads (other volumes,
 * shared readers) cannot replace a thread's message in between.
 */
#define KSHIM_ERR_SLOTS 64
static struct { void *thread; unsigned long long stamp; char msg[192]; } kshim_err_slot[KSHIM_ERR_SLOTS];
static unsigned long long kshim_err_stamp;
#define KSHIM_ERR_LOST 16
static void *kshim_err_lost[KSHIM_ERR_LOST];	/* threads whose slot was reused: their check cannot trust "no message" */
static unsigned int kshim_err_lost_next;
static int kshim_err_lost_overflow;	/* a lost thread fell out of the ring too: no check can trust "no message" */
static uintptr_t kshim_err_lock;
void (*kshim_core_error)(struct super_block *sb, const char *msg);

static void kshim_err_record(const char *msg)
{
	void *t = ngos_current_thread();
	unsigned char irql = ngos_spin_lock(&kshim_err_lock);
	unsigned int i;
	for (i = 0; i < KSHIM_ERR_SLOTS && kshim_err_slot[i].thread != t; i++)
		;
	if (i == KSHIM_ERR_SLOTS)
		for (i = 0; i < KSHIM_ERR_SLOTS && kshim_err_slot[i].thread; i++)
			;
	if (i == KSHIM_ERR_SLOTS) {
		/* The oldest report goes: reports never checked (a read-only volume) are the first to. */
		i = 0;
		for (unsigned int k = 1; k < KSHIM_ERR_SLOTS; k++)
			if (kshim_err_slot[k].stamp < kshim_err_slot[i].stamp)
				i = k;
		if (kshim_err_lost[kshim_err_lost_next % KSHIM_ERR_LOST])
			kshim_err_lost_overflow = 1;
		kshim_err_lost[kshim_err_lost_next++ % KSHIM_ERR_LOST] = kshim_err_slot[i].thread;
	}
	kshim_err_slot[i].thread = t;
	kshim_err_slot[i].stamp = ++kshim_err_stamp;
	strncpy(kshim_err_slot[i].msg, msg, sizeof(kshim_err_slot[i].msg) - 1);
	kshim_err_slot[i].msg[sizeof(kshim_err_slot[i].msg) - 1] = 0;
	ngos_spin_unlock(&kshim_err_lock, irql);
}

int kshim_errseq_check(errseq_t *e, errseq_t since)
{
	struct super_block *sb = container_of(e, struct super_block, s_wb_err);
	char msg[sizeof(kshim_err_slot[0].msg)];
	void *t = ngos_current_thread();
	unsigned char irql;
	(void)since;
	msg[0] = 0;
	irql = ngos_spin_lock(&kshim_err_lock);
	for (unsigned int i = 0; i < KSHIM_ERR_SLOTS; i++)
		if (kshim_err_slot[i].thread == t) {
			memcpy(msg, kshim_err_slot[i].msg, sizeof(msg));
			kshim_err_slot[i].thread = NULL;
			break;
		}
	if (!msg[0])
		for (unsigned int i = 0; i < KSHIM_ERR_LOST; i++)
			if (kshim_err_lost[i] == t) {
				kshim_err_lost[i] = NULL;
				strcpy(msg, "corrupt? (the report was lost)");	/* unknown: counted as damage */
				break;
			}
	if (!msg[0] && kshim_err_lost_overflow)
		strcpy(msg, "corrupt? (reports were lost)");
	ngos_spin_unlock(&kshim_err_lock, irql);
	if (kshim_core_error)
		kshim_core_error(sb, msg);
	return 0;
}

int printk(const char *fmt, ...)
{
	va_list ap;
	int lvl = 4;
	char *buf;

	if (fmt[0] == '<' && fmt[1] >= '0' && fmt[1] <= '7' && fmt[2] == '>') {
		lvl = fmt[1] - '0';
		fmt += 3;
	}
	if (lvl > 4 && !kshim_verbose)
		return 0;
	buf = ngos_alloc(512);
	if (!buf) {
		/* An error report still reaches the classifier: formatted into a spare buffer, not printed. */
		if (lvl <= 3) {
			static char spare[256];
			static uintptr_t spare_lock;
			unsigned char irql = ngos_spin_lock(&spare_lock);
			va_start(ap, fmt);
			vsnprintf(spare, sizeof(spare), fmt, ap);
			va_end(ap);
			kshim_err_record(spare);
			ngos_spin_unlock(&spare_lock, irql);
		}
		return 0;
	}
	memcpy(buf, "ntfsng: ", 8);
	va_start(ap, fmt);
	vsnprintf(buf + 8, 512 - 8, fmt, ap);
	va_end(ap);
	if (lvl <= 3)
		kshim_err_record(buf + 8);
	ngos_print(buf);
	ngos_free(buf);
	return 0;
}

void kshim_bug(const char *file, int line)
{
	ngos_bugcheck("BUG", file, line);
}

void kshim_unimpl(const char *name)
{
	ngos_bugcheck(name, "unimplemented Linux API", 0);
}

/* ------------------------------------------------------------- memory */
/*
 * A 16-byte header (on x86) keeps the size for krealloc and the allocating
 * call site, so live allocations can be attributed when hunting leaks.
 */
struct khdr { size_t n; size_t magic; void *caller; size_t pad; };
#define KMAGIC ((size_t)0x4e474b4dUL)
#define KSITES 1024
static struct { void *caller; long live; long long bytes; } ksites[KSITES];
#ifndef __x86_64__
static uintptr_t ksites_lock;
#endif
long kshim_alloc_live;
long long kshim_alloc_bytes;
/* Unused (cached) inodes over all volumes and what they cost, for the Verbose dump (kshim_dump_icache). */
static long kshim_lru_total;
static long long kshim_lru_bytes_total;
static void kshim_dump_icache(void);
#ifdef __x86_64__
/*
 * Every kmalloc and kfree passes here (dozens per file operation), so on
 * 64-bit it takes no lock: a slot is claimed with a compare-exchange on its
 * caller and the counters are atomic adds. A spin lock here cost a raise and
 * a lower of the IRQL per call (two CR8 writes). The dump reads the table
 * without a lock either way, so it sees the same kind of snapshot.
 */
static void ksite_account(void *caller, long d, long long bytes)
{
	unsigned int h = ((uintptr_t)caller >> 2) % KSITES;
	for (unsigned int i = 0; i < KSITES; i++, h = (h + 1) % KSITES) {
		void *c = __atomic_load_n(&ksites[h].caller, __ATOMIC_ACQUIRE);
		if (!c) {
			void *expected = NULL;
			c = __atomic_compare_exchange_n(&ksites[h].caller, &expected, caller, 0,
							__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? caller : expected;
		}
		if (c == caller) {
			__atomic_add_fetch(&ksites[h].live, d, __ATOMIC_RELAXED);
			__atomic_add_fetch(&ksites[h].bytes, bytes, __ATOMIC_RELAXED);
			break;
		}
	}
	__atomic_add_fetch(&kshim_alloc_live, d, __ATOMIC_RELAXED);
	__atomic_add_fetch(&kshim_alloc_bytes, bytes, __ATOMIC_RELAXED);
}
#else
static void ksite_account(void *caller, long d, long long bytes)
{
	unsigned int h = ((uintptr_t)caller >> 2) % KSITES;
	unsigned char irql = ngos_spin_lock(&ksites_lock);
	for (unsigned int i = 0; i < KSITES; i++, h = (h + 1) % KSITES) {
		if (ksites[h].caller == caller || !ksites[h].caller) {
			ksites[h].caller = caller;
			ksites[h].live += d;
			ksites[h].bytes += bytes;
			break;
		}
	}
	kshim_alloc_live += d;
	kshim_alloc_bytes += bytes;
	ngos_spin_unlock(&ksites_lock, irql);
}
#endif
void kshim_dump_allocs(void)
{
	int top[12], nt = 0;
	kshim_dump_icache();
	for (int k = 0; k < 12; k++) {
		int best = -1;
		for (int i = 0; i < KSITES; i++) {
			int seen = 0;
			for (int j = 0; j < nt; j++) if (top[j] == i) seen = 1;
			if (!seen && ksites[i].caller && (best < 0 || ksites[i].bytes > ksites[best].bytes)) best = i;
		}
		if (best < 0 || ksites[best].live <= 0) break;
		top[nt++] = best;
	}
	printk("allocs: %ld live, %lld bytes; top call sites:\n", kshim_alloc_live, kshim_alloc_bytes);
	for (int k = 0; k < nt; k++)
		printk("  site %p: %ld live, %lld bytes\n", ksites[top[k]].caller, ksites[top[k]].live, ksites[top[k]].bytes);
}
static void *kmalloc_site(size_t n, gfp_t g, void *caller)
{
	struct khdr *h = ngos_alloc(sizeof(*h) + (n ? n : 1));
	if (!h)
		return NULL;
	h->n = n; h->magic = KMAGIC; h->caller = caller;
	ksite_account(caller, 1, n);
	if (g & __GFP_ZERO)
		memset(h + 1, 0, n);
	return h + 1;
}
void *kmalloc(size_t n, gfp_t g) { return kmalloc_site(n, g, __builtin_return_address(0)); }
void *kzalloc(size_t n, gfp_t g) { return kmalloc_site(n, g | __GFP_ZERO, __builtin_return_address(0)); }
void *kcalloc(size_t n, size_t s, gfp_t g)
{
	size_t t;
	if (__builtin_mul_overflow(n, s, &t))
		return NULL;
	return kmalloc_site(t, g | __GFP_ZERO, __builtin_return_address(0));
}
void *kmalloc_array(size_t n, size_t s, gfp_t g)
{
	size_t t;
	if (__builtin_mul_overflow(n, s, &t))
		return NULL;
	return kmalloc_site(t, g, __builtin_return_address(0));
}
void kfree(const void *p)
{
	struct khdr *h;
	if (!p || IS_ERR(p))
		return;
	h = (struct khdr *)p - 1;
	if (h->magic != KMAGIC)
		ngos_bugcheck("kfree of a foreign pointer", __FILE__, __LINE__);
	h->magic = 0;
	ksite_account(h->caller, -1, -(long long)h->n);
	ngos_free(h);
}
void *krealloc(const void *p, size_t n, gfp_t g)
{
	void *q;
	size_t old;
	if (!p)
		return kmalloc(n, g);
	old = ((struct khdr *)p - 1)->n;
	q = kmalloc(n, g);
	if (!q)
		return NULL;
	memcpy(q, p, old < n ? old : n);
	kfree(p);
	return q;
}
char *kstrdup(const char *s, gfp_t g) { return s ? kmemdup(s, strlen(s) + 1, g) : NULL; }
char *kstrndup(const char *s, size_t n, gfp_t g)
{
	size_t l = 0;
	char *p;
	if (!s)
		return NULL;
	while (l < n && s[l]) l++;
	p = kmalloc(l + 1, g);
	if (p) { memcpy(p, s, l); p[l] = 0; }
	return p;
}
void *kmemdup(const void *s, size_t n, gfp_t g) { void *p = kmalloc_site(n, g, __builtin_return_address(0)); if (p) memcpy(p, s, n); return p; }
unsigned long totalram_pages(void) { return ngos_physical_pages(); }
struct kmem_cache *kmem_cache_create(const char *name, unsigned int size,
		unsigned int align, unsigned long flags, void (*ctor)(void *))
{
	struct kmem_cache *c = kzalloc(sizeof(*c), GFP_KERNEL);
	(void)align; (void)flags;
	if (!c)
		return NULL;
	c->size = size; c->name = name; c->ctor = ctor;
	return c;
}
void kmem_cache_destroy(struct kmem_cache *c) { kfree(c); }
void *kmem_cache_alloc(struct kmem_cache *c, gfp_t g)
{
	void *p = kmalloc_site(c->size, g | __GFP_ZERO, __builtin_return_address(0));
	if (p && c->ctor) c->ctor(p);
	return p;
}
void *kmem_cache_zalloc(struct kmem_cache *c, gfp_t g) { return kmem_cache_alloc(c, g); }
void kmem_cache_free(struct kmem_cache *c, void *p) { (void)c; kfree(p); }
unsigned long __get_free_page(gfp_t g) { return (uintptr_t)kmalloc(PAGE_SIZE, g); }
void free_page(unsigned long p) { kfree((void *)(uintptr_t)p); }

/* ------------------------------------------------------------- atomics */
s64 kshim_atomic64_add(atomic64_t *v, s64 d)
{
	unsigned char irql = ngos_spin_lock(&kshim_a64_lock);
	s64 r = (v->counter += d);
	ngos_spin_unlock(&kshim_a64_lock, irql);
	if (d > 0)
		kshim_watch_hit(v);
	return r;
}
void kshim_atomic64_set(atomic64_t *v, s64 i)
{
	unsigned char irql = ngos_spin_lock(&kshim_a64_lock);
	v->counter = i;
	ngos_spin_unlock(&kshim_a64_lock, irql);
}

/* --------------------------------------------------------------- locks */
static void mutex_ready(struct mutex *m)
{
	int st = __atomic_load_n(&m->state, __ATOMIC_ACQUIRE);
	if (st == 2)
		return;
	st = 0;
	if (__atomic_compare_exchange_n(&m->state, &st, 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
		ngos_ev_init(&m->ev, 1, 0);
		__atomic_store_n(&m->state, 2, __ATOMIC_RELEASE);
		return;
	}
	while (__atomic_load_n(&m->state, __ATOMIC_ACQUIRE) != 2)
		ngos_yield();
}
/*
 * count: 0 free, 1 held, more: held with waiters.  Only contention reaches the dispatcher, as with
 * a FAST_MUTEX.  The kernel used to charge a quantum unit for a wait on a signaled event that
 * was satisfied at once (NT 5.2; it no longer does), so with every processor busy at the holder's
 * priority a loop over the cached inodes gave the processor away every few inodes while holding
 * the volume lock; the free path keeps such a loop out of the dispatcher altogether.
 * An unlock that finds a waiter sets the event once; a waiter that has not reached its wait yet
 * finds it signaled.
 */
void mutex_init(struct mutex *m) { ngos_ev_init(&m->ev, 1, 0); m->count = 0; m->state = 2; }
void mutex_lock(struct mutex *m)
{
	mutex_ready(m);
	if (__atomic_add_fetch(&m->count, 1, __ATOMIC_SEQ_CST) != 1)
		ngos_ev_wait(&m->ev);
}
int mutex_trylock(struct mutex *m)
{
	long free = 0;
	mutex_ready(m);
	return __atomic_compare_exchange_n(&m->count, &free, 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
void mutex_unlock(struct mutex *m)
{
	long n = __atomic_sub_fetch(&m->count, 1, __ATOMIC_SEQ_CST);

	/* An unlock without a lock; the shim has no NT_ASSERT, so this is the checked-build diagnostic */
	WARN_ON(n < 0);
	if (n != 0)
		ngos_ev_set(&m->ev);
}
int mutex_is_locked(struct mutex *m) { return __atomic_load_n(&m->count, __ATOMIC_SEQ_CST) != 0; }

void read_lock(rwlock_t *l)
{
	for (;;) {
		long c = __atomic_load_n(&l->cnt, __ATOMIC_ACQUIRE);
		if (c >= 0 && __atomic_compare_exchange_n(&l->cnt, &c, c + 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
			return;
		ngos_yield();
	}
}
void read_unlock(rwlock_t *l) { __atomic_sub_fetch(&l->cnt, 1, __ATOMIC_SEQ_CST); }
void write_lock(rwlock_t *l)
{
	for (;;) {
		long c = 0;
		if (__atomic_compare_exchange_n(&l->cnt, &c, -1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
			return;
		ngos_yield();
	}
}
void write_unlock(rwlock_t *l) { __atomic_store_n(&l->cnt, 0, __ATOMIC_SEQ_CST); }

static void rwsem_ready(struct rw_semaphore *s)
{
	int st = __atomic_load_n(&s->state, __ATOMIC_ACQUIRE);
	if (st == 2)
		return;
	st = 0;
	if (__atomic_compare_exchange_n(&s->state, &st, 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
		s->sl = 0; s->readers = 0; s->writer = 0;
		ngos_ev_init(&s->wake, 0, 0);
		__atomic_store_n(&s->state, 2, __ATOMIC_RELEASE);
		return;
	}
	while (__atomic_load_n(&s->state, __ATOMIC_ACQUIRE) != 2)
		ngos_yield();
}
void init_rwsem(struct rw_semaphore *s)
{
	s->sl = 0; s->readers = 0; s->writer = 0;
	ngos_ev_init(&s->wake, 0, 0);
	s->state = 2;
}
static int rwsem_try(struct rw_semaphore *s, int write, int block)
{
	rwsem_ready(s);
	for (;;) {
		unsigned char irql = ngos_spin_lock(&s->sl);
		if (write ? (!s->writer && !s->readers) : !s->writer) {
			if (write) s->writer = 1; else s->readers++;
			ngos_spin_unlock(&s->sl, irql);
			return 1;
		}
		if (!block) {
			ngos_spin_unlock(&s->sl, irql);
			return 0;
		}
		ngos_ev_clear(&s->wake);
		ngos_spin_unlock(&s->sl, irql);
		ngos_ev_wait(&s->wake);
	}
}
void down_read(struct rw_semaphore *s) { rwsem_try(s, 0, 1); }
void down_write(struct rw_semaphore *s) { rwsem_try(s, 1, 1); }
int down_read_trylock(struct rw_semaphore *s) { return rwsem_try(s, 0, 0); }
int down_write_trylock(struct rw_semaphore *s) { return rwsem_try(s, 1, 0); }
void up_read(struct rw_semaphore *s)
{
	unsigned char irql = ngos_spin_lock(&s->sl);
	if (--s->readers == 0)
		ngos_ev_set(&s->wake);
	ngos_spin_unlock(&s->sl, irql);
}
void up_write(struct rw_semaphore *s)
{
	unsigned char irql = ngos_spin_lock(&s->sl);
	s->writer = 0;
	ngos_ev_set(&s->wake);
	ngos_spin_unlock(&s->sl, irql);
}
void downgrade_write(struct rw_semaphore *s)
{
	unsigned char irql = ngos_spin_lock(&s->sl);
	s->writer = 0; s->readers++;
	ngos_ev_set(&s->wake);
	ngos_spin_unlock(&s->sl, irql);
}
int rwsem_is_locked(struct rw_semaphore *s) { rwsem_ready(s); return s->writer || s->readers; }

/* ------------------------------------------------------------- bitmaps */
unsigned long find_next_bit(const unsigned long *a, unsigned long size, unsigned long off)
{
	for (; off < size; off++) if (test_bit(off, a)) return off;
	return size;
}
unsigned long find_next_zero_bit(const unsigned long *a, unsigned long size, unsigned long off)
{
	for (; off < size; off++) if (!test_bit(off, a)) return off;
	return size;
}
unsigned int bitmap_weight(const unsigned long *a, unsigned int bits)
{
	unsigned int w = 0;
	for (unsigned int i = 0; i < bits; i++) w += test_bit(i, a);
	return w;
}

/* --------------------------------------------- rbtree (unbalanced BST) */
#define RBP(n) ((struct rb_node *)((n)->__rb_parent_color))
void rb_insert_color(struct rb_node *n, struct rb_root *r) { (void)n; (void)r; }
struct rb_node *rb_first(const struct rb_root *r)
{
	struct rb_node *n = r->rb_node;
	if (!n) return NULL;
	while (n->rb_left) n = n->rb_left;
	return n;
}
struct rb_node *rb_next(const struct rb_node *n)
{
	struct rb_node *p;
	if (n->rb_right) { n = n->rb_right; while (n->rb_left) n = n->rb_left; return (struct rb_node *)n; }
	while ((p = RBP(n)) && n == p->rb_right) n = p;
	return p;
}
static void rb_replace_child(struct rb_node *old, struct rb_node *new_, struct rb_root *r)
{
	struct rb_node *p = RBP(old);
	if (!p) r->rb_node = new_;
	else if (p->rb_left == old) p->rb_left = new_;
	else p->rb_right = new_;
	if (new_) new_->__rb_parent_color = (uintptr_t)p;
}
void rb_erase(struct rb_node *n, struct rb_root *r)
{
	if (!n->rb_left) rb_replace_child(n, n->rb_right, r);
	else if (!n->rb_right) rb_replace_child(n, n->rb_left, r);
	else {
		struct rb_node *s = n->rb_right;
		while (s->rb_left) s = s->rb_left;
		if (RBP(s) != n) {
			rb_replace_child(s, s->rb_right, r);
			s->rb_right = n->rb_right;
			s->rb_right->__rb_parent_color = (uintptr_t)s;
		}
		rb_replace_child(n, s, r);
		s->rb_left = n->rb_left;
		s->rb_left->__rb_parent_color = (uintptr_t)s;
	}
}

/* ---------------------------------------------------------------- time */
void ktime_get_coarse_real_ts64(struct timespec64 *ts) { long ns; ngos_time(&ts->tv_sec, &ns); ts->tv_nsec = ns; }
void ktime_get_real_ts64(struct timespec64 *ts) { ktime_get_coarse_real_ts64(ts); }
s64 ktime_get_real_seconds(void) { struct timespec64 t; ktime_get_coarse_real_ts64(&t); return t.tv_sec; }
struct timespec64 current_time(struct inode *i) { struct timespec64 t; (void)i; ktime_get_coarse_real_ts64(&t); return t; }
struct timespec64 inode_set_ctime_current(struct inode *i) { i->i_ctime = current_time(i); return i->i_ctime; }
void simple_inode_init_ts(struct inode *i) { i->i_atime = i->i_mtime = i->i_ctime = current_time(i); }

/* ------------------------------------------------------------ workqueue */
struct workqueue_struct kshim_wq;
struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max, ...)
{ (void)fmt; (void)flags; (void)max; return &kshim_wq; }
void destroy_workqueue(struct workqueue_struct *wq) { (void)wq; }
void flush_workqueue(struct workqueue_struct *wq) { (void)wq; }
/* Work items run synchronously in the caller (the read-only paths queue only the free-cluster precount). */
bool queue_work(struct workqueue_struct *wq, struct work_struct *w) { (void)wq; w->func(w); return true; }
bool schedule_work(struct work_struct *w) { w->func(w); return true; }
bool cancel_work_sync(struct work_struct *w) { (void)w; return false; }
void flush_work(struct work_struct *w) { (void)w; }

/* ------------------------------------------------------------------ nls */
static int utf8_dec(const u8 *s, int len, u32 *out)
{
	if (len < 1) return -1;
	if (s[0] < 0x80) { *out = s[0]; return 1; }
	if ((s[0] & 0xe0) == 0xc0 && len >= 2) { *out = ((s[0] & 0x1f) << 6) | (s[1] & 0x3f); return 2; }
	if ((s[0] & 0xf0) == 0xe0 && len >= 3) { *out = ((s[0] & 0x0f) << 12) | ((s[1] & 0x3f) << 6) | (s[2] & 0x3f); return 3; }
	if ((s[0] & 0xf8) == 0xf0 && len >= 4) { *out = ((s[0] & 0x07) << 18) | ((s[1] & 0x3f) << 12) | ((s[2] & 0x3f) << 6) | (s[3] & 0x3f); return 4; }
	return -1;
}
static int utf8_enc(u32 c, u8 *o, int max)
{
	if (c < 0x80 && max >= 1) { o[0] = c; return 1; }
	if (c < 0x800 && max >= 2) { o[0] = 0xc0 | (c >> 6); o[1] = 0x80 | (c & 0x3f); return 2; }
	if (c < 0x10000 && max >= 3) { o[0] = 0xe0 | (c >> 12); o[1] = 0x80 | ((c >> 6) & 0x3f); o[2] = 0x80 | (c & 0x3f); return 3; }
	if (max >= 4) { o[0] = 0xf0 | (c >> 18); o[1] = 0x80 | ((c >> 12) & 0x3f); o[2] = 0x80 | ((c >> 6) & 0x3f); o[3] = 0x80 | (c & 0x3f); return 4; }
	return -1;
}
int utf8s_to_utf16s(const u8 *s, int len, enum utf16_endian e, wchar_t_ *pwcs, int maxlen)
{
	int o = 0; (void)e;
	while (len > 0 && *s) {
		u32 c; int n = utf8_dec(s, len, &c);
		if (n < 0) return -EINVAL;
		s += n; len -= n;
		if (c >= 0x10000) {
			if (o + 2 > maxlen) break;
			c -= 0x10000; pwcs[o++] = 0xd800 | (c >> 10); pwcs[o++] = 0xdc00 | (c & 0x3ff);
		} else {
			if (o + 1 > maxlen) break;
			pwcs[o++] = c;
		}
	}
	return o;
}
int utf16s_to_utf8s(const wchar_t_ *pwcs, int len, enum utf16_endian e, u8 *s, int maxlen)
{
	int o = 0; (void)e;
	while (len > 0 && *pwcs) {
		u32 c = *pwcs++; len--;
		if (c >= 0xd800 && c < 0xdc00 && len > 0 && *pwcs >= 0xdc00 && *pwcs < 0xe000) {
			c = 0x10000 + ((c - 0xd800) << 10) + (*pwcs++ - 0xdc00); len--;
		}
		int n = utf8_enc(c, s + o, maxlen - o);
		if (n < 0) break;
		o += n;
	}
	return o;
}
static int utf8_uni2char(wchar_t_ uni, unsigned char *out, int boundlen) { int n = utf8_enc(uni, out, boundlen); return n < 0 ? -ENAMETOOLONG : n; }
static int utf8_char2uni(const unsigned char *raw, int boundlen, wchar_t_ *uni)
{ u32 c; int n = utf8_dec(raw, boundlen, &c); if (n < 0 || c > 0xffff) return -EINVAL; *uni = c; return n; }
static struct nls_table kshim_utf8 = { "utf8", utf8_uni2char, utf8_char2uni, NULL };
struct nls_table *load_nls(const char *charset) { return strcmp(charset, "utf8") ? NULL : &kshim_utf8; }
struct nls_table *load_nls_default(void) { return &kshim_utf8; }
void unload_nls(struct nls_table *t) { (void)t; }

/* ------------------------------------------------------------ fs types */
struct file_system_type *kshim_fs_type;
int register_filesystem(struct file_system_type *t) { kshim_fs_type = t; return 0; }
int unregister_filesystem(struct file_system_type *t) { (void)t; kshim_fs_type = NULL; return 0; }
struct ctl_table_header kshim_ctl;
struct ctl_table_header *register_sysctl(const char *p, const struct ctl_table *t) { (void)p; (void)t; return &kshim_ctl; }
void unregister_sysctl_table(struct ctl_table_header *h) { (void)h; }

/* ------------------------------------------------------- block device */
unsigned long kshim_counter_reads, kshim_counter_refused_writes, kshim_counter_writes;
unsigned long long kshim_counter_write_bytes;
int blk_status_to_errno(blk_status_t s) { return s ? -EIO : 0; }
#define KSHIM_RMW_CHUNK (64 * 1024)
/* File data of a write-through write goes to the device with FUA (kshim_wt_fua, only set when the device honours it). */
static inline int kshim_dw(struct block_device *b, u64 off, void *buf, unsigned int len)
{
	return b->kshim_wt_fua ? ngos_dev_write_fua(b->osdev, off, buf, len) : ngos_dev_write(b->osdev, off, buf, len);
}
/* Sector-granular read-modify-write for a write that does not start or end on a sector boundary. */
static int kshim_dev_write_rmw(struct block_device *b, u64 off, const u8 *buf, size_t len)
{
	unsigned int bs = b->logical_block_size;
	u8 *sec = kmalloc(bs, GFP_NOFS), *mid = NULL;
	int err = 0;
	if (!sec)
		return -ENOMEM;
	while (len && !err) {
		u64 base = off & ~(u64)(bs - 1);
		size_t in = off - base, n;
		if (in || len < bs) {
			n = min_t(size_t, bs - in, len);
			err = ngos_dev_read(b->osdev, base, sec, bs) ? -EIO : 0;
			if (!err) {
				kshim_jnl_patch(b, 0, base, sec, bs);
				memcpy(sec + in, buf, n);
				err = kshim_dw(b, base, sec, bs) ? -EIO : 0;
			}
		} else {
			/* The storage stack needs a word-aligned buffer (IDE DMA): bounce the middle part. */
			n = min_t(size_t, len & ~(size_t)(bs - 1), KSHIM_RMW_CHUNK);
			if (!mid)
				mid = kmalloc(KSHIM_RMW_CHUNK, GFP_NOFS);
			if (!mid) {
				err = -ENOMEM;
				break;
			}
			memcpy(mid, buf, n);
			err = kshim_dw(b, off, mid, (unsigned int)n) ? -EIO : 0;
		}
		off += n; buf += n; len -= n;
	}
	kfree(sec);
	kfree(mid);
	return err;
}
/* The storage stack reads whole sectors into a word-aligned buffer: bounce a read that is not one. */
static int kshim_dev_read_bounce(struct block_device *b, u64 off, u8 *buf, size_t len)
{
	unsigned int bs = b->logical_block_size;
	size_t cap = min_t(size_t, KSHIM_RMW_CHUNK, ((off & (bs - 1)) + len + bs - 1) & ~(size_t)(bs - 1));
	u8 *sec;
	int err = 0;
	if (!len)
		return 0;
	sec = kmalloc(cap, GFP_NOFS);
	if (!sec)
		return -ENOMEM;
	while (len && !err) {
		u64 base = off & ~(u64)(bs - 1);
		size_t in = off - base, span = min_t(size_t, (in + len + bs - 1) & ~(size_t)(bs - 1), cap);
		size_t n = min_t(size_t, span - in, len);
		err = ngos_dev_read(b->osdev, base, sec, (unsigned int)span) ? -EIO : 0;
		if (!err)
			memcpy(buf, sec + in, n);
		off += n; buf += n; len -= n;
	}
	kfree(sec);
	return err;
}
static int kshim_dev_rw_do(struct block_device *b, int write, u64 off, void *buf, size_t len);
int kshim_dev_rw(struct block_device *b, int write, u64 off, void *buf, size_t len)
{
	int err = kshim_dev_rw_do(b, write, off, buf, len);
	if (err && write)
		b->kshim_wr_failed++;
	return err;
}
static int kshim_dev_rw_do(struct block_device *b, int write, u64 off, void *buf, size_t len)
{
	if (b->kshim_gone)
		return -EIO;
	if (write && b->kshim_frozen) {
		kshim_counter_refused_writes++;
		return -EROFS;
	}
	if (write) {
		struct super_block *sb = b->bd_super;
		if (!sb || (sb_rdonly(sb) && !b->kshim_remounting)) {
			kshim_counter_refused_writes++;
			printk(KERN_ERR "refusing device write at %llu len %zu (read-only mount)\n",
					(unsigned long long)off, len);
			return -EROFS;
		}
		if (off + len > b->size)
			return -EIO;
		kshim_counter_writes++;
		kshim_counter_write_bytes += len;
		if (b->jnl && kshim_jnl_failed(b))
			return -EIO;
		if (b->jnl && !b->kshim_direct) {
			int r = kshim_jnl_capture(b, off, buf, len);
			if (r != -ENOMEM)
				return r;
			r = kshim_jnl_degrade(b);
			if (r)
				return r == -ENOMEM ? -ENOMEM : -EIO;	/* -ENOMEM: a resize refused to go in place */
		}
		if (b->jnl)
			kshim_jnl_patch(b, 1, off, buf, len);
		if (((off | len) & (b->logical_block_size - 1)) || ((uintptr_t)buf & 3))
			return kshim_dev_write_rmw(b, off, buf, len);
		if (b->kshim_defer_now) {
			/* Sent now, waited for before any flush or journal header (and before the volume lock is let go): see ngc_set_defer. */
			int r = ngos_dev_write_start(b->osdev, off, buf, (unsigned int)len, b->kshim_wt_fua, 1);
			if (r <= 0)
				return r ? -EIO : 0;
		}
		return kshim_dw(b, off, buf, (unsigned int)len) ? -EIO : 0;
	}
	kshim_counter_reads++;
	if (off >= b->size) {
		memset(buf, 0, len);
		return 0;
	}
	if (off + len > b->size) {
		size_t in = (size_t)(b->size - off);
		memset((char *)buf + in, 0, len - in);
		len = in;
	}
	if (((off | len) & (b->logical_block_size - 1)) || ((uintptr_t)buf & 3)) {
		int err = kshim_dev_read_bounce(b, off, buf, len);
		if (err)
			return err;
	} else if (ngos_dev_read(b->osdev, off, buf, (unsigned int)len)) {
		return -EIO;
	}
	kshim_jnl_patch(b, 0, off, buf, len);
	return 0;
}
int bdev_rw_virt(struct block_device *b, sector_t s, void *data, size_t len, blk_opf_t op)
{
	return kshim_dev_rw(b, (op & REQ_OP_MASK) == REQ_OP_WRITE, s << SECTOR_SHIFT, data, len);
}
/*
 * Linux's bio_alloc with a waiting gfp mask does not fail, and the core's MFT writers use its result
 * unchecked: when the pool is empty a write bio comes from a reserve instead, waiting for a slot if need
 * be.  A writer can hold one bio while it takes a second for the MFT mirror, which it submits and puts
 * at once; so a thread that already holds a first-tier slot takes from a second tier of the same size,
 * whose holders never wait, and every first-tier holder can finish.  Reads check for NULL themselves.
 * The core abandons a bio on one MFT writeback error exit: a reserve bio taken inside a writeback scope
 * (kshim_wb_scope_enter/exit, per thread, nested) that is still out when that scope reaches its next
 * folio or returns belonged to a frame that is gone, so it is put back then.
 */
#define KSHIM_BIO_RESERVE 8
#define KSHIM_BIO_RESERVE_VECS 64
static struct kshim_bio_slot {
	struct bio bio; struct bio_vec vec[KSHIM_BIO_RESERVE_VECS]; int used; void *owner; int depth;
} kshim_bio_reserve[2][KSHIM_BIO_RESERVE];
#define KSHIM_WB_SCOPES 256
static struct { void *thread; int depth; } kshim_wb_scope[KSHIM_WB_SCOPES];
static uintptr_t kshim_wb_scope_lock;
static int kshim_wb_find_locked(void *t)
{
	for (int i = 0; i < KSHIM_WB_SCOPES; i++)
		if (kshim_wb_scope[i].thread == t)
			return i;
	return -1;
}
static int kshim_wb_depth_locked(void *t)
{
	int i = kshim_wb_find_locked(t);
	return i < 0 ? 0 : kshim_wb_scope[i].depth;
}
/* Puts back the thread's reserve bios taken at scope depth @depth or deeper (> 0): their frames have returned. */
static void kshim_wb_reclaim_locked(void *t, int depth)
{
	for (int r = 0; r < 2; r++)
		for (int k = 0; k < KSHIM_BIO_RESERVE; k++) {
			struct kshim_bio_slot *sl = &kshim_bio_reserve[r][k];
			if (__atomic_load_n(&sl->used, __ATOMIC_SEQ_CST) && sl->owner == t && sl->depth >= depth) {
				__atomic_store_n(&sl->owner, NULL, __ATOMIC_SEQ_CST);
				__atomic_store_n(&sl->used, 0, __ATOMIC_SEQ_CST);
			}
		}
}
void kshim_wb_scope_enter(void)
{
	void *t = ngos_current_thread();
	for (;;) {
		unsigned char irql = ngos_spin_lock(&kshim_wb_scope_lock);
		int i = kshim_wb_find_locked(t);
		if (i < 0)
			i = kshim_wb_find_locked(NULL);
		if (i >= 0) {
			kshim_wb_scope[i].thread = t;
			kshim_wb_scope[i].depth++;
			ngos_spin_unlock(&kshim_wb_scope_lock, irql);
			return;
		}
		ngos_spin_unlock(&kshim_wb_scope_lock, irql);
		ngos_yield();	/* every entry in use: wait for a scope to end, so that every scope is tracked */
	}
}
void kshim_wb_scope_exit(void)
{
	void *t = ngos_current_thread();
	unsigned char irql = ngos_spin_lock(&kshim_wb_scope_lock);
	int i = kshim_wb_find_locked(t);
	if (i >= 0) {
		kshim_wb_reclaim_locked(t, kshim_wb_scope[i].depth);
		if (!--kshim_wb_scope[i].depth)
			kshim_wb_scope[i].thread = NULL;
	}
	ngos_spin_unlock(&kshim_wb_scope_lock, irql);
}
/* Between two folios of one writepages walk: the frames that wrote the last folio have returned. */
void kshim_wb_scope_point(void)
{
	void *t = ngos_current_thread();
	unsigned char irql = ngos_spin_lock(&kshim_wb_scope_lock);
	int i = kshim_wb_find_locked(t);
	if (i >= 0)
		kshim_wb_reclaim_locked(t, kshim_wb_scope[i].depth);
	ngos_spin_unlock(&kshim_wb_scope_lock, irql);
}
static struct bio *bio_alloc_pool(unsigned short n, gfp_t g)
{
	struct bio *bio = kzalloc(sizeof(*bio), g);
	if (bio) {
		bio->bi_io_vec = kcalloc(n, sizeof(struct bio_vec), g);
		if (!bio->bi_io_vec) {
			kfree(bio);
			bio = NULL;
		}
	}
	return bio;
}
static struct bio *bio_alloc_reserve(void)
{
	void *t = ngos_current_thread();
	int tier = 0;
	for (int i = 0; i < KSHIM_BIO_RESERVE; i++)
		if (__atomic_load_n(&kshim_bio_reserve[0][i].owner, __ATOMIC_SEQ_CST) == t)
			tier = 1;
	for (int i = 0; i < KSHIM_BIO_RESERVE; i++) {
		struct kshim_bio_slot *sl = &kshim_bio_reserve[tier][i];
		if (!__atomic_exchange_n(&sl->used, 1, __ATOMIC_SEQ_CST)) {
			memset(&sl->bio, 0, sizeof(sl->bio));
			memset(sl->vec, 0, sizeof(sl->vec));
			sl->bio.bi_io_vec = sl->vec;
			{
				unsigned char irql = ngos_spin_lock(&kshim_wb_scope_lock);
				sl->depth = kshim_wb_depth_locked(t);
				ngos_spin_unlock(&kshim_wb_scope_lock, irql);
			}
			__atomic_store_n(&sl->owner, t, __ATOMIC_SEQ_CST);
			return &sl->bio;
		}
	}
	return NULL;
}
struct bio *bio_alloc(struct block_device *b, unsigned short nr, blk_opf_t op, gfp_t g)
{
	unsigned short n = nr ? nr : 1;
	struct bio *bio = bio_alloc_pool(n, g);
	while (!bio && n <= KSHIM_BIO_RESERVE_VECS && (op & REQ_OP_MASK) == REQ_OP_WRITE) {
		bio = bio_alloc_reserve();
		if (!bio) {
			ngos_yield();
			bio = bio_alloc_pool(n, g);
		}
	}
	if (!bio)
		return NULL;
	bio->bi_bdev = b; bio->bi_opf = op;
	bio->bi_max_vecs = n;
	return bio;
}
void bio_put(struct bio *b)
{
	for (int t = 0; t < 2; t++)
		for (int i = 0; i < KSHIM_BIO_RESERVE; i++)
			if (b == &kshim_bio_reserve[t][i].bio) {
				__atomic_store_n(&kshim_bio_reserve[t][i].owner, NULL, __ATOMIC_SEQ_CST);
				__atomic_store_n(&kshim_bio_reserve[t][i].used, 0, __ATOMIC_SEQ_CST);
				return;
			}
	kfree(b->bi_io_vec);
	kfree(b);
}
int bio_add_page(struct bio *b, struct page *p, unsigned int len, unsigned int off)
{
	/* Like the block layer, merge a range contiguous with the last segment of the same page. */
	if (b->bi_vcnt) {
		struct bio_vec *v = &b->bi_io_vec[b->bi_vcnt - 1];
		if (v->bv_page == p && v->bv_offset + v->bv_len == off) {
			v->bv_len += len; b->bi_iter.bi_size += len; return len;
		}
	}
	if (b->bi_vcnt >= b->bi_max_vecs) return 0;
	b->bi_io_vec[b->bi_vcnt++] = (struct bio_vec){ p, len, off };
	b->bi_iter.bi_size += len;
	return len;
}
bool bio_add_folio(struct bio *b, struct folio *f, size_t len, size_t off) { return bio_add_page(b, &f->page, len, off) > 0; }
void bio_add_folio_nofail(struct bio *b, struct folio *f, size_t len, size_t off) { BUG_ON(!bio_add_folio(b, f, len, off)); }
void bio_chain(struct bio *b, struct bio *parent) { b->kshim_chain = parent; }
static int kshim_bio_do(struct bio *b)
{
	u64 off = b->bi_iter.bi_sector << SECTOR_SHIFT;
	int write = (b->bi_opf & REQ_OP_MASK) == REQ_OP_WRITE, err = 0;
	for (unsigned i = 0; i < b->bi_vcnt; i++) {
		struct bio_vec *v = &b->bi_io_vec[i];
		int e = kshim_dev_rw(b->bi_bdev, write, off, (char *)v->bv_page->data + v->bv_offset, v->bv_len);
		if (e) err = e;
		off += v->bv_len;
	}
	b->bi_status = err ? BLK_STS_IOERR : BLK_STS_OK;
	return err;
}
void submit_bio(struct bio *b)
{
	/* The core's MFT write completion ignores bi_status: keep the error for the next consistency point
	 * (out of memory stays that, so a resize that refused to go in place does not count as a device error). */
	int err = kshim_bio_do(b);
	if (err && (b->bi_opf & REQ_OP_MASK) == REQ_OP_WRITE && !b->bi_bdev->kshim_wb_err)
		b->bi_bdev->kshim_wb_err = err == -ENOMEM ? -ENOMEM : -EIO;
	if (b->bi_end_io) b->bi_end_io(b);
}
int submit_bio_wait(struct bio *b) { return kshim_bio_do(b); }

/* ----------------------------------------------------------- page cache */
/*
 * Private metadata/data page cache: a per-mapping hash of 4 KiB folios in
 * nonpaged pool.  One shim-wide spin lock guards the hash chains; folio
 * contents are guarded by PG_locked as in Linux.  A mapping keeps at most
 * KSHIM_PC_MAX pages: beyond that, unreferenced clean folios are dropped (all of them, so a
 * working set above the limit is read again from the device by every pass over it).
 * The limit is half the volume-wide soft limit of folio pages (1024 at least, 8192 at most:
 * 32 MB): a directory of 10,000 files with long names has an index of about 1,400 pages,
 * which a flat 1024 made every listing read from the device.  The unused inodes are
 * evicted by the soft limit itself, so this does not raise the memory a volume may use.
 */
unsigned long kshim_pc_soft_limit(void);
static unsigned long kshim_pc_default_max(void)
{
	static unsigned long lim;
	if (!lim) {
		unsigned long l = kshim_pc_soft_limit() / 2;
		lim = l > 8192 ? 8192 : l < 1024 ? 1024 : l;
	}
	return lim;
}
#define KSHIM_PC_MAX kshim_pc_default_max()
unsigned long kshim_pc_pages;
static struct folio *pc_find_locked(struct address_space *m, pgoff_t idx)
{
	for (struct folio *f = m->pc[idx % KSHIM_PC_BUCKETS]; f; f = f->hnext)
		if (f->index == idx) return f;
	return NULL;
}
/*
 * Folio data: one page straight from the pool, which hands out whole pages page aligned.  Through
 * kmalloc's header a folio took 4,128 bytes (two pages) and its data was only 32-byte aligned,
 * too little for storage stacks that need sector-aligned buffers for unbounced transfers.
 */
static void *pc_data_alloc(void)
{
	void *p = ngos_alloc(PAGE_SIZE);
	if (p)
		memset(p, 0, PAGE_SIZE);
	return p;
}
static void pc_data_free(void *p)
{
	if (p)
		ngos_free(p);
}
static void pc_free(struct folio *f)
{
	pc_data_free(f->data);
	kfree(f);
	__atomic_sub_fetch(&kshim_pc_pages, 1, __ATOMIC_SEQ_CST);
}
/* Unlinks unreferenced clean unlocked folios of @m; returns them chained through hnext. */
static struct folio *pc_shrink_locked(struct address_space *m, pgoff_t keep)
{
	struct folio *out = NULL;
	for (int b = 0; b < KSHIM_PC_BUCKETS; b++) {
		struct folio **pp = &m->pc[b];
		while (*pp) {
			struct folio *f = *pp;
			if (f->index != keep && f->refcount == 1 && !(f->flags & ((1UL << PG_locked) | (1UL << PG_dirty) | (1UL << PG_writeback)))) {
				*pp = f->hnext;
				m->nrpages--;
				f->hnext = out;
				out = f;
			} else {
				pp = &f->hnext;
			}
		}
	}
	return out;
}
void kshim_folio_lock(struct folio *f)
{
	while (test_and_set_bit(PG_locked, &f->flags))
		ngos_yield();
}
void folio_get(struct folio *f) { __atomic_add_fetch(&f->refcount, 1, __ATOMIC_SEQ_CST); }
void folio_put(struct folio *f)
{
	int r = __atomic_sub_fetch(&f->refcount, 1, __ATOMIC_SEQ_CST);
	BUG_ON(r < 0);
	/* A folio outside any mapping (alloc_page) is freed with its last reference. */
	if (r == 0 && !f->mapping)
		pc_free(f);
}
struct page *alloc_page(gfp_t g)
{
	struct folio *f = kzalloc(sizeof(struct folio), g);
	if (!f)
		return NULL;
	f->data = pc_data_alloc();
	if (!f->data) { kfree(f); return NULL; }
	f->refcount = 1;
	__atomic_add_fetch(&kshim_pc_pages, 1, __ATOMIC_SEQ_CST);
	return &f->page;
}
void __free_page(struct page *p)
{
	struct folio *f = page_folio(p);
	if (f && !f->mapping)
		pc_free(f);
}
struct folio *__filemap_get_folio(struct address_space *m, pgoff_t idx, fgf_t fgp, gfp_t g)
{
	struct folio *f, *nf = NULL, *drop = NULL;
	unsigned char irql;
	bool eager = false;
	(void)g;
	irql = ngos_spin_lock(&kshim_pc_lock);
	f = pc_find_locked(m, idx);
	if (f)
		__atomic_add_fetch(&f->refcount, 1, __ATOMIC_SEQ_CST);
	ngos_spin_unlock(&kshim_pc_lock, irql);
	if (!f) {
		if (!(fgp & FGP_CREAT))
			return ERR_PTR(-ENOENT);
		nf = kzalloc(sizeof(*nf), GFP_NOFS);
		if (!nf)
			return ERR_PTR(-ENOMEM);
		nf->data = pc_data_alloc();
		if (!nf->data) { kfree(nf); return ERR_PTR(-ENOMEM); }
		nf->mapping = m; nf->index = idx; nf->refcount = 2;  /* the cache's own reference + ours */
		irql = ngos_spin_lock(&kshim_pc_lock);
		f = pc_find_locked(m, idx);
		if (f) {
			__atomic_add_fetch(&f->refcount, 1, __ATOMIC_SEQ_CST);
		} else {
			if (m->nrpages >= (m->kshim_pc_max ? m->kshim_pc_max : KSHIM_PC_MAX)) {
				drop = pc_shrink_locked(m, idx);
				if (!drop && m->kshim_eager_wb)
					eager = true;
			}
			nf->hnext = m->pc[idx % KSHIM_PC_BUCKETS];
			m->pc[idx % KSHIM_PC_BUCKETS] = nf;
			m->nrpages++;
			f = nf;
			nf = NULL;
			__atomic_add_fetch(&kshim_pc_pages, 1, __ATOMIC_SEQ_CST);
		}
		ngos_spin_unlock(&kshim_pc_lock, irql);
		if (nf) { pc_data_free(nf->data); kfree(nf); }
		while (drop) { struct folio *n = drop->hnext; pc_free(drop); drop = n; }
		/* A full block-device mapping of dirty folios (the $LogFile emptying) is written back here. */
		if (eager)
			kshim_mapping_writeback(m);
	}
	if (fgp & FGP_LOCK) folio_lock(f);
	return f;
}
struct folio *filemap_lock_folio(struct address_space *m, pgoff_t idx) { return __filemap_get_folio(m, idx, FGP_LOCK, 0); }
struct folio *filemap_grab_folio(struct address_space *m, pgoff_t idx) { return __filemap_get_folio(m, idx, FGP_LOCK | FGP_CREAT, 0); }
struct folio *filemap_get_folio(struct address_space *m, pgoff_t idx) { return __filemap_get_folio(m, idx, 0, 0); }
struct page *grab_cache_page_nowait(struct address_space *m, pgoff_t idx)
{
	struct folio *f = __filemap_get_folio(m, idx, FGP_LOCK | FGP_CREAT | FGP_NOWAIT, 0);
	return IS_ERR(f) ? NULL : &f->page;
}
struct folio *read_mapping_folio(struct address_space *m, pgoff_t idx, struct file *file)
{
	struct folio *f = __filemap_get_folio(m, idx, FGP_CREAT, 0);
	int err;
	if (IS_ERR(f)) return f;
	if (folio_test_uptodate(f)) return f;
	folio_lock(f);
	if (folio_test_uptodate(f)) { folio_unlock(f); return f; }
	err = m->a_ops->read_folio(file, f);
	if (folio_test_locked(f)) {
		printk(KERN_ERR "read_folio left folio %lu locked\n", (unsigned long)idx);
		folio_unlock(f);
	}
	if (err || !folio_test_uptodate(f)) {
		folio_put(f);
		return ERR_PTR(err ? err : -EIO);
	}
	return f;
}
struct page *read_mapping_page(struct address_space *m, pgoff_t idx, struct file *file)
{
	struct folio *f = read_mapping_folio(m, idx, file);
	return IS_ERR(f) ? (struct page *)f : &f->page;
}
unsigned long kshim_counter_dirty;
/*
 * Bumped after anything becomes dirty that kshim_sync writes back: a folio, an inode, an inode the
 * sync could not see (I_NEW) becoming visible.  A sync that finds nothing dirty records the value it
 * read before its scan; while the value is unchanged, the next sync would find nothing either and
 * skips the scan of every cached inode and folio.  (In a checked build the skip also runs the scan and
 * checks it finds nothing: kshim_check_skip.)
 *
 * The dirtying is set first, the bump follows (sequentially consistent), so a scan that read the value
 * before it started sees every dirtying that was announced before that read, and one that came later
 * changes the value.  EVERY way to make something dirty that kshim_sync would write must go through one of
 * the funnels below (a new one needs a bump, or FlushFileBuffers skips the data):
 *   - folio_mark_dirty (all folio dirtying: filemap_dirty_folio, folio_redirty_for_writepage,
 *     iomap_dirty_folio; it also sets I_DIRTY_PAGES on the host inode)
 *   - __mark_inode_dirty (every mark_inode_dirty* wrapper) and inode_state_set/clear with an I_DIRTY bit
 *   - unlock_new_inode (the scan skips I_NEW inodes: one dirtied while new becomes visible here)
 *   - the two places that put I_DIRTY_PAGES back after a failed or incomplete writeback: kshim_writeback_last
 *     (eviction) and write_inode_now (kshim_wb.c)
 * The counter is 64 bit: a false "clean" needs the counter to return to the recorded value.
 */
unsigned long long kshim_dirty_gen __attribute__((aligned(8)));
void kshim_dirty_bump(void)
{
	__atomic_add_fetch(&kshim_dirty_gen, 1, __ATOMIC_SEQ_CST);
}
bool folio_mark_dirty(struct folio *f)
{
	bool was_clean;
	kshim_counter_dirty++;
	if (f->mapping)
		f->mapping->kshim_dirty_hint = 1;
	if (f->mapping && f->mapping->host)
		f->mapping->host->i_state |= I_DIRTY_PAGES;
	was_clean = !test_and_set_bit(PG_dirty, &f->flags);
	kshim_dirty_bump();
	return was_clean;
}
bool filemap_dirty_folio(struct address_space *m, struct folio *f) { (void)m; return folio_mark_dirty(f); }
void __mark_inode_dirty(struct inode *i, int flags)
{
	i->i_state |= flags;
	kshim_dirty_bump();
}
void file_ra_state_init(struct file_ra_state *ra, struct address_space *m) { (void)m; ra->ra_pages = 32; }
void page_cache_sync_readahead(struct address_space *m, void *ra, struct file *f, pgoff_t i, unsigned long n)
{ (void)m; (void)ra; (void)f; (void)i; (void)n; }
/*
 * A folio leaving its mapping (lock held): unreferenced ones go on @list to be freed; one that
 * another holder still references is only detached, and its holder's last folio_put frees it.
 */
static void pc_detach_or_list(struct folio *f, struct folio **list)
{
	if (f->refcount > 1) {
		f->mapping = NULL;
		f->hnext = NULL;
		/* The other holder may have dropped its reference since the test: then it is freed here. */
		if (__atomic_sub_fetch(&f->refcount, 1, __ATOMIC_SEQ_CST))
			return;
	}
	f->hnext = *list;
	*list = f;
}
static void pc_drop_all(struct address_space *m)
{
	struct folio *list = NULL;
	unsigned char irql = ngos_spin_lock(&kshim_pc_lock);
	for (int b = 0; b < KSHIM_PC_BUCKETS; b++) {
		struct folio *f = m->pc[b];
		while (f) {
			struct folio *n = f->hnext;
			pc_detach_or_list(f, &list);
			f = n;
		}
		m->pc[b] = NULL;
	}
	m->nrpages = 0;
	ngos_spin_unlock(&kshim_pc_lock, irql);
	while (list) { struct folio *n = list->hnext; pc_free(list); list = n; }
}
/* Drops the clean unreferenced folios of a mapping (used after data reads to bound memory). */
void kshim_mapping_shrink(struct address_space *m)
{
	struct folio *drop;
	unsigned char irql = ngos_spin_lock(&kshim_pc_lock);
	drop = pc_shrink_locked(m, (pgoff_t)-1);
	ngos_spin_unlock(&kshim_pc_lock, irql);
	while (drop) { struct folio *n = drop->hnext; pc_free(drop); drop = n; }
}
/* Drops the folios at or past @l (dirty or not) and zeroes the tail of a partial folio, as Linux. */
void truncate_inode_pages(struct address_space *m, loff_t l)
{
	pgoff_t first = (pgoff_t)((l + PAGE_SIZE - 1) >> PAGE_SHIFT);
	struct folio *list = NULL, *part;
	unsigned char irql;
	if (l <= 0) {
		pc_drop_all(m);
		return;
	}
	irql = ngos_spin_lock(&kshim_pc_lock);
	for (int b = 0; b < KSHIM_PC_BUCKETS; b++) {
		struct folio **pp = &m->pc[b];
		while (*pp) {
			struct folio *f = *pp;
			if (f->index >= first) {
				*pp = f->hnext;
				m->nrpages--;
				pc_detach_or_list(f, &list);
			} else {
				pp = &f->hnext;
			}
		}
	}
	part = (l & (PAGE_SIZE - 1)) ? pc_find_locked(m, (pgoff_t)(l >> PAGE_SHIFT)) : NULL;
	if (part)
		__atomic_add_fetch(&part->refcount, 1, __ATOMIC_SEQ_CST);
	ngos_spin_unlock(&kshim_pc_lock, irql);
	while (list) { struct folio *n = list->hnext; pc_free(list); list = n; }
	if (part) {
		folio_lock(part);
		memset((char *)part->data + (l & (PAGE_SIZE - 1)), 0, PAGE_SIZE - (l & (PAGE_SIZE - 1)));
		folio_unlock(part);
		folio_put(part);
	}
}
void truncate_inode_pages_final(struct address_space *m) { pc_drop_all(m); }
void truncate_pagecache(struct inode *i, loff_t n) { truncate_inode_pages(i->i_mapping, n); }
void truncate_setsize(struct inode *i, loff_t n) { loff_t old = i->i_size; i_size_write(i, n); if (n < old) truncate_pagecache(i, n); }
void pagecache_isize_extended(struct inode *i, loff_t from, loff_t to) { (void)i; (void)from; (void)to; }
unsigned long invalidate_mapping_pages(struct address_space *m, pgoff_t s, pgoff_t e) { (void)s; (void)e; kshim_mapping_shrink(m); return 0; }
int inode_newsize_ok(const struct inode *i, loff_t n) { (void)i; return n < 0 ? -EINVAL : 0; }
/* Copies @len bytes at @pos of @m's data into any cached, uptodate folios (NT wrote them to disk). */
void kshim_mapping_update(struct address_space *m, loff_t pos, const void *buf, size_t len)
{
	const u8 *src = buf;
	while (len) {
		pgoff_t idx = (pgoff_t)(pos >> PAGE_SHIFT);
		size_t in = pos & (PAGE_SIZE - 1), n = min_t(size_t, PAGE_SIZE - in, len);
		struct folio *f;
		unsigned char irql = ngos_spin_lock(&kshim_pc_lock);
		f = pc_find_locked(m, idx);
		if (f)
			__atomic_add_fetch(&f->refcount, 1, __ATOMIC_SEQ_CST);
		ngos_spin_unlock(&kshim_pc_lock, irql);
		if (f) {
			folio_lock(f);
			if (folio_test_uptodate(f))
				memcpy((u8 *)f->data + in, src, n);
			folio_unlock(f);
			folio_put(f);
		}
		pos += n; src += n; len -= n;
	}
}

/* The iomap services (extent walk, folio read, writeback) are in kshim_iomap.c. */

/* ------------------------------------------------------------------ inode */
/*
 * Inode cache: a per-superblock list of live inodes and a hash of the hashed
 * ones, under one shim mutex.  As in Linux, an inode whose last reference goes
 * stays cached (unused, on an LRU list) unless the file system drops it, so
 * directory indexes and MFT state are not read again for every operation;
 * the oldest unused inodes are evicted beyond KSHIM_ICACHE_UNUSED or when the
 * shim's page count passes KSHIM_PC_PAGES_SOFT.  Eviction runs only from
 * kshim_icache_trim, which the caller invokes with no file system lock held:
 * evicting one inode in the middle of an operation on another would re-enter
 * the file system (what GFP_NOFS prevents in Linux).
 */
/* Unused inodes kept: 4096, more on a larger machine (a 10,000-file directory listing and the files read after it must fit). */
#define KSHIM_ICACHE_UNUSED kshim_icache_unused_limit()
static unsigned long kshim_icache_unused_limit(void)
{
	static unsigned long lim;
	if (!lim) {
		unsigned long l = ngos_physical_pages() / 64;
		lim = l > 32768 ? 32768 : l < 4096 ? 4096 : l;
	}
	return lim;
}
/*
 * Bytes the unused inodes may hold (what kshim_icache_cost adds up): the count limit times 3 KB, so 12 MB at the smallest
 * (1 GB of RAM or less) up to 96 MB (8 GB or more), per volume.  The count limit alone bounds the bytes only as far as every
 * inode costs the same: a plain file costs about 2.6 KB (inode 1368, copy of its MFT record 1024, a small runlist), and the
 * rest of an inode grows with how fragmented the file is (runlist, attribute list, extent records), so the same count can
 * hold more memory as the files held are more fragmented (the 3 h soak: the average pool allocation of the file system went
 * from 1456 to 1712 bytes with the count flat).  3 KB is 1.15 times a plain file: the byte limit does not bind on ordinary
 * files and holds the heavy ones.
 */
#define KSHIM_ICACHE_AVG_BYTES 3072UL
#define KSHIM_ICACHE_BYTES (KSHIM_ICACHE_UNUSED * KSHIM_ICACHE_AVG_BYTES)
unsigned int (*kshim_icache_cost)(struct inode *i);
/* Folio pages (nonpaged pool) before unused inodes are evicted: 96 MB, or 1/16 of memory if less. */
#define KSHIM_PC_PAGES_SOFT kshim_pc_soft_limit()
unsigned long kshim_pc_soft_limit(void)
{
	static unsigned long lim;
	if (!lim) {
		unsigned long l = ngos_physical_pages() / 16;
		lim = l > 24576 ? 24576 : l < 1024 ? 1024 : l;
	}
	return lim;
}
unsigned long kshim_inodes_live, kshim_icache_hits, kshim_icache_evicted;
extern bool (*kshim_is_data_inode)(struct inode *i);
bool (*kshim_icache_ok)(struct inode *i);
/*
 * Both run under the inode-cache lock.  kshim_icache_evicting: an unused inode was taken to be evicted (nothing else can
 * change it any more): the file system may remember what it needs of it (the glue's compact stat cache).
 * kshim_icache_added: a new inode for a record number was hashed: whatever was remembered of that number is void.
 */
void (*kshim_icache_evicting)(struct inode *i);
void (*kshim_icache_added)(struct inode *i);
static struct inode *kshim_lru_take(struct super_block *sb, bool more);
static void kshim_lru_evict(struct inode *v);
static void kshim_icache_trim_pressure(struct super_block *sb);
unsigned long kshim_icache_pressure_evicted, kshim_icache_byte_evicted;
static void ihash_add_locked(struct inode *i)
{
	struct super_block *sb = i->i_sb;
	unsigned b = (unsigned)((uintptr_t)i->kshim_test_data % KSHIM_IHASH);
	if (i->kshim_hashed)
		return;
	i->kshim_hnext = sb->kshim_ihash[b];
	sb->kshim_ihash[b] = i;
	i->kshim_hashed = 1;
	if (kshim_icache_added)
		kshim_icache_added(i);
}
static void ihash_del_locked(struct inode *i)
{
	struct inode **pp;
	if (!i->kshim_hashed)
		return;
	pp = &i->i_sb->kshim_ihash[(unsigned)((uintptr_t)i->kshim_test_data % KSHIM_IHASH)];
	while (*pp && *pp != i)
		pp = &(*pp)->kshim_hnext;
	if (*pp)
		*pp = i->kshim_hnext;
	i->kshim_hnext = NULL;
	i->kshim_hashed = 0;
}
static void lru_del_locked(struct inode *i)
{
	struct super_block *sb = i->i_sb;
	if (!i->kshim_in_lru)
		return;
	if (i->kshim_lru_prev) i->kshim_lru_prev->kshim_lru_next = i->kshim_lru_next;
	else sb->kshim_lru_head = i->kshim_lru_next;
	if (i->kshim_lru_next) i->kshim_lru_next->kshim_lru_prev = i->kshim_lru_prev;
	else sb->kshim_lru_tail = i->kshim_lru_prev;
	i->kshim_lru_prev = i->kshim_lru_next = NULL;
	i->kshim_in_lru = 0;
	sb->kshim_lru_count--;
	sb->kshim_lru_bytes -= i->kshim_lru_bytes;
	kshim_lru_total--;
	kshim_lru_bytes_total -= i->kshim_lru_bytes;
	i->kshim_lru_bytes = 0;
}
static void lru_add_locked(struct inode *i)
{
	struct super_block *sb = i->i_sb;
	if (i->kshim_in_lru)
		return;
	i->kshim_lru_next = NULL;
	i->kshim_lru_prev = sb->kshim_lru_tail;
	if (sb->kshim_lru_tail) sb->kshim_lru_tail->kshim_lru_next = i;
	else sb->kshim_lru_head = i;
	sb->kshim_lru_tail = i;
	i->kshim_in_lru = 1;
	sb->kshim_lru_count++;
	/* Nobody uses an unused inode, so what it holds cannot change while it is on the list. */
	i->kshim_lru_bytes = kshim_icache_cost ? kshim_icache_cost(i) : 0;
	sb->kshim_lru_bytes += i->kshim_lru_bytes;
	kshim_lru_total++;
	kshim_lru_bytes_total += i->kshim_lru_bytes;
}
void inode_init_once(struct inode *i) { memset(i, 0, sizeof(*i)); }
static void kshim_inode_init(struct super_block *sb, struct inode *i)
{
	i->i_sb = sb;
	i->i_blkbits = sb->s_blocksize_bits;
	i->i_count.counter = 1;
	i->i_nlink = 1;
	i->i_mapping = &i->i_data;
	i->i_data.host = i;
	i->i_data.gfp_mask = GFP_NOFS;
	init_rwsem(&i->i_rwsem);
	init_rwsem(&i->i_data.invalidate_lock);
	INIT_LIST_HEAD(&i->i_data.private_list);
	i->kshim_prev = NULL;
	i->kshim_next = sb->kshim_inodes;
	if (sb->kshim_inodes)
		sb->kshim_inodes->kshim_prev = i;
	sb->kshim_inodes = i;
	kshim_inodes_live++;
}
static void kshim_inode_unlist(struct inode *i)
{
	struct super_block *sb = i->i_sb;
	/* Not listed (never, or already unlisted): nothing to do.  A walk from the head made each eviction cost
	 * O(live inodes), as the oldest inodes, evicted first, sit at the tail. */
	if (!i->kshim_prev && sb->kshim_inodes != i)
		return;
	if (i->kshim_prev)
		i->kshim_prev->kshim_next = i->kshim_next;
	else
		sb->kshim_inodes = i->kshim_next;
	if (i->kshim_next)
		i->kshim_next->kshim_prev = i->kshim_prev;
	i->kshim_next = i->kshim_prev = NULL;
	kshim_inodes_live--;
}
struct inode *new_inode(struct super_block *sb)
{
	struct inode *i = sb->s_op->alloc_inode(sb);
	if (!i) return NULL;
	mutex_lock(&kshim_inode_lock);
	kshim_inode_init(sb, i);
	mutex_unlock(&kshim_inode_lock);
	return i;
}
void insert_inode_hash(struct inode *i)
{
	mutex_lock(&kshim_inode_lock);
	ihash_del_locked(i);
	i->i_hash.pprev = (void *)1;
	i->kshim_test_data = (void *)(uintptr_t)i->i_ino;
	ihash_add_locked(i);
	mutex_unlock(&kshim_inode_lock);
}
void remove_inode_hash(struct inode *i)
{
	mutex_lock(&kshim_inode_lock);
	i->i_hash.pprev = NULL;
	ihash_del_locked(i);
	mutex_unlock(&kshim_inode_lock);
}
static struct inode *kshim_find(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	for (struct inode *i = sb->kshim_ihash[hashval % KSHIM_IHASH]; i; i = i->kshim_hnext)
		if (i->i_hash.pprev && (uintptr_t)i->kshim_test_data == hashval &&
		    !(i->i_state & I_FREEING) && (!test || test(i, data)))
			return i;
	return NULL;
}
/* A reference taken on a cached inode (lock held): it is in use again. */
static void kshim_ref_locked(struct inode *i)
{
	atomic_inc(&i->i_count);
	if (i->kshim_in_lru) {
		lru_del_locked(i);
		kshim_icache_hits++;
	}
}
static struct inode *kshim_find_get(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	struct inode *i;
	for (;;) {
		mutex_lock(&kshim_inode_lock);
		i = kshim_find(sb, hashval, test, data);
		if (i && (i->i_state & I_NEW) && i->i_count.counter > 0) {
			/* Another thread is still filling it in: wait like wait_on_inode(). */
			mutex_unlock(&kshim_inode_lock);
			ngos_yield();
			continue;
		}
		if (i) kshim_ref_locked(i);
		mutex_unlock(&kshim_inode_lock);
		return i;
	}
}
struct inode *ilookup5(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	return kshim_find_get(sb, hashval, test, data);
}
struct inode *ilookup5_nowait(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data, bool *isnew)
{
	struct inode *i;
	mutex_lock(&kshim_inode_lock);
	i = kshim_find(sb, hashval, test, data);
	if (i) kshim_ref_locked(i);
	mutex_unlock(&kshim_inode_lock);
	if (isnew) *isnew = i ? (i->i_state & I_NEW) != 0 : false;
	return i;
}
struct inode *iget5_locked(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), int (*set)(struct inode *, void *), void *data)
{
	struct inode *i, *n = NULL;
	for (;;) {
		i = kshim_find_get(sb, hashval, test, data);
		if (i) {
			if (n) {
				if (sb->s_op->free_inode) sb->s_op->free_inode(n);
				else if (sb->s_op->destroy_inode) sb->s_op->destroy_inode(n);
			}
			return i;
		}
		if (!n && !(n = sb->s_op->alloc_inode(sb)))
			return NULL;
		mutex_lock(&kshim_inode_lock);
		if (!kshim_find(sb, hashval, test, data))
			break;
		/* Another thread hashed one meanwhile (maybe still I_NEW): wait for it and take it. */
		mutex_unlock(&kshim_inode_lock);
	}
	kshim_inode_init(sb, n);
	if (set && set(n, data)) {
		n->i_state |= I_FREEING;
		kshim_inode_unlist(n);
		mutex_unlock(&kshim_inode_lock);
		return NULL;
	}
	n->kshim_test_data = (void *)(uintptr_t)hashval;
	n->i_state |= I_NEW;
	n->i_hash.pprev = (void *)1;
	ihash_add_locked(n);
	mutex_unlock(&kshim_inode_lock);
	return n;
}
/* The mft inode created by fill_super is hashed via insert_inode_hash with i_ino. */
struct inode *find_inode_nowait(struct super_block *sb, unsigned long hashval,
		int (*match)(struct inode *, u64, void *), void *data)
{
	struct inode *ret = NULL;
	mutex_lock(&kshim_inode_lock);
	for (struct inode *i = sb->kshim_ihash[hashval % KSHIM_IHASH]; i; i = i->kshim_hnext) {
		int r;
		if (!i->i_hash.pprev) continue;
		r = match(i, hashval, data);
		if (r) { ret = r > 0 ? i : NULL; break; }
	}
	mutex_unlock(&kshim_inode_lock);
	return ret;
}
/*
 * References every live, hashed inode of @sb that has unwritten changes (dirty state or a dirty folio) into a new array
 * (for the sync loop and its dirty test); returns the count.  The loop wrote every inode of the volume's cache back
 * into this array and dropped the references again, a thousand inodes and more, for each commit.
 */
int kshim_inodes_snapshot(struct super_block *sb, struct inode ***out)
{
	struct inode **v;
	int n = 0, cap;
	*out = NULL;
	mutex_lock(&kshim_inode_lock);
	cap = (int)kshim_inodes_live + 1;
	v = kmalloc_array(cap, sizeof(*v), GFP_NOFS);
	if (v) {
		for (struct inode *i = sb->kshim_inodes; i && n < cap; i = i->kshim_next) {
			if (i->i_state & (I_FREEING | I_NEW))
				continue;
			if (!(i->i_state & I_DIRTY) && !kshim_mapping_dirty(i->i_mapping))
				continue;
			atomic_inc(&i->i_count);
			v[n++] = i;
		}
	}
	mutex_unlock(&kshim_inode_lock);
	*out = v;
	return v ? n : -ENOMEM;
}
#if DBG
/*
 * Checked builds: whether @sb has anything dirty, read from the folios and inode states themselves (not from
 * the dirty hints), for the check of a skipped sync (kshim_check_skip).  Callers hold the volume lock.
 */
bool kshim_sb_dirty_full(struct super_block *sb)
{
	bool d = false;
	mutex_lock(&kshim_inode_lock);
	for (struct inode *i = sb->kshim_inodes; i && !d; i = i->kshim_next) {
		struct address_space *m = i->i_mapping;
		if (i->i_state & (I_FREEING | I_NEW))
			continue;
		if (i->i_state & I_DIRTY) {
			d = true;
			break;
		}
		for (int b = 0; m && b < KSHIM_PC_BUCKETS && !d; b++)
			for (struct folio *x = m->pc[b]; x; x = x->hnext)
				if (folio_test_dirty(x)) {
					d = true;
					break;
				}
	}
	mutex_unlock(&kshim_inode_lock);
	if (!d && sb->s_bdev && sb->s_bdev->bd_mapping) {
		struct address_space *m = sb->s_bdev->bd_mapping;
		for (int b = 0; b < KSHIM_PC_BUCKETS && !d; b++)
			for (struct folio *x = m->pc[b]; x; x = x->hnext)
				if (folio_test_dirty(x)) {
					d = true;
					break;
				}
	}
	return d;
}
#endif
void unlock_new_inode(struct inode *i)
{
	i->i_state &= ~I_NEW;
	kshim_dirty_bump();	/* a sync skips I_NEW inodes: one made dirty while new is visible now */
}
void discard_new_inode(struct inode *i)
{
	mutex_lock(&kshim_inode_lock);
	i->i_state = (i->i_state & ~I_NEW) | I_FREEING;
	mutex_unlock(&kshim_inode_lock);
	iput(i);
}
void iget_failed(struct inode *i) { discard_new_inode(i); }
/*
 * As in Linux, an inode being evicted cannot be grabbed: __ntfs_write_inode grabs the inode it writes,
 * and when eviction writes a dirty inode (a read-only volume skips the writeback before it), its iput
 * would evict the inode a second time.  No lock: find_inode_nowait calls this under kshim_inode_lock.
 */
struct inode *igrab(struct inode *i)
{
	if (i->i_state & I_FREEING)
		return NULL;
	atomic_inc(&i->i_count);
	return i;
}
void ihold(struct inode *i) { atomic_inc(&i->i_count); }
static void kshim_evict(struct inode *i)
{
	struct super_block *sb = i->i_sb;
	i->i_state |= I_FREEING;
	mutex_lock(&kshim_inode_lock);
	i->i_hash.pprev = NULL;
	ihash_del_locked(i);
	lru_del_locked(i);
	mutex_unlock(&kshim_inode_lock);
	if (sb->s_op->evict_inode) sb->s_op->evict_inode(i);
	else truncate_inode_pages_final(i->i_mapping);
	mutex_lock(&kshim_inode_lock);
	kshim_inode_unlist(i);
	mutex_unlock(&kshim_inode_lock);
	if (sb->s_op->destroy_inode) sb->s_op->destroy_inode(i);
	if (sb->s_op->free_inode) sb->s_op->free_inode(i);
}
/* Last reference gone and the file system keeps the inode: cache it as unused.  False: evict it now. */
static bool kshim_icache_keep(struct inode *i)
{
	struct super_block *sb = i->i_sb;
	bool kept = false;
	if (sb->kshim_no_icache || !i->i_hash.pprev || (i->i_state & (I_FREEING | I_NEW)) || !i->i_nlink ||
	    (kshim_icache_ok && !kshim_icache_ok(i)))
		return false;
	if (kshim_is_data_inode && kshim_is_data_inode(i))
		kshim_mapping_shrink(i->i_mapping);
	mutex_lock(&kshim_inode_lock);
	if (i->i_hash.pprev && !(i->i_state & (I_FREEING | I_NEW))) {
		if (!i->i_count.counter)
			lru_add_locked(i);
		kept = true;
	}
	mutex_unlock(&kshim_inode_lock);
	return kept;
}

/*
 * Memory pressure (the Mm low-memory condition is signalled): this cache is nonpaged pool, which the memory manager
 * cannot take back, so it is given back here, down to a floor of a quarter of the normal limits (never below 1024
 * inodes / 256 pages).  The oldest unused inodes go first; each is written back before it is evicted (as in every
 * eviction: kshim_lru_evict), one whose writeback fails stays.  Inodes in use are never touched.  Stops as soon as the
 * condition clears, re-read every 32 evictions, and takes at most 2048 inodes per call so a call stays short.
 * Called from kshim_icache_trim, i.e. from CoreLock release at depth 1 (every file system operation, and the flusher's
 * 2 s pass when the volume is idle): the same context and locks as the trim above; no lock is taken here, the
 * low-memory test only reads an event's state.
 */
static void kshim_icache_trim_pressure(struct super_block *sb)
{
	unsigned long inode_floor = KSHIM_ICACHE_UNUSED / 4, page_floor = KSHIM_PC_PAGES_SOFT / 4;
	long tries = sb->kshim_lru_count + 64;
	int budget = 2048, n = 0;
	struct inode *v;
	if (inode_floor < 1024) inode_floor = 1024;
	if (page_floor < 256) page_floor = 256;
	while (tries-- > 0 && budget-- > 0 && (n++ % 32 || ngos_low_memory()) &&
	       (v = kshim_lru_take(sb, (unsigned long)sb->kshim_lru_count > inode_floor ||
				   (sb->kshim_lru_count && kshim_pc_pages > page_floor)))) {
		kshim_lru_evict(v);
		kshim_icache_pressure_evicted++;
	}
}

/* Evicts the oldest unused inodes beyond the limits.  The caller holds no file system lock. */
void kshim_icache_trim(struct super_block *sb)
{
	struct inode *v;
	int budget = 64;	/* the page count also holds pages of inodes in use: evict a bounded batch for it */
	long tries = sb->kshim_lru_count + 64;	/* an inode whose writeback fails goes back on the list */
	/* Over the byte limit: the oldest go, down to a quarter of the count limit (never below 1024) so a few heavy inodes cannot empty the list. */
	unsigned long byte_floor = KSHIM_ICACHE_UNUSED / 4;
	if (byte_floor < 1024) byte_floor = 1024;
	while (tries-- > 0 && (v = kshim_lru_take(sb, sb->kshim_lru_count > KSHIM_ICACHE_UNUSED ||
				   (sb->kshim_lru_bytes > KSHIM_ICACHE_BYTES && sb->kshim_lru_count > byte_floor && ++kshim_icache_byte_evicted) ||
				   (sb->kshim_lru_count && kshim_pc_pages > KSHIM_PC_PAGES_SOFT && budget-- > 0))))
		kshim_lru_evict(v);
	kshim_icache_trim_pressure(sb);
}

/*
 * Linux writes an inode back before it is evicted.  @i holds one reference (dropped here); true: still
 * in use, or kept because its writeback failed: it stays cached and unused, dirty, so the next sync
 * writes it, instead of eviction dropping its dirty pages.
 */
unsigned long kshim_counter_wb_kept;
/* Verbose dump: where the inode cache stands against its limits (inodes live = unused on the LRU lists + in use). */
static void kshim_dump_icache(void)
{
	printk("icache: %lu inodes live, %ld unused (%lld KB cost) + %ld in use; limits %lu inodes / %lu KB, pages %lu of %lu; "
	       "evicted %lu (byte %lu, pressure %lu, wb kept %lu)\n",
	       kshim_inodes_live, kshim_lru_total, kshim_lru_bytes_total / 1024, (long)kshim_inodes_live - kshim_lru_total,
	       KSHIM_ICACHE_UNUSED, KSHIM_ICACHE_BYTES / 1024, kshim_pc_pages, KSHIM_PC_PAGES_SOFT,
	       kshim_icache_evicted, kshim_icache_byte_evicted, kshim_icache_pressure_evicted, kshim_counter_wb_kept);
}
static bool kshim_writeback_last(struct inode *i)
{
	if (i->i_nlink && !(i->i_state & (I_FREEING | I_NEW)) && i->i_sb && !sb_rdonly(i->i_sb) &&
	    ((i->i_state & I_DIRTY) || kshim_mapping_dirty(i->i_mapping))) {
		int err = write_inode_now(i, 1);
		if (err || (i->i_state & I_DIRTY) || kshim_mapping_dirty(i->i_mapping)) {
			if (kshim_counter_wb_kept++ < 8)
				printk(KERN_ERR "writeback of ino %llu failed %d: kept in memory\n",
				       (unsigned long long)i->i_ino, err);
			i->i_state |= I_DIRTY_PAGES;
			kshim_dirty_bump();
			mutex_lock(&kshim_inode_lock);
			if (atomic_dec_and_test(&i->i_count) && i->i_hash.pprev && !(i->i_state & (I_FREEING | I_NEW)))
				lru_add_locked(i);
			mutex_unlock(&kshim_inode_lock);
			return true;
		}
	}
	return !atomic_dec_and_test(&i->i_count);
}

void iput(struct inode *i)
{
	if (!i || IS_ERR(i))
		return;
	if (!atomic_dec_and_test(&i->i_count))
		return;
	/* A cached inode stays dirty until the next sync or its eviction writes it back. */
	if (!(i->i_sb->s_op->drop_inode ? i->i_sb->s_op->drop_inode(i) : inode_generic_drop(i)) &&
	    kshim_icache_keep(i))
		return;
	atomic_inc(&i->i_count);
	if (kshim_writeback_last(i))
		return;
	/* Taken again by a lookup since the count reached 0: it stays. */
	mutex_lock(&kshim_inode_lock);
	if (i->i_count.counter) {
		mutex_unlock(&kshim_inode_lock);
		return;
	}
	i->i_state |= I_FREEING;
	mutex_unlock(&kshim_inode_lock);
	kshim_evict(i);
}

/* Takes the oldest unused inode off the LRU and pins it, or returns NULL when @more is false or none is left. */
static struct inode *kshim_lru_take(struct super_block *sb, bool more)
{
	struct inode *v;
	mutex_lock(&kshim_inode_lock);
	while (more && (v = sb->kshim_lru_head)) {
		lru_del_locked(v);
		if (v->i_count.counter || (v->i_state & (I_FREEING | I_NEW)))
			continue;
		atomic_inc(&v->i_count);
		mutex_unlock(&kshim_inode_lock);
		return v;
	}
	mutex_unlock(&kshim_inode_lock);
	return NULL;
}

/* Writes back and evicts a pinned unused inode unless it was taken into use meanwhile. */
static void kshim_lru_evict(struct inode *v)
{
	if (kshim_writeback_last(v))
		return;
	mutex_lock(&kshim_inode_lock);
	if (v->i_count.counter || (v->i_state & (I_FREEING | I_NEW))) {
		mutex_unlock(&kshim_inode_lock);
		return;
	}
	v->i_state |= I_FREEING;
	if (kshim_icache_evicting && v->i_nlink)
		kshim_icache_evicting(v);
	mutex_unlock(&kshim_inode_lock);
	kshim_icache_evicted++;
	kshim_evict(v);
}

void kshim_icache_lock(void) { mutex_lock(&kshim_inode_lock); }
void kshim_icache_unlock(void) { mutex_unlock(&kshim_inode_lock); }
/* Under kshim_icache_lock: the inode in memory for @hashval, without a reference, or NULL. */
struct inode *kshim_icache_peek(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	struct inode *i = kshim_find(sb, hashval, test, data);
	return i && !(i->i_state & I_NEW) ? i : NULL;
}

/* The number of inodes for @hashval that match @test and hold a reference. */
int kshim_icache_busy(struct super_block *sb, unsigned long hashval,
		int (*test)(struct inode *, void *), void *data)
{
	int n = 0;
	mutex_lock(&kshim_inode_lock);
	for (struct inode *i = sb->kshim_ihash[hashval % KSHIM_IHASH]; i; i = i->kshim_hnext)
		if (i->i_hash.pprev && (uintptr_t)i->kshim_test_data == hashval && !(i->i_state & I_FREEING) &&
		    atomic_read(&i->i_count) > 0 && test(i, data))
			n++;
	mutex_unlock(&kshim_inode_lock);
	return n;
}

/* Evicts the unused inodes of @sb; with @all also every later one (unmount). */
void kshim_icache_flush(struct super_block *sb, int all)
{
	struct inode *v;
	long tries = sb->kshim_lru_count + 64;
	if (all)
		sb->kshim_no_icache = 1;
	while (tries-- > 0 && (v = kshim_lru_take(sb, true)))
		kshim_lru_evict(v);
}
void clear_inode(struct inode *i) { i->i_state |= I_CLEAR; }
int generic_delete_inode(struct inode *i) { (void)i; return 1; }
int inode_generic_drop(struct inode *i) { return !i->i_nlink; }
void set_nlink(struct inode *i, unsigned int n) { i->i_nlink = n; }
void inc_nlink(struct inode *i) { i->i_nlink++; }
void drop_nlink(struct inode *i) { i->i_nlink--; }
void clear_nlink(struct inode *i) { i->i_nlink = 0; }
void init_special_inode(struct inode *i, umode_t m, dev_t d) { i->i_mode = m; i->i_rdev = d; }
void inode_init_owner(struct mnt_idmap *idmap, struct inode *i, const struct inode *dir, umode_t mode)
{ (void)idmap; (void)dir; i->i_mode = mode; }

/* ---------------------------------------------------------------- dentry */
struct dentry *d_make_root(struct inode *i)
{
	struct dentry *d;
	if (!i) return NULL;
	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d) { iput(i); return NULL; }
	d->d_inode = i; d->d_parent = d; d->d_sb = i->i_sb;
	d->d_name.name = (const unsigned char *)"/"; d->d_name.len = 1;
	return d;
}
struct dentry *d_splice_alias(struct inode *i, struct dentry *d)
{
	if (IS_ERR(i)) return (struct dentry *)i;
	d->d_inode = i;
	return NULL;
}
struct dentry *d_add_ci(struct dentry *d, struct inode *i, struct qstr *n)
{
	if (n && n->name && !IS_ERR(i)) {
		kfree(d->kshim_ci_name);
		d->kshim_ci_name = kmemdup(n->name, n->len, GFP_NOFS);
		d->kshim_ci_len = d->kshim_ci_name ? n->len : 0;
	}
	return d_splice_alias(i, d);
}
void d_add(struct dentry *d, struct inode *i) { d->d_inode = i; }
void dput(struct dentry *d) { (void)d; }
bool dir_emit_dots(struct file *f, struct dir_context *ctx)
{
	if (ctx->pos == 0) {
		if (!ctx->actor(ctx, ".", 1, ctx->pos, f->f_inode->i_ino, DT_DIR)) return false;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		struct dentry *p = f->f_path.dentry ? f->f_path.dentry->d_parent : NULL;
		u64 ino = p && p->d_inode ? p->d_inode->i_ino : f->f_inode->i_ino;
		if (!ctx->actor(ctx, "..", 2, ctx->pos, ino, DT_DIR)) return false;
		ctx->pos = 2;
	}
	return true;
}
unsigned int full_name_hash(const void *salt, const char *n, unsigned int len)
{
	unsigned int h = 0; (void)salt;
	while (len--) h = h * 31 + (unsigned char)*n++;
	return h;
}

/* --------------------------------------------------------------- super */
int sb_set_blocksize(struct super_block *sb, int size)
{
	if (size < 512 || size > (int)PAGE_SIZE || (size & (size - 1))) return 0;
	sb->s_blocksize = size;
	sb->s_blocksize_bits = ilog2(size);
	return size;
}
int sb_min_blocksize(struct super_block *sb, int size)
{
	int min = bdev_logical_block_size(sb->s_bdev);
	return sb_set_blocksize(sb, size < min ? min : size);
}
/* Set by ngcore around get_tree under its mount mutex. */
struct block_device *kshim_mount_bdev;
int get_tree_bdev(struct fs_context *fc, int (*fill_super)(struct super_block *, struct fs_context *))
{
	struct super_block *sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	int err;
	if (!sb)
		return -ENOMEM;
	sb->s_bdev = kshim_mount_bdev;
	sb->s_type = fc->fs_type;
	sb->s_flags = fc->sb_flags;
	sb->s_fs_info = fc->s_fs_info;
	sb->s_user_ns = &init_user_ns;
	fc->s_fs_info = NULL;
	snprintf(sb->s_id, sizeof(sb->s_id), "ntfsng%p", (void *)sb);
	sb_set_blocksize(sb, 512);
	err = fill_super(sb, fc);
	if (err) { kfree(sb); return err; }
	fc->root = sb->s_root;
	fc->kshim_sb = sb;
	return 0;
}
static int kshim_vmsg(const char *pfx, const char *fmt, va_list ap)
{
	char *buf = ngos_alloc(384);
	if (!buf) return 0;
	vsnprintf(buf, 384, fmt, ap);
	printk("%s%s\n", pfx, buf);
	ngos_free(buf);
	return 0;
}
int invalf(struct fs_context *fc, const char *fmt, ...) { va_list ap; (void)fc; va_start(ap, fmt); kshim_vmsg("invalid: ", fmt, ap); va_end(ap); return -EINVAL; }
int errorf(struct fs_context *fc, const char *fmt, ...) { va_list ap; (void)fc; va_start(ap, fmt); kshim_vmsg("error: ", fmt, ap); va_end(ap); return -EINVAL; }
int warnf(struct fs_context *fc, const char *fmt, ...) { va_list ap; (void)fc; va_start(ap, fmt); kshim_vmsg("warning: ", fmt, ap); va_end(ap); return 0; }
int sync_blockdev(struct block_device *b) { return b && b->bd_mapping ? filemap_write_and_wait(b->bd_mapping) : 0; }
int sync_filesystem(struct super_block *sb) { return kshim_sync(sb); }
void seq_printf(struct seq_file *m, const char *fmt, ...) { (void)m; (void)fmt; }
void seq_puts(struct seq_file *m, const char *s) { (void)m; (void)s; }

/* Block device page cache (Linux def_blk_aops equivalent): used by compress.c and bdev-io.c. */
static int kshim_blkdev_read_folio(struct file *f, struct folio *folio)
{
	struct block_device *b = folio->mapping->host->i_private;
	int err = kshim_dev_rw(b, 0, (u64)folio->index << PAGE_SHIFT, folio->data, PAGE_SIZE);
	(void)f;
	if (!err) folio_mark_uptodate(folio);
	folio_unlock(folio);
	return err;
}
int kshim_blkdev_writepages(struct address_space *m, struct writeback_control *w);
static const struct address_space_operations kshim_blkdev_aops = {
	.read_folio = kshim_blkdev_read_folio,
	.writepages = kshim_blkdev_writepages,
};
struct block_device *kshim_bdev_open(void *osdev, u64 size, unsigned int sector_size)
{
	struct block_device *b = kzalloc(sizeof(*b), GFP_KERNEL);
	struct inode *bi = kzalloc(sizeof(*bi), GFP_KERNEL);
	if (!b || !bi) { kfree(b); kfree(bi); return NULL; }
	b->osdev = osdev;
	b->size = size;
	b->logical_block_size = sector_size;
	bi->i_private = b;
	bi->i_size = size;
	bi->i_blkbits = PAGE_SHIFT;
	bi->i_mapping = &bi->i_data;
	bi->i_data.host = bi;
	bi->i_data.a_ops = &kshim_blkdev_aops;
	bi->i_data.kshim_eager_wb = 1;
	init_rwsem(&bi->i_rwsem);
	init_rwsem(&bi->i_data.invalidate_lock);
	b->bd_inode = bi;
	b->bd_mapping = bi->i_mapping;
	return b;
}
void kshim_bdev_close(struct block_device *b)
{
	if (!b) return;
	kshim_jnl_deactivate(b);
	truncate_inode_pages_final(b->bd_mapping);
	kfree(b->bd_inode);
	kfree(b);
}

/* ------------------------------------------------------------- misc libc */
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swp)(void *, void *, int))
{
	/* Insertion sort: fs/ntfs sorts short arrays only. */
	char *b = base;
	for (size_t i = 1; i < num; i++)
		for (size_t j = i; j > 0 && cmp(b + (j - 1) * size, b + j * size) > 0; j--) {
			if (swp) swp(b + (j - 1) * size, b + j * size, (int)size);
			else for (size_t k = 0; k < size; k++) { char t = b[(j - 1) * size + k]; b[(j - 1) * size + k] = b[j * size + k]; b[j * size + k] = t; }
		}
}
int hex_to_bin(unsigned char ch)
{
	if (ch >= '0' && ch <= '9') return ch - '0';
	ch |= 0x20;
	if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
	return -1;
}
