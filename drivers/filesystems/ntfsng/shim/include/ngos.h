/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * ngos.h - the narrow bridge between the Linux-API shim (compiled without any
 * NT header) and the NT kernel.  Implemented in nt/ngos_nt.c.  Only basic C
 * types cross this boundary.
 */
#ifndef NGOS_H
#define NGOS_H

#include <stddef.h>
#include <stdint.h>

/* Opaque storage for a KEVENT (16 bytes on x86, 24 on x64). */
struct ngos_ev { long long w[4]; };

void *ngos_alloc(size_t n);
void ngos_free(void *p);
void ngos_print(const char *s);
void ngos_bugcheck(const char *what, const char *file, int line) __attribute__((noreturn));

void ngos_ev_init(struct ngos_ev *ev, int synchronization, int signaled);
void ngos_ev_set(struct ngos_ev *ev);
void ngos_ev_clear(struct ngos_ev *ev);
void ngos_ev_wait(struct ngos_ev *ev);
int ngos_ev_trywait(struct ngos_ev *ev);
int ngos_ev_state(struct ngos_ev *ev);

unsigned char ngos_spin_lock(uintptr_t *lock);
void ngos_spin_unlock(uintptr_t *lock, unsigned char irql);

void ngos_yield(void);
void *ngos_current_thread(void);
void ngos_sleep_ms(unsigned int ms);
unsigned long ngos_jiffies(void);
unsigned long ngos_physical_pages(void);
/* True while the system is short of free pages (the Mm low-memory condition is signalled). Lock-free, any IRQL. */
int ngos_low_memory(void);
void ngos_low_memory_init(void);	/* once, at PASSIVE_LEVEL, from DriverEntry */
void ngos_time(long long *sec, long *nsec);

int ngos_dev_read(void *dev, unsigned long long off, void *buf, unsigned int len);
int ngos_dev_write(void *dev, unsigned long long off, void *buf, unsigned int len);
int ngos_dev_flush(void *dev);

/* The volume on storage device dev stopped accepting writes after a failed device write: write an event log entry (err: a negative errno). */
void ngos_volume_failed(void *dev, int err);
/*
 * Force Unit Access (nobufw2).  ngos_dev_fua: the device's write cache is volatile and the stack reports that it honours
 * FUA (a write that asks for it is on the medium when it completes), so ngos_dev_write_fua / ngos_dev_write_v_fua are durable
 * without a flush.  ngos_dev_clean: no write that was not FUA has completed since the last flush started, i.e. a flush
 * now would have nothing of this driver's to make durable.  Without FUA support the _fua calls are plain writes (and
 * ngos_dev_clean is what it says: a flush is still needed after any plain write).
 */
int ngos_dev_fua(void *dev);
int ngos_dev_clean(void *dev);
int ngos_dev_write_fua(void *dev, unsigned long long off, void *buf, unsigned int len);
/*
 * Writes that complete later (nobufw2).  ngos_dev_write_start sends one write and returns at once: 0 sent, 1 not sent (the caller writes
 * synchronously), -1 failed.  The buffer must stay valid until ngos_dev_drain, which waits for every write the calling thread started
 * on the device and returns -1 if one failed (@data: the write is file data whose failure poisons the volume: ngos_dev_defer_failed).
 * Every synchronous write and flush on the device drains the caller's started writes first, so a flush or a journal header never
 * overtakes them.  The thread that started a write is the one that waits for it.
 */
int ngos_dev_write_start(void *dev, unsigned long long off, void *buf, unsigned int len, int fua, int data);
int ngos_dev_drain(void *dev);
int ngos_dev_defer_failed(void *dev);

/* Several writes of one transfer, all sent before any is waited for (queue depth > 1); 0, or -1 if any failed. */
struct ngos_iov {
	unsigned long long off;
	void *buf;
	unsigned int len;
};
int ngos_dev_write_v(void *dev, const struct ngos_iov *iov, unsigned int n);
int ngos_dev_write_v_fua(void *dev, const struct ngos_iov *iov, unsigned int n);

/* Time per stage (diagnostics, FSCTL_NG_PROFILE): ngos_prof adds the ticks since @since to stage @id. */
enum {
	NGP_DEV_READ, NGP_DEV_WRITE, NGP_DEV_FLUSH, NGP_COMMIT, NGP_WRITEBACK, NGP_JNL_COMMIT,
	NGP_COMMIT_FULL, NGP_COMMIT_ALLOC, NGP_SYNC, NGP_LOOKUP, NGP_CREATE, NGP_UNLINK, NGP_RENAME,
	NGP_READDIR, NGP_IGET, NGP_PUT, NGP_STAT, NGP_READ, NGP_WRITE, NGP_SET_SIZE, NGP_SET_INFO,
	NGP_SHORT_NAME, NGP_ADD_SHORT_NAME, NGP_SECURITY, NGP_DIR_EMPTY, NGP_LINK, NGP_DIRWALK,
	NGP_SKIP_TAKEN,		/* checked builds: kshim_sync skipped its scan (count) */
	NGP_SKIP_CHECKED,	/* ... and the verifying scan found nothing dirty, as it must (count) */
	NGP_SKIP_WRONG,		/* ... and the verifying scan found something dirty while no dirtying was announced: a missed bump (count) */
	NGP_SKIP_RACED,		/* ... verifying scan found dirt but a dirtier announced itself meanwhile: inconclusive (count) */
	NGP_RESV_RETRY,		/* a growth that failed with ENOSPC while frees were uncommitted committed and tried again (count; every build) */
	NGP_IRP = 32,		/* + the IRP major function */
	NGP_STAGES = 64
};
unsigned long long ngos_ticks(void);
void ngos_prof(int id, unsigned long long since, unsigned long long bytes);

#endif
