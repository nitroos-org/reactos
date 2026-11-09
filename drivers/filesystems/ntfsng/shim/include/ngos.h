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
void ngos_time(long long *sec, long *nsec);

int ngos_dev_read(void *dev, unsigned long long off, void *buf, unsigned int len);
int ngos_dev_write(void *dev, unsigned long long off, void *buf, unsigned int len);
int ngos_dev_flush(void *dev);

/* Several writes of one transfer, all sent before any is waited for (queue depth > 1); 0, or -1 if any failed. */
struct ngos_iov {
	unsigned long long off;
	void *buf;
	unsigned int len;
};
int ngos_dev_write_v(void *dev, const struct ngos_iov *iov, unsigned int n);

/* Time per stage (diagnostics, FSCTL_NG_PROFILE): ngos_prof adds the ticks since @since to stage @id. */
enum {
	NGP_DEV_READ, NGP_DEV_WRITE, NGP_DEV_FLUSH, NGP_COMMIT, NGP_WRITEBACK, NGP_JNL_COMMIT,
	NGP_COMMIT_FULL, NGP_COMMIT_ALLOC, NGP_SYNC, NGP_LOOKUP, NGP_CREATE, NGP_UNLINK, NGP_RENAME,
	NGP_READDIR, NGP_IGET, NGP_PUT, NGP_STAT, NGP_READ, NGP_WRITE, NGP_SET_SIZE, NGP_SET_INFO,
	NGP_SHORT_NAME, NGP_ADD_SHORT_NAME, NGP_SECURITY, NGP_DIR_EMPTY, NGP_LINK, NGP_DIRWALK,
	NGP_IRP = 32,		/* + the IRP major function */
	NGP_STAGES = 64
};
unsigned long long ngos_ticks(void);
void ngos_prof(int id, unsigned long long since, unsigned long long bytes);

#endif
