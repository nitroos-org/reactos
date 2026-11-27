/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     PsExitStatus test declarations
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#ifndef _KMTEST_PSEXITSTATUS_H_
#define _KMTEST_PSEXITSTATUS_H_

/* Hold the next thread of a process that exits (in the thread notify routine), except one */
#define IOCTL_PSEXIT_ARM     1
/* Wait (milliseconds in, the thread id out) until a thread is held */
#define IOCTL_PSEXIT_WAIT    2
/* Let the held thread go on with its exit */
#define IOCTL_PSEXIT_RELEASE 3

typedef struct _PSEXIT_ARM
{
    ULONG ProcessId;
    ULONG SkipThreadId;
} PSEXIT_ARM, *PPSEXIT_ARM;

#endif /* _KMTEST_PSEXITSTATUS_H_ */
