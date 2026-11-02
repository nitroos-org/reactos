/*
 * PROJECT:     ReactOS Hardware Abstraction Layer
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     HAL Processor Routines
 * COPYRIGHT:   Copyright 2010 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

/* INCLUDES ******************************************************************/

#include <hal.h>
#include "tsc.h"
#define NDEBUG
#include <debug.h>

KAFFINITY HalpActiveProcessors;
KAFFINITY HalpDefaultInterruptAffinity;

/* PRIVATE FUNCTIONS *********************************************************/

VOID
NTAPI
HaliHaltSystem(VOID)
{
    /* Disable interrupts and halt the CPU */
    _disable();
    __halt();
}

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
BOOLEAN
NTAPI
HalAllProcessorsStarted(VOID)
{
    /* The performance counter in user mode needs the TSCs of all of them */
    HalpPublishPerformanceCounter();
    return TRUE;
}

/*
 * @implemented
 */
VOID
NTAPI
HalProcessorIdle(VOID)
{
    /* Enable interrupts and halt the processor */
    _enable();
    __halt();
}

/* EOF */
