/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            ntoskrnl/ke/freeze.c
 * PURPOSE:         Routines for freezing and unfreezing processors for
 *                  kernel debugger synchronization.
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

/* Freeze data */
KIRQL KiOldIrql;
ULONG KiFreezeFlag;
#ifndef CONFIG_SMP
/* Nesting of the freezes of the one processor; the SMP code counts its own */
static ULONG KiFreezeNesting;
#endif

/* FUNCTIONS ******************************************************************/

BOOLEAN
NTAPI
KeFreezeExecution(IN PKTRAP_FRAME TrapFrame,
                  IN PKEXCEPTION_FRAME ExceptionFrame)
{
    BOOLEAN Enable, Outermost;
    KIRQL OldIrql;

#ifndef CONFIG_SMP
    UNREFERENCED_PARAMETER(TrapFrame);
    UNREFERENCED_PARAMETER(ExceptionFrame);
#endif

    /* Disable interrupts, get previous state and set the freeze flag */
    Enable = KeDisableInterrupts();
    KiFreezeFlag = 4;

#ifndef CONFIG_SMP
    /* Raise IRQL if we have to */
    OldIrql = KeGetCurrentIrql();
    if (OldIrql < DISPATCH_LEVEL)
        OldIrql = KeRaiseIrqlToDpcLevel();
#else
    /* Raise IRQL to HIGH_LEVEL */
    KeRaiseIrql(HIGH_LEVEL, &OldIrql);
#endif

#ifdef CONFIG_SMP
    /* Architecture specific freeze code. It reports whether this call froze
       the processors, and not a nested one from the debugger's owner */
    Outermost = KxFreezeExecution();
#else
    /* A nested call (the debugger entered again from the session) neither
       replaces the IRQL to go back to nor ends the freeze early */
    Outermost = (KiFreezeNesting++ == 0);
#endif

    /* Save the old IRQL to be restored on unfreeze. A nested call runs at
       HIGH_LEVEL already, and must not replace the one of the outer call */
    if (Outermost)
        KiOldIrql = OldIrql;

    /* Return whether interrupts were enabled */
    return Enable;
}

VOID
NTAPI
KeThawExecution(IN BOOLEAN Enable)
{
    ULONG Dropped = 0, GraceDropped = 0;
    KIRQL OldIrql;

    /* The IRQL to go back to belongs to this freeze, and is read while this processor is still the
       owner: KxThawExecution gives the freeze up, and the next owner (another processor, entering
       the debugger from another IRQL) writes its own IRQL there at once */
    OldIrql = KiOldIrql;

    /* A nested freeze of the owner ends with the others still frozen */
#ifdef CONFIG_SMP
    if (!KxThawExecution())
        return;
#else
    if (--KiFreezeNesting != 0)
        return;
#endif

    /* Clear the freeze flag */
    KiFreezeFlag = 0;

    /* Cleanup CPU caches */
    KxFlushEntireCurrentTb();

#if defined(_M_IX86) || defined(_M_AMD64)
    /* Give an NMI that was dropped during the freeze its normal handling */
    Dropped = KiCheckDroppedNmi();
    GraceDropped = KiCheckGraceDroppedNmi();
#endif

    /* Restore the old IRQL (on one processor the freeze raised it only from below
       DISPATCH_LEVEL, the debugger entry may have raised it before the freeze) */
#ifndef CONFIG_SMP
    if (OldIrql < KeGetCurrentIrql())
#endif
    KeLowerIrql(OldIrql);

    /* Re-enable interrupts */
    KeRestoreInterrupts(Enable);

    /* Say so, now that the others run and the debugger can be entered again.
       Not from the NMI handlers, which run at HIGH_LEVEL on a small stack
       that a print through the debugger can overflow */
    if ((Dropped != 0) && (KeGetCurrentIrql() < HIGH_LEVEL))
        DbgPrint("KE: %lu NMI(s) arrived during the debugger freeze and were dropped\n", Dropped);

    /* The NMIs held by a frozen processor and taken right after its thaw, within
       the grace window, and dropped as belonging to the freeze: counted by
       the NMI handler, which cannot print, and said here at the next thaw */
    if ((GraceDropped != 0) && (KeGetCurrentIrql() < HIGH_LEVEL))
        DbgPrint("KE: %lu NMI(s) held across a debugger thaw were dropped in the post-thaw grace window\n", GraceDropped);
}

/* EOF */
