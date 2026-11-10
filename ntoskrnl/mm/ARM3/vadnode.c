/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            ntoskrnl/mm/ARM3/vadnode.c
 * PURPOSE:         ARM Memory Manager VAD Node Algorithms
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Timo Kreuzer (timo.kreuzer@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

/* Include Mm version of AVL support */
#include "miavl.h"
#include <avlsupp.c>

/* GLOBALS ********************************************************************/

CHAR MmReadWrite[32] =
{
    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_ONLY_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,

    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_ONLY_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,

    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_ONLY_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,

    MM_NO_ACCESS_ALLOWED, MM_READ_ONLY_ALLOWED, MM_READ_ONLY_ALLOWED,
    MM_READ_ONLY_ALLOWED, MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,
    MM_READ_WRITE_ALLOWED, MM_READ_WRITE_ALLOWED,
};

/* FUNCTIONS ******************************************************************/

extern MM_AVL_TABLE MiRosKernelVadRoot;

#if DBG

static
VOID
MiDbgAssertIsLockedForRead(_In_ PMM_AVL_TABLE Table)
{
    if (Table == &MmSectionBasedRoot)
    {
        /* Need to hold MmSectionBasedMutex */
        ASSERT(MmSectionBasedMutex.Owner == KeGetCurrentThread());
    }
    else if (Table == &MiRosKernelVadRoot)
    {
        /* Need to hold either the system working-set lock or
           the idle process' AddressCreationLock */
        ASSERT(PsGetCurrentThread()->OwnsSystemWorkingSetExclusive ||
               PsGetCurrentThread()->OwnsSystemWorkingSetShared ||
               (PsIdleProcess->AddressCreationLock.Owner == KeGetCurrentThread()));
    }
    else
    {
        /* Need to hold either the process working-set lock or
           the current process' AddressCreationLock */
        PEPROCESS Process = CONTAINING_RECORD(Table, EPROCESS, VadRoot);
        ASSERT(MI_WS_OWNER(Process) ||
               (Process->AddressCreationLock.Owner == KeGetCurrentThread()));
    }
}

static
VOID
MiDbgAssertIsLockedForWrite(_In_ PMM_AVL_TABLE Table)
{
    if (Table == &MmSectionBasedRoot)
    {
        /* Need to hold MmSectionBasedMutex */
        ASSERT(MmSectionBasedMutex.Owner == KeGetCurrentThread());
    }
    else if (Table == &MiRosKernelVadRoot)
    {
        /* Need to hold both the system working-set lock exclusive and
           the idle process' AddressCreationLock */
        ASSERT(PsGetCurrentThread()->OwnsSystemWorkingSetExclusive);
        ASSERT(PsIdleProcess->AddressCreationLock.Owner == KeGetCurrentThread());
    }
    else
    {
        /* Need to hold both the process working-set lock exclusive and
           the current process' AddressCreationLock */
        PEPROCESS Process = CONTAINING_RECORD(Table, EPROCESS, VadRoot);
        ASSERT(Process == PsGetCurrentProcess());
        ASSERT(PsGetCurrentThread()->OwnsProcessWorkingSetExclusive);
        ASSERT(Process->AddressCreationLock.Owner == KeGetCurrentThread());
    }
}

#define ASSERT_LOCKED_FOR_READ(Table) MiDbgAssertIsLockedForRead(Table)
#define ASSERT_LOCKED_FOR_WRITE(Table) MiDbgAssertIsLockedForWrite(Table)

#else // DBG

#define ASSERT_LOCKED_FOR_READ(Table)
#define ASSERT_LOCKED_FOR_WRITE(Table)

#endif // DBG

PMMVAD
NTAPI
MiLocateVad(_In_ PMM_AVL_TABLE Table, _In_ PVOID VirtualAddress)
{
    PMMVAD FoundVad;
    ULONG_PTR Vpn;
    TABLE_SEARCH_RESULT SearchResult;

    ASSERT_LOCKED_FOR_READ(Table);

    /* Start with the the hint */
    FoundVad = (PMMVAD)Table->NodeHint;
    if (!FoundVad) return NULL;

    /* Check if this VPN is in the hint, if so, use it */
    Vpn = (ULONG_PTR)VirtualAddress >> PAGE_SHIFT;
    if ((Vpn >= FoundVad->StartingVpn) && (Vpn <= FoundVad->EndingVpn)) return FoundVad;

    /* VAD hint didn't work, go look for it */
    SearchResult = RtlpFindAvlTableNodeOrParent(Table,
                                                (PVOID)Vpn,
                                                (PMMADDRESS_NODE*)&FoundVad);
    if (SearchResult != TableFoundNode) return NULL;

    /* We found it, update the hint */
    ASSERT(FoundVad != NULL);
    ASSERT((Vpn >= FoundVad->StartingVpn) && (Vpn <= FoundVad->EndingVpn));

    /* We allow this (atomic) update without exclusive lock, because it's a hint only */
    Table->NodeHint = FoundVad;
    return FoundVad;
}

PMMVAD
NTAPI
MiLocateAddress(_In_ PVOID VirtualAddress)
{
    PMM_AVL_TABLE Table = &PsGetCurrentProcess()->VadRoot;
    return MiLocateVad(Table, VirtualAddress);
}

TABLE_SEARCH_RESULT
NTAPI
MiCheckForConflictingNode(IN ULONG_PTR StartVpn,
                          IN ULONG_PTR EndVpn,
                          IN PMM_AVL_TABLE Table,
                          OUT PMMADDRESS_NODE *NodeOrParent)
{
    PMMADDRESS_NODE ParentNode, CurrentNode;

    ASSERT_LOCKED_FOR_READ(Table);

    /* If the tree is empty, there is no conflict */
    if (Table->NumberGenericTableElements == 0) return TableEmptyTree;

    /* Start looping from the root node */
    CurrentNode = RtlRightChildAvl(&Table->BalancedRoot);
    ASSERT(CurrentNode != NULL);
    while (CurrentNode)
    {
        ParentNode = CurrentNode;

        /* This address comes after */
        if (StartVpn > CurrentNode->EndingVpn)
        {
            /* Keep searching on the right */
            CurrentNode = RtlRightChildAvl(CurrentNode);
        }
        else if (EndVpn < CurrentNode->StartingVpn)
        {
            /* This address ends before the node starts, search on the left */
            CurrentNode = RtlLeftChildAvl(CurrentNode);
        }
        else
        {
            /* This address is part of this node, return it */
            *NodeOrParent = ParentNode;
            return TableFoundNode;
        }
    }

    /* There is no more child, save the current node as parent */
    *NodeOrParent = ParentNode;
    if (StartVpn > ParentNode->EndingVpn)
    {
        return TableInsertAsRight;
    }
    else
    {
        return TableInsertAsLeft;
    }
}

VOID
NTAPI
MiInsertNode(IN PMM_AVL_TABLE Table,
             IN PMMADDRESS_NODE NewNode,
             IN PMMADDRESS_NODE Parent,
             IN TABLE_SEARCH_RESULT Result)
{
    ASSERT_LOCKED_FOR_WRITE(Table);

    /* Insert it into the tree */
    RtlpInsertAvlTreeNode(Table, NewNode, Parent, Result);
}

VOID
NTAPI
MiInsertVad(IN PMMVAD Vad,
            IN PMM_AVL_TABLE VadRoot)
{
    TABLE_SEARCH_RESULT Result;
    PMMADDRESS_NODE Parent = NULL;

    ASSERT_LOCKED_FOR_WRITE(VadRoot);

    /* Validate the VAD and set it as the current hint */
    ASSERT(Vad->EndingVpn >= Vad->StartingVpn);
    VadRoot->NodeHint = Vad;

    /* Find the parent VAD and where this child should be inserted */
    Result = RtlpFindAvlTableNodeOrParent(VadRoot, (PVOID)Vad->StartingVpn, &Parent);
    ASSERT(Result != TableFoundNode);
    ASSERT((Parent != NULL) || (Result == TableEmptyTree));

    /* Do the actual insert operation */
    MiInsertNode(VadRoot, (PVOID)Vad, Parent, Result);
}

/* A free placeholder that covers exactly the pages from StartingAddress to EndingAddress */
static
BOOLEAN
MiIsPlaceholderFor(
    _In_ PMMVAD Placeholder,
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress)
{
    return (Placeholder->u.VadFlags.PrivateMemory &&
            Placeholder->u2.VadFlags2.Placeholder &&
            (Placeholder->StartingVpn == (StartingAddress >> PAGE_SHIFT)) &&
            (Placeholder->EndingVpn == (EndingAddress >> PAGE_SHIFT)));
}

/*
 * LowestAddress bounds an automatic placement from below (MEM_ADDRESS_REQUIREMENTS).
 * MEM_REPLACE_PLACEHOLDER in AllocationType: the new VAD takes the place of a free placeholder
 * that covers exactly the same pages. The placeholder leaves the tree under the same locks as
 * the new VAD enters it, so no other thread can find the range free in between.
 */
NTSTATUS
NTAPI
MiInsertVadEx2(
    _Inout_ PMMVAD Vad,
    _In_ ULONG_PTR *BaseAddress,
    _In_ SIZE_T ViewSize,
    _In_ ULONG_PTR LowestAddress,
    _In_ ULONG_PTR HighestAddress,
    _In_ ULONG_PTR Alignment,
    _In_ ULONG AllocationType,
    _In_ BOOLEAN AllowLowFixedAddress)
{
    ULONG_PTR StartingAddress = 0, EndingAddress;
    PEPROCESS CurrentProcess;
    PETHREAD CurrentThread;
    TABLE_SEARCH_RESULT Result;
    PMMADDRESS_NODE Parent;
    PMMVAD Replaced = NULL;

    /* Align the view size to pages */
    ViewSize = ALIGN_UP_BY(ViewSize, PAGE_SIZE);

    /* Get the current process */
    CurrentProcess = PsGetCurrentProcess();

    /* Acquire the address creation lock and make sure the process is alive */
    KeAcquireGuardedMutex(&CurrentProcess->AddressCreationLock);
    if (CurrentProcess->VmDeleted)
    {
        KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
        DPRINT1("The process is dying\n");
        return STATUS_PROCESS_IS_TERMINATING;
    }

    /* Did the caller specify an address? */
    if (*BaseAddress == 0)
    {
        /* Make sure HighestAddress is not too large */
        HighestAddress = min(HighestAddress, (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS);

        /* A very restrictive ZeroBits mask must not underflow the search. */
        if (HighestAddress < (ULONG_PTR)MI_LOWEST_VAD_ADDRESS ||
            ViewSize - 1 > HighestAddress - (ULONG_PTR)MI_LOWEST_VAD_ADDRESS)
        {
            KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
            return STATUS_NO_MEMORY;
        }

        /* A placeholder is replaced at its own address only */
        if (AllocationType & MEM_REPLACE_PLACEHOLDER)
        {
            KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
            return STATUS_INVALID_PARAMETER;
        }

        /* Which way should we search? */
        if ((AllocationType & MEM_TOP_DOWN) || CurrentProcess->VmTopDown)
        {
            /* Find an address top-down */
            Result = MiFindEmptyAddressRangeDownTree(ViewSize,
                                                     HighestAddress,
                                                     Alignment,
                                                     &CurrentProcess->VadRoot,
                                                     &StartingAddress,
                                                     &Parent);

            /* The highest place that fits lies below the lowest address: nothing fits */
            if ((Result != TableFoundNode) && (StartingAddress < LowestAddress))
                Result = TableFoundNode;
        }
        else
        {
            /* Find an address bottom-up */
            Result = MiFindEmptyAddressRangeInTreeEx(ViewSize,
                                                     LowestAddress,
                                                     Alignment,
                                                     &CurrentProcess->VadRoot,
                                                     &Parent,
                                                     &StartingAddress);
        }

        /* Get the ending address, which is the last piece we need for the VAD */
        EndingAddress = StartingAddress + ViewSize - 1;

        /* Check if we found a suitable location */
        if ((Result == TableFoundNode) || (EndingAddress > HighestAddress) || (EndingAddress < StartingAddress))
        {
            DPRINT1("Not enough free space to insert this VAD node!\n");
            KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
            return STATUS_NO_MEMORY;
        }

        ASSERT(StartingAddress != 0);
        ASSERT(StartingAddress < (ULONG_PTR)HighestAddress);
        ASSERT(EndingAddress > StartingAddress);
    }
    else
    {
        /* Calculate the starting and ending address */
        StartingAddress = ALIGN_DOWN_BY(*BaseAddress, Alignment);

        /*
         * Nothing goes below the lowest user address, the NULL page included, except for the
         * legacy callers that reserve the VDM's first megabyte from address 1 (kernel32's
         * CreateProcessInternalW and ntvdm on x86)
         */
        if (!AllowLowFixedAddress && (StartingAddress < (ULONG_PTR)MM_LOWEST_USER_ADDRESS))
        {
            /* Windows 10 22H2: NtAllocateVirtualMemoryEx at 0x1000 is STATUS_CONFLICTING_ADDRESSES */
            KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
            return STATUS_CONFLICTING_ADDRESSES;
        }

        /* A section can supply a fixed SEC_BASED address even when its caller
         * requested automatic placement. Enforce the final range here too,
         * before checking conflicts or inserting the VAD. */
        HighestAddress = min(HighestAddress, (ULONG_PTR)MM_HIGHEST_VAD_ADDRESS);
        if (StartingAddress > HighestAddress ||
            ViewSize - 1 > HighestAddress - StartingAddress)
        {
            KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
            return STATUS_NO_MEMORY;
        }
        EndingAddress = StartingAddress + ViewSize - 1;

        /* Make sure it doesn't conflict with an existing allocation */
        Result = MiCheckForConflictingNode(StartingAddress >> PAGE_SHIFT,
                                           EndingAddress >> PAGE_SHIFT,
                                           &CurrentProcess->VadRoot,
                                           &Parent);
        if (Result == TableFoundNode)
        {
            /* Only a placeholder of exactly this range may be in the way of a replacement */
            if (!(AllocationType & MEM_REPLACE_PLACEHOLDER) ||
                !MiIsPlaceholderFor((PMMVAD)Parent, StartingAddress, EndingAddress))
            {
                DPRINT("Given address conflicts with existing node\n");
                KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
                return STATUS_CONFLICTING_ADDRESSES;
            }
            Replaced = (PMMVAD)Parent;
        }
        else if (AllocationType & MEM_REPLACE_PLACEHOLDER)
        {
            /* The placeholder went away since the caller looked at it */
            KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    /* Now set the VAD address */
    Vad->StartingVpn = StartingAddress >> PAGE_SHIFT;
    Vad->EndingVpn = EndingAddress >> PAGE_SHIFT;

    /*
     * Committed private memory, and a copy-on-write view (any page of it can
     * become private), carry a commit charge for the whole range. The caller
     * charged it system-wide before calling us.
     */
    if ((Vad->u.VadFlags.PrivateMemory && Vad->u.VadFlags.MemCommit) ||
        (!Vad->u.VadFlags.PrivateMemory &&
         ((Vad->u.VadFlags.Protection & MM_WRITECOPY) == MM_WRITECOPY)))
    {
        /* Set the commit charge */
        Vad->u.VadFlags.CommitCharge = ViewSize / PAGE_SIZE;
    }

    /* Check if the VAD is to be secured */
    if (Vad->u2.VadFlags2.OneSecured)
    {
        /* This *must* be a long VAD! */
        ASSERT(Vad->u2.VadFlags2.LongVad);

        /* Yeah this is retarded, I didn't invent it! */
        ((PMMVAD_LONG)Vad)->u3.Secured.StartVpn = StartingAddress;
        ((PMMVAD_LONG)Vad)->u3.Secured.EndVpn = EndingAddress;
    }

    /* Lock the working set */
    CurrentThread = PsGetCurrentThread();
    MiLockProcessWorkingSetUnsafe(CurrentProcess, CurrentThread);

    /* Take the placeholder out; the tree changed, so look up the parent again */
    if (Replaced)
    {
        MiRemoveNode((PMMADDRESS_NODE)Replaced, &CurrentProcess->VadRoot);
        CurrentProcess->VirtualSize -= ViewSize;
        Vad->u2.VadFlags2.FromPlaceholder = 1;
        Result = MiCheckForConflictingNode(StartingAddress >> PAGE_SHIFT,
                                           EndingAddress >> PAGE_SHIFT,
                                           &CurrentProcess->VadRoot,
                                           &Parent);
        ASSERT(Result != TableFoundNode);
        if (Result == TableEmptyTree) Parent = NULL;
    }

    /* Insert the VAD */
    CurrentProcess->VadRoot.NodeHint = Vad;
    MiInsertNode(&CurrentProcess->VadRoot, (PVOID)Vad, Parent, Result);

    /* Release the working set */
    MiUnlockProcessWorkingSetUnsafe(CurrentProcess, CurrentThread);

    /* Update the process' virtual size, and peak virtual size */
    CurrentProcess->VirtualSize += ViewSize;
    if (CurrentProcess->VirtualSize > CurrentProcess->PeakVirtualSize)
    {
        CurrentProcess->PeakVirtualSize = CurrentProcess->VirtualSize;
    }

    /*
     * The VAD now owns its charge: account it to the process before the
     * address creation lock is released, so that no other thread can free
     * the VAD and return the charge first
     */
    MiAddProcessCommit(CurrentProcess, Vad->u.VadFlags.CommitCharge);

    /* Unlock the address space */
    KeReleaseGuardedMutex(&CurrentProcess->AddressCreationLock);

    /* The placeholder had no pages and no charge, only its VAD */
    if (Replaced)
    {
        ExFreePool(Replaced);
        PsReturnProcessNonPagedPoolQuota(CurrentProcess, sizeof(MMVAD_LONG));
    }

    *BaseAddress = StartingAddress;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
MiInsertVadEx(
    _Inout_ PMMVAD Vad,
    _In_ ULONG_PTR *BaseAddress,
    _In_ SIZE_T ViewSize,
    _In_ ULONG_PTR HighestAddress,
    _In_ ULONG_PTR Alignment,
    _In_ ULONG AllocationType)
{
    return MiInsertVadEx2(Vad, BaseAddress, ViewSize, 0, HighestAddress, Alignment, AllocationType, TRUE);
}

/* A free placeholder: private, reserved, no access; it takes no commit charge */
VOID
NTAPI
MiInitializePlaceholderVad(
    _Out_ PMMVAD_LONG Vad)
{
    RtlZeroMemory(Vad, sizeof(MMVAD_LONG));
    Vad->u.VadFlags.Protection = MiMakeProtectionMask(PAGE_NOACCESS);
    Vad->u.VadFlags.PrivateMemory = 1;
    Vad->u2.VadFlags2.Placeholder = 1;
}

/*
 * Insert a free placeholder VAD for the pages from StartingAddress to EndingAddress, which the
 * caller has just released. The caller holds the address creation lock and the working set lock
 * of the current process, has charged the VAD's pool quota and accounts the virtual size.
 */
NTSTATUS
NTAPI
MiInsertPlaceholderVad(
    _In_ PEPROCESS Process,
    _In_ PMMVAD_LONG Vad,
    _In_ ULONG_PTR StartingAddress,
    _In_ ULONG_PTR EndingAddress)
{
    TABLE_SEARCH_RESULT Result;
    PMMADDRESS_NODE Parent = NULL;

    ASSERT(Process == PsGetCurrentProcess());
    ASSERT(Vad->u2.VadFlags2.Placeholder);

    Result = MiCheckForConflictingNode(StartingAddress >> PAGE_SHIFT,
                                       EndingAddress >> PAGE_SHIFT,
                                       &Process->VadRoot,
                                       &Parent);
    if (Result == TableFoundNode) return STATUS_CONFLICTING_ADDRESSES;
    if (Result == TableEmptyTree) Parent = NULL;

    Vad->StartingVpn = StartingAddress >> PAGE_SHIFT;
    Vad->EndingVpn = EndingAddress >> PAGE_SHIFT;
    Process->VadRoot.NodeHint = Vad;
    MiInsertNode(&Process->VadRoot, (PVOID)Vad, Parent, Result);
    return STATUS_SUCCESS;
}

VOID
NTAPI
MiInsertBasedSection(IN PSECTION Section)
{
    TABLE_SEARCH_RESULT Result;
    PMMADDRESS_NODE Parent = NULL;
    ASSERT(Section->Address.EndingVpn >= Section->Address.StartingVpn);

    ASSERT_LOCKED_FOR_WRITE(&MmSectionBasedRoot);

    /* Find the parent VAD and where this child should be inserted */
    Result = RtlpFindAvlTableNodeOrParent(&MmSectionBasedRoot, (PVOID)Section->Address.StartingVpn, &Parent);
    ASSERT(Result != TableFoundNode);
    ASSERT((Parent != NULL) || (Result == TableEmptyTree));
    MiInsertNode(&MmSectionBasedRoot, &Section->Address, Parent, Result);
}

/*
 * Where the search for a free range of the kernel table resumes.  A range is taken at the lowest free gap, and
 * the walk from the lowest node to that gap is linear in the number of areas: 4096 for the views of a 1 GB file
 * in the cache, each new view walks them all (27 us per view).  For a request of a size and alignment the walk
 * leaves a node, and below it no gap fits that request; the next request of the same class starts there.  The
 * address space lock (kernel) serializes the searches and removals.  When an area is removed, a gap appears
 * where it was: the hints at or above it go back to the node below it (nothing below that node changed), or to
 * a full walk when it was the lowest.  Inserting an area only fills gaps.
 */
#define MI_KERNEL_GAP_HINTS 4
static struct
{
    PMMADDRESS_NODE Node;       /* resume at this node (NULL: unused entry) */
    ULONG_PTR PageCount;
    ULONG_PTR AlignmentVpn;
    ULONG Age;
} MiKernelGapHints[MI_KERNEL_GAP_HINTS];
static ULONG MiKernelGapHintClock;

static
VOID
MiMoveKernelGapHints(
    _In_ PMMADDRESS_NODE Removed)
{
    PMMADDRESS_NODE Previous = NULL;
    ULONG i;

    for (i = 0; i < MI_KERNEL_GAP_HINTS; i++)
    {
        if (MiKernelGapHints[i].Node == NULL)
            continue;
        if (MiKernelGapHints[i].Node != Removed &&
            MiKernelGapHints[i].Node->StartingVpn < Removed->StartingVpn)
            continue;
        if (Previous == NULL)
            Previous = MiGetPreviousNode(Removed);
        MiKernelGapHints[i].Node = Previous;
    }
}

VOID
NTAPI
MiRemoveNode(IN PMMADDRESS_NODE Node,
             IN PMM_AVL_TABLE Table)
{
    ASSERT_LOCKED_FOR_WRITE(Table);

    /* The kernel table keeps where its gap searches resume (MiFindEmptyAddressRangeInTreeEx) */
    if (Table->Unused == 1)
        MiMoveKernelGapHints(Node);

    /* Call the AVL code */
    RtlpDeleteAvlTreeNode(Table, Node);

    /* Decrease element count */
    Table->NumberGenericTableElements--;

    /* Check if this node was the hint */
    if (Table->NodeHint == Node)
    {
        /* Get a new hint, unless we're empty now, in which case nothing */
        if (!Table->NumberGenericTableElements) Table->NodeHint = NULL;
        else Table->NodeHint = Table->BalancedRoot.RightChild;
    }
}

PMMADDRESS_NODE
NTAPI
MiGetPreviousNode(IN PMMADDRESS_NODE Node)
{
    PMMADDRESS_NODE Parent;

    /* Get the left child */
    if (RtlLeftChildAvl(Node))
    {
        /* Get right-most child */
        Node = RtlLeftChildAvl(Node);
        while (RtlRightChildAvl(Node)) Node = RtlRightChildAvl(Node);
        return Node;
    }

    Parent = RtlParentAvl(Node);
    ASSERT(Parent != NULL);
    while (Parent != Node)
    {
        /* The parent should be a right child, return the real predecessor */
        if (RtlIsRightChildAvl(Node))
        {
            /* Return it unless it's the root */
            if (Parent == RtlParentAvl(Parent)) Parent = NULL;
            return Parent;
        }

        /* Keep lopping until we find our parent */
        Node = Parent;
        Parent = RtlParentAvl(Node);
    }

    /* Nothing found */
    return NULL;
}

/* The node with the lowest address, NULL for an empty table (NitroPager trimmer) */
PMMADDRESS_NODE
NTAPI
MiGetFirstNode(IN PMM_AVL_TABLE Table)
{
    PMMADDRESS_NODE Node;

    if (Table->NumberGenericTableElements == 0)
        return NULL;

    Node = Table->BalancedRoot.RightChild;
    while (RtlLeftChildAvl(Node)) Node = RtlLeftChildAvl(Node);
    return Node;
}

PMMADDRESS_NODE
NTAPI
MiGetNextNode(IN PMMADDRESS_NODE Node)
{
    PMMADDRESS_NODE Parent;

    /* Get the right child */
    if (RtlRightChildAvl(Node))
    {
        /* Get left-most child */
        Node = RtlRightChildAvl(Node);
        while (RtlLeftChildAvl(Node)) Node = RtlLeftChildAvl(Node);
        return Node;
    }

    Parent = RtlParentAvl(Node);
    ASSERT(Parent != NULL);
    while (Parent != Node)
    {
        /* The parent should be a left child, return the real predecessor */
        if (RtlIsLeftChildAvl(Node))
        {
            /* Return it */
            return Parent;
        }

        /* Keep lopping until we find our parent */
        Node = Parent;
        Parent = RtlParentAvl(Node);
    }

    /* Nothing found */
    return NULL;
}

TABLE_SEARCH_RESULT
NTAPI
MiFindEmptyAddressRangeInTreeEx(IN SIZE_T Length,
                                IN ULONG_PTR LowestAddress,
                                IN ULONG_PTR Alignment,
                                IN PMM_AVL_TABLE Table,
                                OUT PMMADDRESS_NODE *PreviousVad,
                                OUT PULONG_PTR Base)
{
    PMMADDRESS_NODE Node, PreviousNode;
    ULONG_PTR PageCount, AlignmentVpn, LowVpn, HighestVpn;
    LONG Hint;
    ULONG i;
    ASSERT(Length != 0);

    ASSERT_LOCKED_FOR_READ(Table);

    /* Calculate page numbers for the length, alignment, and starting address */
    PageCount = BYTES_TO_PAGES(Length);
    AlignmentVpn = Alignment >> PAGE_SHIFT;
    LowVpn = ALIGN_UP_BY(max(LowestAddress, (ULONG_PTR)MM_LOWEST_USER_ADDRESS) >> PAGE_SHIFT, AlignmentVpn);

    /* Check for kernel mode table (memory areas) */
    if (Table->Unused == 1)
    {
        LowVpn = ALIGN_UP_BY((ULONG_PTR)MmSystemRangeStart >> PAGE_SHIFT, AlignmentVpn);
    }

    /* Check if the table is empty */
    if (Table->NumberGenericTableElements == 0)
    {
        /* Tree is empty, the candidate address is already the best one */
        *Base = LowVpn << PAGE_SHIFT;
        return TableEmptyTree;
    }

    /* Otherwise, follow the leftmost child of the right root node's child */
    Node = RtlRightChildAvl(&Table->BalancedRoot);
    while (RtlLeftChildAvl(Node)) Node = RtlLeftChildAvl(Node);

    /* Start a search to find a gap */
    PreviousNode = NULL;
    Hint = -1;
    if (Table->Unused == 1)
    {
        /* A search of this class (size, alignment) left a node: below it no gap fits (MiKernelGapHints) */
        for (i = 0; i < MI_KERNEL_GAP_HINTS; i++)
        {
            if (MiKernelGapHints[i].Node != NULL &&
                MiKernelGapHints[i].PageCount == PageCount &&
                MiKernelGapHints[i].AlignmentVpn == AlignmentVpn)
            {
                Hint = (LONG)i;
                break;
            }
        }
        if (Hint >= 0)
        {
            Node = MiKernelGapHints[Hint].Node;
            PreviousNode = MiGetPreviousNode(Node);
            if (PreviousNode != NULL && PreviousNode->EndingVpn >= LowVpn)
                LowVpn = ALIGN_UP_BY(PreviousNode->EndingVpn + 1, AlignmentVpn);
        }
        else
        {
            /* The least recently used entry takes this class */
            Hint = 0;
            for (i = 1; i < MI_KERNEL_GAP_HINTS; i++)
            {
                if (MiKernelGapHints[i].Node == NULL ||
                    (MiKernelGapHints[Hint].Node != NULL && MiKernelGapHints[i].Age < MiKernelGapHints[Hint].Age))
                    Hint = (LONG)i;
            }
            MiKernelGapHints[Hint].Node = NULL;
            MiKernelGapHints[Hint].PageCount = PageCount;
            MiKernelGapHints[Hint].AlignmentVpn = AlignmentVpn;
        }
        MiKernelGapHints[Hint].Age = ++MiKernelGapHintClock;
    }
    while (Node != NULL)
    {
        /* Check if the gap below the current node is suitable */
        if (Node->StartingVpn >= LowVpn + PageCount)
        {
            /* There is enough space to add our node */
            *Base = LowVpn << PAGE_SHIFT;
            if (Hint >= 0)
                MiKernelGapHints[Hint].Node = Node;

            /* Can we use the current node as parent? */
            if (RtlLeftChildAvl(Node) == NULL)
            {
                /* Node has no left child, so use it as parent */
                *PreviousVad = Node;
                return TableInsertAsLeft;
            }
            else
            {
                /* Node has a left child, this means that the previous node is
                   the right-most child of it's left child and can be used as
                   the parent. In case we use the space before the left-most
                   node, it's left child must be NULL. */
                ASSERT(PreviousNode != NULL);
                ASSERT(RtlRightChildAvl(PreviousNode) == NULL);
                *PreviousVad = PreviousNode;
                return TableInsertAsRight;
            }
        }

        /* The next candidate is above the current node */
        if (Node->EndingVpn >= LowVpn)
            LowVpn = ALIGN_UP_BY(Node->EndingVpn + 1, AlignmentVpn);

        /* Remember the current node and go to the next node */
        PreviousNode = Node;
        Node = MiGetNextNode(Node);
    }

    /* We're up to the highest VAD, will this allocation fit above it? */
    HighestVpn = ((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS + 1) / PAGE_SIZE;

    /* Check for kernel mode table (memory areas) */
    if (Table->Unused == 1)
    {
        HighestVpn = ALIGN_UP_BY((ULONG_PTR)(LONG_PTR)-1 >> PAGE_SHIFT, AlignmentVpn);
    }

    if (HighestVpn >= LowVpn + PageCount)
    {
        /* Yes! Use this VAD to store the allocation */
        *PreviousVad = PreviousNode;
        *Base = LowVpn << PAGE_SHIFT;
        if (Hint >= 0)
            MiKernelGapHints[Hint].Node = PreviousNode;
        return TableInsertAsRight;
    }

    /* Nyet, there's no free address space for this allocation, so we'll fail */
    return TableFoundNode;
}

TABLE_SEARCH_RESULT
NTAPI
MiFindEmptyAddressRangeInTree(IN SIZE_T Length,
                              IN ULONG_PTR Alignment,
                              IN PMM_AVL_TABLE Table,
                              OUT PMMADDRESS_NODE *PreviousVad,
                              OUT PULONG_PTR Base)
{
    return MiFindEmptyAddressRangeInTreeEx(Length, 0, Alignment, Table, PreviousVad, Base);
}

TABLE_SEARCH_RESULT
NTAPI
MiFindEmptyAddressRangeDownTree(IN SIZE_T Length,
                                IN ULONG_PTR BoundaryAddress,
                                IN ULONG_PTR Alignment,
                                IN PMM_AVL_TABLE Table,
                                OUT PULONG_PTR Base,
                                OUT PMMADDRESS_NODE *Parent)
{
    PMMADDRESS_NODE Node, OldNode = NULL, Child;
    ULONG_PTR LowVpn, HighVpn, AlignmentVpn;
    PFN_NUMBER PageCount;

    ASSERT_LOCKED_FOR_READ(Table);

    /* Sanity checks */
    ASSERT(BoundaryAddress);
    ASSERT(BoundaryAddress <= ((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS));
    ASSERT((Alignment & (PAGE_SIZE - 1)) == 0);

    /* Calculate page numbers for the length and alignment */
    Length = ROUND_TO_PAGES(Length);
    PageCount = Length >> PAGE_SHIFT;
    AlignmentVpn = Alignment / PAGE_SIZE;

    /* Check for kernel mode table (memory areas) */
    if (Table->Unused == 1)
    {
        LowVpn = ALIGN_UP_BY((ULONG_PTR)MmSystemRangeStart >> PAGE_SHIFT, AlignmentVpn);
    }
    else
    {
        LowVpn = ALIGN_UP_BY((ULONG_PTR)MM_LOWEST_USER_ADDRESS, Alignment);
    }

    /* Check if there is enough space below the boundary */
    if ((LowVpn + Length) > (BoundaryAddress + 1))
    {
        return TableFoundNode;
    }

    /* Check if the table is empty */
    if (Table->NumberGenericTableElements == 0)
    {
        /* Tree is empty, the candidate address is already the best one */
        *Base = ALIGN_DOWN_BY(BoundaryAddress + 1 - Length, Alignment);
        return TableEmptyTree;
    }

    /* Calculate the initial upper margin */
    HighVpn = (BoundaryAddress + 1) >> PAGE_SHIFT;

    /* Starting from the root, follow the right children until we found a node
       that ends above the boundary */
    Node = RtlRightChildAvl(&Table->BalancedRoot);
    while ((Node->EndingVpn < HighVpn) &&
           ((Child = RtlRightChildAvl(Node)) != NULL)) Node = Child;

    /* Now loop the Vad nodes */
    while (Node)
    {
        /* Calculate the lower margin */
        LowVpn = ALIGN_UP_BY(Node->EndingVpn + 1, AlignmentVpn);

        /* Check if the current bounds are suitable */
        if ((HighVpn > LowVpn) && ((HighVpn - LowVpn) >= PageCount))
        {
            /* There is enough space to add our node */
            LowVpn = ALIGN_DOWN_BY(HighVpn - PageCount, AlignmentVpn);
            *Base = LowVpn << PAGE_SHIFT;

            /* Can we use the current node as parent? */
            if (!RtlRightChildAvl(Node))
            {
                /* Node has no right child, so use it as parent */
                *Parent = Node;
                return TableInsertAsRight;
            }
            else
            {
                /* Node has a right child. This means we must have already
                   moved one node left from the right-most node we started
                   with, thus we already have an OldNode! */
                ASSERT(OldNode != NULL);

                /* The node we had before is the most left grandchild of
                   that right child, use it as parent. */
                ASSERT(RtlLeftChildAvl(OldNode) == NULL);
                *Parent = OldNode;
                return TableInsertAsLeft;
            }
        }

        /* Update the upper margin if necessary */
        if (Node->StartingVpn < HighVpn) HighVpn = Node->StartingVpn;

        /* Remember the current node and go to the previous node */
        OldNode = Node;
        Node = MiGetPreviousNode(Node);
    }

    /* Check if there's enough space before the lowest Vad */
    LowVpn = ALIGN_UP_BY((ULONG_PTR)MI_LOWEST_VAD_ADDRESS, Alignment) / PAGE_SIZE;
    if ((HighVpn > LowVpn) && ((HighVpn - LowVpn) >= PageCount))
    {
        /* There is enough space to add our address */
        LowVpn = ALIGN_DOWN_BY(HighVpn - PageCount, Alignment >> PAGE_SHIFT);
        *Base = LowVpn << PAGE_SHIFT;
        *Parent = OldNode;
        return TableInsertAsLeft;
    }

    /* No address space left at all */
    *Base = 0;
    *Parent = NULL;
    return TableFoundNode;
}

NTSTATUS
NTAPI
MiFindEmptyAddressRangeDownBasedTree(IN SIZE_T Length,
                                     IN ULONG_PTR BoundaryAddress,
                                     IN ULONG_PTR Alignment,
                                     IN PMM_AVL_TABLE Table,
                                     OUT PULONG_PTR Base)
{
    PMMADDRESS_NODE Node, LowestNode;
    ULONG_PTR LowVpn, BestVpn;

    ASSERT_LOCKED_FOR_READ(Table);

    /* Sanity checks */
    ASSERT(Table == &MmSectionBasedRoot);
    ASSERT(BoundaryAddress);
    ASSERT(BoundaryAddress <= ((ULONG_PTR)MM_HIGHEST_VAD_ADDRESS + 1));

    /* Compute page length, make sure the boundary address is valid */
    Length = ROUND_TO_PAGES(Length);
    if ((BoundaryAddress + 1) < Length) return STATUS_NO_MEMORY;

    /* Check if the table is empty */
    BestVpn = ROUND_DOWN(BoundaryAddress + 1 - Length, Alignment);
    if (Table->NumberGenericTableElements == 0)
    {
        /* Tree is empty, the candidate address is already the best one */
        *Base = BestVpn;
        return STATUS_SUCCESS;
    }

    /* Go to the right-most node which should be the biggest address */
    Node = Table->BalancedRoot.RightChild;
    while (RtlRightChildAvl(Node)) Node = RtlRightChildAvl(Node);

    /* Check if we can fit in here */
    LowVpn = ROUND_UP(Node->EndingVpn + 1, Alignment);
    if ((LowVpn < BoundaryAddress) && (Length <= (BoundaryAddress - LowVpn)))
    {
#if (NTDDI_VERSION >= NTDDI_VISTA)
        /* Return the address. */
        *Base = BestVpn;
#else
        /* Note: this is a compatibility hack that mimics a bug in the 2k3
           kernel. It will can waste up to Alignment bytes of memory above
           the allocation. This bug was fixed in Windows Vista */
        *Base = ROUND_DOWN(BoundaryAddress - Length, Alignment);
#endif
        return STATUS_SUCCESS;
    }

    /* Now loop the Vad nodes */
    do
    {
        /* Break out if we've reached the last node */
        LowestNode = MiGetPreviousNode(Node);
        if (!LowestNode) break;

        /* Check if this node could contain the requested address */
        LowVpn = ROUND_UP(LowestNode->EndingVpn + 1, Alignment);
        if ((LowestNode->EndingVpn < BestVpn) &&
            (LowVpn < Node->StartingVpn) &&
            (Length <= (Node->StartingVpn - LowVpn)))
        {
            /* Check if we need to take BoundaryAddress into account */
            if (BoundaryAddress < Node->StartingVpn)
            {
                /* Return the optimal VPN address */
                *Base = BestVpn;
                return STATUS_SUCCESS;
            }
            else
            {
                /* The upper margin is given by the Node's starting address */
                *Base = ROUND_DOWN(Node->StartingVpn - Length, Alignment);
                return STATUS_SUCCESS;
            }
        }

        /* Move to the next node */
        Node = LowestNode;
    } while (TRUE);

    /* Check if there's enough space before the lowest Vad */
    if ((Node->StartingVpn > (ULONG_PTR)MI_LOWEST_VAD_ADDRESS) &&
        ((Node->StartingVpn - (ULONG_PTR)MI_LOWEST_VAD_ADDRESS) >= Length))
    {
        /* Check if it fits in perfectly */
        if (BoundaryAddress < Node->StartingVpn)
        {
            /* Return the optimal VPN address */
            *Base = BestVpn;
            return STATUS_SUCCESS;
        }

        /* Return an aligned base address within this node */
        *Base = ROUND_DOWN(Node->StartingVpn - Length, Alignment);
        return STATUS_SUCCESS;
    }

    /* No address space left at all */
    return STATUS_NO_MEMORY;
}

NTSTATUS
NTAPI
MiCheckSecuredVad(IN PMMVAD Vad,
                  IN PVOID Base,
                  IN SIZE_T Size,
                  IN ULONG ProtectionMask)
{
    ULONG_PTR StartAddress, EndAddress;

    /* Compute start and end address */
    StartAddress = (ULONG_PTR)Base;
    EndAddress = StartAddress + Size - 1;

    /* Are we deleting/unmapping, or changing? */
    if (ProtectionMask < MM_DELETE_CHECK)
    {
        /* Changing... are we allowed to do so? */
        if ((Vad->u.VadFlags.NoChange == 1) &&
            (Vad->u2.VadFlags2.SecNoChange == 1) &&
            (Vad->u.VadFlags.Protection != ProtectionMask))
        {
            /* Nope, bail out */
            DPRINT1("Trying to mess with a no-change VAD!\n");
            return STATUS_INVALID_PAGE_PROTECTION;
        }
    }
    else
    {
        /* This is allowed */
        ProtectionMask = 0;
    }

    /* ARM3 doesn't support this yet */
    ASSERT(Vad->u2.VadFlags2.MultipleSecured == 0);

    /* Is this a one-secured VAD, like a TEB or PEB? */
    if (Vad->u2.VadFlags2.OneSecured)
    {
        /* Is this allocation being described by the VAD? */
        if ((StartAddress <= ((PMMVAD_LONG)Vad)->u3.Secured.EndVpn) &&
            (EndAddress >= ((PMMVAD_LONG)Vad)->u3.Secured.StartVpn))
        {
            /* Guard page? */
            if (ProtectionMask & MM_DECOMMIT)
            {
                DPRINT1("Not allowed to change protection on guard page!\n");
                return STATUS_INVALID_PAGE_PROTECTION;
            }

            /* ARM3 doesn't have read-only VADs yet */
            ASSERT(Vad->u2.VadFlags2.ReadOnly == 0);

            /* Check if read-write protections are allowed */
            if (MmReadWrite[ProtectionMask] < MM_READ_WRITE_ALLOWED)
            {
                DPRINT1("Invalid protection mask for RW access!\n");
                return STATUS_INVALID_PAGE_PROTECTION;
            }
        }
    }

    /* All good, allow the change */
    return STATUS_SUCCESS;
}

/* EOF */
