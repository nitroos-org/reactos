/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Session images: system images with private pages in each session
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A session image is loaded at the same address in every session that loads it, with pages of its
 * own in each one. The image is mapped, relocated and bound to its imports once; a copy of it taken
 * then (before the security cookie and the page protections) fills the pages of every later session.
 * The copy is the same for every session because everything the image imports sits at the same
 * address everywhere: global images once for all, session images at the address reserved for them in
 * every session.
 *
 * The pages of a session image are resident: they are never paged out and are not backed by the file.
 *
 * Everything here runs with MmSystemLoadLock held, in the context of a process of the session
 * concerned (its own thread, or a thread attached to it).
 */

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

#define MODULE_INVOLVED_IN_ARM3
#include <mm/ARM3/miarm.h>

#define TAG_SESSION_IMAGE 'iSmM'

/* balance.c */
BOOLEAN
NTAPI
MmRebalanceMemoryConsumersAndWait(VOID);

#ifdef _M_AMD64
/* section.c */
VOID
NTAPI
MiFillSystemPageDirectory(
    IN PVOID Base,
    IN SIZE_T NumberOfBytes);
#endif

/* Rounds a load waits for free pages before it fails, as for a global image */
#define MI_SESSION_IMAGE_PAGE_WAITS 1000

/* The pages of one session image in one session */
typedef struct _MI_SESSION_IMAGE_INSTANCE
{
    LIST_ENTRY Links;
    ULONG SessionId;
    ULONG LoadCount;
} MI_SESSION_IMAGE_INSTANCE, *PMI_SESSION_IMAGE_INSTANCE;

/* One session image */
typedef struct _MI_SESSION_IMAGE
{
    LIST_ENTRY Links;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PVOID Base;
    PFN_COUNT PageCount;
    PVOID Template;
    LIST_ENTRY Instances;
    ULONG EntryReferences;                  /* references of the session images that import it */
    ULONG SessionImportCount;               /* the session images it imports (not in LoadedImports) */
    PLDR_DATA_TABLE_ENTRY *SessionImports;
} MI_SESSION_IMAGE, *PMI_SESSION_IMAGE;

/* NitroSessions (Session Manager key): 0 = one session as before, session images are not loaded */
ULONG MmNitroSessions;

static LIST_ENTRY MiSessionImageList = { &MiSessionImageList, &MiSessionImageList };
static RTL_BITMAP MiSessionImageBitmap;
static PULONG MiSessionImageBitmapBuffer;

static
ULONG
MiCurrentSessionId(VOID)
{
    ASSERT(PsGetCurrentProcess()->ProcessInSession);
    return MmSessionSpace->SessionId;
}

/* The address range of session image space that can hold images */
static
NTSTATUS
MiSessionImageInitializeBitmap(VOID)
{
    ULONG Bits, Reserved;

    if (MiSessionImageBitmapBuffer) return STATUS_SUCCESS;

    Bits = (ULONG)(MmSessionImageSize >> PAGE_SHIFT);
    MiSessionImageBitmapBuffer = ExAllocatePoolWithTag(NonPagedPool,
                                                       ALIGN_UP_BY(Bits, 32) / 8,
                                                       TAG_SESSION_IMAGE);
    if (!MiSessionImageBitmapBuffer) return STATUS_INSUFFICIENT_RESOURCES;
    RtlInitializeBitMap(&MiSessionImageBitmap, MiSessionImageBitmapBuffer, Bits);
    RtlClearAllBits(&MiSessionImageBitmap);

#ifdef _M_AMD64
    /* The session structure lives at the start of the image range (amd64 init.c): keep its 2 MB */
    Reserved = (2 * _1MB) >> PAGE_SHIFT;
    RtlSetBits(&MiSessionImageBitmap, 0, Reserved);
#else
    Reserved = 0;
#endif
    UNREFERENCED_PARAMETER(Reserved);

    /* The last page stays free: page table commits take an end address below the end of session space */
    RtlSetBits(&MiSessionImageBitmap, Bits - 1, 1);
    return STATUS_SUCCESS;
}

static
PMI_SESSION_IMAGE
MiFindSessionImage(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PLIST_ENTRY Entry;
    PMI_SESSION_IMAGE Image;

    for (Entry = MiSessionImageList.Flink; Entry != &MiSessionImageList; Entry = Entry->Flink)
    {
        Image = CONTAINING_RECORD(Entry, MI_SESSION_IMAGE, Links);
        if (Image->LdrEntry == LdrEntry) return Image;
    }
    return NULL;
}

static
PMI_SESSION_IMAGE_INSTANCE
MiFindSessionImageInstance(
    _In_ PMI_SESSION_IMAGE Image,
    _In_ ULONG SessionId)
{
    PLIST_ENTRY Entry;
    PMI_SESSION_IMAGE_INSTANCE Instance;

    for (Entry = Image->Instances.Flink; Entry != &Image->Instances; Entry = Entry->Flink)
    {
        Instance = CONTAINING_RECORD(Entry, MI_SESSION_IMAGE_INSTANCE, Links);
        if (Instance->SessionId == SessionId) return Instance;
    }
    return NULL;
}

static PLOAD_IMPORTS MiTakeSessionImports(_In_ PLOAD_IMPORTS Imports,
                                          _Out_opt_ PLDR_DATA_TABLE_ENTRY *Taken, _Out_opt_ PULONG TakenCount);
static ULONG MiImportListCount(_In_ PLOAD_IMPORTS Imports);
static PMI_SESSION_IMAGE MiFindSessionImage(_In_ PLDR_DATA_TABLE_ENTRY LdrEntry);

/* Whether every session image of an import list has its descriptor (none is still being loaded) */
static
BOOLEAN
MiSessionImportsComplete(
    _In_ PLOAD_IMPORTS Imports)
{
    PLDR_DATA_TABLE_ENTRY Entry;
    ULONG i;

    if (!Imports || (Imports == MM_SYSLDR_NO_IMPORTS) || (Imports == MM_SYSLDR_BOOT_LOADED))
        return TRUE;
    if ((ULONG_PTR)Imports & MM_SYSLDR_SINGLE_ENTRY)
    {
        Entry = (PVOID)((ULONG_PTR)Imports & ~MM_SYSLDR_SINGLE_ENTRY);
        return !MiIsSessionImage(Entry) || (MiFindSessionImage(Entry) != NULL);
    }
    for (i = 0; (i < Imports->Count) && Imports->Entry[i]; i++)
    {
        Entry = Imports->Entry[i];
        if (MiIsSessionImage(Entry) && !MiFindSessionImage(Entry))
            return FALSE;
    }
    return TRUE;
}

/* Whether the image is a session image (its address is in session image space) */
BOOLEAN
NTAPI
MiIsSessionImage(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    return MI_IS_SESSION_IMAGE_ADDRESS(LdrEntry->DllBase) ? TRUE : FALSE;
}

/* Reserves the same address range for an image in every session */
NTSTATUS
NTAPI
MiReserveSessionImageVa(
    _In_ PFN_COUNT PageCount,
    _Out_ PVOID *Base)
{
    ULONG Index;
    NTSTATUS Status;

    Status = MiSessionImageInitializeBitmap();
    if (!NT_SUCCESS(Status)) return Status;

    Index = RtlFindClearBitsAndSet(&MiSessionImageBitmap, PageCount, 0);
    if (Index == MAXULONG)
    {
        DPRINT1("Session image space is full: %lu pages wanted\n", PageCount);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    *Base = (PVOID)((ULONG_PTR)MiSessionImageStart + ((ULONG_PTR)Index << PAGE_SHIFT));
    return STATUS_SUCCESS;
}

VOID
NTAPI
MiReleaseSessionImageVa(
    _In_ PVOID Base,
    _In_ PFN_COUNT PageCount)
{
    ULONG Index = (ULONG)(((ULONG_PTR)Base - (ULONG_PTR)MiSessionImageStart) >> PAGE_SHIFT);

    ASSERT(RtlAreBitsSet(&MiSessionImageBitmap, Index, PageCount));
    RtlClearBits(&MiSessionImageBitmap, Index, PageCount);
}

/* Gives the current session resident, writable pages for the range, and page tables for them */
NTSTATUS
NTAPI
MiMapSessionImagePages(
    _In_ PVOID Base,
    _In_ PFN_COUNT PageCount)
{
    PMMPTE PointerPte, LastPte;
    MMPTE TempPte;
    PFN_NUMBER PageFrameIndex;
    KIRQL OldIrql;
    ULONG Retry;
    NTSTATUS Status;
    SIZE_T Size = (SIZE_T)PageCount << PAGE_SHIFT;

    ASSERT(MI_IS_SESSION_IMAGE_ADDRESS(Base));
    ASSERT(MI_IS_SESSION_IMAGE_ADDRESS((PVOID)((ULONG_PTR)Base + Size - 1)));

    /* Page tables of the session */
#ifdef _M_AMD64
    if (MmSessionSpace->SessionId == 0)
    {
        /* Session 0 lives in the shared tables */
        MiFillSystemPageDirectory(Base, Size);
        Status = STATUS_SUCCESS;
    }
    else
#endif
    {
        Status = MiSessionCommitPageTables(Base, (PVOID)((ULONG_PTR)Base + Size));
    }
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("No page tables for session image %p: 0x%lx\n", Base, Status);
        return Status;
    }

    PointerPte = MiAddressToPte(Base);
    LastPte = PointerPte + PageCount;

    /* Every page comes from the free lists, taken under one PFN lock hold, as for a global image */
    for (Retry = 0; ; Retry++)
    {
        OldIrql = MiAcquirePfnLock();
        if (MiGetUsablePageCount() >= PageCount)
            break;

        MiReleasePfnLock(OldIrql);
        if (Retry >= MI_SESSION_IMAGE_PAGE_WAITS)
        {
            DPRINT1("Out of pages for a session image: %lx needed\n", PageCount);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (MmRebalanceMemoryConsumersAndWait() && (MiGetUsablePageCount() < PageCount))
        {
            LARGE_INTEGER Delay;

            Delay.QuadPart = -10 * 10000;
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);
        }
    }

    /* Not global: the same address maps other pages in another session */
    TempPte = ValidKernelPteLocal;
    while (PointerPte < LastPte)
    {
        ASSERT(PointerPte->u.Long == 0);

        MI_SET_USAGE(MI_USAGE_DRIVER_PAGE);
        PageFrameIndex = MiRemoveAnyPageGated(MI_GET_NEXT_COLOR());
        MiInitializePfn(PageFrameIndex, PointerPte, TRUE);
        TempPte.u.Hard.PageFrameNumber = PageFrameIndex;
        MI_WRITE_VALID_PTE(PointerPte, TempPte);
        PointerPte++;
    }
    MiReleasePfnLock(OldIrql);

    InterlockedExchangeAddSizeT(&MmSessionSpace->NonPageablePages, PageCount);
    InterlockedExchangeAddSizeT(&MmSessionSpace->CommittedPages, PageCount);
    return STATUS_SUCCESS;
}

/* Frees the current session's pages of the range (the page tables stay with the session) */
VOID
NTAPI
MiUnmapSessionImagePages(
    _In_ PVOID Base,
    _In_ PFN_COUNT PageCount)
{
    PFN_COUNT Freed;

    ASSERT(MI_IS_SESSION_IMAGE_ADDRESS(Base));
    Freed = MiDeleteSystemPageableVm(MiAddressToPte(Base), PageCount, 0, NULL);
    ASSERT(Freed == PageCount);
    InterlockedExchangeAddSizeT(&MmSessionSpace->NonPageablePages, -(SSIZE_T)Freed);
    InterlockedExchangeAddSizeT(&MmSessionSpace->CommittedPages, -(SSIZE_T)Freed);
}

/*
 * The first load is done in the current session (relocated, imports bound): record the image and its
 * copy for the other sessions. The copy is taken now, before the security cookie and the protections.
 */
NTSTATUS
NTAPI
MiCreateSessionImage(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _In_ PFN_COUNT PageCount)
{
    PMI_SESSION_IMAGE Image;
    PMI_SESSION_IMAGE_INSTANCE Instance;

    Image = ExAllocatePoolWithTag(PagedPool, sizeof(*Image), TAG_SESSION_IMAGE);
    Instance = ExAllocatePoolWithTag(PagedPool, sizeof(*Instance), TAG_SESSION_IMAGE);
    if (!Image || !Instance)
        goto Fail;

    Image->Template = ExAllocatePoolWithTag(PagedPool, (SIZE_T)PageCount << PAGE_SHIFT, TAG_SESSION_IMAGE);
    if (!Image->Template)
        goto Fail;
    RtlCopyMemory(Image->Template, LdrEntry->DllBase, (SIZE_T)PageCount << PAGE_SHIFT);

    /* Every session image it imports is a complete one (an import cycle is not supported): checked first */
    if (!MiSessionImportsComplete(LdrEntry->LoadedImports))
    {
        DPRINT1("%wZ imports a session image that is still being loaded\n", &LdrEntry->BaseDllName);
        ExFreePoolWithTag(Image->Template, TAG_SESSION_IMAGE);
        ExFreePoolWithTag(Image, TAG_SESSION_IMAGE);
        ExFreePoolWithTag(Instance, TAG_SESSION_IMAGE);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* The session images it imports are referenced per session: they leave the loader entry's list */
    Image->SessionImportCount = 0;
    Image->SessionImports = NULL;
    if (MiImportListCount(LdrEntry->LoadedImports))
    {
        Image->SessionImports = ExAllocatePoolWithTag(PagedPool,
                                                      MiImportListCount(LdrEntry->LoadedImports) * sizeof(PVOID),
                                                      TAG_SESSION_IMAGE);
        if (!Image->SessionImports)
        {
            ExFreePoolWithTag(Image->Template, TAG_SESSION_IMAGE);
            goto Fail;
        }
        LdrEntry->LoadedImports = MiTakeSessionImports(LdrEntry->LoadedImports,
                                                       Image->SessionImports, &Image->SessionImportCount);
    }

    /*
     * One reference on the entry of each of them as long as this image exists: a session that loads this
     * image later finds them (their pages in a session go with their loads in it)
     */
    {
        ULONG i;
        PMI_SESSION_IMAGE Imported;
        for (i = 0; i < Image->SessionImportCount; i++)
        {
            Imported = MiFindSessionImage(Image->SessionImports[i]);
            ASSERT(Imported != NULL);
            Imported->EntryReferences++;
            Image->SessionImports[i]->LoadCount++;
        }
    }

    Image->EntryReferences = 0;
    Image->LdrEntry = LdrEntry;
    Image->Base = LdrEntry->DllBase;
    Image->PageCount = PageCount;
    InitializeListHead(&Image->Instances);

    Instance->SessionId = MiCurrentSessionId();
    Instance->LoadCount = 1;
    InsertTailList(&Image->Instances, &Instance->Links);
    InsertTailList(&MiSessionImageList, &Image->Links);
    return STATUS_SUCCESS;

Fail:
    if (Image) ExFreePoolWithTag(Image, TAG_SESSION_IMAGE);
    if (Instance) ExFreePoolWithTag(Instance, TAG_SESSION_IMAGE);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * References (or dereferences) in the current session the session images of an array. A dereference is a
 * whole unload: the entry of an image that nothing holds any more goes too (so it is never read again
 * through the array: the caller drops the array, or its entry is not visited again)
 */
static
NTSTATUS
MiForEachSessionImport(
    _In_reads_(Count) PLDR_DATA_TABLE_ENTRY *Entries,
    _In_ ULONG Count,
    _In_ BOOLEAN Reference,
    _In_ ULONG StopAt,
    _Out_opt_ PULONG Done)
{
    ULONG i;
    NTSTATUS Status;

    if (Done) *Done = 0;
    for (i = 0; (i < Count) && (i < StopAt); i++)
    {
        if (!Entries[i]) continue;
        if (Reference)
        {
            Status = MiReferenceSessionImage(Entries[i]);
            if (!NT_SUCCESS(Status))
                return Status;
        }
        else
        {
            MmUnloadSystemImage(Entries[i]);
        }
        if (Done) *Done = i + 1;
    }
    return STATUS_SUCCESS;
}

/*
 * One more load of a session image in the current session: the first in this session gives the
 * session its pages, filled from the copy, protected, with a security cookie of their own; the
 * session images it imports are referenced in this session too
 */
NTSTATUS
NTAPI
MiReferenceSessionImage(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PMI_SESSION_IMAGE Image;
    PMI_SESSION_IMAGE_INSTANCE Instance;
    ULONG SessionId, Done;
    NTSTATUS Status;

    if (!PsGetCurrentProcess()->ProcessInSession) return STATUS_NO_MEMORY;
    SessionId = MiCurrentSessionId();

    Image = MiFindSessionImage(LdrEntry);
    if (!Image)
    {
        /* Still being loaded for the first time (an import cycle): nothing to add */
        ASSERT(LdrEntry->Flags & LDRP_LOAD_IN_PROGRESS);
        return STATUS_SUCCESS;
    }

    Instance = MiFindSessionImageInstance(Image, SessionId);
    if (Instance)
    {
        Instance->LoadCount++;
        LdrEntry->LoadCount++;
        return STATUS_SUCCESS;
    }

    Instance = ExAllocatePoolWithTag(PagedPool, sizeof(*Instance), TAG_SESSION_IMAGE);
    if (!Instance) return STATUS_INSUFFICIENT_RESOURCES;

    /* Its session imports first: its import thunks point into them */
    Status = MiForEachSessionImport(Image->SessionImports, Image->SessionImportCount, TRUE, MAXULONG, &Done);
    if (!NT_SUCCESS(Status))
        goto UndoImports;

    Status = MiMapSessionImagePages(Image->Base, Image->PageCount);
    if (!NT_SUCCESS(Status))
        goto UndoImports;

    RtlCopyMemory(Image->Base, Image->Template, (SIZE_T)Image->PageCount << PAGE_SHIFT);
    MiWriteProtectSystemImage(Image->Base);
    LdrpInitSecurityCookie(LdrEntry);

    Instance->SessionId = SessionId;
    Instance->LoadCount = 1;
    InsertTailList(&Image->Instances, &Instance->Links);
    LdrEntry->LoadCount++;
    DPRINT1("Session image %wZ at %p in session %lu\n", &LdrEntry->BaseDllName, Image->Base, SessionId);
    return STATUS_SUCCESS;

UndoImports:
    MiForEachSessionImport(Image->SessionImports, Image->SessionImportCount, FALSE, Done, NULL);
    ExFreePoolWithTag(Instance, TAG_SESSION_IMAGE);
    return Status;
}

/*
 * One reference fewer. A load in the current session: the last one in the session frees the session's
 * pages and its references to the session images it imports. A reference that is not a session load
 * (the kernel debugger keeps one while it reads the symbols, from a system thread) only counts.
 * Returns TRUE when nothing holds the image any more (no reference, no session has it): the copy and
 * the address range are gone, and the caller removes the loader entry (MmUnloadSystemImage).
 */
BOOLEAN
NTAPI
MiDereferenceSessionImage(
    _In_ PLDR_DATA_TABLE_ENTRY LdrEntry,
    _In_ BOOLEAN EntryReference)
{
    ULONG i;
    PMI_SESSION_IMAGE Image;
    PMI_SESSION_IMAGE_INSTANCE Instance = NULL;

    Image = MiFindSessionImage(LdrEntry);
    if (!Image)
    {
        DPRINT1("%wZ is not a session image\n", &LdrEntry->BaseDllName);
        return FALSE;
    }

    if (!EntryReference && PsGetCurrentProcess()->ProcessInSession)
        Instance = MiFindSessionImageInstance(Image, MiCurrentSessionId());

    /* Without an instance here, only a reference that is not a session load may go (never another session's) */
    if (!Instance && !EntryReference)
    {
        PLIST_ENTRY Entry;
        ULONG Loads = 0;

        for (Entry = Image->Instances.Flink; Entry != &Image->Instances; Entry = Entry->Flink)
            Loads += CONTAINING_RECORD(Entry, MI_SESSION_IMAGE_INSTANCE, Links)->LoadCount;
        if (LdrEntry->LoadCount <= Loads + Image->EntryReferences)
        {
            DPRINT1("Session image %wZ is not loaded in this session: unload refused\n", &LdrEntry->BaseDllName);
            return FALSE;
        }
    }

    ASSERT(LdrEntry->LoadCount != 0);
    if (LdrEntry->LoadCount == 0) return FALSE;
    LdrEntry->LoadCount--;
    if (EntryReference)
    {
        ASSERT(Image->EntryReferences != 0);
        Image->EntryReferences--;
    }

    if (Instance)
    {
        ASSERT(Instance->LoadCount != 0);
        if (--Instance->LoadCount == 0)
        {
            MiUnmapSessionImagePages(Image->Base, Image->PageCount);
            RemoveEntryList(&Instance->Links);
            ExFreePoolWithTag(Instance, TAG_SESSION_IMAGE);
            MiForEachSessionImport(Image->SessionImports, Image->SessionImportCount, FALSE, MAXULONG, NULL);
        }
    }

    if ((LdrEntry->LoadCount != 0) || !IsListEmpty(&Image->Instances)) return FALSE;

    /* Nothing holds it: the address range and the copy go */
    MiReleaseSessionImageVa(Image->Base, Image->PageCount);
    RemoveEntryList(&Image->Links);

    /* The references on the entries of the session images it imports (taken when it was first loaded) */
    for (i = 0; i < Image->SessionImportCount; i++)
    {
        if (Image->SessionImports[i])
            MiUnloadSystemImageEx(Image->SessionImports[i], TRUE);
    }
    if (Image->SessionImports) ExFreePoolWithTag(Image->SessionImports, TAG_SESSION_IMAGE);
    ExFreePoolWithTag(Image->Template, TAG_SESSION_IMAGE);
    ExFreePoolWithTag(Image, TAG_SESSION_IMAGE);
    return TRUE;
}

/*
 * Takes the session images out of an import list, which then holds global images only (the list stays
 * allocated with a shorter run of entries, or is replaced). Their entries go to *Taken (count in
 * *TakenCount) when Taken is given.
 */
static
PLOAD_IMPORTS
MiTakeSessionImports(
    _In_ PLOAD_IMPORTS Imports,
    _Out_opt_ PLDR_DATA_TABLE_ENTRY *Taken,
    _Out_opt_ PULONG TakenCount)
{
    PLDR_DATA_TABLE_ENTRY Single;
    ULONG i, j, Count;

    if (TakenCount) *TakenCount = 0;
    if (!Imports || (Imports == MM_SYSLDR_NO_IMPORTS) || (Imports == MM_SYSLDR_BOOT_LOADED))
        return Imports;

    if ((ULONG_PTR)Imports & MM_SYSLDR_SINGLE_ENTRY)
    {
        Single = (PVOID)((ULONG_PTR)Imports & ~MM_SYSLDR_SINGLE_ENTRY);
        if (!MiIsSessionImage(Single))
            return Imports;
        if (Taken)
        {
            Taken[0] = Single;
            *TakenCount = 1;
        }
        return MM_SYSLDR_NO_IMPORTS;
    }

    /* Every entry is read before any is released: a release can free entries */
    Count = (ULONG)Imports->Count;
    for (i = 0, j = 0; i < Count; i++)
    {
        Single = Imports->Entry[i];
        if (!Single) break;
        Imports->Entry[i] = NULL;
        if (MiIsSessionImage(Single))
        {
            if (Taken) Taken[(*TakenCount)++] = Single;
        }
        else
        {
            Imports->Entry[j++] = Single;
        }
    }
    return Imports;
}

/* The count of entries of an import list, for the array MiTakeSessionImports fills */
static
ULONG
MiImportListCount(
    _In_ PLOAD_IMPORTS Imports)
{
    if (!Imports || (Imports == MM_SYSLDR_NO_IMPORTS) || (Imports == MM_SYSLDR_BOOT_LOADED))
        return 0;
    if ((ULONG_PTR)Imports & MM_SYSLDR_SINGLE_ENTRY)
        return 1;
    return (ULONG)Imports->Count;
}

/* A failed load: the current session's references to the session images of its import list go */
PLOAD_IMPORTS
NTAPI
MiReleaseSessionImports(
    _In_ PLOAD_IMPORTS Imports)
{
    PLDR_DATA_TABLE_ENTRY *Taken;
    ULONG Count = MiImportListCount(Imports), TakenCount;

    if (!Count) return Imports;
    Taken = ExAllocatePoolWithTag(PagedPool, Count * sizeof(PVOID), TAG_SESSION_IMAGE);
    if (!Taken)
    {
        /* Without memory the references stay (the images stay loaded): no entry is read after a release */
        DPRINT1("Session imports kept: no memory\n");
        return MiTakeSessionImports(Imports, NULL, NULL);
    }
    Imports = MiTakeSessionImports(Imports, Taken, &TakenCount);
    MiForEachSessionImport(Taken, TakenCount, FALSE, MAXULONG, NULL);
    ExFreePoolWithTag(Taken, TAG_SESSION_IMAGE);
    return Imports;
}

/*
 * Test hook for kernel tests (an export, found through MmGetSystemRoutineAddress): loads an image of
 * \SystemRoot\ as a session image in the current session, or drops one load of it.
 * Not available unless NitroSessions is set.
 */
NTSTATUS
NTAPI
NitroMmLoadSessionImageForTest(
    _In_ PUNICODE_STRING FileName,
    _Out_ PVOID *ImageHandle,
    _Out_ PVOID *ImageBase)
{
    static const UNICODE_STRING Root = RTL_CONSTANT_STRING(L"\\SystemRoot\\");
    UNICODE_STRING Prefix;

    if (!MmNitroSessions) return STATUS_NOT_SUPPORTED;
    if (!FileName || (FileName->Length <= Root.Length)) return STATUS_INVALID_PARAMETER;

    Prefix = *FileName;
    Prefix.Length = Root.Length;
    if (!RtlEqualUnicodeString(&Prefix, &Root, TRUE)) return STATUS_INVALID_PARAMETER;

    return MmLoadSystemImage(FileName, NULL, NULL, 1, ImageHandle, ImageBase);
}

NTSTATUS
NTAPI
NitroMmUnloadSessionImageForTest(
    _In_ PVOID ImageHandle)
{
    if (!MmNitroSessions) return STATUS_NOT_SUPPORTED;
    if (!MiIsSessionImage(ImageHandle)) return STATUS_INVALID_PARAMETER;
    return MmUnloadSystemImage(ImageHandle);
}
