#include <lwip/mem.h>

#ifndef LWIP_TAG
    #define LWIP_TAG 'PIwl'
#endif

/* A TCP segment of a loopback connection is a pbuf of 16 KB, and lwIP allocates one for every segment
 * it sends and another for the copy that goes to the loopback queue, and frees them at the
 * acknowledgement and at the read. Several pages of nonpaged pool each time: system PTEs to reserve and
 * release under one lock, a page allocation and a TLB flush (on a virtual machine an inter-processor
 * interrupt that wakes a halted processor). Blocks of BIG_MIN to BIG_MAX bytes are therefore rounded up
 * to a multiple of BIG_STEP, and the freed ones are kept (at most BIG_KEEP of each size) for the next
 * request of that size. Every block has a header that says which size it is. */
#define BIG_MIN     8192
#define BIG_MAX     20480
#define BIG_STEP    2048
#define BIG_CLASSES (((BIG_MAX) - (BIG_MIN)) / (BIG_STEP) + 1)
#define BIG_KEEP    32
#define HDR_SIZE    16
#define HDR_PLAIN   0xFFFFFFFFUL
#define HDR_MAGIC   'blwl'

typedef struct _LWIP_BLOCK_HDR
{
    ULONG Class;
    ULONG Magic;
    ULONGLONG Reserved;
} LWIP_BLOCK_HDR, *PLWIP_BLOCK_HDR;

C_ASSERT(sizeof(LWIP_BLOCK_HDR) == HDR_SIZE);

/* A freed block keeps its header; the list entry lives in the user part */
static SLIST_HEADER BigFree[BIG_CLASSES];
static KSPIN_LOCK BigLock;
static volatile LONG BigReady;

static VOID
BigInit(VOID)
{
    ULONG i;

    if (InterlockedCompareExchange(&BigReady, 1, 0) != 0)
    {
        /* Another thread is initialising: it is quick, and nothing is cached before it is done */
        while (BigReady != 2)
            YieldProcessor();
        return;
    }

    for (i = 0; i < BIG_CLASSES; i++)
        InitializeSListHead(&BigFree[i]);
    KeInitializeSpinLock(&BigLock);
    InterlockedExchange(&BigReady, 2);
}

void *
malloc(mem_size_t size)
{
    PLWIP_BLOCK_HDR Hdr;
    SIZE_T Total = (SIZE_T)size + HDR_SIZE;

    if (BigReady != 2)
        BigInit();

    if (Total >= BIG_MIN && Total <= BIG_MAX)
    {
        ULONG Class = (ULONG)((Total - BIG_MIN + BIG_STEP - 1) / BIG_STEP);
        PSLIST_ENTRY Entry = ExInterlockedPopEntrySList(&BigFree[Class], &BigLock);

        if (Entry)
            return Entry;

        Hdr = ExAllocatePoolWithTag(NonPagedPool, BIG_MIN + (SIZE_T)Class * BIG_STEP, LWIP_TAG);
        if (!Hdr)
            return NULL;
        Hdr->Class = Class;
    }
    else
    {
        Hdr = ExAllocatePoolWithTag(NonPagedPool, Total, LWIP_TAG);
        if (!Hdr)
            return NULL;
        Hdr->Class = HDR_PLAIN;
    }

    Hdr->Magic = HDR_MAGIC;
    return (PUCHAR)Hdr + HDR_SIZE;
}

void *
calloc(mem_size_t count, mem_size_t size)
{
    void *mem = malloc(count * size);

    if (!mem) return NULL;

    RtlZeroMemory(mem, count * size);

    return mem;
}

void
free(void *mem)
{
    PLWIP_BLOCK_HDR Hdr;

    if (!mem)
        return;

    Hdr = (PLWIP_BLOCK_HDR)((PUCHAR)mem - HDR_SIZE);
    ASSERT(Hdr->Magic == HDR_MAGIC);

    if (Hdr->Class != HDR_PLAIN && ExQueryDepthSList(&BigFree[Hdr->Class]) < BIG_KEEP)
    {
        ExInterlockedPushEntrySList(&BigFree[Hdr->Class], (PSLIST_ENTRY)mem, &BigLock);
        return;
    }

    ExFreePoolWithTag(Hdr, LWIP_TAG);
}

/* Gives the kept blocks back (the driver unloads) */
void
LibMemoryTrim(void)
{
    ULONG i;
    PSLIST_ENTRY Entry;

    if (BigReady != 2)
        return;

    for (i = 0; i < BIG_CLASSES; i++)
    {
        while ((Entry = ExInterlockedPopEntrySList(&BigFree[i], &BigLock)) != NULL)
            ExFreePoolWithTag((PUCHAR)Entry - HDR_SIZE, LWIP_TAG);
    }
}

/* This is only used to trim in lwIP */
void *
realloc(void *mem, size_t size)
{
    void* new_mem;

    /* realloc() with a NULL mem pointer acts like a call to malloc() */
    if (mem == NULL) {
        return malloc(size);
    }

    /* realloc() with a size 0 acts like a call to free() */
    if (size == 0) {
        free(mem);
        return NULL;
    }

    /* Allocate the new buffer first */
    new_mem = malloc(size);
    if (new_mem == NULL) {
        /* The old buffer is still intact */
        return NULL;
    }

    /* Copy the data over */
    RtlCopyMemory(new_mem, mem, size);

    /* Deallocate the old buffer */
    free(mem);

    /* Return the newly allocated block */
    return new_mem;
}
