/*
 * PROJECT:     ReactOS virtio-gpu 2D miniport (nitro / GFX-02)
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     virtio transport bring-up, virtio-gpu 2D protocol, scanout backing
 *              and the flush pump. This TU lives in the ntddk/virtio world and
 *              reaches VideoPort services only through the scalar virtgpu_vpwrap.h
 *              bridge (implemented in virtgpump.c).
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include "osdep.h"           /* pulls ntddk.h + u8/u16/u32/u64/bool */
#include "virtio_pci.h"
#include "VirtIO.h"
#include "virtio_ring.h"
#include "kdebugprint.h"
#include "virtio_gpu.h"
#include "virtgpu_vpwrap.h"
#include "virtgpump.h"

#ifndef VIRTIO_F_VERSION_1
#define VIRTIO_F_VERSION_1 32
#endif

/* virtio lib debug hooks (required symbols; logging disabled) */
int virtioDebugLevel = 0;
int bDebugPrint = 0;
static void VgpuVirtioDbg(const char *fmt, ...) { UNREFERENCED_PARAMETER(fmt); }
tDebugPrintFunc VirtioDebugPrintProc = VgpuVirtioDbg;

#define VGLOG(...) ((void)0)

#define VGPU_FLUSH_INTERVAL_100NS  (-160000LL)   /* ~16 ms */
#define VGPU_CMD_BUF_SIZE          4096
#define VGPU_MAX_MODES             64
#define VGPU_CMD_TIMEOUT_MS        5000
#define VGPU_CMD_TOKEN             ((void*)(ULONG_PTR)1)

typedef struct _VGPU_MODE { USHORT w; USHORT h; } VGPU_MODE;

typedef struct _VGPU_CORE
{
    void             *Ext;            /* miniport HwDeviceExtension */
    VirtIODevice      VDev;
    struct virtqueue *ControlQ;
    struct virtqueue *CursorQ;

    PVOID             CmdVa;
    PHYSICAL_ADDRESS  CmdPa;
    PVOID             RespVa;
    PHYSICAL_ADDRESS  RespPa;

    /* The frame buffer is the backing of every mode: allocated once, for the largest mode, and kept
       for the life of the device, like the memory of a real adapter. The display driver maps it once
       and keeps drawing into that view across mode sets, so it must never move or be freed while
       the device can be used. */
    PVOID             FbVa;
    PHYSICAL_ADDRESS  FbPa;
    ULONG             FbSize;
    ULONG             Width;
    ULONG             Height;
    ULONG             Stride;

    ULONG             ResourceId;      /* current scanout resource (0 = none) */
    ULONG             NextResourceId;
    ULONG             NumScanouts;

    ULONG             ModeCount;
    VGPU_MODE         Modes[VGPU_MAX_MODES];
    ULONG             DefaultModeIndex;

    HANDLE            FlushThreadHandle;
    PVOID             FlushThreadObj;
    KEVENT            StopEvent;
    KMUTEX            CtrlMutex;
    volatile LONG     FlushEnabled;
    volatile LONG     Broken;          /* the device stopped answering: reset, never used again */

    volatile LONG     DirtyValid;
    ULONG             Dx, Dy, Dw, Dh;
} VGPU_CORE;

/* Candidate modes; filtered by host caps and an 8 MB contiguous-backing budget. */
static const VGPU_MODE g_Candidates[] = {
    {  640, 480 }, {  800, 600 }, { 1024, 600 }, { 1024, 768 },
    { 1152, 864 }, { 1280, 720 }, { 1280, 768 }, { 1280, 1024 },
    { 1366, 768 }, { 1440, 900 }, { 1600, 900 }, { 1600, 1200 },
    { 1680, 1050 }, { 1920, 1080 },
};
#define VGPU_BACKING_BUDGET (8u * 1024u * 1024u)

/* ---- VirtIOSystemOps callbacks ------------------------------------------- */

static u8   sys_r8 (ULONG_PTR r)            { return Vpw_Read8 ((void*)r); }
static u16  sys_r16(ULONG_PTR r)            { return Vpw_Read16((void*)r); }
static u32  sys_r32(ULONG_PTR r)            { return Vpw_Read32((void*)r); }
static void sys_w8 (ULONG_PTR r, u8  v)     { Vpw_Write8 ((void*)r, v); }
static void sys_w16(ULONG_PTR r, u16 v)     { Vpw_Write16((void*)r, v); }
static void sys_w32(ULONG_PTR r, u32 v)     { Vpw_Write32((void*)r, v); }

static void *sys_alloc_contig(void *ctx, size_t size)
{
    PHYSICAL_ADDRESS hi; PVOID p;
    UNREFERENCED_PARAMETER(ctx);
    hi.QuadPart = (LONGLONG)~0ULL;
    p = MmAllocateContiguousMemory(size, hi);
    if (p) RtlZeroMemory(p, size);
    return p;
}
static void sys_free_contig(void *ctx, void *va)
{
    UNREFERENCED_PARAMETER(ctx);
    if (va) MmFreeContiguousMemory(va);
}
static ULONGLONG sys_get_pa(void *ctx, void *va)
{
    UNREFERENCED_PARAMETER(ctx);
    return (ULONGLONG)MmGetPhysicalAddress(va).QuadPart;
}
static void *sys_alloc_np(void *ctx, size_t size)
{
    return Vpw_AllocPool(((VGPU_CORE*)ctx)->Ext, (unsigned long)size);
}
static void sys_free_np(void *ctx, void *addr)
{
    Vpw_FreePool(((VGPU_CORE*)ctx)->Ext, addr);
}
static int sys_pci_r8 (void *ctx, int where, u8  *v) { return Vpw_PciReadConfig(((VGPU_CORE*)ctx)->Ext, where, v, 1); }
static int sys_pci_r16(void *ctx, int where, u16 *v) { return Vpw_PciReadConfig(((VGPU_CORE*)ctx)->Ext, where, v, 2); }
static int sys_pci_r32(void *ctx, int where, u32 *v) { return Vpw_PciReadConfig(((VGPU_CORE*)ctx)->Ext, where, v, 4); }

static size_t sys_res_len(void *ctx, int bar)
{
    unsigned long long ph; unsigned long ln = 0; int io;
    int rc = Vpw_GetBar(((VGPU_CORE*)ctx)->Ext, bar, &ph, &ln, &io);
    if (rc != 0) return 0;
    return (size_t)ln;
}
static void *sys_map_range(void *ctx, int bar, size_t offset, size_t maxlen)
{
    unsigned long long ph; unsigned long ln; int io; size_t avail, maplen;
    if (Vpw_GetBar(((VGPU_CORE*)ctx)->Ext, bar, &ph, &ln, &io) != 0) return NULL;
    if (offset >= ln) return NULL;
    avail = (size_t)ln - offset;
    maplen = (maxlen && maxlen < avail) ? maxlen : avail;
    return Vpw_MapDevice(((VGPU_CORE*)ctx)->Ext, ph + offset, (unsigned long)maplen, io);
}
static u16  sys_get_msix(void *ctx, int queue) { UNREFERENCED_PARAMETER(ctx); UNREFERENCED_PARAMETER(queue); return VIRTIO_MSI_NO_VECTOR; }
static void sys_sleep(void *ctx, unsigned int msecs) { UNREFERENCED_PARAMETER(ctx); while (msecs--) Vpw_Stall(1000); }

static const VirtIOSystemOps VgpuSystemOps =
{
    sys_r8, sys_r16, sys_r32, sys_w8, sys_w16, sys_w32,
    sys_alloc_contig, sys_free_contig, sys_get_pa,
    sys_alloc_np, sys_free_np,
    sys_pci_r8, sys_pci_r16, sys_pci_r32,
    sys_res_len, sys_map_range,
    sys_get_msix, sys_sleep
};

/* ---- control queue command submission (caller holds CtrlMutex) ----------- */

/*
 * The device owns a buffer from the moment it is made available until it comes back in the used
 * ring (VIRTIO 1.2 cs01, 2.7.13 and 2.7.14). One command is in flight at a time and the command and
 * response buffers are reused, so a command the device did not complete must never be followed by
 * another: on a timeout the device is reset (2.4.1: once its status reads 0 it does not interact
 * with the queues any more) and not used again.
 */
static void VgpuMarkBroken(VGPU_CORE *c, const char *why)
{
    if (InterlockedExchange(&c->Broken, 1) == 0)
    {
        c->FlushEnabled = 0;
        virtio_device_reset(&c->VDev);
        Vpw_Log(0, why, 0, 0);
    }
}

static int VgpuSubmit(VGPU_CORE *c, ULONG cmdLen, ULONG respLen)
{
    struct VirtIOBufferDescriptor sg[2];
    void *done; unsigned int len = 0; int ret;
    ULONG spin, waitedMs = 0;
    LARGE_INTEGER delay;

    if (c->Broken) return -1;
    if (cmdLen == 0 || cmdLen > VGPU_CMD_BUF_SIZE ||
        respLen < sizeof(VIRTIO_GPU_CTRL_HDR) || respLen > VGPU_CMD_BUF_SIZE)
        return -1;

    /* A response the device does not write must not read as the answer to an earlier command */
    RtlZeroMemory(c->RespVa, respLen);

    sg[0].physAddr = c->CmdPa;  sg[0].length = cmdLen;
    sg[1].physAddr = c->RespPa; sg[1].length = respLen;

    ret = virtqueue_add_buf(c->ControlQ, sg, 1, 1, VGPU_CMD_TOKEN, NULL, 0);
    if (ret < 0) return -1;
    virtqueue_kick(c->ControlQ);

    /* QEMU answers a 2D command within microseconds: spin briefly, then sleep between polls */
    for (spin = 0; ; spin++)
    {
        done = virtqueue_get_buf(c->ControlQ, &len);
        if (done) break;
        if (spin < 500)
        {
            Vpw_Stall(2);
            continue;
        }
        if (waitedMs >= VGPU_CMD_TIMEOUT_MS)
        {
            VgpuMarkBroken(c, "virtgpu: the device did not complete a command: reset, not used any more\n");
            return -2;
        }
        delay.QuadPart = -10000LL;    /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        waitedMs++;
    }

    /* Only one buffer is outstanding, so the device can only return that one (the ring code drops
       any other id). Bytes beyond the reported length are not to be used (2.7.8.3): the length
       must cover a header, and more than the response buffer is a device error */
    if (done != VGPU_CMD_TOKEN || len < sizeof(VIRTIO_GPU_CTRL_HDR) || len > respLen)
    {
        Vpw_Log(0, "virtgpu: invalid completion, %u response bytes\n", (ULONGLONG)len, 0);
        return -1;
    }
    return 0;
}

static ULONG VgpuRespType(VGPU_CORE *c)
{
    return ((VIRTIO_GPU_CTRL_HDR*)c->RespVa)->type;
}

static int VgpuGetDisplayInfo(VGPU_CORE *c, ULONG *prefW, ULONG *prefH)
{
    VIRTIO_GPU_CTRL_HDR *cmd = (VIRTIO_GPU_CTRL_HDR*)c->CmdVa;
    VIRTIO_GPU_RESP_DISPLAY_INFO *resp = (VIRTIO_GPU_RESP_DISPLAY_INFO*)c->RespVa;

    RtlZeroMemory(cmd, sizeof(*cmd));
    cmd->type = VIRTIO_GPU_CMD_GET_DISPLAY_INFO;
    if (VgpuSubmit(c, sizeof(*cmd), sizeof(*resp)) != 0) return -1;
    if (resp->hdr.type != VIRTIO_GPU_RESP_OK_DISPLAY_INFO) return -1;
    if (resp->pmodes[0].enabled && resp->pmodes[0].r.width && resp->pmodes[0].r.height)
    {
        *prefW = resp->pmodes[0].r.width;
        *prefH = resp->pmodes[0].r.height;
        return 0;
    }
    return 1;
}

static int VgpuCreate2D(VGPU_CORE *c, ULONG resId, ULONG w, ULONG h)
{
    VIRTIO_GPU_RESOURCE_CREATE_2D *cmd = (VIRTIO_GPU_RESOURCE_CREATE_2D*)c->CmdVa;
    RtlZeroMemory(cmd, sizeof(*cmd));
    cmd->hdr.type = VIRTIO_GPU_CMD_RESOURCE_CREATE_2D;
    cmd->resource_id = resId;
    cmd->format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
    cmd->width = w;
    cmd->height = h;
    if (VgpuSubmit(c, sizeof(*cmd), sizeof(VIRTIO_GPU_CTRL_HDR)) != 0) return -1;
    return (VgpuRespType(c) == VIRTIO_GPU_RESP_OK_NODATA) ? 0 : -1;
}

static int VgpuAttachBacking(VGPU_CORE *c, ULONG resId, ULONGLONG pa, ULONG size)
{
    VIRTIO_GPU_RESOURCE_ATTACH_BACKING *cmd = (VIRTIO_GPU_RESOURCE_ATTACH_BACKING*)c->CmdVa;
    VIRTIO_GPU_MEM_ENTRY *me = (VIRTIO_GPU_MEM_ENTRY*)(cmd + 1);
    ULONG total = sizeof(*cmd) + sizeof(*me);
    RtlZeroMemory(cmd, total);
    cmd->hdr.type = VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING;
    cmd->resource_id = resId;
    cmd->nr_entries = 1;
    me->addr = pa;
    me->length = size;
    if (VgpuSubmit(c, total, sizeof(VIRTIO_GPU_CTRL_HDR)) != 0) return -1;
    return (VgpuRespType(c) == VIRTIO_GPU_RESP_OK_NODATA) ? 0 : -1;
}

static int VgpuSetScanout(VGPU_CORE *c, ULONG scanout, ULONG resId, ULONG w, ULONG h)
{
    VIRTIO_GPU_SET_SCANOUT *cmd = (VIRTIO_GPU_SET_SCANOUT*)c->CmdVa;
    RtlZeroMemory(cmd, sizeof(*cmd));
    cmd->hdr.type = VIRTIO_GPU_CMD_SET_SCANOUT;
    cmd->r.x = 0; cmd->r.y = 0; cmd->r.width = w; cmd->r.height = h;
    cmd->scanout_id = scanout;
    cmd->resource_id = resId;
    if (VgpuSubmit(c, sizeof(*cmd), sizeof(VIRTIO_GPU_CTRL_HDR)) != 0) return -1;
    return (VgpuRespType(c) == VIRTIO_GPU_RESP_OK_NODATA) ? 0 : -1;
}

static int VgpuUnref(VGPU_CORE *c, ULONG resId)
{
    VIRTIO_GPU_RESOURCE_UNREF *cmd = (VIRTIO_GPU_RESOURCE_UNREF*)c->CmdVa;
    RtlZeroMemory(cmd, sizeof(*cmd));
    cmd->hdr.type = VIRTIO_GPU_CMD_RESOURCE_UNREF;
    cmd->resource_id = resId;
    if (VgpuSubmit(c, sizeof(*cmd), sizeof(VIRTIO_GPU_CTRL_HDR)) != 0) return -1;
    return (VgpuRespType(c) == VIRTIO_GPU_RESP_OK_NODATA) ? 0 : -1;
}

static int VgpuTransferAndFlush(VGPU_CORE *c, ULONG x, ULONG y, ULONG w, ULONG h)
{
    VIRTIO_GPU_TRANSFER_TO_HOST_2D *t = (VIRTIO_GPU_TRANSFER_TO_HOST_2D*)c->CmdVa;
    VIRTIO_GPU_RESOURCE_FLUSH *f = (VIRTIO_GPU_RESOURCE_FLUSH*)c->CmdVa;

    RtlZeroMemory(t, sizeof(*t));
    t->hdr.type = VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D;
    t->r.x = x; t->r.y = y; t->r.width = w; t->r.height = h;
    t->offset = (ULONGLONG)y * c->Stride + (ULONGLONG)x * 4;
    t->resource_id = c->ResourceId;
    if (VgpuSubmit(c, sizeof(*t), sizeof(VIRTIO_GPU_CTRL_HDR)) != 0) return -1;
    if (VgpuRespType(c) != VIRTIO_GPU_RESP_OK_NODATA) return -1;

    RtlZeroMemory(f, sizeof(*f));
    f->hdr.type = VIRTIO_GPU_CMD_RESOURCE_FLUSH;
    f->r.x = x; f->r.y = y; f->r.width = w; f->r.height = h;
    f->resource_id = c->ResourceId;
    if (VgpuSubmit(c, sizeof(*f), sizeof(VIRTIO_GPU_CTRL_HDR)) != 0) return -1;
    return (VgpuRespType(c) == VIRTIO_GPU_RESP_OK_NODATA) ? 0 : -1;
}

/* ---- flush pump ---------------------------------------------------------- */

/*
 * The driver polls and connects no interrupt, but without MSI-X the device still raises its INTx
 * line and sets the ISR status for used buffers and for configuration changes (VIRTIO 1.2 cs01,
 * 4.1.5.3 and 4.1.5.4), such as a display event when the viewer window is resized (5.7.4.2). The
 * line stays asserted until the ISR status is read (4.1.4.5), which would leave a shared interrupt
 * line held for good. Read it on every tick and clear the events it reports (events_clear, 5.7.4.1).
 * Caller holds CtrlMutex.
 */
static void VgpuAckInterrupt(VGPU_CORE *c)
{
    ULONG events = 0;

    if (c->Broken) return;
    if (virtio_read_isr_status(&c->VDev) & VIRTIO_PCI_ISR_CONFIG)
    {
        virtio_get_config(&c->VDev, FIELD_OFFSET(VIRTIO_GPU_CONFIG, events_read), &events, sizeof(events));
        if (events)
            virtio_set_config(&c->VDev, FIELD_OFFSET(VIRTIO_GPU_CONFIG, events_clear), &events, sizeof(events));
    }
}

static VOID NTAPI VgpuFlushThread(PVOID arg)
{
    VGPU_CORE *c = (VGPU_CORE*)arg;
    LARGE_INTEGER interval;
    NTSTATUS st;

    for (;;)
    {
        interval.QuadPart = VGPU_FLUSH_INTERVAL_100NS;
        st = KeWaitForSingleObject(&c->StopEvent, Executive, KernelMode, FALSE, &interval);
        if (st == STATUS_SUCCESS) break;          /* stop signalled */

        if (c->Broken) continue;

        KeWaitForSingleObject(&c->CtrlMutex, Executive, KernelMode, FALSE, NULL);
        VgpuAckInterrupt(c);
        if (c->FlushEnabled && c->ResourceId && !c->Broken)
        {
            ULONG x = 0, y = 0, w = c->Width, h = c->Height;
            if (InterlockedCompareExchange(&c->DirtyValid, 0, 1) == 1 &&
                c->Dx < c->Width && c->Dy < c->Height &&
                c->Dw && c->Dh && c->Dw <= c->Width - c->Dx && c->Dh <= c->Height - c->Dy)
            {
                /* only a rectangle inside the current mode */
                x = c->Dx; y = c->Dy; w = c->Dw; h = c->Dh;
            }
            VgpuTransferAndFlush(c, x, y, w, h);
        }
        KeReleaseMutex(&c->CtrlMutex, FALSE);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* ---- mode list ----------------------------------------------------------- */

/* The frame buffer for the largest candidate mode that fits the budget, or the largest one the
   system can give contiguously */
static int VgpuAllocFramebuffer(VGPU_CORE *c)
{
    PHYSICAL_ADDRESS hi;
    ULONG i, want, limit = VGPU_BACKING_BUDGET;

    hi.QuadPart = (LONGLONG)~0ULL;
    for (;;)
    {
        want = 0;
        for (i = 0; i < ARRAYSIZE(g_Candidates); i++)
        {
            ULONG sz = (ULONG)g_Candidates[i].w * g_Candidates[i].h * 4;
            if (sz <= limit && sz > want) want = sz;
        }
        if (want == 0) return -1;
        want = (want + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        c->FbVa = MmAllocateContiguousMemory(want, hi);
        if (c->FbVa) break;
        Vpw_Log(0, "virtgpu: no contiguous frame buffer of %u bytes, trying a smaller one\n", (ULONGLONG)want, 0);
        limit = want - 1;
    }
    RtlZeroMemory(c->FbVa, want);
    c->FbPa = MmGetPhysicalAddress(c->FbVa);
    c->FbSize = want;
    return 0;
}

static void VgpuBuildModes(VGPU_CORE *c, ULONG prefW, ULONG prefH)
{
    ULONG i;
    c->ModeCount = 0;
    c->DefaultModeIndex = 0;
    for (i = 0; i < ARRAYSIZE(g_Candidates) && c->ModeCount < VGPU_MAX_MODES; i++)
    {
        ULONG w = g_Candidates[i].w, h = g_Candidates[i].h;
        if ((ULONGLONG)w * h * 4 > c->FbSize) continue;
        c->Modes[c->ModeCount] = g_Candidates[i];
        if (prefW && prefH && w == prefW && h == prefH)
            c->DefaultModeIndex = c->ModeCount;
        else if ((prefW == 0 || prefH == 0) && w == 1024 && h == 768)
            c->DefaultModeIndex = c->ModeCount;
        c->ModeCount++;
    }
    /* VgpuAllocFramebuffer sized the frame buffer for at least one candidate, so the list is never empty */
}

/* ---- public core API ----------------------------------------------------- */

int VgpuCreate(void *ext, void **pCtx)
{
    VGPU_CORE *c;
    NTSTATUS st;
    PHYSICAL_ADDRESS hi;
    u64 features, want;
    ULONG prefW = 0, prefH = 0;
    BOOLEAN deviceUp = FALSE;

    c = (VGPU_CORE*)Vpw_AllocPool(ext, sizeof(VGPU_CORE));
    if (!c) return -1;
    RtlZeroMemory(c, sizeof(VGPU_CORE));
    c->Ext = ext;
    c->NextResourceId = 1;
    KeInitializeMutex(&c->CtrlMutex, 0);
    KeInitializeEvent(&c->StopEvent, NotificationEvent, FALSE);

    hi.QuadPart = (LONGLONG)~0ULL;
    c->CmdVa  = MmAllocateContiguousMemory(VGPU_CMD_BUF_SIZE, hi);
    c->RespVa = MmAllocateContiguousMemory(VGPU_CMD_BUF_SIZE, hi);
    if (!c->CmdVa || !c->RespVa) { Vpw_Log(0, "virtgpu: cmd buf alloc failed\n", 0, 0); goto fail; }
    RtlZeroMemory(c->CmdVa, VGPU_CMD_BUF_SIZE);
    RtlZeroMemory(c->RespVa, VGPU_CMD_BUF_SIZE);
    c->CmdPa  = MmGetPhysicalAddress(c->CmdVa);
    c->RespPa = MmGetPhysicalAddress(c->RespVa);

    st = virtio_device_initialize(&c->VDev, &VgpuSystemOps, c, FALSE);
    if (!NT_SUCCESS(st)) { Vpw_Log(0, "virtgpu: virtio init 0x%x\n", (ULONGLONG)st, 0); goto fail; }
    deviceUp = TRUE;

    VGLOG("virtio_device_initialize st=0x%x\n", st);
    features = virtio_get_features(&c->VDev);
    want = features & (1ULL << VIRTIO_F_VERSION_1);
    st = virtio_set_features(&c->VDev, want);
    if (!NT_SUCCESS(st)) { Vpw_Log(0, "virtgpu: set_features 0x%x\n", (ULONGLONG)st, 0); goto fail; }

    VGLOG("features=0x%I64x set_features st=0x%x\n", features, st);
    st = virtio_reserve_queue_memory(&c->VDev, 2);
    if (!NT_SUCCESS(st)) { Vpw_Log(0, "virtgpu: reserve_queue 0x%x\n", (ULONGLONG)st, 0); goto fail; }
    st = virtio_find_queue(&c->VDev, 0, &c->ControlQ);
    if (!NT_SUCCESS(st) || !c->ControlQ) { Vpw_Log(0, "virtgpu: controlq 0x%x\n", (ULONGLONG)st, 0); goto fail; }
    (void)virtio_find_queue(&c->VDev, 1, &c->CursorQ);   /* optional */
    virtqueue_disable_cb(c->ControlQ);
    if (c->CursorQ) virtqueue_disable_cb(c->CursorQ);

    VGLOG("controlq=%p cursorq=%p ready\n", c->ControlQ, c->CursorQ);
    virtio_device_ready(&c->VDev);

    {
        ULONG numScanouts = 0;
        /* num_scanouts is at offset 8 in virtio_gpu_config (4-byte read); 1 to 16 (5.7.4.1) */
        virtio_get_config(&c->VDev, 8, &numScanouts, sizeof(numScanouts));
        c->NumScanouts = (numScanouts >= 1 && numScanouts <= VIRTIO_GPU_MAX_SCANOUTS) ? numScanouts : 1;
    }

    if (VgpuAllocFramebuffer(c) != 0) { Vpw_Log(0, "virtgpu: no frame buffer\n", 0, 0); goto fail; }

    KeWaitForSingleObject(&c->CtrlMutex, Executive, KernelMode, FALSE, NULL);
    (void)VgpuGetDisplayInfo(c, &prefW, &prefH);
    KeReleaseMutex(&c->CtrlMutex, FALSE);
    if (c->Broken) goto fail;

    VgpuBuildModes(c, prefW, prefH);
    Vpw_Log(1, "virtgpu: ready, scanouts=%d modes avail\n", (ULONGLONG)c->NumScanouts, (ULONGLONG)c->ModeCount);

    st = PsCreateSystemThread(&c->FlushThreadHandle, THREAD_ALL_ACCESS, NULL,
                              NULL, NULL, VgpuFlushThread, c);
    if (!NT_SUCCESS(st)) { Vpw_Log(0, "virtgpu: flush thread 0x%x\n", (ULONGLONG)st, 0); goto fail; }
    (void)ObReferenceObjectByHandle(c->FlushThreadHandle, THREAD_ALL_ACCESS, NULL,
                                    KernelMode, &c->FlushThreadObj, NULL);

    VGLOG("VgpuCreate OK scanouts=%d modes=%d default=%d\n", c->NumScanouts, c->ModeCount, c->DefaultModeIndex);
    *pCtx = c;
    return 0;

fail:
    /* Nothing the device can reach is freed before the device is reset */
    if (deviceUp)
    {
        virtio_device_reset(&c->VDev);
        virtio_delete_queues(&c->VDev);
        virtio_device_shutdown(&c->VDev);
    }
    if (c->FbVa)   MmFreeContiguousMemory(c->FbVa);
    if (c->CmdVa)  MmFreeContiguousMemory(c->CmdVa);
    if (c->RespVa) MmFreeContiguousMemory(c->RespVa);
    Vpw_FreePool(ext, c);
    return -1;
}

void VgpuDestroy(void *ctx)
{
    VGPU_CORE *c = (VGPU_CORE*)ctx;
    if (!c) return;

    c->FlushEnabled = 0;
    KeSetEvent(&c->StopEvent, 0, FALSE);
    if (c->FlushThreadObj)
    {
        KeWaitForSingleObject(c->FlushThreadObj, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(c->FlushThreadObj);
    }
    if (c->FlushThreadHandle) ZwClose(c->FlushThreadHandle);

    KeWaitForSingleObject(&c->CtrlMutex, Executive, KernelMode, FALSE, NULL);
    if (c->ResourceId)
    {
        VgpuSetScanout(c, 0, 0, 0, 0);
        VgpuUnref(c, c->ResourceId);
        c->ResourceId = 0;
    }
    KeReleaseMutex(&c->CtrlMutex, FALSE);

    /* The device reads the frame buffer and writes the queues and responses until it is reset */
    virtio_device_reset(&c->VDev);
    virtio_delete_queues(&c->VDev);
    virtio_device_shutdown(&c->VDev);
    if (c->FbVa)   MmFreeContiguousMemory(c->FbVa);
    if (c->CmdVa)  MmFreeContiguousMemory(c->CmdVa);
    if (c->RespVa) MmFreeContiguousMemory(c->RespVa);
    Vpw_FreePool(c->Ext, c);
}

unsigned long VgpuGetModeCount(void *ctx)
{
    return ((VGPU_CORE*)ctx)->ModeCount;
}
int VgpuGetMode(void *ctx, unsigned long index, unsigned long *w, unsigned long *h)
{
    VGPU_CORE *c = (VGPU_CORE*)ctx;
    if (index >= c->ModeCount) return -1;
    *w = c->Modes[index].w;
    *h = c->Modes[index].h;
    return 0;
}
unsigned long VgpuGetDefaultModeIndex(void *ctx)
{
    return ((VGPU_CORE*)ctx)->DefaultModeIndex;
}

/*
 * A mode set changes only the host resource that is scanned out; its backing is always the one
 * frame buffer (VIRTIO 1.2 cs01, 5.7.6.1). The new resource is created, given the frame buffer
 * and scanned out before the old one is released (the flip of 5.7.6.3), so a failure leaves the
 * old mode on the screen. The display driver sets its mode again after every mode change and
 * after a reset: the mode that is already set is then only presented again.
 */
int VgpuSetModeByIndex(void *ctx, unsigned long index)
{
    VGPU_CORE *c = (VGPU_CORE*)ctx;
    ULONG w, h, stride, size, resId, oldId;
    int rc = -1;

    if (index >= c->ModeCount) return -1;
    VGLOG("SetModeByIndex idx=%d\n", index);
    w = c->Modes[index].w; h = c->Modes[index].h;
    stride = w * 4; size = stride * h;
    if (size > c->FbSize) return -1;

    KeWaitForSingleObject(&c->CtrlMutex, Executive, KernelMode, FALSE, NULL);
    if (c->Broken)
    {
        /* The device was reset and shows nothing any more. The frame buffer is still memory the
           display driver may draw into, and win32k asserts a mode until the driver accepts it:
           accept the mode that is already set, refuse any other */
        if (c->Width == w && c->Height == h) rc = 0;
        goto done;
    }

    if (c->ResourceId && c->Width == w && c->Height == h)
    {
        VgpuTransferAndFlush(c, 0, 0, w, h);
        c->FlushEnabled = !c->Broken;
        rc = 0;
        goto done;
    }

    c->FlushEnabled = 0;
    resId = c->NextResourceId++;
    if (resId == 0 || resId == c->ResourceId) resId = c->NextResourceId++;   /* 0 means no resource */

    if (VgpuCreate2D(c, resId, w, h) != 0) { Vpw_Log(0, "virtgpu: create2d failed\n", 0, 0); goto restore; }
    if (VgpuAttachBacking(c, resId, (ULONGLONG)c->FbPa.QuadPart, size) != 0)
    {
        Vpw_Log(0, "virtgpu: attach failed\n", 0, 0);
        VgpuUnref(c, resId);
        goto restore;
    }
    if (VgpuSetScanout(c, 0, resId, w, h) != 0)
    {
        Vpw_Log(0, "virtgpu: scanout failed\n", 0, 0);
        VgpuUnref(c, resId);
        goto restore;
    }

    oldId = c->ResourceId;
    c->ResourceId = resId;
    c->Width = w; c->Height = h; c->Stride = stride;
    InterlockedExchange(&c->DirtyValid, 0);
    if (oldId) VgpuUnref(c, oldId);
    RtlZeroMemory(c->FbVa, size);   /* a new mode starts black; the display driver draws it next */
    VGLOG("SetMode %dx%d resId=%d fbPa=0x%I64x OK\n", w, h, resId, (ULONGLONG)c->FbPa.QuadPart);
    VgpuTransferAndFlush(c, 0, 0, w, h);
    if (!c->Broken)
    {
        c->FlushEnabled = 1;
        Vpw_Log(1, "virtgpu: mode set %dx%d\n", (ULONGLONG)w, (ULONGLONG)h);
        rc = 0;
    }
    goto done;

restore:
    /* The old resource is still scanned out: keep presenting it */
    if (c->ResourceId && !c->Broken) c->FlushEnabled = 1;

done:
    KeReleaseMutex(&c->CtrlMutex, FALSE);
    return rc;
}

int VgpuGetFramebuffer(void *ctx, unsigned long long *phys, unsigned long *len)
{
    VGPU_CORE *c = (VGPU_CORE*)ctx;
    if (!c->FbVa) return -1;
    *phys = (unsigned long long)c->FbPa.QuadPart;
    *len  = c->FbSize;
    return 0;
}

void VgpuFlushRect(void *ctx, unsigned long x, unsigned long y, unsigned long w, unsigned long h)
{
    VGPU_CORE *c = (VGPU_CORE*)ctx;
    c->Dx = x; c->Dy = y; c->Dw = w; c->Dh = h;
    InterlockedExchange(&c->DirtyValid, 1);
}
