# virtio-gpu 2D / modesetting guest KMD (XDDM) — Design Note

Ticket: GFX-02. Author: Tomas Srnka. Target: reactos-nitro (XDDM, VM-only).
Foundation for GFX-03 (3D / virgl).

## 1. Goal & scope

Drive QEMU's `virtio-gpu-pci` device from a ReactOS XDDM guest driver for:
proper (non-VGA) resolutions, a RAM-backed scanout framebuffer, and live 2D
output via virtio-gpu `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH`. 2D works on a
GPU-less host (QEMU software path). No WDDM; no 3D here (that is GFX-03).

Reuse the already-shipped `sdk/lib/drivers/virtio` modern PCI transport
(`virtio_device_initialize` / `virtio_find_queue` / `virtqueue_add_buf` /
`virtqueue_kick` / `virtqueue_get_buf`) — the same lib netkvm uses.

## 2. Why this shape

ReactOS graphics is XDDM: a kernel **video miniport** (enumerate device, set
mode, own hardware) plus a **display driver** (GDI DDI: DrvEnableSurface, blits).
The existing generic `framebuf.dll` display driver already maps a linear
framebuffer and lets GDI render into it. virtio-gpu differs from stdvga/bochs in
one crucial way: the host does NOT continuously scan out guest RAM — the guest
must *explicitly* push updates (TRANSFER_TO_HOST_2D copies the dirty rect from
the backing into the host resource, RESOURCE_FLUSH presents it).

So the only thing missing versus a plain linear-FB card is a **flush pump**.

### Flush strategy (and why a miniport thread)
- XDDM `HwTimer` fires via `IoStartTimer` at ~1 Hz — useless for a display.
- A display-driver-driven flush (hook DrvBitBlt/DrvCopyBits/DrvTextOut, report
  dirty rects via a private IOCTL) gives true dirty-rect updates but requires a
  bespoke display driver.

MVP decision: a **miniport-owned flush thread** (`PsCreateSystemThread`) that,
at ~60 Hz, issues TRANSFER_TO_HOST_2D + RESOURCE_FLUSH for the active scanout.
This makes a *live desktop work while reusing the stock `framebuf.dll` unchanged*
(much lower risk), and decouples presentation from GDI. A full-screen 1080p flush
is ~8 MB * 60 Hz host-side memcpy — trivial for QEMU.
The private flush IOCTL + dirty-rect accumulator are implemented too, so a future
hooking display driver can shrink the flush region with no miniport change.

## 3. Module layout

    win32ss/drivers/miniport/virtgpu/
      virtgpump.c      XDDM video miniport (miniport.h/video.h world)
      virtgpu_core.c   virtio + DMA + GPU protocol + flush thread (ntddk world)
      virtgpu_vpwrap.h plain-scalar bridge: core -> VideoPort services
      virtio_gpu.h     virtio-gpu 2D protocol structs/constants
      virtgpump.h      shared miniport types / core API prototypes
      virtgpump.inf / virtgpump_reg.inf / virtgpump.rc / CMakeLists.txt

Display side: reuse `framebuf.dll` (wired via InstalledDisplayDrivers), exactly
like bochsmp.

### Why two translation units
`sdk/include/ddk/miniport.h` and `ntddk.h`/`wdm.h` both define `_INTERFACE_TYPE`
etc. and cannot coexist in one TU (verified by compile). The virtio lib's
`osdep.h` pulls `ntddk.h`; the miniport DDI needs `miniport.h`. Split:
- `virtgpump.c`: miniport DDI only. Device extension holds an opaque `PVOID GpuCtx`.
- `virtgpu_core.c`: ntddk + virtio only. Calls VideoPort services through thin
  wrappers in `virtgpu_vpwrap.h` that pass only scalar types (so neither world's
  heavy headers cross the boundary). Mm/Ke/Ps used directly from ntddk.

## 4. Device bring-up (HwFindAdapter / HwInitialize)

HwFindAdapter (miniport): `VideoPortGetAccessRanges` to capture all BAR ranges;
`VideoPortGetBusData(PCIConfiguration)` to read the 6 BARs + enable MEM + bus
master in the PCI command register (SetBusData).

HwInitialize -> VgpuCreate (core):
1. `virtio_device_initialize(&vdev, &VgpuSystemOps, ctx, msix_used=FALSE)` —
   does reset + ACK + DRIVER. Modern caps are parsed by the lib via our
   `pci_read_config_*` + `pci_map_address_range` callbacks.
2. features = `virtio_get_features`; negotiate `VIRTIO_F_VERSION_1` only;
   `virtio_set_features` (sets FEATURES_OK).
3. `virtio_reserve_queue_memory(vdev, 2)`; `virtio_find_queue(0)` = controlq,
   `(1)` = cursorq (unused for now). `virtqueue_disable_cb` (we poll, no IRQ).
4. `virtio_device_ready` (DRIVER_OK).
5. Read config (`virtio_gpu_config.num_scanouts`). GET_DISPLAY_INFO for the
   host's preferred size (logged; used to pick a sensible default mode).
6. Allocate the frame buffer: one contiguous allocation for the largest
   candidate mode within 8 MB (1920x1080), or the largest the system can give.
   It is the backing of every mode and stays in place until the device is
   reset (see section 5).
7. Build the mode list (bochs-style resolution table, only the modes that fit
   the frame buffer).

### VgpuSystemOps (VirtIOSystemOps) mapping
- register r/w (`vdev_*`): VideoPortRead/WriteRegister{Uchar,Ushort,Ulong} on the
  mapped MMIO VA (modern virtio structures live in MMIO BARs).
- `mem_alloc_contiguous_pages`: `MmAllocateContiguousMemory` (+ zero);
  `mem_get_physical_address`: `MmGetPhysicalAddress`.
- `mem_alloc_nonpaged_block`: VideoPortAllocatePool(NonPaged).
- `pci_read_config_*`: VideoPortGetBusData(PCIConfiguration).
- `pci_get_resource_len` / `pci_map_address_range`: derived from the cached BARs
  (decode 64-bit/prefetchable, match against the PnP access ranges for length),
  mapped with VideoPortGetDeviceBase.
- `vdev_get_msix_vector`: VIRTIO_MSI_NO_VECTOR (polling, no MSI-X).
- `vdev_sleep`: VideoPortStallExecution loop.

## 5. Mode set (IOCTL_VIDEO_SET_CURRENT_MODE -> VgpuSetModeByIndex)

The frame buffer never moves: framebuf maps it once (DrvEnableSurface) and
draws into that view until DrvDisableSurface, and a mode change sets the mode
twice (DrvEnableSurface on the new device, DrvAssertMode when win32k enables the
device that stays). Freeing or moving the backing on a mode set left framebuf
drawing into freed pool (fixed 2026-11; see the commit history). So a mode set
only changes the host resource:
1. w,h from the mode; stride = w*4; size = stride*h (fits the frame buffer).
   The mode that is already set: TRANSFER_TO_HOST_2D + RESOURCE_FLUSH, done.
2. resource_id = ++counter; RESOURCE_CREATE_2D(res, FORMAT_B8G8R8X8_UNORM, w, h)
   — matches Windows 32bpp BGRX in-memory byte order.
3. RESOURCE_ATTACH_BACKING(res, 1 entry = {frame buffer PA, size})  (contiguous
   => single mem entry; SG/non-contiguous backing is a documented future step).
4. SET_SCANOUT(scanout 0, res, {0,0,w,h}), then RESOURCE_UNREF of the old
   resource (the flip of VIRTIO 1.2 cs01 5.7.6.3). A failure before this point
   leaves the old resource on the screen.
5. Clear the mode's part of the frame buffer; TRANSFER_TO_HOST_2D +
   RESOURCE_FLUSH; enable the flush thread.

`IOCTL_VIDEO_MAP_VIDEO_MEMORY` (framebuf calls it after set-mode): the miniport
`VideoPortMapMemory`s the whole frame buffer into the caller (win32k) so
GDI renders straight into the scanout backing (x86 keeps it coherent for
QEMU's RAM reads). The view stays valid across mode sets.

## 6. Command submission (controlq, polled)

One reused command buffer + one response buffer (contiguous, PA known). Per cmd:
`sg[0]={cmdPA,cmdLen}` (device-readable), `sg[1]={respPA,respLen}` (device-
writable); `virtqueue_add_buf(vq,sg,1,1,tok,NULL,0)`; `virtqueue_kick`; poll
`virtqueue_get_buf` (a short spin, then 1 ms sleeps); the completion must be the
submitted buffer with a used length that covers a header and fits the response
buffer (cleared before each command); verify the response type is
`VIRTIO_GPU_RESP_OK_*`. A command not completed within 5 s resets the device and
the driver stops using it, so the reused buffers are never handed out again
while the device may still write them. A KMUTEX serialises controlq between the
flush thread and mode changes.

## 7. Flush thread

`KeDelayExecutionThread(~16 ms)` loop; on each tick, if a scanout is active:
TRANSFER_TO_HOST_2D(rect) + RESOURCE_FLUSH(rect), where rect = accumulated dirty
rect from the private IOCTL if present (only inside the current mode), else the
full screen. Each tick also reads the ISR status (without MSI-X the device holds
INTx asserted until it is read) and clears reported display events
(`events_clear`). Signalled to stop via a KEVENT at teardown.

## 8. Cursor

framebuf uses `EngSetPointerShape`; with no hardware pointer the GDI engine
composites the pointer into the primary surface (our backing), so the flush pump
presents it. Hardware cursor (virtio-gpu cursorq UPDATE_CURSOR/MOVE_CURSOR) is a
later optimisation.

## 9. Test plan

Boot nitro bootcd under QEMU with `-device virtio-gpu-pci` (software, no host GPU).
Verify on the serial log + VNC screenshot: device enumerates (VgpuCreate ok, caps
read), a non-VGA mode is set (e.g. 1024x768/1280x1024/1080p), the desktop renders
and updates live (mouse move, window drag), boot-smoke is clean. Compare against
the stdvga/bochs baseline (which tops out at VGA/bochs modes with no flush
semantics).

## 10. Known gaps / future (GFX-03 handoff)

- Contiguous single-entry backing (cap 1080p). Next: scatter-gather backing via
  multiple virtio_gpu_mem_entry pages to lift the size cap / reduce alloc risk.
- Full-screen flush by default; dirty-rect hooking display driver = the perf win.
- No MSI-X / interrupts (polled). Fine for 2D; 3D will want IRQ-driven fences.
- Hardware cursor via cursorq.
- EDID (VIRTIO_GPU_F_EDID) for host-driven preferred modes / hotplug.
- **GFX-03 builds on**: this transport bring-up, controlq submission, resource +
  backing model, and scanout. 3D adds VIRTIO_GPU_F_VIRGL, 3D resource create,
  CTX create, SUBMIT_3D, and capset negotiation on the same controlq, plus a
  WDDM-or-escape path for the GL UMD. The 2D scanout/flush remains the present path.

---

## 11. Results (2026-10-24, on vultr-kvm-1, QEMU 8.2.2, fork/main bbe9454)

**Working 2D/modesetting KMD.** Built into bootcd.iso; boots the ReactOS "Live
Environment" GUI.

- `-vga none -device virtio-gpu-pci` (the ticket's exact target, no VGA device at
  all): desktop renders at **1024x768** (non-VGA) driven entirely by virtgpump.
- `-device virtio-vga`: same, 1024x768.
- Device enumerates; virtgpump binds via CDDB; virtio modern transport brings up
  (polled, no MSI-X); controlq works; RESOURCE_CREATE_2D + ATTACH_BACKING +
  SET_SCANOUT succeed; the flush pump presents live GDI output
  (TRANSFER_TO_HOST_2D + RESOURCE_FLUSH ~60 Hz).
- Live 2D verified: advancing the LiveCD wizard (keystroke) repaints correctly —
  the flush pump pushes updated GDI output; input works.
- Boot-smoke clean: reaches the GUI, no bugcheck on the COM1 debug log.
- Baseline comparison: without the driver the same device shows QEMU
  "Display output is not active" (no scanout) or falls back to 640x480 VGA.

**Two bring-up bugs found and fixed during testing:**
1. `VideoPortGetBusData` (PCI config) is unreliable during `HwFindAdapter`
   (bus/slot not yet assigned) — it returned zero BARs. Fixed by decoding BARs
   on demand in `Vpw_GetBar` from `HwInitialize` context.
2. For VGA-class devices (`virtio-vga`) `VideoPortGetAccessRanges` reports the
   legacy VGA ranges, not the virtio MMIO BARs, so BAR length lookup missed.
   Since the lib only uses the length as a sanity bound (the real mapping uses
   each capability's own offset/length), `Vpw_GetBar` falls back to the decoded
   BAR base + a generous bound when there is no exact access-range match.

**Remaining gap to a "full" 2D KMD / what GFX-03 builds on:** unchanged from
sections 10 — full-screen flush by default (dirty-rect hooking display driver is
the perf win), contiguous single-entry backing capped at 1080p (SG backing next),
polled (no IRQ/MSI-X fences), software cursor (hardware cursorq later), no EDID.
GFX-03 (3D/virgl) reuses this transport bring-up, controlq submission, the
resource+backing model and scanout; it adds VIRTIO_GPU_F_VIRGL, 3D resources,
context create, SUBMIT_3D and capset negotiation on the same controlq.
