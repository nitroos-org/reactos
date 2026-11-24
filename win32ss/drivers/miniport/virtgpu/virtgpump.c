/*
 * PROJECT:     ReactOS virtio-gpu 2D miniport (nitro / GFX-02)
 * LICENSE:     GPL-2.0-or-later
 * PURPOSE:     XDDM video miniport for QEMU virtio-gpu-pci (2D / modesetting).
 *              Pairs with the generic framebuf.dll display driver. The virtio
 *              transport, GPU protocol and flush pump live in virtgpu_core.c;
 *              this TU owns the VideoPort DDI and bridges VideoPort services.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <ntdef.h>
#include <dderror.h>
#include <miniport.h>
#include <video.h>
#include <devioctl.h>

#include "virtgpump.h"
#include "virtgpu_vpwrap.h"

#define MLOG(...) VideoPortDebugPrint(Error, "VIRTGPU-MP: " __VA_ARGS__)

typedef struct _VIRTGPU_DEVICE_EXTENSION
{
    VIDEO_ACCESS_RANGE AccessRanges[8];
    ULONG              NumAccessRanges;
    PVOID              GpuCtx;
    ULONG              CurrentModeIndex;
} VIRTGPU_DEVICE_EXTENSION, *PVIRTGPU_DEVICE_EXTENSION;

/* ---- VideoPort bridge (called from virtgpu_core.c) ----------------------- */

unsigned char  Vpw_Read8 (void *a)  { return VideoPortReadRegisterUchar((PUCHAR)a); }
unsigned short Vpw_Read16(void *a)  { return VideoPortReadRegisterUshort((PUSHORT)a); }
unsigned long  Vpw_Read32(void *a)  { return VideoPortReadRegisterUlong((PULONG)a); }
void Vpw_Write8 (void *a, unsigned char  v) { VideoPortWriteRegisterUchar((PUCHAR)a, v); }
void Vpw_Write16(void *a, unsigned short v) { VideoPortWriteRegisterUshort((PUSHORT)a, v); }
void Vpw_Write32(void *a, unsigned long  v) { VideoPortWriteRegisterUlong((PULONG)a, v); }

int Vpw_PciReadConfig(void *ext, int where, void *buf, int len)
{
    ULONG got = VideoPortGetBusData(ext, PCIConfiguration, 0, buf, where, len);
    return (got == (ULONG)len) ? 0 : 1;
}
int Vpw_PciWriteConfig(void *ext, int where, void *buf, int len)
{
    ULONG put = VideoPortSetBusData(ext, PCIConfiguration, 0, buf, where, len);
    return (put == (ULONG)len) ? 0 : 1;
}

void *Vpw_MapDevice(void *ext, unsigned long long phys, unsigned long len, int io)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)phys;
    return VideoPortGetDeviceBase(ext, pa, len,
        (UCHAR)(io ? VIDEO_MEMORY_SPACE_IO : VIDEO_MEMORY_SPACE_MEMORY));
}

void *Vpw_AllocPool(void *ext, unsigned long len)
{
    return VideoPortAllocatePool(ext, VpNonPagedPool, len, VIRTGPU_TAG);
}
void Vpw_FreePool(void *ext, void *p) { VideoPortFreePool(ext, p); }

void Vpw_Stall(unsigned long usecs) { VideoPortStallExecution(usecs); }

void Vpw_Log(int level, const char *fmt, unsigned long long a, unsigned long long b)
{
    VideoPortDebugPrint(level ? Info : Error, (PCHAR)fmt, a, b);
}

int Vpw_GetBar(void *ext, int bar, unsigned long long *phys, unsigned long *len, int *io)
{
    PVIRTGPU_DEVICE_EXTENSION e = (PVIRTGPU_DEVICE_EXTENSION)ext;
    ULONG raw = 0, rawhi = 0, i;
    ULONGLONG base;
    int isIo, is64;

    if (bar < 0 || bar > 5) return 1;

    /* Read the BAR on demand: VideoPortGetBusData does not work during
     * HwFindAdapter (bus/slot not yet assigned), only from HwInitialize on. */
    VideoPortGetBusData(ext, PCIConfiguration, 0, &raw, 0x10 + bar * 4, sizeof(raw));
    if (raw == 0) return 1;

    isIo = raw & 0x1;
    is64 = 0;
    if (isIo)
    {
        base = raw & ~0x3u;
    }
    else
    {
        is64 = ((raw & 0x6) == 0x4);
        base = raw & ~0xFu;
        if (is64 && bar < 5)
        {
            VideoPortGetBusData(ext, PCIConfiguration, 0, &rawhi, 0x10 + (bar + 1) * 4, sizeof(rawhi));
            base |= ((ULONGLONG)rawhi) << 32;
        }
    }

    for (i = 0; i < e->NumAccessRanges; i++)
    {
        if ((ULONGLONG)e->AccessRanges[i].RangeStart.QuadPart == base &&
            e->AccessRanges[i].RangeLength != 0)
        {
            *phys = base;
            *len  = e->AccessRanges[i].RangeLength;
            *io   = isIo ? 1 : 0;
            return 0;
        }
    }
    /* No exact PCI access-range match (VGA-class devices report legacy VGA
     * ranges, not the virtio MMIO BARs). The access-range length is only a
     * sanity bound in the virtio lib; the actual mapping uses each capability's
     * own offset/length, so fall back to the decoded base + a generous bound. */
    *phys = base;
    *len  = 0x1000000;
    *io   = isIo ? 1 : 0;
    return 0;
}

/* ---- mode info ----------------------------------------------------------- */

static VOID
VirtGpuFillModeInfo(ULONG w, ULONG h, ULONG index, PVIDEO_MODE_INFORMATION mi)
{
    VideoPortZeroMemory(mi, sizeof(*mi));
    mi->Length = sizeof(*mi);
    mi->ModeIndex = index;
    mi->VisScreenWidth = w;
    mi->VisScreenHeight = h;
    mi->ScreenStride = w * 4;
    mi->NumberOfPlanes = 1;
    mi->BitsPerPlane = 32;
    mi->Frequency = 60;
    mi->XMillimeter = w * 254 / 960;
    mi->YMillimeter = h * 254 / 960;
    mi->NumberRedBits = 8;
    mi->NumberGreenBits = 8;
    mi->NumberBlueBits = 8;
    mi->RedMask = 0xff0000;
    mi->GreenMask = 0x00ff00;
    mi->BlueMask = 0x0000ff;
    mi->AttributeFlags = VIDEO_MODE_GRAPHICS | VIDEO_MODE_COLOR | VIDEO_MODE_NO_OFF_SCREEN;
    mi->VideoMemoryBitmapWidth = w;
    mi->VideoMemoryBitmapHeight = h;
}

/* ---- DDI ----------------------------------------------------------------- */

static VP_STATUS NTAPI
VirtGpuFindAdapter(
    _In_ PVOID HwDeviceExtension,
    _In_ PVOID HwContext,
    _In_ PWSTR ArgumentString,
    _In_ PVIDEO_PORT_CONFIG_INFO ConfigInfo,
    _In_ PUCHAR Again)
{
    PVIRTGPU_DEVICE_EXTENSION ext = HwDeviceExtension;
    ULONG numRanges = ARRAYSIZE(ext->AccessRanges);
    USHORT command;

    UNREFERENCED_PARAMETER(HwContext);
    UNREFERENCED_PARAMETER(ArgumentString);
    UNREFERENCED_PARAMETER(Again);

    if (ConfigInfo->Length < sizeof(*ConfigInfo))
        return ERROR_INVALID_PARAMETER;

    VideoPortZeroMemory(ext->AccessRanges, sizeof(ext->AccessRanges));
    if (VideoPortGetAccessRanges(ext, 0, NULL, numRanges, ext->AccessRanges,
                                 NULL, NULL, NULL) != NO_ERROR)
    {
        VideoPortDebugPrint(Error, "virtgpu: GetAccessRanges failed\n");
        return ERROR_DEV_NOT_EXIST;
    }
    ext->NumAccessRanges = numRanges;
    /* Note: PCI config space (VideoPortGetBusData) is NOT reliable during
     * HwFindAdapter (bus/slot not yet assigned). BARs are therefore decoded
     * on demand from HwInitialize context in Vpw_GetBar(). */

    /* enable memory space + bus master so the device can DMA the virtqueues */
    if (VideoPortGetBusData(ext, PCIConfiguration, 0, &command, 0x04, sizeof(command)) == sizeof(command))
    {
        command |= 0x0006;   /* MEM space | bus master */
        VideoPortSetBusData(ext, PCIConfiguration, 0, &command, 0x04, sizeof(command));
    }

    return NO_ERROR;
}

static BOOLEAN NTAPI
VirtGpuInitialize(_In_ PVOID HwDeviceExtension)
{
    PVIRTGPU_DEVICE_EXTENSION ext = HwDeviceExtension;

    MLOG("Initialize\n");
    if (ext->GpuCtx)
    {
        /* Already running: a second bring-up would reset the device under the first one */
        return TRUE;
    }
    if (VgpuCreate(ext, &ext->GpuCtx) != 0)
    {
        VideoPortDebugPrint(Error, "virtgpu: VgpuCreate failed\n");
        return FALSE;
    }
    ext->CurrentModeIndex = VgpuGetDefaultModeIndex(ext->GpuCtx);
    return TRUE;
}

static BOOLEAN
VirtGpuMapVideoMemory(
    PVIRTGPU_DEVICE_EXTENSION ext,
    PVIDEO_MEMORY RequestedAddress,
    PVIDEO_MEMORY_INFORMATION MapInfo,
    PSTATUS_BLOCK StatusBlock)
{
    VP_STATUS status;
    PHYSICAL_ADDRESS pa;
    unsigned long long phys;
    unsigned long len;
    ULONG memSpace = VIDEO_MEMORY_SPACE_MEMORY | VIDEO_MEMORY_SPACE_P6CACHE;

    if (VgpuGetFramebuffer(ext->GpuCtx, &phys, &len) != 0)
    {
        StatusBlock->Status = ERROR_INVALID_PARAMETER;
        return FALSE;
    }

    pa.QuadPart = (LONGLONG)phys;
    MapInfo->VideoRamBase = RequestedAddress->RequestedVirtualAddress;
    MapInfo->VideoRamLength = len;

    status = VideoPortMapMemory(ext, pa, &MapInfo->VideoRamLength, &memSpace,
                                &MapInfo->VideoRamBase);
    if (status != NO_ERROR)
    {
        VideoPortDebugPrint(Error, "virtgpu: MapMemory failed 0x%x\n", status);
        StatusBlock->Status = status;
        return FALSE;
    }

    MapInfo->FrameBufferBase = MapInfo->VideoRamBase;
    MapInfo->FrameBufferLength = MapInfo->VideoRamLength;
    StatusBlock->Information = sizeof(*MapInfo);
    StatusBlock->Status = NO_ERROR;
    return TRUE;
}

static BOOLEAN NTAPI
VirtGpuStartIO(_In_ PVOID HwDeviceExtension, _Inout_ PVIDEO_REQUEST_PACKET rp)
{
    PVIRTGPU_DEVICE_EXTENSION ext = HwDeviceExtension;

    rp->StatusBlock->Status = ERROR_INVALID_FUNCTION;

    switch (rp->IoControlCode)
    {
        case IOCTL_VIDEO_MAP_VIDEO_MEMORY:
            if (rp->InputBufferLength < sizeof(VIDEO_MEMORY) ||
                rp->OutputBufferLength < sizeof(VIDEO_MEMORY_INFORMATION))
            {
                rp->StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return FALSE;
            }
            return VirtGpuMapVideoMemory(ext,
                (PVIDEO_MEMORY)rp->InputBuffer,
                (PVIDEO_MEMORY_INFORMATION)rp->OutputBuffer,
                rp->StatusBlock);

        case IOCTL_VIDEO_UNMAP_VIDEO_MEMORY:
            if (rp->InputBufferLength < sizeof(VIDEO_MEMORY))
            {
                rp->StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return FALSE;
            }
            rp->StatusBlock->Status = VideoPortUnmapMemory(ext,
                ((PVIDEO_MEMORY)rp->InputBuffer)->RequestedVirtualAddress, NULL);
            return (rp->StatusBlock->Status == NO_ERROR);

        case IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES:
        {
            PVIDEO_NUM_MODES nm = (PVIDEO_NUM_MODES)rp->OutputBuffer;
            if (rp->OutputBufferLength < sizeof(VIDEO_NUM_MODES))
            {
                rp->StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return FALSE;
            }
            nm->NumModes = VgpuGetModeCount(ext->GpuCtx);
            nm->ModeInformationLength = sizeof(VIDEO_MODE_INFORMATION);
            rp->StatusBlock->Information = sizeof(*nm);
            rp->StatusBlock->Status = NO_ERROR;
            return TRUE;
        }

        case IOCTL_VIDEO_QUERY_AVAIL_MODES:
        {
            PVIDEO_MODE_INFORMATION mi = (PVIDEO_MODE_INFORMATION)rp->OutputBuffer;
            ULONG count = VgpuGetModeCount(ext->GpuCtx), i;
            unsigned long w, h;
            if (rp->OutputBufferLength < count * sizeof(VIDEO_MODE_INFORMATION))
            {
                rp->StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return FALSE;
            }
            for (i = 0; i < count; i++, mi++)
            {
                VgpuGetMode(ext->GpuCtx, i, &w, &h);
                VirtGpuFillModeInfo(w, h, i, mi);
            }
            rp->StatusBlock->Information = count * sizeof(VIDEO_MODE_INFORMATION);
            rp->StatusBlock->Status = NO_ERROR;
            return TRUE;
        }

        case IOCTL_VIDEO_SET_CURRENT_MODE:
        {
            ULONG req;
            if (rp->InputBufferLength < sizeof(VIDEO_MODE))
            {
                rp->StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return FALSE;
            }
            req = ((PVIDEO_MODE)rp->InputBuffer)->RequestedMode & 0x3fffffff;
            if (VgpuSetModeByIndex(ext->GpuCtx, req) != 0)
            {
                rp->StatusBlock->Status = ERROR_INVALID_PARAMETER;
                return FALSE;
            }
            ext->CurrentModeIndex = req;
            rp->StatusBlock->Status = NO_ERROR;
            return TRUE;
        }

        case IOCTL_VIDEO_QUERY_CURRENT_MODE:
        {
            PVIDEO_MODE_INFORMATION mi = (PVIDEO_MODE_INFORMATION)rp->OutputBuffer;
            unsigned long w, h;
            if (rp->OutputBufferLength < sizeof(VIDEO_MODE_INFORMATION))
            {
                rp->StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return FALSE;
            }
            if (VgpuGetMode(ext->GpuCtx, ext->CurrentModeIndex, &w, &h) != 0)
            {
                rp->StatusBlock->Status = ERROR_INVALID_PARAMETER;
                return FALSE;
            }
            VirtGpuFillModeInfo(w, h, ext->CurrentModeIndex, mi);
            rp->StatusBlock->Information = sizeof(*mi);
            rp->StatusBlock->Status = NO_ERROR;
            return TRUE;
        }

        case IOCTL_VIDEO_RESET_DEVICE:
            rp->StatusBlock->Status = NO_ERROR;
            return TRUE;

        case IOCTL_VIDEO_GET_CHILD_STATE:
            if (rp->OutputBufferLength < sizeof(ULONG))
            {
                rp->StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return FALSE;
            }
            *(PULONG)rp->OutputBuffer = VIDEO_CHILD_ACTIVE;
            rp->StatusBlock->Information = sizeof(ULONG);
            rp->StatusBlock->Status = NO_ERROR;
            return TRUE;

        default:
            VideoPortDebugPrint(Warn, "virtgpu: unknown IOCTL 0x%08x\n", rp->IoControlCode);
            return FALSE;
    }
}

static VP_STATUS NTAPI
VirtGpuSetPowerState(PVOID HwDeviceExtension, ULONG HwId, PVIDEO_POWER_MANAGEMENT Pm)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(HwId);
    UNREFERENCED_PARAMETER(Pm);
    return NO_ERROR;
}

static VP_STATUS NTAPI
VirtGpuGetPowerState(PVOID HwDeviceExtension, ULONG HwId, PVIDEO_POWER_MANAGEMENT Pm)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(HwId);
    UNREFERENCED_PARAMETER(Pm);
    return ERROR_DEVICE_REINITIALIZATION_NEEDED;
}

static VP_STATUS NTAPI
VirtGpuGetChildDescriptor(
    PVOID HwDeviceExtension,
    PVIDEO_CHILD_ENUM_INFO ChildEnumInfo,
    PVIDEO_CHILD_TYPE VideoChildType,
    PUCHAR pChildDescriptor,
    PULONG UId,
    PULONG pUnused)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(pChildDescriptor);

    if (ChildEnumInfo->Size < sizeof(*VideoChildType))
        return VIDEO_ENUM_NO_MORE_DEVICES;

    if (ChildEnumInfo->ChildIndex == 0)
        return VIDEO_ENUM_INVALID_DEVICE;

    *pUnused = 0;
    if (ChildEnumInfo->ChildIndex == DISPLAY_ADAPTER_HW_ID)
    {
        *VideoChildType = VideoChip;
        return VIDEO_ENUM_MORE_DEVICES;
    }
    if (ChildEnumInfo->ChildIndex != 1)
        return VIDEO_ENUM_NO_MORE_DEVICES;

    *UId = 0;
    *VideoChildType = Monitor;
    return VIDEO_ENUM_MORE_DEVICES;
}

ULONG NTAPI
DriverEntry(PVOID Context1, PVOID Context2)
{
    VIDEO_HW_INITIALIZATION_DATA init;

    VideoPortZeroMemory(&init, sizeof(init));
    init.HwInitDataSize = sizeof(init);
    init.HwFindAdapter = VirtGpuFindAdapter;
    init.HwInitialize = VirtGpuInitialize;
    init.HwStartIO = VirtGpuStartIO;
    init.HwDeviceExtensionSize = sizeof(VIRTGPU_DEVICE_EXTENSION);
    init.HwSetPowerState = VirtGpuSetPowerState;
    init.HwGetPowerState = VirtGpuGetPowerState;
    init.HwGetVideoChildDescriptor = VirtGpuGetChildDescriptor;

    MLOG("DriverEntry\n");
    return VideoPortInitialize(Context1, Context2, &init, NULL);
}
