/*
 * PROJECT:     ReactOS Firmware Framebuffer Miniport Driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Display through the framebuffer the firmware left set up (UEFI GOP)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * A machine started through the UEFI boot loader may have no display device
 * our other miniports can program: no VGA BIOS (so no VBE), and either a
 * device we have no driver for (QXL, Cirrus, VMware SVGA, the VirtualBox
 * adapters, a real GPU) or no PCI display device at all (QEMU ramfb, Hyper-V
 * generation 2). What every such machine has is the linear framebuffer the
 * firmware's Graphics Output Protocol set up; the boot loader describes it in
 * the DisplayController entry of the hardware tree (CM_FRAMEBUF_DEVICE_DATA:
 * address, resolution, pixels per scan line, pixel masks), the same data the
 * framebuffer boot video driver draws the boot screen with.
 *
 * This miniport serves that framebuffer as exactly one mode. The mode cannot
 * be changed: after ExitBootServices nothing can program the device any more
 * (the loader chooses the mode while the firmware's services still run).
 * The kernel's firmware mapper creates the device (Root\FIRMWARE_FRAMEBUFFER)
 * only when the loader handed over such a framebuffer, so on a BIOS machine
 * this driver is never loaded. win32k uses the device only when no other
 * display device is there (NitroFallbackDisplay): a real driver of the
 * display hardware always wins.
 */

#include "lfbmp.h"

/* FRAMEBUFFER DESCRIPTION ****************************************************/

/* Number of bits set in a mask */
static ULONG
LfbCountBits(
    _In_ ULONG Mask)
{
    ULONG Count = 0;

    while (Mask)
    {
        Count += Mask & 1;
        Mask >>= 1;
    }
    return Count;
}

/*
 * Checks the pixel format of the description and fills the masks of the
 * extension. The UEFI GOP pixel formats are 32-bit RGB or BGR with 8 bits per
 * colour, or a bit-mask format whose masks the loader passes as they are.
 */
static VP_STATUS
LfbSetPixelFormat(
    _Inout_ PLFB_DEVICE_EXTENSION DeviceExtension,
    _In_ PCM_FRAMEBUF_DEVICE_DATA Data)
{
    ULONG Red = Data->PixelMasks.RedMask;
    ULONG Green = Data->PixelMasks.GreenMask;
    ULONG Blue = Data->PixelMasks.BlueMask;
    ULONG Reserved = Data->PixelMasks.ReservedMask;
    ULONG PixelMask;

    switch (Data->BitsPerPixel)
    {
        case 16:
        case 24:
        case 32:
            break;

        default:
            /* 8 bits and below would need a palette the firmware does not describe */
            VideoDebugPrint((Error, "LfbMp: %lu bits per pixel is not supported\n", Data->BitsPerPixel));
            return ERROR_INVALID_PARAMETER;
    }

    if ((Red == 0) && (Green == 0) && (Blue == 0))
    {
        /* No masks given: the usual layout of the depth (as the loader assumes) */
        if (Data->BitsPerPixel == 16)
        {
            Red = 0xF800;
            Green = 0x07E0;
            Blue = 0x001F;
        }
        else
        {
            Red = 0x00FF0000;
            Green = 0x0000FF00;
            Blue = 0x000000FF;
        }
        Reserved = 0;
    }

    PixelMask = (Data->BitsPerPixel == 32) ? 0xFFFFFFFF : ((1UL << Data->BitsPerPixel) - 1);

    /* Each colour present, inside the pixel, and no two of them overlapping */
    if ((Red == 0) || (Green == 0) || (Blue == 0) ||
        ((Red | Green | Blue | Reserved) & ~PixelMask) ||
        (Red & Green) || (Red & Blue) || (Green & Blue) ||
        ((Red | Green | Blue) & Reserved))
    {
        VideoDebugPrint((Error, "LfbMp: unusable pixel masks R %08lx G %08lx B %08lx X %08lx (%lu bpp)\n",
                         Red, Green, Blue, Reserved, Data->BitsPerPixel));
        return ERROR_INVALID_PARAMETER;
    }

    DeviceExtension->BitsPerPixel = Data->BitsPerPixel;
    DeviceExtension->RedMask = Red;
    DeviceExtension->GreenMask = Green;
    DeviceExtension->BlueMask = Blue;
    return NO_ERROR;
}

/*
 * Parses the "Configuration Data" of a display controller of the hardware
 * tree: a CM_FULL_RESOURCE_DESCRIPTOR (list version 1.2 or later) whose first
 * memory descriptor is the video RAM and whose last descriptor is the
 * device-specific CM_FRAMEBUF_DEVICE_DATA.
 */
static VP_STATUS
LfbParseDescription(
    _Inout_ PLFB_DEVICE_EXTENSION DeviceExtension,
    _In_reads_bytes_(Length) PLFB_CM_FULL_DESCRIPTOR Full,
    _In_ ULONG Length)
{
    PLFB_CM_PARTIAL_DESCRIPTOR Descriptor, Memory = NULL;
    PCM_FRAMEBUF_DEVICE_DATA Data = NULL;
    PUCHAR End = (PUCHAR)Full + Length;
    ULONGLONG Stride, Size;
    ULONG i, BytesPerPixel;
    VP_STATUS Status;

    if (!Full || (Length < FIELD_OFFSET(LFB_CM_FULL_DESCRIPTOR, PartialDescriptors)))
        return ERROR_INVALID_PARAMETER;

    /* The framebuffer data came with version 1.2 of the list */
    if ((Full->Version < 1) || ((Full->Version == 1) && (Full->Revision < 2)))
        return ERROR_INVALID_PARAMETER;

    Descriptor = Full->PartialDescriptors;
    for (i = 0; i < Full->Count; i++, Descriptor++)
    {
        if ((PUCHAR)(Descriptor + 1) > End)
            return ERROR_INVALID_PARAMETER;

        if (Descriptor->Type == LFB_CM_RESOURCE_TYPE_MEMORY)
        {
            if (!Memory)
                Memory = Descriptor;
        }
        else if (Descriptor->Type == LFB_CM_RESOURCE_TYPE_DEVICE_SPECIFIC)
        {
            /* The data follows its descriptor, which is the last one */
            if ((Descriptor->u.DeviceSpecificData.DataSize < sizeof(CM_FRAMEBUF_DEVICE_DATA)) ||
                ((PUCHAR)(Descriptor + 1) + sizeof(CM_FRAMEBUF_DEVICE_DATA) > End))
            {
                return ERROR_INVALID_PARAMETER;
            }
            Data = (PCM_FRAMEBUF_DEVICE_DATA)(Descriptor + 1);
            break;
        }
    }

    if (!Memory || !Data)
        return ERROR_DEV_NOT_EXIST;

    if ((Data->ScreenWidth < LFB_MIN_WIDTH) || (Data->ScreenHeight < LFB_MIN_HEIGHT) ||
        (Data->ScreenWidth > LFB_MAX_DIMENSION) || (Data->ScreenHeight > LFB_MAX_DIMENSION) ||
        (Data->PixelsPerScanLine < Data->ScreenWidth) || (Data->PixelsPerScanLine > LFB_MAX_DIMENSION))
    {
        VideoDebugPrint((Error, "LfbMp: unusable framebuffer size %lux%lu, %lu pixels per scan line\n",
                         Data->ScreenWidth, Data->ScreenHeight, Data->PixelsPerScanLine));
        return ERROR_INVALID_PARAMETER;
    }

    Status = LfbSetPixelFormat(DeviceExtension, Data);
    if (Status != NO_ERROR)
        return Status;

    /* The pitch is given in pixels (UEFI PixelsPerScanLine); it may exceed the width */
    BytesPerPixel = DeviceExtension->BitsPerPixel / 8;
    Stride = (ULONGLONG)Data->PixelsPerScanLine * BytesPerPixel;
    Size = Stride * Data->ScreenHeight;

    /* The visible part must lie inside the video memory the loader described */
    if ((ULONGLONG)Data->FrameBufferOffset + Size > Memory->u.Memory.Length)
    {
        VideoDebugPrint((Error, "LfbMp: framebuffer (offset 0x%lx, 0x%I64x bytes) is larger than its memory (0x%lx bytes)\n",
                         Data->FrameBufferOffset, Size, Memory->u.Memory.Length));
        return ERROR_INVALID_PARAMETER;
    }

    if (Memory->u.Memory.Start.QuadPart == 0)
        return ERROR_INVALID_PARAMETER;

    DeviceExtension->FrameBuffer.QuadPart = Memory->u.Memory.Start.QuadPart + Data->FrameBufferOffset;
    DeviceExtension->Width = Data->ScreenWidth;
    DeviceExtension->Height = Data->ScreenHeight;
    DeviceExtension->Stride = (ULONG)Stride;
    DeviceExtension->MappedLength = (ULONG)Size;
    return NO_ERROR;
}

/* VideoPortGetDeviceData callback: one display controller of the hardware tree */
static VP_STATUS
NTAPI
LfbControllerCallback(
    _In_ PVOID HwDeviceExtension,
    _In_ PVOID Context,
    _In_ VIDEO_DEVICE_DATA_TYPE DeviceDataType,
    _In_ PVOID Identifier,
    _In_ ULONG IdentifierLength,
    _In_ PVOID ConfigurationData,
    _In_ ULONG ConfigurationDataLength,
    _In_ PVOID ComponentInformation,
    _In_ ULONG ComponentInformationLength)
{
    PLFB_DEVICE_EXTENSION DeviceExtension = HwDeviceExtension;
    VP_STATUS Status;

    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(DeviceDataType);
    UNREFERENCED_PARAMETER(IdentifierLength);
    UNREFERENCED_PARAMETER(ComponentInformation);
    UNREFERENCED_PARAMETER(ComponentInformationLength);

    Status = LfbParseDescription(DeviceExtension, ConfigurationData, ConfigurationDataLength);
    VideoDebugPrint((Info, "LfbMp: display controller '%S': status %lu\n",
                     Identifier ? (PWSTR)Identifier : L"", Status));

    /* Remember why the entry that carried framebuffer data was refused */
    if (Status != ERROR_DEV_NOT_EXIST)
        DeviceExtension->FindStatus = Status;
    return Status;
}

static VOID
LfbSetRegistryString(
    _In_ PLFB_DEVICE_EXTENSION DeviceExtension,
    _In_ PWSTR ValueName,
    _In_ PCWSTR String)
{
    ULONG Length = 0;

    while (String[Length])
        Length++;
    VideoPortSetRegistryParameters(DeviceExtension, ValueName, (PVOID)String,
                                   (Length + 1) * sizeof(WCHAR));
}

/* MINIPORT INTERFACE *********************************************************/

CODE_SEG("PAGE")
VP_STATUS
NTAPI
LfbFindAdapter(
    _In_ PVOID HwDeviceExtension,
    _In_ PVOID HwContext,
    _In_ PWSTR ArgumentString,
    _Inout_ PVIDEO_PORT_CONFIG_INFO ConfigInfo,
    _Out_ PUCHAR Again)
{
    PLFB_DEVICE_EXTENSION DeviceExtension = HwDeviceExtension;
    ULONG One = 1, MemorySize;
    VP_STATUS Status;

    UNREFERENCED_PARAMETER(HwContext);
    UNREFERENCED_PARAMETER(ArgumentString);

    *Again = FALSE;

    if (ConfigInfo->Length < sizeof(VIDEO_PORT_CONFIG_INFO))
        return ERROR_INVALID_PARAMETER;

    DeviceExtension->FindStatus = ERROR_DEV_NOT_EXIST;
    Status = VideoPortGetDeviceData(DeviceExtension, VpControllerData, LfbControllerCallback, NULL);
    if (Status != NO_ERROR)
    {
        /* The device exists from an earlier boot, but this time the loader handed over no framebuffer */
        VideoDebugPrint((Error, "LfbMp: no usable firmware framebuffer in the hardware tree (status %lu)\n",
                         DeviceExtension->FindStatus));
        return ERROR_DEV_NOT_EXIST;
    }
    DeviceExtension->Found = TRUE;

    /* No VGA: not usable as the base video device, and no VDM memory */
    ConfigInfo->VdmPhysicalVideoMemoryAddress.QuadPart = 0;
    ConfigInfo->VdmPhysicalVideoMemoryLength = 0;

    /* win32k takes this device only when no other display device is present */
    VideoPortSetRegistryParameters(DeviceExtension, L"NitroFallbackDisplay", &One, sizeof(One));

    /* What the display control panel shows on its adapter page */
    LfbSetRegistryString(DeviceExtension, L"HardwareInformation.ChipType", L"Firmware framebuffer");
    LfbSetRegistryString(DeviceExtension, L"HardwareInformation.DacType", L"Fixed mode");
    LfbSetRegistryString(DeviceExtension, L"HardwareInformation.AdapterString", L"Firmware Framebuffer Display Adapter");
    LfbSetRegistryString(DeviceExtension, L"HardwareInformation.BiosString", L"UEFI Graphics Output Protocol");
    MemorySize = DeviceExtension->MappedLength;
    VideoPortSetRegistryParameters(DeviceExtension, L"HardwareInformation.MemorySize", &MemorySize, sizeof(MemorySize));

    VideoDebugPrint((Warn, "LfbMp: firmware framebuffer %lux%lu, %lu bpp, stride %lu, at 0x%I64x, "
                     "masks R %08lx G %08lx B %08lx, write-combined\n",
                     DeviceExtension->Width, DeviceExtension->Height, DeviceExtension->BitsPerPixel,
                     DeviceExtension->Stride, DeviceExtension->FrameBuffer.QuadPart,
                     DeviceExtension->RedMask, DeviceExtension->GreenMask, DeviceExtension->BlueMask));
    return NO_ERROR;
}

CODE_SEG("PAGE")
BOOLEAN
NTAPI
LfbInitialize(
    _In_ PVOID HwDeviceExtension)
{
    PLFB_DEVICE_EXTENSION DeviceExtension = HwDeviceExtension;

    /* Nothing to program: the firmware set the mode */
    return DeviceExtension->Found;
}

static VOID
LfbFillModeInformation(
    _In_ PLFB_DEVICE_EXTENSION DeviceExtension,
    _Out_ PVIDEO_MODE_INFORMATION ModeInfo)
{
    VideoPortZeroMemory(ModeInfo, sizeof(*ModeInfo));
    ModeInfo->Length = sizeof(*ModeInfo);
    ModeInfo->ModeIndex = 0;
    ModeInfo->VisScreenWidth = DeviceExtension->Width;
    ModeInfo->VisScreenHeight = DeviceExtension->Height;
    ModeInfo->ScreenStride = DeviceExtension->Stride;
    ModeInfo->NumberOfPlanes = 1;
    ModeInfo->BitsPerPlane = DeviceExtension->BitsPerPixel;
    /* The firmware does not tell the refresh rate */
    ModeInfo->Frequency = 60;
    /* 96 DPI */
    ModeInfo->XMillimeter = DeviceExtension->Width * 254 / 960;
    ModeInfo->YMillimeter = DeviceExtension->Height * 254 / 960;
    ModeInfo->NumberRedBits = LfbCountBits(DeviceExtension->RedMask);
    ModeInfo->NumberGreenBits = LfbCountBits(DeviceExtension->GreenMask);
    ModeInfo->NumberBlueBits = LfbCountBits(DeviceExtension->BlueMask);
    ModeInfo->RedMask = DeviceExtension->RedMask;
    ModeInfo->GreenMask = DeviceExtension->GreenMask;
    ModeInfo->BlueMask = DeviceExtension->BlueMask;
    ModeInfo->AttributeFlags = VIDEO_MODE_GRAPHICS | VIDEO_MODE_COLOR | VIDEO_MODE_NO_OFF_SCREEN;
    ModeInfo->VideoMemoryBitmapWidth = DeviceExtension->Width;
    ModeInfo->VideoMemoryBitmapHeight = DeviceExtension->Height;
}

static BOOLEAN
LfbMapVideoMemory(
    _In_ PLFB_DEVICE_EXTENSION DeviceExtension,
    _In_ PVIDEO_MEMORY RequestedAddress,
    _Out_ PVIDEO_MEMORY_INFORMATION MapInformation,
    _Out_ PSTATUS_BLOCK StatusBlock)
{
    /* The framebuffer is mapped write-combined */
    ULONG MemSpace = VIDEO_MEMORY_SPACE_MEMORY | VIDEO_MEMORY_SPACE_P6CACHE;
    VP_STATUS Status;

    MapInformation->VideoRamBase = RequestedAddress->RequestedVirtualAddress;
    MapInformation->VideoRamLength = DeviceExtension->MappedLength;

    Status = VideoPortMapMemory(DeviceExtension,
                                DeviceExtension->FrameBuffer,
                                &MapInformation->VideoRamLength,
                                &MemSpace,
                                &MapInformation->VideoRamBase);
    if (Status != NO_ERROR)
    {
        VideoDebugPrint((Error, "LfbMp: cannot map the framebuffer at 0x%I64x (0x%lx bytes): status %lu\n",
                         DeviceExtension->FrameBuffer.QuadPart, DeviceExtension->MappedLength, Status));
        StatusBlock->Status = Status;
        return FALSE;
    }

    MapInformation->FrameBufferBase = MapInformation->VideoRamBase;
    MapInformation->FrameBufferLength = DeviceExtension->MappedLength;
    StatusBlock->Information = sizeof(*MapInformation);
    StatusBlock->Status = NO_ERROR;
    return TRUE;
}

CODE_SEG("PAGE")
BOOLEAN
NTAPI
LfbStartIO(
    _In_ PVOID HwDeviceExtension,
    _Inout_ PVIDEO_REQUEST_PACKET RequestPacket)
{
    PLFB_DEVICE_EXTENSION DeviceExtension = HwDeviceExtension;
    PSTATUS_BLOCK StatusBlock = RequestPacket->StatusBlock;

    StatusBlock->Status = ERROR_INVALID_FUNCTION;
    StatusBlock->Information = 0;

    switch (RequestPacket->IoControlCode)
    {
        case IOCTL_VIDEO_MAP_VIDEO_MEMORY:
            if ((RequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY)) ||
                (RequestPacket->OutputBufferLength < sizeof(VIDEO_MEMORY_INFORMATION)))
            {
                StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return TRUE;
            }
            LfbMapVideoMemory(DeviceExtension,
                              (PVIDEO_MEMORY)RequestPacket->InputBuffer,
                              (PVIDEO_MEMORY_INFORMATION)RequestPacket->OutputBuffer,
                              StatusBlock);
            return TRUE;

        case IOCTL_VIDEO_UNMAP_VIDEO_MEMORY:
            if (RequestPacket->InputBufferLength < sizeof(VIDEO_MEMORY))
            {
                StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return TRUE;
            }
            StatusBlock->Status = VideoPortUnmapMemory(DeviceExtension,
                                                       ((PVIDEO_MEMORY)RequestPacket->InputBuffer)->RequestedVirtualAddress,
                                                       NULL);
            return TRUE;

        case IOCTL_VIDEO_QUERY_NUM_AVAIL_MODES:
        {
            PVIDEO_NUM_MODES Modes = (PVIDEO_NUM_MODES)RequestPacket->OutputBuffer;

            if (RequestPacket->OutputBufferLength < sizeof(VIDEO_NUM_MODES))
            {
                StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return TRUE;
            }
            Modes->NumModes = 1;
            Modes->ModeInformationLength = sizeof(VIDEO_MODE_INFORMATION);
            StatusBlock->Information = sizeof(VIDEO_NUM_MODES);
            StatusBlock->Status = NO_ERROR;
            return TRUE;
        }

        case IOCTL_VIDEO_QUERY_AVAIL_MODES:
        case IOCTL_VIDEO_QUERY_CURRENT_MODE:
            if (RequestPacket->OutputBufferLength < sizeof(VIDEO_MODE_INFORMATION))
            {
                StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return TRUE;
            }
            LfbFillModeInformation(DeviceExtension, (PVIDEO_MODE_INFORMATION)RequestPacket->OutputBuffer);
            StatusBlock->Information = sizeof(VIDEO_MODE_INFORMATION);
            StatusBlock->Status = NO_ERROR;
            return TRUE;

        case IOCTL_VIDEO_SET_CURRENT_MODE:
        {
            PVIDEO_MODE Mode = (PVIDEO_MODE)RequestPacket->InputBuffer;

            if (RequestPacket->InputBufferLength < sizeof(VIDEO_MODE))
            {
                StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return TRUE;
            }
            /* The only mode is the one already set; VIDEO_MODE_NO_ZERO_MEMORY and friends change nothing */
            if ((Mode->RequestedMode & ~(VIDEO_MODE_NO_ZERO_MEMORY | VIDEO_MODE_MAP_MEM_LINEAR)) != 0)
            {
                StatusBlock->Status = ERROR_INVALID_PARAMETER;
                return TRUE;
            }
            StatusBlock->Status = NO_ERROR;
            return TRUE;
        }

        case IOCTL_VIDEO_RESET_DEVICE:
            /* There is no text mode to go back to: the firmware's mode stays */
            StatusBlock->Status = NO_ERROR;
            return TRUE;

        case IOCTL_VIDEO_GET_CHILD_STATE:
            if (RequestPacket->OutputBufferLength < sizeof(ULONG))
            {
                StatusBlock->Status = ERROR_INSUFFICIENT_BUFFER;
                return TRUE;
            }
            *(PULONG)RequestPacket->OutputBuffer = VIDEO_CHILD_ACTIVE;
            StatusBlock->Information = sizeof(ULONG);
            StatusBlock->Status = NO_ERROR;
            return TRUE;

        default:
            /* No palette (direct colour only), no hardware pointer: the display driver draws it */
            VideoDebugPrint((Info, "LfbMp: IOCTL 0x%08lx not supported\n", RequestPacket->IoControlCode));
            return TRUE;
    }
}

CODE_SEG("PAGE")
VP_STATUS
NTAPI
LfbSetPowerState(
    _In_ PVOID HwDeviceExtension,
    _In_ ULONG HwId,
    _In_ PVIDEO_POWER_MANAGEMENT VideoPowerControl)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(HwId);
    UNREFERENCED_PARAMETER(VideoPowerControl);

    /* No way to turn the screen off: accept and keep it as it is */
    return NO_ERROR;
}

CODE_SEG("PAGE")
VP_STATUS
NTAPI
LfbGetPowerState(
    _In_ PVOID HwDeviceExtension,
    _In_ ULONG HwId,
    _Out_ PVIDEO_POWER_MANAGEMENT VideoPowerControl)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(VideoPowerControl);

    /* The adapter and its screen stay on; the mode cannot be set again after a power down */
    if (VideoPowerControl->PowerState == VideoPowerOn)
        return NO_ERROR;
    return (HwId == DISPLAY_ADAPTER_HW_ID) ? ERROR_DEVICE_REINITIALIZATION_NEEDED : ERROR_INVALID_FUNCTION;
}

CODE_SEG("PAGE")
VP_STATUS
NTAPI
LfbGetVideoChildDescriptor(
    _In_ PVOID HwDeviceExtension,
    _In_ PVIDEO_CHILD_ENUM_INFO ChildEnumInfo,
    _Out_ PVIDEO_CHILD_TYPE VideoChildType,
    _Out_ PUCHAR pChildDescriptor,
    _Out_ PULONG UId,
    _Out_ PULONG pUnused)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(pChildDescriptor);

    if (ChildEnumInfo->Size < sizeof(VIDEO_CHILD_ENUM_INFO))
        return VIDEO_ENUM_NO_MORE_DEVICES;

    *pUnused = 0;
    switch (ChildEnumInfo->ChildIndex)
    {
        case 0:
            /* No ACPI enumeration */
            return VIDEO_ENUM_INVALID_DEVICE;

        case DISPLAY_ADAPTER_HW_ID:
            *VideoChildType = VideoChip;
            return VIDEO_ENUM_MORE_DEVICES;

        case 1:
            /* One monitor, without EDID: the firmware's description has none */
            *VideoChildType = Monitor;
            *UId = 0;
            return VIDEO_ENUM_MORE_DEVICES;

        default:
            return VIDEO_ENUM_NO_MORE_DEVICES;
    }
}

ULONG
NTAPI
DriverEntry(
    _In_ PVOID Context1,
    _In_ PVOID Context2)
{
    VIDEO_HW_INITIALIZATION_DATA InitData;

    VideoPortZeroMemory(&InitData, sizeof(InitData));
    InitData.HwInitDataSize = sizeof(InitData);
    InitData.AdapterInterfaceType = Internal;
    InitData.HwFindAdapter = LfbFindAdapter;
    InitData.HwInitialize = LfbInitialize;
    InitData.HwStartIO = LfbStartIO;
    InitData.HwSetPowerState = LfbSetPowerState;
    InitData.HwGetPowerState = LfbGetPowerState;
    InitData.HwGetVideoChildDescriptor = LfbGetVideoChildDescriptor;
    InitData.HwDeviceExtensionSize = sizeof(LFB_DEVICE_EXTENSION);

    /* A PnP miniport: the device is created by the PnP manager, no legacy detection */
    return VideoPortInitialize(Context1, Context2, &InitData, NULL);
}
