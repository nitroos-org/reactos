/*
 * PROJECT:     ReactOS Firmware Framebuffer Miniport Driver
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Definitions of the firmware framebuffer miniport
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#include <ntdef.h>
#include <dderror.h>
#include <miniport.h>
#include <video.h>
#include <devioctl.h>
#include <section_attribs.h>

/*
 * The "Configuration Data" of a display controller of the hardware tree is a
 * CM_FULL_RESOURCE_DESCRIPTOR, and the loader's framebuffer description is a
 * CM_FRAMEBUF_DEVICE_DATA appended to it. A video miniport cannot include
 * wdm.h (it conflicts with miniport.h), so the parts of those layouts this
 * driver reads are given here (the CM structures are packed to 4 bytes).
 */
#include <pshpack4.h>
typedef struct _CM_VIDEO_DEVICE_DATA
{
    USHORT Version;
    USHORT Revision;
    ULONG VideoClock;
} CM_VIDEO_DEVICE_DATA, *PCM_VIDEO_DEVICE_DATA;

#define LFB_CM_RESOURCE_TYPE_MEMORY           3   /* CmResourceTypeMemory */
#define LFB_CM_RESOURCE_TYPE_DEVICE_SPECIFIC  5   /* CmResourceTypeDeviceSpecific */

typedef struct _LFB_CM_PARTIAL_DESCRIPTOR
{
    UCHAR Type;
    UCHAR ShareDisposition;
    USHORT Flags;
    union
    {
        struct
        {
            PHYSICAL_ADDRESS Start;
            ULONG Length;
        } Memory;
        struct
        {
            ULONG DataSize;
            ULONG Reserved1;
            ULONG Reserved2;
        } DeviceSpecificData;
        /* The largest member (u.MessageInterrupt.Raw): sets the size of the union */
        struct
        {
            USHORT Reserved;
            USHORT MessageCount;
            ULONG Vector;
            ULONG_PTR Affinity;
        } MessageInterruptRaw;
    } u;
} LFB_CM_PARTIAL_DESCRIPTOR, *PLFB_CM_PARTIAL_DESCRIPTOR;

typedef struct _LFB_CM_FULL_DESCRIPTOR
{
    INTERFACE_TYPE InterfaceType;
    ULONG BusNumber;
    USHORT Version;     /* of the partial resource list */
    USHORT Revision;
    ULONG Count;
    LFB_CM_PARTIAL_DESCRIPTOR PartialDescriptors[1];
} LFB_CM_FULL_DESCRIPTOR, *PLFB_CM_FULL_DESCRIPTOR;
#include <poppack.h>

/* sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR): 16 bytes on 32-bit, 20 on 64-bit systems */
C_ASSERT(sizeof(LFB_CM_PARTIAL_DESCRIPTOR) == 12 + sizeof(ULONG_PTR));
C_ASSERT(FIELD_OFFSET(LFB_CM_PARTIAL_DESCRIPTOR, u.Memory.Start) == 4);
C_ASSERT(FIELD_OFFSET(LFB_CM_FULL_DESCRIPTOR, PartialDescriptors) == 16);

/* CM_FRAMEBUF_DEVICE_DATA: what the boot loader writes to the hardware tree */
#include <drivers/bootvid/framebuf.h>

#define LFB_TAG 'pmFL'

/* Bounds of a framebuffer this driver accepts */
#define LFB_MIN_WIDTH       320
#define LFB_MIN_HEIGHT      200
#define LFB_MAX_DIMENSION   16384

typedef struct _LFB_DEVICE_EXTENSION
{
    /* Found in the hardware tree (VideoPortGetDeviceData) */
    BOOLEAN Found;
    VP_STATUS FindStatus;           /* Why the description was refused, if it was */

    /* The one mode: the one the firmware set before the boot loader exited its boot services */
    PHYSICAL_ADDRESS FrameBuffer;   /* Physical address of the first visible pixel */
    ULONG Width;
    ULONG Height;
    ULONG BitsPerPixel;             /* 16, 24 or 32 */
    ULONG Stride;                   /* Bytes from one scan line to the next */
    ULONG RedMask;
    ULONG GreenMask;
    ULONG BlueMask;
    ULONG MappedLength;             /* Stride * Height, what MAP_VIDEO_MEMORY maps */

    BOOLEAN WriteCombined;          /* Map the framebuffer write-combined (default) */
} LFB_DEVICE_EXTENSION, *PLFB_DEVICE_EXTENSION;
