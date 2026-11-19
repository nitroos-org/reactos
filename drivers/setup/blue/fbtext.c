/*
 * PROJECT:     ReactOS Console Text-Mode Device Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Text-mode console on a linear framebuffer (UEFI GOP boot display).
 *
 * A machine started through the UEFI loader has no VGA text mode: there is no
 * 0xB8000 text memory and no CRT controller to program, only the linear
 * framebuffer that the loader describes in the DisplayController entry of the
 * hardware tree (CM_FRAMEBUF_DEVICE_DATA, the same data the framebuffer boot
 * video driver uses). This file draws the 80x50 character cells of the console
 * (8x8 glyphs, the screen of the VGA mode this driver programs on a PC) into
 * that framebuffer: 16 VGA colours, an underline cursor, the whole 640x400 text
 * screen centred and scaled by a whole factor.
 *
 * Nothing here touches an I/O port, so it also works with display devices that
 * have no VGA compatibility.
 */

/* INCLUDES ******************************************************************/

#include "blue.h"
#include <bootvid/framebuf.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

#define SCRFB_MAX_SCALE 8

typedef struct _SCRFB
{
    BOOLEAN Available;      /* A usable framebuffer was found in the hardware tree */
    PHYSICAL_ADDRESS Address;   /* Physical address of the visible framebuffer */
    ULONG Width, Height;    /* Resolution in pixels */
    ULONG Pitch;            /* Bytes per scan line */
    ULONG RedShift, GreenShift, BlueShift;
    ULONG Scale;            /* Whole scale factor of the 640x400 text screen */
    ULONG OriginX, OriginY; /* Pixel position of the text screen */
    PUCHAR Base;            /* Mapped framebuffer, NULL when not mapped */
    ULONG MappedSize;
    PUCHAR Shown;           /* Cells (char + attribute) as currently drawn */
    BOOLEAN ForceAll;       /* Redraw all cells at the next sync */
    ULONG CursorCell;       /* Cell where the cursor is drawn, MAXULONG = none */
    ULONG CursorDrawnSize;
    ULONG Palette[16];
} SCRFB;

static SCRFB ScrFb;

/* Same colours as the VGA palette that blue.c programs in text mode */
static const UCHAR ScrFbRgb[16][3] =
{
    {0x00, 0x00, 0x00},
    {0x00, 0x00, 0xC0},
    {0x00, 0xC0, 0x00},
    {0x00, 0xC0, 0xC0},
    {0xC0, 0x00, 0x00},
    {0xC0, 0x00, 0xC0},
    {0xC0, 0xC0, 0x00},
    {0xC0, 0xC0, 0xC0},
    {0x80, 0x80, 0x80},
    {0x00, 0x00, 0xFF},
    {0x00, 0xFF, 0x00},
    {0x00, 0xFF, 0xFF},
    {0xFF, 0x00, 0x00},
    {0xFF, 0x00, 0xFF},
    {0xFF, 0xFF, 0x00},
    {0xFF, 0xFF, 0xFF}
};

/* DETECTION *****************************************************************/

/* Returns the shift of an 8-bit wide contiguous mask, or -1 if the mask is something else */
static LONG
ScrFbMaskShift(
    _In_ ULONG Mask)
{
    ULONG Shift;

    if (Mask == 0)
        return -1;
    for (Shift = 0; Shift < 32 && !(Mask & (1UL << Shift)); ++Shift)
        ;
    if ((Mask >> Shift) != 0xFF)
        return -1;
    return (LONG)Shift;
}

static BOOLEAN
ScrFbOpenKey(
    _In_opt_ HANDLE Root,
    _In_ PCWSTR Name,
    _Out_ PHANDLE Key)
{
    UNICODE_STRING KeyName;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlInitUnicodeString(&KeyName, Name);
    InitializeObjectAttributes(&ObjectAttributes, &KeyName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, Root, NULL);
    return NT_SUCCESS(ZwOpenKey(Key, KEY_READ, &ObjectAttributes));
}

/* Gets the name of the Index-th subkey (NUL-terminated, at most 63 characters) */
static BOOLEAN
ScrFbEnumKey(
    _In_ HANDLE Key,
    _In_ ULONG Index,
    _Out_writes_(64) PWCHAR Name)
{
    union
    {
        KEY_BASIC_INFORMATION Info;
        UCHAR Buffer[sizeof(KEY_BASIC_INFORMATION) + 64 * sizeof(WCHAR)];
    } u;
    ULONG Length, Count;

    if (!NT_SUCCESS(ZwEnumerateKey(Key, Index, KeyBasicInformation, &u, sizeof(u), &Length)))
        return FALSE;
    Count = u.Info.NameLength / sizeof(WCHAR);
    if (Count > 63)
        return FALSE;
    RtlCopyMemory(Name, u.Info.Name, Count * sizeof(WCHAR));
    Name[Count] = UNICODE_NULL;
    return TRUE;
}

/*
 * Parses the "Configuration Data" value of a display controller. Returns TRUE
 * if it describes a 32-bit linear framebuffer that this driver can draw to.
 */
static BOOLEAN
ScrFbParseConfig(
    _In_ PCM_FULL_RESOURCE_DESCRIPTOR Full,
    _In_ ULONG Length)
{
    PCM_PARTIAL_RESOURCE_LIST List = &Full->PartialResourceList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Descriptor, Memory = NULL;
    PCM_FRAMEBUF_DEVICE_DATA Data = NULL;
    PUCHAR End = (PUCHAR)Full + Length;
    LONG Red, Green, Blue;
    ULONG i, Scale;

    if (Length < FIELD_OFFSET(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList.PartialDescriptors))
        return FALSE;

    /* Framebuffer data was introduced with list version 1.2 */
    if ((List->Version < 1) || ((List->Version == 1) && (List->Revision < 2)))
        return FALSE;

    Descriptor = &List->PartialDescriptors[0];
    for (i = 0; i < List->Count; ++i)
    {
        if ((PUCHAR)(Descriptor + 1) > End)
            return FALSE;

        if (Descriptor->Type == CmResourceTypeMemory)
        {
            if (!Memory)
                Memory = Descriptor;
        }
        else if (Descriptor->Type == CmResourceTypeDeviceSpecific)
        {
            /* The data follows the descriptor and this descriptor is the last one */
            if (Descriptor->u.DeviceSpecificData.DataSize < sizeof(CM_FRAMEBUF_DEVICE_DATA))
                return FALSE;
            if ((PUCHAR)(Descriptor + 1) + sizeof(CM_FRAMEBUF_DEVICE_DATA) > End)
                return FALSE;
            Data = (PCM_FRAMEBUF_DEVICE_DATA)(Descriptor + 1);
            break;
        }
        ++Descriptor;
    }

    if (!Memory || !Data)
        return FALSE;

    if ((Data->BitsPerPixel != 32) ||
        (Data->ScreenWidth < SCRFB_COLUMNS * SCRFB_CHAR_WIDTH) ||
        (Data->ScreenHeight < SCRFB_ROWS * SCRFB_CHAR_HEIGHT) ||
        (Data->PixelsPerScanLine < Data->ScreenWidth) ||
        (Data->PixelsPerScanLine > 0x10000) ||
        (Data->ScreenHeight > 0x10000))
    {
        return FALSE;
    }

    Red   = ScrFbMaskShift(Data->PixelMasks.RedMask);
    Green = ScrFbMaskShift(Data->PixelMasks.GreenMask);
    Blue  = ScrFbMaskShift(Data->PixelMasks.BlueMask);
    if ((Red < 0) || (Green < 0) || (Blue < 0))
        return FALSE;

    /* The framebuffer must be inside the video memory of the descriptor */
    if ((ULONGLONG)Data->FrameBufferOffset +
        (ULONGLONG)Data->ScreenHeight * Data->PixelsPerScanLine * 4 > Memory->u.Memory.Length)
    {
        return FALSE;
    }

    Scale = min(Data->ScreenWidth / (SCRFB_COLUMNS * SCRFB_CHAR_WIDTH),
                Data->ScreenHeight / (SCRFB_ROWS * SCRFB_CHAR_HEIGHT));
    Scale = min(max(Scale, 1), SCRFB_MAX_SCALE);

    ScrFb.Address.QuadPart = Memory->u.Memory.Start.QuadPart + Data->FrameBufferOffset;
    ScrFb.Width = Data->ScreenWidth;
    ScrFb.Height = Data->ScreenHeight;
    ScrFb.Pitch = Data->PixelsPerScanLine * 4;
    ScrFb.RedShift = Red;
    ScrFb.GreenShift = Green;
    ScrFb.BlueShift = Blue;
    ScrFb.Scale = Scale;
    ScrFb.OriginX = (ScrFb.Width  - SCRFB_COLUMNS * SCRFB_CHAR_WIDTH  * Scale) / 2;
    ScrFb.OriginY = (ScrFb.Height - SCRFB_ROWS    * SCRFB_CHAR_HEIGHT * Scale) / 2;
    return TRUE;
}

/*
 * Looks for the boot display controller (class DisplayController, number 0)
 * below any adapter of the hardware tree. The UEFI loader puts it below its
 * "UEFI Internal" multifunction adapter, the BIOS loader below ISA or PCI,
 * where it carries no framebuffer data.
 */
BOOLEAN
ScrFbDetect(VOID)
{
    HANDLE System, TypeKey, BusKey, Controller;
    WCHAR TypeName[64], BusName[64];
    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"Configuration Data");
    ULONG i, j;

    RtlZeroMemory(&ScrFb, sizeof(ScrFb));
    ScrFb.CursorCell = MAXULONG;

    if (!ScrFbOpenKey(NULL, L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System", &System))
        return FALSE;

    for (i = 0; !ScrFb.Available && ScrFbEnumKey(System, i, TypeName); ++i)
    {
        if (!ScrFbOpenKey(System, TypeName, &TypeKey))
            continue;

        for (j = 0; !ScrFb.Available && ScrFbEnumKey(TypeKey, j, BusName); ++j)
        {
            if (!ScrFbOpenKey(TypeKey, BusName, &BusKey))
                continue;

            if (ScrFbOpenKey(BusKey, L"DisplayController\\0", &Controller))
            {
                ULONG Length = 0;
                NTSTATUS Status;

                Status = ZwQueryValueKey(Controller, &ValueName, KeyValuePartialInformation,
                                         NULL, 0, &Length);
                if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) &&
                    Length < 0x1000)
                {
                    PKEY_VALUE_PARTIAL_INFORMATION Info;

                    Info = ExAllocatePoolWithTag(PagedPool, Length, TAG_BLUE);
                    if (Info)
                    {
                        Status = ZwQueryValueKey(Controller, &ValueName, KeyValuePartialInformation,
                                                 Info, Length, &Length);
                        if (NT_SUCCESS(Status) && (Info->Type == REG_FULL_RESOURCE_DESCRIPTOR))
                        {
                            ScrFb.Available = ScrFbParseConfig((PCM_FULL_RESOURCE_DESCRIPTOR)Info->Data,
                                                               Info->DataLength);
                        }
                        ExFreePoolWithTag(Info, TAG_BLUE);
                    }
                }
                ZwClose(Controller);
            }
            ZwClose(BusKey);
        }
        ZwClose(TypeKey);
    }
    ZwClose(System);

    return ScrFb.Available;
}

BOOLEAN
ScrFbIsAvailable(VOID)
{
    return ScrFb.Available;
}

/* MAPPING *******************************************************************/

static ULONG
ScrFbPixel(
    _In_ UCHAR Red,
    _In_ UCHAR Green,
    _In_ UCHAR Blue)
{
    return ((ULONG)Red << ScrFb.RedShift) |
           ((ULONG)Green << ScrFb.GreenShift) |
           ((ULONG)Blue << ScrFb.BlueShift);
}

BOOLEAN
ScrFbMap(VOID)
{
    PHYSICAL_ADDRESS Page;
    ULONG Offset, Size, i;

    if (!ScrFb.Available)
        return FALSE;
    if (ScrFb.Base)
        return TRUE;

    ScrFb.Shown = ExAllocatePoolWithTag(NonPagedPool, SCRFB_COLUMNS * SCRFB_ROWS * 2, TAG_BLUE);
    if (!ScrFb.Shown)
        return FALSE;

    Page.QuadPart = ScrFb.Address.QuadPart & ~((ULONGLONG)PAGE_SIZE - 1);
    Offset = (ULONG)(ScrFb.Address.QuadPart - Page.QuadPart);
    Size = ROUND_TO_PAGES(Offset + ScrFb.Height * ScrFb.Pitch);

    /* Like MmMapVideoDisplay(): cached first, uncached as a fallback */
    ScrFb.Base = MmMapIoSpace(Page, Size, MmFrameBufferCached);
    if (!ScrFb.Base)
        ScrFb.Base = MmMapIoSpace(Page, Size, MmNonCached);
    if (!ScrFb.Base)
    {
        ExFreePoolWithTag(ScrFb.Shown, TAG_BLUE);
        ScrFb.Shown = NULL;
        return FALSE;
    }
    ScrFb.MappedSize = Size;
    ScrFb.Base += Offset;

    for (i = 0; i < 16; ++i)
        ScrFb.Palette[i] = ScrFbPixel(ScrFbRgb[i][0], ScrFbRgb[i][1], ScrFbRgb[i][2]);

    ScrFbClear();
    return TRUE;
}

VOID
ScrFbUnmap(VOID)
{
    if (ScrFb.Base)
    {
        MmUnmapIoSpace(ScrFb.Base - BYTE_OFFSET(ScrFb.Address.QuadPart), ScrFb.MappedSize);
        ScrFb.Base = NULL;
        ScrFb.MappedSize = 0;
    }
    if (ScrFb.Shown)
    {
        ExFreePoolWithTag(ScrFb.Shown, TAG_BLUE);
        ScrFb.Shown = NULL;
    }
}

/* DRAWING *******************************************************************/

VOID
ScrFbInvalidate(VOID)
{
    ScrFb.ForceAll = TRUE;
    ScrFb.CursorCell = MAXULONG;
}

/* Fills the whole screen with black and forces a full redraw at the next sync */
VOID
ScrFbClear(VOID)
{
    ULONG y, x;

    if (!ScrFb.Base)
        return;

    for (y = 0; y < ScrFb.Height; ++y)
    {
        PULONG Pixel = (PULONG)(ScrFb.Base + y * ScrFb.Pitch);
        for (x = 0; x < ScrFb.Width; ++x)
            *Pixel++ = ScrFb.Palette[0];
    }
    ScrFbInvalidate();
}

static VOID
ScrFbDrawCell(
    _In_ ULONG Column,
    _In_ ULONG Row,
    _In_ UCHAR Char,
    _In_ UCHAR Attribute,
    _In_ BOOLEAN WithCursor,
    _In_ ULONG CursorLines,
    _In_opt_ const UCHAR* Font8x8)
{
    ULONG Scale = ScrFb.Scale;
    ULONG Foreground = ScrFb.Palette[Attribute & 0x0F];
    ULONG Background = ScrFb.Palette[(Attribute >> 4) & 0x0F];
    ULONG Line[SCRFB_CHAR_WIDTH * SCRFB_MAX_SCALE];
    ULONG Glyph, x, k;

    for (Glyph = 0; Glyph < SCRFB_CHAR_HEIGHT; ++Glyph)
    {
        UCHAR Bits;
        PUCHAR Dest;

        if (WithCursor && (Glyph >= SCRFB_CHAR_HEIGHT - CursorLines))
            Bits = 0xFF;
        else if (Font8x8)
            Bits = Font8x8[Char * 8 + Glyph];
        else /* No font was loaded: merge each pair of lines of the built-in 8x16 font */
            Bits = ScrFbFont8x16[Char * SCRFB_FONT_HEIGHT + Glyph * 2] |
                   ScrFbFont8x16[Char * SCRFB_FONT_HEIGHT + Glyph * 2 + 1];

        for (x = 0; x < SCRFB_CHAR_WIDTH; ++x)
        {
            ULONG Color = (Bits & (0x80 >> x)) ? Foreground : Background;
            for (k = 0; k < Scale; ++k)
                Line[x * Scale + k] = Color;
        }

        Dest = ScrFb.Base +
               (ScrFb.OriginY + (Row * SCRFB_CHAR_HEIGHT + Glyph) * Scale) * ScrFb.Pitch +
               (ScrFb.OriginX + Column * SCRFB_CHAR_WIDTH * Scale) * 4;
        for (k = 0; k < Scale; ++k)
        {
            RtlCopyMemory(Dest, Line, SCRFB_CHAR_WIDTH * Scale * 4);
            Dest += ScrFb.Pitch;
        }
    }
}

/*
 * Draws the cells that differ from what is on the screen. Cells is the text
 * screen exactly as the VGA text memory would hold it: a character byte then
 * an attribute byte per cell, row by row.
 */
VOID
ScrFbSync(
    _In_reads_bytes_(SCRFB_COLUMNS * SCRFB_ROWS * 2) const UCHAR* Cells,
    _In_ USHORT CursorX,
    _In_ USHORT CursorY,
    _In_ BOOLEAN CursorVisible,
    _In_ ULONG CursorSize,
    _In_opt_ const UCHAR* Font8x8)
{
    ULONG Cell, NewCursor = MAXULONG, CursorLines = 1;
    BOOLEAN Force = ScrFb.ForceAll;

    if (!ScrFb.Base || !ScrFb.Shown)
        return;

    if (CursorVisible && (CursorX < SCRFB_COLUMNS) && (CursorY < SCRFB_ROWS))
        NewCursor = CursorY * SCRFB_COLUMNS + CursorX;

    /* Same height rule as the VGA cursor: CursorSize percent of the cell, at least one line */
    CursorLines = (CursorSize * SCRFB_CHAR_HEIGHT) / 100;
    CursorLines = min(max(CursorLines, 1), SCRFB_CHAR_HEIGHT);

    for (Cell = 0; Cell < SCRFB_COLUMNS * SCRFB_ROWS; ++Cell)
    {
        BOOLEAN IsCursor = (Cell == NewCursor);
        BOOLEAN WasCursor = (Cell == ScrFb.CursorCell);

        if (!Force && !IsCursor && !WasCursor &&
            Cells[Cell * 2] == ScrFb.Shown[Cell * 2] &&
            Cells[Cell * 2 + 1] == ScrFb.Shown[Cell * 2 + 1])
        {
            continue;
        }
        if (!Force && IsCursor && WasCursor && (CursorLines == ScrFb.CursorDrawnSize) &&
            Cells[Cell * 2] == ScrFb.Shown[Cell * 2] &&
            Cells[Cell * 2 + 1] == ScrFb.Shown[Cell * 2 + 1])
        {
            continue;
        }

        ScrFbDrawCell(Cell % SCRFB_COLUMNS, Cell / SCRFB_COLUMNS,
                      Cells[Cell * 2], Cells[Cell * 2 + 1],
                      IsCursor, CursorLines, Font8x8);
        ScrFb.Shown[Cell * 2] = Cells[Cell * 2];
        ScrFb.Shown[Cell * 2 + 1] = Cells[Cell * 2 + 1];
    }

    ScrFb.CursorCell = NewCursor;
    ScrFb.CursorDrawnSize = CursorLines;
    ScrFb.ForceAll = FALSE;
}

/* EOF */
