/*
 * PROJECT:     FreeLoader
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Which PCI devices are in this machine, for loading the drivers that go with them
 *
 * The loader reads the PCI configuration space once (bus 0 and the buses behind the
 * bridges it finds) and answers "is there a device that matches this hardware id?",
 * so that the boot driver list holds the storage drivers of the controllers that are
 * present and not those of every controller the system knows (the Critical Device
 * Database names the driver of each; see CmpFindDrivers).
 */

/* INCLUDES *******************************************************************/

#include <freeldr.h>
#include "winldr.h"

#include <debug.h>
DBG_DEFAULT_CHANNEL(WINDOWS);

/* GLOBALS ********************************************************************/

#if (defined(_M_IX86) || defined(_M_AMD64)) && !defined(SARCH_PC98)

#define WL_PCI_MAX_DEVICES      256

typedef struct _WL_PCI_DEVICE
{
    USHORT VendorId;
    USHORT DeviceId;
    ULONG ClassRevision;    /* config dword 0x08: class code, sub class, prog if, revision */
    ULONG Subsystem;        /* config dword 0x2C of a header type 0 function: subsystem id << 16 | subsystem vendor id */
} WL_PCI_DEVICE;

static WL_PCI_DEVICE WlPciDevices[WL_PCI_MAX_DEVICES];
static ULONG WlPciCount;
static BOOLEAN WlPciScanned;
static BOOLEAN WlPciComplete;

/* FUNCTIONS ******************************************************************/

static
ULONG
WlPciRead(
    _In_ UCHAR Bus,
    _In_ UCHAR Device,
    _In_ UCHAR Function,
    _In_ UCHAR Register)
{
    PCI_TYPE1_CFG_BITS Cfg;

    Cfg.u.AsULONG = 0;
    Cfg.u.bits.Enable = 1;
    Cfg.u.bits.BusNumber = Bus;
    Cfg.u.bits.DeviceNumber = Device;
    Cfg.u.bits.FunctionNumber = Function;
    Cfg.u.bits.RegisterNumber = Register & ~3;

    WRITE_PORT_ULONG(PCI_TYPE1_ADDRESS_PORT, Cfg.u.AsULONG);
    return READ_PORT_ULONG((PULONG)PCI_TYPE1_DATA_PORT);
}

/* Reads every function of bus 0 and of the buses behind the bridges found. */
static
VOID
WlPciScan(VOID)
{
    UCHAR Queue[256];
    BOOLEAN Queued[256] = {FALSE};
    ULONG Head = 0, Tail = 0;
    UCHAR Bus, Device, Function, FunctionCount;
    ULONG Id, HeaderDword;
    UCHAR HeaderType;

    WlPciScanned = TRUE;
    WlPciComplete = FALSE;
    WlPciCount = 0;

    Queue[Tail++] = 0;
    Queued[0] = TRUE;
    while (Head < Tail)
    {
        Bus = Queue[Head++];
        for (Device = 0; Device < 32; ++Device)
        {
            Id = WlPciRead(Bus, Device, 0, 0x00);
            if ((Id & 0xFFFF) == 0xFFFF)
                continue;

            HeaderDword = WlPciRead(Bus, Device, 0, 0x0C);
            FunctionCount = (((HeaderDword >> 16) & 0x80) != 0) ? 8 : 1;

            for (Function = 0; Function < FunctionCount; ++Function)
            {
                if (Function != 0)
                {
                    Id = WlPciRead(Bus, Device, Function, 0x00);
                    if ((Id & 0xFFFF) == 0xFFFF)
                        continue;
                    HeaderDword = WlPciRead(Bus, Device, Function, 0x0C);
                }
                HeaderType = (UCHAR)((HeaderDword >> 16) & 0x7F);

                if (WlPciCount >= WL_PCI_MAX_DEVICES)
                {
                    /* The table is full: we do not know the machine */
                    ERR("PCI: more than %u functions, no filtering\n", WL_PCI_MAX_DEVICES);
                    WlPciComplete = FALSE;
                    return;
                }
                WlPciDevices[WlPciCount].VendorId = (USHORT)(Id & 0xFFFF);
                WlPciDevices[WlPciCount].DeviceId = (USHORT)(Id >> 16);
                WlPciDevices[WlPciCount].ClassRevision = WlPciRead(Bus, Device, Function, 0x08);
                WlPciDevices[WlPciCount].Subsystem = (HeaderType == 0) ? WlPciRead(Bus, Device, Function, 0x2C) : 0;
                ++WlPciCount;

                /* A PCI-to-PCI bridge: go to the bus behind it */
                if (HeaderType == PCI_BRIDGE_TYPE)
                {
                    UCHAR Secondary = (UCHAR)((WlPciRead(Bus, Device, Function, 0x18) >> 8) & 0xFF);
                    if ((Secondary != 0) && !Queued[Secondary])
                    {
                        Queued[Secondary] = TRUE;
                        Queue[Tail++] = Secondary;
                    }
                }
            }
        }
    }

    /* Nothing at all (no configuration mechanism #1): we do not know the machine */
    WlPciComplete = (WlPciCount != 0);
    TRACE("PCI: %lu functions\n", WlPciCount);
}

/* The field starts with this (upper case) text, whatever the case of the id; the caller has checked the length. */
static
BOOLEAN
WlPciHasPrefix(
    _In_ PCWSTR String,
    _In_ PCSTR Prefix)
{
    for (; *Prefix != ANSI_NULL; ++Prefix, ++String)
    {
        WCHAR c = *String;
        if ((c >= L'a') && (c <= L'z'))
            c -= L'a' - L'A';
        if (c != (WCHAR)*Prefix)
            return FALSE;
    }
    return TRUE;
}

static
BOOLEAN
WlPciParseHex(
    _In_ PCWSTR String,
    _In_ ULONG Digits,
    _Out_ PULONG Value)
{
    ULONG i, Result = 0;

    for (i = 0; i < Digits; ++i)
    {
        WCHAR c = String[i];
        ULONG d;
        if ((c >= L'0') && (c <= L'9')) d = c - L'0';
        else if ((c >= L'A') && (c <= L'F')) d = c - L'A' + 10;
        else if ((c >= L'a') && (c <= L'f')) d = c - L'a' + 10;
        else return FALSE;
        Result = (Result << 4) | d;
    }
    *Value = Result;
    return TRUE;
}

#endif /* x86 PC */

/**
 * @brief
 * Is a device that matches the PCI id in this machine?
 * See winldr.h.
 **/
BOOLEAN
NTAPI
WinLdrPciDeviceIdPresent(
    _In_ PCWSTR Id,
    _In_ ULONG Length)
{
    /* "PCI", then '#' (registry key) or '\' (hardware id) */
    if ((Length < 5) ||
        (Id[0] != L'P') || (Id[1] != L'C') || (Id[2] != L'I') ||
        ((Id[3] != L'#') && (Id[3] != L'\\')))
    {
        return FALSE;
    }

#if (defined(_M_IX86) || defined(_M_AMD64)) && !defined(SARCH_PC98)
    {
        ULONG Pos = 4, i;
        BOOLEAN HaveVen = FALSE, HaveDev = FALSE, HaveSubsys = FALSE, HaveRev = FALSE, HaveCc = FALSE;
        ULONG Ven = 0, Dev = 0, Subsys = 0, Rev = 0, Cc = 0, CcDigits = 0;

        if (!WlPciScanned)
            WlPciScan();
        if (!WlPciComplete)
            return TRUE;

        /* Fields separated by '&' */
        while (Pos < Length)
        {
            ULONG End = Pos, Digits;
            while ((End < Length) && (Id[End] != L'&'))
                ++End;
            Digits = End - Pos;

            if ((Digits == 8) && WlPciHasPrefix(&Id[Pos], "VEN_") && !HaveVen)
            {
                if (!WlPciParseHex(&Id[Pos + 4], 4, &Ven)) return FALSE;
                HaveVen = TRUE;
            }
            else if ((Digits == 8) && WlPciHasPrefix(&Id[Pos], "DEV_") && !HaveDev)
            {
                if (!WlPciParseHex(&Id[Pos + 4], 4, &Dev)) return FALSE;
                HaveDev = TRUE;
            }
            else if ((Digits == 15) && WlPciHasPrefix(&Id[Pos], "SUBSYS_") && !HaveSubsys)
            {
                if (!WlPciParseHex(&Id[Pos + 7], 8, &Subsys)) return FALSE;
                HaveSubsys = TRUE;
            }
            else if ((Digits == 6) && WlPciHasPrefix(&Id[Pos], "REV_") && !HaveRev)
            {
                if (!WlPciParseHex(&Id[Pos + 4], 2, &Rev)) return FALSE;
                HaveRev = TRUE;
            }
            else if (((Digits == 7) || (Digits == 9)) && WlPciHasPrefix(&Id[Pos], "CC_") && !HaveCc)
            {
                CcDigits = Digits - 3;
                if (!WlPciParseHex(&Id[Pos + 3], CcDigits, &Cc)) return FALSE;
                HaveCc = TRUE;
            }
            else
            {
                /* A field we do not know: not a device we can find */
                return FALSE;
            }
            Pos = End + 1;
        }
        if (!(HaveVen || HaveDev || HaveSubsys || HaveRev || HaveCc))
            return FALSE;

        for (i = 0; i < WlPciCount; ++i)
        {
            const WL_PCI_DEVICE *D = &WlPciDevices[i];
            ULONG Class = D->ClassRevision >> 8;    /* base, sub class, prog if */

            if (HaveVen && (D->VendorId != Ven)) continue;
            if (HaveDev && (D->DeviceId != Dev)) continue;
            if (HaveSubsys && (D->Subsystem != Subsys)) continue;
            if (HaveRev && ((D->ClassRevision & 0xFF) != Rev)) continue;
            if (HaveCc && ((CcDigits == 6) ? (Class != Cc) : ((Class >> 8) != Cc))) continue;
            return TRUE;
        }
        return FALSE;
    }
#else
    /* Cannot look at the bus: as if every driver were boot-start */
    UNREFERENCED_PARAMETER(Length);
    return TRUE;
#endif
}
