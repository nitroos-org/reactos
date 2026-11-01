

/* SDK/DDK/NDK Headers. */
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winddi.h>
#include <winuser.h>
#include <prntfont.h>

#define NTOS_MODE_USER
#include <ndk/ntndk.h>

/* Public Win32K Headers */
#include <ntgdityp.h>
#include <ntgdi.h>
#include <ntgdihdl.h>

#include "gditools.h"

HBITMAP ghbmp1, ghbmp1_InvCol, ghbmp1_RB, ghbmp4, ghbmp8, ghbmp16, ghbmp24, ghbmp32;
HBITMAP ghbmpDIB1, ghbmpDIB1_InvCol, ghbmpDIB1_RB, ghbmpDIB4, ghbmpDIB8, ghbmpDIB16, ghbmpDIB24, ghbmpDIB32;
HDC ghdcDIB1, ghdcDIB1_InvCol, ghdcDIB1_RB, ghdcDIB4, ghdcDIB8, ghdcDIB16, ghdcDIB24, ghdcDIB32;
PVOID gpvDIB1, gpvDIB1_InvCol, gpvDIB1_RB, gpvDIB4, gpvDIB8, gpvDIB16, gpvDIB24, gpvDIB32;
ULONG (*gpDIB32)[8][8];
HPALETTE ghpal;
HDC ghdcInfo;

MYPAL gpal =
{
    0x300, 8,
    {
        { 0x10, 0x20, 0x30, PC_NOCOLLAPSE },
        { 0x20, 0x30, 0x40, PC_NOCOLLAPSE },
        { 0x30, 0x40, 0x50, PC_NOCOLLAPSE },
        { 0x40, 0x50, 0x60, PC_NOCOLLAPSE },
        { 0x50, 0x60, 0x70, PC_NOCOLLAPSE },
        { 0x60, 0x70, 0x80, PC_NOCOLLAPSE },
        { 0x70, 0x80, 0x90, PC_NOCOLLAPSE },
        { 0x80, 0x90, 0xA0, PC_NOCOLLAPSE },
    }
};

/*
 * A 32-bit process under WoW64 has no GDI handle table in its own PEB (Windows 10 also leaves
 * PEB32.GdiSharedHandleTable NULL). The table is mapped through the 64-bit PEB and keeps the amd64
 * entry layout, 24 bytes per entry. The 64-bit TEB lies two pages below the 32-bit one.
 */
typedef struct _ENTRY64
{
    ULONG64 pobj;
    ULONG ulObj;
    USHORT FullUnique;
    UCHAR Objt;
    UCHAR Flags;
    ULONG64 pUser;
} ENTRY64, *PENTRY64;

C_ASSERT(sizeof(ENTRY64) == 24);
C_ASSERT(FIELD_OFFSET(ENTRY64, pUser) == 16);

/* One entry, read in either layout */
typedef struct _ENTRY_VIEW
{
    LONG64 pobj;
    USHORT FullUnique;
    UCHAR Objt;
    UCHAR Flags;
    ULONG64 pUser;
} ENTRY_VIEW;

#ifndef _WIN64
/* amd64 TEB and PEB, which a 32-bit build of the NDK does not declare */
#define TEB64_BIAS          0x2000
#define TEB64_SELF          0x30
#define TEB64_PEB           0x60
#define PEB64_GDI_TABLE     0xF8

static
PENTRY64
GdiQueryTable64(
    VOID)
{
    static LONG lInit;
    static PENTRY64 pTable64;
    BOOL bWow64 = FALSE;
    PUCHAR pTeb64;
    ULONG64 ullPeb64, ullTable64;

    if (lInit)
        return pTable64;

    if (IsWow64Process(GetCurrentProcess(), &bWow64) && bWow64)
    {
        pTeb64 = (PUCHAR)NtCurrentTeb() - TEB64_BIAS;
        ullPeb64 = *(PULONG64)(pTeb64 + TEB64_PEB);
        if (*(PULONG64)(pTeb64 + TEB64_SELF) == (ULONG_PTR)pTeb64 &&
            ullPeb64 != 0 && (ullPeb64 >> 32) == 0)
        {
            ullTable64 = *(PULONG64)((PUCHAR)(ULONG_PTR)ullPeb64 + PEB64_GDI_TABLE);
            if ((ullTable64 >> 32) == 0)
                pTable64 = (PENTRY64)(ULONG_PTR)ullTable64;
        }
    }

    lInit = 1;
    return pTable64;
}
#endif

/* The table in the native layout of this process, NULL for a 32-bit process under WoW64 */
PENTRY
GdiQueryTable(
    VOID)
{
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    return pPeb->GdiSharedHandleTable;
}

static
BOOL
GdiReadEntry(
    _In_ HGDIOBJ hobj,
    _Out_ ENTRY_VIEW *pView)
{
    USHORT Index = (ULONG_PTR)hobj & 0xFFFF;
    PENTRY pentHmgr;

#ifndef _WIN64
    PENTRY64 pentHmgr64 = GdiQueryTable64();
    if (pentHmgr64)
    {
        PENTRY64 pentry64 = &pentHmgr64[Index];
        pView->pobj = (LONG64)pentry64->pobj;
        pView->FullUnique = pentry64->FullUnique;
        pView->Objt = pentry64->Objt;
        pView->Flags = pentry64->Flags;
        pView->pUser = pentry64->pUser;
        return TRUE;
    }
#endif

    pentHmgr = GdiQueryTable();
    if (!pentHmgr)
        return FALSE;

    pView->pobj = (LONG_PTR)pentHmgr[Index].einfo.pobj;
    pView->FullUnique = pentHmgr[Index].FullUnique;
    pView->Objt = pentHmgr[Index].Objt;
    pView->Flags = pentHmgr[Index].Flags;
    pView->pUser = (ULONG_PTR)pentHmgr[Index].pUser;
    return TRUE;
}

static
BOOL
GdiIsEntryValid(
    _In_ HGDIOBJ hobj,
    _In_ const ENTRY_VIEW *pView)
{
    return (pView->pobj < 0) &&
           (pView->FullUnique == (USHORT)((ULONG_PTR)hobj >> 16));
}

BOOL
GdiIsHandleValid(
    _In_ HGDIOBJ hobj)
{
    ENTRY_VIEW View;

    return GdiReadEntry(hobj, &View) && GdiIsEntryValid(hobj, &View);
}

BOOL
GdiIsHandleValidEx(
    _In_ HGDIOBJ hobj,
    _In_ GDILOOBJTYPE ObjectType)
{
    ENTRY_VIEW View;

    if (!GdiReadEntry(hobj, &View) || !GdiIsEntryValid(hobj, &View) ||
        (View.Objt != (UCHAR)(ObjectType >> 16)) ||
        (View.Flags != (UCHAR)(ObjectType >> 24)))
    {
        return FALSE;
    }

    return TRUE;
}

PVOID
GdiGetHandleUserData(
    _In_ HGDIOBJ hobj)
{
    ENTRY_VIEW View;

    if (!GdiReadEntry(hobj, &View) || !GdiIsEntryValid(hobj, &View))
    {
        return NULL;
    }

    /* A WoW64 process gets its user mode attributes below 4 GB */
    return (PVOID)(ULONG_PTR)View.pUser;
}

VOID
PrintAvailableDisplayModes(void)
{
    DEVMODEW dm = { .dmSize = sizeof(dm) };
    ULONG iMode = 0;

    printf("Available display modes:\n");
    while (EnumDisplaySettingsW(NULL, iMode++, &dm))
    {
        printf("  %ux%u @ %u bpp, freq: %u Hz\n",
               dm.dmPelsWidth, dm.dmPelsHeight, dm.dmBitsPerPel, dm.dmDisplayFrequency);
    }
}

BOOL
ChangeScreenBpp(
    _In_ ULONG cBitsPixel,
    _Out_ PDEVMODEW pdmOld)
{
    DEVMODEW dm = { .dmSize = sizeof(dm) };

    if (!EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dm))
    {
        printf("EnumDisplaySettingsW failed\n");
        return FALSE;
    }

    printf("ChangeScreenBpp(%lu): Old display settings: %ux%u @ %u bpp\n",
           cBitsPixel, dm.dmPelsWidth, dm.dmPelsHeight, dm.dmBitsPerPel);

    *pdmOld = dm;

    if (dm.dmBitsPerPel != cBitsPixel)
    {
        dm.dmBitsPerPel = cBitsPixel;
        if (ChangeDisplaySettingsW(&dm, 0) != DISP_CHANGE_SUCCESSFUL)
        {
            printf("Failed to change display settings.\n");
            PrintAvailableDisplayModes();
            return FALSE;
        }
    }

    EnumDisplaySettingsW(NULL, ENUM_CURRENT_SETTINGS, &dm);
    printf("ChangeScreenBpp(%lu): New display settings: %ux%u @ %u bpp\n",
           cBitsPixel, dm.dmPelsWidth, dm.dmPelsHeight, dm.dmBitsPerPel);

    return TRUE;
}

#define FL_INVERT_COLORS 0x01
#define FL_RED_BLUE 0x02

static
BOOL
InitPerBitDepth(
    _In_ ULONG cBitsPerPixel,
    _In_ ULONG cx,
    _In_ ULONG cy,
    _Out_opt_ HBITMAP *phbmpDDB,
    _Out_ HDC *phdcDIB,
    _Out_ HBITMAP *phbmpDIB,
    _Out_ PVOID *ppvBits,
    _In_ ULONG flags)
{
    struct
    {
        BITMAPINFOHEADER bmiHeader;
        ULONG bmiColors[256];
    } bmiBuffer;
    LPBITMAPINFO pbmi = (LPBITMAPINFO)&bmiBuffer;

    if (phbmpDDB != NULL)
    {
        /* Create a bitmap */
        *phbmpDDB = CreateBitmap(cx, cy, 1, cBitsPerPixel, NULL);
        if (*phbmpDDB == NULL)
        {
            printf("CreateBitmap failed %lu\n", cBitsPerPixel);
            return FALSE;
        }
    }

    /* Setup bitmap info */
    memset(&bmiBuffer, 0, sizeof(bmiBuffer));
    pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    pbmi->bmiHeader.biWidth = cx;
    pbmi->bmiHeader.biHeight = -(LONG)cy;
    pbmi->bmiHeader.biPlanes = 1;
    pbmi->bmiHeader.biBitCount = cBitsPerPixel;
    pbmi->bmiHeader.biCompression = BI_RGB;
    pbmi->bmiHeader.biSizeImage = 0;
    pbmi->bmiHeader.biXPelsPerMeter = 0;
    pbmi->bmiHeader.biYPelsPerMeter = 0;
    pbmi->bmiHeader.biClrUsed = 0;
    pbmi->bmiHeader.biClrImportant = 0;

    if (cBitsPerPixel == 1)
    {
        if (flags & FL_RED_BLUE)
        {
            bmiBuffer.bmiColors[0] = RGB(0xFF, 0x00, 0x00);
            bmiBuffer.bmiColors[1] = RGB(0x00, 0x00, 0xFF);
        }
        else if (flags & FL_INVERT_COLORS)
        {
            bmiBuffer.bmiColors[0] = 0xFFFFFF;
            bmiBuffer.bmiColors[1] = 0;
        }
        else
        {
            bmiBuffer.bmiColors[0] = 0;
            bmiBuffer.bmiColors[1] = 0xFFFFFF;
        }
        pbmi->bmiHeader.biClrUsed = 2;
    }

    /* Create a compatible DC for the DIB */
    *phdcDIB = CreateCompatibleDC(0);
    if (*phdcDIB == NULL)
    {
        printf("CreateCompatibleDC failed %lu\n", cBitsPerPixel);
        return FALSE;
    }

    /* Create the DIB section with the same values */
    *phbmpDIB = CreateDIBSection(*phdcDIB, pbmi, DIB_RGB_COLORS, ppvBits, 0, 0 );
    if (*phbmpDIB == NULL)
    {
        printf("CreateDIBSection failed. %lu\n", cBitsPerPixel);
        return FALSE;
    }

    if (SelectObject(*phdcDIB, *phbmpDIB) == NULL)
    {
        printf("SelectObject failed for %lu bpp DIB\n", cBitsPerPixel);
        return FALSE;
    }

    return TRUE;
}

BOOL GdiToolsInit(void)
{
    /* Initialize a logical palette */
    ghpal = CreatePalette((LOGPALETTE*)&gpal);
    if (!ghpal)
    {
        printf("failed to create a palette\n");
        return FALSE;
    }

    if (!InitPerBitDepth(1, 9, 9, &ghbmp1, &ghdcDIB1, &ghbmpDIB1, &gpvDIB1, 0) ||
        !InitPerBitDepth(1, 9, 9, NULL, &ghdcDIB1_InvCol, &ghbmpDIB1_InvCol, &gpvDIB1_InvCol, FL_INVERT_COLORS) ||
        !InitPerBitDepth(1, 9, 9, NULL, &ghdcDIB1_RB, &ghbmpDIB1_RB, &gpvDIB1_RB, FL_RED_BLUE) ||
        !InitPerBitDepth(4, 5, 5, &ghbmp4, &ghdcDIB4, &ghbmpDIB4, &gpvDIB4, 0) ||
        !InitPerBitDepth(8, 5, 5, &ghbmp8, &ghdcDIB8, &ghbmpDIB8, &gpvDIB8, 0) ||
        !InitPerBitDepth(16, 8, 8, &ghbmp16, &ghdcDIB16, &ghbmpDIB16, &gpvDIB16, 0) ||
        !InitPerBitDepth(24, 8, 8, &ghbmp24, &ghdcDIB24, &ghbmpDIB24, &gpvDIB24, 0) ||
        !InitPerBitDepth(32, 8, 8, &ghbmp32, &ghdcDIB32, &ghbmpDIB32, &gpvDIB32, 0))
    {
        printf("failed to create objects\n");
        return FALSE;
    }

    gpDIB32 = gpvDIB32;

    /* Create an Info-DC */
    ghdcInfo = CreateDCW(L"DISPLAY", NULL, NULL, NULL);
    if (!ghdcInfo)
    {
        printf("failed to create info DC\n");
        return FALSE;
    }

    return TRUE;
}
