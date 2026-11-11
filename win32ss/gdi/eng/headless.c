/*
 * PROJECT:     ReactOS Win32k subsystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Display driver of a session without the console: the screen is memory
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A session that does not own the console (NitroSessions) has no display device of its own: the video
 * device belongs to the console session. Its win32k gets one virtual graphics device instead, driven by
 * this built-in driver, with one fixed mode. The screen surface is an engine-managed bitmap: every drawing
 * call is done by the engine in memory, and nothing reaches a device.
 */

#include <win32k.h>
#define NDEBUG
#include <debug.h>

#define HEADLESS_WIDTH      1024
#define HEADLESS_HEIGHT     768
#define HEADLESS_BPP        32
#define HEADLESS_TAG        'dlHG'

typedef struct _HEADLESS_PDEV
{
    HDEV hdev;
    HSURF hsurf;
    HPALETTE hpal;
} HEADLESS_PDEV, *PHEADLESS_PDEV;

static LOGFONTW HeadlessSystemFont = { 16, 7, 0, 0, 700, 0, 0, 0, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, VARIABLE_PITCH | FF_DONTCARE, L"System" };
static LOGFONTW HeadlessAnsiVariableFont = { 12, 9, 0, 0, 400, 0, 0, 0, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_STROKE_PRECIS, PROOF_QUALITY, VARIABLE_PITCH | FF_DONTCARE, L"MS Sans Serif" };
static LOGFONTW HeadlessAnsiFixedFont = { 12, 9, 0, 0, 400, 0, 0, 0, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_STROKE_PRECIS, PROOF_QUALITY, FIXED_PITCH | FF_DONTCARE, L"Courier" };

/* The one mode */
VOID
HeadlessFillMode(
    _Out_ PDEVMODEW pdm)
{
    RtlZeroMemory(pdm, sizeof(*pdm));
    RtlStringCbCopyW(pdm->dmDeviceName, sizeof(pdm->dmDeviceName), L"headless");
    pdm->dmSpecVersion = DM_SPECVERSION;
    pdm->dmDriverVersion = DM_SPECVERSION;
    pdm->dmSize = sizeof(*pdm);
    pdm->dmBitsPerPel = HEADLESS_BPP;
    pdm->dmPelsWidth = HEADLESS_WIDTH;
    pdm->dmPelsHeight = HEADLESS_HEIGHT;
    pdm->dmDisplayFrequency = 60;
    pdm->dmLogPixels = 96;
    pdm->dmFields = DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY | DM_LOGPIXELS;
}

static
DHPDEV
APIENTRY
HeadlessEnablePDEV(
    _In_ PDEVMODEW pdm,
    _In_ LPWSTR pwszLogAddress,
    _In_ ULONG cPat,
    _Out_ HSURF *phsurfPatterns,
    _In_ ULONG cjCaps,
    _Out_ ULONG *pdevcaps,
    _In_ ULONG cjDevInfo,
    _Out_ DEVINFO *pdi,
    _In_ HDEV hdev,
    _In_ LPWSTR pwszDeviceName,
    _In_ HANDLE hDriver)
{
    PHEADLESS_PDEV ppdev;
    GDIINFO GdiInfo;
    DEVINFO DevInfo;

    UNREFERENCED_PARAMETER(pdm);
    UNREFERENCED_PARAMETER(pwszLogAddress);
    UNREFERENCED_PARAMETER(cPat);
    UNREFERENCED_PARAMETER(phsurfPatterns);
    UNREFERENCED_PARAMETER(hdev);
    UNREFERENCED_PARAMETER(pwszDeviceName);
    UNREFERENCED_PARAMETER(hDriver);

    ppdev = EngAllocMem(FL_ZERO_MEMORY, sizeof(*ppdev), HEADLESS_TAG);
    if (!ppdev) return NULL;

    ppdev->hpal = EngCreatePalette(PAL_BITFIELDS, 0, NULL, 0xFF0000, 0x00FF00, 0x0000FF);
    if (!ppdev->hpal)
    {
        EngFreeMem(ppdev);
        return NULL;
    }

    RtlZeroMemory(&GdiInfo, sizeof(GdiInfo));
    GdiInfo.ulVersion = GDI_DRIVER_VERSION;
    GdiInfo.ulTechnology = DT_RASDISPLAY;
    GdiInfo.ulHorzSize = 320;
    GdiInfo.ulVertSize = 240;
    GdiInfo.ulHorzRes = HEADLESS_WIDTH;
    GdiInfo.ulVertRes = HEADLESS_HEIGHT;
    GdiInfo.ulPanningHorzRes = HEADLESS_WIDTH;
    GdiInfo.ulPanningVertRes = HEADLESS_HEIGHT;
    GdiInfo.cBitsPixel = HEADLESS_BPP;
    GdiInfo.cPlanes = 1;
    GdiInfo.ulNumColors = (ULONG)-1;
    GdiInfo.ulNumPalReg = 0;
    GdiInfo.ulVRefresh = 60;
    GdiInfo.ulBltAlignment = 1;
    GdiInfo.ulLogPixelsX = 96;
    GdiInfo.ulLogPixelsY = 96;
    GdiInfo.flTextCaps = TC_RA_ABLE;
    GdiInfo.ulDACRed = 8;
    GdiInfo.ulDACGreen = 8;
    GdiInfo.ulDACBlue = 8;
    GdiInfo.ulAspectX = 0x24;
    GdiInfo.ulAspectY = 0x24;
    GdiInfo.ulAspectXY = 0x33;
    GdiInfo.xStyleStep = 1;
    GdiInfo.yStyleStep = 1;
    GdiInfo.denStyleStep = 3;
    GdiInfo.ciDevice.Red.x = 6700;
    GdiInfo.ciDevice.Red.y = 3300;
    GdiInfo.ciDevice.Green.x = 2100;
    GdiInfo.ciDevice.Green.y = 7100;
    GdiInfo.ciDevice.Blue.x = 1400;
    GdiInfo.ciDevice.Blue.y = 800;
    GdiInfo.ciDevice.AlignmentWhite.x = 3127;
    GdiInfo.ciDevice.AlignmentWhite.y = 3290;
    GdiInfo.ciDevice.RedGamma = 20000;
    GdiInfo.ciDevice.GreenGamma = 20000;
    GdiInfo.ciDevice.BlueGamma = 20000;
    GdiInfo.ulPrimaryOrder = PRIMARY_ORDER_CBA;
    GdiInfo.ulHTPatternSize = HT_PATSIZE_4x4_M;
    GdiInfo.ulHTOutputFormat = HT_FORMAT_32BPP;
    GdiInfo.flHTFlags = HT_FLAG_ADDITIVE_PRIMS;

    RtlZeroMemory(&DevInfo, sizeof(DevInfo));
    DevInfo.flGraphicsCaps = 0;
    DevInfo.lfDefaultFont = HeadlessSystemFont;
    DevInfo.lfAnsiVarFont = HeadlessAnsiVariableFont;
    DevInfo.lfAnsiFixFont = HeadlessAnsiFixedFont;
    DevInfo.iDitherFormat = BMF_32BPP;
    DevInfo.hpalDefault = ppdev->hpal;

    RtlCopyMemory(pdi, &DevInfo, min(sizeof(DEVINFO), cjDevInfo));
    RtlCopyMemory(pdevcaps, &GdiInfo, min(sizeof(GDIINFO), cjCaps));
    return (DHPDEV)ppdev;
}

static
VOID
APIENTRY
HeadlessCompletePDEV(
    _In_ DHPDEV dhpdev,
    _In_ HDEV hdev)
{
    ((PHEADLESS_PDEV)dhpdev)->hdev = hdev;
}

static
VOID
APIENTRY
HeadlessDisablePDEV(
    _In_ DHPDEV dhpdev)
{
    PHEADLESS_PDEV ppdev = (PHEADLESS_PDEV)dhpdev;

    EngDeletePalette(ppdev->hpal);
    EngFreeMem(ppdev);
}

static
HSURF
APIENTRY
HeadlessEnableSurface(
    _In_ DHPDEV dhpdev)
{
    PHEADLESS_PDEV ppdev = (PHEADLESS_PDEV)dhpdev;
    SIZEL Size = { HEADLESS_WIDTH, HEADLESS_HEIGHT };
    HBITMAP hbm;

    /* Memory the engine draws into, cleared to black */
    hbm = EngCreateBitmap(Size, HEADLESS_WIDTH * (HEADLESS_BPP / 8), BMF_32BPP, BMF_TOPDOWN, NULL);
    if (!hbm) return NULL;

    if (!EngAssociateSurface((HSURF)hbm, ppdev->hdev, 0))
    {
        EngDeleteSurface((HSURF)hbm);
        return NULL;
    }

    ppdev->hsurf = (HSURF)hbm;
    return ppdev->hsurf;
}

static
VOID
APIENTRY
HeadlessDisableSurface(
    _In_ DHPDEV dhpdev)
{
    PHEADLESS_PDEV ppdev = (PHEADLESS_PDEV)dhpdev;

    if (ppdev->hsurf) EngDeleteSurface(ppdev->hsurf);
    ppdev->hsurf = NULL;
}

static
BOOL
APIENTRY
HeadlessAssertMode(
    _In_ DHPDEV dhpdev,
    _In_ BOOL bEnable)
{
    UNREFERENCED_PARAMETER(dhpdev);
    UNREFERENCED_PARAMETER(bEnable);
    return TRUE;
}

static
ULONG
APIENTRY
HeadlessGetModes(
    _In_ HANDLE hDriver,
    _In_ ULONG cjSize,
    _Out_opt_ DEVMODEW *pdm)
{
    UNREFERENCED_PARAMETER(hDriver);

    if (!pdm) return sizeof(DEVMODEW);
    if (cjSize < sizeof(DEVMODEW)) return 0;
    HeadlessFillMode(pdm);
    return sizeof(DEVMODEW);
}

static DRVFN gHeadlessDrvFn[] =
{
    { INDEX_DrvEnablePDEV,      (PFN)HeadlessEnablePDEV },
    { INDEX_DrvCompletePDEV,    (PFN)HeadlessCompletePDEV },
    { INDEX_DrvDisablePDEV,     (PFN)HeadlessDisablePDEV },
    { INDEX_DrvEnableSurface,   (PFN)HeadlessEnableSurface },
    { INDEX_DrvDisableSurface,  (PFN)HeadlessDisableSurface },
    { INDEX_DrvAssertMode,      (PFN)HeadlessAssertMode },
    { INDEX_DrvGetModes,        (PFN)HeadlessGetModes },
};

BOOL
APIENTRY
HeadlessEnableDriver(
    _In_ ULONG iEngineVersion,
    _In_ ULONG cj,
    _Inout_bytecount_(cj) PDRVENABLEDATA pded)
{
    UNREFERENCED_PARAMETER(iEngineVersion);

    if (cj < sizeof(DRVENABLEDATA)) return FALSE;
    pded->iDriverVersion = DDI_DRIVER_VERSION_NT5;
    pded->c = RTL_NUMBER_OF(gHeadlessDrvFn);
    pded->pdrvfn = gHeadlessDrvFn;
    return TRUE;
}
