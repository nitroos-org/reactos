#ifndef __WIN32K_DC_H
#define __WIN32K_DC_H

/* Constants ******************************************************************/

/* flFontState */
enum _FONT_STATE
{
    DC_DIRTYFONT_XFORM = 1,
    DC_DIRTYFONT_LFONT = 2,
    DC_UFI_MAPPING     = 4
};

/* fl */
#define DC_FL_PAL_BACK 1

typedef enum _DCFLAGS
{
    DC_DISPLAY           = 0x0001,
    DC_DIRECT            = 0x0002,
    DC_CANCELED          = 0x0004,
    DC_PERMANANT         = 0x0008,
    DC_DIRTY_RAO         = 0x0010,
    DC_ACCUM_WMGR        = 0x0020,
    DC_ACCUM_APP         = 0x0040,
    DC_RESET             = 0x0080,
    DC_SYNCHRONIZEACCESS = 0x0100,
    DC_EPSPRINTINGESCAPE = 0x0200,
    DC_TEMPINFODC        = 0x0400,
    DC_FULLSCREEN        = 0x0800,
    DC_IN_CLONEPDEV      = 0x1000,
    DC_REDIRECTION       = 0x2000,
    DC_SHAREACCESS       = 0x4000,
    DC_REDIR_ATTRDIRTY   = 0x10000, /* NitroOS: the surface changed (GreRedirBindDC); brushes to realize again */
#if DBG
    DC_PREPARED          = 0x8000
#endif
} DCFLAGS;

typedef enum _DCTYPE
{
    DCTYPE_DIRECT = 0,  /* Normal device context */
    DCTYPE_MEMORY = 1,  /* Memory device context */
    DCTYPE_INFO   = 2,  /* Information context   */
} DCTYPE;


/* Type definitions ***********************************************************/

typedef struct _DCLEVEL
{
  HPALETTE          hpal;
  struct _PALETTE  * ppal;
  PVOID             pColorSpace; /* COLORSPACE* */
  LONG              lIcmMode;
  LONG              lSaveDepth;
  DWORD             unk1_00000000;
  HGDIOBJ           hdcSave;
  POINTL            ptlBrushOrigin;
  PBRUSH            pbrFill;
  PBRUSH            pbrLine;
  _Notnull_ struct _LFONT   * plfnt; /* LFONT* (TEXTOBJ*) */
  HGDIOBJ           hPath; /* HPATH */
  FLONG             flPath;
  LINEATTRS         laPath; /* 0x20 bytes */
  PREGION           prgnClip;
  PREGION           prgnMeta;
  COLORADJUSTMENT   ca;
  FLONG             flFontState;
  UNIVERSAL_FONT_ID ufi;
  UNIVERSAL_FONT_ID ufiLoc[4]; /* Local List. */
  UNIVERSAL_FONT_ID *pUFI;
  ULONG             uNumUFIs;
  BOOL              ufiSet;
  FLONG             fl;
  FLONG             flBrush;
  MATRIX            mxWorldToDevice;
  MATRIX            mxDeviceToWorld;
  MATRIX            mxWorldToPage;
  FLOATOBJ          efM11PtoD;
  FLOATOBJ          efM22PtoD;
  FLOATOBJ          efDxPtoD;
  FLOATOBJ          efDyPtoD;
  FLOATOBJ          efM11_TWIPS;
  FLOATOBJ          efM22_TWIPS;
  FLOATOBJ          efPr11;
  FLOATOBJ          efPr22;
  PSURFACE          pSurface;
  SIZE              sizl;
} DCLEVEL, *PDCLEVEL;

/*
 * The DC object structure.
 * See also: https://reactos.org/wiki/Techwiki:Win32k/DC
 */
typedef struct _DC
{
  /* Header for all gdi objects in the handle table.
     Do not (re)move this. */
  BASEOBJECT  BaseObject;

  DHPDEV      dhpdev;   /* <- PDEVOBJ.hPDev DHPDEV for device. */
  DCTYPE      dctype;
  INT         fs;
  PPDEVOBJ    ppdev;
  PVOID       hsem;   /* PERESOURCE aka HSEMAPHORE */
  FLONG       flGraphicsCaps;
  FLONG       flGraphicsCaps2;
  _Notnull_ PDC_ATTR    pdcattr;
  DCLEVEL     dclevel;
  DC_ATTR     dcattr;
  HDC         hdcNext;
  HDC         hdcPrev;
  RECTL       erclClip;
  POINTL      ptlDCOrig;
  RECTL       erclWindow;
  RECTL       erclBounds;
  RECTL       erclBoundsApp;
  PREGION     prgnAPI;
  _Notnull_ PREGION     prgnVis; /* Visible region (must never be 0) */
  PREGION     prgnRao;
  POINTL      ptlFillOrigin;
  EBRUSHOBJ   eboFill;
  EBRUSHOBJ   eboLine;
  EBRUSHOBJ   eboText;
  EBRUSHOBJ   eboBackground;
  HFONT       hlfntCur;
  FLONG       flSimulationFlags;
  LONG        lEscapement;
  PVOID       prfnt;    /* RFONT* */
  XCLIPOBJ    co;       /* CLIPOBJ */
  PVOID       pPFFList; /* PPFF* */
  PVOID       pClrxFormLnk;
  INT         ipfdDevMax;
  ULONG       ulCopyCount;
  PVOID       pSurfInfo;
  POINTL      ptlDoBanding;
  HWND        hwndGlass;  /* the window of a DC that draws to a glass window (glassblt.c), else NULL */
  RECTL       rclGlass;   /* that window's rectangle on the screen */
  PVOID       pvRedir;    /* while fs & DC_REDIRECTION: the redirection record of the window (ntuser/redir.c) */
  RECTL       rclRedirDraw; /* device rectangle of the primitive being drawn into that surface */
} DC;

/*
 * A window DC of a redirected window (NitroRedirection, ntuser/redir.c) stays DCTYPE_DIRECT but draws
 * into the window's redirection surface instead of the screen: no pointer exclusion, no device lock,
 * no re-selection of the primary surface. DC_IS_SCREEN tells the DCs that really draw on the screen.
 */
#define DC_IS_SCREEN(pdc) ((pdc)->dctype == DCTYPE_DIRECT && !((pdc)->fs & DC_REDIRECTION))

/* redirgdi.c (surfaces are used by pointer: their handles have no owner a process can match) */
#define REDIRBIND_OK    0   /* bound as asked */
#define REDIRBIND_BUSY  1   /* the DC is locked by another process for now: binding unchanged */
#define REDIRBIND_GONE  2   /* the DC handle is no longer valid (or not a window DC) */
BOOL NTAPI GreRedirSetDCOrg(_In_ HDC hdc, _In_ LONG x, _In_ LONG y, _In_opt_ PRECTL prcl);
ULONG NTAPI GreRedirBindDC(_In_ HDC hdc, _In_opt_ PVOID pvRedir, _In_opt_ struct _SURFACE *psurf, _Out_ PVOID *ppvOld);
struct _SURFACE *NTAPI GreRedirCreateSurface(_In_ LONG cx, _In_ LONG cy, _In_opt_ struct _SURFACE *psurfOld);
VOID NTAPI GreRedirDeleteSurface(_In_ struct _SURFACE *psurf);
BOOL NTAPI GreRedirPresent(_In_ struct _SURFACE *psurf, _In_ struct _REGION *prgnScreen, _In_ LONG xWnd, _In_ LONG yWnd);
BOOL NTAPI GreRedirSeedFromScreen(_In_ struct _SURFACE *psurf, _In_ struct _REGION *prgnScreen, _In_ LONG xWnd, _In_ LONG yWnd);
BOOL NTAPI GreRedirCopyToDC(_In_ struct _SURFACE *psurf, _In_ HDC hdcDest, _In_ LONG xSrc, _In_ LONG ySrc, _In_ LONG cx, _In_ LONG cy);
/* ntuser/redir.c */
VOID FASTCALL UserRedirMarkDirty(_In_ PVOID pvRedir, _In_opt_ const RECTL *prcl);
// typedef struct _DC *PDC;

extern PDC defaultDCstate;

/* glassblt.c */
VOID NTAPI GlassBackdropInit(VOID);
VOID NTAPI GlassBackdropDrop(HWND hwnd);
BOOL NTAPI GlassBlendSource(PDC pdc, struct _SURFACE *psurfDest, struct _SURFACE *psurfSrc, const RECTL *prcDest, const RECTL *prcSrc, struct _SURFACE **ppsurfOut);
VOID NTAPI GlassBlendDone(struct _SURFACE *psurf);
BOOL NTAPI GlassBackdropPrepare(HWND hwnd, const RECTL *prcWnd);
BOOL NTAPI GlassBackdropCopyTo(HWND hwnd, const RECTL *prcWnd, struct _SURFACE *psurfDst);

/* Internal functions *********************************************************/

/* dcobjs.c */

VOID FASTCALL DC_vUpdateFillBrush(PDC pdc);
VOID FASTCALL DC_vUpdateLineBrush(PDC pdc);
VOID FASTCALL DC_vUpdateTextBrush(PDC pdc);
VOID FASTCALL DC_vUpdateBackgroundBrush(PDC pdc);

HFONT
NTAPI
DC_hSelectFont(
    _In_ PDC pdc,
    _In_ HFONT hlfntNew);

HPALETTE
NTAPI
GdiSelectPalette(
    _In_ HDC hDC,
    _In_ HPALETTE hpal,
    _In_ BOOL ForceBackground);

/* dcutil.c */

COLORREF
FASTCALL
IntGdiSetBkColor(
    _In_ HDC hDC,
    _In_ COLORREF Color);

INT FASTCALL IntGdiSetBkMode(HDC  hDC, INT  backgroundMode);
COLORREF FASTCALL  IntGdiSetTextColor(HDC hDC, COLORREF color);
UINT FASTCALL IntGdiSetTextAlign(HDC  hDC, UINT  Mode);
VOID FASTCALL DCU_SetDcUndeletable(HDC);
BOOL FASTCALL IntSetDefaultRegion(PDC);
ULONG TranslateCOLORREF(PDC pdc, COLORREF crColor);
int FASTCALL GreSetStretchBltMode(HDC hdc, int iStretchMode);
int FASTCALL GreGetBkMode(HDC);
int FASTCALL GreGetMapMode(HDC);
COLORREF FASTCALL GreGetTextColor(HDC);
COLORREF FASTCALL GreGetBkColor(HDC);
COLORREF FASTCALL IntSetDCBrushColor(HDC,COLORREF);
COLORREF FASTCALL IntSetDCPenColor(HDC,COLORREF);
int FASTCALL GreGetGraphicsMode(HDC);
BOOL FASTCALL GreSetBrushOrg(HDC,INT,INT,LPPOINT);

CODE_SEG("INIT") NTSTATUS NTAPI InitDcImpl(VOID);
PPDEVOBJ FASTCALL IntEnumHDev(VOID);
PDC NTAPI DC_AllocDcWithHandle(GDILOOBJTYPE eDcObjType);
BOOL NTAPI DC_bAllocDcAttr(PDC pdc);
VOID NTAPI DC_vCleanup(PVOID ObjectBody);
BOOL FASTCALL IntGdiDeleteDC(HDC, BOOL);

BOOL FASTCALL DC_InvertXform(const XFORM *xformSrc, XFORM *xformDest);
VOID FASTCALL DC_vUpdateViewportExt(PDC pdc);
VOID FASTCALL DC_vCopyState(PDC pdcSrc, PDC pdcDst, BOOL To);
VOID FASTCALL DC_vFinishBlit(PDC pdc1, PDC pdc2);
VOID FASTCALL DC_vPrepareDCsForBlit(PDC pdcDest, const RECT* rcDest, PDC pdcSrc, const RECT* rcSrc);
/* DC_vPrepareDCsForBlitEx flags: the caller removes the pointer itself around the part of the blit that reaches it;
 * the destination only reaches what lies inside the DC clip object (it draws through pdc->co), as the engine call in
 * question treats the clip object (CLIPLIM_*, see DC_vGetClipLimit) */
#define DCPREP_SPLIT_DEST      0x01
#define DCPREP_CLIP_BITBLT     0x02
#define DCPREP_CLIP_ALPHA      0x04
#define DCPREP_CLIP_NOTRIVIAL  0x08
#define DCPREP_CLIP_MASK       0x0E
/* rcDest is exactly what the primitive writes (blits, fills of rectangles and regions, DIB copies): a redirected
   window presents only that; without it the DC's clip bounds count as drawn (lines, shapes, text: they draw past
   their bounding rectangles). DCPREP_READ_ONLY: the destination is only read (GetPixel). */
#define DCPREP_EXACT_DEST      0x10
#define DCPREP_READ_ONLY       0x20
VOID FASTCALL DC_vPrepareDCsForBlitEx(PDC pdcDest, const RECT* rcDest, PDC pdcSrc, const RECT* rcSrc, FLONG fl);
typedef enum _CLIPLIMIT
{
    CLIPLIM_BITBLT,    /* IntEngBitBlt: always clips to the bounds */
    CLIPLIM_ALPHA,     /* IntEngAlphaBlend: empty bounds draw nothing, a DC_TRIVIAL clip with other bounds is not clipped */
    CLIPLIM_NOTRIVIAL  /* IntEngTransparentBlt, IntEngStretchBlt: the bounds of a DC_TRIVIAL clip are ignored */
} CLIPLIMIT;
VOID FASTCALL DC_vGetClipLimit(PDC pdc, CLIPLIMIT kind, RECTL *prcl);

VOID NTAPI DC_vRestoreDC(IN PDC pdc, INT iSaveLevel);
BOOL FASTCALL DC_bSurfaceInSavedState(_In_ PDC pdc, _In_ PSURFACE psurf);
VOID FASTCALL DC_vReleaseSurface(_In_ PDC pdc, _In_opt_ PSURFACE psurf);

VOID NTAPI DC_vFreeDcAttr(PDC pdc);
VOID NTAPI DC_vInitDc(PDC pdc, DCTYPE dctype, PPDEVOBJ ppdev);

HDC FASTCALL IntGdiCreateDisplayDC(HDEV hDev, ULONG DcType, BOOL EmptyDC);
BOOL FASTCALL IntGdiCleanDC(HDC hDC);
VOID FASTCALL IntvGetDeviceCaps(PPDEVOBJ, PDEVCAPS);
VOID FASTCALL IntUpdateBoundsRect(PDC,PRECTL);

BOOL NTAPI GreSetDCOwner(HDC hdc, ULONG ulOwner);
HDC APIENTRY GreCreateCompatibleDC(HDC hdc, BOOL bAltDc);

VOID
NTAPI
DC_vSetBrushOrigin(PDC pdc, LONG x, LONG y);

/*
 * GreRedirBindDC changes the surface of a window DC from any process (and from the frame timer), where
 * the DC's attributes (pdcattr: user-mode memory of the process that owns the DC) must not be touched.
 * It leaves DC_REDIR_ATTRDIRTY; the brushes are marked for realizing again here, where the DC is locked
 * by its owner (or is public, with its attributes in the kernel).
 */
#define DIRTY_DEFAULT (DIRTY_CHARSET | DIRTY_BACKGROUND | DIRTY_TEXT | DIRTY_LINE | DIRTY_FILL)

FORCEINLINE
VOID
DC_vApplyRedirAttrDirty(PDC pdc)
{
    if (pdc->fs & DC_REDIR_ATTRDIRTY)
    {
        /* The lock checks the owner before it waits: the DC may belong to another process by now
         * (GreSetDCOwner while this thread waited). Its owner applies the mark then. */
        if (pdc->pdcattr != &pdc->dcattr && GreGetObjectOwner(pdc->BaseObject.hHmgr) != GDI_OBJ_HMGR_POWNED)
            return;
        pdc->fs &= ~DC_REDIR_ATTRDIRTY;
        /* As DC_vUpdateDC did for a surface change */
        pdc->pdcattr->ulDirty_ |= DIRTY_DEFAULT;
    }
}

FORCEINLINE
PDC
DC_LockDc(HDC hdc)
{
    PDC pdc;

    pdc = (PDC)GDIOBJ_LockObject(hdc, GDIObjType_DC_TYPE);
    if (pdc)
    {
        ASSERT((GDI_HANDLE_GET_TYPE(pdc->BaseObject.hHmgr) == GDILoObjType_LO_DC_TYPE) ||
               (GDI_HANDLE_GET_TYPE(pdc->BaseObject.hHmgr) == GDILoObjType_LO_ALTDC_TYPE));
        ASSERT(pdc->dclevel.plfnt != NULL);
        ASSERT(GDI_HANDLE_GET_TYPE(((POBJ)pdc->dclevel.plfnt)->hHmgr) == GDILoObjType_LO_FONT_TYPE);
        DC_vApplyRedirAttrDirty(pdc);
    }

    return pdc;
}

/* Lock a DC whatever process owns it. Only for the window manager's own
 * bookkeeping of the DCs it hands out: a DC that is in use by another process
 * is owned by that process, and DC_LockDc cannot reach it. Such a DC is not
 * waited for (see GDIOBJ_LockObjectEx): the result is NULL if it stays locked. */
FORCEINLINE
PDC
DC_LockDcAnyOwner(HDC hdc)
{
    PDC pdc;

    pdc = (PDC)GDIOBJ_LockObjectEx(hdc, GDIObjType_DC_TYPE, GDIOBJFLAG_IGNOREPID);
    if (pdc)
    {
        ASSERT((GDI_HANDLE_GET_TYPE(pdc->BaseObject.hHmgr) == GDILoObjType_LO_DC_TYPE) ||
               (GDI_HANDLE_GET_TYPE(pdc->BaseObject.hHmgr) == GDILoObjType_LO_ALTDC_TYPE));
        ASSERT(pdc->dclevel.plfnt != NULL);
        ASSERT(GDI_HANDLE_GET_TYPE(((POBJ)pdc->dclevel.plfnt)->hHmgr) == GDILoObjType_LO_FONT_TYPE);
    }

    return pdc;
}

FORCEINLINE
VOID
DC_UnlockDc(PDC pdc)
{
    ASSERT(pdc->dclevel.plfnt != NULL);
    ASSERT(GDI_HANDLE_GET_TYPE(((POBJ)pdc->dclevel.plfnt)->hHmgr) == GDILoObjType_LO_FONT_TYPE);

    GDIOBJ_vUnlockObject(&pdc->BaseObject);
}

FORCEINLINE
VOID
DC_vSelectSurface(PDC pdc, PSURFACE psurfNew)
{
    PSURFACE psurfOld = pdc->dclevel.pSurface;
    /* The mark of the surface (hdc) is not touched here, see DC_vReleaseSurface */
    if (psurfOld)
        SURFACE_ShareUnlockSurface(psurfOld);
    if (psurfNew)
        GDIOBJ_vReferenceObjectByPointer((POBJ)psurfNew);
    pdc->dclevel.pSurface = psurfNew;
}

FORCEINLINE
VOID
DC_vSelectFillBrush(PDC pdc, PBRUSH pbrFill)
{
    PBRUSH pbrFillOld = pdc->dclevel.pbrFill;
    if (pbrFillOld)
        BRUSH_ShareUnlockBrush(pbrFillOld);
    if (pbrFill)
        GDIOBJ_vReferenceObjectByPointer((POBJ)pbrFill);
    pdc->dclevel.pbrFill = pbrFill;
}

FORCEINLINE
VOID
DC_vSelectLineBrush(PDC pdc, PBRUSH pbrLine)
{
    PBRUSH pbrLineOld = pdc->dclevel.pbrLine;
    if (pbrLineOld)
        BRUSH_ShareUnlockBrush(pbrLineOld);
    if (pbrLine)
        GDIOBJ_vReferenceObjectByPointer((POBJ)pbrLine);
    pdc->dclevel.pbrLine = pbrLine;
}

FORCEINLINE
VOID
DC_vSelectPalette(PDC pdc, PPALETTE ppal)
{
    PPALETTE ppalOld = pdc->dclevel.ppal;
    if (ppalOld)
        PALETTE_ShareUnlockPalette(ppalOld);
    if (ppal)
        GDIOBJ_vReferenceObjectByPointer((POBJ)ppal);
    pdc->dclevel.ppal = ppal;
}

extern _Notnull_ PBRUSH pbrDefaultBrush;
extern _Notnull_ PSURFACE psurfDefaultBitmap;

#define ASSERT_DC_PREPARED(pdc) NT_ASSERT((pdc)->fs & DC_PREPARED)

#endif /* not __WIN32K_DC_H */
