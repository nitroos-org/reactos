/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * PURPOSE:          Clipboard routines
 * FILE:             win32ss/user/ntuser/clipboard.c
 * PROGRAMER:        Filip Navara <xnavara@volny.cz>
 *                   Pablo Borobia <pborobia@gmail.com>
 *                   Rafal Harabien <rafalh@reactos.org>
 */

#include <win32k.h>
DBG_DEFAULT_CHANNEL(UserClipbrd);

#define DATA_DELAYED     (HANDLE)0
#define DATA_SYNTH_USER  (HANDLE)1
#define DATA_SYNTH_KRNL  (HANDLE)2
#define IS_DATA_DELAYED(ce)     ((ce)->hData == DATA_DELAYED)
#define IS_DATA_SYNTHESIZED(ce) ((ce)->hData == DATA_SYNTH_USER || (ce)->hData == DATA_SYNTH_KRNL)

static PWINSTATION_OBJECT FASTCALL
IntGetWinStaForCbAccess(VOID)
{
    HWINSTA hWinSta;
    PWINSTATION_OBJECT pWinStaObj;
    NTSTATUS Status;

    hWinSta = UserGetProcessWindowStation();
    Status = IntValidateWindowStationHandle(hWinSta, UserMode, WINSTA_ACCESSCLIPBOARD, &pWinStaObj, 0);
    if (!NT_SUCCESS(Status))
    {
        ERR("Cannot open winsta\n");
        SetLastNtError(Status);
        return NULL;
    }

    return pWinStaObj;
}

/* If format exists, returns a non-null value (pointing to formated object) */
static PCLIP FASTCALL
IntGetFormatElement(PWINSTATION_OBJECT pWinStaObj, UINT fmt)
{
    DWORD i;

    for (i = 0; i < pWinStaObj->cNumClipFormats; ++i)
    {
        if (pWinStaObj->pClipBase[i].fmt == fmt)
            return &pWinStaObj->pClipBase[i];
    }

    return NULL;
}

static BOOL FASTCALL
IntIsFormatAvailable(PWINSTATION_OBJECT pWinStaObj, UINT fmt)
{
    return IntGetFormatElement(pWinStaObj, fmt) != NULL;
}

static VOID FASTCALL
IntFreeElementData(PCLIP pElement)
{
    if (!IS_DATA_DELAYED(pElement) &&
        !IS_DATA_SYNTHESIZED(pElement))
    {
        if (pElement->fGlobalHandle)
            UserDeleteObject(pElement->hData, TYPE_CLIPDATA);
        else if (pElement->fOwned &&
                 (pElement->fmt == CF_BITMAP          ||
                 pElement->fmt == CF_PALETTE         ||
                 pElement->fmt == CF_DSPBITMAP       ||
                 pElement->fmt == CF_METAFILEPICT    ||
                 pElement->fmt == CF_DSPMETAFILEPICT ||
                 pElement->fmt == CF_DSPENHMETAFILE  ||
                  pElement->fmt == CF_ENHMETAFILE))
        {
            GreSetObjectOwner(pElement->hData, GDI_OBJ_HMGR_POWNED);
            GreDeleteObject(pElement->hData);
        }
    }
}

/* The GDI object type (base type, derived types such as DIB sections masked off) a clipboard
   format carries, 0 when the format is not one the clipboard owns as a GDI object */
static ULONG FASTCALL
IntClipboardGdiType(UINT fmt)
{
    switch (fmt)
    {
        case CF_BITMAP:
        case CF_DSPBITMAP:
            return GDILoObjType_LO_BITMAP_TYPE;
        case CF_PALETTE:
            return GDILoObjType_LO_PALETTE_TYPE;
        /* gdi32 converts metafiles to server metafile objects before it hands them over */
        case CF_METAFILEPICT:
        case CF_DSPMETAFILEPICT:
        case CF_ENHMETAFILE:
        case CF_DSPENHMETAFILE:
            return GDILoObjType_LO_META_TYPE;
    }
    return 0;
}

/* The clipboard deletes the GDI object of these formats when it drops them (IntFreeElementData).
   Windows accepts any handle in SetClipboardData and a DC or a pen given as a bitmap stays alive
   when the clipboard is emptied, so the handle is stored as given, but only an object that is
   what the format carries and that the caller handed over (its own, or a server metafile, which
   is public from its creation) is the clipboard's to delete. Anything else (a DC, a brush, a stale
   or foreign handle, a public object of another process) is never owner-changed or deleted here.
   The handle the format already holds keeps the state it was stored with. */
static BOOL FASTCALL
IntClipboardTakesObject(PWINSTATION_OBJECT pWinStaObj, UINT fmt, HANDLE hData)
{
    ULONG ulType = IntClipboardGdiType(fmt);
    ULONG ulOwner;
    PCLIP pElement;

    if (!ulType || (ULONG_PTR)hData <= 2)
        return FALSE;

    pElement = IntGetFormatElement(pWinStaObj, fmt);
    if (pElement && pElement->hData == hData && !pElement->fGlobalHandle)
        return pElement->fOwned;

    if ((GDI_HANDLE_GET_TYPE(hData) & 0x1f0000) != ulType)
        return FALSE;

    ulOwner = GreGetObjectOwner(hData);
    if (ulOwner == GDI_OBJ_HMGR_POWNED)
        return TRUE;

    return ulOwner == GDI_OBJ_HMGR_PUBLIC && ulType == GDILoObjType_LO_META_TYPE;
}

/* Adds a new format and data to the clipboard */
static PCLIP NTAPI
IntAddFormatedData(PWINSTATION_OBJECT pWinStaObj, UINT fmt, HANDLE hData, BOOLEAN fGlobalHandle, BOOL bEnd)
{
    PCLIP pElement = NULL;

    /* Use existing entry with specified format */
    if (!bEnd)
        pElement = IntGetFormatElement(pWinStaObj, fmt);

    /* Put new entry at the end if nothing was found */
    if (!pElement)
    {
        /* Allocate bigger clipboard if needed. We could use lists but Windows uses array */
        if (pWinStaObj->cNumClipFormats % 4 == 0)
        {
            PCLIP pNewClip;

            /* Allocate new clipboard */
            pNewClip = ExAllocatePoolWithTag(PagedPool,
                                             (pWinStaObj->cNumClipFormats + 4) * sizeof(CLIP),
                                             USERTAG_CLIPBOARD);
            if (!pNewClip)
            {
                EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
                return NULL;
            }

            /* Copy data */
            memcpy(pNewClip, pWinStaObj->pClipBase, pWinStaObj->cNumClipFormats * sizeof(CLIP));

            /* Free old clipboard */
            if (pWinStaObj->pClipBase)
                ExFreePoolWithTag(pWinStaObj->pClipBase, USERTAG_CLIPBOARD);

            /* Update WinSta */
            pWinStaObj->pClipBase = pNewClip;
        }

        /* New element is at the end */
        pElement = &pWinStaObj->pClipBase[pWinStaObj->cNumClipFormats];
        pElement->fmt = fmt;
        pWinStaObj->cNumClipFormats++;
    }
    else if (pElement->hData != hData || pElement->fGlobalHandle != fGlobalHandle)
    {
        /* Storing the handle the format already holds keeps it: freeing it first would leave
           the clipboard with a handle that no longer exists */
        IntFreeElementData(pElement);
    }

    pElement->hData = hData;
    pElement->fGlobalHandle = fGlobalHandle;
    pElement->fOwned = FALSE;

    return pElement;
}

static BOOL FASTCALL
IntIsClipboardOpenByMe(PWINSTATION_OBJECT pWinSta)
{
    /* Check if the current thread has opened the clipboard */
    return (pWinSta->ptiClipLock &&
            pWinSta->ptiClipLock == PsGetCurrentThreadWin32Thread());
}

/* A window registered with AddClipboardFormatListener. The entry holds a reference
   on the window and a back-pointer to the window station it belongs to (the one of the
   window's desktop). All entries live in one list, newest first, so that a window can be
   unregistered when it is freed without going through its desktop (which may already be
   gone) and regardless of the clipboard access of the freeing thread. The list is
   protected by the USER lock. Entries never outlive their window station:
   UserClipboardFreeListeners drains them when it is deleted. */
typedef struct _CLIPBOARD_LISTENER
{
    LIST_ENTRY ListEntry;
    PWND pwnd;
    PWINSTATION_OBJECT pWinSta;
} CLIPBOARD_LISTENER, *PCLIPBOARD_LISTENER;

static LIST_ENTRY gClipboardListenerList = { &gClipboardListenerList, &gClipboardListenerList };

/* Find the entry of a window; pWinSta may be NULL to match any window station */
static PCLIPBOARD_LISTENER FASTCALL
IntFindClipboardListener(PWINSTATION_OBJECT pWinSta, PWND pWindow)
{
    PLIST_ENTRY pEntry;
    PCLIPBOARD_LISTENER pListener;

    for (pEntry = gClipboardListenerList.Flink;
         pEntry != &gClipboardListenerList;
         pEntry = pEntry->Flink)
    {
        pListener = CONTAINING_RECORD(pEntry, CLIPBOARD_LISTENER, ListEntry);
        if (pListener->pwnd == pWindow && (!pWinSta || pListener->pWinSta == pWinSta))
            return pListener;
    }

    return NULL;
}

static VOID FASTCALL
IntFreeClipboardListener(PCLIPBOARD_LISTENER pListener)
{
    RemoveEntryList(&pListener->ListEntry);
    UserDereferenceObject(pListener->pwnd);
    ExFreePoolWithTag(pListener, USERTAG_CLIPBOARD);
}

/* Windows 10 registers only windows of the calling process. For any other window it
   returns ERROR_ACCESS_DENIED as the result without setting the last error and
   without registering it (measured on 22H2, including the desktop window). A window
   outside the caller's window station gets the same answer. */
static BOOL FASTCALL
IntIsClipboardListenerCandidate(PWINSTATION_OBJECT pWinSta, PWND pWindow)
{
    return pWindow->head.pti &&
           pWindow->head.pti->ppi == PsGetCurrentProcessWin32Process() &&
           pWindow->head.rpdesk &&
           pWindow->head.rpdesk->rpwinstaParent == pWinSta;
}

/* A clipboard change is announced as on Windows: WM_DRAWCLIPBOARD (wParam = the
   clipboard owner) to the head of the viewer chain first, then WM_CLIPBOARDUPDATE
   (wParam = number of formats) posted to every listener, newest registration first. */
static VOID FASTCALL
co_IntNotifyClipboardChange(PWINSTATION_OBJECT pWinSta)
{
    PLIST_ENTRY pEntry;
    PCLIPBOARD_LISTENER pListener;
    HWND hWndOwner = NULL;
    DWORD dwLastError;

    if (pWinSta->spwndClipOwner)
        hWndOwner = UserHMGetHandle(pWinSta->spwndClipOwner);

    if (pWinSta->spwndClipViewer)
    {
        TRACE("Clipboard: sending WM_DRAWCLIPBOARD to %p\n", UserHMGetHandle(pWinSta->spwndClipViewer));
        // For 32-bit applications this message is sent as a notification
        co_IntSendMessageNoWait(UserHMGetHandle(pWinSta->spwndClipViewer), WM_DRAWCLIPBOARD, (WPARAM)hWndOwner, 0);
    }

    /* The send above may have called back into user mode, so walk the list only now.
       Posting does not call back: the list cannot change while it is walked. The post
       must not clobber the last error of the caller (CloseClipboard and friends). */
    dwLastError = EngGetLastError();
    for (pEntry = gClipboardListenerList.Flink;
         pEntry != &gClipboardListenerList;
         pEntry = pEntry->Flink)
    {
        pListener = CONTAINING_RECORD(pEntry, CLIPBOARD_LISTENER, ListEntry);
        if (pListener->pWinSta != pWinSta)
            continue;
        if ((pListener->pwnd->state & WNDS_DESTROYED) ||
            (pListener->pwnd->head.pti &&
             (pListener->pwnd->head.pti->TIF_flags & TIF_INCLEANUP)))
            continue;
        UserPostMessage(UserHMGetHandle(pListener->pwnd), WM_CLIPBOARDUPDATE, pWinSta->cNumClipFormats, 0);
    }
    EngSetLastError(dwLastError);
}

/* Creates the clipboard data object that holds a packed image of cbData bytes; the caller
   fills Data and, when it gives the handle up, deletes it with UserDeleteObject */
static PCLIPBOARDDATA FASTCALL
IntCreateClipData(ULONG cbData, HANDLE *phMem)
{
    ULONG cbObject;
    PCLIPBOARDDATA pClipData;

    if (!NT_SUCCESS(RtlULongAdd(cbData, sizeof(CLIPBOARDDATA), &cbObject)))
        return NULL;

    pClipData = (PCLIPBOARDDATA)UserCreateObject(gHandleTable, NULL, NULL, phMem, TYPE_CLIPDATA, cbObject);
    if (!pClipData)
        return NULL;

    /* Release the extra reference (UserCreateObject added 2 references) */
    UserDereferenceObject(pClipData);
    pClipData->cbData = cbData;
    RtlZeroMemory(pClipData->Data, cbData);
    return pClipData;
}

/* The packed image of a bitmap (CF_DIB). Windows gives the header no colour count when the
   table is the full table of the depth. */
static HANDLE FASTCALL
IntSynthesizeDib(HBITMAP hbm)
{
    HDC hdc;
    ULONG cjInfoSize, cjDataSize;
    PCLIPBOARDDATA pClipboardData;
    HANDLE hMem = NULL;
    INT iResult;
    struct
    {
        BITMAPINFOHEADER bmih;
        RGBQUAD rgbColors[256];
    } bmiBuffer;
    PBITMAPINFO pbmi = (PBITMAPINFO)&bmiBuffer;

    /* Get the display DC */
    hdc = UserGetDCEx(NULL, NULL, DCX_USESTYLE);
    if (!hdc)
        return NULL;

    /* Get information about the bitmap format */
    memset(&bmiBuffer, 0, sizeof(bmiBuffer));
    pbmi->bmiHeader.biSize = sizeof(bmiBuffer.bmih);
    iResult = GreGetDIBitsInternal(hdc, hbm, 0, 0, NULL, pbmi, DIB_RGB_COLORS, 0, sizeof(bmiBuffer));
    if (iResult == 0)
        goto cleanup;

    /* Get the size for a full BITMAPINFO */
    cjInfoSize = DIB_BitmapInfoSize(pbmi, DIB_RGB_COLORS);

    /* The packed DIB; the sum must be overflow-checked before it sizes the allocation */
    if (!NT_SUCCESS(RtlULongAdd(cjInfoSize, pbmi->bmiHeader.biSizeImage, &cjDataSize)))
        goto cleanup;

    pClipboardData = IntCreateClipData(cjDataSize, &hMem);
    if (!pClipboardData)
        goto cleanup;

    /* Copy the BITMAPINFOHEADER */
    memcpy(pClipboardData->Data, pbmi, sizeof(BITMAPINFOHEADER));

    /* Get the bitmap bits and the color table */
    iResult = GreGetDIBitsInternal(hdc,
                                   hbm,
                                   0,
                                   abs(pbmi->bmiHeader.biHeight),
                                   (LPBYTE)pClipboardData->Data + cjInfoSize,
                                   (LPBITMAPINFO)pClipboardData->Data,
                                   DIB_RGB_COLORS,
                                   pbmi->bmiHeader.biSizeImage,
                                   cjInfoSize);
    {
        PBITMAPINFOHEADER pbih = (PBITMAPINFOHEADER)pClipboardData->Data;
        if (pbih->biBitCount <= 8 && pbih->biClrUsed == (1UL << pbih->biBitCount))
            pbih->biClrUsed = 0;
    }

cleanup:
    UserReleaseDC(NULL, hdc, FALSE);
    return hMem;
}

/* The header of a packed image taken from the clipboard is application data. Windows
   converts it (measured on Windows Server 2022) only when:
   - the header is the size the format has: 12 (core) or 40 for CF_DIB, 108 or 124 for CF_DIBV5,
     and the block holds all of it;
   - the block holds the colour table and the bits the header describes (for the uncompressed
     layouts; biSizeImage is not trusted);
   - the width is not negative and the height is not the most negative number;
   - for a bitmap (GDI has to make one): width above 0, height not 0, planes not 0, and a depth
     and layout GDI has: 1, 4, 8, 16, 24, 32 bits uncompressed (bit fields only at 16 and 32), run
     length at 8 or 4 bits, JPEG or PNG at depth 0.
   Everything else is refused here and GDI never sees it. */
static BOOL FASTCALL
IntClipDibValidate(PCLIPBOARDDATA pMemObj, BOOL bV5Source, BOOL bForBitmap)
{
    ULONG cb = pMemObj->cbData;
    PBITMAPINFOHEADER pbih = (PBITMAPINFOHEADER)pMemObj->Data;
    ULONG biSize, cbInfo;
    ULONGLONG cbImage = 0, cbNeeded;
    LONG lHeight, lWidth;
    WORD wBpp;

    if (cb < sizeof(DWORD))
        return FALSE;

    biSize = pbih->biSize;
    if (bV5Source)
    {
        if (biSize != sizeof(BITMAPV4HEADER) && biSize != sizeof(BITMAPV5HEADER))
            return FALSE;
    }
    else if (biSize != sizeof(BITMAPCOREHEADER) && biSize != sizeof(BITMAPINFOHEADER))
        return FALSE;

    /* the whole header it announces */
    if (cb < biSize)
        return FALSE;

    if (biSize == sizeof(BITMAPCOREHEADER))
    {
        PBITMAPCOREHEADER pch = (PBITMAPCOREHEADER)pMemObj->Data;

        if (pch->bcWidth == 0 || pch->bcHeight == 0 || pch->bcPlanes != 1 ||
            (pch->bcBitCount != 1 && pch->bcBitCount != 4 && pch->bcBitCount != 8 && pch->bcBitCount != 24))
            return FALSE;
        cbInfo = sizeof(BITMAPCOREHEADER) + ((pch->bcBitCount <= 8) ? (3UL << pch->bcBitCount) : 0);
        cbImage = (((ULONGLONG)pch->bcWidth * pch->bcBitCount + 31) / 32) * 4 * pch->bcHeight;
        return (ULONGLONG)cbInfo + cbImage <= cb;
    }

    lWidth = pbih->biWidth;
    lHeight = pbih->biHeight;
    wBpp = pbih->biBitCount;
    if (lWidth < 0 || lHeight == (-2147483647L - 1))
        return FALSE;

    if (bForBitmap)
    {
        if (lWidth == 0 || lHeight == 0 || pbih->biPlanes == 0)
            return FALSE;

        switch (pbih->biCompression)
        {
            case BI_RGB:
                if (wBpp != 1 && wBpp != 4 && wBpp != 8 && wBpp != 16 && wBpp != 24 && wBpp != 32)
                    return FALSE;
                break;
            case BI_BITFIELDS:
                if (wBpp != 16 && wBpp != 32)
                    return FALSE;
                break;
            case BI_RLE8:
                if (wBpp != 8)
                    return FALSE;
                break;
            case BI_RLE4:
                if (wBpp != 4)
                    return FALSE;
                break;
            case BI_JPEG:
            case BI_PNG:
                if (wBpp != 0)
                    return FALSE;
                break;
            default:
                return FALSE;
        }

        /* GDI makes a device bitmap of up to 32 bits per pixel from it, however few bytes the block
           holds (run length and the compressed layouts decode into it), and sizes its rows in 32 bits:
           a width of 2^27 pixels or more wraps that size and the decoder then writes past the bitmap.
           The size of the image must be one GDI can create (1 GiB at 32 bits per pixel at most). */
        if (lWidth > 0x1000000 || (ULONGLONG)lWidth * (ULONGLONG)(lHeight < 0 ? -(LONGLONG)lHeight : (LONGLONG)lHeight) > 0x10000000)
            return FALSE;
    }

    /* the colour table, the masks and the bits of an uncompressed image must be in the block */
    cbInfo = DIB_BitmapInfoSize((PBITMAPINFO)pbih, DIB_RGB_COLORS);
    if (cbInfo > cb)
        return FALSE;
    if ((pbih->biCompression == BI_RGB || pbih->biCompression == BI_BITFIELDS) && wBpp != 0)
    {
        cbImage = (((ULONGLONG)lWidth * wBpp + 31) / 32) * 4;
        /* one row must fit the block; this also keeps the product below from wrapping
           (a row of up to 2^47 bytes times a height of up to 2^31 would) */
        if (lHeight != 0 && cbImage > cb)
            return FALSE;
        cbImage *= (ULONGLONG)(lHeight < 0 ? -(LONGLONG)lHeight : (LONGLONG)lHeight);
    }
    cbNeeded = (ULONGLONG)cbInfo + cbImage;
    return cbNeeded <= cb;
}

/* The bitmap of a packed image (CF_DIB or CF_DIBV5 data); NULL when it is not one GDI can make */
static HBITMAP FASTCALL
IntSynthesizeBitmap(PCLIPBOARDDATA pMemObj, BOOL bV5Source)
{
    HDC hdc = NULL;
    PBITMAPINFO pBmi, pConvertedBmi = NULL;
    HBITMAP hBm = NULL;
    ULONG Offset;

    if (!IntClipDibValidate(pMemObj, bV5Source, TRUE))
        return NULL;

    pBmi = (BITMAPINFO*)pMemObj->Data;

    pConvertedBmi = DIB_ConvertBitmapInfo(pBmi, DIB_RGB_COLORS);
    if (!pConvertedBmi)
        goto cleanup;

    Offset = DIB_BitmapInfoSize(pBmi, DIB_RGB_COLORS);
    if (Offset > pMemObj->cbData)
        goto cleanup;

    hdc = UserGetDCEx(NULL, NULL, DCX_USESTYLE);
    if (!hdc)
        goto cleanup;

    hBm = GreCreateDIBitmapInternal(hdc,
                                    pConvertedBmi->bmiHeader.biWidth,
                                    pConvertedBmi->bmiHeader.biHeight,
                                    CBM_INIT,
                                    pMemObj->Data + Offset,
                                    pConvertedBmi,
                                    DIB_RGB_COLORS,
                                    0,
                                    pMemObj->cbData - Offset,
                                    0);

    if (hBm)
        GreSetObjectOwner(hBm, GDI_OBJ_HMGR_PUBLIC);

cleanup:
    if (hdc)
        UserReleaseDC(NULL, hdc, FALSE);

    if (pConvertedBmi)
        DIB_FreeConvertedBitmapInfo(pConvertedBmi, pBmi, -1);

    return hBm;
}

/* The CF_DIBV5 of a CF_DIB: a version 5 header made from the 40 byte one (sRGB colour space,
   intent "images", masks copied into the header when the layout has them), then everything
   that followed the old header (bit field masks, colour table, bits), as Windows does */
static HANDLE FASTCALL
IntSynthesizeDibV5(PCLIPBOARDDATA pDib)
{
    PBITMAPINFOHEADER pbih = (PBITMAPINFOHEADER)pDib->Data;
    PBITMAPV5HEADER pv5;
    PCLIPBOARDDATA pNew;
    HANDLE hMem;
    ULONG cbTail, cbNew;

    if (pDib->cbData < sizeof(BITMAPINFOHEADER) || pbih->biSize != sizeof(BITMAPINFOHEADER) ||
        !IntClipDibValidate(pDib, FALSE, FALSE))
        return NULL;

    cbTail = pDib->cbData - sizeof(BITMAPINFOHEADER);
    if (!NT_SUCCESS(RtlULongAdd(sizeof(BITMAPV5HEADER), cbTail, &cbNew)))
        return NULL;

    pNew = IntCreateClipData(cbNew, &hMem);
    if (!pNew)
        return NULL;

    pv5 = (PBITMAPV5HEADER)pNew->Data;
    pv5->bV5Size = sizeof(BITMAPV5HEADER);
    pv5->bV5Width = pbih->biWidth;
    pv5->bV5Height = pbih->biHeight;
    pv5->bV5Planes = pbih->biPlanes;
    pv5->bV5BitCount = pbih->biBitCount;
    pv5->bV5Compression = pbih->biCompression;
    pv5->bV5SizeImage = pbih->biSizeImage;
    pv5->bV5XPelsPerMeter = pbih->biXPelsPerMeter;
    pv5->bV5YPelsPerMeter = pbih->biYPelsPerMeter;
    pv5->bV5ClrUsed = pbih->biClrUsed;
    pv5->bV5ClrImportant = pbih->biClrImportant;
    if (pbih->biCompression == BI_BITFIELDS && cbTail >= 3 * sizeof(DWORD))
    {
        DWORD *pdwMask = (DWORD *)(pDib->Data + sizeof(BITMAPINFOHEADER));
        pv5->bV5RedMask = pdwMask[0];
        pv5->bV5GreenMask = pdwMask[1];
        pv5->bV5BlueMask = pdwMask[2];
    }
    pv5->bV5CSType = LCS_sRGB;
    pv5->bV5Intent = LCS_GM_IMAGES;
    RtlCopyMemory(pNew->Data + sizeof(BITMAPV5HEADER), pDib->Data + sizeof(BITMAPINFOHEADER), cbTail);
    return hMem;
}

/* The CF_DIB of a CF_DIBV5. Windows refuses a header with the "calibrated RGB" colour space
   (nothing says how to calibrate it): ERROR_TAG_NOT_FOUND there, no data here. */
static HANDLE FASTCALL
IntSynthesizeDibFromV5(PCLIPBOARDDATA pV5)
{
    PBITMAPV5HEADER pv5 = (PBITMAPV5HEADER)pV5->Data;
    PBITMAPINFOHEADER pbih;
    PCLIPBOARDDATA pNew;
    HANDLE hMem;
    ULONG cbTail, cbMasks, cbNew;

    if (pV5->cbData < sizeof(BITMAPV5HEADER) || pv5->bV5Size != sizeof(BITMAPV5HEADER) ||
        !IntClipDibValidate(pV5, TRUE, FALSE))
        return NULL;
    if (pv5->bV5CSType == LCS_CALIBRATED_RGB)
    {
        EngSetLastError(ERROR_TAG_NOT_FOUND);
        return NULL;
    }

    cbMasks = (pv5->bV5Compression == BI_BITFIELDS) ? 3 * sizeof(DWORD) : 0;
    cbTail = pV5->cbData - sizeof(BITMAPV5HEADER);
    if (!NT_SUCCESS(RtlULongAdd(sizeof(BITMAPINFOHEADER) + cbMasks, cbTail, &cbNew)))
        return NULL;

    pNew = IntCreateClipData(cbNew, &hMem);
    if (!pNew)
        return NULL;

    pbih = (PBITMAPINFOHEADER)pNew->Data;
    pbih->biSize = sizeof(BITMAPINFOHEADER);
    pbih->biWidth = pv5->bV5Width;
    pbih->biHeight = pv5->bV5Height;
    pbih->biPlanes = pv5->bV5Planes;
    pbih->biBitCount = pv5->bV5BitCount;
    pbih->biCompression = pv5->bV5Compression;
    pbih->biSizeImage = pv5->bV5SizeImage;
    pbih->biXPelsPerMeter = pv5->bV5XPelsPerMeter;
    pbih->biYPelsPerMeter = pv5->bV5YPelsPerMeter;
    pbih->biClrUsed = pv5->bV5ClrUsed;
    pbih->biClrImportant = pv5->bV5ClrImportant;
    if (cbMasks)
    {
        DWORD *pdwMask = (DWORD *)(pNew->Data + sizeof(BITMAPINFOHEADER));
        pdwMask[0] = pv5->bV5RedMask;
        pdwMask[1] = pv5->bV5GreenMask;
        pdwMask[2] = pv5->bV5BlueMask;
    }
    RtlCopyMemory(pNew->Data + sizeof(BITMAPINFOHEADER) + cbMasks, pV5->Data + sizeof(BITMAPV5HEADER), cbTail);
    return hMem;
}

static VOID NTAPI
IntAddSynthesizedFormats(PWINSTATION_OBJECT pWinStaObj)
{
    BOOL bHaveText, bHaveUniText, bHaveOemText, bHaveLocale, bHaveBm, bHaveDib, bHaveDibV5, bHaveMFP, bHaveEMF;

    bHaveText = IntIsFormatAvailable(pWinStaObj, CF_TEXT);
    bHaveOemText = IntIsFormatAvailable(pWinStaObj, CF_OEMTEXT);
    bHaveUniText = IntIsFormatAvailable(pWinStaObj, CF_UNICODETEXT);
    bHaveLocale = IntIsFormatAvailable(pWinStaObj, CF_LOCALE);
    bHaveBm = IntIsFormatAvailable(pWinStaObj, CF_BITMAP);
    bHaveDib = IntIsFormatAvailable(pWinStaObj, CF_DIB);
    bHaveDibV5 = IntIsFormatAvailable(pWinStaObj, CF_DIBV5);
    bHaveMFP = IntIsFormatAvailable(pWinStaObj, CF_METAFILEPICT);
    bHaveEMF = IntIsFormatAvailable(pWinStaObj, CF_ENHMETAFILE);

    /* Add CF_LOCALE format if we have CF_TEXT, CF_OEMTEXT or CF_UNICODETEXT */
    if (!bHaveLocale && (bHaveText || bHaveOemText || bHaveUniText))
    {
        PCLIPBOARDDATA pMemObj;
        HANDLE hMem;

        pMemObj = (PCLIPBOARDDATA)UserCreateObject(gHandleTable, NULL, NULL, &hMem, TYPE_CLIPDATA,
                                                   sizeof(CLIPBOARDDATA) + sizeof(LCID));
        if (pMemObj)
        {
            pMemObj->cbData = sizeof(LCID);
            *((LCID*)pMemObj->Data) = NtCurrentTeb()->CurrentLocale;
            IntAddFormatedData(pWinStaObj, CF_LOCALE, hMem, TRUE, TRUE);

            /* Release the extra reference (UserCreateObject added 2 references) */
            UserDereferenceObject(pMemObj);
        }
    }

    /* Add CF_TEXT. Note: it is synthesized in user32.dll */
    if (!bHaveText && (bHaveUniText || bHaveOemText))
        IntAddFormatedData(pWinStaObj, CF_TEXT, DATA_SYNTH_USER, FALSE, TRUE);

    /* Add CF_OEMTEXT. Note: it is synthesized in user32.dll */
    if (!bHaveOemText && (bHaveUniText || bHaveText))
        IntAddFormatedData(pWinStaObj, CF_OEMTEXT, DATA_SYNTH_USER, FALSE, TRUE);

    /* Add CF_UNICODETEXT. Note: it is synthesized in user32.dll */
    if (!bHaveUniText && (bHaveText || bHaveOemText))
        IntAddFormatedData(pWinStaObj, CF_UNICODETEXT, DATA_SYNTH_USER, FALSE, TRUE);

    /* The three image formats stand for each other: whichever of CF_BITMAP, CF_DIB and
       CF_DIBV5 the clipboard holds (delayed or not), the missing ones are listed, in that
       order. They are made on demand, whether or not that will succeed (measured). */
    if (bHaveBm || bHaveDib || bHaveDibV5)
    {
        if (!bHaveBm)
            IntAddFormatedData(pWinStaObj, CF_BITMAP, DATA_SYNTH_KRNL, FALSE, TRUE);
        if (!bHaveDib)
            IntAddFormatedData(pWinStaObj, CF_DIB, DATA_SYNTH_KRNL, FALSE, TRUE);
        if (!bHaveDibV5)
            IntAddFormatedData(pWinStaObj, CF_DIBV5, DATA_SYNTH_KRNL, FALSE, TRUE);
    }

    /* Add CF_ENHMETAFILE. Note: it is synthesized in gdi32.dll */
    if (bHaveMFP && !bHaveEMF)
        IntAddFormatedData(pWinStaObj, CF_ENHMETAFILE, DATA_SYNTH_USER, FALSE, TRUE);

    /* Add CF_METAFILEPICT. Note: it is synthesized in gdi32.dll */
    if (bHaveEMF && !bHaveMFP)
        IntAddFormatedData(pWinStaObj, CF_METAFILEPICT, DATA_SYNTH_USER, FALSE, TRUE);
}

/* The clipboard was changed and is released: add the synthesized formats (each one
   advances the sequence number, as on Windows) and announce the change */
static VOID FASTCALL
co_IntClipboardChangeDone(PWINSTATION_OBJECT pWinStaObj)
{
    DWORD cFormats = pWinStaObj->cNumClipFormats;

    /* Add synthesized formats - they are rendered later */
    IntAddSynthesizedFormats(pWinStaObj);
    if (pWinStaObj->cNumClipFormats > cFormats)
        pWinStaObj->iClipSequenceNumber += pWinStaObj->cNumClipFormats - cFormats;

    pWinStaObj->fClipboardChanged = FALSE;
    co_IntNotifyClipboardChange(pWinStaObj);
}

/* Asks the clipboard owner to render a delayed format; returns the element afterwards, which
   is NULL when the format is gone. The owner's handler enters win32k again; the array may
   have moved, so the caller must not keep a pointer into it across this call. */
static PCLIP FASTCALL
co_IntRenderDelayedFormat(PWINSTATION_OBJECT pWinSta, UINT fmt)
{
    if (pWinSta->spwndClipOwner)
    {
        pWinSta->fInDelayedRendering = TRUE;
        co_IntSendMessage(UserHMGetHandle(pWinSta->spwndClipOwner), WM_RENDERFORMAT, (WPARAM)fmt, 0);
        pWinSta->fInDelayedRendering = FALSE;
    }

    return IntGetFormatElement(pWinSta, fmt);
}

/* Makes the data of CF_BITMAP, CF_DIB or CF_DIBV5 when the clipboard lists it as made from
   another of the three. Fails (nothing stored) when there is no source with data, the source
   renders to nothing, or the data cannot be converted: the format stays listed, as on Windows. */
static BOOL FASTCALL
co_IntResolveImageFormat(PWINSTATION_OBJECT pWinSta, UINT target)
{
    static const UINT Sources[3][2] =
    {
        { CF_DIB, CF_DIBV5 },       /* CF_BITMAP */
        { CF_BITMAP, CF_DIBV5 },    /* CF_DIB */
        { CF_DIB, CF_BITMAP },      /* CF_DIBV5 */
    };
    const UINT *pSources = Sources[target == CF_BITMAP ? 0 : (target == CF_DIB ? 1 : 2)];
    UINT src = 0;
    PCLIP pSrc, pTarget;
    PCLIPBOARDDATA pData;
    HANDLE hNew = NULL, hTemp = NULL;
    HBITMAP hbm = NULL;
    int i;

    for (i = 0; i < 2; i++)
    {
        pSrc = IntGetFormatElement(pWinSta, pSources[i]);
        if (pSrc && !IS_DATA_SYNTHESIZED(pSrc))
        {
            src = pSources[i];
            break;
        }
    }
    if (!src)
        return FALSE;

    if (IS_DATA_DELAYED(pSrc))
    {
        if (!pWinSta->spwndClipOwner)
            return FALSE;
        pSrc = co_IntRenderDelayedFormat(pWinSta, src);
        if (!pSrc || IS_DATA_DELAYED(pSrc) || IS_DATA_SYNTHESIZED(pSrc))
            return FALSE;
    }

    if (src == CF_BITMAP)
    {
        if (pSrc->fGlobalHandle || (ULONG_PTR)pSrc->hData <= 2)
            return FALSE;
        hNew = IntSynthesizeDib((HBITMAP)pSrc->hData);
        if (hNew && target == CF_DIBV5)
        {
            /* made from the packed image of the bitmap */
            hTemp = hNew;
            pData = (PCLIPBOARDDATA)UserGetObject(gHandleTable, hTemp, TYPE_CLIPDATA);
            hNew = pData ? IntSynthesizeDibV5(pData) : NULL;
            UserDeleteObject(hTemp, TYPE_CLIPDATA);
        }
    }
    else
    {
        if (!pSrc->fGlobalHandle)
            return FALSE;
        pData = (PCLIPBOARDDATA)UserGetObject(gHandleTable, pSrc->hData, TYPE_CLIPDATA);
        if (!pData)
            return FALSE;

        if (target == CF_BITMAP)
            hbm = IntSynthesizeBitmap(pData, src == CF_DIBV5);
        else if (target == CF_DIB)
            hNew = IntSynthesizeDibFromV5(pData);   /* src is CF_DIBV5 here */
        else
            hNew = IntSynthesizeDibV5(pData);       /* src is CF_DIB here */
    }

    /* the source may have been rendered just now: look the target up again */
    pTarget = IntGetFormatElement(pWinSta, target);
    if (!pTarget || !IS_DATA_SYNTHESIZED(pTarget))
    {
        /* the owner changed the clipboard while it rendered: nothing to store into */
        if (hNew)
            UserDeleteObject(hNew, TYPE_CLIPDATA);
        if (hbm)
            GreDeleteObject(hbm);
        return FALSE;
    }

    if (target == CF_BITMAP)
    {
        if (!hbm)
            return FALSE;
        pTarget->hData = hbm;
        pTarget->fGlobalHandle = FALSE;
        pTarget->fOwned = TRUE;
        return TRUE;
    }

    if (!hNew)
        return FALSE;
    pTarget->hData = hNew;
    pTarget->fGlobalHandle = TRUE;
    pTarget->fOwned = FALSE;
    return TRUE;
}

/* Drops the formats of a window that owned the clipboard and died: those still waiting for the
   owner (nobody can render them now) and, when no text format with data is left, the text
   formats that were made from them. The image and metafile formats made from a dropped one
   stay listed (measured on Windows Server 2022). Returns TRUE when something was dropped;
   that is a change: sequence number, viewers and listeners (the caller notifies). */
static BOOL FASTCALL
IntDropDelayedFormats(PWINSTATION_OBJECT pWinSta)
{
    DWORD i, j, cNew = 0;
    BOOL bAny = FALSE, bRealText = FALSE;
    PCLIP pBase = pWinSta->pClipBase;

    for (i = 0; i < pWinSta->cNumClipFormats; i++)
    {
        if (IS_DATA_DELAYED(&pBase[i]))
            bAny = TRUE;
    }
    if (!bAny)
        return FALSE;

    for (i = 0; i < pWinSta->cNumClipFormats; i++)
    {
        if ((pBase[i].fmt == CF_TEXT || pBase[i].fmt == CF_OEMTEXT || pBase[i].fmt == CF_UNICODETEXT) &&
            !IS_DATA_DELAYED(&pBase[i]) && !IS_DATA_SYNTHESIZED(&pBase[i]))
            bRealText = TRUE;
    }

    for (i = 0, j = 0; i < pWinSta->cNumClipFormats; i++)
    {
        if (IS_DATA_DELAYED(&pBase[i]))
            continue;
        if (!bRealText && IS_DATA_SYNTHESIZED(&pBase[i]) &&
            (pBase[i].fmt == CF_TEXT || pBase[i].fmt == CF_OEMTEXT || pBase[i].fmt == CF_UNICODETEXT))
            continue;
        if (i != j)
            pBase[j] = pBase[i];
        j++;
        cNew++;
    }

    pWinSta->cNumClipFormats = cNew;
    if (cNew == 0)
    {
        ExFreePoolWithTag(pWinSta->pClipBase, USERTAG_CLIPBOARD);
        pWinSta->pClipBase = NULL;
    }
    pWinSta->iClipSerialNumber++;
    pWinSta->iClipSequenceNumber++;
    return TRUE;
}

VOID NTAPI
UserEmptyClipboardData(PWINSTATION_OBJECT pWinSta)
{
    DWORD i;
    PCLIP pElement;

    for (i = 0; i < pWinSta->cNumClipFormats; ++i)
    {
        pElement = &pWinSta->pClipBase[i];
        IntFreeElementData(pElement);
    }

    if (pWinSta->pClipBase)
        ExFreePoolWithTag(pWinSta->pClipBase, USERTAG_CLIPBOARD);

    pWinSta->pClipBase = NULL;
    pWinSta->cNumClipFormats = 0;
}

/* UserClipboardRelease is called from IntSendDestroyMsg in window.c */
VOID FASTCALL
UserClipboardRelease(PWND pWindow)
{
    PWINSTATION_OBJECT pWinStaObj;
    BOOL bDropped;

    if (!pWindow)
        return;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        return;

    if (pWinStaObj->spwndClipOwner)
        co_IntSendMessage(UserHMGetHandle(pWinStaObj->spwndClipOwner), WM_RENDERALLFORMATS, 0, 0);

    /* If the window being destroyed is the current clipboard owner... */
    if (pWindow == pWinStaObj->spwndClipOwner)
    {
        /* ... make it release the clipboard */
        pWinStaObj->spwndClipOwner = NULL;

        /* What it did not render now is gone with it, and that is a change */
        bDropped = IntDropDelayedFormats(pWinStaObj);
        if (bDropped && !pWinStaObj->fClipboardChanged)
            co_IntNotifyClipboardChange(pWinStaObj);
    }

    if (pWinStaObj->fClipboardChanged)
        co_IntClipboardChangeDone(pWinStaObj);

    ObDereferenceObject(pWinStaObj);
}

/* Forget a window that is being freed in a window station's clipboard state */
static VOID FASTCALL
IntClipboardForgetWindow(PWINSTATION_OBJECT pWinSta, PWND pWindow)
{
    if (pWindow == pWinSta->spwndClipOwner)
    {
        /* The owner window was destroyed without UserClipboardRelease (its thread or process
           is being cleaned up): the formats still waiting for it are gone */
        pWinSta->spwndClipOwner = NULL;
        IntDropDelayedFormats(pWinSta);
    }

    /* Check if clipboard is not locked by this window, if yes, unlock it */
    if (pWindow == pWinSta->spwndClipOpen)
    {
        /* The window that opens the clipboard was destroyed */
        pWinSta->spwndClipOpen = NULL;
        pWinSta->ptiClipLock = NULL;
    }
    /* Remove window from window chain */
    if (pWindow == pWinSta->spwndClipViewer)
        pWinSta->spwndClipViewer = NULL;
}

/* UserClipboardFreeWindow is called from co_UserFreeWindow in window.c */
VOID FASTCALL
UserClipboardFreeWindow(PWND pWindow)
{
    PWINSTATION_OBJECT pWinStaObj;
    PWINSTATION_OBJECT pWinStaOwn = NULL;
    PCLIPBOARD_LISTENER pListener;

    /* Drop the window from the listeners, whichever window station it was registered in */
    pListener = IntFindClipboardListener(NULL, pWindow);
    if (pListener)
        IntFreeClipboardListener(pListener);

    /* Clear the clipboard pointers of the window's own window station. This must not
       depend on the window station or the access of the thread that frees the window:
       a thread that switched its window station or lacks WINSTA_ACCESSCLIPBOARD would
       leave stale owner/open/viewer pointers behind. */
    if (pWindow->head.rpdesk)
        pWinStaOwn = pWindow->head.rpdesk->rpwinstaParent;
    if (pWinStaOwn)
        IntClipboardForgetWindow(pWinStaOwn, pWindow);

    /* The thread's own window station may hold the window too (a window of another
       window station can be passed to OpenClipboard). An exiting process that drops
       the last reference to a desktop has none any more (and no TEB for the error). */
    if (UserGetProcessWindowStation() == NULL)
        return;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        return;

    if (pWinStaObj != pWinStaOwn)
        IntClipboardForgetWindow(pWinStaObj, pWindow);

    ObDereferenceObject(pWinStaObj);
}

UINT APIENTRY
UserEnumClipboardFormats(UINT fmt)
{
    UINT Ret = 0;
    PCLIP pElement;
    PWINSTATION_OBJECT pWinStaObj;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    /* Check if the clipboard has been opened */
    if (!IntIsClipboardOpenByMe(pWinStaObj))
    {
        EngSetLastError(ERROR_CLIPBOARD_NOT_OPEN);
        goto cleanup;
    }

    if (fmt == 0)
    {
        /* Return first format */
        if (pWinStaObj->pClipBase && pWinStaObj->cNumClipFormats != 0)
            Ret = pWinStaObj->pClipBase[0].fmt;
    }
    else
    {
        /* Return next format */
        pElement = IntGetFormatElement(pWinStaObj, fmt);
        if (pElement != NULL)
        {
            ++pElement;
            if (pElement < &pWinStaObj->pClipBase[pWinStaObj->cNumClipFormats])
            {
                Ret = pElement->fmt;
            }
        }
    }

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    return Ret;
}

BOOL NTAPI
UserOpenClipboard(HWND hWnd)
{
    PWND pWindow = NULL;
    BOOL bRet = FALSE;
    PWINSTATION_OBJECT pWinStaObj = NULL;

    if (hWnd)
    {
        pWindow = UserGetWindowObject(hWnd);
        if (!pWindow)
            goto cleanup;
    }

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    /* Check if we already opened the clipboard */
    if ((pWindow == pWinStaObj->spwndClipOpen) && IntIsClipboardOpenByMe(pWinStaObj))
    {
        bRet = TRUE;
        goto cleanup;
    }

    /* If the clipboard was already opened by somebody else, bail out */
    if ((pWindow != pWinStaObj->spwndClipOpen) && pWinStaObj->ptiClipLock)
    {
        ERR("Access denied!\n");
        EngSetLastError(ERROR_ACCESS_DENIED);
        goto cleanup;
    }

    /* Open the clipboard */
    pWinStaObj->spwndClipOpen = pWindow;
    pWinStaObj->ptiClipLock = PsGetCurrentThreadWin32Thread();
    bRet = TRUE;

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    return bRet;
}

BOOL APIENTRY
NtUserOpenClipboard(HWND hWnd, DWORD Unknown1)
{
    BOOL bRet;

    UserEnterExclusive();
    bRet = UserOpenClipboard(hWnd);
    UserLeave();

    return bRet;
}

BOOL NTAPI
UserCloseClipboard(VOID)
{
    BOOL bRet = FALSE;
    PWINSTATION_OBJECT pWinStaObj;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    /* Check if the clipboard has been opened */
    if (!IntIsClipboardOpenByMe(pWinStaObj))
    {
        EngSetLastError(ERROR_CLIPBOARD_NOT_OPEN);
        goto cleanup;
    }

    /* Clipboard is no longer open */
    pWinStaObj->spwndClipOpen = NULL;
    pWinStaObj->ptiClipLock = NULL;
    bRet = TRUE;

    if (pWinStaObj->fClipboardChanged)
        co_IntClipboardChangeDone(pWinStaObj);

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    return bRet;
}

BOOL APIENTRY
NtUserCloseClipboard(VOID)
{
    BOOL bRet;

    UserEnterExclusive();
    bRet = UserCloseClipboard();
    UserLeave();

    return bRet;
}

HWND APIENTRY
NtUserGetOpenClipboardWindow(VOID)
{
    HWND hWnd = NULL;
    PWINSTATION_OBJECT pWinStaObj;

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (pWinStaObj->spwndClipOpen)
        hWnd = UserHMGetHandle(pWinStaObj->spwndClipOpen);

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return hWnd;
}

BOOL APIENTRY
NtUserChangeClipboardChain(HWND hWndRemove, HWND hWndNewNext)
{
    BOOL bRet = FALSE;
    PWND pWindowRemove, pWindowNewNext;
    PWINSTATION_OBJECT pWinStaObj;

    TRACE("NtUserChangeClipboardChain(%p, %p)\n", hWndRemove, hWndNewNext);

    UserEnterExclusive();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    /* Both windows are validated before the chain changes: an invalid next window
       fails with ERROR_INVALID_WINDOW_HANDLE and leaves the viewer in place */
    pWindowRemove = UserGetWindowObject(hWndRemove);
    pWindowNewNext = NULL;
    if (pWindowRemove && hWndNewNext)
    {
        pWindowNewNext = UserGetWindowObject(hWndNewNext);
        if (!pWindowNewNext)
            pWindowRemove = NULL;
    }

    if (pWindowRemove && pWinStaObj->spwndClipViewer)
    {
        if (pWindowRemove == pWinStaObj->spwndClipViewer)
        {
            /* The head of the chain leaves: the new next window becomes the head, nobody is
               told and the call succeeds (measured on Windows Server 2022) */
            pWinStaObj->spwndClipViewer = pWindowNewNext;
            bRet = TRUE;
        }
        else
        {
            /* Any other window: the head passes the message down the chain, and the result
               is whatever the chain answers */
            bRet = (BOOL)co_IntSendMessage(UserHMGetHandle(pWinStaObj->spwndClipViewer), WM_CHANGECBCHAIN, (WPARAM)hWndRemove, (LPARAM)hWndNewNext);
        }
    }

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return bRet;
}

DWORD APIENTRY
NtUserCountClipboardFormats(VOID)
{
    DWORD cFormats = 0;
    PWINSTATION_OBJECT pWinStaObj;

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    cFormats = pWinStaObj->cNumClipFormats;

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return cFormats;
}

BOOL NTAPI
UserEmptyClipboard(VOID)
{
    BOOL bRet = FALSE;
    PWINSTATION_OBJECT pWinStaObj;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        return FALSE;

    /* Check if the clipboard has been opened */
    if (!IntIsClipboardOpenByMe(pWinStaObj))
    {
        EngSetLastError(ERROR_CLIPBOARD_NOT_OPEN);
        goto cleanup;
    }

    /* The owner still sees the formats it is about to lose, as on Windows */
    if (pWinStaObj->spwndClipOwner)
    {
        TRACE("Clipboard: WM_DESTROYCLIPBOARD to %p\n", UserHMGetHandle(pWinStaObj->spwndClipOwner));
        // For 32-bit applications this message is sent as a notification
        co_IntSendMessage(UserHMGetHandle(pWinStaObj->spwndClipOwner), WM_DESTROYCLIPBOARD, 0, 0);
    }

    UserEmptyClipboardData(pWinStaObj);

    pWinStaObj->spwndClipOwner = pWinStaObj->spwndClipOpen;

    pWinStaObj->iClipSerialNumber++;
    pWinStaObj->iClipSequenceNumber++;
    pWinStaObj->fClipboardChanged = TRUE;
    pWinStaObj->fInDelayedRendering = FALSE;

    bRet = TRUE;

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    return bRet;
}

BOOL APIENTRY
NtUserEmptyClipboard(VOID)
{
    BOOL bRet;

    TRACE("NtUserEmptyClipboard()\n");

    UserEnterExclusive();
    /* MSDN (JOBOBJECT_BASIC_UI_RESTRICTIONS): JOB_OBJECT_UILIMIT_WRITECLIPBOARD
       prevents writing data to the clipboard; emptying it destroys what is there */
    if (UserJobDenies(JOB_OBJECT_UILIMIT_WRITECLIPBOARD))
        bRet = FALSE;
    else
        bRet = UserEmptyClipboard();
    UserLeave();

    return bRet;
}

INT APIENTRY
NtUserGetClipboardFormatName(UINT fmt, LPWSTR lpszFormatName, INT cchMaxCount)
{
    INT iRet = 0;

    UserEnterShared();

    /* If the format is built-in we fail */
    if (fmt < 0xc000 || fmt > 0xffff)
    {
        /* Registetrated formats are >= 0xc000 */
        EngSetLastError(ERROR_INVALID_PARAMETER);
        goto cleanup;
    }

    /* No room at all is "buffer too small" (measured); a negative size or no buffer is a bad parameter */
    if (cchMaxCount == 0)
    {
        EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
        goto cleanup;
    }

    if (cchMaxCount < 1 || !lpszFormatName)
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        goto cleanup;
    }

    _SEH2_TRY
    {
        ProbeForWrite(lpszFormatName, cchMaxCount * sizeof(WCHAR), 1);

        iRet = IntGetAtomName((RTL_ATOM)fmt,
                              lpszFormatName,
                              cchMaxCount * sizeof(WCHAR));
        iRet /= sizeof(WCHAR);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
    }
    _SEH2_END;

cleanup:
    UserLeave();

    return iRet;
}

HWND APIENTRY
NtUserGetClipboardOwner(VOID)
{
    HWND hWnd = NULL;
    PWINSTATION_OBJECT pWinStaObj;

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (pWinStaObj->spwndClipOwner)
        hWnd = UserHMGetHandle(pWinStaObj->spwndClipOwner);

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return hWnd;
}

HWND APIENTRY
NtUserGetClipboardViewer(VOID)
{
    HWND hWnd = NULL;
    PWINSTATION_OBJECT pWinStaObj;

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (pWinStaObj->spwndClipViewer)
        hWnd = UserHMGetHandle(pWinStaObj->spwndClipViewer);

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return hWnd;
}

INT APIENTRY
NtUserGetPriorityClipboardFormat(UINT *paFormatPriorityList, INT cFormats)
{
    INT i, iRet = 0;
    PWINSTATION_OBJECT pWinStaObj;

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (pWinStaObj->pClipBase == NULL)
    {
        iRet = 0;
    }
    else
    {
        _SEH2_TRY
        {
            SIZE_T cbFormats;

            /* The byte count must not wrap (it did on 32-bit, probing less than the loop reads):
               a count that does not fit the address space is a range that is not in user space */
            if (cFormats < 0 || (ULONGLONG)(UINT)cFormats * sizeof(UINT) > (SIZE_T)-1)
                ExRaiseAccessViolation();
            cbFormats = (SIZE_T)(UINT)cFormats * sizeof(UINT);

            ProbeForRead(paFormatPriorityList, cbFormats, sizeof(UINT));

            iRet = -1;

            for (i = 0; i < cFormats; ++i)
            {
                if (IntIsFormatAvailable(pWinStaObj, paFormatPriorityList[i]))
                {
                    iRet = paFormatPriorityList[i];
                    break;
                }
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Windows: a list that cannot be read is an error, not "no match" (measured: 0 and ERROR_NOACCESS) */
            iRet = 0;
            SetLastNtError(_SEH2_GetExceptionCode());
        }
        _SEH2_END;
    }

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return iRet;

}

BOOL APIENTRY
NtUserIsClipboardFormatAvailable(UINT fmt)
{
    BOOL bRet = FALSE;
    PWINSTATION_OBJECT pWinStaObj;

    TRACE("NtUserIsClipboardFormatAvailable(%x)\n", fmt);

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (IntIsFormatAvailable(pWinStaObj, fmt))
        bRet = TRUE;

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return bRet;
}

HANDLE APIENTRY
NtUserGetClipboardData(UINT fmt, PGETCLIPBDATA pgcd)
{
    HANDLE hRet = NULL;
    PCLIP pElement;
    PWINSTATION_OBJECT pWinStaObj;
    UINT uSourceFmt = fmt;

    TRACE("NtUserGetClipboardData(%x, %p)\n", fmt, pgcd);

    /* Delayed rendering sends WM_RENDERFORMAT, which calls back into user mode (and the
       owner's handler enters win32k again, exclusively): the shared lock cannot be held
       across that, a thread cannot upgrade it */
    UserEnterExclusive();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    /* Check if the clipboard has been opened */
    if (!IntIsClipboardOpenByMe(pWinStaObj))
    {
        EngSetLastError(ERROR_CLIPBOARD_NOT_OPEN);
        goto cleanup;
    }

    /* MSDN (JOBOBJECT_BASIC_UI_RESTRICTIONS): JOB_OBJECT_UILIMIT_READCLIPBOARD
       prevents reading data from the clipboard */
    if (UserJobDenies(JOB_OBJECT_UILIMIT_READCLIPBOARD))
        goto cleanup;

    pElement = IntGetFormatElement(pWinStaObj, fmt);
    if (!pElement)
        goto cleanup;

    if (IS_DATA_SYNTHESIZED(pElement))
    {
        /* Note: Data is synthesized in usermode */
        /* TODO: Add more formats */
        switch (fmt)
        {
            case CF_UNICODETEXT:
            case CF_TEXT:
            case CF_OEMTEXT:
                uSourceFmt = CF_UNICODETEXT;
                pElement = IntGetFormatElement(pWinStaObj, uSourceFmt);
                if (pElement && IS_DATA_SYNTHESIZED(pElement))
                {
                    uSourceFmt = CF_TEXT;
                    pElement = IntGetFormatElement(pWinStaObj, uSourceFmt);
                }
                if (pElement && IS_DATA_SYNTHESIZED(pElement))
                {
                    uSourceFmt = CF_OEMTEXT;
                    pElement = IntGetFormatElement(pWinStaObj, uSourceFmt);
                }
                break;

            case CF_BITMAP:
            case CF_DIB:
            case CF_DIBV5:
                /* Made here from one of the other two (rendering the owner's, if it is
                   delayed); a format that cannot be made stays listed and has no data */
                if (!co_IntResolveImageFormat(pWinStaObj, fmt))
                    goto cleanup;
                pElement = IntGetFormatElement(pWinStaObj, fmt);
                break;

            case CF_METAFILEPICT:
                uSourceFmt = CF_ENHMETAFILE;
                pElement = IntGetFormatElement(pWinStaObj, uSourceFmt);
                break;

            case CF_ENHMETAFILE:
                uSourceFmt = CF_METAFILEPICT;
                pElement = IntGetFormatElement(pWinStaObj, uSourceFmt);
                break;

            default:
                /* Not a format the kernel marks as synthesized: nothing to resolve */
                break;
        }
    }

    /* The source of a synthesized format that is itself only a marker has no data */
    if (pElement && IS_DATA_SYNTHESIZED(pElement))
        goto cleanup;

    if (pElement && IS_DATA_DELAYED(pElement) && pWinStaObj->spwndClipOwner)
    {
        /* Send WM_RENDERFORMAT message */
        pWinStaObj->fInDelayedRendering = TRUE;
        co_IntSendMessage(UserHMGetHandle(pWinStaObj->spwndClipOwner), WM_RENDERFORMAT, (WPARAM)uSourceFmt, 0);
        pWinStaObj->fInDelayedRendering = FALSE;

        /* Data should be in clipboard now */
        pElement = IntGetFormatElement(pWinStaObj, uSourceFmt);
    }

    if (!pElement || IS_DATA_DELAYED(pElement))
        goto cleanup;

    _SEH2_TRY
    {
        ProbeForWrite(pgcd, sizeof(*pgcd), 1);
        pgcd->uFmtRet = pElement->fmt;
        pgcd->fGlobalHandle = pElement->fGlobalHandle;

        /* Text and bitmap needs more data */
        if (fmt == CF_TEXT || fmt == CF_OEMTEXT || fmt == CF_UNICODETEXT)
        {
            PCLIP pLocaleEl;

            pLocaleEl = IntGetFormatElement(pWinStaObj, CF_LOCALE);
            if (pLocaleEl && !IS_DATA_DELAYED(pLocaleEl))
                pgcd->hLocale = pLocaleEl->hData;
        }
        else if (fmt == CF_BITMAP)
        {
            PCLIP pPaletteEl;

            pPaletteEl = IntGetFormatElement(pWinStaObj, CF_PALETTE);
            if (pPaletteEl && !IS_DATA_DELAYED(pPaletteEl))
                pgcd->hPalette = pPaletteEl->hData;
        }

        hRet = pElement->hData;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
    }
    _SEH2_END;

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    UserLeave();

    TRACE("NtUserGetClipboardData returns %p\n", hRet);

    return hRet;
}

HANDLE NTAPI
UserSetClipboardData(UINT fmt, HANDLE hData, PSETCLIPBDATA scd)
{
    HANDLE hRet = NULL;
    PWINSTATION_OBJECT pWinStaObj;
    PCLIP pElement;
    BOOL bChange;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (!fmt || !pWinStaObj->ptiClipLock)
    {
        ERR("Access denied!\n");
        EngSetLastError(ERROR_CLIPBOARD_NOT_OPEN);
        goto cleanup;
    }

    /* An application's SetClipboardData (user32 sets fIncSerialNumber) changes the
       clipboard, with data or for delayed rendering. Data rendered for WM_RENDERFORMAT
       and formats user32 caches after synthesizing them are not changes: on Windows
       they leave the sequence number alone and notify nobody. */
    bChange = scd->fIncSerialNumber && !pWinStaObj->fInDelayedRendering;

    /* Is it a delayed rendering? */
    if (hData)
    {
        /* Does the clipboard take over a GDI object here (and delete it later)? */
        BOOL fOwned = !scd->fGlobalHandle && IntClipboardTakesObject(pWinStaObj, fmt, hData);

        /* Is it a bitmap? */
        if (fOwned && fmt == CF_BITMAP)
        {
            /* Make bitmap public */
            GreSetObjectOwner(hData, GDI_OBJ_HMGR_PUBLIC);
        }

        /* Save data in the clipboard */
        pElement = IntAddFormatedData(pWinStaObj, fmt, hData, scd->fGlobalHandle, FALSE);
        if (pElement)
            pElement->fOwned = fOwned;
        TRACE("hData stored\n");

        /* Note: Synthesized formats are added in NtUserCloseClipboard */
    }
    else
    {
        /* This is a delayed rendering */
        pElement = IntAddFormatedData(pWinStaObj, fmt, DATA_DELAYED, FALSE, FALSE);
        TRACE("SetClipboardData delayed format: %u\n", fmt);
    }

    if (pElement && bChange)
    {
        pWinStaObj->iClipSerialNumber++;
        pWinStaObj->iClipSequenceNumber++;
        pWinStaObj->fClipboardChanged = TRUE;
    }

    /* Return hData on success */
    hRet = hData;

cleanup:
    TRACE("NtUserSetClipboardData returns: %p\n", hRet);

    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    return hRet;
}

HANDLE APIENTRY
NtUserSetClipboardData(UINT fmt, HANDLE hData, PSETCLIPBDATA pUnsafeScd)
{
    SETCLIPBDATA scd;
    HANDLE hRet;

    TRACE("NtUserSetClipboardData(%x %p %p)\n", fmt, hData, pUnsafeScd);

    _SEH2_TRY
    {
        ProbeForRead(pUnsafeScd, sizeof(*pUnsafeScd), 1);
        RtlCopyMemory(&scd, pUnsafeScd, sizeof(scd));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        _SEH2_YIELD(return NULL;)
    }
    _SEH2_END

    UserEnterExclusive();

    /* MSDN (JOBOBJECT_BASIC_UI_RESTRICTIONS): JOB_OBJECT_UILIMIT_WRITECLIPBOARD
       prevents writing data to the clipboard */
    if (UserJobDenies(JOB_OBJECT_UILIMIT_WRITECLIPBOARD))
        hRet = NULL;
    else
        hRet = UserSetClipboardData(fmt, hData, &scd);

    UserLeave();

    return hRet;
}

HWND APIENTRY
NtUserSetClipboardViewer(HWND hWndNewViewer)
{
    HWND hWndNext = NULL;
    PWINSTATION_OBJECT pWinStaObj;
    PWND pWindow;

    UserEnterExclusive();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    /* No window ends the chain: the previous head is returned and nobody is notified
       (measured: no error either) */
    if (!hWndNewViewer)
    {
        if (pWinStaObj->spwndClipViewer)
            hWndNext = UserHMGetHandle(pWinStaObj->spwndClipViewer);
        pWinStaObj->spwndClipViewer = NULL;
        goto cleanup;
    }

    pWindow = UserGetWindowObject(hWndNewViewer);
    if (!pWindow)
    {
        EngSetLastError(ERROR_INVALID_WINDOW_HANDLE);
        goto cleanup;
    }

    /* Return previous viewer. New viever window should
       send messages to rest of the chain */
    if (pWinStaObj->spwndClipViewer)
        hWndNext = UserHMGetHandle(pWinStaObj->spwndClipViewer);

    /* Set new viewer window */
    pWinStaObj->spwndClipViewer = pWindow;

    /* Notify the new viewer; Windows also posts WM_CLIPBOARDUPDATE to the listeners */
    pWinStaObj->fClipboardChanged = FALSE;
    co_IntNotifyClipboardChange(pWinStaObj);

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    UserLeave();

    return hWndNext;
}

// Sequence number is incremented whenever the contents of the clipboard change
// or the clipboard is emptied. If clipboard rendering is delayed,
// the sequence number is not incremented until the changes are rendered.

DWORD APIENTRY
NtUserGetClipboardSequenceNumber(VOID)
{
    DWORD dwRet = 0;
    PWINSTATION_OBJECT pWinStaObj;

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    /* Get windowstation sequence number */
    dwRet = (DWORD)pWinStaObj->iClipSequenceNumber;

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return dwRet;
}

HANDLE APIENTRY
NtUserConvertMemHandle(
   PVOID pData,
   DWORD cbData)
{
    HANDLE hMem = NULL;
    PCLIPBOARDDATA pMemObj;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG cbObject;

    /* cbData is caller-controlled: the object size must not wrap */
    if (!NT_SUCCESS(RtlULongAdd(sizeof(CLIPBOARDDATA), cbData, &cbObject)))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    UserEnterExclusive();

    /* Create Clipboard data object */
    pMemObj = UserCreateObject(gHandleTable, NULL, NULL, &hMem, TYPE_CLIPDATA, cbObject);
    if (!pMemObj)
        goto cleanup;

    pMemObj->cbData = cbData;

    /* Copy data */
    _SEH2_TRY
    {
        ProbeForRead(pData, cbData, 1);
        memcpy(pMemObj->Data, pData, cbData);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    /* Release the extra reference (UserCreateObject added 2 references) */
    UserDereferenceObject(pMemObj);

    /* If we failed to copy data, remove handle */
    if (!NT_SUCCESS(Status))
    {
        UserDeleteObject(hMem, TYPE_CLIPDATA);
        hMem = NULL;
    }

cleanup:
    UserLeave();

    return hMem;
}

NTSTATUS APIENTRY
NtUserCreateLocalMemHandle(
   HANDLE hMem,
   PVOID pData,
   DWORD cbData,
   DWORD *pcbData)
{
    PCLIPBOARDDATA pMemObj;
    PWINSTATION_OBJECT pWinStaObj = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOL bHeld = FALSE;
    DWORD i;

    UserEnterShared();

    /* Like every other clipboard service: the caller's window station must grant clipboard access */
    Status = IntValidateWindowStationHandle(UserGetProcessWindowStation(),
                                            UserMode,
                                            WINSTA_ACCESSCLIPBOARD,
                                            &pWinStaObj,
                                            0);
    if (!NT_SUCCESS(Status))
        goto cleanup;

    /* MSDN (JOBOBJECT_BASIC_UI_RESTRICTIONS): JOB_OBJECT_UILIMIT_READCLIPBOARD prevents
       reading data from the clipboard. This copies the data of a clipboard handle out; the
       handles are global values, so the check of NtUserGetClipboardData alone is not enough. */
    if (UserJobDenies(JOB_OBJECT_UILIMIT_READCLIPBOARD))
    {
        Status = STATUS_ACCESS_DENIED;
        goto cleanup;
    }

    /* Get Clipboard data object */
    pMemObj = (PCLIPBOARDDATA)UserGetObject(gHandleTable, hMem, TYPE_CLIPDATA);
    if (!pMemObj)
    {
        Status = STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    /* The handle must be data of that window station's clipboard: clipboard data handles are
       global, any value that happens to be one must not be readable through another station */
    for (i = 0; i < pWinStaObj->cNumClipFormats; ++i)
    {
        if (pWinStaObj->pClipBase[i].fGlobalHandle && pWinStaObj->pClipBase[i].hData == hMem)
        {
            bHeld = TRUE;
            break;
        }
    }
    if (!bHeld)
    {
        Status = STATUS_INVALID_HANDLE;
        goto cleanup;
    }

    /* Don't overrun */
    if (cbData > pMemObj->cbData)
        cbData = pMemObj->cbData;

    /* Copy data to usermode */
    _SEH2_TRY
    {
        if (pcbData)
        {
            ProbeForWrite(pcbData, sizeof(*pcbData), 1);
            *pcbData = pMemObj->cbData;
        }

        ProbeForWrite(pData, cbData, 1);
        memcpy(pData, pMemObj->Data, cbData);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    UserLeave();

    return Status;
}

/* Window station deletion: windows unregister when they are freed, so none should be
   left by now. Drain defensively; the entries reference windows, so the USER lock is
   needed (the object delete callback does not necessarily run with it). */
VOID NTAPI
UserClipboardFreeListeners(PWINSTATION_OBJECT pWinSta)
{
    PLIST_ENTRY pEntry, pNext;
    PCLIPBOARD_LISTENER pListener;
    BOOL bLocked = UserIsEnteredExclusive();

    if (!bLocked)
        UserEnterExclusive();

    for (pEntry = gClipboardListenerList.Flink; pEntry != &gClipboardListenerList; pEntry = pNext)
    {
        pNext = pEntry->Flink;
        pListener = CONTAINING_RECORD(pEntry, CLIPBOARD_LISTENER, ListEntry);
        if (pListener->pWinSta == pWinSta)
        {
            ERR("Clipboard listener left on a deleted window station\n");
            IntFreeClipboardListener(pListener);
        }
    }

    if (!bLocked)
        UserLeave();
}

BOOL APIENTRY
NtUserAddClipboardFormatListener(HWND hwnd)
{
    BOOL bRet = FALSE;
    PWND pWindow;
    PWINSTATION_OBJECT pWinStaObj = NULL;
    PCLIPBOARD_LISTENER pListener;

    UserEnterExclusive();

    pWindow = UserGetWindowObject(hwnd);
    if (!pWindow)
        goto cleanup;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (!IntIsClipboardListenerCandidate(pWinStaObj, pWindow))
    {
        bRet = ERROR_ACCESS_DENIED;
        goto cleanup;
    }

    if (IntFindClipboardListener(pWinStaObj, pWindow))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        goto cleanup;
    }

    pListener = ExAllocatePoolWithTag(PagedPool, sizeof(*pListener), USERTAG_CLIPBOARD);
    if (!pListener)
    {
        EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto cleanup;
    }

    UserReferenceObject(pWindow);
    pListener->pwnd = pWindow;
    pListener->pWinSta = pWinStaObj;
    InsertHeadList(&gClipboardListenerList, &pListener->ListEntry);
    bRet = TRUE;

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    UserLeave();

    return bRet;
}

BOOL APIENTRY
NtUserRemoveClipboardFormatListener(HWND hwnd)
{
    BOOL bRet = FALSE;
    PWND pWindow;
    PWINSTATION_OBJECT pWinStaObj = NULL;
    PCLIPBOARD_LISTENER pListener;

    UserEnterExclusive();

    pWindow = UserGetWindowObject(hwnd);
    if (!pWindow)
        goto cleanup;

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    if (!IntIsClipboardListenerCandidate(pWinStaObj, pWindow))
    {
        bRet = ERROR_ACCESS_DENIED;
        goto cleanup;
    }

    pListener = IntFindClipboardListener(pWinStaObj, pWindow);
    if (!pListener)
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        goto cleanup;
    }

    IntFreeClipboardListener(pListener);
    bRet = TRUE;

cleanup:
    if (pWinStaObj)
        ObDereferenceObject(pWinStaObj);

    UserLeave();

    return bRet;
}

/* The formats the clipboard holds, in clipboard order; the clipboard need not be open.
   Windows 10: ERROR_NOACCESS without a count pointer, or without a buffer for a
   non-zero size; ERROR_INSUFFICIENT_BUFFER with the needed count otherwise. */
BOOL APIENTRY
NtUserGetUpdatedClipboardFormats(PUINT lpuiFormats, UINT cFormats, PUINT pcFormatsOut)
{
    BOOL bRet = FALSE;
    DWORD i, cCurrent;
    PWINSTATION_OBJECT pWinStaObj;

    UserEnterShared();

    pWinStaObj = IntGetWinStaForCbAccess();
    if (!pWinStaObj)
        goto cleanup;

    cCurrent = pWinStaObj->cNumClipFormats;

    _SEH2_TRY
    {
        ProbeForWrite(pcFormatsOut, sizeof(*pcFormatsOut), 1);
        *pcFormatsOut = cCurrent;

        if (cCurrent == 0)
        {
            bRet = TRUE;
        }
        else if (!lpuiFormats && cFormats)
        {
            EngSetLastError(ERROR_NOACCESS);
        }
        else if (cFormats < cCurrent)
        {
            EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        else
        {
            /* cCurrent <= cFormats, and cCurrent counts kernel pool entries: no overflow */
            ProbeForWrite(lpuiFormats, cCurrent * sizeof(UINT), 1);
            for (i = 0; i < cCurrent; ++i)
                lpuiFormats[i] = pWinStaObj->pClipBase[i].fmt;
            bRet = TRUE;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        bRet = FALSE;
    }
    _SEH2_END;

    ObDereferenceObject(pWinStaObj);

cleanup:
    UserLeave();

    return bRet;
}

/* EOF */
