/*
 *  COPYRIGHT:        See COPYING in the top level directory
 *  PROJECT:          ReactOS Kernel
 *  PURPOSE:          GDI Printing Support
 *  FILE:             dll/win32/gdi32/objects/printdrv.c
 *  PROGRAMER:
 *
 */

// For the wine code:
/*
 * Implementation of some printer driver bits
 *
 * Copyright 1996 John Harvey
 * Copyright 1998 Huw Davies
 * Copyright 1998 Andreas Mohr
 * Copyright 1999 Klaas van Gend
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <precomp.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/
HANDLE ghSpooler = NULL;

static ABORTPRINTER fpAbortPrinter;
CLOSEPRINTER fpClosePrinter;
static CLOSESPOOLFILEHANDLE fpCloseSpoolFileHandle;
static COMMITSPOOLDATA fpCommitSpoolData;
//static fpConnectToLd64In32Server;
static DOCUMENTEVENT fpDocumentEvent;
static DOCUMENTPROPERTIESW fpDocumentPropertiesW;
static ENDDOCPRINTER fpEndDocPrinter;
static ENDPAGEPRINTER fpEndPagePrinter;
static GETSPOOLFILEHANDLE fpGetSpoolFileHandle;
static GETPRINTERW fpGetPrinterW;
static GETPRINTERDRIVERW fpGetPrinterDriverW;
static ISVALIDDEVMODEW fpIsValidDevmodeW;
OPENPRINTERW fpOpenPrinterW;
static QUERYSPOOLMODE fpQuerySpoolMode;
static QUERYREMOTEFONTS fpQueryRemoteFonts;
static QUERYCOLORPROFILE fpQueryColorProfile;
static READPRINTER fpReadPrinter;
static RESETPRINTERW fpResetPrinterW;
static SEEKPRINTER fpSeekPrinter;
static SPLDRIVERUNLOADCOMPLETE fpSplDriverUnloadComplete;
static SPLREADPRINTER fpSplReadPrinter;
static STARTDOCDLGW fpStartDocDlgW;
static STARTDOCPRINTERW fpStartDocPrinterW;
static STARTPAGEPRINTER fpStartPagePrinter;
static WRITEPRINTER fpWritePrinter;

/* PRIVATE FUNCTIONS *********************************************************/

static PLDC FASTCALL PrnDcFromHdc(HDC hdc);
static int FASTCALL PrnDcStartDoc(HDC hdc, PLDC pldc, const DOCINFOW *pdi);
static int FASTCALL PrnDcEndDoc(HDC hdc, PLDC pldc);
static int FASTCALL PrnDcAbortDoc(HDC hdc, PLDC pldc);
static int FASTCALL PrnDcStartPage(HDC hdc, PLDC pldc);
static int FASTCALL PrnDcEndPage(HDC hdc, PLDC pldc);

static
int
FASTCALL
IntEndPage(
    HDC hdc,
    BOOL Form
)
{
    PLDC pldc;
    int Ret = SP_ERROR;
    ULONG hType = GDI_HANDLE_GET_TYPE(hdc);

    pldc = PrnDcFromHdc(hdc);
    if (pldc)
        return PrnDcEndPage(hdc, pldc);

    if (hType == GDILoObjType_LO_DC_TYPE || hType == GDILoObjType_LO_METADC16_TYPE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    pldc = GdiGetLDC(hdc);
    if ( !pldc )
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    if (pldc->Flags & LDC_ATENDPAGE) return 1;

    if (pldc->Flags & LDC_META_PRINT)
    {
        if ( Form )
        {
            // Do MF EndPageForm
        }
        else
        {
            // Do MF EndPage
        }
        return Ret;
    }

    if (pldc->Flags & LDC_KILL_DOCUMENT || pldc->Flags & LDC_INIT_PAGE)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return SP_ERROR;
    }

    if (pldc->Flags & LDC_SAPCALLBACK) GdiSAPCallback(pldc);

    pldc->Flags &= ~LDC_INIT_PAGE;

    DocumentEventEx(NULL, pldc->hPrinter, hdc, DOCUMENTEVENT_ENDPAGE, 0, NULL, 0, NULL);

    GdiResetUserPollCount();

    if ( NtGdiEndPage(hdc) )
    {
        BOOL Good;
//      if (pldc->pUMPDev)
        Good = EndPagePrinterEx(NULL,pldc->hPrinter);

        if (Good) pldc->Flags |= LDC_STARTPAGE;
        Ret = 1;
    }
    else
        SetLastError(ERROR_INVALID_PARAMETER);
    return Ret;
}

/* FUNCTIONS *****************************************************************/

BOOL
FASTCALL
AbortPrinterEx(
    PVOID   pvUMPDev,
    HANDLE  hPrinter
)
{
    return fpAbortPrinter(hPrinter);
}

int
FASTCALL
DocumentEventEx(
    PVOID   pvUMPDev,
    HANDLE  hPrinter,
    HDC     hdc,
    int     iEsc,
    ULONG   cbIn,
    PVOID   pvIn,
    ULONG   cbOut,
    PVOID   pvOut
)
{
    return fpDocumentEvent(hPrinter,hdc,iEsc,cbIn,pvIn,cbOut,pvOut);
}

BOOL
FASTCALL
EndDocPrinterEx(
    PVOID   pvUMPDev,
    HANDLE  hPrinter
)
{
    return fpEndDocPrinter(hPrinter);
}

BOOL
FASTCALL
EndPagePrinterEx(
    PVOID   pvUMPDev,
    HANDLE  hPrinter
)
{
    return fpEndPagePrinter(hPrinter);
}

BOOL
FASTCALL
LoadTheSpoolerDrv(VOID)
{
    HMODULE hModWinSpoolDrv;

    if ( !ghSpooler )
    {
        RtlEnterCriticalSection(&semLocal);

        hModWinSpoolDrv = LoadLibraryW(L"WINSPOOL.DRV");

        if (hModWinSpoolDrv)
        {
            fpAbortPrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "AbortPrinter");
            fpClosePrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "ClosePrinter");
            fpCloseSpoolFileHandle = (PVOID)GetProcAddress(hModWinSpoolDrv, "CloseSpoolFileHandle");
            fpCommitSpoolData = (PVOID)GetProcAddress(hModWinSpoolDrv, "CommitSpoolData");
            // fpConnectToLd64In32Server = (PVOID)GetProcAddress(hModWinSpoolDrv, (LPCSTR)224);
            fpDocumentEvent = (PVOID)GetProcAddress(hModWinSpoolDrv,"DocumentEvent");
            fpDocumentPropertiesW = (PVOID)GetProcAddress(hModWinSpoolDrv, "DocumentPropertiesW");
            fpEndDocPrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "EndDocPrinter");
            fpEndPagePrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "EndPagePrinter");
            fpGetPrinterW = (PVOID)GetProcAddress( hModWinSpoolDrv,"GetPrinterW");
            fpGetPrinterDriverW = (PVOID)GetProcAddress(hModWinSpoolDrv,"GetPrinterDriverW");
            fpGetSpoolFileHandle = (PVOID)GetProcAddress(hModWinSpoolDrv, "GetSpoolFileHandle");
            fpIsValidDevmodeW = (PVOID)GetProcAddress(hModWinSpoolDrv, "IsValidDevmodeW");
            fpOpenPrinterW = (PVOID)GetProcAddress(hModWinSpoolDrv, "OpenPrinterW");
            fpQueryColorProfile = (PVOID)GetProcAddress(hModWinSpoolDrv,"QueryColorProfile");
            fpQueryRemoteFonts = (PVOID)GetProcAddress(hModWinSpoolDrv, "QueryRemoteFonts");
            fpQuerySpoolMode = (PVOID)GetProcAddress(hModWinSpoolDrv, "QuerySpoolMode");
            fpReadPrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "ReadPrinter");
            fpResetPrinterW = (PVOID)GetProcAddress(hModWinSpoolDrv, "ResetPrinterW");
            fpSeekPrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "SeekPrinter");
            fpSplDriverUnloadComplete = (PVOID)GetProcAddress(hModWinSpoolDrv, "SplDriverUnloadComplete");
            fpSplReadPrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, (LPCSTR)205);
            fpStartDocDlgW = (PVOID)GetProcAddress(hModWinSpoolDrv, "StartDocDlgW");
            fpStartDocPrinterW = (PVOID)GetProcAddress(hModWinSpoolDrv, "StartDocPrinterW");
            fpStartPagePrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "StartPagePrinter");
            fpWritePrinter = (PVOID)GetProcAddress(hModWinSpoolDrv, "WritePrinter");

            if ( !fpAbortPrinter ||
                    !fpClosePrinter ||
                    !fpCloseSpoolFileHandle ||
                    !fpCommitSpoolData ||
                    !fpDocumentEvent ||
                    !fpDocumentPropertiesW ||
                    !fpEndDocPrinter ||
                    !fpEndPagePrinter ||
                    !fpGetPrinterW ||
                    !fpGetPrinterDriverW ||
                    !fpGetSpoolFileHandle ||
                    !fpIsValidDevmodeW ||
                    !fpOpenPrinterW ||
                    !fpQueryColorProfile ||
                    !fpQueryRemoteFonts ||
                    !fpQuerySpoolMode ||
                    !fpReadPrinter ||
                    !fpResetPrinterW ||
                    !fpSeekPrinter ||
                    !fpSplDriverUnloadComplete ||
                    !fpSplReadPrinter ||
                    !fpStartDocDlgW ||
                    !fpStartDocPrinterW ||
                    !fpStartPagePrinter ||
                    !fpWritePrinter )
            {
                FreeLibrary(hModWinSpoolDrv);
                hModWinSpoolDrv = NULL;
            }
            ghSpooler = hModWinSpoolDrv;
        }
        RtlLeaveCriticalSection(&semLocal);
    }
    else
        return TRUE;

    if ( !ghSpooler ) SetLastError(ERROR_NOT_ENOUGH_MEMORY);

    return (ghSpooler != NULL);
}

/*
  Note from msdn:

   The sequence for a print job is as follows:

   1. To begin a print job, call StartDocPrinter.
   2. To begin each page, call StartPagePrinter.
   3. To write data to a page, call WritePrinter.
   4. To end each page, call EndPagePrinter.
   5. Repeat 2, 3, and 4 for as many pages as necessary.
   6. To end the print job, call EndDocPrinter.

 */
DWORD
FASTCALL
StartDocPrinterWEx(
    PVOID   pvUMPDev,
    HANDLE  hPrinter,
    DWORD   Level,
    LPBYTE  pDocInfo
)
{
    return fpStartDocPrinterW(hPrinter,Level,pDocInfo);
}

BOOL
FASTCALL
StartPagePrinterEx(
    PVOID   pvUMPDev,
    HANDLE  hPrinter
)
{
    return fpStartPagePrinter(hPrinter);
}

/* SYSCALLS ******************************************************************/

/*
 * @unimplemented
 */
int
WINAPI
AbortDoc(
    HDC	hdc
)
{
    PLDC pldc;
    int Ret = SP_ERROR;
    ULONG hType = GDI_HANDLE_GET_TYPE(hdc);

    pldc = PrnDcFromHdc(hdc);
    if (pldc)
        return PrnDcAbortDoc(hdc, pldc);

    if (hType == GDILoObjType_LO_DC_TYPE || hType == GDILoObjType_LO_METADC16_TYPE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    pldc = GdiGetLDC(hdc);
    if ( !pldc )
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    if ( !(pldc->Flags & LDC_INIT_DOCUMENT) ) return 1;

    DocumentEventEx(NULL, pldc->hPrinter, hdc, DOCUMENTEVENT_ABORTDOC, 0, NULL, 0, NULL);

    GdiResetUserPollCount();

    if ( pldc->Flags & LDC_META_PRINT)
    {
        UNIMPLEMENTED;
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return Ret;
    }

    if (NtGdiAbortDoc(hdc))
    {
        if (fpAbortPrinter(pldc->hPrinter)) Ret = 1;
    }
    else
        Ret = SP_ERROR;

    pldc->Flags &= ~(LDC_ATENDPAGE|LDC_META_PRINT|LDC_STARTPAGE|LDC_INIT_PAGE|LDC_INIT_DOCUMENT|LDC_SAPCALLBACK);

    return Ret;
}

/*
 * @unimplemented
 */
int
WINAPI
EndDoc(
    HDC	hdc
)
{
    PLDC pldc;
    int Ret = SP_ERROR;
    ULONG hType = GDI_HANDLE_GET_TYPE(hdc);

    pldc = PrnDcFromHdc(hdc);
    if (pldc)
        return PrnDcEndDoc(hdc, pldc);

    if (hType == GDILoObjType_LO_DC_TYPE || hType == GDILoObjType_LO_METADC16_TYPE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    pldc = GdiGetLDC(hdc);
    if ( !pldc )
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    if (pldc->Flags & LDC_META_PRINT)
    {
        UNIMPLEMENTED;
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return Ret;
    }

    if (pldc->Flags & LDC_INIT_DOCUMENT)
    {
        BOOL Good;
        if (pldc->Flags & LDC_INIT_PAGE) EndPage(hdc);

        DocumentEventEx(NULL, pldc->hPrinter, hdc, DOCUMENTEVENT_ENDDOC, 0, NULL, 0, NULL);

        GdiResetUserPollCount();

        Good = NtGdiEndDoc(hdc);

//      if (pldc->pUMPDev)
        Good = EndDocPrinterEx(NULL,pldc->hPrinter);

        if (Good)
        {
            DocumentEventEx(NULL, pldc->hPrinter, hdc, DOCUMENTEVENT_ENDDOCPOST, 0, NULL, 0, NULL);
            Ret = 1;
        }
        pldc->Flags &= ~(LDC_ATENDPAGE|LDC_STARTPAGE|LDC_INIT_DOCUMENT|LDC_SAPCALLBACK);
    }
    return Ret;
}

/*
 * @implemented
 */
int
WINAPI
EndFormPage(HDC hdc)
{
    return IntEndPage(hdc,TRUE);
}

/*
 * @implemented
 */
int
WINAPI
EndPage(HDC hdc	)
{
    return IntEndPage(hdc,FALSE);
}

/*
 * @unimplemented
 */
HANDLE
WINAPI
GdiGetSpoolFileHandle(LPWSTR pwszPrinterName,
                      LPDEVMODEW pDevmode,
                      LPWSTR pwszDocName)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiDeleteSpoolFileHandle(HANDLE SpoolFileHandle)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
DWORD
WINAPI
GdiGetPageCount(HANDLE SpoolFileHandle)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
int
WINAPI
StartDocW(
    HDC		hdc,
    CONST DOCINFOW	*lpdi
)
{
    PLDC pldc;
    DOCINFOW diW;
    DOC_INFO_1W di1W;
    LPWSTR lpwstrRet = NULL;
    BOOL Banding;
    int PrnJobNo, Ret = SP_ERROR;
    ULONG hType = GDI_HANDLE_GET_TYPE(hdc);

    pldc = PrnDcFromHdc(hdc);
    if (pldc)
        return PrnDcStartDoc(hdc, pldc, lpdi);

    if (hType == GDILoObjType_LO_DC_TYPE || hType == GDILoObjType_LO_METADC16_TYPE)
        return SP_ERROR;

    pldc = GdiGetLDC(hdc);
    if ( !pldc || pldc->Flags & LDC_ATENDPAGE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    if (!pldc->hPrinter) return SP_ERROR;

    pldc->Flags &= ~LDC_KILL_DOCUMENT;

    if (lpdi)
        RtlCopyMemory(&diW, lpdi, sizeof(DOCINFOW));
    else
    {
        diW.cbSize = sizeof(DOCINFOW);
        diW.lpszDocName  = NULL;
        diW.lpszOutput   = NULL;
        diW.lpszDatatype = NULL;
        diW.fwType = 0;
    }

    if (!diW.lpszOutput)
        if (pldc->pwszPort) diW.lpszOutput = pldc->pwszPort;

    lpwstrRet = fpStartDocDlgW(pldc->hPrinter, &diW);
    if (lpwstrRet == (LPWSTR)SP_APPABORT)
    {
        pldc->Flags |= LDC_KILL_DOCUMENT;
        return SP_ERROR;
    }
    if (lpwstrRet == (LPWSTR)SP_ERROR) return SP_ERROR;

    if (lpwstrRet != 0) diW.lpszOutput = lpwstrRet;

    Ret = DocumentEventEx( NULL,
                           pldc->hPrinter,
                           hdc,
                           DOCUMENTEVENT_STARTDOC,
                           sizeof(ULONG),
                           &diW,
                           0,
                           NULL);

    if (Ret == SP_APPABORT)
    {
        pldc->Flags |= LDC_KILL_DOCUMENT;
        Ret = SP_ERROR;
    }
    if (Ret == SP_ERROR)
    {
        if (lpwstrRet) LocalFree(lpwstrRet);
        return Ret;
    }

    di1W.pDocName    = (LPWSTR)diW.lpszDocName;
    di1W.pOutputFile = (LPWSTR)diW.lpszOutput;
    di1W.pDatatype   = (LPWSTR)diW.lpszDatatype;

    Ret = SP_ERROR;

    PrnJobNo = StartDocPrinterWEx(NULL, pldc->hPrinter, 1, (LPBYTE)&di1W);
    if (PrnJobNo <= 0)
    {
        Ret = NtGdiStartDoc( hdc, &diW, &Banding, PrnJobNo);
        if (Ret)
        {
            if (pldc->pAbortProc)
            {
                GdiSAPCallback(pldc);
                pldc->Flags |= LDC_SAPCALLBACK;
                pldc->CallBackTick = GetTickCount();
            }
            pldc->Flags |= LDC_INIT_DOCUMENT;
            if (!Banding) pldc->Flags |= LDC_STARTPAGE;
        }
    }
    if (Ret == SP_ERROR)
    {
        //if ( pldc->pUMPDev  )
        AbortPrinterEx(NULL, pldc->hPrinter);
        DPRINT1("StartDoc Died!!!\n");
    }
    else
    {
        if ( DocumentEventEx( NULL,
                              pldc->hPrinter,
                              hdc,
                              DOCUMENTEVENT_STARTDOCPOST,
                              sizeof(ULONG),
                              &Ret,
                              0,
                              NULL) == SP_ERROR)
        {
            AbortDoc(hdc);
            Ret = SP_ERROR;
        }
    }
    if (lpwstrRet) LocalFree(lpwstrRet);
    return Ret;
}

/*
 * @implemented
 */
int
WINAPI
StartDocA(
    HDC		hdc,
    CONST DOCINFOA	*lpdi
)
{
    LPWSTR szDocName = NULL, szOutput = NULL, szDatatype = NULL;
    DOCINFOW docW;
    INT ret, len;

    docW.cbSize = lpdi->cbSize;
    if (lpdi->lpszDocName)
    {
        len = MultiByteToWideChar(CP_ACP,0,lpdi->lpszDocName,-1,NULL,0);
        szDocName = HeapAlloc(GetProcessHeap(),0,len*sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP,0,lpdi->lpszDocName,-1,szDocName,len);
    }
    if (lpdi->lpszOutput)
    {
        len = MultiByteToWideChar(CP_ACP,0,lpdi->lpszOutput,-1,NULL,0);
        szOutput = HeapAlloc(GetProcessHeap(),0,len*sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP,0,lpdi->lpszOutput,-1,szOutput,len);
    }
    if (lpdi->lpszDatatype)
    {
        len = MultiByteToWideChar(CP_ACP,0,lpdi->lpszDatatype,-1,NULL,0);
        szDatatype = HeapAlloc(GetProcessHeap(),0,len*sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP,0,lpdi->lpszDatatype,-1,szDatatype,len);
    }

    docW.lpszDocName = szDocName;
    docW.lpszOutput = szOutput;
    docW.lpszDatatype = szDatatype;
    docW.fwType = lpdi->fwType;

    ret = StartDocW(hdc, &docW);

    HeapFree( GetProcessHeap(), 0, szDocName );
    HeapFree( GetProcessHeap(), 0, szOutput );
    HeapFree( GetProcessHeap(), 0, szDatatype );

    return ret;
}

/*
 * @unimplemented
 */
int
WINAPI
StartPage(
    HDC	hdc
)
{
    PLDC pldc;
    ULONG hType = GDI_HANDLE_GET_TYPE(hdc);

    pldc = PrnDcFromHdc(hdc);
    if (pldc)
        return PrnDcStartPage(hdc, pldc);

    if (hType == GDILoObjType_LO_DC_TYPE || hType == GDILoObjType_LO_METADC16_TYPE)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    pldc = GdiGetLDC(hdc);
    if ( !pldc )
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return SP_ERROR;
    }

    if (pldc->Flags & LDC_META_PRINT)
    {
        UNIMPLEMENTED;
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return SP_ERROR;
    }

    pldc->Flags &= ~(LDC_ATENDPAGE|LDC_STARTPAGE);

    if (pldc->Flags & LDC_INIT_PAGE) return 1;

    if (DocumentEventEx(NULL, pldc->hPrinter, hdc, DOCUMENTEVENT_STARTPAGE, 0, NULL, 0, NULL) != SP_ERROR)
    {
        pldc->Flags |= LDC_INIT_PAGE;

        GdiResetUserPollCount();

        if (StartPagePrinterEx(NULL, pldc->hPrinter))
        {
            if (NtGdiStartPage(hdc)) return 1;
        }

        pldc->Flags &= ~(LDC_INIT_PAGE);
        EndDoc(hdc);
        SetLastError(ERROR_INVALID_HANDLE);
    }
    return SP_ERROR;
}

/*
 * @implemented
 */
int
WINAPI
StartFormPage(HDC hdc)
{
    return StartPage(hdc);
}


/*
 * @implemented
 */
int
WINAPI
SetAbortProc(
    HDC hdc,
    ABORTPROC lpAbortProc)
{
    PLDC pldc;
    ULONG hType = GDI_HANDLE_GET_TYPE(hdc);

    pldc = PrnDcFromHdc(hdc);
    if (pldc)
    {
        pldc->pAbortProc = lpAbortProc;
        return 1;
    }

    if (hType == GDILoObjType_LO_DC_TYPE || hType == GDILoObjType_LO_METADC16_TYPE)
        return SP_ERROR;

    pldc = GdiGetLDC(hdc);
    if ( pldc )
    {
        if ( lpAbortProc )
        {
            if ( pldc->Flags & LDC_INIT_DOCUMENT )
            {
                pldc->Flags |= LDC_SAPCALLBACK;
                pldc->CallBackTick = GetTickCount();
            }
        }
        else
        {
            pldc->Flags &= ~LDC_SAPCALLBACK;
        }
        pldc->pAbortProc = lpAbortProc;
        return 1;
    }
    else
    {
        SetLastError(ERROR_INVALID_HANDLE);
    }
    return SP_ERROR;
}

/*
 * @unimplemented
 */
DWORD
WINAPI
gdiPlaySpoolStream(
    DWORD	a0,
    DWORD	a1,
    DWORD	a2,
    DWORD	a3,
    DWORD	a4,
    DWORD	a5
)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
HDC
WINAPI
GdiGetDC(HANDLE SpoolFileHandle)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
HANDLE
WINAPI
GdiGetPageHandle(HANDLE SpoolFileHandle,
                 DWORD Page,
                 LPDWORD pdwPageType)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiStartDocEMF(HANDLE SpoolFileHandle,
               DOCINFOW *pDocInfo)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiStartPageEMF(HANDLE SpoolFileHandle)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiPlayPageEMF(HANDLE SpoolFileHandle,
               HANDLE hemf,
               RECT *prectDocument,
               RECT *prectBorder,
               RECT *prectClip)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiEndPageEMF(HANDLE SpoolFileHandle,
              DWORD dwOptimization)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiEndDocEMF(HANDLE SpoolFileHandle)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiGetDevmodeForPage(HANDLE SpoolFileHandle,
                     DWORD dwPageNumber,
                     PDEVMODEW *pCurrDM,
                     PDEVMODEW *pLastDM)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiResetDCEMF(HANDLE SpoolFileHandle,
              PDEVMODEW pCurrDM)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}


/*
 * @unimplemented
 */
BOOL
WINAPI
GdiPlayEMF(LPWSTR pwszPrinterName,
           LPDEVMODEW pDevmode,
           LPWSTR pwszDocName,
           EMFPLAYPROC pfnEMFPlayFn,
           HANDLE hPageQuery
          )
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiPlayPrivatePageEMF(HANDLE SpoolFileHandle,
                      DWORD unknown,
                      RECT *prectDocument)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiPrinterThunk(
    IN HUMPD humpd,
    DWORD *status,
    DWORD unuse)
{
    /* FIXME figout the protypes, the HUMPD are a STRUCT or COM object */
    /* status contain some form of return value that being save, what it is I do not known */
    /* unsue seam have zero effect, what it is for I do not known */

    // ? return NtGdiSetPUMPDOBJ(humpd->0x10,TRUE, humpd, ?) <- blackbox, OpenRCE info, and api hooks for anylaysing;
    return FALSE;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GdiArtificialDecrementDriver(LPWSTR pDriverName,BOOL unknown)
{
    UNIMPLEMENTED;
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/* SOFTWARE PAGE PRINTER DC **************************************************
 *
 * ReactOS has no raster printer driver (and no UMPD host), so a printer DC
 * cannot be created by Win32k. A printer DC made by CreateDC/CreateIC is a
 * memory DC that owns one page-sized 24 bpp DIB section. GetDeviceCaps reports
 * the page (size, resolution, DT_RASPRINTER). StartDoc/StartPage/EndPage/EndDoc
 * run a spooler job on the printer: every EndPage writes the page as a Windows
 * bitmap (BITMAPFILEHEADER, BITMAPINFOHEADER, bottom-up 24 bpp rows) with
 * WritePrinter. A single page document is therefore a valid .bmp file.
 *
 * The printer, its port, the datatype, the output file ("FILE:" asks for a file
 * name) and the job queue are those of the spooler (winspool, spoolsv, localspl).
 */

/* The page of a LDC_PAGEDC printer DC; LDC.pvEMFSpoolData points to it (such a DC has no EMF spool data) */
typedef struct _PRNDC_PAGE
{
    HBITMAP hbm;
    HGDIOBJ hbmOld;
    PVOID pvBits;
    ULONG cx;
    ULONG cy;
    ULONG cbStride;
} PRNDC_PAGE, *PPRNDC_PAGE;

#define PRNDC_PAGE_OF(pldc) ((PPRNDC_PAGE)(pldc)->pvEMFSpoolData)

#define PRNDC_DEFAULT_DPI   150
#define PRNDC_MIN_DPI       72
#define PRNDC_MAX_DPI       600
#define PRNDC_MAX_PAGE_SIZE (96 * 1024 * 1024)
#define PRNDC_WRITE_CHUNK   0x10000

static const WCHAR wszFilePort[] = L"FILE:";

static
PLDC
FASTCALL
PrnDcFromHdc(HDC hdc)
{
    PLDC pldc;

    if (GDI_HANDLE_GET_TYPE(hdc) != GDILoObjType_LO_DC_TYPE)
        return NULL;

    pldc = GdiGetLDC(hdc);
    if (!pldc || !(pldc->Flags & LDC_PAGEDC))
        return NULL;

    return pldc;
}

/* Page size in tenths of a millimetre of a DEVMODE.dmPaperSize value */
static
BOOL
PrnDcPaperSize(SHORT sPaper, ULONG *pulWidth, ULONG *pulHeight)
{
    switch (sPaper)
    {
        case DMPAPER_LETTER:    *pulWidth = 2159; *pulHeight = 2794; return TRUE;
        case DMPAPER_TABLOID:   *pulWidth = 2794; *pulHeight = 4318; return TRUE;
        case DMPAPER_LEGAL:     *pulWidth = 2159; *pulHeight = 3556; return TRUE;
        case DMPAPER_EXECUTIVE: *pulWidth = 1842; *pulHeight = 2667; return TRUE;
        case DMPAPER_A3:        *pulWidth = 2970; *pulHeight = 4200; return TRUE;
        case DMPAPER_A4:        *pulWidth = 2100; *pulHeight = 2970; return TRUE;
        case DMPAPER_A5:        *pulWidth = 1480; *pulHeight = 2100; return TRUE;
        case DMPAPER_B5:        *pulWidth = 1820; *pulHeight = 2570; return TRUE;
    }
    return FALSE;
}

static
BOOL
PrnDcFillCaps(
    const DEVMODEW *pdm,
    PDEVCAPS pCaps,
    PULONG pcx,
    PULONG pcy)
{
    ULONG ulWidth = 2159, ulHeight = 2794; /* Letter, in tenths of a millimetre */
    ULONG ulDpiX = PRNDC_DEFAULT_DPI, ulDpiY = PRNDC_DEFAULT_DPI;
    ULONG cx, cy, ulTmp;

    if (pdm && pdm->dmSize >= FIELD_OFFSET(DEVMODEW, dmTTOption))
    {
        if (pdm->dmFields & DM_PAPERSIZE)
            PrnDcPaperSize(pdm->dmPaperSize, &ulWidth, &ulHeight);

        if ((pdm->dmFields & DM_PAPERWIDTH) && (pdm->dmFields & DM_PAPERLENGTH) &&
            pdm->dmPaperWidth > 0 && pdm->dmPaperLength > 0 &&
            (!(pdm->dmFields & DM_PAPERSIZE) || pdm->dmPaperSize == 0 || pdm->dmPaperSize == DMPAPER_USER))
        {
            ulWidth = pdm->dmPaperWidth;
            ulHeight = pdm->dmPaperLength;
        }

        if ((pdm->dmFields & DM_ORIENTATION) && pdm->dmOrientation == DMORIENT_LANDSCAPE)
        {
            ulTmp = ulWidth;
            ulWidth = ulHeight;
            ulHeight = ulTmp;
        }

        /* A positive print quality is a resolution in dpi, a negative one is a DMRES_ constant */
        if ((pdm->dmFields & DM_PRINTQUALITY) && pdm->dmPrintQuality > 0)
        {
            ulDpiX = pdm->dmPrintQuality;
            ulDpiY = ulDpiX;
        }
        if ((pdm->dmFields & DM_YRESOLUTION) && pdm->dmYResolution > 0)
            ulDpiY = pdm->dmYResolution;
    }

    ulDpiX = min(max(ulDpiX, PRNDC_MIN_DPI), PRNDC_MAX_DPI);
    ulDpiY = min(max(ulDpiY, PRNDC_MIN_DPI), PRNDC_MAX_DPI);

    if (ulWidth == 0 || ulHeight == 0 || ulWidth > 20000 || ulHeight > 20000)
        return FALSE;

    cx = (ulWidth * ulDpiX) / 254;
    cy = (ulHeight * ulDpiY) / 254;
    if (cx == 0 || cy == 0 || (ULONGLONG)cx * cy * 3 > PRNDC_MAX_PAGE_SIZE)
        return FALSE;

    RtlZeroMemory(pCaps, sizeof(*pCaps));
    pCaps->ulVersion = 0x0400;
    pCaps->ulTechnology = DT_RASPRINTER;
    pCaps->ulHorzSizeM = ulWidth / 10;
    pCaps->ulVertSizeM = ulHeight / 10;
    pCaps->ulHorzSize = pCaps->ulHorzSizeM;
    pCaps->ulVertSize = pCaps->ulVertSizeM;
    pCaps->ulHorzRes = cx;
    pCaps->ulVertRes = cy;
    pCaps->ulBitsPixel = 24;
    pCaps->ulPlanes = 1;
    pCaps->ulNumPens = (ULONG)-1;
    pCaps->ulNumFonts = 0;
    pCaps->ulNumColors = (ULONG)-1;
    pCaps->ulRasterCaps = RC_BITBLT | RC_BITMAP64 | RC_DI_BITMAP | RC_DIBTODEV |
                          RC_STRETCHBLT | RC_STRETCHDIB;
    pCaps->ulAspectX = ulDpiX;
    pCaps->ulAspectY = ulDpiY;
    pCaps->ulAspectXY = (ulDpiX * 1414) / 1000;
    pCaps->ulLogPixelsX = ulDpiX;
    pCaps->ulLogPixelsY = ulDpiY;
    pCaps->ulSizePalette = 0;
    pCaps->ulColorRes = 24;
    pCaps->ulPhysicalWidth = cx;
    pCaps->ulPhysicalHeight = cy;
    pCaps->ulPhysicalOffsetX = 0;
    pCaps->ulPhysicalOffsetY = 0;
    pCaps->ulTextCaps = TC_OP_CHARACTER | TC_OP_STROKE | TC_CP_STROKE |
                        TC_RA_ABLE | TC_UA_ABLE | TC_SO_ABLE;
    pCaps->ulDesktopHorzRes = cx;
    pCaps->ulDesktopVertRes = cy;

    *pcx = cx;
    *pcy = cy;
    return TRUE;
}

static
LPWSTR
PrnDcDupString(LPCWSTR pwsz)
{
    SIZE_T cb = (wcslen(pwsz) + 1) * sizeof(WCHAR);
    LPWSTR pwszCopy = LocalAlloc(LMEM_FIXED, cb);

    if (pwszCopy)
        RtlCopyMemory(pwszCopy, pwsz, cb);
    return pwszCopy;
}

/* The port of the printer, from PRINTER_INFO_5 */
static
LPWSTR
PrnDcQueryPort(HANDLE hPrinter)
{
    DWORD cbNeeded = 0;
    PPRINTER_INFO_5W ppi;
    LPWSTR pwszPort = NULL;

    fpGetPrinterW(hPrinter, 5, NULL, 0, &cbNeeded);
    if (cbNeeded == 0)
        return NULL;

    ppi = LocalAlloc(LMEM_FIXED, cbNeeded);
    if (!ppi)
        return NULL;

    if (fpGetPrinterW(hPrinter, 5, (LPBYTE)ppi, cbNeeded, &cbNeeded) && ppi->pPortName)
        pwszPort = PrnDcDupString(ppi->pPortName);

    LocalFree(ppi);
    return pwszPort;
}

/*
 * pwszDriver is "WINSPOOL" or a driver name, pwszDevice the printer name,
 * pwszOutput the port or output file of the DC (NULL: the port of the printer).
 */
HDC
FASTCALL
PrnDcCreate(
    LPCWSTR pwszDriver,
    LPCWSTR pwszDevice,
    LPCWSTR pwszOutput,
    const DEVMODEW *pdmInit,
    BOOL bInfo)
{
    LPCWSTR pwszName;
    HANDLE hPrinter = NULL;
    PDEVMODEW pdm = NULL;
    PLDC pldc = NULL;
    PPRNDC_PAGE page = NULL;
    HDC hdc = NULL;
    HBITMAP hbm = NULL;
    PVOID pvBits = NULL;
    DEVCAPS caps;
    ULONG cx, cy, cbStride;
    LONG cbDevMode;
    DWORD dwError;
    BITMAPINFO bmi;

    if (pwszDevice && *pwszDevice)
        pwszName = pwszDevice;
    else if (pwszDriver && *pwszDriver && _wcsicmp(pwszDriver, L"WINSPOOL") != 0)
        pwszName = pwszDriver;
    else
    {
        SetLastError(ERROR_INVALID_PRINTER_NAME);
        return NULL;
    }

    if (!ghSpooler)
    {
        SetLastError(ERROR_INVALID_FUNCTION);
        return NULL;
    }

    if (!fpOpenPrinterW((LPWSTR)pwszName, &hPrinter, NULL))
        return NULL;

    /* The DEVMODE of the printer, with the changes of the caller */
    cbDevMode = fpDocumentPropertiesW(NULL, hPrinter, (LPWSTR)pwszName, NULL, NULL, 0);
    if (cbDevMode > 0)
    {
        pdm = LocalAlloc(LMEM_ZEROINIT, cbDevMode);
        if (pdm)
        {
            DWORD dwMode = DM_OUT_BUFFER;

            if (pdmInit)
                dwMode |= DM_IN_BUFFER;
            if (fpDocumentPropertiesW(NULL, hPrinter, (LPWSTR)pwszName, pdm,
                                      (PDEVMODEW)pdmInit, dwMode) != IDOK)
            {
                LocalFree(pdm);
                pdm = NULL;
            }
        }
    }

    if (!PrnDcFillCaps(pdm ? pdm : pdmInit, &caps, &cx, &cy))
    {
        dwError = ERROR_INVALID_PARAMETER;
        goto Fail;
    }

    pldc = LocalAlloc(LMEM_ZEROINIT, sizeof(LDC));
    page = LocalAlloc(LMEM_ZEROINIT, sizeof(PRNDC_PAGE));
    if (!pldc || !page)
    {
        dwError = ERROR_NOT_ENOUGH_MEMORY;
        goto Fail;
    }
    pldc->pvEMFSpoolData = page;

    hdc = CreateCompatibleDC(NULL);
    if (!hdc)
    {
        dwError = GetLastError();
        goto Fail;
    }

    cbStride = (cx * 3 + 3) & ~3;
    if (!bInfo)
    {
        RtlZeroMemory(&bmi, sizeof(bmi));
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = cx;
        bmi.bmiHeader.biHeight = cy; /* bottom-up, as a .bmp file */
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 24;
        bmi.bmiHeader.biCompression = BI_RGB;
        bmi.bmiHeader.biSizeImage = cbStride * cy;
        hbm = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &pvBits, NULL, 0);
        if (!hbm)
        {
            dwError = GetLastError();
            if (dwError == ERROR_SUCCESS)
                dwError = ERROR_NOT_ENOUGH_MEMORY;
            goto Fail;
        }
        page->hbmOld = SelectObject(hdc, hbm);
        PatBlt(hdc, 0, 0, cx, cy, WHITENESS);
    }

    pldc->hDC = hdc;
    pldc->iType = LDC_LDC;
    pldc->Flags = LDC_LDC | LDC_PAGEDC | (bInfo ? LDC_INFODC : 0);
    pldc->hPrinter = hPrinter;
    pldc->pdm = pdm;
    pldc->DevCaps = caps;
    page->hbm = hbm;
    page->pvBits = pvBits;
    page->cx = cx;
    page->cy = cy;
    page->cbStride = cbStride;

    if (pwszOutput && *pwszOutput)
        pldc->pwszPort = PrnDcDupString(pwszOutput);
    else
        pldc->pwszPort = PrnDcQueryPort(hPrinter);

    if (!GdiSetLDC(hdc, pldc))
    {
        dwError = ERROR_INVALID_HANDLE;
        goto Fail;
    }

    return hdc;

Fail:
    if (hdc)
    {
        if (page && page->hbmOld)
            SelectObject(hdc, page->hbmOld);
        NtGdiDeleteObjectApp(hdc);
    }
    if (hbm)
        DeleteObject(hbm);
    if (pldc)
    {
        if (pldc->pwszPort)
            LocalFree(pldc->pwszPort);
        LocalFree(pldc);
    }
    if (page)
        LocalFree(page);
    if (pdm)
        LocalFree(pdm);
    if (hPrinter)
        fpClosePrinter(hPrinter);
    SetLastError(dwError);
    return NULL;
}

BOOL
FASTCALL
PrnDcDelete(
    HDC hdc,
    PBOOL pbHandled)
{
    PLDC pldc = PrnDcFromHdc(hdc);
    BOOL bResult;
    HBITMAP hbm;

    *pbHandled = (pldc != NULL);
    if (!pldc)
        return FALSE;

    /* A document that is still open is thrown away, as Windows does */
    if (pldc->Flags & LDC_INIT_DOCUMENT)
        fpAbortPrinter(pldc->hPrinter);

    GdiSetLDC(hdc, NULL);
    if (PRNDC_PAGE_OF(pldc)->hbmOld)
        SelectObject(hdc, PRNDC_PAGE_OF(pldc)->hbmOld);

    bResult = NtGdiDeleteObjectApp(hdc);

    hbm = PRNDC_PAGE_OF(pldc)->hbm;
    if (hbm)
        DeleteObject(hbm);
    LocalFree(pldc->pvEMFSpoolData);
    if (pldc->hPrinter)
        fpClosePrinter(pldc->hPrinter);
    if (pldc->pwszPort)
        LocalFree(pldc->pwszPort);
    if (pldc->pdm)
        LocalFree(pldc->pdm);
    LocalFree(pldc);
    return bResult;
}

static
BOOL
PrnDcWrite(HANDLE hPrinter, PVOID pvData, DWORD cbData)
{
    PBYTE pb = pvData;
    DWORD cbChunk, cbWritten;

    while (cbData)
    {
        cbChunk = min(cbData, PRNDC_WRITE_CHUNK);
        cbWritten = 0;
        if (!fpWritePrinter(hPrinter, pb, cbChunk, &cbWritten) || cbWritten != cbChunk)
        {
            if (GetLastError() == ERROR_SUCCESS)
                SetLastError(ERROR_WRITE_FAULT);
            return FALSE;
        }
        pb += cbChunk;
        cbData -= cbChunk;
    }
    return TRUE;
}

/* BITMAPFILEHEADER and BITMAPINFOHEADER of a .bmp file, without padding */
#include <pshpack1.h>
typedef struct _PRNDC_BMPHEADER
{
    WORD bfType;
    DWORD bfSize;
    WORD bfReserved1;
    WORD bfReserved2;
    DWORD bfOffBits;
    BITMAPINFOHEADER bi;
} PRNDC_BMPHEADER;
#include <poppack.h>

/* The page as a .bmp file */
static
BOOL
PrnDcWritePage(PLDC pldc)
{
    PRNDC_BMPHEADER hdr;
    ULONG cbBits = PRNDC_PAGE_OF(pldc)->cbStride * PRNDC_PAGE_OF(pldc)->cy;

    GdiFlush();

    RtlZeroMemory(&hdr, sizeof(hdr));
    hdr.bfType = 0x4D42; /* BM */
    hdr.bfSize = sizeof(hdr) + cbBits;
    hdr.bfOffBits = sizeof(hdr);
    hdr.bi.biSize = sizeof(BITMAPINFOHEADER);
    hdr.bi.biWidth = PRNDC_PAGE_OF(pldc)->cx;
    hdr.bi.biHeight = PRNDC_PAGE_OF(pldc)->cy;
    hdr.bi.biPlanes = 1;
    hdr.bi.biBitCount = 24;
    hdr.bi.biCompression = BI_RGB;
    hdr.bi.biSizeImage = cbBits;
    hdr.bi.biXPelsPerMeter = (pldc->DevCaps.ulLogPixelsX * 10000) / 254;
    hdr.bi.biYPelsPerMeter = (pldc->DevCaps.ulLogPixelsY * 10000) / 254;

    return PrnDcWrite(pldc->hPrinter, &hdr, sizeof(hdr)) &&
           PrnDcWrite(pldc->hPrinter, PRNDC_PAGE_OF(pldc)->pvBits, cbBits);
}

static
int
FASTCALL
PrnDcAbortDoc(HDC hdc, PLDC pldc)
{
    UNREFERENCED_PARAMETER(hdc);

    if (!(pldc->Flags & LDC_INIT_DOCUMENT))
        return 1;

    pldc->Flags &= ~(LDC_INIT_PAGE | LDC_INIT_DOCUMENT | LDC_SAPCALLBACK | LDC_KILL_DOCUMENT);
    return fpAbortPrinter(pldc->hPrinter) ? 1 : SP_ERROR;
}

static
int
FASTCALL
PrnDcStartDoc(HDC hdc, PLDC pldc, const DOCINFOW *pdi)
{
    DOCINFOW di;
    DOC_INFO_1W di1;
    LPWSTR pwszDlg;
    DWORD dwJob;

    UNREFERENCED_PARAMETER(hdc);

    if ((pldc->Flags & LDC_INFODC) || (pldc->Flags & LDC_INIT_DOCUMENT))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return SP_ERROR;
    }

    if (pdi)
        di = *pdi;
    else
        RtlZeroMemory(&di, sizeof(di));
    di.cbSize = sizeof(di);

    /* No output file: a document of a FILE: printer or DC goes to a file chosen by the user */
    if (!di.lpszOutput && pldc->pwszPort && !_wcsicmp(pldc->pwszPort, wszFilePort))
        di.lpszOutput = wszFilePort;

    pwszDlg = fpStartDocDlgW(pldc->hPrinter, &di);
    if (pwszDlg == (LPWSTR)SP_APPABORT)
    {
        pldc->Flags |= LDC_KILL_DOCUMENT;
        return SP_ERROR;
    }
    if (pwszDlg == (LPWSTR)SP_ERROR)
        return SP_ERROR;
    if (pwszDlg)
        di.lpszOutput = pwszDlg;

    di1.pDocName = (LPWSTR)di.lpszDocName;
    di1.pOutputFile = (LPWSTR)di.lpszOutput;
    di1.pDatatype = (LPWSTR)di.lpszDatatype;

    dwJob = fpStartDocPrinterW(pldc->hPrinter, 1, (LPBYTE)&di1);
    if (pwszDlg)
        HeapFree(GetProcessHeap(), 0, pwszDlg);
    if (dwJob == 0)
        return SP_ERROR;

    pldc->Flags &= ~LDC_KILL_DOCUMENT;
    pldc->Flags |= LDC_INIT_DOCUMENT;
    return (int)dwJob;
}

static
int
FASTCALL
PrnDcStartPage(HDC hdc, PLDC pldc)
{
    if (!(pldc->Flags & LDC_INIT_DOCUMENT) || (pldc->Flags & LDC_INFODC))
    {
        SetLastError(ERROR_SPL_NO_STARTDOC);
        return SP_ERROR;
    }

    if (pldc->Flags & LDC_INIT_PAGE)
        return 1;

    /* A new page is white */
    SetViewportOrgEx(hdc, 0, 0, NULL);
    SelectClipRgn(hdc, NULL);
    PatBlt(hdc, 0, 0, PRNDC_PAGE_OF(pldc)->cx, PRNDC_PAGE_OF(pldc)->cy, WHITENESS);

    pldc->Flags |= LDC_INIT_PAGE;
    return 1;
}

static
int
FASTCALL
PrnDcEndPage(HDC hdc, PLDC pldc)
{
    BOOL bGood;

    if (!(pldc->Flags & LDC_INIT_DOCUMENT) || !(pldc->Flags & LDC_INIT_PAGE))
    {
        SetLastError(ERROR_SPL_NO_STARTDOC);
        return SP_ERROR;
    }

    pldc->Flags &= ~LDC_INIT_PAGE;

    /* An abort procedure that returns FALSE cancels the document */
    if (pldc->pAbortProc && !pldc->pAbortProc(hdc, 0))
    {
        PrnDcAbortDoc(hdc, pldc);
        SetLastError(ERROR_CANCELLED);
        return SP_ERROR;
    }

    bGood = fpStartPagePrinter(pldc->hPrinter) &&
            PrnDcWritePage(pldc);
    if (bGood)
    {
        bGood = fpEndPagePrinter(pldc->hPrinter);
    }
    else
    {
        DWORD dwError = GetLastError();
        fpEndPagePrinter(pldc->hPrinter);
        SetLastError(dwError);
    }

    if (!bGood)
    {
        DWORD dwError = GetLastError();
        PrnDcAbortDoc(hdc, pldc);
        SetLastError(dwError);
        return SP_ERROR;
    }

    return 1;
}

static
int
FASTCALL
PrnDcEndDoc(HDC hdc, PLDC pldc)
{
    BOOL bGood;

    if (!(pldc->Flags & LDC_INIT_DOCUMENT))
    {
        SetLastError(ERROR_SPL_NO_STARTDOC);
        return SP_ERROR;
    }

    /* A page that was started but not ended is part of the document */
    if ((pldc->Flags & LDC_INIT_PAGE) && PrnDcEndPage(hdc, pldc) == SP_ERROR)
        return SP_ERROR;

    pldc->Flags &= ~(LDC_INIT_PAGE | LDC_INIT_DOCUMENT | LDC_SAPCALLBACK | LDC_KILL_DOCUMENT);
    bGood = fpEndDocPrinter(pldc->hPrinter);
    return bGood ? 1 : SP_ERROR;
}
