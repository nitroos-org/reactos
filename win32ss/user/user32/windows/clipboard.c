/*
 * PROJECT:         ReactOS user32.dll
 * FILE:            win32ss/user/user32/windows/clipboard.c
 * PURPOSE:         Input
 * PROGRAMMER:      Casper S. Hornstrup (chorns@users.sourceforge.net)
 *                  Pablo Borobia <pborobia@gmail.com>
 * UPDATE HISTORY:
 *      09-05-2001  CSH  Created
 *
 */

#include <user32.h>

#define NDEBUG

WINE_DEFAULT_DEBUG_CHANNEL(user32);

HANDLE WINAPI GdiConvertMetaFilePict(HANDLE);
HANDLE WINAPI GdiConvertEnhMetaFile(HANDLE);
HANDLE WINAPI GdiCreateLocalEnhMetaFile(HANDLE);
HANDLE WINAPI GdiCreateLocalMetaFilePict(HANDLE);


/*
 * @implemented
 */
BOOL
WINAPI
OpenClipboard(HWND hWndNewOwner)
{
    return NtUserOpenClipboard(hWndNewOwner, 0);
}

/*
 * @implemented
 */
UINT
WINAPI
EnumClipboardFormats(UINT format)
{
    SetLastError(NO_ERROR);
    return NtUserxEnumClipboardFormats(format);
}

/*
 * @implemented
 */
INT
WINAPI
GetClipboardFormatNameA(UINT format,
                        LPSTR lpszFormatName,
                        int cchMaxCount)
{
    LPWSTR lpBuffer;
    INT Length;

    lpBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, cchMaxCount * sizeof(WCHAR));
    if (!lpBuffer)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return 0;
    }

    /* we need a UNICODE string */
    Length = NtUserGetClipboardFormatName(format, lpBuffer, cchMaxCount);

    if (Length != 0)
    {
        if (!WideCharToMultiByte(CP_ACP, 0, lpBuffer, Length, lpszFormatName, cchMaxCount, NULL, NULL))
        {
            /* clear result string */
            Length = 0;
        }
        lpszFormatName[Length] = ANSI_NULL;
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, lpBuffer);
    return Length;
}

/*
 * @implemented
 */
INT
WINAPI
GetClipboardFormatNameW(UINT uFormat,
                        LPWSTR lpszFormatName,
                        INT cchMaxCount)
{
    return NtUserGetClipboardFormatName(uFormat, lpszFormatName, cchMaxCount);
}

/*
 * @implemented
 */
UINT
WINAPI
RegisterClipboardFormatA(LPCSTR lpszFormat)
{
    UINT ret;
    UNICODE_STRING usFormat = {0};

    if (lpszFormat == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (*lpszFormat == ANSI_NULL)
    {
        SetLastError(ERROR_INVALID_NAME);
        return 0;
    }

    if (!RtlCreateUnicodeStringFromAsciiz(&usFormat, lpszFormat))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    ret = NtUserRegisterWindowMessage(&usFormat); //(LPCWSTR)

    RtlFreeUnicodeString(&usFormat);

    return ret;
}

/*
 * @implemented
 */
UINT
WINAPI
RegisterClipboardFormatW(LPCWSTR lpszFormat)
{
    UNICODE_STRING usFormat = {0};

    if (lpszFormat == NULL)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (*lpszFormat == UNICODE_NULL)
    {
        SetLastError(ERROR_INVALID_NAME);
        return 0;
    }

    RtlInitUnicodeString(&usFormat, lpszFormat);
    return NtUserRegisterWindowMessage(&usFormat);
}

/* The memory blocks this process put on the clipboard (SetClipboardData). The system owns them from then on:
   in this process GetClipboardData hands the same handle back (the clipboard holds a copy for other processes),
   the block is freed when another block is put into the same format and when the process empties the clipboard
   (measured on Windows Server 2022). The kernel's handle of the copy tells whether the clipboard still holds
   what this process put there. */
#define MAX_OWN_DATA 48
static struct { UINT fmt; HANDLE hKernel; HANDLE hLocal; } g_OwnData[MAX_OWN_DATA];
static LONG g_OwnLock;

static VOID IntOwnLock(VOID) { while (InterlockedExchange(&g_OwnLock, 1)) Sleep(0); }
static VOID IntOwnUnlock(VOID) { InterlockedExchange(&g_OwnLock, 0); }

/* a block the application may have freed against the rules: never trust it blindly */
static VOID
IntFreeOwnBlock(HANDLE hLocal)
{
    _SEH2_TRY
    {
        if (hLocal && GlobalFlags(hLocal) != GMEM_INVALID_HANDLE)
            GlobalFree(hLocal);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
    }
    _SEH2_END;
}

static VOID
IntOwnRecord(UINT fmt, HANDLE hKernel, HANDLE hLocal)
{
    int i, iFree = -1;
    HANDLE hOld = NULL;

    IntOwnLock();
    for (i = 0; i < MAX_OWN_DATA; i++)
    {
        if (g_OwnData[i].hLocal && g_OwnData[i].fmt == fmt)
        {
            if (g_OwnData[i].hLocal != hLocal)
                hOld = g_OwnData[i].hLocal;
            g_OwnData[i].hKernel = hKernel;
            g_OwnData[i].hLocal = hLocal;
            goto done;
        }
        if (!g_OwnData[i].hLocal && iFree < 0)
            iFree = i;
    }
    if (iFree >= 0)
    {
        g_OwnData[iFree].fmt = fmt;
        g_OwnData[iFree].hKernel = hKernel;
        g_OwnData[iFree].hLocal = hLocal;
    }
done:
    IntOwnUnlock();
    if (hOld)
        IntFreeOwnBlock(hOld);
}

static HANDLE
IntOwnFind(UINT fmt, HANDLE hKernel)
{
    int i;
    HANDLE h = NULL;

    IntOwnLock();
    for (i = 0; i < MAX_OWN_DATA; i++)
    {
        if (g_OwnData[i].hLocal && g_OwnData[i].fmt == fmt && g_OwnData[i].hKernel == hKernel)
        {
            h = g_OwnData[i].hLocal;
            break;
        }
    }
    IntOwnUnlock();
    return h;
}

static VOID
IntOwnFreeAll(VOID)
{
    int i;
    HANDLE ah[MAX_OWN_DATA];
    int n = 0;

    IntOwnLock();
    for (i = 0; i < MAX_OWN_DATA; i++)
    {
        if (g_OwnData[i].hLocal)
            ah[n++] = g_OwnData[i].hLocal;
        g_OwnData[i].hLocal = NULL;
        g_OwnData[i].hKernel = NULL;
    }
    IntOwnUnlock();
    for (i = 0; i < n; i++)
        IntFreeOwnBlock(ah[i]);
}

/*
 * @implemented
 */
BOOL
WINAPI
EmptyClipboard(VOID)
{
    BOOL ret = NtUserEmptyClipboard();

    if (ret)
        IntOwnFreeAll();
    return ret;
}

/* The code page a clipboard text is in, from the CF_LOCALE the clipboard holds (Windows
   converts text with the code pages of that locale, ANSI or OEM; with no usable CF_LOCALE it
   uses the system's; a block of two or three bytes is read as the low bytes of the LCID, one byte
   is no locale: measured on Windows Server 2022). hLocale is the kernel's handle of the CF_LOCALE
   data, or NULL. */
static UINT
IntClipboardCodePage(HANDLE hLocale, BOOL bOem)
{
    LCID lcid = 0;
    DWORD cbLocale = 0, cp = 0;

    if (hLocale &&
        NT_SUCCESS(NtUserCreateLocalMemHandle(hLocale, &lcid, sizeof(lcid), &cbLocale)) &&
        cbLocale >= sizeof(WORD) &&
        GetLocaleInfoW(lcid, (bOem ? LOCALE_IDEFAULTCODEPAGE : LOCALE_IDEFAULTANSICODEPAGE) | LOCALE_RETURN_NUMBER,
                       (LPWSTR)&cp, sizeof(cp) / sizeof(WCHAR)) &&
        cp != 0 && IsValidCodePage(cp))
    {
        return cp;
    }

    return bOem ? CP_OEMCP : CP_ACP;
}

/* The text of another text format, in a new global block of its own, converted with the given
   code pages (cpSrc for a narrow source, cpDst for a narrow result). The block is as long as
   the conversion of everything the source holds and always ends with a terminator, as on
   Windows: the source belongs to another process and need not have one. cchSrc counts the
   characters of the source (bytes for the narrow formats, words for UNICODE). NULL when the
   conversion fails (a code page without tables, no memory). */
static HGLOBAL
IntSynthesizeTextCp(PVOID pSrc, DWORD cchSrc, UINT fmtSrc, UINT fmtDst, UINT cpSrc, UINT cpDst)
{
    PWSTR pwsWork = NULL;
    PVOID pwSrc = pSrc;
    HGLOBAL hGlobal = NULL;
    INT cch = 0, cbChar, cbGlobal;

    if (fmtSrc != CF_UNICODETEXT)
    {
        /* through UNICODE: the narrow formats convert into each other by it */
        if (cchSrc)
        {
            cch = MultiByteToWideChar(cpSrc, 0, pSrc, cchSrc, NULL, 0);
            if (cch == 0)
                return NULL;
            pwsWork = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, (cch + 1) * sizeof(WCHAR));
            if (!pwsWork)
                return NULL;
            cch = MultiByteToWideChar(cpSrc, 0, pSrc, cchSrc, pwsWork, cch);
            if (cch == 0)
                goto done;
        }
        pwSrc = pwsWork;
    }
    else
        cch = cchSrc;

    if (fmtDst == CF_UNICODETEXT)
    {
        cbChar = sizeof(WCHAR);
        cbGlobal = (cch ? cch : 1) * sizeof(WCHAR);
    }
    else
    {
        cbChar = 1;
        cbGlobal = cch ? WideCharToMultiByte(cpDst, 0, pwSrc, cch, NULL, 0, NULL, NULL) : 1;
        if (cbGlobal < 1)
            goto done;
    }

    /* fixed memory, as the data of another process is on Windows (measured) */
    hGlobal = GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, cbGlobal);
    if (!hGlobal)
        goto done;

    if (cch)
    {
        if (fmtDst == CF_UNICODETEXT)
            RtlCopyMemory(hGlobal, pwSrc, cch * sizeof(WCHAR));
        else if (WideCharToMultiByte(cpDst, 0, pwSrc, cch, hGlobal, cbGlobal, NULL, NULL) == 0)
        {
            GlobalFree(hGlobal);
            hGlobal = NULL;
            goto done;
        }
    }
    /* the terminator, whatever the source had */
    RtlZeroMemory((PBYTE)hGlobal + cbGlobal - cbChar, cbChar);

done:
    if (pwsWork)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pwsWork);
    return hGlobal;
}

/* Converts with the code pages of the clipboard's locale; a code page that cannot convert (its
   tables are missing, or it cannot represent the text at all) falls back to the system's */
static HGLOBAL
IntSynthesizeText(PVOID pSrc, DWORD cchSrc, UINT fmtSrc, UINT fmtDst, HANDLE hLocale)
{
    UINT cpSrc = 0, cpDst = 0;
    HGLOBAL hGlobal;

    if (fmtSrc != CF_UNICODETEXT)
        cpSrc = IntClipboardCodePage(hLocale, fmtSrc == CF_OEMTEXT);
    if (fmtDst != CF_UNICODETEXT)
        cpDst = IntClipboardCodePage(hLocale, fmtDst == CF_OEMTEXT);

    hGlobal = IntSynthesizeTextCp(pSrc, cchSrc, fmtSrc, fmtDst, cpSrc, cpDst);
    if (!hGlobal && hLocale)
    {
        if (fmtSrc != CF_UNICODETEXT)
            cpSrc = (fmtSrc == CF_OEMTEXT) ? CP_OEMCP : CP_ACP;
        if (fmtDst != CF_UNICODETEXT)
            cpDst = (fmtDst == CF_OEMTEXT) ? CP_OEMCP : CP_ACP;
        hGlobal = IntSynthesizeTextCp(pSrc, cchSrc, fmtSrc, fmtDst, cpSrc, cpDst);
    }
    return hGlobal;
}

/*
 * @implemented
 */
HANDLE
WINAPI
GetClipboardData(UINT uFormat)
{
    HANDLE hData = NULL;
    PVOID pData = NULL;
    DWORD cbData = 0;
    GETCLIPBDATA gcd;

    RtlZeroMemory(&gcd, sizeof(gcd));
    hData = NtUserGetClipboardData(uFormat, &gcd);
    if (!hData)
        return NULL;

    switch (uFormat)
    {
        case CF_DSPMETAFILEPICT:
        case CF_METAFILEPICT:
            return GdiCreateLocalMetaFilePict(hData);
        case CF_DSPENHMETAFILE:
        case CF_ENHMETAFILE:
            return GdiCreateLocalEnhMetaFile(hData);
    }

    if (gcd.fGlobalHandle)
    {
        HANDLE hGlobal, hOwn;

        /* what this process put there itself comes back as it was put (same handle) */
        hOwn = (gcd.uFmtRet == uFormat) ? IntOwnFind(uFormat, hData) : NULL;
        if (hOwn)
            return hOwn;

        NtUserCreateLocalMemHandle(hData, NULL, 0, &cbData);
        /* the copy is fixed memory, as the data of another process is on Windows (measured) */
        hGlobal = GlobalAlloc(GMEM_FIXED, cbData);
        if (!hGlobal)
            return NULL;
        pData = hGlobal;
        NtUserCreateLocalMemHandle(hData, pData, cbData, NULL);
        hData = hGlobal;
    }

    if (gcd.uFmtRet != uFormat)
    {
        SETCLIPBDATA scd = {FALSE, FALSE};
        HGLOBAL hNewData = NULL;
        BOOL bText = FALSE;

        /* Synthesize requested format */
        switch (uFormat)
        {
            case CF_TEXT:
            case CF_OEMTEXT:
            case CF_UNICODETEXT:
                if (pData && (gcd.uFmtRet == CF_TEXT || gcd.uFmtRet == CF_OEMTEXT || gcd.uFmtRet == CF_UNICODETEXT))
                {
                    bText = TRUE;
                    DWORD cch = (gcd.uFmtRet == CF_UNICODETEXT) ? cbData / sizeof(WCHAR) : cbData;
                    hNewData = IntSynthesizeText(pData, cch, gcd.uFmtRet, uFormat, gcd.hLocale);
                }
                break;
            default:
                FIXME("Format: %u != %u\n", uFormat, gcd.uFmtRet);
        }

        if (hNewData)
        {
            /* Free old data */
            if (pData)
                GlobalFree(hData);
            hData = hNewData;
            pData = hData;
        }
        else if (pData && bText)
        {
            /* the conversion failed (no memory): nothing to hand out */
            GlobalFree(hData);
            return NULL;
        }

        /* Save synthesized format in clipboard */
        if (pData)
        {
            HANDLE hMem;

            scd.fGlobalHandle = TRUE;
            hMem = NtUserConvertMemHandle(pData, GlobalSize(hData));
            NtUserSetClipboardData(uFormat, hMem, &scd);
        }
        else if (hData)
            NtUserSetClipboardData(uFormat, hData, &scd);
    }

    return hData;
}

/*
 * @implemented
 */
HANDLE
WINAPI
SetClipboardData(UINT uFormat, HANDLE hMem)
{
    DWORD dwSize;
    HANDLE hGlobal;
    LPVOID pMem;
    HANDLE hRet = NULL, hTemp;
    /* An application's SetClipboardData is a clipboard change (sequence number,
       viewers and listeners); the formats GetClipboardData synthesizes are not */
    SETCLIPBDATA scd = {FALSE, TRUE};

    /* The format number (measured on Windows Server 2022): a low word of 0 is no format
       (format 0 itself is the kernel's answer: the clipboard is not open) and the registered
       range must hold a registered format. A global block is made from the caller's only
       after this, so that a refusal leaves nothing behind. */
    if (uFormat != 0)
    {
        if (LOWORD(uFormat) == 0)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
        }
        if (LOWORD(uFormat) >= 0xC000)
        {
            WCHAR awcName[256];

            if (NtUserGetClipboardFormatName(LOWORD(uFormat), awcName, _countof(awcName)) == 0)
            {
                SetLastError(ERROR_INVALID_HANDLE);
                return NULL;
            }
        }
    }

    /* Check if this is a delayed rendering */
    if (hMem == NULL)
        return NtUserSetClipboardData(uFormat, NULL, &scd);

    if (hMem <= (HANDLE)4)
        SetLastError(ERROR_INVALID_PARAMETER);
    /* Bitmaps and palette does not use global handles */
    else if (uFormat == CF_BITMAP || uFormat == CF_DSPBITMAP || uFormat == CF_PALETTE)
        hRet = NtUserSetClipboardData(uFormat, hMem, &scd);
    /* Meta files are probably checked for validity */
    else if (uFormat == CF_DSPMETAFILEPICT || uFormat == CF_METAFILEPICT )
    {
        SetLastError(NO_ERROR);
        hTemp = GdiConvertMetaFilePict( hMem );
        if (!hTemp)
        {
            /* not a metafile picture: refuse (a NULL handle would mean delayed rendering).
               A handle that is no global memory at all is an invalid handle; a global block
               that holds no metafile is refused without an error code (measured). */
            if (GetLastError() == NO_ERROR && GlobalFlags(hMem) == GMEM_INVALID_HANDLE)
                SetLastError(ERROR_INVALID_HANDLE);
            return NULL;
        }
        hRet = NtUserSetClipboardData(uFormat, hTemp, &scd); // Note : LOL, it returns a BOOL not a HANDLE!!!!
        if (hRet == hTemp) hRet = hMem;                      // If successful "TRUE", return the original handle.
    }
    else if (uFormat == CF_DSPENHMETAFILE || uFormat == CF_ENHMETAFILE)
    {
        SetLastError(NO_ERROR);
        hTemp = GdiConvertEnhMetaFile( hMem );
        if (!hTemp)
        {
            if (GetLastError() == NO_ERROR)
                SetLastError(ERROR_INVALID_HANDLE);
            return NULL;
        }
        hRet = NtUserSetClipboardData(uFormat, hTemp, &scd);
        if (hRet == hTemp) hRet = hMem;
    }
    else
    {
        /* Some formats accept only global handles, other accept global handles or integer values */
        pMem = GlobalLock(hMem);
        dwSize = GlobalSize(hMem);

        if (pMem || uFormat == CF_DIB || uFormat == CF_DIBV5 ||
            uFormat == CF_DSPTEXT || uFormat == CF_LOCALE ||
            uFormat == CF_OEMTEXT || uFormat == CF_TEXT ||
            uFormat == CF_UNICODETEXT)
        {
            if (pMem)
            {
                /* The text formats end with a terminator the system puts there, in the
                   caller's own block (measured: TEXT, OEMTEXT and DSPTEXT lose the last
                   byte, UNICODETEXT the last word, and a UNICODETEXT block shorter than a
                   word is refused without an error code) */
                if (uFormat == CF_TEXT || uFormat == CF_OEMTEXT || uFormat == CF_DSPTEXT)
                {
                    if (dwSize >= sizeof(CHAR))
                        ((PBYTE)pMem)[dwSize - sizeof(CHAR)] = 0;
                }
                else if (uFormat == CF_UNICODETEXT)
                {
                    if (dwSize < sizeof(WCHAR))
                    {
                        GlobalUnlock(hMem);
                        SetLastError(NO_ERROR);
                        return NULL;
                    }
                    ((PBYTE)pMem)[dwSize - 2] = 0;
                    ((PBYTE)pMem)[dwSize - 1] = 0;
                }

                /* This is a local memory. Make global memory object */
                hGlobal = NtUserConvertMemHandle(pMem, dwSize);

                /* Unlock memory */
                GlobalUnlock(hMem);
                /* FIXME: free hMem when CloseClipboard is called */

                if (hGlobal)
                {
                    /* Save data */
                    scd.fGlobalHandle = TRUE;
                    hRet = NtUserSetClipboardData(uFormat, hGlobal, &scd);
                }

                /* On success NtUserSetClipboardData returns pMem
                   however caller expects us to return hMem */
                if (hRet == hGlobal)
                {
                    IntOwnRecord(uFormat, hGlobal, hMem);
                    hRet = hMem;
                }
            }
            else
                SetLastError(ERROR_INVALID_HANDLE);
        }
        else
        {
            /* Save a number */
            hRet = NtUserSetClipboardData(uFormat, hMem, &scd);
        }
    }

    if (!hRet)
        ERR("SetClipboardData(%u, %p) failed\n", uFormat, hMem);

    return hRet;
}

/*
 * @implemented
 */
BOOL
WINAPI
AddClipboardFormatListener(HWND hwnd)
{
    return NtUserAddClipboardFormatListener(hwnd);
}

/*
 * @implemented
 */
BOOL
WINAPI
RemoveClipboardFormatListener(HWND hwnd)
{
    return NtUserRemoveClipboardFormatListener(hwnd);
}

/*
 * @implemented
 */
BOOL
WINAPI
GetUpdatedClipboardFormats(PUINT lpuiFormats,
                           UINT cFormats,
                           PUINT pcFormatsOut)
{
    return NtUserGetUpdatedClipboardFormats(lpuiFormats, cFormats, pcFormatsOut);
}
