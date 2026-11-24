/*
 * PROJECT:     ReactOS Spooler API
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Information structures for 32-bit callers on a 64-bit system
 *
 * The spooler service of a 64-bit system fills the buffer of every Get*, Enum* and AddJob call with the layout of the
 * 64-bit structures (8-byte pointers, replaced by offsets relative to the start of each structure). A 32-bit
 * winspool.drv has to hand its caller the 32-bit layout of the same public structures (PRINTER_INFO_n, DRIVER_INFO_n,
 * JOB_INFO_n, FORM_INFO_n, PORT_INFO_n, MONITOR_INFO_n, ...), so it receives the 64-bit block into a temporary buffer
 * and converts it. Only the public layouts are used: each structure is described by one letter per member
 * (see Wow64Shapes below).
 */

#include "precomp.h"

#ifdef _M_IX86

#define MAX_SHAPE_FIELDS 32

typedef struct _WOW64_SHAPE
{
    const CHAR* pszFields;
}
WOW64_SHAPE;

/*
 * Member letters, in declaration order:
 *   D  DWORD / LONG (also the members of SIZEL and RECTL)       W  WORD / LANGID / USHORT
 *   T  SYSTEMTIME   F  FILETIME   Q  DWORDLONG
 *   S  pointer to a NUL-terminated WCHAR string                 A  pointer to a NUL-terminated CHAR string
 *   M  pointer to a MULTI_SZ WCHAR string                      V  pointer to a DEVMODEW
 *   X  pointer to a self-relative SECURITY_DESCRIPTOR
 */

static const CHAR* const PrinterShapes[] =
{
    "SSDDDTDDDDDDDDDDDDDDDDDDWWDDD",    /* 0: PRINTER_INFO_STRESS */
    "DSSS",                             /* 1 */
    "SSSSSSSVSSSSXDDDDDDDD",            /* 2 */
    "X",                                /* 3 */
    "SSD",                              /* 4 */
    "SSDDD",                            /* 5 */
    "D",                                /* 6 */
    "SD",                               /* 7 */
    "V",                                /* 8 */
    "V"                                 /* 9 */
};

static const CHAR* const DriverShapes[] =
{
    NULL,
    "S",                                /* 1 */
    "DSSSSS",                           /* 2 */
    "DSSSSSSMSS",                       /* 3 */
    "DSSSSSSMSSM",                      /* 4 */
    "DSSSSSDDD",                        /* 5 */
    "DSSSSSSMSSMFQSSSS",                /* 6 */
    NULL,
    "DSSSSSSMSSMFQSSSSSSMSDMFQ"         /* 8 */
};

static const CHAR* const FormShapes[] =
{
    NULL,
    "DSDDDDDD",                         /* 1 */
    "DSDDDDDDADSDSW"                    /* 2 */
};

static const CHAR* const JobShapes[] =
{
    NULL,
    "DSSSSSSDDDDDT",                    /* 1 */
    "DSSSSSSSSSVSXDDDDDDDTDD"           /* 2 */
};

static const CHAR* const PortShapes[] =
{
    NULL,
    "S",                                /* 1 */
    "SSSDD"                             /* 2 */
};

static const CHAR* const MonitorShapes[] =
{
    NULL,
    "S",                                /* 1 */
    "SSS"                               /* 2 */
};

static const CHAR* GetShape(DWORD Kind, DWORD Level)
{
    switch (Kind)
    {
        case WOW64_KIND_PRINTER:   return (Level < _countof(PrinterShapes)) ? PrinterShapes[Level] : NULL;
        case WOW64_KIND_DRIVER:    return (Level < _countof(DriverShapes)) ? DriverShapes[Level] : NULL;
        case WOW64_KIND_FORM:      return (Level < _countof(FormShapes)) ? FormShapes[Level] : NULL;
        case WOW64_KIND_JOB:       return (Level < _countof(JobShapes)) ? JobShapes[Level] : NULL;
        case WOW64_KIND_PORT:      return (Level < _countof(PortShapes)) ? PortShapes[Level] : NULL;
        case WOW64_KIND_MONITOR:   return (Level < _countof(MonitorShapes)) ? MonitorShapes[Level] : NULL;
        case WOW64_KIND_DATATYPE:  return (Level == 1) ? "S" : NULL;
        case WOW64_KIND_PROCESSOR: return (Level == 1) ? "S" : NULL;
        case WOW64_KIND_ADDJOB:    return (Level == 1) ? "SD" : NULL;
    }
    return NULL;
}

#ifdef __GNUC__
#define ALIGNOF_QWORD32 __alignof__(DWORDLONG)
#else
#define ALIGNOF_QWORD32 __alignof(DWORDLONG)
#endif

typedef struct _WOW64_LAYOUT
{
    DWORD cFields;
    DWORD cbStruct;
    DWORD Offset[MAX_SHAPE_FIELDS];
    DWORD cbField[MAX_SHAPE_FIELDS];
}
WOW64_LAYOUT;

static BOOL
IsPointerLetter(CHAR c)
{
    return c == 'S' || c == 'A' || c == 'M' || c == 'V' || c == 'X';
}

/* Compute the offsets of the members for a 32-bit or 64-bit compiler, using the public declaration order. */
static BOOL
ComputeLayout(const CHAR* pszShape, DWORD cbPointer, WOW64_LAYOUT* pLayout)
{
    DWORD cbAt = 0, cbMaxAlign = 1, i;

    for (i = 0; pszShape[i]; i++)
    {
        DWORD cb, cbAlign;

        if (i >= MAX_SHAPE_FIELDS)
            return FALSE;

        if (IsPointerLetter(pszShape[i]))
        {
            cb = cbAlign = cbPointer;
        }
        else switch (pszShape[i])
        {
            case 'D': cb = cbAlign = 4; break;
            case 'W': cb = cbAlign = 2; break;
            case 'T': cb = 16; cbAlign = 2; break;
            case 'F': cb = 8; cbAlign = 4; break;
            case 'Q': cb = 8; cbAlign = (cbPointer == 8) ? 8 : ALIGNOF_QWORD32; break;
            default: return FALSE;
        }

        cbAt = (cbAt + cbAlign - 1) & ~(cbAlign - 1);
        pLayout->Offset[i] = cbAt;
        pLayout->cbField[i] = cb;
        cbAt += cb;
        if (cbAlign > cbMaxAlign)
            cbMaxAlign = cbAlign;
    }

    pLayout->cFields = i;
    pLayout->cbStruct = (cbAt + cbMaxAlign - 1) & ~(cbMaxAlign - 1);
    return TRUE;
}

/* Length in bytes of the data a pointer member refers to, or 0 if the data is not complete inside [pData, pData + cbAvail). */
static DWORD
BlobSize(CHAR Letter, const BYTE* pData, DWORD cbAvail)
{
    DWORD i;

    switch (Letter)
    {
        case 'S':
            for (i = 0; i + 1 < cbAvail; i += 2)
                if (!pData[i] && !pData[i + 1])
                    return i + 2;
            return 0;

        case 'A':
            for (i = 0; i < cbAvail; i++)
                if (!pData[i])
                    return i + 1;
            return 0;

        case 'M':
            for (i = 0; i + 3 < cbAvail; i += 2)
                if (!pData[i] && !pData[i + 1] && !pData[i + 2] && !pData[i + 3])
                    return i + 4;
            return 0;

        case 'V':
        {
            /* DEVMODEW: dmSize at offset 68, dmDriverExtra at offset 70 */
            DWORD cb;

            if (cbAvail < 72)
                return 0;
            cb = (DWORD)*(const WORD*)(pData + 68) + *(const WORD*)(pData + 70);
            if (cb < 72 || cb > cbAvail)
                return 0;
            return cb;
        }

        case 'X':
        {
            /* Self-relative SECURITY_DESCRIPTOR: header is 20 bytes */
            DWORD cb;

            if (cbAvail < SECURITY_DESCRIPTOR_MIN_LENGTH)
                return 0;
            if (!(*(const WORD*)(pData + 2) & SE_SELF_RELATIVE))
                return 0;
            if (!IsValidSecurityDescriptor((PSECURITY_DESCRIPTOR)pData))
                return 0;
            cb = GetSecurityDescriptorLength((PSECURITY_DESCRIPTOR)pData);
            if (cb > cbAvail)
                return 0;
            return cb;
        }
    }

    return 0;
}

static DWORD
ConvertBlock(const CHAR* pszShape, const BYTE* pSrc, DWORD cbSrc, DWORD cElements, PBYTE pDst, PDWORD pcbOut)
{
    WOW64_LAYOUT Src, Dst;
    DWORD cbAt, e, i;

    if (!ComputeLayout(pszShape, 8, &Src) || !ComputeLayout(pszShape, 4, &Dst))
        return ERROR_INVALID_DATA;

    if (cElements > 0x100000 || (ULONGLONG)cElements * Src.cbStruct > cbSrc)
        return ERROR_INVALID_DATA;

    cbAt = (cElements * Dst.cbStruct + 7) & ~7;

    for (e = 0; e < cElements; e++)
    {
        const BYTE* pElement = pSrc + (SIZE_T)e * Src.cbStruct;
        DWORD cbLeft = cbSrc - e * Src.cbStruct;

        for (i = 0; i < Src.cFields; i++)
        {
            CHAR Letter = pszShape[i];

            if (!IsPointerLetter(Letter))
            {
                if (pDst)
                    CopyMemory(pDst + e * Dst.cbStruct + Dst.Offset[i], pElement + Src.Offset[i], Src.cbField[i]);
            }
            else
            {
                ULONGLONG Offset;
                DWORD cb, cbAlign;
                BOOL bEmpty = FALSE;

                CopyMemory(&Offset, pElement + Src.Offset[i], sizeof(Offset));
                if (!Offset)
                {
                    if (pDst)
                        *(DWORD*)(pDst + e * Dst.cbStruct + Dst.Offset[i]) = 0;
                    continue;
                }

                if (Offset >= cbLeft)
                    return ERROR_INVALID_DATA;

                cb = BlobSize(Letter, pElement + Offset, cbLeft - (DWORD)Offset);
                if (!cb && Letter == 'X' && cbLeft - (DWORD)Offset >= SECURITY_DESCRIPTOR_MIN_LENGTH)
                {
                    /* The local provider hands out an all-zero SECURITY_DESCRIPTOR structure (not self-relative, not valid).
                       Its size is that of the 64-bit structure; give the 32-bit caller an equally empty one of its own size. */
                    cb = SECURITY_DESCRIPTOR_MIN_LENGTH;
                    bEmpty = TRUE;
                }
                if (!cb)
                    return ERROR_INVALID_DATA;

                cbAlign = (Letter == 'V' || Letter == 'X') ? 8 : 2;
                cbAt = (cbAt + cbAlign - 1) & ~(cbAlign - 1);
                if (pDst)
                {
                    if (!bEmpty)
                        CopyMemory(pDst + cbAt, pElement + Offset, cb);
                    *(DWORD*)(pDst + e * Dst.cbStruct + Dst.Offset[i]) = (DWORD)(ULONG_PTR)(pDst + cbAt);
                }
                cbAt += cb;
            }
        }
    }

    *pcbOut = cbAt;
    return ERROR_SUCCESS;
}

#endif /* _M_IX86 */

BOOL
Wow64InfoBegin(PWOW64_INFO pInfo, DWORD Kind, DWORD Level, PBYTE pUser, DWORD cbUser)
{
    ZeroMemory(pInfo, sizeof(*pInfo));
    pInfo->Kind = Kind;
    pInfo->Level = Level;
    pInfo->pUser = pUser;
    pInfo->cbUser = cbUser;
    pInfo->pRpc = pUser;
    pInfo->cbRpc = cbUser;

#ifdef _M_IX86
    {
        static LONG lWow64 = -1;
        LONG lState = lWow64;

        if (lState < 0)
        {
            BOOL bWow64 = FALSE;

            if (!IsWow64Process(GetCurrentProcess(), &bWow64))
                bWow64 = FALSE;
            lState = bWow64 ? 1 : 0;
            InterlockedExchange(&lWow64, lState);
        }

        if (lState && GetShape(Kind, Level))
        {
            if (!pUser && cbUser)
            {
                /* A size without a buffer: let the spooler judge it (too small, or an invalid buffer) and only once it says
                   "too small" fetch the data into a temporary buffer to learn the size in the 32-bit layout. */
                pInfo->bWow64 = TRUE;
                pInfo->bProbe = TRUE;
            }
            else
            {
                DWORD cbInitial = cbUser * 2 + 4096;

                pInfo->pAlloc = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, cbInitial);
                if (pInfo->pAlloc)
                {
                    pInfo->bWow64 = TRUE;
                    pInfo->pRpc = pInfo->pAlloc;
                    pInfo->cbRpc = cbInitial;
                }
            }
        }
    }
#endif

    return pInfo->bWow64;
}

BOOL
Wow64InfoRetry(PWOW64_INFO pInfo, DWORD dwErrorCode, PDWORD pcbNeeded)
{
    PBYTE pNew;
    DWORD cbNeeded;

    if (!pInfo->bWow64 || dwErrorCode != ERROR_INSUFFICIENT_BUFFER || pInfo->cRetries >= 4)
        return FALSE;

    cbNeeded = *pcbNeeded;
    if (pInfo->bProbe)
    {
        pInfo->bProbe = FALSE;
        if (cbNeeded < 4096)
            cbNeeded = 4096;
    }
    else if (cbNeeded <= pInfo->cbRpc)
        return FALSE;

    pNew = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, cbNeeded);
    if (!pNew)
        return FALSE;

    HeapFree(hProcessHeap, 0, pInfo->pAlloc);
    pInfo->pAlloc = pNew;
    pInfo->pRpc = pNew;
    pInfo->cbRpc = cbNeeded;
    pInfo->cRetries++;
    return TRUE;
}

DWORD
Wow64InfoEnd(PWOW64_INFO pInfo, DWORD dwErrorCode, PDWORD pcbNeeded, PDWORD pcReturned)
{
    if (!pInfo->bWow64)
        return dwErrorCode;

    if (pInfo->bProbe)
        return dwErrorCode;     /* the spooler refused the size without a buffer itself: its answer stands */

#ifdef _M_IX86
    if (dwErrorCode == ERROR_SUCCESS)
    {
        DWORD cbSrc = *pcbNeeded;
        DWORD cElements = pcReturned ? *pcReturned : 1;
        DWORD cbOut = 0;

        if (cbSrc > pInfo->cbRpc)
            cbSrc = pInfo->cbRpc;

        dwErrorCode = ConvertBlock(GetShape(pInfo->Kind, pInfo->Level), pInfo->pRpc, cbSrc, cElements, NULL, &cbOut);
        if (dwErrorCode == ERROR_SUCCESS)
        {
            *pcbNeeded = cbOut;

            if (cbOut && pInfo->cbUser < cbOut)
            {
                if (pcReturned)
                    *pcReturned = 0;
                dwErrorCode = ERROR_INSUFFICIENT_BUFFER;
            }
            else if (cbOut && !pInfo->pUser)
            {
                /* a size that would do, but no buffer */
                *pcbNeeded = 0;
                if (pcReturned)
                    *pcReturned = 0;
                dwErrorCode = ERROR_INVALID_USER_BUFFER;
            }
            else
            {
                ZeroMemory(pInfo->pUser, cbOut);
                dwErrorCode = ConvertBlock(GetShape(pInfo->Kind, pInfo->Level), pInfo->pRpc, cbSrc, cElements, pInfo->pUser, &cbOut);
            }
        }
    }
    else if (dwErrorCode == ERROR_INSUFFICIENT_BUFFER && pcReturned)
    {
        *pcReturned = 0;
    }
#endif

    HeapFree(hProcessHeap, 0, pInfo->pAlloc);
    pInfo->pAlloc = NULL;
    return dwErrorCode;
}
