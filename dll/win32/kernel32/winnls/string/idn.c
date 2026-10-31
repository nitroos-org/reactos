/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IdnToAscii, IdnToUnicode and IdnToNameprepUnicode: the checks of the arguments and the
 *              conversion of NUL terminated strings of Windows around the conversions of Wine (IdnToAscii.c,
 *              IdnToUnicode.c, nameprep.c)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define WIN32_NO_STATUS
#include <wine/unicode.h>

/* kernel32 does not call its own HeapAlloc and HeapFree, they are the heap functions of ntdll */
NTSYSAPI PVOID NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
NTSYSAPI BOOLEAN NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);

#ifndef IDN_ALLOW_UNASSIGNED
#define IDN_ALLOW_UNASSIGNED 0x01
#define IDN_USE_STD3_ASCII_RULES 0x02
#endif

INT WINAPI IdnpToNameprep(DWORD dwFlags, LPCWSTR lpUnicodeCharStr, INT cchUnicodeChar,
                          LPWSTR lpNameprepCharStr, INT cchNameprepChar);
INT WINAPI IdnpToAscii(DWORD dwFlags, LPCWSTR lpUnicodeCharStr, INT cchUnicodeChar,
                       LPWSTR lpASCIICharStr, INT cchASCIIChar);
INT WINAPI IdnpToUnicode(DWORD dwFlags, LPCWSTR lpASCIICharStr, INT cchASCIIChar,
                         LPWSTR lpUnicodeCharStr, INT cchUnicodeChar);

typedef INT (WINAPI *IDN_FUNC)(DWORD, LPCWSTR, INT, LPWSTR, INT);

/*
 * The checks of Windows 10 (measured on 22H2) that come before the conversion: flags, then the string, then
 * the destination (a size of zero asks for the size, a negative one, or a size without a buffer, is an invalid
 * parameter), and an empty string is an invalid name. A string that ends in a NUL (length -1) is converted
 * without it, and the NUL is part of the result and of its length.
 */
static INT IdnConvert(IDN_FUNC convert, DWORD dwFlags, LPCWSTR src, INT cchSrc, LPWSTR dst, INT cchDst)
{
    INT ret;

    if (dwFlags & ~(IDN_ALLOW_UNASSIGNED | IDN_USE_STD3_ASCII_RULES))
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return 0;
    }
    if (!src || cchSrc < -1 || cchDst < 0 || (!dst && cchDst))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (cchSrc == -1)
    {
        cchSrc = (INT)strlenW(src);
        if (!dst)
        {
            ret = cchSrc ? convert(dwFlags, src, cchSrc, NULL, 0) : 0;
            if (!ret)
            {
                if (!cchSrc) SetLastError(ERROR_INVALID_NAME);
                return 0;
            }
            return ret + 1;
        }
        if (!cchSrc)
        {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }
        if (!cchDst)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        ret = convert(dwFlags, src, cchSrc, dst, cchDst - 1);
        if (!ret)
            return 0;
        dst[ret] = 0;
        return ret + 1;
    }

    if (!cchSrc)
    {
        SetLastError(ERROR_INVALID_NAME);
        return 0;
    }
    /* a size of zero is the size query, with or without a buffer */
    return convert(dwFlags, src, cchSrc, cchDst ? dst : NULL, cchDst);
}

/******************************************************************************
 *           IdnToNameprepUnicode (KERNEL32.@)
 */
INT WINAPI IdnToNameprepUnicode(DWORD dwFlags, LPCWSTR lpUnicodeCharStr, INT cchUnicodeChar,
                                LPWSTR lpNameprepCharStr, INT cchNameprepChar)
{
    return IdnConvert(IdnpToNameprep, dwFlags, lpUnicodeCharStr, cchUnicodeChar, lpNameprepCharStr, cchNameprepChar);
}

/******************************************************************************
 *           IdnToAscii (KERNEL32.@)
 */
INT WINAPI IdnToAscii(DWORD dwFlags, LPCWSTR lpUnicodeCharStr, INT cchUnicodeChar,
                      LPWSTR lpASCIICharStr, INT cchASCIIChar)
{
    return IdnConvert(IdnpToAscii, dwFlags, lpUnicodeCharStr, cchUnicodeChar, lpASCIICharStr, cchASCIIChar);
}

/* the conversion of the labels, then the check that Windows makes: the name converted back has to be the
   name that was given (ToUnicode is the reverse of ToAscii; what is not a result of it is an invalid name),
   and what is returned is the nameprepped form (the case of a decoded label is lost) */
static INT WINAPI IdnpToUnicodeWorker(DWORD dwFlags, LPCWSTR src, INT cchSrc, LPWSTR dst, INT cchDst)
{
    HANDLE heap = GetProcessHeap();
    WCHAR *decoded = NULL, *prepped = NULL, *again = NULL;
    INT decoded_len, prepped_len, again_len, ret = 0;
    DWORD error = ERROR_SUCCESS;
    INT i;

    decoded_len = IdnpToUnicode(dwFlags, src, cchSrc, NULL, 0);
    if (!decoded_len)
        return 0;
    if (!(decoded = RtlAllocateHeap(heap, 0, decoded_len * sizeof(WCHAR))))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    decoded_len = IdnpToUnicode(dwFlags, src, cchSrc, decoded, decoded_len);
    if (!decoded_len)
        goto done;

    prepped_len = IdnpToNameprep(dwFlags, decoded, decoded_len, NULL, 0);
    if (!prepped_len)
        goto done;
    if (!(prepped = RtlAllocateHeap(heap, 0, prepped_len * sizeof(WCHAR))))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto done;
    }
    prepped_len = IdnpToNameprep(dwFlags, decoded, decoded_len, prepped, prepped_len);
    if (!prepped_len)
        goto done;

    again_len = IdnpToAscii(dwFlags, prepped, prepped_len, NULL, 0);
    if (!again_len)
        goto done;
    if (!(again = RtlAllocateHeap(heap, 0, again_len * sizeof(WCHAR))))
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto done;
    }
    again_len = IdnpToAscii(dwFlags, prepped, prepped_len, again, again_len);
    if (again_len != cchSrc)
        error = ERROR_INVALID_NAME;
    else
        for (i = 0; i < cchSrc; i++)
            if (tolowerW(again[i]) != tolowerW(src[i]))
            {
                error = ERROR_INVALID_NAME;
                break;
            }
    if (error)
    {
        SetLastError(error);
        goto done;
    }

    if (!dst)
    {
        ret = prepped_len;
    }
    else if (prepped_len > cchDst)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
    }
    else
    {
        memcpy(dst, prepped, prepped_len * sizeof(WCHAR));
        ret = prepped_len;
    }

done:
    if (again) RtlFreeHeap(heap, 0, again);
    if (prepped) RtlFreeHeap(heap, 0, prepped);
    RtlFreeHeap(heap, 0, decoded);
    return ret;
}

/* a result of zero that gave no error is an invalid name (a label "xn--" with nothing after it); the last error
   of a success is left as it was */
static INT WINAPI IdnpToUnicodeChecked(DWORD dwFlags, LPCWSTR src, INT cchSrc, LPWSTR dst, INT cchDst)
{
    DWORD old_error = GetLastError();
    INT ret;

    SetLastError(ERROR_SUCCESS);
    ret = IdnpToUnicodeWorker(dwFlags, src, cchSrc, dst, cchDst);
    if (ret)
        SetLastError(old_error);
    else if (!GetLastError())
        SetLastError(ERROR_INVALID_NAME);
    return ret;
}

/******************************************************************************
 *           IdnToUnicode (KERNEL32.@)
 */
INT WINAPI IdnToUnicode(DWORD dwFlags, LPCWSTR lpASCIICharStr, INT cchASCIIChar,
                        LPWSTR lpUnicodeCharStr, INT cchUnicodeChar)
{
    return IdnConvert(IdnpToUnicodeChecked, dwFlags, lpASCIICharStr, cchASCIIChar, lpUnicodeCharStr, cchUnicodeChar);
}
