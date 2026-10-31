/*
 * PROJECT:         ReactOS system libraries
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Safer functions
 * PROGRAMMER:      Thomas Faber <thomas.faber@reactos.org>
 */

/* INCLUDES ******************************************************************/

#include <advapi32.h>
WINE_DEFAULT_DEBUG_CHANNEL(advapi);


/* FUNCTIONS *****************************************************************/

/**********************************************************************
 *  SaferCreateLevel
 *
 * @unimplemented
 */
BOOL
WINAPI
SaferCreateLevel(
    _In_ DWORD dwScopeId,
    _In_ DWORD dwLevelId,
    _In_ DWORD OpenFlags,
    _Outptr_ SAFER_LEVEL_HANDLE *pLevelHandle,
    _Reserved_ PVOID pReserved)
{
    FIXME("(%lu, %lu, %lu, %p, %p) stub\n", dwScopeId, dwLevelId, OpenFlags, pLevelHandle, pReserved);
    *pLevelHandle = (SAFER_LEVEL_HANDLE)0x42;
    return TRUE;
}


/**********************************************************************
 *  SaferIdentifyLevel
 *
 * @unimplemented
 */
BOOL
WINAPI
SaferIdentifyLevel(
    _In_ DWORD dwNumProperties,
    _In_reads_opt_(dwNumProperties) PSAFER_CODE_PROPERTIES pCodeProperties,
    _Outptr_ SAFER_LEVEL_HANDLE *pLevelHandle,
    _Reserved_ PVOID pReserved)
{
    DWORD i;

    if (pLevelHandle == NULL)
    {
        SetLastError(ERROR_NOACCESS);
        return FALSE;
    }

    for (i = 0; i < dwNumProperties; i++)
    {
        if (pCodeProperties[i].cbSize != sizeof(SAFER_CODE_PROPERTIES_V1))
        {
            SetLastError(ERROR_BAD_LENGTH);
            return FALSE;
        }
    }

    FIXME("(%lu, %p, %p, %p) stub\n", dwNumProperties, pCodeProperties, pLevelHandle, pReserved);

    *pLevelHandle = (SAFER_LEVEL_HANDLE)0x42;
    return TRUE;
}


/**********************************************************************
 *  SaferCloseLevel
 *
 * @unimplemented
 */
BOOL
WINAPI
SaferCloseLevel(
    _In_ SAFER_LEVEL_HANDLE hLevelHandle)
{
    FIXME("(%p) stub\n", hLevelHandle);
    if (hLevelHandle != (SAFER_LEVEL_HANDLE)0x42)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    return TRUE;
}


BOOL
WINAPI
SaferGetLevelInformation(
    _In_ SAFER_LEVEL_HANDLE LevelHandle,
    _In_ SAFER_OBJECT_INFO_CLASS dwInfoType,
    _Out_writes_bytes_opt_(dwInBufferSize) PVOID pQueryBuffer,
    _In_ DWORD dwInBufferSize,
    _Out_ PDWORD pdwOutBufferSize);


BOOL
WINAPI
SaferSetLevelInformation(
    _In_ SAFER_LEVEL_HANDLE LevelHandle,
    _In_ SAFER_OBJECT_INFO_CLASS dwInfoType,
    _In_reads_bytes_(dwInBufferSize) PVOID pQueryBuffer,
    _In_ DWORD dwInBufferSize);


/**********************************************************************
 *  SaferGetPolicyInformation
 *
 * @unimplemented
 */
BOOL
WINAPI
SaferGetPolicyInformation(
    _In_ DWORD dwScopeId,
    _In_ SAFER_POLICY_INFO_CLASS SaferPolicyInfoClass,
    _In_ DWORD InfoBufferSize,
    _Out_writes_bytes_opt_(InfoBufferSize) PVOID InfoBuffer,
    _Out_ PDWORD InfoBufferRetSize,
    _Reserved_ PVOID pReserved)
{
    FIXME("(%lu, %d, %lu, %p, %p, %p) stub\n", dwScopeId, SaferPolicyInfoClass, InfoBufferSize, InfoBuffer, InfoBufferRetSize, pReserved);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


BOOL
WINAPI
SaferSetPolicyInformation(
    _In_ DWORD dwScopeId,
    _In_ SAFER_POLICY_INFO_CLASS SaferPolicyInfoClass,
    _In_ DWORD InfoBufferSize,
    _In_reads_bytes_(InfoBufferSize) PVOID InfoBuffer,
    _Reserved_ PVOID pReserved);


/**********************************************************************
 *  SaferComputeTokenFromLevel
 *
 * @unimplemented
 */
BOOL
WINAPI
SaferComputeTokenFromLevel(
    _In_ SAFER_LEVEL_HANDLE LevelHandle,
    _In_opt_ HANDLE InAccessToken,
    _Out_ PHANDLE OutAccessToken,
    _In_ DWORD dwFlags,
    _Inout_opt_ PVOID pReserved)
{
    FIXME("(%p, %p, %p, 0x%lx, %p) stub\n", LevelHandle, InAccessToken, OutAccessToken, dwFlags, pReserved);
    *OutAccessToken = (dwFlags & SAFER_TOKEN_NULL_IF_EQUAL) ? NULL : UlongToHandle(0xdeadf00d);
    return TRUE;
}


/**********************************************************************
 *  SaferRecordEventLogEntry
 *
 * @unimplemented
 */
BOOL
WINAPI
SaferRecordEventLogEntry(
    _In_ SAFER_LEVEL_HANDLE hLevel,
    _In_ PCWSTR szTargetPath,
    _Reserved_ PVOID pReserved)
{
    FIXME("(%p, %s, %p) stub\n", hLevel, wine_dbgstr_w(szTargetPath), pReserved);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/* The default list of the extensions of the executable file types of the Software Restriction Policies
   (ExecutableTypes of the policy key; Windows takes the list from there when the value is set) */
static const WCHAR SaferExecutableTypes[][4] =
{
    L"ADE", L"ADP", L"BAS", L"BAT", L"CHM", L"CMD", L"COM", L"CPL", L"CRT", L"EXE", L"HLP", L"HTA", L"INF",
    L"INS", L"ISP", L"LNK", L"MDB", L"MDE", L"MSC", L"MSI", L"MSP", L"MST", L"OCX", L"PCD", L"PIF", L"REG",
    L"SCR", L"SHS", L"URL", L"VB", L"WSC"
};


/**********************************************************************
 *  SaferiIsExecutableFileType
 *
 * Whether the extension of the file name is one of the executable types. EXE is not one when the file is
 * started through ShellExecute (the shell has its own check for it). No match is ERROR_NOT_FOUND, an empty
 * name ERROR_INVALID_PARAMETER.
 */
BOOL
WINAPI
SaferiIsExecutableFileType(
    _In_ PCWSTR szFullPath,
    _In_ BOOLEAN bFromShellExecute)
{
    PCWSTR ext;
    SIZE_T i;

    TRACE("(%s, %u)\n", wine_dbgstr_w(szFullPath), bFromShellExecute);

    if (!szFullPath || !*szFullPath)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* the extension is what follows the last dot of the name, not of a directory */
    ext = wcsrchr(szFullPath, L'.');
    if (ext && (wcschr(ext, L'\\') || wcschr(ext, L'/')))
        ext = NULL;

    if (ext && ext[1])
    {
        for (i = 0; i < ARRAYSIZE(SaferExecutableTypes); i++)
        {
            if (_wcsicmp(ext + 1, SaferExecutableTypes[i]) != 0)
                continue;
            if (bFromShellExecute && _wcsicmp(ext + 1, L"EXE") == 0)
                break;
            return TRUE;
        }
    }

    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}


/**********************************************************************
 *  SaferiSearchMatchingHashRules
 *
 * Looks for a hash rule of the policy for a file hash: MD5 (16 bytes) and SHA-256 (32 bytes) are the hashes
 * that the policy knows, any other combination is an invalid parameter. This system has no hash rules, so
 * nothing is ever found (ERROR_NOT_FOUND).
 */
BOOL
WINAPI
SaferiSearchMatchingHashRules(
    _In_ ALG_ID HashAlgorithm,
    _In_reads_bytes_(HashSize) PBYTE Hash,
    _In_ DWORD HashSize,
    _In_ DWORD OriginalFileSize,
    _Out_ PDWORD FoundLevel,
    _Out_ PDWORD FoundFlags)
{
    TRACE("(%#x, %p, %lu, %lu, %p, %p)\n", HashAlgorithm, Hash, HashSize, OriginalFileSize, FoundLevel, FoundFlags);

    if (!Hash || !((HashAlgorithm == 0x8003 && HashSize == 16) || (HashAlgorithm == 0x800c && HashSize == 32)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!FoundLevel || !FoundFlags)
    {
        SetLastError(ERROR_NOACCESS);
        return FALSE;
    }

    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}

/* EOF */
