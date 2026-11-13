/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * PURPOSE:         Vista functions
 * PROGRAMMER:      Thomas Weidenmueller <w3seek@reactos.com>
 */

/* INCLUDES *******************************************************************/

#include <k32_vista.h>

#if _WIN32_WINNT != _WIN32_WINNT_VISTA
#error "This file must be compiled with _WIN32_WINNT == _WIN32_WINNT_VISTA"
#endif

// This is defined only in ntifs.h
#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

#define NDEBUG
#include <debug.h>

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
BOOL
WINAPI
QueryFullProcessImageNameW(
    _In_ HANDLE hProcess,
    _In_ DWORD dwFlags,
    _Out_writes_to_(*lpdwSize, *lpdwSize) LPWSTR lpExeName,
    _Inout_ PDWORD lpdwSize)
{
    BOOL bRet = FALSE;
    DWORD dwBufferSize;
    PUNICODE_STRING pBuffer;
    NTSTATUS Status;

    if (dwFlags & ~PROCESS_NAME_NATIVE)
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER_2);
        return FALSE;
    }

    dwBufferSize = sizeof(UNICODE_STRING) + *lpdwSize * sizeof(WCHAR);
    pBuffer = (PUNICODE_STRING)RtlAllocateHeap(RtlGetProcessHeap(), 0, dwBufferSize);
    if (!pBuffer)
    {
        BaseSetLastNTError(STATUS_NO_MEMORY);
        return FALSE;
    }

    Status = NtQueryInformationProcess(hProcess,
                                       (dwFlags & PROCESS_NAME_NATIVE) ? ProcessImageFileName : ProcessImageFileNameWin32,
                                       pBuffer,
                                       dwBufferSize,
                                       NULL);
    if (NT_SUCCESS(Status))
    {
        DWORD dwCch = pBuffer->Length / sizeof(WCHAR);
        if (dwCch >= *lpdwSize)
        {
            BaseSetLastNTError(STATUS_BUFFER_TOO_SMALL);
        }
        else
        {
            RtlCopyMemory(lpExeName, pBuffer->Buffer, pBuffer->Length);
            lpExeName[dwCch] = UNICODE_NULL;
            *lpdwSize = dwCch;
            bRet = TRUE;
        }
    }
    else
    {
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
            Status = STATUS_BUFFER_TOO_SMALL;
        BaseSetLastNTError(Status);
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, pBuffer);
    return bRet;
}


/*
 * @implemented
 */
BOOL
WINAPI
QueryFullProcessImageNameA(
    _In_ HANDLE hProcess,
    _In_ DWORD dwFlags,
    _Out_writes_to_(*lpdwSize, *lpdwSize) LPSTR lpExeName,
    _Inout_ PDWORD lpdwSize)
{
    BOOL bRet = FALSE;
    DWORD dwSize;
    PWSTR pszFullName;

    dwSize = *lpdwSize;
    pszFullName = (PWSTR)RtlAllocateHeap(RtlGetProcessHeap(), 0, dwSize * sizeof(WCHAR));
    if (!pszFullName)
    {
        BaseSetLastNTError(STATUS_NO_MEMORY);
        return FALSE;
    }

    if (QueryFullProcessImageNameW(hProcess, dwFlags, pszFullName, &dwSize))
    {
        INT iCch;
        iCch = WideCharToMultiByte(CP_ACP,
                                   WC_NO_BEST_FIT_CHARS,
                                   pszFullName,
                                   dwSize + 1,
                                   lpExeName,
                                   *lpdwSize,
                                   NULL,
                                   NULL);
        if (iCch)
        {
            *lpdwSize = iCch - 1;
            bRet = TRUE;
        }
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, pszFullName);
    return bRet;
}


#ifndef SE_CREATE_SYMBOLIC_LINK_PRIVILEGE
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE 35L
#endif

/*
 * @implemented
 */
BOOLEAN
WINAPI
CreateSymbolicLinkW(IN LPCWSTR lpSymlinkFileName,
                    IN LPCWSTR lpTargetFileName,
                    IN DWORD dwFlags)
{
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hSymlink = NULL;
    UNICODE_STRING SymlinkFileName = { 0, 0, NULL };
    UNICODE_STRING TargetFileName = { 0, 0, NULL };
    BOOLEAN bAllocatedTarget = FALSE, bRelativePath = FALSE;
    LPWSTR lpTargetFullFileName = NULL;
    SIZE_T cbPrintName;
    SIZE_T cbReparseData;
    PREPARSE_DATA_BUFFER pReparseData = NULL;
    PBYTE pBufTail;
    NTSTATUS Status;
    ULONG dwCreateOptions;
    DWORD dwErr;
    BOOLEAN bPrivilegeWasEnabled = TRUE, bPrivilegeAdjusted = FALSE, bPrivilegeOnThread = FALSE;

    /*
     * SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE (Windows 10 1703+) is accepted. Windows without developer mode
     * still demands SeCreateSymbolicLinkPrivilege (ERROR_PRIVILEGE_NOT_HELD) even with this flag. ReactOS has no
     * developer mode: the file systems (NTFS-NG, Btrfs) require the privilege for every caller, so the flag has
     * no effect here, as on a Windows system with developer mode off.
     * Like Windows 10 (verified on 22H2), bits other than DIRECTORY and ALLOW_UNPRIVILEGED_CREATE are ignored.
     */
    if(!lpSymlinkFileName || !lpTargetFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if(dwFlags & SYMBOLIC_LINK_FLAG_DIRECTORY)
        dwCreateOptions = FILE_DIRECTORY_FILE;
    else
        dwCreateOptions = FILE_NON_DIRECTORY_FILE;

    switch(RtlDetermineDosPathNameType_U(lpTargetFileName))
    {
    case RtlPathTypeUnknown:
    case RtlPathTypeRooted:
    case RtlPathTypeRelative:
        bRelativePath = TRUE;
        RtlInitUnicodeString(&TargetFileName, lpTargetFileName);
        break;

    case RtlPathTypeDriveRelative:
        {
            LPWSTR FilePart;
            SIZE_T cchTargetFullFileName;

            cchTargetFullFileName = GetFullPathNameW(lpTargetFileName, 0, NULL, &FilePart);

            if(cchTargetFullFileName == 0)
            {
                dwErr = GetLastError();
                goto Cleanup;
            }

            lpTargetFullFileName = RtlAllocateHeap(RtlGetProcessHeap(), 0, cchTargetFullFileName * sizeof(WCHAR));

            if(lpTargetFullFileName == NULL)
            {
                dwErr = ERROR_NOT_ENOUGH_MEMORY;
                goto Cleanup;
            }

            if(GetFullPathNameW(lpTargetFileName, cchTargetFullFileName, lpTargetFullFileName, &FilePart) == 0)
            {
                dwErr = GetLastError();
                goto Cleanup;
            }
        }

        lpTargetFileName = lpTargetFullFileName;

        // fallthrough

    case RtlPathTypeUncAbsolute:
    case RtlPathTypeDriveAbsolute:
    case RtlPathTypeLocalDevice:
    case RtlPathTypeRootLocalDevice:
    default:
        if(!RtlDosPathNameToNtPathName_U(lpTargetFileName, &TargetFileName, NULL, NULL))
        {
            dwErr = ERROR_INVALID_PARAMETER;
            goto Cleanup;
        }
        bAllocatedTarget = TRUE;
    }

    cbPrintName = wcslen(lpTargetFileName) * sizeof(WCHAR);
    cbReparseData = FIELD_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer) + TargetFileName.Length + cbPrintName;
    if (cbReparseData > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
    {
        dwErr = ERROR_FILENAME_EXCED_RANGE;
        goto Cleanup;
    }
    pReparseData = RtlAllocateHeap(RtlGetProcessHeap(), 0, cbReparseData);

    if(pReparseData == NULL)
    {
        dwErr = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    pBufTail = (PBYTE)(pReparseData->SymbolicLinkReparseBuffer.PathBuffer);

    pReparseData->ReparseTag = (ULONG)IO_REPARSE_TAG_SYMLINK;
    pReparseData->ReparseDataLength = (USHORT)cbReparseData - REPARSE_DATA_BUFFER_HEADER_SIZE;
    pReparseData->Reserved = 0;

    pReparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
    pReparseData->SymbolicLinkReparseBuffer.SubstituteNameLength = TargetFileName.Length;
    pBufTail += pReparseData->SymbolicLinkReparseBuffer.SubstituteNameOffset;
    RtlCopyMemory(pBufTail, TargetFileName.Buffer, TargetFileName.Length);

    pReparseData->SymbolicLinkReparseBuffer.PrintNameOffset = pReparseData->SymbolicLinkReparseBuffer.SubstituteNameLength;
    pReparseData->SymbolicLinkReparseBuffer.PrintNameLength = (USHORT)cbPrintName;
    pBufTail += pReparseData->SymbolicLinkReparseBuffer.PrintNameOffset;
    RtlCopyMemory(pBufTail, lpTargetFileName, cbPrintName);

    pReparseData->SymbolicLinkReparseBuffer.Flags = 0;

    if(bRelativePath)
        pReparseData->SymbolicLinkReparseBuffer.Flags |= 1; // TODO! give this lone flag a name

    if(!RtlDosPathNameToNtPathName_U(lpSymlinkFileName, &SymlinkFileName, NULL, NULL))
    {
        dwErr = ERROR_PATH_NOT_FOUND;
        goto Cleanup;
    }

    InitializeObjectAttributes(&ObjectAttributes, &SymlinkFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtCreateFile
    (
        &hSymlink,
        FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | dwCreateOptions,
        NULL,
        0
    );

    if(!NT_SUCCESS(Status))
    {
        dwErr = RtlNtStatusToDosError(Status);
        goto Cleanup;
    }

    /*
     * The privilege is held by the account (administrators) but disabled until a program turns it on, so it is
     * enabled around the request, for the thread if it impersonates and for the process otherwise. Without
     * the privilege the adjustment fails and the file system refuses the request.
     */
    Status = RtlAdjustPrivilege(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, TRUE, TRUE, &bPrivilegeWasEnabled);
    if (NT_SUCCESS(Status))
    {
        bPrivilegeAdjusted = bPrivilegeOnThread = TRUE;
    }
    else if (Status == STATUS_NO_TOKEN)
    {
        Status = RtlAdjustPrivilege(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, TRUE, FALSE, &bPrivilegeWasEnabled);
        if (NT_SUCCESS(Status))
            bPrivilegeAdjusted = TRUE;
    }

    Status = NtFsControlFile
    (
        hSymlink,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        FSCTL_SET_REPARSE_POINT,
        pReparseData,
        cbReparseData,
        NULL,
        0
    );

    if (bPrivilegeAdjusted && !bPrivilegeWasEnabled)
    {
        BOOLEAN bIgnored;
        RtlAdjustPrivilege(SE_CREATE_SYMBOLIC_LINK_PRIVILEGE, FALSE, bPrivilegeOnThread, &bIgnored);
    }

    if(!NT_SUCCESS(Status))
    {
        FILE_DISPOSITION_INFORMATION DispInfo;
        DispInfo.DeleteFile = TRUE;
        NtSetInformationFile(hSymlink, &IoStatusBlock, &DispInfo, sizeof(DispInfo), FileDispositionInformation);

        dwErr = RtlNtStatusToDosError(Status);
        goto Cleanup;
    }

    dwErr = NO_ERROR;

Cleanup:
    if(hSymlink)
        NtClose(hSymlink);

    RtlFreeUnicodeString(&SymlinkFileName);
    if (bAllocatedTarget)
    {
        RtlFreeHeap(RtlGetProcessHeap(),
                    0,
                    TargetFileName.Buffer);
    }

    if(lpTargetFullFileName)
        RtlFreeHeap(RtlGetProcessHeap(), 0, lpTargetFullFileName);

    if(pReparseData)
        RtlFreeHeap(RtlGetProcessHeap(), 0, pReparseData);

    if(dwErr)
    {
        SetLastError(dwErr);
        return FALSE;
    }

    return TRUE;
}


/*
 * @implemented
 */
BOOLEAN
NTAPI
CreateSymbolicLinkA(IN LPCSTR lpSymlinkFileName,
                    IN LPCSTR lpTargetFileName,
                    IN DWORD dwFlags)
{
    PWCHAR SymlinkW, TargetW;
    BOOLEAN Ret;

    if(!lpSymlinkFileName || !lpTargetFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Both names are allocated: the TEB static buffer (alloc == FALSE) must not be freed below */
    if (!(SymlinkW = FilenameA2W(lpSymlinkFileName, TRUE)))
        return FALSE;

    if (!(TargetW = FilenameA2W(lpTargetFileName, TRUE)))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, SymlinkW);
        return FALSE;
    }

    Ret = CreateSymbolicLinkW(SymlinkW,
                              TargetW,
                              dwFlags);

    RtlFreeHeap(RtlGetProcessHeap(), 0, SymlinkW);
    RtlFreeHeap(RtlGetProcessHeap(), 0, TargetW);

    return Ret;
}


/*
 * @implemented
 */
DWORD
WINAPI
GetFinalPathNameByHandleA(IN HANDLE hFile,
                          OUT LPSTR lpszFilePath,
                          IN DWORD cchFilePath,
                          IN DWORD dwFlags)
{
    WCHAR FilePathW[MAX_PATH];
    UNICODE_STRING FilePathU;
    DWORD PrevLastError;
    DWORD Ret = 0;

    if (cchFilePath != 0 &&
        cchFilePath > sizeof(FilePathW) / sizeof(FilePathW[0]))
    {
        FilePathU.Length = 0;
        FilePathU.MaximumLength = (USHORT)cchFilePath * sizeof(WCHAR);
        FilePathU.Buffer = RtlAllocateHeap(RtlGetProcessHeap(),
                                           0,
                                           FilePathU.MaximumLength);
        if (FilePathU.Buffer == NULL)
        {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return 0;
        }
    }
    else
    {
        FilePathU.Length = 0;
        FilePathU.MaximumLength = sizeof(FilePathW);
        FilePathU.Buffer = FilePathW;
    }

    /* save the last error code */
    PrevLastError = GetLastError();
    SetLastError(ERROR_SUCCESS);

    /* call the unicode version that does all the work */
    Ret = GetFinalPathNameByHandleW(hFile,
                                    FilePathU.Buffer,
                                    cchFilePath,
                                    dwFlags);

    if (GetLastError() == ERROR_SUCCESS)
    {
        /* no error, restore the last error code and convert the string */
        SetLastError(PrevLastError);

        Ret = FilenameU2A_FitOrFail(lpszFilePath,
                                    cchFilePath,
                                    &FilePathU);
    }

    /* free allocated memory if necessary */
    if (FilePathU.Buffer != FilePathW)
    {
        RtlFreeHeap(RtlGetProcessHeap(),
                    0,
                    FilePathU.Buffer);
    }

    return Ret;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
SetFileBandwidthReservation(IN HANDLE hFile,
                            IN DWORD nPeriodMilliseconds,
                            IN DWORD nBytesPerPeriod,
                            IN BOOL bDiscardable,
                            OUT LPDWORD lpTransferSize,
                            OUT LPDWORD lpNumOutstandingRequests)
{
    UNIMPLEMENTED;
    return FALSE;
}


/*
 * @unimplemented
 */
BOOL
WINAPI
GetFileBandwidthReservation(IN HANDLE hFile,
                            OUT LPDWORD lpPeriodMilliseconds,
                            OUT LPDWORD lpBytesPerPeriod,
                            OUT LPBOOL pDiscardable,
                            OUT LPDWORD lpTransferSize,
                            OUT LPDWORD lpNumOutstandingRequests)
{
    UNIMPLEMENTED;
    return FALSE;
}


/*
 * @unimplemented
 */
HANDLE
WINAPI
OpenFileById(IN HANDLE hFile,
             IN LPFILE_ID_DESCRIPTOR lpFileID,
             IN DWORD dwDesiredAccess,
             IN DWORD dwShareMode,
             IN LPSECURITY_ATTRIBUTES lpSecurityAttributes  OPTIONAL,
             IN DWORD dwFlags)
{
    UNIMPLEMENTED;
    return INVALID_HANDLE_VALUE;
}



/*
  Vista+ MUI support functions

  References:
   Evolution of MUI Support across Windows Versions: https://learn.microsoft.com/en-us/windows/win32/intl/evolution-of-mui-support-across-windows-versions
   Comparing Windows XP Professional Multilingual Options: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-xp/bb457045(v=technet.10)?redirectedfrom=MSDN

  More info:
   https://web.archive.org/web/20170930153551/http://msdn.microsoft.com/en-us/goglobal/bb978454.aspx
   https://learn.microsoft.com/en-us/windows/win32/intl/multilingual-user-interface-functions
*/

/* FUNCTIONS *****************************************************************/

#define MUI_SIGNATURE 0xfecdfecd
struct mui_resource
{
    DWORD signature;
    DWORD size;
    DWORD version;
    DWORD path_type;
    DWORD file_type;
    DWORD system_attributes;
    DWORD fallback_location;
    BYTE service_checksum[16];
    BYTE checksum[16];
    DWORD unk1[2];
    DWORD mui_path_off;
    DWORD mui_path_size;
    DWORD unk2[2];
    DWORD ln_type_name_off;
    DWORD ln_type_name_size;
    DWORD ln_type_id_off;
    DWORD ln_type_id_size;
    DWORD mui_type_name_off;
    DWORD mui_type_name_size;
    DWORD mui_type_id_off;
    DWORD mui_type_id_size;
    DWORD lang_off;
    DWORD lang_size;
    DWORD fallback_lang_off;
    DWORD fallback_lang_size;
};


static BOOL validate_mui_resource(struct mui_resource *mui, DWORD size)
{
    if (size >= sizeof(DWORD) && mui->signature != MUI_SIGNATURE)
    {
        SetLastError(ERROR_MUI_INVALID_RC_CONFIG);
        return FALSE;
    }

    if (size < FIELD_OFFSET(struct mui_resource, version))
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    size = min( size, mui->size );
    if (size < sizeof(*mui) ||
        mui->ln_type_name_off >= size || mui->ln_type_name_size > size - mui->ln_type_name_off ||
        mui->ln_type_id_off >= size || mui->ln_type_id_size > size - mui->ln_type_id_off ||
        mui->mui_type_name_off >= size || mui->mui_type_name_size > size - mui->mui_type_name_off ||
        mui->mui_type_id_off >= size || mui->mui_type_id_size > size - mui->mui_type_id_off ||
        mui->lang_off >= size || mui->lang_size > size - mui->lang_off ||
        mui->fallback_lang_off >= size || mui->fallback_lang_size > size - mui->fallback_lang_off)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }
    return TRUE;
}


/* Ported from Wine 11.19 (dlls/kernelbase/locale.c) */
BOOL
WINAPI
GetFileMUIInfo(
    DWORD flags,
    PCWSTR path,
    PFILEMUIINFO info,
    DWORD *size)
{
    DWORD off, mui_size, type = MUI_FILETYPE_NOT_LANGUAGE_NEUTRAL;
    ULONGLONG need;
    struct mui_resource *mui = NULL;
    HMODULE hmod;
    HRSRC hrsrc;

    if (!path || !size || (*size && !info) ||
            (info && (*size < sizeof(*info) || info->dwSize != *size ||
                      info->dwVersion != MUI_FILEINFO_VERSION)))
    {
        if (size) *size = 0;
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    if (!flags) flags = MUI_QUERY_TYPE | MUI_QUERY_CHECKSUM;

    hmod = LoadLibraryExW( path, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE );
    if (!hmod) return FALSE;

    hrsrc = FindResourceW( hmod, (LPCWSTR)(ULONG_PTR)1, L"MUI" );
    if (hrsrc)
    {
        mui = LockResource( LoadResource(hmod, hrsrc) );
        if (mui) mui_size = SizeofResource( hmod, hrsrc );
        if (!mui || !validate_mui_resource( mui, mui_size ))
        {
            FreeLibrary( hmod );
            return FALSE;
        }
        if (mui->file_type & (MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN >> 1))
            type = MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN;
        else if (mui->file_type & (MUI_FILETYPE_LANGUAGE_NEUTRAL_MUI >> 1))
            type = MUI_FILETYPE_LANGUAGE_NEUTRAL_MUI;
    }
    if (type == MUI_FILETYPE_NOT_LANGUAGE_NEUTRAL)
    {
        FreeLibrary( hmod );

        if (!info)
        {
            *size = sizeof(*info);
            return TRUE;
        }
        if (info->dwSize < sizeof(*info))
        {
            SetLastError( ERROR_INSUFFICIENT_BUFFER );
            return FALSE;
        }

        memset( info, 0, sizeof(*info) );
        info->dwSize = *size;
        info->dwVersion = MUI_FILEINFO_VERSION;
        if (flags & MUI_QUERY_TYPE) info->dwFileType = type;
        return TRUE;
    }

    need = offsetof(FILEMUIINFO, abBuffer);
    if (flags & MUI_QUERY_LANGUAGE_NAME)
    {
        need += type == MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN ?
            mui->fallback_lang_size : mui->lang_size;
    }
    if (flags & MUI_QUERY_RESOURCE_TYPES)
    {
        /* the language-specific file reports the types it carries in the ln_type fields */
        need += mui->ln_type_name_size;
        need += mui->ln_type_id_size;
        if (type == MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN)
        {
            need += mui->mui_type_name_size;
            need += mui->mui_type_id_size;
        }
    }
    if (need > MAXDWORD)
    {
        FreeLibrary( hmod );
        SetLastError( ERROR_BAD_EXE_FORMAT );
        return FALSE;
    }
    off = need;
    if (off < sizeof(*info)) off = sizeof(*info);

    if (!info || info->dwSize < off)
    {
        FreeLibrary( hmod );
        *size = off;
        SetLastError( ERROR_INSUFFICIENT_BUFFER );
        return FALSE;
    }

    off = 0;
    memset( info, 0, sizeof(*info) );
    info->dwSize = *size;
    info->dwVersion = MUI_FILEINFO_VERSION;
    if (flags & MUI_QUERY_TYPE) info->dwFileType = type;
    if (flags & MUI_QUERY_CHECKSUM)
    {
        memcpy( info->pChecksum, mui->checksum, sizeof(info->pChecksum) );
        memcpy( info->pServiceChecksum, mui->service_checksum, sizeof(info->pServiceChecksum) );
    }
    if (flags & MUI_QUERY_LANGUAGE_NAME)
    {
        if (type == MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN && mui->fallback_lang_off)
        {
            info->dwLanguageNameOffset = offsetof(FILEMUIINFO, abBuffer);
            memcpy(info->abBuffer, ((BYTE *)mui) + mui->fallback_lang_off,
                    mui->fallback_lang_size);
            off += mui->fallback_lang_size;
        }
        if (type == MUI_FILETYPE_LANGUAGE_NEUTRAL_MUI && mui->lang_off)
        {
            info->dwLanguageNameOffset = offsetof(FILEMUIINFO, abBuffer);
            memcpy(info->abBuffer, ((BYTE *)mui) + mui->lang_off, mui->lang_size);
            off += mui->lang_size;
        }
    }
    if (flags & MUI_QUERY_RESOURCE_TYPES && type & MUI_FILETYPE_LANGUAGE_NEUTRAL_MAIN)
    {
        if (mui->ln_type_id_size && mui->ln_type_id_off)
        {
            info->dwTypeIDMainSize = mui->ln_type_id_size / sizeof(DWORD);
            info->dwTypeIDMainOffset = offsetof(FILEMUIINFO, abBuffer[off]);
            memcpy(info->abBuffer + off, ((BYTE *)mui) + mui->ln_type_id_off, mui->ln_type_id_size);
            off += mui->ln_type_id_size;
        }
        if (mui->ln_type_name_off)
        {
            info->dwTypeNameMainOffset = offsetof(FILEMUIINFO, abBuffer[off]);
            memcpy(info->abBuffer + off, ((BYTE *)mui) + mui->ln_type_name_off, mui->ln_type_name_size);
            off += mui->ln_type_name_size;
        }
        if (mui->mui_type_id_size && mui->mui_type_id_off)
        {
            info->dwTypeIDMUISize = mui->mui_type_id_size / sizeof(DWORD);
            info->dwTypeIDMUIOffset = offsetof(FILEMUIINFO, abBuffer[off]);
            memcpy(info->abBuffer + off, ((BYTE *)mui) + mui->mui_type_id_off, mui->mui_type_id_size);
            off += mui->mui_type_id_size;
        }
        if (mui->mui_type_name_off)
        {
            info->dwTypeNameMUIOffset = offsetof(FILEMUIINFO, abBuffer[off]);
            memcpy(info->abBuffer + off, ((BYTE *)mui) + mui->mui_type_name_off, mui->mui_type_name_size);
            off += mui->mui_type_name_size;
        }
    }
    else if(flags & MUI_QUERY_RESOURCE_TYPES)
    {
        if (mui->ln_type_id_size && mui->ln_type_id_off)
        {
            info->dwTypeIDMUISize = mui->ln_type_id_size / sizeof(DWORD);
            info->dwTypeIDMUIOffset = offsetof(FILEMUIINFO, abBuffer[off]);
            memcpy(info->abBuffer + off, ((BYTE *)mui) + mui->ln_type_id_off, mui->ln_type_id_size);
            off += mui->ln_type_id_size;
        }
        if (mui->ln_type_name_off)
        {
            info->dwTypeNameMUIOffset = offsetof(FILEMUIINFO, abBuffer[off]);
            memcpy(info->abBuffer + off, ((BYTE *)mui) + mui->ln_type_name_off, mui->ln_type_name_size);
            off += mui->ln_type_name_size;
        }
    }

    FreeLibrary( hmod );
    return TRUE;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GetFileMUIPath(
    DWORD dwFlags,
    PCWSTR pcwszFilePath,
    PWSTR pwszLanguage,
    PULONG pcchLanguage,
    PWSTR pwszFileMUIPath,
    PULONG pcchFileMUIPath,
    PULONGLONG pululEnumerator)
{
    DPRINT1("%x %p %p %p %p %p\n", dwFlags, pcwszFilePath, pwszLanguage, pwszFileMUIPath, pcchFileMUIPath, pululEnumerator);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/*
 * @unimplemented
 */
#if 0 // This is Windows 7+
BOOL
WINAPI
GetProcessPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    DPRINT1("%x %p %p %p\n", dwFlags, pulNumLanguages, pwszLanguagesBuffer, pcchLanguagesBuffer);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
#endif

/* five languages of the process with their parents (up to three entries each), then the user and the system language with theirs */
#define MAX_UI_LANGUAGES 32

/* Distinct UI languages in order of preference: the identifier (0 for a parent
 * without one) and the locale name (empty for a language without a name) */
typedef struct _UI_LANGUAGE_LIST
{
    ULONG Count;
    LANGID Ids[MAX_UI_LANGUAGES];
    BOOLEAN IsParent[MAX_UI_LANGUAGES];
    WCHAR Names[MAX_UI_LANGUAGES][LOCALE_NAME_MAX_LENGTH];
} UI_LANGUAGE_LIST, *PUI_LANGUAGE_LIST;

static
VOID
AddUILanguageEntry(
    _Inout_ PUI_LANGUAGE_LIST List,
    _In_ LANGID Id,
    _In_ PCWSTR Name,
    _In_ BOOLEAN IsParent)
{
    ULONG i;

    if (List->Count >= MAX_UI_LANGUAGES)
        return;

    for (i = 0; i < List->Count; i++)
    {
        if ((Id && List->Ids[i] == Id) ||
            (Name[0] && _wcsicmp(List->Names[i], Name) == 0))
        {
            return;
        }
    }

    List->Ids[List->Count] = Id;
    List->IsParent[List->Count] = IsParent;
    lstrcpynW(List->Names[List->Count], Name, LOCALE_NAME_MAX_LENGTH);
    List->Count++;
}

/* Adds a language and, if asked, its chain of parent languages: the parent its
 * locale data names, then each name without its last part (zh-TW, zh-Hant, zh) */
static
VOID
AddUILanguage(
    _Inout_ PUI_LANGUAGE_LIST List,
    _In_ LANGID Language,
    _In_ BOOLEAN WithParents)
{
    WCHAR Name[LOCALE_NAME_MAX_LENGTH], Parent[LOCALE_NAME_MAX_LENGTH];
    LCID Lcid = MAKELCID(Language, SORT_DEFAULT);
    PWSTR Dash;
    ULONG Depth;

    if (Language == 0)
        return;

    /* Locales missing from the RTL table still have a name in their NLS data */
    if (LCIDToLocaleName(Lcid, Name, _countof(Name), LOCALE_ALLOW_NEUTRAL_NAMES) <= 1 &&
        GetLocaleInfoW(Lcid, LOCALE_SNAME, Name, _countof(Name)) <= 1)
    {
        Name[0] = UNICODE_NULL;
    }

    AddUILanguageEntry(List, Language, Name, FALSE);
    if (!WithParents || !Name[0])
        return;

    if (GetLocaleInfoW(Lcid, LOCALE_SPARENT, Parent, _countof(Parent)) <= 1 ||
        _wcsicmp(Parent, Name) == 0)
    {
        lstrcpynW(Parent, Name, _countof(Parent));
        Dash = wcsrchr(Parent, L'-');
        if (!Dash)
            return;
        *Dash = UNICODE_NULL;
    }

    for (Depth = 0; Depth < 3 && Parent[0]; Depth++)
    {
        LCID ParentLcid = LocaleNameToLCID(Parent, LOCALE_ALLOW_NEUTRAL_NAMES);

        AddUILanguageEntry(List, ParentLcid ? LANGIDFROMLCID(ParentLcid) : 0, Parent, TRUE);

        Dash = wcsrchr(Parent, L'-');
        if (!Dash)
            break;
        *Dash = UNICODE_NULL;
    }
}

/* The languages of the process come first in the list of a thread */
static
VOID
AddProcessUILanguages(
    _Inout_ PUI_LANGUAGE_LIST List,
    _In_ BOOLEAN WithParents)
{
    LANGID Ids[MAX_PROCESS_UI_LANGUAGES];
    ULONG Count, i;

    Count = BasepGetProcessUILanguageIds(Ids);
    for (i = 0; i < Count; i++)
        AddUILanguage(List, Ids[i], WithParents);
}

/* Writes a language list as a double null-terminated multi-string of
 * hexadecimal language identifiers or of locale names */
static
BOOL
FormatUILanguages(
    _In_ PUI_LANGUAGE_LIST List,
    _In_ DWORD dwFlags,
    _Out_ PULONG pulNumLanguages,
    _Out_writes_opt_(*pcchLanguagesBuffer) PZZWSTR pwszLanguagesBuffer,
    _Inout_ PULONG pcchLanguagesBuffer)
{
    WCHAR Ids[MAX_UI_LANGUAGES][5];
    PCWSTR Strings[MAX_UI_LANGUAGES];
    ULONG Lengths[MAX_UI_LANGUAGES];
    ULONG i, Written = 0, Needed = 1;
    PWSTR Out;

    if (!pulNumLanguages || !pcchLanguagesBuffer ||
        (*pcchLanguagesBuffer && !pwszLanguagesBuffer))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (i = 0; i < List->Count; i++)
    {
        if (dwFlags & MUI_LANGUAGE_ID)
        {
            static const WCHAR Hex[] = L"0123456789ABCDEF";
            LANGID Id = List->Ids[i];

            /* A parent without an identifier is only an extra fallback */
            if (!Id)
                continue;

            Ids[Written][0] = Hex[(Id >> 12) & 0xF];
            Ids[Written][1] = Hex[(Id >> 8) & 0xF];
            Ids[Written][2] = Hex[(Id >> 4) & 0xF];
            Ids[Written][3] = Hex[Id & 0xF];
            Ids[Written][4] = UNICODE_NULL;
            Strings[Written] = Ids[Written];
            Lengths[Written] = 4;
        }
        else
        {
            if (!List->Names[i][0])
            {
                if (List->IsParent[i])
                    continue;
                SetLastError(ERROR_INVALID_PARAMETER);
                return FALSE;
            }
            Strings[Written] = List->Names[i];
            Lengths[Written] = (ULONG)wcslen(List->Names[i]);
        }
        Needed += Lengths[Written] + 1;
        Written++;
    }

    /* An empty list is still a terminated multi-string */
    if (Written == 0)
        Needed = 2;

    if (pwszLanguagesBuffer)
    {
        if (*pcchLanguagesBuffer < Needed)
        {
            *pcchLanguagesBuffer = Needed;
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }

        Out = pwszLanguagesBuffer;
        for (i = 0; i < Written; i++)
        {
            RtlCopyMemory(Out, Strings[i], (Lengths[i] + 1) * sizeof(WCHAR));
            Out += Lengths[i] + 1;
        }
        *Out = UNICODE_NULL;
        if (Written == 0)
            Out[1] = UNICODE_NULL;
    }

    *pulNumLanguages = Written;
    *pcchLanguagesBuffer = Needed;
    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetSystemPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    UI_LANGUAGE_LIST List;

    List.Count = 0;
    if ((dwFlags & ~(MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME | MUI_MACHINE_LANGUAGE_SETTINGS)) ||
        ((dwFlags & MUI_LANGUAGE_ID) && (dwFlags & MUI_LANGUAGE_NAME)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    AddUILanguage(&List, GetSystemDefaultUILanguage(), FALSE);
    return FormatUILanguages(&List, dwFlags, pulNumLanguages,
                             pwszLanguagesBuffer, pcchLanguagesBuffer);
}

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    UI_LANGUAGE_LIST List;

    List.Count = 0;
    if ((dwFlags & ~(MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME | MUI_MERGE_SYSTEM_FALLBACK |
                     MUI_MERGE_USER_FALLBACK | MUI_THREAD_LANGUAGES |
                     MUI_CONSOLE_FILTER | MUI_COMPLEX_SCRIPT_FILTER)) ||
        ((dwFlags & MUI_LANGUAGE_ID) && (dwFlags & MUI_LANGUAGE_NAME)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* No thread preferred languages can be set yet, so the list is the languages of the process
     * (SetProcessPreferredUILanguages), then the user language followed by the system language as
     * fallbacks, the fallbacks with their parent languages. The languages of the process have theirs
     * when the fallbacks of the system are merged (measured on Windows Server 2008 R2). */
    switch (dwFlags & (MUI_MERGE_SYSTEM_FALLBACK | MUI_MERGE_USER_FALLBACK | MUI_THREAD_LANGUAGES))
    {
        case 0:
        case MUI_MERGE_USER_FALLBACK:
            AddProcessUILanguages(&List, FALSE);
            AddUILanguage(&List, GetUserDefaultUILanguage(), FALSE);
            AddUILanguage(&List, GetSystemDefaultUILanguage(), TRUE);
            break;

        case MUI_MERGE_SYSTEM_FALLBACK | MUI_MERGE_USER_FALLBACK:
            AddProcessUILanguages(&List, TRUE);
            AddUILanguage(&List, GetUserDefaultUILanguage(), TRUE);
            AddUILanguage(&List, GetSystemDefaultUILanguage(), TRUE);
            break;

        case MUI_MERGE_SYSTEM_FALLBACK:
            AddProcessUILanguages(&List, TRUE);
            AddUILanguage(&List, GetSystemDefaultUILanguage(), TRUE);
            break;

        case MUI_THREAD_LANGUAGES:
            break;

        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
    }

    return FormatUILanguages(&List, dwFlags, pulNumLanguages,
                             pwszLanguagesBuffer, pcchLanguagesBuffer);
}

/*
 * @implemented
 *
 * The first language of the thread (SetThreadPreferredUILanguages, SetThreadUILanguage), else the first of
 * the process (SetProcessPreferredUILanguages), else the user's UI language: measured on Windows 10 22H2,
 * where the default of a thread is the user's UI language and neither the thread locale nor a new thread
 * of a process whose thread language was set changes it. The thread languages cannot be set yet.
 */
LANGID
WINAPI
GetThreadUILanguage(VOID)
{
    LANGID Ids[MAX_PROCESS_UI_LANGUAGES];

    if (BasepGetProcessUILanguageIds(Ids) != 0)
        return Ids[0];

    return GetUserDefaultUILanguage();
}

/*
 * @unimplemented
 */
BOOL
WINAPI
GetUILanguageInfo(
    DWORD dwFlags,
    PCZZWSTR pwmszLanguage,
    PZZWSTR pwszFallbackLanguages,
    PDWORD pcchFallbackLanguages,
    PDWORD pdwAttributes)
{
    DPRINT1("%x %p %p %p %p\n", dwFlags, pwmszLanguage, pwszFallbackLanguages, pcchFallbackLanguages, pdwAttributes);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}


/*
 * @implemented
 */
BOOL
WINAPI
GetUserPreferredUILanguages(
    DWORD dwFlags,
    PULONG pulNumLanguages,
    PZZWSTR pwszLanguagesBuffer,
    PULONG pcchLanguagesBuffer)
{
    UI_LANGUAGE_LIST List;

    List.Count = 0;
    if ((dwFlags & ~(MUI_LANGUAGE_ID | MUI_LANGUAGE_NAME)) ||
        ((dwFlags & MUI_LANGUAGE_ID) && (dwFlags & MUI_LANGUAGE_NAME)))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    AddUILanguage(&List, GetUserDefaultUILanguage(), FALSE);
    return FormatUILanguages(&List, dwFlags, pulNumLanguages,
                             pwszLanguagesBuffer, pcchLanguagesBuffer);
}

/*
 * @unimplemented
 */
#if 0 // Tis is Windows 7+
BOOL
WINAPI
SetProcessPreferredUILanguages(
    DWORD dwFlags,
    PCZZWSTR pwszLanguagesBuffer,
    PULONG pulNumLanguages)
{
    DPRINT1("%x %p %p\n", dwFlags, pwszLanguagesBuffer, pulNumLanguages);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}
#endif

/*
 * @unimplemented
 */
BOOL
WINAPI
SetThreadPreferredUILanguages(
    DWORD dwFlags,
    PCZZWSTR pwszLanguagesBuffer,
    PULONG pulNumLanguages
    )
{
    DPRINT1("%x %p %p\n", dwFlags, pwszLanguagesBuffer, pulNumLanguages);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/******************************************************************************
 *           CompareStringOrdinal    (KERNEL32.@)
 */
INT WINAPI CompareStringOrdinal(const WCHAR *str1, INT len1, const WCHAR *str2, INT len2, BOOL ignore_case)
{
    int ret;

    if (!str1 || !str2)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (len1 < 0) len1 = strlenW(str1);
    if (len2 < 0) len2 = strlenW(str2);
    ret = RtlCompareUnicodeStrings( str1, len1, str2, len2, ignore_case );
    if (ret < 0) return CSTR_LESS_THAN;
    if (ret > 0) return CSTR_GREATER_THAN;
    return CSTR_EQUAL;
}

/******************************************************************************
 *           FindStringOrdinal    (KERNEL32.@)
 *
 * After Wine's kernelbase (dlls/kernelbase/locale.c), Copyright 2001 Alexandre Julliard and others, LGPL-2.1+,
 * with the argument checks that Windows has (measured on Windows Server 2008 R2).
 */
INT
WINAPI
FindStringOrdinal(
    _In_ DWORD dwFindStringOrdinal,
    _In_ LPCWSTR lpStringSource,
    _In_ INT cchSource,
    _In_ LPCWSTR lpStringValue,
    _In_ INT cchValue,
    _In_ BOOL bIgnoreCase)
{
    INT offset, inc, count;

    /* Windows refuses lengths below -1 and a case flag that is neither 0 nor 1, which Wine does not (measured) */
    if (!lpStringSource || !lpStringValue || cchSource < -1 || cchValue < -1 || (UINT)bIgnoreCase > 1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    /* A flag of 0 searches from the start, like FIND_FROMSTART (measured) */
    if (dwFindStringOrdinal == 0)
        dwFindStringOrdinal = FIND_FROMSTART;

    if (dwFindStringOrdinal != FIND_FROMSTART && dwFindStringOrdinal != FIND_FROMEND &&
        dwFindStringOrdinal != FIND_STARTSWITH && dwFindStringOrdinal != FIND_ENDSWITH)
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return -1;
    }

    if (cchSource == -1) cchSource = lstrlenW(lpStringSource);
    if (cchValue == -1) cchValue = lstrlenW(lpStringValue);

    SetLastError(ERROR_SUCCESS);
    cchSource -= cchValue;
    if (cchSource < 0) return -1;

    count = dwFindStringOrdinal & (FIND_FROMSTART | FIND_FROMEND) ? cchSource + 1 : 1;
    offset = dwFindStringOrdinal & (FIND_FROMSTART | FIND_STARTSWITH) ? 0 : cchSource;
    inc = dwFindStringOrdinal & (FIND_FROMSTART | FIND_STARTSWITH) ? 1 : -1;
    while (count--)
    {
        if (CompareStringOrdinal(lpStringSource + offset, cchValue, lpStringValue, cchValue, bIgnoreCase) == CSTR_EQUAL)
            return offset;
        offset += inc;
    }
    return -1;
}

#if (DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA) /* CompareStringEx is exported by kernel32 from 0x600 on only */
/******************************************************************************
 *           FindNLSStringEx    (KERNEL32.@)
 *
 * After Wine's kernel32 (dlls/kernel32/locale.c, Wine 4.x), Copyright 2001 Alexandre Julliard and others, LGPL-2.1+.
 * A window the length of the value slides over the source and CompareStringEx decides each position, so a match
 * is always as long as the value: the source is not normalized, and a linguistic match of a different length
 * (ignorable characters, expansions) is not found.
 */
INT
WINAPI
FindNLSStringEx(
    _In_opt_ LPCWSTR lpLocaleName,
    _In_ DWORD dwFindNLSStringFlags,
    _In_ LPCWSTR lpStringSource,
    _In_ INT cchSource,
    _In_ LPCWSTR lpStringValue,
    _In_ INT cchValue,
    _Out_opt_ LPINT pcchFound,
    _In_opt_ LPNLSVERSIONINFO lpVersionInformation,
    _In_opt_ LPVOID lpReserved,
    _In_opt_ LPARAM sortHandle)
{
    const DWORD FindFlags = FIND_FROMSTART | FIND_FROMEND | FIND_STARTSWITH | FIND_ENDSWITH;
    DWORD CompareFlags, Direction;
    INT offset, inc, count, ret;

    /* The version information, the reserved pointer and the sort handle are ignored (Windows takes them without an error) */
    UNREFERENCED_PARAMETER(lpVersionInformation);
    UNREFERENCED_PARAMETER(lpReserved);
    UNREFERENCED_PARAMETER(sortHandle);
    if (!lpStringSource || cchSource < -1 || !lpStringValue || cchValue < -1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    /* One direction at most, and none means from the start (measured on Windows 10 22H2) */
    Direction = dwFindNLSStringFlags & FindFlags;
    if (Direction & (Direction - 1))
    {
        SetLastError(ERROR_INVALID_FLAGS);
        return -1;
    }
    if (!Direction) dwFindNLSStringFlags |= FIND_FROMSTART;

    if (cchSource == -1) cchSource = lstrlenW(lpStringSource);
    if (cchValue == -1) cchValue = lstrlenW(lpStringValue);

    CompareFlags = dwFindNLSStringFlags & ~FindFlags;

    /*
     * Zero lengths are no error (measured on Windows 10 22H2), once the flags have passed. An empty value matches
     * at the start, or at the end of the source for FIND_FROMEND and FIND_ENDSWITH, with a found length of 0, and
     * it wins over an empty source; it leaves the last error alone. An empty source finds nothing, with no error.
     */
    if (!cchSource || !cchValue)
    {
        if (!CompareStringEx(lpLocaleName, CompareFlags, L"", 0, L"", 0, NULL, NULL, 0))
            return -1;
        if (!cchValue)
        {
            if (pcchFound) *pcchFound = 0;
            return dwFindNLSStringFlags & (FIND_FROMEND | FIND_ENDSWITH) ? cchSource : 0;
        }
        SetLastError(ERROR_SUCCESS);
        return -1;
    }

    SetLastError(ERROR_SUCCESS);
    cchSource -= cchValue;
    if (cchSource < 0) return -1;

    count = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_FROMEND) ? cchSource + 1 : 1;
    offset = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 0 : cchSource;
    inc = dwFindNLSStringFlags & (FIND_FROMSTART | FIND_STARTSWITH) ? 1 : -1;
    while (count--)
    {
        ret = CompareStringEx(lpLocaleName, CompareFlags, lpStringSource + offset, cchValue,
                              lpStringValue, cchValue, NULL, NULL, 0);
        if (ret == CSTR_EQUAL)
        {
            if (pcchFound) *pcchFound = cchValue;
            return offset;
        }
        /* A bad locale or flag: CompareStringEx has set the error */
        if (!ret) return -1;
        offset += inc;
    }
    return -1;
}
#endif /* DLL_EXPORT_VERSION */
