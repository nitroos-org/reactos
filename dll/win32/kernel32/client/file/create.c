/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/create.c
 * PURPOSE:         Directory functions
 * PROGRAMMER:      Ariadne ( ariadne@xs4all.nl)
 * UPDATE HISTORY:
 *                  Created 01/11/98
 *                  Removed use of SearchPath (not used by Windows)
 *                  18/08/2002: CreateFileW mess cleaned up (KJK::Hyperion)
 *                  24/08/2002: removed superfluous DPRINTs (KJK::Hyperion)
 */

/* INCLUDES *****************************************************************/

#include <k32.h>
#include <fileapi.h>
#define NDEBUG
#include <debug.h>

#if DBG
DEBUG_CHANNEL(kernel32file);
#endif

/* FUNCTIONS ****************************************************************/

/*
 * @implemented
 */
HANDLE WINAPI CreateFileA (LPCSTR			lpFileName,
			    DWORD			dwDesiredAccess,
			    DWORD			dwShareMode,
			    LPSECURITY_ATTRIBUTES	lpSecurityAttributes,
			    DWORD			dwCreationDisposition,
			    DWORD			dwFlagsAndAttributes,
			    HANDLE			hTemplateFile)
{
   PWCHAR FileNameW;
   HANDLE FileHandle;

   TRACE("CreateFileA(lpFileName %s)\n",lpFileName);

   if (!(FileNameW = FilenameA2W(lpFileName, FALSE)))
      return INVALID_HANDLE_VALUE;

   FileHandle = CreateFileW (FileNameW,
			     dwDesiredAccess,
			     dwShareMode,
			     lpSecurityAttributes,
			     dwCreationDisposition,
			     dwFlagsAndAttributes,
			     hTemplateFile);

   return FileHandle;
}

static
HANDLE
BasepCreateFile(LPCWSTR lpFileName,
                DWORD dwDesiredAccess,
                DWORD dwShareMode,
                LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                DWORD dwCreationDisposition,
                DWORD dwFlagsAndAttributes,
                HANDLE hTemplateFile,
                BOOLEAN NoRecall,
                BOOLEAN QosPresent);

/*
 * @implemented
 */
HANDLE WINAPI CreateFileW (LPCWSTR			lpFileName,
			    DWORD			dwDesiredAccess,
			    DWORD			dwShareMode,
			    LPSECURITY_ATTRIBUTES	lpSecurityAttributes,
			    DWORD			dwCreationDisposition,
			    DWORD			dwFlagsAndAttributes,
			    HANDLE			hTemplateFile)
{
   return BasepCreateFile(lpFileName,
                          dwDesiredAccess,
                          dwShareMode,
                          lpSecurityAttributes,
                          dwCreationDisposition,
                          dwFlagsAndAttributes,
                          hTemplateFile,
                          (dwFlagsAndAttributes & FILE_FLAG_OPEN_NO_RECALL) != 0,
                          (dwFlagsAndAttributes & SECURITY_SQOS_PRESENT) != 0);
}

/*
 * @implemented
 */
HANDLE
WINAPI
CreateFile2(IN LPCWSTR lpFileName,
            IN DWORD dwDesiredAccess,
            IN DWORD dwShareMode,
            IN DWORD dwCreationDisposition,
            IN LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams OPTIONAL)
{
    /* What Windows takes from each of the three fields; the rest is ignored */
    static const DWORD AttributesMask = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM |
                                        FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY |
                                        FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_ENCRYPTED;
    static const DWORD FlagsMask = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_DELETE_ON_CLOSE |
                                   FILE_FLAG_NO_BUFFERING | FILE_FLAG_OPEN_NO_RECALL |
                                   FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED |
                                   FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_RANDOM_ACCESS |
                                   FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_WRITE_THROUGH;
    static const DWORD SecurityMask = SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS | SECURITY_IDENTIFICATION |
                                      SECURITY_IMPERSONATION | SECURITY_DELEGATION |
                                      SECURITY_CONTEXT_TRACKING | SECURITY_EFFECTIVE_ONLY;
    SECURITY_ATTRIBUTES *SecurityAttributes = NULL;
    HANDLE TemplateFile = NULL;
    DWORD FlagsAndAttributes = 0;
    BOOLEAN NoRecall = FALSE, QosPresent = FALSE;

    if (pCreateExParams)
    {
        /* A structure from a later Windows is larger and accepted */
        if (pCreateExParams->dwSize < sizeof(*pCreateExParams))
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }

        SecurityAttributes = pCreateExParams->lpSecurityAttributes;
        TemplateFile = pCreateExParams->hTemplateFile;
        /* one bit means FILE_FLAG_OPEN_NO_RECALL in the flags and SECURITY_SQOS_PRESENT in the quality of service */
        NoRecall = (pCreateExParams->dwFileFlags & FILE_FLAG_OPEN_NO_RECALL) != 0;
        QosPresent = (pCreateExParams->dwSecurityQosFlags & SECURITY_SQOS_PRESENT) != 0;
        FlagsAndAttributes = (pCreateExParams->dwFileAttributes & AttributesMask) |
                             (pCreateExParams->dwFileFlags & FlagsMask & ~FILE_FLAG_OPEN_NO_RECALL) |
                             (pCreateExParams->dwSecurityQosFlags & SecurityMask & ~SECURITY_SQOS_PRESENT);
    }

    return BasepCreateFile(lpFileName,
                           dwDesiredAccess,
                           dwShareMode,
                           SecurityAttributes,
                           dwCreationDisposition,
                           FlagsAndAttributes,
                           TemplateFile,
                           NoRecall,
                           QosPresent);
}

/* The two bits of dwFlagsAndAttributes that CreateFileW cannot tell apart, FILE_FLAG_OPEN_NO_RECALL and
   SECURITY_SQOS_PRESENT, are given separately so that CreateFile2 can keep its two fields apart */
static
HANDLE
BasepCreateFile(LPCWSTR lpFileName,
                DWORD dwDesiredAccess,
                DWORD dwShareMode,
                LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                DWORD dwCreationDisposition,
                DWORD dwFlagsAndAttributes,
                HANDLE hTemplateFile,
                BOOLEAN NoRecall,
                BOOLEAN QosPresent)
{
   OBJECT_ATTRIBUTES ObjectAttributes;
   SECURITY_QUALITY_OF_SERVICE SecurityQos;
   IO_STATUS_BLOCK IoStatusBlock;
   UNICODE_STRING NtPathU;
   LPCWSTR pszConsoleFileName;
   HANDLE FileHandle;
   NTSTATUS Status;
   ULONG FileAttributes, Flags = 0;
   PVOID EaBuffer = NULL;
   ULONG EaLength = 0;
   BOOLEAN TrailingBackslash;

   if (!lpFileName || !lpFileName[0])
   {
       SetLastError( ERROR_PATH_NOT_FOUND );
       return INVALID_HANDLE_VALUE;
   }

   TRACE("CreateFileW(lpFileName %S)\n",lpFileName);

   /* validate & translate the creation disposition */
   switch (dwCreationDisposition)
     {
      case CREATE_NEW:
	dwCreationDisposition = FILE_CREATE;
	break;

      case CREATE_ALWAYS:
	dwCreationDisposition = FILE_OVERWRITE_IF;
	break;

      case OPEN_EXISTING:
	dwCreationDisposition = FILE_OPEN;
	break;

      case OPEN_ALWAYS:
	dwCreationDisposition = FILE_OPEN_IF;
	break;

      case TRUNCATE_EXISTING:
	dwCreationDisposition = FILE_OVERWRITE;
        break;

      default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return (INVALID_HANDLE_VALUE);
     }

   /* check for console input/output */
   pszConsoleFileName = IntCheckForConsoleFileName(lpFileName, dwDesiredAccess);
   if (pszConsoleFileName)
   {
      return OpenConsoleW(pszConsoleFileName,
                          dwDesiredAccess,
                          lpSecurityAttributes ? lpSecurityAttributes->bInheritHandle : FALSE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE);
   }

  /* validate & translate the flags */

   /* translate the flags that need no validation */
   if (!(dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED))
   {
      /* yes, nonalert is correct! apc's are not delivered
      while waiting for file io to complete */
      Flags |= FILE_SYNCHRONOUS_IO_NONALERT;
   }

   if(dwFlagsAndAttributes & FILE_FLAG_WRITE_THROUGH)
      Flags |= FILE_WRITE_THROUGH;

   if(dwFlagsAndAttributes & FILE_FLAG_NO_BUFFERING)
      Flags |= FILE_NO_INTERMEDIATE_BUFFERING;

   if(dwFlagsAndAttributes & FILE_FLAG_RANDOM_ACCESS)
      Flags |= FILE_RANDOM_ACCESS;

   if(dwFlagsAndAttributes & FILE_FLAG_SEQUENTIAL_SCAN)
      Flags |= FILE_SEQUENTIAL_ONLY;

   if(dwFlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE)
   {
      Flags |= FILE_DELETE_ON_CLOSE;
      dwDesiredAccess |= DELETE;
   }

   if(dwFlagsAndAttributes & FILE_FLAG_BACKUP_SEMANTICS)
   {
      if(dwDesiredAccess & GENERIC_ALL)
         Flags |= FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REMOTE_INSTANCE;
      else
      {
         if(dwDesiredAccess & GENERIC_READ)
            Flags |= FILE_OPEN_FOR_BACKUP_INTENT;

         if(dwDesiredAccess & GENERIC_WRITE)
            Flags |= FILE_OPEN_REMOTE_INSTANCE;
      }
   }
   else
      Flags |= FILE_NON_DIRECTORY_FILE;

   /* Windows creates a new *directory* (not a file) when the caller asks for
      POSIX semantics together with the directory attribute and CREATE_NEW; this
      is the documented translation performed by kernelbase (get_nt_file_options:
      FILE_FLAG_POSIX_SEMANTICS && FILE_ATTRIBUTE_DIRECTORY && CREATE_NEW ->
      FILE_DIRECTORY_FILE). It is the path WinFsp's installer custom action uses
      to create its junction point before stamping the mount-point reparse data.
      dwCreationDisposition has already been translated to the NT disposition
      above, so CREATE_NEW is FILE_CREATE here. */
   if ((dwFlagsAndAttributes & FILE_FLAG_POSIX_SEMANTICS) &&
       (dwFlagsAndAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
       dwCreationDisposition == FILE_CREATE)
   {
      Flags |= FILE_DIRECTORY_FILE;
   }

   if(dwFlagsAndAttributes & FILE_FLAG_OPEN_REPARSE_POINT)
      Flags |= FILE_OPEN_REPARSE_POINT;

   if (NoRecall)
      Flags |= FILE_OPEN_NO_RECALL;

   FileAttributes = (dwFlagsAndAttributes & (FILE_ATTRIBUTE_VALID_FLAGS & ~FILE_ATTRIBUTE_DIRECTORY));

   /* handle may always be waited on and querying attributes are always allowed */
   dwDesiredAccess |= SYNCHRONIZE | FILE_READ_ATTRIBUTES;

   /* FILE_FLAG_POSIX_SEMANTICS is handled later */

   /* validate & translate the filename */
   if (!RtlDosPathNameToNtPathName_U (lpFileName,
				      &NtPathU,
				      NULL,
				      NULL))
   {
     WARN("Invalid path\n");
     SetLastError(ERROR_FILE_NOT_FOUND);
     return INVALID_HANDLE_VALUE;
   }

   TRACE("NtPathU \'%wZ\'\n", &NtPathU);

   TrailingBackslash = FALSE;
   if (NtPathU.Length >= sizeof(WCHAR) &&
       NtPathU.Buffer[NtPathU.Length / sizeof(WCHAR) - 1] == L'\\')
   {
      TrailingBackslash = TRUE;
   }

   if (hTemplateFile != NULL)
   {
      FILE_EA_INFORMATION EaInformation;

      for (;;)
      {
         /* try to get the size of the extended attributes, if we fail just continue
            creating the file without copying the attributes! */
         Status = NtQueryInformationFile(hTemplateFile,
                                         &IoStatusBlock,
                                         &EaInformation,
                                         sizeof(FILE_EA_INFORMATION),
                                         FileEaInformation);
         if (NT_SUCCESS(Status) && (EaInformation.EaSize != 0))
         {
            /* there's extended attributes to read, let's give it a try */
            EaBuffer = RtlAllocateHeap(RtlGetProcessHeap(),
                                       0,
                                       EaInformation.EaSize);
            if (EaBuffer == NULL)
            {
               RtlFreeHeap(RtlGetProcessHeap(),
                           0,
                           NtPathU.Buffer);

               /* the template file handle is valid and has extended attributes,
                  however we seem to lack some memory here. We should fail here! */
               SetLastError(ERROR_NOT_ENOUGH_MEMORY);
               return INVALID_HANDLE_VALUE;
            }

            Status = NtQueryEaFile(hTemplateFile,
                                   &IoStatusBlock,
                                   EaBuffer,
                                   EaInformation.EaSize,
                                   FALSE,
                                   NULL,
                                   0,
                                   NULL,
                                   TRUE);

            if (NT_SUCCESS(Status))
            {
               /* we successfully read the extended attributes, break the loop
                  and continue */
               EaLength = EaInformation.EaSize;
               break;
            }
            else
            {
               RtlFreeHeap(RtlGetProcessHeap(),
                           0,
                           EaBuffer);
               EaBuffer = NULL;

               if (Status != STATUS_BUFFER_TOO_SMALL)
               {
                  /* unless we just allocated not enough memory, break the loop
                     and just continue without copying extended attributes */
                  break;
               }
            }
         }
         else
         {
            /* we either failed to get the size of the extended attributes or
               they're empty, just continue as there's no need to copy
               attributes */
            break;
         }
      }
   }

   /* build the object attributes */
   InitializeObjectAttributes(&ObjectAttributes,
                              &NtPathU,
                              0,
                              NULL,
                              NULL);

   if (lpSecurityAttributes)
   {
      if(lpSecurityAttributes->bInheritHandle)
         ObjectAttributes.Attributes |= OBJ_INHERIT;

      ObjectAttributes.SecurityDescriptor = lpSecurityAttributes->lpSecurityDescriptor;
   }

   if(!(dwFlagsAndAttributes & FILE_FLAG_POSIX_SEMANTICS))
    ObjectAttributes.Attributes |= OBJ_CASE_INSENSITIVE;

   /* the caller limits what the server end of a pipe may do with its identity */
   if (QosPresent)
   {
      SecurityQos.Length = sizeof(SecurityQos);
      SecurityQos.ImpersonationLevel = (dwFlagsAndAttributes >> 16) & 0x3;
      SecurityQos.ContextTrackingMode =
         (dwFlagsAndAttributes & SECURITY_CONTEXT_TRACKING) ?
         SECURITY_DYNAMIC_TRACKING : SECURITY_STATIC_TRACKING;
      SecurityQos.EffectiveOnly =
         (dwFlagsAndAttributes & SECURITY_EFFECTIVE_ONLY) ? TRUE : FALSE;
      ObjectAttributes.SecurityQualityOfService = &SecurityQos;
   }

   /* perform the call */
   Status = NtCreateFile (&FileHandle,
			  dwDesiredAccess,
			  &ObjectAttributes,
			  &IoStatusBlock,
			  NULL,
			  FileAttributes,
			  dwShareMode,
			  dwCreationDisposition,
			  Flags,
			  EaBuffer,
			  EaLength);

   /* free the extended attributes buffer if allocated */
   if (EaBuffer != NULL)
   {
      RtlFreeHeap(RtlGetProcessHeap(),
                  0,
                  EaBuffer);
   }

   /* error */
   if (!NT_SUCCESS(Status))
   {
      FILE_BASIC_INFORMATION ExistingInformation;
      BOOLEAN IsDirectory = FALSE;

      /* In the case file creation was rejected due to CREATE_NEW flag
       * was specified and file with that name already exists, correct
       * last error is ERROR_FILE_EXISTS and not ERROR_ALREADY_EXISTS.
       * Note: RtlNtStatusToDosError is not the subject to blame here.
       */
      if (Status == STATUS_OBJECT_NAME_COLLISION &&
          dwCreationDisposition == FILE_CREATE)
      {
         /* Windows 10 refuses to create a file over a directory with access denied; the name that was opened is
            asked again, as it was opened (the current directory may have changed since) */
         if (NT_SUCCESS(NtQueryAttributesFile(&ObjectAttributes, &ExistingInformation)) &&
             (ExistingInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
         {
            IsDirectory = TRUE;
         }

         SetLastError( IsDirectory ? ERROR_ACCESS_DENIED : ERROR_FILE_EXISTS );
      }
      else if (Status == STATUS_FILE_IS_A_DIRECTORY &&
               TrailingBackslash)
      {
         SetLastError(ERROR_PATH_NOT_FOUND);
      }
      else
      {
         BaseSetLastNTError (Status);
      }

      RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathU.Buffer);
      return INVALID_HANDLE_VALUE;
   }

   RtlFreeHeap(RtlGetProcessHeap(), 0, NtPathU.Buffer);

  /*
  create with OPEN_ALWAYS (FILE_OPEN_IF) returns info = FILE_OPENED or FILE_CREATED
  create with CREATE_ALWAYS (FILE_OVERWRITE_IF) returns info = FILE_OVERWRITTEN or FILE_CREATED
  */
  if (dwCreationDisposition == FILE_OPEN_IF)
  {
    SetLastError(IoStatusBlock.Information == FILE_OPENED ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
  }
  else if (dwCreationDisposition == FILE_OVERWRITE_IF)
  {
    SetLastError(IoStatusBlock.Information == FILE_OVERWRITTEN ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
  }
  else
  {
    SetLastError(ERROR_SUCCESS);
  }

  return FileHandle;
}

/*
 * @implemented
 */
HFILE WINAPI
OpenFile(LPCSTR lpFileName,
	 LPOFSTRUCT lpReOpenBuff,
	 UINT uStyle)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	UNICODE_STRING FileNameString;
	UNICODE_STRING FileNameU;
	ANSI_STRING FileName;
	WCHAR PathNameW[MAX_PATH];
	HANDLE FileHandle = NULL;
	NTSTATUS errCode;
	PWCHAR FilePart;
	ULONG Len;

	TRACE("OpenFile('%s', lpReOpenBuff %p, uStyle %x)\n", lpFileName, lpReOpenBuff, uStyle);

	if (lpReOpenBuff == NULL)
	{
		return HFILE_ERROR;
	}

    lpReOpenBuff->nErrCode = 0;

	if (uStyle & OF_REOPEN) lpFileName = lpReOpenBuff->szPathName;

	if (!lpFileName)
	{
		return HFILE_ERROR;
	}

	if (!GetFullPathNameA(lpFileName,
						  sizeof(lpReOpenBuff->szPathName),
						  lpReOpenBuff->szPathName,
						  NULL))
	{
	    lpReOpenBuff->nErrCode = (WORD)GetLastError();
		return HFILE_ERROR;
	}

    if (uStyle & OF_PARSE)
    {
        lpReOpenBuff->fFixedDisk = (GetDriveTypeA(lpReOpenBuff->szPathName) != DRIVE_REMOVABLE);
        TRACE("(%s): OF_PARSE, res = '%s'\n", lpFileName, lpReOpenBuff->szPathName);
        return 0;
    }

    if ((uStyle & OF_EXIST) && !(uStyle & OF_CREATE))
    {
        DWORD dwAttributes = GetFileAttributesA(lpReOpenBuff->szPathName);

        switch (dwAttributes)
        {
            case INVALID_FILE_ATTRIBUTES: /* File does not exist */
                SetLastError(ERROR_FILE_NOT_FOUND);
                lpReOpenBuff->nErrCode = (WORD) ERROR_FILE_NOT_FOUND;
                return -1;

            case FILE_ATTRIBUTE_DIRECTORY:
                SetLastError(ERROR_ACCESS_DENIED);
                lpReOpenBuff->nErrCode = (WORD) ERROR_ACCESS_DENIED;
                return -1;

            default:
                lpReOpenBuff->cBytes = sizeof(OFSTRUCT);
                return 1;
        }
    }
    lpReOpenBuff->cBytes = sizeof(OFSTRUCT);
	if ((uStyle & OF_CREATE) == OF_CREATE)
	{
		DWORD Sharing;
		switch (uStyle & 0x70)
		{
			case OF_SHARE_EXCLUSIVE: Sharing = 0; break;
			case OF_SHARE_DENY_WRITE: Sharing = FILE_SHARE_READ; break;
			case OF_SHARE_DENY_READ: Sharing = FILE_SHARE_WRITE; break;
			case OF_SHARE_DENY_NONE:
			case OF_SHARE_COMPAT:
			default:
				Sharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
		}
		return (HFILE)(ULONG_PTR) CreateFileA (lpFileName,
		                            GENERIC_READ | GENERIC_WRITE,
		                            Sharing,
		                            NULL,
		                            CREATE_ALWAYS,
		                            FILE_ATTRIBUTE_NORMAL,
		                            0);
	}

	RtlInitAnsiString (&FileName, (LPSTR)lpFileName);

	/* convert ansi (or oem) string to unicode */
	if (bIsFileApiAnsi)
		RtlAnsiStringToUnicodeString (&FileNameU, &FileName, TRUE);
	else
		RtlOemStringToUnicodeString (&FileNameU, &FileName, TRUE);

	Len = SearchPathW (NULL,
	                   FileNameU.Buffer,
        	           NULL,
	                   OFS_MAXPATHNAME,
	                   PathNameW,
        	           &FilePart);

	RtlFreeUnicodeString(&FileNameU);

	if (Len == 0 || Len > OFS_MAXPATHNAME)
	{
		lpReOpenBuff->nErrCode = (WORD)GetLastError();
		return HFILE_ERROR;
	}

    if (uStyle & OF_DELETE)
    {
        if (!DeleteFileW(PathNameW))
		{
			lpReOpenBuff->nErrCode = (WORD)GetLastError();
			return HFILE_ERROR;
		}
        TRACE("(%s): OF_DELETE return = OK\n", lpFileName);
        return TRUE;
    }

	FileName.Buffer = lpReOpenBuff->szPathName;
	FileName.Length = 0;
	FileName.MaximumLength = OFS_MAXPATHNAME;

	RtlInitUnicodeString(&FileNameU, PathNameW);

	/* convert unicode string to ansi (or oem) */
	if (bIsFileApiAnsi)
		RtlUnicodeStringToAnsiString (&FileName, &FileNameU, FALSE);
	else
		RtlUnicodeStringToOemString (&FileName, &FileNameU, FALSE);

	if (!RtlDosPathNameToNtPathName_U (PathNameW,
					   &FileNameString,
					   NULL,
					   NULL))
	{
		return HFILE_ERROR;
	}

	// FILE_SHARE_READ
	// FILE_NO_INTERMEDIATE_BUFFERING

    InitializeObjectAttributes(&ObjectAttributes,
                               &FileNameString,
                               OBJ_CASE_INSENSITIVE | OBJ_INHERIT,
                               NULL,
                               NULL);

	errCode = NtOpenFile (&FileHandle,
	                      GENERIC_READ | SYNCHRONIZE,
	                      &ObjectAttributes,
	                      &IoStatusBlock,
	                      FILE_SHARE_READ,
	                      FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

	RtlFreeHeap(RtlGetProcessHeap(), 0, FileNameString.Buffer);

	lpReOpenBuff->nErrCode = (WORD)RtlNtStatusToDosError(errCode);

	if (!NT_SUCCESS(errCode))
	{
		BaseSetLastNTError (errCode);
		return HFILE_ERROR;
	}

	if (uStyle & OF_EXIST)
	{
		NtClose(FileHandle);
		return (HFILE)1;
	}

	return (HFILE)(ULONG_PTR)FileHandle;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
OpenDataFile(HANDLE hFile, DWORD dwUnused)
{
    STUB;
    return FALSE;
}

/*
 * Bits of dwFlags that ReOpenFile rejects with ERROR_INVALID_PARAMETER. They are the FILE_ATTRIBUTE_* values:
 * the parameter takes FILE_FLAG_* values only. The set was measured on Windows Server 2022 by passing every single bit;
 * 0x8, 0x40, 0x10000, 0x40000 and the FILE_FLAG_* bits above 0x200000 are accepted (and mostly ignored).
 */
#define REOPENFILE_INVALID_FLAGS 0x005affb7

/*
 * @implemented
 *
 * Opens the file object of a handle again with other access, sharing and flags: a relative open with the handle as the
 * root directory and an empty name. The new handle does not share the file pointer of the original handle.
 */
HANDLE
WINAPI
ReOpenFile(IN HANDLE hOriginalFile,
           IN DWORD dwDesiredAccess,
           IN DWORD dwShareMode,
           IN DWORD dwFlags)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING EmptyName = {0, 0, NULL};
    IO_STATUS_BLOCK IoStatusBlock;
    ULONG Options = FILE_NON_DIRECTORY_FILE;
    NTSTATUS Status;
    HANDLE Handle;

    if (dwFlags & REOPENFILE_INVALID_FLAGS)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    /* Deleting the file when the new handle is closed needs the delete access */
    if (dwFlags & FILE_FLAG_DELETE_ON_CLOSE)
        dwDesiredAccess |= DELETE;

    InitializeObjectAttributes(&ObjectAttributes, &EmptyName, OBJ_CASE_INSENSITIVE, hOriginalFile, NULL);

    /* Same translation of FILE_FLAG_* to NtCreateFile options as CreateFile (directories are refused: measured) */
    if (dwFlags & FILE_FLAG_BACKUP_SEMANTICS)
        Options |= FILE_OPEN_FOR_BACKUP_INTENT;
    if (dwFlags & FILE_FLAG_DELETE_ON_CLOSE)
        Options |= FILE_DELETE_ON_CLOSE;
    if (dwFlags & FILE_FLAG_NO_BUFFERING)
        Options |= FILE_NO_INTERMEDIATE_BUFFERING;
    if (!(dwFlags & FILE_FLAG_OVERLAPPED))
        Options |= FILE_SYNCHRONOUS_IO_NONALERT;
    if (dwFlags & FILE_FLAG_RANDOM_ACCESS)
        Options |= FILE_RANDOM_ACCESS;
    if (dwFlags & FILE_FLAG_SEQUENTIAL_SCAN)
        Options |= FILE_SEQUENTIAL_ONLY;
    if (dwFlags & FILE_FLAG_WRITE_THROUGH)
        Options |= FILE_WRITE_THROUGH;
    if (dwFlags & FILE_FLAG_OPEN_REPARSE_POINT)
        Options |= FILE_OPEN_REPARSE_POINT;

    Status = NtCreateFile(&Handle,
                          dwDesiredAccess | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
                          &ObjectAttributes,
                          &IoStatusBlock,
                          NULL,
                          0,
                          dwShareMode,
                          FILE_OPEN,
                          Options,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return INVALID_HANDLE_VALUE;
    }

    return Handle;
}

/* EOF */
