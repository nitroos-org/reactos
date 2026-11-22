/*
 * COPYRIGHT:        GPL, see COPYING in the top level directory
 * PROJECT:          ReactOS win32 kernel mode subsystem server
 * PURPOSE:          File access support routines
 * FILE:             win32ss/user/ntuser/misc/file.c
 * PROGRAMER:        Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#include <win32k.h>

#define NDEBUG
#include <debug.h>

BOOL
NTAPI
W32kDosPathNameToNtPathName(
    IN PCWSTR pwszDosPathName,
    OUT PUNICODE_STRING pustrNtPathName)
{
    NTSTATUS Status;

    /* Prepend "\??\" */
    pustrNtPathName->Length = 0;
    Status = RtlAppendUnicodeToString(pustrNtPathName, L"\\??\\");
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    /* Append the dos name */
    Status = RtlAppendUnicodeToString(pustrNtPathName, pwszDosPathName);
    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    return TRUE;
}


HANDLE
NTAPI
W32kOpenFile(PCWSTR pwszFileName, DWORD dwDesiredAccess)
{
    UNICODE_STRING ustrFile;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    NTSTATUS Status;

    DPRINT("W32kOpenFile(%S)\n", pwszFileName);

    RtlInitUnicodeString(&ustrFile, pwszFileName);

    /* The name comes from the calling process (SPI_SETDESKWALLPAPER): the file is opened with the
       caller's own rights. OBJ_FORCE_ACCESS_CHECK makes the open check access (the directories on
       the way and the file) for the thread's token although the call comes from kernel mode, so a
       file the caller cannot read cannot be put on their desktop either. */
    InitializeObjectAttributes(&ObjectAttributes,
                               &ustrFile,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_FORCE_ACCESS_CHECK,
                               NULL,
                               NULL);

    Status = ZwCreateFile(&hFile,
                          dwDesiredAccess,
                          &ObjectAttributes,
                          &IoStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          0,
                          FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE,
                          NULL,
                          0);
    if (!NT_SUCCESS(Status))
    {
        SetLastNtError(Status);
        hFile = NULL;
    }

    DPRINT("Leaving W32kOpenFile, Status=0x%lx, hFile=0x%p\n", Status, hFile);
    return hFile;
}

HANDLE
NTAPI
W32kCreateFileSection(HANDLE hFile,
                      ULONG flAllocation,
                      DWORD flPageProtection,
                      ULONGLONG ullMaxSize)
{
    NTSTATUS Status;
    HANDLE hSection;
    ACCESS_MASK amDesiredAccess;

    /* Set access mask */
    amDesiredAccess = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ;

    /* Check if write access is requested */
    if (flPageProtection == PAGE_READWRITE)
    {
        /* Add it to access mask */
        amDesiredAccess |= SECTION_MAP_WRITE;
    }

    /* Now create the actual section */
    Status = ZwCreateSection(&hSection,
                             amDesiredAccess,
                             NULL,
                             NULL,
                             flPageProtection,
                             flAllocation,
                             hFile);
    if (!NT_SUCCESS(Status))
    {
        SetLastNtError(Status);
        hSection = NULL;
    }

    DPRINT("Leaving W32kCreateFileSection, Status=0x%lx, hSection=0x%p\n", Status, hSection);

    /* Return section handle */
    return hSection;
}

PVOID
NTAPI
W32kMapViewOfSection(
    HANDLE hSection,
    DWORD dwPageProtect,
    ULONG_PTR ulSectionOffset)
{
    NTSTATUS Status;
    LARGE_INTEGER liSectionOffset;
    ULONG_PTR ulViewSize;
    PVOID pvBase = NULL;

    liSectionOffset.QuadPart = ulViewSize = ulSectionOffset;
    Status = ZwMapViewOfSection(hSection,
                                NtCurrentProcess(),
                                &pvBase,
                                0,
                                0,
                                &liSectionOffset,
                                &ulViewSize,
                                ViewShare,
                                0,
                                dwPageProtect);
    if (!NT_SUCCESS(Status))
    {
        SetLastNtError(Status);
        pvBase = NULL;
    }

    DPRINT("Leaving W32kMapViewOfSection, Status=0x%lx, pvBase=0x%p\n", Status, pvBase);

    return pvBase;
}

/* Largest bitmap file UserLoadImage copies into pool (a 32 bpp 7680 x 4320 image is about 127 MB) */
#define CJ_MAX_IMAGE_FILE (256 * 1024 * 1024)

HBITMAP
NTAPI
UserLoadImage(PCWSTR pwszName)
{
    NTSTATUS Status = STATUS_SUCCESS;
    HANDLE hFile, hSection;
    IO_STATUS_BLOCK Iosb;
    FILE_STANDARD_INFORMATION FileInfo;
    PVOID pvView;
    BITMAPFILEHEADER *pbmfh = NULL;
    LPBITMAPINFO pbmi;
    PVOID pvBits;
    HBITMAP hbmp = 0;
    ULONG cjFile, cjHeader, cjInfo, cBitCount;

    DPRINT("Enter UserLoadImage(%ls)\n", pwszName);

    /* Open the file */
    hFile = W32kOpenFile(pwszName, FILE_READ_DATA);
    if (!hFile)
    {
        return NULL;
    }

    /* Everything below is bounded by the real size of the file, never by the sizes and offsets
       its header claims */
    Status = ZwQueryInformationFile(hFile, &Iosb, &FileInfo, sizeof(FileInfo), FileStandardInformation);
    if (!NT_SUCCESS(Status) ||
        (FileInfo.EndOfFile.QuadPart < (LONGLONG)(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPCOREHEADER))) ||
        (FileInfo.EndOfFile.QuadPart > CJ_MAX_IMAGE_FILE))
    {
        DPRINT1("Unusable image file size (status 0x%lx)\n", Status);
        ZwClose(hFile);
        return NULL;
    }
    cjFile = (ULONG)FileInfo.EndOfFile.QuadPart;

    /* Create a section */
    hSection = W32kCreateFileSection(hFile, SEC_COMMIT, PAGE_READONLY, 0);
    ZwClose(hFile);
    if (!hSection)
    {
        return NULL;
    }

    /* Map the section */
    pvView = W32kMapViewOfSection(hSection, PAGE_READONLY, 0);
    ZwClose(hSection);
    if (!pvView)
    {
        return NULL;
    }

    /* The view lives in user space, where the process can unmap or change it at any time:
       take a kernel copy under SEH and use nothing else */
    pbmfh = ExAllocatePoolWithTag(PagedPool, cjFile, TAG_DIB);
    if (!pbmfh)
    {
        goto leave;
    }

	_SEH2_TRY
	{
		RtlCopyMemory(pbmfh, pvView, cjFile);
	}
	_SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
	{
		Status = _SEH2_GetExceptionCode();
	}
	_SEH2_END

	if(!NT_SUCCESS(Status))
	{
		DPRINT1("Bad File?\n");
		goto leave;
	}

    if (pbmfh->bfType == 0x4D42 /* 'BM' */)
    {
		/* Could be BITMAPCOREINFO */
		BITMAPINFO* pConvertedInfo;
		HDC hdc;

        /* Get a pointer to the BITMAPINFO */
        pbmi = (LPBITMAPINFO)(pbmfh + 1);

        /* The header and its colour table must be inside the file */
        cjHeader = pbmi->bmiHeader.biSize;
        if (cjHeader == sizeof(BITMAPCOREHEADER))
        {
            cBitCount = ((PBITMAPCOREHEADER)pbmi)->bcBitCount;
            cjInfo = sizeof(BITMAPCOREHEADER) + ((cBitCount <= 8) ? (sizeof(RGBTRIPLE) << cBitCount) : 0);
        }
        else if ((cjHeader >= sizeof(BITMAPINFOHEADER)) &&
                 (cjHeader <= cjFile - sizeof(BITMAPFILEHEADER)))
        {
            cjInfo = (ULONG)DIB_BitmapInfoSize(pbmi, DIB_RGB_COLORS);
        }
        else
        {
            DPRINT1("Invalid header size %lu\n", cjHeader);
            goto leave;
        }

        if ((cjInfo > cjFile - sizeof(BITMAPFILEHEADER)) ||
            (pbmfh->bfOffBits < sizeof(BITMAPFILEHEADER) + cjInfo) ||
            (pbmfh->bfOffBits >= cjFile))
        {
            DPRINT1("Header or bits outside of the file (info %lu, offset %lu, file %lu)\n",
                    cjInfo, pbmfh->bfOffBits, cjFile);
            goto leave;
        }

		pvBits = (PVOID)((PCHAR)pbmfh + pbmfh->bfOffBits);

		pConvertedInfo = DIB_ConvertBitmapInfo(pbmi, DIB_RGB_COLORS);
		if(!pConvertedInfo)
		{
			DPRINT1("Unable to convert the bitmap Info\n");
			goto leave;
		}

		hdc = IntGdiCreateDC(NULL, NULL, NULL, NULL,FALSE);

        /* The bits are the rest of the file (bfSize is not trusted) */
        hbmp = GreCreateDIBitmapInternal(hdc,
                                         pConvertedInfo->bmiHeader.biWidth,
				                         pConvertedInfo->bmiHeader.biHeight,
                                         CBM_INIT,
                                         pvBits,
                                         pConvertedInfo,
                                         DIB_RGB_COLORS,
                                         0,
                                         cjFile - pbmfh->bfOffBits,
                                         0);

		NtGdiDeleteObjectApp(hdc);
		DIB_FreeConvertedBitmapInfo(pConvertedInfo, pbmi, -1);
    }
	else
	{
		DPRINT1("Unknown file type!\n");
	}

leave:
    if (pbmfh) ExFreePoolWithTag(pbmfh, TAG_DIB);

    /* Unmap our section, we don't need it anymore */
    ZwUnmapViewOfSection(NtCurrentProcess(), pvView);

    DPRINT("Leaving UserLoadImage, hbmp = %p\n", hbmp);
    return hbmp;
}
