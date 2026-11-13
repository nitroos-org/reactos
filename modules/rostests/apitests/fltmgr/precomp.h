/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Tests of the filter manager, with the sample mini-filter driver
 */

#ifndef _FLTMGR_APITEST_PRECOMP_H
#define _FLTMGR_APITEST_PRECOMP_H

#include <stdio.h>

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winsvc.h>
#include <winioctl.h>
#include <ndk/ntndk.h>
#include <strsafe.h>

#include "fltsample.h"

#define FLTAPI_FSTYPE_NTFS  2
#define FLTAPI_FSTYPE_FAT   3

typedef struct _SAMPLE
{
    WCHAR Name[32];
    WCHAR Image[MAX_PATH];
    HANDLE Control;
    BOOL ServiceCreated;
    /* What the driver reported when it was unloaded */
    ULONG LastSetups;
    ULONG LastTeardownStarts;
    ULONG LastTeardownCompletes;
    ULONG LastLive;
    ULONG LastFiltering;

} SAMPLE, *PSAMPLE;

/* The result of the IOCTLs that attach or detach every volume */
typedef struct _ATTACH_RESULT
{
    ULONG Done;
    ULONG Failed;
    NTSTATUS LastStatus;

} ATTACH_RESULT;

/* support.c */
BOOL StartFilterManager(void);
BOOL LoadSample(PSAMPLE Sample, PCWSTR Name, PCWSTR Altitude, ULONG AttachMask);
BOOL UnloadSample(PSAMPLE Sample, BOOL ExpectUnload);
BOOL SampleStats(PSAMPLE Sample, PFLTSAMPLE_STATS Stats);
BOOL SampleIoctl(PSAMPLE Sample, ULONG Code, PVOID In, ULONG InSize, PVOID Out, ULONG OutSize);
ULONG SampleLastRun(PSAMPLE Sample, PCWSTR Value);
void GetTestDirectory(PWSTR Buffer, ULONG Length);
void EnsureTestDirectory(void);
BOOL MakeTestFile(PCWSTR Name, PWSTR Path, ULONG Length);
ULONG CurrentFileSystem(void);

#endif
