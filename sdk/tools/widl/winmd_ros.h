/*
 * PROJECT:     ReactOS host tools
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows definitions that widl's metadata.c takes from the Windows headers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#include <typedefs.h>
#include <pecoff.h>
#include <guiddef.h>

#ifndef IMAGE_FILE_EXECUTABLE_IMAGE
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#endif
#ifndef IMAGE_FILE_32BIT_MACHINE
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#endif
#ifndef IMAGE_FILE_DLL
#define IMAGE_FILE_DLL 0x2000
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_CUI
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_SEH
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#endif
#ifndef COMIMAGE_FLAGS_ILONLY
#define COMIMAGE_FLAGS_ILONLY 0x00000001
#endif
#ifndef CALG_SHA
#define CALG_SHA 0x00008004
#endif

typedef struct _WINMD_IMAGE_COR20_HEADER
{
    DWORD cb;
    WORD MajorRuntimeVersion;
    WORD MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    DWORD Flags;
    union
    {
        DWORD EntryPointToken;
        DWORD EntryPointRVA;
    };
    IMAGE_DATA_DIRECTORY Resources;
    IMAGE_DATA_DIRECTORY StrongNameSignature;
    IMAGE_DATA_DIRECTORY CodeManagerTable;
    IMAGE_DATA_DIRECTORY VTableFixups;
    IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY ManagedNativeHeader;
} IMAGE_COR20_HEADER;
