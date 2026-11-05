/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A small hand-made DLL image for the no-execute load tests:
 *              .idata (an import, and DllMain returning a chosen value), .rsrc (RT_STRING, RT_RCDATA), .reloc
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */
#ifndef NOEXECUTEPE_H
#define NOEXECUTEPE_H

#define NXPE_FILE_ALIGN   0x200
#define NXPE_SECT_ALIGN   0x1000

#define NXPE_OFF_IMPORTS  0x000
#define NXPE_OFF_ILT      0x040
#define NXPE_OFF_IAT      0x060
#define NXPE_OFF_HINTNAME 0x080
#define NXPE_OFF_DLLNAME  0x0C0
#define NXPE_OFF_CODE     0x100
#define NXPE_SECT_SIZE    0x400

#define NXPE_RSRC_VA      0x2000
#define NXPE_RSRC_SIZE    0x400
#define NXPE_RELOC_VA     0x3000
#define NXPE_RELOC_SIZE   0x200
#define NXPE_RCDATA       "G4LDRRES"      /* 8 bytes */
#define NXPE_STRING       L"G4STR"        /* string id 0 */

enum { NXPE_RELOC_NONE = 0, NXPE_RELOC_VALID, NXPE_RELOC_SMALLBLOCK, NXPE_RELOC_LONGBLOCK, NXPE_RELOC_BADTARGET };
enum { NXPE_CORRUPT_NONE = 0, NXPE_CORRUPT_LFANEW_FAR, NXPE_CORRUPT_LFANEW_EDGE, NXPE_CORRUPT_SECTIONS, NXPE_CORRUPT_OPTSIZE };

typedef struct _NXPEOPT
{
    int ImportMissing;      /* import "nxpe_nonexistent_dep.dll!Foo" */
    int EntryOk;            /* DllMain returns TRUE (else FALSE) */
    int Reloc;              /* NXPE_RELOC_* */
    int Collide;            /* ImageBase = ULONG_PTR image base of the running exe */
    int Corrupt;            /* NXPE_CORRUPT_* */
} NXPEOPT;

#include <pshpack1.h>
typedef struct _NXHDR
{
    IMAGE_DOS_HEADER Dos;
#ifdef _WIN64
    IMAGE_NT_HEADERS64 Nt;
#else
    IMAGE_NT_HEADERS32 Nt;
#endif
    IMAGE_SECTION_HEADER Sect[3];
} NXHDR;
#include <poppack.h>

#define NXPE_IMAGE_SIZE (NXPE_FILE_ALIGN + NXPE_SECT_SIZE + NXPE_RSRC_SIZE + NXPE_RELOC_SIZE)

static void nx_dir(unsigned char *p, unsigned short nid)
{
    /* IMAGE_RESOURCE_DIRECTORY: Characteristics, TimeDateStamp, Major, Minor, NumberOfNamedEntries, NumberOfIdEntries */
    memset(p, 0, 16);
    *(unsigned short *)(p + 14) = nid;
}
static void nx_ent(unsigned char *p, unsigned long id, unsigned long off, int isdir)
{
    *(unsigned long *)p = id;
    *(unsigned long *)(p + 4) = off | (isdir ? 0x80000000UL : 0);
}

static int NxBuildPe(unsigned char *Image, const NXPEOPT *o, unsigned long long ImageBaseOverride)
{
    NXHDR *H = (NXHDR *)Image;
    unsigned char *S0 = Image + NXPE_FILE_ALIGN;
    unsigned char *S1 = S0 + NXPE_SECT_SIZE;
    unsigned char *S2 = S1 + NXPE_RSRC_SIZE;
    PIMAGE_IMPORT_DESCRIPTOR Imp = (PIMAGE_IMPORT_DESCRIPTOR)(S0 + NXPE_OFF_IMPORTS);
#ifdef _WIN64
    unsigned long long *Ilt = (unsigned long long *)(S0 + NXPE_OFF_ILT), *Iat = (unsigned long long *)(S0 + NXPE_OFF_IAT);
#else
    unsigned long *Ilt = (unsigned long *)(S0 + NXPE_OFF_ILT), *Iat = (unsigned long *)(S0 + NXPE_OFF_IAT);
#endif
    unsigned char *r;

    memset(Image, 0, NXPE_IMAGE_SIZE);
    H->Dos.e_magic = IMAGE_DOS_SIGNATURE;
    H->Dos.e_lfanew = offsetof(NXHDR, Nt);
    H->Nt.Signature = IMAGE_NT_SIGNATURE;
#ifdef _WIN64
    H->Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    H->Nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL;
    H->Nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    H->Nt.OptionalHeader.ImageBase = ImageBaseOverride ? ImageBaseOverride : 0x180000000ULL;
#else
    H->Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    H->Nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL;
    H->Nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    H->Nt.OptionalHeader.ImageBase = ImageBaseOverride ? (unsigned long)ImageBaseOverride : 0x10000000;
#endif
    H->Nt.FileHeader.NumberOfSections = 3;
    H->Nt.FileHeader.SizeOfOptionalHeader = sizeof(H->Nt.OptionalHeader);
    H->Nt.OptionalHeader.SizeOfCode = NXPE_SECT_SIZE;
    H->Nt.OptionalHeader.BaseOfCode = NXPE_SECT_ALIGN;
    H->Nt.OptionalHeader.AddressOfEntryPoint = NXPE_SECT_ALIGN + NXPE_OFF_CODE;
    H->Nt.OptionalHeader.SectionAlignment = NXPE_SECT_ALIGN;
    H->Nt.OptionalHeader.FileAlignment = NXPE_FILE_ALIGN;
    H->Nt.OptionalHeader.MajorOperatingSystemVersion = 5;
    H->Nt.OptionalHeader.MajorSubsystemVersion = 5;
    H->Nt.OptionalHeader.SizeOfImage = 4 * NXPE_SECT_ALIGN;
    H->Nt.OptionalHeader.SizeOfHeaders = NXPE_FILE_ALIGN;
    H->Nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    H->Nt.OptionalHeader.SizeOfStackReserve = 0x100000;
    H->Nt.OptionalHeader.SizeOfStackCommit = 0x1000;
    H->Nt.OptionalHeader.SizeOfHeapReserve = 0x100000;
    H->Nt.OptionalHeader.SizeOfHeapCommit = 0x1000;
    H->Nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    if (o->ImportMissing)
    {
        H->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = NXPE_SECT_ALIGN + NXPE_OFF_IMPORTS;
        H->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 2 * sizeof(*Imp);
    }
    H->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = NXPE_RSRC_VA;
    H->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = 0x300;
    if (o->Reloc != NXPE_RELOC_NONE)
    {
        H->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = NXPE_RELOC_VA;
        H->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0x10;
    }

    memcpy(H->Sect[0].Name, ".idata", 6);
    H->Sect[0].Misc.VirtualSize = NXPE_SECT_SIZE;
    H->Sect[0].VirtualAddress = NXPE_SECT_ALIGN;
    H->Sect[0].SizeOfRawData = NXPE_SECT_SIZE;
    H->Sect[0].PointerToRawData = NXPE_FILE_ALIGN;
    H->Sect[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA |
                                 IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    memcpy(H->Sect[1].Name, ".rsrc", 5);
    H->Sect[1].Misc.VirtualSize = NXPE_RSRC_SIZE;
    H->Sect[1].VirtualAddress = NXPE_RSRC_VA;
    H->Sect[1].SizeOfRawData = NXPE_RSRC_SIZE;
    H->Sect[1].PointerToRawData = NXPE_FILE_ALIGN + NXPE_SECT_SIZE;
    H->Sect[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    memcpy(H->Sect[2].Name, ".reloc", 6);
    H->Sect[2].Misc.VirtualSize = NXPE_RELOC_SIZE;
    H->Sect[2].VirtualAddress = NXPE_RELOC_VA;
    H->Sect[2].SizeOfRawData = NXPE_RELOC_SIZE;
    H->Sect[2].PointerToRawData = NXPE_FILE_ALIGN + NXPE_SECT_SIZE + NXPE_RSRC_SIZE;
    H->Sect[2].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;

    /* import of a DLL that does not exist */
    Imp[0].OriginalFirstThunk = NXPE_SECT_ALIGN + NXPE_OFF_ILT;
    Imp[0].Name = NXPE_SECT_ALIGN + NXPE_OFF_DLLNAME;
    Imp[0].FirstThunk = NXPE_SECT_ALIGN + NXPE_OFF_IAT;
    strcpy((char *)(S0 + NXPE_OFF_DLLNAME), "nxpe_nonexistent_dep.dll");
    strcpy((char *)(S0 + NXPE_OFF_HINTNAME + 2), "Foo");
    Ilt[0] = Iat[0] = NXPE_SECT_ALIGN + NXPE_OFF_HINTNAME;

    /* DllMain: mov eax, EntryOk; ret 12 (x86) / ret (x64) */
    S0[NXPE_OFF_CODE + 0] = 0xB8;
    *(unsigned long *)(S0 + NXPE_OFF_CODE + 1) = o->EntryOk ? 1 : 0;
#ifdef _WIN64
    S0[NXPE_OFF_CODE + 5] = 0xC3;
#else
    S0[NXPE_OFF_CODE + 5] = 0xC2;
    S0[NXPE_OFF_CODE + 6] = 0x0C;
#endif

    /* resources: root{STRING(6)->0x80, RCDATA(10)->0xA0}; name id 1; lang 0x409; data entries 0x100/0x110 */
    r = S1;
    nx_dir(r, 2);                       nx_ent(r + 0x10, 6, 0x80, 1);   nx_ent(r + 0x18, 10, 0xA0, 1);
    nx_dir(r + 0x80, 1);                nx_ent(r + 0x90, 1, 0xC0, 1);
    nx_dir(r + 0xA0, 1);                nx_ent(r + 0xB0, 1, 0xE0, 1);
    nx_dir(r + 0xC0, 1);                nx_ent(r + 0xD0, 0x409, 0x100, 0);
    nx_dir(r + 0xE0, 1);                nx_ent(r + 0xF0, 0x409, 0x110, 0);
    *(unsigned long *)(r + 0x100) = NXPE_RSRC_VA + 0x120;  *(unsigned long *)(r + 0x104) = 42;
    *(unsigned long *)(r + 0x110) = NXPE_RSRC_VA + 0x200;  *(unsigned long *)(r + 0x114) = 8;
    *(unsigned short *)(r + 0x120) = 5;
    memcpy(r + 0x122, NXPE_STRING, 10);
    memcpy(r + 0x200, NXPE_RCDATA, 8);

    /* relocations: one block at the start of .reloc (directory Size is 0x10: header + 4 entries) */
    r = S2;
    switch (o->Reloc)
    {
        case NXPE_RELOC_VALID:        /* HIGHLOW fixup at RVA 0x1000 + 0x1F8 (inside .idata, unused bytes) */
            *(unsigned long *)(r + 0) = NXPE_SECT_ALIGN;
            *(unsigned long *)(r + 4) = 12;
            *(unsigned short *)(r + 8) = (3 << 12) | 0x1F8;
            *(unsigned short *)(r + 10) = 0;
            break;
        case NXPE_RELOC_SMALLBLOCK:
            *(unsigned long *)(r + 0) = NXPE_SECT_ALIGN;
            *(unsigned long *)(r + 4) = 4;
            break;
        case NXPE_RELOC_LONGBLOCK:    /* the block ends far behind the directory */
            *(unsigned long *)(r + 0) = NXPE_SECT_ALIGN;
            *(unsigned long *)(r + 4) = 0x100000;
            break;
        case NXPE_RELOC_BADTARGET:    /* the page lies behind SizeOfImage */
            *(unsigned long *)(r + 0) = 0x00100000;
            *(unsigned long *)(r + 4) = 12;
            *(unsigned short *)(r + 8) = (3 << 12) | 0x010;
            *(unsigned short *)(r + 10) = 0;
            break;
    }

    switch (o->Corrupt)
    {
        case NXPE_CORRUPT_LFANEW_FAR:  H->Dos.e_lfanew = 0x7FFF0000; break;
        case NXPE_CORRUPT_LFANEW_EDGE: H->Dos.e_lfanew = 0x2000 - 8; break;
        case NXPE_CORRUPT_SECTIONS:    H->Nt.FileHeader.NumberOfSections = 0xFFFF; break;
        case NXPE_CORRUPT_OPTSIZE:     H->Nt.FileHeader.SizeOfOptionalHeader = 0xFFF0; break;
    }
    return NXPE_IMAGE_SIZE;
}
#endif
