/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test for the bitness of the process of an IL-only .NET executable (AnyCPU, Prefer32Bit, x86)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * An AnyCPU .NET executable is a PE32 file whose COM descriptor says IL-only, without requiring or preferring 32 bits.
 * 64-bit Windows starts it as a 64-bit process: the image information has ComPlusNativeReady set (and still says
 * i386), the kernel maps the PE32 image, and the loader rewrites its headers to PE32+ without relocating it or
 * snapping its imports. Prefer32Bit, 32BITREQUIRED, a non-IL-only image and a .NET 1.x one start under WOW64.
 * The expectations were measured on Windows 10 22H2 x64. The fixture is generated here and never runs managed code.
 */

#include "precomp.h"
#include <ndk/mmfuncs.h>
#include <ndk/pstypes.h>
#include <ndk/psfuncs.h>
#include <ndk/obfuncs.h>

#define IL_IMAGE_BASE   0x400000UL
#define IL_FILE_ALIGN   0x200
#define IL_TEXT_RVA     0x1000
#define IL_RELOC_RVA    0x2000
#define IL_SIZE_OF_IMAGE 0x3000

/* Layout of .text */
#define IL_IAT_RVA      (IL_TEXT_RVA + 0x00)
#define IL_COR_RVA      (IL_TEXT_RVA + 0x08)
#define IL_META_RVA     (IL_TEXT_RVA + 0x50)
#define IL_IMPORT_RVA   (IL_TEXT_RVA + 0x80)
#define IL_ILT_RVA      (IL_TEXT_RVA + 0xa8)
#define IL_HINT_RVA     (IL_TEXT_RVA + 0xb0)
#define IL_DLLNAME_RVA  (IL_TEXT_RVA + 0xc0)
#define IL_ENTRY_RVA    (IL_TEXT_RVA + 0xd0)

/* COMIMAGE_FLAGS_* */
#define IL_ILONLY           0x00000001
#define IL_32BITREQUIRED    0x00000002
#define IL_32BITPREFERRED   0x00020000

/* SECTION_IMAGE_INFORMATION.ImageFlags */
#define IMAGE_FLAG_NATIVE_READY 0x01
#define IMAGE_FLAG_IL_ONLY      0x02
#define IMAGE_FLAG_PREFER32     0x20
#define IMAGE_FLAGS_COMPLUS     (IMAGE_FLAG_NATIVE_READY | IMAGE_FLAG_IL_ONLY | IMAGE_FLAG_PREFER32)

/* SECTION_IMAGE_INFORMATION.LoaderFlags of an image with a COM descriptor */
#define LOADER_FLAGS_COMPLUS    0x00000001

typedef struct _IL_COR20_HEADER
{
    DWORD cb;
    WORD MajorRuntimeVersion;
    WORD MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    DWORD Flags;
    DWORD EntryPointToken;
    IMAGE_DATA_DIRECTORY Resources;
    IMAGE_DATA_DIRECTORY StrongNameSignature;
    IMAGE_DATA_DIRECTORY CodeManagerTable;
    IMAGE_DATA_DIRECTORY VTableFixups;
    IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY ManagedNativeHeader;
} IL_COR20_HEADER;

C_ASSERT(sizeof(IL_COR20_HEADER) == 0x48);

typedef struct _IL_CASE
{
    DWORD CorFlags;
    WORD MajorRuntimeVersion;
    WORD MinorRuntimeVersion;
    DWORD ComSize;
    UCHAR ImageFlags;   /* & IMAGE_FLAGS_COMPLUS; IL_FLAGS_ANY: not checked */
    BOOL Native;        /* a 64-bit process on a 64-bit system */
    ULONG Layout;
    ULONG Extras;       /* IL_EXTRA_* */
} IL_CASE;

/* Directories the PE32 file carries besides the COM descriptor (layouts of the PE32 structures) */
#define IL_EXTRA_LOADCFG    0x1
#define IL_EXTRA_TLS        0x2
#define IL_EXTRA_TLS_CB     0x4
#define IL_LOADCFG_RVA      (IL_TEXT_RVA + 0x100)
#define IL_LOADCFG_SIZE     0x40
#define IL_TLS_RVA          (IL_TEXT_RVA + 0x180)

/* Where the descriptor is. IL_LAYOUT_RAWTAIL: .text has 0x1200 bytes of file data for 0x100 bytes of virtual size,
 * and the descriptor is in the file bytes at RVA 0x2100, which the view maps as .reloc (not as .text's tail).
 * IL_LAYOUT_STRADDLE: .reloc has 0x1200 bytes of file data, and the descriptor is at RVA 0x2ff0, past SizeOfImage.
 * Windows 10 22H2 does not see the descriptor there and starts both under WOW64. */
#define IL_LAYOUT_NORMAL    0
#define IL_LAYOUT_RAWTAIL   1
#define IL_LAYOUT_STRADDLE  2
#define IL_FLAGS_ANY        0xff

static const IL_CASE IlCases[] =
{
    /* AnyCPU, as csc /platform:anycpu writes it, also with a newer runtime version */
    { IL_ILONLY,                                        2, 5, sizeof(IL_COR20_HEADER), 0x03, TRUE },
    { IL_ILONLY,                                        3, 0, sizeof(IL_COR20_HEADER), 0x03, TRUE },
    /* x86 */
    { IL_ILONLY | IL_32BITREQUIRED,                     2, 5, sizeof(IL_COR20_HEADER), 0x02, FALSE },
    /* AnyCPU with Prefer32Bit, and preferring alone */
    { IL_ILONLY | IL_32BITREQUIRED | IL_32BITPREFERRED, 2, 5, sizeof(IL_COR20_HEADER), 0x23, FALSE },
    { IL_ILONLY | IL_32BITPREFERRED,                    2, 5, sizeof(IL_COR20_HEADER), 0x23, FALSE },
    /* Not IL-only (mixed mode) */
    { 0,                                                2, 5, sizeof(IL_COR20_HEADER), 0x00, FALSE },
    { IL_32BITPREFERRED,                                2, 5, sizeof(IL_COR20_HEADER), 0x00, FALSE },
    /* .NET 1.x */
    { IL_ILONLY,                                        2, 0, sizeof(IL_COR20_HEADER), 0x00, FALSE },
    { IL_ILONLY,                                        2, 4, sizeof(IL_COR20_HEADER), 0x00, FALSE },
    /* A directory too small for the descriptor */
    { IL_ILONLY,                                        2, 5, 0x40,                    0x00, FALSE },
    /* A descriptor that the view of the image does not hold, though the file does */
    { IL_ILONLY,                                        2, 5, sizeof(IL_COR20_HEADER), IL_FLAGS_ANY, FALSE, IL_LAYOUT_RAWTAIL },
    { IL_ILONLY,                                        2, 5, sizeof(IL_COR20_HEADER), IL_FLAGS_ANY, FALSE, IL_LAYOUT_STRADDLE },
};

/* A console executable like the one csc writes: the COM descriptor, a metadata root, an import of
 * mscoree!_CorExeMain, the x86 entry stub (jmp [IAT]) and its relocation */
static
BOOL
WriteIlExe(
    _In_ PCWSTR Path,
    _In_ const IL_CASE *Case)
{
    static BYTE Image[IL_FILE_ALIGN + 0x1200 + 0x1200];
    ULONG TextRaw = (Case->Layout == IL_LAYOUT_RAWTAIL) ? 0x1200 : IL_FILE_ALIGN;
    ULONG RelocRaw = (Case->Layout == IL_LAYOUT_STRADDLE) ? 0x1200 : IL_FILE_ALIGN;
    ULONG FileSize = IL_FILE_ALIGN + TextRaw + RelocRaw;
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Image;
    PIMAGE_NT_HEADERS32 Nt = (PIMAGE_NT_HEADERS32)(Image + 0x80);
    PIMAGE_SECTION_HEADER Section;
    PBYTE Text = Image + IL_FILE_ALIGN;
#define IL_AT(Rva) (Text + (Rva) - IL_TEXT_RVA)
    ULONG ComRva = (Case->Layout == IL_LAYOUT_RAWTAIL) ? 0x2100 :
                   (Case->Layout == IL_LAYOUT_STRADDLE) ? 0x2ff0 : IL_COR_RVA;
    IL_COR20_HEADER *Cor = (IL_COR20_HEADER *)((Case->Layout == IL_LAYOUT_STRADDLE) ?
                                                Image + IL_FILE_ALIGN + TextRaw + (ComRva - IL_RELOC_RVA) :
                                                IL_AT(ComRva));
    PBYTE Metadata = IL_AT(IL_META_RVA);
    PIMAGE_IMPORT_DESCRIPTOR Import = (PIMAGE_IMPORT_DESCRIPTOR)IL_AT(IL_IMPORT_RVA);
    PBYTE Entry = IL_AT(IL_ENTRY_RVA);
    PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)(Image + IL_FILE_ALIGN + TextRaw);
    HANDLE File;
    DWORD Written;
    BOOL Ok;

    ZeroMemory(Image, sizeof(Image));
    Dos->e_magic = IMAGE_DOS_SIGNATURE;
    Dos->e_lfanew = 0x80;

    Nt->Signature = IMAGE_NT_SIGNATURE;
    Nt->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    Nt->FileHeader.NumberOfSections = 2;
    Nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    Nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
    Nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    Nt->OptionalHeader.MajorLinkerVersion = 8;
    Nt->OptionalHeader.SizeOfCode = IL_FILE_ALIGN;
    Nt->OptionalHeader.SizeOfInitializedData = IL_FILE_ALIGN;
    Nt->OptionalHeader.AddressOfEntryPoint = IL_ENTRY_RVA;
    Nt->OptionalHeader.BaseOfCode = IL_TEXT_RVA;
    Nt->OptionalHeader.BaseOfData = IL_RELOC_RVA;
    Nt->OptionalHeader.ImageBase = IL_IMAGE_BASE;
    Nt->OptionalHeader.SectionAlignment = 0x1000;
    Nt->OptionalHeader.FileAlignment = IL_FILE_ALIGN;
    Nt->OptionalHeader.MajorOperatingSystemVersion = 4;
    Nt->OptionalHeader.MajorSubsystemVersion = 4;
    Nt->OptionalHeader.SizeOfImage = IL_SIZE_OF_IMAGE;
    Nt->OptionalHeader.SizeOfHeaders = IL_FILE_ALIGN;
    Nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    Nt->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                            IMAGE_DLLCHARACTERISTICS_NO_SEH |
                                            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
    Nt->OptionalHeader.SizeOfStackReserve = 0x100000;
    Nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    Nt->OptionalHeader.SizeOfHeapReserve = 0x100000;
    Nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
    Nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IL_IMPORT_RVA;
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = IL_RELOC_RVA;
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = sizeof(IMAGE_BASE_RELOCATION) + 2 * sizeof(WORD);
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = IL_IAT_RVA;
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 2 * sizeof(DWORD);
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = ComRva;
    Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = Case->ComSize;

    Section = IMAGE_FIRST_SECTION(Nt);
    memcpy(Section[0].Name, ".text", 5);
    Section[0].Misc.VirtualSize = 0x100;
    Section[0].VirtualAddress = IL_TEXT_RVA;
    Section[0].SizeOfRawData = TextRaw;
    Section[0].PointerToRawData = IL_FILE_ALIGN;
    Section[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    memcpy(Section[1].Name, ".reloc", 6);
    Section[1].Misc.VirtualSize = 0x0c;
    Section[1].VirtualAddress = IL_RELOC_RVA;
    Section[1].SizeOfRawData = RelocRaw;
    Section[1].PointerToRawData = IL_FILE_ALIGN + TextRaw;
    Section[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;

    /* IAT and lookup table: _CorExeMain by name */
    *(PDWORD)IL_AT(IL_IAT_RVA) = IL_HINT_RVA;
    *(PDWORD)IL_AT(IL_ILT_RVA) = IL_HINT_RVA;
    memcpy(IL_AT(IL_HINT_RVA) + 2, "_CorExeMain", sizeof("_CorExeMain"));
    memcpy(IL_AT(IL_DLLNAME_RVA), "mscoree.dll", sizeof("mscoree.dll"));
    Import->OriginalFirstThunk = IL_ILT_RVA;
    Import->Name = IL_DLLNAME_RVA;
    Import->FirstThunk = IL_IAT_RVA;

    if (Case->Extras & IL_EXTRA_LOADCFG)
    {
        /* IMAGE_LOAD_CONFIG_DIRECTORY32 of 0x40 bytes; GlobalFlagsSet = FLG_HEAP_ENABLE_TAIL_CHECK */
        PDWORD Config = (PDWORD)IL_AT(IL_LOADCFG_RVA);
        Config[0] = IL_LOADCFG_SIZE;
        Config[4] = 0x10;
        Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = IL_LOADCFG_RVA;
        Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = IL_LOADCFG_SIZE;
    }
    if (Case->Extras & IL_EXTRA_TLS)
    {
        /* IMAGE_TLS_DIRECTORY32: raw data [0x1200, 0x1210), index slot at 0x1090, callbacks at 0x11a0 (one: int3; ret) */
        PDWORD Tls = (PDWORD)IL_AT(IL_TLS_RVA);
        Tls[0] = IL_IMAGE_BASE + IL_TEXT_RVA + 0x200;
        Tls[1] = IL_IMAGE_BASE + IL_TEXT_RVA + 0x210;
        Tls[2] = IL_IMAGE_BASE + IL_TEXT_RVA + 0x90;
        if (Case->Extras & IL_EXTRA_TLS_CB)
        {
            Tls[3] = IL_IMAGE_BASE + IL_TEXT_RVA + 0x1a0;
            ((PDWORD)IL_AT(IL_TEXT_RVA + 0x1a0))[0] = IL_IMAGE_BASE + IL_TEXT_RVA + 0x1c0;
            IL_AT(IL_TEXT_RVA + 0x1c0)[0] = 0xcc;
            IL_AT(IL_TEXT_RVA + 0x1c0)[1] = 0xc3;
        }
        Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = IL_TLS_RVA;
        Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 24;
    }

    Cor->cb = sizeof(*Cor);
    Cor->MajorRuntimeVersion = Case->MajorRuntimeVersion;
    Cor->MinorRuntimeVersion = Case->MinorRuntimeVersion;
    Cor->MetaData.VirtualAddress = IL_META_RVA;
    Cor->MetaData.Size = 0x20;
    Cor->Flags = Case->CorFlags;
    Cor->EntryPointToken = 0x06000001;
    /* "BSJB" metadata root signature, version 1.1 */
    Metadata[0] = 'B'; Metadata[1] = 'S'; Metadata[2] = 'J'; Metadata[3] = 'B';
    Metadata[4] = 1; Metadata[6] = 1;

    /* jmp dword ptr [IAT] */
    Entry[0] = 0xff;
    Entry[1] = 0x25;
    *(PDWORD)(Entry + 2) = IL_IMAGE_BASE + IL_IAT_RVA;

    Reloc->VirtualAddress = IL_TEXT_RVA;
    Reloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + 2 * sizeof(WORD);
    ((PWORD)(Reloc + 1))[0] = (IMAGE_REL_BASED_HIGHLOW << 12) | (IL_ENTRY_RVA + 2 - IL_TEXT_RVA);
#undef IL_AT

    File = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    Ok = WriteFile(File, Image, FileSize, &Written, NULL) && Written == FileSize;
    CloseHandle(File);
    return Ok;
}

static
void
test_SectionInfo(
    _In_ PCWSTR Path,
    _In_ const IL_CASE *Case,
    _In_ ULONG Index)
{
    HANDLE File, Section;
    SECTION_IMAGE_INFORMATION Info;
    NTSTATUS Status;

    File = CreateFileW(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "%lu: CreateFileW failed, error %lu\n", Index, GetLastError());
    if (File == INVALID_HANDLE_VALUE)
        return;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, File);
    CloseHandle(File);
    ok(Status == STATUS_SUCCESS, "%lu: NtCreateSection returned 0x%08lx\n", Index, Status);
    if (!NT_SUCCESS(Status))
        return;

    FillMemory(&Info, sizeof(Info), 0xcc);
    Status = NtQuerySection(Section, SectionImageInformation, &Info, sizeof(Info), NULL);
    ok(Status == STATUS_SUCCESS, "%lu: NtQuerySection returned 0x%08lx\n", Index, Status);
    if (NT_SUCCESS(Status))
    {
        /* The machine stays i386 even when the image runs natively */
        ok(Info.Machine == IMAGE_FILE_MACHINE_I386, "%lu: machine 0x%04x\n", Index, Info.Machine);
        /* Windows relocates the other images that allow it when it creates the section */
        if ((Case->CorFlags & IL_ILONLY) && Case->ComSize >= sizeof(IL_COR20_HEADER))
        {
            ok((ULONG_PTR)Info.TransferAddress == IL_IMAGE_BASE + IL_ENTRY_RVA, "%lu: transfer address %p\n",
               Index, Info.TransferAddress);
        }
        ok(Info.ImageContainsCode == TRUE, "%lu: contains code %u\n", Index, Info.ImageContainsCode);
        if (Case->ImageFlags != IL_FLAGS_ANY)
        {
            ok((Info.ImageFlags & IMAGE_FLAGS_COMPLUS) == Case->ImageFlags, "%lu: image flags 0x%02x, expected 0x%02x\n",
               Index, Info.ImageFlags, Case->ImageFlags);
        }
        else
        {
            /* Not measured; the descriptor is not seen, so it cannot say the image runs natively */
            ok(!(Info.ImageFlags & IMAGE_FLAG_NATIVE_READY), "%lu: image flags 0x%02x\n", Index, Info.ImageFlags);
        }
        /* Any COM descriptor marks the image for the loader */
        ok(Info.LoaderFlags == LOADER_FLAGS_COMPLUS, "%lu: loader flags 0x%lx\n", Index, Info.LoaderFlags);
    }
    NtClose(Section);
}

#ifdef _WIN64
static
BOOL
ReadRemoteHeaders(
    _In_ HANDLE Process,
    _Out_ PVOID *Base,
    _Out_writes_bytes_(IL_FILE_ALIGN) PBYTE Headers)
{
    PROCESS_BASIC_INFORMATION Basic;
    SIZE_T Read;
    NTSTATUS Status;

    *Base = NULL;
    Status = NtQueryInformationProcess(Process, ProcessBasicInformation, &Basic, sizeof(Basic), NULL);
    if (!NT_SUCCESS(Status))
        return FALSE;
    if (!ReadProcessMemory(Process, &Basic.PebBaseAddress->ImageBaseAddress, Base, sizeof(*Base), &Read))
        return FALSE;
    return ReadProcessMemory(Process, *Base, Headers, IL_FILE_ALIGN, &Read);
}

/* Started suspended, the image is still the PE32 file the kernel mapped; its initial thread is to start at its
 * mapped entry stub, which the loader replaces */
static
void
test_SuspendedNative(
    _In_ HANDLE Process,
    _In_ HANDLE Thread)
{
    BYTE Headers[IL_FILE_ALIGN];
    PIMAGE_NT_HEADERS32 Nt32 = (PIMAGE_NT_HEADERS32)(Headers + 0x80);
    PVOID Base;
    CONTEXT Context;

    if (!ReadRemoteHeaders(Process, &Base, Headers))
    {
        ok(0, "cannot read the headers of the process, error %lu\n", GetLastError());
        return;
    }
    ok(Nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC, "suspended: magic 0x%x\n", Nt32->OptionalHeader.Magic);
    ok(Nt32->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32), "suspended: optional header size 0x%x\n",
       Nt32->FileHeader.SizeOfOptionalHeader);

    Context.ContextFlags = CONTEXT_INTEGER;
    ok(GetThreadContext(Thread, &Context), "GetThreadContext failed, error %lu\n", GetLastError());
    ok(Context.Rcx == (ULONG_PTR)Base + IL_ENTRY_RVA, "suspended: start 0x%I64x, image at %p\n", Context.Rcx, Base);
}

/* At the loader's breakpoint the headers are PE32+, the machine still i386; the image is neither relocated (the entry
 * stub still points at the preferred base) nor are its imports snapped */
static
void
test_DebuggedNative(
    _In_ PCWSTR Path)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DEBUG_EVENT Event;
    BYTE Headers[IL_FILE_ALIGN];
    PIMAGE_NT_HEADERS64 Nt64 = (PIMAGE_NT_HEADERS64)(Headers + 0x80);
    PIMAGE_SECTION_HEADER Section;
    PVOID Base;
    DWORD Operand, Iat;
    SIZE_T Read;
    BOOL Breakpoint = FALSE, Exited = FALSE;
    ULONG Events;

    if (!CreateProcessW(Path, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        ok(0, "CreateProcessW (debug) failed, error %lu\n", GetLastError());
        return;
    }

    for (Events = 0; Events < 200 && !Exited; Events++)
    {
        if (!WaitForDebugEvent(&Event, 10000))
        {
            ok(0, "no debug event, error %lu\n", GetLastError());
            break;
        }
        if (Event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && Event.u.CreateProcessInfo.hFile)
            CloseHandle(Event.u.CreateProcessInfo.hFile);
        else if (Event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && Event.u.LoadDll.hFile)
            CloseHandle(Event.u.LoadDll.hFile);
        else if (Event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
            Exited = TRUE;
        else if (Event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && !Breakpoint &&
                 Event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            Breakpoint = TRUE;
            if (ReadRemoteHeaders(ProcessInfo.hProcess, &Base, Headers))
            {
                ok(Nt64->FileHeader.Machine == IMAGE_FILE_MACHINE_I386, "machine 0x%x\n", Nt64->FileHeader.Machine);
                ok(Nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC, "magic 0x%x\n", Nt64->OptionalHeader.Magic);
                ok(Nt64->FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64), "optional header size 0x%x\n",
                   Nt64->FileHeader.SizeOfOptionalHeader);
                ok(Nt64->FileHeader.NumberOfSections == 2, "%u sections\n", Nt64->FileHeader.NumberOfSections);
                if (Nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    ok(Nt64->OptionalHeader.AddressOfEntryPoint == IL_ENTRY_RVA, "entry point 0x%lx\n",
                       Nt64->OptionalHeader.AddressOfEntryPoint);
                    ok(Nt64->OptionalHeader.ImageBase == IL_IMAGE_BASE, "image base 0x%I64x\n",
                       Nt64->OptionalHeader.ImageBase);
                    ok(Nt64->OptionalHeader.SizeOfImage == IL_SIZE_OF_IMAGE, "size of image 0x%lx\n",
                       Nt64->OptionalHeader.SizeOfImage);
                    ok(Nt64->OptionalHeader.SizeOfStackReserve == 0x100000, "stack reserve 0x%I64x\n",
                       Nt64->OptionalHeader.SizeOfStackReserve);
                    ok(Nt64->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI, "subsystem %u\n",
                       Nt64->OptionalHeader.Subsystem);
                    ok(Nt64->OptionalHeader.NumberOfRvaAndSizes == IMAGE_NUMBEROF_DIRECTORY_ENTRIES, "%lu directories\n",
                       Nt64->OptionalHeader.NumberOfRvaAndSizes);
                    ok(Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress == IL_COR_RVA,
                       "COM descriptor at 0x%lx\n",
                       Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
                    Section = IMAGE_FIRST_SECTION(Nt64);
                    ok((PBYTE)Section - Headers == 0x80 + sizeof(IMAGE_NT_HEADERS64), "section table at 0x%Ix\n",
                       (SIZE_T)((PBYTE)Section - Headers));
                    ok(!memcmp(Section[0].Name, ".text", 6), "first section %.8s\n", Section[0].Name);
                    ok(!memcmp(Section[1].Name, ".reloc", 7), "second section %.8s\n", Section[1].Name);
                }
                Operand = Iat = 0;
                ok(ReadProcessMemory(ProcessInfo.hProcess, (PBYTE)Base + IL_ENTRY_RVA + 2, &Operand, sizeof(Operand), &Read),
                   "cannot read the entry stub, error %lu\n", GetLastError());
                ok(Operand == IL_IMAGE_BASE + IL_IAT_RVA, "the entry stub was relocated: 0x%lx, image at %p\n",
                   Operand, Base);
                ok(ReadProcessMemory(ProcessInfo.hProcess, (PBYTE)Base + IL_IAT_RVA, &Iat, sizeof(Iat), &Read),
                   "cannot read the IAT, error %lu\n", GetLastError());
                ok(Iat == IL_HINT_RVA, "the IAT was snapped: 0x%lx\n", Iat);
            }
            else
            {
                ok(0, "cannot read the headers at the breakpoint, error %lu\n", GetLastError());
            }
            TerminateProcess(ProcessInfo.hProcess, 1);
        }
        /* The loader's breakpoint is handled; any other exception goes back to the process */
        ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId,
                           (Event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                            Event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT) ?
                           DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE);
    }
    ok(Breakpoint, "no loader breakpoint\n");
    if (!Exited)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
        DebugActiveProcessStop(ProcessInfo.dwProcessId);
    }
    WaitForSingleObject(ProcessInfo.hProcess, 5000);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}
#endif

/* PE32 directories that the converted header carries on. Measured on Windows 10 22H2 x64 (the image otherwise as case 0):
 * a LOAD_CONFIG directory stays in the converted header and the process reaches the loader's breakpoint; an image with a
 * TLS directory, with or without callbacks, does not start: the process ends with STATUS_INVALID_IMAGE_FORMAT
 * (0xC000007B) before the loader's breakpoint, so no callback runs */
static const IL_CASE IlExtraCases[] =
{
    { IL_ILONLY, 2, 5, sizeof(IL_COR20_HEADER), 0x03, TRUE, IL_LAYOUT_NORMAL, IL_EXTRA_LOADCFG },
    { IL_ILONLY, 2, 5, sizeof(IL_COR20_HEADER), 0x03, TRUE, IL_LAYOUT_NORMAL, IL_EXTRA_TLS },
    { IL_ILONLY, 2, 5, sizeof(IL_COR20_HEADER), 0x03, TRUE, IL_LAYOUT_NORMAL, IL_EXTRA_TLS | IL_EXTRA_TLS_CB },
    { IL_ILONLY, 2, 5, sizeof(IL_COR20_HEADER), 0x03, TRUE, IL_LAYOUT_NORMAL, IL_EXTRA_TLS | IL_EXTRA_TLS_CB | IL_EXTRA_LOADCFG },
};

#ifdef _WIN64
static
void
test_ExtraDirectories(
    _In_ PCWSTR Path,
    _In_ const IL_CASE *Case,
    _In_ ULONG Index)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    DEBUG_EVENT Event;
    BYTE Headers[IL_FILE_ALIGN];
    PIMAGE_NT_HEADERS64 Nt64 = (PIMAGE_NT_HEADERS64)(Headers + 0x80);
    PVOID Base;
    BOOL Breakpoint = FALSE, Exited = FALSE;
    DWORD ExitCode = 0;
    ULONG Events;

    if (!CreateProcessW(Path, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        ok(0, "extra %lu: CreateProcessW (debug) failed, error %lu\n", Index, GetLastError());
        return;
    }
    for (Events = 0; Events < 300 && !Exited; Events++)
    {
        DWORD Continue = DBG_CONTINUE;

        if (!WaitForDebugEvent(&Event, 10000))
        {
            ok(0, "extra %lu: no debug event, error %lu\n", Index, GetLastError());
            break;
        }
        if (Event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && Event.u.CreateProcessInfo.hFile)
            CloseHandle(Event.u.CreateProcessInfo.hFile);
        else if (Event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && Event.u.LoadDll.hFile)
            CloseHandle(Event.u.LoadDll.hFile);
        else if (Event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            Exited = TRUE;
            ExitCode = Event.u.ExitProcess.dwExitCode;
        }
        else if (Event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            if (!Breakpoint && Event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
            {
                Breakpoint = TRUE;
                if (ReadRemoteHeaders(ProcessInfo.hProcess, &Base, Headers) &&
                    Nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    ok(Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress ==
                           ((Case->Extras & IL_EXTRA_LOADCFG) ? IL_LOADCFG_RVA : 0),
                       "extra %lu: LOAD_CONFIG at 0x%lx\n", Index,
                       Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
                    ok(Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size ==
                           ((Case->Extras & IL_EXTRA_LOADCFG) ? IL_LOADCFG_SIZE : 0),
                       "extra %lu: LOAD_CONFIG size 0x%lx\n", Index,
                       Nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
                }
                else
                {
                    ok(0, "extra %lu: no PE32+ headers at the breakpoint\n", Index);
                }
                TerminateProcess(ProcessInfo.hProcess, 1);
            }
            else if (Event.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT)
            {
                Continue = DBG_EXCEPTION_NOT_HANDLED;
            }
        }
        ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, Continue);
    }
    if (Case->Extras & IL_EXTRA_TLS)
    {
        ok(!Breakpoint, "extra %lu: the loader's breakpoint was reached\n", Index);
        ok(Exited && ExitCode == STATUS_INVALID_IMAGE_FORMAT, "extra %lu: exited %d with 0x%08lx\n", Index, Exited, ExitCode);
    }
    else
    {
        ok(Breakpoint, "extra %lu: no loader breakpoint\n", Index);
    }
    if (!Exited)
    {
        TerminateProcess(ProcessInfo.hProcess, 1);
        DebugActiveProcessStop(ProcessInfo.dwProcessId);
    }
    WaitForSingleObject(ProcessInfo.hProcess, 5000);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}
#endif

static
BOOL
HaveWow64(VOID)
{
    WCHAR Path[MAX_PATH];

    GetWindowsDirectoryW(Path, _countof(Path));
    StringCchCatW(Path, _countof(Path), L"\\SysWOW64\\ntdll.dll");
    return GetFileAttributesW(Path) != INVALID_FILE_ATTRIBUTES;
}

static
void
test_ProcessBitness(
    _In_ PCWSTR Path,
    _In_ const IL_CASE *Case,
    _In_ ULONG Index,
    _In_ BOOL System64)
{
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    BOOL Wow64 = -1, Expected;

    if (!CreateProcessW(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
                        &StartupInfo, &ProcessInfo))
    {
        /* A 64-bit system without WOW64 runs no 32-bit process */
        if (System64 && !Case->Native && GetLastError() == ERROR_BAD_EXE_FORMAT && !HaveWow64())
        {
            skip("%lu: no WOW64\n", Index);
            return;
        }
        ok(0, "%lu: CreateProcessW failed, error %lu\n", Index, GetLastError());
        return;
    }

    Expected = System64 && !Case->Native;
    ok(IsWow64Process(ProcessInfo.hProcess, &Wow64), "%lu: IsWow64Process failed, error %lu\n", Index, GetLastError());
    ok(Wow64 == Expected, "%lu: WOW64 %d, expected %d\n", Index, Wow64, Expected);

#ifdef _WIN64
    if (Case->Native && !Wow64)
        test_SuspendedNative(ProcessInfo.hProcess, ProcessInfo.hThread);
#endif

    TerminateProcess(ProcessInfo.hProcess, 1);
    WaitForSingleObject(ProcessInfo.hProcess, 5000);
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
}

/* The image of a process that just ended can stay in use for a moment */
static
void
DeleteIlExe(
    _In_ PCWSTR Path,
    _In_ ULONG Index)
{
    ULONG Try;

    for (Try = 0; Try < 50; Try++)
    {
        if (DeleteFileW(Path))
            return;
        Sleep(100);
    }
    ok(0, "%lu: DeleteFileW failed, error %lu\n", Index, GetLastError());
}

START_TEST(CreateProcessILOnly)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH];
    BOOL System64 = FALSE;
    ULONG i;

#ifdef _WIN64
    System64 = TRUE;
#else
    IsWow64Process(GetCurrentProcess(), &System64);
#endif

    GetTempPathW(_countof(Dir), Dir);
    for (i = 0; i < _countof(IlCases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%silexe_%lu_%lu.exe", Dir, GetCurrentProcessId(), i);
        if (!WriteIlExe(Path, &IlCases[i]))
        {
            ok(0, "%lu: cannot write %ls, error %lu\n", i, Path, GetLastError());
            continue;
        }
        test_SectionInfo(Path, &IlCases[i], i);
        test_ProcessBitness(Path, &IlCases[i], i, System64);
#ifdef _WIN64
        if (i == 0)
            test_DebuggedNative(Path);
#endif
        DeleteIlExe(Path, i);
    }

#ifdef _WIN64
    for (i = 0; i < _countof(IlExtraCases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%silexe_%lu_x%lu.exe", Dir, GetCurrentProcessId(), i);
        if (!WriteIlExe(Path, &IlExtraCases[i]))
        {
            ok(0, "extra %lu: cannot write %ls, error %lu\n", i, Path, GetLastError());
            continue;
        }
        test_ExtraDirectories(Path, &IlExtraCases[i], i);
        DeleteIlExe(Path, 100 + i);
    }
#endif
}
