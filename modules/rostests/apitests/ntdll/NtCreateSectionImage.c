/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Image section creation from crafted PE headers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

/*
 * Every case writes a small PE file and creates a SEC_IMAGE section for it.
 * The base image is a DLL with a header page and two sections:
 *   .text  RVA 0x1000, VirtualSize 0x100, raw 0x200 bytes at 0x200
 *   .data  RVA 0x2000, VirtualSize 0x100, raw 0x200 bytes at 0x400
 * with SizeOfImage 0x3000, SizeOfHeaders 0x200, FileAlignment 0x200 and
 * SectionAlignment 0x1000. Each case changes one header property, plus the
 * SizeOfImage or entry point that has to follow it.
 */

#define IMG_FILE_SIZE   0x2000
#define IMG_NT_OFFSET   0x40
#define IMG_OPT_OFFSET  (NtOffset + 4 + sizeof(IMAGE_FILE_HEADER))

static BYTE Image[IMG_FILE_SIZE];
static ULONG NtOffset = IMG_NT_OFFSET;
static ULONG ImageFileSize = IMG_FILE_SIZE;
static BOOL Image64;
static BOOL KernelIs64;
static BOOL ProcessIsWow64;

#ifdef _WIN64
#define NATIVE_PE64 TRUE
#else
#define NATIVE_PE64 FALSE
#endif

static PIMAGE_FILE_HEADER FileHdr(void)
{
    return (PIMAGE_FILE_HEADER)(Image + NtOffset + 4);
}

static PIMAGE_OPTIONAL_HEADER32 Opt32(void)
{
    return (PIMAGE_OPTIONAL_HEADER32)(Image + IMG_OPT_OFFSET);
}

static PIMAGE_OPTIONAL_HEADER64 Opt64(void)
{
    return (PIMAGE_OPTIONAL_HEADER64)(Image + IMG_OPT_OFFSET);
}

static PIMAGE_SECTION_HEADER Sec(ULONG Index)
{
    return (PIMAGE_SECTION_HEADER)(Image + IMG_OPT_OFFSET + FileHdr()->SizeOfOptionalHeader) + Index;
}

#define SET_OPT(Field, Value) \
    do { if (Image64) Opt64()->Field = (Value); else Opt32()->Field = (Value); } while (0)

static void SetSection(ULONG Index, const char *Name, DWORD Rva, DWORD VirtualSize,
                       DWORD RawOffset, DWORD RawSize, DWORD Characteristics)
{
    PIMAGE_SECTION_HEADER Section = Sec(Index);

    ZeroMemory(Section, sizeof(*Section));
    memcpy(Section->Name, Name, strlen(Name) < IMAGE_SIZEOF_SHORT_NAME ? strlen(Name) : IMAGE_SIZEOF_SHORT_NAME);
    Section->VirtualAddress = Rva;
    Section->Misc.VirtualSize = VirtualSize;
    Section->PointerToRawData = RawOffset;
    Section->SizeOfRawData = RawSize;
    Section->Characteristics = Characteristics;
}

#define SCN_TEXT (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)
#define SCN_RDATA (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ)
#define SCN_DATA (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)

static void BuildImage(BOOL Pe64, WORD Machine, BOOL HasCode, BOOL IsDll)
{
    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Image;
    PIMAGE_FILE_HEADER File;

    ZeroMemory(Image, sizeof(Image));
    Image64 = Pe64;

    Dos->e_magic = IMAGE_DOS_SIGNATURE;
    Dos->e_lfanew = NtOffset;
    *(DWORD *)(Image + NtOffset) = IMAGE_NT_SIGNATURE;

    File = FileHdr();
    File->Machine = Machine;
    File->NumberOfSections = 2;
    File->SizeOfOptionalHeader = Pe64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    File->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                            (Pe64 ? IMAGE_FILE_LARGE_ADDRESS_AWARE : IMAGE_FILE_32BIT_MACHINE) |
                            (IsDll ? IMAGE_FILE_DLL : 0);

    SET_OPT(Magic, Pe64 ? IMAGE_NT_OPTIONAL_HDR64_MAGIC : IMAGE_NT_OPTIONAL_HDR32_MAGIC);
    SET_OPT(MajorLinkerVersion, 1);
    SET_OPT(SizeOfCode, HasCode ? 0x200 : 0);
    SET_OPT(SizeOfInitializedData, HasCode ? 0x200 : 0x400);
    SET_OPT(AddressOfEntryPoint, HasCode ? 0x1000 : 0);
    SET_OPT(BaseOfCode, 0x1000);
    SET_OPT(ImageBase, IsDll ? 0x10000000 : 0x00400000);
    SET_OPT(SectionAlignment, 0x1000);
    SET_OPT(FileAlignment, 0x200);
    SET_OPT(MajorOperatingSystemVersion, 4);
    SET_OPT(MajorSubsystemVersion, 4);
    SET_OPT(SizeOfImage, 0x3000);
    SET_OPT(SizeOfHeaders, 0x200);
    SET_OPT(Subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI);
    SET_OPT(SizeOfStackReserve, 0x100000);
    SET_OPT(SizeOfStackCommit, 0x1000);
    SET_OPT(SizeOfHeapReserve, 0x100000);
    SET_OPT(SizeOfHeapCommit, 0x1000);
    SET_OPT(NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    if (!Pe64)
        Opt32()->BaseOfData = 0x2000;

    SetSection(0, ".text", 0x1000, 0x100, 0x200, 0x200, HasCode ? SCN_TEXT : SCN_RDATA);
    SetSection(1, ".data", 0x2000, 0x100, 0x400, 0x200, SCN_DATA);

    /* ret */
    if (ImageFileSize > 0x200)
        Image[0x200] = 0xC3;
}

static BOOL WriteImage(PCWSTR Path)
{
    HANDLE hFile;
    DWORD Written;
    BOOL Ret;

    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(hFile, Image, ImageFileSize, &Written, NULL) && Written == ImageFileSize;
    CloseHandle(hFile);
    return Ret;
}

static WCHAR TempDir[MAX_PATH];

static NTSTATUS CreateImageSection(PCSTR Name)
{
    WCHAR Path[MAX_PATH];
    HANDLE hFile, hSection;
    NTSTATUS Status;

    if (!GetTempFileNameW(TempDir, L"ncs", 0, Path))
    {
        skip("%s: GetTempFileNameW failed with %lu\n", Name, GetLastError());
        return STATUS_UNSUCCESSFUL;
    }
    if (!WriteImage(Path))
    {
        skip("%s: cannot write %ls, error %lu\n", Name, Path, GetLastError());
        DeleteFileW(Path);
        return STATUS_UNSUCCESSFUL;
    }

    hFile = CreateFileW(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        skip("%s: cannot open %ls, error %lu\n", Name, Path, GetLastError());
        DeleteFileW(Path);
        return STATUS_UNSUCCESSFUL;
    }

    hSection = NULL;
    Status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_QUERY, NULL, NULL,
                             PAGE_READONLY, SEC_IMAGE, hFile);
    if (NT_SUCCESS(Status))
        NtClose(hSection);
    CloseHandle(hFile);
    DeleteFileW(Path);

    trace("CASE %s pe%u machine %04x: %08lx\n", Name, Image64 ? 64 : 32, FileHdr()->Machine, Status);
    return Status;
}

/* For a refused image, the loader and CreateProcess must refuse it too */
static void CheckRefusedElsewhere(PCSTR Name, BOOL AsExe)
{
    WCHAR Path[MAX_PATH];
    HMODULE hMod;
    STARTUPINFOW StartupInfo = { sizeof(StartupInfo) };
    PROCESS_INFORMATION ProcessInfo;
    BOOL Ret;

    if (!GetTempFileNameW(TempDir, L"ncr", 0, Path))
    {
        skip("%s: GetTempFileNameW failed with %lu\n", Name, GetLastError());
        return;
    }
    if (!WriteImage(Path))
    {
        skip("%s: cannot write %ls, error %lu\n", Name, Path, GetLastError());
        DeleteFileW(Path);
        return;
    }

    if (AsExe)
    {
        SetLastError(0xdeadbeef);
        Ret = CreateProcessW(Path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL,
                             &StartupInfo, &ProcessInfo);
        ok(!Ret, "%s: CreateProcessW succeeded\n", Name);
        if (Ret)
        {
            TerminateProcess(ProcessInfo.hProcess, 1);
            WaitForSingleObject(ProcessInfo.hProcess, 10000);
            CloseHandle(ProcessInfo.hThread);
            CloseHandle(ProcessInfo.hProcess);
        }
        else
        {
            ok(GetLastError() == ERROR_BAD_EXE_FORMAT, "%s: CreateProcessW error %lu\n", Name, GetLastError());
        }
    }
    else
    {
        SetLastError(0xdeadbeef);
        hMod = LoadLibraryExW(Path, NULL, DONT_RESOLVE_DLL_REFERENCES);
        ok(hMod == NULL, "%s: LoadLibraryExW returned %p\n", Name, hMod);
        if (hMod)
            FreeLibrary(hMod);
        else
            ok(GetLastError() == ERROR_BAD_EXE_FORMAT, "%s: LoadLibraryExW error %lu\n", Name, GetLastError());
    }

    ok(DeleteFileW(Path), "%s: DeleteFileW error %lu\n", Name, GetLastError());
}

/* MACHINE TYPES ************************************************************/

static const WORD Machines[] =
{
    IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_IA64,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARMNT,
    IMAGE_FILE_MACHINE_ARM,
    IMAGE_FILE_MACHINE_THUMB,
    IMAGE_FILE_MACHINE_R4000,
    IMAGE_FILE_MACHINE_ALPHA,
    IMAGE_FILE_MACHINE_POWERPC,
    IMAGE_FILE_MACHINE_EBC,
    IMAGE_FILE_MACHINE_UNKNOWN,
    0xdead,
};

/*
 * Where Windows Server 2008 R2 (NT 6.1) and Windows 10 22H2 differ, ReactOS
 * takes the result that accepts the image, so that an image either one maps
 * keeps working (RosLikeWin10 overrides that). NT 6.1 and older are held to
 * the 2008 R2 result, Windows 10 22H2 to its own, and the versions between
 * and after, which were not measured, may give either result.
 */
static BOOL IsExpectedStatus(NTSTATUS Status, NTSTATUS Win7, NTSTATUS Win10, BOOLEAN RosLikeWin10)
{
    if (Win7 == Win10)
        return Status == Win7;
    if (is_reactos())
    {
        if (RosLikeWin10)
            return Status == Win10;
        return Status == ((Win7 == STATUS_SUCCESS || Win10 == STATUS_SUCCESS) ? STATUS_SUCCESS : Win7);
    }
    if (GetNTVersion() <= _WIN32_WINNT_WIN7)
        return Status == Win7;
    if (GetNTVersion() == 0x0A00 && *(ULONG *)(KUSER_SHARED_DATA_UMPTR + 0x0260) == 19045)
        return Status == Win10;
    return Status == Win7 || Status == Win10;
}

/*
 * Measured on Windows Server 2008 R2 and Windows 10 22H2, x64 and WOW64:
 * a PE32 image must be I386 and a PE32+ image must be AMD64, with or without
 * code; 2008 R2 also takes an IA64 PE32+ image. A 32-bit kernel refuses every
 * PE32+ image with STATUS_INVALID_IMAGE_WIN_64 before it looks at the machine
 * (the Wine loader tests record that for 32-bit Windows).
 */
static BOOL IsExpectedMachineStatus(NTSTATUS Status, BOOL Pe64, WORD Machine)
{
    if (Pe64)
    {
        if (!KernelIs64)
            return Status == STATUS_INVALID_IMAGE_WIN_64;
        if (Machine == IMAGE_FILE_MACHINE_AMD64)
            return Status == STATUS_SUCCESS;
        if (Machine == IMAGE_FILE_MACHINE_IA64)
            return IsExpectedStatus(Status, STATUS_SUCCESS, STATUS_INVALID_IMAGE_FORMAT, FALSE);
        return Status == STATUS_INVALID_IMAGE_FORMAT;
    }
    return Status == ((Machine == IMAGE_FILE_MACHINE_I386) ? STATUS_SUCCESS : STATUS_INVALID_IMAGE_FORMAT);
}

static void Test_Machines(void)
{
    ULONG i, Bits, Code;
    NTSTATUS Status;
    char Name[64];

    for (Bits = 0; Bits < 2; Bits++)
    {
        for (i = 0; i < ARRAYSIZE(Machines); i++)
        {
            for (Code = 0; Code < 2; Code++)
            {
                StringCbPrintfA(Name, sizeof(Name), "machine-%s-%04x-%s",
                                Bits ? "pe64" : "pe32", Machines[i], Code ? "code" : "nocode");
                BuildImage(Bits != 0, Machines[i], Code != 0, TRUE);
                Status = CreateImageSection(Name);
                ok(IsExpectedMachineStatus(Status, Bits != 0, Machines[i]), "%s: status %08lx\n", Name, Status);
            }
        }
    }

    /* The loader and CreateProcess of the native bitness refuse them too */
    BuildImage(NATIVE_PE64, 0xdead, TRUE, TRUE);
    CheckRefusedElsewhere("load-machine-dead", FALSE);
    BuildImage(NATIVE_PE64, IMAGE_FILE_MACHINE_UNKNOWN, TRUE, TRUE);
    CheckRefusedElsewhere("load-machine-unknown", FALSE);
    BuildImage(NATIVE_PE64, NATIVE_PE64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64, TRUE, TRUE);
    CheckRefusedElsewhere("load-machine-other-bitness", FALSE);
    BuildImage(NATIVE_PE64, 0xdead, TRUE, FALSE);
    CheckRefusedElsewhere("exe-machine-dead", TRUE);
    BuildImage(NATIVE_PE64, IMAGE_FILE_MACHINE_UNKNOWN, TRUE, FALSE);
    CheckRefusedElsewhere("exe-machine-unknown", TRUE);
    BuildImage(NATIVE_PE64, NATIVE_PE64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64, TRUE, FALSE);
    CheckRefusedElsewhere("exe-machine-other-bitness", TRUE);
}

/* LAYOUT *******************************************************************/

static void L_None(void) { }
static void L_SizeAtLastRva(void) { SET_OPT(SizeOfImage, 0x2000); }
static void L_SizeInLast(void) { SET_OPT(SizeOfImage, 0x2001); }
static void L_SizeEndMinus1(void) { SET_OPT(SizeOfImage, 0x2FFF); }
static void L_SizeLarge(void) { SET_OPT(SizeOfImage, 0x10000); }
static void L_SizeZero(void) { SET_OPT(SizeOfImage, 0); }
static void L_SizeHeadersOnly(void) { SET_OPT(SizeOfImage, 0x1000); }
static void L_SizeLastVirtual(void) { SET_OPT(SizeOfImage, 0x2100); }
static void L_RvaUnaligned(void) { Sec(1)->VirtualAddress = 0x2200; SET_OPT(SizeOfImage, 0x4000); }
static void L_GapFirst(void)
{
    Sec(0)->VirtualAddress = 0x2000;
    Sec(1)->VirtualAddress = 0x3000;
    SET_OPT(AddressOfEntryPoint, 0x2000);
    SET_OPT(SizeOfImage, 0x4000);
}
static void L_GapBetween(void) { Sec(1)->VirtualAddress = 0x3000; SET_OPT(SizeOfImage, 0x4000); }
static void L_Overlap(void) { Sec(1)->VirtualAddress = 0x1000; }
static void L_OutOfOrder(void)
{
    Sec(0)->VirtualAddress = 0x2000;
    Sec(1)->VirtualAddress = 0x1000;
    SET_OPT(AddressOfEntryPoint, 0x2000);
}
static void L_FirstRvaZero(void)
{
    Sec(0)->VirtualAddress = 0;
    SET_OPT(AddressOfEntryPoint, 0);
}
static void DebugLinkFirst(DWORD Rva)
{
    FileHdr()->NumberOfSections = 3;
    SetSection(2, ".data", 0x2000, 0x100, 0x400, 0x200, SCN_DATA);
    SetSection(1, ".text", 0x1000, 0x100, 0x200, 0x200, SCN_TEXT);
    SetSection(0, ".gnu_debuglink", Rva, 0x38, 0x600, 0x200,
               IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ);
}
static void L_DebugLinkFirstC0(void) { DebugLinkFirst(0xC0000000); }
static void L_DebugLinkFirstFFC(void) { DebugLinkFirst(0xFFC00000); }
static void L_DebugLinkLast(void)
{
    FileHdr()->NumberOfSections = 3;
    SetSection(2, ".gnu_debuglink", 0xC0000000, 0x38, 0x600, 0x200,
               IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ);
}
static void L_RawPastEof(void) { Sec(1)->SizeOfRawData = 0x10000; Sec(1)->Misc.VirtualSize = 0x10000; SET_OPT(SizeOfImage, 0x12000); }
static void L_RawOffsetPastEof(void) { Sec(1)->PointerToRawData = 0x10000; }
static void L_RawOverVirtual(void) { Sec(1)->SizeOfRawData = 0x400; }
static void L_RawOverAlignedVirtual(void) { Sec(1)->SizeOfRawData = 0x1200; }
static void L_RawOffsetUnaligned(void) { Sec(1)->PointerToRawData = 0x410; }
static void L_RawSizeUnaligned(void) { Sec(1)->SizeOfRawData = 0x1F0; }
static void L_SectAlignBelowFile(void) { SET_OPT(FileAlignment, 0x2000); }
static void L_SectAlignNotPow2(void)
{
    SET_OPT(SectionAlignment, 0x3000);
    Sec(0)->VirtualAddress = 0x3000;
    Sec(1)->VirtualAddress = 0x6000;
    SET_OPT(AddressOfEntryPoint, 0x3000);
    SET_OPT(SizeOfImage, 0x9000);
}
static void L_SectAlignZero(void) { SET_OPT(SectionAlignment, 0); }
static void L_FileAlignZero(void) { SET_OPT(FileAlignment, 0); }
static void L_FileAlignNotPow2(void) { SET_OPT(FileAlignment, 0x300); }
static void L_FileAlignSmall(void) { SET_OPT(FileAlignment, 0x100); }
static void L_FileAlignLarge(void) { SET_OPT(SectionAlignment, 0x20000); SET_OPT(FileAlignment, 0x20000);
                                     Sec(0)->VirtualAddress = 0x20000; Sec(1)->VirtualAddress = 0x40000;
                                     SET_OPT(AddressOfEntryPoint, 0x20000); SET_OPT(SizeOfImage, 0x60000); }
static void LowAlign(DWORD SecondRva)
{
    SET_OPT(SectionAlignment, 0x200);
    SET_OPT(FileAlignment, 0x200);
    Sec(0)->VirtualAddress = 0x200;
    Sec(1)->VirtualAddress = SecondRva;
    SET_OPT(AddressOfEntryPoint, 0x200);
    SET_OPT(SizeOfImage, SecondRva + 0x200);
}
static void L_LowAlign(void) { LowAlign(0x400); }
static void L_LowAlignRvaNotRaw(void) { LowAlign(0x600); }
static void L_LowAlignFileDiffers(void) { LowAlign(0x400); SET_OPT(FileAlignment, 0x100); }
static void L_HeadersSmall(void) { SET_OPT(SizeOfHeaders, 0x100); }
static void L_HeadersZero(void) { SET_OPT(SizeOfHeaders, 0); }
static void L_HeadersPastFirstRva(void) { SET_OPT(SizeOfHeaders, 0x1200); }
static void L_HeadersUnaligned(void) { SET_OPT(SizeOfHeaders, 0x1F8); }
static void L_BaseUnaligned(void) { SET_OPT(ImageBase, 0x10001000); }
static void L_BaseZero(void) { SET_OPT(ImageBase, 0); }
static void L_NoSections(void) { FileHdr()->NumberOfSections = 0; SET_OPT(AddressOfEntryPoint, 0); SET_OPT(SizeOfImage, 0x1000); }
static void L_ManySections(void) { FileHdr()->NumberOfSections = 97; }
static void L_VirtualZeroRawZero(void) { Sec(1)->Misc.VirtualSize = 0; Sec(1)->SizeOfRawData = 0; Sec(1)->PointerToRawData = 0; }
static void L_VirtualZero(void) { Sec(1)->Misc.VirtualSize = 0; }
static void L_EntryOutside(void) { SET_OPT(AddressOfEntryPoint, 0x12345678); }
static void L_Bss(void) { Sec(1)->PointerToRawData = 0; Sec(1)->SizeOfRawData = 0;
                          Sec(1)->Characteristics = IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE; }
static void L_Cor20IlOnly(void)
{
    IMAGE_DATA_DIRECTORY Dir = { 0x2000, sizeof(IMAGE_COR20_HEADER) };
    IMAGE_COR20_HEADER *Cor = (IMAGE_COR20_HEADER *)(Image + 0x400);

    Cor->cb = sizeof(*Cor);
    Cor->MajorRuntimeVersion = 2;
    Cor->MinorRuntimeVersion = 5;
    Cor->Flags = COMIMAGE_FLAGS_ILONLY;
    if (Image64)
        Opt64()->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] = Dir;
    else
        Opt32()->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] = Dir;
}

static void L_SizeEndPlus1(void) { SET_OPT(SizeOfImage, 0x3001); }
static void L_SizeNextPage(void) { SET_OPT(SizeOfImage, 0x4000); }
static void L_FileAlign80(void) { SET_OPT(FileAlignment, 0x80); }
static void L_FileAlign400(void)
{
    SET_OPT(FileAlignment, 0x400);
    SET_OPT(SizeOfHeaders, 0x400);
    Sec(0)->PointerToRawData = 0x400; Sec(0)->SizeOfRawData = 0x400;
    Sec(1)->PointerToRawData = 0x800; Sec(1)->SizeOfRawData = 0x400;
}
static void L_FileAlign1000(void)
{
    SET_OPT(FileAlignment, 0x1000);
    SET_OPT(SizeOfHeaders, 0x1000);
    Sec(0)->PointerToRawData = 0x1000; Sec(0)->SizeOfRawData = 0x1000;
    Sec(1)->PointerToRawData = 0; Sec(1)->SizeOfRawData = 0;
}
static void LowAlignAt(DWORD Align)
{
    SET_OPT(SectionAlignment, Align);
    SET_OPT(FileAlignment, Align);
    SET_OPT(SizeOfHeaders, 0x200);
    Sec(0)->VirtualAddress = 0x200; Sec(0)->PointerToRawData = 0x200; Sec(0)->SizeOfRawData = 0x200; Sec(0)->Misc.VirtualSize = 0x200;
    Sec(1)->VirtualAddress = 0x400; Sec(1)->PointerToRawData = 0x400; Sec(1)->SizeOfRawData = 0x200; Sec(1)->Misc.VirtualSize = 0x200;
    SET_OPT(AddressOfEntryPoint, 0x200);
    SET_OPT(SizeOfImage, 0x600);
}
static void L_LowAlign100(void) { LowAlignAt(0x100); }
static void L_LowAlign20(void) { LowAlignAt(0x20); }
static void L_LowAlignNoSections(void)
{
    LowAlign(0x400);
    FileHdr()->NumberOfSections = 0;
    SET_OPT(AddressOfEntryPoint, 0);
    SET_OPT(SizeOfImage, 0x200);
}
static void L_NoSectionsHeaderPage(void)
{
    FileHdr()->NumberOfSections = 0;
    SET_OPT(AddressOfEntryPoint, 0);
    SET_OPT(SizeOfHeaders, 0x1000);
    SET_OPT(SizeOfImage, 0x1000);
}
static void L_RawPastEofSmall(void) { Sec(1)->SizeOfRawData = 0x1E00; Sec(1)->Misc.VirtualSize = 0x2000; SET_OPT(SizeOfImage, 0x4000); }
static void L_RawFirstPastEof(void) { Sec(0)->PointerToRawData = 0x1F00; }
static void L_RawOffsetPastEofSize0(void) { Sec(1)->PointerToRawData = 0x10000; Sec(1)->SizeOfRawData = 0; }

static void L_RawVirtualLarge(void) { Sec(1)->Misc.VirtualSize = 0x3000; SET_OPT(SizeOfImage, 0x5000); }
static void L_RawFirstPastEofFull(void) { Sec(0)->PointerToRawData = 0x1F00; Sec(0)->Misc.VirtualSize = 0x200; }
static void L_RawFirstPastEofVirtual(void) { Sec(0)->PointerToRawData = 0x1F00; Sec(0)->Misc.VirtualSize = 0x101; }
static void L_RawEndsAtEof(void) { Sec(1)->PointerToRawData = 0x1E00; }
static void L_RawPastEofVirtualZero(void) { Sec(1)->PointerToRawData = 0x1F00; Sec(1)->Misc.VirtualSize = 0; }
static void L_RawLastPastEofClipped(void) { Sec(1)->PointerToRawData = 0x1F00; Sec(1)->SizeOfRawData = 0x400; }

static void L_RawMiddlePastEof(void)
{
    FileHdr()->NumberOfSections = 3;
    SetSection(2, ".data", 0x3000, 0x100, 0x400, 0x200, SCN_DATA);
    SetSection(1, ".rdata", 0x2000, 0x100, 0x1F00, 0x200, SCN_RDATA);
    SET_OPT(SizeOfImage, 0x4000);
}
static void L_RawPastEofBeforeBss(void)
{
    FileHdr()->NumberOfSections = 3;
    Sec(1)->PointerToRawData = 0x1F00;
    SetSection(2, ".bss", 0x3000, 0x100, 0, 0, IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    SET_OPT(SizeOfImage, 0x4000);
}

static void L_RawLastPastEof(void) { Sec(1)->PointerToRawData = 0x1F00; }

/* The tiny image of the Wine loader tests: the PE header at offset 4, where
 * SectionAlignment doubles as e_lfanew, no sections and SizeOfImage 0x40 */
static void TinyNoSections(DWORD FileSize)
{
    BOOL Pe64 = Image64;
    WORD Machine = FileHdr()->Machine;

    NtOffset = 4;
    ImageFileSize = FileSize;
    BuildImage(Pe64, Machine, FALSE, TRUE);
    FileHdr()->NumberOfSections = 0;
    SET_OPT(SectionAlignment, 4);
    SET_OPT(FileAlignment, 4);
    SET_OPT(SizeOfHeaders, 0);
    SET_OPT(SizeOfImage, 0x40);
}
static void L_Tiny268(void) { TinyNoSections(268); }
static void L_Tiny200(void) { TinyNoSections(0x200); }
static void L_Tiny1000(void) { TinyNoSections(0x1000); }
static void L_Tiny2000(void) { TinyNoSections(0x2000); }

typedef struct _LAYOUT_CASE
{
    const char *Name;
    void (*Mutate)(void);
    NTSTATUS Win7;
    NTSTATUS Win10;
    BOOLEAN RosLikeWin10;
} LAYOUT_CASE;

#define IMG_OK STATUS_SUCCESS
#define IMG_BAD STATUS_INVALID_IMAGE_FORMAT

/*
 * Win7 is Windows Server 2008 R2, Win10 is Windows 10 22H2; both measured as
 * x64 and WOW64. They differ in two places: 2008 R2 wants SizeOfImage to end
 * with the last section (rounded up to SectionAlignment), where Windows 10
 * also takes a larger one, and Windows 10 refuses the tiny image without
 * sections that 2008 R2 maps. ReactOS refuses the tiny image too
 * (RosLikeWin10).
 */
static const LAYOUT_CASE LayoutCases[] =
{
    { "base", L_None, IMG_OK, IMG_OK },
    { "size-at-last-rva", L_SizeAtLastRva, IMG_BAD, IMG_BAD },
    { "size-in-last", L_SizeInLast, IMG_OK, IMG_OK },
    { "size-end-minus-1", L_SizeEndMinus1, IMG_OK, IMG_OK },
    { "size-last-virtual", L_SizeLastVirtual, IMG_OK, IMG_OK },
    { "size-large", L_SizeLarge, IMG_BAD, IMG_OK },
    { "size-zero", L_SizeZero, IMG_BAD, IMG_BAD },
    { "size-headers-only", L_SizeHeadersOnly, IMG_BAD, IMG_BAD },
    { "rva-unaligned", L_RvaUnaligned, IMG_BAD, IMG_BAD },
    { "gap-first", L_GapFirst, IMG_BAD, IMG_BAD },
    { "gap-between", L_GapBetween, IMG_BAD, IMG_BAD },
    { "overlap", L_Overlap, IMG_BAD, IMG_BAD },
    { "out-of-order", L_OutOfOrder, IMG_BAD, IMG_BAD },
    { "first-rva-zero", L_FirstRvaZero, IMG_BAD, IMG_BAD },
    { "debuglink-first-c0", L_DebugLinkFirstC0, IMG_BAD, IMG_BAD },
    { "debuglink-first-ffc", L_DebugLinkFirstFFC, IMG_BAD, IMG_BAD },
    { "debuglink-last", L_DebugLinkLast, IMG_BAD, IMG_BAD },
    { "raw-past-eof", L_RawPastEof, IMG_BAD, IMG_BAD },
    { "raw-offset-past-eof", L_RawOffsetPastEof, IMG_BAD, IMG_BAD },
    { "raw-over-virtual", L_RawOverVirtual, IMG_OK, IMG_OK },
    { "raw-over-aligned-virt", L_RawOverAlignedVirtual, IMG_OK, IMG_OK },
    { "raw-offset-unaligned", L_RawOffsetUnaligned, IMG_OK, IMG_OK },
    { "raw-size-unaligned", L_RawSizeUnaligned, IMG_OK, IMG_OK },
    { "salign-below-falign", L_SectAlignBelowFile, IMG_BAD, IMG_BAD },
    { "salign-not-pow2", L_SectAlignNotPow2, IMG_BAD, IMG_BAD },
    { "salign-zero", L_SectAlignZero, IMG_BAD, IMG_BAD },
    { "falign-zero", L_FileAlignZero, IMG_BAD, IMG_BAD },
    { "falign-not-pow2", L_FileAlignNotPow2, IMG_BAD, IMG_BAD },
    { "falign-small", L_FileAlignSmall, IMG_BAD, IMG_BAD },
    { "falign-large", L_FileAlignLarge, IMG_OK, IMG_OK },
    { "lowalign", L_LowAlign, IMG_OK, IMG_OK },
    { "lowalign-rva-not-raw", L_LowAlignRvaNotRaw, IMG_BAD, IMG_BAD },
    { "lowalign-falign-differs", L_LowAlignFileDiffers, IMG_BAD, IMG_BAD },
    { "headers-small", L_HeadersSmall, IMG_OK, IMG_OK },
    { "headers-zero", L_HeadersZero, IMG_BAD, IMG_BAD },
    { "headers-past-first-rva", L_HeadersPastFirstRva, IMG_BAD, IMG_BAD },
    { "headers-unaligned", L_HeadersUnaligned, IMG_OK, IMG_OK },
    { "base-unaligned", L_BaseUnaligned, IMG_BAD, IMG_BAD },
    { "base-zero", L_BaseZero, IMG_OK, IMG_OK },
    { "no-sections", L_NoSections, IMG_BAD, IMG_BAD },
    { "97-sections", L_ManySections, IMG_BAD, IMG_BAD },
    { "virtual-zero-raw-zero", L_VirtualZeroRawZero, IMG_BAD, IMG_BAD },
    { "virtual-zero", L_VirtualZero, IMG_OK, IMG_OK },
    { "entry-outside", L_EntryOutside, IMG_OK, IMG_OK },
    { "bss", L_Bss, IMG_OK, IMG_OK },
    { "cor20-ilonly", L_Cor20IlOnly, IMG_OK, IMG_OK },
    { "size-end-plus-1", L_SizeEndPlus1, IMG_BAD, IMG_OK },
    { "size-next-page", L_SizeNextPage, IMG_BAD, IMG_OK },
    { "falign-80", L_FileAlign80, IMG_BAD, IMG_BAD },
    { "falign-400", L_FileAlign400, IMG_OK, IMG_OK },
    { "falign-1000", L_FileAlign1000, IMG_OK, IMG_OK },
    { "lowalign-100", L_LowAlign100, IMG_OK, IMG_OK },
    { "lowalign-20", L_LowAlign20, IMG_OK, IMG_OK },
    { "lowalign-no-sections", L_LowAlignNoSections, IMG_BAD, IMG_BAD },
    { "no-sections-header-page", L_NoSectionsHeaderPage, IMG_BAD, IMG_BAD },
    { "raw-past-eof-small", L_RawPastEofSmall, IMG_BAD, IMG_BAD },
    { "raw-first-past-eof", L_RawFirstPastEof, IMG_OK, IMG_OK },
    { "raw-offset-past-eof-size0", L_RawOffsetPastEofSize0, IMG_OK, IMG_OK },
    { "raw-virtual-large", L_RawVirtualLarge, IMG_OK, IMG_OK },
    { "raw-first-past-eof-full", L_RawFirstPastEofFull, IMG_OK, IMG_OK },
    { "raw-first-past-eof-virtual", L_RawFirstPastEofVirtual, IMG_OK, IMG_OK },
    { "raw-ends-at-eof", L_RawEndsAtEof, IMG_OK, IMG_OK },
    { "raw-past-eof-virtual-zero", L_RawPastEofVirtualZero, IMG_BAD, IMG_BAD },
    { "raw-last-past-eof-clipped", L_RawLastPastEofClipped, IMG_BAD, IMG_BAD },
    { "raw-last-past-eof", L_RawLastPastEof, IMG_BAD, IMG_BAD },
    { "raw-middle-past-eof", L_RawMiddlePastEof, IMG_OK, IMG_OK },
    { "raw-past-eof-before-bss", L_RawPastEofBeforeBss, IMG_OK, IMG_OK },
    { "tiny-268", L_Tiny268, IMG_OK, IMG_BAD, TRUE },
    { "tiny-200", L_Tiny200, IMG_OK, IMG_BAD, TRUE },
    { "tiny-1000", L_Tiny1000, IMG_OK, IMG_BAD, TRUE },
    { "tiny-2000", L_Tiny2000, IMG_OK, IMG_BAD, TRUE },
};

static void Test_Layout(BOOL Pe64, WORD Machine)
{
    ULONG i;
    NTSTATUS Status;
    char Name[64];

    for (i = 0; i < ARRAYSIZE(LayoutCases); i++)
    {
        StringCbPrintfA(Name, sizeof(Name), "layout-%s", LayoutCases[i].Name);
        NtOffset = IMG_NT_OFFSET;
        ImageFileSize = IMG_FILE_SIZE;
        BuildImage(Pe64, Machine, TRUE, TRUE);
        LayoutCases[i].Mutate();
        Status = CreateImageSection(Name);
        ok(IsExpectedStatus(Status, LayoutCases[i].Win7, LayoutCases[i].Win10, LayoutCases[i].RosLikeWin10),
           "%s (pe%u): status %08lx, Windows 2008 R2 %08lx, Windows 10 %08lx\n",
           Name, Pe64 ? 64 : 32, Status, LayoutCases[i].Win7, LayoutCases[i].Win10);
    }
}

/* Size of a new image section created with size 0; -1 if it cannot be created */
static LONGLONG QueryImageSize(HANDLE hFile, NTSTATUS *CreateStatus)
{
    SECTION_BASIC_INFORMATION Sbi;
    HANDLE hSection = NULL;
    LARGE_INTEGER Size;
    NTSTATUS Status;

    Size.QuadPart = 0;
    Status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_QUERY, NULL, &Size,
                             PAGE_READONLY, SEC_IMAGE, hFile);
    if (CreateStatus)
        *CreateStatus = Status;
    if (!NT_SUCCESS(Status))
        return -1;
    Status = NtQuerySection(hSection, SectionBasicInformation, &Sbi, sizeof(Sbi), NULL);
    ok(Status == STATUS_SUCCESS, "NtQuerySection: 0x%08lx\n", Status);
    NtClose(hSection);
    return NT_SUCCESS(Status) ? Sbi.Size.QuadPart : -1;
}

/*
 * An image section may be as large as the page-rounded SizeOfImage, also when
 * the sections end below it, and also after the image has been mapped once.
 */
static void Test_SizeLimit(void)
{
    WCHAR Path[MAX_PATH];
    HANDLE hFile, hSection = NULL, hSection2;
    LARGE_INTEGER Size;
    PVOID Base = NULL;
    SIZE_T ViewSize = 0;
    NTSTATUS Status;
    ULONG Pass;

    NtOffset = IMG_NT_OFFSET;
    ImageFileSize = IMG_FILE_SIZE;
    BuildImage(NATIVE_PE64, NATIVE_PE64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386, TRUE, TRUE);
    SET_OPT(SizeOfImage, 0x10000);
    if (!GetTempFileNameW(TempDir, L"ncl", 0, Path) || !WriteImage(Path))
    {
        skip("SizeLimit: cannot write the image, error %lu\n", GetLastError());
        return;
    }
    hFile = CreateFileW(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        skip("SizeLimit: cannot open %ls, error %lu\n", Path, GetLastError());
        DeleteFileW(Path);
        return;
    }

    for (Pass = 0; Pass < 2; Pass++)
    {
        Size.QuadPart = 0x10000;
        hSection2 = NULL;
        Status = NtCreateSection(&hSection2, SECTION_MAP_READ | SECTION_QUERY, NULL, &Size,
                                 PAGE_READONLY, SEC_IMAGE, hFile);
        /* Server 2008 R2 refuses a SizeOfImage above the sections; Windows 10 and ReactOS take it */
        if (Pass == 0 && Status == STATUS_INVALID_IMAGE_FORMAT && !is_reactos())
        {
            skip("SizeLimit: this Windows refuses the image\n");
            break;
        }
        ok(Status == STATUS_SUCCESS, "SizeLimit pass %lu: size of the image: 0x%08lx\n", Pass, Status);
        if (NT_SUCCESS(Status))
        {
            if (!hSection)
                hSection = hSection2;
            else
                NtClose(hSection2);
        }

        Size.QuadPart = 0x10001;
        hSection2 = NULL;
        Status = NtCreateSection(&hSection2, SECTION_MAP_READ | SECTION_QUERY, NULL, &Size,
                                 PAGE_READONLY, SEC_IMAGE, hFile);
        ok(Status == STATUS_SECTION_TOO_BIG, "SizeLimit pass %lu: one byte more: 0x%08lx\n", Pass, Status);
        if (NT_SUCCESS(Status))
            NtClose(hSection2);

        /* Size 0 takes the page-rounded SizeOfImage, before and after a mapping */
        Size.QuadPart = QueryImageSize(hFile, NULL);
        ok(Size.QuadPart == 0x10000, "SizeLimit pass %lu: size 0 gives 0x%I64x\n", Pass, Size.QuadPart);

        /* Map it once, which must not change the limit for the next sections */
        if (Pass == 0 && hSection)
        {
            Status = NtMapViewOfSection(hSection, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize,
                                        ViewShare, 0, PAGE_READONLY);
            ok(NT_SUCCESS(Status), "SizeLimit: NtMapViewOfSection: 0x%08lx\n", Status);
            if (NT_SUCCESS(Status))
                NtUnmapViewOfSection(NtCurrentProcess(), Base);
        }
    }

    if (hSection)
        NtClose(hSection);
    CloseHandle(hFile);
    DeleteFileW(Path);
}

/*
 * A SizeOfImage that is not a multiple of the page size: an image section
 * created with size 0 reports it rounded up to the page, before and after a
 * mapping.
 */
static void Test_SizeUnaligned(void)
{
    WCHAR Path[MAX_PATH];
    HANDLE hFile, hSection = NULL;
    LONGLONG Size;
    PVOID Base = NULL;
    SIZE_T ViewSize = 0;
    NTSTATUS Status;

    NtOffset = IMG_NT_OFFSET;
    ImageFileSize = IMG_FILE_SIZE;
    BuildImage(NATIVE_PE64, NATIVE_PE64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386, TRUE, TRUE);
    SET_OPT(SizeOfImage, 0x2100);
    if (!GetTempFileNameW(TempDir, L"ncu", 0, Path) || !WriteImage(Path))
    {
        skip("SizeUnaligned: cannot write the image, error %lu\n", GetLastError());
        return;
    }
    hFile = CreateFileW(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        skip("SizeUnaligned: cannot open %ls, error %lu\n", Path, GetLastError());
        DeleteFileW(Path);
        return;
    }

    Size = QueryImageSize(hFile, &Status);
    trace("CASE SizeUnaligned: %08lx\n", Status);
    ok(Status == STATUS_SUCCESS, "SizeUnaligned: NtCreateSection: 0x%08lx\n", Status);
    ok(Size == 0x3000, "SizeUnaligned: size 0 gives 0x%I64x before a mapping\n", Size);

    Status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_QUERY, NULL, NULL,
                             PAGE_READONLY, SEC_IMAGE, hFile);
    if (NT_SUCCESS(Status))
    {
        Status = NtMapViewOfSection(hSection, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize,
                                    ViewShare, 0, PAGE_READONLY);
        ok(NT_SUCCESS(Status), "SizeUnaligned: NtMapViewOfSection: 0x%08lx\n", Status);
        if (NT_SUCCESS(Status))
        {
            ok(ViewSize == 0x3000, "SizeUnaligned: ViewSize 0x%Ix\n", ViewSize);
            NtUnmapViewOfSection(NtCurrentProcess(), Base);
        }
        Size = QueryImageSize(hFile, NULL);
        ok(Size == 0x3000, "SizeUnaligned: size 0 gives 0x%I64x after a mapping\n", Size);
        NtClose(hSection);
    }

    CloseHandle(hFile);
    DeleteFileW(Path);
}

/*
 * A section whose raw data ends beyond the end of the file, while the last
 * section header is complete (Windows only checks that one against the file
 * size). .text has 0x300 raw bytes at 0x1e00 and the file ends inside them.
 * The page-in reads up to the valid data length of the file and must leave
 * the rest of the page zero. The raw size ends inside a page, and the read
 * used to describe a whole page more than it asked for (a Debug kernel
 * stopped at an assertion, a Release one went on with the larger MDL).
 * VERIFY ON ORACLE: the status Windows gives for each of these file sizes.
 */
static void Test_TruncatedRaw(void)
{
    static const ULONG FileSizes[] = { 0x1e01, 0x1f00, 0x1fff, 0x2000 };
    ULONG i, j;

    for (i = 0; i < ARRAYSIZE(FileSizes); i++)
    {
        WCHAR Path[MAX_PATH];
        HANDLE hFile, hSection = NULL;
        PVOID Base = NULL;
        SIZE_T ViewSize = 0;
        NTSTATUS Status;
        ULONG Wrong = 0, Valid = FileSizes[i] - 0x1e00;

        NtOffset = IMG_NT_OFFSET;
        ImageFileSize = FileSizes[i];
        BuildImage(NATIVE_PE64, NATIVE_PE64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386, TRUE, TRUE);
        SetSection(0, ".text", 0x1000, 0x100, 0x1e00, 0x300, SCN_TEXT);
        memset(Image + 0x1e00, 0xAA, Valid);
        Image[0x1e00] = 0xC3;
        if (!GetTempFileNameW(TempDir, L"nct", 0, Path) || !WriteImage(Path))
        {
            skip("TruncatedRaw: cannot write the image, error %lu\n", GetLastError());
            ImageFileSize = IMG_FILE_SIZE;
            return;
        }
        hFile = CreateFileW(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            skip("TruncatedRaw: cannot open %ls, error %lu\n", Path, GetLastError());
            DeleteFileW(Path);
            ImageFileSize = IMG_FILE_SIZE;
            return;
        }

        Status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_QUERY, NULL, NULL,
                                 PAGE_READONLY, SEC_IMAGE, hFile);
        trace("CASE TruncatedRaw size 0x%lx: %08lx\n", FileSizes[i], Status);
        ok(Status == STATUS_SUCCESS || Status == STATUS_INVALID_IMAGE_FORMAT,
           "TruncatedRaw 0x%lx: NtCreateSection: 0x%08lx\n", FileSizes[i], Status);
        if (NT_SUCCESS(Status))
        {
            Status = NtMapViewOfSection(hSection, NtCurrentProcess(), &Base, 0, 0, NULL, &ViewSize,
                                        ViewShare, 0, PAGE_READONLY);
            ok(NT_SUCCESS(Status), "TruncatedRaw 0x%lx: NtMapViewOfSection: 0x%08lx\n", FileSizes[i], Status);
            if (NT_SUCCESS(Status))
            {
                /* the .text page: the file bytes, then zero to the end of the page */
                for (j = 0; j < 0x1000; j++)
                {
                    BYTE Expected = (j >= Valid || j >= 0x300) ? 0 : (j == 0 ? 0xC3 : 0xAA);
                    if (((PBYTE)Base)[0x1000 + j] != Expected)
                        Wrong++;
                }
                ok(Wrong == 0, "TruncatedRaw 0x%lx: %lu wrong bytes in .text\n", FileSizes[i], Wrong);
                NtUnmapViewOfSection(NtCurrentProcess(), Base);
            }
            NtClose(hSection);
        }
        CloseHandle(hFile);
        DeleteFileW(Path);
    }
    ImageFileSize = IMG_FILE_SIZE;
}

START_TEST(NtCreateSectionImage)
{
    SYSTEM_INFO SystemInfo;

#if !defined(_M_IX86) && !defined(_M_AMD64)
    skip("Measured for x86 and x64 only\n");
    return;
#endif

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    if (!GetTempPathW(ARRAYSIZE(TempDir), TempDir))
    {
        skip("GetTempPathW failed with %lu\n", GetLastError());
        return;
    }

    if (!IsWow64Process(GetCurrentProcess(), &ProcessIsWow64))
        ProcessIsWow64 = FALSE;
    GetNativeSystemInfo(&SystemInfo);
    KernelIs64 = NATIVE_PE64 || ProcessIsWow64;
    trace("kernel %u-bit, WOW64 %d, processor architecture %u\n",
          KernelIs64 ? 64 : 32, ProcessIsWow64, SystemInfo.wProcessorArchitecture);

    Test_Machines();
    Test_Layout(NATIVE_PE64, NATIVE_PE64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386);
    /* The layout rules of the other header format, where this kernel accepts it */
    if (KernelIs64 && !NATIVE_PE64)
        Test_Layout(TRUE, IMAGE_FILE_MACHINE_AMD64);
    if (KernelIs64 && NATIVE_PE64)
        Test_Layout(FALSE, IMAGE_FILE_MACHINE_I386);
    Test_SizeLimit();
    Test_SizeUnaligned();
    Test_TruncatedRaw();
}
