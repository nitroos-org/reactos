/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Write-protected system image pages are read-only for the hardware
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * MiWriteProtectSystemImage clears the write permission of the code and read-only data
 * sections of every system image. On an SMP kernel the hardware writable bit and the
 * software write bit are different bits, and the first version cleared only the software
 * one: the CPU could still write to the page.
 *
 * MmCodeProtect reads the page table entries of the images of ntoskrnl, the HAL and this
 * driver, and checks for every resident page that the hardware bit follows the sections:
 * writable only where a section is writable, no-execute where no section is executable
 * (where the processor has it). It never writes to a page.
 *
 * The hidden test -MmCodeProtectWrite writes one byte, with the value it already has, to
 * a code page of this driver. A write to a read-only system page stops the system with
 * ATTEMPTED_WRITE_TO_READONLY_MEMORY (0xBE), not an exception a driver can catch, so a
 * pass is that bugcheck. The write sits in SEH anyway: if the system did turn it into an
 * access violation, the test also passes; only a write that succeeds fails.
 */

#include <kmt_test.h>

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID BaseAddress);

#if defined(_M_IX86)
#define TEST_PTE_BASE       0xC0000000UL
#define TEST_PDE_BASE       0xC0300000UL
#define TEST_NO_EXECUTE     0
typedef ULONG TEST_PTE;
#define TEST_PTE_OF(Va)     ((volatile TEST_PTE *)(TEST_PTE_BASE + (((ULONG_PTR)(Va) >> 12) << 2)))
#define TEST_PDE_OF(Va)     ((volatile TEST_PTE *)(TEST_PDE_BASE + (((ULONG_PTR)(Va) >> 22) << 2)))
#elif defined(_M_AMD64)
#define TEST_PTE_BASE       0xFFFFF68000000000ULL
#define TEST_PDE_BASE       0xFFFFF6FB40000000ULL
#define TEST_NO_EXECUTE     0x8000000000000000ULL
typedef ULONG64 TEST_PTE;
#define TEST_PTE_OF(Va)     ((volatile TEST_PTE *)(TEST_PTE_BASE + (((ULONG64)(Va) >> 9) & (0xFFFFFFFFFULL << 3))))
#define TEST_PDE_OF(Va)     ((volatile TEST_PTE *)(TEST_PDE_BASE + (((ULONG64)(Va) >> 18) & (0x7FFFFFFULL << 3))))
#endif

#define TEST_VALID          0x001
#define TEST_HW_WRITABLE    0x002 /* hardware bit 1: the same on every x86 mode */
#define TEST_LARGE          0x080

/* Writable data, so that this image has a page the checks must find writable */
static volatile ULONG WritableData = 0x4B4D5457;

/* The code page the hidden test writes to */
DECLSPEC_NOINLINE
static
ULONG
CodeTarget(
    _In_ ULONG Value)
{
    return Value ^ 0x5A5A5A5A;
}

static
BOOLEAN
PageResident(
    _In_ PVOID Va)
{
    return (*TEST_PDE_OF(Va) & TEST_VALID) &&
           !(*TEST_PDE_OF(Va) & TEST_LARGE) &&
           (*TEST_PTE_OF(Va) & TEST_VALID);
}

/* RtlPcToFileHeader is not exported on every architecture: look for the header page below the address */
static
PVOID
FindImageBase(
    _In_ PVOID Anchor)
{
    ULONG_PTR Va = (ULONG_PTR)Anchor & ~(ULONG_PTR)(PAGE_SIZE - 1);
    ULONG Pages;

    for (Pages = 0; Pages < 0x4000; Pages++, Va -= PAGE_SIZE)
    {
        PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)Va;
        PIMAGE_NT_HEADERS Nt;

        if (!PageResident(Dos) || Dos->e_magic != IMAGE_DOS_SIGNATURE)
            continue;
        if (Dos->e_lfanew <= 0 || Dos->e_lfanew > PAGE_SIZE - sizeof(IMAGE_NT_HEADERS))
            continue;
        Nt = (PIMAGE_NT_HEADERS)(Va + Dos->e_lfanew);
        if (Nt->Signature != IMAGE_NT_SIGNATURE)
            continue;
        if ((ULONG_PTR)Anchor - Va < Nt->OptionalHeader.SizeOfImage)
            return Dos;
    }
    return NULL;
}

static
VOID
CheckImage(
    _In_ PCSTR Name,
    _In_ PVOID Anchor)
{
    PVOID Base = NULL;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER Sections;
    ULONG_PTR Offset, Size, SectionStart, SectionEnd;
    ULONG i, Pages = 0, Skipped = 0, Large = 0;
    ULONG CodeBad = 0, DataBad = 0, ExecBad = 0, CodePages = 0, DataPages = 0;
    BOOLEAN Write, Exec;
    TEST_PTE Pte, FirstCodePte = 0;
    PVOID FirstCodeVa = NULL;

    Base = FindImageBase(Anchor);
    if (skip(Base != NULL, "%s: no image header for %p\n", Name, Anchor))
        return;
    NtHeaders = RtlImageNtHeader(Base);
    if (skip(NtHeaders != NULL, "%s: no NT headers at %p\n", Name, Base))
        return;
    if (skip(NtHeaders->OptionalHeader.MajorOperatingSystemVersion >= 5 &&
              NtHeaders->OptionalHeader.MajorSubsystemVersion >= 5,
              "%s: NT4 image, not protected\n", Name))
        return;
    Sections = IMAGE_FIRST_SECTION(NtHeaders);
    Size = NtHeaders->OptionalHeader.SizeOfImage;

    /* The headers are left read-write, as the loader sets them */
    for (Offset = Sections[0].VirtualAddress & ~(ULONG_PTR)(PAGE_SIZE - 1);
         Offset < Size;
         Offset += PAGE_SIZE)
    {
        PVOID Va = (PUCHAR)Base + Offset;

        if ((*TEST_PDE_OF(Va) & (TEST_VALID | TEST_LARGE)) == (TEST_VALID | TEST_LARGE))
        {
            Large++;
            continue;
        }
        if (!PageResident(Va))
        {
            Skipped++;
            continue;
        }
        Pte = *TEST_PTE_OF(Va);

        /* A page that several sections touch gets the union of their rights */
        Write = FALSE;
        Exec = FALSE;
        for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
        {
            SectionStart = Sections[i].VirtualAddress;
            SectionEnd = SectionStart + max(Sections[i].SizeOfRawData, Sections[i].Misc.VirtualSize);
            if (SectionEnd <= Offset || SectionStart >= Offset + PAGE_SIZE)
                continue;
            if (Sections[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                Write = TRUE;
            if (Sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                Exec = TRUE;
        }

        Pages++;
        if (Write)
        {
            DataPages++;
            if (!(Pte & TEST_HW_WRITABLE))
            {
                if (DataBad++ == 0)
                    trace("%s: writable page %p has PTE %I64x, not writable\n", Name, Va, (ULONG64)Pte);
            }
        }
        else
        {
            CodePages++;
            if (FirstCodeVa == NULL && Exec)
            {
                FirstCodeVa = Va;
                FirstCodePte = Pte;
            }
            if (Pte & TEST_HW_WRITABLE)
            {
                if (CodeBad++ == 0)
                    trace("%s: read-only page %p has PTE %I64x, hardware-writable\n", Name, Va, (ULONG64)Pte);
            }
        }
#if TEST_NO_EXECUTE
        if (!Exec != !!(Pte & TEST_NO_EXECUTE))
        {
            if (ExecBad++ == 0)
                trace("%s: page %p (exec %u) has PTE %I64x\n", Name, Va, Exec, (ULONG64)Pte);
        }
#endif
    }

    trace("%s: base %p, %lu pages checked (%lu read-only, %lu writable), %lu not resident, %lu large; "
          "first code page %p PTE %I64x\n",
          Name, Base, Pages, CodePages, DataPages, Skipped, Large, FirstCodeVa, (ULONG64)FirstCodePte);
    ok(Pages != 0, "%s: no resident page checked\n", Name);
    ok(CodeBad == 0, "%s: %lu read-only pages are hardware-writable\n", Name, CodeBad);
    ok(DataBad == 0, "%s: %lu writable pages are not hardware-writable\n", Name, DataBad);
    ok(ExecBad == 0, "%s: %lu pages have the wrong no-execute bit\n", Name, ExecBad);
}

START_TEST(MmCodeProtect)
{
#ifdef _M_IX86
    if (skip(!ExIsProcessorFeaturePresent(PF_PAE_ENABLED), "PAE page tables are not checked here\n"))
        return;
#endif
    WritableData++;
    CheckImage("ntoskrnl", (PVOID)ExAllocatePoolWithTag);
    CheckImage("hal", (PVOID)KeStallExecutionProcessor);
    CheckImage("kmtest_drv", (PVOID)CodeTarget);
}

START_TEST(MmCodeProtectWrite)
{
    volatile UCHAR *Code = (volatile UCHAR *)CodeTarget;
    BOOLEAN Faulted = FALSE;

#ifdef _M_IX86
    if (skip(!ExIsProcessorFeaturePresent(PF_PAE_ENABLED), "PAE page tables are not checked here\n"))
        return;
#endif
    trace("writing one byte to the code page %p, PTE %I64x\n", Code, (ULONG64)*TEST_PTE_OF(Code));
    _SEH2_TRY
    {
        *Code = *Code;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Faulted = TRUE;
    }
    _SEH2_END;
    ok(Faulted, "the write to a code page went through\n");
}
