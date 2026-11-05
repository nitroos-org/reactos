/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A static import that resolves to a forwarded export whose
 *              target cannot be resolved fails cleanly: LoadLibrary returns
 *              NULL with the loader's error, again and again, the module
 *              lists hold no stale entry, and a process whose own imports
 *              fail this way ends with the loader's status
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

#include <pshpack1.h>
typedef struct _FWIMG
{
    IMAGE_DOS_HEADER Dos;
#ifdef _WIN64
    IMAGE_NT_HEADERS64 Nt;
#else
    IMAGE_NT_HEADERS32 Nt;
#endif
    IMAGE_SECTION_HEADER Sect;
} FWIMG;
#include <poppack.h>

#define IMG_FILE_ALIGN  0x200
#define IMG_SECT_ALIGN  0x1000

/* Section layout, offsets from the section start */
#define OFF_IMPORTS     0x000   /* IMAGE_IMPORT_DESCRIPTOR[MAX_IMPORTS + 1] */
#define OFF_ILT         0x060   /* 0x20 bytes per import: two thunks and the terminator */
#define OFF_IAT         0x0C0
#define OFF_HINTNAME    0x120   /* two names per import, 0x20 bytes each */
#define OFF_DLLNAME     0x1E0   /* 0x20 bytes per import */
#define OFF_BOUND       0x240   /* bound import directory */
#define OFF_CODE        0x2C0
#define OFF_EXPORT      0x300   /* IMAGE_EXPORT_DIRECTORY */
#define OFF_EXPFUNCS    0x340
#define OFF_EXPNAMES    0x3A0
#define OFF_EXPORDS     0x400
#define OFF_EXPSTR      0x440   /* DLL name, export names, forwarder strings */
#define SECT_SIZE       0xC00
#define MAX_EXPORTS     24
#define MAX_IMPORTS     3

#ifdef _WIN64
typedef ULONGLONG THUNK;
#define ORD_FLAG        IMAGE_ORDINAL_FLAG64
#else
typedef ULONG THUNK;
#define ORD_FLAG        IMAGE_ORDINAL_FLAG32
#endif

/* What a bound image has in its IAT: not the address of anything */
#define PREBOUND        ((THUNK)0x7F000100)

typedef struct _FWEXPORT
{
    PCSTR Name;     /* exported name; the ordinal is the position + 1 */
    PCSTR Forward;  /* "Dll.Name" / "Dll.#Ordinal", or NULL for code */
} FWEXPORT;

/* One import descriptor: the DLL and one or two thunks (a name, or an ordinal when the name is NULL) */
typedef struct _FWIMPORT
{
    PCSTR Dll;
    PCSTR Name[2];
    WORD Ordinal[2];
    ULONG Count;
} FWIMPORT;

/* A bound import directory: the DLL the image is bound to and its time stamp, and one forwarder reference */
typedef struct _FWBOUND
{
    DWORD Tds;
    PCSTR FwdDll;
    DWORD FwdTds;
} FWBOUND;

/* When not 0, the name RVA of the import descriptor (out of the image: the
 * loader faults when it reads the name of the DLL to import) */
static DWORD BadImportNameRva;

/* Each DLL gets a base address of its own: one that is not at its base is not a current binding */
static ULONG ImageSeq;

/* A minimal image. It imports Imports (one descriptor each), when Bound is
 * not NULL it is bound to the DLL of the first import (the IAT then holds
 * PREBOUND), and a DLL exports Exports. A DLL has no entry point; an EXE
 * returns 0 at once */
static
BOOL
WriteFwImageEx(PCWSTR Path, BOOL IsDll, PCSTR DllName, const FWIMPORT *Imports, ULONG ImportCount,
               const FWBOUND *Bound, const FWEXPORT *Exports, ULONG ExportCount)
{
    BYTE Image[IMG_FILE_ALIGN + SECT_SIZE] = { 0 };
    FWIMG *Img = (FWIMG *)Image;
    PBYTE Sect = Image + IMG_FILE_ALIGN;
    HANDLE hFile;
    DWORD Written;
    BOOL Ret;
    ULONG n, t;

    C_ASSERT(sizeof(FWIMG) <= IMG_FILE_ALIGN);
    if (ExportCount > MAX_EXPORTS || ImportCount > MAX_IMPORTS)
        return FALSE;

    Img->Dos.e_magic = IMAGE_DOS_SIGNATURE;
    Img->Dos.e_lfanew = FIELD_OFFSET(FWIMG, Nt);
    Img->Nt.Signature = IMAGE_NT_SIGNATURE;
#ifdef _WIN64
    Img->Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    Img->Nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    Img->Nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    Img->Nt.OptionalHeader.ImageBase = IsDll ? 0x180000000ULL + (ImageSeq++ % 64) * 0x100000 : 0x140000000ULL;
#else
    Img->Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    Img->Nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
    Img->Nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    Img->Nt.OptionalHeader.ImageBase = IsDll ? 0x10000000 + (ImageSeq++ % 64) * 0x100000 : 0x00400000;
#endif
    if (IsDll)
        Img->Nt.FileHeader.Characteristics |= IMAGE_FILE_DLL;
    Img->Nt.FileHeader.NumberOfSections = 1;
    Img->Nt.FileHeader.SizeOfOptionalHeader = sizeof(Img->Nt.OptionalHeader);
    Img->Nt.OptionalHeader.SizeOfCode = SECT_SIZE;
    Img->Nt.OptionalHeader.BaseOfCode = IMG_SECT_ALIGN;
    Img->Nt.OptionalHeader.AddressOfEntryPoint = IsDll ? 0 : IMG_SECT_ALIGN + OFF_CODE;
    Img->Nt.OptionalHeader.SectionAlignment = IMG_SECT_ALIGN;
    Img->Nt.OptionalHeader.FileAlignment = IMG_FILE_ALIGN;
    Img->Nt.OptionalHeader.MajorOperatingSystemVersion = 5;
    Img->Nt.OptionalHeader.MajorSubsystemVersion = 5;
    Img->Nt.OptionalHeader.SizeOfImage = 2 * IMG_SECT_ALIGN;
    Img->Nt.OptionalHeader.SizeOfHeaders = IMG_FILE_ALIGN;
    Img->Nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    Img->Nt.OptionalHeader.SizeOfStackReserve = 0x100000;
    Img->Nt.OptionalHeader.SizeOfStackCommit = 0x1000;
    Img->Nt.OptionalHeader.SizeOfHeapReserve = 0x100000;
    Img->Nt.OptionalHeader.SizeOfHeapCommit = 0x1000;
    Img->Nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    memcpy(Img->Sect.Name, ".fwtest", 7);
    Img->Sect.Misc.VirtualSize = SECT_SIZE;
    Img->Sect.VirtualAddress = IMG_SECT_ALIGN;
    Img->Sect.SizeOfRawData = SECT_SIZE;
    Img->Sect.PointerToRawData = IMG_FILE_ALIGN;
    Img->Sect.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA |
                                IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    if (ImportCount)
    {
        PIMAGE_IMPORT_DESCRIPTOR Imp = (PIMAGE_IMPORT_DESCRIPTOR)(Sect + OFF_IMPORTS);

        Img->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IMG_SECT_ALIGN + OFF_IMPORTS;
        Img->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (ImportCount + 1) * sizeof(*Imp);
        for (n = 0; n < ImportCount; n++)
        {
            THUNK *Ilt = (THUNK *)(Sect + OFF_ILT + n * 0x20), *Iat = (THUNK *)(Sect + OFF_IAT + n * 0x20);

            if (Imports[n].Count < 1 || Imports[n].Count > 2)
                return FALSE;
            Imp[n].OriginalFirstThunk = IMG_SECT_ALIGN + OFF_ILT + n * 0x20;
            Imp[n].Name = (BadImportNameRva && n == 0) ? BadImportNameRva : IMG_SECT_ALIGN + OFF_DLLNAME + n * 0x20;
            Imp[n].FirstThunk = IMG_SECT_ALIGN + OFF_IAT + n * 0x20;
            StringCchCopyA((char *)(Sect + OFF_DLLNAME + n * 0x20), 0x20, Imports[n].Dll);
            for (t = 0; t < Imports[n].Count; t++)
            {
                if (Imports[n].Name[t])
                {
                    ULONG Hint = OFF_HINTNAME + (n * 2 + t) * 0x20;

                    StringCchCopyA((char *)(Sect + Hint + 2), 0x1E, Imports[n].Name[t]);
                    Ilt[t] = Iat[t] = IMG_SECT_ALIGN + Hint;
                }
                else
                {
                    Ilt[t] = Iat[t] = ORD_FLAG | Imports[n].Ordinal[t];
                }
                if (Bound)
                    Iat[t] = PREBOUND;
            }
        }
        if (Bound)
        {
            PIMAGE_BOUND_IMPORT_DESCRIPTOR Bd = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(Sect + OFF_BOUND);
            ULONG NameOff = sizeof(*Bd) + (Bound->FwdDll ? sizeof(IMAGE_BOUND_FORWARDER_REF) : 0) + sizeof(*Bd);

            Bd->TimeDateStamp = Bound->Tds;
            Bd->OffsetModuleName = (WORD)NameOff;
            Bd->NumberOfModuleForwarderRefs = Bound->FwdDll ? 1 : 0;
            StringCchCopyA((char *)Bd + NameOff, 0x20, Imports[0].Dll);
            if (Bound->FwdDll)
            {
                PIMAGE_BOUND_FORWARDER_REF Ref = (PIMAGE_BOUND_FORWARDER_REF)(Bd + 1);

                Ref->TimeDateStamp = Bound->FwdTds;
                Ref->OffsetModuleName = (WORD)(NameOff + strlen(Imports[0].Dll) + 1);
                StringCchCopyA((char *)Bd + Ref->OffsetModuleName, 0x20, Bound->FwdDll);
            }
            Img->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = IMG_SECT_ALIGN + OFF_BOUND;
            Img->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0x40;
        }
    }

    if (IsDll)
    {
        PIMAGE_EXPORT_DIRECTORY Exp = (PIMAGE_EXPORT_DIRECTORY)(Sect + OFF_EXPORT);
        PULONG Funcs = (PULONG)(Sect + OFF_EXPFUNCS), Names = (PULONG)(Sect + OFF_EXPNAMES);
        PUSHORT Ords = (PUSHORT)(Sect + OFF_EXPORDS);
        ULONG Order[MAX_EXPORTS], Str = OFF_EXPSTR, i, j;
        size_t Len;

        Img->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = IMG_SECT_ALIGN + OFF_EXPORT;
        Img->Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = SECT_SIZE - OFF_EXPORT;
        Exp->Base = 1;
        Exp->NumberOfFunctions = Exp->NumberOfNames = ExportCount;
        Exp->AddressOfFunctions = IMG_SECT_ALIGN + OFF_EXPFUNCS;
        Exp->AddressOfNames = IMG_SECT_ALIGN + OFF_EXPNAMES;
        Exp->AddressOfNameOrdinals = IMG_SECT_ALIGN + OFF_EXPORDS;

#define PUT_STR(s) \
        (Len = strlen(s) + 1, \
         (Str + Len > SECT_SIZE) ? 0 : (memcpy(Sect + Str, (s), Len), Str += (ULONG)Len, IMG_SECT_ALIGN + Str - (ULONG)Len))

        Exp->Name = PUT_STR(DllName);
        for (i = 0; i < ExportCount; i++)
        {
            /* A forwarder is a string inside the export directory */
            Funcs[i] = Exports[i].Forward ? PUT_STR(Exports[i].Forward) : IMG_SECT_ALIGN + OFF_CODE;
            if (!Funcs[i])
                return FALSE;
        }
        /* The name table is sorted (the loader searches it in halves) */
        for (i = 0; i < ExportCount; i++)
        {
            for (j = i; j > 0 && strcmp(Exports[Order[j - 1]].Name, Exports[i].Name) > 0; j--)
                Order[j] = Order[j - 1];
            Order[j] = i;
        }
        for (i = 0; i < ExportCount; i++)
        {
            Names[i] = PUT_STR(Exports[Order[i]].Name);
            if (!Names[i])
                return FALSE;
            Ords[i] = (USHORT)Order[i];
        }
#undef PUT_STR
    }

    /* xor eax, eax; ret (x86: ret 4, the thread start routine has a parameter) */
    Sect[OFF_CODE + 0] = 0x31;
    Sect[OFF_CODE + 1] = 0xC0;
#ifdef _WIN64
    Sect[OFF_CODE + 2] = 0xC3;
#else
    Sect[OFF_CODE + 2] = 0xC2;
    Sect[OFF_CODE + 3] = 0x04;
#endif

    hFile = CreateFileW(Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    Ret = WriteFile(hFile, Image, sizeof(Image), &Written, NULL) && Written == sizeof(Image);
    CloseHandle(hFile);
    return Ret;
}

/* An image that imports Name (or Ordinal when Name is NULL) from ImportDll, unless ImportDll is NULL */
static
BOOL
WriteFwImage(PCWSTR Path, BOOL IsDll, PCSTR DllName, PCSTR ImportDll, PCSTR Name, WORD Ordinal,
             const FWEXPORT *Exports, ULONG ExportCount)
{
    FWIMPORT Import = { ImportDll, { Name, NULL }, { Ordinal, 0 }, 1 };

    return WriteFwImageEx(Path, IsDll, DllName, &Import, ImportDll ? 1 : 0, NULL, Exports, ExportCount);
}

/*
 * ldrfw_fwd.dll forwards its exports. The ordinal of an export is its
 * position here + 1
 */
static const FWEXPORT FwdExports[] =
{
    { "Real",       NULL },                                 /* 1 */
    { "FwdOk",      "kernel32.GetTickCount" },              /* 2: control */
    { "FwdName",    "kernel32.LdrFwNoSuchExport" },         /* 3: loaded target, missing name */
    { "FwdOrd",     "kernel32.#32000" },                    /* 4: loaded target, missing ordinal */
    { "FwdNewDll",  "ldrfw_tgt.LdrFwNoSuchExport" },        /* 5: target mapped by the snap, missing name */
    { "FwdNewOrd",  "ldrfw_tgt.#4000" },                    /* 6: target mapped by the snap, missing ordinal */
    { "FwdBadDll",  "ldrfw_bad.Foo" },                      /* 7: target whose own import is missing */
    { "FwdNoDll",   "ldrfw_nonexistent.Foo" },              /* 8: target does not exist */
    { "FwdBadImp",  "ldrfw_badimp.Foo" },                   /* 9: target whose own import is missing by name */
    { "FwdMal",     "ldrmal_tgt.Foo" },                     /* 10: target with a malformed import directory */
    { "FwdMal2",    "ldrmal_gpa.Foo" },                     /* 11: same, for GetProcAddress */
    { "FwdChain",   "ldrfw_chain.Mid" },                    /* 12: a forwarder to a forwarder to a missing name */
    { "FwdChainOrd", "ldrfw_chain.MidOrd" },                /* 13: a forwarder to a forwarder to a missing ordinal */
    { "FwdTgtFoo",  "ldrfw_tgt.Foo" },                      /* 14: target mapped by the snap, resolves */
    { "FwdChain3",  "ldrfw_chain.Deep" },                   /* 15: three forwarders, then a missing name */
    { "FwdChain3Ord", "ldrfw_chain.DeepOrd" },              /* 16: three forwarders, then a missing ordinal */
    { "FwdChain3Dll", "ldrfw_chain.DeepDll" },              /* 17: three forwarders, then a missing DLL */
    { "FwdChainOk", "ldrfw_chain.Ok" },                     /* 18: three forwarders that resolve */
    { "FwdLoop",    "ldrfw_chain.Loop" },                   /* 19: a loop through two DLLs */
    { "FwdSelf",    "ldrfw_fwd.FwdSelf" },                  /* 20: a forwarder to itself */
};

/* ldrfw_chain.dll: the second step of the chained forwarders */
static const FWEXPORT ChainExports[] =
{
    { "Mid",        "ldrfw_tgt.LdrFwNoSuchExport" },        /* 1: target mapped by the nested snap, missing name */
    { "MidOrd",     "kernel32.#32000" },                    /* 2: loaded target, missing ordinal */
    { "Deep",       "ldrfw_chain2.Deep" },                  /* 3 */
    { "DeepOrd",    "ldrfw_chain2.DeepOrd" },               /* 4 */
    { "DeepDll",    "ldrfw_chain2.DeepDll" },               /* 5 */
    { "Ok",         "ldrfw_chain2.Ok" },                    /* 6 */
    { "Loop",       "ldrfw_fwd.FwdLoop" },                  /* 7: back to the first step */
};

/* ldrfw_chain2.dll: the third step */
static const FWEXPORT Chain2Exports[] =
{
    { "Deep",       "ldrfw_tgt.LdrFwNoSuchExport" },        /* 1 */
    { "DeepOrd",    "kernel32.#32000" },                    /* 2 */
    { "DeepDll",    "ldrfw_nonexistent.Foo" },              /* 3 */
    { "Ok",         "ldrfw_tgt.Foo" },                      /* 4 */
};

static const FWEXPORT FooExport[] = { { "Foo", NULL } };

typedef struct _FWCASE
{
    PCWSTR File;            /* DLL that imports from ldrfw_fwd.dll */
    PCSTR Name;             /* imported name, or NULL for Ordinal */
    WORD Ordinal;
    DWORD LoadError;        /* LoadLibrary; 0 = it loads */
    LONG HardErrors;        /* NtRaiseHardError calls during one LoadLibrary; HARD_AT_MOST_ONE: 0 or 1 */
    PCWSTR HardName;        /* the entry point the hard error names, NULL = not checked */
    NTSTATUS StartStatus;   /* exit code of an EXE that imports the DLL */
    PCWSTR HardDll;         /* the module the hard error names (its full path, in the test directory), NULL = not checked */
    PCSTR From;             /* the DLL the import is from, NULL = ldrfw_fwd.dll */
} FWCASE;

#define HARD_AT_MOST_ONE    (-1)
#define ERROR_ANY           ((DWORD)-1)

/*
 * Windows 10 22H2 (x64 and WoW64): the status is that of the step that
 * failed. A forwarder to a missing ordinal fails with the ordinal status even
 * for an import by name, and a forwarder whose target DLL (or an import of
 * it) is missing fails with STATUS_DLL_NOT_FOUND. Only a missing name is
 * reported to the system (hard error) during a LoadLibrary of a forwarder,
 * and the report names what the module being snapped imports (not the name
 * the forwarder points to) and the full path of that module (not the DLL the
 * import is from). The last two cases import from kernel32 directly
 */
static const FWCASE Cases[] =
{
    { L"ldrfw_u_ok.dll",     "FwdOk",     0, 0,                     0, NULL, 0 },
    { L"ldrfw_u_name.dll",   "FwdName",   0, ERROR_PROC_NOT_FOUND,  1, L"FwdName", STATUS_ENTRYPOINT_NOT_FOUND, L"ldrfw_u_name.dll" },
    { L"ldrfw_u_ord.dll",    "FwdOrd",    0, ERROR_INVALID_ORDINAL, 0, NULL, STATUS_ORDINAL_NOT_FOUND },
    { L"ldrfw_u_byord.dll",  NULL,        4, ERROR_INVALID_ORDINAL, 0, NULL, STATUS_ORDINAL_NOT_FOUND },
    { L"ldrfw_u_newdll.dll", "FwdNewDll", 0, ERROR_PROC_NOT_FOUND,  1, L"FwdNewDll", STATUS_ENTRYPOINT_NOT_FOUND, L"ldrfw_u_newdll.dll" },
    { L"ldrfw_u_neword.dll", "FwdNewOrd", 0, ERROR_INVALID_ORDINAL, 0, NULL, STATUS_ORDINAL_NOT_FOUND },
    { L"ldrfw_u_baddll.dll", "FwdBadDll", 0, ERROR_MOD_NOT_FOUND,   0, NULL, STATUS_DLL_NOT_FOUND },
    { L"ldrfw_u_nodll.dll",  "FwdNoDll",  0, ERROR_MOD_NOT_FOUND,   0, NULL, STATUS_DLL_NOT_FOUND },
    /* Reported where the target's own import fails: the target is named by the path the forwarder made (".DLL" appended) */
    { L"ldrfw_u_badimp.dll", "FwdBadImp", 0, ERROR_PROC_NOT_FOUND,  1, L"LdrFwNoSuchExport", STATUS_ENTRYPOINT_NOT_FOUND, L"ldrfw_badimp.DLL" },
    /* Chains: the status of the step that failed, as above, reported once (the name: measured) */
    { L"ldrfw_u_chain.dll",  "FwdChain",  0, ERROR_PROC_NOT_FOUND,  1, L"FwdChain", STATUS_ENTRYPOINT_NOT_FOUND, L"ldrfw_u_chain.dll" },
    { L"ldrfw_u_chord.dll",  "FwdChainOrd", 0, ERROR_INVALID_ORDINAL, HARD_AT_MOST_ONE, NULL, STATUS_ORDINAL_NOT_FOUND },
    /* No forwarder: a missing name and a missing ordinal of kernel32 */
    { L"ldrfw_u_plain.dll",  "LdrFwNoSuchExport", 0, ERROR_PROC_NOT_FOUND, 1, L"LdrFwNoSuchExport", STATUS_ENTRYPOINT_NOT_FOUND,
      L"ldrfw_u_plain.dll", "kernel32.dll" },
    { L"ldrfw_u_plord.dll",  NULL, 32000, ERROR_INVALID_ORDINAL, 1, NULL, STATUS_ORDINAL_NOT_FOUND, L"ldrfw_u_plord.dll", "kernel32.dll" },
    /* Chains three forwarders deep */
    { L"ldrfw_u_chain3.dll", "FwdChain3", 0, ERROR_PROC_NOT_FOUND,  1, L"FwdChain3", STATUS_ENTRYPOINT_NOT_FOUND, L"ldrfw_u_chain3.dll" },
    { L"ldrfw_u_chord3.dll", "FwdChain3Ord", 0, ERROR_INVALID_ORDINAL, HARD_AT_MOST_ONE, NULL, STATUS_ORDINAL_NOT_FOUND },
    { L"ldrfw_u_chdll3.dll", "FwdChain3Dll", 0, ERROR_MOD_NOT_FOUND, 0, NULL, STATUS_DLL_NOT_FOUND },
    /* Loops: not measured on Windows, so only that the load fails (some error), cleanly, is checked */
    { L"ldrfw_u_loop.dll",   "FwdLoop", 0, ERROR_ANY, HARD_AT_MOST_ONE, NULL, 0 },
    { L"ldrfw_u_self.dll",   "FwdSelf", 0, ERROR_ANY, HARD_AT_MOST_ONE, NULL, 0 },
};

/* Every image the test writes; none of them may stay loaded after a failure */
static const PCWSTR Helpers[] = { L"ldrfw_fwd.dll", L"ldrfw_tgt.dll", L"ldrfw_bad.dll", L"ldrfw_badimp.dll",
                                  L"ldrfw_chain.dll", L"ldrfw_chain2.dll" };

/* Bits for the helpers above */
#define H_FWD       0x01
#define H_TGT       0x02
#define H_BAD       0x04
#define H_BADIMP    0x08
#define H_CHAIN     0x10
#define H_CHAIN2    0x20

#define LOAD_TIMEOUT    20000
#define LOAD_REPEAT     10

/* The part of LDR_DATA_TABLE_ENTRY / PEB_LDR_DATA this test reads */
typedef struct _FW_LDR_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} FW_LDR_ENTRY;

typedef struct _FW_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} FW_LDR_DATA;

static
FW_LDR_DATA *
GetLdrData(VOID)
{
    PBYTE Peb;

#ifdef _WIN64
    Peb = *(PBYTE *)((PBYTE)NtCurrentTeb() + 0x60);
    return *(FW_LDR_DATA **)(Peb + 0x18);
#else
    Peb = *(PBYTE *)((PBYTE)NtCurrentTeb() + 0x30);
    return *(FW_LDR_DATA **)(Peb + 0x0C);
#endif
}

static
BOOL
IsTestModuleName(PCUNICODE_STRING Name)
{
    static const WCHAR Prefix[] = L"ldrfw_";
    const USHORT PrefixLength = sizeof(Prefix) - sizeof(WCHAR);

    return Name->Buffer && Name->Length >= PrefixLength &&
           !_wcsnicmp(Name->Buffer, Prefix, PrefixLength / sizeof(WCHAR));
}

/*
 * Walks one module list of the loader and checks every entry: the image is
 * still mapped at DllBase, and no image this test wrote is listed. Returns
 * the number of entries, or -1 when the list is broken
 */
static
LONG
CheckModuleList(PLIST_ENTRY Head, SIZE_T LinkOffset, PCSTR ListName, PCSTR Where, BOOL NoTestModules)
{
    PLIST_ENTRY Entry;
    LONG Count = 0;

    for (Entry = Head->Flink; Entry != Head; Entry = Entry->Flink)
    {
        FW_LDR_ENTRY *Ldr = (FW_LDR_ENTRY *)((PBYTE)Entry - LinkOffset);
        MEMORY_BASIC_INFORMATION Mbi;

        if (++Count > 4096 || !Entry->Flink || Entry->Flink->Blink != Entry)
        {
            ok(0, "%s: %s is broken at entry %ld\n", Where, ListName, Count);
            return -1;
        }
        ok(!NoTestModules || !IsTestModuleName(&Ldr->BaseDllName), "%s: %s still holds %wZ (%p)\n",
           Where, ListName, &Ldr->BaseDllName, Ldr->DllBase);
        if (!VirtualQuery(Ldr->DllBase, &Mbi, sizeof(Mbi)) ||
            Mbi.State != MEM_COMMIT || Mbi.Type != MEM_IMAGE || Mbi.AllocationBase != Ldr->DllBase)
        {
            ok(0, "%s: %s entry %wZ: nothing mapped at %p (state 0x%lx type 0x%lx base %p)\n",
               Where, ListName, &Ldr->BaseDllName, Ldr->DllBase, Mbi.State, Mbi.Type, Mbi.AllocationBase);
        }
    }
    return Count;
}

typedef struct _LISTCOUNT
{
    LONG Load, Memory, Init;
} LISTCOUNT;

static
VOID
CheckModuleLists(LISTCOUNT *Counts, PCSTR Where)
{
    FW_LDR_DATA *Ldr = GetLdrData();

    Counts->Load = CheckModuleList(&Ldr->InLoadOrderModuleList,
                                   FIELD_OFFSET(FW_LDR_ENTRY, InLoadOrderLinks), "load-order list", Where, TRUE);
    Counts->Memory = CheckModuleList(&Ldr->InMemoryOrderModuleList,
                                     FIELD_OFFSET(FW_LDR_ENTRY, InMemoryOrderLinks), "memory-order list", Where, TRUE);
    Counts->Init = CheckModuleList(&Ldr->InInitializationOrderModuleList,
                                   FIELD_OFFSET(FW_LDR_ENTRY, InInitializationOrderLinks), "init-order list", Where, TRUE);
}

typedef struct _LOADREQ
{
    WCHAR Path[MAX_PATH];
    HMODULE Module;
    DWORD Error;
} LOADREQ;

static
DWORD
WINAPI
LoadThread(LPVOID Param)
{
    LOADREQ *Req = Param;

    SetLastError(0xdeadbeef);
    /* The directory of the DLL is searched for its imports */
    Req->Module = LoadLibraryExW(Req->Path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    Req->Error = GetLastError();
    return 0;
}

/* The load runs in its own thread so that a loader that waits (hard error)
 * or dies costs a timeout instead of the whole test run. FALSE on a hang */
static
BOOL
LoadGuarded(LOADREQ *Req)
{
    HANDLE Thread = CreateThread(NULL, 0, LoadThread, Req, 0, NULL);

    if (!Thread)
        return FALSE;
    if (WaitForSingleObject(Thread, LOAD_TIMEOUT) != WAIT_OBJECT_0)
        return FALSE; /* leak the thread and its request: it is stuck in the loader */
    CloseHandle(Thread);
    return TRUE;
}

static BOOL Hung;
static LONG HardErrorCount;
static NTSTATUS HardErrorLast;
static WCHAR HardErrorName[64];        /* the entry point of the last missing-export hard error */
static ULONG HardErrorOrdinal;          /* or the ordinal */
static WCHAR HardErrorDll[MAX_PATH];    /* and its DLL */

static
VOID
TestDynamic(PCWSTR Dir)
{
    LISTCOUNT Before, After;
    CHAR Where[64];
    ULONG i, n, h;

    CheckModuleLists(&Before, "before");
    for (i = 0; i < _countof(Cases) && !Hung; i++)
    {
        for (n = 0; n < LOAD_REPEAT && !Hung; n++)
        {
            static LOADREQ Req; /* static: outlives a stuck thread */
            LONG HardErrorsBefore = HardErrorCount;

            ZeroMemory(&Req, sizeof(Req));
            StringCchPrintfW(Req.Path, _countof(Req.Path), L"%ls\\%ls", Dir, Cases[i].File);
            if (!LoadGuarded(&Req))
            {
                ok(0, "LoadLibraryW(%ls) #%lu did not return within %lu ms\n", Cases[i].File, n, (ULONG)LOAD_TIMEOUT);
                Hung = TRUE;
                break;
            }
            ok(Cases[i].HardErrors == HARD_AT_MOST_ONE ? (HardErrorCount - HardErrorsBefore <= 1) :
               (HardErrorCount - HardErrorsBefore == Cases[i].HardErrors),
               "LoadLibraryW(%ls) #%lu raised %ld hard errors (last 0x%lx), expected %ld\n",
               Cases[i].File, n, HardErrorCount - HardErrorsBefore, (ULONG)HardErrorLast, Cases[i].HardErrors);
            if (n == 0 && HardErrorCount != HardErrorsBefore)
            {
                if (HardErrorLast == STATUS_ORDINAL_NOT_FOUND)
                    trace("%ls: hard error 0x%lx for %ls!#%lu\n", Cases[i].File, (ULONG)HardErrorLast, HardErrorDll, HardErrorOrdinal);
                else
                    trace("%ls: hard error 0x%lx for %ls!%ls\n", Cases[i].File, (ULONG)HardErrorLast, HardErrorDll, HardErrorName);
            }
            if (Cases[i].HardName && HardErrorCount != HardErrorsBefore)
                ok(!_wcsicmp(HardErrorName, Cases[i].HardName), "LoadLibraryW(%ls) #%lu: the hard error names %ls, expected %ls\n",
                   Cases[i].File, n, HardErrorName, Cases[i].HardName);
            if (!Cases[i].Name && Cases[i].HardErrors > 0 && HardErrorCount != HardErrorsBefore)
                ok(HardErrorOrdinal == Cases[i].Ordinal, "LoadLibraryW(%ls) #%lu: the hard error names ordinal %lu, expected %u\n",
                   Cases[i].File, n, HardErrorOrdinal, Cases[i].Ordinal);
            if (Cases[i].HardDll && HardErrorCount != HardErrorsBefore)
            {
                WCHAR Expected[MAX_PATH];

                StringCchPrintfW(Expected, _countof(Expected), L"%ls\\%ls", Dir, Cases[i].HardDll);
                ok(!_wcsicmp(HardErrorDll, Expected), "LoadLibraryW(%ls) #%lu: the hard error names the DLL %ls, expected %ls\n",
                   Cases[i].File, n, HardErrorDll, Expected);
            }
            if (!Cases[i].LoadError)
            {
                ok(Req.Module != NULL, "LoadLibraryW(%ls) #%lu failed: %lu\n", Cases[i].File, n, Req.Error);
                if (Req.Module)
                {
                    FARPROC Proc = GetProcAddress(Req.Module, "Foo");
                    ok(Proc != NULL, "%ls!Foo not found: %lu\n", Cases[i].File, GetLastError());
                    FreeLibrary(Req.Module);
                }
                continue;
            }
            ok(Req.Module == NULL, "LoadLibraryW(%ls) #%lu succeeded: %p\n", Cases[i].File, n, Req.Module);
            if (Cases[i].LoadError == ERROR_ANY)
                ok(Req.Error != 0 && Req.Error != 0xdeadbeef, "LoadLibraryW(%ls) #%lu error %lu\n", Cases[i].File, n, Req.Error);
            else
                ok(Req.Error == Cases[i].LoadError, "LoadLibraryW(%ls) #%lu error %lu, expected %lu\n",
                   Cases[i].File, n, Req.Error, Cases[i].LoadError);
            if (Req.Module)
                FreeLibrary(Req.Module);
            ok(GetModuleHandleW(Cases[i].File) == NULL, "%ls stays loaded after #%lu\n", Cases[i].File, n);
            for (h = 0; h < _countof(Helpers); h++)
                ok(GetModuleHandleW(Helpers[h]) == NULL, "%ls stays loaded after %ls #%lu\n", Helpers[h], Cases[i].File, n);
        }
        if (Hung)
            break;
        StringCchPrintfA(Where, _countof(Where), "after %ls", Cases[i].File);
        CheckModuleLists(&After, Where);
        /* A failed load maps nothing that stays; the forwarder targets that
         * were loaded before (kernel32) stay as they were */
        ok(After.Load == Before.Load && After.Memory == Before.Memory && After.Init == Before.Init,
           "after %ls: %ld/%ld/%ld modules (load/memory/init order), before %ld/%ld/%ld\n", Cases[i].File,
           After.Load, After.Memory, After.Init, Before.Load, Before.Memory, Before.Init);
    }
}

/* The forwarders resolved by GetProcAddress on the forwarding DLL itself
 * (no import walk): the same failures, nothing left behind */
static
VOID
TestGetProcAddress(PCWSTR Dir)
{
    static const struct { PCSTR Name; DWORD Error; } Bad[] =
    {
        { "FwdName",   ERROR_PROC_NOT_FOUND },
        { "FwdOrd",    ERROR_INVALID_ORDINAL },
        { "FwdNewDll", ERROR_PROC_NOT_FOUND },
        { "FwdNewOrd", ERROR_INVALID_ORDINAL },
        { "FwdBadDll", ERROR_PROC_NOT_FOUND }, /* not ERROR_MOD_NOT_FOUND as for an import */
        { "FwdNoDll",  ERROR_PROC_NOT_FOUND },
    };
    WCHAR Path[MAX_PATH];
    HMODULE Fwd;
    FARPROC Proc;
    ULONG i, n;

    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_fwd.dll", Dir);
    Fwd = LoadLibraryExW(Path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    ok(Fwd != NULL, "LoadLibraryW(ldrfw_fwd.dll) failed: %lu\n", GetLastError());
    if (!Fwd)
        return;

    Proc = GetProcAddress(Fwd, "FwdOk");
    ok(Proc == GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount"),
       "FwdOk resolves to %p\n", Proc);
    for (i = 0; i < _countof(Bad); i++)
    {
        for (n = 0; n < LOAD_REPEAT; n++)
        {
            SetLastError(0xdeadbeef);
            Proc = GetProcAddress(Fwd, Bad[i].Name);
            ok(Proc == NULL, "GetProcAddress(%s) #%lu = %p\n", Bad[i].Name, n, Proc);
            ok(GetLastError() == Bad[i].Error, "GetProcAddress(%s) #%lu error %lu, expected %lu\n",
               Bad[i].Name, n, GetLastError(), Bad[i].Error);
        }
        /* A target that failed to load is gone. (Windows keeps a target
         * that loaded but lacks the export, ReactOS unloads it) */
        ok(GetModuleHandleW(L"ldrfw_bad.dll") == NULL, "ldrfw_bad.dll stays loaded after %s\n", Bad[i].Name);
    }
    ok(FreeLibrary(Fwd), "FreeLibrary failed: %lu\n", GetLastError());
    ok(GetModuleHandleW(L"ldrfw_fwd.dll") == NULL, "ldrfw_fwd.dll stays loaded\n");

    /* Every listed module is still mapped */
    CheckModuleList(&GetLdrData()->InLoadOrderModuleList, FIELD_OFFSET(FW_LDR_ENTRY, InLoadOrderLinks),
                    "load-order list", "after GetProcAddress", FALSE);
}

#ifdef __REACTOS__
/* Loads Dir\File through LoadGuarded. FALSE on a hang */
static
BOOL
TryLoad(PCWSTR Dir, PCWSTR File, LOADREQ *Req)
{
    ZeroMemory(Req, sizeof(*Req));
    StringCchPrintfW(Req->Path, _countof(Req->Path), L"%ls\\%ls", Dir, File);
    if (LoadGuarded(Req))
        return TRUE;
    ok(0, "LoadLibraryW(%ls) did not return within %lu ms\n", File, (ULONG)LOAD_TIMEOUT);
    Hung = TRUE;
    return FALSE;
}

/* A normal failure after a malformed load: the failed module is unloaded
 * each time (the sweep of the failed load runs), so the retry fails again */
static
VOID
CheckAfterMalformed(PCWSTR Dir, PCSTR What)
{
    static LOADREQ Req; /* static: outlives a stuck thread */
    static const PCWSTR Canaries[] = { L"ldrfw_u_name.dll", L"ldrfw_u_newdll.dll", L"ldrfw_u_neword.dll",
                                       L"ldrfw_u_badimp.dll" };
    ULONG n, i, h;

    for (i = 0; i < _countof(Canaries) && !Hung; i++)
    {
        for (n = 0; n < 3 && !Hung; n++)
        {
            if (!TryLoad(Dir, Canaries[i], &Req))
                return;
            ok(Req.Module == NULL, "after %s: LoadLibraryW(%ls) #%lu succeeded: %p\n",
               What, Canaries[i], n, Req.Module);
            if (Req.Module)
                FreeLibrary(Req.Module);
            ok(GetModuleHandleW(Canaries[i]) == NULL, "after %s: %ls stays loaded after #%lu\n",
               What, Canaries[i], n);
            for (h = 0; h < _countof(Helpers); h++)
                ok(GetModuleHandleW(Helpers[h]) == NULL, "after %s: %ls stays loaded after %ls #%lu\n",
                   What, Helpers[h], Canaries[i], n);
        }
    }
}

/* Starts Dir\Exe (its imports are searched in Dir) and returns its exit
 * code, 0xdead when it did not end in time */
static
DWORD
RunStartupExe(PCWSTR Dir, PCWSTR ExePath)
{
    WCHAR CmdLine[MAX_PATH + 4];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    DWORD Code = 0xdeadbeef;

    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    StringCchPrintfW(CmdLine, _countof(CmdLine), L"\"%ls\"", ExePath);
    if (!CreateProcessW(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, Dir, &Si, &Pi))
        return GetLastError();
    if (WaitForSingleObject(Pi.hProcess, LOAD_TIMEOUT) != WAIT_OBJECT_0)
    {
        TerminateProcess(Pi.hProcess, 0xdead);
        WaitForSingleObject(Pi.hProcess, 5000);
        Code = 0xdead;
    }
    else
    {
        GetExitCodeProcess(Pi.hProcess, &Code);
    }
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return Code;
}

/*
 * A forwarder target whose import directory is malformed (the name of its
 * import is out of the image) makes the loader fault inside the nested import
 * walk. The walk fails with the status of the exception, and the load fails
 * like any other failed import: it unloads what it mapped, the malformed
 * target included. A retry fails again (instead of finding the target mapped
 * with its imports unsnapped and "succeeding"), and a failed load afterwards
 * still unloads what it mapped (the loader does not believe an import walk is
 * still running). LoadLibrary fails with the exception status; GetProcAddress
 * reports a missing procedure, as for any target that cannot be loaded. A
 * process whose static imports hit the image ends with the exception status
 */
static
VOID
TestMalformed(PCWSTR Dir)
{
    static LOADREQ Req;
    static const PCWSTR Mal[] = { L"ldrfw_u_mal.dll", L"ldrmal_tgt.dll", L"ldrmal_gpa.dll" };
    WCHAR Path[MAX_PATH];
    HMODULE Fwd;
    FARPROC Proc;
    DWORD Code;
    UINT OldMode;
    ULONG n, m;

    /* Through the import walk of a DLL, again and again */
    for (n = 0; n < 3; n++)
    {
        if (!TryLoad(Dir, L"ldrfw_u_mal.dll", &Req))
            return;
        ok(Req.Module == NULL, "LoadLibraryW(ldrfw_u_mal.dll) #%lu succeeded: %p\n", n, Req.Module);
        ok(Req.Error == ERROR_NOACCESS, "LoadLibraryW(ldrfw_u_mal.dll) #%lu error %lu, expected %lu\n",
           n, Req.Error, (ULONG)ERROR_NOACCESS);
        if (Req.Module)
            FreeLibrary(Req.Module);
        for (m = 0; m < _countof(Mal); m++)
            ok(GetModuleHandleW(Mal[m]) == NULL, "%ls stays loaded after LoadLibraryW(ldrfw_u_mal.dll) #%lu\n", Mal[m], n);
    }
    CheckAfterMalformed(Dir, "the LoadLibrary of a malformed forwarder target");

    /* Through GetProcAddress */
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_fwd.dll", Dir);
    Fwd = LoadLibraryExW(Path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    ok(Fwd != NULL, "LoadLibraryW(ldrfw_fwd.dll) failed: %lu\n", GetLastError());
    if (Fwd)
    {
        for (n = 0; n < 3; n++)
        {
            SetLastError(0xdeadbeef);
            Proc = GetProcAddress(Fwd, "FwdMal2");
            ok(Proc == NULL, "GetProcAddress(FwdMal2) #%lu = %p\n", n, Proc);
            ok(GetLastError() == ERROR_PROC_NOT_FOUND, "GetProcAddress(FwdMal2) #%lu error %lu, expected %lu\n",
               n, GetLastError(), (ULONG)ERROR_PROC_NOT_FOUND);
            ok(GetModuleHandleW(L"ldrmal_gpa.dll") == NULL, "ldrmal_gpa.dll stays loaded after GetProcAddress #%lu\n", n);
        }
        FreeLibrary(Fwd);
        CheckAfterMalformed(Dir, "the GetProcAddress of a malformed forwarder target");
    }

    /* At process start: through the DLL that imports the forwarder, and directly */
    OldMode = SetErrorMode(SEM_FAILCRITICALERRORS);
    for (n = 0; n < 2; n++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrmal_exe%lu.exe", Dir, n);
        if (!(n ? WriteFwImage(Path, FALSE, NULL, "ldrmal_tgt.dll", "Foo", 0, NULL, 0) :
                  WriteFwImage(Path, FALSE, NULL, "ldrfw_u_mal.dll", "Foo", 0, NULL, 0)))
        {
            ok(0, "Cannot write %ls: %lu\n", Path, GetLastError());
            continue;
        }
        Code = RunStartupExe(Dir, Path);
        ok(Code == (DWORD)STATUS_ACCESS_VIOLATION, "EXE importing %s: exit code 0x%lx, expected 0x%lx\n",
           n ? "ldrmal_tgt.dll" : "ldrfw_u_mal.dll", Code, (DWORD)STATUS_ACCESS_VIOLATION);
        DeleteFileW(Path);
    }
    SetErrorMode(OldMode);
}

#endif /* __REACTOS__ */

static
BOOL
IsLoadedW(PCWSTR Name)
{
    return GetModuleHandleW(Name) != NULL;
}

/* Which of the helper DLLs are loaded now */
static
ULONG
LoadedHelpers(VOID)
{
    ULONG Mask = 0, h;

    for (h = 0; h < _countof(Helpers); h++)
    {
        if (IsLoadedW(Helpers[h]))
            Mask |= 1UL << h;
    }
    return Mask;
}

/*
 * Images with several imports. A forwarder that resolved while an import was
 * snapped keeps its target loaded, and a later import of the same image that
 * fails must not leave that target (or the DLL that forwards to it) behind
 */
typedef struct _MULTICASE
{
    PCWSTR File;
    FWIMPORT Imports[MAX_IMPORTS];
    ULONG ImportCount;
    DWORD LoadError;        /* 0 = it loads */
    LONG HardErrors;        /* NtRaiseHardError calls during one LoadLibrary */
    PCWSTR HardName;        /* the entry point the hard error names, NULL = not checked */
    ULONG Loaded;           /* helpers loaded after the LoadLibrary (failed or not) */
    ULONG AfterFree;        /* helpers loaded after FreeLibrary of the module that loaded */
} MULTICASE;

#define FWD_TGT_FOO     { "FwdTgtFoo" }
static const MULTICASE MultiCases[] =
{
    /* Control: loads, the forwarder target stays while the image is loaded */
    { L"ldrfw_m_ok.dll", { { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { "kernel32.dll", { "Sleep" }, { 0 }, 1 } }, 2,
      0, 0, NULL, H_FWD | H_TGT, 0 },
    { L"ldrfw_m_chok.dll", { { "ldrfw_fwd.dll", { "FwdChainOk" }, { 0 }, 1 }, { "kernel32.dll", { "Sleep" }, { 0 }, 1 } }, 2,
      0, 0, NULL, H_FWD | H_TGT | H_CHAIN | H_CHAIN2, 0 },
    /* A resolved forwarder, then another import fails */
    { L"ldrfw_m_name.dll", { { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { "kernel32.dll", { "LdrFwNoSuchExport" }, { 0 }, 1 } }, 2,
      ERROR_PROC_NOT_FOUND, 1, L"LdrFwNoSuchExport", 0, 0 },
    { L"ldrfw_m_ord.dll", { { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { "kernel32.dll", { NULL }, { 32000 }, 1 } }, 2,
      ERROR_INVALID_ORDINAL, 1, NULL, 0, 0 },
    { L"ldrfw_m_nodll.dll", { { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { "ldrfw_nonexistent.dll", { "Foo" }, { 0 }, 1 } }, 2,
      ERROR_MOD_NOT_FOUND, 0, NULL, 0, 0 },
    { L"ldrfw_m_chname.dll", { { "ldrfw_fwd.dll", { "FwdChainOk" }, { 0 }, 1 }, { "kernel32.dll", { "LdrFwNoSuchExport" }, { 0 }, 1 } }, 2,
      ERROR_PROC_NOT_FOUND, 1, L"LdrFwNoSuchExport", 0, 0 },
    /* A resolved forwarder, then a forwarder that fails, in one descriptor and in two */
    { L"ldrfw_m_same.dll", { { "ldrfw_fwd.dll", { "FwdTgtFoo", "FwdNewDll" }, { 0 }, 2 } }, 1,
      ERROR_PROC_NOT_FOUND, 1, L"FwdNewDll", 0, 0 },
    { L"ldrfw_m_two.dll", { { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { "ldrfw_fwd.dll", { "FwdNewDll" }, { 0 }, 1 } }, 2,
      ERROR_PROC_NOT_FOUND, 1, L"FwdNewDll", 0, 0 },
    { L"ldrfw_m_twoord.dll", { { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { "ldrfw_fwd.dll", { "FwdNewOrd" }, { 0 }, 1 } }, 2,
      ERROR_INVALID_ORDINAL, 0, NULL, 0, 0 },
    { L"ldrfw_m_twodll.dll", { { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { "ldrfw_fwd.dll", { "FwdBadDll" }, { 0 }, 1 } }, 2,
      ERROR_MOD_NOT_FOUND, 0, NULL, 0, 0 },
};

/*
 * Bound images. A binding that is stale (the time stamp of the DLL is not the
 * recorded one) is snapped again from the import names, with the same
 * results as an image that is not bound
 */
typedef struct _BOUNDCASE
{
    PCWSTR File;
    FWIMPORT Import;
    FWBOUND Bound;
    DWORD LoadError;
    LONG HardErrors;
    PCWSTR HardName;
    ULONG Loaded;
    ULONG AfterFree;
} BOUNDCASE;

static const BOUNDCASE BoundCases[] =
{
    { L"ldrfw_b_ok.dll",   { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { 1, NULL, 0 },
      0, 0, NULL, H_FWD | H_TGT, 0 },
    { L"ldrfw_b_ref.dll",  { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { 1, "ldrfw_tgt.dll", 1 },
      0, 0, NULL, H_FWD | H_TGT, 0 },
    /* The binding to ldrfw_fwd.dll is stale, the one to the forwarder target is current: snapped again nevertheless
     * (not measured on Windows 10, which snapped every binding the probe had: a stale one cannot be trusted) */
    { L"ldrfw_b_stref.dll", { "ldrfw_fwd.dll", FWD_TGT_FOO, { 0 }, 1 }, { 1, "ldrfw_tgt.dll", 0 },
      0, 0, NULL, H_FWD | H_TGT, 0 },
    { L"ldrfw_b_name.dll", { "ldrfw_fwd.dll", { "FwdName" }, { 0 }, 1 }, { 1, NULL, 0 },
      ERROR_PROC_NOT_FOUND, 1, L"FwdName", 0, 0 },
    { L"ldrfw_b_nd.dll",   { "ldrfw_fwd.dll", { "FwdNewDll" }, { 0 }, 1 }, { 1, NULL, 0 },
      ERROR_PROC_NOT_FOUND, 1, L"FwdNewDll", 0, 0 },
    { L"ldrfw_b_two.dll",  { "ldrfw_fwd.dll", { "FwdTgtFoo", "FwdNewDll" }, { 0 }, 2 }, { 1, NULL, 0 },
      ERROR_PROC_NOT_FOUND, 1, L"FwdNewDll", 0, 0 },
    { L"ldrfw_b_ord.dll",  { "ldrfw_fwd.dll", { "FwdNewOrd" }, { 0 }, 1 }, { 1, NULL, 0 },
      ERROR_INVALID_ORDINAL, 0, NULL, 0, 0 },
    { L"ldrfw_b_dll.dll",  { "ldrfw_fwd.dll", { "FwdBadDll" }, { 0 }, 1 }, { 1, NULL, 0 },
      ERROR_MOD_NOT_FOUND, 0, NULL, 0, 0 },
    { L"ldrfw_b_c3.dll",   { "ldrfw_fwd.dll", { "FwdChain3" }, { 0 }, 1 }, { 1, NULL, 0 },
      ERROR_PROC_NOT_FOUND, 1, L"FwdChain3", 0, 0 },
};

/* Reads the first thunk of the IAT of a loaded image */
static
ULONG_PTR
FirstIatEntry(HMODULE Module)
{
    return (ULONG_PTR)*(THUNK *)((PBYTE)Module + IMG_SECT_ALIGN + OFF_IAT);
}

/*
 * Loads Dir\File ten times and checks the error, the hard errors, which
 * helpers are loaded afterwards (and after FreeLibrary), and that the loader
 * lists are as before
 */
static
VOID
CheckLoad(PCWSTR Dir, PCWSTR File, DWORD LoadError, LONG HardErrors, PCWSTR HardName, ULONG Loaded, ULONG AfterFree,
          const LISTCOUNT *Before, ULONG_PTR *Iat, ULONG_PTR *Resolved)
{
    CHAR Where[64];
    ULONG n;
    LISTCOUNT After;

    for (n = 0; n < 3 && !Hung; n++)
    {
        static LOADREQ Req; /* static: outlives a stuck thread */
        LONG HardErrorsBefore = HardErrorCount;
        ULONG Mask;

        ZeroMemory(&Req, sizeof(Req));
        StringCchPrintfW(Req.Path, _countof(Req.Path), L"%ls\\%ls", Dir, File);
        if (!LoadGuarded(&Req))
        {
            ok(0, "LoadLibraryW(%ls) #%lu did not return within %lu ms\n", File, n, (ULONG)LOAD_TIMEOUT);
            Hung = TRUE;
            return;
        }
        Mask = LoadedHelpers();
        trace("OBS %ls #%lu: module %p error %lu hard %ld helpers 0x%lx\n", File, n, Req.Module, Req.Error,
              HardErrorCount - HardErrorsBefore, Mask);
        ok(HardErrorCount - HardErrorsBefore == HardErrors, "LoadLibraryW(%ls) #%lu raised %ld hard errors (last 0x%lx), expected %ld\n",
           File, n, HardErrorCount - HardErrorsBefore, (ULONG)HardErrorLast, HardErrors);
        if (HardName && HardErrorCount != HardErrorsBefore)
            ok(!_wcsicmp(HardErrorName, HardName), "LoadLibraryW(%ls) #%lu: the hard error names %ls, expected %ls\n",
               File, n, HardErrorName, HardName);
        ok(Mask == Loaded, "LoadLibraryW(%ls) #%lu: helpers loaded 0x%lx, expected 0x%lx\n", File, n, Mask, Loaded);
        if (!LoadError)
        {
            ok(Req.Module != NULL, "LoadLibraryW(%ls) #%lu failed: %lu\n", File, n, Req.Error);
            if (Req.Module)
            {
                if (Iat && n == 0)
                {
                    HMODULE FwdDll = GetModuleHandleW(L"ldrfw_fwd.dll");

                    *Iat = FirstIatEntry(Req.Module);
                    *Resolved = FwdDll ? (ULONG_PTR)GetProcAddress(FwdDll, "FwdTgtFoo") : 0;
                }
                ok(FreeLibrary(Req.Module), "FreeLibrary(%ls) failed: %lu\n", File, GetLastError());
                Mask = LoadedHelpers();
                trace("OBS %ls #%lu after FreeLibrary: helpers 0x%lx, module loaded %d\n", File, n, Mask, IsLoadedW(File));
                ok(Mask == AfterFree, "%ls #%lu: helpers loaded after FreeLibrary 0x%lx, expected 0x%lx\n", File, n, Mask, AfterFree);
                ok(!IsLoadedW(File), "%ls stays loaded after FreeLibrary #%lu\n", File, n);
            }
        }
        else
        {
            ok(Req.Module == NULL, "LoadLibraryW(%ls) #%lu succeeded: %p\n", File, n, Req.Module);
            ok(Req.Error == LoadError, "LoadLibraryW(%ls) #%lu error %lu, expected %lu\n", File, n, Req.Error, LoadError);
            if (Req.Module)
                FreeLibrary(Req.Module);
            ok(!IsLoadedW(File), "%ls stays loaded after #%lu\n", File, n);
        }
        /* Get rid of what a leak of the loader keeps, to see each load on its own */
        for (Mask = 0; Mask < _countof(Helpers); Mask++)
        {
            HMODULE Leaked = GetModuleHandleW(Helpers[Mask]);

            if (Leaked && !((LoadError ? Loaded : AfterFree) & (1UL << Mask)))
            {
                ULONG k;

                for (k = 0; k < 8 && GetModuleHandleW(Helpers[Mask]); k++)
                    FreeLibrary(Leaked);
            }
        }
    }
    StringCchPrintfA(Where, _countof(Where), "after %ls", File);
    CheckModuleLists(&After, Where);
    ok(After.Load == Before->Load && After.Memory == Before->Memory && After.Init == Before->Init,
       "after %ls: %ld/%ld/%ld modules (load/memory/init order), before %ld/%ld/%ld\n", File,
       After.Load, After.Memory, After.Init, Before->Load, Before->Memory, Before->Init);
}

static
VOID
TestMulti(PCWSTR Dir)
{
    LISTCOUNT Before;
    ULONG i;

    CheckModuleLists(&Before, "before multi");
    for (i = 0; i < _countof(MultiCases) && !Hung; i++)
    {
        const MULTICASE *Case = &MultiCases[i];

        CheckLoad(Dir, Case->File, Case->LoadError, Case->HardErrors, Case->HardName, Case->Loaded, Case->AfterFree,
                  &Before, NULL, NULL);
    }
}

static
VOID
TestBound(PCWSTR Dir)
{
    LISTCOUNT Before;
    ULONG i;

    CheckModuleLists(&Before, "before bound");
    for (i = 0; i < _countof(BoundCases) && !Hung; i++)
    {
        const BOUNDCASE *Case = &BoundCases[i];
        ULONG_PTR Iat = 0, Resolved = 0;

        CheckLoad(Dir, Case->File, Case->LoadError, Case->HardErrors, Case->HardName, Case->Loaded, Case->AfterFree,
                  &Before, &Iat, &Resolved);
        if (Case->LoadError || Hung)
            continue;

        /* The IAT of a successful load is snapped again (Windows 10 does so for a current binding too; not tested: ReactOS keeps the bound IAT then) */
        trace("OBS %ls: first IAT entry 0x%lx (prebound 0x%lx), the forwarder resolves to 0x%lx\n", Case->File,
              (ULONG)Iat, (ULONG)PREBOUND, (ULONG)Resolved);
        ok(Resolved != 0 && Iat == Resolved, "%ls: the IAT holds 0x%lx, the forwarder resolves to 0x%lx\n",
           Case->File, (ULONG)Iat, (ULONG)Resolved);
    }
}

/*
 * What the loader tells the system when a process cannot start because of a
 * forwarder: the process is started under a debugger, and its first call of
 * NtRaiseHardError is caught (int 3 at its entry) and its arguments read
 */
typedef struct _STARTERR
{
    BOOL Captured;
    BOOL Ended;
    DWORD ExitCode;
    NTSTATUS Status;
    ULONG Count;
    ULONG Mask;
    WCHAR Str[2][MAX_PATH];
    ULONG_PTR Val[2];
} STARTERR;

static
VOID
ReadChildString(HANDLE Process, ULONG_PTR Address, PWCHAR Out)
{
    UNICODE_STRING Us;
    SIZE_T Done;

    Out[0] = 0;
    if (!ReadProcessMemory(Process, (PVOID)Address, &Us, sizeof(Us), &Done) || Done != sizeof(Us))
        return;
    if (Us.Length >= (MAX_PATH - 1) * sizeof(WCHAR))
        Us.Length = (MAX_PATH - 1) * sizeof(WCHAR);
    if (!ReadProcessMemory(Process, Us.Buffer, Out, Us.Length, &Done))
        return;
    Out[Us.Length / sizeof(WCHAR)] = 0;
}

static
BOOL
CaptureStartupHardError(PCWSTR Dir, PCWSTR ExePath, STARTERR *Out)
{
    WCHAR CmdLine[MAX_PATH + 4];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    DEBUG_EVENT Ev;
    PBYTE Target = (PBYTE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtRaiseHardError");
    BYTE Orig = 0, Int3 = 0xCC;
    SIZE_T Done;
    BOOL Armed = FALSE, Running = TRUE;
    DWORD Start;
    UINT OldMode;

    ZeroMemory(Out, sizeof(*Out));
    ZeroMemory(&Si, sizeof(Si));
    Si.cb = sizeof(Si);
    StringCchPrintfW(CmdLine, _countof(CmdLine), L"\"%ls\"", ExePath);
    OldMode = SetErrorMode(SEM_FAILCRITICALERRORS);
    if (!CreateProcessW(NULL, CmdLine, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, Dir, &Si, &Pi))
    {
        SetErrorMode(OldMode);
        return FALSE;
    }
    Start = GetTickCount();
    while (Running && GetTickCount() - Start < LOAD_TIMEOUT)
    {
        DWORD Continue = DBG_CONTINUE;

        if (!WaitForDebugEvent(&Ev, 1000))
            continue;
        switch (Ev.dwDebugEventCode)
        {
            case CREATE_PROCESS_DEBUG_EVENT:
                if (Ev.u.CreateProcessInfo.hFile)
                    CloseHandle(Ev.u.CreateProcessInfo.hFile);
                if (Target &&
                    ReadProcessMemory(Pi.hProcess, Target, &Orig, 1, &Done) && Done == 1 &&
                    WriteProcessMemory(Pi.hProcess, Target, &Int3, 1, &Done) && Done == 1)
                {
                    FlushInstructionCache(Pi.hProcess, Target, 1);
                    Armed = TRUE;
                }
                break;
            case LOAD_DLL_DEBUG_EVENT:
                if (Ev.u.LoadDll.hFile)
                    CloseHandle(Ev.u.LoadDll.hFile);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                Out->Ended = TRUE;
                Out->ExitCode = Ev.u.ExitProcess.dwExitCode;
                Running = FALSE;
                break;
            case EXCEPTION_DEBUG_EVENT:
                /* 0x4000001F: the initial breakpoint of a 32-bit process on a 64-bit system */
                if (Ev.u.Exception.ExceptionRecord.ExceptionCode == 0x4000001F)
                    break;
                if (Ev.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT)
                {
                    Continue = DBG_EXCEPTION_NOT_HANDLED;
                    break;
                }
                if (Armed && !Out->Captured && (PBYTE)Ev.u.Exception.ExceptionRecord.ExceptionAddress == Target)
                {
                    HANDLE Thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, Ev.dwThreadId);
                    CONTEXT Ctx;
                    ULONG_PTR Params = 0, Vals[4] = { 0 };
                    ULONG i;

                    ZeroMemory(&Ctx, sizeof(Ctx));
                    Ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                    if (Thread && GetThreadContext(Thread, &Ctx))
                    {
#ifdef _WIN64
                        Out->Status = (NTSTATUS)Ctx.Rcx;
                        Out->Count = (ULONG)Ctx.Rdx;
                        Out->Mask = (ULONG)Ctx.R8;
                        Params = Ctx.R9;
#else
                        ULONG Args[5] = { 0 };

                        ReadProcessMemory(Pi.hProcess, (PVOID)(ULONG_PTR)Ctx.Esp, Args, sizeof(Args), &Done);
                        Out->Status = (NTSTATUS)Args[1];
                        Out->Count = Args[2];
                        Out->Mask = Args[3];
                        Params = Args[4];
#endif
                        if (Out->Count > 4)
                            Out->Count = 4;
                        if (Params)
                            ReadProcessMemory(Pi.hProcess, (PVOID)Params, Vals, Out->Count * sizeof(ULONG_PTR), &Done);
                        for (i = 0; i < 2 && i < Out->Count; i++)
                        {
                            Out->Val[i] = Vals[i];
                            if (Out->Mask & (1UL << i))
                                ReadChildString(Pi.hProcess, Vals[i], Out->Str[i]);
                        }
                        Out->Captured = TRUE;

                        /* Put the instruction back and run it */
                        WriteProcessMemory(Pi.hProcess, Target, &Orig, 1, &Done);
                        FlushInstructionCache(Pi.hProcess, Target, 1);
#ifdef _WIN64
                        Ctx.Rip = (ULONG_PTR)Target;
#else
                        Ctx.Eip = (ULONG_PTR)Target;
#endif
                        SetThreadContext(Thread, &Ctx);
                    }
                    if (Thread)
                        CloseHandle(Thread);
                }
                break;
        }
        ContinueDebugEvent(Ev.dwProcessId, Ev.dwThreadId, Continue);
    }
    if (Running)
    {
        TerminateProcess(Pi.hProcess, 0xdead);
        WaitForSingleObject(Pi.hProcess, 5000);
    }
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    SetErrorMode(OldMode);
    return TRUE;
}

typedef struct _STARTERRCASE
{
    PCSTR Name;                 /* for the messages */
    PCSTR Dll;                  /* the import of the EXE */
    PCSTR Import;
    NTSTATUS Status;            /* exit code and the status of the hard error */
    PCWSTR Param0;              /* first parameter (a string), NULL = not checked */
} STARTERRCASE;

static const STARTERRCASE StartErrCases[] =
{
    { "plain",    "ldrfw_nonexistent.dll", "Foo",          STATUS_DLL_NOT_FOUND, L"ldrfw_nonexistent.dll" },
    { "fwd-nodll", "ldrfw_fwd.dll",        "FwdNoDll",     STATUS_DLL_NOT_FOUND, L"ldrfw_nonexistent.DLL" },
    { "fwd-bad",   "ldrfw_fwd.dll",        "FwdBadDll",    STATUS_DLL_NOT_FOUND, L"ldrfw_nonexistent_dep.dll" },
    { "fwd-c3dll", "ldrfw_fwd.dll",        "FwdChain3Dll", STATUS_DLL_NOT_FOUND, L"ldrfw_nonexistent.DLL" },
};

static
VOID
TestStartupHardErrors(PCWSTR Dir)
{
    WCHAR ExePath[MAX_PATH];
    STARTERR Err;
    ULONG i;

    for (i = 0; i < _countof(StartErrCases) && !Hung; i++)
    {
        const STARTERRCASE *Case = &StartErrCases[i];

        StringCchPrintfW(ExePath, _countof(ExePath), L"%ls\\ldrfw_hexe%lu.exe", Dir, i);
        if (!WriteFwImage(ExePath, FALSE, NULL, Case->Dll, Case->Import, 0, NULL, 0))
        {
            ok(0, "Cannot write %ls: %lu\n", ExePath, GetLastError());
            continue;
        }
        if (!CaptureStartupHardError(Dir, ExePath, &Err))
        {
            skip("Cannot start %ls under a debugger: %lu\n", ExePath, GetLastError());
            DeleteFileW(ExePath);
            continue;
        }
        trace("OBS startup %s: ended %d exit 0x%lx, hard error %d status 0x%lx count %lu mask %lu val0 0x%lx val1 0x%lx '%ls' '%ls'\n",
              Case->Name, Err.Ended, Err.ExitCode, Err.Captured, (ULONG)Err.Status, Err.Count, Err.Mask,
              (ULONG)Err.Val[0], (ULONG)Err.Val[1], Err.Str[0], Err.Str[1]);
        ok(Err.Ended, "%s: the process did not end\n", Case->Name);
        ok(Err.ExitCode == (DWORD)Case->Status, "%s: exit code 0x%lx, expected 0x%lx\n", Case->Name, Err.ExitCode, (DWORD)Case->Status);
        if (Err.Captured)
        {
            ok(Err.Status == Case->Status, "%s: the hard error is 0x%lx, expected 0x%lx\n", Case->Name, (ULONG)Err.Status, (ULONG)Case->Status);
            ok(Err.Count >= 1 && (Err.Mask & 1), "%s: the hard error has %lu parameters, mask %lu\n", Case->Name, Err.Count, Err.Mask);
            if (Case->Param0)
                ok(!wcscmp(Err.Str[0], Case->Param0), "%s: the hard error names '%ls', expected '%ls'\n", Case->Name,
                   Err.Str[0], Case->Param0);
        }
        else
        {
            skip("%s: no hard error caught\n", Case->Name);
        }
        DeleteFileW(ExePath);
    }
}

/* A process whose static import fails ends with the loader's status. The
 * error mode of this process is inherited by the child, so the system does
 * not show the error */
static
VOID
TestStartup(PCWSTR Dir)
{
    WCHAR ExePath[MAX_PATH], CmdLine[MAX_PATH + 4];
    STARTUPINFOW Si;
    PROCESS_INFORMATION Pi;
    UINT OldMode;
    DWORD Code, Wait;
    ULONG i;

    OldMode = SetErrorMode(SEM_FAILCRITICALERRORS);
    for (i = 0; i < 2 * _countof(Cases); i++)
    {
        CHAR Dll[64];
        /* First the EXE imports the DLL that imports the forwarder. Then it
         * imports the forwarded export itself from ldrfw_fwd.dll, as an
         * application does from a forwarding DLL next to it */
        const FWCASE *Case = &Cases[i % _countof(Cases)];
        BOOL Direct = (i >= _countof(Cases));

        /* Only the failures: a process that starts may be kept alive for a
         * while by the loader's worker threads on Windows 10 */
        if (!Case->StartStatus)
            continue;

        StringCchPrintfW(ExePath, _countof(ExePath), L"%ls\\ldrfw_exe%lu.exe", Dir, i);
        WideCharToMultiByte(CP_ACP, 0, Case->File, -1, Dll, sizeof(Dll), NULL, NULL);
        if (!(Direct ? WriteFwImage(ExePath, FALSE, NULL, Case->From ? Case->From : "ldrfw_fwd.dll", Case->Name, Case->Ordinal,
                                    NULL, 0) :
                       WriteFwImage(ExePath, FALSE, NULL, Dll, "Foo", 0, NULL, 0)))
        {
            ok(0, "Cannot write %ls: %lu\n", ExePath, GetLastError());
            continue;
        }
        ZeroMemory(&Si, sizeof(Si));
        Si.cb = sizeof(Si);
        StringCchPrintfW(CmdLine, _countof(CmdLine), L"\"%ls\"", ExePath);
        /* The current directory (the test directory) is searched for the forwarder targets */
        if (!CreateProcessW(NULL, CmdLine, NULL, NULL, FALSE, 0, NULL, Dir, &Si, &Pi))
        {
            ok(0, "CreateProcessW(%ls) failed: %lu\n", ExePath, GetLastError());
            DeleteFileW(ExePath);
            continue;
        }
        Wait = WaitForSingleObject(Pi.hProcess, LOAD_TIMEOUT);
        ok(Wait == WAIT_OBJECT_0, "%ls%s did not end within %lu ms\n", Case->File, Direct ? " (direct)" : "",
           (ULONG)LOAD_TIMEOUT);
        if (Wait != WAIT_OBJECT_0)
        {
            TerminateProcess(Pi.hProcess, 0xdead);
            WaitForSingleObject(Pi.hProcess, 5000);
        }
        else
        {
            Code = 0xdeadbeef;
            GetExitCodeProcess(Pi.hProcess, &Code);
            ok(Code == (DWORD)Case->StartStatus, "EXE importing %s%ls: exit code 0x%lx, expected 0x%lx\n",
               Direct ? "the forwarder of " : "", Case->File, Code, (DWORD)Case->StartStatus);
        }
        CloseHandle(Pi.hThread);
        CloseHandle(Pi.hProcess);
        DeleteFileW(ExePath);
    }
    SetErrorMode(OldMode);
}

/*
 * Answers the hard errors of the loader in this process with "return to
 * caller" instead of sending them to the system: a missing export is reported
 * to the system for a LoadLibrary too, and the message box would wait
 */
static
NTSTATUS
NTAPI
HookedRaiseHardError(NTSTATUS ErrorStatus,
                     ULONG NumberOfParameters,
                     ULONG UnicodeStringParameterMask,
                     PULONG_PTR Parameters,
                     ULONG ValidResponseOptions,
                     PULONG Response)
{
    HardErrorName[0] = HardErrorDll[0] = 0;
    HardErrorOrdinal = 0;
    if (ErrorStatus == STATUS_ENTRYPOINT_NOT_FOUND && NumberOfParameters >= 2 && Parameters &&
        (UnicodeStringParameterMask & 3) == 3)
    {
        PUNICODE_STRING Entry = (PUNICODE_STRING)Parameters[0], Dll = (PUNICODE_STRING)Parameters[1];

        StringCchCopyNW(HardErrorName, _countof(HardErrorName), Entry->Buffer, Entry->Length / sizeof(WCHAR));
        StringCchCopyNW(HardErrorDll, _countof(HardErrorDll), Dll->Buffer, Dll->Length / sizeof(WCHAR));
    }
    else if (ErrorStatus == STATUS_ORDINAL_NOT_FOUND && NumberOfParameters >= 2 && Parameters &&
             (UnicodeStringParameterMask & 3) == 2)
    {
        PUNICODE_STRING Dll = (PUNICODE_STRING)Parameters[1];

        HardErrorOrdinal = (ULONG)Parameters[0];
        StringCchCopyNW(HardErrorDll, _countof(HardErrorDll), Dll->Buffer, Dll->Length / sizeof(WCHAR));
    }
    HardErrorLast = ErrorStatus;
    InterlockedIncrement(&HardErrorCount);
    if (Response)
        *Response = 0; /* ResponseReturnToCaller */
    return 0;
}

#ifdef _WIN64
#define PATCH_SIZE 12
#else
#define PATCH_SIZE 5
#endif

typedef struct _PATCH
{
    PBYTE Target;
    BYTE Saved[PATCH_SIZE];
    BOOL Active;
} PATCH;

static
BOOL
PatchInstall(PATCH *Patch, PCSTR Name)
{
    BYTE Code[PATCH_SIZE];
    DWORD OldProtect;

    Patch->Active = FALSE;
    Patch->Target = (PBYTE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), Name);
    if (!Patch->Target)
        return FALSE;
#ifdef _WIN64
    Code[0] = 0x48; Code[1] = 0xB8;                         /* mov rax, imm64 */
    *(PULONGLONG)&Code[2] = (ULONGLONG)(ULONG_PTR)HookedRaiseHardError;
    Code[10] = 0xFF; Code[11] = 0xE0;                       /* jmp rax */
#else
    Code[0] = 0xE9;                                         /* jmp rel32 */
    *(PLONG)&Code[1] = (LONG)((PBYTE)HookedRaiseHardError - (Patch->Target + 5));
#endif
    if (!VirtualProtect(Patch->Target, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
        return FALSE;
    memcpy(Patch->Saved, Patch->Target, PATCH_SIZE);
    memcpy(Patch->Target, Code, PATCH_SIZE);
    FlushInstructionCache(GetCurrentProcess(), Patch->Target, PATCH_SIZE);
    VirtualProtect(Patch->Target, PATCH_SIZE, OldProtect, &OldProtect);
    Patch->Active = TRUE;
    return TRUE;
}

static
VOID
PatchRemove(PATCH *Patch)
{
    DWORD OldProtect;

    if (!Patch->Active)
        return;
    VirtualProtect(Patch->Target, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect);
    memcpy(Patch->Target, Patch->Saved, PATCH_SIZE);
    FlushInstructionCache(GetCurrentProcess(), Patch->Target, PATCH_SIZE);
    VirtualProtect(Patch->Target, PATCH_SIZE, OldProtect, &OldProtect);
    Patch->Active = FALSE;
}

START_TEST(LoadLibraryForwarder)
{
    WCHAR Dir[MAX_PATH], Path[MAX_PATH], OldDir[MAX_PATH];
    DWORD Length;
    ULONG i;
    BOOL Written = TRUE;
    PATCH NtPatch, ZwPatch;

    Length = GetTempPathW(_countof(Dir), Dir);
    if (!Length || FAILED(StringCchPrintfW(Dir + Length, _countof(Dir) - Length, L"ldrfw-%lu-%lu", GetCurrentProcessId(), GetTickCount())) ||
        !CreateDirectoryW(Dir, NULL))
    {
        skip("Cannot create the test directory: %lu\n", GetLastError());
        return;
    }

    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_fwd.dll", Dir);
    Written &= WriteFwImage(Path, TRUE, "ldrfw_fwd.dll", NULL, NULL, 0, FwdExports, _countof(FwdExports));
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_tgt.dll", Dir);
    Written &= WriteFwImage(Path, TRUE, "ldrfw_tgt.dll", NULL, NULL, 0, FooExport, 1);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_bad.dll", Dir);
    Written &= WriteFwImage(Path, TRUE, "ldrfw_bad.dll", "ldrfw_nonexistent_dep.dll", "Foo", 0, FooExport, 1);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_badimp.dll", Dir);
    Written &= WriteFwImage(Path, TRUE, "ldrfw_badimp.dll", "kernel32.dll", "LdrFwNoSuchExport", 0, FooExport, 1);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_chain.dll", Dir);
    Written &= WriteFwImage(Path, TRUE, "ldrfw_chain.dll", NULL, NULL, 0, ChainExports, _countof(ChainExports));
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_chain2.dll", Dir);
    Written &= WriteFwImage(Path, TRUE, "ldrfw_chain2.dll", NULL, NULL, 0, Chain2Exports, _countof(Chain2Exports));
    for (i = 0; i < _countof(MultiCases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%ls\\%ls", Dir, MultiCases[i].File);
        Written &= WriteFwImageEx(Path, TRUE, "ldrfw_u.dll", MultiCases[i].Imports, MultiCases[i].ImportCount, NULL, FooExport, 1);
    }
    for (i = 0; i < _countof(BoundCases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%ls\\%ls", Dir, BoundCases[i].File);
        Written &= WriteFwImageEx(Path, TRUE, "ldrfw_u.dll", &BoundCases[i].Import, 1, &BoundCases[i].Bound, FooExport, 1);
    }
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrmal_tgt.dll", Dir);
    BadImportNameRva = 0x7F000000;
    Written &= WriteFwImage(Path, TRUE, "ldrmal_tgt.dll", "kernel32.dll", "Sleep", 0, FooExport, 1);
    BadImportNameRva = 0;
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrmal_gpa.dll", Dir);
    BadImportNameRva = 0x7F000000;
    Written &= WriteFwImage(Path, TRUE, "ldrmal_gpa.dll", "kernel32.dll", "Sleep", 0, FooExport, 1);
    BadImportNameRva = 0;
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_u_mal.dll", Dir);
    Written &= WriteFwImage(Path, TRUE, "ldrfw_u.dll", "ldrfw_fwd.dll", "FwdMal", 0, FooExport, 1);
    for (i = 0; i < _countof(Cases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%ls\\%ls", Dir, Cases[i].File);
        Written &= WriteFwImage(Path, TRUE, "ldrfw_u.dll", Cases[i].From ? Cases[i].From : "ldrfw_fwd.dll",
                                Cases[i].Name, Cases[i].Ordinal, FooExport, 1);
    }
    ok(Written, "Cannot write the test images: %lu\n", GetLastError());

    if (Written)
    {
        /* The forwarder targets are found through the current directory */
        GetCurrentDirectoryW(_countof(OldDir), OldDir);
        SetCurrentDirectoryW(Dir);

        if (PatchInstall(&NtPatch, "NtRaiseHardError"))
        {
            if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwRaiseHardError") != (FARPROC)NtPatch.Target)
                PatchInstall(&ZwPatch, "ZwRaiseHardError");
            else
                ZwPatch.Active = FALSE;
#ifdef __REACTOS__
            /* Windows does not survive this image: the load never returns (measured on 10 22H2) */
            TestMalformed(Dir);
#endif
            if (!Hung)
                TestDynamic(Dir);
            if (!Hung)
                TestGetProcAddress(Dir);
            if (!Hung)
                TestMulti(Dir);
            if (!Hung)
                TestBound(Dir);
            PatchRemove(&ZwPatch);
            PatchRemove(&NtPatch);
        }
        else
        {
            skip("Cannot hook NtRaiseHardError\n");
        }
        if (!Hung)
            TestStartup(Dir);
        if (!Hung)
            TestStartupHardErrors(Dir);

        SetCurrentDirectoryW(OldDir);
    }

    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_fwd.dll", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_tgt.dll", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_bad.dll", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_badimp.dll", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_chain.dll", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_chain2.dll", Dir);
    DeleteFileW(Path);
    for (i = 0; i < _countof(MultiCases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%ls\\%ls", Dir, MultiCases[i].File);
        DeleteFileW(Path);
    }
    for (i = 0; i < _countof(BoundCases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%ls\\%ls", Dir, BoundCases[i].File);
        DeleteFileW(Path);
    }
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrmal_tgt.dll", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrmal_gpa.dll", Dir);
    DeleteFileW(Path);
    StringCchPrintfW(Path, _countof(Path), L"%ls\\ldrfw_u_mal.dll", Dir);
    DeleteFileW(Path);
    for (i = 0; i < _countof(Cases); i++)
    {
        StringCchPrintfW(Path, _countof(Path), L"%ls\\%ls", Dir, Cases[i].File);
        DeleteFileW(Path);
    }
    RemoveDirectoryW(Dir);

    if (Hung)
    {
        /* The stuck thread owns the loader lock, so ExitProcess would wait for it too */
        TerminateProcess(GetCurrentProcess(), 1);
    }
}
