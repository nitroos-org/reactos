/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Setup Library
 * FILE:            base/setup/lib/install.c
 * PURPOSE:         Installation functions
 * PROGRAMMERS:     Hervé Poussineau (hpoussin@reactos.org)
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"
#include "filesup.h"
#include "infsupp.h"

#include "setuplib.h" // HACK for USETUP_DATA
#include "components.h"

#include "install.h"

#define NDEBUG
#include <debug.h>


/* FUNCTIONS ****************************************************************/

static BOOL
LookupDirectoryById(
    IN HINF InfHandle,
    IN OUT PINFCONTEXT InfContext,
    IN PCWSTR DirId,
    OUT PCWSTR* pDirectory)
{
    BOOL Success;

    // ReactOS-specific
    Success = SpInfFindFirstLine(InfHandle, L"Directories", DirId, InfContext);
    if (!Success)
    {
        // Windows-compatible
        Success = SpInfFindFirstLine(InfHandle, L"WinntDirectories", DirId, InfContext);
        if (!Success)
            DPRINT1("SpInfFindFirstLine() failed\n");
    }
    if (Success)
    {
        Success = INF_GetData(InfContext, NULL, pDirectory);
        if (!Success)
            DPRINT1("INF_GetData() failed\n");
    }

    if (!Success)
        DPRINT1("LookupDirectoryById(%S) - directory not found!\n", DirId);

    return Success;
}

/*
 * Note: Modeled after SetupGetSourceFileLocation(), SetupGetSourceInfo()
 * and SetupGetTargetPath() APIs.
 * Technically the target path is the same for a given file section,
 * but here we try to remove this constraint.
 *
 * TXTSETUP.SIF entries syntax explained at:
 * https://msfn.org/board/topic/125480-txtsetupsif-syntax/
 */
static NTSTATUS
GetSourceFileAndTargetLocation(
    IN HINF InfHandle,
    IN PINFCONTEXT InfContext OPTIONAL,
    IN PCWSTR SourceFileName OPTIONAL,
    OUT PCWSTR* pSourceRootPath,
    OUT PCWSTR* pSourcePath,
    OUT PCWSTR* pTargetDirectory,
    OUT PCWSTR* pTargetFileName)
{
    BOOL Success;
    INFCONTEXT FileContext;
    INFCONTEXT DirContext;
    PCWSTR SourceRootDirId;
    PCWSTR SourceRootDir;
    PCWSTR SourceRelativePath;
    PCWSTR TargetDirId;
    PCWSTR TargetDir;
    PCWSTR TargetFileName;

    /* Either InfContext or SourceFileName must be specified */
    if (!InfContext && !SourceFileName)
        return STATUS_INVALID_PARAMETER;

    /* InfContext to a file was not given, retrieve one corresponding to SourceFileName */
    if (!InfContext)
    {
        /* Search for the SourceDisksFiles section */

        /* Search in the optional platform-specific first (currently hardcoded; make it runtime-dependent?) */
        Success = SpInfFindFirstLine(InfHandle, L"SourceDisksFiles." INF_ARCH, SourceFileName, &FileContext);
        if (!Success)
        {
            /* Search in the global section */
            Success = SpInfFindFirstLine(InfHandle, L"SourceDisksFiles", SourceFileName, &FileContext);
        }
        if (!Success)
        {
            // pSetupData->LastErrorNumber = ERROR_TXTSETUP_SECTION;
            // if (pSetupData->ErrorRoutine)
                // pSetupData->ErrorRoutine(pSetupData, SectionName);
            return STATUS_NOT_FOUND;
        }
        InfContext = &FileContext;
    }
    // else, InfContext != NULL and ignore SourceFileName (that may or may not be == NULL).

    /*
     * Getting Source File Location -- SetupGetSourceFileLocation()
     */

    /* Get source root directory id */
    if (!INF_GetDataField(InfContext, 1, &SourceRootDirId))
    {
        /* FIXME: Handle error! */
        DPRINT1("INF_GetData() failed\n");
        return STATUS_NOT_FOUND;
    }

    /* Lookup source root directory -- SetupGetSourceInfo() */
    /* Search in the optional platform-specific first (currently hardcoded; make it runtime-dependent?) */
    Success = SpInfFindFirstLine(InfHandle, L"SourceDisksNames." INF_ARCH, SourceRootDirId, &DirContext);
    if (!Success)
    {
        /* Search in the global section */
        Success = SpInfFindFirstLine(InfHandle, L"SourceDisksNames", SourceRootDirId, &DirContext);
        if (!Success)
            DPRINT1("SpInfFindFirstLine(\"SourceDisksNames\", \"%S\") failed\n", SourceRootDirId);
    }
    INF_FreeData(SourceRootDirId);
    if (!Success)
    {
        /* FIXME: Handle error! */
        // pSetupData->LastErrorNumber = ERROR_TXTSETUP_SECTION;
        // if (pSetupData->ErrorRoutine)
            // pSetupData->ErrorRoutine(pSetupData, SectionName);
        return STATUS_NOT_FOUND;
    }
    if (!INF_GetDataField(&DirContext, 4, &SourceRootDir))
    {
        /* FIXME: Handle error! */
        DPRINT1("INF_GetData() failed\n");
        return STATUS_NOT_FOUND;
    }

    /* Get optional source relative directory */
    if (!INF_GetDataField(InfContext, 2, &SourceRelativePath))
    {
        SourceRelativePath = NULL;
    }
    else if (!*SourceRelativePath)
    {
        INF_FreeData(SourceRelativePath);
        SourceRelativePath = NULL;
    }
    if (!SourceRelativePath)
    {
        /* Use WinPE directory instead */
        if (INF_GetDataField(InfContext, 13, &TargetDirId))
        {
            /* Lookup directory */
            Success = LookupDirectoryById(InfHandle, &DirContext, TargetDirId, &SourceRelativePath);
            INF_FreeData(TargetDirId);
            if (!Success)
            {
                SourceRelativePath = NULL;
            }
            else if (!*SourceRelativePath)
            {
                INF_FreeData(SourceRelativePath);
                SourceRelativePath = NULL;
            }
        }
    }

    /*
     * Getting Target File Location -- SetupGetTargetPath()
     */

    /* Get target directory id */
    if (!INF_GetDataField(InfContext, 8, &TargetDirId))
    {
        /* FIXME: Handle error! */
        DPRINT1("INF_GetData() failed\n");
        INF_FreeData(SourceRelativePath);
        INF_FreeData(SourceRootDir);
        return STATUS_NOT_FOUND;
    }

    /* Lookup target directory */
    Success = LookupDirectoryById(InfHandle, &DirContext, TargetDirId, &TargetDir);
    INF_FreeData(TargetDirId);
    if (!Success)
    {
        /* FIXME: Handle error! */
        INF_FreeData(SourceRelativePath);
        INF_FreeData(SourceRootDir);
        return STATUS_NOT_FOUND;
    }

    /* Get optional target file name */
    if (!INF_GetDataField(InfContext, 11, &TargetFileName))
        TargetFileName = NULL;
    else if (!*TargetFileName)
        TargetFileName = NULL;

    DPRINT("GetSourceFileAndTargetLocation(%S) = "
           "SrcRootDir: '%S', SrcRelPath: '%S' --> TargetDir: '%S', TargetFileName: '%S'\n",
           SourceFileName, SourceRootDir, SourceRelativePath, TargetDir, TargetFileName);

#if 0
    INF_FreeData(TargetDir);
    INF_FreeData(TargetFileName);
    INF_FreeData(SourceRelativePath);
    INF_FreeData(SourceRootDir);
#endif

    *pSourceRootPath  = SourceRootDir;
    *pSourcePath      = SourceRelativePath;
    *pTargetDirectory = TargetDir;
    *pTargetFileName  = TargetFileName;

    return STATUS_SUCCESS;
}

static NTSTATUS
BuildFullDirectoryPath(
    IN PCWSTR RootPath,
    IN PCWSTR BasePath,
    IN PCWSTR RelativePath,
    OUT PWSTR FullPath,
    IN SIZE_T cchFullPathSize)
{
    NTSTATUS Status;

    if ((RelativePath[0] == UNICODE_NULL) || (RelativePath[0] == L'\\' && RelativePath[1] == UNICODE_NULL))
    {
        /* Installation path */
        DPRINT("InstallationPath: '%S'\n", RelativePath);

        Status = CombinePaths(FullPath, cchFullPathSize, 2,
                              RootPath, BasePath);

        DPRINT("InstallationPath(2): '%S'\n", FullPath);
    }
    else if (RelativePath[0] == L'\\')
    {
        /* Absolute path */
        DPRINT("AbsolutePath: '%S'\n", RelativePath);

        Status = CombinePaths(FullPath, cchFullPathSize, 2,
                              RootPath, RelativePath);

        DPRINT("AbsolutePath(2): '%S'\n", FullPath);
    }
    else // if (RelativePath[0] != L'\\')
    {
        /* Path relative to the installation path */
        DPRINT("RelativePath: '%S'\n", RelativePath);

        Status = CombinePaths(FullPath, cchFullPathSize, 3,
                              RootPath, BasePath, RelativePath);

        DPRINT("RelativePath(2): '%S'\n", FullPath);
    }

    return Status;
}


/*
 * This code enumerates the list of files in reactos.dff / reactos.inf
 * that need to be extracted from reactos.cab and be installed in their
 * respective directories.
 */
/*
 * IMPORTANT NOTE: The INF file specification used for the .CAB in ReactOS
 * is not compliant with respect to TXTSETUP.SIF syntax or the standard syntax.
 */
static BOOLEAN
AddSectionToCopyQueueCab(
    IN PUSETUP_DATA pSetupData,
    IN HINF InfFile,
    IN PCWSTR SectionName,
    IN PCWSTR SourceCabinet,
    IN PCUNICODE_STRING DestinationPath)
{
    BOOLEAN Success;
    NTSTATUS Status;
    INFCONTEXT FilesContext;
    INFCONTEXT DirContext;
    PCWSTR SourceFileName;
    PCWSTR TargetDirId;
    PCWSTR TargetDir;
    PCWSTR TargetFileName;
    WCHAR FileDstPath[MAX_PATH];

    /* Search for the SectionName section */
    if (!SpInfFindFirstLine(InfFile, SectionName, NULL, &FilesContext))
    {
        DPRINT1("AddSectionToCopyQueueCab(): Unable to find section '%S' in cabinet file\n", SectionName);
        return FALSE;
    }

    /*
     * Enumerate the files in the section and add them to the file queue.
     */
    do
    {
        /* Read the fields separately: INF_GetData rejects entries with an
         * optional target file name (more than one value). */
        if (!INF_GetDataField(&FilesContext, 0, &SourceFileName))
        {
            /* FIXME: Handle error! */
            DPRINT1("Failed to get cabinet source file name\n");
            break;
        }
        if (!INF_GetDataField(&FilesContext, 1, &TargetDirId))
        {
            INF_FreeData(SourceFileName);
            DPRINT1("Failed to get cabinet target directory id\n");
            break;
        }

        /* Get optional target file name */
        if (!INF_GetDataField(&FilesContext, 2, &TargetFileName))
        {
            TargetFileName = NULL;
        }
        else if (!*TargetFileName)
        {
            INF_FreeData(TargetFileName);
            TargetFileName = NULL;
        }

        /* Lookup target directory */
        Success = LookupDirectoryById(InfFile, &DirContext, TargetDirId, &TargetDir);
        INF_FreeData(TargetDirId);
        if (!Success)
        {
            /* FIXME: Handle error! */
            INF_FreeData(TargetFileName);
            INF_FreeData(SourceFileName);
            break;
        }

        /*
         * A file of a component that is left out (answer file [Components]) is not
         * copied: matched on its destination path relative to the installation
         * directory. Without [Components] pSetupData->Components is NULL and every
         * file is queued, as always.
         */
        if (pSetupData->Components)
        {
            WCHAR RelPath[MAX_PATH];
            PCWSTR Dir = TargetDir;

            while (*Dir == L'\\')
                ++Dir;
            if (*Dir)
                RtlStringCchPrintfW(RelPath, ARRAYSIZE(RelPath), L"%s\\%s", Dir, TargetFileName ? TargetFileName : SourceFileName);
            else
                RtlStringCchCopyW(RelPath, ARRAYSIZE(RelPath), TargetFileName ? TargetFileName : SourceFileName);

            if (ComponentsIsFileOmitted((PCOMPONENTS_STATE)pSetupData->Components, RelPath))
            {
                INF_FreeData(TargetDir);
                INF_FreeData(TargetFileName);
                INF_FreeData(SourceFileName);
                continue;
            }
        }

        DPRINT("GetSourceTargetFromCab(%S) = "
               "SrcRootDir: '%S', SrcRelPath: '%S' --> TargetDir: '%S', TargetFileName: '%S'\n",
               SourceFileName,
               pSetupData->SourcePath.Buffer,
               pSetupData->SourceRootDir.Buffer,
               TargetDir, TargetFileName);

        Status = CombinePaths(FileDstPath, ARRAYSIZE(FileDstPath), 2,
                              pSetupData->DestinationPath.Buffer,
                              TargetDir);
        UNREFERENCED_PARAMETER(Status);
        DPRINT("  --> FileDstPath = '%S'\n", FileDstPath);

        INF_FreeData(TargetDir);

        if (!SpFileQueueCopy((HSPFILEQ)pSetupData->SetupFileQueue,
                             pSetupData->SourcePath.Buffer, // SourcePath == SourceRootPath ++ SourceRootDir
                             NULL,
                             SourceFileName,
                             NULL,
                             SourceCabinet,
                             NULL,
                             FileDstPath,
                             TargetFileName,
                             0 /* FIXME */))
        {
            /* FIXME: Handle error! */
            DPRINT1("SpFileQueueCopy() failed\n");
        }

        INF_FreeData(TargetFileName);
        INF_FreeData(SourceFileName);

    } while (SpInfFindNextLine(&FilesContext, &FilesContext));

    return TRUE;
}

// Note: Modeled after the SetupQueueCopySection() API
/*
BOOL SetupQueueCopySection(
  _In_ HSPFILEQ QueueHandle,
  _In_ PCTSTR   SourceRootPath,
  _In_ HINF     InfHandle,
  _In_ HINF     ListInfHandle,
  _In_ PCTSTR   Section,
  _In_ DWORD    CopyStyle
);
*/
static BOOLEAN
AddSectionToCopyQueue(
    IN PUSETUP_DATA pSetupData,
    IN HINF InfFile,
    IN PCWSTR SectionName,
    IN PCUNICODE_STRING DestinationPath)
{
    NTSTATUS Status;
    INFCONTEXT FilesContext;
    PCWSTR SourceFileName;
    PCWSTR SourceRootPath;
    PCWSTR SourcePath;
    PCWSTR TargetDirectory;
    PCWSTR TargetFileName;
    WCHAR FileSrcRootPath[MAX_PATH];
    WCHAR FileDstPath[MAX_PATH];

    /*
     * This code enumerates the list of files in txtsetup.sif
     * that need to be installed in their respective directories.
     */

    /* Search for the SectionName section */
    if (!SpInfFindFirstLine(InfFile, SectionName, NULL, &FilesContext))
    {
        DPRINT1("AddSectionToCopyQueue(): Unable to find section '%S' in TXTSETUP.SIF\n", SectionName);
        return FALSE;
    }

    /*
     * Enumerate the files in the section and add them to the file queue.
     */
    do
    {
        /* Get source file name */
        if (!INF_GetDataField(&FilesContext, 0, &SourceFileName))
        {
            /* FIXME: Handle error! */
            DPRINT1("INF_GetData() failed\n");
            break;
        }

        Status = GetSourceFileAndTargetLocation(InfFile,
                                                &FilesContext,
                                                SourceFileName,
                                                &SourceRootPath, // SourceRootDir
                                                &SourcePath,
                                                &TargetDirectory,
                                                &TargetFileName);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Could not find source and target location for file '%S'\n", SourceFileName);
            INF_FreeData(SourceFileName);

            // FIXME: Another error?
            pSetupData->LastErrorNumber = ERROR_TXTSETUP_SECTION;
            if (pSetupData->ErrorRoutine)
                pSetupData->ErrorRoutine(pSetupData, SectionName);
            return FALSE;
            // break;
        }
        /*
         * SourcePath: '\Device\CdRom0\I386'
         * SourceRootPath: '\Device\CdRom0'
         * SourceRootDir: '\I386'
         */

        Status = CombinePaths(FileSrcRootPath, ARRAYSIZE(FileSrcRootPath), 2,
                              pSetupData->SourceRootPath.Buffer,
                              SourceRootPath);
        UNREFERENCED_PARAMETER(Status);
        // DPRINT1("Could not build the full path for '%S', skipping...\n", SourceRootPath);
        DPRINT("  --> FileSrcRootPath = '%S'\n", FileSrcRootPath);

        INF_FreeData(SourceRootPath);

        Status = CombinePaths(FileDstPath, ARRAYSIZE(FileDstPath), 2,
                              pSetupData->DestinationPath.Buffer,
                              TargetDirectory);
        UNREFERENCED_PARAMETER(Status);
        // DPRINT1("Could not build the full path for '%S', skipping...\n", TargetDirectory);
        DPRINT("  --> FileDstPath = '%S'\n", FileDstPath);

        INF_FreeData(TargetDirectory);

        if (!SpFileQueueCopy((HSPFILEQ)pSetupData->SetupFileQueue,
                             FileSrcRootPath,
                             SourcePath,
                             SourceFileName,
                             NULL,
                             NULL, // No SourceCabinet
                             NULL,
                             FileDstPath,
                             TargetFileName,
                             0 /* FIXME */))
        {
            /* FIXME: Handle error! */
            DPRINT1("SpFileQueueCopy() failed\n");
        }

        INF_FreeData(TargetFileName);
        INF_FreeData(SourcePath);
        INF_FreeData(SourceFileName);

    } while (SpInfFindNextLine(&FilesContext, &FilesContext));

    return TRUE;
}

BOOLEAN // ERROR_NUMBER
PrepareCopyInfFile(
    IN OUT PUSETUP_DATA pSetupData,
    IN HINF InfFile,
    IN PCWSTR SourceCabinet OPTIONAL)
{
    BOOLEAN Success;
    NTSTATUS Status;
    INFCONTEXT DirContext;
    PWCHAR AdditionalSectionName = NULL;
    PCWSTR DirKeyValue;
    WCHAR PathBuffer[MAX_PATH];

    if (SourceCabinet == NULL)
    {
        /* Add common files -- Search for the SourceDisksFiles section */
        /* Search in the optional platform-specific first (currently hardcoded; make it runtime-dependent?) */
        Success = AddSectionToCopyQueue(pSetupData, InfFile,
                                        L"SourceDisksFiles." INF_ARCH,
                                        &pSetupData->DestinationPath);
        if (!Success)
        {
            DPRINT1("AddSectionToCopyQueue(%S) failed!\n", L"SourceDisksFiles." INF_ARCH);
        }
        /* Search in the global section */
        Success = AddSectionToCopyQueue(pSetupData, InfFile,
                                        L"SourceDisksFiles",
                                        &pSetupData->DestinationPath);
        if (!Success)
        {
            DPRINT1("AddSectionToCopyQueue(%S) failed!\n", L"SourceDisksFiles");
            pSetupData->LastErrorNumber = ERROR_TXTSETUP_SECTION;
            if (pSetupData->ErrorRoutine)
                pSetupData->ErrorRoutine(pSetupData, L"SourceDisksFiles");
            return FALSE;
        }

        /* Add specific files depending of computer type */
        {
        PGENERIC_LIST_ENTRY Entry;
        Entry = GetCurrentListEntry(pSetupData->ComputerList);
        ASSERT(Entry);
        pSetupData->ComputerType = ((PGENENTRY)GetListEntryData(Entry))->Id;
        ASSERT(pSetupData->ComputerType);

        if (!ProcessComputerFiles(InfFile, pSetupData->ComputerType, &AdditionalSectionName))
            return FALSE;
        }

        if (AdditionalSectionName &&
            !AddSectionToCopyQueue(pSetupData, InfFile,
                                   AdditionalSectionName,
                                   &pSetupData->DestinationPath))
        {
            pSetupData->LastErrorNumber = ERROR_TXTSETUP_SECTION;
            if (pSetupData->ErrorRoutine)
                pSetupData->ErrorRoutine(pSetupData, AdditionalSectionName);
            return FALSE;
        }
    }
    else
    {
        /* Process a cabinet INF */
        Success = AddSectionToCopyQueueCab(pSetupData, InfFile,
                                           L"SourceFiles",
                                           SourceCabinet,
                                           &pSetupData->DestinationPath);
        if (!Success)
        {
            DPRINT1("AddSectionToCopyQueueCab(%S) failed!\n", SourceCabinet);
            pSetupData->LastErrorNumber = ERROR_CABINET_SECTION;
            if (pSetupData->ErrorRoutine)
                pSetupData->ErrorRoutine(pSetupData, L"SourceFiles");
            return FALSE;
        }
    }

    /* Create directories */

    /*
     * NOTE: This is technically optional since SpFileQueueCommit()
     * does that. This is however needed if one wants to create
     * empty directories.
     */

    /*
     * FIXME:
     * Copying files to pSetupData->DestinationRootPath should be done from within
     * the SystemPartitionFiles section.
     * At the moment we check whether we specify paths like '\foo' or '\\' for that.
     * For installing to pSetupData->DestinationPath specify just '\' .
     */

    /* Get destination path */
    RtlStringCchCopyW(PathBuffer, ARRAYSIZE(PathBuffer),
                      pSetupData->DestinationPath.Buffer);

    DPRINT("FullPath(1): '%S'\n", PathBuffer);

    /* Create the install directory */
    Status = SetupCreateDirectory(PathBuffer);
    if (!NT_SUCCESS(Status) && Status != STATUS_OBJECT_NAME_COLLISION)
    {
        DPRINT1("Creating directory '%S' failed: Status = 0x%08lx\n", PathBuffer, Status);
        pSetupData->LastErrorNumber = ERROR_CREATE_INSTALL_DIR;
        if (pSetupData->ErrorRoutine)
            pSetupData->ErrorRoutine(pSetupData, PathBuffer);
        return FALSE;
    }

    /* Search for the 'Directories' section */
    // ReactOS-specific
    if (!SpInfFindFirstLine(InfFile, L"Directories", NULL, &DirContext))
    {
        // Windows-compatible
        if (!SpInfFindFirstLine(InfFile, L"WinntDirectories", NULL, &DirContext))
        {
            if (SourceCabinet)
                pSetupData->LastErrorNumber = ERROR_CABINET_SECTION;
            else
                pSetupData->LastErrorNumber = ERROR_TXTSETUP_SECTION;

            if (pSetupData->ErrorRoutine)
                pSetupData->ErrorRoutine(pSetupData, L"Directories");
            return FALSE;
        }
    }

    /* Enumerate the directory values and create the subdirectories */
    do
    {
        if (!INF_GetData(&DirContext, NULL, &DirKeyValue))
        {
            DPRINT1("break\n");
            break;
        }

        Status = BuildFullDirectoryPath(pSetupData->DestinationRootPath.Buffer,
                                        pSetupData->InstallPath.Buffer,
                                        DirKeyValue,
                                        PathBuffer,
                                        ARRAYSIZE(PathBuffer));
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("Could not build the full path for '%S', skipping...\n", DirKeyValue);
            INF_FreeData(DirKeyValue);
            continue;
        }

        if ((DirKeyValue[0] == UNICODE_NULL) || (DirKeyValue[0] == L'\\' && DirKeyValue[1] == UNICODE_NULL))
        {
            /*
             * Installation path -- No need to create it
             * because it has been already created above.
             */
        }
        else
        {
            /* Arbitrary path -- Create it */
            Status = SetupCreateDirectory(PathBuffer);
            if (!NT_SUCCESS(Status) && Status != STATUS_OBJECT_NAME_COLLISION)
            {
                INF_FreeData(DirKeyValue);
                DPRINT1("Creating directory '%S' failed: Status = 0x%08lx\n", PathBuffer, Status);
                pSetupData->LastErrorNumber = ERROR_CREATE_DIR;
                if (pSetupData->ErrorRoutine)
                    pSetupData->ErrorRoutine(pSetupData, PathBuffer);
                return FALSE;
            }
        }

        INF_FreeData(DirKeyValue);
    } while (SpInfFindNextLine(&DirContext, &DirContext));

    return TRUE;
}


/*
 * The sizes of the files of the optional components, for the page that asks which to install: every line of the
 * cabinet inf files (the same lines that PrepareFileCopy queues) is given to the components code with its size.
 * The sizes are the last field of the lines of "reactos.sizes", the copy of the inf that the cabinet tool writes
 * next to it (the inf itself cannot carry them: it is also stored in the cabinet header, 64 KB at most). Nothing is
 * copied or opened except these files. Without that file (a medium made by an older cabinet tool) the state says
 * so and the page shows no sizes.
 */
BOOLEAN
NTAPI
ComponentsMeasure(
    IN PUSETUP_DATA pSetupData)
{
    PCOMPONENTS_STATE Components = (PCOMPONENTS_STATE)pSetupData->Components;
    INFCONTEXT CabinetsContext, FilesContext, DirContext;
    PCWSTR CabinetName;
    HINF InfHandle;
    UINT ErrorLine;
    WCHAR PathBuffer[MAX_PATH];
    ULONG Files = 0, Sized = 0;

    if (!Components)
        return FALSE;
    if (!SpInfFindFirstLine(pSetupData->SetupInf, L"Cabinets", NULL, &CabinetsContext))
        return FALSE;

    do
    {
        PWCHAR ptr;

        if (!INF_GetData(&CabinetsContext, NULL, &CabinetName))
            break;
        CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2, pSetupData->SourcePath.Buffer, CabinetName);
        INF_FreeData(CabinetName);

        ptr = wcsrchr(PathBuffer, L'\\');
        if (!ptr) ptr = PathBuffer;
        ptr = wcsrchr(ptr, L'.');
        if (!ptr) ptr = PathBuffer + wcslen(PathBuffer);
        wcscpy(ptr, L".sizes");
        InfHandle = SpInfOpenInfFile(PathBuffer, NULL, INF_STYLE_WIN4, pSetupData->LanguageId, &ErrorLine);
        if (InfHandle == INVALID_HANDLE_VALUE)
        {
            /* no sizes: the plain inf lists the same files, without a size */
            wcscpy(ptr, L".inf");
            InfHandle = SpInfOpenInfFile(PathBuffer, NULL, INF_STYLE_WIN4, pSetupData->LanguageId, &ErrorLine);
        }
        if (InfHandle == INVALID_HANDLE_VALUE)
            continue;

        if (SpInfFindFirstLine(InfHandle, L"SourceFiles", NULL, &FilesContext))
        {
            do
            {
                PCWSTR SourceFileName = NULL, TargetDirId = NULL, TargetFileName = NULL, SizeText = NULL, TargetDir = NULL;
                WCHAR RelPath[MAX_PATH];
                PCWSTR Dir;
                ULONGLONG Bytes = 0;

                if (!INF_GetDataField(&FilesContext, 0, &SourceFileName) ||
                    !INF_GetDataField(&FilesContext, 1, &TargetDirId))
                    goto NextLine;

                if (!INF_GetDataField(&FilesContext, 2, &TargetFileName) || !*TargetFileName)
                {
                    INF_FreeData(TargetFileName);
                    TargetFileName = NULL;
                }
                if (!LookupDirectoryById(InfHandle, &DirContext, TargetDirId, &TargetDir))
                    goto NextLine;

                Dir = TargetDir;
                while (*Dir == L'\\')
                    ++Dir;
                if (*Dir)
                    RtlStringCchPrintfW(RelPath, ARRAYSIZE(RelPath), L"%s\\%s", Dir, TargetFileName ? TargetFileName : SourceFileName);
                else
                    RtlStringCchCopyW(RelPath, ARRAYSIZE(RelPath), TargetFileName ? TargetFileName : SourceFileName);

                ++Files;
                if (INF_GetDataField(&FilesContext, 3, &SizeText))
                {
                    PCWSTR p;

                    /* a size over 4 GB (the cabinet inf writes the size of one file of the medium) is not a size:
                     * it also keeps the sum below from wrapping. The page then shows no sizes at all. */
                    for (p = SizeText; *p >= L'0' && *p <= L'9' && Bytes <= 0xFFFFFFFFULL; ++p)
                        Bytes = Bytes * 10 + (*p - L'0');
                    if (p != SizeText && !*p && Bytes <= 0xFFFFFFFFULL)
                    {
                        ++Sized;
                        ComponentsAddFile(Components, RelPath, Bytes);
                    }
                    INF_FreeData(SizeText);
                }

NextLine:
                if (TargetDir) INF_FreeData(TargetDir);
                if (TargetFileName) INF_FreeData(TargetFileName);
                if (TargetDirId) INF_FreeData(TargetDirId);
                if (SourceFileName) INF_FreeData(SourceFileName);
            } while (SpInfFindNextLine(&FilesContext, &FilesContext));
        }
        SpInfCloseInfFile(InfHandle);
    } while (SpInfFindNextLine(&CabinetsContext, &CabinetsContext));

    /* every file has a size, or the medium does not carry sizes at all */
    Components->SizesKnown = (Files && Sized == Files);
    /* nothing is logged here: an installation that leaves everything in must not differ from one without the page,
     * not even by a log file (ComponentsSetChoice logs the selection when something is left out) */
    return Components->SizesKnown;
}


// #define USE_CABINET_INF

BOOLEAN // ERROR_NUMBER
NTAPI
PrepareFileCopy(
    IN OUT PUSETUP_DATA pSetupData,
    IN PFILE_COPY_STATUS_ROUTINE StatusRoutine OPTIONAL)
{
    HINF InfHandle;
    INFCONTEXT CabinetsContext;
    PCWSTR CabinetName;
    UINT ErrorLine;
#if defined(__REACTOS__) && defined(USE_CABINET_INF)
    ULONG InfFileSize;
    PVOID InfFileData;
    CABINET_CONTEXT CabinetContext;
#endif
    WCHAR PathBuffer[MAX_PATH];

    /* Create the file queue */
    pSetupData->SetupFileQueue = (PVOID)SpFileQueueOpen();
    if (pSetupData->SetupFileQueue == NULL)
    {
        pSetupData->LastErrorNumber = ERROR_COPY_QUEUE;
        if (pSetupData->ErrorRoutine)
            pSetupData->ErrorRoutine(pSetupData);
        return FALSE;
    }

    /* Prepare the copy of the common files that are not in installation cabinets */
    if (!PrepareCopyInfFile(pSetupData, pSetupData->SetupInf, NULL))
    {
        /* FIXME: show an error dialog */
        return FALSE;
    }

    /* Search for the 'Cabinets' section */
    if (!SpInfFindFirstLine(pSetupData->SetupInf, L"Cabinets", NULL, &CabinetsContext))
    {
        /* Skip this step and return success if no cabinet file is listed */
        return TRUE;
    }

    /*
     * Enumerate the installation cabinets listed in the
     * 'Cabinets' section and parse their inf files.
     */
    do
    {
        if (!INF_GetData(&CabinetsContext, NULL, &CabinetName))
            break;

        CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2,
                     pSetupData->SourcePath.Buffer, CabinetName);

#if defined(__REACTOS__) && defined(USE_CABINET_INF)
        INF_FreeData(CabinetName);

        CabinetInitialize(&CabinetContext);
        CabinetSetEventHandlers(&CabinetContext, NULL, NULL, NULL);
        CabinetSetCabinetName(&CabinetContext, PathBuffer);

        if (CabinetOpen(&CabinetContext) == CAB_STATUS_SUCCESS)
        {
            DPRINT("Cabinet %S\n", PathBuffer);

            InfFileData = CabinetGetCabinetReservedArea(&CabinetContext, &InfFileSize);
            if (InfFileData == NULL)
            {
                CabinetCleanup(&CabinetContext);

                pSetupData->LastErrorNumber = ERROR_CABINET_SCRIPT;
                if (pSetupData->ErrorRoutine)
                    pSetupData->ErrorRoutine(pSetupData, PathBuffer);
                return FALSE;
            }
        }
        else
        {
            DPRINT("Cannot open cabinet: %S.\n", PathBuffer);
            CabinetCleanup(&CabinetContext);

            pSetupData->LastErrorNumber = ERROR_CABINET_MISSING;
            if (pSetupData->ErrorRoutine)
                pSetupData->ErrorRoutine(pSetupData, PathBuffer);
            return FALSE;
        }

        InfHandle = INF_OpenBufferedFileA((PSTR)InfFileData,
                                          InfFileSize,
                                          NULL,
                                          INF_STYLE_WIN4,
                                          pSetupData->LanguageId,
                                          &ErrorLine);

        CabinetCleanup(&CabinetContext);
#else
        {
        PWCHAR ptr;

        /* First find the filename */
        ptr = wcsrchr(PathBuffer, L'\\');
        if (!ptr) ptr = PathBuffer;

        /* Then find its extension */
        ptr = wcsrchr(ptr, L'.');
        if (!ptr)
            ptr = PathBuffer + wcslen(PathBuffer);

        /* Replace it by '.inf' */
        wcscpy(ptr, L".inf");

        InfHandle = SpInfOpenInfFile(PathBuffer,
                                     NULL,
                                     INF_STYLE_WIN4,
                                     pSetupData->LanguageId,
                                     &ErrorLine);
        }
#endif

        if (InfHandle == INVALID_HANDLE_VALUE)
        {
            pSetupData->LastErrorNumber = ERROR_INVALID_CABINET_INF;
            if (pSetupData->ErrorRoutine)
                pSetupData->ErrorRoutine(pSetupData, PathBuffer);
            return FALSE;
        }

        if (!PrepareCopyInfFile(pSetupData, InfHandle, CabinetName))
        {
#if !(defined(__REACTOS__) && defined(USE_CABINET_INF))
            SpInfCloseInfFile(InfHandle);
#endif
            /* FIXME: show an error dialog */
            return FALSE;
        }

#if !(defined(__REACTOS__) && defined(USE_CABINET_INF))
        SpInfCloseInfFile(InfHandle);
#endif
    } while (SpInfFindNextLine(&CabinetsContext, &CabinetsContext));

    if (pSetupData->Components)
    {
        PCOMPONENTS_STATE Components = (PCOMPONENTS_STATE)pSetupData->Components;
        SetupLogFormat("components: %lu of %lu files of the cabinet are left out of the copy",
                       Components->SkippedFiles, Components->TotalFiles);
    }

    return TRUE;
}

BOOLEAN
NTAPI
DoFileCopy(
    IN OUT PUSETUP_DATA pSetupData,
    IN PSP_FILE_CALLBACK_W MsgHandler,
    IN PVOID Context OPTIONAL)
{
    BOOLEAN Success;

    Success = SpFileQueueCommit(NULL,
                                (HSPFILEQ)pSetupData->SetupFileQueue,
                                MsgHandler,
                                Context);

    SpFileQueueClose((HSPFILEQ)pSetupData->SetupFileQueue);
    pSetupData->SetupFileQueue = NULL;

    return Success;
}

/* EOF */
