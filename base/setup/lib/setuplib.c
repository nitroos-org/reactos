/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Setup Library
 * FILE:            base/setup/lib/setuplib.c
 * PURPOSE:         Setup Library - Main initialization helpers
 * PROGRAMMERS:     Casper S. Hornstrup (chorns@users.sourceforge.net)
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 *                  Whindmar Saksit <whindsaks@proton.me>
 */

/* INCLUDES *****************************************************************/

#include "precomp.h"
#include "filesup.h"
#include "infsupp.h"
#include "inicache.h"

#include "setuplib.h"
#include "components.h"

#define NDEBUG
#include <debug.h>


/* GLOBALS ******************************************************************/

HANDLE ProcessHeap;
BOOLEAN IsUnattendedSetup = FALSE;
static BOOLEAN UnattendRefused = FALSE;
static PCWSTR InfUnattendSignature = L"$ReactOS$";

/* FUNCTIONS ****************************************************************/

static int
CompareInfFirstLineString(
    _In_ HINF hInf,
    _In_ PCWSTR Section,
    _In_ PCWSTR Name,
    _In_ PCWSTR String)
{
    INFCONTEXT Context;
    PCWSTR Value;
    int Result = STATUS_UNSUCCESSFUL;

    if (!SpInfFindFirstLine(hInf, Section, Name, &Context))
        return Result;

    if (!INF_GetData(&Context, NULL, &Value))
        return Result;

    Result = _wcsicmp(Value, String);

    INF_FreeData(Value);
    return Result;
}

/* An answer file is a few KB. The whole file is read into memory by the INF parser, appended to the
 * installed copy and read again by the second stage: a file larger than this is not an answer file. */
#define UNATTEND_MAX_FILE_SIZE  (1024 * 1024)

static BOOLEAN
IsUnattendFileUsable(
    _In_ PCWSTR InfPath)
{
    NTSTATUS Status;
    HANDLE FileHandle;
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION FileInfo;

    RtlInitUnicodeString(&FileName, InfPath);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    UCHAR Head[2] = {0, 0};

    Status = NtOpenFile(&FileHandle, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status))
        return TRUE; /* the open of the parser reports it */
    Status = NtQueryInformationFile(FileHandle, &IoStatusBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);
    if (NT_SUCCESS(Status) && FileInfo.EndOfFile.QuadPart > UNATTEND_MAX_FILE_SIZE)
    {
        NtClose(FileHandle);
        SetupLogFormat("ignored %S: it is larger than %u bytes, not an answer file", InfPath, (UINT)UNATTEND_MAX_FILE_SIZE);
        return FALSE;
    }
    (void)NtReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, Head, sizeof(Head), NULL, NULL);
    NtClose(FileHandle);
    if ((Head[0] == 0xFF && Head[1] == 0xFE) || (Head[0] == 0xFE && Head[1] == 0xFF))
    {
        /* The text-mode parser reads UTF-16, the second stage reads the copy of the file as 8-bit text: a
         * UTF-16 file would erase a disk unattended and then leave the second stage waiting for a person */
        SetupLogFormat("ignored %S: it is UTF-16 text; save it as ANSI or UTF-8 without a byte order mark", InfPath);
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
IsInfUnattendSetupEnabled(
    _In_ PUSETUP_DATA pSetupData,
    _In_ PCWSTR InfPath,
    _In_ BOOLEAN CheckDetached)
{
    HINF hInf;
    UINT ErrorLine;
    BOOLEAN Result = FALSE;

    if (!IsUnattendFileUsable(InfPath))
        return Result;

    hInf = SpInfOpenInfFile(InfPath,
                            NULL,
                            INF_STYLE_OLDNT,
                            pSetupData->LanguageId,
                            &ErrorLine);
    if (hInf == INVALID_HANDLE_VALUE)
        return Result;

    /* Verify supported inf 'Signature' key */
    if (CompareInfFirstLineString(hInf, L"Unattend", L"Signature", InfUnattendSignature) != 0)
    {
        DPRINT("Signature not %ls\n", InfUnattendSignature);
        goto Quit;
    }

    /* Check whether unattended setup is enabled */
    if (CompareInfFirstLineString(hInf, L"Unattend", L"UnattendSetupEnabled", L"yes") != 0)
        goto Quit;

    /* Extra safety check for inf files not on the ISO */
    if (CheckDetached && CompareInfFirstLineString(hInf, L"Unattend", L"UnattendForDetached", L"yes") != 0)
        goto Quit;

    Result = TRUE;
Quit:
    SpInfCloseInfFile(hInf);
    return Result;
}

static BOOLEAN
GetUnattendInfPath(
    _In_ PUSETUP_DATA pSetupData,
    _Out_writes_z_(cch) PWSTR InfPath,
    _In_ SIZE_T cch)
{
    static WCHAR UnattendInfPath[MAX_PATH] = {UNICODE_NULL};
    static BOOLEAN UnattendInfLookedUp = FALSE;
    NTSTATUS Status;
    USHORT Types;

    /* The operator refused the answer file (DisableUnattendedSetup): there is none */
    if (UnattendRefused)
    {
        if (cch)
            InfPath[0] = UNICODE_NULL;
        return FALSE;
    }

    /* If the unattend.inf file has already been looked for, return
     * its cached path if it was found, or fail otherwise. */
    if (UnattendInfLookedUp)
        goto Quit;

    UnattendInfLookedUp = TRUE;
    pSetupData->UnattendDetachedDrive = UNICODE_NULL;

    /*
     * Search order (the answer file is always named unattend.inf):
     *  1. the installation source directory of the medium setup was started
     *     from (\reactos, \amd64, \i386 on the ISO: the file the ISO ships);
     *  2. the root of that medium (a remastered ISO: no need to know the
     *     source directory);
     *  3. the root of every other volume, removable media and CD/DVD drives
     *     first, then fixed disks: a second CD, a floppy, an IDE/USB disk.
     *     These need UnattendForDetached = yes in the file (see
     *     IsInfUnattendSetupEnabled), so a stray unattend.inf on a disk can
     *     never start an unattended installation by itself.
     * The first file that enables unattended setup wins.
     */
    Status = CombinePaths(UnattendInfPath, _countof(UnattendInfPath), 2,
                          pSetupData->SourcePath.Buffer, L"unattend.inf");
    if (NT_SUCCESS(Status) && DoesFileExist(NULL, UnattendInfPath) &&
        IsInfUnattendSetupEnabled(pSetupData, UnattendInfPath, FALSE))
    {
        SetupLogFormat("answer file: %S (installation source directory)", UnattendInfPath);
        return NT_SUCCESS(RtlStringCchCopyW(InfPath, cch, UnattendInfPath));
    }

    Status = CombinePaths(UnattendInfPath, _countof(UnattendInfPath), 2,
                          pSetupData->SourceRootPath.Buffer, L"unattend.inf");
    if (NT_SUCCESS(Status) && DoesFileExist(NULL, UnattendInfPath) &&
        IsInfUnattendSetupEnabled(pSetupData, UnattendInfPath, FALSE))
    {
        SetupLogFormat("answer file: %S (root of the installation medium)", UnattendInfPath);
        return NT_SUCCESS(RtlStringCchCopyW(InfPath, cch, UnattendInfPath));
    }
    /* Nothing found on the medium so far: keep the first candidate for the fall-back below */
    (void)CombinePaths(UnattendInfPath, _countof(UnattendInfPath), 2,
                       pSetupData->SourcePath.Buffer, L"unattend.inf");

    for (Types = 0; Types <= 1; ++Types)
    {
        CHAR Drive;
        for (Drive = 'A'; Drive <= 'Z'; ++Drive)
        {
            UCHAR DriveType;
            WCHAR szInf[MAX_PATH];
            UNICODE_STRING NtDrive;

            RtlInitEmptyUnicodeString(&NtDrive, szInf, sizeof(szInf) - sizeof(L"\\unattend.inf"));
            RtlZeroMemory(szInf, sizeof(szInf));

            DriveType = GetNtDevicePathOfDriveNumber(Drive - 'A', &NtDrive);
            if (DriveType <= DRIVE_NO_ROOT_DIR)
                continue; /* Invalid drive */
            if ((Types == 0) != (DriveType == DRIVE_REMOVABLE || DriveType == DRIVE_CDROM))
                continue; /* Not the expected drive type */
            szInf[NtDrive.Length / sizeof(WCHAR)] = UNICODE_NULL;

            Status = ConcatPaths(szInf, _countof(szInf), 1, L"unattend.inf");
            if (NT_SUCCESS(Status) && DoesFileExist(NULL, szInf))
            {
                if (IsInfUnattendSetupEnabled(pSetupData, szInf, TRUE))
                {
                    /* Cache the alternative unattend.inf path and return it */
                    (void)RtlStringCchCopyW(UnattendInfPath, _countof(UnattendInfPath), szInf);
                    pSetupData->UnattendDetachedDrive = (WCHAR)Drive;
                    SetupLogFormat("answer file: %S (drive %c:)", szInf, Drive);
                    return NT_SUCCESS(RtlStringCchCopyW(InfPath, cch, szInf));
                }
                SetupLogFormat("ignored %S: it does not enable unattended setup"
                               " (UnattendSetupEnabled = yes and UnattendForDetached = yes are required"
                               " outside the installation medium)", szInf);
            }
        }
    }
    /* Fall back to the default unattend.inf path */

Quit:
    /* Return the cached unattend.inf path if it was found, or fail otherwise */
    if (*UnattendInfPath)
        return NT_SUCCESS(RtlStringCchCopyW(InfPath, cch, UnattendInfPath));
    return FALSE;
}

/*
 * The operator of the computer refused the answer file that was found on another volume (ESC at the notice
 * of usetup): the installation goes on as an interactive one, and the file is neither used nor copied.
 */
VOID
NTAPI
DisableUnattendedSetup(VOID)
{
    UnattendRefused = TRUE;
    IsUnattendedSetup = FALSE;
    SetupLogLine("the answer file was refused at the keyboard: interactive installation");
}

/* A decimal number key of [Unattend]: absent = *pValue is left as it is; present and valid
 * (Min..Max) = *pValue is set; present and bad = logged, *pValue is left as it is.
 * NOTE: SpInfGetIntField() would read "abc" as 0 without failing, so the text is checked. */
static VOID
GetUnattendNumber(
    _In_ HINF hInf,
    _In_ PCWSTR Key,
    _In_ LONG Min,
    _In_ LONG Max,
    _Inout_ PLONG pValue)
{
    INFCONTEXT Context;
    PCWSTR Text;
    ULONG Number;

    if (!SpInfFindFirstLine(hInf, L"Unattend", Key, &Context))
        return;
    if (INF_GetData(&Context, NULL, &Text))
    {
        if (UnattendParseUInt(Text, 0x7FFFFFFF, &Number) && (LONG)Number >= Min && (LONG)Number <= Max)
            *pValue = (LONG)Number;
        else
            SetupLogFormat("bad value for %S (a number from %ld to %ld expected): using %ld", Key, Min, Max, *pValue);
        INF_FreeData(Text);
    }
}

BOOLEAN
NTAPI
CheckUnattendedSetup(
    IN OUT PUSETUP_DATA pSetupData)
{
    INFCONTEXT Context;
    HINF UnattendInf;
    UINT ErrorLine;
    PCWSTR Value;
    WCHAR UnattendInfPath[MAX_PATH];

    if (!GetUnattendInfPath(pSetupData, UnattendInfPath, ARRAYSIZE(UnattendInfPath)))
    {
        DPRINT("Does not exist: %S\n", UnattendInfPath);
        return IsUnattendedSetup;
    }
    DPRINT1("UnattendInf path: '%S'\n", UnattendInfPath);

    if (!IsUnattendFileUsable(UnattendInfPath))
        return IsUnattendedSetup;

    /* Load 'unattend.inf' from installation media */
    UnattendInf = SpInfOpenInfFile(UnattendInfPath,
                                   NULL,
                                   INF_STYLE_OLDNT,
                                   pSetupData->LanguageId,
                                   &ErrorLine);
    if (UnattendInf == INVALID_HANDLE_VALUE)
    {
        DPRINT("SpInfOpenInfFile() failed\n");
        return IsUnattendedSetup;
    }

    /* Open 'Unattend' section */
    if (!SpInfFindFirstLine(UnattendInf, L"Unattend", L"Signature", &Context))
    {
        DPRINT("SpInfFindFirstLine() failed for section 'Unattend'\n");
        goto Quit;
    }

    /* Get pointer 'Signature' key */
    if (!INF_GetData(&Context, NULL, &Value))
    {
        DPRINT("INF_GetData() failed for key 'Signature'\n");
        goto Quit;
    }

    /* Check 'Signature' string */
    if (_wcsicmp(Value, InfUnattendSignature) != 0)
    {
        DPRINT("Signature not %ls\n", InfUnattendSignature);
        INF_FreeData(Value);
        goto Quit;
    }

    INF_FreeData(Value);

    /* Check if Unattend setup is enabled */
    if (!SpInfFindFirstLine(UnattendInf, L"Unattend", L"UnattendSetupEnabled", &Context))
    {
        DPRINT("Can't find key 'UnattendSetupEnabled'\n");
        goto Quit;
    }

    if (!INF_GetData(&Context, NULL, &Value))
    {
        DPRINT("Can't read key 'UnattendSetupEnabled'\n");
        goto Quit;
    }

    if (_wcsicmp(Value, L"yes") != 0)
    {
        DPRINT("Unattend setup is disabled by 'UnattendSetupEnabled' key!\n");
        INF_FreeData(Value);
        goto Quit;
    }

    INF_FreeData(Value);

    /*
     * From here on the file is accepted: every problem with a value is logged
     * (and the documented default is used instead), none of them hands the
     * installation over to the interactive pages.
     */

    /* 'DestinationDiskNumber' and 'DestinationPartitionNumber': default is disk 0, partition 1 */
    GetUnattendNumber(UnattendInf, L"DestinationDiskNumber", 0, 0xFFFF, &pSetupData->DestinationDiskNumber);
    GetUnattendNumber(UnattendInf, L"DestinationPartitionNumber", 0, 0xFFFF, &pSetupData->DestinationPartitionNumber);

    /* Search for 'InstallationDirectory' (optional) */
    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"InstallationDirectory", &Context))
    {
        if (INF_GetData(&Context, NULL, &Value))
        {
            RtlStringCchCopyW(pSetupData->InstallationDirectory,
                              ARRAYSIZE(pSetupData->InstallationDirectory),
                              Value);
            INF_FreeData(Value);
        }
        else
        {
            SetupLogLine("bad value for InstallationDirectory: using the default");
        }
    }

    IsUnattendedSetup = TRUE;
    DPRINT("Running unattended setup\n");

    /* Search for 'BootLoaderLocation' (optional): 0 none, 1 removable media, 2 system partition, 3 VBR only */
    GetUnattendNumber(UnattendInf, L"BootLoaderLocation", 0, 3, &pSetupData->BootLoaderLocation);

    /* 'FormatPartition' and 'AutoPartition' (optional): 1 or 0, yes or no */
    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"FormatPartition", &Context) &&
        INF_GetData(&Context, NULL, &Value))
    {
        LONG Flag;
        if (UnattendParseBool(Value, &Flag))
            pSetupData->FormatPartition = Flag;
        else
            SetupLogFormat("bad value for FormatPartition (0 or 1, yes or no expected): using %ld",
                           pSetupData->FormatPartition);
        INF_FreeData(Value);
    }

    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"AutoPartition", &Context) &&
        INF_GetData(&Context, NULL, &Value))
    {
        LONG Flag;
        if (UnattendParseBool(Value, &Flag))
            pSetupData->AutoPartition = Flag;
        else
            SetupLogFormat("bad value for AutoPartition (0 or 1, yes or no expected): using %ld",
                           pSetupData->AutoPartition);
        INF_FreeData(Value);
    }

    /* Search for 'PartitionSizeMB' (optional): size of the partition AutoPartition creates, 0 = all the free space */
    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"PartitionSizeMB", &Context))
    {
        ULONG Size;
        if (INF_GetData(&Context, NULL, &Value))
        {
            if (UnattendParseUInt(Value, 0x7FFFFFFF, &Size))
                pSetupData->PartitionSizeMB = Size;
            else
                SetupLogLine("bad value for PartitionSizeMB (a number of megabytes expected): using all the free space");
            INF_FreeData(Value);
        }
    }

    /* Search for 'QuickFormat' (optional): 1 (default) quick, 0 full format */
    pSetupData->QuickFormat = 1;
    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"QuickFormat", &Context))
    {
        if (INF_GetData(&Context, NULL, &Value))
        {
            LONG Flag;
            if (UnattendParseBool(Value, &Flag))
                pSetupData->QuickFormat = Flag;
            else
                SetupLogLine("bad value for QuickFormat (yes/no or 1/0 expected): using quick format");
            INF_FreeData(Value);
        }
    }

    /* Search for 'LocaleID' (optional). Whether the system knows it is checked by the caller */
    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"LocaleID", &Context))
    {
        if (INF_GetData(&Context, NULL, &Value))
        {
            PWSTR End = NULL;
            ULONG Id = wcstoul(Value, &End, 16);
            if (!*Value || *End || Id == 0 || Id > 0xFFFF)
            {
                SetupLogLine("bad value for LocaleID (a hexadecimal language id such as 409 expected): using the default");
            }
            else
            {
                RtlStringCchPrintfW(pSetupData->LocaleID,
                                    ARRAYSIZE(pSetupData->LocaleID),
                                    L"%08lx", Id);
            }
            INF_FreeData(Value);
        }
    }

    /* Search for 'KeyboardLayout' (optional): a keyboard layout id, e.g. 00000407; the language's default when absent */
    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"KeyboardLayout", &Context))
    {
        if (INF_GetData(&Context, NULL, &Value))
        {
            if (!UnattendParseKeyboardLayout(Value, pSetupData->KeyboardLayout))
            {
                pSetupData->KeyboardLayout[0] = UNICODE_NULL;
                SetupLogLine("bad value for KeyboardLayout (a layout id such as 00000407 expected): using the default of the language");
            }
            INF_FreeData(Value);
        }
    }

    /* Search for 'FsType' (optional): 0 FAT, 1 BtrFS, 2 NTFS (any other number: FAT); the names are accepted too */
    if (SpInfFindFirstLine(UnattendInf, L"Unattend", L"FsType", &Context))
    {
        /* NOTE: a name must be recognised first: SpInfGetIntField() reads "NTFS" as 0 without failing */
        if (INF_GetData(&Context, NULL, &Value))
        {
            ULONG Number;

            if (!_wcsicmp(Value, L"NTFS"))
                pSetupData->FsType = 2;
            else if (!_wcsicmp(Value, L"BTRFS"))
                pSetupData->FsType = 1;
            else if (!_wcsicmp(Value, L"FAT") || !_wcsicmp(Value, L"FAT32"))
                pSetupData->FsType = 0;
            else if (UnattendParseUInt(Value, 0x7FFFFFFF, &Number))
                pSetupData->FsType = (LONG)Number;  /* 0 FAT, 1 BtrFS, 2 NTFS, any other number FAT */
            else
                SetupLogFormat("bad value for FsType (NTFS, FAT, BTRFS or 2, 0, 1 expected): using %ld",
                               pSetupData->FsType);
            INF_FreeData(Value);
        }
    }

    /*
     * [Components]: Profile and per-component yes/no. Only a file with this section
     * opens components.inf; without it (and in an interactive setup) nothing changes
     * and nothing is logged.
     */
    if (SpInfFindFirstLine(UnattendInf, L"Components", NULL, &Context))
    {
        PCOMPONENTS_STATE Components = ComponentsLoad(pSetupData->SourcePath.Buffer, pSetupData->LanguageId);
        if (Components)
            ComponentsApplyAnswerFile(Components, UnattendInf);
        else
            SetupLogLine("[Components] ignored: components.inf is missing, unreadable or lists no component on the installation medium: everything is installed");
        pSetupData->Components = Components;
    }

    SetupLogFormat("answer file read: disk %ld partition %ld, AutoPartition %ld, FormatPartition %ld, FsType %ld,"
                   " QuickFormat %ld, PartitionSizeMB %lu, BootLoaderLocation %ld, LocaleID %S",
                   pSetupData->DestinationDiskNumber, pSetupData->DestinationPartitionNumber,
                   pSetupData->AutoPartition, pSetupData->FormatPartition, pSetupData->FsType,
                   pSetupData->QuickFormat, pSetupData->PartitionSizeMB,
                   pSetupData->BootLoaderLocation, pSetupData->LocaleID);

Quit:
    SpInfCloseInfFile(UnattendInf);
    return IsUnattendedSetup;
}

VOID
NTAPI
InstallSetupInfFile(
    IN OUT PUSETUP_DATA pSetupData)
{
    NTSTATUS Status;
    PINICACHE IniCache;

#if 0 // HACK FIXME!
    PINICACHE UnattendCache;
    PINICACHEITERATOR Iterator;
#else
    // WCHAR CrLf[] = {L'\r', L'\n'};
    CHAR CrLf[] = {'\r', '\n'};
    HANDLE FileHandle, UnattendFileHandle, SectionHandle;
    FILE_STANDARD_INFORMATION FileInfo;
    ULONG FileSize;
    PVOID ViewBase;
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
#endif

    PINI_SECTION IniSection;
    WCHAR PathBuffer[MAX_PATH];
    WCHAR UnattendInfPath[MAX_PATH];

    /* The installation directory exists now: write the text-mode setup log
     * the graphical stage appends to (<installation directory>\Panther\unattend.log) */
    (void)SetupLogWrite(pSetupData->DestinationPath.Buffer);
    (void)ComponentsWriteManifest((PCOMPONENTS_STATE)pSetupData->Components,
                                  pSetupData->DestinationPath.Buffer,
                                  pSetupData->SourcePath.Buffer);

    /* Create a $winnt$.inf file with default entries */
    IniCache = IniCacheCreate();
    if (!IniCache)
        return;

#if 0 /* If you need to put something in this section, do it after the merge with Unattend.inf */
    IniSection = IniAddSection(IniCache, L"SetupParams");
    if (IniSection)
    {
        /* Key "skipmissingfiles" */
        // RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                            // L"\"%s\"", L"WinNt5.2");
        // IniAddKey(IniSection, L"Version", PathBuffer);
    }
#endif

    IniSection = IniAddSection(IniCache, L"Data");
    if (IniSection)
    {
        RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                            L"\"%s\"", IsUnattendedSetup ? L"yes" : L"no");
        IniAddKey(IniSection, L"UnattendedInstall", PathBuffer);

        // "floppylessbootpath" (yes/no)

        RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                            L"\"%s\"", L"winnt");
        IniAddKey(IniSection, L"ProductType", PathBuffer);

        RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                            L"\"%s\\\"", pSetupData->SourceRootPath.Buffer);
        IniAddKey(IniSection, L"SourcePath", PathBuffer);

        // "floppyless" ("0")
    }

#if 0

    /* TODO: Append the standard unattend.inf file */
    if (!GetUnattendInfPath(pSetupData, UnattendInfPath, ARRAYSIZE(UnattendInfPath)))
    {
        DPRINT("Does not exist: %S\n", UnattendInfPath);
        goto Quit;
    }

    Status = IniCacheLoad(&UnattendCache, UnattendInfPath, FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Cannot load %S as an INI file!\n", UnattendInfPath);
        goto Quit;
    }

    IniCacheDestroy(UnattendCache);

Quit:
    CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2,
                 pSetupData->DestinationPath.Buffer, L"System32\\$winnt$.inf");
    IniCacheSave(IniCache, PathBuffer);
    IniCacheDestroy(IniCache);

#else

    CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2,
                 pSetupData->DestinationPath.Buffer, L"System32\\$winnt$.inf");
    IniCacheSave(IniCache, PathBuffer);
    IniCacheDestroy(IniCache);

    /* TODO: Append the standard unattend.inf file */
    if (!GetUnattendInfPath(pSetupData, UnattendInfPath, ARRAYSIZE(UnattendInfPath)))
    {
        DPRINT("Does not exist: %S\n", UnattendInfPath);
        return;
    }

    RtlInitUnicodeString(&FileName, PathBuffer);
    InitializeObjectAttributes(&ObjectAttributes,
                               &FileName,
                               OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
                               NULL,
                               NULL);
    Status = NtOpenFile(&FileHandle,
                        FILE_APPEND_DATA | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Cannot load %S as an INI file!\n", PathBuffer);
        return;
    }

    /* Query the file size */
    Status = NtQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &FileInfo,
                                    sizeof(FileInfo),
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("NtQueryInformationFile() failed (Status %lx)\n", Status);
        FileInfo.EndOfFile.QuadPart = 0ULL;
    }

    Status = OpenAndMapFile(NULL,
                            UnattendInfPath,
                            &UnattendFileHandle,
                            &FileSize,
                            &SectionHandle,
                            &ViewBase,
                            FALSE);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Cannot load %S !\n", UnattendInfPath);
        NtClose(FileHandle);
        return;
    }

    /* Write to the INI file */

    /* "\r\n" */
    Status = NtWriteFile(FileHandle,
                         NULL,
                         NULL,
                         NULL,
                         &IoStatusBlock,
                         (PVOID)CrLf,
                         sizeof(CrLf),
                         &FileInfo.EndOfFile,
                         NULL);

    Status = NtWriteFile(FileHandle,
                         NULL,
                         NULL,
                         NULL,
                         &IoStatusBlock,
                         ViewBase,
                         FileSize,
                         NULL,
                         NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT("NtWriteFile() failed (Status %lx)\n", Status);
    }

    /* Finally, unmap and close the file */
    UnMapAndCloseFile(UnattendFileHandle, SectionHandle, ViewBase);

    NtClose(FileHandle);
#endif
}

/**
 * @brief
 * Determine the installation source path and isolate its useful
 * path components (root path and source sub-directory).
 *
 * The installation source path is based either on the installer's
 * image file path, or on the \SystemRoot full path.
 *
 * In case the \SystemRoot full path prefixes the image file path,
 * use the resolved \SystemRoot as the installation source path.
 * Otherwise, use the image file path.
 *
 * The returned strings are allocated with RtlCreateUnicodeString(),
 * and need to be freed with RtlFreeUnicodeString() after being used.
 *
 * Example of output:
 *   SourcePath: '\Device\CdRom0\I386'
 *   SourceRootPath: '\Device\CdRom0'
 *   SourceRootDir: '\I386'
 **/
NTSTATUS
GetSourcePaths(
    _Out_ PUNICODE_STRING SourcePath,
    _Out_ PUNICODE_STRING SourceRootPath,
    _Out_ PUNICODE_STRING SourceRootDir)
{
    NTSTATUS Status;
    ULONG BufferSize;
    PWCHAR Ptr;
    HANDLE LinkHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    struct { OBJECT_NAME_INFORMATION; WCHAR Buffer[MAX_PATH]; } ImageFileBuffer;
    PUNICODE_STRING InstallSourcePath = &ImageFileBuffer.Name;
    struct { OBJECT_NAME_INFORMATION; WCHAR Buffer[MAX_PATH]; } SystemRootBuffer;
    PUNICODE_STRING SystemRootPath = &SystemRootBuffer.Name;
    const UNICODE_STRING SystemRoot = RTL_CONSTANT_STRING(L"\\SystemRoot");

    /* Retrieve the installer's full image file path */
    RtlInitEmptyUnicodeString(InstallSourcePath,
                              ImageFileBuffer.Buffer,
                              sizeof(ImageFileBuffer.Buffer));
    BufferSize = sizeof(ImageFileBuffer);
    Status = NtQueryInformationProcess(NtCurrentProcess(),
                                       ProcessImageFileName,
                                       InstallSourcePath,
                                       BufferSize,
                                       NULL);
    // STATUS_INFO_LENGTH_MISMATCH or STATUS_BUFFER_TOO_SMALL ?
    if (!NT_SUCCESS(Status))
        return Status;
    ASSERT(InstallSourcePath->Length < InstallSourcePath->MaximumLength);

    /* Go to the beginning of the path component, stop at the separator */
    Ptr = ImageFileBuffer.Buffer + (InstallSourcePath->Length / sizeof(WCHAR));
    while ((Ptr > ImageFileBuffer.Buffer) && (*Ptr != OBJ_NAME_PATH_SEPARATOR))
        --Ptr;
    /* Strip the trailing file name (at the separator or beginning of buffer)
     * and manually NULL-terminate */
    InstallSourcePath->Length = (ULONG_PTR)Ptr - (ULONG_PTR)ImageFileBuffer.Buffer;
    InstallSourcePath->Buffer[InstallSourcePath->Length / sizeof(WCHAR)] = UNICODE_NULL;


    /*
     * Now, resolve the \SystemRoot symlink target full path.
     *
     * The symlink target path resolution requires reparsing, because it
     * can reference other symlinks. This is what happens, for example when
     * booting the installation from a removable hard-disk. We can have:
     *
     *          \SystemRoot ---> \Device\Harddisk1\Partition1\ReactOS
     * and:     \Device\Harddisk1\Partition1 ---> \Device\HarddiskVolume2
     * etc.
     * and we wish to resolve \SystemRoot to: \Device\HarddiskVolume2\ReactOS
     *
     * We then verify whether it prefixes the image file path obtained
     * from the step above, which is a fully reparsed path.
     *
     * - Using NtOpenSymbolicLinkObject(SYMBOLIC_LINK_QUERY) followed by
     *   NtQuerySymbolicLinkObject() would only resolve the first symlink
     *   but not the others (\Device\Harddisk1\Partition1 left as is).
     *
     * - Since \SystemRoot has to point to a directory, we try opening
     *   the directory itself: NtOpenFile(..., FILE_DIRECTORY_FILE).
     *
     * - A call to NtQueryInformationFile(FileNameInformation) alone on
     *   the obtained handle would only retrieve the FS directory name,
     *   i.e. \ReactOS , but not the whole NT path.
     *
     * - We therefore use NtQueryObject(), which allows retrieving the
     *   full resolved NT path (device name + FS directory name).
     */

    InitializeObjectAttributes(&ObjectAttributes,
                               (PUNICODE_STRING)&SystemRoot,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    RtlInitEmptyUnicodeString(SystemRootPath,
                              SystemRootBuffer.Buffer,
                              sizeof(SystemRootBuffer.Buffer));

    Status = NtOpenFile(&LinkHandle,
                        SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
                            /*| FILE_OPEN_FOR_BACKUP_INTENT*/);
    if (NT_SUCCESS(Status))
    {
        /* Resolve the path and close its handle */
        Status = NtQueryObject(LinkHandle,
                               ObjectNameInformation,
                               &SystemRootBuffer,
                               sizeof(SystemRootBuffer),
                               &BufferSize);
        NtClose(LinkHandle);
    }
    /* If any of the calls above failed, try to naively resolve the symlink */
    if (!NT_SUCCESS(Status))
    {
        RtlInitEmptyUnicodeString(SystemRootPath,
                                  SystemRootBuffer.Buffer,
                                  sizeof(SystemRootBuffer.Buffer));

        Status = NtOpenSymbolicLinkObject(&LinkHandle,
                                          SYMBOLIC_LINK_QUERY,
                                          &ObjectAttributes);
        if (NT_SUCCESS(Status))
        {
            /* Resolve the link and close its handle */
            Status = NtQuerySymbolicLinkObject(LinkHandle,
                                               SystemRootPath,
                                               &BufferSize);
            NtClose(LinkHandle);
        }
    }
    ASSERT(SystemRootPath->Length < SystemRootPath->MaximumLength);

    /*
     * If the resolved \SystemRoot is a prefix of the image file path,
     * use \SystemRoot instead as the installation source path.
     *
     * If opening the \SystemRoot link failed (usually due to wrong
     * access rights), do not consider this as a fatal error, and
     * use the image file path as the installation source path.
     */
    if (NT_SUCCESS(Status) && RtlPrefixUnicodeString(SystemRootPath, InstallSourcePath, TRUE))
        InstallSourcePath = SystemRootPath;


    /*
     * Retrieve the different source path components.
     */
    RtlCreateUnicodeString(SourcePath, InstallSourcePath->Buffer);

    /* Isolate and strip the trailing (source root) directory */
    Ptr = wcsrchr(InstallSourcePath->Buffer, OBJ_NAME_PATH_SEPARATOR);
    if (Ptr)
    {
        RtlCreateUnicodeString(SourceRootDir, Ptr);
        *Ptr = UNICODE_NULL;
    }
    else
    {
        RtlCreateUnicodeString(SourceRootDir, L"");
    }

    RtlCreateUnicodeString(SourceRootPath, InstallSourcePath->Buffer);

    return STATUS_SUCCESS;
}

ERROR_NUMBER
LoadSetupInf(
    IN OUT PUSETUP_DATA pSetupData)
{
    INFCONTEXT Context;
    UINT ErrorLine;
    INT IntValue;
    PCWSTR Value;
    WCHAR FileNameBuffer[MAX_PATH];

    CombinePaths(FileNameBuffer, ARRAYSIZE(FileNameBuffer), 2,
                 pSetupData->SourcePath.Buffer, L"txtsetup.sif");

    DPRINT("SetupInf path: '%S'\n", FileNameBuffer);

    pSetupData->SetupInf =
        SpInfOpenInfFile(FileNameBuffer,
                         NULL,
                         INF_STYLE_WIN4,
                         pSetupData->LanguageId,
                         &ErrorLine);
    if (pSetupData->SetupInf == INVALID_HANDLE_VALUE)
        return ERROR_LOAD_TXTSETUPSIF;

    /* Open 'Version' section */
    if (!SpInfFindFirstLine(pSetupData->SetupInf, L"Version", L"Signature", &Context))
        return ERROR_CORRUPT_TXTSETUPSIF;

    /* Get pointer 'Signature' key */
    if (!INF_GetData(&Context, NULL, &Value))
        return ERROR_CORRUPT_TXTSETUPSIF;

    /* Check 'Signature' string */
    if (_wcsicmp(Value, L"$ReactOS$") != 0 &&
        _wcsicmp(Value, L"$Windows NT$") != 0)
    {
        INF_FreeData(Value);
        return ERROR_SIGNATURE_TXTSETUPSIF;
    }

    INF_FreeData(Value);

    /* Open 'DiskSpaceRequirements' section: the architecture's own section
     * ([DiskSpaceRequirements.amd64], the installed set differs a lot between
     * architectures) first, then the common one */
    if (!SpInfFindFirstLine(pSetupData->SetupInf, L"DiskSpaceRequirements." INF_ARCH, L"FreeSysPartDiskSpace", &Context) &&
        !SpInfFindFirstLine(pSetupData->SetupInf, L"DiskSpaceRequirements", L"FreeSysPartDiskSpace", &Context))
        return ERROR_CORRUPT_TXTSETUPSIF;

    pSetupData->RequiredPartitionDiskSpace = ~0;

    /* Get the 'FreeSysPartDiskSpace' value */
    if (!SpInfGetIntField(&Context, 1, &IntValue))
        return ERROR_CORRUPT_TXTSETUPSIF;

    pSetupData->RequiredPartitionDiskSpace = (ULONG)IntValue;

    //
    // Support "SetupSourceDevice" and "SetupSourcePath" in txtsetup.sif
    // See CORE-9023
    // Support for that should also be added in setupldr.
    //

    /* Update the Setup Source paths */
    if (SpInfFindFirstLine(pSetupData->SetupInf, L"SetupData", L"SetupSourceDevice", &Context))
    {
        /*
         * Get optional pointer 'SetupSourceDevice' key, its presence
         * will dictate whether we also need 'SetupSourcePath'.
         */
        if (INF_GetData(&Context, NULL, &Value))
        {
            /* Free the old source root path string and create the new one */
            RtlFreeUnicodeString(&pSetupData->SourceRootPath);
            RtlCreateUnicodeString(&pSetupData->SourceRootPath, Value);
            INF_FreeData(Value);

            if (!SpInfFindFirstLine(pSetupData->SetupInf, L"SetupData", L"SetupSourcePath", &Context))
            {
                /* The 'SetupSourcePath' value is mandatory! */
                return ERROR_CORRUPT_TXTSETUPSIF;
            }

            /* Get pointer 'SetupSourcePath' key */
            if (!INF_GetData(&Context, NULL, &Value))
            {
                /* The 'SetupSourcePath' value is mandatory! */
                return ERROR_CORRUPT_TXTSETUPSIF;
            }

            /* Free the old source path string and create the new one */
            RtlFreeUnicodeString(&pSetupData->SourceRootDir);
            RtlCreateUnicodeString(&pSetupData->SourceRootDir, Value);
            INF_FreeData(Value);
        }
    }

    /* Search for 'DefaultPath' in the 'SetupData' section */
    pSetupData->InstallationDirectory[0] = 0;
    if (SpInfFindFirstLine(pSetupData->SetupInf, L"SetupData", L"DefaultPath", &Context))
    {
        /* Get pointer 'DefaultPath' key */
        if (!INF_GetData(&Context, NULL, &Value))
            return ERROR_CORRUPT_TXTSETUPSIF;

        RtlStringCchCopyW(pSetupData->InstallationDirectory,
                          ARRAYSIZE(pSetupData->InstallationDirectory),
                          Value);

        INF_FreeData(Value);
    }

    return ERROR_SUCCESS;
}

/**
 * @brief   Find or set the active system partition.
 **/
BOOLEAN
NTAPI
InitSystemPartition(
    /**/_In_ PPARTLIST PartitionList,       /* HACK HACK! */
    /**/_In_ PPARTENTRY InstallPartition,   /* HACK HACK! */
    /**/_Out_ PPARTENTRY* pSystemPartition, /* HACK HACK! */
    _In_opt_ PFSVOL_CALLBACK FsVolCallback,
    _In_opt_ PVOID Context)
{
    FSVOL_OP Result;
    PPARTENTRY SystemPartition;
    PPARTENTRY OldActivePart;

    /*
     * UEFI computer: the system partition is the EFI system partition of the
     * disk where we install; it is created there if the disk has none.
     */
    if (PartitionList->IsUefi && InstallPartition->DiskEntry->MediaType == FixedMedia)
    {
        PDISKENTRY InstallDisk = InstallPartition->DiskEntry;

        if (InstallDisk->DiskStyle != PARTITION_STYLE_GPT)
        {
            /* The firmware cannot boot from an MBR disk */
            FsVolCallback(Context, FSVOLNOTIFY_PARTITIONERROR,
                          ERROR_SYSTEM_PARTITION_NOT_FOUND, 0);
            return FALSE;
        }

        SystemPartition = EnsureEfiSystemPartition(PartitionList, InstallDisk);
        if (!SystemPartition)
        {
            FsVolCallback(Context, FSVOLNOTIFY_PARTITIONERROR,
                          ERROR_SYSTEM_PARTITION_NOT_FOUND, 0);
            return FALSE;
        }
        *pSystemPartition = SystemPartition;
        PartitionList->ForeignBootPartition = NULL;

        if (!SetActivePartition(PartitionList, SystemPartition, NULL))
        {
            DPRINT1("SetActivePartition(0x%p) failed?!\n", SystemPartition);
            ASSERT(FALSE);
        }

        /* A file system check of the system partition is always needed */
        if (SystemPartition->Volume)
            SystemPartition->Volume->NeedsCheck = TRUE;
        return TRUE;
    }

    /*
     * If we install on a fixed disk, try to find a supported system
     * partition on the system. Otherwise if we install on a removable disk
     * use the install partition as the system partition.
     */
    if (InstallPartition->DiskEntry->MediaType == FixedMedia)
    {
        SystemPartition = FindSupportedSystemPartition(PartitionList,
                                                       FALSE,
                                                       InstallPartition->DiskEntry,
                                                       InstallPartition);
        /* Use the original system partition as the old active partition hint */
        OldActivePart = PartitionList->SystemPartition;

        if ( SystemPartition && PartitionList->SystemPartition &&
            (SystemPartition != PartitionList->SystemPartition) )
        {
            DPRINT1("We are using a different system partition!!\n");

            Result = FsVolCallback(Context,
                                   ChangeSystemPartition,
                                   (ULONG_PTR)SystemPartition,
                                   0);
            if (Result != FSVOL_DOIT)
                return FALSE;
        }
    }
    else // if (InstallPartition->DiskEntry->MediaType == RemovableMedia)
    {
        SystemPartition = InstallPartition;
        /* Don't specify any old active partition hint */
        OldActivePart = NULL;
    }

    if (!SystemPartition)
    {
        FsVolCallback(Context,
                      FSVOLNOTIFY_PARTITIONERROR,
                      ERROR_SYSTEM_PARTITION_NOT_FOUND,
                      0);
        return FALSE;
    }

    *pSystemPartition = SystemPartition;

    /* Another system's boot partition that loses the active flag stays bootable through FreeLoader */
    PartitionList->ForeignBootPartition = NULL;
    if (OldActivePart && OldActivePart != SystemPartition && IsForeignNtfsBootPartition(OldActivePart))
        PartitionList->ForeignBootPartition = OldActivePart;

    /*
     * If the system partition can be created in some
     * non-partitioned space, create it now.
     */
    if (!SystemPartition->IsPartitioned)
    {
        /* Automatically create the partition; it will be
         * formatted later with default parameters */
        // FIXME: Don't use the whole empty space, but a minimal size
        // specified from the TXTSETUP.SIF or unattended setup.
        CreatePartition(PartitionList,
                        SystemPartition,
                        0ULL,
                        0);
        ASSERT(SystemPartition->IsPartitioned);
    }

    /* Set it as such */
    if (!SetActivePartition(PartitionList, SystemPartition, OldActivePart))
    {
        DPRINT1("SetActivePartition(0x%p) failed?!\n", SystemPartition);
        ASSERT(FALSE);
    }

    /*
     * In all cases, whether or not we are going to perform a formatting,
     * we must perform a filesystem check of the system partition.
     */
    if (SystemPartition->Volume)
        SystemPartition->Volume->NeedsCheck = TRUE;

    return TRUE;
}


#define IS_PATH_SEPARATOR(c)    ((c) == L'\\' || (c) == L'/')

/**
 * @brief
 * Verify whether the given directory is suitable for ReactOS installation.
 * Each path component must be a valid 8.3 name.
 **/
BOOLEAN
NTAPI
IsValidInstallDirectory(
    _In_ PCWSTR InstallDir)
{
    PCWCH p;

    /* As with the NT installer, fail if the path is empty or "\\" */
    p = InstallDir;
    if (!*p || (IS_PATH_SEPARATOR(*p) && !*(p + 1)))
        return FALSE;

    /* The path must contain only valid characters */
    for (p = InstallDir; *p; ++p)
    {
        if (!IS_VALID_INSTALL_PATH_CHAR(*p))
            return FALSE;
    }

    /*
     * Loop over each path component and verify that each is a valid 8.3 name.
     */
    for (p = InstallDir; *p;)
    {
        PCWSTR Path;
        SIZE_T Length;
        UNICODE_STRING Name;
        BOOLEAN IsNameLegal, SpacesInName;

        /* Skip any first separator */
        if (IS_PATH_SEPARATOR(*p))
            ++p;

        /* Now skip past the path component until we reach the next separator */
        Path = p;
        while (*p && !IS_PATH_SEPARATOR(*p))
            ++p;
        if (p == Path)
        {
            /* Succeed if nothing else follows this separator; otherwise
             * it's a separator and consecutive ones are not supported */
            return (!*p);
        }

        /* Calculate the path component length */
        Length = p - Path;

        /* As with the NT installer, fail for '.' and '..';
         * RtlIsNameLegalDOS8Dot3() would succeed otherwise */
        if ((Length == 1 && *Path == '.') || (Length == 2 && *Path == '.' && *(Path + 1) == '.'))
            return FALSE;

        /* As with the NT installer, allow _only ONE trailing_ dot in
         * the path component (but not 2 or more), by reducing Length
         * in that case; RtlIsNameLegalDOS8Dot3() would fail otherwise */
        if (Length > 1 && *(p - 2) != L'.' && *(p - 1) == L'.')
            --Length;

        if (Length == 0)
            return FALSE;

        /* Verify that the path component is a valid 8.3 name */
        // if (Length > 8+1+3)
        //     return FALSE;
        Name.Length = Name.MaximumLength = (USHORT)(Length * sizeof(WCHAR));
        Name.Buffer = (PWCHAR)Path;
        SpacesInName = FALSE;
        IsNameLegal = RtlIsNameLegalDOS8Dot3(&Name, NULL, &SpacesInName);

        /* If it isn't legal or contain spaces, fail */
        if (!IsNameLegal || SpacesInName)
        {
            DPRINT("'%wZ' is %s 8.3 filename %s spaces\n",
                   &Name,
                   (IsNameLegal ? "a valid" : "an invalid"),
                   (SpacesInName ? "with" : "without"));
            return FALSE;
        }
        /* Go to the next path component */
    }

    return TRUE;
}

/**
 * @brief
 * Query an NT path. Returns FALSE when the file system reports it as absent
 * (name or path not found); anything else (found, access denied, ...) counts
 * as existing. The query status is returned in *pStatus.
 **/
static BOOLEAN
NtPathExists(
    _In_ PCWSTR Path,
    _Out_ PNTSTATUS pStatus)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    FILE_BASIC_INFORMATION BasicInfo;

    RtlInitUnicodeString(&Name, Path);
    InitializeObjectAttributes(&ObjectAttributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    *pStatus = NtQueryAttributesFile(&ObjectAttributes, &BasicInfo);

    return !(*pStatus == STATUS_OBJECT_NAME_NOT_FOUND ||
             *pStatus == STATUS_OBJECT_PATH_NOT_FOUND);
}

/**
 * @brief
 * Check whether the installation directory computed by InitDestinationPaths()
 * (pSetupData->DestinationPath) must not receive a new installation:
 *  - it already exists on the target volume, as a directory or as anything
 *    else (it can be another operating system, e.g. a Windows in \Windows);
 *  - or one of its existing parent directories looks like a system directory,
 *    i.e. holds a System32 subdirectory (e.g. \Windows\Sub next to
 *    \Windows\System32): it would pollute that system's tree. Ordinary parent
 *    folders (e.g. \OS in \OS\Nitro) are fine.
 * Anything but "not found" (e.g. access denied) counts as existing.
 **/
BOOLEAN
NTAPI
IsInstallDirectoryInUse(
    _In_ PUSETUP_DATA pSetupData)
{
    NTSTATUS Status;
    WCHAR Prefix[MAX_PATH + 64];
    WCHAR Probe[MAX_PATH + 64];
    PCWSTR p, Comp;
    SIZE_T Length;

    if (!pSetupData->DestinationPath.Buffer || !pSetupData->DestinationPath.Length)
        return FALSE;

    if (NtPathExists(pSetupData->DestinationPath.Buffer, &Status))
    {
        DPRINT1("Installation directory '%wZ' already exists (Status 0x%08lx)\n",
                &pSetupData->DestinationPath, Status);
        return TRUE;
    }

    /* Check every parent directory of the installation directory (not the volume root) */
    if (!pSetupData->DestinationRootPath.Buffer || !pSetupData->InstallPath.Buffer)
        return FALSE;
    if (!NT_SUCCESS(RtlStringCchCopyW(Prefix, ARRAYSIZE(Prefix),
                                      pSetupData->DestinationRootPath.Buffer)))
        return TRUE; /* too long: fail closed */
    Length = wcslen(Prefix);
    while (Length > 0 && IS_PATH_SEPARATOR(Prefix[Length - 1]))
        Prefix[--Length] = UNICODE_NULL;

    p = pSetupData->InstallPath.Buffer;
    while (TRUE)
    {
        SIZE_T CompLen;

        while (IS_PATH_SEPARATOR(*p))
            ++p;
        Comp = p;
        while (*p && !IS_PATH_SEPARATOR(*p))
            ++p;
        CompLen = (SIZE_T)(p - Comp);
        if (CompLen == 0)
            break;
        while (IS_PATH_SEPARATOR(*p))
            ++p;
        /* The last component is the installation directory itself, checked above */
        if (!*p)
            break;

        if (!NT_SUCCESS(RtlStringCchCatW(Prefix, ARRAYSIZE(Prefix), L"\\")) ||
            !NT_SUCCESS(RtlStringCchCatNW(Prefix, ARRAYSIZE(Prefix), Comp, CompLen)) ||
            !NT_SUCCESS(RtlStringCchPrintfW(Probe, ARRAYSIZE(Probe), L"%s\\System32", Prefix)))
        {
            return TRUE;
        }

        if (NtPathExists(Probe, &Status))
        {
            DPRINT1("Installation directory '%wZ' is inside a system directory ('%S' exists, Status 0x%08lx)\n",
                    &pSetupData->DestinationPath, Probe, Status);
            return TRUE;
        }
    }

    return FALSE;
}


NTSTATUS
NTAPI
InitDestinationPaths(
    _Inout_ PUSETUP_DATA pSetupData,
    _In_ PCWSTR InstallationDir,
    _In_ PVOLENTRY Volume)
{
    NTSTATUS Status;
    PPARTENTRY PartEntry = Volume->PartEntry;
    PDISKENTRY DiskEntry = PartEntry->DiskEntry;
    WCHAR PathBuffer[RTL_NUMBER_OF_FIELD(VOLINFO, DeviceName) + 1];

    ASSERT(PartEntry->IsPartitioned && PartEntry->PartitionNumber != 0);

    /* Create 'pSetupData->DestinationRootPath' string */
    RtlFreeUnicodeString(&pSetupData->DestinationRootPath);
    Status = RtlStringCchPrintfW(PathBuffer, _countof(PathBuffer),
                                 L"%s\\", Volume->Info.DeviceName);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlStringCchPrintfW() failed with status 0x%08lx\n", Status);
        return Status;
    }

    Status = RtlCreateUnicodeString(&pSetupData->DestinationRootPath, PathBuffer) ? STATUS_SUCCESS : STATUS_NO_MEMORY;

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlCreateUnicodeString() failed with status 0x%08lx\n", Status);
        return Status;
    }

    DPRINT("DestinationRootPath: %wZ\n", &pSetupData->DestinationRootPath);

    // FIXME! Which variable to choose?
    if (!InstallationDir)
        InstallationDir = pSetupData->InstallationDirectory;

/** Equivalent of 'NTOS_INSTALLATION::SystemArcPath' **/
    /* Create 'pSetupData->DestinationArcPath' */
    RtlFreeUnicodeString(&pSetupData->DestinationArcPath);

    if (DiskEntry->MediaType == FixedMedia)
    {
        if (DiskEntry->BiosFound)
        {
#if 1
            Status = RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                             L"multi(0)disk(0)rdisk(%lu)partition(%lu)\\",
                             DiskEntry->HwFixedDiskNumber,
                             PartEntry->OnDiskPartitionNumber);
#else
            Status = RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                             L"multi(%lu)disk(%lu)rdisk(%lu)partition(%lu)\\",
                             DiskEntry->HwAdapterNumber,
                             DiskEntry->HwControllerNumber,
                             DiskEntry->HwFixedDiskNumber,
                             PartEntry->OnDiskPartitionNumber);
#endif
            DPRINT1("Fixed disk found by BIOS, using MULTI ARC path '%S'\n", PathBuffer);
        }
        else
        {
            Status = RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                             L"scsi(%u)disk(%u)rdisk(%u)partition(%lu)\\",
                             DiskEntry->Port,
                             DiskEntry->Bus,
                             DiskEntry->Id,
                             PartEntry->OnDiskPartitionNumber);
            DPRINT1("Fixed disk not found by BIOS, using SCSI ARC path '%S'\n", PathBuffer);
        }
    }
    else // if (DiskEntry->MediaType == RemovableMedia)
    {
#if 1
        Status = RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                         L"multi(0)disk(0)rdisk(%lu)partition(%lu)\\",
                         0, 1);
        DPRINT1("Removable disk, using MULTI ARC path '%S'\n", PathBuffer);
#else
        Status = RtlStringCchPrintfW(PathBuffer, ARRAYSIZE(PathBuffer),
                         L"signature(%08x)disk(%u)rdisk(%u)partition(%lu)\\",
                         DiskEntry->LayoutBuffer->Signature,
                         DiskEntry->Bus,
                         DiskEntry->Id,
                         PartEntry->OnDiskPartitionNumber);
        DPRINT1("Removable disk, using SIGNATURE ARC path '%S'\n", PathBuffer);
#endif
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlStringCchPrintfW() failed with status 0x%08lx\n", Status);
        RtlFreeUnicodeString(&pSetupData->DestinationRootPath);
        return Status;
    }

    Status = ConcatPaths(PathBuffer, ARRAYSIZE(PathBuffer), 1, InstallationDir);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ConcatPaths() failed with status 0x%08lx\n", Status);
        RtlFreeUnicodeString(&pSetupData->DestinationRootPath);
        return Status;
    }

    Status = RtlCreateUnicodeString(&pSetupData->DestinationArcPath, PathBuffer) ? STATUS_SUCCESS : STATUS_NO_MEMORY;

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlCreateUnicodeString() failed with status 0x%08lx\n", Status);
        RtlFreeUnicodeString(&pSetupData->DestinationRootPath);
        return Status;
    }

    /*
     * On a GPT disk the partition is also named by what a change of the partition table does not move
     * (the boot entries carry it, the loader resolves it at every boot).
     */
    RtlZeroMemory(&pSetupData->DestinationIdentity, sizeof(pSetupData->DestinationIdentity));
    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT && PartEntry->SectorCount.QuadPart != 0)
    {
        pSetupData->DestinationIdentity.IsGpt = TRUE;
        pSetupData->DestinationIdentity.DiskGuid = DiskEntry->GptDiskId;
        pSetupData->DestinationIdentity.PartitionGuid = PartEntry->GptId;
        pSetupData->DestinationIdentity.FirstSector = PartEntry->StartSector.QuadPart;
        pSetupData->DestinationIdentity.LastSector = PartEntry->StartSector.QuadPart +
                                                     PartEntry->SectorCount.QuadPart - 1;
    }

/** Equivalent of 'NTOS_INSTALLATION::SystemNtPath' **/
    /* Create 'pSetupData->DestinationPath' string */
    RtlFreeUnicodeString(&pSetupData->DestinationPath);
    Status = CombinePaths(PathBuffer, ARRAYSIZE(PathBuffer), 2,
                          pSetupData->DestinationRootPath.Buffer, InstallationDir);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("CombinePaths() failed with status 0x%08lx\n", Status);
        RtlFreeUnicodeString(&pSetupData->DestinationArcPath);
        RtlFreeUnicodeString(&pSetupData->DestinationRootPath);
        return Status;
    }

    Status = RtlCreateUnicodeString(&pSetupData->DestinationPath, PathBuffer) ? STATUS_SUCCESS : STATUS_NO_MEMORY;

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlCreateUnicodeString() failed with status 0x%08lx\n", Status);
        RtlFreeUnicodeString(&pSetupData->DestinationArcPath);
        RtlFreeUnicodeString(&pSetupData->DestinationRootPath);
        return Status;
    }

/** Equivalent of 'NTOS_INSTALLATION::PathComponent' **/
    // FIXME: This is only temporary!! Must be removed later!
    Status = RtlCreateUnicodeString(&pSetupData->InstallPath, InstallationDir) ? STATUS_SUCCESS : STATUS_NO_MEMORY;

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlCreateUnicodeString() failed with status 0x%08lx\n", Status);
        RtlFreeUnicodeString(&pSetupData->DestinationPath);
        RtlFreeUnicodeString(&pSetupData->DestinationArcPath);
        RtlFreeUnicodeString(&pSetupData->DestinationRootPath);
        return Status;
    }

    return STATUS_SUCCESS;
}

// NTSTATUS
ERROR_NUMBER
NTAPI
InitializeSetup(
    _Inout_ PUSETUP_DATA pSetupData,
    _In_opt_ PSETUP_ERROR_ROUTINE ErrorRoutine,
    _In_ PSPFILE_EXPORTS pSpFileExports,
    _In_ PSPINF_EXPORTS pSpInfExports)
{
    ERROR_NUMBER Error;
    NTSTATUS Status;

    IsUnattendedSetup = FALSE;
    RtlZeroMemory(pSetupData, sizeof(*pSetupData));

    /* Initialize error handling */
    pSetupData->LastErrorNumber = ERROR_SUCCESS;
    pSetupData->ErrorRoutine = ErrorRoutine;

    /* Initialize global unicode strings */
    RtlInitUnicodeString(&pSetupData->SourcePath, NULL);
    RtlInitUnicodeString(&pSetupData->SourceRootPath, NULL);
    RtlInitUnicodeString(&pSetupData->SourceRootDir, NULL);
    RtlInitUnicodeString(&pSetupData->DestinationArcPath, NULL);
    RtlInitUnicodeString(&pSetupData->DestinationPath, NULL);
    RtlInitUnicodeString(&pSetupData->DestinationRootPath, NULL);
    RtlInitUnicodeString(&pSetupData->SystemRootPath, NULL);

    // FIXME: This is only temporary!! Must be removed later!
    /***/RtlInitUnicodeString(&pSetupData->InstallPath, NULL);/***/

    /* Initialize SpFile and SpInf support */
    RtlCopyMemory(&SpFileExports, pSpFileExports, sizeof(SpFileExports));
    RtlCopyMemory(&SpInfExports, pSpInfExports, sizeof(SpInfExports));

    //
    // TODO: Load and start SetupDD, and ask it for the information
    //

    /* Get the source path and source root path */
    Status = GetSourcePaths(&pSetupData->SourcePath,
                            &pSetupData->SourceRootPath,
                            &pSetupData->SourceRootDir);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("GetSourcePaths() failed (Status 0x%08lx)\n", Status);
        return ERROR_NO_SOURCE_DRIVE;
    }
    DPRINT1("SourcePath (1): '%wZ'\n", &pSetupData->SourcePath);
    DPRINT1("SourceRootPath (1): '%wZ'\n", &pSetupData->SourceRootPath);
    DPRINT1("SourceRootDir (1): '%wZ'\n", &pSetupData->SourceRootDir);

    /* Set up default values */
    pSetupData->DestinationDiskNumber = 0;
    pSetupData->DestinationPartitionNumber = 1;
    pSetupData->BootLoaderLocation = 2; // Default to "System partition"
    pSetupData->FormatPartition = 0;
    pSetupData->AutoPartition = 0;
    pSetupData->FsType = 2; // NTFS, unless the unattend file says otherwise

    /* Load 'txtsetup.sif' from the installation media */
    Error = LoadSetupInf(pSetupData);
    if (Error != ERROR_SUCCESS)
    {
        DPRINT1("LoadSetupInf() failed (Error 0x%lx)\n", Error);
        return Error;
    }
    DPRINT1("SourcePath (2): '%wZ'\n", &pSetupData->SourcePath);
    DPRINT1("SourceRootPath (2): '%wZ'\n", &pSetupData->SourceRootPath);
    DPRINT1("SourceRootDir (2): '%wZ'\n", &pSetupData->SourceRootDir);

    /* Retrieve the target machine architecture type */
    // FIXME: This should be determined at runtime!!
    // FIXME: Allow for (pre-)installing on an architecture
    //        different from the current one?
#if defined(SARCH_XBOX)
    pSetupData->ArchType = ARCH_Xbox;
// #elif defined(SARCH_PC98)
#else // TODO: Arc
    if (IsUefiBoot())
        pSetupData->ArchType = ARCH_Efi;
    else
        pSetupData->ArchType = (IsNEC_98 ? ARCH_NEC98x86 : ARCH_PcAT);
#endif

    return ERROR_SUCCESS;
}

VOID
NTAPI
FinishSetup(
    IN OUT PUSETUP_DATA pSetupData)
{
    /* Destroy the computer settings list */
    if (pSetupData->ComputerList != NULL)
    {
        DestroyGenericList(pSetupData->ComputerList, TRUE);
        pSetupData->ComputerList = NULL;
    }

    /* Destroy the display settings list */
    if (pSetupData->DisplayList != NULL)
    {
        DestroyGenericList(pSetupData->DisplayList, TRUE);
        pSetupData->DisplayList = NULL;
    }

    /* Destroy the keyboard settings list */
    if (pSetupData->KeyboardList != NULL)
    {
        DestroyGenericList(pSetupData->KeyboardList, TRUE);
        pSetupData->KeyboardList = NULL;
    }

    /* Destroy the keyboard layout list */
    if (pSetupData->LayoutList != NULL)
    {
        DestroyGenericList(pSetupData->LayoutList, TRUE);
        pSetupData->LayoutList = NULL;
    }

    /* Destroy the languages list */
    if (pSetupData->LanguageList != NULL)
    {
        DestroyGenericList(pSetupData->LanguageList, FALSE);
        pSetupData->LanguageList = NULL;
    }

    /* Close the Setup INF */
    SpInfCloseInfFile(pSetupData->SetupInf);
}

/*
 * SIDEEFFECTS
 *  Calls RegInitializeRegistry
 *  Calls ImportRegistryFile
 *  Calls SetDefaultPagefile
 *  Calls SetMountedDeviceValues
 */
ERROR_NUMBER
NTAPI
UpdateRegistry(
    IN OUT PUSETUP_DATA pSetupData,
    /**/IN BOOLEAN RepairUpdateFlag,     /* HACK HACK! */
    /**/IN PPARTLIST PartitionList,      /* HACK HACK! */
    /**/IN WCHAR DestinationDriveLetter, /* HACK HACK! */
    /**/IN PCWSTR SelectedLanguageId,    /* HACK HACK! */
    IN PREGISTRY_STATUS_ROUTINE StatusRoutine OPTIONAL,
    IN PFONTSUBSTSETTINGS SubstSettings OPTIONAL)
{
    ERROR_NUMBER ErrorNumber;
    NTSTATUS Status;
    INFCONTEXT InfContext;
    PCWSTR Action;
    PCWSTR File;
    PCWSTR Section;
    BOOLEAN Success;
    BOOLEAN ShouldRepairRegistry = FALSE;
    BOOLEAN Delete;

    if (RepairUpdateFlag)
    {
        DPRINT1("TODO: Updating / repairing the registry is not completely implemented yet!\n");

        /* Verify the registry hives and check whether we need to update or repair any of them */
        Status = VerifyRegistryHives(&pSetupData->DestinationPath, &ShouldRepairRegistry);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("VerifyRegistryHives failed, Status 0x%08lx\n", Status);
            ShouldRepairRegistry = FALSE;
        }
        if (!ShouldRepairRegistry)
            DPRINT1("No need to repair the registry\n");
    }

DoUpdate:
    ErrorNumber = ERROR_SUCCESS;

    /* Update the registry */
    if (StatusRoutine) StatusRoutine(RegHiveUpdate);

    /* Initialize the registry and setup the registry hives */
    Status = RegInitializeRegistry(&pSetupData->DestinationPath);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RegInitializeRegistry() failed\n");
        /********** HACK!!!!!!!!!!! **********/
        if (Status == STATUS_NOT_IMPLEMENTED)
        {
            /* The hack was called, return its corresponding error */
            return ERROR_INITIALIZE_REGISTRY;
        }
        else
        /*************************************/
        {
            /* Something else failed */
            return ERROR_CREATE_HIVE;
        }
    }

    if (!RepairUpdateFlag || ShouldRepairRegistry)
    {
        /*
         * We fully setup the hives, in case we are doing a fresh installation
         * (RepairUpdateFlag == FALSE), or in case we are doing an update
         * (RepairUpdateFlag == TRUE) BUT we have some registry hives to
         * "repair" (aka. recreate: ShouldRepairRegistry == TRUE).
         */

        Success = SpInfFindFirstLine(pSetupData->SetupInf, L"HiveInfs.Fresh", NULL, &InfContext);       // Windows-compatible
        if (!Success)
            Success = SpInfFindFirstLine(pSetupData->SetupInf, L"HiveInfs.Install", NULL, &InfContext); // ReactOS-specific

        if (!Success)
        {
            DPRINT1("SpInfFindFirstLine() failed\n");
            ErrorNumber = ERROR_FIND_REGISTRY;
            goto Cleanup;
        }
    }
    else // if (RepairUpdateFlag && !ShouldRepairRegistry)
    {
        /*
         * In case we are doing an update (RepairUpdateFlag == TRUE) and
         * NO registry hives need a repair (ShouldRepairRegistry == FALSE),
         * we only update the hives.
         */

        Success = SpInfFindFirstLine(pSetupData->SetupInf, L"HiveInfs.Upgrade", NULL, &InfContext);
        if (!Success)
        {
            /* Nothing to do for update! */
            DPRINT1("No update needed for the registry!\n");
            goto Cleanup;
        }
    }

    do
    {
        INF_GetDataField(&InfContext, 0, &Action);
        INF_GetDataField(&InfContext, 1, &File);
        INF_GetDataField(&InfContext, 2, &Section);

        DPRINT("Action: %S  File: %S  Section %S\n", Action, File, Section);

        if (Action == NULL)
        {
            INF_FreeData(Action);
            INF_FreeData(File);
            INF_FreeData(Section);
            break; // Hackfix
        }

        if (!_wcsicmp(Action, L"AddReg"))
            Delete = FALSE;
        else if (!_wcsicmp(Action, L"DelReg"))
            Delete = TRUE;
        else
        {
            DPRINT1("Unrecognized registry INF action '%S'\n", Action);
            INF_FreeData(Action);
            INF_FreeData(File);
            INF_FreeData(Section);
            continue;
        }

        INF_FreeData(Action);

        if (StatusRoutine) StatusRoutine(ImportRegHive, File);

        if (!ImportRegistryFile(pSetupData->SourcePath.Buffer,
                                File, Section,
                                pSetupData->LanguageId, Delete))
        {
            DPRINT1("Importing %S failed\n", File);
            INF_FreeData(File);
            INF_FreeData(Section);
            ErrorNumber = ERROR_IMPORT_HIVE;
            goto Cleanup;
        }
    } while (SpInfFindNextLine(&InfContext, &InfContext));

    if (!RepairUpdateFlag || ShouldRepairRegistry)
    {
        /* See the explanation for this test above */

        PGENERIC_LIST_ENTRY Entry;
        PCWSTR LanguageId; // LocaleID;

        /* The registry lines of the components that are left out, and the record of the selection */
        (void)ComponentsApplyRegistry((PCOMPONENTS_STATE)pSetupData->Components);

        Entry = GetCurrentListEntry(pSetupData->DisplayList);
        ASSERT(Entry);
        pSetupData->DisplayType = ((PGENENTRY)GetListEntryData(Entry))->Id;
        ASSERT(pSetupData->DisplayType);

        /* Update display registry settings */
        if (StatusRoutine) StatusRoutine(DisplaySettingsUpdate);
        if (!ProcessDisplayRegistry(pSetupData->SetupInf, pSetupData->DisplayType))
        {
            ErrorNumber = ERROR_UPDATE_DISPLAY_SETTINGS;
            goto Cleanup;
        }

        Entry = GetCurrentListEntry(pSetupData->LanguageList);
        ASSERT(Entry);
        LanguageId = ((PGENENTRY)GetListEntryData(Entry))->Id;
        ASSERT(LanguageId);

        /* Set the locale */
        if (StatusRoutine) StatusRoutine(LocaleSettingsUpdate);
        if (!ProcessLocaleRegistry(/*pSetupData->*/LanguageId))
        {
            ErrorNumber = ERROR_UPDATE_LOCALESETTINGS;
            goto Cleanup;
        }

        /* Add the keyboard layouts for the given language (without user override) */
        if (StatusRoutine) StatusRoutine(KeybLayouts);
        if (!AddKeyboardLayouts(SelectedLanguageId))
        {
            ErrorNumber = ERROR_ADDING_KBLAYOUTS;
            goto Cleanup;
        }

        Entry = GetCurrentListEntry(pSetupData->LayoutList);
        ASSERT(Entry);
        pSetupData->LayoutId = ((PGENENTRY)GetListEntryData(Entry))->Id;
        ASSERT(pSetupData->LayoutId);

        /* Update keyboard layout settings with user-overridden values */
        // FIXME: Wouldn't it be better to do it all at once
        // with the AddKeyboardLayouts() step?
        if (StatusRoutine) StatusRoutine(KeybSettingsUpdate);
        if (!ProcessKeyboardLayoutRegistry(pSetupData->LayoutId, SelectedLanguageId))
        {
            ErrorNumber = ERROR_UPDATE_KBSETTINGS;
            goto Cleanup;
        }

        /* Set GeoID */
        if (!SetGeoID(MUIGetGeoID(SelectedLanguageId)))
        {
            ErrorNumber = ERROR_UPDATE_GEOID;
            goto Cleanup;
        }

        /* Add codepage information to registry */
        if (StatusRoutine) StatusRoutine(CodePageInfoUpdate);
        if (!AddCodePage(SelectedLanguageId))
        {
            ErrorNumber = ERROR_ADDING_CODEPAGE;
            goto Cleanup;
        }

        /* Set the default pagefile entry */
        SetDefaultPagefile(DestinationDriveLetter);

        /* Update the mounted devices list */
        // FIXME: This should technically be done by mountmgr (if AutoMount is enabled)!
        SetMountedDeviceValues(PartitionList);
    }

#ifdef __REACTOS__
    if (SubstSettings)
    {
        /* HACK */
        DoRegistryFontFixup(SubstSettings, wcstoul(SelectedLanguageId, NULL, 16));
    }
#endif

Cleanup:
    //
    // TODO: Unload all the registry stuff, perform cleanup,
    // and copy the created hive files into .sav files.
    //
    RegCleanupRegistry(&pSetupData->DestinationPath);

    /*
     * Check whether we were in update/repair mode but we were actually
     * repairing the registry hives. If so, we have finished repairing them,
     * and we now reset the flag and run the proper registry update.
     * Otherwise we have finished the registry update!
     */
    if (RepairUpdateFlag && ShouldRepairRegistry)
    {
        ShouldRepairRegistry = FALSE;
        goto DoUpdate;
    }

    return ErrorNumber;
}

/* EOF */
