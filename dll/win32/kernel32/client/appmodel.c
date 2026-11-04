/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Package identity functions of Windows 8 and later
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* INCLUDES *******************************************************************/

#include <k32.h>
#include <appmodel.h>

#define NDEBUG
#include <debug.h>

/*
 * Every process is a process without a package, and no package is installed. The functions that name the package
 * of a process or look packages up answer as Windows answers an unpackaged process on a system that has none; the
 * ones that only read a package name, an application user model id or a package id are the parsers of the
 * syntax that Windows has for them. The results and errors were measured on Windows 10 (version 22H2).
 */

#define BASEP_ARCH_UNKNOWN      0xFFFF
#define BASEP_VERSION_DIGITS    5

#ifndef PROCESSOR_ARCHITECTURE_NEUTRAL
#define PROCESSOR_ARCHITECTURE_NEUTRAL  11
#endif
#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64    12
#endif

/* GRAMMAR ********************************************************************/

typedef struct _BASEP_PACKAGE_NAME
{
    PCWSTR Name;
    ULONG NameLength;
    PCWSTR ResourceId;
    ULONG ResourceIdLength;
    PCWSTR PublisherId;
    ULONG Architecture;
    UINT64 Version;
} BASEP_PACKAGE_NAME;

static
BOOLEAN
BasepIsNameCharacter(
    _In_ WCHAR Character)
{
    return (Character >= L'0' && Character <= L'9') ||
           (Character >= L'a' && Character <= L'z') ||
           (Character >= L'A' && Character <= L'Z') ||
           Character == L'.' || Character == L'-';
}

/* The names of devices cannot be the names of packages, with or without an extension */
static
BOOLEAN
BasepIsDeviceName(
    _In_ PCWSTR Name,
    _In_ ULONG Length)
{
    ULONG Prefix = 0;

    while (Prefix < Length && Name[Prefix] != L'.')
        Prefix++;

    if (Prefix == 3)
    {
        return !_wcsnicmp(Name, L"con", 3) || !_wcsnicmp(Name, L"prn", 3) ||
               !_wcsnicmp(Name, L"aux", 3) || !_wcsnicmp(Name, L"nul", 3);
    }
    if (Prefix == 4 && Name[3] >= L'1' && Name[3] <= L'9')
        return !_wcsnicmp(Name, L"com", 3) || !_wcsnicmp(Name, L"lpt", 3);

    return FALSE;
}

static
BOOLEAN
BasepIsPackageName(
    _In_ PCWSTR Name,
    _In_ ULONG Length)
{
    ULONG i;

    if (Length < 3 || Length > PACKAGE_NAME_MAX_LENGTH || Name[Length - 1] == L'.')
        return FALSE;

    for (i = 0; i < Length; i++)
    {
        if (!BasepIsNameCharacter(Name[i]))
            return FALSE;
    }

    return !BasepIsDeviceName(Name, Length);
}

static
BOOLEAN
BasepIsResourceId(
    _In_ PCWSTR Name,
    _In_ ULONG Length)
{
    ULONG i;

    if (Length > PACKAGE_RESOURCEID_MAX_LENGTH || (Length != 0 && Name[Length - 1] == L'.'))
        return FALSE;

    for (i = 0; i < Length; i++)
    {
        if (!BasepIsNameCharacter(Name[i]))
            return FALSE;
    }

    return TRUE;
}

/* Thirteen characters of base 32 without the letters i, l, o and u, in either case */
static
BOOLEAN
BasepIsPublisherId(
    _In_ PCWSTR Name,
    _In_ ULONG Length)
{
    ULONG i;
    WCHAR Character;

    if (Length != PACKAGE_PUBLISHERID_MAX_LENGTH)
        return FALSE;

    for (i = 0; i < Length; i++)
    {
        Character = Name[i];
        if (Character >= L'A' && Character <= L'Z')
            Character += L'a' - L'A';

        if (!((Character >= L'0' && Character <= L'9') || (Character >= L'a' && Character <= L'z')) ||
            Character == L'i' || Character == L'l' || Character == L'o' || Character == L'u')
        {
            return FALSE;
        }
    }

    return TRUE;
}

static
BOOLEAN
BasepIsRelativeApplicationId(
    _In_ PCWSTR Name,
    _In_ ULONG Length)
{
    ULONG i;

    if (Length == 0 || Length > PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH)
        return FALSE;

    for (i = 0; i < Length; i++)
    {
        if (!BasepIsNameCharacter(Name[i]) || Name[i] == L'-')
            return FALSE;
    }

    return TRUE;
}

/* Four numbers up to 65535 separated by dots; a number can be left out */
static
BOOLEAN
BasepParseVersion(
    _In_ PCWSTR String,
    _In_ ULONG Length,
    _Out_ UINT64 *Version)
{
    ULONG Field = 0, Digits = 0, Value = 0, i;
    UINT64 Result = 0;

    for (i = 0; i <= Length; i++)
    {
        if (i == Length || String[i] == L'.')
        {
            Result = (Result << 16) | Value;
            Field++;
            Value = 0;
            Digits = 0;
            continue;
        }

        if (String[i] < L'0' || String[i] > L'9' || ++Digits > BASEP_VERSION_DIGITS)
            return FALSE;

        Value = Value * 10 + (String[i] - L'0');
        if (Value > 0xFFFF)
            return FALSE;
    }

    if (Field != 4)
        return FALSE;

    *Version = Result;
    return TRUE;
}

static const struct
{
    PCWSTR Name;
    ULONG Length;
    ULONG Architecture;
} BasepArchitectures[] =
{
    { L"x86", 3, PROCESSOR_ARCHITECTURE_INTEL },
    { L"arm", 3, PROCESSOR_ARCHITECTURE_ARM },
    { L"x64", 3, PROCESSOR_ARCHITECTURE_AMD64 },
    { L"neutral", 7, PROCESSOR_ARCHITECTURE_NEUTRAL },
    { L"arm64", 5, PROCESSOR_ARCHITECTURE_ARM64 },
    { L"x86a64", 6, 14 },
    { L"unknown", 7, BASEP_ARCH_UNKNOWN },
};

static
BOOLEAN
BasepParseArchitecture(
    _In_ PCWSTR String,
    _In_ ULONG Length,
    _Out_ PULONG Architecture)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(BasepArchitectures); i++)
    {
        if (Length == BasepArchitectures[i].Length && !_wcsnicmp(String, BasepArchitectures[i].Name, Length))
        {
            *Architecture = BasepArchitectures[i].Architecture;
            return TRUE;
        }
    }

    return FALSE;
}

static
PCWSTR
BasepArchitectureName(
    _In_ ULONG Architecture)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(BasepArchitectures); i++)
    {
        if (BasepArchitectures[i].Architecture == Architecture)
            return BasepArchitectures[i].Name;
    }

    return NULL;
}

/* Splits at the first of Separator that is at or behind Start; returns the length of the part */
static
ULONG
BasepFieldLength(
    _In_ PCWSTR String,
    _In_ WCHAR Separator)
{
    ULONG Length = 0;

    while (String[Length] != UNICODE_NULL && String[Length] != Separator)
        Length++;

    return Length;
}

static
BOOLEAN
BasepParseFullName(
    _In_ PCWSTR FullName,
    _Out_ BASEP_PACKAGE_NAME *Parsed)
{
    ULONG Length, ArchitectureLength, VersionLength;
    PCWSTR Version, Architecture;

    /* name_version_architecture_resourceid_publisherid: four underscores */
    Parsed->Name = FullName;
    Parsed->NameLength = BasepFieldLength(FullName, L'_');
    if (FullName[Parsed->NameLength] != L'_')
        return FALSE;

    Version = FullName + Parsed->NameLength + 1;
    VersionLength = BasepFieldLength(Version, L'_');
    if (Version[VersionLength] != L'_')
        return FALSE;

    Architecture = Version + VersionLength + 1;
    ArchitectureLength = BasepFieldLength(Architecture, L'_');
    if (Architecture[ArchitectureLength] != L'_')
        return FALSE;

    Parsed->ResourceId = Architecture + ArchitectureLength + 1;
    Parsed->ResourceIdLength = BasepFieldLength(Parsed->ResourceId, L'_');
    if (Parsed->ResourceId[Parsed->ResourceIdLength] != L'_')
        return FALSE;

    Parsed->PublisherId = Parsed->ResourceId + Parsed->ResourceIdLength + 1;
    Length = BasepFieldLength(Parsed->PublisherId, L'_');
    if (Parsed->PublisherId[Length] != UNICODE_NULL)
        return FALSE;

    return BasepIsPackageName(Parsed->Name, Parsed->NameLength) &&
           BasepParseVersion(Version, VersionLength, &Parsed->Version) &&
           BasepParseArchitecture(Architecture, ArchitectureLength, &Parsed->Architecture) &&
           BasepIsResourceId(Parsed->ResourceId, Parsed->ResourceIdLength) &&
           BasepIsPublisherId(Parsed->PublisherId, Length);
}

static
BOOLEAN
BasepParseFamilyName(
    _In_ PCWSTR FamilyName,
    _Out_ PULONG NameLength,
    _Out_ PCWSTR *PublisherId)
{
    ULONG Length = BasepFieldLength(FamilyName, L'_');

    if (FamilyName[Length] != L'_')
        return FALSE;

    *NameLength = Length;
    *PublisherId = FamilyName + Length + 1;
    return BasepIsPackageName(FamilyName, Length) &&
           BasepIsPublisherId(*PublisherId, BasepFieldLength(*PublisherId, UNICODE_NULL));
}

static
BOOLEAN
BasepParseUserModelId(
    _In_ PCWSTR UserModelId,
    _Out_ PULONG FamilyLength,
    _Out_ PCWSTR *RelativeId,
    _Out_ PULONG RelativeIdLength)
{
    ULONG NameLength;
    PCWSTR PublisherId;

    *FamilyLength = BasepFieldLength(UserModelId, L'!');
    if (UserModelId[*FamilyLength] != L'!')
        return FALSE;

    *RelativeId = UserModelId + *FamilyLength + 1;
    *RelativeIdLength = BasepFieldLength(*RelativeId, UNICODE_NULL);
    if (!BasepIsRelativeApplicationId(*RelativeId, *RelativeIdLength))
        return FALSE;

    /* The family name is the part in front of the exclamation mark */
    {
        WCHAR Family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];

        if (*FamilyLength > PACKAGE_FAMILY_NAME_MAX_LENGTH)
            return FALSE;

        RtlCopyMemory(Family, UserModelId, *FamilyLength * sizeof(WCHAR));
        Family[*FamilyLength] = UNICODE_NULL;
        return BasepParseFamilyName(Family, &NameLength, &PublisherId);
    }
}

/* RESULTS ********************************************************************/

/* Copies a string of Length characters to a caller's buffer that has *BufferLength characters */
static
LONG
BasepReturnString(
    _Inout_ UINT32 *BufferLength,
    _Out_writes_opt_(*BufferLength) PWSTR Buffer,
    _In_ PCWSTR String,
    _In_ ULONG Length)
{
    UINT32 Capacity = *BufferLength;

    *BufferLength = Length + 1;
    if (Capacity < Length + 1)
        return ERROR_INSUFFICIENT_BUFFER;

    RtlCopyMemory(Buffer, String, Length * sizeof(WCHAR));
    Buffer[Length] = UNICODE_NULL;
    return ERROR_SUCCESS;
}

/* A length and a buffer that go together: no buffer is fine only for a length of 0 */
static
LONG
BasepCheckBuffer(
    _In_ const UINT32 *BufferLength,
    _In_opt_ PVOID Buffer)
{
    UINT32 Length;
    LONG Error = ERROR_SUCCESS;

    if (!BufferLength)
        return ERROR_INVALID_PARAMETER;

    _SEH2_TRY
    {
        Length = *BufferLength;
        if (Length != 0 && !Buffer)
            Error = ERROR_INVALID_PARAMETER;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

static
LONG
BasepNoPackage(
    _In_ const UINT32 *BufferLength,
    _In_opt_ PVOID Buffer,
    _In_ LONG Result)
{
    LONG Error = BasepCheckBuffer(BufferLength, Buffer);

    return Error != ERROR_SUCCESS ? Error : Result;
}

static
LONG
BasepNoPackageOfProcess(
    _In_ HANDLE ProcessHandle,
    _In_ const UINT32 *BufferLength,
    _In_opt_ PVOID Buffer,
    _In_ LONG Result)
{
    LONG Error = BasepCheckBuffer(BufferLength, Buffer);
    NTSTATUS Status;

    if (Error != ERROR_SUCCESS)
        return Error;

    /* A null handle is a wrong parameter, not a wrong handle */
    if (!ProcessHandle)
        return ERROR_INVALID_PARAMETER;

    Status = BasepCheckHandleType(ProcessHandle,
                                  L"Process",
                                  PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    return Result;
}

static
LONG
BasepNoPackageOfToken(
    _In_ HANDLE TokenHandle,
    _In_ const UINT32 *BufferLength,
    _In_opt_ PVOID Buffer,
    _In_ LONG Result)
{
    LONG Error = BasepCheckBuffer(BufferLength, Buffer);
    NTSTATUS Status;

    if (Error != ERROR_SUCCESS)
        return Error;

    if (!TokenHandle)
        return ERROR_INVALID_PARAMETER;

    /* The pseudo handles of the tokens of the process and of the thread */
    if (TokenHandle == (HANDLE)(LONG_PTR)-4 || TokenHandle == (HANDLE)(LONG_PTR)-5 || TokenHandle == (HANDLE)(LONG_PTR)-6)
        return Result;

    Status = BasepCheckHandleType(TokenHandle, L"Token", TOKEN_QUERY);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    return Result;
}

/* PUBLIC FUNCTIONS: THE PACKAGE OF A PROCESS *********************************/

/*
 * @implemented
 */
LONG
WINAPI
GetCurrentPackageFullName(
    _Inout_ UINT32 *packageFullNameLength,
    _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName)
{
    return BasepNoPackage(packageFullNameLength, packageFullName, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetCurrentPackageFamilyName(
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName)
{
    return BasepNoPackage(packageFamilyNameLength, packageFamilyName, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetCurrentPackageId(
    _Inout_ UINT32 *bufferLength,
    _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer)
{
    return BasepNoPackage(bufferLength, buffer, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetCurrentPackagePath(
    _Inout_ UINT32 *pathLength,
    _Out_writes_opt_(*pathLength) PWSTR path)
{
    return BasepNoPackage(pathLength, path, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetCurrentPackageInfo(
    _In_ const UINT32 flags,
    _Inout_ UINT32 *bufferLength,
    _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer,
    _Out_opt_ UINT32 *count)
{
    LONG Error = BasepNoPackage(bufferLength, buffer, APPMODEL_ERROR_NO_PACKAGE);

    /* The count is not optional here, whatever the declaration says */
    if (Error == APPMODEL_ERROR_NO_PACKAGE && !count)
        return ERROR_INVALID_PARAMETER;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
GetCurrentApplicationUserModelId(
    _Inout_ UINT32 *applicationUserModelIdLength,
    _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId)
{
    return BasepNoPackage(applicationUserModelIdLength, applicationUserModelId, APPMODEL_ERROR_NO_APPLICATION);
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackageFullName(
    _In_ HANDLE hProcess,
    _Inout_ UINT32 *packageFullNameLength,
    _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName)
{
    return BasepNoPackageOfProcess(hProcess, packageFullNameLength, packageFullName, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackageFamilyName(
    _In_ HANDLE hProcess,
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName)
{
    return BasepNoPackageOfProcess(hProcess, packageFamilyNameLength, packageFamilyName, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackageId(
    _In_ HANDLE hProcess,
    _Inout_ UINT32 *bufferLength,
    _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer)
{
    return BasepNoPackageOfProcess(hProcess, bufferLength, buffer, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetApplicationUserModelId(
    _In_ HANDLE hProcess,
    _Inout_ UINT32 *applicationUserModelIdLength,
    _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId)
{
    return BasepNoPackageOfProcess(hProcess, applicationUserModelIdLength, applicationUserModelId, APPMODEL_ERROR_NO_APPLICATION);
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackageFullNameFromToken(
    _In_ HANDLE token,
    _Inout_ UINT32 *packageFullNameLength,
    _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName)
{
    return BasepNoPackageOfToken(token, packageFullNameLength, packageFullName, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackageFamilyNameFromToken(
    _In_ HANDLE token,
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName)
{
    return BasepNoPackageOfToken(token, packageFamilyNameLength, packageFamilyName, APPMODEL_ERROR_NO_PACKAGE);
}

/*
 * @implemented
 */
LONG
WINAPI
GetApplicationUserModelIdFromToken(
    _In_ HANDLE token,
    _Inout_ UINT32 *applicationUserModelIdLength,
    _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId)
{
    return BasepNoPackageOfToken(token, applicationUserModelIdLength, applicationUserModelId, APPMODEL_ERROR_NO_APPLICATION);
}

/* PUBLIC FUNCTIONS: THE SYNTAX OF NAMES **************************************/

/*
 * @implemented
 */
LONG
WINAPI
VerifyPackageFullName(
    _In_ PCWSTR packageFullName)
{
    BASEP_PACKAGE_NAME Parsed;
    LONG Result = ERROR_SUCCESS;

    if (!packageFullName)
        return ERROR_INVALID_PARAMETER;

    _SEH2_TRY
    {
        if (!BasepParseFullName(packageFullName, &Parsed))
            Result = ERROR_INVALID_PARAMETER;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Result;
}

/*
 * @implemented
 */
LONG
WINAPI
VerifyPackageFamilyName(
    _In_ PCWSTR packageFamilyName)
{
    ULONG NameLength;
    PCWSTR PublisherId;
    LONG Result = ERROR_SUCCESS;

    if (!packageFamilyName)
        return ERROR_INVALID_PARAMETER;

    _SEH2_TRY
    {
        if (!BasepParseFamilyName(packageFamilyName, &NameLength, &PublisherId))
            Result = ERROR_INVALID_PARAMETER;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Result;
}

/*
 * @implemented
 */
LONG
WINAPI
VerifyPackageRelativeApplicationId(
    _In_ PCWSTR packageRelativeApplicationId)
{
    LONG Result = ERROR_SUCCESS;

    if (!packageRelativeApplicationId)
        return ERROR_INVALID_PARAMETER;

    _SEH2_TRY
    {
        if (!BasepIsRelativeApplicationId(packageRelativeApplicationId, wcslen(packageRelativeApplicationId)))
            Result = ERROR_INVALID_PARAMETER;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Result;
}

/*
 * @implemented
 */
LONG
WINAPI
VerifyApplicationUserModelId(
    _In_ PCWSTR applicationUserModelId)
{
    ULONG FamilyLength, RelativeIdLength;
    PCWSTR RelativeId;
    LONG Result = ERROR_SUCCESS;

    if (!applicationUserModelId)
        return ERROR_INVALID_PARAMETER;

    _SEH2_TRY
    {
        if (!BasepParseUserModelId(applicationUserModelId, &FamilyLength, &RelativeId, &RelativeIdLength))
            Result = ERROR_INVALID_PARAMETER;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Result;
}

/* A package identity of a caller must be one that Windows takes: name, publisher id, architecture, resource id */
static
LONG
BasepCheckPackageId(
    _In_ const PACKAGE_ID *PackageId,
    _Out_ PCWSTR *ResourceId,
    _Out_ PULONG ResourceIdLength)
{
    LONG Result = ERROR_SUCCESS;

    _SEH2_TRY
    {
        *ResourceId = PackageId->resourceId ? PackageId->resourceId : L"";
        *ResourceIdLength = wcslen(*ResourceId);

        if (!PackageId->name || !PackageId->publisherId ||
            !BasepIsPackageName(PackageId->name, wcslen(PackageId->name)) ||
            !BasepIsPublisherId(PackageId->publisherId, wcslen(PackageId->publisherId)) ||
            !BasepIsResourceId(*ResourceId, *ResourceIdLength) ||
            BasepArchitectureName(PackageId->processorArchitecture) == NULL)
        {
            Result = ERROR_INVALID_PARAMETER;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Result;
}

/*
 * @implemented
 */
LONG
WINAPI
VerifyPackageId(
    _In_ const PACKAGE_ID *packageId)
{
    PCWSTR ResourceId;
    ULONG ResourceIdLength;

    if (!packageId)
        return ERROR_INVALID_PARAMETER;

    return BasepCheckPackageId(packageId, &ResourceId, &ResourceIdLength);
}

/*
 * @implemented
 */
LONG
WINAPI
PackageFamilyNameFromFullName(
    _In_ PCWSTR packageFullName,
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName)
{
    BASEP_PACKAGE_NAME Parsed;
    WCHAR Family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];
    LONG Error;

    if (!packageFullName)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(packageFamilyNameLength, packageFamilyName);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        if (!BasepParseFullName(packageFullName, &Parsed))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else
        {
            RtlCopyMemory(Family, Parsed.Name, Parsed.NameLength * sizeof(WCHAR));
            Family[Parsed.NameLength] = L'_';
            RtlCopyMemory(Family + Parsed.NameLength + 1, Parsed.PublisherId, PACKAGE_PUBLISHERID_MAX_LENGTH * sizeof(WCHAR));
            Error = BasepReturnString(packageFamilyNameLength,
                                      packageFamilyName,
                                      Family,
                                      Parsed.NameLength + 1 + PACKAGE_PUBLISHERID_MAX_LENGTH);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
PackageFamilyNameFromId(
    _In_ const PACKAGE_ID *packageId,
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName)
{
    WCHAR Family[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];
    ULONG NameLength;
    LONG Error;

    if (!packageId)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(packageFamilyNameLength, packageFamilyName);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        NameLength = packageId->name ? wcslen(packageId->name) : 0;

        /* The architecture and the resource id do not matter here */
        if (!packageId->name || !packageId->publisherId ||
            !BasepIsPackageName(packageId->name, NameLength) ||
            !BasepIsPublisherId(packageId->publisherId, wcslen(packageId->publisherId)))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else
        {
            RtlCopyMemory(Family, packageId->name, NameLength * sizeof(WCHAR));
            Family[NameLength] = L'_';
            RtlCopyMemory(Family + NameLength + 1, packageId->publisherId, PACKAGE_PUBLISHERID_MAX_LENGTH * sizeof(WCHAR));
            Error = BasepReturnString(packageFamilyNameLength,
                                      packageFamilyName,
                                      Family,
                                      NameLength + 1 + PACKAGE_PUBLISHERID_MAX_LENGTH);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
PackageFullNameFromId(
    _In_ const PACKAGE_ID *packageId,
    _Inout_ UINT32 *packageFullNameLength,
    _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName)
{
    WCHAR FullName[PACKAGE_FULL_NAME_MAX_LENGTH + 1];
    PCWSTR ResourceId, Architecture;
    ULONG ResourceIdLength;
    LONG Error;

    if (!packageId)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(packageFullNameLength, packageFullName);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = BasepCheckPackageId(packageId, &ResourceId, &ResourceIdLength);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        Architecture = BasepArchitectureName(packageId->processorArchitecture);

        RtlStringCchPrintfW(FullName,
                            RTL_NUMBER_OF(FullName),
                            L"%ls_%u.%u.%u.%u_%ls_%ls_%ls",
                            packageId->name,
                            (UINT32)(packageId->version.Version >> 48) & 0xFFFF,
                            (UINT32)(packageId->version.Version >> 32) & 0xFFFF,
                            (UINT32)(packageId->version.Version >> 16) & 0xFFFF,
                            (UINT32)packageId->version.Version & 0xFFFF,
                            Architecture,
                            ResourceId,
                            packageId->publisherId);
        Error = BasepReturnString(packageFullNameLength, packageFullName, FullName, wcslen(FullName));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
PackageIdFromFullName(
    _In_ PCWSTR packageFullName,
    _In_ const UINT32 flags,
    _Inout_ UINT32 *bufferLength,
    _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer)
{
    BASEP_PACKAGE_NAME Parsed;
    PACKAGE_ID *Id;
    PWSTR Strings;
    UINT32 Needed, Capacity = 0;
    LONG Error;

    if (!packageFullName)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(bufferLength, buffer);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        Capacity = *bufferLength;
        if (!BasepParseFullName(packageFullName, &Parsed))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else
        {
            Needed = sizeof(PACKAGE_ID) +
                     (Parsed.NameLength + 1 + Parsed.ResourceIdLength + 1 + PACKAGE_PUBLISHERID_MAX_LENGTH + 1) * sizeof(WCHAR);
            *bufferLength = Needed;
            if (Capacity < Needed)
            {
                Error = ERROR_INSUFFICIENT_BUFFER;
            }
            else
            {
                Id = (PACKAGE_ID *)buffer;
                RtlZeroMemory(Id, sizeof(*Id));
                Id->processorArchitecture = Parsed.Architecture;
                Id->version.Version = Parsed.Version;

                /* The strings follow the structure: name, resource id, publisher id */
                Strings = (PWSTR)(buffer + sizeof(PACKAGE_ID));
                Id->name = Strings;
                RtlCopyMemory(Strings, Parsed.Name, Parsed.NameLength * sizeof(WCHAR));
                Strings[Parsed.NameLength] = UNICODE_NULL;
                Strings += Parsed.NameLength + 1;

                Id->resourceId = Strings;
                RtlCopyMemory(Strings, Parsed.ResourceId, Parsed.ResourceIdLength * sizeof(WCHAR));
                Strings[Parsed.ResourceIdLength] = UNICODE_NULL;
                Strings += Parsed.ResourceIdLength + 1;

                Id->publisherId = Strings;
                RtlCopyMemory(Strings, Parsed.PublisherId, PACKAGE_PUBLISHERID_MAX_LENGTH * sizeof(WCHAR));
                Strings[PACKAGE_PUBLISHERID_MAX_LENGTH] = UNICODE_NULL;
            }
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
PackageNameAndPublisherIdFromFamilyName(
    _In_ PCWSTR packageFamilyName,
    _Inout_ UINT32 *packageNameLength,
    _Out_writes_opt_(*packageNameLength) PWSTR packageName,
    _Inout_ UINT32 *packagePublisherIdLength,
    _Out_writes_opt_(*packagePublisherIdLength) PWSTR packagePublisherId)
{
    ULONG NameLength;
    PCWSTR PublisherId;
    LONG Error;

    if (!packageFamilyName)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(packageNameLength, packageName);
    if (Error == ERROR_SUCCESS)
        Error = BasepCheckBuffer(packagePublisherIdLength, packagePublisherId);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        if (!BasepParseFamilyName(packageFamilyName, &NameLength, &PublisherId))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else if (*packageNameLength < NameLength + 1 || *packagePublisherIdLength < PACKAGE_PUBLISHERID_MAX_LENGTH + 1)
        {
            /* Both lengths are reported, whichever one is too small */
            *packageNameLength = NameLength + 1;
            *packagePublisherIdLength = PACKAGE_PUBLISHERID_MAX_LENGTH + 1;
            Error = ERROR_INSUFFICIENT_BUFFER;
        }
        else
        {
            *packageNameLength = NameLength + 1;
            *packagePublisherIdLength = PACKAGE_PUBLISHERID_MAX_LENGTH + 1;
            RtlCopyMemory(packageName, packageFamilyName, NameLength * sizeof(WCHAR));
            packageName[NameLength] = UNICODE_NULL;
            RtlCopyMemory(packagePublisherId, PublisherId, PACKAGE_PUBLISHERID_MAX_LENGTH * sizeof(WCHAR));
            packagePublisherId[PACKAGE_PUBLISHERID_MAX_LENGTH] = UNICODE_NULL;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
ParseApplicationUserModelId(
    _In_ PCWSTR applicationUserModelId,
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName,
    _Inout_ UINT32 *packageRelativeApplicationIdLength,
    _Out_writes_opt_(*packageRelativeApplicationIdLength) PWSTR packageRelativeApplicationId)
{
    ULONG FamilyLength, RelativeIdLength;
    PCWSTR RelativeId;
    LONG Error;

    if (!applicationUserModelId)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(packageFamilyNameLength, packageFamilyName);
    if (Error == ERROR_SUCCESS)
        Error = BasepCheckBuffer(packageRelativeApplicationIdLength, packageRelativeApplicationId);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        if (!BasepParseUserModelId(applicationUserModelId, &FamilyLength, &RelativeId, &RelativeIdLength))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else if (*packageFamilyNameLength < FamilyLength + 1 || *packageRelativeApplicationIdLength < RelativeIdLength + 1)
        {
            *packageFamilyNameLength = FamilyLength + 1;
            *packageRelativeApplicationIdLength = RelativeIdLength + 1;
            Error = ERROR_INSUFFICIENT_BUFFER;
        }
        else
        {
            *packageFamilyNameLength = FamilyLength + 1;
            *packageRelativeApplicationIdLength = RelativeIdLength + 1;
            RtlCopyMemory(packageFamilyName, applicationUserModelId, FamilyLength * sizeof(WCHAR));
            packageFamilyName[FamilyLength] = UNICODE_NULL;
            RtlCopyMemory(packageRelativeApplicationId, RelativeId, RelativeIdLength * sizeof(WCHAR));
            packageRelativeApplicationId[RelativeIdLength] = UNICODE_NULL;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
FormatApplicationUserModelId(
    _In_ PCWSTR packageFamilyName,
    _In_ PCWSTR packageRelativeApplicationId,
    _Inout_ UINT32 *applicationUserModelIdLength,
    _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId)
{
    WCHAR UserModelId[APPLICATION_USER_MODEL_ID_MAX_LENGTH + 1];
    ULONG NameLength, RelativeIdLength;
    PCWSTR PublisherId;
    LONG Error;

    if (!packageFamilyName || !packageRelativeApplicationId)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(applicationUserModelIdLength, applicationUserModelId);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        RelativeIdLength = wcslen(packageRelativeApplicationId);
        if (!BasepParseFamilyName(packageFamilyName, &NameLength, &PublisherId) ||
            !BasepIsRelativeApplicationId(packageRelativeApplicationId, RelativeIdLength))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else
        {
            RtlStringCchPrintfW(UserModelId, RTL_NUMBER_OF(UserModelId), L"%ls!%ls", packageFamilyName, packageRelativeApplicationId);
            Error = BasepReturnString(applicationUserModelIdLength, applicationUserModelId, UserModelId, wcslen(UserModelId));
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/* PUBLIC FUNCTIONS: THE PACKAGES ON THE SYSTEM, WHICH ARE NONE ***************/

/*
 * @implemented
 */
LONG
WINAPI
GetPackagePathByFullName(
    _In_ PCWSTR packageFullName,
    _Inout_ UINT32 *pathLength,
    _Out_writes_opt_(*pathLength) PWSTR path)
{
    BASEP_PACKAGE_NAME Parsed;
    LONG Error;

    if (!packageFullName)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(pathLength, path);
    if (Error != ERROR_SUCCESS)
        return Error;

    _SEH2_TRY
    {
        Error = BasepParseFullName(packageFullName, &Parsed) ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackagePath(
    _In_ const PACKAGE_ID *packageId,
    _Reserved_ const UINT32 reserved,
    _Inout_ UINT32 *pathLength,
    _Out_writes_opt_(*pathLength) PWSTR path)
{
    PCWSTR ResourceId;
    ULONG ResourceIdLength;
    LONG Error;

    if (!packageId)
        return ERROR_INVALID_PARAMETER;

    Error = BasepCheckBuffer(pathLength, path);
    if (Error != ERROR_SUCCESS)
        return Error;

    Error = BasepCheckPackageId(packageId, &ResourceId, &ResourceIdLength);
    return Error == ERROR_SUCCESS ? ERROR_NOT_FOUND : Error;
}

/*
 * @implemented
 */
LONG
WINAPI
OpenPackageInfoByFullName(
    _In_ PCWSTR packageFullName,
    _Reserved_ const UINT32 reserved,
    _Out_ PACKAGE_INFO_REFERENCE *packageInfoReference)
{
    BASEP_PACKAGE_NAME Parsed;
    LONG Error;

    if (!packageFullName || !packageInfoReference)
        return ERROR_INVALID_PARAMETER;

    _SEH2_TRY
    {
        Error = BasepParseFullName(packageFullName, &Parsed) ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 *
 * No reference is ever handed out, so none can be closed (a reference that was not handed out crashes Windows).
 */
LONG
WINAPI
ClosePackageInfo(
    _In_ PACKAGE_INFO_REFERENCE packageInfoReference)
{
    return ERROR_INVALID_PARAMETER;
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackageInfo(
    _In_ PACKAGE_INFO_REFERENCE packageInfoReference,
    _In_ const UINT32 flags,
    _Inout_ UINT32 *bufferLength,
    _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer,
    _Out_opt_ UINT32 *count)
{
    return ERROR_INVALID_PARAMETER;
}

/* Shared by the two family functions: the parameters, then the family; there are no packages to list */
static
LONG
BasepListPackages(
    _In_ PCWSTR PackageFamilyName,
    _Inout_ UINT32 *Count,
    _In_opt_ PWSTR *PackageFullNames,
    _Inout_ UINT32 *BufferLength,
    _In_opt_ PWSTR Buffer)
{
    PCWSTR PublisherId;
    ULONG NameLength;
    LONG Error = ERROR_SUCCESS;

    if (!PackageFamilyName || !Count || !BufferLength)
        return ERROR_INVALID_PARAMETER;

    _SEH2_TRY
    {
        if ((*Count != 0 && !PackageFullNames) || (*BufferLength != 0 && !Buffer))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else if (PackageFamilyName[0] == UNICODE_NULL)
        {
            Error = ERROR_FILE_NOT_FOUND;
        }
        else if (!BasepParseFamilyName(PackageFamilyName, &NameLength, &PublisherId))
        {
            Error = ERROR_INVALID_PARAMETER;
        }
        else
        {
            /* No package of any family is installed */
            *Count = 0;
            *BufferLength = 0;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
GetPackagesByPackageFamily(
    _In_ PCWSTR packageFamilyName,
    _Inout_ UINT32 *count,
    _Out_writes_opt_(*count) PWSTR *packageFullNames,
    _Inout_ UINT32 *bufferLength,
    _Out_writes_opt_(*bufferLength) WCHAR *buffer)
{
    return BasepListPackages(packageFamilyName, count, packageFullNames, bufferLength, buffer);
}

/*
 * @implemented
 */
LONG
WINAPI
FindPackagesByPackageFamily(
    _In_ PCWSTR packageFamilyName,
    _In_ UINT32 packageFilters,
    _Inout_ UINT32 *count,
    _Out_writes_opt_(*count) PWSTR *packageFullNames,
    _Inout_ UINT32 *bufferLength,
    _Out_writes_opt_(*bufferLength) WCHAR *buffer,
    _Out_writes_opt_(*count) UINT32 *packageProperties)
{
    /* At least one kind of package has to be asked for */
    if (packageFilters == 0)
        return ERROR_INVALID_PARAMETER;

    return BasepListPackages(packageFamilyName, count, packageFullNames, bufferLength, buffer);
}

/* PUBLIC FUNCTIONS: APPLICATION POLICIES *************************************/

/*
 * The policies of an application that is not a package: Windows' answers for a classic desktop program, the ones
 * the C runtime and the CLR ask for (ucrtbase reads the first four through GetProcAddress). They are those of
 * Wine's implementation of these functions; the token is not examined, because there is no package or
 * AppContainer token here that could change a policy. Not measured on Windows 10: the ClrCompat, CreateFileAccess
 * and LifecycleManagement values are the documented ones for a desktop process.
 */
static
LONG
BasepSetPolicy(
    _Out_opt_ PULONG Policy,
    _In_ ULONG Value)
{
    LONG Error = ERROR_SUCCESS;

    if (!Policy)
        return ERROR_SUCCESS;

    _SEH2_TRY
    {
        *Policy = Value;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Error = ERROR_NOACCESS;
    }
    _SEH2_END;

    return Error;
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetClrCompat(
    _In_ HANDLE processToken,
    _Out_ AppPolicyClrCompat *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyClrCompat_ClassicDesktop);
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetCreateFileAccess(
    _In_ HANDLE processToken,
    _Out_ AppPolicyCreateFileAccess *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyCreateFileAccess_Full);
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetLifecycleManagement(
    _In_ HANDLE processToken,
    _Out_ AppPolicyLifecycleManagement *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyLifecycleManagement_Unmanaged);
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetMediaFoundationCodecLoading(
    _In_ HANDLE processToken,
    _Out_ AppPolicyMediaFoundationCodecLoading *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyMediaFoundationCodecLoading_All);
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetProcessTerminationMethod(
    _In_ HANDLE processToken,
    _Out_ AppPolicyProcessTerminationMethod *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyProcessTerminationMethod_ExitProcess);
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetShowDeveloperDiagnostic(
    _In_ HANDLE processToken,
    _Out_ AppPolicyShowDeveloperDiagnostic *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyShowDeveloperDiagnostic_ShowUI);
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetThreadInitializationType(
    _In_ HANDLE processToken,
    _Out_ AppPolicyThreadInitializationType *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyThreadInitializationType_None);
}

/*
 * @implemented
 */
LONG
WINAPI
AppPolicyGetWindowingModel(
    _In_ HANDLE processToken,
    _Out_ AppPolicyWindowingModel *policy)
{
    return BasepSetPolicy((PULONG)policy, AppPolicyWindowingModel_ClassicDesktop);
}

/*
 * @implemented
 *
 * Only a package can be loaded from: a process without a package gets APPMODEL_ERROR_NO_PACKAGE, as Windows
 * answers it. The reserved argument has to be 0 (checked first).
 */
HMODULE
WINAPI
LoadPackagedLibrary(
    _In_ PCWSTR lpwLibFileName,
    _Reserved_ DWORD Reserved)
{
    if (Reserved != 0 || !lpwLibFileName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    SetLastError(APPMODEL_ERROR_NO_PACKAGE);
    return NULL;
}

/* EOF */
