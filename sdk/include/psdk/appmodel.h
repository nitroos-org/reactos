/*
 * PROJECT:     ReactOS SDK
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Windows AppModel definitions
 * COPYRIGHT:   Copyright 2024 Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum AppPolicyProcessTerminationMethod
{
    AppPolicyProcessTerminationMethod_ExitProcess = 0,
    AppPolicyProcessTerminationMethod_TerminateProcess = 1,
} AppPolicyProcessTerminationMethod;

typedef enum AppPolicyThreadInitializationType
{
    AppPolicyThreadInitializationType_None = 0,
    AppPolicyThreadInitializationType_InitializeWinRT = 1,
} AppPolicyThreadInitializationType;

typedef enum AppPolicyShowDeveloperDiagnostic
{
    AppPolicyShowDeveloperDiagnostic_None = 0,
    AppPolicyShowDeveloperDiagnostic_ShowUI = 1,
} AppPolicyShowDeveloperDiagnostic;

typedef enum AppPolicyWindowingModel
{
    AppPolicyWindowingModel_None = 0,
    AppPolicyWindowingModel_Universal = 1,
    AppPolicyWindowingModel_ClassicDesktop = 2,
    AppPolicyWindowingModel_ClassicPhone = 3
} AppPolicyWindowingModel;

typedef enum AppPolicyMediaFoundationCodecLoading
{
    AppPolicyMediaFoundationCodecLoading_All = 0,
} AppPolicyMediaFoundationCodecLoading;

typedef enum AppPolicyClrCompat
{
    AppPolicyClrCompat_Others = 0,
    AppPolicyClrCompat_ClassicDesktop = 1,
    AppPolicyClrCompat_Universal = 2,
    AppPolicyClrCompat_PackagedDesktop = 3
} AppPolicyClrCompat;

typedef enum AppPolicyCreateFileAccess
{
    AppPolicyCreateFileAccess_Full = 0,
    AppPolicyCreateFileAccess_Limited = 1
} AppPolicyCreateFileAccess;

typedef enum AppPolicyLifecycleManagement
{
    AppPolicyLifecycleManagement_Unmanaged = 0,
    AppPolicyLifecycleManagement_Managed = 1
} AppPolicyLifecycleManagement;

typedef struct PACKAGE_VERSION
{
    union
    {
        UINT64 Version;
        struct
        {
            USHORT Revision;
            USHORT Build;
            USHORT Minor;
            USHORT Major;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PACKAGE_VERSION;

typedef struct PACKAGE_ID
{
    UINT32 reserved;
    UINT32 processorArchitecture;
    PACKAGE_VERSION version;
    PWSTR name;
    PWSTR publisher;
    PWSTR resourceId;
    PWSTR publisherId;
} PACKAGE_ID;

#define PACKAGE_PROPERTY_FRAMEWORK          0x00000001
#define PACKAGE_PROPERTY_RESOURCE           0x00000002
#define PACKAGE_PROPERTY_BUNDLE             0x00000004
#define PACKAGE_PROPERTY_OPTIONAL           0x00000008

#define PACKAGE_FILTER_HEAD                 0x00000010
#define PACKAGE_FILTER_DIRECT               0x00000020
#define PACKAGE_FILTER_RESOURCE             0x00000040
#define PACKAGE_FILTER_BUNDLE               0x00000080

#define PACKAGE_INFORMATION_BASIC           0x00000000
#define PACKAGE_INFORMATION_FULL            0x00000100

#define PACKAGE_PROPERTY_DEVELOPMENT_MODE   0x00010000
#define PACKAGE_FILTER_OPTIONAL             0x00020000
#define PACKAGE_PROPERTY_IS_IN_RELATED_SET  0x00040000
#define PACKAGE_FILTER_IS_IN_RELATED_SET    PACKAGE_PROPERTY_IS_IN_RELATED_SET
#define PACKAGE_PROPERTY_STATIC             0x00080000
#define PACKAGE_FILTER_STATIC               PACKAGE_PROPERTY_STATIC
#define PACKAGE_PROPERTY_DYNAMIC            0x00100000
#define PACKAGE_FILTER_DYNAMIC              PACKAGE_PROPERTY_DYNAMIC

#define PACKAGE_NAME_MAX_LENGTH             50
#define PACKAGE_PUBLISHERID_MAX_LENGTH      13
#define PACKAGE_RESOURCEID_MAX_LENGTH       30
#define PACKAGE_FAMILY_NAME_MAX_LENGTH      (PACKAGE_NAME_MAX_LENGTH + 1 + PACKAGE_PUBLISHERID_MAX_LENGTH)
#define PACKAGE_FULL_NAME_MAX_LENGTH        127
#define PACKAGE_RELATIVE_APPLICATION_ID_MAX_LENGTH 64
#define APPLICATION_USER_MODEL_ID_MAX_LENGTH 130

typedef struct _PACKAGE_INFO_REFERENCE
{
    void *reserved;
} PACKAGE_INFO_REFERENCE, *PPACKAGE_INFO_REFERENCE;

#include <pshpack4.h>
typedef struct PACKAGE_INFO
{
    UINT32 reserved;
    UINT32 flags;
    PWSTR path;
    PWSTR packageFullName;
    PWSTR packageFamilyName;
    PACKAGE_ID packageId;
} PACKAGE_INFO;
#include <poppack.h>

WINBASEAPI LONG WINAPI GetCurrentPackageFullName(_Inout_ UINT32 *packageFullNameLength, _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName);
WINBASEAPI LONG WINAPI GetCurrentPackageFamilyName(_Inout_ UINT32 *packageFamilyNameLength, _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName);
WINBASEAPI LONG WINAPI GetCurrentPackageId(_Inout_ UINT32 *bufferLength, _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer);
WINBASEAPI LONG WINAPI GetCurrentPackagePath(_Inout_ UINT32 *pathLength, _Out_writes_opt_(*pathLength) PWSTR path);
WINBASEAPI LONG WINAPI GetCurrentPackageInfo(_In_ const UINT32 flags, _Inout_ UINT32 *bufferLength, _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer, _Out_opt_ UINT32 *count);
WINBASEAPI LONG WINAPI GetCurrentApplicationUserModelId(_Inout_ UINT32 *applicationUserModelIdLength, _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId);
WINBASEAPI LONG WINAPI GetPackageFullName(_In_ HANDLE hProcess, _Inout_ UINT32 *packageFullNameLength, _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName);
WINBASEAPI LONG WINAPI GetPackageFamilyName(_In_ HANDLE hProcess, _Inout_ UINT32 *packageFamilyNameLength, _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName);
WINBASEAPI LONG WINAPI GetPackageId(_In_ HANDLE hProcess, _Inout_ UINT32 *bufferLength, _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer);
WINBASEAPI LONG WINAPI GetPackagePath(_In_ const PACKAGE_ID *packageId, _Reserved_ const UINT32 reserved, _Inout_ UINT32 *pathLength, _Out_writes_opt_(*pathLength) PWSTR path);
WINBASEAPI LONG WINAPI GetPackageFullNameFromToken(_In_ HANDLE token, _Inout_ UINT32 *packageFullNameLength, _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName);
WINBASEAPI LONG WINAPI GetPackageFamilyNameFromToken(_In_ HANDLE token, _Inout_ UINT32 *packageFamilyNameLength, _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName);
WINBASEAPI LONG WINAPI GetApplicationUserModelIdFromToken(_In_ HANDLE token, _Inout_ UINT32 *applicationUserModelIdLength, _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId);
WINBASEAPI LONG WINAPI GetPackagePathByFullName(_In_ PCWSTR packageFullName, _Inout_ UINT32 *pathLength, _Out_writes_opt_(*pathLength) PWSTR path);
WINBASEAPI LONG WINAPI GetApplicationUserModelId(_In_ HANDLE hProcess, _Inout_ UINT32 *applicationUserModelIdLength, _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId);
WINBASEAPI LONG WINAPI GetPackagesByPackageFamily(_In_ PCWSTR packageFamilyName, _Inout_ UINT32 *count, _Out_writes_opt_(*count) PWSTR *packageFullNames, _Inout_ UINT32 *bufferLength, _Out_writes_opt_(*bufferLength) WCHAR *buffer);
WINBASEAPI LONG WINAPI FindPackagesByPackageFamily(_In_ PCWSTR packageFamilyName, _In_ UINT32 packageFilters, _Inout_ UINT32 *count, _Out_writes_opt_(*count) PWSTR *packageFullNames, _Inout_ UINT32 *bufferLength, _Out_writes_opt_(*bufferLength) WCHAR *buffer, _Out_writes_opt_(*count) UINT32 *packageProperties);
WINBASEAPI LONG WINAPI PackageFamilyNameFromFullName(_In_ PCWSTR packageFullName, _Inout_ UINT32 *packageFamilyNameLength, _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName);
WINBASEAPI LONG WINAPI PackageFamilyNameFromId(_In_ const PACKAGE_ID *packageId, _Inout_ UINT32 *packageFamilyNameLength, _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName);
WINBASEAPI LONG WINAPI PackageFullNameFromId(_In_ const PACKAGE_ID *packageId, _Inout_ UINT32 *packageFullNameLength, _Out_writes_opt_(*packageFullNameLength) PWSTR packageFullName);
WINBASEAPI LONG WINAPI PackageIdFromFullName(_In_ PCWSTR packageFullName, _In_ const UINT32 flags, _Inout_ UINT32 *bufferLength, _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer);
WINBASEAPI LONG WINAPI PackageNameAndPublisherIdFromFamilyName(_In_ PCWSTR packageFamilyName, _Inout_ UINT32 *packageNameLength, _Out_writes_opt_(*packageNameLength) PWSTR packageName, _Inout_ UINT32 *packagePublisherIdLength, _Out_writes_opt_(*packagePublisherIdLength) PWSTR packagePublisherId);
WINBASEAPI LONG WINAPI OpenPackageInfoByFullName(_In_ PCWSTR packageFullName, _Reserved_ const UINT32 reserved, _Out_ PACKAGE_INFO_REFERENCE *packageInfoReference);
WINBASEAPI LONG WINAPI ClosePackageInfo(_In_ PACKAGE_INFO_REFERENCE packageInfoReference);
WINBASEAPI LONG WINAPI GetPackageInfo(_In_ PACKAGE_INFO_REFERENCE packageInfoReference, _In_ const UINT32 flags, _Inout_ UINT32 *bufferLength, _Out_writes_bytes_opt_(*bufferLength) BYTE *buffer, _Out_opt_ UINT32 *count);
WINBASEAPI LONG WINAPI ParseApplicationUserModelId(_In_ PCWSTR applicationUserModelId, _Inout_ UINT32 *packageFamilyNameLength, _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName, _Inout_ UINT32 *packageRelativeApplicationIdLength, _Out_writes_opt_(*packageRelativeApplicationIdLength) PWSTR packageRelativeApplicationId);
WINBASEAPI LONG WINAPI FormatApplicationUserModelId(_In_ PCWSTR packageFamilyName, _In_ PCWSTR packageRelativeApplicationId, _Inout_ UINT32 *applicationUserModelIdLength, _Out_writes_opt_(*applicationUserModelIdLength) PWSTR applicationUserModelId);
WINBASEAPI LONG WINAPI VerifyPackageFullName(_In_ PCWSTR packageFullName);
WINBASEAPI LONG WINAPI VerifyPackageFamilyName(_In_ PCWSTR packageFamilyName);
WINBASEAPI LONG WINAPI VerifyPackageId(_In_ const PACKAGE_ID *packageId);
WINBASEAPI LONG WINAPI VerifyPackageRelativeApplicationId(_In_ PCWSTR packageRelativeApplicationId);
WINBASEAPI LONG WINAPI VerifyApplicationUserModelId(_In_ PCWSTR applicationUserModelId);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetClrCompat(
    _In_ HANDLE processToken,
    _Out_ AppPolicyClrCompat* policy);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetCreateFileAccess(
    _In_ HANDLE processToken,
    _Out_ AppPolicyCreateFileAccess* policy);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetLifecycleManagement(
    _In_ HANDLE processToken,
    _Out_ AppPolicyLifecycleManagement* policy);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetProcessTerminationMethod(
    _In_ HANDLE processToken,
    _Out_ AppPolicyProcessTerminationMethod* policy);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetThreadInitializationType(
    _In_ HANDLE processToken,
    _Out_ AppPolicyThreadInitializationType* policy);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetShowDeveloperDiagnostic(
    _In_ HANDLE processToken,
    _Out_ AppPolicyShowDeveloperDiagnostic* policy);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetWindowingModel(
    _In_ HANDLE processToken,
    _Out_ AppPolicyWindowingModel* policy);

WINBASEAPI
_Check_return_
_Success_(return == ERROR_SUCCESS)
LONG
WINAPI
AppPolicyGetMediaFoundationCodecLoading(
    _In_ HANDLE processToken,
    _Out_ AppPolicyMediaFoundationCodecLoading* policy);

#ifdef __cplusplus
} // extern "C"
#endif
