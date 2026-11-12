/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/version.c
 * PURPOSE:         Version functions
 * PROGRAMMER:      Ariadne (ariadne@xs4all.nl)
                    Ged Murphy (gedmurphy@reactos.org)
 */

#include <k32.h>
#include <compat_undoc.h>
#include <verlie.h>
#include <verifyver.h>

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ******************************************************************/

/*
 * The version Windows 10 tells a program (switch "UnmanifestedVersionLie", see verlie.h).
 * Measured on Windows 10 22H2: the highest supportedOS GUID in the program's own manifest decides.
 * Windows 10 -> the real version; Windows 8.1 -> 6.3.9600; anything else, no GUID, or no manifest -> 6.2.9200.
 * Without any supportedOS element the PE header OS version counts (>= 10.0 real, 6.3 .. 9.x -> 6.3); a supportedOS wins over it.
 */
#define BASEP_VERLIE_OFF    0   /* switch off: the old behaviour, untouched */
#define BASEP_VERLIE_REAL   1   /* switch on, the program targets Windows 10: the real version */
#define BASEP_VERLIE_WIN81  2   /* switch on: 6.3.9600 */
#define BASEP_VERLIE_WIN8   3   /* switch on: 6.2.9200 */

static volatile LONG g_VerLieMode = -1;

static LONG
BaseGetVersionLieMode(VOID)
{
    static const GUID GuidWin81 = {0x1f676c76, 0x80e1, 0x4239, {0x95, 0xbb, 0x83, 0xd0, 0xf6, 0xd0, 0xda, 0x78}};
    static const GUID GuidWin10 = {0x8e0f7a12, 0xbfb3, 0x4fe8, {0xb9, 0xa5, 0x48, 0xfd, 0x50, 0xa1, 0x5a, 0x9a}};
    LONG Mode = g_VerLieMode;
    ACTIVATION_CONTEXT_COMPATIBILITY_INFORMATION *Info;
    SIZE_T Required = 0;
    BOOLEAN HaveOsElement = FALSE;
    PIMAGE_NT_HEADERS NtHeaders;
    PPEB Peb = NtCurrentPeb();
    ULONG i;

    if (Mode >= 0)
        return Mode;

    if (!RosVersionLieEnabled())
    {
        g_VerLieMode = BASEP_VERLIE_OFF;
        return BASEP_VERLIE_OFF;
    }

    /* Nothing found -> Windows 8 */
    Mode = BASEP_VERLIE_WIN8;

    /* A NULL handle selects the process (executable) activation context, not the active one */
    if (RtlQueryInformationActivationContext(RTL_QUERY_ACTIVATION_CONTEXT_FLAG_NO_ADDREF, NULL, NULL,
                                             CompatibilityInformationInActivationContext,
                                             NULL, 0, &Required) == STATUS_BUFFER_TOO_SMALL && Required)
    {
        Info = RtlAllocateHeap(RtlGetProcessHeap(), 0, Required);
        if (Info)
        {
            if (NT_SUCCESS(RtlQueryInformationActivationContext(RTL_QUERY_ACTIVATION_CONTEXT_FLAG_NO_ADDREF, NULL, NULL,
                                                                CompatibilityInformationInActivationContext,
                                                                Info, Required, &Required)))
            {
                for (i = 0; i < Info->ElementCount; ++i)
                {
                    if (Info->Elements[i].Type != ACTCTX_COMPATIBILITY_ELEMENT_TYPE_OS)
                        continue;

                    HaveOsElement = TRUE;
                    if (RtlCompareMemory(&Info->Elements[i].Id, &GuidWin10, sizeof(GUID)) == sizeof(GUID))
                        Mode = BASEP_VERLIE_REAL;
                    else if (Mode != BASEP_VERLIE_REAL &&
                             RtlCompareMemory(&Info->Elements[i].Id, &GuidWin81, sizeof(GUID)) == sizeof(GUID))
                        Mode = BASEP_VERLIE_WIN81;
                }
            }
            RtlFreeHeap(RtlGetProcessHeap(), 0, Info);
        }
    }

    /* A program whose manifest names no supportedOS (or that has none): the OS version in its PE header counts
       (measured on Windows 10: also with a manifest that has no compatibility section, or an empty one) */
    if (!HaveOsElement &&
        (NtHeaders = RtlImageNtHeader(Peb->ImageBaseAddress)) != NULL)
    {
        if (NtHeaders->OptionalHeader.MajorOperatingSystemVersion >= 10)
            Mode = BASEP_VERLIE_REAL;
        else if (NtHeaders->OptionalHeader.MajorOperatingSystemVersion > 6 ||
                 (NtHeaders->OptionalHeader.MajorOperatingSystemVersion == 6 &&
                  NtHeaders->OptionalHeader.MinorOperatingSystemVersion >= 3))
            Mode = BASEP_VERLIE_WIN81;
    }

    g_VerLieMode = Mode;
    return Mode;
}

/* Replaces the version numbers of what RtlGetVersion returned when the program is told a lower version */
static VOID
BaseApplyVersionLie(LONG Mode, PULONG Major, PULONG Minor, PULONG Build)
{
    if (Mode == BASEP_VERLIE_WIN81)
    {
        *Major = 6;
        *Minor = 3;
        *Build = 9600;
    }
    else if (Mode == BASEP_VERLIE_WIN8)
    {
        *Major = 6;
        *Minor = 2;
        *Build = 9200;
    }
}

/*
 * @implemented
 */
DWORD
WINAPI
GetVersion(VOID)
{
    PPEB Peb = NtCurrentPeb();
    ULONG MajorVersion = Peb->OSMajorVersion;
    ULONG MinorVersion = Peb->OSMinorVersion;
    ULONG BuildNumber = Peb->OSBuildNumber;
    UINT EffectiveVersion;
    LONG LieMode = BaseGetVersionLieMode();

    if (LieMode != BASEP_VERLIE_OFF)
    {
        /* The version Windows 10 tells this program; the manifest raise below is not used */
        BaseApplyVersionLie(LieMode, &MajorVersion, &MinorVersion, &BuildNumber);
        return (DWORD)( ((Peb->OSPlatformId ^ 2) << 30) |
                         (BuildNumber            << 16) |
                         (MinorVersion           << 8 ) |
                          MajorVersion );
    }

    /* A process that declares a Windows version in its application manifest
     * must observe that version, as on Windows. ReactOS detects the manifest
     * compatibility GUID (LdrpInitializeProcessCompat) and records it, but the
     * version APIs otherwise report the raw NT version. Honor the higher of the
     * two so manifested apps take the code paths they target (e.g. Crashpad only
     * creates its IPC pipe handle inheritable when GetVersion() reports Vista+). */
    EffectiveVersion = RosGetProcessEffectiveVersion();
    if (EffectiveVersion > ((MajorVersion << 8) | MinorVersion))
    {
        MajorVersion = EffectiveVersion >> 8;
        MinorVersion = EffectiveVersion & 0xFF;
    }

    return (DWORD)( ((Peb->OSPlatformId ^ 2) << 30) |
                     (Peb->OSBuildNumber     << 16) |
                     (MinorVersion           << 8 ) |
                      MajorVersion );
}

/*
 * @implemented
 */
BOOL
WINAPI
GetVersionExW(IN LPOSVERSIONINFOW lpVersionInformation)
{
    NTSTATUS Status;
    LPOSVERSIONINFOEXW lpVersionInformationEx;

    if ((lpVersionInformation->dwOSVersionInfoSize != sizeof(OSVERSIONINFOW)) &&
        (lpVersionInformation->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEXW)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    Status = RtlGetVersion((PRTL_OSVERSIONINFOW)lpVersionInformation);
    if (Status == STATUS_SUCCESS)
    {
        BaseApplyVersionLie(BaseGetVersionLieMode(),
                            &lpVersionInformation->dwMajorVersion,
                            &lpVersionInformation->dwMinorVersion,
                            &lpVersionInformation->dwBuildNumber);
        if (lpVersionInformation->dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXW))
        {
            lpVersionInformationEx = (PVOID)lpVersionInformation;
            lpVersionInformationEx->wReserved = 0;
        }

        return TRUE;
    }

    return FALSE;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetVersionExA(IN LPOSVERSIONINFOA lpVersionInformation)
{
    OSVERSIONINFOEXW VersionInformation;
    LPOSVERSIONINFOEXA lpVersionInformationEx;
    UNICODE_STRING CsdVersionW;
    NTSTATUS Status;
    ANSI_STRING CsdVersionA;

    if ((lpVersionInformation->dwOSVersionInfoSize != sizeof(OSVERSIONINFOA)) &&
        (lpVersionInformation->dwOSVersionInfoSize != sizeof(OSVERSIONINFOEXA)))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    VersionInformation.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    if (!GetVersionExW((LPOSVERSIONINFOW)&VersionInformation)) return FALSE;

    /* Copy back fields that match both supported structures */
    lpVersionInformation->dwMajorVersion = VersionInformation.dwMajorVersion;
    lpVersionInformation->dwMinorVersion = VersionInformation.dwMinorVersion;
    lpVersionInformation->dwBuildNumber = VersionInformation.dwBuildNumber;
    lpVersionInformation->dwPlatformId = VersionInformation.dwPlatformId;

    if (lpVersionInformation->dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXA))
    {
        lpVersionInformationEx = (PVOID)lpVersionInformation;
        lpVersionInformationEx->wServicePackMajor = VersionInformation.wServicePackMajor;
        lpVersionInformationEx->wServicePackMinor = VersionInformation.wServicePackMinor;
        lpVersionInformationEx->wSuiteMask = VersionInformation.wSuiteMask;
        lpVersionInformationEx->wProductType = VersionInformation.wProductType;
        lpVersionInformationEx->wReserved = VersionInformation.wReserved;
    }

    /* Convert the CSD string */
    RtlInitEmptyAnsiString(&CsdVersionA,
                           lpVersionInformation->szCSDVersion,
                           sizeof(lpVersionInformation->szCSDVersion));
    RtlInitUnicodeString(&CsdVersionW, VersionInformation.szCSDVersion);
    Status = RtlUnicodeStringToAnsiString(&CsdVersionA, &CsdVersionW, FALSE);
    return (NT_SUCCESS(Status));
}

/*
 * @implemented
 */
BOOL
WINAPI
VerifyVersionInfoW(IN LPOSVERSIONINFOEXW lpVersionInformation,
                   IN DWORD dwTypeMask,
                   IN DWORDLONG dwlConditionMask)
{
    NTSTATUS Status;
    LONG LieMode = BaseGetVersionLieMode();

    if (LieMode != BASEP_VERLIE_OFF)
    {
        /* Compare against the version this program is told */
        RTL_OSVERSIONINFOEXW Have;

        RtlZeroMemory(&Have, sizeof(Have));
        Have.dwOSVersionInfoSize = sizeof(Have);
        Status = RtlGetVersion((PRTL_OSVERSIONINFOW)&Have);
        if (Status == STATUS_SUCCESS)
        {
            BaseApplyVersionLie(LieMode, &Have.dwMajorVersion, &Have.dwMinorVersion, &Have.dwBuildNumber);
            Status = RtlpVerifyVersionInfo(&Have, (PRTL_OSVERSIONINFOEXW)lpVersionInformation,
                                           dwTypeMask, dwlConditionMask);
        }
    }
    else
    {
        Status = RtlVerifyVersionInfo((PRTL_OSVERSIONINFOEXW)lpVersionInformation,
                                      dwTypeMask,
                                      dwlConditionMask);
    }
    switch (Status)
    {
        case STATUS_INVALID_PARAMETER:
            SetLastError(ERROR_BAD_ARGUMENTS);
            return FALSE;

        case STATUS_REVISION_MISMATCH:
            if (lpVersionInformation)
            {
                DPRINT1("VerifyVersionInfo -- Version mismatch(%d.%d.%d:%d)\n",
                        (dwTypeMask & VER_MAJORVERSION) ? lpVersionInformation->dwMajorVersion : -1,
                        (dwTypeMask & VER_MINORVERSION) ? lpVersionInformation->dwMinorVersion : -1,
                        (dwTypeMask & VER_BUILDNUMBER) ? lpVersionInformation->dwBuildNumber : -1,
                        (dwTypeMask & VER_PLATFORMID) ? lpVersionInformation->dwPlatformId : -1);
            }
            else
            {
                DPRINT1("VerifyVersionInfo -- Version mismatch(NULL)\n");
            }
            SetLastError(ERROR_OLD_WIN_VERSION);
            return FALSE;

        default:
            /* RtlVerifyVersionInfo shouldn't report any other failure code! */
            ASSERT(NT_SUCCESS(Status));
            return TRUE;
    }
}
