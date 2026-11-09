/*
 * PROJECT:         ReactOS Win32 Base API
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            dll/win32/kernel32/client/appcache.c
 * PURPOSE:         Application Compatibility Cache
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

#define NDEBUG
#include <debug.h>

/* GLOBALS ********************************************************************/

ULONG g_ShimsDisabled = -1;
static BOOL g_ApphelpInitialized = FALSE;
static PVOID g_pApphelpCheckRunAppEx;
static PVOID g_pSdbPackAppCompatData;

typedef BOOL (WINAPI *tApphelpCheckRunAppEx)(HANDLE FileHandle, PVOID Unk1, PVOID Unk2, PWCHAR ApplicationName, PVOID Environment, USHORT ExeType, PULONG Reason,
                                             PVOID* SdbQueryAppCompatData, PULONG SdbQueryAppCompatDataSize, PVOID* SxsData, PULONG SxsDataSize,
                                             PULONG FusionFlags, PULONG64 SomeFlag1, PULONG SomeFlag2);
typedef BOOL (WINAPI *tSdbPackAppCompatData)(PVOID hsdb, PVOID pQueryResult, PVOID* ppData, DWORD *dwSize);

#define APPHELP_VALID_RESULT        0x10000
#define APPHELP_RESULT_NOTFOUND     0x20000
#define APPHELP_RESULT_FOUND        0x40000


/* FUNCTIONS ******************************************************************/

BOOLEAN
WINAPI
IsShimInfrastructureDisabled(VOID)
{
    HANDLE KeyHandle;
    NTSTATUS Status;
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    ULONG ResultLength;
    UNICODE_STRING OptionKey = RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\SafeBoot\\Option");
    UNICODE_STRING AppCompatKey = RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\AppCompatibility");
    UNICODE_STRING PolicyKey = RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat");
    UNICODE_STRING OptionValue = RTL_CONSTANT_STRING(L"OptionValue");
    UNICODE_STRING DisableAppCompat = RTL_CONSTANT_STRING(L"DisableAppCompat");
    UNICODE_STRING DisableEngine = RTL_CONSTANT_STRING(L"DisableEngine");
    OBJECT_ATTRIBUTES OptionKeyAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&OptionKey, OBJ_CASE_INSENSITIVE);
    OBJECT_ATTRIBUTES AppCompatKeyAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&AppCompatKey, OBJ_CASE_INSENSITIVE);
    OBJECT_ATTRIBUTES PolicyKeyAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&PolicyKey, OBJ_CASE_INSENSITIVE);

    /*
     * This is a TROOLEAN, -1 means we haven't yet figured it out.
     * 0 means shims are enabled, and 1 means shims are disabled!
     */
    if (g_ShimsDisabled == -1)
    {
        ULONG DisableShims = FALSE;

        /* Open the safe mode key */
        Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &OptionKeyAttributes);
        if (NT_SUCCESS(Status))
        {
            /* Check if this is safemode */
            Status = NtQueryValueKey(KeyHandle,
                                     &OptionValue,
                                     KeyValuePartialInformation,
                                     &KeyInfo,
                                     sizeof(KeyInfo),
                                     &ResultLength);
            NtClose(KeyHandle);
            if ((NT_SUCCESS(Status)) &&
                 (KeyInfo.Type == REG_DWORD) &&
                 (KeyInfo.DataLength == sizeof(ULONG)) &&
                 (KeyInfo.Data[0] != FALSE))
            {
                /* It is, so disable shims! */
                DisableShims = TRUE;
            }
        }

        if (!DisableShims)
        {
            /* Open the app compatibility engine settings key */
            Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &AppCompatKeyAttributes);
            if (NT_SUCCESS(Status))
            {
                /* Check if the app compat engine is turned off */
                Status = NtQueryValueKey(KeyHandle,
                                         &DisableAppCompat,
                                         KeyValuePartialInformation,
                                         &KeyInfo,
                                         sizeof(KeyInfo),
                                         &ResultLength);
                NtClose(KeyHandle);
                if ((NT_SUCCESS(Status)) &&
                    (KeyInfo.Type == REG_DWORD) &&
                    (KeyInfo.DataLength == sizeof(ULONG)) &&
                    (KeyInfo.Data[0] == TRUE))
                {
                    /* It is, so disable shims! */
                    DisableShims = TRUE;
                }
            }
        }
        if (!DisableShims)
        {
            /* Finally, open the app compatibility policy key */
            Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &PolicyKeyAttributes);
            if (NT_SUCCESS(Status))
            {
                /* Check if the system policy disables app compat */
                Status = NtQueryValueKey(KeyHandle,
                                         &DisableEngine,
                                         KeyValuePartialInformation,
                                         &KeyInfo,
                                         sizeof(KeyInfo),
                                         &ResultLength);
                NtClose(KeyHandle);
                if ((NT_SUCCESS(Status)) &&
                    (KeyInfo.Type == REG_DWORD) &&
                    (KeyInfo.DataLength == sizeof(ULONG)) &&
                    (KeyInfo.Data[0] == TRUE))
                {
                    /* It does, so disable shims! */
                    DisableShims = TRUE;
                }
            }
        }
        g_ShimsDisabled = DisableShims;
    }

    /* Return if shims are disabled or not ("Enabled == 1" means disabled!) */
    return g_ShimsDisabled ? TRUE : FALSE;
}

/* apphelp reads the Layers keys of the 64-bit view from a 32-bit process on WoW64; so does the check here */
static
ACCESS_MASK
BasepWow64KeyFlag(VOID)
{
    static LONG Flag = -1;
    LONG Value = Flag;

    if (Value == -1)
    {
        ULONG_PTR Wow64Information = 0;
        NTSTATUS Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information,
                                                    &Wow64Information, sizeof(Wow64Information), NULL);
        Value = (NT_SUCCESS(Status) && Wow64Information) ? KEY_WOW64_64KEY : 0;
        Flag = Value;
    }
    return (ACCESS_MASK)Value;
}

/*
 * Is the registry layer value of this file set in the Layers key under Root?
 * Any failure but "no such key or value" answers TRUE: the cache must not be trusted then.
 */
static
BOOLEAN
BasepLayerValueSet(
    _In_opt_ HANDLE Root,
    _In_ PCUNICODE_STRING KeyPath,
    _In_ PUNICODE_STRING ValueName)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    KEY_VALUE_PARTIAL_INFORMATION Info;
    ULONG Length;
    HANDLE KeyHandle;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, (PUNICODE_STRING)KeyPath, OBJ_CASE_INSENSITIVE, Root, NULL);
    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE | BasepWow64KeyFlag(), &ObjectAttributes);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND) return FALSE;
    if (!NT_SUCCESS(Status)) return TRUE;
    Status = NtQueryValueKey(KeyHandle, ValueName, KeyValuePartialInformation, &Info, sizeof(Info), &Length);
    NtClose(KeyHandle);
    return Status != STATUS_OBJECT_NAME_NOT_FOUND;
}

/*
 * The shim cache answers "the database has nothing for this image", for any caller. Two inputs of that
 * answer are not the image's: the __COMPAT_LAYER of the environment, and the layers set for the file in
 * the Layers keys of the machine and of the user. When either may apply the cache is bypassed (the
 * caller then runs the full check, whose result is not entered into the cache): a layer must be applied
 * whatever another user or launch found earlier.
 * Whether the real Windows bypasses for exactly these inputs: verify on oracle.
 */
BOOL
BasepShimCacheCheckBypass(
    _In_ PCWSTR ApplicationName,
    _In_ HANDLE FileHandle,
    _In_opt_ PCWSTR Environment,
    _In_ BOOL bUnknown,
    _Out_opt_ PULONG pdwReason)
{
    static const UNICODE_STRING EnvName = RTL_CONSTANT_STRING(L"__COMPAT_LAYER");
    static const UNICODE_STRING MachineKey = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers");
    static const UNICODE_STRING UserKey = RTL_CONSTANT_STRING(
        L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers");
    UNICODE_STRING Value, Name;
    WCHAR Buffer[1], LongName[MAX_PATH], DosName[MAX_PATH];
    DWORD Length;
    NTSTATUS Status;
    HANDLE UserRoot;
    BOOLEAN Set;
    PCWSTR p;

    UNREFERENCED_PARAMETER(FileHandle);
    UNREFERENCED_PARAMETER(bUnknown);
    UNREFERENCED_PARAMETER(pdwReason);

    RtlInitEmptyUnicodeString(&Value, Buffer, 0);
    Status = RtlQueryEnvironmentVariable_U((PWSTR)Environment, (PUNICODE_STRING)&EnvName, &Value);
    if (Status != STATUS_VARIABLE_NOT_FOUND) return TRUE;

    /*
     * CreateProcess names the image by an NT path (\??\C:\dir\image.exe); the value of a layer is named by
     * the long DOS path. A path of another form, or one with a short (8.3) component that cannot be resolved,
     * is not looked up: the cache is bypassed.
     */
    p = ApplicationName;
    if (!_wcsnicmp(p, L"\\??\\UNC\\", 8))
    {
        DosName[0] = L'\\';
        if (wcslen(p + 7) >= RTL_NUMBER_OF(DosName) - 1) return TRUE;
        wcscpy(DosName + 1, p + 7);
        p = DosName;
    }
    else
    {
        if (!_wcsnicmp(p, L"\\??\\", 4)) p += 4;
        if (!((p[0] >= L'A' && p[0] <= L'Z') || (p[0] >= L'a' && p[0] <= L'z')) || p[1] != L':') return TRUE;
    }
    RtlInitUnicodeString(&Name, p);
    for (; *p; ++p)
    {
        if (*p == L'~')
        {
            Length = GetLongPathNameW(Name.Buffer, LongName, RTL_NUMBER_OF(LongName));
            if (!Length || Length >= RTL_NUMBER_OF(LongName)) return TRUE;
            RtlInitUnicodeString(&Name, LongName);
            break;
        }
    }

    if (BasepLayerValueSet(NULL, &MachineKey, &Name)) return TRUE;

    Status = RtlOpenCurrentUser(KEY_QUERY_VALUE, &UserRoot);
    if (!NT_SUCCESS(Status)) return TRUE;
    Set = BasepLayerValueSet(UserRoot, &UserKey, &Name);
    NtClose(UserRoot);
    return Set;
}

/*
 * @implemented
 */
BOOL
BasepShimCacheSearch(
    _In_ PCWSTR ApplicationName,
    _In_ HANDLE FileHandle)
{
    APPHELP_CACHE_SERVICE_LOOKUP Lookup;
    RtlInitUnicodeString(&Lookup.ImageName, ApplicationName);
    Lookup.ImageHandle = FileHandle;
    return NT_SUCCESS(NtApphelpCacheControl(ApphelpCacheServiceLookup, &Lookup));
}

/*
 * Is the image on the exclusion list of the cache? Windows keeps one; none is known here, nothing is excluded.
 */
BOOL
BasepCheckCacheExcludeList(
    _In_ PCWSTR ApplicationName)
{
    return FALSE;
}

/*
 * Is the image excluded by a custom list? Same as above.
 */
BOOL
BasepCheckCacheExcludeCustom(
    _In_ PCWSTR ApplicationName)
{
    return FALSE;
}

/*
 * @implemented
 */
VOID
BasepShimCacheRemoveEntry(
    _In_ PCWSTR ApplicationName)
{
    APPHELP_CACHE_SERVICE_LOOKUP Lookup;
    RtlInitUnicodeString(&Lookup.ImageName, ApplicationName);
    Lookup.ImageHandle = INVALID_HANDLE_VALUE;
    NtApphelpCacheControl(ApphelpCacheServiceRemove, &Lookup);
}

/*
 * @implemented
 */
BOOL
BasepShimCacheLookup(
    _In_ PCWSTR ApplicationName,
    _In_ HANDLE FileHandle)
{
    if (!BasepShimCacheSearch(ApplicationName, FileHandle))
        return FALSE;

    /* A hit on an excluded image is not trusted: drop the entry and check */
    if (BasepCheckCacheExcludeList(ApplicationName) ||
        BasepCheckCacheExcludeCustom(ApplicationName))
    {
        BasepShimCacheRemoveEntry(ApplicationName);
        return FALSE;
    }

    return TRUE;
}

/*
 * Enter an image the shim database has nothing for into the kernel cache. The kernel accepts that from
 * SeTcbPrivilege only, so the base server does it for us (BaseSrvUpdateAppcompatCache); it takes the file
 * time and size from our handle. Failing is harmless: the image is checked again next time.
 */
static
VOID
BasepShimCacheUpdate(
    _In_ PCWSTR ApplicationName,
    _In_ HANDLE FileHandle)
{
    BASE_API_MESSAGE ApiMessage;
    PBASE_APPCOMPAT_CACHE_UPDATE Request = &ApiMessage.Data.AppcompatCacheUpdate;
    PCSR_CAPTURE_BUFFER CaptureBuffer;
    SIZE_T Length = wcslen(ApplicationName) * sizeof(WCHAR);

    if (!Length || Length > 0x7FFE) return;
    CaptureBuffer = CsrAllocateCaptureBuffer(1, (ULONG)Length);
    if (!CaptureBuffer) return;
    CsrCaptureMessageBuffer(CaptureBuffer, (PVOID)ApplicationName, (ULONG)Length, (PVOID*)&Request->ImageName);
    Request->ImageNameLength = (ULONG)Length;
    Request->ImageHandle = FileHandle;
    CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage,
                        CaptureBuffer,
                        CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepUpdateAppcompatCache),
                        sizeof(*Request));
    CsrFreeCaptureBuffer(CaptureBuffer);
}

/*
 * @implemented
 */
BOOL
WINAPI
BaseCheckAppcompatCache(
    _In_ PCWSTR ApplicationName,
    _In_ HANDLE FileHandle,
    _In_opt_ PCWSTR Environment,
    _Out_opt_ PULONG pdwReason)
{
    BOOL ret = FALSE;
    ULONG dwReason;

    DPRINT("(%S, %p, %S, %p)\n", ApplicationName, FileHandle, Environment, pdwReason);

    dwReason = 0;
    if (BasepShimCacheCheckBypass(ApplicationName, FileHandle, Environment, TRUE, &dwReason))
    {
        dwReason |= 2;
    }
    else
    {
        ret = BasepShimCacheLookup(ApplicationName, FileHandle);
        if (!ret)
            dwReason |= 1;
    }

    if (pdwReason)
        *pdwReason = dwReason;

    return ret;
}

static
VOID
BaseInitApphelp(VOID)
{
    WCHAR Buffer[MAX_PATH*2];
    UNICODE_STRING DllPath = {0};
    PVOID ApphelpAddress;
    PVOID pApphelpCheckRunAppEx = NULL, pSdbPackAppCompatData = NULL;

    RtlInitEmptyUnicodeString(&DllPath, Buffer, sizeof(Buffer));
    RtlCopyUnicodeString(&DllPath, &BaseWindowsDirectory);
    RtlAppendUnicodeToString(&DllPath, L"\\system32\\apphelp.dll");

    if (NT_SUCCESS(LdrLoadDll(NULL, NULL, &DllPath, &ApphelpAddress)))
    {
        ANSI_STRING ProcName;

        RtlInitAnsiString(&ProcName, "ApphelpCheckRunAppEx");
        if (!NT_SUCCESS(LdrGetProcedureAddress(ApphelpAddress, &ProcName, 0, &pApphelpCheckRunAppEx)))
            pApphelpCheckRunAppEx = NULL;

        RtlInitAnsiString(&ProcName, "SdbPackAppCompatData");
        if (!NT_SUCCESS(LdrGetProcedureAddress(ApphelpAddress, &ProcName, 0, &pSdbPackAppCompatData)))
            pSdbPackAppCompatData = NULL;
    }

    if (InterlockedCompareExchangePointer(&g_pApphelpCheckRunAppEx, RtlEncodeSystemPointer(pApphelpCheckRunAppEx), NULL) == NULL)
    {
        g_pSdbPackAppCompatData = RtlEncodeSystemPointer(pSdbPackAppCompatData);
    }
}

/*
 *
 */
BOOL
WINAPI
BaseCheckRunApp(IN HANDLE FileHandle,
                 IN PWCHAR ApplicationName,
                 IN PWCHAR Environment,
                 IN USHORT ExeType,
                 IN PULONG pReason,
                 IN PVOID* SdbQueryAppCompatData,
                 IN PULONG SdbQueryAppCompatDataSize,
                 IN PVOID* SxsData,
                 IN PULONG SxsDataSize,
                 OUT PULONG FusionFlags)
{
    ULONG Reason = 0;
    ULONG64 Flags1 = 0;
    ULONG Flags2 = 0;
    BOOL Continue, NeedCleanup = FALSE;
    tApphelpCheckRunAppEx pApphelpCheckRunAppEx;
    tSdbPackAppCompatData pSdbPackAppCompatData;
    PVOID QueryResult = NULL;
    ULONG QueryResultSize = 0;

    if (!g_ApphelpInitialized)
    {
        BaseInitApphelp();
        g_ApphelpInitialized = TRUE;
    }

    pApphelpCheckRunAppEx = RtlDecodeSystemPointer(g_pApphelpCheckRunAppEx);
    pSdbPackAppCompatData = RtlDecodeSystemPointer(g_pSdbPackAppCompatData);

    if (!pApphelpCheckRunAppEx || !pSdbPackAppCompatData)
        return TRUE;

    if (pReason)
        Reason = *pReason;

    Continue = pApphelpCheckRunAppEx(FileHandle, NULL, NULL, ApplicationName, Environment, ExeType, &Reason,
        &QueryResult, &QueryResultSize, SxsData, SxsDataSize, FusionFlags, &Flags1, &Flags2);

    if (pReason)
        *pReason = Reason;

    if (Continue)
    {
        if ((Reason & (APPHELP_VALID_RESULT|APPHELP_RESULT_FOUND)) == (APPHELP_VALID_RESULT|APPHELP_RESULT_FOUND))
        {
            if (!pSdbPackAppCompatData(NULL, QueryResult, SdbQueryAppCompatData, SdbQueryAppCompatDataSize))
            {
                DPRINT1("SdbPackAppCompatData returned a failure!\n");
                NeedCleanup = TRUE;
            }
        }
        else
        {
            NeedCleanup = TRUE;
        }
    }

    if (QueryResult)
        RtlFreeHeap(RtlGetProcessHeap(), 0, QueryResult);

    if (NeedCleanup)
    {
        BasepFreeAppCompatData(*SdbQueryAppCompatData, *SxsData);
        *SdbQueryAppCompatData = NULL;
        if (SdbQueryAppCompatDataSize)
            *SdbQueryAppCompatDataSize = 0;
        *SxsData = NULL;
        if (SxsDataSize)
            *SxsDataSize = 0;
    }

    return Continue;
}

/*
 * @implemented
 */
NTSTATUS
WINAPI
BasepCheckBadapp(IN HANDLE FileHandle,
                 IN PWCHAR ApplicationName,
                 IN PWCHAR Environment,
                 IN USHORT ExeType,
                 IN PVOID* SdbQueryAppCompatData,
                 IN PULONG SdbQueryAppCompatDataSize,
                 IN PVOID* SxsData,
                 IN PULONG SxsDataSize,
                 OUT PULONG FusionFlags)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Reason = 0;

    /* Is shimming enabled by group policy? */
    if (IsShimInfrastructureDisabled())
    {
        /* Nothing to worry about */
        Status = STATUS_SUCCESS;
    }
    else
    {
        /* It is, check if we know about this app */
        if (!BaseCheckAppcompatCache(ApplicationName,
                                     FileHandle,
                                     Environment,
                                     &Reason))
        {
            /* Bit 2: the cache was bypassed. That is not for apphelp (it would not return its result), but
             * it means the result must not be entered into the cache either. */
            BOOL Bypassed = (Reason & 2) != 0;
            Reason &= ~2;
            if (!BaseCheckRunApp(FileHandle, ApplicationName, Environment, ExeType, &Reason,
                                SdbQueryAppCompatData, SdbQueryAppCompatDataSize, SxsData, SxsDataSize, FusionFlags))
            {
                Status = STATUS_ACCESS_DENIED;
            }
            else if (!Bypassed &&
                     (Reason & (APPHELP_VALID_RESULT | APPHELP_RESULT_FOUND | APPHELP_RESULT_NOTFOUND)) ==
                     (APPHELP_VALID_RESULT | APPHELP_RESULT_NOTFOUND))
            {
                /* The database has no entry, no layer and no message for it: remember that */
                BasepShimCacheUpdate(ApplicationName, FileHandle);
            }
        }
    }

    /* Return caller the status */
    return Status;
}

/*
 * @implemented
 */
BOOL
WINAPI
BaseDumpAppcompatCache(VOID)
{
    NTSTATUS Status;

    Status = NtApphelpCacheControl(ApphelpCacheServiceDump, NULL);
    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
BOOL
WINAPI
BaseFlushAppcompatCache(VOID)
{
    NTSTATUS Status;

    Status = NtApphelpCacheControl(ApphelpCacheServiceFlush, NULL);
    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
VOID
WINAPI
BasepFreeAppCompatData(IN PVOID AppCompatData,
                       IN PVOID AppCompatSxsData)
{
    /* Free the input pointers if present */
    if (AppCompatData) RtlFreeHeap(RtlGetProcessHeap(), 0, AppCompatData);
    if (AppCompatSxsData) RtlFreeHeap(RtlGetProcessHeap(), 0, AppCompatSxsData);
}

/*
 * @unimplemented
 */
VOID
WINAPI
BaseUpdateAppcompatCache(ULONG Unknown1,
                         ULONG Unknown2,
                         ULONG Unknown3)
{
    STUB;
}

/*
 * @unimplemented
 */
NTSTATUS
WINAPI
BaseCleanupAppcompatCache(VOID)
{
    STUB;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
NTSTATUS
WINAPI
BaseCleanupAppcompatCacheSupport(PVOID pUnknown)
{
    STUB;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
BaseInitAppcompatCache(VOID)
{
    STUB;
    return FALSE;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
BaseInitAppcompatCacheSupport(VOID)
{
    STUB;
    return FALSE;
}

/*
 * @unimplemented
 */
PVOID
WINAPI
GetComPlusPackageInstallStatus(VOID)
{
    STUB;
    return NULL;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetComPlusPackageInstallStatus(IN ULONG ComPlusPackage)
{
    NTSTATUS Status;

    DPRINT("(0x%X)\n", ComPlusPackage);

    if (ComPlusPackage & ~1)
    {
        DPRINT1("0x%lX\n", ComPlusPackage);
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    Status = NtSetSystemInformation(SystemComPlusPackage, &ComPlusPackage, sizeof(ComPlusPackage));
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("0x%lX\n", Status);
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @unimplemented
 */
VOID
WINAPI
SetTermsrvAppInstallMode(IN BOOL bInstallMode)
{
    STUB;
}

/*
 * @unimplemented
 */
BOOL
WINAPI
TermsrvAppInstallMode(VOID)
{
    STUB;
    return FALSE;
}
