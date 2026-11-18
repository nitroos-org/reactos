/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows Filtering Platform user-mode client (fwpuclnt.dll): the management API of an engine that is not there
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * DESIGN NOTE (read before changing the status of any function)
 *
 * NitroOS has no Base Filtering Engine and no filtering platform: its firewall (netsh advfirewall, the firewall
 * service) is not built on WFP. Programs still link to this DLL (VPN, security and sandbox software, native
 * developer tools) and load it even if they never call into it. This DLL exists so that they load and so that every call
 * gets an answer that is true:
 *
 *  - FwpmEngineOpen0 succeeds. The session it opens is to an engine that holds nothing and filters nothing.
 *    A caller can look: every enumeration is empty and every lookup of an object by key or id finds nothing
 *    (FWP_E_*_NOT_FOUND). That is exactly the state of the machine.
 *  - Nothing is ever added. Every function that would install an object (filter, sublayer, provider, callout,
 *    provider context) and every function that would change the engine (options, security) returns ERROR_NOT_SUPPORTED
 *    for a caller that is allowed to do it. It NEVER returns success: software that installs a filter believes it is
 *    protected only if the call succeeded, and here nothing would filter. A failed call is the safe answer.
 *  - Deleting an object that cannot exist reports that it is not found (as the engine does for an unknown key), so
 *    "delete the old filter, then add" code runs up to the add and stops there.
 *  - Transactions are real as far as they go: begin, commit and abort keep the state of the session and report the
 *    errors of the engine (FWP_E_TXN_IN_PROGRESS, FWP_E_NO_TXN_IN_PROGRESS). An empty transaction commits.
 *  - A caller that is not a member of the Administrators group (the token as it is, deny-only entries do not count)
 *    gets ERROR_ACCESS_DENIED for the enumerations, the transactions, the options and every change, as on Windows,
 *    where the engine's security descriptor allows those to administrators only. Opening a session and looking an
 *    object up by key or id are allowed to everybody (measured). This is an approximation of the engine's access
 *    check, not a model of it.
 *  - FwpmGetAppIdFromFileName0 is implemented: the application identifier is the NT path of the file in lower case.
 *
 * Measured on Windows Server 2022 (build 20348, evidence in the harness: evidence/clfix-20261118): the statuses
 * above for open, enumeration, lookup, transaction and the application identifier. Not measured (the peer's
 * configuration must not change): adds, deletes of existing objects and the engine with its service stopped.
 * Windows 10 was not measured. A handle that was closed, or that was never a handle, is ERROR_INVALID_HANDLE here
 * (Windows 2022 faults the process for a closed engine handle).
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <ndk/umtypes.h>
#include <ndk/rtlfuncs.h>

#include <fwpmu.h>

#define TAG_ENGINE 0x4e475746 /* 'FWGN' */
#define TAG_ENUM   0x4d555746 /* 'FWUM' */

/* The status of the engine for a handle that is not a live enumerator (measured, FWP_E_SESSION_ABORTED) */
#define STATUS_ENUM_HANDLE_INVALID ((DWORD)0x80320010)

typedef enum _OBJ_KIND
{
    KindFilter = 1,
    KindSubLayer,
    KindProvider,
    KindCallout,
    KindProviderContext,
    KindLayer,
    KindSession
} OBJ_KIND;

typedef struct _FWP_OBJ
{
    struct _FWP_OBJ *Next;
    ULONG Tag;
    struct _FWP_OBJ *Engine; /* enumerators: the session they belong to */
    ULONG Kind;              /* enumerators: what they enumerate */
    BOOL InTransaction;      /* sessions */
} FWP_OBJ;

static CRITICAL_SECTION ObjLock;
static FWP_OBJ *ObjList;

static FWP_OBJ *Alloc(ULONG Tag, FWP_OBJ *Engine, ULONG Kind)
{
    FWP_OBJ *Obj = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Obj));

    if (!Obj)
        return NULL;
    Obj->Tag = Tag;
    Obj->Engine = Engine;
    Obj->Kind = Kind;
    EnterCriticalSection(&ObjLock);
    Obj->Next = ObjList;
    ObjList = Obj;
    LeaveCriticalSection(&ObjLock);
    return Obj;
}

/* The object for the handle if it is a live one of this tag; with the lock held by the caller */
static FWP_OBJ *FindLocked(HANDLE Handle, ULONG Tag)
{
    FWP_OBJ *Obj;

    for (Obj = ObjList; Obj; Obj = Obj->Next)
    {
        if ((HANDLE)Obj == Handle && Obj->Tag == Tag)
            return Obj;
    }
    return NULL;
}

static void FreeLocked(FWP_OBJ *Obj)
{
    FWP_OBJ **Link;

    for (Link = &ObjList; *Link; Link = &(*Link)->Next)
    {
        if (*Link == Obj)
        {
            *Link = Obj->Next;
            break;
        }
    }
    Obj->Tag = 0;
    HeapFree(GetProcessHeap(), 0, Obj);
}

static BOOL IsAdministrator(void)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = {SECURITY_NT_AUTHORITY};
    PSID AdminSid;
    BOOL Member = FALSE;

    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &AdminSid))
        return FALSE;
    if (!CheckTokenMembership(NULL, AdminSid, &Member))
        Member = FALSE;
    FreeSid(AdminSid);
    return Member;
}

/* ---- session -------------------------------------------------------------------------------------------------- */

DWORD WINAPI
FwpmEngineOpen0(const wchar_t *serverName, UINT32 authnService, SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
                const FWPM_SESSION0 *session, HANDLE *engineHandle)
{
    FWP_OBJ *Engine;

    if (!engineHandle)
        return FWP_E_NULL_POINTER;
    /* Measured: the handle is NULL after a failed call */
    *engineHandle = NULL;
    /* Measured: a server name and an authentication service other than RPC_C_AUTHN_WINNT (10) or
       RPC_C_AUTHN_DEFAULT (0xFFFFFFFF) are ERROR_NOT_SUPPORTED */
    if (serverName || (authnService != 10 && authnService != 0xFFFFFFFF))
        return ERROR_NOT_SUPPORTED;
    Engine = Alloc(TAG_ENGINE, NULL, 0);
    if (!Engine)
        return ERROR_OUTOFMEMORY;
    *engineHandle = (HANDLE)Engine;
    return ERROR_SUCCESS;
}

DWORD WINAPI
FwpmEngineClose0(HANDLE engineHandle)
{
    FWP_OBJ *Engine, *Obj, *Next;

    EnterCriticalSection(&ObjLock);
    Engine = FindLocked(engineHandle, TAG_ENGINE);
    if (!Engine)
    {
        LeaveCriticalSection(&ObjLock);
        return ERROR_INVALID_HANDLE;
    }
    /* the enumerators of the session go with it */
    for (Obj = ObjList; Obj; Obj = Next)
    {
        Next = Obj->Next;
        if (Obj->Tag == TAG_ENUM && Obj->Engine == Engine)
            FreeLocked(Obj);
    }
    FreeLocked(Engine);
    LeaveCriticalSection(&ObjLock);
    return ERROR_SUCCESS;
}

static BOOL IsEngine(HANDLE Handle)
{
    BOOL Found;

    EnterCriticalSection(&ObjLock);
    Found = FindLocked(Handle, TAG_ENGINE) != NULL;
    LeaveCriticalSection(&ObjLock);
    return Found;
}

DWORD WINAPI
FwpmEngineGetOption0(HANDLE engineHandle, FWPM_ENGINE_OPTION option, FWP_VALUE0 **value)
{
    if (!IsEngine(engineHandle))
        return ERROR_INVALID_HANDLE;
    if (!IsAdministrator())
        return ERROR_ACCESS_DENIED;
    if (!value)
        return FWP_E_NULL_POINTER;
    *value = NULL;
    /* Measured: an option number that the engine does not have gives this status (0x8032001d). The options it has describe
       an engine's behaviour; there is none here, so a value is not made up for them. */
    if ((UINT32)option >= FWPM_ENGINE_OPTION_MAX)
        return FWP_E_INVALID_ENUMERATOR;
    return ERROR_NOT_SUPPORTED;
}

DWORD WINAPI
FwpmEngineSetOption0(HANDLE engineHandle, FWPM_ENGINE_OPTION option, const FWP_VALUE0 *newValue)
{
    if (!IsEngine(engineHandle))
        return ERROR_INVALID_HANDLE;
    if (!IsAdministrator())
        return ERROR_ACCESS_DENIED;
    if (!newValue)
        return FWP_E_NULL_POINTER;
    return ERROR_NOT_SUPPORTED;
}

DWORD WINAPI
FwpmEngineGetSecurityInfo0(HANDLE engineHandle, SECURITY_INFORMATION securityInfo, PSID *sidOwner, PSID *sidGroup,
                           PACL *dacl, PACL *sacl, PSECURITY_DESCRIPTOR *securityDescriptor)
{
    if (!IsEngine(engineHandle))
        return ERROR_INVALID_HANDLE;
    if (!IsAdministrator())
        return ERROR_ACCESS_DENIED;
    if (!securityDescriptor)
        return FWP_E_NULL_POINTER;
    *securityDescriptor = NULL;
    return ERROR_NOT_SUPPORTED;
}

DWORD WINAPI
FwpmEngineSetSecurityInfo0(HANDLE engineHandle, SECURITY_INFORMATION securityInfo, const SID *sidOwner,
                           const SID *sidGroup, const ACL *dacl, const ACL *sacl)
{
    if (!IsEngine(engineHandle))
        return ERROR_INVALID_HANDLE;
    if (!IsAdministrator())
        return ERROR_ACCESS_DENIED;
    return ERROR_NOT_SUPPORTED;
}

/* ---- transactions --------------------------------------------------------------------------------------------- */

DWORD WINAPI
FwpmTransactionBegin0(HANDLE engineHandle, UINT32 flags)
{
    FWP_OBJ *Engine;
    DWORD Status;

    EnterCriticalSection(&ObjLock);
    Engine = FindLocked(engineHandle, TAG_ENGINE);
    if (!Engine)
        Status = ERROR_INVALID_HANDLE;
    else if (!IsAdministrator())
        Status = ERROR_ACCESS_DENIED; /* measured: before the check for a transaction already in progress */
    else if (Engine->InTransaction)
        Status = FWP_E_TXN_IN_PROGRESS;
    else
    {
        Engine->InTransaction = TRUE;
        Status = ERROR_SUCCESS;
    }
    LeaveCriticalSection(&ObjLock);
    return Status;
}

static DWORD EndTransaction(HANDLE engineHandle)
{
    FWP_OBJ *Engine;
    DWORD Status;

    EnterCriticalSection(&ObjLock);
    Engine = FindLocked(engineHandle, TAG_ENGINE);
    if (!Engine)
        Status = ERROR_INVALID_HANDLE;
    else if (!Engine->InTransaction)
        Status = FWP_E_NO_TXN_IN_PROGRESS; /* measured, for administrators and others alike */
    else
    {
        Engine->InTransaction = FALSE;
        Status = ERROR_SUCCESS;
    }
    LeaveCriticalSection(&ObjLock);
    return Status;
}

DWORD WINAPI
FwpmTransactionCommit0(HANDLE engineHandle)
{
    /* nothing can have been added in the transaction, so there is nothing to apply */
    return EndTransaction(engineHandle);
}

DWORD WINAPI
FwpmTransactionAbort0(HANDLE engineHandle)
{
    return EndTransaction(engineHandle);
}

/* ---- memory and application identifiers ----------------------------------------------------------------------- */

void WINAPI
FwpmFreeMemory0(void **p)
{
    if (p && *p)
    {
        HeapFree(GetProcessHeap(), 0, *p);
        *p = NULL;
    }
}

/*
 * The identifier is the NT path of the file, in lower case, with its terminating null counted in the size;
 * the blob and the string are one allocation (measured). The file must exist and be a file: the errors are those of opening it.
 */
DWORD WINAPI
FwpmGetAppIdFromFileName0(PCWSTR fileName, FWP_BYTE_BLOB **appId)
{
    UNICODE_STRING NtPath;
    WCHAR Link[MAX_PATH];
    WCHAR Target[MAX_PATH];
    HANDLE File;
    PWSTR Rest;
    SIZE_T LinkLength, TargetLength, RestLength, Total, i;
    FWP_BYTE_BLOB *Blob;
    PWCHAR Data;

    if (!fileName || !appId)
        return FWP_E_NULL_POINTER;
    *appId = NULL;

    if (!RtlDosPathNameToNtPathName_U(fileName, &NtPath, NULL, NULL))
        return ERROR_PATH_NOT_FOUND;

    File = CreateFileW(fileName, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        DWORD Error = GetLastError();

        RtlFreeUnicodeString(&NtPath);
        return Error;
    }
    CloseHandle(File);

    /* "\??\C:\dir\file" -> the target of the link "C:" in the DOS device directory + "\dir\file";
       "\??\UNC\server\share\file" -> "\Device\Mup" + "\server\share\file" */
    if (NtPath.Length < 4 * sizeof(WCHAR) || NtPath.Buffer[0] != L'\\' || NtPath.Buffer[1] != L'?' ||
        NtPath.Buffer[2] != L'?' || NtPath.Buffer[3] != L'\\')
    {
        RtlFreeUnicodeString(&NtPath);
        return ERROR_PATH_NOT_FOUND;
    }
    Rest = NtPath.Buffer + 4;
    LinkLength = 0;
    while (&Rest[LinkLength] < NtPath.Buffer + NtPath.Length / sizeof(WCHAR) && Rest[LinkLength] != L'\\')
        LinkLength++;
    if (LinkLength == 0 || LinkLength >= MAX_PATH)
    {
        RtlFreeUnicodeString(&NtPath);
        return ERROR_PATH_NOT_FOUND;
    }
    for (i = 0; i < LinkLength; i++)
        Link[i] = Rest[i];
    Link[LinkLength] = UNICODE_NULL;
    TargetLength = QueryDosDeviceW(Link, Target, MAX_PATH);
    if (TargetLength == 0)
    {
        DWORD Error = GetLastError();

        RtlFreeUnicodeString(&NtPath);
        return Error ? Error : ERROR_PATH_NOT_FOUND;
    }
    TargetLength = 0;
    while (Target[TargetLength])
        TargetLength++;
    RestLength = NtPath.Length / sizeof(WCHAR) - 4 - LinkLength;
    Rest += LinkLength;

    Total = TargetLength + RestLength + 1;
    Blob = HeapAlloc(GetProcessHeap(), 0, sizeof(*Blob) + Total * sizeof(WCHAR));
    if (!Blob)
    {
        RtlFreeUnicodeString(&NtPath);
        return ERROR_OUTOFMEMORY;
    }
    Data = (PWCHAR)(Blob + 1);
    for (i = 0; i < TargetLength; i++)
        Data[i] = Target[i];
    for (i = 0; i < RestLength; i++)
        Data[TargetLength + i] = Rest[i];
    Data[Total - 1] = UNICODE_NULL;
    RtlFreeUnicodeString(&NtPath);

    for (i = 0; i + 1 < Total; i++)
        Data[i] = RtlDowncaseUnicodeChar(Data[i]);
    Blob->size = (UINT32)(Total * sizeof(WCHAR));
    Blob->data = (UINT8 *)Data;
    *appId = Blob;
    return ERROR_SUCCESS;
}

/* ---- objects: lookups, deletes, adds, enumerations --------------------------------------------------------------- */

/* Lookups are open to everybody (measured) and find nothing */
static DWORD NotFound(HANDLE Engine, const void *Key, void **Out, DWORD Status)
{
    if (!IsEngine(Engine))
        return ERROR_INVALID_HANDLE;
    if (!Out)
        return FWP_E_NULL_POINTER;
    *Out = NULL;
    return Status;
}

/* Deletes need the right to change the engine and find nothing to delete */
static DWORD DeleteNothing(HANDLE Engine, DWORD Status)
{
    if (!IsEngine(Engine))
        return ERROR_INVALID_HANDLE;
    if (!IsAdministrator())
        return ERROR_ACCESS_DENIED;
    return Status;
}

/* Adds are never carried out and never reported as done */
static DWORD AddRefused(HANDLE Engine, const void *Object)
{
    if (!IsEngine(Engine))
        return ERROR_INVALID_HANDLE;
    if (!IsAdministrator())
        return ERROR_ACCESS_DENIED;
    if (!Object)
        return FWP_E_NULL_POINTER;
    return ERROR_NOT_SUPPORTED;
}

static DWORD CreateEnum(HANDLE Engine, ULONG Kind, HANDLE *EnumHandle)
{
    FWP_OBJ *Obj, *EngineObj;

    if (!IsEngine(Engine))
        return ERROR_INVALID_HANDLE;
    if (!IsAdministrator())
        return ERROR_ACCESS_DENIED; /* measured for filters, sublayers and providers */
    if (!EnumHandle)
        return FWP_E_NULL_POINTER;
    EnterCriticalSection(&ObjLock);
    EngineObj = FindLocked(Engine, TAG_ENGINE);
    LeaveCriticalSection(&ObjLock);
    Obj = EngineObj ? Alloc(TAG_ENUM, EngineObj, Kind) : NULL;
    if (!Obj)
        return ERROR_OUTOFMEMORY;
    *EnumHandle = (HANDLE)Obj;
    return ERROR_SUCCESS;
}

static BOOL FindEnumLocked(HANDLE Engine, HANDLE EnumHandle, ULONG Kind)
{
    FWP_OBJ *EngineObj = FindLocked(Engine, TAG_ENGINE), *Obj = FindLocked(EnumHandle, TAG_ENUM);

    return EngineObj && Obj && Obj->Engine == EngineObj && Obj->Kind == Kind;
}

/* The engine holds no objects: the enumeration is at its end at once */
static DWORD EnumNext(HANDLE Engine, HANDLE EnumHandle, ULONG Kind, void ***Entries, UINT32 *Returned)
{
    BOOL Valid;

    if (!IsEngine(Engine))
        return ERROR_INVALID_HANDLE;
    EnterCriticalSection(&ObjLock);
    Valid = FindEnumLocked(Engine, EnumHandle, Kind);
    LeaveCriticalSection(&ObjLock);
    if (!Valid)
        return STATUS_ENUM_HANDLE_INVALID; /* measured for a handle that is not (or no longer) an enumerator */
    if (!Entries || !Returned)
        return FWP_E_NULL_POINTER;
    *Entries = NULL;
    *Returned = 0;
    return ERROR_SUCCESS;
}

static DWORD DestroyEnum(HANDLE Engine, HANDLE EnumHandle, ULONG Kind)
{
    DWORD Status = ERROR_SUCCESS;

    if (!IsEngine(Engine))
        return ERROR_INVALID_HANDLE;
    EnterCriticalSection(&ObjLock);
    if (FindEnumLocked(Engine, EnumHandle, Kind))
        FreeLocked(FindLocked(EnumHandle, TAG_ENUM));
    else
        Status = STATUS_ENUM_HANDLE_INVALID; /* measured, also for a second destroy */
    LeaveCriticalSection(&ObjLock);
    return Status;
}

#define ENUM_FUNCTIONS(Name, EntryType, TemplateType, Kind) \
DWORD WINAPI Fwpm##Name##CreateEnumHandle0(HANDLE engineHandle, const TemplateType *enumTemplate, HANDLE *enumHandle) \
{ return CreateEnum(engineHandle, Kind, enumHandle); } \
DWORD WINAPI Fwpm##Name##Enum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested, EntryType ***entries, \
                               UINT32 *numEntriesReturned) \
{ return EnumNext(engineHandle, enumHandle, Kind, (void ***)entries, numEntriesReturned); } \
DWORD WINAPI Fwpm##Name##DestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle) \
{ return DestroyEnum(engineHandle, enumHandle, Kind); }

ENUM_FUNCTIONS(Filter, FWPM_FILTER0, FWPM_FILTER_ENUM_TEMPLATE0, KindFilter)
ENUM_FUNCTIONS(SubLayer, FWPM_SUBLAYER0, FWPM_SUBLAYER_ENUM_TEMPLATE0, KindSubLayer)
ENUM_FUNCTIONS(Provider, FWPM_PROVIDER0, FWPM_PROVIDER_ENUM_TEMPLATE0, KindProvider)
ENUM_FUNCTIONS(Callout, FWPM_CALLOUT0, FWPM_CALLOUT_ENUM_TEMPLATE0, KindCallout)
ENUM_FUNCTIONS(ProviderContext, FWPM_PROVIDER_CONTEXT0, FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0, KindProviderContext)
ENUM_FUNCTIONS(Layer, FWPM_LAYER0, FWPM_LAYER_ENUM_TEMPLATE0, KindLayer)
ENUM_FUNCTIONS(Session, FWPM_SESSION0, FWPM_SESSION_ENUM_TEMPLATE0, KindSession)

/* Filters */
DWORD WINAPI FwpmFilterAdd0(HANDLE engineHandle, const FWPM_FILTER0 *filter, PSECURITY_DESCRIPTOR sd, UINT64 *id)
{
    if (id)
        *id = 0;
    return AddRefused(engineHandle, filter);
}
DWORD WINAPI FwpmFilterDeleteById0(HANDLE engineHandle, UINT64 id)
{ return DeleteNothing(engineHandle, FWP_E_FILTER_NOT_FOUND); }
DWORD WINAPI FwpmFilterDeleteByKey0(HANDLE engineHandle, const GUID *key)
{ return key ? DeleteNothing(engineHandle, FWP_E_FILTER_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }
DWORD WINAPI FwpmFilterGetById0(HANDLE engineHandle, UINT64 id, FWPM_FILTER0 **filter)
{ return NotFound(engineHandle, NULL, (void **)filter, FWP_E_FILTER_NOT_FOUND); }
DWORD WINAPI FwpmFilterGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_FILTER0 **filter)
{ return key ? NotFound(engineHandle, key, (void **)filter, FWP_E_FILTER_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }

/* Sublayers */
DWORD WINAPI FwpmSubLayerAdd0(HANDLE engineHandle, const FWPM_SUBLAYER0 *subLayer, PSECURITY_DESCRIPTOR sd)
{ return AddRefused(engineHandle, subLayer); }
DWORD WINAPI FwpmSubLayerDeleteByKey0(HANDLE engineHandle, const GUID *key)
{ return key ? DeleteNothing(engineHandle, FWP_E_SUBLAYER_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }
DWORD WINAPI FwpmSubLayerGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_SUBLAYER0 **subLayer)
{ return key ? NotFound(engineHandle, key, (void **)subLayer, FWP_E_SUBLAYER_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }

/* Providers */
DWORD WINAPI FwpmProviderAdd0(HANDLE engineHandle, const FWPM_PROVIDER0 *provider, PSECURITY_DESCRIPTOR sd)
{ return AddRefused(engineHandle, provider); }
DWORD WINAPI FwpmProviderDeleteByKey0(HANDLE engineHandle, const GUID *key)
{ return key ? DeleteNothing(engineHandle, FWP_E_PROVIDER_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }
DWORD WINAPI FwpmProviderGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_PROVIDER0 **provider)
{ return key ? NotFound(engineHandle, key, (void **)provider, FWP_E_PROVIDER_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }

/* Callouts */
DWORD WINAPI FwpmCalloutAdd0(HANDLE engineHandle, const FWPM_CALLOUT0 *callout, PSECURITY_DESCRIPTOR sd, UINT32 *id)
{
    if (id)
        *id = 0;
    return AddRefused(engineHandle, callout);
}
DWORD WINAPI FwpmCalloutDeleteById0(HANDLE engineHandle, UINT32 id)
{ return DeleteNothing(engineHandle, FWP_E_CALLOUT_NOT_FOUND); }
DWORD WINAPI FwpmCalloutDeleteByKey0(HANDLE engineHandle, const GUID *key)
{ return key ? DeleteNothing(engineHandle, FWP_E_CALLOUT_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }
DWORD WINAPI FwpmCalloutGetById0(HANDLE engineHandle, UINT32 id, FWPM_CALLOUT0 **callout)
{ return NotFound(engineHandle, NULL, (void **)callout, FWP_E_CALLOUT_NOT_FOUND); }
DWORD WINAPI FwpmCalloutGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_CALLOUT0 **callout)
{ return key ? NotFound(engineHandle, key, (void **)callout, FWP_E_CALLOUT_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }

/* Provider contexts and layers */
DWORD WINAPI FwpmProviderContextAdd0(HANDLE engineHandle, const FWPM_PROVIDER_CONTEXT0 *providerContext, PSECURITY_DESCRIPTOR sd, UINT64 *id)
{
    if (id)
        *id = 0;
    return AddRefused(engineHandle, providerContext);
}
DWORD WINAPI FwpmProviderContextDeleteById0(HANDLE engineHandle, UINT64 id)
{ return DeleteNothing(engineHandle, FWP_E_PROVIDER_CONTEXT_NOT_FOUND); }
DWORD WINAPI FwpmProviderContextDeleteByKey0(HANDLE engineHandle, const GUID *key)
{ return key ? DeleteNothing(engineHandle, FWP_E_PROVIDER_CONTEXT_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }
DWORD WINAPI FwpmProviderContextGetById0(HANDLE engineHandle, UINT64 id, FWPM_PROVIDER_CONTEXT0 **providerContext)
{ return NotFound(engineHandle, NULL, (void **)providerContext, FWP_E_PROVIDER_CONTEXT_NOT_FOUND); }
DWORD WINAPI FwpmProviderContextGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_PROVIDER_CONTEXT0 **providerContext)
{ return key ? NotFound(engineHandle, key, (void **)providerContext, FWP_E_PROVIDER_CONTEXT_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }
DWORD WINAPI FwpmLayerGetById0(HANDLE engineHandle, UINT16 id, FWPM_LAYER0 **layer)
{ return NotFound(engineHandle, NULL, (void **)layer, FWP_E_LAYER_NOT_FOUND); }
DWORD WINAPI FwpmLayerGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_LAYER0 **layer)
{ return key ? NotFound(engineHandle, key, (void **)layer, FWP_E_LAYER_NOT_FOUND) : (IsEngine(engineHandle) ? FWP_E_NULL_POINTER : ERROR_INVALID_HANDLE); }

BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            InitializeCriticalSection(&ObjLock);
            break;
        case DLL_PROCESS_DETACH:
            if (!lpvReserved)
                DeleteCriticalSection(&ObjLock);
            break;
    }
    return TRUE;
}
