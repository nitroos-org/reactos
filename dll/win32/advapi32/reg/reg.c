/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/advapi32/reg/reg.c
 * PURPOSE:         Registry functions
 * PROGRAMMER:      Ariadne ( ariadne@xs4all.nl)
 *                  Thomas Weidenmueller <w3seek@reactos.com>
 * UPDATE HISTORY:
 *                  Created 01/11/98
 *                  19990309 EA Stubs
 *                  20050502 Fireball imported some stuff from WINE
 */

/* INCLUDES *****************************************************************/

#include <advapi32.h>

#include <ndk/cmfuncs.h>
#include <ndk/obfuncs.h>
#include <wow64reg.h>
#include <pseh/pseh2.h>

#include "reg.h"

WINE_DEFAULT_DEBUG_CHANNEL(reg);

/* DEFINES ******************************************************************/

#define MAX_DEFAULT_HANDLES   6
#define REG_MAX_NAME_SIZE     256
#define REG_MAX_DATA_SIZE     2048

/* GLOBALS ******************************************************************/

static RTL_CRITICAL_SECTION HandleTableCS;
static HANDLE DefaultHandleTable[MAX_DEFAULT_HANDLES];
static HANDLE ProcessHeap;
static BOOLEAN DefaultHandlesDisabled = FALSE;
static BOOLEAN DefaultHandleHKUDisabled = FALSE;
static BOOLEAN DllInitialized = FALSE; /* HACK */

/* PROTOTYPES ***************************************************************/

static NTSTATUS MapDefaultKey (PHANDLE ParentKey, HKEY Key);
static VOID CloseDefaultKeys(VOID);
#define ClosePredefKey(Handle)                                                 \
    if ((ULONG_PTR)Handle & 0x1) {                                             \
        NtClose(Handle);                                                       \
    }
#define IsPredefKey(HKey)                                                      \
    (((ULONG_PTR)(HKey) & 0xF0000000) == 0x80000000)
#define GetPredefKeyIndex(HKey)                                                \
    ((ULONG_PTR)(HKey) & 0x0FFFFFFF)

static NTSTATUS OpenClassesRootKey(PHANDLE KeyHandle);
static NTSTATUS OpenLocalMachineKey (PHANDLE KeyHandle);
static NTSTATUS OpenUsersKey (PHANDLE KeyHandle);
static NTSTATUS OpenCurrentConfigKey(PHANDLE KeyHandle);


/* FUNCTIONS ****************************************************************/
/* check if value type needs string conversion (Ansi<->Unicode) */
__inline static int is_string( DWORD type )
{
    return (type == REG_SZ) || (type == REG_EXPAND_SZ) || (type == REG_MULTI_SZ);
}

/************************************************************************
 *  RegInitDefaultHandles
 */
BOOL
RegInitialize(VOID)
{
    TRACE("RegInitialize()\n");

    /* Lazy init hack */
    if (!DllInitialized)
    {
        ProcessHeap = RtlGetProcessHeap();
        RtlZeroMemory(DefaultHandleTable,
                      MAX_DEFAULT_HANDLES * sizeof(HANDLE));
        RtlInitializeCriticalSection(&HandleTableCS);

        DllInitialized = TRUE;
    }

    return TRUE;
}


/************************************************************************
 *  RegInit
 */
BOOL
RegCleanup(VOID)
{
    TRACE("RegCleanup()\n");

    CloseDefaultKeys();
    RtlDeleteCriticalSection(&HandleTableCS);

    return TRUE;
}


static NTSTATUS
OpenPredefinedKey(IN ULONG Index,
                  OUT HANDLE Handle)
{
    NTSTATUS Status;

    switch (Index)
    {
        case 0: /* HKEY_CLASSES_ROOT */
            Status = OpenClassesRootKey (Handle);
            break;

        case 1: /* HKEY_CURRENT_USER */
            Status = RtlOpenCurrentUser (MAXIMUM_ALLOWED,
                                         Handle);
            break;

        case 2: /* HKEY_LOCAL_MACHINE */
            Status = OpenLocalMachineKey (Handle);
            break;

        case 3: /* HKEY_USERS */
            Status = OpenUsersKey (Handle);
            break;
#if 0
        case 4: /* HKEY_PERFORMANCE_DATA */
            Status = OpenPerformanceDataKey (Handle);
            break;
#endif

        case 5: /* HKEY_CURRENT_CONFIG */
            Status = OpenCurrentConfigKey (Handle);
            break;

        case 6: /* HKEY_DYN_DATA */
            Status = STATUS_NOT_IMPLEMENTED;
            break;

        default:
            WARN("MapDefaultHandle() no handle creator\n");
            Status = STATUS_INVALID_PARAMETER;
            break;
    }

    return Status;
}


static NTSTATUS
MapDefaultKey(OUT PHANDLE RealKey,
              IN HKEY Key)
{
    PHANDLE Handle;
    ULONG Index;
    BOOLEAN DoOpen, DefDisabled;
    NTSTATUS Status = STATUS_SUCCESS;

    TRACE("MapDefaultKey (Key %x)\n", Key);

    if (!IsPredefKey(Key))
    {
        *RealKey = (HANDLE)((ULONG_PTR)Key & ~0x1);
        return STATUS_SUCCESS;
    }

    /* Handle special cases here */
    Index = GetPredefKeyIndex(Key);
    if (Index >= MAX_DEFAULT_HANDLES)
    {
        return STATUS_INVALID_PARAMETER;
    }
    RegInitialize(); /* HACK until delay-loading is implemented */
    RtlEnterCriticalSection (&HandleTableCS);

    if (Key == HKEY_CURRENT_USER)
        DefDisabled = DefaultHandleHKUDisabled;
    else
        DefDisabled = DefaultHandlesDisabled;

    if (!DefDisabled)
    {
        Handle = &DefaultHandleTable[Index];
        DoOpen = (*Handle == NULL);
    }
    else
    {
        Handle = RealKey;
        DoOpen = TRUE;
    }

    if (DoOpen)
    {
        /* create/open the default handle */
        Status = OpenPredefinedKey(Index,
                                   Handle);
    }

    if (NT_SUCCESS(Status))
    {
        if (!DefDisabled)
            *RealKey = *Handle;
        else
            *(PULONG_PTR)Handle |= 0x1;
    }

    RtlLeaveCriticalSection (&HandleTableCS);

    return Status;
}


static VOID
CloseDefaultKeys(VOID)
{
    ULONG i;
    RegInitialize(); /* HACK until delay-loading is implemented */
    RtlEnterCriticalSection(&HandleTableCS);

    for (i = 0; i < MAX_DEFAULT_HANDLES; i++)
    {
        if (DefaultHandleTable[i] != NULL)
        {
            NtClose(DefaultHandleTable[i]);
            DefaultHandleTable[i] = NULL;
        }
    }

    RtlLeaveCriticalSection(&HandleTableCS);
}


static NTSTATUS
OpenClassesRootKey(_Out_ PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\CLASSES");
    NTSTATUS Status;

    TRACE("OpenClassesRootKey()\n");

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenKey(KeyHandle,
                       MAXIMUM_ALLOWED,
                       &Attributes);

    if (!NT_SUCCESS(Status))
        return Status;

    /* Mark it as HKCR */
    MakeHKCRKey((HKEY*)KeyHandle);

    return Status;
}


static NTSTATUS
OpenLocalMachineKey(PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine");
    NTSTATUS Status;

    TRACE("OpenLocalMachineKey()\n");

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    Status = NtOpenKey(KeyHandle,
                       MAXIMUM_ALLOWED,
                       &Attributes);

    TRACE("NtOpenKey(%wZ) => %08x\n", &KeyName, Status);

    return Status;
}


static NTSTATUS
OpenUsersKey(PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\User");

    TRACE("OpenUsersKey()\n");

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    return NtOpenKey(KeyHandle,
                     MAXIMUM_ALLOWED,
                     &Attributes);
}


static NTSTATUS
OpenCurrentConfigKey (PHANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING KeyName =
        RTL_CONSTANT_STRING(L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current");

    TRACE("OpenCurrentConfigKey()\n");

    InitializeObjectAttributes(&Attributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    return NtOpenKey(KeyHandle,
                     MAXIMUM_ALLOWED,
                     &Attributes);
}

#ifndef _ADVAPI32_VISTA_

/************************************************************************
 *  RegDisablePredefinedCache
 *
 * @implemented
 */
LONG WINAPI
RegDisablePredefinedCache(VOID)
{
    RegInitialize(); /* HACK until delay-loading is implemented */
    RtlEnterCriticalSection(&HandleTableCS);
    DefaultHandleHKUDisabled = TRUE;
    RtlLeaveCriticalSection(&HandleTableCS);
    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegDisablePredefinedCacheEx
 *
 * @implemented
 */
LONG WINAPI
RegDisablePredefinedCacheEx(VOID)
{
    RegInitialize(); /* HACK until delay-loading is implemented */
    RtlEnterCriticalSection(&HandleTableCS);
    DefaultHandlesDisabled = TRUE;
    DefaultHandleHKUDisabled = TRUE;
    RtlLeaveCriticalSection(&HandleTableCS);
    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegOverridePredefKey
 *
 * @implemented
 */
LONG WINAPI
RegOverridePredefKey(IN HKEY hKey,
                     IN HKEY hNewHKey  OPTIONAL)
{
    LONG ErrorCode = ERROR_SUCCESS;

    if ((hKey == HKEY_CLASSES_ROOT ||
         hKey == HKEY_CURRENT_CONFIG ||
         hKey == HKEY_CURRENT_USER ||
         hKey == HKEY_LOCAL_MACHINE ||
         hKey == HKEY_PERFORMANCE_DATA ||
         hKey == HKEY_USERS) &&
        !IsPredefKey(hNewHKey))
    {
        PHANDLE Handle;
        ULONG Index;

        Index = GetPredefKeyIndex(hKey);
        Handle = &DefaultHandleTable[Index];

        if (hNewHKey == NULL)
        {
            /* restore the default mapping */
            NTSTATUS Status = OpenPredefinedKey(Index,
                                                &hNewHKey);
            if (!NT_SUCCESS(Status))
            {
                return RtlNtStatusToDosError(Status);
            }

            ASSERT(hNewHKey != NULL);
        }
        RegInitialize(); /* HACK until delay-loading is implemented */
        RtlEnterCriticalSection(&HandleTableCS);

        /* close the currently mapped handle if existing */
        if (*Handle != NULL)
        {
            NtClose(*Handle);
        }

        /* update the mapping */
        *Handle = hNewHKey;

        RtlLeaveCriticalSection(&HandleTableCS);
    }
    else
        ErrorCode = ERROR_INVALID_HANDLE;

    return ErrorCode;
}


/************************************************************************
 *  RegCloseKey
 *
 * @implemented
 */
LONG WINAPI
RegCloseKey(HKEY hKey)
{
    NTSTATUS Status;

    /* don't close null handle or a pseudo handle */
    if (!hKey)
    {
        return ERROR_INVALID_HANDLE;
    }

    if (((ULONG_PTR)hKey & 0xF0000000) == 0x80000000)
    {
        return ERROR_SUCCESS;
    }

    Status = NtClose(hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

  return ERROR_SUCCESS;
}

#endif // _ADVAPI32_VISTA_

static NTSTATUS
RegpCopyTree(IN HKEY hKeySrc,
             IN HKEY hKeyDest)
{
    typedef struct
    {
        LIST_ENTRY ListEntry;
        HANDLE hKeySrc;
        HANDLE hKeyDest;
    } REGP_COPY_KEYS, *PREGP_COPY_KEYS;

    LIST_ENTRY copyQueueHead;
    PREGP_COPY_KEYS copyKeys, newCopyKeys;
    union
    {
        KEY_VALUE_FULL_INFORMATION *KeyValue;
        KEY_NODE_INFORMATION *KeyNode;
        PVOID Buffer;
    } Info;
    ULONG Index, BufferSizeRequired, BufferSize = 0x200;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS Status2 = STATUS_SUCCESS;

    InitializeListHead(&copyQueueHead);

    Info.Buffer = RtlAllocateHeap(ProcessHeap,
                                  0,
                                  BufferSize);
    if (Info.Buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    copyKeys = RtlAllocateHeap(ProcessHeap,
                               0,
                               sizeof(REGP_COPY_KEYS));
    if (copyKeys != NULL)
    {
        copyKeys->hKeySrc = hKeySrc;
        copyKeys->hKeyDest = hKeyDest;
        InsertHeadList(&copyQueueHead,
                       &copyKeys->ListEntry);

        /* FIXME - copy security from hKeySrc to hKeyDest or just for the subkeys? */

        do
        {
            copyKeys = CONTAINING_RECORD(copyQueueHead.Flink,
                                         REGP_COPY_KEYS,
                                         ListEntry);

            /* enumerate all values and copy them */
            Index = 0;
            for (;;)
            {
                Status2 = NtEnumerateValueKey(copyKeys->hKeySrc,
                                              Index,
                                              KeyValueFullInformation,
                                              Info.KeyValue,
                                              BufferSize,
                                              &BufferSizeRequired);
                if (NT_SUCCESS(Status2))
                {
                    UNICODE_STRING ValueName;
                    PVOID Data;

                    /* don't use RtlInitUnicodeString as the string is not NULL-terminated! */
                    ValueName.Length = Info.KeyValue->NameLength;
                    ValueName.MaximumLength = ValueName.Length;
                    ValueName.Buffer = Info.KeyValue->Name;

                    Data = (PVOID)((ULONG_PTR)Info.KeyValue + Info.KeyValue->DataOffset);

                    Status2 = NtSetValueKey(copyKeys->hKeyDest,
                                            &ValueName,
                                            Info.KeyValue->TitleIndex,
                                            Info.KeyValue->Type,
                                            Data,
                                            Info.KeyValue->DataLength);

                    /* don't break, let's try to copy as many values as possible */
                    if (!NT_SUCCESS(Status2) && NT_SUCCESS(Status))
                    {
                        Status = Status2;
                    }

                    Index++;
                }
                else if (Status2 == STATUS_BUFFER_OVERFLOW)
                {
                    PVOID Buffer;

                    ASSERT(BufferSize < BufferSizeRequired);

                    Buffer = RtlReAllocateHeap(ProcessHeap,
                                               0,
                                               Info.Buffer,
                                               BufferSizeRequired);
                    if (Buffer != NULL)
                    {
                        Info.Buffer = Buffer;
                        BufferSize = BufferSizeRequired;
                        /* try again */
                    }
                    else
                    {
                        /* don't break, let's try to copy as many values as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                        Index++;

                        if (NT_SUCCESS(Status))
                        {
                            Status = Status2;
                        }
                    }
                }
                else
                {
                    /* break to avoid an infinite loop in case of denied access or
                       other errors! */
                    if (Status2 != STATUS_NO_MORE_ENTRIES && NT_SUCCESS(Status))
                    {
                        Status = Status2;
                    }

                    break;
                }
            }

            /* enumerate all subkeys and open and enqueue them */
            Index = 0;
            for (;;)
            {
                Status2 = NtEnumerateKey(copyKeys->hKeySrc,
                                         Index,
                                         KeyNodeInformation,
                                         Info.KeyNode,
                                         BufferSize,
                                         &BufferSizeRequired);
                if (NT_SUCCESS(Status2))
                {
                    HANDLE KeyHandle, NewKeyHandle;
                    OBJECT_ATTRIBUTES ObjectAttributes;
                    UNICODE_STRING SubKeyName, ClassName;

                    /* don't use RtlInitUnicodeString as the string is not NULL-terminated! */
                    SubKeyName.Length = Info.KeyNode->NameLength;
                    SubKeyName.MaximumLength = SubKeyName.Length;
                    SubKeyName.Buffer = Info.KeyNode->Name;
                    ClassName.Length = Info.KeyNode->ClassLength;
                    ClassName.MaximumLength = ClassName.Length;
                    ClassName.Buffer = (PWSTR)((ULONG_PTR)Info.KeyNode + Info.KeyNode->ClassOffset);

                    /* open the subkey with sufficient rights */

                    InitializeObjectAttributes(&ObjectAttributes,
                                               &SubKeyName,
                                               OBJ_CASE_INSENSITIVE,
                                               copyKeys->hKeySrc,
                                               NULL);

                    Status2 = NtOpenKey(&KeyHandle,
                                        KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                                        &ObjectAttributes);
                    if (NT_SUCCESS(Status2))
                    {
                        /* FIXME - attempt to query the security information */

                        InitializeObjectAttributes(&ObjectAttributes,
                                               &SubKeyName,
                                               OBJ_CASE_INSENSITIVE,
                                               copyKeys->hKeyDest,
                                               NULL);

                        Status2 = NtCreateKey(&NewKeyHandle,
                                              KEY_ALL_ACCESS,
                                              &ObjectAttributes,
                                              Info.KeyNode->TitleIndex,
                                              &ClassName,
                                              0,
                                              NULL);
                        if (NT_SUCCESS(Status2))
                        {
                            newCopyKeys = RtlAllocateHeap(ProcessHeap,
                                                          0,
                                                          sizeof(REGP_COPY_KEYS));
                            if (newCopyKeys != NULL)
                            {
                                /* save the handles and enqueue the subkey */
                                newCopyKeys->hKeySrc = KeyHandle;
                                newCopyKeys->hKeyDest = NewKeyHandle;
                                InsertTailList(&copyQueueHead,
                                               &newCopyKeys->ListEntry);
                            }
                            else
                            {
                                NtClose(KeyHandle);
                                NtClose(NewKeyHandle);

                                Status2 = STATUS_INSUFFICIENT_RESOURCES;
                            }
                        }
                        else
                        {
                            NtClose(KeyHandle);
                        }
                    }

                    if (!NT_SUCCESS(Status2) && NT_SUCCESS(Status))
                    {
                        Status = Status2;
                    }

                    Index++;
                }
                else if (Status2 == STATUS_BUFFER_OVERFLOW)
                {
                    PVOID Buffer;

                    ASSERT(BufferSize < BufferSizeRequired);

                    Buffer = RtlReAllocateHeap(ProcessHeap,
                                               0,
                                               Info.Buffer,
                                               BufferSizeRequired);
                    if (Buffer != NULL)
                    {
                        Info.Buffer = Buffer;
                        BufferSize = BufferSizeRequired;
                        /* try again */
                    }
                    else
                    {
                        /* don't break, let's try to copy as many keys as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                        Index++;

                        if (NT_SUCCESS(Status))
                        {
                            Status = Status2;
                        }
                    }
                }
                else
                {
                    /* break to avoid an infinite loop in case of denied access or
                       other errors! */
                    if (Status2 != STATUS_NO_MORE_ENTRIES && NT_SUCCESS(Status))
                    {
                        Status = Status2;
                    }

                    break;
                }
            }

            /* close the handles and remove the entry from the list */
            if (copyKeys->hKeySrc != hKeySrc)
            {
                NtClose(copyKeys->hKeySrc);
            }
            if (copyKeys->hKeyDest != hKeyDest)
            {
                NtClose(copyKeys->hKeyDest);
            }

            RemoveEntryList(&copyKeys->ListEntry);

            RtlFreeHeap(ProcessHeap,
                        0,
                        copyKeys);
        } while (!IsListEmpty(&copyQueueHead));
    }
    else
        Status = STATUS_INSUFFICIENT_RESOURCES;

    RtlFreeHeap(ProcessHeap,
                0,
                Info.Buffer);

    return Status;
}


/************************************************************************
 *  RegCopyTreeW
 *
 * @implemented
 */
LONG WINAPI
RegCopyTreeW(IN HKEY hKeySrc,
             IN LPCWSTR lpSubKey  OPTIONAL,
             IN HKEY hKeyDest)
{
    HANDLE DestKeyHandle, KeyHandle, CurKey, SubKeyHandle = NULL;
    NTSTATUS Status;

    Status = MapDefaultKey(&KeyHandle,
                           hKeySrc);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    Status = MapDefaultKey(&DestKeyHandle,
                           hKeyDest);
    if (!NT_SUCCESS(Status))
    {
        goto Cleanup2;
    }

    if (lpSubKey != NULL)
    {
        OBJECT_ATTRIBUTES ObjectAttributes;
        UNICODE_STRING SubKeyName;

        RtlInitUnicodeString(&SubKeyName, lpSubKey);

        InitializeObjectAttributes(&ObjectAttributes,
                                   &SubKeyName,
                                   OBJ_CASE_INSENSITIVE,
                                   KeyHandle,
                                   NULL);

        Status = NtOpenKey(&SubKeyHandle,
                           KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                           &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            goto Cleanup;
        }

        CurKey = SubKeyHandle;
    }
    else
        CurKey = KeyHandle;

    Status = RegpCopyTree(CurKey,
                          hKeyDest);

    if (SubKeyHandle != NULL)
    {
        NtClose(SubKeyHandle);
    }

Cleanup:
    ClosePredefKey(DestKeyHandle);
Cleanup2:
    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}

#ifndef _ADVAPI32_VISTA_

/************************************************************************
 *  RegCopyTreeA
 *
 * @implemented
 */
LONG WINAPI
RegCopyTreeA(IN HKEY hKeySrc,
             IN LPCSTR lpSubKey  OPTIONAL,
             IN HKEY hKeyDest)
{
    UNICODE_STRING SubKeyName = { 0, 0, NULL };
    LONG Ret;

    if (lpSubKey != NULL &&
        !RtlCreateUnicodeStringFromAsciiz(&SubKeyName, lpSubKey))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    Ret = RegCopyTreeW(hKeySrc,
                       SubKeyName.Buffer,
                       hKeyDest);

    RtlFreeUnicodeString(&SubKeyName);

    return Ret;
}


/************************************************************************
 *  RegConnectRegistryA
 *
 * @implemented
 */
LONG WINAPI
RegConnectRegistryA(IN LPCSTR lpMachineName,
                    IN HKEY hKey,
                    OUT PHKEY phkResult)
{
    UNICODE_STRING MachineName = { 0, 0, NULL };
    LONG Ret;

    if (lpMachineName != NULL &&
        !RtlCreateUnicodeStringFromAsciiz(&MachineName, lpMachineName))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    Ret = RegConnectRegistryW(MachineName.Buffer,
                              hKey,
                              phkResult);

    RtlFreeUnicodeString(&MachineName);

    return Ret;
}


/************************************************************************
 *  RegConnectRegistryW
 *
 * @unimplemented
 */
LONG WINAPI
RegConnectRegistryW(LPCWSTR lpMachineName,
                    HKEY hKey,
                    PHKEY phkResult)
{
    LONG ret;

    TRACE("(%s,%p,%p): stub\n",debugstr_w(lpMachineName),hKey,phkResult);

    if (!lpMachineName || !*lpMachineName)
    {
        /* Use the local machine name */
        ret = RegOpenKeyW( hKey, NULL, phkResult );
    }
    else
    {
        WCHAR compName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD len = sizeof(compName) / sizeof(WCHAR);

        /* MSDN says lpMachineName must start with \\ : not so */
        if( lpMachineName[0] == '\\' &&  lpMachineName[1] == '\\')
            lpMachineName += 2;

        if (GetComputerNameW(compName, &len))
        {
            if (!_wcsicmp(lpMachineName, compName))
                ret = RegOpenKeyW(hKey, NULL, phkResult);
            else
            {
                FIXME("Connect to %s is not supported.\n",debugstr_w(lpMachineName));
                ret = ERROR_BAD_NETPATH;
            }
        }
        else
            ret = GetLastError();
    }

    return ret;
}


/* Resolve a shared Software destination before shortening a failed create.
 * For example, Notepad is redirected but Notepad\\DefaultFonts is shared.
 * Retrying the former with the latter's 32-bit selector would create a parent
 * in the wrong tree. Keep this list identical to the kernel's view policy. */
static NTSTATUS
GetSharedNestedKeyName(POBJECT_ATTRIBUTES Attributes, REGSAM DesiredAccess,
                       PUNICODE_STRING Name)
{
    static const UNICODE_STRING Software = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE");
    PKEY_NAME_INFORMATION RootName = NULL;
    PCWSTR RootBuffer = NULL;
    ULONG RootLength = 0;
    UNICODE_STRING Full, Tail, Prefix;
#ifndef _WIN64
    BOOL Wow64;
#endif
    ULONG Size = 0, Length, i, j, Physical = 0;
    NTSTATUS Status;

    Name->Buffer = NULL;
#if defined(_WIN64) && !defined(BUILD_WOW64_ENABLED)
    return STATUS_SUCCESS;
#elif !defined(_WIN64)
    if (!IsWow64Process(GetCurrentProcess(), &Wow64) || !Wow64)
        return STATUS_SUCCESS; /* Native i386 ignores both selectors. */
#endif

    if (Attributes->RootDirectory)
    {
        Status = NtQueryKey(Attributes->RootDirectory, KeyNameInformation, NULL, 0, &Size);
#ifdef _WIN64
        if (Status == STATUS_ACCESS_DENIED)
        {
            /* A zero-access duplicate can be a relative create root, but
             * KeyNameInformation requires an access bit. Object names do not. */
            Status = NtQueryObject(Attributes->RootDirectory, ObjectNameInformation, NULL, 0, &Size);
            if (Status != STATUS_INFO_LENGTH_MISMATCH && Status != STATUS_BUFFER_TOO_SMALL &&
                Status != STATUS_BUFFER_OVERFLOW) return STATUS_SUCCESS;
            RootName = RtlAllocateHeap(ProcessHeap, 0, Size);
            if (!RootName) return STATUS_INSUFFICIENT_RESOURCES;
            Status = NtQueryObject(Attributes->RootDirectory, ObjectNameInformation, RootName, Size, &Size);
            if (!NT_SUCCESS(Status))
            {
                Status = STATUS_SUCCESS;
                goto Exit;
            }
            RootBuffer = ((PUNICODE_STRING)RootName)->Buffer;
            RootLength = ((PUNICODE_STRING)RootName)->Length;
            goto BuildName;
        }
#endif
        if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW)
            return STATUS_SUCCESS; /* Keep relative retries for unrepresentable ancestry. */
        RootName = RtlAllocateHeap(ProcessHeap, 0, Size);
        if (!RootName) return STATUS_INSUFFICIENT_RESOURCES;
        Status = NtQueryKey(Attributes->RootDirectory, KeyNameInformation, RootName, Size, &Size);
        if (!NT_SUCCESS(Status))
        {
            Status = STATUS_SUCCESS;
            goto Exit;
        }
        RootBuffer = RootName->Name;
        RootLength = RootName->NameLength;
    }
#ifdef _WIN64
BuildName:
#endif
    Length = (RootName ? RootLength + sizeof(WCHAR) : 0) + Attributes->ObjectName->Length;
    if (Length > MAXUSHORT - sizeof(WCHAR))
    {
        Status = STATUS_SUCCESS; /* Native relative names have no absolute-name limit. */
        goto Exit;
    }
    Full.Buffer = RtlAllocateHeap(ProcessHeap, 0, Length + sizeof(WCHAR));
    if (!Full.Buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    Full.Length = Length;
    Full.MaximumLength = Length + sizeof(WCHAR);
    i = 0;
    if (RootName)
    {
        RtlCopyMemory(Full.Buffer, RootBuffer, RootLength);
        i = RootLength / sizeof(WCHAR);
        Full.Buffer[i++] = L'\\';
    }
    RtlCopyMemory(Full.Buffer + i, Attributes->ObjectName->Buffer, Attributes->ObjectName->Length);
    for (i = j = 0; i < Full.Length / sizeof(WCHAR); ++i)
    {
        if (Full.Buffer[i] == L'\\' && j && Full.Buffer[j - 1] == L'\\') continue;
        Full.Buffer[j++] = Full.Buffer[i];
    }
    Full.Buffer[j] = UNICODE_NULL;
    Full.Length = j * sizeof(WCHAR);
    if (RtlPrefixUnicodeString(&Software, &Full, TRUE))
    {
        Tail.Buffer = Full.Buffer + Software.Length / sizeof(WCHAR);
        Tail.Length = Tail.MaximumLength = Full.Length - Software.Length;
        RtlInitUnicodeString(&Prefix, L"\\Wow6432Node");
        if (RtlPrefixUnicodeString(&Prefix, &Tail, TRUE) &&
            (Tail.Length == Prefix.Length || Tail.Buffer[Prefix.Length / sizeof(WCHAR)] == L'\\'))
        {
            Physical = Prefix.Length;
            Tail.Buffer += Physical / sizeof(WCHAR);
            Tail.Length = Tail.MaximumLength = Tail.Length - Physical;
        }
#ifdef _WIN64
        /* Native default requests already use the logical shared tree. Keep
         * their relative, selector-free retries: reconstructing an absolute
         * name and selecting a view imposes a limit on otherwise valid names.
         * Physical shared aliases still need their native parents resolved. */
        if (!Physical && !(DesiredAccess & (KEY_WOW64_32KEY | KEY_WOW64_64KEY)))
        {
            RtlFreeHeap(ProcessHeap, 0, Full.Buffer);
            Status = STATUS_SUCCESS;
            goto Exit;
        }
#endif
        for (i = 0; i < RTL_NUMBER_OF(Wow64SharedSoftware); ++i)
        {
            RtlInitUnicodeString(&Prefix, Wow64SharedSoftware[i]);
            if (RtlPrefixUnicodeString(&Prefix, &Tail, TRUE) &&
                (Tail.Length == Prefix.Length || Tail.Buffer[Prefix.Length / sizeof(WCHAR)] == L'\\'))
            {
                if (Physical)
                {
                    RtlMoveMemory(Full.Buffer + Software.Length / sizeof(WCHAR), Tail.Buffer, Tail.Length);
                    Full.Length -= Physical;
                    Full.Buffer[Full.Length / sizeof(WCHAR)] = UNICODE_NULL;
                }
                *Name = Full;
                break;
            }
        }
    }
    if (!Name->Buffer) RtlFreeHeap(ProcessHeap, 0, Full.Buffer);
    Status = STATUS_SUCCESS;
Exit:
    if (RootName) RtlFreeHeap(ProcessHeap, 0, RootName);
    return Status;
}

/************************************************************************
 *  CreateNestedKey
 *
 *  Create key and all necessary intermediate keys
 */
static NTSTATUS
CreateNestedKey(PHKEY KeyHandle,
                POBJECT_ATTRIBUTES ObjectAttributes,
                PUNICODE_STRING ClassString,
                DWORD dwOptions,
                REGSAM samDesired,
                DWORD *lpdwDisposition)
{
    OBJECT_ATTRIBUTES LocalObjectAttributes;
    UNICODE_STRING LocalKeyName;
    ULONG Disposition;
    NTSTATUS Status;
    ULONG FullNameLength;
    ULONG Length;
    PWCHAR Ptr;
    HANDLE LocalKeyHandle;
    REGSAM IntermediateAccess = KEY_CREATE_SUB_KEY | (samDesired & (KEY_WOW64_32KEY | KEY_WOW64_64KEY));

    Status = NtCreateKey((PHANDLE) KeyHandle,
                         samDesired,
                         ObjectAttributes,
                         0,
                         ClassString,
                         dwOptions,
                         (PULONG)lpdwDisposition);
    TRACE("NtCreateKey(%wZ) called (Status %lx)\n", ObjectAttributes->ObjectName, Status);
    if (Status != STATUS_OBJECT_NAME_NOT_FOUND)
        return Status;

    /* Copy object attributes */
    RtlCopyMemory(&LocalObjectAttributes,
                  ObjectAttributes,
                  sizeof(OBJECT_ATTRIBUTES));
    Status = GetSharedNestedKeyName(ObjectAttributes, samDesired, &LocalKeyName);
    if (!NT_SUCCESS(Status)) return Status;
    if (LocalKeyName.Buffer)
    {
        LocalObjectAttributes.RootDirectory = NULL;
        IntermediateAccess = KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY;
    }
    else if (!RtlCreateUnicodeString(&LocalKeyName, ObjectAttributes->ObjectName->Buffer))
        return STATUS_INSUFFICIENT_RESOURCES;
    LocalObjectAttributes.ObjectName = &LocalKeyName;
    Status = STATUS_OBJECT_NAME_NOT_FOUND;
    FullNameLength = LocalKeyName.Length / sizeof(WCHAR);

    LocalKeyHandle = NULL;

    /* Remove the last part of the key name and try to create the key again. */
    while (Status == STATUS_OBJECT_NAME_NOT_FOUND)
    {
        Ptr = wcsrchr(LocalKeyName.Buffer, '\\');
        if (Ptr == NULL || Ptr == LocalKeyName.Buffer)
        {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }

        *Ptr = (WCHAR)0;
        LocalKeyName.Length = (USHORT)wcslen(LocalKeyName.Buffer) * sizeof(WCHAR);

        Status = NtCreateKey(&LocalKeyHandle,
                             IntermediateAccess,
                             &LocalObjectAttributes,
                             0,
                             NULL,
                             0,
                             &Disposition);
        TRACE("NtCreateKey(%wZ) called (Status %lx)\n", &LocalKeyName, Status);
    }

    if (!NT_SUCCESS(Status))
    {
        RtlFreeUnicodeString(&LocalKeyName);
        return Status;
    }

    /* Add removed parts of the key name and create them too. */
    Length = wcslen(LocalKeyName.Buffer);
    while (TRUE)
    {
        if (LocalKeyHandle)
            NtClose (LocalKeyHandle);

        LocalKeyName.Buffer[Length] = L'\\';
        Length = wcslen (LocalKeyName.Buffer);
        LocalKeyName.Length = Length * sizeof(WCHAR);

        if (Length == FullNameLength)
        {
            Status = NtCreateKey((PHANDLE) KeyHandle,
                                 samDesired,
                                 ObjectAttributes,
                                 0,
                                 ClassString,
                                 dwOptions,
                                 (PULONG)lpdwDisposition);
            break;
        }

        Status = NtCreateKey(&LocalKeyHandle,
                             IntermediateAccess,
                             &LocalObjectAttributes,
                             0,
                             NULL,
                             0,
                             &Disposition);
        TRACE("NtCreateKey(%wZ) called (Status %lx)\n", &LocalKeyName, Status);
        if (!NT_SUCCESS(Status))
            break;
    }

    RtlFreeUnicodeString(&LocalKeyName);

    return Status;
}


/************************************************************************
 *  RegCreateKeyExA
 *
 * @implemented
 */
LONG WINAPI
RegCreateKeyExA(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ DWORD Reserved,
    _In_ LPSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_ LPDWORD lpdwDisposition)
{
    UNICODE_STRING SubKeyString;
    UNICODE_STRING ClassString;
    DWORD ErrorCode;

    RtlInitEmptyUnicodeString(&ClassString, NULL, 0);
    RtlInitEmptyUnicodeString(&SubKeyString, NULL, 0);

    if (lpClass)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&ClassString, lpClass))
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    if (lpSubKey)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&SubKeyString, lpSubKey))
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    ErrorCode = RegCreateKeyExW(
        hKey,
        SubKeyString.Buffer,
        Reserved,
        ClassString.Buffer,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition);

Exit:
    RtlFreeUnicodeString(&SubKeyString);
    RtlFreeUnicodeString(&ClassString);

    return ErrorCode;
}


/************************************************************************
 *  RegCreateKeyExW
 *
 * @implemented
 */
LONG
WINAPI
RegCreateKeyExW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ DWORD Reserved,
    _In_opt_ LPWSTR lpClass,
    _In_ DWORD dwOptions,
    _In_ REGSAM samDesired,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _Out_ PHKEY phkResult,
    _Out_opt_ LPDWORD lpdwDisposition)
{
    UNICODE_STRING SubKeyString;
    UNICODE_STRING ClassString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ParentKey;
    ULONG Attributes = OBJ_CASE_INSENSITIVE;
    NTSTATUS Status;

    TRACE("RegCreateKeyExW() called\n");

    /* get the real parent key */
    Status = MapDefaultKey(&ParentKey,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    TRACE("ParentKey %p\n", ParentKey);

    if (IsHKCRKey(ParentKey))
    {
        LONG ErrorCode = CreateHKCRKey(
            ParentKey,
            lpSubKey,
            Reserved,
            lpClass,
            dwOptions,
            samDesired,
            lpSecurityAttributes,
            phkResult,
            lpdwDisposition);
        ClosePredefKey(ParentKey);
        return ErrorCode;
    }

    if (dwOptions & REG_OPTION_OPEN_LINK)
        Attributes |= OBJ_OPENLINK;

    RtlInitUnicodeString(&ClassString,
                         lpClass);
    RtlInitUnicodeString(&SubKeyString,
                         lpSubKey);
    InitializeObjectAttributes(&ObjectAttributes,
                               &SubKeyString,
                               Attributes,
                               (HANDLE)ParentKey,
                               lpSecurityAttributes ? (PSECURITY_DESCRIPTOR)lpSecurityAttributes->lpSecurityDescriptor : NULL);
    Status = CreateNestedKey(phkResult,
                             &ObjectAttributes,
                             (lpClass == NULL)? NULL : &ClassString,
                             dwOptions,
                             samDesired,
                             lpdwDisposition);

    ClosePredefKey(ParentKey);

    TRACE("Status %x\n", Status);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegCreateKeyA
 *
 * @implemented
 */
LONG WINAPI
RegCreateKeyA(HKEY hKey,
              LPCSTR lpSubKey,
              PHKEY phkResult)
{
    return RegCreateKeyExA(hKey,
                           lpSubKey,
                           0,
                           NULL,
                           0,
                           MAXIMUM_ALLOWED,
                           NULL,
                           phkResult,
                           NULL);
}


/************************************************************************
 *  RegCreateKeyW
 *
 * @implemented
 */
LONG WINAPI
RegCreateKeyW(HKEY hKey,
              LPCWSTR lpSubKey,
              PHKEY phkResult)
{
    return RegCreateKeyExW(hKey,
                           lpSubKey,
                           0,
                           NULL,
                           0,
                           MAXIMUM_ALLOWED,
                           NULL,
                           phkResult,
                           NULL);
}


/************************************************************************
 *  RegDeleteKeyA
 *
 * @implemented
 */
LONG
WINAPI
RegDeleteKeyA(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey)
{
    return RegDeleteKeyExA(hKey, lpSubKey, 0, 0);
}


/************************************************************************
 *  RegDeleteKeyW
 *
 * @implemented
 */
LONG
WINAPI
RegDeleteKeyW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey)
{
    return RegDeleteKeyExW(hKey, lpSubKey, 0, 0);
}


/************************************************************************
 *  RegDeleteKeyExA
 *
 * @implemented
 */
LONG
WINAPI
RegDeleteKeyExA(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ REGSAM samDesired,
    _In_ DWORD Reserved)
{
    LONG ErrorCode;
    UNICODE_STRING SubKeyName;

    if (lpSubKey)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&SubKeyName, lpSubKey))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
        RtlInitEmptyUnicodeString(&SubKeyName, NULL, 0);

    ErrorCode = RegDeleteKeyExW(hKey, SubKeyName.Buffer, samDesired, Reserved);

    RtlFreeUnicodeString(&SubKeyName);

    return ErrorCode;
}


/************************************************************************
 *  RegDeleteKeyExW
 *
 * @implemented
 */
LONG
WINAPI
RegDeleteKeyExW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpSubKey,
    _In_ REGSAM samDesired,
    _In_ DWORD Reserved)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING SubKeyName;
    HANDLE ParentKey;
    HANDLE TargetKey;
    NTSTATUS Status;

    /* Make sure we got a subkey */
    if (!lpSubKey)
    {
        /* Fail */
        return ERROR_INVALID_PARAMETER;
    }

    Status = MapDefaultKey(&ParentKey,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (IsHKCRKey(ParentKey))
    {
        LONG ErrorCode = DeleteHKCRKey(ParentKey, lpSubKey, samDesired, Reserved);
        ClosePredefKey(ParentKey);
        return ErrorCode;
    }

    RtlInitUnicodeString(&SubKeyName, lpSubKey);
    InitializeObjectAttributes(&ObjectAttributes,
                               &SubKeyName,
                               OBJ_CASE_INSENSITIVE,
                               ParentKey,
                               NULL);
    Status = NtOpenKey(&TargetKey,
                       DELETE | (samDesired & KEY_WOW64_RES),
                       &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

    Status = NtDeleteKey(TargetKey);
    NtClose(TargetKey);

Cleanup:
    ClosePredefKey(ParentKey);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegDeleteKeyValueW
 *
 * @implemented
 */
LONG WINAPI
RegDeleteKeyValueW(IN HKEY hKey,
                   IN LPCWSTR lpSubKey  OPTIONAL,
                   IN LPCWSTR lpValueName  OPTIONAL)
{
    HKEY hSubKey = hKey;
    LONG ErrorCode;

    if (lpSubKey)
    {
        ErrorCode = RegOpenKeyExW(hKey, lpSubKey, 0, KEY_SET_VALUE, &hSubKey);
        if (ErrorCode)
        {
            return ErrorCode;
        }
    }
    ErrorCode = RegDeleteValueW(hSubKey, lpValueName);

    if (hSubKey != hKey)
    {
        RegCloseKey(hSubKey);
    }
    return ErrorCode;
}


/************************************************************************
 *  RegDeleteKeyValueA
 *
 * @implemented
 */
LONG WINAPI
RegDeleteKeyValueA(IN HKEY hKey,
                   IN LPCSTR lpSubKey  OPTIONAL,
                   IN LPCSTR lpValueName  OPTIONAL)
{
    UNICODE_STRING SubKey = { 0, 0, NULL }, ValueName = { 0, 0, NULL };
    LONG Ret;

    if (lpSubKey != NULL &&
        !RtlCreateUnicodeStringFromAsciiz(&SubKey, lpSubKey))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (lpValueName != NULL &&
        !RtlCreateUnicodeStringFromAsciiz(&ValueName, lpValueName))
    {
        RtlFreeUnicodeString(&SubKey);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    Ret = RegDeleteKeyValueW(hKey,
                             SubKey.Buffer,
                             ValueName.Buffer);

    RtlFreeUnicodeString(&SubKey);
    RtlFreeUnicodeString(&ValueName);

    return Ret;
}

#if 0
// Non-recursive RegDeleteTreeW implementation by Thomas, however it needs bugfixing
static NTSTATUS
RegpDeleteTree(IN HKEY hKey)
{
    typedef struct
    {
        LIST_ENTRY ListEntry;
        HANDLE KeyHandle;
    } REGP_DEL_KEYS, *PREG_DEL_KEYS;

    LIST_ENTRY delQueueHead;
    PREG_DEL_KEYS delKeys, newDelKeys;
    HANDLE ProcessHeap;
    ULONG BufferSize;
    PKEY_BASIC_INFORMATION BasicInfo;
    PREG_DEL_KEYS KeyDelRoot;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS Status2 = STATUS_SUCCESS;

    InitializeListHead(&delQueueHead);

    ProcessHeap = RtlGetProcessHeap();

    /* NOTE: no need to allocate enough memory for an additional KEY_BASIC_INFORMATION
             structure for the root key, we only do that for subkeys as we need to
             allocate REGP_DEL_KEYS structures anyway! */
    KeyDelRoot = RtlAllocateHeap(ProcessHeap,
                                 0,
                                 sizeof(REGP_DEL_KEYS));
    if (KeyDelRoot != NULL)
    {
        KeyDelRoot->KeyHandle = hKey;
        InsertTailList(&delQueueHead,
                       &KeyDelRoot->ListEntry);

        do
        {
            delKeys = CONTAINING_RECORD(delQueueHead.Flink,
                                        REGP_DEL_KEYS,
                                        ListEntry);

            BufferSize = 0;
            BasicInfo = NULL;
            newDelKeys = NULL;

ReadFirstSubKey:
            /* check if this key contains subkeys and delete them first by queuing
               them at the head of the list */
            Status2 = NtEnumerateKey(delKeys->KeyHandle,
                                     0,
                                     KeyBasicInformation,
                                     BasicInfo,
                                     BufferSize,
                                     &BufferSize);

            if (NT_SUCCESS(Status2))
            {
                OBJECT_ATTRIBUTES ObjectAttributes;
                UNICODE_STRING SubKeyName;

                ASSERT(newDelKeys != NULL);
                ASSERT(BasicInfo != NULL);

                /* don't use RtlInitUnicodeString as the string is not NULL-terminated! */
                SubKeyName.Length = BasicInfo->NameLength;
                SubKeyName.MaximumLength = BasicInfo->NameLength;
                SubKeyName.Buffer = BasicInfo->Name;

                InitializeObjectAttributes(&ObjectAttributes,
                                           &SubKeyName,
                                           OBJ_CASE_INSENSITIVE,
                                           delKeys->KeyHandle,
                                           NULL);

                /* open the subkey */
                Status2 = NtOpenKey(&newDelKeys->KeyHandle,
                                    DELETE | KEY_ENUMERATE_SUB_KEYS,
                                    &ObjectAttributes);
                if (!NT_SUCCESS(Status2))
                {
                    goto SubKeyFailure;
                }

                /* enqueue this key to the head of the deletion queue */
                InsertHeadList(&delQueueHead,
                               &newDelKeys->ListEntry);

                /* try again from the head of the list */
                continue;
            }
            else
            {
                if (Status2 == STATUS_BUFFER_TOO_SMALL)
                {
                    newDelKeys = RtlAllocateHeap(ProcessHeap,
                                                 0,
                                                 BufferSize + sizeof(REGP_DEL_KEYS));
                    if (newDelKeys != NULL)
                    {
                        BasicInfo = (PKEY_BASIC_INFORMATION)(newDelKeys + 1);

                        /* try again */
                        goto ReadFirstSubKey;
                    }
                    else
                    {
                        /* don't break, let's try to delete as many keys as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                        goto SubKeyFailureNoFree;
                    }
                }
                else if (Status2 == STATUS_BUFFER_OVERFLOW)
                {
                    PREG_DEL_KEYS newDelKeys2;

                    ASSERT(newDelKeys != NULL);

                    /* we need more memory to query the key name */
                    newDelKeys2 = RtlReAllocateHeap(ProcessHeap,
                                                    0,
                                                    newDelKeys,
                                                    BufferSize + sizeof(REGP_DEL_KEYS));
                    if (newDelKeys2 != NULL)
                    {
                        newDelKeys = newDelKeys2;
                        BasicInfo = (PKEY_BASIC_INFORMATION)(newDelKeys + 1);

                        /* try again */
                        goto ReadFirstSubKey;
                    }
                    else
                    {
                        /* don't break, let's try to delete as many keys as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
                else if (Status2 == STATUS_NO_MORE_ENTRIES)
                {
                    /* in some race conditions where another thread would delete
                       the same tree at the same time, newDelKeys could actually
                       be != NULL! */
                    if (newDelKeys != NULL)
                    {
                        RtlFreeHeap(ProcessHeap,
                                    0,
                                    newDelKeys);
                    }
                    break;
                }

SubKeyFailure:
                /* newDelKeys can be NULL here when NtEnumerateKey returned an
                   error other than STATUS_BUFFER_TOO_SMALL or STATUS_BUFFER_OVERFLOW! */
                if (newDelKeys != NULL)
                {
                    RtlFreeHeap(ProcessHeap,
                                0,
                                newDelKeys);
                }

SubKeyFailureNoFree:
                /* don't break, let's try to delete as many keys as possible */
                if (NT_SUCCESS(Status))
                {
                    Status = Status2;
                }
            }

            Status2 = NtDeleteKey(delKeys->KeyHandle);

            /* NOTE: do NOT close the handle anymore, it's invalid already! */

            if (!NT_SUCCESS(Status2))
            {
                /* close the key handle so we don't leak handles for keys we were
                   unable to delete. But only do this for handles not supplied
                   by the caller! */

                if (delKeys->KeyHandle != hKey)
                {
                    NtClose(delKeys->KeyHandle);
                }

                if (NT_SUCCESS(Status))
                {
                    /* don't break, let's try to delete as many keys as possible */
                    Status = Status2;
                }
            }

            /* remove the entry from the list */
            RemoveEntryList(&delKeys->ListEntry);

            RtlFreeHeap(ProcessHeap,
                        0,
                        delKeys);
        } while (!IsListEmpty(&delQueueHead));
    }
    else
        Status = STATUS_INSUFFICIENT_RESOURCES;

    return Status;
}


/************************************************************************
 *  RegDeleteTreeW
 *
 * @implemented
 */
LONG WINAPI
RegDeleteTreeW(IN HKEY hKey,
               IN LPCWSTR lpSubKey  OPTIONAL)
{
    HANDLE KeyHandle, CurKey, SubKeyHandle = NULL;
    NTSTATUS Status;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (lpSubKey != NULL)
    {
        OBJECT_ATTRIBUTES ObjectAttributes;
        UNICODE_STRING SubKeyName;

        RtlInitUnicodeString(&SubKeyName, lpSubKey);

        InitializeObjectAttributes(&ObjectAttributes,
                                   &SubKeyName,
                                   OBJ_CASE_INSENSITIVE,
                                   KeyHandle,
                                   NULL);

        Status = NtOpenKey(&SubKeyHandle,
                           DELETE | KEY_ENUMERATE_SUB_KEYS,
                           &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            goto Cleanup;
        }

        CurKey = SubKeyHandle;
    }
    else
        CurKey = KeyHandle;

    Status = RegpDeleteTree(CurKey);

    if (NT_SUCCESS(Status))
    {
        /* make sure we only close hKey (KeyHandle) when the caller specified a
           subkey, because the handle would be invalid already! */
        if (CurKey != KeyHandle)
        {
            ClosePredefKey(KeyHandle);
        }

        return ERROR_SUCCESS;
    }
    else
    {
        /* make sure we close all handles we created! */
        if (SubKeyHandle != NULL)
        {
            NtClose(SubKeyHandle);
        }

Cleanup:
        ClosePredefKey(KeyHandle);

        return RtlNtStatusToDosError(Status);
    }
}
#endif

#endif // _ADVAPI32_VISTA_

/************************************************************************
 *  RegDeleteTreeW
 *
 * @implemented
 */
LSTATUS
WINAPI
RegDeleteTreeW(HKEY hKey,
               LPCWSTR lpszSubKey)
{
    LONG ret;
    DWORD dwMaxSubkeyLen, dwMaxValueLen;
    DWORD dwMaxLen, dwSize;
    NTSTATUS Status;
    HANDLE KeyHandle;
    HKEY hSubKey;
    WCHAR szNameBuf[MAX_PATH], *lpszName = szNameBuf;

    TRACE("(hkey=%p,%p %s)\n", hKey, lpszSubKey, debugstr_w(lpszSubKey));

    /* An empty subkey name means hKey itself, same as NULL: its subkeys and
     * values are deleted and the key stays. Windows does not delete hKey here;
     * callers such as .NET RegistryKey.DeleteSubKeyTree delete it afterwards
     * with RegDeleteKeyEx(hKey, ""), which fails if the key is already gone. */
    if (lpszSubKey && !*lpszSubKey)
        lpszSubKey = NULL;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    hSubKey = KeyHandle;

    if(lpszSubKey)
    {
        ret = RegOpenKeyExW(KeyHandle, lpszSubKey, 0, KEY_READ, &hSubKey);
        if (ret)
        {
            ClosePredefKey(KeyHandle);
            return ret;
        }
    }

    /* Get highest length for keys, values */
    ret = RegQueryInfoKeyW(hSubKey, NULL, NULL, NULL, NULL,
            &dwMaxSubkeyLen, NULL, NULL, &dwMaxValueLen, NULL, NULL, NULL);
    if (ret) goto cleanup;

    dwMaxSubkeyLen++;
    dwMaxValueLen++;
    dwMaxLen = max(dwMaxSubkeyLen, dwMaxValueLen);
    if (dwMaxLen > sizeof(szNameBuf)/sizeof(WCHAR))
    {
        /* Name too big: alloc a buffer for it */
        if (!(lpszName = RtlAllocateHeap( RtlGetProcessHeap(), 0, dwMaxLen*sizeof(WCHAR))))
        {
            ret = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }
    }


    /* Recursively delete all the subkeys */
    while (TRUE)
    {
        dwSize = dwMaxLen;
        if (RegEnumKeyExW(hSubKey, 0, lpszName, &dwSize, NULL,
                          NULL, NULL, NULL)) break;

        ret = RegDeleteTreeW(hSubKey, lpszName);
        if (ret) goto cleanup;
    }

    if (lpszSubKey)
        ret = RegDeleteKeyW(KeyHandle, lpszSubKey);
    else
        while (TRUE)
        {
            dwSize = dwMaxLen;
            if (RegEnumValueW(KeyHandle, 0, lpszName, &dwSize,
                  NULL, NULL, NULL, NULL)) break;

            ret = RegDeleteValueW(KeyHandle, lpszName);
            if (ret) goto cleanup;
        }

cleanup:
    /* Free buffer if allocated */
    if (lpszName != szNameBuf)
        RtlFreeHeap( RtlGetProcessHeap(), 0, lpszName);
    if(lpszSubKey)
        RegCloseKey(hSubKey);

    ClosePredefKey(KeyHandle);

    return ret;
}


/************************************************************************
 *  RegDeleteTreeA
 *
 * @implemented
 */
LONG WINAPI
RegDeleteTreeA(IN HKEY hKey,
               IN LPCSTR lpSubKey  OPTIONAL)
{
    UNICODE_STRING SubKeyName = { 0, 0, NULL };
    LONG Ret;

    if (lpSubKey != NULL &&
        !RtlCreateUnicodeStringFromAsciiz(&SubKeyName, lpSubKey))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    Ret = RegDeleteTreeW(hKey,
                         SubKeyName.Buffer);

    RtlFreeUnicodeString(&SubKeyName);

    return Ret;
}

#ifndef _ADVAPI32_VISTA_

/************************************************************************
 *  RegDisableReflectionKey
 *
 * @unimplemented
 */
LONG WINAPI
RegDisableReflectionKey(IN HKEY hBase)
{
    FIXME("RegDisableReflectionKey(0x%p) UNIMPLEMENTED!\n", hBase);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/************************************************************************
 *  RegEnableReflectionKey
 *
 * @unimplemented
 */
LONG WINAPI
RegEnableReflectionKey(IN HKEY hBase)
{
    FIXME("RegEnableReflectionKey(0x%p) UNIMPLEMENTED!\n", hBase);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/******************************************************************************
 * RegpApplyRestrictions   [internal]
 *
 * Helper function for RegGetValueA/W.
 */
static VOID
RegpApplyRestrictions(DWORD dwFlags,
                      DWORD dwType,
                      DWORD cbData,
                      PLONG ret)
{
    /* Check if the type is restricted by the passed flags */
    if (*ret == ERROR_SUCCESS || *ret == ERROR_MORE_DATA)
    {
        DWORD dwMask = 0;

        switch (dwType)
        {
        case REG_NONE: dwMask = RRF_RT_REG_NONE; break;
        case REG_SZ: dwMask = RRF_RT_REG_SZ; break;
        case REG_EXPAND_SZ: dwMask = RRF_RT_REG_EXPAND_SZ; break;
        case REG_MULTI_SZ: dwMask = RRF_RT_REG_MULTI_SZ; break;
        case REG_BINARY: dwMask = RRF_RT_REG_BINARY; break;
        case REG_DWORD: dwMask = RRF_RT_REG_DWORD; break;
        case REG_QWORD: dwMask = RRF_RT_REG_QWORD; break;
        }

        if (dwFlags & dwMask)
        {
            /* Type is not restricted, check for size mismatch */
            if (dwType == REG_BINARY)
            {
                DWORD cbExpect = 0;

                if ((dwFlags & RRF_RT_ANY) == RRF_RT_DWORD)
                    cbExpect = 4;
                else if ((dwFlags & RRF_RT_ANY) == RRF_RT_QWORD)
                    cbExpect = 8;

                if (cbExpect && cbData != cbExpect)
                    *ret = ERROR_DATATYPE_MISMATCH;
            }
        }
        else *ret = ERROR_UNSUPPORTED_TYPE;
    }
}


/******************************************************************************
 * RegpReadWholeValue   [internal]
 *
 * Helper function for RegGetValueA/W. Reads the whole value into a new heap
 * buffer that has cbSpare bytes after the data, so a string can be terminated
 * in place.
 */
static LONG
RegpReadWholeValue(HKEY hKey,
                   LPCWSTR pszValue,
                   DWORD cbSpare,
                   LPDWORD pdwType,
                   PBYTE *ppData,
                   LPDWORD pcbData)
{
    PBYTE pData = NULL;
    DWORD cbAlloc = 0, cbNeed = 0, cbData = 0;
    LONG ret;

    ret = RegQueryValueExW(hKey, pszValue, NULL, pdwType, NULL, &cbNeed);

    /* The value can change between the calls. The capacity only grows, so
     * this ends once the buffer is as large as the largest size seen. */
    while (ret == ERROR_SUCCESS)
    {
        if (!pData || cbNeed > cbAlloc)
        {
            if (cbNeed > MAXDWORD - cbSpare)
            {
                ret = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }

            HeapFree(GetProcessHeap(), 0, pData);
            pData = HeapAlloc(GetProcessHeap(), 0, cbNeed + cbSpare);
            if (!pData)
            {
                ret = ERROR_NOT_ENOUGH_MEMORY;
                break;
            }
            cbAlloc = cbNeed;
        }

        cbData = cbAlloc;
        ret = RegQueryValueExW(hKey, pszValue, NULL, pdwType, pData, &cbData);
        if (ret != ERROR_MORE_DATA)
            break;

        cbNeed = max(cbData, cbAlloc + 1);
        ret = ERROR_SUCCESS;
    }

    if (ret != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, pData);
        *ppData = NULL;
        return ret;
    }

    *ppData = pData;
    *pcbData = cbData;
    return ret;
}


/******************************************************************************
 * RegpTerminatedSize   [internal]
 *
 * Helper function for RegGetValueA/W. Returns the size a Unicode string value
 * has once it is terminated: a partial last character is dropped, as Windows
 * does, and missing terminators are added (two for REG_MULTI_SZ). The
 * terminated string is the whole characters of the value followed by zero
 * bytes up to that size.
 */
static DWORD
RegpTerminatedSize(DWORD dwType,
                   const BYTE *pData,
                   DWORD cbData)
{
    DWORD cchData = cbData / sizeof(WCHAR);
    DWORD cchNul = (dwType == REG_MULTI_SZ) ? 2 : 1;
    DWORD cchHave = 0;
    const BYTE *pChar;

    /* Count the terminators that are already there; the buffer need not be
     * aligned */
    while (cchHave < cchNul && cchHave < cchData)
    {
        pChar = pData + (cchData - 1 - cchHave) * sizeof(WCHAR);
        if (pChar[0] || pChar[1])
            break;
        cchHave++;
    }

    return (cchData + cchNul - cchHave) * sizeof(WCHAR);
}


/******************************************************************************
 * RegpExpandString   [internal]
 *
 * Helper function for RegGetValueA/W. Expands a terminated Unicode string into
 * a new heap buffer and returns its size in bytes, including the terminator.
 */
static LONG
RegpExpandString(LPCWSTR pszSource,
                 LPWSTR *ppszExpanded,
                 LPDWORD pcbExpanded)
{
    LPWSTR pszExpanded = NULL;
    DWORD cchAlloc = 0, cch;
    LONG ret = ERROR_SUCCESS;

    /* ExpandEnvironmentStrings silently truncates a longer source, and above
     * the output length below it can return a size that fits the buffer for
     * a truncated, unterminated result */
    if (wcslen(pszSource) > (UNICODE_STRING_MAX_BYTES - sizeof(UNICODE_NULL)) / sizeof(WCHAR))
    {
        *ppszExpanded = NULL;
        *pcbExpanded = 0;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    cch = ExpandEnvironmentStringsW(pszSource, NULL, 0);

    /* The environment can change between the calls, so repeat until it fits */
    for (;;)
    {
        if (!cch)
        {
            ret = GetLastError();
            if (ret == ERROR_SUCCESS)
                ret = ERROR_INVALID_DATA;
            break;
        }

        if (cch > UNICODE_STRING_MAX_CHARS - 2)
        {
            ret = ERROR_INSUFFICIENT_BUFFER;
            break;
        }

        if (cch <= cchAlloc)
            break;

        HeapFree(GetProcessHeap(), 0, pszExpanded);
        cchAlloc = cch;
        pszExpanded = HeapAlloc(GetProcessHeap(), 0, cchAlloc * sizeof(WCHAR));
        if (!pszExpanded)
        {
            ret = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }

        cch = ExpandEnvironmentStringsW(pszSource, pszExpanded, cchAlloc);
    }

    if (ret != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, pszExpanded);
        pszExpanded = NULL;
        cch = 0;
    }

    *ppszExpanded = pszExpanded;
    *pcbExpanded = cch * sizeof(WCHAR);
    return ret;
}


/******************************************************************************
 * RegpGetValueCommon   [internal]
 *
 * Implementation of RegGetValueA/W. The caller has already opened the subkey.
 * bAnsi selects ANSI output for string values.
 */
static LONG
RegpGetValueCommon(HKEY hKey,
                   LPCWSTR pszValue,
                   BOOL bAnsi,
                   DWORD dwFlags,
                   LPDWORD pdwType,
                   PVOID pvData,
                   LPDWORD pcbData)
{
    DWORD dwType = REG_NONE, cbBuffer = (pvData && pcbData) ? *pcbData : 0;
    DWORD cbData = cbBuffer, cbOut;
    PBYTE pRaw = NULL;
    LPWSTR pszExpanded = NULL;
    PVOID pOut;
    LONG ret = ERROR_SUCCESS;

    /* Unicode output writes a value that needs no further work in place */
    if (!bAnsi)
    {
        ret = RegQueryValueExW(hKey, pszValue, NULL, &dwType, pvData, &cbData);
        if ((ret != ERROR_SUCCESS && ret != ERROR_MORE_DATA) || !is_string(dwType))
            goto Quit;

        if (ret == ERROR_SUCCESS && pvData &&
            (dwType != REG_EXPAND_SZ || (dwFlags & RRF_NOEXPAND)) &&
            RegpTerminatedSize(dwType, pvData, cbData) == cbData)
        {
            goto Quit;
        }
    }

    if (!pcbData)
    {
        /* Nothing to return but the type, which is REG_SZ after expansion */
        if (bAnsi)
            ret = RegQueryValueExW(hKey, pszValue, NULL, &dwType, NULL, &cbData);
        if (ret == ERROR_SUCCESS && dwType == REG_EXPAND_SZ && !(dwFlags & RRF_NOEXPAND))
            dwType = REG_SZ;
        goto Quit;
    }

    /* Otherwise take the whole value, terminate it, expand it if needed, and
     * copy it to the caller's buffer only if all of it fits */
    if (!bAnsi && ret == ERROR_SUCCESS && pvData)
    {
        /* The value is already in the caller's buffer, which can also hold
         * the value name: work on a copy instead of reading it again */
        if (cbData <= MAXDWORD - 2 * sizeof(WCHAR))
            pRaw = HeapAlloc(GetProcessHeap(), 0, cbData + 2 * sizeof(WCHAR));
        if (!pRaw)
        {
            ret = ERROR_NOT_ENOUGH_MEMORY;
            goto Quit;
        }
        CopyMemory(pRaw, pvData, cbData);
    }
    else
    {
        ret = RegpReadWholeValue(hKey, pszValue, 2 * sizeof(WCHAR), &dwType, &pRaw, &cbData);
        if (ret != ERROR_SUCCESS)
            goto Quit;
    }

    pOut = pRaw;
    cbOut = cbData;
    if (is_string(dwType))
    {
        DWORD cbWhole = cbData - cbData % sizeof(WCHAR);

        cbOut = RegpTerminatedSize(dwType, pRaw, cbData);
        ZeroMemory(pRaw + cbWhole, cbOut - cbWhole);

        if (dwType == REG_EXPAND_SZ && !(dwFlags & RRF_NOEXPAND))
        {
            ret = RegpExpandString((LPCWSTR)pRaw, &pszExpanded, &cbOut);
            if (ret != ERROR_SUCCESS)
                goto Quit;
            pOut = pszExpanded;
            dwType = REG_SZ;
        }

        if (bAnsi)
        {
            DWORD cbAnsi;

            /* The terminators convert to zero bytes */
            RtlUnicodeToMultiByteSize(&cbAnsi, pOut, cbOut);
            if (pvData && cbAnsi <= cbBuffer)
                RtlUnicodeToMultiByteN(pvData, cbBuffer, NULL, pOut, cbOut);
            else if (pvData)
                ret = ERROR_MORE_DATA;

            /* Windows asks one byte more for an expanded ANSI string, as
             * ExpandEnvironmentStringsA does */
            if (pszExpanded && (!pvData || ret == ERROR_MORE_DATA))
                cbAnsi++;

            cbData = cbAnsi;
            goto Quit;
        }
    }

    if (pvData)
    {
        if (cbOut > cbBuffer)
            ret = ERROR_MORE_DATA;
        else
            CopyMemory(pvData, pOut, cbOut);
    }
    cbData = cbOut;

Quit:
    HeapFree(GetProcessHeap(), 0, pszExpanded);
    HeapFree(GetProcessHeap(), 0, pRaw);

    RegpApplyRestrictions(dwFlags, dwType, cbData, &ret);

    if (pvData && ret != ERROR_SUCCESS && (dwFlags & RRF_ZEROONFAILURE))
        ZeroMemory(pvData, cbBuffer);

    if (pdwType)
        *pdwType = dwType;

    if (pcbData)
        *pcbData = cbData;

    return ret;
}


/******************************************************************************
 * RegGetValueW   [ADVAPI32.@]
 *
 * Retrieves the type and data for a value name associated with a key,
 * optionally expanding its content and restricting its type.
 *
 * PARAMS
 *  hKey      [I] Handle to an open key.
 *  pszSubKey [I] Name of the subkey of hKey.
 *  pszValue  [I] Name of value under hKey/szSubKey to query.
 *  dwFlags   [I] Flags restricting the value type to retrieve.
 *  pdwType   [O] Destination for the values type, may be NULL.
 *  pvData    [O] Destination for the values content, may be NULL.
 *  pcbData   [I/O] Size of pvData, updated with the size in bytes required to
 *                  retrieve the whole content, including the trailing '\0'
 *                  for strings.
 *
 * RETURNS
 *  Success: ERROR_SUCCESS
 *  Failure: nonzero error code from Winerror.h
 *
 * NOTES
 *  - Unless RRF_NOEXPAND is specified, REG_EXPAND_SZ values are automatically
 *    expanded and pdwType is set to REG_SZ instead.
 *  - Restrictions are applied after expanding: RRF_RT_REG_EXPAND_SZ without
 *    RRF_NOEXPAND does not match an expanded value (ERROR_UNSUPPORTED_TYPE,
 *    as Windows 8 and later), but combined with RRF_RT_REG_SZ it is accepted,
 *    also without a data buffer: the size needed after expansion is returned.
 *  - Strings are always returned terminated (REG_MULTI_SZ with two
 *    terminators); the terminators are counted in pcbData. A string is copied
 *    to pvData only if all of it fits.
 */
LSTATUS WINAPI
RegGetValueW(HKEY hKey,
             LPCWSTR pszSubKey,
             LPCWSTR pszValue,
             DWORD dwFlags,
             LPDWORD pdwType,
             PVOID pvData,
             LPDWORD pcbData)
{
    /* The result can overwrite pszSubKey, so decide about closing now */
    BOOL bSubKey = (pszSubKey && pszSubKey[0]);
    LONG ret;

    TRACE("(%p,%s,%s,%ld,%p,%p,%p=%ld)\n",
          hKey, debugstr_w(pszSubKey), debugstr_w(pszValue), dwFlags, pdwType,
          pvData, pcbData, pcbData ? *pcbData : 0);

    if (pvData && !pcbData)
        return ERROR_INVALID_PARAMETER;

    if (bSubKey)
    {
        ret = RegOpenKeyExW(hKey, pszSubKey, 0, KEY_QUERY_VALUE, &hKey);
        if (ret != ERROR_SUCCESS) return ret;
    }

    ret = RegpGetValueCommon(hKey, pszValue, FALSE, dwFlags, pdwType, pvData, pcbData);

    if (bSubKey)
        RegCloseKey(hKey);

    return ret;
}


/******************************************************************************
 * RegGetValueA   [ADVAPI32.@]
 *
 * See RegGetValueW.
 */
LSTATUS WINAPI
RegGetValueA(HKEY hKey,
             LPCSTR pszSubKey,
             LPCSTR pszValue,
             DWORD dwFlags,
             LPDWORD pdwType,
             PVOID pvData,
             LPDWORD pcbData)
{
    /* The result can overwrite pszSubKey, so decide about closing now */
    BOOL bSubKey = (pszSubKey && pszSubKey[0]);
    UNICODE_STRING ValueName;
    LONG ret;

    TRACE("(%p,%s,%s,%ld,%p,%p,%p=%ld)\n",
          hKey, pszSubKey, pszValue, dwFlags, pdwType, pvData, pcbData,
          pcbData ? *pcbData : 0);

    if (pvData && !pcbData)
        return ERROR_INVALID_PARAMETER;

    if (pszValue)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&ValueName, pszValue))
        {
            if (pvData && (dwFlags & RRF_ZEROONFAILURE))
                ZeroMemory(pvData, *pcbData);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }
    else
        RtlInitEmptyUnicodeString(&ValueName, NULL, 0);

    if (bSubKey)
    {
        ret = RegOpenKeyExA(hKey, pszSubKey, 0, KEY_QUERY_VALUE, &hKey);
        if (ret != ERROR_SUCCESS)
        {
            RtlFreeUnicodeString(&ValueName);
            return ret;
        }
    }

    ret = RegpGetValueCommon(hKey, ValueName.Buffer, TRUE, dwFlags, pdwType, pvData, pcbData);

    if (bSubKey)
        RegCloseKey(hKey);

    RtlFreeUnicodeString(&ValueName);
    return ret;
}

#endif // _ADVAPI32_VISTA_

/************************************************************************
 *  RegSetKeyValueW
 *
 * @implemented
 */
LONG WINAPI
RegSetKeyValueW(IN HKEY hKey,
                IN LPCWSTR lpSubKey  OPTIONAL,
                IN LPCWSTR lpValueName  OPTIONAL,
                IN DWORD dwType,
                IN LPCVOID lpData  OPTIONAL,
                IN DWORD cbData)
{
    HANDLE KeyHandle, CurKey, SubKeyHandle = NULL;
    NTSTATUS Status;
    LONG Ret;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (lpSubKey != NULL)
    {
        OBJECT_ATTRIBUTES ObjectAttributes;
        UNICODE_STRING SubKeyName;

        RtlInitUnicodeString(&SubKeyName, lpSubKey);

        InitializeObjectAttributes(&ObjectAttributes,
                                   &SubKeyName,
                                   OBJ_CASE_INSENSITIVE,
                                   KeyHandle,
                                   NULL);

        Status = NtOpenKey(&SubKeyHandle,
                           KEY_SET_VALUE,
                           &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            Ret = RtlNtStatusToDosError(Status);
            goto Cleanup;
        }

        CurKey = SubKeyHandle;
    }
    else
        CurKey = KeyHandle;

    Ret = RegSetValueExW(CurKey,
                         lpValueName,
                         0,
                         dwType,
                         lpData,
                         cbData);

    if (SubKeyHandle != NULL)
    {
        NtClose(SubKeyHandle);
    }

Cleanup:
    ClosePredefKey(KeyHandle);

    return Ret;
}

#ifndef _ADVAPI32_VISTA_

/************************************************************************
 *  RegSetKeyValueA
 *
 * @implemented
 */
LONG WINAPI
RegSetKeyValueA(IN HKEY hKey,
                IN LPCSTR lpSubKey  OPTIONAL,
                IN LPCSTR lpValueName  OPTIONAL,
                IN DWORD dwType,
                IN LPCVOID lpData  OPTIONAL,
                IN DWORD cbData)
{
    HANDLE KeyHandle, CurKey, SubKeyHandle = NULL;
    NTSTATUS Status;
    LONG Ret;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (lpSubKey != NULL)
    {
        OBJECT_ATTRIBUTES ObjectAttributes;
        UNICODE_STRING SubKeyName;

        if (!RtlCreateUnicodeStringFromAsciiz(&SubKeyName, lpSubKey))
        {
            Ret = ERROR_NOT_ENOUGH_MEMORY;
            goto Cleanup;
        }

        InitializeObjectAttributes(&ObjectAttributes,
                                   &SubKeyName,
                                   OBJ_CASE_INSENSITIVE,
                                   KeyHandle,
                                   NULL);

        Status = NtOpenKey(&SubKeyHandle,
                           KEY_SET_VALUE,
                           &ObjectAttributes);

        RtlFreeUnicodeString(&SubKeyName);

        if (!NT_SUCCESS(Status))
        {
            Ret = RtlNtStatusToDosError(Status);
            goto Cleanup;
        }

        CurKey = SubKeyHandle;
    }
    else
        CurKey = KeyHandle;

    Ret = RegSetValueExA(CurKey,
                         lpValueName,
                         0,
                         dwType,
                         lpData,
                         cbData);

    if (SubKeyHandle != NULL)
    {
        NtClose(SubKeyHandle);
    }

Cleanup:
    ClosePredefKey(KeyHandle);

    return Ret;
}


/************************************************************************
 *  RegDeleteValueA
 *
 * @implemented
 */
LONG WINAPI
RegDeleteValueA(HKEY hKey,
                LPCSTR lpValueName)
{
    UNICODE_STRING ValueName;
    HANDLE KeyHandle;
    NTSTATUS Status;
    LONG ErrorCode = ERROR_SUCCESS;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (!RtlCreateUnicodeStringFromAsciiz(&ValueName, lpValueName))
    {
        ClosePredefKey(KeyHandle);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (IsHKCRKey(KeyHandle))
    {
        ErrorCode = DeleteHKCRValue(KeyHandle, &ValueName);
    }
    else
    {
        Status = NtDeleteValueKey(KeyHandle, &ValueName);
        if (!NT_SUCCESS(Status))
            ErrorCode = RtlNtStatusToDosError(Status);
    }
    RtlFreeUnicodeString(&ValueName);
    ClosePredefKey(KeyHandle);
    return ErrorCode;
}


/************************************************************************
 *  RegDeleteValueW
 *
 * @implemented
 */
LONG WINAPI
RegDeleteValueW(HKEY hKey,
                LPCWSTR lpValueName)
{
    UNICODE_STRING ValueName;
    NTSTATUS Status;
    HANDLE KeyHandle;
    LONG ErrorCode = ERROR_SUCCESS;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    RtlInitUnicodeString(&ValueName, lpValueName);

    if (IsHKCRKey(KeyHandle))
    {
        ErrorCode = DeleteHKCRValue(KeyHandle, &ValueName);
    }
    else
    {
        Status = NtDeleteValueKey(KeyHandle, &ValueName);
        if (!NT_SUCCESS(Status))
            ErrorCode = RtlNtStatusToDosError(Status);
    }
    ClosePredefKey(KeyHandle);
    return ErrorCode;
}


/************************************************************************
 *  RegEnumKeyA
 *
 * @implemented
 */
LONG WINAPI
RegEnumKeyA(HKEY hKey,
            DWORD dwIndex,
            LPSTR lpName,
            DWORD cbName)
{
    DWORD dwLength;

    dwLength = cbName;
    return RegEnumKeyExA(hKey,
                         dwIndex,
                         lpName,
                         &dwLength,
                         NULL,
                         NULL,
                         NULL,
                         NULL);
}


/************************************************************************
 *  RegEnumKeyW
 *
 * @implemented
 */
LONG WINAPI
RegEnumKeyW(HKEY hKey,
            DWORD dwIndex,
            LPWSTR lpName,
            DWORD cbName)
{
    DWORD dwLength;

    dwLength = cbName;
    return RegEnumKeyExW(hKey,
                         dwIndex,
                         lpName,
                         &dwLength,
                         NULL,
                         NULL,
                         NULL,
                         NULL);
}


/************************************************************************
 *  RegEnumKeyExA
 *
 * @implemented
 */
LONG
WINAPI
RegEnumKeyExA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_ LPSTR lpName,
    _Inout_ LPDWORD lpcbName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPSTR lpClass,
    _Inout_opt_ LPDWORD lpcbClass,
    _Out_opt_ PFILETIME lpftLastWriteTime)
{
    WCHAR* NameBuffer = NULL;
    WCHAR* ClassBuffer = NULL;
    DWORD NameLength = 0, ClassLength = 0;
    LONG ErrorCode;

    /* Allocate our buffers */
    if (*lpcbName > 0)
    {
        NameLength = *lpcbName;
        NameBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, *lpcbName * sizeof(WCHAR));
        if (NameBuffer == NULL)
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    if (lpClass)
    {
        if (*lpcbClass > 0)
        {
            ClassLength = *lpcbClass;
            ClassBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, *lpcbClass * sizeof(WCHAR));
            if (ClassBuffer == NULL)
            {
                ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
                goto Exit;
            }
        }
    }

    /* Do the actual call */
    ErrorCode = RegEnumKeyExW(
        hKey,
        dwIndex,
        NameBuffer,
        lpcbName,
        lpReserved,
        ClassBuffer,
        lpcbClass,
        lpftLastWriteTime);

    if (ErrorCode != ERROR_SUCCESS)
        goto Exit;

    /* Convert the strings */
    RtlUnicodeToMultiByteN(lpName, *lpcbName, 0, NameBuffer, *lpcbName * sizeof(WCHAR));
    /* NULL terminate if we can */
    if (NameLength > *lpcbName)
        lpName[*lpcbName] = '\0';

    if (lpClass)
    {
        RtlUnicodeToMultiByteN(lpClass, *lpcbClass, 0, ClassBuffer, *lpcbClass * sizeof(WCHAR));
        if (ClassLength > *lpcbClass)
            lpClass[*lpcbClass] = '\0';
    }

Exit:
    if (NameBuffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, NameBuffer);
    if (ClassBuffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, ClassBuffer);

    return ErrorCode;
}


/************************************************************************
 *  RegEnumKeyExW
 *
 * @implemented
 */
LONG
WINAPI
RegEnumKeyExW(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_ LPWSTR lpName,
    _Inout_ LPDWORD lpcbName,
    _Reserved_ LPDWORD lpReserved,
    _Out_opt_ LPWSTR lpClass,
    _Inout_opt_ LPDWORD lpcbClass,
    _Out_opt_ PFILETIME lpftLastWriteTime)
{
    union
    {
        KEY_NODE_INFORMATION Node;
        KEY_BASIC_INFORMATION Basic;
    } *KeyInfo;

    ULONG BufferSize;
    ULONG ResultSize;
    ULONG NameLength;
    ULONG ClassLength = 0;
    HANDLE KeyHandle;
    LONG ErrorCode = ERROR_SUCCESS;
    NTSTATUS Status;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        /* The performance data key has no subkeys */
        return ERROR_NO_MORE_ITEMS;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (IsHKCRKey(KeyHandle))
    {
        ErrorCode = EnumHKCRKey(
            KeyHandle,
            dwIndex,
            lpName,
            lpcbName,
            lpReserved,
            lpClass,
            lpcbClass,
            lpftLastWriteTime);
        ClosePredefKey(KeyHandle);
        return ErrorCode;
    }

    if (*lpcbName > 0)
    {
        NameLength = min (*lpcbName - 1, REG_MAX_NAME_SIZE) * sizeof (WCHAR);
    }
    else
    {
        NameLength = 0;
    }

    if (lpClass)
    {
        if (*lpcbClass > 0)
        {
            ClassLength = min (*lpcbClass - 1, REG_MAX_NAME_SIZE) * sizeof(WCHAR);
        }
        else
        {
            ClassLength = 0;
        }

        BufferSize = ((sizeof(KEY_NODE_INFORMATION) + NameLength + 3) & ~3) + ClassLength;
    }
    else
    {
        BufferSize = sizeof(KEY_BASIC_INFORMATION) + NameLength;
    }

    KeyInfo = RtlAllocateHeap(ProcessHeap,
                              0,
                              BufferSize);
    if (KeyInfo == NULL)
    {
        ErrorCode = ERROR_OUTOFMEMORY;
        goto Cleanup;
    }

    Status = NtEnumerateKey(KeyHandle,
                            (ULONG)dwIndex,
                            lpClass ? KeyNodeInformation : KeyBasicInformation,
                            KeyInfo,
                            BufferSize,
                            &ResultSize);
    TRACE("NtEnumerateKey() returned status 0x%X\n", Status);
    if (!NT_SUCCESS(Status))
    {
        ErrorCode = RtlNtStatusToDosError (Status);
    }
    else
    {
        if (lpClass == NULL)
        {
            if (KeyInfo->Basic.NameLength > NameLength)
            {
                ErrorCode = ERROR_MORE_DATA;
            }
            else
            {
                RtlCopyMemory(lpName,
                              KeyInfo->Basic.Name,
                              KeyInfo->Basic.NameLength);
                *lpcbName = (DWORD)(KeyInfo->Basic.NameLength / sizeof(WCHAR));
                lpName[*lpcbName] = 0;
            }
        }
        else
        {
            if (KeyInfo->Node.NameLength > NameLength ||
                KeyInfo->Node.ClassLength > ClassLength)
            {
                ErrorCode = ERROR_MORE_DATA;
            }
            else
            {
                RtlCopyMemory(lpName,
                              KeyInfo->Node.Name,
                              KeyInfo->Node.NameLength);
                *lpcbName = KeyInfo->Node.NameLength / sizeof(WCHAR);
                lpName[*lpcbName] = 0;
                if (KeyInfo->Node.ClassLength)
                {
                    RtlCopyMemory(lpClass,
                                  (PVOID)((ULONG_PTR)&KeyInfo->Node + KeyInfo->Node.ClassOffset),
                                  KeyInfo->Node.ClassLength);
                }
                *lpcbClass = (DWORD)(KeyInfo->Node.ClassLength / sizeof(WCHAR));
                lpClass[*lpcbClass] = 0;
            }
        }

        if (ErrorCode == ERROR_SUCCESS && lpftLastWriteTime != NULL)
        {
            if (lpClass == NULL)
            {
                lpftLastWriteTime->dwLowDateTime = KeyInfo->Basic.LastWriteTime.u.LowPart;
                lpftLastWriteTime->dwHighDateTime = KeyInfo->Basic.LastWriteTime.u.HighPart;
            }
            else
            {
                lpftLastWriteTime->dwLowDateTime = KeyInfo->Node.LastWriteTime.u.LowPart;
                lpftLastWriteTime->dwHighDateTime = KeyInfo->Node.LastWriteTime.u.HighPart;
            }
        }
    }

    RtlFreeHeap(ProcessHeap,
                0,
                KeyInfo);

Cleanup:
    ClosePredefKey(KeyHandle);

    return ErrorCode;
}


/*
 * The general RegEnumValueA: it asks for the size of the longest value name, then lists the value twice (the first
 * time for its type). It serves the keys the quick one below does not (HKEY_CLASSES_ROOT and the performance data).
 */
static LONG
RegEnumValueAGeneral(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_ LPSTR lpName,
    _Inout_ LPDWORD lpcbName,
    _Reserved_ LPDWORD lpdwReserved,
    _Out_opt_ LPDWORD lpdwType,
    _Out_opt_ LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData)
{
    WCHAR* NameBuffer;
    DWORD NameBufferSize, NameLength;
    LONG ErrorCode;
    DWORD LocalType = REG_NONE;
    BOOL NameOverflow = FALSE;

    /* Do parameter checks now, once and for all. */
    if (!lpName || !lpcbName)
        return ERROR_INVALID_PARAMETER;

    if ((lpData && !lpcbData) || lpdwReserved)
        return ERROR_INVALID_PARAMETER;

    /* Get the size of the buffer we must use for the first call to RegEnumValueW */
    ErrorCode = RegQueryInfoKeyW(
        hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &NameBufferSize, NULL, NULL, NULL);
    if (ErrorCode != ERROR_SUCCESS)
        return ErrorCode;

    /* Add space for the null terminator */
    NameBufferSize++;

    /* Allocate the buffer for the unicode name */
    NameBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, NameBufferSize * sizeof(WCHAR));
    if (NameBuffer == NULL)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /*
     * This code calls RegEnumValueW twice, because we need to know the type of the enumerated value.
     * So for the first call, we check if we overflow on the name, as we have no way of knowing if this
     * is an overflow on the data or on the name during the the second call. So the first time, we make the
     * call with the supplied value. This is merdique, but this is how it is.
     */
    NameLength = *lpcbName;
    ErrorCode = RegEnumValueW(
        hKey,
        dwIndex,
        NameBuffer,
        &NameLength,
        NULL,
        &LocalType,
        NULL,
        NULL);
    if (ErrorCode != ERROR_SUCCESS)
    {
        if (ErrorCode == ERROR_MORE_DATA)
            NameOverflow = TRUE;
        else
            goto Exit;
    }

    if (is_string(LocalType) && lpcbData)
    {
        /* We must allocate a buffer to get the unicode data */
        DWORD DataBufferSize = *lpcbData * sizeof(WCHAR);
        WCHAR* DataBuffer = NULL;
        DWORD DataLength = *lpcbData;
        LPSTR DataStr = (LPSTR)lpData;

        if (lpData)
            DataBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, *lpcbData * sizeof(WCHAR));

        /* Do the real call */
        ErrorCode = RegEnumValueW(
            hKey,
            dwIndex,
            NameBuffer,
            &NameBufferSize,
            lpdwReserved,
            lpdwType,
            (LPBYTE)DataBuffer,
            &DataBufferSize);

        *lpcbData = DataBufferSize / sizeof(WCHAR);

        if (ErrorCode != ERROR_SUCCESS)
        {
            RtlFreeHeap(RtlGetProcessHeap(), 0, DataBuffer);
            goto Exit;
        }

        /* Copy the data whatever the error code is */
        if (lpData)
        {
            /* Do the data conversion */
            RtlUnicodeToMultiByteN(DataStr, DataLength, 0, DataBuffer, DataBufferSize);
            /* NULL-terminate if there is enough room */
            if ((DataLength > *lpcbData) && (*lpcbData > 0) && (DataStr[*lpcbData - 1] != '\0'))
                DataStr[*lpcbData] = '\0';
        }

        RtlFreeHeap(RtlGetProcessHeap(), 0, DataBuffer);
    }
    else
    {
        /* No data conversion needed. Do the call with provided buffers */
        ErrorCode = RegEnumValueW(
            hKey,
            dwIndex,
            NameBuffer,
            &NameBufferSize,
            lpdwReserved,
            lpdwType,
            lpData,
            lpcbData);

        if (ErrorCode != ERROR_SUCCESS)
        {
            goto Exit;
        }
    }

    if (NameOverflow)
    {
        ErrorCode = ERROR_MORE_DATA;
        goto Exit;
    }

    /* Convert the name string */
    RtlUnicodeToMultiByteN(lpName, *lpcbName, lpcbName, NameBuffer, NameBufferSize * sizeof(WCHAR));
    lpName[*lpcbName] = ANSI_NULL;

Exit:
    if (NameBuffer)
        RtlFreeHeap(RtlGetProcessHeap(), 0, NameBuffer);

    return ErrorCode;
}


/************************************************************************
 *  RegEnumValueA
 *
 * @implemented
 *
 * One system call for the value (name, type and data come together), where the general function above needs
 * three. The results, the error codes and what is written to the caller's buffers are those of the general one.
 */
LONG WINAPI
RegEnumValueA(
    _In_ HKEY hKey,
    _In_ DWORD dwIndex,
    _Out_ LPSTR lpName,
    _Inout_ LPDWORD lpcbName,
    _Reserved_ LPDWORD lpdwReserved,
    _Out_opt_ LPDWORD lpdwType,
    _Out_opt_ LPBYTE lpData,
    _Inout_opt_ LPDWORD lpcbData)
{
    HANDLE KeyHandle;
    NTSTATUS Status;
    ULONG TotalSize;
    char Buffer[256], *BufPtr = Buffer;
    KEY_VALUE_FULL_INFORMATION *Info = (KEY_VALUE_FULL_INFORMATION *)Buffer;
    static const int InfoSize = FIELD_OFFSET(KEY_VALUE_FULL_INFORMATION, Name);
    LONG ErrorCode;
    BOOL NameOverflow;
    DWORD NameChars, DataBytes;
    PWCHAR DataW;

    /* Do parameter checks now, once and for all. */
    if (!lpName || !lpcbName)
        return ERROR_INVALID_PARAMETER;

    if ((lpData && !lpcbData) || lpdwReserved)
        return ERROR_INVALID_PARAMETER;

    /* The performance data and the classes root have their own ways */
    if (hKey == HKEY_PERFORMANCE_DATA)
        goto General;

    Status = MapDefaultKey(&KeyHandle, hKey);
    if (!NT_SUCCESS(Status))
        return RtlNtStatusToDosError(Status);

    if (IsHKCRKey(KeyHandle))
    {
        ClosePredefKey(KeyHandle);
        goto General;
    }

    /* The name, the type and a small value fit the buffer; anything bigger is asked for again */
    TotalSize = InfoSize + (MAX_PATH + 1) * sizeof(WCHAR);
    if (lpData && lpcbData) TotalSize += *lpcbData * sizeof(WCHAR);
    TotalSize = min(sizeof(Buffer), TotalSize);

    Status = NtEnumerateValueKey(KeyHandle, dwIndex, KeyValueFullInformation, Buffer, TotalSize, &TotalSize);
    while ((Status == STATUS_BUFFER_OVERFLOW) || (Status == STATUS_BUFFER_TOO_SMALL))
    {
        if (BufPtr != Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, BufPtr);
        BufPtr = RtlAllocateHeap(RtlGetProcessHeap(), 0, TotalSize);
        if (!BufPtr)
        {
            ClosePredefKey(KeyHandle);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        Info = (KEY_VALUE_FULL_INFORMATION *)BufPtr;
        Status = NtEnumerateValueKey(KeyHandle, dwIndex, KeyValueFullInformation, BufPtr, TotalSize, &TotalSize);
    }
    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        ErrorCode = RtlNtStatusToDosError(Status);
        goto Exit;
    }

    NameChars = Info->NameLength / sizeof(WCHAR);
    NameOverflow = (NameChars >= *lpcbName);
    DataW = (PWCHAR)(BufPtr + Info->DataOffset);

    if (is_string(Info->Type) && lpcbData)
    {
        /* The caller counts the data in characters */
        DWORD DataLength = *lpcbData;

        if (lpdwType) *lpdwType = Info->Type;
        DataBytes = Info->DataLength;
        *lpcbData = DataBytes / sizeof(WCHAR);

        if (lpData)
        {
            if (DataBytes > DataLength * sizeof(WCHAR))
            {
                ErrorCode = ERROR_MORE_DATA;
                goto Exit;
            }

            RtlUnicodeToMultiByteN((LPSTR)lpData, DataLength, 0, DataW, DataBytes);
            /* NULL-terminate if there is enough room */
            if ((DataLength > *lpcbData) && (*lpcbData > 0) && (lpData[*lpcbData - 1] != '\0'))
                lpData[*lpcbData] = '\0';
        }
    }
    else
    {
        if (lpdwType) *lpdwType = Info->Type;
        if (lpData)
        {
            if (Info->DataLength > *lpcbData)
            {
                *lpcbData = Info->DataLength;
                ErrorCode = ERROR_MORE_DATA;
                goto Exit;
            }
            RtlCopyMemory(lpData, DataW, Info->DataLength);
        }
        if (lpcbData) *lpcbData = Info->DataLength;
    }

    if (NameOverflow)
    {
        ErrorCode = ERROR_MORE_DATA;
        goto Exit;
    }

    /* Convert the name string */
    RtlUnicodeToMultiByteN(lpName, *lpcbName, lpcbName, Info->Name, Info->NameLength);
    lpName[*lpcbName] = ANSI_NULL;
    ErrorCode = ERROR_SUCCESS;

Exit:
    if (BufPtr != Buffer) RtlFreeHeap(RtlGetProcessHeap(), 0, BufPtr);
    return ErrorCode;

General:
    return RegEnumValueAGeneral(hKey, dwIndex, lpName, lpcbName, lpdwReserved, lpdwType, lpData, lpcbData);
}


/******************************************************************************
 * RegEnumValueW   [ADVAPI32.@]
 * @implemented
 *
 * PARAMS
 *  hkey       [I] Handle to key to query
 *  index      [I] Index of value to query
 *  value      [O] Value string
 *  val_count  [I/O] Size of value buffer (in wchars)
 *  reserved   [I] Reserved
 *  type       [O] Type code
 *  data       [O] Value data
 *  count      [I/O] Size of data buffer (in bytes)
 *
 * RETURNS
 *  Success: ERROR_SUCCESS
 *  Failure: nonzero error code from Winerror.h
 */
LONG
WINAPI
RegEnumValueW(
    _In_ HKEY hKey,
    _In_ DWORD index,
    _Out_ LPWSTR value,
    _Inout_ PDWORD val_count,
    _Reserved_ PDWORD reserved,
    _Out_opt_ PDWORD type,
    _Out_opt_ LPBYTE data,
    _Inout_opt_ PDWORD count)
{
    HANDLE KeyHandle;
    NTSTATUS status;
    ULONG total_size;
    char buffer[256], *buf_ptr = buffer;
    KEY_VALUE_FULL_INFORMATION *info = (KEY_VALUE_FULL_INFORMATION *)buffer;
    static const int info_size = FIELD_OFFSET( KEY_VALUE_FULL_INFORMATION, Name );

    TRACE("(%p,%ld,%p,%p,%p,%p,%p,%p)\n",
          hKey, index, value, val_count, reserved, type, data, count );

    if (!value || !val_count)
        return ERROR_INVALID_PARAMETER;

    if ((data && !count) || reserved)
        return ERROR_INVALID_PARAMETER;

    /* The performance data key has no enumerable values */
    if (hKey == HKEY_PERFORMANCE_DATA)
        return ERROR_NO_MORE_ITEMS;

    status = MapDefaultKey(&KeyHandle, hKey);
    if (!NT_SUCCESS(status))
    {
        return RtlNtStatusToDosError(status);
    }

    if (IsHKCRKey(KeyHandle))
    {
        LONG ErrorCode = EnumHKCRValue(
            KeyHandle,
            index,
            value,
            val_count,
            reserved,
            type,
            data,
            count);
        ClosePredefKey(KeyHandle);
        return ErrorCode;
    }

    total_size = info_size + (MAX_PATH + 1) * sizeof(WCHAR);
    if (data) total_size += *count;
    total_size = min( sizeof(buffer), total_size );

    status = NtEnumerateValueKey( KeyHandle, index, KeyValueFullInformation,
                                  buffer, total_size, &total_size );
    if (status && (status != STATUS_BUFFER_OVERFLOW) && (status != STATUS_BUFFER_TOO_SMALL)) goto done;

    if (value || data)
    {
        /* retry with a dynamically allocated buffer */
        while ((status == STATUS_BUFFER_OVERFLOW) || (status == STATUS_BUFFER_TOO_SMALL))
        {
            if (buf_ptr != buffer) HeapFree( GetProcessHeap(), 0, buf_ptr );
            if (!(buf_ptr = HeapAlloc( GetProcessHeap(), 0, total_size )))
            {
                status = ERROR_NOT_ENOUGH_MEMORY;
                goto done;
            }
            info = (KEY_VALUE_FULL_INFORMATION *)buf_ptr;
            status = NtEnumerateValueKey( KeyHandle, index, KeyValueFullInformation,
                                          buf_ptr, total_size, &total_size );
        }

        if (status) goto done;

        if (value)
        {
            if (info->NameLength/sizeof(WCHAR) >= *val_count)
            {
                status = STATUS_BUFFER_OVERFLOW;
                goto overflow;
            }
            memcpy( value, info->Name, info->NameLength );
            *val_count = info->NameLength / sizeof(WCHAR);
            value[*val_count] = 0;
        }

        if (data)
        {
            if (info->DataLength > *count)
            {
                status = STATUS_BUFFER_OVERFLOW;
                goto overflow;
            }
            memcpy( data, buf_ptr + info->DataOffset, info->DataLength );
            if (is_string(info->Type) &&
                info->DataLength >= sizeof(WCHAR) &&
                *count >= sizeof(WCHAR) &&
                info->DataLength <= *count - sizeof(WCHAR))
            {
                /* if the type is REG_SZ and data is not 0-terminated
                 * and there is enough space in the buffer NT appends a \0 */
                WCHAR *ptr = (WCHAR *)(data + info->DataLength);
                if (ptr[-1]) *ptr = 0;
            }
        }
    }
    else status = STATUS_SUCCESS;

 overflow:
    if (type) *type = info->Type;
    if (count) *count = info->DataLength;

 done:
    if (buf_ptr != buffer) HeapFree( GetProcessHeap(), 0, buf_ptr );
    ClosePredefKey(KeyHandle);
    return RtlNtStatusToDosError(status);
}


/************************************************************************
 *  RegFlushKey
 *
 * @implemented
 */
LONG WINAPI
RegFlushKey(HKEY hKey)
{
    HANDLE KeyHandle;
    NTSTATUS Status;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_SUCCESS;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    Status = NtFlushKey(KeyHandle);

    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegGetKeySecurity
 *
 * @implemented
 */
LONG WINAPI
RegGetKeySecurity(HKEY hKey,
                  SECURITY_INFORMATION SecurityInformation,
                  PSECURITY_DESCRIPTOR pSecurityDescriptor,
                  LPDWORD lpcbSecurityDescriptor)
{
    HANDLE KeyHandle;
    NTSTATUS Status;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_INVALID_HANDLE;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        TRACE("MapDefaultKey() failed (Status %lx)\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    Status = NtQuerySecurityObject(KeyHandle,
                                   SecurityInformation,
                                   pSecurityDescriptor,
                                   *lpcbSecurityDescriptor,
                                   lpcbSecurityDescriptor);

    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
         WARN("NtQuerySecurityObject() failed (Status %lx)\n", Status);
         return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegLoadKeyA
 *
 * @implemented
 */
LONG WINAPI
RegLoadKeyA(HKEY hKey,
            LPCSTR lpSubKey,
            LPCSTR lpFile)
{
    UNICODE_STRING FileName;
    UNICODE_STRING KeyName;
    LONG ErrorCode;

    RtlInitEmptyUnicodeString(&KeyName, NULL, 0);
    RtlInitEmptyUnicodeString(&FileName, NULL, 0);

    if (lpSubKey)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&KeyName, lpSubKey))
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    if (lpFile)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&FileName, lpFile))
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    ErrorCode = RegLoadKeyW(hKey,
                            KeyName.Buffer,
                            FileName.Buffer);

Exit:
    RtlFreeUnicodeString(&FileName);
    RtlFreeUnicodeString(&KeyName);

    return ErrorCode;
}


/************************************************************************
 *  RegLoadKeyW
 *
 * @implemented
 */
LONG WINAPI
RegLoadKeyW(HKEY hKey,
            LPCWSTR lpSubKey,
            LPCWSTR lpFile)
{
    OBJECT_ATTRIBUTES FileObjectAttributes;
    OBJECT_ATTRIBUTES KeyObjectAttributes;
    UNICODE_STRING FileName;
    UNICODE_STRING KeyName;
    HANDLE KeyHandle;
    NTSTATUS Status;
    LONG ErrorCode = ERROR_SUCCESS;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_INVALID_HANDLE;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (!RtlDosPathNameToNtPathName_U(lpFile,
                                      &FileName,
                                      NULL,
                                      NULL))
    {
      ErrorCode = ERROR_BAD_PATHNAME;
      goto Cleanup;
    }

    InitializeObjectAttributes(&FileObjectAttributes,
                               &FileName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    RtlInitUnicodeString(&KeyName, lpSubKey);

    InitializeObjectAttributes(&KeyObjectAttributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               KeyHandle,
                               NULL);

    Status = NtLoadKey(&KeyObjectAttributes,
                       &FileObjectAttributes);

    RtlFreeHeap(RtlGetProcessHeap(),
                0,
                FileName.Buffer);

    if (!NT_SUCCESS(Status))
    {
        ErrorCode = RtlNtStatusToDosError(Status);
        goto Cleanup;
    }

Cleanup:
    ClosePredefKey(KeyHandle);

    return ErrorCode;
}


/************************************************************************
 *  RegNotifyChangeKeyValue
 *
 * @implemented
 */
LONG WINAPI
RegNotifyChangeKeyValue(HKEY hKey,
                        BOOL bWatchSubtree,
                        DWORD dwNotifyFilter,
                        HANDLE hEvent,
                        BOOL fAsynchronous)
{
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE KeyHandle;
    NTSTATUS Status;
    LONG ErrorCode = ERROR_SUCCESS;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_INVALID_HANDLE;
    }

    if ((fAsynchronous != FALSE) && (hEvent == NULL))
    {
        return ERROR_INVALID_PARAMETER;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    /* FIXME: Remote key handles must fail */

    Status = NtNotifyChangeKey(KeyHandle,
                               hEvent,
                               0,
                               0,
                               /* An asynchronous request completes after we have
                                * returned: no block of ours can outlive the call,
                                * the caller gets the result through hEvent */
                               fAsynchronous ? NULL : &IoStatusBlock,
                               dwNotifyFilter,
                               bWatchSubtree,
                               0,
                               0,
                               fAsynchronous);
    if (!NT_SUCCESS(Status) && Status != STATUS_TIMEOUT)
    {
        ErrorCode = RtlNtStatusToDosError(Status);
    }

    ClosePredefKey(KeyHandle);

    return ErrorCode;
}


/************************************************************************
 *  RegOpenCurrentUser
 *
 * @implemented
 */
LONG WINAPI
RegOpenCurrentUser(IN REGSAM samDesired,
                   OUT PHKEY phkResult)
{
    NTSTATUS Status;

    Status = RtlOpenCurrentUser((ACCESS_MASK)samDesired,
                                (PHANDLE)phkResult);
    if (!NT_SUCCESS(Status))
    {
        /* NOTE - don't set the last error code! just return the error! */
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegOpenKeyA
 *
 *  20050503 Fireball - imported from WINE
 *
 * @implemented
 */
LONG WINAPI
RegOpenKeyA(HKEY hKey,
            LPCSTR lpSubKey,
            PHKEY phkResult)
{
    TRACE("RegOpenKeyA hKey 0x%x lpSubKey %s phkResult %p\n",
          hKey, lpSubKey, phkResult);

    if (!phkResult)
        return ERROR_INVALID_PARAMETER;

    if (!hKey && !lpSubKey)
    {
        *phkResult = hKey;
        return ERROR_SUCCESS;
    }

    return RegOpenKeyExA(hKey,
                         lpSubKey,
                         0,
                         MAXIMUM_ALLOWED,
                         phkResult);
}


/************************************************************************
 *  RegOpenKeyW
 *
 *  19981101 Ariadne
 *  19990525 EA
 *  20050503 Fireball - imported from WINE
 *
 * @implemented
 */
LONG WINAPI
RegOpenKeyW(HKEY hKey,
            LPCWSTR lpSubKey,
            PHKEY phkResult)
{
    TRACE("RegOpenKeyW hKey 0x%x lpSubKey %S phkResult %p\n",
          hKey, lpSubKey, phkResult);

    if (!phkResult)
        return ERROR_INVALID_PARAMETER;

    if (!hKey && !lpSubKey)
    {
        *phkResult = hKey;
        return ERROR_SUCCESS;
    }

    return RegOpenKeyExW(hKey,
                         lpSubKey,
                         0,
                         MAXIMUM_ALLOWED,
                         phkResult);
}


/************************************************************************
 *  RegOpenKeyExA
 *
 * @implemented
 */
LONG WINAPI
RegOpenKeyExA(
    _In_ HKEY hKey,
    _In_ LPCSTR lpSubKey,
    _In_ DWORD ulOptions,
    _In_ REGSAM samDesired,
    _Out_ PHKEY phkResult)
{
    UNICODE_STRING SubKeyString;
    LONG ErrorCode;

    TRACE("RegOpenKeyExA hKey 0x%x lpSubKey %s ulOptions 0x%x samDesired 0x%x phkResult %p\n",
          hKey, lpSubKey, ulOptions, samDesired, phkResult);

    if (lpSubKey)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&SubKeyString, lpSubKey))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
        RtlInitEmptyUnicodeString(&SubKeyString, NULL, 0);

    ErrorCode = RegOpenKeyExW(hKey, SubKeyString.Buffer, ulOptions, samDesired, phkResult);

    RtlFreeUnicodeString(&SubKeyString);

    return ErrorCode;
}


/************************************************************************
 *  RegOpenKeyExW
 *
 * @implemented
 */
LONG WINAPI
RegOpenKeyExW(HKEY hKey,
              LPCWSTR lpSubKey,
              DWORD ulOptions,
              REGSAM samDesired,
              PHKEY phkResult)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING SubKeyString;
    HANDLE KeyHandle;
    NTSTATUS Status;
    ULONG Attributes = OBJ_CASE_INSENSITIVE;
    LONG ErrorCode = ERROR_SUCCESS;
    BOOLEAN SubKeyStringAllocated = FALSE;

    TRACE("RegOpenKeyExW hKey 0x%x lpSubKey %S ulOptions 0x%x samDesired 0x%x phkResult %p\n",
          hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (!phkResult)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (!hKey && lpSubKey && phkResult)
    {
        return ERROR_INVALID_HANDLE;
    }

    /* The performance data is not in the registry: there is nothing to open, with or without a subkey */
    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_INVALID_HANDLE;
    }

    if (IsPredefKey(hKey) && (!lpSubKey || !*lpSubKey))
    {
        *phkResult = hKey;
        return ERROR_SUCCESS;
    }

    Status = MapDefaultKey(&KeyHandle, hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (IsHKCRKey(KeyHandle))
    {
        ErrorCode = OpenHKCRKey(KeyHandle, lpSubKey, ulOptions, samDesired, phkResult);
        ClosePredefKey(KeyHandle);
        return ErrorCode;
    }

    if (ulOptions & REG_OPTION_OPEN_LINK)
        Attributes |= OBJ_OPENLINK;

    if (lpSubKey == NULL || wcscmp(lpSubKey, L"\\") == 0)
    {
        RtlInitUnicodeString(&SubKeyString, L"");
    }
    else
    {
        RtlInitUnicodeString(&SubKeyString, lpSubKey);

        /* Handle unaligned lpSubKey */
        if ((ULONG_PTR)lpSubKey & 1)
        {
            UNICODE_STRING AlignedString;

            Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
                                               &SubKeyString,
                                               &AlignedString);
            if (!NT_SUCCESS(Status))
            {
                goto Exit;
            }

            SubKeyString = AlignedString;
            SubKeyStringAllocated = TRUE;
        }
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               &SubKeyString,
                               Attributes,
                               KeyHandle,
                               NULL);

    Status = NtOpenKey((PHANDLE)phkResult,
                       samDesired,
                       &ObjectAttributes);

Exit:

    if (SubKeyStringAllocated)
    {
        RtlFreeUnicodeString(&SubKeyString);
    }

    if (!NT_SUCCESS(Status))
    {
        ErrorCode = RtlNtStatusToDosError(Status);
    }

    ClosePredefKey(KeyHandle);

    return ErrorCode;
}


/************************************************************************
 *  RegOpenUserClassesRoot
 *
 * @implemented
 */
LONG WINAPI
RegOpenUserClassesRoot(IN HANDLE hToken,
                       IN DWORD dwOptions,
                       IN REGSAM samDesired,
                       OUT PHKEY phkResult)
{
    const WCHAR UserClassesKeyPrefix[] = L"\\Registry\\User\\";
    const WCHAR UserClassesKeySuffix[] = L"_Classes";
    PTOKEN_USER TokenUserData;
    ULONG RequiredLength;
    UNICODE_STRING UserSidString, UserClassesKeyRoot;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;

    /* check parameters */
    if (hToken == NULL || dwOptions != 0 || phkResult == NULL)
    {
        return ERROR_INVALID_PARAMETER;
    }

    /*
     * Get the user sid from the token
     */

ReadTokenSid:
    /* determine how much memory we need */
    Status = NtQueryInformationToken(hToken,
                                     TokenUser,
                                     NULL,
                                     0,
                                     &RequiredLength);
    if (!NT_SUCCESS(Status) && (Status != STATUS_BUFFER_TOO_SMALL))
    {
        /* NOTE - as opposed to all other registry functions windows does indeed
                  change the last error code in case the caller supplied a invalid
                  handle for example! */
        return RtlNtStatusToDosError(Status);
    }
    RegInitialize(); /* HACK until delay-loading is implemented */
    TokenUserData = RtlAllocateHeap(ProcessHeap,
                                    0,
                                    RequiredLength);
    if (TokenUserData == NULL)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* attempt to read the information */
    Status = NtQueryInformationToken(hToken,
                                     TokenUser,
                                     TokenUserData,
                                     RequiredLength,
                                     &RequiredLength);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(ProcessHeap,
                    0,
                    TokenUserData);
        if (Status == STATUS_BUFFER_TOO_SMALL)
        {
            /* the information appears to have changed?! try again */
            goto ReadTokenSid;
        }

        /* NOTE - as opposed to all other registry functions windows does indeed
                  change the last error code in case the caller supplied a invalid
                  handle for example! */
        return RtlNtStatusToDosError(Status);
    }

    /*
     * Build the absolute path for the user's registry in the form
     * "\Registry\User\<SID>_Classes"
     */
    Status = RtlConvertSidToUnicodeString(&UserSidString,
                                          TokenUserData->User.Sid,
                                          TRUE);

    /* we don't need the user data anymore, free it */
    RtlFreeHeap(ProcessHeap,
                0,
                TokenUserData);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    /* allocate enough memory for the entire key string */
    UserClassesKeyRoot.Length = 0;
    UserClassesKeyRoot.MaximumLength = UserSidString.Length +
                                       sizeof(UserClassesKeyPrefix) +
                                       sizeof(UserClassesKeySuffix);
    UserClassesKeyRoot.Buffer = RtlAllocateHeap(ProcessHeap,
                                                0,
                                                UserClassesKeyRoot.MaximumLength);
    if (UserClassesKeyRoot.Buffer == NULL)
    {
        RtlFreeUnicodeString(&UserSidString);
        return RtlNtStatusToDosError(Status);
    }

    /* build the string */
    RtlAppendUnicodeToString(&UserClassesKeyRoot,
                             UserClassesKeyPrefix);
    RtlAppendUnicodeStringToString(&UserClassesKeyRoot,
                                   &UserSidString);
    RtlAppendUnicodeToString(&UserClassesKeyRoot,
                             UserClassesKeySuffix);

    TRACE("RegOpenUserClassesRoot: Absolute path: %wZ\n", &UserClassesKeyRoot);

    /*
     * Open the key
     */
    InitializeObjectAttributes(&ObjectAttributes,
                               &UserClassesKeyRoot,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtOpenKey((PHANDLE)phkResult,
                       samDesired,
                       &ObjectAttributes);

    RtlFreeUnicodeString(&UserSidString);
    RtlFreeUnicodeString(&UserClassesKeyRoot);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegQueryInfoKeyA
 *
 * @implemented
 */
LONG WINAPI
RegQueryInfoKeyA(HKEY hKey,
                 LPSTR lpClass,
                 LPDWORD lpcClass,
                 LPDWORD lpReserved,
                 LPDWORD lpcSubKeys,
                 LPDWORD lpcMaxSubKeyLen,
                 LPDWORD lpcMaxClassLen,
                 LPDWORD lpcValues,
                 LPDWORD lpcMaxValueNameLen,
                 LPDWORD lpcMaxValueLen,
                 LPDWORD lpcbSecurityDescriptor,
                 PFILETIME lpftLastWriteTime)
{
    WCHAR ClassName[MAX_PATH];
    UNICODE_STRING UnicodeString;
    ANSI_STRING AnsiString;
    LONG ErrorCode;
    NTSTATUS Status;
    DWORD cClass = 0;

    if ((lpClass) && (!lpcClass))
    {
        return ERROR_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&UnicodeString,
                         NULL);
    if (lpClass != NULL)
    {
        RtlInitEmptyUnicodeString(&UnicodeString,
                                  ClassName,
                                  sizeof(ClassName));
        cClass = sizeof(ClassName) / sizeof(WCHAR);
    }

    ErrorCode = RegQueryInfoKeyW(hKey,
                                 UnicodeString.Buffer,
                                 &cClass,
                                 lpReserved,
                                 lpcSubKeys,
                                 lpcMaxSubKeyLen,
                                 lpcMaxClassLen,
                                 lpcValues,
                                 lpcMaxValueNameLen,
                                 lpcMaxValueLen,
                                 lpcbSecurityDescriptor,
                                 lpftLastWriteTime);
    if ((ErrorCode == ERROR_SUCCESS) && (lpClass != NULL))
    {
        if (*lpcClass == 0)
        {
            return ErrorCode;
        }

        RtlInitEmptyAnsiString(&AnsiString, lpClass, *lpcClass);
        UnicodeString.Length = cClass * sizeof(WCHAR);
        Status = RtlUnicodeStringToAnsiString(&AnsiString,
                                              &UnicodeString,
                                              FALSE);
        ErrorCode = RtlNtStatusToDosError(Status);
        cClass = AnsiString.Length;
        lpClass[cClass] = ANSI_NULL;
    }

    if (lpcClass != NULL)
    {
        *lpcClass = cClass;
    }

    return ErrorCode;
}


/************************************************************************
 *  RegQueryInfoKeyW
 *
 * @implemented
 */
LONG WINAPI
RegQueryInfoKeyW(HKEY hKey,
                 LPWSTR lpClass,
                 LPDWORD lpcClass,
                 LPDWORD lpReserved,
                 LPDWORD lpcSubKeys,
                 LPDWORD lpcMaxSubKeyLen,
                 LPDWORD lpcMaxClassLen,
                 LPDWORD lpcValues,
                 LPDWORD lpcMaxValueNameLen,
                 LPDWORD lpcMaxValueLen,
                 LPDWORD lpcbSecurityDescriptor,
                 PFILETIME lpftLastWriteTime)
{
    KEY_FULL_INFORMATION FullInfoBuffer;
    PKEY_FULL_INFORMATION FullInfo;
    ULONG FullInfoSize;
    ULONG ClassLength = 0;
    HANDLE KeyHandle;
    NTSTATUS Status;
    ULONG Length;
    LONG ErrorCode = ERROR_SUCCESS;

    if ((lpClass) && (!lpcClass))
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        /* The performance data key is not backed by the registry:
         * it has no subkeys and no class */
        if (lpClass != NULL && lpcClass != NULL && *lpcClass > 0)
            lpClass[0] = UNICODE_NULL;
        if (lpcClass != NULL)
            *lpcClass = 0;
        if (lpcSubKeys != NULL)
            *lpcSubKeys = 0;
        if (lpcMaxSubKeyLen != NULL)
            *lpcMaxSubKeyLen = 0;
        if (lpcMaxClassLen != NULL)
            *lpcMaxClassLen = 0;
        if (lpcValues != NULL)
            *lpcValues = 0;
        if (lpcMaxValueNameLen != NULL)
            *lpcMaxValueNameLen = 0;
        if (lpcMaxValueLen != NULL)
            *lpcMaxValueLen = 0;
        if (lpcbSecurityDescriptor != NULL)
            *lpcbSecurityDescriptor = 0;
        if (lpftLastWriteTime != NULL)
        {
            lpftLastWriteTime->dwLowDateTime = 0;
            lpftLastWriteTime->dwHighDateTime = 0;
        }
        return ERROR_SUCCESS;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (IsHKCRKey(KeyHandle))
    {
        ErrorCode = QueryInfoHKCRKey(KeyHandle, lpClass, lpcClass, lpReserved,
                                     lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen,
                                     lpcValues, lpcMaxValueNameLen, lpcMaxValueLen,
                                     lpcbSecurityDescriptor, lpftLastWriteTime);
        ClosePredefKey(KeyHandle);
        return ErrorCode;
    }

    if (lpClass != NULL)
    {
        if (*lpcClass > 0)
        {
            ClassLength = min(*lpcClass - 1, REG_MAX_NAME_SIZE) * sizeof(WCHAR);
        }
        else
        {
            ClassLength = 0;
        }

        FullInfoSize = sizeof(KEY_FULL_INFORMATION) + ((ClassLength + 3) & ~3);
        FullInfo = RtlAllocateHeap(ProcessHeap,
                                   0,
                                   FullInfoSize);
        if (FullInfo == NULL)
        {
            ErrorCode = ERROR_OUTOFMEMORY;
            goto Cleanup;
        }
    }
    else
    {
        FullInfoSize = sizeof(KEY_FULL_INFORMATION);
        FullInfo = &FullInfoBuffer;
    }

    if (lpcbSecurityDescriptor != NULL)
        *lpcbSecurityDescriptor = 0;

    Status = NtQueryKey(KeyHandle,
                        KeyFullInformation,
                        FullInfo,
                        FullInfoSize,
                        &Length);
    TRACE("NtQueryKey() returned status 0x%X\n", Status);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW)
    {
        ErrorCode = RtlNtStatusToDosError(Status);
        goto Cleanup;
    }

    TRACE("SubKeys %d\n", FullInfo->SubKeys);
    if (lpcSubKeys != NULL)
    {
        *lpcSubKeys = FullInfo->SubKeys;
    }

    TRACE("MaxNameLen %lu\n", FullInfo->MaxNameLen);
    if (lpcMaxSubKeyLen != NULL)
    {
        *lpcMaxSubKeyLen = FullInfo->MaxNameLen / sizeof(WCHAR);
    }

    TRACE("MaxClassLen %lu\n", FullInfo->MaxClassLen);
    if (lpcMaxClassLen != NULL)
    {
        *lpcMaxClassLen = FullInfo->MaxClassLen / sizeof(WCHAR);
    }

    TRACE("Values %lu\n", FullInfo->Values);
    if (lpcValues != NULL)
    {
        *lpcValues = FullInfo->Values;
    }

    TRACE("MaxValueNameLen %lu\n", FullInfo->MaxValueNameLen);
    if (lpcMaxValueNameLen != NULL)
    {
        *lpcMaxValueNameLen = FullInfo->MaxValueNameLen / sizeof(WCHAR);
    }

    TRACE("MaxValueDataLen %lu\n", FullInfo->MaxValueDataLen);
    if (lpcMaxValueLen != NULL)
    {
        *lpcMaxValueLen = FullInfo->MaxValueDataLen;
    }

    if (lpcbSecurityDescriptor != NULL)
    {
        Status = NtQuerySecurityObject(KeyHandle,
                                       OWNER_SECURITY_INFORMATION |
                                       GROUP_SECURITY_INFORMATION |
                                       DACL_SECURITY_INFORMATION,
                                       NULL,
                                       0,
                                       lpcbSecurityDescriptor);
        TRACE("NtQuerySecurityObject() returned status 0x%X\n", Status);
    }

    if (lpftLastWriteTime != NULL)
    {
        lpftLastWriteTime->dwLowDateTime = FullInfo->LastWriteTime.u.LowPart;
        lpftLastWriteTime->dwHighDateTime = FullInfo->LastWriteTime.u.HighPart;
    }

    if (lpClass != NULL)
    {
        if (*lpcClass == 0)
        {
            goto Cleanup;
        }

        if (FullInfo->ClassLength > ClassLength)
        {
            ErrorCode = ERROR_INSUFFICIENT_BUFFER;
        }
        else
        {
            RtlCopyMemory(lpClass,
                          FullInfo->Class,
                          FullInfo->ClassLength);
            lpClass[FullInfo->ClassLength / sizeof(WCHAR)] = UNICODE_NULL;
        }
    }

    if (lpcClass != NULL)
    {
        *lpcClass = FullInfo->ClassLength / sizeof(WCHAR);
    }

Cleanup:
    if (lpClass != NULL)
    {
        RtlFreeHeap(ProcessHeap,
                    0,
                    FullInfo);
    }

    ClosePredefKey(KeyHandle);

    return ErrorCode;
}


/************************************************************************
 *  RegQueryMultipleValuesA
 *
 * @implemented
 */
LONG WINAPI
RegQueryMultipleValuesA(HKEY hKey,
                        PVALENTA val_list,
                        DWORD num_vals,
                        LPSTR lpValueBuf,
                        LPDWORD ldwTotsize)
{
    ULONG i;
    DWORD maxBytes = *ldwTotsize;
    LPSTR bufptr = lpValueBuf;
    LONG ErrorCode;

    if (maxBytes >= (1024*1024))
        return ERROR_MORE_DATA;

    *ldwTotsize = 0;

    TRACE("RegQueryMultipleValuesA(%p,%p,%ld,%p,%p=%ld)\n",
          hKey, val_list, num_vals, lpValueBuf, ldwTotsize, *ldwTotsize);

    for (i = 0; i < num_vals; i++)
    {
        val_list[i].ve_valuelen = 0;
        ErrorCode = RegQueryValueExA(hKey,
                                     val_list[i].ve_valuename,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &val_list[i].ve_valuelen);
        if (ErrorCode != ERROR_SUCCESS)
        {
            return ErrorCode;
        }

        if (lpValueBuf != NULL && *ldwTotsize + val_list[i].ve_valuelen <= maxBytes)
        {
            ErrorCode = RegQueryValueExA(hKey,
                                         val_list[i].ve_valuename,
                                         NULL,
                                         &val_list[i].ve_type,
                                         (LPBYTE)bufptr,
                                         &val_list[i].ve_valuelen);
            if (ErrorCode != ERROR_SUCCESS)
            {
                return ErrorCode;
            }

            val_list[i].ve_valueptr = (DWORD_PTR)bufptr;

            bufptr += val_list[i].ve_valuelen;
        }

        *ldwTotsize += val_list[i].ve_valuelen;
    }

    return (lpValueBuf != NULL && *ldwTotsize <= maxBytes) ? ERROR_SUCCESS : ERROR_MORE_DATA;
}


/************************************************************************
 *  RegQueryMultipleValuesW
 *
 * @implemented
 */
LONG WINAPI
RegQueryMultipleValuesW(HKEY hKey,
                        PVALENTW val_list,
                        DWORD num_vals,
                        LPWSTR lpValueBuf,
                        LPDWORD ldwTotsize)
{
    ULONG i;
    DWORD maxBytes = *ldwTotsize;
    LPSTR bufptr = (LPSTR)lpValueBuf;
    LONG ErrorCode;

    if (maxBytes >= (1024*1024))
        return ERROR_MORE_DATA;

    *ldwTotsize = 0;

    TRACE("RegQueryMultipleValuesW(%p,%p,%ld,%p,%p=%ld)\n",
          hKey, val_list, num_vals, lpValueBuf, ldwTotsize, *ldwTotsize);

    for (i = 0; i < num_vals; i++)
    {
        val_list[i].ve_valuelen = 0;
        ErrorCode = RegQueryValueExW(hKey,
                                     val_list[i].ve_valuename,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &val_list[i].ve_valuelen);
        if (ErrorCode != ERROR_SUCCESS)
        {
            return ErrorCode;
         }

        if (lpValueBuf != NULL && *ldwTotsize + val_list[i].ve_valuelen <= maxBytes)
        {
            ErrorCode = RegQueryValueExW(hKey,
                                         val_list[i].ve_valuename,
                                         NULL,
                                         &val_list[i].ve_type,
                                         (LPBYTE)bufptr,
                                         &val_list[i].ve_valuelen);
            if (ErrorCode != ERROR_SUCCESS)
            {
                return ErrorCode;
            }

            val_list[i].ve_valueptr = (DWORD_PTR)bufptr;

            bufptr += val_list[i].ve_valuelen;
        }

        *ldwTotsize += val_list[i].ve_valuelen;
    }

    return (lpValueBuf != NULL && *ldwTotsize <= maxBytes) ? ERROR_SUCCESS : ERROR_MORE_DATA;
}


/************************************************************************
 *  RegQueryReflectionKey
 *
 * @unimplemented
 */
LONG WINAPI
RegQueryReflectionKey(IN HKEY hBase,
                      OUT BOOL* bIsReflectionDisabled)
{
    FIXME("RegQueryReflectionKey(0x%p, 0x%p) UNIMPLEMENTED!\n",
          hBase, bIsReflectionDisabled);
    return ERROR_CALL_NOT_IMPLEMENTED;
}


/******************************************************************************
 * RegQueryValueExA   [ADVAPI32.@]
 *
 * Get the type and contents of a specified value under with a key.
 *
 * PARAMS
 *  hkey      [I]   Handle of the key to query
 *  name      [I]   Name of value under hkey to query
 *  reserved  [I]   Reserved - must be NULL
 *  type      [O]   Destination for the value type, or NULL if not required
 *  data      [O]   Destination for the values contents, or NULL if not required
 *  count     [I/O] Size of data, updated with the number of bytes returned
 *
 * RETURNS
 *  Success: ERROR_SUCCESS. *count is updated with the number of bytes copied to data.
 *  Failure: ERROR_INVALID_HANDLE, if hkey is invalid.
 *           ERROR_INVALID_PARAMETER, if any other parameter is invalid.
 *           ERROR_MORE_DATA, if on input *count is too small to hold the contents.
 *
 * NOTES
 *   MSDN states that if data is too small it is partially filled. In reality
 *   it remains untouched.
 */
LONG
WINAPI
RegQueryValueExA(
    _In_ HKEY hkeyorg,
    _In_ LPCSTR name,
    _In_ LPDWORD reserved,
    _Out_opt_ LPDWORD type,
    _Out_opt_ LPBYTE data,
    _Inout_opt_ LPDWORD count)
{
    UNICODE_STRING nameW;
    DWORD DataLength;
    DWORD ErrorCode;
    DWORD BufferSize = 0;
    WCHAR* Buffer;
    CHAR* DataStr = (CHAR*)data;
    DWORD LocalType;

    /* Validate those parameters, the rest will be done with the first RegQueryValueExW call */
    if ((data && !count) || reserved)
        return ERROR_INVALID_PARAMETER;

    /* The performance data is not in the registry. Without a value name, ANSI callers get "Global". */
    if (RegpIsPerformanceKey(hkeyorg))
    {
        ULONG NameLength;
        PWSTR NameBuffer = NULL;

        if (name)
        {
            NameLength = (ULONG)strlen(name);
            if (NameLength > 0xFFFF / sizeof(WCHAR) - 1)
                return ERROR_INVALID_PARAMETER;

            NameBuffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, (NameLength + 1) * sizeof(WCHAR));
            if (!NameBuffer)
                return ERROR_NOT_ENOUGH_MEMORY;
            RtlMultiByteToUnicodeN(NameBuffer, NameLength * sizeof(WCHAR), NULL, name, NameLength);
            NameBuffer[NameLength] = UNICODE_NULL;
        }

        ErrorCode = RegpQueryPerformanceValue(hkeyorg, NameBuffer, TRUE, type, data, count);
        if (NameBuffer)
            RtlFreeHeap(RtlGetProcessHeap(), 0, NameBuffer);
        return ErrorCode;
    }

    if (name)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&nameW, name))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
        RtlInitEmptyUnicodeString(&nameW, NULL, 0);

    ErrorCode = RegQueryValueExW(hkeyorg, nameW.Buffer, NULL, &LocalType, NULL, &BufferSize);
    if (ErrorCode != ERROR_SUCCESS)
    {
        if ((!data) && count)
            *count = 0;
        RtlFreeUnicodeString(&nameW);
        return ErrorCode;
    }

    /* See if we can directly handle the call without caring for conversion */
    if (!is_string(LocalType) || !count)
    {
        ErrorCode = RegQueryValueExW(hkeyorg, nameW.Buffer, reserved, type, data, count);
        RtlFreeUnicodeString(&nameW);
        return ErrorCode;
    }

    /* Allocate a unicode string to get the data */
    Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, BufferSize);
    if (!Buffer)
    {
        RtlFreeUnicodeString(&nameW);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    ErrorCode = RegQueryValueExW(hkeyorg, nameW.Buffer, reserved, type, (LPBYTE)Buffer, &BufferSize);
    if (ErrorCode != ERROR_SUCCESS)
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        RtlFreeUnicodeString(&nameW);
        return ErrorCode;
    }

    /* We don't need this anymore */
    RtlFreeUnicodeString(&nameW);

    /* Get the length for the multi-byte string (without the terminating NULL!) */
    DataLength = *count;
    RtlUnicodeToMultiByteSize(count, Buffer, BufferSize);

    if ((!data) || (DataLength < *count))
    {
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        return  data ? ERROR_MORE_DATA : ERROR_SUCCESS;
    }

    /* We can finally do the conversion */
    RtlUnicodeToMultiByteN(DataStr, DataLength, NULL, Buffer, BufferSize);

    /* NULL-terminate if there is enough room */
    if (DataLength > *count)
        DataStr[*count] = '\0';

    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegQueryValueExW
 *
 * @implemented
 */
LONG
WINAPI
RegQueryValueExW(
    _In_ HKEY hkeyorg,
    _In_ LPCWSTR name,
    _In_ LPDWORD reserved,
    _In_ LPDWORD type,
    _In_ LPBYTE data,
    _In_ LPDWORD count)
{
    HANDLE hkey;
    NTSTATUS status;
    UNICODE_STRING name_str;
    DWORD total_size;
    char buffer[256], *buf_ptr = buffer;
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)buffer;
    static const int info_size = offsetof( KEY_VALUE_PARTIAL_INFORMATION, Data );

    TRACE("(%p,%s,%p,%p,%p,%p=%d)\n",
          hkeyorg, debugstr_w(name), reserved, type, data, count,
          (count && data) ? *count : 0 );

    if ((data && !count) || reserved) return ERROR_INVALID_PARAMETER;

    /* The performance data is not in the registry */
    if (RegpIsPerformanceKey(hkeyorg))
    {
        if (!name) return ERROR_INVALID_PARAMETER;
        return RegpQueryPerformanceValue(hkeyorg, name, FALSE, type, data, count);
    }

    status = MapDefaultKey(&hkey, hkeyorg);
    if (!NT_SUCCESS(status))
    {
        return RtlNtStatusToDosError(status);
    }

    if (IsHKCRKey(hkey))
    {
        LONG ErrorCode = QueryHKCRValue(hkey, name, reserved, type, data, count);
        ClosePredefKey(hkey);
        return ErrorCode;
    }

    RtlInitUnicodeString( &name_str, name );

    if (data)
        total_size = min( sizeof(buffer), *count + info_size );
    else
        total_size = info_size;


    status = NtQueryValueKey( hkey, &name_str, KeyValuePartialInformation,
                              buffer, total_size, &total_size );

    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW)
    {
        // NT: Valid handles with inexistant/null values or invalid (but not NULL) handles sets type to REG_NONE
        // On windows these conditions are likely to be side effects of the implementation...
        if (status == STATUS_INVALID_HANDLE && hkey)
        {
            if (type) *type = REG_NONE;
            if (count) *count = 0;
        }
        else if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        {
            if (type) *type = REG_NONE;
            if (data == NULL && count) *count = 0;
        }
        goto done;
    }

    if (data)
    {
        /* retry with a dynamically allocated buffer */
        while (status == STATUS_BUFFER_OVERFLOW && total_size - info_size <= *count)
        {
            if (buf_ptr != buffer) HeapFree( GetProcessHeap(), 0, buf_ptr );
            if (!(buf_ptr = HeapAlloc( GetProcessHeap(), 0, total_size )))
            {
                ClosePredefKey(hkey);
                return ERROR_NOT_ENOUGH_MEMORY;
            }
            info = (KEY_VALUE_PARTIAL_INFORMATION *)buf_ptr;
            status = NtQueryValueKey( hkey, &name_str, KeyValuePartialInformation,
                                      buf_ptr, total_size, &total_size );
        }

        if (NT_SUCCESS(status))
        {
            memcpy( data, buf_ptr + info_size, total_size - info_size );
            /* if the type is REG_SZ and data is not 0-terminated
             * and there is enough space in the buffer NT appends a \0 */
            if (is_string(info->Type) &&
                total_size - info_size >= sizeof(WCHAR) &&
                *count >= sizeof(WCHAR) &&
                total_size - info_size <= *count - sizeof(WCHAR))
            {
                WCHAR *ptr = (WCHAR *)(data + total_size - info_size);
                if (ptr[-1]) *ptr = 0;
            }
        }
        else if (status != STATUS_BUFFER_OVERFLOW) goto done;
    }
    else status = STATUS_SUCCESS;

    if (type) *type = info->Type;
    if (count) *count = total_size - info_size;

 done:
    if (buf_ptr != buffer) HeapFree( GetProcessHeap(), 0, buf_ptr );
    ClosePredefKey(hkey);
    return RtlNtStatusToDosError(status);
}


/************************************************************************
 *  RegQueryValueA
 *
 * @implemented
 */
LSTATUS WINAPI RegQueryValueA( HKEY hkey, LPCSTR name, LPSTR data, LPLONG count )
{
    DWORD ret;
    HKEY subkey = hkey;

    TRACE("(%p,%s,%p,%d)\n", hkey, debugstr_a(name), data, count ? *count : 0 );

    if (name && name[0])
    {
    if ((ret = RegOpenKeyA( hkey, name, &subkey )) != ERROR_SUCCESS) return ret;
    }
    ret = RegQueryValueExA( subkey, NULL, NULL, NULL, (LPBYTE)data, (LPDWORD)count );
    if (subkey != hkey) RegCloseKey( subkey );
    if (ret == ERROR_FILE_NOT_FOUND)
    {
    /* return empty string if default value not found */
    if (data) *data = 0;
    if (count) *count = 1;
    ret = ERROR_SUCCESS;
    }
    return ret;
}


/************************************************************************
 *  RegQueryValueW
 *
 * @implemented
 */
LSTATUS WINAPI RegQueryValueW( HKEY hkey, LPCWSTR name, LPWSTR data, LPLONG count )
{
    DWORD ret;
    HKEY subkey = hkey;

    TRACE("(%p,%s,%p,%d)\n", hkey, debugstr_w(name), data, count ? *count : 0 );
    if (hkey == NULL)
    {
       return ERROR_INVALID_HANDLE;
    }
    if (name && name[0])
    {
        ret = RegOpenKeyW( hkey, name, &subkey);
        if (ret != ERROR_SUCCESS)
        {
            return ret;
        }
    }

    ret = RegQueryValueExW( subkey, NULL, NULL, NULL, (LPBYTE)data, (LPDWORD)count );

    if (subkey != hkey)
    {
        RegCloseKey( subkey );
    }

    if (ret == ERROR_FILE_NOT_FOUND)
    {
        /* return empty string if default value not found */
        if (data)
            *data = 0;
        if (count)
            *count = sizeof(WCHAR);
        ret = ERROR_SUCCESS;
    }
    return ret;
}


/************************************************************************
 *  RegRenameKey
 *
 * @implemented
 */
LSTATUS
WINAPI
RegRenameKey(
    _In_ HKEY hKey,
    _In_opt_ LPCWSTR lpSubKeyName,
    _In_ LPCWSTR lpNewKeyName)
{
    UNICODE_STRING NewName;
    HKEY KeyHandle = hKey;
    NTSTATUS Status;
    LONG ErrorCode;

    TRACE("RegRenameKey(%p, %S, %S)\n", hKey, lpSubKeyName, lpNewKeyName);

    /*
     * As on Windows: a subkey name, even an empty one, is opened for KEY_WRITE
     * (the caller's handle needs no more than the right to open it); without
     * one the handle itself is renamed, and a predefined handle is not mapped
     * to its key (ERROR_INVALID_HANDLE). The rename itself is NtRenameKey's.
     */
    if (lpSubKeyName)
    {
        ErrorCode = RegOpenKeyExW(hKey, lpSubKeyName, 0, KEY_WRITE, &KeyHandle);
        if (ErrorCode != ERROR_SUCCESS)
            return ErrorCode;
    }

    RtlInitUnicodeString(&NewName, lpNewKeyName);
    Status = NtRenameKey((HANDLE)KeyHandle, &NewName);

    if (KeyHandle != hKey)
        RegCloseKey(KeyHandle);

    return RtlNtStatusToDosError(Status);
}


/************************************************************************
 *  RegReplaceKeyA
 *
 * @implemented
 */
LONG WINAPI
RegReplaceKeyA(HKEY hKey,
               LPCSTR lpSubKey,
               LPCSTR lpNewFile,
               LPCSTR lpOldFile)
{
    UNICODE_STRING SubKey;
    UNICODE_STRING NewFile;
    UNICODE_STRING OldFile;
    LONG ErrorCode;

    RtlInitEmptyUnicodeString(&SubKey, NULL, 0);
    RtlInitEmptyUnicodeString(&OldFile, NULL, 0);
    RtlInitEmptyUnicodeString(&NewFile, NULL, 0);

    if (lpSubKey)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&SubKey, lpSubKey))
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    if (lpOldFile)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&OldFile, lpOldFile))
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    if (lpNewFile)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&NewFile, lpNewFile))
        {
            ErrorCode = ERROR_NOT_ENOUGH_MEMORY;
            goto Exit;
        }
    }

    ErrorCode = RegReplaceKeyW(hKey,
                               SubKey.Buffer,
                               NewFile.Buffer,
                               OldFile.Buffer);

Exit:
    RtlFreeUnicodeString(&OldFile);
    RtlFreeUnicodeString(&NewFile);
    RtlFreeUnicodeString(&SubKey);

    return ErrorCode;
}


/************************************************************************
 *  RegReplaceKeyW
 *
 * @unimplemented
 */
LONG WINAPI
RegReplaceKeyW(HKEY hKey,
               LPCWSTR lpSubKey,
               LPCWSTR lpNewFile,
               LPCWSTR lpOldFile)
{
    OBJECT_ATTRIBUTES KeyObjectAttributes;
    OBJECT_ATTRIBUTES NewObjectAttributes;
    OBJECT_ATTRIBUTES OldObjectAttributes;
    UNICODE_STRING SubKeyName;
    UNICODE_STRING NewFileName;
    UNICODE_STRING OldFileName;
    BOOLEAN CloseRealKey;
    HANDLE RealKeyHandle;
    HANDLE KeyHandle;
    NTSTATUS Status;
    LONG ErrorCode = ERROR_SUCCESS;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_INVALID_HANDLE;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    /* Open the real key */
    if (lpSubKey != NULL && *lpSubKey != (WCHAR)0)
    {
        RtlInitUnicodeString(&SubKeyName, lpSubKey);
        InitializeObjectAttributes(&KeyObjectAttributes,
                                   &SubKeyName,
                                   OBJ_CASE_INSENSITIVE,
                                   KeyHandle,
                                   NULL);
        Status = NtOpenKey(&RealKeyHandle,
                           MAXIMUM_ALLOWED,
                           &KeyObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            ErrorCode = RtlNtStatusToDosError(Status);
            goto Cleanup;
        }

        CloseRealKey = TRUE;
    }
    else
    {
        RealKeyHandle = KeyHandle;
        CloseRealKey = FALSE;
    }

    /* Convert new file name */
    if (!RtlDosPathNameToNtPathName_U(lpNewFile,
                                      &NewFileName,
                                      NULL,
                                      NULL))
    {
        if (CloseRealKey)
        {
            NtClose(RealKeyHandle);
        }

        ErrorCode = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    InitializeObjectAttributes(&NewObjectAttributes,
                               &NewFileName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    /* Convert old file name */
    if (!RtlDosPathNameToNtPathName_U(lpOldFile,
                                      &OldFileName,
                                      NULL,
                                      NULL))
    {
        RtlFreeHeap(RtlGetProcessHeap (),
                    0,
                    NewFileName.Buffer);
        if (CloseRealKey)
        {
            NtClose(RealKeyHandle);
        }

        ErrorCode = ERROR_INVALID_PARAMETER;
        goto Cleanup;
    }

    InitializeObjectAttributes(&OldObjectAttributes,
                               &OldFileName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtReplaceKey(&NewObjectAttributes,
                          RealKeyHandle,
                          &OldObjectAttributes);

    RtlFreeHeap(RtlGetProcessHeap(),
                0,
                OldFileName.Buffer);
    RtlFreeHeap(RtlGetProcessHeap(),
                0,
                NewFileName.Buffer);

    if (CloseRealKey)
    {
        NtClose(RealKeyHandle);
    }

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

Cleanup:
    ClosePredefKey(KeyHandle);

    return ErrorCode;
}


/************************************************************************
 *  RegRestoreKeyA
 *
 * @implemented
 */
LONG WINAPI
RegRestoreKeyA(HKEY hKey,
               LPCSTR lpFile,
               DWORD dwFlags)
{
    UNICODE_STRING FileName;
    LONG ErrorCode;

    if (lpFile)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&FileName, lpFile))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
        RtlInitEmptyUnicodeString(&FileName, NULL, 0);

    ErrorCode = RegRestoreKeyW(hKey,
                               FileName.Buffer,
                               dwFlags);

    RtlFreeUnicodeString(&FileName);

    return ErrorCode;
}


/************************************************************************
 *  RegRestoreKeyW
 *
 * @implemented
 */
LONG WINAPI
RegRestoreKeyW(HKEY hKey,
               LPCWSTR lpFile,
               DWORD dwFlags)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING FileName;
    HANDLE FileHandle;
    HANDLE KeyHandle;
    NTSTATUS Status;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_INVALID_HANDLE;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (!RtlDosPathNameToNtPathName_U(lpFile,
                                      &FileName,
                                      NULL,
                                      NULL))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               &FileName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtOpenFile(&FileHandle,
                        FILE_GENERIC_READ,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    RtlFreeHeap(RtlGetProcessHeap(),
                0,
                FileName.Buffer);
    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

    Status = NtRestoreKey(KeyHandle,
                          FileHandle,
                          (ULONG)dwFlags);
    NtClose (FileHandle);

Cleanup:
    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegSaveKeyA
 *
 * @implemented
 */
LONG WINAPI
RegSaveKeyA(HKEY hKey,
            LPCSTR lpFile,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    UNICODE_STRING FileName;
    LONG ErrorCode;

    if (lpFile)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&FileName, lpFile))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
        RtlInitEmptyUnicodeString(&FileName, NULL, 0);

    ErrorCode = RegSaveKeyW(hKey,
                            FileName.Buffer,
                            lpSecurityAttributes);
    RtlFreeUnicodeString(&FileName);

    return ErrorCode;
}


/************************************************************************
 *  RegSaveKeyW
 *
 * @implemented
 */
LONG WINAPI
RegSaveKeyW(HKEY hKey,
            LPCWSTR lpFile,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING FileName;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;
    HANDLE KeyHandle;
    NTSTATUS Status;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (!RtlDosPathNameToNtPathName_U(lpFile,
                                      &FileName,
                                      NULL,
                                      NULL))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    if (lpSecurityAttributes != NULL)
    {
        SecurityDescriptor = lpSecurityAttributes->lpSecurityDescriptor;
    }

    InitializeObjectAttributes(&ObjectAttributes,
                               &FileName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               SecurityDescriptor);
    Status = NtCreateFile(&FileHandle,
                          GENERIC_WRITE | SYNCHRONIZE,
                          &ObjectAttributes,
                          &IoStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ,
                          FILE_CREATE,
                          FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT,
                          NULL,
                          0);
    RtlFreeHeap(RtlGetProcessHeap(),
                0,
                FileName.Buffer);
    if (!NT_SUCCESS(Status))
    {
        goto Cleanup;
    }

    Status = NtSaveKey(KeyHandle,
                       FileHandle);
    NtClose (FileHandle);

Cleanup:
    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegSaveKeyExA
 *
 * @implemented
 */
LONG
WINAPI
RegSaveKeyExA(HKEY hKey,
              LPCSTR lpFile,
              LPSECURITY_ATTRIBUTES lpSecurityAttributes,
              DWORD Flags)
{
    UNICODE_STRING FileName;
    LONG ErrorCode;

    if (lpFile)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&FileName, lpFile))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
        RtlInitEmptyUnicodeString(&FileName, NULL, 0);

    ErrorCode = RegSaveKeyExW(hKey,
                              FileName.Buffer,
                              lpSecurityAttributes,
                              Flags);
    RtlFreeUnicodeString(&FileName);

    return ErrorCode;
}


/************************************************************************
 *  RegSaveKeyExW
 *
 * @unimplemented
 */
LONG
WINAPI
RegSaveKeyExW(HKEY hKey,
              LPCWSTR lpFile,
              LPSECURITY_ATTRIBUTES lpSecurityAttributes,
              DWORD Flags)
{
    switch (Flags)
    {
        case REG_STANDARD_FORMAT:
        case REG_LATEST_FORMAT:
        case REG_NO_COMPRESSION:
            break;
        default:
            return ERROR_INVALID_PARAMETER;
    }

    FIXME("RegSaveKeyExW(): Flags ignored!\n");

    return RegSaveKeyW(hKey,
                       lpFile,
                       lpSecurityAttributes);
}


/************************************************************************
 *  RegSetKeySecurity
 *
 * @implemented
 */
LONG WINAPI
RegSetKeySecurity(HKEY hKey,
                  SECURITY_INFORMATION SecurityInformation,
                  PSECURITY_DESCRIPTOR pSecurityDescriptor)
{
    HANDLE KeyHandle;
    NTSTATUS Status;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
        return ERROR_INVALID_HANDLE;
    }

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    Status = NtSetSecurityObject(KeyHandle,
                                 SecurityInformation,
                                 pSecurityDescriptor);

    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegSetValueExA
 *
 * @implemented
 */
LONG WINAPI
RegSetValueExA(HKEY hKey,
               LPCSTR lpValueName,
               DWORD Reserved,
               DWORD dwType,
               CONST BYTE* lpData,
               DWORD cbData)
{
    UNICODE_STRING ValueName;
    LPWSTR pValueName;
    ANSI_STRING AnsiString;
    UNICODE_STRING Data;
    LONG ErrorCode;
    LPBYTE pData;
    DWORD DataSize;
    NTSTATUS Status;

    /* Convert SubKey name to Unicode */
    if (lpValueName != NULL && lpValueName[0] != '\0')
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&ValueName, lpValueName))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
    {
        ValueName.Buffer = NULL;
    }

    pValueName = (LPWSTR)ValueName.Buffer;


    if (is_string(dwType) && (cbData != 0))
    {
        /* Convert ANSI string Data to Unicode */
        /* If last character NOT zero then increment length */
        LONG bNoNulledStr = ((lpData[cbData-1] != '\0') ? 1 : 0);
        AnsiString.Buffer = (PSTR)lpData;
        AnsiString.Length = cbData + bNoNulledStr;
        AnsiString.MaximumLength = cbData + bNoNulledStr;
        Status = RtlAnsiStringToUnicodeString(&Data,
                                     &AnsiString,
                                     TRUE);

        if (!NT_SUCCESS(Status))
        {
            if (pValueName != NULL)
                RtlFreeUnicodeString(&ValueName);

            return RtlNtStatusToDosError(Status);
        }
        pData = (LPBYTE)Data.Buffer;
        DataSize = cbData * sizeof(WCHAR);
    }
    else
    {
        Data.Buffer = NULL;
        pData = (LPBYTE)lpData;
        DataSize = cbData;
    }

    ErrorCode = RegSetValueExW(hKey,
                               pValueName,
                               Reserved,
                               dwType,
                               pData,
                               DataSize);

    if (pValueName != NULL)
        RtlFreeUnicodeString(&ValueName);

    if (Data.Buffer != NULL)
        RtlFreeUnicodeString(&Data);

    return ErrorCode;
}


/************************************************************************
 *  RegSetValueExW
 *
 * @implemented
 */
LONG
WINAPI
RegSetValueExW(
    _In_ HKEY hKey,
    _In_ LPCWSTR lpValueName,
    _In_ DWORD Reserved,
    _In_ DWORD dwType,
    _In_ CONST BYTE* lpData,
    _In_ DWORD cbData)
{
    UNICODE_STRING ValueName;
    HANDLE KeyHandle;
    NTSTATUS Status;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (IsHKCRKey(KeyHandle))
    {
        LONG ErrorCode = SetHKCRValue(KeyHandle, lpValueName, Reserved, dwType, lpData, cbData);
        ClosePredefKey(KeyHandle);
        return ErrorCode;
    }

    if (is_string(dwType) && (cbData != 0))
    {
        PWSTR pwsData = (PWSTR)lpData;

        _SEH2_TRY
        {
            if((pwsData[cbData / sizeof(WCHAR) - 1] != L'\0') &&
                (pwsData[cbData / sizeof(WCHAR)] == L'\0'))
            {
                /* Increment length if last character is not zero and next is zero */
                cbData += sizeof(WCHAR);
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            /* Do not fail if we fault where we were told not to go */
        }
        _SEH2_END;
    }

    RtlInitUnicodeString(&ValueName, lpValueName);

    Status = NtSetValueKey(KeyHandle,
                           &ValueName,
                           0,
                           dwType,
                           (PVOID)lpData,
                           (ULONG)cbData);

    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}


/************************************************************************
 *  RegSetValueA
 *
 * @implemented
 */
LONG WINAPI
RegSetValueA(HKEY hKeyOriginal,
             LPCSTR lpSubKey,
             DWORD dwType,
             LPCSTR lpData,
             DWORD cbData)
{
    HKEY subkey;
    HANDLE hKey;
    DWORD ret;
    NTSTATUS Status;

    TRACE("(%p,%s,%d,%s,%d)\n", hKeyOriginal, debugstr_a(lpSubKey), dwType, debugstr_a(lpData), cbData );

    if (dwType != REG_SZ || !lpData) return ERROR_INVALID_PARAMETER;

    Status = MapDefaultKey(&hKey, hKeyOriginal);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError (Status);
    }
    subkey = hKey;

    if (lpSubKey && lpSubKey[0])  /* need to create the subkey */
    {
        ret = RegCreateKeyA(hKey, lpSubKey, &subkey);
        if (ret != ERROR_SUCCESS)
            goto Cleanup;
    }

    ret = RegSetValueExA( subkey, NULL, 0, REG_SZ, (const BYTE*)lpData, strlen(lpData)+1 );
    if (subkey != hKey)
        RegCloseKey(subkey);

Cleanup:
    ClosePredefKey(hKey);

    return ret;
}


/************************************************************************
 *  RegSetValueW
 *
 * @implemented
 */
LONG WINAPI
RegSetValueW(HKEY hKeyOriginal,
             LPCWSTR lpSubKey,
             DWORD dwType,
             LPCWSTR lpData,
             DWORD cbData)
{
    HKEY subkey;
    HANDLE hKey;
    DWORD ret;
    NTSTATUS Status;

    TRACE("(%p,%s,%d,%s,%d)\n", hKeyOriginal, debugstr_w(lpSubKey), dwType, debugstr_w(lpData), cbData );

    if (dwType != REG_SZ || !lpData)
        return ERROR_INVALID_PARAMETER;

    Status = MapDefaultKey(&hKey,
                           hKeyOriginal);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }
    subkey = hKey;

    if (lpSubKey && lpSubKey[0])  /* need to create the subkey */
    {
        ret = RegCreateKeyW(hKey, lpSubKey, &subkey);
        if (ret != ERROR_SUCCESS)
            goto Cleanup;
    }

    ret = RegSetValueExW( subkey, NULL, 0, REG_SZ, (const BYTE*)lpData,
                          (wcslen( lpData ) + 1) * sizeof(WCHAR) );
    if (subkey != hKey)
        RegCloseKey(subkey);

Cleanup:
    ClosePredefKey(hKey);

    return ret;
}


/************************************************************************
 *  RegUnLoadKeyA
 *
 * @implemented
 */
LONG WINAPI
RegUnLoadKeyA(HKEY hKey,
              LPCSTR lpSubKey)
{
    UNICODE_STRING KeyName;
    DWORD ErrorCode;

    if (lpSubKey)
    {
        if (!RtlCreateUnicodeStringFromAsciiz(&KeyName, lpSubKey))
            return ERROR_NOT_ENOUGH_MEMORY;
    }
    else
        RtlInitEmptyUnicodeString(&KeyName, NULL, 0);

    ErrorCode = RegUnLoadKeyW(hKey,
                              KeyName.Buffer);

    RtlFreeUnicodeString (&KeyName);

    return ErrorCode;
}


/************************************************************************
 *  RegUnLoadKeyW
 *
 * @implemented
 */
LONG WINAPI
RegUnLoadKeyW(HKEY hKey,
              LPCWSTR lpSubKey)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName;
    HANDLE KeyHandle;
    NTSTATUS Status;

    if (hKey == HKEY_PERFORMANCE_DATA)
    {
      return ERROR_INVALID_HANDLE;
    }

    Status = MapDefaultKey(&KeyHandle, hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    RtlInitUnicodeString(&KeyName, lpSubKey);

    InitializeObjectAttributes(&ObjectAttributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               KeyHandle,
                               NULL);

    Status = NtUnloadKey(&ObjectAttributes);

    ClosePredefKey(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    return ERROR_SUCCESS;
}

#endif // _ADVAPI32_VISTA_

#ifndef LOAD_LIBRARY_AS_IMAGE_RESOURCE
#define LOAD_LIBRARY_AS_IMAGE_RESOURCE 0x00000020
#endif

/******************************************************************************
 * find_mui_string [Internal]
 *
 * Locates string resource resId in the string table of hModule (the length-prefixed
 * layout of RT_STRING blocks). Returns the length in characters, 0 with *pError set on failure.
 * Not user32's LoadStringW: advapi32 must not import user32.
 */
static DWORD find_mui_string(HMODULE hModule, UINT resId, const WCHAR **ppString, LONG *pError)
{
    HRSRC hResource;
    HGLOBAL hMemory;
    const WCHAR *pString;
    UINT idxString;

    hResource = FindResourceW(hModule, MAKEINTRESOURCEW((resId >> 4) + 1), (LPWSTR)RT_STRING);
    if (!hResource)
    {
        *pError = GetLastError();
        return 0;
    }
    hMemory = LoadResource(hModule, hResource);
    pString = hMemory ? LockResource(hMemory) : NULL;
    if (!pString)
    {
        *pError = GetLastError();
        return 0;
    }

    /* Strings are length-prefixed; the lowest nibble of resId is the index in the block. */
    for (idxString = resId & 0xf; idxString; idxString--)
        pString += *pString + 1;

    if (!*pString)
    {
        *pError = ERROR_NOT_FOUND;
        return 0;
    }
    *ppString = pString + 1;
    return *pString;
}

/******************************************************************************
 * load_mui_string [Internal]
 *
 * Helper for RegLoadMUIStringW: loads string resId of the module file_name into the buffer.
 * *pcchRequired is the length including the terminating NUL.
 */
static LONG load_mui_string(LPCWSTR file_name, UINT resId, LPWSTR buffer, DWORD cchBuffer,
                            DWORD *pcchRequired, DWORD flags)
{
    const WCHAR *string = NULL;
    HMODULE hModule;
    WCHAR *full_name;
    DWORD size, cchCopy;
    LONG result;

    /* Verify the file existence, i.e. do not rely on the PATH variable */
    if (GetFileAttributesW(file_name) == INVALID_FILE_ATTRIBUTES)
        return ERROR_FILE_NOT_FOUND;

    size = GetFullPathNameW(file_name, 0, NULL, NULL);
    if (!size)
        return GetLastError();
    full_name = HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
    if (!full_name)
        return ERROR_NOT_ENOUGH_MEMORY;
    GetFullPathNameW(file_name, size, full_name, NULL);

    hModule = LoadLibraryExW(full_name, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    HeapFree(GetProcessHeap(), 0, full_name);
    if (!hModule)
        return GetLastError();

    result = ERROR_SUCCESS;
    size = find_mui_string(hModule, resId, &string, &result);
    if (!size)
        goto cleanup;

    *pcchRequired = size + 1;

    /* No buffer: report the size only. */
    if (!buffer)
    {
        result = ERROR_MORE_DATA;
        goto cleanup;
    }

    cchCopy = cchBuffer;
    if (size < cchBuffer)
    {
        cchCopy = size;
    }
    else if (flags & REG_MUI_STRING_TRUNCATE)
    {
        if (cchCopy)
            cchCopy--;
    }
    else
    {
        result = ERROR_MORE_DATA;
        goto cleanup;
    }

    if (cchBuffer)
    {
        memcpy(buffer, string, cchCopy * sizeof(WCHAR));
        buffer[cchCopy] = L'\0';
    }

cleanup:
    FreeLibrary(hModule);
    return result;
}

/************************************************************************
 *  RegLoadMUIStringW
 *
 * Loads the localized string of a registry value of the form
 * "@[path\]dllname,-resourceId" (REG_SZ or REG_EXPAND_SZ; environment
 * variables are expanded in both). A value that does not start with '@' is
 * ERROR_INVALID_DATA, as on Windows.
 *
 * pcbData receives the size in bytes of the string including the NUL (also
 * with ERROR_MORE_DATA). Flags: REG_MUI_STRING_TRUNCATE only, and not
 * together with pcbData. pszDirectory is prepended to the module path.
 *
 * @implemented
 */
LONG WINAPI
RegLoadMUIStringW(
    IN HKEY hKey,
    IN LPCWSTR pszValue  OPTIONAL,
    OUT LPWSTR pszOutBuf,
    IN DWORD cbOutBuf,
    OUT LPDWORD pcbData OPTIONAL,
    IN DWORD Flags,
    IN LPCWSTR pszDirectory  OPTIONAL)
{
    DWORD dwValueType, cbData;
    LPWSTR pwszTempBuffer = NULL, pwszExpandedBuffer = NULL;
    LONG result;

    /* Parameter sanity checks. */
    if (!hKey || (!pszOutBuf && cbOutBuf) || (cbOutBuf % sizeof(WCHAR)) ||
        ((Flags & REG_MUI_STRING_TRUNCATE) && pcbData) || (Flags & ~REG_MUI_STRING_TRUNCATE))
        return ERROR_INVALID_PARAMETER;

    /* Check for value existence and correctness of its type, allocate a buffer and load it. */
    result = RegQueryValueExW(hKey, pszValue, NULL, &dwValueType, NULL, &cbData);
    if (result != ERROR_SUCCESS) goto cleanup;
    if (!(dwValueType == REG_SZ || dwValueType == REG_EXPAND_SZ) || !cbData)
    {
        result = ERROR_FILE_NOT_FOUND;
        goto cleanup;
    }
    /* room for a terminator the registry may have left out */
    pwszTempBuffer = HeapAlloc(GetProcessHeap(), 0, cbData + sizeof(WCHAR));
    if (!pwszTempBuffer)
    {
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }
    result = RegQueryValueExW(hKey, pszValue, NULL, &dwValueType, (LPBYTE)pwszTempBuffer, &cbData);
    if (result != ERROR_SUCCESS) goto cleanup;
    pwszTempBuffer[cbData / sizeof(WCHAR)] = L'\0';

    /* '@' is the prefix for resource based string entries. */
    if (*pwszTempBuffer != L'@')
    {
        result = ERROR_INVALID_DATA;
        goto cleanup;
    }

    /* Expand environment variables regardless of the type. */
    cbData = ExpandEnvironmentStringsW(pwszTempBuffer, NULL, 0) * sizeof(WCHAR);
    if (!cbData)
    {
        result = GetLastError();
        goto cleanup;
    }
    pwszExpandedBuffer = HeapAlloc(GetProcessHeap(), 0, cbData);
    if (!pwszExpandedBuffer)
    {
        result = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }
    ExpandEnvironmentStringsW(pwszTempBuffer, pwszExpandedBuffer, cbData / sizeof(WCHAR));

    /* Parse the value and load the string. */
    {
        WCHAR *pComma = wcsrchr(pwszExpandedBuffer, L','), *pNewBuffer;
        UINT uiStringId;
        SIZE_T baseDirLen;
        DWORD cchRequired = 0;

        /* Format of the expanded value is 'path_to_dll,-resId' */
        if (!pComma || pComma[1] != L'-')
        {
            result = ERROR_INVALID_DATA;
            goto cleanup;
        }

        uiStringId = (UINT)wcstol(pComma + 2, NULL, 10);
        *pComma = L'\0';

        /* Build the resource dll path. */
        baseDirLen = pszDirectory ? wcslen(pszDirectory) : 0;
        cbData = (DWORD)((baseDirLen + 1 + wcslen(pwszExpandedBuffer + 1) + 1) * sizeof(WCHAR));
        pNewBuffer = HeapReAlloc(GetProcessHeap(), 0, pwszTempBuffer, cbData);
        if (!pNewBuffer)
        {
            result = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }
        pwszTempBuffer = pNewBuffer;
        pwszTempBuffer[0] = L'\0';
        if (baseDirLen)
        {
            wcscpy(pwszTempBuffer, pszDirectory);
            if (pszDirectory[baseDirLen - 1] != L'\\')
                wcscat(pwszTempBuffer, L"\\");
        }
        wcscat(pwszTempBuffer, pwszExpandedBuffer + 1);

        result = load_mui_string(pwszTempBuffer, uiStringId, pszOutBuf, cbOutBuf / sizeof(WCHAR),
                                 &cchRequired, Flags);
        if (pcbData && (result == ERROR_SUCCESS || result == ERROR_MORE_DATA))
            *pcbData = cchRequired * sizeof(WCHAR);
    }

cleanup:
    HeapFree(GetProcessHeap(), 0, pwszTempBuffer);
    HeapFree(GetProcessHeap(), 0, pwszExpandedBuffer);
    return result;
}

/************************************************************************
 *  RegLoadMUIStringA
 *
 * Not implemented on Windows either (the export exists and fails).
 *
 * @implemented
 */
LONG WINAPI
RegLoadMUIStringA(
    IN HKEY hKey,
    IN LPCSTR pszValue  OPTIONAL,
    OUT LPSTR pszOutBuf,
    IN DWORD cbOutBuf,
    OUT LPDWORD pcbData OPTIONAL,
    IN DWORD Flags,
    IN LPCSTR pszDirectory  OPTIONAL)
{
    return ERROR_CALL_NOT_IMPLEMENTED;
}

/* EOF */
