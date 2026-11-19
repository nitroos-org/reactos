/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Workstation service: the NetrUse* functions over the SMB client
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

/*
 * NetrUse*: done as the RPC client (impersonated), through the network provider ntlanman.dll and
 * the redirector's connection list, so they act on the caller's own logon session, as net use does.
 */

#include "precomp.h"
#include <winioctl.h>
#include <winnetwk.h>
#include <npapi.h>
#include <drivers/smbrdr/smbconn.h>

WINE_DEFAULT_DEBUG_CHANNEL(wkssvc);

/* lmuse.h values (its structures clash with the RPC ones of wkssvc.idl) */
#define USE_LOCAL_PARMNUM 1
#define USE_REMOTE_PARMNUM 2
#define USE_ASGTYPE_PARMNUM 4
#define USE_OK 0
#define USE_DISCONN 2
#define USE_WILDCARD ((DWORD)-1)
#define USE_DISKDEV 0
#define USE_NOFORCE 0

/* NetrUse* ******************************************************************/

typedef DWORD (APIENTRY *PFN_ADD3)(HWND, LPNETRESOURCEW, LPWSTR, LPWSTR, DWORD);
typedef DWORD (APIENTRY *PFN_CANCEL)(LPWSTR, BOOL);

static HMODULE Provider;
static PFN_ADD3 ProviderAdd;
static PFN_CANCEL ProviderCancel;

static
BOOL
LoadProvider(VOID)
{
    HMODULE Module;

    if (Provider != NULL)
        return TRUE;
    Module = LoadLibraryW(L"ntlanman.dll");
    if (Module == NULL)
        return FALSE;
    ProviderAdd = (PFN_ADD3)GetProcAddress(Module, "NPAddConnection3");
    ProviderCancel = (PFN_CANCEL)GetProcAddress(Module, "NPCancelConnection");
    if (ProviderAdd == NULL || ProviderCancel == NULL)
    {
        FreeLibrary(Module);
        return FALSE;
    }
    if (InterlockedCompareExchangePointer((PVOID *)&Provider, Module, NULL) != NULL)
        FreeLibrary(Module);
    return TRUE;
}

/* The redirector's list for the impersonated caller; HeapFree the result */
static
PSMBCONN_ENUM_OUTPUT
GetUses(DWORD *Error)
{
    PSMBCONN_ENUM_OUTPUT Out = NULL;
    DWORD Size = 4096, Got;
    HANDLE Device;
    int Tries;

    /* Opened as the impersonated caller: the driver answers for the caller's logon session */
    Device = CreateFileW(L"\\\\.\\GLOBALROOT" SMBCONN_DEVICE_NAME, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (Device == INVALID_HANDLE_VALUE)
    {
        *Error = ERROR_NO_NETWORK;
        return NULL;
    }
    *Error = ERROR_NOT_ENOUGH_MEMORY;
    for (Tries = 0; Tries < 4; Tries++)
    {
        Out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
        if (Out == NULL)
            break;
        if (DeviceIoControl(Device, IOCTL_SMBCONN_ENUM, NULL, 0, Out, Size, &Got, NULL))
        {
            *Error = ERROR_SUCCESS;
            CloseHandle(Device);
            return Out;
        }
        if (GetLastError() != ERROR_MORE_DATA)
        {
            *Error = GetLastError();
            break;
        }
        Size = Out->Needed + 1024;
        HeapFree(GetProcessHeap(), 0, Out);
        Out = NULL;
    }
    if (Out != NULL)
        HeapFree(GetProcessHeap(), 0, Out);
    CloseHandle(Device);
    return NULL;
}

static
LPWSTR
DupCounted(PSMBCONN_ENUM_OUTPUT Uses, ULONG Offset, ULONG Length)
{
    LPWSTR s = midl_user_allocate(Length + sizeof(WCHAR));

    if (s != NULL)
    {
        if (Length != 0)
            memcpy(s, (PUCHAR)Uses + Offset, Length);
        s[Length / sizeof(WCHAR)] = 0;
    }
    return s;
}

/* One USE_INFO_2 of a list entry (strings with midl_user_allocate); level 0/1 use its first part */
static
BOOL
FillUse(PSMBCONN_ENUM_OUTPUT Uses, PSMBCONN_ENTRY e, LPUSE_INFO_2 Info)
{
    WCHAR Local[3] = { e->Local, L':', 0 };
    LPWSTR User, Slash;

    ZeroMemory(Info, sizeof(*Info));
    Info->ui2_useinfo.ui1_local = midl_user_allocate(sizeof(Local));
    if (Info->ui2_useinfo.ui1_local == NULL)
        return FALSE;
    if (e->Local)
        memcpy(Info->ui2_useinfo.ui1_local, Local, sizeof(Local));
    else
        Info->ui2_useinfo.ui1_local[0] = 0;
    Info->ui2_useinfo.ui1_remote = DupCounted(Uses, e->RemoteOffset, e->RemoteLength);
    Info->ui2_useinfo.ui1_status = (e->Flags & SMBCONN_FLAG_CONNECTED) ? USE_OK : USE_DISCONN;
    Info->ui2_useinfo.ui1_asg_type = USE_DISKDEV;
    Info->ui2_useinfo.ui1_refcount = (e->Flags & SMBCONN_FLAG_TREE_CONNECTED) ? 1 : 0;
    Info->ui2_useinfo.ui1_usecount = 1;
    User = DupCounted(Uses, e->UserOffset, e->UserLength);
    if (User != NULL && (Slash = wcschr(User, L'\\')) != NULL)
    {
        *Slash = 0;
        Info->ui2_domainname = User;
        Info->ui2_username = midl_user_allocate((wcslen(Slash + 1) + 1) * sizeof(WCHAR));
        if (Info->ui2_username)
            wcscpy(Info->ui2_username, Slash + 1);
    }
    else
    {
        Info->ui2_username = User;
        Info->ui2_domainname = midl_user_allocate(sizeof(WCHAR));
        if (Info->ui2_domainname)
            Info->ui2_domainname[0] = 0;
    }
    return Info->ui2_useinfo.ui1_remote != NULL && Info->ui2_username != NULL && Info->ui2_domainname != NULL;
}

static
VOID
FreeUse(LPUSE_INFO_2 Info)
{
    midl_user_free(Info->ui2_useinfo.ui1_local);
    midl_user_free(Info->ui2_useinfo.ui1_remote);
    midl_user_free(Info->ui2_username);
    midl_user_free(Info->ui2_domainname);
}

NET_API_STATUS
WksUseAdd(DWORD Level, LPUSE_INFO_ADD InfoStruct, DWORD *ErrorParameter)
{
    LPUSE_INFO_1 Info1;
    LPWSTR User = NULL, UserName = NULL, Domain = NULL;
    NETRESOURCEW Resource;
    NET_API_STATUS Status;

    if (Level != 1 && Level != 2)
        return ERROR_INVALID_LEVEL;
    if (InfoStruct == NULL || InfoStruct->UseInfo1 == NULL)
    {
        ERR("NetrUseAdd: no structure (level %lu, union %p, arm %p)\n", Level, InfoStruct,
            InfoStruct ? (PVOID)InfoStruct->UseInfo2 : NULL);
        return ERROR_INVALID_PARAMETER;
    }
    Info1 = InfoStruct->UseInfo1;
    if (Info1->ui1_asg_type != USE_DISKDEV && Info1->ui1_asg_type != USE_WILDCARD)
    {
        if (ErrorParameter) *ErrorParameter = USE_ASGTYPE_PARMNUM;
        return ERROR_NOT_SUPPORTED;
    }
    if (Level == 2)
    {
        UserName = InfoStruct->UseInfo2->ui2_username;
        Domain = InfoStruct->UseInfo2->ui2_domainname;
    }
    if (UserName != NULL && UserName[0])
    {
        SIZE_T n = wcslen(UserName) + (Domain ? wcslen(Domain) : 0) + 2;

        User = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR));
        if (User == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
        if (Domain != NULL && Domain[0])
            _snwprintf(User, n, L"%s\\%s", Domain, UserName);
        else
            wcscpy(User, UserName);
    }
    if (!LoadProvider())
    {
        HeapFree(GetProcessHeap(), 0, User);
        return ERROR_NO_NETWORK;
    }

    ZeroMemory(&Resource, sizeof(Resource));
    Resource.dwType = RESOURCETYPE_DISK;
    Resource.lpLocalName = Info1->ui1_local;
    Resource.lpRemoteName = Info1->ui1_remote;

    /* As the caller: its logon session, its device map */
    Status = RpcImpersonateClient(NULL);
    if (Status == RPC_S_OK)
    {
        Status = ProviderAdd(NULL, &Resource, Info1->ui1_password, User, 0);
        RpcRevertToSelf();
    }
    if (Info1->ui1_password != NULL)
        SecureZeroMemory(Info1->ui1_password, wcslen(Info1->ui1_password) * sizeof(WCHAR));
    HeapFree(GetProcessHeap(), 0, User);
    if (Status != NO_ERROR)
        TRACE("NetrUseAdd %S: %lu\n", Info1->ui1_remote, Status);
    if (Status == WN_ALREADY_CONNECTED)
        Status = ERROR_ALREADY_ASSIGNED;
    else if (Status == WN_BAD_NETNAME && ErrorParameter)
        *ErrorParameter = USE_REMOTE_PARMNUM;
    else if (Status == WN_BAD_LOCALNAME && ErrorParameter)
        *ErrorParameter = USE_LOCAL_PARMNUM;
    return Status;
}

NET_API_STATUS
WksUseDel(LPWSTR UseName, DWORD ForceLevel)
{
    NET_API_STATUS Status;

    if (UseName == NULL)
        return ERROR_INVALID_PARAMETER;
    if (!LoadProvider())
        return ERROR_NO_NETWORK;
    Status = RpcImpersonateClient(NULL);
    if (Status != RPC_S_OK)
        return Status;
    Status = ProviderCancel(UseName, ForceLevel != USE_NOFORCE);
    RpcRevertToSelf();
    return Status;
}

static
BOOL
UseMatches(PSMBCONN_ENUM_OUTPUT Uses, PSMBCONN_ENTRY e, LPCWSTR Name)
{
    if (Name[0] && Name[1] == L':' && !Name[2])
        return e->Local == towupper(Name[0]);
    return e->Local == 0 && e->RemoteLength == wcslen(Name) * sizeof(WCHAR) &&
           _wcsnicmp((PCWSTR)((PUCHAR)Uses + e->RemoteOffset), Name, wcslen(Name)) == 0;
}

static
VOID
CopyLevel(DWORD Level, LPUSE_INFO_2 From, PVOID To)
{
    if (Level == 0)
    {
        ((LPUSE_INFO_0)To)->ui0_local = From->ui2_useinfo.ui1_local;
        ((LPUSE_INFO_0)To)->ui0_remote = From->ui2_useinfo.ui1_remote;
        midl_user_free(From->ui2_username);
        midl_user_free(From->ui2_domainname);
    }
    else if (Level == 1)
    {
        *(LPUSE_INFO_1)To = From->ui2_useinfo;
        midl_user_free(From->ui2_username);
        midl_user_free(From->ui2_domainname);
    }
    else
    {
        *(LPUSE_INFO_2)To = *From;
    }
}

NET_API_STATUS
WksUseGetInfo(LPWSTR UseName, DWORD Level, LPUSE_INFO InfoStruct)
{
    PSMBCONN_ENUM_OUTPUT Uses;
    NET_API_STATUS Status;
    USE_INFO_2 Info;
    DWORD i, Size;
    PVOID Out;

    if (Level > 2)
        return ERROR_INVALID_LEVEL;
    if (UseName == NULL)
        return ERROR_INVALID_PARAMETER;
    Status = RpcImpersonateClient(NULL);
    if (Status != RPC_S_OK)
        return Status;
    Uses = GetUses(&Status);
    RpcRevertToSelf();
    if (Uses == NULL)
        return Status == ERROR_NO_NETWORK ? NERR_UseNotFound : Status;

    Status = NERR_UseNotFound;
    for (i = 0; i < Uses->Count; i++)
    {
        if (!(Uses->Entries[i].Flags & SMBCONN_FLAG_TREE_CONNECTED) || !UseMatches(Uses, &Uses->Entries[i], UseName))
            continue;
        Size = Level == 0 ? sizeof(USE_INFO_0) : Level == 1 ? sizeof(USE_INFO_1) : sizeof(USE_INFO_2);
        Out = midl_user_allocate(Size);
        if (Out == NULL || !FillUse(Uses, &Uses->Entries[i], &Info))
        {
            if (Out == NULL)
                ZeroMemory(&Info, sizeof(Info));
            FreeUse(&Info);
            midl_user_free(Out);
            Status = ERROR_NOT_ENOUGH_MEMORY;
            break;
        }
        CopyLevel(Level, &Info, Out);
        InfoStruct->UseInfo0 = Out;
        Status = NERR_Success;
        break;
    }
    HeapFree(GetProcessHeap(), 0, Uses);
    return Status;
}

NET_API_STATUS
WksUseEnum(LPUSE_ENUM_STRUCT InfoStruct, DWORD *TotalEntries, DWORD *ResumeHandle)
{
    PSMBCONN_ENUM_OUTPUT Uses;
    NET_API_STATUS Status;
    DWORD i, n = 0, Level = InfoStruct->Level, Size, Count = 0;
    PUCHAR Array;
    USE_INFO_2 Info;

    if (Level > 2)
        return ERROR_INVALID_LEVEL;
    if (InfoStruct->UseInfo.Level0 == NULL)
        return ERROR_INVALID_PARAMETER;
    Status = RpcImpersonateClient(NULL);
    if (Status != RPC_S_OK)
        return Status;
    Uses = GetUses(&Status);
    RpcRevertToSelf();
    if (Uses == NULL)
    {
        if (Status != ERROR_NO_NETWORK)
            return Status;
        InfoStruct->UseInfo.Level0->EntriesRead = 0;
        InfoStruct->UseInfo.Level0->Buffer = NULL;
        if (TotalEntries) *TotalEntries = 0;
        return NERR_Success;
    }
    for (i = 0; i < Uses->Count; i++)
        if (Uses->Entries[i].Flags & SMBCONN_FLAG_TREE_CONNECTED)
            Count++;
    Size = Level == 0 ? sizeof(USE_INFO_0) : Level == 1 ? sizeof(USE_INFO_1) : sizeof(USE_INFO_2);
    Array = Count ? midl_user_allocate(Count * Size) : NULL;
    if (Count && Array == NULL)
    {
        HeapFree(GetProcessHeap(), 0, Uses);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    for (i = 0; i < Uses->Count && n < Count; i++)
    {
        if (!(Uses->Entries[i].Flags & SMBCONN_FLAG_TREE_CONNECTED))
            continue;
        if (!FillUse(Uses, &Uses->Entries[i], &Info))
        {
            FreeUse(&Info);
            continue;
        }
        CopyLevel(Level, &Info, Array + n * Size);
        n++;
    }
    HeapFree(GetProcessHeap(), 0, Uses);
    InfoStruct->UseInfo.Level0->EntriesRead = n;
    InfoStruct->UseInfo.Level0->Buffer = (LPUSE_INFO_0)Array;
    if (TotalEntries) *TotalEntries = n;
    if (ResumeHandle) *ResumeHandle = 0;
    return NERR_Success;
}
