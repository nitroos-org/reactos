/* ReactOS WoW64 process creation. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"
#include <reactos/wow64process.h>
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

typedef struct
{
    ULONG Size, Reserved, Desktop, Title;
    ULONG X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
    USHORT ShowWindow, ReservedSize;
    ULONG ReservedData, Input, Output, Error;
} STARTUPINFO32;

/* The guest kernel32's attribute list (proc.c): a header, then one entry per
 * attribute pointing at the caller's value. */
typedef struct
{
    ULONG Attribute, Size, Value;
} PROC_THREAD_ATTRIBUTE_ENTRY32;

typedef struct
{
    ULONG PresentFlags, AttributeCount, LastAttribute, SpareUlong0, ExtendedFlagsAttribute;
    PROC_THREAD_ATTRIBUTE_ENTRY32 Attributes[ANYSIZE_ARRAY];
} PROC_THREAD_ATTRIBUTE_LIST32;

/* More attributes than the guest kernel32 can have put in a list are refused;
 * handle lists have the native limit */
#define WOW64_MAX_ATTRIBUTES 32

typedef BOOL (WINAPI *INITIALIZE_ATTRIBUTES)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *UPDATE_ATTRIBUTE)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);

typedef BOOL (WINAPI *CREATE_PROCESS)(HANDLE, PCWSTR, PWSTR,
    SECURITY_ATTRIBUTES *, SECURITY_ATTRIBUTES *, BOOL, DWORD, PVOID, PCWSTR,
    STARTUPINFOW *, PROCESS_INFORMATION *, PHANDLE);

static SECURITY_ATTRIBUTES *
CaptureSecurity(ULONG Address, SECURITY_ATTRIBUTES *To, SECURITY_DESCRIPTOR *Sd)
{
    ULONG *From = PTR32(Address);
    if (!From) return NULL;
    To->nLength = sizeof(*To);
    To->lpSecurityDescriptor = PTR32(From[1]);
    To->bInheritHandle = From[2];
    if (To->lpSecurityDescriptor &&
        !(((SECURITY_DESCRIPTOR *)To->lpSecurityDescriptor)->Control & SE_SELF_RELATIVE))
    {
        SECURITY_DESCRIPTOR_RELATIVE *In = To->lpSecurityDescriptor;
        Sd->Revision = In->Revision;
        Sd->Sbz1 = In->Sbz1;
        Sd->Control = In->Control;
        Sd->Owner = PTR32(In->Owner);
        Sd->Group = PTR32(In->Group);
        Sd->Sacl = PTR32(In->Sacl);
        Sd->Dacl = PTR32(In->Dacl);
        To->lpSecurityDescriptor = Sd;
    }
    return To;
}

static VOID CaptureString(UNICODE_STRING *To, const WOW64_STRING *From)
{
    To->Length = From->Length;
    To->MaximumLength = From->MaximumLength;
    To->Buffer = PTR32(From->Buffer);
}

/* Size bytes at a guest address lie below the guest's highest address */
static BOOLEAN GuestRange(ULONG Address, ULONG64 Size)
{
    return Address && (ULONG64)Address + Size <= (ULONG64)Wow64HighestUserAddress + 1;
}

/* Widens a guest handle array attribute (handle list, job list) into a native
 * array the caller frees */
static NTSTATUS CaptureHandles(UPDATE_ATTRIBUTE Update, LPPROC_THREAD_ATTRIBUTE_LIST List,
                               const PROC_THREAD_ATTRIBUTE_ENTRY32 *Entry, HANDLE **Handles)
{
    const ULONG *Guest = PTR32(Entry->Value);
    ULONG Number = Entry->Size / sizeof(ULONG), j;
    if (*Handles || !Number || Entry->Size % sizeof(ULONG) || Number > ROS_PS_MAX_HANDLE_COUNT ||
        !GuestRange(Entry->Value, Entry->Size))
        return STATUS_INVALID_PARAMETER;
    *Handles = RtlAllocateHeap(RtlGetProcessHeap(), 0, (SIZE_T)Number * sizeof(HANDLE));
    if (!*Handles) return STATUS_NO_MEMORY;
    for (j = 0; j < Number; ++j) (*Handles)[j] = HANDLE32(Guest[j]);
    if (!Update(List, 0, Entry->Attribute, *Handles, (SIZE_T)Number * sizeof(HANDLE), NULL, NULL))
        return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

/* A native copy of the guest's attribute list. The guest kernel32 accepted it
 * (handle list, job list, ideal processor, mitigation, child process and
 * component filter policies). Every guest range is checked and read once:
 * handle values widen into *Handles and *Jobs, the small values (no pointers)
 * are copied into storage after the native list, which is one allocation (*List). */
static NTSTATUS CaptureAttributeList(PVOID Module, ULONG Address, LPPROC_THREAD_ATTRIBUTE_LIST *List, HANDLE **Handles,
                                     HANDLE **Jobs, BOOLEAN *Reported)
{
    PROC_THREAD_ATTRIBUTE_LIST32 *From = PTR32(Address);
    ANSI_STRING InitializeName = RTL_CONSTANT_STRING("InitializeProcThreadAttributeList");
    ANSI_STRING UpdateName = RTL_CONSTANT_STRING("UpdateProcThreadAttribute");
    INITIALIZE_ATTRIBUTES Initialize;
    UPDATE_ATTRIBUTE Update;
    PROC_THREAD_ATTRIBUTE_ENTRY32 Entry;
    ULONGLONG (*Values)[2];
    SIZE_T Size = 0, ListSize;
    ULONG Count, i;
    NTSTATUS Status;

    *List = NULL;
    *Handles = NULL;
    *Jobs = NULL;
    if (!From) return STATUS_SUCCESS;
    Status = LdrGetProcedureAddress(Module, &InitializeName, 0, (PVOID *)&Initialize);
    if (NT_SUCCESS(Status)) Status = LdrGetProcedureAddress(Module, &UpdateName, 0, (PVOID *)&Update);
    if (!NT_SUCCESS(Status)) return Status;
    if (!GuestRange(Address, FIELD_OFFSET(PROC_THREAD_ATTRIBUTE_LIST32, Attributes))) return STATUS_INVALID_PARAMETER;
    Count = From->LastAttribute;
    if (Count > From->AttributeCount || Count > WOW64_MAX_ATTRIBUTES ||
        !GuestRange(Address, FIELD_OFFSET(PROC_THREAD_ATTRIBUTE_LIST32, Attributes[Count])))
        return STATUS_INVALID_PARAMETER;
    Initialize(NULL, Count, 0, &Size);
    ListSize = ALIGN_UP_BY(Size, sizeof(ULONGLONG));
    *List = RtlAllocateHeap(RtlGetProcessHeap(), 0, ListSize + Count * sizeof(*Values));
    if (!*List) return STATUS_NO_MEMORY;
    Values = (PVOID)((PUCHAR)*List + ListSize);
    if (!Initialize(*List, Count, 0, &Size)) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < Count; ++i)
    {
        Entry = From->Attributes[i];
        if (Entry.Attribute == PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
        {
            Status = CaptureHandles(Update, *List, &Entry, Handles);
            if (!NT_SUCCESS(Status)) return Status;
        }
        else if (Entry.Attribute == PROC_THREAD_ATTRIBUTE_JOB_LIST)
        {
            /* Chromium's sandbox passes the target's job here on Windows 10 */
            Status = CaptureHandles(Update, *List, &Entry, Jobs);
            if (!NT_SUCCESS(Status)) return Status;
        }
        else if (Entry.Attribute == PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR ||
                 Entry.Attribute == PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY ||
                 Entry.Attribute == PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY ||
                 Entry.Attribute == PROC_THREAD_ATTRIBUTE_COMPONENT_FILTER)
        {
            /* PROCESSOR_NUMBER and the DWORD/DWORD64 policies: no pointers, at most 16 bytes */
            if (!Entry.Size || Entry.Size > sizeof(Values[i]) || !GuestRange(Entry.Value, Entry.Size))
                return STATUS_INVALID_PARAMETER;
            RtlCopyMemory(Values[i], PTR32(Entry.Value), Entry.Size);
            if (!Update(*List, 0, Entry.Attribute, Values[i], Entry.Size, NULL, NULL))
                return STATUS_INVALID_PARAMETER;
        }
        else return Wow64Unsupported(WOW64_SERVICE_CREATE_PROCESS, WOW64_UNSUPPORTED_ATTRIBUTE, Entry.Attribute,
                                     Reported);
    }
    return STATUS_SUCCESS;
}

NTSTATUS Wow64CreateProcess(PVOID Buffer, BOOLEAN *Reported)
{
    WOW64_CREATE_PROCESS *Out = Buffer, Request = *Out;
    WOW64_CPU_STATE *Cpu = NtCurrentTeb()->TlsSlots[WOW64_TLS_CPU];
    PVOID SavedParameters = Cpu->ProcessParameters;
    WOW64_PARAMETERS *From = PTR32(Request.ParentParameters);
    RTL_USER_PROCESS_PARAMETERS Parent = *NtCurrentPeb()->ProcessParameters;
    STARTUPINFO32 In;
    STARTUPINFOEXW Startup = {{sizeof(Startup.StartupInfo)}};
    LPPROC_THREAD_ATTRIBUTE_LIST AttributeList = NULL;
    HANDLE *ListHandles = NULL, *ListJobs = NULL;
    SECURITY_ATTRIBUTES ProcessSecurity, ThreadSecurity, *Ps, *Ts;
    SECURITY_DESCRIPTOR ProcessSd, ThreadSd;
    PROCESS_INFORMATION Info = {0};
    HANDLE NewToken = NULL;
    UNICODE_STRING Path = {0}, Name, ModuleName;
    OBJECT_ATTRIBUTES Attributes;
    PVOID Redirected = NULL, Module;
    PWSTR Application = NULL;
    WCHAR ModulePath[MAX_PATH];
    ANSI_STRING Export = RTL_CONSTANT_STRING("CreateProcessInternalW");
    CREATE_PROCESS Create;
    BOOL Created;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG *Result = PTR32(Request.ProcessInformation);
    ULONG i;


    _SEH2_TRY
    {
        /* Validate destinations before creating a suspended child. Ownership
         * stays here until every output and the optional resume succeed. */
        for (i = 0; i < 4; ++i) ((volatile ULONG *)Result)[i] = 0;
        Out->Error = 0;
        if (Request.NewToken) *(volatile ULONG *)PTR32(Request.NewToken) = 0;
        In = *(STARTUPINFO32 *)PTR32(Request.StartupInfo);
        Startup.StartupInfo.lpReserved = PTR32(In.Reserved);
        Startup.StartupInfo.lpDesktop = PTR32(In.Desktop);
        Startup.StartupInfo.lpTitle = PTR32(In.Title);
        RtlCopyMemory(&Startup.StartupInfo.dwX, &In.X, 8 * sizeof(ULONG));
        Startup.StartupInfo.wShowWindow = In.ShowWindow;
        Startup.StartupInfo.cbReserved2 = In.ReservedSize;
        Startup.StartupInfo.lpReserved2 = PTR32(In.ReservedData);
        Startup.StartupInfo.hStdInput = HANDLE32(In.Input);
        Startup.StartupInfo.hStdOutput = HANDLE32(In.Output);
        Startup.StartupInfo.hStdError = HANDLE32(In.Error);
        Ps = CaptureSecurity(Request.ProcessAttributes, &ProcessSecurity, &ProcessSd);
        Ts = CaptureSecurity(Request.ThreadAttributes, &ThreadSecurity, &ThreadSd);

        Parent.Flags = From->Flags;
        Parent.ConsoleHandle = HANDLE32(From->ConsoleHandle);
        Parent.ConsoleFlags = From->ConsoleFlags;
        Parent.StandardInput = HANDLE32(From->StandardInput);
        Parent.StandardOutput = HANDLE32(From->StandardOutput);
        Parent.StandardError = HANDLE32(From->StandardError);
        Parent.CurrentDirectory.Handle = HANDLE32(From->CurrentDirectory.Handle);
        CaptureString(&Parent.CurrentDirectory.DosPath, &From->CurrentDirectory.DosPath);
        CaptureString(&Parent.DesktopInfo, &From->DesktopInfo);
        Parent.Environment = PTR32(From->Environment);

        if (!RtlDosPathNameToNtPathName_U(PTR32(Request.Application), &Path, NULL, NULL))
        {
            Status = STATUS_OBJECT_PATH_INVALID;
            _SEH2_LEAVE;
        }
        InitializeObjectAttributes(&Attributes, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);
        Status = Wow64RedirectFile(&Attributes, &Name, &Redirected);
        if (!NT_SUCCESS(Status)) _SEH2_LEAVE;
        Name = *Attributes.ObjectName;
        /* The input is an absolute DOS path resolved by guest kernel32.
         * Preserve its ordinary Win32 form: adding a device prefix changes
         * GetModuleFileName in the child and breaks path-based applications. */
        if (Name.Length < 4 * sizeof(WCHAR) || wcsncmp(Name.Buffer, L"\\??\\", 4))
        {
            Status = STATUS_OBJECT_PATH_INVALID;
            _SEH2_LEAVE;
        }
        Application = RtlAllocateHeap(RtlGetProcessHeap(), 0, Name.Length + sizeof(WCHAR));
        if (!Application) { Status = STATUS_NO_MEMORY; _SEH2_LEAVE; }
        if (!wcsncmp(PTR32(Request.Application), L"\\\\?\\", 4))
        {
            RtlCopyMemory(Application, Name.Buffer, Name.Length);
            Application[1] = L'\\';
            Application[Name.Length / sizeof(WCHAR)] = 0;
        }
        else if (Name.Length >= 8 * sizeof(WCHAR) && !_wcsnicmp(Name.Buffer + 4, L"UNC\\", 4))
        {
            Application[0] = Application[1] = L'\\';
            RtlCopyMemory(Application + 2, Name.Buffer + 8, Name.Length - 8 * sizeof(WCHAR));
            Application[Name.Length / sizeof(WCHAR) - 6] = 0;
        }
        else
        {
            RtlCopyMemory(Application, Name.Buffer + 4, Name.Length - 4 * sizeof(WCHAR));
            Application[Name.Length / sizeof(WCHAR) - 4] = 0;
        }

        wcscpy(ModulePath, SharedUserData->NtSystemRoot);
        wcscat(ModulePath, L"\\System32\\kernel32.dll");
        RtlInitUnicodeString(&ModuleName, ModulePath);
        Status = LdrGetDllHandle(NULL, NULL, &ModuleName, &Module);
        if (!NT_SUCCESS(Status)) Status = LdrLoadDll(NULL, NULL, &ModuleName, &Module);
        if (!NT_SUCCESS(Status)) _SEH2_LEAVE;
        Status = LdrGetProcedureAddress(Module, &Export, 0, (PVOID *)&Create);
        if (!NT_SUCCESS(Status)) _SEH2_LEAVE;
        if (Request.CreationFlags & EXTENDED_STARTUPINFO_PRESENT)
        {
            Startup.StartupInfo.cb = sizeof(Startup);
            Status = CaptureAttributeList(Module, Request.AttributeList, &AttributeList, &ListHandles, &ListJobs,
                                          Reported);
            if (!NT_SUCCESS(Status)) _SEH2_LEAVE;
            Startup.lpAttributeList = AttributeList;
        }

        Cpu->ProcessParameters = &Parent;
        /* A debugged child is attached by the native creator to the debug object of the native
         * TEB (DbgUiConnectToDbg): that is the guest's own object, in TEB32, which the guest's
         * WaitForDebugEvent and ContinueDebugEvent use. One object, as for a native debugger. */
        if (Request.CreationFlags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS))
            NtCurrentTeb()->DbgSsReserved[1] = HANDLE32(WOW64_TEB32(NtCurrentTeb())->DbgSsReserved[1]);
        Created = Create(HANDLE32(Request.Token), Application, PTR32(Request.CommandLine), Ps, Ts,
                         Request.InheritHandles, Request.CreationFlags | CREATE_SUSPENDED,
                         Request.Environment ? PTR32(Request.Environment) : Parent.Environment,
                         Request.CurrentDirectory ? PTR32(Request.CurrentDirectory) : Parent.CurrentDirectory.DosPath.Buffer,
                         &Startup.StartupInfo, &Info, Request.NewToken ? &NewToken : NULL);
        /* The object the creator made (or kept) is the guest's from now on, also when it failed */
        if (Request.CreationFlags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS))
            WOW64_TEB32(NtCurrentTeb())->DbgSsReserved[1] = HandleToUlong(NtCurrentTeb()->DbgSsReserved[1]);
        if (!Created)
        {
            Out->Error = NtCurrentTeb()->LastErrorValue;
            if (!Out->Error) Out->Error = ERROR_GEN_FAILURE;
            _SEH2_LEAVE;
        }
        Result[0] = HandleToUlong(Info.hProcess);
        Result[1] = HandleToUlong(Info.hThread);
        Result[2] = Info.dwProcessId;
        Result[3] = Info.dwThreadId;
        if (Request.NewToken) *(ULONG *)PTR32(Request.NewToken) = HandleToUlong(NewToken);
        if (!(Request.CreationFlags & CREATE_SUSPENDED))
            Status = NtResumeThread(Info.hThread, NULL);
        if (NT_SUCCESS(Status))
        {
            Info.hProcess = Info.hThread = NewToken = NULL;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    Cpu->ProcessParameters = SavedParameters;
    if (Info.hProcess)
    {
        NtTerminateProcess(Info.hProcess, STATUS_UNSUCCESSFUL);
        NtClose(Info.hProcess);
    }
    if (Info.hThread) NtClose(Info.hThread);
    if (NewToken) NtClose(NewToken);
    if (AttributeList) RtlFreeHeap(RtlGetProcessHeap(), 0, AttributeList);
    if (ListHandles) RtlFreeHeap(RtlGetProcessHeap(), 0, ListHandles);
    if (ListJobs) RtlFreeHeap(RtlGetProcessHeap(), 0, ListJobs);
    if (Application) RtlFreeHeap(RtlGetProcessHeap(), 0, Application);
    if (Redirected) RtlFreeHeap(RtlGetProcessHeap(), 0, Redirected);
    RtlFreeUnicodeString(&Path);
    return Status;
}
