/* ReactOS WoW64 startup. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"
#include <reactos/compat_undoc.h>

ULONG Wow64HighestUserAddress;

ULONG_PTR Wow64ZeroBits(ULONG ZeroBits)
{
    if (!ZeroBits) return Wow64HighestUserAddress;
    if (ZeroBits < 32)
        return max(ZeroBits, Wow64HighestUserAddress < 0x80000000 ? 1 : 0);
    return min(ZeroBits, Wow64HighestUserAddress);
}

static NTSTATUS InitializeAddressLimit(VOID)
{
    SECTION_IMAGE_INFORMATION Image;
    PVOID Boundary;
    SIZE_T Size = 0x10000;
    NTSTATUS Status;
    /* The image section's characteristics, which the kernel uses for the same
     * limit (ProcessTlsInformation), not the mapped header a parent can change */
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessImageInformation, &Image, sizeof(Image), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    Wow64HighestUserAddress = (Image.ImageCharacteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ?
                             0xfffeffff : 0x7ffeffff;
    /* ZeroBits masks round to their highest set bit. Reserve the final 64 KiB
     * so a top-down guest allocation cannot end at 2/4 GiB and wrap pointer
     * arithmetic. This also preserves the documented maximum user address. */
    Boundary = (PVOID)((ULONG_PTR)Wow64HighestUserAddress + 1);
    return NtAllocateVirtualMemory(NtCurrentProcess(), &Boundary, 0, &Size,
                                   MEM_RESERVE, PAGE_NOACCESS);
}

NTSTATUS Wow64Allocate(SIZE_T Size, PVOID *Base)
{
    *Base = NULL;
    return NtAllocateVirtualMemory(NtCurrentProcess(), Base, 0xFFFFFFFF,
                                   &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

/* The first guest thread gets the stack a native i386 process gets for its
 * first thread (kernel32 CreateProcess and BaseCreateStack): the image's
 * reserve, at least 256 KiB, with the image's commit at the top and a guard
 * page below it, so the stack grows on demand and an overflow is raised as
 * STATUS_STACK_OVERFLOW. Later threads get the same layout from the guest's
 * own kernel32. */
static NTSTATUS CreateGuestStack(INITIAL_TEB *Stack)
{
    SECTION_IMAGE_INFORMATION Image;
    SIZE_T Reserve, Commit, MinimumCommit, Size = 0;
    PVOID Base = NULL, Limit;
    BOOLEAN Guard = FALSE;
    ULONG OldProtect;
    NTSTATUS Status;

    RtlZeroMemory(Stack, sizeof(*Stack));
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessImageInformation,
                                       &Image, sizeof(Image), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    /* PE32 sizes are 32-bit, so the rounding below cannot wrap */
    Reserve = max(256 * 1024, (ULONG)Image.MaximumStackSize);
    Commit = ROUND_TO_PAGES((ULONG)Image.CommittedStackSize);
    /* MinimumStackCommit is in the PEB, which the process's creator can write: read it once and let
     * it raise the commit only up to the reserve the image asks for, as the kernel's staging does */
    MinimumCommit = NtCurrentPeb()->MinimumStackCommit;
    if (MinimumCommit > Reserve) MinimumCommit = Reserve;
    if (Commit < MinimumCommit) Commit = ROUND_TO_PAGES(MinimumCommit);
    Reserve = ALIGN_UP_BY(Reserve, 64 * 1024);
    if (Commit >= Reserve) Reserve = ALIGN_UP_BY(Commit, 1024 * 1024);
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, Wow64ZeroBits(0),
                                     &Reserve, MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) return Status;
    Limit = (PUCHAR)Base + Reserve - Commit;
    if (Reserve >= Commit + PAGE_SIZE)
    {
        Limit = (PUCHAR)Limit - PAGE_SIZE;
        Commit += PAGE_SIZE;
        Guard = TRUE;
    }
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Limit, 0, &Commit,
                                     MEM_COMMIT, PAGE_READWRITE);
    if (NT_SUCCESS(Status) && Guard)
    {
        PVOID Page = Limit;
        SIZE_T PageSize = PAGE_SIZE;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &Page, &PageSize,
                                        PAGE_READWRITE | PAGE_GUARD, &OldProtect);
        Limit = (PUCHAR)Limit + PAGE_SIZE;
    }
    if (!NT_SUCCESS(Status))
    {
        NtFreeVirtualMemory(NtCurrentProcess(), &Base, &Size, MEM_RELEASE);
        return Status;
    }
    Stack->AllocatedStackBase = Base;
    Stack->StackBase = (PUCHAR)Base + Reserve;
    Stack->StackLimit = Limit;
    return STATUS_SUCCESS;
}

NTSTATUS Wow64CopyString(WOW64_STRING *To, const UNICODE_STRING *From)
{
    PVOID Buffer;
    NTSTATUS Status;
    if (!From->MaximumLength) return STATUS_SUCCESS;
    Status = Wow64Allocate(From->MaximumLength, &Buffer);
    if (!NT_SUCCESS(Status)) return Status;
    RtlCopyMemory(Buffer, From->Buffer, From->Length);
    To->Buffer = PtrToUlong(Buffer);
    To->Length = From->Length;
    To->MaximumLength = From->MaximumLength;
    return STATUS_SUCCESS;
}

static NTSTATUS InitializeParameters(PEB32 *Peb32)
{
    PRTL_USER_PROCESS_PARAMETERS From = RtlNormalizeProcessParams(NtCurrentPeb()->ProcessParameters);
    WOW64_PARAMETERS *To;
    NTSTATUS Status;
    PVOID Environment, NativeEnvironment = NULL;
    SIZE_T Size;
    ULONG i;

    Status = Wow64Allocate(sizeof(*To), (PVOID *)&To);
    if (!NT_SUCCESS(Status)) return Status;
    To->MaximumLength = To->Length = sizeof(*To);
    To->Flags = From->Flags | RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
    To->DebugFlags = From->DebugFlags;
#define COPY_HANDLE(Field) To->Field = HandleToUlong(From->Field)
    COPY_HANDLE(ConsoleHandle);
    COPY_HANDLE(StandardInput);
    COPY_HANDLE(StandardOutput);
    COPY_HANDLE(StandardError);
    COPY_HANDLE(CurrentDirectory.Handle);
#undef COPY_HANDLE
    To->ConsoleFlags = From->ConsoleFlags;
    RtlCopyMemory(&To->StartingX, &From->StartingX, 9 * sizeof(ULONG));
#define COPY_STRING(Field) \
    Status = Wow64CopyString(&To->Field, &From->Field); \
    if (!NT_SUCCESS(Status)) return Status
    COPY_STRING(CurrentDirectory.DosPath);
    COPY_STRING(ImagePathName);
    COPY_STRING(CommandLine);
    COPY_STRING(WindowTitle);
    COPY_STRING(DesktopInfo);
    COPY_STRING(ShellInfo);
    COPY_STRING(RuntimeData);
    for (i = 0; i < 32; ++i)
    {
        To->CurrentDirectories[i].Flags = From->CurrentDirectories[i].Flags;
        To->CurrentDirectories[i].Length = From->CurrentDirectories[i].Length;
        To->CurrentDirectories[i].TimeStamp = From->CurrentDirectories[i].TimeStamp;
        COPY_STRING(CurrentDirectories[i].DosPath);
    }
#undef COPY_STRING
    /* The search path stays logical, as on Windows: System32 first. The file system
     * redirector selects SysWOW64 when the loader opens the file, so the module is
     * still taken from SysWOW64, but FullDllName and GetModuleFileName report
     * <windir>\System32\<name>, the directory GetSystemDirectory returns.
     * Programs compare the two: eID Klient's CardAPI refuses to continue unless
     * winscard.dll was loaded from GetSystemDirectory. */
    Status = Wow64CopyString(&To->DllPath, &From->DllPath);
    if (!NT_SUCCESS(Status)) return Status;
    Status = Wow64CreateEnvironment(&NativeEnvironment);
    if (NT_SUCCESS(Status))
    {
        PWSTR End = NativeEnvironment;
        while (*End) End += wcslen(End) + 1;
        Size = (End + 1 - (PWSTR)NativeEnvironment) * sizeof(WCHAR);
        Status = Wow64Allocate(Size, &Environment);
        if (NT_SUCCESS(Status))
        {
            RtlCopyMemory(Environment, NativeEnvironment, Size);
            To->Environment = PtrToUlong(Environment);
            To->EnvironmentSize = Size;
        }
    }
    if (NativeEnvironment) RtlDestroyEnvironment(NativeEnvironment);
    if (!NT_SUCCESS(Status)) return Status;
    Peb32->ProcessParameters = PtrToUlong(To);
    return STATUS_SUCCESS;
}

static NTSTATUS InitializePeb(PEB32 *To)
{
    PPEB From = NtCurrentPeb();
    MEMORY_BASIC_INFORMATION Info;
    PVOID Nls;
    NTSTATUS Status;

    RtlZeroMemory(To, sizeof(*To));
#define COPY(Field) To->Field = From->Field
    COPY(InheritedAddressSpace); COPY(ReadImageFileExecOptions); COPY(BeingDebugged);
    COPY(OSMajorVersion); COPY(OSMinorVersion); COPY(OSBuildNumber); COPY(OSPlatformId);
    COPY(OSCSDVersion); COPY(NumberOfProcessors); COPY(NtGlobalFlag); COPY(SessionId);
    COPY(HeapSegmentReserve); COPY(HeapSegmentCommit); COPY(HeapDeCommitTotalFreeThreshold);
    COPY(HeapDeCommitFreeBlockThreshold); COPY(CriticalSectionTimeout); COPY(MinimumStackCommit);
    COPY(ImageSubsystem); COPY(ImageSubsystemMajorVersion); COPY(ImageSubsystemMinorVersion);
#undef COPY
    To->Mutant = HandleToUlong(From->Mutant);
    To->ImageBaseAddress = PtrToUlong(From->ImageBaseAddress);
    To->ImageProcessAffinityMask = (ULONG)From->ImageProcessAffinityMask;
    To->MaximumNumberOfHeaps = (PAGE_SIZE - sizeof(*To)) / sizeof(ULONG);
    To->ProcessHeaps = PtrToUlong(To + 1);
    Status = NtQueryVirtualMemory(NtCurrentProcess(), From->AnsiCodePageData,
                                  MemoryBasicInformation, &Info, sizeof(Info), NULL);
    if (!NT_SUCCESS(Status)) return Status;
    Status = Wow64Allocate(Info.RegionSize, &Nls);
    if (!NT_SUCCESS(Status)) return Status;
    RtlCopyMemory(Nls, Info.BaseAddress, Info.RegionSize);
#define COPY_NLS(Field) To->Field = PtrToUlong((PUCHAR)Nls + ((PUCHAR)From->Field - (PUCHAR)Info.BaseAddress))
    COPY_NLS(AnsiCodePageData); COPY_NLS(OemCodePageData); COPY_NLS(UnicodeCaseTableData);
#undef COPY_NLS
    if (From->pShimData)
    {
        ReactOS_ShimData *Native = From->pShimData, *Guest;
        /* The query and version fields are fixed-width. Only amd64 appends
         * an aligned pointer to its private MSYS helper; the guest loader
         * owns its own helper and must not receive that native pointer. */
        const ULONG GuestSize = FIELD_OFFSET(ReactOS_ShimData, dwRosProcessCompatVersion) + sizeof(DWORD);
        if (Native->dwMagic != REACTOS_SHIMDATA_MAGIC || Native->dwSize != sizeof(*Native))
            return STATUS_INVALID_PARAMETER;
        Status = Wow64Allocate(GuestSize, (PVOID *)&Guest);
        if (!NT_SUCCESS(Status)) return Status;
        RtlCopyMemory(Guest, Native, GuestSize);
        Guest->dwSize = GuestSize;
        To->pShimData = PtrToUlong(Guest);
    }
    return InitializeParameters(To);
}

static NTSTATUS MapNtdll(PVOID *Base)
{
    WCHAR Buffer[MAX_PATH];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE File, Section;
    IO_STATUS_BLOCK Io;
    SIZE_T Size = 0;
    NTSTATUS Status;

    RtlInitEmptyUnicodeString(&Name, Buffer, sizeof(Buffer));
    RtlAppendUnicodeToString(&Name, L"\\??\\");
    RtlAppendUnicodeToString(&Name, SharedUserData->NtSystemRoot);
    RtlAppendUnicodeToString(&Name, L"\\SysWOW64\\ntdll.dll");
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&File, FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
                        &Attributes, &Io, FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) return Status;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, NULL,
                             PAGE_EXECUTE, SEC_IMAGE, File);
    NtClose(File);
    if (!NT_SUCCESS(Status)) return Status;
    *Base = NULL;
    Status = NtMapViewOfSection(Section, NtCurrentProcess(), Base, 0xFFFFFFFF,
                                0, NULL, &Size, ViewUnmap, 0, PAGE_READONLY);
    NtClose(Section);
    if (NT_SUCCESS(Status))
    {
        PIMAGE_NT_HEADERS32 Header = RtlImageNtHeader(*Base);
        PVOID Preferred;
        if (Header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
            Header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return STATUS_INVALID_IMAGE_FORMAT;
        Preferred = ULongToPtr(Header->OptionalHeader.ImageBase);
        if (*Base != Preferred)
        {
            /* The kernel maps the i386 ntdll at its base when it creates the
             * process, and the creator may have patched that view (system-call
             * hooks of a sandbox): run it, not this copy */
            if (!NT_SUCCESS(NtAreMappedFilesTheSame(Preferred, *Base)))
                return STATUS_CONFLICTING_ADDRESSES;
            NtUnmapViewOfSection(NtCurrentProcess(), *Base);
            *Base = Preferred;
        }
    }
    return Status;
}

static PVOID Wow64Ntdll32, Wow64Loader32, Wow64Gate, Wow64ExitThread32;
/* Published with the other process state (wow64.h); read by the kernel's context requests */
static WOW64_LAYER_CODE Wow64LayerCode;

static VOID InitializeLayerCode(PVOID Gate)
{
    static const PCWSTR Names[] = { L"ntdll.dll", L"wow64.dll", L"wow64win.dll", L"wow64cpu.dll" };
    UNICODE_STRING Name;
    PIMAGE_NT_HEADERS Headers;
    PVOID Base;
    ULONG i;

    C_ASSERT(RTL_NUMBER_OF(Names) == WOW64_LAYER_RANGES - 1);
    for (i = 0; i < RTL_NUMBER_OF(Names); ++i)
    {
        RtlInitUnicodeString(&Name, Names[i]);
        if (!NT_SUCCESS(LdrGetDllHandle(NULL, NULL, &Name, &Base))) continue;
        Headers = RtlImageNtHeader(Base);
        if (!Headers) continue;
        Wow64LayerCode.Range[i].Start = (ULONG_PTR)Base;
        Wow64LayerCode.Range[i].End = (ULONG_PTR)Base + Headers->OptionalHeader.SizeOfImage;
    }
    /* The gate page's far jump lands in 64-bit code on the same page (Wow64CpuInitialize allocates
     * the gate with NtAllocateVirtualMemory, so Gate is page-aligned and the page is the whole gate) */
    Wow64LayerCode.Range[i].Start = (ULONG_PTR)Gate;
    Wow64LayerCode.Range[i].End = (ULONG_PTR)Gate + PAGE_SIZE;
}
/* Only the native loader's process initializer may build the guest process.
 * Publish all shared pointers together, including on weakly ordered hosts. */
static LONG Wow64ProcessReady;

VOID Wow64InitializeTeb(TEB32 *Teb32, const TEB *Teb, PTEB RemoteTeb, const INITIAL_TEB *Stack)
{
    RtlZeroMemory(Teb32, sizeof(*Teb32));
    Teb32->NtTib.ExceptionList = MAXULONG;
    Teb32->NtTib.Version = 30 << 8;
    /* Windows 10: the TEB32 holds the (negative) distance back to the 64-bit TEB, which holds +0x2000 */
    PS_TEB32_WOW_TEB_OFFSET(Teb32) = -(LONG)ROUND_TO_PAGES(sizeof(TEB));
    Teb32->NtTib.Self = PtrToUlong(WOW64_TEB32(RemoteTeb));
    Teb32->NtTib.StackBase = PtrToUlong(Stack->StackBase);
    Teb32->NtTib.StackLimit = PtrToUlong(Stack->StackLimit);
    Teb32->DeallocationStack = PtrToUlong(Stack->AllocatedStackBase);
    Teb32->ProcessEnvironmentBlock = PtrToUlong(WOW64_PEB32(Teb->ProcessEnvironmentBlock));
    Teb32->ClientId.UniqueProcess = HandleToUlong(Teb->ClientId.UniqueProcess);
    Teb32->ClientId.UniqueThread = HandleToUlong(Teb->ClientId.UniqueThread);
    Teb32->RealClientId = Teb32->ClientId;
    Teb32->CurrentLocale = Teb->CurrentLocale;
    Teb32->WOW32Reserved = PtrToUlong(Wow64Gate);
    Teb32->StaticUnicodeString.Buffer = PtrToUlong(WOW64_TEB32(RemoteTeb)->StaticUnicodeBuffer);
    Teb32->StaticUnicodeString.MaximumLength = sizeof(Teb32->StaticUnicodeBuffer);
}

/* A native thread the console server started for a control event (Wow64CsrThreadStart)
 * becomes a guest thread, as kernel32's CreateRemoteThread would start it natively: a guest
 * stack sized from the image, TEB32, and a context that enters Routine(Parameter) through
 * the guest loader's thread initialization. The routine (kernel32's control dispatcher)
 * ends the thread itself; should it return, it returns into RtlExitUserThread. */
static NTSTATUS CsrGuestThread(ULONG Routine, ULONG Parameter, WOW64_CONTEXT *GuestContext)
{
    PTEB Teb = NtCurrentTeb();
    INITIAL_TEB Stack;
    ULONG *Frame;
    ULONG_PTR StartAddress = Routine;
    NTSTATUS Status;

    if (!Wow64ExitThread32) return STATUS_ENTRYPOINT_NOT_FOUND;
    Status = CreateGuestStack(&Stack);
    if (!NT_SUCCESS(Status)) return Status;
    Wow64InitializeTeb(WOW64_TEB32(Teb), Teb, Teb, &Stack);
    NtSetInformationThread(NtCurrentThread(), ThreadQuerySetWin32StartAddress,
                           &StartAddress, sizeof(StartAddress));
    /* The return address, the parameter, then RtlExitUserThread's own frame. The routine
     * is entered as after a call: the stack pointer 4 below a 16-byte boundary, so that the
     * parameter, the first stack slot above the return address, is aligned. */
    Frame = (ULONG *)(((ULONG_PTR)Stack.StackBase & ~(ULONG_PTR)15) - 5 * sizeof(ULONG));
    Frame[0] = PtrToUlong(Wow64ExitThread32);
    Frame[1] = Parameter;
    Frame[2] = 0;
    Frame[3] = 0;
    Frame[4] = 0;
    RtlZeroMemory(GuestContext, sizeof(*GuestContext));
    GuestContext->ContextFlags = WOW64_CONTEXT_FULL | WOW64_CONTEXT_EXTENDED_REGISTERS;
    GuestContext->Eip = Routine;
    GuestContext->Esp = PtrToUlong(Frame);
    GuestContext->EFlags = 0x202;
    GuestContext->SegCs = 0x23;
    GuestContext->SegSs = GuestContext->SegDs = GuestContext->SegEs = 0x2b;
    GuestContext->SegFs = 0x53;
    *(USHORT *)(GuestContext->ExtendedRegisters) = 0x27f;
    *(ULONG *)(GuestContext->ExtendedRegisters + 24) = 0x1f80;
    return STATUS_SUCCESS;
}

VOID NTAPI Wow64LdrpInitialize(PCONTEXT Context, BOOLEAN ProcessStartup)
{
    PPEB Peb = NtCurrentPeb();
    PTEB Teb = NtCurrentTeb();
    PEB32 *Peb32 = WOW64_PEB32(Peb);
    TEB32 *Teb32 = WOW64_TEB32(Teb);
    WOW64_CPU_STATE State = {0};
    /* The CPU area the kernel staged for the main thread, with its start context (psctx.c) */
    WOW64_CPU_STATE *Staged = Teb->TlsSlots[WOW64_TLS_CPU];
    WOW64_CONTEXT StartContext;
    PVOID Ntdll32, Entry, Gate;
    INITIAL_TEB Stack;
    ANSI_STRING Name = RTL_CONSTANT_STRING("LdrInitializeWow64");
    NTSTATUS Status;
    WOW64_CONTEXT *GuestContext = NULL, CsrContext;
    BOOLEAN CallbackReady = FALSE;

    if (!ProcessStartup)
    {
        LARGE_INTEGER Delay;
        ULONG Routine, Parameter;
        /* The kernel stages the first thread of the process (psctx.c), which is normally the one the
         * native loader initializes it on. Should another thread have done that, this one is a
         * native helper or a wow64.dll-created guest thread: it must not keep a CPU area nobody
         * entered, or it would look like a running guest thread (APC dispatch, context requests). */
        if (Staged)
        {
            Teb->TlsSlots[WOW64_TLS_CPU] = NULL;
            Staged = NULL;
        }
        /* Native helper threads never initialize or enter the guest loader,
         * except the console server's control event threads. */
        if (Context->Rdx != WOW64_THREAD_START_MARKER &&
            !Wow64CsrThreadStart(Context, &Routine, &Parameter))
            return;
        Delay.QuadPart = -10000;
        while (!InterlockedCompareExchange(&Wow64ProcessReady, 0, 0))
            NtDelayExecution(FALSE, &Delay);
        if (Context->Rdx != WOW64_THREAD_START_MARKER)
        {
            /* The server ignores a failed control thread: end only this one */
            Status = CsrGuestThread(Routine, Parameter, &CsrContext);
            if (!NT_SUCCESS(Status))
            {
                DbgPrint("WoW64: cannot start the console control routine: %08lx\n", Status);
                for (;;) NtTerminateThread(NtCurrentThread(), Status);
            }
            GuestContext = &CsrContext;
        }
        else GuestContext = (WOW64_CONTEXT *)(ULONG_PTR)Context->Rcx;
        if (!GuestContext) { Status = STATUS_INVALID_PARAMETER; goto Failed; }
        Ntdll32 = Wow64Ntdll32;
        Entry = Wow64Loader32;
        Gate = Wow64Gate;
        goto ThreadReady;
    }
    Status = InitializeAddressLimit();
    if (!NT_SUCCESS(Status)) goto Failed;
    /* Establish the guest stack before variable-size startup data. A child
     * may replace its bootstrap stack with the parent's stack reservation;
     * RuntimeData must not take that range merely because it is nonempty. */
    if (Staged)
    {
        /* The guest stack staged with the start context */
        RtlZeroMemory(&Stack, sizeof(Stack));
        Stack.StackBase = PTR32(Teb32->NtTib.StackBase);
        Stack.StackLimit = PTR32(Teb32->NtTib.StackLimit);
        Stack.AllocatedStackBase = PTR32(Teb32->DeallocationStack);
        Status = Stack.StackBase ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    }
    else Status = CreateGuestStack(&Stack);
    if (!NT_SUCCESS(Status)) goto Failed;
    Status = Wow64InitializeRedirection();
    if (!NT_SUCCESS(Status)) goto Failed;
    Status = InitializePeb(Peb32);
    if (!NT_SUCCESS(Status)) goto Failed;
    Status = MapNtdll(&Ntdll32);
    if (!NT_SUCCESS(Status)) goto Failed;
    /* Export-directory entries have the same RVA representation for PE32. */
    {
        ULONG Bytes, i;
        PIMAGE_EXPORT_DIRECTORY Exports = RtlImageDirectoryEntryToData(Ntdll32, TRUE,
                                             IMAGE_DIRECTORY_ENTRY_EXPORT, &Bytes);
        ULONG *Names, *Functions;
        USHORT *Ordinals;
        Entry = NULL;
        if (!Exports) { Status = STATUS_ENTRYPOINT_NOT_FOUND; goto Failed; }
        Names = (PVOID)((PUCHAR)Ntdll32 + Exports->AddressOfNames);
        Functions = (PVOID)((PUCHAR)Ntdll32 + Exports->AddressOfFunctions);
        Ordinals = (PVOID)((PUCHAR)Ntdll32 + Exports->AddressOfNameOrdinals);
        for (i = 0; i < Exports->NumberOfNames; ++i)
        {
            if (!strcmp((PCHAR)Ntdll32 + Names[i], "KiUserCallbackDispatcher") &&
                Ordinals[i] < Exports->NumberOfFunctions)
                CallbackReady = NT_SUCCESS(Wow64WinInitialize((PUCHAR)Ntdll32 + Functions[Ordinals[i]]));
            if (!strcmp((PCHAR)Ntdll32 + Names[i], "KiUserApcDispatcher") &&
                Ordinals[i] < Exports->NumberOfFunctions)
                Wow64ApcDispatcher = (PUCHAR)Ntdll32 + Functions[Ordinals[i]];
            if (!strcmp((PCHAR)Ntdll32 + Names[i], "RtlExitUserThread") &&
                Ordinals[i] < Exports->NumberOfFunctions)
                Wow64ExitThread32 = (PUCHAR)Ntdll32 + Functions[Ordinals[i]];
            if (!strcmp((PCHAR)Ntdll32 + Names[i], "KiUserExceptionDispatcher") &&
                Ordinals[i] < Exports->NumberOfFunctions)
                Wow64ExceptionDispatcher = (PUCHAR)Ntdll32 + Functions[Ordinals[i]];
            if (!strcmp((PCHAR)Ntdll32 + Names[i], Name.Buffer) && Ordinals[i] < Exports->NumberOfFunctions)
            {
                Entry = (PUCHAR)Ntdll32 + Functions[Ordinals[i]];
            }
        }
        if (!Entry || !Wow64ExceptionDispatcher || !Wow64ApcDispatcher || !CallbackReady) { Status = STATUS_ENTRYPOINT_NOT_FOUND; goto Failed; }
    }
    Status = Wow64CpuInitialize(Wow64SystemService, &Gate);
    if (!NT_SUCCESS(Status)) goto Failed;
    InitializeLayerCode(Gate);
    Wow64Ntdll32 = Ntdll32;
    Wow64Loader32 = Entry;
    Wow64Gate = Gate;
    RtlZeroMemory(Teb32, sizeof(*Teb32));
    Teb32->NtTib.ExceptionList = MAXULONG;
    Teb32->NtTib.Version = 30 << 8;
    PS_TEB32_WOW_TEB_OFFSET(Teb32) = -(LONG)ROUND_TO_PAGES(sizeof(TEB));
    Teb32->NtTib.Self = PtrToUlong(Teb32);
    Teb32->NtTib.StackBase = PtrToUlong(Stack.StackBase);
    Teb32->NtTib.StackLimit = PtrToUlong(Stack.StackLimit);
    Teb32->DeallocationStack = PtrToUlong(Stack.AllocatedStackBase);
    Teb32->ProcessEnvironmentBlock = PtrToUlong(Peb32);
    Teb32->ClientId.UniqueProcess = HandleToUlong(Teb->ClientId.UniqueProcess);
    Teb32->ClientId.UniqueThread = HandleToUlong(Teb->ClientId.UniqueThread);
    Teb32->RealClientId = Teb32->ClientId;
    Teb32->CurrentLocale = Teb->CurrentLocale;
    Teb32->WOW32Reserved = PtrToUlong(Gate);
    Teb32->StaticUnicodeString.Buffer = PtrToUlong(Teb32->StaticUnicodeBuffer);
    Teb32->StaticUnicodeString.MaximumLength = sizeof(Teb32->StaticUnicodeBuffer);
    if (Staged)
    {
        /* Take the start context over, with any change a debugger made: from here a
         * context request waits (STATUS_RETRY) until the guest runs */
        InterlockedExchange(&Staged->InTransition, 1);
        Wow64CpuToContext(&StartContext, Staged);
        GuestContext = &StartContext;
    }
    InterlockedExchange(&Wow64ProcessReady, 1);
ThreadReady:
    /* Preserve the parent's pre-resume activation-context setup in TEB32. */
    Teb32->WOW32Reserved = PtrToUlong(Gate);
    State.LayerCode = &Wow64LayerCode;
    if (GuestContext)
    {
        State.Esp = (GuestContext->Esp - sizeof(*GuestContext)) & ~15;
        RtlCopyMemory(PTR32(State.Esp), GuestContext, sizeof(*GuestContext));
        GuestContext = PTR32(State.Esp);
    }
    else State.Esp = Teb32->NtTib.StackBase;
    State.Esp -= 12;
    ((ULONG *)(ULONG_PTR)State.Esp)[0] = 0;
    ((ULONG *)(ULONG_PTR)State.Esp)[1] = PtrToUlong(Ntdll32);
    ((ULONG *)(ULONG_PTR)State.Esp)[2] = PtrToUlong(GuestContext);
    *(USHORT *)(State.ExtendedRegisters) = 0x27f;
    *(ULONG *)(State.ExtendedRegisters + 24) = 0x1f80;
    /* The registers of a thread that has not run are the area's, which the first return loads */
    State.FpSaved = TRUE;
    State.Eip = PtrToUlong(Entry);
    State.EFlags = 0x202;
#if DBG
    if (!GuestContext)
        DbgPrint("WoW64: entering i386 ntdll at %lx, PEB32 %p TEB32 %p\n", State.Eip, Peb32, Teb32);
#endif
    if (Staged)
    {
        /* The staged area stays the thread's CPU area, at the top of its native stack as on
         * Windows. InTransition is 1 in both, so no request sees the copy half done. */
        State.InTransition = 1;
        *Staged = State;
    }
    Wow64CpuRun(Staged ? Staged : &State);
Failed:
    DbgPrint("WoW64: initialization failed: %08lx\n", Status);
    NtTerminateProcess(NtCurrentProcess(), Status);
    for (;;) NtTerminateThread(NtCurrentThread(), Status);
}
