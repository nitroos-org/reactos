/* SPDX-License-Identifier: GPL-2.0-or-later
 * The 32-bit context of a WoW64 thread as a debugger reads it.
 * 64-bit: the main thread of a suspended WoW64 child has its start context before it
 * runs (RtlUserThreadStart-style: the image entry in EAX, the PEB32 in EBX, the top of
 * the 32-bit stack), which can be changed, and keeps a readable context while the
 * native loader initializes the process.
 * 32-bit under WoW64: a thread running 64-bit code it entered with a far transfer has a
 * readable context (exception active), and that code finds the TEB in R12, the CPU area
 * in R13 and the native stack in R14.
 * The expected values are what Windows 10 reports. */
#include "precomp.h"
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/mmfuncs.h>
#include <reactos/wow64.h>

#ifndef CONTEXT_EXCEPTION_REQUEST
#define CONTEXT_EXCEPTION_ACTIVE    0x08000000
#define CONTEXT_SERVICE_ACTIVE      0x10000000
#define CONTEXT_EXCEPTION_REQUEST   0x40000000
#define CONTEXT_EXCEPTION_REPORTING 0x80000000
#endif

#ifdef _WIN64
/* kernel32's Wow64Get/SetThreadContext, which the headers of this build do not declare */
static BOOL (WINAPI *pWow64GetThreadContext)(HANDLE, PWOW64_CONTEXT);
static BOOL (WINAPI *pWow64SetThreadContext)(HANDLE, const WOW64_CONTEXT *);
#define Wow64GetThreadContext pWow64GetThreadContext
#define Wow64SetThreadContext pWow64SetThreadContext

/* The address of an export of the PE32 image mapped at Base in Process, 0 if none */
static ULONG RemoteExport32(HANDLE Process, ULONG Base, const char *Name, char *Module, SIZE_T ModuleSize)
{
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS32 Nt;
    IMAGE_EXPORT_DIRECTORY Exports;
    ULONG i, NameRva, FunctionRva;
    USHORT Ordinal;
    char Text[64];
    SIZE_T Read;
    PUCHAR Image = (PUCHAR)(ULONG_PTR)Base;

    if (!ReadProcessMemory(Process, Image, &Dos, sizeof(Dos), &Read) ||
        !ReadProcessMemory(Process, Image + Dos.e_lfanew, &Nt, sizeof(Nt), &Read) ||
        Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        !Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress ||
        !ReadProcessMemory(Process, Image + Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                           &Exports, sizeof(Exports), &Read))
        return 0;
    memset(Module, 0, ModuleSize);
    ReadProcessMemory(Process, Image + Exports.Name, Module, ModuleSize - 1, &Read);
    for (i = 0; i < Exports.NumberOfNames; ++i)
    {
        memset(Text, 0, sizeof(Text));
        if (!ReadProcessMemory(Process, Image + Exports.AddressOfNames + i * sizeof(ULONG), &NameRva, sizeof(NameRva), &Read) ||
            !ReadProcessMemory(Process, Image + NameRva, Text, sizeof(Text) - 1, &Read))
            return 0;
        if (strcmp(Text, Name)) continue;
        if (!ReadProcessMemory(Process, Image + Exports.AddressOfNameOrdinals + i * sizeof(USHORT), &Ordinal, sizeof(Ordinal), &Read) ||
            !ReadProcessMemory(Process, Image + Exports.AddressOfFunctions + Ordinal * sizeof(ULONG), &FunctionRva, sizeof(FunctionRva), &Read))
            return 0;
        return Base + FunctionRva;
    }
    return 0;
}

/* The kernel does not take the main thread's entry from the PEB, which the process's creator can
 * write before the thread runs. The PEB's image base is pointed at memory the test controls: a
 * forged MZ/PE header whose image base and entry differ from the real image's (Forged), or a
 * kernel-range address, and the minimum stack commit is set outsized. The staged start context
 * still has the real entry in EAX, never the forged one. */
static void TestEditedPeb(const char *Path, BOOL Forged)
{
    HANDLE File, Section = NULL, Process = NULL, Thread = NULL;
    SECTION_IMAGE_INFORMATION Image;
    PROCESS_BASIC_INFORMATION Basic;
    INITIAL_TEB Stack = {0};
    CONTEXT Native = {0};
    WOW64_CONTEXT Context;
    CLIENT_ID Id;
    struct ForgedHeader { IMAGE_DOS_HEADER Dos; BYTE Pad[0x40]; IMAGE_NT_HEADERS32 Nt; } Header;
    PVOID StackBase = NULL, FakeBase = (PVOID)(ULONG_PTR)0xfffff78000000000ULL, FakeHeader = NULL;
    SIZE_T Size = 64 * 1024, FakeSize = 0x1000, Huge = ~(SIZE_T)0, Written;
    ULONG FakeEntry = 0;
    NTSTATUS Status;

    File = CreateFileA(Path, GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    ok(File != INVALID_HANDLE_VALUE, "cannot open %s: %lu\n", Path, GetLastError());
    if (File == INVALID_HANDLE_VALUE) return;
    Status = NtCreateSection(&Section, SECTION_ALL_ACCESS, NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, File);
    CloseHandle(File);
    ok(NT_SUCCESS(Status), "NtCreateSection: %lx\n", Status);
    if (!NT_SUCCESS(Status)) return;
    NtQuerySection(Section, SectionImageInformation, &Image, sizeof(Image), NULL);
    Status = NtCreateProcessEx(&Process, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(), 0, Section, NULL, NULL, FALSE);
    ok(NT_SUCCESS(Status), "NtCreateProcessEx: %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Done;
    Status = NtQueryInformationProcess(Process, ProcessBasicInformation, &Basic, sizeof(Basic), NULL);
    ok(NT_SUCCESS(Status), "ProcessBasicInformation: %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Done;
    if (Forged)
    {
        /* A PE32 header in the child's memory (below 2 GiB), with its own base and entry */
        Status = NtAllocateVirtualMemory(Process, &FakeHeader, 0x7fffffff, &FakeSize,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        ok(NT_SUCCESS(Status), "forged header: %lx\n", Status);
        if (!NT_SUCCESS(Status)) goto Done;
        memset(&Header, 0, sizeof(Header));
        Header.Dos.e_magic = IMAGE_DOS_SIGNATURE;
        Header.Dos.e_lfanew = FIELD_OFFSET(struct ForgedHeader, Nt);
        Header.Nt.Signature = IMAGE_NT_SIGNATURE;
        Header.Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
        Header.Nt.FileHeader.SizeOfOptionalHeader = sizeof(Header.Nt.OptionalHeader);
        Header.Nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        Header.Nt.OptionalHeader.ImageBase = (ULONG)(ULONG_PTR)FakeHeader;
        Header.Nt.OptionalHeader.AddressOfEntryPoint = 0x777;
        Header.Nt.OptionalHeader.SizeOfImage = 0x1000;
        FakeEntry = (ULONG)(ULONG_PTR)FakeHeader + 0x777;
        ok(WriteProcessMemory(Process, FakeHeader, &Header, sizeof(Header), &Written),
           "cannot write the forged header: %lu\n", GetLastError());
        FakeBase = FakeHeader;
    }
    ok(WriteProcessMemory(Process, &Basic.PebBaseAddress->ImageBaseAddress, &FakeBase, sizeof(FakeBase), &Written),
       "cannot write the PEB image base: %lu\n", GetLastError());
    ok(WriteProcessMemory(Process, &Basic.PebBaseAddress->MinimumStackCommit, &Huge, sizeof(Huge), &Written),
       "cannot write the PEB minimum stack commit: %lu\n", GetLastError());

    /* The first thread, created suspended; it never runs user code */
    Status = NtAllocateVirtualMemory(Process, &StackBase, 0, &Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ok(NT_SUCCESS(Status), "stack: %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Done;
    Stack.AllocatedStackBase = Stack.StackLimit = StackBase;
    Stack.StackBase = (PUCHAR)StackBase + Size;
    Native.ContextFlags = CONTEXT_FULL;
    Native.Rsp = (ULONG_PTR)Stack.StackBase - 0x28;
    Native.Rip = (ULONG_PTR)Image.TransferAddress;
    Native.SegCs = 0x33;
    Native.SegSs = Native.SegDs = Native.SegEs = Native.SegGs = 0x2b;
    Native.SegFs = 0x53;
    Native.EFlags = 0x200;
    Status = NtCreateThread(&Thread, THREAD_ALL_ACCESS, NULL, Process, &Id, &Native, &Stack, TRUE);
    ok(NT_SUCCESS(Status), "NtCreateThread: %lx\n", Status);
    if (!NT_SUCCESS(Status)) goto Done;

    memset(&Context, 0x55, sizeof(Context));
    Context.ContextFlags = WOW64_CONTEXT_ALL;
    ok(Wow64GetThreadContext(Thread, &Context), "edited PEB: Wow64GetThreadContext: %lu\n", GetLastError());
    ok(Context.Eax == (ULONG)(ULONG_PTR)Image.TransferAddress,
       "edited PEB (%s): eax %08lx, image entry %p\n", Forged ? "forged header" : "kernel address",
       Context.Eax, Image.TransferAddress);
    ok(!Forged || Context.Eax != FakeEntry, "edited PEB: eax %08lx is the forged header's entry\n", Context.Eax);
    ok(Context.Ebx != 0x55555555 && Context.SegCs == 0x23, "edited PEB: ebx %08lx cs %04lx\n",
       Context.Ebx, Context.SegCs);
Done:
    if (Process) NtTerminateProcess(Process, 0);
    if (Thread)
    {
        WaitForSingleObject(Thread, 10000);
        CloseHandle(Thread);
    }
    if (Process) CloseHandle(Process);
    if (Section) CloseHandle(Section);
}

/* An image whose preferred base is taken when its view is mapped is mapped elsewhere (the guest
 * loader relocates it later), and the start context still has its real entry: the view's base plus
 * the entry RVA, not the entry at the preferred base. The preferred base is made unavailable by
 * moving it over the shared user data page, which every process has before its image is mapped:
 * a copy of the 32-bit cmd.exe, header ImageBase changed to the top of the 32-bit address space
 * (the copy never runs). */
static void TestRelocatedImage(const char *Path)
{
    char Copy[MAX_PATH], Dir[MAX_PATH];
    STARTUPINFOA Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Child;
    PROCESS_BASIC_INFORMATION Basic;
    WOW64_CONTEXT Context;
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS32 Nt;
    ULONG_PTR Peb32 = 0, ViewBase = 0;
    ULONG Preferred, Size;
    HANDLE File;
    PUCHAR Data;
    DWORD Read, Written;
    SIZE_T Remote;

    GetTempPathA(sizeof(Dir), Dir);
    GetTempFileNameA(Dir, "w64", 0, Copy);
    File = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
    {
        skip("cannot open %s: %lu\n", Path, GetLastError());
        return;
    }
    Size = GetFileSize(File, NULL);
    Data = HeapAlloc(GetProcessHeap(), 0, Size);
    if (!Data || !ReadFile(File, Data, Size, &Read, NULL) || Read != Size)
    {
        skip("cannot read %s\n", Path);
        CloseHandle(File);
        if (Data) HeapFree(GetProcessHeap(), 0, Data);
        return;
    }
    CloseHandle(File);
    memcpy(&Dos, Data, sizeof(Dos));
    memcpy(&Nt, Data + Dos.e_lfanew, sizeof(Nt));
    if (Dos.e_magic != IMAGE_DOS_SIGNATURE || Nt.Signature != IMAGE_NT_SIGNATURE ||
        Nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC || Nt.OptionalHeader.SizeOfImage <= 0x10000 ||
        !Nt.OptionalHeader.AddressOfEntryPoint || !Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        skip("%s is not a relocatable PE32 over 64 KiB\n", Path);
        HeapFree(GetProcessHeap(), 0, Data);
        return;
    }
    /* The highest 64 KiB aligned base whose image ends below 0x7fff0000: it covers 0x7ffe0000 */
    Preferred = (0x7fff0000 - Nt.OptionalHeader.SizeOfImage) & ~0xffff;
    ((PIMAGE_NT_HEADERS32)(Data + Dos.e_lfanew))->OptionalHeader.ImageBase = Preferred;
    File = CreateFileA(Copy, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    ok(File != INVALID_HANDLE_VALUE && WriteFile(File, Data, Size, &Written, NULL) && Written == Size,
       "cannot write %s: %lu\n", Copy, GetLastError());
    HeapFree(GetProcessHeap(), 0, Data);
    if (File == INVALID_HANDLE_VALUE) return;
    CloseHandle(File);

    if (!CreateProcessA(Copy, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Child))
    {
        skip("cannot start the rebased copy: %lu\n", GetLastError());
        DeleteFileA(Copy);
        return;
    }
    if (NT_SUCCESS(NtQueryInformationProcess(Child.hProcess, ProcessBasicInformation, &Basic, sizeof(Basic), NULL)))
        ReadProcessMemory(Child.hProcess, &Basic.PebBaseAddress->ImageBaseAddress, &ViewBase, sizeof(ViewBase), &Remote);
    NtQueryInformationProcess(Child.hProcess, ProcessWow64Information, &Peb32, sizeof(Peb32), NULL);
    if (!Peb32 || !ViewBase)
        skip("no WoW64 child or view base (%p, %p)\n", (PVOID)Peb32, (PVOID)ViewBase);
    else if (ViewBase == Preferred)
        skip("the image was mapped at its preferred base %08lx\n", Preferred);
    else
    {
        memset(&Context, 0x55, sizeof(Context));
        Context.ContextFlags = WOW64_CONTEXT_ALL;
        ok(Wow64GetThreadContext(Child.hThread, &Context), "relocated: Wow64GetThreadContext: %lu\n", GetLastError());
        ok(ViewBase < MAXULONG && Context.Eax == (ULONG)ViewBase + Nt.OptionalHeader.AddressOfEntryPoint,
           "relocated: eax %08lx, view base %p + entry RVA %08lx (preferred base %08lx)\n", Context.Eax,
           (PVOID)ViewBase, Nt.OptionalHeader.AddressOfEntryPoint, Preferred);
    }
    TerminateProcess(Child.hProcess, 0);
    WaitForSingleObject(Child.hProcess, 10000);
    CloseHandle(Child.hThread);
    CloseHandle(Child.hProcess);
    DeleteFileA(Copy);
}

static void TestSuspendedMain(void)
{
    char Path[MAX_PATH], Command[] = "cmd.exe /c exit 7";
    STARTUPINFOA Startup = { sizeof(Startup) };
    PROCESS_INFORMATION Child;
    THREAD_BASIC_INFORMATION Basic;
    WOW64_CONTEXT Context;
    ULONG_PTR Peb32 = 0;
    ULONG ImageBase = 0, HeaderOffset = 0, EntryRva = 0, Samples = 0, Retries = 0, Failures = 0, i;
    ULONG_PTR NativeStackBase = 0, CpuArea = 0;
    TEB32 Teb32;
    SIZE_T Read;
    DWORD ExitCode = 0, Error;
    BOOL Ok;

    if (!GetSystemWow64DirectoryA(Path, sizeof(Path) - 16))
    {
        skip("no SysWOW64\n");
        return;
    }
    strcat(Path, "\\cmd.exe");
    if (!CreateProcessA(Path, Command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Startup, &Child))
    {
        skip("cannot start %s: %lu\n", Path, GetLastError());
        return;
    }
    if (!NT_SUCCESS(NtQueryInformationProcess(Child.hProcess, ProcessWow64Information, &Peb32, sizeof(Peb32), NULL)) ||
        !Peb32)
    {
        skip("%s is not a WoW64 child\n", Path);
        TerminateProcess(Child.hProcess, 0);
        goto Done;
    }
    ReadProcessMemory(Child.hProcess, (PUCHAR)Peb32 + 8, &ImageBase, sizeof(ImageBase), &Read);
    ReadProcessMemory(Child.hProcess, (PUCHAR)(ULONG_PTR)ImageBase + 0x3c, &HeaderOffset, sizeof(HeaderOffset), &Read);
    ReadProcessMemory(Child.hProcess, (PUCHAR)(ULONG_PTR)ImageBase + HeaderOffset + 0x28, &EntryRva, sizeof(EntryRva), &Read);

    /* The start context, before the thread ever ran */
    memset(&Context, 0x55, sizeof(Context));
    Context.ContextFlags = WOW64_CONTEXT_ALL;
    Ok = Wow64GetThreadContext(Child.hThread, &Context);
    ok(Ok, "Wow64GetThreadContext on the suspended main thread: %lu\n", GetLastError());
    ok(Context.ContextFlags == WOW64_CONTEXT_ALL, "flags %#lx\n", Context.ContextFlags);
    ok(Context.Eax == ImageBase + EntryRva, "eax %08lx, entry %08lx\n", Context.Eax, ImageBase + EntryRva);
    ok(Context.Ebx == (ULONG)Peb32, "ebx %08lx, PEB32 %08lx\n", Context.Ebx, (ULONG)Peb32);
    ok(!Context.Ecx && !Context.Edx && !Context.Esi && !Context.Edi && !Context.Ebp,
       "ecx %08lx edx %08lx esi %08lx edi %08lx ebp %08lx\n",
       Context.Ecx, Context.Edx, Context.Esi, Context.Edi, Context.Ebp);
    ok((Context.EFlags & ~2) == 0x200, "eflags %08lx\n", Context.EFlags);
    ok(Context.SegCs == 0x23 && Context.SegSs == 0x2b && Context.SegDs == 0x2b && Context.SegEs == 0x2b &&
       Context.SegFs == 0x53 && Context.SegGs == 0x2b, "cs %04lx ss %04lx ds %04lx es %04lx fs %04lx gs %04lx\n",
       Context.SegCs, Context.SegSs, Context.SegDs, Context.SegEs, Context.SegFs, Context.SegGs);
    ok((WORD)Context.FloatSave.ControlWord == 0x27f, "control word %08lx\n", Context.FloatSave.ControlWord);
    ok(*(WORD *)Context.ExtendedRegisters == 0x27f, "SSE control word %04x\n", *(WORD *)Context.ExtendedRegisters);
    ok(*(DWORD *)(Context.ExtendedRegisters + 24) == 0x1f80, "mxcsr %08lx\n", *(DWORD *)(Context.ExtendedRegisters + 24));
    /* EIP is the guest ntdll's RtlUserThreadStart, as on Windows */
    {
        MEMORY_BASIC_INFORMATION Region;
        char Module[16];
        ULONG Expected = 0;
        if (Ok && VirtualQueryEx(Child.hProcess, (PVOID)(ULONG_PTR)Context.Eip, &Region, sizeof(Region)))
            Expected = RemoteExport32(Child.hProcess, (ULONG)(ULONG_PTR)Region.AllocationBase,
                                      "RtlUserThreadStart", Module, sizeof(Module));
        ok(Expected && Context.Eip == Expected && !_stricmp(Module, "ntdll.dll"),
           "eip %08lx, ntdll32!RtlUserThreadStart %08lx (module %s)\n", Context.Eip, Expected,
           Expected ? Module : "?");
    }

    /* Its stack is the guest stack the TEB32 names; the CPU area tops the native stack */
    if (NT_SUCCESS(NtQueryInformationThread(Child.hThread, ThreadBasicInformation, &Basic, sizeof(Basic), NULL)))
    {
        memset(&Teb32, 0, sizeof(Teb32));
        ReadProcessMemory(Child.hProcess, WOW64_TEB32(Basic.TebBaseAddress), &Teb32, sizeof(Teb32), &Read);
        ok(Teb32.NtTib.StackBase && ((Context.Esp + 0xfff) & ~0xfff) == Teb32.NtTib.StackBase,
           "esp %08lx, guest stack base %08lx\n", Context.Esp, Teb32.NtTib.StackBase);
        ReadProcessMemory(Child.hProcess, &((PTEB)Basic.TebBaseAddress)->NtTib.StackBase, &NativeStackBase,
                          sizeof(NativeStackBase), &Read);
        ReadProcessMemory(Child.hProcess, &((PTEB)Basic.TebBaseAddress)->TlsSlots[WOW64_TLS_CPU], &CpuArea,
                          sizeof(CpuArea), &Read);
        ok(CpuArea && CpuArea == NativeStackBase, "CPU area %p, native stack base %p\n",
           (PVOID)CpuArea, (PVOID)NativeStackBase);
    }

    /* A change shows in the next read */
    Context.Ecx = 0x12345678;
    ok(Wow64SetThreadContext(Child.hThread, &Context), "Wow64SetThreadContext: %lu\n", GetLastError());
    memset(&Context, 0x55, sizeof(Context));
    Context.ContextFlags = WOW64_CONTEXT_ALL;
    ok(Wow64GetThreadContext(Child.hThread, &Context), "Wow64GetThreadContext: %lu\n", GetLastError());
    ok(Context.Ecx == 0x12345678, "ecx %08lx\n", Context.Ecx);
    Context.Ecx = 0;
    ok(Wow64SetThreadContext(Child.hThread, &Context), "Wow64SetThreadContext: %lu\n", GetLastError());

    /* While the process initializes, in either mode, the context stays readable. A sample
     * taken during a mode transition asks the caller to retry. */
    for (i = 0; i < 2000 && WaitForSingleObject(Child.hProcess, 0) == WAIT_TIMEOUT; ++i)
    {
        ResumeThread(Child.hThread);
        if (i & 1) Sleep(0);
        SuspendThread(Child.hThread);
        memset(&Context, 0x55, sizeof(Context));
        Context.ContextFlags = WOW64_CONTEXT_ALL | CONTEXT_EXCEPTION_REQUEST;
        if (Wow64GetThreadContext(Child.hThread, &Context))
        {
            ++Samples;
            ok(Context.SegCs == 0x23 && Context.SegDs == 0x2b && Context.SegGs == 0x2b,
               "sample %lu: cs %04lx ds %04lx gs %04lx\n", i, Context.SegCs, Context.SegDs, Context.SegGs);
            ok(Context.ContextFlags & CONTEXT_EXCEPTION_REPORTING, "sample %lu: flags %#lx\n", i, Context.ContextFlags);
            continue;
        }
        Error = GetLastError();
        if (Error == ERROR_RETRY) ++Retries;
        /* A thread that is ending (STATUS_THREAD_IS_TERMINATING) */
        else if (Error != ERROR_ACCESS_DENIED && ++Failures <= 5)
            ok(0, "sample %lu: Wow64GetThreadContext failed: %lu\n", i, Error);
    }
    ok(Samples > 0, "no context read while the child started (retries %lu)\n", Retries);
    trace("%lu samples, %lu retries, %lu failures\n", Samples, Retries, Failures);

    /* The staged start runs the image */
    ResumeThread(Child.hThread);
    ok(WaitForSingleObject(Child.hProcess, 60000) == WAIT_OBJECT_0, "the child did not end\n");
    GetExitCodeProcess(Child.hProcess, &ExitCode);
    ok(ExitCode == 7, "exit code %lu\n", ExitCode);
Done:
    CloseHandle(Child.hThread);
    CloseHandle(Child.hProcess);
    TestEditedPeb(Path, TRUE);
    TestEditedPeb(Path, FALSE);
    TestRelocatedImage(Path);
}
#else
/* A far call into 64-bit code at Code + sizeof(FarCall) */
static const BYTE FarCall[] =
{
    0x58,                         /* pop eax */
    0x0e,                         /* push cs */
    0x50,                         /* push eax */
    0x6a, 0x33,                   /* push 0x33 */
    0xe8, 0, 0, 0, 0,             /* call 1f */
    0x83, 0x04, 0x24, 0x05,       /* 1: add dword ptr [esp], 5 */
    0xcb,                         /* retf */
};
/* mov rax, Registers; mov [rax], r12; mov [rax + 8], r13; mov [rax + 16], r14;
 * 1: cmp dword ptr [rax + 24], 0; jne 1b; retf */
static BYTE Body64[] =
{
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
    0x4c, 0x89, 0x20,
    0x4c, 0x89, 0x68, 0x08,
    0x4c, 0x89, 0x70, 0x10,
    0x83, 0x78, 0x18, 0x00,
    0x75, 0xfa,
    0xcb,
};
static volatile ULONG64 Registers[4];
static BYTE *Code;

static DWORD WINAPI Spin64(PVOID Parameter)
{
    ((void (*)(void))Code)();
    return 0;
}

static void TestFarTransfer(void)
{
    PUCHAR Teb64 = (PUCHAR)NtCurrentTeb() - 0x2000;
    ULONG64 StackBase, StackLimit, CpuArea;
    CONTEXT Context;
    HANDLE Thread;
    BOOL IsWow64 = FALSE;
    ULONG i;

    if (!IsWow64Process(GetCurrentProcess(), &IsWow64) || !IsWow64)
    {
        skip("not running under WoW64\n");
        return;
    }
    Code = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!Code)
    {
        skip("no code page\n");
        return;
    }
    *(ULONG64 *)(Body64 + 2) = (ULONG_PTR)Registers;
    memcpy(Code, FarCall, sizeof(FarCall));
    memcpy(Code + sizeof(FarCall), Body64, sizeof(Body64));

    /* The registers 64-bit code finds */
    Registers[3] = 0;
    ((void (*)(void))Code)();
    StackBase = *(ULONG64 *)(Teb64 + 0x08);
    StackLimit = *(ULONG64 *)(Teb64 + 0x10);
    /* The 64-bit TEB's TlsSlots are at 0x1480 */
    CpuArea = *(ULONG64 *)(Teb64 + 0x1480 + WOW64_TLS_CPU * sizeof(ULONG64));
    ok(Registers[0] == (ULONG_PTR)Teb64, "r12 %08lx%08lx, TEB %p\n",
       (ULONG)(Registers[0] >> 32), (ULONG)Registers[0], Teb64);
    ok(Registers[1] >= CpuArea && Registers[1] <= (CpuArea | 0xfff), "r13 %08lx%08lx, CPU area %08lx\n",
       (ULONG)(Registers[1] >> 32), (ULONG)Registers[1], (ULONG)CpuArea);
    ok(Registers[2] >= StackLimit && Registers[2] <= StackBase, "r14 %08lx%08lx, native stack %08lx-%08lx\n",
       (ULONG)(Registers[2] >> 32), (ULONG)Registers[2], (ULONG)StackLimit, (ULONG)StackBase);

    /* A thread that stays in 64-bit code */
    Registers[0] = 0;
    Registers[3] = 1;
    Thread = CreateThread(NULL, 0, Spin64, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread: %lu\n", GetLastError());
    if (!Thread) return;
    for (i = 0; i < 500 && !Registers[0]; ++i) Sleep(10);
    ok(Registers[0] != 0, "the thread did not reach 64-bit code\n");
    for (i = 0; i < 3; ++i)
    {
        SuspendThread(Thread);
        memset(&Context, 0x55, sizeof(Context));
        Context.ContextFlags = CONTEXT_CONTROL | CONTEXT_EXCEPTION_REQUEST;
        ok(GetThreadContext(Thread, &Context), "GetThreadContext in 64-bit code: %lu\n", GetLastError());
        ok(Context.ContextFlags == (CONTEXT_CONTROL | CONTEXT_EXCEPTION_REQUEST | CONTEXT_EXCEPTION_REPORTING |
                                    CONTEXT_EXCEPTION_ACTIVE), "flags %#lx\n", Context.ContextFlags);
        ok(Context.SegCs == 0x23, "cs %04lx\n", Context.SegCs);
        ResumeThread(Thread);
        Sleep(10);
    }
    Registers[3] = 0;
    ok(WaitForSingleObject(Thread, 10000) == WAIT_OBJECT_0, "the thread did not end\n");
    CloseHandle(Thread);
}
#endif

START_TEST(Wow64StartContext)
{
#ifdef _WIN64
    HMODULE Kernel32 = GetModuleHandleA("kernel32.dll");
    pWow64GetThreadContext = (PVOID)GetProcAddress(Kernel32, "Wow64GetThreadContext");
    pWow64SetThreadContext = (PVOID)GetProcAddress(Kernel32, "Wow64SetThreadContext");
    if (!pWow64GetThreadContext || !pWow64SetThreadContext)
    {
        skip("no Wow64Get/SetThreadContext\n");
        return;
    }
    TestSuspendedMain();
#else
    TestFarTransfer();
#endif
}
