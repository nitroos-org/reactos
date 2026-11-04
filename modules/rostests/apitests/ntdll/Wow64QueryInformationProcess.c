/* NtQueryInformationProcess from a 32-bit process: I/O counters, times, memory counters,
 * device map, image file name and handle count (GetProcessIoCounters, GetProcessTimes,
 * GetProcessMemoryInfo, GetLogicalDrives' process map, GetProcessImageFileName,
 * GetProcessHandleCount) and handle table (the Chromium sandbox checks its target's handles
 * with it; sandboxed Firefox content processes exit when either fails). Expected
 * values measured on Windows Server 2008 R2 and Windows 10 WoW64.
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "precomp.h"

/* The 32-bit layouts */
typedef struct { ULONG PeakVirtualSize, VirtualSize, PageFaultCount, PeakWorkingSetSize, WorkingSetSize,
                 QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage,
                 PagefileUsage, PeakPagefileUsage, PrivateUsage; } VM_COUNTERS_EX32;
typedef struct { ULONG DriveMap; UCHAR DriveType[32]; } DEVICEMAP32;

static NTSTATUS Query(PROCESSINFOCLASS Class, PVOID Buffer, ULONG Length, PULONG Ret)
{
    *Ret = 0xdeadbeef;
    return NtQueryInformationProcess(NtCurrentProcess(), Class, Buffer, Length, Ret);
}

/* Every length but Good fails with STATUS_INFO_LENGTH_MISMATCH */
static void WrongLengths(PROCESSINFOCLASS Class, const ULONG *Lengths, ULONG Count, const char *Name)
{
    UCHAR Buffer[256];
    ULONG Ret, i, j;
    NTSTATUS Status;
    for (i = 0; i < Count; ++i)
    {
        memset(Buffer, 0x5a, sizeof(Buffer));
        Status = Query(Class, Buffer, Lengths[i], &Ret);
        ok(Status == STATUS_INFO_LENGTH_MISMATCH, "%s length %lu: 0x%lx\n", Name, Lengths[i], Status);
        for (j = 0; j < sizeof(Buffer) && Buffer[j] == 0x5a; ++j);
        ok(j == sizeof(Buffer), "%s length %lu: written at %lu\n", Name, Lengths[i], j);
    }
}

static void TestIoCounters(void)
{
    static const ULONG Lengths[] = {40, 44, 52, 56, 96};
    DECLSPEC_ALIGN(8) UCHAR Buffer[64];
    IO_COUNTERS Io;
    ULONG Ret;
    NTSTATUS Status;

    C_ASSERT(sizeof(IO_COUNTERS) == 48);
    Status = Query(ProcessIoCounters, &Io, sizeof(Io), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(Ret, sizeof(Io));
    ok(Io.ReadOperationCount + Io.OtherOperationCount > 0, "No I/O operations\n");
    Status = Query(ProcessIoCounters, Buffer + 4, sizeof(Io), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = Query(ProcessIoCounters, Buffer + 1, sizeof(Io), &Ret);
    ok_ntstatus(Status, STATUS_DATATYPE_MISALIGNMENT);
    WrongLengths(ProcessIoCounters, Lengths, ARRAYSIZE(Lengths), "IoCounters");
}

static void TestTimes(void)
{
    static const ULONG Lengths[] = {28, 36, 64};
    KERNEL_USER_TIMES Times;
    LARGE_INTEGER Now;
    UCHAR Buffer[64];
    ULONG Ret;
    NTSTATUS Status;

    Status = Query(ProcessTimes, &Times, sizeof(Times), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(Ret, sizeof(Times));
    NtQuerySystemTime(&Now);
    /* The system time is updated at clock ticks; the creation time can be a little later */
    ok(Times.CreateTime.QuadPart > 0 && Times.CreateTime.QuadPart <= Now.QuadPart + 10000000, "CreateTime %I64x, now %I64x\n",
       Times.CreateTime.QuadPart, Now.QuadPart);
    ok(Times.ExitTime.QuadPart == 0, "ExitTime %I64x\n", Times.ExitTime.QuadPart);
    ok(Times.UserTime.QuadPart + Times.KernelTime.QuadPart >= 0, "Negative times\n");
    Status = Query(ProcessTimes, Buffer + 1, sizeof(Times), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(!memcmp(Buffer + 1, &Times, sizeof(LARGE_INTEGER)), "Unaligned CreateTime differs\n");
    Status = Query(ProcessTimes, (PVOID)0x10, sizeof(Times), &Ret);
    ok_ntstatus(Status, STATUS_ACCESS_VIOLATION);
    WrongLengths(ProcessTimes, Lengths, ARRAYSIZE(Lengths), "Times");
}

static void TestVmCounters(void)
{
    static const ULONG Lengths[] = {40, 52, 88, 96};
    VM_COUNTERS_EX32 Vm;
    UCHAR Buffer[64];
    ULONG Ret;
    NTSTATUS Status;

    memset(&Vm, 0x5a, sizeof(Vm));
    Status = Query(ProcessVmCounters, &Vm, sizeof(Vm), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(Ret, sizeof(Vm));
    /* The ReactOS memory manager does not count page faults, for 64-bit processes either */
    todo_if(is_reactos())
    ok(Vm.PageFaultCount > 0, "PageFaultCount %lu\n", Vm.PageFaultCount);
    ok(Vm.VirtualSize > 0 && Vm.PeakVirtualSize >= Vm.VirtualSize, "Virtual %lx, peak %lx\n", Vm.VirtualSize, Vm.PeakVirtualSize);
    ok(Vm.WorkingSetSize > 0 && Vm.PeakWorkingSetSize >= Vm.WorkingSetSize, "Working set %lx, peak %lx\n",
       Vm.WorkingSetSize, Vm.PeakWorkingSetSize);
    ok(Vm.PagefileUsage > 0 && Vm.PeakPagefileUsage >= Vm.PagefileUsage, "Pagefile %lx, peak %lx\n",
       Vm.PagefileUsage, Vm.PeakPagefileUsage);
    ok(Vm.PrivateUsage == Vm.PagefileUsage, "Private %lx, pagefile %lx\n", Vm.PrivateUsage, Vm.PagefileUsage);

    memset(Buffer, 0x5a, sizeof(Buffer));
    Status = Query(ProcessVmCounters, Buffer + 1, FIELD_OFFSET(VM_COUNTERS_EX32, PrivateUsage), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(Ret, FIELD_OFFSET(VM_COUNTERS_EX32, PrivateUsage));
    ok(Buffer[1 + FIELD_OFFSET(VM_COUNTERS_EX32, PrivateUsage)] == 0x5a, "Wrote PrivateUsage\n");
    ok(((VM_COUNTERS_EX32 UNALIGNED *)(Buffer + 1))->PageFaultCount >= Vm.PageFaultCount, "Unaligned counters wrong\n");
    WrongLengths(ProcessVmCounters, Lengths, ARRAYSIZE(Lengths), "VmCounters");
}

static void TestDeviceMap(void)
{
    static const ULONG Lengths[] = {32, 40, 44};
    DEVICEMAP32 Map;
    WCHAR Windows[MAX_PATH];
    ULONG Ret, Drive;
    NTSTATUS Status;

    C_ASSERT(sizeof(DEVICEMAP32) == 36);
    memset(&Map, 0x5a, sizeof(Map));
    Status = Query(ProcessDeviceMap, &Map, sizeof(Map), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(Ret, sizeof(Map));
    GetWindowsDirectoryW(Windows, ARRAYSIZE(Windows));
    Drive = towupper(Windows[0]) - L'A';
    ok(Drive < 26 && (Map.DriveMap & (1 << Drive)), "Drive map %lx lacks the system drive %c:\n", Map.DriveMap, Windows[0]);
    if (Drive < 26)
        ok(Map.DriveType[Drive] == DRIVE_FIXED, "System drive type %u\n", Map.DriveType[Drive]);
    WrongLengths(ProcessDeviceMap, Lengths, ARRAYSIZE(Lengths), "DeviceMap");
}

static void TestImageFileName(void)
{
    UCHAR Buffer[1024];
    PUNICODE_STRING Name = (PUNICODE_STRING)Buffer;
    WCHAR Path[MAX_PATH], *Exe;
    ULONG Ret, Needed, Length, i;
    SIZE_T ExeLength;
    NTSTATUS Status;

    memset(Buffer, 0x5a, sizeof(Buffer));
    Status = Query(ProcessImageFileName, Buffer, sizeof(Buffer), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    ok(Name->Buffer == (PWSTR)(Name + 1), "Buffer %p, expected %p\n", Name->Buffer, Name + 1);
    ok(Name->Length > 8 && Name->MaximumLength == Name->Length + sizeof(WCHAR), "Length %u, MaximumLength %u\n",
       Name->Length, Name->MaximumLength);
    Needed = sizeof(UNICODE_STRING) + Name->Length + sizeof(WCHAR);
    ok_long(Ret, Needed);
    if (Name->Buffer != (PWSTR)(Name + 1) || Needed >= sizeof(Buffer)) return;
    ok(Name->Buffer[Name->Length / sizeof(WCHAR)] == UNICODE_NULL, "Not terminated\n");
    ok(Buffer[Needed] == 0x5a, "Wrote past the name\n");
    ok(!_wcsnicmp(Name->Buffer, L"\\Device\\", 8), "Name %wZ\n", Name);
    GetModuleFileNameW(NULL, Path, ARRAYSIZE(Path));
    Exe = wcsrchr(Path, L'\\');
    ExeLength = Exe ? wcslen(Exe) : 0;
    ok(Exe && Name->Length >= ExeLength * sizeof(WCHAR) &&
       !_wcsnicmp(Name->Buffer + Name->Length / sizeof(WCHAR) - ExeLength, Exe, ExeLength),
       "Name %wZ, executable %S\n", Name, Path);

    /* Every shorter buffer fails with the required length */
    for (Length = 0; Length < Needed; Length += (Length < 24 ? 4 : Needed - 1 - Length))
    {
        memset(Buffer, 0x5a, sizeof(Buffer));
        Status = Query(ProcessImageFileName, Buffer, Length, &Ret);
        ok(Status == STATUS_INFO_LENGTH_MISMATCH, "Length %lu: 0x%lx\n", Length, Status);
        ok(Ret == Needed, "Length %lu: return length %lu, expected %lu\n", Length, Ret, Needed);
        for (i = 0; i < sizeof(Buffer) && Buffer[i] == 0x5a; ++i);
        ok(i == sizeof(Buffer), "Length %lu: written at %lu\n", Length, i);
        if (Length == Needed - 1) break;
    }
    Status = Query(ProcessImageFileName, Buffer + 1, Needed, &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, Buffer, Needed, NULL);
    ok_ntstatus(Status, STATUS_SUCCESS);
    /* A return length inside the buffer is stored first and overwritten by the name (measured
     * on Windows WoW64; the memory section name stores it last) */
    memset(Buffer, 0x5a, sizeof(Buffer));
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, Buffer, sizeof(Buffer),
                                       (PULONG)(Buffer + sizeof(UNICODE_STRING)));
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Name->Buffer == (PWSTR)(Name + 1) && Name->MaximumLength == Needed - sizeof(UNICODE_STRING),
       "Aliased query: buffer %p, MaximumLength %u\n", Name->Buffer, Name->MaximumLength);
    ok(!_wcsnicmp((PWSTR)(Buffer + sizeof(UNICODE_STRING)), L"\\Device\\", 8), "Name overwritten: %.8S\n",
       (PWSTR)(Buffer + sizeof(UNICODE_STRING)));
}

static void TestHandleCount(void)
{
    static const ULONG Wrong[] = { 0, 2, 3, 5, 16 };
    ULONG Count = 0, After = 0, Ret;
    NTSTATUS Status;
    HANDLE Event;

    Status = Query(ProcessHandleCount, &Count, sizeof(Count), &Ret);
    ok(Status == STATUS_SUCCESS, "Handle count: 0x%lx\n", Status);
    ok(Ret == sizeof(ULONG), "Handle count: return length %lu\n", Ret);
    ok(Count > 0, "Handle count: %lu\n", Count);
    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(Event != NULL, "CreateEvent: %lu\n", GetLastError());
    Status = Query(ProcessHandleCount, &After, sizeof(After), &Ret);
    ok(Status == STATUS_SUCCESS && After == Count + 1, "Handle count with an event: 0x%lx, %lu after %lu\n",
       Status, After, Count);
    if (Event) CloseHandle(Event);
    WrongLengths(ProcessHandleCount, Wrong, RTL_NUMBER_OF(Wrong), "Handle count");
}

/* ProcessHandleTable (Windows 8.1 and later): the handle values as ULONGs */
#define ProcessHandleTableClass ((PROCESSINFOCLASS)58)
static void TestHandleTable(void)
{
    ULONG Table[4096], Ret, i;
    BOOL Found = FALSE;
    NTSTATUS Status;
    HANDLE Event;

    if (GetNTVersion() < _WIN32_WINNT_WINBLUE)
    {
        skip("ProcessHandleTable is Windows 8.1 and later\n");
        return;
    }
    Event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(Event != NULL, "CreateEvent: %lu\n", GetLastError());
    Status = Query(ProcessHandleTableClass, Table, sizeof(Table), &Ret);
    ok(Status == STATUS_SUCCESS, "Handle table: 0x%lx\n", Status);
    ok(Ret % sizeof(ULONG) == 0 && Ret > sizeof(ULONG) && Ret <= sizeof(Table), "Handle table: return length %lu\n", Ret);
    for (i = 0; Status == STATUS_SUCCESS && i < Ret / sizeof(ULONG); ++i)
        if (Table[i] == HandleToUlong(Event)) Found = TRUE;
    ok(Found, "Handle table: event %p not listed\n", Event);
    if (Event) CloseHandle(Event);
}

/* ProcessMitigationPolicy (52): { Policy, Flags }, the same in both widths. A sandboxed 32-bit Firefox asks for the
 * Win32k lockdown of its own process this way; the request must reach the kernel, not fail as unsupported */
#define ProcessMitigationPolicyClass ((PROCESSINFOCLASS)52)
static void TestMitigationPolicy(void)
{
    ULONG Request[2], Ret;
    NTSTATUS Status;

    if (GetNTVersion() < _WIN32_WINNT_WIN8)
    {
        skip("ProcessMitigationPolicy is Windows 8 and later\n");
        return;
    }
    Request[0] = 4;     /* ProcessSystemCallDisablePolicy */
    Request[1] = 0xdeadbeef;
    Status = Query(ProcessMitigationPolicyClass, Request, sizeof(Request), &Ret);
    ok(Status == STATUS_SUCCESS, "Mitigation policy: 0x%lx\n", Status);
    ok(Request[0] == 4, "Mitigation policy: policy %lu\n", Request[0]);
    ok(Request[1] == 0, "Mitigation policy: flags 0x%lx, a process that was not created locked down has none\n", Request[1]);
}

START_TEST(Wow64QueryInformationProcess)
{
    BOOL Wow64 = FALSE;

    /* The 32-bit layouts and the semantics of the WoW64 translation */
    IsWow64Process(GetCurrentProcess(), &Wow64);
    if (!Wow64)
    {
        skip("Not a 32-bit process under WoW64\n");
        return;
    }
    TestIoCounters();
    TestTimes();
    TestVmCounters();
    TestDeviceMap();
    TestImageFileName();
    TestHandleCount();
    TestHandleTable();
    TestMitigationPolicy();
}
