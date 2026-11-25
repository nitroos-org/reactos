/* NtQueryInformationProcess / NtQueryInformationThread classes whose 32-bit form is the same as the
 * native one (a ULONG, a pair of ULONGLONGs, a GUID, ...) or has 4-byte pointer-sized fields
 * (ProcessImageInformation, ThreadGroupInformation). Lengths and results as a 32-bit program gets
 * them on Windows Server 2022 (own 32-bit probe: status, accepted length and returned length of
 * the own process and thread per class). Runs in a 32-bit program only (i386 or WoW64).
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "precomp.h"

#define ProcessWx86InformationClass 19
#define ProcessPriorityBoostClass 22
#define ProcessLUIDDeviceMapsEnabledClass 28
#define ProcessImageInformationClass 37
#define ProcessCycleTimeClass 38
#define ProcessProtectionInformationClass 61

static void ProcessClass(ULONG Class, ULONG Length, const char *Name)
{
    UCHAR Buffer[64];
    ULONG Ret = 0xdeadbeef;
    NTSTATUS Status;

    memset(Buffer, 0xa5, sizeof(Buffer));
    Status = NtQueryInformationProcess(NtCurrentProcess(), Class, Buffer, Length, &Ret);
    ok(Status == STATUS_SUCCESS, "%s: 0x%lx\n", Name, Status);
    ok(Ret == Length, "%s: returned length %lu, expected %lu\n", Name, Ret, Length);
    if (Length > 1)
    {
        memset(Buffer, 0xa5, sizeof(Buffer));
        Ret = 0xdeadbeef;
        Status = NtQueryInformationProcess(NtCurrentProcess(), Class, Buffer, Length - 1, &Ret);
        ok(Status == STATUS_INFO_LENGTH_MISMATCH, "%s: one byte short: 0x%lx\n", Name, Status);
    }
}

static void ThreadClass(ULONG Class, ULONG Length, const char *Name)
{
    UCHAR Buffer[64];
    ULONG Ret = 0xdeadbeef;
    NTSTATUS Status;

    memset(Buffer, 0xa5, sizeof(Buffer));
    Status = NtQueryInformationThread(NtCurrentThread(), Class, Buffer, Length, &Ret);
    ok(Status == STATUS_SUCCESS, "%s: 0x%lx\n", Name, Status);
    ok(Ret == Length, "%s: returned length %lu, expected %lu\n", Name, Ret, Length);
    memset(Buffer, 0xa5, sizeof(Buffer));
    Status = NtQueryInformationThread(NtCurrentThread(), Class, Buffer, Length - 1, &Ret);
    ok(Status == STATUS_INFO_LENGTH_MISMATCH, "%s: one byte short: 0x%lx\n", Name, Status);
}

typedef struct
{
    ULONG TransferAddress, ZeroBits, MaximumStackSize, CommittedStackSize, SubSystemType, SubSystemVersion, GpValue;
    USHORT ImageCharacteristics, DllCharacteristics, Machine;
    UCHAR ImageContainsCode, ImageFlags;
    ULONG LoaderFlags, ImageFileSize, CheckSum;
} IMAGE_INFORMATION32;

static void InvalidClasses(void)
{
    /* Classes that Windows Server 2022 answers STATUS_INVALID_INFO_CLASS for a 32-bit program (and that the native
     * service refuses as well) */
    static const ULONG ProcessClasses[] = { 5, 6, 8, 9, 11, 13, 16, 17, 25, 40, 41, 48, 53, 56, 57, 62, 63, 68 };
    static const ULONG ThreadClasses[] = { 2, 3, 5, 7, 8, 10, 13, 15, 19, 27, 28, 31 };
    UCHAR Buffer[64];
    ULONG i;
    NTSTATUS Status;

    for (i = 0; i < _countof(ProcessClasses); i++)
    {
        Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessClasses[i], Buffer, sizeof(Buffer), NULL);
        ok(Status == STATUS_INVALID_INFO_CLASS, "process class %lu: 0x%lx\n", ProcessClasses[i], Status);
    }
    for (i = 0; i < _countof(ThreadClasses); i++)
    {
        Status = NtQueryInformationThread(NtCurrentThread(), ThreadClasses[i], Buffer, sizeof(Buffer), NULL);
        ok(Status == STATUS_INVALID_INFO_CLASS, "thread class %lu: 0x%lx\n", ThreadClasses[i], Status);
    }
}

START_TEST(Wow64QueryInformationClasses)
{
    IMAGE_INFORMATION32 Image;
    struct { ULONG Mask; USHORT Group; USHORT Reserved[3]; } Group;
    ULONGLONG Cycles[2];
    ULONG Ret = 0;
    NTSTATUS Status;

    if (sizeof(PVOID) != 4)
    {
        skip("32-bit layouts: 32-bit program only\n");
        return;
    }

    InvalidClasses();
    ProcessClass(ProcessWx86InformationClass, 4, "ProcessWx86Information");
    ProcessClass(ProcessPriorityBoostClass, 4, "ProcessPriorityBoost");
    ProcessClass(ProcessLUIDDeviceMapsEnabledClass, 4, "ProcessLUIDDeviceMapsEnabled");
    ProcessClass(ProcessCycleTimeClass, 16, "ProcessCycleTime");
    ProcessClass(ProcessProtectionInformationClass, 1, "ProcessProtectionInformation");

    memset(&Image, 0xa5, sizeof(Image));
    Ret = 0xdeadbeef;
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessImageInformationClass, &Image, sizeof(Image), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(Ret, 48);
    ok(sizeof(Image) == 48, "layout\n");
    ok(Image.TransferAddress != 0 && Image.TransferAddress != 0xa5a5a5a5, "TransferAddress %lx\n", Image.TransferAddress);
    ok(Image.SubSystemType == IMAGE_SUBSYSTEM_WINDOWS_CUI, "SubSystemType %lu\n", Image.SubSystemType);
    ok(Image.Machine == IMAGE_FILE_MACHINE_I386, "Machine %x\n", Image.Machine);
    ok(Image.ImageContainsCode, "ImageContainsCode\n");
    ok(Image.CommittedStackSize != 0 && Image.CommittedStackSize <= Image.MaximumStackSize, "stack sizes %lx %lx\n",
       Image.CommittedStackSize, Image.MaximumStackSize);
    ok(Image.ImageFileSize != 0, "ImageFileSize\n");
    ok(Image.ImageCharacteristics & IMAGE_FILE_EXECUTABLE_IMAGE, "ImageCharacteristics %x\n", Image.ImageCharacteristics);
    memset(&Image, 0xa5, sizeof(Image));
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessImageInformationClass, &Image, 47, &Ret);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);

    memset(Cycles, 0, sizeof(Cycles));
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessCycleTimeClass, Cycles, sizeof(Cycles), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok(Cycles[0] != 0, "process cycle time is zero\n");

    ThreadClass(ThreadIoPriority, 4, "ThreadIoPriority");
    ThreadClass(ThreadCycleTime, 16, "ThreadCycleTime");
    ThreadClass(ThreadPagePriority, 4, "ThreadPagePriority");
    ThreadClass(ThreadActualBasePriority, 4, "ThreadActualBasePriority");
    ThreadClass(ThreadIdealProcessorEx, 4, "ThreadIdealProcessorEx");
    ThreadClass(ThreadSuspendCount, 4, "ThreadSuspendCount");
    ThreadClass(ThreadContainerId, 16, "ThreadContainerId");
    ThreadClass(ThreadDynamicCodePolicyInfo, 4, "ThreadDynamicCodePolicyInfo");

    memset(&Group, 0xa5, sizeof(Group));
    Ret = 0xdeadbeef;
    Status = NtQueryInformationThread(NtCurrentThread(), ThreadGroupInformation, &Group, sizeof(Group), &Ret);
    ok_ntstatus(Status, STATUS_SUCCESS);
    ok_long(Ret, 12);
    ok(Group.Mask != 0 && Group.Mask != 0xa5a5a5a5, "group mask %lx\n", Group.Mask);
    ok(Group.Group == 0, "group %u\n", Group.Group);
    Status = NtQueryInformationThread(NtCurrentThread(), ThreadGroupInformation, &Group, 16, &Ret);
    ok_ntstatus(Status, STATUS_INFO_LENGTH_MISMATCH);
}
