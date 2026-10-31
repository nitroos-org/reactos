/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Shared check for ProcessorNumber.c and the wow64_procnum.exe fixture
 */

#ifndef _PROCESSOR_NUMBER_CHECK_H_
#define _PROCESSOR_NUMBER_CHECK_H_

/* Not declared at the WINVER of the i386 build, so everything is looked up */
typedef DWORD (WINAPI *PFN_GetCurrentProcessorNumber)(VOID);
typedef ULONG (NTAPI *PFN_NtGetCurrentProcessorNumber)(VOID);
typedef LONG (NTAPI *PFN_NtGetCurrentProcessorNumberEx)(PROCESSOR_NUMBER *);
typedef VOID (WINAPI *PFN_GetCurrentProcessorNumberEx)(PROCESSOR_NUMBER *);

/*
 * Pins the calling thread to each processor of the process affinity mask in turn and checks that
 * GetCurrentProcessorNumber, GetCurrentProcessorNumberEx, RtlGetCurrentProcessorNumber,
 * NtGetCurrentProcessorNumber and NtGetCurrentProcessorNumberEx all report that processor.
 * Returns the number of processors that disagreed (or could not be pinned to). Message gets the
 * first mismatch. *Checked gets the number of processors tried.
 */
static ULONG
CheckProcessorNumbers(
    _Out_writes_(Size) PSTR Message,
    _In_ SIZE_T Size,
    _Out_ PULONG Checked)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    PFN_NtGetCurrentProcessorNumber pNt, pRtl;
    PFN_NtGetCurrentProcessorNumberEx pNtEx;
    PFN_GetCurrentProcessorNumber pK32;
    PFN_GetCurrentProcessorNumberEx pK32Ex;
    DWORD_PTR ProcessMask, SystemMask, Bit;
    BOOLEAN Pinned = FALSE;
    ULONG Cpu, Attempt, Failures = 0;

    *Checked = 0;
    Message[0] = '\0';
    pNt = (PFN_NtGetCurrentProcessorNumber)GetProcAddress(hNtdll, "NtGetCurrentProcessorNumber");
    pRtl = (PFN_NtGetCurrentProcessorNumber)GetProcAddress(hNtdll, "RtlGetCurrentProcessorNumber");
    pNtEx = (PFN_NtGetCurrentProcessorNumberEx)GetProcAddress(hNtdll, "NtGetCurrentProcessorNumberEx");
    pK32 = (PFN_GetCurrentProcessorNumber)GetProcAddress(hKernel32, "GetCurrentProcessorNumber");
    pK32Ex = (PFN_GetCurrentProcessorNumberEx)GetProcAddress(hKernel32, "GetCurrentProcessorNumberEx");

    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask) || !ProcessMask)
    {
        StringCchPrintfA(Message, Size, "GetProcessAffinityMask failed %lu", GetLastError());
        return 1;
    }

    for (Cpu = 0, Bit = 1; Bit; Cpu++, Bit <<= 1)
    {
        ULONG Nt = 0, Rtl = 0, K32 = 0, NtExStatus = 0;
        PROCESSOR_NUMBER K32Ex, NtEx;
        BOOLEAN Good = FALSE;

        if (!(ProcessMask & Bit))
            continue;

        if (!SetThreadAffinityMask(GetCurrentThread(), Bit))
        {
            if (!Failures)
                StringCchPrintfA(Message, Size, "cannot pin to processor %lu (error %lu)", Cpu, GetLastError());
            Failures++;
            break;
        }
        Pinned = TRUE;
        (*Checked)++;

        /* The migration happens on the way out of SetThreadAffinityMask or a little later */
        for (Attempt = 0; Attempt < 100 && !Good; Attempt++)
        {
            Sleep(1);
            memset(&K32Ex, 0xAA, sizeof(K32Ex));
            memset(&NtEx, 0xAA, sizeof(NtEx));
            K32 = pK32 ? pK32() : Cpu;
            if (pK32Ex) pK32Ex(&K32Ex); else K32Ex.Number = (UCHAR)Cpu, K32Ex.Group = 0;
            Rtl = pRtl ? pRtl() : Cpu;
            Nt = pNt ? pNt() : Cpu;
            if (pNtEx) NtExStatus = (ULONG)pNtEx(&NtEx); else NtEx.Number = (UCHAR)Cpu, NtEx.Group = 0, NtEx.Reserved = 0;
            Good = K32 == Cpu && K32Ex.Number == Cpu && K32Ex.Group == 0 &&
                   Rtl == Cpu && Nt == Cpu &&
                   NtExStatus == 0 && NtEx.Number == Cpu && NtEx.Group == 0 && NtEx.Reserved == 0;
        }
        if (!Good)
        {
            if (!Failures)
                StringCchPrintfA(Message, Size,
                    "pinned to %lu: GetCurrentProcessorNumber %lu, GetCurrentProcessorNumberEx %u/%u, "
                    "RtlGetCurrentProcessorNumber %lu, NtGetCurrentProcessorNumber %lu, "
                    "NtGetCurrentProcessorNumberEx 0x%lx %u/%u/%u",
                    Cpu, K32, K32Ex.Group, K32Ex.Number, Rtl, Nt, NtExStatus, NtEx.Group, NtEx.Number, NtEx.Reserved);
            Failures++;
        }
    }

    if (Pinned)
        SetThreadAffinityMask(GetCurrentThread(), ProcessMask);
    return Failures;
}

#endif /* _PROCESSOR_NUMBER_CHECK_H_ */
