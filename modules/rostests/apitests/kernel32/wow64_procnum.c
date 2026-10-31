/* PE32 fixture for ProcessorNumber.c. SPDX-License-Identifier: MIT */
#define WIN32_NO_STATUS
#include <windows.h>
#include <strsafe.h>
#include "ProcessorNumberCheck.h"

void __cdecl mainCRTStartup(void)
{
    CHAR Message[512], Line[640];
    ULONG Checked, Failures;
    DWORD Written;

    Failures = CheckProcessorNumbers(Message, sizeof(Message), &Checked);
    StringCchPrintfA(Line, sizeof(Line), "wow64_procnum: %lu of %lu processors disagree %s\r\n", Failures, Checked, Message);
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), Line, lstrlenA(Line), &Written, NULL);
    ExitProcess(Failures != 0);
}
