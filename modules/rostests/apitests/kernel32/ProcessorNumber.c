/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests that the processor number APIs report the processor the thread runs on
 */

#include "precomp.h"
#include "ProcessorNumberCheck.h"

START_TEST(ProcessorNumber)
{
    CHAR Message[512];
    ULONG Checked, Failures;

    Failures = CheckProcessorNumbers(Message, sizeof(Message), &Checked);
    ok(Failures == 0, "%lu of %lu processors disagree, first: %s\n", Failures, Checked, Message);
    ok(Checked >= 1, "no processor checked\n");
    if (Checked < 2)
        skip("only %lu processor, the test cannot tell a constant from the current processor\n", Checked);

#ifdef _WIN64
    /* The 32-bit side of WoW64: the i386 fixture runs the same check */
    {
        WCHAR Image[MAX_PATH];
        STARTUPINFOW Startup = {sizeof(Startup)};
        PROCESS_INFORMATION Process;
        DWORD ExitCode = ~0u;

        GetWindowsDirectoryW(Image, RTL_NUMBER_OF(Image));
        wcscat(Image, L"\\SysWOW64\\wow64_procnum.exe");
        if (GetFileAttributesW(Image) == INVALID_FILE_ATTRIBUTES)
        {
            skip("Install the i386 wow64_procnum.exe fixture to test the WoW64 path\n");
            return;
        }
        if (!CreateProcessW(Image, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &Startup, &Process))
        {
            ok(0, "CreateProcess wow64_procnum.exe failed %lu\n", GetLastError());
            return;
        }
        ok(WaitForSingleObject(Process.hProcess, 60000) == WAIT_OBJECT_0, "fixture did not exit\n");
        GetExitCodeProcess(Process.hProcess, &ExitCode);
        ok(ExitCode == 0, "the 32-bit process saw a wrong processor number (exit code %lu, run it to see)\n", ExitCode);
        CloseHandle(Process.hThread);
        CloseHandle(Process.hProcess);
    }
#endif
}
