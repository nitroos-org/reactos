/*
 * PROJECT:     NitroOS tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Gate S8 of the sessions design: the SM APIs that start
 *              processes or sessions (SmExecPgm, SmStartCsr, SmStopCsr)
 *              refuse a client that is not LocalSystem in session 0.
 *              Run it as an administrator (not SYSTEM): \SmApiPort itself
 *              admits administrators. "startcsr" also calls SmStartCsr; only
 *              pass it on a build with the gate, since without it the call
 *              would really start a session.
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 */

#include <stdio.h>
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#define NTOS_MODE_USER
#include <ndk/lpcfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <sm/smmsg.h>

int
wmain(int argc, wchar_t *argv[])
{
    NTSTATUS Status;
    HANDLE Port = NULL;
    RTL_USER_PROCESS_INFORMATION Info;
    UNICODE_STRING Name;
    ULONG MuSessionId = 0;
    HANDLE CsrPid = NULL, InitialPid = NULL;
    int Failures = 0;

    Status = SmConnectToSm(NULL, NULL, 0, &Port);
    printf("SMGATE connect 0x%08lx\n", Status);
    if (!NT_SUCCESS(Status))
    {
        printf("SMGATE no connection (not an administrator?)\n");
        return 2;
    }

    /* No real process: the gate must answer before the handles are used */
    RtlZeroMemory(&Info, sizeof(Info));
    Info.Size = sizeof(Info);
    Info.ImageInformation.SubSystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    Status = SmExecPgm(Port, &Info, FALSE);
    printf("SMGATE execpgm 0x%08lx\n", Status);
    if (Status != STATUS_ACCESS_DENIED) Failures++;

    Status = SmStopCsr(Port, 7);
    printf("SMGATE stopcsr 0x%08lx\n", Status);
    if (Status != STATUS_ACCESS_DENIED) Failures++;

    if (argc > 1 && !_wcsicmp(argv[1], L"startcsr"))
    {
        Status = SmStartCsr(Port, &MuSessionId, NULL, &CsrPid, &InitialPid);
        printf("SMGATE startcsr 0x%08lx\n", Status);
        if (Status != STATUS_ACCESS_DENIED) Failures++;
    }

    /* Not gated: the reply is the API's own */
    RtlInitUnicodeString(&Name, L"NoSuchSubsystem");
    Status = SmLoadDeferedSubsystem(Port, &Name);
    printf("SMGATE loaddefered 0x%08lx\n", Status);

    NtClose(Port);
    printf("SMGATE failures=%d\n", Failures);
    return Failures;
}
