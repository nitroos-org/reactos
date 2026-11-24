/*
 * PROJECT:     NitroOS Windows Installer
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The request that msi.dll sends to the Installer service (msiexec /V, LocalSystem)
 *              to start a program of a deferred custom action marked "no impersonation"
 *
 * On Windows the Installer service runs such an action as LocalSystem. msi.dll runs inside the
 * process of the user who started msiexec, so for an elevated administrator it asks the service to
 * start the program (the custom action server, or the program of an EXE action): the service
 * checks the caller and answers with a handle to the new process, valid in the caller.
 * Private to msi.dll and msiexec.exe.
 */

#pragma once

/* documented (kernel32 since Vista, advapi32), not declared by our SDK headers */
BOOL WINAPI GetNamedPipeServerProcessId(HANDLE Pipe, PULONG ServerProcessId);
BOOL WINAPI IsTokenRestricted(HANDLE TokenHandle);

#define MSI_LAUNCH_PIPE_NAME    L"\\\\.\\pipe\\NitroMsiLaunch"
#define MSI_LAUNCH_MAGIC        0x4C41494D  /* "MIAL" */
#define MSI_LAUNCH_MAX_STRING   32768       /* characters of each string */

#define MSI_LAUNCH_CA_SERVER    1           /* msiexec.exe -Embedding <ClientPid>; Arch 32 or 64 */
#define MSI_LAUNCH_PROGRAM      2           /* CreateProcessW(Application, CommandLine, Directory) */

typedef struct _MSI_LAUNCH_REQUEST
{
    DWORD Magic;
    DWORD Kind;
    DWORD ClientPid;        /* the caller's own process id: checked against the pipe's client */
    DWORD Arch;             /* MSI_LAUNCH_CA_SERVER: 32 or 64 */
    DWORD ApplicationChars; /* the strings follow, each with its terminating NUL counted */
    DWORD CommandLineChars;
    DWORD DirectoryChars;
    /* WCHAR Application[ApplicationChars]; WCHAR CommandLine[CommandLineChars]; WCHAR Directory[DirectoryChars]; */
} MSI_LAUNCH_REQUEST, *PMSI_LAUNCH_REQUEST;

typedef struct _MSI_LAUNCH_REPLY
{
    DWORD Magic;
    DWORD Error;            /* 0 or a Win32 error code */
    DWORD ProcessId;
    DWORD Reserved;
    ULONG64 ProcessHandle;  /* the new process, as a handle in the caller (all access) */
} MSI_LAUNCH_REPLY, *PMSI_LAUNCH_REPLY;
