/*
 * PROJECT:     ReactOS NT-Compatible Session Manager
 * LICENSE:     BSD 2-Clause License (https://spdx.org/licenses/BSD-2-Clause)
 * PURPOSE:     SMSS Client (SB and SM) Message Format
 * COPYRIGHT:   Copyright 2012-2013 Alex Ionescu <alex.ionescu@reactos.org>
 *              Copyright 2021 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2022 Hermès Bélusca-Maïto <hermes.belusca-maito@reactos.org>
 */

#ifndef _SM_MSG_
#define _SM_MSG_

#pragma once

//
// There are the APIs that a Client (such as CSRSS) can send to the SMSS Server.
// These are called "SM" APIs.
//
// The exact names are not known, but we are basing them on the SmpApiName array
// in the checked build of SMSS, which is probably a close approximation. We add
// "p" to use the similar nomenclature seen/leaked out in the Base CSRSS APIs.
//
// The enumeration finishes with an enumeratee holding the maximum API number.
// Its name is based on BasepMaxApiNumber, UserpMaxApiNumber...
//
typedef enum _SMSRV_API_NUMBER
{
    SmpCreateForeignSessionApi,
    SmpSessionCompleteApi,
    SmpTerminateForeignSessionApi,
    SmpExecPgmApi,
    SmpLoadDeferedSubsystemApi,
    SmpStartCsrApi,
    SmpStopCsrApi,
    SmpForwardProcessRegistrationApi, /* NitroOS: cross-session CSR registration */

    SmpMaxApiNumber
} SMSRV_API_NUMBER;

//
// These are the structures making up the SM_API_MSG packet structure defined
// below. Each one corresponds to an equivalent API from the list above.
//
typedef struct _SM_CREATE_FOREIGN_SESSION_MSG
{
    ULONG NotImplemented;
} SM_CREATE_FOREIGN_SESSION_MSG, *PSM_CREATE_FOREIGN_SESSION_MSG;

typedef struct _SM_SESSION_COMPLETE_MSG
{
    ULONG SessionId;
    NTSTATUS SessionStatus;
} SM_SESSION_COMPLETE_MSG, *PSM_SESSION_COMPLETE_MSG;

typedef struct _SM_TERMINATE_FOREIGN_SESSION_MSG
{
    ULONG NotImplemented;
} SM_TERMINATE_FOREIGN_SESSION_MSG, *PSM_TERMINATE_FOREIGN_SESSION_MSG;

typedef struct _SM_EXEC_PGM_MSG
{
    RTL_USER_PROCESS_INFORMATION ProcessInformation;
    BOOLEAN DebugFlag;
} SM_EXEC_PGM_MSG, *PSM_EXEC_PGM_MSG;
#ifndef _WIN64
C_ASSERT(sizeof(SM_EXEC_PGM_MSG) == 0x48);
#else
C_ASSERT(sizeof(SM_EXEC_PGM_MSG) == 0x70);
#endif

typedef struct _SM_LOAD_DEFERED_SUBSYSTEM_MSG
{
    ULONG Length;
    WCHAR Buffer[32];
} SM_LOAD_DEFERED_SUBSYSTEM_MSG, *PSM_LOAD_DEFERED_SUBSYSTEM_MSG;

typedef struct _SM_START_CSR_MSG
{
    ULONG MuSessionId;
    ULONG Length;
    WCHAR Buffer[128];
    HANDLE WindowsSubSysProcessId;
    HANDLE SmpInitialCommandProcessId;
} SM_START_CSR_MSG, *PSM_START_CSR_MSG;
#ifndef _WIN64
C_ASSERT(sizeof(SM_START_CSR_MSG) == 0x110);
#else
C_ASSERT(sizeof(SM_START_CSR_MSG) == 0x118);
#endif

typedef struct _SM_STOP_CSR_MSG
{
    ULONG MuSessionId;
} SM_STOP_CSR_MSG, *PSM_STOP_CSR_MSG;

/*
 * NitroOS (sessions design 3.5, option A): the csrss of the creating session
 * asks SMSS to register a process it did not create records for, because the
 * process is in another session, with the csrss of that session. SMSS accepts
 * it only from a csrss it started itself and forwards it over the target
 * csrss's Sb port (SbpCreateRemoteProcess). No handles are passed: the target
 * csrss opens the process and thread by id and checks them itself.
 */
#define SM_REMOTE_PROCESS_NEW_GROUP     0x1 /* CREATE_NEW_PROCESS_GROUP */
#define SM_REMOTE_PROCESS_CONSOLE_APP   0x2 /* a console (CUI) application */
#define SM_REMOTE_PROCESS_VALID_FLAGS   (SM_REMOTE_PROCESS_NEW_GROUP | SM_REMOTE_PROCESS_CONSOLE_APP)

typedef struct _SM_FORWARD_PROCESS_REGISTRATION_MSG
{
    CLIENT_ID ClientId;     /* the new process and its first thread */
    ULONG MuSessionId;      /* the session the process is in */
    ULONG Flags;            /* SM_REMOTE_PROCESS_* */
} SM_FORWARD_PROCESS_REGISTRATION_MSG, *PSM_FORWARD_PROCESS_REGISTRATION_MSG;

#if defined(__REACTOS__) && DBG
#include "smrosdbg.h"
#endif

//
// This is the actual packet structure sent over LPC to the \SmApiPort
//
typedef struct _SM_API_MSG
{
    PORT_MESSAGE h;
    SMSRV_API_NUMBER ApiNumber;
    NTSTATUS ReturnValue;
    union
    {
        SM_CREATE_FOREIGN_SESSION_MSG CreateForeignSession;
        SM_SESSION_COMPLETE_MSG SessionComplete;
        SM_TERMINATE_FOREIGN_SESSION_MSG TerminateForeignComplete;
        SM_EXEC_PGM_MSG ExecPgm;
        SM_LOAD_DEFERED_SUBSYSTEM_MSG LoadDefered;
        SM_START_CSR_MSG StartCsr;
        SM_STOP_CSR_MSG StopCsr;
        SM_FORWARD_PROCESS_REGISTRATION_MSG ForwardRegistration;

#if defined(__REACTOS__) && DBG
        SM_QUERYINFO_MSG QueryInfo;
#endif
    } u;
} SM_API_MSG, *PSM_API_MSG;

//
// This is the size that Server 2003 SP1 SMSS expects, so make sure we conform.
//
#ifndef _WIN64
C_ASSERT(sizeof(SM_API_MSG) == 0x130);
#else
C_ASSERT(sizeof(SM_API_MSG) == 0x148);
#endif

//
// There are the APIs that the SMSS Server can send to a client (such as CSRSS).
// These are called "SB" APIs.
//
// The exact names are unknown but we are basing them on the CsrServerSbApiName
// array in the checked build of CSRSRV which is probably a close approximation.
// We add "p" to use the similar nomenclature seen/leaked out in the Base CSRSS
// APIs.
//
// The enumeration finishes with an enumeratee holding the maximum API number.
// Its name is based on BasepMaxApiNumber, UserpMaxApiNumber...
//
typedef enum _SB_API_NUMBER
{
    SbpCreateSession,
    SbpTerminateSession,
    SbpForeignSessionComplete,
    SbpCreateProcess,
    SbpCreateRemoteProcess, /* NitroOS: SMSS forwards SmpForwardProcessRegistrationApi */

    SbpMaxApiNumber
} SB_API_NUMBER;

//
// These are the structures making up the SB_API_MSG packet structure defined
// below. Each one corresponds to an equivalent API from the list above.
//
typedef struct _SB_CREATE_SESSION_MSG
{
    ULONG SessionId;
    RTL_USER_PROCESS_INFORMATION ProcessInfo;
    PVOID Reserved;
    ULONG DbgSessionId;
    CLIENT_ID DbgUiClientId;
} SB_CREATE_SESSION_MSG, *PSB_CREATE_SESSION_MSG;
#ifndef _WIN64
C_ASSERT(sizeof(SB_CREATE_SESSION_MSG) == 0x58);
#else
C_ASSERT(sizeof(SB_CREATE_SESSION_MSG) == 0x90);
#endif

typedef struct _SB_TERMINATE_SESSION_MSG
{
    ULONG SessionId;
} SB_TERMINATE_SESSION_MSG, *PSB_TERMINATE_SESSION_MSG;

typedef struct _SB_FOREIGN_SESSION_COMPLETE_MSG
{
    ULONG SessionId;
} SB_FOREIGN_SESSION_COMPLETE_MSG, *PSB_FOREIGN_SESSION_COMPLETE_MSG;

#define SB_PROCESS_FLAGS_DEBUG          0x1
#define SB_PROCESS_FLAGS_WAIT_ON_THREAD 0x2
#define SB_PROCESS_FLAGS_RESERVE_1MB    0x8
#define SB_PROCESS_FLAGS_SKIP_CHECKS    0x20
typedef struct _SB_CREATE_PROCESS_MSG
{
    union
    {
        struct
        {
            PUNICODE_STRING ImageName;
            PUNICODE_STRING CurrentDirectory;
            PUNICODE_STRING CommandLine;
            PUNICODE_STRING DllPath;
            ULONG Flags;
            ULONG DebugFlags;
        } In;
        struct
        {
            HANDLE ProcessHandle;
            HANDLE ThreadHandle;
            ULONG SubsystemType;
            CLIENT_ID ClientId;
        } Out;
    };
} SB_CREATE_PROCESS_MSG, *PSB_CREATE_PROCESS_MSG;
#ifndef _WIN64
C_ASSERT(sizeof(SB_CREATE_PROCESS_MSG) == 0x18);
#else
C_ASSERT(sizeof(SB_CREATE_PROCESS_MSG) == 0x28);
#endif

typedef struct _SB_CREATE_REMOTE_PROCESS_MSG
{
    ULONG SessionId;        /* the SMSS session id for the CSR NT session */
    ULONG MuSessionId;      /* must be the session of the receiving csrss */
    CLIENT_ID ClientId;     /* the process and its first thread, opened by id */
    ULONG Flags;            /* SM_REMOTE_PROCESS_* */
} SB_CREATE_REMOTE_PROCESS_MSG, *PSB_CREATE_REMOTE_PROCESS_MSG;

#ifdef CreateProcess
#undef CreateProcess
#endif

//
// When the server connects to a client, this structure is exchanged
//
typedef struct _SB_CONNECTION_INFO
{
    ULONG SubsystemType;
    WCHAR SbApiPortName[120];
} SB_CONNECTION_INFO, *PSB_CONNECTION_INFO;

//
// This is the actual packet structure sent over LPC to the \SbApiPort
//
typedef struct _SB_API_MSG
{
    PORT_MESSAGE h;
    union
    {
        SB_CONNECTION_INFO ConnectionInfo;
        struct
        {
            SB_API_NUMBER ApiNumber;
            NTSTATUS ReturnValue;
            union
            {
                SB_CREATE_SESSION_MSG CreateSession;
                SB_TERMINATE_SESSION_MSG TerminateSession;
                SB_FOREIGN_SESSION_COMPLETE_MSG ForeignSessionComplete;
                SB_CREATE_PROCESS_MSG CreateProcess;
                SB_CREATE_REMOTE_PROCESS_MSG CreateRemoteProcess;
            } u;
        };
    };
} SB_API_MSG, *PSB_API_MSG;

//
// This is the size that Server 2003 SP1 SMSS expects, so make sure we conform.
//
#ifndef _WIN64
C_ASSERT(sizeof(SB_API_MSG) == 0x110);
#else
C_ASSERT(sizeof(SB_API_MSG) == 0x120);
#endif

//
// SB Message Handler
//
typedef
BOOLEAN
(NTAPI *PSB_API_ROUTINE)(
    _In_ PSB_API_MSG SbApiMsg
);

//
// The actual server functions that a client linking with SMLIB can call.
//
/* NTDLL!RtlConnectToSm */
NTSTATUS
NTAPI
SmConnectToSm(
    _In_opt_ PUNICODE_STRING SbApiPortName,
    _In_opt_ HANDLE SbApiPort,
    _In_opt_ ULONG ImageType,
    _Out_ PHANDLE SmApiPort);

/* NTDLL!RtlSendMsgToSm */
NTSTATUS
NTAPI
SmSendMsgToSm(
    _In_ HANDLE SmApiPort,
    _Inout_ PSM_API_MSG SmApiMsg);

NTSTATUS
NTAPI
SmSessionComplete(
    _In_ HANDLE SmApiPort,
    _In_ ULONG SessionId,
    _In_ NTSTATUS SessionStatus);

NTSTATUS
NTAPI
SmExecPgm(
    _In_ HANDLE SmApiPort,
    _In_ PRTL_USER_PROCESS_INFORMATION ProcessInformation,
    _In_ BOOLEAN DebugFlag);

NTSTATUS
NTAPI
SmLoadDeferedSubsystem(
    _In_ HANDLE SmApiPort,
    _In_ PUNICODE_STRING DeferedSubsystem);

NTSTATUS
NTAPI
SmStartCsr(
    _In_ HANDLE SmApiPort,
    _Out_ PULONG pMuSessionId,
    _In_opt_ PUNICODE_STRING CommandLine,
    _Out_ PHANDLE pWindowsSubSysProcessId,
    _Out_ PHANDLE pInitialCommandProcessId);

NTSTATUS
NTAPI
SmStopCsr(
    _In_ HANDLE SmApiPort,
    _In_ ULONG MuSessionId);

NTSTATUS
NTAPI
SmForwardProcessRegistration(
    _In_ HANDLE SmApiPort,
    _In_ PCLIENT_ID ClientId,
    _In_ ULONG MuSessionId,
    _In_ ULONG Flags);

#endif // _SM_MSG_
