/* ReactOS WoW64 CSR translation. SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64p.h"
#include <winuser.h>
#include <wincon.h>
#include <wingdi.h>
#include <wincon_undoc.h>
#include <csr/csr.h>
#include <win/base.h>
#include <win/basemsg.h>
#include <win/conmsg.h>
#include <win/winmsg.h>
#include "csr32.h"

/* API names for the diagnostics, in the order of the server API enumerations */
static const char *BaseApiNames[] =
{
    "BasepCreateProcess", "BasepCreateThread", "BasepGetTempFile", "BasepExitProcess", "BasepDebugProcess",
    "BasepCheckVDM", "BasepUpdateVDMEntry", "BasepGetNextVDMCommand", "BasepExitVDM", "BasepIsFirstVDM",
    "BasepGetVDMExitCode", "BasepSetReenterCount", "BasepSetProcessShutdownParam",
    "BasepGetProcessShutdownParam", "BasepNlsSetUserInfo", "BasepNlsSetMultipleUserInfo",
    "BasepNlsCreateSection", "BasepSetVDMCurDirs", "BasepGetVDMCurDirs", "BasepBatNotification",
    "BasepRegisterWowExec", "BasepSoundSentryNotification", "BasepRefreshIniFileMapping",
    "BasepDefineDosDevice", "BasepSetTermsrvAppInstallMode", "BasepNlsUpdateCacheCount",
    "BasepSetTermsrvClientTimeZone", "BasepSxsCreateActivationContext", "BasepDebugProcessStop",
    "BasepRegisterThread", "BasepNlsGetUserInfo",
};
static const char *ConsoleApiNames[] =
{
    "ConsolepOpenConsole", "ConsolepGetConsoleInput", "ConsolepWriteConsoleInput",
    "ConsolepReadConsoleOutput", "ConsolepWriteConsoleOutput", "ConsolepReadConsoleOutputString",
    "ConsolepWriteConsoleOutputString", "ConsolepFillConsoleOutput", "ConsolepGetMode",
    "ConsolepGetNumberOfFonts", "ConsolepGetNumberOfInputEvents", "ConsolepGetScreenBufferInfo",
    "ConsolepGetCursorInfo", "ConsolepGetMouseInfo", "ConsolepGetFontInfo", "ConsolepGetFontSize",
    "ConsolepGetCurrentFont", "ConsolepSetMode", "ConsolepSetActiveScreenBuffer", "ConsolepFlushInputBuffer",
    "ConsolepGetLargestWindowSize", "ConsolepSetScreenBufferSize", "ConsolepSetCursorPosition",
    "ConsolepSetCursorInfo", "ConsolepSetWindowInfo", "ConsolepScrollScreenBuffer",
    "ConsolepSetTextAttribute", "ConsolepSetFont", "ConsolepSetIcon", "ConsolepReadConsole",
    "ConsolepWriteConsole", "ConsolepDuplicateHandle", "ConsolepGetHandleInformation",
    "ConsolepSetHandleInformation", "ConsolepCloseHandle", "ConsolepVerifyIoHandle", "ConsolepAlloc",
    "ConsolepFree", "ConsolepGetTitle", "ConsolepSetTitle", "ConsolepCreateScreenBuffer",
    "ConsolepInvalidateBitMapRect", "ConsolepVDMOperation", "ConsolepSetCursor", "ConsolepShowCursor",
    "ConsolepMenuControl", "ConsolepSetPalette", "ConsolepSetDisplayMode", "ConsolepRegisterVDM",
    "ConsolepGetHardwareState", "ConsolepSetHardwareState", "ConsolepGetDisplayMode", "ConsolepAddAlias",
    "ConsolepGetAlias", "ConsolepGetAliasesLength", "ConsolepGetAliasExesLength", "ConsolepGetAliases",
    "ConsolepGetAliasExes", "ConsolepExpungeCommandHistory", "ConsolepSetNumberOfCommands",
    "ConsolepGetCommandHistoryLength", "ConsolepGetCommandHistory", "ConsolepSetCommandHistoryMode",
    "ConsolepGetCP", "ConsolepSetCP", "ConsolepSetKeyShortcuts", "ConsolepSetMenuClose",
    "ConsolepNotifyLastClose", "ConsolepGenerateCtrlEvent", "ConsolepGetKeyboardLayoutName",
    "ConsolepGetConsoleWindow", "ConsolepCharType", "ConsolepSetLocalEUDC", "ConsolepSetCursorMode",
    "ConsolepGetCursorMode", "ConsolepRegisterOS2", "ConsolepSetOS2OemFormat", "ConsolepGetNlsMode",
    "ConsolepSetNlsMode", "ConsolepRegisterConsoleIME", "ConsolepUnregisterConsoleIME", "ConsolepGetLangId",
    "ConsolepAttach", "ConsolepGetSelectionInfo", "ConsolepGetProcessList", "ConsolepGetHistory",
    "ConsolepSetHistory", "ConsolepGetScrollback", "ConsolepGetExtColors",
};
static const char *UserApiNames[] =
{
    "UserpExitWindowsEx", "UserpEndTask", "UserpLogon", "UserpRegisterServicesProcess",
    "UserpActivateDebugger", "UserpGetThreadConsoleDesktop", "UserpDeviceEvent", "UserpRegisterLogonProcess",
    "UserpCreateSystemThreads", "UserpRecordShutdownReason",
};
C_ASSERT(RTL_NUMBER_OF(BaseApiNames) == BasepMaxApiNumber - BASESRV_FIRST_API_NUMBER);
C_ASSERT(RTL_NUMBER_OF(ConsoleApiNames) == ConsolepMaxApiNumber - CONSRV_FIRST_API_NUMBER);
C_ASSERT(RTL_NUMBER_OF(UserApiNames) == UserpMaxApiNumber - USERSRV_FIRST_API_NUMBER);

static NTSTATUS UnsupportedApi(ULONG Api, ULONG Size, BOOLEAN *Reported)
{
    ULONG Server = CSR_API_NUMBER_TO_SERVER_ID(Api), Number = CSR_API_NUMBER_TO_API_ID(Api);
    const char *ServerName = "server", *Name = "unknown";
#define NAME(Index, Table, First) \
    if (Server == Index) { ServerName = #Index; \
        if (Number - First < RTL_NUMBER_OF(Table)) Name = Table[Number - First]; }
    NAME(BASESRV_SERVERDLL_INDEX, BaseApiNames, BASESRV_FIRST_API_NUMBER)
    NAME(CONSRV_SERVERDLL_INDEX, ConsoleApiNames, CONSRV_FIRST_API_NUMBER)
    NAME(USERSRV_SERVERDLL_INDEX, UserApiNames, USERSRV_FIRST_API_NUMBER)
#undef NAME
    if (Wow64FirstReport(WOW64_SERVICE_CSR, WOW64_UNSUPPORTED_CSR_API, Api))
        DbgPrint("WoW64: unsupported CSR API %lx (%s %s), size %lu, pid %lx\n", Api, ServerName, Name, Size,
                 HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess));
    *Reported = TRUE;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS CopyBaseData(VOID)
{
    PBASE_STATIC_SERVER_DATA From = NtCurrentPeb()->ReadOnlyStaticServerData[BASESRV_SERVERDLL_INDEX];
    WOW64_BASE_DATA *To;
    ULONG *Table;
    NTSTATUS Status;
    SIZE_T Size;
    PVOID ProtectBase;
    ULONG OldProtect;
    PEB32 *Peb = WOW64_PEB32(NtCurrentPeb());

    if (Peb->ReadOnlyStaticServerData) return STATUS_SUCCESS;
    Status = Wow64Allocate(sizeof(*To), (PVOID *)&To);
    if (!NT_SUCCESS(Status)) return Status;
    Status = Wow64Allocate(4 * sizeof(ULONG), (PVOID *)&Table);
    if (!NT_SUCCESS(Status)) return Status;
#define STR(Field) do { Status = Wow64CopyString(&To->Field, &From->Field); \
    if (!NT_SUCCESS(Status)) return Status; } while (0)
    STR(WindowsDirectory); STR(NamedObjectDirectory);
    STR(WindowsSys32x86Directory);
    /* This API returns the logical System32 path. Filesystem redirection
     * selects SysWOW64; disabling it must let installers start native helpers
     * using the very same path returned by GetSystemDirectory. */
    STR(WindowsSystemDirectory);
#undef STR
#define COPY(Field) To->Field = From->Field
    COPY(WindowsMajorVersion); COPY(WindowsMinorVersion); COPY(BuildNumber);
    COPY(CSDNumber); COPY(RCNumber); COPY(TimeOfDay); COPY(NlsUserInfo);
    COPY(DefaultSeparateVDM); COPY(IsWowTaskReady); COPY(fTermsrvAppInstallMode);
    COPY(tziTermsrvClientTimeZone); COPY(ktTermsrvClientBias); COPY(TermsrvClientTimeZoneId);
    COPY(LUIDDeviceMapsEnabled); COPY(TermsrvClientTimeZoneChangeNum);
    COPY(SysInfo.Reserved); COPY(SysInfo.TimerResolution); COPY(SysInfo.PageSize);
    COPY(SysInfo.NumberOfPhysicalPages); COPY(SysInfo.LowestPhysicalPageNumber);
    COPY(SysInfo.HighestPhysicalPageNumber); COPY(SysInfo.AllocationGranularity);
    COPY(SysInfo.NumberOfProcessors);
#undef COPY
    RtlCopyMemory(To->CSDVersion, From->CSDVersion, sizeof(To->CSDVersion));
    To->SysInfo.MinimumUserModeAddress = 0x10000;
    To->SysInfo.MaximumUserModeAddress = Wow64HighestUserAddress;
    To->SysInfo.ActiveProcessorsAffinityMask = (ULONG)From->SysInfo.ActiveProcessorsAffinityMask;
    Table[BASESRV_SERVERDLL_INDEX] = PtrToUlong(To);
    ProtectBase = To; Size = sizeof(*To);
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &ProtectBase, &Size, PAGE_READONLY, &OldProtect);
    if (!NT_SUCCESS(Status)) return Status;
    ProtectBase = Table; Size = 4 * sizeof(ULONG);
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &ProtectBase, &Size, PAGE_READONLY, &OldProtect);
    if (!NT_SUCCESS(Status)) return Status;
    Peb->ReadOnlyStaticServerData = PtrToUlong(Table);
    return STATUS_SUCCESS;
}

/* The control routine the guest's kernel32 registered with the console server
 * (CTRL_C, CTRL_BREAK, CTRL_CLOSE, logoff, shutdown) at connect, AllocConsole or
 * AttachConsole, whichever came last. The server starts it as a native thread,
 * so it is given ConsoleControl instead: a thread started there enters this
 * guest routine on a new guest stack (Wow64CsrThreadStart). No other guest
 * address can be entered this way, and the parameter is the server's ULONG. */
static LONG GuestCtrlRoutine;

/* Without a guest routine, end the process as the default handler does */
static DWORD WINAPI ConsoleControl(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    NtTerminateProcess(NtCurrentProcess(), STATUS_CONTROL_C_EXIT);
    return 0;
}

/* The property sheet routine receives a section whose CONSOLE_STATE_INFO layout
 * depends on the pointer size, and the server never starts the IME routine:
 * neither is started in the guest. Started as a thread (Wow64CsrThreadStart),
 * which has no caller to return to. */
static DWORD WINAPI UnsupportedConsoleCallback(PVOID Parameter)
{
    UNREFERENCED_PARAMETER(Parameter);
    NtCurrentTeb()->FreeStackOnTermination = TRUE;
    NtTerminateThread(NtCurrentThread(), STATUS_NOT_SUPPORTED);
    return ERROR_NOT_SUPPORTED;
}

/* The native routine registered with the server for a guest control routine. The previous
 * guest routine is returned in *Previous, for RestoreCtrlRoutine when the registering
 * request fails. A guest that registers none gets no control events, as natively (the
 * server records NULL); the routine stays set for events already queued for it. */
static LPTHREAD_START_ROUTINE RegisterCtrlRoutine(ULONG Routine, LONG *Previous)
{
    *Previous = (LONG)Routine;
    if (!Routine) return NULL;
    *Previous = InterlockedExchange(&GuestCtrlRoutine, (LONG)Routine);
    return ConsoleControl;
}

/* The request that registered Routine failed: the server kept its earlier registration,
 * so the guest routine is the earlier one again, unless a newer registration replaced it. */
static VOID RestoreCtrlRoutine(ULONG Routine, LONG Previous)
{
    if (Routine) InterlockedCompareExchange(&GuestCtrlRoutine, Previous, (LONG)Routine);
}

/* The console server delivers control events with CreateRemoteThread, whose initial context
 * enters the server's own kernel32 BaseThreadStartup with the routine in RCX and the parameter
 * in RDX. Native kernel32 is not loaded in a WoW64 process, so that thunk is not mapped. A
 * thread starting ConsoleControl once the guest has registered its control routine returns
 * TRUE with that routine and the event: the caller runs it as a guest thread. Otherwise a
 * thread starting one of the routines registered above enters it directly instead, with the
 * stack pointer aligned as after a call and room for the home space; neither returns. Other
 * native threads are left alone. */
BOOLEAN Wow64CsrThreadStart(PCONTEXT Context, ULONG *Routine, ULONG *Parameter)
{
    if (Context->Rcx == (ULONG_PTR)ConsoleControl)
    {
        *Routine = (ULONG)InterlockedCompareExchange(&GuestCtrlRoutine, 0, 0);
        *Parameter = (ULONG)Context->Rdx;
        if (*Routine) return TRUE;
    }
    else if (Context->Rcx != (ULONG_PTR)UnsupportedConsoleCallback) return FALSE;
    Context->Rip = Context->Rcx;
    Context->Rcx = Context->Rdx;
    Context->Rsp = ((Context->Rsp & ~(ULONG_PTR)15) - 0x30) - sizeof(ULONG_PTR);
    return FALSE;
}

/* Guest CONSOLE_START_INFO to native, shared by the console connect and ConsolepAttach. The
 * handles are widened; the property tail contains only fixed-width fields. InitEvents are
 * outputs and stay zero. */
static VOID ConsoleStartToNative(CONSOLE_START_INFO *To, const WOW64_CONSOLE_START *From)
{
#define H(Field) To->Field = HANDLE32(From->Field)
    H(ConsoleHandle); H(InputWaitHandle); H(InputHandle); H(OutputHandle); H(ErrorHandle);
    H(hIcon); H(hIconSm);
#undef H
    To->IconIndex = From->IconIndex;
    RtlCopyMemory((PUCHAR)To + FIELD_OFFSET(CONSOLE_START_INFO, dwHotKey),
                  (PUCHAR)From + FIELD_OFFSET(WOW64_CONSOLE_START, dwHotKey),
                  sizeof(WOW64_CONSOLE_START) - FIELD_OFFSET(WOW64_CONSOLE_START, dwHotKey));
}

/* The handles the server returns, back into the guest structure */
static VOID ConsoleStartToGuest(WOW64_CONSOLE_START *To, const CONSOLE_START_INFO *From)
{
    ULONG i;
#define H(Field) To->Field = HandleToUlong(From->Field)
    H(ConsoleHandle); H(InputWaitHandle); H(InputHandle); H(OutputHandle); H(ErrorHandle);
#undef H
    for (i = 0; i < MAX_INIT_EVENTS; ++i)
        To->InitEvents[i] = HandleToUlong(From->InitEvents[i]);
}

static NTSTATUS Connect(ULONG *a, BOOLEAN *Reported)
{
    ULONG *Length = PTR32(a[3]);
    NTSTATUS Status;
    BOOLEAN InServer = FALSE;
    if (!Length || !a[2]) return STATUS_INVALID_PARAMETER;
    if (a[1] == BASESRV_SERVERDLL_INDEX)
    {
        /* The connection code sizes its capture and its copy back by this length:
         * hand it a native copy of the checked value, then return its result */
        ULONG NativeLength = *Length;
        if (NativeLength != sizeof(BASESRV_API_CONNECTINFO)) return STATUS_INFO_LENGTH_MISMATCH;
        Status = CsrClientConnectToServer(PTR32(a[0]), a[1], PTR32(a[2]), &NativeLength, &InServer);
        *Length = NativeLength;
        if (NT_SUCCESS(Status)) Status = CopyBaseData();
    }
    else if (a[1] == CONSRV_SERVERDLL_INDEX)
    {
        WOW64_CONSOLE_CONNECT *From = PTR32(a[2]);
        CONSRV_API_CONNECTINFO To = {0};
        LONG PrevCtrl;
        ULONG GuestCtrl;
        ULONG NativeLength = sizeof(To);
        if (*Length != sizeof(*From)) return STATUS_INFO_LENGTH_MISMATCH;
        ConsoleStartToNative(&To.ConsoleStartInfo, &From->ConsoleStartInfo);
        To.IsConsoleApp = From->IsConsoleApp;
        To.IsWindowVisible = From->IsWindowVisible;
        GuestCtrl = *(volatile ULONG *)&From->CtrlRoutine;
        To.CtrlRoutine = RegisterCtrlRoutine(GuestCtrl, &PrevCtrl);
        To.PropRoutine = To.ImeRoutine = UnsupportedConsoleCallback;
        To.TitleLength = From->TitleLength;
        To.DesktopLength = From->DesktopLength;
        To.Desktop = PTR32(From->Desktop);
        To.AppNameLength = From->AppNameLength;
        To.CurDirLength = From->CurDirLength;
        RtlCopyMemory(To.ConsoleTitle, From->ConsoleTitle, sizeof(To.ConsoleTitle));
        RtlCopyMemory(To.AppName, From->AppName, sizeof(To.AppName));
        RtlCopyMemory(To.CurDir, From->CurDir, sizeof(To.CurDir));
        Status = CsrClientConnectToServer(PTR32(a[0]), a[1], &To, &NativeLength, &InServer);
        if (NT_SUCCESS(Status))
        {
            ConsoleStartToGuest(&From->ConsoleStartInfo, &To.ConsoleStartInfo);
        }
        else RestoreCtrlRoutine(GuestCtrl, PrevCtrl);
    }
    else return Wow64Unsupported(WOW64_SERVICE_CSR, WOW64_UNSUPPORTED_CSR_SERVER, a[1], Reported);
    if (a[4]) *(BOOLEAN *)PTR32(a[4]) = InServer;
    return Status;
}

/* Guest capture-buffer data: a range in the guest's address space. Every page is touched (and
 * written back for output) before a native capture buffer is allocated, so that a bad pointer
 * faults into the caller's handler before this layer holds resources. */
static NTSTATUS GuestBuffer(ULONG Address, ULONG64 Size, BOOLEAN Write, PVOID *Buffer)
{
    volatile UCHAR *Bytes;
    ULONG64 Offset;

    *Buffer = NULL;
    if (!Size) return STATUS_SUCCESS;
    if (!Address || (ULONG64)Address + Size > (ULONG64)Wow64HighestUserAddress + 1) return STATUS_INVALID_PARAMETER;
    Bytes = PTR32(Address);
    for (Offset = 0; Offset < Size; Offset = (Offset | (PAGE_SIZE - 1)) + 1)
    {
        if (Write) Bytes[Offset] = Bytes[Offset]; else (VOID)Bytes[Offset];
    }
    if (Write) Bytes[Size - 1] = Bytes[Size - 1]; else (VOID)Bytes[Size - 1];
    *Buffer = (PVOID)Bytes;
    return STATUS_SUCCESS;
}

/* The member tables below describe console requests that need no other conversion than:
 * handles widened (sign-extended, as HANDLE32) on the way in and narrowed on the way out; values
 * copied in and back; and buffers in the guest capture buffer, sized by a guest length member
 * times a unit, captured natively and (for MEMBER_INOUT) copied back. The whole reply is copied
 * back whatever the status, because the guest library reads some members after a failure. Sizes
 * used for copying back are the ones validated before the call, never the reply's. */
enum { MEMBER_HANDLE, MEMBER_VALUE, MEMBER_IN, MEMBER_INOUT };
typedef struct
{
    UCHAR Kind;
    UCHAR Size;          /* MEMBER_VALUE: bytes; buffers: bytes of the length member (2 or 4) */
    UCHAR Unit;          /* buffers: bytes per unit of the length member */
    USHORT Guest, Native;/* offsets of the member */
    USHORT Length;       /* buffers: offset of the length member in the guest request */
    USHORT NativeLength; /* buffers: offset of the length member in the native request */
} WOW64_CSR_MEMBER;

typedef struct
{
    ULONG Api;
    USHORT GuestSize, NativeSize;
    ULONG Count;
    const WOW64_CSR_MEMBER *Members;
} WOW64_CSR_REQUEST;

/* Fails to compile unless the guest and native member have the same size */
#define SAME_SIZE(T, F) (RTL_FIELD_SIZE(T, F) + \
    0 * sizeof(char[RTL_FIELD_SIZE(T, F) == RTL_FIELD_SIZE(WOW64_##T, F) ? 1 : -1]))
#define H(T, F) { MEMBER_HANDLE, 0, 0, FIELD_OFFSET(WOW64_##T, F), FIELD_OFFSET(T, F), 0, 0 }
#define V(T, F) { MEMBER_VALUE, SAME_SIZE(T, F), 0, FIELD_OFFSET(WOW64_##T, F), FIELD_OFFSET(T, F), 0, 0 }
#define B(Kind, T, F, L, U) { MEMBER_##Kind, SAME_SIZE(T, L), U, FIELD_OFFSET(WOW64_##T, F), \
                              FIELD_OFFSET(T, F), FIELD_OFFSET(WOW64_##T, L), FIELD_OFFSET(T, L) }
#define MEMBERS(Name) static const WOW64_CSR_MEMBER Name##Members[]

MEMBERS(GetNumFonts) = { H(CONSOLE_GETNUMFONTS, ConsoleHandle), V(CONSOLE_GETNUMFONTS, NumFonts) };
MEMBERS(GetNumInputEvents) = { H(CONSOLE_GETNUMINPUTEVENTS, ConsoleHandle), H(CONSOLE_GETNUMINPUTEVENTS, InputHandle),
    V(CONSOLE_GETNUMINPUTEVENTS, NumberOfEvents) };
MEMBERS(CursorInfo) = { H(CONSOLE_GETSETCURSORINFO, ConsoleHandle), H(CONSOLE_GETSETCURSORINFO, OutputHandle),
    V(CONSOLE_GETSETCURSORINFO, Info) };
MEMBERS(GetMouseInfo) = { H(CONSOLE_GETMOUSEINFO, ConsoleHandle), V(CONSOLE_GETMOUSEINFO, NumButtons) };
MEMBERS(GetFontInfo) = { H(CONSOLE_GETFONTINFO, ConsoleHandle), H(CONSOLE_GETFONTINFO, OutputHandle),
    V(CONSOLE_GETFONTINFO, MaximumWindow), V(CONSOLE_GETFONTINFO, NumFonts),
    B(INOUT, CONSOLE_GETFONTINFO, FontInfo, NumFonts, sizeof(CONSOLE_FONT_INFO)) };
MEMBERS(GetFontSize) = { H(CONSOLE_GETFONTSIZE, ConsoleHandle), H(CONSOLE_GETFONTSIZE, OutputHandle),
    V(CONSOLE_GETFONTSIZE, FontIndex), V(CONSOLE_GETFONTSIZE, FontSize) };
MEMBERS(GetCurrentFont) = { H(CONSOLE_GETCURRENTFONT, ConsoleHandle), H(CONSOLE_GETCURRENTFONT, OutputHandle),
    V(CONSOLE_GETCURRENTFONT, MaximumWindow), V(CONSOLE_GETCURRENTFONT, FontIndex), V(CONSOLE_GETCURRENTFONT, FontSize) };
MEMBERS(SetActiveScreenBuffer) = { H(CONSOLE_SETACTIVESCREENBUFFER, ConsoleHandle),
    H(CONSOLE_SETACTIVESCREENBUFFER, OutputHandle) };
MEMBERS(FlushInputBuffer) = { H(CONSOLE_FLUSHINPUTBUFFER, ConsoleHandle), H(CONSOLE_FLUSHINPUTBUFFER, InputHandle) };
MEMBERS(GetLargestWindowSize) = { H(CONSOLE_GETLARGESTWINDOWSIZE, ConsoleHandle),
    H(CONSOLE_GETLARGESTWINDOWSIZE, OutputHandle), V(CONSOLE_GETLARGESTWINDOWSIZE, Size) };
MEMBERS(SetScreenBufferSize) = { H(CONSOLE_SETSCREENBUFFERSIZE, ConsoleHandle),
    H(CONSOLE_SETSCREENBUFFERSIZE, OutputHandle), V(CONSOLE_SETSCREENBUFFERSIZE, Size) };
MEMBERS(SetCursorPosition) = { H(CONSOLE_SETCURSORPOSITION, ConsoleHandle), H(CONSOLE_SETCURSORPOSITION, OutputHandle),
    V(CONSOLE_SETCURSORPOSITION, Position) };
MEMBERS(SetWindowInfo) = { H(CONSOLE_SETWINDOWINFO, ConsoleHandle), H(CONSOLE_SETWINDOWINFO, OutputHandle),
    V(CONSOLE_SETWINDOWINFO, Absolute), V(CONSOLE_SETWINDOWINFO, WindowRect) };
MEMBERS(ScrollScreenBuffer) = { H(CONSOLE_SCROLLSCREENBUFFER, ConsoleHandle), H(CONSOLE_SCROLLSCREENBUFFER, OutputHandle),
    V(CONSOLE_SCROLLSCREENBUFFER, ScrollRectangle), V(CONSOLE_SCROLLSCREENBUFFER, ClipRectangle),
    V(CONSOLE_SCROLLSCREENBUFFER, UseClipRectangle), V(CONSOLE_SCROLLSCREENBUFFER, DestinationOrigin),
    V(CONSOLE_SCROLLSCREENBUFFER, Fill), V(CONSOLE_SCROLLSCREENBUFFER, Unicode) };
MEMBERS(SetTextAttribute) = { H(CONSOLE_SETTEXTATTRIB, ConsoleHandle), H(CONSOLE_SETTEXTATTRIB, OutputHandle),
    V(CONSOLE_SETTEXTATTRIB, Attributes) };
MEMBERS(SetFont) = { H(CONSOLE_SETFONT, ConsoleHandle), H(CONSOLE_SETFONT, OutputHandle), V(CONSOLE_SETFONT, FontIndex) };
MEMBERS(ShowCursor) = { H(CONSOLE_SHOWCURSOR, ConsoleHandle), H(CONSOLE_SHOWCURSOR, OutputHandle),
    V(CONSOLE_SHOWCURSOR, Show), V(CONSOLE_SHOWCURSOR, RefCount) };
MEMBERS(DuplicateHandle) = { H(CONSOLE_DUPLICATEHANDLE, ConsoleHandle), H(CONSOLE_DUPLICATEHANDLE, SourceHandle),
    V(CONSOLE_DUPLICATEHANDLE, DesiredAccess), V(CONSOLE_DUPLICATEHANDLE, InheritHandle),
    V(CONSOLE_DUPLICATEHANDLE, Options), H(CONSOLE_DUPLICATEHANDLE, TargetHandle) };
MEMBERS(GetHandleInfo) = { H(CONSOLE_GETHANDLEINFO, ConsoleHandle), H(CONSOLE_GETHANDLEINFO, Handle),
    V(CONSOLE_GETHANDLEINFO, Flags) };
MEMBERS(SetHandleInfo) = { H(CONSOLE_SETHANDLEINFO, ConsoleHandle), H(CONSOLE_SETHANDLEINFO, Handle),
    V(CONSOLE_SETHANDLEINFO, Mask), V(CONSOLE_SETHANDLEINFO, Flags) };
MEMBERS(CloseHandle) = { H(CONSOLE_CLOSEHANDLE, ConsoleHandle), H(CONSOLE_CLOSEHANDLE, Handle) };
MEMBERS(GetDisplayMode) = { H(CONSOLE_GETDISPLAYMODE, ConsoleHandle), V(CONSOLE_GETDISPLAYMODE, DisplayMode) };
MEMBERS(SetDisplayMode) = { H(CONSOLE_SETDISPLAYMODE, ConsoleHandle), H(CONSOLE_SETDISPLAYMODE, OutputHandle),
    V(CONSOLE_SETDISPLAYMODE, DisplayMode), V(CONSOLE_SETDISPLAYMODE, NewSBDim), H(CONSOLE_SETDISPLAYMODE, EventHandle) };
MEMBERS(SetMenuClose) = { H(CONSOLE_SETMENUCLOSE, ConsoleHandle), V(CONSOLE_SETMENUCLOSE, Enable) };
MEMBERS(NotifyLastClose) = { H(CONSOLE_NOTIFYLASTCLOSE, ConsoleHandle) };
MEMBERS(GenerateCtrlEvent) = { H(CONSOLE_GENERATECTRLEVENT, ConsoleHandle), V(CONSOLE_GENERATECTRLEVENT, CtrlEvent),
    V(CONSOLE_GENERATECTRLEVENT, ProcessGroupId) };
MEMBERS(GetKbdLayoutName) = { H(CONSOLE_GETKBDLAYOUTNAME, ConsoleHandle), V(CONSOLE_GETKBDLAYOUTNAME, LayoutBuffer),
    V(CONSOLE_GETKBDLAYOUTNAME, Ansi) };
MEMBERS(GetSelectionInfo) = { H(CONSOLE_GETSELECTIONINFO, ConsoleHandle), V(CONSOLE_GETSELECTIONINFO, Info) };
MEMBERS(SetHistoryMode) = { H(CONSOLE_SETHISTORYMODE, ConsoleHandle), V(CONSOLE_SETHISTORYMODE, Mode) };
MEMBERS(HistoryInfo) = { V(CONSOLE_GETSETHISTORYINFO, HistoryBufferSize),
    V(CONSOLE_GETSETHISTORYINFO, NumberOfHistoryBuffers), V(CONSOLE_GETSETHISTORYINFO, dwFlags) };
MEMBERS(GetTitle) = { H(CONSOLE_GETSETCONSOLETITLE, ConsoleHandle), V(CONSOLE_GETSETCONSOLETITLE, Length),
    V(CONSOLE_GETSETCONSOLETITLE, Unicode), B(INOUT, CONSOLE_GETSETCONSOLETITLE, Title, Length, 1) };
MEMBERS(SetTitle) = { H(CONSOLE_GETSETCONSOLETITLE, ConsoleHandle), V(CONSOLE_GETSETCONSOLETITLE, Length),
    V(CONSOLE_GETSETCONSOLETITLE, Unicode), B(IN, CONSOLE_GETSETCONSOLETITLE, Title, Length, 1) };
#define ALIAS_COMMON(T) H(T, ConsoleHandle), V(T, SourceLength), V(T, TargetLength), V(T, ExeLength), \
    V(T, Unicode), V(T, Unicode2), B(IN, T, Source, SourceLength, 1), B(IN, T, ExeName, ExeLength, 1)
MEMBERS(AddAlias) = { ALIAS_COMMON(CONSOLE_ADDGETALIAS), B(IN, CONSOLE_ADDGETALIAS, Target, TargetLength, 1) };
MEMBERS(GetAlias) = { ALIAS_COMMON(CONSOLE_ADDGETALIAS), B(INOUT, CONSOLE_ADDGETALIAS, Target, TargetLength, 1) };
#undef ALIAS_COMMON
MEMBERS(GetAliases) = { H(CONSOLE_GETALLALIASES, ConsoleHandle), V(CONSOLE_GETALLALIASES, ExeLength),
    V(CONSOLE_GETALLALIASES, Unicode), V(CONSOLE_GETALLALIASES, Unicode2), V(CONSOLE_GETALLALIASES, AliasesBufferLength),
    B(IN, CONSOLE_GETALLALIASES, ExeName, ExeLength, 1),
    B(INOUT, CONSOLE_GETALLALIASES, AliasesBuffer, AliasesBufferLength, 1) };
MEMBERS(GetAliasesLength) = { H(CONSOLE_GETALLALIASESLENGTH, ConsoleHandle), V(CONSOLE_GETALLALIASESLENGTH, ExeLength),
    V(CONSOLE_GETALLALIASESLENGTH, Length), V(CONSOLE_GETALLALIASESLENGTH, Unicode),
    V(CONSOLE_GETALLALIASESLENGTH, Unicode2), B(IN, CONSOLE_GETALLALIASESLENGTH, ExeName, ExeLength, 1) };
MEMBERS(GetAliasExes) = { H(CONSOLE_GETALIASESEXES, ConsoleHandle), V(CONSOLE_GETALIASESEXES, Length),
    V(CONSOLE_GETALIASESEXES, Unicode), B(INOUT, CONSOLE_GETALIASESEXES, ExeNames, Length, 1) };
MEMBERS(GetAliasExesLength) = { H(CONSOLE_GETALIASESEXESLENGTH, ConsoleHandle), V(CONSOLE_GETALIASESEXESLENGTH, Length),
    V(CONSOLE_GETALIASESEXESLENGTH, Unicode) };
#define EXE_NAME(T) H(T, ConsoleHandle), V(T, ExeLength), V(T, Unicode), V(T, Unicode2), B(IN, T, ExeName, ExeLength, 1)
MEMBERS(ExpungeHistory) = { EXE_NAME(CONSOLE_EXPUNGECOMMANDHISTORY) };
MEMBERS(SetNumberOfCommands) = { EXE_NAME(CONSOLE_SETHISTORYNUMBERCOMMANDS),
    V(CONSOLE_SETHISTORYNUMBERCOMMANDS, NumCommands) };
MEMBERS(GetHistoryLength) = { EXE_NAME(CONSOLE_GETCOMMANDHISTORYLENGTH), V(CONSOLE_GETCOMMANDHISTORYLENGTH, HistoryLength) };
MEMBERS(GetHistory) = { EXE_NAME(CONSOLE_GETCOMMANDHISTORY), V(CONSOLE_GETCOMMANDHISTORY, HistoryLength),
    B(INOUT, CONSOLE_GETCOMMANDHISTORY, History, HistoryLength, 1) };
#undef EXE_NAME
MEMBERS(SetIcon) = { H(CONSOLE_SETICON, ConsoleHandle), H(CONSOLE_SETICON, IconHandle) };
MEMBERS(SetCursor) = { H(CONSOLE_SETCURSOR, ConsoleHandle), H(CONSOLE_SETCURSOR, OutputHandle),
    H(CONSOLE_SETCURSOR, CursorHandle) };
MEMBERS(SetPalette) = { H(CONSOLE_SETPALETTE, ConsoleHandle), H(CONSOLE_SETPALETTE, OutputHandle),
    H(CONSOLE_SETPALETTE, PaletteHandle), V(CONSOLE_SETPALETTE, Usage) };
MEMBERS(MenuControl) = { H(CONSOLE_MENUCONTROL, ConsoleHandle), H(CONSOLE_MENUCONTROL, OutputHandle),
    V(CONSOLE_MENUCONTROL, CmdIdLow), V(CONSOLE_MENUCONTROL, CmdIdHigh), H(CONSOLE_MENUCONTROL, MenuHandle) };
MEMBERS(InvalidateDIBits) = { H(CONSOLE_INVALIDATEDIBITS, ConsoleHandle), H(CONSOLE_INVALIDATEDIBITS, OutputHandle),
    V(CONSOLE_INVALIDATEDIBITS, Region) };
MEMBERS(HardwareState) = { H(CONSOLE_GETSETHWSTATE, ConsoleHandle), H(CONSOLE_GETSETHWSTATE, OutputHandle),
    V(CONSOLE_GETSETHWSTATE, Flags), V(CONSOLE_GETSETHWSTATE, State) };
MEMBERS(SoundSentry) = { V(BASE_SOUND_SENTRY, VideoMode) };
MEMBERS(EndTask) = { V(USER_END_TASK, LastError), H(USER_END_TASK, WndHandle), V(USER_END_TASK, Force),
    V(USER_END_TASK, Success) };
MEMBERS(FillOutput) = { H(CONSOLE_FILLOUTPUTCODE, ConsoleHandle), H(CONSOLE_FILLOUTPUTCODE, OutputHandle),
    V(CONSOLE_FILLOUTPUTCODE, WriteCoord), V(CONSOLE_FILLOUTPUTCODE, CodeType), V(CONSOLE_FILLOUTPUTCODE, Code),
    V(CONSOLE_FILLOUTPUTCODE, NumCodes) };

#define SERVER_REQUEST(Server, Api, T, Name) { CSR_CREATE_API_NUMBER(Server, Api), \
    sizeof(WOW64_##T), sizeof(T), RTL_NUMBER_OF(Name##Members), Name##Members }
#define REQUEST(Api, T, Name) SERVER_REQUEST(CONSRV_SERVERDLL_INDEX, Consolep##Api, T, Name)
/* The last two entries are a base and a user server request, as small as the console ones: values and
 * handles only. Not translated (they end in UnsupportedApi): VDM requests, the console IME (conime.exe
 * registers it), graphics screen buffers (a bitmap section), UserpDeviceEvent (the server only returns
 * STATUS_NOT_IMPLEMENTED, and its DEV_BROADCAST_HANDLE data is pointer-sized), the logon and service
 * registrations (winlogon and services only), and every request no client library sends. */
static const WOW64_CSR_REQUEST MemberRequests[] =
{
    REQUEST(GetNumberOfFonts, CONSOLE_GETNUMFONTS, GetNumFonts),
    REQUEST(GetNumberOfInputEvents, CONSOLE_GETNUMINPUTEVENTS, GetNumInputEvents),
    REQUEST(GetCursorInfo, CONSOLE_GETSETCURSORINFO, CursorInfo),
    REQUEST(SetCursorInfo, CONSOLE_GETSETCURSORINFO, CursorInfo),
    REQUEST(GetMouseInfo, CONSOLE_GETMOUSEINFO, GetMouseInfo),
    REQUEST(GetFontInfo, CONSOLE_GETFONTINFO, GetFontInfo),
    REQUEST(GetFontSize, CONSOLE_GETFONTSIZE, GetFontSize),
    REQUEST(GetCurrentFont, CONSOLE_GETCURRENTFONT, GetCurrentFont),
    REQUEST(SetActiveScreenBuffer, CONSOLE_SETACTIVESCREENBUFFER, SetActiveScreenBuffer),
    REQUEST(FlushInputBuffer, CONSOLE_FLUSHINPUTBUFFER, FlushInputBuffer),
    REQUEST(GetLargestWindowSize, CONSOLE_GETLARGESTWINDOWSIZE, GetLargestWindowSize),
    REQUEST(SetScreenBufferSize, CONSOLE_SETSCREENBUFFERSIZE, SetScreenBufferSize),
    REQUEST(SetCursorPosition, CONSOLE_SETCURSORPOSITION, SetCursorPosition),
    REQUEST(SetWindowInfo, CONSOLE_SETWINDOWINFO, SetWindowInfo),
    REQUEST(ScrollScreenBuffer, CONSOLE_SCROLLSCREENBUFFER, ScrollScreenBuffer),
    REQUEST(SetTextAttribute, CONSOLE_SETTEXTATTRIB, SetTextAttribute),
    REQUEST(SetFont, CONSOLE_SETFONT, SetFont),
    REQUEST(ShowCursor, CONSOLE_SHOWCURSOR, ShowCursor),
    REQUEST(DuplicateHandle, CONSOLE_DUPLICATEHANDLE, DuplicateHandle),
    REQUEST(GetHandleInformation, CONSOLE_GETHANDLEINFO, GetHandleInfo),
    REQUEST(SetHandleInformation, CONSOLE_SETHANDLEINFO, SetHandleInfo),
    REQUEST(CloseHandle, CONSOLE_CLOSEHANDLE, CloseHandle),
    REQUEST(GetDisplayMode, CONSOLE_GETDISPLAYMODE, GetDisplayMode),
    REQUEST(SetDisplayMode, CONSOLE_SETDISPLAYMODE, SetDisplayMode),
    REQUEST(SetMenuClose, CONSOLE_SETMENUCLOSE, SetMenuClose),
    REQUEST(NotifyLastClose, CONSOLE_NOTIFYLASTCLOSE, NotifyLastClose),
    REQUEST(GenerateCtrlEvent, CONSOLE_GENERATECTRLEVENT, GenerateCtrlEvent),
    REQUEST(GetKeyboardLayoutName, CONSOLE_GETKBDLAYOUTNAME, GetKbdLayoutName),
    REQUEST(GetSelectionInfo, CONSOLE_GETSELECTIONINFO, GetSelectionInfo),
    REQUEST(SetCommandHistoryMode, CONSOLE_SETHISTORYMODE, SetHistoryMode),
    REQUEST(GetHistory, CONSOLE_GETSETHISTORYINFO, HistoryInfo),
    REQUEST(SetHistory, CONSOLE_GETSETHISTORYINFO, HistoryInfo),
    REQUEST(GetTitle, CONSOLE_GETSETCONSOLETITLE, GetTitle),
    REQUEST(SetTitle, CONSOLE_GETSETCONSOLETITLE, SetTitle),
    REQUEST(AddAlias, CONSOLE_ADDGETALIAS, AddAlias),
    REQUEST(GetAlias, CONSOLE_ADDGETALIAS, GetAlias),
    REQUEST(GetAliases, CONSOLE_GETALLALIASES, GetAliases),
    REQUEST(GetAliasesLength, CONSOLE_GETALLALIASESLENGTH, GetAliasesLength),
    REQUEST(GetAliasExes, CONSOLE_GETALIASESEXES, GetAliasExes),
    REQUEST(GetAliasExesLength, CONSOLE_GETALIASESEXESLENGTH, GetAliasExesLength),
    REQUEST(ExpungeCommandHistory, CONSOLE_EXPUNGECOMMANDHISTORY, ExpungeHistory),
    REQUEST(SetNumberOfCommands, CONSOLE_SETHISTORYNUMBERCOMMANDS, SetNumberOfCommands),
    REQUEST(GetCommandHistoryLength, CONSOLE_GETCOMMANDHISTORYLENGTH, GetHistoryLength),
    REQUEST(GetCommandHistory, CONSOLE_GETCOMMANDHISTORY, GetHistory),
    REQUEST(FillConsoleOutput, CONSOLE_FILLOUTPUTCODE, FillOutput),
    REQUEST(SetIcon, CONSOLE_SETICON, SetIcon),
    REQUEST(SetCursor, CONSOLE_SETCURSOR, SetCursor),
    REQUEST(SetPalette, CONSOLE_SETPALETTE, SetPalette),
    REQUEST(MenuControl, CONSOLE_MENUCONTROL, MenuControl),
    REQUEST(InvalidateBitMapRect, CONSOLE_INVALIDATEDIBITS, InvalidateDIBits),
    REQUEST(GetHardwareState, CONSOLE_GETSETHWSTATE, HardwareState),
    REQUEST(SetHardwareState, CONSOLE_GETSETHWSTATE, HardwareState),
    SERVER_REQUEST(BASESRV_SERVERDLL_INDEX, BasepSoundSentryNotification, BASE_SOUND_SENTRY, SoundSentry),
    SERVER_REQUEST(USERSRV_SERVERDLL_INDEX, UserpEndTask, USER_END_TASK, EndTask),
};
#undef REQUEST
#undef SERVER_REQUEST
#undef MEMBERS
#undef B
#undef V
#undef H
#undef SAME_SIZE

#define WOW64_CSR_MAX_BUFFERS 4

/* The requests of the three servers share one message layout: a header, then the request data */
C_ASSERT(FIELD_OFFSET(BASE_API_MESSAGE, Data) == FIELD_OFFSET(CONSOLE_API_MESSAGE, Data));
C_ASSERT(FIELD_OFFSET(USER_API_MESSAGE, Data) == FIELD_OFFSET(CONSOLE_API_MESSAGE, Data));

static NTSTATUS CallMembers(const WOW64_CSR_REQUEST *Request, PUCHAR Guest, ULONG Length)
{
    CONSOLE_API_MESSAGE Message = {0};
    PUCHAR Native = (PUCHAR)&Message.Data;
    PCSR_CAPTURE_BUFFER Capture = NULL;
    PVOID GuestData[WOW64_CSR_MAX_BUFFERS], NativeData[WOW64_CSR_MAX_BUFFERS];
    ULONG Size[WOW64_CSR_MAX_BUFFERS], Units[WOW64_CSR_MAX_BUFFERS], Buffers = 0, i, b;
    ULONG64 Total = 0;
    NTSTATUS Status;

    if (Length != Request->GuestSize) return STATUS_INFO_LENGTH_MISMATCH;
    /* Validate and touch every guest buffer first */
    for (i = 0; i < Request->Count; ++i)
    {
        const WOW64_CSR_MEMBER *M = &Request->Members[i];
        if (M->Kind != MEMBER_IN && M->Kind != MEMBER_INOUT) continue;
        if (Buffers == WOW64_CSR_MAX_BUFFERS) return STATUS_INTERNAL_ERROR;
        /* Read once: the native request and the copies use this value */
        Units[Buffers] = (M->Size == sizeof(USHORT)) ? *(USHORT *)(Guest + M->Length) : *(ULONG *)(Guest + M->Length);
        Total += (ULONG64)Units[Buffers] * M->Unit;
        if (Total > WOW64_MAX_INFO_BUFFER) return STATUS_NO_MEMORY;
        Size[Buffers] = Units[Buffers] * M->Unit;
        Status = GuestBuffer(*(ULONG *)(Guest + M->Guest), Size[Buffers], M->Kind == MEMBER_INOUT, &GuestData[Buffers]);
        if (!NT_SUCCESS(Status)) return Status;
        ++Buffers;
    }
    if (Buffers)
    {
        Capture = CsrAllocateCaptureBuffer(Buffers, (ULONG)Total);
        if (!Capture) return STATUS_NO_MEMORY;
    }
    for (i = 0, b = 0; i < Request->Count; ++i)
    {
        const WOW64_CSR_MEMBER *M = &Request->Members[i];
        switch (M->Kind)
        {
        case MEMBER_HANDLE:
            *(HANDLE *)(Native + M->Native) = HANDLE32(*(ULONG *)(Guest + M->Guest));
            break;
        case MEMBER_VALUE:
            RtlCopyMemory(Native + M->Native, Guest + M->Guest, M->Size);
            break;
        default:
            /* Inputs and outputs are both copied in: bytes the server does not write are returned unchanged */
            CsrCaptureMessageBuffer(Capture, GuestData[b], Size[b], (PVOID *)(Native + M->Native));
            NativeData[b] = *(PVOID *)(Native + M->Native);
            ++b;
            break;
        }
    }
    /* The length members describe the captured sizes, whatever the guest stores meanwhile */
    for (i = 0, b = 0; i < Request->Count; ++i)
    {
        const WOW64_CSR_MEMBER *M = &Request->Members[i];
        if (M->Kind != MEMBER_IN && M->Kind != MEMBER_INOUT) continue;
        if (M->Size == sizeof(USHORT)) *(USHORT *)(Native + M->NativeLength) = (USHORT)Units[b];
        else *(ULONG *)(Native + M->NativeLength) = Units[b];
        ++b;
    }
    Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Request->Api, Request->NativeSize);
    for (i = 0, b = 0; i < Request->Count; ++i)
    {
        const WOW64_CSR_MEMBER *M = &Request->Members[i];
        switch (M->Kind)
        {
        case MEMBER_HANDLE:
            *(ULONG *)(Guest + M->Guest) = HandleToUlong(*(HANDLE *)(Native + M->Native));
            break;
        case MEMBER_VALUE:
            RtlCopyMemory(Guest + M->Guest, Native + M->Native, M->Size);
            break;
        case MEMBER_INOUT:
            if (Size[b]) RtlCopyMemory(GuestData[b], NativeData[b], Size[b]);
            /* Fall through */
        default:
            ++b;
            break;
        }
    }
    if (Capture) CsrFreeCaptureBuffer(Capture);
    return Status;
}

/* Number of CHAR_INFO cells of a region, computed as the server does */
static ULONG64 RegionCells(const SMALL_RECT *Region)
{
    LONG Width = (Region->Left > Region->Right) ? 0 : Region->Right - Region->Left + 1;
    LONG Height = (Region->Top > Region->Bottom) ? 0 : Region->Bottom - Region->Top + 1;
    return (ULONG64)Width * (ULONG64)Height;
}

/* ReadConsole: the static buffer carries the executable name (and the initial characters of a
 * continued read) in, and the characters out when no more than 80 bytes are read */
static NTSTATUS ReadConsole32(WOW64_CONSOLE_READCONSOLE *Guest)
{
    CONSOLE_API_MESSAGE Message = {0};
    CONSOLE_READCONSOLE *Read = &Message.Data.ReadConsoleRequest;
    PCSR_CAPTURE_BUFFER Capture = NULL;
    /* Each guest member is read once; the server trusts NumBytes against the buffer it uses */
    ULONG Size = Guest->CaptureBufferSize, NumBytes = Guest->NumBytes, Initial = Guest->InitialNumBytes;
    PVOID GuestData = NULL, NativeData = NULL;
    NTSTATUS Status;

    if (NumBytes > Size || Initial > NumBytes) return STATUS_INVALID_PARAMETER;
    if (Size > sizeof(Read->StaticBuffer))
    {
        if (Size > WOW64_MAX_INFO_BUFFER) return STATUS_NO_MEMORY;
        Status = GuestBuffer(Guest->Buffer, Size, TRUE, &GuestData);
        if (!NT_SUCCESS(Status)) return Status;
        Capture = CsrAllocateCaptureBuffer(1, Size);
        if (!Capture) return STATUS_NO_MEMORY;
        CsrCaptureMessageBuffer(Capture, GuestData, Size, &Read->Buffer);
        NativeData = Read->Buffer;
    }
    else Read->Buffer = Read->StaticBuffer;
    Read->ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
    Read->InputHandle = HANDLE32(Guest->InputHandle);
    Read->ExeLength = Guest->ExeLength;
    RtlCopyMemory(Read->StaticBuffer, Guest->StaticBuffer, sizeof(Read->StaticBuffer));
    Read->NumBytes = NumBytes;
    Read->CaptureBufferSize = Size;
    Read->InitialNumBytes = Initial;
    Read->CtrlWakeupMask = Guest->CtrlWakeupMask;
    Read->ControlKeyState = Guest->ControlKeyState;
    Read->Unicode = Guest->Unicode;
    Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX,
                                 ConsolepReadConsole), sizeof(*Read));
    Guest->NumBytes = min(Read->NumBytes, Size);
    Guest->ControlKeyState = Read->ControlKeyState;
    if (Capture)
    {
        RtlCopyMemory(GuestData, NativeData, Size);
        CsrFreeCaptureBuffer(Capture);
    }
    else RtlCopyMemory(Guest->StaticBuffer, Read->StaticBuffer, sizeof(Guest->StaticBuffer));
    return Status;
}

/* GetConsoleInput (Peek/ReadConsoleInput) and WriteConsoleInput: at most five records inline */
static NTSTATUS ConsoleInput32(ULONG Api, PVOID Request)
{
    CONSOLE_API_MESSAGE Message = {0};
    BOOLEAN Write = (Api == CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepWriteConsoleInput));
    WOW64_CONSOLE_GETINPUT *GetGuest = Request;
    WOW64_CONSOLE_WRITEINPUT *WriteGuest = Request;
    CONSOLE_GETINPUT *Get = &Message.Data.GetInputRequest;
    CONSOLE_WRITEINPUT *Put = &Message.Data.WriteInputRequest;
    PCSR_CAPTURE_BUFFER Capture = NULL;
    ULONG Count = Write ? WriteGuest->NumRecords : GetGuest->NumRecords;
    ULONG GuestPointer = Write ? WriteGuest->RecordBufPtr : GetGuest->RecordBufPtr;
    PVOID GuestData = NULL, NativeData = NULL, *NativePointer = Write ? (PVOID *)&Put->RecordBufPtr
                                                                      : (PVOID *)&Get->RecordBufPtr;
    ULONG Size = 0;
    NTSTATUS Status;

    if (Count > RTL_NUMBER_OF(Get->RecordStaticBuffer))
    {
        if (Count > WOW64_MAX_INFO_BUFFER / sizeof(INPUT_RECORD)) return STATUS_NO_MEMORY;
        Size = Count * sizeof(INPUT_RECORD);
        Status = GuestBuffer(GuestPointer, Size, !Write, &GuestData);
        if (!NT_SUCCESS(Status)) return Status;
        Capture = CsrAllocateCaptureBuffer(1, Size);
        if (!Capture) return STATUS_NO_MEMORY;
        CsrCaptureMessageBuffer(Capture, GuestData, Size, NativePointer);
        NativeData = *NativePointer;
    }
    if (Write)
    {
        Put->ConsoleHandle = HANDLE32(WriteGuest->ConsoleHandle);
        Put->InputHandle = HANDLE32(WriteGuest->InputHandle);
        RtlCopyMemory(Put->RecordStaticBuffer, WriteGuest->RecordStaticBuffer, sizeof(Put->RecordStaticBuffer));
        if (!Capture) Put->RecordBufPtr = Put->RecordStaticBuffer;
        Put->NumRecords = Count;
        Put->Unicode = WriteGuest->Unicode;
        Put->AppendToEnd = WriteGuest->AppendToEnd;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Api, sizeof(*Put));
        WriteGuest->NumRecords = Put->NumRecords;
    }
    else
    {
        Get->ConsoleHandle = HANDLE32(GetGuest->ConsoleHandle);
        Get->InputHandle = HANDLE32(GetGuest->InputHandle);
        if (!Capture) Get->RecordBufPtr = Get->RecordStaticBuffer;
        Get->NumRecords = Count;
        Get->Flags = GetGuest->Flags;
        Get->Unicode = GetGuest->Unicode;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Api, sizeof(*Get));
        GetGuest->NumRecords = Get->NumRecords;
        if (Capture) RtlCopyMemory(GuestData, NativeData, Size);
        else RtlCopyMemory(GetGuest->RecordStaticBuffer, Get->RecordStaticBuffer, sizeof(Get->RecordStaticBuffer));
    }
    if (Capture) CsrFreeCaptureBuffer(Capture);
    return Status;
}

/* ReadConsoleOutput and WriteConsoleOutput: one cell inline. A write too large for the native
 * CSR heap is read by the server from the guest's buffer (UseVirtualMemory), as the native
 * library does with its own heap buffer. */
static NTSTATUS ConsoleOutput32(ULONG Api, WOW64_CONSOLE_READWRITEOUTPUT *Guest)
{
    CONSOLE_API_MESSAGE Message = {0};
    BOOLEAN Write = (Api == CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepWriteConsoleOutput));
    CONSOLE_READOUTPUT *Read = &Message.Data.ReadOutputRequest;
    CONSOLE_WRITEOUTPUT *Put = &Message.Data.WriteOutputRequest;
    PCSR_CAPTURE_BUFFER Capture = NULL;
    SMALL_RECT Region = Guest->Region;
    ULONG64 Cells = RegionCells(&Region);
    ULONG64 Size = Cells * sizeof(CHAR_INFO);
    PVOID GuestData = NULL, NativeData = NULL;
    NTSTATUS Status;

    C_ASSERT(FIELD_OFFSET(CONSOLE_READOUTPUT, ReadRegion) == FIELD_OFFSET(CONSOLE_WRITEOUTPUT, WriteRegion));
    C_ASSERT(FIELD_OFFSET(CONSOLE_READOUTPUT, Unicode) == FIELD_OFFSET(CONSOLE_WRITEOUTPUT, Unicode));
    C_ASSERT(FIELD_OFFSET(CONSOLE_READOUTPUT, CharInfo) == FIELD_OFFSET(CONSOLE_WRITEOUTPUT, CharInfo));
    C_ASSERT(FIELD_OFFSET(CONSOLE_READOUTPUT, StaticBuffer) == FIELD_OFFSET(CONSOLE_WRITEOUTPUT, StaticBuffer));
    if (Write && Guest->UseVirtualMemory)
    {
        /* The guest library's own heap buffer */
        Status = GuestBuffer(Guest->CharInfo, Size, FALSE, &GuestData);
        if (!NT_SUCCESS(Status)) return Status;
        Put->CharInfo = GuestData;
        Put->UseVirtualMemory = TRUE;
    }
    else if (Cells > 1)
    {
        Status = GuestBuffer(Guest->CharInfo, Size, !Write, &GuestData);
        if (!NT_SUCCESS(Status)) return Status;
        if (Size <= WOW64_MAX_INFO_BUFFER) Capture = CsrAllocateCaptureBuffer(1, (ULONG)Size);
        if (Capture)
        {
            CsrCaptureMessageBuffer(Capture, GuestData, (ULONG)Size, (PVOID *)&Read->CharInfo);
            NativeData = Read->CharInfo;
        }
        else if (Write)
        {
            Put->CharInfo = GuestData;
            Put->UseVirtualMemory = TRUE;
        }
        else return STATUS_NO_MEMORY;
    }
    else Read->CharInfo = &Read->StaticBuffer;
    Read->ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
    Read->OutputHandle = HANDLE32(Guest->OutputHandle);
    Read->StaticBuffer = Guest->StaticBuffer;
    Read->ReadRegion = Region;
    Read->Unicode = Guest->Unicode;
    Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Api,
                                 Write ? sizeof(*Put) : sizeof(*Read));
    Guest->Region = Read->ReadRegion;
    if (!Write)
    {
        if (Capture) RtlCopyMemory(GuestData, NativeData, (SIZE_T)Size);
        else Guest->StaticBuffer = Read->StaticBuffer;
    }
    if (Capture) CsrFreeCaptureBuffer(Capture);
    return Status;
}

/* ReadConsoleOutputString and WriteConsoleOutputString: at most 80 bytes inline */
static NTSTATUS OutputCode32(ULONG Api, WOW64_CONSOLE_OUTPUTCODE *Guest)
{
    CONSOLE_API_MESSAGE Message = {0};
    BOOLEAN Write = (Api == CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepWriteConsoleOutputString));
    CONSOLE_READOUTPUTCODE *Code = &Message.Data.ReadOutputCodeRequest;
    PCSR_CAPTURE_BUFFER Capture = NULL;
    CODE_TYPE Type = Guest->CodeType;
    ULONG NumCodes = Guest->NumCodes;
    ULONG64 Size;
    PVOID GuestData = NULL, NativeData = NULL;
    NTSTATUS Status;

    switch (Type)
    {
    case CODE_ASCII: Size = sizeof(CHAR); break;
    case CODE_UNICODE: Size = sizeof(WCHAR); break;
    case CODE_ATTRIBUTE: Size = sizeof(WORD); break;
    default: return STATUS_INVALID_PARAMETER;
    }
    Size *= NumCodes;
    if (Size > sizeof(Code->CodeStaticBuffer))
    {
        if (Size > WOW64_MAX_INFO_BUFFER) return STATUS_NO_MEMORY;
        Status = GuestBuffer(Guest->pCode, Size, !Write, &GuestData);
        if (!NT_SUCCESS(Status)) return Status;
        Capture = CsrAllocateCaptureBuffer(1, (ULONG)Size);
        if (!Capture) return STATUS_NO_MEMORY;
        CsrCaptureMessageBuffer(Capture, GuestData, (ULONG)Size, &Code->pCode);
        NativeData = Code->pCode;
    }
    else Code->pCode = Code->CodeStaticBuffer;
    Code->ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
    Code->OutputHandle = HANDLE32(Guest->OutputHandle);
    Code->Coord = Guest->Coord;
    Code->CodeType = Type;
    RtlCopyMemory(Code->CodeStaticBuffer, Guest->CodeStaticBuffer, sizeof(Code->CodeStaticBuffer));
    Code->NumCodes = NumCodes;
    Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Api, sizeof(*Code));
    Guest->Coord = Code->Coord;
    Guest->NumCodes = Code->NumCodes;
    if (!Write)
    {
        if (Capture) RtlCopyMemory(GuestData, NativeData, (SIZE_T)Size);
        else RtlCopyMemory(Guest->CodeStaticBuffer, Code->CodeStaticBuffer, sizeof(Guest->CodeStaticBuffer));
    }
    if (Capture) CsrFreeCaptureBuffer(Capture);
    return Status;
}

/* AllocConsole: the start info and four strings are in the guest capture buffer. The start
 * info is widened as for the connection; the handles and init events the server returns are
 * written back there, where the guest library waits on the events. */
static NTSTATUS AllocConsole32(WOW64_CONSOLE_ALLOCCONSOLE *Guest)
{
    CONSOLE_API_MESSAGE Message = {0};
    CONSOLE_ALLOCCONSOLE *Alloc = &Message.Data.AllocConsoleRequest;
    CONSOLE_START_INFO NativeStart = {0};
    PCSR_CAPTURE_BUFFER Capture;
    WOW64_CONSOLE_START *GuestStart;
    PVOID Title, Desktop, AppName, CurDir;
    /* Each length is read once: the capture buffer is sized from these values */
    ULONG TitleLength = Guest->TitleLength, DesktopLength = Guest->DesktopLength;
    ULONG AppNameLength = Guest->AppNameLength, CurDirLength = Guest->CurDirLength;
    ULONG64 Total = (ULONG64)TitleLength + DesktopLength + AppNameLength + CurDirLength;
    ULONG GuestCtrl = Guest->CtrlRoutine;
    LONG PrevCtrl;
    NTSTATUS Status;

    if (Total > WOW64_MAX_INFO_BUFFER) return STATUS_NO_MEMORY;
    Status = GuestBuffer(Guest->ConsoleStartInfo, sizeof(*GuestStart), TRUE, (PVOID *)&GuestStart);
    if (NT_SUCCESS(Status) && !GuestStart) Status = STATUS_INVALID_PARAMETER;
    if (NT_SUCCESS(Status)) Status = GuestBuffer(Guest->ConsoleTitle, TitleLength, FALSE, &Title);
    if (NT_SUCCESS(Status)) Status = GuestBuffer(Guest->Desktop, DesktopLength, FALSE, &Desktop);
    if (NT_SUCCESS(Status)) Status = GuestBuffer(Guest->AppName, AppNameLength, FALSE, &AppName);
    if (NT_SUCCESS(Status)) Status = GuestBuffer(Guest->CurDir, CurDirLength, FALSE, &CurDir);
    if (!NT_SUCCESS(Status)) return Status;
    ConsoleStartToNative(&NativeStart, GuestStart);
    Capture = CsrAllocateCaptureBuffer(5, (ULONG)Total + sizeof(NativeStart));
    if (!Capture) return STATUS_NO_MEMORY;
    CsrCaptureMessageBuffer(Capture, &NativeStart, sizeof(NativeStart), (PVOID *)&Alloc->ConsoleStartInfo);
    Alloc->TitleLength = TitleLength;
    CsrCaptureMessageBuffer(Capture, Title, TitleLength, (PVOID *)&Alloc->ConsoleTitle);
    Alloc->DesktopLength = DesktopLength;
    CsrCaptureMessageBuffer(Capture, Desktop, DesktopLength, (PVOID *)&Alloc->Desktop);
    Alloc->CurDirLength = CurDirLength;
    CsrCaptureMessageBuffer(Capture, CurDir, CurDirLength, (PVOID *)&Alloc->CurDir);
    Alloc->AppNameLength = AppNameLength;
    CsrCaptureMessageBuffer(Capture, AppName, AppNameLength, (PVOID *)&Alloc->AppName);
    Alloc->CtrlRoutine = RegisterCtrlRoutine(GuestCtrl, &PrevCtrl);
    Alloc->PropRoutine = UnsupportedConsoleCallback;
    Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture,
                                 CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepAlloc), sizeof(*Alloc));
    if (NT_SUCCESS(Status)) ConsoleStartToGuest(GuestStart, Alloc->ConsoleStartInfo);
    else RestoreCtrlRoutine(GuestCtrl, PrevCtrl);
    CsrFreeCaptureBuffer(Capture);
    return Status;
}

static NTSTATUS Call(ULONG *a, BOOLEAN *Reported)
{
    /* PORT_MESSAGE32 is 24 bytes, followed by four ULONG CSR fields. */
    ULONG *Data = (ULONG *)((PUCHAR)PTR32(a[0]) + 40);
    ULONG Api = a[2];
    CONSOLE_API_MESSAGE Message = {0};
    NTSTATUS Status;

    /* The message and its request data (a[3] bytes) must lie in the guest's range: replies
     * are written there. A fault inside the range is caught by the caller's SEH. */
    if ((ULONG64)a[0] + 40 + a[3] > (ULONG64)Wow64HighestUserAddress + 1) return STATUS_ACCESS_VIOLATION;
    /* The guest library stores the status in the header after the call: the whole message must
     * be writable before a request changes server state */
    {
        volatile UCHAR *Bytes = PTR32(a[0]);
        ULONG i;
        for (i = 0; i < 40 + a[3]; ++i) Bytes[i] = Bytes[i];
    }
    switch (Api)
    {
    case CSR_CREATE_API_NUMBER(USERSRV_SERVERDLL_INDEX, UserpGetThreadConsoleDesktop):
    {
        USER_API_MESSAGE UserMessage = {0};
        if (a[3] != 2 * sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        UserMessage.Data.GetThreadConsoleDesktopRequest.ThreadId = Data[0];
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&UserMessage, NULL, Api,
                                    sizeof(USER_GET_THREAD_CONSOLE_DESKTOP));
        if (NT_SUCCESS(Status))
            Data[1] = HandleToUlong(UserMessage.Data.GetThreadConsoleDesktopRequest.ConsoleDesktop);
        return Status;
    }
    case CSR_CREATE_API_NUMBER(USERSRV_SERVERDLL_INDEX, UserpExitWindowsEx):
    {
        /* ExitWindowsEx, logoff, shutdown, reboot: three ULONGs in the guest as natively (no pointers).
         * The failure statuses carry meaning: STATUS_CANT_WAIT asks the guest library to run the
         * request again on a thread of its own, and the server stores LastError for the others. */
        WOW64_USER_EXIT_REACTOS *Guest = (PVOID)Data;
        USER_API_MESSAGE UserMessage = {0};
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        UserMessage.Data.ExitReactOSRequest.Flags = Guest->Flags;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&UserMessage, NULL, Api, sizeof(USER_EXIT_REACTOS));
        Guest->LastError = UserMessage.Data.ExitReactOSRequest.LastError;
        Guest->Success = UserMessage.Data.ExitReactOSRequest.Success;
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepWriteConsole):
    {
        WOW64_CONSOLE_WRITE *From = (PVOID)Data;
        CONSOLE_WRITECONSOLE *To = &Message.Data.WriteConsoleRequest;
        PCSR_CAPTURE_BUFFER Capture = NULL;
        ULONG NumBytes;
        PVOID GuestData;
        if (a[3] != sizeof(*From)) return STATUS_INFO_LENGTH_MISMATCH;
        /* Read once: it sizes the copy into the inline buffer or the capture */
        NumBytes = From->NumBytes;
        Status = GuestBuffer(From->Buffer, NumBytes, FALSE, &GuestData);
        if (!NT_SUCCESS(Status)) return Status;
        To->ConsoleHandle = HANDLE32(From->ConsoleHandle);
        To->OutputHandle = HANDLE32(From->OutputHandle);
        To->Unicode = From->Unicode;
        To->NumBytes = NumBytes;
        if (NumBytes <= sizeof(To->StaticBuffer))
        {
            To->UsingStaticBuffer = TRUE;
            To->Buffer = To->StaticBuffer;
            RtlCopyMemory(To->Buffer, GuestData, NumBytes);
        }
        else
        {
            Capture = CsrAllocateCaptureBuffer(1, NumBytes);
            if (!Capture) return STATUS_NO_MEMORY;
            CsrCaptureMessageBuffer(Capture, GuestData, NumBytes, &To->Buffer);
        }
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Api, sizeof(*To));
        if (Capture) CsrFreeCaptureBuffer(Capture);
        From->NumBytes = To->NumBytes;
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetMode):
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepSetMode):
        if (a[3] != 12) return STATUS_INFO_LENGTH_MISMATCH;
        Message.Data.ConsoleModeRequest.ConsoleHandle = HANDLE32(Data[0]);
        Message.Data.ConsoleModeRequest.Handle = HANDLE32(Data[1]);
        Message.Data.ConsoleModeRequest.Mode = Data[2];
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(Message.Data.ConsoleModeRequest));
        Data[2] = Message.Data.ConsoleModeRequest.Mode;
        return Status;
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetScreenBufferInfo):
    {
        WOW64_CONSOLE_SCREEN_BUFFER_INFO *Guest = (PVOID)Data;
        CONSOLE_GETSCREENBUFFERINFO *Info = &Message.Data.ScreenBufferInfoRequest;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Info->ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        Info->OutputHandle = HANDLE32(Guest->OutputHandle);
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(*Info));
        if (NT_SUCCESS(Status))
        {
            Guest->ScreenBufferSize = Info->ScreenBufferSize;
            Guest->CursorPosition = Info->CursorPosition;
            Guest->ViewOrigin = Info->ViewOrigin;
            Guest->Attributes = Info->Attributes;
            Guest->ViewSize = Info->ViewSize;
            Guest->MaximumViewSize = Info->MaximumViewSize;
        }
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetCP):
    {
        WOW64_CONSOLE_GET_CP *Guest = (PVOID)Data;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Message.Data.GetConsoleCPRequest.ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        Message.Data.GetConsoleCPRequest.OutputCP = Guest->OutputCP;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(Message.Data.GetConsoleCPRequest));
        if (NT_SUCCESS(Status)) Guest->CodePage = Message.Data.GetConsoleCPRequest.CodePage;
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepSetCP):
    {
        WOW64_CONSOLE_SET_CP *Guest = (PVOID)Data;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Message.Data.SetConsoleCPRequest.ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        Message.Data.SetConsoleCPRequest.CodePage = Guest->CodePage;
        Message.Data.SetConsoleCPRequest.OutputCP = Guest->OutputCP;
        Message.Data.SetConsoleCPRequest.EventHandle = HANDLE32(Guest->EventHandle);
        return CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(Message.Data.SetConsoleCPRequest));
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetLangId):
    {
        WOW64_CONSOLE_LANGID *Guest = (PVOID)Data;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Message.Data.LangIdRequest.ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(Message.Data.LangIdRequest));
        if (NT_SUCCESS(Status)) Guest->LangId = Message.Data.LangIdRequest.LangId;
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepVerifyIoHandle):
        if (a[3] != 12) return STATUS_INFO_LENGTH_MISMATCH;
        Message.Data.VerifyHandleRequest.ConsoleHandle = HANDLE32(Data[1]);
        Message.Data.VerifyHandleRequest.Handle = HANDLE32(Data[2]);
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(Message.Data.VerifyHandleRequest));
        Data[0] = Message.Data.VerifyHandleRequest.IsValid;
        return Status;
    case CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepCreateThread):
    {
        BASE_API_MESSAGE BaseMessage = {0};
        if (a[3] != 3 * sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        BaseMessage.Data.CreateThreadRequest.ThreadHandle = HANDLE32(Data[0]);
        BaseMessage.Data.CreateThreadRequest.ClientId.UniqueProcess = HANDLE32(Data[1]);
        BaseMessage.Data.CreateThreadRequest.ClientId.UniqueThread = HANDLE32(Data[2]);
        return CsrClientCallServer((PCSR_API_MESSAGE)&BaseMessage, NULL, Api,
                                  sizeof(BASE_CREATE_THREAD));
    }
    case CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepGetTempFile):
    {
        BASE_API_MESSAGE BaseMessage = {0};
        if (a[3] != sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&BaseMessage, NULL, Api,
                                     sizeof(BASE_GET_TEMP_FILE));
        Data[0] = BaseMessage.Data.GetTempFileRequest.UniqueID;
        return Status;
    }
    case CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepSetProcessShutdownParam):
    case CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepGetProcessShutdownParam):
    {
        /* Two ULONGs, the same for both sizes */
        BASE_API_MESSAGE BaseMessage = {0};
        BASE_GETSET_PROCESS_SHUTDOWN_PARAMS *Guest = (PVOID)Data;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        BaseMessage.Data.ShutdownParametersRequest = *Guest;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&BaseMessage, NULL, Api, sizeof(*Guest));
        if (NT_SUCCESS(Status) && Api == CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepGetProcessShutdownParam))
            *Guest = BaseMessage.Data.ShutdownParametersRequest;
        return Status;
    }
    case CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepDefineDosDevice):
    {
        /* ULONG Flags and two UNICODE_STRINGs whose buffers lie in the guest capture buffer (20 bytes; the
         * native request is 40). Each string is copied once into a native capture buffer with a terminator,
         * as the server validates the target with one. */
        struct { ULONG Flags; USHORT NameLength, NameMax; ULONG Name; USHORT TargetLength, TargetMax; ULONG Target; }
            Guest;
        BASE_API_MESSAGE BaseMessage = {0};
        PBASE_DEFINE_DOS_DEVICE To = &BaseMessage.Data.DefineDosDeviceRequest;
        PCSR_CAPTURE_BUFFER Capture;
        PVOID GuestName, GuestTarget, Buffer;
        ULONG Buffers;
        C_ASSERT(sizeof(Guest) == 20);
        if (a[3] != sizeof(Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        RtlCopyMemory(&Guest, Data, sizeof(Guest));
        Status = GuestBuffer(Guest.Name, Guest.NameLength, FALSE, &GuestName);
        if (NT_SUCCESS(Status)) Status = GuestBuffer(Guest.Target, Guest.TargetLength, FALSE, &GuestTarget);
        if (!NT_SUCCESS(Status)) return Status;
        Buffers = 1 + (Guest.TargetLength != 0);
        Capture = CsrAllocateCaptureBuffer(Buffers, Guest.NameLength + Guest.TargetLength + 16);
        if (!Capture) return STATUS_NO_MEMORY;
        To->Flags = Guest.Flags;
        To->DeviceName.Length = Guest.NameLength;
        /* The pointer fields must be those of the message: the capture buffer turns them into offsets */
        To->DeviceName.MaximumLength = CsrAllocateMessagePointer(Capture, Guest.NameLength + sizeof(WCHAR),
                                                                 (PVOID *)&To->DeviceName.Buffer);
        Buffer = To->DeviceName.Buffer;
        if (Guest.NameLength) RtlCopyMemory(Buffer, GuestName, Guest.NameLength);
        ((PWCHAR)((PUCHAR)Buffer + Guest.NameLength))[0] = UNICODE_NULL;
        if (Guest.TargetLength)
        {
            To->TargetPath.Length = Guest.TargetLength;
            To->TargetPath.MaximumLength = CsrAllocateMessagePointer(Capture, Guest.TargetLength + sizeof(WCHAR),
                                                                     (PVOID *)&To->TargetPath.Buffer);
            Buffer = To->TargetPath.Buffer;
            RtlCopyMemory(Buffer, GuestTarget, Guest.TargetLength);
            ((PWCHAR)((PUCHAR)Buffer + Guest.TargetLength))[0] = UNICODE_NULL;
        }
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&BaseMessage, Capture, Api, sizeof(*To));
        CsrFreeCaptureBuffer(Capture);
        return Status;
    }
    case CSR_CREATE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepExitProcess):
    {
        BASE_API_MESSAGE BaseMessage = {0};
        if (a[3] != sizeof(BASE_EXIT_PROCESS)) return STATUS_INFO_LENGTH_MISMATCH;
        BaseMessage.Data.ExitProcessRequest.uExitCode = Data[0];
        return CsrClientCallServer((PCSR_API_MESSAGE)&BaseMessage, NULL, Api, sizeof(BASE_EXIT_PROCESS));
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepOpenConsole):
    {
        WOW64_CONSOLE_OPENCONSOLE *Guest = (PVOID)Data;
        CONSOLE_OPENCONSOLE *Open = &Message.Data.OpenConsoleRequest;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Open->ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        Open->HandleType = Guest->HandleType;
        Open->DesiredAccess = Guest->DesiredAccess;
        Open->InheritHandle = Guest->InheritHandle;
        Open->ShareMode = Guest->ShareMode;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(*Open));
        if (NT_SUCCESS(Status)) Guest->Handle = HandleToUlong(Open->Handle);
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepCreateScreenBuffer):
    {
        WOW64_CONSOLE_CREATESCREENBUFFER *Guest = (PVOID)Data;
        CONSOLE_CREATESCREENBUFFER *Create = &Message.Data.CreateScreenBufferRequest;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        /* A graphics screen buffer carries a BITMAPINFO pointer and a shared
         * section mapping; only text-mode buffers are a pure fixed-width request. */
        if (Guest->ScreenBufferType != CONSOLE_TEXTMODE_BUFFER)
            return UnsupportedApi(Api, a[3], Reported);
        Create->ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        Create->DesiredAccess = Guest->DesiredAccess;
        Create->InheritHandle = Guest->InheritHandle;
        Create->ShareMode = Guest->ShareMode;
        Create->ScreenBufferType = Guest->ScreenBufferType;
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api, sizeof(*Create));
        if (NT_SUCCESS(Status)) Guest->OutputHandle = HandleToUlong(Create->OutputHandle);
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepAttach):
    {
        WOW64_CONSOLE_ATTACH *Guest = (PVOID)Data;
        CONSOLE_ATTACHCONSOLE *Attach = &Message.Data.AttachConsoleRequest;
        WOW64_CONSOLE_START *GuestStart;
        CONSOLE_START_INFO NativeStart = {0};
        PCSR_CAPTURE_BUFFER Capture;
        ULONG StartInfo;
        LONG PrevCtrl;
        ULONG GuestCtrl;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        /* The guest start info lives in the guest's capture buffer; the reply is written there.
         * Read its address once: the range check and every use see the same pointer. */
        StartInfo = *(volatile ULONG *)&Guest->ConsoleStartInfo;
        if (!StartInfo ||
            (ULONG64)StartInfo + sizeof(*GuestStart) > (ULONG64)Wow64HighestUserAddress + 1)
            return STATUS_INVALID_PARAMETER;
        GuestStart = PTR32(StartInfo);
        {
            volatile UCHAR *Bytes = (volatile UCHAR *)GuestStart;
            ULONG i;
            for (i = 0; i < sizeof(*GuestStart); ++i) Bytes[i] = Bytes[i];
        }
        ConsoleStartToNative(&NativeStart, GuestStart);
        Capture = CsrAllocateCaptureBuffer(1, sizeof(NativeStart));
        if (!Capture) return STATUS_NO_MEMORY;
        Attach->ProcessId = Guest->ProcessId; /* ATTACH_PARENT_PROCESS (-1) stays -1 */
        GuestCtrl = *(volatile ULONG *)&Guest->CtrlRoutine;
        Attach->CtrlRoutine = RegisterCtrlRoutine(GuestCtrl, &PrevCtrl);
        Attach->PropRoutine = UnsupportedConsoleCallback;
        CsrCaptureMessageBuffer(Capture, &NativeStart, sizeof(NativeStart), (PVOID *)&Attach->ConsoleStartInfo);
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Api, sizeof(*Attach));
        /* The server filled the captured copy (handles and init events) */
        if (NT_SUCCESS(Status)) ConsoleStartToGuest(GuestStart, Attach->ConsoleStartInfo);
        else RestoreCtrlRoutine(GuestCtrl, PrevCtrl);
        CsrFreeCaptureBuffer(Capture);
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepFree):
    {
        WOW64_CONSOLE_FREE *Guest = (PVOID)Data;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Message.Data.FreeConsoleRequest.ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        return CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api,
                                   sizeof(Message.Data.FreeConsoleRequest));
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetConsoleWindow):
    {
        WOW64_CONSOLE_GETWINDOW *Guest = (PVOID)Data;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Message.Data.GetWindowRequest.ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, NULL, Api,
                                     sizeof(Message.Data.GetWindowRequest));
        if (NT_SUCCESS(Status)) Guest->WindowHandle = HandleToUlong(Message.Data.GetWindowRequest.WindowHandle);
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetProcessList):
    {
        WOW64_CONSOLE_GETPROCESSLIST *Guest = (PVOID)Data;
        CONSOLE_GETPROCESSLIST *List = &Message.Data.GetProcessListRequest;
        PCSR_CAPTURE_BUFFER Capture;
        ULONG Count, Copy, IdsList;
        if (a[3] != sizeof(*Guest)) return STATUS_INFO_LENGTH_MISMATCH;
        Count = *(volatile ULONG *)&Guest->ProcessCount;
        /* The id array lives in the guest capture buffer and is written back: it must lie in the
         * guest range and be writable before the server is asked. Its address is read once, so
         * the check, the touch and the copy back all use the same one. */
        IdsList = *(volatile ULONG *)&Guest->ProcessIdsList;
        if (!IdsList || Count > 0x10000 ||
            (ULONG64)IdsList + (ULONG64)Count * sizeof(ULONG) > (ULONG64)Wow64HighestUserAddress + 1)
            return STATUS_INVALID_PARAMETER;
        {
            volatile UCHAR *Bytes = PTR32(IdsList);
            ULONG i;
            for (i = 0; i < Count * sizeof(ULONG); ++i) Bytes[i] = Bytes[i];
        }
        /* The ids are ULONGs on both sides: only the buffer itself is native */
        Capture = CsrAllocateCaptureBuffer(1, Count * sizeof(ULONG));
        if (!Capture) return STATUS_NO_MEMORY;
        List->ConsoleHandle = HANDLE32(Guest->ConsoleHandle);
        List->ProcessCount = Count;
        CsrAllocateMessagePointer(Capture, Count * sizeof(ULONG), (PVOID *)&List->ProcessIdsList);
        Status = CsrClientCallServer((PCSR_API_MESSAGE)&Message, Capture, Api, sizeof(*List));
        if (NT_SUCCESS(Status))
        {
            /* The server returns the total; only the first Count ids were stored */
            Guest->ProcessCount = List->ProcessCount;
            Copy = min(List->ProcessCount, Count);
            RtlCopyMemory(PTR32(IdsList), List->ProcessIdsList, Copy * sizeof(ULONG));
        }
        CsrFreeCaptureBuffer(Capture);
        return Status;
    }
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepReadConsole):
        if (a[3] != sizeof(WOW64_CONSOLE_READCONSOLE)) return STATUS_INFO_LENGTH_MISMATCH;
        return ReadConsole32((PVOID)Data);
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepGetConsoleInput):
        if (a[3] != sizeof(WOW64_CONSOLE_GETINPUT)) return STATUS_INFO_LENGTH_MISMATCH;
        return ConsoleInput32(Api, Data);
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepWriteConsoleInput):
        if (a[3] != sizeof(WOW64_CONSOLE_WRITEINPUT)) return STATUS_INFO_LENGTH_MISMATCH;
        return ConsoleInput32(Api, Data);
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepReadConsoleOutput):
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepWriteConsoleOutput):
        if (a[3] != sizeof(WOW64_CONSOLE_READWRITEOUTPUT)) return STATUS_INFO_LENGTH_MISMATCH;
        return ConsoleOutput32(Api, (PVOID)Data);
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepReadConsoleOutputString):
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepWriteConsoleOutputString):
        if (a[3] != sizeof(WOW64_CONSOLE_OUTPUTCODE)) return STATUS_INFO_LENGTH_MISMATCH;
        return OutputCode32(Api, (PVOID)Data);
    case CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepAlloc):
        if (a[3] != sizeof(WOW64_CONSOLE_ALLOCCONSOLE)) return STATUS_INFO_LENGTH_MISMATCH;
        return AllocConsole32((PVOID)Data);
    default:
    {
        ULONG i;
        for (i = 0; i < RTL_NUMBER_OF(MemberRequests); ++i)
            if (MemberRequests[i].Api == Api) return CallMembers(&MemberRequests[i], (PUCHAR)Data, a[3]);
        return UnsupportedApi(Api, a[3], Reported);
    }
    }
}

NTSTATUS Wow64CsrDispatch(ULONG Operation, ULONG *Arguments, BOOLEAN *Reported)
{
    /* The argument array is guest memory: Connect and Call use a copy read once
     * (csrlib passes five and four ULONGs) */
    ULONG Captured[5];
    switch (Operation)
    {
    case 0:
        RtlCopyMemory(Captured, Arguments, 5 * sizeof(ULONG));
        return Connect(Captured, Reported);
    case 1:
        RtlCopyMemory(Captured, Arguments, 4 * sizeof(ULONG));
        Captured[4] = 0;
        return Call(Captured, Reported);
    case 2: return CsrNewThread();
    default: return Wow64Unsupported(WOW64_SERVICE_CSR, WOW64_UNSUPPORTED_OPERATION, Operation, Reported);
    }
}
