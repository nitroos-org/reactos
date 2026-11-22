/* ReactOS WoW64 USER raw-input and SendInput translation.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64win.h"

/* The i386 view: every field is four bytes wide, so these lay out identically on both targets. */
typedef struct { LONG dx, dy; ULONG mouseData, dwFlags, time, dwExtraInfo; } MOUSEINPUT32;
typedef struct { USHORT wVk, wScan; ULONG dwFlags, time, dwExtraInfo; } KEYBDINPUT32;
typedef struct { ULONG uMsg; USHORT wParamL, wParamH; } HARDWAREINPUT32;
typedef struct { ULONG type; union { MOUSEINPUT32 mi; KEYBDINPUT32 ki; HARDWAREINPUT32 hi; } u; } INPUT32;
typedef struct { ULONG dwType, dwSize, hDevice, wParam; } RAWINPUTHEADER32;
typedef struct { USHORT usUsagePage, usUsage; ULONG dwFlags, hwndTarget; } RAWINPUTDEVICE32;
typedef struct { ULONG hDevice, dwType; } RAWINPUTDEVICELIST32;
typedef struct { INT x, y; ULONG time, dwExtraInfo; } MOUSEMOVEPOINT32;
C_ASSERT(sizeof(INPUT32) == 28);
C_ASSERT(sizeof(RAWINPUTHEADER32) == 16);
C_ASSERT(sizeof(RAWINPUTDEVICE32) == 12);
C_ASSERT(sizeof(RAWINPUTDEVICELIST32) == 8);
C_ASSERT(sizeof(MOUSEMOVEPOINT32) == 16);
C_ASSERT(sizeof(INPUT) == 40);
C_ASSERT(sizeof(RAWINPUTHEADER) == 24);
C_ASSERT(sizeof(RAWINPUTHEADER) - sizeof(RAWINPUTHEADER32) == 8);

#define FAIL32 ((ULONG_PTR)0xFFFFFFFFul)
#define HEADER_DELTA (sizeof(RAWINPUTHEADER) - sizeof(RAWINPUTHEADER32))
#define INPUT_CHUNK 1024
#define RAWBUFFER_MAX 0x100000
#define MOUSEMOVE_MAX 64
#define REGISTER_MAX 4096
#define RETRIES 4
#define DEVICE_TOKENS 256

static VOID SetNtError(NTSTATUS Status) { RtlSetLastWin32Error(RtlNtStatusToDosError(Status)); }

static PVOID Alloc(ULONGLONG Size)
{
    if (Size > MAXLONG) return NULL;
    return RtlAllocateHeap(RtlGetProcessHeap(), 0, (SIZE_T)Size);
}

static VOID Free(PVOID Block) { if (Block) RtlFreeHeap(RtlGetProcessHeap(), 0, Block); }

/* The guest owns the low 4 GiB; a range may not run into native-only addresses. */
static BOOLEAN GuestRange(ULONG Address, ULONGLONG Length) { return Length <= 0x100000000ULL - Address; }

/* Mirrors ProbeForWrite: the range must lie in the guest space and every page must be writable. */
static NTSTATUS Touch(ULONG Address, ULONGLONG Length)
{
    ULONGLONG Off;
    NTSTATUS Status = STATUS_SUCCESS;
    if (!Length) return STATUS_SUCCESS;
    if (!GuestRange(Address, Length)) return STATUS_ACCESS_VIOLATION;
    _SEH2_TRY
    {
        for (Off = 0; Off < Length; Off += 0x1000)
            *(volatile BYTE *)P32(Address + Off) = *(volatile BYTE *)P32(Address + Off);
        *(volatile BYTE *)P32(Address + Length - 1) = *(volatile BYTE *)P32(Address + Length - 1);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    return Status;
}

static NTSTATUS GuestRead32(ULONG Address, ULONG *Value)
{
    NTSTATUS Status = STATUS_SUCCESS;
    if (Address & 3) return STATUS_DATATYPE_MISALIGNMENT;
    if (!GuestRange(Address, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    _SEH2_TRY { *Value = *(volatile ULONG *)P32(Address); }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    return Status;
}

static NTSTATUS GuestWrite32(ULONG Address, ULONG Value)
{
    NTSTATUS Status = STATUS_SUCCESS;
    if (Address & 3) return STATUS_DATATYPE_MISALIGNMENT;
    if (!GuestRange(Address, sizeof(ULONG))) return STATUS_ACCESS_VIOLATION;
    _SEH2_TRY { *(volatile ULONG *)P32(Address) = Value; }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    return Status;
}

/* Device handles are kernel pointers; the guest sees stable 32-bit tokens, oldest evicted first. */
static struct { HANDLE Native; ULONG Token; } DeviceTokens[DEVICE_TOKENS];
static ULONG DeviceNext, DeviceSerial;
/* A critical section rather than SRW: the SRW exports need DLL_EXPORT_VERSION 0x600, which a WoW64 build does not
 * require. Statically initialized like LdrpDllNotificationLock, so no setup path has to run first. */
static RTL_CRITICAL_SECTION DeviceLock;
static RTL_CRITICAL_SECTION_DEBUG DeviceLockDebug = { .CriticalSection = &DeviceLock };
static RTL_CRITICAL_SECTION DeviceLock = { &DeviceLockDebug, -1, 0, 0, 0, 0 };

static VOID DeviceLockEnter(VOID) { RtlEnterCriticalSection(&DeviceLock); }
static VOID DeviceLockLeave(VOID) { RtlLeaveCriticalSection(&DeviceLock); }

static ULONG DeviceToken(HANDLE Native)
{
    ULONG i, Token = 0;
    if (!Native) return 0;
    DeviceLockEnter();
    for (i = 0; i < DEVICE_TOKENS; ++i)
        if (DeviceTokens[i].Token && DeviceTokens[i].Native == Native) { Token = DeviceTokens[i].Token; break; }
    if (!Token)
    {
        do { ++DeviceSerial; } while ((DeviceSerial & 0x3FFFFFFF) == 0);
        Token = ((DeviceSerial & 0x3FFFFFFF) << 2) | 2;
        i = DeviceNext++ % DEVICE_TOKENS;
        DeviceTokens[i].Native = Native;
        DeviceTokens[i].Token = Token;
    }
    DeviceLockLeave();
    return Token;
}

static HANDLE DeviceFromToken(ULONG Token)
{
    ULONG i;
    HANDLE Native = (HANDLE)(ULONG_PTR)Token;
    if (!Token) return NULL;
    DeviceLockEnter();
    for (i = 0; i < DEVICE_TOKENS; ++i)
        if (DeviceTokens[i].Token == Token) { Native = DeviceTokens[i].Native; break; }
    DeviceLockLeave();
    return Native;
}

static VOID InputIn(INPUT *To, const INPUT32 *From)
{
    INPUT32 Local;
    RtlCopyMemory(&Local, From, sizeof(Local));
    RtlZeroMemory(To, sizeof(*To));
    To->type = Local.type;
    switch (Local.type)
    {
    case INPUT_MOUSE:
        To->mi.dx = Local.u.mi.dx; To->mi.dy = Local.u.mi.dy; To->mi.mouseData = Local.u.mi.mouseData;
        To->mi.dwFlags = Local.u.mi.dwFlags; To->mi.time = Local.u.mi.time; To->mi.dwExtraInfo = Local.u.mi.dwExtraInfo;
        break;
    case INPUT_KEYBOARD:
        To->ki.wVk = Local.u.ki.wVk; To->ki.wScan = Local.u.ki.wScan; To->ki.dwFlags = Local.u.ki.dwFlags;
        To->ki.time = Local.u.ki.time; To->ki.dwExtraInfo = Local.u.ki.dwExtraInfo;
        break;
    case INPUT_HARDWARE:
        To->hi.uMsg = Local.u.hi.uMsg; To->hi.wParamL = Local.u.hi.wParamL; To->hi.wParamH = Local.u.hi.wParamH;
        break;
    }
}

static ULONG_PTR SendInput32(ULONG *a)
{
    ULONG Total = 0, Left, Chunk, Done, Start = a[1];
    ULONGLONG Avail;
    INPUT *Native;
    NTSTATUS Fault = STATUS_SUCCESS;

    if (!a[0] || !a[1] || a[2] != sizeof(INPUT32)) return NtUserSendInput(0, NULL, 0);
    Avail = (0x100000000ULL - Start) / sizeof(INPUT32);
    Left = (ULONG)min((ULONGLONG)a[0], Avail);
    Native = Alloc((ULONGLONG)min(Left, INPUT_CHUNK) * sizeof(INPUT));
    if (!Native && Left) { RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    if (Left < a[0]) Fault = STATUS_ACCESS_VIOLATION;
    while (Left)
    {
        const INPUT32 *Guest = P32(Start);
        Chunk = min(Left, INPUT_CHUNK);
        Done = 0;
        _SEH2_TRY
        {
            for (; Done < Chunk; ++Done) InputIn(&Native[Done], &Guest[Done]);
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Fault = _SEH2_GetExceptionCode(); }
        _SEH2_END;
        /* A fault delivers the readable prefix first, as the native loop does. */
        if (Done)
        {
            ULONG Saved = RtlGetLastWin32Error();
            UINT Sent;

            RtlSetLastWin32Error(ERROR_SUCCESS);
            Sent = NtUserSendInput(Done, Native, sizeof(INPUT));
            if (Sent || RtlGetLastWin32Error() == ERROR_SUCCESS) RtlSetLastWin32Error(Saved);
            /* Refused because the thread's desktop does not have the input: a 32-bit program on Windows
               (WOW64) gets the number of inputs back, with the last error ERROR_ACCESS_DENIED that the native
               call set, and nothing is sent (Windows Server 2022, row V7: SendInput of 2 keys returns 2) */
            if (!Sent && RtlGetLastWin32Error() == ERROR_ACCESS_DENIED) Sent = Done;
            Total += Sent;
        }
        if (Done < Chunk) break;
        Start += Chunk * sizeof(INPUT32);
        Left -= Chunk;
    }
    Free(Native);
    if (Fault) SetNtError(Fault);
    return Total;
}

static VOID RawHeaderOut(RAWINPUTHEADER32 *To, const RAWINPUTHEADER *From)
{
    To->dwType = From->dwType;
    To->dwSize = From->dwSize - (ULONG)HEADER_DELTA;
    To->hDevice = DeviceToken(From->hDevice);
    To->wParam = (ULONG)From->wParam;
}

/* Native records are packed back to back by dwSize; guest records are padded to DWORD like NEXTRAWINPUTBLOCK. */
static BOOLEAN RawRecordsOut(const BYTE *Buf, ULONG BufSize, ULONG Count, ULONG GuestAddress, ULONG GuestSize)
{
    ULONG i, NOff = 0, GOff = 0, Size, Pad;
    RAWINPUTHEADER Header;
    RAWINPUTHEADER32 Header32;
    BYTE *Guest = P32(GuestAddress);

    for (i = 0; i < Count; ++i)
    {
        if (BufSize - NOff < sizeof(Header)) return FALSE;
        RtlCopyMemory(&Header, Buf + NOff, sizeof(Header));
        Size = Header.dwSize;
        if (Size < sizeof(Header) || Size > BufSize - NOff) return FALSE;
        if (Size - HEADER_DELTA > GuestSize - GOff) return FALSE;
        RawHeaderOut(&Header32, &Header);
        RtlCopyMemory(Guest + GOff, &Header32, sizeof(Header32));
        RtlCopyMemory(Guest + GOff + sizeof(Header32), Buf + NOff + sizeof(Header), Size - sizeof(Header));
        NOff += Size;
        GOff += Size - (ULONG)HEADER_DELTA;
        Pad = -GOff & 3;
        if (i + 1 < Count)
        {
            if (Pad > GuestSize - GOff) return FALSE;
            RtlZeroMemory(Guest + GOff, Pad);
            GOff += Pad;
        }
    }
    return TRUE;
}

static ULONG_PTR RawBuffer32(ULONG *a)
{
    ULONG Capacity = 0, Limit, Initial, Saved, Err, Count;
    UINT Local = 0;
    ULONG_PTR Result;
    DWORD Ret;
    NTSTATUS Status;
    BYTE *Buf;
    BOOLEAN Ok = TRUE;

    if (a[2] != sizeof(RAWINPUTHEADER32) || !a[1]) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FAIL32; }
    Status = GuestRead32(a[1], &Capacity);
    if (Status) { SetNtError(Status); return FAIL32; }

    if (!a[0])
    {
        /* Native leaves the size alone when the thread has no queue. */
        Local = 0xFFFFFFFF;
        Ret = NtUserGetRawInputBuffer(NULL, &Local, sizeof(RAWINPUTHEADER));
        if (Ret == (DWORD)-1) return FAIL32;
        if (Local == 0xFFFFFFFF) return Ret;
        Status = GuestWrite32(a[1], Local >= sizeof(RAWINPUTHEADER) ? Local - (ULONG)HEADER_DELTA : 0);
        if (Status) { SetNtError(Status); return FAIL32; }
        return Ret;
    }

    /* Like ProbeForWrite, an empty destination is not checked for alignment. */
    if (Capacity && (a[0] & 3)) { SetNtError(STATUS_DATATYPE_MISALIGNMENT); return FAIL32; }
    /* The native call retires queued messages, so the whole destination must be writable before it runs. */
    Status = Touch(a[0], Capacity);
    if (Status) { SetNtError(Status); return FAIL32; }

    /* Eight spare native bytes let the first record fit exactly when its guest form does. */
    Limit = min(Capacity, RAWBUFFER_MAX);
    Initial = Limit + (ULONG)HEADER_DELTA;
    Buf = Alloc(Initial);
    if (!Buf) { RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY); return FAIL32; }
    Local = Initial;
    Saved = RtlGetLastWin32Error();
    RtlSetLastWin32Error(0);
    Ret = NtUserGetRawInputBuffer((PRAWINPUT)Buf, &Local, sizeof(RAWINPUTHEADER));
    Err = RtlGetLastWin32Error();
    if (Ret != (DWORD)-1) RtlSetLastWin32Error(Saved);

    if (Ret == (DWORD)-1)
    {
        Result = FAIL32;
        if (Err != ERROR_INSUFFICIENT_BUFFER) { Free(Buf); return FAIL32; }
        /* An exact native fit is copied and consumed while still reporting the size. */
        Count = Local == Initial ? 1 : 0;
    }
    else
    {
        Result = Ret;
        Count = Ret;
    }

    Status = STATUS_SUCCESS;
    _SEH2_TRY
    {
        if (Count && !RawRecordsOut(Buf, Initial, Count, a[0], Limit)) Ok = FALSE;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    Free(Buf);
    if (!Status && ((Ret == (DWORD)-1 && Local != 0) || (Ret != (DWORD)-1 && Local != Initial)))
        Status = GuestWrite32(a[1], Local >= sizeof(RAWINPUTHEADER) ? Local - (ULONG)HEADER_DELTA : 0);
    if (Status) { SetNtError(Status); return FAIL32; }
    if (!Ok) { RtlSetLastWin32Error(ERROR_INVALID_DATA); return FAIL32; }
    return Result;
}

static ULONG_PTR RawData32(ULONG *a)
{
    ULONG NativeSize, Guest = 0, Size32;
    UINT Local = 0;
    DWORD Ret;
    NTSTATUS Status;
    BYTE *Buf;
    HANDLE Raw = G(0);
    RAWINPUTHEADER Header;
    RAWINPUTHEADER32 Header32;

    if (a[4] != sizeof(RAWINPUTHEADER32)) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FAIL32; }
    /* Native rejects a bad handle, then a NULL size pointer, and only then looks at the command. */
    if (!a[3]) return NtUserGetRawInputData(Raw, a[1], NULL, NULL, sizeof(RAWINPUTHEADER));
    /* A NULL-buffer query validates the handle and command, and yields the native size. */
    Ret = NtUserGetRawInputData(Raw, a[1], NULL, &Local, sizeof(RAWINPUTHEADER));
    if (Ret == (DWORD)-1) return FAIL32;
    NativeSize = Local;
    if (NativeSize < sizeof(RAWINPUTHEADER)) { RtlSetLastWin32Error(ERROR_INVALID_DATA); return FAIL32; }
    Size32 = NativeSize - (ULONG)HEADER_DELTA;

    Status = GuestRead32(a[3], &Guest);
    if (!Status && !a[2]) Status = GuestWrite32(a[3], Size32);
    if (Status) { SetNtError(Status); return FAIL32; }
    if (!a[2]) return 0;
    if (Guest < Size32) { RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER); return FAIL32; }
    Status = Touch(a[2], Size32);
    if (Status) { SetNtError(Status); return FAIL32; }

    Buf = Alloc(NativeSize);
    if (!Buf) { RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY); return FAIL32; }
    Local = NativeSize;
    Ret = NtUserGetRawInputData(Raw, a[1], Buf, &Local, sizeof(RAWINPUTHEADER));
    if (Ret == (DWORD)-1) { Free(Buf); return FAIL32; }
    RtlCopyMemory(&Header, Buf, sizeof(Header));
    if (Ret != NativeSize || Header.dwSize < sizeof(Header) || (a[1] == RID_INPUT && Header.dwSize != NativeSize))
    { Free(Buf); RtlSetLastWin32Error(ERROR_INVALID_DATA); return FAIL32; }
    RawHeaderOut(&Header32, &Header);
    _SEH2_TRY
    {
        RtlCopyMemory(P(2), &Header32, sizeof(Header32));
        if (a[1] == RID_INPUT)
            RtlCopyMemory((BYTE *)P(2) + sizeof(Header32), Buf + sizeof(Header), NativeSize - sizeof(Header));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    Free(Buf);
    if (Status) { SetNtError(Status); return FAIL32; }
    return Size32;
}

static ULONG_PTR RawDeviceList32(ULONG *a)
{
    ULONG Try, Guest = 0, Count, Grown = 0, i;
    UINT Local;
    DWORD Ret;
    NTSTATUS Status;
    RAWINPUTDEVICELIST *Native;

    if (a[2] != sizeof(RAWINPUTDEVICELIST32)) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FAIL32; }
    if (!a[0]) return NtUserGetRawInputDeviceList(NULL, P(1), sizeof(RAWINPUTDEVICELIST));
    Status = GuestRead32(a[1], &Guest);
    if (Status) { SetNtError(Status); return FAIL32; }

    for (Try = 0; Try < RETRIES; ++Try)
    {
        Local = 0;
        Ret = NtUserGetRawInputDeviceList(NULL, &Local, sizeof(RAWINPUTDEVICELIST));
        if (Ret == (DWORD)-1) return FAIL32;
        Count = Local;
        if (Guest < Count)
        {
            Status = GuestWrite32(a[1], Count);
            if (Status) SetNtError(Status); else RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
            return FAIL32;
        }
        if (!Count) return 0;
        if (a[0] & 3) { SetNtError(STATUS_DATATYPE_MISALIGNMENT); return FAIL32; }
        Status = Touch(a[0], (ULONGLONG)Count * sizeof(RAWINPUTDEVICELIST32));
        if (Status) { SetNtError(Status); return FAIL32; }
        Native = Alloc((ULONGLONG)Count * sizeof(*Native));
        if (!Native) { RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY); return FAIL32; }
        Local = Count;
        Ret = NtUserGetRawInputDeviceList(Native, &Local, sizeof(RAWINPUTDEVICELIST));
        if (Ret != (DWORD)-1)
        {
            RAWINPUTDEVICELIST32 *Out = P(0);
            _SEH2_TRY
            {
                for (i = 0; i < min(Ret, Count); ++i)
                {
                    RAWINPUTDEVICELIST32 Item;
                    Item.hDevice = DeviceToken(Native[i].hDevice);
                    Item.dwType = Native[i].dwType;
                    RtlCopyMemory(&Out[i], &Item, sizeof(Item));
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
            _SEH2_END;
            Free(Native);
            if (Status) { SetNtError(Status); return FAIL32; }
            return Ret;
        }
        Free(Native);
        if (Local <= Count) return FAIL32;
        Grown = Local;
    }
    Status = GuestWrite32(a[1], Grown);
    if (Status) SetNtError(Status); else RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
    return FAIL32;
}

static ULONG_PTR RawDeviceInfo32(ULONG *a)
{
    ULONG Size = 0;
    UINT Local;
    DWORD Ret;
    NTSTATUS Status;

    /* RID_DEVICE_INFO and the name and preparsed buffers share one layout. The size is read once and the
     * native service gets a private copy, so the range bound below holds for what it writes. */
    Status = GuestRead32(a[3], &Size);
    if (Status) { SetNtError(Status); return FAIL32; }
    if (a[1] == RIDI_PREPARSEDDATA)
    {
        /* The blob is the hidparser collection context (sdk/lib/drivers/hidparser/context.c): every
         * HID_COLLECTION in it embeds three pointers ahead of its offset array (parser.h), so a 32-bit
         * hid.dll would misread the native layout. The guest buffer never reaches the service; size
         * queries, short buffers and probes keep the native order, and a copy of data is refused. */
        Local = 0;
        if (NtUserGetRawInputDeviceInfo(DeviceFromToken(a[0]), a[1], NULL, &Local) == (DWORD)-1) return FAIL32;
        if (!a[2] || Size < Local)
        {
            Status = GuestWrite32(a[3], Local);
            if (Status) { SetNtError(Status); return FAIL32; }
            if (!a[2]) return 0;
            RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
            return FAIL32;
        }
        if (!Local) return 0;
        Status = (a[2] & 3) ? STATUS_DATATYPE_MISALIGNMENT : Touch(a[2], Local);
        if (Status) { SetNtError(Status); return FAIL32; }
        RtlSetLastWin32Error(ERROR_NOT_SUPPORTED);
        return FAIL32;
    }
    if (a[2] && !GuestRange(a[2], a[1] == RIDI_DEVICENAME ? (ULONGLONG)Size * sizeof(WCHAR) : Size))
    { SetNtError(STATUS_ACCESS_VIOLATION); return FAIL32; }
    Local = Size;
    Ret = NtUserGetRawInputDeviceInfo(DeviceFromToken(a[0]), a[1], P(2), &Local);
    if (Local != Size || (!a[2] && Ret != (DWORD)-1))
    {
        Status = GuestWrite32(a[3], Local);
        if (Status) { SetNtError(Status); return FAIL32; }
    }
    return Ret;
}

static ULONG_PTR RawRegistered32(ULONG *a)
{
    ULONG Try, Guest = 0, Count, Grown = 0, i;
    UINT Local;
    DWORD Ret;
    NTSTATUS Status;
    RAWINPUTDEVICE *Native;

    if (a[2] != sizeof(RAWINPUTDEVICE32)) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FAIL32; }
    if (!a[0]) return NtUserGetRegisteredRawInputDevices(NULL, P(1), sizeof(RAWINPUTDEVICE));
    Status = GuestRead32(a[1], &Guest);
    if (Status) { SetNtError(Status); return FAIL32; }
    if (!Guest) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FAIL32; }
    /* Native probes the declared capacity before comparing it with the registered count. */
    if (a[0] & 3) { SetNtError(STATUS_DATATYPE_MISALIGNMENT); return FAIL32; }
    Status = Touch(a[0], (ULONGLONG)Guest * sizeof(RAWINPUTDEVICE32));
    if (Status) { SetNtError(Status); return FAIL32; }

    for (Try = 0; Try < RETRIES; ++Try)
    {
        Local = 0;
        Ret = NtUserGetRegisteredRawInputDevices(NULL, &Local, sizeof(RAWINPUTDEVICE));
        if (Ret == (DWORD)-1) return FAIL32;
        Count = Local;
        if (Guest < Count)
        {
            Status = GuestWrite32(a[1], Count);
            if (Status) SetNtError(Status); else RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
            return FAIL32;
        }
        if (!Count) return 0;
        Native = Alloc((ULONGLONG)Count * sizeof(*Native));
        if (!Native) { RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY); return FAIL32; }
        Local = Count;
        Ret = NtUserGetRegisteredRawInputDevices(Native, &Local, sizeof(RAWINPUTDEVICE));
        if (Ret != (DWORD)-1)
        {
            RAWINPUTDEVICE32 *Out = P(0);
            _SEH2_TRY
            {
                for (i = 0; i < min(Ret, Count); ++i)
                {
                    RAWINPUTDEVICE32 Item;
                    Item.usUsagePage = Native[i].usUsagePage; Item.usUsage = Native[i].usUsage;
                    Item.dwFlags = Native[i].dwFlags; Item.hwndTarget = HandleToUlong(Native[i].hwndTarget);
                    RtlCopyMemory(&Out[i], &Item, sizeof(Item));
                }
            }
            _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
            _SEH2_END;
            Free(Native);
            if (Status) { SetNtError(Status); return FAIL32; }
            return Ret;
        }
        Free(Native);
        if (Local <= Count) return FAIL32;
        Grown = Local;
    }
    Status = GuestWrite32(a[1], Grown);
    if (Status) SetNtError(Status); else RtlSetLastWin32Error(ERROR_INSUFFICIENT_BUFFER);
    return FAIL32;
}

static ULONG_PTR RawRegister32(ULONG *a)
{
    ULONG i;
    NTSTATUS Status = STATUS_SUCCESS;
    RAWINPUTDEVICE *Native;
    BOOL Ret;

    if (!a[0] || !a[1] || a[2] != sizeof(RAWINPUTDEVICE32) || a[1] > REGISTER_MAX)
    { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (a[0] & 3) { SetNtError(STATUS_DATATYPE_MISALIGNMENT); return FALSE; }
    if (!GuestRange(a[0], (ULONGLONG)a[1] * sizeof(RAWINPUTDEVICE32))) { SetNtError(STATUS_ACCESS_VIOLATION); return FALSE; }
    Native = Alloc((ULONGLONG)a[1] * sizeof(*Native));
    if (!Native) { RtlSetLastWin32Error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    _SEH2_TRY
    {
        const RAWINPUTDEVICE32 *Guest = P(0);
        for (i = 0; i < a[1]; ++i)
        {
            RAWINPUTDEVICE32 Item;
            RtlCopyMemory(&Item, &Guest[i], sizeof(Item));
            Native[i].usUsagePage = Item.usUsagePage; Native[i].usUsage = Item.usUsage;
            Native[i].dwFlags = Item.dwFlags; Native[i].hwndTarget = H32(Item.hwndTarget);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    if (Status) { Free(Native); SetNtError(Status); return FALSE; }
    Ret = NtUserRegisterRawInputDevices(Native, a[1], sizeof(RAWINPUTDEVICE));
    Free(Native);
    return Ret;
}

static ULONG_PTR MouseMove32(ULONG *a)
{
    /* Outside every screen and high-resolution coordinate range: a history point equals it only if a
     * caller injects this exact relative move, time and extra info, and then just that point is not copied. */
    static const MOUSEMOVEPOINT Unfilled = { MINLONG, MINLONG, MAXULONG, MAXULONG_PTR };
    MOUSEMOVEPOINT In, Out[MOUSEMOVE_MAX];
    MOUSEMOVEPOINT32 Item;
    const MOUSEMOVEPOINT32 *GuestIn = P(1), *GuestOut = P(2);
    INT n = (INT)a[3], i;
    DWORD Ret;
    NTSTATUS Status = STATUS_SUCCESS;

    if (a[0] != sizeof(MOUSEMOVEPOINT32) || n < 0 || n > MOUSEMOVE_MAX) { RtlSetLastWin32Error(ERROR_INVALID_PARAMETER); return FAIL32; }
    if (!a[1] || (!a[2] && n)) { RtlSetLastWin32Error(ERROR_NOACCESS); return FAIL32; }
    if (!GuestRange(a[1], sizeof(MOUSEMOVEPOINT32)) || (n && !GuestRange(a[2], (ULONGLONG)n * sizeof(MOUSEMOVEPOINT32))))
    { SetNtError(STATUS_ACCESS_VIOLATION); return FAIL32; }

    RtlZeroMemory(&In, sizeof(In));
    _SEH2_TRY
    {
        RtlCopyMemory(&Item, GuestIn, sizeof(Item));
        In.x = Item.x; In.y = Item.y; In.time = Item.time; In.dwExtraInfo = Item.dwExtraInfo;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
    _SEH2_END;
    if (Status) { SetNtError(Status); return FAIL32; }
    /* Native probes one element for write in display-point mode and writes none. */
    if (n && a[4] == GMMP_USE_DISPLAY_POINTS)
    {
        Status = Touch(a[2], sizeof(MOUSEMOVEPOINT32));
        if (Status) { SetNtError(Status); return FAIL32; }
    }
    /* Native writes only the points it fills, and this kernel fills none. Copy back exactly the entries the
     * kernel changed, an all-zero point included; the guest buffer is never read, as native never reads it. */
    for (i = 0; i < n; ++i) RtlCopyMemory(&Out[i], &Unfilled, sizeof(Unfilled));

    Ret = NtUserGetMouseMovePointsEx(sizeof(MOUSEMOVEPOINT), &In, n ? Out : NULL, n, a[4]);
    if ((INT)Ret > 0 && n)
    {
        _SEH2_TRY
        {
            for (i = 0; i < min((INT)Ret, n); ++i)
            {
                if (RtlCompareMemory(&Out[i], &Unfilled, sizeof(Out[i])) == sizeof(Out[i])) continue;
                Item.x = Out[i].x; Item.y = Out[i].y; Item.time = Out[i].time; Item.dwExtraInfo = (ULONG)Out[i].dwExtraInfo;
                RtlCopyMemory((PVOID)&GuestOut[i], &Item, sizeof(Item));
            }
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) { Status = _SEH2_GetExceptionCode(); }
        _SEH2_END;
        if (Status) { SetNtError(Status); return FAIL32; }
    }
    return Ret;
}

static ULONG ArgumentCount(ULONG Number)
{
    switch (Number)
    {
    case W64_NtUserSendInput: case W64_NtUserGetRawInputBuffer: case W64_NtUserGetRawInputDeviceList:
    case W64_NtUserGetRegisteredRawInputDevices: case W64_NtUserRegisterRawInputDevices:
        return 3;
    case W64_NtUserGetRawInputDeviceInfo: return 4;
    case W64_NtUserGetRawInputData: case W64_NtUserGetMouseMovePointsEx: return 5;
    default: return 0;
    }
}

ULONG_PTR Wow64WinUserInputService(ULONG Number, ULONG *Guest)
{
    ULONG a[5], Count = ArgumentCount(Number), i;

    if (!Count) return Wow64WinUserImeService(Number, Guest);
    if ((ULONGLONG)(ULONG_PTR)Guest + Count * sizeof(ULONG) > 0x100000000ULL)
    {
        SetNtError(STATUS_ACCESS_VIOLATION);
        return Number == W64_NtUserSendInput || Number == W64_NtUserRegisterRawInputDevices ? 0 : FAIL32;
    }
    /* Another guest thread can rewrite the argument words while a service runs. */
    for (i = 0; i < Count; ++i) a[i] = ((const volatile ULONG *)Guest)[i];
    switch (Number)
    {
    case W64_NtUserSendInput: return SendInput32(a);
    case W64_NtUserGetRawInputBuffer: return RawBuffer32(a);
    case W64_NtUserGetRawInputData: return RawData32(a);
    case W64_NtUserGetRawInputDeviceInfo: return RawDeviceInfo32(a);
    case W64_NtUserGetRawInputDeviceList: return RawDeviceList32(a);
    case W64_NtUserGetRegisteredRawInputDevices: return RawRegistered32(a);
    case W64_NtUserRegisterRawInputDevices: return RawRegister32(a);
    default: return MouseMove32(a);
    }
}
