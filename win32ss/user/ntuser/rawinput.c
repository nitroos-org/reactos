/*
 * PROJECT:     ReactOS Win32k subsystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Functions related to Raw Input handling
 * COPYRIGHT:   Copyright 2026 Hervé Poussineau
 */

#include <win32k.h>
#define NDEBUG
#include <debug.h>

#ifndef HID_USAGE_PAGE_GENERIC
#define HID_USAGE_PAGE_GENERIC      0x01
#endif

#ifndef HID_USAGE_GENERIC_MOUSE
#define HID_USAGE_GENERIC_MOUSE     0x02
#endif

#ifndef HID_USAGE_GENERIC_KEYBOARD
#define HID_USAGE_GENERIC_KEYBOARD  0x06
#endif

typedef struct _USER_RAWINPUT
{
    LIST_ENTRY ListEntry;
    HRAWINPUT Handle;
    RAWINPUT RawInput;
} USER_RAWINPUT, *PUSER_RAWINPUT;

/* Handles are serial numbers, not addresses: a freed packet's memory is reused at once,
   and an old handle must not read the packet that took its place */
static ULONG gRawInputSerial;

C_ASSERT(FIELD_OFFSET(RAWINPUT, data) == sizeof(RAWINPUTHEADER));
C_ASSERT(sizeof(RAWINPUTHEADER) + sizeof(RAWMOUSE) <= sizeof(RAWINPUT));
C_ASSERT(sizeof(RAWINPUTHEADER) + sizeof(RAWKEYBOARD) <= sizeof(RAWINPUT));

#define MAX_RAWINPUT_PER_QUEUE 256

static PAGED_LOOKASIDE_LIST gRawInputLookasideList;
BOOLEAN RawInputEnabled = FALSE;

#ifndef WM_INPUT_DEVICE_CHANGE
#define WM_INPUT_DEVICE_CHANGE 0x00FE
#endif

#ifndef MOUSEEVENTF_MOVE_NOCOALESCE
#define MOUSEEVENTF_MOVE_NOCOALESCE 0x2000
#endif

#ifndef MOUSE_MOVE_NOCOALESCE
#define MOUSE_MOVE_NOCOALESCE 0x08
#endif

#ifndef MOUSEEVENTF_HWHEEL
#define MOUSEEVENTF_HWHEEL 0x1000
#endif

#ifndef RI_MOUSE_HWHEEL
#define RI_MOUSE_HWHEEL 0x0800
#endif

#define RIDEV_CLASS_MASK (RIDEV_EXCLUDE | RIDEV_PAGEONLY)

/* Registrations of one process, kept sorted by usage page and usage; owned
   by the process and protected by the USER lock */
typedef struct _RAWINPUT_REG
{
    RAWINPUTDEVICE Device;
    PTHREADINFO ptiTarget; /* thread of the target window when it was registered */
} RAWINPUT_REG;

struct _RAWINPUT_REGTABLE
{
    UINT cRegs;
    RAWINPUT_REG aRegs[ANYSIZE_ARRAY];
};

DWORD
APIENTRY
NtUserGetRawInputDeviceInfo(
    _In_opt_ HANDLE hDevice,
    _In_ UINT uiCommand,
    _Inout_opt_ LPVOID pData,
    _Inout_ PUINT pcbSize)
{
    PINPUT_DEVICE_INFO DeviceInfo;
    UINT cbSize, cbRequiredSize;
    UINT Ret = (UINT)-1;

    _SEH2_TRY
    {
        ProbeForRead(pcbSize, sizeof(*pcbSize), sizeof(DWORD));
        cbSize = *pcbSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        _SEH2_YIELD(return Ret);
    }
    _SEH2_END;

    AcquireDeviceInfoListMutex();
    for (DeviceInfo = gpInputDeviceInfo; DeviceInfo && DeviceInfo->hRawDevice != hDevice; DeviceInfo = DeviceInfo->pNextDeviceInfo)
        ;
    if (!DeviceInfo)
    {
        ReleaseDeviceInfoListMutex();
        EngSetLastError(ERROR_INVALID_HANDLE);
        return Ret;
    }

    UserEnterShared();

    switch (uiCommand)
    {
        case RIDI_PREPARSEDDATA:
            if (DeviceInfo->DeviceType == RIM_TYPEHID)
                cbRequiredSize = DeviceInfo->Hid.CollectionInformation.DescriptorSize;
            else
                cbRequiredSize = 0;
            break;
        case RIDI_DEVICENAME:
            cbRequiredSize = DeviceInfo->DeviceName.Length / sizeof(WCHAR) + sizeof(ANSI_NULL);
            break;
        case RIDI_DEVICEINFO:
            cbRequiredSize = sizeof(RID_DEVICE_INFO);
            break;
        default:
            EngSetLastError(ERROR_INVALID_PARAMETER);
            goto cleanup;
    }

    _SEH2_TRY
    {
        if (!pData)
        {
            ProbeForWrite(pcbSize, sizeof(*pcbSize), sizeof(DWORD));
            *pcbSize = cbRequiredSize;
            Ret = 0;
            _SEH2_LEAVE;
        }

        if (cbSize < cbRequiredSize)
        {
            ProbeForWrite(pcbSize, sizeof(*pcbSize), sizeof(DWORD));
            *pcbSize = cbRequiredSize;
            EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
            _SEH2_LEAVE;
        }

        ProbeForWrite(pData, cbRequiredSize, sizeof(DWORD));
        switch (uiCommand)
        {
            case RIDI_PREPARSEDDATA:
                if (DeviceInfo->DeviceType == RIM_TYPEHID)
                    RtlCopyMemory(pData, DeviceInfo->Hid.PreparsedData, cbRequiredSize);
                break;
            case RIDI_DEVICENAME:
                // As cbSize/cbRequiredSize are in chars, we didn't probe a big enough buffer
                // Do it again
                ProbeForWrite(pData, DeviceInfo->DeviceName.Length + sizeof(UNICODE_NULL), sizeof(DWORD));
                RtlCopyMemory(pData, DeviceInfo->DeviceName.Buffer, DeviceInfo->DeviceName.Length);
                ((WCHAR*)pData)[cbRequiredSize - 1] = UNICODE_NULL;
                break;
            case RIDI_DEVICEINFO:
            {
                PRID_DEVICE_INFO prdi = pData;
                ProbeForRead(&prdi->cbSize, sizeof(prdi->cbSize), sizeof(DWORD));
                if (prdi->cbSize != cbRequiredSize)
                {
                    EngSetLastError(ERROR_INVALID_PARAMETER);
                    _SEH2_YIELD(break);
                }

                ProbeForWrite(prdi, sizeof(*prdi), sizeof(DWORD));
                RtlZeroMemory(prdi, sizeof(*prdi));
                prdi->cbSize = sizeof(*prdi);
                prdi->dwType = DeviceInfo->DeviceType;

                switch (DeviceInfo->DeviceType)
                {
                    case RIM_TYPEMOUSE:
                        prdi->mouse.dwId = DeviceInfo->Mouse.Attributes.MouseIdentifier & ~HORIZONTAL_WHEEL_PRESENT;
                        prdi->mouse.dwNumberOfButtons = DeviceInfo->Mouse.Attributes.NumberOfButtons;
                        prdi->mouse.dwSampleRate = DeviceInfo->Mouse.Attributes.SampleRate;
                        prdi->mouse.fHasHorizontalWheel = !!(DeviceInfo->Mouse.Attributes.MouseIdentifier & HORIZONTAL_WHEEL_PRESENT);
                        break;

                    case RIM_TYPEKEYBOARD:
                        prdi->keyboard.dwType = DeviceInfo->Keyboard.Attributes.KeyboardIdentifier.Type;
                        prdi->keyboard.dwSubType = DeviceInfo->Keyboard.Attributes.KeyboardIdentifier.Subtype;
                        prdi->keyboard.dwKeyboardMode = DeviceInfo->Keyboard.Attributes.KeyboardMode;
                        prdi->keyboard.dwNumberOfFunctionKeys = DeviceInfo->Keyboard.Attributes.NumberOfFunctionKeys;
                        prdi->keyboard.dwNumberOfIndicators = DeviceInfo->Keyboard.Attributes.NumberOfIndicators;
                        prdi->keyboard.dwNumberOfKeysTotal = DeviceInfo->Keyboard.Attributes.NumberOfKeysTotal;
                        break;

                    case RIM_TYPEHID:
                        prdi->hid.dwVendorId = DeviceInfo->Hid.CollectionInformation.VendorID;
                        prdi->hid.dwProductId = DeviceInfo->Hid.CollectionInformation.ProductID;
                        prdi->hid.dwVersionNumber = DeviceInfo->Hid.CollectionInformation.VersionNumber;
                        prdi->hid.usUsagePage = DeviceInfo->Hid.Caps.UsagePage;
                        prdi->hid.usUsage = DeviceInfo->Hid.Caps.Usage;
                        break;

                    default:
                        break;
                }
                break;
            }
            default:
                ASSERT(FALSE);
                break;
        }
        Ret = cbRequiredSize;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
    }
    _SEH2_END;

cleanup:
    UserLeave();
    ReleaseDeviceInfoListMutex();
    return Ret;
}



static
DWORD
RawInputUsageFromType(
    DWORD dwType)
{
    switch (dwType)
    {
        case RIM_TYPEMOUSE:
            return HID_USAGE_GENERIC_MOUSE;

        case RIM_TYPEKEYBOARD:
            return HID_USAGE_GENERIC_KEYBOARD;

        default:
            return 0;
    }
}

static
BOOL
RawRegIsPageEntry(
    const RAWINPUTDEVICE *Reg)
{
    return (Reg->dwFlags & RIDEV_CLASS_MASK) == RIDEV_PAGEONLY;
}

/* Registration that applies to a top level collection, NULL if none or excluded */
static
const RAWINPUTDEVICE *
RawRegLookup(
    PRAWINPUT_REGTABLE Table,
    USHORT usUsagePage,
    USHORT usUsage)
{
    const RAWINPUTDEVICE *PageReg = NULL;
    UINT i;

    if (!Table)
        return NULL;

    for (i = 0; i < Table->cRegs; i++)
    {
        const RAWINPUTDEVICE *Reg = &Table->aRegs[i].Device;

        if (Reg->usUsagePage != usUsagePage)
            continue;

        if (RawRegIsPageEntry(Reg))
        {
            PageReg = Reg;
        }
        else if (Reg->usUsage == usUsage)
        {
            if ((Reg->dwFlags & RIDEV_CLASS_MASK) == RIDEV_EXCLUDE)
                return NULL;
            return Reg;
        }
    }

    return PageReg;
}

static
const RAWINPUTDEVICE *
RawRegLookupType(
    PRAWINPUT_REGTABLE Table,
    DWORD dwType)
{
    DWORD Usage = RawInputUsageFromType(dwType);

    if (!Usage)
        return NULL;

    return RawRegLookup(Table, HID_USAGE_PAGE_GENERIC, (USHORT)Usage);
}

static
VOID
RawInputUpdateEnabled(VOID)
{
    PPROCESSINFO ppi;
    BOOLEAN Enabled = FALSE;

    for (ppi = gppiList; ppi && !Enabled; ppi = ppi->ppiNext)
    {
        Enabled = RawRegLookupType(ppi->pRawInputRegs, RIM_TYPEMOUSE) ||
                  RawRegLookupType(ppi->pRawInputRegs, RIM_TYPEKEYBOARD);
    }

    RawInputEnabled = Enabled;
}

static
INT
RawRegCompare(
    const RAWINPUTDEVICE *a,
    const RAWINPUTDEVICE *b)
{
    if (a->usUsagePage != b->usUsagePage)
        return a->usUsagePage < b->usUsagePage ? -1 : 1;
    if (a->usUsage != b->usUsage)
        return a->usUsage < b->usUsage ? -1 : 1;
    return 0;
}

static
PRAWINPUT_REGTABLE
RawRegAlloc(
    UINT cRegs)
{
    PRAWINPUT_REGTABLE Table;

    Table = ExAllocatePoolWithTag(PagedPool,
                                  FIELD_OFFSET(RAWINPUT_REGTABLE, aRegs[cRegs ? cRegs : 1]),
                                  'iwar');
    if (Table)
    {
        Table->cRegs = cRegs;
        if (cRegs)
            RtlZeroMemory(Table->aRegs, cRegs * sizeof(Table->aRegs[0]));
    }
    return Table;
}

/* Sets (or with Remove clears) one registration. Adding copies the table first so a
   failed allocation leaves the old table untouched; removing works in place. */
static
BOOL
RawRegApply(
    PPROCESSINFO ppi,
    const RAWINPUTDEVICE *Device,
    PTHREADINFO ptiTarget,
    BOOL Remove)
{
    PRAWINPUT_REGTABLE Old = ppi->pRawInputRegs, New;
    RAWINPUTDEVICE Entry = *Device;
    UINT i, Pos, cOld = Old ? Old->cRegs : 0;
    BOOL Found = FALSE;

    /* Windows keeps neither the notification nor the 0x800 bit, and the extended sink wins */
    Entry.dwFlags &= ~(RIDEV_DEVNOTIFY | 0x800);
    if (Entry.dwFlags & RIDEV_EXINPUTSINK)
        Entry.dwFlags &= ~RIDEV_INPUTSINK;

    for (Pos = 0; Pos < cOld; Pos++)
    {
        INT Cmp = RawRegCompare(&Old->aRegs[Pos].Device, &Entry);

        if (Cmp == 0)
        {
            Found = TRUE;
            break;
        }
        if (Cmp > 0)
            break;
    }

    if (Remove)
    {
        if (!Found)
            return TRUE;

        if (cOld == 1)
        {
            ppi->pRawInputRegs = NULL;
            ExFreePoolWithTag(Old, 'iwar');
            return TRUE;
        }

        /* Removal never allocates: it cannot fail, so a thread exit or a REMOVE always
           drops the registration (and a NOLEGACY with it) */
        for (i = Pos + 1; i < cOld; i++)
            Old->aRegs[i - 1] = Old->aRegs[i];
        Old->cRegs--;
        return TRUE;
    }
    else if (Found)
    {
        Old->aRegs[Pos].Device = Entry;
        Old->aRegs[Pos].ptiTarget = ptiTarget;
        return TRUE;
    }
    else
    {
        New = RawRegAlloc(cOld + 1);
        if (!New)
            return FALSE;
        for (i = 0; i < Pos; i++)
            New->aRegs[i] = Old->aRegs[i];
        New->aRegs[Pos].Device = Entry;
        New->aRegs[Pos].ptiTarget = ptiTarget;
        for (i = Pos; i < cOld; i++)
            New->aRegs[i + 1] = Old->aRegs[i];
    }

    ppi->pRawInputRegs = New;
    if (Old)
        ExFreePoolWithTag(Old, 'iwar');
    return TRUE;
}

VOID
FASTCALL
UserRawInputProcessDestroy(
    PPROCESSINFO ppi)
{
    if (ppi->pRawInputRegs)
    {
        ExFreePoolWithTag(ppi->pRawInputRegs, 'iwar');
        ppi->pRawInputRegs = NULL;
    }
    RawInputUpdateEnabled();
}

/* Windows drops the registrations aimed at the windows of a thread when the thread exits */
VOID
FASTCALL
UserRawInputThreadCleanup(
    PTHREADINFO pti)
{
    PPROCESSINFO ppi = pti->ppi;
    PRAWINPUT_REGTABLE Table = ppi->pRawInputRegs;
    UINT i = 0;

    while (Table && i < Table->cRegs)
    {
        if (Table->aRegs[i].ptiTarget == pti)
        {
            RAWINPUTDEVICE Entry = Table->aRegs[i].Device;

            RawRegApply(ppi, &Entry, NULL, TRUE);
            Table = ppi->pRawInputRegs;
            continue;
        }
        i++;
    }

    RawInputUpdateEnabled();
}

BOOL
FASTCALL
UserRawInputNoLegacy(
    PPROCESSINFO ppi,
    DWORD dwType)
{
    const RAWINPUTDEVICE *Reg;

    if (!RawInputEnabled || !ppi)
        return FALSE;

    Reg = RawRegLookupType(ppi->pRawInputRegs, dwType);
    return Reg && (Reg->dwFlags & RIDEV_CLASS_MASK) == RIDEV_NOLEGACY;
}

static
PUSER_RAWINPUT
RawInputEntryFromHandle(
    PUSER_MESSAGE_QUEUE MessageQueue,
    HRAWINPUT hRawInput)
{
    PLIST_ENTRY Entry;

    if (!MessageQueue || !hRawInput)
        return NULL;

    for (Entry = MessageQueue->RawInputListHead.Flink;
         Entry != &MessageQueue->RawInputListHead;
         Entry = Entry->Flink)
    {
        PUSER_RAWINPUT RawEntry = CONTAINING_RECORD(Entry, USER_RAWINPUT, ListEntry);
        if (RawEntry->Handle == hRawInput)
            return RawEntry;
    }

    return NULL;
}

static
VOID
RawInputFreeEntry(
    PUSER_MESSAGE_QUEUE MessageQueue,
    PUSER_RAWINPUT RawEntry)
{
    ASSERT(MessageQueue->cRawInput > 0);
    RemoveEntryList(&RawEntry->ListEntry);
    MessageQueue->cRawInput--;
    ExFreeToPagedLookasideList(&gRawInputLookasideList, RawEntry);
}

CODE_SEG("INIT")
NTSTATUS
NTAPI
InitRawInputImpl(VOID)
{
    ExInitializePagedLookasideList(&gRawInputLookasideList,
                                   NULL,
                                   NULL,
                                   0,
                                   sizeof(USER_RAWINPUT),
                                   'iwar',
                                   256);
    return STATUS_SUCCESS;
}

#if DBG
ULONG
FASTCALL
UserRawInputSetSerial(
    ULONG Serial)
{
    ULONG Old = gRawInputSerial;

    gRawInputSerial = Serial;
    return Old;
}
#endif

HRAWINPUT
FASTCALL
UserCreateRawInput(
    PTHREADINFO pti,
    DWORD dwType,
    HANDLE hDevice,
    WPARAM wParam,
    CONST VOID *pData,
    UINT cbData)
{
    PUSER_RAWINPUT RawEntry;

    if (!pti || !pti->MessageQueue || !pData)
        return NULL;

    ASSERT(cbData <= sizeof(RawEntry->RawInput.data));
    if (cbData > sizeof(RawEntry->RawInput.data))
        return NULL;

    if (pti->MessageQueue->cRawInput >= MAX_RAWINPUT_PER_QUEUE)
    {
        DPRINT("Dropping raw input, queue %p is not being pumped\n", pti->MessageQueue);
        return NULL;
    }

    RawEntry = ExAllocateFromPagedLookasideList(&gRawInputLookasideList);
    if (!RawEntry)
        return NULL;

    RtlZeroMemory(RawEntry, sizeof(*RawEntry));
    RawEntry->RawInput.header.dwType = dwType;
    RawEntry->RawInput.header.dwSize = sizeof(RAWINPUTHEADER) + cbData;
    RawEntry->RawInput.header.hDevice = hDevice;
    RawEntry->RawInput.header.wParam = wParam;
    RtlCopyMemory(&RawEntry->RawInput.data, pData, cbData);

    /* The serial space wraps: a handle that is still live in the queue is skipped */
    do
    {
        do
        {
            ++gRawInputSerial;
        } while ((gRawInputSerial & 0x3FFFFFFF) == 0);
        RawEntry->Handle = (HRAWINPUT)(ULONG_PTR)(((gRawInputSerial & 0x3FFFFFFF) << 2) | 1);
    } while (RawInputEntryFromHandle(pti->MessageQueue, RawEntry->Handle));

    InsertTailList(&pti->MessageQueue->RawInputListHead, &RawEntry->ListEntry);
    pti->MessageQueue->cRawInput++;
    return RawEntry->Handle;
}

BOOL
FASTCALL
UserFreeRawInput(
    PUSER_MESSAGE_QUEUE MessageQueue,
    HRAWINPUT hRawInput)
{
    PUSER_RAWINPUT RawEntry = RawInputEntryFromHandle(MessageQueue, hRawInput);

    if (!RawEntry)
        return FALSE;

    RawInputFreeEntry(MessageQueue, RawEntry);
    return TRUE;
}

VOID
FASTCALL
UserUpdatePrevRawInput(
    PTHREADINFO pti,
    CONST MSG *pMsg)
{
    if (pti->hPrevRawInput)
    {
        UserFreeRawInput(pti->MessageQueue, pti->hPrevRawInput);
        pti->hPrevRawInput = NULL;
    }

    if (pMsg->message == WM_INPUT &&
        (pMsg->wParam == RIM_INPUT || pMsg->wParam == RIM_INPUTSINK))
    {
        pti->hPrevRawInput = (HRAWINPUT)pMsg->lParam;
    }
}

VOID
FASTCALL
UserCleanupRawInput(
    PUSER_MESSAGE_QUEUE MessageQueue)
{
    while (!IsListEmpty(&MessageQueue->RawInputListHead))
    {
        PUSER_RAWINPUT RawEntry;
        RawEntry = CONTAINING_RECORD(MessageQueue->RawInputListHead.Flink,
                                     USER_RAWINPUT,
                                     ListEntry);
        RawInputFreeEntry(MessageQueue, RawEntry);
    }
}

/* Process that owns the focus (else the active) window of the foreground queue; the
   thread recorded in the queue at its creation is not the owner once threads attach */
static
PPROCESSINFO
RawInputFocusProcess(
    PUSER_MESSAGE_QUEUE pFocusQueue)
{
    PWND pWnd;

    if (!pFocusQueue)
        return NULL;

    pWnd = pFocusQueue->spwndFocus ? pFocusQueue->spwndFocus : pFocusQueue->spwndActive;
    if (pWnd && pWnd->head.pti)
        return pWnd->head.pti->ppi;

    return pFocusQueue->ptiKeyboard ? pFocusQueue->ptiKeyboard->ppi : NULL;
}

/* NOLEGACY for the keys that the focus queue posts on its own (Alt+Numpad characters) */
BOOL
FASTCALL
UserRawInputQueueNoLegacy(
    PUSER_MESSAGE_QUEUE pFocusQueue,
    DWORD dwType)
{
    return UserRawInputNoLegacy(RawInputFocusProcess(pFocusQueue), dwType);
}

/* Window that receives the raw input of one process, NULL if it gets none now */
static
PWND
RawInputFindTarget(
    PPROCESSINFO ppi,
    const RAWINPUTDEVICE *Reg,
    PUSER_MESSAGE_QUEUE pFocusQueue)
{
    PWND pWnd;

    if (Reg->hwndTarget)
    {
        pWnd = UserGetWindowObject(Reg->hwndTarget);
    }
    else
    {
        if (!pFocusQueue)
            return NULL;
        pWnd = pFocusQueue->spwndFocus;
        if (!pWnd)
            pWnd = pFocusQueue->spwndActive;
    }

    if (!pWnd || !pWnd->head.pti || pWnd->head.pti->ppi != ppi)
        return NULL;

    return pWnd;
}

VOID
FASTCALL
UserRawInputDeliver(
    DWORD dwType,
    HANDLE hDevice,
    CONST VOID *pData,
    UINT cbData)
{
    PUSER_MESSAGE_QUEUE pFocusQueue;
    PPROCESSINFO ppi, ppiFocus = NULL;

    if (!RawInputEnabled)
        return;

    pFocusQueue = IntGetFocusMessageQueue();
    ppiFocus = RawInputFocusProcess(pFocusQueue);

    for (ppi = gppiList; ppi; ppi = ppi->ppiNext)
    {
        const RAWINPUTDEVICE *Reg;
        PTHREADINFO pti;
        PWND pWnd;
        WPARAM wParam;
        HRAWINPUT hRawInput;
        MSG Msg = {0};

        if ((ppi->W32PF_flags & W32PF_TERMINATED) || !ppi->pRawInputRegs)
            continue;

        Reg = RawRegLookupType(ppi->pRawInputRegs, dwType);
        if (!Reg)
            continue;

        pWnd = RawInputFindTarget(ppi, Reg, pFocusQueue);
        if (!pWnd)
            continue;

        pti = pWnd->head.pti;
        if (Reg->dwFlags & RIDEV_INPUTSINK)
        {
            /* Sinks only reach windows of the input desktop */
            if (!pti->rpdesk || !IntIsActiveDesktop(pti->rpdesk))
                continue;
            wParam = (ppi == ppiFocus) ? RIM_INPUT : RIM_INPUTSINK;
        }
        else if (ppi == ppiFocus)
        {
            /* The foreground process gets it at the registered window, whatever thread owns that */
            wParam = RIM_INPUT;
        }
        else if (Reg->dwFlags & RIDEV_EXINPUTSINK)
        {
            /* Sinks of any kind only reach windows of the input desktop: nothing may
               listen to the keys typed on another one (the secure desktop) */
            if (!pti->rpdesk || !IntIsActiveDesktop(pti->rpdesk))
                continue;
            /* Background delivery only while the foreground process gets none */
            if (ppiFocus && RawRegLookupType(ppiFocus->pRawInputRegs, dwType))
                continue;
            wParam = RIM_INPUTSINK;
        }
        else
        {
            continue;
        }

        hRawInput = UserCreateRawInput(pti, dwType, hDevice, wParam, pData, cbData);
        if (!hRawInput)
            continue;

        Msg.hwnd = UserHMGetHandle(pWnd);
        Msg.message = WM_INPUT;
        Msg.wParam = wParam;
        Msg.lParam = (LPARAM)hRawInput;
        Msg.time = EngGetTickCount32();
        Msg.pt = gpsi->ptCursor;

        if (!MsqPostMessage(pti, &Msg, TRUE, QS_RAWINPUT, 0, 0))
            UserFreeRawInput(pti->MessageQueue, hRawInput);
    }
}

VOID
FASTCALL
UserRawInputSendMouse(
    MOUSEINPUT *pmi)
{
    RAWMOUSE rm = {0};
    DWORD dwFlags = UserStripMouseDataFlags(pmi->dwFlags);

    if (!RawInputEnabled)
        return;

    if (dwFlags & MOUSEEVENTF_MOVE)
    {
        if (dwFlags & MOUSEEVENTF_ABSOLUTE)
            rm.usFlags |= MOUSE_MOVE_ABSOLUTE;
        if (dwFlags & MOUSEEVENTF_VIRTUALDESK)
            rm.usFlags |= MOUSE_VIRTUAL_DESKTOP;
        if (dwFlags & MOUSEEVENTF_MOVE_NOCOALESCE)
            rm.usFlags |= MOUSE_MOVE_NOCOALESCE;
        rm.lLastX = pmi->dx;
        rm.lLastY = pmi->dy;
    }

    if (dwFlags & MOUSEEVENTF_LEFTDOWN)   rm.usButtonFlags |= RI_MOUSE_LEFT_BUTTON_DOWN;
    if (dwFlags & MOUSEEVENTF_LEFTUP)     rm.usButtonFlags |= RI_MOUSE_LEFT_BUTTON_UP;
    if (dwFlags & MOUSEEVENTF_RIGHTDOWN)  rm.usButtonFlags |= RI_MOUSE_RIGHT_BUTTON_DOWN;
    if (dwFlags & MOUSEEVENTF_RIGHTUP)    rm.usButtonFlags |= RI_MOUSE_RIGHT_BUTTON_UP;
    if (dwFlags & MOUSEEVENTF_MIDDLEDOWN) rm.usButtonFlags |= RI_MOUSE_MIDDLE_BUTTON_DOWN;
    if (dwFlags & MOUSEEVENTF_MIDDLEUP)   rm.usButtonFlags |= RI_MOUSE_MIDDLE_BUTTON_UP;
    if (dwFlags & MOUSEEVENTF_XDOWN)
    {
        if (pmi->mouseData & XBUTTON1) rm.usButtonFlags |= RI_MOUSE_BUTTON_4_DOWN;
        if (pmi->mouseData & XBUTTON2) rm.usButtonFlags |= RI_MOUSE_BUTTON_5_DOWN;
    }
    if (dwFlags & MOUSEEVENTF_XUP)
    {
        if (pmi->mouseData & XBUTTON1) rm.usButtonFlags |= RI_MOUSE_BUTTON_4_UP;
        if (pmi->mouseData & XBUTTON2) rm.usButtonFlags |= RI_MOUSE_BUTTON_5_UP;
    }
    /* A wheel of distance zero still makes a raw record, the legacy message is not posted */
    if (dwFlags & MOUSEEVENTF_WHEEL)
    {
        rm.usButtonFlags |= RI_MOUSE_WHEEL;
        rm.usButtonData = (USHORT)UserClampWheelDelta(pmi->mouseData);
    }
    if (dwFlags & MOUSEEVENTF_HWHEEL)
    {
        rm.usButtonFlags |= RI_MOUSE_HWHEEL;
        rm.usButtonData = (USHORT)UserClampWheelDelta(pmi->mouseData);
    }
    rm.ulExtraInformation = (ULONG)pmi->dwExtraInfo;

    UserRawInputDeliver(RIM_TYPEMOUSE, NULL, &rm, sizeof(rm));
}

VOID
FASTCALL
UserRawInputSendKeyboard(
    WORD wScan,
    WORD wVk,
    BOOL bUp,
    BOOL bExt,
    ULONG_PTR dwExtraInfo,
    UINT Message)
{
    RAWKEYBOARD kb = {0};

    if (!RawInputEnabled)
        return;

    kb.MakeCode = wScan & 0x7F;
    kb.Flags = bUp ? RI_KEY_BREAK : RI_KEY_MAKE;
    if (bExt)
        kb.Flags |= RI_KEY_E0;
    kb.VKey = wVk & 0xFF;
    kb.Message = Message;
    kb.ExtraInformation = (ULONG)dwExtraInfo;

    UserRawInputDeliver(RIM_TYPEKEYBOARD, NULL, &kb, sizeof(kb));
}

static
DWORD
RawInputCopyData(
    PRAWINPUT RawInput,
    UINT uiCommand,
    LPVOID pData,
    PUINT pcbSize)
{
    UINT OutputDataSize, cbSize;
    DWORD Ret = ~0u;

    switch (uiCommand)
    {
        case RID_INPUT:
            OutputDataSize = RawInput->header.dwSize;
            break;

        case RID_HEADER:
            OutputDataSize = sizeof(RAWINPUTHEADER);
            break;

        default:
            EngSetLastError(ERROR_INVALID_PARAMETER);
            return ~0u;
    }

    _SEH2_TRY
    {
        ProbeForRead(pcbSize, sizeof(*pcbSize), sizeof(UINT));
        cbSize = *pcbSize;

        if (!pData)
        {
            ProbeForWrite(pcbSize, sizeof(*pcbSize), sizeof(UINT));
            *pcbSize = OutputDataSize;
            Ret = 0;
        }
        else if (cbSize < OutputDataSize)
        {
            /* Windows leaves the size alone here; only a NULL buffer asks for it */
            EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        else
        {
            ProbeForWrite(pData, OutputDataSize, 1);
            RtlCopyMemory(pData, RawInput, OutputDataSize);
            Ret = OutputDataSize;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        Ret = ~0u;
    }
    _SEH2_END;

    return Ret;
}

/* The WM_INPUT messages of one thread sit in the hardware list of its queue
   (shared by attached threads); the wake bit is charged to the owning thread */
static
PUSER_MESSAGE
RawInputNextMessage(
    PTHREADINFO pti,
    PLIST_ENTRY *pEntry)
{
    PUSER_MESSAGE_QUEUE MessageQueue = pti->MessageQueue;

    while (*pEntry != &MessageQueue->HardwareMessagesListHead)
    {
        PUSER_MESSAGE Message = CONTAINING_RECORD(*pEntry, USER_MESSAGE, ListEntry);

        *pEntry = (*pEntry)->Flink;
        if (Message->Msg.message == WM_INPUT &&
            (Message->QS_Flags & QS_RAWINPUT) &&
            Message->pti == pti &&
            !MsqHardwareMessageInPlay(MessageQueue, Message))
            return Message;
    }

    return NULL;
}

DWORD
APIENTRY
NtUserGetRawInputBuffer(
    PRAWINPUT pData,
    PUINT pcbSize,
    UINT cbSizeHeader)
{
    PTHREADINFO pti;
    PUSER_MESSAGE_QUEUE MessageQueue;
    PUSER_RAWINPUT RawEntry;
    PUSER_MESSAGE Message;
    PLIST_ENTRY Entry;
    UINT BufferSize = 0, UsedSize = 0, Count = 0;
    DWORD Ret = ~0u;

    if (cbSizeHeader != sizeof(RAWINPUTHEADER) || !pcbSize)
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return ~0u;
    }

    UserEnterExclusive();

    pti = PsGetCurrentThreadWin32Thread();
    MessageQueue = pti ? pti->MessageQueue : NULL;

    _SEH2_TRY
    {
        ProbeForRead(pcbSize, sizeof(*pcbSize), sizeof(UINT));
        BufferSize = *pcbSize;
        if (pData)
        {
            /* Windows takes DWORD alignment in every ABI (measured natively and under WOW64) */
            ULONG Alignment = sizeof(DWORD);
            ProbeForWrite(pData, BufferSize, Alignment);
        }

        if (!MessageQueue)
        {
            Ret = 0;
            _SEH2_LEAVE;
        }

        Entry = MessageQueue->HardwareMessagesListHead.Flink;
        if (!pData)
        {
            ProbeForWrite(pcbSize, sizeof(*pcbSize), sizeof(UINT));
            Message = RawInputNextMessage(pti, &Entry);
            RawEntry = Message ? RawInputEntryFromHandle(MessageQueue, (HRAWINPUT)Message->Msg.lParam) : NULL;
            *pcbSize = RawEntry ? RawEntry->RawInput.header.dwSize : 0;
            Ret = 0;
            _SEH2_LEAVE;
        }

        while ((Message = RawInputNextMessage(pti, &Entry)) != NULL)
        {
            UINT RawSize;

            RawEntry = RawInputEntryFromHandle(MessageQueue, (HRAWINPUT)Message->Msg.lParam);
            if (!RawEntry)
                continue;

            RawSize = RawEntry->RawInput.header.dwSize;
            if (RawSize > BufferSize - UsedSize)
            {
                if (Count == 0)
                {
                    ProbeForWrite(pcbSize, sizeof(*pcbSize), sizeof(UINT));
                    *pcbSize = RawSize;
                    EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
                    _SEH2_LEAVE;
                }
                break;
            }

            RtlCopyMemory((PBYTE)pData + UsedSize, &RawEntry->RawInput, RawSize);
            UsedSize += RawSize;
            Count++;

            /* The bit was counted at enqueue time for Message->pti */
            pti->timeLast = Message->Msg.time;
            MsqRetireRawInputMessage(MessageQueue, Message);

            /* Windows wants one spare byte: an exact fit still consumes and copies
               the entry but reports a too small buffer */
            if (Count == 1 && UsedSize == BufferSize)
            {
                ProbeForWrite(pcbSize, sizeof(*pcbSize), sizeof(UINT));
                *pcbSize = RawSize;
                EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
                _SEH2_LEAVE;
            }
        }

        Ret = Count;

        /* An empty queue reports size 0 to a process that has registered */
        if (Count == 0 && pti->ppi->pRawInputRegs)
        {
            ProbeForWrite(pcbSize, sizeof(*pcbSize), sizeof(UINT));
            *pcbSize = 0;
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        Ret = ~0u;
    }
    _SEH2_END;

    UserLeave();
    return Ret;
}

DWORD
APIENTRY
NtUserGetRawInputDeviceList(
    _Out_opt_ PRAWINPUTDEVICELIST pRawInputDeviceList,
    _Inout_ PUINT puiNumDevices,
    _In_ UINT cbSize)
{
    PINPUT_DEVICE_INFO DeviceInfo;
    UINT cDevices = 0, i, Ret = (UINT)-1;

    if (cbSize != sizeof(RAWINPUTDEVICELIST))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return Ret;
    }

    AcquireDeviceInfoListMutex();
    for (DeviceInfo = gpInputDeviceInfo; DeviceInfo; DeviceInfo = DeviceInfo->pNextDeviceInfo)
        cDevices++;

    UserEnterShared();

    _SEH2_TRY
    {
        if (!pRawInputDeviceList)
        {
            ProbeForWrite(puiNumDevices, sizeof(*puiNumDevices), sizeof(DWORD));
            *puiNumDevices = cDevices;
            Ret = 0;
            _SEH2_LEAVE;
        }

        ProbeForRead(puiNumDevices, sizeof(*puiNumDevices), sizeof(DWORD));
        if (*puiNumDevices < cDevices)
        {
            ProbeForWrite(puiNumDevices, sizeof(*puiNumDevices), sizeof(DWORD));
            *puiNumDevices = cDevices;
            EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
            _SEH2_LEAVE;
        }

        ProbeForWrite(pRawInputDeviceList, cDevices * sizeof(*pRawInputDeviceList), sizeof(PVOID));
        for (DeviceInfo = gpInputDeviceInfo, i = 0; DeviceInfo && i < cDevices; DeviceInfo = DeviceInfo->pNextDeviceInfo, i++)
        {
            pRawInputDeviceList[i].hDevice = DeviceInfo->hRawDevice;
            pRawInputDeviceList[i].dwType = DeviceInfo->DeviceType;
        }
        Ret = cDevices;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
    }
    _SEH2_END;

    UserLeave();
    ReleaseDeviceInfoListMutex();
    return Ret;
}

DWORD
NTAPI
NtUserGetRawInputData(
    HRAWINPUT hRawInput,
    UINT uiCommand,
    LPVOID pData,
    PUINT pcbSize,
    UINT cbSizeHeader)
{
    PTHREADINFO pti;
    PUSER_RAWINPUT RawEntry;
    DWORD Ret;

    if (cbSizeHeader != sizeof(RAWINPUTHEADER))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return ~0u;
    }

    if (!hRawInput)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        return ~0u;
    }

    UserEnterShared();

    pti = PsGetCurrentThreadWin32Thread();
    RawEntry = RawInputEntryFromHandle(pti ? pti->MessageQueue : NULL, hRawInput);
    if (!RawEntry)
    {
        EngSetLastError(ERROR_INVALID_HANDLE);
        Ret = ~0u;
    }
    else if (!pcbSize)
    {
        EngSetLastError(ERROR_NOACCESS);
        Ret = ~0u;
    }
    else
    {
        Ret = RawInputCopyData(&RawEntry->RawInput, uiCommand, pData, pcbSize);
    }

    UserLeave();
    return Ret;
}

DWORD
APIENTRY
NtUserGetRegisteredRawInputDevices(
    _Out_opt_ PRAWINPUTDEVICE pRawInputDevices,
    _Inout_ PUINT puiNumDevices,
    _In_ UINT cbSize)
{
    PTHREADINFO pti;
    PRAWINPUT_REGTABLE Table;
    UINT i, cDevices, uiNumDevices, Ret = (UINT)-1;

    if (cbSize != sizeof(RAWINPUTDEVICE))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return Ret;
    }

    UserEnterShared();

    pti = PsGetCurrentThreadWin32Thread();
    Table = pti ? pti->ppi->pRawInputRegs : NULL;
    cDevices = Table ? Table->cRegs : 0;

    _SEH2_TRY
    {
        if (!pRawInputDevices)
        {
            ProbeForWrite(puiNumDevices, sizeof(*puiNumDevices), sizeof(DWORD));
            *puiNumDevices = cDevices;
            Ret = 0;
            _SEH2_LEAVE;
        }

        ProbeForRead(puiNumDevices, sizeof(*puiNumDevices), sizeof(DWORD));
        uiNumDevices = *puiNumDevices;
        if (uiNumDevices == 0)
        {
            EngSetLastError(ERROR_INVALID_PARAMETER);
            _SEH2_LEAVE;
        }

        /* Windows raises an access violation for counts it cannot probe */
        if (uiNumDevices > MAXULONG / sizeof(*pRawInputDevices))
        {
            EngSetLastError(ERROR_NOACCESS);
            _SEH2_LEAVE;
        }

        ProbeForWrite(pRawInputDevices, uiNumDevices * sizeof(*pRawInputDevices), sizeof(PVOID));
        if (uiNumDevices < cDevices)
        {
            ProbeForWrite(puiNumDevices, sizeof(*puiNumDevices), sizeof(DWORD));
            *puiNumDevices = cDevices;
            EngSetLastError(ERROR_INSUFFICIENT_BUFFER);
            _SEH2_LEAVE;
        }

        for (i = 0; i < cDevices; i++)
            pRawInputDevices[i] = Table->aRegs[i].Device;
        Ret = cDevices;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
    }
    _SEH2_END;

    UserLeave();
    return Ret;
}

/* Flags Windows accepts (0x800 is accepted and ignored) */
#define RIDEV_VALID_MASK (RIDEV_REMOVE | RIDEV_NOLEGACY | RIDEV_INPUTSINK | RIDEV_CAPTUREMOUSE | \
                          RIDEV_APPKEYS | 0x800 | RIDEV_EXINPUTSINK | RIDEV_DEVNOTIFY)

/* Validates one registration the way Windows does; FALSE with the last error set */
static
BOOL
RawInputCheckDevice(
    PPROCESSINFO ppi,
    const RAWINPUTDEVICE *Device)
{
    DWORD dwFlags = Device->dwFlags;
    DWORD dwClass = dwFlags & RIDEV_CLASS_MASK;
    BOOL bMouseOrKeyboard = Device->usUsagePage == HID_USAGE_PAGE_GENERIC &&
                            (Device->usUsage == HID_USAGE_GENERIC_MOUSE ||
                             Device->usUsage == HID_USAGE_GENERIC_KEYBOARD);

    if (dwFlags & ~RIDEV_VALID_MASK)
        goto invalid_flags;

    if ((dwFlags & RIDEV_REMOVE) && dwClass == RIDEV_NOLEGACY)
        goto invalid_flags;

    if (!Device->usUsagePage)
        goto invalid;

    switch (dwClass)
    {
        case RIDEV_PAGEONLY:
            if (Device->usUsage)
                goto invalid;
            break;

        case RIDEV_NOLEGACY:
            if (!bMouseOrKeyboard)
                goto invalid;
            break;

        default: /* plain and exclude */
            if (!Device->usUsage)
                goto invalid;
            break;
    }

    if (dwFlags & RIDEV_REMOVE)
    {
        if (Device->hwndTarget)
            goto invalid;
        return TRUE;
    }

    if ((dwFlags & (RIDEV_INPUTSINK | RIDEV_EXINPUTSINK)) && !Device->hwndTarget)
        goto invalid;

    /* The mouse capture and application key bits only mean something with NOLEGACY,
       except that the keyboard takes the first one on its own */
    if ((dwFlags & RIDEV_CAPTUREMOUSE) && dwClass != RIDEV_NOLEGACY &&
        Device->usUsage != HID_USAGE_GENERIC_KEYBOARD)
        goto invalid_flags;
    if ((dwFlags & RIDEV_APPKEYS) && dwClass != RIDEV_NOLEGACY)
        goto invalid_flags;

    if (Device->hwndTarget)
    {
        PWND pWnd = UserGetWindowObject(Device->hwndTarget);

        if (!pWnd || !pWnd->head.pti || pWnd->head.pti->ppi != ppi)
            goto invalid;
    }

    return TRUE;

invalid_flags:
    EngSetLastError(ERROR_INVALID_FLAGS);
    return FALSE;

invalid:
    EngSetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
}

BOOL
APIENTRY
NtUserRegisterRawInputDevices(
    IN PCRAWINPUTDEVICE pRawInputDevices,
    IN UINT uiNumDevices,
    IN UINT cbSize)
{
    PTHREADINFO pti;
    PRAWINPUTDEVICE Devices = NULL;
    UINT i;
    BOOL Ret = FALSE, bNotify = FALSE;

    if (!pRawInputDevices || !uiNumDevices || cbSize != sizeof(RAWINPUTDEVICE))
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (uiNumDevices > 4096)
    {
        EngSetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Devices = ExAllocatePoolWithTag(PagedPool, uiNumDevices * sizeof(*Devices), 'iwar');
    if (!Devices)
    {
        EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    _SEH2_TRY
    {
        ProbeForRead(pRawInputDevices, uiNumDevices * sizeof(*Devices), sizeof(PVOID));
        RtlCopyMemory(Devices, pRawInputDevices, uiNumDevices * sizeof(*Devices));
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        SetLastNtError(_SEH2_GetExceptionCode());
        ExFreePoolWithTag(Devices, 'iwar');
        return FALSE;
    }
    _SEH2_END;

    for (i = 0; i < uiNumDevices; i++)
    {
        if ((Devices[i].dwFlags & (RIDEV_DEVNOTIFY | RIDEV_REMOVE)) == RIDEV_DEVNOTIFY && Devices[i].hwndTarget)
            bNotify = TRUE;
    }

    /* Same order as NtUserGetRawInputDeviceList: device list first, then the USER lock */
    if (bNotify)
        AcquireDeviceInfoListMutex();
    UserEnterExclusive();

    pti = PsGetCurrentThreadWin32Thread();
    if (!pti)
        goto cleanup;

    for (i = 0; i < uiNumDevices; i++)
    {
        if (!RawInputCheckDevice(pti->ppi, &Devices[i]))
            goto cleanup;
    }

    for (i = 0; i < uiNumDevices; i++)
    {
        const RAWINPUTDEVICE *Device = &Devices[i];

        PWND pWnd = Device->hwndTarget ? UserGetWindowObject(Device->hwndTarget) : NULL;

        if (!RawRegApply(pti->ppi, Device, pWnd ? pWnd->head.pti : NULL, !!(Device->dwFlags & RIDEV_REMOVE)))
        {
            EngSetLastError(ERROR_NOT_ENOUGH_MEMORY);
            RawInputUpdateEnabled();
            goto cleanup;
        }
    }

    RawInputUpdateEnabled();

    /* A registration with device notification gets the devices that already exist */
    for (i = 0; bNotify && i < uiNumDevices; i++)
    {
        const RAWINPUTDEVICE *Device = &Devices[i];
        PINPUT_DEVICE_INFO DeviceInfo;

        if ((Device->dwFlags & (RIDEV_DEVNOTIFY | RIDEV_REMOVE)) != RIDEV_DEVNOTIFY || !Device->hwndTarget)
            continue;

        for (DeviceInfo = gpInputDeviceInfo; DeviceInfo; DeviceInfo = DeviceInfo->pNextDeviceInfo)
        {
            if (RawRegLookupType(pti->ppi->pRawInputRegs, DeviceInfo->DeviceType) == NULL ||
                Device->usUsagePage != HID_USAGE_PAGE_GENERIC ||
                (Device->usUsage != RawInputUsageFromType(DeviceInfo->DeviceType) && !(Device->dwFlags & RIDEV_PAGEONLY)))
                continue;

            UserPostMessage(Device->hwndTarget, WM_INPUT_DEVICE_CHANGE, GIDC_ARRIVAL, (LPARAM)DeviceInfo->hRawDevice);
        }
    }

    Ret = TRUE;

cleanup:
    UserLeave();
    if (bNotify)
        ReleaseDeviceInfoListMutex();
    ExFreePoolWithTag(Devices, 'iwar');
    return Ret;
}
