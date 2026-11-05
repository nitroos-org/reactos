/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     D3DKMT calls that cross the 32-bit to 64-bit win32k boundary under WoW64
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The native win32k has no display-driver adapter interface, so every D3DKMT call that would reach a
 * miniport answers STATUS_PROCEDURE_NOT_FOUND and gdi32 falls back to its own software adapter. A 32-bit
 * program under WoW64 has to get the same answers: the status of the native service, with the structure
 * converted both ways, and never "service not implemented". The same executable runs on native i386, on
 * WoW64 and on Windows. Windows has a real adapter only in an interactive session, so most checks accept
 * the failure Windows gives without one; the exact ReactOS statuses are checked only on ReactOS.
 */

#include "precomp.h"

#include <ntstatus.h>
#include <d3dkmthk.h>

typedef NTSTATUS (APIENTRY *PFN_KMT)(PVOID);
#define KMT_SUCCESS(Status) ((LONG)(Status) >= 0)

#define FILL 0xCC
/* KMTQAITYPE_ADAPTERTYPE; the tree header predates it */
#define QAI_TYPE_ADAPTERTYPE ((KMTQUERYADAPTERINFOTYPE)15)
#define SENTINEL_ADAPTER 0xdeadbeef
#define SENTINEL_DEVICE 0xfeedf00d

static PFN_KMT GetKmt(const char *Name)
{
    PFN_KMT Fn;
    HMODULE hMod = GetModuleHandleW(L"gdi32.dll");

    Fn = (PFN_KMT)GetProcAddress(hMod, Name);
    if (!Fn)
    {
        /* ReactOS NT 5.x builds export them from gdi32_vista */
        hMod = LoadLibraryW(L"gdi32_vista.dll");
        if (hMod)
            Fn = (PFN_KMT)GetProcAddress(hMod, Name);
    }
    return Fn;
}

/* The status the 32-bit program must never see: it means the WoW64 layer has no translation. */
#define ok_not_unsupported(Status) \
    ok((Status) != STATUS_NOT_IMPLEMENTED, "Got STATUS_NOT_IMPLEMENTED for a call that must be translated\n")

static void CheckTail(const BYTE *Raw, size_t Size, const char *What)
{
    size_t i;

    for (i = Size; i < 256; i++)
    {
        if (Raw[i] != FILL)
        {
            ok(0, "%s wrote past the structure at +%lu (0x%02x)\n", What, (unsigned long)i, Raw[i]);
            return;
        }
    }
}

static void test_OpenAdapterFromHdc(void)
{
    PFN_KMT pOpen = GetKmt("D3DKMTOpenAdapterFromHdc");
    BYTE Raw[256];
    D3DKMT_OPENADAPTERFROMHDC *Desc = (D3DKMT_OPENADAPTERFROMHDC *)Raw;
    HDC hdc;
    NTSTATUS Status;

    if (!pOpen)
    {
        skip("D3DKMTOpenAdapterFromHdc is not available\n");
        return;
    }

    hdc = GetDC(NULL);
    memset(Raw, FILL, sizeof(Raw));
    Desc->hDc = hdc;
    Desc->hAdapter = SENTINEL_ADAPTER;
    Desc->AdapterLuid.LowPart = 0x11111111;
    Desc->AdapterLuid.HighPart = 0x22222222;
    Desc->VidPnSourceId = 0x33333333;
    Status = pOpen(Desc);
    ok_not_unsupported(Status);
    ok(Desc->hDc == hdc, "hDc was changed to %p\n", Desc->hDc);
    CheckTail(Raw, sizeof(*Desc), "D3DKMTOpenAdapterFromHdc");
    if (is_reactos())
    {
        /* Passes the status of the native service through. It has no adapter, so it leaves the outputs alone */
        ok(Status == STATUS_SUCCESS, "Got unexpected status 0x%lx\n", Status);
        ok(Desc->hAdapter == SENTINEL_ADAPTER, "hAdapter is 0x%x\n", Desc->hAdapter);
        ok(Desc->AdapterLuid.LowPart == 0x11111111 && Desc->AdapterLuid.HighPart == 0x22222222,
           "AdapterLuid is %lx:%lx\n", Desc->AdapterLuid.HighPart, Desc->AdapterLuid.LowPart);
        ok(Desc->VidPnSourceId == 0x33333333, "VidPnSourceId is 0x%x\n", Desc->VidPnSourceId);
    }
    else if (KMT_SUCCESS(Status))
    {
        D3DKMT_CLOSEADAPTER Close;
        PFN_KMT pClose = GetKmt("D3DKMTCloseAdapter");

        ok(Desc->hAdapter != SENTINEL_ADAPTER && Desc->hAdapter != 0, "hAdapter is 0x%x\n", Desc->hAdapter);
        ok(Desc->AdapterLuid.LowPart != 0x11111111 || Desc->AdapterLuid.HighPart != 0x22222222, "AdapterLuid unchanged\n");
        ok(Desc->VidPnSourceId != 0x33333333, "VidPnSourceId unchanged\n");
        Close.hAdapter = Desc->hAdapter;
        if (pClose)
            pClose(&Close);
    }
    else
    {
        /* Windows without an interactive display: nothing is opened, whether or not it clears the output */
        ok(Desc->hAdapter == SENTINEL_ADAPTER || Desc->hAdapter == 0, "hAdapter is 0x%x after a failure\n", Desc->hAdapter);
    }
    ReleaseDC(NULL, hdc);
}

static void test_OpenAdapterFromDeviceName(void)
{
    PFN_KMT pOpen = GetKmt("D3DKMTOpenAdapterFromDeviceName");
    static const WCHAR Name[] = L"\\\\.\\DISPLAY1";
    BYTE Raw[256];
    D3DKMT_OPENADAPTERFROMDEVICENAME *Desc = (D3DKMT_OPENADAPTERFROMDEVICENAME *)Raw;
    NTSTATUS Status;

    if (!pOpen)
    {
        skip("D3DKMTOpenAdapterFromDeviceName is not available\n");
        return;
    }

    memset(Raw, FILL, sizeof(Raw));
    Desc->pDeviceName = Name;
    Desc->hAdapter = SENTINEL_ADAPTER;
    Desc->AdapterLuid.LowPart = 0x11111111;
    Desc->AdapterLuid.HighPart = 0x22222222;
    Status = pOpen(Desc);
    ok_not_unsupported(Status);
    ok(Desc->pDeviceName == Name, "pDeviceName was changed to %p\n", Desc->pDeviceName);
    CheckTail(Raw, sizeof(*Desc), "D3DKMTOpenAdapterFromDeviceName");
    if (is_reactos())
    {
        ok(Status == STATUS_SUCCESS, "Got unexpected status 0x%lx\n", Status);
        ok(Desc->hAdapter == SENTINEL_ADAPTER, "hAdapter is 0x%x\n", Desc->hAdapter);
        ok(Desc->AdapterLuid.LowPart == 0x11111111 && Desc->AdapterLuid.HighPart == 0x22222222,
           "AdapterLuid is %lx:%lx\n", Desc->AdapterLuid.HighPart, Desc->AdapterLuid.LowPart);
    }
    else if (KMT_SUCCESS(Status))
    {
        D3DKMT_CLOSEADAPTER Close;
        PFN_KMT pClose = GetKmt("D3DKMTCloseAdapter");

        ok(Desc->hAdapter != SENTINEL_ADAPTER, "hAdapter unchanged\n");
        Close.hAdapter = Desc->hAdapter;
        if (pClose)
            pClose(&Close);
    }
}

static void test_QueryAdapterInfo(void)
{
    PFN_KMT pQuery = GetKmt("D3DKMTQueryAdapterInfo");
    BYTE Raw[256], Data[32];
    D3DKMT_QUERYADAPTERINFO *Query = (D3DKMT_QUERYADAPTERINFO *)Raw;
    NTSTATUS Status;
    size_t i;

    if (!pQuery)
    {
        skip("D3DKMTQueryAdapterInfo is not available\n");
        return;
    }

    memset(Raw, FILL, sizeof(Raw));
    memset(Data, FILL, sizeof(Data));
    Query->hAdapter = SENTINEL_ADAPTER;
    Query->Type = QAI_TYPE_ADAPTERTYPE;
    Query->pPrivateDriverData = Data;
    Query->PrivateDriverDataSize = sizeof(Data);
    Status = pQuery(Query);
    ok_not_unsupported(Status);
    CheckTail(Raw, sizeof(*Query), "D3DKMTQueryAdapterInfo");
    ok(Query->hAdapter == SENTINEL_ADAPTER, "hAdapter was changed to 0x%x\n", Query->hAdapter);
    ok(Query->Type == QAI_TYPE_ADAPTERTYPE, "Type was changed to %d\n", Query->Type);
    ok(Query->pPrivateDriverData == Data, "pPrivateDriverData was changed to %p\n", Query->pPrivateDriverData);
    ok(Query->PrivateDriverDataSize == sizeof(Data), "PrivateDriverDataSize was changed to %u\n",
       Query->PrivateDriverDataSize);
    if (is_reactos())
        ok(Status == STATUS_PROCEDURE_NOT_FOUND, "Got unexpected status 0x%lx\n", Status);
    if (!KMT_SUCCESS(Status))
    {
        /* The data block is not touched when the query fails */
        for (i = 0; i < sizeof(Data); i++)
        {
            if (Data[i] != FILL)
            {
                ok(0, "Data block changed at +%lu after status 0x%lx\n", (unsigned long)i, Status);
                break;
            }
        }
    }

    /* Without a data block */
    memset(Raw, FILL, sizeof(Raw));
    Query->hAdapter = SENTINEL_ADAPTER;
    Query->Type = QAI_TYPE_ADAPTERTYPE;
    Query->pPrivateDriverData = NULL;
    Query->PrivateDriverDataSize = 0;
    Status = pQuery(Query);
    ok_not_unsupported(Status);
    if (is_reactos())
        ok(Status == STATUS_PROCEDURE_NOT_FOUND, "Got unexpected status 0x%lx\n", Status);
}

static void test_CheckOcclusion(void)
{
    PFN_KMT pCheck = GetKmt("D3DKMTCheckOcclusion");
    BYTE Raw[256];
    D3DKMT_CHECKOCCLUSION *Desc = (D3DKMT_CHECKOCCLUSION *)Raw;
    NTSTATUS Status;

    if (!pCheck)
    {
        skip("D3DKMTCheckOcclusion is not available\n");
        return;
    }

    memset(Raw, FILL, sizeof(Raw));
    Desc->hWindow = GetDesktopWindow();
    Status = pCheck(Desc);
    ok_not_unsupported(Status);
    ok(Desc->hWindow == GetDesktopWindow(), "hWindow was changed to %p\n", Desc->hWindow);
    CheckTail(Raw, sizeof(*Desc), "D3DKMTCheckOcclusion");
    /* No miniport: the answer depends on the window handle only, see D3DKMTCheckOcclusion.c */
    ok(Status == STATUS_SUCCESS, "Got unexpected status 0x%lx\n", Status);
}

/* gdi32 opens the adapter and the device itself when win32k has none, so these work under WoW64 only if
 * the native status NtGdiDdDDICreateDevice and friends return is passed through. */
static void test_Device(void)
{
    PFN_KMT pOpenName = GetKmt("D3DKMTOpenAdapterFromGdiDisplayName");
    PFN_KMT pClose = GetKmt("D3DKMTCloseAdapter");
    PFN_KMT pCreate = GetKmt("D3DKMTCreateDevice");
    PFN_KMT pDestroy = GetKmt("D3DKMTDestroyDevice");
    PFN_KMT pOwner = GetKmt("D3DKMTSetVidPnSourceOwner");
    D3DKMT_OPENADAPTERFROMGDIDISPLAYNAME Open;
    D3DKMT_CLOSEADAPTER Close;
    D3DKMT_CREATEDEVICE Create;
    D3DKMT_DESTROYDEVICE Destroy;
    D3DKMT_SETVIDPNSOURCEOWNER Owner;
    D3DKMT_VIDPNSOURCEOWNER_TYPE Type;
    D3DDDI_VIDEO_PRESENT_SOURCE_ID Source;
    NTSTATUS Status;
    D3DKMT_HANDLE hDevice;

    if (!pOpenName || !pClose || !pCreate || !pDestroy || !pOwner)
    {
        skip("The D3DKMT adapter functions are not available\n");
        return;
    }

    ZeroMemory(&Open, sizeof(Open));
    wcscpy(Open.DeviceName, L"\\\\.\\DISPLAY1");
    Status = pOpenName(&Open);
    if (!KMT_SUCCESS(Status))
    {
        /* Windows without an interactive display has no adapter to open */
        ok(!is_reactos(), "D3DKMTOpenAdapterFromGdiDisplayName failed with 0x%lx\n", Status);
        skip("No display adapter\n");
        return;
    }
    ok(Open.hAdapter != 0, "hAdapter is 0\n");

    ZeroMemory(&Create, sizeof(Create));
    Create.hAdapter = Open.hAdapter;
    Create.hDevice = SENTINEL_DEVICE;
    Status = pCreate(&Create);
    ok(Status == STATUS_SUCCESS, "D3DKMTCreateDevice returned 0x%lx\n", Status);
    ok(Create.hAdapter == Open.hAdapter, "hAdapter was changed to 0x%x\n", Create.hAdapter);
    if (Status != STATUS_SUCCESS)
    {
        Close.hAdapter = Open.hAdapter;
        pClose(&Close);
        return;
    }
    ok(Create.hDevice != 0 && Create.hDevice != SENTINEL_DEVICE, "hDevice is 0x%x\n", Create.hDevice);
    hDevice = Create.hDevice;

    /* Ownership of the VidPn source: the arrays are read by the 32-bit to 64-bit conversion */
    Type = D3DKMT_VIDPNSOURCEOWNER_SHARED;
    Source = Open.VidPnSourceId;
    ZeroMemory(&Owner, sizeof(Owner));
    Owner.hDevice = hDevice;
    Owner.pType = &Type;
    Owner.pVidPnSourceId = &Source;
    Owner.VidPnSourceCount = 1;
    Status = pOwner(&Owner);
    ok_not_unsupported(Status);
    ok(Status == STATUS_SUCCESS || Status == STATUS_PROCEDURE_NOT_FOUND, "D3DKMTSetVidPnSourceOwner returned 0x%lx\n", Status);
    ok(Owner.pType == &Type && Owner.pVidPnSourceId == &Source && Owner.VidPnSourceCount == 1,
       "The ownership description was changed\n");

    /* A zero count releases ownership and never fails */
    ZeroMemory(&Owner, sizeof(Owner));
    Owner.hDevice = hDevice;
    Status = pOwner(&Owner);
    ok(Status == STATUS_SUCCESS, "Release returned 0x%lx\n", Status);

    /* An unknown device is rejected */
    Owner.hDevice = 0xbad0;
    Owner.pType = &Type;
    Owner.pVidPnSourceId = &Source;
    Owner.VidPnSourceCount = 1;
    Status = pOwner(&Owner);
    ok(Status == STATUS_INVALID_PARAMETER, "Unknown device returned 0x%lx\n", Status);

    Destroy.hDevice = hDevice;
    Status = pDestroy(&Destroy);
    ok(Status == STATUS_SUCCESS, "D3DKMTDestroyDevice returned 0x%lx\n", Status);
    Status = pDestroy(&Destroy);
    ok(Status == STATUS_INVALID_PARAMETER, "Second D3DKMTDestroyDevice returned 0x%lx\n", Status);

    Close.hAdapter = Open.hAdapter;
    Status = pClose(&Close);
    ok(Status == STATUS_SUCCESS, "D3DKMTCloseAdapter returned 0x%lx\n", Status);
}

/* Calls that only a display driver can answer, with a structure of zeros: the status of the native service */
static void test_NoAdapterCalls(void)
{
    static const char *Names[] =
    {
        "D3DKMTCreateAllocation", "D3DKMTCreateContext", "D3DKMTCreateOverlay", "D3DKMTDestroyAllocation",
        "D3DKMTEscape", "D3DKMTFlipOverlay", "D3DKMTGetDisplayModeList", "D3DKMTGetMultisampleMethodList",
        "D3DKMTGetPresentHistory", "D3DKMTGetRuntimeData", "D3DKMTInvalidateActiveVidPn", "D3DKMTLock",
        "D3DKMTOpenResource", "D3DKMTPresent", "D3DKMTQueryAllocationResidency", "D3DKMTQueryResourceInfo",
        "D3DKMTQueryStatistics", "D3DKMTRender", "D3DKMTSetAllocationPriority", "D3DKMTSetGammaRamp",
        "D3DKMTUnlock", "D3DKMTUpdateOverlay"
    };
    BYTE Raw[256];
    ULONG i;

    /* Windows would validate the zeros against a real adapter, which is not a comparison worth the risk */
    if (!is_reactos())
    {
        skip("ReactOS only\n");
        return;
    }

    for (i = 0; i < ARRAYSIZE(Names); i++)
    {
        PFN_KMT Fn = GetKmt(Names[i]);
        NTSTATUS Status;

        if (!Fn)
        {
            ok(0, "%s is not exported\n", Names[i]);
            continue;
        }
        memset(Raw, 0, sizeof(Raw));
        Status = Fn(Raw);
        ok(Status == STATUS_PROCEDURE_NOT_FOUND, "%s returned 0x%lx\n", Names[i], Status);
    }
}

/* The converted structure carries handles in both directions: a memory DC over caller memory */
static void test_DCFromMemory(void)
{
    PFN_KMT pCreate = GetKmt("D3DKMTCreateDCFromMemory");
    PFN_KMT pDestroy = GetKmt("D3DKMTDestroyDCFromMemory");
    static const D3DDDIFORMAT Formats[] = { D3DDDIFMT_X8R8G8B8, D3DDDIFMT_A8R8G8B8, D3DDDIFMT_R8G8B8, D3DDDIFMT_R5G6B5, D3DDDIFMT_P8 };
    static const UINT Depth[] = { 32, 32, 24, 16, 8 };
    BYTE Raw[256];
    D3DKMT_CREATEDCFROMMEMORY *Desc = (D3DKMT_CREATEDCFROMMEMORY *)Raw;
    D3DKMT_DESTROYDCFROMMEMORY Destroy;
    DWORD Bits[64 * 8];
    HDC hDevice;
    NTSTATUS Status;
    ULONG i;

    if (!pCreate || !pDestroy)
    {
        skip("D3DKMTCreateDCFromMemory is not available\n");
        return;
    }

    hDevice = GetDC(NULL);
    for (i = 0; i < ARRAYSIZE(Formats); i++)
    {
        UINT Pitch = (((16 * Depth[i] + 31) >> 3) & ~3);

        memset(Raw, FILL, sizeof(Raw));
        memset(Bits, 0, sizeof(Bits));
        Desc->pMemory = Bits;
        Desc->Format = Formats[i];
        Desc->Width = 16;
        Desc->Height = 4;
        Desc->Pitch = Pitch;
        Desc->hDeviceDc = hDevice;
        Desc->pColorTable = NULL;
        Desc->hDc = (HDC)(ULONG_PTR)0x010baade;
        Desc->hBitmap = (HANDLE)(ULONG_PTR)0x020baade;
        Status = pCreate(Desc);
        ok(Status == STATUS_SUCCESS, "Format %d: got unexpected status 0x%lx\n", Formats[i], Status);
        CheckTail(Raw, sizeof(*Desc), "D3DKMTCreateDCFromMemory");
        ok(Desc->pMemory == Bits && Desc->Format == Formats[i] && Desc->Width == 16 && Desc->Height == 4 &&
           Desc->Pitch == Pitch && Desc->hDeviceDc == hDevice, "Format %d: an input field was changed\n", Formats[i]);
        if (Status != STATUS_SUCCESS)
            continue;

        ok(Desc->hDc != (HDC)(ULONG_PTR)0x010baade && Desc->hBitmap != (HANDLE)(ULONG_PTR)0x020baade,
           "Format %d: the handles were not returned\n", Formats[i]);
        ok(GetObjectType(Desc->hDc) == OBJ_MEMDC, "Format %d: got unexpected DC type %lu\n", Formats[i], GetObjectType(Desc->hDc));
        ok(GetObjectType(Desc->hBitmap) == OBJ_BITMAP, "Format %d: got unexpected bitmap type %lu\n", Formats[i], GetObjectType(Desc->hBitmap));
        if (Formats[i] == D3DDDIFMT_X8R8G8B8)
        {
            /* The drawing lands in the caller's memory */
            SetPixel(Desc->hDc, 1, 0, RGB(0x11, 0x22, 0x33));
            GdiFlush();
            ok(Bits[1] == 0x00112233, "Format %d: memory holds 0x%08lx\n", Formats[i], Bits[1]);
        }

        Destroy.hDc = Desc->hDc;
        Destroy.hBitmap = Desc->hBitmap;
        Status = pDestroy(&Destroy);
        ok(Status == STATUS_SUCCESS, "Format %d: destroy returned 0x%lx\n", Formats[i], Status);
        ok(Destroy.hDc == Desc->hDc && Destroy.hBitmap == Desc->hBitmap, "The destroy descriptor was changed\n");

        /* They are gone now. Windows rejects the stale handles; win32k only checks their type */
        Status = pDestroy(&Destroy);
        todo_if(is_reactos())
        ok(Status == STATUS_INVALID_PARAMETER, "Format %d: second destroy returned 0x%lx\n", Formats[i], Status);
    }

    /* The device DC and the memory are required */
    memset(Raw, FILL, sizeof(Raw));
    Desc->pMemory = Bits;
    Desc->Format = D3DDDIFMT_X8R8G8B8;
    Desc->Width = 4;
    Desc->Height = 4;
    Desc->Pitch = 16;
    Desc->hDeviceDc = NULL;
    Desc->pColorTable = NULL;
    Desc->hDc = NULL;
    Desc->hBitmap = NULL;
    Status = pCreate(Desc);
    ok(Status == STATUS_INVALID_PARAMETER, "No device DC: got unexpected status 0x%lx\n", Status);
    Desc->hDeviceDc = hDevice;
    Desc->pMemory = NULL;
    Status = pCreate(Desc);
    ok(Status == STATUS_INVALID_PARAMETER, "No memory: got unexpected status 0x%lx\n", Status);
    Desc->pMemory = Bits;
    Desc->hDeviceDc = (HDC)(ULONG_PTR)0x1234;
    Status = pCreate(Desc);
    ok(Status == STATUS_INVALID_PARAMETER, "Bad device DC: got unexpected status 0x%lx\n", Status);

    /* Handles that are not a DC and a bitmap */
    Destroy.hDc = NULL;
    Destroy.hBitmap = NULL;
    Status = pDestroy(&Destroy);
    ok(Status == STATUS_INVALID_PARAMETER, "Null handles: got unexpected status 0x%lx\n", Status);
    ReleaseDC(NULL, hDevice);
}

START_TEST(D3DKMTWow64Thunks)
{
    test_DCFromMemory();
    test_OpenAdapterFromHdc();
    test_OpenAdapterFromDeviceName();
    test_QueryAdapterInfo();
    test_CheckOcclusion();
    test_Device();
    test_NoAdapterCalls();
}
