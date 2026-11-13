/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Nitro-private interfaces of the Windows.UI.Composition objects in dcomp.dll (not Windows API)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * INitroDrawingSurfaceInterop has the six methods of the documented ICompositionDrawingSurfaceInterop with the
 * documented signatures (learn.microsoft.com). Its own IID is OURS and nothing running on Windows asks for it; the
 * vtable is the one of the real interface, which is answered for the real IID too (IID_ICompositionDrawingSurfaceInterop):
 * IID and member order (BeginDraw, EndDraw, Resize, Scroll, ResumeDraw, SuspendDraw) from microsoft/windows-rs commit
 * cd03f9369a896b62151242c1c3321e695df63cfc, file metadata/win32/windowsuicompositioninterop.rdl.
 * INitroCompositionTest is a test hook: render the visual tree below a visual into a bitmap on the CPU and dump
 * the tree as text, and wait for / observe the render thread of the presentation path (present.c).
 */

#pragma once

#include <windows.h>
#include <objbase.h>

typedef struct INitroDrawingSurfaceInterop INitroDrawingSurfaceInterop;
typedef struct INitroCompositionTest INitroCompositionTest;

typedef struct INitroDrawingSurfaceInteropVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(INitroDrawingSurfaceInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(INitroDrawingSurfaceInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(INitroDrawingSurfaceInterop *This);
    HRESULT (STDMETHODCALLTYPE *BeginDraw)(INitroDrawingSurfaceInterop *This, const RECT *updateRect, REFIID iid,
            void **updateObject, POINT *updateOffset);
    HRESULT (STDMETHODCALLTYPE *EndDraw)(INitroDrawingSurfaceInterop *This);
    HRESULT (STDMETHODCALLTYPE *Resize)(INitroDrawingSurfaceInterop *This, SIZE sizePixels);
    HRESULT (STDMETHODCALLTYPE *Scroll)(INitroDrawingSurfaceInterop *This, const RECT *scrollRect,
            const RECT *clipRect, int offsetX, int offsetY);
    HRESULT (STDMETHODCALLTYPE *ResumeDraw)(INitroDrawingSurfaceInterop *This);
    HRESULT (STDMETHODCALLTYPE *SuspendDraw)(INitroDrawingSurfaceInterop *This);
} INitroDrawingSurfaceInteropVtbl;
struct INitroDrawingSurfaceInterop { const INitroDrawingSurfaceInteropVtbl *lpVtbl; };

typedef struct INitroCompositionTestVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(INitroCompositionTest *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(INitroCompositionTest *This);
    ULONG (STDMETHODCALLTYPE *Release)(INitroCompositionTest *This);
    /* bgra: width * height * 4 bytes, premultiplied, cleared by the call, rows stride bytes apart */
    HRESULT (STDMETHODCALLTYPE *RenderToBitmap)(INitroCompositionTest *This, UINT width, UINT height,
            void *bgra, UINT stride);
    /* text of the scene graph below the object, truncated to size (NUL terminated) */
    HRESULT (STDMETHODCALLTYPE *DumpTree)(INitroCompositionTest *This, char *buffer, UINT size);
} INitroCompositionTestVtbl;
struct INitroCompositionTest { const INitroCompositionTestVtbl *lpVtbl; };

/* the presentation path (present.c): its render thread is observable and can be slowed down for tests */
typedef struct INitroCompositionTest2 INitroCompositionTest2;
typedef struct INitroCompositionTest2Vtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(INitroCompositionTest2 *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(INitroCompositionTest2 *This);
    ULONG (STDMETHODCALLTYPE *Release)(INitroCompositionTest2 *This);
    /* wait until every committed frame has been presented or dropped (S_OK, or HRESULT_FROM_WIN32(WAIT_TIMEOUT));
     * ICompositorController::Commit itself returns without waiting */
    HRESULT (STDMETHODCALLTYPE *WaitForPresent)(INitroCompositionTest2 *This, DWORD milliseconds);
    /* every surface read-back of the renderer takes this many ms longer (0 = off): a slow GPU for tests */
    HRESULT (STDMETHODCALLTYPE *SetReadbackDelay)(INitroCompositionTest2 *This, DWORD milliseconds);
    /* process-wide counters: [0] frames rendered, [1] frames replaced before they were rendered, [2] commits that
     * showed the same as the previous one (not rendered again), [3] surface read-backs from the GPU, [4] surfaces
     * taken from the read-back cache; count <= 8 */
    HRESULT (STDMETHODCALLTYPE *GetStats)(INitroCompositionTest2 *This, LONG *values, UINT count);
} INitroCompositionTest2Vtbl;
struct INitroCompositionTest2 { const INitroCompositionTest2Vtbl *lpVtbl; };

DEFINE_GUID(IID_INitroDrawingSurfaceInterop, 0xc8b9638c, 0x5641, 0x4d99, 0xac, 0xac, 0x26, 0xbe, 0xa9, 0x29, 0x6a, 0xb5);
DEFINE_GUID(IID_ICompositionDrawingSurfaceInterop, 0xfd04e6e3, 0xfe0c, 0x4c3c, 0xab, 0x19, 0xa0, 0x76, 0x01, 0xa5, 0x76, 0xee);
/* ICompositionGraphicsDeviceInterop: IID and member order (GetRenderingDevice, SetRenderingDevice) from
 * microsoft/windows-rs commit cd03f9369a896b62151242c1c3321e695df63cfc, metadata/win32/windowsuicompositioninterop.rdl */
typedef struct ICompGraphicsDeviceInterop ICompGraphicsDeviceInterop;
typedef struct ICompGraphicsDeviceInteropVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICompGraphicsDeviceInterop *This, REFIID iid, void **out);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICompGraphicsDeviceInterop *This);
    ULONG (STDMETHODCALLTYPE *Release)(ICompGraphicsDeviceInterop *This);
    HRESULT (STDMETHODCALLTYPE *GetRenderingDevice)(ICompGraphicsDeviceInterop *This, IUnknown **value);
    HRESULT (STDMETHODCALLTYPE *SetRenderingDevice)(ICompGraphicsDeviceInterop *This, IUnknown *value);
} ICompGraphicsDeviceInteropVtbl;
struct ICompGraphicsDeviceInterop { const ICompGraphicsDeviceInteropVtbl *lpVtbl; };
DEFINE_GUID(IID_ICompositionGraphicsDeviceInterop, 0xa116ff71, 0xf8bf, 0x4c8a, 0x9c, 0x98, 0x70, 0x77, 0x9a, 0x32, 0xa9, 0xc8);

DEFINE_GUID(IID_INitroCompositionTest, 0x37168b4f, 0xcb77, 0x4388, 0xa4, 0xf1, 0xa4, 0x71, 0x38, 0xfb, 0xcd, 0x25);
DEFINE_GUID(IID_INitroCompositionTest2, 0x5a1c7d3e, 0x92b4, 0x4f60, 0x8e, 0x1d, 0x6b, 0x3f, 0x07, 0xa2, 0xc9, 0x54);
