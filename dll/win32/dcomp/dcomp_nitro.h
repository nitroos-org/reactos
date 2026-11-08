/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Nitro-private interfaces of the Windows.UI.Composition objects in dcomp.dll (not Windows API)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * INitroDrawingSurfaceInterop has the six methods of the documented ICompositionDrawingSurfaceInterop with the
 * documented signatures (learn.microsoft.com), but its IID and vtable order are OURS: no clean public source
 * (learn, Wine IDLs, mingw-w64) gives the real IID or vtable order, so the real interface stays unimplemented
 * until one does. Nothing running on Windows asks for this IID.
 * INitroCompositionTest is a test hook: render the visual tree below a visual into a bitmap on the CPU and dump
 * the tree as text. The real presentation path (stage 4) does not use it.
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

DEFINE_GUID(IID_INitroDrawingSurfaceInterop, 0xc8b9638c, 0x5641, 0x4d99, 0xac, 0xac, 0x26, 0xbe, 0xa9, 0x29, 0x6a, 0xb5);
DEFINE_GUID(IID_INitroCompositionTest, 0x37168b4f, 0xcb77, 0x4388, 0xa4, 0xf1, 0xa4, 0x71, 0x38, 0xfb, 0xcd, 0x25);
