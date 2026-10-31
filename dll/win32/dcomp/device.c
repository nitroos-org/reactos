/*
 * Copyright 2020 Nikolay Sivov for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "objidl.h"
#include "dxgi.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

/* DirectComposition is not implemented: every entry point that creates something fails with E_NOTIMPL, and
 * the module exposes no COM classes. The module exists so that programs importing it (statically, or by
 * delay load) get their imports resolved and take their no-DirectComposition path at the first call. */

HRESULT WINAPI DCompositionCreateDevice(IDXGIDevice *dxgi_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p.\n", dxgi_device, debugstr_guid(iid), device);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionCreateDevice2(IUnknown *rendering_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionCreateDevice3(IUnknown *rendering_device, REFIID iid, void **device)
{
    FIXME("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionCreateSurfaceHandle(DWORD access, SECURITY_ATTRIBUTES *attributes, HANDLE *handle)
{
    FIXME("%#lx, %p, %p.\n", access, attributes, handle);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionAttachMouseDragToHwnd(void *visual, HWND hwnd, BOOL enable)
{
    FIXME("%p, %p, %d.\n", visual, hwnd, enable);

    return E_NOTIMPL;
}

HRESULT WINAPI DCompositionAttachMouseWheelToHwnd(void *visual, HWND hwnd, BOOL enable)
{
    FIXME("%p, %p, %d.\n", visual, hwnd, enable);

    return E_NOTIMPL;
}

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **obj)
{
    FIXME("%s, %s, %p.\n", debugstr_guid(clsid), debugstr_guid(iid), obj);

    *obj = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllGetActivationFactory(void *classid, void **factory)
{
    FIXME("%p, %p.\n", classid, factory);

    *factory = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DwmEnableMMCSS(BOOL enable)
{
    FIXME("%d.\n", enable);

    return E_NOTIMPL;
}

HRESULT WINAPI DwmFlush(void)
{
    FIXME("\n");

    return E_NOTIMPL;
}

HRESULT WINAPI DwmpEnableDDASupport(void)
{
    FIXME("\n");

    return E_NOTIMPL;
}
