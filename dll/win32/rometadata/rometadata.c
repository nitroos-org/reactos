/*
 * PROJECT:     ReactOS Windows Runtime metadata (rometadata.dll)
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     MetaDataGetDispenser, the entry point of the metadata reader
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Microsoft.WindowsAppRuntime.dll (the Windows App SDK runtime, which PowerToys and every other
 * WinUI 3 application loads first) imports MetaDataGetDispenser from rometadata.dll. Without the
 * library the loader fails with "module not found" before any application code runs. The metadata
 * reader itself (IMetaDataDispenser, IMetaDataImport2) is not implemented: the function reports
 * E_NOTIMPL, so a caller that really needs to read a .winmd file fails there, visibly.
 */

#include <windef.h>
#include <winbase.h>
#include <winerror.h>

HRESULT
WINAPI
MetaDataGetDispenser(
    _In_ REFCLSID rclsid,
    _In_ REFIID riid,
    _Out_ LPVOID *ppv)
{
    UNREFERENCED_PARAMETER(rclsid);
    UNREFERENCED_PARAMETER(riid);

    if (!ppv)
        return E_INVALIDARG;

    *ppv = NULL;
    return E_NOTIMPL;
}
