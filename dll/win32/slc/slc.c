/*
 * PROJECT:     ReactOS Software Licensing client forwarder
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     slc.dll: the SL* client API; calls go to sppc.dll, SLGetWindowsInformation lives here
 *
 * The Edge WebView2 runtime (msedgewebview2.exe, Chromium 94) delay-loads SLC.dll!SLGetWindowsInformation;
 * without the module the browser process dies with 0xC06D007E at startup and every WebView2 host
 * (GraphPad Prism 11, ...) shows an empty page.
 *
 * Like sppc.dll this client has no licensing store of Windows: the Windows information values
 * (Kernel-*, Security-SPP-*) are not present, so a lookup answers SL_E_VALUE_NOT_FOUND.
 */

#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <slpublic.h>

HRESULT
WINAPI
SLGetWindowsInformation(_In_ PCWSTR pwszValueName,
                        _Out_opt_ SLDATATYPE *peDataType,
                        _Out_ UINT *pcbValue,
                        _Outptr_result_bytebuffer_maybenull_(*pcbValue) PBYTE *ppbValue)
{
    if (!pwszValueName || !pcbValue || !ppbValue)
        return E_INVALIDARG;
    *pcbValue = 0;
    *ppbValue = NULL;
    return SL_E_VALUE_NOT_FOUND;
}
