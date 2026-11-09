/*
 * PROJECT:     apphelp_apitest
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Helper for the shimload test: reports whether the shim library is in the process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windows.h>

int main(void)
{
    if (GetModuleHandleW(L"acgenral.dll"))
        return 37;
    /* a compatibility layer (appcache test) */
    return GetModuleHandleW(L"aclayers.dll") ? 39 : 38;
}
