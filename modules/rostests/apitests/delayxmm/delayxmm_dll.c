/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Helper DLL of the delay-load test: functions that take floating point arguments
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <windef.h>
#include <winbase.h>

/* The weights tell which argument was lost */
double WINAPI DelayXmmSum(double a, double b, double c, double d)
{
    return a * 1000.0 + b * 100.0 + c * 10.0 + d;
}

float WINAPI DelayXmmSumFloat(float a, float b, float c, float d)
{
    return a * 1000.0f + b * 100.0f + c * 10.0f + d;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
