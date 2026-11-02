/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     DLL with a read-only shared section (as Qt6Core.dll has) and a pointer that needs a relocation
 */

#include <windows.h>

#ifdef __GNUC__
/* GCC cannot make a const object shared, so emit the section by hand: data, shared, read-only (the flag order matters to gas) */
extern const int SharedRoValue __asm__("SharedRoValue");
__asm__(".section .rshr, \"dsr\"\n"
        ".globl SharedRoValue\n"
        "SharedRoValue:\n"
        ".long 0x1234\n"
        ".text\n");
#else
#pragma section(".rshr", read, shared)
__declspec(allocate(".rshr")) const int SharedRoValue = 0x1234;
#endif

/* In .data: holds an absolute address, so it is fixed up when the image is relocated */
__declspec(dllexport) const int *SharedRoPointer = &SharedRoValue;

BOOL
WINAPI
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_ LPVOID lpvReserved)
{
    return TRUE;
}
