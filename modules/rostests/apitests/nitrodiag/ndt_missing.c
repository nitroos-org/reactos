/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test target for the compatibility log tool: needs ndt_full.dll (and one function of it)
 */

#include <stdio.h>
#include <windows.h>

int WINAPI NdFuncA(void);
int WINAPI NdFuncB(void);

int main(int argc, char **argv)
{
    printf("ndt_missing: A=%d B=%d\n", NdFuncA(), NdFuncB());
    return 0;
}
