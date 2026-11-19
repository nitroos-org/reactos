/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test target for the compatibility log tool: a C++ exception nothing catches
 */

#include <stdio.h>

int main()
{
    printf("ndt_cpp: about to throw\n");
    fflush(stdout);
    throw 42;
}
