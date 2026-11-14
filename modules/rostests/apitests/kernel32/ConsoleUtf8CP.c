/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     A console accepts the UTF-8 code page (65001) for output and input
 */

#include "precomp.h"

START_TEST(ConsoleUtf8CP)
{
    UINT OldOut, OldIn;
    BOOL Ret;

    FreeConsole();
    ok(AllocConsole(), "Couldn't alloc console\n");

    OldOut = GetConsoleOutputCP();
    OldIn = GetConsoleCP();
    ok(OldOut != 0, "GetConsoleOutputCP failed with %lu\n", GetLastError());
    ok(OldIn != 0, "GetConsoleCP failed with %lu\n", GetLastError());

    /* dotnet.exe and the .NET console class select UTF-8 this way; a refusal ends in an unhandled IOException */
    SetLastError(0xdeadbeef);
    Ret = SetConsoleOutputCP(CP_UTF8);
    ok(Ret, "SetConsoleOutputCP(CP_UTF8) failed with %lu\n", GetLastError());
    ok(GetConsoleOutputCP() == CP_UTF8, "Output code page is %u, expected %u\n", GetConsoleOutputCP(), CP_UTF8);

    SetLastError(0xdeadbeef);
    Ret = SetConsoleCP(CP_UTF8);
    ok(Ret, "SetConsoleCP(CP_UTF8) failed with %lu\n", GetLastError());
    ok(GetConsoleCP() == CP_UTF8, "Input code page is %u, expected %u\n", GetConsoleCP(), CP_UTF8);

    /* Back to the original code pages and to UTF-8 again */
    ok(SetConsoleOutputCP(OldOut), "SetConsoleOutputCP(%u) failed with %lu\n", OldOut, GetLastError());
    ok(GetConsoleOutputCP() == OldOut, "Output code page is %u, expected %u\n", GetConsoleOutputCP(), OldOut);
    SetLastError(0xdeadbeef);
    Ret = SetConsoleOutputCP(CP_UTF8);
    ok(Ret, "SetConsoleOutputCP(CP_UTF8) failed with %lu\n", GetLastError());
    ok(GetConsoleOutputCP() == CP_UTF8, "Output code page is %u, expected %u\n", GetConsoleOutputCP(), CP_UTF8);

    SetConsoleOutputCP(OldOut);
    SetConsoleCP(OldIn);
    FreeConsole();
}
