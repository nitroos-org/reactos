/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     IoIs32bitProcess test client: sends the requests of the test from its own process
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 *
 * Built for i386 and run on a 64-bit system, this is a WoW64 process: IoIs32bitProcess must be TRUE for every
 * request it sends. kmtest.exe loads the driver and runs this (see IoIs32bitProcess_user.c); the exit code is
 * the number of failed checks.
 */

#define WIN32_NO_STATUS
#define UNICODE
#include <windef.h>
#include <winbase.h>
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/mmfuncs.h>
#include <strsafe.h>
#include <stdio.h>

static LONG Failures;

#define ok(test, ...) \
    do { if (!(test)) { Failures++; printf("IoIs32bitProcess_client.c:%d: Test failed: ", __LINE__); printf(__VA_ARGS__); } } while (0)
#define trace(...) \
    do { printf("IoIs32bitProcess_client.c:%d: ", __LINE__); printf(__VA_ARGS__); } while (0)
#define ok_eq_print(value, expected, spec) \
    ok((value) == (expected), #value " = " spec ", expected " spec "\n", value, expected)
#define ok_eq_ulong(value, expected) ok_eq_print(value, expected, "%lu")
#define ok_eq_long(value, expected)  ok_eq_print(value, expected, "%ld")
#define ok_eq_hex(value, expected)   ok_eq_print((ULONG)(value), (ULONG)(expected), "0x%08lx")

#include "IoIs32bitProcess_cases.h"

int
main(VOID)
{
    BOOLEAN Wow64 = IsWow64Caller();

    trace("running as a %s process, IoIs32bitProcess expected %s\n",
          Wow64 ? "WoW64" : (sizeof(PVOID) == 8 ? "64-bit" : "native 32-bit"), Wow64 ? "TRUE" : "FALSE");
    RunIoIs32Requests(Wow64);
    trace("%ld failures\n", Failures);
    return Failures > 250 ? 250 : (int)Failures;
}
