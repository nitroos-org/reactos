/*
 * PROJECT:     ReactOS Kernel-Mode Tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     User-mode half of the ObRegisterCallbacks test (obcbtest.sys): prints the
 *              access of the handles it gets and says PASS or FAIL.
 *                obcbcheck stripped   callbacks A and B are registered
 *                obcbcheck full       no callbacks: everything asked for is granted
 * COPYRIGHT:   Copyright 2026 Tomas Srnka (tomas.srnka@e2b.dev)
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <stdio.h>
#include <string.h>

typedef struct _OBI
{
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} OBI;

static LONG (NTAPI *pNtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static ACCESS_MASK Granted(HANDLE h)
{
    OBI Info;
    ULONG Len;
    memset(&Info, 0, sizeof(Info));
    if (pNtQueryObject(h, 0 /* ObjectBasicInformation */, &Info, sizeof(Info), &Len) != 0)
        return 0xFFFFFFFF;
    return Info.GrantedAccess;
}

static int Failures;
static void Expect(const char *what, ACCESS_MASK got, ACCESS_MASK mustHave, ACCESS_MASK mustLack)
{
    int ok = ((got & mustHave) == mustHave) && !(got & mustLack);
    printf("%s %s: granted %08lx (must have %08lx, must lack %08lx)\n", ok ? "PASS" : "FAIL", what,
           (unsigned long)got, (unsigned long)mustHave, (unsigned long)mustLack);
    if (!ok) Failures++;
}

int main(int argc, char **argv)
{
    int stripped = (argc > 1 && !strcmp(argv[1], "stripped"));
    ACCESS_MASK Want = PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
    ACCESS_MASK Keep = PROCESS_QUERY_INFORMATION;
    ACCESS_MASK Gone = PROCESS_SET_QUOTA | PROCESS_TERMINATE;
    HANDLE h, d, t;

    pNtQueryObject = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
    if (!pNtQueryObject) { printf("FAIL no NtQueryObject\n"); return 2; }

    /* OpenProcess of ourselves: the create-handle callbacks */
    h = OpenProcess(Want, FALSE, GetCurrentProcessId());
    if (!h) { printf("FAIL OpenProcess error %lu\n", GetLastError()); return 2; }
    if (stripped) Expect("OpenProcess(self) with callbacks", Granted(h), Keep, Gone);
    else Expect("OpenProcess(self) without callbacks", Granted(h), Want, 0);

    /* DuplicateHandle of the pseudo handle asking for everything: the duplicate-handle callbacks */
    if (DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &d,
                        Want, FALSE, 0))
    {
        if (stripped) Expect("DuplicateHandle(self) with callbacks", Granted(d), Keep, Gone);
        else Expect("DuplicateHandle(self) without callbacks", Granted(d), Want, 0);
        CloseHandle(d);
    }
    else
    {
        printf("FAIL DuplicateHandle error %lu\n", GetLastError());
        Failures++;
    }

    /* threads are not registered by the test driver: untouched */
    t = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, FALSE, GetCurrentThreadId());
    if (t)
    {
        Expect("OpenThread(self), no thread callbacks", Granted(t),
               THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, 0);
        CloseHandle(t);
    }
    CloseHandle(h);

    printf("%s\n", Failures ? "RESULT FAIL" : "RESULT PASS");
    return Failures ? 1 : 0;
}
