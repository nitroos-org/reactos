/*
 * PROJECT:         ReactOS api tests
 * LICENSE:         GPLv2+ - See COPYING in the top level directory
 * PURPOSE:         Test for FormatMessage and resources
 * PROGRAMMERS:     Pierre Schweitzer
 */

#include <apitest.h>
#include <FormatMessage.h>

WCHAR First[] = L"This is a test message.\r\n";
WCHAR Second[] = L"This is a second test message.\r\n";

START_TEST(FormatMessage)
{
    PWSTR Buffer;
    DWORD Written;

    Buffer = NULL;
    Written = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                             NULL, MSG_FIRST_MESSAGE, 0, (LPWSTR)&Buffer, 0, NULL);
    ok(Written != 0, "Unexpected error: %lx\n", GetLastError());
    ok(Buffer != NULL, "No buffer allocated\n");
    ok(Written == (sizeof(First) - sizeof(UNICODE_NULL)) / sizeof(WCHAR),
       "Invalid size: %ld (expected: %d)\n",
       Written, (sizeof(First) - sizeof(UNICODE_NULL)) / sizeof(WCHAR));
    ok(RtlCompareMemory(Buffer, First, sizeof(First) - sizeof(UNICODE_NULL)) ==
                        sizeof(First) - sizeof(UNICODE_NULL),
       "Mismatching string: %S (expected : %S)\n", Buffer, First);
    LocalFree(Buffer);

    Buffer = NULL;
    Written = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                             NULL, MSG_SECOND_MESSAGE, 0, (LPWSTR)&Buffer, 0, NULL);
    ok(Written != 0, "Unexpected error: %lx\n", GetLastError());
    ok(Buffer != NULL, "No buffer allocated\n");
    ok(Written == (sizeof(Second) - sizeof(UNICODE_NULL)) / sizeof(WCHAR),
       "Invalid size: %ld (expected: %d)\n",
       Written, (sizeof(Second) - sizeof(UNICODE_NULL)) / sizeof(WCHAR));
    ok(RtlCompareMemory(Buffer, Second, sizeof(Second) - sizeof(UNICODE_NULL)) ==
       sizeof(Second) - sizeof(UNICODE_NULL),
       "Mismatching string: %S (expected: %S)\n", Buffer, Second);
    LocalFree(Buffer);

    Buffer = NULL;
    Written = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER,
                             NULL, MSG_SECOND_MESSAGE + 1, 0, (LPWSTR)&Buffer, 0, NULL);
    ok(Written == 0, "Unexpected success: %ld\n", Written);
    ok(Buffer == NULL, "Unexpected success: %p\n", Buffer);
    ok(GetLastError() == 0x13d, "Unexpected error: %lx\n", GetLastError());

    /* The system message table has no text for the 12000-12999 range (the Internet errors of
       wininet.dll, ERROR_FLT_* are HRESULTs), measured on Windows Server 2022: return 0, error 317.
       The IPsec errors from 13000 on are in the table. */
    {
        char Out[256];
        DWORD Id;

        for (Id = 12000; Id <= 12030; Id++)
        {
            SetLastError(0);
            Written = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                     NULL, Id, 0, Out, sizeof(Out), NULL);
            ok(Written == 0, "%lu: FormatMessageA returned %lu\n", Id, Written);
            ok(GetLastError() == ERROR_MR_MID_NOT_FOUND, "%lu: error %lu\n", Id, GetLastError());
        }
        Written = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, 13000, 0, Out, sizeof(Out), NULL);
        ok(Written != 0, "13000: FormatMessageA returned 0, error %lu\n", GetLastError());
    }
}
