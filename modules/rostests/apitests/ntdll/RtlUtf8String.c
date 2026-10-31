/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for RtlInitStringEx, the RtlInitUTF8String functions, the conversions between UTF8 and
 *              Unicode strings, RtlDoesNameContainWildCards and RtlStringFromGUIDEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef struct { USHORT Length; USHORT MaximumLength; PCHAR Buffer; } TEST_STRING;
typedef struct { USHORT Length; USHORT MaximumLength; PWCHAR Buffer; } TEST_USTRING;

typedef NTSTATUS (NTAPI *PFN_InitEx)(TEST_STRING *, const char *);
typedef VOID (NTAPI *PFN_Init)(TEST_STRING *, const char *);
typedef NTSTATUS (NTAPI *PFN_Utf8ToWide)(TEST_USTRING *, TEST_STRING *, BOOLEAN);
typedef NTSTATUS (NTAPI *PFN_WideToUtf8)(TEST_STRING *, TEST_USTRING *, BOOLEAN);
typedef VOID (NTAPI *PFN_Free)(TEST_STRING *);
typedef BOOLEAN (NTAPI *PFN_Wild)(TEST_USTRING *);
typedef NTSTATUS (NTAPI *PFN_GuidEx)(const GUID *, TEST_USTRING *, BOOLEAN);

static HMODULE Ntdll;

static void *Get(const char *Name)
{
    void *p = GetProcAddress(Ntdll, Name);

    if (!p)
        ok(!is_reactos(), "%s is not exported by ntdll.dll\n", Name);
    return p;
}

static void Test_Init(void)
{
    PFN_InitEx pInitStringEx = Get("RtlInitStringEx"), pInitUtf8Ex = Get("RtlInitUTF8StringEx");
    PFN_Init pInitUtf8 = Get("RtlInitUTF8String");
    TEST_STRING S;
    NTSTATUS Status;
    char *Big;

    if (!pInitStringEx || !pInitUtf8Ex || !pInitUtf8)
        return;

    memset(&S, 0xAA, sizeof(S));
    Status = pInitStringEx(&S, "abc");
    ok(Status == STATUS_SUCCESS && S.Length == 3 && S.MaximumLength == 4, "RtlInitStringEx: %lx %u %u\n", Status, S.Length, S.MaximumLength);

    memset(&S, 0xAA, sizeof(S));
    Status = pInitStringEx(&S, NULL);
    ok(Status == STATUS_SUCCESS && S.Length == 0 && S.MaximumLength == 0 && S.Buffer == NULL, "NULL source: %lx %u %u %p\n", Status, S.Length, S.MaximumLength, S.Buffer);

    Big = HeapAlloc(GetProcessHeap(), 0, 70000);
    memset(Big, 'a', 70000);
    Big[65534] = 0;
    memset(&S, 0xAA, sizeof(S));
    Status = pInitStringEx(&S, Big);
    ok(Status == STATUS_SUCCESS && S.Length == 65534 && S.MaximumLength == 65535, "65534 characters: %lx %u %u\n", Status, S.Length, S.MaximumLength);

    Big[65534] = 'a';
    Big[65535] = 0;
    memset(&S, 0xAA, sizeof(S));
    Status = pInitStringEx(&S, Big);
    ok(Status == STATUS_NAME_TOO_LONG && S.Length == 0 && S.MaximumLength == 0 && S.Buffer == Big,
       "65535 characters: %lx %u %u %p\n", Status, S.Length, S.MaximumLength, S.Buffer);
    memset(&S, 0xAA, sizeof(S));
    Status = pInitUtf8Ex(&S, Big);
    ok(Status == STATUS_NAME_TOO_LONG && S.Length == 0 && S.MaximumLength == 0 && S.Buffer == Big,
       "RtlInitUTF8StringEx, 65535 characters: %lx %u %u %p\n", Status, S.Length, S.MaximumLength, S.Buffer);

    memset(&S, 0xAA, sizeof(S));
    pInitUtf8(&S, "h\xC3\xA9llo");
    ok(S.Length == 6 && S.MaximumLength == 7, "RtlInitUTF8String: %u %u\n", S.Length, S.MaximumLength);
    memset(&S, 0xAA, sizeof(S));
    pInitUtf8(&S, Big);
    ok(S.Length == 65534 && S.MaximumLength == 65535 && S.Buffer == Big, "RtlInitUTF8String, long: %u %u\n", S.Length, S.MaximumLength);
    memset(&S, 0xAA, sizeof(S));
    Status = pInitUtf8Ex(&S, "x");
    ok(Status == STATUS_SUCCESS && S.Length == 1 && S.MaximumLength == 2, "RtlInitUTF8StringEx: %lx %u %u\n", Status, S.Length, S.MaximumLength);

    HeapFree(GetProcessHeap(), 0, Big);
}

static void Test_Utf8ToWide(void)
{
    PFN_Utf8ToWide pConvert = Get("RtlUTF8StringToUnicodeString");
    TEST_STRING In;
    TEST_USTRING U;
    WCHAR Buffer[16];
    NTSTATUS Status;
    char Source[] = "h\xC3\xA9llo\xE2\x82\xAC"; /* héllo and the euro sign */
    char *Big;

    if (!pConvert)
        return;

    In.Buffer = Source;
    In.Length = In.MaximumLength = sizeof(Source) - 1;

    memset(Buffer, 0xAA, sizeof(Buffer));
    U.Length = 0;
    U.MaximumLength = sizeof(Buffer);
    U.Buffer = Buffer;
    Status = pConvert(&U, &In, FALSE);
    ok(Status == STATUS_SUCCESS && U.Length == 12 && U.MaximumLength == sizeof(Buffer), "fixed buffer: %lx %u %u\n", Status, U.Length, U.MaximumLength);
    ok(!memcmp(Buffer, L"h\x00e9llo\x20ac", 12) && Buffer[6] == 0, "fixed buffer text\n");

    /* the terminator has to fit, and nothing is written when it does not */
    memset(Buffer, 0xAA, sizeof(Buffer));
    U.Length = 0;
    U.MaximumLength = 12;
    Status = pConvert(&U, &In, FALSE);
    ok(Status == STATUS_BUFFER_OVERFLOW && U.Length == 12 && U.MaximumLength == 12 && Buffer[0] == 0xAAAA,
       "no room for the terminator: %lx %u %u\n", Status, U.Length, U.MaximumLength);
    U.MaximumLength = 0;
    U.Length = 99;
    Status = pConvert(&U, &In, FALSE);
    ok(Status == STATUS_BUFFER_OVERFLOW && U.Length == 12, "empty buffer: %lx %u\n", Status, U.Length);
    U.MaximumLength = 14;
    Status = pConvert(&U, &In, FALSE);
    ok(Status == STATUS_SUCCESS && U.Length == 12 && Buffer[6] == 0, "exactly enough: %lx %u\n", Status, U.Length);

    /* allocation: length plus the terminator */
    memset(&U, 0, sizeof(U));
    Status = pConvert(&U, &In, TRUE);
    ok(Status == STATUS_SUCCESS && U.Length == 12 && U.MaximumLength == 14 && U.Buffer != NULL, "allocated: %lx %u %u\n", Status, U.Length, U.MaximumLength);
    if (U.Buffer)
    {
        ok(!memcmp(U.Buffer, L"h\x00e9llo\x20ac", 12) && U.Buffer[6] == 0, "allocated text\n");
        RtlFreeUnicodeString((PUNICODE_STRING)&U);
    }
    In.Length = 0;
    memset(&U, 0, sizeof(U));
    Status = pConvert(&U, &In, TRUE);
    ok(Status == STATUS_SUCCESS && U.Length == 0 && U.MaximumLength == 2 && U.Buffer != NULL && U.Buffer[0] == 0, "allocated empty: %lx %u %u\n", Status, U.Length, U.MaximumLength);
    if (U.Buffer)
        RtlFreeUnicodeString((PUNICODE_STRING)&U);

    /* invalid bytes become U+FFFD, an incomplete sequence one of them, a surrogate pair is made */
    In.Buffer = "a\xFF" "z";
    In.Length = 3;
    memset(Buffer, 0xAA, sizeof(Buffer));
    U.MaximumLength = sizeof(Buffer);
    U.Buffer = Buffer;
    Status = pConvert(&U, &In, FALSE);
    ok(Status == STATUS_SUCCESS && U.Length == 6 && Buffer[0] == 'a' && Buffer[1] == 0xfffd && Buffer[2] == 'z', "invalid byte: %lx %u\n", Status, U.Length);
    In.Buffer = "\xF0\x9F\x98\x80";
    In.Length = 4;
    Status = pConvert(&U, &In, FALSE);
    ok(Status == STATUS_SUCCESS && U.Length == 4 && Buffer[0] == 0xd83d && Buffer[1] == 0xde00, "surrogate pair: %lx %u\n", Status, U.Length);

    /* the result has to fit a UNICODE_STRING with its terminator */
    Big = HeapAlloc(GetProcessHeap(), 0, 70000);
    memset(Big, 'a', 70000);
    In.Buffer = Big;
    In.Length = 32766;
    memset(&U, 0, sizeof(U));
    Status = pConvert(&U, &In, TRUE);
    ok(Status == STATUS_SUCCESS && U.Length == 65532 && U.MaximumLength == 65534, "32766 characters: %lx %u %u\n", Status, U.Length, U.MaximumLength);
    if (U.Buffer)
        RtlFreeUnicodeString((PUNICODE_STRING)&U);
    In.Length = 32767;
    memset(&U, 0, sizeof(U));
    Status = pConvert(&U, &In, TRUE);
    ok(Status == STATUS_INVALID_PARAMETER_2 && U.Buffer == NULL, "32767 characters: %lx %p\n", Status, U.Buffer);
    HeapFree(GetProcessHeap(), 0, Big);
}

static void Test_WideToUtf8(void)
{
    PFN_WideToUtf8 pConvert = Get("RtlUnicodeStringToUTF8String");
    PFN_Free pFree = Get("RtlFreeUTF8String");
    static const WCHAR Source[] = L"h\x00e9llo\x20ac";
    TEST_USTRING U;
    TEST_STRING S;
    char Buffer[32];
    NTSTATUS Status;

    if (!pConvert || !pFree)
        return;

    U.Buffer = (PWCHAR)Source;
    U.Length = U.MaximumLength = sizeof(Source) - sizeof(WCHAR);

    memset(Buffer, 0xAA, sizeof(Buffer));
    S.Length = 0;
    S.MaximumLength = sizeof(Buffer);
    S.Buffer = Buffer;
    Status = pConvert(&S, &U, FALSE);
    ok(Status == STATUS_SUCCESS && S.Length == 9 && S.MaximumLength == sizeof(Buffer), "fixed buffer: %lx %u %u\n", Status, S.Length, S.MaximumLength);
    ok(!memcmp(Buffer, "h\xC3\xA9llo\xE2\x82\xAC", 10), "fixed buffer text (including the terminator)\n");

    /* a buffer that is too small takes the whole characters that fit with one byte kept for the terminator */
    memset(Buffer, 0xAA, sizeof(Buffer));
    S.Length = 99;
    S.MaximumLength = 5;
    Status = pConvert(&S, &U, FALSE);
    ok(Status == STATUS_BUFFER_TOO_SMALL && S.Length == 4 && !memcmp(Buffer, "h\xC3\xA9l", 4), "small buffer: %lx %u\n", Status, S.Length);
    memset(Buffer, 'x', sizeof(Buffer));
    S.Length = 99;
    S.MaximumLength = 1;
    Status = pConvert(&S, &U, FALSE);
    ok(Status == STATUS_BUFFER_TOO_SMALL && S.Length == 0 && Buffer[0] == 'x', "one-byte buffer: %lx %u\n", Status, S.Length);
    S.Length = 99;
    S.MaximumLength = 0;
    Status = pConvert(&S, &U, FALSE);
    ok(Status == STATUS_BUFFER_OVERFLOW && S.Length == 9, "empty buffer: %lx %u\n", Status, S.Length);
    S.MaximumLength = 10;
    Status = pConvert(&S, &U, FALSE);
    ok(Status == STATUS_SUCCESS && S.Length == 9 && Buffer[9] == 0, "exactly enough: %lx %u\n", Status, S.Length);

    /* allocation: length plus the terminator, released by RtlFreeUTF8String */
    memset(&S, 0, sizeof(S));
    Status = pConvert(&S, &U, TRUE);
    ok(Status == STATUS_SUCCESS && S.Length == 9 && S.MaximumLength == 10 && S.Buffer != NULL, "allocated: %lx %u %u\n", Status, S.Length, S.MaximumLength);
    if (S.Buffer)
    {
        ok(!memcmp(S.Buffer, "h\xC3\xA9llo\xE2\x82\xAC", 10), "allocated text\n");
        pFree(&S);
        ok(S.Buffer == NULL && S.Length == 0 && S.MaximumLength == 0, "after RtlFreeUTF8String: %p %u %u\n", S.Buffer, S.Length, S.MaximumLength);
        pFree(&S);
    }
    U.Length = 0;
    memset(&S, 0, sizeof(S));
    Status = pConvert(&S, &U, TRUE);
    ok(Status == STATUS_SUCCESS && S.Length == 0 && S.MaximumLength == 1 && S.Buffer != NULL && S.Buffer[0] == 0, "allocated empty: %lx %u %u\n", Status, S.Length, S.MaximumLength);
    if (S.Buffer)
        pFree(&S);

    /* an unpaired surrogate becomes U+FFFD */
    {
        static const WCHAR Lone[] = { 'a', 0xD800, 'b', 0 };

        U.Buffer = (PWCHAR)Lone;
        U.Length = 6;
        S.Buffer = Buffer;
        S.MaximumLength = sizeof(Buffer);
        Status = pConvert(&S, &U, FALSE);
        ok(Status == STATUS_SUCCESS && S.Length == 5 && !memcmp(Buffer, "a\xEF\xBF\xBD" "b", 5), "lone surrogate: %lx %u\n", Status, S.Length);
    }
}

static void Test_Misc(void)
{
    PFN_Wild pWild = Get("RtlDoesNameContainWildCards");
    PFN_GuidEx pGuidEx = Get("RtlStringFromGUIDEx");
    static const struct { const WCHAR *Text; BOOLEAN Expected; } Names[] =
    {
        { L"abc", FALSE }, { L"a*c", TRUE }, { L"a?c", TRUE }, { L"a<c", TRUE }, { L"a>c", TRUE },
        { L"a\"c", TRUE }, { L"a.c", FALSE }, { L"", FALSE }, { L"a|c", FALSE }, { L"[a]", FALSE },
    };
    static const GUID Guid = { 0x01234567, 0x89ab, 0xcdef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    TEST_USTRING U;
    WCHAR Buffer[64];
    NTSTATUS Status;
    ULONG i;

    if (pWild)
    {
        for (i = 0; i < RTL_NUMBER_OF(Names); i++)
        {
            U.Buffer = (PWCHAR)Names[i].Text;
            U.Length = U.MaximumLength = (USHORT)(wcslen(Names[i].Text) * sizeof(WCHAR));
            ok(pWild(&U) == Names[i].Expected, "RtlDoesNameContainWildCards(%ls) is %d\n", Names[i].Text, pWild(&U));
        }
    }

    if (pGuidEx)
    {
        memset(&U, 0, sizeof(U));
        Status = pGuidEx(&Guid, &U, TRUE);
        ok(Status == STATUS_SUCCESS && U.Length == 76 && U.MaximumLength == 78 && U.Buffer != NULL, "RtlStringFromGUIDEx, allocated: %lx %u %u\n", Status, U.Length, U.MaximumLength);
        if (U.Buffer)
        {
            ok(!wcscmp(U.Buffer, L"{01234567-89ab-cdef-0123-456789abcdef}"), "the text is %ls\n", U.Buffer);
            RtlFreeUnicodeString((PUNICODE_STRING)&U);
        }

        memset(Buffer, 0xAA, sizeof(Buffer));
        U.Length = 0;
        U.MaximumLength = 78;
        U.Buffer = Buffer;
        Status = pGuidEx(&Guid, &U, FALSE);
        ok(Status == STATUS_SUCCESS && U.Length == 76 && U.MaximumLength == 78 && Buffer[38] == 0, "fixed buffer: %lx %u\n", Status, U.Length);
        U.Length = 123;
        U.MaximumLength = 77;
        Status = pGuidEx(&Guid, &U, FALSE);
        ok(Status == STATUS_BUFFER_TOO_SMALL && U.Length == 123, "buffer short of the terminator: %lx %u\n", Status, U.Length);
        U.MaximumLength = 76;
        Status = pGuidEx(&Guid, &U, FALSE);
        ok(Status == STATUS_BUFFER_TOO_SMALL, "buffer for the text only: %lx\n", Status);
    }
}

START_TEST(RtlUtf8String)
{
    Ntdll = GetModuleHandleW(L"ntdll.dll");
    Test_Init();
    Test_Utf8ToWide();
    Test_WideToUtf8();
    Test_Misc();
}
