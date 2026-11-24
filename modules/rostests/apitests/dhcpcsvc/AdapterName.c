/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     The DHCP client service keeps and compares the adapter name (IFROW bDescr, up to 256 bytes) in
 *              buffers of its own: names of every length up to the limit must neither overrun them nor be left
 *              without a terminator
 */

#include <apitest.h>

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "adapname.h"

#define DESCR_MAX 256   /* MAXLEN_IFDESCR */
#define GUARD_CCH 64
#define GUARD_FILL 0xA5A5

typedef struct
{
    wchar_t Buf[DHCP_ADAPTER_NAME_WIDE_CCH];
    wchar_t Guard[GUARD_CCH];
} WIDE_WITH_GUARD;

static
BOOL
GuardIntact(const wchar_t *Guard)
{
    int i;

    for (i = 0; i < GUARD_CCH; i++)
        if (Guard[i] != GUARD_FILL)
            return FALSE;
    return TRUE;
}

/* a bDescr of Len characters ('a' + position, so two lengths never compare equal), NOT terminated when full */
static
void
MakeDescr(unsigned char *Descr, size_t Len)
{
    size_t i;

    memset(Descr, 0, DESCR_MAX);
    for (i = 0; i < Len && i < DESCR_MAX; i++)
        Descr[i] = (unsigned char)('a' + (i % 26));
}

#ifdef DHCPDESC_OLD_PATTERN

/* the conversion as the service had it: a 45-character buffer, the count from the description (evidence build only) */
START_TEST(AdapterName)
{
    static const size_t Lens[] = { 0, 1, 38, 44, 45, 46, 127, 128, 129, 200, 255, 256 };
    unsigned char Descr[DESCR_MAX];
    struct { wchar_t Small[45]; wchar_t Guard[GUARD_CCH]; } Old;
    char Tmp[DESCR_MAX + 1];
    size_t k, i;

    for (k = 0; k < sizeof(Lens) / sizeof(Lens[0]); k++)
    {
        MakeDescr(Descr, Lens[k]);
        memcpy(Tmp, Descr, DESCR_MAX);
        Tmp[DESCR_MAX] = 0;
        for (i = 0; i < GUARD_CCH; i++)
            Old.Guard[i] = GUARD_FILL;
        mbstowcs(Old.Small, Tmp, strlen(Tmp) + 1);
        ok(GuardIntact(Old.Guard), "len %lu: the conversion wrote past its 45-character buffer\n",
           (unsigned long)Lens[k]);
    }
}

#else

START_TEST(AdapterName)
{
    static const size_t Lens[] = { 0, 1, 38, 44, 45, 46, 127, 128, 129, 200, 255, 256 };
    unsigned char Descr[DESCR_MAX];
    char Name[DESCR_MAX];
    WIDE_WITH_GUARD W;
    wchar_t Expect[DESCR_MAX + 1];
    size_t k, i, n;

    for (k = 0; k < sizeof(Lens) / sizeof(Lens[0]); k++)
    {
        n = Lens[k];
        MakeDescr(Descr, n);

        /* the wide conversion for AdapterFindName */
        for (i = 0; i < GUARD_CCH; i++)
            W.Guard[i] = GUARD_FILL;
        memset(W.Buf, 0xFF, sizeof(W.Buf));
        DhcpAdapterNameToWide(W.Buf, Descr, sizeof(Descr));
        ok(GuardIntact(W.Guard), "len %lu: wide conversion wrote past its buffer\n", (unsigned long)n);
        for (i = 0; i < n; i++)
            Expect[i] = (wchar_t)('a' + (i % 26));
        Expect[n] = 0;
        ok(wcslen(W.Buf) == n, "len %lu: wide length %lu\n", (unsigned long)n, (unsigned long)wcslen(W.Buf));
        ok(wcscmp(W.Buf, Expect) == 0, "len %lu: wide name differs\n", (unsigned long)n);

        /* the name kept for the registry paths */
        memset(Name, 0x7E, sizeof(Name));
        DhcpAdapterNameCopy(Name, sizeof(Name), Descr, sizeof(Descr));
        i = strnlen(Name, sizeof(Name));
        ok(i < sizeof(Name), "len %lu: kept name is not terminated\n", (unsigned long)n);
        ok(i == (n < DHCP_ADAPTER_NAME_MAX ? n : DHCP_ADAPTER_NAME_MAX), "len %lu: kept name length %lu\n",
           (unsigned long)n, (unsigned long)i);
        ok(memcmp(Name, Descr, i) == 0, "len %lu: kept name differs\n", (unsigned long)n);
    }

    /* a destination of one character holds only the terminator */
    Name[0] = 'x';
    DhcpAdapterNameCopy(Name, 1, (const unsigned char *)"abc", 3);
    ok(Name[0] == '\0', "one-character destination: %d\n", Name[0]);

    /* a source that is full and unterminated is read only up to its size */
    memset(Descr, 'z', sizeof(Descr));
    DhcpAdapterNameToWide(W.Buf, Descr, 10);
    ok(wcslen(W.Buf) == 10, "source size honoured: %lu\n", (unsigned long)wcslen(W.Buf));

    /* the name of an interface row: the guid after \DEVICE\TCPIP_ (any case of the prefix), nothing otherwise */
    {
        static const wchar_t Good[] = L"\\DEVICE\\TCPIP_{E19C9217-81DB-4E02-BF1A-15E7C465C771}";
        static const wchar_t LowerPrefix[] = L"\\device\\tcpip_{E19C9217-81DB-4E02-BF1A-15E7C465C771}";
        static const wchar_t NoPrefix[] = L"Intel(R) PRO/1000 Network Connection";
        static const wchar_t OnlyPrefix[] = L"\\DEVICE\\TCPIP_";
        static const wchar_t Wide[] = { '\\', 'D', 'E', 'V', 'I', 'C', 'E', '\\', 'T', 'C', 'P', 'I', 'P', '_', 0x263A, 0 };
        wchar_t Long[300];
        char Out[DESCR_MAX];
        int Ret;

        memset(Out, 0x7E, sizeof(Out));
        Ret = DhcpAdapterNameFromWszName(Out, sizeof(Out), Good, 256);
        ok(Ret == 1, "guid name: %d\n", Ret);
        ok(strcmp(Out, "{E19C9217-81DB-4E02-BF1A-15E7C465C771}") == 0, "guid name: '%s'\n", Out);

        Ret = DhcpAdapterNameFromWszName(Out, sizeof(Out), LowerPrefix, 256);
        ok(Ret == 1, "lower case prefix: %d\n", Ret);
        ok(strcmp(Out, "{E19C9217-81DB-4E02-BF1A-15E7C465C771}") == 0, "lower case prefix: '%s'\n", Out);

        ok(DhcpAdapterNameFromWszName(Out, sizeof(Out), NoPrefix, 256) == 0, "no prefix\n");
        ok(DhcpAdapterNameFromWszName(Out, sizeof(Out), OnlyPrefix, 256) == 0, "prefix only\n");
        ok(DhcpAdapterNameFromWszName(Out, sizeof(Out), Wide, 256) == 0, "name above 0x7f\n");
        ok(DhcpAdapterNameFromWszName(Out, 0, Good, 256) == 0, "empty destination\n");

        /* the source is read only up to its size: a full, unterminated name */
        Ret = DhcpAdapterNameFromWszName(Out, sizeof(Out), Good, 14 + 5);
        ok(Ret == 1 && strcmp(Out, "{E19C") == 0, "short source: %d '%s'\n", Ret, Out);

        /* a long name is cut and terminated */
        wcscpy(Long, L"\\DEVICE\\TCPIP_");
        for (i = 14; i < 299; i++)
            Long[i] = L'a';
        Long[299] = 0;
        memset(Out, 0x7E, sizeof(Out));
        Ret = DhcpAdapterNameFromWszName(Out, sizeof(Out), Long, 300);
        ok(Ret == 1 && strlen(Out) == DHCP_ADAPTER_NAME_MAX, "long name: %d %lu\n", Ret, (unsigned long)strlen(Out));
        Ret = DhcpAdapterNameFromWszName(Out, 8, Good, 256);
        ok(Ret == 1 && strlen(Out) == 7, "small destination: %d %lu\n", Ret, (unsigned long)strlen(Out));
    }
}

#endif
