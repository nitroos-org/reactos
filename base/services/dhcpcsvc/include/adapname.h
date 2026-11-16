/*
 * PROJECT:     ReactOS DHCP client service
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Bounded handling of the adapter name the stack reports (IFROW bDescr, up to MAXLEN_IFDESCR bytes)
 *
 * Header-only on purpose: the service and its API test use the same code.
 */

#ifndef _DHCPCSVC_ADAPNAME_H
#define _DHCPCSVC_ADAPNAME_H

#include <stdlib.h>

/* Characters of an adapter name that the registry paths built in dhclient.c ("...\Interfaces\" + name into 200-byte
 * buffers) can hold. The name kept in the interface_info is cut here. */
#define DHCP_ADAPTER_NAME_MAX 128

/* The wide characters (with the terminating zero) that DhcpAdapterNameToWide needs: bDescr is at most
 * MAXLEN_IFDESCR bytes, a multi-byte character never gives more than one wide character per byte. */
#define DHCP_ADAPTER_NAME_WIDE_CCH (256 + 1)

/*
 * Copies the adapter name, at most DHCP_ADAPTER_NAME_MAX characters, always zero-terminated. The source is the bDescr
 * array (IfCch bytes, it need not be terminated when it is full).
 */
static __inline void
DhcpAdapterNameCopy(char *Dest, size_t DestCch, const unsigned char *Src, size_t SrcCch)
{
    size_t Max = DestCch ? DestCch - 1 : 0;
    size_t n;

    if (!DestCch)
        return;
    if (Max > DHCP_ADAPTER_NAME_MAX)
        Max = DHCP_ADAPTER_NAME_MAX;
    for (n = 0; n < Max && n < SrcCch && Src[n]; n++)
        Dest[n] = (char)Src[n];
    Dest[n] = '\0';
}

/*
 * Converts the whole adapter name to wide characters for a comparison. Out holds DHCP_ADAPTER_NAME_WIDE_CCH
 * characters, never more are written; an unconvertible name gives an empty string (it matches nothing).
 */
static __inline void
DhcpAdapterNameToWide(wchar_t *Out, const unsigned char *Src, size_t SrcCch)
{
    char Tmp[DHCP_ADAPTER_NAME_WIDE_CCH];
    size_t n, Conv;

    for (n = 0; n < DHCP_ADAPTER_NAME_WIDE_CCH - 1 && n < SrcCch && Src[n]; n++)
        Tmp[n] = (char)Src[n];
    Tmp[n] = '\0';

    Conv = mbstowcs(Out, Tmp, DHCP_ADAPTER_NAME_WIDE_CCH - 1);
    if (Conv == (size_t)-1)
        Conv = 0;
    Out[Conv] = L'\0';
}

#endif /* _DHCPCSVC_ADAPNAME_H */
