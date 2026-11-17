/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv6 addresses in text form, and the names of the "<address>.ipv6-literal.net" form (the name
 *              Windows clients use to give an IPv6 address where only a host name fits, e.g. in a UNC path)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Used by ws2_32 (GetAddrInfoW and its relatives) and dnsapi (DnsQuery_W): both answer such a name from the name
 * itself, without a DNS query. The includer provides the Windows and NT type declarations (RtlIpv6StringToAddressW
 * of ntdll, wcslen/wcscmp/wcschr, IN6_ADDR, BOOL, ULONG) before this header.
 *
 * The rules were measured on Windows Server 2022 (21H2, build 20348), GetAddrInfoW / GetAddrInfoExW / getaddrinfo /
 * DnsQuery_W alike:
 *  - the name ends in ".ipv6-literal.net", the suffix in exactly this (lower) case, optionally followed by one
 *    root dot; nothing else may follow it
 *  - in the rest of the name every '-' stands for ':' and every lower case 's' for '%'; the result is an IPv6
 *    address in text form ("2001-db8--1" is 2001:db8::1, "fe80--1s4" is fe80::1%4)
 *  - the text may carry what the text form allows: an IPv4 tail ("0--ffff-1.2.3.4"), upper case hex digits,
 *    leading zeros, a bracketed form with a port (the port is not used), a literal ':' or '%'
 *  - a scope is decimal digits only (leading zeros allowed), at most 0xFFFFFFFF; "s0" is scope 0
 */

#ifndef _REACTOS_IPV6LITERAL_H
#define _REACTOS_IPV6LITERAL_H

/* Number of characters of the text form (without the suffix) that is looked at: the longest address text */
#define IPV6LITERAL_TEXT_MAX 64

/*
 * An IPv6 address in text form: "::1", "fe80::1%4", and both of them in brackets, with or without a port
 * ("[::1]:80", the port is not used). A numeric scope id after '%' is the only zone accepted; it must fit 32 bits.
 */
static inline
BOOL
Ipv6TextToAddress(PCWSTR AddressString,
                  IN6_ADDR *pAddress,
                  ULONG *pScopeId)
{
    WCHAR Text[IPV6LITERAL_TEXT_MAX];
    PCWSTR Terminator = NULL;
    PCWSTR Scope, Close;
    SIZE_T Length;
    ULONGLONG Id = 0;

    *pScopeId = 0;
    if (!AddressString || !wcschr(AddressString, L':'))
        return FALSE;

    if (*AddressString == L'[')
    {
        Close = wcschr(AddressString, L']');
        if (!Close)
            return FALSE;

        /* After the bracket: nothing, or a port */
        Scope = Close + 1;
        if (*Scope == L':')
        {
            if (!*++Scope)
                return FALSE;
            for (; *Scope; Scope++)
            {
                if (*Scope < L'0' || *Scope > L'9')
                    return FALSE;
            }
        }
        else if (*Scope)
        {
            return FALSE;
        }

        Length = Close - (AddressString + 1);
        if (!Length || Length >= IPV6LITERAL_TEXT_MAX)
            return FALSE;
        RtlCopyMemory(Text, AddressString + 1, Length * sizeof(WCHAR));
        Text[Length] = UNICODE_NULL;
        AddressString = Text;
    }

    if (!NT_SUCCESS(RtlIpv6StringToAddressW(AddressString, &Terminator, (PVOID)pAddress)) || !Terminator)
        return FALSE;

    if (*Terminator == L'%')
    {
        Scope = Terminator + 1;
        if (!*Scope)
            return FALSE;
        for (; *Scope; Scope++)
        {
            if (*Scope < L'0' || *Scope > L'9')
                return FALSE;
            Id = Id * 10 + (*Scope - L'0');
            if (Id > 0xFFFFFFFFULL)
                return FALSE;
        }
        *pScopeId = (ULONG)Id;
        return TRUE;
    }

    return *Terminator == UNICODE_NULL;
}

/*
 * Is Name a "<address>.ipv6-literal.net" name, and which address does it mean? TRUE with the address and the
 * scope id (0 when the name has none); FALSE for every other name, including names with the suffix whose
 * address part is not an address.
 */
static inline
BOOL
Ipv6LiteralNameToAddress(PCWSTR Name,
                         IN6_ADDR *pAddress,
                         ULONG *pScopeId)
{
    static const WCHAR Suffix[] = L".ipv6-literal.net";
    const SIZE_T SuffixLength = (sizeof(Suffix) / sizeof(WCHAR)) - 1;
    WCHAR Text[IPV6LITERAL_TEXT_MAX];
    SIZE_T Length, i;

    if (!Name)
        return FALSE;

    Length = wcslen(Name);

    /* One root dot may follow the suffix */
    if (Length && Name[Length - 1] == L'.')
        Length--;

    if (Length <= SuffixLength || Length - SuffixLength >= IPV6LITERAL_TEXT_MAX)
        return FALSE;

    Length -= SuffixLength;
    if (wcsncmp(Name + Length, Suffix, SuffixLength) != 0)
        return FALSE;

    for (i = 0; i < Length; i++)
    {
        WCHAR c = Name[i];

        if (c == L'-')
            c = L':';
        else if (c == L's')
            c = L'%';
        Text[i] = c;
    }
    Text[Length] = UNICODE_NULL;

    return Ipv6TextToAddress(Text, pAddress, pScopeId);
}

#endif /* _REACTOS_IPV6LITERAL_H */
