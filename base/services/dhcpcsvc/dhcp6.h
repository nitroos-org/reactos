/*
 * PROJECT:     ReactOS DHCP client service
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     DHCPv6 client (RFC 8415): names shared by the client, the IP Helper and dhcpcsvc6.dll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/*
 * Where the client keeps what it learned. All of it under
 *   HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
 * the machine-wide DUID there, the rest per interface under Interfaces\<adapter GUID, with braces>.
 * The values of an interface are written by the service when a Reply arrives and removed when the interface loses
 * its reason for DHCPv6 (the router stops saying "other configuration", the link goes away) and when the service
 * starts or stops: what a stateless client learned is not kept across a restart.
 */
#define DHCP6_VALUE_DUID            "Dhcpv6DUID"                    /* REG_BINARY, DUID-LLT, machine-wide, created once */
#define DHCP6_VALUE_IAID            "Dhcpv6Iaid"                    /* REG_DWORD, interface */
#define DHCP6_VALUE_NAMESERVER      "Dhcpv6NameServer"              /* REG_SZ, IPv6 text, blank separated */
#define DHCP6_VALUE_SEARCHLIST      "Dhcpv6DomainSearchList"        /* REG_SZ, names, blank separated */
#define DHCP6_VALUE_SERVER          "Dhcpv6ServerAddress"           /* REG_SZ, link-local address of the server, no zone */
#define DHCP6_VALUE_REFRESH         "Dhcpv6InformationRefreshTime"  /* REG_DWORD seconds */
#define DHCP6_VALUE_OPTIONS         "Dhcpv6Options"                 /* REG_BINARY, the options of the last Reply */
#define DHCP6_VALUE_REPLIES         "Dhcpv6ReplyCount"              /* REG_DWORD, incremented with every accepted Reply */

#define DHCP6_PARAMETERS_KEY        "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
#define DHCP6_INTERFACES_KEY        DHCP6_PARAMETERS_KEY "\\Interfaces"

/* The event dhcpcsvc6.dll signals to make the client send a new Information-Request at once (administrators and
   SYSTEM only) */
#define DHCP6_FORCE_EVENT_NAME      L"Global\\NitroDhcpv6Inform"

/* Started by ServiceMain after the adapter discovery; stops when hStopEvent is signaled. INVALID_HANDLE_VALUE on failure */
HANDLE StartDhcp6Client(HANDLE hStopEvent);
