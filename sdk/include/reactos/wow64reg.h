/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* A native 64-bit caller of NtOpenKey / NtOpenKeyEx / NtCreateKey has its
 * KEY_WOW64_32KEY / KEY_WOW64_64KEY bits ignored by the kernel, as on
 * Windows: the registry API selects the view. advapi32 asks the kernel to
 * apply the view it was given by setting this reserved access bit next to
 * the selector. The kernel removes it before the access check. A process
 * running under WoW64 needs no marker: the kernel always applies its view. */
#define CM_WOW64_VIEW_REQUEST   0x08000000

/* Shared by the configuration manager and advapi32's nested-create retry.
 * A shortened path must retain the destination of the original request. */
/* Windows 7 / Server 2008 R2: shared Software subtrees. Match complete
 * components: similarly named application keys still use the redirected view.
 * See the registry view matrix fixture and its reference measurements. */
static const PCWSTR Wow64SharedSoftware[] = {
    L"\\Clients",
    L"\\Microsoft\\COM3",
    L"\\Microsoft\\Cryptography\\Calais\\Current",
    L"\\Microsoft\\Cryptography\\Calais\\Readers",
    L"\\Microsoft\\Cryptography\\Services",
    L"\\Microsoft\\CTF\\SystemShared",
    L"\\Microsoft\\CTF\\TIP",
    L"\\Microsoft\\DFS",
    L"\\Microsoft\\Driver Signing",
    L"\\Microsoft\\EnterpriseCertificates",
    L"\\Microsoft\\EventSystem",
    L"\\Microsoft\\MSMQ",
    L"\\Microsoft\\Non-Driver Signing",
    L"\\Microsoft\\Notepad\\DefaultFonts",
    L"\\Microsoft\\Ole",
    L"\\Microsoft\\Ras",
    L"\\Microsoft\\Rpc",
    L"\\Microsoft\\Software\\Microsoft\\Shared Tools\\Msinfo",
    L"\\Microsoft\\SystemCertificates",
    L"\\Microsoft\\TermServLicensing",
    L"\\Microsoft\\Transaction Server",
    L"\\Microsoft\\Windows\\CurrentVersion\\App Paths",
    L"\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Cursors\\Schemes",
    L"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers",
    L"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons",
    L"\\Microsoft\\Windows\\CurrentVersion\\Explorer\\KindMap",
    L"\\Microsoft\\Windows\\CurrentVersion\\Group Policy",
    L"\\Microsoft\\Windows\\CurrentVersion\\Policies",
    L"\\Microsoft\\Windows\\CurrentVersion\\PreviewHandlers",
    L"\\Microsoft\\Windows\\CurrentVersion\\Setup",
    L"\\Microsoft\\Windows\\CurrentVersion\\Telephony\\Locations",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\Console",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\FontDPI",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\FontLink",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\FontMapper",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\LanguagePack",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\Perflib",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\Ports",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\Print",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
    L"\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones",
    L"\\Policies",
    L"\\RegisteredApplications",
};
