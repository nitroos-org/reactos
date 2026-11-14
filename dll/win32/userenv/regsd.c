/*
 * PROJECT:     ReactOS system libraries
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The control flags of the security descriptors of the system hive keys, on an older install
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Windows 10 holds the roots of the SYSTEM and SOFTWARE hives, and the keys below that carry a copy of their
 * DACL, with SE_DACL_AUTO_INHERITED (SDDL "AI"), most of them also protected ("PAI"); a few keys carry neither
 * (HKLM\SOFTWARE\Microsoft is "D:" with explicit ACEs). Setup gives a new install those flags (regacl_sd.h).
 * An install made before has the roots protected without AI, and the keys below with no flags of their own.
 *
 * Only the control flags change here: every ACE stays as it is (the INHERITED_ACE mark of an ACE that was not
 * stored is dropped, since the key now holds it itself). No key becomes more permissive.
 */

#include "precomp.h"

#include <accctrl.h>
#include <aclapi.h>

#define NDEBUG
#include <debug.h>

enum
{
    /* Protected and auto-inherited (Windows: PAI) */
    RegSdPai,
    /* Neither, held as the key's own (Windows: the descriptor has its own ACEs and no flags) */
    RegSdPlain,
    /* Auto-inherited, if the key is protected and holds its own descriptor (Windows: PAI; the ACEs are Windows') */
    RegSdAiOnly
};

static const struct
{
    PCWSTR Path;
    DWORD Mode;
} s_Keys[] =
{
    /* Parents first, the roots last (the pass runs while the SOFTWARE root has no AI: see below) */
    { L"SOFTWARE\\Microsoft", RegSdPlain },
    { L"SOFTWARE\\Microsoft\\Windows", RegSdPlain },
    { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion", RegSdPai },
    { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", RegSdPai },
    { L"SOFTWARE\\Microsoft\\Windows NT", RegSdPlain },
    { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", RegSdPai },
    { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache", RegSdAiOnly },
    { L"SOFTWARE\\Classes", RegSdPai },
    { L"SOFTWARE\\Policies", RegSdAiOnly },
    { L"SYSTEM\\Select", RegSdPlain },
    { L"SYSTEM\\Setup", RegSdPlain },
    { L"SYSTEM\\CurrentControlSet\\Control", RegSdPlain },
    { L"SYSTEM\\CurrentControlSet\\Control\\Lsa", RegSdPai },
    { L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", RegSdPlain },
    { L"SYSTEM\\CurrentControlSet\\Enum", RegSdPlain },
    { L"SYSTEM\\CurrentControlSet\\Services\\Tcpip", RegSdPai },
    { L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", RegSdAiOnly },
    { L"SYSTEM\\CurrentControlSet\\Services\\EventLog", RegSdAiOnly },
    { L"SYSTEM", RegSdAiOnly },
    { L"SOFTWARE", RegSdAiOnly },
};

#define SOFTWARE_ROOT (ARRAYSIZE(s_Keys) - 1)

/* The key's descriptor (owner, group, DACL), to be freed with LocalFree, and its control flags */
static PSECURITY_DESCRIPTOR
QueryKeyDescriptor(
    _In_ HKEY hKey,
    _Out_ PWORD pControl)
{
    SECURITY_INFORMATION Info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    PSECURITY_DESCRIPTOR pSd;
    DWORD dwLength = 0, dwRevision;
    SECURITY_DESCRIPTOR_CONTROL Control;

    if (RegGetKeySecurity(hKey, Info, NULL, &dwLength) != ERROR_INSUFFICIENT_BUFFER || dwLength == 0)
        return NULL;
    pSd = LocalAlloc(LMEM_FIXED, dwLength);
    if (!pSd)
        return NULL;
    if (RegGetKeySecurity(hKey, Info, pSd, &dwLength) != ERROR_SUCCESS ||
        !GetSecurityDescriptorControl(pSd, &Control, &dwRevision))
    {
        LocalFree(pSd);
        return NULL;
    }
    *pControl = Control;
    return pSd;
}

static VOID
UpgradeKey(
    _In_ HKEY hRoot,
    _In_ PCWSTR pszPath,
    _In_ DWORD Mode)
{
    HKEY hKey;
    PSECURITY_DESCRIPTOR pSd;
    WORD Control;
    BOOL bPresent, bDefaulted, bProtect;
    PACL pDacl;
    DWORD i;
    SECURITY_INFORMATION Info = DACL_SECURITY_INFORMATION;
    SECURITY_DESCRIPTOR_CONTROL Wanted;

    if (RegOpenKeyExW(hRoot, pszPath, 0, READ_CONTROL | WRITE_DAC, &hKey) != ERROR_SUCCESS)
        return;

    pSd = QueryKeyDescriptor(hKey, &Control);
    if (!pSd)
    {
        RegCloseKey(hKey);
        return;
    }

    switch (Mode)
    {
        case RegSdPai:
            if ((Control & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED)) == (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED))
                goto Done;
            Wanted = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_PROTECTED;
            bProtect = TRUE;
            break;

        case RegSdPlain:
            /*
             * Not skipped when the flags already are none: the key may hold no descriptor of its own
             * (it reports the one it inherits), and it must keep this one when its parent turns AI.
             */
            Wanted = 0;
            bProtect = FALSE;
            break;

        default:
            /* Only a key that holds a protected descriptor of its own, the one setup stored */
            if (!(Control & SE_DACL_PROTECTED) || (Control & SE_DACL_AUTO_INHERITED))
                goto Done;
            Wanted = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_PROTECTED;
            bProtect = TRUE;
            break;
    }

    /* The ACEs are kept as they are, none is flagged as inherited any more */
    if (GetSecurityDescriptorDacl(pSd, &bPresent, &pDacl, &bDefaulted) && bPresent && pDacl)
    {
        for (i = 0; i < pDacl->AceCount; i++)
        {
            PACE_HEADER pAce;
            if (!GetAce(pDacl, i, (PVOID *)&pAce))
                break;
            pAce->AceFlags &= ~INHERITED_ACE;
        }
    }
    else
    {
        goto Done;
    }

    if (!SetSecurityDescriptorControl(pSd,
                                      SE_DACL_AUTO_INHERIT_REQ | SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED,
                                      Wanted))
    {
        goto Done;
    }
    Info |= bProtect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
    if (RegSetKeySecurity(hKey, Info, pSd) != ERROR_SUCCESS)
        DPRINT1("Failed to upgrade the descriptor of %S\n", pszPath);

Done:
    LocalFree(pSd);
    RegCloseKey(hKey);
}

/*
 * Called by winlogon at every start. An install from before the hive roots had SE_DACL_AUTO_INHERITED has the
 * root of SOFTWARE protected and without it: that is what is looked for, so that a key an administrator has
 * changed since is not reset (the pass has run, or the install is new, once the root has it).
 */
BOOL
WINAPI
SecureRegistryKeys(VOID)
{
    PSECURITY_DESCRIPTOR pSd;
    HKEY hKey;
    WORD Control;
    BOOL bOld = FALSE;
    SIZE_T i;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, s_Keys[SOFTWARE_ROOT].Path, 0, READ_CONTROL, &hKey) != ERROR_SUCCESS)
        return FALSE;
    pSd = QueryKeyDescriptor(hKey, &Control);
    RegCloseKey(hKey);
    if (pSd)
    {
        bOld = (Control & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED)) == SE_DACL_PROTECTED;
        LocalFree(pSd);
    }
    if (!bOld)
        return TRUE;

    for (i = 0; i < ARRAYSIZE(s_Keys); i++)
        UpgradeKey(HKEY_LOCAL_MACHINE, s_Keys[i].Path, s_Keys[i].Mode);

    return TRUE;
}

/* EOF */
