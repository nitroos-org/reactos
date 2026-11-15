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
 *
 * The pass runs once: it needs the root of SOFTWARE as the pre-fix setup stored it (protected, not auto-inherited,
 * the ACEs of the hive root template) and no marker value, and it writes the marker when it is done. A system that
 * is not of that kind (a new install, or one that was upgraded) gets the marker the first time this runs, so that an
 * administrator who clears the flags of the root later does not have the pass run again over keys that were changed.
 */

#include "precomp.h"

#include <accctrl.h>
#include <aclapi.h>
#include <reactos/regacl_sd.h>

#define NDEBUG
#include <debug.h>

enum
{
    /* Protected and auto-inherited (Windows: PAI) */
    RegSdPai,
    /* Neither, held as the key's own (Windows: the descriptor has its own ACEs and no flags) */
    RegSdPlain,
    /* Auto-inherited, if the key is protected and holds its own descriptor (Windows: PAI; the ACEs are Windows') */
    RegSdAiOnly,
    /*
     * Auto-inherited and not protected, the key holding its own copy (Windows: AI, the ACEs flagged as inherited):
     * only a key that holds exactly the ACEs of REGSD_T_INHAI (the flags of the ACEs ignored) and is not protected.
     * Any other key (an administrator changed it, or its parent) is left as it is.
     */
    RegSdAiTemplate,
    /* As RegSdPlain, but a protected key is left as it is (the key was protected by an administrator) */
    RegSdPlainUnprotected
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
    /* The 32-bit view (Windows 10 has the same flags there) */
    { L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion", RegSdPai },
    { L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", RegSdPai },
    { L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion", RegSdPai },
    { L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache", RegSdAiOnly },
    { L"SOFTWARE\\Classes", RegSdPai },
    { L"SOFTWARE\\Policies", RegSdAiOnly },
    /*
     * ControlSet001 (and CurrentControlSet, its link) is a plain copy on Windows 10 while Services and Hardware
     * Profiles are auto-inherited: those two hold their own copy first, so that they do not inherit the plain flags.
     */
    { L"SYSTEM\\CurrentControlSet\\Services", RegSdAiTemplate },
    { L"SYSTEM\\CurrentControlSet\\Hardware Profiles", RegSdAiTemplate },
    { L"SYSTEM\\CurrentControlSet", RegSdPlainUnprotected },
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

/* Written (REG_DWORD 1) under HKLM\SOFTWARE\ReactOS once the pass has run or is not needed */
#define MARKER_KEY   L"SOFTWARE\\ReactOS"
#define MARKER_VALUE L"HiveKeyFlagsUpgrade"

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

/* Do the two DACLs hold the same ACEs in the same order (type, flags but IgnoreFlags, mask, SID)? */
static BOOL
SameAces(
    _In_ PACL pDacl,
    _In_ PACL pOther,
    _In_ BYTE IgnoreFlags)
{
    DWORD i;

    if (pDacl->AceCount != pOther->AceCount)
        return FALSE;
    for (i = 0; i < pDacl->AceCount; i++)
    {
        PACCESS_ALLOWED_ACE pAce, pOtherAce;

        if (!GetAce(pDacl, i, (PVOID *)&pAce) || !GetAce(pOther, i, (PVOID *)&pOtherAce))
            return FALSE;
        if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || pOtherAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
            (pAce->Header.AceFlags & ~IgnoreFlags) != (pOtherAce->Header.AceFlags & ~IgnoreFlags) ||
            pAce->Mask != pOtherAce->Mask || !EqualSid((PSID)&pAce->SidStart, (PSID)&pOtherAce->SidStart))
        {
            return FALSE;
        }
    }
    return TRUE;
}

/* FALSE when the key is there and its descriptor could not be written */
static BOOL
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
    BOOL bMarkInherited = FALSE, bOk = TRUE;

    if (RegOpenKeyExW(hRoot, pszPath, 0, READ_CONTROL | WRITE_DAC, &hKey) != ERROR_SUCCESS)
        return TRUE;

    pSd = QueryKeyDescriptor(hKey, &Control);
    if (!pSd)
    {
        RegCloseKey(hKey);
        return TRUE;
    }

    switch (Mode)
    {
        case RegSdPai:
            if ((Control & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED)) == (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED))
                goto Done;
            Wanted = SE_DACL_AUTO_INHERIT_REQ | SE_DACL_PROTECTED;
            bProtect = TRUE;
            break;

        case RegSdPlainUnprotected:
            if (Control & SE_DACL_PROTECTED)
                goto Done;
            /* fall through */
        case RegSdPlain:
            /*
             * Not skipped when the flags already are none: the key may hold no descriptor of its own
             * (it reports the one it inherits), and it must keep this one when its parent turns AI.
             */
            Wanted = 0;
            bProtect = FALSE;
            break;

        case RegSdAiTemplate:
        {
            UCHAR Template[REGSD_MAX_ACES * 80];
            PACL pTemplateDacl;

            /*
             * Only a key that has nothing of its own: unprotected and holding exactly the ACEs it would inherit
             * (those of the template). It then holds them flagged as inherited, so that a change an administrator
             * makes to ControlSet001 (propagated) reaches it as it reaches a key that was never upgraded. A key
             * with other ACEs, or a protected one, was changed by someone and stays as it is.
             */
            if ((Control & SE_DACL_PROTECTED) || !RegSdBuild(REGSD_T_INHAI, NULL, Template, sizeof(Template)))
                goto Done;
            if (!GetSecurityDescriptorDacl(pSd, &bPresent, &pDacl, &bDefaulted) || !bPresent || !pDacl ||
                !GetSecurityDescriptorDacl((PSECURITY_DESCRIPTOR)Template, &bPresent, &pTemplateDacl, &bDefaulted) ||
                !bPresent || !pTemplateDacl || !SameAces(pDacl, pTemplateDacl, INHERITED_ACE))
            {
                goto Done;
            }
            Wanted = SE_DACL_AUTO_INHERIT_REQ;
            bProtect = FALSE;
            bMarkInherited = TRUE;
            break;
        }

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
            if (bMarkInherited)
                pAce->AceFlags |= INHERITED_ACE;
            else
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
    {
        DPRINT1("Failed to upgrade the descriptor of %S\n", pszPath);
        bOk = FALSE;
    }

Done:
    LocalFree(pSd);
    RegCloseKey(hKey);
    return bOk;
}

static BOOL
HasMarker(VOID)
{
    HKEY hKey;
    DWORD dwType, dwValue = 0, dwSize = sizeof(dwValue);
    BOOL bFound = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MARKER_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return FALSE;
    if (RegQueryValueExW(hKey, MARKER_VALUE, NULL, &dwType, (LPBYTE)&dwValue, &dwSize) == ERROR_SUCCESS &&
        dwType == REG_DWORD && dwValue == 1)
    {
        bFound = TRUE;
    }
    RegCloseKey(hKey);
    return bFound;
}

static VOID
WriteMarker(VOID)
{
    HKEY hKey;
    DWORD dwValue = 1;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MARKER_KEY, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return;
    RegSetValueExW(hKey, MARKER_VALUE, 0, REG_DWORD, (const BYTE *)&dwValue, sizeof(dwValue));
    RegCloseKey(hKey);
}

/*
 * Is this the root of SOFTWARE as setup stored it before the roots had SE_DACL_AUTO_INHERITED: protected, not
 * auto-inherited, the ACEs of the hive root template (no ACE marked as inherited), owner and group as the template?
 */
static BOOL
IsPreFixRoot(
    _In_ PSECURITY_DESCRIPTOR pSd,
    _In_ WORD Control)
{
    UCHAR Template[REGSD_MAX_ACES * 80];
    PSECURITY_DESCRIPTOR pTemplate = (PSECURITY_DESCRIPTOR)Template;
    PACL pDacl, pTemplateDacl;
    PSID pOwner, pTemplateOwner, pGroup, pTemplateGroup;
    BOOL bPresent, bDefaulted;

    if ((Control & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED)) != SE_DACL_PROTECTED)
        return FALSE;
    if (!RegSdBuild(REGSD_T_HIVEROOT, NULL, Template, sizeof(Template)))
        return FALSE;

    if (!GetSecurityDescriptorOwner(pSd, &pOwner, &bDefaulted) ||
        !GetSecurityDescriptorOwner(pTemplate, &pTemplateOwner, &bDefaulted) ||
        !pOwner || !pTemplateOwner || !EqualSid(pOwner, pTemplateOwner))
        return FALSE;
    if (!GetSecurityDescriptorGroup(pSd, &pGroup, &bDefaulted) ||
        !GetSecurityDescriptorGroup(pTemplate, &pTemplateGroup, &bDefaulted) ||
        !pGroup || !pTemplateGroup || !EqualSid(pGroup, pTemplateGroup))
        return FALSE;

    if (!GetSecurityDescriptorDacl(pSd, &bPresent, &pDacl, &bDefaulted) || !bPresent || !pDacl ||
        !GetSecurityDescriptorDacl(pTemplate, &bPresent, &pTemplateDacl, &bDefaulted) || !bPresent || !pTemplateDacl)
        return FALSE;
    return SameAces(pDacl, pTemplateDacl, 0);
}

/* Does the root of SOFTWARE hold the descriptor the pass waits for, and does it hold auto-inherit? */
static BOOL
QueryRoot(
    _Out_ PBOOL pbPreFix,
    _Out_ PBOOL pbAi)
{
    PSECURITY_DESCRIPTOR pSd;
    HKEY hKey;
    WORD Control;

    *pbPreFix = *pbAi = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, s_Keys[SOFTWARE_ROOT].Path, 0, READ_CONTROL, &hKey) != ERROR_SUCCESS)
        return FALSE;
    pSd = QueryKeyDescriptor(hKey, &Control);
    RegCloseKey(hKey);
    if (pSd)
    {
        *pbPreFix = IsPreFixRoot(pSd, Control);
        *pbAi = (Control & SE_DACL_AUTO_INHERITED) != 0;
        LocalFree(pSd);
    }
    return TRUE;
}

/*
 * Called by winlogon at every start. An install from before the hive roots had SE_DACL_AUTO_INHERITED has the
 * root of SOFTWARE as IsPreFixRoot describes: that, and no marker, is what the pass waits for, so that a key an
 * administrator has changed since is not reset. A system whose root has the flag (a new install, or one the pass
 * has run on) gets the marker here at once, so that clearing the flag later does not bring the pass back.
 *
 * The marker is written only when the pass is complete: every other key was written (or is absent), and then the
 * root, last, and a re-read of the root shows that the write took (it does not while the registry access control
 * is in legacy mode, which stores nothing: the pass is then tried again when the system leaves it). The root is
 * written only after all the other keys, so a failed key is retried at the next start.
 */
BOOL
WINAPI
SecureRegistryKeys(VOID)
{
    BOOL bOld, bAi, bOk = TRUE;
    SIZE_T i;

    if (HasMarker())
        return TRUE;

    if (!QueryRoot(&bOld, &bAi))
        return FALSE;
    if (!bOld)
    {
        if (bAi)
            WriteMarker();
        return TRUE;
    }

    for (i = 0; i < SOFTWARE_ROOT; i++)
    {
        if (!UpgradeKey(HKEY_LOCAL_MACHINE, s_Keys[i].Path, s_Keys[i].Mode))
            bOk = FALSE;
    }
    if (!bOk)
        return TRUE;

    if (UpgradeKey(HKEY_LOCAL_MACHINE, s_Keys[SOFTWARE_ROOT].Path, s_Keys[SOFTWARE_ROOT].Mode) &&
        QueryRoot(&bOld, &bAi) && !bOld && bAi)
    {
        WriteMarker();
    }

    return TRUE;
}

/* EOF */
