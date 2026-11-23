/*
 * PROJECT:     ReactOS private headers
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Whether a named kernel object that a Create* call opened (ERROR_ALREADY_EXISTS) was made by a process
 *              at least as trusted as the caller
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

/*
 * The named object directories let processes at Low integrity and up create objects (as on Windows), and kernel32
 * creates every named object with OBJ_OPENIF: a Create* call of a name someone made first returns that object
 * (ERROR_ALREADY_EXISTS). A component that then waits on it or trusts what it holds asks this first: the object is
 * trusted when its owner is SYSTEM, the Administrators, or (AllowSameUser) the caller's own user, and its mandatory
 * label (none: Medium) is not below the caller's integrity level (Medium for callers above it: objects made by
 * subjects at Medium and above carry no label). The handle needs READ_CONTROL (every Create*
 * opens with the type's all access). FALSE when the descriptor cannot be read.
 */

#include <windows.h>

static __inline DWORD
NamedObjTrustLabelRid(
    _In_ PSECURITY_DESCRIPTOR Sd)
{
    BOOL Present = FALSE, Defaulted;
    PACL Sacl = NULL;
    DWORD i;

    if (!GetSecurityDescriptorSacl(Sd, &Present, &Sacl, &Defaulted) || !Present || !Sacl)
        return SECURITY_MANDATORY_MEDIUM_RID;
    for (i = 0; i < Sacl->AceCount; i++)
    {
        PSYSTEM_MANDATORY_LABEL_ACE Ace;
        PSID Sid;

        if (!GetAce(Sacl, i, (PVOID *)&Ace))
            break;
        if (Ace->Header.AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE || (Ace->Header.AceFlags & INHERIT_ONLY_ACE))
            continue;
        Sid = (PSID)&Ace->SidStart;
        if (IsValidSid(Sid) && *GetSidSubAuthorityCount(Sid) >= 1)
            return *GetSidSubAuthority(Sid, *GetSidSubAuthorityCount(Sid) - 1);
    }
    return SECURITY_MANDATORY_MEDIUM_RID;
}

static __inline BOOL
NamedObjectIsTrusted(
    _In_ HANDLE Object,
    _In_ BOOL AllowSameUser)
{
    BYTE SdBuffer[512], TokenBuffer[256], AdminSid[SECURITY_MAX_SID_SIZE], SystemSid[SECURITY_MAX_SID_SIZE];
    PSECURITY_DESCRIPTOR Sd = (PSECURITY_DESCRIPTOR)SdBuffer;
    DWORD Needed = 0, Size, CallerRid = SECURITY_MANDATORY_MEDIUM_RID;
    PSID Owner = NULL, User = NULL;
    BOOL Defaulted, Trusted = FALSE;
    HANDLE Token;

    if (!GetKernelObjectSecurity(Object, OWNER_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, Sd, sizeof(SdBuffer), &Needed) ||
        !GetSecurityDescriptorOwner(Sd, &Owner, &Defaulted) || !Owner)
    {
        return FALSE;
    }

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &Token) &&
        !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token))
    {
        return FALSE;
    }
    if (GetTokenInformation(Token, TokenIntegrityLevel, TokenBuffer, sizeof(TokenBuffer), &Needed))
    {
        PSID LabelSid = ((PTOKEN_MANDATORY_LABEL)TokenBuffer)->Label.Sid;
        if (*GetSidSubAuthorityCount(LabelSid) >= 1)
            CallerRid = *GetSidSubAuthority(LabelSid, *GetSidSubAuthorityCount(LabelSid) - 1);
    }
    Size = sizeof(AdminSid);
    if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, AdminSid, &Size) && EqualSid(Owner, (PSID)AdminSid))
        Trusted = TRUE;
    Size = sizeof(SystemSid);
    if (!Trusted && CreateWellKnownSid(WinLocalSystemSid, NULL, SystemSid, &Size) && EqualSid(Owner, (PSID)SystemSid))
        Trusted = TRUE;
    if (!Trusted && AllowSameUser &&
        GetTokenInformation(Token, TokenUser, TokenBuffer, sizeof(TokenBuffer), &Needed))
    {
        User = ((PTOKEN_USER)TokenBuffer)->User.Sid;
        Trusted = EqualSid(Owner, User);
    }
    CloseHandle(Token);

    /* Objects made at Medium and above carry no label (Medium): for callers above Medium that is the level to reach */
    if (CallerRid > SECURITY_MANDATORY_MEDIUM_RID)
        CallerRid = SECURITY_MANDATORY_MEDIUM_RID;
    return Trusted && NamedObjTrustLabelRid(Sd) >= CallerRid;
}
