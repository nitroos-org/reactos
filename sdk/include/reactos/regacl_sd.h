/*
 * PROJECT:     ReactOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Registry security descriptors of the hive roots and a few well-known keys
 *
 * The descriptors are written as data (owner, group, control flags and a list of
 * allow ACEs with a mask and flags each) and built into a self-relative security
 * descriptor with memcpy only, so that the same table serves the hive maker (a host
 * tool), the setup library (a native program) and the user profile code.
 * Windows 10 22H2 reference values, read from the live system with the READ_CONTROL
 * access (sddl text in the comments).
 */

#pragma once

#include <string.h>

/* Well-known SIDs the tables use */
#define REGSD_SID_SY      0   /* S-1-5-18, Local System */
#define REGSD_SID_BA      1   /* S-1-5-32-544, Administrators */
#define REGSD_SID_BU      2   /* S-1-5-32-545, Users */
#define REGSD_SID_WD      3   /* S-1-1-0, Everyone */
#define REGSD_SID_RC      4   /* S-1-5-12, Restricted */
#define REGSD_SID_CO      5   /* S-1-3-0, Creator Owner */
#define REGSD_SID_AC      6   /* S-1-15-2-1, All Application Packages */
#define REGSD_SID_LPAC    7   /* the capability SID Windows 10 uses for All Restricted Application Packages */
#define REGSD_SID_AU      8   /* S-1-5-11, Authenticated Users */
#define REGSD_SID_SO      9   /* S-1-5-32-549, Server Operators */
#define REGSD_SID_NS      10  /* S-1-5-20, Network Service */
#define REGSD_SID_LS      11  /* S-1-5-19, Local Service */
#define REGSD_SID_NO      12  /* S-1-5-32-556, Network Configuration Operators */
#define REGSD_SID_OW      13  /* S-1-3-4, Owner Rights */
#define REGSD_SID_SVC_A   14  /* S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582 (service SID) */
#define REGSD_SID_SVC_B   15  /* S-1-5-80-3981856537-581775623-1136376035-2066872258-409572886 (service SID) */
#define REGSD_SID_CAP1    16  /* S-1-15-3-1 */
#define REGSD_SID_CAP2    17  /* S-1-15-3-2 */
#define REGSD_SID_CAP3    18  /* S-1-15-3-3 */
#define REGSD_SID_CAP4    19  /* S-1-15-3-4214768333-1334025770-122408079-3919188833 */
#define REGSD_SID_USER    20  /* the SID given to RegSdBuild (the profile's user) */
#define REGSD_SID_COUNT   21

/* ACE flags */
#define REGSD_OI  0x01
#define REGSD_CI  0x02
#define REGSD_IO  0x08

/* Access masks (the SDDL names are the Windows 10 spelling) */
#define REGSD_KA    0x000F003FUL    /* KEY_ALL_ACCESS */
#define REGSD_KR    0x00020019UL    /* KEY_READ */
#define REGSD_RCWD  0x00060000UL    /* READ_CONTROL | WRITE_DAC */
#define REGSD_BCD   0x00060019UL    /* CC SW RP RC WD */
#define REGSD_TC    0x00030019UL    /* CC SW RP SD RC */
#define REGSD_GR    0x80000000UL    /* GENERIC_READ */
#define REGSD_GA    0x10000000UL    /* GENERIC_ALL */
#define REGSD_RC    0x00020000UL    /* READ_CONTROL */
#define REGSD_NETW  0x0003003FUL    /* CC DC LC SW RP WP SD RC */
#define REGSD_NETS  0x0003001FUL    /* CC DC LC SW RP SD RC */
#define REGSD_NETR  0x0002001FUL    /* CC DC LC SW RP RC */

/* Control flags of the descriptors (self-relative is added by the builder) */
#define REGSD_DACL_PRESENT   0x0004
#define REGSD_SACL_PRESENT   0x0010   /* with no SACL: a present NULL SACL, offset 0 */
#define REGSD_DACL_AUTOINH   0x0400
#define REGSD_SACL_AUTOINH   0x0800
#define REGSD_DACL_PROTECTED 0x1000

#define REGSD_MAX_ACES 16

typedef struct _REGSD_ACE
{
    UCHAR Flags;
    UCHAR Sid;      /* REGSD_SID_* */
    ULONG Mask;
} REGSD_ACE;

typedef struct _REGSD_TEMPLATE
{
    const char *Name;
    USHORT Control;     /* without SE_SELF_RELATIVE */
    UCHAR Owner;
    UCHAR Group;
    UCHAR AceCount;
    REGSD_ACE Aces[REGSD_MAX_ACES];
} REGSD_TEMPLATE;

/* The templates. The index is the REGSD_T_* value. */
#define REGSD_T_MASTER      0   /* \Registry, \Registry\Machine, \Registry\User, HKLM\HARDWARE */
#define REGSD_T_HIVEROOT    1   /* HKLM\SYSTEM, HKLM\SOFTWARE, HKLM\SAM */
#define REGSD_T_DEFAULT     2   /* HKU\.DEFAULT */
#define REGSD_T_SAMSAM      3   /* HKLM\SAM\SAM */
#define REGSD_T_SECURITY    4   /* HKLM\SECURITY */
#define REGSD_T_BCD         5   /* HKLM\BCD00000000 */
#define REGSD_T_USER        6   /* HKU\<user SID>, the profile's HKCU root (needs the SID) */
#define REGSD_T_TASKCACHE   7   /* ...\Windows NT\CurrentVersion\Schedule\TaskCache */
#define REGSD_T_EVENTLOG    8   /* ...\Services\EventLog */
#define REGSD_T_POLICIES    9   /* HKLM\SOFTWARE\Policies */
#define REGSD_T_TCPIPPARAMS 10  /* ...\Services\Tcpip\Parameters */
#define REGSD_T_COUNT       11

static const REGSD_TEMPLATE RegSdTemplates[REGSD_T_COUNT] =
{
    /* O:SYG:SYD:(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;WD)(A;CI;KR;;;RC)(A;CI;KR;;;AC)(A;CI;KR;;;LPAC) */
    { "master", REGSD_DACL_PRESENT, REGSD_SID_SY, REGSD_SID_SY, 6,
      { { REGSD_CI, REGSD_SID_SY, REGSD_KA }, { REGSD_CI, REGSD_SID_BA, REGSD_KA },
        { REGSD_CI, REGSD_SID_WD, REGSD_KR }, { REGSD_CI, REGSD_SID_RC, REGSD_KR },
        { REGSD_CI, REGSD_SID_AC, REGSD_KR }, { REGSD_CI, REGSD_SID_LPAC, REGSD_KR } } },

    /* O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;CI;KR;;;AC)(A;CI;KR;;;LPAC)S:AINO_ACCESS_CONTROL */
    { "hiveroot", REGSD_DACL_PRESENT | REGSD_DACL_PROTECTED | REGSD_DACL_AUTOINH | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH,
      REGSD_SID_BA, REGSD_SID_SY, 6,
      { { REGSD_CI, REGSD_SID_BU, REGSD_KR }, { REGSD_CI, REGSD_SID_BA, REGSD_KA },
        { REGSD_CI, REGSD_SID_SY, REGSD_KA }, { REGSD_CI, REGSD_SID_CO, REGSD_KA },
        { REGSD_CI, REGSD_SID_AC, REGSD_KR }, { REGSD_CI, REGSD_SID_LPAC, REGSD_KR } } },

    /* O:BAG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KA;;;CO)(A;;KR;;;AC)(A;;KR;;;LPAC)S:AINO_ACCESS_CONTROL */
    { "default", REGSD_DACL_PRESENT | REGSD_DACL_PROTECTED | REGSD_DACL_AUTOINH | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH,
      REGSD_SID_BA, REGSD_SID_SY, 6,
      { { REGSD_CI, REGSD_SID_BU, REGSD_KR }, { REGSD_CI, REGSD_SID_BA, REGSD_KA },
        { REGSD_CI, REGSD_SID_SY, REGSD_KA }, { REGSD_CI, REGSD_SID_CO, REGSD_KA },
        { 0, REGSD_SID_AC, REGSD_KR }, { 0, REGSD_SID_LPAC, REGSD_KR } } },

    /* O:BAG:SYD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA) */
    { "sam\\sam", REGSD_DACL_PRESENT | REGSD_SACL_AUTOINH, REGSD_SID_BA, REGSD_SID_SY, 2,
      { { REGSD_CI, REGSD_SID_SY, REGSD_KA }, { REGSD_CI, REGSD_SID_BA, REGSD_RCWD } } },

    /* O:BAG:SYD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)S:AINO_ACCESS_CONTROL */
    { "security", REGSD_DACL_PRESENT | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH, REGSD_SID_BA, REGSD_SID_SY, 2,
      { { REGSD_CI, REGSD_SID_SY, REGSD_KA }, { REGSD_CI, REGSD_SID_BA, REGSD_RCWD } } },

    /* O:BAG:SYD:(A;;CCSWRPRCWD;;;BA)(A;;KA;;;SY) */
    { "bcd", REGSD_DACL_PRESENT, REGSD_SID_BA, REGSD_SID_SY, 2,
      { { 0, REGSD_SID_BA, REGSD_BCD }, { 0, REGSD_SID_SY, REGSD_KA } } },

    /* O:BAG:SYD:P(A;OICI;KA;;;<user>)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;OICI;KR;;;RC)(A;;KR;;;AC)(A;;KR;;;LPAC)S:AINO_ACCESS_CONTROL */
    { "user", REGSD_DACL_PRESENT | REGSD_DACL_PROTECTED | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH,
      REGSD_SID_BA, REGSD_SID_SY, 6,
      { { REGSD_OI | REGSD_CI, REGSD_SID_USER, REGSD_KA }, { REGSD_OI | REGSD_CI, REGSD_SID_SY, REGSD_KA },
        { REGSD_OI | REGSD_CI, REGSD_SID_BA, REGSD_KA }, { REGSD_OI | REGSD_CI, REGSD_SID_RC, REGSD_KR },
        { 0, REGSD_SID_AC, REGSD_KR }, { 0, REGSD_SID_LPAC, REGSD_KR } } },

    /* O:SYG:SYD:PAI(A;OICI;CCSWRPSDRC;;;BA)(A;OICI;KA;;;SY)S:AINO_ACCESS_CONTROL */
    { "taskcache", REGSD_DACL_PRESENT | REGSD_DACL_PROTECTED | REGSD_DACL_AUTOINH | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH,
      REGSD_SID_SY, REGSD_SID_SY, 2,
      { { REGSD_OI | REGSD_CI, REGSD_SID_BA, REGSD_TC }, { REGSD_OI | REGSD_CI, REGSD_SID_SY, REGSD_KA } } },

    /* O:BAG:SYD:PAI(A;;KR;;;AU)(A;CIIO;GR;;;AU)(A;;KR;;;SO)(A;CIIO;GR;;;SO)(A;;KA;;;BA)(A;CIIO;GA;;;BA)(A;;KA;;;SY)(A;CIIO;GA;;;SY)S:AINO_ACCESS_CONTROL */
    { "eventlog", REGSD_DACL_PRESENT | REGSD_DACL_PROTECTED | REGSD_DACL_AUTOINH | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH,
      REGSD_SID_BA, REGSD_SID_SY, 8,
      { { 0, REGSD_SID_AU, REGSD_KR }, { REGSD_CI | REGSD_IO, REGSD_SID_AU, REGSD_GR },
        { 0, REGSD_SID_SO, REGSD_KR }, { REGSD_CI | REGSD_IO, REGSD_SID_SO, REGSD_GR },
        { 0, REGSD_SID_BA, REGSD_KA }, { REGSD_CI | REGSD_IO, REGSD_SID_BA, REGSD_GA },
        { 0, REGSD_SID_SY, REGSD_KA }, { REGSD_CI | REGSD_IO, REGSD_SID_SY, REGSD_GA } } },

    /* O:SYG:SYD:PAI(A;;KR;;;AU)(A;;KA;;;SY)(A;;KA;;;BA)(A;OICIIO;GR;;;AU)(A;OICIIO;GA;;;SY)(A;OICIIO;GA;;;BA)
       (A;;KR;;;AC)(A;OICIIO;GR;;;AC)(A;;KR;;;LPAC)(A;OICIIO;GR;;;LPAC)S:AINO_ACCESS_CONTROL */
    { "policies", REGSD_DACL_PRESENT | REGSD_DACL_PROTECTED | REGSD_DACL_AUTOINH | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH,
      REGSD_SID_SY, REGSD_SID_SY, 10,
      { { 0, REGSD_SID_AU, REGSD_KR }, { 0, REGSD_SID_SY, REGSD_KA }, { 0, REGSD_SID_BA, REGSD_KA },
        { REGSD_OI | REGSD_CI | REGSD_IO, REGSD_SID_AU, REGSD_GR },
        { REGSD_OI | REGSD_CI | REGSD_IO, REGSD_SID_SY, REGSD_GA },
        { REGSD_OI | REGSD_CI | REGSD_IO, REGSD_SID_BA, REGSD_GA },
        { 0, REGSD_SID_AC, REGSD_KR }, { REGSD_OI | REGSD_CI | REGSD_IO, REGSD_SID_AC, REGSD_GR },
        { 0, REGSD_SID_LPAC, REGSD_KR }, { REGSD_OI | REGSD_CI | REGSD_IO, REGSD_SID_LPAC, REGSD_GR } } },

    /* O:SYG:SYD:PAI(A;CI;KR;;;BU)(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;CCDCLCSWRPWPSDRC;;;NS)(A;CI;KR;;;LS)
       (A;CI;CCDCLCSWRPSDRC;;;NO)(A;CI;CCDCLCSWRPSDRC;;;<service A>)(A;CIIO;RC;;;OW)(A;CI;CCDCLCSWRPRC;;;<service B>)
       (A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-3-1)(A;CI;KR;;;S-1-15-3-2)(A;CI;KR;;;S-1-15-3-3)(A;CI;KR;;;<capability 4>)S:AINO_ACCESS_CONTROL */
    { "tcpip\\parameters", REGSD_DACL_PRESENT | REGSD_DACL_PROTECTED | REGSD_DACL_AUTOINH | REGSD_SACL_PRESENT | REGSD_SACL_AUTOINH,
      REGSD_SID_SY, REGSD_SID_SY, 14,
      { { REGSD_CI, REGSD_SID_BU, REGSD_KR }, { REGSD_CI, REGSD_SID_BA, REGSD_KA }, { REGSD_CI, REGSD_SID_SY, REGSD_KA },
        { REGSD_CI, REGSD_SID_NS, REGSD_NETW }, { REGSD_CI, REGSD_SID_LS, REGSD_KR },
        { REGSD_CI, REGSD_SID_NO, REGSD_NETS }, { REGSD_CI, REGSD_SID_SVC_A, REGSD_NETS },
        { REGSD_CI | REGSD_IO, REGSD_SID_OW, REGSD_RC }, { REGSD_CI, REGSD_SID_SVC_B, REGSD_NETR },
        { REGSD_CI, REGSD_SID_AC, REGSD_KR }, { REGSD_CI, REGSD_SID_CAP1, REGSD_KR },
        { REGSD_CI, REGSD_SID_CAP2, REGSD_KR }, { REGSD_CI, REGSD_SID_CAP3, REGSD_KR },
        { REGSD_CI, REGSD_SID_CAP4, REGSD_KR } } },
};

/* A SID as authority (last byte of the 48-bit value) and sub-authorities */
typedef struct _REGSD_SIDDEF
{
    UCHAR Authority;
    UCHAR SubCount;
    ULONG Sub[10];
} REGSD_SIDDEF;

static const REGSD_SIDDEF RegSdSids[REGSD_SID_COUNT - 1] =
{
    /* SY  */ { 5, 1, { 18 } },
    /* BA  */ { 5, 2, { 32, 544 } },
    /* BU  */ { 5, 2, { 32, 545 } },
    /* WD  */ { 1, 1, { 0 } },
    /* RC  */ { 5, 1, { 12 } },
    /* CO  */ { 3, 1, { 0 } },
    /* AC  */ { 15, 2, { 2, 1 } },
    /* LPAC */ { 15, 10, { 3, 1024, 1065365936UL, 1281604716UL, 3511738428UL, 1654721687UL, 432734479UL,
                           3232135806UL, 4053264122UL, 3456934681UL } },
    /* AU  */ { 5, 1, { 11 } },
    /* SO  */ { 5, 2, { 32, 549 } },
    /* NS  */ { 5, 1, { 20 } },
    /* LS  */ { 5, 1, { 19 } },
    /* NO  */ { 5, 2, { 32, 556 } },
    /* OW  */ { 3, 1, { 4 } },
    /* SVC_A */ { 5, 6, { 80, 2940520708UL, 3855866260UL, 481812779UL, 327648279UL, 1710889582UL } },
    /* SVC_B */ { 5, 6, { 80, 3981856537UL, 581775623UL, 1136376035UL, 2066872258UL, 409572886UL } },
    /* CAP1 */ { 15, 2, { 3, 1 } },
    /* CAP2 */ { 15, 2, { 3, 2 } },
    /* CAP3 */ { 15, 2, { 3, 3 } },
    /* CAP4 */ { 15, 5, { 3, 4214768333UL, 1334025770UL, 122408079UL, 3919188833UL } },
};

#define REGSD_MAX_SID_LENGTH 68

static inline ULONG
RegSdPutSid(UCHAR *Out, const REGSD_SIDDEF *Def)
{
    ULONG i;

    Out[0] = 1;
    Out[1] = Def->SubCount;
    Out[2] = Out[3] = Out[4] = Out[5] = Out[6] = 0;
    Out[7] = Def->Authority;
    for (i = 0; i < Def->SubCount; i++)
    {
        Out[8 + 4 * i + 0] = (UCHAR)(Def->Sub[i]);
        Out[8 + 4 * i + 1] = (UCHAR)(Def->Sub[i] >> 8);
        Out[8 + 4 * i + 2] = (UCHAR)(Def->Sub[i] >> 16);
        Out[8 + 4 * i + 3] = (UCHAR)(Def->Sub[i] >> 24);
    }
    return 8 + 4 * (ULONG)Def->SubCount;
}

/* Length of a SID given as bytes (revision 1), 0 when it is not well formed */
static inline ULONG
RegSdSidLength(const UCHAR *Sid)
{
    if (!Sid || Sid[0] != 1 || Sid[1] > 15)
        return 0;
    return 8 + 4 * (ULONG)Sid[1];
}

/*
 * Build the self-relative security descriptor of a template (header, DACL, owner, group (a present NULL SACL has no bytes):
 * the order Windows uses). UserSid is the SID bytes for REGSD_SID_USER, or NULL for the
 * templates that do not name one. Returns the length, or 0 when Buffer is too small or
 * the template needs a user SID and none (or a bad one) was given.
 */
static inline ULONG
RegSdBuild(
    ULONG Template,
    const UCHAR *UserSid,
    UCHAR *Buffer,
    ULONG BufferSize)
{
    const REGSD_TEMPLATE *T;
    UCHAR Sid[REGSD_MAX_SID_LENGTH];
    ULONG Length, AclSize, Pos, i, SidLen, UserLen;
    ULONG OwnerOff, GroupOff;

    if (Template >= REGSD_T_COUNT)
        return 0;
    T = &RegSdTemplates[Template];
    UserLen = RegSdSidLength(UserSid);

    /* Sizes */
    AclSize = 8;
    for (i = 0; i < T->AceCount; i++)
    {
        if (T->Aces[i].Sid == REGSD_SID_USER)
        {
            if (!UserLen)
                return 0;
            SidLen = UserLen;
        }
        else
        {
            SidLen = 8 + 4 * (ULONG)RegSdSids[T->Aces[i].Sid].SubCount;
        }
        AclSize += 8 + SidLen;
    }
    OwnerOff = 20 + AclSize;
    GroupOff = OwnerOff + 8 + 4 * (ULONG)RegSdSids[T->Owner].SubCount;
    Length = GroupOff + 8 + 4 * (ULONG)RegSdSids[T->Group].SubCount;
    if (Length > BufferSize)
        return 0;

    memset(Buffer, 0, Length);
    Buffer[0] = 1;                                  /* Revision */
    Buffer[2] = (UCHAR)((T->Control | 0x8000));     /* Control, SE_SELF_RELATIVE added */
    Buffer[3] = (UCHAR)((T->Control | 0x8000) >> 8);
    Buffer[4] = (UCHAR)OwnerOff; Buffer[5] = (UCHAR)(OwnerOff >> 8);
    Buffer[8] = (UCHAR)GroupOff; Buffer[9] = (UCHAR)(GroupOff >> 8);
    /* A template with REGSD_SACL_PRESENT keeps a NULL SACL marked present (SDDL S:AINO_ACCESS_CONTROL), as Windows
       does: the Sacl offset stays 0. */
    Buffer[16] = 20;                                /* Dacl offset */

    /* DACL */
    Buffer[20] = 2;                                 /* AclRevision */
    Buffer[22] = (UCHAR)AclSize; Buffer[23] = (UCHAR)(AclSize >> 8);
    Buffer[24] = T->AceCount;
    Pos = 28;
    for (i = 0; i < T->AceCount; i++)
    {
        if (T->Aces[i].Sid == REGSD_SID_USER)
        {
            memcpy(Sid, UserSid, UserLen);
            SidLen = UserLen;
        }
        else
        {
            SidLen = RegSdPutSid(Sid, &RegSdSids[T->Aces[i].Sid]);
        }
        Buffer[Pos + 0] = 0;                        /* ACCESS_ALLOWED_ACE_TYPE */
        Buffer[Pos + 1] = T->Aces[i].Flags;
        Buffer[Pos + 2] = (UCHAR)(8 + SidLen); Buffer[Pos + 3] = (UCHAR)((8 + SidLen) >> 8);
        Buffer[Pos + 4] = (UCHAR)(T->Aces[i].Mask); Buffer[Pos + 5] = (UCHAR)(T->Aces[i].Mask >> 8);
        Buffer[Pos + 6] = (UCHAR)(T->Aces[i].Mask >> 16); Buffer[Pos + 7] = (UCHAR)(T->Aces[i].Mask >> 24);
        memcpy(&Buffer[Pos + 8], Sid, SidLen);
        Pos += 8 + SidLen;
    }

    RegSdPutSid(&Buffer[OwnerOff], &RegSdSids[T->Owner]);
    RegSdPutSid(&Buffer[GroupOff], &RegSdSids[T->Group]);
    return Length;
}
