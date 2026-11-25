/*
 * Integrity/ACL viewer/editor
 *
 * Copyright (C) 2009 Andrey Turkin (stub)
 * Copyright (C) 2016 Charles Davis (stub)
 * Copyright 2026 Tomas Srnka (implementation)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * Supported: display, /grant[:r], /deny, /remove[:g|:d], /inheritance:e|d|r,
 * /reset, /setowner, /findsid, /verify, /save, /restore and the /T /C /L /Q
 * modifiers. /setintegritylevel and /substitute are recognised but not
 * implemented.
 *
 * The ACL editing is done on the raw ACE list with the Win32 security APIs
 * (GetNamedSecurityInfo / SetNamedSecurityInfo, LookupAccountName, SDDL
 * conversion); no SetEntriesInAcl is used so that the ACE order and the
 * merge rules do not depend on the provider.
 */

#define WIN32_LEAN_AND_MEAN
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(icacls);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define F_RIGHTS   0x001F01FF
#define M_RIGHTS   0x001301BF
#define RX_RIGHTS  0x001200A9
#define R_RIGHTS   0x00120089
#define W_RIGHTS   0x00100116
#define D_RIGHTS   0x00110000 /* DELETE | SYNCHRONIZE */
#define FILE_GEN_READ    0x00120089
#define FILE_GEN_WRITE   0x00120116
#define FILE_GEN_EXEC    0x001200A0
#define FILE_GEN_ALL     0x001F01FF

#define INHERIT_MASK (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE)

#define ERR_NO_MAPPING 1332
#define ERR_BAD_SID    1337

/* ---------------------------------------------------------------- output */

static HANDLE out_handle;
static BOOL out_console;
static UINT out_cp;

static void emit(const WCHAR *s, int len)
{
    DWORD written;
    char *mb;
    int n;

    if (len <= 0) return;
    if (out_console)
    {
        WriteConsoleW(out_handle, s, len, &written, NULL);
        return;
    }
    n = WideCharToMultiByte(out_cp, 0, s, len, NULL, 0, NULL, NULL);
    if ((mb = HeapAlloc(GetProcessHeap(), 0, n + 1)))
    {
        WideCharToMultiByte(out_cp, 0, s, len, mb, n, NULL, NULL);
        WriteFile(out_handle, mb, n, &written, NULL);
        HeapFree(GetProcessHeap(), 0, mb);
    }
}

static void out_printf(const WCHAR *fmt, ...)
{
    WCHAR *buf;
    va_list args;
    int len, cap = 8192;

    for (;;)
    {
        if (!(buf = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(WCHAR)))) return;
        va_start(args, fmt);
        len = _vsnwprintf(buf, cap - 1, fmt, args);
        va_end(args);
        if (len >= 0 || cap > 1 << 20) break;
        HeapFree(GetProcessHeap(), 0, buf);
        cap *= 4;
    }
    if (len < 0) len = cap - 1;
    emit(buf, len);
    HeapFree(GetProcessHeap(), 0, buf);
}

static void out_error_text(DWORD err)
{
    WCHAR *msg = NULL;

    if (FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, 0, (WCHAR *)&msg, 0, NULL) && msg)
    {
        size_t len = wcslen(msg);
        while (len && (msg[len - 1] == '\r' || msg[len - 1] == '\n' || msg[len - 1] == ' ')) msg[--len] = 0;
        out_printf(L"%ls", msg);
        LocalFree(msg);
    }
    else out_printf(L"Unknown error %lu", err);
}

static void usage(void)
{
    out_printf(L"\n"
        L"ICACLS name [/grant[:r] Sid:perm[...]] [/deny Sid:perm[...]]\n"
        L"            [/remove[:g|:d] Sid[...]] [/inheritance:e|d|r]\n"
        L"            [/reset] [/T] [/C] [/L] [/Q]\n"
        L"ICACLS name /save aclfile [/T] [/C] [/L] [/Q]\n"
        L"ICACLS directory /restore aclfile [/C] [/L] [/Q]\n"
        L"ICACLS name /setowner Sid [/T] [/C] [/L] [/Q]\n"
        L"ICACLS name /findsid Sid [/T] [/C] [/L] [/Q]\n"
        L"ICACLS name /verify [/T] [/C] [/L] [/Q]\n"
        L"\n"
        L"With only a name, the DACL of every matching file is displayed.\n"
        L"\n"
        L"  /grant[:r]   add rights for the Sid to its explicit ACEs; with :r the\n"
        L"               rights replace the explicit grant of the same kind\n"
        L"  /deny        add an explicit deny ACE and take the denied rights out of\n"
        L"               the Sid's matching explicit grant\n"
        L"  /remove      delete the Sid's explicit ACEs; :g only grants, :d only denies\n"
        L"  /inheritance e: enable inheritance, d: disable it and keep the inherited\n"
        L"               ACEs as explicit ones, r: disable it and drop them\n"
        L"  /reset       replace the DACL by the ACEs inherited from the parent\n"
        L"  /save, /restore   write or re-apply DACLs (SDDL, one name per record)\n"
        L"  /setowner    set the owner;  /findsid  list names whose DACL mentions the Sid\n"
        L"  /verify      list names whose DACL is not in canonical order\n"
        L"\n"
        L"  /T  also process the files and directories below the matching\n"
        L"      directories (reparse-point directories are not entered)\n"
        L"  /C  continue after errors      /L  act on a symbolic link itself\n"
        L"  /Q  do not list each processed name\n"
        L"\n"
        L"A Sid is an account name, or *S-1-... for a numeric SID.\n"
        L"perm is a sequence of simple rights, or a comma list of specific rights\n"
        L"in parentheses, optionally preceded by inheritance flags that apply to\n"
        L"directories only:\n"
        L"  simple:    F full, M modify, RX read and execute, R read, W write, D delete\n"
        L"  specific:  DE RC WDAC WO S AS MA GR GW GE GA RD WD AD REA WEA X DC RA WA\n"
        L"  flags:     (OI) (CI) (IO) (NP)\n"
        L"\n"
        L"Example:  icacls C:\\data /grant *S-1-5-32-545:(OI)(CI)RX /T\n");
}

/* ----------------------------------------------------------- ACE list */

typedef struct
{
    BYTE *p;
    DWORD size;
} ace_t;

typedef struct
{
    ace_t *a;
    int n, cap;
} acelist;

static BOOL standard_ace(const ace_t *e)
{
    BYTE t = ((ACE_HEADER *)e->p)->AceType;
    return t == ACCESS_ALLOWED_ACE_TYPE || t == ACCESS_DENIED_ACE_TYPE;
}

static BOOL is_deny(const ace_t *e) { return ((ACE_HEADER *)e->p)->AceType == ACCESS_DENIED_ACE_TYPE; }
static BYTE ace_flags(const ace_t *e) { return ((ACE_HEADER *)e->p)->AceFlags; }
static BOOL is_inherited(const ace_t *e) { return (ace_flags(e) & INHERITED_ACE) != 0; }
static DWORD ace_mask(const ace_t *e) { return ((ACCESS_ALLOWED_ACE *)e->p)->Mask; }
static PSID ace_sid(const ace_t *e) { return (PSID)&((ACCESS_ALLOWED_ACE *)e->p)->SidStart; }

static void acelist_free(acelist *l)
{
    int i;
    for (i = 0; i < l->n; i++) HeapFree(GetProcessHeap(), 0, l->a[i].p);
    HeapFree(GetProcessHeap(), 0, l->a);
    l->a = NULL;
    l->n = l->cap = 0;
}

static void acelist_insert(acelist *l, int at, BYTE *p, DWORD size)
{
    if (l->n == l->cap)
    {
        int cap = l->cap ? l->cap * 2 : 16;
        ace_t *na = l->a ? HeapReAlloc(GetProcessHeap(), 0, l->a, cap * sizeof(*na))
                         : HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*na));
        if (!na) ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
        l->a = na;
        l->cap = cap;
    }
    memmove(&l->a[at + 1], &l->a[at], (l->n - at) * sizeof(ace_t));
    l->a[at].p = p;
    l->a[at].size = size;
    l->n++;
}

static void acelist_delete(acelist *l, int at)
{
    HeapFree(GetProcessHeap(), 0, l->a[at].p);
    memmove(&l->a[at], &l->a[at + 1], (l->n - at - 1) * sizeof(ace_t));
    l->n--;
}

static BOOL acelist_load(acelist *l, PACL acl, UCHAR *revision)
{
    int i;
    void *ace;

    l->a = NULL;
    l->n = l->cap = 0;
    *revision = ACL_REVISION;
    if (!acl) return TRUE;
    *revision = acl->AclRevision;
    for (i = 0; i < acl->AceCount; i++)
    {
        BYTE *copy;
        WORD size;

        if (!GetAce(acl, i, &ace)) return FALSE;
        size = ((ACE_HEADER *)ace)->AceSize;
        if (!(copy = HeapAlloc(GetProcessHeap(), 0, size))) return FALSE;
        memcpy(copy, ace, size);
        acelist_insert(l, l->n, copy, size);
    }
    return TRUE;
}

/* builds an ACL from the list; when explicit_only is set the inherited ACEs are left out */
static PACL acelist_build(const acelist *l, UCHAR revision, BOOL explicit_only)
{
    DWORD total = sizeof(ACL);
    PACL acl;
    int i;

    for (i = 0; i < l->n; i++)
        if (!explicit_only || !is_inherited(&l->a[i])) total += l->a[i].size;
    total = (total + 3) & ~3u;
    if (total > 0xFFFC) return NULL;
    if (!(acl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total))) return NULL;
    if (revision < ACL_REVISION) revision = ACL_REVISION;
    if (!InitializeAcl(acl, total, revision)) goto fail;
    for (i = 0; i < l->n; i++)
    {
        if (explicit_only && is_inherited(&l->a[i])) continue;
        if (!AddAce(acl, revision, MAXDWORD, l->a[i].p, l->a[i].size)) goto fail;
    }
    return acl;
fail:
    HeapFree(GetProcessHeap(), 0, acl);
    return NULL;
}

static BOOL is_container_flags(BYTE f) { return (f & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) != 0; }

/* new ACEs go to the front of their group: deny before allow, and within a group ordered by
   (OI,CI) class 0..3, newest first */
static int insert_position(const acelist *l, BOOL deny, BYTE flags)
{
    int idx = 0, cls = flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);

    while (idx < l->n && !is_inherited(&l->a[idx]))
    {
        BOOL d = is_deny(&l->a[idx]);
        int c = ace_flags(&l->a[idx]) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE);

        if (deny)
        {
            if (!d || c >= cls) break;
        }
        else if (!d && c >= cls) break;
        idx++;
    }
    return idx;
}

static BYTE *make_ace(BOOL deny, PSID sid, DWORD mask, BYTE flags, DWORD *size)
{
    DWORD sidlen = GetLengthSid(sid);
    DWORD sz = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) + sidlen;
    ACCESS_ALLOWED_ACE *ace = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);

    if (!ace) return NULL;
    ace->Header.AceType = deny ? ACCESS_DENIED_ACE_TYPE : ACCESS_ALLOWED_ACE_TYPE;
    ace->Header.AceFlags = flags;
    ace->Header.AceSize = (WORD)sz;
    ace->Mask = mask;
    CopySid(sidlen, (PSID)&ace->SidStart, sid);
    *size = sz;
    return (BYTE *)ace;
}

/* rights that a deny (or grant) takes out of the opposite ACE: SYNCHRONIZE is shared by almost everything
   and is left alone */
static void trim_opposite(acelist *l, PSID sid, BYTE flags, BOOL new_is_deny, DWORD mask)
{
    int i;
    DWORD cut = mask & ~SYNCHRONIZE;

    for (i = 0; i < l->n; i++)
    {
        ace_t *e = &l->a[i];
        DWORD m;

        if (is_inherited(e) || !standard_ace(e) || is_deny(e) == new_is_deny) continue;
        if ((ace_flags(e) & INHERIT_MASK) != flags || !EqualSid(ace_sid(e), sid)) continue;
        m = ace_mask(e) & ~cut;
        if (!(m & ~SYNCHRONIZE)) acelist_delete(l, i--);
        else ((ACCESS_ALLOWED_ACE *)e->p)->Mask = m;
    }
}

static BOOL add_entry(acelist *l, BOOL deny, BOOL replace, PSID sid, DWORD mask, BYTE flags, BOOL is_dir)
{
    int i;
    BYTE *p;
    DWORD size;

    /* inheritance flags only make sense on directories; an inherit-only ACE that inherits to nothing is dropped */
    if (!is_dir && flags) mask = 0;
    if (!is_container_flags(flags))
    {
        if (flags & INHERIT_ONLY_ACE) mask = 0;
        flags &= ~NO_PROPAGATE_INHERIT_ACE;
    }

    trim_opposite(l, sid, flags, deny, mask);
    if (!mask)
    {
        if (replace && !deny)
            for (i = 0; i < l->n; i++)
                if (!is_inherited(&l->a[i]) && standard_ace(&l->a[i]) && !is_deny(&l->a[i]) &&
                    (ace_flags(&l->a[i]) & INHERIT_MASK) == flags && EqualSid(ace_sid(&l->a[i]), sid))
                    acelist_delete(l, i--);
        return TRUE;
    }

    if (!deny)
    {
        for (i = 0; i < l->n; i++)
        {
            ace_t *e = &l->a[i];

            if (is_inherited(e) || !standard_ace(e) || is_deny(e)) continue;
            if ((ace_flags(e) & INHERIT_MASK) != flags || !EqualSid(ace_sid(e), sid)) continue;
            if (replace) ((ACCESS_ALLOWED_ACE *)e->p)->Mask = mask;
            else ((ACCESS_ALLOWED_ACE *)e->p)->Mask |= mask;
            if (replace)
            {
                int j;
                for (j = i + 1; j < l->n; j++)
                    if (!is_inherited(&l->a[j]) && standard_ace(&l->a[j]) && !is_deny(&l->a[j]) &&
                        (ace_flags(&l->a[j]) & INHERIT_MASK) == flags && EqualSid(ace_sid(&l->a[j]), sid))
                        acelist_delete(l, j--);
            }
            return TRUE;
        }
    }

    if (!(p = make_ace(deny, sid, mask, flags, &size))) return FALSE;
    acelist_insert(l, insert_position(l, deny, flags), p, size);
    return TRUE;
}

static void remove_sid(acelist *l, PSID sid, int which /* 0 all, 1 grants, 2 denies */)
{
    int i;

    for (i = 0; i < l->n; i++)
    {
        ace_t *e = &l->a[i];

        if (is_inherited(e) || !standard_ace(e) || !EqualSid(ace_sid(e), sid)) continue;
        if (which == 1 && is_deny(e)) continue;
        if (which == 2 && !is_deny(e)) continue;
        acelist_delete(l, i--);
    }
}

/* ------------------------------------------------------------- parsing */

typedef enum { OP_GRANT, OP_GRANT_R, OP_DENY, OP_REMOVE, OP_REMOVE_G, OP_REMOVE_D,
               OP_INH_E, OP_INH_D, OP_INH_R, OP_RESET } optype;

typedef struct
{
    optype type;
    WCHAR *name;         /* the account part as typed */
    WCHAR *arg;          /* the whole argument as typed */
    PSID sid;
    DWORD mask;
    BYTE flags;
} op_t;

static op_t *ops;
static int nops, capops;

typedef enum { MODE_DISPLAY, MODE_MODIFY, MODE_SAVE, MODE_RESTORE, MODE_SETOWNER, MODE_FINDSID, MODE_VERIFY } mode_t_;

static struct
{
    BOOL t, c, l, q;
    mode_t_ mode;
    const WCHAR *file;   /* save / restore file */
    WCHAR *sidname;      /* setowner / findsid */
    PSID sid;
} opt;

static op_t *new_op(optype type)
{
    if (nops == capops)
    {
        capops = capops ? capops * 2 : 16;
        ops = ops ? HeapReAlloc(GetProcessHeap(), 0, ops, capops * sizeof(op_t))
                  : HeapAlloc(GetProcessHeap(), 0, capops * sizeof(op_t));
        if (!ops) ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
    }
    memset(&ops[nops], 0, sizeof(op_t));
    ops[nops].type = type;
    return &ops[nops++];
}

static const struct { const WCHAR *in, *out; DWORD bits; } specific[] =
{
    { L"DE", L"DE", DELETE }, { L"RC", L"Rc", READ_CONTROL }, { L"WDAC", L"WDAC", WRITE_DAC },
    { L"WO", L"WO", WRITE_OWNER }, { L"S", L"S", SYNCHRONIZE }, { L"AS", L"AS", ACCESS_SYSTEM_SECURITY },
    { L"MA", L"MA", MAXIMUM_ALLOWED }, { L"GR", L"GR", GENERIC_READ }, { L"GW", L"GW", GENERIC_WRITE },
    { L"GE", L"GE", GENERIC_EXECUTE }, { L"GA", L"GA", GENERIC_ALL },
    { L"RD", L"RD", 0x1 }, { L"WD", L"WD", 0x2 }, { L"AD", L"AD", 0x4 }, { L"REA", L"REA", 0x8 },
    { L"WEA", L"WEA", 0x10 }, { L"X", L"X", 0x20 }, { L"DC", L"DC", 0x40 }, { L"RA", L"RA", 0x80 },
    { L"WA", L"WA", 0x100 },
};

static const struct { const WCHAR *name; DWORD bits; } simple[] =
{
    { L"F", F_RIGHTS }, { L"M", M_RIGHTS }, { L"RX", RX_RIGHTS }, { L"R", R_RIGHTS },
    { L"W", W_RIGHTS }, { L"D", D_RIGHTS },
};

static BOOL lookup_right(const WCHAR *tok, int len, DWORD *bits)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(simple); i++)
        if ((int)wcslen(simple[i].name) == len && !_wcsnicmp(tok, simple[i].name, len))
        {
            *bits = simple[i].bits;
            return TRUE;
        }
    for (i = 0; i < ARRAY_SIZE(specific); i++)
        if ((int)wcslen(specific[i].in) == len && !_wcsnicmp(tok, specific[i].in, len))
        {
            *bits = specific[i].bits;
            return TRUE;
        }
    return FALSE;
}

static DWORD map_generic(DWORD mask)
{
    if (mask & GENERIC_READ) mask = (mask & ~GENERIC_READ) | FILE_GEN_READ;
    if (mask & GENERIC_WRITE) mask = (mask & ~GENERIC_WRITE) | FILE_GEN_WRITE;
    if (mask & GENERIC_EXECUTE) mask = (mask & ~GENERIC_EXECUTE) | FILE_GEN_EXEC;
    if (mask & GENERIC_ALL) mask = (mask & ~GENERIC_ALL) | FILE_GEN_ALL;
    return mask & ~(MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
}

static BOOL parse_perm(const WCHAR *p, DWORD *mask, BYTE *flags)
{
    BOOL have_rights = FALSE;

    *mask = 0;
    *flags = 0;
    while (*p)
    {
        if (*p == '(')
        {
            const WCHAR *close = wcschr(p, ')'), *q, *start;
            int len;

            if (!close) return FALSE;
            len = (int)(close - p - 1);
            if (len == 2 && !_wcsnicmp(p + 1, L"OI", 2)) *flags |= OBJECT_INHERIT_ACE;
            else if (len == 2 && !_wcsnicmp(p + 1, L"CI", 2)) *flags |= CONTAINER_INHERIT_ACE;
            else if (len == 2 && !_wcsnicmp(p + 1, L"IO", 2)) *flags |= INHERIT_ONLY_ACE;
            else if (len == 2 && !_wcsnicmp(p + 1, L"NP", 2)) *flags |= NO_PROPAGATE_INHERIT_ACE;
            else
            {
                if (have_rights == FALSE && len == 0) return FALSE;
                start = p + 1;
                for (q = start; q <= close; q++)
                {
                    if (q == close || *q == ',')
                    {
                        DWORD bits;

                        if (q == start || !lookup_right(start, (int)(q - start), &bits)) return FALSE;
                        *mask |= bits;
                        start = q + 1;
                    }
                }
                have_rights = TRUE;
            }
            p = close + 1;
        }
        else
        {
            /* a sequence of simple rights ends the permission */
            while (*p)
            {
                if (!_wcsnicmp(p, L"RX", 2)) { *mask |= RX_RIGHTS; p += 2; }
                else if (*p == 'F' || *p == 'f') { *mask |= F_RIGHTS; p++; }
                else if (*p == 'M' || *p == 'm') { *mask |= M_RIGHTS; p++; }
                else if (*p == 'R' || *p == 'r') { *mask |= R_RIGHTS; p++; }
                else if (*p == 'W' || *p == 'w') { *mask |= W_RIGHTS; p++; }
                else if (*p == 'D' || *p == 'd') { *mask |= D_RIGHTS; p++; }
                else return FALSE;
                have_rights = TRUE;
            }
        }
    }
    if (!have_rights) return FALSE;
    *mask = map_generic(*mask);
    return TRUE;
}

static DWORD resolve_sid(const WCHAR *name, PSID *out)
{
    DWORD sidlen = 0, domlen = 0;
    SID_NAME_USE use;
    WCHAR *dom;
    PSID sid;

    *out = NULL;
    if (name[0] == '*')
    {
        PSID tmp, copy;
        DWORD len;

        if (!ConvertStringSidToSidW(name + 1, &tmp)) return ERR_BAD_SID;
        len = GetLengthSid(tmp);
        if (!(copy = HeapAlloc(GetProcessHeap(), 0, len))) { LocalFree(tmp); return ERROR_NOT_ENOUGH_MEMORY; }
        CopySid(len, copy, tmp);
        LocalFree(tmp);
        *out = copy;
        return ERROR_SUCCESS;
    }
    LookupAccountNameW(NULL, name, NULL, &sidlen, NULL, &domlen, &use);
    if (!sidlen) return ERR_NO_MAPPING;
    sid = HeapAlloc(GetProcessHeap(), 0, sidlen);
    dom = HeapAlloc(GetProcessHeap(), 0, (domlen + 1) * sizeof(WCHAR));
    if (!sid || !dom || !LookupAccountNameW(NULL, name, sid, &sidlen, dom, &domlen, &use))
    {
        HeapFree(GetProcessHeap(), 0, sid);
        HeapFree(GetProcessHeap(), 0, dom);
        return ERR_NO_MAPPING;
    }
    HeapFree(GetProcessHeap(), 0, dom);
    *out = sid;
    return ERROR_SUCCESS;
}

static void bad_param(const WCHAR *arg)
{
    out_printf(L"Invalid parameter \"%ls\"\n", arg);
}

static BOOL is_option(const WCHAR *a) { return a[0] == '/'; }

/* returns 0 on success, otherwise the exit code */
static int parse_args(int argc, WCHAR **argv)
{
    int i = 2;

    while (i < argc)
    {
        WCHAR *a = argv[i];
        optype t;

        if (!_wcsicmp(a, L"/T")) { opt.t = TRUE; i++; }
        else if (!_wcsicmp(a, L"/C")) { opt.c = TRUE; i++; }
        else if (!_wcsicmp(a, L"/L")) { opt.l = TRUE; i++; }
        else if (!_wcsicmp(a, L"/Q")) { opt.q = TRUE; i++; }
        else if (!_wcsicmp(a, L"/grant") || !_wcsicmp(a, L"/grant:r") || !_wcsicmp(a, L"/deny"))
        {
            int first = i + 1;

            t = !_wcsicmp(a, L"/deny") ? OP_DENY : (!_wcsicmp(a, L"/grant") ? OP_GRANT : OP_GRANT_R);
            if (first >= argc || is_option(argv[first])) { bad_param(a); return ERROR_INVALID_PARAMETER; }
            for (i = first; i < argc && !is_option(argv[i]); i++)
            {
                WCHAR *colon = wcsrchr(argv[i], ':');
                op_t *op;
                DWORD mask;
                BYTE flags;

                if (!colon || colon == argv[i] || !parse_perm(colon + 1, &mask, &flags))
                {
                    bad_param(argv[i]);
                    return ERROR_INVALID_PARAMETER;
                }
                op = new_op(t);
                op->arg = argv[i];
                op->name = HeapAlloc(GetProcessHeap(), 0, (colon - argv[i] + 1) * sizeof(WCHAR));
                memcpy(op->name, argv[i], (colon - argv[i]) * sizeof(WCHAR));
                op->name[colon - argv[i]] = 0;
                op->mask = mask;
                op->flags = flags;
            }
            opt.mode = MODE_MODIFY;
        }
        else if (!_wcsicmp(a, L"/remove") || !_wcsicmp(a, L"/remove:g") || !_wcsicmp(a, L"/remove:d"))
        {
            int first = i + 1;

            t = !_wcsicmp(a, L"/remove") ? OP_REMOVE : (!_wcsicmp(a, L"/remove:g") ? OP_REMOVE_G : OP_REMOVE_D);
            if (first >= argc || is_option(argv[first])) { bad_param(a); return ERROR_INVALID_PARAMETER; }
            for (i = first; i < argc && !is_option(argv[i]); i++)
            {
                op_t *op = new_op(t);
                op->arg = op->name = argv[i];
            }
            opt.mode = MODE_MODIFY;
        }
        else if (!_wcsnicmp(a, L"/inheritance:", 13) && a[13] && !a[14] && wcschr(L"edrEDR", a[13]))
        {
            WCHAR c = a[13] | 0x20;
            new_op(c == 'e' ? OP_INH_E : (c == 'd' ? OP_INH_D : OP_INH_R));
            opt.mode = MODE_MODIFY;
            i++;
        }
        else if (!_wcsicmp(a, L"/reset")) { new_op(OP_RESET); opt.mode = MODE_MODIFY; i++; }
        else if (!_wcsicmp(a, L"/verify")) { opt.mode = MODE_VERIFY; i++; }
        else if (!_wcsicmp(a, L"/save") || !_wcsicmp(a, L"/restore") || !_wcsicmp(a, L"/setowner") ||
                 !_wcsicmp(a, L"/findsid"))
        {
            if (i + 1 >= argc || is_option(argv[i + 1])) { bad_param(a); return ERROR_INVALID_PARAMETER; }
            if (!_wcsicmp(a, L"/save")) { opt.mode = MODE_SAVE; opt.file = argv[i + 1]; }
            else if (!_wcsicmp(a, L"/restore")) { opt.mode = MODE_RESTORE; opt.file = argv[i + 1]; }
            else
            {
                opt.mode = !_wcsicmp(a, L"/setowner") ? MODE_SETOWNER : MODE_FINDSID;
                opt.sidname = argv[i + 1];
            }
            i += 2;
        }
        else if (!_wcsicmp(a, L"/setintegritylevel") || !_wcsicmp(a, L"/substitute"))
        {
            out_printf(L"The %ls option is not supported by this version of icacls.\n", a);
            return ERROR_NOT_SUPPORTED;
        }
        else
        {
            bad_param(a);
            return ERROR_INVALID_PARAMETER;
        }
    }
    return 0;
}

/* ------------------------------------------------------------- display */

static WCHAR *account_name(PSID sid)
{
    WCHAR name[256], dom[256], *res;
    DWORD nl = ARRAY_SIZE(name), dl = ARRAY_SIZE(dom);
    SID_NAME_USE use;

    if (LookupAccountSidW(NULL, sid, name, &nl, dom, &dl, &use))
    {
        res = HeapAlloc(GetProcessHeap(), 0, (nl + dl + 2) * sizeof(WCHAR));
        if (dom[0]) _snwprintf(res, nl + dl + 2, L"%ls\\%ls", dom, name);
        else wcscpy(res, name);
        return res;
    }
    else
    {
        WCHAR *str = NULL;

        if (ConvertSidToStringSidW(sid, &str))
        {
            res = HeapAlloc(GetProcessHeap(), 0, (wcslen(str) + 1) * sizeof(WCHAR));
            wcscpy(res, str);
            LocalFree(str);
            return res;
        }
    }
    res = HeapAlloc(GetProcessHeap(), 0, 2 * sizeof(WCHAR));
    wcscpy(res, L"?");
    return res;
}

static void format_rights(DWORD mask, BOOL deny, WCHAR *buf)
{
    DWORD rem = mask;
    size_t i;
    BOOL first = TRUE;

    buf[0] = 0;
    /* a deny of everything reads as "no access"; denies list SYNCHRONIZE along with the rights */
    if (deny) mask |= SYNCHRONIZE;
    rem = mask;
    for (i = 0; i < ARRAY_SIZE(simple); i++)
    {
        if ((mask & simple[i].bits) != simple[i].bits) continue;
        if (i == 3 && (mask & RX_RIGHTS) == RX_RIGHTS) continue; /* R is part of RX */
        if (!first) wcscat(buf, L",");
        wcscat(buf, simple[i].name);
        first = FALSE;
        rem &= ~simple[i].bits;
        if (i < 2) { rem = 0; break; } /* F and M cover everything below them */
    }
    for (i = 0; i < ARRAY_SIZE(specific); i++)
    {
        if (specific[i].bits >= 0x10000000 || !(rem & specific[i].bits)) continue;
        if (!first) wcscat(buf, L",");
        wcscat(buf, specific[i].out);
        first = FALSE;
        rem &= ~specific[i].bits;
    }
    if (rem)
    {
        WCHAR hex[16];
        _snwprintf(hex, ARRAY_SIZE(hex), L"%ls0x%lx", first ? L"" : L",", rem);
        wcscat(buf, hex);
    }
}

static void print_dacl(const WCHAR *path, PACL dacl)
{
    int i, indent = (int)wcslen(path) + 1;
    BOOL first = TRUE;

    out_printf(L"%ls ", path);
    if (dacl)
    {
        for (i = 0; i < dacl->AceCount; i++)
        {
            ace_t e;
            WCHAR *name, rights[256], flags[64];
            BYTE f;
            BOOL deny, all;

            if (!GetAce(dacl, i, (void **)&e.p)) continue;
            e.size = ((ACE_HEADER *)e.p)->AceSize;
            if (!standard_ace(&e)) continue;
            f = ace_flags(&e);
            deny = is_deny(&e);
            name = account_name(ace_sid(&e));
            flags[0] = 0;
            if (f & INHERITED_ACE) wcscat(flags, L"(I)");
            if (f & OBJECT_INHERIT_ACE) wcscat(flags, L"(OI)");
            if (f & CONTAINER_INHERIT_ACE) wcscat(flags, L"(CI)");
            if (f & NO_PROPAGATE_INHERIT_ACE) wcscat(flags, L"(NP)");
            if (f & INHERIT_ONLY_ACE) wcscat(flags, L"(IO)");
            all = deny && (ace_mask(&e) & F_RIGHTS) == F_RIGHTS;
            if (all) wcscpy(rights, L"N");
            else format_rights(ace_mask(&e), deny, rights);
            if (!first) out_printf(L"%*ls", indent, L"");
            out_printf(L"%ls:%ls%ls(%ls)\n", name, flags, deny && !all ? L"(DENY)" : L"", rights);
            first = FALSE;
            HeapFree(GetProcessHeap(), 0, name);
        }
    }
    if (first) out_printf(L"\n");
    out_printf(L"\n");
}

/* ---------------------------------------------------------- processing */

static DWORD processed, failed, first_error;
static BOOL found_sid;
static HANDLE save_handle = INVALID_HANDLE_VALUE;
static size_t save_prefix;

static BOOL read_security(const WCHAR *path, SECURITY_INFORMATION si, PSECURITY_DESCRIPTOR *sd, PACL *dacl,
                          BOOL *protect, DWORD *err)
{
    SECURITY_DESCRIPTOR_CONTROL ctl;
    DWORD rev;

    *dacl = NULL;
    *sd = NULL;
    *err = GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, si, NULL, NULL, dacl, NULL, sd);
    if (*err) return FALSE;
    if (protect)
    {
        *protect = FALSE;
        if (GetSecurityDescriptorControl(*sd, &ctl, &rev)) *protect = (ctl & SE_DACL_PROTECTED) != 0;
    }
    return TRUE;
}

static void report_failure(const WCHAR *path, DWORD err)
{
    out_printf(L"%ls: ", path);
    out_error_text(err);
    out_printf(L"\n");
    failed++;
    if (!first_error) first_error = err;
}

static DWORD write_dacl(const WCHAR *path, const acelist *l, UCHAR revision, BOOL protect)
{
    PACL acl = acelist_build(l, revision, !protect);
    DWORD err;

    if (!acl) return ERROR_NOT_ENOUGH_MEMORY;
    err = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                                DACL_SECURITY_INFORMATION |
                                (protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION),
                                NULL, NULL, acl, NULL);
    HeapFree(GetProcessHeap(), 0, acl);
    return err;
}

static WCHAR *join_path(const WCHAR *dir, const WCHAR *name)
{
    size_t dl = wcslen(dir), nl = wcslen(name);
    WCHAR *r = HeapAlloc(GetProcessHeap(), 0, (dl + nl + 2) * sizeof(WCHAR));

    wcscpy(r, dir);
    if (dl && r[dl - 1] != '\\' && r[dl - 1] != '/') wcscat(r, L"\\");
    wcscat(r, name);
    return r;
}

static DWORD apply_ops(const WCHAR *path, BOOL is_dir)
{
    PSECURITY_DESCRIPTOR sd;
    PACL dacl;
    BOOL protect;
    DWORD err;
    acelist l;
    UCHAR rev;
    int i;

    if (!read_security(path, DACL_SECURITY_INFORMATION, &sd, &dacl, &protect, &err)) return err;
    if (!acelist_load(&l, dacl, &rev)) { LocalFree(sd); return ERROR_NOT_ENOUGH_MEMORY; }
    for (i = 0; i < nops; i++)
    {
        op_t *op = &ops[i];
        int j;

        switch (op->type)
        {
        case OP_GRANT:
        case OP_GRANT_R:
        case OP_DENY:
            add_entry(&l, op->type == OP_DENY, op->type == OP_GRANT_R, op->sid, op->mask, op->flags, is_dir);
            break;
        case OP_REMOVE: remove_sid(&l, op->sid, 0); break;
        case OP_REMOVE_G: remove_sid(&l, op->sid, 1); break;
        case OP_REMOVE_D: remove_sid(&l, op->sid, 2); break;
        case OP_INH_E: protect = FALSE; break;
        case OP_INH_D:
            for (j = 0; j < l.n; j++) ((ACE_HEADER *)l.a[j].p)->AceFlags &= ~INHERITED_ACE;
            protect = TRUE;
            break;
        case OP_INH_R:
            for (j = 0; j < l.n; j++)
                if (is_inherited(&l.a[j])) acelist_delete(&l, j--);
            protect = TRUE;
            break;
        case OP_RESET:
            acelist_free(&l);
            protect = FALSE;
            break;
        }
    }
    /* SetNamedSecurityInfo passes the inheritable entries on to what exists below a directory */
    err = write_dacl(path, &l, rev, protect);
    acelist_free(&l);
    LocalFree(sd);
    return err;
}

static BOOL canonical(const acelist *l)
{
    int i, stage = 0; /* 0 explicit deny, 1 explicit allow, 2 inherited deny, 3 inherited allow */

    for (i = 0; i < l->n; i++)
    {
        int s;

        if (!standard_ace(&l->a[i])) continue;
        s = (is_inherited(&l->a[i]) ? 2 : 0) + (is_deny(&l->a[i]) ? 0 : 1);
        if (s < stage) return FALSE;
        stage = s;
    }
    return TRUE;
}

static BOOL acl_mentions(PACL dacl, PSID sid)
{
    int i;
    void *ace;

    if (!dacl) return FALSE;
    for (i = 0; i < dacl->AceCount; i++)
    {
        ace_t e;

        if (!GetAce(dacl, i, &ace)) continue;
        e.p = ace;
        e.size = ((ACE_HEADER *)ace)->AceSize;
        if (standard_ace(&e) && EqualSid(ace_sid(&e), sid)) return TRUE;
    }
    return FALSE;
}

static void write_save(const WCHAR *rel, const WCHAR *sddl)
{
    DWORD written;
    static const WCHAR crlf[] = L"\r\n";

    WriteFile(save_handle, rel, (DWORD)(wcslen(rel) * sizeof(WCHAR)), &written, NULL);
    WriteFile(save_handle, crlf, sizeof(crlf) - sizeof(WCHAR), &written, NULL);
    WriteFile(save_handle, sddl, (DWORD)(wcslen(sddl) * sizeof(WCHAR)), &written, NULL);
    WriteFile(save_handle, crlf, sizeof(crlf) - sizeof(WCHAR), &written, NULL);
}

/* handles one name; returns FALSE when processing must stop */
static BOOL handle_name(const WCHAR *path, DWORD attrs)
{
    BOOL is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    DWORD err = 0;

    switch (opt.mode)
    {
    case MODE_DISPLAY:
        if (!read_security(path, DACL_SECURITY_INFORMATION, &sd, &dacl, NULL, &err)) break;
        print_dacl(path, dacl);
        LocalFree(sd);
        break;
    case MODE_MODIFY:
        err = apply_ops(path, is_dir);
        if (!err && !opt.q) out_printf(L"processed file: %ls\n", path);
        break;
    case MODE_SETOWNER:
        err = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, opt.sid, NULL, NULL, NULL);
        if (!err && !opt.q) out_printf(L"processed file: %ls\n", path);
        break;
    case MODE_FINDSID:
        if (!read_security(path, DACL_SECURITY_INFORMATION, &sd, &dacl, NULL, &err)) break;
        if (acl_mentions(dacl, opt.sid))
        {
            out_printf(L"SID Found: %ls.\n", path);
            found_sid = TRUE;
        }
        LocalFree(sd);
        break;
    case MODE_VERIFY:
    {
        acelist l;
        UCHAR rev;

        if (!read_security(path, DACL_SECURITY_INFORMATION, &sd, &dacl, NULL, &err)) break;
        if (acelist_load(&l, dacl, &rev))
        {
            if (!canonical(&l)) out_printf(L"%ls: the ACL is not in canonical form\n", path);
            else if (!opt.q) out_printf(L"processed file: %ls\n", path);
            acelist_free(&l);
        }
        LocalFree(sd);
        break;
    }
    case MODE_SAVE:
    {
        WCHAR *sddl = NULL;

        if (!read_security(path, DACL_SECURITY_INFORMATION, &sd, &dacl, NULL, &err)) break;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                                                                  &sddl, NULL))
            err = GetLastError();
        else
        {
            write_save(path + save_prefix, sddl);
            LocalFree(sddl);
            if (!opt.q) out_printf(L"processed file: %ls\n", path);
        }
        LocalFree(sd);
        break;
    }
    default:
        break;
    }
    if (err)
    {
        report_failure(path, err);
        return opt.c;
    }
    processed++;
    return TRUE;
}

typedef struct
{
    WIN32_FIND_DATAW *e;
    int n;
} dlist;

/* the entries of a directory; taken before the directory's own DACL is touched, since a restrictive
   result (an empty DACL after /inheritance:r) would stop us from listing it afterwards */
static dlist list_dir(const WCHAR *dir)
{
    dlist l = { NULL, 0 };
    int cap = 0;
    WCHAR *pattern = join_path(dir, L"*");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);

    HeapFree(GetProcessHeap(), 0, pattern);
    if (h == INVALID_HANDLE_VALUE) return l;
    do
    {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        if (l.n == cap)
        {
            cap = cap ? cap * 2 : 32;
            l.e = l.e ? HeapReAlloc(GetProcessHeap(), 0, l.e, cap * sizeof(*l.e))
                      : HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*l.e));
            if (!l.e) ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
        }
        l.e[l.n++] = fd;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return l;
}

static BOOL descend(DWORD attrs)
{
    return opt.t && (attrs & FILE_ATTRIBUTE_DIRECTORY) && !(attrs & FILE_ATTRIBUTE_REPARSE_POINT);
}

/* processes the entries of dir (list is consumed), then the contents of its subdirectories */
static BOOL walk(const WCHAR *dir, dlist *l)
{
    dlist *subs = l->n ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, l->n * sizeof(dlist)) : NULL;
    BOOL ok = TRUE;
    int i;

    for (i = 0; i < l->n && ok; i++)
    {
        WCHAR *p = join_path(dir, l->e[i].cFileName);

        if (descend(l->e[i].dwFileAttributes)) subs[i] = list_dir(p);
        ok = handle_name(p, l->e[i].dwFileAttributes);
        /* a directory whose DACL denied listing may be listable now */
        if (ok && descend(l->e[i].dwFileAttributes) && !subs[i].n) subs[i] = list_dir(p);
        HeapFree(GetProcessHeap(), 0, p);
    }
    for (i = 0; i < l->n; i++)
    {
        if (ok && descend(l->e[i].dwFileAttributes))
        {
            WCHAR *p = join_path(dir, l->e[i].cFileName);
            ok = walk(p, &subs[i]);
            HeapFree(GetProcessHeap(), 0, p);
        }
        else HeapFree(GetProcessHeap(), 0, subs[i].e);
    }
    HeapFree(GetProcessHeap(), 0, subs);
    HeapFree(GetProcessHeap(), 0, l->e);
    return ok;
}

static BOOL process_one(const WCHAR *path, DWORD attrs)
{
    dlist l = { NULL, 0 };
    BOOL ok, listed = descend(attrs);

    if (listed) l = list_dir(path);
    ok = handle_name(path, attrs);
    if (ok && listed && !l.n) l = list_dir(path);
    if (ok && listed) return walk(path, &l);
    HeapFree(GetProcessHeap(), 0, l.e);
    return ok;
}

static void process_name(const WCHAR *name)
{
    const WCHAR *slash = wcsrchr(name, '\\'), *slash2 = wcsrchr(name, '/'), *pat;
    size_t dirlen;
    BOOL wild;

    if (slash2 > slash) slash = slash2;
    dirlen = slash ? (size_t)(slash - name + 1) : 0;
    pat = name + dirlen;
    wild = wcspbrk(pat, L"*?") != NULL;
    save_prefix = dirlen;

    if (wild)
    {
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(name, &fd);
        WCHAR **paths = NULL;
        DWORD *attrs = NULL;
        int n = 0, cap = 0, i;
        BOOL ok = TRUE;
        dlist *subs;

        if (h == INVALID_HANDLE_VALUE)
        {
            report_failure(name, GetLastError());
            return;
        }
        do
        {
            WCHAR *p;

            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
            if (n == cap)
            {
                cap = cap ? cap * 2 : 32;
                paths = paths ? HeapReAlloc(GetProcessHeap(), 0, paths, cap * sizeof(*paths))
                              : HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*paths));
                attrs = attrs ? HeapReAlloc(GetProcessHeap(), 0, attrs, cap * sizeof(*attrs))
                              : HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*attrs));
                if (!paths || !attrs) ExitProcess(ERROR_NOT_ENOUGH_MEMORY);
            }
            p = HeapAlloc(GetProcessHeap(), 0, (dirlen + wcslen(fd.cFileName) + 1) * sizeof(WCHAR));
            memcpy(p, name, dirlen * sizeof(WCHAR));
            wcscpy(p + dirlen, fd.cFileName);
            paths[n] = p;
            attrs[n++] = fd.dwFileAttributes;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
        if (!n) report_failure(name, ERROR_FILE_NOT_FOUND);

        /* all matches first, then the contents of the matching directories */
        subs = n ? HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * sizeof(dlist)) : NULL;
        for (i = 0; i < n && ok; i++)
        {
            if (descend(attrs[i])) subs[i] = list_dir(paths[i]);
            ok = handle_name(paths[i], attrs[i]);
            if (ok && descend(attrs[i]) && !subs[i].n) subs[i] = list_dir(paths[i]);
        }
        for (i = 0; i < n; i++)
        {
            if (ok && descend(attrs[i])) ok = walk(paths[i], &subs[i]);
            else HeapFree(GetProcessHeap(), 0, subs[i].e);
        }
        HeapFree(GetProcessHeap(), 0, subs);
        for (i = 0; i < n; i++) HeapFree(GetProcessHeap(), 0, paths[i]);
        HeapFree(GetProcessHeap(), 0, paths);
        HeapFree(GetProcessHeap(), 0, attrs);
    }
    else
    {
        DWORD attrs = GetFileAttributesW(name);

        if (attrs == INVALID_FILE_ATTRIBUTES)
        {
            report_failure(name, GetLastError());
            return;
        }
        process_one(name, attrs);
    }
}

/* ------------------------------------------------------------- restore */

static WCHAR *read_unicode_file(const WCHAR *file, DWORD *err)
{
    HANDLE h = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD size, got;
    BYTE *buf;
    WCHAR *text;

    if (h == INVALID_HANDLE_VALUE) { *err = GetLastError(); return NULL; }
    size = GetFileSize(h, NULL);
    buf = HeapAlloc(GetProcessHeap(), 0, size + 4);
    if (!buf || !ReadFile(h, buf, size, &got, NULL)) { *err = GetLastError(); CloseHandle(h); return NULL; }
    CloseHandle(h);
    memset(buf + got, 0, 4);
    text = (WCHAR *)buf;
    if (got >= 2 && text[0] == 0xFEFF) text++;
    *err = 0;
    return text;
}

static void restore_one(const WCHAR *path, const WCHAR *sddl)
{
    PSECURITY_DESCRIPTOR sd;
    PACL dacl;
    BOOL present, defaulted, protect = FALSE;
    SECURITY_DESCRIPTOR_CONTROL ctl;
    DWORD rev, err;
    acelist l;
    UCHAR arev;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL))
    {
        report_failure(path, GetLastError());
        return;
    }
    GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted);
    if (GetSecurityDescriptorControl(sd, &ctl, &rev)) protect = (ctl & SE_DACL_PROTECTED) != 0;
    if (!acelist_load(&l, present ? dacl : NULL, &arev)) { LocalFree(sd); report_failure(path, ERROR_NOT_ENOUGH_MEMORY); return; }
    err = write_dacl(path, &l, arev, protect);
    acelist_free(&l);
    LocalFree(sd);
    if (err) { report_failure(path, err); return; }
    if (!opt.q) out_printf(L"processed file: %ls\n", path);
    processed++;
}

static int do_restore(const WCHAR *dirname)
{
    DWORD err;
    WCHAR *text = read_unicode_file(opt.file, &err), *p, *dir;
    size_t dl = wcslen(dirname);

    if (!text)
    {
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) out_printf(L"No such file or directory\n");
        else { out_error_text(err); out_printf(L"\n"); }
        out_printf(L"Successfully processed 0 files; Failed processing 0 files\n");
        return err == ERROR_PATH_NOT_FOUND ? ERROR_FILE_NOT_FOUND : err;
    }
    dir = _wcsdup(dirname);
    while (dl > 1 && (dir[dl - 1] == '\\' || dir[dl - 1] == '/')) dir[--dl] = 0;
    for (p = text; *p;)
    {
        WCHAR *name = p, *sddl, *e;

        e = wcschr(p, '\n');
        if (!e) break;
        *e = 0;
        if (e > name && e[-1] == '\r') e[-1] = 0;
        sddl = e + 1;
        e = wcschr(sddl, '\n');
        if (e) { *e = 0; if (e > sddl && e[-1] == '\r') e[-1] = 0; p = e + 1; }
        else p += wcslen(p);
        if (!name[0] || !sddl[0]) continue;
        {
            WCHAR *full = join_path(dir, name);

            if (GetFileAttributesW(full) != INVALID_FILE_ATTRIBUTES) restore_one(full, sddl);
            HeapFree(GetProcessHeap(), 0, full);
        }
        if (failed && !opt.c) break;
    }
    free(dir);
    out_printf(L"Successfully processed %lu files; Failed processing %lu files\n", processed, failed);
    return opt.c ? 0 : first_error;
}

/* ---------------------------------------------------------------- main */

/* like the Windows tool, use the backup privilege (when held) so that directories whose DACL denies listing
   can still be walked */
static void enable_privilege(const WCHAR *name)
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValueW(NULL, name, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(token);
}

int __cdecl wmain(int argc, WCHAR *argv[])
{
    int i, rc;

    out_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    {
        DWORD mode;
        out_console = GetFileType(out_handle) == FILE_TYPE_CHAR && GetConsoleMode(out_handle, &mode);
    }
    out_cp = GetConsoleOutputCP();
    if (!out_cp) out_cp = GetOEMCP();
    enable_privilege(L"SeBackupPrivilege");
    enable_privilege(L"SeRestorePrivilege");

    if (argc < 2)
    {
        usage();
        return ERROR_BAD_ARGUMENTS;
    }
    if (!wcscmp(argv[1], L"/?") || !wcscmp(argv[1], L"-?"))
    {
        usage();
        return 0;
    }
    if (is_option(argv[1]))
    {
        out_printf(L"First parameter must be a file name pattern or \"/?\"\n");
        usage();
        return ERROR_INVALID_PARAMETER;
    }
    for (i = 2; i < argc; i++)
        if (!wcscmp(argv[i], L"/?"))
        {
            usage();
            return 0;
        }

    if ((rc = parse_args(argc, argv))) return rc;

    /* resolve every account before touching a file */
    for (i = 0; i < nops; i++)
    {
        DWORD err;

        if (!ops[i].name) continue;
        err = resolve_sid(ops[i].name, &ops[i].sid);
        if (err)
        {
            if (ops[i].type == OP_REMOVE || ops[i].type == OP_REMOVE_G || ops[i].type == OP_REMOVE_D)
            {
                out_printf(L"Successfully processed 0 files; Failed processing 0 files\n");
                return err;
            }
            out_printf(L"%ls: ", ops[i].name);
            out_error_text(err);
            out_printf(L"\nSuccessfully processed 0 files; Failed processing 1 files\n");
            return err;
        }
    }
    if (opt.sidname)
    {
        DWORD err = resolve_sid(opt.sidname, &opt.sid);

        if (err)
        {
            if (opt.mode == MODE_FINDSID) out_printf(L"No files with a matching SID was found\n");
            else { out_error_text(err); out_printf(L"\n"); }
            out_printf(L"Successfully processed 0 files; Failed processing 0 files\n");
            return err;
        }
    }

    if (opt.mode == MODE_RESTORE) return do_restore(argv[1]);

    if (opt.mode == MODE_SAVE)
    {
        save_handle = CreateFileW(opt.file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (save_handle == INVALID_HANDLE_VALUE)
        {
            DWORD err = GetLastError();

            out_printf(L"%ls: ", opt.file);
            out_error_text(err);
            out_printf(L"\nSuccessfully processed 0 files; Failed processing 0 files\n");
            return err;
        }
    }

    process_name(argv[1]);

    if (save_handle != INVALID_HANDLE_VALUE) CloseHandle(save_handle);
    if (opt.mode == MODE_FINDSID && !found_sid && !failed) out_printf(L"No files with a matching SID was found\n");
    if (opt.mode == MODE_SAVE && opt.q) processed = 0; /* the Windows tool reports no files for a quiet save */
    out_printf(L"Successfully processed %lu files; Failed processing %lu files\n", processed, failed);
    return opt.c ? 0 : first_error;
}
