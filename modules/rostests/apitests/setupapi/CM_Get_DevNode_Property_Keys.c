/*
 * PROJECT:     ReactOS API Tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Tests for CM_Get_DevNode_Property_Keys and CM_Get_DevNode_Property_Keys_Ex (cfgmgr32.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The return codes were measured on Windows 10 22H2 (x64 and x86). The devnodes and their properties differ from
 * system to system (Windows keeps many more in its property store), so the lists are compared with what
 * CM_Get_DevNode_PropertyW says about the same devnode: every key of the list has a value, and the keys that are
 * always there are in it.
 */

#include <apitest.h>

#define WIN32_NO_STATUS
#define INITGUID
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <cfgmgr32.h>
#include <devpropdef.h>
#include <devpkey.h>

typedef CONFIGRET (WINAPI *FN_KEYS)(DEVINST, DEVPROPKEY *, PULONG, ULONG);
typedef CONFIGRET (WINAPI *FN_KEYS_EX)(DEVINST, DEVPROPKEY *, PULONG, ULONG, HMACHINE);
typedef CONFIGRET (WINAPI *FN_PROP)(DEVINST, const DEVPROPKEY *, DEVPROPTYPE *, PBYTE, PULONG, ULONG);

static FN_KEYS pKeys;
static FN_PROP pProperty;

#define FILL 0xab

static BOOL InList(const DEVPROPKEY *Keys, ULONG Count, const DEVPROPKEY *Key)
{
    ULONG i;

    for (i = 0; i < Count; i++)
        if (Keys[i].pid == Key->pid && IsEqualGUID(&Keys[i].fmtid, &Key->fmtid))
            return TRUE;
    return FALSE;
}

static void CheckDevNode(DEVINST Dev, BOOL HasParent)
{
    DEVPROPKEY Keys[256], Small[256];
    WCHAR Id[MAX_DEVICE_ID_LEN];
    ULONG Count, Need, i, j;
    DEVPROPTYPE Type;
    CONFIGRET cr;

    if (CM_Get_Device_IDW(Dev, Id, ARRAYSIZE(Id), 0) != CR_SUCCESS)
        return;

    /* The size: no buffer, or a buffer of none */
    Count = 0;
    cr = pKeys(Dev, NULL, &Count, 0);
    ok(cr == CR_BUFFER_SMALL && Count > 0, "%ls: size query: %lx, count %lu\n", Id, cr, Count);
    Need = Count;
    Count = 0;
    cr = pKeys(Dev, Keys, &Count, 0);
    ok(cr == CR_BUFFER_SMALL && Count == Need, "%ls: count 0: %lx, count %lu, expected %lu\n", Id, cr, Count, Need);

    /* One short: the count, and the array is not touched */
    if (Need > 1)
    {
        memset(Small, FILL, sizeof(Small));
        Count = Need - 1;
        cr = pKeys(Dev, Small, &Count, 0);
        ok(cr == CR_BUFFER_SMALL && Count == Need, "%ls: short array: %lx, count %lu, expected %lu\n", Id, cr, Count, Need);
        ok(Small[0].pid == 0xabababab, "%ls: the short array was written\n", Id);
    }

    /* Enough, and more than enough */
    Count = ARRAYSIZE(Keys);
    memset(Keys, 0, sizeof(Keys));
    cr = pKeys(Dev, Keys, &Count, 0);
    ok(cr == CR_SUCCESS && Count == Need, "%ls: full: %lx, count %lu, expected %lu\n", Id, cr, Count, Need);
    if (cr != CR_SUCCESS)
        return;

    /* No key twice, each has a value */
    for (i = 0; i < Count; i++)
    {
        ULONG Size = 0;

        for (j = i + 1; j < Count; j++)
            ok(!(Keys[i].pid == Keys[j].pid && IsEqualGUID(&Keys[i].fmtid, &Keys[j].fmtid)), "%ls: key %lu twice\n", Id, i);

        Type = 0xdeadbeef;
        cr = pProperty(Dev, &Keys[i], &Type, NULL, &Size, 0);
        ok(cr == CR_BUFFER_SMALL || cr == CR_SUCCESS, "%ls: key %lu (pid %lu) is listed but has no value: %lx\n", Id, i, Keys[i].pid, cr);
    }

    /* The properties every devnode has */
    ok(InList(Keys, Count, &DEVPKEY_Device_InstanceId), "%ls: no instance ID in the list\n", Id);
    ok(InList(Keys, Count, &DEVPKEY_Device_DevNodeStatus), "%ls: no status in the list\n", Id);
    ok(InList(Keys, Count, &DEVPKEY_Device_ProblemCode), "%ls: no problem code in the list\n", Id);
    if (HasParent)
        ok(InList(Keys, Count, &DEVPKEY_Device_Parent), "%ls: no parent in the list\n", Id);
    else
        ok(!InList(Keys, Count, &DEVPKEY_Device_Parent), "%ls: a parent in the list of the root\n", Id);
}

START_TEST(CM_Get_DevNode_Property_Keys)
{
    HMODULE hCfgMgr = LoadLibraryW(L"cfgmgr32.dll");
    FN_KEYS_EX pKeysEx;
    DEVPROPKEY Keys[8];
    DEVINST Root, Child, Grandchild;
    ULONG Count;
    CONFIGRET cr;
    unsigned Seen = 0;

    pKeys = hCfgMgr ? (FN_KEYS)GetProcAddress(hCfgMgr, "CM_Get_DevNode_Property_Keys") : NULL;
    pKeysEx = hCfgMgr ? (FN_KEYS_EX)GetProcAddress(hCfgMgr, "CM_Get_DevNode_Property_Keys_Ex") : NULL;
    pProperty = hCfgMgr ? (FN_PROP)GetProcAddress(hCfgMgr, "CM_Get_DevNode_PropertyW") : NULL;
    if (!pKeys || !pKeysEx || !pProperty)
    {
        ok(!is_reactos(), "CM_Get_DevNode_Property_Keys is not exported by cfgmgr32.dll\n");
        skip("CM_Get_DevNode_Property_Keys is not available\n");
        return;
    }

    cr = CM_Locate_DevNodeW(&Root, NULL, 0);
    ok(cr == CR_SUCCESS, "CM_Locate_DevNode failed with %lx\n", cr);
    if (cr != CR_SUCCESS)
        return;

    /* Parameters */
    Count = 5;
    cr = pKeys(0, Keys, &Count, 0);
    ok(cr == CR_INVALID_DEVNODE && Count == 5, "devnode 0: %lx, count %lu\n", cr, Count);
    Count = 5;
    cr = pKeys(0x12345, Keys, &Count, 0);
    ok(cr == CR_INVALID_DEVNODE && Count == 5, "bogus devnode: %lx, count %lu\n", cr, Count);
    Count = 5;
    cr = pKeys(Root, Keys, &Count, 1);
    ok(cr == CR_INVALID_FLAG && Count == 5, "flags 1: %lx, count %lu\n", cr, Count);
    cr = pKeys(Root, Keys, NULL, 0);
    ok(cr == CR_INVALID_POINTER, "no count: %lx\n", cr);
    Count = 5;
    cr = pKeys(Root, NULL, &Count, 0);
    ok(cr == CR_INVALID_POINTER && Count == 5, "no array with a count: %lx, count %lu\n", cr, Count);

    /* The extended call with the local machine gives the same */
    {
        ULONG Plain = 0, Extended = 0;

        pKeys(Root, NULL, &Plain, 0);
        cr = pKeysEx(Root, NULL, &Extended, 0, NULL);
        ok(cr == CR_BUFFER_SMALL && Extended == Plain, "extended call: %lx, count %lu, expected %lu\n", cr, Extended, Plain);
    }

    CheckDevNode(Root, FALSE);
    for (cr = CM_Get_Child(&Child, Root, 0); cr == CR_SUCCESS && Seen < 4; cr = CM_Get_Sibling(&Child, Child, 0), Seen++)
    {
        CheckDevNode(Child, TRUE);
        if (CM_Get_Child(&Grandchild, Child, 0) == CR_SUCCESS)
            CheckDevNode(Grandchild, TRUE);
    }
    ok(Seen > 0, "the root has no children\n");
}
