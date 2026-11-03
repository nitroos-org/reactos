/*
 * PROJECT:     ReactOS Timedate Control Panel
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dll/cpl/timedate/timezone.c
 * PURPOSE:     Time Zone property page
 * COPYRIGHT:   Copyright 2004-2005 Eric Kohl
 *              Copyright 2006 Ged Murphy <gedmurphy@gmail.com>
 *              Copyright 2006 Christoph v. Wittich <Christoph@ActiveVB.de>
 *
 */

#include "timedate.h"
#include <tzlib.h>

typedef struct _TIMEZONE_ENTRY
{
    struct _TIMEZONE_ENTRY *Prev;
    struct _TIMEZONE_ENTRY *Next;
    WCHAR Description[128]; /* 'Display' */
    WCHAR StandardName[33]; /* 'Std' */
    WCHAR DaylightName[33]; /* 'Dlt' */
    WCHAR KeyName[128]; /* Key name under 'Time Zones' */
    REG_TZI_FORMAT TimezoneInfo; /* 'TZI' */
} TIMEZONE_ENTRY, *PTIMEZONE_ENTRY;


static HBITMAP hBitmap = NULL;
static int cxSource, cySource;

PTIMEZONE_ENTRY TimeZoneListHead = NULL;
PTIMEZONE_ENTRY TimeZoneListTail = NULL;

static PTIMEZONE_ENTRY
GetSelectedTimeZoneEntry(HWND hwndCombo)
{
    PTIMEZONE_ENTRY Entry;
    DWORD dwIndex;
    DWORD i;

    dwIndex = (DWORD)SendMessageW(hwndCombo, CB_GETCURSEL, 0, 0);
    if (dwIndex == CB_ERR)
        return NULL;

    for (Entry = TimeZoneListHead, i = 0; i < dwIndex; i++, Entry = Entry->Next)
    {
        if (Entry == NULL)
            return NULL;
    }

    return Entry;
}

static BOOL
HasDaylightSaving(PTIMEZONE_ENTRY Entry)
{
    /* If StandardDate.wMonth is 0, DST does not apply to this timezone */
    return (Entry != NULL && Entry->TimezoneInfo.StandardDate.wMonth != 0);
}

static VOID
UpdateDstCheckbox(HWND hwndDlg)
{
    HWND hwndCombo = GetDlgItem(hwndDlg, IDC_TIMEZONELIST);
    HWND hwndCheckbox = GetDlgItem(hwndDlg, IDC_AUTODAYLIGHT);
    PTIMEZONE_ENTRY Entry;
    BOOL bHasDst;

    Entry = GetSelectedTimeZoneEntry(hwndCombo);
    bHasDst = HasDaylightSaving(Entry);

    /* Enable or disable the checkbox based on DST support, and respect user preference when DST is supported */
    if (bHasDst)
    {
        BOOL bAutoDaylight = GetAutoDaylight();

        EnableWindow(hwndCheckbox, TRUE);
        SendMessageW(hwndCheckbox,
                     BM_SETCHECK,
                     bAutoDaylight ? BST_CHECKED : BST_UNCHECKED,
                     0);
    }
    else
    {
        EnableWindow(hwndCheckbox, FALSE);
        SendMessageW(hwndCheckbox, BM_SETCHECK, BST_UNCHECKED, 0);
    }
}

static
PTIMEZONE_ENTRY
GetLargerTimeZoneEntry(
    LONG Bias,
    LPWSTR lpDescription)
{
    PTIMEZONE_ENTRY Entry;

    Entry = TimeZoneListHead;
    while (Entry != NULL)
    {
        if (Entry->TimezoneInfo.Bias < Bias)
            return Entry;
        if (Entry->TimezoneInfo.Bias == Bias)
        {
            if (_wcsicmp(Entry->Description, lpDescription) > 0)
                return Entry;
        }

        Entry = Entry->Next;
    }

    return NULL;
}

static LONG
RetrieveTimeZone(
    IN HKEY hZoneKey,
    IN PCWSTR ZoneKeyName,
    IN PVOID Context)
{
    LONG lError;
    PTIMEZONE_ENTRY Entry;
    PTIMEZONE_ENTRY Current;
    ULONG DescriptionSize;
    ULONG StandardNameSize;
    ULONG DaylightNameSize;

    Entry = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TIMEZONE_ENTRY));
    if (Entry == NULL)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    DescriptionSize  = sizeof(Entry->Description);
    StandardNameSize = sizeof(Entry->StandardName);
    DaylightNameSize = sizeof(Entry->DaylightName);

    lError = QueryTimeZoneData(hZoneKey,
                               NULL,
                               &Entry->TimezoneInfo,
                               Entry->Description,
                               &DescriptionSize,
                               Entry->StandardName,
                               &StandardNameSize,
                               Entry->DaylightName,
                               &DaylightNameSize);
    if (lError != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, Entry);
        return lError;
    }

    /* A name too long for TimeZoneKeyName stays empty and is never matched */
    if (wcslen(ZoneKeyName) < ARRAYSIZE(Entry->KeyName))
        StringCchCopyW(Entry->KeyName, ARRAYSIZE(Entry->KeyName), ZoneKeyName);

    if (TimeZoneListHead == NULL &&
        TimeZoneListTail == NULL)
    {
        Entry->Prev = NULL;
        Entry->Next = NULL;
        TimeZoneListHead = Entry;
        TimeZoneListTail = Entry;
    }
    else
    {
        Current = GetLargerTimeZoneEntry(Entry->TimezoneInfo.Bias, Entry->Description);
        if (Current != NULL)
        {
            if (Current == TimeZoneListHead)
            {
                /* Prepend to head */
                Entry->Prev = NULL;
                Entry->Next = TimeZoneListHead;
                TimeZoneListHead->Prev = Entry;
                TimeZoneListHead = Entry;
            }
            else
            {
                /* Insert before current */
                Entry->Prev = Current->Prev;
                Entry->Next = Current;
                Current->Prev->Next = Entry;
                Current->Prev = Entry;
            }
        }
        else
        {
            /* Append to tail */
            Entry->Prev = TimeZoneListTail;
            Entry->Next = NULL;
            TimeZoneListTail->Next = Entry;
            TimeZoneListTail = Entry;
        }
    }

    return ERROR_SUCCESS;
}

static VOID
CreateTimeZoneList(VOID)
{
    EnumerateTimeZoneList(RetrieveTimeZone, NULL);
}

static VOID
DestroyTimeZoneList(VOID)
{
    PTIMEZONE_ENTRY Entry;

    while (TimeZoneListHead != NULL)
    {
        Entry = TimeZoneListHead;

        TimeZoneListHead = Entry->Next;
        if (TimeZoneListHead != NULL)
        {
            TimeZoneListHead->Prev = NULL;
        }

        HeapFree(GetProcessHeap(), 0, Entry);
    }

    TimeZoneListTail = NULL;
}


static VOID
ShowTimeZoneList(HWND hwnd)
{
    TIME_ZONE_INFORMATION TimeZoneInfo;
    PTIMEZONE_ENTRY Entry;
    DWORD dwCount;
    DWORD dwIndex = 0;
    DWORD dwKeyIndex = 0;
    BOOL bFound = FALSE;
    BOOL bKeyFound = FALSE;
    BOOL bHaveKeyName;
    WCHAR szKeyName[128];

    if (GetTimeZoneInformation(&TimeZoneInfo) == TIME_ZONE_ID_INVALID)
    {
        /* Failed to retrieve current time-zone info, reset it */
        ZeroMemory(&TimeZoneInfo, sizeof(TimeZoneInfo));
    }

    /* The zone's key name wins over the names; SetTimeZoneInformation clears it */
    bHaveKeyName = GetTimeZoneKeyName(szKeyName, ARRAYSIZE(szKeyName));

    for (Entry = TimeZoneListHead; Entry != NULL; Entry = Entry->Next)
    {
        dwCount = SendMessageW(hwnd,
                               CB_ADDSTRING,
                               0,
                               (LPARAM)Entry->Description);
        if (dwCount == CB_ERR || dwCount == CB_ERRSPACE)
            continue;

        if (bHaveKeyName && !bKeyFound &&
            (_wcsicmp(Entry->KeyName, szKeyName) == 0))
        {
            dwKeyIndex = dwCount;
            bKeyFound = TRUE;
        }

        /* If the time-zone was found in the list, skip the tests */
        if (bFound)
            continue;

        if (*TimeZoneInfo.StandardName && *Entry->StandardName)
        {
            /* Compare by name; a 32-character name was cut to fit TIME_ZONE_INFORMATION */
            if (wcsncmp(Entry->StandardName, TimeZoneInfo.StandardName,
                        ARRAYSIZE(TimeZoneInfo.StandardName) - 1) == 0)
            {
                dwIndex = dwCount;
                bFound = TRUE;
            }
        }
        else
        {
            /* Compare by date and bias */
            if ((Entry->TimezoneInfo.Bias == TimeZoneInfo.Bias) &&
                (Entry->TimezoneInfo.StandardBias == TimeZoneInfo.StandardBias) &&
                (Entry->TimezoneInfo.DaylightBias == TimeZoneInfo.DaylightBias) &&
                (memcmp(&Entry->TimezoneInfo.StandardDate, &TimeZoneInfo.StandardDate, sizeof(SYSTEMTIME)) == 0) &&
                (memcmp(&Entry->TimezoneInfo.DaylightDate, &TimeZoneInfo.DaylightDate, sizeof(SYSTEMTIME)) == 0))
            {
                dwIndex = dwCount;
                bFound = TRUE;
            }
        }
    }

    SendMessageW(hwnd,
                 CB_SETCURSEL,
                 (WPARAM)(bKeyFound ? dwKeyIndex : dwIndex),
                 0);
}


typedef struct _TIMEZONE_DYNAMIC_INFORMATION
{
    TIME_ZONE_INFORMATION Zone;
    WCHAR TimeZoneKeyName[128];
    BOOLEAN DynamicDaylightTimeDisabled;
} TIMEZONE_DYNAMIC_INFORMATION;

typedef BOOL (WINAPI *PFN_SETDYNAMICTIMEZONEINFORMATION)(const TIMEZONE_DYNAMIC_INFORMATION *);

static VOID
SetLocalTimeZone(HWND hwnd, BOOL bAutoDaylight)
{
    TIME_ZONE_INFORMATION TimeZoneInformation;
    TIMEZONE_DYNAMIC_INFORMATION DynamicInformation;
    PFN_SETDYNAMICTIMEZONEINFORMATION pSetDynamicTimeZoneInformation;
    PTIMEZONE_ENTRY Entry;

    Entry = GetSelectedTimeZoneEntry(hwnd);
    if (Entry == NULL)
        return;

    /* Only a zone with DST can have its automatic adjustment turned off */
    if (!HasDaylightSaving(Entry))
        bAutoDaylight = TRUE;

    /* Both fields hold 31 characters and the terminator */
    StringCchCopyW(TimeZoneInformation.StandardName,
                   ARRAYSIZE(TimeZoneInformation.StandardName),
                   Entry->StandardName);
    StringCchCopyW(TimeZoneInformation.DaylightName,
                   ARRAYSIZE(TimeZoneInformation.DaylightName),
                   Entry->DaylightName);

    TimeZoneInformation.Bias = Entry->TimezoneInfo.Bias;
    TimeZoneInformation.StandardBias = Entry->TimezoneInfo.StandardBias;
    TimeZoneInformation.DaylightBias = Entry->TimezoneInfo.DaylightBias;

    memcpy(&TimeZoneInformation.StandardDate,
           &Entry->TimezoneInfo.StandardDate,
           sizeof(SYSTEMTIME));
    memcpy(&TimeZoneInformation.DaylightDate,
           &Entry->TimezoneInfo.DaylightDate,
           sizeof(SYSTEMTIME));

    /* Without automatic adjustment the zone stays on standard time all year */
    if (!bAutoDaylight)
    {
        wcscpy(TimeZoneInformation.DaylightName,
               TimeZoneInformation.StandardName);
        TimeZoneInformation.Bias += TimeZoneInformation.StandardBias;
        TimeZoneInformation.StandardBias = 0;
        TimeZoneInformation.DaylightBias = 0;
        ZeroMemory(&TimeZoneInformation.StandardDate, sizeof(SYSTEMTIME));
        ZeroMemory(&TimeZoneInformation.DaylightDate, sizeof(SYSTEMTIME));
    }

    /*
     * The kernel stores the zone, its key name and the daylight flag in one step
     * (as Windows 10 does): this page runs as a standard user, who may not write
     * the key. Where kernel32 has no SetDynamicTimeZoneInformation (NT 5 builds),
     * the three registry writes remain.
     */
    pSetDynamicTimeZoneInformation = (PFN_SETDYNAMICTIMEZONEINFORMATION)
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetDynamicTimeZoneInformation");
    if (pSetDynamicTimeZoneInformation)
    {
        ZeroMemory(&DynamicInformation, sizeof(DynamicInformation));
        memcpy(&DynamicInformation, &TimeZoneInformation, sizeof(TimeZoneInformation));
        StringCchCopyW(DynamicInformation.TimeZoneKeyName,
                       ARRAYSIZE(DynamicInformation.TimeZoneKeyName),
                       Entry->KeyName);
        DynamicInformation.DynamicDaylightTimeDisabled = !bAutoDaylight;
        pSetDynamicTimeZoneInformation(&DynamicInformation);
        return;
    }

    /* Set time zone information */
    if (!SetTimeZoneInformation(&TimeZoneInformation))
        return;

    /* The key exists once SetTimeZoneInformation has written it */
    SetAutoDaylight(bAutoDaylight);
    SetTimeZoneKeyName(Entry->KeyName);
}


/* Property page dialog callback */
INT_PTR CALLBACK
TimeZonePageProc(HWND hwndDlg,
                 UINT uMsg,
                 WPARAM wParam,
                 LPARAM lParam)
{
    BITMAP bitmap;

    switch (uMsg)
    {
        case WM_INITDIALOG:
        {
            CreateTimeZoneList();
            ShowTimeZoneList(GetDlgItem(hwndDlg, IDC_TIMEZONELIST));

            /* Update DST checkbox based on the selected timezone's DST support */
            UpdateDstCheckbox(hwndDlg);

            hBitmap = LoadImageW(hApplet, MAKEINTRESOURCEW(IDC_WORLD), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
            if (hBitmap != NULL)
            {
                GetObjectW(hBitmap, sizeof(bitmap), &bitmap);

                cxSource = bitmap.bmWidth;
                cySource = bitmap.bmHeight;
            }
            break;
        }

        case WM_DRAWITEM:
        {
            LPDRAWITEMSTRUCT lpDrawItem;
            lpDrawItem = (LPDRAWITEMSTRUCT)lParam;
            if(lpDrawItem->CtlID == IDC_WORLD_BACKGROUND)
            {
                HDC hdcMem;
                hdcMem = CreateCompatibleDC(lpDrawItem->hDC);
                if (hdcMem != NULL)
                {
                    SelectObject(hdcMem, hBitmap);
                    StretchBlt(lpDrawItem->hDC, lpDrawItem->rcItem.left, lpDrawItem->rcItem.top,
                               lpDrawItem->rcItem.right - lpDrawItem->rcItem.left,
                               lpDrawItem->rcItem.bottom - lpDrawItem->rcItem.top,
                               hdcMem, 0, 0, cxSource, cySource, SRCCOPY);
                    DeleteDC(hdcMem);
                }
            }
        }
        break;

        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_TIMEZONELIST && HIWORD(wParam) == CBN_SELCHANGE)
            {
                /* Update DST checkbox based on the selected timezone's DST support */
                UpdateDstCheckbox(hwndDlg);
                /* Enable the 'Apply' button */
                PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
            }
            else if (LOWORD(wParam) == IDC_AUTODAYLIGHT && HIWORD(wParam) == BN_CLICKED)
            {
                /* Enable the 'Apply' button */
                PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
            }
            break;

        case WM_DESTROY:
            DestroyTimeZoneList();
            DeleteObject(hBitmap);
            break;

        case WM_NOTIFY:
        {
            LPNMHDR lpnm = (LPNMHDR)lParam;

            switch (lpnm->code)
            {
                case PSN_APPLY:
                {
                    SetLocalTimeZone(GetDlgItem(hwndDlg, IDC_TIMEZONELIST),
                                     SendDlgItemMessage(hwndDlg, IDC_AUTODAYLIGHT,
                                                        BM_GETCHECK, 0, 0) != BST_UNCHECKED);
                    SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, PSNRET_NOERROR);
                    return TRUE;
                }

                default:
                    break;
            }
        }
        break;
    }

  return FALSE;
}
