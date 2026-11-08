/*
 * Locale-dependent format handling
 *
 * Copyright 1995 Martin von Loewis
 * Copyright 1998 David Lee Lambert
 * Copyright 2000 Julio César Gázquez
 * Copyright 2003 Jon Griffiths
 * Copyright 2005 Dmitry Timoshkov
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

#ifdef __REACTOS__

#include <k32.h>
#include "japanese.h"   /* Japanese eras */

#include "lcformat_private.h"
#include "calendar_data.h"

#define NDEBUG
#include <debug.h>
DEBUG_CHANNEL(nls);

#undef _WIN32_WINNT
#undef WINVER
#define _WIN32_WINNT DLL_EXPORT_VERSION
#define WINVER DLL_EXPORT_VERSION

LCID WINAPI LocaleNameToLCID(_In_ LPCWSTR, _In_ DWORD);
#define LOCALE_SSHORTESTDAYNAME1 96
#define LOCALE_SSHORTESTDAYNAME2 97
#define LOCALE_SSHORTESTDAYNAME3 98
#define LOCALE_SSHORTESTDAYNAME4 99
#define LOCALE_SSHORTESTDAYNAME5 100
#define LOCALE_SSHORTESTDAYNAME6 101
#define LOCALE_SSHORTESTDAYNAME7 102

/* The headers hide these below WINVER 0x600 and this file redefines WINVER after including them */
#ifndef CAL_SSHORTESTDAYNAME1
#define CAL_SSHORTESTDAYNAME1 49
#define CAL_SSHORTESTDAYNAME2 50
#define CAL_SSHORTESTDAYNAME3 51
#define CAL_SSHORTESTDAYNAME4 52
#define CAL_SSHORTESTDAYNAME5 53
#define CAL_SSHORTESTDAYNAME6 54
#define CAL_SSHORTESTDAYNAME7 55
#endif
#ifndef CAL_SRELATIVELONGDATE
#define CAL_SRELATIVELONGDATE 58
#endif
#ifndef CAL_SMONTHDAY
#define CAL_SMONTHDAY 56
#endif
#ifndef LOCALE_SMONTHDAY
#define LOCALE_SMONTHDAY 0x78
#endif

#define CRITICAL_SECTION RTL_CRITICAL_SECTION
#define CRITICAL_SECTION_DEBUG RTL_CRITICAL_SECTION_DEBUG
/* Windows 10 default for TwoDigitYearMax of the Gregorian calendar (2029 up to Windows 8.1) */
#define CALINFO_MAX_YEAR 2049

#define IS_LCID_JAPANESE(lcid) PRIMARYLANGID(LANGIDFROMLCID(lcid)) == LANG_JAPANESE

/* TwoDigitYearMax of a calendar (CAL_ITWODIGITYEARMAX): Windows answers for any calendar, whatever the locale */
static DWORD NLS_GetTwoDigitYearMax(CALID Calendar)
{
    switch (Calendar)
    {
        case CAL_KOREA:         return 4382;
        case CAL_HIJRI:         return 1451;
        case CAL_THAI:          return 2592;
        case CAL_HEBREW:        return 5810;
        case 22:                return 1429; /* CAL_PERSIAN */
        case 23:                return 1451; /* CAL_UMALQURA */
        case CAL_JAPAN:
        case CAL_TAIWAN:
            return 99;
        case CAL_GREGORIAN:
        case CAL_GREGORIAN_US:
        case CAL_GREGORIAN_ME_FRENCH:
        case CAL_GREGORIAN_ARABIC:
        case 11: /* CAL_GREGORIAN_XLIT_ENGLISH */
        case 12: /* CAL_GREGORIAN_XLIT_FRENCH */
        case 13:
        case 0:
            return CALINFO_MAX_YEAR;
        default:
            return 99;
    }
}

/* Calendar data of the locales (calendar_data.c) */

static const NLS_CAL_ROW *NLS_FindCalRow(const NLS_CAL_ROW *Rows, ULONG Count, DWORD Key)
{
    LONG Low = 0, High = (LONG)Count - 1;

    while (Low <= High)
    {
        LONG Mid = (Low + High) / 2;

        if (Rows[Mid].Key == Key)
            return &Rows[Mid];
        if (Rows[Mid].Key < Key)
            Low = Mid + 1;
        else
            High = Mid - 1;
    }
    return NULL;
}

/* Pseudo calendars of the enumeration rows: the date formats of all calendars, the time formats */
#define NLS_CAL_ALL_FORMATS 0xff
#define NLS_CAL_TIME_FORMATS 0xfe

#define NLS_CAL_KEY(Lcid, Cal, Type) \
    (((DWORD)LANGIDFROMLCID(Lcid) << 16) | (((Cal) & 0xff) << 8) | ((Type) & 0xff))

/* The string of a calendar type of a calendar in the data, or NULL */
static const WCHAR *NLS_GetCalendarString(LCID Lcid, CALID Cal, CALTYPE Type)
{
    const NLS_CAL_ROW *Rows, *Row;
    ULONG Count;

    if (Cal > 0xff || Type > 0xff)
        return NULL;
    Rows = NlsCalRowTable(&Count);
    Row = NLS_FindCalRow(Rows, Count, NLS_CAL_KEY(Lcid, Cal, Type));
    return Row ? NlsCalPoolBase() + Row->Offset : NULL;
}

/* The NUL-separated list that EnumCalendarInfo hands out for a calendar type of a calendar, or NULL */
static const WCHAR *NLS_GetCalendarEnumList(LCID Lcid, CALID Cal, CALTYPE Type)
{
    const NLS_CAL_ROW *Rows, *Row;
    ULONG Count;

    if (Cal > 0xff || Type > 0xff)
        return NULL;
    Rows = NlsCalEnumRowTable(&Count);
    Row = NLS_FindCalRow(Rows, Count, NLS_CAL_KEY(Lcid, Cal, Type));
    return Row ? NlsCalPoolBase() + Row->Offset : NULL;
}

static const NLS_CAL_LIST *NLS_GetCalendarList(LCID Lcid)
{
    const NLS_CAL_LIST *List;
    ULONG Count, Low = 0, High;
    WORD LangId = LANGIDFROMLCID(Lcid);

    List = NlsCalListTable(&Count);
    High = Count;
    while (Low < High)
    {
        ULONG Mid = (Low + High) / 2;

        if (List[Mid].LangId == LangId)
            return &List[Mid];
        if (List[Mid].LangId < LangId)
            Low = Mid + 1;
        else
            High = Mid;
    }
    return NULL;
}

/* Hands a string out the way GetCalendarInfo does: the size query, the buffer check, the length with the NUL */
static int NLS_ReturnCalendarString(const WCHAR *Value, LPWSTR lpCalData, int cchData)
{
    int Length = (int)wcslen(Value) + 1;

    if (!lpCalData || !cchData)
        return Length;
    if (cchData < Length)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    RtlCopyMemory(lpCalData, Value, Length * sizeof(WCHAR));
    return Length;
}

static int NLS_ReturnCalendarNumber(DWORD Number, CALTYPE CalType, LPWSTR lpCalData, int cchData, LPDWORD lpValue)
{
    if (CalType & CAL_RETURN_NUMBER)
    {
        *lpValue = Number;
        return sizeof(DWORD) / sizeof(WCHAR);
    }
    else
    {
        WCHAR Buffer[16];
        static const WCHAR fmtW[] = {'%','u',0};

        snprintfW(Buffer, ARRAY_SIZE(Buffer), fmtW, Number);
        return NLS_ReturnCalendarString(Buffer, lpCalData, cchData);
    }
}


#ifndef CAL_SABBREVERASTRING
    #define CAL_SABBREVERASTRING 0x00000039
#endif

#else /* __REACTOS__ */

#include "config.h"
#include "wine/port.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "windef.h"
#include "winbase.h"
#include "wine/unicode.h"
#include "wine/debug.h"
#include "winternl.h"

#include "kernel_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(nls);

#endif /* __REACTOS__ */

#define DATE_DATEVARSONLY 0x0100  /* only date stuff: yMdg */
#define TIME_TIMEVARSONLY 0x0200  /* only time stuff: hHmst */

/* Since calculating the formatting data for each locale is time-consuming,
 * we get the format data for each locale only once and cache it in memory.
 * We cache both the system default and user overridden data, after converting
 * them into the formats that the functions here expect. Since these functions
 * will typically be called with only a small number of the total locales
 * installed, the memory overhead is minimal while the speedup is significant.
 *
 * Our cache takes the form of a singly linked list, whose node is below:
 */
#define NLS_NUM_CACHED_STRINGS 57

typedef struct _NLS_FORMAT_NODE
{
  LCID  lcid;         /* Locale Id */
  DWORD dwFlags;      /* 0 or LOCALE_NOUSEROVERRIDE */
  DWORD dwCodePage;   /* Default code page (if LOCALE_USE_ANSI_CP not given) */
  NUMBERFMTW   fmt;   /* Default format for numbers */
  CURRENCYFMTW cyfmt; /* Default format for currencies */
  LPWSTR lppszStrings[NLS_NUM_CACHED_STRINGS]; /* Default formats,day/month names */
  WCHAR szShortAM[2]; /* Short 'AM' marker */
  WCHAR szShortPM[2]; /* Short 'PM' marker */
  struct _NLS_FORMAT_NODE *next;
} NLS_FORMAT_NODE;

/* Macros to get particular data strings from a format node */
#define GetNegative(fmt)  fmt->lppszStrings[0]
#define GetLongDate(fmt)  fmt->lppszStrings[1]
#define GetShortDate(fmt) fmt->lppszStrings[2]
#define GetTime(fmt)      fmt->lppszStrings[3]
#define GetAM(fmt)        fmt->lppszStrings[54]
#define GetPM(fmt)        fmt->lppszStrings[55]
#define GetYearMonth(fmt) fmt->lppszStrings[56]

#define GetLongDay(fmt,day)       fmt->lppszStrings[4 + day]
#define GetShortDay(fmt,day)      fmt->lppszStrings[11 + day]
#define GetLongMonth(fmt,mth)     fmt->lppszStrings[18 + mth]
#define GetGenitiveMonth(fmt,mth) fmt->lppszStrings[30 + mth]
#define GetShortMonth(fmt,mth)    fmt->lppszStrings[42 + mth]

/* Write access to the cache is protected by this critical section */
static CRITICAL_SECTION NLS_FormatsCS;
static CRITICAL_SECTION_DEBUG NLS_FormatsCS_debug =
{
    0, 0, &NLS_FormatsCS,
    { &NLS_FormatsCS_debug.ProcessLocksList,
      &NLS_FormatsCS_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": NLS_Formats") }
};
static CRITICAL_SECTION NLS_FormatsCS = { &NLS_FormatsCS_debug, -1, 0, 0, 0, 0 };

/**************************************************************************
 * NLS_GetLocaleNumber <internal>
 *
 * Get a numeric locale format value.
 */
static DWORD NLS_GetLocaleNumber(LCID lcid, DWORD dwFlags)
{
  WCHAR szBuff[80];
  DWORD dwVal = 0;

  szBuff[0] = '\0';
  GetLocaleInfoW(lcid, dwFlags, szBuff, ARRAY_SIZE(szBuff));

  if (szBuff[0] && szBuff[1] == ';' && szBuff[2] != '0')
    dwVal = (szBuff[0] - '0') * 10 + (szBuff[2] - '0');
  else
  {
    const WCHAR* iter = szBuff;
    dwVal = 0;
    while(*iter >= '0' && *iter <= '9')
      dwVal = dwVal * 10 + (*iter++ - '0');
  }
  return dwVal;
}

/**************************************************************************
 * NLS_GetLocaleString <internal>
 *
 * Get a string locale format value.
 */
static WCHAR* NLS_GetLocaleString(LCID lcid, DWORD dwFlags)
{
  WCHAR szBuff[80], *str;
  DWORD dwLen;

  szBuff[0] = '\0';
  GetLocaleInfoW(lcid, dwFlags, szBuff, ARRAY_SIZE(szBuff));
  dwLen = strlenW(szBuff) + 1;
  str = HeapAlloc(GetProcessHeap(), 0, dwLen * sizeof(WCHAR));
  if (str)
    memcpy(str, szBuff, dwLen * sizeof(WCHAR));
  return str;
}

#define GET_LOCALE_NUMBER(num, type) num = NLS_GetLocaleNumber(lcid, type|dwFlags); \
  TRACE( #type ": %d (%08x)\n", (DWORD)num, (DWORD)num)

#define GET_LOCALE_STRING(str, type) str = NLS_GetLocaleString(lcid, type|dwFlags); \
  TRACE( #type ": %s\n", debugstr_w(str))

/**************************************************************************
 * NLS_GetFormats <internal>
 *
 * Calculate (and cache) the number formats for a locale.
 */
static const NLS_FORMAT_NODE *NLS_GetFormats(LCID lcid, DWORD dwFlags)
{
  /* GetLocaleInfo() identifiers for cached formatting strings */
  static const LCTYPE NLS_LocaleIndices[] = {
    LOCALE_SNEGATIVESIGN,
    LOCALE_SLONGDATE,   LOCALE_SSHORTDATE,
    LOCALE_STIMEFORMAT,
    LOCALE_SDAYNAME1, LOCALE_SDAYNAME2, LOCALE_SDAYNAME3,
    LOCALE_SDAYNAME4, LOCALE_SDAYNAME5, LOCALE_SDAYNAME6, LOCALE_SDAYNAME7,
    LOCALE_SABBREVDAYNAME1, LOCALE_SABBREVDAYNAME2, LOCALE_SABBREVDAYNAME3,
    LOCALE_SABBREVDAYNAME4, LOCALE_SABBREVDAYNAME5, LOCALE_SABBREVDAYNAME6,
    LOCALE_SABBREVDAYNAME7,
    LOCALE_SMONTHNAME1, LOCALE_SMONTHNAME2, LOCALE_SMONTHNAME3,
    LOCALE_SMONTHNAME4, LOCALE_SMONTHNAME5, LOCALE_SMONTHNAME6,
    LOCALE_SMONTHNAME7, LOCALE_SMONTHNAME8, LOCALE_SMONTHNAME9,
    LOCALE_SMONTHNAME10, LOCALE_SMONTHNAME11, LOCALE_SMONTHNAME12,
    LOCALE_SMONTHNAME1  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME2  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME3  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME4  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME5  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME6  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME7  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME8  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME9  | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME10 | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME11 | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SMONTHNAME12 | LOCALE_RETURN_GENITIVE_NAMES,
    LOCALE_SABBREVMONTHNAME1, LOCALE_SABBREVMONTHNAME2, LOCALE_SABBREVMONTHNAME3,
    LOCALE_SABBREVMONTHNAME4, LOCALE_SABBREVMONTHNAME5, LOCALE_SABBREVMONTHNAME6,
    LOCALE_SABBREVMONTHNAME7, LOCALE_SABBREVMONTHNAME8, LOCALE_SABBREVMONTHNAME9,
    LOCALE_SABBREVMONTHNAME10, LOCALE_SABBREVMONTHNAME11, LOCALE_SABBREVMONTHNAME12,
    LOCALE_S1159, LOCALE_S2359,
    LOCALE_SYEARMONTH
  };
  static NLS_FORMAT_NODE *NLS_CachedFormats = NULL;
  NLS_FORMAT_NODE *node = NLS_CachedFormats;

  dwFlags &= LOCALE_NOUSEROVERRIDE;

  TRACE("(0x%04x,0x%08x)\n", lcid, dwFlags);

  /* See if we have already cached the locales number format */
  while (node && (node->lcid != lcid || node->dwFlags != dwFlags) && node->next)
    node = node->next;

  if (!node || node->lcid != lcid || node->dwFlags != dwFlags)
  {
    NLS_FORMAT_NODE *new_node;
    DWORD i;

    TRACE("Creating new cache entry\n");

    if (!(new_node = HeapAlloc(GetProcessHeap(), 0, sizeof(NLS_FORMAT_NODE))))
      return NULL;

    GET_LOCALE_NUMBER(new_node->dwCodePage, LOCALE_IDEFAULTANSICODEPAGE);

    /* Number Format */
    new_node->lcid = lcid;
    new_node->dwFlags = dwFlags;
    new_node->next = NULL;

    GET_LOCALE_NUMBER(new_node->fmt.NumDigits, LOCALE_IDIGITS);
    GET_LOCALE_NUMBER(new_node->fmt.LeadingZero, LOCALE_ILZERO);
    GET_LOCALE_NUMBER(new_node->fmt.NegativeOrder, LOCALE_INEGNUMBER);

    GET_LOCALE_NUMBER(new_node->fmt.Grouping, LOCALE_SGROUPING);
    if (new_node->fmt.Grouping > 9 && new_node->fmt.Grouping != 32)
    {
      WARN("LOCALE_SGROUPING (%d) unhandled, please report!\n",
           new_node->fmt.Grouping);
      new_node->fmt.Grouping = 0;
    }

    GET_LOCALE_STRING(new_node->fmt.lpDecimalSep, LOCALE_SDECIMAL);
    GET_LOCALE_STRING(new_node->fmt.lpThousandSep, LOCALE_STHOUSAND);

    /* Currency Format */
    new_node->cyfmt.NumDigits = new_node->fmt.NumDigits;
    new_node->cyfmt.LeadingZero = new_node->fmt.LeadingZero;

    GET_LOCALE_NUMBER(new_node->cyfmt.Grouping, LOCALE_SGROUPING);

    if (new_node->cyfmt.Grouping > 9)
    {
      WARN("LOCALE_SMONGROUPING (%d) unhandled, please report!\n",
           new_node->cyfmt.Grouping);
      new_node->cyfmt.Grouping = 0;
    }

    GET_LOCALE_NUMBER(new_node->cyfmt.NegativeOrder, LOCALE_INEGCURR);
    if (new_node->cyfmt.NegativeOrder > 15)
    {
      WARN("LOCALE_INEGCURR (%d) unhandled, please report!\n",
           new_node->cyfmt.NegativeOrder);
      new_node->cyfmt.NegativeOrder = 0;
    }
    GET_LOCALE_NUMBER(new_node->cyfmt.PositiveOrder, LOCALE_ICURRENCY);
    if (new_node->cyfmt.PositiveOrder > 3)
    {
      WARN("LOCALE_IPOSCURR (%d) unhandled,please report!\n",
           new_node->cyfmt.PositiveOrder);
      new_node->cyfmt.PositiveOrder = 0;
    }
    GET_LOCALE_STRING(new_node->cyfmt.lpDecimalSep, LOCALE_SMONDECIMALSEP);
    GET_LOCALE_STRING(new_node->cyfmt.lpThousandSep, LOCALE_SMONTHOUSANDSEP);
    GET_LOCALE_STRING(new_node->cyfmt.lpCurrencySymbol, LOCALE_SCURRENCY);

    /* Date/Time Format info, negative character, etc */
    for (i = 0; i < ARRAY_SIZE(NLS_LocaleIndices); i++)
    {
      GET_LOCALE_STRING(new_node->lppszStrings[i], NLS_LocaleIndices[i]);
    }
    /* Save some memory if month genitive name is the same or not present */
    for (i = 0; i < 12; i++)
    {
      if (strcmpW(GetLongMonth(new_node, i), GetGenitiveMonth(new_node, i)) == 0)
      {
        HeapFree(GetProcessHeap(), 0, GetGenitiveMonth(new_node, i));
        GetGenitiveMonth(new_node, i) = NULL;
      }
    }

    new_node->szShortAM[0] = GetAM(new_node)[0]; new_node->szShortAM[1] = '\0';
    new_node->szShortPM[0] = GetPM(new_node)[0]; new_node->szShortPM[1] = '\0';

    /* Now add the computed format to the cache */
    RtlEnterCriticalSection(&NLS_FormatsCS);

    /* Search again: We may have raced to add the node */
    node = NLS_CachedFormats;
    while (node && (node->lcid != lcid || node->dwFlags != dwFlags) && node->next)
      node = node->next;

    if (!node)
    {
      node = NLS_CachedFormats = new_node; /* Empty list */
      new_node = NULL;
    }
    else if (node->lcid != lcid || node->dwFlags != dwFlags)
    {
      node->next = new_node; /* Not in the list, add to end */
      node = new_node;
      new_node = NULL;
    }

    RtlLeaveCriticalSection(&NLS_FormatsCS);

    if (new_node)
    {
      /* We raced and lost: The node was already added by another thread.
       * node points to the currently cached node, so free new_node.
       */
      for (i = 0; i < ARRAY_SIZE(NLS_LocaleIndices); i++)
        HeapFree(GetProcessHeap(), 0, new_node->lppszStrings[i]);
      HeapFree(GetProcessHeap(), 0, new_node->fmt.lpDecimalSep);
      HeapFree(GetProcessHeap(), 0, new_node->fmt.lpThousandSep);
      HeapFree(GetProcessHeap(), 0, new_node->cyfmt.lpDecimalSep);
      HeapFree(GetProcessHeap(), 0, new_node->cyfmt.lpThousandSep);
      HeapFree(GetProcessHeap(), 0, new_node->cyfmt.lpCurrencySymbol);
      HeapFree(GetProcessHeap(), 0, new_node);
    }
  }
  return node;
}

/*
 * NLS_GetAnsiCodePage <internal>
 * Helper used by ANSI entrypoints to determine the locale codepage.
 */
DWORD NLS_GetAnsiCodePage(LCID lcid, DWORD dwFlags)
{
    const NLS_FORMAT_NODE *node = NLS_GetFormats(lcid, dwFlags);
    return node ? node->dwCodePage : 0;
}

/**************************************************************************
 * NLS_IsUnicodeOnlyLcid <internal>
 *
 * Determine if a locale is Unicode only, and thus invalid in ASCII calls.
 */
BOOL NLS_IsUnicodeOnlyLcid(LCID lcid)
{
  lcid = ConvertDefaultLocale(lcid);

  switch (PRIMARYLANGID(lcid))
  {
  case LANG_ARMENIAN:
  case LANG_DIVEHI:
  case LANG_GEORGIAN:
  case LANG_GUJARATI:
  case LANG_HINDI:
  case LANG_KANNADA:
  case LANG_KONKANI:
  case LANG_MARATHI:
  case LANG_PUNJABI:
  case LANG_SANSKRIT:
    TRACE("lcid 0x%08x: langid 0x%4x is Unicode Only\n", lcid, PRIMARYLANGID(lcid));
    return TRUE;
  default:
    return FALSE;
  }
}

/*
 * Formatting of dates, times, numbers and currencies.
 */

#define IsLiteralMarker(p) (p == '\'')
#define IsDateFmtChar(p)   (p == 'd'||p == 'M'||p == 'y'||p == 'g')
#define IsTimeFmtChar(p)   (p == 'H'||p == 'h'||p == 'm'||p == 's'||p == 't')

/* Only the following flags can be given if a date/time format is specified */
#ifdef __REACTOS__
#define DATE_FORMAT_FLAGS (DATE_DATEVARSONLY | DATE_USE_ALT_CALENDAR)
#else
#define DATE_FORMAT_FLAGS (DATE_DATEVARSONLY)
#endif
#define TIME_FORMAT_FLAGS (TIME_TIMEVARSONLY|TIME_FORCE24HOURFORMAT| \
                           TIME_NOMINUTESORSECONDS|TIME_NOSECONDS| \
                           TIME_NOTIMEMARKER)

/******************************************************************************
 * NLS_GetDateTimeFormatW <internal>
 *
 * Performs the formatting for GetDateFormatW/GetTimeFormatW.
 *
 * FIXME
 * DATE_USE_ALT_CALENDAR           - Requires GetCalendarInfo to work first.
 * DATE_LTRREADING/DATE_RTLREADING - Not yet implemented.
 */
static INT NLS_GetDateTimeFormatW(LCID lcid, DWORD dwFlags,
                                  const SYSTEMTIME* lpTime, LPCWSTR lpFormat,
                                  LPWSTR lpStr, INT cchOut)
{
  const NLS_FORMAT_NODE *node;
  SYSTEMTIME st;
  INT cchWritten = 0;
  INT lastFormatPos = 0;
  BOOL bSkipping = FALSE; /* Skipping text around marker? */
  BOOL bDropSpaces = FALSE; /* Dropping the spaces after a leading marker that is not shown? */
  BOOL d_dd_formatted = FALSE; /* previous formatted part was for d or dd */

  /* Verify our arguments */
  if ((cchOut && !lpStr) || !(node = NLS_GetFormats(lcid, dwFlags)))
    goto invalid_parameter;

  if (dwFlags & ~(DATE_DATEVARSONLY|TIME_TIMEVARSONLY))
  {
    if (lpFormat &&
        ((dwFlags & DATE_DATEVARSONLY && dwFlags & ~DATE_FORMAT_FLAGS) ||
         (dwFlags & TIME_TIMEVARSONLY && dwFlags & ~TIME_FORMAT_FLAGS)))
    {
      goto invalid_flags;
    }

    if (dwFlags & DATE_DATEVARSONLY)
    {
      if ((dwFlags & (DATE_LTRREADING|DATE_RTLREADING)) == (DATE_LTRREADING|DATE_RTLREADING))
        goto invalid_flags;
      else if (dwFlags & (DATE_LTRREADING|DATE_RTLREADING))
        FIXME("Unsupported flags: DATE_LTRREADING/DATE_RTLREADING\n");

      switch (dwFlags & (DATE_SHORTDATE|DATE_LONGDATE|DATE_YEARMONTH))
      {
      case 0:
        break;
      case DATE_SHORTDATE:
      case DATE_LONGDATE:
      case DATE_YEARMONTH:
        if (lpFormat)
          goto invalid_flags;
        break;
      default:
        goto invalid_flags;
      }
    }
  }

  if (!lpFormat)
  {
    /* Use the appropriate default format */
    if (dwFlags & DATE_DATEVARSONLY)
    {
      if (dwFlags & DATE_YEARMONTH)
        lpFormat = GetYearMonth(node);
      else if (dwFlags & DATE_LONGDATE)
        lpFormat = GetLongDate(node);
      else
        lpFormat = GetShortDate(node);
    }
    else
      lpFormat = GetTime(node);
  }

  if (!lpTime)
  {
    GetLocalTime(&st); /* Default to current time */
    lpTime = &st;
  }
  else
  {
    if (dwFlags & DATE_DATEVARSONLY)
    {
      FILETIME ftTmp;

      /* Verify the date and correct the D.O.W. if needed */
      memset(&st, 0, sizeof(st));
      st.wYear = lpTime->wYear;
      st.wMonth = lpTime->wMonth;
      st.wDay = lpTime->wDay;

      if (st.wDay > 31 || st.wMonth > 12 || !SystemTimeToFileTime(&st, &ftTmp))
        goto invalid_parameter;

      FileTimeToSystemTime(&ftTmp, &st);
      lpTime = &st;
    }

    if (dwFlags & TIME_TIMEVARSONLY)
    {
      /* Verify the time */
      if (lpTime->wHour > 24 || lpTime->wMinute > 59 || lpTime->wSecond > 59)
        goto invalid_parameter;
    }
  }

  /* Format the output */
  while (*lpFormat)
  {
    if (IsLiteralMarker(*lpFormat))
    {
      /* Start of a literal string */
      lpFormat++;

      /* Loop until the end of the literal marker or end of the string */
      while (*lpFormat)
      {
        if (IsLiteralMarker(*lpFormat))
        {
          lpFormat++;
          if (!IsLiteralMarker(*lpFormat))
            break; /* Terminating literal marker */
        }

        if (!cchOut)
          cchWritten++;   /* Count size only */
        else if (cchWritten >= cchOut)
          goto overrun;
        else if (!bSkipping)
        {
          lpStr[cchWritten] = *lpFormat;
          cchWritten++;
        }
        lpFormat++;
      }
    }
    else if ((dwFlags & DATE_DATEVARSONLY && IsDateFmtChar(*lpFormat)) ||
             (dwFlags & TIME_TIMEVARSONLY && IsTimeFmtChar(*lpFormat)))
    {
      WCHAR buff[32], fmtChar;
      LPCWSTR szAdd = NULL;
      DWORD dwVal = 0;
      int   count = 0, dwLen;

      bSkipping = FALSE;
      bDropSpaces = FALSE;

      fmtChar = *lpFormat;
      while (*lpFormat == fmtChar)
      {
        count++;
        lpFormat++;
      }
      buff[0] = '\0';

      if (fmtChar != 'M') d_dd_formatted = FALSE;
      switch(fmtChar)
      {
      case 'd':
        if (count >= 4)
          szAdd = GetLongDay(node, (lpTime->wDayOfWeek + 6) % 7);
        else if (count == 3)
          szAdd = GetShortDay(node, (lpTime->wDayOfWeek + 6) % 7);
        else
        {
          dwVal = lpTime->wDay;
          szAdd = buff;
          d_dd_formatted = TRUE;
        }
        break;

      case 'M':
        if (count >= 4)
        {
          LPCWSTR genitive = GetGenitiveMonth(node, lpTime->wMonth - 1);
          if (genitive)
          {
            if (d_dd_formatted)
            {
              szAdd = genitive;
              break;
            }
            else
            {
              LPCWSTR format = lpFormat;
              /* Look forward now, if next format pattern is for day genitive
                 name should be used */
              while (*format)
              {
                /* Skip parts within markers */
                if (IsLiteralMarker(*format))
                {
                  ++format;
                  while (*format)
                  {
                    if (IsLiteralMarker(*format))
                    {
                      ++format;
                      if (!IsLiteralMarker(*format)) break;
                    }
                  }
                }
                if (*format != ' ') break;
                ++format;
              }
              /* Only numeric day form matters */
              if (*format == 'd')
              {
                INT dcount = 1;
                while (*++format == 'd') dcount++;
                if (dcount < 3)
                {
                  szAdd = genitive;
                  break;
                }
              }
            }
          }
          szAdd = GetLongMonth(node, lpTime->wMonth - 1);
        }
        else if (count == 3)
          szAdd = GetShortMonth(node, lpTime->wMonth - 1);
        else
        {
          dwVal = lpTime->wMonth;
          szAdd = buff;
        }
        break;

      case 'y':
#ifdef __REACTOS__
        if (IS_LCID_JAPANESE(lcid) && (dwFlags & DATE_USE_ALT_CALENDAR))
        {
            PCJAPANESE_ERA pEra = JapaneseEra_Find(lpTime);
            if (pEra)
            {
                if (count >= 2)
                {
                    count = 2;
                }

                dwVal = lpTime->wYear - pEra->wYear + 1;

                if (dwVal == 1 && JapaneseEra_IsFirstYearGannen())
                {
                    // Gan of 'Gannen'
                    buff[0] = 0x5143;
                    buff[1] = 0;
                }
                szAdd = buff;
                break;
            }
            SetLastError(ERROR_INVALID_PARAMETER);
            return 0;
        }
#endif
        if (count >= 4)
        {
          count = 4;
          dwVal = lpTime->wYear;
        }
        else
        {
          count = count > 2 ? 2 : count;
          dwVal = lpTime->wYear % 100;
        }
        szAdd = buff;
        break;

      case 'g':
#ifdef __REACTOS__
        if (IS_LCID_JAPANESE(lcid))
        {
            if (dwFlags & DATE_USE_ALT_CALENDAR)
            {
                PCJAPANESE_ERA pEra = JapaneseEra_Find(lpTime);
                if (pEra)
                {
                    RtlStringCbCopyW(buff, sizeof(buff), pEra->szEraName);
                    szAdd = buff;
                    break;
                }
                SetLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }
            else
            {
                /* Seireki */
                buff[0] = 0x897F;
                buff[1] = 0x66A6;
                buff[2] = 0;
                szAdd = buff;
                break;
            }
        }
#endif
        if (count == 2)
        {
          /* FIXME: Our GetCalendarInfo() does not yet support CAL_SERASTRING.
           *        When it is fixed, this string should be cached in 'node'.
           */
          FIXME("Should be using GetCalendarInfo(CAL_SERASTRING), defaulting to 'AD'\n");
          buff[0] = 'A'; buff[1] = 'D'; buff[2] = '\0';
        }
        else
        {
          buff[0] = 'g'; buff[1] = '\0'; /* Add a literal 'g' */
        }
        szAdd = buff;
        break;

      case 'h':
        if (!(dwFlags & TIME_FORCE24HOURFORMAT))
        {
          count = count > 2 ? 2 : count;
          dwVal = lpTime->wHour == 0 ? 12 : (lpTime->wHour - 1) % 12 + 1;
          szAdd = buff;
          break;
        }
        /* .. fall through if we are forced to output in 24 hour format */

      case 'H':
        count = count > 2 ? 2 : count;
        dwVal = lpTime->wHour;
        szAdd = buff;
        break;

      case 'm':
        if (dwFlags & TIME_NOMINUTESORSECONDS)
        {
          cchWritten = lastFormatPos; /* Skip */
          bSkipping = TRUE;
        }
        else
        {
          count = count > 2 ? 2 : count;
          dwVal = lpTime->wMinute;
          szAdd = buff;
        }
        break;

      case 's':
        if (dwFlags & (TIME_NOSECONDS|TIME_NOMINUTESORSECONDS))
        {
          cchWritten = lastFormatPos; /* Skip */
          bSkipping = TRUE;
        }
        else
        {
          count = count > 2 ? 2 : count;
          dwVal = lpTime->wSecond;
          szAdd = buff;
        }
        break;

      case 't':
        if (dwFlags & TIME_NOTIMEMARKER)
        {
          cchWritten = lastFormatPos; /* Skip */
          bSkipping = TRUE;
          /* Windows also drops the spaces behind a marker at the start of the output */
#ifdef __REACTOS__
          bDropSpaces = (cchWritten == 0);
#endif
        }
        else
        {
          if (count == 1)
            szAdd = lpTime->wHour < 12 ? node->szShortAM : node->szShortPM;
          else
            szAdd = lpTime->wHour < 12 ? GetAM(node) : GetPM(node);
#ifdef __REACTOS__
          /* An empty marker string (de-DE) takes the space in front of it away, like a skipped marker */
          if (szAdd && !*szAdd)
          {
            cchWritten = lastFormatPos;
            bSkipping = TRUE;
            szAdd = NULL;
          }
#endif
        }
        break;
      }

      if (szAdd == buff && buff[0] == '\0')
      {
        static const WCHAR fmtW[] = {'%','.','*','d',0};
        /* We have a numeric value to add */
        snprintfW(buff, ARRAY_SIZE(buff), fmtW, count, dwVal);
      }

      dwLen = szAdd ? strlenW(szAdd) : 0;

      if (cchOut && dwLen)
      {
        if (cchWritten + dwLen < cchOut)
          memcpy(lpStr + cchWritten, szAdd, dwLen * sizeof(WCHAR));
        else
        {
          memcpy(lpStr + cchWritten, szAdd, (cchOut - cchWritten) * sizeof(WCHAR));
          goto overrun;
        }
      }
      cchWritten += dwLen;
      lastFormatPos = cchWritten; /* Save position of last output format text */
    }
    else
    {
      /* Literal character */
#ifdef __REACTOS__
      if (bDropSpaces && *lpFormat == ' ')
        ; /* Not shown, see TIME_NOTIMEMARKER above */
      else
#endif
      if (!cchOut)
        cchWritten++;   /* Count size only */
      else if (cchWritten >= cchOut)
        goto overrun;
      else if (!bSkipping || *lpFormat == ' ')
      {
        lpStr[cchWritten] = *lpFormat;
        cchWritten++;
      }
      lpFormat++;
    }
  }

  /* Final string terminator and sanity check */
  if (cchOut)
  {
   if (cchWritten >= cchOut)
     goto overrun;
   else
     lpStr[cchWritten] = '\0';
  }
  cchWritten++; /* Include terminating NUL */

  TRACE("returning length=%d, output=%s\n", cchWritten, debugstr_w(lpStr));
  return cchWritten;

overrun:
  TRACE("returning 0, (ERROR_INSUFFICIENT_BUFFER)\n");
  SetLastError(ERROR_INSUFFICIENT_BUFFER);
  return 0;

invalid_parameter:
  SetLastError(ERROR_INVALID_PARAMETER);
  return 0;

invalid_flags:
  SetLastError(ERROR_INVALID_FLAGS);
  return 0;
}

/******************************************************************************
 * NLS_GetDateTimeFormatA <internal>
 *
 * ASCII wrapper for GetDateFormatA/GetTimeFormatA.
 */
static INT NLS_GetDateTimeFormatA(LCID lcid, DWORD dwFlags,
                                  const SYSTEMTIME* lpTime,
                                  LPCSTR lpFormat, LPSTR lpStr, INT cchOut)
{
  DWORD cp = CP_ACP;
  WCHAR szFormat[128], szOut[128];
  INT iRet;

  TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n", lcid, dwFlags, lpTime,
        debugstr_a(lpFormat), lpStr, cchOut);

  if (NLS_IsUnicodeOnlyLcid(lcid))
  {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
  }

  if (!(dwFlags & LOCALE_USE_CP_ACP))
  {
    const NLS_FORMAT_NODE *node = NLS_GetFormats(lcid, dwFlags);
    if (!node)
    {
      SetLastError(ERROR_INVALID_PARAMETER);
      return 0;
    }

    cp = node->dwCodePage;
  }

  if (lpFormat)
    MultiByteToWideChar(cp, 0, lpFormat, -1, szFormat, ARRAY_SIZE(szFormat));

  if (cchOut > (int) ARRAY_SIZE(szOut))
    cchOut = ARRAY_SIZE(szOut);

  szOut[0] = '\0';

  iRet = NLS_GetDateTimeFormatW(lcid, dwFlags, lpTime, lpFormat ? szFormat : NULL,
                                lpStr ? szOut : NULL, cchOut);

  if (lpStr)
  {
    if (szOut[0])
      WideCharToMultiByte(cp, 0, szOut, iRet ? -1 : cchOut, lpStr, cchOut, 0, 0);
    else if (cchOut && iRet)
      *lpStr = '\0';
  }
  return iRet;
}

/******************************************************************************
 * GetDateFormatA [KERNEL32.@]
 *
 * Format a date for a given locale.
 *
 * PARAMS
 *  lcid      [I] Locale to format for
 *  dwFlags   [I] LOCALE_ and DATE_ flags from "winnls.h"
 *  lpTime    [I] Date to format
 *  lpFormat  [I] Format string, or NULL to use the system defaults
 *  lpDateStr [O] Destination for formatted string
 *  cchOut    [I] Size of lpDateStr, or 0 to calculate the resulting size
 *
 * NOTES
 *  - If lpFormat is NULL, lpDateStr will be formatted according to the format
 *    details returned by GetLocaleInfoA() and modified by dwFlags.
 *  - lpFormat is a string of characters and formatting tokens. Any characters
 *    in the string are copied verbatim to lpDateStr, with tokens being replaced
 *    by the date values they represent.
 *  - The following tokens have special meanings in a date format string:
 *|  Token  Meaning
 *|  -----  -------
 *|  d      Single digit day of the month (no leading 0)
 *|  dd     Double digit day of the month
 *|  ddd    Short name for the day of the week
 *|  dddd   Long name for the day of the week
 *|  M      Single digit month of the year (no leading 0)
 *|  MM     Double digit month of the year
 *|  MMM    Short name for the month of the year
 *|  MMMM   Long name for the month of the year
 *|  y      Double digit year number (no leading 0)
 *|  yy     Double digit year number
 *|  yyyy   Four digit year number
 *|  gg     Era string, for example 'AD'.
 *  - To output any literal character that could be misidentified as a token,
 *    enclose it in single quotes.
 *  - The Ascii version of this function fails if lcid is Unicode only.
 *
 * RETURNS
 *  Success: The number of character written to lpDateStr, or that would
 *           have been written, if cchOut is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
INT WINAPI GetDateFormatA( LCID lcid, DWORD dwFlags, const SYSTEMTIME* lpTime,
                           LPCSTR lpFormat, LPSTR lpDateStr, INT cchOut)
{
  TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n",lcid, dwFlags, lpTime,
        debugstr_a(lpFormat), lpDateStr, cchOut);

  return NLS_GetDateTimeFormatA(lcid, dwFlags | DATE_DATEVARSONLY, lpTime,
                                lpFormat, lpDateStr, cchOut);
}

#if _WIN32_WINNT >= 0x600
/******************************************************************************
 * GetDateFormatEx [KERNEL32.@]
 *
 * Format a date for a given locale.
 *
 * PARAMS
 *  localename [I] Locale to format for
 *  flags      [I] LOCALE_ and DATE_ flags from "winnls.h"
 *  date       [I] Date to format
 *  format     [I] Format string, or NULL to use the locale defaults
 *  outbuf     [O] Destination for formatted string
 *  bufsize    [I] Size of outbuf, or 0 to calculate the resulting size
 *  calendar   [I] Reserved, must be NULL
 *
 * See GetDateFormatA for notes.
 *
 * RETURNS
 *  Success: The number of characters written to outbuf, or that would have
 *           been written if bufsize is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
INT WINAPI GetDateFormatEx(LPCWSTR localename, DWORD flags,
                           const SYSTEMTIME* date, LPCWSTR format,
                           LPWSTR outbuf, INT bufsize, LPCWSTR calendar)
{
  TRACE("(%s,0x%08x,%p,%s,%p,%d,%s)\n", debugstr_w(localename), flags,
        date, debugstr_w(format), outbuf, bufsize, debugstr_w(calendar));

  /* Parameter is currently reserved and Windows errors if set */
  if (calendar != NULL)
  {
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
  }

  return NLS_GetDateTimeFormatW(LocaleNameToLCID(localename, 0),
                                flags | DATE_DATEVARSONLY, date, format,
                                outbuf, bufsize);
}
#endif /* _WIN32_WINNT >= 0x600 */

/******************************************************************************
 * GetDateFormatW	[KERNEL32.@]
 *
 * See GetDateFormatA.
 */
INT WINAPI GetDateFormatW(LCID lcid, DWORD dwFlags, const SYSTEMTIME* lpTime,
                          LPCWSTR lpFormat, LPWSTR lpDateStr, INT cchOut)
{
  TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n", lcid, dwFlags, lpTime,
        debugstr_w(lpFormat), lpDateStr, cchOut);

  return NLS_GetDateTimeFormatW(lcid, dwFlags|DATE_DATEVARSONLY, lpTime,
                                lpFormat, lpDateStr, cchOut);
}

/******************************************************************************
 *		GetTimeFormatA	[KERNEL32.@]
 *
 * Format a time for a given locale.
 *
 * PARAMS
 *  lcid      [I] Locale to format for
 *  dwFlags   [I] LOCALE_ and TIME_ flags from "winnls.h"
 *  lpTime    [I] Time to format
 *  lpFormat  [I] Formatting overrides
 *  lpTimeStr [O] Destination for formatted string
 *  cchOut    [I] Size of lpTimeStr, or 0 to calculate the resulting size
 *
 * NOTES
 *  - If lpFormat is NULL, lpszValue will be formatted according to the format
 *    details returned by GetLocaleInfoA() and modified by dwFlags.
 *  - lpFormat is a string of characters and formatting tokens. Any characters
 *    in the string are copied verbatim to lpTimeStr, with tokens being replaced
 *    by the time values they represent.
 *  - The following tokens have special meanings in a time format string:
 *|  Token  Meaning
 *|  -----  -------
 *|  h      Hours with no leading zero (12-hour clock)
 *|  hh     Hours with full two digits (12-hour clock)
 *|  H      Hours with no leading zero (24-hour clock)
 *|  HH     Hours with full two digits (24-hour clock)
 *|  m      Minutes with no leading zero
 *|  mm     Minutes with full two digits
 *|  s      Seconds with no leading zero
 *|  ss     Seconds with full two digits
 *|  t      Short time marker (e.g. "A" or "P")
 *|  tt     Long time marker (e.g. "AM", "PM")
 *  - To output any literal character that could be misidentified as a token,
 *    enclose it in single quotes.
 *  - The Ascii version of this function fails if lcid is Unicode only.
 *
 * RETURNS
 *  Success: The number of character written to lpTimeStr, or that would
 *           have been written, if cchOut is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
INT WINAPI GetTimeFormatA(LCID lcid, DWORD dwFlags, const SYSTEMTIME* lpTime,
                          LPCSTR lpFormat, LPSTR lpTimeStr, INT cchOut)
{
  TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n",lcid, dwFlags, lpTime,
        debugstr_a(lpFormat), lpTimeStr, cchOut);

  return NLS_GetDateTimeFormatA(lcid, dwFlags|TIME_TIMEVARSONLY, lpTime,
                                lpFormat, lpTimeStr, cchOut);
}

#if _WIN32_WINNT >= 0x600
/******************************************************************************
 * GetTimeFormatEx [KERNEL32.@]
 *
 * Format a date for a given locale.
 *
 * PARAMS
 *  localename [I] Locale to format for
 *  flags      [I] LOCALE_ and TIME_ flags from "winnls.h"
 *  time       [I] Time to format
 *  format     [I] Formatting overrides
 *  outbuf     [O] Destination for formatted string
 *  bufsize    [I] Size of outbuf, or 0 to calculate the resulting size
 *
 * See GetTimeFormatA for notes.
 *
 * RETURNS
 *  Success: The number of characters written to outbuf, or that would have
 *           have been written if bufsize is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
INT WINAPI GetTimeFormatEx(LPCWSTR localename, DWORD flags,
                           const SYSTEMTIME* time, LPCWSTR format,
                           LPWSTR outbuf, INT bufsize)
{
  TRACE("(%s,0x%08x,%p,%s,%p,%d)\n", debugstr_w(localename), flags, time,
        debugstr_w(format), outbuf, bufsize);

  return NLS_GetDateTimeFormatW(LocaleNameToLCID(localename, 0),
                                flags | TIME_TIMEVARSONLY, time, format,
                                outbuf, bufsize);
}
#endif /* _WIN32_WINNT >= 0x600 */

/******************************************************************************
 *		GetTimeFormatW	[KERNEL32.@]
 *
 * See GetTimeFormatA.
 */
INT WINAPI GetTimeFormatW(LCID lcid, DWORD dwFlags, const SYSTEMTIME* lpTime,
                          LPCWSTR lpFormat, LPWSTR lpTimeStr, INT cchOut)
{
  TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n",lcid, dwFlags, lpTime,
        debugstr_w(lpFormat), lpTimeStr, cchOut);

  return NLS_GetDateTimeFormatW(lcid, dwFlags|TIME_TIMEVARSONLY, lpTime,
                                lpFormat, lpTimeStr, cchOut);
}

/* Number parsing state flags */
#define NF_ISNEGATIVE 0x1  /* '-' found */
#define NF_ISREAL     0x2  /* '.' found */
#define NF_DIGITS     0x4  /* '0'-'9' found */
#define NF_DIGITS_OUT 0x8  /* Digits before the '.' found */
#define NF_ROUND      0x10 /* Number needs to be rounded */

/* Formatting options for Numbers */
#define NLS_NEG_PARENS      0 /* "(1.1)" */
#define NLS_NEG_LEFT        1 /* "-1.1"  */
#define NLS_NEG_LEFT_SPACE  2 /* "- 1.1" */
#define NLS_NEG_RIGHT       3 /* "1.1-"  */
#define NLS_NEG_RIGHT_SPACE 4 /* "1.1 -" */

/**************************************************************************
 *              GetNumberFormatW	(KERNEL32.@)
 *
 * See GetNumberFormatA.
 */
INT WINAPI GetNumberFormatW(LCID lcid, DWORD dwFlags,
                            LPCWSTR lpszValue,  const NUMBERFMTW *lpFormat,
                            LPWSTR lpNumberStr, int cchOut)
{
  WCHAR szBuff[128], *szOut = szBuff + ARRAY_SIZE(szBuff) - 1;
  WCHAR szNegBuff[8];
  const WCHAR *lpszNeg = NULL, *lpszNegStart, *szSrc;
  DWORD dwState = 0, dwDecimals = 0, dwGroupCount = 0, dwCurrentGroupCount = 0;
  INT iRet;

  TRACE("(0x%04x,0x%08x,%s,%p,%p,%d)\n", lcid, dwFlags, debugstr_w(lpszValue),
        lpFormat, lpNumberStr, cchOut);

  if (!lpszValue || cchOut < 0 || (cchOut > 0 && !lpNumberStr) ||
      !IsValidLocale(lcid, 0) ||
      (lpFormat && (dwFlags || !lpFormat->lpDecimalSep || !lpFormat->lpThousandSep)))
  {
    goto error;
  }

  if (!lpFormat)
  {
    const NLS_FORMAT_NODE *node = NLS_GetFormats(lcid, dwFlags);

    if (!node)
      goto error;
    lpFormat = &node->fmt;
    lpszNegStart = lpszNeg = GetNegative(node);
  }
  else
  {
    GetLocaleInfoW(lcid, LOCALE_SNEGATIVESIGN|(dwFlags & LOCALE_NOUSEROVERRIDE),
                   szNegBuff, ARRAY_SIZE(szNegBuff));
    lpszNegStart = lpszNeg = szNegBuff;
  }
  lpszNeg = lpszNeg + strlenW(lpszNeg) - 1;

  dwFlags &= (LOCALE_NOUSEROVERRIDE|LOCALE_USE_CP_ACP);

  /* Format the number backwards into a temporary buffer */

  szSrc = lpszValue;
  *szOut-- = '\0';

  /* Check the number for validity */
  while (*szSrc)
  {
    if (*szSrc >= '0' && *szSrc <= '9')
    {
      dwState |= NF_DIGITS;
      if (dwState & NF_ISREAL)
        dwDecimals++;
    }
    else if (*szSrc == '-')
    {
      if (dwState)
        goto error; /* '-' not first character */
      dwState |= NF_ISNEGATIVE;
    }
    else if (*szSrc == '.')
    {
      if (dwState & NF_ISREAL)
        goto error; /* More than one '.' */
      dwState |= NF_ISREAL;
    }
    else
      goto error; /* Invalid char */
    szSrc++;
  }
  szSrc--; /* Point to last character */

  if (!(dwState & NF_DIGITS))
    goto error; /* No digits */

  /* Add any trailing negative sign */
  if (dwState & NF_ISNEGATIVE)
  {
    switch (lpFormat->NegativeOrder)
    {
    case NLS_NEG_PARENS:
      *szOut-- = ')';
      break;
    case NLS_NEG_RIGHT:
    case NLS_NEG_RIGHT_SPACE:
      while (lpszNeg >= lpszNegStart)
        *szOut-- = *lpszNeg--;
     if (lpFormat->NegativeOrder == NLS_NEG_RIGHT_SPACE)
       *szOut-- = ' ';
      break;
    }
  }

  /* Copy all digits up to the decimal point */
  if (!lpFormat->NumDigits)
  {
    if (dwState & NF_ISREAL)
    {
      while (*szSrc != '.') /* Don't write any decimals or a separator */
      {
        if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
          dwState |= NF_ROUND;
        else
          dwState &= ~NF_ROUND;
        szSrc--;
      }
      szSrc--;
    }
  }
  else
  {
    LPWSTR lpszDec = lpFormat->lpDecimalSep + strlenW(lpFormat->lpDecimalSep) - 1;

    if (dwDecimals <= lpFormat->NumDigits)
    {
      dwDecimals = lpFormat->NumDigits - dwDecimals;
      while (dwDecimals--)
        *szOut-- = '0'; /* Pad to correct number of dp */
    }
    else
    {
      dwDecimals -= lpFormat->NumDigits;
      /* Skip excess decimals, and determine if we have to round the number */
      while (dwDecimals--)
      {
        if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
          dwState |= NF_ROUND;
        else
          dwState &= ~NF_ROUND;
        szSrc--;
      }
    }

    if (dwState & NF_ISREAL)
    {
      while (*szSrc != '.')
      {
        if (dwState & NF_ROUND)
        {
          if (*szSrc == '9')
            *szOut-- = '0'; /* continue rounding */
          else
          {
            dwState &= ~NF_ROUND;
            *szOut-- = (*szSrc)+1;
          }
          szSrc--;
        }
        else
          *szOut-- = *szSrc--; /* Write existing decimals */
      }
      szSrc--; /* Skip '.' */
    }

    while (lpszDec >= lpFormat->lpDecimalSep)
      *szOut-- = *lpszDec--; /* Write decimal separator */
  }

  dwGroupCount = lpFormat->Grouping == 32 ? 3 : lpFormat->Grouping;

  /* Write the remaining whole number digits, including grouping chars */
  while (szSrc >= lpszValue && *szSrc >= '0' && *szSrc <= '9')
  {
    if (dwState & NF_ROUND)
    {
      if (*szSrc == '9')
        *szOut-- = '0'; /* continue rounding */
      else
      {
        dwState &= ~NF_ROUND;
        *szOut-- = (*szSrc)+1;
      }
      szSrc--;
    }
    else
      *szOut-- = *szSrc--;

    dwState |= NF_DIGITS_OUT;
    dwCurrentGroupCount++;
    if (szSrc >= lpszValue && dwCurrentGroupCount == dwGroupCount && *szSrc != '-')
    {
      LPWSTR lpszGrp = lpFormat->lpThousandSep + strlenW(lpFormat->lpThousandSep) - 1;

      while (lpszGrp >= lpFormat->lpThousandSep)
        *szOut-- = *lpszGrp--; /* Write grouping char */

      dwCurrentGroupCount = 0;
      if (lpFormat->Grouping == 32)
        dwGroupCount = 2; /* Indic grouping: 3 then 2 */
    }
  }
  if (dwState & NF_ROUND)
  {
    *szOut-- = '1'; /* e.g. .6 > 1.0 */
  }
  else if (!(dwState & NF_DIGITS_OUT) && lpFormat->LeadingZero)
    *szOut-- = '0'; /* Add leading 0 if we have no digits before the decimal point */

  /* Add any leading negative sign */
  if (dwState & NF_ISNEGATIVE)
  {
    switch (lpFormat->NegativeOrder)
    {
    case NLS_NEG_PARENS:
      *szOut-- = '(';
      break;
    case NLS_NEG_LEFT_SPACE:
      *szOut-- = ' ';
      /* Fall through */
    case NLS_NEG_LEFT:
      while (lpszNeg >= lpszNegStart)
        *szOut-- = *lpszNeg--;
      break;
    }
  }
  szOut++;

  iRet = strlenW(szOut) + 1;
  if (cchOut)
  {
    if (iRet <= cchOut)
      memcpy(lpNumberStr, szOut, iRet * sizeof(WCHAR));
    else
    {
      memcpy(lpNumberStr, szOut, cchOut * sizeof(WCHAR));
      lpNumberStr[cchOut - 1] = '\0';
      SetLastError(ERROR_INSUFFICIENT_BUFFER);
      iRet = 0;
    }
  }
  return iRet;

error:
  SetLastError(lpFormat && dwFlags ? ERROR_INVALID_FLAGS : ERROR_INVALID_PARAMETER);
  return 0;
}

#if _WIN32_WINNT >= 0x600
/**************************************************************************
 *              GetNumberFormatEx	(KERNEL32.@)
 */
INT WINAPI GetNumberFormatEx(LPCWSTR name, DWORD flags,
                             LPCWSTR value, const NUMBERFMTW *format,
                             LPWSTR number, int numout)
{
  LCID lcid;

  TRACE("(%s,0x%08x,%s,%p,%p,%d)\n", debugstr_w(name), flags,
        debugstr_w(value), format, number, numout);

  lcid = LocaleNameToLCID(name, 0);
  if (!lcid)
    return 0;

  return GetNumberFormatW(lcid, flags, value, format, number, numout);
}
#endif /* _WIN32_WINNT >= 0x600 */

/* Formatting states for Currencies. We use flags to avoid code duplication. */
#define CF_PARENS       0x1  /* Parentheses      */
#define CF_MINUS_LEFT   0x2  /* '-' to the left  */
#define CF_MINUS_RIGHT  0x4  /* '-' to the right */
#define CF_MINUS_BEFORE 0x8  /* '-' before '$'   */
#define CF_CY_LEFT      0x10 /* '$' to the left  */
#define CF_CY_RIGHT     0x20 /* '$' to the right */
#define CF_CY_SPACE     0x40 /* ' ' by '$'       */

/**************************************************************************
 *              GetCurrencyFormatW	(KERNEL32.@)
 *
 * See GetCurrencyFormatA.
 */
INT WINAPI GetCurrencyFormatW(LCID lcid, DWORD dwFlags,
                              LPCWSTR lpszValue,  const CURRENCYFMTW *lpFormat,
                              LPWSTR lpCurrencyStr, int cchOut)
{
  static const BYTE NLS_NegCyFormats[16] =
  {
    CF_PARENS|CF_CY_LEFT,                       /* ($1.1) */
    CF_MINUS_LEFT|CF_MINUS_BEFORE|CF_CY_LEFT,   /* -$1.1  */
    CF_MINUS_LEFT|CF_CY_LEFT,                   /* $-1.1  */
    CF_MINUS_RIGHT|CF_CY_LEFT,                  /* $1.1-  */
    CF_PARENS|CF_CY_RIGHT,                      /* (1.1$) */
    CF_MINUS_LEFT|CF_CY_RIGHT,                  /* -1.1$  */
    CF_MINUS_RIGHT|CF_MINUS_BEFORE|CF_CY_RIGHT, /* 1.1-$  */
    CF_MINUS_RIGHT|CF_CY_RIGHT,                 /* 1.1$-  */
    CF_MINUS_LEFT|CF_CY_RIGHT|CF_CY_SPACE,      /* -1.1 $ */
    CF_MINUS_LEFT|CF_MINUS_BEFORE|CF_CY_LEFT|CF_CY_SPACE,   /* -$ 1.1 */
    CF_MINUS_RIGHT|CF_CY_RIGHT|CF_CY_SPACE,     /* 1.1 $-  */
    CF_MINUS_RIGHT|CF_CY_LEFT|CF_CY_SPACE,      /* $ 1.1-  */
    CF_MINUS_LEFT|CF_CY_LEFT|CF_CY_SPACE,       /* $ -1.1  */
    CF_MINUS_RIGHT|CF_MINUS_BEFORE|CF_CY_RIGHT|CF_CY_SPACE, /* 1.1- $ */
    CF_PARENS|CF_CY_LEFT|CF_CY_SPACE,           /* ($ 1.1) */
    CF_PARENS|CF_CY_RIGHT|CF_CY_SPACE,          /* (1.1 $) */
  };
  static const BYTE NLS_PosCyFormats[4] =
  {
    CF_CY_LEFT,              /* $1.1  */
    CF_CY_RIGHT,             /* 1.1$  */
    CF_CY_LEFT|CF_CY_SPACE,  /* $ 1.1 */
    CF_CY_RIGHT|CF_CY_SPACE, /* 1.1 $ */
  };
  WCHAR szBuff[128], *szOut = szBuff + ARRAY_SIZE(szBuff) - 1;
  WCHAR szNegBuff[8];
  const WCHAR *lpszNeg = NULL, *lpszNegStart, *szSrc, *lpszCy, *lpszCyStart;
  DWORD dwState = 0, dwDecimals = 0, dwGroupCount = 0, dwCurrentGroupCount = 0, dwFmt;
  INT iRet;

  TRACE("(0x%04x,0x%08x,%s,%p,%p,%d)\n", lcid, dwFlags, debugstr_w(lpszValue),
        lpFormat, lpCurrencyStr, cchOut);

  if (!lpszValue || cchOut < 0 || (cchOut > 0 && !lpCurrencyStr) ||
      !IsValidLocale(lcid, 0) ||
      (lpFormat && (dwFlags || !lpFormat->lpDecimalSep || !lpFormat->lpThousandSep ||
      !lpFormat->lpCurrencySymbol || lpFormat->NegativeOrder > 15 ||
      lpFormat->PositiveOrder > 3)))
  {
    goto error;
  }

  if (!lpFormat)
  {
    const NLS_FORMAT_NODE *node = NLS_GetFormats(lcid, dwFlags);

    if (!node)
      goto error;

    lpFormat = &node->cyfmt;
    lpszNegStart = lpszNeg = GetNegative(node);
  }
  else
  {
    GetLocaleInfoW(lcid, LOCALE_SNEGATIVESIGN|(dwFlags & LOCALE_NOUSEROVERRIDE),
                   szNegBuff, ARRAY_SIZE(szNegBuff));
    lpszNegStart = lpszNeg = szNegBuff;
  }
  dwFlags &= (LOCALE_NOUSEROVERRIDE|LOCALE_USE_CP_ACP);

  lpszNeg = lpszNeg + strlenW(lpszNeg) - 1;
  lpszCyStart = lpFormat->lpCurrencySymbol;
  lpszCy = lpszCyStart + strlenW(lpszCyStart) - 1;

  /* Format the currency backwards into a temporary buffer */

  szSrc = lpszValue;
  *szOut-- = '\0';

  /* Check the number for validity */
  while (*szSrc)
  {
    if (*szSrc >= '0' && *szSrc <= '9')
    {
      dwState |= NF_DIGITS;
      if (dwState & NF_ISREAL)
        dwDecimals++;
    }
    else if (*szSrc == '-')
    {
      if (dwState)
        goto error; /* '-' not first character */
      dwState |= NF_ISNEGATIVE;
    }
    else if (*szSrc == '.')
    {
      if (dwState & NF_ISREAL)
        goto error; /* More than one '.' */
      dwState |= NF_ISREAL;
    }
    else
      goto error; /* Invalid char */
    szSrc++;
  }
  szSrc--; /* Point to last character */

  if (!(dwState & NF_DIGITS))
    goto error; /* No digits */

  if (dwState & NF_ISNEGATIVE)
    dwFmt = NLS_NegCyFormats[lpFormat->NegativeOrder];
  else
    dwFmt = NLS_PosCyFormats[lpFormat->PositiveOrder];

  /* Add any trailing negative or currency signs */
  if (dwFmt & CF_PARENS)
    *szOut-- = ')';

  while (dwFmt & (CF_MINUS_RIGHT|CF_CY_RIGHT))
  {
    switch (dwFmt & (CF_MINUS_RIGHT|CF_MINUS_BEFORE|CF_CY_RIGHT))
    {
    case CF_MINUS_RIGHT:
    case CF_MINUS_RIGHT|CF_CY_RIGHT:
      while (lpszNeg >= lpszNegStart)
        *szOut-- = *lpszNeg--;
      dwFmt &= ~CF_MINUS_RIGHT;
      break;

    case CF_CY_RIGHT:
    case CF_MINUS_BEFORE|CF_CY_RIGHT:
    case CF_MINUS_RIGHT|CF_MINUS_BEFORE|CF_CY_RIGHT:
      while (lpszCy >= lpszCyStart)
        *szOut-- = *lpszCy--;
      if (dwFmt & CF_CY_SPACE)
        *szOut-- = ' ';
      dwFmt &= ~(CF_CY_RIGHT|CF_MINUS_BEFORE);
      break;
    }
  }

  /* Copy all digits up to the decimal point */
  if (!lpFormat->NumDigits)
  {
    if (dwState & NF_ISREAL)
    {
      while (*szSrc != '.') /* Don't write any decimals or a separator */
      {
        if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
          dwState |= NF_ROUND;
        else
          dwState &= ~NF_ROUND;
        szSrc--;
      }
      szSrc--;
    }
  }
  else
  {
    LPWSTR lpszDec = lpFormat->lpDecimalSep + strlenW(lpFormat->lpDecimalSep) - 1;

    if (dwDecimals <= lpFormat->NumDigits)
    {
      dwDecimals = lpFormat->NumDigits - dwDecimals;
      while (dwDecimals--)
        *szOut-- = '0'; /* Pad to correct number of dp */
    }
    else
    {
      dwDecimals -= lpFormat->NumDigits;
      /* Skip excess decimals, and determine if we have to round the number */
      while (dwDecimals--)
      {
        if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
          dwState |= NF_ROUND;
        else
          dwState &= ~NF_ROUND;
        szSrc--;
      }
    }

    if (dwState & NF_ISREAL)
    {
      while (*szSrc != '.')
      {
        if (dwState & NF_ROUND)
        {
          if (*szSrc == '9')
            *szOut-- = '0'; /* continue rounding */
          else
          {
            dwState &= ~NF_ROUND;
            *szOut-- = (*szSrc)+1;
          }
          szSrc--;
        }
        else
          *szOut-- = *szSrc--; /* Write existing decimals */
      }
      szSrc--; /* Skip '.' */
    }
    while (lpszDec >= lpFormat->lpDecimalSep)
      *szOut-- = *lpszDec--; /* Write decimal separator */
  }

  dwGroupCount = lpFormat->Grouping == 32 ? 3 : lpFormat->Grouping;

  /* Write the remaining whole number digits, including grouping chars */
  while (szSrc >= lpszValue && *szSrc >= '0' && *szSrc <= '9')
  {
    if (dwState & NF_ROUND)
    {
      if (*szSrc == '9')
        *szOut-- = '0'; /* continue rounding */
      else
      {
        dwState &= ~NF_ROUND;
        *szOut-- = (*szSrc)+1;
      }
      szSrc--;
    }
    else
      *szOut-- = *szSrc--;

    dwState |= NF_DIGITS_OUT;
    dwCurrentGroupCount++;
    if (szSrc >= lpszValue && dwCurrentGroupCount == dwGroupCount && *szSrc != '-')
    {
      LPWSTR lpszGrp = lpFormat->lpThousandSep + strlenW(lpFormat->lpThousandSep) - 1;

      while (lpszGrp >= lpFormat->lpThousandSep)
        *szOut-- = *lpszGrp--; /* Write grouping char */

      dwCurrentGroupCount = 0;
      if (lpFormat->Grouping == 32)
        dwGroupCount = 2; /* Indic grouping: 3 then 2 */
    }
  }
  if (dwState & NF_ROUND)
    *szOut-- = '1'; /* e.g. .6 > 1.0 */
  else if (!(dwState & NF_DIGITS_OUT) && lpFormat->LeadingZero)
    *szOut-- = '0'; /* Add leading 0 if we have no digits before the decimal point */

  /* Add any leading negative or currency sign */
  while (dwFmt & (CF_MINUS_LEFT|CF_CY_LEFT))
  {
    switch (dwFmt & (CF_MINUS_LEFT|CF_MINUS_BEFORE|CF_CY_LEFT))
    {
    case CF_MINUS_LEFT:
    case CF_MINUS_LEFT|CF_CY_LEFT:
      while (lpszNeg >= lpszNegStart)
        *szOut-- = *lpszNeg--;
      dwFmt &= ~CF_MINUS_LEFT;
      break;

    case CF_CY_LEFT:
    case CF_CY_LEFT|CF_MINUS_BEFORE:
    case CF_MINUS_LEFT|CF_MINUS_BEFORE|CF_CY_LEFT:
      if (dwFmt & CF_CY_SPACE)
        *szOut-- = ' ';
      while (lpszCy >= lpszCyStart)
        *szOut-- = *lpszCy--;
      dwFmt &= ~(CF_CY_LEFT|CF_MINUS_BEFORE);
      break;
    }
  }
  if (dwFmt & CF_PARENS)
    *szOut-- = '(';
  szOut++;

  iRet = strlenW(szOut) + 1;
  if (cchOut)
  {
    if (iRet <= cchOut)
      memcpy(lpCurrencyStr, szOut, iRet * sizeof(WCHAR));
    else
    {
      memcpy(lpCurrencyStr, szOut, cchOut * sizeof(WCHAR));
      lpCurrencyStr[cchOut - 1] = '\0';
      SetLastError(ERROR_INSUFFICIENT_BUFFER);
      iRet = 0;
    }
  }
  return iRet;

error:
  SetLastError(lpFormat && dwFlags ? ERROR_INVALID_FLAGS : ERROR_INVALID_PARAMETER);
  return 0;
}

#if _WIN32_WINNT >= 0x600
/***********************************************************************
 *            GetCurrencyFormatEx (KERNEL32.@)
 */
int WINAPI GetCurrencyFormatEx(LPCWSTR localename, DWORD flags, LPCWSTR value,
                                const CURRENCYFMTW *format, LPWSTR str, int len)
{
    TRACE("(%s,0x%08x,%s,%p,%p,%d)\n", debugstr_w(localename), flags,
            debugstr_w(value), format, str, len);

    return GetCurrencyFormatW( LocaleNameToLCID(localename, 0), flags, value, format, str, len);
}
#endif


/* FIXME: Everything below here needs to move somewhere else along with the
 *        other EnumXXX functions, when a method for storing resources for
 *        alternate calendars is determined.
 */

/* Types for Enum* internals are declared in lcformat_private.h */

/******************************************************************************
 * NLS_EnumDateFormats <internal>
 * Enumerates date formats for a specified locale.
 *
 * PARAMS
 *    ctxt [I] enumeration context, see 'struct enumdateformats_context'
 *
 * RETURNS
 *    Success: TRUE.
 *    Failure: FALSE. Use GetLastError() to determine the cause.
 */
BOOL NLS_EnumDateFormats(const struct enumdateformats_context *ctxt)
{
    WCHAR bufW[256];
    char bufA[256];
    LCTYPE lctype;
    CALID cal_id;
    INT ret;

    if (!ctxt->u.callback)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!GetLocaleInfoW(ctxt->lcid, LOCALE_ICALENDARTYPE|LOCALE_RETURN_NUMBER, (LPWSTR)&cal_id, sizeof(cal_id)/sizeof(WCHAR)))
        return FALSE;

    switch (ctxt->flags & ~LOCALE_USE_CP_ACP)
    {
    case 0:
    case DATE_SHORTDATE:
        lctype = LOCALE_SSHORTDATE;
        break;
    case DATE_LONGDATE:
        lctype = LOCALE_SLONGDATE;
        break;
    case DATE_YEARMONTH:
        lctype = LOCALE_SYEARMONTH;
        break;
    default:
        FIXME("Unknown date format (0x%08x)\n", ctxt->flags);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

#ifdef __REACTOS__
    /* Windows enumerates the formats of all calendars, each with its calendar; the locale data has one only */
    {
        const WCHAR *formats = NLS_GetCalendarEnumList(ctxt->lcid, NLS_CAL_ALL_FORMATS,
                                                       lctype == LOCALE_SSHORTDATE ? CAL_SSHORTDATE :
                                                       lctype == LOCALE_SLONGDATE ? CAL_SLONGDATE : CAL_SYEARMONTH);

        if (formats)
        {
            for (; *formats; formats += wcslen(formats) + 1)
            {
                const WCHAR *text = formats + 1;
                CALID entry_cal = formats[0];

                if (!ctxt->unicode)
                {
                    if (!WideCharToMultiByte(CP_ACP, 0, text, -1, bufA, sizeof(bufA), NULL, NULL))
                        return FALSE;
                    text = (const WCHAR *)bufA;
                }

                switch (ctxt->type)
                {
                case CALLBACK_ENUMPROC:
                    ret = ctxt->u.callback((WCHAR *)text);
                    break;
                case CALLBACK_ENUMPROCEX:
                    ret = ctxt->u.callbackex((WCHAR *)text, entry_cal);
                    break;
                case CALLBACK_ENUMPROCEXEX:
                    ret = ctxt->u.callbackexex((WCHAR *)text, entry_cal, ctxt->lParam);
                    break;
                default:
                    ret = TRUE;
                }
                if (!ret)
                    break;
            }
            return TRUE;
        }
    }
#endif

    lctype |= ctxt->flags & LOCALE_USE_CP_ACP;
    if (ctxt->unicode)
        ret = GetLocaleInfoW(ctxt->lcid, lctype, bufW, ARRAY_SIZE(bufW));
    else
        ret = GetLocaleInfoA(ctxt->lcid, lctype, bufA, ARRAY_SIZE(bufA));

    if (ret)
    {
        switch (ctxt->type)
        {
        case CALLBACK_ENUMPROC:
            ctxt->u.callback(ctxt->unicode ? bufW : (WCHAR*)bufA);
            break;
        case CALLBACK_ENUMPROCEX:
            ctxt->u.callbackex(ctxt->unicode ? bufW : (WCHAR*)bufA, cal_id);
            break;
        case CALLBACK_ENUMPROCEXEX:
            ctxt->u.callbackexex(bufW, cal_id, ctxt->lParam);
            break;
        default:
            ;
        }
    }

    return TRUE;
}

/**************************************************************************
 *              EnumDateFormatsExA    (KERNEL32.@)
 *
 * FIXME: MSDN mentions only LOCALE_USE_CP_ACP, should we handle
 * LOCALE_NOUSEROVERRIDE here as well?
 */
BOOL WINAPI EnumDateFormatsExA(DATEFMT_ENUMPROCEXA proc, LCID lcid, DWORD flags)
{
    struct enumdateformats_context ctxt;

    ctxt.type = CALLBACK_ENUMPROCEX;
    ctxt.u.callbackex = (DATEFMT_ENUMPROCEXW)proc;
    ctxt.lcid = lcid;
    ctxt.flags = flags;
    ctxt.unicode = FALSE;

    return NLS_EnumDateFormats(&ctxt);
}

/**************************************************************************
 *              EnumDateFormatsExW    (KERNEL32.@)
 */
BOOL WINAPI EnumDateFormatsExW(DATEFMT_ENUMPROCEXW proc, LCID lcid, DWORD flags)
{
    struct enumdateformats_context ctxt;

    ctxt.type = CALLBACK_ENUMPROCEX;
    ctxt.u.callbackex = proc;
    ctxt.lcid = lcid;
    ctxt.flags = flags;
    ctxt.unicode = TRUE;

    return NLS_EnumDateFormats(&ctxt);
}

/**************************************************************************
 *              EnumDateFormatsW	(KERNEL32.@)
 */
BOOL WINAPI EnumDateFormatsW(DATEFMT_ENUMPROCW proc, LCID lcid, DWORD flags)
{
    struct enumdateformats_context ctxt;

    ctxt.type = CALLBACK_ENUMPROC;
    ctxt.u.callback = proc;
    ctxt.lcid = lcid;
    ctxt.flags = flags;
    ctxt.unicode = TRUE;

    return NLS_EnumDateFormats(&ctxt);
}

#if _WIN32_WINNT >= 0x600
/**************************************************************************
 *              EnumDateFormatsExEx	(KERNEL32.@)
 */
BOOL WINAPI EnumDateFormatsExEx(DATEFMT_ENUMPROCEXEX proc, const WCHAR *locale, DWORD flags, LPARAM lParam)
{
    struct enumdateformats_context ctxt;

    ctxt.type = CALLBACK_ENUMPROCEXEX;
    ctxt.u.callbackexex = proc;
    ctxt.lcid = LocaleNameToLCID(locale, 0);
    ctxt.flags = flags;
    ctxt.lParam = lParam;
    ctxt.unicode = TRUE;

    return NLS_EnumDateFormats(&ctxt);
}
#endif /* _WIN32_WINNT >= 0x600 */

BOOL NLS_EnumTimeFormats(struct enumtimeformats_context *ctxt)
{
    WCHAR bufW[256];
    char bufA[256];
    LCTYPE lctype;
    INT ret;

    if (!ctxt->u.callback)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    switch (ctxt->flags & ~LOCALE_USE_CP_ACP)
    {
    case 0:
        lctype = LOCALE_STIMEFORMAT;
        break;
    case TIME_NOSECONDS:
        lctype = LOCALE_SSHORTTIME;
        break;
    default:
        FIXME("Unknown time format (%d)\n", ctxt->flags);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

#ifdef __REACTOS__
    /* Windows has several time formats */
    if (lctype == LOCALE_STIMEFORMAT)
    {
        const WCHAR *formats = NLS_GetCalendarEnumList(ctxt->lcid, NLS_CAL_TIME_FORMATS, 0);

        if (formats)
        {
            for (; *formats; formats += wcslen(formats) + 1)
            {
                const WCHAR *text = formats;

                if (!ctxt->unicode)
                {
                    if (!WideCharToMultiByte(CP_ACP, 0, text, -1, bufA, sizeof(bufA), NULL, NULL))
                        return FALSE;
                    text = (const WCHAR *)bufA;
                }

                switch (ctxt->type)
                {
                case CALLBACK_ENUMPROC:
                    ret = ctxt->u.callback((WCHAR *)text);
                    break;
                case CALLBACK_ENUMPROCEX:
                    ret = ctxt->u.callbackex((WCHAR *)text, ctxt->lParam);
                    break;
                default:
                    ret = TRUE;
                }
                if (!ret)
                    break;
            }
            return TRUE;
        }
    }
#endif

    lctype |= ctxt->flags & LOCALE_USE_CP_ACP;
    if (ctxt->unicode)
        ret = GetLocaleInfoW(ctxt->lcid, lctype, bufW, ARRAY_SIZE(bufW));
    else
        ret = GetLocaleInfoA(ctxt->lcid, lctype, bufA, ARRAY_SIZE(bufA));

    if (ret)
    {
        switch (ctxt->type)
        {
        case CALLBACK_ENUMPROC:
            ctxt->u.callback(ctxt->unicode ? bufW : (WCHAR*)bufA);
            break;
        case CALLBACK_ENUMPROCEX:
            ctxt->u.callbackex(bufW, ctxt->lParam);
            break;
        default:
            ;
        }
    }

    return TRUE;
}

/**************************************************************************
 *              EnumTimeFormatsW	(KERNEL32.@)
 */
BOOL WINAPI EnumTimeFormatsW(TIMEFMT_ENUMPROCW proc, LCID lcid, DWORD flags)
{
    struct enumtimeformats_context ctxt;

    ctxt.type = CALLBACK_ENUMPROC;
    ctxt.u.callback = proc;
    ctxt.lcid = lcid;
    ctxt.flags = flags;
    ctxt.unicode = TRUE;

    return NLS_EnumTimeFormats(&ctxt);
}

#if _WIN32_WINNT >= 0x600
/**************************************************************************
 *              EnumTimeFormatsEx	(KERNEL32.@)
 */
BOOL WINAPI EnumTimeFormatsEx(TIMEFMT_ENUMPROCEX proc, const WCHAR *locale, DWORD flags, LPARAM lParam)
{
    struct enumtimeformats_context ctxt;

    ctxt.type = CALLBACK_ENUMPROCEX;
    ctxt.u.callbackex = proc;
    ctxt.lcid = LocaleNameToLCID(locale, 0);
    ctxt.flags = flags;
    ctxt.lParam = lParam;
    ctxt.unicode = TRUE;

    return NLS_EnumTimeFormats(&ctxt);
}
#endif /* _WIN32_WINNT >= 0x600 */


/******************************************************************************
 * NLS_EnumCalendarInfo <internal>
 * Enumerates calendar information for a specified locale.
 *
 * PARAMS
 *    ctxt [I] enumeration context, see 'struct enumcalendar_context'
 *
 * RETURNS
 *    Success: TRUE.
 *    Failure: FALSE. Use GetLastError() to determine the cause.
 *
 * NOTES
 *    When the ANSI version of this function is used with a Unicode-only LCID,
 *    the call can succeed because the system uses the system code page.
 *    However, characters that are undefined in the system code page appear
 *    in the string as a question mark (?).
 *
 * TODO
 *    The above note should be respected by GetCalendarInfoA.
 */
static BOOL NLS_CallCalendarCallback(const struct enumcalendar_context *ctxt, WCHAR *buf, CALID calendar)
{
    switch (ctxt->type)
    {
    case CALLBACK_ENUMPROC:
        return ctxt->u.callback(buf);
    case CALLBACK_ENUMPROCEX:
        return ctxt->u.callbackex(buf, calendar);
    case CALLBACK_ENUMPROCEXEX:
        return ctxt->u.callbackexex(buf, calendar, NULL, ctxt->lParam);
    default:
        return TRUE;
    }
}

BOOL NLS_EnumCalendarInfo(const struct enumcalendar_context *ctxt)
{
  WCHAR *buf, *opt = NULL, *iter;
  CALID calendars[NLS_CAL_MAX + 16];
  UINT numCalendars = 0, index;
  BOOL ret = FALSE;
  int bufSz = 200;		/* the size of the buffer */

  if (ctxt->u.callback == NULL)
  {
    SetLastError(ERROR_INVALID_PARAMETER);
    return FALSE;
  }

  buf = HeapAlloc(GetProcessHeap(), 0, bufSz);
  if (buf == NULL)
  {
    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return FALSE;
  }

  if (ctxt->calendar == ENUM_ALL_CALENDARS)
  {
    const NLS_CAL_LIST *list = NLS_GetCalendarList(ctxt->lcid);

    if (list)
    {
      /* The calendars of Windows 10, the default one first */
      for (index = 0; index < list->Count && numCalendars < ARRAY_SIZE(calendars); index++)
        calendars[numCalendars++] = list->Calendars[index];
    }
    else
    {
      int optSz = GetLocaleInfoW(ctxt->lcid, LOCALE_IOPTIONALCALENDAR, NULL, 0);

      calendars[numCalendars++] = NLS_GetLocaleNumber(ctxt->lcid, LOCALE_ICALENDARTYPE);
      if (optSz > 1)
      {
        opt = HeapAlloc(GetProcessHeap(), 0, optSz * sizeof(WCHAR));
        if (opt == NULL)
        {
          SetLastError(ERROR_NOT_ENOUGH_MEMORY);
          goto cleanup;
        }
        if (GetLocaleInfoW(ctxt->lcid, LOCALE_IOPTIONALCALENDAR, opt, optSz))
        {
          /* NUL-separated decimal numbers; 0 means none */
          /* the list ends with the NUL of its last number: stop at its size (a one-number list was read one
           * character past the end, a stray value there was ERROR_BADDB) */
          for (iter = opt; iter < opt + optSz && *iter && numCalendars < ARRAY_SIZE(calendars); )
          {
            CALID id = 0;
            UINT known;

            while (iter < opt + optSz && (*iter >= '0') && (*iter <= '9'))
              id = id * 10 + *iter++ - '0';

            if (iter >= opt + optSz || *iter++ != 0)
            {
              SetLastError(ERROR_BADDB);
              goto cleanup;
            }

            for (known = 0; known < numCalendars; known++)
            {
              if (calendars[known] == id)
                break;
            }
            if (id && known == numCalendars)
              calendars[numCalendars++] = id;
          }
        }
      }
    }
  }
  else
    calendars[numCalendars++] = ctxt->calendar;

  for (index = 0; index < numCalendars; index++)	/* loop through calendars */
  {
    CALID calendar = calendars[index];
    const WCHAR *values = NULL;

    if (!(ctxt->caltype & CAL_RETURN_NUMBER))
      values = NLS_GetCalendarEnumList(ctxt->lcid, calendar, ctxt->caltype & 0xffff);

    if (values)
    {
      /* Windows has several entries: the formats of a date, the eras of a calendar */
      for (; *values; values += wcslen(values) + 1)
      {
        BOOL more;

        if (ctxt->unicode)
        {
          more = NLS_CallCalendarCallback(ctxt, (WCHAR *)values, calendar);
        }
        else
        {
          char valueA[256];
          int lenA = WideCharToMultiByte(CP_ACP, 0, values, -1, valueA, sizeof(valueA), NULL, NULL);

          if (!lenA)
          {
            ret = FALSE;
            goto cleanup;
          }
          more = NLS_CallCalendarCallback(ctxt, (WCHAR *)valueA, calendar);
        }
        if (!more)			/* the callback told to stop */
        {
          ret = TRUE;
          goto cleanup;
        }
      }
      ret = TRUE;
      continue;
    }

    if (ctxt->caltype & CAL_RETURN_NUMBER)
    {
      /* Windows hands the number to the callback as text */
      static const WCHAR fmtW[] = {'%','u',0};
      WCHAR number[16];
      DWORD value = 0;

      if (!GetCalendarInfoW(ctxt->lcid, calendar, ctxt->caltype, NULL, 0, &value))
      {
        ret = FALSE;
        goto cleanup;
      }
      snprintfW(number, ARRAY_SIZE(number), fmtW, value);
      if (ctxt->unicode)
        strcpyW(buf, number);
      else
        WideCharToMultiByte(CP_ACP, 0, number, -1, (CHAR *)buf, bufSz, NULL, NULL);

      ret = TRUE;
      if (!NLS_CallCalendarCallback(ctxt, buf, calendar))
        break;
      continue;
    }

    do				/* loop until there's no error */
    {
      if (ctxt->caltype & CAL_RETURN_NUMBER)
        ret = GetCalendarInfoW(ctxt->lcid, calendar, ctxt->caltype, NULL, bufSz / sizeof(WCHAR), (LPDWORD)buf);
      else if (ctxt->unicode)
        ret = GetCalendarInfoW(ctxt->lcid, calendar, ctxt->caltype, buf, bufSz / sizeof(WCHAR), NULL);
      else ret = GetCalendarInfoA(ctxt->lcid, calendar, ctxt->caltype, (CHAR*)buf, bufSz / sizeof(CHAR), NULL);

      if (!ret)
      {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {				/* so resize it */
          int newSz;
          if (ctxt->unicode)
            newSz = GetCalendarInfoW(ctxt->lcid, calendar, ctxt->caltype, NULL, 0, NULL) * sizeof(WCHAR);
          else newSz = GetCalendarInfoA(ctxt->lcid, calendar, ctxt->caltype, NULL, 0, NULL) * sizeof(CHAR);
          if (bufSz >= newSz)
          {
            ERR("Buffer resizing disorder: was %d, requested %d.\n", bufSz, newSz);
            goto cleanup;
          }
          bufSz = newSz;
          WARN("Buffer too small; resizing to %d bytes.\n", bufSz);
          buf = HeapReAlloc(GetProcessHeap(), 0, buf, bufSz);
          if (buf == NULL)
            goto cleanup;
        } else goto cleanup;
      }
    } while (!ret);

    /* Here we are. We pass the buffer to the correct version of
     * the callback. Because it's not the same number of params,
     * we must check for Ex, but we don't care about Unicode
     * because the buffer is already in the correct format.
     */
    if (!NLS_CallCalendarCallback(ctxt, buf, calendar))
    {				/* the callback told to stop */
      ret = TRUE;
      break;
    }
  }

cleanup:
  HeapFree(GetProcessHeap(), 0, opt);
  HeapFree(GetProcessHeap(), 0, buf);
  return ret;
}

/******************************************************************************
 *		EnumCalendarInfoW	[KERNEL32.@]
 */
BOOL WINAPI EnumCalendarInfoW( CALINFO_ENUMPROCW calinfoproc,LCID locale,
                               CALID calendar,CALTYPE caltype )
{
  struct enumcalendar_context ctxt;

  TRACE("(%p,0x%08x,0x%08x,0x%08x)\n", calinfoproc, locale, calendar, caltype);

  ctxt.type = CALLBACK_ENUMPROC;
  ctxt.u.callback = calinfoproc;
  ctxt.lcid = locale;
  ctxt.calendar = calendar;
  ctxt.caltype = caltype;
  ctxt.lParam = 0;
  ctxt.unicode = TRUE;
  return NLS_EnumCalendarInfo(&ctxt);
}

/******************************************************************************
 *		EnumCalendarInfoExA	[KERNEL32.@]
 */

/******************************************************************************
 *		EnumCalendarInfoExW	[KERNEL32.@]
 */
BOOL WINAPI EnumCalendarInfoExW( CALINFO_ENUMPROCEXW calinfoproc,LCID locale,
                                 CALID calendar,CALTYPE caltype )
{
  struct enumcalendar_context ctxt;

  TRACE("(%p,0x%08x,0x%08x,0x%08x)\n", calinfoproc, locale, calendar, caltype);

  ctxt.type = CALLBACK_ENUMPROCEX;
  ctxt.u.callbackex = calinfoproc;
  ctxt.lcid = locale;
  ctxt.calendar = calendar;
  ctxt.caltype = caltype;
  ctxt.lParam = 0;
  ctxt.unicode = TRUE;
  return NLS_EnumCalendarInfo(&ctxt);
}

#if _WIN32_WINNT >= 0x600
/******************************************************************************
 *		EnumCalendarInfoExEx	[KERNEL32.@]
 */
BOOL WINAPI EnumCalendarInfoExEx( CALINFO_ENUMPROCEXEX calinfoproc, LPCWSTR locale, CALID calendar,
    LPCWSTR reserved, CALTYPE caltype, LPARAM lParam)
{
  struct enumcalendar_context ctxt;

  TRACE("(%p,%s,0x%08x,%p,0x%08x,0x%ld)\n", calinfoproc, debugstr_w(locale), calendar, reserved, caltype, lParam);

  ctxt.type = CALLBACK_ENUMPROCEXEX;
  ctxt.u.callbackexex = calinfoproc;
  ctxt.lcid = LocaleNameToLCID(locale, 0);
  ctxt.calendar = calendar;
  ctxt.caltype = caltype;
  ctxt.lParam = lParam;
  ctxt.unicode = TRUE;
  return NLS_EnumCalendarInfo(&ctxt);
}
#endif /* _WIN32_WINNT >= 0x600 */

/*********************************************************************
 *	GetCalendarInfoW				(KERNEL32.@)
 *
 */
int WINAPI GetCalendarInfoW(LCID Locale, CALID Calendar, CALTYPE CalType,
			    LPWSTR lpCalData, int cchData, LPDWORD lpValue)
{
    static const LCTYPE caltype_lctype_map[] = {
        0, /* not used */
        0, /* CAL_ICALINTVALUE */
        0, /* CAL_SCALNAME */
        0, /* CAL_IYEAROFFSETRANGE */
        0, /* CAL_SERASTRING */
        LOCALE_SSHORTDATE,
        LOCALE_SLONGDATE,
        LOCALE_SDAYNAME1,
        LOCALE_SDAYNAME2,
        LOCALE_SDAYNAME3,
        LOCALE_SDAYNAME4,
        LOCALE_SDAYNAME5,
        LOCALE_SDAYNAME6,
        LOCALE_SDAYNAME7,
        LOCALE_SABBREVDAYNAME1,
        LOCALE_SABBREVDAYNAME2,
        LOCALE_SABBREVDAYNAME3,
        LOCALE_SABBREVDAYNAME4,
        LOCALE_SABBREVDAYNAME5,
        LOCALE_SABBREVDAYNAME6,
        LOCALE_SABBREVDAYNAME7,
        LOCALE_SMONTHNAME1,
        LOCALE_SMONTHNAME2,
        LOCALE_SMONTHNAME3,
        LOCALE_SMONTHNAME4,
        LOCALE_SMONTHNAME5,
        LOCALE_SMONTHNAME6,
        LOCALE_SMONTHNAME7,
        LOCALE_SMONTHNAME8,
        LOCALE_SMONTHNAME9,
        LOCALE_SMONTHNAME10,
        LOCALE_SMONTHNAME11,
        LOCALE_SMONTHNAME12,
        LOCALE_SMONTHNAME13,
        LOCALE_SABBREVMONTHNAME1,
        LOCALE_SABBREVMONTHNAME2,
        LOCALE_SABBREVMONTHNAME3,
        LOCALE_SABBREVMONTHNAME4,
        LOCALE_SABBREVMONTHNAME5,
        LOCALE_SABBREVMONTHNAME6,
        LOCALE_SABBREVMONTHNAME7,
        LOCALE_SABBREVMONTHNAME8,
        LOCALE_SABBREVMONTHNAME9,
        LOCALE_SABBREVMONTHNAME10,
        LOCALE_SABBREVMONTHNAME11,
        LOCALE_SABBREVMONTHNAME12,
        LOCALE_SABBREVMONTHNAME13,
        LOCALE_SYEARMONTH,
        0, /* CAL_ITWODIGITYEARMAX */
        LOCALE_SSHORTESTDAYNAME1,
        LOCALE_SSHORTESTDAYNAME2,
        LOCALE_SSHORTESTDAYNAME3,
        LOCALE_SSHORTESTDAYNAME4,
        LOCALE_SSHORTESTDAYNAME5,
        LOCALE_SSHORTESTDAYNAME6,
        LOCALE_SSHORTESTDAYNAME7,
        LOCALE_SMONTHDAY,
        0, /* CAL_SABBREVERASTRING */
        LOCALE_SRELATIVELONGDATE,
    };
    DWORD localeflags = 0;
    CALTYPE calinfo;

    if (CalType & CAL_NOUSEROVERRIDE)
	FIXME("flag CAL_NOUSEROVERRIDE used, not fully implemented\n");
    if (CalType & CAL_USE_CP_ACP)
	FIXME("flag CAL_USE_CP_ACP used, not fully implemented\n");

    if (CalType & CAL_RETURN_NUMBER) {
        if (!lpValue)
        {
            SetLastError( ERROR_INVALID_PARAMETER );
            return 0;
        }
	if (lpCalData != NULL)
	    WARN("lpCalData not NULL (%p) when it should!\n", lpCalData);
	if (cchData != 0)
	    WARN("cchData not 0 (%d) when it should!\n", cchData);
    } else {
	if (lpValue != NULL)
	    WARN("lpValue not NULL (%p) when it should!\n", lpValue);
    }

    /* FIXME: No verification is made yet wrt Locale
     * for the CALTYPES not requiring GetLocaleInfoA */

    calinfo = CalType & 0xffff;

#ifdef __REACTOS__
    if (CalType & LOCALE_RETURN_GENITIVE_NAMES)
#else
    if (CalType & CAL_RETURN_GENITIVE_NAMES)
#endif
        localeflags |= LOCALE_RETURN_GENITIVE_NAMES;

#ifdef __REACTOS__
    /* The calendar data measured on Windows 10; the Japanese calendar below has its own era table */
    if (!(IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN))
    {
        const WCHAR *Value;

        if (calinfo == CAL_ICALINTVALUE)
        {
            /* Windows answers with the calendar itself when the locale supports it */
            const NLS_CAL_LIST *List = NLS_GetCalendarList(Locale);

            if (List && Calendar)
            {
                UINT Index;

                for (Index = 0; Index < List->Count; Index++)
                {
                    if (List->Calendars[Index] == Calendar)
                        return NLS_ReturnCalendarNumber(Calendar, CalType, lpCalData, cchData, lpValue);
                }
            }
        }
        else if ((Value = NLS_GetCalendarString(Locale, Calendar, calinfo)) != NULL)
        {
            if ((CalType & CAL_RETURN_NUMBER) && (calinfo == CAL_IYEAROFFSETRANGE || calinfo == CAL_ITWODIGITYEARMAX))
                return NLS_ReturnCalendarNumber((DWORD)strtolW(Value, NULL, 10), CalType, lpCalData, cchData, lpValue);
            return NLS_ReturnCalendarString(Value, lpCalData, cchData);
        }
    }
#endif

    switch (calinfo) {
	case CAL_ICALINTVALUE:
#ifdef __REACTOS__
        if (IS_LCID_JAPANESE(Locale))
        {
            if (CalType & CAL_RETURN_NUMBER)
            {
                *lpValue = CAL_JAPAN;
                return sizeof(DWORD) / sizeof(WCHAR);
            }
            else
            {
                static const WCHAR fmtW[] = {'%','u',0};
                WCHAR buffer[10];
                int ret = snprintfW( buffer, 10, fmtW, CAL_JAPAN ) + 1;
                if (!lpCalData) return ret;
                if (ret <= cchData)
                {
                    strcpyW( lpCalData, buffer );
                    return ret;
                }
                SetLastError( ERROR_INSUFFICIENT_BUFFER );
                return 0;
            }
        }
#endif
            if (CalType & CAL_RETURN_NUMBER)
                return GetLocaleInfoW(Locale, LOCALE_RETURN_NUMBER | LOCALE_ICALENDARTYPE,
                        (LPWSTR)lpValue, 2);
            return GetLocaleInfoW(Locale, LOCALE_ICALENDARTYPE, lpCalData, cchData);
	case CAL_SCALNAME:
#ifdef __REACTOS__
        if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN)
        {
            // Wareki
            if (!lpCalData || !cchData)
                return 3;
            if (cchData < 3)
            {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return 0;
            }
            lpCalData[0] = 0x548C;
            lpCalData[1] = 0x66A6;
            lpCalData[2] = 0;
            return 3;
        }
#endif
            FIXME("Unimplemented caltype %d\n", calinfo);
            if (lpCalData) *lpCalData = 0;
	    return 1;
	case CAL_IYEAROFFSETRANGE:
#ifdef __REACTOS__
        if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN)
        {
            PCJAPANESE_ERA pEra = JapaneseEra_Find(NULL);
            if (pEra)
            {
                if (CalType & CAL_RETURN_NUMBER)
                {
                    *lpValue = pEra->wYear;
                    return sizeof(DWORD) / sizeof(WCHAR);
                }
                else
                {
                    static const WCHAR fmtW[] = {'%','u',0};
                    WCHAR buffer[10];
                    int ret = snprintfW( buffer, 10, fmtW, pEra->wYear ) + 1;
                    if (!lpCalData) return ret;
                    if (ret <= cchData)
                    {
                        strcpyW( lpCalData, buffer );
                        return ret;
                    }
                    SetLastError( ERROR_INSUFFICIENT_BUFFER );
                    return 0;
                }
            }
            else
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
#endif
            /* Gregorian calendars have no year offset range: Windows returns 0 */
            if (CalType & CAL_RETURN_NUMBER)
            {
                *lpValue = 0;
                return sizeof(DWORD) / sizeof(WCHAR);
            }
            if (!lpCalData || !cchData) return 2;
            if (cchData < 2)
            {
                SetLastError( ERROR_INSUFFICIENT_BUFFER );
                return 0;
            }
            lpCalData[0] = L'0';
            lpCalData[1] = 0;
            return 2;
	case CAL_SERASTRING:
#ifdef __REACTOS__
        if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN)
        {
            PCJAPANESE_ERA pEra = JapaneseEra_Find(NULL);
            if (pEra)
            {
                if (!lpCalData || !cchData)
                    return strlenW(pEra->szEraName) + 1;
                RtlStringCchCopyW(lpCalData, cchData, pEra->szEraName);
                return strlenW(lpCalData) + 1;
            }
            else
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }
        }
#endif
            FIXME("Unimplemented caltype %d\n", calinfo);
	    return 0;
	case CAL_SSHORTDATE:
	case CAL_SLONGDATE:
	case CAL_SDAYNAME1:
	case CAL_SDAYNAME2:
	case CAL_SDAYNAME3:
	case CAL_SDAYNAME4:
	case CAL_SDAYNAME5:
	case CAL_SDAYNAME6:
	case CAL_SDAYNAME7:
	case CAL_SABBREVDAYNAME1:
	case CAL_SABBREVDAYNAME2:
	case CAL_SABBREVDAYNAME3:
	case CAL_SABBREVDAYNAME4:
	case CAL_SABBREVDAYNAME5:
	case CAL_SABBREVDAYNAME6:
	case CAL_SABBREVDAYNAME7:
	case CAL_SMONTHNAME1:
	case CAL_SMONTHNAME2:
	case CAL_SMONTHNAME3:
	case CAL_SMONTHNAME4:
	case CAL_SMONTHNAME5:
	case CAL_SMONTHNAME6:
	case CAL_SMONTHNAME7:
	case CAL_SMONTHNAME8:
	case CAL_SMONTHNAME9:
	case CAL_SMONTHNAME10:
	case CAL_SMONTHNAME11:
	case CAL_SMONTHNAME12:
	case CAL_SMONTHNAME13:
	case CAL_SABBREVMONTHNAME1:
	case CAL_SABBREVMONTHNAME2:
	case CAL_SABBREVMONTHNAME3:
	case CAL_SABBREVMONTHNAME4:
	case CAL_SABBREVMONTHNAME5:
	case CAL_SABBREVMONTHNAME6:
	case CAL_SABBREVMONTHNAME7:
	case CAL_SABBREVMONTHNAME8:
	case CAL_SABBREVMONTHNAME9:
	case CAL_SABBREVMONTHNAME10:
	case CAL_SABBREVMONTHNAME11:
	case CAL_SABBREVMONTHNAME12:
	case CAL_SABBREVMONTHNAME13:
	case CAL_SYEARMONTH:
	case CAL_SSHORTESTDAYNAME1:
	case CAL_SSHORTESTDAYNAME2:
	case CAL_SSHORTESTDAYNAME3:
	case CAL_SSHORTESTDAYNAME4:
	case CAL_SSHORTESTDAYNAME5:
	case CAL_SSHORTESTDAYNAME6:
	case CAL_SSHORTESTDAYNAME7:
	case CAL_SMONTHDAY:
	case CAL_SRELATIVELONGDATE:
            return GetLocaleInfoW(Locale, caltype_lctype_map[calinfo] | localeflags, lpCalData, cchData);
	case CAL_ITWODIGITYEARMAX:
#ifdef __REACTOS__
        if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN)
        {
            if (CalType & CAL_RETURN_NUMBER)
            {
                *lpValue = JAPANESE_MAX_TWODIGITYEAR;
                return sizeof(DWORD) / sizeof(WCHAR);
            }
            else
            {
                static const WCHAR fmtW[] = {'%','u',0};
                WCHAR buffer[10];
                int ret = snprintfW( buffer, 10, fmtW, JAPANESE_MAX_TWODIGITYEAR ) + 1;
                if (!lpCalData) return ret;
                if (ret <= cchData)
                {
                    strcpyW( lpCalData, buffer );
                    return ret;
                }
                SetLastError( ERROR_INSUFFICIENT_BUFFER );
                return 0;
            }
        }
#endif
            if (CalType & CAL_RETURN_NUMBER)
            {
                *lpValue = NLS_GetTwoDigitYearMax(Calendar);
                return sizeof(DWORD) / sizeof(WCHAR);
            }
            else
            {
                static const WCHAR fmtW[] = {'%','u',0};
                WCHAR buffer[10];
                int ret = snprintfW( buffer, 10, fmtW, NLS_GetTwoDigitYearMax(Calendar) ) + 1;
                if (!lpCalData) return ret;
                if (ret <= cchData)
                {
                    strcpyW( lpCalData, buffer );
                    return ret;
                }
                SetLastError( ERROR_INSUFFICIENT_BUFFER );
                return 0;
            }
	    break;
#ifdef __REACTOS__
    case CAL_SABBREVERASTRING:
        if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN)
        {
            PCJAPANESE_ERA pEra = JapaneseEra_Find(NULL);
            if (pEra)
            {
                if (!lpCalData || !cchData)
                    return strlenW(pEra->szEraAbbrev) + 1;
                RtlStringCchCopyW(lpCalData, cchData, pEra->szEraAbbrev);
                return strlenW(lpCalData) + 1;
            }
        }
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
#endif
	default:
            FIXME("Unknown caltype %d\n", calinfo);
            SetLastError(ERROR_INVALID_FLAGS);
            return 0;
    }
    return 0;
}

#if _WIN32_WINNT >= 0x600
/*********************************************************************
 *	GetCalendarInfoEx				(KERNEL32.@)
 */
int WINAPI GetCalendarInfoEx(LPCWSTR locale, CALID calendar, LPCWSTR lpReserved, CALTYPE caltype,
    LPWSTR data, int len, DWORD *value)
{
    static int once;

    LCID lcid = LocaleNameToLCID(locale, 0);
    if (!once++)
        FIXME("(%s, %d, %p, 0x%08x, %p, %d, %p): semi-stub\n", debugstr_w(locale), calendar, lpReserved, caltype,
        data, len, value);
    return GetCalendarInfoW(lcid, calendar, caltype, data, len, value);
}
#endif


/*********************************************************************
 *	SetCalendarInfoW				(KERNEL32.@)
 *
 *
 */
int WINAPI	SetCalendarInfoW(LCID Locale, CALID Calendar, CALTYPE CalType, LPCWSTR lpCalData)
{
    FIXME("(%08x,%08x,%08x,%s): stub\n",
	  Locale, Calendar, CalType, debugstr_w(lpCalData));
    return 0;
}
