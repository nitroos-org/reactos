/*
 * Copyright 2013 Dmitry Timoshkov
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

#include <stdarg.h>

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "initguid.h"
#include "objbase.h"
#include "xmllite.h"
#include "taskschd.h"
#include "winsvc.h"
#include "schrpc.h"
#include "taskschd_private.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(taskschd);

typedef struct {
    IRepetitionPattern IRepetitionPattern_iface;
    LONG ref;
    BSTR interval;
    BSTR duration;
    VARIANT_BOOL stop_at_duration_end;
} RepetitionPattern;

static inline RepetitionPattern *impl_from_IRepetitionPattern(IRepetitionPattern *iface)
{
    return CONTAINING_RECORD(iface, RepetitionPattern, IRepetitionPattern_iface);
}

static HRESULT WINAPI RepetitionPattern_QueryInterface(IRepetitionPattern *iface, REFIID riid, void **ppv)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);

    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppv);

    if (IsEqualGUID(&IID_IUnknown, riid) ||
        IsEqualGUID(&IID_IDispatch, riid) ||
        IsEqualGUID(&IID_IRepetitionPattern, riid))
    {
        *ppv = &This->IRepetitionPattern_iface;
    }
    else
    {
        FIXME("unsupported riid %s\n", debugstr_guid(riid));
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown *)*ppv);
    return S_OK;
}

static ULONG WINAPI RepetitionPattern_AddRef(IRepetitionPattern *iface)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);
    LONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    return ref;
}

static ULONG WINAPI RepetitionPattern_Release(IRepetitionPattern *iface)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        SysFreeString(This->interval);
        SysFreeString(This->duration);
        free(This);
    }

    return ref;
}

static HRESULT WINAPI RepetitionPattern_GetTypeInfoCount(IRepetitionPattern *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI RepetitionPattern_GetTypeInfo(IRepetitionPattern *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IRepetitionPattern, index, lcid, info);
}

static HRESULT WINAPI RepetitionPattern_GetIDsOfNames(IRepetitionPattern *iface, REFIID riid, LPOLESTR *names,
                                                       UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IRepetitionPattern, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI RepetitionPattern_Invoke(IRepetitionPattern *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                                DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IRepetitionPattern, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI RepetitionPattern_get_Interval(IRepetitionPattern *iface, BSTR *interval)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);

    TRACE("(%p)->(%p)\n", This, interval);

    if (!interval) return E_POINTER;

    if (This->interval)
    {
        *interval = SysAllocString(This->interval);
        if (!*interval) return E_OUTOFMEMORY;
    }
    else
        *interval = NULL;

    return S_OK;
}

static HRESULT WINAPI RepetitionPattern_put_Interval(IRepetitionPattern *iface, BSTR interval)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);
    BSTR str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(interval));

    if (interval)
    {
        str = SysAllocString(interval);
        if (!str) return E_OUTOFMEMORY;
    }

    SysFreeString(This->interval);
    This->interval = str;
    return S_OK;
}

static HRESULT WINAPI RepetitionPattern_get_Duration(IRepetitionPattern *iface, BSTR *duration)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);

    TRACE("(%p)->(%p)\n", This, duration);

    if (!duration) return E_POINTER;

    if (This->duration)
    {
        *duration = SysAllocString(This->duration);
        if (!*duration) return E_OUTOFMEMORY;
    }
    else
        *duration = NULL;

    return S_OK;
}

static HRESULT WINAPI RepetitionPattern_put_Duration(IRepetitionPattern *iface, BSTR duration)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);
    BSTR str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(duration));

    if (duration)
    {
        str = SysAllocString(duration);
        if (!str) return E_OUTOFMEMORY;
    }

    SysFreeString(This->duration);
    This->duration = str;
    return S_OK;
}

static HRESULT WINAPI RepetitionPattern_get_StopAtDurationEnd(IRepetitionPattern *iface, VARIANT_BOOL *stop)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);

    TRACE("(%p)->(%p)\n", This, stop);

    if (!stop) return E_POINTER;

    *stop = This->stop_at_duration_end;
    return S_OK;
}

static HRESULT WINAPI RepetitionPattern_put_StopAtDurationEnd(IRepetitionPattern *iface, VARIANT_BOOL stop)
{
    RepetitionPattern *This = impl_from_IRepetitionPattern(iface);

    TRACE("(%p)->(%x)\n", This, stop);

    This->stop_at_duration_end = stop;
    return S_OK;
}

static const IRepetitionPatternVtbl RepetitionPattern_vtbl = {
    RepetitionPattern_QueryInterface,
    RepetitionPattern_AddRef,
    RepetitionPattern_Release,
    RepetitionPattern_GetTypeInfoCount,
    RepetitionPattern_GetTypeInfo,
    RepetitionPattern_GetIDsOfNames,
    RepetitionPattern_Invoke,
    RepetitionPattern_get_Interval,
    RepetitionPattern_put_Interval,
    RepetitionPattern_get_Duration,
    RepetitionPattern_put_Duration,
    RepetitionPattern_get_StopAtDurationEnd,
    RepetitionPattern_put_StopAtDurationEnd
};

static HRESULT RepetitionPattern_create(IRepetitionPattern **out)
{
    RepetitionPattern *pattern;

    pattern = malloc(sizeof(*pattern));
    if (!pattern) return E_OUTOFMEMORY;

    pattern->IRepetitionPattern_iface.lpVtbl = &RepetitionPattern_vtbl;
    pattern->ref = 1;
    pattern->interval = NULL;
    pattern->duration = NULL;
    pattern->stop_at_duration_end = VARIANT_FALSE;

    *out = &pattern->IRepetitionPattern_iface;
    return S_OK;
}

/* a trigger keeps the pattern it hands out, so that changes made through it stick */
static HRESULT get_repetition(IRepetitionPattern **stored, IRepetitionPattern **repeat)
{
    HRESULT hr;

    if (!repeat) return E_POINTER;
    if (!*stored && (hr = RepetitionPattern_create(stored)) != S_OK) return hr;

    IRepetitionPattern_AddRef(*stored);
    *repeat = *stored;
    return S_OK;
}

static HRESULT put_repetition(IRepetitionPattern **stored, IRepetitionPattern *repeat)
{
    if (!repeat) return E_POINTER;

    IRepetitionPattern_AddRef(repeat);
    if (*stored) IRepetitionPattern_Release(*stored);
    *stored = repeat;
    return S_OK;
}

/* The triggers that share one implementation: daily, weekly, monthly and monthly day-of-week
 * (all four are a CalendarTrigger in the task XML), and the idle, event and session state
 * change triggers.  One object holds the fields of all of them and its type picks the
 * interface (and so the vtable) it presents; a trigger read from a CalendarTrigger element is
 * a daily one until its ScheduleByXxx child says otherwise (trigger_set_calendar_type).
 * Whatever the XML of such a trigger holds that the object does not model (the event trigger's
 * ValueQueries and occurrence settings, for one) is kept as text in 'extra' and written back, so
 * that a task read and registered again is not changed. */
typedef struct
{
    ITrigger ITrigger_iface;    /* the interface pointer of every interface of the object */
    LONG ref;
    TASK_TRIGGER_TYPE2 type;
    BOOL enabled;
    WCHAR *id;
    WCHAR *start_boundary;
    WCHAR *end_boundary;
    WCHAR *execution_time_limit;
    WCHAR *random_delay;
    WCHAR *delay;               /* event, session state change */
    WCHAR *user_id;             /* session state change */
    WCHAR *subscription;        /* event */
    WCHAR *extra;               /* XML of the elements that are not modelled */
    IRepetitionPattern *repetition;
    short days_interval;        /* daily */
    short days_of_week;         /* weekly, monthly day-of-week: bit 0 = Sunday */
    short weeks_interval;       /* weekly */
    short months;               /* monthly, monthly day-of-week: bit 0 = January */
    short weeks;                /* monthly day-of-week: bit 0 = first week */
    LONG days_of_month;         /* monthly: bit 0 = day 1 */
    BOOL run_last;              /* monthly: the last day, monthly day-of-week: the last week */
    LONG state_change;          /* session state change */
} SchedTrigger;

static const IDailyTriggerVtbl DailyTrigger_vtbl;
static const IWeeklyTriggerVtbl WeeklyTrigger_vtbl;
static const IMonthlyTriggerVtbl MonthlyTrigger_vtbl;
static const IMonthlyDOWTriggerVtbl MonthlyDOWTrigger_vtbl;
static const IIdleTriggerVtbl IdleTrigger_vtbl;
static const IEventTriggerVtbl EventTrigger_vtbl;
static const ISessionStateChangeTriggerVtbl SessionStateChangeTrigger_vtbl;

static const IID *trigger_iid(TASK_TRIGGER_TYPE2 type)
{
    switch (type)
    {
    case TASK_TRIGGER_WEEKLY: return &IID_IWeeklyTrigger;
    case TASK_TRIGGER_MONTHLY: return &IID_IMonthlyTrigger;
    case TASK_TRIGGER_MONTHLYDOW: return &IID_IMonthlyDOWTrigger;
    case TASK_TRIGGER_IDLE: return &IID_IIdleTrigger;
    case TASK_TRIGGER_EVENT: return &IID_IEventTrigger;
    case TASK_TRIGGER_SESSION_STATE_CHANGE: return &IID_ISessionStateChangeTrigger;
    default: return &IID_IDailyTrigger;
    }
}

static const void *trigger_vtbl(TASK_TRIGGER_TYPE2 type)
{
    switch (type)
    {
    case TASK_TRIGGER_WEEKLY: return &WeeklyTrigger_vtbl;
    case TASK_TRIGGER_MONTHLY: return &MonthlyTrigger_vtbl;
    case TASK_TRIGGER_MONTHLYDOW: return &MonthlyDOWTrigger_vtbl;
    case TASK_TRIGGER_IDLE: return &IdleTrigger_vtbl;
    case TASK_TRIGGER_EVENT: return &EventTrigger_vtbl;
    case TASK_TRIGGER_SESSION_STATE_CHANGE: return &SessionStateChangeTrigger_vtbl;
    default: return &DailyTrigger_vtbl;
    }
}

static BOOL is_sched_trigger(ITrigger *trigger)
{
    return trigger->lpVtbl == trigger_vtbl(TASK_TRIGGER_DAILY) ||
           trigger->lpVtbl == trigger_vtbl(TASK_TRIGGER_WEEKLY) ||
           trigger->lpVtbl == trigger_vtbl(TASK_TRIGGER_MONTHLY) ||
           trigger->lpVtbl == trigger_vtbl(TASK_TRIGGER_MONTHLYDOW) ||
           trigger->lpVtbl == trigger_vtbl(TASK_TRIGGER_IDLE) ||
           trigger->lpVtbl == trigger_vtbl(TASK_TRIGGER_EVENT) ||
           trigger->lpVtbl == trigger_vtbl(TASK_TRIGGER_SESSION_STATE_CHANGE);
}

/* the defaults are those of a trigger Windows creates */
static void trigger_set_defaults(SchedTrigger *This)
{
    This->days_interval = 1;
    This->weeks_interval = 1;
    switch (This->type)
    {
    case TASK_TRIGGER_MONTHLY: This->months = 0xfff; break;
    case TASK_TRIGGER_MONTHLYDOW: This->days_of_week = 1; This->weeks = 1; This->months = 1; break;
    default: break;
    }
}

static HRESULT SchedTrigger_create(TASK_TRIGGER_TYPE2 type, ITrigger **trigger)
{
    SchedTrigger *This = calloc(1, sizeof(*This));

    if (!This) return E_OUTOFMEMORY;

    This->ITrigger_iface.lpVtbl = trigger_vtbl(type);
    This->ref = 1;
    This->type = type;
    This->enabled = TRUE;
    trigger_set_defaults(This);

    *trigger = &This->ITrigger_iface;
    return S_OK;
}

/* a daily trigger that a CalendarTrigger element turned out to be a weekly, monthly or monthly
 * day-of-week one: the same object, so everything read so far is kept */
static void trigger_set_calendar_type(ITrigger *trigger, TASK_TRIGGER_TYPE2 type)
{
    SchedTrigger *This = CONTAINING_RECORD(trigger, SchedTrigger, ITrigger_iface);

    This->type = type;
    This->ITrigger_iface.lpVtbl = trigger_vtbl(type);
    This->days_interval = 1;
    This->weeks_interval = 1;
    This->days_of_week = 0;
    This->months = 0;
    This->weeks = 0;
    This->days_of_month = 0;
    This->run_last = FALSE;
}

/* text of an element that the trigger has no property for, written back as it came */
static HRESULT trigger_add_extra(ITrigger *trigger, const WCHAR *xml)
{
    SchedTrigger *This = CONTAINING_RECORD(trigger, SchedTrigger, ITrigger_iface);
    size_t old = This->extra ? wcslen(This->extra) : 0;
    WCHAR *str = realloc(This->extra, (old + wcslen(xml) + 1) * sizeof(WCHAR));

    if (!str) return E_OUTOFMEMORY;
    wcscpy(str + old, xml);
    This->extra = str;
    return S_OK;
}

static const WCHAR *trigger_get_extra(ITrigger *trigger)
{
    return CONTAINING_RECORD(trigger, SchedTrigger, ITrigger_iface)->extra;
}

static HRESULT trigger_get_string(const WCHAR *value, BSTR *out)
{
    if (!out) return E_POINTER;
    if (!value) *out = NULL;
    else if (!(*out = SysAllocString(value))) return E_OUTOFMEMORY;
    return S_OK;
}

static HRESULT trigger_put_string(WCHAR **field, BSTR value)
{
    WCHAR *str = NULL;

    if (value && !(str = wcsdup(value))) return E_OUTOFMEMORY;
    free(*field);
    *field = str;
    return S_OK;
}

static HRESULT trigger_QueryInterface(SchedTrigger *This, REFIID riid, void **ppv)
{
    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppv);

    if (IsEqualGUID(&IID_IUnknown, riid) || IsEqualGUID(&IID_IDispatch, riid) ||
        IsEqualGUID(&IID_ITrigger, riid) || IsEqualGUID(trigger_iid(This->type), riid))
    {
        *ppv = &This->ITrigger_iface;
        IUnknown_AddRef((IUnknown *)*ppv);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG trigger_AddRef(SchedTrigger *This)
{
    LONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);
    return ref;
}

static ULONG trigger_Release(SchedTrigger *This)
{
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);
    if (!ref)
    {
        free(This->id);
        free(This->start_boundary);
        free(This->end_boundary);
        free(This->execution_time_limit);
        free(This->random_delay);
        free(This->delay);
        free(This->user_id);
        free(This->subscription);
        free(This->extra);
        if (This->repetition) IRepetitionPattern_Release(This->repetition);
        free(This);
    }
    return ref;
}

/* the methods of ITrigger, for every interface that derives from it */
#define TRIGGER_METHODS(Cls, Iface) \
static HRESULT WINAPI Cls##_QueryInterface(Iface *iface, REFIID riid, void **ppv) \
{ return trigger_QueryInterface((SchedTrigger *)iface, riid, ppv); } \
static ULONG WINAPI Cls##_AddRef(Iface *iface) { return trigger_AddRef((SchedTrigger *)iface); } \
static ULONG WINAPI Cls##_Release(Iface *iface) { return trigger_Release((SchedTrigger *)iface); } \
static HRESULT WINAPI Cls##_GetTypeInfoCount(Iface *iface, UINT *count) { return taskschd_GetTypeInfoCount(count); } \
static HRESULT WINAPI Cls##_GetTypeInfo(Iface *iface, UINT index, LCID lcid, ITypeInfo **info) \
{ return taskschd_GetTypeInfo(trigger_iid(((SchedTrigger *)iface)->type), index, lcid, info); } \
static HRESULT WINAPI Cls##_GetIDsOfNames(Iface *iface, REFIID riid, LPOLESTR *names, UINT count, LCID lcid, \
                                          DISPID *dispid) \
{ return taskschd_GetIDsOfNames(trigger_iid(((SchedTrigger *)iface)->type), riid, names, count, lcid, dispid); } \
static HRESULT WINAPI Cls##_Invoke(Iface *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags, \
                                   DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr) \
{ return taskschd_Invoke(trigger_iid(((SchedTrigger *)iface)->type), iface, dispid, riid, lcid, flags, params, \
                         result, excepinfo, argerr); } \
static HRESULT WINAPI Cls##_get_Type(Iface *iface, TASK_TRIGGER_TYPE2 *type) \
{ if (!type) return E_POINTER; *type = ((SchedTrigger *)iface)->type; return S_OK; } \
static HRESULT WINAPI Cls##_get_Id(Iface *iface, BSTR *id) \
{ return trigger_get_string(((SchedTrigger *)iface)->id, id); } \
static HRESULT WINAPI Cls##_put_Id(Iface *iface, BSTR id) \
{ return trigger_put_string(&((SchedTrigger *)iface)->id, id); } \
static HRESULT WINAPI Cls##_get_Repetition(Iface *iface, IRepetitionPattern **repeat) \
{ return get_repetition(&((SchedTrigger *)iface)->repetition, repeat); } \
static HRESULT WINAPI Cls##_put_Repetition(Iface *iface, IRepetitionPattern *repeat) \
{ return put_repetition(&((SchedTrigger *)iface)->repetition, repeat); } \
static HRESULT WINAPI Cls##_get_ExecutionTimeLimit(Iface *iface, BSTR *limit) \
{ return trigger_get_string(((SchedTrigger *)iface)->execution_time_limit, limit); } \
static HRESULT WINAPI Cls##_put_ExecutionTimeLimit(Iface *iface, BSTR limit) \
{ return trigger_put_string(&((SchedTrigger *)iface)->execution_time_limit, limit); } \
static HRESULT WINAPI Cls##_get_StartBoundary(Iface *iface, BSTR *start) \
{ return trigger_get_string(((SchedTrigger *)iface)->start_boundary, start); } \
static HRESULT WINAPI Cls##_put_StartBoundary(Iface *iface, BSTR start) \
{ return trigger_put_string(&((SchedTrigger *)iface)->start_boundary, start); } \
static HRESULT WINAPI Cls##_get_EndBoundary(Iface *iface, BSTR *end) \
{ return trigger_get_string(((SchedTrigger *)iface)->end_boundary, end); } \
static HRESULT WINAPI Cls##_put_EndBoundary(Iface *iface, BSTR end) \
{ return trigger_put_string(&((SchedTrigger *)iface)->end_boundary, end); } \
static HRESULT WINAPI Cls##_get_Enabled(Iface *iface, VARIANT_BOOL *enabled) \
{ if (!enabled) return E_POINTER; *enabled = ((SchedTrigger *)iface)->enabled ? VARIANT_TRUE : VARIANT_FALSE; \
  return S_OK; } \
static HRESULT WINAPI Cls##_put_Enabled(Iface *iface, VARIANT_BOOL enabled) \
{ ((SchedTrigger *)iface)->enabled = !!enabled; return S_OK; }

#define TRIGGER_VTBL_HEAD(Cls) \
    Cls##_QueryInterface, Cls##_AddRef, Cls##_Release, Cls##_GetTypeInfoCount, Cls##_GetTypeInfo, \
    Cls##_GetIDsOfNames, Cls##_Invoke, Cls##_get_Type, Cls##_get_Id, Cls##_put_Id, Cls##_get_Repetition, \
    Cls##_put_Repetition, Cls##_get_ExecutionTimeLimit, Cls##_put_ExecutionTimeLimit, Cls##_get_StartBoundary, \
    Cls##_put_StartBoundary, Cls##_get_EndBoundary, Cls##_put_EndBoundary, Cls##_get_Enabled, Cls##_put_Enabled

#define TRIGGER_RANDOM_DELAY(Cls, Iface) \
static HRESULT WINAPI Cls##_get_RandomDelay(Iface *iface, BSTR *delay) \
{ return trigger_get_string(((SchedTrigger *)iface)->random_delay, delay); } \
static HRESULT WINAPI Cls##_put_RandomDelay(Iface *iface, BSTR delay) \
{ return trigger_put_string(&((SchedTrigger *)iface)->random_delay, delay); }

/* a short property with a range */
static HRESULT trigger_put_short(short *field, short value, short min, short max)
{
    if (value < min || value > max) return E_INVALIDARG;
    *field = value;
    return S_OK;
}

static HRESULT trigger_get_short(short value, short *out)
{
    if (!out) return E_POINTER;
    *out = value;
    return S_OK;
}

/* daily */

TRIGGER_METHODS(DailyTrigger, IDailyTrigger)
TRIGGER_RANDOM_DELAY(DailyTrigger, IDailyTrigger)

static HRESULT WINAPI DailyTrigger_get_DaysInterval(IDailyTrigger *iface, short *days)
{
    return trigger_get_short(((SchedTrigger *)iface)->days_interval, days);
}

static HRESULT WINAPI DailyTrigger_put_DaysInterval(IDailyTrigger *iface, short days)
{
    return trigger_put_short(&((SchedTrigger *)iface)->days_interval, days, 1, 32767);
}

static const IDailyTriggerVtbl DailyTrigger_vtbl =
{
    TRIGGER_VTBL_HEAD(DailyTrigger),
    DailyTrigger_get_DaysInterval,
    DailyTrigger_put_DaysInterval,
    DailyTrigger_get_RandomDelay,
    DailyTrigger_put_RandomDelay
};

/* weekly */

TRIGGER_METHODS(WeeklyTrigger, IWeeklyTrigger)
TRIGGER_RANDOM_DELAY(WeeklyTrigger, IWeeklyTrigger)

static HRESULT WINAPI WeeklyTrigger_get_DaysOfWeek(IWeeklyTrigger *iface, short *days)
{
    return trigger_get_short(((SchedTrigger *)iface)->days_of_week, days);
}

static HRESULT WINAPI WeeklyTrigger_put_DaysOfWeek(IWeeklyTrigger *iface, short days)
{
    return trigger_put_short(&((SchedTrigger *)iface)->days_of_week, days, 0, 0x7f);
}

static HRESULT WINAPI WeeklyTrigger_get_WeeksInterval(IWeeklyTrigger *iface, short *weeks)
{
    return trigger_get_short(((SchedTrigger *)iface)->weeks_interval, weeks);
}

static HRESULT WINAPI WeeklyTrigger_put_WeeksInterval(IWeeklyTrigger *iface, short weeks)
{
    return trigger_put_short(&((SchedTrigger *)iface)->weeks_interval, weeks, 1, 52);
}

static const IWeeklyTriggerVtbl WeeklyTrigger_vtbl =
{
    TRIGGER_VTBL_HEAD(WeeklyTrigger),
    WeeklyTrigger_get_DaysOfWeek,
    WeeklyTrigger_put_DaysOfWeek,
    WeeklyTrigger_get_WeeksInterval,
    WeeklyTrigger_put_WeeksInterval,
    WeeklyTrigger_get_RandomDelay,
    WeeklyTrigger_put_RandomDelay
};

/* monthly */

TRIGGER_METHODS(MonthlyTrigger, IMonthlyTrigger)
TRIGGER_RANDOM_DELAY(MonthlyTrigger, IMonthlyTrigger)

static HRESULT WINAPI MonthlyTrigger_get_DaysOfMonth(IMonthlyTrigger *iface, LONG *days)
{
    if (!days) return E_POINTER;
    *days = ((SchedTrigger *)iface)->days_of_month;
    return S_OK;
}

static HRESULT WINAPI MonthlyTrigger_put_DaysOfMonth(IMonthlyTrigger *iface, LONG days)
{
    if (days < 0) return E_INVALIDARG;
    ((SchedTrigger *)iface)->days_of_month = days;
    return S_OK;
}

static HRESULT WINAPI MonthlyTrigger_get_MonthsOfYear(IMonthlyTrigger *iface, short *months)
{
    return trigger_get_short(((SchedTrigger *)iface)->months, months);
}

static HRESULT WINAPI MonthlyTrigger_put_MonthsOfYear(IMonthlyTrigger *iface, short months)
{
    return trigger_put_short(&((SchedTrigger *)iface)->months, months, 0, 0xfff);
}

static HRESULT WINAPI MonthlyTrigger_get_RunOnLastDayOfMonth(IMonthlyTrigger *iface, VARIANT_BOOL *last)
{
    if (!last) return E_POINTER;
    *last = ((SchedTrigger *)iface)->run_last ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI MonthlyTrigger_put_RunOnLastDayOfMonth(IMonthlyTrigger *iface, VARIANT_BOOL last)
{
    ((SchedTrigger *)iface)->run_last = !!last;
    return S_OK;
}

static const IMonthlyTriggerVtbl MonthlyTrigger_vtbl =
{
    TRIGGER_VTBL_HEAD(MonthlyTrigger),
    MonthlyTrigger_get_DaysOfMonth,
    MonthlyTrigger_put_DaysOfMonth,
    MonthlyTrigger_get_MonthsOfYear,
    MonthlyTrigger_put_MonthsOfYear,
    MonthlyTrigger_get_RunOnLastDayOfMonth,
    MonthlyTrigger_put_RunOnLastDayOfMonth,
    MonthlyTrigger_get_RandomDelay,
    MonthlyTrigger_put_RandomDelay
};

/* monthly day-of-week */

TRIGGER_METHODS(MonthlyDOWTrigger, IMonthlyDOWTrigger)
TRIGGER_RANDOM_DELAY(MonthlyDOWTrigger, IMonthlyDOWTrigger)

static HRESULT WINAPI MonthlyDOWTrigger_get_DaysOfWeek(IMonthlyDOWTrigger *iface, short *days)
{
    return trigger_get_short(((SchedTrigger *)iface)->days_of_week, days);
}

static HRESULT WINAPI MonthlyDOWTrigger_put_DaysOfWeek(IMonthlyDOWTrigger *iface, short days)
{
    return trigger_put_short(&((SchedTrigger *)iface)->days_of_week, days, 0, 0x7f);
}

static HRESULT WINAPI MonthlyDOWTrigger_get_WeeksOfMonth(IMonthlyDOWTrigger *iface, short *weeks)
{
    return trigger_get_short(((SchedTrigger *)iface)->weeks, weeks);
}

static HRESULT WINAPI MonthlyDOWTrigger_put_WeeksOfMonth(IMonthlyDOWTrigger *iface, short weeks)
{
    return trigger_put_short(&((SchedTrigger *)iface)->weeks, weeks, 0, 0xf);
}

static HRESULT WINAPI MonthlyDOWTrigger_get_MonthsOfYear(IMonthlyDOWTrigger *iface, short *months)
{
    return trigger_get_short(((SchedTrigger *)iface)->months, months);
}

static HRESULT WINAPI MonthlyDOWTrigger_put_MonthsOfYear(IMonthlyDOWTrigger *iface, short months)
{
    return trigger_put_short(&((SchedTrigger *)iface)->months, months, 0, 0xfff);
}

static HRESULT WINAPI MonthlyDOWTrigger_get_RunOnLastWeekOfMonth(IMonthlyDOWTrigger *iface, VARIANT_BOOL *last)
{
    if (!last) return E_POINTER;
    *last = ((SchedTrigger *)iface)->run_last ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI MonthlyDOWTrigger_put_RunOnLastWeekOfMonth(IMonthlyDOWTrigger *iface, VARIANT_BOOL last)
{
    ((SchedTrigger *)iface)->run_last = !!last;
    return S_OK;
}

static const IMonthlyDOWTriggerVtbl MonthlyDOWTrigger_vtbl =
{
    TRIGGER_VTBL_HEAD(MonthlyDOWTrigger),
    MonthlyDOWTrigger_get_DaysOfWeek,
    MonthlyDOWTrigger_put_DaysOfWeek,
    MonthlyDOWTrigger_get_WeeksOfMonth,
    MonthlyDOWTrigger_put_WeeksOfMonth,
    MonthlyDOWTrigger_get_MonthsOfYear,
    MonthlyDOWTrigger_put_MonthsOfYear,
    MonthlyDOWTrigger_get_RunOnLastWeekOfMonth,
    MonthlyDOWTrigger_put_RunOnLastWeekOfMonth,
    MonthlyDOWTrigger_get_RandomDelay,
    MonthlyDOWTrigger_put_RandomDelay
};

/* idle: nothing but what every trigger has */

TRIGGER_METHODS(IdleTrigger, IIdleTrigger)

static const IIdleTriggerVtbl IdleTrigger_vtbl =
{
    TRIGGER_VTBL_HEAD(IdleTrigger)
};

/* event */

TRIGGER_METHODS(EventTrigger, IEventTrigger)

static HRESULT WINAPI EventTrigger_get_Subscription(IEventTrigger *iface, BSTR *query)
{
    return trigger_get_string(((SchedTrigger *)iface)->subscription, query);
}

static HRESULT WINAPI EventTrigger_put_Subscription(IEventTrigger *iface, BSTR query)
{
    return trigger_put_string(&((SchedTrigger *)iface)->subscription, query);
}

static HRESULT WINAPI EventTrigger_get_Delay(IEventTrigger *iface, BSTR *delay)
{
    return trigger_get_string(((SchedTrigger *)iface)->delay, delay);
}

static HRESULT WINAPI EventTrigger_put_Delay(IEventTrigger *iface, BSTR delay)
{
    return trigger_put_string(&((SchedTrigger *)iface)->delay, delay);
}

static HRESULT WINAPI EventTrigger_get_ValueQueries(IEventTrigger *iface, ITaskNamedValueCollection **queries)
{
    FIXME("(%p)->(%p) the value queries are kept in the XML only\n", iface, queries);
    return E_NOTIMPL;
}

static HRESULT WINAPI EventTrigger_put_ValueQueries(IEventTrigger *iface, ITaskNamedValueCollection *queries)
{
    FIXME("(%p)->(%p)\n", iface, queries);
    return E_NOTIMPL;
}

static const IEventTriggerVtbl EventTrigger_vtbl =
{
    TRIGGER_VTBL_HEAD(EventTrigger),
    EventTrigger_get_Subscription,
    EventTrigger_put_Subscription,
    EventTrigger_get_Delay,
    EventTrigger_put_Delay,
    EventTrigger_get_ValueQueries,
    EventTrigger_put_ValueQueries
};

/* session state change */

TRIGGER_METHODS(SessionStateChangeTrigger, ISessionStateChangeTrigger)

static HRESULT WINAPI SessionStateChangeTrigger_get_Delay(ISessionStateChangeTrigger *iface, BSTR *delay)
{
    return trigger_get_string(((SchedTrigger *)iface)->delay, delay);
}

static HRESULT WINAPI SessionStateChangeTrigger_put_Delay(ISessionStateChangeTrigger *iface, BSTR delay)
{
    return trigger_put_string(&((SchedTrigger *)iface)->delay, delay);
}

static HRESULT WINAPI SessionStateChangeTrigger_get_UserId(ISessionStateChangeTrigger *iface, BSTR *user)
{
    return trigger_get_string(((SchedTrigger *)iface)->user_id, user);
}

static HRESULT WINAPI SessionStateChangeTrigger_put_UserId(ISessionStateChangeTrigger *iface, BSTR user)
{
    return trigger_put_string(&((SchedTrigger *)iface)->user_id, user);
}

static HRESULT WINAPI SessionStateChangeTrigger_get_StateChange(ISessionStateChangeTrigger *iface,
                                                                TASK_SESSION_STATE_CHANGE_TYPE *type)
{
    if (!type) return E_POINTER;
    *type = ((SchedTrigger *)iface)->state_change;
    return S_OK;
}

static HRESULT WINAPI SessionStateChangeTrigger_put_StateChange(ISessionStateChangeTrigger *iface,
                                                                TASK_SESSION_STATE_CHANGE_TYPE type)
{
    if (type != TASK_CONSOLE_CONNECT && type != TASK_CONSOLE_DISCONNECT && type != TASK_REMOTE_CONNECT &&
        type != TASK_REMOTE_DISCONNECT && type != TASK_SESSION_LOCK && type != TASK_SESSION_UNLOCK)
        return E_INVALIDARG;
    ((SchedTrigger *)iface)->state_change = type;
    return S_OK;
}

static const ISessionStateChangeTriggerVtbl SessionStateChangeTrigger_vtbl =
{
    TRIGGER_VTBL_HEAD(SessionStateChangeTrigger),
    SessionStateChangeTrigger_get_Delay,
    SessionStateChangeTrigger_put_Delay,
    SessionStateChangeTrigger_get_UserId,
    SessionStateChangeTrigger_put_UserId,
    SessionStateChangeTrigger_get_StateChange,
    SessionStateChangeTrigger_put_StateChange
};

typedef struct {
    IRegistrationTrigger IRegistrationTrigger_iface;
    BOOL enabled;
    LONG ref;
} RegistrationTrigger;

static inline RegistrationTrigger *impl_from_IRegistrationTrigger(IRegistrationTrigger *iface)
{
    return CONTAINING_RECORD(iface, RegistrationTrigger, IRegistrationTrigger_iface);
}

static HRESULT WINAPI RegistrationTrigger_QueryInterface(IRegistrationTrigger *iface, REFIID riid, void **ppv)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);

    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppv);

    if(IsEqualGUID(&IID_IUnknown, riid) ||
       IsEqualGUID(&IID_IDispatch, riid) ||
       IsEqualGUID(&IID_ITrigger, riid) ||
       IsEqualGUID(&IID_IRegistrationTrigger, riid))
    {
        *ppv = &This->IRegistrationTrigger_iface;
    }
    else
    {
        FIXME("unsupported riid %s\n", debugstr_guid(riid));
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*ppv);
    return S_OK;
}

static ULONG WINAPI RegistrationTrigger_AddRef(IRegistrationTrigger *iface)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    LONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    return ref;
}

static ULONG WINAPI RegistrationTrigger_Release(IRegistrationTrigger *iface)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    if(!ref)
    {
        TRACE("destroying %p\n", iface);
        free(This);
    }

    return ref;
}

static HRESULT WINAPI RegistrationTrigger_GetTypeInfoCount(IRegistrationTrigger *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI RegistrationTrigger_GetTypeInfo(IRegistrationTrigger *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IRegistrationTrigger, index, lcid, info);
}

static HRESULT WINAPI RegistrationTrigger_GetIDsOfNames(IRegistrationTrigger *iface, REFIID riid, LPOLESTR *names,
                                            UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IRegistrationTrigger, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI RegistrationTrigger_Invoke(IRegistrationTrigger *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                     DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IRegistrationTrigger, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI RegistrationTrigger_get_Type(IRegistrationTrigger *iface, TASK_TRIGGER_TYPE2 *type)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);

    TRACE("(%p)->(%p)\n", This, type);

    if (!type) return E_POINTER;

    *type = TASK_TRIGGER_REGISTRATION;
    return S_OK;
}

static HRESULT WINAPI RegistrationTrigger_get_Id(IRegistrationTrigger *iface, BSTR *id)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%p)\n", This, id);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_put_Id(IRegistrationTrigger *iface, BSTR id)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%s)\n", This, debugstr_w(id));
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_get_Repetition(IRegistrationTrigger *iface, IRepetitionPattern **repeat)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);

    TRACE("(%p)->(%p)\n", This, repeat);

    if (!repeat) return E_POINTER;

    return RepetitionPattern_create(repeat);
}

static HRESULT WINAPI RegistrationTrigger_put_Repetition(IRegistrationTrigger *iface, IRepetitionPattern *repeat)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%p)\n", This, repeat);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_get_ExecutionTimeLimit(IRegistrationTrigger *iface, BSTR *limit)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%p)\n", This, limit);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_put_ExecutionTimeLimit(IRegistrationTrigger *iface, BSTR limit)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%s)\n", This, debugstr_w(limit));
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_get_StartBoundary(IRegistrationTrigger *iface, BSTR *start)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%p)\n", This, start);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_put_StartBoundary(IRegistrationTrigger *iface, BSTR start)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%s)\n", This, debugstr_w(start));
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_get_EndBoundary(IRegistrationTrigger *iface, BSTR *end)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%p)\n", This, end);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_put_EndBoundary(IRegistrationTrigger *iface, BSTR end)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%s)\n", This, debugstr_w(end));
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_get_Enabled(IRegistrationTrigger *iface, VARIANT_BOOL *enabled)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);

    TRACE("(%p)->(%p)\n", This, enabled);

    if (!enabled) return E_POINTER;

    *enabled = This->enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI RegistrationTrigger_put_Enabled(IRegistrationTrigger *iface, VARIANT_BOOL enabled)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);

    TRACE("(%p)->(%x)\n", This, enabled);

    This->enabled = !!enabled;
    return S_OK;
}

static HRESULT WINAPI RegistrationTrigger_get_Delay(IRegistrationTrigger *iface, BSTR *pDelay)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%p)\n", This, pDelay);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationTrigger_put_Delay(IRegistrationTrigger *iface, BSTR delay)
{
    RegistrationTrigger *This = impl_from_IRegistrationTrigger(iface);
    FIXME("(%p)->(%s)\n", This, debugstr_w(delay));
    return E_NOTIMPL;
}

static const IRegistrationTriggerVtbl RegistrationTrigger_vtbl = {
    RegistrationTrigger_QueryInterface,
    RegistrationTrigger_AddRef,
    RegistrationTrigger_Release,
    RegistrationTrigger_GetTypeInfoCount,
    RegistrationTrigger_GetTypeInfo,
    RegistrationTrigger_GetIDsOfNames,
    RegistrationTrigger_Invoke,
    RegistrationTrigger_get_Type,
    RegistrationTrigger_get_Id,
    RegistrationTrigger_put_Id,
    RegistrationTrigger_get_Repetition,
    RegistrationTrigger_put_Repetition,
    RegistrationTrigger_get_ExecutionTimeLimit,
    RegistrationTrigger_put_ExecutionTimeLimit,
    RegistrationTrigger_get_StartBoundary,
    RegistrationTrigger_put_StartBoundary,
    RegistrationTrigger_get_EndBoundary,
    RegistrationTrigger_put_EndBoundary,
    RegistrationTrigger_get_Enabled,
    RegistrationTrigger_put_Enabled,
    RegistrationTrigger_get_Delay,
    RegistrationTrigger_put_Delay
};

static HRESULT RegistrationTrigger_create(ITrigger **trigger)
{
    RegistrationTrigger *registration_trigger;

    registration_trigger = malloc(sizeof(*registration_trigger));
    if (!registration_trigger)
        return E_OUTOFMEMORY;

    registration_trigger->IRegistrationTrigger_iface.lpVtbl = &RegistrationTrigger_vtbl;
    registration_trigger->ref = 1;
    registration_trigger->enabled = TRUE;

    *trigger = (ITrigger*)&registration_trigger->IRegistrationTrigger_iface;
    return S_OK;
}

typedef struct {
    ILogonTrigger ILogonTrigger_iface;
    BOOL enabled;
    LONG ref;
    WCHAR *user_id;
    WCHAR *id;
    WCHAR *execution_time_limit;
    WCHAR *start_boundary;
    WCHAR *end_boundary;
    WCHAR *delay;
    IRepetitionPattern *repetition;
} LogonTrigger;

static inline LogonTrigger *impl_from_ILogonTrigger(ILogonTrigger *iface)
{
    return CONTAINING_RECORD(iface, LogonTrigger, ILogonTrigger_iface);
}

static HRESULT WINAPI LogonTrigger_QueryInterface(ILogonTrigger *iface, REFIID riid, void **ppv)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppv);

    if(IsEqualGUID(&IID_IUnknown, riid) ||
       IsEqualGUID(&IID_IDispatch, riid) ||
       IsEqualGUID(&IID_ITrigger, riid) ||
       IsEqualGUID(&IID_ILogonTrigger, riid))
    {
        *ppv = &This->ILogonTrigger_iface;
    }
    else
    {
        FIXME("unsupported riid %s\n", debugstr_guid(riid));
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*ppv);
    return S_OK;
}

static ULONG WINAPI LogonTrigger_AddRef(ILogonTrigger *iface)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    LONG ref = InterlockedIncrement(&This->ref);
    TRACE("(%p) ref=%ld\n", This, ref);

    return ref;
}

static ULONG WINAPI LogonTrigger_Release(ILogonTrigger *iface)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    if(!ref)
    {
        TRACE("destroying %p\n", iface);
        free(This->user_id);
        free(This->id);
        free(This->execution_time_limit);
        free(This->start_boundary);
        free(This->end_boundary);
        free(This->delay);
        if (This->repetition) IRepetitionPattern_Release(This->repetition);
        free(This);
    }

    return ref;
}

static HRESULT WINAPI LogonTrigger_GetTypeInfoCount(ILogonTrigger *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI LogonTrigger_GetTypeInfo(ILogonTrigger *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_ILogonTrigger, index, lcid, info);
}

static HRESULT WINAPI LogonTrigger_GetIDsOfNames(ILogonTrigger *iface, REFIID riid, LPOLESTR *names,
                                        UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_ILogonTrigger, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI LogonTrigger_Invoke(ILogonTrigger *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                 DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_ILogonTrigger, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI LogonTrigger_get_Type(ILogonTrigger *iface, TASK_TRIGGER_TYPE2 *type)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, type);

    if (!type) return E_POINTER;

    *type = TASK_TRIGGER_LOGON;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_get_Id(ILogonTrigger *iface, BSTR *id)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, id);

    if (!id) return E_POINTER;

    if (!This->id) *id = NULL;
    else if (!(*id = SysAllocString(This->id))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI LogonTrigger_put_Id(ILogonTrigger *iface, BSTR id)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(id));

    if (id && !(str = wcsdup(id))) return E_OUTOFMEMORY;
    free(This->id);
    This->id = str;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_get_Repetition(ILogonTrigger *iface, IRepetitionPattern **repeat)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, repeat);

    return get_repetition(&This->repetition, repeat);
}

static HRESULT WINAPI LogonTrigger_put_Repetition(ILogonTrigger *iface, IRepetitionPattern *repeat)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, repeat);

    return put_repetition(&This->repetition, repeat);
}

static HRESULT WINAPI LogonTrigger_get_ExecutionTimeLimit(ILogonTrigger *iface, BSTR *limit)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, limit);

    if (!limit) return E_POINTER;

    if (!This->execution_time_limit) *limit = NULL;
    else if (!(*limit = SysAllocString(This->execution_time_limit))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI LogonTrigger_put_ExecutionTimeLimit(ILogonTrigger *iface, BSTR limit)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(limit));

    if (limit && !(str = wcsdup(limit))) return E_OUTOFMEMORY;
    free(This->execution_time_limit);
    This->execution_time_limit = str;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_get_StartBoundary(ILogonTrigger *iface, BSTR *start)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, start);

    if (!start) return E_POINTER;

    if (!This->start_boundary) *start = NULL;
    else if (!(*start = SysAllocString(This->start_boundary))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI LogonTrigger_put_StartBoundary(ILogonTrigger *iface, BSTR start)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(start));

    if (start && !(str = wcsdup(start))) return E_OUTOFMEMORY;
    free(This->start_boundary);
    This->start_boundary = str;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_get_EndBoundary(ILogonTrigger *iface, BSTR *end)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, end);

    if (!end) return E_POINTER;

    if (!This->end_boundary) *end = NULL;
    else if (!(*end = SysAllocString(This->end_boundary))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI LogonTrigger_put_EndBoundary(ILogonTrigger *iface, BSTR end)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(end));

    if (end && !(str = wcsdup(end))) return E_OUTOFMEMORY;
    free(This->end_boundary);
    This->end_boundary = str;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_get_Enabled(ILogonTrigger *iface, VARIANT_BOOL *enabled)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, enabled);

    if (!enabled) return E_POINTER;

    *enabled = This->enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_put_Enabled(ILogonTrigger *iface, VARIANT_BOOL enabled)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%x)\n", This, enabled);

    This->enabled = !!enabled;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_get_Delay(ILogonTrigger *iface, BSTR *pDelay)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, pDelay);

    if (!pDelay) return E_POINTER;

    if (!This->delay) *pDelay = NULL;
    else if (!(*pDelay = SysAllocString(This->delay))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI LogonTrigger_put_Delay(ILogonTrigger *iface, BSTR delay)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(delay));

    if (delay && !(str = wcsdup(delay))) return E_OUTOFMEMORY;
    free(This->delay);
    This->delay = str;
    return S_OK;
}

static HRESULT WINAPI LogonTrigger_get_UserId(ILogonTrigger *iface, BSTR *pUser)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);

    TRACE("(%p)->(%p)\n", This, pUser);

    if (!pUser) return E_POINTER;

    if (!This->user_id) *pUser = NULL;
    else if (!(*pUser = SysAllocString(This->user_id))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI LogonTrigger_put_UserId(ILogonTrigger *iface, BSTR user)
{
    LogonTrigger *This = impl_from_ILogonTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(user));

    if (user && !(str = wcsdup(user))) return E_OUTOFMEMORY;
    free(This->user_id);
    This->user_id = str;
    return S_OK;
}

static const ILogonTriggerVtbl LogonTrigger_vtbl = {
    LogonTrigger_QueryInterface,
    LogonTrigger_AddRef,
    LogonTrigger_Release,
    LogonTrigger_GetTypeInfoCount,
    LogonTrigger_GetTypeInfo,
    LogonTrigger_GetIDsOfNames,
    LogonTrigger_Invoke,
    LogonTrigger_get_Type,
    LogonTrigger_get_Id,
    LogonTrigger_put_Id,
    LogonTrigger_get_Repetition,
    LogonTrigger_put_Repetition,
    LogonTrigger_get_ExecutionTimeLimit,
    LogonTrigger_put_ExecutionTimeLimit,
    LogonTrigger_get_StartBoundary,
    LogonTrigger_put_StartBoundary,
    LogonTrigger_get_EndBoundary,
    LogonTrigger_put_EndBoundary,
    LogonTrigger_get_Enabled,
    LogonTrigger_put_Enabled,
    LogonTrigger_get_Delay,
    LogonTrigger_put_Delay,
    LogonTrigger_get_UserId,
    LogonTrigger_put_UserId
};

static HRESULT LogonTrigger_create(ITrigger **trigger)
{
    LogonTrigger *logon_trigger;

    logon_trigger = malloc(sizeof(*logon_trigger));
    if (!logon_trigger)
        return E_OUTOFMEMORY;

    logon_trigger->ILogonTrigger_iface.lpVtbl = &LogonTrigger_vtbl;
    logon_trigger->ref = 1;
    logon_trigger->enabled = TRUE;
    logon_trigger->user_id = NULL;
    logon_trigger->id = NULL;
    logon_trigger->execution_time_limit = NULL;
    logon_trigger->start_boundary = NULL;
    logon_trigger->end_boundary = NULL;
    logon_trigger->delay = NULL;
    logon_trigger->repetition = NULL;

    *trigger = (ITrigger*)&logon_trigger->ILogonTrigger_iface;
    return S_OK;
}

typedef struct {
    IBootTrigger IBootTrigger_iface;
    BOOL enabled;
    LONG ref;
    WCHAR *id;
    WCHAR *execution_time_limit;
    WCHAR *start_boundary;
    WCHAR *end_boundary;
    WCHAR *delay;
    IRepetitionPattern *repetition;
} BootTrigger;

static inline BootTrigger *impl_from_IBootTrigger(IBootTrigger *iface)
{
    return CONTAINING_RECORD(iface, BootTrigger, IBootTrigger_iface);
}

static HRESULT WINAPI BootTrigger_QueryInterface(IBootTrigger *iface, REFIID riid, void **ppv)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppv);

    if(IsEqualGUID(&IID_IUnknown, riid) ||
       IsEqualGUID(&IID_IDispatch, riid) ||
       IsEqualGUID(&IID_ITrigger, riid) ||
       IsEqualGUID(&IID_IBootTrigger, riid))
    {
        *ppv = &This->IBootTrigger_iface;
    }
    else
    {
        FIXME("unsupported riid %s\n", debugstr_guid(riid));
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*ppv);
    return S_OK;
}

static ULONG WINAPI BootTrigger_AddRef(IBootTrigger *iface)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);
    LONG ref = InterlockedIncrement(&This->ref);
    TRACE("(%p) ref=%ld\n", This, ref);

    return ref;
}

static ULONG WINAPI BootTrigger_Release(IBootTrigger *iface)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    if(!ref)
    {
        TRACE("destroying %p\n", iface);
        free(This->id);
        free(This->execution_time_limit);
        free(This->start_boundary);
        free(This->end_boundary);
        free(This->delay);
        if (This->repetition) IRepetitionPattern_Release(This->repetition);
        free(This);
    }

    return ref;
}

static HRESULT WINAPI BootTrigger_GetTypeInfoCount(IBootTrigger *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI BootTrigger_GetTypeInfo(IBootTrigger *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IBootTrigger, index, lcid, info);
}

static HRESULT WINAPI BootTrigger_GetIDsOfNames(IBootTrigger *iface, REFIID riid, LPOLESTR *names,
                                        UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IBootTrigger, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI BootTrigger_Invoke(IBootTrigger *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                 DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IBootTrigger, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI BootTrigger_get_Type(IBootTrigger *iface, TASK_TRIGGER_TYPE2 *type)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, type);

    if (!type) return E_POINTER;

    *type = TASK_TRIGGER_BOOT;
    return S_OK;
}

static HRESULT WINAPI BootTrigger_get_Id(IBootTrigger *iface, BSTR *id)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, id);

    if (!id) return E_POINTER;

    if (!This->id) *id = NULL;
    else if (!(*id = SysAllocString(This->id))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI BootTrigger_put_Id(IBootTrigger *iface, BSTR id)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(id));

    if (id && !(str = wcsdup(id))) return E_OUTOFMEMORY;
    free(This->id);
    This->id = str;
    return S_OK;
}

static HRESULT WINAPI BootTrigger_get_Repetition(IBootTrigger *iface, IRepetitionPattern **repeat)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, repeat);

    return get_repetition(&This->repetition, repeat);
}

static HRESULT WINAPI BootTrigger_put_Repetition(IBootTrigger *iface, IRepetitionPattern *repeat)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, repeat);

    return put_repetition(&This->repetition, repeat);
}

static HRESULT WINAPI BootTrigger_get_ExecutionTimeLimit(IBootTrigger *iface, BSTR *limit)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, limit);

    if (!limit) return E_POINTER;

    if (!This->execution_time_limit) *limit = NULL;
    else if (!(*limit = SysAllocString(This->execution_time_limit))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI BootTrigger_put_ExecutionTimeLimit(IBootTrigger *iface, BSTR limit)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(limit));

    if (limit && !(str = wcsdup(limit))) return E_OUTOFMEMORY;
    free(This->execution_time_limit);
    This->execution_time_limit = str;
    return S_OK;
}

static HRESULT WINAPI BootTrigger_get_StartBoundary(IBootTrigger *iface, BSTR *start)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, start);

    if (!start) return E_POINTER;

    if (!This->start_boundary) *start = NULL;
    else if (!(*start = SysAllocString(This->start_boundary))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI BootTrigger_put_StartBoundary(IBootTrigger *iface, BSTR start)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(start));

    if (start && !(str = wcsdup(start))) return E_OUTOFMEMORY;
    free(This->start_boundary);
    This->start_boundary = str;
    return S_OK;
}

static HRESULT WINAPI BootTrigger_get_EndBoundary(IBootTrigger *iface, BSTR *end)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, end);

    if (!end) return E_POINTER;

    if (!This->end_boundary) *end = NULL;
    else if (!(*end = SysAllocString(This->end_boundary))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI BootTrigger_put_EndBoundary(IBootTrigger *iface, BSTR end)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(end));

    if (end && !(str = wcsdup(end))) return E_OUTOFMEMORY;
    free(This->end_boundary);
    This->end_boundary = str;
    return S_OK;
}

static HRESULT WINAPI BootTrigger_get_Enabled(IBootTrigger *iface, VARIANT_BOOL *enabled)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, enabled);

    if (!enabled) return E_POINTER;

    *enabled = This->enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI BootTrigger_put_Enabled(IBootTrigger *iface, VARIANT_BOOL enabled)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%x)\n", This, enabled);

    This->enabled = !!enabled;
    return S_OK;
}

static HRESULT WINAPI BootTrigger_get_Delay(IBootTrigger *iface, BSTR *pDelay)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);

    TRACE("(%p)->(%p)\n", This, pDelay);

    if (!pDelay) return E_POINTER;

    if (!This->delay) *pDelay = NULL;
    else if (!(*pDelay = SysAllocString(This->delay))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI BootTrigger_put_Delay(IBootTrigger *iface, BSTR delay)
{
    BootTrigger *This = impl_from_IBootTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(delay));

    if (delay && !(str = wcsdup(delay))) return E_OUTOFMEMORY;
    free(This->delay);
    This->delay = str;
    return S_OK;
}

static const IBootTriggerVtbl BootTrigger_vtbl = {
    BootTrigger_QueryInterface,
    BootTrigger_AddRef,
    BootTrigger_Release,
    BootTrigger_GetTypeInfoCount,
    BootTrigger_GetTypeInfo,
    BootTrigger_GetIDsOfNames,
    BootTrigger_Invoke,
    BootTrigger_get_Type,
    BootTrigger_get_Id,
    BootTrigger_put_Id,
    BootTrigger_get_Repetition,
    BootTrigger_put_Repetition,
    BootTrigger_get_ExecutionTimeLimit,
    BootTrigger_put_ExecutionTimeLimit,
    BootTrigger_get_StartBoundary,
    BootTrigger_put_StartBoundary,
    BootTrigger_get_EndBoundary,
    BootTrigger_put_EndBoundary,
    BootTrigger_get_Enabled,
    BootTrigger_put_Enabled,
    BootTrigger_get_Delay,
    BootTrigger_put_Delay,
};

static HRESULT BootTrigger_create(ITrigger **trigger)
{
    BootTrigger *boot_trigger;

    boot_trigger = malloc(sizeof(*boot_trigger));
    if (!boot_trigger)
        return E_OUTOFMEMORY;

    boot_trigger->IBootTrigger_iface.lpVtbl = &BootTrigger_vtbl;
    boot_trigger->ref = 1;
    boot_trigger->enabled = TRUE;
    boot_trigger->id = NULL;
    boot_trigger->execution_time_limit = NULL;
    boot_trigger->start_boundary = NULL;
    boot_trigger->end_boundary = NULL;
    boot_trigger->delay = NULL;
    boot_trigger->repetition = NULL;

    *trigger = (ITrigger*)&boot_trigger->IBootTrigger_iface;
    return S_OK;
}

typedef struct {
    ITimeTrigger ITimeTrigger_iface;
    BOOL enabled;
    LONG ref;
    WCHAR *id;
    WCHAR *execution_time_limit;
    WCHAR *start_boundary;
    WCHAR *end_boundary;
    WCHAR *delay;
    IRepetitionPattern *repetition;
} TimeTrigger;

static inline TimeTrigger *impl_from_ITimeTrigger(ITimeTrigger *iface)
{
    return CONTAINING_RECORD(iface, TimeTrigger, ITimeTrigger_iface);
}

static HRESULT WINAPI TimeTrigger_QueryInterface(ITimeTrigger *iface, REFIID riid, void **ppv)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppv);

    if(IsEqualGUID(&IID_IUnknown, riid) ||
       IsEqualGUID(&IID_IDispatch, riid) ||
       IsEqualGUID(&IID_ITrigger, riid) ||
       IsEqualGUID(&IID_ITimeTrigger, riid))
    {
        *ppv = &This->ITimeTrigger_iface;
    }
    else
    {
        FIXME("unsupported riid %s\n", debugstr_guid(riid));
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*ppv);
    return S_OK;
}

static ULONG WINAPI TimeTrigger_AddRef(ITimeTrigger *iface)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);
    LONG ref = InterlockedIncrement(&This->ref);
    TRACE("(%p) ref=%ld\n", This, ref);

    return ref;
}

static ULONG WINAPI TimeTrigger_Release(ITimeTrigger *iface)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    if(!ref)
    {
        TRACE("destroying %p\n", iface);
        free(This->id);
        free(This->execution_time_limit);
        free(This->start_boundary);
        free(This->end_boundary);
        free(This->delay);
        if (This->repetition) IRepetitionPattern_Release(This->repetition);
        free(This);
    }

    return ref;
}

static HRESULT WINAPI TimeTrigger_GetTypeInfoCount(ITimeTrigger *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI TimeTrigger_GetTypeInfo(ITimeTrigger *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_ITimeTrigger, index, lcid, info);
}

static HRESULT WINAPI TimeTrigger_GetIDsOfNames(ITimeTrigger *iface, REFIID riid, LPOLESTR *names,
                                        UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_ITimeTrigger, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI TimeTrigger_Invoke(ITimeTrigger *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                 DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_ITimeTrigger, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI TimeTrigger_get_Type(ITimeTrigger *iface, TASK_TRIGGER_TYPE2 *type)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, type);

    if (!type) return E_POINTER;

    *type = TASK_TRIGGER_TIME;
    return S_OK;
}

static HRESULT WINAPI TimeTrigger_get_Id(ITimeTrigger *iface, BSTR *id)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, id);

    if (!id) return E_POINTER;

    if (!This->id) *id = NULL;
    else if (!(*id = SysAllocString(This->id))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TimeTrigger_put_Id(ITimeTrigger *iface, BSTR id)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(id));

    if (id && !(str = wcsdup(id))) return E_OUTOFMEMORY;
    free(This->id);
    This->id = str;
    return S_OK;
}

static HRESULT WINAPI TimeTrigger_get_Repetition(ITimeTrigger *iface, IRepetitionPattern **repeat)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, repeat);

    return get_repetition(&This->repetition, repeat);
}

static HRESULT WINAPI TimeTrigger_put_Repetition(ITimeTrigger *iface, IRepetitionPattern *repeat)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, repeat);

    return put_repetition(&This->repetition, repeat);
}

static HRESULT WINAPI TimeTrigger_get_ExecutionTimeLimit(ITimeTrigger *iface, BSTR *limit)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, limit);

    if (!limit) return E_POINTER;

    if (!This->execution_time_limit) *limit = NULL;
    else if (!(*limit = SysAllocString(This->execution_time_limit))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TimeTrigger_put_ExecutionTimeLimit(ITimeTrigger *iface, BSTR limit)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(limit));

    if (limit && !(str = wcsdup(limit))) return E_OUTOFMEMORY;
    free(This->execution_time_limit);
    This->execution_time_limit = str;
    return S_OK;
}

static HRESULT WINAPI TimeTrigger_get_StartBoundary(ITimeTrigger *iface, BSTR *start)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, start);

    if (!start) return E_POINTER;

    if (!This->start_boundary) *start = NULL;
    else if (!(*start = SysAllocString(This->start_boundary))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TimeTrigger_put_StartBoundary(ITimeTrigger *iface, BSTR start)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(start));

    if (start && !(str = wcsdup(start))) return E_OUTOFMEMORY;
    free(This->start_boundary);
    This->start_boundary = str;
    return S_OK;
}

static HRESULT WINAPI TimeTrigger_get_EndBoundary(ITimeTrigger *iface, BSTR *end)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, end);

    if (!end) return E_POINTER;

    if (!This->end_boundary) *end = NULL;
    else if (!(*end = SysAllocString(This->end_boundary))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TimeTrigger_put_EndBoundary(ITimeTrigger *iface, BSTR end)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(end));

    if (end && !(str = wcsdup(end))) return E_OUTOFMEMORY;
    free(This->end_boundary);
    This->end_boundary = str;
    return S_OK;
}

static HRESULT WINAPI TimeTrigger_get_Enabled(ITimeTrigger *iface, VARIANT_BOOL *enabled)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, enabled);

    if (!enabled) return E_POINTER;

    *enabled = This->enabled ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI TimeTrigger_put_Enabled(ITimeTrigger *iface, VARIANT_BOOL enabled)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%x)\n", This, enabled);

    This->enabled = !!enabled;
    return S_OK;
}

static HRESULT WINAPI TimeTrigger_get_RandomDelay(ITimeTrigger *iface, BSTR *pDelay)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);

    TRACE("(%p)->(%p)\n", This, pDelay);

    if (!pDelay) return E_POINTER;

    if (!This->delay) *pDelay = NULL;
    else if (!(*pDelay = SysAllocString(This->delay))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TimeTrigger_put_RandomDelay(ITimeTrigger *iface, BSTR delay)
{
    TimeTrigger *This = impl_from_ITimeTrigger(iface);
    WCHAR *str = NULL;

    TRACE("(%p)->(%s)\n", This, debugstr_w(delay));

    if (delay && !(str = wcsdup(delay))) return E_OUTOFMEMORY;
    free(This->delay);
    This->delay = str;
    return S_OK;
}

static const ITimeTriggerVtbl TimeTrigger_vtbl = {
    TimeTrigger_QueryInterface,
    TimeTrigger_AddRef,
    TimeTrigger_Release,
    TimeTrigger_GetTypeInfoCount,
    TimeTrigger_GetTypeInfo,
    TimeTrigger_GetIDsOfNames,
    TimeTrigger_Invoke,
    TimeTrigger_get_Type,
    TimeTrigger_get_Id,
    TimeTrigger_put_Id,
    TimeTrigger_get_Repetition,
    TimeTrigger_put_Repetition,
    TimeTrigger_get_ExecutionTimeLimit,
    TimeTrigger_put_ExecutionTimeLimit,
    TimeTrigger_get_StartBoundary,
    TimeTrigger_put_StartBoundary,
    TimeTrigger_get_EndBoundary,
    TimeTrigger_put_EndBoundary,
    TimeTrigger_get_Enabled,
    TimeTrigger_put_Enabled,
    TimeTrigger_get_RandomDelay,
    TimeTrigger_put_RandomDelay,
};

static HRESULT TimeTrigger_create(ITrigger **trigger)
{
    TimeTrigger *time_trigger;

    time_trigger = malloc(sizeof(*time_trigger));
    if (!time_trigger)
        return E_OUTOFMEMORY;

    time_trigger->ITimeTrigger_iface.lpVtbl = &TimeTrigger_vtbl;
    time_trigger->ref = 1;
    time_trigger->enabled = TRUE;
    time_trigger->id = NULL;
    time_trigger->execution_time_limit = NULL;
    time_trigger->start_boundary = NULL;
    time_trigger->end_boundary = NULL;
    time_trigger->delay = NULL;
    time_trigger->repetition = NULL;

    *trigger = (ITrigger*)&time_trigger->ITimeTrigger_iface;
    return S_OK;
}

typedef struct
{
    ITriggerCollection ITriggerCollection_iface;
    LONG ref;
    ITrigger **triggers;
    LONG count;
    LONG size;
} trigger_collection;

static inline trigger_collection *impl_from_ITriggerCollection(ITriggerCollection *iface)
{
    return CONTAINING_RECORD(iface, trigger_collection, ITriggerCollection_iface);
}

static HRESULT WINAPI TriggerCollection_QueryInterface(ITriggerCollection *iface, REFIID riid, void **ppv)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);

    TRACE("(%p)->(%s %p)\n", This, debugstr_guid(riid), ppv);

    if(IsEqualGUID(&IID_IUnknown, riid) ||
       IsEqualGUID(&IID_IDispatch, riid) ||
       IsEqualGUID(&IID_ITriggerCollection, riid)) {
        *ppv = &This->ITriggerCollection_iface;
    }else {
        FIXME("unimplemented interface %s\n", debugstr_guid(riid));
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*ppv);
    return S_OK;
}

static ULONG WINAPI TriggerCollection_AddRef(ITriggerCollection *iface)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);
    LONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    return ref;
}

static ULONG WINAPI TriggerCollection_Release(ITriggerCollection *iface)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%ld\n", This, ref);

    if(!ref)
    {
        while (This->count) ITrigger_Release(This->triggers[--This->count]);
        free(This->triggers);
        free(This);
    }

    return ref;
}

static HRESULT WINAPI TriggerCollection_GetTypeInfoCount(ITriggerCollection *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI TriggerCollection_GetTypeInfo(ITriggerCollection *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_ITriggerCollection, index, lcid, info);
}

static HRESULT WINAPI TriggerCollection_GetIDsOfNames(ITriggerCollection *iface, REFIID riid, LPOLESTR *names,
                                                   UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_ITriggerCollection, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI TriggerCollection_Invoke(ITriggerCollection *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                               DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_ITriggerCollection, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI TriggerCollection_get_Count(ITriggerCollection *iface, LONG *count)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);

    TRACE("(%p)->(%p)\n", This, count);

    if (!count) return E_POINTER;

    *count = This->count;
    return S_OK;
}

static HRESULT WINAPI TriggerCollection_get_Item(ITriggerCollection *iface, LONG index, ITrigger **trigger)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);

    TRACE("(%p)->(%ld %p)\n", This, index, trigger);

    if (!trigger) return E_POINTER;
    if (index < 1 || index > This->count) return E_INVALIDARG;

    ITrigger_AddRef(*trigger = This->triggers[index - 1]);
    return S_OK;
}

static HRESULT WINAPI TriggerCollection_get__NewEnum(ITriggerCollection *iface, IUnknown **penum)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);
    IDispatch **items;
    LONG i;

    TRACE("(%p)->(%p)\n", This, penum);

    if (!penum) return E_POINTER;

    items = calloc(This->count ? This->count : 1, sizeof(*items));
    if (!items) return E_OUTOFMEMORY;
    for (i = 0; i < This->count; i++)
    {
        ITrigger_AddRef(This->triggers[i]);
        items[i] = (IDispatch *)This->triggers[i];
    }
    return taskschd_create_enum(items, This->count, penum);
}

static HRESULT WINAPI TriggerCollection_Create(ITriggerCollection *iface, TASK_TRIGGER_TYPE2 type, ITrigger **trigger)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);

    HRESULT hr;

    TRACE("(%p)->(%d %p)\n", This, type, trigger);

    if (!trigger) return E_POINTER;

    if (This->count == This->size)
    {
        LONG size = This->size ? This->size * 2 : 4;
        ITrigger **triggers = realloc(This->triggers, size * sizeof(*triggers));

        if (!triggers) return E_OUTOFMEMORY;
        This->triggers = triggers;
        This->size = size;
    }

    switch(type) {
    case TASK_TRIGGER_TIME:
        hr = TimeTrigger_create(trigger);
        break;
    case TASK_TRIGGER_DAILY:
    case TASK_TRIGGER_WEEKLY:
    case TASK_TRIGGER_MONTHLY:
    case TASK_TRIGGER_MONTHLYDOW:
    case TASK_TRIGGER_IDLE:
    case TASK_TRIGGER_EVENT:
    case TASK_TRIGGER_SESSION_STATE_CHANGE:
        hr = SchedTrigger_create(type, trigger);
        break;
    case TASK_TRIGGER_BOOT:
        hr = BootTrigger_create(trigger);
        break;
    case TASK_TRIGGER_REGISTRATION:
        hr = RegistrationTrigger_create(trigger);
        break;
    case TASK_TRIGGER_LOGON:
        hr = LogonTrigger_create(trigger);
        break;
    default:
        FIXME("Unimplemented type %d\n", type);
        return E_NOTIMPL;
    }
    if (hr != S_OK) return hr;

    ITrigger_AddRef(This->triggers[This->count++] = *trigger);
    return S_OK;
}

static HRESULT WINAPI TriggerCollection_Remove(ITriggerCollection *iface, VARIANT index)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);
    VARIANT var;
    LONG i;

    TRACE("(%p)->(%s)\n", This, debugstr_variant(&index));

    VariantInit(&var);
    if (FAILED(VariantChangeType(&var, &index, 0, VT_I4)))
    {
        FIXME("unsupported index %s\n", debugstr_variant(&index));
        return E_INVALIDARG;
    }
    i = V_I4(&var);
    if (i < 1 || i > This->count) return E_INVALIDARG;

    ITrigger_Release(This->triggers[i - 1]);
    memmove(&This->triggers[i - 1], &This->triggers[i], (This->count - i) * sizeof(*This->triggers));
    This->count--;
    return S_OK;
}

static HRESULT WINAPI TriggerCollection_Clear(ITriggerCollection *iface)
{
    trigger_collection *This = impl_from_ITriggerCollection(iface);

    TRACE("(%p)\n", This);

    while (This->count) ITrigger_Release(This->triggers[--This->count]);
    return S_OK;
}

static const ITriggerCollectionVtbl TriggerCollection_vtbl = {
    TriggerCollection_QueryInterface,
    TriggerCollection_AddRef,
    TriggerCollection_Release,
    TriggerCollection_GetTypeInfoCount,
    TriggerCollection_GetTypeInfo,
    TriggerCollection_GetIDsOfNames,
    TriggerCollection_Invoke,
    TriggerCollection_get_Count,
    TriggerCollection_get_Item,
    TriggerCollection_get__NewEnum,
    TriggerCollection_Create,
    TriggerCollection_Remove,
    TriggerCollection_Clear
};

typedef struct
{
    IRegistrationInfo IRegistrationInfo_iface;
    LONG ref;
    WCHAR *description, *author, *version, *date, *documentation, *uri, *source;
} registration_info;

static inline registration_info *impl_from_IRegistrationInfo(IRegistrationInfo *iface)
{
    return CONTAINING_RECORD(iface, registration_info, IRegistrationInfo_iface);
}

static ULONG WINAPI RegistrationInfo_AddRef(IRegistrationInfo *iface)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    return InterlockedIncrement(&reginfo->ref);
}

static ULONG WINAPI RegistrationInfo_Release(IRegistrationInfo *iface)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    LONG ref = InterlockedDecrement(&reginfo->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        free(reginfo->description);
        free(reginfo->author);
        free(reginfo->version);
        free(reginfo->date);
        free(reginfo->documentation);
        free(reginfo->uri);
        free(reginfo->source);
        free(reginfo);
    }

    return ref;
}

static HRESULT WINAPI RegistrationInfo_QueryInterface(IRegistrationInfo *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_IRegistrationInfo) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        IRegistrationInfo_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI RegistrationInfo_GetTypeInfoCount(IRegistrationInfo *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI RegistrationInfo_GetTypeInfo(IRegistrationInfo *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IRegistrationInfo, index, lcid, info);
}

static HRESULT WINAPI RegistrationInfo_GetIDsOfNames(IRegistrationInfo *iface, REFIID riid, LPOLESTR *names,
                                                   UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IRegistrationInfo, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI RegistrationInfo_Invoke(IRegistrationInfo *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                            DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IRegistrationInfo, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI RegistrationInfo_get_Description(IRegistrationInfo *iface, BSTR *description)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);

    TRACE("%p,%p\n", iface, description);

    if (!description) return E_POINTER;

    if (!reginfo->description) *description = NULL;
    else if (!(*description = SysAllocString(reginfo->description))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_put_Description(IRegistrationInfo *iface, BSTR description)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(description));

    if (description && !(str = wcsdup(description))) return E_OUTOFMEMORY;
    free(reginfo->description);
    reginfo->description = str;
    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_get_Author(IRegistrationInfo *iface, BSTR *author)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);

    TRACE("%p,%p\n", iface, author);

    if (!author) return E_POINTER;

    if (!reginfo->author) *author = NULL;
    else if (!(*author = SysAllocString(reginfo->author))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_put_Author(IRegistrationInfo *iface, BSTR author)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(author));

    if (author && !(str = wcsdup(author))) return E_OUTOFMEMORY;
    free(reginfo->author);
    reginfo->author = str;
    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_get_Version(IRegistrationInfo *iface, BSTR *version)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);

    TRACE("%p,%p\n", iface, version);

    if (!version) return E_POINTER;

    if (!reginfo->version) *version = NULL;
    else if (!(*version = SysAllocString(reginfo->version))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_put_Version(IRegistrationInfo *iface, BSTR version)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(version));

    if (version && !(str = wcsdup(version))) return E_OUTOFMEMORY;
    free(reginfo->version);
    reginfo->version = str;
    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_get_Date(IRegistrationInfo *iface, BSTR *date)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);

    TRACE("%p,%p\n", iface, date);

    if (!date) return E_POINTER;

    if (!reginfo->date) *date = NULL;
    else if (!(*date = SysAllocString(reginfo->date))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_put_Date(IRegistrationInfo *iface, BSTR date)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(date));

    if (date && !(str = wcsdup(date))) return E_OUTOFMEMORY;
    free(reginfo->date);
    reginfo->date = str;
    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_get_Documentation(IRegistrationInfo *iface, BSTR *doc)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);

    TRACE("%p,%p\n", iface, doc);

    if (!doc) return E_POINTER;

    if (!reginfo->documentation) *doc = NULL;
    else if (!(*doc = SysAllocString(reginfo->documentation))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_put_Documentation(IRegistrationInfo *iface, BSTR doc)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(doc));

    if (doc && !(str = wcsdup(doc))) return E_OUTOFMEMORY;
    free(reginfo->documentation);
    reginfo->documentation = str;
    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_get_XmlText(IRegistrationInfo *iface, BSTR *xml)
{
    FIXME("%p,%p: stub\n", iface, xml);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationInfo_put_XmlText(IRegistrationInfo *iface, BSTR xml)
{
    FIXME("%p,%s: stub\n", iface, debugstr_w(xml));
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationInfo_get_URI(IRegistrationInfo *iface, BSTR *uri)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);

    TRACE("%p,%p\n", iface, uri);

    if (!uri) return E_POINTER;

    if (!reginfo->uri) *uri = NULL;
    else if (!(*uri = SysAllocString(reginfo->uri))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_put_URI(IRegistrationInfo *iface, BSTR uri)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(uri));

    if (uri && !(str = wcsdup(uri))) return E_OUTOFMEMORY;
    free(reginfo->uri);
    reginfo->uri = str;
    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_get_SecurityDescriptor(IRegistrationInfo *iface, VARIANT *sddl)
{
    FIXME("%p,%p: stub\n", iface, sddl);
    return E_NOTIMPL;
}

static HRESULT WINAPI RegistrationInfo_put_SecurityDescriptor(IRegistrationInfo *iface, VARIANT sddl)
{
    FIXME("%p,%s: stub\n", iface, debugstr_variant(&sddl));
    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_get_Source(IRegistrationInfo *iface, BSTR *source)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);

    TRACE("%p,%p\n", iface, source);

    if (!source) return E_POINTER;

    if (!reginfo->source) *source = NULL;
    else if (!(*source = SysAllocString(reginfo->source))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI RegistrationInfo_put_Source(IRegistrationInfo *iface, BSTR source)
{
    registration_info *reginfo = impl_from_IRegistrationInfo(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(source));

    if (source && !(str = wcsdup(source))) return E_OUTOFMEMORY;
    free(reginfo->source);
    reginfo->source = str;
    return S_OK;
}

static const IRegistrationInfoVtbl RegistrationInfo_vtbl =
{
    RegistrationInfo_QueryInterface,
    RegistrationInfo_AddRef,
    RegistrationInfo_Release,
    RegistrationInfo_GetTypeInfoCount,
    RegistrationInfo_GetTypeInfo,
    RegistrationInfo_GetIDsOfNames,
    RegistrationInfo_Invoke,
    RegistrationInfo_get_Description,
    RegistrationInfo_put_Description,
    RegistrationInfo_get_Author,
    RegistrationInfo_put_Author,
    RegistrationInfo_get_Version,
    RegistrationInfo_put_Version,
    RegistrationInfo_get_Date,
    RegistrationInfo_put_Date,
    RegistrationInfo_get_Documentation,
    RegistrationInfo_put_Documentation,
    RegistrationInfo_get_XmlText,
    RegistrationInfo_put_XmlText,
    RegistrationInfo_get_URI,
    RegistrationInfo_put_URI,
    RegistrationInfo_get_SecurityDescriptor,
    RegistrationInfo_put_SecurityDescriptor,
    RegistrationInfo_get_Source,
    RegistrationInfo_put_Source
};

static HRESULT RegistrationInfo_create(IRegistrationInfo **obj)
{
    registration_info *reginfo;

    reginfo = calloc(1, sizeof(*reginfo));
    if (!reginfo) return E_OUTOFMEMORY;

    reginfo->IRegistrationInfo_iface.lpVtbl = &RegistrationInfo_vtbl;
    reginfo->ref = 1;
    *obj = &reginfo->IRegistrationInfo_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

static HRESULT get_string_property(const WCHAR *value, BSTR *ret)
{
    if (!ret) return E_POINTER;

    if (!value) *ret = NULL;
    else if (!(*ret = SysAllocString(value))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT put_string_property(WCHAR **value, const WCHAR *str)
{
    WCHAR *copy = NULL;

    if (str && !(copy = wcsdup(str))) return E_OUTOFMEMORY;
    free(*value);
    *value = copy;
    return S_OK;
}

typedef struct
{
    IIdleSettings IIdleSettings_iface;
    LONG ref;
    WCHAR *idle_duration;
    WCHAR *wait_timeout;
    VARIANT_BOOL stop_on_idle_end;
    VARIANT_BOOL restart_on_idle;
} IdleSettings;

static inline IdleSettings *impl_from_IIdleSettings(IIdleSettings *iface)
{
    return CONTAINING_RECORD(iface, IdleSettings, IIdleSettings_iface);
}

static HRESULT WINAPI IdleSettings_QueryInterface(IIdleSettings *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_IIdleSettings) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        IIdleSettings_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI IdleSettings_AddRef(IIdleSettings *iface)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);
    return InterlockedIncrement(&settings->ref);
}

static ULONG WINAPI IdleSettings_Release(IIdleSettings *iface)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);
    LONG ref = InterlockedDecrement(&settings->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        free(settings->idle_duration);
        free(settings->wait_timeout);
        free(settings);
    }

    return ref;
}

static HRESULT WINAPI IdleSettings_GetTypeInfoCount(IIdleSettings *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI IdleSettings_GetTypeInfo(IIdleSettings *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IIdleSettings, index, lcid, info);
}

static HRESULT WINAPI IdleSettings_GetIDsOfNames(IIdleSettings *iface, REFIID riid, LPOLESTR *names,
                                                 UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IIdleSettings, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI IdleSettings_Invoke(IIdleSettings *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                          DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IIdleSettings, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI IdleSettings_get_IdleDuration(IIdleSettings *iface, BSTR *delay)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);
    TRACE("%p,%p\n", iface, delay);
    return get_string_property(settings->idle_duration, delay);
}

static HRESULT WINAPI IdleSettings_put_IdleDuration(IIdleSettings *iface, BSTR delay)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);
    TRACE("%p,%s\n", iface, debugstr_w(delay));
    return put_string_property(&settings->idle_duration, delay);
}

static HRESULT WINAPI IdleSettings_get_WaitTimeout(IIdleSettings *iface, BSTR *timeout)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);
    TRACE("%p,%p\n", iface, timeout);
    return get_string_property(settings->wait_timeout, timeout);
}

static HRESULT WINAPI IdleSettings_put_WaitTimeout(IIdleSettings *iface, BSTR timeout)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);
    TRACE("%p,%s\n", iface, debugstr_w(timeout));
    return put_string_property(&settings->wait_timeout, timeout);
}

static HRESULT WINAPI IdleSettings_get_StopOnIdleEnd(IIdleSettings *iface, VARIANT_BOOL *stop)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);

    TRACE("%p,%p\n", iface, stop);

    if (!stop) return E_POINTER;

    *stop = settings->stop_on_idle_end;
    return S_OK;
}

static HRESULT WINAPI IdleSettings_put_StopOnIdleEnd(IIdleSettings *iface, VARIANT_BOOL stop)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);

    TRACE("%p,%d\n", iface, stop);

    settings->stop_on_idle_end = stop ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static HRESULT WINAPI IdleSettings_get_RestartOnIdle(IIdleSettings *iface, VARIANT_BOOL *restart)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);

    TRACE("%p,%p\n", iface, restart);

    if (!restart) return E_POINTER;

    *restart = settings->restart_on_idle;
    return S_OK;
}

static HRESULT WINAPI IdleSettings_put_RestartOnIdle(IIdleSettings *iface, VARIANT_BOOL restart)
{
    IdleSettings *settings = impl_from_IIdleSettings(iface);

    TRACE("%p,%d\n", iface, restart);

    settings->restart_on_idle = restart ? VARIANT_TRUE : VARIANT_FALSE;
    return S_OK;
}

static const IIdleSettingsVtbl IdleSettings_vtbl =
{
    IdleSettings_QueryInterface,
    IdleSettings_AddRef,
    IdleSettings_Release,
    IdleSettings_GetTypeInfoCount,
    IdleSettings_GetTypeInfo,
    IdleSettings_GetIDsOfNames,
    IdleSettings_Invoke,
    IdleSettings_get_IdleDuration,
    IdleSettings_put_IdleDuration,
    IdleSettings_get_WaitTimeout,
    IdleSettings_put_WaitTimeout,
    IdleSettings_get_StopOnIdleEnd,
    IdleSettings_put_StopOnIdleEnd,
    IdleSettings_get_RestartOnIdle,
    IdleSettings_put_RestartOnIdle
};

static HRESULT IdleSettings_create(IIdleSettings **obj)
{
    IdleSettings *settings;

    if (!(settings = malloc(sizeof(*settings)))) return E_OUTOFMEMORY;

    settings->IIdleSettings_iface.lpVtbl = &IdleSettings_vtbl;
    settings->ref = 1;
    /* the defaults */
    settings->idle_duration = wcsdup(L"PT10M");
    settings->wait_timeout = wcsdup(L"PT1H");
    settings->stop_on_idle_end = VARIANT_TRUE;
    settings->restart_on_idle = VARIANT_FALSE;

    *obj = &settings->IIdleSettings_iface;
    return S_OK;
}

typedef struct
{
    ITaskSettings ITaskSettings_iface;
    LONG ref;
    WCHAR *restart_interval;
    WCHAR *execution_time_limit;
    WCHAR *delete_expired_task_after;
    int restart_count;
    int priority;
    TASK_INSTANCES_POLICY policy;
    TASK_COMPATIBILITY compatibility;
    BOOL allow_on_demand_start;
    BOOL stop_if_going_on_batteries;
    BOOL disallow_start_if_on_batteries;
    BOOL allow_hard_terminate;
    BOOL start_when_available;
    BOOL run_only_if_network_available;
    BOOL enabled;
    BOOL hidden;
    BOOL run_only_if_idle;
    BOOL wake_to_run;
    IIdleSettings *idle_settings;
} TaskSettings;

static inline TaskSettings *impl_from_ITaskSettings(ITaskSettings *iface)
{
    return CONTAINING_RECORD(iface, TaskSettings, ITaskSettings_iface);
}

static ULONG WINAPI TaskSettings_AddRef(ITaskSettings *iface)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);
    return InterlockedIncrement(&taskset->ref);
}

static ULONG WINAPI TaskSettings_Release(ITaskSettings *iface)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);
    LONG ref = InterlockedDecrement(&taskset->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        free(taskset->restart_interval);
        free(taskset->execution_time_limit);
        free(taskset->delete_expired_task_after);
        if (taskset->idle_settings) IIdleSettings_Release(taskset->idle_settings);
        free(taskset);
    }

    return ref;
}

static HRESULT WINAPI TaskSettings_QueryInterface(ITaskSettings *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_ITaskSettings) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        ITaskSettings_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI TaskSettings_GetTypeInfoCount(ITaskSettings *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI TaskSettings_GetTypeInfo(ITaskSettings *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_ITaskSettings, index, lcid, info);
}

static HRESULT WINAPI TaskSettings_GetIDsOfNames(ITaskSettings *iface, REFIID riid, LPOLESTR *names,
                                                 UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_ITaskSettings, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI TaskSettings_Invoke(ITaskSettings *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                          DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_ITaskSettings, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI TaskSettings_get_AllowDemandStart(ITaskSettings *iface, VARIANT_BOOL *allow)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, allow);

    if (!allow) return E_POINTER;

    *allow = taskset->allow_on_demand_start ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_AllowDemandStart(ITaskSettings *iface, VARIANT_BOOL allow)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, allow);

    taskset->allow_on_demand_start = !!allow;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_RestartInterval(ITaskSettings *iface, BSTR *interval)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, interval);

    if (!interval) return E_POINTER;

    if (!taskset->restart_interval)
    {
        *interval = NULL;
        return S_OK;
    }

    if (!taskset->restart_interval) *interval = NULL;
    else if (!(*interval = SysAllocString(taskset->restart_interval))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_RestartInterval(ITaskSettings *iface, BSTR interval)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(interval));

    if (interval && !(str = wcsdup(interval))) return E_OUTOFMEMORY;
    free(taskset->restart_interval);
    taskset->restart_interval = str;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_RestartCount(ITaskSettings *iface, INT *count)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, count);

    if (!count) return E_POINTER;

    *count = taskset->restart_count;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_RestartCount(ITaskSettings *iface, INT count)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, count);

    taskset->restart_count = count;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_MultipleInstances(ITaskSettings *iface, TASK_INSTANCES_POLICY *policy)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, policy);

    if (!policy) return E_POINTER;

    *policy = taskset->policy;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_MultipleInstances(ITaskSettings *iface, TASK_INSTANCES_POLICY policy)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, policy);

    taskset->policy = policy;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_StopIfGoingOnBatteries(ITaskSettings *iface, VARIANT_BOOL *stop)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, stop);

    if (!stop) return E_POINTER;

    *stop = taskset->stop_if_going_on_batteries ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_StopIfGoingOnBatteries(ITaskSettings *iface, VARIANT_BOOL stop)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, stop);

    taskset->stop_if_going_on_batteries = !!stop;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_DisallowStartIfOnBatteries(ITaskSettings *iface, VARIANT_BOOL *disallow)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, disallow);

    if (!disallow) return E_POINTER;

    *disallow = taskset->disallow_start_if_on_batteries ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_DisallowStartIfOnBatteries(ITaskSettings *iface, VARIANT_BOOL disallow)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, disallow);

    taskset->disallow_start_if_on_batteries = !!disallow;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_AllowHardTerminate(ITaskSettings *iface, VARIANT_BOOL *allow)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, allow);

    if (!allow) return E_POINTER;

    *allow = taskset->allow_hard_terminate ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_AllowHardTerminate(ITaskSettings *iface, VARIANT_BOOL allow)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, allow);

    taskset->allow_hard_terminate = !!allow;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_StartWhenAvailable(ITaskSettings *iface, VARIANT_BOOL *start)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, start);

    if (!start) return E_POINTER;

    *start = taskset->start_when_available ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_StartWhenAvailable(ITaskSettings *iface, VARIANT_BOOL start)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, start);

    taskset->start_when_available = !!start;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_XmlText(ITaskSettings *iface, BSTR *xml)
{
    FIXME("%p,%p: stub\n", iface, xml);
    return E_NOTIMPL;
}

static HRESULT WINAPI TaskSettings_put_XmlText(ITaskSettings *iface, BSTR xml)
{
    FIXME("%p,%s: stub\n", iface, debugstr_w(xml));
    return E_NOTIMPL;
}

static HRESULT WINAPI TaskSettings_get_RunOnlyIfNetworkAvailable(ITaskSettings *iface, VARIANT_BOOL *run)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, run);

    if (!run) return E_POINTER;

    *run = taskset->run_only_if_network_available ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_RunOnlyIfNetworkAvailable(ITaskSettings *iface, VARIANT_BOOL run)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, run);

    taskset->run_only_if_network_available = !!run;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_ExecutionTimeLimit(ITaskSettings *iface, BSTR *limit)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, limit);

    if (!limit) return E_POINTER;

    if (!taskset->execution_time_limit)
    {
        *limit = NULL;
        return S_OK;
    }

    if (!taskset->execution_time_limit) *limit = NULL;
    else if (!(*limit = SysAllocString(taskset->execution_time_limit))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_ExecutionTimeLimit(ITaskSettings *iface, BSTR limit)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(limit));

    if (limit && !(str = wcsdup(limit))) return E_OUTOFMEMORY;
    free(taskset->execution_time_limit);
    taskset->execution_time_limit = str;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_Enabled(ITaskSettings *iface, VARIANT_BOOL *enabled)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, enabled);

    if (!enabled) return E_POINTER;

    *enabled = taskset->enabled ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_Enabled(ITaskSettings *iface, VARIANT_BOOL enabled)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, enabled);

    taskset->enabled = !!enabled;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_DeleteExpiredTaskAfter(ITaskSettings *iface, BSTR *delay)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, delay);

    if (!delay) return E_POINTER;

    if (!taskset->delete_expired_task_after) *delay = NULL;
    else if (!(*delay = SysAllocString(taskset->delete_expired_task_after))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_DeleteExpiredTaskAfter(ITaskSettings *iface, BSTR delay)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(delay));

    if (delay && !(str = wcsdup(delay))) return E_OUTOFMEMORY;
    free(taskset->delete_expired_task_after);
    taskset->delete_expired_task_after = str;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_Priority(ITaskSettings *iface, INT *priority)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, priority);

    if (!priority) return E_POINTER;

    *priority = taskset->priority;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_Priority(ITaskSettings *iface, INT priority)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, priority);

    taskset->priority = priority;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_Compatibility(ITaskSettings *iface, TASK_COMPATIBILITY *level)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, level);

    if (!level) return E_POINTER;

    *level = taskset->compatibility;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_Compatibility(ITaskSettings *iface, TASK_COMPATIBILITY level)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, level);

    taskset->compatibility = level;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_Hidden(ITaskSettings *iface, VARIANT_BOOL *hidden)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, hidden);

    if (!hidden) return E_POINTER;

    *hidden = taskset->hidden ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_Hidden(ITaskSettings *iface, VARIANT_BOOL hidden)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, hidden);

    taskset->hidden = !!hidden;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_IdleSettings(ITaskSettings *iface, IIdleSettings **settings)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);
    HRESULT hr;

    TRACE("%p,%p\n", iface, settings);

    if (!settings) return E_POINTER;
    if (!taskset->idle_settings && (hr = IdleSettings_create(&taskset->idle_settings)) != S_OK) return hr;

    IIdleSettings_AddRef(*settings = taskset->idle_settings);
    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_IdleSettings(ITaskSettings *iface, IIdleSettings *settings)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, settings);

    if (!settings) return E_POINTER;

    IIdleSettings_AddRef(settings);
    if (taskset->idle_settings) IIdleSettings_Release(taskset->idle_settings);
    taskset->idle_settings = settings;
    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_RunOnlyIfIdle(ITaskSettings *iface, VARIANT_BOOL *run)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, run);

    if (!run) return E_POINTER;

    *run = taskset->run_only_if_idle ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_RunOnlyIfIdle(ITaskSettings *iface, VARIANT_BOOL run)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, run);

    taskset->run_only_if_idle = !!run;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_WakeToRun(ITaskSettings *iface, VARIANT_BOOL *wake)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%p\n", iface, wake);

    if (!wake) return E_POINTER;

    *wake = taskset->wake_to_run ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_put_WakeToRun(ITaskSettings *iface, VARIANT_BOOL wake)
{
    TaskSettings *taskset = impl_from_ITaskSettings(iface);

    TRACE("%p,%d\n", iface, wake);

    taskset->wake_to_run = !!wake;

    return S_OK;
}

static HRESULT WINAPI TaskSettings_get_NetworkSettings(ITaskSettings *iface, INetworkSettings **settings)
{
    FIXME("%p,%p: stub\n", iface, settings);
    return E_NOTIMPL;
}

static HRESULT WINAPI TaskSettings_put_NetworkSettings(ITaskSettings *iface, INetworkSettings *settings)
{
    FIXME("%p,%p: stub\n", iface, settings);
    return E_NOTIMPL;
}

static const ITaskSettingsVtbl TaskSettings_vtbl =
{
    TaskSettings_QueryInterface,
    TaskSettings_AddRef,
    TaskSettings_Release,
    TaskSettings_GetTypeInfoCount,
    TaskSettings_GetTypeInfo,
    TaskSettings_GetIDsOfNames,
    TaskSettings_Invoke,
    TaskSettings_get_AllowDemandStart,
    TaskSettings_put_AllowDemandStart,
    TaskSettings_get_RestartInterval,
    TaskSettings_put_RestartInterval,
    TaskSettings_get_RestartCount,
    TaskSettings_put_RestartCount,
    TaskSettings_get_MultipleInstances,
    TaskSettings_put_MultipleInstances,
    TaskSettings_get_StopIfGoingOnBatteries,
    TaskSettings_put_StopIfGoingOnBatteries,
    TaskSettings_get_DisallowStartIfOnBatteries,
    TaskSettings_put_DisallowStartIfOnBatteries,
    TaskSettings_get_AllowHardTerminate,
    TaskSettings_put_AllowHardTerminate,
    TaskSettings_get_StartWhenAvailable,
    TaskSettings_put_StartWhenAvailable,
    TaskSettings_get_XmlText,
    TaskSettings_put_XmlText,
    TaskSettings_get_RunOnlyIfNetworkAvailable,
    TaskSettings_put_RunOnlyIfNetworkAvailable,
    TaskSettings_get_ExecutionTimeLimit,
    TaskSettings_put_ExecutionTimeLimit,
    TaskSettings_get_Enabled,
    TaskSettings_put_Enabled,
    TaskSettings_get_DeleteExpiredTaskAfter,
    TaskSettings_put_DeleteExpiredTaskAfter,
    TaskSettings_get_Priority,
    TaskSettings_put_Priority,
    TaskSettings_get_Compatibility,
    TaskSettings_put_Compatibility,
    TaskSettings_get_Hidden,
    TaskSettings_put_Hidden,
    TaskSettings_get_IdleSettings,
    TaskSettings_put_IdleSettings,
    TaskSettings_get_RunOnlyIfIdle,
    TaskSettings_put_RunOnlyIfIdle,
    TaskSettings_get_WakeToRun,
    TaskSettings_put_WakeToRun,
    TaskSettings_get_NetworkSettings,
    TaskSettings_put_NetworkSettings
};

static HRESULT TaskSettings_create(ITaskSettings **obj)
{
    TaskSettings *taskset;

    taskset = malloc(sizeof(*taskset));
    if (!taskset) return E_OUTOFMEMORY;

    taskset->ITaskSettings_iface.lpVtbl = &TaskSettings_vtbl;
    taskset->ref = 1;
    /* set the defaults */
    taskset->restart_interval = NULL;
    taskset->execution_time_limit = wcsdup(L"PT72H");
    taskset->delete_expired_task_after = NULL;
    taskset->restart_count = 0;
    taskset->priority = 7;
    taskset->policy = TASK_INSTANCES_IGNORE_NEW;
    taskset->compatibility = TASK_COMPATIBILITY_V2;
    taskset->allow_on_demand_start = TRUE;
    taskset->stop_if_going_on_batteries = TRUE;
    taskset->disallow_start_if_on_batteries = TRUE;
    taskset->allow_hard_terminate = TRUE;
    taskset->start_when_available = FALSE;
    taskset->run_only_if_network_available = FALSE;
    taskset->enabled = TRUE;
    taskset->hidden = FALSE;
    taskset->run_only_if_idle = FALSE;
    taskset->wake_to_run = FALSE;
    taskset->idle_settings = NULL;

    *obj = &taskset->ITaskSettings_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

typedef struct
{
    IPrincipal IPrincipal_iface;
    LONG ref;
    WCHAR *id;
    WCHAR *display_name;
    WCHAR *user_id;
    WCHAR *group_id;
    TASK_LOGON_TYPE logon_type;
    TASK_RUNLEVEL_TYPE run_level;
} Principal;


static inline Principal *impl_from_IPrincipal(IPrincipal *iface)
{
    return CONTAINING_RECORD(iface, Principal, IPrincipal_iface);
}

static ULONG WINAPI Principal_AddRef(IPrincipal *iface)
{
    Principal *principal = impl_from_IPrincipal(iface);
    return InterlockedIncrement(&principal->ref);
}

static ULONG WINAPI Principal_Release(IPrincipal *iface)
{
    Principal *principal = impl_from_IPrincipal(iface);
    LONG ref = InterlockedDecrement(&principal->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        free(principal->id);
        free(principal->display_name);
        free(principal->user_id);
        free(principal->group_id);
        free(principal);
    }

    return ref;
}

static HRESULT WINAPI Principal_QueryInterface(IPrincipal *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_IPrincipal) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        IPrincipal_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI Principal_GetTypeInfoCount(IPrincipal *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI Principal_GetTypeInfo(IPrincipal *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IPrincipal, index, lcid, info);
}

static HRESULT WINAPI Principal_GetIDsOfNames(IPrincipal *iface, REFIID riid, LPOLESTR *names,
                                              UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IPrincipal, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI Principal_Invoke(IPrincipal *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                       DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IPrincipal, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI Principal_get_Id(IPrincipal *iface, BSTR *id)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%p\n", iface, id);
    return get_string_property(principal->id, id);
}

static HRESULT WINAPI Principal_put_Id(IPrincipal *iface, BSTR id)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%s\n", iface, debugstr_w(id));
    return put_string_property(&principal->id, id);
}

static HRESULT WINAPI Principal_get_DisplayName(IPrincipal *iface, BSTR *name)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%p\n", iface, name);
    return get_string_property(principal->display_name, name);
}

static HRESULT WINAPI Principal_put_DisplayName(IPrincipal *iface, BSTR name)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%s\n", iface, debugstr_w(name));
    return put_string_property(&principal->display_name, name);
}

static HRESULT WINAPI Principal_get_UserId(IPrincipal *iface, BSTR *user_id)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%p\n", iface, user_id);
    return get_string_property(principal->user_id, user_id);
}

static HRESULT WINAPI Principal_put_UserId(IPrincipal *iface, BSTR user_id)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%s\n", iface, debugstr_w(user_id));
    return put_string_property(&principal->user_id, user_id);
}

static HRESULT WINAPI Principal_get_LogonType(IPrincipal *iface, TASK_LOGON_TYPE *logon_type)
{
    Principal *principal = impl_from_IPrincipal(iface);

    TRACE("%p,%p\n", iface, logon_type);

    if (!logon_type) return E_POINTER;

    *logon_type = principal->logon_type;
    return S_OK;
}

static HRESULT WINAPI Principal_put_LogonType(IPrincipal *iface, TASK_LOGON_TYPE logon_type)
{
    Principal *principal = impl_from_IPrincipal(iface);

    TRACE("%p,%u\n", iface, logon_type);

    if (logon_type < TASK_LOGON_NONE || logon_type > TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD)
        return E_INVALIDARG;

    principal->logon_type = logon_type;
    return S_OK;
}

static HRESULT WINAPI Principal_get_GroupId(IPrincipal *iface, BSTR *group_id)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%p\n", iface, group_id);
    return get_string_property(principal->group_id, group_id);
}

static HRESULT WINAPI Principal_put_GroupId(IPrincipal *iface, BSTR group_id)
{
    Principal *principal = impl_from_IPrincipal(iface);
    TRACE("%p,%s\n", iface, debugstr_w(group_id));
    return put_string_property(&principal->group_id, group_id);
}

static HRESULT WINAPI Principal_get_RunLevel(IPrincipal *iface, TASK_RUNLEVEL_TYPE *run_level)
{
    Principal *principal = impl_from_IPrincipal(iface);

    TRACE("%p,%p\n", iface, run_level);

    if (!run_level) return E_POINTER;

    *run_level = principal->run_level;
    return S_OK;
}

static HRESULT WINAPI Principal_put_RunLevel(IPrincipal *iface, TASK_RUNLEVEL_TYPE run_level)
{
    Principal *principal = impl_from_IPrincipal(iface);

    TRACE("%p,%u\n", iface, run_level);

    if (run_level != TASK_RUNLEVEL_LUA && run_level != TASK_RUNLEVEL_HIGHEST)
        return E_INVALIDARG;

    principal->run_level = run_level;
    return S_OK;
}

static const IPrincipalVtbl Principal_vtbl =
{
    Principal_QueryInterface,
    Principal_AddRef,
    Principal_Release,
    Principal_GetTypeInfoCount,
    Principal_GetTypeInfo,
    Principal_GetIDsOfNames,
    Principal_Invoke,
    Principal_get_Id,
    Principal_put_Id,
    Principal_get_DisplayName,
    Principal_put_DisplayName,
    Principal_get_UserId,
    Principal_put_UserId,
    Principal_get_LogonType,
    Principal_put_LogonType,
    Principal_get_GroupId,
    Principal_put_GroupId,
    Principal_get_RunLevel,
    Principal_put_RunLevel
};

static HRESULT Principal_create(IPrincipal **obj)
{
    Principal *principal;

    principal = malloc(sizeof(*principal));
    if (!principal) return E_OUTOFMEMORY;

    principal->IPrincipal_iface.lpVtbl = &Principal_vtbl;
    principal->ref = 1;
    principal->id = NULL;
    principal->display_name = NULL;
    principal->user_id = NULL;
    principal->group_id = NULL;
    principal->logon_type = TASK_LOGON_NONE;
    principal->run_level = TASK_RUNLEVEL_LUA;

    *obj = &principal->IPrincipal_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

typedef struct
{
    IExecAction IExecAction_iface;
    LONG ref;
    WCHAR *path;
    WCHAR *directory;
    WCHAR *args;
    WCHAR *id;
} ExecAction;

static inline ExecAction *impl_from_IExecAction(IExecAction *iface)
{
    return CONTAINING_RECORD(iface, ExecAction, IExecAction_iface);
}

static ULONG WINAPI ExecAction_AddRef(IExecAction *iface)
{
    ExecAction *action = impl_from_IExecAction(iface);
    return InterlockedIncrement(&action->ref);
}

static ULONG WINAPI ExecAction_Release(IExecAction *iface)
{
    ExecAction *action = impl_from_IExecAction(iface);
    LONG ref = InterlockedDecrement(&action->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        free(action->path);
        free(action->directory);
        free(action->args);
        free(action->id);
        free(action);
    }

    return ref;
}

static HRESULT WINAPI ExecAction_QueryInterface(IExecAction *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_IExecAction) ||
        IsEqualGUID(riid, &IID_IAction) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        IExecAction_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI ExecAction_GetTypeInfoCount(IExecAction *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI ExecAction_GetTypeInfo(IExecAction *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IExecAction, index, lcid, info);
}

static HRESULT WINAPI ExecAction_GetIDsOfNames(IExecAction *iface, REFIID riid, LPOLESTR *names,
                                               UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IExecAction, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI ExecAction_Invoke(IExecAction *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                        DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IExecAction, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI ExecAction_get_Id(IExecAction *iface, BSTR *id)
{
    ExecAction *action = impl_from_IExecAction(iface);

    TRACE("%p,%p\n", iface, id);

    if (!id) return E_POINTER;

    if (!action->id) *id = NULL;
    else if (!(*id = SysAllocString(action->id))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI ExecAction_put_Id(IExecAction *iface, BSTR id)
{
    ExecAction *action = impl_from_IExecAction(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(id));

    if (id && !(str = wcsdup((id)))) return E_OUTOFMEMORY;
    free(action->id);
    action->id = str;

    return S_OK;
}

static HRESULT WINAPI ExecAction_get_Type(IExecAction *iface, TASK_ACTION_TYPE *type)
{
    TRACE("%p,%p\n", iface, type);

    if (!type) return E_POINTER;

    *type = TASK_ACTION_EXEC;

    return S_OK;
}

static HRESULT WINAPI ExecAction_get_Path(IExecAction *iface, BSTR *path)
{
    ExecAction *action = impl_from_IExecAction(iface);

    TRACE("%p,%p\n", iface, path);

    if (!path) return E_POINTER;

    if (!action->path) *path = NULL;
    else if (!(*path = SysAllocString(action->path))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI ExecAction_put_Path(IExecAction *iface, BSTR path)
{
    ExecAction *action = impl_from_IExecAction(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(path));

    if (path && !(str = wcsdup((path)))) return E_OUTOFMEMORY;
    free(action->path);
    action->path = str;

    return S_OK;
}

static HRESULT WINAPI ExecAction_get_Arguments(IExecAction *iface, BSTR *arguments)
{
    ExecAction *action = impl_from_IExecAction(iface);

    TRACE("%p,%p\n", iface, arguments);

    if (!arguments) return E_POINTER;

    if (!action->args) *arguments = NULL;
    else if (!(*arguments = SysAllocString(action->args))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI ExecAction_put_Arguments(IExecAction *iface, BSTR arguments)
{
    ExecAction *action = impl_from_IExecAction(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(arguments));

    if (arguments && !(str = wcsdup((arguments)))) return E_OUTOFMEMORY;
    free(action->args);
    action->args = str;

    return S_OK;
}

static HRESULT WINAPI ExecAction_get_WorkingDirectory(IExecAction *iface, BSTR *directory)
{
    ExecAction *action = impl_from_IExecAction(iface);

    TRACE("%p,%p\n", iface, directory);

    if (!directory) return E_POINTER;

    if (!action->directory) *directory = NULL;
    else if (!(*directory = SysAllocString(action->directory))) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI ExecAction_put_WorkingDirectory(IExecAction *iface, BSTR directory)
{
    ExecAction *action = impl_from_IExecAction(iface);
    WCHAR *str = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(directory));

    if (directory && !(str = wcsdup((directory)))) return E_OUTOFMEMORY;
    free(action->directory);
    action->directory = str;

    return S_OK;
}

static const IExecActionVtbl Action_vtbl =
{
    ExecAction_QueryInterface,
    ExecAction_AddRef,
    ExecAction_Release,
    ExecAction_GetTypeInfoCount,
    ExecAction_GetTypeInfo,
    ExecAction_GetIDsOfNames,
    ExecAction_Invoke,
    ExecAction_get_Id,
    ExecAction_put_Id,
    ExecAction_get_Type,
    ExecAction_get_Path,
    ExecAction_put_Path,
    ExecAction_get_Arguments,
    ExecAction_put_Arguments,
    ExecAction_get_WorkingDirectory,
    ExecAction_put_WorkingDirectory
};

static HRESULT ExecAction_create(IExecAction **obj)
{
    ExecAction *action;

    action = malloc(sizeof(*action));
    if (!action) return E_OUTOFMEMORY;

    action->IExecAction_iface.lpVtbl = &Action_vtbl;
    action->ref = 1;
    action->path = NULL;
    action->directory = NULL;
    action->args = NULL;
    action->id = NULL;

    *obj = &action->IExecAction_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

typedef struct
{
    IActionCollection IActionCollection_iface;
    LONG ref;
    IAction **actions;
    LONG count;
    LONG size;
    WCHAR *context;
} Actions;

static inline Actions *impl_from_IActionCollection(IActionCollection *iface)
{
    return CONTAINING_RECORD(iface, Actions, IActionCollection_iface);
}

static ULONG WINAPI Actions_AddRef(IActionCollection *iface)
{
    Actions *actions = impl_from_IActionCollection(iface);
    return InterlockedIncrement(&actions->ref);
}

static ULONG WINAPI Actions_Release(IActionCollection *iface)
{
    Actions *actions = impl_from_IActionCollection(iface);
    LONG ref = InterlockedDecrement(&actions->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        while (actions->count) IAction_Release(actions->actions[--actions->count]);
        free(actions->actions);
        free(actions->context);
        free(actions);
    }

    return ref;
}

static HRESULT WINAPI Actions_QueryInterface(IActionCollection *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_IActionCollection) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        IActionCollection_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI Actions_GetTypeInfoCount(IActionCollection *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI Actions_GetTypeInfo(IActionCollection *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_IActionCollection, index, lcid, info);
}

static HRESULT WINAPI Actions_GetIDsOfNames(IActionCollection *iface, REFIID riid, LPOLESTR *names,
                                            UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_IActionCollection, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI Actions_Invoke(IActionCollection *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                     DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_IActionCollection, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI Actions_get_Count(IActionCollection *iface, LONG *count)
{
    Actions *actions = impl_from_IActionCollection(iface);

    TRACE("%p,%p\n", iface, count);

    if (!count) return E_POINTER;

    *count = actions->count;
    return S_OK;
}

static HRESULT WINAPI Actions_get_Item(IActionCollection *iface, LONG index, IAction **action)
{
    Actions *actions = impl_from_IActionCollection(iface);

    TRACE("%p,%ld,%p\n", iface, index, action);

    if (!action) return E_POINTER;
    if (index < 1 || index > actions->count) return E_INVALIDARG;

    IAction_AddRef(*action = actions->actions[index - 1]);
    return S_OK;
}

static HRESULT WINAPI Actions_get__NewEnum(IActionCollection *iface, IUnknown **penum)
{
    Actions *actions = impl_from_IActionCollection(iface);
    IDispatch **items;
    LONG i;

    TRACE("%p,%p\n", iface, penum);

    if (!penum) return E_POINTER;

    items = calloc(actions->count ? actions->count : 1, sizeof(*items));
    if (!items) return E_OUTOFMEMORY;
    for (i = 0; i < actions->count; i++)
    {
        IAction_AddRef(actions->actions[i]);
        items[i] = (IDispatch *)actions->actions[i];
    }
    return taskschd_create_enum(items, actions->count, penum);
}

static HRESULT WINAPI Actions_get_XmlText(IActionCollection *iface, BSTR *xml)
{
    FIXME("%p,%p: stub\n", iface, xml);
    return E_NOTIMPL;
}

static HRESULT WINAPI Actions_put_XmlText(IActionCollection *iface, BSTR xml)
{
    FIXME("%p,%s: stub\n", iface, debugstr_w(xml));
    return E_NOTIMPL;
}

static HRESULT WINAPI Actions_Create(IActionCollection *iface, TASK_ACTION_TYPE type, IAction **action)
{
    Actions *actions = impl_from_IActionCollection(iface);
    HRESULT hr;

    TRACE("%p,%u,%p\n", iface, type, action);

    if (!action) return E_POINTER;

    if (actions->count == actions->size)
    {
        LONG size = actions->size ? actions->size * 2 : 4;
        IAction **list = realloc(actions->actions, size * sizeof(*list));

        if (!list) return E_OUTOFMEMORY;
        actions->actions = list;
        actions->size = size;
    }

    switch (type)
    {
    case TASK_ACTION_EXEC:
        hr = ExecAction_create((IExecAction **)action);
        break;

    default:
        FIXME("unimplemented type %u\n", type);
        return E_NOTIMPL;
    }
    if (hr != S_OK) return hr;

    IAction_AddRef(actions->actions[actions->count++] = *action);
    return S_OK;
}

static HRESULT WINAPI Actions_Remove(IActionCollection *iface, VARIANT index)
{
    Actions *actions = impl_from_IActionCollection(iface);
    VARIANT var;
    LONG i;

    TRACE("%p,%s\n", iface, debugstr_variant(&index));

    VariantInit(&var);
    if (FAILED(VariantChangeType(&var, &index, 0, VT_I4)))
    {
        FIXME("unsupported index %s\n", debugstr_variant(&index));
        return E_INVALIDARG;
    }
    i = V_I4(&var);
    if (i < 1 || i > actions->count) return E_INVALIDARG;

    IAction_Release(actions->actions[i - 1]);
    memmove(&actions->actions[i - 1], &actions->actions[i], (actions->count - i) * sizeof(*actions->actions));
    actions->count--;
    return S_OK;
}

static HRESULT WINAPI Actions_Clear(IActionCollection *iface)
{
    Actions *actions = impl_from_IActionCollection(iface);

    TRACE("%p\n", iface);

    while (actions->count) IAction_Release(actions->actions[--actions->count]);
    return S_OK;
}

static HRESULT WINAPI Actions_get_Context(IActionCollection *iface, BSTR *ctx)
{
    Actions *actions = impl_from_IActionCollection(iface);
    TRACE("%p,%p\n", iface, ctx);
    return get_string_property(actions->context, ctx);
}

static HRESULT WINAPI Actions_put_Context(IActionCollection *iface, BSTR ctx)
{
    Actions *actions = impl_from_IActionCollection(iface);
    TRACE("%p,%s\n", iface, debugstr_w(ctx));
    return put_string_property(&actions->context, ctx);
}

static const IActionCollectionVtbl Actions_vtbl =
{
    Actions_QueryInterface,
    Actions_AddRef,
    Actions_Release,
    Actions_GetTypeInfoCount,
    Actions_GetTypeInfo,
    Actions_GetIDsOfNames,
    Actions_Invoke,
    Actions_get_Count,
    Actions_get_Item,
    Actions_get__NewEnum,
    Actions_get_XmlText,
    Actions_put_XmlText,
    Actions_Create,
    Actions_Remove,
    Actions_Clear,
    Actions_get_Context,
    Actions_put_Context
};

static HRESULT Actions_create(IActionCollection **obj)
{
    Actions *actions;

    actions = malloc(sizeof(*actions));
    if (!actions) return E_OUTOFMEMORY;

    actions->IActionCollection_iface.lpVtbl = &Actions_vtbl;
    actions->ref = 1;
    actions->actions = NULL;
    actions->count = 0;
    actions->size = 0;
    actions->context = NULL;

    *obj = &actions->IActionCollection_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

typedef struct
{
    ITaskDefinition ITaskDefinition_iface;
    LONG ref;
    IRegistrationInfo *reginfo;
    ITaskSettings *taskset;
    ITriggerCollection *triggers;
    IPrincipal *principal;
    IActionCollection *actions;
    BSTR data;
} TaskDefinition;

static inline TaskDefinition *impl_from_ITaskDefinition(ITaskDefinition *iface)
{
    return CONTAINING_RECORD(iface, TaskDefinition, ITaskDefinition_iface);
}

static ULONG WINAPI TaskDefinition_AddRef(ITaskDefinition *iface)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    return InterlockedIncrement(&taskdef->ref);
}

static ULONG WINAPI TaskDefinition_Release(ITaskDefinition *iface)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    LONG ref = InterlockedDecrement(&taskdef->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);

        if (taskdef->reginfo)
            IRegistrationInfo_Release(taskdef->reginfo);
        if (taskdef->taskset)
            ITaskSettings_Release(taskdef->taskset);
        if (taskdef->triggers)
            ITriggerCollection_Release(taskdef->triggers);
        if (taskdef->principal)
            IPrincipal_Release(taskdef->principal);
        if (taskdef->actions)
            IActionCollection_Release(taskdef->actions);
        if (taskdef->data)
            SysFreeString(taskdef->data);

        free(taskdef);
    }

    return ref;
}

static HRESULT WINAPI TaskDefinition_QueryInterface(ITaskDefinition *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_ITaskDefinition) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        ITaskDefinition_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI TaskDefinition_GetTypeInfoCount(ITaskDefinition *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI TaskDefinition_GetTypeInfo(ITaskDefinition *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_ITaskDefinition, index, lcid, info);
}

static HRESULT WINAPI TaskDefinition_GetIDsOfNames(ITaskDefinition *iface, REFIID riid, LPOLESTR *names,
                                                   UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_ITaskDefinition, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI TaskDefinition_Invoke(ITaskDefinition *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                            DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_ITaskDefinition, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI TaskDefinition_get_RegistrationInfo(ITaskDefinition *iface, IRegistrationInfo **info)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    HRESULT hr;

    TRACE("%p,%p\n", iface, info);

    if (!info) return E_POINTER;

    if (!taskdef->reginfo)
    {
        hr = RegistrationInfo_create(&taskdef->reginfo);
        if (hr != S_OK) return hr;
    }

    IRegistrationInfo_AddRef(taskdef->reginfo);
    *info = taskdef->reginfo;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_put_RegistrationInfo(ITaskDefinition *iface, IRegistrationInfo *info)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);

    TRACE("%p,%p\n", iface, info);

    if (!info) return E_POINTER;

    if (taskdef->reginfo)
        IRegistrationInfo_Release(taskdef->reginfo);

    IRegistrationInfo_AddRef(info);
    taskdef->reginfo = info;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_get_Triggers(ITaskDefinition *iface, ITriggerCollection **triggers)
{
    TaskDefinition *This = impl_from_ITaskDefinition(iface);

    TRACE("%p,%p\n", This, triggers);

    if (!This->triggers)
    {
        trigger_collection *collection;

        collection = malloc(sizeof(*collection));
        if (!collection) return E_OUTOFMEMORY;

        collection->ITriggerCollection_iface.lpVtbl = &TriggerCollection_vtbl;
        collection->ref = 1;
        collection->triggers = NULL;
        collection->count = 0;
        collection->size = 0;
        This->triggers = &collection->ITriggerCollection_iface;
    }

    ITriggerCollection_AddRef(*triggers = This->triggers);
    return S_OK;
}

static HRESULT WINAPI TaskDefinition_put_Triggers(ITaskDefinition *iface, ITriggerCollection *triggers)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);

    TRACE("%p,%p\n", iface, triggers);

    if (!triggers) return E_POINTER;

    if (taskdef->triggers)
        ITriggerCollection_Release(taskdef->triggers);

    ITriggerCollection_AddRef(triggers);
    taskdef->triggers = triggers;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_get_Settings(ITaskDefinition *iface, ITaskSettings **settings)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    HRESULT hr;

    TRACE("%p,%p\n", iface, settings);

    if (!settings) return E_POINTER;

    if (!taskdef->taskset)
    {
        hr = TaskSettings_create(&taskdef->taskset);
        if (hr != S_OK) return hr;
    }

    ITaskSettings_AddRef(taskdef->taskset);
    *settings = taskdef->taskset;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_put_Settings(ITaskDefinition *iface, ITaskSettings *settings)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);

    TRACE("%p,%p\n", iface, settings);

    if (!settings) return E_POINTER;

    if (taskdef->taskset)
        ITaskSettings_Release(taskdef->taskset);

    ITaskSettings_AddRef(settings);
    taskdef->taskset = settings;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_get_Data(ITaskDefinition *iface, BSTR *data)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);

    TRACE("%p,%p\n", iface, data);

    if (!data) return E_POINTER;

    if (!taskdef->data)
        *data = NULL;
    else
    {
        *data = SysAllocString(taskdef->data);
        if (!*data) return E_OUTOFMEMORY;
    }

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_put_Data(ITaskDefinition *iface, BSTR data)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    BSTR copy = NULL;

    TRACE("%p,%s\n", iface, debugstr_w(data));

    if (data)
    {
        copy = SysAllocString(data);
        if (!copy) return E_OUTOFMEMORY;
    }

    if (taskdef->data)
        SysFreeString(taskdef->data);

    taskdef->data = copy;
    return S_OK;
}

static HRESULT WINAPI TaskDefinition_get_Principal(ITaskDefinition *iface, IPrincipal **principal)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    HRESULT hr;

    TRACE("%p,%p\n", iface, principal);

    if (!principal) return E_POINTER;

    if (!taskdef->principal)
    {
        hr = Principal_create(&taskdef->principal);
        if (hr != S_OK) return hr;
    }

    IPrincipal_AddRef(taskdef->principal);
    *principal = taskdef->principal;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_put_Principal(ITaskDefinition *iface, IPrincipal *principal)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);

    TRACE("%p,%p\n", iface, principal);

    if (!principal) return E_POINTER;

    if (taskdef->principal)
        IPrincipal_Release(taskdef->principal);

    IPrincipal_AddRef(principal);
    taskdef->principal = principal;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_get_Actions(ITaskDefinition *iface, IActionCollection **actions)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    HRESULT hr;

    TRACE("%p,%p\n", iface, actions);

    if (!actions) return E_POINTER;

    if (!taskdef->actions)
    {
        hr = Actions_create(&taskdef->actions);
        if (hr != S_OK) return hr;
    }

    IActionCollection_AddRef(taskdef->actions);
    *actions = taskdef->actions;

    return S_OK;
}

static HRESULT WINAPI TaskDefinition_put_Actions(ITaskDefinition *iface, IActionCollection *actions)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);

    TRACE("%p,%p\n", iface, actions);

    if (!actions) return E_POINTER;

    if (taskdef->actions)
        IActionCollection_Release(taskdef->actions);

    IActionCollection_AddRef(actions);
    taskdef->actions = actions;

    return S_OK;
}

static int xml_indent;

static inline void push_indent(void)
{
    xml_indent += 2;
}

static inline void pop_indent(void)
{
    xml_indent -= 2;
}

static inline HRESULT write_stringW(IStream *stream, const WCHAR *str)
{
    return IStream_Write(stream, str, lstrlenW(str) * sizeof(WCHAR), NULL);
}

static void write_indent(IStream *stream)
{
    int i;
    for (i = 0; i < xml_indent; i += 2)
        write_stringW(stream, L"  ");
}

static inline HRESULT write_empty_element(IStream *stream, const WCHAR *name)
{
    write_indent(stream);
    write_stringW(stream, L"<");
    write_stringW(stream, name);
    return write_stringW(stream, L"/>\n");
}

static inline HRESULT write_element(IStream *stream, const WCHAR *name)
{
    write_indent(stream);
    write_stringW(stream, L"<");
    write_stringW(stream, name);
    return write_stringW(stream, L">\n");
}

static inline HRESULT write_element_end(IStream *stream, const WCHAR *name)
{
    write_indent(stream);
    write_stringW(stream, L"</");
    write_stringW(stream, name);
    return write_stringW(stream, L">\n");
}

static inline HRESULT write_text_value(IStream *stream, const WCHAR *name, const WCHAR *value)
{
    write_indent(stream);
    write_stringW(stream, L"<");
    write_stringW(stream, name);
    write_stringW(stream, L">");
    write_stringW(stream, value);
    write_stringW(stream, L"</");
    write_stringW(stream, name);
    return write_stringW(stream, L">\n");
}

static HRESULT write_bool_value(IStream *stream, const WCHAR *name, VARIANT_BOOL value)
{
    return write_text_value(stream, name, value ? L"true" : L"false");
}

static HRESULT write_int_value(IStream *stream, const WCHAR *name, int val)
{
    WCHAR s[32];

    swprintf(s, ARRAY_SIZE(s), L"%d", val);
    return write_text_value(stream, name, s);
}

static HRESULT write_task_attributes(IStream *stream, ITaskDefinition *taskdef)
{
    HRESULT hr;
    ITaskSettings *taskset;
    TASK_COMPATIBILITY level;
    const WCHAR *compatibility;

    hr = ITaskDefinition_get_Settings(taskdef, &taskset);
    if (hr != S_OK) return hr;

    hr = ITaskSettings_get_Compatibility(taskset, &level);
    if (hr != S_OK) level = TASK_COMPATIBILITY_V2_1;

    ITaskSettings_Release(taskset);

    switch (level)
    {
    case TASK_COMPATIBILITY_AT:
        compatibility = L"1.0";
        break;
    case TASK_COMPATIBILITY_V1:
        compatibility = L"1.1";
        break;
    case TASK_COMPATIBILITY_V2:
        compatibility = L"1.2";
        break;
    default:
        compatibility = L"1.3";
        break;
    }

    write_stringW(stream, L"<Task version=\"");
    write_stringW(stream, compatibility);
    write_stringW(stream, L"\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">");
    return write_stringW(stream, L"\n");
}

static HRESULT write_registration_info(IStream *stream, IRegistrationInfo *reginfo)
{
    HRESULT hr;
    BSTR bstr;
    VARIANT var;

    if (!reginfo)
        return write_empty_element(stream, L"RegistrationInfo");

    hr = write_element(stream, L"RegistrationInfo");
    if (hr != S_OK) return hr;

    push_indent();

    hr = IRegistrationInfo_get_Source(reginfo, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"Source", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IRegistrationInfo_get_Date(reginfo, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"Date", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IRegistrationInfo_get_Author(reginfo, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"Author", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IRegistrationInfo_get_Version(reginfo, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"Version", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IRegistrationInfo_get_Description(reginfo, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"Description", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IRegistrationInfo_get_Documentation(reginfo, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"Documentation", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IRegistrationInfo_get_URI(reginfo, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"URI", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IRegistrationInfo_get_SecurityDescriptor(reginfo, &var);
    if (hr == S_OK)
    {
        if (V_VT(&var) == VT_BSTR)
        {
            hr = write_text_value(stream, L"SecurityDescriptor", V_BSTR(&var));
            VariantClear(&var);
            if (hr != S_OK) return hr;
        }
        else
            FIXME("SecurityInfo variant type %d is not supported\n", V_VT(&var));
    }

    pop_indent();

    return write_element_end(stream, L"RegistrationInfo");
}

static HRESULT write_principal(IStream *stream, IPrincipal *principal)
{
    HRESULT hr;
    BSTR bstr;
    TASK_LOGON_TYPE logon;
    TASK_RUNLEVEL_TYPE level;

    if (!principal)
        return write_empty_element(stream, L"Principals");

    hr = write_element(stream, L"Principals");
    if (hr != S_OK) return hr;

    push_indent();

    hr = IPrincipal_get_Id(principal, &bstr);
    if (hr == S_OK && bstr)
    {
        write_indent(stream);
        write_stringW(stream, L"<Principal id=\"");
        write_stringW(stream, bstr);
        write_stringW(stream, L"\">\n");
        SysFreeString(bstr);
    }
    else
        write_element(stream, L"Principal");

    push_indent();

    hr = IPrincipal_get_GroupId(principal, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"GroupId", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IPrincipal_get_DisplayName(principal, &bstr);
    if (hr == S_OK && bstr)
    {
        hr = write_text_value(stream, L"DisplayName", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IPrincipal_get_UserId(principal, &bstr);
    if (hr == S_OK && lstrlenW(bstr))
    {
        hr = write_text_value(stream, L"UserId", bstr);
        SysFreeString(bstr);
        if (hr != S_OK) return hr;
    }
    hr = IPrincipal_get_RunLevel(principal, &level);
    if (hr == S_OK)
    {
        const WCHAR *level_str = NULL;

        switch (level)
        {
        case TASK_RUNLEVEL_HIGHEST:
            level_str = L"HighestAvailable";
            break;
        case TASK_RUNLEVEL_LUA:
            level_str = L"LeastPrivilege";
            break;
        default:
            FIXME("Principal run level %d\n", level);
            break;
        }

        if (level_str)
        {
            hr = write_text_value(stream, L"RunLevel", level_str);
            if (hr != S_OK) return hr;
        }
    }
    hr = IPrincipal_get_LogonType(principal, &logon);
    if (hr == S_OK)
    {
        const WCHAR *logon_str = NULL;

        switch (logon)
        {
        case TASK_LOGON_PASSWORD:
            logon_str = L"Password";
            break;
        case TASK_LOGON_S4U:
            logon_str = L"S4U";
            break;
        case TASK_LOGON_INTERACTIVE_TOKEN:
            logon_str = L"InteractiveToken";
            break;
        case TASK_LOGON_SERVICE_ACCOUNT:
            logon_str = L"ServiceAccount";
            break;
        case TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD:
            logon_str = L"InteractiveTokenOrPassword";
            break;
        case TASK_LOGON_NONE:
            break;
        default:
            FIXME("Principal logon type %d\n", logon);
            break;
        }

        if (logon_str)
        {
            hr = write_text_value(stream, L"LogonType", logon_str);
            if (hr != S_OK) return hr;
        }
    }

    pop_indent();
    write_element_end(stream, L"Principal");

    pop_indent();
    return write_element_end(stream, L"Principals");
}

const WCHAR *string_from_instances_policy(TASK_INSTANCES_POLICY policy)
{
    switch (policy)
    {
        case TASK_INSTANCES_PARALLEL:       return L"Parallel";
        case TASK_INSTANCES_QUEUE:          return L"Queue";
        case TASK_INSTANCES_IGNORE_NEW:     return L"IgnoreNew";
        case TASK_INSTANCES_STOP_EXISTING : return L"StopExisting";
    }
    return L"<error>";
}

static HRESULT write_settings(IStream *stream, ITaskSettings *settings)
{
    INetworkSettings *network_settings;
    TASK_INSTANCES_POLICY policy;
    IIdleSettings *idle_settings;
    VARIANT_BOOL bval;
    HRESULT hr;
    INT ival;
    BSTR s;

    if (!settings)
        return write_empty_element(stream, L"Settings");

    if (FAILED(hr = write_element(stream, L"Settings")))
        return hr;

    push_indent();

#define WRITE_BOOL_OPTION(name) \
    { \
        if (FAILED(hr = ITaskSettings_get_##name(settings, &bval))) \
            return hr; \
        if (FAILED(hr = write_bool_value(stream, L ## #name, bval))) \
            return hr; \
    }


    if (FAILED(hr = ITaskSettings_get_AllowDemandStart(settings, &bval)))
        return hr;
    if (FAILED(hr = write_bool_value(stream, L"AllowStartOnDemand", bval)))
        return hr;

    if (SUCCEEDED(hr = TaskSettings_get_RestartInterval(settings, &s)) && s)
    {
        FIXME("RestartInterval not handled.\n");
        SysFreeString(s);
    }
    if (FAILED(hr = ITaskSettings_get_MultipleInstances(settings, &policy)))
        return hr;
    if (FAILED(hr = write_text_value(stream, L"MultipleInstancesPolicy", string_from_instances_policy(policy))))
        return hr;

    WRITE_BOOL_OPTION(DisallowStartIfOnBatteries);
    WRITE_BOOL_OPTION(StopIfGoingOnBatteries);
    WRITE_BOOL_OPTION(AllowHardTerminate);
    WRITE_BOOL_OPTION(StartWhenAvailable);
    WRITE_BOOL_OPTION(RunOnlyIfNetworkAvailable);
    WRITE_BOOL_OPTION(WakeToRun);
    WRITE_BOOL_OPTION(Enabled);
    WRITE_BOOL_OPTION(Hidden);

    if (SUCCEEDED(hr = TaskSettings_get_DeleteExpiredTaskAfter(settings, &s)) && s)
    {
        hr = write_text_value(stream, L"DeleteExpiredTaskAfter", s);
        SysFreeString(s);
        if (FAILED(hr))
            return hr;
    }
    if (SUCCEEDED(hr = TaskSettings_get_IdleSettings(settings, &idle_settings)))
    {
        WARN("IdleSettings not handled.\n");
        IIdleSettings_Release(idle_settings);
    }
    if (SUCCEEDED(hr = TaskSettings_get_NetworkSettings(settings, &network_settings)))
    {
        FIXME("NetworkSettings not handled.\n");
        INetworkSettings_Release(network_settings);
    }
    if (SUCCEEDED(hr = TaskSettings_get_ExecutionTimeLimit(settings, &s)) && s)
    {
        hr = write_text_value(stream, L"ExecutionTimeLimit", s);
        SysFreeString(s);
        if (FAILED(hr))
            return hr;
    }
    if (FAILED(hr = ITaskSettings_get_Priority(settings, &ival)))
        return hr;
    if (FAILED(hr = write_int_value(stream, L"Priority", ival)))
        return hr;

    WRITE_BOOL_OPTION(RunOnlyIfIdle);
#undef WRITE_BOOL_OPTION

    pop_indent();
    write_element_end(stream, L"Settings");

    return S_OK;
}

static HRESULT write_escaped_string(IStream *stream, const WCHAR *str)
{
    const WCHAR *p, *entity;
    HRESULT hr = S_OK;

    for (p = str; *p; p++)
    {
        switch (*p)
        {
        case '&': entity = L"&amp;"; break;
        case '<': entity = L"&lt;"; break;
        case '>': entity = L"&gt;"; break;
        case '"': entity = L"&quot;"; break;
        default: continue;
        }
        if (p > str) IStream_Write(stream, str, (p - str) * sizeof(WCHAR), NULL);
        hr = write_stringW(stream, entity);
        str = p + 1;
    }
    if (p > str) hr = IStream_Write(stream, str, (p - str) * sizeof(WCHAR), NULL);
    return hr;
}

static HRESULT write_escaped_value(IStream *stream, const WCHAR *name, const WCHAR *value)
{
    write_indent(stream);
    write_stringW(stream, L"<");
    write_stringW(stream, name);
    write_stringW(stream, L">");
    write_escaped_string(stream, value);
    write_stringW(stream, L"</");
    write_stringW(stream, name);
    return write_stringW(stream, L">\n");
}

/* <name> or <name id="..."> */
static HRESULT write_element_with_id(IStream *stream, const WCHAR *name, const WCHAR *id)
{
    if (!id || !*id) return write_element(stream, name);

    write_indent(stream);
    write_stringW(stream, L"<");
    write_stringW(stream, name);
    write_stringW(stream, L" id=\"");
    write_escaped_string(stream, id);
    return write_stringW(stream, L"\">\n");
}

/* writes a string property that a getter returns, if it is set */
static HRESULT write_bstr_value(IStream *stream, const WCHAR *name, HRESULT hr, BSTR bstr)
{
    if (hr == S_OK && bstr && *bstr) hr = write_escaped_value(stream, name, bstr);
    else hr = S_OK;
    SysFreeString(bstr);
    return hr;
}

static HRESULT write_repetition(IStream *stream, ITrigger *trigger)
{
    IRepetitionPattern *repetition;
    BSTR interval = NULL, duration = NULL;
    VARIANT_BOOL stop = VARIANT_FALSE;
    HRESULT hr;

    if (ITrigger_get_Repetition(trigger, &repetition) != S_OK) return S_OK;

    if (IRepetitionPattern_get_Interval(repetition, &interval) == S_OK && interval && *interval)
    {
        if (IRepetitionPattern_get_Duration(repetition, &duration) != S_OK) duration = NULL;
        IRepetitionPattern_get_StopAtDurationEnd(repetition, &stop);

        write_element(stream, L"Repetition");
        push_indent();
        write_escaped_value(stream, L"Interval", interval);
        if (duration && *duration) write_escaped_value(stream, L"Duration", duration);
        write_bool_value(stream, L"StopAtDurationEnd", stop);
        pop_indent();
        hr = write_element_end(stream, L"Repetition");
    }
    else
        hr = S_OK;

    SysFreeString(interval);
    SysFreeString(duration);
    IRepetitionPattern_Release(repetition);
    return hr;
}

static const WCHAR *const day_names[7] =
{
    L"Sunday", L"Monday", L"Tuesday", L"Wednesday", L"Thursday", L"Friday", L"Saturday"
};

static const WCHAR *const month_names[12] =
{
    L"January", L"February", L"March", L"April", L"May", L"June", L"July", L"August", L"September", L"October",
    L"November", L"December"
};

static const struct { const WCHAR *name; TASK_SESSION_STATE_CHANGE_TYPE type; } state_changes[] =
{
    { L"ConsoleConnect", TASK_CONSOLE_CONNECT },
    { L"ConsoleDisconnect", TASK_CONSOLE_DISCONNECT },
    { L"RemoteConnect", TASK_REMOTE_CONNECT },
    { L"RemoteDisconnect", TASK_REMOTE_DISCONNECT },
    { L"SessionLock", TASK_SESSION_LOCK },
    { L"SessionUnlock", TASK_SESSION_UNLOCK },
};

/* <name><Monday /><Friday /></name>: the members of a set, in the order of the schema */
static HRESULT write_name_set(IStream *stream, const WCHAR *name, const WCHAR *const *names, unsigned int count,
                              unsigned int mask)
{
    unsigned int i;

    if (!(mask & ((1u << count) - 1))) return write_empty_element(stream, name);

    write_element(stream, name);
    push_indent();
    for (i = 0; i < count; i++)
        if (mask & (1u << i)) write_empty_element(stream, names[i]);
    pop_indent();
    return write_element_end(stream, name);
}

/* <name><item>1</item><item>Last</item></name>: a set of numbers, 1 for bit 0, and the last one */
static HRESULT write_number_set(IStream *stream, const WCHAR *name, const WCHAR *item, unsigned int count,
                                unsigned int mask, BOOL last)
{
    unsigned int i;

    if (!(mask & (count >= 32 ? ~0u : (1u << count) - 1)) && !last) return write_empty_element(stream, name);

    write_element(stream, name);
    push_indent();
    for (i = 0; i < count; i++)
        if (mask & (1u << i)) write_int_value(stream, item, i + 1);
    if (last) write_text_value(stream, item, L"Last");
    pop_indent();
    return write_element_end(stream, name);
}

/* the ScheduleByWeek, ScheduleByMonth or ScheduleByMonthDayOfWeek element of a calendar trigger */
static HRESULT write_calendar_schedule(IStream *stream, ITrigger *trigger, TASK_TRIGGER_TYPE2 type)
{
    switch (type)
    {
    case TASK_TRIGGER_WEEKLY:
    {
        IWeeklyTrigger *weekly;
        short days = 0, weeks = 1;

        if (ITrigger_QueryInterface(trigger, &IID_IWeeklyTrigger, (void **)&weekly) != S_OK) break;
        IWeeklyTrigger_get_DaysOfWeek(weekly, &days);
        IWeeklyTrigger_get_WeeksInterval(weekly, &weeks);
        IWeeklyTrigger_Release(weekly);

        write_element(stream, L"ScheduleByWeek");
        push_indent();
        write_name_set(stream, L"DaysOfWeek", day_names, 7, days);
        write_int_value(stream, L"WeeksInterval", weeks);
        pop_indent();
        return write_element_end(stream, L"ScheduleByWeek");
    }
    case TASK_TRIGGER_MONTHLY:
    {
        IMonthlyTrigger *monthly;
        LONG days = 0;
        short months = 0;
        VARIANT_BOOL last = VARIANT_FALSE;

        if (ITrigger_QueryInterface(trigger, &IID_IMonthlyTrigger, (void **)&monthly) != S_OK) break;
        IMonthlyTrigger_get_DaysOfMonth(monthly, &days);
        IMonthlyTrigger_get_MonthsOfYear(monthly, &months);
        IMonthlyTrigger_get_RunOnLastDayOfMonth(monthly, &last);
        IMonthlyTrigger_Release(monthly);

        write_element(stream, L"ScheduleByMonth");
        push_indent();
        write_number_set(stream, L"DaysOfMonth", L"Day", 31, days, last != VARIANT_FALSE);
        write_name_set(stream, L"Months", month_names, 12, months);
        pop_indent();
        return write_element_end(stream, L"ScheduleByMonth");
    }
    case TASK_TRIGGER_MONTHLYDOW:
    {
        IMonthlyDOWTrigger *dow;
        short days = 0, weeks = 0, months = 0;
        VARIANT_BOOL last = VARIANT_FALSE;

        if (ITrigger_QueryInterface(trigger, &IID_IMonthlyDOWTrigger, (void **)&dow) != S_OK) break;
        IMonthlyDOWTrigger_get_DaysOfWeek(dow, &days);
        IMonthlyDOWTrigger_get_WeeksOfMonth(dow, &weeks);
        IMonthlyDOWTrigger_get_MonthsOfYear(dow, &months);
        IMonthlyDOWTrigger_get_RunOnLastWeekOfMonth(dow, &last);
        IMonthlyDOWTrigger_Release(dow);

        write_element(stream, L"ScheduleByMonthDayOfWeek");
        push_indent();
        write_number_set(stream, L"Weeks", L"Week", 4, weeks, last != VARIANT_FALSE);
        write_name_set(stream, L"DaysOfWeek", day_names, 7, days);
        write_name_set(stream, L"Months", month_names, 12, months);
        pop_indent();
        return write_element_end(stream, L"ScheduleByMonthDayOfWeek");
    }
    default:
        break;
    }
    return S_OK;
}

static HRESULT write_trigger(IStream *stream, ITrigger *trigger)
{
    TASK_TRIGGER_TYPE2 type;
    const WCHAR *name;
    VARIANT_BOOL enabled;
    BSTR bstr = NULL;
    HRESULT hr;

    hr = ITrigger_get_Type(trigger, &type);
    if (hr != S_OK)
    {
        FIXME("trigger %p has no type\n", trigger);
        return S_OK;
    }

    switch (type)
    {
    case TASK_TRIGGER_TIME: name = L"TimeTrigger"; break;
    case TASK_TRIGGER_DAILY:
    case TASK_TRIGGER_WEEKLY:
    case TASK_TRIGGER_MONTHLY:
    case TASK_TRIGGER_MONTHLYDOW: name = L"CalendarTrigger"; break;
    case TASK_TRIGGER_BOOT: name = L"BootTrigger"; break;
    case TASK_TRIGGER_LOGON: name = L"LogonTrigger"; break;
    case TASK_TRIGGER_REGISTRATION: name = L"RegistrationTrigger"; break;
    case TASK_TRIGGER_IDLE: name = L"IdleTrigger"; break;
    case TASK_TRIGGER_EVENT: name = L"EventTrigger"; break;
    case TASK_TRIGGER_SESSION_STATE_CHANGE: name = L"SessionStateChangeTrigger"; break;
    default:
        FIXME("trigger type %d\n", type);
        return S_OK;
    }

    if (ITrigger_get_Id(trigger, &bstr) != S_OK) bstr = NULL;
    hr = write_element_with_id(stream, name, bstr);
    SysFreeString(bstr);
    if (hr != S_OK) return hr;

    push_indent();

    write_repetition(stream, trigger);
    hr = ITrigger_get_StartBoundary(trigger, &bstr);
    write_bstr_value(stream, L"StartBoundary", hr, hr == S_OK ? bstr : NULL);
    hr = ITrigger_get_EndBoundary(trigger, &bstr);
    write_bstr_value(stream, L"EndBoundary", hr, hr == S_OK ? bstr : NULL);
    hr = ITrigger_get_ExecutionTimeLimit(trigger, &bstr);
    write_bstr_value(stream, L"ExecutionTimeLimit", hr, hr == S_OK ? bstr : NULL);
    if (ITrigger_get_Enabled(trigger, &enabled) == S_OK)
        write_bool_value(stream, L"Enabled", enabled);

    switch (type)
    {
    case TASK_TRIGGER_TIME:
    {
        ITimeTrigger *time_trigger;

        if (ITrigger_QueryInterface(trigger, &IID_ITimeTrigger, (void **)&time_trigger) == S_OK)
        {
            hr = ITimeTrigger_get_RandomDelay(time_trigger, &bstr);
            write_bstr_value(stream, L"RandomDelay", hr, hr == S_OK ? bstr : NULL);
            ITimeTrigger_Release(time_trigger);
        }
        break;
    }
    case TASK_TRIGGER_WEEKLY:
    case TASK_TRIGGER_MONTHLY:
    case TASK_TRIGGER_MONTHLYDOW:
    {
        IWeeklyTrigger *weekly;
        IMonthlyTrigger *monthly;
        IMonthlyDOWTrigger *monthly_dow;

        /* RandomDelay comes before the schedule, as in the XML Windows writes */
        if (type == TASK_TRIGGER_WEEKLY && ITrigger_QueryInterface(trigger, &IID_IWeeklyTrigger, (void **)&weekly) == S_OK)
        {
            hr = IWeeklyTrigger_get_RandomDelay(weekly, &bstr);
            write_bstr_value(stream, L"RandomDelay", hr, hr == S_OK ? bstr : NULL);
            IWeeklyTrigger_Release(weekly);
        }
        else if (type == TASK_TRIGGER_MONTHLY &&
                 ITrigger_QueryInterface(trigger, &IID_IMonthlyTrigger, (void **)&monthly) == S_OK)
        {
            hr = IMonthlyTrigger_get_RandomDelay(monthly, &bstr);
            write_bstr_value(stream, L"RandomDelay", hr, hr == S_OK ? bstr : NULL);
            IMonthlyTrigger_Release(monthly);
        }
        else if (type == TASK_TRIGGER_MONTHLYDOW &&
                 ITrigger_QueryInterface(trigger, &IID_IMonthlyDOWTrigger, (void **)&monthly_dow) == S_OK)
        {
            hr = IMonthlyDOWTrigger_get_RandomDelay(monthly_dow, &bstr);
            write_bstr_value(stream, L"RandomDelay", hr, hr == S_OK ? bstr : NULL);
            IMonthlyDOWTrigger_Release(monthly_dow);
        }
        write_calendar_schedule(stream, trigger, type);
        break;
    }
    case TASK_TRIGGER_EVENT:
    {
        IEventTrigger *event_trigger;

        if (ITrigger_QueryInterface(trigger, &IID_IEventTrigger, (void **)&event_trigger) == S_OK)
        {
            hr = IEventTrigger_get_Subscription(event_trigger, &bstr);
            write_bstr_value(stream, L"Subscription", hr, hr == S_OK ? bstr : NULL);
            hr = IEventTrigger_get_Delay(event_trigger, &bstr);
            write_bstr_value(stream, L"Delay", hr, hr == S_OK ? bstr : NULL);
            IEventTrigger_Release(event_trigger);
        }
        break;
    }
    case TASK_TRIGGER_SESSION_STATE_CHANGE:
    {
        ISessionStateChangeTrigger *session;
        TASK_SESSION_STATE_CHANGE_TYPE change = 0;
        unsigned int i;

        if (ITrigger_QueryInterface(trigger, &IID_ISessionStateChangeTrigger, (void **)&session) == S_OK)
        {
            hr = ISessionStateChangeTrigger_get_UserId(session, &bstr);
            write_bstr_value(stream, L"UserId", hr, hr == S_OK ? bstr : NULL);
            hr = ISessionStateChangeTrigger_get_Delay(session, &bstr);
            write_bstr_value(stream, L"Delay", hr, hr == S_OK ? bstr : NULL);
            ISessionStateChangeTrigger_get_StateChange(session, &change);
            ISessionStateChangeTrigger_Release(session);
            for (i = 0; i < ARRAY_SIZE(state_changes); i++)
                if (state_changes[i].type == change)
                    write_text_value(stream, L"StateChange", state_changes[i].name);
        }
        break;
    }
    case TASK_TRIGGER_DAILY:
    {
        IDailyTrigger *daily_trigger;
        short days = 1;

        if (ITrigger_QueryInterface(trigger, &IID_IDailyTrigger, (void **)&daily_trigger) == S_OK)
        {
            hr = IDailyTrigger_get_RandomDelay(daily_trigger, &bstr);
            write_bstr_value(stream, L"RandomDelay", hr, hr == S_OK ? bstr : NULL);
            IDailyTrigger_get_DaysInterval(daily_trigger, &days);
            IDailyTrigger_Release(daily_trigger);
        }
        write_element(stream, L"ScheduleByDay");
        push_indent();
        write_int_value(stream, L"DaysInterval", days);
        pop_indent();
        write_element_end(stream, L"ScheduleByDay");
        break;
    }
    case TASK_TRIGGER_BOOT:
    {
        IBootTrigger *boot_trigger;

        if (ITrigger_QueryInterface(trigger, &IID_IBootTrigger, (void **)&boot_trigger) == S_OK)
        {
            hr = IBootTrigger_get_Delay(boot_trigger, &bstr);
            write_bstr_value(stream, L"Delay", hr, hr == S_OK ? bstr : NULL);
            IBootTrigger_Release(boot_trigger);
        }
        break;
    }
    case TASK_TRIGGER_LOGON:
    {
        ILogonTrigger *logon_trigger;

        if (ITrigger_QueryInterface(trigger, &IID_ILogonTrigger, (void **)&logon_trigger) == S_OK)
        {
            hr = ILogonTrigger_get_UserId(logon_trigger, &bstr);
            write_bstr_value(stream, L"UserId", hr, hr == S_OK ? bstr : NULL);
            hr = ILogonTrigger_get_Delay(logon_trigger, &bstr);
            write_bstr_value(stream, L"Delay", hr, hr == S_OK ? bstr : NULL);
            ILogonTrigger_Release(logon_trigger);
        }
        break;
    }
    case TASK_TRIGGER_REGISTRATION:
    {
        IRegistrationTrigger *registration_trigger;

        if (ITrigger_QueryInterface(trigger, &IID_IRegistrationTrigger, (void **)&registration_trigger) == S_OK)
        {
            hr = IRegistrationTrigger_get_Delay(registration_trigger, &bstr);
            write_bstr_value(stream, L"Delay", hr, hr == S_OK ? bstr : NULL);
            IRegistrationTrigger_Release(registration_trigger);
        }
        break;
    }
    default:
        break;
    }

    if (is_sched_trigger(trigger) && trigger_get_extra(trigger))
    {
        /* one line per element that was kept as text */
        WCHAR *text = wcsdup(trigger_get_extra(trigger)), *line, *nl;

        for (line = text; line && *line; line = nl ? nl + 1 : NULL)
        {
            if ((nl = wcschr(line, '\n'))) *nl = 0;
            write_indent(stream);
            write_stringW(stream, line);
            write_stringW(stream, L"\n");
        }
        free(text);
    }

    pop_indent();
    return write_element_end(stream, name);
}

static HRESULT write_triggers(IStream *stream, ITriggerCollection *triggers)
{
    ITrigger *trigger;
    LONG count, i;
    HRESULT hr;

    if (!triggers)
        return write_empty_element(stream, L"Triggers");

    hr = ITriggerCollection_get_Count(triggers, &count);
    if (hr != S_OK || !count) return S_OK;

    hr = write_element(stream, L"Triggers");
    if (hr != S_OK) return hr;

    push_indent();
    for (i = 1; i <= count; i++)
    {
        if (ITriggerCollection_get_Item(triggers, i, &trigger) != S_OK) continue;
        hr = write_trigger(stream, trigger);
        ITrigger_Release(trigger);
        if (hr != S_OK) return hr;
    }
    pop_indent();

    return write_element_end(stream, L"Triggers");
}

static HRESULT write_exec_action(IStream *stream, IExecAction *action)
{
    BSTR bstr = NULL;
    HRESULT hr;

    if (IExecAction_get_Id(action, &bstr) != S_OK) bstr = NULL;
    hr = write_element_with_id(stream, L"Exec", bstr);
    SysFreeString(bstr);
    if (hr != S_OK) return hr;

    push_indent();
    hr = IExecAction_get_Path(action, &bstr);
    write_bstr_value(stream, L"Command", hr, hr == S_OK ? bstr : NULL);
    hr = IExecAction_get_Arguments(action, &bstr);
    write_bstr_value(stream, L"Arguments", hr, hr == S_OK ? bstr : NULL);
    hr = IExecAction_get_WorkingDirectory(action, &bstr);
    write_bstr_value(stream, L"WorkingDirectory", hr, hr == S_OK ? bstr : NULL);
    pop_indent();

    return write_element_end(stream, L"Exec");
}

static HRESULT write_actions(IStream *stream, IActionCollection *actions)
{
    IExecAction *exec_action;
    TASK_ACTION_TYPE type;
    IAction *action;
    BSTR context = NULL;
    LONG count, i;
    HRESULT hr;

    if (!actions)
    {
        write_element(stream, L"Actions");
        push_indent();
        write_empty_element(stream, L"Exec");
        pop_indent();
        return write_element_end(stream, L"Actions");
    }

    hr = IActionCollection_get_Count(actions, &count);
    if (hr != S_OK || !count) return S_OK;

    if (IActionCollection_get_Context(actions, &context) == S_OK && context && *context)
    {
        write_indent(stream);
        write_stringW(stream, L"<Actions Context=\"");
        write_escaped_string(stream, context);
        hr = write_stringW(stream, L"\">\n");
    }
    else
        hr = write_element(stream, L"Actions");
    SysFreeString(context);
    if (hr != S_OK) return hr;

    push_indent();
    for (i = 1; i <= count; i++)
    {
        if (IActionCollection_get_Item(actions, i, &action) != S_OK) continue;

        if (IAction_get_Type(action, &type) == S_OK && type == TASK_ACTION_EXEC &&
            IAction_QueryInterface(action, &IID_IExecAction, (void **)&exec_action) == S_OK)
        {
            hr = write_exec_action(stream, exec_action);
            IExecAction_Release(exec_action);
        }
        else
            FIXME("unsupported action %p\n", action);

        IAction_Release(action);
        if (hr != S_OK) return hr;
    }
    pop_indent();

    return write_element_end(stream, L"Actions");
}

static HRESULT WINAPI TaskDefinition_get_XmlText(ITaskDefinition *iface, BSTR *xml)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    HRESULT hr;
    IStream *stream;
    HGLOBAL hmem;
    void *p;

    TRACE("%p,%p\n", iface, xml);

    hmem = GlobalAlloc(GMEM_MOVEABLE | GMEM_NODISCARD, 16);
    if (!hmem) return E_OUTOFMEMORY;

    hr = CreateStreamOnHGlobal(hmem, TRUE, &stream);
    if (hr != S_OK)
    {
        GlobalFree(hmem);
        return hr;
    }

    hr = write_task_attributes(stream, &taskdef->ITaskDefinition_iface);
    if (hr != S_OK) goto failed;

    push_indent();

    hr = write_registration_info(stream, taskdef->reginfo);
    if (hr != S_OK) goto failed;

    hr = write_triggers(stream, taskdef->triggers);
    if (hr != S_OK) goto failed;

    hr = write_principal(stream, taskdef->principal);
    if (hr != S_OK) goto failed;

    hr = write_settings(stream, taskdef->taskset);
    if (hr != S_OK) goto failed;

    hr = write_actions(stream, taskdef->actions);
    if (hr != S_OK) goto failed;

    if (taskdef->data)
    {
        hr = write_text_value(stream, L"Data", taskdef->data);
        if (hr != S_OK) goto failed;
    }

    pop_indent();

    write_element_end(stream, L"Task");
    IStream_Write(stream, "\0\0", 2, NULL);

    p = GlobalLock(hmem);
    *xml = SysAllocString(p);
    GlobalUnlock(hmem);

    IStream_Release(stream);

    return *xml ? S_OK : E_OUTOFMEMORY;

failed:
    IStream_Release(stream);
    return hr;
}

static HRESULT read_text_value(IXmlReader *reader, WCHAR **value)
{
    HRESULT hr;
    XmlNodeType type;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_Text:
            hr = IXmlReader_GetValue(reader, (const WCHAR **)value, NULL);
            if (hr != S_OK) return hr;
            TRACE("%s\n", debugstr_w(*value));
            return S_OK;

        case XmlNodeType_Whitespace:
        case XmlNodeType_Comment:
            break;

        default:
            FIXME("unexpected node type %d\n", type);
            return E_FAIL;
        }
    }

    return E_FAIL;
}

static HRESULT read_variantbool_value(IXmlReader *reader, VARIANT_BOOL *vbool)
{
    HRESULT hr;
    WCHAR *value;

    hr = read_text_value(reader, &value);
    if (hr != S_OK) return hr;

    if (!lstrcmpW(value, L"true"))
        *vbool = VARIANT_TRUE;
    else if (!lstrcmpW(value, L"false"))
        *vbool = VARIANT_FALSE;
    else
    {
        WARN("unexpected bool value %s\n", debugstr_w(value));
        return SCHED_E_INVALIDVALUE;
    }

    return S_OK;
}

static HRESULT read_int_value(IXmlReader *reader, int *int_val)
{
    HRESULT hr;
    WCHAR *value;

    hr = read_text_value(reader, &value);
    if (hr != S_OK) return hr;

    *int_val = wcstol(value, NULL, 10);

    return S_OK;
}

/* skips the element the reader is on, with everything in it */
static HRESULT skip_element(IXmlReader *reader)
{
    XmlNodeType type;
    UINT depth = 1;

    if (IXmlReader_IsEmptyElement(reader)) return S_OK;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        if (type == XmlNodeType_Element && !IXmlReader_IsEmptyElement(reader)) depth++;
        else if (type == XmlNodeType_EndElement && !--depth) return S_OK;
    }
    return SCHED_E_MALFORMEDXML;
}

/* the id="..." attribute of the element the reader is on, or NULL */
static WCHAR *read_id_attribute(IXmlReader *reader)
{
    const WCHAR *name, *value;
    WCHAR *id = NULL;
    HRESULT hr;

    hr = IXmlReader_MoveToFirstAttribute(reader);
    while (hr == S_OK)
    {
        if (IXmlReader_GetLocalName(reader, &name, NULL) == S_OK &&
            IXmlReader_GetValue(reader, &value, NULL) == S_OK)
        {
            if (!lstrcmpW(name, L"id")) id = wcsdup(value);
            else FIXME("unhandled attribute %s\n", debugstr_w(name));
        }
        hr = IXmlReader_MoveToNextAttribute(reader);
    }
    IXmlReader_MoveToElement(reader);
    return id;
}

static HRESULT read_repetition(IXmlReader *reader, ITrigger *trigger)
{
    IRepetitionPattern *repetition;
    XmlNodeType type;
    const WCHAR *name;
    VARIANT_BOOL bool_val;
    WCHAR *value;
    HRESULT hr;

    if (IXmlReader_IsEmptyElement(reader)) return S_OK;

    hr = ITrigger_get_Repetition(trigger, &repetition);
    if (hr != S_OK) return skip_element(reader);

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr == S_OK && !lstrcmpW(name, L"Repetition"))
            {
                IRepetitionPattern_Release(repetition);
                return S_OK;
            }
            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            if (!lstrcmpW(name, L"Interval"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    IRepetitionPattern_put_Interval(repetition, value);
            }
            else if (!lstrcmpW(name, L"Duration"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    IRepetitionPattern_put_Duration(repetition, value);
            }
            else if (!lstrcmpW(name, L"StopAtDurationEnd"))
            {
                if (read_variantbool_value(reader, &bool_val) == S_OK)
                    IRepetitionPattern_put_StopAtDurationEnd(repetition, bool_val);
            }
            else
            {
                FIXME("unhandled Repetition element %s\n", debugstr_w(name));
                skip_element(reader);
            }
            break;

        default:
            break;
        }
    }

    IRepetitionPattern_Release(repetition);
    WARN("Repetition was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_schedule_by_day(IXmlReader *reader, ITrigger *trigger)
{
    IDailyTrigger *daily_trigger;
    XmlNodeType type;
    const WCHAR *name;
    int days;
    HRESULT hr;

    if (IXmlReader_IsEmptyElement(reader)) return S_OK;

    if (ITrigger_QueryInterface(trigger, &IID_IDailyTrigger, (void **)&daily_trigger) != S_OK)
        return skip_element(reader);

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr == S_OK && !lstrcmpW(name, L"ScheduleByDay"))
            {
                IDailyTrigger_Release(daily_trigger);
                return S_OK;
            }
            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            if (!lstrcmpW(name, L"DaysInterval"))
            {
                if (read_int_value(reader, &days) == S_OK)
                    IDailyTrigger_put_DaysInterval(daily_trigger, days);
            }
            else
            {
                FIXME("unhandled ScheduleByDay element %s\n", debugstr_w(name));
                skip_element(reader);
            }
            break;

        default:
            break;
        }
    }

    IDailyTrigger_Release(daily_trigger);
    WARN("ScheduleByDay was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

/* appends text to a buffer that grows */
static HRESULT append_text(WCHAR **buf, size_t *len, size_t *cap, const WCHAR *text, size_t n)
{
    if (*len + n + 1 > *cap)
    {
        size_t size = max(*cap * 2, *len + n + 1 + 64);
        WCHAR *str = realloc(*buf, size * sizeof(WCHAR));

        if (!str) return E_OUTOFMEMORY;
        *buf = str;
        *cap = size;
    }
    memcpy(*buf + *len, text, n * sizeof(WCHAR));
    *len += n;
    (*buf)[*len] = 0;
    return S_OK;
}

static HRESULT append_escaped(WCHAR **buf, size_t *len, size_t *cap, const WCHAR *text)
{
    const WCHAR *entity;
    HRESULT hr = S_OK;

    for (; *text && hr == S_OK; text++)
    {
        switch (*text)
        {
        case '&': entity = L"&amp;"; break;
        case '<': entity = L"&lt;"; break;
        case '>': entity = L"&gt;"; break;
        case '"': entity = L"&quot;"; break;
        default: hr = append_text(buf, len, cap, text, 1); continue;
        }
        hr = append_text(buf, len, cap, entity, wcslen(entity));
    }
    return hr;
}

/* the element the reader is on, with everything in it, as one line of XML without the indentation
 * (the text of an element that a trigger keeps as it came); the reader is left on its end */
static HRESULT capture_element(IXmlReader *reader, WCHAR **out)
{
    WCHAR *buf = NULL;
    size_t len = 0, cap = 0;
    XmlNodeType type;
    const WCHAR *name, *value;
    unsigned int depth = 0;
    HRESULT hr = S_OK;
    BOOL element = TRUE;    /* the reader is on the first element */

    for (;;)
    {
        if (element)
        {
            BOOL empty = IXmlReader_IsEmptyElement(reader);
            HRESULT attr;

            element = FALSE;
            if ((hr = IXmlReader_GetLocalName(reader, &name, NULL)) != S_OK) break;
            if ((hr = append_text(&buf, &len, &cap, L"<", 1)) != S_OK) break;
            if ((hr = append_text(&buf, &len, &cap, name, wcslen(name))) != S_OK) break;
            for (attr = IXmlReader_MoveToFirstAttribute(reader); attr == S_OK; attr = IXmlReader_MoveToNextAttribute(reader))
            {
                if (IXmlReader_GetLocalName(reader, &name, NULL) != S_OK ||
                    IXmlReader_GetValue(reader, &value, NULL) != S_OK) continue;
                append_text(&buf, &len, &cap, L" ", 1);
                append_text(&buf, &len, &cap, name, wcslen(name));
                append_text(&buf, &len, &cap, L"=\"", 2);
                append_escaped(&buf, &len, &cap, value);
                append_text(&buf, &len, &cap, L"\"", 1);
            }
            IXmlReader_MoveToElement(reader);
            if ((hr = append_text(&buf, &len, &cap, empty ? L"/>" : L">", empty ? 2 : 1)) != S_OK) break;
            if (empty && !depth) break;
            if (!empty) depth++;
        }
        else if (IXmlReader_Read(reader, &type) != S_OK)
        {
            hr = SCHED_E_MALFORMEDXML;
            break;
        }
        else switch (type)
        {
        case XmlNodeType_Element:
            element = TRUE;
            continue;
        case XmlNodeType_EndElement:
            if (IXmlReader_GetLocalName(reader, &name, NULL) != S_OK) { hr = E_FAIL; break; }
            append_text(&buf, &len, &cap, L"</", 2);
            append_text(&buf, &len, &cap, name, wcslen(name));
            hr = append_text(&buf, &len, &cap, L">", 1);
            if (!--depth) goto done;
            continue;
        case XmlNodeType_Text:
        case XmlNodeType_CDATA:
            if (IXmlReader_GetValue(reader, &value, NULL) == S_OK) hr = append_escaped(&buf, &len, &cap, value);
            continue;
        default:
            continue;
        }
        if (hr != S_OK) break;
    }
done:
    if (hr == S_OK && (hr = append_text(&buf, &len, &cap, L"\n", 1)) == S_OK)
    {
        *out = buf;
        return S_OK;
    }
    free(buf);
    return hr;
}

/* the members of a set given as elements (<Monday />, <March />): their bits */
static HRESULT read_name_set(IXmlReader *reader, const WCHAR *end_name, const WCHAR *const *names, unsigned int count,
                             int *mask)
{
    XmlNodeType type;
    const WCHAR *name;
    unsigned int i;
    WCHAR *end_copy;

    *mask = 0;
    if (IXmlReader_IsEmptyElement(reader)) return S_OK;
    if (!(end_copy = wcsdup(end_name))) return E_OUTOFMEMORY;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        if (type == XmlNodeType_EndElement)
        {
            if (IXmlReader_GetLocalName(reader, &name, NULL) == S_OK && !lstrcmpW(name, end_copy))
            {
                free(end_copy);
                return S_OK;
            }
        }
        else if (type == XmlNodeType_Element)
        {
            if (IXmlReader_GetLocalName(reader, &name, NULL) != S_OK) break;
            for (i = 0; i < count; i++)
                if (!lstrcmpW(name, names[i])) break;
            if (i < count) *mask |= 1 << i;
            else FIXME("unknown name %s in %s\n", debugstr_w(name), debugstr_w(end_copy));
            skip_element(reader);
        }
    }
    free(end_copy);
    return SCHED_E_MALFORMEDXML;
}

/* <Days><Day>1</Day><Day>Last</Day></Days>: numbers 1..count as bits, and "Last" */
static HRESULT read_number_set(IXmlReader *reader, const WCHAR *end_name, unsigned int count, int *mask, BOOL *last)
{
    XmlNodeType type;
    const WCHAR *name;
    WCHAR *value, *end_copy;
    long n;

    *mask = 0;
    *last = FALSE;
    if (IXmlReader_IsEmptyElement(reader)) return S_OK;
    if (!(end_copy = wcsdup(end_name))) return E_OUTOFMEMORY;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        if (type == XmlNodeType_EndElement)
        {
            if (IXmlReader_GetLocalName(reader, &name, NULL) == S_OK && !lstrcmpW(name, end_copy))
            {
                free(end_copy);
                return S_OK;
            }
        }
        else if (type == XmlNodeType_Element)
        {
            if (read_text_value(reader, &value) != S_OK) break;
            if (!lstrcmpW(value, L"Last")) *last = TRUE;
            else
            {
                n = wcstol(value, NULL, 10);
                if (n >= 1 && n <= (long)count) *mask |= 1 << (n - 1);
                else FIXME("value %s out of range in %s\n", debugstr_w(value), debugstr_w(end_copy));
            }
        }
    }
    free(end_copy);
    return SCHED_E_MALFORMEDXML;
}

/* ScheduleByWeek, ScheduleByMonth and ScheduleByMonthDayOfWeek: the trigger, read as a daily one
 * so far, becomes a weekly, monthly or monthly day-of-week one */
static HRESULT read_schedule_calendar(IXmlReader *reader, ITrigger *trigger, const WCHAR *element)
{
    TASK_TRIGGER_TYPE2 type;
    XmlNodeType node;
    const WCHAR *name;
    WCHAR *end_copy, *value;
    int mask, weeks = 0, days = 0, months = 0, dom = 0, interval = 1;
    BOOL last = FALSE, have_interval = FALSE, empty = IXmlReader_IsEmptyElement(reader);
    SchedTrigger *This;

    if (!lstrcmpW(element, L"ScheduleByWeek")) type = TASK_TRIGGER_WEEKLY;
    else if (!lstrcmpW(element, L"ScheduleByMonth")) type = TASK_TRIGGER_MONTHLY;
    else type = TASK_TRIGGER_MONTHLYDOW;

    if (!is_sched_trigger(trigger)) return skip_element(reader);
    if (!(end_copy = wcsdup(element))) return E_OUTOFMEMORY;

    while (!empty && IXmlReader_Read(reader, &node) == S_OK)
    {
        if (node == XmlNodeType_EndElement)
        {
            if (IXmlReader_GetLocalName(reader, &name, NULL) == S_OK && !lstrcmpW(name, end_copy)) break;
        }
        else if (node == XmlNodeType_Element)
        {
            if (IXmlReader_GetLocalName(reader, &name, NULL) != S_OK) break;
            if (!lstrcmpW(name, L"DaysOfWeek") && type != TASK_TRIGGER_MONTHLY)
                read_name_set(reader, L"DaysOfWeek", day_names, 7, &days);
            else if (!lstrcmpW(name, L"Months") && type != TASK_TRIGGER_WEEKLY)
                read_name_set(reader, L"Months", month_names, 12, &months);
            else if (!lstrcmpW(name, L"WeeksInterval") && type == TASK_TRIGGER_WEEKLY)
            {
                if (read_text_value(reader, &value) == S_OK) { interval = wcstol(value, NULL, 10); have_interval = TRUE; }
            }
            else if (!lstrcmpW(name, L"DaysOfMonth") && type == TASK_TRIGGER_MONTHLY)
                read_number_set(reader, L"DaysOfMonth", 31, &dom, &last);
            else if (!lstrcmpW(name, L"Weeks") && type == TASK_TRIGGER_MONTHLYDOW)
                read_number_set(reader, L"Weeks", 4, &weeks, &last);
            else
            {
                FIXME("unhandled %s element %s\n", debugstr_w(end_copy), debugstr_w(name));
                skip_element(reader);
            }
        }
    }
    free(end_copy);

    trigger_set_calendar_type(trigger, type);
    This = CONTAINING_RECORD(trigger, SchedTrigger, ITrigger_iface);
    This->days_of_week = days;
    This->months = months;
    This->weeks = weeks;
    This->days_of_month = dom;
    This->run_last = last;
    mask = have_interval ? interval : 1;
    if (mask < 1 || mask > 52) return SCHED_E_INVALIDVALUE;
    This->weeks_interval = mask;
    return S_OK;
}

static void put_trigger_delay(ITrigger *trigger, const WCHAR *element, BSTR value)
{
    ILogonTrigger *logon_trigger;
    IBootTrigger *boot_trigger;
    IRegistrationTrigger *registration_trigger;
    ITimeTrigger *time_trigger;
    IDailyTrigger *daily_trigger;
    IWeeklyTrigger *weekly_trigger;
    IMonthlyTrigger *monthly_trigger;
    IMonthlyDOWTrigger *monthly_dow_trigger;
    IEventTrigger *event_trigger;
    ISessionStateChangeTrigger *session_trigger;

    if (!lstrcmpW(element, L"Delay"))
    {
        if (ITrigger_QueryInterface(trigger, &IID_ILogonTrigger, (void **)&logon_trigger) == S_OK)
        {
            ILogonTrigger_put_Delay(logon_trigger, value);
            ILogonTrigger_Release(logon_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_IBootTrigger, (void **)&boot_trigger) == S_OK)
        {
            IBootTrigger_put_Delay(boot_trigger, value);
            IBootTrigger_Release(boot_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_IRegistrationTrigger, (void **)&registration_trigger) == S_OK)
        {
            IRegistrationTrigger_put_Delay(registration_trigger, value);
            IRegistrationTrigger_Release(registration_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_IEventTrigger, (void **)&event_trigger) == S_OK)
        {
            IEventTrigger_put_Delay(event_trigger, value);
            IEventTrigger_Release(event_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_ISessionStateChangeTrigger, (void **)&session_trigger) == S_OK)
        {
            ISessionStateChangeTrigger_put_Delay(session_trigger, value);
            ISessionStateChangeTrigger_Release(session_trigger);
        }
    }
    else
    {
        if (ITrigger_QueryInterface(trigger, &IID_ITimeTrigger, (void **)&time_trigger) == S_OK)
        {
            ITimeTrigger_put_RandomDelay(time_trigger, value);
            ITimeTrigger_Release(time_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_IDailyTrigger, (void **)&daily_trigger) == S_OK)
        {
            IDailyTrigger_put_RandomDelay(daily_trigger, value);
            IDailyTrigger_Release(daily_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_IWeeklyTrigger, (void **)&weekly_trigger) == S_OK)
        {
            IWeeklyTrigger_put_RandomDelay(weekly_trigger, value);
            IWeeklyTrigger_Release(weekly_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_IMonthlyTrigger, (void **)&monthly_trigger) == S_OK)
        {
            IMonthlyTrigger_put_RandomDelay(monthly_trigger, value);
            IMonthlyTrigger_Release(monthly_trigger);
        }
        else if (ITrigger_QueryInterface(trigger, &IID_IMonthlyDOWTrigger, (void **)&monthly_dow_trigger) == S_OK)
        {
            IMonthlyDOWTrigger_put_RandomDelay(monthly_dow_trigger, value);
            IMonthlyDOWTrigger_Release(monthly_dow_trigger);
        }
    }
}

static HRESULT read_trigger(IXmlReader *reader, ITrigger *trigger, const WCHAR *element)
{
    XmlNodeType type;
    const WCHAR *name;
    VARIANT_BOOL bool_val;
    WCHAR *value, *id;
    WCHAR *element_name;
    HRESULT hr;
    BOOL empty = IXmlReader_IsEmptyElement(reader);

    if ((id = read_id_attribute(reader)))
    {
        ITrigger_put_Id(trigger, id);
        free(id);
    }
    if (empty) return S_OK;

    /* the reader reuses the buffer of the name */
    if (!(element_name = wcsdup(element))) return E_OUTOFMEMORY;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr == S_OK && !lstrcmpW(name, element_name))
            {
                free(element_name);
                return S_OK;
            }
            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"StartBoundary"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    ITrigger_put_StartBoundary(trigger, value);
            }
            else if (!lstrcmpW(name, L"EndBoundary"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    ITrigger_put_EndBoundary(trigger, value);
            }
            else if (!lstrcmpW(name, L"ExecutionTimeLimit"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    ITrigger_put_ExecutionTimeLimit(trigger, value);
            }
            else if (!lstrcmpW(name, L"Enabled"))
            {
                if (read_variantbool_value(reader, &bool_val) == S_OK)
                    ITrigger_put_Enabled(trigger, bool_val);
            }
            else if (!lstrcmpW(name, L"Repetition"))
                read_repetition(reader, trigger);
            else if (!lstrcmpW(name, L"ScheduleByDay"))
                read_schedule_by_day(reader, trigger);
            else if (!lstrcmpW(name, L"ScheduleByWeek") || !lstrcmpW(name, L"ScheduleByMonth") ||
                     !lstrcmpW(name, L"ScheduleByMonthDayOfWeek"))
            {
                WCHAR *schedule_name = wcsdup(name);

                hr = schedule_name ? read_schedule_calendar(reader, trigger, schedule_name) : E_OUTOFMEMORY;
                free(schedule_name);
                if (hr != S_OK)
                {
                    free(element_name);
                    return hr;
                }
            }
            else if (!lstrcmpW(name, L"Subscription"))
            {
                IEventTrigger *event_trigger;

                if (read_text_value(reader, &value) == S_OK &&
                    ITrigger_QueryInterface(trigger, &IID_IEventTrigger, (void **)&event_trigger) == S_OK)
                {
                    IEventTrigger_put_Subscription(event_trigger, value);
                    IEventTrigger_Release(event_trigger);
                }
            }
            else if (!lstrcmpW(name, L"StateChange"))
            {
                ISessionStateChangeTrigger *session;
                unsigned int i;

                if (read_text_value(reader, &value) == S_OK &&
                    ITrigger_QueryInterface(trigger, &IID_ISessionStateChangeTrigger, (void **)&session) == S_OK)
                {
                    for (i = 0; i < ARRAY_SIZE(state_changes); i++)
                        if (!lstrcmpW(value, state_changes[i].name))
                            ISessionStateChangeTrigger_put_StateChange(session, state_changes[i].type);
                    ISessionStateChangeTrigger_Release(session);
                }
            }
            else if (!lstrcmpW(name, L"Delay") || !lstrcmpW(name, L"RandomDelay"))
            {
                WCHAR *delay_name = wcsdup(name);

                if (delay_name && read_text_value(reader, &value) == S_OK)
                    put_trigger_delay(trigger, delay_name, value);
                free(delay_name);
            }
            else if (!lstrcmpW(name, L"UserId"))
            {
                ILogonTrigger *logon_trigger;

                ISessionStateChangeTrigger *session;

                if (read_text_value(reader, &value) != S_OK) break;
                if (ITrigger_QueryInterface(trigger, &IID_ILogonTrigger, (void **)&logon_trigger) == S_OK)
                {
                    ILogonTrigger_put_UserId(logon_trigger, value);
                    ILogonTrigger_Release(logon_trigger);
                }
                else if (ITrigger_QueryInterface(trigger, &IID_ISessionStateChangeTrigger, (void **)&session) == S_OK)
                {
                    ISessionStateChangeTrigger_put_UserId(session, value);
                    ISessionStateChangeTrigger_Release(session);
                }
            }
            else if (is_sched_trigger(trigger))
            {
                /* not modelled by the object: kept as text, so that it is registered as it was read */
                WCHAR *text;

                TRACE("keeping %s element %s\n", debugstr_w(element_name), debugstr_w(name));
                if ((hr = capture_element(reader, &text)) != S_OK)
                {
                    free(element_name);
                    return hr;
                }
                hr = trigger_add_extra(trigger, text);
                free(text);
                if (hr != S_OK)
                {
                    free(element_name);
                    return hr;
                }
            }
            else
            {
                FIXME("unhandled %s element %s\n", debugstr_w(element_name), debugstr_w(name));
                skip_element(reader);
            }
            break;

        default:
            break;
        }
    }

    WARN("%s was not terminated\n", debugstr_w(element_name));
    free(element_name);
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_triggers(IXmlReader *reader, ITaskDefinition *taskdef)
{
    static const struct { const WCHAR *name; TASK_TRIGGER_TYPE2 type; } trigger_types[] =
    {
        { L"TimeTrigger", TASK_TRIGGER_TIME },
        { L"CalendarTrigger", TASK_TRIGGER_DAILY },
        { L"BootTrigger", TASK_TRIGGER_BOOT },
        { L"LogonTrigger", TASK_TRIGGER_LOGON },
        { L"RegistrationTrigger", TASK_TRIGGER_REGISTRATION },
        { L"IdleTrigger", TASK_TRIGGER_IDLE },
        { L"EventTrigger", TASK_TRIGGER_EVENT },
        { L"SessionStateChangeTrigger", TASK_TRIGGER_SESSION_STATE_CHANGE },
    };
    ITriggerCollection *triggers;
    ITrigger *trigger;
    XmlNodeType type;
    const WCHAR *name;
    unsigned int i;
    HRESULT hr;

    if (IXmlReader_IsEmptyElement(reader))
    {
        TRACE("Triggers is empty\n");
        return S_OK;
    }

    hr = ITaskDefinition_get_Triggers(taskdef, &triggers);
    if (hr != S_OK) return hr;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            TRACE("/%s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Triggers"))
            {
                ITriggerCollection_Release(triggers);
                return S_OK;
            }
            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            TRACE("Element: %s\n", debugstr_w(name));

            for (i = 0; i < ARRAY_SIZE(trigger_types); i++)
                if (!lstrcmpW(name, trigger_types[i].name)) break;

            if (i < ARRAY_SIZE(trigger_types) &&
                ITriggerCollection_Create(triggers, trigger_types[i].type, &trigger) == S_OK)
            {
                hr = read_trigger(reader, trigger, trigger_types[i].name);
                ITrigger_Release(trigger);
                if (hr != S_OK)
                {
                    ITriggerCollection_Release(triggers);
                    return hr;
                }
            }
            else
            {
                FIXME("unhandled Triggers element %s\n", debugstr_w(name));
                skip_element(reader);
            }
            break;

        default:
            break;
        }
    }

    ITriggerCollection_Release(triggers);
    WARN("Triggers was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_principal_attributes(IXmlReader *reader, IPrincipal *principal)
{
    HRESULT hr;
    const WCHAR *name;
    const WCHAR *value;

    hr = IXmlReader_MoveToFirstAttribute(reader);

    while (hr == S_OK)
    {
        hr = IXmlReader_GetLocalName(reader, &name, NULL);
        if (hr != S_OK) break;

        hr = IXmlReader_GetValue(reader, &value, NULL);
        if (hr != S_OK) break;

        TRACE("%s=%s\n", debugstr_w(name), debugstr_w(value));

        if (!lstrcmpW(name, L"id"))
            IPrincipal_put_Id(principal, (BSTR)value);
        else
            FIXME("unhandled Principal attribute %s\n", debugstr_w(name));

        hr = IXmlReader_MoveToNextAttribute(reader);
    }

    return S_OK;
}

static HRESULT read_principal(IXmlReader *reader, IPrincipal *principal)
{
    HRESULT hr;
    XmlNodeType type;
    const WCHAR *name;
    WCHAR *value;

    if (IXmlReader_IsEmptyElement(reader))
    {
        TRACE("Principal is empty\n");
        return S_OK;
    }

    read_principal_attributes(reader, principal);

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("/%s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Principal"))
                return S_OK;

            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"UserId"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IPrincipal_put_UserId(principal, value);
            }
            else if (!lstrcmpW(name, L"LogonType"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                {
                    TASK_LOGON_TYPE logon = TASK_LOGON_NONE;

                    if (!lstrcmpW(value, L"InteractiveToken"))
                        logon = TASK_LOGON_INTERACTIVE_TOKEN;
                    else if (!lstrcmpW(value, L"Password"))
                        logon = TASK_LOGON_PASSWORD;
                    else if (!lstrcmpW(value, L"S4U"))
                        logon = TASK_LOGON_S4U;
                    else if (!lstrcmpW(value, L"ServiceAccount"))
                        logon = TASK_LOGON_SERVICE_ACCOUNT;
                    else if (!lstrcmpW(value, L"InteractiveTokenOrPassword"))
                        logon = TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD;
                    else
                        FIXME("unhandled LogonType %s\n", debugstr_w(value));

                    IPrincipal_put_LogonType(principal, logon);
                }
            }
            else if (!lstrcmpW(name, L"GroupId"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IPrincipal_put_GroupId(principal, value);
            }
            else if (!lstrcmpW(name, L"DisplayName"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IPrincipal_put_DisplayName(principal, value);
            }
            else if (!lstrcmpW(name, L"RunLevel"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                {
                    TASK_RUNLEVEL_TYPE level = TASK_RUNLEVEL_LUA;

                    if (!lstrcmpW(value, L"LeastPrivilege"))
                        level = TASK_RUNLEVEL_LUA;
                    else if (!lstrcmpW(value, L"HighestAvailable"))
                        level = TASK_RUNLEVEL_HIGHEST;
                    else
                        FIXME("unhandled RunLevel %s\n", debugstr_w(value));

                    IPrincipal_put_RunLevel(principal, level);
                }
            }
            else
                FIXME("unhandled Principal element %s\n", debugstr_w(name));

            break;

        case XmlNodeType_Whitespace:
        case XmlNodeType_Comment:
            break;

        default:
            FIXME("unhandled Principal node type %d\n", type);
            break;
        }
    }

    WARN("Principal was not terminated\n");
    return E_FAIL;
}

static HRESULT read_principals(IXmlReader *reader, ITaskDefinition *taskdef)
{
    HRESULT hr;
    XmlNodeType type;
    const WCHAR *name;

    if (IXmlReader_IsEmptyElement(reader))
    {
        TRACE("Principals is empty\n");
        return S_OK;
    }

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("/%s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Principals"))
                return S_OK;

            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Principal"))
            {
                IPrincipal *principal;

                hr = ITaskDefinition_get_Principal(taskdef, &principal);
                if (hr != S_OK) return hr;
                hr = read_principal(reader, principal);
                IPrincipal_Release(principal);
            }
            else
                FIXME("unhandled Principals element %s\n", debugstr_w(name));

            break;

        case XmlNodeType_Whitespace:
        case XmlNodeType_Comment:
            break;

        default:
            FIXME("unhandled Principals node type %d\n", type);
            break;
        }
    }

    WARN("Principals was not terminated\n");
    return E_FAIL;
}

static HRESULT read_exec_action(IXmlReader *reader, IExecAction *action)
{
    XmlNodeType type;
    const WCHAR *name;
    WCHAR *value, *id;
    HRESULT hr;
    BOOL empty = IXmlReader_IsEmptyElement(reader);

    if ((id = read_id_attribute(reader)))
    {
        IExecAction_put_Id(action, id);
        free(id);
    }
    if (empty) return S_OK;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr == S_OK && !lstrcmpW(name, L"Exec")) return S_OK;
            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Command"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    IExecAction_put_Path(action, value);
            }
            else if (!lstrcmpW(name, L"Arguments"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    IExecAction_put_Arguments(action, value);
            }
            else if (!lstrcmpW(name, L"WorkingDirectory"))
            {
                if (read_text_value(reader, &value) == S_OK)
                    IExecAction_put_WorkingDirectory(action, value);
            }
            else
            {
                FIXME("unhandled Exec element %s\n", debugstr_w(name));
                skip_element(reader);
            }
            break;

        default:
            break;
        }
    }

    WARN("Exec was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_actions(IXmlReader *reader, ITaskDefinition *taskdef)
{
    IActionCollection *actions;
    IExecAction *exec_action;
    IAction *action;
    XmlNodeType type;
    const WCHAR *name, *value;
    HRESULT hr;
    BOOL empty = IXmlReader_IsEmptyElement(reader);

    hr = ITaskDefinition_get_Actions(taskdef, &actions);
    if (hr != S_OK) return hr;

    hr = IXmlReader_MoveToFirstAttribute(reader);
    while (hr == S_OK)
    {
        if (IXmlReader_GetLocalName(reader, &name, NULL) == S_OK &&
            IXmlReader_GetValue(reader, &value, NULL) == S_OK)
        {
            if (!lstrcmpW(name, L"Context")) IActionCollection_put_Context(actions, (BSTR)value);
            else FIXME("unhandled Actions attribute %s\n", debugstr_w(name));
        }
        hr = IXmlReader_MoveToNextAttribute(reader);
    }
    IXmlReader_MoveToElement(reader);

    if (empty)
    {
        IActionCollection_Release(actions);
        return S_OK;
    }

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            TRACE("/%s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Actions"))
            {
                IActionCollection_Release(actions);
                return S_OK;
            }
            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) break;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Exec") &&
                IActionCollection_Create(actions, TASK_ACTION_EXEC, &action) == S_OK)
            {
                hr = IAction_QueryInterface(action, &IID_IExecAction, (void **)&exec_action);
                if (hr == S_OK)
                {
                    hr = read_exec_action(reader, exec_action);
                    IExecAction_Release(exec_action);
                }
                IAction_Release(action);
                if (hr != S_OK)
                {
                    IActionCollection_Release(actions);
                    return hr;
                }
            }
            else
            {
                FIXME("unhandled Actions element %s\n", debugstr_w(name));
                skip_element(reader);
            }
            break;

        default:
            break;
        }
    }

    IActionCollection_Release(actions);
    WARN("Actions was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_idle_settings(IXmlReader *reader, ITaskSettings *taskset)
{
    FIXME("stub\n");
    return S_OK;
}

static HRESULT read_settings(IXmlReader *reader, ITaskSettings *taskset)
{
    HRESULT hr;
    XmlNodeType type;
    const WCHAR *name;
    WCHAR *value;
    VARIANT_BOOL bool_val;
    int int_val;

    if (IXmlReader_IsEmptyElement(reader))
    {
        TRACE("Settings is empty\n");
        return S_OK;
    }

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("/%s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Settings"))
                return S_OK;

            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"MultipleInstancesPolicy"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                {
                    int_val = TASK_INSTANCES_IGNORE_NEW;

                    if (!lstrcmpW(value, L"IgnoreNew"))
                        int_val = TASK_INSTANCES_IGNORE_NEW;
                    else
                        FIXME("unhandled MultipleInstancesPolicy %s\n", debugstr_w(value));

                    ITaskSettings_put_MultipleInstances(taskset, int_val);
                }
            }
            else if (!lstrcmpW(name, L"DisallowStartIfOnBatteries"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_DisallowStartIfOnBatteries(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"AllowStartOnDemand"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_AllowDemandStart(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"StopIfGoingOnBatteries"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_StopIfGoingOnBatteries(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"AllowHardTerminate"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_AllowHardTerminate(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"StartWhenAvailable"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_StartWhenAvailable(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"RunOnlyIfNetworkAvailable"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_RunOnlyIfNetworkAvailable(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"Enabled"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_Enabled(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"Hidden"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_Hidden(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"RunOnlyIfIdle"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_RunOnlyIfIdle(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"WakeToRun"))
            {
                hr = read_variantbool_value(reader, &bool_val);
                if (hr != S_OK) return hr;
                ITaskSettings_put_WakeToRun(taskset, bool_val);
            }
            else if (!lstrcmpW(name, L"ExecutionTimeLimit"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    ITaskSettings_put_ExecutionTimeLimit(taskset, value);
            }
            else if (!lstrcmpW(name, L"Priority"))
            {
                hr = read_int_value(reader, &int_val);
                if (hr == S_OK)
                    ITaskSettings_put_Priority(taskset, int_val);
            }
            else if (!lstrcmpW(name, L"IdleSettings"))
            {
                hr = read_idle_settings(reader, taskset);
                if (hr != S_OK) return hr;
            }
            else
                FIXME("unhandled Settings element %s\n", debugstr_w(name));

            break;

        case XmlNodeType_Whitespace:
        case XmlNodeType_Comment:
            break;

        default:
            FIXME("unhandled Settings node type %d\n", type);
            break;
        }
    }

    WARN("Settings was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_registration_info(IXmlReader *reader, IRegistrationInfo *info)
{
    HRESULT hr;
    XmlNodeType type;
    const WCHAR *name;
    WCHAR *value;

    if (IXmlReader_IsEmptyElement(reader))
    {
        TRACE("RegistrationInfo is empty\n");
        return S_OK;
    }

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("/%s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"RegistrationInfo"))
                return S_OK;

            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Author"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IRegistrationInfo_put_Author(info, value);
            }
            else if (!lstrcmpW(name, L"Description"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IRegistrationInfo_put_Description(info, value);
            }
            else if (!lstrcmpW(name, L"Version"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IRegistrationInfo_put_Version(info, value);
            }
            else if (!lstrcmpW(name, L"Date"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IRegistrationInfo_put_Date(info, value);
            }
            else if (!lstrcmpW(name, L"Documentation"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IRegistrationInfo_put_Documentation(info, value);
            }
            else if (!lstrcmpW(name, L"URI"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IRegistrationInfo_put_URI(info, value);
            }
            else if (!lstrcmpW(name, L"Source"))
            {
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    IRegistrationInfo_put_Source(info, value);
            }
            else
                FIXME("unhandled RegistrationInfo element %s\n", debugstr_w(name));

            break;

        case XmlNodeType_Whitespace:
        case XmlNodeType_Comment:
            break;

        default:
            FIXME("unhandled RegistrationInfo node type %d\n", type);
            break;
        }
    }

    WARN("RegistrationInfo was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_task_attributes(IXmlReader *reader, ITaskDefinition *taskdef)
{
    HRESULT hr;
    ITaskSettings *taskset;
    const WCHAR *name;
    const WCHAR *value;
    BOOL xmlns_ok = FALSE;

    TRACE("\n");

    hr = ITaskDefinition_get_Settings(taskdef, &taskset);
    if (hr != S_OK) return hr;

    hr = IXmlReader_MoveToFirstAttribute(reader);

    while (hr == S_OK)
    {
        hr = IXmlReader_GetLocalName(reader, &name, NULL);
        if (hr != S_OK) break;

        hr = IXmlReader_GetValue(reader, &value, NULL);
        if (hr != S_OK) break;

        TRACE("%s=%s\n", debugstr_w(name), debugstr_w(value));

        if (!lstrcmpW(name, L"version"))
        {
            TASK_COMPATIBILITY compatibility = TASK_COMPATIBILITY_V2;

            if (!lstrcmpW(value, L"1.0"))
                compatibility = TASK_COMPATIBILITY_AT;
            else if (!lstrcmpW(value, L"1.1"))
                compatibility = TASK_COMPATIBILITY_V1;
            else if (!lstrcmpW(value, L"1.2"))
                compatibility = TASK_COMPATIBILITY_V2;
            else if (!lstrcmpW(value, L"1.3"))
                compatibility = TASK_COMPATIBILITY_V2_1;
            else
                FIXME("unknown version %s\n", debugstr_w(value));

            ITaskSettings_put_Compatibility(taskset, compatibility);
        }
        else if (!lstrcmpW(name, L"xmlns"))
        {
            if (lstrcmpW(value, L"http://schemas.microsoft.com/windows/2004/02/mit/task"))
            {
                FIXME("unknown namespace %s\n", debugstr_w(value));
                break;
            }
            xmlns_ok = TRUE;
        }
        else
            FIXME("unhandled Task attribute %s\n", debugstr_w(name));

        hr = IXmlReader_MoveToNextAttribute(reader);
    }

    ITaskSettings_Release(taskset);
    return xmlns_ok ? S_OK : SCHED_E_NAMESPACE;
}

static HRESULT read_task(IXmlReader *reader, ITaskDefinition *taskdef)
{
    HRESULT hr;
    XmlNodeType type;
    const WCHAR *name;

    if (IXmlReader_IsEmptyElement(reader))
    {
        TRACE("Task is empty\n");
        return S_OK;
    }

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_EndElement:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("/%s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Task"))
                return S_OK;

            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"RegistrationInfo"))
            {
                IRegistrationInfo *info;

                hr = ITaskDefinition_get_RegistrationInfo(taskdef, &info);
                if (hr != S_OK) return hr;
                hr = read_registration_info(reader, info);
                IRegistrationInfo_Release(info);
            }
            else if (!lstrcmpW(name, L"Settings"))
            {
                ITaskSettings *taskset;

                hr = ITaskDefinition_get_Settings(taskdef, &taskset);
                if (hr != S_OK) return hr;
                hr = read_settings(reader, taskset);
                ITaskSettings_Release(taskset);
            }
            else if (!lstrcmpW(name, L"Triggers"))
                hr = read_triggers(reader, taskdef);
            else if (!lstrcmpW(name, L"Principals"))
                hr = read_principals(reader, taskdef);
            else if (!lstrcmpW(name, L"Actions"))
                hr = read_actions(reader, taskdef);
            else if (!lstrcmpW(name, L"Data"))
            {
                WCHAR *value;
                hr = read_text_value(reader, &value);
                if (hr == S_OK)
                    ITaskDefinition_put_Data(taskdef, value);
            }
            else
                FIXME("unhandled Task element %s\n", debugstr_w(name));

            if (hr != S_OK) return hr;
            break;

        case XmlNodeType_Comment:
        case XmlNodeType_Whitespace:
            break;

        default:
            FIXME("unhandled Task node type %d\n", type);
            break;
        }
    }

    WARN("Task was not terminated\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT read_xml(IXmlReader *reader, ITaskDefinition *taskdef)
{
    HRESULT hr;
    XmlNodeType type;
    const WCHAR *name;

    while (IXmlReader_Read(reader, &type) == S_OK)
    {
        switch (type)
        {
        case XmlNodeType_XmlDeclaration:
            TRACE("XmlDeclaration\n");
            break;

        case XmlNodeType_Element:
            hr = IXmlReader_GetLocalName(reader, &name, NULL);
            if (hr != S_OK) return hr;

            TRACE("Element: %s\n", debugstr_w(name));

            if (!lstrcmpW(name, L"Task"))
            {
                hr = read_task_attributes(reader, taskdef);
                if (hr != S_OK) return hr;

                return read_task(reader, taskdef);
            }
            else
                FIXME("unhandled XML element %s\n", debugstr_w(name));

            break;

        case XmlNodeType_Comment:
        case XmlNodeType_Whitespace:
            break;

        default:
            FIXME("unhandled XML node type %d\n", type);
            break;
        }
    }

    WARN("Task definition was not found\n");
    return SCHED_E_MALFORMEDXML;
}

static HRESULT WINAPI TaskDefinition_put_XmlText(ITaskDefinition *iface, BSTR xml)
{
    TaskDefinition *taskdef = impl_from_ITaskDefinition(iface);
    HRESULT hr;
    IStream *stream;
    IXmlReader *reader;
    HGLOBAL hmem;
    void *buf;

    TRACE("%p,%s\n", iface, debugstr_w(xml));

    if (!xml) return E_INVALIDARG;

    hmem = GlobalAlloc(0, lstrlenW(xml) * sizeof(WCHAR));
    if (!hmem) return E_OUTOFMEMORY;

    buf = GlobalLock(hmem);
    memcpy(buf, xml, lstrlenW(xml) * sizeof(WCHAR));
    GlobalUnlock(hmem);

    hr = CreateStreamOnHGlobal(hmem, TRUE, &stream);
    if (hr != S_OK)
    {
        GlobalFree(hmem);
        return hr;
    }

    hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL);
    if (hr != S_OK)
    {
        IStream_Release(stream);
        return hr;
    }

    hr = IXmlReader_SetInput(reader, (IUnknown *)stream);
    if (hr == S_OK)
    {
        if (taskdef->reginfo)
        {
            IRegistrationInfo_Release(taskdef->reginfo);
            taskdef->reginfo = NULL;
        }
        if (taskdef->taskset)
        {
            ITaskSettings_Release(taskdef->taskset);
            taskdef->taskset = NULL;
        }
        if (taskdef->triggers)
        {
            ITriggerCollection_Release(taskdef->triggers);
            taskdef->triggers = NULL;
        }
        if (taskdef->principal)
        {
            IPrincipal_Release(taskdef->principal);
            taskdef->principal = NULL;
        }
        if (taskdef->actions)
        {
            IActionCollection_Release(taskdef->actions);
            taskdef->actions = NULL;
        }
        if (taskdef->data)
        {
            SysFreeString(taskdef->data);
            taskdef->data = NULL;
        }

        hr = read_xml(reader, iface);
    }

    IXmlReader_Release(reader);
    IStream_Release(stream);

    return hr;
}

static const ITaskDefinitionVtbl TaskDefinition_vtbl =
{
    TaskDefinition_QueryInterface,
    TaskDefinition_AddRef,
    TaskDefinition_Release,
    TaskDefinition_GetTypeInfoCount,
    TaskDefinition_GetTypeInfo,
    TaskDefinition_GetIDsOfNames,
    TaskDefinition_Invoke,
    TaskDefinition_get_RegistrationInfo,
    TaskDefinition_put_RegistrationInfo,
    TaskDefinition_get_Triggers,
    TaskDefinition_put_Triggers,
    TaskDefinition_get_Settings,
    TaskDefinition_put_Settings,
    TaskDefinition_get_Data,
    TaskDefinition_put_Data,
    TaskDefinition_get_Principal,
    TaskDefinition_put_Principal,
    TaskDefinition_get_Actions,
    TaskDefinition_put_Actions,
    TaskDefinition_get_XmlText,
    TaskDefinition_put_XmlText
};

HRESULT TaskDefinition_create(ITaskDefinition **obj)
{
    TaskDefinition *taskdef;

    taskdef = calloc(1, sizeof(*taskdef));
    if (!taskdef) return E_OUTOFMEMORY;

    taskdef->ITaskDefinition_iface.lpVtbl = &TaskDefinition_vtbl;
    taskdef->ref = 1;
    *obj = &taskdef->ITaskDefinition_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

typedef struct
{
    ITaskService ITaskService_iface;
    LONG ref;
    BOOL connected;
    DWORD version;
    WCHAR comp_name[MAX_COMPUTERNAME_LENGTH + 1];
    WCHAR user_name[256];
    WCHAR domain_name[256];
} TaskService;

static inline TaskService *impl_from_ITaskService(ITaskService *iface)
{
    return CONTAINING_RECORD(iface, TaskService, ITaskService_iface);
}

static ULONG WINAPI TaskService_AddRef(ITaskService *iface)
{
    TaskService *task_svc = impl_from_ITaskService(iface);
    return InterlockedIncrement(&task_svc->ref);
}

static ULONG WINAPI TaskService_Release(ITaskService *iface)
{
    TaskService *task_svc = impl_from_ITaskService(iface);
    LONG ref = InterlockedDecrement(&task_svc->ref);

    if (!ref)
    {
        TRACE("destroying %p\n", iface);
        free(task_svc);
    }

    return ref;
}

static HRESULT WINAPI TaskService_QueryInterface(ITaskService *iface, REFIID riid, void **obj)
{
    if (!riid || !obj) return E_INVALIDARG;

    TRACE("%p,%s,%p\n", iface, debugstr_guid(riid), obj);

    if (IsEqualGUID(riid, &IID_ITaskService) ||
        IsEqualGUID(riid, &IID_IDispatch) ||
        IsEqualGUID(riid, &IID_IUnknown))
    {
        ITaskService_AddRef(iface);
        *obj = iface;
        return S_OK;
    }

    FIXME("interface %s is not implemented\n", debugstr_guid(riid));
    *obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI TaskService_GetTypeInfoCount(ITaskService *iface, UINT *count)
{
    return taskschd_GetTypeInfoCount(count);
}

static HRESULT WINAPI TaskService_GetTypeInfo(ITaskService *iface, UINT index, LCID lcid, ITypeInfo **info)
{
    return taskschd_GetTypeInfo(&IID_ITaskService, index, lcid, info);
}

static HRESULT WINAPI TaskService_GetIDsOfNames(ITaskService *iface, REFIID riid, LPOLESTR *names,
                                                UINT count, LCID lcid, DISPID *dispid)
{
    return taskschd_GetIDsOfNames(&IID_ITaskService, riid, names, count, lcid, dispid);
}

static HRESULT WINAPI TaskService_Invoke(ITaskService *iface, DISPID dispid, REFIID riid, LCID lcid, WORD flags,
                                         DISPPARAMS *params, VARIANT *result, EXCEPINFO *excepinfo, UINT *argerr)
{
    return taskschd_Invoke(&IID_ITaskService, iface, dispid, riid, lcid, flags, params, result, excepinfo, argerr);
}

static HRESULT WINAPI TaskService_GetFolder(ITaskService *iface, BSTR path, ITaskFolder **folder)
{
    TaskService *task_svc = impl_from_ITaskService(iface);

    TRACE("%p,%s,%p\n", iface, debugstr_w(path), folder);

    if (!folder) return E_POINTER;

    if (!task_svc->connected)
        return HRESULT_FROM_WIN32(ERROR_ONLY_IF_CONNECTED);

    return TaskFolder_create(path, NULL, folder, FALSE);
}

static HRESULT WINAPI TaskService_GetRunningTasks(ITaskService *iface, LONG flags, IRunningTaskCollection **tasks)
{
    FIXME("%p,%lx,%p: stub\n", iface, flags, tasks);
    return E_NOTIMPL;
}

static HRESULT WINAPI TaskService_NewTask(ITaskService *iface, DWORD flags, ITaskDefinition **definition)
{
    TRACE("%p,%lx,%p\n", iface, flags, definition);

    if (!definition) return E_POINTER;

    if (flags)
        FIXME("unsupported flags %lx\n", flags);

    return TaskDefinition_create(definition);
}

static inline BOOL is_variant_null(const VARIANT *var)
{
    /* an omitted optional argument of a late-bound call is VT_ERROR/DISP_E_PARAMNOTFOUND */
    return V_VT(var) == VT_EMPTY || V_VT(var) == VT_NULL ||
          (V_VT(var) == VT_ERROR && V_ERROR(var) == DISP_E_PARAMNOTFOUND) ||
          (V_VT(var) == VT_BSTR && (V_BSTR(var) == NULL || !*V_BSTR(var)));
}

static HRESULT start_schedsvc(void)
{
    SC_HANDLE scm, service;
    SERVICE_STATUS_PROCESS status;
    ULONGLONG start_time;
    HRESULT hr = SCHED_E_SERVICE_NOT_RUNNING;

    TRACE("Trying to start Schedule service\n");

    scm = OpenSCManagerW(NULL, NULL, 0);
    if (!scm) return SCHED_E_SERVICE_NOT_INSTALLED;

    service = OpenServiceW(scm, L"Schedule", SERVICE_START | SERVICE_QUERY_STATUS);
    if (service)
    {
        if (StartServiceW(service, 0, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
        {
            start_time = GetTickCount64();
            do
            {
                DWORD dummy;

                if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&status, sizeof(status), &dummy))
                {
                    WARN("failed to query scheduler status (%lu)\n", GetLastError());
                    break;
                }

                if (status.dwCurrentState == SERVICE_RUNNING)
                {
                    hr = S_OK;
                    break;
                }

                if (GetTickCount64() - start_time > 30000) break;
                Sleep(1000);

            } while (status.dwCurrentState == SERVICE_START_PENDING);

            if (status.dwCurrentState != SERVICE_RUNNING)
                WARN("scheduler failed to start %lu\n", status.dwCurrentState);
        }
        else
            WARN("failed to start scheduler service (%lu)\n", GetLastError());

        CloseServiceHandle(service);
    }
    else
        WARN("failed to open scheduler service (%lu)\n", GetLastError());

    CloseServiceHandle(scm);
    return hr;
}

static HRESULT WINAPI TaskService_Connect(ITaskService *iface, VARIANT server, VARIANT user, VARIANT domain, VARIANT password)
{
    static WCHAR ncalrpc[] = L"ncalrpc";
    TaskService *task_svc = impl_from_ITaskService(iface);
    WCHAR comp_name[MAX_COMPUTERNAME_LENGTH + 1];
    WCHAR user_name[256];
    WCHAR domain_name[256];
    DWORD len;
    HRESULT hr;
    RPC_WSTR binding_str;
    extern handle_t schrpc_handle;

    TRACE("%p,%s,%s,%s,%s\n", iface, debugstr_variant(&server), debugstr_variant(&user),
          debugstr_variant(&domain), debugstr_variant(&password));

    if (!is_variant_null(&user) || !is_variant_null(&domain) || !is_variant_null(&password))
        FIXME("user/domain/password are ignored\n");

    len = ARRAY_SIZE(comp_name);
    if (!GetComputerNameW(comp_name, &len))
        return HRESULT_FROM_WIN32(GetLastError());

    len = ARRAY_SIZE(user_name);
    if (!GetUserNameW(user_name, &len))
        return HRESULT_FROM_WIN32(GetLastError());

    len = ARRAY_SIZE(domain_name);
    if(!GetEnvironmentVariableW(L"USERDOMAIN", domain_name, len))
    {
        if (!GetComputerNameExW(ComputerNameDnsHostname, domain_name, &len))
            return HRESULT_FROM_WIN32(GetLastError());
        wcsupr(domain_name);
    }

    if (!is_variant_null(&server))
    {
        const WCHAR *server_name;

        if (V_VT(&server) != VT_BSTR)
        {
            FIXME("server variant type %d is not supported\n", V_VT(&server));
            return HRESULT_FROM_WIN32(ERROR_BAD_NETPATH);
        }

        /* skip UNC prefix if any */
        server_name = V_BSTR(&server);
        if (server_name[0] == '\\' && server_name[1] == '\\')
            server_name += 2;

        if (wcsicmp(server_name, comp_name))
        {
            FIXME("connection to remote server %s is not supported\n", debugstr_w(V_BSTR(&server)));
            return HRESULT_FROM_WIN32(ERROR_BAD_NETPATH);
        }
    }

    hr = start_schedsvc();
    if (hr != S_OK) return hr;

    hr = RpcStringBindingComposeW(NULL, ncalrpc, NULL, NULL, NULL, &binding_str);
    if (hr != RPC_S_OK) return hr;
    hr = RpcBindingFromStringBindingW(binding_str, &schrpc_handle);
    RpcStringFreeW(&binding_str);
    if (hr != RPC_S_OK) return hr;

    /* Make sure that the connection works */
    hr = SchRpcHighestVersion(&task_svc->version);
    if (hr != S_OK) return hr;

    TRACE("server version %#lx\n", task_svc->version);

    lstrcpyW(task_svc->comp_name, comp_name);
    lstrcpyW(task_svc->user_name, user_name);
    lstrcpyW(task_svc->domain_name, domain_name);
    task_svc->connected = TRUE;

    return S_OK;
}

static HRESULT WINAPI TaskService_get_Connected(ITaskService *iface, VARIANT_BOOL *connected)
{
    TaskService *task_svc = impl_from_ITaskService(iface);

    TRACE("%p,%p\n", iface, connected);

    if (!connected) return E_POINTER;

    *connected = task_svc->connected ? VARIANT_TRUE : VARIANT_FALSE;

    return S_OK;
}

static HRESULT WINAPI TaskService_get_TargetServer(ITaskService *iface, BSTR *server)
{
    TaskService *task_svc = impl_from_ITaskService(iface);

    TRACE("%p,%p\n", iface, server);

    if (!server) return E_POINTER;

    if (!task_svc->connected)
        return HRESULT_FROM_WIN32(ERROR_ONLY_IF_CONNECTED);

    *server = SysAllocString(task_svc->comp_name);
    if (!*server) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TaskService_get_ConnectedUser(ITaskService *iface, BSTR *user)
{
    TaskService *task_svc = impl_from_ITaskService(iface);

    TRACE("%p,%p\n", iface, user);

    if (!user) return E_POINTER;

    if (!task_svc->connected)
        return HRESULT_FROM_WIN32(ERROR_ONLY_IF_CONNECTED);

    *user = SysAllocString(task_svc->user_name);
    if (!*user) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TaskService_get_ConnectedDomain(ITaskService *iface, BSTR *domain)
{
    TaskService *task_svc = impl_from_ITaskService(iface);

    TRACE("%p,%p\n", iface, domain);

    if (!domain) return E_POINTER;

    if (!task_svc->connected)
        return HRESULT_FROM_WIN32(ERROR_ONLY_IF_CONNECTED);

    *domain = SysAllocString(task_svc->domain_name);
    if (!*domain) return E_OUTOFMEMORY;

    return S_OK;
}

static HRESULT WINAPI TaskService_get_HighestVersion(ITaskService *iface, DWORD *version)
{
    TaskService *task_svc = impl_from_ITaskService(iface);

    TRACE("%p,%p\n", iface, version);

    if (!version) return E_POINTER;

    if (!task_svc->connected)
        return HRESULT_FROM_WIN32(ERROR_ONLY_IF_CONNECTED);

    *version = task_svc->version;

    return S_OK;
}

static const ITaskServiceVtbl TaskService_vtbl =
{
    TaskService_QueryInterface,
    TaskService_AddRef,
    TaskService_Release,
    TaskService_GetTypeInfoCount,
    TaskService_GetTypeInfo,
    TaskService_GetIDsOfNames,
    TaskService_Invoke,
    TaskService_GetFolder,
    TaskService_GetRunningTasks,
    TaskService_NewTask,
    TaskService_Connect,
    TaskService_get_Connected,
    TaskService_get_TargetServer,
    TaskService_get_ConnectedUser,
    TaskService_get_ConnectedDomain,
    TaskService_get_HighestVersion
};

HRESULT TaskService_create(void **obj)
{
    TaskService *task_svc;

    task_svc = malloc(sizeof(*task_svc));
    if (!task_svc) return E_OUTOFMEMORY;

    task_svc->ITaskService_iface.lpVtbl = &TaskService_vtbl;
    task_svc->ref = 1;
    task_svc->connected = FALSE;
    *obj = &task_svc->ITaskService_iface;

    TRACE("created %p\n", *obj);

    return S_OK;
}

void __RPC_FAR *__RPC_USER MIDL_user_allocate(SIZE_T n)
{
    return malloc(n);
}

void __RPC_USER MIDL_user_free(void __RPC_FAR *p)
{
    free(p);
}
