/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     testlist
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define STANDALONE
#include <apitest.h>

extern void func_Schtasks(void);
extern void func_TaskSchedulerCalendar(void);
extern void func_TaskSchedulerDispatch(void);
extern void func_TaskScheduler(void);
extern void func_TaskSchedulerApi(void);
extern void func_TaskSchedulerSecurity(void);

const struct test winetest_testlist[] =
{
    { "Schtasks", func_Schtasks },
    { "TaskSchedulerCalendar", func_TaskSchedulerCalendar },
    { "TaskSchedulerDispatch", func_TaskSchedulerDispatch },
    { "TaskScheduler", func_TaskScheduler },
    { "TaskSchedulerApi", func_TaskSchedulerApi },
    { "TaskSchedulerSecurity", func_TaskSchedulerSecurity },
    { 0, 0 }
};
