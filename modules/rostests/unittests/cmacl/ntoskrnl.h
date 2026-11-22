/*
 * PROJECT:     NitroOS unit tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     User mode stand-in for ntoskrnl.h, for ntoskrnl/config/cmaclsd.c
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#pragma once

#include <apitest.h>

#define WIN32_NO_STATUS
#include <ndk/rtlfuncs.h>
