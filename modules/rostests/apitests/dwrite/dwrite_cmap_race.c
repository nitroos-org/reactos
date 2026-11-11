/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DirectWrite builds the character map of a font when it is first asked, and several threads
 *              may ask at once: the map must be built once and only used when it is complete
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <windows.h>
#include <dwrite.h>

#include "wine/test.h"

#define NUM_THREADS 4
#define ITERATIONS 300

struct thread_data
{
    IDWriteFont *font;
    HANDLE start;
    LONG wrong;
};

static DWORD WINAPI cmap_thread(void *param)
{
    struct thread_data *data = param;
    BOOL exists;
    HRESULT hr;
    UINT32 ch;

    WaitForSingleObject(data->start, INFINITE);
    for (ch = 'A'; ch < 'A' + 8; ++ch)
    {
        exists = FALSE;
        hr = IDWriteFont_HasCharacter(data->font, ch, &exists);
        if (FAILED(hr) || !exists)
            InterlockedIncrement(&data->wrong);
    }
    return 0;
}

START_TEST(dwrite_cmap_race)
{
    IDWriteFontCollection *collection;
    IDWriteFontFamily *family;
    IDWriteFactory *factory;
    IDWriteFont *font;
    HANDLE threads[NUM_THREADS];
    struct thread_data data;
    LONG wrong = 0;
    HRESULT hr;
    int i, j;

    data.start = CreateEventW(NULL, TRUE, FALSE, NULL);

    for (i = 0; i < ITERATIONS; ++i)
    {
        /* An isolated factory has its own font data, so the map is not built yet. */
        hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_ISOLATED, &IID_IDWriteFactory, (IUnknown **)&factory);
        ok(hr == S_OK, "DWriteCreateFactory failed, hr %#lx\n", hr);
        if (FAILED(hr))
            return;
        hr = IDWriteFactory_GetSystemFontCollection(factory, &collection, FALSE);
        ok(hr == S_OK, "GetSystemFontCollection failed, hr %#lx\n", hr);
        hr = IDWriteFontCollection_GetFontFamily(collection, 0, &family);
        ok(hr == S_OK, "GetFontFamily failed, hr %#lx\n", hr);
        hr = IDWriteFontFamily_GetFont(family, 0, &font);
        ok(hr == S_OK, "GetFont failed, hr %#lx\n", hr);
        if (FAILED(hr))
            return;

        data.font = font;
        data.wrong = 0;
        ResetEvent(data.start);
        for (j = 0; j < NUM_THREADS; ++j)
            threads[j] = CreateThread(NULL, 0, cmap_thread, &data, 0, NULL);
        SetEvent(data.start);
        WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
        for (j = 0; j < NUM_THREADS; ++j)
            CloseHandle(threads[j]);
        wrong += data.wrong;

        IDWriteFont_Release(font);
        IDWriteFontFamily_Release(family);
        IDWriteFontCollection_Release(collection);
        IDWriteFactory_Release(factory);
    }
    ok(wrong == 0, "%ld of %d character lookups failed\n", wrong, ITERATIONS * NUM_THREADS * 8);
    CloseHandle(data.start);
}
