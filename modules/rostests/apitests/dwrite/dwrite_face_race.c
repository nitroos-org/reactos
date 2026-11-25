/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     DirectWrite keeps one FreeType library for the whole process; font faces created and
 *              released, and glyphs measured, on several threads at once must not corrupt it
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#define COBJMACROS
#include <windows.h>
#include <dwrite.h>

#include "wine/test.h"

#define NUM_THREADS 16
#define ITERATIONS 100

struct thread_data
{
    HANDLE start;
    LONG failed;
};

static void use_face(struct thread_data *data)
{
    IDWriteFontCollection *collection;
    IDWriteFontFamily *family;
    IDWriteFontFace *face;
    IDWriteFactory *factory;
    IDWriteFont *font;
    UINT32 codepoints[4] = { 'A', 'B', 'g', 'y' };
    UINT16 indices[4];
    DWRITE_GLYPH_METRICS metrics[4];
    HRESULT hr;

    /* An isolated factory has its own faces, but they all live in the one FreeType library. */
    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_ISOLATED, &IID_IDWriteFactory, (IUnknown **)&factory);
    if (FAILED(hr))
        goto fail;
    hr = IDWriteFactory_GetSystemFontCollection(factory, &collection, FALSE);
    if (FAILED(hr))
    {
        IDWriteFactory_Release(factory);
        goto fail;
    }
    hr = IDWriteFontCollection_GetFontFamily(collection, 0, &family);
    if (SUCCEEDED(hr))
    {
        hr = IDWriteFontFamily_GetFont(family, 0, &font);
        if (SUCCEEDED(hr))
        {
            hr = IDWriteFont_CreateFontFace(font, &face);
            if (SUCCEEDED(hr))
            {
                /* The first glyph query makes the face create its FreeType face. */
                hr = IDWriteFontFace_GetGlyphIndices(face, codepoints, 4, indices);
                if (SUCCEEDED(hr))
                    hr = IDWriteFontFace_GetDesignGlyphMetrics(face, indices, 4, metrics, FALSE);
                IDWriteFontFace_Release(face);
            }
            IDWriteFont_Release(font);
        }
        IDWriteFontFamily_Release(family);
    }
    IDWriteFontCollection_Release(collection);
    IDWriteFactory_Release(factory);
    if (FAILED(hr))
        goto fail;
    return;
fail:
    InterlockedIncrement(&data->failed);
}

/* Faces created and released back to back from one font file: nothing but FreeType's face list is touched in the loop,
   which makes the faces of several threads overlap far more often than the factory round trips above do */
#define LEAN_ITERATIONS 6000

static void use_faces_fast(struct thread_data *data)
{
    IDWriteFactory *factory;
    IDWriteFontFile *file;
    WCHAR path[MAX_PATH];
    HRESULT hr;
    int i;

    GetWindowsDirectoryW(path, MAX_PATH);
    lstrcatW(path, L"\\Fonts\\arial.ttf");
    hr = DWriteCreateFactory(DWRITE_FACTORY_TYPE_ISOLATED, &IID_IDWriteFactory, (IUnknown **)&factory);
    if (FAILED(hr))
        goto fail;
    hr = IDWriteFactory_CreateFontFileReference(factory, path, NULL, &file);
    if (FAILED(hr))
    {
        IDWriteFactory_Release(factory);
        goto fail;
    }
    for (i = 0; i < LEAN_ITERATIONS; ++i)
    {
        IDWriteFontFace *face;
        UINT32 codepoint = 'A';
        UINT16 index;

        hr = IDWriteFactory_CreateFontFace(factory, DWRITE_FONT_FACE_TYPE_TRUETYPE, 1, &file, 0, DWRITE_FONT_SIMULATIONS_NONE, &face);
        if (FAILED(hr))
            break;
        /* the first glyph query makes the face create its FreeType face */
        hr = IDWriteFontFace_GetGlyphIndices(face, &codepoint, 1, &index);
        if (SUCCEEDED(hr))
        {
            DWRITE_GLYPH_METRICS metrics;
            hr = IDWriteFontFace_GetDesignGlyphMetrics(face, &index, 1, &metrics, FALSE);
        }
        IDWriteFontFace_Release(face);
        if (FAILED(hr))
            break;
    }
    IDWriteFontFile_Release(file);
    IDWriteFactory_Release(factory);
    if (SUCCEEDED(hr))
        return;
fail:
    InterlockedIncrement(&data->failed);
}

static DWORD WINAPI face_thread(void *param)
{
    struct thread_data *data = param;
    int i;

    WaitForSingleObject(data->start, INFINITE);
    use_faces_fast(data);
    for (i = 0; i < ITERATIONS; ++i)
        use_face(data);
    return 0;
}

START_TEST(dwrite_face_race)
{
    HANDLE threads[NUM_THREADS];
    struct thread_data data;
    int i;

    data.start = CreateEventW(NULL, TRUE, FALSE, NULL);
    data.failed = 0;

    for (i = 0; i < NUM_THREADS; ++i)
        threads[i] = CreateThread(NULL, 0, face_thread, &data, 0, NULL);
    SetEvent(data.start);
    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);
    for (i = 0; i < NUM_THREADS; ++i)
        CloseHandle(threads[i]);

    ok(data.failed == 0, "%ld of %d face round trips failed\n", data.failed, NUM_THREADS * (ITERATIONS + 1));
    CloseHandle(data.start);
}
