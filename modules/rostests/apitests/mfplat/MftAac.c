/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     MFTRegister / MFTEnumEx registration of an AAC decoder transform, and, when the optional
 *              "AAC audio decoder" feature (aac-lc: LC only, or aac: LC + HE-AAC + HE-AAC v2) is turned on, the
 *              behaviour of CLSID_CMSAACDecMFT
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Part 1 always runs: it registers a throw-away transform the way the AAC feature registers its own (category
 * MFT_CATEGORY_AUDIO_DECODER, input MFAudioFormat_AAC, output PCM and Float, MFT_ENUM_FLAG_SYNCMFT) and checks that
 * MFTEnumEx finds it for the AAC input type and not for others, and that MFTUnregister removes it.
 * Part 2 runs when MFTEnumEx lists CLSID_CMSAACDecMFT (the feature is on): the documented behaviour of the Windows AAC
 * decoder MFT for the attributes Firefox sets (MF_MT_AAC_PAYLOAD_TYPE, MF_MT_USER_DATA = HEAACWAVEINFO tail + ASC),
 * one silent AAC-LC frame, and that HE-AAC (SBR, audioObjectType 5) and HE-AAC v2 (PS, 29) AudioSpecificConfigs are
 * refused by the aac-lc feature and accepted by the aac feature (told apart by the registered class name); AAC Main
 * (1) is refused by both.
 * Not measured on Windows (the oracle was not used for this test): expectations come from the Microsoft documentation.
 */

#include <apitest.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#define COBJMACROS
#include <ole2.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <wmcodecdsp.h>

/* the CLSID Windows (and Firefox) use for the AAC decoder MFT; the NitroOS feature registers its own DLL under it */
static const GUID CLSID_AacDecoder =
    { 0x32d186a7, 0x218f, 0x4c75, { 0x88, 0x76, 0xdd, 0x77, 0x27, 0x3a, 0x89, 0x99 } };

/* a CLSID only this test uses */
static const GUID CLSID_AacApitestDummy =
    { 0x7e2d1f4a, 0x0b1c, 0x4b5d, { 0x9a, 0x53, 0x4e, 0x1d, 0x7a, 0x5c, 0x00, 0x01 } };

static BOOL ClsidInList(IMFActivate **Acts, UINT32 Count, const GUID *Clsid)
{
    UINT32 i;
    GUID g;

    for (i = 0; i < Count; i++)
    {
        if (SUCCEEDED(IMFActivate_GetGUID(Acts[i], &MFT_TRANSFORM_CLSID_Attribute, &g)) && IsEqualGUID(&g, Clsid))
            return TRUE;
    }
    return FALSE;
}

static BOOL Enum(const GUID *Subtype, UINT32 Flags, const GUID *Clsid)
{
    MFT_REGISTER_TYPE_INFO In = { MFMediaType_Audio, *Subtype };
    IMFActivate **Acts = NULL;
    UINT32 Count = 0, i;
    BOOL Found;
    HRESULT hr;

    hr = MFTEnumEx(MFT_CATEGORY_AUDIO_DECODER, Flags, &In, NULL, &Acts, &Count);
    ok(hr == S_OK, "MFTEnumEx returned %08lx\n", hr);
    if (FAILED(hr))
        return FALSE;
    Found = ClsidInList(Acts, Count, Clsid);
    for (i = 0; i < Count; i++)
        IMFActivate_Release(Acts[i]);
    CoTaskMemFree(Acts);
    return Found;
}

static void TestRegistration(void)
{
    MFT_REGISTER_TYPE_INFO In[1] = { { MFMediaType_Audio, MFAudioFormat_AAC } };
    MFT_REGISTER_TYPE_INFO Out[2] = { { MFMediaType_Audio, MFAudioFormat_PCM }, { MFMediaType_Audio, MFAudioFormat_Float } };
    HRESULT hr;

    hr = MFTRegister(CLSID_AacApitestDummy, MFT_CATEGORY_AUDIO_DECODER, (LPWSTR)L"mfplat apitest AAC (dummy)",
                     MFT_ENUM_FLAG_SYNCMFT, 1, In, 2, Out, NULL);
    if (hr == E_ACCESSDENIED || hr == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED))
    {
        skip("MFTRegister needs an administrator (%08lx)\n", hr);
        return;
    }
    ok(hr == S_OK, "MFTRegister returned %08lx\n", hr);
    if (FAILED(hr))
        return;

    ok(Enum(&MFAudioFormat_AAC, MFT_ENUM_FLAG_SYNCMFT, &CLSID_AacApitestDummy),
       "the registered transform is not enumerated for AAC input\n");
    ok(Enum(&MFAudioFormat_AAC, MFT_ENUM_FLAG_ALL, &CLSID_AacApitestDummy),
       "the registered transform is not enumerated with MFT_ENUM_FLAG_ALL\n");
    ok(!Enum(&MFAudioFormat_MP3, MFT_ENUM_FLAG_SYNCMFT, &CLSID_AacApitestDummy),
       "the AAC transform is enumerated for MP3 input\n");
    ok(!Enum(&MFAudioFormat_AAC, MFT_ENUM_FLAG_ASYNCMFT, &CLSID_AacApitestDummy),
       "a SYNCMFT transform is enumerated for MFT_ENUM_FLAG_ASYNCMFT\n");

    hr = MFTUnregister(CLSID_AacApitestDummy);
    ok(hr == S_OK, "MFTUnregister returned %08lx\n", hr);
    ok(!Enum(&MFAudioFormat_AAC, MFT_ENUM_FLAG_ALL, &CLSID_AacApitestDummy),
       "the transform is still enumerated after MFTUnregister\n");
}

static IMFMediaType *AacType(const BYTE *UserData, UINT32 UserDataLen, UINT32 Payload, UINT32 Channels, UINT32 Rate)
{
    IMFMediaType *Type = NULL;

    if (FAILED(MFCreateMediaType(&Type)))
        return NULL;
    IMFMediaType_SetGUID(Type, &MF_MT_MAJOR_TYPE, &MFMediaType_Audio);
    IMFMediaType_SetGUID(Type, &MF_MT_SUBTYPE, &MFAudioFormat_AAC);
    IMFMediaType_SetUINT32(Type, &MF_MT_AUDIO_PREFER_WAVEFORMATEX, 1);
    IMFMediaType_SetUINT32(Type, &MF_MT_AAC_PAYLOAD_TYPE, Payload);
    if (Channels)
        IMFMediaType_SetUINT32(Type, &MF_MT_AUDIO_NUM_CHANNELS, Channels);
    if (Rate)
        IMFMediaType_SetUINT32(Type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, Rate);
    if (UserData)
        IMFMediaType_SetBlob(Type, &MF_MT_USER_DATA, UserData, UserDataLen);
    return Type;
}

/* TRUE when the registered decoder is the full-AAC one (class name "... (NitroOS AAC)", not "... (NitroOS AAC-LC)") */
static BOOL IsFullAac(void)
{
    WCHAR Name[128];
    DWORD Size = sizeof(Name) - sizeof(WCHAR), Type;
    HKEY Key;
    BOOL Full = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\{32D186A7-218F-4C75-8876-DD77273A8999}", 0, KEY_READ, &Key) != ERROR_SUCCESS)
        return FALSE;
    ZeroMemory(Name, sizeof(Name));
    if (RegQueryValueExW(Key, NULL, NULL, &Type, (LPBYTE)Name, &Size) == ERROR_SUCCESS && Type == REG_SZ)
        Full = wcsstr(Name, L"(NitroOS AAC)") != NULL;
    RegCloseKey(Key);
    return Full;
}

static void TestDecoder(void)
{
    /* HEAACWAVEINFO tail (payload 0, level 0x29, struct type 0, 0, 0) + AudioSpecificConfig: AAC-LC, 44100 Hz, mono */
    static const BYTE UserLc[] = { 0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x08 };
    /* explicit HE-AAC signalling: audioObjectType 5 (SBR), core 24000 Hz mono, extension 48000 Hz, then AAC-LC */
    static const BYTE UserHe[] = { 0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2b, 0x09, 0x88 };
    /* the same as HE-AAC v2: audioObjectType 29 (PS) */
    static const BYTE UserHe2[] = { 0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xeb, 0x09, 0x88 };
    /* AAC Main (audioObjectType 1), 44100 Hz mono */
    static const BYTE UserMain[] = { 0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a, 0x08 };
    /* one raw_data_block: a mono SCE with max_sfb 0 = 1024 samples of silence */
    static const BYTE Silence[] = { 0x00, 0x00, 0x00, 0x07 };
    IMFTransform *Mft = NULL;
    IMFMediaType *Type, *OutType = NULL, *Cur = NULL;
    MFT_INPUT_STREAM_INFO InInfo;
    MFT_OUTPUT_STREAM_INFO OutInfo;
    DWORD InMin, InMax, OutMin, OutMax, nIn, nOut, Flags, Status;
    GUID Sub;
    UINT32 Val;
    HRESULT hr;
    BOOL Full;
    int i;

    hr = CoCreateInstance(&CLSID_AacDecoder, NULL, CLSCTX_INPROC_SERVER, &IID_IMFTransform, (void **)&Mft);
    ok(hr == S_OK, "CoCreateInstance(CLSID_CMSAACDecMFT) returned %08lx\n", hr);
    if (FAILED(hr))
        return;

    hr = IMFTransform_GetStreamCount(Mft, &nIn, &nOut);
    ok(hr == S_OK && nIn == 1 && nOut == 1, "GetStreamCount: %08lx, %lu in, %lu out\n", hr, nIn, nOut);
    hr = IMFTransform_GetStreamLimits(Mft, &InMin, &InMax, &OutMin, &OutMax);
    ok(hr == S_OK && InMin == 1 && InMax == 1 && OutMin == 1 && OutMax == 1, "GetStreamLimits: %08lx\n", hr);

    hr = IMFTransform_GetInputAvailableType(Mft, 0, 0, &Type);
    ok(hr == S_OK, "GetInputAvailableType returned %08lx\n", hr);
    if (hr == S_OK)
    {
        hr = IMFMediaType_GetGUID(Type, &MF_MT_SUBTYPE, &Sub);
        ok(hr == S_OK && IsEqualGUID(&Sub, &MFAudioFormat_AAC), "available input subtype is not AAC\n");
        IMFMediaType_Release(Type);
    }

    /* no type yet */
    hr = IMFTransform_GetOutputAvailableType(Mft, 0, 0, &Type);
    ok(hr == MF_E_TRANSFORM_TYPE_NOT_SET, "GetOutputAvailableType before SetInputType returned %08lx\n", hr);
    hr = IMFTransform_GetInputCurrentType(Mft, 0, &Cur);
    ok(hr == MF_E_TRANSFORM_TYPE_NOT_SET, "GetInputCurrentType before SetInputType returned %08lx\n", hr);

    /* HE-AAC (audioObjectType 5) and HE-AAC v2 (29): refused by the LC-only feature, accepted by the full one;
     * AAC Main (1) and ADIF (payload 2) are refused by both, also as a test */
    Full = IsFullAac();
    trace("decoder under test: %s\n", Full ? "full AAC (LC, HE-AAC, HE-AAC v2)" : "AAC-LC only");
    for (i = 0; i < 2; i++)
    {
        Type = AacType(i ? UserHe2 : UserHe, sizeof(UserHe), 0, 0, 0);
        hr = IMFTransform_SetInputType(Mft, 0, Type, MFT_SET_TYPE_TEST_ONLY);
        ok(hr == (Full ? S_OK : MF_E_INVALIDMEDIATYPE), "SetInputType(test, %s) returned %08lx\n", i ? "HE-AAC v2" : "HE-AAC", hr);
        hr = IMFTransform_SetInputType(Mft, 0, Type, 0);
        ok(hr == (Full ? S_OK : MF_E_INVALIDMEDIATYPE), "SetInputType(%s) returned %08lx\n", i ? "HE-AAC v2" : "HE-AAC", hr);
        if (Full && hr == S_OK)
        {
            /* the output type of HE-AAC is at the SBR rate (48000 Hz); HE-AAC v2 is stereo */
            IMFMediaType *Out0 = NULL;
            hr = IMFTransform_GetOutputAvailableType(Mft, 0, 0, &Out0);
            ok(hr == S_OK, "GetOutputAvailableType(%s) returned %08lx\n", i ? "HE-AAC v2" : "HE-AAC", hr);
            if (Out0)
            {
                UINT32 V = 0;
                hr = IMFMediaType_GetUINT32(Out0, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &V);
                ok(hr == S_OK && V == 48000, "%s output rate %u (%08lx), expected 48000\n", i ? "HE-AAC v2" : "HE-AAC", V, hr);
                hr = IMFMediaType_GetUINT32(Out0, &MF_MT_AUDIO_NUM_CHANNELS, &V);
                ok(hr == S_OK && V == (i ? 2u : 1u), "%s output channels %u (%08lx)\n", i ? "HE-AAC v2" : "HE-AAC", V, hr);
                IMFMediaType_Release(Out0);
            }
        }
        IMFMediaType_Release(Type);
    }
    Type = AacType(UserMain, sizeof(UserMain), 0, 0, 0);
    hr = IMFTransform_SetInputType(Mft, 0, Type, MFT_SET_TYPE_TEST_ONLY);
    ok(hr == MF_E_INVALIDMEDIATYPE, "SetInputType(test, AAC Main) returned %08lx\n", hr);
    IMFMediaType_Release(Type);
    Type = AacType(UserLc, sizeof(UserLc), 2, 1, 44100);
    hr = IMFTransform_SetInputType(Mft, 0, Type, 0);
    ok(hr == MF_E_INVALIDMEDIATYPE, "SetInputType(ADIF payload) returned %08lx\n", hr);
    IMFMediaType_Release(Type);

    /* the type Firefox sets */
    Type = AacType(UserLc, sizeof(UserLc), 0, 0, 0);
    hr = IMFTransform_SetInputType(Mft, 0, Type, MFT_SET_TYPE_TEST_ONLY);
    ok(hr == S_OK, "SetInputType(test, AAC-LC) returned %08lx\n", hr);
    hr = IMFTransform_SetInputType(Mft, 0, Type, 0);
    ok(hr == S_OK, "SetInputType(AAC-LC) returned %08lx\n", hr);
    IMFMediaType_Release(Type);
    if (FAILED(hr))
        goto done;

    hr = IMFTransform_GetInputCurrentType(Mft, 0, &Cur);
    ok(hr == S_OK, "GetInputCurrentType returned %08lx\n", hr);
    if (Cur)
        IMFMediaType_Release(Cur);

    hr = IMFTransform_GetInputStreamInfo(Mft, 0, &InInfo);
    ok(hr == S_OK, "GetInputStreamInfo returned %08lx\n", hr);
    ok((InInfo.dwFlags & (MFT_INPUT_STREAM_WHOLE_SAMPLES | MFT_INPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER)) ==
       (MFT_INPUT_STREAM_WHOLE_SAMPLES | MFT_INPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER), "input flags %08lx\n", InInfo.dwFlags);

    /* output types: PCM 16 bit, then float 32 bit, mono 44100 as the ASC says */
    for (i = 0; i < 2; i++)
    {
        hr = IMFTransform_GetOutputAvailableType(Mft, 0, i, &Type);
        ok(hr == S_OK, "GetOutputAvailableType(%d) returned %08lx\n", i, hr);
        if (FAILED(hr))
            continue;
        hr = IMFMediaType_GetGUID(Type, &MF_MT_SUBTYPE, &Sub);
        ok(hr == S_OK && IsEqualGUID(&Sub, i ? &MFAudioFormat_Float : &MFAudioFormat_PCM), "output type %d subtype wrong\n", i);
        hr = IMFMediaType_GetUINT32(Type, &MF_MT_AUDIO_NUM_CHANNELS, &Val);
        ok(hr == S_OK && Val == 1, "output type %d channels %lu\n", i, (ULONG)Val);
        hr = IMFMediaType_GetUINT32(Type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &Val);
        ok(hr == S_OK && Val == 44100, "output type %d rate %lu\n", i, (ULONG)Val);
        hr = IMFMediaType_GetUINT32(Type, &MF_MT_AUDIO_BITS_PER_SAMPLE, &Val);
        ok(hr == S_OK && Val == (i ? 32u : 16u), "output type %d bits %lu\n", i, (ULONG)Val);
        if (i == 0)
            OutType = Type;
        else
            IMFMediaType_Release(Type);
    }
    hr = IMFTransform_GetOutputAvailableType(Mft, 0, 2, &Type);
    ok(hr == MF_E_NO_MORE_TYPES, "GetOutputAvailableType(2) returned %08lx\n", hr);
    if (!OutType)
        goto done;

    hr = IMFTransform_SetOutputType(Mft, 0, OutType, 0);
    ok(hr == S_OK, "SetOutputType(PCM16) returned %08lx\n", hr);

    hr = IMFTransform_GetOutputStreamInfo(Mft, 0, &OutInfo);
    ok(hr == S_OK, "GetOutputStreamInfo returned %08lx\n", hr);
    ok(OutInfo.cbSize >= 1024 * 2, "output cbSize %lu is smaller than one frame\n", OutInfo.cbSize);
    ok(!(OutInfo.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES), "the MFT claims to provide output samples\n");

    /* nothing decoded yet */
    {
        MFT_OUTPUT_DATA_BUFFER Buf = { 0 };
        IMFSample *OutS;
        IMFMediaBuffer *OutB, *InB;
        IMFSample *InS;
        BYTE *p;
        DWORD Len;
        BOOL AllZero = TRUE;

        MFCreateSample(&OutS);
        MFCreateMemoryBuffer(OutInfo.cbSize, &OutB);
        IMFSample_AddBuffer(OutS, OutB);
        Buf.pSample = OutS;
        hr = IMFTransform_ProcessOutput(Mft, 0, 1, &Buf, &Status);
        ok(hr == MF_E_TRANSFORM_NEED_MORE_INPUT, "ProcessOutput without input returned %08lx\n", hr);

        MFCreateSample(&InS);
        MFCreateMemoryBuffer(sizeof(Silence), &InB);
        IMFMediaBuffer_Lock(InB, &p, NULL, NULL);
        memcpy(p, Silence, sizeof(Silence));
        IMFMediaBuffer_Unlock(InB);
        IMFMediaBuffer_SetCurrentLength(InB, sizeof(Silence));
        IMFSample_AddBuffer(InS, InB);
        IMFSample_SetSampleTime(InS, 5000000);
        IMFSample_SetSampleDuration(InS, 232199);

        hr = IMFTransform_GetInputStatus(Mft, 0, &Flags);
        ok(hr == S_OK && (Flags & MFT_INPUT_STATUS_ACCEPT_DATA), "GetInputStatus before input: %08lx %08lx\n", hr, Flags);
        hr = IMFTransform_ProcessInput(Mft, 0, InS, 0);
        ok(hr == S_OK, "ProcessInput(silence) returned %08lx\n", hr);
        hr = IMFTransform_GetOutputStatus(Mft, &Flags);
        ok(hr == S_OK && (Flags & MFT_OUTPUT_STATUS_SAMPLE_READY), "GetOutputStatus after input: %08lx %08lx\n", hr, Flags);
        hr = IMFTransform_ProcessInput(Mft, 0, InS, 0);
        ok(hr == MF_E_NOTACCEPTING, "second ProcessInput without ProcessOutput returned %08lx\n", hr);

        hr = IMFTransform_ProcessOutput(Mft, 0, 1, &Buf, &Status);
        ok(hr == S_OK, "ProcessOutput returned %08lx\n", hr);
        if (hr == S_OK)
        {
            LONGLONG T = -1;
            IMFMediaBuffer_Lock(OutB, &p, NULL, &Len);
            ok(Len == 1024 * 2, "one AAC-LC frame decoded to %lu bytes, expected %u\n", Len, 1024 * 2);
            for (i = 0; i < (int)Len; i++)
                if (p[i])
                    AllZero = FALSE;
            ok(AllZero, "a silent frame decoded to non-zero samples\n");
            IMFMediaBuffer_Unlock(OutB);
            hr = IMFSample_GetSampleTime(OutS, &T);
            ok(hr == S_OK && T == 5000000, "output sample time %I64d (%08lx)\n", T, hr);
        }
        hr = IMFTransform_ProcessOutput(Mft, 0, 1, &Buf, &Status);
        ok(hr == MF_E_TRANSFORM_NEED_MORE_INPUT, "second ProcessOutput returned %08lx\n", hr);

        /* flush and drain are accepted */
        hr = IMFTransform_ProcessMessage(Mft, MFT_MESSAGE_COMMAND_FLUSH, 0);
        ok(hr == S_OK, "MFT_MESSAGE_COMMAND_FLUSH returned %08lx\n", hr);
        hr = IMFTransform_ProcessMessage(Mft, MFT_MESSAGE_COMMAND_DRAIN, 0);
        ok(hr == S_OK, "MFT_MESSAGE_COMMAND_DRAIN returned %08lx\n", hr);
        hr = IMFTransform_ProcessMessage(Mft, MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        ok(hr == S_OK, "MFT_MESSAGE_NOTIFY_START_OF_STREAM returned %08lx\n", hr);

        IMFMediaBuffer_Release(OutB);
        IMFSample_Release(OutS);
        IMFMediaBuffer_Release(InB);
        IMFSample_Release(InS);
    }
    IMFMediaType_Release(OutType);
done:
    IMFTransform_Release(Mft);
}

START_TEST(MftAac)
{
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK || hr == S_FALSE, "CoInitializeEx returned %08lx\n", hr);
    hr = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    ok(hr == S_OK, "MFStartup returned %08lx\n", hr);
    if (FAILED(hr))
        return;

    TestRegistration();

    if (Enum(&MFAudioFormat_AAC, MFT_ENUM_FLAG_SYNCMFT, &CLSID_AacDecoder))
        TestDecoder();
    else
        skip("CLSID_CMSAACDecMFT is not registered (the AAC audio decoder feature is off)\n");

    MFShutdown();
    CoUninitialize();
}
