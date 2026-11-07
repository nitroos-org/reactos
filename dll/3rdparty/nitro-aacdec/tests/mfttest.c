/*
 * mfttest: feeds an ADTS AAC file through an AAC decoder MFT and writes the decoded audio, for the checks of the
 * "AAC audio decoder (AAC-LC)" feature (compare with FFmpeg's own decode of the same file, refuse HE-AAC / non-LC).
 *   mfttest <dll|-> <in.aac> <out.raw> <adts|raw> [pcm16|float] [mainflip]
 *     dll       load this DLL and call its DllGetClassObject (no registration needed); "-" = CoCreateInstance(CLSID)
 *     adts      MF_MT_AAC_PAYLOAD_TYPE 1: the frames go in with their ADTS headers
 *     raw       payload type 0: headers stripped, MF_MT_USER_DATA = 12 byte HEAACWAVEINFO tail + AudioSpecificConfig (as Firefox)
 *     mainflip  rewrite the ADTS profile of every frame to 0 (AAC Main) first: the MFT must refuse it
 * Prints one line: RESULT in=<frames> out=<frames> bytes=<n> firsterr=<hr> setinput=<hr>.  Mingw build, see build-tests.sh.
 * LICENSE: LGPL-2.1-or-later
 */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <initguid.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>

DEFINE_GUID(CLSID_AacMft, 0x32d186a7, 0x218f, 0x4c75, 0x88, 0x76, 0xdd, 0x77, 0x27, 0x3a, 0x89, 0x99);
typedef HRESULT (WINAPI *PGCO)(REFCLSID, REFIID, void **);

int main(int argc, char **argv)
{
    FILE *f, *o;
    unsigned char *buf;
    long size, pos = 0;
    int raw, flt, flip, in = 0, out = 0;
    HRESULT hr, first = S_OK, seti = S_OK;
    IMFTransform *mft = NULL;
    IMFMediaType *t, *ot;
    DWORD bytes = 0;
    UINT32 ch = 0, rate = 0;
    static const int rates[13] = { 96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350 };

    if (argc < 5) { fprintf(stderr, "usage: mfttest dll|- in.aac out.raw adts|raw [pcm16|float] [mainflip]\n"); return 2; }
    raw = !strcmp(argv[4], "raw");
    flt = argc > 5 && !strcmp(argv[5], "float");
    flip = argc > 6 && !strcmp(argv[6], "mainflip");
    f = fopen(argv[2], "rb");
    if (!f) { perror("in"); return 2; }
    fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, 0, SEEK_SET);
    buf = malloc(size); fread(buf, 1, size, f); fclose(f);
    if (size < 7 || buf[0] != 0xff || (buf[1] & 0xf0) != 0xf0) { fprintf(stderr, "not ADTS\n"); return 2; }
    {
        int sf = (buf[2] >> 2) & 15, cc = ((buf[2] & 1) << 2) | (buf[3] >> 6);
        rate = rates[sf]; ch = cc;
    }

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (strcmp(argv[1], "-"))
    {
        HMODULE m = LoadLibraryA(argv[1]);
        PGCO g;
        IClassFactory *cf = NULL;
        if (!m) { printf("RESULT loadfail=%lu\n", GetLastError()); return 1; }
        g = (PGCO)GetProcAddress(m, "DllGetClassObject");
        hr = g ? g(&CLSID_AacMft, &IID_IClassFactory, (void **)&cf) : E_FAIL;
        if (SUCCEEDED(hr)) hr = IClassFactory_CreateInstance(cf, NULL, &IID_IMFTransform, (void **)&mft);
    }
    else
        hr = CoCreateInstance(&CLSID_AacMft, NULL, CLSCTX_INPROC_SERVER, &IID_IMFTransform, (void **)&mft);
    if (FAILED(hr)) { printf("RESULT createfail=0x%08lx\n", hr); return 1; }

    MFCreateMediaType(&t);
    IMFMediaType_SetGUID(t, &MF_MT_MAJOR_TYPE, &MFMediaType_Audio);
    IMFMediaType_SetGUID(t, &MF_MT_SUBTYPE, &MFAudioFormat_AAC);
    IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_PREFER_WAVEFORMATEX, 1);
    IMFMediaType_SetUINT32(t, &MF_MT_AAC_PAYLOAD_TYPE, raw ? 0 : 1);
    if (raw)
    {
        BYTE ud[14] = { 0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        unsigned prof = ((buf[2] >> 6) & 3) + 1, sf = (buf[2] >> 2) & 15, cc = ((buf[2] & 1) << 2) | (buf[3] >> 6);
        unsigned v = (prof << 11) | (sf << 7) | (cc << 3);
        ud[12] = v >> 8; ud[13] = v & 0xff;
        IMFMediaType_SetBlob(t, &MF_MT_USER_DATA, ud, sizeof(ud));
    }
    else
    {
        IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_NUM_CHANNELS, ch);
        IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_SAMPLES_PER_SECOND, rate);
    }
    seti = IMFTransform_SetInputType(mft, 0, t, 0);
    if (SUCCEEDED(seti))
    {
        hr = IMFTransform_GetOutputAvailableType(mft, 0, flt ? 1 : 0, &ot);
        if (SUCCEEDED(hr)) { hr = IMFTransform_SetOutputType(mft, 0, ot, 0); IMFMediaType_Release(ot); }
        if (FAILED(hr)) seti = hr;
    }
    if (FAILED(seti)) { printf("RESULT in=0 out=0 bytes=0 firsterr=0x00000000 setinput=0x%08lx\n", seti); return 0; }
    IMFTransform_ProcessMessage(mft, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    IMFTransform_ProcessMessage(mft, MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);

    o = fopen(argv[3], "wb");
    while (pos + 7 <= size)
    {
        int hdr = (buf[pos + 1] & 1) ? 7 : 9;
        long len = ((buf[pos + 3] & 3) << 11) | (buf[pos + 4] << 3) | (buf[pos + 5] >> 5);
        IMFSample *s; IMFMediaBuffer *b; BYTE *p; MFT_OUTPUT_STREAM_INFO si; MFT_OUTPUT_DATA_BUFFER ob = { 0 }; DWORD st;
        if (len < hdr || pos + len > size) break;
        if (flip) buf[pos + 2] &= 0x3f;
        MFCreateSample(&s);
        MFCreateMemoryBuffer(len, &b);
        IMFMediaBuffer_Lock(b, &p, NULL, NULL);
        memcpy(p, buf + pos + (raw ? hdr : 0), len - (raw ? hdr : 0));
        IMFMediaBuffer_Unlock(b);
        IMFMediaBuffer_SetCurrentLength(b, len - (raw ? hdr : 0));
        IMFSample_AddBuffer(s, b);
        IMFSample_SetSampleTime(s, (LONGLONG)in * 10000000LL * 1024 / (rate ? rate : 44100));
        hr = IMFTransform_ProcessInput(mft, 0, s, 0);
        in++;
        IMFSample_Release(s); IMFMediaBuffer_Release(b);
        if (FAILED(hr)) { if (SUCCEEDED(first)) first = hr; break; }
        for (;;)
        {
            IMFSample *os; IMFMediaBuffer *obf; BYTE *q; DWORD cur;
            IMFTransform_GetOutputStreamInfo(mft, 0, &si);
            MFCreateSample(&os); MFCreateMemoryBuffer(si.cbSize, &obf); IMFSample_AddBuffer(os, obf);
            ob.pSample = os; ob.dwStatus = 0;
            hr = IMFTransform_ProcessOutput(mft, 0, 1, &ob, &st);
            if (hr == S_OK)
            {
                IMFMediaBuffer_Lock(obf, &q, NULL, &cur);
                fwrite(q, 1, cur, o); bytes += cur; out++;
                IMFMediaBuffer_Unlock(obf);
            }
            IMFMediaBuffer_Release(obf); IMFSample_Release(os);
            if (hr == MF_E_TRANSFORM_STREAM_CHANGE)
            {
                IMFMediaType *nt;
                if (SUCCEEDED(IMFTransform_GetOutputAvailableType(mft, 0, flt ? 1 : 0, &nt))) { IMFTransform_SetOutputType(mft, 0, nt, 0); IMFMediaType_Release(nt); }
                continue;
            }
            if (hr != S_OK) { if (hr != MF_E_TRANSFORM_NEED_MORE_INPUT && SUCCEEDED(first)) first = hr; break; }
        }
        if (FAILED(first)) break;
        pos += len;
    }
    fclose(o);
    printf("RESULT in=%d out=%d bytes=%lu firsterr=0x%08lx setinput=0x%08lx\n", in, out, bytes, first, seti);
    IMFTransform_Release(mft);
    MFShutdown();
    return 0;
}
