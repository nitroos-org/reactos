/*
 * PROJECT:     NitroOS
 * LICENSE:     LGPL-2.1-or-later (links FFmpeg's libavcodec "aac" decoder, LGPL-2.1-or-later, AAC-LC only build)
 * PURPOSE:     AAC decoder Media Foundation transform (CLSID_CMSAACDecMFT): AAC-LC only
 *
 * A synchronous IMFTransform that decodes raw (payload type 0) or ADTS (payload type 1) AAC-LC to 16-bit PCM or
 * 32-bit float. Behaviour follows the public documentation of the Windows AAC decoder MFT
 * (https://learn.microsoft.com/windows/win32/medfound/aac-decoder), not any Microsoft binary:
 *   input   MFMediaType_Audio / MFAudioFormat_AAC, MF_MT_AAC_PAYLOAD_TYPE (0 raw, 1 ADTS),
 *           MF_MT_USER_DATA = the tail of HEAACWAVEINFO (12 bytes) followed by the AudioSpecificConfig,
 *           MF_MT_AUDIO_NUM_CHANNELS / SAMPLES_PER_SECOND / MF_MT_AAC_AUDIO_PROFILE_LEVEL_INDICATION (optional)
 *   output  MFAudioFormat_PCM (16 bit) or MFAudioFormat_Float (32 bit), interleaved, one 1024-frame sample per AAC frame
 * HE-AAC (SBR) and HE-AAC v2 (PS) are not supported: the decoder is built without them (see README.md) and the
 * input type is refused (MF_E_INVALIDMEDIATYPE) when the AudioSpecificConfig signals them.
 */
#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <initguid.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <wmcodecdsp.h>
#include <mmreg.h>

#include <libavcodec/avcodec.h>
#include <libavutil/channel_layout.h>
#include <libavutil/error.h>
#include <libavutil/log.h>

#define NITRO_MFT_NAME L"AAC Decoder MFT (NitroOS AAC-LC)"
#define MAX_CH 8
#define FRAME_LEN 1024

static HINSTANCE g_inst;
static LONG g_objects, g_locks;
static CRITICAL_SECTION g_open_cs;
static FILE *g_log;

static void dbg(const char *fmt, ...)
{
    va_list ap;
    if (!g_log) return;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

static void av_cb(void *ptr, int level, const char *fmt, va_list vl)
{
    if (!g_log || level > AV_LOG_WARNING) return;
    fputs("avcodec: ", g_log);
    vfprintf(g_log, fmt, vl);
    fflush(g_log);
}

/* ---- decoder object -------------------------------------------------------------------------------------------- */

struct decoder
{
    IMFTransform IMFTransform_iface;
    LONG refcount;
    CRITICAL_SECTION cs;

    IMFMediaType *input_type;
    IMFMediaType *output_type;
    UINT32 payload_type;            /* 0 raw, 1 ADTS */
    UINT32 channels, rate;          /* of the input type / the stream */
    DWORD channel_mask;
    BOOL out_float;                 /* output type: float (else PCM16) */

    AVCodecContext *avctx;
    AVPacket *pkt;
    AVFrame *frame;

    /* one decoded frame waiting for ProcessOutput, interleaved float */
    BOOL pending;
    float pcm[FRAME_LEN * MAX_CH];
    UINT32 pending_frames, pending_channels, pending_rate;
    LONGLONG pending_time, pending_dur;
    BOOL pending_time_valid, pending_discont;
    BOOL format_changed;            /* the pending frame has a format other than the output type */
    BOOL draining;
};

static inline struct decoder *impl_from_IMFTransform(IMFTransform *iface)
{
    return CONTAINING_RECORD(iface, struct decoder, IMFTransform_iface);
}

static void decoder_close_codec(struct decoder *d)
{
    if (d->frame) av_frame_free(&d->frame);
    if (d->pkt) av_packet_free(&d->pkt);
    if (d->avctx) avcodec_free_context(&d->avctx);
    d->pending = FALSE;
}

/* ---- media type helpers ---------------------------------------------------------------------------------------- */

static const int rate_table[13] = { 96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350 };

static int rate_index(UINT32 rate)
{
    int i;
    for (i = 0; i < 13; i++) if ((UINT32)rate_table[i] == rate) return i;
    return -1;
}

struct aac_config
{
    UINT32 payload_type, channels, rate;
    BYTE asc[64];
    UINT32 asc_len;
};

/* Reads the attributes of a candidate input type. Returns S_OK or MF_E_INVALIDMEDIATYPE. */
static HRESULT parse_input_type(IMFMediaType *type, struct aac_config *cfg)
{
    GUID major, sub;
    UINT32 n, blob_len = 0;
    BYTE blob[128];
    UINT32 hdr = 0;

    memset(cfg, 0, sizeof(*cfg));
    if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_MAJOR_TYPE, &major)) || !IsEqualGUID(&major, &MFMediaType_Audio))
        return MF_E_INVALIDMEDIATYPE;
    if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_SUBTYPE, &sub)) || !IsEqualGUID(&sub, &MFAudioFormat_AAC))
        return MF_E_INVALIDMEDIATYPE;

    if (SUCCEEDED(IMFMediaType_GetUINT32(type, &MF_MT_AAC_PAYLOAD_TYPE, &n)))
        cfg->payload_type = n;
    if (cfg->payload_type > 1)      /* ADIF (2) and LOAS (3) are not supported */
        return MF_E_INVALIDMEDIATYPE;

    if (SUCCEEDED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_NUM_CHANNELS, &n))) cfg->channels = n;
    if (SUCCEEDED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &n))) cfg->rate = n;

    if (SUCCEEDED(IMFMediaType_GetBlob(type, &MF_MT_USER_DATA, blob, sizeof(blob), &blob_len)) && blob_len)
    {
        /* HEAACWAVEINFO tail (wPayloadType, wAudioProfileLevelIndication, wStructType, wReserved1, dwReserved2) */
        if (blob_len >= 14)
        {
            UINT16 pt = blob[0] | (blob[1] << 8), st = blob[4] | (blob[5] << 8);
            if (pt <= 3 && st == 0) hdr = 12;
        }
        cfg->asc_len = blob_len - hdr;
        if (cfg->asc_len > sizeof(cfg->asc)) return MF_E_INVALIDMEDIATYPE;
        memcpy(cfg->asc, blob + hdr, cfg->asc_len);
    }

    if (cfg->payload_type == 0 && !cfg->asc_len)
    {
        /* no AudioSpecificConfig: build the AAC-LC one from channels and rate */
        int ri = rate_index(cfg->rate);
        if (ri < 0 || cfg->channels < 1 || cfg->channels > 7) return MF_E_INVALIDMEDIATYPE;
        {
            UINT16 v = (2 << 11) | (ri << 7) | (cfg->channels << 3);
            cfg->asc[0] = v >> 8;
            cfg->asc[1] = v & 0xff;
            cfg->asc_len = 2;
        }
    }
    if (cfg->asc_len)
    {
        /* audioObjectType (5 bits; 31 = escape) must be 2 (AAC-LC); 5 (SBR), 29 (PS) and the rest are not supported */
        int aot = cfg->asc[0] >> 3;
        if (aot != 2 || cfg->asc_len < 2)
        {
            dbg("input type refused: audioObjectType %d (only 2 = AAC-LC is supported), %u bytes of config", aot, cfg->asc_len);
            return MF_E_INVALIDMEDIATYPE;
        }
        {   /* samplingFrequencyIndex (4 bits) and channelConfiguration (4 bits) are authoritative */
            int sf = ((cfg->asc[0] & 7) << 1) | (cfg->asc[1] >> 7);
            int cc = (cfg->asc[1] >> 3) & 15;
            if (sf < 13) cfg->rate = rate_table[sf];
            if (cc >= 1 && cc <= 6) cfg->channels = cc;
            else if (cc == 7) cfg->channels = 8;
        }
    }
    return S_OK;
}

static HRESULT make_output_type(UINT32 channels, UINT32 rate, DWORD mask, BOOL flt, IMFMediaType **out)
{
    IMFMediaType *t;
    UINT32 bits = flt ? 32 : 16, align = channels * bits / 8;
    HRESULT hr;

    if (FAILED(hr = MFCreateMediaType(&t))) return hr;
    IMFMediaType_SetGUID(t, &MF_MT_MAJOR_TYPE, &MFMediaType_Audio);
    IMFMediaType_SetGUID(t, &MF_MT_SUBTYPE, flt ? &MFAudioFormat_Float : &MFAudioFormat_PCM);
    IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_NUM_CHANNELS, channels);
    IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_SAMPLES_PER_SECOND, rate);
    IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_BITS_PER_SAMPLE, bits);
    IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_BLOCK_ALIGNMENT, align);
    IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_AVG_BYTES_PER_SECOND, align * rate);
    IMFMediaType_SetUINT32(t, &MF_MT_ALL_SAMPLES_INDEPENDENT, 1);
    IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_PREFER_WAVEFORMATEX, 1);
    if (mask) IMFMediaType_SetUINT32(t, &MF_MT_AUDIO_CHANNEL_MASK, mask);
    *out = t;
    return S_OK;
}

static DWORD default_mask(UINT32 ch)
{
    switch (ch)
    {
    case 1: return SPEAKER_FRONT_CENTER;
    case 2: return SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;
    case 3: return SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER;
    case 4: return SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT;
    case 5: return SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT;
    case 6: return SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER | SPEAKER_LOW_FREQUENCY | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT;
    case 8: return SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER | SPEAKER_LOW_FREQUENCY | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT | SPEAKER_SIDE_LEFT | SPEAKER_SIDE_RIGHT;
    }
    return 0;
}

/* ---- IUnknown -------------------------------------------------------------------------------------------------- */

static HRESULT WINAPI dec_QueryInterface(IMFTransform *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IMFTransform) || IsEqualIID(riid, &IID_IUnknown))
    {
        *obj = iface;
        IMFTransform_AddRef(iface);
        return S_OK;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI dec_AddRef(IMFTransform *iface)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    return InterlockedIncrement(&d->refcount);
}

static ULONG WINAPI dec_Release(IMFTransform *iface)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    ULONG ref = InterlockedDecrement(&d->refcount);
    if (!ref)
    {
        decoder_close_codec(d);
        if (d->input_type) IMFMediaType_Release(d->input_type);
        if (d->output_type) IMFMediaType_Release(d->output_type);
        DeleteCriticalSection(&d->cs);
        free(d);
        InterlockedDecrement(&g_objects);
    }
    return ref;
}

/* ---- streams --------------------------------------------------------------------------------------------------- */

static HRESULT WINAPI dec_GetStreamLimits(IMFTransform *iface, DWORD *imin, DWORD *imax, DWORD *omin, DWORD *omax)
{
    *imin = *imax = *omin = *omax = 1;
    return S_OK;
}

static HRESULT WINAPI dec_GetStreamCount(IMFTransform *iface, DWORD *inputs, DWORD *outputs)
{
    *inputs = *outputs = 1;
    return S_OK;
}

static HRESULT WINAPI dec_GetStreamIDs(IMFTransform *iface, DWORD isize, DWORD *ids, DWORD osize, DWORD *oids)
{
    return E_NOTIMPL;       /* ids are 0 and 0 */
}

static HRESULT WINAPI dec_GetInputStreamInfo(IMFTransform *iface, DWORD id, MFT_INPUT_STREAM_INFO *info)
{
    if (id) return MF_E_INVALIDSTREAMNUMBER;
    info->hnsMaxLatency = 0;
    info->dwFlags = MFT_INPUT_STREAM_WHOLE_SAMPLES | MFT_INPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER;
    info->cbSize = 0;
    info->cbMaxLookahead = 0;
    info->cbAlignment = 1;
    return S_OK;
}

static HRESULT WINAPI dec_GetOutputStreamInfo(IMFTransform *iface, DWORD id, MFT_OUTPUT_STREAM_INFO *info)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    UINT32 ch, bytes;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    EnterCriticalSection(&d->cs);
    ch = d->channels ? d->channels : 2;
    bytes = d->output_type ? (d->out_float ? 4 : 2) : 4;
    LeaveCriticalSection(&d->cs);
    info->dwFlags = MFT_OUTPUT_STREAM_WHOLE_SAMPLES | MFT_OUTPUT_STREAM_SINGLE_SAMPLE_PER_BUFFER | MFT_OUTPUT_STREAM_FIXED_SAMPLE_SIZE;
    info->cbSize = FRAME_LEN * ch * bytes;
    info->cbAlignment = 1;
    return S_OK;
}

static HRESULT WINAPI dec_GetAttributes(IMFTransform *iface, IMFAttributes **attributes)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI dec_GetInputStreamAttributes(IMFTransform *iface, DWORD id, IMFAttributes **attributes)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI dec_GetOutputStreamAttributes(IMFTransform *iface, DWORD id, IMFAttributes **attributes)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI dec_DeleteInputStream(IMFTransform *iface, DWORD id)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI dec_AddInputStreams(IMFTransform *iface, DWORD streams, DWORD *ids)
{
    return E_NOTIMPL;
}

/* ---- media types ----------------------------------------------------------------------------------------------- */

static HRESULT WINAPI dec_GetInputAvailableType(IMFTransform *iface, DWORD id, DWORD index, IMFMediaType **type)
{
    IMFMediaType *t;
    HRESULT hr;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    if (index) return MF_E_NO_MORE_TYPES;
    if (FAILED(hr = MFCreateMediaType(&t))) return hr;
    IMFMediaType_SetGUID(t, &MF_MT_MAJOR_TYPE, &MFMediaType_Audio);
    IMFMediaType_SetGUID(t, &MF_MT_SUBTYPE, &MFAudioFormat_AAC);
    *type = t;
    return S_OK;
}

static HRESULT WINAPI dec_GetOutputAvailableType(IMFTransform *iface, DWORD id, DWORD index, IMFMediaType **type)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    HRESULT hr;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    EnterCriticalSection(&d->cs);
    if (!d->input_type) hr = MF_E_TRANSFORM_TYPE_NOT_SET;
    else if (index > 1) hr = MF_E_NO_MORE_TYPES;
    else hr = make_output_type(d->channels, d->rate, d->channel_mask, index == 1, type);   /* PCM16 first, then float */
    LeaveCriticalSection(&d->cs);
    return hr;
}

static HRESULT open_codec(struct decoder *d, const struct aac_config *cfg)
{
    const AVCodec *codec;
    int ret;

    decoder_close_codec(d);
    if (!(codec = avcodec_find_decoder(AV_CODEC_ID_AAC))) return MF_E_INVALIDMEDIATYPE;
    if (!(d->avctx = avcodec_alloc_context3(codec))) return E_OUTOFMEMORY;
    if (cfg->asc_len)
    {
        d->avctx->extradata = av_mallocz(cfg->asc_len + AV_INPUT_BUFFER_PADDING_SIZE);
        if (!d->avctx->extradata) { decoder_close_codec(d); return E_OUTOFMEMORY; }
        memcpy(d->avctx->extradata, cfg->asc, cfg->asc_len);
        d->avctx->extradata_size = cfg->asc_len;
    }
    d->avctx->request_sample_fmt = AV_SAMPLE_FMT_FLTP;
    d->avctx->thread_count = 1;
    EnterCriticalSection(&g_open_cs);       /* libavcodec is built without threads: its one-time table init is not thread-safe */
    ret = avcodec_open2(d->avctx, codec, NULL);
    LeaveCriticalSection(&g_open_cs);
    if (ret < 0)
    {
        dbg("avcodec_open2 failed: %d", ret);
        decoder_close_codec(d);
        return MF_E_INVALIDMEDIATYPE;
    }
    if (!(d->pkt = av_packet_alloc()) || !(d->frame = av_frame_alloc()))
    {
        decoder_close_codec(d);
        return E_OUTOFMEMORY;
    }
    return S_OK;
}

static HRESULT WINAPI dec_SetInputType(IMFTransform *iface, DWORD id, IMFMediaType *type, DWORD flags)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    struct aac_config cfg;
    HRESULT hr;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    EnterCriticalSection(&d->cs);
    if (!type)
    {
        decoder_close_codec(d);
        if (d->input_type) IMFMediaType_Release(d->input_type);
        if (d->output_type) IMFMediaType_Release(d->output_type);
        d->input_type = d->output_type = NULL;
        d->channels = d->rate = 0;
        hr = S_OK;
        goto done;
    }
    if (FAILED(hr = parse_input_type(type, &cfg))) goto done;
    if (flags & MFT_SET_TYPE_TEST_ONLY) { hr = S_OK; goto done; }

    if (FAILED(hr = open_codec(d, &cfg))) goto done;
    d->payload_type = cfg.payload_type;
    d->channels = d->avctx->ch_layout.nb_channels;
    d->rate = d->avctx->sample_rate;
    if (!d->channels && cfg.channels) d->channels = cfg.channels;
    if (!d->rate && cfg.rate) d->rate = cfg.rate;
    if (d->channels > MAX_CH || !d->channels || !d->rate)
    {
        dbg("input type refused: %u channels, %u Hz", d->channels, d->rate);
        decoder_close_codec(d);
        hr = MF_E_INVALIDMEDIATYPE;
        goto done;
    }
    d->channel_mask = (d->avctx->ch_layout.order == AV_CHANNEL_ORDER_NATIVE) ? (DWORD)d->avctx->ch_layout.u.mask : default_mask(d->channels);
    if (!d->channel_mask) d->channel_mask = default_mask(d->channels);
    if (d->input_type) IMFMediaType_Release(d->input_type);
    d->input_type = type;
    IMFMediaType_AddRef(type);
    /* a new input type invalidates the output type */
    if (d->output_type) { IMFMediaType_Release(d->output_type); d->output_type = NULL; }
    d->pending = FALSE;
    d->draining = FALSE;
    dbg("input type set: %u ch %u Hz payload %u asc %u bytes", d->channels, d->rate, d->payload_type, cfg.asc_len);
    hr = S_OK;
done:
    LeaveCriticalSection(&d->cs);
    return hr;
}

static HRESULT WINAPI dec_SetOutputType(IMFTransform *iface, DWORD id, IMFMediaType *type, DWORD flags)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    GUID major, sub;
    UINT32 ch = 0, rate = 0, bits = 0;
    BOOL flt;
    HRESULT hr = MF_E_INVALIDMEDIATYPE;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    EnterCriticalSection(&d->cs);
    if (!d->input_type) { hr = MF_E_TRANSFORM_TYPE_NOT_SET; goto done; }
    if (!type)
    {
        if (d->output_type) IMFMediaType_Release(d->output_type);
        d->output_type = NULL;
        hr = S_OK;
        goto done;
    }
    if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_MAJOR_TYPE, &major)) || !IsEqualGUID(&major, &MFMediaType_Audio)) goto done;
    if (FAILED(IMFMediaType_GetGUID(type, &MF_MT_SUBTYPE, &sub))) goto done;
    if (IsEqualGUID(&sub, &MFAudioFormat_Float)) flt = TRUE;
    else if (IsEqualGUID(&sub, &MFAudioFormat_PCM)) flt = FALSE;
    else goto done;
    IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_BITS_PER_SAMPLE, &bits);
    if (bits != (flt ? 32u : 16u)) goto done;
    if (SUCCEEDED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_NUM_CHANNELS, &ch)) && ch != d->channels) goto done;
    if (SUCCEEDED(IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &rate)) && rate != d->rate) goto done;
    if (flags & MFT_SET_TYPE_TEST_ONLY) { hr = S_OK; goto done; }
    if (d->output_type) IMFMediaType_Release(d->output_type);
    d->output_type = type;
    IMFMediaType_AddRef(type);
    d->out_float = flt;
    hr = S_OK;
done:
    LeaveCriticalSection(&d->cs);
    return hr;
}

static HRESULT WINAPI dec_GetInputCurrentType(IMFTransform *iface, DWORD id, IMFMediaType **type)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    HRESULT hr = S_OK;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    EnterCriticalSection(&d->cs);
    if (!d->input_type) hr = MF_E_TRANSFORM_TYPE_NOT_SET;
    else { *type = d->input_type; IMFMediaType_AddRef(*type); }
    LeaveCriticalSection(&d->cs);
    return hr;
}

static HRESULT WINAPI dec_GetOutputCurrentType(IMFTransform *iface, DWORD id, IMFMediaType **type)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    HRESULT hr = S_OK;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    EnterCriticalSection(&d->cs);
    if (!d->output_type) hr = MF_E_TRANSFORM_TYPE_NOT_SET;
    else { *type = d->output_type; IMFMediaType_AddRef(*type); }
    LeaveCriticalSection(&d->cs);
    return hr;
}

static HRESULT WINAPI dec_GetInputStatus(IMFTransform *iface, DWORD id, DWORD *flags)
{
    struct decoder *d = impl_from_IMFTransform(iface);

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    EnterCriticalSection(&d->cs);
    *flags = (d->input_type && d->output_type && !d->pending) ? MFT_INPUT_STATUS_ACCEPT_DATA : 0;
    LeaveCriticalSection(&d->cs);
    return S_OK;
}

static HRESULT WINAPI dec_GetOutputStatus(IMFTransform *iface, DWORD *flags)
{
    struct decoder *d = impl_from_IMFTransform(iface);

    EnterCriticalSection(&d->cs);
    *flags = d->pending ? MFT_OUTPUT_STATUS_SAMPLE_READY : 0;
    LeaveCriticalSection(&d->cs);
    return S_OK;
}

static HRESULT WINAPI dec_SetOutputBounds(IMFTransform *iface, LONGLONG lower, LONGLONG upper)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI dec_ProcessEvent(IMFTransform *iface, DWORD id, IMFMediaEvent *event)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI dec_ProcessMessage(IMFTransform *iface, MFT_MESSAGE_TYPE message, ULONG_PTR param)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    HRESULT hr = S_OK;

    EnterCriticalSection(&d->cs);
    switch (message)
    {
    case MFT_MESSAGE_COMMAND_FLUSH:
        if (d->avctx) avcodec_flush_buffers(d->avctx);
        d->pending = FALSE;
        d->draining = FALSE;
        break;
    case MFT_MESSAGE_COMMAND_DRAIN:
        d->draining = TRUE;     /* nothing is buffered inside: the pending sample (if any) is the last output */
        break;
    case MFT_MESSAGE_SET_D3D_MANAGER:
        hr = E_NOTIMPL;
        break;
    case MFT_MESSAGE_NOTIFY_BEGIN_STREAMING:
    case MFT_MESSAGE_NOTIFY_END_STREAMING:
    case MFT_MESSAGE_NOTIFY_END_OF_STREAM:
    case MFT_MESSAGE_NOTIFY_START_OF_STREAM:
    case MFT_MESSAGE_COMMAND_MARKER:
        break;
    default:
        hr = E_NOTIMPL;
        break;
    }
    LeaveCriticalSection(&d->cs);
    return hr;
}

/* ---- data path ------------------------------------------------------------------------------------------------- */

static HRESULT WINAPI dec_ProcessInput(IMFTransform *iface, DWORD id, IMFSample *sample, DWORD flags)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    IMFMediaBuffer *buf = NULL;
    BYTE *data = NULL;
    DWORD len = 0, maxlen;
    LONGLONG t = 0, dur = 0;
    UINT32 disc = 0;
    HRESULT hr;
    int ret;

    if (id) return MF_E_INVALIDSTREAMNUMBER;
    if (!sample) return E_POINTER;
    EnterCriticalSection(&d->cs);
    if (!d->input_type || !d->output_type) { hr = MF_E_TRANSFORM_TYPE_NOT_SET; goto done; }
    if (d->pending) { hr = MF_E_NOTACCEPTING; goto done; }

    if (FAILED(hr = IMFSample_ConvertToContiguousBuffer(sample, &buf))) goto done;
    if (FAILED(hr = IMFMediaBuffer_Lock(buf, &data, &maxlen, &len))) goto done;
    if (!len) { IMFMediaBuffer_Unlock(buf); hr = S_OK; goto done; }

    if (d->payload_type == 1)
    {
        /* ADTS: syncword 0xFFF, profile (audio object type - 1) must be 1 = AAC-LC */
        if (len < 7 || data[0] != 0xff || (data[1] & 0xf0) != 0xf0 || ((data[2] >> 6) & 3) != 1)
        {
            IMFMediaBuffer_Unlock(buf);
            hr = MF_E_INVALID_STREAM_DATA;
            goto done;
        }
    }

    av_packet_unref(d->pkt);
    if (av_new_packet(d->pkt, len) < 0) { IMFMediaBuffer_Unlock(buf); hr = E_OUTOFMEMORY; goto done; }
    memcpy(d->pkt->data, data, len);
    IMFMediaBuffer_Unlock(buf);

    d->pending_time_valid = SUCCEEDED(IMFSample_GetSampleTime(sample, &t));
    if (FAILED(IMFSample_GetSampleDuration(sample, &dur))) dur = 0;
    d->pending_time = t;
    d->pending_discont = SUCCEEDED(IMFSample_GetUINT32(sample, &MFSampleExtension_Discontinuity, &disc)) && disc;

    ret = avcodec_send_packet(d->avctx, d->pkt);
    if (ret < 0)
    {
        dbg("avcodec_send_packet: %d", ret);
        hr = MF_E_INVALID_STREAM_DATA;
        goto done;
    }
    ret = avcodec_receive_frame(d->avctx, d->frame);
    if (ret == AVERROR(EAGAIN)) { hr = S_OK; goto done; }
    if (ret < 0)
    {
        dbg("avcodec_receive_frame: %d", ret);
        hr = MF_E_INVALID_STREAM_DATA;
        goto done;
    }
    {
        UINT32 ch = d->frame->ch_layout.nb_channels, n = d->frame->nb_samples, i, c;
        UINT32 rate = d->frame->sample_rate;
        if (!ch || ch > MAX_CH || n > FRAME_LEN || d->frame->format != AV_SAMPLE_FMT_FLTP)
        {
            av_frame_unref(d->frame);
            hr = MF_E_INVALID_STREAM_DATA;
            goto done;
        }
        for (c = 0; c < ch; c++)
        {
            const float *src = (const float *)d->frame->extended_data[c];
            for (i = 0; i < n; i++) d->pcm[i * ch + c] = src[i];
        }
        d->pending_frames = n;
        d->pending_channels = ch;
        d->pending_rate = rate;
        d->format_changed = (ch != d->channels || rate != d->rate);
        d->pending_dur = dur ? dur : (LONGLONG)10000000 * n / (rate ? rate : d->rate);
        d->pending = TRUE;
        av_frame_unref(d->frame);
    }
    hr = S_OK;
done:
    if (buf) IMFMediaBuffer_Release(buf);
    LeaveCriticalSection(&d->cs);
    return hr;
}

static HRESULT WINAPI dec_ProcessOutput(IMFTransform *iface, DWORD flags, DWORD count, MFT_OUTPUT_DATA_BUFFER *out, DWORD *status)
{
    struct decoder *d = impl_from_IMFTransform(iface);
    IMFMediaBuffer *buf = NULL;
    BYTE *data = NULL;
    DWORD maxlen, curlen, need;
    UINT32 n, ch, i;
    HRESULT hr;

    if (count != 1 || !out) return E_INVALIDARG;
    if (out->dwStreamID) return MF_E_INVALIDSTREAMNUMBER;
    *status = 0;
    out->dwStatus = 0;
    out->pEvents = NULL;
    EnterCriticalSection(&d->cs);
    if (!d->input_type || !d->output_type) { hr = MF_E_TRANSFORM_TYPE_NOT_SET; goto done; }
    if (!d->pending) { hr = MF_E_TRANSFORM_NEED_MORE_INPUT; goto done; }
    if (!out->pSample) { hr = E_INVALIDARG; goto done; }

    if (d->format_changed)
    {
        /* the stream does not have the format the types said: publish the real one and ask the client to renegotiate */
        IMFMediaType *t;
        d->channels = d->pending_channels;
        d->rate = d->pending_rate;
        d->channel_mask = default_mask(d->channels);
        if (SUCCEEDED(make_output_type(d->channels, d->rate, d->channel_mask, d->out_float, &t)))
        {
            if (d->output_type) IMFMediaType_Release(d->output_type);
            d->output_type = t;
        }
        d->format_changed = FALSE;
        out->dwStatus = MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE;
        hr = MF_E_TRANSFORM_STREAM_CHANGE;
        goto done;
    }

    n = d->pending_frames;
    ch = d->pending_channels;
    need = n * ch * (d->out_float ? 4 : 2);
    if (FAILED(hr = IMFSample_ConvertToContiguousBuffer(out->pSample, &buf))) goto done;
    if (FAILED(hr = IMFMediaBuffer_Lock(buf, &data, &maxlen, &curlen))) goto done;
    if (maxlen < need)
    {
        IMFMediaBuffer_Unlock(buf);
        hr = MF_E_BUFFERTOOSMALL;
        goto done;
    }
    if (d->out_float)
        memcpy(data, d->pcm, need);
    else
    {
        INT16 *o = (INT16 *)data;
        for (i = 0; i < n * ch; i++)
        {
            float v = d->pcm[i] * 32768.0f;
            o[i] = v >= 32767.0f ? 32767 : v <= -32768.0f ? -32768 : (INT16)lrintf(v);
        }
    }
    IMFMediaBuffer_Unlock(buf);
    IMFMediaBuffer_SetCurrentLength(buf, need);
    if (d->pending_time_valid) IMFSample_SetSampleTime(out->pSample, d->pending_time);
    IMFSample_SetSampleDuration(out->pSample, d->pending_dur);
    if (d->pending_discont) IMFSample_SetUINT32(out->pSample, &MFSampleExtension_Discontinuity, 1);
    d->pending = FALSE;
    hr = S_OK;
done:
    if (buf) IMFMediaBuffer_Release(buf);
    LeaveCriticalSection(&d->cs);
    return hr;
}

static const IMFTransformVtbl decoder_vtbl =
{
    dec_QueryInterface, dec_AddRef, dec_Release,
    dec_GetStreamLimits, dec_GetStreamCount, dec_GetStreamIDs, dec_GetInputStreamInfo, dec_GetOutputStreamInfo,
    dec_GetAttributes, dec_GetInputStreamAttributes, dec_GetOutputStreamAttributes, dec_DeleteInputStream,
    dec_AddInputStreams, dec_GetInputAvailableType, dec_GetOutputAvailableType, dec_SetInputType, dec_SetOutputType,
    dec_GetInputCurrentType, dec_GetOutputCurrentType, dec_GetInputStatus, dec_GetOutputStatus, dec_SetOutputBounds,
    dec_ProcessEvent, dec_ProcessMessage, dec_ProcessInput, dec_ProcessOutput,
};

/* ---- class factory --------------------------------------------------------------------------------------------- */

static HRESULT decoder_create(REFIID riid, void **obj)
{
    struct decoder *d;
    HRESULT hr;

    if (!(d = calloc(1, sizeof(*d)))) return E_OUTOFMEMORY;
    d->IMFTransform_iface.lpVtbl = (IMFTransformVtbl *)&decoder_vtbl;
    d->refcount = 1;
    InitializeCriticalSection(&d->cs);
    InterlockedIncrement(&g_objects);
    hr = IMFTransform_QueryInterface(&d->IMFTransform_iface, riid, obj);
    IMFTransform_Release(&d->IMFTransform_iface);
    return hr;
}

struct factory { IClassFactory IClassFactory_iface; };

static HRESULT WINAPI factory_QueryInterface(IClassFactory *iface, REFIID riid, void **obj)
{
    if (IsEqualIID(riid, &IID_IClassFactory) || IsEqualIID(riid, &IID_IUnknown)) { *obj = iface; return S_OK; }
    *obj = NULL;
    return E_NOINTERFACE;
}
static ULONG WINAPI factory_AddRef(IClassFactory *iface) { return 2; }
static ULONG WINAPI factory_Release(IClassFactory *iface) { return 1; }
static HRESULT WINAPI factory_CreateInstance(IClassFactory *iface, IUnknown *outer, REFIID riid, void **obj)
{
    *obj = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    return decoder_create(riid, obj);
}
static HRESULT WINAPI factory_LockServer(IClassFactory *iface, BOOL lock)
{
    if (lock) InterlockedIncrement(&g_locks); else InterlockedDecrement(&g_locks);
    return S_OK;
}
static const IClassFactoryVtbl factory_vtbl = { factory_QueryInterface, factory_AddRef, factory_Release, factory_CreateInstance, factory_LockServer };
static struct factory g_factory = { { (IClassFactoryVtbl *)&factory_vtbl } };

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void **obj)
{
    if (!IsEqualCLSID(clsid, &CLSID_CMSAACDecMFT)) { *obj = NULL; return CLASS_E_CLASSNOTAVAILABLE; }
    return IClassFactory_QueryInterface(&g_factory.IClassFactory_iface, riid, obj);
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return (g_objects || g_locks) ? S_FALSE : S_OK;
}

/* ---- registration (regsvr32; featmgr writes the same keys from catalog/aac-lc.ini) ----------------------------- */

static void guid_str(const GUID *g, WCHAR *s)
{
    swprintf(s, 39, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", g->Data1, g->Data2, g->Data3, g->Data4[0],
             g->Data4[1], g->Data4[2], g->Data4[3], g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
}

HRESULT WINAPI DllRegisterServer(void)
{
    WCHAR path[MAX_PATH], clsid[40], key[MAX_PATH + 64];
    MFT_REGISTER_TYPE_INFO in[1] = { { MFMediaType_Audio, MFAudioFormat_AAC } };
    MFT_REGISTER_TYPE_INFO out[2] = { { MFMediaType_Audio, MFAudioFormat_PCM }, { MFMediaType_Audio, MFAudioFormat_Float } };
    HKEY k;
    DWORD cb;
    HRESULT hr;

    GetModuleFileNameW(g_inst, path, MAX_PATH);
    guid_str(&CLSID_CMSAACDecMFT, clsid);
    swprintf(key, ARRAYSIZE(key), L"SOFTWARE\\Classes\\CLSID\\%ls", clsid);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL)) return E_FAIL;
    RegSetValueExW(k, NULL, 0, REG_SZ, (BYTE *)NITRO_MFT_NAME, sizeof(NITRO_MFT_NAME));
    RegCloseKey(k);
    wcscat(key, L"\\InprocServer32");
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL)) return E_FAIL;
    cb = (lstrlenW(path) + 1) * sizeof(WCHAR);
    RegSetValueExW(k, NULL, 0, REG_SZ, (BYTE *)path, cb);
    RegSetValueExW(k, L"ThreadingModel", 0, REG_SZ, (BYTE *)L"Both", 5 * sizeof(WCHAR));
    RegCloseKey(k);
    if (FAILED(hr = MFStartup(MF_VERSION, MFSTARTUP_LITE))) return hr;
    hr = MFTRegister(CLSID_CMSAACDecMFT, MFT_CATEGORY_AUDIO_DECODER, (LPWSTR)NITRO_MFT_NAME, MFT_ENUM_FLAG_SYNCMFT,
                     1, in, 2, out, NULL);
    MFShutdown();
    return hr;
}

HRESULT WINAPI DllUnregisterServer(void)
{
    WCHAR clsid[40], key[MAX_PATH + 64];

    MFStartup(MF_VERSION, MFSTARTUP_LITE);
    MFTUnregister(CLSID_CMSAACDecMFT);
    MFShutdown();
    guid_str(&CLSID_CMSAACDecMFT, clsid);
    swprintf(key, ARRAYSIZE(key), L"SOFTWARE\\Classes\\CLSID\\%ls\\InprocServer32", clsid);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key);
    swprintf(key, ARRAYSIZE(key), L"SOFTWARE\\Classes\\CLSID\\%ls", clsid);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, key);
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, void *reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        char path[MAX_PATH];
        g_inst = inst;
        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_open_cs);
        if (GetEnvironmentVariableA("NITRO_AACDEC_LOG", path, sizeof(path))) g_log = fopen(path, "a");
        av_log_set_callback(av_cb);
        break;
    }
    case DLL_PROCESS_DETACH:
        if (g_log) fclose(g_log);
        break;
    }
    return TRUE;
}
