/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.UI.Composition: present the visual tree of a DesktopWindowTarget into its window
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Without a desktop compositor (window surfaces at redirection level 0) the visual tree is drawn into the window
 * itself, the way the DirectComposition device draws composition swap chains (device.c). The tree under the
 * target's Root is rendered by the CPU renderer of composition.c at the size of the window's client area
 * (composition units are client pixels, no DPI scaling) and alpha-blended over the window's client area through a
 * window DC: a non-topmost target leaves the child windows on top (DCX_CLIPCHILDREN), a topmost one draws over them.
 *
 * Nothing on the caller's side waits for the GPU or for the renderer:
 *  - A commit (ICompositorController::Commit, or the automatic commit of a Compositor that has no controller) only
 *    records a frame description of each target of the Compositor (comp_frame_collect_locked: the visual tree
 *    flattened to the sprites that draw something, copied under comp_lock) and wakes the render thread. A newer commit
 *    replaces a frame that was not rendered yet, and one that shows the same as the previous commit is dropped.
 *  - The render thread (a DLL-owned thread that starts on demand and retires when idle) reads back the surfaces that
 *    changed since their last read-back (compgfx.c: a surface keeps a CPU copy and a version, EndDraw / Resize /
 *    Scroll change the version; the GPU is waited for by polling a query, with no lock held), draws the frame, and
 *    presents it: the finished frame replaces the target's last frame and is blended into the window.
 *  - The window hooks never wait for rendering: they blend the last presented frame (or post a request, or ask the
 *    render thread to lay the tree out again after a WM_SIZE) and take only present_lock, which no thread holds while
 *    it waits for anything. comp_lock (the object model) is not taken by a hook, and a hook never destroys an object:
 *    the reference it took is handed to the render thread.
 *
 * What the window paints itself would overwrite the tree, so the last frame is kept and blended again after every
 * WM_PAINT of the window (and, for a topmost target, of its children): a thread hook on the window's thread
 * (only for windows of this process) posts a private message when it sees WM_PAINT leave the queue and blends the
 * frame when that message comes back, i.e. after the paint; a WM_PAINT sent by UpdateWindow is seen when its
 * window procedure returns. When a new frame does not cover what the previous one drew (a visual moved or became
 * transparent), the part of the window that is no longer covered is invalidated so that its own content comes back.
 * A request whose private message never comes back (window gone, message filtered) is posted again after 250 ms.
 *
 * FIXME: not done: a window of another process gets the frame at the end of the render only (no hook); resize renders
 * the live tree, not the last committed one; every frame draws the whole client area (an area over 16 Mpixels is
 * cut: no tiling); no redirection surface or DWM path (level 1+ windows are drawn the same way). Verify on the
 * oracle: whether the tree is laid out in the client area (assumed) and in physical pixels (assumed), and how soon
 * pixels show after a Commit (here: some milliseconds to seconds, never in the caller).
 */

#include <stdarg.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "winerror.h"
#include "objbase.h"
#include "inspectable.h"
#include <windows.foundation.h>
#include <windows.ui.composition.h>
#include <windows.ui.composition.interop.h>
#include "comp_private.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

#define MAX_TARGET_DIM 16384
#define MAX_FRAME_PIXELS (16 * 1024 * 1024)     /* 64 MB of frame */
#define POST_RETRY_MS 250
#define RENDER_IDLE_MS 3000

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* an immutable rendered frame; shared by the target and the blends that read it */
struct fbuf
{
    LONG refs;
    UINT w, h;
    BOOL used;                          /* a pixel that is not transparent */
    BYTE px[1];                         /* premultiplied BGRA, w * h * 4 */
};

/* present_lock guards the list of targets and the presentation fields of a target (comp_private.h). Nobody waits
 * for anything (GPU, window, another lock but hook_cs, worker_cs) while holding it. */
static CRITICAL_SECTION present_cs;
static CRITICAL_SECTION_DEBUG present_cs_debug =
{
    0, 0, &present_cs, { &present_cs_debug.ProcessLocksList, &present_cs_debug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": present_cs") }
};
static CRITICAL_SECTION present_cs = { &present_cs_debug, -1, 0, 0, 0, 0 };
static void present_lock(void) { EnterCriticalSection(&present_cs); }
static void present_unlock(void) { LeaveCriticalSection(&present_cs); }

static struct cobj *targets;            /* every attached DesktopWindowTarget, under present_lock */
static struct cobj *dropq;              /* targets whose reference a hook handed over, under present_lock */
static LONG inflight;                   /* frames queued, being rendered or resize requests: under present_lock */
static LONG pseq_counter;
static UINT present_msg;                /* private message: blend the frame again after a WM_PAINT */

struct thread_hook
{
    DWORD tid;
    HANDLE thread;                      /* keeps the thread id from being reused while an entry exists */
    HHOOK getmsg, callret;
    LONG refs;
};

static CRITICAL_SECTION hook_cs;
static CRITICAL_SECTION_DEBUG hook_cs_debug =
{
    0, 0, &hook_cs, { &hook_cs_debug.ProcessLocksList, &hook_cs_debug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": hook_cs") }
};
static CRITICAL_SECTION hook_cs = { &hook_cs_debug, -1, 0, 0, 0, 0 };
static struct thread_hook *hooks;       /* under hook_cs */
static int nhooks, caphooks;

/* ---- DLL-owned worker threads ---- */

static CRITICAL_SECTION worker_cs;
static CRITICAL_SECTION_DEBUG worker_cs_debug =
{
    0, 0, &worker_cs, { &worker_cs_debug.ProcessLocksList, &worker_cs_debug.ProcessLocksList },
    0, 0, { (DWORD_PTR)(__FILE__ ": worker_cs") }
};
static CRITICAL_SECTION worker_cs = { &worker_cs_debug, -1, 0, 0, 0, 0 };

BOOL comp_worker_kick(struct comp_worker *w)
{
    BOOL ok = TRUE;

    EnterCriticalSection(&worker_cs);
    w->kicked = TRUE;
    if (!w->running)
    {
        HMODULE self = NULL;
        HANDLE th;

        if (!w->event && !(w->event = CreateEventW(NULL, FALSE, FALSE, NULL))) ok = FALSE;
        /* the thread owns a reference on the DLL until it has left its code (FreeLibraryAndExitThread) */
        else if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)w->proc, &self)) ok = FALSE;
        else if (!(th = CreateThread(NULL, 0, w->proc, w, 0, NULL)))
        {
            FreeLibrary(self);
            ok = FALSE;
        }
        else
        {
            CloseHandle(th);
            w->running = TRUE;
        }
        if (!ok)
        {
            WARN("no worker thread: %lu\n", GetLastError());
            w->kicked = FALSE;
            if (w->event) { CloseHandle(w->event); w->event = NULL; }
        }
    }
    if (ok) SetEvent(w->event);
    LeaveCriticalSection(&worker_cs);
    return ok;
}

void comp_worker_sleep(struct comp_worker *w, DWORD ms, BOOL retire)
{
    DWORD r = WaitForSingleObject(w->event, ms);    /* w->event only changes while this thread is not running */

    EnterCriticalSection(&worker_cs);
    if (r != WAIT_OBJECT_0 && retire && !w->kicked)
    {
        HMODULE self = NULL;

        w->running = FALSE;
        CloseHandle(w->event);
        w->event = NULL;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)w->proc, &self);
        LeaveCriticalSection(&worker_cs);
        if (self) FreeLibraryAndExitThread(self, 0);
        ExitThread(0);
    }
    w->kicked = FALSE;
    LeaveCriticalSection(&worker_cs);
}

/* ---- frames ---- */

static void fbuf_release(struct fbuf *f)
{
    if (f && !InterlockedDecrement(&f->refs)) HeapFree(GetProcessHeap(), 0, f);
}

static struct fbuf *fbuf_ref(struct fbuf *f)
{
    if (f) InterlockedIncrement(&f->refs);
    return f;
}

/* a reference to a target found under present_lock, unless it is already being destroyed; caller holds present_lock */
static BOOL grab_locked(struct cobj *t)
{
    LONG r;

    for (;;)
    {
        r = t->ref;
        if (r <= 0) return FALSE;
        if (InterlockedCompareExchange(&t->ref, r + 1, r) == r) return TRUE;
    }
}

/* only where destroying the object is acceptable (not in a hook procedure) */
static void drop(struct cobj *t)
{
    IInspectable_Release(&t->identity);
}

static DWORD WINAPI render_main(void *arg);
static struct comp_worker render_worker = { render_main };

/* a hook gives its reference to the render thread: the last reference would destroy the target, and that unhooks
 * the hook that is running */
static void defer_drop(struct cobj *t)
{
    present_lock();
    if (!t->drops++)
    {
        t->dnext = dropq;
        dropq = t;
    }
    present_unlock();
    comp_worker_kick(&render_worker);   /* no thread: released by the next commit */
}

static BOOL run_drops(void)
{
    struct cobj *list, *t;
    BOOL any = FALSE;

    present_lock();
    list = dropq; dropq = NULL;
    present_unlock();
    while (list)
    {
        LONG n;

        t = list;
        present_lock();
        list = t->dnext; t->dnext = NULL;
        n = t->drops; t->drops = 0;
        present_unlock();
        while (n-- > 0) { drop(t); any = TRUE; }
    }
    return any;
}

static void frames_done(LONG n)
{
    present_lock();
    inflight -= n;
    present_unlock();
}

/* the frame size for a client area: whole area, capped (a huge window is not drawn past the cap) */
static void frame_size(const RECT *rc, UINT *w, UINT *h)
{
    UINT cw = rc->right < MAX_TARGET_DIM ? rc->right : MAX_TARGET_DIM;
    UINT ch = rc->bottom < MAX_TARGET_DIM ? rc->bottom : MAX_TARGET_DIM;

    if ((unsigned long long)cw * ch > MAX_FRAME_PIXELS) ch = MAX_FRAME_PIXELS / cw;
    *w = cw; *h = ch;
}

/* blend the target's last frame over its window; nothing when there is no frame */
static void target_blit(struct cobj *t)
{
    BITMAPINFO bmi;
    BLENDFUNCTION bf;
    HBITMAP dib = NULL, oldbmp;
    HDC hdc, mem;
    void *bits = NULL;
    HWND hwnd;
    struct fbuf *fb;
    UINT w = 0, h = 0;
    BOOL topmost, cached = FALSE;

    present_lock();
    fb = fbuf_ref(t->frame);
    hwnd = t->hwnd; topmost = t->topmost;
    if (fb && fb->used)
    {
        w = fb->w; h = fb->h;
        if (!t->cdib_busy && t->cdib && t->cdib_w == w && t->cdib_h == h)
        {
            t->cdib_busy = TRUE;
            dib = t->cdib; bits = t->cdib_bits;
            cached = TRUE;
        }
    }
    present_unlock();
    if (!fb || !fb->used || !w || !h || !IsWindow(hwnd))
    {
        if (cached) { present_lock(); t->cdib_busy = FALSE; present_unlock(); }
        fbuf_release(fb);
        return;
    }

    if (!cached)
    {
        memset(&bmi, 0, sizeof(bmi));
        bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -(LONG)h;  /* top-down, like the frame */
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        if (!(dib = CreateDIBSection(NULL, &bmi, DIB_RGB_COLORS, &bits, NULL, 0)) || !bits)
        {
            WARN("no %ux%u DIB section for window %p\n", w, h, hwnd);
            if (dib) DeleteObject(dib);
            fbuf_release(fb);
            return;
        }
    }
    memcpy(bits, fb->px, (size_t)w * h * 4);
    if ((hdc = GetDCEx(hwnd, NULL, DCX_CACHE | DCX_CLIPSIBLINGS | (topmost ? 0 : DCX_CLIPCHILDREN))))
    {
        if ((mem = CreateCompatibleDC(hdc)))
        {
            oldbmp = SelectObject(mem, dib);
            bf.BlendOp = AC_SRC_OVER;
            bf.BlendFlags = 0;
            bf.SourceConstantAlpha = 255;
            bf.AlphaFormat = AC_SRC_ALPHA;          /* the frame is premultiplied BGRA */
            if (!GdiAlphaBlend(hdc, 0, 0, w, h, mem, 0, 0, w, h, bf))
                WARN("GdiAlphaBlend into window %p failed\n", hwnd);
            SelectObject(mem, oldbmp);
            DeleteDC(mem);
        }
        ReleaseDC(hwnd, hdc);
    }
    fbuf_release(fb);
    if (cached)
    {
        present_lock(); t->cdib_busy = FALSE; present_unlock();
    }
    else
    {
        HBITMAP gone = NULL;

        /* keep this DIB for the next paint unless another blend is using the cached one */
        present_lock();
        if (!t->cdib_busy)
        {
            gone = t->cdib;
            t->cdib = dib; t->cdib_bits = bits; t->cdib_w = w; t->cdib_h = h;
            dib = NULL;
        }
        present_unlock();
        if (gone) DeleteObject(gone);
        if (dib) DeleteObject(dib);
    }
}

/* the frame is on the target: blend it, or have the window repaint where the old frame is not covered */
static void target_present(struct cobj *t, struct fbuf *nf)
{
    struct fbuf *old;
    DWORD hooked;
    HWND hwnd;
    RECT bb = { 0 };
    BOOL repaint = FALSE;
    UINT x, y;

    present_lock();
    if (!t->attached)
    {
        present_unlock();
        fbuf_release(nf);
        return;
    }
    old = t->frame; t->frame = nf;
    hwnd = t->hwnd; hooked = t->hook_tid;
    present_unlock();
    InterlockedIncrement(&comp_stats[0]);
    /* what the old frame drew stays on the window unless the new one covers it opaquely */
    if (old && old->used)
    {
        for (y = 0; y < old->h; y++)
            for (x = 0; x < old->w; x++)
            {
                if (!old->px[((size_t)y * old->w + x) * 4 + 3]) continue;
                if (x >= nf->w || y >= nf->h || nf->px[((size_t)y * nf->w + x) * 4 + 3] != 255)
                {
                    if (!repaint) { bb.left = x; bb.top = y; bb.right = x + 1; bb.bottom = y + 1; repaint = TRUE; }
                    else
                    {
                        if ((LONG)x < bb.left) bb.left = x;
                        if ((LONG)x >= bb.right) bb.right = x + 1;
                        bb.bottom = y + 1;
                    }
                }
            }
    }
    fbuf_release(old);
    TRACE("window %p: %ux%u frame%s%s\n", hwnd, nf->w, nf->h, nf->used ? "" : " (empty)", repaint ? ", repaint" : "");
    if (repaint && hooked)
        InvalidateRect(hwnd, &bb, TRUE);    /* the hook blends the new frame after the window's paint */
    else
        target_blit(t);
}

/* render one frame of a target on the render thread; f is NULL for "lay the live tree out again" */
static void render_target(struct cobj *t, struct frame_desc *f)
{
    struct fbuf *fb;
    RECT rc;
    UINT w, h, i;
    BOOL used = FALSE;

    if (!f)
    {
        if (!IsWindow(t->hwnd) || !GetClientRect(t->hwnd, &rc) || rc.right <= 0 || rc.bottom <= 0) return;
        frame_size(&rc, &w, &h);
        comp_lock();
        f = comp_frame_collect_locked(t->root, w, h);
        comp_unlock();
        if (!f) return;
    }
    comp_frame_resolve(f);
    comp_frame_size(f, &w, &h);
    if (!(fb = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FIELD_OFFSET(struct fbuf, px) + (size_t)w * h * 4)))
    {
        WARN("no memory for a %ux%u frame of window %p\n", w, h, t->hwnd);
        comp_frame_free(f);
        present_lock(); t->have_sig = FALSE; present_unlock();
        return;
    }
    fb->refs = 1; fb->w = w; fb->h = h;
    comp_frame_raster(f, fb->px, w * 4);
    comp_frame_free(f);
    for (i = 0; i < (size_t)w * h && !used; i++) used = fb->px[(size_t)i * 4 + 3] != 0;
    fb->used = used;
    target_present(t, fb);
}

/* one unit of the render thread's work; FALSE = nothing to do */
static BOOL render_step(void)
{
    struct cobj *t, *best = NULL;
    struct frame_desc *f = NULL, *discard = NULL;
    BOOL resize = FALSE, did = run_drops();

    present_lock();
    for (t = targets; t; t = t->tnext)
        if (t->attached && (t->pending || t->need_resize) && (!best || t->pseq - best->pseq < 0)) best = t;
    if (best && grab_locked(best))
    {
        t = best;
        if (t->need_resize)
        {
            resize = TRUE; t->need_resize = FALSE;
            discard = t->pending; t->pending = NULL;    /* the layout it carries is for the old size */
            if (discard) { inflight--; InterlockedIncrement(&comp_stats[1]); }
        }
        else
        {
            f = t->pending; t->pending = NULL;
        }
    }
    else
        t = NULL;
    present_unlock();
    comp_frame_free(discard);
    if (!t) return did;
    render_target(t, resize ? NULL : f);
    frames_done(1);
    drop(t);
    return TRUE;
}

static DWORD WINAPI render_main(void *arg)
{
    for (;;)
    {
        if (render_step()) continue;
        comp_worker_sleep(&render_worker, RENDER_IDLE_MS, TRUE);
    }
    return 0;
}

static void render_kick(void)
{
    if (!comp_worker_kick(&render_worker))
        while (render_step()) ;                     /* no thread: render here (slow, but the frame is not lost) */
}

HRESULT comp_wait_present(DWORD ms)
{
    DWORD start = GetTickCount();

    for (;;)
    {
        LONG n;

        present_lock(); n = inflight; present_unlock();
        if (!n) return S_OK;
        if (GetTickCount() - start >= ms) return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
        Sleep(1);
    }
}

/* ---- hooks ---- */

/* collect references to the attached targets of a window (or, with children, whose window is hwnd's ancestor) */
static int targets_of_window(HWND hwnd, BOOL children, struct cobj **out, int max)
{
    struct cobj *t;
    HWND list[16];
    int n = 0, k, nl = 0;

    if (children)
    {
        present_lock();
        for (t = targets; t && nl < ARRAY_SIZE(list); t = t->tnext)
            if (t->topmost && t->hwnd != hwnd) list[nl++] = t->hwnd;
        present_unlock();
        for (k = 0; k < nl; k++)
            if (!IsChild(list[k], hwnd)) list[k] = NULL;
    }
    present_lock();
    for (t = targets; t && n < max; t = t->tnext)
    {
        BOOL match = t->hwnd == hwnd;
        for (k = 0; k < nl && !match; k++) match = list[k] && t->hwnd == list[k];
        if (match && grab_locked(t)) out[n++] = t;
    }
    present_unlock();
    /* non-topmost targets first: the topmost one is composed above (a window has at most one of each) */
    if (n == 2 && out[0]->topmost && !out[1]->topmost)
    {
        t = out[0]; out[0] = out[1]; out[1] = t;
    }
    return n;
}

static LRESULT CALLBACK getmsg_hook(int code, WPARAM wp, LPARAM lp)
{
    MSG *m = (MSG *)lp;
    struct cobj *list[8];
    int n, k;

    if (code == HC_ACTION && wp == PM_REMOVE && m && m->hwnd && targets)
    {
        if (m->message == WM_PAINT)
        {
            n = targets_of_window(m->hwnd, TRUE, list, ARRAY_SIZE(list));
            for (k = 0; k < n; k++)
            {
                BOOL post;
                DWORD now = GetTickCount();

                if (!now) now = 1;
                present_lock();
                /* a request that was posted long ago and never came back is lost: post again */
                post = list[k]->frame && list[k]->frame->used &&
                       (!list[k]->post_tick || now - list[k]->post_tick > POST_RETRY_MS);
                if (post) list[k]->post_tick = now;
                present_unlock();
                if (post && present_msg && !PostMessageW(list[k]->hwnd, present_msg, 0, 0))
                {
                    present_lock(); list[k]->post_tick = 0; present_unlock();
                }
                defer_drop(list[k]);
            }
        }
        else if (present_msg && m->message == present_msg)
        {
            n = targets_of_window(m->hwnd, FALSE, list, ARRAY_SIZE(list));
            for (k = 0; k < n; k++)
            {
                present_lock(); list[k]->post_tick = 0; present_unlock();
                target_blit(list[k]);
                defer_drop(list[k]);
            }
            m->message = WM_NULL;           /* private: the window procedure does not see it */
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static LRESULT CALLBACK callret_hook(int code, WPARAM wp, LPARAM lp)
{
    CWPRETSTRUCT *r = (CWPRETSTRUCT *)lp;
    struct cobj *list[8];
    int n, k;

    if (code == HC_ACTION && r && r->hwnd && targets && (r->message == WM_PAINT || r->message == WM_SIZE))
    {
        n = targets_of_window(r->hwnd, r->message == WM_PAINT, list, ARRAY_SIZE(list));
        for (k = 0; k < n; k++)
        {
            if (r->message == WM_SIZE)
            {
                /* the render thread lays the tree out for the new size; until its frame arrives the last one stays */
                present_lock();
                if (list[k]->attached && !list[k]->need_resize) { list[k]->need_resize = TRUE; inflight++; }
                present_unlock();
                comp_worker_kick(&render_worker);
            }
            else target_blit(list[k]);
            defer_drop(list[k]);
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static BOOL hook_thread(DWORD tid)
{
    struct thread_hook *grown;
    HMODULE self = NULL;
    int k;
    BOOL ok = FALSE;

    EnterCriticalSection(&hook_cs);
    for (k = 0; k < nhooks; k++)
        if (hooks[k].tid == tid) { hooks[k].refs++; ok = TRUE; break; }
    if (!ok)
    {
        if (!present_msg) present_msg = RegisterWindowMessageW(L"NitroCompositionPresent");
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)getmsg_hook, &self);
        if (nhooks == caphooks)
        {
            int cap = caphooks ? caphooks * 2 : 4;
            grown = hooks ? HeapReAlloc(GetProcessHeap(), 0, hooks, cap * sizeof(*grown))
                          : HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*grown));
            if (grown) { hooks = grown; caphooks = cap; }
        }
        if (nhooks < caphooks)
        {
            struct thread_hook *h = &hooks[nhooks];
            h->tid = tid; h->refs = 1;
            /* the handle keeps the id of an exited thread from being given to a new one while this entry exists */
            h->thread = OpenThread(SYNCHRONIZE, FALSE, tid);
            h->getmsg = SetWindowsHookExW(WH_GETMESSAGE, getmsg_hook, self, tid);
            h->callret = SetWindowsHookExW(WH_CALLWNDPROCRET, callret_hook, self, tid);
            if (h->getmsg || h->callret) { nhooks++; ok = TRUE; }
            else
            {
                WARN("no message hook on thread %lx: %lu\n", tid, GetLastError());
                if (h->thread) CloseHandle(h->thread);
            }
        }
    }
    LeaveCriticalSection(&hook_cs);
    return ok;
}

static void unhook_thread(DWORD tid)
{
    HHOOK a = NULL, b = NULL;
    HANDLE th = NULL;
    int k;

    EnterCriticalSection(&hook_cs);
    for (k = 0; k < nhooks; k++)
        if (hooks[k].tid == tid)
        {
            if (!--hooks[k].refs)
            {
                a = hooks[k].getmsg; b = hooks[k].callret; th = hooks[k].thread;
                hooks[k] = hooks[--nhooks];
            }
            break;
        }
    LeaveCriticalSection(&hook_cs);
    if (a) UnhookWindowsHookEx(a);
    if (b) UnhookWindowsHookEx(b);
    if (th) CloseHandle(th);
}

void present_attach(struct cobj *t)
{
    DWORD pid = 0, tid = GetWindowThreadProcessId(t->hwnd, &pid);

    if (tid && pid == GetCurrentProcessId() && !hook_thread(tid)) tid = 0;
    if (pid != GetCurrentProcessId()) tid = 0;
    present_lock();
    t->hook_tid = tid;
    t->attached = TRUE;
    t->tnext = targets;
    targets = t;
    present_unlock();
    TRACE("target %p for window %p (thread %lx, topmost %d)\n", t, t->hwnd, tid, t->topmost);
}

void present_detach(struct cobj *t)
{
    struct cobj **p;
    struct fbuf *frame;
    struct frame_desc *pending;
    BOOL used;
    DWORD tid;

    present_lock();
    if (!t->attached) { present_unlock(); return; }
    for (p = &targets; *p; p = &(*p)->tnext)
        if (*p == t) { *p = t->tnext; break; }
    t->attached = FALSE;
    t->tnext = NULL;
    frame = t->frame; t->frame = NULL; used = frame && frame->used;
    pending = t->pending; t->pending = NULL;
    if (pending) inflight--;
    if (t->need_resize) { t->need_resize = FALSE; inflight--; }
    t->have_sig = FALSE; t->post_tick = 0;
    tid = t->hook_tid; t->hook_tid = 0;
    present_unlock();
    if (tid) unhook_thread(tid);
    fbuf_release(frame);
    comp_frame_free(pending);
    /* the tree is no longer shown: the window paints its own content again */
    if (used && IsWindow(t->hwnd)) InvalidateRect(t->hwnd, NULL, TRUE);
}

/* the last reference is gone: nothing uses the target any more */
void present_free(struct cobj *t)
{
    if (t->cdib) DeleteObject(t->cdib);
    t->cdib = NULL;
}

/* a commit of one target: record the frame and hand it to the render thread */
static void commit_target(struct cobj *t)
{
    struct frame_desc *f, *old;
    RECT rc;
    UINT w, h;
    UINT64 sig;
    BOOL same;

    if (!IsWindow(t->hwnd) || !GetClientRect(t->hwnd, &rc) || rc.right <= 0 || rc.bottom <= 0) return;
    frame_size(&rc, &w, &h);
    comp_lock();
    f = comp_frame_collect_locked(t->root, w, h);
    comp_unlock();
    if (!f) return;
    sig = comp_frame_sig(f);
    present_lock();
    if (!t->attached) { present_unlock(); comp_frame_free(f); return; }
    /* the same as the newest frame (rendered or waiting): nothing to do; a window that is not hooked is blended
     * again by every commit, since nothing else brings the frame back after the window painted */
    same = t->have_sig && t->sig == sig && t->hook_tid;
    if (same)
    {
        present_unlock();
        InterlockedIncrement(&comp_stats[2]);
        comp_frame_free(f);
        return;
    }
    t->have_sig = TRUE; t->sig = sig;
    old = t->pending;
    t->pending = f;
    t->pseq = ++pseq_counter;
    if (old) InterlockedIncrement(&comp_stats[1]);
    else inflight++;
    present_unlock();
    comp_frame_free(old);
    render_kick();
}

/* a commit: every target of the Compositor shows its tree as it is now; returns at once, the render thread draws it */
void comp_commit_targets(IUnknown *compositor)
{
    struct cobj *t, **list;
    int n = 0, k, max = 0;

    run_drops();                                    /* references a hook left behind when it could not wake the thread */
    present_lock();
    for (t = targets; t; t = t->tnext) max++;
    present_unlock();
    if (!max || !(list = HeapAlloc(GetProcessHeap(), 0, max * sizeof(*list)))) return;
    present_lock();
    for (t = targets; t && n < max; t = t->tnext)
        if (t->compositor == compositor && t->attached && grab_locked(t)) list[n++] = t;
    present_unlock();
    for (k = 0; k < n; k++)
    {
        commit_target(list[k]);
        drop(list[k]);
    }
    HeapFree(GetProcessHeap(), 0, list);
}
