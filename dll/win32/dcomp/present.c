/*
 * PROJECT:     ReactOS DirectComposition
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Windows.UI.Composition: present the visual tree of a DesktopWindowTarget into its window
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Without a desktop compositor (window surfaces at redirection level 0) the visual tree is drawn into the window
 * itself, the way the DirectComposition device draws composition swap chains (device.c). On a commit
 * (ICompositorController::Commit, or the automatic commit of a Compositor that has no controller) the tree under
 * the target's Root is rendered by the CPU renderer of composition.c at the size of the window's client area
 * (composition units are client pixels, no DPI scaling) and alpha-blended over the window's client area through a
 * window DC: a non-topmost target leaves the child windows on top (DCX_CLIPCHILDREN), a topmost one draws over them.
 *
 * What the window paints itself would overwrite the tree, so the last frame is kept and blended again after every
 * WM_PAINT of the window (and, for a topmost target, of its children): a thread hook on the window's thread
 * (only for windows of this process) posts a private message when it sees WM_PAINT leave the queue and blends the
 * frame when that message comes back, i.e. after the paint; a WM_PAINT sent by UpdateWindow is seen when its
 * window procedure returns; WM_SIZE renders the tree again at the new size. When a new frame does not cover what
 * the previous one drew (a visual moved or became transparent), the window is invalidated so that its own content
 * comes back under the new frame.
 *
 * FIXME: not done: a window of another process gets the frame at commit time only (no hook); resize renders the
 * live tree, not the last committed one; no partial updates (every commit renders the whole client area); no
 * redirection surface or DWM path (level 1+ windows are drawn the same way). Verify on the oracle: whether the
 * tree is laid out in the client area (assumed) and in physical pixels (assumed).
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

#define MAX_TARGET_SIZE 16384

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static struct cobj *targets;            /* every attached DesktopWindowTarget, under comp_lock */
static UINT present_msg;                /* private message: blend the frame again after a WM_PAINT */

struct thread_hook
{
    DWORD tid;
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

/* a reference to a target found under comp_lock, unless it is already being destroyed; caller holds comp_lock */
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

static void drop(struct cobj *t)
{
    IInspectable_Release(&t->identity);
}

/* blend the target's last frame over its window; nothing when there is no frame */
static void target_blit(struct cobj *t)
{
    BITMAPINFO bmi;
    BLENDFUNCTION bf;
    HBITMAP dib, oldbmp;
    HDC hdc, mem;
    void *bits = NULL;
    HWND hwnd;
    UINT w, h;
    BOOL topmost, ok;

    comp_lock();
    hwnd = t->hwnd; w = t->fw; h = t->fh; topmost = t->topmost;
    ok = t->frame && t->frame_used && w && h;
    comp_unlock();
    if (!ok || !IsWindow(hwnd)) return;

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
        return;
    }
    comp_lock();
    ok = t->frame && t->fw == w && t->fh == h;
    if (ok) memcpy(bits, t->frame, (size_t)w * h * 4);
    comp_unlock();
    if (ok && (hdc = GetDCEx(hwnd, NULL, DCX_CACHE | DCX_CLIPSIBLINGS | (topmost ? 0 : DCX_CLIPCHILDREN))))
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
    DeleteObject(dib);
}

/* render the tree at the client size; blend it, or have the window repaint when the old frame is not covered */
static void target_render(struct cobj *t)
{
    BYTE *frame, *old;
    UINT w, h, ow, oh, x, y;
    BOOL attached, repaint = FALSE, used = FALSE;
    DWORD hooked;
    size_t i;
    HWND hwnd;
    RECT rc;

    comp_lock();
    hwnd = t->hwnd; attached = t->attached && !t->closed; hooked = t->hook_tid;
    comp_unlock();
    if (!attached || !IsWindow(hwnd) || !GetClientRect(hwnd, &rc)) return;
    if (rc.right <= 0 || rc.bottom <= 0) return;
    w = rc.right < MAX_TARGET_SIZE ? rc.right : MAX_TARGET_SIZE;
    h = rc.bottom < MAX_TARGET_SIZE ? rc.bottom : MAX_TARGET_SIZE;
    if (!(frame = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)w * h * 4)))
    {
        WARN("no memory for a %ux%u frame of window %p\n", w, h, hwnd);
        return;
    }
    comp_lock();
    if (t->root) comp_render_locked(t->root, w, h, frame, w * 4);
    for (i = 0; i < (size_t)w * h && !used; i++) used = frame[i * 4 + 3] != 0;
    old = t->frame; ow = t->fw; oh = t->fh;
    /* what the old frame drew stays on the window unless the new one covers it opaquely */
    if (old && t->frame_used)
    {
        for (y = 0; y < oh && !repaint; y++)
            for (x = 0; x < ow; x++)
            {
                if (!old[((size_t)y * ow + x) * 4 + 3]) continue;
                if (x >= w || y >= h || frame[((size_t)y * w + x) * 4 + 3] != 255) { repaint = TRUE; break; }
            }
    }
    t->frame = frame; t->fw = w; t->fh = h; t->frame_used = used;
    comp_unlock();
    HeapFree(GetProcessHeap(), 0, old);
    TRACE("window %p: %ux%u frame%s%s\n", hwnd, w, h, used ? "" : " (empty)", repaint ? ", repaint" : "");
    if (repaint && hooked)
        InvalidateRect(hwnd, NULL, TRUE);   /* the hook blends the new frame after the window's paint */
    else
        target_blit(t);
}

/* collect references to the attached targets of a window (or, with children, whose window is hwnd's ancestor) */
static int targets_of_window(HWND hwnd, BOOL children, struct cobj **out, int max)
{
    struct cobj *t;
    HWND list[16];
    int n = 0, k, nl = 0;

    if (children)
    {
        comp_lock();
        for (t = targets; t && nl < ARRAY_SIZE(list); t = t->tnext)
            if (t->topmost && t->hwnd != hwnd) list[nl++] = t->hwnd;
        comp_unlock();
        for (k = 0; k < nl; k++)
            if (!IsChild(list[k], hwnd)) list[k] = NULL;
    }
    comp_lock();
    for (t = targets; t && n < max; t = t->tnext)
    {
        BOOL match = t->hwnd == hwnd;
        for (k = 0; k < nl && !match; k++) match = list[k] && t->hwnd == list[k];
        if (match && grab_locked(t)) out[n++] = t;
    }
    comp_unlock();
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
                comp_lock();
                post = list[k]->frame_used && !list[k]->post_pending;
                if (post) list[k]->post_pending = TRUE;
                comp_unlock();
                if (post && present_msg) PostMessageW(list[k]->hwnd, present_msg, 0, 0);
                drop(list[k]);
            }
        }
        else if (present_msg && m->message == present_msg)
        {
            n = targets_of_window(m->hwnd, FALSE, list, ARRAY_SIZE(list));
            for (k = 0; k < n; k++)
            {
                comp_lock(); list[k]->post_pending = FALSE; comp_unlock();
                target_blit(list[k]);
                drop(list[k]);
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
            if (r->message == WM_SIZE) target_render(list[k]);
            else target_blit(list[k]);
            drop(list[k]);
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
            h->getmsg = SetWindowsHookExW(WH_GETMESSAGE, getmsg_hook, self, tid);
            h->callret = SetWindowsHookExW(WH_CALLWNDPROCRET, callret_hook, self, tid);
            if (h->getmsg || h->callret) { nhooks++; ok = TRUE; }
            else WARN("no message hook on thread %lx: %lu\n", tid, GetLastError());
        }
    }
    LeaveCriticalSection(&hook_cs);
    return ok;
}

static void unhook_thread(DWORD tid)
{
    HHOOK a = NULL, b = NULL;
    int k;

    EnterCriticalSection(&hook_cs);
    for (k = 0; k < nhooks; k++)
        if (hooks[k].tid == tid)
        {
            if (!--hooks[k].refs)
            {
                a = hooks[k].getmsg; b = hooks[k].callret;
                hooks[k] = hooks[--nhooks];
            }
            break;
        }
    LeaveCriticalSection(&hook_cs);
    if (a) UnhookWindowsHookEx(a);
    if (b) UnhookWindowsHookEx(b);
}

void present_attach(struct cobj *t)
{
    DWORD pid = 0, tid = GetWindowThreadProcessId(t->hwnd, &pid);

    if (tid && pid == GetCurrentProcessId() && !hook_thread(tid)) tid = 0;
    if (pid != GetCurrentProcessId()) tid = 0;
    comp_lock();
    t->hook_tid = tid;
    t->attached = TRUE;
    t->tnext = targets;
    targets = t;
    comp_unlock();
    TRACE("target %p for window %p (thread %lx, topmost %d)\n", t, t->hwnd, tid, t->topmost);
}

void present_detach(struct cobj *t)
{
    struct cobj **p;
    BYTE *frame;
    BOOL used;
    DWORD tid;

    comp_lock();
    if (!t->attached) { comp_unlock(); return; }
    for (p = &targets; *p; p = &(*p)->tnext)
        if (*p == t) { *p = t->tnext; break; }
    t->attached = FALSE;
    t->tnext = NULL;
    frame = t->frame; t->frame = NULL; used = t->frame_used; t->frame_used = FALSE;
    tid = t->hook_tid; t->hook_tid = 0;
    comp_unlock();
    if (tid) unhook_thread(tid);
    HeapFree(GetProcessHeap(), 0, frame);
    /* the tree is no longer shown: the window paints its own content again */
    if (used && IsWindow(t->hwnd)) InvalidateRect(t->hwnd, NULL, TRUE);
}

/* a commit: every target of the Compositor shows its tree as it is now */
void comp_commit_targets(IUnknown *compositor)
{
    struct cobj *t, **list;
    int n = 0, k, max = 0;

    comp_lock();
    for (t = targets; t; t = t->tnext) max++;
    comp_unlock();
    if (!max || !(list = HeapAlloc(GetProcessHeap(), 0, max * sizeof(*list)))) return;
    comp_lock();
    for (t = targets; t && n < max; t = t->tnext)
        if (t->compositor == compositor && !t->closed && grab_locked(t)) list[n++] = t;
    comp_unlock();
    for (k = 0; k < n; k++)
    {
        target_render(list[k]);
        drop(list[k]);
    }
    HeapFree(GetProcessHeap(), 0, list);
}
