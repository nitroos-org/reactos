#pragma once

/* Redirected window surfaces (redir.c, windc.c, gdi/ntgdi/redirgdi.c) */
extern ULONG gRedirLevel;
extern PKTIMER gRedirTimer;

VOID NTAPI UserRedirInit(VOID);
PWND FASTCALL UserRedirRootFor(PWND Wnd);
PVOID FASTCALL UserRedirGet(PWND Root);
VOID FASTCALL UserRedirDetachWindow(PWND Wnd);
VOID FASTCALL UserRedirAddRef(PVOID pvRedir);
VOID FASTCALL UserRedirRelease(PVOID pvRedir);
struct _SURFACE *FASTCALL UserRedirSurface(PVOID pvRedir);
PWND FASTCALL UserRedirWindow(PVOID pvRedir);
VOID FASTCALL UserRedirReleased(PVOID pvRedir, BOOL bEndPaint);
VOID FASTCALL UserRedirRetryCount(LONG Delta);
VOID FASTCALL UserRedirDcRelease(PVOID pvRedir);
VOID FASTCALL UserRedirWindowMoved(PWND Wnd);
VOID FASTCALL UserRedirPresentPending(VOID);
BOOL FASTCALL UserRedirHasSurface(PWND Wnd);
VOID FASTCALL UserRedirExpose(PWND DesktopWnd, PREGION RgnScreen);
BOOL FASTCALL UserRedirCopyToDC(PWND Wnd, HDC hdc, LONG xSrc, LONG ySrc, LONG cx, LONG cy);
/* Level 2 (layered and glass windows composed) */
BOOL FASTCALL UserRedirIsUlw(PVOID pvRedir);
BOOL FASTCALL UserRedirNoPaint(PWND Wnd);
BOOL FASTCALL UserRedirKeepOnHide(PWND Wnd);
VOID FASTCALL UserRedirLayoutChanged(PWND Wnd, const RECTL *prcOld);
VOID FASTCALL UserRedirLayeredSet(PWND Wnd, BOOL bFirst);
BOOL FASTCALL UserRedirLayeredFits(PWND Wnd, LONG cx, LONG cy);
VOID FASTCALL UserRedirUlwSeen(PWND Wnd);
VOID FASTCALL UserRedirFreeFrameBuffer(VOID);
BOOL FASTCALL UserRedirUpdateLayered(PWND Wnd, const RECTL *prcOld, HDC hdcSrc, const POINT *pptSrc, const RECT *prcDirty,
                                     const BLENDFUNCTION *pBlend, COLORREF crKey, DWORD dwFlags, PBOOL pbRet);

/* windc.c */
VOID FASTCALL DceRedirUnbindAll(PVOID pvRedir);
VOID FASTCALL DceRedirRebindAll(PVOID pvRedir, struct _SURFACE *psurf);
VOID FASTCALL DceRedirRetryAll(_Inout_ PLONG plBudget);
