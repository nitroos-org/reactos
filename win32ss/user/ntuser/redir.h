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
VOID FASTCALL UserRedirReleased(PVOID pvRedir, BOOL bForce);
VOID FASTCALL UserRedirWindowMoved(PWND Wnd);
VOID FASTCALL UserRedirPresentPending(VOID);
BOOL FASTCALL UserRedirHasSurface(PWND Wnd);

/* windc.c */
VOID FASTCALL DceRedirUnbindAll(PVOID pvRedir);
VOID FASTCALL DceRedirRebindAll(PVOID pvRedir, struct _SURFACE *psurf);
