#pragma once

/* Saved bits of windows of a class with CS_SAVEBITS (spb.c) */
VOID FASTCALL UserSpbSave(PWND Wnd);
BOOL FASTCALL UserSpbRestore(PWND Wnd, PREGION prgnExposed);
VOID FASTCALL UserSpbDrop(PWND Wnd);
VOID FASTCALL UserSpbDropAll(VOID);
VOID FASTCALL UserSpbNoteRect(PWND Wnd, const RECTL *prc);
VOID FASTCALL UserSpbNoteDC(PWND Wnd);
extern ULONG gSpbCount;
