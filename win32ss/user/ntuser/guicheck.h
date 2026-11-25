#pragma once

BOOL FASTCALL co_IntGraphicsCheck(BOOL Create);
VOID FASTCALL co_IntUserManualGuiCheck(BOOL Create);
VOID FASTCALL co_IntHoldHeadlessDisplay(VOID);
BOOL FASTCALL IntCreatePrimarySurface(VOID);
VOID FASTCALL IntDestroyPrimarySurface(VOID);

/* EOF */
