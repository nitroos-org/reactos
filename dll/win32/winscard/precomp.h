
#ifndef _WINSCARD_PCH_
#define _WINSCARD_PCH_

#include <stdarg.h>

#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H

#include <windef.h>
#include <winbase.h>
#include <winscard.h>

#include <wine/debug.h>

#ifndef SCARD_AUTOALLOCATE
#define SCARD_AUTOALLOCATE ((DWORD)-1)
#endif

#ifndef SCARD_STATE_UNAWARE
#define SCARD_STATE_UNAWARE 0x00000000
#define SCARD_STATE_IGNORE  0x00000001
#define SCARD_STATE_CHANGED 0x00000002
#define SCARD_STATE_UNKNOWN 0x00000004
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* Set by the Smart Card service (base/services/scardsvr) while it runs */
#define SCARD_STARTED_EVENT_NAME L"Global\\Microsoft Smart Card Resource Manager Started"

LONG scard_empty_multistring(BOOL wide, void *buf, DWORD *len);
LONG scard_return_multistring(BOOL wide, const WCHAR *src, DWORD srclen, void *buf, DWORD *len);
LONG scard_no_context(void);
void scard_init(void);
void scard_exit(BOOL process_terminating);

#endif /* !_WINSCARD_PCH_ */
