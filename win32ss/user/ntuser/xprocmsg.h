#pragma once

/* xprocmsg.c: what Windows does when a message goes from this process to a thread of another one */
#define XPROC_POST     0
#define XPROC_SEND     1  /* SendMessage and SendMessageTimeout */
#define XPROC_NOTIFY   2
#define XPROC_CALLBACK 3
#define XPROC_THREAD   4

/* returned instead of an error code: the message is swallowed, no error, the result is in *pRet */
#define XPROC_SILENT   0xFFFFFFFF

DWORD FASTCALL
IntXprocMsgRefusal(PTHREADINFO ptiTarget, UINT Msg, WPARAM wParam, LPARAM lParam, UINT Kind, PBOOL pRet);
