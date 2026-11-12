#include <rtltests.h>
#include <pseh/pseh2.h>
#include <compat_undoc.h>
#include <compatguid_undoc.h>

#define NDEBUG
#include <debug.h>

BOOLEAN LdrpShutdownInProgress;
HANDLE LdrpShutdownThreadId;

VOID
NTAPI
LdrpInitializeProcessCompat(PVOID pProcessActctx, PVOID* pOldShimData)
{
}

VOID NTAPI
AVrfInternalHeapFreeNotification(PVOID AllocationBase, SIZE_T AllocationSize)
{
    /* Stub for linking against rtl */
}

#ifdef _M_IX86
/* rtl_um also calls private WoW64 services supplied by ntdll's dispatch
 * object. Static RTL tests use the loaded ntdll exports for those services. */
NTSTATUS NTAPI
RtlpWow64EnableFsRedirectionEx(PVOID Level, PVOID *Previous)
{
    typedef NTSTATUS (NTAPI *SERVICE)(PVOID, PVOID *);
    SERVICE Service = (SERVICE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                               "RtlWow64EnableFsRedirectionEx");
    return Service ? Service(Level, Previous) : STATUS_PROCEDURE_NOT_FOUND;
}

NTSTATUS NTAPI
RtlpWow64GetNativeSystemInformation(SYSTEM_INFORMATION_CLASS Class, PVOID Buffer,
                                    ULONG Length, PULONG ReturnLength)
{
    typedef NTSTATUS (NTAPI *SERVICE)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    SERVICE Service = (SERVICE)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                               "RtlGetNativeSystemInformation");
    return Service ? Service(Class, Buffer, Length, ReturnLength) : STATUS_PROCEDURE_NOT_FOUND;
}
#endif

BOOLEAN
NTAPI
LdrpLookupImageRange(PVOID Address, PVOID *ImageBase)
{
    /* No loader here: RtlPcToFileHeader searches the module list */
    return FALSE;
}
