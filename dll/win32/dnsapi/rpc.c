#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <dnsrslvr_c.h>

#define NDEBUG
#include <debug.h>

/*
 * The binding to the resolver service of this machine, made on the first call and kept for the life of the module.
 *
 * The NDR client of rpcrt4 never calls the unbind function of a generic handle (it takes the handle for the unbind call
 * before the bind function has made it), so a binding made for every call was never freed: 149 bytes of the process heap
 * (the binding, "ncalrpc", the empty network address and "DNSResolver") leaked by every query. One binding for all
 * calls does not leak, and every call has the same association with the service as before.
 */
static handle_t g_LocalBinding = NULL;

static handle_t
CreateBinding(DNSRSLVR_HANDLE pszMachineName)
{
    handle_t hBinding = NULL;
    LPWSTR pszStringBinding;
    RPC_STATUS Status;

    DPRINT("CreateBinding(%S)\n", pszMachineName);

    Status = RpcStringBindingComposeW(NULL,
                                      L"ncalrpc",
                                      pszMachineName,
                                      L"DNSResolver",
                                      NULL,
                                      &pszStringBinding);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcStringBindingCompose returned 0x%x\n", Status);
        return NULL;
    }

    /* Set the binding handle that will be used to bind to the server. */
    Status = RpcBindingFromStringBindingW(pszStringBinding,
                                          &hBinding);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcBindingFromStringBinding returned 0x%x\n", Status);
    }

    Status = RpcStringFreeW(&pszStringBinding);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcStringFree returned 0x%x\n", Status);
    }

    return hBinding;
}

handle_t __RPC_USER
DNSRSLVR_HANDLE_bind(DNSRSLVR_HANDLE pszMachineName)
{
    handle_t hBinding, hOld;

    DPRINT("DNSRSLVR_HANDLE_bind(%S)\n", pszMachineName);

    /* Another machine: a binding of its own for the call (freed by the unbind function) */
    if (pszMachineName != NULL)
        return CreateBinding(pszMachineName);

    hBinding = g_LocalBinding;
    if (hBinding != NULL)
        return hBinding;

    hBinding = CreateBinding(NULL);
    if (hBinding == NULL)
        return NULL;

    /* Two threads that bind at once: one binding is kept, the other one freed */
    hOld = InterlockedCompareExchangePointer((PVOID volatile *)&g_LocalBinding, hBinding, NULL);
    if (hOld != NULL)
    {
        RpcBindingFree(&hBinding);
        return hOld;
    }

    return hBinding;
}

void __RPC_USER
DNSRSLVR_HANDLE_unbind(DNSRSLVR_HANDLE pszMachineName,
                       handle_t hBinding)
{
    RPC_STATUS Status;

    DPRINT("DNSRSLVR_HANDLE_unbind(%S)\n", pszMachineName);

    /* The binding of this machine is kept (see g_LocalBinding) */
    if (pszMachineName == NULL)
        return;

    Status = RpcBindingFree(&hBinding);
    if (Status != RPC_S_OK)
    {
        DPRINT1("RpcBindingFree returned 0x%x\n", Status);
    }
}

BOOL WINAPI
DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hInstance);
            break;

        case DLL_PROCESS_DETACH:
            /* Unloaded (not the process ending): give the binding back */
            if (lpReserved == NULL && g_LocalBinding != NULL)
            {
                handle_t hBinding = g_LocalBinding;

                g_LocalBinding = NULL;
                RpcBindingFree(&hBinding);
            }
            break;
    }

    return TRUE;
}

void __RPC_FAR * __RPC_USER
midl_user_allocate(SIZE_T len)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
}

void __RPC_USER
midl_user_free(void __RPC_FAR * ptr)
{
    HeapFree(GetProcessHeap(), 0, ptr);
}
