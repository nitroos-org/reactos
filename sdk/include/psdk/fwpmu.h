/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Windows Filtering Platform: management functions of fwpuclnt.dll (written from the public documentation of fwpmu.h)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef _FWPMU_H
#define _FWPMU_H

#include <rpc.h>
#include <fwptypes.h>
#include <fwpmtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef FWPMU_API
#define FWPMU_API
#endif

#define FWPM_AUTO_WEIGHT_BITS 60

/* Engine session */
DWORD WINAPI FwpmEngineOpen0(const wchar_t *serverName, UINT32 authnService, SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
                             const FWPM_SESSION0 *session, HANDLE *engineHandle);
DWORD WINAPI FwpmEngineClose0(HANDLE engineHandle);
DWORD WINAPI FwpmEngineGetOption0(HANDLE engineHandle, FWPM_ENGINE_OPTION option, FWP_VALUE0 **value);
DWORD WINAPI FwpmEngineSetOption0(HANDLE engineHandle, FWPM_ENGINE_OPTION option, const FWP_VALUE0 *newValue);
DWORD WINAPI FwpmEngineGetSecurityInfo0(HANDLE engineHandle, SECURITY_INFORMATION securityInfo, PSID *sidOwner,
                                        PSID *sidGroup, PACL *dacl, PACL *sacl, PSECURITY_DESCRIPTOR *securityDescriptor);
DWORD WINAPI FwpmEngineSetSecurityInfo0(HANDLE engineHandle, SECURITY_INFORMATION securityInfo, const SID *sidOwner,
                                        const SID *sidGroup, const ACL *dacl, const ACL *sacl);

/* Transactions */
DWORD WINAPI FwpmTransactionBegin0(HANDLE engineHandle, UINT32 flags);
DWORD WINAPI FwpmTransactionCommit0(HANDLE engineHandle);
DWORD WINAPI FwpmTransactionAbort0(HANDLE engineHandle);

/* Memory returned by the functions below is released with this one */
void WINAPI FwpmFreeMemory0(void **p);

/* The application identifier of a file: its NT path in lower case */
DWORD WINAPI FwpmGetAppIdFromFileName0(PCWSTR fileName, FWP_BYTE_BLOB **appId);

/* Filters */
DWORD WINAPI FwpmFilterAdd0(HANDLE engineHandle, const FWPM_FILTER0 *filter, PSECURITY_DESCRIPTOR sd, UINT64 *id);
DWORD WINAPI FwpmFilterDeleteById0(HANDLE engineHandle, UINT64 id);
DWORD WINAPI FwpmFilterDeleteByKey0(HANDLE engineHandle, const GUID *key);
DWORD WINAPI FwpmFilterGetById0(HANDLE engineHandle, UINT64 id, FWPM_FILTER0 **filter);
DWORD WINAPI FwpmFilterGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_FILTER0 **filter);
DWORD WINAPI FwpmFilterCreateEnumHandle0(HANDLE engineHandle, const FWPM_FILTER_ENUM_TEMPLATE0 *enumTemplate, HANDLE *enumHandle);
DWORD WINAPI FwpmFilterEnum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested, FWPM_FILTER0 ***entries,
                             UINT32 *numEntriesReturned);
DWORD WINAPI FwpmFilterDestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle);

/* Sublayers */
DWORD WINAPI FwpmSubLayerAdd0(HANDLE engineHandle, const FWPM_SUBLAYER0 *subLayer, PSECURITY_DESCRIPTOR sd);
DWORD WINAPI FwpmSubLayerDeleteByKey0(HANDLE engineHandle, const GUID *key);
DWORD WINAPI FwpmSubLayerGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_SUBLAYER0 **subLayer);
DWORD WINAPI FwpmSubLayerCreateEnumHandle0(HANDLE engineHandle, const FWPM_SUBLAYER_ENUM_TEMPLATE0 *enumTemplate, HANDLE *enumHandle);
DWORD WINAPI FwpmSubLayerEnum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested, FWPM_SUBLAYER0 ***entries,
                               UINT32 *numEntriesReturned);
DWORD WINAPI FwpmSubLayerDestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle);

/* Providers */
DWORD WINAPI FwpmProviderAdd0(HANDLE engineHandle, const FWPM_PROVIDER0 *provider, PSECURITY_DESCRIPTOR sd);
DWORD WINAPI FwpmProviderDeleteByKey0(HANDLE engineHandle, const GUID *key);
DWORD WINAPI FwpmProviderGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_PROVIDER0 **provider);
DWORD WINAPI FwpmProviderCreateEnumHandle0(HANDLE engineHandle, const FWPM_PROVIDER_ENUM_TEMPLATE0 *enumTemplate, HANDLE *enumHandle);
DWORD WINAPI FwpmProviderEnum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested, FWPM_PROVIDER0 ***entries,
                               UINT32 *numEntriesReturned);
DWORD WINAPI FwpmProviderDestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle);

/* Callouts */
DWORD WINAPI FwpmCalloutAdd0(HANDLE engineHandle, const FWPM_CALLOUT0 *callout, PSECURITY_DESCRIPTOR sd, UINT32 *id);
DWORD WINAPI FwpmCalloutDeleteById0(HANDLE engineHandle, UINT32 id);
DWORD WINAPI FwpmCalloutDeleteByKey0(HANDLE engineHandle, const GUID *key);
DWORD WINAPI FwpmCalloutGetById0(HANDLE engineHandle, UINT32 id, FWPM_CALLOUT0 **callout);
DWORD WINAPI FwpmCalloutGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_CALLOUT0 **callout);
DWORD WINAPI FwpmCalloutCreateEnumHandle0(HANDLE engineHandle, const FWPM_CALLOUT_ENUM_TEMPLATE0 *enumTemplate, HANDLE *enumHandle);
DWORD WINAPI FwpmCalloutEnum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested, FWPM_CALLOUT0 ***entries,
                              UINT32 *numEntriesReturned);
DWORD WINAPI FwpmCalloutDestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle);

/* Provider contexts, layers and sessions (enumeration only) */
DWORD WINAPI FwpmProviderContextAdd0(HANDLE engineHandle, const FWPM_PROVIDER_CONTEXT0 *providerContext, PSECURITY_DESCRIPTOR sd, UINT64 *id);
DWORD WINAPI FwpmProviderContextDeleteById0(HANDLE engineHandle, UINT64 id);
DWORD WINAPI FwpmProviderContextDeleteByKey0(HANDLE engineHandle, const GUID *key);
DWORD WINAPI FwpmProviderContextGetById0(HANDLE engineHandle, UINT64 id, FWPM_PROVIDER_CONTEXT0 **providerContext);
DWORD WINAPI FwpmProviderContextGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_PROVIDER_CONTEXT0 **providerContext);
DWORD WINAPI FwpmProviderContextCreateEnumHandle0(HANDLE engineHandle, const FWPM_PROVIDER_CONTEXT_ENUM_TEMPLATE0 *enumTemplate,
                                                  HANDLE *enumHandle);
DWORD WINAPI FwpmProviderContextEnum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested,
                                      FWPM_PROVIDER_CONTEXT0 ***entries, UINT32 *numEntriesReturned);
DWORD WINAPI FwpmProviderContextDestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle);
DWORD WINAPI FwpmLayerGetById0(HANDLE engineHandle, UINT16 id, FWPM_LAYER0 **layer);
DWORD WINAPI FwpmLayerGetByKey0(HANDLE engineHandle, const GUID *key, FWPM_LAYER0 **layer);
DWORD WINAPI FwpmLayerCreateEnumHandle0(HANDLE engineHandle, const FWPM_LAYER_ENUM_TEMPLATE0 *enumTemplate, HANDLE *enumHandle);
DWORD WINAPI FwpmLayerEnum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested, FWPM_LAYER0 ***entries,
                            UINT32 *numEntriesReturned);
DWORD WINAPI FwpmLayerDestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle);
DWORD WINAPI FwpmSessionCreateEnumHandle0(HANDLE engineHandle, const FWPM_SESSION_ENUM_TEMPLATE0 *enumTemplate, HANDLE *enumHandle);
DWORD WINAPI FwpmSessionEnum0(HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested, FWPM_SESSION0 ***entries,
                              UINT32 *numEntriesReturned);
DWORD WINAPI FwpmSessionDestroyEnumHandle0(HANDLE engineHandle, HANDLE enumHandle);

#ifdef __cplusplus
}
#endif

#endif /* _FWPMU_H */
