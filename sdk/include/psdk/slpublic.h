/*
 * PROJECT:     ReactOS PSDK
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Software Licensing client API (sppc.dll / slc.dll): types and prototypes
 */

#ifndef _SLPUBLIC_H_
#define _SLPUBLIC_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef GUID SLID;
DECLARE_HANDLE(HSLC);

typedef enum _tagSLIDTYPE
{
    SL_ID_APPLICATION = 0,
    SL_ID_PRODUCT_SKU,
    SL_ID_LICENSE_FILE,
    SL_ID_LICENSE,
    SL_ID_PKEY,
    SL_ID_ALL_LICENSES,
    SL_ID_ALL_LICENSE_FILES,
    SL_ID_STORE_TOKEN,
    SL_ID_LAST
} SLIDTYPE;

typedef enum _tagSLDATATYPE
{
    SL_DATA_NONE = REG_NONE,
    SL_DATA_SZ = REG_SZ,
    SL_DATA_DWORD = REG_DWORD,
    SL_DATA_BINARY = REG_BINARY,
    SL_DATA_MULTI_SZ = REG_MULTI_SZ,
    SL_DATA_SUM = 100
} SLDATATYPE;

typedef enum _tagSLLICENSINGSTATUS
{
    SL_LICENSING_STATUS_UNLICENSED = 0,
    SL_LICENSING_STATUS_LICENSED,
    SL_LICENSING_STATUS_IN_GRACE_PERIOD,
    SL_LICENSING_STATUS_NOTIFICATION,
    SL_LICENSING_STATUS_LAST
} SLLICENSINGSTATUS;

typedef struct _tagSL_LICENSING_STATUS
{
    SLID SkuId;
    SLLICENSINGSTATUS eStatus;
    DWORD dwGraceTime;
    DWORD dwTotalGraceDays;
    HRESULT hrReason;
    UINT64 qwValidityExpiration;
} SL_LICENSING_STATUS;

#define SL_E_LICENSE_FILE_NOT_INSTALLED ((HRESULT)0xC004F011L)
#define SL_E_VALUE_NOT_FOUND            ((HRESULT)0xC004F012L)
#define SL_E_RIGHT_NOT_GRANTED          ((HRESULT)0xC004F013L)
#define SL_E_PKEY_NOT_INSTALLED         ((HRESULT)0xC004F014L)
#define SL_E_PRODUCT_SKU_NOT_INSTALLED  ((HRESULT)0xC004F015L)
#define SL_E_NOT_SUPPORTED              ((HRESULT)0xC004F016L)

HRESULT WINAPI SLOpen(_Out_ HSLC *phSLC);
HRESULT WINAPI SLClose(_In_ HSLC hSLC);
HRESULT WINAPI SLInstallLicense(_In_ HSLC hSLC, _In_ UINT cbLicenseBlob, _In_reads_bytes_(cbLicenseBlob) const BYTE *pbLicenseBlob, _Out_ SLID *pLicenseFileId);
HRESULT WINAPI SLUninstallLicense(_In_ HSLC hSLC, _In_ const SLID *pLicenseFileId);
HRESULT WINAPI SLGetSLIDList(_In_ HSLC hSLC, _In_ SLIDTYPE eQueryIdType, _In_opt_ const SLID *pQueryId, _In_ SLIDTYPE eReturnIdType, _Out_ UINT *pnReturnIds, _Outptr_result_buffer_(*pnReturnIds) SLID **ppReturnIds);
HRESULT WINAPI SLGetLicense(_In_ HSLC hSLC, _In_ const SLID *pLicenseFileId, _Out_ UINT *pcbLicenseFile, _Outptr_result_bytebuffer_(*pcbLicenseFile) PBYTE *ppbLicenseFile);
HRESULT WINAPI SLGetLicenseFileId(_In_ HSLC hSLC, _In_ UINT cbLicenseBlob, _In_reads_bytes_(cbLicenseBlob) const BYTE *pbLicenseBlob, _Out_ SLID *pLicenseFileId);

#ifdef __cplusplus
}
#endif

#endif /* _SLPUBLIC_H_ */
