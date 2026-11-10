@ stdcall SLActivateProduct(ptr ptr long ptr ptr wstr long) sppc.SLActivateProduct
@ stdcall SLClose(ptr) sppc.SLClose
@ stdcall SLConsumeRight(ptr ptr ptr wstr ptr) sppc.SLConsumeRight
@ stdcall SLDepositMigrationBlob(ptr long ptr ptr ptr) sppc.SLDepositMigrationBlob
@ stdcall SLDepositOfflineConfirmationId(ptr ptr wstr wstr) sppc.SLDepositOfflineConfirmationId
@ stdcall SLGenerateOfflineInstallationId(ptr ptr ptr) sppc.SLGenerateOfflineInstallationId
@ stdcall SLGetApplicationInformation(ptr ptr wstr ptr ptr ptr) sppc.SLGetApplicationInformation
@ stdcall -arch=win64 SLGetApplicationPolicy(ptr ptr ptr ptr ptr) sppc.SLGetApplicationPolicy
@ stdcall -arch=win64 SLGetAuthenticationResult(ptr ptr ptr ptr) sppc.SLGetAuthenticationResult
@ stdcall SLGetInstalledProductKeyIds(ptr ptr ptr ptr) sppc.SLGetInstalledProductKeyIds
@ stdcall SLGetLicense(ptr ptr ptr ptr) sppc.SLGetLicense
@ stdcall SLGetLicenseFileId(ptr long ptr ptr) sppc.SLGetLicenseFileId
@ stdcall SLGetLicenseInformation(ptr ptr wstr ptr ptr ptr) sppc.SLGetLicenseInformation
@ stdcall SLGetLicensingStatusInformation(ptr ptr ptr wstr ptr ptr) sppc.SLGetLicensingStatusInformation
@ stdcall -arch=win64 SLGetPKeyId(ptr wstr long ptr ptr) sppc.SLGetPKeyId
@ stdcall SLGetPKeyInformation(ptr ptr wstr ptr ptr ptr) sppc.SLGetPKeyInformation
@ stdcall SLGetPolicyInformation(ptr wstr ptr ptr ptr) sppc.SLGetPolicyInformation
@ stdcall SLGetPolicyInformationDWORD(ptr wstr ptr) sppc.SLGetPolicyInformationDWORD
@ stdcall SLGetProductSkuInformation(ptr ptr wstr ptr ptr ptr) sppc.SLGetProductSkuInformation
@ stdcall SLGetSLIDList(ptr long ptr long ptr ptr) sppc.SLGetSLIDList
@ stdcall SLGetServiceInformation(ptr wstr ptr ptr ptr) sppc.SLGetServiceInformation
@ stdcall SLGetWindowsInformation(wstr ptr ptr ptr)
@ stdcall SLGetWindowsInformationDWORD(wstr ptr) sppc.SLGetWindowsInformationDWORD
@ stdcall SLInstallLicense(ptr long ptr ptr) sppc.SLInstallLicense
@ stdcall SLInstallProofOfPurchase(ptr wstr wstr long ptr ptr) sppc.SLInstallProofOfPurchase
@ stdcall -arch=win64 SLLoadApplicationPolicies(ptr ptr ptr ptr long) sppc.SLLoadApplicationPolicies
@ stdcall SLOpen(ptr) sppc.SLOpen
@ stdcall SLPersistApplicationPolicies(ptr ptr ptr) sppc.SLPersistApplicationPolicies
@ stdcall SLPersistRTSPayloadOverride(ptr ptr wstr) sppc.SLPersistRTSPayloadOverride
@ stdcall -arch=win64 SLReArm(ptr ptr ptr ptr) sppc.SLReArm
@ stdcall -arch=win64 SLRegisterPlugin(ptr ptr ptr ptr) sppc.SLRegisterPlugin
@ stdcall -arch=win64 SLSetAuthenticationData(ptr long ptr ptr ptr) sppc.SLSetAuthenticationData
@ stdcall SLUninstallLicense(ptr ptr) sppc.SLUninstallLicense
@ stdcall SLUninstallProofOfPurchase(ptr ptr) sppc.SLUninstallProofOfPurchase
@ stdcall -arch=win64 SLUnloadApplicationPolicies(ptr ptr) sppc.SLUnloadApplicationPolicies
