@ stdcall SLActivateProduct(ptr ptr long ptr ptr wstr long) sppc.SLActivateProduct
@ stdcall SLClose(ptr) sppc.SLClose
@ stdcall SLConsumeRight(ptr ptr ptr wstr ptr) sppc.SLConsumeRight
@ stdcall SLDepositMigrationBlob(ptr long ptr ptr ptr) sppc.SLDepositMigrationBlob
@ stdcall SLGetInstalledProductKeyIds(ptr ptr ptr ptr) sppc.SLGetInstalledProductKeyIds
@ stdcall SLGetLicense(ptr ptr ptr ptr) sppc.SLGetLicense
@ stdcall SLGetLicenseFileId(ptr long ptr ptr) sppc.SLGetLicenseFileId
@ stdcall SLGetLicenseInformation(ptr ptr wstr ptr ptr ptr) sppc.SLGetLicenseInformation
@ stdcall SLGetLicensingStatusInformation(ptr ptr ptr wstr ptr ptr) sppc.SLGetLicensingStatusInformation
@ stdcall SLGetPKeyInformation(ptr ptr wstr ptr ptr ptr) sppc.SLGetPKeyInformation
@ stdcall SLGetPolicyInformationDWORD(ptr wstr ptr) sppc.SLGetPolicyInformationDWORD
@ stdcall SLGetSLIDList(ptr long ptr long ptr ptr) sppc.SLGetSLIDList
@ stdcall SLGetWindowsInformation(wstr ptr ptr ptr)
@ stdcall SLGetWindowsInformationDWORD(wstr ptr) sppc.SLGetWindowsInformationDWORD
@ stdcall SLInstallLicense(ptr long ptr ptr) sppc.SLInstallLicense
@ stdcall SLInstallProofOfPurchase(ptr wstr wstr long ptr ptr) sppc.SLInstallProofOfPurchase
@ stdcall SLOpen(ptr) sppc.SLOpen
@ stdcall SLPersistApplicationPolicies(ptr ptr ptr) sppc.SLPersistApplicationPolicies
@ stdcall SLPersistRTSPayloadOverride(ptr ptr wstr) sppc.SLPersistRTSPayloadOverride
@ stdcall SLUninstallLicense(ptr ptr) sppc.SLUninstallLicense
@ stdcall SLUninstallProofOfPurchase(ptr ptr) sppc.SLUninstallProofOfPurchase
