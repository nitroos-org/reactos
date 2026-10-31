# Forward-only module: exports of Windows 10 kernel.appcore.dll (names checked on the reference VM) whose implementation
# lives in kernel32, kernelbase_ros. Every entry copies the version/arch gate of the target spec line; stubs are not forwarded.
# Regenerate when a target spec gains or loses an export.
@ stdcall AppContainerFreeMemory(ptr) kernelbase_ros.AppContainerFreeMemory
@ stdcall AppContainerLookupMoniker(ptr ptr) kernelbase_ros.AppContainerLookupMoniker
@ stdcall AppContainerRegisterSid(ptr wstr wstr) kernelbase_ros.AppContainerRegisterSid
@ stdcall AppContainerUnregisterSid(ptr) kernelbase_ros.AppContainerUnregisterSid
@ stdcall ClosePackageInfo(ptr) kernel32.ClosePackageInfo
@ stdcall FindPackagesByPackageFamily(wstr long ptr ptr ptr ptr ptr) kernel32.FindPackagesByPackageFamily
@ stdcall FormatApplicationUserModelId(wstr wstr ptr ptr) kernel32.FormatApplicationUserModelId
@ stdcall GetApplicationUserModelId(long ptr ptr) kernel32.GetApplicationUserModelId
@ stdcall GetApplicationUserModelIdFromToken(long ptr ptr) kernel32.GetApplicationUserModelIdFromToken
@ stdcall GetCurrentApplicationUserModelId(ptr ptr) kernel32.GetCurrentApplicationUserModelId
@ stdcall GetCurrentPackageFamilyName(ptr ptr) kernel32.GetCurrentPackageFamilyName
@ stdcall GetCurrentPackageFullName(ptr ptr) kernel32.GetCurrentPackageFullName
@ stdcall GetCurrentPackageId(ptr ptr) kernel32.GetCurrentPackageId
@ stdcall GetCurrentPackageInfo(long ptr ptr ptr) kernel32.GetCurrentPackageInfo
@ stdcall GetCurrentPackagePath(ptr ptr) kernel32.GetCurrentPackagePath
@ stdcall GetPackageFamilyName(long ptr ptr) kernel32.GetPackageFamilyName
@ stdcall GetPackageFamilyNameFromToken(long ptr ptr) kernel32.GetPackageFamilyNameFromToken
@ stdcall GetPackageFullName(long ptr ptr) kernel32.GetPackageFullName
@ stdcall GetPackageFullNameFromToken(long ptr ptr) kernel32.GetPackageFullNameFromToken
@ stdcall GetPackageId(long ptr ptr) kernel32.GetPackageId
@ stdcall GetPackageInfo(ptr long ptr ptr ptr) kernel32.GetPackageInfo
@ stdcall GetPackagePath(ptr long ptr ptr) kernel32.GetPackagePath
@ stdcall GetPackagePathByFullName(wstr ptr ptr) kernel32.GetPackagePathByFullName
@ stdcall GetPackagesByPackageFamily(wstr ptr ptr ptr ptr) kernel32.GetPackagesByPackageFamily
@ stdcall OpenPackageInfoByFullName(wstr long ptr) kernel32.OpenPackageInfoByFullName
@ stdcall PackageFamilyNameFromFullName(wstr ptr ptr) kernel32.PackageFamilyNameFromFullName
@ stdcall PackageFamilyNameFromId(ptr ptr ptr) kernel32.PackageFamilyNameFromId
@ stdcall PackageFullNameFromId(ptr ptr ptr) kernel32.PackageFullNameFromId
@ stdcall PackageIdFromFullName(wstr long ptr ptr) kernel32.PackageIdFromFullName
@ stdcall PackageNameAndPublisherIdFromFamilyName(wstr ptr ptr ptr ptr) kernel32.PackageNameAndPublisherIdFromFamilyName
@ stdcall ParseApplicationUserModelId(wstr ptr ptr ptr ptr) kernel32.ParseApplicationUserModelId
@ stdcall VerifyApplicationUserModelId(wstr) kernel32.VerifyApplicationUserModelId
@ stdcall VerifyPackageFamilyName(wstr) kernel32.VerifyPackageFamilyName
@ stdcall VerifyPackageFullName(wstr) kernel32.VerifyPackageFullName
@ stdcall VerifyPackageId(ptr) kernel32.VerifyPackageId
@ stdcall VerifyPackageRelativeApplicationId(wstr) kernel32.VerifyPackageRelativeApplicationId
