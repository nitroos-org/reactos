# Forward-only module: exports of Windows 10 sechost.dll (names checked on the reference VM) whose implementation
# lives in advapi32. Every entry copies the version/arch gate of the target spec line; stubs are not forwarded.
# Regenerate when a target spec gains or loses an export.
@ stdcall -version=0x600+ AuditEnumerateCategories(ptr ptr) advapi32.AuditEnumerateCategories
@ stdcall -version=0x600+ AuditEnumerateSubCategories(ptr long ptr ptr) advapi32.AuditEnumerateSubCategories
@ stdcall -version=0x600+ AuditFree(ptr) advapi32.AuditFree
@ stdcall -version=0x600+ AuditLookupCategoryNameW(ptr ptr) advapi32.AuditLookupCategoryNameW
@ stdcall -version=0x600+ AuditLookupSubCategoryNameW(ptr ptr) advapi32.AuditLookupSubCategoryNameW
@ stdcall ChangeServiceConfig2A(long long ptr) advapi32.ChangeServiceConfig2A
@ stdcall ChangeServiceConfig2W(long long ptr) advapi32.ChangeServiceConfig2W
@ stdcall ChangeServiceConfigA(long long long long wstr str ptr str str str str) advapi32.ChangeServiceConfigA
@ stdcall ChangeServiceConfigW(long long long long wstr wstr ptr wstr wstr wstr wstr) advapi32.ChangeServiceConfigW
@ stdcall CloseServiceHandle(long) advapi32.CloseServiceHandle
@ stdcall CloseTrace(int64) advapi32.CloseTrace
@ stdcall ControlService(long long ptr) advapi32.ControlService
@ stdcall -version=0x600+ ControlServiceExA(long long long ptr) advapi32.ControlServiceExA
@ stdcall -version=0x600+ ControlServiceExW(long long long ptr) advapi32.ControlServiceExW
@ stdcall -version=0x502 ControlTraceA(double str ptr long) advapi32.ControlTraceA
@ stdcall -version=0x600+ ControlTraceA(double str ptr long) advapi32.ControlTraceA
@ stdcall -version=0x502 ControlTraceW(double wstr ptr long) advapi32.ControlTraceW
@ stdcall -version=0x600+ ControlTraceW(double wstr ptr long) advapi32.ControlTraceW
@ stdcall ConvertSecurityDescriptorToStringSecurityDescriptorW(ptr long long ptr ptr) advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
@ stdcall ConvertSidToStringSidW(ptr ptr) advapi32.ConvertSidToStringSidW
@ stdcall ConvertStringSecurityDescriptorToSecurityDescriptorW(wstr long ptr ptr) advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
@ stdcall ConvertStringSidToSidW(ptr ptr) advapi32.ConvertStringSidToSidW
@ stdcall CreateServiceA(long str str long long long long str str ptr str str str) advapi32.CreateServiceA
@ stdcall CreateServiceW(long wstr wstr long long long long wstr wstr ptr wstr wstr wstr) advapi32.CreateServiceW
@ stdcall CredDeleteA(str long long) advapi32.CredDeleteA
@ stdcall CredDeleteW(wstr long long) advapi32.CredDeleteW
@ stdcall CredEnumerateA(str long ptr ptr) advapi32.CredEnumerateA
@ stdcall CredEnumerateW(wstr long ptr ptr) advapi32.CredEnumerateW
@ stdcall CredFree(ptr) advapi32.CredFree
@ stdcall CredGetSessionTypes(long ptr) advapi32.CredGetSessionTypes
@ stdcall CredIsMarshaledCredentialW(wstr) advapi32.CredIsMarshaledCredentialW
@ stdcall CredMarshalCredentialA(long ptr str) advapi32.CredMarshalCredentialA
@ stdcall CredMarshalCredentialW(long ptr wstr) advapi32.CredMarshalCredentialW
@ stdcall CredReadA(str long long ptr) advapi32.CredReadA
@ stdcall CredReadDomainCredentialsA(ptr long ptr ptr) advapi32.CredReadDomainCredentialsA
@ stdcall CredReadDomainCredentialsW(ptr long ptr ptr) advapi32.CredReadDomainCredentialsW
@ stdcall CredReadW(wstr long long ptr) advapi32.CredReadW
@ stdcall CredUnmarshalCredentialA(str ptr ptr) advapi32.CredUnmarshalCredentialA
@ stdcall CredUnmarshalCredentialW(wstr ptr ptr) advapi32.CredUnmarshalCredentialW
@ stdcall CredWriteA(ptr long) advapi32.CredWriteA
@ stdcall CredWriteW(ptr long) advapi32.CredWriteW
@ stdcall DeleteService(long) advapi32.DeleteService
@ stdcall -version=0x601+ EnableTraceEx2(int64 ptr long long int64 int64 long ptr) advapi32.EnableTraceEx2
@ stdcall EnumDependentServicesW(long long ptr long ptr ptr) advapi32.EnumDependentServicesW
@ stdcall EnumServicesStatusExW(long long long long ptr long ptr ptr ptr wstr) advapi32.EnumServicesStatusExW
@ stdcall GetServiceDisplayNameW(ptr wstr ptr ptr) advapi32.GetServiceDisplayNameW
@ stdcall GetServiceKeyNameW(long wstr ptr ptr) advapi32.GetServiceKeyNameW
@ stdcall I_QueryTagInformation(ptr long ptr) advapi32.I_QueryTagInformation
@ stdcall I_ScIsSecurityProcess() advapi32.I_ScIsSecurityProcess
@ stdcall I_ScPnPGetServiceName(ptr wstr long) advapi32.I_ScPnPGetServiceName
@ stdcall I_ScSendPnPMessage(ptr long long ptr) advapi32.I_ScSendPnPMessage
@ stdcall I_ScSetServiceBitsA(ptr long long long str) advapi32.I_ScSetServiceBitsA
@ stdcall I_ScSetServiceBitsW(ptr long long long wstr) advapi32.I_ScSetServiceBitsW
@ stdcall LsaAddAccountRights(ptr ptr ptr long) advapi32.LsaAddAccountRights
@ stdcall LsaClose(ptr) advapi32.LsaClose
@ stdcall LsaCreateSecret(ptr ptr long ptr) advapi32.LsaCreateSecret
@ stdcall LsaDelete(ptr) advapi32.LsaDelete
@ stdcall LsaEnumerateAccountRights(ptr ptr ptr ptr) advapi32.LsaEnumerateAccountRights
@ stdcall LsaEnumerateAccountsWithUserRight(ptr ptr ptr ptr) advapi32.LsaEnumerateAccountsWithUserRight
@ stdcall LsaFreeMemory(ptr) advapi32.LsaFreeMemory
@ stdcall LsaLookupNames2(ptr long long ptr ptr ptr) advapi32.LsaLookupNames2
@ stdcall LsaLookupSids(ptr long ptr ptr ptr) advapi32.LsaLookupSids
@ stdcall -version=0x600+ LsaLookupSids2(ptr long long ptr ptr ptr) advapi32.LsaLookupSids2
@ stdcall LsaOpenPolicy(ptr ptr long ptr) advapi32.LsaOpenPolicy
@ stdcall LsaOpenSecret(ptr ptr long ptr) advapi32.LsaOpenSecret
@ stdcall LsaQueryInformationPolicy(ptr long ptr) advapi32.LsaQueryInformationPolicy
@ stdcall LsaQuerySecret(ptr ptr ptr ptr ptr) advapi32.LsaQuerySecret
@ stdcall LsaRemoveAccountRights(ptr ptr long ptr long) advapi32.LsaRemoveAccountRights
@ stdcall LsaRetrievePrivateData(ptr ptr ptr) advapi32.LsaRetrievePrivateData
@ stdcall LsaSetInformationPolicy(ptr long ptr) advapi32.LsaSetInformationPolicy
@ stdcall LsaSetSecret(ptr ptr ptr) advapi32.LsaSetSecret
@ stdcall LsaStorePrivateData(ptr ptr ptr) advapi32.LsaStorePrivateData
@ stdcall OpenSCManagerA(str str long) advapi32.OpenSCManagerA
@ stdcall OpenSCManagerW(wstr wstr long) advapi32.OpenSCManagerW
@ stdcall OpenServiceA(long str long) advapi32.OpenServiceA
@ stdcall OpenServiceW(long wstr long) advapi32.OpenServiceW
@ stdcall OpenTraceW(ptr) advapi32.OpenTraceW
@ stdcall -version=0x600+ PerfCreateInstance(long ptr wstr long) advapi32.PerfCreateInstance
@ stdcall -version=0x600+ PerfDeleteInstance(long ptr) advapi32.PerfDeleteInstance
@ stdcall -version=0x600+ PerfSetCounterRefValue(long ptr long ptr) advapi32.PerfSetCounterRefValue
@ stdcall -version=0x600+ PerfSetCounterSetInfo(long ptr long) advapi32.PerfSetCounterSetInfo
@ stdcall -version=0x600+ PerfStartProvider(ptr ptr ptr) advapi32.PerfStartProvider
@ stdcall -version=0x600+ PerfStartProviderEx(ptr ptr ptr) advapi32.PerfStartProviderEx
@ stdcall -version=0x600+ PerfStopProvider(long) advapi32.PerfStopProvider
@ stdcall ProcessTrace(ptr long ptr ptr) advapi32.ProcessTrace
@ stdcall -version=0x502 QueryAllTracesA(ptr long ptr) advapi32.QueryAllTracesA
@ stdcall -version=0x600+ QueryAllTracesA(ptr long ptr) advapi32.QueryAllTracesA
@ stdcall -version=0x502 QueryAllTracesW(ptr long ptr) advapi32.QueryAllTracesW
@ stdcall -version=0x600+ QueryAllTracesW(ptr long ptr) advapi32.QueryAllTracesW
@ stdcall QueryServiceConfig2A(long long ptr long ptr) advapi32.QueryServiceConfig2A
@ stdcall QueryServiceConfig2W(long long ptr long ptr) advapi32.QueryServiceConfig2W
@ stdcall QueryServiceConfigA(long ptr long ptr) advapi32.QueryServiceConfigA
@ stdcall QueryServiceConfigW(long ptr long ptr) advapi32.QueryServiceConfigW
@ stdcall QueryServiceObjectSecurity(long long ptr long ptr) advapi32.QueryServiceObjectSecurity
@ stdcall QueryServiceStatus(long ptr) advapi32.QueryServiceStatus
@ stdcall QueryServiceStatusEx(long long ptr long ptr) advapi32.QueryServiceStatusEx
@ stdcall RegisterServiceCtrlHandlerA(str ptr) advapi32.RegisterServiceCtrlHandlerA
@ stdcall RegisterServiceCtrlHandlerExA(str ptr ptr) advapi32.RegisterServiceCtrlHandlerExA
@ stdcall RegisterServiceCtrlHandlerExW(wstr ptr ptr) advapi32.RegisterServiceCtrlHandlerExW
@ stdcall RegisterServiceCtrlHandlerW(wstr ptr) advapi32.RegisterServiceCtrlHandlerW
@ stdcall RegisterTraceGuidsA(ptr ptr ptr long ptr str str ptr) advapi32.RegisterTraceGuidsA
@ stdcall SetServiceObjectSecurity(long long ptr) advapi32.SetServiceObjectSecurity
@ stdcall SetServiceStatus(long long) advapi32.SetServiceStatus
@ stdcall StartServiceA(long long ptr) advapi32.StartServiceA
@ stdcall StartServiceCtrlDispatcherA(ptr) advapi32.StartServiceCtrlDispatcherA
@ stdcall StartServiceCtrlDispatcherW(ptr) advapi32.StartServiceCtrlDispatcherW
@ stdcall StartServiceW(long long ptr) advapi32.StartServiceW
@ stdcall -version=0x502 StartTraceA(ptr str ptr) advapi32.StartTraceA
@ stdcall -version=0x600+ StartTraceA(ptr str ptr) advapi32.StartTraceA
@ stdcall -version=0x502 StartTraceW(ptr wstr ptr) advapi32.StartTraceW
@ stdcall -version=0x600+ StartTraceW(ptr wstr ptr) advapi32.StartTraceW
@ stdcall -version=0x502 StopTraceW(double wstr ptr) advapi32.StopTraceW
@ stdcall -version=0x600+ StopTraceW(double wstr ptr) advapi32.StopTraceW
