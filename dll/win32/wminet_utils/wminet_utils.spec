@ stdcall ResetSecurity(ptr) wmi_ResetSecurity
@ stdcall SetSecurity(ptr ptr) wmi_SetSecurity
@ stdcall BlessIWbemServices(ptr wstr ptr wstr long long) wmi_BlessIWbemServices
@ stdcall BlessIWbemServicesObject(ptr wstr ptr wstr long long) wmi_BlessIWbemServicesObject
@ stdcall GetPropertyHandle(long ptr wstr ptr ptr) wmi_GetPropertyHandle
@ stdcall WritePropertyValue(long ptr long long ptr) wmi_WritePropertyValue
@ stdcall Clone(long ptr ptr) wmi_Clone
@ stdcall VerifyClientKey() wmi_VerifyClientKey
@ stdcall GetQualifierSet(long ptr ptr) wmi_GetQualifierSet
@ stdcall Get(long ptr wstr long ptr ptr ptr) wmi_Get
@ stdcall Put(long ptr wstr long ptr long) wmi_Put
@ stdcall Delete(long ptr wstr) wmi_Delete
@ stdcall GetNames(long ptr wstr long ptr ptr) wmi_GetNames
@ stdcall BeginEnumeration(long ptr long) wmi_BeginEnumeration
@ stdcall Next(long ptr long ptr ptr ptr ptr) wmi_Next
@ stdcall EndEnumeration(long ptr) wmi_EndEnumeration
@ stdcall GetPropertyQualifierSet(long ptr wstr ptr) wmi_GetPropertyQualifierSet
@ stdcall GetObjectText(long ptr long ptr) wmi_GetObjectText
@ stdcall SpawnDerivedClass(long ptr long ptr) wmi_SpawnDerivedClass
@ stdcall SpawnInstance(long ptr long ptr) wmi_SpawnInstance
@ stdcall CompareTo(long ptr long ptr) wmi_CompareTo
@ stdcall GetPropertyOrigin(long ptr wstr ptr) wmi_GetPropertyOrigin
@ stdcall InheritsFrom(long ptr wstr) wmi_InheritsFrom
@ stdcall GetMethod(long ptr wstr long ptr ptr) wmi_GetMethod
@ stdcall PutMethod(long ptr wstr long ptr ptr) wmi_PutMethod
@ stdcall DeleteMethod(long ptr wstr) wmi_DeleteMethod
@ stdcall BeginMethodEnumeration(long ptr long) wmi_BeginMethodEnumeration
@ stdcall NextMethod(long ptr long ptr ptr ptr) wmi_NextMethod
@ stdcall EndMethodEnumeration(long ptr) wmi_EndMethodEnumeration
@ stdcall GetMethodQualifierSet(long ptr wstr ptr) wmi_GetMethodQualifierSet
@ stdcall GetMethodOrigin(long ptr wstr ptr) wmi_GetMethodOrigin
@ stdcall QualifierSet_Get(long ptr wstr long ptr ptr) wmi_QualifierSet_Get
@ stdcall QualifierSet_Put(long ptr wstr ptr long) wmi_QualifierSet_Put
@ stdcall QualifierSet_Delete(long ptr wstr) wmi_QualifierSet_Delete
@ stdcall QualifierSet_GetNames(long ptr long ptr) wmi_QualifierSet_GetNames
@ stdcall QualifierSet_BeginEnumeration(long ptr long) wmi_QualifierSet_BeginEnumeration
@ stdcall QualifierSet_Next(long ptr long ptr ptr ptr) wmi_QualifierSet_Next
@ stdcall QualifierSet_EndEnumeration(long ptr) wmi_QualifierSet_EndEnumeration
@ stdcall GetCurrentApartmentType(long ptr ptr) wmi_GetCurrentApartmentType
@ stdcall GetDemultiplexedStub(ptr long ptr) wmi_GetDemultiplexedStub
@ stdcall CreateInstanceEnumWmi(wstr long ptr ptr long long ptr wstr ptr wstr) wmi_CreateInstanceEnumWmi
@ stdcall CreateClassEnumWmi(wstr long ptr ptr long long ptr wstr ptr wstr) wmi_CreateClassEnumWmi
@ stdcall ExecQueryWmi(wstr wstr long ptr ptr long long ptr wstr ptr wstr) wmi_ExecQueryWmi
@ stdcall ExecNotificationQueryWmi(wstr wstr long ptr ptr long long ptr wstr ptr wstr) wmi_ExecNotificationQueryWmi
@ stdcall PutInstanceWmi(ptr long ptr ptr long long ptr wstr ptr wstr) wmi_PutInstanceWmi
@ stdcall PutClassWmi(ptr long ptr ptr long long ptr wstr ptr wstr) wmi_PutClassWmi
@ stdcall CloneEnumWbemClassObject(ptr long long ptr wstr ptr wstr) wmi_CloneEnumWbemClassObject
@ stdcall ConnectServerWmi(wstr wstr ptr wstr long wstr ptr ptr long long) wmi_ConnectServerWmi
@ stdcall GetErrorInfo() wmi_GetErrorInfo
@ stdcall Initialize(long) wmi_Initialize
