@ stub HttpAddFragmentToCache
@ stdcall HttpAddUrl(ptr wstr ptr)
@ stdcall HttpAddUrlToUrlGroup(int64 wstr int64 long)
@ stub HttpCreateAppPool
@ stub HttpCreateConfigGroup
@ stub HttpCreateFilter
@ stdcall HttpCreateHttpHandle(ptr long)
@ stdcall HttpCreateRequestQueue(long wstr ptr long ptr)
@ stdcall HttpCreateServerSession(long ptr long)
@ stdcall HttpCreateUrlGroup(int64 ptr long)
@ stub HttpDeleteConfigGroup
@ stdcall HttpDeleteServiceConfiguration(ptr long ptr long ptr)
@ stub HttpFilterAccept
@ stub HttpFilterAppRead
@ stub HttpFilterAppWrite
@ stub HttpFilterAppWriteAndRawRead
@ stub HttpFilterClose
@ stub HttpFilterRawRead
@ stub HttpFilterRawWrite
@ stub HttpFilterRawWriteAndAppRead
@ stub HttpFlushResponseCache
@ stub HttpGetCounters
@ stdcall HttpInitialize(long long ptr)
@ stub HttpOpenAppPool
@ stub HttpOpenControlChannel
@ stub HttpOpenFilter
@ stub HttpQueryAppPoolInformation
@ stub HttpQueryConfigGroupInformation
@ stub HttpQueryControlChannelInformation
@ stdcall HttpQueryServiceConfiguration(ptr long ptr long ptr long ptr ptr)
@ stub HttpReadFragmentFromCache
@ stdcall HttpReceiveClientCertificate(ptr int64 long ptr long ptr ptr)
@ stdcall HttpReceiveHttpRequest(ptr int64 long ptr long ptr ptr)
@ stdcall HttpReceiveRequestEntityBody(ptr int64 long ptr long ptr ptr)
@ stub HttpRemoveAllUrlsFromConfigGroup
@ stdcall HttpRemoveUrl(ptr wstr)
@ stdcall HttpRemoveUrlFromUrlGroup(int64 wstr long)
@ stdcall HttpSendHttpResponse(ptr int64 long ptr ptr ptr ptr long ptr ptr)
@ stub HttpSetAppPoolInformation
@ stub HttpSetConfigGroupInformation
@ stub HttpSetControlChannelInformation
@ stdcall HttpSetServiceConfiguration(ptr long ptr long ptr)
@ stub HttpShutdownAppPool
@ stub HttpShutdownFilter
@ stdcall HttpTerminate(long ptr)
@ stub HttpWaitForDemandStart
@ stdcall HttpWaitForDisconnect(ptr int64 ptr)
@ stdcall HttpWaitForDisconnectEx(ptr int64 long ptr)
@ stdcall HttpCancelHttpRequest(ptr int64 ptr)
@ stdcall HttpCloseRequestQueue(ptr)
@ stdcall HttpCloseServerSession(int64)
@ stdcall HttpCloseUrlGroup(int64)
@ stub HttpControlService
@ stdcall HttpQueryRequestQueueProperty(ptr long ptr long long ptr ptr)
@ stdcall HttpQueryServerSessionProperty(int64 long ptr long ptr)
@ stdcall HttpQueryUrlGroupProperty(int64 long ptr long ptr)
@ stdcall HttpSendResponseEntityBody(ptr int64 long long ptr ptr ptr long ptr ptr)
@ stdcall HttpSetRequestQueueProperty(ptr long ptr long long ptr)
@ stdcall HttpSetServerSessionProperty(int64 long ptr long)
@ stdcall HttpSetUrlGroupProperty(int64 long ptr long)
@ stdcall HttpShutdownRequestQueue(ptr)
