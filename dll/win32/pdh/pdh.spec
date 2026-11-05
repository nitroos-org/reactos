1 stub PdhPlaGetLogFileNameA
@ stub PdhAdd009CounterA
@ stub PdhAdd009CounterW
@ stdcall PdhAddCounterA(ptr str long ptr)
@ stdcall PdhAddCounterW(ptr wstr long ptr)
@ stdcall PdhAddEnglishCounterA(ptr str long ptr)
@ stdcall PdhAddEnglishCounterW(ptr wstr long ptr)
@ stdcall PdhBindInputDataSourceA(ptr str)
@ stdcall PdhBindInputDataSourceW(ptr wstr)
@ stub PdhBrowseCountersA
@ stub PdhBrowseCountersHA
@ stub PdhBrowseCountersHW
@ stub PdhBrowseCountersW
@ stdcall PdhCalculateCounterFromRawValue(ptr long ptr ptr ptr)
@ stdcall PdhCloseLog(ptr long)
@ stdcall PdhCloseQuery(ptr)
@ stdcall PdhCollectQueryData(ptr)
@ stdcall PdhCollectQueryDataWithTime(ptr ptr)
@ stdcall PdhCollectQueryDataEx(ptr long ptr)
@ stdcall PdhComputeCounterStatistics(ptr long long long ptr ptr)
@ stdcall PdhConnectMachineA(str)
@ stdcall PdhConnectMachineW(wstr)
@ stub PdhCreateSQLTablesA
@ stub PdhCreateSQLTablesW
@ stub PdhEnumLogSetNamesA
@ stub PdhEnumLogSetNamesW
@ stdcall PdhEnumMachinesA(str ptr ptr)
@ stdcall PdhEnumMachinesHA(ptr ptr ptr)
@ stdcall PdhEnumMachinesHW(ptr ptr ptr)
@ stdcall PdhEnumMachinesW(wstr ptr ptr)
@ stdcall PdhEnumObjectItemsA(str str str ptr ptr ptr ptr long long)
@ stdcall PdhEnumObjectItemsHA(ptr str str ptr ptr ptr ptr long long)
@ stdcall PdhEnumObjectItemsHW(ptr wstr wstr ptr ptr ptr ptr long long)
@ stdcall PdhEnumObjectItemsW(wstr wstr wstr ptr ptr ptr ptr long long)
@ stdcall PdhEnumObjectsA(str str ptr ptr long long)
@ stdcall PdhEnumObjectsHA(ptr str ptr ptr long long)
@ stdcall PdhEnumObjectsHW(ptr wstr ptr ptr long long)
@ stdcall PdhEnumObjectsW(wstr wstr ptr ptr long long)
@ stdcall PdhExpandCounterPathA(str ptr ptr)
@ stdcall PdhExpandCounterPathW(wstr ptr ptr)
@ stdcall PdhExpandWildCardPathA(str str ptr ptr long)
@ stdcall PdhExpandWildCardPathHA(ptr str ptr ptr long)
@ stdcall PdhExpandWildCardPathHW(ptr wstr ptr ptr long)
@ stdcall PdhExpandWildCardPathW(wstr wstr ptr ptr long)
@ stdcall PdhFormatFromRawValue(long long ptr ptr ptr ptr)
@ stdcall PdhGetCounterInfoA(ptr long ptr ptr)
@ stdcall PdhGetCounterInfoW(ptr long ptr ptr)
@ stdcall PdhGetCounterTimeBase(ptr ptr)
@ stub PdhGetDataSourceTimeRangeA
@ stub PdhGetDataSourceTimeRangeH
@ stub PdhGetDataSourceTimeRangeW
@ stdcall PdhGetDefaultPerfCounterA(str str str ptr ptr)
@ stdcall PdhGetDefaultPerfCounterHA(ptr str str ptr ptr)
@ stdcall PdhGetDefaultPerfCounterHW(ptr wstr wstr ptr ptr)
@ stdcall PdhGetDefaultPerfCounterW(wstr wstr wstr ptr ptr)
@ stdcall PdhGetDefaultPerfObjectA(str str ptr ptr)
@ stdcall PdhGetDefaultPerfObjectHA(ptr str ptr ptr)
@ stdcall PdhGetDefaultPerfObjectHW(ptr wstr ptr ptr)
@ stdcall PdhGetDefaultPerfObjectW(wstr wstr ptr ptr)
@ stdcall PdhGetDllVersion(ptr)
@ stdcall PdhGetFormattedCounterArrayA(ptr long ptr ptr ptr)
@ stdcall PdhGetFormattedCounterArrayW(ptr long ptr ptr ptr)
@ stdcall PdhGetFormattedCounterValue(ptr long ptr ptr)
@ stub PdhGetLogFileSize
@ stdcall PdhGetLogFileTypeA(str ptr)
@ stdcall PdhGetLogFileTypeW(wstr ptr)
@ stub PdhGetLogSetGUID
@ stdcall PdhGetRawCounterArrayA(ptr ptr ptr ptr)
@ stdcall PdhGetRawCounterArrayW(ptr ptr ptr ptr)
@ stdcall PdhGetRawCounterValue(ptr ptr ptr)
@ stdcall PdhIsRealTimeQuery(ptr)
@ stub PdhListLogFileHeaderA
@ stub PdhListLogFileHeaderW
@ stub PdhLogServiceCommandA
@ stub PdhLogServiceCommandW
@ stub PdhLogServiceControlA
@ stub PdhLogServiceControlW
@ stdcall PdhLookupPerfIndexByNameA(str str ptr)
@ stdcall PdhLookupPerfIndexByNameW(wstr wstr ptr)
@ stdcall PdhLookupPerfNameByIndexA(str long ptr ptr)
@ stdcall PdhLookupPerfNameByIndexW(wstr long ptr ptr)
@ stdcall PdhMakeCounterPathA(ptr ptr ptr long)
@ stdcall PdhMakeCounterPathW(ptr ptr ptr long)
@ stub PdhOpenLogA
@ stub PdhOpenLogW
@ stdcall PdhOpenQuery(wstr long ptr) PdhOpenQueryW
@ stdcall PdhOpenQueryA(str long ptr)
@ stdcall PdhOpenQueryH(ptr long ptr)
@ stdcall PdhOpenQueryW(wstr long ptr)
@ stdcall PdhParseCounterPathA(str ptr ptr long)
@ stdcall PdhParseCounterPathW(wstr ptr ptr long)
@ stdcall PdhParseInstanceNameA(str ptr ptr ptr ptr ptr)
@ stdcall PdhParseInstanceNameW(wstr ptr ptr ptr ptr ptr)
@ stub PdhPlaAddItemA
@ stub PdhPlaAddItemW
@ stub PdhPlaCreateA
@ stub PdhPlaCreateW
@ stub PdhPlaDeleteA
@ stub PdhPlaDeleteW
@ stub PdhPlaEnumCollectionsA
@ stub PdhPlaEnumCollectionsW
@ stub PdhPlaGetInfoA
@ stub PdhPlaGetInfoW
@ stub PdhPlaGetLogFileNameW
@ stub PdhPlaGetScheduleA
@ stub PdhPlaGetScheduleW
@ stub PdhPlaRemoveAllItemsA
@ stub PdhPlaRemoveAllItemsW
@ stub PdhPlaScheduleA
@ stub PdhPlaScheduleW
@ stub PdhPlaSetInfoA
@ stub PdhPlaSetInfoW
@ stub PdhPlaSetItemListA
@ stub PdhPlaSetItemListW
@ stub PdhPlaSetRunAsA
@ stub PdhPlaSetRunAsW
@ stub PdhPlaStartA
@ stub PdhPlaStartW
@ stub PdhPlaStopA
@ stub PdhPlaStopW
@ stub PdhPlaValidateInfoA
@ stub PdhPlaValidateInfoW
@ stub PdhReadRawLogRecord
@ stub PdhRelogA
@ stub PdhRelogW
@ stdcall PdhRemoveCounter(ptr)
@ stub PdhSelectDataSourceA
@ stub PdhSelectDataSourceW
@ stdcall PdhSetCounterScaleFactor(ptr long)
@ stdcall PdhSetDefaultRealTimeDataSource(long)
@ stub PdhSetLogSetRunID
@ stub PdhSetQueryTimeRange
@ stdcall PdhTranslate009CounterA(str ptr ptr)
@ stdcall PdhTranslate009CounterW(wstr ptr ptr)
@ stdcall PdhTranslateLocaleCounterA(str ptr ptr)
@ stdcall PdhTranslateLocaleCounterW(wstr ptr ptr)
@ stub PdhUpdateLogA
@ stub PdhUpdateLogFileCatalog
@ stub PdhUpdateLogW
@ stdcall PdhValidatePathA(str)
@ stdcall PdhValidatePathExA(ptr str)
@ stdcall PdhValidatePathExW(ptr wstr)
@ stdcall PdhValidatePathW(wstr)
@ stdcall PdhVbAddCounter(ptr str ptr)
@ stub PdhVbCreateCounterPathList
@ stub PdhVbGetCounterPathElements
@ stub PdhVbGetCounterPathFromList
@ stdcall PdhVbGetDoubleCounterValue(ptr ptr)
@ stub PdhVbGetLogFileSize
@ stub PdhVbGetOneCounterPath
@ stub PdhVbIsGoodStatus
@ stub PdhVbOpenLog
@ stub PdhVbOpenQuery
@ stub PdhVbUpdateLog
@ stub PdhVerifySQLDBA
@ stub PdhVerifySQLDBW
@ stub PdhiPla2003SP1Installed
@ stub PdhiPlaFormatBlanksA
@ stub PdhiPlaFormatBlanksW
@ stub PdhiPlaGetVersion
@ stub PdhiPlaRunAs
@ stub PdhiPlaSetRunAs
@ stub PlaTimeInfoToMilliSeconds
