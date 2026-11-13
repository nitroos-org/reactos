
include_directories(include)

#
# subdirectories containing special-purpose drivers
#
add_subdirectory(example)
add_subdirectory(fltmgr)
add_subdirectory(hidparse)
add_subdirectory(kernel32)
add_subdirectory(ntos_cc)
add_subdirectory(ntos_cm)
add_subdirectory(ntos_io)
add_subdirectory(ntos_ke/KeTrapFrame)
add_subdirectory(ntos_mm)
add_subdirectory(ntos_po)
add_subdirectory(tcpip)

list(APPEND COMMON_SOURCE
    example/GuardedMemory.c
    rtl/RtlAvlTree.c
    rtl/RtlException.c
    ../apitests/rtl/RtlIntSafe.c
    rtl/RtlMemory.c
    rtl/RtlMemoryOps.c
    rtl/RtlRegistry.c
    rtl/RtlSplayTree.c
    rtl/RtlStack.c
    rtl/RtlStrSafe.c
    rtl/RtlUnicodeString.c)

if(ARCH STREQUAL "i386")

elseif(ARCH STREQUAL "amd64")
    add_asm_files(kmtest_common_asm ../apitests/rtl/amd64/RtlCaptureContext-asm.s)
    list(APPEND COMMON_SOURCE
        ../apitests/rtl/amd64/RtlCaptureContext.c
        ${kmtest_common_asm}
    )
endif()

#
# kmtest_drv.sys driver
#
list(APPEND KMTEST_DRV_SOURCE
    kmtest_drv/guid.c
    kmtest_drv/kmtest_drv.c
    kmtest_drv/structs.c
    kmtest_drv/testlist.c
    kmtest_drv/vm_detect.c

    example/Example.c
    example/KernelType.c
    hal/HalDma.c
    hal/HalDmaBounce.c
    hal/HalDmaSgWait.c
    hal/HalSystemInfo.c
    npfs/NpfsConnect.c
    npfs/NpfsCreate.c
    npfs/NpfsFileInfo.c
    npfs/NpfsHelpers.c
    npfs/NpfsReadWrite.c
    npfs/NpfsVolumeInfo.c
    novp_fsrtl/FsRtlRemoveDotsFromPath.c
    ntos_cc/CcPurgeCacheSection.c
    ntos_cm/CmAclAudit.c
    ntos_cm/CmRename.c
    ntos_cm/CmSkStore.c
    ntos_cm/CmSecurity.c
    ntos_ex/ExCallback.c
    ntos_ex/ExDoubleList.c
    ntos_ex/ExFastMutex.c
    ntos_ex/ExHardError.c
    ntos_ex/ExInterlocked.c
    ntos_ex/ExInterlockedIpi.c
    ntos_ex/ExAllocatePool2.c
    ntos_ex/ExLookasideListEx.c
    ntos_ex/ExPools.c
    ntos_ex/ExPushLock.c
    ntos_ex/ExSListPopFault.c
    ntos_ex/ExResource.c
    ntos_ex/ExSequencedList.c
    ntos_ex/ExSingleList.c
    ntos_ex/ExStubHit.c
    ntos_ex/ExTimer.c
    ntos_ex/ExTimerResolution.c
    ntos_ex/ExUuid.c
    ntos_ex/ExWorkQueue.c
    ntos_ex/ProbeCapture.c
    ntos_fsrtl/FsRtlDissect.c
    ntos_fsrtl/FsRtlEcp.c
    ntos_fsrtl/FsRtlExpression.c
    ntos_fsrtl/FsRtlFileLock.c
    ntos_fsrtl/FsRtlLegal.c
    ntos_fsrtl/FsRtlMcb.c
    ntos_fsrtl/FsRtlNotify.c
    ntos_fsrtl/FsRtlPerStreamContext.c
    ntos_fsrtl/FsRtlTunnel.c
    ntos_io/IoCreateFile.c
    ntos_io/IoDeviceInterface.c
    ntos_io/IoDeviceProperty.c
    ntos_io/IoEvent.c
    ntos_io/IoFilesystem.c
    ntos_io/IoInterrupt.c
    ntos_io/IoIrp.c
    ntos_io/KsCapture.c
    ntos_io/IoMdl.c
    ntos_io/IoNonFileName.c
    ntos_io/IoCreateDeviceSecure.c
    ntos_io/IoCreateSystemThread.c
    ntos_io/IoValidateDeviceIoControlAccess.c
    ntos_io/IoWMINotification.c
    ntos_io/IoPnpEventQueue.c
    ntos_io/IoVolume.c
    ntos_kd/KdSystemDebugControl.c
    ntos_ke/KeProcessorGroups.c
    ntos_ke/KeApc.c
    ntos_ke/KeApcDelivery.c
    ntos_ke/KeBugCheckCallback.c
    ntos_ke/KeDelayExecution.c
    ntos_ke/KeDevQueue.c
    ntos_ke/KeClockTime.c
    ntos_ke/KeDpc.c
    ntos_ke/KeEvent.c
    ntos_ke/KeFastFail.c
    ntos_ke/KeGeneralProtection.c
    ntos_ke/KeFloatPointState.c
    ntos_ke/KeGenericCallDpc.c
    ntos_ke/KeGuardedMutex.c
    ntos_ke/KeFreezeDpc.c
    ntos_ke/KeIrql.c
    ntos_ke/KeMutex.c
    ntos_ke/KePriority.c
    ntos_ke/KeProfile.c
    ntos_ke/KeProcessor.c
    ntos_ke/KeQpc.c
    ntos_ke/KeSpinLock.c
    ntos_ke/KeSystemCall32.c
    ntos_ke/KeTimer.c
    ntos_mm/MmMapViewAligned.c
    ntos_mm/MmMdl.c
    ntos_mm/MmCommitKernelFail.c
    ntos_mm/MmContiguousStandby.c
    ntos_mm/MmFaultFileHeld.c
    ntos_mm/MmOomRetry.c
    ntos_mm/MmReservedMapping.c
    ntos_mm/MmSection.c
    ntos_mm/MmSessionSpace.c
    ntos_mm/MmSessionImage.c
    ntos_mm/MmSessionTables.c
    ntos_mm/MmCodeProtect.c
    ntos_mm/MmSpecialPool.c
    ntos_mm/MmIrqlFault.c
    ntos_mm/ZwAllocateVirtualMemory.c
    ntos_mm/ZwCreateSection.c
    ntos_mm/ZwMapViewOfSection.c
    ntos_ob/ObHandle.c
    ntos_ob/ObWithTag.c
    ntos_ob/ObQuery.c
    ntos_ob/ObReference.c
    ntos_ob/ObSecurity.c
    ntos_ob/ObSymbolicLink.c
    ntos_ob/ObType.cpp
    ntos_ob/ObTypes.cpp
    ntos_ob/ObWait.c
    ntos_ps/PsNotify.c
    ntos_ps/PsQuota.c
    ntos_ps/PsQuotaLimited.c
    ntos_ps/PsQuotaSwitchRace.c
    ntos_se/SeAutoInherit.c
    ntos_se/SeHelpers.c
    ntos_se/SeInheritance.c
    ntos_se/SeLogonSession.c
    ntos_se/SeQueryInfoToken.c
    ntos_se/SeTokenFiltering.c
    rtl/RtlIsValidOemCharacter.c
    rtl/RtlRangeList.c
    ${COMMON_SOURCE}

    kmtest_drv/kmtest_drv.rc)

if(ARCH STREQUAL "i386" OR ARCH STREQUAL "amd64")
    add_asm_files(KMTEST_DRV_ASM
        kmtest_drv/vm_detect.S)
    list(APPEND KMTEST_DRV_SOURCE
        ${KMTEST_DRV_ASM}
        hal/HalIoApic.c
        hal/HalPortIo.c)
endif()

add_library(kmtest_drv MODULE ${KMTEST_DRV_SOURCE})
set_module_type(kmtest_drv kernelmodedriver)
target_link_libraries(kmtest_drv kmtest_printf chkstk memcmp ntoskrnl_vista wdmsec ${PSEH_LIB})
add_importlibs(kmtest_drv ntoskrnl hal ks)
add_dependencies(kmtest_drv bugcodes xdk)
target_compile_definitions(kmtest_drv PRIVATE KMT_KERNEL_MODE NTDDI_VERSION=NTDDI_WS03SP1)
#add_pch(kmtest_drv include/kmt_test.h)
add_rostests_file(TARGET kmtest_drv)

add_library(kmtest_printf
    kmtest_drv/printf_stubs.c
    ${REACTOS_SOURCE_DIR}/sdk/lib/crt/string/strnlen.c
    ${REACTOS_SOURCE_DIR}/sdk/lib/crt/string/wcsnlen.c
    ${REACTOS_SOURCE_DIR}/sdk/lib/crt/printf/streamout.c)
target_compile_definitions(kmtest_printf PRIVATE _LIBCNT_ _USER32_WSPRINTF wctomb=KmtWcToMb)
target_include_directories(kmtest_printf PRIVATE ${REACTOS_SOURCE_DIR}/sdk/lib/crt/include)

#
# kmtest.exe loader application
#

list(APPEND KMTEST_SOURCE
    kmtest/filter.c
    kmtest/fltsupport.c
    kmtest/kmtest.c
    kmtest/service.c
    kmtest/support.c
    kmtest/testlist.c

    example/Example_user.c

    fltmgr/fltmgr_load/fltmgr_user.c
    fltmgr/fltmgr_register/fltmgr_reg_user.c

    hidparse/HidP_user.c
    kernel32/FileAttributes_user.c
    kernel32/FindFile_user.c
    ntos_cc/CcCopyRead_user.c
    ntos_cc/CcCopyWrite_user.c
    ntos_cc/CcZeroData_user.c
    ntos_cc/CcLazyWriteDelete_user.c
    ntos_cc/CcMapData_user.c
    ntos_cc/CcPinMappedData_user.c
    ntos_cc/CcPinRead_user.c
    ntos_cc/CcSetFileSizes_user.c
    ntos_cm/CmFlush_user.c
    ntos_io/IoCreateFile_user.c
    ntos_io/IoCreateFileEx_user.c
    ntos_io/IoDeviceObject_user.c
    ntos_io/IoIs32bitProcess_user.c
    ntos_io/IoReadWrite_user.c
    ntos_kd/NtSystemDebugControl.c
    ntos_ke/KeSystemCall32_user.c
    ntos_ke/KeProfile_user.c
    ntos_ke/KeTrapFrame/KeTrapFrame_user.c
    ntos_mm/MmMapLockedPagesSpecifyCache_user.c
    ntos_mm/MmContiguousStandby_user.c
    ntos_mm/MmPager_user.c
    ntos_mm/MmSpecialPool_user.c
    ntos_mm/NtCreateSection_user.c
    ntos_po/PoIrp_user.c
    tcpip/TcpIp_user.c
    ${COMMON_SOURCE}

    kmtest/kmtest.rc)

if(ARCH STREQUAL "i386")
    add_asm_files(kmtest_trap_asm ntos_ke/KeTrapFrame/KeTrapFrame_i386.S)
    list(APPEND KMTEST_SOURCE ${kmtest_trap_asm})
endif()

if(ARCH STREQUAL "amd64")
    add_asm_files(kmtest_cstar_asm ntos_ke/KeSystemCall32_amd64.S)
    list(APPEND KMTEST_SOURCE ${kmtest_cstar_asm})
endif()

add_executable(kmtest ${KMTEST_SOURCE})
set_module_type(kmtest win32cui)
target_link_libraries(kmtest ${PSEH_LIB})
add_importlibs(kmtest fltlib advapi32 ws2_32 msvcrt kernel32 ntdll)
target_compile_definitions(kmtest PRIVATE KMT_USER_MODE NTDDI_VERSION=NTDDI_WS03SP1)
#add_pch(kmtest include/kmt_test.h)
add_rostests_file(TARGET kmtest)

#
# Group targets
#
add_custom_target(kmtest_drivers)
add_dependencies(kmtest_drivers
    kmtest_drv
    ketrapframe_drv
    example_drv
    hidp_drv
    iocreatefile_drv
    iodeviceobject_drv
    iohelper_drv
    iois32bitprocess_drv
    iois32bitprocess_client
    ioreadwrite_drv
    kernel32_drv
    mmmaplockedpagesspecifycache_drv
    ntcreatesection_drv
    poirp_drv
    tcpip_drv
    cccopyread_drv
    cczerodata_drv
    cmflush_drv
    ccmapdata_drv)

add_custom_target(kmtest_all)
add_dependencies(kmtest_all kmtest_drivers kmtest)
