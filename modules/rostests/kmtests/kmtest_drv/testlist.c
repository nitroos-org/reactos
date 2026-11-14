/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Kernel-Mode Test Suite kernel-mode test list
 */

#include <kmt_test.h>

KMT_TESTFUNC Test_KeSystemCall32;
KMT_TESTFUNC Test_KeProfile;
KMT_TESTFUNC_WITH_DATA Test_KeProfileWithData;
KMT_TESTFUNC Test_MmMapViewAligned;

KMT_TESTFUNC Test_CcPurgeCacheSection;
KMT_TESTFUNC Test_CmAclAudit;
KMT_TESTFUNC Test_CmRename;
KMT_TESTFUNC Test_CmSkStore;
KMT_TESTFUNC Test_CmSecurity;
KMT_TESTFUNC Test_Example;
KMT_TESTFUNC Test_KsCapture;
KMT_TESTFUNC Test_ExCallback;
KMT_TESTFUNC Test_ExDoubleList;
KMT_TESTFUNC Test_ExFastMutex;
KMT_TESTFUNC Test_ExHardError;
KMT_TESTFUNC Test_ExHardErrorInteractive;
KMT_TESTFUNC Test_ExHardErrorSystemThread;
KMT_TESTFUNC Test_ExInterlocked;
KMT_TESTFUNC Test_ExInterlockedIpi;
KMT_TESTFUNC Test_ExAllocatePool2;
KMT_TESTFUNC Test_ExLookasideListEx;
KMT_TESTFUNC Test_ExPoolCacheAligned;
KMT_TESTFUNC Test_ExPools;
KMT_TESTFUNC Test_ExStubHit;
KMT_TESTFUNC Test_ProbeCapture;
KMT_TESTFUNC Test_ExPushLock;
KMT_TESTFUNC Test_ExResource;
KMT_TESTFUNC Test_ExResourceGrow;
KMT_TESTFUNC Test_ExSListPopFault;
KMT_TESTFUNC Test_ExSequencedList;
KMT_TESTFUNC Test_ExSingleList;
KMT_TESTFUNC Test_ExTimer;
KMT_TESTFUNC Test_ExTimerResolution;
KMT_TESTFUNC Test_ExUuid;
KMT_TESTFUNC Test_ExWorkQueue;
KMT_TESTFUNC Test_FsRtlDissect;
KMT_TESTFUNC Test_FsRtlEcp;
KMT_TESTFUNC Test_FsRtlExpression;
KMT_TESTFUNC Test_FsRtlFileLock;
KMT_TESTFUNC Test_FsRtlFileLockIrp;
KMT_TESTFUNC Test_FsRtlFileLockStress;
KMT_TESTFUNC Test_FsRtlLegal;
KMT_TESTFUNC Test_FsRtlMcb;
KMT_TESTFUNC Test_FsRtlNotify;
KMT_TESTFUNC Test_FsRtlPerStreamContext;
KMT_TESTFUNC Test_FsRtlRemoveDotsFromPath;
KMT_TESTFUNC Test_FsRtlTunnel;
KMT_TESTFUNC Test_HalDma;
#if defined(_M_IX86) || defined(_M_AMD64)
KMT_TESTFUNC Test_HalDmaBounce;
KMT_TESTFUNC Test_HalDmaSgWait;
KMT_TESTFUNC Test_HalDmaSgWaitNoItem;
KMT_TESTFUNC Test_HalDmaSgWaitFlaky;
KMT_TESTFUNC Test_HalIoApic;
KMT_TESTFUNC Test_HalPortIo;
#endif
KMT_TESTFUNC Test_HalSystemInfo;
KMT_TESTFUNC Test_IoCreateFile;
KMT_TESTFUNC Test_IoDeviceInterface;
KMT_TESTFUNC Test_IoDeviceProperty;
KMT_TESTFUNC Test_IoEvent;
KMT_TESTFUNC Test_IoFilesystem;
KMT_TESTFUNC Test_IoInterrupt;
KMT_TESTFUNC Test_IoIrp;
KMT_TESTFUNC Test_IoMdl;
KMT_TESTFUNC Test_IoCreateDeviceSecure;
KMT_TESTFUNC Test_KeProcessorGroups;
KMT_TESTFUNC Test_ObWithTag;
KMT_TESTFUNC Test_IoCreateSystemThread;
KMT_TESTFUNC Test_IoNonFileName;
KMT_TESTFUNC Test_IoValidateDeviceIoControlAccess;
KMT_TESTFUNC Test_IoWMINotification;
KMT_TESTFUNC Test_IoPnpEventQueue;
KMT_TESTFUNC Test_IoVolume;
KMT_TESTFUNC Test_KdSystemDebugControl;
KMT_TESTFUNC Test_KeApc;
KMT_TESTFUNC Test_KeApcDelivery;
KMT_TESTFUNC Test_KeBugCheckCallback;
KMT_TESTFUNC Test_KeDeviceQueue;
KMT_TESTFUNC Test_KeDpc;
KMT_TESTFUNC Test_KeEvent;
KMT_TESTFUNC Test_KeFastFail;
KMT_TESTFUNC Test_KeGeneralProtection;
KMT_TESTFUNC Test_KeFloatPointState;
KMT_TESTFUNC Test_KeGenericCallDpc;
KMT_TESTFUNC Test_KeGuardedMutex;
KMT_TESTFUNC Test_KeFreezeBreakDpc;
KMT_TESTFUNC Test_KeFreezeBugCheckDpc;
KMT_TESTFUNC Test_KeFreezeNmiDpc;
KMT_TESTFUNC Test_KeIrql;
KMT_TESTFUNC Test_KeIrqlPerf;
KMT_TESTFUNC Test_KeMutex;
KMT_TESTFUNC Test_KePriority;
KMT_TESTFUNC Test_KeProcessor;
KMT_TESTFUNC Test_KeQpc;
KMT_TESTFUNC Test_KeSpinLock;
KMT_TESTFUNC Test_KeTimer;
KMT_TESTFUNC Test_KeClockTime;
KMT_TESTFUNC Test_KeDelayExecution;
KMT_TESTFUNC Test_KernelType;
KMT_TESTFUNC Test_MmMdl;
KMT_TESTFUNC Test_MmCommitKernelFail;
KMT_TESTFUNC Test_MmContiguousAlign;
KMT_TESTFUNC Test_MmContiguousExhaust;
KMT_TESTFUNC Test_MmContiguousStandby;
KMT_TESTFUNC Test_MmFaultFileHeld;
KMT_TESTFUNC Test_MmOomRetry;
KMT_TESTFUNC Test_MmSection;
KMT_TESTFUNC Test_MmSpecialPool;
KMT_TESTFUNC Test_MmSpecialPoolOverrun;
KMT_TESTFUNC Test_MmSpecialPoolUnderrun;
KMT_TESTFUNC Test_MmSpecialPoolUseAfterFree;
KMT_TESTFUNC Test_MmSpecialPoolUseAfterFreeDpc;
KMT_TESTFUNC Test_MmSpecialPoolUseAfterFreeNoInts;
KMT_TESTFUNC Test_MmSpecialPoolMalformed;
KMT_TESTFUNC Test_MmIrqlFaultNullDriver;
KMT_TESTFUNC Test_MmIrqlFaultNullKernel;
KMT_TESTFUNC Test_MmIrqlFaultPagedWrite;
KMT_TESTFUNC Test_MmReservedMapping;
KMT_TESTFUNC Test_MmSystemPtes;
KMT_TESTFUNC Test_MmSessionSpace;
KMT_TESTFUNC Test_KeServiceTableAgain;
KMT_TESTFUNC Test_MmSessionImage;
KMT_TESTFUNC Test_MmSessionImageBugCheck;
KMT_TESTFUNC Test_MmSessionTables;
KMT_TESTFUNC Test_MmCodeProtect;
KMT_TESTFUNC Test_MmCodeProtectWrite;
KMT_TESTFUNC Test_NpfsConnect;
KMT_TESTFUNC Test_NpfsCreate;
KMT_TESTFUNC Test_NpfsFileInfo;
KMT_TESTFUNC Test_NpfsReadWrite;
KMT_TESTFUNC Test_NpfsVolumeInfo;
KMT_TESTFUNC Test_ObHandle;
KMT_TESTFUNC Test_ObQuery;
KMT_TESTFUNC Test_ObReference;
KMT_TESTFUNC Test_ObSecurity;
KMT_TESTFUNC Test_ObSymbolicLink;
KMT_TESTFUNC Test_ObType;
KMT_TESTFUNC Test_ObTypeClean;
KMT_TESTFUNC Test_ObTypeNoClean;
KMT_TESTFUNC Test_ObTypes;
KMT_TESTFUNC Test_PsNotify;
KMT_TESTFUNC Test_PsQuota;
KMT_TESTFUNC Test_PsQuotaLimited;
KMT_TESTFUNC Test_PsQuotaLimitedTrim;
KMT_TESTFUNC Test_PsQuotaLimitedSetLimits;
KMT_TESTFUNC Test_PsQuotaLimitedThreshold;
KMT_TESTFUNC Test_PsQuotaSwitchRace;
KMT_TESTFUNC Test_SeAutoInherit;
KMT_TESTFUNC Test_SeInheritance;
KMT_TESTFUNC Test_SeLogonSession;
KMT_TESTFUNC Test_SeOwnerRights;
KMT_TESTFUNC Test_SeOwnerRightsPerf;
KMT_TESTFUNC Test_SeQueryInfoToken;
KMT_TESTFUNC Test_SeTokenFiltering;
KMT_TESTFUNC Test_RtlAvlTree;
KMT_TESTFUNC Test_RtlCaptureContext;
KMT_TESTFUNC Test_RtlException;
KMT_TESTFUNC Test_RtlIntSafe;
KMT_TESTFUNC Test_RtlIsValidOemCharacter;
KMT_TESTFUNC Test_RtlMemory;
KMT_TESTFUNC Test_RtlMemoryOps;
KMT_TESTFUNC Test_RtlRangeList;
KMT_TESTFUNC Test_RtlRegistry;
KMT_TESTFUNC Test_RtlSplayTree;
KMT_TESTFUNC Test_RtlStack;
KMT_TESTFUNC Test_RtlStrSafe;
KMT_TESTFUNC Test_RtlUnicodeString;
KMT_TESTFUNC Test_ZwAllocateVirtualMemory;
KMT_TESTFUNC Test_ZwCreateSection;
KMT_TESTFUNC Test_ZwMapViewOfSection;
KMT_TESTFUNC Test_ZwWaitForMultipleObjects;

const KMT_TEST TestList[] =
{
    { "CcPurgeCacheSection",                Test_CcPurgeCacheSection },
    { "CmAclAudit",                         Test_CmAclAudit },
    { "CmRename",                           Test_CmRename },
    { "CmSkStore",                          Test_CmSkStore },
    { "CmSecurity",                         Test_CmSecurity },
    { "ExCallback",                         Test_ExCallback },
    { "ExDoubleList",                       Test_ExDoubleList },
    { "ExFastMutex",                        Test_ExFastMutex },
    { "ExHardError",                        Test_ExHardError },
    { "-ExHardErrorInteractive",            Test_ExHardErrorInteractive },
    { "ExHardErrorSystemThread",            Test_ExHardErrorSystemThread },
    { "ExInterlocked",                      Test_ExInterlocked },
    { "ExInterlockedIpi",                   Test_ExInterlockedIpi },
    { "ExAllocatePool2",                    Test_ExAllocatePool2 },
    { "ExLookasideListEx",                  Test_ExLookasideListEx },
    { "ExPoolCacheAligned",                 Test_ExPoolCacheAligned },
    { "ExPools",                            Test_ExPools },
    { "ExStubHit",                          Test_ExStubHit },
    { "ProbeCapture",                       Test_ProbeCapture },
    { "ExPushLock",                         Test_ExPushLock },
    { "ExResource",                         Test_ExResource },
    { "-ExResourceGrow",                    Test_ExResourceGrow },
    { "ExSListPopFault",                      Test_ExSListPopFault },
    { "ExSequencedList",                    Test_ExSequencedList },
    { "ExSingleList",                       Test_ExSingleList },
    { "-ExTimer",                           Test_ExTimer },
    { "ExTimerResolution",                  Test_ExTimerResolution },
    { "ExUuid",                             Test_ExUuid },
    { "ExWorkQueue",                        Test_ExWorkQueue },
    { "KsCapture",                          Test_KsCapture },
    { "Example",                            Test_Example },
    { "FsRtlDissect",                       Test_FsRtlDissect },
    { "FsRtlEcp",                           Test_FsRtlEcp },
    { "FsRtlExpression",                    Test_FsRtlExpression },
    { "FsRtlFileLock",                      Test_FsRtlFileLock },
    { "FsRtlFileLockIrp",                   Test_FsRtlFileLockIrp },
    { "FsRtlFileLockStress",                Test_FsRtlFileLockStress },
    { "FsRtlLegal",                         Test_FsRtlLegal },
    { "FsRtlMcb",                           Test_FsRtlMcb },
    { "FsRtlNotify",                        Test_FsRtlNotify },
    { "FsRtlPerStreamContext",              Test_FsRtlPerStreamContext },
    { "FsRtlRemoveDotsFromPath",            Test_FsRtlRemoveDotsFromPath },
    { "FsRtlTunnel",                        Test_FsRtlTunnel },
    { "HalDma",                             Test_HalDma },
#if defined(_M_IX86) || defined(_M_AMD64)
    { "-HalIoApic",                         Test_HalIoApic },
    { "HalDmaBounce",                       Test_HalDmaBounce },
    { "HalDmaSgWait",                       Test_HalDmaSgWait },
    { "HalDmaSgWaitNoItem",                 Test_HalDmaSgWaitNoItem },
    { "HalDmaSgWaitFlaky",                  Test_HalDmaSgWaitFlaky },
    { "HalPortIo",                          Test_HalPortIo },
#endif
    { "HalSystemInfo",                      Test_HalSystemInfo },
    { "IoCreateFile",                       Test_IoCreateFile },
    { "IoDeviceInterface",                  Test_IoDeviceInterface },
    { "IoDeviceProperty",                   Test_IoDeviceProperty },
    { "IoEvent",                            Test_IoEvent },
    { "IoFilesystem",                       Test_IoFilesystem },
    { "IoInterrupt",                        Test_IoInterrupt },
    { "IoIrp",                              Test_IoIrp },
    { "IoMdl",                              Test_IoMdl },
    { "IoCreateDeviceSecure",               Test_IoCreateDeviceSecure },
    { "KeProcessorGroups",                  Test_KeProcessorGroups },
    { "ObWithTag",                          Test_ObWithTag },
    { "IoCreateSystemThread",               Test_IoCreateSystemThread },
    { "IoNonFileName",                      Test_IoNonFileName },
    { "IoValidateDeviceIoControlAccess",    Test_IoValidateDeviceIoControlAccess },
    { "IoWMINotification",                  Test_IoWMINotification },
    { "IoPnpEventQueue",                    Test_IoPnpEventQueue },
    { "IoVolume",                           Test_IoVolume },
    { "KdSystemDebugControl",               Test_KdSystemDebugControl },
    { "KeApc",                              Test_KeApc },
    { "KeApcDelivery",                      Test_KeApcDelivery },
    { "-KeBugCheckCallback",                Test_KeBugCheckCallback },
    { "KeDeviceQueue",                      Test_KeDeviceQueue },
    { "KeDpc",                              Test_KeDpc },
    { "KeEvent",                            Test_KeEvent },
    { "-KeFastFail",                        Test_KeFastFail },
    { "-KeGeneralProtection",               Test_KeGeneralProtection },
    { "KeFloatPointState",                  Test_KeFloatPointState },
    { "KeGenericCallDpc",                   Test_KeGenericCallDpc },
    { "KeGuardedMutex",                     Test_KeGuardedMutex },
    { "-KeFreezeBreakDpc",                Test_KeFreezeBreakDpc },
    { "-KeFreezeBugCheckDpc",             Test_KeFreezeBugCheckDpc },
    { "-KeFreezeNmiDpc",                  Test_KeFreezeNmiDpc },
    { "KeIrql",                             Test_KeIrql },
    { "-KeIrqlPerf",                        Test_KeIrqlPerf },
    { "KeMutex",                            Test_KeMutex },
    { "KePriority",                         Test_KePriority },
    { "KeProfile",                          Test_KeProfile, Test_KeProfileWithData },
    { "-KeProcessor",                       Test_KeProcessor },
    { "KeQpc",                              Test_KeQpc },
    { "KeSpinLock",                         Test_KeSpinLock },
    { "MmMapViewAligned",            Test_MmMapViewAligned },
    { "KeSystemCall32",              Test_KeSystemCall32 },
    { "KeTimer",                            Test_KeTimer },
    { "KeClockTime",                        Test_KeClockTime },
    { "KeDelayExecution",                   Test_KeDelayExecution },
    { "-KernelType",                        Test_KernelType },
    { "MmMdl",                              Test_MmMdl },
    { "-MmCommitKernelFail",                Test_MmCommitKernelFail },
    { "MmContiguousAlign",                  Test_MmContiguousAlign },
    { "MmContiguousExhaust",                Test_MmContiguousExhaust },
    { "-MmContiguousStandby",               Test_MmContiguousStandby },
    { "MmFaultFileHeld",                    Test_MmFaultFileHeld },
    { "MmOomRetry",                         Test_MmOomRetry },
    { "MmSection",                          Test_MmSection },
    { "MmSpecialPool",                      Test_MmSpecialPool },
    { "-MmSpecialPoolOverrun",              Test_MmSpecialPoolOverrun },
    { "-MmSpecialPoolUnderrun",             Test_MmSpecialPoolUnderrun },
    { "-MmSpecialPoolUseAfterFree",         Test_MmSpecialPoolUseAfterFree },
    { "-MmSpecialPoolUseAfterFreeDpc",      Test_MmSpecialPoolUseAfterFreeDpc },
    { "-MmSpecialPoolUseAfterFreeNoInts",   Test_MmSpecialPoolUseAfterFreeNoInts },
    { "-MmSpecialPoolMalformed",            Test_MmSpecialPoolMalformed },
    { "-MmIrqlFaultNullDriver",             Test_MmIrqlFaultNullDriver },
    { "-MmIrqlFaultNullKernel",             Test_MmIrqlFaultNullKernel },
    { "-MmIrqlFaultPagedWrite",             Test_MmIrqlFaultPagedWrite },
    { "MmReservedMapping",                  Test_MmReservedMapping },
    { "MmSystemPtes",                       Test_MmSystemPtes },
    { "MmSessionSpace",                     Test_MmSessionSpace },
    { "KeServiceTableAgain",                Test_KeServiceTableAgain },
    { "MmSessionImage",                     Test_MmSessionImage },
    { "-MmSessionImageBugCheck",            Test_MmSessionImageBugCheck },
    { "MmSessionTables",                    Test_MmSessionTables },
    { "MmCodeProtect",                        Test_MmCodeProtect },
    { "-MmCodeProtectWrite",                  Test_MmCodeProtectWrite },
    { "NpfsConnect",                        Test_NpfsConnect },
    { "NpfsCreate",                         Test_NpfsCreate },
    { "NpfsFileInfo",                       Test_NpfsFileInfo },
    { "NpfsReadWrite",                      Test_NpfsReadWrite },
    { "NpfsVolumeInfo",                     Test_NpfsVolumeInfo },
    { "ObHandle",                           Test_ObHandle },
    { "ObQuery",                            Test_ObQuery },
    { "ObReference",                        Test_ObReference },
    { "ObSecurity",                         Test_ObSecurity },
    { "ObSymbolicLink",                     Test_ObSymbolicLink },
    { "ObType",                             Test_ObType },
    { "-ObTypeClean",                       Test_ObTypeClean },
    { "-ObTypeNoClean",                     Test_ObTypeNoClean },
    { "ObTypes",                            Test_ObTypes },
    { "PsNotify",                           Test_PsNotify },
    { "PsQuota",                            Test_PsQuota },
    { "PsQuotaLimited",                     Test_PsQuotaLimited },
    { "PsQuotaLimitedTrim",                 Test_PsQuotaLimitedTrim },
    { "PsQuotaLimitedSetLimits",            Test_PsQuotaLimitedSetLimits },
    { "PsQuotaLimitedThreshold",            Test_PsQuotaLimitedThreshold },
    { "PsQuotaSwitchRace",                 Test_PsQuotaSwitchRace },
    { "RtlAvlTreeKM",                       Test_RtlAvlTree },
    { "RtlExceptionKM",                     Test_RtlException },
    { "RtlIntSafeKM",                       Test_RtlIntSafe },
    { "RtlIsValidOemCharacter",             Test_RtlIsValidOemCharacter },
    { "RtlMemoryKM",                        Test_RtlMemory },
    { "RtlMemoryOpsKM",                     Test_RtlMemoryOps },
    { "RtlRangeList",                       Test_RtlRangeList },
    { "RtlRegistryKM",                      Test_RtlRegistry },
    { "RtlSplayTreeKM",                     Test_RtlSplayTree },
    { "RtlStackKM",                         Test_RtlStack },
    { "RtlStrSafeKM",                       Test_RtlStrSafe },
    { "RtlUnicodeStringKM",                 Test_RtlUnicodeString },
    { "SeAutoInherit",                      Test_SeAutoInherit },
    { "SeInheritance",                      Test_SeInheritance },
    { "SeLogonSession",                     Test_SeLogonSession },
    { "SeOwnerRights",                      Test_SeOwnerRights },
    { "-SeOwnerRightsPerf",                 Test_SeOwnerRightsPerf },
    { "SeQueryInfoToken",                  Test_SeQueryInfoToken },
    { "SeTokenFiltering",                   Test_SeTokenFiltering },
    { "ZwAllocateVirtualMemory",            Test_ZwAllocateVirtualMemory },
    { "ZwCreateSection",                    Test_ZwCreateSection },
    { "ZwMapViewOfSection",                 Test_ZwMapViewOfSection },
    { "ZwWaitForMultipleObjects",           Test_ZwWaitForMultipleObjects},
#ifdef _M_AMD64
    { "RtlCaptureContextKM",                Test_RtlCaptureContext },
#endif
    { NULL,                                 NULL }
};
