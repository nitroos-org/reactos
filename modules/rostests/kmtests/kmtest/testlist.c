/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1+ (https://spdx.org/licenses/LGPL-2.1+)
 * PURPOSE:     Kernel-Mode Test Suite user-mode test list
 */

#include <kmt_test.h>

KMT_TESTFUNC Test_KeSystemCall32;
KMT_TESTFUNC Test_KeProfile;
KMT_TESTFUNC Test_KeTrapFrame;

KMT_TESTFUNC Test_CcCopyRead;
KMT_TESTFUNC Test_CcCopyWrite;
KMT_TESTFUNC Test_CcZeroData;
KMT_TESTFUNC Test_CcLazyWriteDelete;
KMT_TESTFUNC Test_CcMapData;
KMT_TESTFUNC Test_CcPinLazyWrite;
KMT_TESTFUNC Test_CcPinMappedData;
KMT_TESTFUNC Test_CcPinRead;
KMT_TESTFUNC Test_CcPurgeCacheSectionView;
KMT_TESTFUNC Test_CcSetFileSizes;
KMT_TESTFUNC Test_CmCreatorSd;
KMT_TESTFUNC Test_CmFlush;
KMT_TESTFUNC Test_Example;
KMT_TESTFUNC Test_FileAttributes;
KMT_TESTFUNC Test_FindFile;
KMT_TESTFUNC Test_FltMgrLoad;
KMT_TESTFUNC Test_FltMgrReg;
KMT_TESTFUNC Test_HidPDescription;
KMT_TESTFUNC Test_IoCreateFile;
KMT_TESTFUNC Test_IoCreateFileEx;
KMT_TESTFUNC Test_IoDeviceObject;
KMT_TESTFUNC Test_IoIs32bitProcess;
KMT_TESTFUNC Test_IoReadWrite;
KMT_TESTFUNC Test_MmContiguousStandby;
KMT_TESTFUNC Test_MmMapLockedPagesProcessExit;
KMT_TESTFUNC Test_MmMapLockedPagesSpecifyCache;
KMT_TESTFUNC Test_MmPager;
KMT_TESTFUNC Test_MmSpecialPoolUser;
KMT_TESTFUNC Test_NtCreateSection;
KMT_TESTFUNC Test_NtSystemDebugControl;
KMT_TESTFUNC Test_PoIrp;
KMT_TESTFUNC Test_RtlAvlTree;
KMT_TESTFUNC Test_RtlCaptureContext;
KMT_TESTFUNC Test_RtlException;
KMT_TESTFUNC Test_RtlIntSafe;
KMT_TESTFUNC Test_RtlMemory;
KMT_TESTFUNC Test_RtlMemoryOps;
KMT_TESTFUNC Test_RtlRegistry;
KMT_TESTFUNC Test_RtlSplayTree;
KMT_TESTFUNC Test_RtlStack;
KMT_TESTFUNC Test_RtlStrSafe;
KMT_TESTFUNC Test_RtlUnicodeString;
KMT_TESTFUNC Test_TcpIpIoctl;
KMT_TESTFUNC Test_TcpIpTdi;
KMT_TESTFUNC Test_TcpIpConnect;
KMT_TESTFUNC Test_TcpIpListenCancel;

/* tests with a leading '-' will not be listed */
const KMT_TEST TestList[] =
{
    { "-CcCopyRead",                   Test_CcCopyRead },   // TODO: Crashes on TestWHS
    { "-CcCopyWrite",                  Test_CcCopyWrite },  // TODO: Crashes on TestWHS
    { "CcZeroData",                    Test_CcZeroData },
    { "-CcLazyWriteDelete",            Test_CcLazyWriteDelete },
    { "-CcMapData",                    Test_CcMapData },
    { "-CcPinLazyWrite",               Test_CcPinLazyWrite },
    { "-CcPinMappedData",              Test_CcPinMappedData },
    { "-CcPinRead",                    Test_CcPinRead },
    { "-CcPurgeCacheSectionView",      Test_CcPurgeCacheSectionView },
    { "-CcSetFileSizes",               Test_CcSetFileSizes },
    { "CmCreatorSd",                  Test_CmCreatorSd },
    { "CmFlush",                      Test_CmFlush },
    { "-Example",                     Test_Example },
    { "FileAttributes",               Test_FileAttributes },
    { "FindFile",                     Test_FindFile },
    { "-FltMgrLoad",                  Test_FltMgrLoad }, // TODO: WIP/untested/crashes.
    { "-FltMgrReg",                   Test_FltMgrReg }, // TODO: WIP/untested/crashes.
    { "HidPDescription",              Test_HidPDescription },
    { "IoCreateFile",                 Test_IoCreateFile },
    { "IoCreateFileEx",               Test_IoCreateFileEx },
    { "IoDeviceObject",               Test_IoDeviceObject },
    { "IoIs32bitProcess",             Test_IoIs32bitProcess },
    { "IoReadWrite",                  Test_IoReadWrite },
    { "KeTrapFrame",                  Test_KeTrapFrame },
    { "KeProfile",                    Test_KeProfile },
    { "KeSystemCall32",               Test_KeSystemCall32 },
    { "MmContiguousStandby",          Test_MmContiguousStandby },
    { "MmMapLockedPagesProcessExit",  Test_MmMapLockedPagesProcessExit },
    { "MmMapLockedPagesSpecifyCache", Test_MmMapLockedPagesSpecifyCache },
    { "MmPager",                      Test_MmPager },
    { "MmSpecialPoolUser",            Test_MmSpecialPoolUser },
    { "NtCreateSection",              Test_NtCreateSection },
    { "NtSystemDebugControl",         Test_NtSystemDebugControl },
    { "PoIrp",                        Test_PoIrp },
    { "RtlAvlTree",                   Test_RtlAvlTree },
    { "RtlException",                 Test_RtlException },
    { "RtlIntSafe",                   Test_RtlIntSafe },
    { "RtlMemory",                    Test_RtlMemory },
    { "RtlMemoryOps",                 Test_RtlMemoryOps },
    { "RtlRegistry",                  Test_RtlRegistry },
    { "RtlSplayTree",                 Test_RtlSplayTree },
    { "RtlStack",                     Test_RtlStack },
    { "RtlStrSafe",                   Test_RtlStrSafe },
    { "RtlUnicodeString",             Test_RtlUnicodeString },
    { "TcpIpTdi",                     Test_TcpIpTdi },
    { "TcpIpConnect",                 Test_TcpIpConnect },
    { "TcpIpListenCancel",            Test_TcpIpListenCancel },
#ifdef _M_AMD64
    { "RtlCaptureContextUM",          Test_RtlCaptureContext },
#endif
    { NULL,                           NULL },
};
