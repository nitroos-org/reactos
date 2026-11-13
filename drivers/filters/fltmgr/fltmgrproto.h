#ifndef _FLTMGR_PROTO_H
#define _FLTMGR_PROTO_H

/* Internal prototypes shared between the fltmgr source files (needs fltmgr.h and fltmgrint.h) */

/* Filter.c */
extern LIST_ENTRY FilterList;
extern ERESOURCE FilterListLock;
extern DRIVER_DATA DriverData;

LONG
FltpCompareAltitudeStrings(
    _In_ PCUNICODE_STRING Altitude1,
    _In_ PCUNICODE_STRING Altitude2
);

NTSTATUS
FltpSnapshotFilters(
    _Outptr_result_buffer_(*Count) PFLT_FILTER **Filters,
    _Out_ PULONG Count
);

VOID
FltpFreeFilterSnapshot(
    _In_ PFLT_FILTER *Filters,
    _In_ ULONG Count
);

/* Volume.c */
extern LIST_ENTRY FltpVolumeList;

BOOLEAN
FltpIsAttachedToDevice(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PDEVICE_OBJECT *AttachedDeviceObject
);

NTSTATUS
FltpEnumerateFileSystemVolumes(
    _In_ PDEVICE_OBJECT DeviceObject
);

NTSTATUS
FltpAttachToVolumeDevice(
    _In_ PDEVICE_OBJECT VolumeDeviceObject,
    _In_ PDEVICE_OBJECT StorageDeviceObject,
    _In_ BOOLEAN NewlyMounted
);

VOID
FltpTeardownVolume(
    _In_ PFLT_VOLUME Volume,
    _In_ ULONG Reason
);

NTSTATUS
FltpSnapshotVolumes(
    _Outptr_result_buffer_(*Count) PFLT_VOLUME **Volumes,
    _Out_ PULONG Count
);

VOID
FltpFreeVolumeSnapshot(
    _In_ PFLT_VOLUME *Volumes,
    _In_ ULONG Count
);

NTSTATUS
FltpAttachFilterToVolume(
    _In_ PFLT_FILTER Filter,
    _In_ PFLT_VOLUME Volume,
    _In_ ULONG SetupFlags
);

/* Instance.c */
NTSTATUS
FltpAttachInstance(
    _In_ PFLT_FILTER Filter,
    _In_ PFLT_VOLUME Volume,
    _In_opt_ PCUNICODE_STRING Altitude,
    _In_opt_ PCUNICODE_STRING Name,
    _In_ ULONG SetupFlags,
    _Out_opt_ PFLT_INSTANCE *RetInstance
);

VOID
FltpTeardownInstance(
    _In_ PFLT_INSTANCE Instance,
    _In_ ULONG Reason
);

VOID
FltpTeardownFilterInstances(
    _In_ PFLT_FILTER Filter,
    _In_ ULONG Reason
);

VOID
FltpTeardownVolumeInstances(
    _In_ PFLT_VOLUME Volume,
    _In_ ULONG Reason
);

/* Operation.c */
NTSTATUS
FltpPerformIrp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

BOOLEAN
FltpFastIoDisallowed(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR MajorFunction
);

/* Context.c */
VOID
FltpTeardownInstanceContexts(
    _In_ PFLT_INSTANCE Instance
);

VOID
FltpTeardownVolumeContexts(
    _In_ PFLT_VOLUME Volume
);

#endif /* _FLTMGR_PROTO_H */
