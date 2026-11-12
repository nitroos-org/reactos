
#pragma once

extern POBJECT_TYPE WmipGuidObjectType;

#define GUID_STRING_LENGTH 36

typedef struct _WMIP_IRP_CONTEXT
{
    LIST_ENTRY GuidObjectListHead;
} WMIP_IRP_CONTEXT, *PWMIP_IRP_CONTEXT;

typedef struct _WMIP_GUID_OBJECT
{
    KEVENT Event;
    GUID Guid;
    PIRP Irp;
    LIST_ENTRY IrpLink;

    /* Kernel notification callback (IoWMISetNotificationCallback) */
    LIST_ENTRY NotifyLink;
    WMI_NOTIFICATION_CALLBACK NotifyCallback;
    PVOID NotifyContext;
    LONG NotifyInFlight;
    BOOLEAN NotifyLinked;
} WMIP_GUID_OBJECT, *PWMIP_GUID_OBJECT;


_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
NTSTATUS
NTAPI
WmipDriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
NTAPI
WmipInitializeGuidObjectType(
    VOID);

NTSTATUS
NTAPI
WmipOpenGuidObject(
    _In_ LPCGUID Guid,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE OutGuidObjectHandle,
    _Outptr_ PVOID *OutGuidObject);

NTSTATUS
NTAPI
WmipOpenGuidObjectByName(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE OutGuidObjectHandle,
    _Outptr_ PVOID *OutGuidObject);

VOID
NTAPI
WmipNotifyInitialize(
    VOID);

VOID
NTAPI
WmipNotifyRemove(
    _In_ PWMIP_GUID_OBJECT GuidObject);

NTSTATUS
NTAPI
WmipNotifySetCallback(
    _In_ PWMIP_GUID_OBJECT GuidObject,
    _In_opt_ WMI_NOTIFICATION_CALLBACK Callback,
    _In_opt_ PVOID Context);

VOID
NTAPI
WmipNotifyDeliver(
    _In_ PWNODE_HEADER Wnode);

NTSTATUS
NTAPI
WmipQueryRawSMBiosTables(
    _Inout_ ULONG *InOutBufferSize,
    _Out_opt_ PVOID OutBuffer);

