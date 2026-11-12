/* ReactOS WoW64 USER display, desktop and window-station translation.
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "wow64win.h"

typedef struct { ULONG Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService; } OBJECT_ATTRIBUTES32;
typedef struct { BYTE Revision, Sbz1; WORD Control; ULONG Owner, Group, Sacl, Dacl; } SECURITY_DESCRIPTOR32;
typedef struct { OBJECT_ATTRIBUTES Attributes; UNICODE_STRING Name; SECURITY_DESCRIPTOR Descriptor; } NATIVE_ATTRIBUTES;
C_ASSERT(sizeof(OBJECT_ATTRIBUTES32) == 24);
C_ASSERT(sizeof(SECURITY_DESCRIPTOR32) == 20);
C_ASSERT(sizeof(SECURITY_DESCRIPTOR) == 40);
C_ASSERT(sizeof(DEVMODEW) == 220);
C_ASSERT(sizeof(DISPLAY_DEVICEW) == 840);

/* The guest owns the low 4 GiB; a range may not run into native-only addresses. */
static BOOLEAN GuestRange(ULONG Address, ULONGLONG Length) { return Length <= 0x100000000ULL - Address; }

static VOID GuestProbe(ULONG Address, ULONGLONG Length)
{
    if (!GuestRange(Address, Length)) RtlRaiseStatus(STATUS_ACCESS_VIOLATION);
}

/* A guest structure that cannot be read must not reach the native service in
 * its 32-bit layout. It is replaced by an address in the never-mapped 64 KiB
 * at the native user probe address (one past the highest user address, the
 * same value the kernel uses), which fails every probe and access there,
 * so the service fails exactly as for an inaccessible argument of its own.
 * The low bits are kept so that misalignment is still reported first. */
#define GUEST_UNREADABLE_BASE ((ULONG_PTR)MI_HIGHEST_USER_ADDRESS + 1)
C_ASSERT((GUEST_UNREADABLE_BASE & 0xFFFF) == 0);
#define GUEST_UNREADABLE(Address) ((PVOID)(GUEST_UNREADABLE_BASE | ((Address) & 3)))

static PUNICODE_STRING StringIn(UNICODE_STRING *To, ULONG Address)
{
    PUNICODE_STRING Result = To;
    if (!Address) return NULL;
    _SEH2_TRY
    {
        STRING32 From;
        GuestProbe(Address, sizeof(From));
        From = *(const volatile STRING32 *)P32(Address);
        To->Length = From.Length;
        To->MaximumLength = From.MaximumLength;
        To->Buffer = P32(From.Buffer);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = GUEST_UNREADABLE(Address);
    }
    _SEH2_END;
    return Result;
}

static PVOID SecurityDescriptorIn(SECURITY_DESCRIPTOR *To, ULONG Address)
{
    PVOID Result = To;
    if (!Address) return NULL;
    _SEH2_TRY
    {
        SECURITY_DESCRIPTOR32 From;
        GuestProbe(Address, sizeof(From));
        From = *(const volatile SECURITY_DESCRIPTOR32 *)P32(Address);
        if (From.Control & SE_SELF_RELATIVE)
        {
            Result = P32(Address);
        }
        else
        {
            To->Revision = From.Revision;
            To->Sbz1 = From.Sbz1;
            To->Control = From.Control;
            To->Owner = P32(From.Owner);
            To->Group = P32(From.Group);
            To->Sacl = P32(From.Sacl);
            To->Dacl = P32(From.Dacl);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = GUEST_UNREADABLE(Address);
    }
    _SEH2_END;
    return Result;
}

static VOID GuestAttributes(OBJECT_ATTRIBUTES32 *To, ULONG Address)
{
    const volatile BYTE *From = P32(Address);
    ULONG i;
    if (Address & (sizeof(ULONG) - 1)) RtlRaiseStatus(STATUS_DATATYPE_MISALIGNMENT);
    GuestProbe(Address, sizeof(*To));
    for (i = 0; i < sizeof(*To); ++i) ((BYTE *)To)[i] = From[i];
}

/* Only the 24-byte guest layout is accepted; any other Length reaches the
 * native service as zero and is rejected there. */
static POBJECT_ATTRIBUTES AttributesIn(NATIVE_ATTRIBUTES *To, ULONG Address)
{
    POBJECT_ATTRIBUTES Result = &To->Attributes;
    if (!Address) return NULL;
    RtlZeroMemory(To, sizeof(*To));
    _SEH2_TRY
    {
        OBJECT_ATTRIBUTES32 From;
        GuestAttributes(&From, Address);
        if (From.Length == sizeof(OBJECT_ATTRIBUTES32))
        {
            To->Attributes.Length = sizeof(OBJECT_ATTRIBUTES);
            To->Attributes.RootDirectory = H32(From.RootDirectory);
            To->Attributes.Attributes = From.Attributes;
            To->Attributes.ObjectName = StringIn(&To->Name, From.ObjectName);
            To->Attributes.SecurityDescriptor = SecurityDescriptorIn(&To->Descriptor, From.SecurityDescriptor);
            To->Attributes.SecurityQualityOfService = P32(From.SecurityQualityOfService);
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Result = GUEST_UNREADABLE(Address);
    }
    _SEH2_END;
    return Result;
}

/* The native service writes the caller's attributes when it builds a default
 * name, so the guest structure must be writable in the same cases. */
static BOOL WinStaAttributesWritable(ULONG Address, BOOL Open)
{
    BOOL Ok = TRUE;
    if (!Address) return TRUE;
    _SEH2_TRY
    {
        volatile BYTE *Bytes = P32(Address);
        OBJECT_ATTRIBUTES32 Guest;
        STRING32 Name;
        const WCHAR *Buffer;
        BOOL Build = FALSE;
        /* Raises before any access unless all 24 bytes are guest memory. */
        GuestAttributes(&Guest, Address);
        if (Guest.Length == sizeof(OBJECT_ATTRIBUTES32))
        {
            Build = !Guest.ObjectName;
            if (!Build)
            {
                GuestProbe(Guest.ObjectName, sizeof(Name));
                Name = *(const volatile STRING32 *)P32(Guest.ObjectName);
                Buffer = P32(Name.Buffer);
                if (Buffer && Name.Length) GuestProbe(Name.Buffer, max(Name.Length, sizeof(WCHAR)));
                Build = !Buffer || !Name.Length || !Buffer[0];
                if (!Build && Open)
                    Build = Name.Length == sizeof(L"Service-0x00000000-00000000$") - sizeof(WCHAR) &&
                            !_wcsnicmp(Buffer, L"Service-0x00000000-00000000$", Name.Length / sizeof(WCHAR));
            }
        }
        if (Build)
        {
            ULONG i;
            for (i = 0; i < sizeof(OBJECT_ATTRIBUTES32); ++i) Bytes[i] = Bytes[i];
        }
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        RtlSetLastWin32Error(RtlNtStatusToDosError(_SEH2_GetExceptionCode()));
        Ok = FALSE;
    }
    _SEH2_END;
    return Ok;
}


static ULONG_PTR ResolveDesktop(ULONG *a)
{
    UNICODE_STRING Path;
    HWINSTA Untouched = (HWINSTA)(ULONG_PTR)-2, WinSta = Untouched;
    HWINSTA *Native = NULL;
    HDESK Desktop;
    BOOLEAN Failed = FALSE;
    if (a[3])
    {
        Native = &WinSta;
        _SEH2_TRY
        {
            volatile ULONG *Out = P(3);
            GuestProbe(a[3], sizeof(ULONG));
            *Out = *Out;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Native = NULL;
        }
        _SEH2_END;
    }
    Desktop = NtUserResolveDesktop(H(0), StringIn(&Path, a[1]), (BOOL)S(2), Native);
    if (Native && WinSta != Untouched)
    {
        _SEH2_TRY
        {
            *(ULONG *)P(3) = (ULONG)(ULONG_PTR)WinSta;
        }
        _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
        {
            Failed = TRUE;
        }
        _SEH2_END;
    }
    if (Failed)
    {
        if (Desktop) NtClose(Desktop);
        if (WinSta) NtClose(WinSta);
        return 0;
    }
    return (ULONG_PTR)Desktop;
}

ULONG_PTR Wow64WinUserDisplayService(ULONG Number, ULONG *a)
{
    switch (Number)
    {
    case W64_NtUserChangeDisplaySettings:
    {
        UNICODE_STRING Device;
        return (ULONG_PTR)(LONG)NtUserChangeDisplaySettings(StringIn(&Device, a[0]), P(1), a[2], P(3));
    }
    case W64_NtUserEnumDisplayDevices:
    {
        UNICODE_STRING Device;
        return NtUserEnumDisplayDevices(StringIn(&Device, a[0]), a[1], P(2), a[3]);
    }
    case W64_NtUserEnumDisplaySettings:
    {
        UNICODE_STRING Device;
        return (ULONG_PTR)(LONG)NtUserEnumDisplaySettings(StringIn(&Device, a[0]), a[1], P(2), a[3]);
    }
    case W64_NtUserCreateDesktop:
    {
        NATIVE_ATTRIBUTES Attributes; UNICODE_STRING Device;
        POBJECT_ATTRIBUTES Native = AttributesIn(&Attributes, a[0]);
        return (ULONG_PTR)NtUserCreateDesktop(Native, StringIn(&Device, a[1]), P(2), a[3], a[4]);
    }
    case W64_NtUserOpenDesktop:
    {
        NATIVE_ATTRIBUTES Attributes;
        POBJECT_ATTRIBUTES Native = AttributesIn(&Attributes, a[0]);
        return (ULONG_PTR)NtUserOpenDesktop(Native, a[1], a[2]);
    }
    case W64_NtUserCreateWindowStation:
    {
        NATIVE_ATTRIBUTES Attributes;
        POBJECT_ATTRIBUTES Native;
        if (!WinStaAttributesWritable(a[0], FALSE)) return 0;
        Native = AttributesIn(&Attributes, a[0]);
        return (ULONG_PTR)NtUserCreateWindowStation(Native, a[1], a[2], a[3], a[4], a[5], a[6]);
    }
    case W64_NtUserOpenWindowStation:
    {
        NATIVE_ATTRIBUTES Attributes;
        POBJECT_ATTRIBUTES Native;
        if (!WinStaAttributesWritable(a[0], TRUE)) return 0;
        Native = AttributesIn(&Attributes, a[0]);
        return (ULONG_PTR)NtUserOpenWindowStation(Native, a[1]);
    }
    case W64_NtUserResolveDesktop: return ResolveDesktop(a);
    default:
        return Wow64WinUserMiscService(Number, a);
    }
}
