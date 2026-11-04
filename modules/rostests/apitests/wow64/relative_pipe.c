/*
 * PROJECT:     NitroOS
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Relative pipe-root opens used by MSYS installer helpers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/* Relative pipe-root opens used by MSYS installer helpers. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } STRING;
typedef struct { ULONG Length; HANDLE Root; STRING *Name; ULONG Flags; PVOID Security, Qos; } ATTRIBUTES;
typedef struct { ULONG_PTR Status, Information; } IOSB;
typedef LONG (WINAPI *OPEN)(PHANDLE, ULONG, ATTRIBUTES *, IOSB *, ULONG, ULONG);
typedef LONG (WINAPI *CREATE_PIPE)(PHANDLE, ULONG, ATTRIBUTES *, IOSB *, ULONG, ULONG,
                                  ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, LARGE_INTEGER *);
static unsigned Checks, Failures;
#define CHECK(x) do { ++Checks; if (!(x)) { ++Failures; printf("FAIL line %u: %s error=%lu\n", __LINE__, #x, GetLastError()); } } while (0)

int main(void)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    OPEN Open = (OPEN)GetProcAddress(Ntdll, "NtOpenFile");
    CREATE_PIPE CreatePipe = (CREATE_PIPE)GetProcAddress(Ntdll, "NtCreateNamedPipeFile");
    WCHAR Buffer[80];
    STRING Name;
    ATTRIBUTES Attributes = {sizeof(Attributes), NULL, &Name, 0x40, NULL, NULL};
    IOSB Io;
    LARGE_INTEGER Timeout;
    HANDLE Root = NULL, Server = NULL, Client = NULL;
    DWORD Bytes, Flags, Inbound, Outbound, Instances;
    char Data[16] = {0};
    BOOL Wow = FALSE;
    setvbuf(stdout, NULL, _IONBF, 0);
    IsWow64Process(GetCurrentProcess(), &Wow);
    if (!Wow)
    {
        /* Native ReactOS still has the NPFS relative-root assertion. */
        puts("RELATIVE PIPE skip: this regression targets the WoW64 path");
        return 0;
    }
    CHECK(Open && CreatePipe);
    if (!Open || !CreatePipe) return 1;
    Name.Buffer = L"\\Device\\NamedPipe\\";
    Name.Length = wcslen(Name.Buffer) * sizeof(WCHAR); Name.MaximumLength = Name.Length + sizeof(WCHAR);
    CHECK(Open(&Root, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &Attributes, &Io, 3, 0x20) == 0);
    if (!Root) return 1;
    _snwprintf(Buffer, 80, L"w643c-relative-pipe-%lu", GetCurrentProcessId());
    Name.Buffer = Buffer;
    Name.Length = wcslen(Buffer) * sizeof(WCHAR); Name.MaximumLength = Name.Length + sizeof(WCHAR);
    Attributes.Root = Root;
    Timeout.QuadPart = -50000000;
    CHECK(CreatePipe(&Server, GENERIC_READ | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES, &Attributes,
                     &Io, 3, 2, 0x20, 0, 0, 0, 1, 4096, 4096, &Timeout) == 0);
    if (Server)
    {
        puts("RELATIVE PIPE opening client");
        CHECK(Open(&Client, GENERIC_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &Attributes, &Io, 0, 0x20) == 0);
        if (Client)
        {
            CHECK(GetNamedPipeInfo(Server, &Flags, &Outbound, &Inbound, &Instances));
            CHECK(!(Flags & PIPE_TYPE_MESSAGE) && Inbound && Instances == 1);
            CHECK(WriteFile(Client, "helper", 6, &Bytes, NULL) && Bytes == 6);
            CHECK(ReadFile(Server, Data, sizeof(Data), &Bytes, NULL) && Bytes == 6 && !memcmp(Data, "helper", 6));
            CloseHandle(Client);
        }
        CloseHandle(Server);
    }
    /* A nonexistent relative name must retain ordinary lookup semantics. */
    Name.Buffer = L"w643c-relative-missing";
    Name.Length = wcslen(Name.Buffer) * sizeof(WCHAR); Name.MaximumLength = Name.Length + sizeof(WCHAR);
    Client = NULL;
    CHECK(Open(&Client, GENERIC_WRITE | SYNCHRONIZE, &Attributes, &Io, 0, 0x20) == (LONG)0xc0000034);
    if (Client) CloseHandle(Client);
    CloseHandle(Root);
    printf("RELATIVE PIPE checks=%u failures=%u\n", Checks, Failures);
    return Failures ? 1 : 0;
}
