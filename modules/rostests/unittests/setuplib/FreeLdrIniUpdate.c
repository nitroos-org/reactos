/*
 * PROJECT:     ReactOS Setup Library - Unit-tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Setup updating an existing freeldr.ini (repair, upgrade, a second installation): the boot entry of
 *              the installation and the kernel debugging entry
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

extern HANDLE ProcessHeap;

#define ARC_A "multi(0)disk(0)rdisk(0)partition(1)\\ReactOS"
#define ARC_B "multi(0)disk(0)rdisk(0)partition(2)\\Other"
#define GUID_1 "{11111111-2222-4333-8444-555555555555}"
#define GUID_1W L"{11111111-2222-4333-8444-555555555555}"
#define GUID_2W L"{AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE}"
#define GUID_2 "{AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE}"
#define DISK_1 "{CCCCCCCC-DDDD-4EEE-8FFF-000000000000}"
#define DISK_W L"{CCCCCCCC-DDDD-4EEE-8FFF-000000000000}"
#define RANGE "100-200"
#define RANGE_W L"100-200"

static const char Head[] =
    "[FREELOADER]\r\n"
    "TimeOut=5\r\n"
    "DefaultOS=ReactOS\r\n"
    "\r\n"
    "[Operating Systems]\r\n"
    "ReactOS=\"NitroOS\"\r\n"
    "ReactOS_Debug=\"NitroOS (Debug)\"\r\n";
static const char Sections[] =
    "\r\n"
    "[ReactOS]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=" ARC_A "\r\n"
    "Options=/FASTDETECT\r\n"
    "\r\n"
    "[ReactOS_Debug]\r\n"
    "BootType=Windows2003\r\n"
    "SystemPath=" ARC_A "\r\n"
    "Options=/DEBUG /DEBUGPORT=COM1 /BAUDRATE=115200 /SOS\r\n";

static WCHAR Dir[MAX_PATH], IniFile[MAX_PATH], NtDir[MAX_PATH + 8];
static char Text[8192];

static const char *FindNoCase(const char *Haystack, const char *Needle)
{
    size_t Length = strlen(Needle);

    for (; *Haystack; Haystack++)
    {
        if (!_strnicmp(Haystack, Needle, Length))
            return Haystack;
    }
    return NULL;
}

static BOOL WriteIni(const char *ListExtra, const char *SectionExtra)
{
    HANDLE File;
    DWORD Written;
    char Buffer[4096];

    /* Setup saves the file hidden, system and read-only */
    SetFileAttributesW(IniFile, FILE_ATTRIBUTE_NORMAL);
    File = CreateFileW(IniFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    _snprintf(Buffer, sizeof(Buffer), "%s%s%s%s", Head, ListExtra, Sections, SectionExtra);
    WriteFile(File, Buffer, (DWORD)strlen(Buffer), &Written, NULL);
    CloseHandle(File);
    return TRUE;
}

/* The file with the head as above and the sections as given */
static BOOL WriteWithSections(const char *OwnSections)
{
    HANDLE File;
    DWORD Written;
    char Buffer[4096];

    SetFileAttributesW(IniFile, FILE_ATTRIBUTE_NORMAL);
    File = CreateFileW(IniFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    _snprintf(Buffer, sizeof(Buffer), "%s%s", Head, OwnSections);
    WriteFile(File, Buffer, (DWORD)strlen(Buffer), &Written, NULL);
    CloseHandle(File);
    return TRUE;
}

static BOOL ReadIni(void)
{
    HANDLE File = CreateFileW(IniFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD Read = 0;

    Text[0] = 0;
    if (File == INVALID_HANDLE_VALUE)
        return FALSE;
    ReadFile(File, Text, sizeof(Text) - 1, &Read, NULL);
    Text[Read] = 0;
    CloseHandle(File);
    return TRUE;
}

/* Number of lines that start with Prefix (case-insensitive) */
static int Lines(const char *Prefix)
{
    const char *Line = Text;
    size_t Length = strlen(Prefix);
    int Count = 0;

    while (*Line)
    {
        if (!_strnicmp(Line, Prefix, Length))
            Count++;
        Line = strchr(Line, '\n');
        if (!Line)
            break;
        Line++;
    }
    return Count;
}

/* The value of Key in Section, or "" */
static const char *Value(const char *Section, const char *Key, char *Out, size_t OutSize)
{
    char Header[64];
    const char *Line, *End;
    size_t KeyLength = strlen(Key);

    Out[0] = 0;
    _snprintf(Header, sizeof(Header), "[%s]", Section);
    Line = FindNoCase(Text, Header);
    if (!Line)
        return Out;
    for (Line = strchr(Line, '\n'); Line && *++Line && *Line != '['; Line = strchr(Line, '\n'))
    {
        if (!_strnicmp(Line, Key, KeyLength) && Line[KeyLength] == '=')
        {
            Line += KeyLength + 1;
            End = Line + strcspn(Line, "\r\n");
            _snprintf(Out, OutSize, "%.*s", (int)(End - Line), Line);
            break;
        }
    }
    return Out;
}

static NTSTATUS Update(PCWSTR ArcPath)
{
    return UpdateFreeLoaderIni(NtDir, ArcPath);
}

#define ARC_AW L"multi(0)disk(0)rdisk(0)partition(1)\\ReactOS"
#define ARC_BW L"multi(0)disk(0)rdisk(0)partition(2)\\Other"

START_TEST(FreeLdrIniUpdate)
{
    WCHAR Temp[MAX_PATH];
    char Buffer[256];
    NTSTATUS Status;
#ifdef NITRO_KDKIT
    const int Kit = 1;
#else
    const int Kit = 0;
#endif

    ProcessHeap = RtlGetProcessHeap();
    GetTempPathW(_countof(Temp), Temp);
    _snwprintf(Dir, _countof(Dir), L"%lsfldrini%lu", Temp, GetCurrentProcessId());
    CreateDirectoryW(Dir, NULL);
    _snwprintf(IniFile, _countof(IniFile), L"%ls\\freeldr.ini", Dir);
    _snwprintf(NtDir, _countof(NtDir), L"\\??\\%ls", Dir);

    /* An existing freeldr.ini without the entry (repair or upgrade of an older installation): it is added after the
     * others, the default entry and the timeout stay */
    ok(WriteIni("", ""), "cannot write %ls\n", IniFile);
    Status = Update(ARC_AW);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIni 0x%08lx\n", Status);
    ok(ReadIni(), "cannot read the result\n");
    ok(Lines("[ReactOS_KdKit]") == Kit, "missing: %d kit sections\n", Lines("[ReactOS_KdKit]"));
    ok(Lines("ReactOS_KdKit=") == Kit, "missing: %d kit entries in the list\n", Lines("ReactOS_KdKit="));
    ok(Lines("[ReactOS]") == 1 && Lines("[ReactOS_1]") == 0, "missing: the installation's entry was added again\n");
    ok(!strcmp(Value("FREELOADER", "DefaultOS", Buffer, sizeof(Buffer)), "ReactOS"), "DefaultOS is '%s'\n", Buffer);
    ok(!strcmp(Value("FREELOADER", "TimeOut", Buffer, sizeof(Buffer)), "5"), "TimeOut is '%s'\n", Buffer);
    if (Kit)
    {
        ok(!strcmp(Value("ReactOS_KdKit", "SystemPath", Buffer, sizeof(Buffer)), ARC_A), "kit SystemPath '%s'\n", Buffer);
        ok(FindNoCase(Value("ReactOS_KdKit", "Options", Buffer, sizeof(Buffer)), "/KERNEL=ntkrnlkd.exe") != NULL,
           "kit Options '%s'\n", Buffer);
    }

    /* Setup over that again: no second entry */
    Status = Update(ARC_AW);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIni (again) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_KdKit]") == Kit, "present: %d kit sections\n", Lines("[ReactOS_KdKit]"));
    ok(Lines("ReactOS_KdKit=") == Kit, "present: %d kit entries in the list\n", Lines("ReactOS_KdKit="));

    /* An entry the user edited (another name, port and speed, other case of the key): left as it is */
    ok(WriteIni("reactos_kdkit=\"My debug entry\"\r\n",
                "\r\n[reactos_kdkit]\r\nBootType=Windows2003\r\nSystemPath=" ARC_A "\r\n"
                "Options=/KERNEL=ntkrnlkd.exe /DEBUG /DEBUGPORT=COM2 /BAUDRATE=57600\r\n"), "cannot write %ls\n", IniFile);
    Status = Update(ARC_AW);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIni (edited) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_KdKit]") == 1, "edited: %d kit sections\n", Lines("[ReactOS_KdKit]"));
    ok(Lines("ReactOS_KdKit=") == 1, "edited: %d kit entries in the list\n", Lines("ReactOS_KdKit="));
    ok(FindNoCase(Text, "\"My debug entry\"") != NULL, "edited: the user's name is gone\n");
    ok(FindNoCase(Value("ReactOS_KdKit", "Options", Buffer, sizeof(Buffer)), "COM2 /BAUDRATE=57600") != NULL,
       "edited: Options '%s'\n", Buffer);

    /* A second installation on another partition: its own entry, and the kit entry for it when there is none */
    ok(WriteIni("", ""), "cannot write %ls\n", IniFile);
    Status = Update(ARC_BW);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIni (second) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_1]") == 1, "second: %d entries ReactOS_1\n", Lines("[ReactOS_1]"));
    ok(Lines("[ReactOS_KdKit]") == Kit, "second: %d kit sections\n", Lines("[ReactOS_KdKit]"));
    if (Kit)
        ok(!strcmp(Value("ReactOS_KdKit", "SystemPath", Buffer, sizeof(Buffer)), ARC_B), "second: kit SystemPath '%s'\n", Buffer);
    ok(!strcmp(Value("FREELOADER", "DefaultOS", Buffer, sizeof(Buffer)), "ReactOS"), "second: DefaultOS is '%s'\n", Buffer);

    /* A second installation (GPT) whose partition has the position the first one's entries still hold in their path:
     * those entries name the first partition by its GUID, they are not reused, an entry of its own is added and the
     * first installation's entries keep their GUID */
    ok(WriteWithSections(
                "\r\n[ReactOS]\r\nBootType=Windows2003\r\nSystemPath=" ARC_A "\r\nOptions=/FASTDETECT\r\n"
                "SystemPathPartitionGuid=" GUID_1 "\r\n"
                "\r\n[ReactOS_Debug]\r\nBootType=Windows2003\r\nSystemPath=" ARC_A "\r\nOptions=/DEBUG\r\n"
                "SystemPathPartitionGuid=" GUID_1 "\r\n"), "cannot write %ls\n", IniFile);
    Status = UpdateFreeLoaderIniForIdentity(NtDir, ARC_AW, GUID_2W, DISK_W, RANGE_W);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIniForIdentity (other GUID) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_1]") == 1, "other GUID: %d entries ReactOS_1\n", Lines("[ReactOS_1]"));
    ok(!strcmp(Value("ReactOS_1", "SystemPath", Buffer, sizeof(Buffer)), ARC_A), "other GUID: SystemPath '%s'\n", Buffer);
    ok(!strcmp(Value("ReactOS", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_1),
       "other GUID: the first entry's GUID is '%s'\n", Buffer);
    ok(!strcmp(Value("ReactOS_Debug", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_1),
       "other GUID: the debug entry's GUID is '%s'\n", Buffer);
    ok(!strcmp(Value("FREELOADER", "DefaultOS", Buffer, sizeof(Buffer)), "ReactOS"), "other GUID: DefaultOS is '%s'\n", Buffer);

    /* Setup over it again for the second installation: its entry is found, no third one */
    Status = UpdateFreeLoaderIniForIdentity(NtDir, ARC_AW, GUID_2W, DISK_W, RANGE_W);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIniForIdentity (again) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_1]") == 1 && Lines("[ReactOS_2]") == 0, "other GUID, again: %d ReactOS_1, %d ReactOS_2\n",
       Lines("[ReactOS_1]"), Lines("[ReactOS_2]"));

    /* The partition of the first installation itself: its entry is reused (a repair or an upgrade) */
    ok(WriteWithSections(
                "\r\n[ReactOS]\r\nBootType=Windows2003\r\nSystemPath=" ARC_A "\r\nOptions=/FASTDETECT\r\n"
                "SystemPathPartitionGuid=" GUID_1 "\r\n"), "cannot write %ls\n", IniFile);
    Status = UpdateFreeLoaderIniForPartition(NtDir, ARC_AW, GUID_1W);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIniForPartition (same GUID) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS]") == 1 && Lines("[ReactOS_1]") == 0, "same GUID: %d ReactOS, %d ReactOS_1\n",
       Lines("[ReactOS]"), Lines("[ReactOS_1]"));

    /* No GUID known (a BIOS install): the entries are matched by their path, as before */
    Status = UpdateFreeLoaderIniForPartition(NtDir, ARC_AW, NULL);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIniForPartition (no GUID) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_1]") == 0, "no GUID: %d entries ReactOS_1\n", Lines("[ReactOS_1]"));

    /*
     * Entries written before the GUID keys existed (install 1, a table change, then install 2 onto the position that
     * the old entries still name). Without anything known about them they are not ours: an entry of its own is added
     * (with the keys, also the kit entry when it is added), the old ones stay byte for byte.
     */
    FreeLdrForgetPendingIdentities();
    ok(WriteIni("", ""), "cannot write %ls\n", IniFile);
    Status = UpdateFreeLoaderIniForIdentity(NtDir, ARC_AW, GUID_2W, DISK_W, RANGE_W);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIniForIdentity (keyless) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_1]") == 1, "keyless: %d entries ReactOS_1\n", Lines("[ReactOS_1]"));
    ok(!strcmp(Value("ReactOS_1", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_2),
       "keyless: the new entry's GUID is '%s'\n", Buffer);
    ok(!strcmp(Value("ReactOS_1", "SystemPathPartitionRange", Buffer, sizeof(Buffer)), RANGE),
       "keyless: the new entry's range is '%s'\n", Buffer);
    ok(!strcmp(Value("ReactOS", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), ""),
       "keyless: the old entry got the GUID '%s'\n", Buffer);
    ok(!strcmp(Value("ReactOS_Debug", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), ""),
       "keyless: the old debug entry got the GUID '%s'\n", Buffer);
    ok(Lines("SystemPathPartitionGuid=") == 1 + Kit, "keyless: %d GUID keys\n", Lines("SystemPathPartitionGuid="));
    if (Kit)
    {
        ok(!strcmp(Value("ReactOS_KdKit", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_2),
           "keyless: the kit entry's GUID is '%s'\n", Buffer);
    }

    /* The same entries, but Setup identified their partition before the table changed: they get the keys once and
     * are then told apart from the entries of another partition by them */
    {
        PVOID Store;
        GUID Part1 = { 0x11111111, 0x2222, 0x4333, { 0x84, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 } };
        GUID Disk = { 0xCCCCCCCC, 0xDDDD, 0x4EEE, { 0x8F, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

        FreeLdrForgetPendingIdentities();
        ok(FreeLdrAddPendingIdentity(ARC_AW, &Part1, &Disk, 10, 20), "cannot register the identity\n");
        ok(FreeLdrAddPendingIdentity(ARC_AW, &Part1, &Disk, 30, 40), "cannot register the identity again\n");
        ok(WriteIni("", ""), "cannot write %ls\n", IniFile);
        Status = OpenBootStore(&Store, NtDir, FreeLdr, BS_OpenExisting, BS_ReadWriteAccess);
        ok(Status == STATUS_SUCCESS, "OpenBootStore 0x%08lx\n", Status);
        if (NT_SUCCESS(Status))
        {
            Status = FreeLdrApplyPendingIdentities(Store);
            ok(Status == STATUS_SUCCESS, "FreeLdrApplyPendingIdentities 0x%08lx\n", Status);
            CloseBootStore(Store);
        }
        ReadIni();
        ok(!strcmp(Value("ReactOS", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_1),
           "identified: GUID of the entry '%s'\n", Buffer);
        ok(!strcmp(Value("ReactOS_Debug", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_1),
           "identified: GUID of the debug entry '%s'\n", Buffer);
        ok(!strcmp(Value("ReactOS", "SystemPathPartitionRange", Buffer, sizeof(Buffer)), "10-20"),
           "identified: the first registration counts, range '%s'\n", Buffer);
        ok(!_stricmp(Value("ReactOS", "SystemPathDiskGuid", Buffer, sizeof(Buffer)), DISK_1),
           "identified: disk GUID '%s'\n", Buffer);
        FreeLdrForgetPendingIdentities();
    }

    /* the partition of the entries: they are reused, no second set */
    Status = UpdateFreeLoaderIniForIdentity(NtDir, ARC_AW, GUID_1W, DISK_W, RANGE_W);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIniForIdentity (identified, same) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_1]") == 0, "identified, same partition: %d entries ReactOS_1\n", Lines("[ReactOS_1]"));

    /* another partition with the same position (a new install): its own entry, the identified ones keep theirs */
    Status = UpdateFreeLoaderIniForIdentity(NtDir, ARC_AW, GUID_2W, DISK_W, RANGE_W);
    ok(Status == STATUS_SUCCESS, "UpdateFreeLoaderIniForIdentity (identified, other) 0x%08lx\n", Status);
    ReadIni();
    ok(Lines("[ReactOS_1]") == 1, "identified, other partition: %d entries ReactOS_1\n", Lines("[ReactOS_1]"));
    ok(!strcmp(Value("ReactOS", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_1),
       "identified, other partition: the old GUID is '%s'\n", Buffer);
    ok(!strcmp(Value("ReactOS_1", "SystemPathPartitionGuid", Buffer, sizeof(Buffer)), GUID_2),
       "identified, other partition: the new GUID is '%s'\n", Buffer);

    SetFileAttributesW(IniFile, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(IniFile);
    RemoveDirectoryW(Dir);
}
