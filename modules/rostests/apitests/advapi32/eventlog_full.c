/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Event log default size and retention, and what a full log does to a writer
 */

#include "precomp.h"
#include <evtlib.h>

/* ERROR_LOG_FILE_FULL (1502) is "The event log file is full" */
#define LOG_MAX_SIZE 0x20000 /* 128 KB */
#define LOG_FILE_SIZE 0x80000

static DWORD get_dword(const WCHAR *log, const WCHAR *name, DWORD *value)
{
    WCHAR path[128];
    HKEY key;
    DWORD size = sizeof(*value), type;
    LONG ret;

    StringCchPrintfW(path, ARRAYSIZE(path), L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\%s", log);
    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &key);
    if (ret) return ret;
    ret = RegQueryValueExW(key, name, NULL, &type, (BYTE *)value, &size);
    RegCloseKey(key);
    return ret ? ret : type == REG_DWORD ? 0 : ERROR_INVALID_DATA;
}

static void test_default_settings(void)
{
    static const WCHAR *logs[] = { L"Application", L"System", L"Security" };
    DWORD value, i, count;
    HANDLE log;
    BYTE *data;

    /* Windows 10: Application, System and Security are 20 MB and events are overwritten as needed */
    for (i = 0; i < ARRAYSIZE(logs); i++)
    {
        value = 0;
        ok(!get_dword(logs[i], L"MaxSize", &value), "%ls: no MaxSize value\n", logs[i]);
        ok(value == 20 * 1024 * 1024, "%ls: MaxSize is %lu, expected %u\n", logs[i], value, 20 * 1024 * 1024);
        value = 0xdeadbeef;
        ok(!get_dword(logs[i], L"Retention", &value), "%ls: no Retention value\n", logs[i]);
        ok(value == 0, "%ls: Retention is %lu, expected 0\n", logs[i], value);
    }

    /* About 6 MB of events (more than the 5 MB the log file had before) into the Application log (an unknown source goes there): all of them succeed */
    log = RegisterEventSourceW(NULL, L"EvtFullDefaultSrc");
    ok(log != NULL, "RegisterEventSourceW failed with error %lu\n", GetLastError());
    data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1000);
    if (!log || !data) goto done;
    memset(data, 0x5a, 1000);
    for (count = 0; count < 6000; count++)
    {
        SetLastError(0xdeadbeef);
        if (!ReportEventW(log, EVENTLOG_INFORMATION_TYPE, 0, 1, NULL, 0, 1000, NULL, data)) break;
    }
    ok(count == 6000, "only %lu of 6000 events written, error %lu\n", count, GetLastError());
done:
    HeapFree(GetProcessHeap(), 0, data);
    if (log) DeregisterEventSource(log);
}

/* The file engine of the event log service over a memory buffer */
static BYTE *file_buffer;

static PVOID NTAPI mem_alloc(SIZE_T size, ULONG flags, ULONG tag)
{
    return HeapAlloc(GetProcessHeap(), flags, size);
}

static VOID NTAPI mem_free(PVOID ptr, ULONG flags, ULONG tag)
{
    HeapFree(GetProcessHeap(), flags, ptr);
}

static ULONG file_size;

static NTSTATUS NTAPI mem_set_size(PEVTLOGFILE file, ULONG size, ULONG old_size)
{
    if (size > LOG_FILE_SIZE) return STATUS_DISK_FULL;
    file_size = size;
    return STATUS_SUCCESS;
}

/* a NULL offset continues after the previous transfer, as with a file handle */
static ULONGLONG file_pos;

static NTSTATUS NTAPI mem_write(PEVTLOGFILE file, PLARGE_INTEGER offset, PVOID buffer, SIZE_T length, PSIZE_T written)
{
    ULONGLONG pos = offset ? offset->QuadPart : file_pos;

    if (pos + length > LOG_FILE_SIZE) return STATUS_DISK_FULL;
    memcpy(file_buffer + pos, buffer, length);
    file_pos = pos + length;
    if (written) *written = length;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI mem_read(PEVTLOGFILE file, PLARGE_INTEGER offset, PVOID buffer, SIZE_T length, PSIZE_T read)
{
    ULONGLONG pos = offset ? offset->QuadPart : file_pos;

    if (pos + length > file_size) return STATUS_END_OF_FILE;
    memcpy(buffer, file_buffer + pos, length);
    file_pos = pos + length;
    if (read) *read = length;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI mem_flush(PEVTLOGFILE file, PLARGE_INTEGER offset, ULONG length)
{
    return STATUS_SUCCESS;
}

#define RECORD_DATA 1000

static NTSTATUS write_record(EVTLOGFILE *file, ULONG now)
{
    BYTE buffer[sizeof(EVENTLOGRECORD) + RECORD_DATA + sizeof(ULONG)];
    EVENTLOGRECORD *rec = (EVENTLOGRECORD *)buffer;

    memset(buffer, 0, sizeof(buffer));
    rec->Length = sizeof(buffer);
    rec->Reserved = LOGFILE_SIGNATURE;
    rec->TimeGenerated = now;
    rec->TimeWritten = now;
    rec->EventID = 1;
    rec->EventType = EVENTLOG_INFORMATION_TYPE;
    rec->StringOffset = sizeof(EVENTLOGRECORD);
    rec->UserSidOffset = sizeof(EVENTLOGRECORD);
    rec->DataLength = RECORD_DATA;
    rec->DataOffset = sizeof(EVENTLOGRECORD);
    memset(buffer + sizeof(EVENTLOGRECORD), 0x5a, RECORD_DATA);
    *(ULONG *)(buffer + sizeof(buffer) - sizeof(ULONG)) = sizeof(buffer);
    return ElfWriteRecord(file, rec, sizeof(buffer));
}

/* Returns the number of records written before the first failure, *status is that failure */
static ULONG fill_log(ULONG retention, ULONG count, NTSTATUS *status, ULONG *oldest, ULONG *current)
{
    EVTLOGFILE file;
    LARGE_INTEGER time;
    ULONG now, i;
    NTSTATUS ret;

    memset(file_buffer, 0, LOG_FILE_SIZE);
    file_pos = 0;
    file_size = 0;
    GetSystemTimeAsFileTime((FILETIME *)&time);
    RtlTimeToSecondsSince1970(&time, &now);

    *status = STATUS_SUCCESS;
    ret = ElfCreateFile(&file, NULL, 0, LOG_MAX_SIZE, retention, TRUE, FALSE,
                        mem_alloc, mem_free, mem_set_size, mem_write, mem_read, mem_flush);
    ok(ret == STATUS_SUCCESS, "ElfCreateFile returned %#lx\n", ret);
    if (ret) return 0;

    for (i = 0; i < count; i++)
    {
        ret = write_record(&file, now);
        if (ret) { *status = ret; break; }
    }
    *oldest = ElfGetOldestRecord(&file);
    *current = ElfGetCurrentRecord(&file);
    ElfCloseFile(&file);
    return i;
}

static void test_full_log(void)
{
    NTSTATUS status;
    ULONG written, oldest, current;

    file_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LOG_FILE_SIZE);
    ok(file_buffer != NULL, "no memory\n");
    if (!file_buffer) return;

    /* Retention 0: overwrite as needed. 600 KB into a 128 KB log: every write succeeds, the oldest record moves on */
    written = fill_log(0, 600, &status, &oldest, &current);
    ok(status == STATUS_SUCCESS, "retention 0: write %lu returned %#lx\n", written, status);
    ok(written == 600, "retention 0: %lu of 600 records written\n", written);
    ok(current == 601, "retention 0: next record number %lu, expected 601\n", current);
    ok(oldest > 1 && oldest < current, "retention 0: oldest record %lu, expected the log to have wrapped\n", oldest);
    ok(current - oldest < 600 && (current - oldest) * (sizeof(EVENTLOGRECORD) + RECORD_DATA + sizeof(ULONG)) <= LOG_MAX_SIZE, "retention 0: %lu records kept in a 128 KB log\n", current - oldest);

    /* Retention -1: never overwrite. The log fills up and the writer is told so (ERROR_LOG_FILE_FULL) */
    written = fill_log(0xffffffff, 600, &status, &oldest, &current);
    ok(status == STATUS_LOG_FILE_FULL, "retention -1: status %#lx, expected %#lx\n", status, STATUS_LOG_FILE_FULL);
    ok(written > 0 && written < 600, "retention -1: %lu of 600 records written\n", written);
    ok(oldest == 1, "retention -1: oldest record %lu, expected 1\n", oldest);
    ok(RtlNtStatusToDosError(STATUS_LOG_FILE_FULL) == ERROR_LOG_FILE_FULL, "STATUS_LOG_FILE_FULL maps to %lu\n",
       RtlNtStatusToDosError(STATUS_LOG_FILE_FULL));

    /* Retention 7 days (the old default): events younger than that are not overwritten, so the log is full too */
    written = fill_log(604800, 600, &status, &oldest, &current);
    ok(status == STATUS_LOG_FILE_FULL, "retention 7 days: status %#lx, expected %#lx\n", status, STATUS_LOG_FILE_FULL);
    ok(written > 0 && written < 600, "retention 7 days: %lu of 600 records written\n", written);

    HeapFree(GetProcessHeap(), 0, file_buffer);
}

#define RECORD_SIZE (sizeof(EVENTLOGRECORD) + RECORD_DATA + sizeof(ULONG))

/* Number of records from oldest to current - 1 that read back whole */
static ULONG count_good_records(EVTLOGFILE *file, ULONG oldest, ULONG current)
{
    BYTE buffer[RECORD_SIZE + 64];
    EVENTLOGRECORD *rec = (EVENTLOGRECORD *)buffer;
    SIZE_T read;
    ULONG num, good = 0;

    for (num = oldest; num != current; num++)
    {
        memset(buffer, 0, sizeof(buffer));
        if (ElfReadRecord(file, num, rec, sizeof(buffer), &read, NULL)) break;
        if (rec->RecordNumber != num || rec->Length != RECORD_SIZE ||
            buffer[sizeof(EVENTLOGRECORD)] != 0x5a || buffer[sizeof(EVENTLOGRECORD) + RECORD_DATA - 1] != 0x5a) break;
        good++;
    }
    return good;
}

/* Opens the log the memory buffer holds, as the service does at its start */
static NTSTATUS open_log(EVTLOGFILE *file, ULONG max_size, ULONG retention)
{
    file_pos = 0;
    return ElfCreateFile(file, NULL, file_size, max_size, retention, FALSE, FALSE,
                         mem_alloc, mem_free, mem_set_size, mem_write, mem_read, mem_flush);
}

/* Writes up to count records, returns how many were written */
static ULONG append_records(EVTLOGFILE *file, ULONG count, NTSTATUS *status)
{
    LARGE_INTEGER time;
    ULONG now, i;

    GetSystemTimeAsFileTime((FILETIME *)&time);
    RtlTimeToSecondsSince1970(&time, &now);
    *status = STATUS_SUCCESS;
    for (i = 0; i < count; i++)
    {
        *status = write_record(file, now);
        if (*status) break;
    }
    return i;
}

/* A log file that exists is opened with the MaxSize and Retention of the registry */
static void test_existing_log(void)
{
    EVTLOGFILE file;
    NTSTATUS status, ret;
    ULONG written, oldest, current, kept, good, size_before;

    file_buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, LOG_FILE_SIZE);
    ok(file_buffer != NULL, "no memory\n");
    if (!file_buffer) return;

    /* Full 128 KB log with the 7 days of the old default, none of it can be overwritten */
    fill_log(604800, 600, &status, &oldest, &current);
    ok(status == STATUS_LOG_FILE_FULL, "old log: status %#lx\n", status);
    kept = current - oldest;
    size_before = file_size;
    ok(size_before == LOG_MAX_SIZE, "old log: file size %#lx\n", size_before);

    /* Opened with 384 KB and Retention 0: the records are there, the log has room and then overwrites */
    ret = open_log(&file, 3 * LOG_MAX_SIZE, 0);
    ok(ret == STATUS_SUCCESS, "reopen returned %#lx\n", ret);
    if (!ret)
    {
        ok(ElfGetOldestRecord(&file) == oldest && ElfGetCurrentRecord(&file) == current,
           "grown log: records %lu-%lu, expected %lu-%lu\n", ElfGetOldestRecord(&file), ElfGetCurrentRecord(&file), oldest, current);
        good = count_good_records(&file, oldest, current);
        ok(good == kept, "grown log: %lu of %lu records read back\n", good, kept);
        written = append_records(&file, 600, &status);
        ok(status == STATUS_SUCCESS && written == 600, "grown log: write %lu returned %#lx\n", written, status);
        oldest = ElfGetOldestRecord(&file);
        current = ElfGetCurrentRecord(&file);
        ok(current - oldest > kept, "grown log: %lu records kept, was %lu in 128 KB\n", current - oldest, kept);
        ok(current - oldest <= 3 * LOG_MAX_SIZE / RECORD_SIZE, "grown log: %lu records kept in 384 KB\n", current - oldest);
        good = count_good_records(&file, oldest, current);
        ok(good == current - oldest, "grown log: %lu of %lu records read back\n", good, current - oldest);
        ok(file_size > size_before && file_size <= 3 * LOG_MAX_SIZE, "grown log: file size %#lx\n", file_size);
        ElfCloseFile(&file);

        /* and the log it left is a good one */
        ret = open_log(&file, 3 * LOG_MAX_SIZE, 0);
        ok(ret == STATUS_SUCCESS, "reopen of the grown log returned %#lx\n", ret);
        if (!ret)
        {
            ok(ElfGetOldestRecord(&file) == oldest && ElfGetCurrentRecord(&file) == current,
               "grown log: records %lu-%lu after reopen, expected %lu-%lu\n", ElfGetOldestRecord(&file), ElfGetCurrentRecord(&file), oldest, current);
            good = count_good_records(&file, oldest, current);
            ok(good == current - oldest, "grown log: %lu of %lu records read back after reopen\n", good, current - oldest);
            ElfCloseFile(&file);
        }
    }

    /* Retention 0 log that wrapped: the oldest records are in the last part of the file */
    fill_log(0, 600, &status, &oldest, &current);
    kept = current - oldest;
    ret = open_log(&file, 3 * LOG_MAX_SIZE, 0);
    ok(ret == STATUS_SUCCESS, "reopen of the wrapped log returned %#lx\n", ret);
    if (!ret)
    {
        ok(ElfGetOldestRecord(&file) == oldest && ElfGetCurrentRecord(&file) == current,
           "wrapped log: records %lu-%lu, expected %lu-%lu\n", ElfGetOldestRecord(&file), ElfGetCurrentRecord(&file), oldest, current);
        good = count_good_records(&file, oldest, current);
        ok(good == kept, "wrapped log: %lu of %lu records read back\n", good, kept);
        written = append_records(&file, 100, &status);
        ok(status == STATUS_SUCCESS && written == 100, "wrapped log: write %lu returned %#lx\n", written, status);
        oldest = ElfGetOldestRecord(&file);
        current = ElfGetCurrentRecord(&file);
        ok(current - oldest > kept, "wrapped log: %lu records kept, was %lu in 128 KB\n", current - oldest, kept);
        good = count_good_records(&file, oldest, current);
        ok(good == current - oldest, "wrapped log: %lu of %lu records read back\n", good, current - oldest);
        written = append_records(&file, 600, &status);
        ok(status == STATUS_SUCCESS && written == 600, "wrapped log: write %lu returned %#lx\n", written, status);
        oldest = ElfGetOldestRecord(&file);
        current = ElfGetCurrentRecord(&file);
        good = count_good_records(&file, oldest, current);
        ok(good == current - oldest && current - oldest > kept, "wrapped log: %lu of %lu records read back\n", good, current - oldest);
        ElfCloseFile(&file);

        ret = open_log(&file, 3 * LOG_MAX_SIZE, 0);
        ok(ret == STATUS_SUCCESS, "reopen of the grown wrapped log returned %#lx\n", ret);
        if (!ret)
        {
            ok(ElfGetOldestRecord(&file) == oldest && ElfGetCurrentRecord(&file) == current,
               "wrapped log: records %lu-%lu after reopen, expected %lu-%lu\n", ElfGetOldestRecord(&file), ElfGetCurrentRecord(&file), oldest, current);
            good = count_good_records(&file, oldest, current);
            ok(good == current - oldest, "wrapped log: %lu of %lu records read back after reopen\n", good, current - oldest);
            ElfCloseFile(&file);
        }
    }

    /* A MaxSize below the size of the file does not truncate it: the records stay and the file stays as it is */
    fill_log(0, 600, &status, &oldest, &current);
    kept = current - oldest;
    size_before = file_size;
    ret = open_log(&file, LOG_MAX_SIZE / 2, 0);
    ok(ret == STATUS_SUCCESS, "reopen with a lower size returned %#lx\n", ret);
    if (!ret)
    {
        ok(ElfGetOldestRecord(&file) == oldest && ElfGetCurrentRecord(&file) == current,
           "lowered log: records %lu-%lu, expected %lu-%lu\n", ElfGetOldestRecord(&file), ElfGetCurrentRecord(&file), oldest, current);
        good = count_good_records(&file, oldest, current);
        ok(good == kept, "lowered log: %lu of %lu records read back\n", good, kept);
        written = append_records(&file, 300, &status);
        ok(status == STATUS_SUCCESS && written == 300, "lowered log: write %lu returned %#lx\n", written, status);
        ok(file_size == size_before, "lowered log: file size %#lx, was %#lx\n", file_size, size_before);
        oldest = ElfGetOldestRecord(&file);
        current = ElfGetCurrentRecord(&file);
        ok(current - oldest <= kept + 1, "lowered log: %lu records kept in the %#lx bytes of the file\n", current - oldest, size_before);
        good = count_good_records(&file, oldest, current);
        ok(good == current - oldest, "lowered log: %lu of %lu records read back\n", good, current - oldest);
        ElfCloseFile(&file);
    }

    HeapFree(GetProcessHeap(), 0, file_buffer);
}

START_TEST(eventlog_full)
{
    test_default_settings();
    test_full_log();
    test_existing_log();
}
