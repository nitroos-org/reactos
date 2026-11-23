/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Uart16550GetByte: a character received with a framing or parity error
 *
 * The error flags of the LSR belong to the character at the front of the receive FIFO.  The library reports
 * CP_GET_ERROR; the character has to go out of the FIFO then, or the next call hands it out as data (flags
 * that the LSR read reset) or reports the error again for ever (flags that stay with the character).
 */

#include <windows.h>
#include "wine/test.h"

#define CP_GET_SUCCESS  0
#define CP_GET_NODATA   1
#define CP_GET_ERROR    2

VOID UartMockReset(BOOLEAN Sticky);
VOID UartMockPush(UCHAR Data, UCHAR Errors);
VOID UartMockOverrun(VOID);
ULONG UartMockLeft(VOID);
USHORT UartMockGetByte(PUCHAR Byte, BOOLEAN Wait, BOOLEAN Poll);

static void TestErrorByte(BOOLEAN Sticky, UCHAR Errors)
{
    UCHAR Byte;
    USHORT Status;
    ULONG i;

    UartMockReset(Sticky);
    UartMockPush('A', 0);
    UartMockPush('B', Errors);
    UartMockPush('C', 0);

    Status = UartMockGetByte(&Byte, FALSE, FALSE);
    ok(Status == CP_GET_SUCCESS && Byte == 'A', "1st: status %u byte 0x%02x\n", Status, Byte);

    Status = UartMockGetByte(&Byte, FALSE, FALSE);
    ok(Status == CP_GET_ERROR, "2nd (flagged '%c', sticky %d): status %u\n", Errors, Sticky, Status);
    ok(Byte == 0, "2nd: byte 0x%02x\n", Byte);

    /* The flagged character is gone: the next one is the third. A bounded loop, the old code never leaves the error. */
    for (i = 0; i < 4; i++)
    {
        Status = UartMockGetByte(&Byte, FALSE, FALSE);
        if (Status != CP_GET_ERROR)
            break;
    }
    ok(Status == CP_GET_SUCCESS && Byte == 'C', "3rd (flagged '%c', sticky %d): status %u byte 0x%02x after %lu errors\n",
       Errors, Sticky, Status, Byte, i);

    Status = UartMockGetByte(&Byte, FALSE, FALSE);
    ok(Status == CP_GET_NODATA, "4th: status %u\n", Status);
}

START_TEST(Uart16550GetByte)
{
    UCHAR Byte;
    USHORT Status;

    TestErrorByte(FALSE, 'f');
    TestErrorByte(FALSE, 'p');
    TestErrorByte(TRUE, 'f');
    TestErrorByte(TRUE, 'p');

    /* An overrun is not the front character's error: it is reported once and that character is still there. */
    UartMockReset(FALSE);
    UartMockPush('A', 0);
    UartMockPush('B', 0);
    UartMockOverrun();
    Status = UartMockGetByte(&Byte, FALSE, FALSE);
    ok(Status == CP_GET_ERROR, "overrun: status %u\n", Status);
    ok(UartMockLeft() == 2, "overrun: %lu characters left, 2 expected\n", UartMockLeft());
    Status = UartMockGetByte(&Byte, FALSE, FALSE);
    ok(Status == CP_GET_SUCCESS && Byte == 'A', "after the overrun: status %u byte 0x%02x\n", Status, Byte);

    /* A caller that only polls does not take the character out. */
    UartMockReset(FALSE);
    UartMockPush('B', 'f');
    Status = UartMockGetByte(&Byte, FALSE, TRUE);
    ok(Status == CP_GET_ERROR, "poll: status %u\n", Status);
    ok(UartMockLeft() == 1, "poll: %lu characters left, 1 expected\n", UartMockLeft());

    /* Nothing received. */
    UartMockReset(FALSE);
    Status = UartMockGetByte(&Byte, FALSE, FALSE);
    ok(Status == CP_GET_NODATA, "empty: status %u\n", Status);
}
