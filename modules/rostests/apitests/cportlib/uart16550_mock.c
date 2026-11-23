/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     The 16550 code of the COM port library (sdk/lib/cportlib/ns16550.c) on a model of the UART
 *
 * The register accesses of the library are redirected to a model of the receive side of a 16550: a FIFO of
 * characters, each with the error flags of its own, the LSR with the data ready flag and the flags of the
 * character at the front, the receive buffer register that takes the front character out.  This file includes
 * the library source and shares no header with the test (the library uses the native headers).
 */

#define NO_PORT_MACROS
#define READ_PORT_UCHAR(p)      MockReadPort((PUCHAR)(p))
#define WRITE_PORT_UCHAR(p, v)  MockWritePort((PUCHAR)(p), (UCHAR)(v))

#include <ntdef.h>

static UCHAR MockReadPort(PUCHAR Port);
static VOID MockWritePort(PUCHAR Port, UCHAR Value);

#include "../../../../sdk/lib/cportlib/ns16550.c"

#define MOCK_BASE ((PUCHAR)(ULONG_PTR)0x3F8)

static struct
{
    UCHAR Data;
    UCHAR Flags;    /* SERIAL_LSR_PE | SERIAL_LSR_FE of the character */
} MockFifo[32];
static ULONG MockCount, MockHead;
static BOOLEAN MockSticky;
static UCHAR MockOverrun;
static ULONG MockRbrReads;

static UCHAR MockReadPort(PUCHAR Port)
{
    UCHAR Lsr;
    ULONG Offset = (ULONG)(Port - MOCK_BASE);

    if (Offset == LINE_STATUS_REGISTER)
    {
        Lsr = 0x60; /* THRE | TEMT */
        if (MockHead < MockCount)
        {
            Lsr |= SERIAL_LSR_DR | MockFifo[MockHead].Flags;
            /* Reading the LSR resets the error flags; they belong to the character, which stays. */
            if (!MockSticky)
                MockFifo[MockHead].Flags = 0;
        }
        Lsr |= MockOverrun;
        MockOverrun = 0;
        return Lsr;
    }
    if (Offset == RECEIVE_BUFFER_REGISTER)
    {
        MockRbrReads++;
        return (MockHead < MockCount) ? MockFifo[MockHead++].Data : 0;
    }
    return 0;
}

static VOID MockWritePort(PUCHAR Port, UCHAR Value)
{
}

VOID UartMockReset(BOOLEAN Sticky)
{
    MockCount = MockHead = 0;
    MockSticky = Sticky;
    MockOverrun = 0;
    MockRbrReads = 0;
}

VOID UartMockPush(UCHAR Data, UCHAR Errors)
{
    MockFifo[MockCount].Data = Data;
    /* 'f' framing, 'p' parity */
    MockFifo[MockCount].Flags = (Errors == 'f' ? SERIAL_LSR_FE : 0) | (Errors == 'p' ? SERIAL_LSR_PE : 0);
    MockCount++;
}

VOID UartMockOverrun(VOID)
{
    MockOverrun = SERIAL_LSR_OE;
}

ULONG UartMockLeft(VOID)
{
    return MockCount - MockHead;
}

USHORT UartMockGetByte(PUCHAR Byte, BOOLEAN Wait, BOOLEAN Poll)
{
    CPPORT Port;

    Port.Address = MOCK_BASE;
    Port.BaudRate = 115200;
    Port.Flags = 0;
    return Uart16550GetByte(&Port, Byte, Wait, Poll);
}
