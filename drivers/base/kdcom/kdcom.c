/*
 * COPYRIGHT:       GPL, see COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            drivers/base/kdcom/kdcom.c
 * PURPOSE:         COM port functions for the kernel debugger.
 * PROGRAMMER:      Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#include "kddll.h"

#include <arc/arc.h>
#include <stdlib.h>
#include <ndk/halfuncs.h>

#include <cportlib/cportlib.h>
#include <cportlib/uartinfo.h>

/* GLOBALS ********************************************************************/

CPPORT KdComPort;

/*
 * The wait for an acknowledge is counted in polls of the port, and is short:
 * a host that is attached answers within milliseconds, and one that is not
 * must not hold the machine for minutes (each packet used to wait 20 times
 * 200,000 polls, 2.7 s each under a hypervisor). Before any host was heard
 * a single wait of KDP_ACK_SPIN_NOHOST ends the attempt; afterwards the
 * packet is resent a few times (KDP_HOST_RETRIES in kddll.c). A boot with
 * /BREAK is patient: the user said a debugger is coming, so its first stop
 * waits until the host is there.
 */
#define KDP_ACK_SPIN_NOHOST     8000
#define KDP_ACK_SPIN_HOST       12000

ULONG KdpByteSpin;          /* 0: wait as long as the port library does */
BOOLEAN KdpHostSeen;
BOOLEAN KdpPatient;
BOOLEAN KdpBreakInSeen;
BOOLEAN KdpRememberBreakIn;
#ifdef KDDEBUG
CPPORT KdDebugComPort;
#endif

/* DEBUGGING ******************************************************************/

#ifdef KDDEBUG
#include <stdio.h>
ULONG KdpDbgPrint(const char *Format, ...)
{
    va_list ap;
    int Length;
    char* ptr;
    CHAR Buffer[512];

    va_start(ap, Format);
    Length = _vsnprintf(Buffer, sizeof(Buffer), Format, ap);
    va_end(ap);

    /* Check if we went past the buffer */
    if (Length == -1)
    {
        /* Terminate it if we went over-board */
        Buffer[sizeof(Buffer) - 1] = '\n';

        /* Put maximum */
        Length = sizeof(Buffer);
    }

    ptr = Buffer;
    while (Length--)
    {
        if (*ptr == '\n')
            CpPutByte(&KdDebugComPort, '\r');

        CpPutByte(&KdDebugComPort, *ptr++);
    }

    return 0;
}
#endif

/* FUNCTIONS ******************************************************************/

ULONG
NTAPI
KdpAckSpin(VOID)
{
    return KdpHostSeen ? KDP_ACK_SPIN_HOST : KDP_ACK_SPIN_NOHOST;
}

/* A packet leader or a break-in byte arrived: there is a debugger on the other end */
VOID
NTAPI
KdpHostIsPresent(VOID)
{
    KdpHostSeen = TRUE;
    KD_DEBUGGER_NOT_PRESENT = FALSE;
    SharedUserData->KdDebuggerEnabled |= 0x00000002;
}

NTSTATUS
NTAPI
KdD0Transition(VOID)
{
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdD3Transition(VOID)
{
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdSave(IN BOOLEAN SleepTransition)
{
    /* Nothing to do on COM ports */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdRestore(IN BOOLEAN SleepTransition)
{
    /* Nothing to do on COM ports */
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
KdpPortInitialize(
    _In_ PUCHAR PortAddress,
    _In_ ULONG BaudRate)
{
    NTSTATUS Status;

    Status = CpInitialize(&KdComPort, PortAddress, BaudRate);
    if (!NT_SUCCESS(Status))
        return STATUS_INVALID_PARAMETER;

    KdComPortInUse = KdComPort.Address;
    return STATUS_SUCCESS;
}

/******************************************************************************
 * \name KdDebuggerInitialize0
 * \brief Phase 0 initialization.
 * \param [opt] LoaderBlock Pointer to the Loader parameter block. Can be NULL.
 * \return Status
 */
NTSTATUS
NTAPI
KdDebuggerInitialize0(IN PLOADER_PARAMETER_BLOCK LoaderBlock OPTIONAL)
{
#define CONST_STR_LEN(x) (sizeof(x)/sizeof(x[0]) - 1)

    ULONG ComPortNumber   = DEFAULT_DEBUG_PORT;
    ULONG ComPortBaudRate = DEFAULT_DEBUG_BAUD_RATE;
    PUCHAR ComPortAddress = NULL;

    PSTR CommandLine, PortString, BaudString;
    ULONG Value;

    /*
     * Without a loader block (KD enabled again, or by a bug check after a
     * CRASHDEBUG boot) keep the port the boot options gave us, instead of
     * falling back to the default one.
     */
    if (!LoaderBlock && KdComPort.Address)
        return STATUS_SUCCESS;

    /* Check if we have a LoaderBlock */
    if (LoaderBlock)
    {
        /* Get the Command Line */
        CommandLine = LoaderBlock->LoadOptions;

        /* Upcase it */
        _strupr(CommandLine);

        /* /BREAK: the first stop of the boot waits for the debugger to come */
        KdpPatient = (strstr(CommandLine, "BREAK") != NULL);

        /* Get the port and baud rate */
        PortString = strstr(CommandLine, "DEBUGPORT");
        BaudString = strstr(CommandLine, "BAUDRATE");

        /* Check if we got the DEBUGPORT parameter */
        if (PortString)
        {
            /* Move past the actual string and any spaces */
            PortString += CONST_STR_LEN("DEBUGPORT");
            while (*PortString == ' ') ++PortString;
            /* Skip the equals sign */
            if (*PortString) ++PortString;

            /* Do we have a serial port? */
            if (_strnicmp(PortString, "COM", CONST_STR_LEN("COM")) != 0)
                return STATUS_INVALID_PARAMETER;

            /* Check for a valid serial port */
            PortString += CONST_STR_LEN("COM");
            if (*PortString != ':')
            {
                Value = (ULONG)atol(PortString);
                if (Value > MAX_COM_PORTS)
                    return STATUS_INVALID_PARAMETER;
                // if (Value > 0 && Value <= MAX_COM_PORTS)
                /* Set the port to use */
                ComPortNumber = Value;
            }
            else
            {
                /* Retrieve and set its address */
                Value = strtoul(PortString + 1, NULL, 0);
                if (Value)
                {
                    ComPortNumber = 0;
                    ComPortAddress = UlongToPtr(Value);
                }
            }
        }

        /* Check if we got a baud rate */
        if (BaudString)
        {
            /* Move past the actual string and any spaces */
            BaudString += CONST_STR_LEN("BAUDRATE");
            while (*BaudString == ' ') ++BaudString;

            /* Make sure we have a rate */
            if (*BaudString)
            {
                /* Read and set it */
                Value = (ULONG)atol(BaudString + 1);
                if (Value) ComPortBaudRate = Value;
            }
        }
    }

    if (!ComPortAddress)
        ComPortAddress = UlongToPtr(BaseArray[ComPortNumber]);

#ifdef KDDEBUG
    /*
     * Try to find a free COM port and use it as the KD debugging port.
     * NOTE: Inspired by freeldr/comm/rs232.c, Rs232PortInitialize(...)
     */
    {
    /*
     * Enumerate COM ports from the last to the first one, and stop
     * when we find a valid port. If we reach the first list element
     * (the undefined COM port), no valid port was found.
     */
    PUCHAR Address = NULL;
    ULONG ComPort;
    for (ComPort = MAX_COM_PORTS; ComPort > 0; ComPort--)
    {
        /* Check if the port exist; skip the KD port */
        Address = UlongToPtr(BaseArray[ComPort]);
        if ((Address != ComPortAddress) && CpDoesPortExist(Address))
            break;
    }
    if (ComPort != 0 && Address != NULL)
        CpInitialize(&KdDebugComPort, Address, DEFAULT_BAUD_RATE);
    }
#endif

    /* Initialize the port */
    return KdpPortInitialize(ComPortAddress, ComPortBaudRate);
}

/******************************************************************************
 * \name KdDebuggerInitialize1
 * \brief Phase 1 initialization.
 * \param [opt] LoaderBlock Pointer to the Loader parameter block. Can be NULL.
 * \return Status
 */
NTSTATUS
NTAPI
KdDebuggerInitialize1(IN PLOADER_PARAMETER_BLOCK LoaderBlock OPTIONAL)
{
    return STATUS_SUCCESS;
}


VOID
NTAPI
KdpSendByte(IN UCHAR Byte)
{
    /* Send the byte */
    CpPutByte(&KdComPort, Byte);
}

KDP_STATUS
NTAPI
KdpPollByte(OUT PUCHAR OutByte)
{
    USHORT Status;

    /* Poll the byte */
    Status = CpGetByte(&KdComPort, OutByte, FALSE, FALSE);
    switch (Status)
    {
        case CP_GET_SUCCESS:
            return KDP_PACKET_RECEIVED;

        case CP_GET_NODATA:
            return KDP_PACKET_TIMEOUT;

        case CP_GET_ERROR:
        default:
            return KDP_PACKET_RESEND;
    }
}

KDP_STATUS
NTAPI
KdpReceiveByte(OUT PUCHAR OutByte)
{
    USHORT Status;
    ULONG Spin = KdpByteSpin;

    if (!Spin)
    {
        /* Wait as long as the port library does */
        Status = CpGetByte(&KdComPort, OutByte, TRUE, FALSE);
    }
    else
    {
        /* A bounded wait: poll the port Spin times */
        do
        {
            Status = CpGetByte(&KdComPort, OutByte, FALSE, FALSE);
        } while ((Status == CP_GET_NODATA) && (--Spin != 0));
    }

    switch (Status)
    {
        case CP_GET_SUCCESS:
            return KDP_PACKET_RECEIVED;

        case CP_GET_NODATA:
            return KDP_PACKET_TIMEOUT;

        case CP_GET_ERROR:
        default:
            return KDP_PACKET_RESEND;
    }
}

/*
 * Look for a break-in request: a byte seen earlier while a packet was
 * exchanged (KdpBreakInSeen), or one that is waiting in the port now. Every
 * byte that is waiting is taken, a host that sent a packet first must not
 * make the break-in wait for one poll per clock tick.
 */
KDP_STATUS
NTAPI
KdpPollBreakIn(VOID)
{
    KDP_STATUS KdStatus;
    UCHAR Byte;
    ULONG Count;
    BOOLEAN BreakIn = KdpBreakInSeen;

    for (Count = 0; Count < 32; Count++)
    {
        KdStatus = KdpPollByte(&Byte);
        if (KdStatus == KDP_PACKET_TIMEOUT)
            break;
        if ((KdStatus == KDP_PACKET_RECEIVED) && (Byte == BREAKIN_PACKET_BYTE))
            BreakIn = TRUE;
    }

    if (!BreakIn)
        return KDP_PACKET_TIMEOUT;

    /* The host is there, also if it was not heard before (it attached late) */
    KdpBreakInSeen = FALSE;
    KdpHostIsPresent();
    return KDP_PACKET_RECEIVED;
}

/* EOF */
