;
;  SCRIPTS program of the sym53c8xx miniport: one command at a time, no tagged queueing, asynchronous
;  and narrow transfers. Select with a table, run the information transfer phases, wait for the
;  reselection after a disconnect message. Everything is relative or table indirect: the program does not
;  need to be relocated, the host starts it at the physical address of its first instruction.
;
;  The program is derived from the SCRIPTS program siop.ss of OpenBSD (sys/dev/microcode/siop/siop.ss,
;  revision 1.10): the phase dispatch, the message in handling and the data loop follow it; the scheduler
;  slots, the per-target switch scripts and the tag switch are not used. It carries the notice of that file:
;
;  Copyright (c) 2000 Manuel Bouyer.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions
;  are met:
;  1. Redistributions of source code must retain the above copyright
;     notice, this list of conditions and the following disclaimer.
;  2. Redistributions in binary form must reproduce the above copyright
;     notice, this list of conditions and the following disclaimer in the
;     documentation and/or other materials provided with the distribution.
;
;  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
;  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
;  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
;  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
;  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
;  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
;  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
;  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
;  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;
;  Assembled with the assembler of the same OpenBSD directory (ncr53cxxx.c, BSD licence):
;      ncr53cxxx sym53c8xx.ss -p sym53c8xx.out   (the output is turned into sym53c8xx_script.h; the .out file is not kept)

ARCH 720

; offsets of the table entries in the command block (the DSA register points at it)
ABSOLUTE t_id = 0;
ABSOLUTE t_msg_out = 8;
ABSOLUTE t_cmd = 16;
ABSOLUTE t_status = 24;
ABSOLUTE t_msg_in = 32;
ABSOLUTE t_data = 40;

; interrupt codes (the value of the DSPS register after an INT instruction)
ABSOLUTE int_done	= 0xff00;
ABSOLUTE int_msgin	= 0xff01;
ABSOLUTE int_disc	= 0xff04;
ABSOLUTE int_resel	= 0xff80;
ABSOLUTE int_resfail	= 0xff83;
ABSOLUTE int_err 	= 0xffff;

; flag in SCRATCHA0: data has moved
ABSOLUTE flag_data 	= 0x02;

ENTRY start;
ENTRY reselect;
ENTRY msgin_ack;
ENTRY waitphase;

PROC sym_script:

start:
	SELECT ATN FROM t_id, REL(sel_fail);
	MOVE 0 TO SCRATCHA0;
waitphase:
	JUMP REL(msgout), WHEN MSG_OUT;
	JUMP REL(msgin), WHEN MSG_IN;
	JUMP REL(dataout), WHEN DATA_OUT;
	JUMP REL(datain), WHEN DATA_IN;
	JUMP REL(cmdout), WHEN CMD;
	JUMP REL(status), WHEN STATUS;
	INT int_err;

sel_fail:
	INT int_err;

; wait for a target to reselect, take its identify message, let the host check who it is
reselect:
	WAIT RESELECT REL(resel_fail);
	MOVE FROM t_msg_in, WHEN MSG_IN;
	INT int_resel;
resel_fail:
	INT int_resfail;

; the host has accepted the identify message
msgin_ack:
	CLEAR ACK;
	JUMP REL(waitphase);

msgout:
	MOVE FROM t_msg_out, WHEN MSG_OUT;
	CLEAR ATN;
	JUMP REL(waitphase);
cmdout:
	MOVE FROM t_cmd, WHEN CMD;
	JUMP REL(waitphase);
status:
	MOVE FROM t_status, WHEN STATUS;
	JUMP REL(waitphase);

msgin:
	CLEAR ATN;
	MOVE FROM t_msg_in, WHEN MSG_IN;
	JUMP REL(cmpl), IF 0x00;
	JUMP REL(sdp), IF 0x02;
	INT int_msgin, IF NOT 0x04;
; disconnect message
	MOVE SCNTL2 & 0x7f TO SCNTL2;
	CLEAR ATN;
	CLEAR ACK;
	WAIT DISCONNECT;
	INT int_disc;

; save data pointer: a disconnect message follows
sdp:
	CLEAR ACK;
	JUMP REL(msgin);

; command complete message
cmpl:
	MOVE SCNTL2 & 0x7f TO SCNTL2;
	CLEAR ATN;
	CLEAR ACK;
	WAIT DISCONNECT;
	INT int_done;

datain:
	CALL REL(savedsa);
	MOVE SCRATCHA0 | flag_data TO SCRATCHA0;
datain_loop:
	MOVE FROM t_data, WHEN DATA_IN;
	MOVE DSA0 + 8 to DSA0;
	MOVE DSA1 + 0 to DSA1 WITH CARRY;
	MOVE DSA2 + 0 to DSA2 WITH CARRY;
	MOVE DSA3 + 0 to DSA3 WITH CARRY;
	JUMP REL(datain_loop), WHEN DATA_IN;
	CALL REL(restoredsa);
	JUMP REL(waitphase);

dataout:
	CALL REL(savedsa);
	MOVE SCRATCHA0 | flag_data TO SCRATCHA0;
dataout_loop:
	MOVE FROM t_data, WHEN DATA_OUT;
	MOVE DSA0 + 8 to DSA0;
	MOVE DSA1 + 0 to DSA1 WITH CARRY;
	MOVE DSA2 + 0 to DSA2 WITH CARRY;
	MOVE DSA3 + 0 to DSA3 WITH CARRY;
	JUMP REL(dataout_loop), WHEN DATA_OUT;
	CALL REL(restoredsa);
	JUMP REL(waitphase);

savedsa:
	MOVE DSA0 to SFBR;
	MOVE SFBR to SCRATCHB0;
	MOVE DSA1 to SFBR;
	MOVE SFBR to SCRATCHB1;
	MOVE DSA2 to SFBR;
	MOVE SFBR to SCRATCHB2;
	MOVE DSA3 to SFBR;
	MOVE SFBR to SCRATCHB3;
	RETURN;

restoredsa:
	MOVE SCRATCHB0 TO SFBR;
	MOVE SFBR TO DSA0;
	MOVE SCRATCHB1 TO SFBR;
	MOVE SFBR TO DSA1;
	MOVE SCRATCHB2 TO SFBR;
	MOVE SFBR TO DSA2;
	MOVE SCRATCHB3 TO SFBR;
	MOVE SFBR TO DSA3;
	RETURN;
