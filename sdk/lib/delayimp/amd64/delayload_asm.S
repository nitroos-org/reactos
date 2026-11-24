/*
 * PROJECT:     ReactOS delayimport Library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     The entry of the delay-load helper keeps the floating point argument registers
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The stub that dlltool generates for a delay-imported DLL saves rcx, rdx, r8 and r9 around its call to
 * __delayLoadHelper2, but not xmm0-xmm3. Those registers carry the first four arguments of a delay-loaded
 * function that takes floating point values, and the helper is C code that may use them. This entry saves
 * them and calls the helper.
 */

#include <asm.inc>
#include <ksamd64.inc>

.code64

EXTERN __delayLoadHelper2_c:PROC

/*
 * FARPROC
 * __delayLoadHelper2(
 *     PCImgDelayDescr pidd@<rcx>,
 *     PImgThunkData pIATEntry@<rdx>);
 */
PUBLIC __delayLoadHelper2
.PROC __delayLoadHelper2

    /* 0x20 bytes of home space, 4 xmm registers, and the alignment of the call */
    alloc_stack 104
    save_xmm128 xmm0, 32
    save_xmm128 xmm1, 48
    save_xmm128 xmm2, 64
    save_xmm128 xmm3, 80
    .ENDPROLOG

    call __delayLoadHelper2_c

    movaps xmm0, [rsp + 32]
    movaps xmm1, [rsp + 48]
    movaps xmm2, [rsp + 64]
    movaps xmm3, [rsp + 80]
    add rsp, 104
    ret

.ENDP

END
