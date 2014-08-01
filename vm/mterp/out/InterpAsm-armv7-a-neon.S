/*
 * This file was generated automatically by gen-mterp.py for 'armv7-a-neon'.
 *
 * --> DO NOT EDIT <--
 */

/* File: armv5te_taint/header.S */
/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * ARMv5 definitions and declarations.
 */

/*
ARM EABI general notes:

r0-r3 hold first 4 args to a method; they are not preserved across method calls
r4-r8 are available for general use
r9 is given special treatment in some situations, but not for us
r10 (sl) seems to be generally available
r11 (fp) is used by gcc (unless -fomit-frame-pointer is set)
r12 (ip) is scratch -- not preserved across method calls
r13 (sp) should be managed carefully in case a signal arrives
r14 (lr) must be preserved
r15 (pc) can be tinkered with directly

r0 holds returns of <= 4 bytes
r0-r1 hold returns of 8 bytes, low word in r0

Callee must save/restore r4+ (except r12) if it modifies them.  If VFP
is present, registers s16-s31 (a/k/a d8-d15, a/k/a q4-q7) must be preserved,
s0-s15 (d0-d7, q0-a3) do not need to be.

Stack is "full descending".  Only the arguments that don't fit in the first 4
registers are placed on the stack.  "sp" points at the first stacked argument
(i.e. the 5th arg).

VFP: single-precision results in s0, double-precision results in d0.

In the EABI, "sp" must be 64-bit aligned on entry to a function, and any
64-bit quantities (long long, double) must be 64-bit aligned.
*/

/*
Mterp and ARM notes:

The following registers have fixed assignments:

  reg nick      purpose
  r4  rPC       interpreted program counter, used for fetching instructions
  r5  rFP       interpreted frame pointer, used for accessing locals and args
  r6  rSELF     self (Thread) pointer
  r7  rINST     first 16-bit code unit of current instruction
  r8  rIBASE    interpreted instruction base pointer, used for computed goto

Macros are provided for common operations.  Each macro MUST emit only
one instruction to make instruction-counting easier.  They MUST NOT alter
unspecified registers or condition codes.
*/

/* single-purpose registers, given names for clarity */
#define rPC     r4
#define rFP     r5
#define rSELF   r6
#define rINST   r7
#define rIBASE  r8

/* save/restore the PC and/or FP from the thread struct */
#define LOAD_PC_FROM_SELF()     ldr     rPC, [rSELF, #offThread_pc]
#define SAVE_PC_TO_SELF()       str     rPC, [rSELF, #offThread_pc]
#define LOAD_FP_FROM_SELF()     ldr     rFP, [rSELF, #offThread_curFrame]
#define SAVE_FP_TO_SELF()       str     rFP, [rSELF, #offThread_curFrame]
#define LOAD_PC_FP_FROM_SELF()  ldmia   rSELF, {rPC, rFP}
#define SAVE_PC_FP_TO_SELF()    stmia   rSELF, {rPC, rFP}

/*
 * "export" the PC to the stack frame, f/b/o future exception objects.  Must
 * be done *before* something throws.
 *
 * In C this is "SAVEAREA_FROM_FP(fp)->xtra.currentPc = pc", i.e.
 * fp - sizeof(StackSaveArea) + offsetof(SaveArea, xtra.currentPc)
 *
 * It's okay to do this more than once.
 */
#define EXPORT_PC() \
    str     rPC, [rFP, #(-sizeofStackSaveArea + offStackSaveArea_currentPc)]

/*
 * Given a frame pointer, find the stack save area.
 *
 * In C this is "((StackSaveArea*)(_fp) -1)".
 */
#define SAVEAREA_FROM_FP(_reg, _fpreg) \
    sub     _reg, _fpreg, #sizeofStackSaveArea

/*
 * Fetch the next instruction from rPC into rINST.  Does not advance rPC.
 */
#define FETCH_INST()            ldrh    rINST, [rPC]

/*
 * Fetch the next instruction from the specified offset.  Advances rPC
 * to point to the next instruction.  "_count" is in 16-bit code units.
 *
 * Because of the limited size of immediate constants on ARM, this is only
 * suitable for small forward movements (i.e. don't try to implement "goto"
 * with this).
 *
 * This must come AFTER anything that can throw an exception, or the
 * exception catch may miss.  (This also implies that it must come after
 * EXPORT_PC().)
 */
#define FETCH_ADVANCE_INST(_count) ldrh    rINST, [rPC, #((_count)*2)]!

/*
 * The operation performed here is similar to FETCH_ADVANCE_INST, except the
 * src and dest registers are parameterized (not hard-wired to rPC and rINST).
 */
#define PREFETCH_ADVANCE_INST(_dreg, _sreg, _count) \
        ldrh    _dreg, [_sreg, #((_count)*2)]!

/*
 * Fetch the next instruction from an offset specified by _reg.  Updates
 * rPC to point to the next instruction.  "_reg" must specify the distance
 * in bytes, *not* 16-bit code units, and may be a signed value.
 *
 * We want to write "ldrh rINST, [rPC, _reg, lsl #1]!", but some of the
 * bits that hold the shift distance are used for the half/byte/sign flags.
 * In some cases we can pre-double _reg for free, so we require a byte offset
 * here.
 */
#define FETCH_ADVANCE_INST_RB(_reg) ldrh    rINST, [rPC, _reg]!

/*
 * Fetch a half-word code unit from an offset past the current PC.  The
 * "_count" value is in 16-bit code units.  Does not advance rPC.
 *
 * The "_S" variant works the same but treats the value as signed.
 */
#define FETCH(_reg, _count)     ldrh    _reg, [rPC, #((_count)*2)]
#define FETCH_S(_reg, _count)   ldrsh   _reg, [rPC, #((_count)*2)]

/*
 * Fetch one byte from an offset past the current PC.  Pass in the same
 * "_count" as you would for FETCH, and an additional 0/1 indicating which
 * byte of the halfword you want (lo/hi).
 */
#define FETCH_B(_reg, _count, _byte) ldrb     _reg, [rPC, #((_count)*2+(_byte))]

/*
 * Put the instruction's opcode field into the specified register.
 */
#define GET_INST_OPCODE(_reg)   and     _reg, rINST, #255

/*
 * Put the prefetched instruction's opcode field into the specified register.
 */
#define GET_PREFETCHED_OPCODE(_oreg, _ireg)   and     _oreg, _ireg, #255

/*
 * Begin executing the opcode in _reg.  Because this only jumps within the
 * interpreter, we don't have to worry about pre-ARMv5 THUMB interwork.
 */
#define GOTO_OPCODE(_reg)       add     pc, rIBASE, _reg, lsl #6
#define GOTO_OPCODE_BASE(_base,_reg)  add     pc, _base, _reg, lsl #6
#define GOTO_OPCODE_IFEQ(_reg)  addeq   pc, rIBASE, _reg, lsl #6
#define GOTO_OPCODE_IFNE(_reg)  addne   pc, rIBASE, _reg, lsl #6

/*
 * Get/set the 32-bit value from a Dalvik register.
 */
#ifdef WITH_TAINT_TRACKING
#define SET_TAINT_FP(_reg)      add     _reg, rFP, #4
#define SET_TAINT_CLEAR(_reg)   mov     _reg, #0
#define GET_VREG(_reg, _vreg)   ldr     _reg, [rFP, _vreg, lsl #3]
#define SET_VREG(_reg, _vreg)   str     _reg, [rFP, _vreg, lsl #3]
#define GET_VREG_TAINT(_reg, _vreg, _rFP)   ldr     _reg, [_rFP, _vreg, lsl #3]
#define SET_VREG_TAINT(_reg, _vreg, _rFP)   str     _reg, [_rFP, _vreg, lsl #3]
#else
#define GET_VREG(_reg, _vreg)   ldr     _reg, [rFP, _vreg, lsl #2]
#define SET_VREG(_reg, _vreg)   str     _reg, [rFP, _vreg, lsl #2]
#endif /*WITH_TAINT_TRACKING*/

/*
 * Convert a virtual register index into an address.
 */
#ifdef WITH_TAINT_TRACKING
#define VREG_INDEX_TO_ADDR(_reg, _vreg) \
        add     _reg, rFP, _vreg, lsl #3
#else
#define VREG_INDEX_TO_ADDR(_reg, _vreg) \
        add     _reg, rFP, _vreg, lsl #2
#endif /*WITH_TAINT_TRACKING*/

/*
 * This is a #include, not a %include, because we want the C pre-processor
 * to expand the macros into assembler assignment statements.
 */
#include "../common/asm-constants.h"

#if defined(WITH_JIT)
#include "../common/jit-config.h"
#endif

/* File: armv7-a/platform.S */
/*
 * ===========================================================================
 *  CPU-version-specific defines
 * ===========================================================================
 */

#if !defined(ANDROID_SMP)
# error "Must define ANDROID_SMP"
#endif

/*
 * Macro for data memory barrier.
 */
.macro  SMP_DMB
#if ANDROID_SMP != 0
    dmb
#else
    /* not SMP */
#endif
.endm

/*
 * Macro for data memory barrier (store/store variant).
 */
.macro  SMP_DMB_ST
#if ANDROID_SMP != 0
    dmb     st
#else
    /* not SMP */
#endif
.endm

/* File: armv5te_taint/entry.S */
/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Interpreter entry point.
 */

/*
 * We don't have formal stack frames, so gdb scans upward in the code
 * to find the start of the function (a label with the %function type),
 * and then looks at the next few instructions to figure out what
 * got pushed onto the stack.  From this it figures out how to restore
 * the registers, including PC, for the previous stack frame.  If gdb
 * sees a non-function label, it stops scanning, so either we need to
 * have nothing but assembler-local labels between the entry point and
 * the break, or we need to fake it out.
 *
 * When this is defined, we add some stuff to make gdb less confused.
 */
#define ASSIST_DEBUGGER 1

    .text
    .align  2
    .global dvmMterpStdRun
    .type   dvmMterpStdRun, %function

/*
 * On entry:
 *  r0  Thread* self
 *
 * The return comes via a call to dvmMterpStdBail().
 */
dvmMterpStdRun:
#define MTERP_ENTRY1 \
    .save {r4-r10,fp,lr}; \
    stmfd   sp!, {r4-r10,fp,lr}         @ save 9 regs
#define MTERP_ENTRY2 \
    .pad    #4; \
    sub     sp, sp, #4                  @ align 64

    .fnstart
    MTERP_ENTRY1
    MTERP_ENTRY2

    /* save stack pointer, add magic word for debuggerd */
    str     sp, [r0, #offThread_bailPtr]  @ save SP for eventual return

    /* set up "named" registers, figure out entry point */
    mov     rSELF, r0                   @ set rSELF
    LOAD_PC_FP_FROM_SELF()              @ load rPC and rFP from "thread"
    ldr     rIBASE, [rSELF, #offThread_curHandlerTable] @ set rIBASE

#if defined(WITH_JIT)
.LentryInstr:
    /* Entry is always a possible trace start */
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    FETCH_INST()
    mov     r1, #0                      @ prepare the value for the new state
    str     r1, [rSELF, #offThread_inJitCodeCache] @ back to the interp land
    cmp     r0,#0                       @ is profiling disabled?
#if !defined(WITH_SELF_VERIFICATION)
    bne     common_updateProfile        @ profiling is enabled
#else
    ldr     r2, [rSELF, #offThread_shadowSpace] @ to find out the jit exit state
    beq     1f                          @ profiling is disabled
    ldr     r3, [r2, #offShadowSpace_jitExitState]  @ jit exit state
    cmp     r3, #kSVSTraceSelect        @ hot trace following?
    moveq   r2,#kJitTSelectRequestHot   @ ask for trace selection
    beq     common_selectTrace          @ go build the trace
    cmp     r3, #kSVSNoProfile          @ don't profile the next instruction?
    beq     1f                          @ intrepret the next instruction
    b       common_updateProfile        @ collect profiles
#endif
1:
    GET_INST_OPCODE(ip)
    GOTO_OPCODE(ip)
#else
    /* start executing the instruction at rPC */
    FETCH_INST()                        @ load rINST from rPC
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction
#endif

.Lbad_arg:
    ldr     r0, strBadEntryPoint
0:  add     r0, pc
    @ r1 holds value of entryPoint
    bl      printf
    bl      dvmAbort
    .fnend
    .size   dvmMterpStdRun, .-dvmMterpStdRun

strBadEntryPoint:
    .word   PCREL_REF(.LstrBadEntryPoint,0b)

    .global dvmMterpStdBail
    .type   dvmMterpStdBail, %function

/*
 * Restore the stack pointer and PC from the save point established on entry.
 * This is essentially the same as a longjmp, but should be cheaper.  The
 * last instruction causes us to return to whoever called dvmMterpStdRun.
 *
 * We pushed some registers on the stack in dvmMterpStdRun, then saved
 * SP and LR.  Here we restore SP, restore the registers, and then restore
 * LR to PC.
 *
 * On entry:
 *  r0  Thread* self
 */
dvmMterpStdBail:
    ldr     sp, [r0, #offThread_bailPtr]    @ sp<- saved SP
    add     sp, sp, #4                      @ un-align 64
    ldmfd   sp!, {r4-r10,fp,pc}             @ restore 9 regs and return



    .global dvmAsmInstructionStart
    .type   dvmAsmInstructionStart, %function
dvmAsmInstructionStart = .L_OP_NOP
    .text

/* ------------------------------ */
    .balign 64
.L_OP_NOP: /* 0x00 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_NOP      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE: /* 0x01 */
/* File: armv6t2_taint/OP_MOVE.S */
    /* for move, move-object, long-to-int */
    /* op vA, vB */
    mov     r1, rINST, lsr #12          @ r1<- B from 15:12
    ubfx    r0, rINST, #8, #4           @ r0<- A from 11:8
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    GET_VREG(r2, r1)                    @ r2<- fp[B]
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r3)
    GET_VREG_TAINT(r1, r1, r3)
    SET_VREG_TAINT(r1, r0, r3)
// end WITH_TAINT_TRACKING
    GET_INST_OPCODE(ip)                 @ ip<- opcode from rINST
    SET_VREG(r2, r0)                    @ fp[A]<- r2
    GOTO_OPCODE(ip)                     @ execute next instruction

/* ------------------------------ */
    .balign 64
.L_OP_MOVE_FROM16: /* 0x02 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_FROM16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_16: /* 0x03 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_WIDE: /* 0x04 */
/* File: armv6t2_taint/OP_MOVE_WIDE.S */
    /* move-wide vA, vB */
    /* NOTE: regs can overlap, e.g. "move v6,v7" or "move v7,v6" */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r2, rINST, #8, #4           @ r2<- A
// begin WITH_TAINT_TRACKING
    add     r3, rFP, r3, lsl #3         @ r3<- &fp[B]
    add     r9, rFP, r2, lsl #3         @ r9<- &fp[A]
    ldmia   r3, {r0-r3}                 @ r0/r1<- fp[B]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
// begin WITH_TAINT_TRACKING
    stmia   r9, {r0-r3}                 @ fp[A]<- r0/r1
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction

/* ------------------------------ */
    .balign 64
.L_OP_MOVE_WIDE_FROM16: /* 0x05 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_WIDE_FROM16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_WIDE_16: /* 0x06 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_WIDE_16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_OBJECT: /* 0x07 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_OBJECT_FROM16: /* 0x08 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_OBJECT_FROM16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_OBJECT_16: /* 0x09 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_OBJECT_16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_RESULT: /* 0x0a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_RESULT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_RESULT_WIDE: /* 0x0b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_RESULT_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_RESULT_OBJECT: /* 0x0c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_RESULT_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MOVE_EXCEPTION: /* 0x0d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MOVE_EXCEPTION      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_RETURN_VOID: /* 0x0e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_RETURN_VOID      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_RETURN: /* 0x0f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_RETURN      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_RETURN_WIDE: /* 0x10 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_RETURN_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_RETURN_OBJECT: /* 0x11 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_RETURN_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_4: /* 0x12 */
/* File: armv6t2_taint/OP_CONST_4.S */
    /* const/4 vA, #+B */
    mov     r1, rINST, lsl #16          @ r1<- Bxxx0000
    ubfx    r0, rINST, #8, #4           @ r0<- A
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    mov     r1, r1, asr #28             @ r1<- sssssssB (sign-extended)
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r2)
    SET_TAINT_CLEAR(r3)
    SET_VREG_TAINT(r3, r0, r2)
// end WITH_TAINT_TRACKING
    GET_INST_OPCODE(ip)                 @ ip<- opcode from rINST
    SET_VREG(r1, r0)                    @ fp[A]<- r1
    GOTO_OPCODE(ip)                     @ execute next instruction

/* ------------------------------ */
    .balign 64
.L_OP_CONST_16: /* 0x13 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST: /* 0x14 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_HIGH16: /* 0x15 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_HIGH16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_WIDE_16: /* 0x16 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_WIDE_16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_WIDE_32: /* 0x17 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_WIDE_32      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_WIDE: /* 0x18 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_WIDE_HIGH16: /* 0x19 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_WIDE_HIGH16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_STRING: /* 0x1a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_STRING      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_STRING_JUMBO: /* 0x1b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_STRING_JUMBO      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CONST_CLASS: /* 0x1c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CONST_CLASS      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MONITOR_ENTER: /* 0x1d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MONITOR_ENTER      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MONITOR_EXIT: /* 0x1e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MONITOR_EXIT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CHECK_CAST: /* 0x1f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CHECK_CAST      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INSTANCE_OF: /* 0x20 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INSTANCE_OF      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ARRAY_LENGTH: /* 0x21 */
/* File: armv6t2_taint/OP_ARRAY_LENGTH.S */
    /*
     * Return the length of an array.
     */
    mov     r1, rINST, lsr #12          @ r1<- B
    ubfx    r2, rINST, #8, #4           @ r2<- A
    GET_VREG(r0, r1)                    @ r0<- vB (object ref)
    cmp     r0, #0                      @ is object null?
    beq     common_errNullObject        @ yup, fail
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    SET_TAINT_CLEAR(r3)
    SET_VREG_TAINT(r3, r2, r1)
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    ldr     r3, [r0, #offArrayObject_length]    @ r3<- array length
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    SET_VREG(r3, r2)                    @ vB<- length
    GOTO_OPCODE(ip)                     @ jump to next instruction

/* ------------------------------ */
    .balign 64
.L_OP_NEW_INSTANCE: /* 0x22 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_NEW_INSTANCE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_NEW_ARRAY: /* 0x23 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_NEW_ARRAY      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_FILLED_NEW_ARRAY: /* 0x24 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_FILLED_NEW_ARRAY      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_FILLED_NEW_ARRAY_RANGE: /* 0x25 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_FILLED_NEW_ARRAY_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_FILL_ARRAY_DATA: /* 0x26 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_FILL_ARRAY_DATA      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_THROW: /* 0x27 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_THROW      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_GOTO: /* 0x28 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_GOTO      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_GOTO_16: /* 0x29 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_GOTO_16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_GOTO_32: /* 0x2a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_GOTO_32      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_PACKED_SWITCH: /* 0x2b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_PACKED_SWITCH      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPARSE_SWITCH: /* 0x2c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPARSE_SWITCH      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CMPL_FLOAT: /* 0x2d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CMPL_FLOAT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CMPG_FLOAT: /* 0x2e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CMPG_FLOAT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CMPL_DOUBLE: /* 0x2f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CMPL_DOUBLE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CMPG_DOUBLE: /* 0x30 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CMPG_DOUBLE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_CMP_LONG: /* 0x31 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_CMP_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IF_EQ: /* 0x32 */
/* File: armv6t2_taint/OP_IF_EQ.S */
/* File: armv6t2_taint/bincmp.S */
    /*
     * Generic two-operand compare-and-branch operation.  Provide a "revcmp"
     * fragment that specifies the *reverse* comparison to perform, e.g.
     * for "if-le" you would use "gt".
     *
     * For: if-eq, if-ne, if-lt, if-ge, if-gt, if-le
     */
    /* if-cmp vA, vB, +CCCC */
    mov     r1, rINST, lsr #12          @ r1<- B
    ubfx    r0, rINST, #8, #4           @ r0<- A
    GET_VREG(r3, r1)                    @ r3<- vB
    GET_VREG(r2, r0)                    @ r2<- vA
    FETCH_S(r1, 1)                      @ r1<- branch offset, in code units
    cmp     r2, r3                      @ compare (vA, vB)
    movne r1, #2                 @ r1<- BYTE branch dist for not-taken
    adds    r2, r1, r1                  @ convert to bytes, check sign
    FETCH_ADVANCE_INST_RB(r2)           @ update rPC, load rINST
#if defined(WITH_JIT)
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    cmp     r0, #0
    bne     common_updateProfile
#else
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
#endif
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IF_NE: /* 0x33 */
/* File: armv6t2_taint/OP_IF_NE.S */
/* File: armv6t2_taint/bincmp.S */
    /*
     * Generic two-operand compare-and-branch operation.  Provide a "revcmp"
     * fragment that specifies the *reverse* comparison to perform, e.g.
     * for "if-le" you would use "gt".
     *
     * For: if-eq, if-ne, if-lt, if-ge, if-gt, if-le
     */
    /* if-cmp vA, vB, +CCCC */
    mov     r1, rINST, lsr #12          @ r1<- B
    ubfx    r0, rINST, #8, #4           @ r0<- A
    GET_VREG(r3, r1)                    @ r3<- vB
    GET_VREG(r2, r0)                    @ r2<- vA
    FETCH_S(r1, 1)                      @ r1<- branch offset, in code units
    cmp     r2, r3                      @ compare (vA, vB)
    moveq r1, #2                 @ r1<- BYTE branch dist for not-taken
    adds    r2, r1, r1                  @ convert to bytes, check sign
    FETCH_ADVANCE_INST_RB(r2)           @ update rPC, load rINST
#if defined(WITH_JIT)
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    cmp     r0, #0
    bne     common_updateProfile
#else
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
#endif
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IF_LT: /* 0x34 */
/* File: armv6t2_taint/OP_IF_LT.S */
/* File: armv6t2_taint/bincmp.S */
    /*
     * Generic two-operand compare-and-branch operation.  Provide a "revcmp"
     * fragment that specifies the *reverse* comparison to perform, e.g.
     * for "if-le" you would use "gt".
     *
     * For: if-eq, if-ne, if-lt, if-ge, if-gt, if-le
     */
    /* if-cmp vA, vB, +CCCC */
    mov     r1, rINST, lsr #12          @ r1<- B
    ubfx    r0, rINST, #8, #4           @ r0<- A
    GET_VREG(r3, r1)                    @ r3<- vB
    GET_VREG(r2, r0)                    @ r2<- vA
    FETCH_S(r1, 1)                      @ r1<- branch offset, in code units
    cmp     r2, r3                      @ compare (vA, vB)
    movge r1, #2                 @ r1<- BYTE branch dist for not-taken
    adds    r2, r1, r1                  @ convert to bytes, check sign
    FETCH_ADVANCE_INST_RB(r2)           @ update rPC, load rINST
#if defined(WITH_JIT)
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    cmp     r0, #0
    bne     common_updateProfile
#else
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
#endif
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IF_GE: /* 0x35 */
/* File: armv6t2_taint/OP_IF_GE.S */
/* File: armv6t2_taint/bincmp.S */
    /*
     * Generic two-operand compare-and-branch operation.  Provide a "revcmp"
     * fragment that specifies the *reverse* comparison to perform, e.g.
     * for "if-le" you would use "gt".
     *
     * For: if-eq, if-ne, if-lt, if-ge, if-gt, if-le
     */
    /* if-cmp vA, vB, +CCCC */
    mov     r1, rINST, lsr #12          @ r1<- B
    ubfx    r0, rINST, #8, #4           @ r0<- A
    GET_VREG(r3, r1)                    @ r3<- vB
    GET_VREG(r2, r0)                    @ r2<- vA
    FETCH_S(r1, 1)                      @ r1<- branch offset, in code units
    cmp     r2, r3                      @ compare (vA, vB)
    movlt r1, #2                 @ r1<- BYTE branch dist for not-taken
    adds    r2, r1, r1                  @ convert to bytes, check sign
    FETCH_ADVANCE_INST_RB(r2)           @ update rPC, load rINST
#if defined(WITH_JIT)
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    cmp     r0, #0
    bne     common_updateProfile
#else
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
#endif
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IF_GT: /* 0x36 */
/* File: armv6t2_taint/OP_IF_GT.S */
/* File: armv6t2_taint/bincmp.S */
    /*
     * Generic two-operand compare-and-branch operation.  Provide a "revcmp"
     * fragment that specifies the *reverse* comparison to perform, e.g.
     * for "if-le" you would use "gt".
     *
     * For: if-eq, if-ne, if-lt, if-ge, if-gt, if-le
     */
    /* if-cmp vA, vB, +CCCC */
    mov     r1, rINST, lsr #12          @ r1<- B
    ubfx    r0, rINST, #8, #4           @ r0<- A
    GET_VREG(r3, r1)                    @ r3<- vB
    GET_VREG(r2, r0)                    @ r2<- vA
    FETCH_S(r1, 1)                      @ r1<- branch offset, in code units
    cmp     r2, r3                      @ compare (vA, vB)
    movle r1, #2                 @ r1<- BYTE branch dist for not-taken
    adds    r2, r1, r1                  @ convert to bytes, check sign
    FETCH_ADVANCE_INST_RB(r2)           @ update rPC, load rINST
#if defined(WITH_JIT)
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    cmp     r0, #0
    bne     common_updateProfile
#else
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
#endif
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IF_LE: /* 0x37 */
/* File: armv6t2_taint/OP_IF_LE.S */
/* File: armv6t2_taint/bincmp.S */
    /*
     * Generic two-operand compare-and-branch operation.  Provide a "revcmp"
     * fragment that specifies the *reverse* comparison to perform, e.g.
     * for "if-le" you would use "gt".
     *
     * For: if-eq, if-ne, if-lt, if-ge, if-gt, if-le
     */
    /* if-cmp vA, vB, +CCCC */
    mov     r1, rINST, lsr #12          @ r1<- B
    ubfx    r0, rINST, #8, #4           @ r0<- A
    GET_VREG(r3, r1)                    @ r3<- vB
    GET_VREG(r2, r0)                    @ r2<- vA
    FETCH_S(r1, 1)                      @ r1<- branch offset, in code units
    cmp     r2, r3                      @ compare (vA, vB)
    movgt r1, #2                 @ r1<- BYTE branch dist for not-taken
    adds    r2, r1, r1                  @ convert to bytes, check sign
    FETCH_ADVANCE_INST_RB(r2)           @ update rPC, load rINST
#if defined(WITH_JIT)
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    cmp     r0, #0
    bne     common_updateProfile
#else
    ldrmi   rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
#endif
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IF_EQZ: /* 0x38 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IF_EQZ      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IF_NEZ: /* 0x39 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IF_NEZ      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IF_LTZ: /* 0x3a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IF_LTZ      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IF_GEZ: /* 0x3b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IF_GEZ      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IF_GTZ: /* 0x3c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IF_GTZ      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IF_LEZ: /* 0x3d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IF_LEZ      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_3E: /* 0x3e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_3E      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_3F: /* 0x3f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_3F      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_40: /* 0x40 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_40      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_41: /* 0x41 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_41      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_42: /* 0x42 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_42      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_43: /* 0x43 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_43      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AGET: /* 0x44 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AGET      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AGET_WIDE: /* 0x45 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AGET_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AGET_OBJECT: /* 0x46 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AGET_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AGET_BOOLEAN: /* 0x47 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AGET_BOOLEAN      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AGET_BYTE: /* 0x48 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AGET_BYTE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AGET_CHAR: /* 0x49 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AGET_CHAR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AGET_SHORT: /* 0x4a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AGET_SHORT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_APUT: /* 0x4b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_APUT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_APUT_WIDE: /* 0x4c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_APUT_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_APUT_OBJECT: /* 0x4d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_APUT_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_APUT_BOOLEAN: /* 0x4e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_APUT_BOOLEAN      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_APUT_BYTE: /* 0x4f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_APUT_BYTE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_APUT_CHAR: /* 0x50 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_APUT_CHAR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_APUT_SHORT: /* 0x51 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_APUT_SHORT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET: /* 0x52 */
/* File: armv6t2_taint/OP_IGET.S */
    /*
     * General 32-bit instance field get.
     *
     * for: iget, iget-object, iget-boolean, iget-byte, iget-char, iget-short
     */
    /* op vA, vB, field@CCCC */
    mov     r0, rINST, lsr #12          @ r0<- B
    ldr     r3, [rSELF, #offThread_methodClassDex]    @ r3<- DvmDex
    FETCH(r1, 1)                        @ r1<- field ref CCCC
    ldr     r2, [r3, #offDvmDex_pResFields] @ r2<- pDvmDex->pResFields
// begin WITH_TAINT_TRACKING
    bl      .LOP_IGET_taint_prop
// end WITH_TAINT_TRACKING
    cmp     r0, #0                      @ is resolved entry null?
    bne     .LOP_IGET_finish          @ no, already resolved
8:  ldr     r2, [rSELF, #offThread_method]    @ r2<- current method
    EXPORT_PC()                         @ resolve() could throw
    ldr     r0, [r2, #offMethod_clazz]  @ r0<- method->clazz
    bl      dvmResolveInstField         @ r0<- resolved InstField ptr
    cmp     r0, #0
    bne     .LOP_IGET_finish
    b       common_exceptionThrown

/* ------------------------------ */
    .balign 64
.L_OP_IGET_WIDE: /* 0x53 */
/* File: armv6t2_taint/OP_IGET_WIDE.S */
    /*
     * Wide 32-bit instance field get.
     */
    /* iget-wide vA, vB, field@CCCC */
    mov     r0, rINST, lsr #12          @ r0<- B
    ldr     r3, [rSELF, #offThread_methodClassDex]    @ r3<- DvmDex
    FETCH(r1, 1)                        @ r1<- field ref CCCC
    ldr     r2, [r3, #offDvmDex_pResFields] @ r2<- pResFields
// begin WITH_TAINT_TRACKING
    bl      .LOP_IGET_WIDE_taint_prop
// end WITH_TAINT_TRACKING
    cmp     r0, #0                      @ is resolved entry null?
    bne     .LOP_IGET_WIDE_finish          @ no, already resolved
8:  ldr     r2, [rSELF, #offThread_method] @ r2<- current method
    EXPORT_PC()                         @ resolve() could throw
    ldr     r0, [r2, #offMethod_clazz]  @ r0<- method->clazz
    bl      dvmResolveInstField         @ r0<- resolved InstField ptr
    cmp     r0, #0
    bne     .LOP_IGET_WIDE_finish
    b       common_exceptionThrown

/* ------------------------------ */
    .balign 64
.L_OP_IGET_OBJECT: /* 0x54 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_BOOLEAN: /* 0x55 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_BOOLEAN      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_BYTE: /* 0x56 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_BYTE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_CHAR: /* 0x57 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_CHAR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_SHORT: /* 0x58 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_SHORT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT: /* 0x59 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_WIDE: /* 0x5a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_OBJECT: /* 0x5b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_BOOLEAN: /* 0x5c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_BOOLEAN      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_BYTE: /* 0x5d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_BYTE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_CHAR: /* 0x5e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_CHAR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_SHORT: /* 0x5f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_SHORT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET: /* 0x60 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_WIDE: /* 0x61 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_OBJECT: /* 0x62 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_BOOLEAN: /* 0x63 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_BOOLEAN      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_BYTE: /* 0x64 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_BYTE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_CHAR: /* 0x65 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_CHAR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_SHORT: /* 0x66 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_SHORT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT: /* 0x67 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_WIDE: /* 0x68 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_WIDE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_OBJECT: /* 0x69 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_OBJECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_BOOLEAN: /* 0x6a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_BOOLEAN      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_BYTE: /* 0x6b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_BYTE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_CHAR: /* 0x6c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_CHAR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_SHORT: /* 0x6d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_SHORT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_VIRTUAL: /* 0x6e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_VIRTUAL      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_SUPER: /* 0x6f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_SUPER      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_DIRECT: /* 0x70 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_DIRECT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_STATIC: /* 0x71 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_STATIC      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_INTERFACE: /* 0x72 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_INTERFACE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_73: /* 0x73 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_73      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_VIRTUAL_RANGE: /* 0x74 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_VIRTUAL_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_SUPER_RANGE: /* 0x75 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_SUPER_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_DIRECT_RANGE: /* 0x76 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_DIRECT_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_STATIC_RANGE: /* 0x77 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_STATIC_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_INTERFACE_RANGE: /* 0x78 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_INTERFACE_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_79: /* 0x79 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_79      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_7A: /* 0x7a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_7A      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_NEG_INT: /* 0x7b */
/* File: armv6t2_taint/OP_NEG_INT.S */
/* File: armv6t2_taint/unop.S */
    /*
     * Generic 32-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0".
     * This could be an ARM instruction or a function call.
     *
     * for: neg-int, not-int, neg-float, int-to-float, float-to-int,
     *      int-to-byte, int-to-char, int-to-short
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    GET_VREG_TAINT(r2, r3, r1)          @ r2<- vB.taint
    SET_VREG_TAINT(r2, r9, r1)
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    rsb     r0, r0, #0                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    SET_VREG(r0, r9)                    @ vAA<- r0
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 8-9 instructions */


/* ------------------------------ */
    .balign 64
.L_OP_NOT_INT: /* 0x7c */
/* File: armv6t2_taint/OP_NOT_INT.S */
/* File: armv6t2_taint/unop.S */
    /*
     * Generic 32-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0".
     * This could be an ARM instruction or a function call.
     *
     * for: neg-int, not-int, neg-float, int-to-float, float-to-int,
     *      int-to-byte, int-to-char, int-to-short
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    GET_VREG_TAINT(r2, r3, r1)          @ r2<- vB.taint
    SET_VREG_TAINT(r2, r9, r1)
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    mvn     r0, r0                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    SET_VREG(r0, r9)                    @ vAA<- r0
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 8-9 instructions */


/* ------------------------------ */
    .balign 64
.L_OP_NEG_LONG: /* 0x7d */
/* File: armv6t2_taint/OP_NEG_LONG.S */
/* File: armv6t2_taint/unopWide.S */
    /*
     * Generic 64-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0/r1".
     * This could be an ARM instruction or a function call.
     *
     * For: neg-long, not-long, neg-double, long-to-double, double-to-long
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
// begin WITH_TAINT_TRACKING
    add     r3, rFP, r3, lsl #3         @ r3<- &fp[B]
    add     r9, rFP, r9, lsl #3         @ r9<- &fp[A]
//    ldmia   r3, {r0-r1}                 @ r0/r1<- vAA
    ldr     r0, [r3, #0]
    ldr     r1, [r3, #8]
    ldr     r10, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    rsbs    r0, r0, #0                           @ optional op; may set condition codes
    rsc     r1, r1, #0                              @ r0/r1<- op, r2-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    b       .LOP_NEG_LONG_finish


/* ------------------------------ */
    .balign 64
.L_OP_NOT_LONG: /* 0x7e */
/* File: armv6t2_taint/OP_NOT_LONG.S */
/* File: armv6t2_taint/unopWide.S */
    /*
     * Generic 64-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0/r1".
     * This could be an ARM instruction or a function call.
     *
     * For: neg-long, not-long, neg-double, long-to-double, double-to-long
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
// begin WITH_TAINT_TRACKING
    add     r3, rFP, r3, lsl #3         @ r3<- &fp[B]
    add     r9, rFP, r9, lsl #3         @ r9<- &fp[A]
//    ldmia   r3, {r0-r1}                 @ r0/r1<- vAA
    ldr     r0, [r3, #0]
    ldr     r1, [r3, #8]
    ldr     r10, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    mvn     r0, r0                           @ optional op; may set condition codes
    mvn     r1, r1                              @ r0/r1<- op, r2-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    b       .LOP_NOT_LONG_finish


/* ------------------------------ */
    .balign 64
.L_OP_NEG_FLOAT: /* 0x7f */
/* File: armv6t2_taint/OP_NEG_FLOAT.S */
/* File: armv6t2_taint/unop.S */
    /*
     * Generic 32-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0".
     * This could be an ARM instruction or a function call.
     *
     * for: neg-int, not-int, neg-float, int-to-float, float-to-int,
     *      int-to-byte, int-to-char, int-to-short
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    GET_VREG_TAINT(r2, r3, r1)          @ r2<- vB.taint
    SET_VREG_TAINT(r2, r9, r1)
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    add     r0, r0, #0x80000000                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    SET_VREG(r0, r9)                    @ vAA<- r0
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 8-9 instructions */


/* ------------------------------ */
    .balign 64
.L_OP_NEG_DOUBLE: /* 0x80 */
/* File: armv6t2_taint/OP_NEG_DOUBLE.S */
/* File: armv6t2_taint/unopWide.S */
    /*
     * Generic 64-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0/r1".
     * This could be an ARM instruction or a function call.
     *
     * For: neg-long, not-long, neg-double, long-to-double, double-to-long
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
// begin WITH_TAINT_TRACKING
    add     r3, rFP, r3, lsl #3         @ r3<- &fp[B]
    add     r9, rFP, r9, lsl #3         @ r9<- &fp[A]
//    ldmia   r3, {r0-r1}                 @ r0/r1<- vAA
    ldr     r0, [r3, #0]
    ldr     r1, [r3, #8]
    ldr     r10, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
                               @ optional op; may set condition codes
    add     r1, r1, #0x80000000                              @ r0/r1<- op, r2-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    b       .LOP_NEG_DOUBLE_finish


/* ------------------------------ */
    .balign 64
.L_OP_INT_TO_LONG: /* 0x81 */
/* File: armv6t2_taint/OP_INT_TO_LONG.S */
/* File: armv6t2_taint/unopWider.S */
    /*
     * Generic 32bit-to-64bit unary operation.  Provide an "instr" line
     * that specifies an instruction that performs "result = op r0", where
     * "result" is a 64-bit quantity in r0/r1.
     *
     * For: int-to-long, int-to-double, float-to-long, float-to-double
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r2)
    GET_VREG_TAINT(r10, r3, r2)
    add     r9, rFP, r9, lsl #3         @ r9<- &fp[A]
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    mov     r1, r0, asr #31                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    b      .LOP_INT_TO_LONG_finish


/* ------------------------------ */
    .balign 64
.L_OP_INT_TO_FLOAT: /* 0x82 */
/* File: arm-vfp_taint/OP_INT_TO_FLOAT.S */
/* File: arm-vfp_taint/funop.S */
    /*
     * Generic 32-bit unary floating-point operation.  Provide an "instr"
     * line that specifies an instruction that performs "s1 = op s0".
     *
     * for: int-to-float, float-to-int
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    mov     r9, rINST, lsr #8           @ r9<- A+
    VREG_INDEX_TO_ADDR(r3, r3)          @ r3<- &vB
    flds    s0, [r3]                    @ s0<- vB
// begin WITH_TAINT_TRACKING
    ldr     r0, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    and     r9, r9, #15                 @ r9<- A
    fsitos  s1, s0                              @ s1<- op
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    VREG_INDEX_TO_ADDR(r9, r9)          @ r9<- &vA
    fsts    s1, [r9]                    @ vA<- s1
// begin WITH_TAINT_TRACKING
    str     r0, [r9, #4]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_INT_TO_DOUBLE: /* 0x83 */
/* File: arm-vfp_taint/OP_INT_TO_DOUBLE.S */
/* File: arm-vfp_taint/funopWider.S */
    /*
     * Generic 32bit-to-64bit floating point unary operation.  Provide an
     * "instr" line that specifies an instruction that performs "d0 = op s0".
     *
     * For: int-to-double, float-to-double
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    mov     r9, rINST, lsr #8           @ r9<- A+
    VREG_INDEX_TO_ADDR(r3, r3)          @ r3<- &vB
    flds    s0, [r3]                    @ s0<- vB
// begin WITH_TAINT_TRACKING
    ldr     r0, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    and     r9, r9, #15                 @ r9<- A
    fsitod  d0, s0                              @ d0<- op
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    VREG_INDEX_TO_ADDR(r9, r9)          @ r9<- &vA
// begin WITH_TAINT_TRACKING
//    fstd    d0, [r9]                    @ vA<- d0
    fsts    s0, [r9]
    fsts    s1, [r9, #8]
    str     r0, [r9, #4]
    str     r0, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_LONG_TO_INT: /* 0x84 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_LONG_TO_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_LONG_TO_FLOAT: /* 0x85 */
/* File: armv6t2_taint/OP_LONG_TO_FLOAT.S */
/* File: armv6t2_taint/unopNarrower.S */
    /*
     * Generic 64bit-to-32bit unary operation.  Provide an "instr" line
     * that specifies an instruction that performs "result = op r0/r1", where
     * "result" is a 32-bit quantity in r0.
     *
     * For: long-to-float, double-to-int, double-to-float
     *
     * (This would work for long-to-int, but that instruction is actually
     * an exact match for OP_MOVE.)
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
// begin WITH_TAINT_TRACKING
    add     r3, rFP, r3, lsl #3         @ r3<- &fp[B]
//    ldmia   r3, {r0-r1}                 @ r0/r1<- vB/vB+1
    ldr     r0, [r3, #0]
    ldr     r10, [r3, #4]
    ldr     r1, [r3, #8]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
                               @ optional op; may set condition codes
    bl      __aeabi_l2f                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
// begin WITH_TAINT_TRACKING
    SET_VREG(r0, r9)                    @ vA<- r0
    SET_TAINT_FP(r1)
    SET_VREG_TAINT(r10, r9, r1)
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 9-10 instructions */


/* ------------------------------ */
    .balign 64
.L_OP_LONG_TO_DOUBLE: /* 0x86 */
/* File: armv6t2_taint/OP_LONG_TO_DOUBLE.S */
/* File: armv6t2_taint/unopWide.S */
    /*
     * Generic 64-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0/r1".
     * This could be an ARM instruction or a function call.
     *
     * For: neg-long, not-long, neg-double, long-to-double, double-to-long
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
// begin WITH_TAINT_TRACKING
    add     r3, rFP, r3, lsl #3         @ r3<- &fp[B]
    add     r9, rFP, r9, lsl #3         @ r9<- &fp[A]
//    ldmia   r3, {r0-r1}                 @ r0/r1<- vAA
    ldr     r0, [r3, #0]
    ldr     r1, [r3, #8]
    ldr     r10, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
                               @ optional op; may set condition codes
    bl      __aeabi_l2d                              @ r0/r1<- op, r2-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    b       .LOP_LONG_TO_DOUBLE_finish


/* ------------------------------ */
    .balign 64
.L_OP_FLOAT_TO_INT: /* 0x87 */
/* File: arm-vfp_taint/OP_FLOAT_TO_INT.S */
/* File: arm-vfp_taint/funop.S */
    /*
     * Generic 32-bit unary floating-point operation.  Provide an "instr"
     * line that specifies an instruction that performs "s1 = op s0".
     *
     * for: int-to-float, float-to-int
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    mov     r9, rINST, lsr #8           @ r9<- A+
    VREG_INDEX_TO_ADDR(r3, r3)          @ r3<- &vB
    flds    s0, [r3]                    @ s0<- vB
// begin WITH_TAINT_TRACKING
    ldr     r0, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    and     r9, r9, #15                 @ r9<- A
    ftosizs s1, s0                              @ s1<- op
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    VREG_INDEX_TO_ADDR(r9, r9)          @ r9<- &vA
    fsts    s1, [r9]                    @ vA<- s1
// begin WITH_TAINT_TRACKING
    str     r0, [r9, #4]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_FLOAT_TO_LONG: /* 0x88 */
/* File: armv6t2_taint/OP_FLOAT_TO_LONG.S */
@include "armv6t2_taint/unopWider.S" {"instr":"bl      __aeabi_f2lz"}
/* File: armv6t2_taint/unopWider.S */
    /*
     * Generic 32bit-to-64bit unary operation.  Provide an "instr" line
     * that specifies an instruction that performs "result = op r0", where
     * "result" is a 64-bit quantity in r0/r1.
     *
     * For: int-to-long, int-to-double, float-to-long, float-to-double
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r2)
    GET_VREG_TAINT(r10, r3, r2)
    add     r9, rFP, r9, lsl #3         @ r9<- &fp[A]
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    bl      f2l_doconv                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    b      .LOP_FLOAT_TO_LONG_finish



/* ------------------------------ */
    .balign 64
.L_OP_FLOAT_TO_DOUBLE: /* 0x89 */
/* File: arm-vfp_taint/OP_FLOAT_TO_DOUBLE.S */
/* File: arm-vfp_taint/funopWider.S */
    /*
     * Generic 32bit-to-64bit floating point unary operation.  Provide an
     * "instr" line that specifies an instruction that performs "d0 = op s0".
     *
     * For: int-to-double, float-to-double
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    mov     r9, rINST, lsr #8           @ r9<- A+
    VREG_INDEX_TO_ADDR(r3, r3)          @ r3<- &vB
    flds    s0, [r3]                    @ s0<- vB
// begin WITH_TAINT_TRACKING
    ldr     r0, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    and     r9, r9, #15                 @ r9<- A
    fcvtds  d0, s0                              @ d0<- op
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    VREG_INDEX_TO_ADDR(r9, r9)          @ r9<- &vA
// begin WITH_TAINT_TRACKING
//    fstd    d0, [r9]                    @ vA<- d0
    fsts    s0, [r9]
    fsts    s1, [r9, #8]
    str     r0, [r9, #4]
    str     r0, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_DOUBLE_TO_INT: /* 0x8a */
/* File: arm-vfp_taint/OP_DOUBLE_TO_INT.S */
/* File: arm-vfp_taint/funopNarrower.S */
    /*
     * Generic 64bit-to-32bit unary floating point operation.  Provide an
     * "instr" line that specifies an instruction that performs "s0 = op d0".
     *
     * For: double-to-int, double-to-float
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    mov     r9, rINST, lsr #8           @ r9<- A+
    VREG_INDEX_TO_ADDR(r3, r3)          @ r3<- &vB
// begin WITH_TAINT_TRACKING
//    fldd    d0, [r3]                    @ d0<- vB
    flds    s0, [r3]
    flds    s1, [r3, #8]
    ldr     r0, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    and     r9, r9, #15                 @ r9<- A
    ftosizd  s0, d0                              @ s0<- op
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    VREG_INDEX_TO_ADDR(r9, r9)          @ r9<- &vA
    fsts    s0, [r9]                    @ vA<- s0
// begin WITH_TAINT_TRACKING
    str     r0, [r9, #4]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_DOUBLE_TO_LONG: /* 0x8b */
/* File: armv6t2_taint/OP_DOUBLE_TO_LONG.S */
@include "armv6t2_taint/unopWide.S" {"instr":"bl      __aeabi_d2lz"}
/* File: armv6t2_taint/unopWide.S */
    /*
     * Generic 64-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0/r1".
     * This could be an ARM instruction or a function call.
     *
     * For: neg-long, not-long, neg-double, long-to-double, double-to-long
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
// begin WITH_TAINT_TRACKING
    add     r3, rFP, r3, lsl #3         @ r3<- &fp[B]
    add     r9, rFP, r9, lsl #3         @ r9<- &fp[A]
//    ldmia   r3, {r0-r1}                 @ r0/r1<- vAA
    ldr     r0, [r3, #0]
    ldr     r1, [r3, #8]
    ldr     r10, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
                               @ optional op; may set condition codes
    bl      d2l_doconv                              @ r0/r1<- op, r2-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    b       .LOP_DOUBLE_TO_LONG_finish



/* ------------------------------ */
    .balign 64
.L_OP_DOUBLE_TO_FLOAT: /* 0x8c */
/* File: arm-vfp_taint/OP_DOUBLE_TO_FLOAT.S */
/* File: arm-vfp_taint/funopNarrower.S */
    /*
     * Generic 64bit-to-32bit unary floating point operation.  Provide an
     * "instr" line that specifies an instruction that performs "s0 = op d0".
     *
     * For: double-to-int, double-to-float
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    mov     r9, rINST, lsr #8           @ r9<- A+
    VREG_INDEX_TO_ADDR(r3, r3)          @ r3<- &vB
// begin WITH_TAINT_TRACKING
//    fldd    d0, [r3]                    @ d0<- vB
    flds    s0, [r3]
    flds    s1, [r3, #8]
    ldr     r0, [r3, #4]
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    and     r9, r9, #15                 @ r9<- A
    fcvtsd  s0, d0                              @ s0<- op
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    VREG_INDEX_TO_ADDR(r9, r9)          @ r9<- &vA
    fsts    s0, [r9]                    @ vA<- s0
// begin WITH_TAINT_TRACKING
    str     r0, [r9, #4]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_INT_TO_BYTE: /* 0x8d */
/* File: armv6t2_taint/OP_INT_TO_BYTE.S */
/* File: armv6t2_taint/unop.S */
    /*
     * Generic 32-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0".
     * This could be an ARM instruction or a function call.
     *
     * for: neg-int, not-int, neg-float, int-to-float, float-to-int,
     *      int-to-byte, int-to-char, int-to-short
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    GET_VREG_TAINT(r2, r3, r1)          @ r2<- vB.taint
    SET_VREG_TAINT(r2, r9, r1)
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    sxtb    r0, r0                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    SET_VREG(r0, r9)                    @ vAA<- r0
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 8-9 instructions */


/* ------------------------------ */
    .balign 64
.L_OP_INT_TO_CHAR: /* 0x8e */
/* File: armv6t2_taint/OP_INT_TO_CHAR.S */
/* File: armv6t2_taint/unop.S */
    /*
     * Generic 32-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0".
     * This could be an ARM instruction or a function call.
     *
     * for: neg-int, not-int, neg-float, int-to-float, float-to-int,
     *      int-to-byte, int-to-char, int-to-short
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    GET_VREG_TAINT(r2, r3, r1)          @ r2<- vB.taint
    SET_VREG_TAINT(r2, r9, r1)
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    uxth    r0, r0                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    SET_VREG(r0, r9)                    @ vAA<- r0
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 8-9 instructions */


/* ------------------------------ */
    .balign 64
.L_OP_INT_TO_SHORT: /* 0x8f */
/* File: armv6t2_taint/OP_INT_TO_SHORT.S */
/* File: armv6t2_taint/unop.S */
    /*
     * Generic 32-bit unary operation.  Provide an "instr" line that
     * specifies an instruction that performs "result = op r0".
     * This could be an ARM instruction or a function call.
     *
     * for: neg-int, not-int, neg-float, int-to-float, float-to-int,
     *      int-to-byte, int-to-char, int-to-short
     */
    /* unop vA, vB */
    mov     r3, rINST, lsr #12          @ r3<- B
    ubfx    r9, rINST, #8, #4           @ r9<- A
    GET_VREG(r0, r3)                    @ r0<- vB
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    GET_VREG_TAINT(r2, r3, r1)          @ r2<- vB.taint
    SET_VREG_TAINT(r2, r9, r1)
// end WITH_TAINT_TRACKING
                               @ optional op; may set condition codes
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    sxth    r0, r0                              @ r0<- op, r0-r3 changed
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    SET_VREG(r0, r9)                    @ vAA<- r0
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 8-9 instructions */


/* ------------------------------ */
    .balign 64
.L_OP_ADD_INT: /* 0x90 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_INT: /* 0x91 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_INT: /* 0x92 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_INT: /* 0x93 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_INT: /* 0x94 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AND_INT: /* 0x95 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AND_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_OR_INT: /* 0x96 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_OR_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_XOR_INT: /* 0x97 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_XOR_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHL_INT: /* 0x98 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHL_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHR_INT: /* 0x99 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHR_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_USHR_INT: /* 0x9a */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_USHR_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_LONG: /* 0x9b */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_LONG: /* 0x9c */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_LONG: /* 0x9d */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_LONG: /* 0x9e */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_LONG: /* 0x9f */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AND_LONG: /* 0xa0 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AND_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_OR_LONG: /* 0xa1 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_OR_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_XOR_LONG: /* 0xa2 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_XOR_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHL_LONG: /* 0xa3 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHL_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHR_LONG: /* 0xa4 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHR_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_USHR_LONG: /* 0xa5 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_USHR_LONG      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_FLOAT: /* 0xa6 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_FLOAT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_FLOAT: /* 0xa7 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_FLOAT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_FLOAT: /* 0xa8 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_FLOAT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_FLOAT: /* 0xa9 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_FLOAT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_FLOAT: /* 0xaa */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_FLOAT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_DOUBLE: /* 0xab */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_DOUBLE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_DOUBLE: /* 0xac */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_DOUBLE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_DOUBLE: /* 0xad */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_DOUBLE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_DOUBLE: /* 0xae */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_DOUBLE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_DOUBLE: /* 0xaf */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_DOUBLE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_INT_2ADDR: /* 0xb0 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_INT_2ADDR: /* 0xb1 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_INT_2ADDR: /* 0xb2 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_INT_2ADDR: /* 0xb3 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_INT_2ADDR: /* 0xb4 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AND_INT_2ADDR: /* 0xb5 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AND_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_OR_INT_2ADDR: /* 0xb6 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_OR_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_XOR_INT_2ADDR: /* 0xb7 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_XOR_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHL_INT_2ADDR: /* 0xb8 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHL_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHR_INT_2ADDR: /* 0xb9 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHR_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_USHR_INT_2ADDR: /* 0xba */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_USHR_INT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_LONG_2ADDR: /* 0xbb */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_LONG_2ADDR: /* 0xbc */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_LONG_2ADDR: /* 0xbd */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_LONG_2ADDR: /* 0xbe */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_LONG_2ADDR: /* 0xbf */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AND_LONG_2ADDR: /* 0xc0 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AND_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_OR_LONG_2ADDR: /* 0xc1 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_OR_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_XOR_LONG_2ADDR: /* 0xc2 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_XOR_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHL_LONG_2ADDR: /* 0xc3 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHL_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHR_LONG_2ADDR: /* 0xc4 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHR_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_USHR_LONG_2ADDR: /* 0xc5 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_USHR_LONG_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_FLOAT_2ADDR: /* 0xc6 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_FLOAT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_FLOAT_2ADDR: /* 0xc7 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_FLOAT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_FLOAT_2ADDR: /* 0xc8 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_FLOAT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_FLOAT_2ADDR: /* 0xc9 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_FLOAT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_FLOAT_2ADDR: /* 0xca */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_FLOAT_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_DOUBLE_2ADDR: /* 0xcb */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_DOUBLE_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SUB_DOUBLE_2ADDR: /* 0xcc */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SUB_DOUBLE_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_DOUBLE_2ADDR: /* 0xcd */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_DOUBLE_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_DOUBLE_2ADDR: /* 0xce */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_DOUBLE_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_DOUBLE_2ADDR: /* 0xcf */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_DOUBLE_2ADDR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_INT_LIT16: /* 0xd0 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_INT_LIT16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_RSUB_INT: /* 0xd1 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_RSUB_INT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_INT_LIT16: /* 0xd2 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_INT_LIT16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_INT_LIT16: /* 0xd3 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_INT_LIT16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_INT_LIT16: /* 0xd4 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_INT_LIT16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AND_INT_LIT16: /* 0xd5 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AND_INT_LIT16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_OR_INT_LIT16: /* 0xd6 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_OR_INT_LIT16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_XOR_INT_LIT16: /* 0xd7 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_XOR_INT_LIT16      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_ADD_INT_LIT8: /* 0xd8 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_ADD_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_RSUB_INT_LIT8: /* 0xd9 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_RSUB_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_MUL_INT_LIT8: /* 0xda */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_MUL_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_DIV_INT_LIT8: /* 0xdb */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_DIV_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_REM_INT_LIT8: /* 0xdc */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_REM_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_AND_INT_LIT8: /* 0xdd */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_AND_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_OR_INT_LIT8: /* 0xde */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_OR_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_XOR_INT_LIT8: /* 0xdf */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_XOR_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHL_INT_LIT8: /* 0xe0 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHL_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SHR_INT_LIT8: /* 0xe1 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SHR_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_USHR_INT_LIT8: /* 0xe2 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_USHR_INT_LIT8      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_VOLATILE: /* 0xe3 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_VOLATILE: /* 0xe4 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_VOLATILE: /* 0xe5 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_VOLATILE: /* 0xe6 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_OBJECT_VOLATILE: /* 0xe7 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_OBJECT_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_WIDE_VOLATILE: /* 0xe8 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_WIDE_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_WIDE_VOLATILE: /* 0xe9 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_WIDE_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_WIDE_VOLATILE: /* 0xea */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_WIDE_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_WIDE_VOLATILE: /* 0xeb */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_WIDE_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_BREAKPOINT: /* 0xec */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_BREAKPOINT      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_THROW_VERIFICATION_ERROR: /* 0xed */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_THROW_VERIFICATION_ERROR      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_EXECUTE_INLINE: /* 0xee */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_EXECUTE_INLINE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_EXECUTE_INLINE_RANGE: /* 0xef */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_EXECUTE_INLINE_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_OBJECT_INIT_RANGE: /* 0xf0 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_OBJECT_INIT_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_RETURN_VOID_BARRIER: /* 0xf1 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_RETURN_VOID_BARRIER      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IGET_QUICK: /* 0xf2 */
/* File: armv6t2_taint/OP_IGET_QUICK.S */
    /* For: iget-quick, iget-object-quick */
    /* op vA, vB, offset@CCCC */
    mov     r2, rINST, lsr #12          @ r2<- B
    FETCH(r1, 1)                        @ r1<- field byte offset
    GET_VREG(r3, r2)                    @ r3<- object we're operating on
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r0)
    GET_VREG_TAINT(r9, r2, r0)
// end WITH_TAINT_TRACKING
    ubfx    r2, rINST, #8, #4           @ r2<- A
    cmp     r3, #0                      @ check object for null
    beq     common_errNullObject        @ object was null
    ldr     r0, [r3, r1]                @ r0<- obj.field (always 32 bits)
// begin WITH_TAINT_TRACKING
    bl      .LOP_IGET_QUICK_taint_prop
//    FETCH_ADVANCE_INST(2)               @ advance rPC, load rINST // in subroutine
// end WITH_TAINT_TRACKING
    SET_VREG(r0, r2)                    @ fp[A]<- r0
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r0)
    SET_VREG_TAINT(r10, r2, r0)
// end WITH_TAINT_TRACKING
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IGET_WIDE_QUICK: /* 0xf3 */
/* File: armv6t2_taint/OP_IGET_WIDE_QUICK.S */
    /* iget-wide-quick vA, vB, offset@CCCC */
    mov     r2, rINST, lsr #12          @ r2<- B
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r0)
    GET_VREG_TAINT(r9, r2, r0)
// end WITH_TAINT_TRACKING
    FETCH(ip, 1)                        @ ip<- field byte offset
    GET_VREG(r3, r2)                    @ r3<- object we're operating on
    ubfx    r2, rINST, #8, #4           @ r2<- A
    cmp     r3, #0                      @ check object for null
    beq     common_errNullObject        @ object was null
// begin WITH_TAINT_TRACKING
    add     r10, ip, #8
    ldrd    r0, [r3, ip]                @ r0<- obj.field (64 bits, aligned)
    ldr     r10, [r3, r10]
    orr     r10, r9, r10
// end WITH_TAINT_TRACKING
    FETCH_ADVANCE_INST(2)               @ advance rPC, load rINST
// begin WITH_TAINT_TRACKING
    bl      iget_wide_quick_taint_prop
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction


/* ------------------------------ */
    .balign 64
.L_OP_IGET_OBJECT_QUICK: /* 0xf4 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IGET_OBJECT_QUICK      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_QUICK: /* 0xf5 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_QUICK      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_WIDE_QUICK: /* 0xf6 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_WIDE_QUICK      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_OBJECT_QUICK: /* 0xf7 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_OBJECT_QUICK      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_VIRTUAL_QUICK: /* 0xf8 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_VIRTUAL_QUICK      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_VIRTUAL_QUICK_RANGE: /* 0xf9 */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_VIRTUAL_QUICK_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_SUPER_QUICK: /* 0xfa */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_SUPER_QUICK      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_INVOKE_SUPER_QUICK_RANGE: /* 0xfb */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_INVOKE_SUPER_QUICK_RANGE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_IPUT_OBJECT_VOLATILE: /* 0xfc */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_IPUT_OBJECT_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SGET_OBJECT_VOLATILE: /* 0xfd */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SGET_OBJECT_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_SPUT_OBJECT_VOLATILE: /* 0xfe */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_SPUT_OBJECT_VOLATILE      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
/* ------------------------------ */
    .balign 64
.L_OP_UNUSED_FF: /* 0xff */
    /* (stub) */
    SAVE_PC_FP_TO_SELF()            @ only need to export these two
    mov     r0, rSELF               @ self is first arg to function
    bl      dvmMterp_OP_UNUSED_FF      @ call
    LOAD_PC_FP_FROM_SELF()          @ retrieve updated values
    FETCH_INST()                    @ load next instruction from rPC
    GET_INST_OPCODE(ip)             @ ...trim down to just the opcode
    GOTO_OPCODE(ip)                 @ ...and jump to the handler
    .balign 64
    .size   dvmAsmInstructionStart, .-dvmAsmInstructionStart
    .global dvmAsmInstructionEnd
dvmAsmInstructionEnd:

/*
 * ===========================================================================
 *  Sister implementations
 * ===========================================================================
 */
    .global dvmAsmSisterStart
    .type   dvmAsmSisterStart, %function
    .text
    .balign 4
dvmAsmSisterStart:

/* continuation for OP_IGET */

    /*
     * Currently:
     *  r0 holds resolved field
     *  r9 holds object
     */
.LOP_IGET_finish:
    @bl      common_squeak0
    cmp     r9, #0                      @ check object for null
    ldr     r3, [r0, #offInstField_byteOffset]  @ r3<- byte offset of field
    beq     common_errNullObject        @ object was null
// begin WITH_TAINT_TRACKING
    ldr   r0, [r9, r3]                @ r0<- obj.field (8/16/32 bits)
    add     r3, r3, #4
    ldr	    r3, [r9, r3]
    orr     r3, r3, r10
// end WITH_TAINT_TRACKING
    ubfx    r2, rINST, #8, #4           @ r2<- A
    FETCH_ADVANCE_INST(2)               @ advance rPC, load rINST
    SET_VREG(r0, r2)                    @ fp[A]<- r0
// begin WITH_TAINT_TRACKING
    SET_TAINT_FP(r1)
    SET_VREG_TAINT(r3, r2, r1)
// end WITH_TAINT_TRACKING
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction

.LOP_IGET_taint_prop:
    GET_VREG(r9, r0)                    @ r9<- fp[B], the object pointer
    SET_TAINT_FP(r3)
    GET_VREG_TAINT(r10, r0, r3)
    ldr     r0, [r2, r1, lsl #2]        @ r0<- resolved InstField ptr
    bx      lr

/* continuation for OP_IGET_WIDE */

    /*
     * Currently:
     *  r0 holds resolved field
     *  r9 holds object
     */
.LOP_IGET_WIDE_finish:
    cmp     r9, #0                      @ check object for null
    ldr     r3, [r0, #offInstField_byteOffset]  @ r3<- byte offset of field
    beq     common_errNullObject        @ object was null
// begin WITH_TAINT_TRACKING
    ldrd    r0, [r9, r3]                @ r0/r1<- obj.field (64-bit align ok)
    add     r3, r3, #8
    ldr     r3, [r9, r3]
    orr	    r10, r3, r10
    ubfx    r2, rINST, #8, #4           @ r2<- A
    FETCH_ADVANCE_INST(2)               @ advance rPC, load rINST
    add     r3, rFP, r2, lsl #3         @ r3<- &fp[A]
// end WITH_TAINT_TRACKING
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
// begin WITH_TAINT_TRACKING
//    stmia   r3, {r0-r1}                 @ fp[A]<- r0/r1
    str    r0, [r3, #0]
    str    r10, [r3, #4]
    str    r1, [r3, #8]
    str    r10, [r3, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction

.LOP_IGET_WIDE_taint_prop:
    GET_VREG(r9, r0)                    @ r9<- fp[B], the object pointer
    SET_TAINT_FP(r3)
    GET_VREG_TAINT(r10, r0, r3)
    ldr     r0, [r2, r1, lsl #2]        @ r0<- resolved InstField ptr
    bx      lr

/* continuation for OP_NEG_LONG */

.LOP_NEG_LONG_finish:
// begin WITH_TAINT_TRACKING
//    stmia   r9, {r0-r1}                 @ vAA<- r0/r1
    str     r0, [r9, #0]
    str     r10, [r9, #4]
    str     r1, [r9, #8]
    str     r10, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 10-11 instructions */

/* continuation for OP_NOT_LONG */

.LOP_NOT_LONG_finish:
// begin WITH_TAINT_TRACKING
//    stmia   r9, {r0-r1}                 @ vAA<- r0/r1
    str     r0, [r9, #0]
    str     r10, [r9, #4]
    str     r1, [r9, #8]
    str     r10, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 10-11 instructions */

/* continuation for OP_NEG_DOUBLE */

.LOP_NEG_DOUBLE_finish:
// begin WITH_TAINT_TRACKING
//    stmia   r9, {r0-r1}                 @ vAA<- r0/r1
    str     r0, [r9, #0]
    str     r10, [r9, #4]
    str     r1, [r9, #8]
    str     r10, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 10-11 instructions */

/* continuation for OP_INT_TO_LONG */

.LOP_INT_TO_LONG_finish:
// begin WITH_TAINT_TRACKING
//    stmia   r9, {r0-r1}                 @ vA/vA+1<- r0/r1
    str     r0, [r9, #0]
    str     r10, [r9, #4]
    str     r1, [r9, #8]
    str     r10, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 9-10 instructions */

/* continuation for OP_LONG_TO_DOUBLE */

.LOP_LONG_TO_DOUBLE_finish:
// begin WITH_TAINT_TRACKING
//    stmia   r9, {r0-r1}                 @ vAA<- r0/r1
    str     r0, [r9, #0]
    str     r10, [r9, #4]
    str     r1, [r9, #8]
    str     r10, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 10-11 instructions */

/* continuation for OP_FLOAT_TO_LONG */

.LOP_FLOAT_TO_LONG_finish:
// begin WITH_TAINT_TRACKING
//    stmia   r9, {r0-r1}                 @ vA/vA+1<- r0/r1
    str     r0, [r9, #0]
    str     r10, [r9, #4]
    str     r1, [r9, #8]
    str     r10, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 9-10 instructions */

/* continuation for OP_FLOAT_TO_LONG */
/*
 * Convert the float in r0 to a long in r0/r1.
 *
 * We have to clip values to long min/max per the specification.  The
 * expected common case is a "reasonable" value that converts directly
 * to modest integer.  The EABI convert function isn't doing this for us.
 */
f2l_doconv:
    stmfd   sp!, {r4, lr}
    mov     r1, #0x5f000000             @ (float)maxlong
    mov     r4, r0
    bl      __aeabi_fcmpge              @ is arg >= maxlong?
    cmp     r0, #0                      @ nonzero == yes
    mvnne   r0, #0                      @ return maxlong (7fffffff)
    mvnne   r1, #0x80000000
    ldmnefd sp!, {r4, pc}

    mov     r0, r4                      @ recover arg
    mov     r1, #0xdf000000             @ (float)minlong
    bl      __aeabi_fcmple              @ is arg <= minlong?
    cmp     r0, #0                      @ nonzero == yes
    movne   r0, #0                      @ return minlong (80000000)
    movne   r1, #0x80000000
    ldmnefd sp!, {r4, pc}

    mov     r0, r4                      @ recover arg
    mov     r1, r4
    bl      __aeabi_fcmpeq              @ is arg == self?
    cmp     r0, #0                      @ zero == no
    moveq   r1, #0                      @ return zero for NaN
    ldmeqfd sp!, {r4, pc}

    mov     r0, r4                      @ recover arg
    bl      __aeabi_f2lz                @ convert float to long
    ldmfd   sp!, {r4, pc}

/* continuation for OP_DOUBLE_TO_LONG */

.LOP_DOUBLE_TO_LONG_finish:
// begin WITH_TAINT_TRACKING
//    stmia   r9, {r0-r1}                 @ vAA<- r0/r1
    str     r0, [r9, #0]
    str     r10, [r9, #4]
    str     r1, [r9, #8]
    str     r10, [r9, #12]
// end WITH_TAINT_TRACKING
    GOTO_OPCODE(ip)                     @ jump to next instruction
    /* 10-11 instructions */

/* continuation for OP_DOUBLE_TO_LONG */
/*
 * Convert the double in r0/r1 to a long in r0/r1.
 *
 * We have to clip values to long min/max per the specification.  The
 * expected common case is a "reasonable" value that converts directly
 * to modest integer.  The EABI convert function isn't doing this for us.
 */
d2l_doconv:
    stmfd   sp!, {r4, r5, lr}           @ save regs
    mov     r3, #0x43000000             @ maxlong, as a double (high word)
    add     r3, #0x00e00000             @  0x43e00000
    mov     r2, #0                      @ maxlong, as a double (low word)
    sub     sp, sp, #4                  @ align for EABI
    mov     r4, r0                      @ save a copy of r0
    mov     r5, r1                      @  and r1
    bl      __aeabi_dcmpge              @ is arg >= maxlong?
    cmp     r0, #0                      @ nonzero == yes
    mvnne   r0, #0                      @ return maxlong (7fffffffffffffff)
    mvnne   r1, #0x80000000
    bne     1f

    mov     r0, r4                      @ recover arg
    mov     r1, r5
    mov     r3, #0xc3000000             @ minlong, as a double (high word)
    add     r3, #0x00e00000             @  0xc3e00000
    mov     r2, #0                      @ minlong, as a double (low word)
    bl      __aeabi_dcmple              @ is arg <= minlong?
    cmp     r0, #0                      @ nonzero == yes
    movne   r0, #0                      @ return minlong (8000000000000000)
    movne   r1, #0x80000000
    bne     1f

    mov     r0, r4                      @ recover arg
    mov     r1, r5
    mov     r2, r4                      @ compare against self
    mov     r3, r5
    bl      __aeabi_dcmpeq              @ is arg == self?
    cmp     r0, #0                      @ zero == no
    moveq   r1, #0                      @ return zero for NaN
    beq     1f

    mov     r0, r4                      @ recover arg
    mov     r1, r5
    bl      __aeabi_d2lz                @ convert double to long

1:
    add     sp, sp, #4
    ldmfd   sp!, {r4, r5, pc}

/* continuation for OP_IGET_QUICK */

.LOP_IGET_QUICK_taint_prop:
    add     r1, r1, #4
    ldr     r10, [r3, r1]
    orr     r10, r9, r10
    FETCH_ADVANCE_INST(2)               @ advance rPC, load rINST
    bx      lr


/* continuation for OP_IGET_WIDE_QUICK */

iget_wide_quick_taint_prop:
    add     r3, rFP, r2, lsl #3         @ r3<- &fp[A]
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
//    stmia   r3, {r0-r1}                 @ fp[A]<- r0/r1
    str     r0, [r3, #0]
    str     r10, [r3, #4]
    str     r1, [r3, #8]
    str     r10, [r3, #12]
    bx      lr

    .size   dvmAsmSisterStart, .-dvmAsmSisterStart
    .global dvmAsmSisterEnd
dvmAsmSisterEnd:


    .global dvmAsmAltInstructionStart
    .type   dvmAsmAltInstructionStart, %function
    .text

dvmAsmAltInstructionStart = .L_ALT_OP_NOP
/* ------------------------------ */
    .balign 64
.L_ALT_OP_NOP: /* 0x00 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (0 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE: /* 0x01 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (1 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_FROM16: /* 0x02 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (2 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_16: /* 0x03 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (3 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_WIDE: /* 0x04 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (4 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_WIDE_FROM16: /* 0x05 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (5 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_WIDE_16: /* 0x06 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (6 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_OBJECT: /* 0x07 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (7 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_OBJECT_FROM16: /* 0x08 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (8 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_OBJECT_16: /* 0x09 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (9 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_RESULT: /* 0x0a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (10 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_RESULT_WIDE: /* 0x0b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (11 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_RESULT_OBJECT: /* 0x0c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (12 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MOVE_EXCEPTION: /* 0x0d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (13 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_RETURN_VOID: /* 0x0e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (14 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_RETURN: /* 0x0f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (15 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_RETURN_WIDE: /* 0x10 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (16 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_RETURN_OBJECT: /* 0x11 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (17 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_4: /* 0x12 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (18 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_16: /* 0x13 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (19 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST: /* 0x14 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (20 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_HIGH16: /* 0x15 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (21 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_WIDE_16: /* 0x16 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (22 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_WIDE_32: /* 0x17 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (23 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_WIDE: /* 0x18 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (24 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_WIDE_HIGH16: /* 0x19 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (25 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_STRING: /* 0x1a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (26 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_STRING_JUMBO: /* 0x1b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (27 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CONST_CLASS: /* 0x1c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (28 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MONITOR_ENTER: /* 0x1d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (29 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MONITOR_EXIT: /* 0x1e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (30 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CHECK_CAST: /* 0x1f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (31 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INSTANCE_OF: /* 0x20 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (32 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ARRAY_LENGTH: /* 0x21 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (33 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NEW_INSTANCE: /* 0x22 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (34 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NEW_ARRAY: /* 0x23 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (35 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_FILLED_NEW_ARRAY: /* 0x24 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (36 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_FILLED_NEW_ARRAY_RANGE: /* 0x25 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (37 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_FILL_ARRAY_DATA: /* 0x26 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (38 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_THROW: /* 0x27 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (39 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_GOTO: /* 0x28 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (40 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_GOTO_16: /* 0x29 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (41 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_GOTO_32: /* 0x2a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (42 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_PACKED_SWITCH: /* 0x2b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (43 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPARSE_SWITCH: /* 0x2c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (44 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CMPL_FLOAT: /* 0x2d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (45 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CMPG_FLOAT: /* 0x2e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (46 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CMPL_DOUBLE: /* 0x2f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (47 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CMPG_DOUBLE: /* 0x30 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (48 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_CMP_LONG: /* 0x31 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (49 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_EQ: /* 0x32 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (50 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_NE: /* 0x33 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (51 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_LT: /* 0x34 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (52 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_GE: /* 0x35 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (53 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_GT: /* 0x36 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (54 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_LE: /* 0x37 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (55 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_EQZ: /* 0x38 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (56 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_NEZ: /* 0x39 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (57 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_LTZ: /* 0x3a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (58 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_GEZ: /* 0x3b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (59 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_GTZ: /* 0x3c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (60 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IF_LEZ: /* 0x3d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (61 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_3E: /* 0x3e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (62 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_3F: /* 0x3f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (63 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_40: /* 0x40 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (64 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_41: /* 0x41 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (65 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_42: /* 0x42 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (66 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_43: /* 0x43 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (67 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AGET: /* 0x44 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (68 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AGET_WIDE: /* 0x45 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (69 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AGET_OBJECT: /* 0x46 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (70 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AGET_BOOLEAN: /* 0x47 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (71 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AGET_BYTE: /* 0x48 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (72 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AGET_CHAR: /* 0x49 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (73 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AGET_SHORT: /* 0x4a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (74 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_APUT: /* 0x4b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (75 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_APUT_WIDE: /* 0x4c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (76 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_APUT_OBJECT: /* 0x4d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (77 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_APUT_BOOLEAN: /* 0x4e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (78 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_APUT_BYTE: /* 0x4f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (79 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_APUT_CHAR: /* 0x50 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (80 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_APUT_SHORT: /* 0x51 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (81 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET: /* 0x52 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (82 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_WIDE: /* 0x53 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (83 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_OBJECT: /* 0x54 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (84 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_BOOLEAN: /* 0x55 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (85 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_BYTE: /* 0x56 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (86 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_CHAR: /* 0x57 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (87 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_SHORT: /* 0x58 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (88 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT: /* 0x59 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (89 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_WIDE: /* 0x5a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (90 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_OBJECT: /* 0x5b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (91 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_BOOLEAN: /* 0x5c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (92 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_BYTE: /* 0x5d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (93 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_CHAR: /* 0x5e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (94 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_SHORT: /* 0x5f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (95 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET: /* 0x60 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (96 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_WIDE: /* 0x61 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (97 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_OBJECT: /* 0x62 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (98 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_BOOLEAN: /* 0x63 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (99 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_BYTE: /* 0x64 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (100 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_CHAR: /* 0x65 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (101 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_SHORT: /* 0x66 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (102 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT: /* 0x67 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (103 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_WIDE: /* 0x68 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (104 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_OBJECT: /* 0x69 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (105 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_BOOLEAN: /* 0x6a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (106 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_BYTE: /* 0x6b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (107 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_CHAR: /* 0x6c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (108 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_SHORT: /* 0x6d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (109 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_VIRTUAL: /* 0x6e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (110 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_SUPER: /* 0x6f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (111 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_DIRECT: /* 0x70 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (112 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_STATIC: /* 0x71 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (113 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_INTERFACE: /* 0x72 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (114 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_73: /* 0x73 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (115 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_VIRTUAL_RANGE: /* 0x74 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (116 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_SUPER_RANGE: /* 0x75 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (117 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_DIRECT_RANGE: /* 0x76 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (118 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_STATIC_RANGE: /* 0x77 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (119 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_INTERFACE_RANGE: /* 0x78 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (120 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_79: /* 0x79 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (121 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_7A: /* 0x7a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (122 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NEG_INT: /* 0x7b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (123 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NOT_INT: /* 0x7c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (124 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NEG_LONG: /* 0x7d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (125 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NOT_LONG: /* 0x7e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (126 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NEG_FLOAT: /* 0x7f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (127 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_NEG_DOUBLE: /* 0x80 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (128 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INT_TO_LONG: /* 0x81 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (129 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INT_TO_FLOAT: /* 0x82 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (130 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INT_TO_DOUBLE: /* 0x83 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (131 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_LONG_TO_INT: /* 0x84 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (132 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_LONG_TO_FLOAT: /* 0x85 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (133 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_LONG_TO_DOUBLE: /* 0x86 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (134 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_FLOAT_TO_INT: /* 0x87 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (135 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_FLOAT_TO_LONG: /* 0x88 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (136 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_FLOAT_TO_DOUBLE: /* 0x89 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (137 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DOUBLE_TO_INT: /* 0x8a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (138 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DOUBLE_TO_LONG: /* 0x8b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (139 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DOUBLE_TO_FLOAT: /* 0x8c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (140 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INT_TO_BYTE: /* 0x8d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (141 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INT_TO_CHAR: /* 0x8e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (142 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INT_TO_SHORT: /* 0x8f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (143 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_INT: /* 0x90 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (144 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_INT: /* 0x91 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (145 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_INT: /* 0x92 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (146 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_INT: /* 0x93 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (147 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_INT: /* 0x94 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (148 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AND_INT: /* 0x95 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (149 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_OR_INT: /* 0x96 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (150 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_XOR_INT: /* 0x97 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (151 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHL_INT: /* 0x98 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (152 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHR_INT: /* 0x99 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (153 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_USHR_INT: /* 0x9a */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (154 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_LONG: /* 0x9b */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (155 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_LONG: /* 0x9c */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (156 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_LONG: /* 0x9d */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (157 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_LONG: /* 0x9e */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (158 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_LONG: /* 0x9f */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (159 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AND_LONG: /* 0xa0 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (160 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_OR_LONG: /* 0xa1 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (161 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_XOR_LONG: /* 0xa2 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (162 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHL_LONG: /* 0xa3 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (163 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHR_LONG: /* 0xa4 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (164 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_USHR_LONG: /* 0xa5 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (165 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_FLOAT: /* 0xa6 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (166 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_FLOAT: /* 0xa7 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (167 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_FLOAT: /* 0xa8 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (168 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_FLOAT: /* 0xa9 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (169 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_FLOAT: /* 0xaa */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (170 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_DOUBLE: /* 0xab */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (171 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_DOUBLE: /* 0xac */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (172 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_DOUBLE: /* 0xad */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (173 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_DOUBLE: /* 0xae */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (174 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_DOUBLE: /* 0xaf */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (175 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_INT_2ADDR: /* 0xb0 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (176 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_INT_2ADDR: /* 0xb1 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (177 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_INT_2ADDR: /* 0xb2 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (178 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_INT_2ADDR: /* 0xb3 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (179 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_INT_2ADDR: /* 0xb4 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (180 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AND_INT_2ADDR: /* 0xb5 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (181 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_OR_INT_2ADDR: /* 0xb6 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (182 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_XOR_INT_2ADDR: /* 0xb7 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (183 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHL_INT_2ADDR: /* 0xb8 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (184 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHR_INT_2ADDR: /* 0xb9 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (185 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_USHR_INT_2ADDR: /* 0xba */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (186 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_LONG_2ADDR: /* 0xbb */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (187 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_LONG_2ADDR: /* 0xbc */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (188 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_LONG_2ADDR: /* 0xbd */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (189 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_LONG_2ADDR: /* 0xbe */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (190 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_LONG_2ADDR: /* 0xbf */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (191 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AND_LONG_2ADDR: /* 0xc0 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (192 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_OR_LONG_2ADDR: /* 0xc1 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (193 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_XOR_LONG_2ADDR: /* 0xc2 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (194 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHL_LONG_2ADDR: /* 0xc3 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (195 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHR_LONG_2ADDR: /* 0xc4 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (196 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_USHR_LONG_2ADDR: /* 0xc5 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (197 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_FLOAT_2ADDR: /* 0xc6 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (198 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_FLOAT_2ADDR: /* 0xc7 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (199 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_FLOAT_2ADDR: /* 0xc8 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (200 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_FLOAT_2ADDR: /* 0xc9 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (201 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_FLOAT_2ADDR: /* 0xca */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (202 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_DOUBLE_2ADDR: /* 0xcb */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (203 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SUB_DOUBLE_2ADDR: /* 0xcc */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (204 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_DOUBLE_2ADDR: /* 0xcd */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (205 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_DOUBLE_2ADDR: /* 0xce */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (206 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_DOUBLE_2ADDR: /* 0xcf */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (207 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_INT_LIT16: /* 0xd0 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (208 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_RSUB_INT: /* 0xd1 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (209 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_INT_LIT16: /* 0xd2 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (210 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_INT_LIT16: /* 0xd3 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (211 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_INT_LIT16: /* 0xd4 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (212 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AND_INT_LIT16: /* 0xd5 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (213 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_OR_INT_LIT16: /* 0xd6 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (214 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_XOR_INT_LIT16: /* 0xd7 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (215 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_ADD_INT_LIT8: /* 0xd8 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (216 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_RSUB_INT_LIT8: /* 0xd9 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (217 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_MUL_INT_LIT8: /* 0xda */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (218 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_DIV_INT_LIT8: /* 0xdb */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (219 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_REM_INT_LIT8: /* 0xdc */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (220 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_AND_INT_LIT8: /* 0xdd */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (221 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_OR_INT_LIT8: /* 0xde */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (222 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_XOR_INT_LIT8: /* 0xdf */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (223 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHL_INT_LIT8: /* 0xe0 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (224 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SHR_INT_LIT8: /* 0xe1 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (225 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_USHR_INT_LIT8: /* 0xe2 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (226 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_VOLATILE: /* 0xe3 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (227 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_VOLATILE: /* 0xe4 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (228 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_VOLATILE: /* 0xe5 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (229 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_VOLATILE: /* 0xe6 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (230 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_OBJECT_VOLATILE: /* 0xe7 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (231 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_WIDE_VOLATILE: /* 0xe8 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (232 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_WIDE_VOLATILE: /* 0xe9 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (233 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_WIDE_VOLATILE: /* 0xea */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (234 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_WIDE_VOLATILE: /* 0xeb */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (235 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_BREAKPOINT: /* 0xec */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (236 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_THROW_VERIFICATION_ERROR: /* 0xed */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (237 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_EXECUTE_INLINE: /* 0xee */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (238 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_EXECUTE_INLINE_RANGE: /* 0xef */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (239 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_OBJECT_INIT_RANGE: /* 0xf0 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (240 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_RETURN_VOID_BARRIER: /* 0xf1 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (241 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_QUICK: /* 0xf2 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (242 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_WIDE_QUICK: /* 0xf3 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (243 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IGET_OBJECT_QUICK: /* 0xf4 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (244 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_QUICK: /* 0xf5 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (245 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_WIDE_QUICK: /* 0xf6 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (246 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_OBJECT_QUICK: /* 0xf7 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (247 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_VIRTUAL_QUICK: /* 0xf8 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (248 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_VIRTUAL_QUICK_RANGE: /* 0xf9 */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (249 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_SUPER_QUICK: /* 0xfa */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (250 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_INVOKE_SUPER_QUICK_RANGE: /* 0xfb */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (251 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_IPUT_OBJECT_VOLATILE: /* 0xfc */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (252 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SGET_OBJECT_VOLATILE: /* 0xfd */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (253 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_SPUT_OBJECT_VOLATILE: /* 0xfe */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (254 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

/* ------------------------------ */
    .balign 64
.L_ALT_OP_UNUSED_FF: /* 0xff */
/* File: armv5te_taint/alt_stub.S */
/*
 * Inter-instruction transfer stub.  Call out to dvmCheckBefore to handle
 * any interesting requests and then jump to the real instruction
 * handler.    Note that the call to dvmCheckBefore is done as a tail call.
 * rIBASE updates won't be seen until a refresh, and we can tell we have a
 * stale rIBASE if breakFlags==0.  Always refresh rIBASE here, and then
 * bail to the real handler if breakFlags==0.
 */
    ldrb   r3, [rSELF, #offThread_breakFlags]
    adrl   lr, dvmAsmInstructionStart + (255 * 64)
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    cmp    r3, #0
    bxeq   lr                   @ nothing to do - jump to real handler
    EXPORT_PC()
    mov    r0, rPC              @ arg0
    mov    r1, rFP              @ arg1
    mov    r2, rSELF            @ arg2
    b      dvmCheckBefore       @ (dPC,dFP,self) tail call

    .balign 64
    .size   dvmAsmAltInstructionStart, .-dvmAsmAltInstructionStart
    .global dvmAsmAltInstructionEnd
dvmAsmAltInstructionEnd:
/* File: armv5te_taint/footer.S */
/*
 * ===========================================================================
 *  Common subroutines and data
 * ===========================================================================
 */

    .text
    .align  2

#if defined(WITH_JIT)

#if defined(WITH_SELF_VERIFICATION)
/*
 * "longjmp" to a translation after single-stepping.  Before returning
 * to translation, must save state for self-verification.
 */
    .global dvmJitResumeTranslation              @ (Thread* self, u4* dFP)
dvmJitResumeTranslation:
    mov    rSELF, r0                             @ restore self
    mov    rPC, r1                               @ restore Dalvik pc
    mov    rFP, r2                               @ restore Dalvik fp
    ldr    r10, [rSELF,#offThread_jitResumeNPC]  @ resume address
    mov    r2, #0
    str    r2, [rSELF,#offThread_jitResumeNPC]   @ reset resume address
    ldr    sp, [rSELF,#offThread_jitResumeNSP]   @ cut back native stack
    b      jitSVShadowRunStart                   @ resume as if cache hit
                                                 @ expects resume addr in r10

    .global dvmJitToInterpPunt
dvmJitToInterpPunt:
    mov    r2,#kSVSPunt                 @ r2<- interpreter entry point
    mov    r3, #0
    str    r3, [rSELF, #offThread_inJitCodeCache] @ Back to the interp land
    b      jitSVShadowRunEnd            @ doesn't return

    .global dvmJitToInterpSingleStep
dvmJitToInterpSingleStep:
    mov    rPC, r0              @ set up dalvik pc
    EXPORT_PC()
    str    lr, [rSELF,#offThread_jitResumeNPC]
    str    sp, [rSELF,#offThread_jitResumeNSP]
    str    r1, [rSELF,#offThread_jitResumeDPC]
    mov    r2,#kSVSSingleStep           @ r2<- interpreter entry point
    b      jitSVShadowRunEnd            @ doesn't return


    .global dvmJitToInterpNoChainNoProfile
dvmJitToInterpNoChainNoProfile:
    mov    r0,rPC                       @ pass our target PC
    mov    r2,#kSVSNoProfile            @ r2<- interpreter entry point
    mov    r3, #0                       @ 0 means !inJitCodeCache
    str    r3, [rSELF, #offThread_inJitCodeCache] @ back to the interp land
    b      jitSVShadowRunEnd            @ doesn't return

    .global dvmJitToInterpTraceSelectNoChain
dvmJitToInterpTraceSelectNoChain:
    mov    r0,rPC                       @ pass our target PC
    mov    r2,#kSVSTraceSelect          @ r2<- interpreter entry point
    mov    r3, #0                       @ 0 means !inJitCodeCache
    str    r3, [rSELF, #offThread_inJitCodeCache] @ Back to the interp land
    b      jitSVShadowRunEnd            @ doesn't return

    .global dvmJitToInterpTraceSelect
dvmJitToInterpTraceSelect:
    ldr    r0,[lr, #-1]                 @ pass our target PC
    mov    r2,#kSVSTraceSelect          @ r2<- interpreter entry point
    mov    r3, #0                       @ 0 means !inJitCodeCache
    str    r3, [rSELF, #offThread_inJitCodeCache] @ Back to the interp land
    b      jitSVShadowRunEnd            @ doesn't return

    .global dvmJitToInterpBackwardBranch
dvmJitToInterpBackwardBranch:
    ldr    r0,[lr, #-1]                 @ pass our target PC
    mov    r2,#kSVSBackwardBranch       @ r2<- interpreter entry point
    mov    r3, #0                       @ 0 means !inJitCodeCache
    str    r3, [rSELF, #offThread_inJitCodeCache] @ Back to the interp land
    b      jitSVShadowRunEnd            @ doesn't return

    .global dvmJitToInterpNormal
dvmJitToInterpNormal:
    ldr    r0,[lr, #-1]                 @ pass our target PC
    mov    r2,#kSVSNormal               @ r2<- interpreter entry point
    mov    r3, #0                       @ 0 means !inJitCodeCache
    str    r3, [rSELF, #offThread_inJitCodeCache] @ Back to the interp land
    b      jitSVShadowRunEnd            @ doesn't return

    .global dvmJitToInterpNoChain
dvmJitToInterpNoChain:
    mov    r0,rPC                       @ pass our target PC
    mov    r2,#kSVSNoChain              @ r2<- interpreter entry point
    mov    r3, #0                       @ 0 means !inJitCodeCache
    str    r3, [rSELF, #offThread_inJitCodeCache] @ Back to the interp land
    b      jitSVShadowRunEnd            @ doesn't return
#else

/*
 * "longjmp" to a translation after single-stepping.
 */
    .global dvmJitResumeTranslation              @ (Thread* self, u4* dFP)
dvmJitResumeTranslation:
    mov    rSELF, r0                             @ restore self
    mov    rPC, r1                               @ restore Dalvik pc
    mov    rFP, r2                               @ restore Dalvik fp
    ldr    r0, [rSELF,#offThread_jitResumeNPC]
    mov    r2, #0
    str    r2, [rSELF,#offThread_jitResumeNPC]   @ reset resume address
    ldr    sp, [rSELF,#offThread_jitResumeNSP]   @ cut back native stack
    bx     r0                                    @ resume translation

/*
 * Return from the translation cache to the interpreter when the compiler is
 * having issues translating/executing a Dalvik instruction. We have to skip
 * the code cache lookup otherwise it is possible to indefinitely bouce
 * between the interpreter and the code cache if the instruction that fails
 * to be compiled happens to be at a trace start.
 */
    .global dvmJitToInterpPunt
dvmJitToInterpPunt:
    mov    rPC, r0
#if defined(WITH_JIT_TUNING)
    mov    r0,lr
    bl     dvmBumpPunt;
#endif
    EXPORT_PC()
    mov    r0, #0
    str    r0, [rSELF, #offThread_inJitCodeCache] @ Back to the interp land
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    FETCH_INST()
    GET_INST_OPCODE(ip)
    GOTO_OPCODE(ip)

/*
 * Return to the interpreter to handle a single instruction.
 * We'll use the normal single-stepping mechanism via interpBreak,
 * but also save the native pc of the resume point in the translation
 * and the native sp so that we can later do the equivalent of a
 * longjmp() to resume.
 * On entry:
 *    dPC <= Dalvik PC of instrucion to interpret
 *    lr <= resume point in translation
 *    r1 <= Dalvik PC of next instruction
 */
    .global dvmJitToInterpSingleStep
dvmJitToInterpSingleStep:
    mov    rPC, r0              @ set up dalvik pc
    EXPORT_PC()
    str    lr, [rSELF,#offThread_jitResumeNPC]
    str    sp, [rSELF,#offThread_jitResumeNSP]
    str    r1, [rSELF,#offThread_jitResumeDPC]
    mov    r1, #1
    str    r1, [rSELF,#offThread_singleStepCount]  @ just step once
    mov    r0, rSELF
    mov    r1, #kSubModeCountedStep
    bl     dvmEnableSubMode     @ (self, newMode)
    ldr    rIBASE, [rSELF,#offThread_curHandlerTable]
    FETCH_INST()
    GET_INST_OPCODE(ip)
    GOTO_OPCODE(ip)

/*
 * Return from the translation cache and immediately request
 * a translation for the exit target.  Commonly used for callees.
 */
    .global dvmJitToInterpTraceSelectNoChain
dvmJitToInterpTraceSelectNoChain:
#if defined(WITH_JIT_TUNING)
    bl     dvmBumpNoChain
#endif
    mov    r0,rPC
    mov    r1,rSELF
    bl     dvmJitGetTraceAddrThread @ (pc, self)
    str    r0, [rSELF, #offThread_inJitCodeCache] @ set the inJitCodeCache flag
    mov    r1, rPC                  @ arg1 of translation may need this
    mov    lr, #0                   @  in case target is HANDLER_INTERPRET
    cmp    r0,#0                    @ !0 means translation exists
    bxne   r0                       @ continue native execution if so
    b      2f                       @ branch over to use the interpreter

/*
 * Return from the translation cache and immediately request
 * a translation for the exit target.  Commonly used following
 * invokes.
 */
    .global dvmJitToInterpTraceSelect
dvmJitToInterpTraceSelect:
    ldr    rPC,[lr, #-1]           @ get our target PC
    add    rINST,lr,#-5            @ save start of chain branch
    add    rINST, #-4              @  .. which is 9 bytes back
    mov    r0,rPC
    mov    r1,rSELF
    bl     dvmJitGetTraceAddrThread @ (pc, self)
    str    r0, [rSELF, #offThread_inJitCodeCache] @ set the inJitCodeCache flag
    cmp    r0,#0
    beq    2f
    mov    r1,rINST
    bl     dvmJitChain              @ r0<- dvmJitChain(codeAddr,chainAddr)
    mov    r1, rPC                  @ arg1 of translation may need this
    mov    lr, #0                   @ in case target is HANDLER_INTERPRET
    cmp    r0,#0                    @ successful chain?
    bxne   r0                       @ continue native execution
    b      toInterpreter            @ didn't chain - resume with interpreter

/* No translation, so request one if profiling isn't disabled*/
2:
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    ldr    r0, [rSELF, #offThread_pJitProfTable]
    FETCH_INST()
    cmp    r0, #0
    movne  r2,#kJitTSelectRequestHot   @ ask for trace selection
    bne    common_selectTrace
    GET_INST_OPCODE(ip)
    GOTO_OPCODE(ip)

/*
 * Return from the translation cache to the interpreter.
 * The return was done with a BLX from thumb mode, and
 * the following 32-bit word contains the target rPC value.
 * Note that lr (r14) will have its low-order bit set to denote
 * its thumb-mode origin.
 *
 * We'll need to stash our lr origin away, recover the new
 * target and then check to see if there is a translation available
 * for our new target.  If so, we do a translation chain and
 * go back to native execution.  Otherwise, it's back to the
 * interpreter (after treating this entry as a potential
 * trace start).
 */
    .global dvmJitToInterpNormal
dvmJitToInterpNormal:
    ldr    rPC,[lr, #-1]           @ get our target PC
    add    rINST,lr,#-5            @ save start of chain branch
    add    rINST,#-4               @ .. which is 9 bytes back
#if defined(WITH_JIT_TUNING)
    bl     dvmBumpNormal
#endif
    mov    r0,rPC
    mov    r1,rSELF
    bl     dvmJitGetTraceAddrThread @ (pc, self)
    str    r0, [rSELF, #offThread_inJitCodeCache] @ set the inJitCodeCache flag
    cmp    r0,#0
    beq    toInterpreter            @ go if not, otherwise do chain
    mov    r1,rINST
    bl     dvmJitChain              @ r0<- dvmJitChain(codeAddr,chainAddr)
    mov    r1, rPC                  @ arg1 of translation may need this
    mov    lr, #0                   @  in case target is HANDLER_INTERPRET
    cmp    r0,#0                    @ successful chain?
    bxne   r0                       @ continue native execution
    b      toInterpreter            @ didn't chain - resume with interpreter

/*
 * Return from the translation cache to the interpreter to do method invocation.
 * Check if translation exists for the callee, but don't chain to it.
 */
    .global dvmJitToInterpNoChainNoProfile
dvmJitToInterpNoChainNoProfile:
#if defined(WITH_JIT_TUNING)
    bl     dvmBumpNoChain
#endif
    mov    r0,rPC
    mov    r1,rSELF
    bl     dvmJitGetTraceAddrThread @ (pc, self)
    str    r0, [rSELF, #offThread_inJitCodeCache] @ set the inJitCodeCache flag
    mov    r1, rPC                  @ arg1 of translation may need this
    mov    lr, #0                   @  in case target is HANDLER_INTERPRET
    cmp    r0,#0
    bxne   r0                       @ continue native execution if so
    EXPORT_PC()
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    FETCH_INST()
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction

/*
 * Return from the translation cache to the interpreter to do method invocation.
 * Check if translation exists for the callee, but don't chain to it.
 */
    .global dvmJitToInterpNoChain
dvmJitToInterpNoChain:
#if defined(WITH_JIT_TUNING)
    bl     dvmBumpNoChain
#endif
    mov    r0,rPC
    mov    r1,rSELF
    bl     dvmJitGetTraceAddrThread @ (pc, self)
    str    r0, [rSELF, #offThread_inJitCodeCache] @ set the inJitCodeCache flag
    mov    r1, rPC                  @ arg1 of translation may need this
    mov    lr, #0                   @  in case target is HANDLER_INTERPRET
    cmp    r0,#0
    bxne   r0                       @ continue native execution if so
#endif

/*
 * No translation, restore interpreter regs and start interpreting.
 * rSELF & rFP were preserved in the translated code, and rPC has
 * already been restored by the time we get here.  We'll need to set
 * up rIBASE & rINST, and load the address of the JitTable into r0.
 */
toInterpreter:
    EXPORT_PC()
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    FETCH_INST()
    ldr    r0, [rSELF, #offThread_pJitProfTable]
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    @ NOTE: intended fallthrough

/*
 * Similar to common_updateProfile, but tests for null pJitProfTable
 * r0 holds pJifProfTAble, rINST is loaded, rPC is current and
 * rIBASE has been recently refreshed.
 */
common_testUpdateProfile:
    cmp     r0, #0               @ JIT switched off?
    beq     4f                   @ return to interp if so

/*
 * Common code to update potential trace start counter, and initiate
 * a trace-build if appropriate.
 * On entry here:
 *    r0    <= pJitProfTable (verified non-NULL)
 *    rPC   <= Dalvik PC
 *    rINST <= next instruction
 */
common_updateProfile:
    eor     r3,rPC,rPC,lsr #12 @ cheap, but fast hash function
    lsl     r3,r3,#(32 - JIT_PROF_SIZE_LOG_2)          @ shift out excess bits
    ldrb    r1,[r0,r3,lsr #(32 - JIT_PROF_SIZE_LOG_2)] @ get counter
    GET_INST_OPCODE(ip)
    subs    r1,r1,#1           @ decrement counter
    strb    r1,[r0,r3,lsr #(32 - JIT_PROF_SIZE_LOG_2)] @ and store it
    GOTO_OPCODE_IFNE(ip)       @ if not threshold, fallthrough otherwise */

    /* Looks good, reset the counter */
    ldr     r1, [rSELF, #offThread_jitThreshold]
    strb    r1,[r0,r3,lsr #(32 - JIT_PROF_SIZE_LOG_2)] @ reset counter
    EXPORT_PC()
    mov     r0,rPC
    mov     r1,rSELF
    bl      dvmJitGetTraceAddrThread    @ (pc, self)
    str     r0, [rSELF, #offThread_inJitCodeCache] @ set the inJitCodeCache flag
    mov     r1, rPC                     @ arg1 of translation may need this
    mov     lr, #0                      @  in case target is HANDLER_INTERPRET
    cmp     r0,#0
#if !defined(WITH_SELF_VERIFICATION)
    bxne    r0                          @ jump to the translation
    mov     r2,#kJitTSelectRequest      @ ask for trace selection
    @ fall-through to common_selectTrace
#else
    moveq   r2,#kJitTSelectRequest      @ ask for trace selection
    beq     common_selectTrace
    /*
     * At this point, we have a target translation.  However, if
     * that translation is actually the interpret-only pseudo-translation
     * we want to treat it the same as no translation.
     */
    mov     r10, r0                     @ save target
    bl      dvmCompilerGetInterpretTemplate
    cmp     r0, r10                     @ special case?
    bne     jitSVShadowRunStart         @ set up self verification shadow space
    @ Need to clear the inJitCodeCache flag
    mov    r3, #0                       @ 0 means not in the JIT code cache
    str    r3, [rSELF, #offThread_inJitCodeCache] @ back to the interp land
    GET_INST_OPCODE(ip)
    GOTO_OPCODE(ip)
    /* no return */
#endif

/*
 * On entry:
 *  r2 is jit state.
 */
common_selectTrace:
    ldrh    r0,[rSELF,#offThread_subMode]
    ands    r0, #(kSubModeJitTraceBuild | kSubModeJitSV)
    bne     3f                         @ already doing JIT work, continue
    str     r2,[rSELF,#offThread_jitState]
    mov     r0, rSELF
/*
 * Call out to validate trace-building request.  If successful,
 * rIBASE will be swapped to to send us into single-stepping trace
 * building mode, so we need to refresh before we continue.
 */
    EXPORT_PC()
    SAVE_PC_FP_TO_SELF()                 @ copy of pc/fp to Thread
    bl      dvmJitCheckTraceRequest
3:
    FETCH_INST()
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
4:
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)
    /* no return */
#endif

#if defined(WITH_SELF_VERIFICATION)
/*
 * Save PC and registers to shadow memory for self verification mode
 * before jumping to native translation.
 * On entry:
 *    rPC, rFP, rSELF: the values that they should contain
 *    r10: the address of the target translation.
 */
jitSVShadowRunStart:
    mov     r0,rPC                      @ r0<- program counter
    mov     r1,rFP                      @ r1<- frame pointer
    mov     r2,rSELF                    @ r2<- self (Thread) pointer
    mov     r3,r10                      @ r3<- target translation
    bl      dvmSelfVerificationSaveState @ save registers to shadow space
    ldr     rFP,[r0,#offShadowSpace_shadowFP] @ rFP<- fp in shadow space
    bx      r10                         @ jump to the translation

/*
 * Restore PC, registers, and interpreter state to original values
 * before jumping back to the interpreter.
 * On entry:
 *   r0:  dPC
 *   r2:  self verification state
 */
jitSVShadowRunEnd:
    mov    r1,rFP                        @ pass ending fp
    mov    r3,rSELF                      @ pass self ptr for convenience
    bl     dvmSelfVerificationRestoreState @ restore pc and fp values
    LOAD_PC_FP_FROM_SELF()               @ restore pc, fp
    ldr    r1,[r0,#offShadowSpace_svState] @ get self verification state
    cmp    r1,#0                         @ check for punt condition
    beq    1f
    @ Set up SV single-stepping
    mov    r0, rSELF
    mov    r1, #kSubModeJitSV
    bl     dvmEnableSubMode              @ (self, subMode)
    mov    r2,#kJitSelfVerification      @ ask for self verification
    str    r2,[rSELF,#offThread_jitState]
    @ intentional fallthrough
1:                                       @ exit to interpreter without check
    EXPORT_PC()
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]
    FETCH_INST()
    GET_INST_OPCODE(ip)
    GOTO_OPCODE(ip)
#endif

/*
 * The equivalent of "goto bail", this calls through the "bail handler".
 * It will end this interpreter activation, and return to the caller
 * of dvmMterpStdRun.
 *
 * State registers will be saved to the "thread" area before bailing
 * debugging purposes
 */
common_gotoBail:
    SAVE_PC_FP_TO_SELF()                @ export state to "thread"
    mov     r0, rSELF                   @ r0<- self ptr
    b       dvmMterpStdBail             @ call(self, changeInterp)

/*
 * The JIT's invoke method needs to remember the callsite class and
 * target pair.  Save them here so that they are available to
 * dvmCheckJit following the interpretation of this invoke.
 */
#if defined(WITH_JIT)
save_callsiteinfo:
    cmp     r9, #0
    ldrne   r9, [r9, #offObject_clazz]
    str     r0, [rSELF, #offThread_methodToCall]
    str     r9, [rSELF, #offThread_callsiteClass]
    bx      lr
#endif

/*
 * Common code for method invocation with range.
 *
 * On entry:
 *  r0 is "Method* methodToCall", r9 is "this"
 */
common_invokeMethodRange:
.LinvokeNewRange:
#if defined(WITH_JIT)
    ldrh    r1, [rSELF, #offThread_subMode]
    ands    r1, #kSubModeJitTraceBuild
    blne    save_callsiteinfo
#endif
    @ prepare to copy args to "outs" area of current frame
// begin WITH_TAINT_TRACKING
//    movs    r2, rINST, lsr #8           @ r2<- AA (arg count) -- test for zero
    mov     r2, rINST, lsr #8           @ r2<- AA (arg count)
    SAVEAREA_FROM_FP(r10, rFP)          @ r10<- stack save area
//    beq     .LinvokeArgsDone            @ if no args, skip the rest
    str     r2, [r10, #offStackSaveArea_argCount]	@ save arg count
// end WITH_TAINT_TRACKING
    FETCH(r1, 2)                        @ r1<- CCCC

// begin WITH_TAINT_TRACKING
    // is this a native method?
    stmfd   sp!, {r0}                   @ push methodToCall to stack
    ldr     r0, [r0, #offMethod_accessFlags] @ r0<- methodToCall->accessFlags
    tst     r0, #ACC_NATIVE
    ldmfd   sp!, {r0}                   @ restore methodToCall
    bne     .LinvokeRangeNative

.LinvokeRangeArgs:
    @ r0=methodToCall, r1=CCCC, r2=count, r10=outs
    @ (very few methods have > 10 args; could unroll for common cases)
    stmfd   sp!, {r0}                   @ push methodToCall to stack
    mov	    r9, #0
    str     r9, [r10, #-4]              @ clear native hack
    cmp	    r2, #0
    beq     .LinvokeRangeDone           @ if no args, skip the rest
    add     r3, rFP, r1, lsl #3         @ r3<- &fp[CCCC]
    sub     r10, r10, r2, lsl #3        @ r10<- "outs" area, for call args
    sub	    r10, r10, #4
    //mov     r9, #0                      @ r9<- slot = 0
1:  ldrd    r0, [r3, r9]
    subs    r2, r2, #1                  @ count--
    strd    r0, [r10, r9]               @ *outs++ = val
    add	    r9, r9, #8
    bne     1b                          @ ...while count != 0

.LinvokeRangeDone:
    ldmfd   sp!, {r0}                   @ restore methodToCall
    // PJG: moved
    //ldrh    r9, [r0, #offMethod_registersSize]  @ r9<- methodToCall->regsSize
    //ldrh    r3, [r0, #offMethod_outsSize]   @ r3<- methodToCall->outsSize
    b       .LinvokeArgsDone

.LinvokeRangeNative:
    @ r0=methodToCall, r1=CCCC, r2=count, r10=outs
    @ (very few methods have > 10 args; could unroll for common cases)
    stmfd   sp!, {r0}                   @ push methodToCall to stack
    sub	    r10, r10, #4
    sub     r10, r10, r2, lsl #3        @ r10<- "outs" area, for call args
    mov	    r9, #0                      @ r9<- index
    str     r9, [r10, r2, lsl #2]       @ clear native hack
    cmp	    r2, #0
    beq     .LinvokeRangeNativeDone     @ if no args, skip the rest
    add     r3, rFP, r1, lsl #3         @ r3<- &fp[CCCC]
    mov	    r0, r2                      @ r0<- count
    mov	    r2, r2, lsl #2
    add	    r2, r2, #4                  @ r2<- index (taint)
1:  stmfd   sp!, {r0}                   @ push count
    stmfd   sp!, {r10}                  @ ANDOW
    mov	    r10, r9, lsl #3
    ldrd    r0, [r3, r10]
    ldmfd   sp!, {r10}
    str	    r0, [r10, r9, lsl #2]
    str	    r1, [r10, r2]
    add	    r9, r9, #1
    add	    r2, r2, #4
    ldmfd   sp!, {r0}                   @ pop count
    subs    r0, r0, #1                  @ count--
    bne     1b                          @ ...while count != 0
.LinvokeRangeNativeDone:
    ldmfd   sp!, {r0}                   @ restore methodToCall
    // PJG: moved
    //ldrh    r9, [r0, #offMethod_registersSize]  @ r9<- methodToCall->regsSize
    //ldrh    r3, [r0, #offMethod_outsSize]   @ r3<- methodToCall->outsSize
    b       .LinvokeArgsDone
// end WITH_TAINT_TRACKING



/*
 * Common code for method invocation without range.
 *
 * On entry:
 *  r0 is "Method* methodToCall", r9 is "this"
 */
common_invokeMethodNoRange:
.LinvokeNewNoRange:
#if defined(WITH_JIT)
    ldrh    r1, [rSELF, #offThread_subMode]
    ands    r1, #kSubModeJitTraceBuild
    blne    save_callsiteinfo
#endif
    @ prepare to copy args to "outs" area of current frame
// begin WITH_TAINT_TRACKING
//    movs    r2, rINST, lsr #12          @ r2<- B (arg count) -- test for zero
    movs    r2, rINST, lsr #12          @ r2<- B (arg count)
    SAVEAREA_FROM_FP(r10, rFP)          @ r10<- stack save area
    str     r2, [r10, #offStackSaveArea_argCount]    @ save arg count
    FETCH(r1, 2)                        @ r1<- GFED (load here to hide latency)
    // is this a native method?
    stmfd   sp!, {r0}                   @ push methodToCall to stack
    ldr     r0, [r0, #offMethod_accessFlags] @ r0<- methodToCall->accessFlags
    tst     r0, #ACC_NATIVE
    bne     .LinvokeNonRangeNative
// end WITH_TAINT_TRACKING

    @ r0=methodToCall, r1=GFED, r2=count, r10=outs
.LinvokeNonRange:
// begin WITH_TAINT_TRACKING
    stmfd   sp!, {r3}                   @ push count, outSize to stack
    stmfd   sp!, {r9}                   @ ANDOW
    // clear native hack
    mov	    r3, #0
    str     r3, [r10, #-4]!
// end WITH_TAINT_TRACKING
    rsb     r2, r2, #5                  @ r2<- 5-r2
    add     pc, pc, r2, lsl #4          @ computed goto, 4 instrs each
    bl      common_abort                @ (skipped due to ARM prefetch)
// begin WITH_TAINT_TRACKING
5:  and     ip, rINST, #0x0f00          @ isolate A
    mov	    r9, ip, lsr #5
    ldrd    r2, [rFP, r9]               @ r2/r3<- vA (shift right 8, left 2) / taint
    strd    r2, [r10, #-8]!             @ *--outs = vA
4:  and     ip, r1, #0xf000             @ isolate G
    mov	    r9, ip, lsr #9
    ldrd    r2, [rFP, r9]               @ r2<- vG (shift right 12, left 2)
    strd    r2, [r10, #-8]!             @ *--outs = vG
3:  and     ip, r1, #0x0f00             @ isolate F
    mov	    r9, ip, lsr #5
    ldrd    r2, [rFP, r9]               @ r2<- vF
    strd    r2, [r10, #-8]!             @ *--outs = vF
2:  and     ip, r1, #0x00f0             @ isolate E
    mov	    r9, ip, lsr #1
    ldrd    r2, [rFP, r9]               @ r2<- vE
    strd    r2, [r10, #-8]!             @ *--outs = vE
1:  and     ip, r1, #0x000f             @ isolate D
    mov	    r9, ip, lsl #3
    ldrd    r2, [rFP, r9]               @ r2<- vD
    strd    r2, [r10, #-8]!             @ *--outs = vD
// end WITH_TAINT_TRACKING
0:  @ fall through to .LinvokeArgsDone
// begin WITH_TAINT_TRACKING
    ldmfd   sp!, {r9}
    ldmfd   sp!, {r3}                   @ restore outSize
    ldmfd   sp!, {r0}                   @ restore methodToCall
    b       .LinvokeArgsDone            @ jump over .LinvokeNonRangeNative
// end WITH_TAINT_TRACKING

    @ r0=methodToCall, r1=GFED, r2=count, r10=outs
.LinvokeNonRangeNative:
// begin WITH_TAINT_TRACKING
    sub	    r0, r10, r2, lsl #2         @ r0<- outs (no taint)
    sub	    r0, r0, #4                  @ native hack
    stmfd   sp!, {r3}                   @ push outSize to stack
    stmfd   sp!, {r9}                   @ ANDOW
// end WITH_TAINT_TRACKING
    rsb     r2, r2, #5                  @ r2<- 5-r2
// begin WITH_TAINT_TRACKING
    mov	    r3, #5
    mul	    r2, r2, r3
    add     pc, pc, r2, lsl #2         	@ computed goto, 5 instrs each, 4-byte instrs
// end WITH_TAINT_TRACKING
    bl      common_abort                @ (skipped due to ARM prefetch)
// begin WITH_TAINT_TRACKING
5:  and     ip, rINST, #0x0f00          @ isolate A
    mov	    r9, ip, lsr #5
    ldrd    r2, [rFP, r9]               @ r2/r3<- vA (shift right 8, left 2) / taint
    str     r2, [r0, #-4]!
    str	    r3, [r10, #-4]!
4:  and     ip, r1, #0xf000             @ isolate G
    mov	    r9, ip, lsr #9
    ldrd    r2, [rFP, r9]               @ r2<- vG (shift right 12, left 2)
    str     r2, [r0, #-4]!
    str	    r3, [r10, #-4]!
3:  and     ip, r1, #0x0f00             @ isolate F
    mov	    r9, ip, lsr #5
    ldrd    r2, [rFP, r9]               @ r2<- vF
    str     r2, [r0, #-4]!
    str	    r3, [r10, #-4]!
2:  and     ip, r1, #0x00f0             @ isolate E
    mov	    r9, ip, lsr #1
    ldrd    r2, [rFP, r9]               @ r2<- vE
    str     r2, [r0, #-4]!
    str	    r3, [r10, #-4]!
1:  and     ip, r1, #0x000f             @ isolate D
    mov	    r9, ip, lsl #3
    ldrd    r2, [rFP, r9]               @ r2/r3<- vD+taint
    str     r2, [r0, #-4]!
    str     r3, [r10, #-4]!
// end WITH_TAINT_TRACKING
0:  @ fall through to .LinvokeArgsDone
// begin WITH_TAINT_TRACKING
    // clear native hack
    mov		r3, #0
    str     r3, [r10, #-4]!
    ldmfd   sp!, {r9}                   @ ANDOW
    ldmfd   sp!, {r3}                   @ restore outSize
    ldmfd   sp!, {r0}                   @ restore methodToCall
// end WITH_TAINT_TRACKING

.LinvokeArgsDone: @ r0=methodToCall
    ldrh    r9, [r0, #offMethod_registersSize]  @ r9<- methodToCall->regsSize
    ldrh    r3, [r0, #offMethod_outsSize]  @ r3<- methodToCall->outsSize
    ldr     r2, [r0, #offMethod_insns]  @ r2<- method->insns
    ldr     rINST, [r0, #offMethod_clazz]  @ rINST<- method->clazz
    @ find space for the new stack frame, check for overflow
    SAVEAREA_FROM_FP(r1, rFP)           @ r1<- stack save area
// begin WITH_TAINT_TRACKING
    sub     r1, r1, r9, lsl #3
    sub	    r1, r1, #4                  @ r1<- newFp (old savearea - 2*regsSize - 4)
// end WITH_TAINT_TRACKING
//    sub     r1, r1, r9, lsl #2          @ r1<- newFp (old savearea - regsSize)
    SAVEAREA_FROM_FP(r10, r1)           @ r10<- newSaveArea
@    bl      common_dumpRegs
    ldr     r9, [rSELF, #offThread_interpStackEnd]    @ r9<- interpStackEnd
// begin WITH_TAINT_TRACKING
    sub     r3, r10, r3, lsl #2
    sub	    r3, r3, #4                  @ r3<- bottom (newsave - outsSize - 4)
// end WITH_TAINT_TRACKING
//    sub     r3, r10, r3, lsl #2         @ r3<- bottom (newsave - outsSize)
    cmp     r3, r9                      @ bottom < interpStackEnd?
    ldrh    lr, [rSELF, #offThread_subMode]
    ldr     r3, [r0, #offMethod_accessFlags] @ r3<- methodToCall->accessFlags
    blo     .LstackOverflow             @ yes, this frame will overflow stack

    @ set up newSaveArea
#ifdef EASY_GDB
    SAVEAREA_FROM_FP(ip, rFP)           @ ip<- stack save area
    str     ip, [r10, #offStackSaveArea_prevSave]
#endif
    str     rFP, [r10, #offStackSaveArea_prevFrame]
    str     rPC, [r10, #offStackSaveArea_savedPc]
#if defined(WITH_JIT)
    mov     r9, #0
    str     r9, [r10, #offStackSaveArea_returnAddr]
#endif
    str     r0, [r10, #offStackSaveArea_method]

    @ Profiling?
    cmp     lr, #0                      @ any special modes happening?
    bne     2f                          @ go if so
1:
    tst     r3, #ACC_NATIVE
    bne     .LinvokeNative

    /*
    stmfd   sp!, {r0-r3}
    bl      common_printNewline
    mov     r0, rFP
    mov     r1, #0
    bl      dvmDumpFp
    ldmfd   sp!, {r0-r3}
    stmfd   sp!, {r0-r3}
    mov     r0, r1
    mov     r1, r10
    bl      dvmDumpFp
    bl      common_printNewline
    ldmfd   sp!, {r0-r3}
    */

    ldrh    r9, [r2]                        @ r9 <- load INST from new PC
    ldr     r3, [rINST, #offClassObject_pDvmDex] @ r3<- method->clazz->pDvmDex
    mov     rPC, r2                         @ publish new rPC

    @ Update state values for the new method
    @ r0=methodToCall, r1=newFp, r3=newMethodClass, r9=newINST
    str     r0, [rSELF, #offThread_method]    @ self->method = methodToCall
    str     r3, [rSELF, #offThread_methodClassDex] @ self->methodClassDex = ...
    mov     r2, #1
    str     r2, [rSELF, #offThread_debugIsMethodEntry]
#if defined(WITH_JIT)
    ldr     r0, [rSELF, #offThread_pJitProfTable]
    mov     rFP, r1                         @ fp = newFp
    GET_PREFETCHED_OPCODE(ip, r9)           @ extract prefetched opcode from r9
    mov     rINST, r9                       @ publish new rINST
    str     r1, [rSELF, #offThread_curFrame]   @ curFrame = newFp
    cmp     r0,#0
    bne     common_updateProfile
    GOTO_OPCODE(ip)                         @ jump to next instruction
#else
    mov     rFP, r1                         @ fp = newFp
    GET_PREFETCHED_OPCODE(ip, r9)           @ extract prefetched opcode from r9
    mov     rINST, r9                       @ publish new rINST
    str     r1, [rSELF, #offThread_curFrame]   @ curFrame = newFp
    GOTO_OPCODE(ip)                         @ jump to next instruction
#endif

2:
    @ Profiling - record method entry.  r0: methodToCall
    stmfd   sp!, {r0-r3}                @ preserve r0-r3
    str     rPC, [rSELF, #offThread_pc] @ update interpSave.pc
    mov     r1, r0
    mov     r0, rSELF
    bl      dvmReportInvoke             @ (self, method)
    ldmfd   sp!, {r0-r3}                @ restore r0-r3
    b       1b

.LinvokeNative:
    @ Prep for the native call
    @ r0=methodToCall, r1=newFp, r10=newSaveArea
    ldrh    lr, [rSELF, #offThread_subMode]
    ldr     r9, [rSELF, #offThread_jniLocal_topCookie]@r9<-thread->localRef->...
    str     r1, [rSELF, #offThread_curFrame]   @ curFrame = newFp
    str     r9, [r10, #offStackSaveArea_localRefCookie] @newFp->localRefCookie=top
    mov     r2, r0                      @ r2<- methodToCall
    mov     r0, r1                      @ r0<- newFp (points to args)
    add     r1, rSELF, #offThread_retval  @ r1<- &retval
    mov     r3, rSELF                   @ arg3<- self

#ifdef ASSIST_DEBUGGER
    /* insert fake function header to help gdb find the stack frame */
    b       .Lskip
    .type   dalvik_mterp, %function
dalvik_mterp:
    .fnstart
    MTERP_ENTRY1
    MTERP_ENTRY2
.Lskip:
#endif

    cmp     lr, #0                      @ any special SubModes active?
    bne     11f                         @ go handle them if so
    ldr     ip, [r2, #offMethod_nativeFunc] @ pc<- methodToCall->nativeFunc
    blx     ip
7:

    @ native return; r10=newSaveArea

// begin WITH_TAINT_TRACKING
    // set return taint
    SAVEAREA_FROM_FP(r0, rFP)           @ r0<- stack save area
    ldr     r1, [r0, #offStackSaveArea_argCount]    @ r1<- arg count
    sub     r0, r0, r1, lsl #2
    ldr     r2, [r0, #-4]               @ r2<- return taint
    str	    r2, [rSELF, #offThread_rtaint]
// end WITH_TAINT_TRACKING

    @ equivalent to dvmPopJniLocals
    ldr     r0, [r10, #offStackSaveArea_localRefCookie] @ r0<- saved top
    ldr     r1, [rSELF, #offThread_exception] @ check for exception
    str     rFP, [rSELF, #offThread_curFrame]  @ curFrame = fp
    cmp     r1, #0                      @ null?
    str     r0, [rSELF, #offThread_jniLocal_topCookie] @ new top <- old top
    bne     common_exceptionThrown      @ no, handle exception

    FETCH_ADVANCE_INST(3)               @ advance rPC, load rINST
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction

11:
    @ r0=newFp, r1=&retval, r2=methodToCall, r3=self, lr=subModes
    stmfd   sp!, {r0-r3}                @ save all but subModes
    mov     r0, r2                      @ r0<- methodToCall
    mov     r1, rSELF
    mov     r2, rFP
    bl      dvmReportPreNativeInvoke    @ (methodToCall, self, fp)
    ldmfd   sp, {r0-r3}                 @ refresh.  NOTE: no sp autoincrement

    @ Call the native method
    ldr     ip, [r2, #offMethod_nativeFunc] @ pc<- methodToCall->nativeFunc
    blx     ip

    @ Restore the pre-call arguments
    ldmfd   sp!, {r0-r3}                @ r2<- methodToCall (others unneeded)

    @ Finish up any post-invoke subMode requirements
    mov     r0, r2                      @ r0<- methodToCall
    mov     r1, rSELF
    mov     r2, rFP
    bl      dvmReportPostNativeInvoke   @ (methodToCall, self, fp)
    b       7b                          @ resume

.LstackOverflow:    @ r0=methodToCall
    mov     r1, r0                      @ r1<- methodToCall
    mov     r0, rSELF                   @ r0<- self
    bl      dvmHandleStackOverflow
    b       common_exceptionThrown
#ifdef ASSIST_DEBUGGER
    .fnend
    .size   dalvik_mterp, .-dalvik_mterp
#endif


    /*
     * Common code for method invocation, calling through "glue code".
     *
     * TODO: now that we have range and non-range invoke handlers, this
     *       needs to be split into two.  Maybe just create entry points
     *       that set r9 and jump here?
     *
     * On entry:
     *  r0 is "Method* methodToCall", the method we're trying to call
     *  r9 is "bool methodCallRange", indicating if this is a /range variant
     */
     .if    0
.LinvokeOld:
    sub     sp, sp, #8                  @ space for args + pad
    FETCH(ip, 2)                        @ ip<- FEDC or CCCC
    mov     r2, r0                      @ A2<- methodToCall
    mov     r0, rSELF                   @ A0<- self
    SAVE_PC_FP_TO_SELF()                @ export state to "self"
    mov     r1, r9                      @ A1<- methodCallRange
    mov     r3, rINST, lsr #8           @ A3<- AA
    str     ip, [sp, #0]                @ A4<- ip
    bl      dvmMterp_invokeMethod       @ call the C invokeMethod
    add     sp, sp, #8                  @ remove arg area
    b       common_resumeAfterGlueCall  @ continue to next instruction
    .endif



/*
 * Common code for handling a return instruction.
 *
 * This does not return.
 */
common_returnFromMethod:
.LreturnNew:
    ldrh    lr, [rSELF, #offThread_subMode]
    SAVEAREA_FROM_FP(r0, rFP)
    ldr     r9, [r0, #offStackSaveArea_savedPc] @ r9 = saveArea->savedPc
    cmp     lr, #0                      @ any special subMode handling needed?
    bne     19f
14:
    ldr     rFP, [r0, #offStackSaveArea_prevFrame] @ fp = saveArea->prevFrame
    ldr     r2, [rFP, #(offStackSaveArea_method - sizeofStackSaveArea)]
                                        @ r2<- method we're returning to
    cmp     r2, #0                      @ is this a break frame?
#if defined(WORKAROUND_CORTEX_A9_745320)
    /* Don't use conditional loads if the HW defect exists */
    beq     15f
    ldr     r10, [r2, #offMethod_clazz] @ r10<- method->clazz
15:
#else
    ldrne   r10, [r2, #offMethod_clazz] @ r10<- method->clazz
#endif
    beq     common_gotoBail             @ break frame, bail out completely

    ldr     rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    PREFETCH_ADVANCE_INST(rINST, r9, 3) @ advance r9, update new rINST
    str     r2, [rSELF, #offThread_method]@ self->method = newSave->method
    ldr     r1, [r10, #offClassObject_pDvmDex]   @ r1<- method->clazz->pDvmDex
    str     rFP, [rSELF, #offThread_curFrame]  @ curFrame = fp
#if defined(WITH_JIT)
    ldr     r10, [r0, #offStackSaveArea_returnAddr] @ r10 = saveArea->returnAddr
    mov     rPC, r9                     @ publish new rPC
    str     r1, [rSELF, #offThread_methodClassDex]
    str     r10, [rSELF, #offThread_inJitCodeCache]  @ may return to JIT'ed land
    cmp     r10, #0                      @ caller is compiled code
    blxne   r10
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction
#else
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    mov     rPC, r9                     @ publish new rPC
    str     r1, [rSELF, #offThread_methodClassDex]
    GOTO_OPCODE(ip)                     @ jump to next instruction
#endif

19:
    @ Handle special actions
    @ On entry, r0: StackSaveArea
    ldr     r1, [r0, #offStackSaveArea_prevFrame]  @ r2<- prevFP
    str     rPC, [rSELF, #offThread_pc] @ update interpSave.pc
    str     r1, [rSELF, #offThread_curFrame]   @ update interpSave.curFrame
    mov     r0, rSELF
    bl      dvmReportReturn             @ (self)
    SAVEAREA_FROM_FP(r0, rFP)           @ restore StackSaveArea
    b       14b                         @ continue

    /*
     * Return handling, calls through "glue code".
     */
     .if    0
.LreturnOld:
    SAVE_PC_FP_TO_SELF()                @ export state
    mov     r0, rSELF                   @ arg to function
    bl      dvmMterp_returnFromMethod
    b       common_resumeAfterGlueCall
    .endif


/*
 * Somebody has thrown an exception.  Handle it.
 *
 * If the exception processing code returns to us (instead of falling
 * out of the interpreter), continue with whatever the next instruction
 * now happens to be.
 *
 * This does not return.
 */
     .global dvmMterpCommonExceptionThrown
dvmMterpCommonExceptionThrown:
common_exceptionThrown:
.LexceptionNew:

    EXPORT_PC()

    mov     r0, rSELF
    bl      dvmCheckSuspendPending

    ldr     r9, [rSELF, #offThread_exception] @ r9<- self->exception
    mov     r1, rSELF                   @ r1<- self
    mov     r0, r9                      @ r0<- exception
    bl      dvmAddTrackedAlloc          @ don't let the exception be GCed
    ldrh    r2, [rSELF, #offThread_subMode]  @ get subMode flags
    mov     r3, #0                      @ r3<- NULL
    str     r3, [rSELF, #offThread_exception] @ self->exception = NULL

    @ Special subMode?
    cmp     r2, #0                      @ any special subMode handling needed?
    bne     7f                          @ go if so
8:
    /* set up args and a local for "&fp" */
    /* (str sp, [sp, #-4]!  would be perfect here, but is discouraged) */
    str     rFP, [sp, #-4]!             @ *--sp = fp
    mov     ip, sp                      @ ip<- &fp
    mov     r3, #0                      @ r3<- false
    str     ip, [sp, #-4]!              @ *--sp = &fp
    ldr     r1, [rSELF, #offThread_method] @ r1<- self->method
    mov     r0, rSELF                   @ r0<- self
    ldr     r1, [r1, #offMethod_insns]  @ r1<- method->insns
    mov     r2, r9                      @ r2<- exception
    sub     r1, rPC, r1                 @ r1<- pc - method->insns
    mov     r1, r1, asr #1              @ r1<- offset in code units

    /* call, r0 gets catchRelPc (a code-unit offset) */
    bl      dvmFindCatchBlock           @ call(self, relPc, exc, scan?, &fp)

    /* fix earlier stack overflow if necessary; may trash rFP */
    ldrb    r1, [rSELF, #offThread_stackOverflowed]
    cmp     r1, #0                      @ did we overflow earlier?
    beq     1f                          @ no, skip ahead
    mov     rFP, r0                     @ save relPc result in rFP
    mov     r0, rSELF                   @ r0<- self
    mov     r1, r9                      @ r1<- exception
    bl      dvmCleanupStackOverflow     @ call(self)
    mov     r0, rFP                     @ restore result
1:

    /* update frame pointer and check result from dvmFindCatchBlock */
    ldr     rFP, [sp, #4]               @ retrieve the updated rFP
    cmp     r0, #0                      @ is catchRelPc < 0?
    add     sp, sp, #8                  @ restore stack
    bmi     .LnotCaughtLocally

    /* adjust locals to match self->interpSave.curFrame and updated PC */
    SAVEAREA_FROM_FP(r1, rFP)           @ r1<- new save area
    ldr     r1, [r1, #offStackSaveArea_method] @ r1<- new method
    str     r1, [rSELF, #offThread_method]  @ self->method = new method
    ldr     r2, [r1, #offMethod_clazz]      @ r2<- method->clazz
    ldr     r3, [r1, #offMethod_insns]      @ r3<- method->insns
    ldr     r2, [r2, #offClassObject_pDvmDex] @ r2<- method->clazz->pDvmDex
    add     rPC, r3, r0, asl #1             @ rPC<- method->insns + catchRelPc
    str     r2, [rSELF, #offThread_methodClassDex] @ self->pDvmDex = meth...

    /* release the tracked alloc on the exception */
    mov     r0, r9                      @ r0<- exception
    mov     r1, rSELF                   @ r1<- self
    bl      dvmReleaseTrackedAlloc      @ release the exception

    /* restore the exception if the handler wants it */
    ldr    rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh rIBASE
    FETCH_INST()                        @ load rINST from rPC
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    cmp     ip, #OP_MOVE_EXCEPTION      @ is it "move-exception"?
    streq   r9, [rSELF, #offThread_exception] @ yes, restore the exception
    GOTO_OPCODE(ip)                     @ jump to next instruction

    @ Manage debugger bookkeeping
7:
    str     rPC, [rSELF, #offThread_pc]     @ update interpSave.pc
    str     rFP, [rSELF, #offThread_curFrame]     @ update interpSave.curFrame
    mov     r0, rSELF                       @ arg0<- self
    mov     r1, r9                          @ arg1<- exception
    bl      dvmReportExceptionThrow         @ (self, exception)
    b       8b                              @ resume with normal handling

.LnotCaughtLocally: @ r9=exception
    /* fix stack overflow if necessary */
    ldrb    r1, [rSELF, #offThread_stackOverflowed]
    cmp     r1, #0                      @ did we overflow earlier?
    movne   r0, rSELF                   @ if yes: r0<- self
    movne   r1, r9                      @ if yes: r1<- exception
    blne    dvmCleanupStackOverflow     @ if yes: call(self)

    @ may want to show "not caught locally" debug messages here
#if DVM_SHOW_EXCEPTION >= 2
    /* call __android_log_print(prio, tag, format, ...) */
    /* "Exception %s from %s:%d not caught locally" */
    @ dvmLineNumFromPC(method, pc - method->insns)
    ldr     r0, [rSELF, #offThread_method]
    ldr     r1, [r0, #offMethod_insns]
    sub     r1, rPC, r1
    asr     r1, r1, #1
    bl      dvmLineNumFromPC
    str     r0, [sp, #-4]!
    @ dvmGetMethodSourceFile(method)
    ldr     r0, [rSELF, #offThread_method]
    bl      dvmGetMethodSourceFile
    str     r0, [sp, #-4]!
    @ exception->clazz->descriptor
    ldr     r3, [r9, #offObject_clazz]
    ldr     r3, [r3, #offClassObject_descriptor]
    @
    ldr     r2, strExceptionNotCaughtLocally
0:  add     r2, pc
    ldr     r1, strLogTag
1:  add     r1, pc
    mov     r0, #3                      @ LOG_DEBUG
    bl      __android_log_print
#endif
    str     r9, [rSELF, #offThread_exception] @ restore exception
    mov     r0, r9                      @ r0<- exception
    mov     r1, rSELF                   @ r1<- self
    bl      dvmReleaseTrackedAlloc      @ release the exception
    b       common_gotoBail             @ bail out

strExceptionNotCaughtLocally:
    .word   PCREL_REF(.LstrExceptionNotCaughtLocally,0b)
strLogTag:
    .word   PCREL_REF(.LstrLogTag,1b)

    /*
     * Exception handling, calls through "glue code".
     */
    .if     0
.LexceptionOld:
    SAVE_PC_FP_TO_SELF()                @ export state
    mov     r0, rSELF                   @ arg to function
    bl      dvmMterp_exceptionThrown
    b       common_resumeAfterGlueCall
    .endif

#if defined(WITH_JIT)
    /*
     * If the JIT is actively building a trace we need to make sure
     * that the field is fully resolved before including the current
     * instruction.
     *
     * On entry:
     *     r10: &dvmDex->pResFields[field]
     *     r0:  field pointer (must preserve)
     */
common_verifyField:
    ldrh    r3, [rSELF, #offThread_subMode]  @ r3 <- submode byte
    ands    r3, #kSubModeJitTraceBuild
    bxeq    lr                          @ Not building trace, continue
    ldr     r1, [r10]                   @ r1<- reload resolved StaticField ptr
    cmp     r1, #0                      @ resolution complete?
    bxne    lr                          @ yes, continue
    stmfd   sp!, {r0-r2,lr}             @ save regs
    mov     r0, rSELF
    mov     r1, rPC
    bl      dvmJitEndTraceSelect        @ (self,pc) end trace before this inst
    ldmfd   sp!, {r0-r2, lr}
    bx      lr                          @ return
#endif

/*
 * After returning from a "glued" function, pull out the updated
 * values and start executing at the next instruction.
 */
common_resumeAfterGlueCall:
    LOAD_PC_FP_FROM_SELF()              @ pull rPC and rFP out of thread
    ldr     rIBASE, [rSELF, #offThread_curHandlerTable]  @ refresh
    FETCH_INST()                        @ load rINST from rPC
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    GOTO_OPCODE(ip)                     @ jump to next instruction

/*
 * Invalid array index. Note that our calling convention is strange; we use r1
 * and r3 because those just happen to be the registers all our callers are
 * using. We move r3 before calling the C function, but r1 happens to match.
 * r1: index
 * r3: size
 */
common_errArrayIndex:
    EXPORT_PC()
    mov     r0, r3
    bl      dvmThrowArrayIndexOutOfBoundsException
    b       common_exceptionThrown

/*
 * Integer divide or mod by zero.
 */
common_errDivideByZero:
    EXPORT_PC()
    ldr     r0, strDivideByZero
0:  add     r0, pc
    bl      dvmThrowArithmeticException
    b       common_exceptionThrown

strDivideByZero:
    .word   PCREL_REF(.LstrDivideByZero,0b)

/*
 * Attempt to allocate an array with a negative size.
 * On entry: length in r1
 */
common_errNegativeArraySize:
    EXPORT_PC()
    mov     r0, r1                                @ arg0 <- len
    bl      dvmThrowNegativeArraySizeException    @ (len)
    b       common_exceptionThrown

/*
 * Invocation of a non-existent method.
 * On entry: method name in r1
 */
common_errNoSuchMethod:
    EXPORT_PC()
    mov     r0, r1
    bl      dvmThrowNoSuchMethodError
    b       common_exceptionThrown

/*
 * We encountered a null object when we weren't expecting one.  We
 * export the PC, throw a NullPointerException, and goto the exception
 * processing code.
 */
common_errNullObject:
    EXPORT_PC()
    mov     r0, #0
    bl      dvmThrowNullPointerException
    b       common_exceptionThrown

/*
 * For debugging, cause an immediate fault.  The source address will
 * be in lr (use a bl instruction to jump here).
 */
common_abort:
    ldr     pc, .LdeadFood
.LdeadFood:
    .word   0xdeadf00d

/*
 * Spit out a "we were here", preserving all registers.  (The attempt
 * to save ip won't work, but we need to save an even number of
 * registers for EABI 64-bit stack alignment.)
 */
    .macro  SQUEAK num
common_squeak\num:
    stmfd   sp!, {r0, r1, r2, r3, ip, lr}
    ldr     r0, strSqueak\num
0:  add     r0, pc
    mov     r1, #\num
    bl      printf
    ldmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bx      lr

strSqueak\num:
    .word   PCREL_REF(.LstrSqueak,0b)
    .endm

    SQUEAK  0
    SQUEAK  1
    SQUEAK  2
    SQUEAK  3
    SQUEAK  4
    SQUEAK  5

/*
 * Spit out the number in r0, preserving registers.
 */
common_printNum:
    stmfd   sp!, {r0, r1, r2, r3, ip, lr}
    mov     r1, r0
    ldr     r0, strSqueak
0:  add     r0, pc
    bl      printf
    ldmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bx      lr

strSqueak:
    .word   PCREL_REF(.LstrSqueak,0b)

/*
 * Print a newline, preserving registers.
 */
common_printNewline:
    stmfd   sp!, {r0, r1, r2, r3, ip, lr}
    ldr     r0, strNewline
0:  add     r0, pc
    bl      printf
    ldmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bx      lr

strNewline:
    .word   PCREL_REF(.LstrNewline,0b)

    /*
     * Print the 32-bit quantity in r0 as a hex value, preserving registers.
     */
common_printHex:
    stmfd   sp!, {r0, r1, r2, r3, ip, lr}
    mov     r1, r0
    ldr     r0, strPrintHex
0:  add     r0, pc
    bl      printf
    ldmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bx      lr

strPrintHex:
    .word   PCREL_REF(.LstrPrintHex,0b)

/*
 * Print the 64-bit quantity in r0-r1, preserving registers.
 */
common_printLong:
    stmfd   sp!, {r0, r1, r2, r3, ip, lr}
    mov     r3, r1
    mov     r2, r0
    ldr     r0, strPrintLong
0:  add     r0, pc
    bl      printf
    ldmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bx      lr

strPrintLong:
    .word   PCREL_REF(.LstrPrintLong,0b)

/*
 * Print full method info.  Pass the Method* in r0.  Preserves regs.
 */
common_printMethod:
    stmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bl      dvmMterpPrintMethod
    ldmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bx      lr

/*
 * Call a C helper function that dumps regs and possibly some
 * additional info.  Requires the C function to be compiled in.
 */
    .if     0
common_dumpRegs:
    stmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bl      dvmMterpDumpArmRegs
    ldmfd   sp!, {r0, r1, r2, r3, ip, lr}
    bx      lr
    .endif

#if 0
/*
 * Experiment on VFP mode.
 *
 * uint32_t setFPSCR(uint32_t val, uint32_t mask)
 *
 * Updates the bits specified by "mask", setting them to the values in "val".
 */
setFPSCR:
    and     r0, r0, r1                  @ make sure no stray bits are set
    fmrx    r2, fpscr                   @ get VFP reg
    mvn     r1, r1                      @ bit-invert mask
    and     r2, r2, r1                  @ clear masked bits
    orr     r2, r2, r0                  @ set specified bits
    fmxr    fpscr, r2                   @ set VFP reg
    mov     r0, r2                      @ return new value
    bx      lr

    .align  2
    .global dvmConfigureFP
    .type   dvmConfigureFP, %function
dvmConfigureFP:
    stmfd   sp!, {ip, lr}
    /* 0x03000000 sets DN/FZ */
    /* 0x00009f00 clears the six exception enable flags */
    bl      common_squeak0
    mov     r0, #0x03000000             @ r0<- 0x03000000
    add     r1, r0, #0x9f00             @ r1<- 0x03009f00
    bl      setFPSCR
    ldmfd   sp!, {ip, pc}
#endif



/*
 * Zero-terminated ASCII string data.
 *
 * On ARM we have two choices: do like gcc does, and LDR from a .word
 * with the address, or use an ADR pseudo-op to get the address
 * directly.  ADR saves 4 bytes and an indirection, but it's using a
 * PC-relative addressing mode and hence has a limited range, which
 * makes it not work well with mergeable string sections.
 */
    .section .rodata.str1.4,"aMS",%progbits,1

.LstrBadEntryPoint:
    .asciz  "Bad entry point %d\n"
.LstrFilledNewArrayNotImpl:
    .asciz  "filled-new-array only implemented for objects and 'int'"
.LstrDivideByZero:
    .asciz  "divide by zero"
.LstrLogTag:
    .asciz  "mterp"
.LstrExceptionNotCaughtLocally:
    .asciz  "Exception %s from %s:%d not caught locally\n"

.LstrNewline:
    .asciz  "\n"
.LstrSqueak:
    .asciz  "<%d>"
.LstrPrintHex:
    .asciz  "<%#x>"
.LstrPrintLong:
    .asciz  "<%lld>"

