/*===--------- The Lamassembler ---------===*/
/*=== Simple assembler for the 6502 CPU -===*/
/*        lmasm.c - assembler core          */
/*                                          */
/*   This file contains the main program.   */

/*
 * Copyright (c) 2019, Tomas Glozar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the Lamassembler project.
 */

#include <stdio.h>
#include <stdlib.h>

char *output_file, *input_file;
FILE *output_fh, *input_fh;

// Instruction implementation.

enum addr_mode {
    // Different instruction address modes.
    ACC,    // Accumulator register (A)
    HHLL,   // Address in the (two-byte) argument
    HHLL_X, // ^ + X register with carry
    HHLL_Y, // ^ + Y register with carry
    IMM,    // Immediate (the byte in argument directly)
    IMPL,   // Implied (from opcode)
    INDR,   // Indirect - word (two bytes) residing at the addr. in arg.
    INDR_X, // ^ - word residing at (zeroext addr. in arg. + X) without carry
    INDR_Y, // ^ - word residing at zeroext addr. in arg. incremented by Y 
            // with carry
    REL,    // Address relative to program counter (PC) + signed (byte) argument
    ZPG,    // Address specified in argument (zeroext)
    ZPG_X,  // ^ incremented by X (without carry)
    ZPG_Y   // ^ incremented by Y (without carry)
};

typedef unsigned int operation;

struct instr {
    // Instruction structure.
    operation op; // Operation + arguments (aligned to the right).
    unsigned char len; // Length in bytes (1, 2 or 3).
};

struct instr make_instr(enum addr_mode am, unsigned char opcode, unsigned opr) {
    // The sole purpose of this function is to evaluate the instruction length
    // based on the address mode and generate the instruction from its opcode
    // and operand.
    // Note: all instructions on the 6502 have either one or zero operands; the
    // only thing that may differ is its length (1 or 2 bytes).
    struct instr res;

    switch (am) {
        case IMPL:
            res.op = opcode;
            res.len = 1;
            break;
        case ACC:
        case IMM:
        case ZPG:
        case ZPG_X:
        case ZPG_Y:
        case REL:
        case INDR_X:
        case INDR_Y:
            res.op = opcode << 8 | opr;
            res.len = 2;
            break;
        case INDR:
        case HHLL:
        case HHLL_X:
        case HHLL_Y:
            res.op = opcode << 16 | opr;
            res.len = 3;
            break;
    }
    
    return res;
}

struct instr ip_mem_to_acc(enum addr_mode am, unsigned char opt, unsigned opr) {
    // Operation template for common "memory to accumulator" (e.g. AND Memory
    // with Accumulator, ...) instructions sharing a type of a common template.
    // These use a common scheme - their lower bytes represent the address mode
    // and their higher bytes (which are passed as an "pseudo-opcode" argument
    // to the function) are used to represent the operation type (ADD, AND, ...)
    switch (am) {
        case IMM:
            return make_instr(am, opt + 0x09, opr);
        case ZPG:
            return make_instr(am, opt + 0x05, opr);
        case ZPG_X:
            return make_instr(am, opt + 0x15, opr);
        case HHLL:
            return make_instr(am, opt + 0x0D, opr);
        case HHLL_X:
            return make_instr(am, opt + 0x1D, opr);
        case HHLL_Y:
            return make_instr(am, opt + 0x19, opr);
        case INDR_X:
            return make_instr(am, opt + 0x01, opr);
        case INDR_Y:
            return make_instr(am, opt + 0x11, opr);
    }
}

struct instr ip_mem_or_acc(enum addr_mode am, unsigned char opt, unsigned opr) {
    // Operation template for common "memory or accumulator" instructions.
    // Note: for the mechanism see the comment of ip_mem_to_acc.
    switch (am) {
        case ACC:
            return make_instr(am, opt + 0x0A, opr);
        case ZPG:
            return make_instr(am, opt + 0x06, opr);
        case ZPG_X:
            return make_instr(am, opt + 0x16, opr);
        case HHLL:
            return make_instr(am, opt + 0x0E, opr);
        case HHLL_X:
            return make_instr(am, opt + 0x1E, opr);
    }
}

#define MKINST(name) struct instr i_##name(enum addr_mode am, unsigned opr)

MKINST(ADC) {
    // Add Memory to Accumulator with Carry.
    return ip_mem_to_acc(am, 0x60, opr);
}

MKINST(AND) {
    // AND Memory with Accumulator.
    return ip_mem_to_acc(am, 0x20, opr);
}

MKINST(ASL) {
    // Shift Left One Bit (Memory or Accumulator).
    return ip_mem_or_acc(am, 0x00, opr);
}

MKINST(BCC) {
    /// Branch on Carry Clear.
    return make_instr(REL, 0x90, opr);
}

MKINST(BCS) {
    // Branch on Carry Set.
    return make_instr(REL, 0xB0, opr);
}

MKINST(BEQ) {
    // Branch on Result Zero.
    return make_instr(REL, 0xF0, opr);
}

MKINST(BIT) {
    // Test Bits in Memory with Accumulator.
    switch (am) {
        case ZPG:
            return make_instr(am, 0x24, opr);
        case HHLL:
            return make_instr(am, 0x2C, opr);
    }
}

MKINST(BMI) {
    // Branch on Result Minus.
    return make_instr(REL, 0x30, opr);
}

MKINST(BNE) {
    // Branch on Result not Zero.
    return make_instr(REL, 0xD0, opr);
}

MKINST(BPL) {
    // Branch on Result Plus.
    return make_instr(REL, 0x10, opr);
}

MKINST(BRK) {
    // Force Break.
    return make_instr(IMPL, 0x00, 0);
}

MKINST(BVC) {
    // Branch on Overflow Clear.
    return make_instr(REL, 0x50, opr);
}

MKINST(BVS) {
    // Branch on Overflow Clear.
    return make_instr(REL, 0x70, opr);
}

MKINST(CLC) {
    // Clear Carry Flag.
    return make_instr(IMPL, 0x18, 0);
}

MKINST(CLD) {
    // Clear Decimal Mode.
    return make_instr(IMPL, 0x18, 0);
}

MKINST(CLI) {
    // Clear Interrupt Disable Bit.
    return make_instr(IMPL, 0x58, 0);
}

MKINST(CLV) {
    // Clear Overflow Flag.
    return make_instr(IMPL, 0xB8, 0);
}

MKINST(CMP) {
    // Compare Memory with Accumulator.
    return ip_mem_to_acc(am, 0xC0, opr);
}

MKINST(CPX) {
    // Compare Memory and Index X.
    switch (am) {
        case IMM:
            return make_instr(am, 0xE0, opr);
        case ZPG:
            return make_instr(am, 0xE4, opr);
        case HHLL:
            return make_instr(am, 0xEC, opr);
    }
}

MKINST(CPY) {
    // Compare Memory and Index Y.
    switch (am) {
        case IMM:
            return make_instr(am, 0xC0, opr);
        case ZPG:
            return make_instr(am, 0xC4, opr);
        case HHLL:
            return make_instr(am, 0xCC, opr);
    }
}

MKINST(DEC) {
    // Decrement Memory by One.
    switch (am) {
        case ZPG:
            return make_instr(am, 0xC6, opr);
        case ZPG_X:
            return make_instr(am, 0xD6, opr);
        case HHLL:
            return make_instr(am, 0xCE, opr);
        case HHLL_X:
            return make_instr(am, 0xDE, opr);
    }
}

MKINST(DEX) {
    // Decrement Index X by One.
    return make_instr(am, 0xCA, opr);
}

MKINST(DEY) {
    // Decrement Index Y by One.
    return make_instr(am, 0x88, opr);
}

// End of instruction implementation.

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: lmasm <input> <output>\n");
        exit(1);
    }

    input_file = argv[1];
    output_file = argv[2];
    
    input_fh = fopen(input_file, "r");
    output_fh = fopen(output_file, "w");
}
