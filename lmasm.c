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
#include <string.h>

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


struct instr {
    // Instruction structure.
    char op[3]; // Operation + arguments (aligned to the right).
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
            res.op[0] = opcode;
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
            res.op[0] = opcode;
            res.op[1] = opr;
            res.len = 2;
            break;
        case INDR:
        case HHLL:
        case HHLL_X:
        case HHLL_Y:
            res.op[0] = opcode;
            res.op[1] = opr >> 8;
            res.op[2] = opr;
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

MKINST(EOR) {
    // Exclusive-OR Memory with Accumulator.
    return ip_mem_to_acc(am, 0x40, opr);
}

MKINST(INC) {
    // Increment Memory by One.
    switch (am) {
        case ZPG:
            return make_instr(am, 0xE6, opr);
        case ZPG_X:
            return make_instr(am, 0xF6, opr);
        case HHLL:
            return make_instr(am, 0xEE, opr);
        case HHLL_X:
            return make_instr(am, 0xFE, opr);
    }
}

MKINST(INX) {
    // Increment Index X by One.
    return ip_mem_to_acc(am, 0xE8, opr);
}

MKINST(INY) {
    // Increment Index Y by One.
    return ip_mem_to_acc(am, 0xC8, opr);
}

MKINST(JMP) {
    // Jump to New Location.
    switch (am) {
        case HHLL:
            return make_instr(am, 0x4C, opr);
        case INDR:
            return make_instr(am, 0x6C, opr);
    }
}

MKINST(JSR) {
    // Jump to New Locaino Saving Return Address.
    return make_instr(HHLL, 0x20, opr);
}

MKINST(LDA) {
    // Load Accumulator with Memory.
    return ip_mem_to_acc(am, 0xA0, opr);
}

MKINST(LDX) {
    // Load X with Memory.
    switch (am) {
        case IMM:
            return make_instr(am, 0xA2, opr);
        case ZPG:
            return make_instr(am, 0xA6, opr);
        case ZPG_Y:
            return make_instr(am, 0xB6, opr);
        case HHLL:
            return make_instr(am, 0xAE, opr);
        case HHLL_Y:
            return make_instr(am, 0xBE, opr);
    }
}

MKINST(LDY) {
    // Load Y with Memory.
    switch (am) {
        case IMM:
            return make_instr(am, 0xA0, opr);
        case ZPG:
            return make_instr(am, 0xA4, opr);
        case ZPG_X:
            return make_instr(am, 0xB4, opr);
        case HHLL:
            return make_instr(am, 0xAC, opr);
        case HHLL_X:
            return make_instr(am, 0xBC, opr);
    }
}

MKINST(LSR) {
    // Shift One Bit Right (Memory or Accumulator).
    return ip_mem_or_acc(am, 0x40, opr);
}

MKINST(NOP) {
    // No Operation.
    return make_instr(IMPL, 0xEA, 0);
}

MKINST(ORA) {
    // OR Memory with Accumulator.
    return ip_mem_to_acc(am, 0x00, opr);
}

MKINST(PHA) {
    // Push Accumulator on Stack.
    return make_instr(IMPL, 0x48, 0);
}

MKINST(PHP) {
    // Push Processor Status on Stack.
    return make_instr(IMPL, 0x08, 0);
}

MKINST(PLA) {
    // Pull Accumulator from Stack.
    return make_instr(IMPL, 0x68, 0);
}

MKINST(PLP) {
    // Push Processor Status from Stack.
    return make_instr(IMPL, 0x28, 0);
}

MKINST(ROL) {
    // Rotate One Bit Left (Memory or Accumulator).
    return ip_mem_or_acc(am, 0x20, opr);
}

MKINST(ROR) {
    // Rotate One Bit Right (Memory or Accumulator).
    return ip_mem_or_acc(am, 0x60, opr);
}

MKINST(RTI) {
    // Return from Interrupt.
    return make_instr(IMPL, 0x40, opr);
}

MKINST(RTS) {
    // Return from Subroutine.
    return make_instr(IMPL, 0x60, opr);
}

MKINST(SBC) {
    // Subtract Memory from Accumulator with Borrow.
    return ip_mem_to_acc(am, 0xE0, opr);
}

MKINST(SEC) {
    // Set Carry Flag.
    return make_instr(IMPL, 0x38, opr);
}


MKINST(SED) {
    // Set Decimal Flag.
    return make_instr(IMPL, 0xF8, opr);
}

MKINST(SEI) {
    // Set Interrupt Disable Status
    return make_instr(IMPL, 0x78, opr);
}

MKINST(STA) {
    // Store Accumulator In Memory.
    return ip_mem_to_acc(am, 0x80, opr);
}

MKINST(STX) {
    // Store Index X in Memory.
    switch (am) {
        case ZPG:
            return make_instr(am, 0x86, opr);
        case ZPG_Y:
            return make_instr(am, 0x96, opr);
        case HHLL:
            return make_instr(am, 0x8E, opr);
    }
}

MKINST(STY) {
    // Store Index Y in Memory.
    switch (am) {
        case ZPG:
            return make_instr(am, 0x84, opr);
        case ZPG_Y:
            return make_instr(am, 0x94, opr);
        case HHLL:
            return make_instr(am, 0x8C, opr);
    }
}

MKINST(TAX) {
    // Transfer Accumulator to Index X.
    return make_instr(IMPL, 0xAA, opr);
}

MKINST(TAY) {
    // Transfer Accumulator to Index Y.
    return make_instr(IMPL, 0xA8, opr);
}

MKINST(TSX) {
    // Transfer Stack Pointer to Index X.
    return make_instr(IMPL, 0xBA, opr);
}

MKINST(TXA) {
    // Transfer Index X to Accumulator.
    return make_instr(IMPL, 0x8A, opr);
}

MKINST(TXS) {
    // Transfer Index X to Stack Register.
    return make_instr(IMPL, 0x9A, opr);
}

MKINST(TYA) {
    // Transfer Index Y to Accumulator.
    return make_instr(IMPL, 0x98, opr);
}

// End of instruction implementation.

// File system functions.

int cur_pos = 0; // Current position (in bytes) in the assembled output.

void write_instr(struct instr i, FILE *f) {
    fwrite((const void *) i.op, i.len, 1, f);
    cur_pos += i.len;
}

void write_data(const void *data, int len, FILE *f) {
    fwrite(data, len, 1, f);
    cur_pos += len;
}

// End of file system functions.

// Helper functions.

void h_org(int pos) {
    // Organization function.
    // Corresponds to: .org <pos>.
    // Meaning: set the current position (the beginning of the program) to pos.
    cur_pos = pos;
}

struct {
    const char *name;
    int pos;
} label_arr[10000]; int label_arr_c = 0;

void h_label(const char *label) {
    // Makes a label.
    // Corresponds to: <label>:.
    label_arr[label_arr_c++].name = label;
    label_arr[label_arr_c - 1].pos = cur_pos;
}

int h_get_label(const char *label) {
    // Looks up a label in the label table.
    // Corresponds to: <label>:.
    for (int i = 0; i < label_arr_c; i++) {
        if (strcmp(label, label_arr[i].name) != 0)
            continue;
        return label_arr[i].pos;
    }
    fprintf(stderr, "lmasm: warning: label %s is not defined\n", label);
    return 0;
}

// End of helper functions.

// Parser functions.



// End of parser functions.

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: lmasm <input> <output>\n");
        exit(1);
    }

    input_file = argv[1];
    output_file = argv[2];

    input_fh = fopen(input_file, "r");
    output_fh = fopen(output_file, "w");

    h_org(0x0080);
    write_instr(i_LDA(IMM, 0x00), output_fh);
    h_label("loop");
    write_instr(i_JMP(HHLL, h_get_label("loop")), output_fh);

    fclose(input_fh);
    fclose(output_fh);
}
