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

typedef int bool;
// Maximum for operation parameters (applies both to instruction and
// directives).
#define PARAMETER_MAXIMUM 100

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
            res.op[1] = opr;
            res.op[2] = opr >> 8;
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

void write_data(const void *data, int len) {
    fwrite(data, len, 1, output_fh);
    cur_pos += len;
}

// End of file system functions.

// Helper functions.

void h_org(int pos) {
    // Organization function.
    // Corresponds to: .org <pos>.
    // Meaning: set the current position (the beginning of the program) to pos.
    printf("Org: %d\n", pos);
    cur_pos = pos;
}

struct {
    char *name;
    int pos;
} label_arr[10000]; int label_arr_c = 0;

void h_label(const char *label) {
    // Makes a label.
    // Corresponds to: <label>:.
    // Note: a copy of the label is made, because it is not ensured that the
    // string that the arguments points will survive outside this function.
    printf("Recording label: %s\n", label);
    char *label_perm = calloc(sizeof(char), strlen(label));
    strcpy(label_perm, label);
    label_arr[label_arr_c++].name = label_perm;
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
    fprintf(stderr, "lmasm: error: label %s is not defined\n", label);
    exit(1);
}

int h_is_number(const char *input) {
    // Returns 1 if the input string represents a number.
    // Note: a character literal is also treated as a number. Floating point
    // number is not, since the 6502 can't process floats.
    if (strlen(input) >= 2 && input[0] == '0' && input[1] == 'x') {
        // Hexadecimal number prefix. Check whether all digits are in the range
        // 0-9 and a-f (A-F).
        for (int i = 2; i < strlen(input); i++) {
            if (!((input[i] >= 'a' && input[i] <= 'f') ||
                  (input[i] >= 'A' && input[i] <= 'F') ||
                  (input[i] >= '0' && input[i] <= '9')))
                return 0;
        }
        return 1;
    } else if (strlen(input) >= 2 && input[0] == '0') {
        // Octal number. Check whether all digits are from 0 to 7.
        for (int i = 1; i < strlen(input); i++) {
            if (!(input[i] >= '0' && input[i] <= '7'))
                return 0;
        }
        return 1;
    } else if (strlen(input) == 3 && input[0] == '\'' && input[2] == '\'') {
        return 1;
    } else {
        // Decimal number.
        for (int i = 1; i < strlen(input); i++) {
            if (!(input[i] >= '0' && input[i] <= '9'))
                return 0;
        }
        return 1;
    }
    return 0;
}

int h_number_parser(const char *input) {
    int output;
    if (!h_is_number(input)) {
        fprintf(stderr, "lmasm: error: number expected, got %s instead\n",
                input);
        exit(1);
    }
    if (strlen(input) >= 2 && input[0] == '0' && input[1] == 'x') {
        // Numbers beginning with 0x are treated as hexadecimal.
        if (!sscanf(input + 2, "%x", &output)) {
            fprintf(stderr, "lmasm: error: invalid number: %s\n", input);
            exit(1);
        }
        return output;
    }
    if (strlen(input) >= 2 && input[0] == '0') {
        // Numbers beginning with 0 are treated as octal.
        if (!sscanf(input, "%o", &output)) {
            fprintf(stderr, "lmasm: error: invalid number: %s\n", input);
            exit(1);
        }
        return output;
    }
    if (strlen(input) == 3 && input[0] == '\'' && input[2] == '\'') {
        // Single character.
        output = input[1];
        return output;
    }
    // All other numbers are treated as decimal.
    if (!sscanf(input, "%d", &output)) {
        fprintf(stderr, "lmasm: error: invalid number: %s\n", input);
        exit(1);
    }
    return output;
}

int h_expression_parser(const char *input) {
    // Parses an (single-word) expression.
    // Note: this is an expression either a byte or two bytes long; either
    // a number or a label.
    if (h_is_number(input))
        return h_number_parser(input);
    else
        return h_get_label(input);
}

// End of helper functions.

// Parser functions.

int line_n; // Used only for the purpose of debugging messages.

void p_dir_org(int argc, char **argv) {
    // Parser function for .org directive.
    if (argc != 1) {
        fprintf(stderr, 
                "lmasm: error: incorrect number of arguments to .org\n");
        exit(1);
    }

    // Call the appropriate helper functions. (Parse the argument first.)
    h_org(h_number_parser(argv[0]));
}

void p_dir_data(int argc, char **argv) {
    // Parser function for the .data directive.
    // Note: the data directive can have as many arguments as needed - they are
    // all translated into data and sequentially concatenated.
    // Note 2: strings are expanded without the zero character at the end.
    int data_length = 0;
    // First determine the length of the string.
    for (int i = 0; i < argc; i++) {
        if (h_is_number(argv[i])) {
            // Determine whether to parse this as a 8-bit or 16-bit number.
            // 0xFF and less is treated as 8-bit, larger numbers are treated
            // like 16-bit.
            // Note: if one needs to specify a longer that 8-bit number, he
            // would need to manually write the zeroes, like 0xff00 or 0xff, 0
            // for 16-bit 255.
            if ((unsigned) h_number_parser(argv[i]) <= 0xff)
                data_length += 1;
            else
                data_length += 2;
        } else if (argv[i][0] == '"' && argv[i][strlen(argv[i]) - 1] == '"') {
            // We are parsing a string.
            data_length += strlen(argv[i]) - 2;
        } else {
            // Parse as label.
            // Note: label is an address, and therefore has two bytes.
            data_length += 2;
        }
    }
    // Then allocate the needed space, collect the data and write it.
    char *data = calloc(sizeof(char), data_length);
    int data_i = 0;
    for (int i = 0; i < argc; i++) {
        if (h_is_number(argv[i])) {
            unsigned number = (unsigned) h_number_parser(argv[i]);
            printf("Writing: %d\n", number);
            if (number <= 0xff) {
                data[data_i++] = (char) number;
            } else {
                // A reminder: little endian.
                data[data_i++] = (char) number;
                data[data_i++] = (char) (number >> 8);
            }
        } else if (argv[i][0] == '"' && argv[i][strlen(argv[i]) - 1] == '"') {
            // Copy the string over.
            for (int j = 1; j < strlen(argv[i]) - 1; j++) {
                data[data_i++] = argv[i][j];
                printf("Writing: %d\n", argv[i][j]);
            }
        } else {
            // Label.
            int address = h_get_label(argv[i]);
            printf("Writing: %d\n", address);
            data[data_i++] = (char) address;
            data[data_i++] = (char) (address >> 8);
        }
    }

    write_data(data, data_length);
    free(data);
}

void p_directive_distribution(char *directive, int argc, char **argv) {
    // Calls the appropriate function representing the directive and passes it
    // the arguments.
    printf("Processing special directive: %s\n", directive);
    for (int i = 0; i < argc; i++) {
        printf("Argument number %d: %s\n", i, argv[i]);
    }
    
    if (strcmp(directive, ".data") == 0) {
        p_dir_data(argc, argv);
    } else if (strcmp(directive, ".org") == 0) {
        p_dir_org(argc, argv);
    }
}

void p_line(const char *line) {
    int len = strlen(line);
    char *line2 = calloc(sizeof(char), len + 1);
    bool inside_quotes = 0;

    // Remove comments.
    // Note: here we want to copy over the zero character if the line is
    // complete (i.e. not ended with a comment), that's why we use len + 1
    // instead of len as the for limit.
    for (int i = 0; i < (len + 1); i++) {
        if (line[i] == '"' || line[i] == '\'' &&
                (i == 0 || line[i - 1] != '\\'))
            inside_quotes = !inside_quotes;
        if (line[i] == ';' && !inside_quotes) {
            line2[i] = '\0';
            break;
        } else
            line2[i] = line[i];
    }

    if (inside_quotes) {
        fprintf(stderr, "lmasm: error: line %d: wrong quote pairing\n", line_n);
        exit(1);
    }

    // Then process any labels on the line. (Also skip any whitespace.)
    char *label = calloc(sizeof(char), len + 1);
    int label_index = 0;
    int skip_index = 0;
    char *line3 = calloc(sizeof(char), len + 1);
    int line3_index = 0;

    for (int i = 0; i < len; i++) {
        if (line2[i] == '"' || line2[i] == '\'' &&
                (i == 0 || line2[i - 1] != '\\'))
            inside_quotes = !inside_quotes;
        if (line2[i] == ':' && !inside_quotes) {
            // End label by zero to be processed correctly by the string library
            // functions and reset the loading index to zero.
            label[label_index] = '\0';
            label_index = 0;
            // Write label into array.
            h_label(label);
            // We don't want to include the label into line3, therefore shift
            // the line3 index back.
            line3_index -= skip_index;
            skip_index = 0;
        } else {
            if (line2[i] != ' ' && line2[i] != '\t' && !inside_quotes) {
                label[label_index++] = line2[i];
            }
            skip_index++;
            line3[line3_index++] = line2[i];
        }
    }

    // Now we have to check if the line represent a special assembler directive.
    // This is checked by looking at the first character (all special directives
    // begin with a dot).
    // Note: we reuse the memory for line2 (which won't be used again) to
    // contain the directive.
    char *directive = line2;
    int directive_i = 0;
    int start = -1;
    for (int i = 0; i < strlen(line3); i++) {
        // Skip any initial spaces.
        if (line3[i] != ' ' && line3[i] != '\t') {
            start = i;
            break;
        }
    }
    if (start == -1) {
        // Empty line.
        return;
    }
    if (line3[start] == '.') {
        // Special directive detected. Load its name and its parameters.
        int i = start;
        for (; i < strlen(line3); i++) {
            if (line3[i] == ' ' || line3[i] == '\t') {
                start = i;
                directive[directive_i] = '\0';
                break;
            }
            directive[directive_i++] = line3[i];
        }
        // Now load parameters until the end of the line is reached.
        int argc = 0;
        char **argv = calloc(sizeof(char *), PARAMETER_MAXIMUM);
        // Index of the end of the line.
        const int eol = strlen(line3);
        while (i < eol) {
            // First skip any initial spaces.
            while (i < eol && (line3[i] == ' ' || line3[i] == '\t'))
                i++;
            if (i == eol)
                // We reached the end of the line (this "argument" contained
                // only whitespace).
                break;
            // Then load the paramterer while looking for the separator (in this
            // case a comma).
            // Note: Again, "inside quotes" mechanism has to be used to avoid
            // counting the separator inside a literal.
            argv[argc] = calloc(sizeof(char), strlen(line3) + 1);
            int argv_i = 0;
            for (; i < eol; i++) {
                if (line3[i] == '"' || line3[i] == '\'' &&
                        (i == 0 || line3[i - 1] != '\\'))
                    inside_quotes = !inside_quotes;
                if (line3[i] == ',' && !inside_quotes) {
                    break;
                }
                argv[argc][argv_i++] = line3[i];
            }
            // End the parameter with a zero and move the index to enable their
            // next argument to be loaded. (Otherwise the next iteration of the
            // cycle would see the comma and load an empty argument).
            argv[argc][argv_i] = '\0';
            ++argc; ++i;
        }
        // Process the directive and free argv.
        // Note: we do not need to free the variable directive, because it uses
        // the same address space as line2, which is freed at the end of the
        // function.
        p_directive_distribution(directive, argc, argv);
        for (int j = 0; i < argc; i++)
            free(argv[j]);
        free(argv);
    }

    free(line2);
    free(line3);
    free(label);
}

void p_cleanup() {
    // Label names are generated dynamically - free the memory.
    for (int i = 0; i < label_arr_c; i++) {
        free(label_arr[i].name);
    }
}

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

    size_t len = 0;
    ssize_t read = 0;
    char *line = NULL;

    while ((read = getline(&line, &len, input_fh)) != -1) {
        // Remove newline character.
        line[strlen(line) - 1] = '\0';
        p_line(line);
    }

    if (line)
        free(line);

    fclose(input_fh);
    fclose(output_fh);
    p_cleanup();
}
