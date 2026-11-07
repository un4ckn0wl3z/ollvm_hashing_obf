#pragma once
///////////////////////////////////////////////////////////////////////////////
//  VM Definitions — Custom ISA for code virtualization
//
//  Register-based VM with 8 general-purpose 32-bit registers.
//  Bytecode is stored encrypted and decrypted at runtime.
///////////////////////////////////////////////////////////////////////////////

#include <cstdint>

namespace prot {

// Virtual registers
enum VMReg : uint8_t {
    R0 = 0, R1, R2, R3, R4, R5, R6, R7,
    VM_REG_COUNT = 8
};

// Opcodes for our custom ISA
// Format: OPCODE [operands...]
enum VMOpcode : uint8_t {
    // Misc
    OP_NOP       = 0x00,  // No operation

    // Data movement
    OP_MOV_IMM   = 0x01,  // Rd, imm32         — Rd = imm32
    OP_MOV_REG   = 0x02,  // Rd, Rs            — Rd = Rs
    OP_PUSH      = 0x03,  // Rs                — push Rs
    OP_POP       = 0x04,  // Rd                — pop to Rd

    // Arithmetic (3-address: Rd = Ra ○ Rb)
    OP_ADD       = 0x10,  // Rd, Ra, Rb        — Rd = Ra + Rb
    OP_SUB       = 0x11,  // Rd, Ra, Rb        — Rd = Ra - Rb
    OP_MUL       = 0x12,  // Rd, Ra, Rb        — Rd = Ra * Rb

    // Bitwise
    OP_XOR       = 0x20,  // Rd, Ra, Rb        — Rd = Ra ^ Rb
    OP_AND       = 0x21,  // Rd, Ra, Rb        — Rd = Ra & Rb
    OP_OR        = 0x22,  // Rd, Ra, Rb        — Rd = Ra | Rb
    OP_NOT       = 0x23,  // Rd, Rs            — Rd = ~Rs
    OP_SHL       = 0x24,  // Rd, Rs, imm8      — Rd = Rs << imm8
    OP_SHR       = 0x25,  // Rd, Rs, imm8      — Rd = Rs >> imm8
    OP_ROL       = 0x26,  // Rd, Rs, imm8      — Rd = rotl(Rs, imm8)
    OP_ROR       = 0x27,  // Rd, Rs, imm8      — Rd = rotr(Rs, imm8)

    // Unary
    OP_INC       = 0x30,  // Rd                — Rd++
    OP_DEC       = 0x31,  // Rd                — Rd--
    OP_ADD_IMM   = 0x32,  // Rd, Rs, imm32     — Rd = Rs + imm32

    // Memory (external data buffer)
    OP_LOAD_DATA = 0x40,  // Rd, Ra            — Rd = data[Ra] (byte)
    OP_LOAD_DATA_W= 0x41, // Rd, Ra            — Rd = data32[Ra] (dword)

    // Compare
    OP_CMP       = 0x50,  // Ra, Rb            — flags = cmp(Ra, Rb)
    OP_CMP_IMM   = 0x51,  // Ra, imm32         — flags = cmp(Ra, imm32)
    OP_TEST      = 0x52,  // Ra, Rb            — flags = test(Ra & Rb)

    // Branching
    OP_JMP       = 0x60,  // offset16           — unconditional jump
    OP_JE        = 0x61,  // offset16           — jump if equal
    OP_JNE       = 0x62,  // offset16           — jump if not equal
    OP_JG        = 0x63,  // offset16           — jump if greater
    OP_JL        = 0x64,  // offset16           — jump if less
    OP_JGE       = 0x65,  // offset16           — jump if greater or equal
    OP_JLE       = 0x66,  // offset16           — jump if less or equal

    // Subroutine
    OP_CALL      = 0x70,  // offset16           — push IP, jump
    OP_RET       = 0x71,  //                    — pop IP, return

    // VM control
    OP_HALT      = 0xFF,  // Stop execution, return R0
};

// Flag bits for comparison results
enum VMFlags : uint32_t {
    FLAG_ZERO    = 1 << 0,  // ZF: result is zero / operands equal
    FLAG_SIGN    = 1 << 1,  // SF: result is negative (signed)
    FLAG_CARRY   = 1 << 2,  // CF: unsigned overflow
    FLAG_GREATER = 1 << 3,  // GF: a > b (unsigned)
};

} // namespace prot
