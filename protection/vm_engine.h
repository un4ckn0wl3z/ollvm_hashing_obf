#pragma once
///////////////////////////////////////////////////////////////////////////////
//  VM Engine — Interprets encrypted custom bytecode
//
//  Features:
//    - Rolling XOR decryption of bytecode at runtime
//    - Register-based execution (8 GP registers)
//    - External data buffer for reading input
//    - Stack for CALL/RET subroutines
//    - Comparison flags for branching
///////////////////////////////////////////////////////////////////////////////

#include "vm_defs.h"
#include <vector>
#include <cstdint>
#include <cstring>

namespace prot {

class VMEngine {
public:
    static constexpr size_t STACK_SIZE  = 256;
    static constexpr size_t MAX_CODE    = 65536;

private:
    // Execution state
    uint32_t m_regs[VM_REG_COUNT] = {};
    uint32_t m_flags  = 0;
    uint32_t m_ip     = 0;
    uint32_t m_sp     = 0;
    uint32_t m_stack[STACK_SIZE] = {};

    // Bytecode (decrypted in-memory)
    std::vector<uint8_t> m_code;

    // External data buffer (e.g., the string being hashed)
    const uint8_t* m_data     = nullptr;
    size_t         m_dataSize = 0;

    //--- Fetch helpers ---
    uint8_t fetch8() {
        if (m_ip >= m_code.size()) return OP_HALT;
        return m_code[m_ip++];
    }

    uint16_t fetch16() {
        uint8_t lo = fetch8();
        uint8_t hi = fetch8();
        return static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
    }

    uint32_t fetch32() {
        uint8_t b0 = fetch8(), b1 = fetch8(), b2 = fetch8(), b3 = fetch8();
        return static_cast<uint32_t>(b0)
             | (static_cast<uint32_t>(b1) << 8)
             | (static_cast<uint32_t>(b2) << 16)
             | (static_cast<uint32_t>(b3) << 24);
    }

    //--- Stack helpers ---
    void push(uint32_t v) {
        if (m_sp < STACK_SIZE) m_stack[m_sp++] = v;
    }

    uint32_t pop() {
        return (m_sp > 0) ? m_stack[--m_sp] : 0;
    }

    //--- Flag helpers ---
    void setCompareFlags(uint32_t a, uint32_t b) {
        m_flags = 0;
        if (a == b) m_flags |= FLAG_ZERO;
        if (a > b)  m_flags |= FLAG_GREATER;
        if (static_cast<int32_t>(a - b) < 0) m_flags |= FLAG_SIGN;
    }

    //--- Bitwise rotate ---
    static uint32_t rotl32(uint32_t v, uint8_t n) {
        n &= 31;
        return (v << n) | (v >> (32 - n));
    }
    static uint32_t rotr32(uint32_t v, uint8_t n) {
        n &= 31;
        return (v >> n) | (v << (32 - n));
    }

public:
    VMEngine() = default;

    /// Load encrypted bytecode and decrypt with rolling XOR key
    void loadProgram(const std::vector<uint8_t>& encrypted, uint8_t key) {
        m_code.resize(encrypted.size());
        for (size_t i = 0; i < encrypted.size(); ++i) {
            // Rolling key: key + (i * 0x37 + 0x13) to make pattern harder to spot
            uint8_t k = static_cast<uint8_t>(key + (i * 0x37 + 0x13));
            m_code[i] = encrypted[i] ^ k;
        }
    }

    /// Load plaintext bytecode (for testing/debugging)
    void loadPlain(const std::vector<uint8_t>& code) {
        m_code = code;
    }

    /// Set external data buffer (e.g., input string bytes)
    void setData(const uint8_t* data, size_t size) {
        m_data     = data;
        m_dataSize = size;
    }

    /// Set a register value before execution
    void setReg(uint8_t r, uint32_t val) {
        if (r < VM_REG_COUNT) m_regs[r] = val;
    }

    /// Read a register value after execution
    uint32_t getReg(uint8_t r) const {
        return (r < VM_REG_COUNT) ? m_regs[r] : 0;
    }

    /// Reset all state
    void reset() {
        memset(m_regs, 0, sizeof(m_regs));
        m_flags = 0;
        m_ip    = 0;
        m_sp    = 0;
        memset(m_stack, 0, sizeof(m_stack));
    }

    /// Execute loaded bytecode, return R0 on HALT/RET
    uint32_t execute() {
        m_ip = 0;
        m_sp = 0;

        uint32_t maxSteps = 1000000; // infinite-loop guard
        uint32_t steps    = 0;

        while (m_ip < m_code.size() && steps < maxSteps) {
            ++steps;
            uint8_t op = fetch8();

            switch (op) {

            // --- Misc ---
            case OP_NOP: break;

            // --- Data movement ---
            case OP_MOV_IMM: {
                uint8_t d = fetch8() & 0x07;
                m_regs[d] = fetch32();
                break;
            }
            case OP_MOV_REG: {
                uint8_t d = fetch8() & 0x07;
                uint8_t s = fetch8() & 0x07;
                m_regs[d] = m_regs[s];
                break;
            }
            case OP_PUSH: {
                uint8_t s = fetch8() & 0x07;
                push(m_regs[s]);
                break;
            }
            case OP_POP: {
                uint8_t d = fetch8() & 0x07;
                m_regs[d] = pop();
                break;
            }

            // --- Arithmetic ---
            case OP_ADD: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                m_regs[d] = m_regs[a] + m_regs[b];
                break;
            }
            case OP_SUB: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                m_regs[d] = m_regs[a] - m_regs[b];
                break;
            }
            case OP_MUL: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                m_regs[d] = m_regs[a] * m_regs[b];
                break;
            }

            // --- Bitwise ---
            case OP_XOR: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                m_regs[d] = m_regs[a] ^ m_regs[b];
                break;
            }
            case OP_AND: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                m_regs[d] = m_regs[a] & m_regs[b];
                break;
            }
            case OP_OR: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                m_regs[d] = m_regs[a] | m_regs[b];
                break;
            }
            case OP_NOT: {
                uint8_t d = fetch8() & 0x07;
                uint8_t s = fetch8() & 0x07;
                m_regs[d] = ~m_regs[s];
                break;
            }
            case OP_SHL: {
                uint8_t d = fetch8() & 0x07;
                uint8_t s = fetch8() & 0x07;
                uint8_t n = fetch8() & 0x1F;
                m_regs[d] = m_regs[s] << n;
                break;
            }
            case OP_SHR: {
                uint8_t d = fetch8() & 0x07;
                uint8_t s = fetch8() & 0x07;
                uint8_t n = fetch8() & 0x1F;
                m_regs[d] = m_regs[s] >> n;
                break;
            }
            case OP_ROL: {
                uint8_t d = fetch8() & 0x07;
                uint8_t s = fetch8() & 0x07;
                uint8_t n = fetch8();
                m_regs[d] = rotl32(m_regs[s], n);
                break;
            }
            case OP_ROR: {
                uint8_t d = fetch8() & 0x07;
                uint8_t s = fetch8() & 0x07;
                uint8_t n = fetch8();
                m_regs[d] = rotr32(m_regs[s], n);
                break;
            }

            // --- Unary ---
            case OP_INC: {
                uint8_t d = fetch8() & 0x07;
                m_regs[d]++;
                break;
            }
            case OP_DEC: {
                uint8_t d = fetch8() & 0x07;
                m_regs[d]--;
                break;
            }
            case OP_ADD_IMM: {
                uint8_t d = fetch8() & 0x07;
                uint8_t s = fetch8() & 0x07;
                uint32_t imm = fetch32();
                m_regs[d] = m_regs[s] + imm;
                break;
            }

            // --- Memory (external data) ---
            case OP_LOAD_DATA: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint32_t addr = m_regs[a];
                m_regs[d] = (m_data && addr < m_dataSize)
                          ? static_cast<uint32_t>(m_data[addr])
                          : 0;
                break;
            }
            case OP_LOAD_DATA_W: {
                uint8_t d = fetch8() & 0x07;
                uint8_t a = fetch8() & 0x07;
                uint32_t addr = m_regs[a];
                if (m_data && addr + 3 < m_dataSize) {
                    uint32_t v = 0;
                    memcpy(&v, m_data + addr, 4);
                    m_regs[d] = v;
                } else {
                    m_regs[d] = 0;
                }
                break;
            }

            // --- Compare ---
            case OP_CMP: {
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                setCompareFlags(m_regs[a], m_regs[b]);
                break;
            }
            case OP_CMP_IMM: {
                uint8_t a = fetch8() & 0x07;
                uint32_t imm = fetch32();
                setCompareFlags(m_regs[a], imm);
                break;
            }
            case OP_TEST: {
                uint8_t a = fetch8() & 0x07;
                uint8_t b = fetch8() & 0x07;
                uint32_t result = m_regs[a] & m_regs[b];
                m_flags = 0;
                if (result == 0) m_flags |= FLAG_ZERO;
                break;
            }

            // --- Branching ---
            case OP_JMP: {
                m_ip = fetch16();
                break;
            }
            case OP_JE: {
                uint16_t target = fetch16();
                if (m_flags & FLAG_ZERO) m_ip = target;
                break;
            }
            case OP_JNE: {
                uint16_t target = fetch16();
                if (!(m_flags & FLAG_ZERO)) m_ip = target;
                break;
            }
            case OP_JG: {
                uint16_t target = fetch16();
                if (m_flags & FLAG_GREATER) m_ip = target;
                break;
            }
            case OP_JL: {
                uint16_t target = fetch16();
                if (!(m_flags & (FLAG_ZERO | FLAG_GREATER))) m_ip = target;
                break;
            }
            case OP_JGE: {
                uint16_t target = fetch16();
                if (m_flags & (FLAG_ZERO | FLAG_GREATER)) m_ip = target;
                break;
            }
            case OP_JLE: {
                uint16_t target = fetch16();
                if (!(m_flags & FLAG_GREATER)) m_ip = target;
                break;
            }

            // --- Subroutine ---
            case OP_CALL: {
                uint16_t target = fetch16();
                push(m_ip);
                m_ip = target;
                break;
            }
            case OP_RET: {
                uint32_t retAddr = pop();
                if (m_sp == 0 && retAddr == 0) {
                    // Top-level return — exit VM
                    return m_regs[0];
                }
                m_ip = retAddr;
                break;
            }

            // --- VM control ---
            case OP_HALT:
                return m_regs[0];

            default:
                // Unknown opcode — halt with error marker
                m_regs[0] = 0xDEADC0DE;
                return m_regs[0];
            }
        }

        return m_regs[0];
    }
};

} // namespace prot
