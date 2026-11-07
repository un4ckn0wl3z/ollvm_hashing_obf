#pragma once
///////////////////////////////////////////////////////////////////////////////
//  VM Compiler — Builder pattern for assembling VM bytecode programs
//
//  Supports labels + forward references (resolved at link time).
//  Outputs either plaintext or encrypted bytecode.
///////////////////////////////////////////////////////////////////////////////

#include "vm_defs.h"
#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <cassert>

namespace prot {

class VMCompiler {
    std::vector<uint8_t> m_code;

    // Label support
    std::map<std::string, uint16_t> m_labels;
    struct Fixup { size_t position; std::string label; };
    std::vector<Fixup> m_fixups;

    //--- Emit helpers ---
    void emit8(uint8_t v)  { m_code.push_back(v); }
    void emit16(uint16_t v) {
        m_code.push_back(static_cast<uint8_t>(v & 0xFF));
        m_code.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    }
    void emit32(uint32_t v) {
        m_code.push_back(static_cast<uint8_t>(v & 0xFF));
        m_code.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        m_code.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        m_code.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    }

    void emitJump(uint8_t op, const std::string& target) {
        emit8(op);
        m_fixups.push_back({m_code.size(), target});
        emit16(0); // placeholder
    }

public:
    /// Current code position (useful for manual offset calculation)
    uint16_t pos() const { return static_cast<uint16_t>(m_code.size()); }

    /// Define a label at the current position
    void label(const std::string& name) {
        m_labels[name] = pos();
    }

    //=== Data Movement ===
    void nop()                              { emit8(OP_NOP); }
    void mov_imm(uint8_t d, uint32_t imm)   { emit8(OP_MOV_IMM); emit8(d); emit32(imm); }
    void mov_reg(uint8_t d, uint8_t s)       { emit8(OP_MOV_REG); emit8(d); emit8(s); }
    void push(uint8_t s)                     { emit8(OP_PUSH); emit8(s); }
    void pop(uint8_t d)                      { emit8(OP_POP); emit8(d); }

    //=== Arithmetic ===
    void add(uint8_t d, uint8_t a, uint8_t b) { emit8(OP_ADD); emit8(d); emit8(a); emit8(b); }
    void sub(uint8_t d, uint8_t a, uint8_t b) { emit8(OP_SUB); emit8(d); emit8(a); emit8(b); }
    void mul(uint8_t d, uint8_t a, uint8_t b) { emit8(OP_MUL); emit8(d); emit8(a); emit8(b); }

    //=== Bitwise ===
    void xor_(uint8_t d, uint8_t a, uint8_t b) { emit8(OP_XOR); emit8(d); emit8(a); emit8(b); }
    void and_(uint8_t d, uint8_t a, uint8_t b) { emit8(OP_AND); emit8(d); emit8(a); emit8(b); }
    void or_(uint8_t d, uint8_t a, uint8_t b)  { emit8(OP_OR);  emit8(d); emit8(a); emit8(b); }
    void not_(uint8_t d, uint8_t s)             { emit8(OP_NOT); emit8(d); emit8(s); }
    void shl(uint8_t d, uint8_t s, uint8_t n)  { emit8(OP_SHL); emit8(d); emit8(s); emit8(n); }
    void shr(uint8_t d, uint8_t s, uint8_t n)  { emit8(OP_SHR); emit8(d); emit8(s); emit8(n); }
    void rol(uint8_t d, uint8_t s, uint8_t n)  { emit8(OP_ROL); emit8(d); emit8(s); emit8(n); }
    void ror(uint8_t d, uint8_t s, uint8_t n)  { emit8(OP_ROR); emit8(d); emit8(s); emit8(n); }

    //=== Unary ===
    void inc(uint8_t d)                              { emit8(OP_INC); emit8(d); }
    void dec(uint8_t d)                              { emit8(OP_DEC); emit8(d); }
    void add_imm(uint8_t d, uint8_t s, uint32_t imm) { emit8(OP_ADD_IMM); emit8(d); emit8(s); emit32(imm); }

    //=== Memory ===
    void load_data(uint8_t d, uint8_t a)   { emit8(OP_LOAD_DATA);   emit8(d); emit8(a); }
    void load_data_w(uint8_t d, uint8_t a) { emit8(OP_LOAD_DATA_W); emit8(d); emit8(a); }

    //=== Compare ===
    void cmp(uint8_t a, uint8_t b)           { emit8(OP_CMP);     emit8(a); emit8(b); }
    void cmp_imm(uint8_t a, uint32_t imm)     { emit8(OP_CMP_IMM); emit8(a); emit32(imm); }
    void test(uint8_t a, uint8_t b)           { emit8(OP_TEST);    emit8(a); emit8(b); }

    //=== Branching ===
    void jmp(const std::string& target)  { emitJump(OP_JMP, target); }
    void je(const std::string& target)   { emitJump(OP_JE,  target); }
    void jne(const std::string& target)  { emitJump(OP_JNE, target); }
    void jg(const std::string& target)   { emitJump(OP_JG,  target); }
    void jl(const std::string& target)   { emitJump(OP_JL,  target); }
    void jge(const std::string& target)  { emitJump(OP_JGE, target); }
    void jle(const std::string& target)  { emitJump(OP_JLE, target); }

    //=== Subroutine ===
    void call(const std::string& target) { emitJump(OP_CALL, target); }
    void ret()  { emit8(OP_RET); }
    void halt() { emit8(OP_HALT); }

    //=== Junk insertion (makes pattern matching harder) ===
    void junk() {
        // NOP sled with register-preserving garbage
        emit8(OP_NOP);
        // push R7, pop R7 (no-op pair)
        emit8(OP_PUSH); emit8(R7);
        emit8(OP_POP);  emit8(R7);
    }

    /// Resolve all label references. Returns false on unresolved labels.
    bool link() {
        for (auto& fixup : m_fixups) {
            auto it = m_labels.find(fixup.label);
            if (it == m_labels.end()) return false;
            uint16_t addr = it->second;
            m_code[fixup.position]     = static_cast<uint8_t>(addr & 0xFF);
            m_code[fixup.position + 1] = static_cast<uint8_t>((addr >> 8) & 0xFF);
        }
        return true;
    }

    /// Get raw (plaintext) bytecode
    std::vector<uint8_t> getRawCode() const { return m_code; }

    /// Get encrypted bytecode (matching VMEngine::loadProgram decryption)
    std::vector<uint8_t> getEncryptedCode(uint8_t key) const {
        std::vector<uint8_t> enc(m_code.size());
        for (size_t i = 0; i < m_code.size(); ++i) {
            uint8_t k = static_cast<uint8_t>(key + (i * 0x37 + 0x13));
            enc[i] = m_code[i] ^ k;
        }
        return enc;
    }

    /// Get code size
    size_t codeSize() const { return m_code.size(); }

    /// Clear all state for reuse
    void clear() {
        m_code.clear();
        m_labels.clear();
        m_fixups.clear();
    }
};

} // namespace prot
