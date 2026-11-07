#pragma once
///////////////////////////////////////////////////////////////////////////////
//  VM Hash — Jenkins One-At-A-Time hash implemented as VM bytecode
//
//  The hash algorithm lives only as encrypted bytecode inside the binary.
//  No native implementation exists — a reverser must first understand our
//  custom VM ISA, then decrypt the bytecode, then decompile it.
///////////////////////////////////////////////////////////////////////////////

#include "vm_compiler.h"
#include "vm_engine.h"
#include <cstdint>
#include <cstring>
#include <vector>

namespace prot {

/// Build Jenkins hash as encrypted VM bytecode
///
/// Register allocation:
///   R0 = Hash (accumulator, also return value)
///   R1 = Index (loop counter)
///   R2 = Length (input, set by caller)
///   R3 = current character
///   R4 = shift temp
///   R5 = scratch
///
inline std::vector<uint8_t> buildJenkinsHashProgram(uint8_t encryptionKey) {
    VMCompiler c;

    // Initialize Hash = 0, Index = 0
    c.mov_imm(R0, 0);                   // Hash = 0
    c.mov_imm(R1, 0);                   // Index = 0

    // --- Main loop ---
    c.label("loop_start");
    c.cmp(R1, R2);                       // compare Index, Length
    c.je("finalize");                    // if Index == Length, exit loop

    // Hash += String[Index]
    c.load_data(R3, R1);                 // R3 = data[Index]  (byte)
    c.add(R0, R0, R3);                   // Hash += char

    // Hash += Hash << INITIAL_SEED (7)
    c.shl(R4, R0, 7);                   // R4 = Hash << 7
    c.add(R0, R0, R4);                   // Hash += Hash << 7

    // Hash ^= Hash >> 6
    c.shr(R4, R0, 6);                   // R4 = Hash >> 6
    c.xor_(R0, R0, R4);                 // Hash ^= Hash >> 6

    // Index++
    c.inc(R1);

    c.jmp("loop_start");

    // --- Finalize ---
    c.label("finalize");

    // Hash += Hash << 3
    c.shl(R4, R0, 3);                   // R4 = Hash << 3
    c.add(R0, R0, R4);                   // Hash += Hash << 3

    // Hash ^= Hash >> 11
    c.shr(R4, R0, 11);                  // R4 = Hash >> 11
    c.xor_(R0, R0, R4);                 // Hash ^= Hash >> 11

    // Hash += Hash << 15
    c.shl(R4, R0, 15);                  // R4 = Hash << 15
    c.add(R0, R0, R4);                   // Hash += Hash << 15

    // Return Hash (in R0)
    c.halt();

    // Link labels
    bool ok = c.link();
    (void)ok; // should always succeed for this program

    return c.getEncryptedCode(encryptionKey);
}

/// Execute Jenkins hash entirely within the VM
///
/// @param str       The null-terminated string to hash
/// @param vmKey     Encryption key for bytecode (compile-time constant)
/// @return          Jenkins One-At-A-Time 32-bit hash
///
inline uint32_t vmJenkinsHash(const char* str, uint8_t vmKey = 0xC3) {
    // Build bytecode once (encrypted), then keep it around
    static std::vector<uint8_t> s_bytecode = buildJenkinsHashProgram(vmKey);

    size_t len = 0;
    const char* p = str;
    while (*p++) ++len;

    VMEngine vm;
    vm.loadProgram(s_bytecode, vmKey);
    vm.setData(reinterpret_cast<const uint8_t*>(str), len);
    vm.setReg(R2, static_cast<uint32_t>(len));

    return vm.execute();
}

/// Native Jenkins hash for verification (same algorithm as before_source.cpp)
inline uint32_t nativeJenkinsHash(const char* str) {
    uint32_t hash = 0;
    size_t len = strlen(str);
    for (size_t i = 0; i < len; ++i) {
        hash += static_cast<uint8_t>(str[i]);
        hash += hash << 7;   // INITIAL_SEED = 7
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash;
}

} // namespace prot
