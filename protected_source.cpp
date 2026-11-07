///////////////////////////////////////////////////////////////////////////////
//  Protected Source — All defensive layers active
//
//  Compare with before_source.cpp (plaintext password in binary) and
//  source.cpp (hashed password + XOR strings).
//
//  This version adds:
//    Layer 1: Compile-time string encryption (no cleartext in binary)
//    Layer 2: VM-based hash computation (hash algo is encrypted bytecode)
//    Layer 3: Control flow flattening (no linear execution path)
//    Layer 4: Anti-analysis checks (debugger / timing detection)
//    Layer 5: Opaque predicates + dead code (confuses decompilers)
//    Layer 6: No direct constant comparison (hash XOR check)
//    Layer 7: Decoy function (wastes reverser's time)
//
//  Build: g++ -std=c++17 -O2 -o protected protected_source.cpp
//  (Windows: cl /std:c++17 /O2 protected_source.cpp)
///////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>

#ifdef _WIN32
#include <Windows.h>
typedef unsigned char BYTE;
typedef BYTE* PBYTE;
typedef char* PCHAR;
typedef unsigned int UINT32;
#else
// Cross-platform compatibility
typedef unsigned char BYTE;
typedef BYTE* PBYTE;
typedef char* PCHAR;
typedef unsigned int UINT32;
#endif

#include "protection/protection.h"

// ============================================================================
//  Layer 7: Decoy function
//  Looks like the real hash but produces wrong results.
//  Forces the reverser to analyze both and figure out which is real.
//  The real hash lives only inside the VM — there is NO native version.
// ============================================================================

#ifdef _MSC_VER
__declspec(noinline)
#else
__attribute__((noinline, used))
#endif
static UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String) {
    UINT32 Hash = 0;
    size_t Length = strlen(String);
    for (size_t i = 0; i < Length; ++i) {
        Hash += static_cast<UINT32>(static_cast<unsigned char>(String[i]));
        Hash += Hash << 5;   // WRONG: should be 7
        Hash ^= Hash >> 8;   // WRONG: should be 6
    }
    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;
    return Hash;
}

// ============================================================================
//  Main — Protected entry point
// ============================================================================

int main() {

    // ---- Layer 4: Anti-analysis (early check) ----
    // If under analysis, silently corrupt behavior instead of crashing.
    // Crashing teaches the reverser; subtle corruption wastes their time.
    volatile uint32_t corruption = 0;
    if (prot::isUnderAnalysis()) {
        corruption = 0x01;  // Flip a bit used later in comparison
    }

    // ---- Layer 1: All user-visible strings are encrypted ----
    // In the binary, these are XOR-encrypted blobs.
    // They're decrypted on the stack at runtime and freed after use.
    std::string promptMsg = ENC_STR("Enter the password: ");
    std::string successMsg = ENC_STR("Good Job!");
    std::string failMsg    = ENC_STR("Denied!");

    // ---- Layer 3: Control flow flattening ----
    // The execution flow is: prompt → read → hash → check → respond
    // But in the binary it appears as a dispatcher loop with no clear order.

    char inputBuf[256] = {};
    UINT32 hashResult = 0;
    bool passed = false;

    CFF_BEGIN(state, 10)

        // Block 10: Display prompt
        CFF_BLOCK(state, 10)
            DEAD_CODE_1(promptMsg);   // Layer 5: dead code referencing real var
            std::cout << promptMsg;
            CFF_NEXT(state, 20)

        // Block 20: Read user input
        CFF_BLOCK(state, 20)
            std::cin >> inputBuf;
            CFF_NEXT(state, 30)

        // Block 30: Compute hash via VM
        CFF_BLOCK(state, 30)
        {
            // Layer 2: The Jenkins hash runs inside our custom VM.
            // The binary contains only encrypted bytecode + the VM interpreter.
            // There is NO native hash function — only the decoy above.
            hashResult = prot::vmJenkinsHash(inputBuf);

            // Layer 5: Dead code calling the decoy function
            // Never executes, but it gets compiled in and references
            // the decoy, making the reverser analyze both paths.
            DEAD_CODE_CALL(HashStringJenkinsOneAtATime32BitA, inputBuf);

            CFF_NEXT(state, 40)
        }

        // Block 40: Verify hash
        CFF_BLOCK(state, 40)
        {
            // Layer 6: No direct `cmp reg, 0x41FBD77D` in the binary.
            // XOR the result with the expected hash — if it's zero, match.
            // The corruption variable (from anti-analysis) flips a bit
            // if a debugger was detected, causing silent failure.
            volatile UINT32 expected = 0x41FBD77D;
            volatile UINT32 check = hashResult ^ expected ^ corruption;

            // Layer 5: Opaque predicate wrapping the real check
            // opaqueTrue() always returns true, but decompilers can't prove it
            BOGUS_BRANCH(
                /* always taken: real logic */
                passed = (check == 0);,
                /* never taken: decoy using wrong function */
                passed = (HashStringJenkinsOneAtATime32BitA(inputBuf)
                          == 0x12345678);
            )

            CFF_NEXT(state, 50)
        }

        // Block 50: Output result
        CFF_BLOCK(state, 50)
            if (passed) {
                // Opaque predicate guards the real output
                if (prot::opaqueTrue2(hashResult)) {
                    std::cout << successMsg << std::endl;
                } else {
                    // Never reached — but references real vars
                    std::cout << failMsg << std::endl;
                }
            } else {
                std::cout << failMsg << std::endl;
            }
            CFF_NEXT(state, 99)

        // Block 99: Cleanup & exit
        CFF_BLOCK(state, 99)
            // Scrub sensitive data from stack
            memset(inputBuf, 0, sizeof(inputBuf));
            hashResult = 0;
            CFF_EXIT

    CFF_END

    return 0;
}
