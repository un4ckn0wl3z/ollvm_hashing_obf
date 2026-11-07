///////////////////////////////////////////////////////////////////////////////
//  VM Correctness Test
//
//  Verifies that the VM-based Jenkins hash produces identical results
//  to the native C implementation.
//
//  Build: g++ -std=c++17 -O2 -o test_vm test_vm.cpp
//  Run:   ./test_vm
///////////////////////////////////////////////////////////////////////////////

#include <iostream>
#include <cstdint>
#include <cstring>
#include <cassert>

#include "protection/protection.h"

// ---- Test the native vs VM implementations ----

struct TestCase {
    const char* input;
    uint32_t    expectedHash; // 0 means "just compare native vs VM"
};

int main() {
    std::cout << "=== VM Engine Correctness Test ===" << std::endl;
    std::cout << std::endl;

    // Test cases
    TestCase tests[] = {
        {"",            0},
        {"a",           0},
        {"abc",         0},
        {"hello",       0},
        {"6uncr4ck6",   0x41FBD77D},  // The known password hash from source.cpp
        {"test123",     0},
        {"password",    0},
        {"AAAAAAAAAA",  0},
        {"\x01\x02\x03", 0},
    };

    int passed = 0;
    int total  = sizeof(tests) / sizeof(tests[0]);

    for (auto& tc : tests) {
        uint32_t native = prot::nativeJenkinsHash(tc.input);
        uint32_t vm     = prot::vmJenkinsHash(tc.input);

        bool ok = (native == vm);
        if (tc.expectedHash != 0) {
            ok = ok && (native == tc.expectedHash);
        }

        const char* status = ok ? "PASS" : "FAIL";
        printf("  [%s] \"%s\"  native=0x%08X  vm=0x%08X",
               status, tc.input, native, vm);
        if (tc.expectedHash != 0) {
            printf("  expected=0x%08X", tc.expectedHash);
        }
        printf("\n");

        if (ok) ++passed;
    }

    std::cout << std::endl;
    std::cout << "Results: " << passed << "/" << total << " passed" << std::endl;

    // ---- Test string encryption ----
    std::cout << std::endl;
    std::cout << "=== String Encryption Test ===" << std::endl;

    std::string dec1 = ENC_STR("Hello, World!");
    std::string dec2 = ENC_STR("Enter the password: ");
    std::string dec3 = ENC_STR("Good Job!");
    std::string dec4 = ENC_STR("Denied!");

    bool strOk = (dec1 == "Hello, World!")
              && (dec2 == "Enter the password: ")
              && (dec3 == "Good Job!")
              && (dec4 == "Denied!");

    printf("  [%s] String decryption: \"%s\"\n",
           strOk ? "PASS" : "FAIL", dec1.c_str());
    printf("  [%s] String decryption: \"%s\"\n",
           strOk ? "PASS" : "FAIL", dec2.c_str());
    printf("  [%s] String decryption: \"%s\"\n",
           strOk ? "PASS" : "FAIL", dec3.c_str());
    printf("  [%s] String decryption: \"%s\"\n",
           strOk ? "PASS" : "FAIL", dec4.c_str());

    // ---- Test opaque predicates ----
    std::cout << std::endl;
    std::cout << "=== Opaque Predicate Test ===" << std::endl;

    bool opaqueOk = true;
    for (uint32_t i = 0; i < 1000; ++i) {
        if (!prot::opaqueTrue(i))   { opaqueOk = false; break; }
        if (prot::opaqueFalse(i))   { opaqueOk = false; break; }
        if (!prot::opaqueTrue2(i))  { opaqueOk = false; break; }
        if (prot::opaqueFalse2(i))  { opaqueOk = false; break; }
    }
    printf("  [%s] Opaque predicates (1000 iterations)\n",
           opaqueOk ? "PASS" : "FAIL");

    // ---- Test VM compiler/linker ----
    std::cout << std::endl;
    std::cout << "=== VM Compiler Test ===" << std::endl;

    // Build a simple program: R0 = 5 + 3
    prot::VMCompiler comp;
    comp.mov_imm(prot::R0, 5);
    comp.mov_imm(prot::R1, 3);
    comp.add(prot::R0, prot::R0, prot::R1);
    comp.halt();
    comp.link();

    prot::VMEngine vm;
    vm.loadPlain(comp.getRawCode());
    uint32_t result = vm.execute();
    printf("  [%s] Simple add: 5 + 3 = %u (expected 8)\n",
           result == 8 ? "PASS" : "FAIL", result);

    // Build a program with a loop: sum 1..10
    prot::VMCompiler comp2;
    comp2.mov_imm(prot::R0, 0);   // sum = 0
    comp2.mov_imm(prot::R1, 1);   // i = 1
    comp2.mov_imm(prot::R2, 11);  // limit = 11

    comp2.label("loop");
    comp2.cmp(prot::R1, prot::R2);
    comp2.je("done");
    comp2.add(prot::R0, prot::R0, prot::R1);  // sum += i
    comp2.inc(prot::R1);                        // i++
    comp2.jmp("loop");

    comp2.label("done");
    comp2.halt();
    comp2.link();

    prot::VMEngine vm2;
    vm2.loadPlain(comp2.getRawCode());
    result = vm2.execute();
    printf("  [%s] Sum 1..10: %u (expected 55)\n",
           result == 55 ? "PASS" : "FAIL", result);

    // Test encrypted bytecode
    uint8_t testKey = 0xAB;
    auto encrypted = comp2.getEncryptedCode(testKey);
    prot::VMEngine vm3;
    vm3.loadProgram(encrypted, testKey);
    result = vm3.execute();
    printf("  [%s] Encrypted bytecode: sum 1..10 = %u (expected 55)\n",
           result == 55 ? "PASS" : "FAIL", result);

    // ---- Summary ----
    std::cout << std::endl;
    std::cout << "=== All tests complete ===" << std::endl;

    return (passed == total && strOk && opaqueOk) ? 0 : 1;
}
