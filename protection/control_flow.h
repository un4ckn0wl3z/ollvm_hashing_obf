#pragma once
///////////////////////////////////////////////////////////////////////////////
//  Control Flow Obfuscation — Flattening + Opaque Predicates
//
//  1. Control Flow Flattening: transforms sequential blocks into a
//     switch-based dispatcher, hiding the original execution order.
//
//  2. Opaque Predicates: conditions whose outcome is mathematically
//     determined but hard for static analysis to prove, allowing
//     insertion of unreachable decoy code.
//
//  3. Dead Code Insertion: injects plausible-looking but unreachable
//     code that references real variables (prevents optimizer removal).
///////////////////////////////////////////////////////////////////////////////

#include <cstdint>

namespace prot {

// ============================================================================
//  Opaque Predicates
//  Mathematical invariants that fool decompilers.
//
//  IMPORTANT: All predicates must use modular divisors that divide 2^32
//  (i.e., powers of 2) to remain correct under uint32_t overflow.
//  Using % 3, % 5, % 7, % 10, etc. BREAKS when x*x overflows!
// ============================================================================

/// Always evaluates to TRUE.
/// Proof: for any integer x, x*(x+1) is always even (consecutive integers).
///        Since 2 divides 2^32, (x*x + x) mod 2^32 mod 2 = x(x+1) mod 2 = 0.
inline bool opaqueTrue(uint32_t x) {
    return ((x * x + x) % 2) == 0;
}

/// Always evaluates to TRUE (variant — different code shape).
/// Proof: 2x+1 is always odd. Odd × odd = odd in uint32_t
///        (LSB multiplication: 1×1 = 1). So (2x+1)² & 1 = 1.
inline bool opaqueTrue2(uint32_t x) {
    uint32_t odd = 2u * x + 1u;
    uint32_t sq  = odd * odd;
    return (sq & 1u) == 1u;
}

/// Always evaluates to FALSE.
/// Proof: negation of opaqueTrue. x(x+1) is always even, never odd.
inline bool opaqueFalse(uint32_t x) {
    return ((x * x + x) % 2) == 1;
}

/// Always evaluates to FALSE (variant — different code shape).
/// Proof: x² mod 4 ∈ {0, 1} for all integers.
///        Since 4 divides 2^32, overflow doesn't change the result.
///        Even² mod 4 = 0, Odd² mod 4 = 1. Neither is 2.
inline bool opaqueFalse2(uint32_t x) {
    return ((x * x) % 4) == 2;
}

// ============================================================================
//  Control Flow Flattening Macros
//  Transform:  block1 → block2 → block3
//  Into:       while(running) { switch(state) { case 1: ... case 2: ... } }
// ============================================================================

/// Begin a flattened control flow region
/// @param st   Name for the state variable
/// @param init Starting block ID
#define CFF_BEGIN(st, init) \
    { \
        volatile uint32_t st = (init); \
        volatile bool _cff_run = true; \
        while (_cff_run) { \
            switch (st) {

/// Define a block within the flattened region
/// @param st  State variable name (must match CFF_BEGIN)
/// @param id  Unique block ID (integer)
#define CFF_BLOCK(st, id) \
            case (id):

/// Transition to another block
/// @param st     State variable name
/// @param next   Block ID to go to
#define CFF_NEXT(st, next) \
                st = (next); \
                continue;

/// Exit the flattened region
#define CFF_EXIT \
                _cff_run = false; \
                continue;

/// End the flattened control flow region
#define CFF_END \
            default: \
                _cff_run = false; \
                break; \
            } \
        } \
    }

// ============================================================================
//  Dead Code Insertion
//  References real variables so the optimizer can't remove it
// ============================================================================

/// Insert dead code that looks real but never executes
/// Uses opaque predicate to guarantee the branch is never taken
#define DEAD_CODE_1(var) \
    if (::prot::opaqueFalse(static_cast<uint32_t>(__LINE__))) { \
        volatile auto _dead = (var); \
        (void)_dead; \
    }

/// Insert dead code with a function call (decoy)
#define DEAD_CODE_CALL(func, arg) \
    if (::prot::opaqueFalse2(static_cast<uint32_t>(__LINE__))) { \
        volatile auto _dead = func(arg); \
        (void)_dead; \
    }

/// Insert a fake branch that always falls through (confuses decompilers)
#define BOGUS_BRANCH(code_true, code_false) \
    if (::prot::opaqueTrue(static_cast<uint32_t>(__LINE__))) { \
        code_true \
    } else { \
        code_false \
    }

} // namespace prot
