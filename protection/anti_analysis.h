#pragma once
///////////////////////////////////////////////////////////////////////////////
//  Anti-Analysis — Defensive runtime checks for software protection
//
//  Detects debuggers, single-stepping, and code tampering.
//  All techniques use standard, documented OS APIs.
//
//  On non-Windows platforms, checks return false (not detected).
///////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <cstring>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace prot {

// ============================================================================
//  Timing Analysis Detection
// ============================================================================

/// Timing-based integrity check using high-resolution timer.
/// Single-stepping through code causes measurable delays.
inline bool timingCheckDetected() {
#if defined(_WIN32)
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    // Lightweight busy-work (should take microseconds natively)
    volatile uint32_t x = 0;
    for (int i = 0; i < 100; ++i) x += i * 3;

    QueryPerformanceCounter(&t2);

    // Under a debugger with single-stepping, this loop takes milliseconds
    double elapsed = static_cast<double>(t2.QuadPart - t1.QuadPart)
                   / static_cast<double>(freq.QuadPart);
    return elapsed > 0.05; // 50ms threshold
#else
    // Linux: use clock_gettime for similar check
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    volatile uint32_t x = 0;
    for (int i = 0; i < 100; ++i) x += i * 3;

    clock_gettime(CLOCK_MONOTONIC, &t2);

    double elapsed = (t2.tv_sec - t1.tv_sec)
                   + (t2.tv_nsec - t1.tv_nsec) / 1e9;
    return elapsed > 0.05;
#endif
}

// ============================================================================
//  Debugger Presence Detection
// ============================================================================

/// Check if a debugger is attached (standard OS API)
inline bool debuggerDetected() {
#if defined(_WIN32)
    // Standard Windows API check
    if (IsDebuggerPresent()) return true;

    // Check for remote debugger
    BOOL remotePresentFlag = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remotePresentFlag);
    if (remotePresentFlag) return true;
#elif defined(__linux__)
    // On Linux, check /proc/self/status for TracerPid
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = 0;
                sscanf(line + 10, "%d", &pid);
                fclose(f);
                return pid != 0;
            }
        }
        fclose(f);
    }
#endif
    return false;
}

// ============================================================================
//  Code Integrity Verification
// ============================================================================

/// FNV-1a hash of a memory region (for code integrity checks)
///
/// Usage: compute the hash of a critical function at build time (or on first
/// run), then periodically re-check at runtime.  If someone patches the
/// code in memory, the hash will change.
///
inline uint32_t fnv1aHash(const void* data, size_t length) {
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t hash = 0x811C9DC5u; // FNV offset basis
    for (size_t i = 0; i < length; ++i) {
        hash ^= bytes[i];
        hash *= 0x01000193u;     // FNV prime
    }
    return hash;
}

/// Verify integrity of a code region against a known checksum.
/// @param funcPtr   Pointer to the start of the function/region
/// @param length    Number of bytes to check
/// @param expected  The hash value computed at build/load time
///
inline bool integrityVerified(const void* funcPtr, size_t length,
                              uint32_t expected) {
    return fnv1aHash(funcPtr, length) == expected;
}

// ============================================================================
//  Combined check — use this in your protection code
// ============================================================================

/// Run all detection heuristics.
/// Returns true if analysis/tampering is detected.
inline bool isUnderAnalysis() {
    if (debuggerDetected())   return true;
    if (timingCheckDetected()) return true;
    return false;
}

} // namespace prot
