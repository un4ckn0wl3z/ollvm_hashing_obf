#pragma once
///////////////////////////////////////////////////////////////////////////////
//  Compile-Time String Encryption
//
//  Strings are XOR-encrypted at compile time (constexpr constructor).
//  Only the encrypted bytes appear in the binary — the plaintext is never
//  stored on disk.  Decryption happens at runtime via .dec().
//
//  Usage:
//    std::string msg = ENC_STR("Hello, World!");
//    // or with a custom key:
//    constexpr prot::EncStr<14, 0xAB> enc("Hello, World!");
//    std::string msg = enc.dec();
///////////////////////////////////////////////////////////////////////////////

#include <array>
#include <string>
#include <cstdint>
#include <cstddef>

namespace prot {

template <std::size_t N, uint8_t BaseKey = 0x5A>
class EncStr {
    std::array<char, N> m_data;

    // Per-character key derivation: makes frequency analysis useless
    static constexpr uint8_t charKey(std::size_t i) {
        return static_cast<uint8_t>(
            BaseKey ^ static_cast<uint8_t>((i * 0x6D + 0x1F) & 0xFF)
        );
    }

public:
    /// Encrypts the string at compile time
    constexpr EncStr(const char (&str)[N]) : m_data{} {
        for (std::size_t i = 0; i < N; ++i) {
            m_data[i] = static_cast<char>(str[i] ^ charKey(i));
        }
    }

    /// Decrypts at runtime — returns std::string (no null terminator issues)
    std::string dec() const {
        std::string result;
        result.reserve(N - 1);
        for (std::size_t i = 0; i < N - 1; ++i) {
            result.push_back(static_cast<char>(m_data[i] ^ charKey(i)));
        }
        return result;
    }

    /// Raw encrypted data (for embedding)
    const std::array<char, N>& encrypted() const { return m_data; }

    /// Size including null terminator
    static constexpr std::size_t size() { return N; }
};

/// Helper macro — encrypts a string literal in one expression
/// The result is a std::string containing the decrypted text
#define ENC_STR(s) \
    ([]() -> std::string { \
        static constexpr ::prot::EncStr<sizeof(s)> _enc(s); \
        return _enc.dec(); \
    }())

/// Same but with a custom base key
#define ENC_STR_KEY(s, key) \
    ([]() -> std::string { \
        static constexpr ::prot::EncStr<sizeof(s), key> _enc(s); \
        return _enc.dec(); \
    }())

} // namespace prot
