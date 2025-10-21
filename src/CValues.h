#pragma once
#include <cstdint>

/**
 * @brief Static tables of constants used by the 2G COMP128-1 emulator.
 *
 * These arrays store pre-defined substitution/compression tables that are used
 * to emulate the behavior of legacy A3/A8 implementations. They are exposed as
 * public static members so that the COMP128-1 implementation can reference them
 * without constructing instances.
 */
class CValues {
public:
    /** 512-byte constant table. */
    static const uint8_t c512[512];
    /** 256-byte constant table. */
    static const uint8_t c256[256];
    /** 128-byte constant table. */
    static const uint8_t c128[128];
    /** 64-byte constant table. */
    static const uint8_t c64[64];
    /** 32-byte constant table. */
    static const uint8_t c32[32];
    /** Convenience vector of pointers {c512, c256, c128, c64, c32}. */
    static const uint8_t * values[5];
};
