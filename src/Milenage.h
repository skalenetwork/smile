#pragma once

// Milenage.hpp
#pragma once

#include <cstdint>
#include <array>


// All parameters are 16 bytes (128 bits) unless noted otherwise
using Block128 = std::array<uint8_t, 16>;

// A 256-bit (32-byte) block, used for K_ASME, etc.
using Block256 = std::array<uint8_t, 32>;

// Operator‐specific constant OP (16 bytes) and derived OPc.
void deriveOpc(const Block128 &K, const Block128 &OP, Block128 &OPc);

// Core functions
void f1(const Block128 &K, const Block128 &RAND,
        const Block128 &SQN, const Block128 &AMF,
        const Block128 &OPc,
        std::array<uint8_t, 8> &MAC_A, std::array<uint8_t, 8> &MAC_S);

void f2345(const Block128 &K, const Block128 &RAND, const Block128 &OPc,
           std::array<uint8_t, 8> &RES,
           Block128 &CK, Block128 &IK,
           std::array<uint8_t, 6> &AK, std::array<uint8_t, 6> &AKstar);
