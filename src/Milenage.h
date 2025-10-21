#pragma once

// Milenage.hpp
#pragma once

#include <cstdint>
#include <array>


// All parameters are 16 bytes (128 bits) unless noted otherwise
using array16 = std::array<uint8_t, 16>;

// A 256-bit (32-byte) block, used for K_ASME, etc.
using array256 = std::array<uint8_t, 32>;

// Operator‐specific constant OP (16 bytes) and derived OPc.
void deriveOpc(const array16 &K, const array16 &OP, array16 &OPc);

// Core functions
void f1(const array16 &K, const array16 &RAND,
        const array16 &SQN, const array16 &AMF,
        const array16 &OPc,
        std::array<uint8_t, 8> &MAC_A, std::array<uint8_t, 8> &MAC_S);

void f2345(const array16 &K, const array16 &RAND, const array16 &OPc,
           std::array<uint8_t, 8> &RES,
           array16 &CK, array16 &IK,
           std::array<uint8_t, 6> &AK, std::array<uint8_t, 6> &AKstar);
