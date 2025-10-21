#pragma once

// Milenage.hpp
#pragma once

#include <cstdint>
#include <array>

/**
 * @file Milenage.h
 * @brief Declarations for 3GPP Milenage authentication and key generation functions.
 *
 * The Milenage algorithm set (f1–f5 and f1*–f5*) is specified in 3GPP TS 35.206/35.205.
 * These functions are used by 3G/4G/5G AKA procedures to compute MAC-A/S, RES, CK, IK,
 * and anonymity keys (AK/AK*), given subscriber key K, operator variant constant OPc,
 * and network random challenge RAND.
 */

// Operator‐specific constant OP (16 bytes) and derived OPc.
/**
 * @brief Derives OPc from subscriber key K and operator constant OP.
 *
 * OPc is defined as OPc = OP ⊕ AES-128_K(OP).
 *
 * @param K  16-byte subscriber key.
 * @param OP 16-byte operator constant.
 * @param OPc Output buffer for the 16-byte operator variant constant.
 */
void deriveOpc(const array16 &K, const array16 &OP, array16 &OPc);

// Core functions
/**
 * @brief Computes Milenage f1 and f1* to generate MAC-A and MAC-S.
 *
 * @param K   16-byte subscriber key.
 * @param RAND 16-byte random challenge.
 * @param SQN  16-byte sequence number (only 48 bits used in practice; sized here for convenience).
 * @param AMF  16-byte Authentication Management Field (only 2 bytes used; sized here for convenience).
 * @param OPc  16-byte operator variant constant.
 * @param MAC_A Output 8-byte network authentication code (f1).
 * @param MAC_S Output 8-byte resynchronization code (f1*).
 */
void f1(const array16 &K, const array16 &RAND,
        const array16 &SQN, const array16 &AMF,
        const array16 &OPc,
        std::array<uint8_t, 8> &MAC_A, std::array<uint8_t, 8> &MAC_S);

/**
 * @brief Computes Milenage f2, f3, f4, f5, and f5*.
 *
 * @param K    16-byte subscriber key.
 * @param RAND 16-byte random challenge.
 * @param OPc  16-byte operator variant constant.
 * @param RES  Output 8-byte response.
 * @param CK   Output 16-byte cipher key.
 * @param IK   Output 16-byte integrity key.
 * @param AK   Output 6-byte anonymity key.
 * @param AKstar Output 6-byte anonymity key (resync variant).
 */
void f2345(const array16 &K, const array16 &RAND, const array16 &OPc,
           std::array<uint8_t, 8> &RES,
           array16 &CK, array16 &IK,
           std::array<uint8_t, 6> &AK, std::array<uint8_t, 6> &AKstar);
