#pragma once
#include <vector>
#include <string>
#include "common.h"

/**
 * @brief Minimal BIP32 wallet utilities for seed, key, and child derivation.
 *
 * Provides helper functions to derive a BIP32 master key/chain code from a 32-byte seed,
 * derive a child private key at an index (hardened/non-hardened), and compute the
 * corresponding compressed public key from a private key on secp256k1.
 *
 * All methods are stateless. On error (e.g., HMAC failure or invalid key range),
 * functions throw std::runtime_error.
 */
class Bip32Wallet {


    /**
     * @brief Derives the master key from a given seed using BIP32 (HMAC-SHA512).
     *
     * Uses key = "Bitcoin seed" and computes I = HMAC-SHA512(key, seed), then splits
     * I into IL (master private key) and IR (master chain code). The function verifies
     * IL is a valid secp256k1 private key (in [1, n-1]).
     *
     * @param seed A 256-bit (32-byte) seed.
     * @return A pair {masterPrivKey[32], masterChainCode[32]}.
     * @throws std::runtime_error if HMAC or range validation fails.
     */
    static std::pair<array32, array32> deriveBIPMasterKey(const array32& seed);

    /**
     * @brief Checks whether a 32-byte scalar is a valid secp256k1 private key.
     *
     * Validity means the value is in the interval [1, n-1], where n is the curve order.
     * All-zero or value >= n are invalid.
     *
     * @param privkey 32-byte candidate private key.
     * @return true if valid, false otherwise.
     */
    static bool isValidKey(const array32& privkey);

public:

    /**
     * @brief Derives a child private key at the given index from a 32-byte seed.
     *
     * Steps:
     * 1) Derive BIP32 master key pair (k_par, c_par) from seed via deriveBIPMasterKey.
     * 2) If index has bit 31 set, perform hardened derivation with data = 0x00 || ser256(k_par) || ser32(index).
     *    Otherwise use non-hardened derivation with data = serP(K_par) || ser32(index) where K_par = point(k_par).
     * 3) Compute I = HMAC-SHA512(c_par, data) and split into IL, IR.
     * 4) Compute k_child = (IL + k_par) mod n and validate it.
     *
     * @param seed 32-byte seed used to derive the master key first.
     * @param index Child index; set bit 31 (0x80000000) for hardened children.
     * @return 32-byte child private key.
     * @throws std::runtime_error on HMAC failure or invalid derived key.
     */
    static array32 deriveWalletPrivateKey(const array32& seed, uint32_t index = 0);

    /**
     * @brief Computes a compressed secp256k1 public key from a 32-byte private key.
     *
     * Uses OpenSSL to multiply the curve generator by the scalar and encodes the
     * resulting EC point in 33-byte compressed form (0x02/0x03 || X).
     *
     * @param privkey 32-byte private key.
     * @return 33-byte compressed public key.
     * @throws std::runtime_error if key setup or point multiplication fails.
     */
    static std::array<uint8_t, 33> computePublicKeyFromPrivate(const array32 &privkey);


};