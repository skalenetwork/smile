#pragma once
#include <vector>
#include <string>
#include "common.h"

class Bip32Wallet {
public:
    /**
     * @brief Derives the master key from a given seed using BIP32.
     *
     * This function takes a 256-bit (32-byte) seed and uses it to generate a
     * master private key and chain code for a hierarchical deterministic (HD)
     * wallet, following the BIP32 standard.
     *
     * @param seed A 256-bit (32-byte) seed.
     * @return A pair containing the 32-byte master private key and the 32-byte chain code.
     */

    static std::pair<array256, array256> deriveBIPMasterKey(const array256& seed);

    static bool isValidKey(const array256& privkey);


};