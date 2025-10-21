#include "Wallet.h"
#include "common.h"
#include <iostream>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <cstring> // For strlen
#include <algorithm> // For std::all_of



// The order of the secp256k1 curve
static const array256 SECP256K1_ORDER = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

bool Wallet::isValidKey(const array256& privkey) {
    if (std::all_of(privkey.begin(), privkey.end(), [](uint8_t b){ return b == 0; }))
        return false;

    for (size_t i = 0; i < 32; ++i) {
        if (privkey[i] < SECP256K1_ORDER[i]) return true;
        if (privkey[i] > SECP256K1_ORDER[i]) return false;
    }
    return false; // equal to n is invalid
}

std::pair<array256, array256> Wallet::deriveMaster(const array256& seed) {
    static constexpr char key[] = "Bitcoin seed";
    unsigned int outlen = 64;
    std::array<uint8_t, 64> out{};

    unsigned char* result = HMAC(
        EVP_sha512(),
        key, sizeof(key) - 1,
        seed.data(), seed.size(),
        out.data(), &outlen
    );

    if (!result || outlen != 64) {
        throw std::runtime_error("HMAC-SHA512 failed");
    }

    array256 privkey, chaincode;
    std::memcpy(privkey.data(), out.data(), 32);
    std::memcpy(chaincode.data(), out.data() + 32, 32);

    if (!isValidKey(privkey)) {
        throw std::runtime_error("Invalid master private key (IL out of range)");
    }

    return {privkey, chaincode};
}


