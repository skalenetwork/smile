#include "Bip32Wallet.h"
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
static const array32 SECP256K1_ORDER = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

bool Bip32Wallet::isValidKey(const array32& privkey) {
    if (std::all_of(privkey.begin(), privkey.end(), [](uint8_t b){ return b == 0; }))
        return false;

    for (size_t i = 0; i < 32; ++i) {
        if (privkey[i] < SECP256K1_ORDER[i]) return true;
        if (privkey[i] > SECP256K1_ORDER[i]) return false;
    }
    return false; // equal to n is invalid
}

std::pair<array32, array32> Bip32Wallet::deriveBIPMasterKey(const array32& seed) {
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

    array32 privkey, chaincode;
    std::memcpy(privkey.data(), out.data(), 32);
    std::memcpy(chaincode.data(), out.data() + 32, 32);

    if (!isValidKey(privkey)) {
        throw std::runtime_error("Invalid master private key (IL out of range)");
    }

    return {privkey, chaincode};
}

// Helper: compute EC public key from private key (compressed)
std::array<uint8_t, 33> Bip32Wallet::computePublicKeyFromPrivate(const array32 &privkey) {
    std::array<uint8_t, 33> pub{};
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) throw std::runtime_error("Failed to create EC key");

    BIGNUM *bn = BN_bin2bn(privkey.data(), 32, nullptr);
    if (!EC_KEY_set_private_key(key, bn)) {
        BN_free(bn);
        EC_KEY_free(key);
        throw std::runtime_error("Failed to set private key");
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!EC_POINT_mul(group, pub_point, bn, nullptr, nullptr, nullptr)) {
        BN_free(bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(key);
        throw std::runtime_error("EC_POINT_mul failed");
    }

    if (!EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED,
                            pub.data(), pub.size(), nullptr)) {
        BN_free(bn);
        EC_POINT_free(pub_point);
        EC_KEY_free(key);
        throw std::runtime_error("Public key conversion failed");
    }

    BN_free(bn);
    EC_POINT_free(pub_point);
    EC_KEY_free(key);
    return pub;
}

array32 Bip32Wallet::deriveWalletPrivateKey(const array32& seed, uint32_t index)
{

    auto [parentPrivKey, parentChainCode] = deriveBIPMasterKey(seed);

    unsigned char data[1 + 33 + 4];
    size_t data_len = 0;

    bool hardened = (index & 0x80000000) != 0;

    if (hardened) {
        // Hardened derivation: 0x00 || parent_privkey || index
        data[0] = 0x00;
        std::memcpy(data + 1, parentPrivKey.data(), 32);
        data_len = 1 + 32;
    } else {
        // Normal derivation: serP(parent_pubkey) || index
        auto pub = computePublicKeyFromPrivate(parentPrivKey);
        std::memcpy(data, pub.data(), pub.size());
        data_len = pub.size();
    }

    // Append child index (big-endian)
    data[data_len + 0] = (index >> 24) & 0xFF;
    data[data_len + 1] = (index >> 16) & 0xFF;
    data[data_len + 2] = (index >> 8) & 0xFF;
    data[data_len + 3] = index & 0xFF;
    data_len += 4;

    // HMAC-SHA512(chaincode, data)
    std::array<uint8_t, 64> I{};
    unsigned int I_len = 0;
    unsigned char *res = HMAC(EVP_sha512(),
                              parentChainCode.data(), parentChainCode.size(),
                              data, data_len,
                              I.data(), &I_len);
    if (!res || I_len != 64)
        throw std::runtime_error("HMAC-SHA512 failed in child derivation");

    // Split into IL, IR
    array32 IL, IR;
    std::memcpy(IL.data(), I.data(), 32);
    std::memcpy(IR.data(), I.data() + 32, 32);

    // Compute k_child = (IL + k_parent) mod n
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");

    BIGNUM *bn_IL = BN_bin2bn(IL.data(), 32, nullptr);
    BIGNUM *bn_kp = BN_bin2bn(parentPrivKey.data(), 32, nullptr);
    BIGNUM *bn_n = BN_bin2bn(SECP256K1_ORDER.data(), 32, nullptr);
    BIGNUM *bn_kc = BN_new();

    BN_mod_add(bn_kc, bn_IL, bn_kp, bn_n, ctx);

    array32 child_priv{};
    BN_bn2binpad(bn_kc, child_priv.data(), 32);

    BN_free(bn_IL);
    BN_free(bn_kp);
    BN_free(bn_n);
    BN_free(bn_kc);
    BN_CTX_free(ctx);

    if (!isValidKey(child_priv))
        throw std::runtime_error("Derived invalid child private key");

    return {child_priv};
}
