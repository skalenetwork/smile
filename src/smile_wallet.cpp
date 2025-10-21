#include "smile_wallet.h"
#include <iostream>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <cstring> // For strlen

// Helper: print bytes as hex
static void print_hex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << "  " << label << ": ";
    for (auto b : data) std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    std::cout << std::dec << std::endl;
}

// Implements BIP-32 master key derivation (returns privkey + chaincode)
static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> bip32_master_key(const std::vector<uint8_t>& seed) {
    const char* key = "Bitcoin seed";
    unsigned int outlen = 64;
    std::vector<uint8_t> out(64);
    HMAC(EVP_sha512(), key, strlen(key), seed.data(), seed.size(), out.data(), &outlen);
    std::vector<uint8_t> privkey(out.begin(), out.begin() + 32);
    std::vector<uint8_t> chaincode(out.begin() + 32, out.end());
    return {privkey, chaincode};
}

void SmileWallet::derive_master(const std::vector<uint8_t>& seed) {
    auto [privkey, chaincode] = bip32_master_key(seed);
    std::cout << "[SMILE] Derived master key (BIP-32):\n";
    print_hex("privkey", privkey);
    print_hex("chaincode", chaincode);
}