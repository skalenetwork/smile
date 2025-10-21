#include "Sim.h"
#include "kdf.h"
#include "Bip32Wallet.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <iomanip>

/**
 * @brief Entry point: demonstrates SIM AKA -> HKDF -> BIP32 seed workflow.
 *
 * High-level steps:
 * 1) Connect to a SIM/USIM (stubbed) and run an AUTHENTICATE to obtain CK and IK.
 * 2) Concatenate Z = CK || IK and derive a seed via HKDF-Extract/HKDF-Expand using a
 *    fixed label for domain separation.
 * 3) Convert the 32-byte seed into a BIP32 child private key (index 0) to validate the flow.
 * 4) Emit a small JSON object with the status and seed (as binary) for inspection.
 *
 * Returns 0 on success; non-zero on failures such as connection/authentication errors.
 */
int main() {
    SIM sim;
    if (!sim.connect()) {
        std::cerr << "Failed to connect to SIM.\n";
        return 1;
    }

    auto aka = sim.authenticate({0x00, 0x11, 0x22, 0x33}, {0x44, 0x55});
    if (!aka) {
        std::cerr << "AUTHENTICATE failed.\n";
        return 1;
    }

    // Z = CK || IK
    std::vector<uint8_t> Z = aka->ck;
    Z.insert(Z.end(), aka->ik.begin(), aka->ik.end());

    std::vector<uint8_t> salt = {0x00};
    auto prk = hkdf_extract(salt, Z);
    auto seed_vec = hkdf_expand(prk, "SMILE|AKA->BIP|seed|v1", 32);

    array32 seed;
    std::copy(seed_vec.begin(), seed_vec.end(), seed.begin());

    Bip32Wallet::deriveWalletPrivateKey(seed, 0);
    sim.disconnect();

    nlohmann::json j;
    j["status"] = "ok";
    j["seed_hex"] = nlohmann::json::binary(seed_vec);
    std::cout << j.dump(2) << "\n";

    return 0;
}