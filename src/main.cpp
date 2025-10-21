#include "smile_sim.h"
#include "smile_kdf.h"
#include "smile_wallet.h"
#include <nlohmann/json.hpp>
#include <iostream>
#include <iomanip>

int main() {
    SmileSIM sim;
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
    auto prk = smile_hkdf_extract(salt, Z);
    auto seed = smile_hkdf_expand(prk, "SMILE|AKA->BIP|seed|v1", 64);

    SmileWallet::derive_master(seed);
    sim.disconnect();

    nlohmann::json j;
    j["status"] = "ok";
    j["seed_hex"] = nlohmann::json::binary(seed);
    std::cout << j.dump(2) << "\n";

    return 0;
}