#pragma once
#include <vector>
#include <string>

class SmileWallet {
public:
    static void derive_master(const std::vector<uint8_t>& seed);
};