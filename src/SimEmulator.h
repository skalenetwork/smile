#pragma once



class SimEmulator {
public:
    // 2G Authentication (COMP128-1)
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    authenticate2G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& ki);
};