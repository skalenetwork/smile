#pragma once
#include <vector>
#include <string>
#include <optional>

struct AKAResult {
    std::vector<uint8_t> res;
    std::vector<uint8_t> ck;
    std::vector<uint8_t> ik;
};

class SIM {
public:
    SIM();
    bool connect();
    std::optional<AKAResult> authenticate(const std::vector<uint8_t>& rand,
                                          const std::vector<uint8_t>& autn);
    void disconnect();

private:
    void* cardCtx_;
    void* cardHandle_;
};