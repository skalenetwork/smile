#pragma once


#include "Milenage.h"

class SimEmulator {
public:
    // 2G Authentication (COMP128-1)
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    authenticate2G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& ki);

    // 3G Authentication (Milenage)
    static std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
    authenticate3G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& autn,
                   const std::vector<uint8_t>& k, const std::vector<uint8_t>& opc, const std::vector<uint8_t>& amf);

    // 4G Authentication (EPS-AKA)
    static std::pair<std::vector<uint8_t>, Block256>
    authenticate4G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& autn,
                   const std::vector<uint8_t>& k, const std::vector<uint8_t>& opc, const std::vector<uint8_t>& amf,
                   const std::string& snn);

    // 5G Authentication (5G-AKA)
    static std::pair<std::vector<uint8_t>, Block256>
    authenticate5G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& autn,
                   const std::vector<uint8_t>& k, const std::vector<uint8_t>& opc, const std::vector<uint8_t>& amf,
                   const std::string& snn);
};