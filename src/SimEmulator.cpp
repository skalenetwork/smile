#include "common.h"
#include "CValues.h"
#include "SimEmulator.h"


#include "Aka2G.h"



std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
SimEmulator::authenticate2G(const std::vector<uint8_t>& rand,
                            const std::vector<uint8_t>& ki)
{
    std::vector<uint8_t> sres(4);
    std::vector<uint8_t> kc(8);
    Aka2G::runAka(ki.data(), rand.data(), sres.data(), kc.data());
    return {sres, kc};
}