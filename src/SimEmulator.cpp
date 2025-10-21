#include "common.h"
#include "comp128_table.h"
#include "SimEmulator.h"



// Permutation helper (bit shuffle)
static void permute(uint8_t* x) {
    uint8_t tmp[32];
    for (int i = 0; i < 32; ++i) {
        tmp[i] = x[(i*17) & 31];
    }
    memcpy(x, tmp, 32);
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
SimEmulator::authenticate2G(const std::vector<uint8_t>& rand,
                            const std::vector<uint8_t>& ki)
{
    if (rand.size() != 16 || ki.size() != 16)
        throw std::runtime_error("RAND and Ki must be 16 bytes each.");

    // Step 1: concatenate RAND and Ki
    uint8_t x[32];
    memcpy(x, rand.data(), 16);
    memcpy(x + 16, ki.data(), 16);

    // Step 2: 8 rounds of mixing
    for (int round = 0; round < 8; ++round) {
        for (int i = 0; i < 16; ++i) {
            uint8_t idx1 = x[2*i];
            uint8_t idx2 = x[2*i + 1];
            x[i] = comp_128_tab[idx1 ^ (round*16)] ^ comp_128_tab[256 + idx2];
        }
        permute(x);
    }

    // Step 3: Derive 12-byte output
    uint8_t out[12];
    memcpy(out, x, 12);

    // Step 4: SRES = first 4 bytes
    std::vector<uint8_t> sres(out, out + 4);

    // Step 5: Kc = next 8 bytes (mask out 10th bit of each byte)
    std::vector<uint8_t> kc(out + 4, out + 12);
    kc[7] &= 0xF0; // per COMP128-1 spec (forces last 10 bits to 0)

    return {sres, kc};
}