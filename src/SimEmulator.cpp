#include "common.h"
#include "CValues.h"
#include "SimEmulator.h"
#include "Milenage.h"

#include <vector>
#include <tuple>
#include <stdexcept>
#include <cstring>


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


std::tuple<std::vector<uint8_t>, std::vector<uint8_t>,
           std::vector<uint8_t>, std::vector<uint8_t>>
SimEmulator::authenticate3G(const std::vector<uint8_t>& rand,
                            const std::vector<uint8_t>& autn,
                            const std::vector<uint8_t>& k,
                            const std::vector<uint8_t>& opc,
                            const std::vector<uint8_t>& amf)
{

    if (rand.size() != 16 || autn.size() != 16 ||
        k.size() != 16 || opc.size() != 16 || amf.size() != 2)
        throw std::invalid_argument("authenticate3G: invalid input sizes");

    Block128 RAND, K, OPc, AMF{};
    std::copy(rand.begin(), rand.end(), RAND.begin());
    std::copy(k.begin(), k.end(), K.begin());
    std::copy(opc.begin(), opc.end(), OPc.begin());
    std::copy(amf.begin(), amf.end(), AMF.begin());

    // Split AUTN fields: SQN ⊕ AK (6), AMF (2), MAC-A (8)
    std::array<uint8_t,6> sqn_xor_ak{};
    std::array<uint8_t,8> mac_a_received{};
    std::memcpy(sqn_xor_ak.data(), autn.data(), 6);
    std::memcpy(mac_a_received.data(), autn.data() + 8, 8);

    // --- Step 1: Derive RES, CK, IK, AK from RAND ---
    std::array<uint8_t,8> RES{};
    Block128 CK{}, IK{};
    std::array<uint8_t,6> AK{}, AKstar{};
    f2345(K, RAND, OPc, RES, CK, IK, AK, AKstar);

    // --- Step 2: Recover SQN = (SQN⊕AK)⊕AK ---
    Block128 SQN{};
    for (int i = 0; i < 6; ++i)
        SQN[i] = sqn_xor_ak[i] ^ AK[i];

    // --- Step 3: Compute expected MAC-A using f1() ---
    std::array<uint8_t,8> MAC_A{}, MAC_S{};
    f1(K, RAND, SQN, AMF, OPc, MAC_A, MAC_S);

    if (std::memcmp(MAC_A.data(), mac_a_received.data(), 8) != 0)
        throw std::runtime_error("3G authentication failed: MAC mismatch");

    // --- Step 4: Return success with (RES, CK, IK, AK) ---
    return {
        std::vector<uint8_t>(RES.begin(), RES.end()),
        std::vector<uint8_t>(CK.begin(),  CK.end()),
        std::vector<uint8_t>(IK.begin(),  IK.end()),
        std::vector<uint8_t>(AK.begin(),  AK.end())
    };
}
