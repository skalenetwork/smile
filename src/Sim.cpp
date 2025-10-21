#include "common.h"
#include "Sim.h"
#include <iostream>

SIM::SIM() : cardCtx_(nullptr), cardHandle_(nullptr) {}

bool SIM::connect() {
    std::cout << "[SMILE] Connecting to SIM via PC/SC...\n";
    // TODO: Use SCardEstablishContext + SCardConnect
    return true;
}

std::optional<AKAResult> SIM::authenticate(const std::vector<uint8_t>& rand,
                                                const std::vector<uint8_t>& autn) {
    std::cout << "[SMILE] Performing AUTHENTICATE(RAND, AUTN)...\n";

    // Stub — replace with APDU exchange via SCardTransmit
    AKAResult result;
    result.res = {0x01, 0x02, 0x03, 0x04};
    result.ck  = std::vector<uint8_t>(16, 0xAA);
    result.ik  = std::vector<uint8_t>(16, 0xBB);
    return result;
}

void SIM::disconnect() {
    std::cout << "[SMILE] Disconnecting.\n";
    // TODO: SCardDisconnect + SCardReleaseContext
}