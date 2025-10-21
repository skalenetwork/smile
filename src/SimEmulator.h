#pragma once


#include "Milenage.h"

class SimEmulator {
public:
    /**
     * @brief Performs 2G (GSM) authentication using the COMP128-1 algorithm.
     *
     * This function simulates the authentication process of a 2G SIM card. It takes a random
     * challenge (RAND) from the network and the secret key (Ki) from the SIM, and computes
     * the Signed Response (SRES) and the Ciphering Key (Kc).
     *
     * @param rand A 16-byte (128-bit) random challenge from the network.
     * @param ki A 16-byte (128-bit) secret key stored on the SIM card.
     * @return A pair containing the 4-byte SRES and the 8-byte Kc.
     */
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    authenticate2G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& ki);

    /**
     * @brief Performs 3G (UMTS) authentication using the Milenage algorithm.
     *
     * This function simulates the 3G authentication and key agreement (AKA) procedure. It takes
     * a random challenge (RAND), an Authentication Token (AUTN), the secret key (K), the Operator
     * Variant Algorithm Configuration Field (OPc), and the Authentication Management Field (AMF).
     * It verifies the AUTN and, if successful, computes the Response (RES), Cipher Key (CK),
     * Integrity Key (IK), and Anonymity Key (AK).
     *
     * @param rand A 16-byte random challenge.
     * @param autn A 16-byte authentication token from the network.
     * @param k A 16-byte secret key.
     * @param opc A 16-byte operator variant configuration field.
     * @param amf A 2-byte authentication management field.
     * @return A tuple containing the RES, CK, IK, and AK.
     */
    static std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
    authenticate3G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& autn,
                   const std::vector<uint8_t>& k, const std::vector<uint8_t>& opc, const std::vector<uint8_t>& amf);

    /**
     * @brief Performs 4G (LTE) Evolved Packet System (EPS) authentication (EPS-AKA).
     *
     * This function builds on 3G AKA to perform 4G authentication. It takes the same parameters
     * as 3G AKA, plus the Serving Network Name (SNN). It first runs the 3G authentication
     * process to generate RES, CK, and IK. It then uses CK and IK to derive the K_ASME
     * (Key for Access Security Management Entity) as specified in 3GPP TS 33.401.
     *
     * @param rand A 16-byte random challenge.
     * @param autn A 16-byte authentication token from the network.
     * @param k A 16-byte secret key.
     * @param opc A 16-byte operator variant configuration field.
     * @param amf A 2-byte authentication management field.
     * @param snn The Serving Network Name, used in the key derivation process.
     * @return A pair containing the 8-byte RES and the 32-byte K_ASME.
     */
    static std::pair<std::vector<uint8_t>, Block256>
    authenticate4G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& autn,
                   const std::vector<uint8_t>& k, const std::vector<uint8_t>& opc, const std::vector<uint8_t>& amf,
                   const std::string& snn);

    /**
     * @brief Performs 5G authentication and key agreement (5G-AKA).
     *
     * This function simulates the 5G AKA procedure as specified in 3GPP TS 33.501. It starts
     * by performing a 3G AKA authentication to obtain RES, CK, and IK. It then uses these
     * keys and the Serving Network Name (SNN) to derive the 5G keys: K_AUSF (Key for the
     * Authentication Server Function) and K_SEAF (Key for the Security Anchor Function).
     * Finally, it computes the 5G response, RES*.
     *
     * @param rand A 16-byte random challenge.
     * @param autn A 16-byte authentication token from the network.
     * @param k A 16-byte secret key.
     * @param opc A 16-byte operator variant configuration field.
     * @param amf A 2-byte authentication management field.
     * @param snn The Serving Network Name, used in the key derivation process.
     * @return A pair containing the 16-byte RES* and the 32-byte K_SEAF.
     */
    static std::pair<std::vector<uint8_t>, Block256>
    authenticate5G(const std::vector<uint8_t>& rand, const std::vector<uint8_t>& autn,
                   const std::vector<uint8_t>& k, const std::vector<uint8_t>& opc, const std::vector<uint8_t>& amf,
                   const std::string& snn);
};