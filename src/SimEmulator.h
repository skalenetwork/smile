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
    static std::pair<std::array<uint8_t,4>, std::array<uint8_t,8>>
    authenticate2G(const Block128& rand, const Block128& ki);

    /**
     * @brief Derives a 256-bit seed from 2G authentication outputs.
     *
     * This function performs a 2G authentication and then securely hashes the resulting
     * SRES and Kc values using SHA-256 to produce a 256-bit seed.
     *
     * @param rand A 16-byte (128-bit) random challenge from the network.
     * @param ki A 16-byte (128-bit) secret key stored on the SIM card.
     * @return A 256-bit (32-byte) seed as a std::array.
     */
    static Block256 deriveSeed2G(const Block128& rand, const Block128& ki);

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
    static std::tuple<std::array<uint8_t,8>, std::array<uint8_t,16>, std::array<uint8_t,16>, std::array<uint8_t,6>>
    authenticate3G(const Block128& rand, const Block128& autn,
                   const Block128& k, const Block128& opc, const std::array<uint8_t,2>& amf);

    /**
     * @brief Derives a 256-bit seed from 3G AKA outputs (RES, CK, IK).
     *
     * How it works:
     * 1) Invokes authenticate3G(rand, autn, k, opc, amf). On success this verifies AUTN
     *    (MAC-A check) and returns the tuple (RES[8], CK[16], IK[16], AK[6]).
     * 2) Builds a domain-separated message M = prefix || RES || CK || IK where:
     *      - prefix = ASCII string "SMILE|3G|seed|v1" used to prevent cross-protocol
     *        or cross-version collisions (i.e., the same values used elsewhere will not
     *        accidentally hash to the same seed).
     *      - AK is intentionally excluded because it masks SQN and is not used as keying material.
     * 3) Computes seed = SHA-256(M) and returns the 32-byte digest as Block256.
     *
     * Properties and notes:
     * - Deterministic: identical inputs yield the same seed; any input change flips the seed.
     * - authenticate3G throws if AUTN verification fails; this function propagates that error.
     * - No state is stored; inputs are not modified.
     *
     * @param rand 16-byte random challenge RAND from the network.
     * @param autn 16-byte AUTN token containing SQN⊕AK || AMF || MAC-A.
     * @param k 16-byte subscriber key K.
     * @param opc 16-byte operator variant constant OPc.
     * @param amf 2-byte AMF used by Milenage f1/f1*.
     * @return 32-byte seed (SHA-256 digest) as Block256.
     * @throws std::runtime_error if AKA verification or hashing fails.
     */
    static Block256 deriveSeed3G(const Block128& rand, const Block128& autn,
                                 const Block128& k, const Block128& opc,
                                 const std::array<uint8_t,2>& amf);

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
    static std::pair<std::array<uint8_t,8>, Block256>
    authenticate4G(const Block128& rand, const Block128& autn,
                   const Block128& k, const Block128& opc, const std::array<uint8_t,2>& amf,
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
    static std::pair<std::array<uint8_t,16>, Block256>
    authenticate5G(const Block128& rand, const Block128& autn,
                   const Block128& k, const Block128& opc, const std::array<uint8_t,2>& amf,
                   const std::string& snn);
};