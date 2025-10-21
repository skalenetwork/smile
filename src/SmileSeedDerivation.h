#pragma once


#include "Milenage.h"

class SmileSeedDerivation {


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
    static array256 deriveBIP32MasterSeed2G(const array16 &rand, const array16 &ki);

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
 * @param opc 16-byte operator variant constant OPc. Fixed per operator.
 * @param amf 2-byte AMF used by Milenage f1/f1*. Fixed per operator.
 * @return 32-byte seed (SHA-256 digest) as Block256.
 * @throws std::runtime_error if AKA verification or hashing fails.
 */
    static array256 deriveBIP32MasterSeed3G(const array16 &rand, const array16 &autn,
                                            const array16 &k, const array16 &opc,
                                            const array2 &amf);

    /**
     * @brief Derives a 256-bit seed from 4G EPS-AKA outputs (RES, K_ASME).
     *
     * This function invokes authenticate4G to run 3G AKA and LTE key derivation, obtaining
     * the 8-byte RES and the 32-byte K_ASME. It then computes:
     *   seed = SHA-256( "SMILE|4G|seed|v1" || RES || K_ASME )
     * and returns the 32-byte digest.
     *
     * @param rand 16-byte RAND from the network.
     * @param autn 16-byte AUTN token.
     * @param k 16-byte subscriber key K.
     * @param opc 16-byte operator variant constant OPc. Fixed per operator.
     * @param amf 2-byte AMF. Fixed per operator.
     * @param snn Serving Network Name (string) for 4G KDF. Fixed per operator.
     * @return 32-byte seed (SHA-256 digest) as Block256.
     */
    static array256 deriveBIP32MasterSeed4G(const array16 &rand, const array16 &autn,
                                            const array16 &k, const array16 &opc,
                                            const array2 &amf,
                                            const std::string &snn);

    /**
 * @brief Derives a 256-bit seed from 5G AKA outputs (RES*, K_SEAF).
 *
 * This function invokes authenticate5G to obtain the 16-byte RES* and the 32-byte K_SEAF.
 * It then computes a domain-separated seed using HKDF-SHA256 as follows:
 *   - salt = SHA-256( snn || "|SMILE|5G|v1" )
 *   - PRK = HKDF-Extract(salt, K_SEAF)
 *   - seed = HKDF-Expand(PRK, info = "SMILE|5G|seed|v1", L = 32)
 * The result is returned as a 32-byte Block256.
 *
 * @param rand 16-byte RAND from the network.
 * @param autn 16-byte AUTN token.
 * @param k 16-byte subscriber key K.
 * @param opc 16-byte operator variant constant OPc. Fixed per operator.
 * @param amf 2-byte AMF. Fixed per operator.
 * @param snn Serving Network Name. Fixed per operator.
 * @return 32-byte seed (HKDF-SHA256) as Block256.
 */
    static array256 deriveBIP32MasterSeed5G(const array16 &rand, const array16 &autn,
                                            const array16 &k, const array16 &opc,
                                            const array2 &amf,
                                            const std::string &snn);

private:
    /**
     * @brief Performs 2G (GSM) authentication (A3/A8) using a COMP128-1 implementation.
     *
     * This simulates the GSM SIM-side authentication procedure where the network sends a
     * random challenge RAND and the SIM computes the Signed RESponse (SRES) and the 64-bit
     * ciphering key Kc. The interface and output sizes follow the SIM-ME command "RUN GSM
     * ALGORITHM" specified in 3GPP TS 51.011 (historically GSM 11.11). The specific A3/A8
     * algorithm used by operators is not standardized; this emulator uses COMP128-1 purely
     * for demonstration/testing purposes.
     *
     * References:
     *  - 3GPP TS 51.011: Specification of the Subscriber Identity Module – Mobile Equipment (SIM-ME)
     *    interface (see RUN GSM ALGORITHM command for A3/A8 producing SRES[32] and Kc[64]).
     *  - GSM/3GPP security architecture documents describe the use of SRES and Kc on the air
     *    interface (e.g., 3GPP TS 43.020/TS 44.018 context), but do not fix the A3/A8 algorithm.
     *
     * @param rand A 16-byte (128-bit) random challenge from the network (RAND).
     * @param ki A 16-byte (128-bit) secret key stored on the SIM card (Ki).
     * @return A pair containing the 4-byte SRES and the 8-byte Kc.
     */
    static std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 8> >
    authenticate2G(const array16 &rand, const array16 &ki);


    /**
     * @brief Performs 3G (UMTS) Authentication and Key Agreement (AKA) with Milenage.
     *
     * Implements the subscriber-side AKA procedure defined by 3GPP for UMTS as described in
     * 3GPP TS 33.102 (Security architecture) using the Milenage algorithm set specified in
     * 3GPP TS 35.206 (Specification of the MILENAGE algorithm set: An example algorithm set for the 3GPP
     * authentication and key generation functions) with reference test data in TS 35.207 and
     * general algorithm description in TS 35.205.
     *
     * Inputs are:
     *  - RAND (16 bytes): network random challenge.
     *  - AUTN (16 bytes): authentication token structured as SQN ⊕ AK || AMF || MAC-A
     *    per TS 33.102 and TS 35.206.
     *  - K (16 bytes): subscriber long-term key.
     *  - OPc (16 bytes): operator variant constant OPc = OP ⊕ AES-128_K(OP), precomputed per TS 35.206.
     *  - AMF (2 bytes): Authentication Management Field used by f1/f1*.
     *
     * Processing summary (per TS 33.102/TS 35.206):
     *  1) Compute AK = f5(K, RAND) and recover SQN = (SQN ⊕ AK) ⊕ AK from AUTN.
     *  2) Verify MAC-A in AUTN using f1(K, SQN || AMF, RAND). If the MAC check fails, authentication
     *     must be rejected.
     *  3) Optionally check SQN freshness per TS 33.102 (range/window check). If the sequence check fails,
     *     authentication must be rejected or resynchronization is required (not handled here).
     *  4) On success, derive:
     *       - RES (8 bytes) = f2(K, RAND)
     *       - CK  (16 bytes) = f3(K, RAND)
     *       - IK  (16 bytes) = f4(K, RAND)
     *       - AK  (6 bytes)  = f5(K, RAND)
     *
     * Return value is a tuple (RES[8], CK[16], IK[16], AK[6]). The function throws if AUTN verification
     * fails (e.g., MAC-A mismatch or sequence check failure).
     *
     * @param rand 16-byte RAND (random challenge).
     * @param autn 16-byte AUTN = SQN ⊕ AK || AMF || MAC-A.
     * @param k 16-byte subscriber key K.
     * @param opc 16-byte operator variant constant OPc.
     * @param amf 2-byte AMF for f1/f1*.
     * @return Tuple {RES, CK, IK, AK} with sizes {8, 16, 16, 6} bytes respectively.
     * @see 3GPP TS 33.102; 3GPP TS 35.205/35.206/35.207.
     */
    static std::tuple<std::array<uint8_t, 8>, std::array<uint8_t, 16>, std::array<uint8_t, 16>, std::array<uint8_t, 6> >
    authenticate3G(const array16 &rand, const array16 &autn,
                   const array16 &k, const array16 &opc, const std::array<uint8_t, 2> &amf);


    /**
     * @brief Performs 4G (LTE) Evolved Packet System AKA (EPS‑AKA) and derives K_ASME.
     *
     * Standards followed (normative references):
     * - 3GPP TS 35.206 (and TS 35.205/35.208): MILENAGE algorithms f1–f5/f1*–f5* used for 3G AKA
     *   to compute RES, CK, IK, AK and to verify AUTN (MAC‑A), given K, OPc, RAND, AMF, SQN.
     * - 3GPP TS 33.401, Annex A (Key derivation functions for EPS): Derivation of K_ASME from
     *   CK||IK using the EPS AKA KDF with function code FC = 0x10 and input parameters including
     *   the Serving Network Name (SN id/SNN) and the concealed sequence number (SQN ⊕ AK).
     *   See TS 33.401 Annex A.2/A.4 for the precise string/length encoding of inputs.
     * - 3GPP TS 23.003 (naming): Definition/formatting of the Serving Network Name for EPS
     *   (e.g., epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org).
     *
     * What this function does:
     * 1) Runs 3G AKA (Milenage) to verify AUTN and obtain RES (64‑bit), CK (128‑bit), IK (128‑bit).
     * 2) Applies the EPS AKA KDF per TS 33.401 Annex A to (CK||IK) with SNN and SQN⊕AK to derive
     *    K_ASME (256‑bit). The function returns RES and K_ASME for subsequent LTE procedures.
     *
     * @param rand A 16-byte random challenge RAND.
     * @param autn A 16-byte authentication token AUTN from the network.
     * @param k A 16-byte subscriber key K.
     * @param opc A 16-byte operator variant constant OPc.
     * @param amf A 2-byte Authentication Management Field (AMF).
     * @param snn The Serving Network Name (SNN/SN id) used by the EPS KDF per TS 33.401.
     * @return A pair containing the 8-byte RES and the 32-byte K_ASME.
     */
    static std::pair<std::array<uint8_t, 8>, array256>
    authenticate4G(const array16 &rand, const array16 &autn,
                   const array16 &k, const array16 &opc, const std::array<uint8_t, 2> &amf,
                   const std::string &snn);


    /**
     * @brief Performs 5G authentication and key agreement (5G-AKA) with cited standards.
     *
     * Standards followed (informative):
     * - 3GPP TS 33.501, Annex A (Release 15+):
     *   - A.4: Derivation of K_AUSF from CK||IK, SNN and (SQN⊕AK) using HMAC-SHA-256 (FC = 0x6A).
     *   - A.5: Derivation of K_SEAF from K_AUSF and SNN using HMAC-SHA-256 (FC = 0x6B).
     *   - A.6: Derivation of RES* from CK||IK, SNN, RAND and RES using HMAC-SHA-256 (FC = 0x6D),
     *          with RES* defined as the rightmost 16 bytes of the 32-byte output.
     * - 3G/UMTS AKA primitives are per 3GPP TS 35.206/35.208 (Milenage): RES, CK, IK, AK.
     *   This function reuses authenticate3G to obtain RES/CK/IK/AK prior to 5G KDF steps.
     * - Serving Network Name (SNN) definition/encoding as used by 5G AKA follows 3GPP TS 33.501
     *   and is typically derived from NAS procedures in TS 24.501.
     *
     * What this function does:
     * 1) Runs 3G AKA (Milenage) to get RES, CK, IK, AK.
     * 2) Builds the 5G KDF input strings S according to Annex A with function codes and
     *    16-bit big-endian length fields appended after each parameter.
     * 3) Derives K_AUSF = HMAC-SHA-256(CK||IK, 0x6A || SNN || L0 || (SQN⊕AK) || L1).
     * 4) Derives K_SEAF = HMAC-SHA-256(K_AUSF, 0x6B || SNN || L0).
     * 5) Derives RES*  = HMAC-SHA-256(CK||IK, 0x6D || SNN || L0 || RAND || L1 || RES || L2),
     *    then returns the rightmost 16 bytes as RES*.
     *
     * Notes:
     * - HMAC-SHA-256 is the MAC used in 33.501 Annex A for these KDFs.
     * - Length fields (L0, L1, L2, …) are 16-bit big-endian encodings of the immediately
     *   preceding parameter lengths, per Annex A conventions.
     * - This routine is a developer-friendly emulator and is not a conformance test tool.
     *
     * @param rand 16-byte network RAND (aka RAND).
     * @param autn 16-byte AUTN (contains SQN⊕AK in its first 6 bytes).
     * @param k 16-byte subscriber key K used by Milenage.
     * @param opc 16-byte OPc (operator variant constant) for Milenage.
     * @param amf 2-byte AMF for Milenage.
     * @param snn Serving Network Name used as KDF context (per 3GPP TS 33.501 Annex A).
     * @return Pair of {RES* (16 bytes), K_SEAF (32 bytes)}.
     */
    static std::pair<std::array<uint8_t, 16>, array256>
    authenticate5G(const array16 &rand, const array16 &autn,
                   const array16 &k, const array16 &opc, const std::array<uint8_t, 2> &amf,
                   const std::string &snn);


    /**
     * @brief HKDF-SHA256 per RFC 5869: Extract-and-Expand to 32 bytes.
     *
     * What this function does:
     * - Implements the two-stage HKDF construction defined in RFC 5869 using SHA-256:
     *   1) HKDF-Extract(salt, IKM) -> PRK (a 32-byte pseudorandom key)
     *   2) HKDF-Expand(PRK, info, L=32) -> OKM (output keying material)
     * - Returns OKM as a 32-byte Block256.
     *
     * Parameter roles:
     * - ikm: Input Keying Material (arbitrary-length secret bytes). In 5G code paths this is
     *        typically a derived key such as K_SEAF. It must have sufficient entropy; HKDF
     *        does not add entropy on its own.
     * - salt: Optional non-secret randomizer for Extract. If empty, RFC 5869 treats it as an
     *         all-zero string of length HashLen (32 for SHA-256). Providing a salt is
     *         RECOMMENDED for better robustness; the caller controls this input.
     * - info: Optional context string for Expand that provides domain separation (e.g.,
     *         protocol/version/label). Different info values yield independent OKM even with
     *         the same PRK. This repository uses labels like "SMILE|5G|seed|v1" to avoid
     *         cross-protocol collisions.
     *
     * How it is implemented (OpenSSL EVP_PKEY HKDF API):
     * - Extract stage:
     *   * Create an HKDF context (EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF)).
     *   * Initialize for derivation and set the hash to SHA-256.
     *   * If salt is non-empty, set it with EVP_PKEY_CTX_set1_hkdf_salt; otherwise OpenSSL
     *     behaves as if a zero salt is used (consistent with RFC 5869 guidance).
     *   * Provide IKM via EVP_PKEY_CTX_set1_hkdf_key.
     *   * Call EVP_PKEY_derive to compute PRK and validate the expected output length (32).
     * - Expand stage:
     *   * Create a new HKDF context and set SHA-256 again.
     *   * Feed the PRK as the HKDF key (per OpenSSL's API design).
     *   * Add the info string with EVP_PKEY_CTX_add1_hkdf_info.
     *   * Derive exactly 32 bytes of OKM into the output Block256.
     * - On success, securely cleanse the temporary PRK buffer with OPENSSL_cleanse.
     *
     * Error handling and safety:
     * - Every OpenSSL call is checked; any failure throws std::runtime_error with a short label.
     * - The temporary PRK (sensitive material) is cleared from memory before returning.
     * - No global state is used; the function is deterministic for given (ikm, salt, info).
     *
     * Cryptographic notes (RFC 5869):
     * - If you lack a suitable salt, using an all-zero salt is acceptable but not ideal; when
     *   possible, use a random or protocol-specific salt to bind the PRK to your application.
     * - Use distinct info labels for different outputs (keys vs. seeds) to prevent key/seed reuse.
     * - The output length here is fixed to 32 bytes (HashLen). If you need a different length,
     *   you would adjust L accordingly during the Expand phase.
     */
    array256 static rfc5869Hkdf(const std::vector<uint8_t> &ikm,
                                std::string_view salt,
                                std::string_view info);
};
