#include "common.h"
#include "CValues.h"
#include "SimEmulator.h"
#include "Milenage.h"

#include <vector>
#include <tuple>
#include <stdexcept>
#include <cstring>


#include "Aka2G.h"


using Block128 = std::array<uint8_t, 16>;
using Block256 = std::array<uint8_t, 32>;


std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 8> >
SimEmulator::authenticate2G(const Block128 &rand,
                            const Block128 &ki) {
    std::array<uint8_t, 4> sres{};
    std::array<uint8_t, 8> kc{};
    Aka2G::runAka(ki.data(), rand.data(), sres.data(), kc.data());
    return {sres, kc};
}

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>

Block256
SimEmulator::deriveSeed2G(const Block128 &rand, const Block128 &ki)
{
    // 1️⃣ Run 2G AKA to obtain SRES (4 bytes) and Kc (8 bytes)
    auto [sres, kc] = authenticate2G(rand, ki);

    // 2️⃣ Domain-separated labels for salt and info
    constexpr std::string_view salt_label = "SMILE|2G|salt|v1";
    constexpr std::string_view info_label = "SMILE|2G|seed|v1";

    // 3️⃣ Combine SRES||Kc as input keying material (IKM)
    std::vector<uint8_t> ikm;
    ikm.reserve(sres.size() + kc.size());
    ikm.insert(ikm.end(), sres.begin(), sres.end());
    ikm.insert(ikm.end(), kc.begin(), kc.end());

    // 4️⃣ HKDF-Extract: PRK = HMAC-SHA256(salt = salt_label, ikm = SRES||Kc)
    unsigned char prk[32];
    size_t prk_len = sizeof(prk);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
        throw std::runtime_error("deriveSeed2G: EVP_PKEY_CTX_new_id failed (extract)");

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(
            pctx,
            reinterpret_cast<const unsigned char*>(salt_label.data()),
            static_cast<int>(salt_label.size())
        ) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0 ||
        EVP_PKEY_derive(pctx, prk, &prk_len) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("deriveSeed2G: HKDF-Extract failed");
    }
    EVP_PKEY_CTX_free(pctx);

    // 5️⃣ HKDF-Expand: SEED = HKDF-Expand(PRK, info = info_label, L = 32)
    Block256 seed{};
    size_t out_len = seed.size();
    EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ectx)
        throw std::runtime_error("deriveSeed2G: EVP_PKEY_CTX_new_id failed (expand)");

    if (EVP_PKEY_derive_init(ectx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ectx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ectx, prk, prk_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ectx,
            reinterpret_cast<const unsigned char*>(info_label.data()),
            static_cast<int>(info_label.size())
        ) <= 0 ||
        EVP_PKEY_derive(ectx, seed.data(), &out_len) <= 0 ||
        out_len != seed.size())
    {
        EVP_PKEY_CTX_free(ectx);
        throw std::runtime_error("deriveSeed2G: HKDF-Expand failed");
    }

    EVP_PKEY_CTX_free(ectx);
    return seed;
}




Block256 SimEmulator::deriveSeed3G(const Block128& rand,
                                   const Block128& autn,
                                   const Block128& k,
                                   const Block128& opc,
                                   const std::array<uint8_t, 2>& amf)
{
    auto [res, ck, ik, ak] = authenticate3G(rand, autn, k, opc, amf);

    constexpr std::string_view salt_label = "SMILE|3G|salt|v1";
    constexpr std::string_view info_label = "SMILE|3G|seed|v1";

    std::vector<uint8_t> ikm;
    ikm.reserve(ck.size() + ik.size());
    ikm.insert(ikm.end(), ck.begin(), ck.end());
    ikm.insert(ikm.end(), ik.begin(), ik.end());

    std::vector<uint8_t> ctx;
    ctx.insert(ctx.end(), rand.begin(), rand.end());
    ctx.insert(ctx.end(), autn.begin(), autn.end());
    ctx.insert(ctx.end(), salt_label.begin(), salt_label.end());

    unsigned char salt_hash[EVP_MAX_MD_SIZE];
    unsigned int salt_len = 0;
    if (!EVP_Digest(ctx.data(), ctx.size(), salt_hash, &salt_len, EVP_sha256(), nullptr))
        throw std::runtime_error("deriveSeed3G: context hash failed");

    unsigned char prk[32];
    size_t prk_len = sizeof(prk);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw std::runtime_error("deriveSeed3G: HKDF context creation failed");

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt_hash, salt_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0 ||
        EVP_PKEY_derive(pctx, prk, &prk_len) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("deriveSeed3G: HKDF-Extract failed");
    }
    EVP_PKEY_CTX_free(pctx);

    Block256 seed{};
    size_t out_len = seed.size();
    EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ectx) throw std::runtime_error("deriveSeed3G: HKDF context creation failed (expand)");

    if (EVP_PKEY_derive_init(ectx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ectx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ectx, prk, prk_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ectx,
            reinterpret_cast<const unsigned char*>(info_label.data()),
            static_cast<int>(info_label.size())) <= 0 ||
        EVP_PKEY_derive(ectx, seed.data(), &out_len) <= 0 ||
        out_len != seed.size())
    {
        EVP_PKEY_CTX_free(ectx);
        throw std::runtime_error("deriveSeed3G: HKDF-Expand failed");
    }

    EVP_PKEY_CTX_free(ectx);
    return seed;
}



std::tuple<std::array<uint8_t, 8>, std::array<uint8_t, 16>,
    std::array<uint8_t, 16>, std::array<uint8_t, 6> >
SimEmulator::authenticate3G(const Block128 &rand,
                            const Block128 &autn,
                            const Block128 &k,
                            const Block128 &opc,
                            const std::array<uint8_t, 2> &amf) {
    // Inputs are fixed-size arrays; sizes are guaranteed at compile time.
    const Block128 &RAND = rand;
    const Block128 &K = k;
    const Block128 &OPc = opc;
    Block128 AMF{};
    std::copy(amf.begin(), amf.end(), AMF.begin());

    // Split AUTN fields: SQN ⊕ AK (6), AMF (2), MAC-A (8)
    std::array<uint8_t, 6> sqn_xor_ak{};
    std::array<uint8_t, 8> mac_a_received{};
    std::memcpy(sqn_xor_ak.data(), autn.data(), 6);
    std::memcpy(mac_a_received.data(), autn.data() + 8, 8);

    // --- Step 1: Derive RES, CK, IK, AK from RAND ---
    std::array<uint8_t, 8> RES{};
    Block128 CK{}, IK{};
    std::array<uint8_t, 6> AK{}, AKstar{};
    f2345(K, RAND, OPc, RES, CK, IK, AK, AKstar);

    // --- Step 2: Recover SQN = (SQN⊕AK)⊕AK ---
    Block128 SQN{};
    for (int i = 0; i < 6; ++i)
        SQN[i] = sqn_xor_ak[i] ^ AK[i];

    // --- Step 3: Compute expected MAC-A using f1() ---
    std::array<uint8_t, 8> MAC_A{}, MAC_S{};
    f1(K, RAND, SQN, AMF, OPc, MAC_A, MAC_S);

    if (std::memcmp(MAC_A.data(), mac_a_received.data(), 8) != 0)
        throw std::runtime_error("3G authentication failed: MAC mismatch");

    // --- Step 4: Return success with (RES, CK, IK, AK) ---
    return {RES, CK, IK, AK};
}


std::pair<std::array<uint8_t, 8>, Block256>
SimEmulator::authenticate4G(const Block128 &rand,
                            const Block128 &autn,
                            const Block128 &k,
                            const Block128 &opc,
                            const std::array<uint8_t, 2> &amf,
                            const std::string &snn) {
    // Step 1: Perform 3G AKA
    auto [res, ck, ik, ak] = authenticate3G(rand, autn, k, opc, amf);

    // Step 2: Build KDF key = CK || IK
    std::vector<uint8_t> kdf_key;
    kdf_key.reserve(32);
    kdf_key.insert(kdf_key.end(), ck.begin(), ck.end());
    kdf_key.insert(kdf_key.end(), ik.begin(), ik.end());

    // Step 3: Construct input string S for KDF (3GPP TS 33.401 §A.2.1)
    // FC = 0x10 for K_ASME derivation
    std::vector<uint8_t> s;
    s.push_back(0x10);

    // Parameter 0: SNN
    s.insert(s.end(), snn.begin(), snn.end());
    const uint16_t L0 = static_cast<uint16_t>(snn.size());
    s.push_back(static_cast<uint8_t>(L0 >> 8));
    s.push_back(static_cast<uint8_t>(L0 & 0xFF));

    // Parameter 1: SQN ⊕ AK (extracted from AUTN)
    std::array<uint8_t, 6> sqn_xor_ak{};
    std::memcpy(sqn_xor_ak.data(), autn.data(), 6);
    const uint16_t L1 = static_cast<uint16_t>(sqn_xor_ak.size());
    s.insert(s.end(), sqn_xor_ak.begin(), sqn_xor_ak.end());
    s.push_back(static_cast<uint8_t>(L1 >> 8));
    s.push_back(static_cast<uint8_t>(L1 & 0xFF));

    // Step 4: HMAC-SHA-256 key derivation
    Block256 k_asme{};
    unsigned int k_asme_len = 0;

    if (!HMAC(EVP_sha256(), kdf_key.data(), static_cast<int>(kdf_key.size()),
              s.data(), s.size(), k_asme.data(), &k_asme_len))
        throw std::runtime_error("HMAC computation failed");

    if (k_asme_len != 32)
        throw std::runtime_error("K_ASME length mismatch");

    // Optional: cleanse sensitive memory
    // OPENSSL_cleanse(kdf_key.data(), kdf_key.size());

    return {res, k_asme};
}

std::pair<std::array<uint8_t, 16>, Block256>
SimEmulator::authenticate5G(const Block128 &rand,
                            const Block128 &autn,
                            const Block128 &k,
                            const Block128 &opc,
                            const std::array<uint8_t, 2> &amf,
                            const std::string &snn) {
    // Step 1: Perform 3G AKA → RES, CK, IK, AK
    auto [res, ck, ik, ak] = authenticate3G(rand, autn, k, opc, amf);

    // Base key: CK || IK
    std::vector<uint8_t> ck_ik;
    ck_ik.reserve(32);
    ck_ik.insert(ck_ik.end(), ck.begin(), ck.end());
    ck_ik.insert(ck_ik.end(), ik.begin(), ik.end());

    // --- Helper lambda to append a 16-bit big-endian length ---
    auto append_len = [](std::vector<uint8_t> &v, size_t len) {
        v.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        v.push_back(static_cast<uint8_t>(len & 0xFF));
    };

    // Extract SQN⊕AK from AUTN (first 6 bytes)
    std::array<uint8_t, 6> sqn_xor_ak{};
    std::memcpy(sqn_xor_ak.data(), autn.data(), 6);

    // ──────────────────────────────
    // Step 2 – Derive K_AUSF (Annex A.4)
    // S = FC || SNN || L0 || (SQN⊕AK) || L1
    std::vector<uint8_t> s_kausf;
    s_kausf.push_back(0x6A); // FC
    s_kausf.insert(s_kausf.end(), snn.begin(), snn.end());
    append_len(s_kausf, snn.size());
    s_kausf.insert(s_kausf.end(), sqn_xor_ak.begin(), sqn_xor_ak.end());
    append_len(s_kausf, sqn_xor_ak.size());

    Block256 k_ausf{};
    unsigned int k_ausf_len = 0;
    if (!HMAC(EVP_sha256(), ck_ik.data(), static_cast<int>(ck_ik.size()),
              s_kausf.data(), s_kausf.size(), k_ausf.data(), &k_ausf_len) ||
        k_ausf_len != 32)
        throw std::runtime_error("Failed to derive K_AUSF");

    // ──────────────────────────────
    // Step 3 – Derive K_SEAF (Annex A.5)
    // S = FC || SNN || L0
    std::vector<uint8_t> s_kseaf;
    s_kseaf.push_back(0x6B);
    s_kseaf.insert(s_kseaf.end(), snn.begin(), snn.end());
    append_len(s_kseaf, snn.size());

    Block256 k_seaf{};
    unsigned int k_seaf_len = 0;
    if (!HMAC(EVP_sha256(), k_ausf.data(), static_cast<int>(k_ausf.size()),
              s_kseaf.data(), s_kseaf.size(), k_seaf.data(), &k_seaf_len) ||
        k_seaf_len != 32)
        throw std::runtime_error("Failed to derive K_SEAF");

    // ──────────────────────────────
    // Step 4 – Derive RES* (Annex A.6)
    // S = FC || SNN || L0 || RAND || L1 || RES || L2
    std::vector<uint8_t> s_res_star;
    s_res_star.push_back(0x6D);
    s_res_star.insert(s_res_star.end(), snn.begin(), snn.end());
    append_len(s_res_star, snn.size());
    s_res_star.insert(s_res_star.end(), rand.begin(), rand.end());
    append_len(s_res_star, rand.size());
    s_res_star.insert(s_res_star.end(), res.begin(), res.end());
    append_len(s_res_star, res.size());

    std::array<uint8_t, 32> res_star_full{};
    unsigned int res_star_len = 0;
    if (!HMAC(EVP_sha256(), ck_ik.data(), static_cast<int>(ck_ik.size()),
              s_res_star.data(), s_res_star.size(),
              res_star_full.data(), &res_star_len) ||
        res_star_len != 32)
        throw std::runtime_error("Failed to derive RES*");

    // Rightmost 16 bytes = RES*
    std::array<uint8_t, 16> res_star{};
    std::memcpy(res_star.data(), res_star_full.data() + 16, 16);

    return {res_star, k_seaf};
}


Block256 SimEmulator::deriveSeed4G(const Block128& rand,
                                   const Block128& autn,
                                   const Block128& k,
                                   const Block128& opc,
                                   const std::array<uint8_t, 2>& amf,
                                   const std::string& snn)
{
    auto [res, k_asme] = authenticate4G(rand, autn, k, opc, amf, snn);

    constexpr std::string_view salt_label = "SMILE|4G|salt|v1";
    constexpr std::string_view info_label = "SMILE|4G|seed|v1";

    std::string ctx = snn + "|" + std::string(salt_label);
    unsigned char ctx_hash[EVP_MAX_MD_SIZE];
    unsigned int ctx_hash_len = 0;
    if (!EVP_Digest(ctx.data(), ctx.size(), ctx_hash, &ctx_hash_len, EVP_sha256(), nullptr))
        throw std::runtime_error("deriveSeed4G: context hash failed");

    unsigned char prk[32];
    size_t prk_len = sizeof(prk);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
        throw std::runtime_error("deriveSeed4G: EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, ctx_hash, ctx_hash_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, k_asme.data(), k_asme.size()) <= 0 ||
        EVP_PKEY_derive(pctx, prk, &prk_len) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("deriveSeed4G: HKDF-Extract failed");
    }
    EVP_PKEY_CTX_free(pctx);

    Block256 seed{};
    size_t out_len = seed.size();
    EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ectx)
        throw std::runtime_error("deriveSeed4G: EVP_PKEY_CTX_new_id failed (expand)");

    if (EVP_PKEY_derive_init(ectx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ectx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ectx, prk, prk_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ectx,
            reinterpret_cast<const unsigned char*>(info_label.data()),
            static_cast<int>(info_label.size())) <= 0 ||
        EVP_PKEY_derive(ectx, seed.data(), &out_len) <= 0 ||
        out_len != seed.size())
    {
        EVP_PKEY_CTX_free(ectx);
        throw std::runtime_error("deriveSeed4G: HKDF-Expand failed");
    }

    EVP_PKEY_CTX_free(ectx);
    return seed;
}




Block256 SimEmulator::deriveSeed5G(const Block128& rand,
                                   const Block128& autn,
                                   const Block128& k,
                                   const Block128& opc,
                                   const std::array<uint8_t, 2>& amf,
                                   const std::string& snn)
{
    auto [res_star, k_seaf] = authenticate5G(rand, autn, k, opc, amf, snn);

    constexpr std::string_view salt_label = "SMILE|5G|salt|v1";
    constexpr std::string_view info_label = "SMILE|5G|seed|v1";

    std::string ctx = snn + "|" + std::string(salt_label);
    unsigned char ctx_hash[EVP_MAX_MD_SIZE];
    unsigned int ctx_hash_len = 0;
    if (!EVP_Digest(ctx.data(), ctx.size(), ctx_hash, &ctx_hash_len, EVP_sha256(), nullptr))
        throw std::runtime_error("deriveSeed5G: context hash failed");

    unsigned char prk[32];
    size_t prk_len = sizeof(prk);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
        throw std::runtime_error("deriveSeed5G: EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, ctx_hash, ctx_hash_len) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, k_seaf.data(), k_seaf.size()) <= 0 ||
        EVP_PKEY_derive(pctx, prk, &prk_len) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("deriveSeed5G: HKDF-Extract failed");
    }
    EVP_PKEY_CTX_free(pctx);

    Block256 seed{};
    size_t out_len = seed.size();
    EVP_PKEY_CTX* ectx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ectx)
        throw std::runtime_error("deriveSeed5G: EVP_PKEY_CTX_new_id failed (expand)");

    if (EVP_PKEY_derive_init(ectx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ectx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ectx, prk, prk_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(
            ectx,
            reinterpret_cast<const unsigned char*>(info_label.data()),
            static_cast<int>(info_label.size())) <= 0 ||
        EVP_PKEY_derive(ectx, seed.data(), &out_len) <= 0 ||
        out_len != seed.size())
    {
        EVP_PKEY_CTX_free(ectx);
        throw std::runtime_error("deriveSeed5G: HKDF-Expand failed");
    }

    EVP_PKEY_CTX_free(ectx);
    return seed;
}



