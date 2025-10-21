<p align="center">
  <img src="smile.png" alt="SMILE" width="25%" />
</p>





# 😄 SMILE — SIM Mobile Identity for Ledgers

**Turn your SIM card into a crypto wallet. No applets. No passwords. No KYC.**


SMILE is a breakthrough protocol that derives blockchain wallets directly from SIM cards,
using open standards, 2G-5G telecom APIs, and the trusted cryptography already built into mobile networks.

Every SIM card already belongs to the world’s largest identity network. 
SMILE turns it into the world’s most universal crypto wallet.

With SMILE, your SIM card instantly becomes a secure, self-sovereign blockchain identity —
seamlessly integrated with the x402 protocol to enable trustless transactions, instant onboarding, 
and hardware-grade wallet security.


Your phone number is now your wallet identity.

---

## 🚀 What SMILE Does

- 🧬 **Derives a BIP-32/39 HD wallet** from the SIM’s AKA authentication keys
- 🛰 **Uses only existing 3G/4G/5G SIM commands** — no Java Card or carrier mods
- 🤝 **Cooperates with the carrier** for proof-of-presence via RAND/AUTN
- 🔏 **HKDF → BIP seed → master key** — all on device, zero exposure of Ki or K
- 🪪 **Optionally carrier-signed tokens (COSE/JWS)** for verifiable attestation

---

## 💡 Why It Matters

- **No fragile seed UX** — the SIM *is* your root of trust
- **Pay-per-use connectivity**: pay per MB, per minute, per sensor tick
- **Tap-to-transact IoT**: vending machines, EV chargers, drones, kiosks
- **Carrier ↔ crypto flywheel**: airtime, rewards, promos → on-chain assets
- **Signed operations**: firmware updates, door unlocks, telemetry notarization


---

## 🛠 Reference Implementation

Build and run the SMILE reference implementation:

```bash
git clone https://github.com/your-org/smile
cd smile && mkdir build && cd build
cmake .. && make
./smile
```

# `SmileSeedDerivation` Class

**Header:** `SmileSeedDerivation.h`

## Overview

`SmileSeedDerivation` provides a unified cryptographic abstraction for deriving **256-bit deterministic master seeds** (e.g., for BIP-32 hierarchical key systems) directly from cellular authentication primitives across multiple generations — **2G (GSM)**, **3G (UMTS-AKA)**, **4G (EPS-AKA)**, and **5G (5G-AKA)**.

Each generation uses the same conceptual structure:

| Generation | Underlying Standard | Key Algorithm | Output |
|-------------|---------------------|----------------|---------|
| 2G | GSM / TS 51.011 | COMP128-1 (A3/A8) → SHA-256 | 32-byte seed |
| 3G | TS 33.102 / TS 35.206 | Milenage → SHA-256 | 32-byte seed |
| 4G | TS 33.401 | EPS-AKA KDF → SHA-256 | 32-byte seed |
| 5G | TS 33.501 | 5G-AKA KDF → HKDF-SHA-256 | 32-byte seed |

All derivations are **deterministic**, **stateless**, and **domain-separated** using versioned ASCII labels (e.g., `"SMILE|4G|seed|v1"`).

---

## Public Interface Summary

| Function | Input | Core Algorithm | Output |
|-----------|--------|----------------|---------|
| `deriveBIP32MasterSeed2G` | RAND, Ki | COMP128-1 → SHA-256(SRES ‖ Kc) | 256-bit seed |
| `deriveBIP32MasterSeed3G` | RAND, AUTN, K, OPc, AMF | Milenage → SHA-256(RES ‖ CK ‖ IK) | 256-bit seed |
| `deriveBIP32MasterSeed4G` | RAND, AUTN, K, OPc, AMF, SNN | EPS-AKA KDF → SHA-256(RES ‖ K_ASME) | 256-bit seed |
| `deriveBIP32MasterSeed5G` | RAND, AUTN, K, OPc, AMF, SNN | 5G-AKA KDF → HKDF-SHA-256(K_SEAF) | 256-bit seed |

---

## `deriveBIP32MasterSeed2G`

```cpp
static array256 deriveBIP32MasterSeed2G(const array16 &rand, const array16 &ki);
```

### Description
Derives a **256-bit BIP-32 master seed** from GSM (2G) authentication results.

### Parameters
| Name | Size | Description |
|------|------|-------------|
| `rand` | 16 bytes | Network random challenge (RAND) |
| `ki` | 16 bytes | Subscriber secret key stored on the SIM card (Ki) |

### Returns
| Type | Size | Description |
|-------|------|-------------|
| `array256` | 32 bytes | Derived seed value suitable as BIP-32 master seed |

### Notes
- Deterministic for fixed `(RAND, Ki)`.
- COMP128-1 used internally as demonstration; real SIMs may use proprietary A3/A8 variants.

---

## `deriveBIP32MasterSeed3G`

```cpp
static array256 deriveBIP32MasterSeed3G(
    const array16 &rand,
    const array16 &autn,
    const array16 &k,
    const array16 &opc,
    const array2 &amf);
```

### Description
Implements **3G/UMTS-AKA** (Authentication and Key Agreement), and derives a  **256-bit BIP-32 master seed** 
from the authentication results (RES, CK, IK).


### Parameters
| Name | Size | Description |
|------|------|-------------|
| `rand` | 16 B | Network challenge RAND |
| `autn` | 16 B | AUTN = (SQN ⊕ AK) ‖ AMF ‖ MAC-A |
| `k` | 16 B | Subscriber long-term key K |
| `opc` | 16 B | Operator variant constant OPc = OP ⊕ AES_K(OP) |
| `amf` | 2 B | Authentication Management Field (typically 0x8000) |

### Returns
- 32-byte SHA-256 digest as `array256`.

### Behavior
- Throws `std::runtime_error` if MAC-A verification fails.
- Stateless; excludes AK (anonymity key) from seed input.

### Standards
- 3GPP TS 33.102 § 6.3
- 3GPP TS 35.205 – 35.207 (Milenage)

---

## `deriveBIP32MasterSeed4G`

```cpp
static array256 deriveBIP32MasterSeed4G(
    const array16 &rand,
    const array16 &autn,
    const array16 &k,
    const array16 &opc,
    const array2 &amf,
    const std::string &snn);
```

### Description
Derives a  **256-bit BIP-32 master seed** from LTE/EPS-AKA authentication results (RES, K_ASME).

### Parameters
| Name | Description |
|------|--------------|
| `rand` | 16-byte network challenge RAND |
| `autn` | 16-byte authentication token AUTN |
| `k` | Subscriber key K |
| `opc` | Operator constant OPc |
| `amf` | 2-byte Authentication Management Field |
| `snn` | **Serving Network Name** (e.g., `"mnc410.mcc310.3gppnetwork.org"`) |

### Returns
- 32-byte SHA-256 digest as `array256`.

### Notes
- `SNN` introduces domain separation between PLMNs.
- Used for LTE / EPC key hierarchies where K_ASME anchors all further keys.

### Standards
- 3GPP TS 33.401 Annex A.2–A.4
- 3GPP TS 23.003 § 28.7 (SNN format)

---

## `deriveBIP32MasterSeed5G`

```cpp
static array256 deriveBIP32MasterSeed5G(
    const array16 &rand,
    const array16 &autn,
    const array16 &k,
    const array16 &opc,
    const array2 &amf,
    const std::string &snn);
```

### Description
Computes a  **256-bit BIP-32 master seed**  from 5G-AKA authentication results (`RES*`, `K_SEAF`).

### Parameters
| Name | Description |
|------|--------------|
| `rand` | 16-byte RAND |
| `autn` | 16-byte AUTN |
| `k` | 16-byte subscriber key |
| `opc` | 16-byte operator variant constant |
| `amf` | 2-byte AMF |
| `snn` | Serving Network Name (as per 3GPP TS 33.501) |

### Returns
- 32-byte seed derived via HKDF-SHA256 (RFC 5869).


### Standards
- 3GPP TS 33.501 Annex A.4–A.6
- RFC 5869 (HKDF)
- 3GPP TS 24.501 (SNN naming)

---

## 📘 Summary Table

| Generation | Function | Key Material Used | KDF Type | Output |
|-------------|-----------|------------------|-----------|---------|
| **2G** | `deriveBIP32MasterSeed2G` | SRES ‖ Kc | SHA-256 | 256 bits |
| **3G** | `deriveBIP32MasterSeed3G` | RES ‖ CK ‖ IK | SHA-256 | 256 bits |
| **4G** | `deriveBIP32MasterSeed4G` | RES ‖ K_ASME | SHA-256 | 256 bits |
| **5G** | `deriveBIP32MasterSeed5G` | K_SEAF | HKDF-SHA-256 | 256 bits |

---

## 🔗 References

| Standard | Document | Description |
|-----------|-----------|--------------|
| GSM / 2G | 3GPP TS 51.011 | SIM–ME interface, A3/A8 |
| 3G | 3GPP TS 33.102 / 35.205-207 | UMTS AKA / Milenage |
| 4G | 3GPP TS 33.401 | EPS AKA KDF for K_ASME |
| 5G | 3GPP TS 33.501 | 5G-AKA KDF for K_SEAF, RES* |
| KDF | RFC 5869 | HMAC-based Key Derivation Function |

---

# Spec: BIP32 Master Seed Derivation using Cellular Authentication (2G–5G)

**Standards:**
- 3GPP TS 33.102 (3G Security Architecture)
- 3GPP TS 33.401 (LTE Security Architecture)
- 3GPP TS 33.501 (5G Security Architecture)
- RFC 5869: HMAC-based Key Derivation Function (HKDF)
- BIP32: Hierarchical Deterministic Wallets

---

## 1. Overview

This specification defines a set of deterministic algorithms for deriving a **BIP32 master seed** using **SIM/USIM/ISIM-based authentication primitives** from mobile communication systems (2G–5G).

The approach leverages cryptographically secure values generated during cellular authentication — such as **SRES**, **Kc**, **CK**, **IK**, **K_ASME**, and **K_SEAF** — as entropy sources for the BIP32 root seed.

The final seed derivation uses the standardized **HKDF** function (RFC 5869) over the authentication-derived keying material.

---

## 2. Notation

| Symbol | Meaning |
|---------|----------|
| `RAND` | Random challenge generated by the network |
| `AUTN` | Authentication token |
| `K` | Subscriber permanent key (stored securely in SIM/USIM/ISIM) |
| `OPc` | Operator variant key constant (Milenage parameter) |
| `AMF` | Authentication Management Field |
| `SNN` | Serving Network Name |
| `SRES` | Signed response (2G AKA output) |
| `Kc` | Cipher key (2G AKA output) |
| `CK` | Cipher key (3G/4G/5G AKA output) |
| `IK` | Integrity key (3G/4G/5G AKA output) |
| `AK` | Anonymity key (3G/4G/5G AKA output) |
| `K_ASME` | Access Security Management Entity key (4G) |
| `K_SEAF` | Security Anchor Function key (5G) |
| `HMAC_SHA256(key, data)` | HMAC using SHA-256 |
| `HKDF_Extract(salt, IKM)` | RFC 5869 extract stage |
| `HKDF_Expand(PRK, info, L)` | RFC 5869 expand stage |
| `‖` | Byte concatenation |

---

## 3. Cryptographic Framework

### 3.1. HKDF (RFC 5869)

Let:
- `IKM` be the input keying material (entropy source)
- `salt` be an optional context string (domain separation)
- `info` be an optional identifier for derived key usage
- `L` be the desired output length (32 bytes)

Then:

```
PRK = HMAC_SHA256(salt, IKM)
OKM = HMAC_SHA256(PRK, info || 0x01)
Seed = OKM[0..31]
```

---

## 4. 2G: deriveBIP32MasterSeed2G

### 4.1. Authentication Source

2G authentication (GSM AKA) yields:

```
(SRES, Kc) = A3/A8(K, RAND)
```

- `SRES`: 32-bit signed response
- `Kc`: 64-bit session key

### 4.2. Input Keying Material (IKM)

```
IKM_2G = SRES || Kc
```

(12 bytes total)

### 4.3. HKDF Context

- Salt = "SMILE|2G|salt|v1"
- Info = "SMILE|2G|seed|v1"

### 4.4. Derivation Equation

```
Seed_2G = HKDF_SHA256(IKM_2G, Salt, Info)
```

### 4.5. Output

- 256-bit (32-byte) seed suitable as BIP32 master seed.
- Entropy source limited (~96 bits), so use only for deterministic derivations, not high-assurance wallet seeds.

---

## 5. 3G: deriveBIP32MasterSeed3G

### 5.1. Authentication Source

3G AKA (Milenage) yields:

```
(RES, CK, IK, AK) = f1..5(K, RAND, OPc, AMF)
```

- `CK`: 128-bit cipher key
- `IK`: 128-bit integrity key

### 5.2. Input Keying Material

```
IKM_3G = CK || IK
```
(256 bits)

### 5.3. Salt Construction

```
ctx = RAND || AUTN || "SMILE|3G|salt|v1"
Salt_3G = SHA256(ctx)
```

### 5.4. HKDF Derivation

```
Seed_3G = HKDF_SHA256(IKM_3G, Salt_3G, "SMILE|3G|seed|v1")
```

### 5.5. Output

- 256-bit BIP32 seed with high entropy (~256 bits).
- Combines network challenge RAND with key material for domain separation.

---

## 6. 4G: deriveBIP32MasterSeed4G

### 6.1. Authentication Source

LTE AKA yields the derived **Access Security Management Entity key** `K_ASME` from `CK` and `IK` using:

```
K_ASME = HMAC_SHA256(CK||IK, FC||SNN||L0||(SQN⊕AK)||L1)
```

(Per 3GPP TS 33.401 §A.2.1, with FC = 0x10.)

### 6.2. Input Keying Material

```
IKM_4G = K_ASME
```
(256 bits)

### 6.3. Salt Construction

```
ctx = SNN || "|" || "SMILE|4G|salt|v1"
Salt_4G = SHA256(ctx)
```

### 6.4. HKDF Derivation

```
Seed_4G = HKDF_SHA256(IKM_4G, Salt_4G, "SMILE|4G|seed|v1")
```

### 6.5. Output

- 256-bit BIP32 seed.
- Strong cryptographic entropy, sourced from LTE authentication hierarchy.
- Safe for generating HD wallet roots tied to mobile identity.

---

## 7. 5G: deriveBIP32MasterSeed5G

### 7.1. Authentication Source

5G AKA (TS 33.501) derives the following hierarchy:

```
K_AUSF = HMAC_SHA256(CK||IK, FC||SNN||L0||(SQN⊕AK)||L1), FC = 0x6A
K_SEAF = HMAC_SHA256(K_AUSF, FC||SNN||L0), FC = 0x6B
```

### 7.2. Input Keying Material

```
IKM_5G = K_SEAF
```

### 7.3. Salt Construction

```
ctx = SNN || "|" || "SMILE|5G|salt|v1"
Salt_5G = SHA256(ctx)
```

### 7.4. HKDF Derivation

```
Seed_5G = HKDF_SHA256(IKM_5G, Salt_5G, "SMILE|5G|seed|v1")
```

### 7.5. Output

- 256-bit master seed (BIP32 m/ root).
- Entropy sourced from 5G key hierarchy (K_SEAF), which derives from K via CK/IK → K_AUSF → K_SEAF.
- Represents cryptographic coupling between SIM identity and HD wallet seed.

---

## 8. Security Discussion

1. **Entropy:**
    - 2G: ≤ 96 bits
    - 3G/4G/5G: ≥ 256 bits (AES-based + random challenge)

2. **Forward Secrecy:**
    - Each derivation depends on network RAND, ensuring session uniqueness.

3. **Domain Separation:**
    - HKDF salt and info labels include generation and versioning tags (SMILE|xG|...|v1).

4. **Compatibility:**
    - Final output format (32 bytes) matches BIP32 master seed input for:
      ```
      (m, c) = HMAC_SHA512("Bitcoin seed", Seed)
      ```

---

## 9. Example End-to-End Derivation Flow (5G)

```
Step 1: AKA → CK, IK, AK, RES
Step 2: K_AUSF = HMAC_SHA256(CK||IK, 0x6A||SNN||L0||(SQN⊕AK)||L1)
Step 3: K_SEAF = HMAC_SHA256(K_AUSF, 0x6B||SNN||L0)
Step 4: Salt = SHA256(SNN||"|"||"SMILE|5G|salt|v1")
Step 5: Seed = HKDF_SHA256(K_SEAF, Salt, "SMILE|5G|seed|v1")
Output: Seed_5G ∈ {0,1}^256
```

---

## 10. Implementation Notes

- All HKDF operations use HMAC-SHA256 as the PRF.
- All salts and info strings are ASCII-encoded.
- The seed output can be directly passed to BIP32 as the entropy input for HMAC-SHA512 keychain derivation.

---

## 11. Security Level Summary

| Generation | Entropy Source | Algorithmic Base | Cryptographic Strength |
|-------------|----------------|------------------|------------------------|
| 2G | (SRES‖Kc) | COMP128 / A3/A8 | Weak / Legacy |
| 3G | (CK‖IK) via Milenage | AES-128 | Strong |
| 4G | K_ASME (HMAC-SHA256) | AES-128 + SHA256 | Strong |
| 5G | K_SEAF (HMAC-SHA256 chain) | AES-128 + SHA256 | Very Strong |

---

## 12. Final Formula Summary

| Function | Final Formula | Output Bits |
|-----------|----------------|--------------|
| `deriveBIP32MasterSeed2G` | `HKDF_SHA256(SRES‖Kc, "SMILE|2G|salt|v1", "SMILE|2G|seed|v1")` | 256 |
| `deriveBIP32MasterSeed3G` | `HKDF_SHA256(CK‖IK, SHA256(RAND‖AUTN‖"SMILE|3G|salt|v1"), "SMILE|3G|seed|v1")` | 256 |
| `deriveBIP32MasterSeed4G` | `HKDF_SHA256(K_ASME, SHA256(SNN‖"|"‖"SMILE|4G|salt|v1"), "SMILE|4G|seed|v1")` | 256 |
| `deriveBIP32MasterSeed5G` | `HKDF_SHA256(K_SEAF, SHA256(SNN‖"|"‖"SMILE|5G|salt|v1"), "SMILE|5G|seed|v1")` | 256 |


