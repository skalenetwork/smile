<p align="center">
  <img src="smile.png" alt="SMILE" width="25%" />
</p>

<h1 align="center">SMILE Protocol - SIM Mobile Identity for Ledgers</h1>

Use blockchain and x402 protocol using SIM card identity for secure wallets.

# 😄 SMILE — SIM Mobile Identity for Ledgers

**Turn your SIM card into a crypto wallet. No applets. No passwords. No KYC.**

SMILE is a new protocol that **derives blockchain wallets directly from SIM cards** —  
using only standard telecom APIs and cryptography you already trust.

> 🔐 Your phone number is now your wallet identity.

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

> Every SIM becomes a verifiable crypto identity — globally deployed, instantly usable.

---

## 🧠 How It Works

### 🔐 How SMILE Derives a Wallet

📶 **SIM AUTHENTICATE(RAND, AUTN)**  
⬇️  
🔑 **CK ∥ IK (or K_AUSF)** — keying material from 3G/4G/5G AKA  
⬇️  
🧮 **HKDF** — derive pseudorandom seed  
⬇️  
🌱 **SMILE Seed (64 bytes)**  
⬇️  
🪙 **BIP-32 / BIP-39** — HD wallet generation  
⬇️  
💼 **HD Wallet Tree → xpub / xpriv / addresses**

⚙️ Build Once, Smile Everywhere

🧩 Runs on phones, modems, IoT, or embedded Linux

🌐 Works with 3G, 4G, 5G, eSIM, iSIM

🪶 No baseband mods, no root, no side channels

❤️ Join the Movement

Every SIM card already holds the world’s largest identity network.
SMILE turns it into the world’s most universal crypto wallet.

📞 The future of crypto starts with your SIM.



No custom SIMs. No secret sharing. Just standard 3GPP math.

---

## 🛠 Reference Implementation

C++ / CMake / vcpkg stack:

- 🔹 **OpenSSL** — HKDF / HMAC-SHA256
- 🔹 **Trezor Crypto** — BIP-32 / BIP-39
- 🔹 **PC/SC** — SIM APDU access
- 🔹 **nlohmann/json** — serialization

```bash
git clone https://github.com/your-org/smile
cd smile && mkdir build && cd build
cmake .. && make
./smile-demo