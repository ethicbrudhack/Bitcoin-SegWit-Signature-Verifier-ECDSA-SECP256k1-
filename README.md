# 🧩 Bitcoin SegWit Signature Verifier (ECDSA SECP256k1)

> ⚙️ **Advanced cryptographic tool for validating SegWit Bitcoin transaction signatures**  
> This script demonstrates how to **rebuild SegWit transaction preimages**,  
> **parse ECDSA signatures**, **decompress public keys**,  
> and verify them directly against the **SECP256k1** elliptic curve.

---

## 🚀 Overview

This project provides a complete low-level implementation of Bitcoin’s **SegWit signature verification** process.

It:
- 🧠 Reconstructs SegWit preimages (BIP-143)
- 🔑 Decompresses compressed public keys (0x02/0x03 → X,Y)
- 🧮 Decodes DER ECDSA signatures (r, s)
- 🧾 Computes `z` (the double-SHA256 digest for signature verification)
- ✅ Verifies the signature using the `ecdsa` Python library

All cryptographic operations follow **Bitcoin Core consensus rules**.

---

## ✨ Features

| Feature | Description |
|----------|--------------|
| ⚙️ **Full BIP-143 preimage builder** | Computes `z` for SegWit inputs |
| 🧮 **DER decoding** | Extracts r/s values from transaction signatures |
| 🔐 **Public key decompression** | Converts compressed pubkeys into full elliptic curve points |
| 🧠 **ECDSA verification** | Verifies signatures using SECP256k1 |
| 📜 **Readable transaction reconstruction** | Parses real TX inputs and outputs |
| 💾 **Detailed console logging** | Displays z, r, s, pubkey, and verification result |

---

## 📂 File Structure

| File | Description |
|------|-------------|
| `verify_segwit_signature.py` | Main script |
| `README.md` | Documentation (this file) |

---

## ⚙️ Configuration

| Variable | Description |
|-----------|-------------|
| `tx` | Dictionary describing a Bitcoin transaction (inputs, outputs, witnesses) |
| `SECP256k1` | Elliptic curve used by Bitcoin |
| `z_hash` | Computed message digest (double SHA256 of preimage) |
| `r, s` | Signature values decoded from DER format |
| `vk` | Reconstructed VerifyingKey from public point |

**Dependencies**

pip install ecdsa


---

## 🧠 How It Works

### 1️⃣ SegWit Preimage Construction (BIP-143)
Each SegWit input is signed using a specific message (preimage):

```python
z_hash = build_segwit_preimage(tx, input_index)


The preimage includes:

Transaction version

Hash of all inputs (hash_prevouts)

Hash of sequences (hash_sequence)

Input’s outpoint (TXID + index)

Script code and amount

Hash of outputs (hash_outputs)

Locktime + sighash type

After concatenation, the preimage is hashed twice (sha256d).

2️⃣ DER Signature Decoding

Signatures are encoded using DER format (r and s values).
The last byte (sighash type) is removed before verification.

der_sig = bytes.fromhex(inp["witness"][0])
r, s = util.sigdecode_der(der_sig[:-1], SECP256k1.order)

3️⃣ Public Key Decompression

Bitcoin compressed public keys start with 0x02 or 0x03
(encoding only the X coordinate and Y parity).
The script rebuilds the Y coordinate from X:

def decompress_pubkey(compressed_hex):
    x = int.from_bytes(compressed[1:], "big")
    y_sq = (x**3 + 7) % p
    y = pow(y_sq, (p+1)//4, p)

4️⃣ Signature Verification

Using the reconstructed verifying key:

vk = VerifyingKey.from_public_point(point, curve=SECP256k1)
vk.verify_digest(signature, z_hash)


If no exception is raised → the signature is valid ✅

🧾 Example Output
z      = 58d5a7c8ff3cf4c9b18ed7c96c514f701ac63c3f0b7a4c8b8da9f6c1dfef2447
r      = 6216579c3aa0801a7cc327e96a980549b5a3df1903fa21ab100f5bdc2d138bbe
s      = 7f0eda2c46dffebfd8fb630878eba1a7b46b0a8f2afc6762ff3e253abfa267bc
pubkey = 02174ee672429ff94304321cdae1fc1e487edf658b34bd1d36da03761658a2bb09
✅ Podpis jest poprawny!

🧩 Core Functions
Function	Description
sha256d()	Double SHA256 hash function
encode_varint()	Encodes integers using Bitcoin varint format
hash_prevouts()	Concatenates and hashes all input outpoints
hash_sequence()	Hashes all input sequence numbers
hash_outputs()	Builds and hashes all transaction outputs
build_segwit_preimage()	Constructs a full BIP-143 preimage for SegWit signing
decompress_pubkey()	Expands compressed pubkey into full elliptic curve point
⚡ Performance Notes

🚀 Preimage generation and hashing are pure Python → suitable for analysis or teaching.

🧮 For high-speed validation, use C-based Bitcoin libraries (e.g., python-bitcointx).

🧠 Ideal for cryptographic education or debugging ECDSA signature mismatches.

🔎 Replace tx dictionary with real transaction data to verify any SegWit input manually.

🔒 Ethical & Legal Notice

This script is a cryptographic research utility.
It performs no network calls, no blockchain queries, and no private key recovery.

You may:

Audit and validate your own transaction signatures.

Learn the structure of SegWit transactions.

Explore how Bitcoin’s signature verification logic works.

You must not:

Attempt unauthorized transaction modifications or key recovery.

Use this for non-consensual or malicious blockchain analysis.

Respect privacy, legality, and network integrity at all times. ⚖️

🧰 Suggested Improvements

🔁 Add support for legacy (non-SegWit) P2PKH verification.

🧩 Implement Bech32m for Taproot (P2TR) signatures.

💾 Save z/r/s/public key values to JSON for reproducibility.

📊 Add interactive verification for multiple TX inputs.

⚙️ Add command-line parser for TXID and input index.

🪪 License

MIT License
© 2025 — Author: [Ethicbrudhack]

💡 Summary

This project delivers a precise, step-by-step reconstruction
of Bitcoin’s SegWit ECDSA signature verification pipeline.

It’s perfect for:

🧠 Researchers studying BIP-143

🧩 Developers debugging custom Bitcoin transactions

🧮 Learners mastering cryptography fundamentals

“Understand the math behind every satoshi.” — [Ethicbrudhack]

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
