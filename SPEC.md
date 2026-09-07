# QuantaSeal Hybrid PQC Envelope - Wire Format Specification

**Version:** 1.0  
**Status:** Stable  
**Published:** May 2026  
**Licence:** Apache 2.0 - anyone may implement a compatible encoder/decoder

---

## Purpose

This document specifies the encrypted payload envelope used by QuantaSeal for
all data-in-transit and at-rest encryption operations. The spec is published
so that:

1. Security researchers can independently verify the cryptographic design
2. Enterprise customers can decrypt their own data without QuantaSeal software
   (key escrow / business continuity)
3. Third-party implementations can interoperate with QuantaSeal-encrypted payloads

---

## Design Principles

- **Hybrid mode is mandatory.** The envelope always combines a post-quantum KEM
  (ML-KEM-768) with a classical symmetric cipher (AES-256-GCM). Neither pure
  PQC nor pure classical alone is acceptable.
- **Authentication before decryption.** Both the ML-DSA-65 signature and the
  HMAC-SHA-512 must be verified before any decryption is attempted. Failures are
  rejected via bitwise `&` - short-circuit evaluation is not used.
- **No nonce in the wire format.** The AES-256-GCM nonce is embedded inside
  `ciphertext_data` (prepended, first 12 bytes). It is never stored, logged,
  or transmitted separately.

---

## JSON Envelope Structure

```json
{
  "encrypted": {
    "ciphertext_kem":  "<base64>",
    "ciphertext_data": "<base64>",
    "tenant_id":       "<uuid>",
    "algorithm":       "ML-KEM-768"
  },
  "signature": {
    "pqc_signature":   "<base64>",
    "hmac_signature":  "<base64>",
    "tenant_id":       "<uuid>",
    "algorithm":       "ML-DSA-65+HMAC-SHA-512"
  }
}
```

---

## Field Specifications

### `encrypted` object

| Field           | Type     | Size (bytes)  | Description |
|----------------|----------|---------------|-------------|
| `ciphertext_kem`  | base64   | **1088** (ML-KEM-768 NIST FIPS 203 §4, Table 2) | ML-KEM-768 KEM ciphertext. Decapsulating this with the tenant's ML-KEM-768 secret key yields the 32-byte shared secret `K`. |
| `ciphertext_data` | base64   | variable      | Concatenation of: `nonce[12] ‖ AES-256-GCM-ciphertext[n] ‖ GCM-tag[16]`. The nonce is the first 12 bytes; the GCM authentication tag is the last 16 bytes. |
| `tenant_id`       | string   | 36 (UUID)     | Identifies which tenant ML-KEM-768 keypair was used for encapsulation. |
| `algorithm`       | string   | -             | Always `"ML-KEM-768"`. Implementations MUST reject envelopes with any other value. |

### `signature` object

| Field           | Type     | Size (bytes)  | Description |
|----------------|----------|---------------|-------------|
| `pqc_signature`   | base64   | ≤ **3309** (ML-DSA-65 NIST FIPS 204 §4, Table 2) | ML-DSA-65 signature over `ciphertext_data` bytes. |
| `hmac_signature`  | base64   | **64**        | HMAC-SHA-512 over `ciphertext_data` bytes using the tenant HMAC key (derived from the tenant secret key with `hashlib.sha512`). |
| `tenant_id`       | string   | 36 (UUID)     | Must match `encrypted.tenant_id`. |
| `algorithm`       | string   | -             | Always `"ML-DSA-65+HMAC-SHA-512"`. |

---

## Encryption Process

```
Input:  plaintext (bytes), tenant ML-KEM-768 public key, tenant HMAC secret

1.  Generate ML-KEM-768 keypair (ephemeral):   (ek_ephemeral, dk_ephemeral)
2.  Encapsulate against tenant public key:      (ciphertext_kem, shared_secret_K)
        shared_secret_K = ML-KEM-768.Encaps(tenant_pk)   → 32 bytes
3.  Derive AES key:
        aes_key = HKDF-SHA-512(ikm=shared_secret_K, length=32,
                               info=b"quantaseal-aes-key")
4.  Encrypt payload:
        nonce          = os.urandom(12)
        ciphertext, tag = AES-256-GCM.encrypt(key=aes_key, nonce=nonce,
                                               plaintext=plaintext)
        ciphertext_data = nonce ‖ ciphertext ‖ tag
5.  Sign ciphertext_data:
        pqc_signature  = ML-DSA-65.Sign(dk_tenant, ciphertext_data)
        hmac_signature = HMAC-SHA-512(key=tenant_hmac_key, msg=ciphertext_data)

Output: JSON envelope as specified above
```

---

## Decryption Process

```
Input:  envelope (JSON), tenant ML-KEM-768 secret key, tenant HMAC secret

1.  Validate algorithm fields - reject if not "ML-KEM-768" / "ML-DSA-65+HMAC-SHA-512"
2.  Verify BOTH signatures (bitwise AND - do NOT short-circuit):
        pqc_ok   = ML-DSA-65.Verify(pk_tenant, ciphertext_data, pqc_signature)
        hmac_ok  = HMAC-SHA-512(key=tenant_hmac_key, msg=ciphertext_data)
                     == hmac_signature   (constant-time comparison)
        if not (pqc_ok & hmac_ok):
            raise SignatureVerificationError
3.  Decapsulate KEM ciphertext:
        shared_secret_K = ML-KEM-768.Decaps(dk_tenant, ciphertext_kem)
4.  Derive AES key (same derivation as encryption):
        aes_key = HKDF-SHA-512(ikm=shared_secret_K, length=32,
                               info=b"quantaseal-aes-key")
5.  Decrypt:
        nonce          = ciphertext_data[:12]
        ciphertext_tag = ciphertext_data[12:]
        plaintext      = AES-256-GCM.decrypt(key=aes_key, nonce=nonce,
                                              ciphertext=ciphertext_tag)

Output: plaintext (bytes)
```

---

## Algorithm Parameters (NIST references)

| Algorithm      | Standard   | Security Level | Parameters |
|---------------|------------|----------------|------------|
| ML-KEM-768    | FIPS 203   | Level 3 (192-bit PQ) | pk=1184 B, sk=2400 B, ct=1088 B, ss=32 B |
| ML-DSA-65     | FIPS 204   | Level 3 (192-bit PQ) | pk=1952 B, sk=4032 B, sig≤3309 B |
| AES-256-GCM   | FIPS 197 + SP 800-38D | 256-bit classical | nonce=12 B, tag=16 B |
| HKDF-SHA-512  | RFC 5869   | -              | output=32 B |
| HMAC-SHA-512  | FIPS 198-1 | -              | key=64 B (SHA-512 of tenant secret), output=64 B |

**Forbidden algorithms:** ML-KEM-512, ML-DSA-44, RSA, ECDSA, AES-128, AES-CBC.  
Implementations MUST reject envelopes using these algorithms.

---

## Reference Implementations

| Language | Repository | Package |
|---------|------------|---------|
| Python  | [github.com/quantaseal/sdk-python](https://github.com/quantaseal/sdk-python) | `pip install quantaseal` |
| Node.js | [github.com/quantaseal/sdk-node](https://github.com/quantaseal/sdk-node)   | `npm install @quantaseal/sdk` |
| Go      | [github.com/quantaseal/sdk-go](https://github.com/quantaseal/sdk-go)       | `go get github.com/quantaseal/sdk/go` |

Live parameter verification (runs fresh ML-KEM-768 and ML-DSA-65 operations on every request, validates sizes against this spec):  
→ https://quantaseal.io/security/pqc-attestation

---

## Key Escrow / Business Continuity

Enterprise customers can decrypt their QuantaSeal-protected data without
QuantaSeal software using any conformant ML-KEM-768 + AES-256-GCM
implementation (e.g. [liboqs](https://github.com/open-quantum-safe/liboqs),
AWS Encryption SDK with a custom KDF).

Required material (exportable on request per the QuantaSeal SLA):

- Tenant ML-KEM-768 secret key (`dk_tenant`)
- Tenant HMAC secret (`tenant_hmac_key`)
- Tenant ML-DSA-65 signing key (for signature verification)

---

## Changelog

| Version | Date       | Change |
|---------|-----------|--------|
| 1.0     | 2026-05-29 | Initial public specification |
