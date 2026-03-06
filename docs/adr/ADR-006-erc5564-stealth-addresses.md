# ADR-006: ERC-5564 Stealth Address Implementation

## Status

Accepted

## Date

2026-02-28

## Context

ZASEON needs recipient privacy for cross-chain transfers. Without stealth addresses, on-chain observers can link sender and recipient addresses across chains. Requirements:

1. **Unlinkability**: External observers cannot link a stealth address to the recipient's main address
2. **Recoverability**: Recipient can deterministically derive the stealth address private key
3. **Standards compliance**: Follow emerging Ethereum standards for ecosystem interoperability
4. **Cross-chain**: Same spending key must work across all supported L2s

Evaluated approaches: custom ECDH scheme, Tornado-style commitment scheme, ERC-5564.

## Decision

Implement **ERC-5564 (Stealth Addresses)** with dual-key architecture (spending key + viewing key).

### Architecture

- `StealthAddressRegistry`: On-chain registry mapping addresses to stealth meta-addresses (spending pubkey + viewing pubkey)
- `StealthContractFactory`: Deploys stealth contracts at deterministic addresses using CREATE2
- `EncryptedStealthAnnouncements`: Off-chain announcement log for recipients to scan
- `ViewKeyRegistry`: Optional disclosure of viewing keys for compliance

### Key generation flow

1. Recipient registers stealth meta-address: `(spendingPubKey, viewingPubKey)`
2. Sender generates ephemeral keypair `(r, R = r·G)`
3. Sender computes shared secret: `S = r · viewingPubKey`
4. Stealth address: `stealthAddr = spendingPubKey + hash(S)·G`
5. Sender publishes ephemeral pubkey `R` in announcement
6. Recipient scans announcements, computes `S = viewingKey · R`, checks if address matches

### Rationale

- **ERC-5564**: Standardized approach with growing ecosystem support
- **Dual-key**: Viewing key can be shared with auditors without compromising spending ability
- **CREATE2**: Deterministic stealth contract addresses work cross-chain
- **Secp256k1**: Native EVM curve, no precompile dependency

## Consequences

- Recipients must periodically scan announcement logs (SDK handles this)
- Viewing key sharing enables selective compliance disclosure
- Gas cost: ~45k for registration, ~65k for announcement
- Cross-chain scanning requires indexing announcements on each L2
