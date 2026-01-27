# Post-Quantum Cryptography (PQC) for Soul v2

## Overview

The Soul Protocol (Soul) v2 includes comprehensive post-quantum cryptography support to protect against future quantum computer attacks. This implementation follows NIST's post-quantum cryptography standards and provides multiple verification approaches optimized for different security and cost requirements.

## Threat Model

### Quantum Computing Threats

1. **Shor's Algorithm**: Breaks RSA, DSA, ECDSA, and ECDH
2. **Grover's Algorithm**: Reduces symmetric key security by half
3. **Harvest-Now-Decrypt-Later**: Adversaries collect encrypted data today to decrypt with future quantum computers

### Why PQC for Soul?

- Cross-chain messages may be archived indefinitely
- Long-term confidentiality requirements for encrypted containers
- Critical infrastructure requiring decades of security
- Regulatory compliance (NIST, CNSA 2.0)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     PQC Container Extension                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  Container PQC  │  │  Cross-Chain    │  │   Ownership     │  │
│  │  Authentication │  │  PQC Messages   │  │   Transfers     │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
└───────────┼─────────────────────┼────────────────────┼──────────┘
            │                     │                    │
            ▼                     ▼                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Verification Layer                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  PostQuantum    │  │   Hybrid        │  │    PQC Key      │  │
│  │  SigVerifier    │  │   CryptoVerifier│  │    Registry     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Supported Algorithms

### Digital Signatures

| Algorithm | NIST Level | Signature Size | Public Key Size | Use Case |
|-----------|------------|----------------|-----------------|----------|
| Dilithium2 | 2 | 2,420 bytes | 1,312 bytes | General purpose |
| Dilithium3 | 3 | 3,293 bytes | 1,952 bytes | Higher security |
| Dilithium5 | 5 | 4,595 bytes | 2,592 bytes | Maximum security |
| SPHINCS+-128f | 1 | 17,088 bytes | 32 bytes | Long-term security |
| SPHINCS+-192f | 3 | 35,664 bytes | 48 bytes | Conservative |
| SPHINCS+-256f | 5 | 49,856 bytes | 64 bytes | Ultra-conservative |
| Falcon-512 | 1 | 666 bytes | 897 bytes | Size-constrained |
| Falcon-1024 | 5 | 1,280 bytes | 1,793 bytes | High security |

### Key Encapsulation (KEM)

| Algorithm | NIST Level | Ciphertext Size | Shared Secret |
|-----------|------------|-----------------|---------------|
| Kyber-512 | 1 | 768 bytes | 32 bytes |
| Kyber-768 | 3 | 1,088 bytes | 32 bytes |
| Kyber-1024 | 5 | 1,568 bytes | 32 bytes |

## Contracts

### 1. IPostQuantumCrypto.sol

Core interfaces defining the PQC type system:

```solidity
// Signature algorithm enumeration
enum PQSignatureAlgorithm {
    NONE,
    DILITHIUM2,
    DILITHIUM3,
    DILITHIUM5,
    SPHINCS_SHA2_128F,
    SPHINCS_SHA2_192F,
    SPHINCS_SHA2_256F,
    FALCON512,
    FALCON1024
}

// PQC signature structure
struct PQSignature {
    PQSignatureAlgorithm algorithm;
    bytes signatureData;
    bytes32 signatureHash;
    bytes32 nonce;
}

// Hybrid signature combining classical + PQC
struct HybridSignature {
    HybridMode mode;
    bytes classicalSignature;  // ECDSA or EdDSA
    PQSignature pqSignature;
    bytes32 bindingData;
}
```

### 2. PostQuantumSignatureVerifier.sol

Handles PQC signature verification with multiple approaches:

#### Optimistic Verification
Gas-efficient verification with fraud proof challenge period:

```solidity
// Submit verification request
bytes32 verificationId = pqVerifier.submitOptimisticVerification(
    signature,
    publicKey,
    message
);

// After challenge period (1 hour), finalize
pqVerifier.finalizeOptimisticVerification(verificationId);
```

#### Trusted Verifier Attestation
Off-chain verification with on-chain attestation:

```solidity
// Trusted verifier attests to signature validity
bytes32 attestationId = pqVerifier.submitAttestation(
    signature,
    publicKey,
    message,
    isValid,
    evidenceHash
);
```

### 3. HybridCryptoVerifier.sol

Combines classical and post-quantum cryptography for defense-in-depth:

```solidity
// Register hybrid key pair
bytes32 hybridKeyHash = hybridVerifier.registerHybridKey(
    HybridMode.ECDSA_DILITHIUM3,
    pqKeyHash
);

// Verify hybrid signature (requires BOTH classical AND PQ valid)
bool isValid = hybridVerifier.verifyHybridSignature(
    hybridKeyHash,
    message,
    hybridSignature
);

// Derive hybrid shared key
bytes32 sharedKey = hybridVerifier.deriveHybridKey(
    classicalSecret,
    pqSecret,
    context
);
```

### 4. PQCKeyRegistry.sol

Manages PQC key lifecycle:

```solidity
// Register a new PQC key
bytes32 keyHash = keyRegistry.registerKey(
    PQSignatureAlgorithm.DILITHIUM3,
    publicKeyBytes,
    expirationTimestamp
);

// Rotate to new key with grace period
(bytes32 rotationId, bytes32 newKeyHash) = keyRegistry.requestRotation(
    oldKeyHash,
    PQSignatureAlgorithm.DILITHIUM5,
    newPublicKey,
    newExpiry
);

// Revoke a compromised key
keyRegistry.revokeKey(keyHash);
```

### 5. PQCContainerExtension.sol

Adds PQC protection to ProofCarryingContainers:

```solidity
// Extend container with PQC authentication
containerExtension.extendContainerWithPQC(
    containerId,
    creatorKeyHash,
    pqSignature,
    hybridSignature  // optional
);

// Transfer container ownership with PQC authorization
containerExtension.transferContainerOwnership(
    containerId,
    newOwnerKeyHash,
    authorizationSignature,
    hybridSig
);

// Receive PQC-authenticated cross-chain message
bool valid = containerExtension.receiveCrossChainMessage(message);
```

## Security Levels

The implementation enforces NIST security levels:

| Level | Classical Equivalent | Quantum Security | Recommended For |
|-------|---------------------|------------------|-----------------|
| 1 | AES-128 | 64-bit | Short-term |
| 2 | SHA-256 | 128-bit | General purpose |
| 3 | AES-192 | 192-bit | Sensitive data |
| 5 | AES-256 | 256-bit | Critical infrastructure |

```solidity
// Enforce minimum security level
containerExtension.setMinSecurityLevel(3); // Require NIST Level 3+
```

## Verification Approaches

### 1. Full On-Chain (Future EVM Precompiles)

When EVM precompiles for PQC algorithms become available:

```solidity
function verifyDilithium(
    bytes calldata signature,
    bytes calldata publicKey,
    bytes calldata message
) external returns (bool) {
    // Use EVM precompile when available
    return DILITHIUM_PRECOMSoulE.verify(signature, publicKey, message);
}
```

### 2. Optimistic Verification

Current gas-efficient approach:

1. Submit signature + public key + message hash
2. Challenge period (1 hour default)
3. If challenged: submit fraud proof
4. If unchallenged: finalize as valid

```
Gas Cost: ~100k (submit) + ~50k (finalize)
Security: Relies on honest challenger assumption
```

### 3. Trusted Verifier Network

For immediate verification:

1. Off-chain verifiers validate signatures
2. Submit attestation on-chain
3. Weighted voting for consensus

```
Gas Cost: ~80k per attestation
Security: Relies on verifier honesty (stake-backed)
```

### 4. ZK-Wrapped Verification

Wrap PQC verification in ZK proof:

1. Generate ZK proof of correct PQC verification off-chain
2. Verify ZK proof on-chain (Groth16/PLONK)

```
Gas Cost: ~250k (ZK verification)
Security: Cryptographic soundness
```

## Hybrid Cryptography

The hybrid approach provides defense-in-depth:

```
HybridSignature = ECDSA(message) || Dilithium(message)
```

Both signatures must be valid for verification to succeed. This protects against:
- Unknown weaknesses in new PQC algorithms
- Implementation bugs in either scheme
- Transitional security during migration

### Key Derivation

Hybrid key derivation using HKDF-style construction:

```
DerivedKey = HKDF(classical_secret || pq_secret, context)
```

## Migration Guide

### Phase 1: Preparation
1. Deploy PQC contracts
2. Register PQC keys for critical operators
3. Enable hybrid mode (optional but recommended)

### Phase 2: Parallel Operation
1. Create containers with both classical and PQC authentication
2. Verify using hybrid mode
3. Monitor for any issues

### Phase 3: PQC-Primary
1. Make hybrid mode mandatory
2. Phase out classical-only verification
3. Increase minimum security level

### Phase 4: PQC-Only (Future)
1. Deprecate classical signatures
2. Full PQC operation
3. Remove hybrid requirements

## Configuration

### Admin Functions

```solidity
// Set mandatory hybrid mode
containerExtension.setMandatoryHybridMode(true);

// Set minimum security level (1-5)
containerExtension.setMinSecurityLevel(3);

// Add trusted verifier
pqVerifier.addTrustedVerifier(verifierAddress, weight);

// Set minimum attestation weight for key activation
keyRegistry.setMinAttestationWeight(50);
```

### Key Management

```solidity
// Maximum keys per owner
uint256 MAX_KEYS_PER_OWNER = 50;

// Key validity period constraints
uint256 MIN_VALIDITY_PERIOD = 7 days;
uint256 MAX_VALIDITY_PERIOD = 5 years;

// Rotation grace period
uint256 ROTATION_GRACE_PERIOD = 7 days;
```

## Testing

Run the PQC test suite:

```bash
forge test --match-contract PostQuantumCryptoTest -vvv
```

## Gas Estimates

| Operation | Gas (approx) |
|-----------|-------------|
| Register PQC key | 150k |
| Submit optimistic verification | 100k |
| Finalize verification | 50k |
| Submit attestation | 80k |
| Register hybrid key | 120k |
| Verify hybrid signature | 200k |
| Extend container with PQC | 180k |
| Transfer ownership | 150k |

## Security Considerations

1. **Key Storage**: PQC private keys are larger; ensure secure storage
2. **Signature Size**: Large signatures may affect calldata costs
3. **Algorithm Agility**: Support for algorithm upgrades built-in
4. **Trusted Verifiers**: Stake-backed for economic security
5. **Challenge Period**: Balance between security and UX

## Future Roadmap

1. **EVM Precompiles**: Native PQC verification when available
2. **Hardware Acceleration**: HSM support for PQC operations
3. **Cross-Chain PQC**: Standardized PQC message format
4. **Formal Verification**: Certora specs for PQC contracts
5. **Threshold PQC**: Distributed key generation and signing

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [SPHINCS+](https://sphincs.org/)
- [Falcon](https://falcon-sign.info/)
- [EIP-PQC Precompiles Draft](https://github.com/ethereum/EIPs/issues/PQC)
