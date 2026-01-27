# ZK Privacy Circuits Documentation (Noir)

## Overview

The Soul Protocol (Soul) uses zero-knowledge circuits to enable private cross-chain transactions. All circuits have been migrated from Circom to **Noir**, Aztec's domain-specific language for ZK proofs, providing better safety guarantees, improved developer experience, and native integration with the Barretenberg prover.

## Circuit Location

All Noir circuits are located in the `noir/` directory:

```
noir/
├── cross_domain_nullifier/    # Cross-chain nullifier derivation
├── private_transfer/          # Private transfers with stealth addresses
├── ring_signature/            # CLSAG-style ring signatures
├── balance_proof/             # Balance verification proofs
├── compliance_proof/          # Regulatory compliance proofs
├── cross_chain_proof/         # Cross-chain state proofs
├── merkle_proof/              # Merkle tree membership
├── nullifier/                 # Basic nullifier derivation
├── pedersen_commitment/       # Pedersen commitment proofs
├── policy/                    # Policy enforcement circuits
├── private_order/             # Private order book operations
└── swap_proof/                # Atomic swap proofs
```

---

## Circuit Inventory

### 1. Cross-Domain Nullifier Circuit
**File:** `noir/cross_domain_nullifier/src/main.nr`

Proves knowledge of a nullifier's preimage without revealing it, enabling cross-chain double-spend prevention while maintaining privacy.

**Public Inputs:**
- `source_chain_id`: Origin chain identifier
- `source_app_id`: Origin application identifier
- `source_epoch_id`: Epoch for nullifier evolution
- `source_nullifier`: Nullifier hash from source chain
- `target_chain_id`: Destination chain identifier
- `target_app_id`: Destination application identifier
- `target_epoch_id`: Target epoch
- `target_nullifier`: Nullifier hash for target chain
- `target_transition_id`: Unique transition identifier

**Private Inputs:**
- `parent_secret`: User's master secret
- `derivation_nonce`: Nonce for derivation path

**Features:**
- Merkle tree membership proofs (16-depth)
- Private transfers with balance verification
- Range proofs for 64-bit values
- Epoch-based nullifier evolution
- Cross-domain transfer verification

**Security Properties:**
- Nullifier uniqueness: Same secret + domain produces same nullifier
- Cross-domain isolation: Nullifiers are domain-specific (A→B ≠ B→A)
- Commitment hiding: Original values not revealed
- Balance conservation: Verified without revealing amounts

---

### 2. Private Transfer Circuit
**File:** `noir/private_transfer/src/main.nr`

Enables fully private transfers with hidden amounts, sender anonymity, and recipient privacy using stealth addresses.

**Public Inputs:**
- `merkle_root`: UTXO commitment tree root
- `input_nullifiers`: Nullifiers for spent inputs (array of 2)
- `output_commitments`: New output commitments (array of 2)
- `fee`: Transaction fee (public for relayer payment)

**Private Inputs (TransferInput struct × 2):**
- `secret`: Secret for the input UTXO
- `blinding`: Blinding factor
- `value`: Input amount
- `merkle_path`: Merkle proof path (20 elements)
- `merkle_indices`: Path indices (20 bits)

**Private Inputs (TransferOutput struct × 2):**
- `value`: Output amount
- `blinding`: Output blinding factor
- `recipient_spend_key_x/y`: Recipient's spend public key
- `recipient_view_key_x/y`: Recipient's view public key
- `ephemeral_key`: Random ephemeral scalar

**Public Outputs:**
- `key_images`: For double-spend detection (array of 2)
- `stealth_addresses`: Derived recipient addresses (array of 2)
- `ephemeral_pubkey_x/y`: For recipient scanning (arrays of 2)
- `view_tags`: For efficient wallet scanning (array of 2)

**Security Properties:**
- Amount hiding: Values encrypted in Pedersen commitments
- Balance conservation: Σ inputs = Σ outputs + fee (proven without revealing)
- Range proofs: All values proven to be in [0, 2^64)
- Stealth addresses: Unlinkable to recipient identity
- Key images: Linkability without revealing which UTXO spent

---

### 3. Ring Signature Circuit
**File:** `noir/ring_signature/src/main.nr`

Implements CLSAG-style ring signatures for sender anonymity within a set.

**Public Inputs (RingPublicInputs struct):**
- `ring_members`: Public keys in the ring (8 Points)
- `message_hash`: Signed message digest
- `key_image`: Linkable key image (Point)

**Private Inputs:**
- `secret_key`: Actual signer's private key
- `signer_index`: Position in ring (hidden)
- `random_scalars`: Ring signature responses (8 scalars)

**Public Outputs:**
- `bool`: True if signature is valid

**Ring Size:** 8 (configurable via constant)

**Security Properties:**
- Anonymity: Signer indistinguishable from ring members
- Linkability: Same key produces same key image (prevents double-spend)
- Unforgeability: Cannot forge without private key
- Challenge chain closure: Verifies ring properly closes

**Additional Features:**
- RingCT support: `verify_ringct` function for confidential transactions
- Pedersen commitment verification
- Balance verification for hidden amounts

---

## Installation

### Prerequisites
```bash
# Install Noir (Nargo)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup

# Verify installation
nargo --version
```

### Compile Circuits
```bash
# Cross-domain nullifier
cd noir/cross_domain_nullifier
nargo compile

# Private transfer
cd noir/private_transfer
nargo compile

# Ring signature
cd noir/ring_signature
nargo compile
```

### Run Tests
```bash
# Test specific circuit
cd noir/private_transfer
nargo test

# Test all circuits
for d in noir/*/; do
    echo "Testing $d"
    (cd "$d" && nargo test)
done
```

---

## Usage

### Generate Proof (TypeScript/JavaScript)
```typescript
import { BarretenbergBackend } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';
import circuit from './target/private_transfer.json';

async function generateProof(inputs: any) {
    const backend = new BarretenbergBackend(circuit);
    const noir = new Noir(circuit, backend);
    
    const { witness } = await noir.execute(inputs);
    const proof = await backend.generateProof(witness);
    
    return proof;
}

// Example inputs
const inputs = {
    input_0: {
        secret: "123456",
        blinding: "111111",
        value: "1000000",
        merkle_path: Array(20).fill("0"),
        merkle_indices: Array(20).fill(0)
    },
    input_1: {
        secret: "789012",
        blinding: "222222",
        value: "500000",
        merkle_path: Array(20).fill("0"),
        merkle_indices: Array(20).fill(0)
    },
    output_0: {
        value: "1400000",
        blinding: "333333",
        recipient_spend_key_x: "...",
        recipient_spend_key_y: "...",
        recipient_view_key_x: "...",
        recipient_view_key_y: "...",
        ephemeral_key: "555555"
    },
    output_1: {
        value: "90000",
        blinding: "444444",
        // ... other fields
    },
    pub_inputs: {
        merkle_root: "...",
        input_nullifiers: ["...", "..."],
        output_commitments: ["...", "..."],
        fee: "10000"
    }
};
```

### Verify On-Chain (Solidity)
```solidity
// Import auto-generated UltraPlonk verifier
import "./UltraVerifier.sol";

contract PrivateTransfer {
    UltraVerifier public verifier;
    
    constructor(address _verifier) {
        verifier = UltraVerifier(_verifier);
    }

    function executeTransfer(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        require(verifier.verify(proof, publicInputs), "Invalid proof");
        // Process transfer...
    }
}
```

### Generate Solidity Verifier
```bash
cd noir/private_transfer
nargo codegen-verifier
# Outputs to contract/plonk_vk.sol
```

---

## Architecture

### Cryptographic Primitives

| Primitive | Implementation | Description |
|-----------|---------------|-------------|
| Hash | Poseidon BN254 | Circuit-efficient hash, ~300 constraints |
| Commitment | Pedersen-style (Poseidon) | H(domain, value, blinding) |
| Nullifier | H(NULLIFIER_DOMAIN, secret, commitment) | Double-spend prevention |
| Key Image | H(KEY_IMAGE_DOMAIN, secret, H(commitment)) | Ring signature linkability |
| Merkle Tree | Poseidon binary tree | UTXO membership proofs |
| Stealth Address | ECDH-style with Poseidon | Recipient privacy |

### Domain Separators

```noir
global CDNA_PREFIX: Field = 0x434e4441_76310000;      // "CDNA_v1"
global COMMITMENT_DOMAIN: Field = 0x434f4d4d49545f5631; // "COMMIT_V1"
global NULLIFIER_DOMAIN: Field = 0x4e554c4c5f5631;      // "NULL_V1"
global KEY_IMAGE_DOMAIN: Field = 0x4b4559494d475f5631;  // "KEYIMG_V1"
global STEALTH_DOMAIN: Field = 0x535445414c54485f5631; // "STEALTH_V1"
global RING_SIG_DOMAIN: Field = 0x52494e475349475f5631; // "RINGSIG_V1"
global CHALLENGE_DOMAIN: Field = 0x4348414c4c5f5631;    // "CHALL_V1"
global HASH_TO_POINT_DOMAIN: Field = 0x483250545f5631;  // "H2PT_V1"
```

---

## Security Considerations

### No Trusted Setup
Noir uses UltraPlonk which has a **universal trusted setup** (Aztec's Ignition ceremony), eliminating per-circuit trust requirements.

### Memory Safety
Noir is a memory-safe language with:
- No null pointers
- Bounds checking on arrays
- Explicit handling of optional values

### Constraint System
- UltraPlonk supports custom gates
- More efficient than R1CS for certain operations
- Native range check support

### Nullifier Security
- Domain separators prevent cross-protocol replay
- Chain ID binding prevents cross-chain replay
- Epoch-based evolution enables key rotation

### Range Proofs
- Native 64-bit range checks via `to_be_bits()`
- Compiler enforces bit decomposition correctness
- Overflow protection for balance equations

---

## Performance

### Proving Time (M1 MacBook Pro, Barretenberg)
| Circuit | Constraints | Proving Time | Memory |
|---------|-------------|--------------|--------|
| Cross-Domain Nullifier | ~8K | 1.5s | 400 MB |
| Private Transfer | ~40K | 6.2s | 1.5 GB |
| Ring Signature (8) | ~60K | 10.1s | 2.2 GB |

### Verification Time (On-Chain)
| Backend | Gas Cost |
|---------|----------|
| UltraPlonk | ~280,000 |

### Proof Size
| Format | Size |
|--------|------|
| UltraPlonk | ~2,000 bytes |

---

## Testing

```bash
# Run all circuit tests
cd noir/cross_domain_nullifier && nargo test
cd noir/private_transfer && nargo test
cd noir/ring_signature && nargo test

# Run specific test
nargo test test_commitment_determinism

# Generate test coverage
nargo test --show-coverage
```

### Test Vectors
Test vectors are automatically generated by the test functions and can be exported for integration testing.

---

## Migration from Circom

The Soul circuits were migrated from Circom to Noir for the following benefits:

| Feature | Circom | Noir |
|---------|--------|------|
| Type Safety | Limited | Full |
| Memory Safety | Manual | Automatic |
| Trusted Setup | Per-circuit | Universal |
| Standard Library | circomlib | std:: |
| Testing | snarkjs | Built-in |
| Debugging | Limited | Full stack traces |
| IDE Support | Minimal | VS Code extension |

### Breaking Changes
- Signal syntax changed to function parameters
- Template → struct + function
- component → direct function call
- `<==` constraint → `assert()` + assignment

---

## Future Improvements

1. **Recursive Proofs**: Noir 0.30+ supports recursive verification
2. **Folding Schemes**: Nova/SuperNova for incremental proving
3. **Multi-Proof Batching**: Aggregate multiple proofs
4. **Hardware Acceleration**: GPU proving via CUDA
5. **WASM Proving**: Browser-based proof generation

---

## References

- [Noir Documentation](https://noir-lang.org/docs)
- [Noir Standard Library](https://noir-lang.org/docs/noir/standard_library)
- [Barretenberg](https://github.com/AztecProtocol/barretenberg)
- [Poseidon Hash](https://eprint.iacr.org/2019/458.pdf)
- [CLSAG Ring Signatures](https://eprint.iacr.org/2019/654.pdf)
- [Stealth Addresses (ERC-5564)](https://eips.ethereum.org/EIPS/eip-5564)
- [UltraPlonk](https://docs.aztec.network/aztec/protocol/cryptography/plonk)
