# Privacy Interoperability Layer (PIL)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-blue.svg)](https://docs.soliditylang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

Cross-chain middleware for private state transfer and zero-knowledge proof verification across heterogeneous blockchain networks.

## Features

- **Confidential State Management** - AES-256-GCM encrypted state containers with ZK proof verification
- **Cross-Chain ZK Bridge** - Transfer proofs between different ZK systems (Groth16, PLONK, FRI-based)
- **Relayer Network** - Decentralized proof aggregation with staking and slashing
- **Atomic Swaps** - HTLC-based private cross-chain swaps with stealth commitments
- **Compliance Layer** - Optional KYC/AML with zero-knowledge selective disclosure

### PIL v2 Novel Primitives

- **PC³ (Proof-Carrying Containers)** - Self-authenticating confidential containers with embedded proofs
- **PBP (Policy-Bound Proofs)** - Proofs cryptographically scoped by disclosure policy
- **EASC (Execution-Agnostic State Commitments)** - Backend-independent state verification
- **CDNA (Cross-Domain Nullifier Algebra)** - Domain-separated nullifiers for cross-chain replay protection

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Privacy Interoperability Layer                │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6: TEE Attestation                                       │
│  SGX (EPID/DCAP) | TDX | SEV-SNP | TrustZone                    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5: PIL v2 Primitives                                     │
│  PC³ | PBP | EASC | CDNA | HH | ADA | CRP                       │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: Execution Sandbox                                     │
│  PILAtomicSwap  |  PILCompliance  |  PILOracle                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Relayer Network                                       │
│  CrossChainProofHub + Staking + Slashing                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Proof Translation                                     │
│  Groth16 (BN254/BLS12-381) | PLONK | FRI/STARK                  │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Confidential State                                    │
│  ConfidentialStateContainer + NullifierRegistry                 │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Description |
|-------|-------------|
| TEE Attestation | Hardware-based attestation for trusted execution environments |
| PIL v2 Primitives | Novel cryptographic primitives for advanced privacy operations |
| Confidential State | Encrypted state storage with Pedersen commitments and nullifier tracking |
| Proof Translation | Verifiers for different ZK systems with proof format conversion |
| Relayer Network | Decentralized relayer infrastructure with staking and slashing |
| Execution Sandbox | High-level applications (swaps, compliance, oracles) |

## Project Structure

```
├── contracts/           # Solidity smart contracts
│   ├── core/           # State container, verifiers, nullifier registry
│   ├── bridge/         # Cross-chain proof hub, atomic swaps
│   ├── compliance/     # KYC/AML modules
│   ├── primitives/     # PIL v2 primitives (PC³, PBP, EASC, CDNA)
│   ├── security/       # Time-locked admin, security infrastructure
│   └── infrastructure/ # Oracles, rate limiting, governance
├── circuits/           # Circom ZK circuits
├── sdk/                # TypeScript SDK
├── specs/              # Formal verification specifications
├── relayer/            # Relayer node service
├── test/               # Test suites
└── docs/               # Documentation
```

## Security Features

### Time-Locked Admin Operations

All sensitive administrative operations go through the `PILTimelock` contract:

- **48-hour minimum delay** for standard operations
- **6-hour emergency delay** for critical operations
- **Multi-confirmation** required before execution
- **7-day grace period** after ready time
- **Predecessor ordering** for dependent operations

```solidity
// Schedule a pause operation
bytes32 opId = timelockAdmin.schedulePausePC3(salt);

// Wait for delay...
// Get confirmations...

// Execute after ready time
timelock.execute(target, 0, data, predecessor, salt);
```

### Formal Verification

The codebase includes formal verification specifications in `specs/`:

- `FormalVerification.spec` - High-level invariants and safety properties
- `PC3.spec` - Certora rules for ProofCarryingContainer
- `Timelock.spec` - Certora rules for PILTimelock

Run with Certora Prover:
```bash
certoraRun specs/PC3.spec --contract ProofCarryingContainer
```

## Quick Start

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

### Installation

```bash
git clone https://github.com/soul-research-labs/PIL.git
cd PIL

npm install
npm run compile
```

### Running Tests

```bash
# Run all tests
npm test

# Run with gas reporting
REPORT_GAS=true npm test
```

### Deployment

```bash
# Local network
npx hardhat run scripts/deploy.js --network localhost

# Sepolia testnet
npx hardhat run scripts/deploy.js --network sepolia
```

## Core Contracts

### ConfidentialStateContainer

Manages encrypted confidential states with ZK proof verification.

```solidity
function registerState(
    bytes calldata encryptedState,
    bytes32 commitment,
    bytes32 nullifier,
    bytes calldata proof,
    bytes calldata publicInputs
) external;

function transferState(
    bytes32 oldCommitment,
    bytes calldata newEncryptedState,
    bytes32 newCommitment,
    bytes32 newNullifier,
    bytes calldata proof,
    bytes calldata publicInputs,
    address newOwner
) external;
```

### CrossChainProofHub

Aggregates and relays proofs across chains with gas-optimized batching.

```solidity
function submitProof(
    uint256 destChain,
    bytes calldata proof,
    bytes calldata publicInputs
) external returns (bytes32 messageId);

function registerRelayer() external payable;
function claimBatch(bytes32 batchId) external;
```

### PILAtomicSwap

HTLC-based atomic swaps with stealth address support.

```solidity
function createSwapETH(
    address recipient,
    bytes32 hashLock,
    uint256 timeLock,
    bytes32 commitment
) external payable returns (bytes32 swapId);

function claim(bytes32 swapId, bytes32 secret) external;
```

## PIL v2 Primitives

### ProofCarryingContainer (PC³)

Self-authenticating confidential containers that carry their own correctness and policy proofs.

```solidity
// Create a container with embedded proofs
function createContainer(
    bytes calldata encryptedPayload,
    bytes32 stateCommitment,
    bytes32 nullifier,
    ProofBundle calldata proofs,
    bytes32 policyHash
) external returns (bytes32 containerId);

// Verify container proofs
function verifyContainer(bytes32 containerId) external view returns (VerificationResult memory);

// Consume container (marks nullifier as used)
function consumeContainer(bytes32 containerId) external;

// Export for cross-chain transfer
function exportContainer(bytes32 containerId) external view returns (bytes memory);
```

### PolicyBoundProofs (PBP)

Proofs that are cryptographically scoped by disclosure policy.

```solidity
// Register a disclosure policy
function registerPolicy(DisclosurePolicy calldata policy) external returns (bytes32 policyId);

// Bind verification key to policy
function bindVerificationKey(bytes32 vkHash, bytes32 policyHash) external returns (bytes32 domainSeparator);

// Verify a policy-bound proof
function verifyBoundProof(BoundProof calldata proof, bytes32 vkHash) external returns (VerificationResult memory);
```

### ExecutionAgnosticStateCommitments (EASC)

State commitments that are valid across different execution backends (zkVM, TEE, MPC).

```solidity
// Register an execution backend
function registerBackend(
    BackendType backendType,
    string calldata name,
    bytes32 attestationKey,
    bytes32 configHash
) external returns (bytes32 backendId);

// Create execution-agnostic commitment
function createCommitment(
    bytes32 stateHash,
    bytes32 transitionHash,
    bytes32 nullifier
) external returns (bytes32 commitmentId);

// Attest commitment from a backend
function attestCommitment(
    bytes32 commitmentId,
    bytes32 backendId,
    bytes calldata attestationProof,
    bytes32 executionHash
) external;
```

### CrossDomainNullifierAlgebra (CDNA)

Domain-separated nullifiers that compose across chains, epochs, and applications.

```solidity
// Register a domain for nullifier separation
function registerDomain(
    uint64 chainId,
    bytes32 appId,
    uint64 epochEnd
) external returns (bytes32 domainId);

// Register a nullifier in a domain
function registerNullifier(
    bytes32 domainId,
    bytes32 nullifierValue,
    bytes32 commitmentHash,
    bytes32 transitionId
) external returns (bytes32 nullifier);

// Derive cross-domain nullifier
function registerDerivedNullifier(
    bytes32 parentNullifier,
    bytes32 targetDomainId,
    bytes32 transitionId,
    bytes calldata derivationProof
) external returns (bytes32 childNullifier);

// Consume nullifier (prevent double-spend)
function consumeNullifier(bytes32 nullifier) external;
```

### PILv2Orchestrator

Integrates all PIL v2 primitives for coordinated workflows.

```solidity
// Create policy-bound commitment
function createPolicyBoundCommitment(
    bytes32 stateHash,
    bytes32 transitionHash,
    bytes32 nullifier,
    bytes32 policyId
) external returns (bytes32 commitmentId);

// Create coordinated transition across all primitives
function createCoordinatedTransition(
    bytes32 containerId,
    bytes32 containerNullifier,
    bytes32 stateHash,
    bytes32 transitionHash,
    bytes32 domainId,
    bytes32 policyId
) external returns (bytes32 transitionId);
```

## SDK Usage

```typescript
import { PILSDK, PILv2ClientFactory } from '@pil/sdk';

const sdk = new PILSDK({
  rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY',
  contracts: {
    stateContainer: '0x...',
    proofHub: '0x...',
    atomicSwap: '0x...'
  }
});

await sdk.initialize();

// Send private state cross-chain
const receipt = await sdk.sendPrivateState({
  targetChain: 137,
  encryptedState: await sdk.encrypt(data, recipientPubKey),
  proof: await sdk.generateProof('state_transfer', inputs)
});

// PIL v2 Primitives Usage
const pilv2 = new PILv2ClientFactory({
  proofCarryingContainer: '0x...',
  policyBoundProofs: '0x...',
  executionAgnosticStateCommitments: '0x...',
  crossDomainNullifierAlgebra: '0x...'
}, provider);

// Create a self-authenticating container
const pc3 = pilv2.proofCarryingContainer();
const { containerId } = await pc3.createContainer({
  encryptedPayload: '0x...',
  stateCommitment: '0x...',
  nullifier: '0x...',
  validityProof: '0x...',
  policyProof: '0x...',
  nullifierProof: '0x...',
  proofExpiry: Math.floor(Date.now() / 1000) + 86400,
  policyHash: '0x...'
});

// Register a disclosure policy
const pbp = pilv2.policyBoundProofs();
const { policyId } = await pbp.registerPolicy({
  name: 'KYC Compliant',
  description: 'Requires identity verification',
  requiresIdentity: true,
  requiresJurisdiction: true,
  requiresAmount: false,
  requiresCounterparty: false,
  minAmount: 0n,
  maxAmount: ethers.MaxUint256,
  allowedAssets: [],
  blockedCountries: [],
  expiresAt: 0
});
```

## Gas Costs

| Function | Average Gas | Notes |
|----------|-------------|-------|
| registerState | ~160,000 | First-time state registration |
| transferState | ~164,000 | State ownership transfer |
| submitProof | ~275,000 | Optimized (67% reduction from v1) |
| createSwapETH | ~248,000 | HTLC swap initiation |
| claim | ~51,000 | Swap claim with secret |

## Security

- OpenZeppelin security patterns (Ownable, ReentrancyGuard, Pausable)
- AES-256-GCM encryption for state data
- Pedersen commitments with hiding/binding properties
- Nullifier-based double-spend prevention
- Relayer staking with slashing for misbehavior

## Testing

```bash
npm test                    # Run all tests (281 passing)
npm run test:integration    # Integration tests only
REPORT_GAS=true npm test    # With gas reporting
```

### PIL v2 Primitives Tests

```bash
# Run PIL v2 primitives tests
npx hardhat test test/PILv2Primitives.test.js
```

Test coverage includes:
- Container creation, verification, and consumption
- Policy registration and binding
- Multi-backend attestation
- Cross-domain nullifier operations
- Batch operations for all primitives
- End-to-end integration tests
- Gas usage benchmarks

## Roadmap

- [x] Core protocol (state container, verifiers, nullifiers)
- [x] Cross-chain infrastructure (proof hub, relayers, swaps)
- [x] Compliance layer (KYC/AML)
- [x] PIL v2 primitives (PC³, PBP, EASC, CDNA)
- [x] PIL v2 orchestrator integration
- [x] SDK clients for PIL v2 primitives
- [x] PLONK verifier (universal trusted setup support)
- [x] FRI verifier (STARK proof support, transparent setup)
- [x] TEE attestation integration (SGX, TDX, SEV-SNP)
- [x] Homomorphic Hiding (HH) - research grade
- [x] Aggregate Disclosure Algebra (ADA) - research grade
- [x] Composable Revocation Proofs (CRP) - research grade
- [x] Comprehensive test suite (281 tests passing)
- [x] Local testnet deployment complete
- [ ] Professional security audit
- [ ] Testnet deployment (Sepolia)
- [ ] Mainnet deployment

## Proof System Support

| System | Contract | Status |
|--------|----------|--------|
| Groth16 (BN254) | `Groth16VerifierBN254.sol` | ✅ Production |
| Groth16 (BLS12-381) | `Groth16VerifierBLS12381.sol` | ✅ Production |
| PLONK | `PLONKVerifier.sol` | ✅ Production |
| FRI/STARK | `FRIVerifier.sol` | ✅ Production |

## TEE Support

| Platform | Description | Status |
|----------|-------------|--------|
| Intel SGX EPID | Legacy attestation | ✅ Supported |
| Intel SGX DCAP | Modern datacenter attestation | ✅ Supported |
| Intel TDX | Trust Domain Extensions | ✅ Supported |
| AMD SEV-SNP | Secure Encrypted Virtualization | ✅ Supported |
| ARM TrustZone | Mobile TEE | 🔄 Planned |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/name`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/name`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Deployments

### Local Testnet (Hardhat)

Deployed to localhost (Chain ID: 31337):

| Contract | Address |
|----------|--------|
| VerifierRegistry | `0x67d269191c92Caf3cD7723F116c85e6E9bf55933` |
| Groth16VerifierBN254 | `0xE6E340D132b5f46d1e472DebcD681B2aBc16e57E` |
| PLONKVerifier | `0xc3e53F4d16Ae77Db1c982e75a937B9f60FE63690` |
| FRIVerifier | `0x84eA74d481Ee0A5332c457a4d796187F6Ba67fEB` |
| TEEAttestation | `0x9E545E3C0baAB3E08CdfD552C960A1050f373042` |
| ProofCarryingContainer | `0xa82fF9aFd8f496c3d6ac40E2a0F282E47488CFc9` |
| PolicyBoundProofs | `0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8` |
| ExecutionAgnosticStateCommitments | `0x851356ae760d987E095750cCeb3bC6014560891C` |
| CrossDomainNullifierAlgebra | `0xf5059a5D33d5853360D16C683c16e67980206f36` |
| PILv2Orchestrator | `0x95401dc811bb5740090279Ba06cfA8fcF6113778` |
| PILTimelock | `0x998abeb3E57409262aE5b751f60747921B33613E` |
| TimelockAdmin | `0x70e0bA845a1A0F2DA3359C97E0285013525FFC49` |

### Sepolia Testnet

To deploy to Sepolia:

1. Copy `.env.example` to `.env` and add your private key
2. Get Sepolia ETH from [sepoliafaucet.com](https://sepoliafaucet.com)
3. Run: `npx hardhat run scripts/deploy-pilv2-testnet.js --network sepolia`

## Documentation

- [Architecture Guide](docs/architecture.md)
- [Gas Optimization Report](docs/gas-optimization-report.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [API Documentation](docs/README.md)
