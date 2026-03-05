# Aztec Integration Guide

> Integration guide for ZASEON's privacy bridge to Aztec — the privacy-first ZK-rollup using UltraHonk proofs via Noir circuits on BN254.

---

## Table of Contents

- [Architecture](#architecture)
- [Comparison: Aztec vs Other Privacy Chains](#comparison-aztec-vs-other-privacy-chains)
- [Contract Details](#contract-details)
- [Message Flow](#message-flow)
- [Pre-Existing Aztec Infrastructure in ZASEON](#pre-existing-aztec-infrastructure-in-zaseon)
- [Deployment](#deployment)
- [SDK Usage](#sdk-usage)
- [Security Considerations](#security-considerations)
- [Test Coverage](#test-coverage)

---

Aztec is a **privacy-first ZK-rollup** on Ethereum that uses **UltraHonk proofs** via **Noir circuits** on BN254. ZASEON integrates with Aztec through the `AztecBridgeAdapter`, enabling private cross-chain state transfer between Aztec's encrypted execution environment and ZASEON's privacy middleware.

## Architecture

```
┌─────────────┐                ┌──────────────────┐                ┌─────────────┐
│   ZASEON     │                │ AztecBridgeAdapter│                │  Aztec L2   │
│   Protocol   │◄──────────────►│  (L1 Contract)   │◄──────────────►│ (ZK-Rollup) │
│              │   IBridgeAdapter │                   │  RollupProcessor │              │
└─────────────┘                └──────────────────┘                └─────────────┘
       │                              │                                   │
       │  Proof aggregation           │  depositPendingFunds()            │  Noir circuits
       │  Nullifier tracking          │  withdrawMessage()                │  UltraHonk proofs
       │                              │  DeFi Bridge convert()            │  Encrypted notes
       ▼                              ▼                                   ▼
  CrossChainProofHub         Ethereum L1 Settlement           Private Execution Layer
```

## Comparison: Aztec vs Other Privacy Chains

| Feature             | Aztec            | Midnight      | Railgun             | Secret Network  |
| ------------------- | ---------------- | ------------- | ------------------- | --------------- |
| **Type**            | ZK-Rollup L2     | Custom L1     | EVM-native protocol | TEE-based L1    |
| **Proof System**    | UltraHonk (Noir) | PLONK         | Groth16             | N/A (TEE)       |
| **Settlement**      | Ethereum L1      | Own network   | Host EVM chain      | Own network     |
| **Privacy Model**   | Encrypted notes  | Shielded txns | Shielded UTXOs      | Encrypted state |
| **ZASEON Chain ID** | 4100             | 2100          | 3100                | N/A             |
| **Bridge Type**     | AZTEC (index 16) | MIDNIGHT (14) | RAILGUN (15)        | N/A             |

## Contract Details

### AztecBridgeAdapter.sol

- **Location**: `contracts/crosschain/AztecBridgeAdapter.sol`
- **Inherits**: `IBridgeAdapter`, `AccessControl`, `ReentrancyGuard`, `Pausable`
- **Constructor**: `(address _rollupProcessor, address _defiBridge, address _admin)`
- **Virtual chain ID**: `4100` (ZASEON internal)
- **Proof system**: UltraHonk via Noir on BN254
- **Finality**: 15 L1 blocks (Ethereum finality for rollup proofs)

### Key Functions

| Function                                   | Description                                           |
| ------------------------------------------ | ----------------------------------------------------- |
| `depositMessage(bytes32, bytes)`           | Deposit ZASEON state into Aztec's encrypted note tree |
| `withdrawMessage(bytes, uint256[], bytes)` | Verify Honk proof and consume Aztec withdrawal        |
| `bridgeMessage(address, bytes, address)`   | IBridgeAdapter-compliant bridging                     |
| `estimateFee(address, bytes)`              | Estimate native fee for deposit                       |
| `isMessageVerified(bytes32)`               | Check if a message has been processed                 |

### Roles

| Role                 | Purpose                                |
| -------------------- | -------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Full admin: config, unpause, emergency |
| `OPERATOR_ROLE`      | Deposit/bridge operations              |
| `GUARDIAN_ROLE`      | Emergency and guardian actions         |
| `RELAYER_ROLE`       | Relay withdrawal proofs from Aztec     |
| `PAUSER_ROLE`        | Pause the adapter                      |

## Message Flow

### ZASEON → Aztec (Deposit)

```
1. User/Operator calls depositMessage(noteCommitment, payload)
2. AztecBridgeAdapter calculates protocol fee
3. Calls RollupProcessor.depositPendingFunds() on L1
4. Aztec sequencer includes deposit in next rollup batch
5. Honk proof posted to L1, data tree updated
6. Encrypted note available in Aztec's private execution layer
```

### Aztec → ZASEON (Withdrawal)

```
1. User initiates withdrawal inside Aztec (private execution)
2. Aztec sequencer produces UltraHonk proof for the withdrawal
3. Proof published to L1
4. Relayer calls withdrawMessage(proof, publicInputs, payload)
5. DeFi bridge convert() validates the proof
6. Nullifier registered → double-spend protection
7. ZASEON state updated with received message
```

## Pre-Existing Aztec Infrastructure in ZASEON

- `NullifierType.AZTEC_NOTE = 7` in [NullifierClient.ts](../sdk/src/privacy/NullifierClient.ts)
- `CHAIN_DOMAINS.AZTEC` domain config in NullifierClient.ts
- `ChainVM.NOIR_AZTEC` in [IUniversalChainAdapter.sol](../contracts/interfaces/IUniversalChainAdapter.sol)
- `ProofSystem.HONK` mapped to NOIR_AZTEC in UniversalChainRegistry
- `@aztec/bb.js ^0.82.0` as SDK dependency for Barretenberg backend
- Formal verification planned in [FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md)

## Deployment

### Environment Variables

```bash
export AZTEC_ROLLUP_PROCESSOR=0x...   # Aztec Rollup Processor on L1
export AZTEC_DEFI_BRIDGE=0x...        # Aztec DeFi Bridge Proxy on L1
export MULTISIG_ADMIN=0x...           # Gnosis Safe admin
export DEPLOYER_PRIVATE_KEY=0x...     # Deployer key
export RELAYER_ADDRESS=0x...          # Relayer EOA (optional)
```

### Deploy Command

```bash
DEPLOY_TARGET=aztec forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $ETH_RPC --broadcast --verify -vvv
```

### Post-Deployment

1. Verify adapter via `isConfigured()` returns `true`
2. Grant `RELAYER_ROLE` to relayer address via multisig
3. Set bridge fee if desired via `setBridgeFee(bps)`
4. Register in MultiBridgeRouter with `BridgeType.AZTEC`

## SDK Usage

```typescript
import { AztecBridge } from "@zaseon/sdk/bridges";

// Check chain ID
console.log(AztecBridge.AZTEC_CHAIN_ID); // 4100

// Estimate fees
const fee = AztecBridge.estimateTotalFee(
  1000000000000000000n, // 1 ETH
  50, // 0.5% bridge fee
  5000000000000000n, // 0.005 ETH min fee
);

// Encode payload for deposit
const payload = AztecBridge.encodeZaseonPayload(
  1, // source: Ethereum
  "0xABCD...1234", // target note commitment
  new Uint8Array([0x01, 0x02, 0x03]),
);

// Check deployment
console.log(AztecBridge.isAztecDeployed(1)); // true (Ethereum)
console.log(AztecBridge.isAztecDeployed(42161)); // false
```

## Security Considerations

1. **UltraHonk Proofs**: Verified via Aztec's L1 verifier contracts (Barretenberg backend)
2. **Nullifier Protection**: Each Aztec note can only be spent once; nullifier tracked in ZASEON
3. **Data Root Validation**: Withdrawal proofs reference finalized data tree roots
4. **Settlement Security**: Aztec inherits Ethereum L1 security for proof finality
5. **DeFi Bridge Risk**: DeFi bridge interactions are subject to Aztec's bridge approval process
6. **Trusted Sequencer**: Current Aztec design uses a single sequencer (decentralization planned)

## Test Coverage

- 61+ tests covering all contract functions
- Fuzz testing with 10,000 runs for fee bounds and payload variants
- Constructor validation (zero-address checks)
- Deposit/withdrawal flows with proof verification
- Replay protection via nullifier uniqueness
- IBridgeAdapter compliance tests
- Pause/unpause and emergency withdrawal tests

Run Aztec tests:

```bash
forge test --match-path "test/crosschain/AztecBridgeAdapter.t.sol" --skip "AggregatorHonkVerifier" -vvv
```
