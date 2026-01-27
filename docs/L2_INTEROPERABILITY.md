# L2 Interoperability Guide

> **Soul native integration with Arbitrum, Optimism, Base, and zkEVM networks**

[![L2s](https://img.shields.io/badge/L2s-Arbitrum%20|%20Optimism%20|%20Base%20|%20zkSync-blue.svg)]()

---

## Table of Contents

- [Supported Networks](#supported-networks)
- [Architecture](#architecture)
  - [Arbitrum Integration](#arbitrum-integration)
  - [Optimism Integration](#optimism-integration)
  - [Base Integration](#base-integration)
- [Contract Interfaces](#contract-interfaces)
- [Usage Examples](#usage-examples)
- [Deployment](#deployment)
- [Security Considerations](#security-considerations)
- [Testnet Faucets](#testnet-faucets)

---

**Features:** Proof Relay • State Sync • Nullifier Propagation • USDC via CCTP (Base)

## Supported Networks

| Network | Chain ID | Type | Adapter Contract |
|---------|----------|------|------------------|
| Arbitrum One | 42161 | Optimistic Rollup | `ArbitrumBridgeAdapter.sol` |
| Arbitrum Nova | 42170 | AnyTrust | `ArbitrumBridgeAdapter.sol` |
| Arbitrum Sepolia | 421614 | Testnet | `ArbitrumBridgeAdapter.sol` |
| Optimism | 10 | OP Stack | `OptimismBridgeAdapter.sol` |
| Optimism Sepolia | 11155420 | Testnet | `OptimismBridgeAdapter.sol` |
| Base | 8453 | OP Stack | `BaseBridgeAdapter.sol` |
| Base Sepolia | 84532 | Testnet | `BaseBridgeAdapter.sol` |
| zkSync Era | 324 | ZK Rollup | `L2ChainAdapter.sol` |
| Scroll | 534352 | zkEVM | `L2ChainAdapter.sol` |
| Linea | 59144 | zkEVM | `L2ChainAdapter.sol` |
| Polygon zkEVM | 1101 | zkEVM | `L2ChainAdapter.sol` |

## Architecture

### Arbitrum Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Soul <-> Arbitrum Bridge                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐           ┌───────────────────┐                 │
│  │   Soul Protocol    │           │   Arbitrum        │                 │
│  │  (L1 Ethereum)    │           │   (L2 Rollup)     │                 │
│  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
│  │  │ Delayed     │  │           │  │ ArbOS       │  │                 │
│  │  │ Inbox       │  │──────────►│  │ Execution   │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  │        │          │           │        │          │                 │
│  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
│  │  │ Outbox      │  │◄──────────│  │ L2 to L1   │  │                 │
│  │  │ Proof       │  │           │  │ Messages   │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  └───────────────────┘           └───────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- Retryable Tickets for guaranteed L1→L2 delivery
- Outbox Merkle proofs for L2→L1 verification
- ~7 day challenge period for withdrawals
- Native ETH bridging

### Optimism Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Soul <-> Optimism Bridge                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐           ┌───────────────────┐                 │
│  │   Soul Protocol    │           │   Optimism        │                 │
│  │  (L1 Ethereum)    │           │   (L2 OP Stack)   │                 │
│  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
│  │  │ L1 Cross    │  │           │  │ L2 Cross    │  │                 │
│  │  │ Domain      │  │──────────►│  │ Domain      │  │                 │
│  │  │ Messenger   │  │           │  │ Messenger   │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  │        │          │           │        │          │                 │
│  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
│  │  │ Optimism    │  │◄──────────│  │ L2 to L1   │  │                 │
│  │  │ Portal      │  │           │  │ Messages   │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  └───────────────────┘           └───────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- CrossDomainMessenger for bidirectional messaging
- Bedrock upgrade with modular architecture
- Fault proofs for dispute resolution
- ~7 day withdrawal period

### Base Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Soul <-> Base Bridge                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Features unique to Base:                                               │
│  - OP Stack architecture (same as Optimism)                             │
│  - Native USDC via Circle's CCTP                                        │
│  - Coinbase attestation integration                                     │
│  - Coinbase ecosystem (wallet, commerce, etc.)                          │
│                                                                         │
│  CCTP Domains:                                                          │
│  - Ethereum: 0                                                          │
│  - Base: 6                                                              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- Same OP Stack as Optimism
- CCTP for native USDC (no wrapped tokens)
- Coinbase Verifications (on-chain attestations)
- Lower fees than Ethereum mainnet

## Contract Interfaces

### ArbitrumBridgeAdapter

```solidity
// Send proof to Arbitrum L2
function sendProofToL2(
    bytes32 proofHash,
    bytes calldata proof,
    bytes calldata publicInputs,
    uint256 gasLimit,
    uint256 maxSubmissionCost
) external payable returns (bytes32 ticketId);

// Create retryable ticket
function createRetryableTicket(
    address l2Target,
    bytes calldata data,
    uint256 gasLimit,
    uint256 maxSubmissionCost,
    uint256 gasPriceBid
) external payable returns (bytes32 ticketId);

// Receive proof from L1 (on L2)
function receiveProofFromL1(
    bytes32 proofHash,
    bytes calldata proof,
    bytes calldata publicInputs
) external;
```

### OptimismBridgeAdapter

```solidity
// Send proof to Optimism L2
function sendProofToL2(
    bytes32 proofHash,
    bytes calldata proof,
    bytes calldata publicInputs,
    uint256 gasLimit
) external payable returns (bytes32 messageId);

// Initiate withdrawal to L1
function initiateWithdrawal(
    bytes32 proofHash
) external payable returns (bytes32 withdrawalId);

// Complete withdrawal on L1 (after 7 days)
function completeWithdrawal(
    bytes32 withdrawalId
) external;

// Sync state root to L2
function syncStateToL2(
    bytes32 stateRoot,
    uint256 blockNumber,
    uint256 gasLimit
) external returns (bytes32 messageId);
```

### BaseBridgeAdapter

```solidity
// All Optimism functions plus:

// Initiate USDC transfer via CCTP
function initiateUSDCTransfer(
    address recipient,
    uint256 amount,
    uint32 destDomain
) external returns (bytes32 transferId);

// Complete CCTP transfer
function completeCCTPTransfer(
    bytes32 transferId,
    bytes calldata message,
    bytes calldata attestation
) external;

// Sync Coinbase attestation
function syncAttestation(
    bytes32 attestationId,
    address subject,
    bytes32 schemaId,
    bytes calldata data
) external;
```

### L2ChainAdapter (Generic)

```solidity
// Add new L2 chain configuration
function addChain(
    uint256 chainId,
    string memory name,
    address bridge,
    address messenger,
    uint256 confirmations,
    uint256 gasLimit
) external;

// Send message to L2
function sendMessage(
    uint256 targetChain,
    address target,
    bytes calldata payload,
    uint256 gasLimit
) external payable returns (bytes32 messageId);

// Get supported chains
function getSupportedChains() external view returns (uint256[] memory);
```

## Usage Examples

### Relay Proof from Ethereum to Arbitrum

```typescript
import { ethers } from "ethers";

// Connect to contracts
const l1Adapter = new ethers.Contract(
  ARBITRUM_BRIDGE_ADAPTER_L1,
  ArbitrumBridgeAdapterABI,
  l1Signer
);

// Prepare proof
const proofHash = ethers.keccak256(proof);
const gasLimit = 1_000_000n;
const maxSubmissionCost = ethers.parseEther("0.01");
const gasPriceBid = ethers.parseGwei("0.1");

// Calculate total ETH needed
const totalValue = maxSubmissionCost + gasLimit * gasPriceBid;

// Send proof to L2
const tx = await l1Adapter.sendProofToL2(
  proofHash,
  proof,
  publicInputs,
  gasLimit,
  maxSubmissionCost,
  { value: totalValue }
);

const receipt = await tx.wait();
console.log("Retryable ticket created:", receipt.hash);
```

### Relay Proof from Ethereum to Base

```typescript
// Connect to Base adapter
const baseAdapter = new ethers.Contract(
  BASE_BRIDGE_ADAPTER_L1,
  BaseBridgeAdapterABI,
  l1Signer
);

// Send proof
const tx = await baseAdapter.sendProofToL2(
  proofHash,
  proof,
  publicInputs,
  1_000_000n,
  { value: ethers.parseEther("0.001") }
);

await tx.wait();
```

### Bridge USDC via CCTP (Base)

```typescript
// Approve USDC
const usdc = new ethers.Contract(USDC_ADDRESS, ERC20ABI, signer);
await usdc.approve(BASE_BRIDGE_ADAPTER, amount);

// Initiate CCTP transfer
const tx = await baseAdapter.initiateUSDCTransfer(
  recipientOnBase,
  amount,
  6 // Base CCTP domain
);

const receipt = await tx.wait();
const transferId = receipt.logs[0].args.transferId;

// On Base: complete transfer with Circle attestation
await baseAdapterL2.completeCCTPTransfer(
  transferId,
  cctpMessage,
  circleAttestation
);
```

## Deployment

### Deploy L2 Adapters

```bash
# Deploy to Arbitrum Sepolia
npx hardhat run scripts/deploy-l2-adapters.ts --network arbitrumSepolia

# Deploy to Base Sepolia  
npx hardhat run scripts/deploy-l2-adapters.ts --network baseSepolia

# Deploy to Optimism Sepolia
npx hardhat run scripts/deploy-l2-adapters.ts --network optimismSepolia
```

### Configuration

Each adapter needs to be configured with the correct messenger addresses:

| Network | L1 CrossDomainMessenger | L2 CrossDomainMessenger |
|---------|-------------------------|-------------------------|
| Arbitrum | `0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f` | (ArbSys) |
| Optimism | `0x25ace71c97B33Cc4729CF772ae268934F7ab5fA1` | `0x4200000000000000000000000000000000000007` |
| Base | `0x866E82a600A1414e583f7F13623F1aC5d58b0Afa` | `0x4200000000000000000000000000000000000007` |

## Security Considerations

| Aspect | Details |
|--------|--------|
| **Challenge Period** | All optimistic rollups: ~7 days for L2→L1 messages |
| **Message Verification** | Always verify `msg.sender == l2CrossDomainMessenger` |
| **Gas Limits** | Proof relay: 500K-1M gas • State sync: 200K-500K • Simple ops: 100K-200K |

## Testnet Faucets

Arbitrum/Optimism/Base Sepolia: [Alchemy Faucets](https://www.alchemy.com/faucets) | Sepolia L1: [sepoliafaucet.com](https://sepoliafaucet.com)

## See Also

[BRIDGE_INTEGRATION.md](./BRIDGE_INTEGRATION.md) • [ETHEREUM_INTEROPERABILITY.md](./ETHEREUM_INTEROPERABILITY.md) • [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md)
