# L2 Interoperability Guide

> **Zaseon native integration with Arbitrum, Optimism, Base, zkSync Era, Scroll, Linea, and cross-chain messaging protocols**

[![L2s](https://img.shields.io/badge/L2s-Arbitrum%20|%20Optimism%20|%20Base%20|%20zkSync%20|%20Scroll%20|%20Linea-blue.svg)]()

---

## Table of Contents

- [Supported Networks](#supported-networks)
- [Architecture](#architecture)
  - [Arbitrum Integration](#arbitrum-integration)
  - [Optimism Integration](#optimism-integration)
  - [Base Integration](#base-integration)
  - [zkSync Era Integration](#zksync-era-integration)
  - [Scroll Integration](#scroll-integration)
  - [Linea Integration](#linea-integration)
- [Cross-Chain Messaging Protocols](#cross-chain-messaging-protocols)
  - [LayerZero V2](#layerzero-v2)
  - [Hyperlane](#hyperlane)
- [Contract Interfaces](#contract-interfaces)
- [Usage Examples](#usage-examples)
- [Deployment](#deployment)
- [Security Considerations](#security-considerations)
- [Testnet Faucets](#testnet-faucets)

---

**Features:** Proof Relay • State Sync • Nullifier Propagation • USDC via CCTP (Base) • ZK Finality (zkSync/Scroll/Linea)

## Supported Networks

### Native L2 Adapters

| Network          | Chain ID | Type              | Adapter Contract            | Status        |
| ---------------- | -------- | ----------------- | --------------------------- | ------------- |
| Arbitrum One     | 42161    | Optimistic Rollup | `ArbitrumBridgeAdapter.sol` | ✅ Production |
| Arbitrum Nova    | 42170    | AnyTrust          | `ArbitrumBridgeAdapter.sol` | ✅ Production |
| Arbitrum Sepolia | 421614   | Testnet           | `ArbitrumBridgeAdapter.sol` | ✅ Production |
| Optimism         | 10       | OP Stack          | `OptimismBridgeAdapter.sol` | ✅ Production |
| Optimism Sepolia | 11155420 | Testnet           | `OptimismBridgeAdapter.sol` | ✅ Production |
| Base             | 8453     | OP Stack          | `BaseBridgeAdapter.sol`     | ✅ Production |
| Base Sepolia     | 84532    | Testnet           | `BaseBridgeAdapter.sol`     | ✅ Production |
| zkSync Era       | 324      | ZK Rollup         | `zkSyncBridgeAdapter.sol`   | ✅ Production |
| zkSync Sepolia   | 300      | Testnet           | `zkSyncBridgeAdapter.sol`   | ✅ Production |
| Scroll           | 534352   | zkEVM             | `ScrollBridgeAdapter.sol`   | ✅ Production |
| Scroll Sepolia   | 534351   | Testnet           | `ScrollBridgeAdapter.sol`   | ✅ Production |
| Linea            | 59144    | zkEVM             | `LineaBridgeAdapter.sol`    | ✅ Production |
| Linea Sepolia    | 59141    | Testnet           | `LineaBridgeAdapter.sol`    | ✅ Production |

### Cross-Chain Messaging Protocols

| Protocol  | Adapter                | Chains Supported | Status        |
| --------- | ---------------------- | ---------------- | ------------- |
| LayerZero | `LayerZeroAdapter.sol` | 120+             | ✅ Production |
| Hyperlane | `HyperlaneAdapter.sol` | 60+              | ✅ Production |

### Planned

| Network       | Chain ID | Adapter                     | Priority |
| ------------- | -------- | --------------------------- | -------- |
| Polygon zkEVM | 1101     | `PolygonZkEVMBridgeAdapter` | Medium   |
| Starknet      | —        | `StarknetBridgeAdapter`     | Medium   |

## Architecture

### Arbitrum Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zaseon <-> Arbitrum Bridge                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐           ┌───────────────────┐                 │
│  │   ZASEON    │           │   Arbitrum        │                 │
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
│                    Zaseon <-> Optimism Bridge                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐           ┌───────────────────┐                 │
│  │   ZASEON    │           │   Optimism        │                 │
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
│                    Zaseon <-> Base Bridge                                  │
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

### zkSync Era Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zaseon <-> zkSync Era Bridge                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐           ┌───────────────────┐                 │
│  │   ZASEON           │           │   zkSync Era      │                 │
│  │  (L1 Ethereum)    │           │   (L2 ZK Rollup)  │                 │
│  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
│  │  │ Diamond     │  │           │  │ Bootloader  │  │                 │
│  │  │ Proxy       │  │──────────►│  │ Execution   │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  │        │          │           │        │          │                 │
│  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
│  │  │ ZK Proof    │  │◄──────────│  │ L2→L1      │  │                 │
│  │  │ Verification│  │           │  │ Messages   │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  └───────────────────┘           └───────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**

- ZK validity proofs — no challenge period
- ~1 hour finality (proof generation + verification)
- Diamond Proxy architecture for upgrades
- Native account abstraction

### Scroll Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zaseon <-> Scroll Bridge                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐           ┌───────────────────┐                 │
│  │   ZASEON           │           │   Scroll          │                 │
│  │  (L1 Ethereum)    │           │   (L2 zkEVM)      │                 │
│  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
│  │  │ L1 Scroll   │  │           │  │ L2 Scroll   │  │                 │
│  │  │ Messenger   │  │──────────►│  │ Messenger   │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  │        │          │           │        │          │                 │
│  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
│  │  │ Rollup      │  │◄──────────│  │ Batch       │  │                 │
│  │  │ Contract    │  │           │  │ Submission  │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  └───────────────────┘           └───────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**

- zkEVM — bytecode-level EVM compatibility
- ~4 hour finality (batch proof generation)
- L1ScrollMessenger + L1GatewayRouter for messaging
- L1MessageQueue for ordered message delivery

### Linea Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zaseon <-> Linea Bridge                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────┐           ┌───────────────────┐                 │
│  │   ZASEON           │           │   Linea           │                 │
│  │  (L1 Ethereum)    │           │   (L2 zkEVM)      │                 │
│  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
│  │  │ L1 Message  │  │           │  │ L2 Message  │  │                 │
│  │  │ Service     │  │──────────►│  │ Service     │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  │        │          │           │        │          │                 │
│  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
│  │  │ ZK Proof    │  │◄──────────│  │ Batch       │  │                 │
│  │  │ Verification│  │           │  │ Finalization │  │                 │
│  │  └─────────────┘  │           │  └─────────────┘  │                 │
│  └───────────────────┘           └───────────────────┘                 │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**

- Consensys zkEVM with lattice-based proof system
- L1MessageService + TokenBridge for cross-chain messaging
- Multi-hour finality (batch proof generation + verification)
- Automatic message claiming through postman service

### LayerZero Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zaseon <-> LayerZero V2                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐           │
│  │  Source Chain │     │   LayerZero  │     │  Dest Chain  │           │
│  │              │     │   Protocol   │     │              │           │
│  │ ┌──────────┐ │     │ ┌──────────┐ │     │ ┌──────────┐ │           │
│  │ │ LZ       │ │────►│ │ DVN      │ │────►│ │ LZ       │ │           │
│  │ │ Endpoint │ │     │ │ + Exec   │ │     │ │ Endpoint │ │           │
│  │ └──────────┘ │     │ └──────────┘ │     │ └──────────┘ │           │
│  └──────────────┘     └──────────────┘     └──────────────┘           │
│                                                                         │
│  Supported Chains: All 7 L2s + Ethereum mainnet                         │
│  Security: Configurable DVN threshold (default 2-of-3)                  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**

- Omnichain messaging across all supported L2s
- Decentralized Verifier Networks (DVN) for security
- Configurable security with DVN thresholds
- Gas abstraction via Executor framework

### Hyperlane Integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Zaseon <-> Hyperlane                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐           │
│  │  Source Chain │     │  Hyperlane   │     │  Dest Chain  │           │
│  │              │     │  Validators  │     │              │           │
│  │ ┌──────────┐ │     │ ┌──────────┐ │     │ ┌──────────┐ │           │
│  │ │ Mailbox  │ │────►│ │ ISM      │ │────►│ │ Mailbox  │ │           │
│  │ │          │ │     │ │ Verify   │ │     │ │          │ │           │
│  │ └──────────┘ │     │ └──────────┘ │     │ └──────────┘ │           │
│  └──────────────┘     └──────────────┘     └──────────────┘           │
│                                                                         │
│  Supported Chains: All 7 L2s + Ethereum mainnet                         │
│  Security: Interchain Security Modules (ISM) per route                  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**

- Permissionless deployment on any EVM chain
- Interchain Security Modules (ISM) for customizable verification
- Mailbox-based dispatch/handle pattern
- Sovereign consensus per route (multisig, optimistic, ZK)

## Contract Interfaces

### ArbitrumBridgeAdapter

```solidity
function deposit(uint256 chainId, address l2Recipient, address l1Token,
    uint256 amount, uint256 submissionCost, uint256 l2GasLimit,
    uint256 l2GasPrice) external payable returns (bytes32 depositId);

// Claim withdrawal with Outbox verification
// Uses outbox.isSpent(index) for direct callers
function claimWithdrawal(bytes32 withdrawalId, bytes32[] calldata proof,
    uint256 index) external;
```

### OptimismBridgeAdapter

```solidity
function sendProofToL2(bytes32 proofHash, bytes calldata proof,
    bytes calldata publicInputs, uint256 gasLimit) external payable returns (bytes32 messageId);

function initiateWithdrawal(bytes32 proofHash) external payable returns (bytes32 withdrawalId);

function completeWithdrawal(bytes32 withdrawalId) external;
```

### BaseBridgeAdapter

```solidity
// All Optimism functions plus:
function initiateUSDCTransfer(address recipient, uint256 amount,
    uint32 destDomain) external returns (bytes32 transferId);

function completeCCTPTransfer(bytes32 transferId, bytes calldata message,
    bytes calldata attestation) external;
```

### zkSyncBridgeAdapter

```solidity
function deposit(uint256 chainId, address l2Recipient, address l1Token,
    uint256 amount, uint256 l2GasLimit) external payable returns (bytes32 depositId);

function proveWithdrawal(bytes32 withdrawalId,
    L2LogProof calldata proof) external;

// ZK-proven: no challenge period needed
function claimWithdrawal(bytes32 withdrawalId) external;

function configureBridge(uint256 chainId, address diamondProxy,
    address l1Bridge, address l2Bridge) external;
```

### ScrollBridgeAdapter

```solidity
function deposit(uint256 chainId, address l2Recipient, address l1Token,
    uint256 amount, uint256 l2GasLimit) external payable returns (bytes32 depositId);

function proveWithdrawal(bytes32 withdrawalId,
    ScrollWithdrawalProof calldata proof) external;

function claimWithdrawal(bytes32 withdrawalId) external;

// All 4 addresses validated for zero-address
function configureScroll(uint256 chainId, address l1Messenger,
    address l1GatewayRouter, address l1MessageQueue, address rollup) external;
```

### LineaBridgeAdapter

```solidity
function deposit(uint256 chainId, address l2Recipient, address l1Token,
    uint256 amount, uint256 messageFee) external payable returns (bytes32 depositId);

function proveWithdrawal(bytes32 withdrawalId,
    LineaClaimProof calldata proof) external;

function claimWithdrawal(bytes32 withdrawalId) external;

function configureLinea(uint256 chainId, address messageService,
    address tokenBridge) external;
```

### LayerZeroAdapter

```solidity
function send(uint32 dstEid, address receiver, bytes calldata payload,
    MessagingOptions calldata options) external payable returns (bytes32 messageId);

function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce,
    bytes calldata payload) external;

function estimateFee(uint32 dstEid, bytes calldata payload,
    uint128 dstGasLimit) external view returns (MessagingFee memory);

function configureEndpoint(uint32 eid, address endpoint,
    uint64 confirmations, uint128 baseGas) external;

function setPeer(uint32 eid, bytes32 peer) external;
```

### HyperlaneAdapter

```solidity
function dispatch(uint32 dstDomain, bytes32 recipient,
    bytes calldata body) external payable returns (bytes32 messageId);

function handle(uint32 srcDomain, bytes32 sender,
    bytes calldata body) external;

function quoteDispatch(uint32 dstDomain,
    bytes calldata body) external view returns (uint256 nativeFee);

function configureDomain(uint32 domain, bytes32 router,
    address ism, uint256 gasOverhead) external;
```

## Usage Examples

### Relay Proof from Ethereum to Arbitrum

```typescript
import { ethers } from "ethers";

const l1Adapter = new ethers.Contract(
  ARBITRUM_BRIDGE_ADAPTER_L1,
  ArbitrumBridgeAdapterABI,
  l1Signer,
);

const proofHash = ethers.keccak256(proof);
const gasLimit = 1_000_000n;
const maxSubmissionCost = ethers.parseEther("0.01");
const gasPriceBid = ethers.parseGwei("0.1");
const totalValue = maxSubmissionCost + gasLimit * gasPriceBid;

const tx = await l1Adapter.sendProofToL2(
  proofHash,
  proof,
  publicInputs,
  gasLimit,
  maxSubmissionCost,
  { value: totalValue },
);
await tx.wait();
```

### Deposit ETH to zkSync Era

```typescript
const zkSyncAdapter = new ethers.Contract(
  ZKSYNC_BRIDGE_ADAPTER,
  zkSyncBridgeAdapterABI,
  l1Signer,
);

const depositAmount = ethers.parseEther("1.0");
const tx = await zkSyncAdapter.deposit(
  324, // zkSync Era chain ID
  recipientAddress, // L2 recipient
  ethers.ZeroAddress, // ETH (not ERC20)
  depositAmount,
  2_000_000, // L2 gas limit
  { value: depositAmount },
);
await tx.wait();
```

### Send Message via LayerZero

```typescript
const lzAdapter = new ethers.Contract(
  LAYERZERO_ADAPTER,
  LayerZeroAdapterABI,
  signer,
);

const fee = await lzAdapter.estimateFee(
  30101, // Arbitrum LZ endpoint ID
  payload,
  200_000, // dst gas
);

const tx = await lzAdapter.send(
  30101, // dstEid
  receiverAddress,
  payload,
  { dstGasLimit: 200_000, dstNativeAmount: 0, extraOptions: "0x" },
  { value: fee.nativeFee },
);
await tx.wait();
```

### Dispatch via Hyperlane

```typescript
const hyperlaneAdapter = new ethers.Contract(
  HYPERLANE_ADAPTER,
  HyperlaneAdapterABI,
  signer,
);

const fee = await hyperlaneAdapter.quoteDispatch(42161, messageBody);

const tx = await hyperlaneAdapter.dispatch(
  42161, // Arbitrum domain
  ethers.zeroPadValue(recipientAddress, 32), // bytes32 recipient
  messageBody,
  { value: fee },
);
await tx.wait();
```

### Bridge USDC via CCTP (Base)

```typescript
const usdc = new ethers.Contract(USDC_ADDRESS, ERC20ABI, signer);
await usdc.approve(BASE_BRIDGE_ADAPTER, amount);

const tx = await baseAdapter.initiateUSDCTransfer(
  recipientOnBase,
  amount,
  6, // Base CCTP domain
);
const receipt = await tx.wait();
const transferId = receipt.logs[0].args.transferId;

// On Base: complete transfer with Circle attestation
await baseAdapterL2.completeCCTPTransfer(
  transferId,
  cctpMessage,
  circleAttestation,
);
```

## Deployment

### Deploy L2 Adapters

```bash
# Validate environment first
./scripts/validate-env.sh --phase 2

# Deploy to L2 testnets
npx hardhat run scripts/deploy-l2-adapters.ts --network arbitrumSepolia
npx hardhat run scripts/deploy-l2-adapters.ts --network baseSepolia
npx hardhat run scripts/deploy-l2-adapters.ts --network optimismSepolia

# Deploy new ZK-rollup and messaging adapters (unified script)
forge script scripts/deploy/DeployL2Bridges.s.sol --rpc-url $SEPOLIA_RPC --broadcast
```

### Configuration

Each adapter needs to be configured with the correct messenger/endpoint addresses:

| Network   | Key Contract                                        | Adapter Config Function |
| --------- | --------------------------------------------------- | ----------------------- |
| Arbitrum  | Inbox: `0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f` | `configureArbitrum()`   |
| Optimism  | L1CDM: `0x25ace71c97B33Cc4729CF772ae268934F7ab5fA1` | `configureOptimism()`   |
| Base      | L1CDM: `0x866E82a600A1414e583f7F13623F1aC5d58b0Afa` | `configureBase()`       |
| zkSync    | Diamond: zkSync Diamond Proxy                       | `configureBridge()`     |
| Scroll    | L1Messenger: L1ScrollMessenger                      | `configureScroll()`     |
| Linea     | L1MessageService                                    | `configureLinea()`      |
| LayerZero | LZ Endpoint V2                                      | `configureEndpoint()`   |
| Hyperlane | Mailbox                                             | `configureDomain()`     |

## Security Considerations

| Aspect                          | Details                                                                      |
| ------------------------------- | ---------------------------------------------------------------------------- |
| **Optimistic Challenge Period** | All optimistic rollups: ~7 days for L2→L1 messages                           |
| **ZK Finality**                 | zkSync (~1h), Scroll (~4h), Linea (~hours) — no challenge period needed      |
| **Message Verification**        | Always verify `msg.sender == messenger/mailbox/endpoint`                     |
| **Gas Limits**                  | Proof relay: 500K-1M gas • State sync: 200K-500K • Simple ops: 100K-200K     |
| **Zero-Address Checks**         | All adapters validate recipient and config addresses                         |
| **ETH Transfer Safety**         | All `claimWithdrawal()` functions use CEI pattern with `nonReentrant`        |
| **Outbox Verification**         | Arbitrum uses `outbox.isSpent(index)` for direct withdrawal claims           |
| **Dispatch Failure**            | LayerZero/Hyperlane revert on endpoint failure (no silent accounting errors) |
| **Emergency Recovery**          | All adapters support `emergencyWithdrawETH()` and `emergencyWithdrawERC20()` |

## Testnet Faucets

- Arbitrum/Optimism/Base Sepolia: [Alchemy Faucets](https://www.alchemy.com/faucets)
- Sepolia L1: [sepoliafaucet.com](https://sepoliafaucet.com)
- zkSync Sepolia: [zkSync Faucet](https://portal.zksync.io/faucet)
- Scroll Sepolia: [Scroll Faucet](https://scroll.io/portal)
- Linea Sepolia: [Linea Faucet](https://faucet.goerli.linea.build)

## See Also

[BRIDGE_INTEGRATION.md](./BRIDGE_INTEGRATION.md) • [DEPLOYMENT.md](./DEPLOYMENT.md) • [ARBITRUM_INTEGRATION.md](./ARBITRUM_INTEGRATION.md) • [OPTIMISM_INTEGRATION.md](./OPTIMISM_INTEGRATION.md)
