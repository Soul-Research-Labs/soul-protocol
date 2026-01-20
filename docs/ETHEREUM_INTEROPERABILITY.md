# Ethereum L1 Interoperability

## Overview

The Privacy Interoperability Layer (PIL) provides comprehensive Ethereum mainnet (L1) interoperability through a multi-layered bridge architecture. This enables secure cross-chain proof relay, state synchronization, and privacy-preserving asset transfers between Ethereum L1 and various L2 networks.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PIL Ethereum Interoperability                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Application Layer                                 │   │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │   │
│  │  │  Privacy DApps  │  │  ZK Verifiers   │  │  State Oracles  │     │   │
│  │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘     │   │
│  └───────────┼────────────────────┼────────────────────┼───────────────┘   │
│              │                    │                    │                    │
│  ┌───────────▼────────────────────▼────────────────────▼───────────────┐   │
│  │                    Bridge Layer                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  EthereumL1Bridge.sol                                        │   │   │
│  │  │  - L2 Chain Configuration                                    │   │   │
│  │  │  - State Commitment Relay                                    │   │   │
│  │  │  - Deposit/Withdrawal Management                             │   │   │
│  │  │  - Privacy Commitment Handling                               │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  │                                                                      │   │
│  │  ┌─────────────────────────────────────────────────────────────┐   │   │
│  │  │  CrossChainMessageRelay.sol                                  │   │   │
│  │  │  - Message Encoding/Decoding                                 │   │   │
│  │  │  - Signature Verification                                    │   │   │
│  │  │  - Batch Processing                                          │   │   │
│  │  │  - Retry Mechanism                                           │   │   │
│  │  └─────────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Canonical Bridge Adapters                          │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ Arbitrum │ │ Optimism │ │   Base   │ │  zkSync  │ │  Scroll  │  │  │
│  │  │ Inbox    │ │ Portal   │ │ Portal   │ │ Diamond  │ │ Messenger│  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Supported Networks

| Network | Chain ID | Type | Challenge Period | Status |
|---------|----------|------|------------------|--------|
| Ethereum Mainnet | 1 | L1 | N/A | ✅ Supported |
| Arbitrum One | 42161 | Optimistic | 7 days | ✅ Supported |
| Optimism | 10 | Optimistic | 7 days | ✅ Supported |
| Base | 8453 | Optimistic | 7 days | ✅ Supported |
| zkSync Era | 324 | ZK Rollup | Instant | ✅ Supported |
| Scroll | 534352 | ZK Rollup | Instant | ✅ Supported |
| Linea | 59144 | ZK Rollup | Instant | ✅ Supported |
| Polygon zkEVM | 1101 | ZK Rollup | Instant | ✅ Supported |

## Core Contracts

### EthereumL1Bridge.sol

The main bridge contract for Ethereum L1 interoperability.

#### Key Features

1. **L2 Chain Management**
   - Configure L2 chains with rollup-specific parameters
   - Support for optimistic and ZK rollup finality models
   - Dynamic chain enable/disable functionality

2. **State Commitment Relay**
   - Submit state roots from L2 chains
   - Challenge mechanism for optimistic rollups
   - Automatic finalization for ZK rollups

3. **Privacy-Preserving Deposits**
   - Deposit ETH with PIL commitments
   - Nullifier-based double-spend prevention
   - Merkle proof verification for withdrawals

4. **Rate Limiting & Security**
   - Circuit breaker functionality
   - Submission bonds for commitments
   - Role-based access control

#### Usage Example

```solidity
// Configure L2 chain
bridge.configureL2Chain(L2Config({
    chainId: 42161,
    name: "Arbitrum One",
    rollupType: RollupType.OPTIMISTIC,
    canonicalBridge: ARBITRUM_INBOX,
    messenger: address(0),
    stateCommitmentChain: address(0),
    challengePeriod: 7 days,
    confirmationBlocks: 1,
    enabled: true,
    gasLimit: 1000000,
    lastSyncedBlock: 0
}));

// Submit state commitment from L2
bridge.submitStateCommitment{value: 0.1 ether}(
    42161,           // Arbitrum chain ID
    stateRoot,       // L2 state root
    proofRoot,       // PIL proof merkle root
    blockNumber      // L2 block number
);

// Deposit ETH to L2 with privacy commitment
bytes32 commitment = keccak256(abi.encodePacked(secret, nullifier));
bridge.depositETH{value: 1 ether}(42161, commitment);

// Withdraw from L2 to L1
bridge.initiateWithdrawal(
    42161,           // Source chain
    1 ether,         // Amount
    nullifier,       // PIL nullifier
    merkleProof      // Proof from L2 state
);
```

### CrossChainMessageRelay.sol

Handles cross-chain message passing between L1 and L2 networks.

#### Key Features

1. **Message Sending (L1 → L2)**
   - Encode and queue outbound messages
   - Support for value transfers
   - Configurable gas limits

2. **Message Receiving (L2 → L1)**
   - Signature verification
   - Merkle proof validation
   - Automatic execution with gas stipend

3. **Batch Processing**
   - Aggregate multiple messages
   - Merkle tree commitment
   - Gas-efficient batch execution

4. **Retry Mechanism**
   - Failed message tracking
   - Configurable retry delay
   - Message expiry handling

#### Usage Example

```solidity
// Send message to L2
bytes32 messageId = relay.sendMessage(
    42161,                              // Target chain (Arbitrum)
    targetContract,                     // Target address on L2
    abi.encodeCall(ITarget.execute, (params)),  // Calldata
    500000                              // Gas limit
);

// Receive message from L2 (by relayer)
relay.receiveMessage(message, signature);

// Retry failed message
relay.retryMessage(messageId);
```

## Integration Patterns

### Pattern 1: Privacy-Preserving Cross-Chain Transfer

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│   L1 Deposit │     │ PIL Privacy   │     │   L2 Claim   │
│   + Commit   │────▶│ Commitment    │────▶│   + Nullify  │
└──────────────┘     └───────────────┘     └──────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
   Lock ETH          Store commitment      Verify nullifier
   in bridge         in merkle tree        Release funds
```

### Pattern 2: ZK Proof Relay

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│   L2 ZK      │     │ State Root    │     │   L1 Verify  │
│   Prover     │────▶│ Submission    │────▶│   + Execute  │
└──────────────┘     └───────────────┘     └──────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
   Generate proof    Submit to L1         Verify against
   on L2             bridge               state root
```

### Pattern 3: Batched Message Relay

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│   Multiple   │     │ Batch         │     │   Execute    │
│   Messages   │────▶│ Aggregation   │────▶│   All Msgs   │
└──────────────┘     └───────────────┘     └──────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
   Queue msgs        Merkle tree          Batch execution
   on L2             commitment           on L1
```

## Security Considerations

### Finality Models

| Rollup Type | Finality | Challenge Period | Security Model |
|-------------|----------|------------------|----------------|
| Optimistic | Delayed | 7 days | Fraud proofs |
| ZK Rollup | Instant | 0 | Validity proofs |

### Rate Limiting

The bridge implements rate limiting to prevent DoS attacks:
- Maximum 100 state commitments per hour
- Configurable by OPERATOR_ROLE

### Submission Bonds

Relayers must submit bonds with state commitments:
- Minimum bond: 0.1 ETH (configurable)
- Returned after successful finalization
- Slashed if commitment is successfully challenged

### Role-Based Access

| Role | Permissions |
|------|-------------|
| RELAYER_ROLE | Submit commitments, relay messages |
| OPERATOR_ROLE | Configure chains, set parameters |
| GUARDIAN_ROLE | Pause contracts in emergencies |
| DEFAULT_ADMIN_ROLE | Grant/revoke roles |

## Deployment Guide

### Prerequisites

1. Deploy PIL core contracts
2. Configure verifiers (Groth16, PLONK)
3. Set up relayer infrastructure

### Deployment Steps

```bash
# 1. Deploy EthereumL1Bridge
forge create contracts/crosschain/EthereumL1Bridge.sol:EthereumL1Bridge \
  --rpc-url $ETH_RPC_URL \
  --private-key $DEPLOYER_KEY

# 2. Deploy CrossChainMessageRelay
forge create contracts/crosschain/CrossChainMessageRelay.sol:CrossChainMessageRelay \
  --rpc-url $ETH_RPC_URL \
  --private-key $DEPLOYER_KEY

# 3. Configure canonical bridges
cast send $BRIDGE_ADDRESS "setCanonicalBridge(uint256,address)" \
  42161 $ARBITRUM_INBOX \
  --rpc-url $ETH_RPC_URL \
  --private-key $OPERATOR_KEY

# 4. Set trusted remotes
cast send $RELAY_ADDRESS "setTrustedRemote(uint256,address)" \
  42161 $ARBITRUM_REMOTE \
  --rpc-url $ETH_RPC_URL \
  --private-key $OPERATOR_KEY
```

### Post-Deployment

1. Grant RELAYER_ROLE to relayer accounts
2. Configure L2 canonical bridge addresses
3. Set up monitoring for bridge events
4. Initialize cross-chain nullifier registry

## Gas Optimization

### Batch Processing

Messages are batched for gas efficiency:
- Up to 50 messages per batch
- Single Merkle root commitment
- Amortized verification costs

### EIP-4844 Support (Future)

The architecture is designed to support EIP-4844 blob transactions:
- State commitments via blob data
- Reduced L1 gas costs
- Higher throughput

## Monitoring & Alerts

### Key Events to Monitor

```solidity
event StateCommitmentSubmitted(bytes32 indexed commitmentId, uint256 indexed sourceChainId, bytes32 stateRoot, address submitter);
event StateCommitmentChallenged(bytes32 indexed commitmentId, address challenger, bytes32 reason);
event StateCommitmentFinalized(bytes32 indexed commitmentId, bytes32 stateRoot);
event DepositInitiated(bytes32 indexed depositId, address indexed depositor, uint256 indexed targetChainId, address token, uint256 amount, bytes32 commitment);
event WithdrawalFinalized(bytes32 indexed withdrawalId, address recipient, uint256 amount);
```

### Recommended Alerts

1. **High Priority**
   - State commitment challenged
   - Circuit breaker triggered (pause)
   - Unusual deposit volume

2. **Medium Priority**
   - Message execution failures
   - Rate limit approached
   - Submission bond depleted

3. **Low Priority**
   - New chain configured
   - Parameter updates

## Related Documentation

- [ZK Proof Systems](./ZK_PROOF_SYSTEMS.md)
- [Cross-Chain Architecture](./CROSS_CHAIN_ARCHITECTURE.md)
- [Security Model](./SECURITY_MODEL.md)
- [PIL Protocol Specification](./PROTOCOL_SPEC.md)
