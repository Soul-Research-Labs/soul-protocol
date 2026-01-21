# PIL Bridge Adapters Integration Guide

This guide covers integrating with PIL's bridge adapters for cross-chain privacy-preserving transfers.

## Table of Contents

1. [Overview](#overview)
2. [Supported Chains](#supported-chains)
3. [Common Interface](#common-interface)
4. [Chain-Specific Integration](#chain-specific-integration)
5. [Error Handling](#error-handling)
6. [Security Considerations](#security-considerations)

---

## Overview

PIL Bridge Adapters provide a unified interface for cross-chain operations while handling the complexity of different blockchain protocols. Each adapter implements the `IBridgeAdapter` interface:

```solidity
interface IBridgeAdapter {
    function bridgeTransfer(
        bytes32 targetChainId,
        bytes32 recipient,
        uint256 amount,
        bytes calldata proof
    ) external returns (bytes32 transferId);
    
    function completeBridge(
        bytes32 transferId,
        bytes calldata proof
    ) external returns (bool success);
    
    function verifyBridgeProof(
        bytes calldata proof,
        bytes32 expectedRoot
    ) external view returns (bool valid);
}
```

---

## Supported Chains

| Chain | Adapter | Protocol | Finality | Notes |
|-------|---------|----------|----------|-------|
| Cardano | `CardanoBridgeAdapter` | Plutus Light Client | ~20 blocks | Ouroboros consensus |
| Midnight | `MidnightBridgeAdapter` | DustJS ZK | ~10 blocks | Native privacy |
| Polkadot | `PolkadotBridgeAdapter` | XCMP | ~30 blocks | Relay chain verification |
| Cosmos | `CosmosBridgeAdapter` | IBC | ~15 blocks | Tendermint light client |
| NEAR | `NEARBridgeAdapter` | Rainbow Bridge | ~4 epochs | ED25519 signatures |
| zkSync Era | `zkSyncBridgeAdapter` | Priority Ops | Instant (L2) | ZK rollup |
| Avalanche | `AvalancheBridgeAdapter` | Warp Messaging | ~2 seconds | BLS signatures |
| Arbitrum | `ArbitrumBridgeAdapter` | Retryable Tickets | 7 days (withdrawal) | Optimistic rollup |
| Solana | `SolanaBridgeAdapter` | SPL Bridge | ~32 slots | Ed25519 validators |
| Bitcoin | `BitcoinBridgeAdapter` | HTLC | 6 blocks | Hash time-locked contracts |

---

## Common Interface

### Initiating a Bridge Transfer

```typescript
import { PILBridge, ChainId } from '@pil/sdk';

const bridge = new PILBridge(provider);

// Initiate cross-chain transfer
const transferId = await bridge.transfer({
  sourceChain: ChainId.ETHEREUM,
  targetChain: ChainId.POLYGON,
  amount: ethers.parseEther('1.0'),
  recipient: '0x...',
  privateTransfer: true  // Enable privacy features
});

// Monitor transfer status
const status = await bridge.getTransferStatus(transferId);
console.log(status); // 'pending' | 'relayed' | 'completed' | 'failed'
```

### Completing a Bridge Transfer

```typescript
// On destination chain
const completed = await bridge.completeBridge(transferId, proof);
```

---

## Chain-Specific Integration

### Cardano / Midnight

```typescript
import { CardanoBridge } from '@pil/sdk/bridges';

const cardanoBridge = new CardanoBridge({
  sourceRpc: 'https://eth-mainnet...',
  cardanoNode: 'https://cardano-node...',
  blockfrostApiKey: 'your-api-key'
});

// Bridge ETH to Cardano
const transfer = await cardanoBridge.bridgeToCardano({
  amount: ethers.parseEther('1.0'),
  cardanoAddress: 'addr1...',
  proof: zkProof
});

// Wait for Plutus verification
await transfer.waitForConfirmation(20); // 20 block confirmations
```

### Cosmos / IBC

```typescript
import { CosmosBridge } from '@pil/sdk/bridges';

const cosmosBridge = new CosmosBridge({
  sourceRpc: 'https://eth-mainnet...',
  cosmosRpc: 'https://cosmos-rpc...',
  ibcChannel: 'channel-0'
});

// Bridge via IBC
const transfer = await cosmosBridge.bridgeViaiBC({
  amount: ethers.parseEther('1.0'),
  cosmosAddress: 'cosmos1...',
  timeoutHeight: { revisionNumber: 1n, revisionHeight: 1000000n },
  timeoutTimestamp: BigInt(Date.now() + 3600000) * 1000000n
});

// Monitor IBC packet
const packetStatus = await cosmosBridge.getPacketStatus(transfer.packetId);
```

### Polkadot / Substrate

```typescript
import { PolkadotBridge } from '@pil/sdk/bridges';

const polkadotBridge = new PolkadotBridge({
  sourceRpc: 'https://eth-mainnet...',
  relayChainRpc: 'wss://rpc.polkadot.io',
  paraId: 2000
});

// Bridge via XCMP
const transfer = await polkadotBridge.bridgeViaXCMP({
  amount: ethers.parseEther('1.0'),
  destinationParaId: 2004,
  recipientMultiLocation: {
    parents: 1,
    interior: { X1: { AccountId32: { id: '0x...', network: null } } }
  }
});
```

### NEAR / Rainbow Bridge

```typescript
import { NEARBridge } from '@pil/sdk/bridges';

const nearBridge = new NEARBridge({
  sourceRpc: 'https://eth-mainnet...',
  nearRpc: 'https://rpc.mainnet.near.org',
  rainbowBridgeAddress: '0x...'
});

// Bridge to NEAR
const transfer = await nearBridge.bridgeToNEAR({
  amount: ethers.parseEther('1.0'),
  nearAccountId: 'user.near',
  proof: zkProof
});

// Wait for Rainbow Bridge relay (4 epochs)
await transfer.waitForRelayerConfirmation();
```

### zkSync Era

```typescript
import { zkSyncBridge } from '@pil/sdk/bridges';

const bridge = new zkSyncBridge({
  l1Rpc: 'https://eth-mainnet...',
  l2Rpc: 'https://mainnet.era.zksync.io'
});

// Deposit to zkSync (priority operation)
const deposit = await bridge.deposit({
  amount: ethers.parseEther('1.0'),
  l2Recipient: '0x...',
  l2GasLimit: 2000000n,
  gasPerPubdataByte: 800n
});

// Withdraw from zkSync
const withdrawal = await bridge.withdraw({
  amount: ethers.parseEther('1.0'),
  l1Recipient: '0x...'
});

// Wait for L2 batch verification
await withdrawal.waitForVerification();
```

### Avalanche

```typescript
import { AvalancheBridge } from '@pil/sdk/bridges';

const avaxBridge = new AvalancheBridge({
  sourceRpc: 'https://eth-mainnet...',
  cChainRpc: 'https://api.avax.network/ext/bc/C/rpc'
});

// Bridge via Warp Messaging
const transfer = await avaxBridge.bridgeViaWarp({
  amount: ethers.parseEther('1.0'),
  destinationBlockchainId: C_CHAIN_ID,
  recipientAddress: '0x...'
});

// Fast finality with BLS signatures
const finalized = await transfer.waitForWarpSignatures(67); // 67% threshold
```

### Arbitrum

```typescript
import { ArbitrumBridge } from '@pil/sdk/bridges';

const arbitrumBridge = new ArbitrumBridge({
  l1Rpc: 'https://eth-mainnet...',
  l2Rpc: 'https://arb1.arbitrum.io/rpc'
});

// Deposit via retryable ticket
const deposit = await arbitrumBridge.depositViaRetryable({
  amount: ethers.parseEther('1.0'),
  l2Recipient: '0x...',
  maxSubmissionCost: ethers.parseEther('0.001'),
  gasLimit: 1000000n,
  maxFeePerGas: 100000000n // 0.1 gwei
});

// Track retryable ticket
const ticketStatus = await arbitrumBridge.getRetryableStatus(deposit.ticketId);

// Withdraw (7 day challenge period)
const withdrawal = await arbitrumBridge.initiateWithdrawal({
  amount: ethers.parseEther('1.0'),
  l1Recipient: '0x...'
});

// Wait for challenge period
await withdrawal.waitForChallengePeriod(); // ~7 days

// Claim on L1
await withdrawal.executeWithdrawal();
```

### Solana

```typescript
import { SolanaBridge } from '@pil/sdk/bridges';

const solanaBridge = new SolanaBridge({
  sourceRpc: 'https://eth-mainnet...',
  solanaRpc: 'https://api.mainnet-beta.solana.com'
});

// Bridge to Solana
const transfer = await solanaBridge.bridgeToSolana({
  amount: ethers.parseEther('1.0'),
  solanaWallet: new PublicKey('...'),
  proof: zkProof
});

// Claim wrapped token on Solana
await transfer.claimOnSolana(solanaKeypair);
```

### Bitcoin

```typescript
import { BitcoinBridge } from '@pil/sdk/bridges';

const btcBridge = new BitcoinBridge({
  sourceRpc: 'https://eth-mainnet...',
  bitcoinRpc: 'https://blockstream.info/api'
});

// Bridge via HTLC
const htlc = await btcBridge.createHTLC({
  amount: ethers.parseEther('1.0'),
  bitcoinRecipient: 'bc1q...',
  secretHash: keccak256(secret),
  lockTime: Math.floor(Date.now() / 1000) + 86400 // 24 hours
});

// Monitor Bitcoin transaction
const btcTx = await htlc.waitForBitcoinLock();

// Claim with preimage
await htlc.claimWithSecret(secret);
```

---

## Error Handling

```typescript
import { PILBridgeError, ErrorCodes } from '@pil/sdk';

try {
  await bridge.transfer(params);
} catch (error) {
  if (error instanceof PILBridgeError) {
    switch (error.code) {
      case ErrorCodes.INSUFFICIENT_BALANCE:
        // Handle insufficient funds
        break;
      case ErrorCodes.PROOF_VERIFICATION_FAILED:
        // Handle invalid ZK proof
        break;
      case ErrorCodes.BRIDGE_PAUSED:
        // Handle paused bridge
        break;
      case ErrorCodes.TIMEOUT_EXCEEDED:
        // Handle timeout
        break;
      case ErrorCodes.INVALID_RECIPIENT:
        // Handle invalid recipient address
        break;
      default:
        throw error;
    }
  }
}
```

---

## Security Considerations

### 1. Proof Verification

Always verify proofs on-chain before completing bridges:

```solidity
require(verifier.verifyProof(proof, publicInputs), "Invalid proof");
```

### 2. Timeout Handling

Set appropriate timeouts for cross-chain operations:

```typescript
const transfer = await bridge.transfer({
  ...params,
  timeout: 3600, // 1 hour in seconds
  refundAddress: '0x...' // Address for timeout refunds
});
```

### 3. Challenge Period Awareness

For optimistic bridges (Arbitrum), always wait for challenge periods:

```typescript
const withdrawal = await arbitrumBridge.initiateWithdrawal(params);

// Check if challenge period has passed
const canExecute = await withdrawal.canExecuteWithdrawal();
if (!canExecute) {
  const remaining = await withdrawal.getRemainingChallengeTime();
  console.log(`Wait ${remaining} seconds before execution`);
}
```

### 4. Replay Protection

All transfers include nonces and chain IDs to prevent replay:

```typescript
const transferId = keccak256(abi.encodePacked(
  sourceChainId,
  targetChainId,
  nonce,
  sender,
  recipient,
  amount
));
```

### 5. Amount Validation

Validate transfer amounts against configured limits:

```typescript
const limits = await bridge.getLimits(targetChainId);
if (amount < limits.minAmount || amount > limits.maxAmount) {
  throw new Error('Amount outside allowed range');
}
```

---

## Next Steps

- [API Reference](./api/README.md) - Full API documentation
- [Tutorials](./tutorials/) - Step-by-step guides
- [Architecture](./architecture.md) - System design details
- [Security](./SECURITY_AUDIT.md) - Security considerations
