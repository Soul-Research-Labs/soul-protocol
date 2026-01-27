# Soul Bridge Adapters Integration Guide

> Cross-chain privacy-preserving transfers via unified `IBridgeAdapter` interface.

Soul Bridge Adapters provide a unified interface for cross-chain operations while handling the complexity of different blockchain protocols. Each adapter implements the `IBridgeAdapter` interface:

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
import { SoulBridge, ChainId } from '@pil/sdk';

const bridge = new SoulBridge(provider);

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
import { SoulBridgeError, ErrorCodes } from '@pil/sdk';

try {
  await bridge.transfer(params);
} catch (error) {
  if (error instanceof SoulBridgeError) {
    // ErrorCodes: INSUFFICIENT_BALANCE, PROOF_VERIFICATION_FAILED, 
    // BRIDGE_PAUSED, TIMEOUT_EXCEEDED, INVALID_RECIPIENT
    handleError(error.code);
  }
}
```

---

## Security Considerations

| Check | Requirement |
|-------|-------------|
| **Proof Verification** | Always verify ZK proofs on-chain before completing |
| **Timeout Handling** | Set appropriate timeouts with refund address |
| **Challenge Period** | Wait for 7-day challenge period (optimistic bridges) |
| **Replay Protection** | All transfers include nonces + chain IDs |
| **Amount Validation** | Validate against min/max limits before transfer |

---

## See Also

- [API Reference](./API_REFERENCE.md)
- [L2 Interoperability](./L2_INTEROPERABILITY.md) - L2-specific integration
- [Architecture](./architecture.md)
