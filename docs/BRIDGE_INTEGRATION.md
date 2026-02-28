# Zaseon Bridge Adapters Integration Guide

> Cross-chain privacy-preserving transfers via unified `IBridgeAdapter` interface.

Zaseon Bridge Adapters provide a unified interface for cross-chain operations. Each adapter implements the `IBridgeAdapter` interface:

```solidity
interface IBridgeAdapter {
    function bridgeTransfer(
        bytes32 targetChainId,
        bytes32 recipient,
        uint256 amount,
        bytes calldata proof
    ) external returns (bytes32 relayId);

    function completeBridge(
        bytes32 relayId,
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

| Chain            | Adapter                 | Protocol          | Finality            | Status        |
| ---------------- | ----------------------- | ----------------- | ------------------- | ------------- |
| Arbitrum One     | `ArbitrumBridgeAdapter` | Retryable Tickets | 7 days (withdrawal) | ✅ Production |
| Arbitrum Sepolia | `ArbitrumBridgeAdapter` | Retryable Tickets | 7 days              | ✅ Production |
| Base             | `BaseBridgeAdapter`     | OP Stack          | 7 days              | ✅ Production |
| Optimism         | `OptimismBridgeAdapter` | OP Stack          | 7 days              | ✅ Production |
| LayerZero        | `LayerZeroAdapter`      | OApp V2           | Chain-dependent     | ✅ Production |
| Ethereum L1      | `EthereumL1Bridge`      | Native            | Finalized           | ✅ Production |

---

## Common Interface

### Initiating a Bridge Transfer

```typescript
import { ZaseonBridge, ChainId } from "@zaseon/sdk";

const bridge = new ZaseonBridge(provider);

// Initiate cross-chain transfer
const relayId = await bridge.transfer({
  sourceChain: ChainId.ETHEREUM,
  targetChain: ChainId.POLYGON,
  amount: ethers.parseEther("1.0"),
  recipient: "0x...",
  privateTransfer: true, // Enable privacy features
});

// Monitor transfer status
const status = await bridge.getRequestStatus(relayId);
console.log(status); // 'pending' | 'relayed' | 'completed' | 'failed'
```

### Completing a Bridge Transfer

```typescript
// On destination chain
const completed = await bridge.completeBridge(relayId, proof);
```

---

## Chain-Specific Integration

### Arbitrum

```typescript
import { ZaseonBridge, ChainId } from "@zaseon/sdk";

const bridge = new ZaseonBridge(provider);

// Bridge to Arbitrum using native messaging
const relayId = await bridge.transfer({
  sourceChain: ChainId.ETHEREUM,
  targetChain: ChainId.ARBITRUM,
  amount: ethers.parseEther("1.0"),
  recipient: "0x...",
  privateTransfer: true,
});

// Arbitrum uses retryable tickets - may need to manually redeem
const status = await bridge.getRequestStatus(relayId);
if (status === "pending_retry") {
  await bridge.redeemRetryableTicket(relayId);
}
```

### LayerZero

```typescript
import { LayerZeroAdapter } from "@zaseon/sdk/bridges";

const lzBridge = new LayerZeroAdapter({
  sourceRpc: "https://eth-mainnet...",
  endpoint: "0x1a44076050125825900e736c501f859c50fE728c", // LZ V2 endpoint
});

// Bridge via LayerZero OApp
const transfer = await lzBridge.send({
  dstEid: 30110, // Arbitrum endpoint ID
  amount: ethers.parseEther("1.0"),
  recipient: "0x...",
  options: {
    gas: 200000n,
    value: 0n,
  },
});
```

### Direct L2-to-L2

```typescript
import { DirectL2Messenger } from "@zaseon/sdk/bridges";

const messenger = new DirectL2Messenger({
  sourceRpc: process.env.ARBITRUM_RPC,
  destRpc: process.env.BASE_RPC,
});

// Send message directly between L2s
const messageId = await messenger.sendMessage({
  destChainId: 8453, // Base
  target: "0x...",
  data: encodedCalldata,
  gasLimit: 100000n,
});
```

---

## Future Integrations

The following chains are planned for future releases:

| Chain      | Status     | Expected |
| ---------- | ---------- | -------- |
| zkSync Era | 📋 Planned | Q3 2026  |
| Scroll     | 📋 Planned | Q3 2026  |
| Linea      | 📋 Planned | Q3 2026  |

---

## Error Handling

```typescript
import { ZaseonBridgeError, ErrorCodes } from "@zaseon/sdk";

try {
  await bridge.transfer(params);
} catch (error) {
  if (error instanceof ZaseonBridgeError) {
    // ErrorCodes: INSUFFICIENT_BALANCE, PROOF_VERIFICATION_FAILED,
    // BRIDGE_PAUSED, TIMEOUT_EXCEEDED, INVALID_RECIPIENT
    handleError(error.code);
  }
}
```

---

## Security Considerations

| Check                  | Requirement                                          |
| ---------------------- | ---------------------------------------------------- |
| **Proof Verification** | Always verify ZK proofs on-chain before completing   |
| **Timeout Handling**   | Set appropriate timeouts with refund address         |
| **Challenge Period**   | Wait for 7-day challenge period (optimistic bridges) |
| **Replay Protection**  | All transfers include nonces + chain IDs             |
| **Amount Validation**  | Validate against min/max limits before transfer      |

---

## See Also

- [API Reference](./API_REFERENCE.md)
- [L2 Interoperability](./L2_INTEROPERABILITY.md) - L2-specific integration
- [Architecture](./architecture.md)
