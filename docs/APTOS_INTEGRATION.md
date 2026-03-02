# Aptos Integration

## Overview

ZASEON integrates with **Aptos**, a high-throughput Layer 1 blockchain built on the Move programming language. Originally developed for the Diem project, Aptos features Block-STM for parallel transaction execution and AptosBFT (DiemBFT v4) for consensus.

| Property        | Value                           |
| --------------- | ------------------------------- |
| ZASEON Chain ID | `15100`                         |
| Bridge Type     | LayerZero-DVN                   |
| Contract        | `AptosBridgeAdapter.sol`        |
| VM              | Move (Aptos variant)            |
| Finality        | ~700ms (AptosBFT)               |
| Security Model  | LayerZero DVN + trusted remotes |
| LZ Chain ID     | 108                             |

## Architecture

```
┌─────────────┐    LayerZero V2    ┌──────────────────┐     DVN      ┌─────────────┐
│   ZASEON     │ ─────send────────▶│  LZ Endpoint     │ ──verify───▶│  Decentralized│
│   Adapter    │                   │  (Ethereum)      │             │  Verifiers   │
└─────────────┘                   └──────────────────┘             └─────────────┘
       ▲                                                                  │
       │                      Verified message delivery                   │
       └──────────────────────────────────────────────────────────────────┘
```

### Key Concepts

- **Move VM**: Resource-oriented programming (account-based, unlike Sui's objects)
- **Block-STM**: Optimistic parallel execution engine
- **AptosBFT (DiemBFT v4)**: Byzantine fault-tolerant consensus
- **Jellyfish Merkle Tree**: State storage with efficient inclusion proofs
- **LayerZero**: Primary cross-chain messaging to/from Aptos
- **DVN (Decentralized Verifier Network)**: Security model for message verification
- **Trusted Remotes**: Whitelisted source addresses per chain

## Contract Details

### AptosBridgeAdapter

The adapter provides:

1. **Outbound messaging** via LayerZero endpoint `send` to LZ chain ID 108
2. **Inbound verification** using trusted remote pattern
3. **Optional state proof verification** via Aptos light client (JMT proofs)
4. **Nullifier-based replay protection** via ZASEON CDNA

### Key Functions

```solidity
// Send a message to Aptos via LayerZero
function sendMessage(bytes calldata aptosTarget, bytes calldata payload)
    external payable returns (bytes32 messageHash);

// Receive a message from Aptos
function receiveMessage(
    uint16 srcChainId,
    bytes calldata srcAddress,
    bytes calldata payload
) external returns (bytes32 messageHash);

// Verify an Aptos state proof
function verifyStateProof(bytes32 stateRoot, bytes calldata proof)
    external view returns (bool valid);

// Set trusted remote for source verification
function setTrustedRemote(uint16 _chainId, bytes calldata _remote) external;
```

### Security Features

- Trusted remote verification (only whitelisted sources accepted)
- Optional Jellyfish Merkle Tree state proof verification
- Nullifier tracking prevents double-spending
- LayerZero DVN-based message attestation
- Pause/unpause for emergency response
- Role-based access (OPERATOR, RELAYER, GUARDIAN, PAUSER)

## SDK Usage

```typescript
import {
  APTOS_CHAIN_ID,
  LZ_APTOS_CHAIN_ID,
  AptosBridgeAdapterABI,
} from "@zaseon/sdk/bridges/aptos";

// Send a privacy message to Aptos
const tx = await walletClient.writeContract({
  address: adapterAddress,
  abi: AptosBridgeAdapterABI,
  functionName: "sendMessage",
  args: [aptosTargetBytes, payload],
  value: lzFee,
});
```

## Aptos Addresses

Aptos uses 32-byte hex addresses, often with leading zeros stripped:

```
0x1                    // Core framework
0x3                    // Token module
0xa4e7...f3b2          // User account
```

When encoding for the adapter, use full 32-byte representation:

```
0x0000000000000000000000000000000000000000000000000000000000000001
```

## Deployment

```bash
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "aptos" \
  --rpc-url $RPC_URL \
  --broadcast
```

## References

- [Aptos Documentation](https://aptos.dev/)
- [Block-STM](https://aptos.dev/en/network/blockchain/execution)
- [Jellyfish Merkle Tree](https://github.com/aptos-labs/aptos-core/tree/main/storage/jellyfish-merkle)
- [LayerZero on Aptos](https://docs.layerzero.network/v2/developers/evm/technical-reference/deployed-contracts)
- [Move Language](https://move-language.github.io/move/)
