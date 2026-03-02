# TON Integration

## Overview

ZASEON integrates with **TON (The Open Network)**, a multi-blockchain platform featuring a masterchain that coordinates multiple workchains and shardchains. Originally designed by Nikolai Durov, TON uses the TVM (TON Virtual Machine) and FunC/Tact smart contract languages.

| Property          | Value                              |
| ----------------- | ---------------------------------- |
| ZASEON Chain ID   | `16100`                            |
| Bridge Type       | BridgeRelay-CatchainBFT            |
| Contract          | `TONBridgeAdapter.sol`             |
| VM                | TVM (TON Virtual Machine)          |
| Finality          | ~5 seconds (masterchain block)     |
| Security Model    | Validator multisig + Merkle proofs |
| Default Workchain | 0 (basechain)                      |

## Architecture

```
┌─────────────┐    TON Bridge     ┌──────────────────┐  Validators  ┌─────────────┐
│   ZASEON     │ ──sendMessage────▶│   TON Bridge     │ ─attestation▶│  ~340 TON   │
│   Adapter    │                   │   Relay (ETH)    │              │  Validators │
└─────────────┘                   └──────────────────┘              └─────────────┘
       ▲                                                                   │
       │                    Merkle proof / validator sigs                   │
       └───────────────────────────────────────────────────────────────────┘
```

### Key Concepts

- **TVM**: Stack-based virtual machine using Cells data structure
- **Masterchain**: Coordinates all workchains, handles validator set rotation
- **Workchains**: Independent blockchains (workchain 0 = basechain)
- **Shardchains**: Dynamic sharding within each workchain
- **Catchain BFT**: Consensus protocol for validator agreement
- **Cells**: Tree-of-cells data structure (up to 1023 bits + 4 refs per cell)
- **Addresses**: workchain_id (int8) + account_id (bytes32)
- **Validators**: ~340 validators with rotating sessions

## Contract Details

### TONBridgeAdapter

The adapter provides:

1. **Outbound messaging** via TON Bridge relay `sendMessage`
2. **Inbound verification** using light client proofs or bridge relay verification
3. **Contract whitelisting** for trusted TON addresses (workchain-qualified)
4. **Workchain support management** (enable/disable workchains)
5. **Nullifier-based replay protection** via ZASEON CDNA

### Key Functions

```solidity
// Send a message to TON
function sendMessage(
    int8 workchain,
    bytes32 destination,
    bytes calldata payload
) external payable returns (bytes32 messageHash);

// Receive and verify a message from TON
function receiveMessage(
    bytes32 tonSender,
    int8 workchain,
    bytes calldata payload,
    bytes calldata proof
) external returns (bytes32 messageHash);

// Whitelist a TON contract address
function whitelistContract(bytes32 tonContract) external;

// Enable/disable workchain support
function setSupportedWorkchain(int8 workchain, bool supported) external;
```

### Security Features

- Dual verification: light client proofs OR bridge relay attestation
- Contract whitelisting (only trusted TON addresses accepted)
- Workchain validation (only enabled workchains accepted)
- Nullifier tracking prevents double-spending
- Pause/unpause for emergency response
- Role-based access (OPERATOR, RELAYER, GUARDIAN, PAUSER)

## SDK Usage

```typescript
import {
  TON_CHAIN_ID,
  DEFAULT_WORKCHAIN,
  TONBridgeAdapterABI,
} from "@zaseon/sdk/bridges/ton";

// Send a privacy message to TON basechain
const tx = await walletClient.writeContract({
  address: adapterAddress,
  abi: TONBridgeAdapterABI,
  functionName: "sendMessage",
  args: [DEFAULT_WORKCHAIN, tonDestination, payload],
  value: relayFee,
});
```

## TON Addresses

TON addresses consist of a workchain ID and a 32-byte account hash:

```
Workchain 0:  EQ... (basechain, user-friendly format)
Workchain -1: Ef... (masterchain)
```

Raw format: `workchain:account_hash`

```
0:a4e7c8d2f1b3e5a6c8d0f2e4b6a8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2
```

When passing to the adapter:

- `workchain` = `0` (int8)
- `destination` = `0xa4e7...f0a2` (bytes32)

## Deployment

```bash
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "ton" \
  --rpc-url $RPC_URL \
  --broadcast
```

## References

- [TON Documentation](https://docs.ton.org/)
- [TON Blockchain Overview](https://docs.ton.org/learn/overviews/ton-blockchain)
- [TVM Specification](https://docs.ton.org/learn/tvm-instructions/tvm-overview)
- [TON Bridge](https://docs.ton.org/participate/crosschain/bridge-addresses)
- [FunC Language](https://docs.ton.org/develop/func/overview)
- [Tact Language](https://docs.tact-lang.org/)
