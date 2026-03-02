# Axelar Network Integration

## Overview

ZASEON integrates with **Axelar Network** for cross-chain privacy-preserving message passing using Axelar's **General Message Passing (GMP)** protocol. Axelar is a decentralised cross-chain communication platform connecting 60+ blockchains through a delegated proof-of-stake (DPoS) validator set that collectively signs cross-chain messages via **threshold ECDSA multi-sig** (weighted by stake).

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ZASEON Protocol                       │
│                                                         │
│  ┌─────────────────────┐    ┌────────────────────────┐  │
│  │  MultiBridgeRouter   │───│  AxelarBridgeAdapter   │  │
│  │  (BridgeType.AXELAR) │   │  (IBridgeAdapter)      │  │
│  └──────────┬──────────┘    └──────────┬─────────────┘  │
│             │                          │                 │
└─────────────┼──────────────────────────┼─────────────────┘
              │                          │
              │    ┌─────────────────────┼──────────┐
              │    │  Axelar Network                 │
              │    │                                 │
              │    │  ┌────────────────┐             │
              ├────┼──│ Gas Service    │  gas prepay │
              │    │  └────────────────┘             │
              │    │  ┌────────────────┐             │
              └────┼──│ Gateway        │  GMP calls  │
                   │  └───────┬────────┘             │
                   │          │                      │
                   │  ┌───────▼────────┐             │
                   │  │ DPoS Validators│             │
                   │  │ Threshold ECDSA│             │
                   │  └───────┬────────┘             │
                   │          │                      │
                   └──────────┼──────────────────────┘
                              │
              ┌───────────────▼───────────────────┐
              │     Destination Chain              │
              │  ┌────────────────┐                │
              │  │ Gateway        │ validateCall   │
              │  └───────┬────────┘                │
              │          │                         │
              │  ┌───────▼────────────────────┐    │
              │  │ AxelarBridgeAdapter (dest) │    │
              │  └────────────────────────────┘    │
              └────────────────────────────────────┘
```

## Contract

**`contracts/crosschain/AxelarBridgeAdapter.sol`**

| Property            | Value                         |
| ------------------- | ----------------------------- |
| Chain ID (ZASEON)   | `12100`                       |
| Chain Name          | `"axelar"`                    |
| Finality            | 28 blocks                     |
| Bridge Type         | `BridgeType.AXELAR` (index 4) |
| Verification        | Threshold ECDSA via Gateway   |
| Payload Limit       | 10,000 bytes                  |
| Max Fee             | 100 bps                       |
| Execution Gas Limit | 300,000 (configurable)        |

### Key Interfaces

```solidity
interface IAxelarGateway {
    function callContract(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload
    ) external;

    function callContractWithToken(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload,
        string calldata symbol,
        uint256 amount
    ) external;

    function isCommandExecuted(bytes32 commandId) external view returns (bool);

    function validateContractCall(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external returns (bool);
}

interface IAxelarGasService {
    function payNativeGasForContractCall(
        address sender,
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable;

    function estimateGasFee(
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes calldata payload,
        uint256 executionGasLimit,
        bytes calldata params
    ) external view returns (uint256);
}
```

### Axelar Chain Names

Axelar uses **string-based chain identifiers** (unlike numeric chain IDs). The adapter uses a `registeredChains` mapping to allow only whitelisted destinations:

| Axelar Name | Network   |
| ----------- | --------- |
| `ethereum`  | Ethereum  |
| `avalanche` | Avalanche |
| `polygon`   | Polygon   |
| `arbitrum`  | Arbitrum  |
| `optimism`  | Optimism  |
| `base`      | Base      |
| `fantom`    | Fantom    |
| `moonbeam`  | Moonbeam  |
| `binance`   | BNB Chain |
| `scroll`    | Scroll    |
| `linea`     | Linea     |
| `mantle`    | Mantle    |
| `kava`      | Kava      |
| `filecoin`  | Filecoin  |
| `celo`      | Celo      |

Register chains via admin:

```solidity
adapter.registerChain("avalanche");
adapter.registerChain("polygon");
```

### Sending Messages

```solidity
// 1. Estimate gas via Gas Service
uint256 fee = adapter.estimateFee(targetAddress, payload);

// 2. Send with gas payment
bytes32 msgId = adapter.sendMessage{value: fee}(
    "avalanche",              // destination chain name
    "0xDestContract...",      // destination address
    payload                   // ZASEON privacy payload
);
```

### Receiving Messages

Inbound messages are verified via the Gateway's `validateContractCall`:

```solidity
bytes32 msgHash = adapter.receiveMessage(
    commandId,           // Axelar command ID
    "ethereum",          // source chain
    "0xSrcContract...",  // source address
    payload
);
```

The adapter verifies:

1. Gateway confirms the command via `validateContractCall`
2. Command hasn't been executed before (replay protection)
3. Source chain is a registered chain
4. Payload passes length and format checks

## Security Considerations

### Threshold ECDSA Multi-Sig

Axelar validators collectively sign messages using weighted threshold ECDSA. This means:

- No single validator can forge a cross-chain message
- The threshold is weighted by staked AXL tokens
- Slashing conditions apply for misbehaving validators

### Replay Protection

Three layers:

1. **Axelar Gateway**: `isCommandExecuted` check prevents replaying commands
2. **ZASEON Adapter**: `processedMessages` mapping tracks all received message hashes
3. **ZASEON CDNA**: NullifierRegistryV3 catches domain-level replays

### Access Control

| Role       | Capability                                                    |
| ---------- | ------------------------------------------------------------- |
| `ADMIN`    | Set gateway/gas service, register/unregister chains, set fees |
| `OPERATOR` | Send messages                                                 |
| `RELAYER`  | Receive messages (relay inbound GMP calls)                    |
| `GUARDIAN` | Emergency operations (drain, pause)                           |
| `PAUSER`   | Pause/unpause adapter                                         |

### Gas Prepayment

Axelar requires gas prepayment via the Gas Service for destination chain execution. The adapter:

1. Forwards `msg.value` to `IAxelarGasService.payNativeGasForContractCall`
2. Axelar relayers execute on the destination using prepaid gas
3. Excess gas is refunded to the specified `refundAddress`

## Deployment

### Environment Variables

```bash
AXELAR_GATEWAY=0x...        # Axelar Gateway address (chain-specific)
AXELAR_GAS_SERVICE=0x...    # Axelar Gas Service address (chain-specific)
```

### Mainnet Gateway Addresses

| Chain     | Gateway                                      |
| --------- | -------------------------------------------- |
| Ethereum  | `0x4F4495243837681061C4743b74B3eEdf548D56A5` |
| Avalanche | `0x5029C0EFf6C34351a0CEc334542cDb22c7928aa7` |
| Polygon   | `0x6f015F16De9fC8791b234eF68D486d2bF203FBA8` |
| Arbitrum  | `0xe432150cce91c13a887f7D836923d5597adD8E31` |
| Optimism  | `0xe432150cce91c13a887f7D836923d5597adD8E31` |
| Base      | `0xe432150cce91c13a887f7D836923d5597adD8E31` |

### Deploy Script

```bash
# Via DeployL2Bridges.s.sol
forge script scripts/deploy/DeployL2Bridges.s.sol \
  --sig "run(string)" "axelar" \
  --broadcast --verify
```

### Post-Deploy

1. Register destination chains:

   ```solidity
   adapter.registerChain("avalanche");
   adapter.registerChain("polygon");
   adapter.registerChain("arbitrum");
   ```

2. Register adapter with MultiBridgeRouter:

   ```solidity
   router.registerBridgeAdapter(
       BridgeType.AXELAR,
       address(axelarAdapter)
   );
   ```

3. Wire into ProtocolHub:
   ```solidity
   hub.wireAll();
   ```

## SDK Usage

### TypeScript

```typescript
import { AxelarBridge } from "@zaseon/sdk/bridges";

// Constants
console.log(AxelarBridge.AXELAR_CHAIN_ID); // 12100
console.log(AxelarBridge.AXELAR_FINALITY_BLOCKS); // 28
console.log(AxelarBridge.AXELAR_CHAIN_NAMES.AVALANCHE); // "avalanche"

// Validate chain names
AxelarBridge.isValidAxelarChainName("avalanche"); // true
AxelarBridge.isValidAxelarChainName("AVALANCHE"); // false (must be lowercase)

// Get chain name
AxelarBridge.getAxelarChainName("POLYGON"); // "polygon"

// Nullifier tagging (for CDNA)
const tag = AxelarBridge.getAxelarNullifierTag("0xabc...");
// => "axelar:gmp:threshold-ecdsa:0xabc..."

// Fee estimation
const totalFee = AxelarBridge.estimateTotalFee(
  50000000000000n, // gas service fee (0.00005 ETH)
  10, // 10 bps protocol fee
  1000000000000000000n, // 1 ETH value
);
```

### Using with viem

```typescript
import { createPublicClient, http } from "viem";
import { mainnet } from "viem/chains";
import { AXELAR_BRIDGE_ADAPTER_ABI } from "@zaseon/sdk/bridges/axelar";

const client = createPublicClient({ chain: mainnet, transport: http() });

// Check if chain is registered
const isRegistered = await client.readContract({
  address: "0xAdapterAddress...",
  abi: AXELAR_BRIDGE_ADAPTER_ABI,
  functionName: "isChainRegistered",
  args: ["avalanche"],
});

// Estimate fee
const fee = await client.readContract({
  address: "0xAdapterAddress...",
  abi: AXELAR_BRIDGE_ADAPTER_ABI,
  functionName: "estimateFee",
  args: ["0xTargetAddress...", payload],
});
```

## Testing

```bash
# Run Axelar adapter tests
forge test --match-path 'test/crosschain/AxelarBridgeAdapter.t.sol' -vvv
```

The test suite includes:

- **~60 unit tests** covering constructor, constants, views, admin, send, receive, pause, emergency
- **4 fuzz tests** covering fee bounds, payload lengths, chain name generation, and destination addresses
- Mock Gateway (configurable approval) and Gas Service (gas tracking)

## Comparison with Other Bridge Adapters

| Feature          | Axelar          | Hyperlane        | LayerZero        | Chainlink CCIP   |
| ---------------- | --------------- | ---------------- | ---------------- | ---------------- |
| Verification     | Threshold ECDSA | ISM (modular)    | Ultra-Light Node | DON + Risk Mgmt  |
| Chain IDs        | String-based    | Numeric (uint32) | Numeric (uint16) | Numeric (uint64) |
| Gas Payment      | Gas Service     | Interchain Gas   | LayerZero fees   | LINK token       |
| Chains Supported | 60+             | 50+              | 40+              | 20+              |
| Finality         | ~28 blocks      | Varies by ISM    | Varies by ULN    | Varies by chain  |

## References

- [Axelar Network Docs](https://docs.axelar.dev/)
- [Axelar GMP](https://docs.axelar.dev/dev/general-message-passing/overview)
- [Axelar Gateway Contracts](https://docs.axelar.dev/dev/reference/mainnet-contract-addresses)
- [ZASEON Bridge Integration Guide](BRIDGE_INTEGRATION.md)
