# LayerZero V2 Bridge Integration

## Overview

The `LayerZeroBridgeAdapter` integrates LayerZero V2's omnichain messaging protocol for cross-chain communication. Supports OFT (Omnichain Fungible Token) bridging, composed messaging, and multi-chain deployments with flexible DVN-based security.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                LayerZero V2 Integration                       │
│                                                                │
│  ┌──────────────┐    ┌──────────────┐    ┌── ────────────┐   │
│  │ LayerZero    │───▶│ DVN          │───▶│ Destination   │   │
│  │ Bridge       │    │ Verification │    │ Execution     │   │
│  │ Adapter      │    │ Network      │    │               │   │
│  └──────┬───────┘    └──────────────┘    └───────────────┘   │
│         │                                                     │
│  ┌──────▼───────┐    ┌──────────────┐                        │
│  │ OFT/ONFT     │    │ Composed     │                        │
│  │ Bridging     │    │ Messaging    │                        │
│  └──────────────┘    └──────────────┘                        │
│                                                                │
│  Supported Chains: EVM, Solana, Aptos, SUI, IOTA, Hyperliquid│
└───────────────────────────────────────────────────────────────┘
```

## Contract

- **Path**: `contracts/crosschain/LayerZeroBridgeAdapter.sol`
- **Solidity**: `^0.8.24`
- **Lines**: ~955

## Key Features

- LayerZero V2 Endpoint integration
- Peer management with per-chain security levels
- OFT (Omnichain Fungible Token) send/receive
- ONFT (Omnichain NFT) transfers
- Composed messaging for complex cross-chain operations
- DVN (Decentralized Verifier Network) configuration
- Send/Receive library configurations per endpoint
- Multi-chain type support (EVM, Solana, Aptos, SUI, etc.)
- Bridge fee accrual in basis points (max 1%)

## Security Levels

| Level | Description |
|-------|-------------|
| `STANDARD` | Single DVN verification |
| `ENHANCED` | 2-of-N DVN verification |
| `MAXIMUM` | Required + Optional DVNs with threshold |

## Roles

| Role | Purpose |
|------|---------|
| `DEFAULT_ADMIN_ROLE` | Set endpoint, bridge fee |
| `OPERATOR_ROLE` | Operational tasks |
| `GUARDIAN_ROLE` | Pause, deactivate peers, update security |
| `EXECUTOR_ROLE` | Execute received messages |
| `CONFIG_ROLE` | Manage peers, library configs |

## Configuration

```solidity
LayerZeroBridgeAdapter bridge = new LayerZeroBridgeAdapter();

// Set endpoint
bridge.setEndpoint(lzEndpointAddress, localEid);

// Add peer (Arbitrum)
bridge.setPeer(
    30110,                      // Arbitrum EID
    bytes32(uint256(uint160(remoteOApp))),
    ChainType.EVM,
    200000,                     // minGas
    SecurityLevel.ENHANCED
);

// Set bridge fee
bridge.setBridgeFee(10);  // 0.1%
```

## SDK Usage

```typescript
import {
    LAYERZERO_BRIDGE_ABI,
    LZ_EIDS,
    addressToBytes32,
    calculateLzFee,
    createDefaultOptions
} from '@zaseon/sdk/bridges/layerzero';

const peerAddr = addressToBytes32(remoteContractAddress);
const options = createDefaultOptions(200_000n);
```

## Testing

```bash
# Run fuzz tests
forge test --match-contract LayerZeroBridgeFuzz -vvv
```

## Deployment

```bash
npx hardhat run scripts/deploy/deploy-layerzero-bridge.ts --network mainnet
```

## Security Considerations

- DVN-based security with configurable verification levels
- Bridge fee capped at 1% (100 bps)
- Peer deactivation for emergency chain isolation
- Message nonce tracking prevents replay attacks
- Failed messages are stored for retry
- All state-changing functions use ReentrancyGuard
