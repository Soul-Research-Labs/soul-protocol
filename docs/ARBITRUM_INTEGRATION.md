# Arbitrum Bridge Integration

## Overview

The `ArbitrumBridgeAdapter` provides native integration with Arbitrum's canonical bridge for L1↔L2 message passing and asset transfers within the Soul Protocol ecosystem.

## Architecture

```
┌─────────────────────┐        ┌─────────────────────┐
│   Ethereum L1       │        │    Arbitrum L2       │
│                     │        │                      │
│  ┌───────────────┐  │        │  ┌───────────────┐   │
│  │ Arbitrum      │──┼────────┼─▶│ L2 Gateway    │   │
│  │ BridgeAdapter │  │        │  │               │   │
│  └───────┬───────┘  │        │  └───────────────┘   │
│          │          │        │                      │
│  ┌───────▼───────┐  │        │                      │
│  │ Inbox/Outbox  │  │        │                      │
│  │ Router        │──┼────────┼─▶ Challenge Window   │
│  └───────────────┘  │        │   (6.4 days)         │
└─────────────────────┘        └─────────────────────┘
```

## Contract

- **Path**: `contracts/crosschain/ArbitrumBridgeAdapter.sol`
- **Solidity**: `^0.8.24`
- **Lines**: ~811

## Key Features

- Native Inbox/Outbox integration for retryable tickets
- Configurable rollup parameters (challenge period, gas oracle)
- Token mapping (L1 ↔ L2 gateway addresses)
- Fast exit support with liquidity providers
- Deposit limits (min/max configurable per operator)
- Fee management in basis points
- Withdrawal proof verification with challenge window

## Roles

| Role | Purpose |
|------|---------|
| `DEFAULT_ADMIN_ROLE` | Configure rollup, set operator/guardian |
| `OPERATOR_ROLE` | Map tokens, adjust deposit limits, configure fees |
| `GUARDIAN_ROLE` | Pause/unpause, emergency withdraw |

## Configuration

```solidity
// Set rollup target addresses
bridge.setRollupConfig(inbox, outbox, rollup, challengePeriod, gasOracle);

// Map L1 token to L2 gateway
bridge.mapToken(l1Token, l2Gateway, l2Token);

// Configure fees
bridge.setFeeConfig(depositFeeBps, withdrawalFeeBps);
```

## SDK Usage

```typescript
import { ARBITRUM_BRIDGE_ABI, ArbitrumConstants, calculateBridgeFee } from '@soul/sdk/bridges/arbitrum';

const fee = calculateBridgeFee(depositAmount, feeBps);
```

## Testing

```bash
# Run fuzz tests
forge test --match-contract ArbitrumBridgeFuzz -vvv

# Run Certora verification
certorun certora/conf/verify_arbitrum_bridge.conf
```

## Deployment

```bash
npx hardhat run scripts/deploy/deploy-arbitrum-bridge.ts --network arbitrum
```

## Security Considerations

- Challenge period defaults to 6.4 days for L2→L1 messages
- All state-changing functions protected by ReentrancyGuard
- Fast exits require sufficient liquidity provider stake
- Deposit limits prevent economic attacks
