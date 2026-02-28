# Base (OP Stack) Bridge Integration

## Overview

The `BaseBridgeAdapter` provides integration with Base and the OP Stack canonical bridge for cross-chain messaging and asset transfers. Supports native L1↔L2 messaging via CrossDomainMessenger and CCTP for USDC transfers.

## Architecture

```
┌─────────────────────┐        ┌─────────────────────┐
│   Ethereum L1       │        │    Base L2           │
│                     │        │                      │
│  ┌───────────────┐  │        │  ┌───────────────┐   │
│  │ Base Bridge   │──┼────────┼─▶│ L2 Messenger  │   │
│  │ Adapter       │  │        │  │               │   │
│  └───────┬───────┘  │        │  └───────────────┘   │
│          │          │        │                      │
│  ┌───────▼───────┐  │        │  ┌───────────────┐   │
│  │ CrossDomain   │  │        │  │ Optimism      │   │
│  │ Messenger     │──┼────────┼─▶│ Portal        │   │
│  └───────────────┘  │        │  └───────────────┘   │
│                     │        │                      │
│  ┌───────────────┐  │        │  ┌───────────────┐   │
│  │ CCTP          │──┼────────┼─▶│ USDC Bridge   │   │
│  │ TokenMessenger│  │        │  │               │   │
│  └───────────────┘  │        │  └───────────────┘   │
└─────────────────────┘        └─────────────────────┘
```

## Contract

- **Path**: `contracts/crosschain/BaseBridgeAdapter.sol`
- **Solidity**: `^0.8.24`
- **Lines**: ~891

## Key Features

- Native OP Stack CrossDomainMessenger integration
- OptimismPortal support for withdrawal proving and finalization
- CCTP (Cross-Chain Transfer Protocol) for USDC
- Cross-chain proof relay with duplicate protection
- L2 target chain management (Base, OP Mainnet, Mode, etc.)
- State synchronization with batched updates
- Emergency withdrawal mechanism

## Roles

| Role                 | Purpose                             |
| -------------------- | ----------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Core configuration                  |
| `OPERATOR_ROLE`      | Manage L2 targets, configure CCTP   |
| `GUARDIAN_ROLE`      | Pause/unpause, emergency operations |
| `RELAYER_ROLE`       | Relay proofs, sync state            |

## Configuration

```solidity
// Constructor params
BaseBridgeAdapter bridge = new BaseBridgeAdapter(
    l1Messenger,       // L1CrossDomainMessenger
    optimismPortal,    // OptimismPortalProxy
    admin
);

// Add L2 target chain
bridge.addL2Target(8453, l2Messenger, "base");

// Configure CCTP
bridge.configureCCTP(cctpMessenger, usdcAddress, baseDomain);
```

## SDK Usage

```typescript
import {
  BASE_BRIDGE_ABI,
  computeMessageId,
  isWithdrawalReady,
} from "@zaseon/sdk/bridges/base";

const msgId = computeMessageId(origin, sender, nonce, target, message);
const ready = isWithdrawalReady(provenAt, challengePeriod);
```

## Testing

```bash
# Run fuzz tests
forge test --match-contract BaseBridgeFuzz -vvv

# Run Hardhat tests
npx hardhat test test/crosschain/BaseBridge.test.ts

# Certora verification
certoraRun certora/conf/verify_base_bridge.conf
```

## Deployment

```bash
npx hardhat run scripts/deploy/deploy-base-bridge.ts --network mainnet
```

## Security Considerations

- 7-day challenge/finalization period for L2→L1 withdrawals
- Duplicate proof relay protection via message hash tracking
- All state-changing functions use ReentrancyGuard
- CCTP transfers have separate domain validation
