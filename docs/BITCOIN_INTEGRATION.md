# Bitcoin Bridge Integration

## Overview

The `BitcoinBridgeAdapter` provides trustless Bitcoin integration using SPV (Simple Payment Verification) proofs and HTLC (Hash Time-Locked Contracts) for cross-chain atomic swaps between Soul Protocol and the Bitcoin network.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Soul ↔ Bitcoin Bridge                         │
│                                                              │
│  ┌──────────────┐      ┌──────────────┐    ┌──────────┐    │
│  │ Bitcoin      │      │ SPV Light    │    │ HTLC     │    │
│  │ Bridge       │◄────▶│ Client       │    │ Engine   │    │
│  │ Adapter      │      │ (Headers)    │    │          │    │
│  └──────┬───────┘      └──────────────┘    └────┬─────┘    │
│         │                                        │          │
│  ┌──────▼───────┐      ┌──────────────┐    ┌────▼─────┐   │
│  │ wBTC         │      │ Block        │    │ Timelock │   │
│  │ Minting      │◄────▶│ Relay        │    │ Manager  │   │
│  └──────────────┘      └──────────────┘    └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Contract

- **Path**: `contracts/crosschain/BitcoinBridgeAdapter.sol`
- **Solidity**: `^0.8.20`
- **Lines**: ~891

## Key Features

- SPV proof verification for trustless Bitcoin transaction inclusion
- HTLC-based atomic swaps with configurable timelock bounds
- wBTC minting/burning for representation on EVM chains
- Block header relay for light client operation
- Configurable confirmation requirements (default: 6 blocks)
- Registration-based withdrawal system
- Emergency pause and guardian controls

## HTLC Lifecycle

```
1. Create HTLC → Lock funds with hashlock + timelock
2. Counterparty reveals preimage on Bitcoin
3. Claim HTLC → Redeem with preimage
   OR
4. Timelock expires → Refund to creator
```

## Roles

| Role | Purpose |
|------|---------|
| `DEFAULT_ADMIN_ROLE` | Configure SPV verifier, wBTC address |
| `OPERATOR_ROLE` | Manage HTLC operations, relay blocks |
| `GUARDIAN_ROLE` | Pause/unpause, emergency withdraw |

## Configuration

```solidity
BitcoinBridgeAdapter bridge = new BitcoinBridgeAdapter(admin);

// Configure SPV verifier and wBTC
bridge.configure(spvVerifier, wbtcAddress);

// Set timelock bounds
bridge.setTimelockBounds(minTimelock, maxTimelock);

// Set confirmation requirement
bridge.setRequiredConfirmations(6);
```

## SDK Usage

```typescript
import { BITCOIN_BRIDGE_ABI, BitcoinConstants } from '@soul/sdk/bridges/bitcoin';
```

## Testing

```bash
# Run fuzz tests
forge test --match-contract BitcoinBridgeFuzz -vvv
```

## Deployment

```bash
npx hardhat run scripts/deploy/deploy-bitcoin-bridge.ts --network mainnet
```

## Security Considerations

- SPV proofs require minimum 6 block confirmations
- HTLC timelocks bounded to prevent griefing attacks
- All HTLC state transitions are irreversible and logged
- wBTC minting requires verified SPV proof
- ReentrancyGuard on all state-changing operations
