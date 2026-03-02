# Scroll Integration

## Overview

ZASEON integrates with **Scroll**, a Type 2 zkEVM rollup providing bytecode-level EVM compatibility with zkSNARK validity proofs.

| Property       | Value                                  |
| -------------- | -------------------------------------- |
| Chain ID       | `534352` (mainnet), `534351` (Sepolia) |
| Bridge Type    | ScrollMessenger / ZK Proof             |
| Contract       | `ScrollBridgeAdapter.sol`              |
| VM             | EVM (Type 2 zkEVM)                     |
| Finality       | Instant (ZK proof finality)            |
| Security Model | zkSNARK validity proofs                |
| Status         | Graduated, Certora verified            |

## Key Features

- Type 2 EVM equivalence (bytecode-compatible)
- L1ScrollMessenger / L2ScrollMessenger for messaging
- zkSNARK proofs for state verification
- Gateway Router for token bridging
- Withdrawal proofs against verified state roots
- `FINALITY_BLOCKS = 1`

## Contract

```solidity
constructor(
    address _scrollMessenger,
    address _gatewayRouter,
    address _rollupContract,
    address _admin
)
```

## Deployment

```bash
DEPLOY_TARGET=scroll forge script scripts/deploy/DeployL2Bridges.s.sol \
  --rpc-url $SCROLL_RPC --broadcast --verify -vvv
```

## References

- [Scroll Documentation](https://docs.scroll.io/)
- [Scroll Architecture](https://docs.scroll.io/en/technology/)
