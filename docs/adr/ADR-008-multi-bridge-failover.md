# ADR-008: Multi-Bridge Failover Architecture

## Status

Accepted

## Date

2026-03-01

## Context

ZASEON routes cross-chain messages through multiple bridge protocols. Single-bridge dependency creates:

1. **Liveness risk**: Bridge downtime halts state transfers
2. **Safety risk**: Bridge compromise enables invalid state injection
3. **Cost risk**: No fee competition, users pay whatever one bridge charges

Requirements: fault-tolerant message delivery, configurable bridge priority, automatic failover.

## Decision

Implement **MultiBridgeRouter** with configurable routing strategies via `IBridgeAdapter` plugin interface.

### Architecture

```
MultiBridgeRouter
├── Primary: Native L2 bridge (cheapest, most trust)
├── Secondary: LayerZero or Hyperlane (fastest, widest reach)
└── Tertiary: Wormhole, Axelar, or CCIP (redundancy)
```

### Routing strategies

1. **Priority**: Try bridges in configured order, failover on revert
2. **Cheapest**: Query `estimateFee()` on all adapters, pick lowest
3. **Fastest**: Use messaging bridges (LayerZero/Hyperlane) for time-critical ops
4. **Redundant**: Send via N-of-M bridges, require quorum for acceptance

### IBridgeAdapter interface

All 11 bridge adapters implement:

- `bridgeMessage(uint256, address, bytes)`: Send a cross-chain message
- `estimateFee(uint256, bytes)`: Quote the fee for a message
- `isMessageVerified(bytes32)`: Check if a received message is verified

### Failover logic

1. Router calls primary adapter's `bridgeMessage()`
2. If reverts or returns empty, try secondary
3. If all configured adapters fail, revert with `AllBridgesFailed`
4. For redundant mode: require `threshold` of `adapters.length` successes

### Rationale

- **Plugin interface**: New bridges added without router changes
- **Per-route config**: Different chains can prefer different bridges
- **Fee competition**: `estimateFee()` enables cost optimization
- **Trust minimization**: Redundant mode requires multi-bridge consensus

## Consequences

- Each supported chain has a `RouteConfig` specifying bridge priority
- Bridge adapters are independently pausable via Guardian role
- Route changes require Operator role + optional timelock
- Gas overhead: ~5k per bridge query in cheapest mode
- 9 adapters currently deployed: Arbitrum, Optimism, Base, Aztec, zkSync, Scroll, Linea, LayerZero, Hyperlane
