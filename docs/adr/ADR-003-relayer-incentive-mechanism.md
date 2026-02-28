# ADR-003: Relayer Incentive Mechanism

## Status

Accepted

## Date

2026-02-27

## Context

ZASEON's privacy transactions require relayers to submit proofs on behalf of users (to avoid linking the user's address to the transaction). The relayer infrastructure must:

1. **Incentivize speed**: Faster relay improves UX and reduces exposure to MEV/front-running
2. **Prevent freeloading**: Relayers must stake to participate, ensuring accountability
3. **Dynamic pricing**: Fee market must adapt to demand without manual intervention
4. **Resist griefing**: Relayers claiming jobs and not completing them must be penalized
5. **Support decentralization**: Target 50+ independent relayers for censorship resistance

Traditional approaches:

- **Fixed fees**: Simple but doesn't adapt to demand; undershoots during congestion, overshoots during calm
- **First-come-first-served**: Leads to gas wars between relayers
- **Auction-only**: High latency, complex for users

## Decision

Implement a **three-layer relayer incentive architecture**: EIP-1559-style dynamic fee market, staking with slashing, and speed-tiered instant rewards.

### Layer 1: Dynamic Fee Market (RelayerFeeMarket)

EIP-1559-inspired pricing with per-epoch (1-hour) base fee adjustment:

```
Target utilization: 50% (5000 bps)
Adjustment rate:    12.5% per epoch (matching EIP-1559)
Max relays/epoch:   1000
Min base fee:       0.0001 ETH
Max base fee:       1.0 ETH
Request deadline:   4 hours
Claim timeout:      30 minutes
Protocol cut:       5%
```

Users submit requests with `maxFee` + `priorityFee` (tip). Relayers claim requests and complete them within the claim timeout. For high-value transfers (configurable threshold), a **sealed-bid first-price auction** replaces the open fee market.

**Fee calculation**: `effectiveFee = min(baseFee + priorityFee, maxFee)`

### Layer 2: Staking & Slashing (RelayerStaking)

```
Min stake:            Configurable at deploy
Unbonding period:     7 days
Slashing percentage:  10% (1000 bps)
Flash loan protection: 1-day minimum stake duration before rewards
Reward model:         Per-share (rewardPerShare with 1e18 precision)
```

Relayer lifecycle:

1. `stake()` — deposit ETH, auto-activate when ≥ `minStake`
2. Active relaying — accumulate rewards per successful relay
3. `requestUnstake()` → 7-day unbonding → `completeUnstake()`
4. Slashing by `SLASHER_ROLE` for provable misbehavior (failed relays, timeout violations)

Per-relayer tracking: `stakedAmount`, `pendingUnstake`, `unstakeRequestTime`, `rewardDebt`, `successfulRelays`, `failedRelays`, `isActive`, `metadata`.

### Layer 3: Speed-Tiered Instant Rewards (InstantRelayerRewards)

| Speed Tier | Threshold    | Multiplier                |
| ---------- | ------------ | ------------------------- |
| ULTRA_FAST | < 30 seconds | 1.5x (15000 bps)          |
| FAST       | < 60 seconds | 1.25x (12500 bps)         |
| NORMAL     | < 5 minutes  | 1.0x (10000 bps)          |
| SLOW       | ≥ 5 minutes  | 0.9x (9000 bps) — penalty |

Flow: `depositRelayFee()` → relayer claims → `completeRelayWithReward()` calculates tiered payout → protocol cut (5%) + relayer instant reward + surplus refunded to user.

Per-relayer stats: `totalRewards`, `totalRelays`, `ultraFastCount`, `fastCount`, `normalCount`, `slowCount`, `avgResponseTime`. Max 1000 relays tracked per relayer for gas bounds.

### Supporting infrastructure

- **RelayerHealthMonitor**: Track uptime, latency, success rates
- **RelayerSLAEnforcer**: Enforce service level agreements
- **MultiRelayerRouter**: Route across multiple relayers with failover
- **HeterogeneousRelayerRegistry**: Support different relayer types (full, light, specialized)
- **GelatoRelayAdapter / SelfRelayAdapter**: Integration with external relay services and user self-relay fallback

## Consequences

### Positive

- **Market efficiency**: EIP-1559-style pricing auto-adjusts to demand, preventing both overpayment and underpayment
- **Speed incentive**: 1.5x multiplier for < 30s relay creates strong economic pressure for fast infrastructure
- **Griefing resistance**: 30-min claim timeout + 10% slashing makes claim-and-abandon unprofitable
- **Flash loan protection**: 1-day minimum stake duration prevents stake-borrow-relay-unstake attacks
- **Decentralization**: Per-share reward model + low barrier (configurable min stake) enables wide participation
- **Self-relay fallback**: Users can relay their own transactions if all relayers are offline

### Negative

- **Three-contract complexity**: Fee market, staking, and rewards are separate contracts that must be correctly integrated
- **Gas overhead**: Speed tier calculation and per-relayer stat tracking add ~30-50k gas per relay completion
- **Epoch boundary effects**: Fee adjustments happen per-epoch (1 hour), so sudden demand spikes within an epoch aren't immediately priced
- **Sealed-bid auction UX**: High-value transfer auctions add latency and complexity for users
- **1000-relay tracking limit**: Per-relayer stats are bounded at 1000 entries, losing historical data

### Risks

- Insufficient relayer participation at launch → mitigated by SelfRelayAdapter and GelatoRelayAdapter
- Collusion between relayers to inflate base fees → mitigated by 50% target utilization and max base fee cap
- MEV extraction by relayers during relay → future mitigation via PrivateRelayerNetwork (experimental)

## References

- [RelayerFeeMarket.sol](../../contracts/relayer/RelayerFeeMarket.sol)
- [RelayerStaking.sol](../../contracts/relayer/RelayerStaking.sol)
- [InstantRelayerRewards.sol](../../contracts/relayer/InstantRelayerRewards.sol)
- EIP-1559: Fee market change for ETH 1.0 chain
- Flashbots MEV-Share: Inspiration for sealed-bid relay auctions
