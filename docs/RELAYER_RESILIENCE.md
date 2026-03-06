# Relayer Network Resilience Strategy

> Multi-layer resilience approach for ZASEON's relayer network — ensuring reliable cross-chain message delivery with redundancy and failover.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [Multi-Layer Resilience Approach](#multi-layer-resilience-approach)
- [Implementation Roadmap](#implementation-roadmap)
- [Success Metrics](#success-metrics)
- [Monitoring Dashboard](#monitoring-dashboard)
- [Contract Reference](#contract-reference)
- [Fee Market](#fee-market)
- [Multi-Relayer Routing](#multi-relayer-routing)
- [Relayer Clusters](#relayer-clusters)
- [Instant Rewards](#instant-rewards)
- [Gelato Integration](#gelato-integration)
- [Heterogeneous Registry](#heterogeneous-registry)
- [Interface](#interface)
- [Resources](#resources)

---

## Problem Statement

ZASEON depends on relayers for cross-chain message delivery. Single points of failure or relayer unavailability could disrupt service.

## Multi-Layer Resilience Approach

### 1. Relayer Diversity

**Current State**: Single relayer network
**Target State**: Multiple independent relayer options

#### Implementation

```solidity
// contracts/relayer/MultiRelayerRouter.sol
contract MultiRelayerRouter {
    enum RelayerType {
        ZASEON_NATIVE,      // Zaseon's own relayer network
        GELATO,           // Gelato Network
        CHAINLINK_CCIP,   // Chainlink CCIP
        LAYERZERO,        // LayerZero relayers
        HYPERLANE,        // Hyperlane validators
        USER_SELF_RELAY   // Users can relay their own txs
    }

    // Fallback cascade: try each relayer type in order
    RelayerType[] public relayerPriority;

    function submitWithFallback(bytes calldata message) external {
        for (uint i = 0; i < relayerPriority.length; i++) {
            if (tryRelay(relayerPriority[i], message)) {
                return;
            }
        }
        revert("All relayers failed");
    }
}
```

### 2. Self-Relay Option

**Allow users to relay their own transactions** when relayer network is unavailable.

#### Benefits

- No relayer dependency for critical operations
- Users maintain control
- Fallback for network issues

#### Implementation

```solidity
// contracts/relayer/SelfRelayAdapter.sol
contract SelfRelayAdapter {
    /// @notice Users can relay their own cross-chain messages
    /// @dev Higher gas cost but guaranteed execution
    function selfRelay(
        uint256 destinationChainId,
        bytes calldata proof,
        bytes calldata message
    ) external payable {
        require(msg.value >= estimateGas(destinationChainId), "Insufficient gas");

        // User pays for destination chain gas
        // No relayer fee required
        emit SelfRelayInitiated(msg.sender, destinationChainId, message);

        // Submit directly to bridge
        bridge.submitMessage{value: msg.value}(destinationChainId, message);
    }
}
```

### 3. Relayer Health Monitoring

**Real-time monitoring** with automatic failover.

#### Metrics to Track

- Response time (< 30s target)
- Success rate (> 99% target)
- Uptime (> 99.9% target)
- Gas efficiency
- Stake amount

#### Implementation

```solidity
// contracts/relayer/RelayerHealthMonitor.sol
contract RelayerHealthMonitor {
    struct HealthMetrics {
        uint256 successCount;
        uint256 failureCount;
        uint256 avgResponseTime;
        uint256 lastActiveTimestamp;
        bool isHealthy;
    }

    mapping(address => HealthMetrics) public relayerHealth;

    function updateHealth(address relayer, bool success, uint256 responseTime) external {
        HealthMetrics storage metrics = relayerHealth[relayer];

        if (success) {
            metrics.successCount++;
        } else {
            metrics.failureCount++;
        }

        metrics.avgResponseTime = (metrics.avgResponseTime + responseTime) / 2;
        metrics.lastActiveTimestamp = block.timestamp;

        // Mark unhealthy if success rate < 95% or offline > 1 hour
        uint256 successRate = (metrics.successCount * 100) /
            (metrics.successCount + metrics.failureCount);
        bool isActive = block.timestamp - metrics.lastActiveTimestamp < 1 hours;

        metrics.isHealthy = successRate >= 95 && isActive;

        if (!metrics.isHealthy) {
            emit RelayerUnhealthy(relayer, successRate, isActive);
        }
    }

    function getHealthyRelayers() external view returns (address[] memory) {
        // Return list of currently healthy relayers
    }
}
```

### 4. Economic Incentives

**Strengthen relayer incentives** to ensure network reliability.

#### Current Model

- Minimum stake: 10 ETH
- Fee: 0.1% of value
- Slashing: Up to 100%

#### Enhanced Model

```solidity
// contracts/relayer/EnhancedRelayerIncentives.sol
contract EnhancedRelayerIncentives {
    // Tiered staking with better rewards
    struct StakeTier {
        uint256 minStake;
        uint256 feeMultiplier;  // 100 = 1x, 150 = 1.5x
        uint256 priorityBoost;
    }

    StakeTier[] public tiers = [
        StakeTier(10 ether, 100, 0),    // Bronze: 1x fees
        StakeTier(50 ether, 125, 1),    // Silver: 1.25x fees, +1 priority
        StakeTier(100 ether, 150, 2),   // Gold: 1.5x fees, +2 priority
        StakeTier(500 ether, 200, 5)    // Platinum: 2x fees, +5 priority
    ];

    // Performance bonuses
    mapping(address => uint256) public performanceBonus;

    function calculateReward(address relayer, uint256 baseReward)
        public view returns (uint256)
    {
        StakeTier memory tier = getRelayerTier(relayer);
        uint256 reward = baseReward * tier.feeMultiplier / 100;
        reward += performanceBonus[relayer];
        return reward;
    }

    // Bonus for high uptime
    function awardPerformanceBonus(address relayer) external {
        HealthMetrics memory health = healthMonitor.relayerHealth(relayer);
        uint256 successRate = (health.successCount * 100) /
            (health.successCount + health.failureCount);

        if (successRate >= 99) {
            performanceBonus[relayer] += 0.01 ether;  // 0.01 ETH bonus
        }
    }
}
```

### 5. Decentralized Relayer Registry

**Permissionless relayer registration** to increase network size.

```solidity
// contracts/relayer/DecentralizedRelayerRegistry.sol
contract DecentralizedRelayerRegistry {
    struct Relayer {
        address operator;
        uint256 stake;
        string endpoint;  // API endpoint
        uint256[] supportedChains;
        bool isActive;
    }

    mapping(address => Relayer) public relayers;
    address[] public activeRelayers;

    function registerRelayer(
        string calldata endpoint,
        uint256[] calldata supportedChains
    ) external payable {
        require(msg.value >= 10 ether, "Insufficient stake");
        require(bytes(endpoint).length > 0, "Invalid endpoint");

        relayers[msg.sender] = Relayer({
            operator: msg.sender,
            stake: msg.value,
            endpoint: endpoint,
            supportedChains: supportedChains,
            isActive: true
        });

        activeRelayers.push(msg.sender);
        emit RelayerRegistered(msg.sender, msg.value, endpoint);
    }

    function selectRelayer(uint256 chainId) external view returns (address) {
        // Select based on: stake, health, random selection
        address[] memory eligible = getEligibleRelayers(chainId);
        require(eligible.length > 0, "No relayers available");

        // Weighted random selection based on stake
        return weightedRandomSelection(eligible);
    }
}
```

### 6. Emergency Fallback Mechanisms

**Graceful degradation** when relayers are unavailable.

#### Option A: Delayed Self-Execution

```solidity
// Users can execute after timeout period
function emergencyExecute(bytes32 messageHash) external {
    Message storage msg = messages[messageHash];
    require(block.timestamp > msg.timestamp + 24 hours, "Too early");
    require(!msg.executed, "Already executed");

    // Execute without relayer
    _executeMessage(msg);
}
```

#### Option B: Governance Override

```solidity
// Governance can manually relay critical messages
function governanceRelay(bytes calldata message) external onlyGovernance {
    require(isEmergency, "Not in emergency mode");
    _relayMessage(message);
}
```

#### Option C: Bridge Direct Execution

```solidity
// Use native bridge messaging as fallback
function fallbackToNativeBridge(bytes calldata message) external {
    require(relayerUnavailable(), "Relayers available");

    // Use Arbitrum/Optimism native bridge
    nativeBridge.sendMessage{value: msg.value}(message);
}
```

### 7. Service Level Agreements (SLAs)

**Define and enforce relayer SLAs**.

```solidity
contract RelayerSLA {
    struct SLA {
        uint256 maxResponseTime;     // 30 seconds
        uint256 minSuccessRate;       // 99%
        uint256 minUptime;            // 99.9%
        uint256 penaltyPerViolation;  // 0.1 ETH
    }

    SLA public sla = SLA({
        maxResponseTime: 30 seconds,
        minSuccessRate: 99,
        minUptime: 999,  // 99.9% = 999/1000
        penaltyPerViolation: 0.1 ether
    });

    function checkSLACompliance(address relayer) external {
        HealthMetrics memory health = healthMonitor.relayerHealth(relayer);

        // Check success rate
        uint256 successRate = (health.successCount * 100) /
            (health.successCount + health.failureCount);
        if (successRate < sla.minSuccessRate) {
            _penalizeRelayer(relayer, sla.penaltyPerViolation);
        }

        // Check response time
        if (health.avgResponseTime > sla.maxResponseTime) {
            _penalizeRelayer(relayer, sla.penaltyPerViolation);
        }
    }
}
```

## Implementation Roadmap

### Phase 1: Monitoring (Week 1-2)

- [ ] Deploy RelayerHealthMonitor
- [ ] Integrate health checks into existing relayers
- [ ] Set up alerting for unhealthy relayers

### Phase 2: Self-Relay (Week 3-4)

- [ ] Implement SelfRelayAdapter
- [ ] Add UI for self-relay option
- [ ] Document gas costs and trade-offs

### Phase 3: Multi-Relayer (Week 5-8)

- [ ] Deploy MultiRelayerRouter
- [ ] Integrate Gelato/Chainlink CCIP as alternatives
- [ ] Implement fallback cascade logic

### Phase 4: Enhanced Incentives (Week 9-12)

- [ ] Deploy tiered staking system
- [ ] Implement performance bonuses
- [ ] Launch relayer recruitment campaign

### Phase 5: Decentralization (Month 4-6)

- [ ] Open permissionless registration
- [ ] Implement SLA enforcement
- [ ] Achieve 50+ independent relayers

## Success Metrics

- **Relayer Count**: 50+ independent operators
- **Geographic Distribution**: 5+ regions
- **Uptime**: 99.9% network availability
- **Redundancy**: 3+ relayers per route
- **Self-Relay Usage**: < 5% (indicates healthy network)
- **Response Time**: < 30s average

## Monitoring Dashboard

Track key metrics:

- Active relayers count
- Average response time
- Success rate by relayer
- Geographic distribution
- Stake distribution
- Self-relay vs relayer usage

## Contract Reference

| Contract                       | File                               | Description                                                                      |
| ------------------------------ | ---------------------------------- | -------------------------------------------------------------------------------- |
| `RelayerStaking`               | `RelayerStaking.sol`               | Stake/unstake with 7-day unbonding, reward pool, slashing                        |
| `RelayerHealthMonitor`         | `RelayerHealthMonitor.sol`         | Per-relayer success/failure/response-time tracking                               |
| `DecentralizedRelayerRegistry` | `DecentralizedRelayerRegistry.sol` | Permissionless registration with stake-weighted selection                        |
| `RelayerSLAEnforcer`           | `RelayerSLAEnforcer.sol`           | On-chain SLA enforcement with escalating penalties (WARNING → FINE → SUSPENSION) |
| `MultiRelayerRouter`           | `MultiRelayerRouter.sol`           | Priority-ordered adapter routing with automatic fallback                         |
| `RelayerFeeMarket`             | `RelayerFeeMarket.sol`             | EIP-1559-style dynamic fee market for relay pricing                              |
| `InstantRelayerRewards`        | `InstantRelayerRewards.sol`        | Per-relay instant payouts with speed-tier multipliers                            |
| `RelayerCluster`               | `RelayerCluster.sol`               | Cluster-based grouping for chain-pair fault tolerance                            |
| `GelatoRelayAdapter`           | `GelatoRelayAdapter.sol`           | Gelato Relay Network adapter (gasless relaying)                                  |
| `HeterogeneousRelayerRegistry` | `HeterogeneousRelayerRegistry.sol` | Multi-role registry: Proof Generators, Light Relayers, Watchtowers               |
| `SelfRelayAdapter`             | `SelfRelayAdapter.sol`             | User self-relay fallback (no relayer dependency)                                 |
| `IRelayerAdapter`              | `IRelayerAdapter.sol`              | Standard interface all relay adapters implement                                  |

All contracts live under `contracts/relayer/`.

---

## Fee Market

**Contract**: `RelayerFeeMarket.sol` — Dynamic fee market for cross-chain relay pricing.

Implements an **EIP-1559-style base fee** mechanism:

1. **Base Fee** adjusts per epoch (1 hour) based on utilization rate against `DEFAULT_TARGET_UTILIZATION` (50%). If relay demand exceeds the target, the base fee increases by `FEE_ADJUSTMENT_BPS` (12.5%); if below, it decreases.
2. **Priority Fee** is a user-set tip above the base fee to incentivize faster relay pickup.
3. **Relay Auction** — for high-value transfers, a sealed-bid first-price auction selects the relayer.

**Lifecycle**: User calls `submitRelayRequest()` with `maxFee` and `priorityFee` → relayer claims → relayer completes relay → collects effective fee (base + priority). Unclaimed requests expire after `DEFAULT_DEADLINE` (4 hours). Claimed relays must complete within `CLAIM_TIMEOUT` (30 minutes).

**Key constants**: `MAX_EPOCH_RELAYS` = 1000, `DEFAULT_MIN_BASE_FEE` = 0.0001 ETH, `DEFAULT_MAX_BASE_FEE` = 1 ETH, protocol fee = 5%.

**Key functions**: `submitRelayRequest()`, `claimRelayRequest()`, `completeRelay()`, `getEffectiveFee()`.

---

## Multi-Relayer Routing

**Contract**: `MultiRelayerRouter.sol` — Priority-ordered multi-adapter router with health-aware selection.

Maintains up to `MAX_ADAPTERS` (10) relay adapters (Gelato, CCIP, native, self-relay, etc.) ordered by priority. On `relay()`:

1. Fetches the sorted adapter list (active adapters first, degraded adapters last).
2. Tries each adapter in order — calls `IRelayerAdapter.getFee()` then `relayMessage()`.
3. If an adapter reverts, increments its `consecutiveFails` counter and moves to the next.
4. After `DEGRADE_THRESHOLD` (3) consecutive failures, the adapter is auto-degraded.
5. Degraded adapters auto-recover after `RECOVERY_COOLDOWN` (1 hour).

**Emergency relay** (`EMERGENCY_ROLE`) bypasses all adapters for direct message execution, providing censorship resistance.

**Key functions**: `relay()`, `registerAdapter()`, `removeAdapter()`, `emergencyRelay()`, `setAdapterPriority()`.

**Gas limits**: `MIN_GAS_LIMIT` = 21,000, `MAX_GAS_LIMIT` = 10,000,000. Excess ETH is refunded to the caller.

---

## Relayer Clusters

**Contract**: `RelayerCluster.sol` — Cluster-based relayer grouping for chain-pair fault tolerance.

Inspired by Arcium's cluster model. Groups relayers into fault-tolerant units for specific **source → destination chain pairs**.

**Lifecycle**:

- `createCluster()` — admin creates a cluster for a chain pair with `minStakePerMember` and `maxMembers`.
- Cluster starts **INACTIVE** until `≥ MIN_CLUSTER_SIZE` (3) members join with required stake.
- Auto-activates when member threshold is reached; auto-deactivates when `healthScore` drops below 50.
- `recordRelay()` (ROUTER_ROLE only) updates success/failure stats and recalculates health.

**Constraints**: `MAX_CLUSTER_SIZE` = 20, `MAX_CLUSTERS_PER_RELAYER` = 10. Stake is locked per cluster.

**Key functions**: `createCluster()`, `joinCluster()`, `leaveCluster()`, `recordRelay()`, `getBestCluster()`.

---

## Instant Rewards

**Contract**: `InstantRelayerRewards.sol` — Per-relay instant fee distribution with speed-based tiers.

Layered on top of `RelayerStaking` (which handles long-term pool rewards). This contract handles **instant per-relay payouts** tied to fulfillment speed.

**Speed Tiers**:

| Tier       | Threshold    | Multiplier     |
| ---------- | ------------ | -------------- |
| ULTRA_FAST | < 30 seconds | 1.5x           |
| FAST       | < 60 seconds | 1.25x          |
| NORMAL     | < 5 minutes  | 1.0x           |
| SLOW       | ≥ 5 minutes  | 0.9x (penalty) |

**Flow**: Fee deposited via `depositRelayFee()` → relayer claims → `completeRelayWithReward()` calculates tiered payout → protocol takes 5% cut → relayer receives instant reward → surplus refunded to requester.

**Key functions**: `depositRelayFee()`, `claimRelay()`, `completeRelayWithReward()`, `getRelayerStats()`.

Per-relayer stats track `totalRewards`, `totalRelays`, and counts per tier.

---

## Gelato Integration

**Contract**: `GelatoRelayAdapter.sol` — Adapter wrapping the Gelato Relay Network for gasless relaying.

Implements `IRelayerAdapter` so it plugs directly into `MultiRelayerRouter`. Uses Gelato's `callWithSyncFee` where the caller pays in native ETH and Gelato deducts the fee from the forwarded value.

**Key details**:

- `GELATO_RELAY` is immutable, set at deployment.
- `relayMessage(target, payload, gasLimit)` forwards to `IGelatoRelay.callWithSyncFee()`.
- `getFee(gasLimit)` returns a fixed estimate (0.001 ETH). Production should query Gelato's fee oracle for dynamic pricing.
- For meta-transaction support, production deployments should use `GelatoRelayContext` or `callWithSyncFeeERC2771`.

**Key functions**: `relayMessage()`, `getFee()`.

---

## Heterogeneous Registry

**Contract**: `HeterogeneousRelayerRegistry.sol` — Role-separated relayer system with specialized types.

Replaces the uniform relayer model with **specialized roles** matching actual workload demands (inspired by LayerZero's Block Producer/Validator split):

| Role                | Purpose                                          | Min Stake |
| ------------------- | ------------------------------------------------ | --------- |
| **Proof Generator** | Generate ZK proofs, aggregate batches (GPU/FPGA) | 1 ETH     |
| **Light Relayer**   | Relay proofs to destination chains, submit txns  | 0.1 ETH   |
| **Watchtower**      | Verify proofs, raise disputes, fraud detection   | 0.5 ETH   |

**Key properties**: Lower barriers for Light Relayers increase decentralization. Reputation score (0–10,000, default 5,000) drives task assignment priority. Slashing is proportional to offense severity. Exit requires `EXIT_COOLDOWN` (7 days).

**Task routing**: `TASK_ASSIGNER_ROLE` assigns tasks to relayers by role + reputation. `PERFORMANCE_REPORTER_ROLE` updates reputation scores based on outcomes.

**Key functions**: `registerProofGenerator()`, `registerLightRelayer()`, `registerWatchtower()`, `assignTask()`, `completeTask()`, `slashRelayer()`, `requestExit()`.

---

## Interface

**Contract**: `IRelayerAdapter.sol` — Standard interface that all relay adapters must implement.

```solidity
interface IRelayerAdapter {
    function relayMessage(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    ) external payable returns (bytes32 taskId);

    function getFee(uint256 gasLimit) external view returns (uint256 fee);
}
```

- `relayMessage()` — Relays calldata to a target contract with a specified gas limit. Returns a task ID for tracking. Accepts ETH via `msg.value` to cover relay fees.
- `getFee()` — Returns the estimated relay fee in wei for a given gas limit.

Implemented by: `GelatoRelayAdapter`, `SelfRelayAdapter`, and any future adapter registered in `MultiRelayerRouter`.

---

## Resources

- [Gelato Network Integration](https://docs.gelato.network/)
- [Chainlink CCIP](https://docs.chain.link/ccip)
- [LayerZero Relayer Docs](https://layerzero.gitbook.io/)
- [Hyperlane Validators](https://docs.hyperlane.xyz/)
