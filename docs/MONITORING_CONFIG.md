# ZASEON - Monitoring Configuration

> Monitoring alerts and thresholds configuration for ZASEON production deployment.

---

## Table of Contents

- [Overview](#overview)
- [Alert Severity Levels](#alert-severity-levels)
- [Core Contract Monitoring](#core-contract-monitoring)
- [Bridge Adapter Monitoring](#bridge-adapter-monitoring)
- [Cross-Chain Messaging Monitoring](#cross-chain-messaging-monitoring)
- [Security & Emergency Monitoring](#security--emergency-monitoring)
- [On-Chain Metrics](#on-chain-metrics)
- [Infrastructure Monitoring](#infrastructure-monitoring)
- [Alert Integrations](#alert-integrations)
- [Grafana Dashboard Panels](#grafana-dashboard-panels)
- [Runbook References](#runbook-references)

---

## Overview

This document defines monitoring alerts and thresholds for ZASEON production deployment across Ethereum L1 and 7 supported L2 networks (Arbitrum, Optimism, Base, zkSync Era, Scroll, Linea, Polygon zkEVM).

## Alert Severity Levels

| Level       | Response Time     | Notification    | Example                           |
| ----------- | ----------------- | --------------- | --------------------------------- |
| 🔴 Critical | < 5 min           | PagerDuty + SMS | Contract paused, large theft      |
| 🟠 High     | < 30 min          | Slack + Email   | Failed proofs, bridge delays      |
| 🟡 Medium   | < 2 hours         | Slack           | Elevated gas costs, slow indexing |
| 🟢 Low      | Next business day | Email           | Minor anomalies                   |

---

## Core Contract Monitoring

### ZKBoundStateLocks

```yaml
events:
  - name: StateLockCreated
    alert: low
    description: Track new lock creation rate
    threshold:
      warning: "> 100/hour"
      critical: "> 1000/hour"

  - name: StateUnlocked
    alert: medium
    description: Monitor unlock patterns
    threshold:
      warning: "unlock_rate > create_rate * 1.5"

  - name: EmergencyPaused
    alert: critical
    description: Contract paused
    response: "Immediate investigation required"
```

### CrossChainProofHubV3

```yaml
events:
  - name: ProofSubmitted
    alert: low
    description: Track proof submission volume

  - name: ProofVerificationFailed
    alert: high
    description: Invalid proof detected
    threshold:
      warning: "> 5/hour"
      critical: "> 10/hour"

  - name: BatchAggregated
    alert: low
    description: Batch proof aggregation completed

  - name: RelayerSlashed
    alert: high
    description: Malicious relayer detected and slashed

  - name: RateLimitExceeded
    alert: high
    description: Value-based rate limit triggered (_checkRateLimit)
    threshold:
      warning: "> 3/hour"
      critical: "> 10/hour"
    response: "Review submission patterns for potential abuse"
```

### NullifierRegistryV3

```yaml
events:
  - name: NullifierRegistered
    alert: low
    description: New nullifier consumed

  - name: DuplicateNullifierAttempt
    alert: high
    description: Double-spend attempt detected
    threshold:
      critical: "> 1"
```

### BatchAccumulator

```yaml
events:
  - name: BatchCreated
    alert: low
    description: New batch created

  - name: BatchFinalized
    alert: low
    description: Batch successfully finalized

  - name: BatchFailed
    alert: high
    description: Batch failed — nullifiers recovered
    response: "Verify nullifier rollback completed correctly"
    threshold:
      warning: "> 1/day"
      critical: "> 5/day"

  - name: NullifierRecovered
    alert: medium
    description: Nullifier recovered from failed batch
```

### DecentralizedRelayerRegistry

```yaml
events:
  - name: RelayerRegistered
    alert: low
    description: New relayer registered with stake

  - name: RelayerDeregistered
    alert: medium
    description: Relayer exited the network

  - name: StakeRefunded
    alert: medium
    description: Overpayment above MIN_STAKE refunded
    threshold:
      warning: "refund > 1 ETH"

  - name: RelayerSlashed
    alert: high
    description: Relayer slashed for misbehavior
    response: "Review slashing evidence and relayer history"
```

### ZaseonGovernance

```yaml
events:
  - name: ProposalCreated
    alert: low
    description: New governance proposal created

  - name: ProposalExecuted
    alert: high
    description: Governance proposal executed
    response: "Verify execution matches expected behavior"

  - name: ProposalCancelled
    alert: medium
    description: Governance proposal cancelled
```

---

## Bridge Adapter Monitoring

### All Bridge Adapters (Common)

```yaml
events:
  - name: DepositInitiated
    alert: low
    description: Cross-chain deposit started
    threshold:
      warning: "value > 100 ETH"
      critical: "value > 1000 ETH"

  - name: WithdrawalClaimed
    alert: low
    description: Withdrawal successfully claimed

  - name: WithdrawalFailed
    alert: high
    description: Withdrawal claim reverted
    threshold:
      critical: "> 1"
    response: "Check proof validity and bridge state"

  - name: EmergencyWithdrawETH
    alert: critical
    description: Emergency ETH withdrawal by admin
    response: "Verify authorized admin action"

  - name: EmergencyWithdrawERC20
    alert: critical
    description: Emergency ERC20 withdrawal by admin
```

### ArbitrumBridgeAdapter

```yaml
events:
  - name: RetryableTicketCreated
    alert: low
    description: L1→L2 retryable ticket

  - name: OutboxProofVerified
    alert: low
    description: L2→L1 Outbox.isSpent verification passed

  - name: RetryableTicketRedeemed
    alert: low
    description: Retryable ticket auto-redeemed on L2
```

### zkSyncBridgeAdapter

```yaml
events:
  - name: ZKProofVerified
    alert: low
    description: zkSync ZK proof verified for withdrawal

  - name: BridgeConfigured
    alert: high
    description: Bridge configuration changed (Diamond Proxy addresses)
    response: "Verify configuration matches zkSync Diamond Proxy"
```

### ScrollBridgeAdapter

```yaml
events:
  - name: ScrollMessageSent
    alert: low
    description: Message sent via L1ScrollMessenger

  - name: ScrollConfigured
    alert: high
    description: Scroll bridge configuration updated
    response: "Verify all 4 addresses (messenger, gateway, queue, rollup)"
```

### LineaBridgeAdapter

```yaml
events:
  - name: LineaMessageSent
    alert: low
    description: Message sent via LineaMessageService

  - name: LineaConfigured
    alert: high
    description: Linea bridge configuration updated
    response: "Verify messageService and tokenBridge addresses"
```

---

## Cross-Chain Messaging Monitoring

### LayerZeroAdapter

```yaml
events:
  - name: MessageSent
    alert: low
    description: LayerZero message dispatched

  - name: MessageReceived
    alert: low
    description: LayerZero message received via lzReceive

  - name: PeerSet
    alert: high
    description: LayerZero peer address changed
    response: "Verify peer address is authorized"

  - name: EndpointConfigured
    alert: high
    description: LZ Endpoint configuration changed
    response: "Verify endpoint address and confirmation settings"
```

### HyperlaneAdapter

```yaml
events:
  - name: MessageDispatched
    alert: low
    description: Hyperlane message dispatched via Mailbox

  - name: MessageHandled
    alert: low
    description: Hyperlane message received and handled

  - name: DomainConfigured
    alert: high
    description: Hyperlane domain router/ISM changed
    response: "Verify router and ISM addresses are correct"
```

### CrossChainNullifierSync

```yaml
events:
  - name: NullifierSynced
    alert: low
    description: Nullifier synchronized cross-chain

  - name: SyncSequenceGap
    alert: high
    description: Gap detected in syncSequence mapping
    threshold:
      critical: "> 1"
    response: "Investigate potential replay or skipped sync"

  - name: DuplicateSyncAttempt
    alert: high
    description: Replay attempt detected via syncSequence
```

---

## Security & Emergency Monitoring

### ProtocolEmergencyCoordinator

```yaml
events:
  - name: EmergencyDeclared
    alert: critical
    description: Protocol-wide emergency declared
    response: "Execute incident response runbook immediately"

  - name: RoleSeparationConfirmed
    alert: high
    description: "confirmRoleSeparation(guardian, responder, recovery) called"
    response: "Verify 3 addresses are distinct multisigs"

  - name: EmergencyResolved
    alert: high
    description: Emergency resolved, review impact
```

### CrossChainEmergencyRelay

```yaml
events:
  - name: EmergencyBroadcast
    alert: critical
    description: Emergency propagated cross-chain

  - name: InvalidSourceChain
    alert: critical
    description: Emergency relay from unauthorized chain (sourceChainId not in active chains)
    response: "Potential attack — investigate immediately"

  - name: ChainActivated
    alert: high
    description: New chain added to active chain set

  - name: ChainDeactivated
    alert: high
    description: Chain removed from active set
```

### ExperimentalFeatureRegistry

```yaml
events:
  - name: FeatureRegistered
    alert: medium
    description: New experimental feature registered

  - name: FeatureGraduated
    alert: medium
    description: Feature graduated to production

  - name: FeatureRevoked
    alert: high
    description: Feature revoked — check dependent contracts
```

---

## On-Chain Metrics

### Gas Usage

```yaml
metrics:
  - name: avg_gas_per_proof
    description: Average gas cost for proof verification
    threshold:
      warning: "> 500,000 gas"
      critical: "> 1,000,000 gas"

  - name: total_daily_gas
    description: Total protocol gas usage per day
    threshold:
      warning: "> 100 ETH equivalent"
```

### Protocol Health

```yaml
metrics:
  - name: active_locks_count
    description: Number of active ZK state locks

  - name: pending_proofs_count
    description: Proofs waiting for verification
    threshold:
      warning: "> 100"
      critical: "> 500"

  - name: bridge_queue_depth
    description: Messages waiting for relay
    threshold:
      warning: "> 50"
      critical: "> 200"
```

### Security Metrics

```yaml
metrics:
  - name: failed_verification_rate
    description: Percentage of failed proof verifications
    threshold:
      warning: "> 1%"
      critical: "> 5%"

  - name: unusual_access_patterns
    description: Calls from new addresses to admin functions
    alert: high

  - name: large_value_transfers
    description: Single transfers exceeding threshold
    threshold:
      warning: "> 100 ETH"
      critical: "> 1000 ETH"
```

---

## Infrastructure Monitoring

### RPC Endpoints

```yaml
endpoints:
  - url: "${MAINNET_RPC_URL}"
    health_check: "eth_blockNumber"
    latency_threshold: 500ms
    alert_on_failure: critical

  - url: "${BACKUP_RPC_URL}"
    health_check: "eth_blockNumber"
    latency_threshold: 1000ms
    alert_on_failure: high
```

### TheGraph Subgraph

```yaml
subgraph:
  name: zaseon-mainnet
  health_endpoint: "https://api.thegraph.com/subgraphs/name/zaseon/zaseon-mainnet"

  metrics:
    - name: indexing_lag
      description: Blocks behind chain head
      threshold:
        warning: "> 10 blocks"
        critical: "> 100 blocks"

    - name: query_latency
      description: Average query response time
      threshold:
        warning: "> 1s"
        critical: "> 5s"
```

---

## Alert Integrations

### PagerDuty (Critical)

```yaml
pagerduty:
  service_key: "${PAGERDUTY_SERVICE_KEY}"
  escalation_policy: "zaseon-security"

  triggers:
    - EmergencyPaused
    - LargeTheftDetected
    - CircuitBreakerTripped
    - MultipleFailedProofs
```

### Slack (High/Medium)

```yaml
slack:
  webhook: "${SLACK_WEBHOOK_URL}"
  channel: "#zaseon-alerts"

  triggers:
    - ProofVerificationFailed
    - SwapRefunded
    - RelayerSlashed
    - IndexingLag
```

### Telegram Bot (Optional)

```yaml
telegram:
  bot_token: "${TELEGRAM_BOT_TOKEN}"
  chat_id: "${TELEGRAM_CHAT_ID}"

  triggers:
    - DailyDigest
    - WeeklyReport
```

---

## Grafana Dashboard Panels

### Overview Dashboard

1. **Protocol Health Score** - Composite metric (0-100)
2. **Active Locks** - Time series chart
3. **Proof Throughput** - Proofs/hour bar chart
4. **Failed Verifications** - Counter with trend
5. **Bridge Queue Depth** - Gauge
6. **Gas Costs** - Daily ETH spent

### Security Dashboard

1. **Failed Proof Attempts** - Time series with anomaly detection
2. **Unusual Address Activity** - New addresses interacting
3. **Large Value Transfers** - Log of transfers > threshold
4. **Admin Action Log** - All privileged operations
5. **Pause Status** - Contract pause state

### Financial Dashboard

1. **Total Value Locked** - TVL across all contracts
2. **Daily Volume** - Swap/transfer volume
3. **Fee Revenue** - Protocol fees collected
4. **Gas Efficiency** - Gas per operation trend

---

## Runbook References

| Alert                   | Runbook                                                                                                    |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- |
| EmergencyPaused         | [INCIDENT_RESPONSE_RUNBOOK.md#emergency-pause](./INCIDENT_RESPONSE_RUNBOOK.md#emergency-pause)             |
| EmergencyDeclared       | [INCIDENT_RESPONSE_RUNBOOK.md#emergency-pause](./INCIDENT_RESPONSE_RUNBOOK.md#emergency-pause)             |
| ProofVerificationFailed | [INCIDENT_RESPONSE_RUNBOOK.md#failed-proofs](./INCIDENT_RESPONSE_RUNBOOK.md#failed-proofs)                 |
| LargeValueTransfer      | [INCIDENT_RESPONSE_RUNBOOK.md#large-transfers](./INCIDENT_RESPONSE_RUNBOOK.md#large-transfers)             |
| IndexingLag             | [INCIDENT_RESPONSE_RUNBOOK.md#subgraph-issues](./INCIDENT_RESPONSE_RUNBOOK.md#subgraph-issues)             |
| InvalidSourceChain      | [INCIDENT_RESPONSE_RUNBOOK.md#cross-chain-emergency](./INCIDENT_RESPONSE_RUNBOOK.md#cross-chain-emergency) |
| BatchFailed             | [INCIDENT_RESPONSE_RUNBOOK.md#batch-failure](./INCIDENT_RESPONSE_RUNBOOK.md#batch-failure)                 |
| WithdrawalFailed        | [INCIDENT_RESPONSE_RUNBOOK.md#bridge-failure](./INCIDENT_RESPONSE_RUNBOOK.md#bridge-failure)               |

---

## Metadata Protection Monitoring

### GasNormalizer

```yaml
events:
  - name: GasNormalized
    alert: low
    description: Gas usage normalized to tier

  - name: TierOverflow
    alert: high
    description: Operation exceeded maximum gas tier
    threshold:
      warning: "> 5/day"
      critical: "> 20/day"
```

### MultiRelayerQuorum

```yaml
events:
  - name: QuorumReached
    alert: low
    description: Multi-relayer quorum achieved

  - name: QuorumFailed
    alert: high
    description: Quorum not reached within timeout
    response: "Check relayer availability and network connectivity"
    threshold:
      warning: "> 3/hour"
      critical: "> 10/hour"

  - name: AttestationMismatch
    alert: critical
    description: Relayers disagreed on message content
    response: "Investigate potential relayer compromise or message tampering"
    threshold:
      critical: "> 0"
```

### ERC20DenominationEnforcer

```yaml
events:
  - name: DenominationRejected
    alert: medium
    description: Deposit rejected due to non-standard denomination
    threshold:
      warning: "> 50/day"
```

---

_Monitoring configuration version: 2.1.0_
_Last updated: March 2026_
