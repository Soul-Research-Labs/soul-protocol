# ZASEON - Monitoring Configuration

## Overview

This document defines monitoring alerts and thresholds for ZASEON production deployment.

## Alert Severity Levels

| Level | Response Time | Notification | Example |
|-------|--------------|--------------|---------|
| 🔴 Critical | < 5 min | PagerDuty + SMS | Contract paused, large theft |
| 🟠 High | < 30 min | Slack + Email | Failed proofs, bridge delays |
| 🟡 Medium | < 2 hours | Slack | Elevated gas costs, slow indexing |
| 🟢 Low | Next business day | Email | Minor anomalies |

---

## Contract Event Monitoring

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

### CrossChainProofHub

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
```

### NullifierRegistry

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

### ZaseonAtomicSwap

```yaml
events:
  - name: SwapInitiated
    alert: low
    description: New atomic swap started
    threshold:
      warning: "value > 100 ETH"
      critical: "value > 1000 ETH"
      
  - name: SwapCompleted
    alert: low
    description: Swap successfully completed
    
  - name: SwapRefunded
    alert: medium
    description: Swap expired and refunded
    threshold:
```

### ZaseonMultiSigGovernance

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

### BridgeWatchtower

```yaml
events:
  - name: WatchtowerSlashed
    alert: high
    description: Watchtower slashed for misbehavior
    
  - name: ReportSubmitted
    alert: medium
    description: Anomaly report submitted
    threshold:
      warning: "> 10/hour"
      critical: "> 50/hour"
      
  - name: ReportFinalized
    alert: high
    description: Report consensus reached
```

### ConfidentialDataAvailability

```yaml
events:
  - name: BlobPublished
    alert: low
    description: New confidential blob published
    
  - name: ChallengeCreated
    alert: high
    description: Data availability challenged
    
  - name: MinChallengeStakeUpdated
    alert: medium
    description: Admin configuration changed
    
  - name: VerifiersUpdated
    alert: high
    description: Verifier addresses changed
    response: "Verify new verifiers are legitimate"
```
      warning: "> 10% of swaps refunded"
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

| Alert | Runbook |
|-------|---------|
| EmergencyPaused | [INCIDENT_RESPONSE_RUNBOOK.md#emergency-pause](./INCIDENT_RESPONSE_RUNBOOK.md#emergency-pause) |
| ProofVerificationFailed | [INCIDENT_RESPONSE_RUNBOOK.md#failed-proofs](./INCIDENT_RESPONSE_RUNBOOK.md#failed-proofs) |
| LargeValueTransfer | [INCIDENT_RESPONSE_RUNBOOK.md#large-transfers](./INCIDENT_RESPONSE_RUNBOOK.md#large-transfers) |
| IndexingLag | [INCIDENT_RESPONSE_RUNBOOK.md#subgraph-issues](./INCIDENT_RESPONSE_RUNBOOK.md#subgraph-issues) |

---

*Monitoring configuration version: 1.0.0*  
*Last updated: January 2026*
