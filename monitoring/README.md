# ZASEON - Monitoring Infrastructure

This directory contains configuration for monitoring ZASEON in production.

## Monitoring Services

### Tenderly

[tenderly.config.json](tenderly.config.json) provides:
- Real-time transaction monitoring
- Event-based alerting (critical/high/medium/low)
- Transaction simulation for health checks
- Web3 Actions for automated responses

**Setup:**
1. Create Tenderly account at https://tenderly.co
2. Create new project for ZASEON
3. Import config: `tenderly config import tenderly.config.json`
4. Add contract addresses after deployment
5. Configure notification channels (Slack, PagerDuty, Email)

### OpenZeppelin Defender

[defender.config.json](defender.config.json) provides:
- Sentinel monitors for on-chain events
- Autotasks for automated responses
- Relayer management for meta-transactions
- Access control management

**Setup:**
1. Create Defender account at https://defender.openzeppelin.com
2. Import config via Defender CLI:
   ```bash
   npx @openzeppelin/defender-client import defender.config.json
   ```
3. Add contract addresses after deployment
4. Configure secrets in Defender dashboard
5. Enable actions as needed

## Alert Severity Levels

| Level | Response Time | Notification | Examples |
|-------|---------------|--------------|----------|
| 🔴 Critical | < 5 min | PagerDuty + SMS | Contract paused, emergency withdrawal, double-spend |
| 🟠 High | < 30 min | Slack + Email | Failed proofs, relayer slashed, admin actions |
| 🟡 Medium | < 2 hours | Slack | High gas usage, queue depth, refunds |
| 🟢 Low | Aggregated | Dashboard | Normal operations tracking |

## Critical Alerts

These events trigger immediate response:

1. **Contract Paused** - Any Zaseon contract has been paused
2. **Emergency Withdrawal** - Emergency funds extraction executed
3. **Circuit Breaker Triggered** - Security circuit breaker activated
4. **Double-Spend Attempt** - Nullifier reuse detected
5. **Large Value Transfer** - Transfer > 1000 ETH threshold

## Configuration

### Environment Variables

Set these in your monitoring service:

```bash
# PagerDuty
PAGERDUTY_SERVICE_KEY=xxx

# Slack Webhooks
SLACK_CRITICAL_WEBHOOK=https://hooks.slack.com/...
SLACK_SECURITY_WEBHOOK=https://hooks.slack.com/...
SLACK_ALERTS_WEBHOOK=https://hooks.slack.com/...
SLACK_ADMIN_WEBHOOK=https://hooks.slack.com/...
SLACK_OPS_WEBHOOK=https://hooks.slack.com/...

# Contract Addresses (after deployment)
PROOF_HUB_ADDRESS=0x...
NULLIFIER_REGISTRY_ADDRESS=0x...
ZK_BOUND_STATE_LOCKS_ADDRESS=0x...
ATOMIC_SWAP_ADDRESS=0x...
DIRECT_L2_MESSENGER_ADDRESS=0x...
```

### Adding Contract Addresses

After deployment, update the config files with actual addresses:

```javascript
// Example: Add to tenderly.config.json
"networks": {
  "mainnet": {
    "chainId": 1,
    "contracts": [
      {
        "address": "0x1234...",
        "name": "CrossChainProofHubV3"
      }
    ]
  }
}
```

## Response Playbooks

### Critical: Emergency Pause

1. ⚡ Acknowledge alert within 5 minutes
2. 🔍 Review transaction on Tenderly/Etherscan
3. 🛑 Verify pause was intentional
4. 📞 Contact on-call security engineer
5. 📝 Document incident

### Critical: Double-Spend Attempt

1. ⚡ Acknowledge alert immediately
2. 🔍 Identify source address
3. 🛑 Consider protocol pause if ongoing attack
4. 📊 Analyze attack vector
5. 🔒 Implement mitigations
6. 📝 Post-mortem report

### High: Proof Verification Failed

1. 📊 Check failure rate trend
2. 🔍 Review failed proof details
3. 🐛 Check for circuit/verifier bugs
4. 👤 Contact prover operators if relayer issue
5. 📝 Document findings

## Testing Alerts

Run test alerts to verify configuration:

```bash
# Tenderly - Simulate transaction
tenderly simulate --config tenderly.config.json

# Defender - Test notification
npx @openzeppelin/defender-client test-notification zaseon-slack-alerts
```

## Additional Resources

- [MONITORING_CONFIG.md](../docs/MONITORING_CONFIG.md) - Full monitoring specification
- [THREAT_MODEL.md](../docs/THREAT_MODEL.md) - Security threat model
- [DEPLOYMENT.md](../docs/DEPLOYMENT.md) - Deployment procedures
