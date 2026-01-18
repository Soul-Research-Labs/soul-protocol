# PIL Operations Runbook

This runbook provides procedures for operating and maintaining the Privacy Interoperability Layer (PIL) in production.

---

## Table of Contents

1. [Monitoring & Alerts](#monitoring--alerts)
2. [Incident Response](#incident-response)
3. [Routine Maintenance](#routine-maintenance)
4. [Emergency Procedures](#emergency-procedures)
5. [Recovery Procedures](#recovery-procedures)
6. [Upgrade Procedures](#upgrade-procedures)

---

## Monitoring & Alerts

### Dashboard Access

- **Grafana**: https://monitoring.pil.network/grafana
- **Tenderly**: https://dashboard.tenderly.co/pil-protocol
- **Forta Explorer**: https://explorer.forta.network/bot/pil-protocol-monitor

### Key Metrics to Monitor

| Metric | Warning Threshold | Critical Threshold |
|--------|------------------|-------------------|
| Container creation rate | > 1000/min | > 5000/min |
| Failed transactions | > 1% | > 5% |
| Average gas usage | > 500k | > 1M |
| Proof verification time | > 2s | > 5s |
| Contract balance (ETH) | < 1 ETH | < 0.1 ETH |
| Relayer response time | > 5s | > 30s |

### Alert Channels

- **PagerDuty**: Critical alerts, on-call rotation
- **Slack #pil-alerts**: All alerts
- **Email**: Daily summaries

---

## Incident Response

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| P0 | Critical - Service down | 15 min | Contract paused, funds at risk |
| P1 | High - Major degradation | 30 min | High failure rate, stuck transactions |
| P2 | Medium - Minor impact | 2 hours | Elevated latency, single relayer down |
| P3 | Low - Informational | 24 hours | Unusual patterns, capacity warnings |

### Incident Response Checklist

#### P0/P1 Incidents

```markdown
[ ] Acknowledge alert in PagerDuty
[ ] Join incident Slack channel #pil-incident-<date>
[ ] Assess impact and scope
[ ] Communicate to stakeholders
[ ] Execute appropriate runbook procedure
[ ] Document timeline in incident report
[ ] Post-incident review within 48 hours
```

### Communication Templates

#### Status Page Update

```
[INVESTIGATING] We are investigating reports of [issue description].
Impact: [affected services/chains]
Started: [timestamp UTC]
Updates every 30 minutes.
```

#### Resolution Notice

```
[RESOLVED] The issue affecting [services] has been resolved.
Duration: [X hours Y minutes]
Root cause: [brief description]
Full postmortem to follow.
```

---

## Routine Maintenance

### Daily Tasks

```bash
#!/bin/bash
# daily-checks.sh

# 1. Check contract states
echo "Checking contract health..."
npx hardhat run scripts/health-check.js --network mainnet

# 2. Verify relayer status
echo "Checking relayer status..."
curl -s https://api.pil.network/relayers/health | jq .

# 3. Check gas reserves
echo "Checking gas reserves..."
npx hardhat run scripts/check-balances.js --network mainnet

# 4. Review overnight alerts
echo "Review Forta alerts from last 24h..."
```

### Weekly Tasks

1. **Review Metrics**
   - Transaction volume trends
   - Gas cost analysis
   - Error rate patterns

2. **Audit Logs Review**
   - Check admin operations
   - Review role changes
   - Verify upgrade proposals

3. **Dependency Updates**
   - Check for security patches
   - Update non-breaking dependencies
   - Run test suite

### Monthly Tasks

1. **Security Review**
   - Run Slither analysis
   - Check for new CVEs
   - Review access controls

2. **Capacity Planning**
   - Analyze growth trends
   - Plan infrastructure scaling
   - Review cost optimization

3. **Documentation Update**
   - Update runbooks if needed
   - Review and update diagrams
   - Archive old procedures

---

## Emergency Procedures

### EP-001: Emergency Pause

**When to use**: Active exploit, critical vulnerability discovered

```bash
# 1. Connect to multi-sig
# 2. Execute pause on affected contract(s)

# Using Hardhat
npx hardhat run scripts/emergency-pause.js --network mainnet

# Manual via multi-sig
# Go to https://app.safe.global
# Navigate to PIL Safe
# Execute pauseAll() on Orchestrator
```

**Script: emergency-pause.js**
```javascript
const { ethers } = require("hardhat");

async function main() {
  const orchestrator = await ethers.getContractAt(
    "PILv2Orchestrator",
    process.env.ORCHESTRATOR_ADDRESS
  );
  
  console.log("Executing emergency pause...");
  const tx = await orchestrator.pause();
  await tx.wait();
  console.log(`Paused in tx: ${tx.hash}`);
}
```

### EP-002: Relayer Emergency Rotation

**When to use**: Relayer compromised or unresponsive

```bash
# 1. Remove compromised relayer
npx hardhat run scripts/rotate-relayer.js --network mainnet

# 2. Verify pending transactions
npx hardhat run scripts/check-pending.js --network mainnet

# 3. Add new relayer
npx hardhat run scripts/add-relayer.js --network mainnet --relayer <address>
```

### EP-003: Circuit Key Rotation

**When to use**: Trusted setup compromised

```bash
# 1. Generate new trusted setup
./scripts/trusted-setup-ceremony.sh new

# 2. Update verifier contract via timelock
# (48 hour delay - coordinate with team)

# 3. Announce deprecation of old proofs

# 4. Monitor for old proof attempts
```

### EP-004: Fund Recovery

**When to use**: Funds stuck in contract

```bash
# 1. Assess situation
npx hardhat run scripts/assess-funds.js --network mainnet

# 2. Prepare recovery transaction via multi-sig
# 3. Execute with appropriate timelock delay
# 4. Verify fund transfer
# 5. Document incident
```

---

## Recovery Procedures

### RP-001: Recover from Pause

```bash
# 1. Verify threat is mitigated
npx hardhat run scripts/security-check.js --network mainnet

# 2. Review pending operations
npx hardhat run scripts/pending-ops.js --network mainnet

# 3. Unpause via multi-sig (requires M-of-N signatures)
# Schedule through timelock (6 hour emergency delay)

# 4. Monitor closely for 24 hours
# 5. Resume normal operations
```

### RP-002: State Recovery

```bash
# 1. Identify last known good state
LAST_GOOD_BLOCK=12345678

# 2. Export state at that block
npx hardhat run scripts/export-state.js --network mainnet --block $LAST_GOOD_BLOCK

# 3. Verify state integrity
npx hardhat run scripts/verify-state.js

# 4. Deploy recovery contracts if needed
# 5. Migrate affected users
```

### RP-003: Database Recovery

```bash
# 1. Stop affected services
docker-compose -f infra/docker-compose.yml stop indexer

# 2. Restore from backup
./scripts/restore-db.sh --backup-id <BACKUP_ID>

# 3. Verify data integrity
./scripts/verify-db.sh

# 4. Replay missing events from blockchain
npx hardhat run scripts/replay-events.js --from-block <LAST_INDEXED>

# 5. Restart services
docker-compose -f infra/docker-compose.yml up -d indexer
```

---

## Upgrade Procedures

### UP-001: Contract Upgrade (via Proxy)

**Timeline**: 7 days (includes timelock delay)

#### Day 1: Prepare Upgrade

```bash
# 1. Deploy new implementation
npx hardhat run scripts/deploy-implementation.js --network mainnet

# 2. Verify on Etherscan
npx hardhat verify --network mainnet <NEW_IMPL_ADDRESS>

# 3. Run storage layout check
npx hardhat run scripts/check-storage.js

# 4. Submit upgrade proposal to timelock
npx hardhat run scripts/propose-upgrade.js --network mainnet
```

#### Day 1-7: Monitoring Period

```bash
# Monitor for issues
# Community feedback period
# Final review by signers
```

#### Day 7: Execute Upgrade

```bash
# 1. Execute timelock transaction (after delay)
npx hardhat run scripts/execute-upgrade.js --network mainnet

# 2. Verify upgrade success
npx hardhat run scripts/verify-upgrade.js --network mainnet

# 3. Update documentation and addresses
# 4. Announce completion
```

### UP-002: SDK Release

```bash
# 1. Update version
npm version patch|minor|major

# 2. Run full test suite
npm test

# 3. Build
npm run build

# 4. Publish (with 2FA)
npm publish --access public

# 5. Update documentation
# 6. Announce in Discord/Twitter
```

### UP-003: Infrastructure Update

```bash
# 1. Deploy to staging
./scripts/deploy-staging.sh

# 2. Run smoke tests
npm run test:e2e:staging

# 3. Gradual rollout (canary)
kubectl apply -f k8s/canary-deployment.yaml

# 4. Monitor metrics (30 min)
# 5. Full rollout if healthy
kubectl apply -f k8s/production-deployment.yaml

# 6. Rollback if issues
kubectl rollout undo deployment/pil-api
```

---

## Contacts

### On-Call Rotation

Access current rotation: https://pil.pagerduty.com/schedules

### Escalation Path

1. **Level 1**: On-call engineer
2. **Level 2**: Engineering lead
3. **Level 3**: CTO / Security team
4. **Level 4**: External security partners

### External Contacts

| Service | Contact | SLA |
|---------|---------|-----|
| Alchemy | support@alchemy.com | 1 hour |
| Tenderly | enterprise@tenderly.co | 30 min |
| Forta | security@forta.org | 1 hour |
| Audit Partner | security@<auditor>.com | 4 hours |

---

## Appendix

### Useful Commands

```bash
# Get contract state
cast call $CONTRACT_ADDRESS "isPaused()(bool)" --rpc-url $RPC_URL

# Check admin roles
cast call $CONTRACT_ADDRESS "hasRole(bytes32,address)(bool)" \
  $ADMIN_ROLE $ADDRESS --rpc-url $RPC_URL

# Decode transaction data
cast 4byte-decode $CALLDATA

# Estimate gas
cast estimate $CONTRACT_ADDRESS "functionName(args)" --rpc-url $RPC_URL

# Get transaction status
cast receipt $TX_HASH --rpc-url $RPC_URL | jq .status
```

### Environment Variables

```bash
# Required for scripts
export MAINNET_RPC_URL=
export PRIVATE_KEY=
export ORCHESTRATOR_ADDRESS=
export PC3_ADDRESS=
export PBP_ADDRESS=
export EASC_ADDRESS=
export CDNA_ADDRESS=
export ETHERSCAN_API_KEY=
export PAGERDUTY_API_KEY=
```
