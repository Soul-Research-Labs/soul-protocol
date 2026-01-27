# Soul Incident Response Runbook

> Step-by-step procedures for security incidents. All operational team members must be familiar with these procedures.

## Incident Classification

### Severity Levels

| Level | Name | Description | Response Time | Example |
|-------|------|-------------|---------------|---------|
| **P0** | Critical | Active exploitation, fund loss imminent | < 15 min | Drain attack in progress |
| **P1** | High | Vulnerability discovered, exploit possible | < 1 hour | Critical bug found |
| **P2** | Medium | Security issue, no immediate exploit | < 4 hours | Access control weakness |
| **P3** | Low | Minor issue, no user impact | < 24 hours | Information disclosure |
| **P4** | Info | Security improvement opportunity | < 1 week | Best practice suggestion |

### Classification Matrix (Impact × Exploitability)

| Impact | None | Low | Med | High | Active |
|--------|------|-----|-----|------|--------|
| Critical (>$1M) | P2 | P1 | P0 | P0 | P0 |
| High ($100K-$1M) | P3 | P2 | P1 | P0 | P0 |
| Medium ($10K-$100K) | P3 | P3 | P2 | P1 | P0 |
| Low (<$10K) | P4 | P3 | P3 | P2 | P1 |
| None | P4 | P4 | P3 | P3 | P2 |

---

## Response Team Structure

### Roles & Responsibilities

| Role | Primary | Backup | Responsibilities |
|------|---------|--------|------------------|
| **Incident Commander** | @lead | @backup-lead | Overall coordination, decisions |
| **Technical Lead** | @tech-lead | @senior-dev | Technical investigation, fixes |
| **Communications Lead** | @comms | @pm | User/public communication |
| **Operations Lead** | @ops | @devops | System access, deployments |
| **Legal/Compliance** | @legal | External | Regulatory, legal guidance |

### Escalation Path

1. **Detector** → On-Call Engineer (15 min SLA)
2. **P3/P4**: Handle independently
3. **P0/P1/P2**: Escalate to Incident Commander → branches to Technical, Communications, Operations
4. **P0 Only**: CEO/Board involvement

---

## Communication Protocols

### Internal Channels

| Channel | Purpose | SLA |
|---------|---------|-----|
| #incident-war-room | Active incident coordination | Real-time |
| #security-alerts | Automated monitoring alerts | 5 min |
| @security-oncall | Direct escalation | 15 min |
| Incident Call | Voice coordination for P0/P1 | Immediate |

### External Communication

| Audience | Channel | Timing | Approver |
|----------|---------|--------|----------|
| Users | Status page | Every 30 min during P0/P1 | Comms Lead |
| Community | Discord/Twitter | After initial assessment | Incident Commander |
| Partners | Direct email | Within 1 hour of P0 | CEO |
| Regulators | Formal notice | As required by law | Legal |
| Media | Press release | Only for major incidents | CEO + Legal |

### Communication Templates

**Status Update (During)**: `[INCIDENT] - [COMPONENT] Temporarily Paused. Investigating. Funds safe. Next update: [TIME]`

**Resolution**: `[RESOLVED] - [COMPONENT] Resolved. Duration: [X]. Cause: [BRIEF]. Post-mortem in 48h.`

---

## Incident Response Procedures

### Phase 1: Detection & Triage (0-15 min)

1. **Acknowledge**: Respond to #security-alerts, claim in PagerDuty, start incident log
2. **Assess**: Identify components, check fund risk, classify severity (P0-P4), check if active
3. **Escalate (P0/P1/P2)**: Page Incident Commander, create #incident-YYYY-MM-DD channel
4. **Contain (if active)**: Execute emergency pause (Playbook 1), document all actions

### Phase 2: Containment (15-60 min)

1. **Assemble Team**: IC online, Technical Lead, Comms Lead, Ops on standby
2. **Isolate**: Pause contracts, disable integrations, rate limit, blacklist attackers
3. **Preserve Evidence**: Snapshot state, export logs, record attacker txs, document timeline
4. **Communicate**: Update status page, post in Discord, prepare holding statement

### Phase 3: Investigation (1-4 hours)

1. **Root Cause**: ID vulnerability type, attack vector, analyze attacker txs, ID affected contracts
2. **Impact Assessment**: Calculate funds at risk/lost, identify affected users, assess data exposure
3. **Develop Fix**: Design patch, review with 2+ seniors, test on fork, prepare deployment
4. **Validate**: Check for similar vulns, review related code, verify other contracts unaffected

### Phase 4: Eradication & Recovery (4-24 hours)

1. **Deploy Fix**: Execute upgrade (timelock or emergency), verify deployment, run integration tests
2. **Restore Services**: Gradually re-enable, monitor for anomalies, verify cross-chain ops
3. **Fund Recovery**: Contact exchanges, coordinate with on-chain sleuths, law enforcement if needed
4. **Communicate**: Announce resolution, impact summary, compensation plan, post-mortem timeline

---

## Specific Incident Playbooks

### Playbook 1: Emergency Contract Pause

**Trigger**: Active exploit detected, funds at risk

**Authority**: Guardian role holder

**Procedure**:

```bash
# 1. Connect to emergency wallet
# Ensure Guardian role wallet is available

# 2. Execute pause on affected contract(s)
# Using Foundry cast command:

cast send $CONTRACT_ADDRESS "pause()" \
  --rpc-url $RPC_URL \
  --private-key $GUARDIAN_PRIVATE_KEY \
  --gas-limit 100000

# For multiple contracts, pause in order:
# 1. CrossChainProofHubV3
# 2. SoulAtomicSwapV2
# 3. All bridge adapters
# 4. ZKBoundStateLocks
```

**Verification**:
```bash
# Verify pause state
cast call $CONTRACT_ADDRESS "paused()(bool)" --rpc-url $RPC_URL
# Should return: true
```

**Rollback**:
```bash
# Only after incident resolved and fix deployed
cast send $CONTRACT_ADDRESS "unpause()" \
  --rpc-url $RPC_URL \
  --private-key $GUARDIAN_PRIVATE_KEY
```

### Playbook 2: Circuit Breaker Activation

**Trigger**: Anomaly detected by monitoring

**Authority**: Automatic or Operator role

**Monitoring Thresholds**:
- Volume spike: > 3x average in 1 hour
- Failed transactions: > 10% in 10 minutes
- Large withdrawal: > $100K single tx
- Multiple withdrawals: > $500K in 1 hour

**Procedure**:
```bash
# Manual activation if automatic trigger failed
cast send $CIRCUIT_BREAKER_ADDRESS \
  "triggerCircuitBreaker(string)" \
  "Manual activation: [REASON]" \
  --rpc-url $RPC_URL \
  --private-key $OPERATOR_PRIVATE_KEY
```

### Playbook 3: Malicious Message Block

**Trigger**: Suspected malicious cross-chain message

**Authority**: Operator role

**Procedure**:
```bash
# 1. Block specific source address
cast send $BRIDGE_ADAPTER_ADDRESS \
  "blockSource(uint256,address)" \
  $SOURCE_CHAIN_ID $MALICIOUS_ADDRESS \
  --rpc-url $RPC_URL \
  --private-key $OPERATOR_PRIVATE_KEY

# 2. Block entire source chain (extreme measure)
cast send $BRIDGE_ADAPTER_ADDRESS \
  "setChainBlocked(uint256,bool)" \
  $SOURCE_CHAIN_ID true \
  --rpc-url $RPC_URL \
  --private-key $OPERATOR_PRIVATE_KEY
```

### Playbook 4: Emergency Upgrade

**Trigger**: Critical vulnerability requires immediate fix

**Authority**: Multi-sig (3/7) + Emergency timelock bypass

**Procedure**:
```bash
# 1. Prepare upgrade transaction
# (Fix must already be audited/reviewed)

# 2. Collect multi-sig signatures
# Coordinate through secure channel

# 3. Execute emergency upgrade
cast send $UPGRADE_TIMELOCK_ADDRESS \
  "executeEmergency(address,bytes)" \
  $PROXY_ADDRESS $UPGRADE_CALLDATA \
  --rpc-url $RPC_URL \
  --private-key $MULTISIG_EXECUTION_KEY

# 4. Verify upgrade
cast call $PROXY_ADDRESS "getImplementation()(address)" \
  --rpc-url $RPC_URL
```

### Playbook 5: Key Compromise Response

**Trigger**: Private key suspected or confirmed compromised

**Authority**: Incident Commander + Multi-sig

**Procedure**:

1. **Immediate Actions** (< 5 minutes)
   - Pause all contracts using remaining valid keys
   - Revoke compromised key's roles
   - Monitor for unauthorized transactions

2. **Containment** (< 30 minutes)
   ```bash
   # Revoke compromised address from all roles
   cast send $CONTRACT_ADDRESS \
     "revokeRole(bytes32,address)" \
     $ROLE_HASH $COMPROMISED_ADDRESS \
     --rpc-url $RPC_URL \
     --private-key $ADMIN_PRIVATE_KEY
   ```

3. **Recovery** (< 24 hours)
   - Generate new keys securely
   - Update multi-sig configuration
   - Re-grant roles to new addresses
   - Document key rotation

### Playbook 6: Bridge Drain Attack

**Trigger**: Unauthorized large withdrawals detected

**Authority**: Guardian + Incident Commander

**Procedure**:

1. **Immediate** (< 2 minutes)
   - Pause all bridge adapters
   - Pause central hub contract
   - Alert all exchanges

2. **Containment** (< 15 minutes)
   ```bash
   # Block attacker addresses
   cast send $BRIDGE_ADDRESS \
     "blacklistAddress(address)" \
     $ATTACKER_ADDRESS \
     --rpc-url $RPC_URL \
     --private-key $GUARDIAN_PRIVATE_KEY
   ```

3. **Investigation**
   - Trace attack origin
   - Identify exploited vulnerability
   - Calculate total loss

4. **Recovery**
   - Contact exchanges (Binance, Coinbase, etc.)
   - File law enforcement report
   - Coordinate with on-chain investigators

---

## Recovery Procedures

### Contract Re-enablement Checklist

```
□ Fix verified and deployed
□ Integration tests passing
□ No new vulnerabilities introduced
□ Monitoring enhanced for recurrence
□ Multi-sig approval for unpause
□ Gradual re-enablement plan ready
□ Communication prepared

Re-enablement Order:
1. ZKBoundStateLocks (lowest risk)
2. NullifierRegistry
3. CrossChainProofHubV3
4. Bridge Adapters (one at a time)
5. SoulAtomicSwapV2 (highest risk, last)
```

### Service Restoration Verification

```bash
# 1. Verify contract states
for CONTRACT in $CONTRACT_LIST; do
  echo "Checking $CONTRACT..."
  cast call $CONTRACT "paused()(bool)" --rpc-url $RPC_URL
done

# 2. Run smoke tests
npm run test:smoke

# 3. Verify cross-chain functionality
npm run test:crosschain:smoke

# 4. Monitor for 1 hour before announcing resolution
```

---

## Post-Incident Activities

### Post-Mortem Process

**Timeline**: Complete within 48 hours of resolution

**Template**:
```markdown
# Post-Mortem: [INCIDENT NAME]

## Summary
- **Date**: 
- **Duration**: 
- **Severity**: 
- **Impact**: 

## Timeline
- HH:MM - Detection
- HH:MM - Escalation
- HH:MM - Containment
- HH:MM - Root cause identified
- HH:MM - Fix deployed
- HH:MM - Services restored

## Root Cause
[Detailed technical explanation]

## Impact
- Funds lost: 
- Users affected: 
- Downtime: 

## Response Assessment
### What went well
- 
### What could be improved
- 

## Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
|        |       |          |        |

## Lessons Learned
```

### Long-term Improvements

| Category | Action | Timeline |
|----------|--------|----------|
| Prevention | Add automated checks | 2 weeks |
| Detection | Enhance monitoring | 1 week |
| Response | Update runbooks | 3 days |
| Recovery | Improve backup procedures | 2 weeks |
| Training | Conduct incident drill | 1 month |

---

## Appendix

### Emergency Contacts

| Role | Name | Phone | Telegram |
|------|------|-------|----------|
| Primary On-Call | [REDACTED] | [REDACTED] | @[REDACTED] |
| Incident Commander | [REDACTED] | [REDACTED] | @[REDACTED] |
| Legal Counsel | [REDACTED] | [REDACTED] | N/A |

### External Resources

| Resource | Contact | Purpose |
|----------|---------|---------|
| Immunefi | platform@immunefi.com | Bug bounty coordination |
| Chainanalysis | incident@chainalysis.com | Fund tracing |
| AWS Support | Enterprise support line | Infrastructure |

### Multi-Sig Wallet Addresses

| Network | Address | Signers Required |
|---------|---------|------------------|
| Ethereum | [ADDRESS] | 4/7 |
| Arbitrum | [ADDRESS] | 3/5 |
| Optimism | [ADDRESS] | 3/5 |
| Base | [ADDRESS] | 3/5 |

---

*Last Updated: January 2026*
*Version: 1.0.0*
*Review Schedule: Quarterly*
