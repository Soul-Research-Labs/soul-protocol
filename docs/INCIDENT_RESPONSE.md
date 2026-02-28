# Zaseon Incident Response

> Quick reference for security incidents. For detailed procedures, see [INCIDENT_RESPONSE_RUNBOOK.md](INCIDENT_RESPONSE_RUNBOOK.md).

## Severity Levels

| Level | Response | Action |
|-------|----------|--------|
| P1 Critical | <15 min | Active exploit, all-hands, pause protocol |
| P2 High | <1 hour | Vulnerability found, core team + security |
| P3 Medium | <4 hours | Suspicious activity, security team |
| P4 Low | <24 hours | Minor issues, on-call engineer |

## Response Team

**Incident Commander** (CTO) → **Tech Lead** (Sr. Engineer) → **Comms Lead** (Community) → **Guardian Coordinator** (Ops)

```
P1/P2: Detector → On-Call → Incident Commander → Full Team
P3/P4: Detector → On-Call → Security Team Lead
```

## Critical Alerts

| Alert | Trigger | Action |
|-------|---------|--------|
| Large Transfer | >$100k | Page on-call |
| Failed Proofs | >10 in 5 min | Page on-call |
| Contract Paused | Event detected | Notify team |
| Admin Change | Role granted/revoked | Notify security |
| Gas Anomaly | >3x average | Log & notify |

## Emergency Actions

### Immediate Pause (P1)
```bash
# Emergency pause all contracts
npx hardhat run scripts/emergency-pause.js --network mainnet
```

### Guardian Multi-Sig Thresholds
| Action | Signatures | Timelock |
|--------|------------|----------|
| Pause | 1/N (Owner) | None |
| Unpause | 3/5 | 4h |
| Fund Recovery | 4/5 | 24h |
| Upgrade | 4/5 | 48h |

## Communication

**Initial:**
```
🚨 Zaseon Security Notice - Investigating [COMPONENT]. Status: [IN PROGRESS]. Updates every [30 min].
```

**Resolved:**
```
✅ Zaseon Security Update - Resolved. Root cause: [X]. Impact: [Y]. Post-mortem in 7 days.
```

## Post-Incident

- [ ] Post-mortem within 7 days
- [ ] Action items assigned
- [ ] Monitoring improved
- [ ] Runbooks updated
- [ ] Bug bounty paid (if applicable)

## Emergency Contacts

See [INCIDENT_RESPONSE_RUNBOOK.md](INCIDENT_RESPONSE_RUNBOOK.md) for full contact list.

---
*Review quarterly | Update after every P1/P2*
