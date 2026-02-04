# Soul Protocol - Mainnet Security Checklist

## Pre-Launch Security Verification

### Smart Contract Security

#### ✅ Completed Checks
- [x] All tests pass: `forge test --summary` (230+ tests)
- [x] Fuzz testing: 116+ fuzz tests with high iterations
- [x] Invariant testing: 8 invariant tests
- [x] Attack simulation: 44 attack vectors tested
- [x] Echidna property tests: 21 properties verified
- [x] Slither analysis: No critical/high findings
- [x] Code coverage: >80% on core contracts

#### ✅ Internal Security Audit (February 2026)
- [x] **26 vulnerabilities fixed** - see [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md)
- [x] 5 Critical: Nullifier race, access control, proof verification
- [x] 6 High: EIP-712 binding, hash collisions, reward mapping
- [x] 15 Medium: Events, validation, pagination, role separation

#### 🔄 Pending Verification
- [ ] External audit (Trail of Bits / OpenZeppelin / Consensys Diligence)
- [ ] Certora formal verification specs executed
- [ ] Bug bounty program launched (Immunefi)
- [ ] 30+ days testnet stability

### Access Control Verification

#### Pre-Mainnet Role Separation ⚠️ REQUIRED
```bash
# After deployment, call these to enforce role separation:
ZKBoundStateLocks.confirmRoleSeparation()
CrossChainProofHubV3.confirmRoleSeparation()
```

| Role | Required Setup | Status |
|------|----------------|--------|
| DEFAULT_ADMIN_ROLE | Must NOT hold OPERATOR, DISPUTE_RESOLVER, RECOVERY | [ ] Verify |
| RELAYER_ROLE | Separate from admin | [ ] Verify |
| CHALLENGER | Any address (open participation) | ✅ |

```bash
# Run access control tests
forge test --match-path "test/security/*" -vvv
```

| Role | Holder | Verified |
|------|--------|----------|
| Admin | Gnosis Safe (3/5 multisig) | [ ] |
| Guardian | Security Council (2/3) | [ ] |
| Pauser | Emergency Multisig | [ ] |
| Upgrader | Timelock (48h delay) | [ ] |

### Contract Deployment Verification

Run this script after deployment to verify all contracts:

```bash
npx hardhat run scripts/verify-mainnet.ts --network mainnet
```

## Mainnet Configuration

### Timelock Parameters
```javascript
const TIMELOCK_CONFIG = {
  minDelay: 48 * 60 * 60,        // 48 hours minimum
  emergencyDelay: 6 * 60 * 60,   // 6 hours for emergencies
  gracePeriod: 7 * 24 * 60 * 60, // 7 days to execute
  
  // Required signatures
  proposerThreshold: 2,
  executorThreshold: 3,
  cancellerThreshold: 1,
};
```

### Bridge Rate Limits
```javascript
const RATE_LIMITS = {
  maxSingleTransfer: parseEther("1000"),   // 1000 ETH per tx
  dailyLimit: parseEther("10000"),         // 10,000 ETH daily
  cooldownPeriod: 60 * 60,                 // 1 hour between large transfers
};
```

### Circuit Breaker Thresholds
```javascript
const CIRCUIT_BREAKER = {
  failedProofThreshold: 10,    // Pause after 10 failed proofs
  timeWindow: 60 * 60,         // Within 1 hour
  largeTransferThreshold: 100, // ETH threshold for alerts
};
```

## Launch Day Protocol

### T-24 Hours
- [ ] Final testnet integration test
- [ ] Verify all contract bytecode matches audited code
- [ ] Team availability confirmed
- [ ] Status page operational
- [ ] Incident response team on standby

### T-1 Hour
- [ ] Final gas price check
- [ ] Deployer wallet funded
- [ ] RPC endpoints stable
- [ ] Block explorer accessible

### Deployment Sequence
```bash
# 1. Deploy verifiers (no dependencies)
npx hardhat run scripts/deploy/01-verifiers.ts --network mainnet

# 2. Deploy core infrastructure
npx hardhat run scripts/deploy/02-core.ts --network mainnet

# 3. Deploy application layer
npx hardhat run scripts/deploy/03-apps.ts --network mainnet

# 4. Configure permissions
npx hardhat run scripts/deploy/04-permissions.ts --network mainnet

# 5. Verify all contracts
npx hardhat run scripts/verify-contracts.ts --network mainnet
```

### Post-Deployment (First 24 Hours)
- [ ] All contracts verified on Etherscan
- [ ] Initial state verified (no unexpected storage)
- [ ] Admin transferred to multisig
- [ ] Monitoring alerts active
- [ ] First successful transaction confirmed

## Emergency Response

### Pause Triggers
1. **Automatic**: Circuit breaker trips (10+ failed proofs/hour)
2. **Manual**: Guardian calls `emergencyPause()`
3. **Scheduled**: Via timelock for maintenance

### Emergency Contacts
| Role | Primary | Backup |
|------|---------|--------|
| Security Lead | security@soul.network | +1-XXX-XXX-XXXX |
| Smart Contract Lead | contracts@soul.network | - |
| Infrastructure | infra@soul.network | - |

### Runbook Location
- [docs/INCIDENT_RESPONSE_RUNBOOK.md](./INCIDENT_RESPONSE_RUNBOOK.md)
- Internal: `notion.so/soul/incident-response`

## Contract Upgrade Policy

### Standard Upgrade (Non-Critical)
```
Day 1:  Upgrade proposed → Timelock starts (48h)
Day 3:  Community review window
Day 7:  Upgrade executed (within grace period)
```

### Critical Security Upgrade
```
Hour 0:  Vulnerability discovered → Team notified
Hour 1:  Assessment complete → Fix developed
Hour 6:  Emergency timelock (6h) → Fix deployed
Hour 24: Post-mortem published
```

### Upgrade Verification
```bash
# Verify upgrade implementation matches
forge verify-check <IMPLEMENTATION_ADDRESS> \
  --chain-id 1 \
  --constructor-args $(cast abi-encode "constructor()")
```

---

## Monitoring Dashboard URLs

| Service | URL | Purpose |
|---------|-----|---------|
| Dune | `dune.com/soul/mainnet` | Analytics |
| TheGraph | `thegraph.com/hosted-service/subgraph/soul/soul-mainnet` | Indexing |
| Tenderly | `dashboard.tenderly.co/soul` | Transaction simulation |
| OZ Defender | `defender.openzeppelin.com` | Admin operations |

---

*Security checklist version: 1.0.0*  
*Last updated: January 2026*
