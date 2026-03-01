# ZASEON - Mainnet Security Checklist

## Pre-Launch Security Verification

### Smart Contract Security

#### ✅ Completed Checks

- [x] All tests pass: `forge test --summary` (4,426 tests / 189 suites)
- [x] Fuzz testing: 300+ fuzz tests with high iterations
- [x] Invariant testing: 8 invariant tests
- [x] Attack simulation: 44 attack vectors tested
- [x] Echidna property tests: 6 invariant properties verified
- [x] Halmos symbolic execution: 12 symbolic checks (CrossChainProofHub + ZKBoundStateLocks)
- [x] Slither analysis: No critical/high findings (all 9 findings addressed)
- [x] Code coverage: >80% on core contracts
- [x] Bridge adapter tests: 200 tests across 5 adapters
- [x] Privacy contract tests: 183 tests across 3 contracts
- [x] Certora formal specs: 54 spec files with invariants
- [x] K Framework: 5 algebraic specifications for protocol invariants
- [x] TLA+ model checking: 4 safety properties (TVL conservation, no double-spend)
- [x] CLSAG ring signature verifier: 18 test vectors (valid/invalid/gas benchmarks)
- [x] Storage layout: 8 base/upgradeable contract pairs verified compatible
- [x] Cross-chain fork tests: 8 integration tests (chain ID isolation, replay protection)
- [x] Gambit mutation testing: 8 contracts covered

#### ✅ Internal Security Audit (February–March 2026)

- [x] **65 vulnerabilities fixed** - see [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md)
- [x] Phase 1: 26 vulnerabilities (5 Critical, 6 High, 15 Medium)
- [x] Phase 2: 18 vulnerabilities (2 Critical, 4 High, 6 Medium, 6 Low)
- [x] Phase 3 (Session 8): 21 vulnerabilities (4 Critical, 6 High, 7 Medium, 4 Low)
- [x] ReentrancyGuard added to governance and security contracts
- [x] Deprecated .transfer() replaced with .call{}
- [x] Zero-address validation added to admin setters
- [x] Missing events added for config changes
- [x] Batch verifier bypass in ShieldedPool eliminated (require non-zero address)
- [x] Historical Merkle root eviction on ring buffer overwrite
- [x] MultiBridgeRouter ETH forwarding and emergency withdrawal
- [x] NullifierRegistryV3 source Merkle root validation
- [x] All 7 bridge adapters have ERC20 emergency withdrawal

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

| Role               | Required Setup                                     | Status     |
| ------------------ | -------------------------------------------------- | ---------- |
| DEFAULT_ADMIN_ROLE | Must NOT hold OPERATOR, DISPUTE_RESOLVER, RECOVERY | [ ] Verify |
| RELAYER_ROLE       | Separate from admin                                | [ ] Verify |
| CHALLENGER         | Any address (open participation)                   | ✅         |

```bash
# Run access control tests
forge test --match-path "test/security/*" -vvv
```

| Role     | Holder                     | Verified |
| -------- | -------------------------- | -------- |
| Admin    | Gnosis Safe (3/5 multisig) | [ ]      |
| Guardian | Security Council (2/3)     | [ ]      |
| Pauser   | Emergency Multisig         | [ ]      |
| Upgrader | Timelock (48h delay)       | [ ]      |

### Contract Deployment Verification

Run this script after deployment to verify all contracts:

```bash
npx hardhat run scripts/verify-mainnet.ts --network mainnet
```

## Mainnet Configuration

### Timelock Parameters

```javascript
const TIMELOCK_CONFIG = {
  minDelay: 48 * 60 * 60, // 48 hours minimum
  emergencyDelay: 6 * 60 * 60, // 6 hours for emergencies
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
  maxSingleTransfer: parseEther("1000"), // 1000 ETH per tx
  dailyLimit: parseEther("10000"), // 10,000 ETH daily
  cooldownPeriod: 60 * 60, // 1 hour between large transfers
};
```

### Circuit Breaker Thresholds

```javascript
const CIRCUIT_BREAKER = {
  failedProofThreshold: 10, // Pause after 10 failed proofs
  timeWindow: 60 * 60, // Within 1 hour
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

<!-- ACTION REQUIRED: Replace these with actual team contacts before mainnet launch.
     See internal contacts sheet: notion.so/zaseon/emergency-contacts -->

| Role                | Primary                        | Backup     |
| ------------------- | ------------------------------ | ---------- |
| Security Lead       | `REDACTED — set before launch` | `REDACTED` |
| Smart Contract Lead | `REDACTED — set before launch` | -          |
| Infrastructure      | `REDACTED — set before launch` | -          |

### Runbook Location

- [docs/INCIDENT_RESPONSE_RUNBOOK.md](./INCIDENT_RESPONSE_RUNBOOK.md)
- Internal: `notion.so/zaseon/incident-response`

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

| Service     | URL                                                          | Purpose                |
| ----------- | ------------------------------------------------------------ | ---------------------- |
| Dune        | `dune.com/zaseon/mainnet`                                    | Analytics              |
| TheGraph    | `thegraph.com/hosted-service/subgraph/zaseon/zaseon-mainnet` | Indexing               |
| Tenderly    | `dashboard.tenderly.co/zaseon`                               | Transaction simulation |
| OZ Defender | `defender.openzeppelin.com`                                  | Admin operations       |

---

_Security checklist version: 1.1.0_  
_Last updated: February 2026_
