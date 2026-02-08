# Soul Protocol Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability within Soul Protocol, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities.

2. **Email us directly** at: security@soul.network

3. **Encrypt your message** using our PGP key (available at https://soul.network/.well-known/pgp-key.txt)

4. Include in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 24 hours
- **Initial Assessment**: Within 72 hours
- **Status Updates**: Weekly until resolved
- **Resolution Timeline**: Varies by severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Severity Levels

**Critical**
- Direct fund theft
- Permanent loss of funds
- Unauthorized token minting
- Governance takeover

**High**
- Temporary fund lock
- Proof forgery
- Access control bypass
- Cross-chain message manipulation

**Medium**
- Denial of service
- Gas griefing
- Information disclosure
- Nullifier collision (theoretical)

**Low**
- UI/UX issues
- Documentation errors
- Non-critical code quality issues

## Internal Security Program

> **Note:** Bug bounty program in preparation. Third-party audits scheduled for Q2 2026.

### Bug Bounty Program (Planned)

| Severity | Reward Range | Examples |
|----------|--------------|----------|
| Critical | $50,000 - $500,000 | Direct fund theft, proof forgery |
| High | $10,000 - $50,000 | Access control bypass, cross-chain manipulation |
| Medium | $2,000 - $10,000 | DoS attacks, gas griefing |
| Low | $500 - $2,000 | Information disclosure, non-critical issues |

**Scope:**
- Smart contracts in `/contracts`
- Noir circuits in `/noir`
- SDK security issues affecting contract interaction

**Out of Scope:**
- Documentation errors
- UI/frontend issues
- Already-known issues in SECURITY_AUDIT_REPORT.md

### Monitoring Recommendations

| Component | Monitoring Tool | Alert Threshold |
|-----------|-----------------|-----------------|
| Bridge Deposits | Tenderly/OpenZeppelin Defender | > $100k single tx |
| Proof Verifications | Custom Indexer | Failure rate > 1% |
| TVL Changes | Dune Dashboard | > 10% in 1 hour |
| Admin Actions | Defender Sentinels | Any timelock proposal |
| Relayer Health | Prometheus/Grafana | Latency > 30s |

**Recommended Alert Channels:**
- PagerDuty for Critical (24/7)
- Slack/Discord for High/Medium
- Email digest for Low

### Internal Security Testing

| Tool | Purpose | Frequency |
|------|---------|-----------|
| Certora | Formal verification | Per release |
| Slither | Static analysis | Every commit |
| Echidna | Property fuzzing | Weekly |
| Halmos | Symbolic execution | Weekly |
| Foundry Fuzz | Differential testing | Every PR |
| Mutation Testing | Test quality | Monthly |

### Security Focus Areas

**In Scope:**
- Smart contracts in `/contracts`
- Circuit implementations in `/circuits`
- SDK security issues
- Cross-chain message validation
- Proof verification logic

**Development Only:**
- All testing on local forks only
- No mainnet/testnet deployment planned
- Internal red team exercises

## Security Measures

### Smart Contract Security

- All contracts are upgradeable via proxy pattern
- 48-hour timelock on all upgrades
- Multi-sig requirement for admin operations
- Pausable emergency mechanism
- Reentrancy guards on all external calls

### Cryptographic Security

- Groth16 proofs on BN254 curve
- Poseidon hash function for circuits
- Formal verification of key invariants
- **Signature malleability protection** on all ECDSA operations
- **VRF verification** for randomness in relayer selection
- **Cross-chain replay protection** via chain ID validation

### Recent Security Fixes (February 2026)

#### Phase 1: Core Protocol Fixes

##### Critical Fixes
| Fix | Contract | Description |
|-----|----------|-------------|
| Nullifier Race Condition | ZKBoundStateLocks | Fixed double-spend via optimisticUnlock() race |
| Access Control | CrossChainProofHubV3 | Added role checks to submitProofInstant/submitBatch |
| Proof Verification | UnifiedNullifierManager | Fixed _verifyDerivationProof accepting any proof |
| Signature Malleability | Various | Added SECP256K1_N_DIV_2 check |
| VRF Bypass | Various | Fixed logic error allowing any non-zero gamma |
| Chain ID Validation | CrossChainMessageRelay | Added block.chainid check in proof verification |

##### High Fixes
| Fix | Contract | Description |
|-----|----------|-------------|
| EIP-712 Binding | ConfidentialStateContainerV3 | Signature now binds to encryptedState/metadata |
| Hash Collision | UnifiedNullifierManager | Changed abi.encodePacked to abi.encode |
| Recovery Bypass | ZKBoundStateLocks | recoverLock now validates unlock state + nullifier |
| Chain ID Truncation | ZKBoundStateLocks | Extended domain separator to uint64 chainId |
| Double-Counting | CrossChainProofHubV3 | Fixed relayerSuccessCount double increment |
| Challenger Rewards | CrossChainProofHubV3 | Added claimableRewards + withdrawRewards() |

##### Medium Fixes
| Fix | Contract | Description |
|-----|----------|-------------|
| Missing Events | Multiple | Added events for all admin configuration changes |
| Input Validation | DirectL2Messenger | Zero-checks, upper bounds on parameters |
| DoS Prevention | ZKBoundStateLocks | MAX_ACTIVE_LOCKS enforcement |
| Pagination | ConfidentialStateContainerV3, UnifiedNullifierManager | Added paginated getters |
| Role Separation | ZKBoundStateLocks | Added confirmRoleSeparation() |
| Silent Failures | CrossChainMessageRelay | Emit MessageFailed on batch verification failure |

#### Phase 2: Governance & Infrastructure Fixes (February 5, 2026)

##### Critical Fixes
| Fix | Contract | Description |
|-----|----------|-------------|
| Reentrancy | SoulMultiSigGovernance | Added ReentrancyGuard + nonReentrant to executeProposal() |
| Reentrancy | BridgeWatchtower | Added ReentrancyGuard to completeExit() and claimRewards() |

##### High Fixes
| Fix | Contract | Description |
|-----|----------|-------------|
| DoS via .transfer() | SoulPreconfirmationHandler | Replaced .transfer() with .call{value:}() in 4 locations |
| DoS via .transfer() | SoulIntentResolver | Replaced .transfer() with .call{value:}() in withdrawBond() |
| DoS via .transfer() | SoulL2Messenger | Replaced .transfer() with .call{value:}() in withdrawBond() |
| Loop Gas | BridgeWatchtower | Optimized slashInactive() with cached length + batch storage writes |

##### Medium Fixes
| Fix | Contract | Description |
|-----|----------|-------------|
| Zero-Address | SoulProtocolHub | Added validation to addSupportedChain() |

**Total: 44 vulnerabilities fixed across both phases**

For complete details, see [docs/SECURITY_AUDIT_REPORT.md](./docs/SECURITY_AUDIT_REPORT.md).

### Dependency Vulnerabilities (Known Issues)

As of February 2026, the following dependency vulnerabilities exist with **no upstream fix available**:

| CVE | Package | Severity | Status | Risk Mitigation |
|-----|---------|----------|--------|-----------------|
| CVE-2025-14505 | elliptic ≤6.6.1 | Low (2.9/10) | No patch available | See mitigation below |

**CVE-2025-14505 Details:**
- **Affected**: `elliptic` library (all versions ≤6.6.1), used by ethers.js v5 via `@nomicfoundation/hardhat-verify`
- **Issue**: ECDSA signature generation flaw when interim value 'k' has leading zeros
- **Impact**: Potential secret key exposure under specific cryptanalysis conditions
- **EPSS Score**: 0.01% (1st percentile - very low exploitation probability)

**Why This Doesn't Affect Soul Protocol:**
1. **Smart Contracts**: On-chain signature verification uses `ecrecover` opcode, not JavaScript elliptic
2. **ZK Proofs**: All cryptographic operations use Noir circuits with BN254, not elliptic curves via JS
3. **SDK Usage**: The SDK uses ethers.js v6 (main dependency), not v5
4. **Hardhat Verify**: Only used for contract verification on block explorers (dev tooling), not production code
5. **ZK Proofs**: All proof verification delegated to registered IProofVerifier implementations

**Actions Taken:**
- ✅ Replaced `circomlibjs` with `poseidon-lite` (zero dependencies) for Poseidon hashing
- ✅ Reduced vulnerabilities from 19 to 11 (all remaining are in Hardhat verify tooling)
- npm overrides configured to use latest elliptic version when available

**Monitoring Actions:**
- Track [indutny/elliptic#321](https://github.com/indutny/elliptic/issues/321) for upstream fix
- Monitor `@nomicfoundation/hardhat-verify` for migration to ethers v6

### Known Dependency Issues

| Package | Severity | Status | Details |
|---------|----------|--------|---------|
| elliptic | LOW | Upstream Issue | GHSA-848j-6mx2-7j84 - Risky crypto implementation in elliptic used by @ethersproject/signing-key (ethers v5) via @nomicfoundation/hardhat-verify. No fix available until Hardhat migrates to ethers v6. Risk mitigated: hardhat-verify is only used for contract verification on block explorers, not for transaction signing or production operations. |

**Note:** npm overrides are used to enforce security patches for transitive dependencies (diff, jsonpath, undici, ws, tar). See `package.json` overrides section.

### Operational Security

- Role-based access control (RBAC)
- Emergency withdrawal mechanisms
- Continuous automated security testing
- Incident response procedures documented

### Incident Response Procedures

**Severity Classification:**
| Level | Response Time | Escalation |
|-------|---------------|------------|
| P0 (Critical) | 15 minutes | All hands, pause contracts |
| P1 (High) | 1 hour | Security team + on-call |
| P2 (Medium) | 4 hours | Security team |
| P3 (Low) | 24 hours | Normal triage |

**Response Steps:**
1. **Detect** - Monitoring alerts or user report
2. **Assess** - Determine severity and scope
3. **Contain** - Pause affected contracts if needed
4. **Remediate** - Deploy fix via timelock (or emergency if P0)
5. **Recover** - Restore normal operations
6. **Review** - Post-mortem within 48 hours

**Emergency Contacts:**
- Primary: Security Lead (on-call rotation)
- Secondary: Protocol Lead
- Tertiary: Legal/Comms

### Key Management & Rotation

**Key Types:**
| Key | Rotation Period | Storage |
|-----|-----------------|---------|
| Admin Multisig | Annual review | Hardware wallets |
| Operator Keys | Quarterly | HSM or hardware wallet |
| Relayer Keys | Monthly | Secure enclave |
| Monitoring Keys | On compromise | Environment vars |

**Rotation Procedure:**
1. Generate new key in secure environment
2. Add new key via timelock proposal
3. Wait for timelock execution
4. Remove old key via timelock
5. Update documentation
6. Revoke old key access

## Security Roadmap

See [docs/SECURITY_ROADMAP.md](./docs/SECURITY_ROADMAP.md) for the comprehensive security hardening plan.

### Current Phase: L3 - Hardening
- Mutation testing
- Attack simulations
- Chaos testing

### Next Phase: L4 - Resilience
- Economic security analysis
- Game theory verification
- Stress testing

## Internal Security Contacts

- Security Lead: [Internal]
- Emergency Channel: [Internal Slack/Discord]
- Response SLA: 24 hours

## Security Documentation

| Document | Description |
|----------|-------------|
| [SECURITY_ROADMAP.md](./docs/SECURITY_ROADMAP.md) | Complete security plan |
| [SECURITY_AUDIT_REPORT.md](./docs/SECURITY_AUDIT_REPORT.md) | February 2026 audit findings (26 fixes) |
| [SECURITY_INVARIANTS.md](./docs/SECURITY_INVARIANTS.md) | Formal invariants |
| [THREAT_MODEL.md](./docs/THREAT_MODEL.md) | Threat analysis |

Thank you for contributing to Soul Protocol security!
