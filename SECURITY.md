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

> **Note:** External bug bounty and third-party audits are currently on hold. All security efforts are focused on internal hardening.

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
- Post-quantum cryptography (Dilithium, Kyber, SPHINCS+)
- Formal verification of key invariants
- **Signature malleability protection** on all ECDSA operations
- **VRF verification** for randomness in relayer selection
- **Cross-chain replay protection** via chain ID validation

### Recent Security Fixes (February 2026)

| Fix | Severity | Description |
|-----|----------|-------------|
| Signature Malleability | CRITICAL | Added SECP256K1_N_DIV_2 check to reject malleable signatures |
| VRF Bypass | CRITICAL | Fixed logic error allowing any non-zero gamma to pass VRF |
| Chain ID Validation | CRITICAL | Added block.chainid check in cross-chain message execution |
| DoS Protection | HIGH | O(1) relayer removal prevents unbounded loop gas griefing |
| ReentrancyGuard | HIGH | Added nonReentrant to depositStake() and DirectL2Messenger |
| Zero-Address Checks | MEDIUM | Validation added to setVerifier/setVerifierRegistry |
| Unused Return Value | LOW | Fixed unused return in VerifierRegistry._isValidVerifier |

### Known Dependency Issues

| Package | Severity | Status | Details |
|---------|----------|--------|---------|
| elliptic | LOW | Upstream Issue | GHSA-848j-6mx2-7j84 - Risky crypto implementation in elliptic used by @ethersproject/signing-key (ethers v5) via circomlibjs. No fix available until circomlibjs migrates to ethers v6. Risk mitigated: circomlibjs is only used for ZK circuit development, not for transaction signing in production. |

**Note:** npm overrides are used to enforce security patches for transitive dependencies (diff, jsonpath, undici, ws, tar). See `package.json` overrides section.

### Operational Security

- Role-based access control (RBAC)
- Emergency withdrawal mechanisms
- Continuous automated security testing
- Incident response procedures documented

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
| [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md) | Latest findings |
| [SECURITY_INVARIANTS.md](./docs/SECURITY_INVARIANTS.md) | Formal invariants |
| [THREAT_MODEL.md](./docs/THREAT_MODEL.md) | Threat analysis |

Thank you for contributing to Soul Protocol security!
