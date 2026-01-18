# PIL Protocol Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability within PIL Protocol, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities.

2. **Email us directly** at: security@pil.network

3. **Encrypt your message** using our PGP key (available at https://pil.network/.well-known/pgp-key.txt)

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

## Bug Bounty Program

We operate a bug bounty program for responsible disclosure.

### Rewards

| Severity | Reward Range |
|----------|--------------|
| Critical | $50,000 - $250,000 |
| High | $10,000 - $50,000 |
| Medium | $2,000 - $10,000 |
| Low | $500 - $2,000 |

### Scope

**In Scope:**
- Smart contracts in `/contracts`
- Circuit implementations in `/circuits`
- SDK security issues
- Cross-chain message validation
- Proof verification logic

**Out of Scope:**
- Third-party dependencies (report to maintainers)
- Previously reported issues
- Issues in non-production code
- Social engineering attacks
- Denial of service via high gas costs

### Rules

1. Do not exploit vulnerabilities on mainnet
2. Test only on testnets or local forks
3. Do not access or modify other users' data
4. Provide sufficient detail to reproduce
5. Allow reasonable time for fixes before disclosure

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
- Powers of Tau ceremony for trusted setup
- Formal verification of key invariants

### Operational Security

- Multi-sig wallets for treasury and admin
- Hardware security modules for key management
- Regular security audits (quarterly)
- Continuous monitoring with Forta agents
- Incident response procedures documented

## Audit Reports

| Auditor | Date | Scope | Report |
|---------|------|-------|--------|
| TBD | TBD | Core Contracts | [Link] |
| TBD | TBD | Circuit Security | [Link] |

## Responsible Disclosure

We kindly ask security researchers to:

1. Give us reasonable time to fix issues before public disclosure
2. Make a good faith effort to avoid privacy violations
3. Not degrade the user experience or disrupt services
4. Only interact with your own accounts during testing

## Contact

- Security Email: security@pil.network
- PGP Fingerprint: XXXX XXXX XXXX XXXX XXXX
- Discord: #security-reports
- Response SLA: 24 hours

Thank you for helping keep PIL Protocol secure!
