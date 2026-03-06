# Architecture Decision Records (ADRs)

Records of significant architectural decisions made during ZASEON development.

## Index

| ADR                                                  | Title                                   | Status   | Date       |
| ---------------------------------------------------- | --------------------------------------- | -------- | ---------- |
| [ADR-001](ADR-001-groth16-over-plonk.md)             | Why UltraHonk (Noir) over Groth16/PLONK | Accepted | 2026-02-27 |
| [ADR-002](ADR-002-cross-chain-nullifier-design.md)   | Cross-Chain Nullifier Design (CDNA)     | Accepted | 2026-02-27 |
| [ADR-003](ADR-003-relayer-incentive-mechanism.md)    | Relayer Incentive Mechanism             | Accepted | 2026-02-27 |
| [ADR-004](ADR-004-experimental-feature-isolation.md) | Experimental Feature Isolation          | Accepted | 2026-02-27 |
| [ADR-005](ADR-005-uups-proxy-pattern.md)             | UUPS Proxy Pattern                      | Accepted | 2026-02-28 |
| [ADR-006](ADR-006-erc5564-stealth-addresses.md)      | ERC-5564 Stealth Addresses              | Accepted | 2026-02-28 |
| [ADR-007](ADR-007-poseidon-hash.md)                  | Poseidon Hash Function                  | Accepted | 2026-02-28 |
| [ADR-008](ADR-008-multi-bridge-failover.md)          | Multi-Bridge Failover                   | Accepted | 2026-03-01 |
| [ADR-009](ADR-009-compliance-oracle.md)              | Compliance Oracle Integration           | Accepted | 2026-03-01 |
| [ADR-010](ADR-010-token-governance-model.md)         | Token Governance Model                  | Accepted | 2026-03-01 |
| [ADR-011](ADR-011-noir-migration.md)                 | Noir ZK Circuit Migration               | Accepted | 2026-03-01 |
| [ADR-012](ADR-012-bridge-plugin-architecture.md)     | Bridge Plugin Architecture              | Accepted | 2026-03-01 |

## ADR Template

```markdown
# ADR-NNN: Title

## Status

Proposed | Accepted | Deprecated | Superseded by ADR-NNN

## Context

What is the issue that we're seeing that is motivating this decision or change?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or more difficult because of this change?
```
