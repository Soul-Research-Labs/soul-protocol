# ADR-009: Compliance Oracle Architecture

## Status

Accepted

## Date

2026-03-01

## Context

ZASEON must support regulatory compliance without compromising user privacy. Specific requirements:

1. **Sanctions screening**: Block transfers to/from OFAC-sanctioned addresses
2. **Accredited investor verification**: Gate access to certain pools
3. **Selective disclosure**: Allow users to prove compliance without revealing balances
4. **Jurisdictional flexibility**: Different rules per jurisdiction

Key tension: privacy-preserving transfers must still comply with AML/CFT regulations.

## Decision

Implement a **modular compliance layer** with on-chain oracles and ZK-based selective disclosure.

### Components

- `CrossChainSanctionsOracle`: Aggregates sanctions lists, queryable by contracts
- `SelectiveDisclosureController`: Processes ZK proofs of compliance
- `ComplianceReporting`: Generates audit-ready reports from disclosed data
- `PolicyEngine`: Configurable per-jurisdiction rules

### ZK compliance proofs

Users prove compliance without revealing sensitive data:

- **Sanctions proof**: "My address is NOT on list L" (Merkle non-membership)
- **Accredited investor**: "My verified balance > $X" (range proof)
- **Source of funds**: "Funds originated from whitelisted protocol" (path proof)

### Oracle design

- Sanctions data updated by authorized `ORACLE_OPERATOR` role
- Merkle root of sanctioned addresses stored on-chain
- Proof of non-membership verified in ZK circuit
- Cross-chain: sanctions root propagated via bridge adapters

### Rationale

- **ZK compliance**: Users prove compliance without revealing identity to smart contracts
- **Modular policies**: Jurisdictions can configure different rules without code changes
- **Oracle pattern**: Separates data sourcing from enforcement logic
- **Selective disclosure**: Viewing key sharing enables auditor access without on-chain exposure

## Consequences

- Compliance is opt-in per pool/route (pools can require compliance proofs)
- Oracle updates require multi-sig authorization
- ZK circuits for compliance add ~15k constraints per proof
- Sanctions list updates propagate cross-chain within bridge finality window
- SDK provides `ComplianceClient` for proof generation
