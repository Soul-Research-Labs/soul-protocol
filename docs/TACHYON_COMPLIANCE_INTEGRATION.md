# Tachyon-Inspired Compliance Features — Integration Guide

> **Status**: Phase 1 (Selective Disclosure) & Phase 2 (Privacy Levels + Reporting) — **IMPLEMENTED**

## Overview

Soul Protocol integrates three compliance features inspired by Tachyon's institutional-grade approach,
while preserving ZK-first privacy guarantees — no TEE, no trusted hardware.

| Contract                     | Purpose                                                | Lines | Tests |
| ---------------------------- | ------------------------------------------------------ | ----- | ----- |
| `SelectiveDisclosureManager` | Field-level viewing permissions + audit trail          | ~430  | 39    |
| `ConfigurablePrivacyLevels`  | Per-transaction privacy config + jurisdiction policies | ~310  | 32    |
| `ComplianceReportingModule`  | On-chain compliance reports + ZK attestation           | ~400  | 31    |

**Total: ~1,140 lines of production code, 102 tests (including fuzz tests)**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              ConfidentialStateContainerV3                     │
│  registerState() ──► _registerWithDisclosureManager()        │
└───────────────────────────┬──────────────────────────────────┘
                            │ (optional, non-reverting)
┌───────────────────────────▼──────────────────────────────────┐
│           SelectiveDisclosureManager                          │
│  • registerTransaction / registerTransactionFor               │
│  • grantViewingKey / revokeViewingKey                        │
│  • recordView (audit trail)                                  │
│  • submitComplianceProof → IProofVerifier                    │
└───────────────────────────┬──────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────┐
│           ConfigurablePrivacyLevels                           │
│  • setPrivacyConfig (per commitment)                         │
│  • setDefaultLevel (per user)                                │
│  • jurisdictionPolicies (per country)                        │
│  • feeTiers (per privacy level)                              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│           ComplianceReportingModule                            │
│  • generateReport (time-windowed, encrypted)                  │
│  • verifyReport → IProofVerifier (ZK attestation)            │
│  • recordReportAccess (audit trail)                          │
│  • addReportViewer / removeReportViewer                      │
└──────────────────────────────────────────────────────────────┘
```

---

## 1. SelectiveDisclosureManager

### What It Does

Enables transaction owners to grant field-level viewing permissions
to auditors, regulators, and counterparties — with expiration, revocation,
and on-chain audit trail.

### Key Design Decisions

- **No on-chain encrypted data**: The old implementation stored `encryptedData` and had placeholder `_decryptFields`. This was removed. Decryption happens off-chain; the contract only manages access grants and audit trail.
- **IProofVerifier integration**: Compliance proofs are verified through the standard `IProofVerifier` interface, not a placeholder `proof.length > 0` check.
- **Bounded storage**: Max 50 viewers per transaction, 500 audit entries. Prevents unbounded gas growth.
- **nonReentrant on all mutations**: Every state-changing function is protected.
- **Zero-address validation**: All viewer grants check for `address(0)`.

### Usage

```solidity
// Owner registers a transaction for disclosure
sdm.registerTransaction(txId, commitment, DisclosureLevel.NONE);

// Grant viewing key to auditor (expires in 30 days, field-level access)
FieldType[] memory fields = new FieldType[](2);
fields[0] = FieldType.AMOUNT;
fields[1] = FieldType.SENDER;
sdm.grantViewingKey(txId, auditorAddress, DisclosureLevel.AUDITOR, 30 days, fields);

// Auditor records their view (off-chain decryption, on-chain audit trail)
sdm.recordView(txId, fields); // reverts if unauthorized/expired

// Submit ZK compliance proof
sdm.submitComplianceProof(txId, proof, publicInputs);
```

### Integration with ConfidentialStateContainerV3

When a `disclosureManager` is configured via `setDisclosureManager()`, every
`registerState()` call **optionally** calls `registerTransactionFor()` on the
disclosure manager. This is wrapped in `try/catch` — failure never blocks
state registration.

```solidity
// Admin configures (one-time)
container.setDisclosureManager(address(sdm));

// Now every registerState() automatically tracks in SDM
```

---

## 2. ConfigurablePrivacyLevels

### What It Does

Allows users to choose per-transaction privacy levels, with admin-configurable
jurisdiction policies and fee tiers.

### Privacy Levels

| Level       | Metadata             | Auditor | Fee  |
| ----------- | -------------------- | ------- | ---- |
| MAXIMUM     | None                 | No      | 1.5x |
| HIGH        | Encrypted hash       | No      | 1.2x |
| MEDIUM      | Selective disclosure | No      | 1.0x |
| COMPLIANT   | Mandatory disclosure | Yes     | 0.8x |
| TRANSPARENT | Public               | Yes     | 0.5x |

### Usage

```solidity
// User sets privacy level for a commitment
cpl.setPrivacyConfig(commitment, PrivacyLevel.COMPLIANT, metadataHash, 365 days);

// User sets their default level
cpl.setDefaultLevel(PrivacyLevel.HIGH);

// Admin enforces jurisdiction policy
cpl.setJurisdictionPolicy("US", PrivacyLevel.COMPLIANT, PrivacyLevel.TRANSPARENT, 5 years);

// Check effective level
PrivacyLevel level = cpl.getEffectiveLevel(commitment, owner);
```

---

## 3. ComplianceReportingModule

### What It Does

Generates on-chain compliance reports covering time-windowed transaction sets.
Reports can be ZK-verified (proving compliance without revealing data),
and access is tracked with an immutable audit trail.

### Report Lifecycle

```
DRAFT → SUBMITTED → VERIFIED (ZK proof)
  │                     │
  └─────────────────────┴──→ REVOKED
                              │
                              └──→ EXPIRED (auto, based on retention period)
```

### Usage

```solidity
// Compliance officer generates a report
address[] memory viewers = new address[](1);
viewers[0] = regulatorAddress;

bytes32 reportId = crm.generateReport(
    entityAddress,
    ReportType.TRANSACTION_SUMMARY,
    periodStart,
    periodEnd,
    reportHash,    // hash of encrypted report (stored off-chain)
    txCount,
    viewers
);

// Verify with ZK proof
crm.verifyReport(reportId, proof, publicInputs);

// Regulator records access
crm.recordReportAccess(reportId, accessProof);
```

---

## Deployment

```bash
# Testnet (deployer acts as all roles)
forge script scripts/deploy/DeployComplianceSuite.s.sol:DeployComplianceSuiteTestnet \
  --rpc-url $RPC_URL --broadcast

# Production (with separate admin and verifier)
COMPLIANCE_ADMIN=0x... COMPLIANCE_VERIFIER=0x... \
forge script scripts/deploy/DeployComplianceSuite.s.sol:DeployComplianceSuite \
  --rpc-url $RPC_URL --broadcast --verify
```

---

## Security Considerations

1. **No placeholder verification**: All proof verification goes through `IProofVerifier`. No `proof.length > 0` shortcuts.
2. **Bounded arrays**: Viewer lists (50), audit trails (500/200), batch operations (50) — all bounded.
3. **ReentrancyGuard**: All state-changing external functions are nonReentrant.
4. **Zero-address checks**: All critical setters validate against address(0).
5. **Non-reverting integration**: CSCv3 → SDM call uses try/catch — compliance failures never block core protocol.
6. **AccessControl**: All admin functions gated by role-based access.

---

## What Was Learned From Tachyon (Reference)

See [docs/TACHYON_LEARNINGS.md](TACHYON_LEARNINGS.md) for the complete analysis.

**Key insight**: Tachyon's compliance-first design attracts institutions.
Soul's approach adds compliance as an **optional layer** on top of ZK privacy —
never compromising the cryptographic foundation.

**Implemented from Tachyon**:

1. Programmable viewing permissions (SelectiveDisclosureManager)
2. Configurable privacy levels (ConfigurablePrivacyLevels)
3. Enterprise compliance reporting (ComplianceReportingModule)
4. Intent-based architecture with solver networks (IntentSettlementLayer) — **NEW**
5. Instant settlement guarantees with solver-backed bonds (InstantSettlementGuarantee + InstantRelayerRewards) — **NEW**
6. Dynamic routing orchestration (DynamicRoutingOrchestrator) — **NEW**
7. Privacy ↔ Compliance bridge (CrossChainPrivacyHub compliance hooks) — **NEW**

All 7 Tachyon learnings are now implemented, wired into SoulProtocolHub (22 components),
and covered by integration tests, invariant/fuzz tests, and SDK clients.

---

## Test Coverage

```bash
# Run compliance tests only
forge test --match-path "test/compliance/*" -vv

# Run with fuzz iterations
forge test --match-path "test/compliance/*" --fuzz-runs 10000

# Full regression
forge test --no-match-path "test/stress/*" --summary
```

| Test Suite                 | Tests   | Fuzz Tests |
| -------------------------- | ------- | ---------- |
| SelectiveDisclosureManager | 39      | 3          |
| ConfigurablePrivacyLevels  | 32      | 3          |
| ComplianceReportingModule  | 31      | 2          |
| SoulComplianceV2           | 36      | 0          |
| CrossChainSanctionsOracle  | 10      | 0          |
| **Total**                  | **148** | **8**      |
