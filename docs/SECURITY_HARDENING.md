# ZASEON Security Hardening Guide

> Summary of all security fixes applied across Phase 1–4 internal audits (February–March 2026).

---

## Table of Contents

- [Overview](#overview)
- [Phase 4 Fixes (Session 9)](#phase-4-fixes-session-9)
- [Phase 3 Fixes (Session 8)](#phase-3-fixes-session-8)
- [Phase 1–2 Summary](#phase-12-summary)
- [Verification](#verification)
- [See Also](#see-also)

---

## Overview

| Phase     | Session | Vulnerabilities | Critical | High   | Medium | Low    |
| --------- | ------- | --------------- | -------- | ------ | ------ | ------ |
| Phase 1   | 1–5     | 26              | 5        | 6      | 15     | 0      |
| Phase 2   | 6–7     | 18              | 2        | 4      | 6      | 6      |
| Phase 3   | 8       | 21              | 4        | 6      | 7      | 4      |
| Phase 4   | 9       | 14              | 3        | 5      | 4      | 2      |
| **Total** |         | **79**          | **14**   | **21** | **32** | **12** |

---

## Phase 4 Fixes (Session 9)

### P4-1: ECDSA Signature Malleability (Critical)

**Contracts**: `CrossChainProofHubV3`, `ZKBoundStateLocks`, `ProofCarryingContainer`

All ECDSA signature recovery now enforces `s < secp256k1n/2` to prevent signature replay with the second valid `s` value.

```solidity
// Before: accepted both s values
(address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);

// After: enforce low-s
bytes32 s;
assembly { s := mload(add(signature, 0x40)) }
require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
    "Invalid signature: s too high");
(address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
```

### P4-2: Value-Based Rate Limiting (High)

**Contract**: `CrossChainProofHubV3`

Rate limiter now tracks both submission count AND cumulative value per hour.

```solidity
// Before: only tracked count
function _checkRateLimit() internal { ... }

// After: tracks count and value
function _checkRateLimit(uint256 count, uint256 value) internal {
    RateWindow storage w = _rateWindows[msg.sender];
    if (block.timestamp > w.windowStart + 1 hours) {
        w.windowStart = block.timestamp;
        w.count = 0;
        w.totalValue = 0;
    }
    w.count += count;
    w.totalValue += value;
    require(w.count <= hourlyCountLimit, "Rate limit: count");
    require(w.totalValue <= hourlyValueLimit, "Rate limit: value");
}
```

### P4-3: ConfirmRoleSeparation Enforcement (High)

**Contracts**: `ProtocolEmergencyCoordinator`, `ZKBoundStateLocks`, `CrossChainProofHubV3`

Previously accepted zero parameters and enforced nothing. Now takes 3 addresses and validates distinctness.

```solidity
// Before
function confirmRoleSeparation() external onlyRole(DEFAULT_ADMIN_ROLE) {
    roleSeparationConfirmed = true;
}

// After
function confirmRoleSeparation(
    address guardian,
    address responder,
    address recovery
) external onlyRole(DEFAULT_ADMIN_ROLE) {
    require(guardian != address(0) && responder != address(0) && recovery != address(0));
    require(guardian != responder && guardian != recovery && responder != recovery);
    roleSeparationConfirmed = true;
    emit RoleSeparationConfirmed(guardian, responder, recovery);
}
```

### P4-4: Arbitrum Outbox Verification (Critical)

**Contract**: `ArbitrumBridgeAdapter`

Previously verified proofs without checking if they were already spent. Now uses `outbox.isSpent(index)`.

```solidity
// Before: manual proof verification only
bytes32[] memory proof = ...;
outbox.executeTransaction(...);

// After: direct spend check
require(!outbox.isSpent(index), "Already spent");
outbox.executeTransaction(...);
```

### P4-5: Cross-Chain Emergency Source Validation (Critical)

**Contract**: `CrossChainEmergencyRelay`

Emergency relays accepted from any source chain. Now validates against active chain registry.

```solidity
// Before: no source validation
function relayEmergency(uint256 sourceChainId, bytes calldata data) external {
    _processEmergency(data);
}

// After: validates source chain is active
function relayEmergency(uint256 sourceChainId, bytes calldata data) external {
    require(chains[sourceChainId].active, "Source chain not active");
    _processEmergency(data);
}
```

### P4-6: Nullifier Sync Replay Protection (High)

**Contract**: `CrossChainNullifierSync`

Added `syncSequence` mapping to prevent replay and ensure ordered processing.

```solidity
// After: ordered sync with replay protection
mapping(uint256 => uint256) public syncSequence; // chainId => lastSequence

function syncNullifier(uint256 sourceChain, uint256 sequence, bytes32 nullifier) external {
    require(sequence == syncSequence[sourceChain] + 1, "Invalid sequence");
    syncSequence[sourceChain] = sequence;
    _registerNullifier(nullifier);
}
```

### P4-7: Staking Overpayment Refund (Medium)

**Contract**: `DecentralizedRelayerRegistry`

Silently absorbed any amount above `MIN_STAKE`. Now refunds the difference.

```solidity
// Before: kept all ETH
function register() external payable {
    require(msg.value >= MIN_STAKE);
    relayers[msg.sender].stake = msg.value;
}

// After: refunds overpayment
function register() external payable {
    require(msg.value >= MIN_STAKE);
    relayers[msg.sender].stake = MIN_STAKE;
    uint256 excess = msg.value - MIN_STAKE;
    if (excess > 0) {
        (bool ok,) = msg.sender.call{value: excess}("");
        require(ok, "Refund failed");
        emit OverpaymentRefunded(msg.sender, excess);
    }
}
```

### P4-8: Batch Nullifier Recovery (High)

**Contract**: `BatchAccumulator`

Failed batches previously left nullifiers in a consumed state, permanently locking them.

```solidity
// After: nullifier recovery on batch failure
function failBatch(bytes32 batchId) internal {
    Batch storage batch = batches[batchId];
    batch.status = BatchStatus.Failed;
    for (uint256 i = 0; i < batch.nullifiers.length; i++) {
        nullifierRegistry.unregister(batch.nullifiers[i]);
        emit NullifierRecovered(batchId, batch.nullifiers[i]);
    }
}
```

### P4-9 through P4-14: Additional Fixes

| ID    | Severity | Contract              | Fix                                               |
| ----- | -------- | --------------------- | ------------------------------------------------- |
| P4-9  | Medium   | `ScrollBridgeAdapter` | Zero-address validation on all 4 config addresses |
| P4-10 | Medium   | `LineaBridgeAdapter`  | Zero-address validation on config addresses       |
| P4-11 | Medium   | `LayerZeroAdapter`    | Peer address validation on `setPeer()`            |
| P4-12 | Low      | `HyperlaneAdapter`    | ISM address validation on `configureDomain()`     |
| P4-13 | Low      | `zkSyncBridgeAdapter` | Diamond proxy address validation                  |
| P4-14 | High     | `IPrivacyPool`        | Added `token` and `relayer` params to interface   |

---

## Phase 3 Fixes (Session 8)

| ID          | Severity | Contract                            | Fix                                          |
| ----------- | -------- | ----------------------------------- | -------------------------------------------- |
| S8-1        | Critical | `UniversalShieldedPool`             | Merkle root ring buffer evicts old roots     |
| S8-2        | Critical | `UniversalShieldedPool`             | `batchVerifier` must be non-zero             |
| S8-3        | Critical | `UniversalShieldedPoolUpgradeable`  | Same `batchVerifier` fix                     |
| S8-4        | Critical | `StealthAddressRegistryUpgradeable` | `canClaimStealth()` aligned with generate    |
| S8-5        | High     | `MultiBridgeRouter`                 | `receive()` function + emergency withdrawal  |
| S8-6        | High     | `MultiBridgeRouter`                 | ETH forwarded to bridge adapters             |
| S8-7        | High     | Bridge adapters (7 contracts)       | `emergencyWithdrawERC20()` added             |
| S8-8        | High     | `NullifierRegistryV3`               | Non-zero `sourceMerkleRoot` required         |
| S8-9        | High     | `ZaseonCrossChainRelay`             | Nullifier binding validation                 |
| S8-10       | Medium   | `VerifierRegistryV2`                | Adapter type-safety                          |
| S8-11–S8-21 | Various  | Multiple contracts                  | Event emissions, config validation, gas opts |

---

## Phase 1–2 Summary

Phases 1 and 2 addressed 44 vulnerabilities (7 Critical, 10 High, 21 Medium, 6 Low) across core contracts including:

- **ReentrancyGuard**: Added to all governance and security contracts
- **Safe ETH Transfers**: Replaced `.transfer()` with `.call{value:}()`
- **Zero-Address Validation**: All critical setters
- **Event Emission**: All configuration changes emit events
- **Loop Gas Optimization**: Array length caching, batch storage writes

See [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md) for complete details.

---

## Verification

```bash
# Run all tests (5,760+ passing)
forge test -vvv

# Run security-focused tests
forge test --match-path "test/security/*" -vvv

# Run fuzz tests (10,000 runs)
forge test --match-contract Fuzz -vvv

# Run Certora formal verification
certoraRun certora/conf/verify.conf

# Static analysis
slither . --config-file slither.config.json

# Validate pre-deploy environment
./scripts/validate-env.sh
```

---

## See Also

- [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md) — Full vulnerability details
- [THREAT_MODEL.md](./THREAT_MODEL.md) — Threat model with all known limitations
- [MAINNET_SECURITY_CHECKLIST.md](./MAINNET_SECURITY_CHECKLIST.md) — Pre-launch checklist
- [INCIDENT_RESPONSE_RUNBOOK.md](./INCIDENT_RESPONSE_RUNBOOK.md) — Emergency procedures

---

_Last updated: March 2026_
