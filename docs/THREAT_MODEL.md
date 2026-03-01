# ZASEON (Zaseon) Threat Model

## Document Information

| Field          | Value      |
| -------------- | ---------- |
| Version        | 2.0.0      |
| Last Updated   | 2026-02-01 |
| Status         | Active     |
| Classification | Public     |

---

## 1. Executive Summary

This document provides a comprehensive threat model for the ZASEON (Zaseon), a cross-chain privacy infrastructure enabling confidential state management and zero-knowledge proof verification across multiple blockchain networks.

## 2. System Overview

### 2.1 Architecture Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Zaseon Core Infrastructure                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Confidential    │  │  Nullifier      │  │  ZK-Bound       │  │
│  │ State Container │  │  Registry       │  │  State Locks    │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                    │            │
│  ┌────────▼────────────────────▼────────────────────▼────────┐  │
│  │              Cross-Chain Proof Hub                         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                   ┌────────▼────────┐                           │
│                   │  Groth16 (BN254)│                           │
│                   │  Verifier       │                           │
│                   └─────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Trust Boundaries

1. **Smart Contract Layer** - On-chain, verified, immutable
2. **Proof Generation** - Off-chain, trusted client environment
3. **Cross-Chain Messaging** - External bridge protocols
4. **User Interface** - Client applications

---

## 3. Threat Actors

### 3.1 External Attackers

| Actor                       | Motivation               | Capability                        | Risk Level |
| --------------------------- | ------------------------ | --------------------------------- | ---------- |
| **Opportunistic Hackers**   | Financial gain           | Script-level attacks              | Medium     |
| **Sophisticated Attackers** | Large-scale theft        | Custom exploits, MEV              | High       |
| **Nation-State Actors**     | Surveillance, disruption | Quantum computing, vast resources | Critical   |
| **Competitors**             | Market disruption        | Funded security research          | Medium     |

### 3.2 Internal Threats

| Actor                      | Motivation        | Capability           | Risk Level |
| -------------------------- | ----------------- | -------------------- | ---------- |
| **Malicious Developers**   | Backdoors, theft  | Code access          | High       |
| **Compromised Admin Keys** | Protocol takeover | Admin functions      | Critical   |
| **Rogue Relayers**         | Fee extraction    | Transaction ordering | Medium     |

---

## 4. Attack Vectors & Mitigations

### 4.1 Smart Contract Vulnerabilities

#### 4.1.1 Reentrancy Attacks

**Threat**: Recursive calls to drain funds or manipulate state.

**Affected Components**:

- `ZaseonAtomicSwapV2.sol`
- `ConfidentialStateContainerV3.sol`
- `ZaseonUpgradeTimelock.sol`
- `BridgeWatchtower.sol`
- `ZaseonProtocolHub.sol`
- `ZaseonL2Messenger.sol`

**Mitigations**:

- ✅ ReentrancyGuard on all external state-changing functions
- ✅ Checks-Effects-Interactions pattern
- ✅ Pull-over-push payment patterns
- ✅ Replaced deprecated `.transfer()` with `.call{value:}()`

**Code Reference**:

```solidity
function registerState(...) external nonReentrant whenNotPaused {
    // Checks
    require(!commitmentExists[commitment], "Duplicate commitment");

    // Effects
    commitmentExists[commitment] = true;
    nullifierUsed[nullifier] = true;

    // Interactions
    emit StateRegistered(commitment, nullifier);
}
```

#### 4.1.2 Integer Overflow/Underflow

**Threat**: Arithmetic errors leading to incorrect state calculations.

**Mitigations**:

- ✅ Solidity 0.8.24 with built-in overflow checks
- ✅ LLVM-safe bit operations in ZK-SLocks
- ✅ Explicit bounds checking on array indices

**LLVM-Safe Implementation**:

```solidity
// Prevents LLVM optimization issues
function safeBitRotate(uint256 value, uint256 shift) internal pure returns (uint256) {
    require(shift < 256, "Shift overflow");
    return (value << shift) | (value >> (256 - shift));
}
```

#### 4.1.3 Access Control Bypass

**Threat**: Unauthorized access to admin functions.

**Affected Components**:

- All pausable contracts
- Role-based access control systems

**Mitigations**:

- ✅ OpenZeppelin AccessControl
- ✅ Role hierarchy with separation of duties
- ✅ Time-locked admin operations via ZaseonTimelock

**Role Structure**:

```
DEFAULT_ADMIN_ROLE
    ├── PAUSER_ROLE
    ├── UPGRADER_ROLE
    ├── OPERATOR_ROLE
    └── GUARDIAN_ROLE
```

### 4.2 Cryptographic Vulnerabilities

#### 4.2.1 Proof Forgery

**Threat**: Creating valid-looking proofs without knowing secrets.

**Mitigations**:

- ✅ Groth16 verifier (BN254) using EVM precompiles
- ✅ Input validation before verification
- ✅ Trusted setup ceremony with secure parameters

**Verification Flow**:

```
User Proof → Input Validation → Curve Check → Pairing Verification → Result
```

#### 4.2.2 Nullifier Grinding

**Threat**: Precomputing nullifiers to front-run or replay transactions.

**Mitigations**:

- ✅ Nullifier bound to commitment and user address
- ✅ Domain separation via CrossDomainNullifierAlgebra
- ✅ Randomness requirements in proof generation

**Nullifier Construction**:

```solidity
bytes32 nullifier = keccak256(abi.encodePacked(
    commitment,
    userSecret,
    domainSeparator,
    blockHash  // Adds entropy
));
```

#### 4.2.3 Weak Randomness

**Threat**: Predictable random values enabling proof manipulation.

**Mitigations**:

- ✅ User-provided entropy required in ZK-SLocks
- ✅ VDF-based randomness beacon (planned)
- ✅ Commit-reveal schemes for sensitive operations

### 4.3 Cross-Chain Attacks

#### 4.3.1 Bridge Exploitation

**Threat**: Exploiting bridge protocols to forge cross-chain proofs.

**Mitigations**:

- ✅ Multi-source proof verification
- ✅ Chain-specific domain separators
- ✅ Finality requirements before proof acceptance

**Chain Verification**:

```solidity
mapping(uint256 => bool) public supportedChains;
mapping(uint256 => uint256) public chainFinalityBlocks;

function submitCrossChainProof(...) external {
    require(supportedChains[sourceChainId], "Unsupported chain");
    require(blockConfirmations >= chainFinalityBlocks[sourceChainId], "Insufficient finality");
    // ...
}
```

#### 4.3.2 Replay Attacks

**Threat**: Replaying proofs across chains or after state changes.

**Mitigations**:

- ✅ Chain ID in proof public inputs
- ✅ Nonce tracking per user per chain
- ✅ Nullifier consumption prevents replay
- ✅ (Session 8) NullifierRegistryV3 requires non-zero `sourceMerkleRoot` for cross-chain nullifiers
- ✅ (Session 8) `completeRelay()` validates nullifier binding matches relay transfer

### 4.4 Economic Attacks

#### 4.4.1 Front-Running

**Threat**: MEV bots extracting value from pending transactions.

**Mitigations**:

- ✅ Commit-reveal for sensitive operations
- ✅ Private mempool integration support
- ✅ Time-locked execution windows

#### 4.4.2 Griefing Attacks

**Threat**: DoS by submitting many low-value transactions.

**Mitigations**:

- ✅ Rate limiting via RateLimiter contract
- ✅ Minimum stake requirements for relayers
- ✅ Batch operation limits (max 100 items)

**Rate Limiting**:

```solidity
uint256 public constant MAX_OPS_PER_BLOCK = 100;
mapping(address => uint256) public lastOpBlock;
mapping(address => uint256) public opsInBlock;

modifier rateLimited() {
    if (lastOpBlock[msg.sender] == block.number) {
        require(opsInBlock[msg.sender] < MAX_OPS_PER_BLOCK, "Rate limit");
        opsInBlock[msg.sender]++;
    } else {
        lastOpBlock[msg.sender] = block.number;
        opsInBlock[msg.sender] = 1;
    }
    _;
}
```

### 4.5 Operational Attacks

#### 4.5.1 Private Key Compromise

**Threat**: Admin or user private keys stolen.

**Mitigations**:

- ✅ Multi-sig requirements (EmergencyRecovery)
- ✅ Timelock delays for critical operations
- ✅ Guardian system with threshold signatures

**Emergency Recovery Structure**:

```
Emergency Action → Guardian Signatures (M of N) → Timelock (24-72h) → Execution
```

#### 4.5.2 Upgrade Attacks

**Threat**: Malicious contract upgrades.

**Mitigations**:

- ✅ UUPS proxy pattern with access control
- ✅ Storage layout verification (StorageLayoutReport)
- ✅ Governance approval required

---

## 5. Risk Matrix

| Threat                | Likelihood | Impact   | Risk Score | Status                  |
| --------------------- | ---------- | -------- | ---------- | ----------------------- |
| Reentrancy            | Low        | High     | Medium     | ✅ Mitigated            |
| Proof Forgery         | Very Low   | Critical | Medium     | ✅ Mitigated            |
| Access Control Bypass | Low        | Critical | High       | ✅ Mitigated            |
| Front-Running         | High       | Medium   | High       | ⚠️ Partially Mitigated  |
| Bridge Exploitation   | Medium     | Critical | High       | ✅ Mitigated            |
| Key Compromise        | Medium     | Critical | Critical   | ✅ Mitigated            |
| Griefing/DoS          | High       | Low      | Medium     | ✅ Mitigated            |
| Quantum Attack        | Very Low   | Critical | Low        | ⚠️ Future Consideration |

---

## 6. Security Controls Summary

### 6.1 Preventive Controls

| Control          | Implementation               | Coverage                  |
| ---------------- | ---------------------------- | ------------------------- |
| Access Control   | OpenZeppelin RBAC            | All contracts             |
| Reentrancy Guard | OpenZeppelin ReentrancyGuard | State-changing functions  |
| Pause Mechanism  | OpenZeppelin Pausable        | All critical contracts    |
| Input Validation | Custom checks                | All external functions    |
| Rate Limiting    | RateLimiter contract         | High-frequency operations |

### 6.2 Detective Controls

| Control         | Implementation              | Coverage          |
| --------------- | --------------------------- | ----------------- |
| Event Logging   | Comprehensive events        | All state changes |
| Monitoring      | Event logging + OZ Defender | System-wide       |
| Static Analysis | Slither                     | All contracts     |
| Fuzzing         | Echidna harnesses           | Core contracts    |

### 6.3 Corrective Controls

| Control           | Implementation  | Coverage               |
| ----------------- | --------------- | ---------------------- |
| Emergency Pause   | Owner-triggered | All pausable contracts |
| Guardian Recovery | Multi-sig       | Critical operations    |
| Timelock          | ZaseonTimelock  | Admin functions        |
| Upgradability     | UUPS Proxy      | Upgradeable contracts  |

---

## 7. Incident Response Triggers

The following conditions should trigger immediate incident response:

1. **Critical**: Unexpected token transfers > $100,000
2. **Critical**: Multiple failed proof verifications in short period
3. **High**: Admin role changes without governance approval
4. **High**: Contract pause triggered by non-owner
5. **Medium**: Rate limit thresholds exceeded by 10x
6. **Medium**: Cross-chain proof submission from unsupported chain

---

## 8. Recommendations

### 8.1 Immediate Actions

1. ✅ Complete formal verification with Certora
2. ✅ Conduct external security audit
3. ⬜ Implement monitoring dashboard
4. ⬜ Bug bounty program launch

### 8.2 Short-term (1-3 months)

1. ⬜ MEV protection integration
2. ⬜ Multi-chain deployment hardening
3. ⬜ Incident response drill

### 8.3 Long-term (6-12 months)

1. ⬜ Advanced cryptographic research (signature schemes, hash functions)
2. ⬜ Decentralized governance activation
3. ⬜ Cross-chain bridge diversity

---

## 8.4 Known Limitations

| Component                | Description                                                                                                                                                                                             | Severity      | Status                                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | --------------------------------------------- |
| Ring Signature Verifier  | `RingSignatureVerifier.sol` implements BN254 CLSAG ring signature verification using EVM precompiles (ecAdd, ecMul, modExp). Integrated with `GasOptimizedPrivacy.sol`. Gas cost: ~26k per ring member. | Informational | Resolved — production CLSAG verifier deployed |
| Noir Circuit Compilation | All 20 Noir circuits compile successfully after February 2026 migration from external `poseidon` crate to `std::hash::poseidon::bn254`. Existing 8 generated Solidity verifiers remain valid.           | Informational | Resolved — see `noir/README.md`               |
| Batch Verifier Bypass    | `insertCrossChainCommitments()` previously skipped verification when `batchVerifier == address(0)`. Now requires non-zero batch verifier.                                                               | Critical      | Resolved — Session 8 (S8-2/S8-3)              |
| Historical Root Growth   | `UniversalShieldedPool` Merkle root ring buffer never evicted old roots from `historicalRoots`, allowing unbounded set growth. Now evicts on overwrite.                                                 | Critical      | Resolved — Session 8 (S8-1)                   |
| ETH Trapped in Router    | `MultiBridgeRouter` accepted `msg.value` but never forwarded to bridge adapters. ETH is now forwarded; emergency withdrawal added.                                                                      | High          | Resolved — Session 8 (S8-5/S8-6)              |
| Stealth Derivation       | `canClaimStealth()` used different derivation than `generateStealthAddress()`. Now aligned with 4-parameter signature.                                                                                  | Critical      | Resolved — Session 8 (S8-4)                   |

---

## 9. Appendix

### 9.1 Security Tool Results

| Tool               | Findings          | Critical | High | Medium | Low |
| ------------------ | ----------------- | -------- | ---- | ------ | --- |
| Slither            | 9 (all addressed) | 0        | 0    | 2      | 7   |
| Foundry Tests      | 5,600+            | N/A      | N/A  | N/A    | N/A |
| Fuzz Tests         | 300+              | N/A      | N/A  | N/A    | N/A |
| Halmos Symbolic    | 12 checks         | N/A      | N/A  | N/A    | N/A |
| Echidna Properties | 6 invariants      | N/A      | N/A  | N/A    | N/A |
| K Framework        | 5 specs           | N/A      | N/A  | N/A    | N/A |
| TLA+ Model Check   | 4 properties      | N/A      | N/A  | N/A    | N/A |
| Certora CVL        | 80+ specs         | N/A      | N/A  | N/A    | N/A |
| Internal Audit S8  | 21                | 4        | 6    | 7      | 4   |

### 9.2 Contact Information

- **Security Team**: security@zaseon.network
- **Bug Bounty**: bounty@zaseon.network
- **Emergency**: emergency@zaseon.network

---

_This threat model should be reviewed and updated quarterly or after any significant protocol changes._
