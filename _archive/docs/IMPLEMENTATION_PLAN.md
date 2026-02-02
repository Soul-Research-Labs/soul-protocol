# Soul Protocol - Improvement Implementation Plan

> **Document Version:** 1.0  
> **Created:** February 1, 2026  
> **Target Completion:** Q2 2026

---

## Executive Summary

This document outlines a comprehensive implementation plan to address four key improvement areas:

| Priority | Issue | Impact | Effort | Timeline |
|----------|-------|--------|--------|----------|
| P0 | Coverage Challenges | High | Medium | 4 weeks |
| P1 | PQC Precompile Dependencies | High | High | 8 weeks |
| P2 | NatSpec Documentation | Medium | Low | 3 weeks |
| P3 | Governance Organization | Low | Low | 1 week |

**Total Estimated Timeline:** 12 weeks (with parallelization)

---

## Issue 1: Coverage Challenges (P0)

### Current State
- Forge coverage fails with "stack too deep" errors in complex ZK verifier contracts
- ~50 contracts require stub replacements for coverage to run
- Current workaround: `scripts/run_coverage.py` swaps contracts with stubs
- Actual test coverage is unknown due to tooling limitations

### Root Cause Analysis
1. **Complex Assembly Blocks**: Verifier contracts (Groth16, PLONK, FRI) use heavy assembly
2. **Deep Call Stacks**: ZK verification pipelines chain multiple verifier calls
3. **Foundry Limitation**: Coverage instrumentation adds stack overhead
4. **IR Pipeline**: Even with `via_ir = true`, stack limits hit during instrumentation

### Implementation Plan

#### Phase 1: Contract Refactoring (Week 1-2)

**1.1 Identify High-Priority Contracts**
```bash
# Create priority list based on contract importance
contracts/primitives/ZKBoundStateLocks.sol      # Core - MUST have coverage
contracts/bridge/CrossChainProofHubV3.sol       # Core - MUST have coverage
contracts/privacy/UnifiedNullifierManager.sol   # Core - MUST have coverage
contracts/core/ConfidentialStateContainerV3.sol # Core - MUST have coverage
```

**1.2 Refactor for Stack Depth Reduction**
- Extract large inline functions to internal libraries
- Split monolithic functions into smaller composable units
- Use struct packing to reduce local variable count
- Move verification logic to separate helper contracts

**Example Refactoring Pattern:**
```solidity
// BEFORE: All logic in one contract (stack overflow)
contract ZKBoundStateLocks {
    function unlock(UnlockProof memory proof) external {
        // 50+ local variables, deep assembly
    }
}

// AFTER: Split into composable modules
contract ZKBoundStateLocks {
    ZKSLocksValidator internal validator;
    ZKSLocksStorage internal lockStorage;
    
    function unlock(UnlockProof memory proof) external {
        validator.validateProof(proof);
        lockStorage.executeUnlock(proof.lockId);
    }
}
```

**1.3 Create `contracts/internal/` Directory**
```
contracts/internal/
├── validators/
│   ├── ProofValidator.sol
│   ├── NullifierValidator.sol
│   └── CommitmentValidator.sol
├── storage/
│   ├── LockStorage.sol
│   └── StateStorage.sol
└── helpers/
    ├── StackOptimizedHelper.sol
    └── VerifierProxy.sol
```

#### Phase 2: Alternative Coverage Solutions (Week 2-3)

**2.1 Implement Targeted Coverage via Hardhat**
```javascript
// hardhat.config.ts
module.exports = {
  solidity: {
    compilers: [
      {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 200 },
          viaIR: false, // Disable IR for coverage compatibility
        },
      },
    ],
  },
  paths: {
    sources: "./contracts-coverage", // Separate source tree
  },
};
```

**2.2 Create Coverage-Compatible Contract Wrappers**
```
contracts-coverage/
├── ZKBoundStateLocksTestable.sol      # Inherits + exposes internals
├── CrossChainProofHubTestable.sol
└── verifiers/
    └── MockVerifierForCoverage.sol     # Deterministic mock responses
```

**2.3 Implement Dual-Mode Verifiers**
```solidity
// contracts/verifiers/DualModeVerifier.sol
abstract contract DualModeVerifier {
    bool public immutable COVERAGE_MODE;
    
    constructor(bool coverageMode) {
        COVERAGE_MODE = coverageMode;
    }
    
    function verify(bytes calldata proof) external returns (bool) {
        if (COVERAGE_MODE) {
            return _mockVerify(proof);
        }
        return _realVerify(proof);
    }
    
    function _mockVerify(bytes calldata) internal pure returns (bool) {
        return true; // Simplified for coverage
    }
    
    function _realVerify(bytes calldata proof) internal virtual returns (bool);
}
```

#### Phase 3: Comprehensive Test Enhancement (Week 3-4)

**3.1 Branch Coverage Analysis Script**
```python
# scripts/analyze_coverage.py
"""
Analyzes uncovered branches and generates targeted test recommendations.
"""

def identify_uncovered_branches():
    # Parse LCOV output
    # Map to source locations
    # Generate test recommendations
    pass
```

**3.2 Create Coverage CI Pipeline**
```yaml
# .github/workflows/coverage.yml
name: Coverage Analysis

on: [push, pull_request]

jobs:
  coverage-core:
    runs-on: ubuntu-latest
    steps:
      - name: Run Core Coverage
        run: |
          python scripts/run_coverage.py --report=lcov
          
      - name: Upload to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: lcov.info
          
  coverage-security:
    runs-on: ubuntu-latest
    steps:
      - name: Run Security Coverage
        run: |
          forge coverage --match-path "contracts/security/*" --report lcov
```

**3.3 Coverage Tracking Dashboard**
Create `docs/COVERAGE.md`:
```markdown
# Coverage Tracking

## Core Contracts (Target: 95%)
| Contract | Line | Branch | Status |
|----------|------|--------|--------|
| ZKBoundStateLocks | 87% | 82% | 🟡 |
| CrossChainProofHubV3 | 91% | 88% | 🟢 |

## Alternative Verification
| Method | Coverage Equivalent |
|--------|---------------------|
| Fuzz Tests | 10,000 runs/function |
| Invariant Tests | 256 runs, depth 128 |
| Certora Specs | 38 properties verified |
| Halmos | Symbolic execution pass |
```

### Deliverables
- [ ] Refactored contracts with reduced stack depth
- [ ] `contracts/internal/` library structure
- [ ] `contracts-coverage/` testable wrappers
- [ ] `scripts/analyze_coverage.py` analysis tool
- [ ] `.github/workflows/coverage.yml` CI pipeline
- [ ] `docs/COVERAGE.md` tracking documentation

---

## Issue 2: PQC Precompile Dependencies (P1)

### Current State
- `DilithiumVerifier.sol` uses mock mode (`useMockVerification = true`)
- `KyberKEM.sol` uses mock mode (`useMockMode = true`)
- `SPHINCSPlusVerifier.sol` uses mock mode
- No EVM precompiles exist for post-quantum cryptography (as of Feb 2026)

### Security Implications
- Mock mode provides **zero cryptographic security**
- Production deployment with mocks = critical vulnerability
- Transition to real verification requires careful orchestration

### Implementation Plan

#### Phase 1: Pure Solidity PQC Libraries (Week 1-4)

**1.1 Implement Dilithium in Solidity**
```solidity
// contracts/pqc/lib/DilithiumCore.sol
library DilithiumCore {
    // NTT operations for polynomial multiplication
    function ntt(int16[] memory a) internal pure returns (int16[] memory) {
        // Implementation based on NIST reference
    }
    
    // Signature verification without precompile
    function verifySignature(
        bytes memory publicKey,
        bytes memory message,
        bytes memory signature
    ) internal pure returns (bool) {
        // Full Dilithium3 verification in Solidity
        // Gas cost: ~5-10M gas (expensive but functional)
    }
}
```

**1.2 Implement Kyber in Solidity**
```solidity
// contracts/pqc/lib/KyberCore.sol
library KyberCore {
    function decapsulate(
        bytes memory ciphertext,
        bytes memory secretKey
    ) internal pure returns (bytes32 sharedSecret) {
        // Full Kyber768 decapsulation
    }
}
```

**1.3 Create Hybrid Verification Strategy**
```solidity
// contracts/pqc/HybridPQCVerifier.sol
contract HybridPQCVerifier {
    enum VerificationMode {
        MOCK,           // Testing only
        PURE_SOLIDITY,  // Expensive but functional
        PRECOMPILE,     // Future: when EIP lands
        OFFCHAIN_ZK     // ZK proof of PQC verification
    }
    
    VerificationMode public mode;
    
    function verify(
        bytes memory publicKey,
        bytes memory message,
        bytes memory signature
    ) external returns (bool) {
        if (mode == VerificationMode.PURE_SOLIDITY) {
            return DilithiumCore.verifySignature(publicKey, message, signature);
        } else if (mode == VerificationMode.OFFCHAIN_ZK) {
            // Verify ZK proof that off-chain verification passed
            return _verifyZKProof(publicKey, message, signature);
        }
        // ...
    }
}
```

#### Phase 2: Off-Chain ZK Verification (Week 4-6)

**2.1 Create Noir Circuit for PQC Verification**
```
noir/pqc_verifier/src/main.nr
```
```rust
// Verify Dilithium signature in ZK circuit
fn verify_dilithium(
    public_key: [u8; 1952],
    message_hash: Field,
    signature: [u8; 3293]
) -> pub bool {
    // Dilithium verification in Noir
    // Generate succinct proof of verification
}
```

**2.2 Integration Architecture**
```
┌──────────────────────────────────────────────────────────────┐
│                    PQC Verification Flow                      │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. User signs with Dilithium     ─────────────────────┐    │
│                                                        │    │
│  2. Off-chain prover verifies                          │    │
│     └── Generates ZK proof of verification             │    │
│                                                        ▼    │
│  3. On-chain contract verifies ZK proof only      ┌────────┐│
│     └── ~300K gas vs 10M for direct verification  │ Verify ││
│                                                   └────────┘│
└──────────────────────────────────────────────────────────────┘
```

**2.3 SDK Integration**
```typescript
// sdk/src/pqc/dilithium.ts
export class DilithiumSigner {
  async signAndProve(message: Uint8Array): Promise<{
    signature: Uint8Array;
    zkProof: Uint8Array;
  }> {
    const signature = await this.sign(message);
    const zkProof = await this.generateVerificationProof(
      this.publicKey,
      message,
      signature
    );
    return { signature, zkProof };
  }
}
```

#### Phase 3: Production Hardening (Week 6-8)

**3.1 Mode Transition Guards**
```solidity
// contracts/pqc/PQCModeController.sol
contract PQCModeController is AccessControl {
    event ModeTransition(VerificationMode from, VerificationMode to);
    
    // Timelock for mode changes (72 hours)
    uint256 public constant MODE_CHANGE_DELAY = 72 hours;
    
    function requestModeChange(VerificationMode newMode) external onlyRole(ADMIN_ROLE) {
        require(newMode != VerificationMode.MOCK, "Cannot switch to mock");
        // Queue mode change with timelock
    }
}
```

**3.2 Add Certora Specs for PQC Mode**
```cvl
// certora/specs/PQCModeSafety.spec
rule mockModeCannotBeReEnabled {
    env e;
    VerificationMode modeBefore = currentMode();
    
    // After leaving mock mode, cannot return
    require modeBefore != VerificationMode.MOCK;
    
    transitionMode(e, _);
    
    assert currentMode() != VerificationMode.MOCK;
}
```

**3.3 Deployment Configuration**
```typescript
// scripts/deploy/pqc-config.ts
export const PQC_DEPLOYMENT_CONFIG = {
  testnet: {
    mode: "MOCK",
    warning: "DO NOT USE IN PRODUCTION",
  },
  staging: {
    mode: "PURE_SOLIDITY",
    gasLimit: 15_000_000,
  },
  mainnet: {
    mode: "OFFCHAIN_ZK",
    proverEndpoint: "https://prover.soul.network",
    fallback: "PURE_SOLIDITY",
  },
};
```

### Deliverables
- [ ] `contracts/pqc/lib/DilithiumCore.sol` - Pure Solidity implementation
- [ ] `contracts/pqc/lib/KyberCore.sol` - Pure Solidity implementation
- [ ] `contracts/pqc/HybridPQCVerifier.sol` - Multi-mode verifier
- [ ] `noir/pqc_verifier/` - ZK circuit for PQC verification
- [ ] `contracts/pqc/PQCModeController.sol` - Safe mode transitions
- [ ] `certora/specs/PQCModeSafety.spec` - Formal verification
- [ ] `sdk/src/pqc/` - SDK integration
- [ ] `docs/POST_QUANTUM_DEPLOYMENT.md` - Deployment guide

---

## Issue 3: NatSpec Documentation (P2)

### Current State
- Core contracts have good documentation (e.g., `ZKBoundStateLocks.sol`)
- Some contracts lack `@param` and `@return` annotations
- Several utility contracts have minimal NatSpec
- Inconsistent documentation style across modules

### Gap Analysis
```bash
# Contracts with insufficient NatSpec
contracts/crosschain/*.sol          # ~40% documented
contracts/security/*.sol            # ~60% documented
contracts/fhe/*.sol                 # ~50% documented
contracts/mpc/*.sol                 # ~30% documented
contracts/relayer/*.sol             # ~45% documented
```

### Implementation Plan

#### Phase 1: Documentation Standards (Week 1)

**1.1 Create NatSpec Style Guide**
```markdown
# docs/NATSPEC_STYLE_GUIDE.md

## Required Elements

### Contracts
- `@title` - Contract name
- `@author` - "Soul Protocol"
- `@notice` - User-facing description
- `@dev` - Developer notes (architecture, integrations)
- `@custom:security-contact` - security@soul.network

### Functions
- `@notice` - What it does (user-facing)
- `@dev` - How it works (developer notes)
- `@param` - Every parameter
- `@return` - Every return value
- `@custom:security` - Security considerations

### Events
- `@notice` - When emitted
- `@param` - Every indexed and non-indexed parameter

### Example
```solidity
/**
 * @notice Locks confidential state for cross-chain transfer
 * @dev Creates ZK-bound lock that can only be unlocked with valid proof.
 *      Integrates with CDNA for nullifier generation.
 * @param commitment The Poseidon hash of the confidential state
 * @param transitionHash Hash of the allowed state transition circuit
 * @param deadline Unix timestamp after which lock expires
 * @return lockId Unique identifier for the created lock
 * @custom:security Caller must be state owner or approved operator
 */
function createLock(
    bytes32 commitment,
    bytes32 transitionHash,
    uint256 deadline
) external returns (bytes32 lockId);
```
```

**1.2 Create Linting Rules**
```javascript
// .solhint.json additions
{
  "rules": {
    "natspec-author": "warn",
    "natspec-title": "error",
    "natspec-notice": "error",
    "natspec-dev": "warn",
    "natspec-param": "error",
    "natspec-return": "error"
  }
}
```

#### Phase 2: Automated Documentation Generation (Week 1-2)

**2.1 Set Up Foundry Doc Generation**
```bash
# Generate documentation
forge doc --out docs/api

# Serve locally
forge doc --serve --port 4000
```

**2.2 Create CI Check**
```yaml
# .github/workflows/docs.yml
name: Documentation

on: [pull_request]

jobs:
  natspec-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Check NatSpec Coverage
        run: |
          npx solhint 'contracts/**/*.sol' --config .solhint.json
          
      - name: Generate Docs
        run: forge doc --out docs/api
        
      - name: Check for Missing Docs
        run: python scripts/check_natspec_coverage.py --threshold 90
```

**2.3 Create NatSpec Coverage Checker**
```python
# scripts/check_natspec_coverage.py
"""
Checks NatSpec coverage across all contracts.
"""

import re
from pathlib import Path

def check_coverage(contracts_dir: Path, threshold: float = 0.9):
    """
    Returns True if NatSpec coverage >= threshold.
    """
    total_functions = 0
    documented_functions = 0
    
    for sol_file in contracts_dir.rglob("*.sol"):
        content = sol_file.read_text()
        
        # Count external/public functions
        functions = re.findall(r'function\s+\w+\s*\([^)]*\)\s+(?:external|public)', content)
        total_functions += len(functions)
        
        # Count functions with @notice
        documented = re.findall(r'@notice.*\n.*function\s+\w+', content)
        documented_functions += len(documented)
    
    coverage = documented_functions / total_functions if total_functions > 0 else 1.0
    
    print(f"NatSpec Coverage: {coverage:.1%} ({documented_functions}/{total_functions})")
    return coverage >= threshold
```

#### Phase 3: Contract Documentation (Week 2-3)

**3.1 Priority 1 - Crosschain Contracts**
```
contracts/crosschain/
├── ArbitrumBridgeAdapter.sol       # NEEDS: @param, @return
├── LayerZeroBridgeAdapter.sol      # NEEDS: Full NatSpec
├── L2ProofRouter.sol               # NEEDS: @param, @return
├── DirectL2Messenger.sol           # NEEDS: @dev notes
└── ...
```

**3.2 Priority 2 - Security Contracts**
```
contracts/security/
├── SecurityModule.sol              # Good - template for others
├── FlashLoanGuard.sol              # NEEDS: @custom:security
├── MEVProtection.sol               # NEEDS: Full NatSpec
├── RuntimeSecurityMonitor.sol      # NEEDS: @dev notes
└── ...
```

**3.3 Priority 3 - FHE/MPC Contracts**
```
contracts/fhe/
├── SoulFHEModule.sol               # NEEDS: Full NatSpec
├── EncryptedERC20.sol              # NEEDS: @param, @return
└── ...

contracts/mpc/
├── ThresholdMPC.sol                # NEEDS: Full NatSpec
└── ...
```

### Deliverables
- [ ] `docs/NATSPEC_STYLE_GUIDE.md` - Documentation standards
- [ ] Updated `.solhint.json` with NatSpec rules
- [ ] `scripts/check_natspec_coverage.py` - Coverage checker
- [ ] `.github/workflows/docs.yml` - CI pipeline
- [ ] Full NatSpec for `contracts/crosschain/*.sol`
- [ ] Full NatSpec for `contracts/security/*.sol`
- [ ] Full NatSpec for `contracts/fhe/*.sol`
- [ ] `docs/api/` - Generated API documentation

---

## Issue 4: Governance Organization (P3)

### Current State
- Governance logic exists in `contracts/security/SoulMultiSigGovernance.sol`
- Timelock exists in `contracts/security/SoulTimelock.sol` and `SoulUpgradeTimelock.sol`
- No dedicated `contracts/governance/` directory
- Governance contracts mixed with security contracts

### Implementation Plan

#### Phase 1: Directory Restructuring (Week 1)

**1.1 Create Governance Directory**
```bash
mkdir -p contracts/governance
```

**1.2 Move Existing Governance Contracts**
```
# Current Location → New Location
contracts/security/SoulMultiSigGovernance.sol → contracts/governance/SoulMultiSigGovernance.sol
contracts/security/SoulTimelock.sol           → contracts/governance/SoulTimelock.sol
contracts/security/SoulUpgradeTimelock.sol    → contracts/governance/SoulUpgradeTimelock.sol
contracts/security/TimelockAdmin.sol          → contracts/governance/TimelockAdmin.sol
```

**1.3 Update Imports Across Codebase**
```bash
# Find and replace imports
find contracts -name "*.sol" -exec sed -i '' \
  's|security/SoulMultiSigGovernance|governance/SoulMultiSigGovernance|g' {} \;
```

**1.4 Final Directory Structure**
```
contracts/governance/
├── SoulMultiSigGovernance.sol      # Multi-sig governance
├── SoulTimelock.sol                # Standard timelock
├── SoulUpgradeTimelock.sol         # Upgrade-specific timelock
├── TimelockAdmin.sol               # Timelock administration
├── SoulGovernor.sol                # (NEW) OpenZeppelin Governor
├── SoulVotes.sol                   # (NEW) Voting token wrapper
└── interfaces/
    ├── ISoulGovernor.sol
    └── ISoulTimelock.sol
```

#### Phase 2: Governance Enhancements (Optional - Future)

**2.1 Add OpenZeppelin Governor Integration**
```solidity
// contracts/governance/SoulGovernor.sol
import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";

contract SoulGovernor is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorVotes,
    GovernorTimelockControl
{
    constructor(
        IVotes _token,
        TimelockController _timelock
    )
        Governor("Soul Governor")
        GovernorSettings(1 days, 1 weeks, 100_000e18) // delay, period, threshold
        GovernorVotes(_token)
        GovernorTimelockControl(_timelock)
    {}
}
```

**2.2 Update Certora Specs**
```bash
# Rename/move spec file
mv certora/specs/SoulGovernor.spec → stays (already exists)

# Create new governance specs
certora/specs/GovernanceIntegration.spec
certora/specs/TimelockSafety.spec
```

### Deliverables
- [ ] `contracts/governance/` directory created
- [ ] Existing governance contracts moved
- [ ] All imports updated across codebase
- [ ] `contracts/governance/interfaces/` created
- [ ] Tests updated with new paths
- [ ] (Optional) `SoulGovernor.sol` using OpenZeppelin Governor

---

## Implementation Timeline

```
Week 1-2:   ████████░░░░░░░░░░░░░░░░  Coverage Refactoring
Week 2-3:   ░░░░████████░░░░░░░░░░░░  Coverage Solutions
Week 3-4:   ░░░░░░░░████████░░░░░░░░  Coverage CI
Week 1-4:   ████████████████░░░░░░░░  PQC Pure Solidity
Week 4-6:   ░░░░░░░░░░░░░░░░████████  PQC ZK Integration
Week 6-8:   ░░░░░░░░░░░░░░░░░░░░████  PQC Production
Week 1:     ████░░░░░░░░░░░░░░░░░░░░  NatSpec Standards
Week 1-2:   ████████░░░░░░░░░░░░░░░░  NatSpec Tooling
Week 2-3:   ░░░░░░░░████████░░░░░░░░  NatSpec Writing
Week 1:     ████░░░░░░░░░░░░░░░░░░░░  Governance Reorg
```

## Resource Requirements

| Area | Engineers | Skills Required |
|------|-----------|-----------------|
| Coverage | 1 Senior | Foundry, Solidity optimization |
| PQC | 2 Senior | Cryptography, ZK circuits, Noir |
| NatSpec | 1 Mid | Technical writing, Solidity |
| Governance | 1 Mid | Solidity, OpenZeppelin |

## Success Metrics

| Issue | Current | Target | Measurement |
|-------|---------|--------|-------------|
| Coverage | Unknown | ≥85% line, ≥80% branch | LCOV report |
| PQC Mock | 100% mock | ≤5% mock (testnet only) | Deployment config |
| NatSpec | ~50% | ≥95% | `check_natspec_coverage.py` |
| Governance | Scattered | Organized | Directory structure |

---

## Appendix A: File Changes Summary

### New Files to Create
```
docs/COVERAGE.md
docs/NATSPEC_STYLE_GUIDE.md
docs/POST_QUANTUM_DEPLOYMENT.md
scripts/analyze_coverage.py
scripts/check_natspec_coverage.py
.github/workflows/coverage.yml
.github/workflows/docs.yml
contracts/internal/validators/
contracts/internal/storage/
contracts/internal/helpers/
contracts/coverage/
contracts/pqc/lib/DilithiumCore.sol
contracts/pqc/lib/KyberCore.sol
contracts/pqc/HybridPQCVerifier.sol
contracts/pqc/PQCModeController.sol
contracts/governance/
contracts/governance/interfaces/
noir/pqc_verifier/
certora/specs/PQCModeSafety.spec
```

### Files to Move
```
contracts/security/SoulMultiSigGovernance.sol → contracts/governance/
contracts/security/SoulTimelock.sol → contracts/governance/
contracts/security/SoulUpgradeTimelock.sol → contracts/governance/
contracts/security/TimelockAdmin.sol → contracts/governance/
```

### Files to Update
```
foundry.toml                    # Coverage profile improvements
.solhint.json                   # NatSpec rules
package.json                    # New scripts
contracts/crosschain/*.sol      # NatSpec additions
contracts/security/*.sol        # NatSpec additions
contracts/fhe/*.sol             # NatSpec additions
```

---

## Appendix B: Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| PQC Solidity too expensive | Medium | High | Use ZK off-chain verification |
| Coverage refactoring breaks tests | Medium | Medium | Comprehensive test suite first |
| Import changes break builds | Low | Medium | Automated find/replace + CI |
| NatSpec slows development | Low | Low | Automate with templates |

---

*Document maintained by: Soul Protocol Engineering Team*
