# Experimental Features Policy

## Overview

Soul Protocol includes experimental cryptographic features (FHE, PQC, MPC) that are not yet production-ready. This document outlines how to manage these features safely.

## Feature Classification

### Production (Green)

✅ **Ready for mainnet with real value**

- Groth16 verification (BN254)
- Poseidon hashing
- ECDSA signatures
- Merkle trees
- Core ZK-SLocks

**Criteria**: Audited, formally verified, battle-tested

### Beta (Yellow)

⚠️ **Testnet only, limited value**

- Ring signatures (CLSAG)
- Stealth addresses
- Cross-chain bridges (some)
- Recursive proof aggregation

**Criteria**: Extensive testing, security review, testnet deployment

### Experimental (Red)

🔴 **Research/prototype, no real value**

- FHE operations (SoulFHEModule, EncryptedERC20)
- Post-quantum crypto (Dilithium, Kyber, SPHINCS+)
- MPC threshold signatures
- Advanced privacy (Seraphim, Triptych)

**Criteria**: Proof of concept, research phase, not audited

## Isolation Strategy

### 1. Separate Deployment Tracks

```
Production Track (Mainnet)
├── Core contracts only
├── Audited bridges
└── Battle-tested verifiers

Experimental Track (Testnet)
├── All experimental features
├── Isolated from production
└── Clearly marked as experimental
```

### 2. Feature Flags

```solidity
// contracts/security/ExperimentalFeatureRegistry.sol
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ExperimentalFeatureRegistry is AccessControl {
    bytes32 public constant FEATURE_ADMIN = keccak256("FEATURE_ADMIN");

    enum FeatureStatus {
        DISABLED,
        EXPERIMENTAL,  // Testnet only
        BETA,          // Limited mainnet
        PRODUCTION     // Full mainnet
    }

    struct Feature {
        string name;
        FeatureStatus status;
        address implementation;
        uint256 maxValueLocked;  // Risk limit
        bool requiresWarning;
        string documentationUrl;
    }

    mapping(bytes32 => Feature) public features;

    // Feature identifiers
    bytes32 public constant FHE_OPERATIONS = keccak256("FHE_OPERATIONS");
    bytes32 public constant PQC_SIGNATURES = keccak256("PQC_SIGNATURES");
    bytes32 public constant MPC_THRESHOLD = keccak256("MPC_THRESHOLD");
    bytes32 public constant SERAPHIM_PRIVACY = keccak256("SERAPHIM_PRIVACY");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(FEATURE_ADMIN, msg.sender);

        // Initialize experimental features as DISABLED
        _registerFeature(
            FHE_OPERATIONS,
            "FHE Operations",
            FeatureStatus.EXPERIMENTAL,
            address(0),
            1 ether,  // Max 1 ETH for testing
            true,
            "https://docs.soul.xyz/experimental/fhe"
        );

        _registerFeature(
            PQC_SIGNATURES,
            "Post-Quantum Signatures",
            FeatureStatus.EXPERIMENTAL,
            address(0),
            0.1 ether,
            true,
            "https://docs.soul.xyz/experimental/pqc"
        );
    }

    function _registerFeature(
        bytes32 featureId,
        string memory name,
        FeatureStatus status,
        address implementation,
        uint256 maxValueLocked,
        bool requiresWarning,
        string memory documentationUrl
    ) internal {
        features[featureId] = Feature({
            name: name,
            status: status,
            implementation: implementation,
            maxValueLocked: maxValueLocked,
            requiresWarning: requiresWarning,
            documentationUrl: documentationUrl
        });
    }

    function isFeatureEnabled(bytes32 featureId) external view returns (bool) {
        return features[featureId].status != FeatureStatus.DISABLED;
    }

    function requireFeatureEnabled(bytes32 featureId) external view {
        require(
            features[featureId].status != FeatureStatus.DISABLED,
            "Feature is disabled"
        );
    }

    function requireProductionReady(bytes32 featureId) external view {
        require(
            features[featureId].status == FeatureStatus.PRODUCTION,
            "Feature not production-ready"
        );
    }

    function updateFeatureStatus(
        bytes32 featureId,
        FeatureStatus newStatus
    ) external onlyRole(FEATURE_ADMIN) {
        features[featureId].status = newStatus;
        emit FeatureStatusUpdated(featureId, newStatus);
    }

    event FeatureStatusUpdated(bytes32 indexed featureId, FeatureStatus status);
}
```

### 3. Risk Limits

**Enforce maximum value at risk** for experimental features.

```solidity
// contracts/security/ExperimentalRiskLimiter.sol
contract ExperimentalRiskLimiter {
    ExperimentalFeatureRegistry public registry;

    mapping(bytes32 => uint256) public totalValueLocked;

    modifier withinRiskLimit(bytes32 featureId, uint256 amount) {
        Feature memory feature = registry.features(featureId);
        require(
            totalValueLocked[featureId] + amount <= feature.maxValueLocked,
            "Exceeds risk limit for experimental feature"
        );
        _;
        totalValueLocked[featureId] += amount;
    }

    function lockWithFHE(uint256 amount)
        external
        withinRiskLimit(registry.FHE_OPERATIONS(), amount)
    {
        // FHE operation with risk limit
    }
}
```

### 4. Clear User Warnings

```solidity
// contracts/interfaces/IExperimentalWarning.sol
interface IExperimentalWarning {
    /// @notice WARNING: This feature is EXPERIMENTAL and NOT AUDITED
    /// @notice Use only for testing with small amounts
    /// @notice Risk of total loss of funds
    /// @dev See documentation: https://docs.soul.xyz/experimental/fhe
    function experimentalFHEOperation() external;
}
```

### 5. Separate Documentation

Create clear documentation hierarchy:

```
docs/
├── production/          # Production features
│   ├── zk-slocks.md
│   ├── bridges.md
│   └── security.md
├── beta/                # Beta features
│   ├── ring-signatures.md
│   └── stealth-addresses.md
└── experimental/        # Experimental features
    ├── README.md        # ⚠️ WARNING: NOT PRODUCTION READY
    ├── fhe.md
    ├── pqc.md
    └── mpc.md
```

## Graduation Path

### Experimental → Beta

**Requirements**:

- [ ] Security review completed
- [ ] Extensive testing (>1000 test cases)
- [ ] Testnet deployment (>3 months)
- [ ] No critical issues found
- [ ] Documentation complete
- [ ] Community feedback positive

**Process**:

1. Submit graduation proposal
2. Security committee review
3. Community vote
4. Gradual rollout with limits

### Beta → Production

**Requirements**:

- [ ] Full security audit by 2+ firms
- [ ] Formal verification complete
- [ ] Bug bounty program (>6 months)
- [ ] Testnet usage (>10,000 transactions)
- [ ] No high/critical issues
- [ ] Insurance coverage available
- [ ] Governance approval

**Process**:

1. Audit reports published
2. Governance proposal
3. Timelock period (7 days)
4. Gradual limit increases
5. Full production after 3 months

## Current Feature Status

### FHE (Fully Homomorphic Encryption)

**Status**: 🔴 Experimental

**Contracts**:

- `SoulFHEModule.sol`
- `EncryptedERC20.sol`
- `EncryptedVoting.sol`
- `FHEGateway.sol`

**Issues**:

- Gas costs extremely high (>10M gas per operation)
- Limited FHE library support on EVM
- Not audited
- Unproven in production

**Recommendation**:

- Keep disabled on mainnet
- Continue research on testnet
- Consider L2 deployment for lower gas
- Wait for FHE coprocessor maturity (Zama, Fhenix)

**Timeline**: 12-18 months to production

### PQC (Post-Quantum Cryptography)

**Status**: 🔴 Experimental

**Contracts**:

- `DilithiumVerifier.sol`
- `KyberKEM.sol`
- `SPHINCSPlusVerifier.sol`
- `PQCRegistry.sol`

**Issues**:

- Large signature sizes (2-4KB)
- High verification gas costs (>5M gas)
- NIST standards recently finalized (2024)
- Limited production usage

**Recommendation**:

- Keep disabled on mainnet
- Monitor quantum computing threats
- Prepare for future activation
- Consider hybrid classical+PQC approach

**Timeline**: 24-36 months to production (when quantum threat is imminent)

### MPC (Multi-Party Computation)

**Status**: 🔴 Experimental

**Contracts**:

- `SoulThresholdSignature.sol`
- `SoulMPCComplianceModule.sol`

**Issues**:

- Complex coordination requirements
- Network latency sensitive
- Not fully implemented
- Requires off-chain infrastructure

**Recommendation**:

- Keep disabled on mainnet
- Focus on threshold signatures first
- Partner with MPC providers (Lit Protocol, Fireblocks)
- Gradual rollout for governance only

**Timeline**: 6-12 months to beta

### Advanced Privacy (Seraphim, Triptych)

**Status**: 🔴 Experimental

**Contracts**:

- `SeraphisFullProtocol.sol`
- `TriptychSignatures.sol`
- `TriptychPlusSignatures.sol`

**Issues**:

- Novel cryptography (not battle-tested)
- High complexity
- Limited tooling
- Unaudited

**Recommendation**:

- Research phase only
- Extensive testing required
- Consider simpler alternatives (CLSAG)
- Academic collaboration needed

**Timeline**: 18-24 months to beta

## Monitoring & Incident Response

### Monitoring

Track experimental feature usage:

- Transaction count
- Value locked
- Error rates
- Gas consumption
- User feedback

### Incident Response

If issues found in experimental features:

1. **Immediate**: Disable feature via FeatureRegistry
2. **24 hours**: Publish incident report
3. **48 hours**: Propose fix or deprecation
4. **7 days**: Implement fix or remove feature

### Bug Bounty

Separate bug bounty tiers:

- **Production**: Up to $1M
- **Beta**: Up to $100K
- **Experimental**: Up to $10K

## Communication Strategy

### User-Facing

**In UI**:

```
⚠️ EXPERIMENTAL FEATURE
This feature is not production-ready and has not been audited.
Use only for testing with small amounts.
Risk of total loss of funds.
[Learn More] [I Understand, Continue]
```

**In Documentation**:

```markdown
# ⚠️ EXPERIMENTAL: FHE Operations

**Status**: Research Phase
**Audit Status**: Not Audited
**Recommended Use**: Testing only
**Max Value**: 1 ETH
**Risk Level**: HIGH

This feature is experimental and should not be used with real value...
```

### Developer-Facing

**In Code**:

```solidity
/// @custom:security-contact security@soul.xyz
/// @custom:experimental This contract is EXPERIMENTAL and NOT AUDITED
/// @custom:risk-level HIGH
/// @custom:max-value 1 ether
/// @custom:status RESEARCH_PHASE
contract SoulFHEModule {
    // ...
}
```

## Deprecation Policy

If experimental feature fails to graduate:

1. **Announcement**: 3 months notice
2. **Deprecation**: Mark as deprecated, disable new usage
3. **Migration Period**: 6 months for existing users
4. **Removal**: Archive code, remove from docs

## Success Criteria

An experimental feature is successful if:

- [ ] Graduates to beta within 18 months
- [ ] Achieves >100 active users on testnet
- [ ] No critical security issues found
- [ ] Community demand is strong
- [ ] Technical feasibility proven
- [ ] Cost-benefit analysis positive

## Resources

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Zama FHE](https://www.zama.ai/)
- [Lit Protocol MPC](https://litprotocol.com/)
- [Experimental Features Dashboard](https://testnet.soul.xyz/experimental)
