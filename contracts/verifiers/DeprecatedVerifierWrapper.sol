// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IProofVerifier.sol";

/**
 * @title DeprecatedVerifierWrapper
 * @author Soul Protocol
 * @notice Wraps legacy verifiers (Groth16, PLONK) with deprecation warnings and migration path
 * @dev Implements a staged deprecation: ACTIVE → SOFT_DEPRECATED → HARD_DEPRECATED → REMOVED
 *
 * Deprecation Timeline (per plan):
 *   - Week 0:  Deploy Noir verifiers, wrapper enters ACTIVE
 *   - Week 4:  WARN mode - emit deprecation warnings
 *   - Week 12: SOFT_DEPRECATED - prefer Noir, fallback to legacy
 *   - Week 24: HARD_DEPRECATED - revert on legacy calls
 *   - Week 26: REMOVED - contract can be self-destructed
 *
 * Usage:
 *   1. Deploy with legacy and Noir verifier addresses
 *   2. Consumer contracts use wrapper instead of direct legacy calls
 *   3. Wrapper transparently migrates to Noir based on timeline
 */
contract DeprecatedVerifierWrapper is IProofVerifier {
    /*//////////////////////////////////////////////////////////////
                          DEPRECATION STAGES
    //////////////////////////////////////////////////////////////*/

    enum DeprecationStage {
        ACTIVE, // Both verifiers available, prefer legacy
        WARN, // Emit warnings, use legacy
        SOFT_DEPRECATED, // Prefer Noir, fallback to legacy
        HARD_DEPRECATED, // Noir only, revert on legacy
        REMOVED // Contract disabled
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice The legacy verifier (Groth16, PLONK, etc.)
    IProofVerifier public immutable legacyVerifier;

    /// @notice The Noir UltraPlonk verifier (replacement)
    IProofVerifier public immutable noirVerifier;

    /// @notice Deployment timestamp
    uint256 public immutable deployedAt;

    /// @notice Soft deprecation date (Week 12)
    uint256 public immutable softDeprecationDate;

    /// @notice Hard deprecation date (Week 24)
    uint256 public immutable hardDeprecationDate;

    /// @notice Removal date (Week 26)
    uint256 public immutable removalDate;

    /// @notice Warning mode start (Week 4)
    uint256 public immutable warnModeDate;

    /// @notice Admin for emergency controls
    address public immutable admin;

    /// @notice Force hard deprecation (emergency)
    bool public forceHardDeprecation;

    /// @notice Force removal (emergency)
    bool public forceRemoval;

    /// @notice Legacy usage counter (for metrics)
    uint256 public legacyCallCount;

    /// @notice Noir usage counter (for metrics)
    uint256 public noirCallCount;

    /// @notice Name of the legacy verifier type
    string public legacyVerifierType;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event DeprecationWarning(
        address indexed caller,
        string message,
        uint256 remainingDays
    );

    event LegacyVerifierUsed(
        address indexed caller,
        bytes32 indexed proofHash,
        DeprecationStage stage
    );

    event NoirVerifierUsed(address indexed caller, bytes32 indexed proofHash);

    event ForceDeprecationEnabled(
        address indexed admin,
        bool hard,
        bool removal
    );

    event MigrationMetrics(
        uint256 legacyCalls,
        uint256 noirCalls,
        uint256 noirPercentage
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error LegacyVerifierDeprecated();
    error VerifierRemoved();
    error OnlyAdmin();
    error InvalidVerifierAddress();

    /*//////////////////////////////////////////////////////////////
                            MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyAdmin() {
        if (msg.sender != admin) revert OnlyAdmin();
        _;
    }

    modifier notRemoved() {
        if (getCurrentStage() == DeprecationStage.REMOVED) {
            revert VerifierRemoved();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a deprecation wrapper
     * @param _legacy Address of legacy verifier (Groth16, PLONK)
     * @param _noir Address of Noir replacement verifier
     * @param _legacyType Human-readable legacy verifier type
     * @param _admin Admin address for emergency controls
     */
    constructor(
        address _legacy,
        address _noir,
        string memory _legacyType,
        address _admin
    ) {
        if (_legacy == address(0) || _noir == address(0)) {
            revert InvalidVerifierAddress();
        }

        legacyVerifier = IProofVerifier(_legacy);
        noirVerifier = IProofVerifier(_noir);
        legacyVerifierType = _legacyType;
        admin = _admin;

        deployedAt = block.timestamp;

        // Timeline based on plan: 4w warn, 12w soft, 24w hard, 26w remove
        warnModeDate = block.timestamp + 4 weeks;
        softDeprecationDate = block.timestamp + 12 weeks;
        hardDeprecationDate = block.timestamp + 24 weeks;
        removalDate = block.timestamp + 26 weeks;
    }

    /*//////////////////////////////////////////////////////////////
                      VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IProofVerifier
     * @notice Verify proof with automatic migration based on deprecation stage
     */
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override notRemoved returns (bool) {
        DeprecationStage stage = getCurrentStage();

        // Hard deprecated: Noir only
        if (stage == DeprecationStage.HARD_DEPRECATED) {
            return noirVerifier.verifyProof(proof, publicInputs);
        }

        // Soft deprecated: prefer Noir, fallback to legacy
        if (stage == DeprecationStage.SOFT_DEPRECATED) {
            try noirVerifier.verifyProof(proof, publicInputs) returns (
                bool result
            ) {
                return result;
            } catch {
                // Fallback to legacy if Noir fails (proof format compatibility)
                return legacyVerifier.verifyProof(proof, publicInputs);
            }
        }

        // Active or Warn: use legacy
        return legacyVerifier.verifyProof(proof, publicInputs);
    }

    /**
     * @inheritdoc IProofVerifier
     * @notice Verify with uint256[] inputs (legacy format)
     */
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override notRemoved returns (bool) {
        DeprecationStage stage = getCurrentStage();

        if (stage == DeprecationStage.HARD_DEPRECATED) {
            return noirVerifier.verify(proof, publicInputs);
        }

        if (stage == DeprecationStage.SOFT_DEPRECATED) {
            try noirVerifier.verify(proof, publicInputs) returns (bool result) {
                return result;
            } catch {
                return legacyVerifier.verify(proof, publicInputs);
            }
        }

        return legacyVerifier.verify(proof, publicInputs);
    }

    /**
     * @notice Verify with explicit verifier choice (for testing migration)
     * @param proof The proof bytes
     * @param publicInputs The public inputs
     * @param useNoir Force use of Noir verifier
     * @return valid Whether proof is valid
     */
    function verifyWithChoice(
        bytes calldata proof,
        bytes calldata publicInputs,
        bool useNoir
    ) external view notRemoved returns (bool valid) {
        if (useNoir) {
            return noirVerifier.verifyProof(proof, publicInputs);
        }

        DeprecationStage stage = getCurrentStage();
        if (stage == DeprecationStage.HARD_DEPRECATED) {
            revert LegacyVerifierDeprecated();
        }

        return legacyVerifier.verifyProof(proof, publicInputs);
    }

    /**
     * @notice Compare both verifiers (for testing equivalence)
     * @param proof The proof bytes
     * @param publicInputs The public inputs
     * @return legacyResult Result from legacy verifier
     * @return noirResult Result from Noir verifier
     * @return match_ Whether results match
     */
    function compareVerifiers(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool legacyResult, bool noirResult, bool match_) {
        DeprecationStage stage = getCurrentStage();

        if (
            stage != DeprecationStage.HARD_DEPRECATED &&
            stage != DeprecationStage.REMOVED
        ) {
            try legacyVerifier.verifyProof(proof, publicInputs) returns (
                bool result
            ) {
                legacyResult = result;
            } catch {
                legacyResult = false;
            }
        }

        if (stage != DeprecationStage.REMOVED) {
            try noirVerifier.verifyProof(proof, publicInputs) returns (
                bool result
            ) {
                noirResult = result;
            } catch {
                noirResult = false;
            }
        }

        match_ = legacyResult == noirResult;
    }

    /*//////////////////////////////////////////////////////////////
                        STAGE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get current deprecation stage
     * @return stage Current DeprecationStage enum value
     */
    function getCurrentStage() public view returns (DeprecationStage stage) {
        if (forceRemoval) return DeprecationStage.REMOVED;
        if (block.timestamp >= removalDate) return DeprecationStage.REMOVED;

        if (forceHardDeprecation) return DeprecationStage.HARD_DEPRECATED;
        if (block.timestamp >= hardDeprecationDate)
            return DeprecationStage.HARD_DEPRECATED;

        if (block.timestamp >= softDeprecationDate)
            return DeprecationStage.SOFT_DEPRECATED;
        if (block.timestamp >= warnModeDate) return DeprecationStage.WARN;

        return DeprecationStage.ACTIVE;
    }

    /**
     * @notice Get days until next stage
     * @return daysRemaining Days until next deprecation stage
     * @return nextStage The next stage name
     */
    function getDaysUntilNextStage()
        external
        view
        returns (uint256 daysRemaining, string memory nextStage)
    {
        DeprecationStage current = getCurrentStage();

        if (current == DeprecationStage.ACTIVE) {
            daysRemaining = (warnModeDate - block.timestamp) / 1 days;
            nextStage = "WARN";
        } else if (current == DeprecationStage.WARN) {
            daysRemaining = (softDeprecationDate - block.timestamp) / 1 days;
            nextStage = "SOFT_DEPRECATED";
        } else if (current == DeprecationStage.SOFT_DEPRECATED) {
            daysRemaining = (hardDeprecationDate - block.timestamp) / 1 days;
            nextStage = "HARD_DEPRECATED";
        } else if (current == DeprecationStage.HARD_DEPRECATED) {
            daysRemaining = (removalDate - block.timestamp) / 1 days;
            nextStage = "REMOVED";
        } else {
            daysRemaining = 0;
            nextStage = "FINAL";
        }
    }

    /**
     * @notice Get stage information as string
     * @return info Human-readable stage information
     */
    function getStageInfo() external view returns (string memory info) {
        DeprecationStage stage = getCurrentStage();

        if (stage == DeprecationStage.ACTIVE) {
            return
                string(
                    abi.encodePacked(
                        "ACTIVE: ",
                        legacyVerifierType,
                        " in use. Migration to Noir planned."
                    )
                );
        } else if (stage == DeprecationStage.WARN) {
            return
                string(
                    abi.encodePacked(
                        "WARNING: ",
                        legacyVerifierType,
                        " deprecated. Migrate to Noir verifier."
                    )
                );
        } else if (stage == DeprecationStage.SOFT_DEPRECATED) {
            return
                string(
                    abi.encodePacked(
                        "SOFT DEPRECATED: Noir preferred. ",
                        legacyVerifierType,
                        " fallback available."
                    )
                );
        } else if (stage == DeprecationStage.HARD_DEPRECATED) {
            return
                string(
                    abi.encodePacked(
                        "HARD DEPRECATED: ",
                        legacyVerifierType,
                        " disabled. Noir only."
                    )
                );
        } else {
            return "REMOVED: Verifier wrapper is disabled.";
        }
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Force hard deprecation (emergency)
     * @param enable Enable or disable force deprecation
     */
    function setForceHardDeprecation(bool enable) external onlyAdmin {
        forceHardDeprecation = enable;
        emit ForceDeprecationEnabled(msg.sender, enable, forceRemoval);
    }

    /**
     * @notice Force removal (emergency)
     * @param enable Enable or disable force removal
     */
    function setForceRemoval(bool enable) external onlyAdmin {
        forceRemoval = enable;
        emit ForceDeprecationEnabled(msg.sender, forceHardDeprecation, enable);
    }

    /**
     * @notice Get migration metrics
     * @return legacy Legacy call count
     * @return noir Noir call count
     * @return noirPct Percentage using Noir
     */
    function getMetrics()
        external
        view
        returns (uint256 legacy, uint256 noir, uint256 noirPct)
    {
        legacy = legacyCallCount;
        noir = noirCallCount;
        uint256 total = legacy + noir;
        noirPct = total > 0 ? (noir * 100) / total : 0;
    }

    /*//////////////////////////////////////////////////////////////
                    IPROOFVERIFIER INTERFACE
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IProofVerifier
     */
    function getPublicInputCount() external view override returns (uint256) {
        // Use Noir verifier's input count as canonical
        return noirVerifier.getPublicInputCount();
    }

    /**
     * @inheritdoc IProofVerifier
     */
    function verifySingle(
        bytes calldata proof,
        uint256 publicInput
    ) external view override notRemoved returns (bool) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = publicInput;

        DeprecationStage stage = getCurrentStage();

        if (stage == DeprecationStage.HARD_DEPRECATED) {
            return noirVerifier.verify(proof, inputs);
        }

        if (stage == DeprecationStage.SOFT_DEPRECATED) {
            try noirVerifier.verify(proof, inputs) returns (bool result) {
                return result;
            } catch {
                return legacyVerifier.verify(proof, inputs);
            }
        }

        return legacyVerifier.verify(proof, inputs);
    }

    /**
     * @inheritdoc IProofVerifier
     */
    function isReady() external view override returns (bool) {
        DeprecationStage stage = getCurrentStage();
        if (stage == DeprecationStage.REMOVED) {
            return false;
        }
        return true;
    }
}

/**
 * @title DeprecatedGroth16Wrapper
 * @notice Pre-configured wrapper for Groth16VerifierBN254
 */
contract DeprecatedGroth16Wrapper is DeprecatedVerifierWrapper {
    constructor(
        address _legacy,
        address _noir,
        address _admin
    ) DeprecatedVerifierWrapper(_legacy, _noir, "Groth16 BN254", _admin) {}
}

/**
 * @title DeprecatedPLONKWrapper
 * @notice Pre-configured wrapper for PLONKVerifier
 */
contract DeprecatedPLONKWrapper is DeprecatedVerifierWrapper {
    constructor(
        address _legacy,
        address _noir,
        address _admin
    ) DeprecatedVerifierWrapper(_legacy, _noir, "PLONK", _admin) {}
}

/**
 * @title DeprecatedOptimizedGroth16Wrapper
 * @notice Pre-configured wrapper for OptimizedGroth16Verifier
 */
contract DeprecatedOptimizedGroth16Wrapper is DeprecatedVerifierWrapper {
    constructor(
        address _legacy,
        address _noir,
        address _admin
    ) DeprecatedVerifierWrapper(_legacy, _noir, "Optimized Groth16", _admin) {}
}
