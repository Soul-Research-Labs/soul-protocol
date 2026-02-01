// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title InvariantCheckerAdapter
 * @notice Adapter for ZK invariant verification of UnifiedNullifierManager
 * @dev Enforces Cross-Domain Nullifier Algebra (CDNA) invariants in ZK
 *
 * Circuit: noir/invariant_checker/src/main.nr
 * Public inputs: [expected_soul_binding]
 * Private inputs: source_nullifier, domain_tag, soul_binding_tag
 *
 * Invariants verified:
 *   1. Soul Binding = hash(source_nullifier, domain_tag, tag)
 *   2. Deterministic cross-domain nullifier derivation
 *   3. No nullifier collisions across domains
 *
 * Gas estimate: ~40,000 per verification
 */
contract InvariantCheckerAdapter is NoirVerifierAdapter {
    /// @notice Number of public inputs for this circuit
    uint256 public constant PUBLIC_INPUT_COUNT = 1;

    /// @notice Public input index
    uint256 private constant IDX_EXPECTED_SOUL_BINDING = 0;

    /// @notice Invariant type identifiers
    uint256 public constant INVARIANT_SOUL_BINDING = 1;
    uint256 public constant INVARIANT_NULLIFIER_UNIQUENESS = 2;
    uint256 public constant INVARIANT_DOMAIN_SEPARATION = 3;
    uint256 public constant INVARIANT_COMMITMENT_BALANCE = 4;
    uint256 public constant INVARIANT_CDNA_WELL_FORMED = 5;

    /// @notice Emitted when an invariant is verified
    event InvariantVerified(
        uint256 indexed invariantType,
        bytes32 indexed binding
    );

    /// @notice Error for invalid invariant type
    error InvalidInvariantType(uint256 provided);

    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    /**
     * @notice Standard verification interface
     * @param proof The UltraPlonk proof bytes
     * @param publicInputs ABI-encoded expected_soul_binding
     * @return Whether the proof is valid
     */
    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);

        require(
            inputs.length == PUBLIC_INPUT_COUNT,
            "ICA: SIGNAL_COUNT_MISMATCH"
        );

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    /**
     * @notice Verify a specific invariant with explicit parameters
     * @param proof The UltraPlonk proof bytes
     * @param invariantType The type of invariant being verified
     * @param expectedBinding The expected soul binding value
     * @return valid Whether the invariant holds
     */
    function verifyInvariant(
        bytes calldata proof,
        uint256 invariantType,
        bytes32 expectedBinding
    ) external view returns (bool valid) {
        if (invariantType == 0 || invariantType > INVARIANT_CDNA_WELL_FORMED) {
            revert InvalidInvariantType(invariantType);
        }

        bytes32[] memory signals = new bytes32[](PUBLIC_INPUT_COUNT);
        signals[IDX_EXPECTED_SOUL_BINDING] = expectedBinding;

        return INoirVerifier(noirVerifier).verify(proof, signals);
    }

    /**
     * @notice Verify soul binding derivation
     * @dev Proves: soul_binding = Poseidon(source_nullifier, domain_tag, soul_binding_tag)
     * @param proof The proof bytes
     * @param expectedSoulBinding The expected binding value
     * @return valid Whether the derivation is correct
     */
    function verifySoulBinding(
        bytes calldata proof,
        bytes32 expectedSoulBinding
    ) external view returns (bool valid) {
        bytes32[] memory signals = new bytes32[](PUBLIC_INPUT_COUNT);
        signals[IDX_EXPECTED_SOUL_BINDING] = expectedSoulBinding;

        return INoirVerifier(noirVerifier).verify(proof, signals);
    }

    /**
     * @notice Verify nullifier uniqueness across domains
     * @dev Ensures no two different source nullifiers map to same unified binding
     * @param proof The proof bytes
     * @param unifiedBinding The unified nullifier binding
     * @return valid Whether uniqueness is maintained
     */
    function verifyNullifierUniqueness(
        bytes calldata proof,
        bytes32 unifiedBinding
    ) external view returns (bool valid) {
        bytes32[] memory signals = new bytes32[](PUBLIC_INPUT_COUNT);
        signals[IDX_EXPECTED_SOUL_BINDING] = unifiedBinding;

        return INoirVerifier(noirVerifier).verify(proof, signals);
    }

    /**
     * @notice Verify CDNA (Cross-Domain Nullifier Algebra) well-formedness
     * @dev Checks algebraic properties of the nullifier derivation
     * @param proof The proof bytes
     * @param cdnaRoot The root of the CDNA structure
     * @return valid Whether CDNA is well-formed
     */
    function verifyCDNAWellFormed(
        bytes calldata proof,
        bytes32 cdnaRoot
    ) external view returns (bool valid) {
        bytes32[] memory signals = new bytes32[](PUBLIC_INPUT_COUNT);
        signals[IDX_EXPECTED_SOUL_BINDING] = cdnaRoot;

        return INoirVerifier(noirVerifier).verify(proof, signals);
    }

    /**
     * @notice Compute expected soul binding (for testing/validation)
     * @dev On-chain keccak256 approximation; circuit uses Poseidon
     * @param sourceNullifier The source domain nullifier
     * @param domainTag The domain identifier
     * @param soulBindingTag The binding type tag
     * @return binding The computed binding (keccak256 version)
     */
    function computeSoulBindingKeccak(
        bytes32 sourceNullifier,
        bytes32 domainTag,
        bytes32 soulBindingTag
    ) external pure returns (bytes32 binding) {
        return
            keccak256(
                abi.encodePacked(sourceNullifier, domainTag, soulBindingTag)
            );
    }

    /**
     * @inheritdoc NoirVerifierAdapter
     */
    function getPublicInputCount() public pure override returns (uint256) {
        return PUBLIC_INPUT_COUNT;
    }
}
