// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title VerifierHub
 * @author Soul Protocol
 * @notice Central registry and router for all ZK proof verifiers
 * @dev Manages multiple circuit verifiers with versioning and upgrade support
 */
contract VerifierHub is AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuit types supported by Soul
    enum CircuitType {
        StateCommitment, // 0: Prove knowledge of state preimage
        StateTransfer, // 1: Prove valid state ownership transfer
        MerkleProof, // 2: Prove merkle tree membership
        CrossChainProof, // 3: Prove cross-chain state validity
        ComplianceProof // 4: Prove compliance without revealing data
    }

    /// @notice Verifier metadata
    struct VerifierInfo {
        address verifier; // Verifier contract address
        uint256 version; // Version number
        uint256 deployedAt; // Deployment timestamp
        bool active; // Whether verifier is active
        uint256 totalVerifications; // Total successful verifications
        uint256 totalFailures; // Total failed verifications
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuit type => Verifier info
    mapping(CircuitType => VerifierInfo) public verifiers;

    /// @notice Global Verifier Registry (optional fallback)
    address public verifierRegistry;

    /// @notice Historical verifiers (circuit => version => address)
    mapping(CircuitType => mapping(uint256 => address))
        public historicalVerifiers;

    /// @notice Proof hash => already verified (replay protection)
    mapping(bytes32 => bool) public verifiedProofs;

    /// @notice Enable proof replay protection
    bool public replayProtectionEnabled;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event VerifierRegistered(
        CircuitType indexed circuitType,
        address indexed verifier,
        uint256 version
    );

    event VerifierDeactivated(
        CircuitType indexed circuitType,
        address indexed verifier
    );

    event ProofVerified(
        CircuitType indexed circuitType,
        bytes32 indexed proofHash,
        bool success
    );

    event ReplayProtectionToggled(bool enabled);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error VerifierNotRegistered(CircuitType circuitType);
    error VerifierInactive(CircuitType circuitType);
    error ZeroAddress();
    error ProofAlreadyUsed(bytes32 proofHash);
    error VerificationFailed();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
        replayProtectionEnabled = true;
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new verifier for a circuit type
     * @param circuitType The circuit type
     * @param verifier The verifier contract address
     */
    function registerVerifier(
        CircuitType circuitType,
        address verifier
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (verifier == address(0)) revert ZeroAddress();

        VerifierInfo storage info = verifiers[circuitType];

        // Store historical version if exists
        if (info.verifier != address(0)) {
            historicalVerifiers[circuitType][info.version] = info.verifier;
        }

        uint256 newVersion = info.version + 1;

        info.verifier = verifier;
        info.version = newVersion;
        info.deployedAt = block.timestamp;
        info.active = true;

        emit VerifierRegistered(circuitType, verifier, newVersion);
    }

    /**
     * @notice Set the global verifier registry
     * @param _registry The VerifierRegistry address
     */
    function setVerifierRegistry(
        address _registry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        verifierRegistry = _registry;
    }

    /**
     * @notice Deactivate a verifier
     * @param circuitType The circuit type to deactivate
     */
    function deactivateVerifier(
        CircuitType circuitType
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        VerifierInfo storage info = verifiers[circuitType];
        if (info.verifier == address(0))
            revert VerifierNotRegistered(circuitType);

        info.active = false;
        emit VerifierDeactivated(circuitType, info.verifier);
    }

    /**
     * @notice Toggle replay protection
     * @param enabled Whether to enable replay protection
     */
    function setReplayProtection(
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        replayProtectionEnabled = enabled;
        emit ReplayProtectionToggled(enabled);
    }

    /**
     * @notice Pause all verifications
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause verifications
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                       VERIFICATION FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a proof for a specific circuit type
     * @param circuitType The type of circuit
     * @param proof The proof data
     * @param publicInputs The public inputs
     * @return success Whether the proof is valid
     */
    function verifyProof(
        CircuitType circuitType,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external whenNotPaused returns (bool success) {
        VerifierInfo storage info = verifiers[circuitType];

        address verifier = info.verifier;
        if (verifier == address(0) || !info.active) {
            if (verifierRegistry != address(0)) {
                // Map CircuitType to bytes32 proofType for Registry lookup
                // This matches the PROOF_TYPES mapping used in migrate_to_noir.ts
                bytes32 proofType;
                if (circuitType == CircuitType.StateTransfer) proofType = keccak256("STATE_TRANSITION_PROOF");
                else if (circuitType == CircuitType.StateCommitment) proofType = keccak256("COMMITMENT_PROOF");
                else if (circuitType == CircuitType.CrossChainProof) proofType = keccak256("CROSS_CHAIN_PROOF");
                else if (circuitType == CircuitType.ComplianceProof) proofType = keccak256("COMPLIANCE_PROOF");
                
                if (proofType != bytes32(0)) {
                    (bool regSuccess, bytes memory regData) = verifierRegistry.staticcall(
                        abi.encodeWithSignature("getVerifier(bytes32)", proofType)
                    );
                    if (regSuccess && regData.length == 32) {
                        verifier = abi.decode(regData, (address));
                    }
                }
            }
        }

        if (verifier == address(0)) revert VerifierNotRegistered(circuitType);

        // Compute proof hash for replay protection
        bytes32 proofHash = keccak256(abi.encode(proof, publicInputs));

        if (replayProtectionEnabled && verifiedProofs[proofHash]) {
            revert ProofAlreadyUsed(proofHash);
        }

        // Call the verifier (all adapters now support verifyProof)
        (bool callSuccess, bytes memory result) = verifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(bytes,bytes)",
                proof,
                publicInputs
            )
        );

        success = callSuccess && abi.decode(result, (bool));

        // Update stats
        if (success) {
            info.totalVerifications++;
            if (replayProtectionEnabled) {
                verifiedProofs[proofHash] = true;
            }
        } else {
            info.totalFailures++;
        }

        emit ProofVerified(circuitType, proofHash, success);
    }

    /**
     * @notice Verify a state commitment proof
     * @param proof The Groth16 proof
     * @param commitment The state commitment
     * @param ownerPubkey The owner's public key
     */
    function verifyStateCommitment(
        uint256[8] calldata proof,
        uint256 commitment,
        uint256 ownerPubkey
    ) external whenNotPaused returns (bool) {
        VerifierInfo storage info = verifiers[CircuitType.StateCommitment];
        if (info.verifier == address(0))
            revert VerifierNotRegistered(CircuitType.StateCommitment);
        if (!info.active) revert VerifierInactive(CircuitType.StateCommitment);

        // Pack public inputs
        uint256[] memory pubInputs = new uint256[](2);
        pubInputs[0] = commitment;
        pubInputs[1] = ownerPubkey;

        // Call verifier with Groth16 format
        (bool callSuccess, bytes memory result) = info.verifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
                [proof[0], proof[1]],
                [[proof[2], proof[3]], [proof[4], proof[5]]],
                [proof[6], proof[7]],
                pubInputs
            )
        );

        bool success = callSuccess && abi.decode(result, (bool));

        if (success) {
            info.totalVerifications++;
        } else {
            info.totalFailures++;
        }

        return success;
    }

    /**
     * @notice Verify a state transfer proof
     * @param proof The Groth16 proof
     * @param oldCommitment The old state commitment
     * @param newCommitment The new state commitment
     * @param nullifier The nullifier to prevent double-spending
     * @param senderPubkey The sender's public key
     * @param recipientPubkey The recipient's public key
     */
    function verifyStateTransfer(
        uint256[8] calldata proof,
        uint256 oldCommitment,
        uint256 newCommitment,
        uint256 nullifier,
        uint256 senderPubkey,
        uint256 recipientPubkey
    ) external whenNotPaused returns (bool) {
        VerifierInfo storage info = verifiers[CircuitType.StateTransfer];
        if (info.verifier == address(0))
            revert VerifierNotRegistered(CircuitType.StateTransfer);
        if (!info.active) revert VerifierInactive(CircuitType.StateTransfer);

        // Pack public inputs
        uint256[] memory pubInputs = new uint256[](5);
        pubInputs[0] = oldCommitment;
        pubInputs[1] = newCommitment;
        pubInputs[2] = nullifier;
        pubInputs[3] = senderPubkey;
        pubInputs[4] = recipientPubkey;

        // Call verifier
        (bool callSuccess, bytes memory result) = info.verifier.staticcall(
            abi.encodeWithSignature(
                "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[])",
                [proof[0], proof[1]],
                [[proof[2], proof[3]], [proof[4], proof[5]]],
                [proof[6], proof[7]],
                pubInputs
            )
        );

        bool success = callSuccess && abi.decode(result, (bool));

        if (success) {
            info.totalVerifications++;
        } else {
            info.totalFailures++;
        }

        return success;
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get verifier info for a circuit type
     * @param circuitType The circuit type
     * @return info The verifier information
     */
    function getVerifierInfo(
        CircuitType circuitType
    ) external view returns (VerifierInfo memory info) {
        return verifiers[circuitType];
    }

    /**
     * @notice Check if a verifier is active
     * @param circuitType The circuit type
     * @return active Whether the verifier is active
     */
    function isVerifierActive(
        CircuitType circuitType
    ) external view returns (bool active) {
        return verifiers[circuitType].active;
    }

    /**
     * @notice Get historical verifier address
     * @param circuitType The circuit type
     * @param version The version number
     * @return verifier The verifier address
     */
    function getHistoricalVerifier(
        CircuitType circuitType,
        uint256 version
    ) external view returns (address verifier) {
        return historicalVerifiers[circuitType][version];
    }

    /**
     * @notice Check if a proof has been used
     * @param proofHash The proof hash
     * @return used Whether the proof has been used
     */
    function isProofUsed(bytes32 proofHash) external view returns (bool used) {
        return verifiedProofs[proofHash];
    }
}
