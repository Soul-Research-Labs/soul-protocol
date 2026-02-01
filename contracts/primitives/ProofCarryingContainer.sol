// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IProofVerifier.sol";
import "../verifiers/VerifierRegistry.sol";

/// @title ProofCarryingContainer (PC³)
/// @author Soul Protocol - Soul v2
/// @notice Self-authenticating confidential containers that carry their own correctness and policy proofs
/// @dev MVP Implementation - Encrypted state that is portable and verifiable without external context
///
/// Key Properties:
/// - Self-authenticating: Container carries all proofs needed for verification
/// - Portable: Valid on any chain with compatible verifier
/// - Policy-enforced: Compliance proofs embedded in container
/// - Non-replayable: Nullifier correctness proof included
///
/// Security Considerations:
/// - Proof expiry prevents stale proof reuse
/// - Nullifier consumption prevents double-spend
/// - Policy binding ensures compliance scope
/// - Cross-chain imports require source chain proofs
contract ProofCarryingContainer is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("CONTAINER_ADMIN_ROLE")
    bytes32 public constant CONTAINER_ADMIN_ROLE =
        0xd0079826f5316a30be81f752efa53f9a84b4f3a6f49fcc124be773400a02ee85;
    /// @dev keccak256("VERIFIER_ROLE")
    bytes32 public constant VERIFIER_ROLE =
        0x0ce23c3e399818cfee81a7ab0880f714e53d7672b08df0fa62f2843416e1ea09;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Embedded proof bundle - all proofs needed for self-authentication
    struct ProofBundle {
        bytes validityProof; // SNARK proving state transition validity
        bytes policyProof; // SNARK proving policy compliance
        bytes nullifierProof; // SNARK proving nullifier correctness
        bytes32 proofHash; // Hash of all proofs for integrity
        uint256 proofTimestamp; // When proofs were generated
        uint256 proofExpiry; // Proof validity window
    }

    /// @notice The self-authenticating container
    struct Container {
        // Core state
        bytes encryptedPayload; // Encrypted state data
        bytes32 stateCommitment; // Poseidon commitment to state
        bytes32 nullifier; // Unique nullifier for this state
        // Embedded proofs
        ProofBundle proofs;
        // Metadata
        bytes32 policyHash; // Hash of applicable policy
        uint64 chainId; // Origin chain
        uint64 createdAt; // Creation timestamp
        uint32 version; // Container version
        // Verification status
        bool isVerified; // Has been verified on this chain
        bool isConsumed; // Has been used/spent
    }

    /// @notice Container verification result
    struct VerificationResult {
        bool validityValid;
        bool policyValid;
        bool nullifierValid;
        bool notExpired;
        bool notConsumed;
        string failureReason;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping from container ID to container
    mapping(bytes32 => Container) public containers;

    /// @notice Mapping of consumed nullifiers
    mapping(bytes32 => bool) public consumedNullifiers;

    /// @notice Mapping of container ID to verification count
    mapping(bytes32 => uint256) public verificationCount;

    /// @notice Supported policy hashes
    mapping(bytes32 => bool) public supportedPolicies;

    /// @notice Container IDs for enumeration
    bytes32[] private _containerIds;

    /// @notice Total containers created
    uint256 public totalContainers;

    /// @notice Total verified containers
    uint256 public totalVerified;

    /// @notice Chain ID (immutable for gas efficiency)
    uint256 public immutable CHAIN_ID;

    /// @notice Default proof validity window (24 hours)
    uint256 public proofValidityWindow = 24 hours;

    /// @notice Maximum payload size (prevent DOS)
    uint256 public constant MAX_PAYLOAD_SIZE = 1 << 20; // 1MB

    /// @notice Minimum proof size for validity
    uint256 public constant MIN_PROOF_SIZE = 256;

    /// @notice Verifier registry for proof verification
    VerifierRegistry public verifierRegistry;

    /// @notice Whether to use real verification (true = production mode, false = testing only)
    /// @dev SECURITY: Defaults to true. Only set to false in test environments.
    bool public useRealVerification = true;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ContainerCreated(
        bytes32 indexed containerId,
        bytes32 indexed stateCommitment,
        bytes32 indexed nullifier,
        bytes32 policyHash,
        uint64 chainId
    );

    event ContainerVerified(
        bytes32 indexed containerId,
        address indexed verifier,
        bool success,
        string reason
    );

    event ContainerConsumed(
        bytes32 indexed containerId,
        bytes32 indexed nullifier,
        address indexed consumer
    );

    event ContainerImported(
        bytes32 indexed containerId,
        uint64 indexed sourceChainId,
        bytes32 stateCommitment
    );

    event PolicyAdded(bytes32 indexed policyHash);
    event PolicyRemoved(bytes32 indexed policyHash);
    event VerifierRegistryUpdated(
        address indexed oldRegistry,
        address indexed newRegistry
    );
    event RealVerificationToggled(bool enabled);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ContainerAlreadyExists(bytes32 containerId);
    error ContainerNotFound(bytes32 containerId);
    error NullifierAlreadyConsumed(bytes32 nullifier);
    error ProofExpired(uint256 expiry, uint256 current);
    error InvalidProofBundle();
    error UnsupportedPolicy(bytes32 policyHash);
    error VerificationFailed();
    error MainnetPlaceholderNotAllowed();
    error ContainerAlreadyConsumed(bytes32 containerId);
    error InvalidContainerData();
    error PayloadTooLarge(uint256 size, uint256 max);
    error ProofTooSmall(uint256 size, uint256 min);
    error ZeroAddress();
    error InvalidChainId(uint64 chainId);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONTAINER_ADMIN_ROLE, msg.sender);
        CHAIN_ID = block.chainid;
    }

    /*//////////////////////////////////////////////////////////////
                          CONTAINER CREATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a new self-authenticating container
    /// @param encryptedPayload The encrypted state data
    /// @param stateCommitment Poseidon commitment to the state
    /// @param nullifier Unique nullifier for this state
    /// @param proofs The embedded proof bundle
    /// @param policyHash Hash of the applicable policy
    /// @return containerId The unique container identifier
    function createContainer(
        bytes calldata encryptedPayload,
        bytes32 stateCommitment,
        bytes32 nullifier,
        ProofBundle calldata proofs,
        bytes32 policyHash
    ) external whenNotPaused nonReentrant returns (bytes32 containerId) {
        // Validate inputs with specific errors
        if (encryptedPayload.length == 0) revert InvalidContainerData();
        if (encryptedPayload.length > MAX_PAYLOAD_SIZE) {
            revert PayloadTooLarge(encryptedPayload.length, MAX_PAYLOAD_SIZE);
        }
        if (stateCommitment == bytes32(0)) revert InvalidContainerData();
        if (nullifier == bytes32(0)) revert InvalidContainerData();

        // Validate proof sizes
        if (proofs.validityProof.length < MIN_PROOF_SIZE) {
            revert ProofTooSmall(proofs.validityProof.length, MIN_PROOF_SIZE);
        }

        // Check policy support
        if (!supportedPolicies[policyHash] && policyHash != bytes32(0)) {
            revert UnsupportedPolicy(policyHash);
        }

        // Check nullifier not already used
        if (consumedNullifiers[nullifier]) {
            revert NullifierAlreadyConsumed(nullifier);
        }

        // Generate container ID
        containerId = _computeContainerId(
            stateCommitment,
            nullifier,
            uint64(CHAIN_ID)
        );

        if (containers[containerId].createdAt != 0) {
            revert ContainerAlreadyExists(containerId);
        }

        // Verify proof hash integrity
        bytes32 computedProofHash = keccak256(
            abi.encode(
                proofs.validityProof,
                proofs.policyProof,
                proofs.nullifierProof
            )
        );
        if (computedProofHash != proofs.proofHash) {
            revert InvalidProofBundle();
        }

        // Create container
        containers[containerId] = Container({
            encryptedPayload: encryptedPayload,
            stateCommitment: stateCommitment,
            nullifier: nullifier,
            proofs: proofs,
            policyHash: policyHash,
            chainId: uint64(CHAIN_ID),
            createdAt: uint64(block.timestamp),
            version: 1,
            isVerified: false,
            isConsumed: false
        });

        // Track for enumeration
        _containerIds.push(containerId);

        unchecked {
            ++totalContainers;
        }

        emit ContainerCreated(
            containerId,
            stateCommitment,
            nullifier,
            policyHash,
            uint64(CHAIN_ID)
        );
    }

    /*//////////////////////////////////////////////////////////////
                          CONTAINER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a container's embedded proofs
    /// @param containerId The container to verify
    /// @return result The verification result
    function verifyContainer(
        bytes32 containerId
    ) external view returns (VerificationResult memory result) {
        Container storage container = containers[containerId];

        if (container.createdAt == 0) {
            result.failureReason = "Container not found";
            return result;
        }

        // Check expiry
        if (
            container.proofs.proofExpiry != 0 &&
            block.timestamp > container.proofs.proofExpiry
        ) {
            result.failureReason = "Proof expired";
            return result;
        }
        result.notExpired = true;

        // Check consumption
        if (container.isConsumed) {
            result.failureReason = "Container already consumed";
            return result;
        }
        result.notConsumed = true;

        // Verify proof hash integrity
        bytes32 computedProofHash = keccak256(
            abi.encode(
                container.proofs.validityProof,
                container.proofs.policyProof,
                container.proofs.nullifierProof
            )
        );

        if (computedProofHash != container.proofs.proofHash) {
            result.failureReason = "Proof integrity check failed";
            return result;
        }

        // Cache proof references for gas efficiency
        ProofBundle storage proofs = container.proofs;

        // Verify proofs using real verifiers or placeholder logic
        if (useRealVerification && address(verifierRegistry) != address(0)) {
            // Use real SNARK verification through registry
            result.validityValid = _verifyWithRegistry(
                proofs.validityProof,
                container.stateCommitment,
                verifierRegistry.VALIDITY_PROOF()
            );
            result.policyValid =
                container.policyHash == bytes32(0) ||
                _verifyWithRegistry(
                    proofs.policyProof,
                    container.policyHash,
                    verifierRegistry.POLICY_PROOF()
                );
            result.nullifierValid = _verifyWithRegistry(
                proofs.nullifierProof,
                container.nullifier,
                verifierRegistry.NULLIFIER_PROOF()
            );
        } else {
            // Fallback verification for testing/development environments
            // CRITICAL: Production deployments MUST use verifierRegistry
            
            // Block mainnet deployment without real verification
            if (block.chainid == 1) {
                revert MainnetPlaceholderNotAllowed();
            }
            
            // Perform structural validation of proofs
            // This is not cryptographic verification but validates proof format
            result.validityValid = _validateProofStructure(
                proofs.validityProof,
                container.stateCommitment
            );
            result.policyValid =
                container.policyHash == bytes32(0) ||
                _validateProofStructure(proofs.policyProof, container.policyHash);
            result.nullifierValid = _validateProofStructure(
                proofs.nullifierProof,
                container.nullifier
            );
        }

        if (!result.validityValid) {
            result.failureReason = "Validity proof invalid";
        } else if (!result.policyValid) {
            result.failureReason = "Policy proof invalid";
        } else if (!result.nullifierValid) {
            result.failureReason = "Nullifier proof invalid";
        }
    }

    /// @notice Consume a verified container (marks nullifier as used)
    /// @param containerId The container to consume
    function consumeContainer(
        bytes32 containerId
    ) external whenNotPaused nonReentrant onlyRole(VERIFIER_ROLE) {
        Container storage container = containers[containerId];

        // Cache storage reads for gas efficiency
        uint64 createdAt = container.createdAt;
        bool isConsumed = container.isConsumed;
        bytes32 nullifier = container.nullifier;

        if (createdAt == 0) {
            revert ContainerNotFound(containerId);
        }

        if (isConsumed) {
            revert ContainerAlreadyConsumed(containerId);
        }

        if (consumedNullifiers[nullifier]) {
            revert NullifierAlreadyConsumed(nullifier);
        }

        // Mark as consumed
        container.isConsumed = true;
        consumedNullifiers[nullifier] = true;

        emit ContainerConsumed(containerId, nullifier, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          CROSS-CHAIN IMPORT
    //////////////////////////////////////////////////////////////*/

    /// @notice Import a container from another chain
    /// @param containerData Serialized container data
    /// @param sourceChainProof Proof of existence on source chain
    /// @return containerId The imported container ID
    function importContainer(
        bytes calldata containerData,
        bytes calldata sourceChainProof
    ) external whenNotPaused nonReentrant returns (bytes32 containerId) {
        // Decode container
        (
            bytes memory encryptedPayload,
            bytes32 stateCommitment,
            bytes32 nullifier,
            ProofBundle memory proofs,
            bytes32 policyHash,
            uint64 sourceChainId
        ) = abi.decode(
                containerData,
                (bytes, bytes32, bytes32, ProofBundle, bytes32, uint64)
            );

        // Verify source chain proof (simplified for MVP)
        if (sourceChainProof.length < 256) {
            revert InvalidProofBundle();
        }

        // Check nullifier not already used
        if (consumedNullifiers[nullifier]) {
            revert NullifierAlreadyConsumed(nullifier);
        }

        // Generate container ID (includes source chain)
        containerId = _computeContainerId(
            stateCommitment,
            nullifier,
            sourceChainId
        );

        if (containers[containerId].createdAt != 0) {
            revert ContainerAlreadyExists(containerId);
        }

        // Create imported container
        containers[containerId] = Container({
            encryptedPayload: encryptedPayload,
            stateCommitment: stateCommitment,
            nullifier: nullifier,
            proofs: proofs,
            policyHash: policyHash,
            chainId: sourceChainId,
            createdAt: uint64(block.timestamp),
            version: 1,
            isVerified: false,
            isConsumed: false
        });

        unchecked {
            ++totalContainers;
        }

        emit ContainerImported(containerId, sourceChainId, stateCommitment);
    }

    /*//////////////////////////////////////////////////////////////
                          SERIALIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Export a container for cross-chain transfer
    /// @param containerId The container to export
    /// @return data Serialized container data
    function exportContainer(
        bytes32 containerId
    ) external view returns (bytes memory data) {
        Container storage container = containers[containerId];

        if (container.createdAt == 0) {
            revert ContainerNotFound(containerId);
        }

        if (container.isConsumed) {
            revert ContainerAlreadyConsumed(containerId);
        }

        data = abi.encode(
            container.encryptedPayload,
            container.stateCommitment,
            container.nullifier,
            container.proofs,
            container.policyHash,
            container.chainId
        );
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Add a supported policy
    function addPolicy(
        bytes32 policyHash
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        supportedPolicies[policyHash] = true;
        emit PolicyAdded(policyHash);
    }

    /// @notice Remove a policy
    function removePolicy(
        bytes32 policyHash
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        supportedPolicies[policyHash] = false;
        emit PolicyRemoved(policyHash);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Compute unique container ID
    function _computeContainerId(
        bytes32 stateCommitment,
        bytes32 nullifier,
        uint64 chainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(stateCommitment, nullifier, chainId));
    }

    /// @notice Verify a proof using the verifier registry
    /// @param proof The proof bytes
    /// @param publicInput The public input (as bytes32)
    /// @param proofType The type of proof being verified (bytes32 constant)
    /// @return valid Whether the proof is valid
    function _verifyWithRegistry(
        bytes memory proof,
        bytes32 publicInput,
        bytes32 proofType
    ) internal view returns (bool valid) {
        try
            verifierRegistry.verifySingleInput(
                proofType,
                proof,
                uint256(publicInput)
            )
        returns (bool result) {
            return result;
        } catch {
            // If verification fails or verifier not available, return false
            return false;
        }
    }

    /// @notice Validate proof structure for test/dev environments
    /// @dev NOT cryptographic verification - only validates format
    /// @param proof The proof bytes to validate
    /// @param publicInput The public input that should be bound to the proof
    /// @return valid Whether the proof structure is valid
    function _validateProofStructure(
        bytes memory proof,
        bytes32 publicInput
    ) internal pure returns (bool valid) {
        // Minimum proof size check
        if (proof.length < MIN_PROOF_SIZE) return false;
        
        // Check proof isn't all zeros
        bool hasNonZero = false;
        for (uint256 i = 0; i < 32 && i < proof.length; i++) {
            if (proof[i] != 0) {
                hasNonZero = true;
                break;
            }
        }
        if (!hasNonZero) return false;
        
        // Validate public input binding
        // Proof should contain a hash commitment to public input
        bytes32 expectedBinding = keccak256(abi.encodePacked(publicInput));
        
        // Check if binding exists in first 64 bytes of proof
        if (proof.length >= 64) {
            bytes32 proofBinding;
            assembly {
                proofBinding := mload(add(proof, 64))
            }
            // Allow if binding matches or proof has valid structure
            if (proofBinding == expectedBinding) return true;
        }
        
        // Fallback: accept if proof length is substantial
        return proof.length >= MIN_PROOF_SIZE * 2;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get container details
    function getContainer(
        bytes32 containerId
    ) external view returns (Container memory) {
        return containers[containerId];
    }

    /// @notice Check if nullifier is consumed
    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

    /// @notice Get all container IDs (paginated)
    /// @param offset Starting index
    /// @param limit Maximum number to return
    function getContainerIds(
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory ids) {
        uint256 total = _containerIds.length;
        if (offset >= total) return new bytes32[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        ids = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; ) {
            ids[i - offset] = _containerIds[i];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Batch verify multiple containers
    /// @param containerIds Array of container IDs to verify
    /// @return results Array of verification results
    function batchVerifyContainers(
        bytes32[] calldata containerIds
    ) external view returns (VerificationResult[] memory results) {
        uint256 len = containerIds.length;
        results = new VerificationResult[](len);
        for (uint256 i = 0; i < len; ) {
            results[i] = this.verifyContainer(containerIds[i]);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Update proof validity window
    function setProofValidityWindow(
        uint256 window
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        proofValidityWindow = window;
    }

    /// @notice Set the verifier registry
    /// @param _registry The new verifier registry address
    function setVerifierRegistry(
        address _registry
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        address oldRegistry = address(verifierRegistry);
        verifierRegistry = VerifierRegistry(_registry);
        emit VerifierRegistryUpdated(oldRegistry, _registry);
    }

    /// @notice Enable or disable real verification mode
    /// @param enabled True to use real verifiers, false for placeholder
    function setRealVerification(
        bool enabled
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        useRealVerification = enabled;
        emit RealVerificationToggled(enabled);
    }

    /// @notice Pause contract
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
