// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "../interfaces/IProofVerifier.sol";
import "../verifiers/VerifierRegistryV2.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title ProofCarryingContainerUpgradeable (PC³)
/// @author Soul Protocol - Soul v2
/// @notice Upgradeable version of PC³ using UUPS proxy pattern
/// @dev Self-authenticating confidential containers with embedded ZK proofs
contract ProofCarryingContainerUpgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeCast for uint256;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant CONTAINER_ADMIN_ROLE =
        keccak256("CONTAINER_ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Embedded proof bundle
    struct ProofBundle {
        bytes validityProof;
        bytes policyProof;
        bytes nullifierProof;
        bytes32 proofHash;
        uint256 proofTimestamp;
        uint256 proofExpiry;
    }

    /// @notice The self-authenticating container
    struct Container {
        bytes encryptedPayload;
        bytes32 stateCommitment;
        bytes32 nullifier;
        ProofBundle proofs;
        bytes32 policyHash;
        uint64 chainId;
        uint64 createdAt;
        uint32 version;
        bool isVerified;
        bool isConsumed;
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

    /// @notice Default proof validity window (24 hours)
    uint256 public proofValidityWindow;

    /// @notice Maximum payload size (prevent DOS)
    uint256 public constant MAX_PAYLOAD_SIZE = 1 << 20; // 1MB

    /// @notice Minimum proof size for validity
    uint256 public constant MIN_PROOF_SIZE = 256;

    /// @notice Verifier registry for proof verification (V2 with CircuitType enum)
    VerifierRegistryV2 public verifierRegistry;

    /// @notice Whether to use real verification
    bool public useRealVerification;

    /// @notice Contract version for upgrade tracking
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                            STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;

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

    event PolicyAdded(bytes32 indexed policyHash);
    event PolicyRemoved(bytes32 indexed policyHash);
    event VerifierRegistryUpdated(
        address indexed oldRegistry,
        address indexed newRegistry
    );
    event RealVerificationToggled(bool enabled);
    event ContractUpgraded(
        uint256 indexed oldVersion,
        uint256 indexed newVersion
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ContainerAlreadyExists(bytes32 containerId);
    error ContainerNotFound(bytes32 containerId);
    error NullifierAlreadyConsumed(bytes32 nullifier);
    error ProofExpired(uint256 expiry, uint256 current);
    error InvalidProofBundle();
    error UnsupportedPolicy(bytes32 policyHash);
    error VerificationFailed(string reason);
    error ContainerAlreadyConsumed(bytes32 containerId);
    error InvalidContainerData();
    error PayloadTooLarge(uint256 size, uint256 max);
    error ProofTooSmall(uint256 size, uint256 min);

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract (replaces constructor)
    /// @param admin The initial admin address
    function initialize(address admin) public initializer {
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CONTAINER_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        proofValidityWindow = 24 hours;
        contractVersion = 1;
    }

    /*//////////////////////////////////////////////////////////////
                          UPGRADE AUTHORIZATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Authorize upgrade - only UPGRADER_ROLE can upgrade
    function _authorizeUpgrade(
        address /* newImplementation */
    ) internal override onlyRole(UPGRADER_ROLE) {
        uint256 oldVersion = contractVersion;
        contractVersion++;
        emit ContractUpgraded(oldVersion, contractVersion);
    }

    /*//////////////////////////////////////////////////////////////
                          CONTAINER CREATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a new self-authenticating container
    function createContainer(
        bytes calldata encryptedPayload,
        bytes32 stateCommitment,
        bytes32 nullifier,
        ProofBundle calldata proofs,
        bytes32 policyHash
    ) external whenNotPaused nonReentrant returns (bytes32 containerId) {
        if (encryptedPayload.length == 0) revert InvalidContainerData();
        if (encryptedPayload.length > MAX_PAYLOAD_SIZE) {
            revert PayloadTooLarge(encryptedPayload.length, MAX_PAYLOAD_SIZE);
        }
        if (stateCommitment == bytes32(0)) revert InvalidContainerData();
        if (nullifier == bytes32(0)) revert InvalidContainerData();

        if (proofs.validityProof.length < MIN_PROOF_SIZE) {
            revert ProofTooSmall(proofs.validityProof.length, MIN_PROOF_SIZE);
        }

        if (!supportedPolicies[policyHash] && policyHash != bytes32(0)) {
            revert UnsupportedPolicy(policyHash);
        }

        if (consumedNullifiers[nullifier]) {
            revert NullifierAlreadyConsumed(nullifier);
        }

        containerId = _computeContainerId(
            stateCommitment,
            nullifier,
            block.chainid.toUint64()
        );

        if (containers[containerId].createdAt != 0) {
            revert ContainerAlreadyExists(containerId);
        }

        bytes32 computedProofHash = keccak256(
            abi.encodePacked(
                proofs.validityProof,
                proofs.policyProof,
                proofs.nullifierProof
            )
        );
        if (computedProofHash != proofs.proofHash) {
            revert InvalidProofBundle();
        }

        containers[containerId] = Container({
            encryptedPayload: encryptedPayload,
            stateCommitment: stateCommitment,
            nullifier: nullifier,
            proofs: proofs,
            policyHash: policyHash,
            chainId: block.chainid.toUint64(),
            createdAt: uint64(block.timestamp),
            version: 1,
            isVerified: false,
            isConsumed: false
        });

        _containerIds.push(containerId);

        unchecked {
            ++totalContainers;
        }

        emit ContainerCreated(
            containerId,
            stateCommitment,
            nullifier,
            policyHash,
            block.chainid.toUint64()
        );
    }

    /*//////////////////////////////////////////////////////////////
                          CONTAINER VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify a container's embedded proofs
    function verifyContainer(
        bytes32 containerId
    ) external view returns (VerificationResult memory result) {
        Container storage container = containers[containerId];

        if (container.createdAt == 0) {
            result.failureReason = "Container not found";
            return result;
        }

        if (
            container.proofs.proofExpiry != 0 &&
            block.timestamp > container.proofs.proofExpiry
        ) {
            result.failureReason = "Proof expired";
            return result;
        }
        result.notExpired = true;

        if (container.isConsumed) {
            result.failureReason = "Container already consumed";
            return result;
        }
        result.notConsumed = true;

        bytes32 computedProofHash = keccak256(
            abi.encodePacked(
                container.proofs.validityProof,
                container.proofs.policyProof,
                container.proofs.nullifierProof
            )
        );

        if (computedProofHash != container.proofs.proofHash) {
            result.failureReason = "Proof integrity check failed";
            return result;
        }

        ProofBundle storage proofs = container.proofs;

        if (useRealVerification && address(verifierRegistry) != address(0)) {
            result.validityValid = _verifyWithRegistry(
                proofs.validityProof,
                container.stateCommitment,
                VerifierRegistryV2.CircuitType.STATE_TRANSFER
            );
            result.policyValid =
                container.policyHash == bytes32(0) ||
                _verifyWithRegistry(
                    proofs.policyProof,
                    container.policyHash,
                    VerifierRegistryV2.CircuitType.POLICY
                );
            result.nullifierValid = _verifyWithRegistry(
                proofs.nullifierProof,
                container.nullifier,
                VerifierRegistryV2.CircuitType.NULLIFIER
            );
        } else {
            // No real verification configured — reject all proofs
            // Call setRealVerification(true) and setVerifierRegistry() to enable
            revert(
                "Real verification not enabled: configure VerifierRegistryV2"
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

    /// @notice Consume a verified container
    function consumeContainer(
        bytes32 containerId
    ) external whenNotPaused nonReentrant onlyRole(VERIFIER_ROLE) {
        Container storage container = containers[containerId];

        if (container.createdAt == 0) {
            revert ContainerNotFound(containerId);
        }

        if (container.isConsumed) {
            revert ContainerAlreadyConsumed(containerId);
        }

        if (consumedNullifiers[container.nullifier]) {
            revert NullifierAlreadyConsumed(container.nullifier);
        }

        container.isConsumed = true;
        consumedNullifiers[container.nullifier] = true;

        emit ContainerConsumed(containerId, container.nullifier, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _computeContainerId(
        bytes32 stateCommitment,
        bytes32 nullifier,
        uint64 chainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(stateCommitment, nullifier, chainId));
    }

    function _verifyWithRegistry(
        bytes memory proof,
        bytes32 publicInput,
        VerifierRegistryV2.CircuitType circuitType
    ) internal view returns (bool valid) {
        try
            verifierRegistry.verify(
                circuitType,
                proof,
                abi.encode(uint256(publicInput))
            )
        returns (bool result) {
            return result;
        } catch {
            return false;
        }
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getContainer(
        bytes32 containerId
    ) external view returns (Container memory) {
        return containers[containerId];
    }

    function isNullifierConsumed(
        bytes32 nullifier
    ) external view returns (bool) {
        return consumedNullifiers[nullifier];
    }

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

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function addPolicy(
        bytes32 policyHash
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        supportedPolicies[policyHash] = true;
        emit PolicyAdded(policyHash);
    }

    function removePolicy(
        bytes32 policyHash
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        supportedPolicies[policyHash] = false;
        emit PolicyRemoved(policyHash);
    }

    function setProofValidityWindow(
        uint256 window
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        proofValidityWindow = window;
    }

    function setVerifierRegistry(
        address _registry
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        address oldRegistry = address(verifierRegistry);
        verifierRegistry = VerifierRegistryV2(_registry);
        emit VerifierRegistryUpdated(oldRegistry, _registry);
    }

    function setRealVerification(
        bool enabled
    ) external onlyRole(CONTAINER_ADMIN_ROLE) {
        useRealVerification = enabled;
        emit RealVerificationToggled(enabled);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Get the implementation version
    function getImplementationVersion() external pure returns (string memory) {
        return "1.0.0";
    }
}
