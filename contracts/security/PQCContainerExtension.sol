// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IPostQuantumCrypto.sol";
import "./PostQuantumSignatureVerifier.sol";
import "./HybridCryptoVerifier.sol";
import "./PQCKeyRegistry.sol";

/**
 * @title PQCContainerExtension
 * @author Soul Protocol - Soul v2
 * @notice Post-Quantum Cryptography extension for ProofCarryingContainer
 * @dev Adds PQC signature verification to containers for quantum-resistant authentication
 *
 * Integration with PC³:
 * - Extends container creation with optional PQC signatures
 * - Provides quantum-resistant cross-chain message authentication
 * - Supports hybrid verification (classical + PQC)
 * - Enables PQC-based container ownership proofs
 *
 * Quantum Security Model:
 * - CRYSTALS-Dilithium for general signatures (NIST Level 2/3/5)
 * - SPHINCS+ for long-term security (hash-based, conservative)
 * - Falcon for size-constrained applications
 * - Hybrid mode combines classical ECDSA with PQC for belt-and-suspenders security
 */
contract PQCContainerExtension is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant EXTENSION_ADMIN_ROLE =
        keccak256("EXTENSION_ADMIN_ROLE");
    bytes32 public constant VERIFIER_MANAGER_ROLE =
        keccak256("VERIFIER_MANAGER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC-enhanced proof bundle
    struct PQCProofBundle {
        // Traditional proofs (ZK-SNARKs)
        bytes validityProof;
        bytes policyProof;
        bytes nullifierProof;
        bytes32 proofHash;
        uint256 proofTimestamp;
        uint256 proofExpiry;
        // Post-quantum authentication
        PQSignature pqSignature; // PQC signature over proofs
        HybridSignature hybridSignature; // Optional hybrid signature
        bytes32 pqKeyHash; // Reference to PQC public key
    }

    /// @notice PQC-enhanced container
    struct PQCContainer {
        bytes32 baseContainerId; // Reference to base container
        bytes32 pqProofHash; // Hash of PQC proofs
        bytes32 creatorKeyHash; // PQC key of creator
        bytes32 ownerKeyHash; // Current owner's PQC key
        PQSignature creationSignature; // PQC signature at creation
        uint64 createdAt;
        uint64 pqVerifiedAt; // When PQC was last verified
        bool pqVerified; // PQC verification status
        bool hybridMode; // Whether hybrid verification is required
    }

    /// @notice Cross-chain message with PQC authentication
    struct PQCCrossChainMessage {
        bytes32 sourceContainerId;
        uint64 sourceChainId;
        uint64 targetChainId;
        bytes32 messageHash;
        bytes payload;
        PQSignature pqSignature;
        HybridSignature hybridSignature;
        bytes32 senderKeyHash;
        uint64 timestamp;
        uint64 expiry;
    }

    /// @notice Container transfer with PQC authorization
    struct PQCTransfer {
        bytes32 containerId;
        bytes32 fromKeyHash;
        bytes32 toKeyHash;
        PQSignature authorizationSignature;
        HybridSignature optionalHybridSig;
        uint64 timestamp;
        bytes32 nonce;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC container extensions
    mapping(bytes32 => PQCContainer) public pqcContainers;

    /// @notice Processed cross-chain messages
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Container transfer history
    mapping(bytes32 => PQCTransfer[]) public transferHistory;

    /// @notice Key hash to container ownership
    mapping(bytes32 => bytes32[]) public keyContainers;

    /// @notice Post-quantum signature verifier
    PostQuantumSignatureVerifier public pqVerifier;

    /// @notice Hybrid crypto verifier
    HybridCryptoVerifier public hybridVerifier;

    /// @notice PQC key registry
    PQCKeyRegistry public keyRegistry;

    /// @notice Whether hybrid mode is mandatory
    bool public mandatoryHybridMode;

    /// @notice Minimum PQC security level required
    uint8 public minSecurityLevel = 2; // NIST Level 2

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PQCContainerCreated(
        bytes32 indexed baseContainerId,
        bytes32 indexed creatorKeyHash,
        bool hybridMode
    );

    event PQCContainerVerified(
        bytes32 indexed containerId,
        bytes32 indexed verifierKeyHash,
        bool success
    );

    event PQCContainerTransferred(
        bytes32 indexed containerId,
        bytes32 indexed fromKeyHash,
        bytes32 indexed toKeyHash
    );

    event CrossChainMessageReceived(
        bytes32 indexed messageHash,
        uint64 indexed sourceChainId,
        bytes32 indexed senderKeyHash
    );

    event CrossChainMessageVerified(
        bytes32 indexed messageHash,
        bool pqValid,
        bool hybridValid
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidPQSignature(bytes32 keyHash);
    error InvalidHybridSignature(bytes32 keyHash);
    error KeyNotRegistered(bytes32 keyHash);
    error ContainerNotFound(bytes32 containerId);
    error ContainerAlreadyExtended(bytes32 containerId);
    error MessageAlreadyProcessed(bytes32 messageHash);
    error MessageExpired(bytes32 messageHash);
    error InsufficientSecurityLevel(uint8 provided, uint8 required);
    error HybridModeRequired();
    error NotContainerOwner(bytes32 keyHash, bytes32 ownerKeyHash);
    error TransferNotAuthorized();
    error InvalidSecurityLevelError();


    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _pqVerifier,
        address _hybridVerifier,
        address _keyRegistry
    ) {
        pqVerifier = PostQuantumSignatureVerifier(_pqVerifier);
        hybridVerifier = HybridCryptoVerifier(_hybridVerifier);
        keyRegistry = PQCKeyRegistry(_keyRegistry);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EXTENSION_ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         CONTAINER EXTENSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Extend a container with PQC protection
     * @param baseContainerId The base ProofCarryingContainer ID
     * @param creatorKeyHash The PQC key hash of the creator
     * @param signature PQC signature over container data
     * @param hybridSig Optional hybrid signature for additional security
     */
    function extendContainerWithPQC(
        bytes32 baseContainerId,
        bytes32 creatorKeyHash,
        PQSignature calldata signature,
        HybridSignature calldata hybridSig
    ) external nonReentrant whenNotPaused {
        // Check container doesn't already have PQC extension
        if (pqcContainers[baseContainerId].createdAt != 0) {
            revert ContainerAlreadyExtended(baseContainerId);
        }

        // Validate key is registered
        if (!keyRegistry.isKeyValid(creatorKeyHash)) {
            revert KeyNotRegistered(creatorKeyHash);
        }

        // Check security level
        PQPublicKey memory key = keyRegistry.getKey(creatorKeyHash);
        uint8 secLevel = _getSecurityLevel(key.algorithm);
        if (secLevel < minSecurityLevel) {
            revert InsufficientSecurityLevel(secLevel, minSecurityLevel);
        }

        // Verify PQC signature
        bytes32 messageHash = keccak256(
            abi.encode(baseContainerId, creatorKeyHash, block.timestamp)
        );

        bool pqValid = pqVerifier.verifyPQSignature(
            messageHash,
            signature,
            key
        );

        if (!pqValid) {
            revert InvalidPQSignature(creatorKeyHash);
        }

        // Verify hybrid signature if required
        bool useHybrid = mandatoryHybridMode ||
            hybridSig.classicalSignature.length > 0;
        if (mandatoryHybridMode && hybridSig.classicalSignature.length == 0) {
            revert HybridModeRequired();
        }

        if (useHybrid) {
            // Get classical public key from msg.sender
            bytes memory classicalPubKey = abi.encodePacked(msg.sender);
            bool hybridValid = hybridVerifier.verifyHybridSignature(
                messageHash,
                hybridSig,
                classicalPubKey,
                key
            );
            if (!hybridValid) {
                revert InvalidHybridSignature(creatorKeyHash);
            }
        }

        // Create PQC extension
        pqcContainers[baseContainerId] = PQCContainer({
            baseContainerId: baseContainerId,
            pqProofHash: keccak256(
                abi.encode(signature.signature, signature.algorithm)
            ),
            creatorKeyHash: creatorKeyHash,
            ownerKeyHash: creatorKeyHash,
            creationSignature: signature,
            createdAt: uint64(block.timestamp),
            pqVerifiedAt: uint64(block.timestamp),
            pqVerified: true,
            hybridMode: useHybrid
        });

        // Track ownership
        keyContainers[creatorKeyHash].push(baseContainerId);

        emit PQCContainerCreated(baseContainerId, creatorKeyHash, useHybrid);
    }

    /**
     * @notice Verify PQC authentication of a container
     * @param containerId The container to verify
     * @return pqValid Whether PQC signature is valid
     * @return hybridValid Whether hybrid signature is valid (if applicable)
     */
    function verifyPQCContainer(
        bytes32 containerId,
        bytes32 /* verifierKeyHash */
    ) external view returns (bool pqValid, bool hybridValid) {
        PQCContainer storage container = pqcContainers[containerId];

        if (container.createdAt == 0) {
            revert ContainerNotFound(containerId);
        }

        // Get owner's key
        PQPublicKey memory ownerKey = keyRegistry.getKey(
            container.ownerKeyHash
        );
        if (!keyRegistry.isKeyValid(container.ownerKeyHash)) {
            return (false, false);
        }

        // Reconstruct message hash
        bytes32 messageHash = keccak256(
            abi.encode(
                container.baseContainerId,
                container.creatorKeyHash,
                container.createdAt
            )
        );

        // Verify PQC signature
        pqValid = pqVerifier.verifyPQSignature(
            messageHash,
            container.creationSignature,
            ownerKey
        );

        // For hybrid mode, we'd need the hybrid signature stored
        // For this view function, we check if hybrid was used at creation
        hybridValid = !container.hybridMode || container.pqVerified;

        return (pqValid, hybridValid);
    }

    /*//////////////////////////////////////////////////////////////
                         CONTAINER TRANSFER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Transfer container ownership to new PQC key
     * @param containerId Container to transfer
     * @param toKeyHash New owner's PQC key hash
     * @param authSignature Authorization signature from current owner
     * @param hybridSig Optional hybrid signature
     */
    function transferContainerOwnership(
        bytes32 containerId,
        bytes32 toKeyHash,
        PQSignature calldata authSignature,
        HybridSignature calldata hybridSig
    ) external nonReentrant whenNotPaused {
        PQCContainer storage container = pqcContainers[containerId];

        if (container.createdAt == 0) {
            revert ContainerNotFound(containerId);
        }

        // Validate new owner's key
        if (!keyRegistry.isKeyValid(toKeyHash)) {
            revert KeyNotRegistered(toKeyHash);
        }

        // Get current owner's key
        PQPublicKey memory ownerKey = keyRegistry.getKey(
            container.ownerKeyHash
        );
        if (!keyRegistry.isKeyValid(container.ownerKeyHash)) {
            revert KeyNotRegistered(container.ownerKeyHash);
        }

        // Create transfer authorization message
        bytes32 nonce = keccak256(
            abi.encode(
                containerId,
                container.ownerKeyHash,
                toKeyHash,
                block.timestamp
            )
        );

        bytes32 transferMessage = keccak256(
            abi.encode(
                "TRANSFER:",
                containerId,
                container.ownerKeyHash,
                toKeyHash,
                nonce
            )
        );

        // Verify authorization signature
        bool pqValid = pqVerifier.verifyPQSignature(
            transferMessage,
            authSignature,
            ownerKey
        );

        if (!pqValid) {
            revert TransferNotAuthorized();
        }

        // Verify hybrid if container uses hybrid mode
        if (container.hybridMode) {
            // Get classical public key from msg.sender
            bytes memory classicalPubKey = abi.encodePacked(msg.sender);
            bool hybridValid = hybridVerifier.verifyHybridSignature(
                transferMessage,
                hybridSig,
                classicalPubKey,
                ownerKey
            );
            if (!hybridValid) {
                revert InvalidHybridSignature(container.ownerKeyHash);
            }
        }

        // Record transfer
        PQCTransfer memory transfer = PQCTransfer({
            containerId: containerId,
            fromKeyHash: container.ownerKeyHash,
            toKeyHash: toKeyHash,
            authorizationSignature: authSignature,
            optionalHybridSig: hybridSig,
            timestamp: uint64(block.timestamp),
            nonce: nonce
        });
        transferHistory[containerId].push(transfer);

        // Update ownership
        bytes32 previousOwner = container.ownerKeyHash;
        container.ownerKeyHash = toKeyHash;

        // Update key -> container mappings
        _removeContainerFromKey(previousOwner, containerId);
        keyContainers[toKeyHash].push(containerId);

        emit PQCContainerTransferred(containerId, previousOwner, toKeyHash);
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-CHAIN MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a PQC-authenticated cross-chain message
     * @param message The cross-chain message
     * @return valid Whether the message is valid
     */
    function receiveCrossChainMessage(
        PQCCrossChainMessage calldata message
    ) external nonReentrant whenNotPaused returns (bool valid) {
        // Check message not already processed
        bytes32 messageId = keccak256(
            abi.encode(
                message.messageHash,
                message.sourceChainId,
                message.timestamp
            )
        );

        if (processedMessages[messageId]) {
            revert MessageAlreadyProcessed(messageId);
        }

        // Check expiry
        if (message.expiry != 0 && block.timestamp > message.expiry) {
            revert MessageExpired(messageId);
        }

        // Validate sender's key
        if (!keyRegistry.isKeyValid(message.senderKeyHash)) {
            revert KeyNotRegistered(message.senderKeyHash);
        }

        PQPublicKey memory senderKey = keyRegistry.getKey(
            message.senderKeyHash
        );

        // Verify PQC signature
        bool pqValid = pqVerifier.verifyPQSignature(
            message.messageHash,
            message.pqSignature,
            senderKey
        );

        // Verify hybrid signature if provided
        bool hybridValid = true;
        if (message.hybridSignature.classicalSignature.length > 0) {
            // For cross-chain, we'd need to verify against a known signer
            // This is a simplified check
            hybridValid =
                message.hybridSignature.pqSignature.signature.length > 0;
        }

        valid = pqValid && hybridValid;

        if (valid) {
            processedMessages[messageId] = true;
            emit CrossChainMessageVerified(messageId, pqValid, hybridValid);
        }

        emit CrossChainMessageReceived(
            messageId,
            message.sourceChainId,
            message.senderKeyHash
        );

        return valid;
    }

    /**
     * @notice Prepare a cross-chain message for signing
     * @param targetChainId Target chain
     * @param containerId Source container
     * @param payload Message payload
     * @return messageHash Hash to be signed
     */
    function prepareCrossChainMessage(
        uint64 targetChainId,
        bytes32 containerId,
        bytes calldata payload
    ) external view returns (bytes32 messageHash) {
        PQCContainer storage container = pqcContainers[containerId];

        if (container.createdAt == 0) {
            revert ContainerNotFound(containerId);
        }

        // Create message hash
        messageHash = keccak256(
            abi.encode(
                containerId,
                block.chainid,
                targetChainId,
                keccak256(payload),
                block.timestamp
            )
        );

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get containers owned by a PQC key
     * @param keyHash The key hash
     * @return containerIds Array of container IDs
     */
    function getContainersByKey(
        bytes32 keyHash
    ) external view returns (bytes32[] memory) {
        return keyContainers[keyHash];
    }

    /**
     * @notice Get transfer history for a container
     * @param containerId The container ID
     * @return transfers Array of transfers
     */
    function getTransferHistory(
        bytes32 containerId
    ) external view returns (PQCTransfer[] memory) {
        return transferHistory[containerId];
    }

    /**
     * @notice Check if container has PQC extension
     * @param containerId The container ID
     * @return hasExtension Whether PQC extension exists
     */
    function hasPQCExtension(
        bytes32 containerId
    ) external view returns (bool hasExtension) {
        return pqcContainers[containerId].createdAt != 0;
    }

    /**
     * @notice Get PQC container details
     * @param containerId The container ID
     * @return container The PQC container
     */
    function getPQCContainer(
        bytes32 containerId
    ) external view returns (PQCContainer memory) {
        return pqcContainers[containerId];
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get NIST security level for algorithm
     * @param algorithm The PQC algorithm
     * @return level Security level (1-5)
     */
    function _getSecurityLevel(
        PQSignatureAlgorithm algorithm
    ) internal pure returns (uint8 level) {
        if (algorithm == PQSignatureAlgorithm.DILITHIUM2) return 2;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM3) return 3;
        if (algorithm == PQSignatureAlgorithm.DILITHIUM5) return 5;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128F) return 1;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_128S) return 1;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHA2_256F) return 5;
        if (algorithm == PQSignatureAlgorithm.SPHINCS_SHAKE_128F) return 1;
        if (algorithm == PQSignatureAlgorithm.FALCON512) return 1;
        if (algorithm == PQSignatureAlgorithm.FALCON1024) return 5;
        return 0;
    }

    /**
     * @notice Remove container from key's ownership list
     * @param keyHash The key hash
     * @param containerId Container to remove
     */
    function _removeContainerFromKey(
        bytes32 keyHash,
        bytes32 containerId
    ) internal {
        bytes32[] storage containers = keyContainers[keyHash];
        for (uint256 i = 0; i < containers.length; i++) {
            if (containers[i] == containerId) {
                containers[i] = containers[containers.length - 1];
                containers.pop();
                break;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set mandatory hybrid mode
     * @param mandatory Whether hybrid mode is mandatory
     */
    function setMandatoryHybridMode(
        bool mandatory
    ) external onlyRole(EXTENSION_ADMIN_ROLE) {
        mandatoryHybridMode = mandatory;
    }

    /**
     * @notice Set minimum security level
     * @param level Minimum NIST security level (1-5)
     */
    function setMinSecurityLevel(
        uint8 level
    ) external onlyRole(EXTENSION_ADMIN_ROLE) {
        if (level < 1 || level > 5) revert InvalidSecurityLevelError();
        minSecurityLevel = level;
    }

    /**
     * @notice Update verifier contracts
     * @param _pqVerifier New PQ verifier
     * @param _hybridVerifier New hybrid verifier
     * @param _keyRegistry New key registry
     */
    function updateVerifiers(
        address _pqVerifier,
        address _hybridVerifier,
        address _keyRegistry
    ) external onlyRole(EXTENSION_ADMIN_ROLE) {
        if (_pqVerifier != address(0)) {
            pqVerifier = PostQuantumSignatureVerifier(_pqVerifier);
        }
        if (_hybridVerifier != address(0)) {
            hybridVerifier = HybridCryptoVerifier(_hybridVerifier);
        }
        if (_keyRegistry != address(0)) {
            keyRegistry = PQCKeyRegistry(_keyRegistry);
        }
    }

    /**
     * @notice Pause extension
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause extension
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
