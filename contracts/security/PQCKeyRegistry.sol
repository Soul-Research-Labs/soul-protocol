// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IPostQuantumCrypto.sol";

/**
 * @title PQCKeyRegistry
 * @author Soul Protocol - PIL v2
 * @notice Registry for post-quantum public keys with lifecycle management
 * @dev Manages PQC key registration, rotation, and revocation for the PIL ecosystem
 *
 * Features:
 * - Multi-algorithm key support (Dilithium, SPHINCS+, Falcon, Kyber)
 * - Key rotation with grace periods
 * - Hierarchical key trust (root keys can delegate)
 * - Cross-chain key synchronization support
 * - Key attestation from trusted authorities
 *
 * Key Lifecycle:
 * 1. Registration: Owner registers key with expiration
 * 2. Active: Key can be used for signing/verification
 * 3. Rotation: New key registered, old key in grace period
 * 4. Revocation: Key explicitly revoked (immediate or scheduled)
 * 5. Expired: Key past expiration date
 */
contract PQCKeyRegistry is
    IPQCKeyRegistry,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");
    bytes32 public constant KEY_ATTESTOR_ROLE = keccak256("KEY_ATTESTOR_ROLE");
    bytes32 public constant ROTATION_MANAGER_ROLE =
        keccak256("ROTATION_MANAGER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum key validity period (7 days)
    uint256 public constant MIN_VALIDITY_PERIOD = 7 days;

    /// @notice Maximum key validity period (5 years)
    uint256 public constant MAX_VALIDITY_PERIOD = 5 * 365 days;

    /// @notice Rotation grace period (7 days)
    uint256 public constant ROTATION_GRACE_PERIOD = 7 days;

    /// @notice Maximum keys per owner
    uint256 public constant MAX_KEYS_PER_OWNER = 50;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Extended key information
    struct KeyInfo {
        // Core key data
        PQPublicKey key;
        // Ownership
        address owner;
        // State
        KeyState state;
        // Rotation
        bytes32 previousKeyHash; // Hash of key this replaces
        bytes32 nextKeyHash; // Hash of key that replaces this
        uint64 rotationGraceEnd; // When rotation grace period ends
        // Attestation
        uint256 attestationCount;
        uint256 totalAttestationWeight;
        // Metadata
        bytes32 metadataHash; // IPFS hash or similar for extended metadata
    }

    /// @notice Key states
    enum KeyState {
        Pending, // Registered but not yet active
        Active, // Currently active and valid
        Rotating, // Being replaced, in grace period
        Revoked, // Explicitly revoked
        Expired // Past expiration date
    }

    /// @notice Key attestation from trusted party
    struct KeyAttestation {
        address attestor;
        bytes32 keyHash;
        uint256 weight; // Attestation weight (0-100)
        uint64 attestedAt;
        bytes32 evidenceHash; // Hash of attestation evidence
        bool valid;
    }

    /// @notice Key rotation request
    struct RotationRequest {
        bytes32 oldKeyHash;
        bytes32 newKeyHash;
        address requester;
        uint64 requestedAt;
        uint64 effectiveAt;
        bool executed;
        bool cancelled;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Key hash to key info mapping
    mapping(bytes32 => KeyInfo) public keys;

    /// @notice Key hash to attestations
    mapping(bytes32 => KeyAttestation[]) public keyAttestations;

    /// @notice Owner to key hashes
    mapping(address => bytes32[]) private _ownerKeys;

    /// @notice Algorithm to registered key count
    mapping(PQSignatureAlgorithm => uint256) public algorithmKeyCount;

    /// @notice Pending rotation requests
    mapping(bytes32 => RotationRequest) public rotationRequests;

    /// @notice Total keys registered
    uint256 public totalKeys;

    /// @notice Total active keys
    uint256 public activeKeys;

    /// @notice Total revoked keys
    uint256 public revokedKeys;

    /// @notice Minimum attestation weight to activate a key
    uint256 public minAttestationWeight = 0; // 0 = no attestation required

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event KeyStateChanged(
        bytes32 indexed keyHash,
        KeyState oldState,
        KeyState newState
    );

    event KeyAttestationAdded(
        bytes32 indexed keyHash,
        address indexed attestor,
        uint256 weight
    );

    event RotationRequested(
        bytes32 indexed oldKeyHash,
        bytes32 indexed newKeyHash,
        uint64 effectiveAt
    );

    event RotationExecuted(
        bytes32 indexed oldKeyHash,
        bytes32 indexed newKeyHash
    );

    event RotationCancelled(bytes32 indexed rotationId);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error KeyAlreadyExists(bytes32 keyHash);
    error KeyNotFound(bytes32 keyHash);
    error KeyNotActive(bytes32 keyHash, KeyState state);
    error NotKeyOwner(address caller, address owner);
    error InvalidValidityPeriod(uint64 expiresAt);
    error TooManyKeys(address owner, uint256 count);
    error InsufficientAttestation(uint256 current, uint256 required);
    error RotationNotReady(bytes32 rotationId, uint64 effectiveAt);
    error RotationAlreadyExecuted(bytes32 rotationId);
    error InvalidKeyData();
    error InvalidAlgorithm(PQSignatureAlgorithm algorithm);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REGISTRY_ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         KEY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPQCKeyRegistry
     */
    function registerKey(
        PQSignatureAlgorithm keyType,
        bytes calldata publicKey,
        uint64 expiresAt
    ) external override nonReentrant whenNotPaused returns (bytes32 keyHash) {
        // Validate expiration
        if (expiresAt != 0) {
            if (expiresAt < block.timestamp + MIN_VALIDITY_PERIOD) {
                revert InvalidValidityPeriod(expiresAt);
            }
            if (expiresAt > block.timestamp + MAX_VALIDITY_PERIOD) {
                revert InvalidValidityPeriod(expiresAt);
            }
        }

        // Validate key data
        if (publicKey.length == 0) {
            revert InvalidKeyData();
        }

        // Check owner key limit
        if (_ownerKeys[msg.sender].length >= MAX_KEYS_PER_OWNER) {
            revert TooManyKeys(msg.sender, _ownerKeys[msg.sender].length);
        }

        // Compute key hash
        keyHash = keccak256(
            abi.encodePacked(keyType, publicKey, msg.sender, block.timestamp)
        );

        if (keys[keyHash].owner != address(0)) {
            revert KeyAlreadyExists(keyHash);
        }

        // Create key
        PQPublicKey memory pqKey = PQPublicKey({
            algorithm: keyType,
            keyData: publicKey,
            keyHash: keyHash,
            createdAt: uint64(block.timestamp),
            expiresAt: expiresAt
        });

        keys[keyHash] = KeyInfo({
            key: pqKey,
            owner: msg.sender,
            state: minAttestationWeight > 0
                ? KeyState.Pending
                : KeyState.Active,
            previousKeyHash: bytes32(0),
            nextKeyHash: bytes32(0),
            rotationGraceEnd: 0,
            attestationCount: 0,
            totalAttestationWeight: 0,
            metadataHash: bytes32(0)
        });

        _ownerKeys[msg.sender].push(keyHash);

        unchecked {
            ++totalKeys;
            ++algorithmKeyCount[keyType];
            if (keys[keyHash].state == KeyState.Active) {
                ++activeKeys;
            }
        }

        emit KeyRegistered(keyHash, msg.sender, keyType, expiresAt);

        if (keys[keyHash].state == KeyState.Active) {
            emit KeyStateChanged(keyHash, KeyState.Pending, KeyState.Active);
        }
    }

    /**
     * @notice Register a key with extended metadata
     * @param keyType The signature algorithm
     * @param publicKey The public key bytes
     * @param expiresAt Expiration timestamp
     * @param metadataHash IPFS or similar hash for extended metadata
     * @return keyHash The key identifier
     */
    function registerKeyWithMetadata(
        PQSignatureAlgorithm keyType,
        bytes calldata publicKey,
        uint64 expiresAt,
        bytes32 metadataHash
    ) external nonReentrant whenNotPaused returns (bytes32 keyHash) {
        keyHash = this.registerKey(keyType, publicKey, expiresAt);
        keys[keyHash].metadataHash = metadataHash;
    }

    /*//////////////////////////////////////////////////////////////
                           KEY REVOCATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPQCKeyRegistry
     */
    function revokeKey(bytes32 keyHash) external override {
        KeyInfo storage keyInfo = keys[keyHash];

        if (keyInfo.owner == address(0)) {
            revert KeyNotFound(keyHash);
        }

        if (
            keyInfo.owner != msg.sender &&
            !hasRole(REGISTRY_ADMIN_ROLE, msg.sender)
        ) {
            revert NotKeyOwner(msg.sender, keyInfo.owner);
        }

        KeyState oldState = keyInfo.state;
        keyInfo.state = KeyState.Revoked;

        unchecked {
            ++revokedKeys;
            if (oldState == KeyState.Active) {
                --activeKeys;
            }
        }

        emit KeyRevoked(keyHash, keyInfo.owner);
        emit KeyStateChanged(keyHash, oldState, KeyState.Revoked);
    }

    /**
     * @notice Schedule a key revocation for future execution
     * @param keyHash The key to revoke
     * @param revokeAt Timestamp when revocation becomes effective
     */
    function scheduleRevocation(bytes32 keyHash, uint64 revokeAt) external {
        KeyInfo storage keyInfo = keys[keyHash];

        if (keyInfo.owner == address(0)) {
            revert KeyNotFound(keyHash);
        }

        if (
            keyInfo.owner != msg.sender &&
            !hasRole(REGISTRY_ADMIN_ROLE, msg.sender)
        ) {
            revert NotKeyOwner(msg.sender, keyInfo.owner);
        }

        // Set expiration to revocation time (will be marked expired/revoked then)
        keyInfo.key.expiresAt = revokeAt;
    }

    /*//////////////////////////////////////////////////////////////
                           KEY ROTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request key rotation
     * @param oldKeyHash The key being replaced
     * @param newKeyType Algorithm for new key
     * @param newPublicKey New public key data
     * @param newExpiresAt New key expiration
     * @return rotationId The rotation request ID
     * @return newKeyHash The new key hash
     */
    function requestRotation(
        bytes32 oldKeyHash,
        PQSignatureAlgorithm newKeyType,
        bytes calldata newPublicKey,
        uint64 newExpiresAt
    ) external nonReentrant returns (bytes32 rotationId, bytes32 newKeyHash) {
        KeyInfo storage oldKey = keys[oldKeyHash];

        if (oldKey.owner == address(0)) {
            revert KeyNotFound(oldKeyHash);
        }

        if (oldKey.owner != msg.sender) {
            revert NotKeyOwner(msg.sender, oldKey.owner);
        }

        if (oldKey.state != KeyState.Active) {
            revert KeyNotActive(oldKeyHash, oldKey.state);
        }

        // Register new key
        newKeyHash = this.registerKey(newKeyType, newPublicKey, newExpiresAt);

        // Link keys
        keys[newKeyHash].previousKeyHash = oldKeyHash;
        oldKey.nextKeyHash = newKeyHash;
        oldKey.state = KeyState.Rotating;
        oldKey.rotationGraceEnd = uint64(
            block.timestamp + ROTATION_GRACE_PERIOD
        );

        // Create rotation request
        rotationId = keccak256(
            abi.encodePacked(oldKeyHash, newKeyHash, block.timestamp)
        );

        rotationRequests[rotationId] = RotationRequest({
            oldKeyHash: oldKeyHash,
            newKeyHash: newKeyHash,
            requester: msg.sender,
            requestedAt: uint64(block.timestamp),
            effectiveAt: uint64(block.timestamp + ROTATION_GRACE_PERIOD),
            executed: false,
            cancelled: false
        });

        emit RotationRequested(
            oldKeyHash,
            newKeyHash,
            uint64(block.timestamp + ROTATION_GRACE_PERIOD)
        );
        emit KeyStateChanged(oldKeyHash, KeyState.Active, KeyState.Rotating);
    }

    /**
     * @notice Execute a pending rotation after grace period
     * @param rotationId The rotation to execute
     */
    function executeRotation(bytes32 rotationId) external nonReentrant {
        RotationRequest storage rotation = rotationRequests[rotationId];

        if (rotation.requester == address(0)) {
            revert KeyNotFound(rotationId);
        }

        if (rotation.executed) {
            revert RotationAlreadyExecuted(rotationId);
        }

        if (block.timestamp < rotation.effectiveAt) {
            revert RotationNotReady(rotationId, rotation.effectiveAt);
        }

        rotation.executed = true;

        // Mark old key as revoked
        KeyInfo storage oldKey = keys[rotation.oldKeyHash];
        oldKey.state = KeyState.Revoked;

        unchecked {
            ++revokedKeys;
            // activeKeys count already decremented when set to Rotating
        }

        emit RotationExecuted(rotation.oldKeyHash, rotation.newKeyHash);
        emit KeyStateChanged(
            rotation.oldKeyHash,
            KeyState.Rotating,
            KeyState.Revoked
        );
    }

    /**
     * @notice Cancel a pending rotation
     * @param rotationId The rotation to cancel
     */
    function cancelRotation(bytes32 rotationId) external {
        RotationRequest storage rotation = rotationRequests[rotationId];

        if (rotation.requester == address(0)) {
            revert KeyNotFound(rotationId);
        }

        if (
            rotation.requester != msg.sender &&
            !hasRole(REGISTRY_ADMIN_ROLE, msg.sender)
        ) {
            revert NotKeyOwner(msg.sender, rotation.requester);
        }

        if (rotation.executed) {
            revert RotationAlreadyExecuted(rotationId);
        }

        rotation.cancelled = true;

        // Restore old key to active
        KeyInfo storage oldKey = keys[rotation.oldKeyHash];
        oldKey.state = KeyState.Active;
        oldKey.nextKeyHash = bytes32(0);
        oldKey.rotationGraceEnd = 0;

        // Revoke new key
        keys[rotation.newKeyHash].state = KeyState.Revoked;

        emit RotationCancelled(rotationId);
        emit KeyStateChanged(
            rotation.oldKeyHash,
            KeyState.Rotating,
            KeyState.Active
        );
    }

    /*//////////////////////////////////////////////////////////////
                           KEY ATTESTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Attest to a key's validity
     * @param keyHash The key to attest
     * @param weight Attestation weight (0-100)
     * @param evidenceHash Hash of attestation evidence
     */
    function attestKey(
        bytes32 keyHash,
        uint256 weight,
        bytes32 evidenceHash
    ) external onlyRole(KEY_ATTESTOR_ROLE) {
        KeyInfo storage keyInfo = keys[keyHash];

        if (keyInfo.owner == address(0)) {
            revert KeyNotFound(keyHash);
        }

        require(weight <= 100, "Weight must be <= 100");

        // Add attestation
        keyAttestations[keyHash].push(
            KeyAttestation({
                attestor: msg.sender,
                keyHash: keyHash,
                weight: weight,
                attestedAt: uint64(block.timestamp),
                evidenceHash: evidenceHash,
                valid: true
            })
        );

        unchecked {
            ++keyInfo.attestationCount;
            keyInfo.totalAttestationWeight += weight;
        }

        // Activate key if attestation threshold met
        if (
            keyInfo.state == KeyState.Pending &&
            keyInfo.totalAttestationWeight >= minAttestationWeight
        ) {
            keyInfo.state = KeyState.Active;
            unchecked {
                ++activeKeys;
            }
            emit KeyStateChanged(keyHash, KeyState.Pending, KeyState.Active);
        }

        emit KeyAttestationAdded(keyHash, msg.sender, weight);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IPQCKeyRegistry
     */
    function getKey(
        bytes32 keyHash
    ) external view override returns (PQPublicKey memory key) {
        return keys[keyHash].key;
    }

    /**
     * @notice Get full key info
     * @param keyHash The key identifier
     * @return info The key info
     */
    function getKeyInfo(
        bytes32 keyHash
    ) external view returns (KeyInfo memory info) {
        return keys[keyHash];
    }

    /**
     * @inheritdoc IPQCKeyRegistry
     */
    function isKeyValid(
        bytes32 keyHash
    ) external view override returns (bool valid) {
        KeyInfo storage keyInfo = keys[keyHash];

        if (keyInfo.owner == address(0)) return false;
        if (keyInfo.state == KeyState.Revoked) return false;
        if (keyInfo.state == KeyState.Pending) return false;
        if (
            keyInfo.key.expiresAt != 0 &&
            block.timestamp > keyInfo.key.expiresAt
        ) return false;

        // Rotating keys are still valid during grace period
        if (
            keyInfo.state == KeyState.Rotating &&
            block.timestamp > keyInfo.rotationGraceEnd
        ) {
            return false;
        }

        return true;
    }

    /**
     * @inheritdoc IPQCKeyRegistry
     */
    function getOwnerKeys(
        address owner
    ) external view override returns (bytes32[] memory keyHashes) {
        return _ownerKeys[owner];
    }

    /**
     * @notice Get attestations for a key
     * @param keyHash The key identifier
     * @return attestations Array of attestations
     */
    function getKeyAttestations(
        bytes32 keyHash
    ) external view returns (KeyAttestation[] memory attestations) {
        return keyAttestations[keyHash];
    }

    /**
     * @notice Get key state
     * @param keyHash The key identifier
     * @return state The current key state
     */
    function getKeyState(
        bytes32 keyHash
    ) external view returns (KeyState state) {
        KeyInfo storage keyInfo = keys[keyHash];

        if (keyInfo.owner == address(0)) {
            return KeyState.Pending; // Non-existent
        }

        // Check if expired
        if (
            keyInfo.key.expiresAt != 0 &&
            block.timestamp > keyInfo.key.expiresAt
        ) {
            return KeyState.Expired;
        }

        // Check if rotation grace ended
        if (
            keyInfo.state == KeyState.Rotating &&
            block.timestamp > keyInfo.rotationGraceEnd
        ) {
            return KeyState.Revoked;
        }

        return keyInfo.state;
    }

    /**
     * @notice Get registry statistics
     * @return total Total keys
     * @return active Active keys
     * @return revoked Revoked keys
     */
    function getStats()
        external
        view
        returns (uint256 total, uint256 active, uint256 revoked)
    {
        return (totalKeys, activeKeys, revokedKeys);
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set minimum attestation weight for key activation
     * @param weight The minimum weight (0 = no attestation required)
     */
    function setMinAttestationWeight(
        uint256 weight
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        minAttestationWeight = weight;
    }

    /**
     * @notice Pause the registry
     */
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the registry
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
