// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

/**
 * @title PQCProtectedLock
 * @author Soul Protocol
 * @notice Extension for ZK-SLocks with post-quantum cryptographic protection
 * @dev Adds hybrid signature verification to lock operations, providing
 *      quantum-resistant security for high-value or long-duration locks.
 *
 * Security Model:
 * - Lock creation requires classical ECDSA (backwards compatible)
 * - Lock unlocking can optionally require hybrid verification
 * - Key rotation supports PQC migration path
 * - Emergency recovery with time-locked PQC signatures
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../pqc/PQCRegistry.sol";
import "../pqc/lib/HybridSignatureLib.sol";

interface IZKBoundStateLocks {
    struct Lock {
        bytes32 stateRoot;
        bytes32 nullifierHash;
        address owner;
        uint64 createdAt;
        uint64 expiresAt;
        bool isUnlocked;
    }

    function getLock(bytes32 lockId) external view returns (Lock memory);

    function createLock(
        bytes32 stateRoot,
        bytes32 commitment,
        bytes32 nullifierHash,
        bytes32 zkProof,
        uint64 duration
    ) external returns (bytes32 lockId);
}

contract PQCProtectedLock is AccessControl, Pausable, ReentrancyGuard {
    using HybridSignatureLib for bytes;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Minimum value for mandatory PQC protection
    uint256 public constant PQC_THRESHOLD_VALUE = 10 ether;

    /// @notice Minimum duration for mandatory PQC protection (30 days)
    uint64 public constant PQC_THRESHOLD_DURATION = 30 days;

    /// @notice EIP-712 domain separator
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice Typehash for unlock authorization
    bytes32 public constant UNLOCK_TYPEHASH =
        keccak256(
            "UnlockAuthorization(bytes32 lockId,address recipient,uint256 nonce,uint256 deadline)"
        );

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice PQC protection configuration for a lock
     */
    struct PQCLockConfig {
        bytes32 pqPublicKeyHash; // Hash of the PQ public key
        PQCRegistry.PQCPrimitive algorithm; // Which PQ algorithm
        bool requireHybrid; // Must verify both classical + PQ
        bool requirePQOnly; // Only PQ required (future)
        uint64 pqRegisteredAt; // When PQC was configured
        uint256 recoveryDelay; // Time delay for emergency recovery
    }

    /**
     * @notice Unlock authorization with hybrid signature
     */
    struct UnlockAuth {
        bytes32 lockId;
        address recipient;
        uint256 deadline;
        bytes classicalSig;
        bytes pqSignature;
        bytes pqPublicKey;
    }

    // =============================================================================
    // STATE
    // =============================================================================

    /// @notice PQC Registry for signature verification
    PQCRegistry public pqcRegistry;

    /// @notice Underlying ZK-SLocks contract
    IZKBoundStateLocks public zkSlocks;

    /// @notice PQC configuration per lock
    mapping(bytes32 => PQCLockConfig) public lockPQCConfigs;

    /// @notice Nonces for replay protection
    mapping(address => uint256) public nonces;

    /// @notice Lock values for threshold determination
    mapping(bytes32 => uint256) public lockValues;

    /// @notice Pending emergency recoveries
    mapping(bytes32 => uint256) public pendingRecoveries;

    /// @notice Whether PQC is mandatory for new high-value locks
    bool public pqcMandatoryForHighValue;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event PQCConfigured(
        bytes32 indexed lockId,
        bytes32 indexed pqPublicKeyHash,
        PQCRegistry.PQCPrimitive algorithm,
        bool requireHybrid
    );

    event PQCUnlockVerified(
        bytes32 indexed lockId,
        address indexed unlocker,
        bool hybridVerified
    );

    event EmergencyRecoveryInitiated(
        bytes32 indexed lockId,
        address indexed initiator,
        uint256 executeAfter
    );

    event EmergencyRecoveryExecuted(
        bytes32 indexed lockId,
        address indexed recipient
    );

    event EmergencyRecoveryCancelled(bytes32 indexed lockId);

    // =============================================================================
    // ERRORS
    // =============================================================================

    error PQCNotConfigured();
    error HybridVerificationFailed();
    error PQVerificationFailed();
    error ClassicalVerificationFailed();
    error SignatureExpired();
    error InvalidNonce();
    error RecoveryNotPending();
    error RecoveryDelayNotMet();
    error PQCRequired();
    error InvalidLock();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor(address _pqcRegistry, address _zkSlocks) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        pqcRegistry = PQCRegistry(_pqcRegistry);
        zkSlocks = IZKBoundStateLocks(_zkSlocks);

        pqcMandatoryForHighValue = true;

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("SoulPQCProtectedLock"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    // =============================================================================
    // PQC CONFIGURATION
    // =============================================================================

    /**
     * @notice Configure PQC protection for an existing lock
     * @param lockId The lock to protect
     * @param pqPublicKey The post-quantum public key
     * @param algorithm The PQ algorithm to use
     * @param requireHybrid Whether to require both classical + PQ verification
     * @param recoveryDelay Time delay for emergency recovery (0 = no recovery)
     */
    function configurePQC(
        bytes32 lockId,
        bytes calldata pqPublicKey,
        PQCRegistry.PQCPrimitive algorithm,
        bool requireHybrid,
        uint256 recoveryDelay
    ) external whenNotPaused {
        IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);
        if (lock.owner != msg.sender) revert InvalidLock();
        if (lock.isUnlocked) revert InvalidLock();

        bytes32 pqKeyHash = keccak256(pqPublicKey);

        lockPQCConfigs[lockId] = PQCLockConfig({
            pqPublicKeyHash: pqKeyHash,
            algorithm: algorithm,
            requireHybrid: requireHybrid,
            requirePQOnly: false,
            pqRegisteredAt: uint64(block.timestamp),
            recoveryDelay: recoveryDelay
        });

        emit PQCConfigured(lockId, pqKeyHash, algorithm, requireHybrid);
    }

    /**
     * @notice Configure PQC for a new lock with value tracking
     * @param lockId The lock ID
     * @param value The value locked
     * @param pqPublicKey The PQ public key (optional if value below threshold)
     * @param algorithm The algorithm
     */
    function configureNewLockPQC(
        bytes32 lockId,
        uint256 value,
        bytes calldata pqPublicKey,
        PQCRegistry.PQCPrimitive algorithm
    ) external whenNotPaused {
        IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);
        if (lock.owner != msg.sender) revert InvalidLock();

        lockValues[lockId] = value;

        // Check if PQC is mandatory
        bool requirePQC = _requiresPQC(value, lock.expiresAt - lock.createdAt);

        if (requirePQC && pqPublicKey.length == 0) {
            revert PQCRequired();
        }

        if (pqPublicKey.length > 0) {
            bytes32 pqKeyHash = keccak256(pqPublicKey);
            lockPQCConfigs[lockId] = PQCLockConfig({
                pqPublicKeyHash: pqKeyHash,
                algorithm: algorithm,
                requireHybrid: true,
                requirePQOnly: false,
                pqRegisteredAt: uint64(block.timestamp),
                recoveryDelay: 7 days
            });

            emit PQCConfigured(lockId, pqKeyHash, algorithm, true);
        }
    }

    // =============================================================================
    // HYBRID UNLOCK VERIFICATION
    // =============================================================================

    /**
     * @notice Verify a hybrid unlock authorization
     * @param auth The unlock authorization with signatures
     * @return valid True if authorization is valid
     */
    function verifyUnlockAuth(
        UnlockAuth calldata auth
    ) public returns (bool valid) {
        if (block.timestamp > auth.deadline) revert SignatureExpired();

        IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(auth.lockId);
        if (lock.owner == address(0)) revert InvalidLock();

        PQCLockConfig storage config = lockPQCConfigs[auth.lockId];

        // Build message hash
        bytes32 structHash = keccak256(
            abi.encode(
                UNLOCK_TYPEHASH,
                auth.lockId,
                auth.recipient,
                nonces[lock.owner],
                auth.deadline
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        // Verify classical signature
        if (
            !HybridSignatureLib.verifyECDSA(
                digest,
                auth.classicalSig,
                lock.owner
            )
        ) {
            revert ClassicalVerificationFailed();
        }

        // If PQC is configured, verify PQ signature
        if (config.pqPublicKeyHash != bytes32(0)) {
            // Verify PQ public key matches
            if (keccak256(auth.pqPublicKey) != config.pqPublicKeyHash) {
                revert PQVerificationFailed();
            }

            // Verify through registry
            bool pqValid = pqcRegistry.verifySignature(
                lock.owner,
                digest,
                auth.pqSignature,
                auth.pqPublicKey
            );

            if (config.requireHybrid && !pqValid) {
                revert HybridVerificationFailed();
            }

            emit PQCUnlockVerified(auth.lockId, msg.sender, pqValid);
        }

        nonces[lock.owner]++;
        return true;
    }

    /**
     * @notice Execute unlock with hybrid verification
     * @param auth The unlock authorization
     */
    function executeHybridUnlock(
        UnlockAuth calldata auth
    ) external nonReentrant whenNotPaused {
        if (!verifyUnlockAuth(auth)) {
            revert HybridVerificationFailed();
        }

        // The actual unlock would be done on the ZK-SLocks contract
        // This contract only handles authorization verification
    }

    // =============================================================================
    // EMERGENCY RECOVERY
    // =============================================================================

    /**
     * @notice Initiate emergency recovery with time delay
     * @param lockId The lock to recover
     * @param pqSignature PQ signature for authorization
     * @param pqPublicKey The PQ public key
     */
    function initiateRecovery(
        bytes32 lockId,
        bytes calldata pqSignature,
        bytes calldata pqPublicKey
    ) external whenNotPaused {
        PQCLockConfig storage config = lockPQCConfigs[lockId];
        if (config.pqPublicKeyHash == bytes32(0)) revert PQCNotConfigured();
        if (config.recoveryDelay == 0) revert PQCNotConfigured();

        IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);

        // Verify PQ signature
        bytes32 recoveryHash = keccak256(
            abi.encode("EmergencyRecovery", lockId, msg.sender, block.timestamp)
        );

        if (keccak256(pqPublicKey) != config.pqPublicKeyHash) {
            revert PQVerificationFailed();
        }

        bool pqValid = pqcRegistry.verifySignature(
            lock.owner,
            recoveryHash,
            pqSignature,
            pqPublicKey
        );

        if (!pqValid) revert PQVerificationFailed();

        uint256 executeAfter = block.timestamp + config.recoveryDelay;
        pendingRecoveries[lockId] = executeAfter;

        emit EmergencyRecoveryInitiated(lockId, msg.sender, executeAfter);
    }

    /**
     * @notice Execute pending recovery after delay
     * @param lockId The lock to recover
     * @param recipient Where to send recovered assets
     */
    function executeRecovery(
        bytes32 lockId,
        address recipient
    ) external nonReentrant {
        uint256 executeAfter = pendingRecoveries[lockId];
        if (executeAfter == 0) revert RecoveryNotPending();
        if (block.timestamp < executeAfter) revert RecoveryDelayNotMet();

        delete pendingRecoveries[lockId];

        // Execute recovery logic...

        emit EmergencyRecoveryExecuted(lockId, recipient);
    }

    /**
     * @notice Cancel a pending recovery
     * @param lockId The lock
     * @param classicalSig Classical signature from owner
     */
    function cancelRecovery(
        bytes32 lockId,
        bytes calldata classicalSig
    ) external {
        if (pendingRecoveries[lockId] == 0) revert RecoveryNotPending();

        IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);

        bytes32 cancelHash = keccak256(
            abi.encode("CancelRecovery", lockId, block.timestamp)
        );
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", cancelHash)
        );

        if (
            !HybridSignatureLib.verifyECDSA(ethHash, classicalSig, lock.owner)
        ) {
            revert ClassicalVerificationFailed();
        }

        delete pendingRecoveries[lockId];

        emit EmergencyRecoveryCancelled(lockId);
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    /**
     * @notice Check if a lock has PQC protection
     */
    function hasPQCProtection(bytes32 lockId) external view returns (bool) {
        return lockPQCConfigs[lockId].pqPublicKeyHash != bytes32(0);
    }

    /**
     * @notice Get PQC configuration for a lock
     */
    function getPQCConfig(
        bytes32 lockId
    ) external view returns (PQCLockConfig memory) {
        return lockPQCConfigs[lockId];
    }

    /**
     * @notice Get current nonce for an address
     */
    function getNonce(address account) external view returns (uint256) {
        return nonces[account];
    }

    /**
     * @notice Check if recovery is pending
     */
    function isRecoveryPending(
        bytes32 lockId
    ) external view returns (bool pending, uint256 executeAfter) {
        executeAfter = pendingRecoveries[lockId];
        pending = executeAfter != 0;
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setPQCRegistry(address _registry) external onlyRole(ADMIN_ROLE) {
        pqcRegistry = PQCRegistry(_registry);
    }

    function setPQCMandatory(bool mandatory) external onlyRole(ADMIN_ROLE) {
        pqcMandatoryForHighValue = mandatory;
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // =============================================================================
    // INTERNAL FUNCTIONS
    // =============================================================================

    function _requiresPQC(
        uint256 value,
        uint64 duration
    ) internal view returns (bool) {
        if (!pqcMandatoryForHighValue) return false;
        return
            value >= PQC_THRESHOLD_VALUE || duration >= PQC_THRESHOLD_DURATION;
    }

    function _hashTypedDataV4(
        bytes32 structHash
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
            );
    }
}
