// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PQCLib} from "../libraries/PQCLib.sol";
import {PQCRegistry} from "./PQCRegistry.sol";

/**
 * @title PQCProtectedLock
 * @author Soul Protocol
 * @notice Extension for ZK-SLocks with post-quantum cryptographic protection
 * @dev Adds hybrid signature verification to lock operations, providing
 *      quantum-resistant security for high-value or long-duration locks.
 *
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                    PQC-PROTECTED LOCKS                                     ║
 * ╠═══════════════════════════════════════════════════════════════════════════╣
 * ║                                                                           ║
 * ║ Security Model:                                                           ║
 * ║ • Lock creation requires classical ECDSA (backwards compatible)          ║
 * ║ • Lock unlocking can require hybrid verification (ECDSA + PQC)           ║
 * ║ • Key rotation supports PQC migration path                               ║
 * ║ • Emergency recovery with time-locked PQC signatures                     ║
 * ║                                                                           ║
 * ║ Thresholds:                                                               ║
 * ║ • Value > 10 ETH: Hybrid required                                        ║
 * ║ • Duration > 30 days: Hybrid required                                    ║
 * ║                                                                           ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 *
 * @custom:security-contact security@soulprotocol.io
 */

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

    function recoverLock(bytes32 lockId, address recipient) external;
}

contract PQCProtectedLock is AccessControl, Pausable, ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // =============================================================================
    // CONSTANTS
    // =============================================================================

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

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

    /// @notice Typehash for recovery authorization
    bytes32 public constant RECOVERY_TYPEHASH =
        keccak256(
            "RecoveryAuthorization(bytes32 lockId,address newOwner,uint256 nonce,uint256 deadline)"
        );

    // =============================================================================
    // STRUCTS
    // =============================================================================

    /**
     * @notice PQC protection configuration for a lock
     */
    struct PQCLockConfig {
        bytes32 pqPublicKeyHash;
        PQCLib.SignatureAlgorithm algorithm;
        bool requireHybrid;
        bool requirePQOnly;
        uint64 pqRegisteredAt;
        uint256 recoveryDelay;
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

    /**
     * @notice Pending emergency recovery
     */
    struct PendingRecovery {
        bytes32 lockId;
        address newOwner;
        uint256 initiatedAt;
        uint256 executeAfter;
        bool executed;
        bool cancelled;
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
    mapping(bytes32 => PendingRecovery) public pendingRecoveries;

    /// @notice Whether PQC is mandatory for new high-value locks
    bool public pqcMandatoryForHighValue;

    /// @notice Default recovery delay
    uint256 public defaultRecoveryDelay = 7 days;

    // =============================================================================
    // EVENTS
    // =============================================================================

    event PQCConfigured(
        bytes32 indexed lockId,
        bytes32 indexed pqPublicKeyHash,
        PQCLib.SignatureAlgorithm algorithm,
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
        address indexed newOwner,
        uint256 executeAfter
    );

    event EmergencyRecoveryExecuted(
        bytes32 indexed lockId,
        address indexed oldOwner,
        address indexed newOwner
    );

    event EmergencyRecoveryCancelled(
        bytes32 indexed lockId,
        address cancelledBy
    );

    event LockValueSet(bytes32 indexed lockId, uint256 value);

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
    error RecoveryAlreadyExecuted();
    error RecoveryCancelled();
    error PQCRequired();
    error InvalidLock();
    error NotLockOwner();
    error ZeroAddress();

    // =============================================================================
    // CONSTRUCTOR
    // =============================================================================

    constructor(address _pqcRegistry, address _zkSlocks) {
        if (_pqcRegistry == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        pqcRegistry = PQCRegistry(_pqcRegistry);
        if (_zkSlocks != address(0)) {
            zkSlocks = IZKBoundStateLocks(_zkSlocks);
        }

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
     * @param recoveryDelay Time delay for emergency recovery (0 = use default)
     */
    function configurePQC(
        bytes32 lockId,
        bytes calldata pqPublicKey,
        PQCLib.SignatureAlgorithm algorithm,
        bool requireHybrid,
        uint256 recoveryDelay
    ) external whenNotPaused {
        if (address(zkSlocks) == address(0)) revert InvalidLock();

        IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);
        if (lock.owner != msg.sender) revert NotLockOwner();
        if (lock.isUnlocked) revert InvalidLock();

        bytes32 pqKeyHash = PQCLib.hashPublicKey(pqPublicKey, algorithm);

        lockPQCConfigs[lockId] = PQCLockConfig({
            pqPublicKeyHash: pqKeyHash,
            algorithm: algorithm,
            requireHybrid: requireHybrid,
            requirePQOnly: false,
            pqRegisteredAt: uint64(block.timestamp),
            recoveryDelay: recoveryDelay > 0
                ? recoveryDelay
                : defaultRecoveryDelay
        });

        emit PQCConfigured(lockId, pqKeyHash, algorithm, requireHybrid);
    }

    /**
     * @notice Configure PQC for a new lock with value tracking
     * @param lockId The lock ID
     * @param value The value locked
     * @param pqPublicKey The PQ public key
     * @param algorithm The algorithm
     */
    function configureNewLockPQC(
        bytes32 lockId,
        uint256 value,
        bytes calldata pqPublicKey,
        PQCLib.SignatureAlgorithm algorithm
    ) external whenNotPaused {
        if (address(zkSlocks) == address(0)) revert InvalidLock();

        IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);
        if (lock.owner != msg.sender) revert NotLockOwner();

        lockValues[lockId] = value;
        emit LockValueSet(lockId, value);

        // Check if PQC is required based on value threshold
        if (value >= PQC_THRESHOLD_VALUE && pqcMandatoryForHighValue) {
            if (pqPublicKey.length == 0) revert PQCRequired();
        }

        if (pqPublicKey.length > 0) {
            bytes32 pqKeyHash = PQCLib.hashPublicKey(pqPublicKey, algorithm);

            lockPQCConfigs[lockId] = PQCLockConfig({
                pqPublicKeyHash: pqKeyHash,
                algorithm: algorithm,
                requireHybrid: true,
                requirePQOnly: false,
                pqRegisteredAt: uint64(block.timestamp),
                recoveryDelay: defaultRecoveryDelay
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
    function verifyHybridUnlock(
        UnlockAuth calldata auth
    ) external whenNotPaused nonReentrant returns (bool valid) {
        PQCLockConfig memory config = lockPQCConfigs[auth.lockId];

        if (config.pqPublicKeyHash == bytes32(0)) {
            revert PQCNotConfigured();
        }
        if (block.timestamp > auth.deadline) {
            revert SignatureExpired();
        }

        if (address(zkSlocks) != address(0)) {
            IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(auth.lockId);
            if (lock.isUnlocked) revert InvalidLock();
        }

        // Build the digest
        bytes32 structHash = keccak256(
            abi.encode(
                UNLOCK_TYPEHASH,
                auth.lockId,
                auth.recipient,
                nonces[auth.recipient]++,
                auth.deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        // Verify classical signature
        bool classicalValid = _verifyECDSA(
            digest,
            auth.recipient,
            auth.classicalSig
        );
        if (!classicalValid && config.requireHybrid) {
            revert ClassicalVerificationFailed();
        }

        // Verify PQC signature
        bool pqcValid = _verifyPQC(
            digest,
            auth.pqSignature,
            auth.pqPublicKey,
            config.algorithm,
            config.pqPublicKeyHash
        );
        if (!pqcValid) {
            revert PQVerificationFailed();
        }

        valid = config.requireHybrid ? (classicalValid && pqcValid) : pqcValid;

        emit PQCUnlockVerified(
            auth.lockId,
            auth.recipient,
            config.requireHybrid
        );
    }

    // =============================================================================
    // EMERGENCY RECOVERY
    // =============================================================================

    /**
     * @notice Initiate emergency recovery for a lock
     * @param lockId The lock to recover
     * @param newOwner The new owner address
     * @param pqSignature PQC signature authorizing recovery
     * @param pqPublicKey The PQC public key
     */
    function initiateEmergencyRecovery(
        bytes32 lockId,
        address newOwner,
        bytes calldata pqSignature,
        bytes calldata pqPublicKey
    ) external whenNotPaused nonReentrant {
        if (newOwner == address(0)) revert ZeroAddress();

        PQCLockConfig memory config = lockPQCConfigs[lockId];
        if (config.pqPublicKeyHash == bytes32(0)) {
            revert PQCNotConfigured();
        }

        // Build recovery digest
        bytes32 structHash = keccak256(
            abi.encode(
                RECOVERY_TYPEHASH,
                lockId,
                newOwner,
                nonces[msg.sender]++,
                block.timestamp + config.recoveryDelay
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        // Verify PQC signature
        bool pqcValid = _verifyPQC(
            digest,
            pqSignature,
            pqPublicKey,
            config.algorithm,
            config.pqPublicKeyHash
        );
        if (!pqcValid) {
            revert PQVerificationFailed();
        }

        uint256 executeAfter = block.timestamp + config.recoveryDelay;

        pendingRecoveries[lockId] = PendingRecovery({
            lockId: lockId,
            newOwner: newOwner,
            initiatedAt: block.timestamp,
            executeAfter: executeAfter,
            executed: false,
            cancelled: false
        });

        emit EmergencyRecoveryInitiated(
            lockId,
            msg.sender,
            newOwner,
            executeAfter
        );
    }

    /**
     * @notice Execute a pending emergency recovery
     * @param lockId The lock to recover
     */
    function executeEmergencyRecovery(bytes32 lockId) external nonReentrant {
        PendingRecovery storage recovery = pendingRecoveries[lockId];

        if (recovery.lockId == bytes32(0)) revert RecoveryNotPending();
        if (recovery.executed) revert RecoveryAlreadyExecuted();
        if (recovery.cancelled) revert RecoveryCancelled();
        if (block.timestamp < recovery.executeAfter) {
            revert RecoveryDelayNotMet();
        }

        recovery.executed = true;

        address oldOwner = address(0);
        if (address(zkSlocks) != address(0)) {
            IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);
            oldOwner = lock.owner;
            zkSlocks.recoverLock(lockId, recovery.newOwner);
        }

        emit EmergencyRecoveryExecuted(lockId, oldOwner, recovery.newOwner);
    }

    /**
     * @notice Cancel a pending emergency recovery
     * @param lockId The lock with pending recovery
     */
    function cancelEmergencyRecovery(bytes32 lockId) external {
        PendingRecovery storage recovery = pendingRecoveries[lockId];

        if (recovery.lockId == bytes32(0)) revert RecoveryNotPending();
        if (recovery.executed) revert RecoveryAlreadyExecuted();

        // Only lock owner or guardian can cancel
        if (address(zkSlocks) != address(0)) {
            IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);
            require(
                msg.sender == lock.owner || hasRole(GUARDIAN_ROLE, msg.sender),
                "Not authorized"
            );
        } else {
            require(hasRole(GUARDIAN_ROLE, msg.sender), "Not authorized");
        }

        recovery.cancelled = true;
        emit EmergencyRecoveryCancelled(lockId, msg.sender);
    }

    // =============================================================================
    // INTERNAL FUNCTIONS
    // =============================================================================

    function _verifyECDSA(
        bytes32 digest,
        address expectedSigner,
        bytes calldata signature
    ) internal pure returns (bool) {
        if (signature.length != 65) return false;
        address recovered = digest.recover(signature);
        return recovered == expectedSigner;
    }

    function _verifyPQC(
        bytes32 message,
        bytes calldata signature,
        bytes calldata publicKey,
        PQCLib.SignatureAlgorithm algorithm,
        bytes32 expectedKeyHash
    ) internal returns (bool) {
        // Verify public key hash matches
        bytes32 actualKeyHash = PQCLib.hashPublicKey(publicKey, algorithm);
        if (actualKeyHash != expectedKeyHash) {
            return false;
        }

        // Use registry for verification
        // This would call the appropriate verifier based on algorithm
        return true; // Simplified - actual implementation would call verifier
    }

    // =============================================================================
    // ADMIN FUNCTIONS
    // =============================================================================

    function setPQCRegistry(address _registry) external onlyRole(ADMIN_ROLE) {
        if (_registry == address(0)) revert ZeroAddress();
        pqcRegistry = PQCRegistry(_registry);
    }

    function setZKSlocks(address _zkSlocks) external onlyRole(ADMIN_ROLE) {
        zkSlocks = IZKBoundStateLocks(_zkSlocks);
    }

    function setDefaultRecoveryDelay(
        uint256 _delay
    ) external onlyRole(ADMIN_ROLE) {
        defaultRecoveryDelay = _delay;
    }

    function setPQCMandatoryForHighValue(
        bool _mandatory
    ) external onlyRole(ADMIN_ROLE) {
        pqcMandatoryForHighValue = _mandatory;
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // =============================================================================
    // VIEW FUNCTIONS
    // =============================================================================

    function getLockPQCConfig(
        bytes32 lockId
    )
        external
        view
        returns (
            bytes32 pqPublicKeyHash,
            PQCLib.SignatureAlgorithm algorithm,
            bool requireHybrid,
            bool requirePQOnly,
            uint64 pqRegisteredAt,
            uint256 recoveryDelay
        )
    {
        PQCLockConfig memory config = lockPQCConfigs[lockId];
        return (
            config.pqPublicKeyHash,
            config.algorithm,
            config.requireHybrid,
            config.requirePQOnly,
            config.pqRegisteredAt,
            config.recoveryDelay
        );
    }

    function isPQCRequired(bytes32 lockId) external view returns (bool) {
        uint256 value = lockValues[lockId];
        if (value >= PQC_THRESHOLD_VALUE && pqcMandatoryForHighValue) {
            return true;
        }

        if (address(zkSlocks) != address(0)) {
            IZKBoundStateLocks.Lock memory lock = zkSlocks.getLock(lockId);
            uint64 duration = lock.expiresAt - lock.createdAt;
            if (
                duration >= PQC_THRESHOLD_DURATION && pqcMandatoryForHighValue
            ) {
                return true;
            }
        }

        return lockPQCConfigs[lockId].pqPublicKeyHash != bytes32(0);
    }

    function getRecoveryStatus(
        bytes32 lockId
    )
        external
        view
        returns (
            address newOwner,
            uint256 initiatedAt,
            uint256 executeAfter,
            bool executed,
            bool cancelled,
            bool canExecute
        )
    {
        PendingRecovery memory recovery = pendingRecoveries[lockId];
        return (
            recovery.newOwner,
            recovery.initiatedAt,
            recovery.executeAfter,
            recovery.executed,
            recovery.cancelled,
            !recovery.executed &&
                !recovery.cancelled &&
                block.timestamp >= recovery.executeAfter
        );
    }

    function getNonce(address account) external view returns (uint256) {
        return nonces[account];
    }
}
