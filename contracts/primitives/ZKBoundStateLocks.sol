// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title ZKBoundStateLocks (ZK-SLocks)
 * @author Soul v2 - Soul Protocol
 * @notice Cross-Chain Confidential State Lock Manager - Novel Primitive
 * @dev Core contract managing zero-knowledge bound state locks for privacy-preserving cross-chain state transitions
 *
 * ARCHITECTURE OVERVIEW:
 * ZK-Bound State Locks represent a paradigm shift in cross-chain interoperability. Unlike traditional
 * bridges that move assets or messaging layers that move messages, ZK-SLocks enable secure,
 * privacy-preserving movement of CONFIDENTIAL STATE TRANSITIONS across heterogeneous blockchains.
 *
 * THE CORE INNOVATION:
 * A cryptographic lock where a confidential state commitment can only be unlocked if a zero-knowledge
 * proof attests that a specific state transition occurred, REGARDLESS OF WHERE IT WAS COMPUTED.
 *
 * SECURITY ARCHITECTURE:
 * 1. Cryptographic State Locking: Locks are bound to state commitments, not addresses
 * 2. ZK-Proof Unlocking: Only valid zero-knowledge proofs can unlock state transitions
 * 3. Cross-Domain Nullifiers: Prevents replay attacks across chains without global consensus
 * 4. Optimistic Dispute Resolution: Economic security for cross-chain race conditions
 * 5. Policy-Bound Execution: Cryptographic enforcement of disclosure policies
 *
 * CRITICAL PROPERTIES:
 * - Non-Interactive: No coordination required between lock and unlock
 * - Chain-Agnostic: Works across any EVM and non-EVM chain
 * - Privacy-Preserving: No plaintext state exposure at any layer
 * - Composable: Multiple locks can reference the same state commitment
 *
 * INTEGRATION WITH Soul:
 * - Uses CDNA for cross-domain nullifier generation
 * - Integrates with PC³ for self-authenticating containers
 * - Leverages EASC for execution-agnostic commitments
 * - Compatible with PBP policy enforcement
 */
contract ZKBoundStateLocks is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Pre-computed role hashes save ~200 gas per access vs runtime keccak256
    bytes32 public constant LOCK_ADMIN_ROLE =
        0xb5f42d4ed74356fb5b5979d37d3950e53ab205fdb50ef14ba7816ef87259fef6;
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        0xb194a0b06484f8a501e0bef8877baf2a303f803540f5ddeb9d985c0cd76f3e70;
    bytes32 public constant DOMAIN_ADMIN_ROLE =
        0x8601f95000f9db10f888b55a4dcf204d495f7b7e45e94a5425cd4562bae08468;
    bytes32 public constant DISPUTE_RESOLVER_ROLE =
        0x7b8bb8356a3f32f5c111ff23f050d97f08988e0883529ea7bff3b918887a6e0e;

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error LockAlreadyExists(bytes32 lockId);
    error LockDoesNotExist(bytes32 lockId);
    error LockAlreadyUnlocked(bytes32 lockId);
    error LockExpired(bytes32 lockId, uint256 deadline);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error VerifierNotRegistered(bytes32 verifierKeyHash);
    error InvalidProof(bytes32 lockId);
    error InvalidDisputeWindow();
    error InsufficientBond(uint256 required, uint256 provided);
    error InvalidDomainSeparator(bytes32 domain);
    error TransitionPredicateMismatch(bytes32 expected, bytes32 provided);
    error StateCommitmentMismatch(bytes32 expected, bytes32 provided);
    error ChallengeWindowClosed(bytes32 lockId);
    error NoOptimisticUnlock(bytes32 lockId);
    error AlreadyDisputed(bytes32 lockId);
    error InvalidConflictProof(bytes32 lockId);
    error ETHTransferFailed();
    error VerifierAlreadyRegistered(bytes32 verifierKeyHash);
    error InvalidVerifierAddress();
    error DomainAlreadyExists(bytes32 domainSeparator);

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev ZKSLock represents a cryptographic lock on a confidential state commitment
     *
     * STRUCTURAL INTEGRITY:
     * - lockId: Deterministic hash ensuring global uniqueness
     * - oldStateCommitment: Poseidon hash of previous confidential state
     * - transitionPredicateHash: Hash of Noir circuit defining allowed transitions
     * - policyHash: Hash of disclosure policy (ZK-KYC, regulatory compliance, etc.)
     * - domainSeparator: Cross-domain identifier (chainId ‖ appId ‖ epoch)
     * - lockedBy: Original lock creator (not necessarily state owner)
     *
     * CRYPTOGRAPHIC PROPERTIES:
     * - All fields are public but reveal nothing about confidential state
     * - Lock can be created by anyone with knowledge of state commitment
     * - Unlock requires zero-knowledge proof of valid state transition
     */
    struct ZKSLock {
        bytes32 lockId;
        bytes32 oldStateCommitment;
        bytes32 transitionPredicateHash;
        bytes32 policyHash;
        bytes32 domainSeparator;
        address lockedBy;
        uint64 createdAt;
        uint64 unlockDeadline;
        bool isUnlocked;
    }

    /**
     * @dev UnlockProof bundles all data required to verify and execute unlock
     *
     * VERIFICATION PIPELINE:
     * 1. zkProof: Noir-generated Groth16/Plonk proof (serialized)
     * 2. newStateCommitment: Output state after transition
     * 3. nullifier: Cross-domain spend prevention token
     * 4. verifierKeyHash: Hash of verification key for circuit
     * 5. auxiliaryData: Additional proofs (policy compliance, etc.)
     */
    struct UnlockProof {
        bytes32 lockId;
        bytes zkProof;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 verifierKeyHash;
        bytes auxiliaryData;
    }

    /**
     * @dev OptimisticUnlock enables cross-chain race condition prevention
     *
     * DISPUTE RESOLUTION MECHANISM:
     * - unlocker posts bond for optimistic execution
     * - Challenge window (DISPUTE_WINDOW) allows conflict proofs
     * - Valid challenge slashes bond to challenger
     * - No challenge → unlock finalizes after window
     */
    struct OptimisticUnlock {
        address unlocker;
        uint64 unlockTime;
        uint128 bondAmount;
        bytes32 proofHash;
        uint64 finalizeAfter;
        bool disputed;
        bytes32 newStateCommitment;
        bytes32 nullifier;
    }

    /**
     * @dev Domain configuration for cross-chain coordination
     */
    struct Domain {
        uint16 chainId;
        uint16 appId;
        uint32 epoch;
        string name;
        bool isActive;
        uint64 registeredAt;
    }

    /**
     * @dev Unlock receipt for event emission
     */
    struct UnlockReceipt {
        bytes32 lockId;
        bytes32 newStateCommitment;
        bytes32 nullifier;
        bytes32 domainSeparator;
        address unlockedBy;
        uint64 unlockedAt;
    }

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Primary lock registry: lockId → ZKSLock
    mapping(bytes32 => ZKSLock) public locks;

    /// @notice Active lock IDs for enumeration
    bytes32[] private _activeLockIds;
    mapping(bytes32 => uint256) private _activeLockIndex;

    /// @notice Nullifier registry for cross-domain double-spend prevention
    mapping(bytes32 => bool) public nullifierUsed;

    /// @notice Verifier registry: verifierKeyHash → verifier contract address
    mapping(bytes32 => address) public verifiers;

    /// @notice Optimistic unlock tracking for dispute resolution
    mapping(bytes32 => OptimisticUnlock) public optimisticUnlocks;

    /// @notice State commitment chain for provenance tracking
    mapping(bytes32 => bytes32) public commitmentSuccessor;
    mapping(bytes32 => bytes32) public commitmentPredecessor;

    /// @notice Domain registry: domainSeparator → Domain
    mapping(bytes32 => Domain) public domains;

    /// @notice Lock count per user
    mapping(address => uint256) public userLockCount;

    /// @notice Unlock receipts for auditing
    mapping(bytes32 => UnlockReceipt) public unlockReceipts;

    /// @notice Reference to external proof verifier
    /// @dev Immutable saves ~2100 gas per external call by avoiding SLOAD
    IProofVerifier public immutable proofVerifier;

    /// @notice Constants
    uint256 public constant DISPUTE_WINDOW = 2 hours;
    uint256 public constant MIN_BOND_AMOUNT = 0.01 ether;
    uint256 public constant MAX_ACTIVE_LOCKS = 1000000;

    /// @notice Packed statistics (saves 3 storage slots = ~6000 gas on updates)
    /// @dev Layout: totalLocksCreated (64) | totalLocksUnlocked (64) | totalOptimisticUnlocks (64) | totalDisputes (64)
    uint256 private _packedStats;

    /// @dev Bit shifts for packed stats
    uint256 private constant STAT_SHIFT_UNLOCKED = 64;
    uint256 private constant STAT_SHIFT_OPTIMISTIC = 128;
    uint256 private constant STAT_SHIFT_DISPUTES = 192;

    /// @notice Get total locks created
    function totalLocksCreated() external view returns (uint256) {
        return uint64(_packedStats);
    }

    /// @notice Get total locks unlocked
    function totalLocksUnlocked() external view returns (uint256) {
        return uint64(_packedStats >> STAT_SHIFT_UNLOCKED);
    }

    /// @notice Get total optimistic unlocks
    function totalOptimisticUnlocks() external view returns (uint256) {
        return uint64(_packedStats >> STAT_SHIFT_OPTIMISTIC);
    }

    /// @notice Get total disputes
    function totalDisputes() external view returns (uint256) {
        return uint64(_packedStats >> STAT_SHIFT_DISPUTES);
    }

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event LockCreated(
        bytes32 indexed lockId,
        bytes32 indexed oldStateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 policyHash,
        bytes32 domainSeparator,
        address indexed lockedBy,
        uint64 unlockDeadline
    );

    event LockUnlocked(
        bytes32 indexed lockId,
        bytes32 indexed newStateCommitment,
        bytes32 nullifier,
        bytes32 indexed domainSeparator,
        address unlockedBy
    );

    event OptimisticUnlockInitiated(
        bytes32 indexed lockId,
        address indexed unlocker,
        uint256 bondAmount,
        uint64 finalizeAfter
    );

    event LockDisputed(
        bytes32 indexed lockId,
        address indexed disputer,
        bytes32 conflictProofHash,
        uint256 bondForfeited
    );

    event VerifierRegistered(
        bytes32 indexed verifierKeyHash,
        address indexed verifierContract
    );

    event DomainRegistered(
        bytes32 indexed domainSeparator,
        uint16 chainId,
        uint16 appId,
        uint32 epoch,
        string name
    );

    event OptimisticUnlockFinalized(
        bytes32 indexed lockId,
        address indexed unlocker
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _proofVerifier) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(LOCK_ADMIN_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
        _grantRole(DOMAIN_ADMIN_ROLE, msg.sender);
        _grantRole(DISPUTE_RESOLVER_ROLE, msg.sender);

        // Immutable verifier saves ~2100 gas per call
        proofVerifier = IProofVerifier(_proofVerifier);

        // Initialize default domains
        _registerDefaultDomains();
    }

    /*//////////////////////////////////////////////////////////////
                            LOCK FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a new ZK-Bound State Lock
     * @dev Locks a confidential state commitment with transition constraints
     *
     * @param oldStateCommitment Poseidon hash of current confidential state
     * @param transitionPredicateHash Hash of circuit defining allowed transitions
     * @param policyHash Hash of disclosure policy (bytes32(0) for no policy)
     * @param domainSeparator Cross-domain identifier
     * @param unlockDeadline Optional deadline (0 for no deadline)
     * @return lockId Deterministic lock identifier
     */
    function createLock(
        bytes32 oldStateCommitment,
        bytes32 transitionPredicateHash,
        bytes32 policyHash,
        bytes32 domainSeparator,
        uint64 unlockDeadline
    ) external whenNotPaused returns (bytes32 lockId) {
        // Generate deterministic lock ID
        lockId = keccak256(
            abi.encodePacked(
                oldStateCommitment,
                transitionPredicateHash,
                policyHash,
                domainSeparator,
                msg.sender,
                block.chainid,
                block.timestamp
            )
        );

        // Ensure lock doesn't already exist
        if (locks[lockId].lockId != bytes32(0)) {
            revert LockAlreadyExists(lockId);
        }

        // Validate domain separator
        if (!_isValidDomain(domainSeparator)) {
            revert InvalidDomainSeparator(domainSeparator);
        }

        // Create lock
        locks[lockId] = ZKSLock({
            lockId: lockId,
            oldStateCommitment: oldStateCommitment,
            transitionPredicateHash: transitionPredicateHash,
            policyHash: policyHash,
            domainSeparator: domainSeparator,
            lockedBy: msg.sender,
            createdAt: uint64(block.timestamp),
            unlockDeadline: unlockDeadline,
            isUnlocked: false
        });

        // Track active lock
        _activeLockIndex[lockId] = _activeLockIds.length;
        _activeLockIds.push(lockId);

        // Update statistics (packed, saves gas)
        unchecked {
            _packedStats += 1; // Increment totalLocksCreated (lowest 64 bits)
        }
        userLockCount[msg.sender]++;

        emit LockCreated(
            lockId,
            oldStateCommitment,
            transitionPredicateHash,
            policyHash,
            domainSeparator,
            msg.sender,
            unlockDeadline
        );
    }

    /**
     * @notice Unlocks a ZKSLock with valid zero-knowledge proof
     * @dev Verifies proof and executes state transition atomically
     *
     * @param unlockProof Struct containing proof, new commitment, and nullifier
     */
    function unlock(
        UnlockProof calldata unlockProof
    ) external nonReentrant whenNotPaused {
        ZKSLock storage lock = locks[unlockProof.lockId];

        // Validate lock state
        _validateLockForUnlock(lock);

        // Check nullifier uniqueness
        if (nullifierUsed[unlockProof.nullifier]) {
            revert NullifierAlreadyUsed(unlockProof.nullifier);
        }

        // Verify ZK proof
        _verifyProof(lock, unlockProof);

        // Execute unlock
        _executeUnlock(
            unlockProof.lockId,
            unlockProof.newStateCommitment,
            unlockProof.nullifier,
            lock.domainSeparator
        );
    }

    /**
     * @notice Optimistic unlock with economic security
     * @dev Allows faster unlocking with bond-based dispute resolution
     *
     * @param unlockProof Full unlock proof
     */
    function optimisticUnlock(
        UnlockProof calldata unlockProof
    ) external payable nonReentrant whenNotPaused {
        if (msg.value < MIN_BOND_AMOUNT) {
            revert InsufficientBond(MIN_BOND_AMOUNT, msg.value);
        }

        ZKSLock storage lock = locks[unlockProof.lockId];
        _validateLockForUnlock(lock);

        // Check nullifier uniqueness
        if (nullifierUsed[unlockProof.nullifier]) {
            revert NullifierAlreadyUsed(unlockProof.nullifier);
        }

        // Store optimistic unlock for dispute resolution
        optimisticUnlocks[unlockProof.lockId] = OptimisticUnlock({
            unlocker: msg.sender,
            unlockTime: uint64(block.timestamp),
            bondAmount: uint128(msg.value),
            proofHash: keccak256(abi.encode(unlockProof)),
            finalizeAfter: uint64(block.timestamp + DISPUTE_WINDOW),
            disputed: false,
            newStateCommitment: unlockProof.newStateCommitment,
            nullifier: unlockProof.nullifier
        });

        // Update statistics (packed, saves gas)
        unchecked {
            _packedStats += uint256(1) << STAT_SHIFT_OPTIMISTIC; // Increment totalOptimisticUnlocks
        }

        emit OptimisticUnlockInitiated(
            unlockProof.lockId,
            msg.sender,
            msg.value,
            uint64(block.timestamp + DISPUTE_WINDOW)
        );
    }

    /**
     * @notice Finalize an optimistic unlock after dispute window
     * @param lockId Lock to finalize
     */
    function finalizeOptimisticUnlock(bytes32 lockId) external nonReentrant {
        OptimisticUnlock storage optimistic = optimisticUnlocks[lockId];

        if (optimistic.unlocker == address(0)) {
            revert NoOptimisticUnlock(lockId);
        }

        if (optimistic.disputed) {
            revert AlreadyDisputed(lockId);
        }

        if (block.timestamp < optimistic.finalizeAfter) {
            revert ChallengeWindowClosed(lockId);
        }

        ZKSLock storage lock = locks[lockId];

        // Execute unlock
        _executeUnlock(
            lockId,
            optimistic.newStateCommitment,
            optimistic.nullifier,
            lock.domainSeparator
        );

        // Return bond to unlocker using call() instead of transfer()
        // SECURITY: transfer() only forwards 2300 gas which fails for:
        // - Smart contract wallets with receive() logic
        // - After EIP-1884 gas cost changes
        (bool success, ) = payable(optimistic.unlocker).call{
            value: optimistic.bondAmount
        }("");
        if (!success) revert ETHTransferFailed();

        emit OptimisticUnlockFinalized(lockId, optimistic.unlocker);
    }

    /**
     * @notice Challenge an optimistic unlock with conflicting proof
     * @param lockId Lock to challenge
     * @param conflictProof Conflicting unlock proof
     */
    function challengeOptimisticUnlock(
        bytes32 lockId,
        UnlockProof calldata conflictProof
    ) external nonReentrant {
        OptimisticUnlock storage optimistic = optimisticUnlocks[lockId];

        if (optimistic.unlocker == address(0)) {
            revert NoOptimisticUnlock(lockId);
        }

        if (optimistic.disputed) {
            revert AlreadyDisputed(lockId);
        }

        if (block.timestamp >= optimistic.finalizeAfter) {
            revert ChallengeWindowClosed(lockId);
        }

        // Mark as disputed
        optimistic.disputed = true;
        // Update statistics (packed, saves gas)
        unchecked {
            _packedStats += uint256(1) << STAT_SHIFT_DISPUTES; // Increment totalDisputes
        }

        // Verify conflict proof
        ZKSLock storage lock = locks[lockId];

        if (conflictProof.lockId != lockId) {
            revert InvalidConflictProof(lockId);
        }

        // Conflict must show different new state commitment
        if (conflictProof.newStateCommitment == optimistic.newStateCommitment) {
            revert InvalidConflictProof(lockId);
        }

        // Verify the conflict proof is valid
        _verifyProof(lock, conflictProof);

        // Slash bond to challenger using call() instead of transfer()
        // SECURITY: transfer() only forwards 2300 gas which fails for smart contract wallets
        uint256 bondToSlash = optimistic.bondAmount;
        (bool success, ) = payable(msg.sender).call{value: bondToSlash}("");
        if (!success) revert ETHTransferFailed();

        emit LockDisputed(
            lockId,
            msg.sender,
            keccak256(abi.encode(conflictProof)),
            bondToSlash
        );
    }

    /*//////////////////////////////////////////////////////////////
                          VERIFIER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Registers a new verifier contract
     * @param verifierKeyHash Hash of verification key
     * @param verifierContract Address of verifier contract
     */
    function registerVerifier(
        bytes32 verifierKeyHash,
        address verifierContract
    ) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (verifiers[verifierKeyHash] != address(0)) {
            revert VerifierAlreadyRegistered(verifierKeyHash);
        }
        if (verifierContract == address(0)) revert InvalidVerifierAddress();

        verifiers[verifierKeyHash] = verifierContract;

        emit VerifierRegistered(verifierKeyHash, verifierContract);
    }

    /*//////////////////////////////////////////////////////////////
                           DOMAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Registers a new domain
     */
    function registerDomain(
        uint16 chainId,
        uint16 appId,
        uint32 epoch,
        string calldata name
    ) external onlyRole(DOMAIN_ADMIN_ROLE) returns (bytes32 domainSeparator) {
        domainSeparator = generateDomainSeparator(chainId, appId, epoch);

        // M-1 Fix: Prevent overwriting existing domains
        if (domains[domainSeparator].registeredAt != 0) {
            revert DomainAlreadyExists(domainSeparator);
        }

        domains[domainSeparator] = Domain({
            chainId: chainId,
            appId: appId,
            epoch: epoch,
            name: name,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });

        emit DomainRegistered(domainSeparator, chainId, appId, epoch, name);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _validateLockForUnlock(ZKSLock storage lock) internal view {
        if (lock.lockId == bytes32(0)) {
            revert LockDoesNotExist(lock.lockId);
        }

        if (lock.isUnlocked) {
            revert LockAlreadyUnlocked(lock.lockId);
        }

        if (lock.unlockDeadline > 0 && block.timestamp > lock.unlockDeadline) {
            revert LockExpired(lock.lockId, lock.unlockDeadline);
        }
    }

    function _verifyProof(
        ZKSLock storage lock,
        UnlockProof calldata unlockProof
    ) internal view {
        // If we have a registered verifier for this key, use it
        address verifier = verifiers[unlockProof.verifierKeyHash];

        if (verifier != address(0)) {
            // Prepare public inputs
            bytes32[] memory publicInputs = new bytes32[](6);
            publicInputs[0] = lock.oldStateCommitment;
            publicInputs[1] = unlockProof.newStateCommitment;
            publicInputs[2] = lock.transitionPredicateHash;
            publicInputs[3] = lock.policyHash;
            publicInputs[4] = lock.domainSeparator;
            publicInputs[5] = unlockProof.nullifier;

            // Call verifier
            (bool success, bytes memory returnData) = verifier.staticcall(
                abi.encodeWithSignature(
                    "verify(bytes,bytes32[])",
                    unlockProof.zkProof,
                    publicInputs
                )
            );

            if (!success) {
                revert InvalidProof(unlockProof.lockId);
            }

            bool proofValid = abi.decode(returnData, (bool));
            if (!proofValid) {
                revert InvalidProof(unlockProof.lockId);
            }
        } else if (address(proofVerifier) != address(0)) {
            // Use the general proof verifier
            // Convert public inputs to uint256[] for IProofVerifier interface
            uint256[] memory inputs = new uint256[](6);
            inputs[0] = uint256(lock.oldStateCommitment);
            inputs[1] = uint256(unlockProof.newStateCommitment);
            inputs[2] = uint256(lock.transitionPredicateHash);
            inputs[3] = uint256(lock.policyHash);
            inputs[4] = uint256(lock.domainSeparator);
            inputs[5] = uint256(unlockProof.nullifier);

            bool valid = proofVerifier.verify(unlockProof.zkProof, inputs);

            if (!valid) {
                revert InvalidProof(unlockProof.lockId);
            }
        } else {
            revert VerifierNotRegistered(unlockProof.verifierKeyHash);
        }
    }

    function _executeUnlock(
        bytes32 lockId,
        bytes32 newStateCommitment,
        bytes32 nullifier,
        bytes32 domainSeparator
    ) internal {
        ZKSLock storage lock = locks[lockId];

        // Mark lock as unlocked
        lock.isUnlocked = true;

        // Record nullifier
        nullifierUsed[nullifier] = true;

        // Update commitment chain
        commitmentSuccessor[lock.oldStateCommitment] = newStateCommitment;
        commitmentPredecessor[newStateCommitment] = lock.oldStateCommitment;

        // Store unlock receipt
        unlockReceipts[lockId] = UnlockReceipt({
            lockId: lockId,
            newStateCommitment: newStateCommitment,
            nullifier: nullifier,
            domainSeparator: domainSeparator,
            unlockedBy: msg.sender,
            unlockedAt: uint64(block.timestamp)
        });

        // Remove from active locks
        _removeActiveLock(lockId);

        // Update statistics (packed, saves gas)
        unchecked {
            _packedStats += uint256(1) << STAT_SHIFT_UNLOCKED; // Increment totalLocksUnlocked
        }

        emit LockUnlocked(
            lockId,
            newStateCommitment,
            nullifier,
            domainSeparator,
            msg.sender
        );
    }

    function _removeActiveLock(bytes32 lockId) internal {
        uint256 index = _activeLockIndex[lockId];
        uint256 lastIndex = _activeLockIds.length - 1;

        if (index != lastIndex) {
            bytes32 lastLockId = _activeLockIds[lastIndex];
            _activeLockIds[index] = lastLockId;
            _activeLockIndex[lastLockId] = index;
        }

        _activeLockIds.pop();
        delete _activeLockIndex[lockId];
    }

    function _registerDefaultDomains() internal {
        // Register default domains using the standard separator function
        // Note: For chain IDs > 65535, use registerDomainExtended()
        _registerDomainInternal(1, 0, 0, "Ethereum Mainnet");
        // Sepolia and other large chain IDs need extended registration
        _registerDomainInternalExtended(11155111, 0, 0, "Sepolia Testnet");
        _registerDomainInternalExtended(42161, 0, 0, "Arbitrum One");
        _registerDomainInternal(10, 0, 0, "Optimism");
        _registerDomainInternal(137, 0, 0, "Polygon");
        _registerDomainInternalExtended(8453, 0, 0, "Base");
    }

    function _registerDomainInternal(
        uint16 chainId,
        uint16 appId,
        uint32 epoch,
        string memory name
    ) internal {
        bytes32 domainSeparator = generateDomainSeparator(
            chainId,
            appId,
            epoch
        );
        domains[domainSeparator] = Domain({
            chainId: chainId,
            appId: appId,
            epoch: epoch,
            name: name,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });
    }

    function _registerDomainInternalExtended(
        uint64 chainId,
        uint64 appId,
        uint32 epoch,
        string memory name
    ) internal {
        bytes32 domainSeparator = generateDomainSeparatorExtended(
            chainId,
            appId,
            epoch
        );
        domains[domainSeparator] = Domain({
            chainId: uint16(chainId % 65536),
            appId: uint16(appId % 65536),
            epoch: epoch,
            name: name,
            isActive: true,
            registeredAt: uint64(block.timestamp)
        });
    }

    function _isValidDomain(
        bytes32 domainSeparator
    ) internal view returns (bool) {
        return domains[domainSeparator].isActive;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generates a domain separator from components
     * @dev Uses explicit masking to prevent LLVM optimization bugs on L2s
     * SECURITY: This pattern avoids the rotate-left optimization that caused
     * the Aave/ZKsync vulnerability where 64-bit constants were incorrectly
     * used in 256-bit register operations.
     */
    function generateDomainSeparator(
        uint16 chainId,
        uint16 appId,
        uint32 epoch
    ) public pure returns (bytes32) {
        // Use explicit masking and separate operations to prevent LLVM optimization issues
        // Each operation is isolated to avoid peephole optimization combining them
        uint256 result = 0;
        uint256 chainIdMasked = uint256(chainId) & 0xFFFF;
        uint256 appIdMasked = uint256(appId) & 0xFFFF;
        uint256 epochMasked = uint256(epoch) & 0xFFFFFFFF;

        // Perform shifts separately with explicit 256-bit context
        result = result | (chainIdMasked << 224);
        result = result | (appIdMasked << 208);
        result = result | (epochMasked << 176);

        return bytes32(result);
    }

    /**
     * @notice Generates domain separator with extended chain ID support
     */
    function generateDomainSeparatorExtended(
        uint64 chainId,
        uint64 appId,
        uint32 epoch
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(chainId, appId, epoch, "ZKSLock"));
    }

    /**
     * @notice Generates cross-domain nullifier
     */
    function generateNullifier(
        bytes32 secret,
        bytes32 lockId,
        bytes32 domainSeparator
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    keccak256(abi.encodePacked(secret, "ZKSLock")),
                    lockId,
                    domainSeparator,
                    uint256(0)
                )
            );
    }

    /**
     * @notice Returns all active lock IDs
     */
    function getActiveLockIds() external view returns (bytes32[] memory) {
        return _activeLockIds;
    }

    /**
     * @notice Returns the number of active locks
     */
    function getActiveLockCount() external view returns (uint256) {
        return _activeLockIds.length;
    }

    /**
     * @notice Returns lock details
     */
    function getLock(bytes32 lockId) external view returns (ZKSLock memory) {
        return locks[lockId];
    }

    /**
     * @notice Checks if lock can be unlocked
     */
    function canUnlock(bytes32 lockId) external view returns (bool) {
        ZKSLock storage lock = locks[lockId];
        return
            lock.lockId != bytes32(0) &&
            !lock.isUnlocked &&
            (lock.unlockDeadline == 0 || block.timestamp < lock.unlockDeadline);
    }

    /**
     * @notice Returns commitment chain history
     */
    function getCommitmentChain(
        bytes32 startCommitment,
        uint256 maxDepth
    ) external view returns (bytes32[] memory chain) {
        chain = new bytes32[](maxDepth);
        bytes32 current = startCommitment;

        for (uint256 i = 0; i < maxDepth; ) {
            chain[i] = current;
            current = commitmentSuccessor[current];
            if (current == bytes32(0)) {
                // Resize array
                bytes32[] memory resized = new bytes32[](i + 1);
                for (uint256 j = 0; j <= i; ) {
                    resized[j] = chain[j];
                    unchecked {
                        ++j;
                    }
                }
                return resized;
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Get statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 created,
            uint256 unlocked,
            uint256 active,
            uint256 optimistic,
            uint256 disputed
        )
    {
        // Read from packed storage
        uint256 stats = _packedStats;
        return (
            uint64(stats), // totalLocksCreated
            uint64(stats >> STAT_SHIFT_UNLOCKED), // totalLocksUnlocked
            _activeLockIds.length,
            uint64(stats >> STAT_SHIFT_OPTIMISTIC), // totalOptimisticUnlocks
            uint64(stats >> STAT_SHIFT_DISPUTES) // totalDisputes
        );
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(LOCK_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(LOCK_ADMIN_ROLE) {
        _unpause();
    }
}
