// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title ConfidentialStateContainerV3
/// @author Soul Protocol
/// @notice Production-ready confidential state management with enhanced security
/// @dev Gas-optimized with storage packing, assembly, and immutable variables
contract ConfidentialStateContainerV3 is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Precomputed role hashes (saves ~200 gas per access vs runtime keccak)
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @notice Role for emergency actions
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /// @notice Role for verifier management
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        keccak256("VERIFIER_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice State status enum
    enum StateStatus {
        Active, // Normal active state
        Locked, // Temporarily locked (e.g., during dispute)
        Frozen, // Frozen by compliance
        Retired // State has been consumed/transferred
    }

    /// @notice Encrypted state structure with gas-optimized packing
    /// @dev Packed to minimize storage slots: slot1=commitment, slot2=nullifier,
    ///      slot3=owner+version+status+createdAt, slot4=updatedAt+metadata(partial),
    ///      slot5+=encryptedState (dynamic)
    struct EncryptedState {
        bytes32 commitment; // slot 0
        bytes32 nullifier; // slot 1
        bytes32 metadata; // slot 2
        address owner; // slot 3 (20 bytes)
        uint48 createdAt; // slot 3 (6 bytes) - supports dates until year 8.9M
        uint48 updatedAt; // slot 3 (6 bytes)
        uint32 version; // slot 4 (4 bytes) - 4B+ versions
        StateStatus status; // slot 4 (1 byte)
        bytes encryptedState; // slot 5+ (dynamic)
    }

    /// @notice State transition record for auditing
    struct StateTransition {
        bytes32 fromCommitment;
        bytes32 toCommitment;
        address fromOwner;
        address toOwner;
        uint256 timestamp;
        bytes32 transactionHash;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifier interface (immutable saves ~2100 gas per call)
    IProofVerifier public immutable verifier;

    /// @notice Mapping from commitment to encrypted state
    mapping(bytes32 => EncryptedState) internal _states;

    /// @notice Mapping of nullifier to used status (bitmap for gas efficiency)
    mapping(bytes32 => bool) internal _nullifiers;

    /// @notice Mapping of nullifier to commitment (reverse lookup)
    mapping(bytes32 => bytes32) internal _nullifierToCommitment;

    /// @notice Mapping of owner to their commitments
    mapping(address => bytes32[]) internal _ownerCommitments;

    /// @notice State transition history (commitment => transitions)
    mapping(bytes32 => StateTransition[]) internal _stateHistory;

    /// @dev Packed counters: totalStates (128 bits) | activeStates (128 bits)
    uint256 private _packedCounters;

    /// @dev Packed config: proofValidityWindow (128 bits) | maxStateSize (128 bits)
    uint256 private _packedConfig;

    /// @notice Maximum history length per state to prevent unbounded storage growth
    uint256 public constant MAX_HISTORY_LENGTH = 100;

    /// @notice Nonce for signature replay prevention
    mapping(address => uint256) public nonces;

    /// @notice EIP-712 domain separator (includes chain ID for replay protection)
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice EIP-712 type hash for state registration
    bytes32 public constant REGISTER_STATE_TYPEHASH =
        keccak256(
            "RegisterState(bytes32 commitment,bytes32 nullifier,address owner,uint256 nonce,uint256 deadline,uint256 chainId)"
        );

    /// @notice Chain ID for this deployment (immutable for gas savings)
    uint256 public immutable CHAIN_ID;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event StateRegistered(
        bytes32 indexed commitment,
        address indexed owner,
        bytes32 nullifier,
        uint256 timestamp
    );

    event StateTransferred(
        bytes32 indexed fromCommitment,
        bytes32 indexed toCommitment,
        address indexed newOwner,
        uint256 version
    );

    event StateStatusChanged(
        bytes32 indexed commitment,
        StateStatus oldStatus,
        StateStatus newStatus
    );

    event StateBatchRegistered(
        bytes32[] commitments,
        address indexed owner,
        uint256 count
    );

    event ProofValidityWindowUpdated(uint256 oldWindow, uint256 newWindow);
    event MaxStateSizeUpdated(uint256 oldSize, uint256 newSize);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error NotStateOwner(address caller, address owner);
    error ZeroAddress();
    error EmptyEncryptedState();
    error CommitmentAlreadyExists(bytes32 commitment);
    error CommitmentNotFound(bytes32 commitment);
    error StateSizeTooLarge(uint256 size, uint256 maxSize);
    error StateNotActive(bytes32 commitment, StateStatus status);
    error InvalidSignature();
    error SignatureExpired();
    error InvalidNonce();
    error BatchTooLarge(uint256 size, uint256 maxSize);

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_BATCH_SIZE = 50;

    /// @dev Default proof validity window (1 hour)
    uint256 private constant DEFAULT_PROOF_VALIDITY = 1 hours;

    /// @dev Default max state size (64KB)
    uint256 private constant DEFAULT_MAX_STATE_SIZE = 65536;

    /// @dev Bit shift for counter packing
    uint256 private constant COUNTER_SHIFT = 128;

    /// @dev Pre-computed shift increment for counter operations
    /// SECURITY: Explicit constant prevents LLVM optimization issues on L2s (ZKsync)
    /// where `1 << 128` could be incorrectly compiled with 64-bit operations
    uint256 private constant COUNTER_INCREMENT = uint256(1) << 128;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the contract
    /// @param _verifier Address of the proof verifier contract
    constructor(address _verifier) {
        if (_verifier == address(0)) revert ZeroAddress();

        verifier = IProofVerifier(_verifier);

        // Initialize chain ID and EIP-712 domain separator
        CHAIN_ID = block.chainid;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("ConfidentialStateContainer"),
                keccak256("3"),
                block.chainid,
                address(this)
            )
        );

        // Pack config: proofValidityWindow | maxStateSize
        _packedConfig =
            (DEFAULT_PROOF_VALIDITY << COUNTER_SHIFT) |
            DEFAULT_MAX_STATE_SIZE;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         PACKED STORAGE GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total states registered
    function totalStates() external view returns (uint256) {
        return _packedCounters >> COUNTER_SHIFT;
    }

    /// @notice Total active states
    function activeStates() external view returns (uint256) {
        return uint128(_packedCounters);
    }

    /// @notice Minimum proof validity window
    function proofValidityWindow() external view returns (uint256) {
        return _packedConfig >> COUNTER_SHIFT;
    }

    /// @notice Maximum encrypted state size
    function maxStateSize() public view returns (uint256) {
        return uint128(_packedConfig);
    }

    /// @notice Public getter for states mapping
    function states(
        bytes32 commitment
    ) external view returns (EncryptedState memory) {
        return _states[commitment];
    }

    /// @notice Public getter for nullifiers
    function nullifiers(bytes32 nullifier) external view returns (bool) {
        return _nullifiers[nullifier];
    }

    /// @notice Public getter for nullifier to commitment
    function nullifierToCommitment(
        bytes32 nullifier
    ) external view returns (bytes32) {
        return _nullifierToCommitment[nullifier];
    }

    /// @notice Public getter for owner commitments
    function ownerCommitments(
        address owner,
        uint256 index
    ) external view returns (bytes32) {
        return _ownerCommitments[owner][index];
    }

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Registers a new confidential state
    /// @param encryptedState The encrypted state data
    /// @param commitment The Pedersen commitment
    /// @param nullifier The nullifier for double-spend prevention
    /// @param proof The ZK proof bytes
    /// @param publicInputs The public inputs for verification
    /// @param metadata Optional metadata hash
    function registerState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 metadata
    ) external nonReentrant whenNotPaused {
        _validateAndRegisterState(
            encryptedState,
            commitment,
            nullifier,
            proof,
            publicInputs,
            metadata,
            msg.sender
        );
    }

    /// @notice Registers state with signature (meta-transaction support)
    /// @param encryptedState The encrypted state data
    /// @param commitment The Pedersen commitment
    /// @param nullifier The nullifier
    /// @param proof The ZK proof bytes
    /// @param publicInputs The public inputs
    /// @param metadata Optional metadata hash
    /// @param owner The intended owner
    /// @param deadline Signature deadline
    /// @param signature Owner's signature
    function registerStateWithSignature(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 metadata,
        address owner,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (block.timestamp > deadline) revert SignatureExpired();

        // Verify chain ID matches to prevent cross-chain replay
        if (block.chainid != CHAIN_ID) revert InvalidSignature();

        // EIP-712 compliant struct hash with chain ID
        bytes32 structHash = keccak256(
            abi.encode(
                REGISTER_STATE_TYPEHASH,
                commitment,
                nullifier,
                owner,
                nonces[owner]++,
                deadline,
                block.chainid
            )
        );

        // Create EIP-712 digest
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        address signer = digest.recover(signature);

        if (signer != owner) revert InvalidSignature();

        _validateAndRegisterState(
            encryptedState,
            commitment,
            nullifier,
            proof,
            publicInputs,
            metadata,
            owner
        );
    }

    /// @notice Batch registers multiple states
    /// @param stateInputs Array of state data to register
    function batchRegisterStates(
        BatchStateInput[] calldata stateInputs
    ) external nonReentrant whenNotPaused {
        uint256 len = stateInputs.length;
        if (len == 0) revert EmptyEncryptedState();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        bytes32[] memory commitments = new bytes32[](len);

        for (uint256 i = 0; i < len; ) {
            _validateAndRegisterState(
                stateInputs[i].encryptedState,
                stateInputs[i].commitment,
                stateInputs[i].nullifier,
                stateInputs[i].proof,
                stateInputs[i].publicInputs,
                stateInputs[i].metadata,
                msg.sender
            );
            commitments[i] = stateInputs[i].commitment;
            unchecked {
                ++i;
            }
        }

        emit StateBatchRegistered(commitments, msg.sender, len);
    }

    /// @notice Transfers state ownership
    /// @param oldCommitment The current state commitment
    /// @param newEncryptedState The new encrypted state
    /// @param newCommitment The new commitment
    /// @param newNullifier The new nullifier
    /// @param proof The ZK proof
    /// @param publicInputs The public inputs
    /// @param newOwner The new owner address
    function transferState(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        address newOwner
    ) external nonReentrant whenNotPaused {
        _transferState(
            oldCommitment,
            newEncryptedState,
            newCommitment,
            newNullifier,
            proof,
            publicInputs,
            newOwner,
            msg.sender
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _validateAndRegisterState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 metadata,
        address owner
    ) internal {
        // Cache length to avoid multiple CALLDATASIZE ops
        uint256 stateLen = encryptedState.length;

        // Validations with cached maxStateSize
        if (stateLen == 0) revert EmptyEncryptedState();
        uint256 _maxSize = uint128(_packedConfig);
        if (stateLen > _maxSize) revert StateSizeTooLarge(stateLen, _maxSize);

        // Check commitment doesn't exist (owner != address(0))
        if (_states[commitment].owner != address(0))
            revert CommitmentAlreadyExists(commitment);

        // Check nullifier not used
        if (_nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // Verify proof (external call, can't optimize further)
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Store state with optimized struct
        uint48 timestamp = uint48(block.timestamp);
        EncryptedState storage newState = _states[commitment];
        newState.commitment = commitment;
        newState.nullifier = nullifier;
        newState.metadata = metadata;
        newState.owner = owner;
        newState.createdAt = timestamp;
        newState.updatedAt = timestamp;
        newState.version = 1;
        newState.status = StateStatus.Active;
        newState.encryptedState = encryptedState;

        // Register nullifier
        _nullifiers[nullifier] = true;
        _nullifierToCommitment[nullifier] = commitment;

        // Track owner's commitments
        _ownerCommitments[owner].push(commitment);

        // Update packed counters (both +1)
        // SECURITY: Uses pre-computed COUNTER_INCREMENT constant to avoid LLVM
        // optimization bugs where `1 << 128` could be miscompiled on L2s
        unchecked {
            _packedCounters += COUNTER_INCREMENT + 1;
        }

        emit StateRegistered(commitment, owner, nullifier, block.timestamp);
    }

    function _transferState(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes calldata proof,
        bytes calldata publicInputs,
        address newOwner,
        address caller
    ) internal {
        // Validations with cached maxStateSize
        if (newOwner == address(0)) revert ZeroAddress();
        if (newEncryptedState.length == 0) revert EmptyEncryptedState();
        uint256 _maxSize = uint128(_packedConfig);
        if (newEncryptedState.length > _maxSize) 
            revert StateSizeTooLarge(newEncryptedState.length, _maxSize);

        EncryptedState storage oldState = _states[oldCommitment];

        // Cache owner to avoid multiple SLOADs
        address oldOwner = oldState.owner;
        if (oldOwner == address(0)) revert CommitmentNotFound(oldCommitment);
        if (oldOwner != caller) revert NotStateOwner(caller, oldOwner);

        if (oldState.status != StateStatus.Active)
            revert StateNotActive(oldCommitment, oldState.status);
        if (_nullifiers[newNullifier])
            revert NullifierAlreadyUsed(newNullifier);

        // Verify proof
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Record history before state changes
        _recordTransitionHistory(oldCommitment, newCommitment, oldOwner, newOwner);

        // Cache timestamp and get new version
        uint48 timestamp = uint48(block.timestamp);
        uint32 newVersion = oldState.version + 1;
        bytes32 oldMetadata = oldState.metadata;

        // Mark old state as retired
        oldState.status = StateStatus.Retired;
        oldState.updatedAt = timestamp;

        // Store new state
        _createNewState(
            newCommitment, 
            newNullifier, 
            oldMetadata, 
            newOwner, 
            timestamp, 
            newVersion, 
            newEncryptedState
        );

        emit StateTransferred(oldCommitment, newCommitment, newOwner, newVersion);
    }

    /// @dev Records state transition history
    function _recordTransitionHistory(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        address oldOwner,
        address newOwner
    ) internal {
        // M-2 Fix: Enforce history limit
        if (_stateHistory[oldCommitment].length >= MAX_HISTORY_LENGTH) return;

        bytes32 txHash;
        uint256 ts = block.timestamp;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, oldCommitment)
            mstore(add(ptr, 0x20), newCommitment)
            mstore(add(ptr, 0x40), ts)
            txHash := keccak256(ptr, 0x60)
        }

        _stateHistory[oldCommitment].push(
            StateTransition({
                fromCommitment: oldCommitment,
                toCommitment: newCommitment,
                fromOwner: oldOwner,
                toOwner: newOwner,
                timestamp: ts,
                transactionHash: txHash
            })
        );
    }

    /// @dev Creates a new state entry
    function _createNewState(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 metadata,
        address owner,
        uint48 timestamp,
        uint32 version,
        bytes calldata encryptedState
    ) internal {
        EncryptedState storage newState = _states[commitment];
        newState.commitment = commitment;
        newState.nullifier = nullifier;
        newState.metadata = metadata;
        newState.owner = owner;
        newState.createdAt = timestamp;
        newState.updatedAt = timestamp;
        newState.version = version;
        newState.status = StateStatus.Active;
        newState.encryptedState = encryptedState;

        // Register new nullifier
        _nullifiers[nullifier] = true;
        _nullifierToCommitment[nullifier] = commitment;

        // Track owner's commitments
        _ownerCommitments[owner].push(commitment);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if a state exists and is active
    /// @param commitment The commitment to check
    /// @return exists True if exists and active
    function isStateActive(
        bytes32 commitment
    ) external view returns (bool exists) {
        return _states[commitment].status == StateStatus.Active;
    }

    /// @notice Gets full state details
    /// @param commitment The commitment to query
    /// @return state The encrypted state struct
    function getState(
        bytes32 commitment
    ) external view returns (EncryptedState memory state) {
        return _states[commitment];
    }

    /// @notice Gets all commitments for an owner
    /// @param owner The owner address
    /// @return commitments Array of commitment hashes
    function getOwnerCommitments(
        address owner
    ) external view returns (bytes32[] memory commitments) {
        return _ownerCommitments[owner];
    }

    /// @notice Gets state transition history
    /// @param commitment The commitment to query
    /// @return transitions Array of state transitions
    function getStateHistory(
        bytes32 commitment
    ) external view returns (StateTransition[] memory transitions) {
        return _stateHistory[commitment];
    }

    /// @notice Gets current nonce for an address
    /// @param account The account to query
    /// @return nonce The current nonce
    function getNonce(address account) external view returns (uint256 nonce) {
        return nonces[account];
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Updates proof validity window
    /// @param _window The new window in seconds
    function setProofValidityWindow(
        uint256 _window
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 packed = _packedConfig;
        uint256 oldWindow = packed >> COUNTER_SHIFT;
        // Keep maxStateSize (lower 128 bits), update window (upper 128 bits)
        _packedConfig = (_window << COUNTER_SHIFT) | uint128(packed);
        emit ProofValidityWindowUpdated(oldWindow, _window);
    }

    /// @notice Updates maximum state size
    /// @param _maxSize The new maximum size in bytes
    function setMaxStateSize(
        uint256 _maxSize
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 packed = _packedConfig;
        uint256 oldSize = uint128(packed);
        // Keep window (upper 128 bits), update maxStateSize (lower 128 bits)
        _packedConfig =
            (packed & (uint256(type(uint128).max) << COUNTER_SHIFT)) |
            _maxSize;
        emit MaxStateSizeUpdated(oldSize, _maxSize);
    }

    /// @notice Locks a state (e.g., during dispute resolution)
    /// @param commitment The commitment to lock
    function lockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);

        StateStatus oldStatus = state.status;
        state.status = StateStatus.Locked;
        state.updatedAt = uint48(block.timestamp);

        emit StateStatusChanged(commitment, oldStatus, StateStatus.Locked);
    }

    /// @notice Unlocks a previously locked state
    /// @param commitment The commitment to unlock
    function unlockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);

        StateStatus oldStatus = state.status;
        state.status = StateStatus.Active;
        state.updatedAt = uint48(block.timestamp);

        emit StateStatusChanged(commitment, oldStatus, StateStatus.Active);
    }

    /// @notice Freezes a state (compliance action)
    /// @param commitment The commitment to freeze
    function freezeState(bytes32 commitment) external onlyRole(EMERGENCY_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);

        StateStatus oldStatus = state.status;
        state.status = StateStatus.Frozen;
        state.updatedAt = uint48(block.timestamp);

        // Decrement active states (lower 128 bits) with underflow protection
        uint128 activeCount = uint128(_packedCounters);
        if (activeCount > 0) {
            unchecked {
                --_packedCounters;
            }
        }

        emit StateStatusChanged(commitment, oldStatus, StateStatus.Frozen);
    }

    /// @notice Pauses the contract
    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}

/*//////////////////////////////////////////////////////////////
                          INTERFACES
//////////////////////////////////////////////////////////////*/

interface IProofVerifier {
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool);
}

/// @notice Batch input structure
struct BatchStateInput {
    bytes encryptedState;
    bytes32 commitment;
    bytes32 nullifier;
    bytes proof;
    bytes publicInputs;
    bytes32 metadata;
}
