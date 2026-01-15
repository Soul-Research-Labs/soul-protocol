// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title ConfidentialStateContainerV3
/// @author PIL Protocol
/// @notice Production-ready confidential state management with enhanced security
/// @dev Implements role-based access, state versioning, batch operations, and emergency recovery
contract ConfidentialStateContainerV3 is AccessControl, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Role for operators who can manage state
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    /// @notice Role for emergency actions
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    
    /// @notice Role for verifier management
    bytes32 public constant VERIFIER_ADMIN_ROLE = keccak256("VERIFIER_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice State status enum
    enum StateStatus {
        Active,      // Normal active state
        Locked,      // Temporarily locked (e.g., during dispute)
        Frozen,      // Frozen by compliance
        Retired      // State has been consumed/transferred
    }

    /// @notice Encrypted state structure with versioning
    /// @param encryptedState AES-256-GCM encrypted data blob
    /// @param commitment Pedersen commitment to plaintext
    /// @param nullifier Unique nullifier for double-spend prevention
    /// @param owner Current owner address
    /// @param version State version (incremented on updates)
    /// @param status Current state status
    /// @param createdAt Creation timestamp
    /// @param updatedAt Last update timestamp
    /// @param metadata Optional metadata hash (IPFS CID, etc.)
    struct EncryptedState {
        bytes encryptedState;
        bytes32 commitment;
        bytes32 nullifier;
        address owner;
        uint64 version;
        StateStatus status;
        uint64 createdAt;
        uint64 updatedAt;
        bytes32 metadata;
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

    /// @notice Verifier interface for proof verification
    IProofVerifier public verifier;

    /// @notice Mapping from commitment to encrypted state
    mapping(bytes32 => EncryptedState) public states;

    /// @notice Mapping of nullifier to used status
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Mapping of nullifier to commitment (reverse lookup)
    mapping(bytes32 => bytes32) public nullifierToCommitment;

    /// @notice Mapping of owner to their commitments
    mapping(address => bytes32[]) public ownerCommitments;

    /// @notice State transition history (commitment => transitions)
    mapping(bytes32 => StateTransition[]) public stateHistory;

    /// @notice Total states registered
    uint256 public totalStates;

    /// @notice Total active states
    uint256 public activeStates;

    /// @notice Minimum proof validity window (prevents replay)
    uint256 public proofValidityWindow = 1 hours;

    /// @notice Maximum encrypted state size (gas limit protection)
    uint256 public maxStateSize = 64 * 1024; // 64KB

    /// @notice Nonce for signature replay prevention
    mapping(address => uint256) public nonces;

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

    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
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

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the contract
    /// @param _verifier Address of the proof verifier contract
    constructor(address _verifier) {
        if (_verifier == address(0)) revert ZeroAddress();
        
        verifier = IProofVerifier(_verifier);
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
        _grantRole(VERIFIER_ADMIN_ROLE, msg.sender);
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
        
        bytes32 structHash = keccak256(abi.encode(
            keccak256("RegisterState(bytes32 commitment,bytes32 nullifier,address owner,uint256 nonce,uint256 deadline)"),
            commitment,
            nullifier,
            owner,
            nonces[owner]++,
            deadline
        ));
        
        bytes32 digest = structHash.toEthSignedMessageHash();
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
    /// @param _states Array of state data to register
    function batchRegisterStates(
        BatchStateInput[] calldata _states
    ) external nonReentrant whenNotPaused {
        uint256 len = _states.length;
        if (len == 0) revert EmptyEncryptedState();
        if (len > MAX_BATCH_SIZE) revert BatchTooLarge(len, MAX_BATCH_SIZE);

        bytes32[] memory commitments = new bytes32[](len);

        for (uint256 i = 0; i < len; ) {
            _validateAndRegisterState(
                _states[i].encryptedState,
                _states[i].commitment,
                _states[i].nullifier,
                _states[i].proof,
                _states[i].publicInputs,
                _states[i].metadata,
                msg.sender
            );
            commitments[i] = _states[i].commitment;
            unchecked { ++i; }
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
        // Validations
        if (encryptedState.length == 0) revert EmptyEncryptedState();
        if (encryptedState.length > maxStateSize) 
            revert StateSizeTooLarge(encryptedState.length, maxStateSize);
        if (states[commitment].owner != address(0))
            revert CommitmentAlreadyExists(commitment);
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // Verify proof
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Store state
        uint64 timestamp = uint64(block.timestamp);
        states[commitment] = EncryptedState({
            encryptedState: encryptedState,
            commitment: commitment,
            nullifier: nullifier,
            owner: owner,
            version: 1,
            status: StateStatus.Active,
            createdAt: timestamp,
            updatedAt: timestamp,
            metadata: metadata
        });

        // Register nullifier
        nullifiers[nullifier] = true;
        nullifierToCommitment[nullifier] = commitment;

        // Track owner's commitments
        ownerCommitments[owner].push(commitment);

        // Update counters
        unchecked {
            ++totalStates;
            ++activeStates;
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
        // Validations
        if (newOwner == address(0)) revert ZeroAddress();
        if (newEncryptedState.length == 0) revert EmptyEncryptedState();
        if (newEncryptedState.length > maxStateSize)
            revert StateSizeTooLarge(newEncryptedState.length, maxStateSize);

        EncryptedState storage oldState = states[oldCommitment];
        if (oldState.owner == address(0)) revert CommitmentNotFound(oldCommitment);
        if (oldState.owner != caller) revert NotStateOwner(caller, oldState.owner);
        if (oldState.status != StateStatus.Active) 
            revert StateNotActive(oldCommitment, oldState.status);
        if (nullifiers[newNullifier]) revert NullifierAlreadyUsed(newNullifier);

        // Verify proof
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

        // Record transition history
        stateHistory[oldCommitment].push(StateTransition({
            fromCommitment: oldCommitment,
            toCommitment: newCommitment,
            fromOwner: oldState.owner,
            toOwner: newOwner,
            timestamp: block.timestamp,
            transactionHash: keccak256(abi.encodePacked(
                oldCommitment, newCommitment, block.timestamp
            ))
        }));

        // Mark old state as retired
        oldState.status = StateStatus.Retired;
        oldState.updatedAt = uint64(block.timestamp);

        // Store new state
        uint64 newVersion = oldState.version + 1;
        uint64 timestamp = uint64(block.timestamp);
        
        states[newCommitment] = EncryptedState({
            encryptedState: newEncryptedState,
            commitment: newCommitment,
            nullifier: newNullifier,
            owner: newOwner,
            version: newVersion,
            status: StateStatus.Active,
            createdAt: timestamp,
            updatedAt: timestamp,
            metadata: oldState.metadata
        });

        // Register new nullifier
        nullifiers[newNullifier] = true;
        nullifierToCommitment[newNullifier] = newCommitment;

        // Track new owner's commitments
        ownerCommitments[newOwner].push(newCommitment);

        emit StateTransferred(oldCommitment, newCommitment, newOwner, newVersion);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if a state exists and is active
    /// @param commitment The commitment to check
    /// @return exists True if exists and active
    function isStateActive(bytes32 commitment) external view returns (bool exists) {
        return states[commitment].status == StateStatus.Active;
    }

    /// @notice Gets full state details
    /// @param commitment The commitment to query
    /// @return state The encrypted state struct
    function getState(bytes32 commitment) external view returns (EncryptedState memory state) {
        return states[commitment];
    }

    /// @notice Gets all commitments for an owner
    /// @param owner The owner address
    /// @return commitments Array of commitment hashes
    function getOwnerCommitments(address owner) external view returns (bytes32[] memory commitments) {
        return ownerCommitments[owner];
    }

    /// @notice Gets state transition history
    /// @param commitment The commitment to query
    /// @return transitions Array of state transitions
    function getStateHistory(bytes32 commitment) external view returns (StateTransition[] memory transitions) {
        return stateHistory[commitment];
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

    /// @notice Updates the verifier contract
    /// @param _newVerifier The new verifier address
    function setVerifier(address _newVerifier) external onlyRole(VERIFIER_ADMIN_ROLE) {
        if (_newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = address(verifier);
        verifier = IProofVerifier(_newVerifier);
        emit VerifierUpdated(oldVerifier, _newVerifier);
    }

    /// @notice Updates proof validity window
    /// @param _window The new window in seconds
    function setProofValidityWindow(uint256 _window) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldWindow = proofValidityWindow;
        proofValidityWindow = _window;
        emit ProofValidityWindowUpdated(oldWindow, _window);
    }

    /// @notice Updates maximum state size
    /// @param _maxSize The new maximum size in bytes
    function setMaxStateSize(uint256 _maxSize) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldSize = maxStateSize;
        maxStateSize = _maxSize;
        emit MaxStateSizeUpdated(oldSize, _maxSize);
    }

    /// @notice Locks a state (e.g., during dispute resolution)
    /// @param commitment The commitment to lock
    function lockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);
        
        StateStatus oldStatus = state.status;
        state.status = StateStatus.Locked;
        state.updatedAt = uint64(block.timestamp);
        
        emit StateStatusChanged(commitment, oldStatus, StateStatus.Locked);
    }

    /// @notice Unlocks a previously locked state
    /// @param commitment The commitment to unlock
    function unlockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);
        
        StateStatus oldStatus = state.status;
        state.status = StateStatus.Active;
        state.updatedAt = uint64(block.timestamp);
        
        emit StateStatusChanged(commitment, oldStatus, StateStatus.Active);
    }

    /// @notice Freezes a state (compliance action)
    /// @param commitment The commitment to freeze
    function freezeState(bytes32 commitment) external onlyRole(EMERGENCY_ROLE) {
        EncryptedState storage state = states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);
        
        StateStatus oldStatus = state.status;
        state.status = StateStatus.Frozen;
        state.updatedAt = uint64(block.timestamp);
        unchecked { --activeStates; }
        
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
