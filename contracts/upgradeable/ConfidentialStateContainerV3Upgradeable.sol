// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IConfidentialStateContainerV3, BatchStateInput} from "../interfaces/IConfidentialStateContainerV3.sol";

/// @title ConfidentialStateContainerV3Upgradeable
/// @author ZASEON
/// @notice UUPS-upgradeable version of ConfidentialStateContainerV3
/// @dev Converts immutables (verifier, CHAIN_ID, DOMAIN_SEPARATOR) to storage variables
///      for proxy compatibility. DOMAIN_SEPARATOR is computed in initialize() using
///      address(this) which will be the proxy address.
///
///      Gas optimizations preserved: packed counters, pre-computed role hashes,
///      assembly hash operations, unchecked arithmetic.
///
/// @custom:security-contact security@zaseon.network
/// @custom:oz-upgrades-from ConfidentialStateContainerV3
/**
 * @title ConfidentialStateContainerV3Upgradeable
 * @author ZASEON Team
 * @notice Confidential State Container V3 Upgradeable contract
 */
contract ConfidentialStateContainerV3Upgradeable is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    IConfidentialStateContainerV3
{
    using ECDSA for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev Precomputed role hash: keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @notice Role for emergency actions
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /// @notice Role for verifier management
    bytes32 public constant VERIFIER_ADMIN_ROLE =
        0xb194a0b06484f8a501e0bef8877baf2a303f803540f5ddeb9d985c0cd76f3e70;

    /// @notice Role for contract upgrades
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    // StateStatus, EncryptedState, and StateTransition types
    // are inherited from IConfidentialStateContainerV3 to prevent struct drift.

    /// @notice Parameters for creating a new state (reduces stack depth)
    struct NewStateParams {
        bytes32 commitment;
        bytes32 nullifier;
        bytes32 metadata;
        address owner;
        uint48 timestamp;
        uint32 version;
    }

    /// @notice Parameters for state transfer (reduces stack depth)
    struct TransferStateParams {
        bytes32 oldCommitment;
        bytes32 newCommitment;
        bytes32 newNullifier;
        bytes32 spendingNullifier;
        address newOwner;
        address caller;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifier interface (storage instead of immutable for proxy)
    ICSCProofVerifier public verifier;

    /// @notice Mapping from commitment to encrypted state
    mapping(bytes32 => EncryptedState) internal _states;

    /// @notice Mapping of nullifier to used status
    mapping(bytes32 => bool) internal _nullifiers;

    /// @notice Mapping of nullifier to commitment (reverse lookup)
    mapping(bytes32 => bytes32) internal _nullifierToCommitment;

    /// @notice Mapping of owner to their commitments
    mapping(address => bytes32[]) internal _ownerCommitments;

    /// @notice State transition history
    mapping(bytes32 => StateTransition[]) internal _stateHistory;

    /// @dev Packed counters: totalStates (128 bits) | activeStates (128 bits)
    uint256 private _packedCounters;

    /// @dev Packed config: proofValidityWindow (128 bits) | maxStateSize (128 bits)
    uint256 private _packedConfig;

    /// @notice Maximum history length per state
    uint256 public constant MAX_HISTORY_LENGTH = 100;

    /// @notice Nonce for signature replay prevention
    mapping(address => uint256) public nonces;

    /// @notice EIP-712 domain separator (storage instead of immutable for proxy)
    bytes32 public domainSeparator;

    /// @notice EIP-712 type hash for state registration
    bytes32 public constant REGISTER_STATE_TYPEHASH =
        keccak256(
            "RegisterState(bytes32 commitment,bytes32 nullifier,address owner,bytes32 encryptedStateHash,bytes32 metadata,uint256 nonce,uint256 deadline,uint256 chainId)"
        );

    /// @notice Chain ID for this deployment (storage instead of immutable)
    uint256 public chainId;

    /// @notice Contract version for upgrade tracking
    uint256 public contractVersion;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 private constant _DEFAULT_PROOF_VALIDITY = 1 hours;
    uint256 private constant _DEFAULT_MAX_STATE_SIZE = 65536;
    uint256 private constant _COUNTER_SHIFT = 128;
    uint256 private constant _COUNTER_INCREMENT = uint256(1) << 128;

    /*//////////////////////////////////////////////////////////////
                            STORAGE GAP
    //////////////////////////////////////////////////////////////*/

    /// @dev Reserved storage gap for future upgrades
    uint256[50] private __gap;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    // Events inherited from IConfidentialStateContainerV3

    event ContractUpgraded(
        uint256 indexed oldVersion,
        uint256 indexed newVersion
    );

    // Errors inherited from IConfidentialStateContainerV3

    /*//////////////////////////////////////////////////////////////
                             INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the contract (replaces constructor)
    /// @param admin The initial admin address
    /// @param _verifier Address of the proof verifier contract
        /**
     * @notice Initializes the operation
     * @param admin The admin bound
     * @param _verifier The _verifier
     */
function initialize(address admin, address _verifier) public initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (_verifier == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        verifier = ICSCProofVerifier(_verifier);
        chainId = block.chainid;

        // Compute domain separator with proxy address
        domainSeparator = keccak256(
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
            (_DEFAULT_PROOF_VALIDITY << _COUNTER_SHIFT) |
            _DEFAULT_MAX_STATE_SIZE;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(EMERGENCY_ROLE, admin);
        _grantRole(VERIFIER_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

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
                         PACKED STORAGE GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Total states registered
        /**
     * @notice Total states
     * @return The result value
     */
function totalStates() external view returns (uint256) {
        return _packedCounters >> _COUNTER_SHIFT;
    }

    /// @notice Total active states
        /**
     * @notice Active states
     * @return The result value
     */
function activeStates() external view returns (uint256) {
        return uint128(_packedCounters);
    }

    /// @notice Minimum proof validity window
        /**
     * @notice Proof validity window
     * @return The result value
     */
function proofValidityWindow() external view returns (uint256) {
        return _packedConfig >> _COUNTER_SHIFT;
    }

    /// @notice Maximum encrypted state size
        /**
     * @notice Max state size
     * @return The result value
     */
function maxStateSize() public view returns (uint256) {
        return uint128(_packedConfig);
    }

    /// @notice Public getter for states mapping
        /**
     * @notice States
     * @param commitment The cryptographic commitment
     * @return The result value
     */
function states(
        bytes32 commitment
    ) external view returns (EncryptedState memory) {
        return _states[commitment];
    }

    /// @notice Public getter for nullifiers
        /**
     * @notice Nullifiers
     * @param nullifier The nullifier hash
     * @return The result value
     */
function nullifiers(bytes32 nullifier) external view returns (bool) {
        return _nullifiers[nullifier];
    }

    /// @notice Public getter for nullifier to commitment
        /**
     * @notice Nullifier to commitment
     * @param nullifier The nullifier hash
     * @return The result value
     */
function nullifierToCommitment(
        bytes32 nullifier
    ) external view returns (bytes32) {
        return _nullifierToCommitment[nullifier];
    }

    /// @notice Public getter for owner commitments
        /**
     * @notice Owner commitments
     * @param owner The owner address
     * @param index The index in the collection
     * @return The result value
     */
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
    /// @param metadata Optional metadata hash
        /**
     * @notice Registers state
     * @param encryptedState The encrypted state
     * @param commitment The cryptographic commitment
     * @param nullifier The nullifier hash
     * @param proof The ZK proof data
     * @param metadata The metadata bytes
     */
function registerState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32 metadata
    ) external nonReentrant whenNotPaused {
        _validateAndRegisterState(
            encryptedState,
            commitment,
            nullifier,
            proof,
            metadata,
            msg.sender
        );
    }

    /// @notice Registers state with signature (meta-transaction support)
    /// @param encryptedState The encrypted state data
    /// @param commitment The Pedersen commitment
    /// @param nullifier The nullifier
    /// @param proof The ZK proof bytes
    /// @param metadata Optional metadata hash
    /// @param owner The intended owner
    /// @param deadline Signature deadline
    /// @param signature Owner's signature
        /**
     * @notice Registers state with signature
     * @param encryptedState The encrypted state
     * @param commitment The cryptographic commitment
     * @param nullifier The nullifier hash
     * @param proof The ZK proof data
     * @param metadata The metadata bytes
     * @param owner The owner address
     * @param deadline The deadline timestamp
     * @param signature The cryptographic signature
     */
function registerStateWithSignature(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32 metadata,
        address owner,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant whenNotPaused {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (block.chainid != chainId) revert InvalidSignature();

        bytes32 structHash = keccak256(
            abi.encode(
                REGISTER_STATE_TYPEHASH,
                commitment,
                nullifier,
                owner,
                keccak256(encryptedState),
                metadata,
                nonces[owner]++,
                deadline,
                block.chainid
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, structHash)
        );
        address signer = digest.recover(signature);

        if (signer != owner) revert InvalidSignature();

        _validateAndRegisterState(
            encryptedState,
            commitment,
            nullifier,
            proof,
            metadata,
            owner
        );
    }

    /// @notice Batch registers multiple states
    /// @param stateInputs Array of state data to register
        /**
     * @notice Batchs register states
     * @param stateInputs The state inputs
     */
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
    /// @param spendingNullifier The spending nullifier to consume
    /// @param proof The ZK proof
    /// @param newOwner The new owner address
        /**
     * @notice Transfers state
     * @param oldCommitment The old commitment
     * @param newEncryptedState The new EncryptedState value
     * @param newCommitment The new Commitment value
     * @param newNullifier The new Nullifier value
     * @param spendingNullifier The spending nullifier
     * @param proof The ZK proof data
     * @param newOwner The new Owner value
     */
function transferState(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes32 spendingNullifier,
        bytes calldata proof,
        address newOwner
    ) external nonReentrant whenNotPaused {
        _transferState(
            TransferStateParams({
                oldCommitment: oldCommitment,
                newCommitment: newCommitment,
                newNullifier: newNullifier,
                spendingNullifier: spendingNullifier,
                newOwner: newOwner,
                caller: msg.sender
            }),
            newEncryptedState,
            proof
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
        bytes32 metadata,
        address owner
    ) internal {
        uint256 stateLen = encryptedState.length;
        if (stateLen == 0) revert EmptyEncryptedState();
        uint256 _maxSize = uint128(_packedConfig);
        if (stateLen > _maxSize) revert StateSizeTooLarge(stateLen, _maxSize);

        if (_states[commitment].owner != address(0))
            revert CommitmentAlreadyExists(commitment);
        if (_nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        bytes memory publicInputs = abi.encode(
            commitment,
            nullifier,
            metadata,
            uint256(uint160(owner)),
            block.chainid
        );

        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();

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

        _nullifiers[nullifier] = true;
        _nullifierToCommitment[nullifier] = commitment;
        _ownerCommitments[owner].push(commitment);

        unchecked {
            _packedCounters += _COUNTER_INCREMENT + 1;
        }

        emit StateRegistered(commitment, owner, nullifier, block.timestamp);
    }

    function _validateTransferParams(
        bytes32 oldCommitment,
        bytes calldata newEncryptedState,
        bytes32 newNullifier,
        bytes32 spendingNullifier,
        address newOwner,
        address caller
    ) internal view returns (address oldOwner) {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newEncryptedState.length == 0) revert EmptyEncryptedState();
        uint256 _maxSize = uint128(_packedConfig);
        if (newEncryptedState.length > _maxSize)
            revert StateSizeTooLarge(newEncryptedState.length, _maxSize);

        EncryptedState storage oldState = _states[oldCommitment];
        oldOwner = oldState.owner;
        if (oldOwner == address(0)) revert CommitmentNotFound(oldCommitment);
        if (oldOwner != caller) revert NotStateOwner(caller, oldOwner);
        if (oldState.status != StateStatus.Active)
            revert StateNotActive(oldCommitment, oldState.status);
        if (_nullifiers[newNullifier])
            revert NullifierAlreadyUsed(newNullifier);
        if (_nullifiers[spendingNullifier])
            revert NullifierAlreadyUsed(spendingNullifier);
    }

        /**
     * @notice _verify transfer proof
     * @param oldCommitment The old commitment
     * @param newCommitment The new Commitment value
     * @param newNullifier The new Nullifier value
     * @param spendingNullifier The spending nullifier
     * @param newOwner The new Owner value
     * @param proof The ZK proof data
     */
function _verifyTransferProof(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        bytes32 newNullifier,
        bytes32 spendingNullifier,
        address newOwner,
        bytes calldata proof
    ) internal view {
        bytes memory publicInputs = abi.encode(
            oldCommitment,
            newCommitment,
            newNullifier,
            spendingNullifier,
            uint256(uint160(newOwner)),
            block.chainid
        );
        if (!verifier.verifyProof(proof, publicInputs)) revert InvalidProof();
    }

    function _transferState(
        TransferStateParams memory p,
        bytes calldata newEncryptedState,
        bytes calldata proof
    ) internal {
        address oldOwner = _validateTransferParams(
            p.oldCommitment,
            newEncryptedState,
            p.newNullifier,
            p.spendingNullifier,
            p.newOwner,
            p.caller
        );

        if (_states[p.newCommitment].owner != address(0))
            revert CommitmentAlreadyExists(p.newCommitment);

        _nullifiers[p.spendingNullifier] = true;
        _nullifierToCommitment[p.spendingNullifier] = p.oldCommitment;

        _verifyTransferProof(
            p.oldCommitment,
            p.newCommitment,
            p.newNullifier,
            p.spendingNullifier,
            p.newOwner,
            proof
        );

        _executeTransferStateUpdate(p, oldOwner, newEncryptedState);
    }

    function _executeTransferStateUpdate(
        TransferStateParams memory p,
        address oldOwner,
        bytes calldata newEncryptedState
    ) private {
        _recordTransitionHistory(
            p.oldCommitment,
            p.newCommitment,
            oldOwner,
            p.newOwner
        );

        EncryptedState storage oldState = _states[p.oldCommitment];
        uint48 timestamp = uint48(block.timestamp);
        uint32 newVersion = oldState.version + 1;
        bytes32 oldMetadata = oldState.metadata;

        oldState.status = StateStatus.Retired;
        oldState.updatedAt = timestamp;

        _createNewState(
            NewStateParams({
                commitment: p.newCommitment,
                nullifier: p.newNullifier,
                metadata: oldMetadata,
                owner: p.newOwner,
                timestamp: timestamp,
                version: newVersion
            }),
            newEncryptedState
        );

        emit StateTransferred(
            p.oldCommitment,
            p.newCommitment,
            p.newOwner,
            newVersion
        );
    }

    function _recordTransitionHistory(
        bytes32 oldCommitment,
        bytes32 newCommitment,
        address oldOwner,
        address newOwner
    ) internal {
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

    function _createNewState(
        NewStateParams memory params,
        bytes calldata encryptedState
    ) internal {
        EncryptedState storage newState = _states[params.commitment];
        newState.commitment = params.commitment;
        newState.nullifier = params.nullifier;
        newState.metadata = params.metadata;
        newState.owner = params.owner;
        newState.createdAt = params.timestamp;
        newState.updatedAt = params.timestamp;
        newState.version = params.version;
        newState.status = StateStatus.Active;
        newState.encryptedState = encryptedState;

        _nullifiers[params.nullifier] = true;
        _nullifierToCommitment[params.nullifier] = params.commitment;
        _ownerCommitments[params.owner].push(params.commitment);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Checks if a state exists and is active
    /// @param commitment The commitment to check
    /// @return True if exists and active
        /**
     * @notice Checks if state active
     * @param commitment The cryptographic commitment
     * @return The result value
     */
function isStateActive(bytes32 commitment) external view returns (bool) {
        return _states[commitment].status == StateStatus.Active;
    }

    /// @notice Gets full state details
    /// @param commitment The commitment to query
    /// @return state The encrypted state struct
        /**
     * @notice Returns the state
     * @param commitment The cryptographic commitment
     * @return state The state
     */
function getState(
        bytes32 commitment
    ) external view returns (EncryptedState memory state) {
        return _states[commitment];
    }

    /// @notice Gets all commitments for an owner
    /// @param owner The owner address
    /// @return commitments Array of commitment hashes
        /**
     * @notice Returns the owner commitments
     * @param owner The owner address
     * @return commitments The commitments
     */
function getOwnerCommitments(
        address owner
    ) external view returns (bytes32[] memory commitments) {
        return _ownerCommitments[owner];
    }

    /// @notice Gets commitments for an owner with pagination
    /// @param owner The owner address
    /// @param offset Starting index
    /// @param limit Maximum number of commitments to return
    /// @return commitments Array of commitment hashes
    /// @return total Total number of commitments for this owner
        /**
     * @notice Returns the owner commitments paginated
     * @param owner The owner address
     * @param offset The offset
     * @param limit The limit value
     * @return commitments The commitments
     * @return total The total
     */
function getOwnerCommitmentsPaginated(
        address owner,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory commitments, uint256 total) {
        bytes32[] storage allCommitments = _ownerCommitments[owner];
        total = allCommitments.length;

        if (offset >= total) {
            return (new bytes32[](0), total);
        }

        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        commitments = new bytes32[](count);

        for (uint256 i = 0; i < count; ) {
            commitments[i] = allCommitments[offset + i];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Gets state transition history
    /// @param commitment The commitment to query
    /// @return transitions Array of state transitions
        /**
     * @notice Returns the state history
     * @param commitment The cryptographic commitment
     * @return transitions The transitions
     */
function getStateHistory(
        bytes32 commitment
    ) external view returns (StateTransition[] memory transitions) {
        return _stateHistory[commitment];
    }

    /// @notice Gets current nonce for an address
    /// @param account The account to query
    /// @return nonce The current nonce
        /**
     * @notice Returns the nonce
     * @param account The account address
     * @return nonce The nonce
     */
function getNonce(address account) external view returns (uint256 nonce) {
        return nonces[account];
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Updates proof validity window
    /// @param _window The new window in seconds
        /**
     * @notice Sets the proof validity window
     * @param _window The _window
     */
function setProofValidityWindow(
        uint256 _window
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 packed = _packedConfig;
        uint256 oldWindow = packed >> _COUNTER_SHIFT;
        _packedConfig = (_window << _COUNTER_SHIFT) | uint128(packed);
        emit ProofValidityWindowUpdated(oldWindow, _window);
    }

    /// @notice Updates maximum state size
    /// @param _maxSize The new maximum size in bytes
        /**
     * @notice Sets the max state size
     * @param _maxSize The _maxSize bound
     */
function setMaxStateSize(
        uint256 _maxSize
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_maxSize <= type(uint128).max, "Size exceeds uint128");
        uint256 packed = _packedConfig;
        uint256 oldSize = uint128(packed);
        _packedConfig =
            (packed & (uint256(type(uint128).max) << _COUNTER_SHIFT)) |
            _maxSize;
        emit MaxStateSizeUpdated(oldSize, _maxSize);
    }

    /// @notice Locks a state
    /// @param commitment The commitment to lock
        /**
     * @notice Locks state
     * @param commitment The cryptographic commitment
     */
function lockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);
        if (state.status != StateStatus.Active)
            revert StateNotActive(commitment, state.status);

        state.status = StateStatus.Locked;
        state.updatedAt = uint48(block.timestamp);

        emit StateStatusChanged(
            commitment,
            StateStatus.Active,
            StateStatus.Locked
        );
    }

    /// @notice Unlocks a previously locked state
    /// @param commitment The commitment to unlock
        /**
     * @notice Unlocks state
     * @param commitment The cryptographic commitment
     */
function unlockState(bytes32 commitment) external onlyRole(OPERATOR_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);
        if (state.status != StateStatus.Locked)
            revert StateNotActive(commitment, state.status);

        state.status = StateStatus.Active;
        state.updatedAt = uint48(block.timestamp);

        emit StateStatusChanged(
            commitment,
            StateStatus.Locked,
            StateStatus.Active
        );
    }

    /// @notice Freezes a state (compliance action)
    /// @param commitment The commitment to freeze
        /**
     * @notice Freeze state
     * @param commitment The cryptographic commitment
     */
function freezeState(bytes32 commitment) external onlyRole(EMERGENCY_ROLE) {
        EncryptedState storage state = _states[commitment];
        if (state.owner == address(0)) revert CommitmentNotFound(commitment);

        StateStatus oldStatus = state.status;
        if (oldStatus != StateStatus.Active && oldStatus != StateStatus.Locked)
            revert StateNotActive(commitment, oldStatus);

        state.status = StateStatus.Frozen;
        state.updatedAt = uint48(block.timestamp);

        if (oldStatus == StateStatus.Active) {
            uint128 activeCount = uint128(_packedCounters);
            if (activeCount > 0) {
                unchecked {
                    --_packedCounters;
                }
            }
        }

        emit StateStatusChanged(commitment, oldStatus, StateStatus.Frozen);
    }

    /// @notice Pauses the contract
        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}

/*//////////////////////////////////////////////////////////////
                          INTERFACES
//////////////////////////////////////////////////////////////*/

interface ICSCProofVerifier {
        /**
     * @notice Verifys proof
     * @param proof The ZK proof data
     * @param publicInputs The public inputs
     * @return The result value
     */
function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool);
}

// CSCBatchStateInput removed — using BatchStateInput from IConfidentialStateContainerV3 to avoid overload clash
