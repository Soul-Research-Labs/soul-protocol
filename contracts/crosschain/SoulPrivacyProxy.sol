// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISoulLookupTable} from "../interfaces/ISoulLookupTable.sol";
import {ISoulExecutionTable} from "../interfaces/ISoulExecutionTable.sol";

/// @title SoulPrivacyProxy
/// @author Soul Protocol
/// @notice Proxy contract for synchronous cross-chain privacy calls
/// @dev Deployed on L1/L2, represents Soul privacy contracts on remote chains
///
/// This contract enables synchronous privacy operations by:
/// 1. Looking up pre-proven I/O from the lookup table
/// 2. Consuming execution table entries for cross-chain calls
/// 3. Providing a local interface that behaves like calling the remote contract
///
/// From the caller's perspective, interacting with the proxy is indistinguishable
/// from interacting with the real contract on the remote chain.
///
/// Reference: https://ethresear.ch/t/synchronous-composability-between-rollups-via-realtime-proving/23998
contract SoulPrivacyProxy {
    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Configuration for the proxy
    struct ProxyConfig {
        uint64 remoteChainId;
        address remoteContract;
        address lookupTable;
        address executionTable;
        bool requirePreProven; // If true, only pre-proven operations allowed
    }

    /*//////////////////////////////////////////////////////////////
                              IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice The lookup table for pre-proven I/O
    ISoulLookupTable public immutable lookupTable;

    /// @notice The execution table for cross-chain operations
    ISoulExecutionTable public immutable executionTable;

    /// @notice Remote chain ID this proxy represents
    uint64 public immutable remoteChainId;

    /// @notice Remote contract address this proxy represents
    address public immutable remoteContract;

    /// @notice This chain's ID
    uint64 public immutable thisChainId;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Whether to require pre-proven operations only
    bool public requirePreProven;

    /// @notice Active execution table for nested calls
    bytes32 public activeTableId;

    /// @notice Current execution index in active table
    uint256 public currentEntryIndex;

    /// @notice Mapping of input hash to consumed status
    mapping(bytes32 => bool) public consumedLookups;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a proxy call is executed
    event ProxyCallExecuted(
        bytes32 indexed inputHash,
        bytes32 indexed outputHash,
        address indexed caller,
        bool fromLookupTable
    );

    /// @notice Emitted when a private transfer is executed
    event PrivateTransferExecuted(
        bytes32 indexed commitment,
        bytes32 indexed nullifier,
        address indexed caller
    );

    /// @notice Emitted when an atomic swap is executed
    event AtomicSwapExecuted(bytes32 indexed swapId, address indexed initiator);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Operation not pre-proven and pre-proven required
    error OperationNotPreProven(bytes32 inputHash);

    /// @notice Invalid proof provided
    error InvalidProof();

    /// @notice Execution table mismatch
    error TableMismatch(bytes32 expected, bytes32 actual);

    /// @notice Not in execution context
    error NotInExecutionContext();

    /// @notice Lookup already consumed
    error LookupAlreadyConsumed(bytes32 inputHash);

    /// @notice Unauthorized caller
    error Unauthorized();

    /*//////////////////////////////////////////////////////////////
                                STORAGE (owner)
    //////////////////////////////////////////////////////////////*/

    /// @notice Owner/admin of this proxy
    address public owner;

    /// @notice Only owner modifier
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy a privacy proxy
    /// @param _lookupTable Address of the lookup table contract
    /// @param _executionTable Address of the execution table contract
    /// @param _remoteChainId Chain ID of the remote chain
    /// @param _remoteContract Address of the remote contract
    constructor(
        address _lookupTable,
        address _executionTable,
        uint64 _remoteChainId,
        address _remoteContract
    ) {
        lookupTable = ISoulLookupTable(_lookupTable);
        executionTable = ISoulExecutionTable(_executionTable);
        remoteChainId = _remoteChainId;
        remoteContract = _remoteContract;
        thisChainId = uint64(block.chainid);
        owner = msg.sender;
        requirePreProven = true;
    }

    /*//////////////////////////////////////////////////////////////
                          SYNCHRONOUS CALLS
    //////////////////////////////////////////////////////////////*/

    /// @notice Execute a synchronous privacy-preserving transfer
    /// @param commitment The Pedersen commitment for the transfer
    /// @param nullifier The nullifier to spend (prevents double-spend)
    /// @param recipient Encrypted recipient (only decryptable by recipient)
    /// @param proof ZK proof of valid transfer (or empty if using lookup table)
    /// @return success Whether the transfer succeeded
    function privateTransfer(
        bytes32 commitment,
        bytes32 nullifier,
        bytes32 recipient,
        bytes calldata proof
    ) external returns (bool success) {
        // Compute input hash
        bytes32 inputHash = keccak256(
            abi.encode(
                this.privateTransfer.selector,
                commitment,
                nullifier,
                recipient
            )
        );

        // Try lookup table first
        if (lookupTable.lookupExists(inputHash)) {
            ISoulLookupTable.LookupEntry memory entry = lookupTable
                .consumeLookup(inputHash);

            // Verify nullifier delta matches
            require(entry.nullifierDelta == nullifier, "Nullifier mismatch");

            emit PrivateTransferExecuted(commitment, nullifier, msg.sender);
            emit ProxyCallExecuted(
                inputHash,
                entry.outputHash,
                msg.sender,
                true
            );

            return true;
        }

        // If pre-proven required and not found, revert
        if (requirePreProven) {
            revert OperationNotPreProven(inputHash);
        }

        // Otherwise, verify proof inline (expensive but works)
        // This path is for backwards compatibility
        if (proof.length > 0) {
            // Verify proof via lookup table's verifier
            // In production, this would call the appropriate verifier
            // For now, we require pre-proven operations
            revert OperationNotPreProven(inputHash);
        }

        revert InvalidProof();
    }

    /// @notice Execute a synchronous atomic swap
    /// @param swapId Unique swap identifier
    /// @param counterpartyCommitment Counterparty's commitment
    /// @param myNullifier My nullifier to spend
    /// @param proof ZK proof of valid swap
    /// @return success Whether the swap succeeded
    function atomicSwap(
        bytes32 swapId,
        bytes32 counterpartyCommitment,
        bytes32 myNullifier,
        bytes calldata proof
    ) external returns (bool success) {
        bytes32 inputHash = keccak256(
            abi.encode(
                this.atomicSwap.selector,
                swapId,
                counterpartyCommitment,
                myNullifier
            )
        );

        if (lookupTable.lookupExists(inputHash)) {
            ISoulLookupTable.LookupEntry memory entry = lookupTable
                .consumeLookup(inputHash);

            emit AtomicSwapExecuted(swapId, msg.sender);
            emit ProxyCallExecuted(
                inputHash,
                entry.outputHash,
                msg.sender,
                true
            );

            return true;
        }

        if (requirePreProven) {
            revert OperationNotPreProven(inputHash);
        }

        revert InvalidProof();
    }

    /// @notice Execute a state unlock operation
    /// @param lockId The lock to unlock
    /// @param proof ZK proof of valid unlock conditions
    /// @return unlockedState The unlocked state data
    function unlockState(
        bytes32 lockId,
        bytes calldata proof
    ) external returns (bytes memory unlockedState) {
        bytes32 inputHash = keccak256(
            abi.encode(this.unlockState.selector, lockId)
        );

        if (lookupTable.lookupExists(inputHash)) {
            ISoulLookupTable.LookupEntry memory entry = lookupTable
                .consumeLookup(inputHash);

            // Return data is encoded in the output hash
            // In practice, we'd store the actual return data
            emit ProxyCallExecuted(
                inputHash,
                entry.outputHash,
                msg.sender,
                true
            );

            return abi.encode(entry.outputHash);
        }

        if (requirePreProven) {
            revert OperationNotPreProven(inputHash);
        }

        revert InvalidProof();
    }

    /// @notice Verify a credential without revealing it
    /// @param credentialHash Hash of the credential
    /// @param policyId Policy to verify against
    /// @param proof ZK proof of credential validity
    /// @return valid Whether credential is valid for policy
    function verifyCredential(
        bytes32 credentialHash,
        bytes32 policyId,
        bytes calldata proof
    ) external returns (bool valid) {
        bytes32 inputHash = keccak256(
            abi.encode(this.verifyCredential.selector, credentialHash, policyId)
        );

        if (lookupTable.lookupExists(inputHash)) {
            ISoulLookupTable.LookupEntry memory entry = lookupTable
                .consumeLookup(inputHash);
            emit ProxyCallExecuted(
                inputHash,
                entry.outputHash,
                msg.sender,
                true
            );

            // Output hash encodes validity
            return entry.outputHash != bytes32(0);
        }

        if (requirePreProven) {
            revert OperationNotPreProven(inputHash);
        }

        revert InvalidProof();
    }

    /*//////////////////////////////////////////////////////////////
                       EXECUTION TABLE CONTEXT
    //////////////////////////////////////////////////////////////*/

    /// @notice Set active execution table for nested calls
    /// @dev Called by execution table when starting cross-chain execution
    /// @param tableId The table being executed
    /// @param entryIndex Current entry index
    function setExecutionContext(bytes32 tableId, uint256 entryIndex) external {
        require(msg.sender == address(executionTable), "Only execution table");
        activeTableId = tableId;
        currentEntryIndex = entryIndex;
    }

    /// @notice Clear execution context after completion
    function clearExecutionContext() external {
        require(msg.sender == address(executionTable), "Only execution table");
        activeTableId = bytes32(0);
        currentEntryIndex = 0;
    }

    /// @notice Execute from active execution table
    /// @dev Used for nested L1 calls during cross-chain execution
    /// @return result The return data
    function executeFromTable() external returns (bytes memory result) {
        if (activeTableId == bytes32(0)) {
            revert NotInExecutionContext();
        }

        return executionTable.executeEntry(activeTableId, currentEntryIndex);
    }

    /*//////////////////////////////////////////////////////////////
                          GENERIC CALL PROXY
    //////////////////////////////////////////////////////////////*/

    /// @notice Generic proxy call with pre-proven I/O
    /// @param callData The call data to execute
    /// @return result The return data
    function proxyCall(
        bytes calldata callData
    ) external returns (bytes memory result) {
        bytes32 inputHash = keccak256(callData);

        if (lookupTable.lookupExists(inputHash)) {
            ISoulLookupTable.LookupEntry memory entry = lookupTable
                .consumeLookup(inputHash);
            emit ProxyCallExecuted(
                inputHash,
                entry.outputHash,
                msg.sender,
                true
            );

            // In a full implementation, we'd return the actual stored return data
            return abi.encode(entry.outputHash);
        }

        if (requirePreProven) {
            revert OperationNotPreProven(inputHash);
        }

        revert InvalidProof();
    }

    /*//////////////////////////////////////////////////////////////
                            ADMINISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Toggle pre-proven requirement
    /// @param required Whether pre-proven is required
    function setRequirePreProven(bool required) external onlyOwner {
        requirePreProven = required;
    }

    /*//////////////////////////////////////////////////////////////
                               GETTERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get proxy configuration
    /// @return config The proxy configuration
    function getConfig() external view returns (ProxyConfig memory config) {
        return
            ProxyConfig({
                remoteChainId: remoteChainId,
                remoteContract: remoteContract,
                lookupTable: address(lookupTable),
                executionTable: address(executionTable),
                requirePreProven: requirePreProven
            });
    }

    /// @notice Check if an operation is pre-proven
    /// @param callData The call data to check
    /// @return proven Whether the operation is pre-proven
    function isPreProven(
        bytes calldata callData
    ) external view returns (bool proven) {
        bytes32 inputHash = keccak256(callData);
        return lookupTable.lookupExists(inputHash);
    }
}
