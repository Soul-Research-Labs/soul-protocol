// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title CrossChainCommitmentRelay
 * @author Soul Protocol
 * @notice Bridges CrossChainPrivacyHub ↔ UniversalShieldedPool for cross-chain commitment sync.
 *
 * @dev This contract is the missing link between:
 *   - CrossChainPrivacyHub.completeTransfer() (which marks transfers complete on dest chain)
 *   - UniversalShieldedPool.insertCrossChainCommitments() (which inserts commitments into the Merkle tree)
 *
 * FLOW:
 *   1. Relayer detects commitments on source chain via events
 *   2. Relayer calls this relay contract with the batch of commitments + proof
 *   3. Relay verifies the relayer's role, validates batch integrity
 *   4. Relay calls ShieldedPool.insertCrossChainCommitments() to insert into local Merkle tree
 *   5. User can then withdraw on the destination chain using a ZK proof referencing the new root
 *
 * ARCHITECTURE:
 *   ┌──────────────┐      ┌────────────────────────┐      ┌─────────────────────────┐
 *   │ CrossChain   │ ───> │ CrossChainCommitment   │ ───> │ UniversalShieldedPool   │
 *   │ PrivacyHub   │      │ Relay (this)           │      │ .insertCrossChain       │
 *   │ (completes   │      │ (bridges the gap)      │      │  Commitments()          │
 *   │  transfers)  │      └────────────────────────┘      └─────────────────────────┘
 *   └──────────────┘
 *
 * @custom:security-contact security@soul.network
 */
contract CrossChainCommitmentRelay is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Mirrors UniversalShieldedPool.CrossChainCommitmentBatch
    struct CommitmentBatch {
        bytes32 sourceChainId;
        bytes32[] commitments;
        bytes32[] assetIds;
        bytes32 batchRoot;
        bytes proof;
        uint256 sourceTreeSize;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The shielded pool to relay commitments into
    address public shieldedPool;

    /// @notice The cross-chain privacy hub
    address public privacyHub;

    /// @notice Total batches relayed
    uint256 public totalBatchesRelayed;

    /// @notice Processed batch roots (dedup)
    mapping(bytes32 => bool) public processedBatches;

    /// @notice Per-chain commitment counts
    mapping(bytes32 => uint256) public chainCommitmentCounts;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event BatchRelayed(
        bytes32 indexed sourceChainId,
        bytes32 indexed batchRoot,
        uint256 commitmentCount,
        address indexed relayer
    );

    event ShieldedPoolUpdated(address indexed oldPool, address indexed newPool);
    event PrivacyHubUpdated(address indexed oldHub, address indexed newHub);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error BatchAlreadyRelayed(bytes32 batchRoot);
    error EmptyBatch();
    error BatchLengthMismatch();
    error RelayFailed(string reason);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _shieldedPool, address _privacyHub) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        if (_shieldedPool != address(0)) {
            shieldedPool = _shieldedPool;
        }
        if (_privacyHub != address(0)) {
            privacyHub = _privacyHub;
        }
    }

    /*//////////////////////////////////////////////////////////////
                          RELAY OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Relay a batch of commitments from a source chain into the local ShieldedPool
     * @dev The relayer must have RELAYER_ROLE on both this contract AND the ShieldedPool.
     *      The ShieldedPool.insertCrossChainCommitments() is gated by its own RELAYER_ROLE,
     *      so this contract's address must be granted RELAYER_ROLE on the pool.
     * @param batch The commitment batch to relay
     */
    function relayCommitmentBatch(
        CommitmentBatch calldata batch
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (shieldedPool == address(0)) revert ZeroAddress();
        if (batch.commitments.length == 0) revert EmptyBatch();
        if (batch.commitments.length != batch.assetIds.length)
            revert BatchLengthMismatch();
        if (processedBatches[batch.batchRoot])
            revert BatchAlreadyRelayed(batch.batchRoot);

        processedBatches[batch.batchRoot] = true;

        // Forward to UniversalShieldedPool.insertCrossChainCommitments()
        // Uses the same struct layout
        (bool success, bytes memory returnData) = shieldedPool.call(
            abi.encodeWithSignature(
                "insertCrossChainCommitments((bytes32,bytes32[],bytes32[],bytes32,bytes,uint256))",
                batch.sourceChainId,
                batch.commitments,
                batch.assetIds,
                batch.batchRoot,
                batch.proof,
                batch.sourceTreeSize
            )
        );

        if (!success) {
            // Bubble up the revert reason
            if (returnData.length > 0) {
                assembly {
                    revert(add(returnData, 32), mload(returnData))
                }
            }
            revert RelayFailed("insertCrossChainCommitments call failed");
        }

        unchecked {
            ++totalBatchesRelayed;
            chainCommitmentCounts[batch.sourceChainId] += batch
                .commitments
                .length;
        }

        emit BatchRelayed(
            batch.sourceChainId,
            batch.batchRoot,
            batch.commitments.length,
            msg.sender
        );
    }

    /**
     * @notice Relay multiple batches in a single transaction (gas optimization)
     * @param batches Array of commitment batches to relay
     */
    function relayMultipleBatches(
        CommitmentBatch[] calldata batches
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (shieldedPool == address(0)) revert ZeroAddress();

        for (uint256 i = 0; i < batches.length; ) {
            CommitmentBatch calldata batch = batches[i];

            if (batch.commitments.length == 0) revert EmptyBatch();
            if (batch.commitments.length != batch.assetIds.length)
                revert BatchLengthMismatch();
            if (processedBatches[batch.batchRoot])
                revert BatchAlreadyRelayed(batch.batchRoot);

            processedBatches[batch.batchRoot] = true;

            (bool success, bytes memory returnData) = shieldedPool.call(
                abi.encodeWithSignature(
                    "insertCrossChainCommitments((bytes32,bytes32[],bytes32[],bytes32,bytes,uint256))",
                    batch.sourceChainId,
                    batch.commitments,
                    batch.assetIds,
                    batch.batchRoot,
                    batch.proof,
                    batch.sourceTreeSize
                )
            );

            if (!success) {
                if (returnData.length > 0) {
                    assembly {
                        revert(add(returnData, 32), mload(returnData))
                    }
                }
                revert RelayFailed("batch relay failed");
            }

            unchecked {
                ++totalBatchesRelayed;
                chainCommitmentCounts[batch.sourceChainId] += batch
                    .commitments
                    .length;
            }

            emit BatchRelayed(
                batch.sourceChainId,
                batch.batchRoot,
                batch.commitments.length,
                msg.sender
            );

            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Permissionless self-relay for users — bypasses RELAYER_ROLE.
     * @dev Prevents censorship and single-point-of-failure if all relayers go offline.
     *      Mirrors SoulCrossChainRelay.selfRelayProof() pattern.
     *      Anyone can relay a commitment batch by paying gas directly.
     *      The shielded pool's own RELAYER_ROLE gate still applies — this contract's
     *      address must be granted RELAYER_ROLE on the pool.
     * @param batch The commitment batch to relay
     */
    function selfRelayCommitmentBatch(
        CommitmentBatch calldata batch
    ) external nonReentrant whenNotPaused {
        if (shieldedPool == address(0)) revert ZeroAddress();
        if (batch.commitments.length == 0) revert EmptyBatch();
        if (batch.commitments.length != batch.assetIds.length)
            revert BatchLengthMismatch();
        if (processedBatches[batch.batchRoot])
            revert BatchAlreadyRelayed(batch.batchRoot);

        processedBatches[batch.batchRoot] = true;

        // Forward to UniversalShieldedPool.insertCrossChainCommitments()
        (bool success, bytes memory returnData) = shieldedPool.call(
            abi.encodeWithSignature(
                "insertCrossChainCommitments((bytes32,bytes32[],bytes32[],bytes32,bytes,uint256))",
                batch.sourceChainId,
                batch.commitments,
                batch.assetIds,
                batch.batchRoot,
                batch.proof,
                batch.sourceTreeSize
            )
        );

        if (!success) {
            if (returnData.length > 0) {
                assembly {
                    revert(add(returnData, 32), mload(returnData))
                }
            }
            revert RelayFailed("self-relay insertCrossChainCommitments failed");
        }

        unchecked {
            ++totalBatchesRelayed;
            chainCommitmentCounts[batch.sourceChainId] += batch
                .commitments
                .length;
        }

        emit BatchRelayed(
            batch.sourceChainId,
            batch.batchRoot,
            batch.commitments.length,
            msg.sender
        );
    }

    /// @notice Set the shielded pool contract address
    /// @param _pool The new shielded pool address (must be non-zero)
    function setShieldedPool(address _pool) external onlyRole(OPERATOR_ROLE) {
        if (_pool == address(0)) revert ZeroAddress();
        address old = shieldedPool;
        shieldedPool = _pool;
        emit ShieldedPoolUpdated(old, _pool);
    }

    /// @notice Set the privacy hub contract address
    /// @param _hub The new privacy hub address (must be non-zero)
    function setPrivacyHub(address _hub) external onlyRole(OPERATOR_ROLE) {
        if (_hub == address(0)) revert ZeroAddress();
        address old = privacyHub;
        privacyHub = _hub;
        emit PrivacyHubUpdated(old, _hub);
    }

    /// @notice Pause commitment relay operations
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause commitment relay operations
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the number of commitments relayed for a given chain
    /// @param chainId The universal chain identifier
    /// @return The total commitment count for the chain
    function getChainStats(bytes32 chainId) external view returns (uint256) {
        return chainCommitmentCounts[chainId];
    }
}
