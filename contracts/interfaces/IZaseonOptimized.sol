// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IZaseonOptimized
 * @author ZASEON
 * @notice Gas-optimized interfaces for ZASEON core operations
 * @dev Designed for minimal gas overhead with efficient call patterns
 *
 * OPTIMIZATION PRINCIPLES:
 * - Use calldata for array/bytes parameters (saves ~3k gas per call)
 * - Minimal return data where possible
 * - Batch operations to amortize fixed costs
 * - Custom errors instead of require strings
 */

/*//////////////////////////////////////////////////////////////
                           COMMON ERRORS
//////////////////////////////////////////////////////////////*/

/// @notice Common custom errors shared across contracts
/// @dev Using custom errors saves ~100 gas vs require strings

error Unauthorized();
error InvalidProof();
error InvalidNullifier();
error NullifierAlreadySpent();
error InvalidCommitment();
error CommitmentAlreadyExists();
error InvalidChainId();
error InvalidAddress();
error BatchTooLarge();
error ExpiredDeadline();
error InvalidSignature();
error Paused();

/*//////////////////////////////////////////////////////////////
                     NULLIFIER OPERATIONS
//////////////////////////////////////////////////////////////*/

/**
 * @title INullifierRegistry
 * @notice Optimized interface for nullifier operations
 */
interface INullifierRegistry {
    /**
     * @notice Check if nullifier is spent (single)
     * @param nullifier The nullifier hash
     * @return spent True if already spent
     */
    function isSpent(bytes32 nullifier) external view returns (bool spent);

    /**
     * @notice Batch check nullifiers (gas efficient)
     * @param nullifiers Array of nullifier hashes
     * @return bitmap Packed bitmap of spent status (bit i = nullifiers[i])
     */
    function batchIsSpent(
        bytes32[] calldata nullifiers
    ) external view returns (uint256 bitmap);

    /**
     * @notice Register nullifier (authorized only)
     * @param nullifier The nullifier to register
     * @param commitment Associated commitment
     * @return index Tree index of registered nullifier
     */
    function register(
        bytes32 nullifier,
        bytes32 commitment
    ) external returns (uint256 index);

    /**
     * @notice Batch register nullifiers
     * @param nullifiers Array of nullifiers
     * @param commitments Array of commitments (same length or empty)
     * @return startIndex Starting tree index
     */
    function batchRegister(
        bytes32[] calldata nullifiers,
        bytes32[] calldata commitments
    ) external returns (uint256 startIndex);

    /**
     * @notice Get current merkle root
     */
    function getMerkleRoot() external view returns (bytes32 root);
}

/*//////////////////////////////////////////////////////////////
                    STATE CONTAINER OPERATIONS
//////////////////////////////////////////////////////////////*/

/**
 * @title IStateContainer
 * @notice Optimized interface for confidential state operations
 */
interface IStateContainer {
    /**
     * @notice Register new confidential state
     * @param encryptedState The encrypted state data
     * @param commitment Pedersen commitment
     * @param nullifier Nullifier for double-spend prevention
     * @param proof ZK proof bytes
     * @param metadata Optional metadata hash
     */
    function registerState(
        bytes calldata encryptedState,
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32 metadata
    ) external;

    /**
     * @notice Get state by commitment
     * @param commitment The state commitment
     * @return owner State owner
     * @return status State status (0=Active, 1=Locked, 2=Frozen, 3=Retired)
     * @return exists Whether state exists
     */
    function getState(
        bytes32 commitment
    ) external view returns (address owner, uint8 status, bool exists);

    /**
     * @notice Transfer state ownership with proof
     * @param fromCommitment Source commitment
     * @param toCommitment Destination commitment
     * @param newOwner New owner address
     * @param proof Transfer proof
     */
    function transferState(
        bytes32 fromCommitment,
        bytes32 toCommitment,
        address newOwner,
        bytes calldata proof
    ) external;
}

/*//////////////////////////////////////////////////////////////
                   CROSS-CHAIN OPERATIONS
//////////////////////////////////////////////////////////////*/

/**
 * @title ICrossChainRelay
 * @notice Optimized interface for cross-chain messaging
 */
interface ICrossChainRelay {
    /**
     * @notice Send message to another chain
     * @param destChainId Destination chain ID
     * @param target Target contract address
     * @param data Call data
     * @param gasLimit Gas limit for execution
     * @return messageId Unique message identifier
     */
    function sendMessage(
        uint256 destChainId,
        address target,
        bytes calldata data,
        uint256 gasLimit
    ) external payable returns (bytes32 messageId);

    /**
     * @notice Get message status
     * @param messageId The message ID
     * @return status 0=Unknown, 1=Pending, 2=Relayed, 3=Executed, 4=Failed, 5=Expired
     */
    function getMessageStatus(
        bytes32 messageId
    ) external view returns (uint8 status);

    /**
     * @notice Estimate message fee
     * @param destChainId Destination chain
     * @param dataLength Approximate data length
     * @param gasLimit Gas limit
     * @return fee Estimated fee in wei
     */
    function estimateFee(
        uint256 destChainId,
        uint256 dataLength,
        uint256 gasLimit
    ) external view returns (uint256 fee);
}

/*//////////////////////////////////////////////////////////////
                    PROOF ROUTER OPERATIONS
//////////////////////////////////////////////////////////////*/

/**
 * @title IProofRouter
 * @notice Optimized interface for proof routing
 */
interface IProofRouter {
    /**
     * @notice Submit proof for cross-chain routing
     * @param proofType Type of proof (0-7)
     * @param destChainId Destination chain
     * @param proofData Proof bytes
     * @param publicInputs Public inputs
     * @return proofId Unique proof identifier
     */
    function submitProof(
        uint8 proofType,
        uint256 destChainId,
        bytes calldata proofData,
        bytes calldata publicInputs
    ) external returns (bytes32 proofId);

    /**
     * @notice Check if proof is cached
     * @param proofType Type of proof
     * @param proofData Proof data
     * @return cached True if proof result is cached
     * @return result Cached verification result
     */
    function checkCache(
        uint8 proofType,
        bytes calldata proofData
    ) external view returns (bool cached, bool result);

    /**
     * @notice Get batch status
     * @param batchId Batch identifier
     * @return status 0=Open, 1=Full, 2=Routing, 3=Completed, 4=Failed
     * @return proofCount Number of proofs in batch
     */
    function getBatchStatus(
        bytes32 batchId
    ) external view returns (uint8 status, uint256 proofCount);
}

/*//////////////////////////////////////////////////////////////
                    STEALTH ADDRESS OPERATIONS
//////////////////////////////////////////////////////////////*/

/**
 * @title IStealthRegistry
 * @notice Optimized interface for stealth address operations
 */
interface IStealthRegistry {
    /**
     * @notice Generate stealth address
     * @param ephemeralPubKeyX Ephemeral public key X coordinate
     * @param ephemeralPubKeyY Ephemeral public key Y coordinate
     * @param spendingPubKeyX Recipient spending key X
     * @param spendingPubKeyY Recipient spending key Y
     * @param viewingPubKeyX Recipient viewing key X
     * @param viewingPubKeyY Recipient viewing key Y
     * @return stealthAddress Generated stealth address
     * @return viewTag View tag for scanning
     */
    function generateStealthAddress(
        uint256 ephemeralPubKeyX,
        uint256 ephemeralPubKeyY,
        uint256 spendingPubKeyX,
        uint256 spendingPubKeyY,
        uint256 viewingPubKeyX,
        uint256 viewingPubKeyY
    ) external returns (address stealthAddress, uint8 viewTag);

    /**
     * @notice Check view tag for efficient scanning
     * @param viewingPubKeyX Viewing key X
     * @param viewingPubKeyY Viewing key Y
     * @param ephemeralPubKeyX Ephemeral key X
     * @param ephemeralPubKeyY Ephemeral key Y
     * @return viewTag Computed view tag
     */
    function computeViewTag(
        uint256 viewingPubKeyX,
        uint256 viewingPubKeyY,
        uint256 ephemeralPubKeyX,
        uint256 ephemeralPubKeyY
    ) external pure returns (uint8 viewTag);
}

/*//////////////////////////////////////////////////////////////
                      BATCH HELPER STRUCT
//////////////////////////////////////////////////////////////*/

/**
 * @notice Efficient batch operation result
 * @dev Packed for minimal storage/return overhead
 */
struct BatchResult {
    uint256 successBitmap; // Bit i = 1 if operation i succeeded
    uint256 processed; // Number of items processed
    bytes32 resultHash; // Hash of results for verification
}
