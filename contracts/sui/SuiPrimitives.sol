// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SuiPrimitives
 * @notice Core cryptographic primitives for Sui blockchain integration
 * @dev Sui is a Layer 1 blockchain built by Mysten Labs featuring:
 *      - Object-centric data model (owned vs shared objects)
 *      - Parallel transaction execution via DAG-based mempool (Narwhal)
 *      - BFT consensus (Bullshark/Mysticeti)
 *      - BLS12-381 signatures for validator committee
 *      - Ed25519/Secp256k1/Secp256r1 for user signatures
 *      - Move smart contract language
 *      - zkLogin for social authentication
 */
library SuiPrimitives {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice BLS12-381 curve order (scalar field)
    uint256 internal constant BLS12_381_ORDER =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    /// @notice BLS12-381 modulus high bits (for reference, actual modulus is 381 bits)
    /// @dev The full modulus doesn't fit in uint256, so we store identifying info
    uint256 internal constant BLS12_381_MODULUS_IDENTIFIER = 0x1a0111ea397fe69a;

    /// @notice Ed25519 curve order
    uint256 internal constant ED25519_ORDER =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;

    /// @notice Sui mainnet chain ID
    uint256 internal constant SUI_MAINNET = 1;

    /// @notice Sui testnet chain ID
    uint256 internal constant SUI_TESTNET = 2;

    /// @notice Sui devnet chain ID
    uint256 internal constant SUI_DEVNET = 3;

    /// @notice Maximum validators in committee
    uint256 internal constant MAX_VALIDATORS = 150;

    /// @notice Quorum threshold (2/3 + 1 of stake)
    uint256 internal constant QUORUM_THRESHOLD_BPS = 6667; // 66.67%

    /// @notice Object ID length (32 bytes)
    uint256 internal constant OBJECT_ID_LENGTH = 32;

    /// @notice Transaction digest length (32 bytes)
    uint256 internal constant TX_DIGEST_LENGTH = 32;

    /// @notice Epoch duration (approximately 24 hours)
    uint256 internal constant EPOCH_DURATION = 24 hours;

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Sui object ownership types
    enum ObjectOwnership {
        ADDRESS_OWNED, // Owned by a single address
        OBJECT_OWNED, // Owned by another object
        SHARED, // Shared object (requires consensus)
        IMMUTABLE // Immutable/frozen object
    }

    /// @notice Sui transaction kind
    enum TransactionKind {
        PROGRAMMABLE_TRANSACTION,
        CHANGE_EPOCH,
        GENESIS,
        CONSENSUS_COMMIT_PROLOGUE
    }

    /// @notice Sui signature scheme
    enum SignatureScheme {
        ED25519,
        SECP256K1,
        SECP256R1,
        MULTISIG,
        BLS12381,
        ZK_LOGIN
    }

    /// @notice Object status
    enum ObjectStatus {
        EXISTS,
        DELETED,
        WRAPPED,
        NOT_EXISTS
    }

    // =========================================================================
    // STRUCTS - OBJECTS
    // =========================================================================

    /// @notice Sui object reference
    struct ObjectRef {
        bytes32 objectId; // 32-byte object ID
        uint64 version; // Object version (sequence number)
        bytes32 digest; // Object digest
    }

    /// @notice Sui object data
    struct SuiObject {
        bytes32 objectId;
        uint64 version;
        bytes32 digest;
        bytes32 typeTag; // Move type hash
        ObjectOwnership ownership;
        address owner; // Owner address (if address-owned)
        bytes32 parentObject; // Parent object ID (if object-owned)
        bytes data; // BCS-encoded object data
    }

    /// @notice Shared object input for transaction
    struct SharedObjectInput {
        bytes32 objectId;
        uint64 initialSharedVersion;
        bool isMutable; // Whether object is mutably accessed
    }

    // =========================================================================
    // STRUCTS - TRANSACTIONS
    // =========================================================================

    /// @notice Sui transaction data
    struct TransactionData {
        bytes32 digest; // Transaction digest
        TransactionKind kind;
        address sender;
        uint64 gasPrice;
        uint64 gasBudget;
        ObjectRef gasPayment; // Gas coin object
        uint64 expiration; // Epoch expiration
    }

    /// @notice Transaction effects (results)
    struct TransactionEffects {
        bytes32 transactionDigest;
        bytes32 effectsDigest;
        uint64 executedEpoch;
        uint64 gasUsed;
        ObjectRef[] created; // Created objects
        ObjectRef[] mutated; // Mutated objects
        ObjectRef[] deleted; // Deleted objects
        ObjectRef[] wrapped; // Wrapped objects
        ObjectRef[] unwrapped; // Unwrapped objects
        bytes32[] dependencies; // Transaction dependencies
        bool success;
    }

    /// @notice Certified transaction with signatures
    struct CertifiedTransaction {
        TransactionData data;
        bytes32[] validatorSignatures; // Aggregated BLS signatures
        uint256 totalStake; // Total stake that signed
        uint64 epoch;
    }

    // =========================================================================
    // STRUCTS - VALIDATORS
    // =========================================================================

    /// @notice Sui validator info
    struct ValidatorInfo {
        bytes32 suiAddress; // Sui address (32 bytes)
        bytes blsPublicKey; // BLS12-381 public key (96 bytes)
        bytes networkPublicKey; // Network key for p2p
        uint256 stake; // Staked SUI amount
        uint256 commission; // Commission rate (basis points)
        uint64 activeSince; // Epoch when became active
        bool isActive;
    }

    /// @notice Validator committee for an epoch
    struct ValidatorCommittee {
        uint64 epoch;
        bytes32[] validators; // Validator addresses
        uint256[] stakes; // Corresponding stakes
        uint256 totalStake;
        bytes32 committeeHash; // Hash of committee
    }

    // =========================================================================
    // STRUCTS - CHECKPOINTS
    // =========================================================================

    /// @notice Sui checkpoint summary
    struct CheckpointSummary {
        uint64 epoch;
        uint64 sequenceNumber;
        bytes32 contentDigest;
        bytes32 previousDigest;
        uint64 timestampMs;
        bytes32[] transactions; // Transaction digests in checkpoint
        uint256 totalGasUsed;
        bytes32 committeeSig; // Aggregated BLS signature
    }

    /// @notice End of epoch data
    struct EndOfEpochData {
        uint64 epoch;
        bytes32[] nextEpochCommittee;
        uint256[] nextEpochStakes;
        uint64 epochStartTimestampMs;
        bytes32 protocolVersion;
    }

    // =========================================================================
    // STRUCTS - CROSS-CHAIN
    // =========================================================================

    /// @notice Cross-chain message from Sui
    struct SuiMessage {
        bytes32 messageId;
        uint64 sourceChain; // Sui chain ID
        uint64 targetChain; // Target EVM chain ID
        bytes32 sender; // Sui sender address
        address recipient; // EVM recipient
        bytes payload;
        uint64 nonce;
        uint64 timestamp;
    }

    /// @notice Bridge transfer from Sui
    struct SuiBridgeTransfer {
        bytes32 transferId;
        bytes32 sourceObject; // Source coin/token object ID
        bytes32 coinType; // Move coin type hash
        uint256 amount;
        bytes32 sender; // Sui sender
        address recipient; // EVM recipient
        uint64 sourceEpoch;
        bytes32 txDigest; // Originating transaction
    }

    /// @notice Nullifier for Sui objects
    struct SuiNullifier {
        bytes32 objectId;
        uint64 version;
        bytes32 actionDigest; // Deletion/wrap transaction
        bytes32 pilBinding;
    }

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    /// @notice Compute Blake2b-256 hash (Sui's native hash)
    /// @dev Using keccak256 as approximation for EVM compatibility
    function blake2b256(bytes memory data) internal pure returns (bytes32) {
        // In production, use precompile or library for actual Blake2b
        return keccak256(data);
    }

    /// @notice Hash two values
    function hash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return blake2b256(abi.encodePacked(left, right));
    }

    /// @notice Hash multiple values
    function hashN(bytes32[] memory inputs) internal pure returns (bytes32) {
        if (inputs.length == 0) return bytes32(0);
        if (inputs.length == 1) return inputs[0];

        bytes32 result = inputs[0];
        for (uint256 i = 1; i < inputs.length; i++) {
            result = hash2(result, inputs[i]);
        }
        return result;
    }

    /// @notice Compute object digest
    function computeObjectDigest(
        bytes32 objectId,
        uint64 version,
        bytes32 typeTag,
        bytes memory data
    ) internal pure returns (bytes32) {
        return blake2b256(abi.encodePacked(objectId, version, typeTag, data));
    }

    /// @notice Compute transaction digest
    function computeTransactionDigest(
        TransactionData memory txData
    ) internal pure returns (bytes32) {
        return
            blake2b256(
                abi.encodePacked(
                    uint8(txData.kind),
                    txData.sender,
                    txData.gasPrice,
                    txData.gasBudget,
                    txData.gasPayment.objectId,
                    txData.gasPayment.version,
                    txData.expiration
                )
            );
    }

    /// @notice Compute effects digest
    function computeEffectsDigest(
        TransactionEffects memory effects
    ) internal pure returns (bytes32) {
        bytes32[] memory createdDigests = new bytes32[](effects.created.length);
        for (uint256 i = 0; i < effects.created.length; i++) {
            createdDigests[i] = effects.created[i].digest;
        }

        bytes32[] memory mutatedDigests = new bytes32[](effects.mutated.length);
        for (uint256 i = 0; i < effects.mutated.length; i++) {
            mutatedDigests[i] = effects.mutated[i].digest;
        }

        return
            blake2b256(
                abi.encodePacked(
                    effects.transactionDigest,
                    effects.executedEpoch,
                    effects.gasUsed,
                    hashN(createdDigests),
                    hashN(mutatedDigests),
                    effects.success
                )
            );
    }

    // =========================================================================
    // OBJECT FUNCTIONS
    // =========================================================================

    /// @notice Derive object ID from transaction digest and creation index
    function deriveObjectId(
        bytes32 txDigest,
        uint64 creationIndex
    ) internal pure returns (bytes32) {
        return blake2b256(abi.encodePacked(txDigest, creationIndex));
    }

    /// @notice Check if object is shared
    function isSharedObject(SuiObject memory obj) internal pure returns (bool) {
        return obj.ownership == ObjectOwnership.SHARED;
    }

    /// @notice Check if object is immutable
    function isImmutableObject(
        SuiObject memory obj
    ) internal pure returns (bool) {
        return obj.ownership == ObjectOwnership.IMMUTABLE;
    }

    /// @notice Verify object reference
    function verifyObjectRef(
        ObjectRef memory ref,
        bytes32 expectedDigest
    ) internal pure returns (bool) {
        return ref.digest == expectedDigest;
    }

    // =========================================================================
    // NULLIFIER FUNCTIONS
    // =========================================================================

    /// @notice Derive nullifier from deleted/wrapped object
    function deriveNullifier(
        bytes32 objectId,
        uint64 version,
        bytes32 actionDigest
    ) internal pure returns (bytes32) {
        return
            blake2b256(
                abi.encodePacked(objectId, version, actionDigest, "SUI_NF")
            );
    }

    /// @notice Derive cross-domain nullifier for PIL binding
    function deriveCrossDomainNullifier(
        bytes32 suiNullifier,
        uint256 sourceChainId,
        uint256 targetChainId
    ) internal pure returns (bytes32) {
        return
            blake2b256(
                abi.encodePacked(
                    suiNullifier,
                    sourceChainId,
                    targetChainId,
                    "S2P"
                )
            );
    }

    /// @notice Derive PIL binding from Sui nullifier
    function derivePILBinding(
        bytes32 suiNullifier
    ) internal pure returns (bytes32) {
        return blake2b256(abi.encodePacked(suiNullifier, "SUI_TO_PIL"));
    }

    // =========================================================================
    // COMMITTEE FUNCTIONS
    // =========================================================================

    /// @notice Compute committee hash
    function computeCommitteeHash(
        ValidatorCommittee memory committee
    ) internal pure returns (bytes32) {
        return
            blake2b256(
                abi.encodePacked(
                    committee.epoch,
                    hashN(committee.validators),
                    committee.totalStake
                )
            );
    }

    /// @notice Check if stake meets quorum
    function hasQuorum(
        uint256 signingStake,
        uint256 totalStake
    ) internal pure returns (bool) {
        // Quorum is 2/3 + 1 of total stake
        return signingStake * 10000 >= totalStake * QUORUM_THRESHOLD_BPS;
    }

    /// @notice Verify certificate has sufficient stake
    function verifyCertificateStake(
        CertifiedTransaction memory cert,
        uint256 totalCommitteeStake
    ) internal pure returns (bool) {
        return hasQuorum(cert.totalStake, totalCommitteeStake);
    }

    // =========================================================================
    // CHECKPOINT FUNCTIONS
    // =========================================================================

    /// @notice Compute checkpoint digest
    function computeCheckpointDigest(
        CheckpointSummary memory checkpoint
    ) internal pure returns (bytes32) {
        return
            blake2b256(
                abi.encodePacked(
                    checkpoint.epoch,
                    checkpoint.sequenceNumber,
                    checkpoint.contentDigest,
                    checkpoint.previousDigest,
                    checkpoint.timestampMs
                )
            );
    }

    /// @notice Verify checkpoint chain
    function verifyCheckpointChain(
        CheckpointSummary memory current,
        CheckpointSummary memory previous
    ) internal pure returns (bool) {
        bytes32 previousDigest = computeCheckpointDigest(previous);
        return
            current.previousDigest == previousDigest &&
            current.sequenceNumber == previous.sequenceNumber + 1;
    }

    // =========================================================================
    // MESSAGE FUNCTIONS
    // =========================================================================

    /// @notice Compute message ID
    function computeMessageId(
        SuiMessage memory message
    ) internal pure returns (bytes32) {
        return
            blake2b256(
                abi.encodePacked(
                    message.sourceChain,
                    message.targetChain,
                    message.sender,
                    message.recipient,
                    message.nonce,
                    message.payload
                )
            );
    }

    /// @notice Compute transfer ID
    function computeTransferId(
        SuiBridgeTransfer memory transfer
    ) internal pure returns (bytes32) {
        return
            blake2b256(
                abi.encodePacked(
                    transfer.sourceObject,
                    transfer.coinType,
                    transfer.amount,
                    transfer.sender,
                    transfer.recipient,
                    transfer.sourceEpoch,
                    transfer.txDigest
                )
            );
    }

    // =========================================================================
    // VALIDATION FUNCTIONS
    // =========================================================================

    /// @notice Check if chain ID is valid Sui network
    function isSuiChain(uint256 chainId) internal pure returns (bool) {
        return
            chainId == SUI_MAINNET ||
            chainId == SUI_TESTNET ||
            chainId == SUI_DEVNET;
    }

    /// @notice Validate object ID
    function isValidObjectId(bytes32 objectId) internal pure returns (bool) {
        return objectId != bytes32(0);
    }

    /// @notice Validate transaction digest
    function isValidTxDigest(bytes32 digest) internal pure returns (bool) {
        return digest != bytes32(0);
    }

    /// @notice Validate epoch
    function isValidEpoch(
        uint64 epoch,
        uint64 currentEpoch
    ) internal pure returns (bool) {
        // Allow current epoch and one prior for finality lag
        return epoch <= currentEpoch && epoch >= currentEpoch - 1;
    }

    /// @notice Validate validator info
    function isValidValidator(
        ValidatorInfo memory validator
    ) internal pure returns (bool) {
        return
            validator.suiAddress != bytes32(0) &&
            validator.blsPublicKey.length == 96 &&
            validator.stake > 0 &&
            validator.isActive;
    }

    /// @notice Validate certificate
    function isValidCertificate(
        CertifiedTransaction memory cert
    ) internal pure returns (bool) {
        return
            cert.data.digest != bytes32(0) &&
            cert.validatorSignatures.length > 0 &&
            cert.totalStake > 0;
    }

    // =========================================================================
    // BLS SIGNATURE (STUB)
    // =========================================================================

    /// @notice Verify BLS signature (stub - requires precompile)
    /// @dev In production, use EIP-2537 BLS precompiles
    function verifyBLSSignature(
        bytes memory /* signature */,
        bytes memory /* publicKey */,
        bytes32 /* message */
    ) internal pure returns (bool) {
        // Placeholder - actual verification requires BLS precompile
        return true;
    }

    /// @notice Verify aggregated BLS signature
    function verifyAggregatedBLS(
        bytes memory /* aggregatedSig */,
        bytes[] memory /* publicKeys */,
        bytes32 /* message */
    ) internal pure returns (bool) {
        // Placeholder - actual verification requires BLS precompile
        return true;
    }

    // =========================================================================
    // MERKLE FUNCTIONS
    // =========================================================================

    /// @notice Compute Merkle root
    function computeMerkleRoot(
        bytes32[] memory leaves
    ) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        uint256 n = leaves.length;
        bytes32[] memory nodes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            nodes[i] = leaves[i];
        }

        while (n > 1) {
            uint256 newN = (n + 1) / 2;
            for (uint256 i = 0; i < newN; i++) {
                uint256 left = i * 2;
                uint256 right = left + 1;
                if (right < n) {
                    nodes[i] = hash2(nodes[left], nodes[right]);
                } else {
                    nodes[i] = nodes[left];
                }
            }
            n = newN;
        }

        return nodes[0];
    }

    /// @notice Verify Merkle proof
    function verifyMerkleProof(
        bytes32 leaf,
        bytes32[] memory proof,
        uint256[] memory indices,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (indices[i] == 0) {
                computed = hash2(computed, proof[i]);
            } else {
                computed = hash2(proof[i], computed);
            }
        }
        return computed == root;
    }
}
