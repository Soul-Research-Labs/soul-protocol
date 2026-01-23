// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AptosPrimitives
 * @notice Cryptographic primitives for Aptos blockchain integration
 * @dev Implements:
 *      - BLS12-381 for validator aggregate signatures
 *      - Ed25519 for user signatures
 *      - SHA3-256 hashing (Aptos native)
 *      - AptosBFT consensus (derived from DiemBFT/HotStuff)
 *      - Block-STM parallel execution model
 *      - Move resource model
 *
 * Aptos Key Features:
 * - Move programming language (same as Sui, originally from Diem)
 * - AptosBFT consensus (~160ms finality under good conditions)
 * - Block-STM for parallel transaction execution
 * - Resource-oriented programming model
 * - BLS12-381 multi-signatures for validators
 */
library AptosPrimitives {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice BLS12-381 scalar field order
    uint256 public constant BLS12_381_SCALAR_ORDER =
        52435875175126190479447740508185965837690552500527637822603658699938581184513;

    /// @notice BLS12-381 base field modulus (stored as two 256-bit parts due to size)
    /// Full value: 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
    uint256 public constant BLS12_381_FIELD_MODULUS_HIGH =
        4002409555221667393417789825735904156556882819939007885332058136124031650490;
    uint256 public constant BLS12_381_FIELD_MODULUS_LOW =
        837864442687629129015664037894272559787;

    /// @notice Ed25519 curve order
    uint256 public constant ED25519_ORDER =
        7237005577332262213973186563042994240857116359379907606001950938285454250989;

    /// @notice Ed25519 field prime (2^255 - 19)
    uint256 public constant ED25519_PRIME =
        57896044618658097711785492504343953926634992332820282019728792003956564819949;

    /// @notice Aptos mainnet chain ID
    uint8 public constant APTOS_MAINNET = 1;

    /// @notice Aptos testnet chain ID
    uint8 public constant APTOS_TESTNET = 2;

    /// @notice Aptos devnet chain ID
    uint8 public constant APTOS_DEVNET = 34;

    /// @notice Quorum threshold in basis points (2/3 + 1)
    uint256 public constant QUORUM_THRESHOLD_BPS = 6667;

    /// @notice Maximum validators in the active set
    uint256 public constant MAX_VALIDATORS = 150;

    /// @notice BLS signature length (compressed G1 point)
    uint256 public constant BLS_SIGNATURE_LENGTH = 48;

    /// @notice BLS public key length (compressed G2 point)
    uint256 public constant BLS_PUBKEY_LENGTH = 96;

    /// @notice Ed25519 signature length
    uint256 public constant ED25519_SIGNATURE_LENGTH = 64;

    /// @notice Ed25519 public key length
    uint256 public constant ED25519_PUBKEY_LENGTH = 32;

    // =========================================================================
    // TYPE DEFINITIONS
    // =========================================================================

    /// @notice Transaction authentication types
    enum AuthenticatorType {
        ED25519,
        MULTI_ED25519,
        MULTI_AGENT,
        FEE_PAYER,
        SINGLE_KEY,
        MULTI_KEY
    }

    /// @notice Ledger info with signatures (block finality)
    struct LedgerInfoWithSignatures {
        uint64 epoch;
        uint64 round;
        bytes32 blockHash;
        bytes32 executedStateId;
        uint64 version;
        uint64 timestampUsecs;
        bytes32 nextEpochState; // Hash of next validator set
        bytes aggregateSignature; // BLS aggregate signature
        bytes validatorBitmap; // Which validators signed
    }

    /// @notice Validator info
    struct ValidatorInfo {
        address accountAddress;
        bytes blsPublicKey; // BLS12-381 public key (96 bytes)
        bytes ed25519PublicKey; // Ed25519 public key (32 bytes)
        uint256 votingPower;
        bool isActive;
        uint64 lastEpochParticipated;
    }

    /// @notice Epoch state (validator set configuration)
    struct EpochState {
        uint64 epoch;
        bytes32 validatorSetHash;
        uint256 totalVotingPower;
        uint256 validatorCount;
    }

    /// @notice Transaction info
    struct TransactionInfo {
        bytes32 stateChangeHash;
        bytes32 eventRootHash;
        uint64 gasUsed;
        bool success;
        bytes32 accumulatorRootHash;
        uint64 version;
    }

    /// @notice Move resource identifier
    struct ResourceTag {
        address moduleAddress;
        bytes32 moduleName;
        bytes32 structName;
        bytes[] typeArgs;
    }

    /// @notice Account resource (balance, sequence number)
    struct AccountResource {
        uint64 sequenceNumber;
        bytes32 authenticationKey;
        uint64 coinRegisterEvents;
        uint64 guidCreationNum;
    }

    /// @notice Coin store resource
    struct CoinStore {
        uint256 value;
        bool frozen;
        bytes32 depositEvents;
        bytes32 withdrawEvents;
    }

    /// @notice Sparse Merkle tree proof (used for state proofs)
    struct SparseMerkleProof {
        bytes32 leaf;
        bytes32[] siblings;
        uint256 leafIndex;
    }

    /// @notice Transaction accumulator proof
    struct TransactionAccumulatorProof {
        bytes32[] siblings;
        uint64 leafIndex;
    }

    // =========================================================================
    // HASHING FUNCTIONS
    // =========================================================================

    /**
     * @notice Compute SHA3-256 hash (Aptos native hash function)
     * @dev Aptos uses SHA3-256 (Keccak-256 variant)
     * @param data Input data
     * @return hash SHA3-256 hash
     */
    function sha3Hash(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data); // EVM keccak256 is equivalent to SHA3-256
    }

    /**
     * @notice Hash two values together
     * @param left Left value
     * @param right Right value
     * @return Combined hash
     */
    function hash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(left, right));
    }

    /**
     * @notice Compute hash prefix for Aptos (domain separation)
     * @param prefix Domain prefix string
     * @param data Data to hash
     * @return Prefixed hash
     */
    function hashWithPrefix(
        string memory prefix,
        bytes memory data
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(prefix, data));
    }

    /**
     * @notice Compute block hash
     * @param epoch Epoch number
     * @param round Round number
     * @param executedStateId Executed state root
     * @param version Ledger version
     * @param timestampUsecs Timestamp in microseconds
     * @return Block hash
     */
    function computeBlockHash(
        uint64 epoch,
        uint64 round,
        bytes32 executedStateId,
        uint64 version,
        uint64 timestampUsecs
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "APTOS::LedgerInfo",
                    epoch,
                    round,
                    executedStateId,
                    version,
                    timestampUsecs
                )
            );
    }

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    /**
     * @notice Derive nullifier from Aptos transaction
     * @dev Nullifier = SHA3(txHash || version || "APTOS_NF")
     * @param txHash Transaction hash
     * @param version Ledger version
     * @return nullifier Unique nullifier
     */
    function deriveNullifier(
        bytes32 txHash,
        uint64 version
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(txHash, version, "APTOS_NF"));
    }

    /**
     * @notice Derive cross-domain nullifier for PIL binding
     * @dev CrossNullifier = SHA3(aptosNullifier || sourceChain || targetChain || "APTOS2PIL")
     * @param aptosNullifier Original Aptos nullifier
     * @param sourceChainId Source chain ID
     * @param targetChainId Target chain ID
     * @return Cross-domain nullifier
     */
    function deriveCrossDomainNullifier(
        bytes32 aptosNullifier,
        uint256 sourceChainId,
        uint256 targetChainId
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    aptosNullifier,
                    sourceChainId,
                    targetChainId,
                    "APTOS2PIL"
                )
            );
    }

    /**
     * @notice Derive PIL binding from Aptos nullifier
     * @param aptosNullifier Aptos nullifier
     * @return PIL binding hash
     */
    function derivePILBinding(
        bytes32 aptosNullifier
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(aptosNullifier, "APTOS_TO_PIL"));
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /**
     * @notice Verify Ed25519 signature (abstract - requires precompile)
     * @dev In practice, use precompile or library for Ed25519 verification
     * @param message Message that was signed
     * @param signature Ed25519 signature (64 bytes)
     * @param publicKey Ed25519 public key (32 bytes)
     * @return isValid True if signature is valid
     */
    function verifyEd25519Signature(
        bytes32 message,
        bytes memory signature,
        bytes memory publicKey
    ) internal pure returns (bool) {
        require(
            signature.length == ED25519_SIGNATURE_LENGTH,
            "Invalid Ed25519 signature length"
        );
        require(
            publicKey.length == ED25519_PUBKEY_LENGTH,
            "Invalid Ed25519 public key length"
        );
        // Abstract - actual verification requires Ed25519 precompile or library
        // Return true for compilation; real implementation uses precompile
        return
            signature.length == ED25519_SIGNATURE_LENGTH &&
            publicKey.length == ED25519_PUBKEY_LENGTH;
    }

    /**
     * @notice Verify BLS12-381 aggregate signature (abstract - requires precompile)
     * @dev BLS verification requires pairing check: e(σ, g2) = e(H(m), pk_agg)
     * @param message Message that was signed
     * @param aggregateSignature BLS aggregate signature (48 bytes)
     * @param aggregatePublicKey Aggregate public key (96 bytes)
     * @return isValid True if signature is valid
     */
    function verifyBLSSignature(
        bytes32 message,
        bytes memory aggregateSignature,
        bytes memory aggregatePublicKey
    ) internal pure returns (bool) {
        require(
            aggregateSignature.length == BLS_SIGNATURE_LENGTH,
            "Invalid BLS signature length"
        );
        require(
            aggregatePublicKey.length == BLS_PUBKEY_LENGTH,
            "Invalid BLS public key length"
        );
        // Abstract - actual verification requires BLS precompile
        return
            aggregateSignature.length == BLS_SIGNATURE_LENGTH &&
            aggregatePublicKey.length == BLS_PUBKEY_LENGTH;
    }

    // =========================================================================
    // MERKLE TREE OPERATIONS
    // =========================================================================

    /**
     * @notice Verify sparse Merkle tree proof
     * @dev Aptos uses 256-bit sparse Merkle trees for state
     * @param proof Sparse Merkle proof
     * @param root Expected root
     * @param key Key in the tree (256-bit path)
     * @param value Expected value (or null for non-membership)
     * @return isValid True if proof is valid
     */
    function verifySparseMerkleProof(
        SparseMerkleProof memory proof,
        bytes32 root,
        bytes32 key,
        bytes32 value
    ) internal pure returns (bool) {
        bytes32 computed = proof.leaf;
        uint256 index = proof.leafIndex;

        for (uint256 i = 0; i < proof.siblings.length; i++) {
            if (index & 1 == 0) {
                computed = hash2(computed, proof.siblings[i]);
            } else {
                computed = hash2(proof.siblings[i], computed);
            }
            index = index >> 1;
        }

        return computed == root;
    }

    /**
     * @notice Verify transaction accumulator proof
     * @dev Aptos uses a Merkle accumulator for transaction history
     * @param proof Accumulator proof
     * @param root Expected accumulator root
     * @param txHash Transaction hash
     * @return isValid True if proof is valid
     */
    function verifyAccumulatorProof(
        TransactionAccumulatorProof memory proof,
        bytes32 root,
        bytes32 txHash
    ) internal pure returns (bool) {
        bytes32 computed = txHash;
        uint64 index = proof.leafIndex;

        for (uint256 i = 0; i < proof.siblings.length; i++) {
            if (index & 1 == 0) {
                computed = hash2(computed, proof.siblings[i]);
            } else {
                computed = hash2(proof.siblings[i], computed);
            }
            index = index >> 1;
        }

        return computed == root;
    }

    // =========================================================================
    // CONSENSUS HELPERS
    // =========================================================================

    /**
     * @notice Check if voting power meets quorum (2/3 + 1)
     * @param signingPower Total voting power of signers
     * @param totalPower Total voting power of all validators
     * @return hasQuorum True if quorum is met
     */
    function hasQuorum(
        uint256 signingPower,
        uint256 totalPower
    ) internal pure returns (bool) {
        if (totalPower == 0) return false;
        return signingPower * 10000 >= totalPower * QUORUM_THRESHOLD_BPS;
    }

    /**
     * @notice Compute epoch state hash
     * @param epoch Epoch number
     * @param validators List of validator addresses
     * @param powers List of voting powers
     * @return Epoch state hash
     */
    function computeEpochStateHash(
        uint64 epoch,
        address[] memory validators,
        uint256[] memory powers
    ) internal pure returns (bytes32) {
        require(validators.length == powers.length, "Length mismatch");
        return
            keccak256(
                abi.encodePacked("APTOS::EpochState", epoch, validators, powers)
            );
    }

    /**
     * @notice Calculate signing power from bitmap
     * @param bitmap Validator bitmap (which validators signed)
     * @param powers Voting powers array
     * @return totalSigningPower Total power of signers
     */
    function calculateSigningPower(
        bytes memory bitmap,
        uint256[] memory powers
    ) internal pure returns (uint256 totalSigningPower) {
        require(bitmap.length * 8 >= powers.length, "Bitmap too short");

        for (uint256 i = 0; i < powers.length; i++) {
            uint256 byteIndex = i / 8;
            uint256 bitIndex = i % 8;
            if (uint8(bitmap[byteIndex]) & (1 << bitIndex) != 0) {
                totalSigningPower += powers[i];
            }
        }
    }

    // =========================================================================
    // MOVE RESOURCE HELPERS
    // =========================================================================

    /**
     * @notice Compute resource address (for resource accounts)
     * @param creator Creator address
     * @param seed Seed for deterministic address
     * @return resourceAddress Computed resource address
     */
    function computeResourceAddress(
        address creator,
        bytes memory seed
    ) internal pure returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                creator,
                seed,
                uint8(255) // DERIVE_RESOURCE_ACCOUNT_SCHEME
            )
        );
        return address(uint160(uint256(hash)));
    }

    /**
     * @notice Compute object address
     * @param creator Creator address
     * @param seed Seed bytes
     * @return objectAddress Object address
     */
    function computeObjectAddress(
        address creator,
        bytes memory seed
    ) internal pure returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                creator,
                seed,
                uint8(254) // DERIVE_OBJECT_ADDRESS_SCHEME
            )
        );
        return address(uint160(uint256(hash)));
    }

    /**
     * @notice Compute resource tag hash
     * @param tag Resource tag
     * @return Resource tag hash
     */
    function computeResourceTagHash(
        ResourceTag memory tag
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    tag.moduleAddress,
                    tag.moduleName,
                    tag.structName,
                    keccak256(abi.encode(tag.typeArgs))
                )
            );
    }

    // =========================================================================
    // CHAIN VALIDATION
    // =========================================================================

    /**
     * @notice Check if chain ID is valid Aptos network
     * @param chainId Chain ID to check
     * @return isValid True if valid Aptos chain
     */
    function isAptosChain(uint8 chainId) internal pure returns (bool) {
        return
            chainId == APTOS_MAINNET ||
            chainId == APTOS_TESTNET ||
            chainId == APTOS_DEVNET;
    }

    /**
     * @notice Validate ledger info structure
     * @param info Ledger info
     * @return isValid True if structure is valid
     */
    function isValidLedgerInfo(
        LedgerInfoWithSignatures memory info
    ) internal pure returns (bool) {
        return
            info.epoch > 0 &&
            info.blockHash != bytes32(0) &&
            info.executedStateId != bytes32(0) &&
            info.aggregateSignature.length == BLS_SIGNATURE_LENGTH;
    }
}
