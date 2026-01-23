// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SeiPrimitives
 * @notice Core cryptographic primitives for Sei blockchain integration
 * @dev Sei is a Layer 1 blockchain optimized for trading/DeFi featuring:
 *      - Twin-turbo consensus (optimistic block processing + intelligent block propagation)
 *      - ~400ms finality (fastest Cosmos chain)
 *      - Native order matching engine (built-in orderbook)
 *      - Parallelized EVM (Sei V2) - parallel transaction execution
 *      - Cosmos SDK based with IBC support
 *      - secp256k1 signatures (Cosmos standard)
 *      - Tendermint BFT consensus
 */
library SeiPrimitives {
    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice secp256k1 curve order
    uint256 internal constant SECP256K1_ORDER =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice secp256k1 field prime
    uint256 internal constant SECP256K1_PRIME =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @notice Sei mainnet chain ID
    string internal constant SEI_MAINNET_CHAIN_ID = "pacific-1";

    /// @notice Sei testnet chain ID
    string internal constant SEI_TESTNET_CHAIN_ID = "atlantic-2";

    /// @notice Sei devnet chain ID
    string internal constant SEI_DEVNET_CHAIN_ID = "arctic-1";

    /// @notice Sei mainnet numeric ID (for EVM compatibility)
    uint256 internal constant SEI_MAINNET_NUMERIC = 1329;

    /// @notice Sei testnet numeric ID
    uint256 internal constant SEI_TESTNET_NUMERIC = 1328;

    /// @notice Maximum validators in active set
    uint256 internal constant MAX_VALIDATORS = 100;

    /// @notice Block time (~400ms)
    uint256 internal constant BLOCK_TIME_MS = 400;

    /// @notice Finality threshold (2/3 + 1)
    uint256 internal constant FINALITY_THRESHOLD_BPS = 6667;

    /// @notice IBC timeout default (10 minutes)
    uint256 internal constant IBC_TIMEOUT_DEFAULT = 600;

    /// @notice Epoch duration in blocks
    uint256 internal constant EPOCH_BLOCKS = 21600; // ~2.4 hours at 400ms

    // =========================================================================
    // ENUMS
    // =========================================================================

    /// @notice Sei execution mode
    enum ExecutionMode {
        COSMOS_NATIVE, // Native Cosmos transactions
        EVM_PARALLEL, // Parallelized EVM (Sei V2)
        EVM_SEQUENTIAL // Sequential EVM fallback
    }

    /// @notice IBC packet status
    enum IBCPacketStatus {
        PENDING,
        ACKNOWLEDGED,
        TIMEOUT,
        ERROR
    }

    /// @notice Order type for native DEX
    enum OrderType {
        LIMIT,
        MARKET,
        STOP_LOSS,
        TAKE_PROFIT
    }

    /// @notice Order side
    enum OrderSide {
        BUY,
        SELL
    }

    /// @notice Transaction priority
    enum TxPriority {
        LOW,
        MEDIUM,
        HIGH,
        URGENT
    }

    // =========================================================================
    // STRUCTS - CONSENSUS
    // =========================================================================

    /// @notice Tendermint block header
    struct BlockHeader {
        int64 height;
        uint64 timestamp;
        bytes32 lastBlockId;
        bytes32 lastCommitHash;
        bytes32 dataHash;
        bytes32 validatorsHash;
        bytes32 nextValidatorsHash;
        bytes32 consensusHash;
        bytes32 appHash;
        bytes32 lastResultsHash;
        bytes32 evidenceHash;
        bytes32 proposerAddress;
    }

    /// @notice Validator info
    struct ValidatorInfo {
        bytes32 operatorAddress; // Bech32 encoded operator address hash
        bytes pubKey; // secp256k1 public key (33 bytes compressed)
        uint256 votingPower; // Voting power (staked SEI)
        uint256 commission; // Commission rate (basis points)
        bool jailed;
        bool active;
    }

    /// @notice Commit signature
    struct CommitSig {
        bytes32 validatorAddress;
        uint64 timestamp;
        bytes signature; // 64 bytes secp256k1 signature
        bool forBlock; // true = vote for block, false = nil vote
    }

    /// @notice Block commit (aggregated signatures)
    struct Commit {
        int64 height;
        int32 round;
        bytes32 blockId;
        CommitSig[] signatures;
        uint256 totalVotingPower;
    }

    // =========================================================================
    // STRUCTS - IBC
    // =========================================================================

    /// @notice IBC channel
    struct IBCChannel {
        string channelId;
        string portId;
        string counterpartyChannelId;
        string counterpartyPortId;
        string connectionId;
        uint8 state; // 0=UNINITIALIZED, 1=INIT, 2=TRYOPEN, 3=OPEN, 4=CLOSED
        uint8 ordering; // 0=NONE, 1=UNORDERED, 2=ORDERED
    }

    /// @notice IBC packet
    struct IBCPacket {
        uint64 sequence;
        string sourcePort;
        string sourceChannel;
        string destPort;
        string destChannel;
        bytes data;
        uint64 timeoutHeight;
        uint64 timeoutTimestamp;
    }

    /// @notice IBC transfer
    struct IBCTransfer {
        bytes32 transferId;
        string denom;
        uint256 amount;
        bytes32 sender; // Sei address hash
        address receiver; // EVM address
        string sourceChannel;
        uint64 timeoutTimestamp;
        IBCPacketStatus status;
    }

    // =========================================================================
    // STRUCTS - DEX
    // =========================================================================

    /// @notice Native DEX order
    struct DexOrder {
        bytes32 orderId;
        bytes32 creator;
        string contractAddr; // Market contract
        OrderType orderType;
        OrderSide side;
        uint256 price; // Price in quote asset
        uint256 quantity; // Quantity in base asset
        uint256 filledQuantity;
        uint64 createdAt;
        bool isCancelled;
    }

    /// @notice Market pair
    struct MarketPair {
        bytes32 pairId;
        string baseAsset;
        string quoteAsset;
        uint256 tickSize;
        uint256 minQuantity;
        bool active;
    }

    // =========================================================================
    // STRUCTS - CROSS-CHAIN
    // =========================================================================

    /// @notice Cross-chain message from Sei
    struct SeiMessage {
        bytes32 messageId;
        uint256 sourceChainId; // Sei numeric chain ID
        uint256 targetChainId; // Target EVM chain ID
        bytes32 sender; // Sei sender address hash
        address recipient; // EVM recipient
        bytes payload;
        uint64 nonce;
        uint64 timestamp;
        ExecutionMode execMode;
    }

    /// @notice Bridge transfer from Sei
    struct SeiBridgeTransfer {
        bytes32 transferId;
        string denom; // Token denomination
        uint256 amount;
        bytes32 sender; // Sei sender
        address recipient; // EVM recipient
        int64 sourceHeight; // Block height on Sei
        bytes32 txHash; // Sei transaction hash
    }

    /// @notice Nullifier for Sei transactions
    struct SeiNullifier {
        bytes32 txHash;
        int64 height;
        uint64 index; // Transaction index in block
        bytes32 pilBinding;
    }

    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================

    /// @notice Compute SHA256 hash (Cosmos standard)
    function sha256Hash(bytes memory data) internal pure returns (bytes32) {
        return sha256(data);
    }

    /// @notice Hash two values using SHA256
    function hash2(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(left, right));
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

    /// @notice Compute block hash from header
    function computeBlockHash(
        BlockHeader memory header
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    header.height,
                    header.timestamp,
                    header.lastBlockId,
                    header.dataHash,
                    header.validatorsHash,
                    header.appHash
                )
            );
    }

    /// @notice Compute commit hash
    function computeCommitHash(
        Commit memory commit
    ) internal pure returns (bytes32) {
        bytes32[] memory sigHashes = new bytes32[](commit.signatures.length);
        for (uint256 i = 0; i < commit.signatures.length; i++) {
            sigHashes[i] = sha256(
                abi.encodePacked(
                    commit.signatures[i].validatorAddress,
                    commit.signatures[i].timestamp,
                    commit.signatures[i].forBlock
                )
            );
        }
        return
            sha256(
                abi.encodePacked(
                    commit.height,
                    commit.round,
                    commit.blockId,
                    hashN(sigHashes)
                )
            );
    }

    // =========================================================================
    // NULLIFIER FUNCTIONS
    // =========================================================================

    /// @notice Derive nullifier from Sei transaction
    function deriveNullifier(
        bytes32 txHash,
        int64 height,
        uint64 index
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(txHash, height, index, "SEI_NF"));
    }

    /// @notice Derive cross-domain nullifier for PIL binding
    function deriveCrossDomainNullifier(
        bytes32 seiNullifier,
        uint256 sourceChainId,
        uint256 targetChainId
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    seiNullifier,
                    sourceChainId,
                    targetChainId,
                    "SEI2PIL"
                )
            );
    }

    /// @notice Derive PIL binding from Sei nullifier
    function derivePILBinding(
        bytes32 seiNullifier
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(seiNullifier, "SEI_TO_PIL"));
    }

    // =========================================================================
    // VALIDATOR FUNCTIONS
    // =========================================================================

    /// @notice Compute validator set hash
    function computeValidatorSetHash(
        ValidatorInfo[] memory validators
    ) internal pure returns (bytes32) {
        bytes32[] memory validatorHashes = new bytes32[](validators.length);
        for (uint256 i = 0; i < validators.length; i++) {
            validatorHashes[i] = sha256(
                abi.encodePacked(
                    validators[i].operatorAddress,
                    validators[i].pubKey,
                    validators[i].votingPower
                )
            );
        }
        return hashN(validatorHashes);
    }

    /// @notice Check if voting power meets finality threshold
    function hasFinality(
        uint256 signingPower,
        uint256 totalPower
    ) internal pure returns (bool) {
        if (totalPower == 0) return false;
        return signingPower * 10000 >= totalPower * FINALITY_THRESHOLD_BPS;
    }

    /// @notice Calculate total voting power
    function calculateTotalPower(
        ValidatorInfo[] memory validators
    ) internal pure returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i].active && !validators[i].jailed) {
                total += validators[i].votingPower;
            }
        }
        return total;
    }

    // =========================================================================
    // IBC FUNCTIONS
    // =========================================================================

    /// @notice Compute IBC packet commitment
    function computePacketCommitment(
        IBCPacket memory packet
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    packet.sequence,
                    packet.sourcePort,
                    packet.sourceChannel,
                    packet.destPort,
                    packet.destChannel,
                    sha256(packet.data),
                    packet.timeoutHeight,
                    packet.timeoutTimestamp
                )
            );
    }

    /// @notice Compute IBC channel hash
    function computeChannelHash(
        IBCChannel memory channel
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    channel.channelId,
                    channel.portId,
                    channel.counterpartyChannelId,
                    channel.counterpartyPortId,
                    channel.connectionId,
                    channel.state
                )
            );
    }

    /// @notice Compute transfer ID
    function computeTransferId(
        SeiBridgeTransfer memory transfer
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    transfer.denom,
                    transfer.amount,
                    transfer.sender,
                    transfer.recipient,
                    transfer.sourceHeight,
                    transfer.txHash
                )
            );
    }

    // =========================================================================
    // MESSAGE FUNCTIONS
    // =========================================================================

    /// @notice Compute message ID
    function computeMessageId(
        SeiMessage memory message
    ) internal pure returns (bytes32) {
        return
            sha256(
                abi.encodePacked(
                    message.sourceChainId,
                    message.targetChainId,
                    message.sender,
                    message.recipient,
                    message.nonce,
                    message.payload
                )
            );
    }

    // =========================================================================
    // VALIDATION FUNCTIONS
    // =========================================================================

    /// @notice Check if chain ID is valid Sei network
    function isSeiChain(uint256 chainId) internal pure returns (bool) {
        return chainId == SEI_MAINNET_NUMERIC || chainId == SEI_TESTNET_NUMERIC;
    }

    /// @notice Validate block height
    function isValidHeight(int64 height) internal pure returns (bool) {
        return height > 0;
    }

    /// @notice Validate IBC channel state
    function isChannelOpen(
        IBCChannel memory channel
    ) internal pure returns (bool) {
        return channel.state == 3; // OPEN state
    }

    /// @notice Validate validator info
    function isValidValidator(
        ValidatorInfo memory validator
    ) internal pure returns (bool) {
        return
            validator.operatorAddress != bytes32(0) &&
            validator.pubKey.length == 33 &&
            validator.votingPower > 0 &&
            validator.active &&
            !validator.jailed;
    }

    /// @notice Validate commit has enough signatures
    function isValidCommit(
        Commit memory commit,
        uint256 totalPower
    ) internal pure returns (bool) {
        return
            commit.signatures.length > 0 &&
            hasFinality(commit.totalVotingPower, totalPower);
    }

    // =========================================================================
    // SIGNATURE VERIFICATION (STUB)
    // =========================================================================

    /// @notice Verify secp256k1 signature
    /// @dev Uses ecrecover for EVM compatibility
    function verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;

        address recovered = ecrecover(messageHash, v, r, s);
        return recovered != address(0) && recovered == expectedSigner;
    }

    /// @notice Recover signer from signature
    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) v += 27;

        return ecrecover(messageHash, v, r, s);
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

    // =========================================================================
    // DEX FUNCTIONS
    // =========================================================================

    /// @notice Compute order ID
    function computeOrderId(
        bytes32 creator,
        string memory contractAddr,
        uint64 nonce
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(creator, contractAddr, nonce));
    }

    /// @notice Compute market pair ID
    function computePairId(
        string memory baseAsset,
        string memory quoteAsset
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(baseAsset, "/", quoteAsset));
    }
}
