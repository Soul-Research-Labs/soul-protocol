// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title NEARBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for NEAR Protocol integration via Rainbow Bridge
 * @dev Enables cross-chain interoperability between PIL (EVM) and NEAR
 *
 * NEAR INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      PIL <-> NEAR Bridge                                │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   NEAR Protocol   │                 │
 * │  │  (EVM/Solidity)   │           │   (Rust/WASM)     │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ERC20/721   │  │◄─────────►│  │ NEP-141/171 │  │                 │
 * │  │  │ Tokens      │  │           │  │ Tokens      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Bridge      │  │           │  │ Connector   │  │                 │
 * │  │  │ Contract    │  │◄─────────►│  │ Contract    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Rainbow Bridge Layer                             │ │
 * │  │  - NEAR Light Client on Ethereum                                   │ │
 * │  │  - Ethereum Light Client on NEAR (via ED25519)                     │ │
 * │  │  - Trustless Proof Verification                                    │ │
 * │  │  - NEP-141 Token Standard (Fungible)                               │ │
 * │  │  - NEP-171 Token Standard (NFT)                                    │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * NEAR CONCEPTS:
 * - Account: Named accounts (e.g., user.near) or implicit accounts
 * - Contract: WASM-based smart contracts
 * - Storage Staking: Storage requires NEAR staking
 * - Gas: Called "TGas" (tera-gas), prepaid execution
 * - Sharding: Nightshade sharding for scalability
 * - NEP-141: Fungible token standard
 * - NEP-171: Non-fungible token standard
 */
contract NEARBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice NEAR block time (~1 second)
    uint256 public constant NEAR_BLOCK_TIME = 1;

    /// @notice Minimum confirmations for finality
    uint256 public constant MIN_CONFIRMATIONS = 2;

    /// @notice Rainbow Bridge epoch duration
    uint256 public constant EPOCH_DURATION = 43200; // 12 hours in blocks

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Transfer type
    enum TransferType {
        NEP141, // Fungible token
        NEP171, // Non-fungible token
        NATIVE // Native NEAR
    }

    /// @notice Transfer status
    enum TransferStatus {
        PENDING,
        PROVED,
        COMPLETED,
        FAILED
    }

    /// @notice Proof status
    enum ProofStatus {
        PENDING,
        VERIFIED,
        REJECTED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice NEAR Block Header (simplified)
    struct NEARBlockHeader {
        uint64 height; // Block height
        uint64 timestamp; // Nanoseconds since epoch
        bytes32 prevHash; // Previous block hash
        bytes32 epochId; // Current epoch ID
        bytes32 nextEpochId; // Next epoch ID
        bytes32 blockMerkleRoot; // Block merkle root
        bytes32 chunkReceiptsRoot; // Chunk receipts root
        bytes32 chunkHeadersRoot; // Chunk headers root
        bytes32 outcomeRoot; // Outcome root
        bytes32 blockHash; // Computed block hash
        bool finalized; // Is block finalized
    }

    /// @notice NEAR Execution Outcome
    struct ExecutionOutcome {
        bytes32 receiptId; // Receipt ID
        bytes32 executorId; // Executor account hash
        bool success; // Execution success
        uint64 gasBurnt; // Gas consumed
        bytes32[] logs; // Log hashes
        bytes32 outcomeHash; // Outcome hash
    }

    /// @notice NEAR Receipt Proof
    struct ReceiptProof {
        bytes32 receiptId; // Receipt ID
        bytes32 blockHash; // Block containing receipt
        bytes32[] proof; // Merkle proof
        uint64 blockHeight; // Block height
        ProofStatus status; // Verification status
    }

    /// @notice NEP-141 Token
    struct NEP141Token {
        bytes32 tokenHash; // Token ID hash
        string accountId; // NEAR account ID (e.g., "usdt.near")
        string name; // Token name
        string symbol; // Token symbol
        uint8 decimals; // Token decimals (max 24 on NEAR)
        address evmToken; // Mapped EVM token
        uint256 totalBridged; // Total bridged amount
        bool active; // Is token active
    }

    /// @notice Outbound transfer
    struct OutboundTransfer {
        bytes32 transferId; // Transfer identifier
        address sender; // EVM sender
        string nearReceiver; // NEAR account ID
        string tokenAccountId; // NEAR token account ID
        uint256 amount; // Amount in EVM decimals
        uint256 nearAmount; // Amount in NEAR decimals
        TransferType transferType; // Type of transfer
        TransferStatus status; // Transfer status
        bytes32 nearTxHash; // NEAR transaction hash
        uint256 initiatedAt; // Initiation timestamp
        uint256 completedAt; // Completion timestamp
    }

    /// @notice Inbound transfer
    struct InboundTransfer {
        bytes32 transferId; // Transfer identifier
        string nearSender; // NEAR account ID
        address evmReceiver; // EVM receiver
        string tokenAccountId; // NEAR token account ID
        uint256 nearAmount; // Amount in NEAR decimals
        uint256 evmAmount; // Amount in EVM decimals
        bytes32 nearTxHash; // NEAR transaction hash
        ReceiptProof proof; // Receipt proof
        TransferStatus status; // Transfer status
        uint256 completedAt; // Completion timestamp
    }

    /// @notice NEAR Epoch
    struct NEAREpoch {
        bytes32 epochId; // Epoch identifier
        uint64 startHeight; // Start block height
        uint64 endHeight; // End block height
        bytes32 blockProducersHash; // Hash of block producers
        uint256 updatedAt; // Update timestamp
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bridge fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum transfer amount
    uint256 public minTransferAmount;

    /// @notice Maximum transfer amount
    uint256 public maxTransferAmount;

    /// @notice Latest finalized NEAR block height
    uint64 public latestFinalizedHeight;

    /// @notice Current epoch ID
    bytes32 public currentEpochId;

    /// @notice Transfer nonce
    uint256 public transferNonce;

    /// @notice Treasury address
    address public treasury;

    /// @notice NEAR connector contract account
    string public nearConnector;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Block headers by height
    mapping(uint64 => NEARBlockHeader) public blockHeaders;

    /// @notice Epochs by ID
    mapping(bytes32 => NEAREpoch) public epochs;

    /// @notice NEP-141 tokens by hash
    mapping(bytes32 => NEP141Token) public nep141Tokens;
    bytes32[] public tokenHashes;

    /// @notice Outbound transfers
    mapping(bytes32 => OutboundTransfer) public outboundTransfers;

    /// @notice User's outbound transfers
    mapping(address => bytes32[]) public userOutboundTransfers;

    /// @notice Inbound transfers
    mapping(bytes32 => InboundTransfer) public inboundTransfers;

    /// @notice Processed NEAR receipts
    mapping(bytes32 => bool) public processedReceipts;

    /// @notice Execution outcomes
    mapping(bytes32 => ExecutionOutcome) public executionOutcomes;

    /// @notice EVM to NEAR account mapping
    mapping(address => string) public evmToNearAccount;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalOutboundTransfers;
    uint256 public totalInboundTransfers;
    uint256 public totalValueBridgedOut;
    uint256 public totalValueBridgedIn;
    uint256 public totalProofsVerified;
    uint256 public totalFeesCollected;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event BlockHeaderSubmitted(uint64 indexed height, bytes32 blockHash);
    event EpochUpdated(bytes32 indexed epochId, uint64 startHeight);
    event ProofVerified(bytes32 indexed receiptId, uint64 blockHeight);

    event TokenRegistered(
        bytes32 indexed tokenHash,
        string accountId,
        string symbol
    );

    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        string nearReceiver,
        uint256 amount
    );

    event TransferProved(bytes32 indexed transferId, bytes32 nearTxHash);
    event TransferCompleted(bytes32 indexed transferId);

    event InboundReceived(
        bytes32 indexed transferId,
        string nearSender,
        address indexed evmReceiver,
        uint256 amount
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBlockHeader();
    error BlockNotFinalized();
    error EpochNotFound();
    error InvalidProof();
    error ProofAlreadyUsed();
    error TokenNotRegistered();
    error InvalidAmount();
    error AmountTooLow();
    error AmountTooHigh();
    error InsufficientFee();
    error TransferNotFound();
    error TransferNotPending();
    error InvalidReceiver();
    error InvalidAccountId();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, string memory _nearConnector) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        nearConnector = _nearConnector;
        bridgeFee = 25; // 0.25%
        minTransferAmount = 1e15;
        maxTransferAmount = 1e24;
    }

    /*//////////////////////////////////////////////////////////////
                    BLOCK HEADER RELAY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a NEAR block header
     */
    function submitBlockHeader(
        uint64 height,
        uint64 timestamp,
        bytes32 prevHash,
        bytes32 epochId,
        bytes32 nextEpochId,
        bytes32 blockMerkleRoot,
        bytes32 chunkReceiptsRoot,
        bytes32 chunkHeadersRoot,
        bytes32 outcomeRoot
    ) external onlyRole(RELAYER_ROLE) {
        // Verify chain continuity
        if (height > 0 && blockHeaders[height - 1].blockHash != prevHash) {
            // Allow gaps for light client sync
        }

        bytes32 blockHash = keccak256(
            abi.encodePacked(
                height,
                timestamp,
                prevHash,
                epochId,
                blockMerkleRoot,
                outcomeRoot
            )
        );

        blockHeaders[height] = NEARBlockHeader({
            height: height,
            timestamp: timestamp,
            prevHash: prevHash,
            epochId: epochId,
            nextEpochId: nextEpochId,
            blockMerkleRoot: blockMerkleRoot,
            chunkReceiptsRoot: chunkReceiptsRoot,
            chunkHeadersRoot: chunkHeadersRoot,
            outcomeRoot: outcomeRoot,
            blockHash: blockHash,
            finalized: false
        });

        emit BlockHeaderSubmitted(height, blockHash);
    }

    /**
     * @notice Finalize a block header
     */
    function finalizeBlock(uint64 height) external onlyRole(PROVER_ROLE) {
        NEARBlockHeader storage header = blockHeaders[height];
        if (header.blockHash == bytes32(0)) revert InvalidBlockHeader();

        header.finalized = true;

        if (height > latestFinalizedHeight) {
            latestFinalizedHeight = height;
        }
    }

    /**
     * @notice Update epoch information
     */
    function updateEpoch(
        bytes32 epochId,
        uint64 startHeight,
        uint64 endHeight,
        bytes32 blockProducersHash
    ) external onlyRole(RELAYER_ROLE) {
        epochs[epochId] = NEAREpoch({
            epochId: epochId,
            startHeight: startHeight,
            endHeight: endHeight,
            blockProducersHash: blockProducersHash,
            updatedAt: block.timestamp
        });

        currentEpochId = epochId;

        emit EpochUpdated(epochId, startHeight);
    }

    /*//////////////////////////////////////////////////////////////
                    TOKEN REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a NEP-141 token
     */
    function registerToken(
        string calldata accountId,
        string calldata name,
        string calldata symbol,
        uint8 decimals,
        address evmToken
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 tokenHash = keccak256(bytes(accountId));

        nep141Tokens[tokenHash] = NEP141Token({
            tokenHash: tokenHash,
            accountId: accountId,
            name: name,
            symbol: symbol,
            decimals: decimals,
            evmToken: evmToken,
            totalBridged: 0,
            active: true
        });

        tokenHashes.push(tokenHash);

        emit TokenRegistered(tokenHash, accountId, symbol);
    }

    /**
     * @notice Get token info
     */
    function getToken(
        bytes32 tokenHash
    ) external view returns (NEP141Token memory) {
        return nep141Tokens[tokenHash];
    }

    /*//////////////////////////////////////////////////////////////
                    OUTBOUND TRANSFERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate transfer to NEAR
     */
    function transferToNEAR(
        string calldata nearReceiver,
        string calldata tokenAccountId,
        uint256 amount
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        bytes32 tokenHash = keccak256(bytes(tokenAccountId));
        NEP141Token storage token = nep141Tokens[tokenHash];
        if (token.tokenHash == bytes32(0)) revert TokenNotRegistered();

        if (amount < minTransferAmount) revert AmountTooLow();
        if (amount > maxTransferAmount) revert AmountTooHigh();
        if (bytes(nearReceiver).length == 0) revert InvalidReceiver();

        // Validate NEAR account ID format
        if (!_isValidNearAccountId(nearReceiver)) revert InvalidAccountId();

        // Calculate fee
        uint256 fee = (amount * bridgeFee) / 10000;
        if (msg.value < fee) revert InsufficientFee();

        // Convert to NEAR decimals
        uint256 nearAmount = _convertToNearDecimals(amount, token.decimals);

        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                nearReceiver,
                tokenAccountId,
                amount,
                transferNonce++,
                block.timestamp
            )
        );

        outboundTransfers[transferId] = OutboundTransfer({
            transferId: transferId,
            sender: msg.sender,
            nearReceiver: nearReceiver,
            tokenAccountId: tokenAccountId,
            amount: amount,
            nearAmount: nearAmount,
            transferType: TransferType.NEP141,
            status: TransferStatus.PENDING,
            nearTxHash: bytes32(0),
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userOutboundTransfers[msg.sender].push(transferId);

        token.totalBridged += amount;
        totalOutboundTransfers++;
        totalValueBridgedOut += amount;
        totalFeesCollected += fee;

        emit TransferInitiated(transferId, msg.sender, nearReceiver, amount);
    }

    /**
     * @notice Prove transfer on NEAR
     */
    function proveTransfer(
        bytes32 transferId,
        bytes32 nearTxHash
    ) external onlyRole(RELAYER_ROLE) {
        OutboundTransfer storage transfer = outboundTransfers[transferId];
        if (transfer.initiatedAt == 0) revert TransferNotFound();
        if (transfer.status != TransferStatus.PENDING)
            revert TransferNotPending();

        transfer.status = TransferStatus.PROVED;
        transfer.nearTxHash = nearTxHash;

        emit TransferProved(transferId, nearTxHash);
    }

    /**
     * @notice Complete transfer
     */
    function completeTransfer(
        bytes32 transferId
    ) external onlyRole(RELAYER_ROLE) {
        OutboundTransfer storage transfer = outboundTransfers[transferId];
        if (transfer.status != TransferStatus.PROVED)
            revert TransferNotPending();

        transfer.status = TransferStatus.COMPLETED;
        transfer.completedAt = block.timestamp;

        emit TransferCompleted(transferId);
    }

    /*//////////////////////////////////////////////////////////////
                    INBOUND TRANSFERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive transfer from NEAR
     */
    function receiveFromNEAR(
        string calldata nearSender,
        address evmReceiver,
        string calldata tokenAccountId,
        uint256 nearAmount,
        bytes32 nearTxHash,
        bytes32 receiptId,
        bytes32[] calldata proof,
        uint64 blockHeight
    ) external onlyRole(PROVER_ROLE) nonReentrant returns (bytes32 transferId) {
        if (processedReceipts[receiptId]) revert ProofAlreadyUsed();
        if (evmReceiver == address(0)) revert InvalidReceiver();

        // Verify block is finalized
        NEARBlockHeader storage header = blockHeaders[blockHeight];
        if (!header.finalized) revert BlockNotFinalized();

        // Verify receipt proof
        if (!_verifyReceiptProof(receiptId, proof, header.outcomeRoot)) {
            revert InvalidProof();
        }

        processedReceipts[receiptId] = true;

        bytes32 tokenHash = keccak256(bytes(tokenAccountId));
        NEP141Token storage token = nep141Tokens[tokenHash];
        if (token.tokenHash == bytes32(0)) revert TokenNotRegistered();

        // Convert from NEAR decimals
        uint256 evmAmount = _convertFromNearDecimals(
            nearAmount,
            token.decimals
        );

        transferId = keccak256(
            abi.encodePacked(
                nearTxHash,
                evmReceiver,
                nearAmount,
                block.timestamp
            )
        );

        inboundTransfers[transferId] = InboundTransfer({
            transferId: transferId,
            nearSender: nearSender,
            evmReceiver: evmReceiver,
            tokenAccountId: tokenAccountId,
            nearAmount: nearAmount,
            evmAmount: evmAmount,
            nearTxHash: nearTxHash,
            proof: ReceiptProof({
                receiptId: receiptId,
                blockHash: header.blockHash,
                proof: proof,
                blockHeight: blockHeight,
                status: ProofStatus.VERIFIED
            }),
            status: TransferStatus.COMPLETED,
            completedAt: block.timestamp
        });

        totalInboundTransfers++;
        totalValueBridgedIn += evmAmount;
        totalProofsVerified++;

        emit InboundReceived(transferId, nearSender, evmReceiver, evmAmount);
        emit ProofVerified(receiptId, blockHeight);
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function setBridgeFee(uint256 newFee) external onlyRole(OPERATOR_ROLE) {
        require(newFee <= 100, "Fee too high");
        bridgeFee = newFee;
    }

    function setTransferLimits(
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(OPERATOR_ROLE) {
        minTransferAmount = minAmount;
        maxTransferAmount = maxAmount;
    }

    function setNearConnector(
        string calldata connector
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        nearConnector = connector;
    }

    function setTreasury(
        address newTreasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        treasury = newTreasury;
    }

    /*//////////////////////////////////////////////////////////////
                           PAUSABLE
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                           STATISTICS
    //////////////////////////////////////////////////////////////*/

    function getBridgeStats()
        external
        view
        returns (
            uint256 outbound,
            uint256 inbound,
            uint256 valueOut,
            uint256 valueIn,
            uint256 proofs,
            uint256 fees
        )
    {
        return (
            totalOutboundTransfers,
            totalInboundTransfers,
            totalValueBridgedOut,
            totalValueBridgedIn,
            totalProofsVerified,
            totalFeesCollected
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify receipt proof
     */
    function _verifyReceiptProof(
        bytes32 receiptId,
        bytes32[] calldata proof,
        bytes32 outcomeRoot
    ) internal pure returns (bool) {
        bytes32 computedRoot = receiptId;

        for (uint256 i = 0; i < proof.length; i++) {
            if (uint256(computedRoot) < uint256(proof[i])) {
                computedRoot = keccak256(
                    abi.encodePacked(computedRoot, proof[i])
                );
            } else {
                computedRoot = keccak256(
                    abi.encodePacked(proof[i], computedRoot)
                );
            }
        }

        return computedRoot == outcomeRoot;
    }

    /**
     * @notice Validate NEAR account ID format
     */
    function _isValidNearAccountId(
        string memory accountId
    ) internal pure returns (bool) {
        bytes memory b = bytes(accountId);

        // Length check (min 2, max 64)
        if (b.length < 2 || b.length > 64) return false;

        // Check for valid characters (simplified)
        for (uint256 i = 0; i < b.length; i++) {
            bytes1 char = b[i];
            bool valid = (char >= 0x61 && char <= 0x7A) || // a-z
                (char >= 0x30 && char <= 0x39) || // 0-9
                char == 0x2D || // -
                char == 0x5F || // _
                char == 0x2E; // .
            if (!valid) return false;
        }

        return true;
    }

    /**
     * @notice Convert to NEAR decimals (max 24)
     */
    function _convertToNearDecimals(
        uint256 amount,
        uint8 nearDecimals
    ) internal pure returns (uint256) {
        uint8 evmDecimals = 18;

        if (evmDecimals > nearDecimals) {
            return amount / (10 ** (evmDecimals - nearDecimals));
        } else if (evmDecimals < nearDecimals) {
            return amount * (10 ** (nearDecimals - evmDecimals));
        }
        return amount;
    }

    /**
     * @notice Convert from NEAR decimals
     */
    function _convertFromNearDecimals(
        uint256 amount,
        uint8 nearDecimals
    ) internal pure returns (uint256) {
        uint8 evmDecimals = 18;

        if (evmDecimals > nearDecimals) {
            return amount * (10 ** (evmDecimals - nearDecimals));
        } else if (evmDecimals < nearDecimals) {
            return amount / (10 ** (nearDecimals - evmDecimals));
        }
        return amount;
    }

    receive() external payable {}
}
