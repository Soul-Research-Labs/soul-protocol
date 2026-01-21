// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AvalancheBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Avalanche C-Chain and subnet integration
 * @dev Enables cross-chain interoperability between PIL and Avalanche ecosystem
 *
 * AVALANCHE INTEGRATION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                   PIL <-> Avalanche Bridge                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Avalanche       │                 │
 * │  │  (Ethereum)       │           │   (C-Chain/Subnets│                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ERC20       │  │◄─────────►│  │ ARC20       │  │                 │
 * │  │  │ Tokens      │  │           │  │ Tokens      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Bridge      │  │           │  │ Teleporter  │  │                 │
 * │  │  │ Contract    │  │◄─────────►│  │ Protocol    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Avalanche Warp Messaging                         │ │
 * │  │  - Cross-Subnet Communication                                      │ │
 * │  │  - BLS Signature Aggregation                                       │ │
 * │  │  - Teleporter Protocol                                             │ │
 * │  │  - Subnet <-> C-Chain Bridging                                     │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * AVALANCHE CONCEPTS:
 * - Primary Network: X-Chain, P-Chain, C-Chain
 * - Subnets: Custom blockchains with own validators
 * - Snowman Consensus: Optimistic BFT consensus
 * - Avalanche Warp: Native cross-subnet messaging
 * - Teleporter: Cross-chain messaging protocol
 */
contract AvalancheBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant WARP_ROLE = keccak256("WARP_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice C-Chain ID
    bytes32 public constant C_CHAIN_ID = keccak256("C-Chain");

    /// @notice Warp message version
    uint32 public constant WARP_VERSION = 1;

    /// @notice Default message gas limit
    uint256 public constant DEFAULT_GAS_LIMIT = 500000;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum TransferStatus {
        PENDING,
        DELIVERED,
        EXECUTED,
        FAILED
    }

    enum MessageType {
        TRANSFER,
        CALL,
        MULTI_HOP
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Avalanche Subnet configuration
    struct SubnetConfig {
        bytes32 subnetId; // Subnet identifier
        bytes32 blockchainId; // Blockchain ID on subnet
        string name; // Subnet name
        address teleporterAddress; // Teleporter messenger address
        bool isEVMCompatible; // Is EVM compatible
        bool active; // Is subnet active
        uint256 registeredAt; // Registration timestamp
    }

    /// @notice Warp Message
    struct WarpMessage {
        bytes32 messageId; // Unique message ID
        bytes32 sourceBlockchainId; // Source blockchain
        bytes32 destBlockchainId; // Destination blockchain
        address sourceAddress; // Source contract
        address destAddress; // Destination contract
        bytes payload; // Message payload
        uint256 gasLimit; // Execution gas limit
        uint256 timestamp; // Message timestamp
    }

    /// @notice Warp Signature (BLS aggregated)
    struct WarpSignature {
        bytes32 messageHash; // Hash of message
        bytes signature; // BLS aggregate signature
        bytes32[] signingSubnetIds; // Subnets that signed
        uint256 signedWeight; // Total signing weight
        uint256 totalWeight; // Total possible weight
    }

    /// @notice Cross-chain transfer
    struct CrossChainTransfer {
        bytes32 transferId; // Transfer identifier
        address sender; // Sender address
        address recipient; // Recipient address
        bytes32 sourceChain; // Source blockchain ID
        bytes32 destChain; // Destination blockchain ID
        address token; // Token address (source)
        address destToken; // Token address (destination)
        uint256 amount; // Transfer amount
        bytes32 messageId; // Warp message ID
        TransferStatus status; // Transfer status
        uint256 initiatedAt; // Initiation timestamp
        uint256 completedAt; // Completion timestamp
    }

    /// @notice Teleporter message receipt
    struct TeleporterReceipt {
        bytes32 receiptId; // Receipt identifier
        bytes32 messageId; // Original message ID
        bytes32 sourceBlockchain; // Source blockchain
        address relayer; // Relayer address
        bool success; // Execution success
        bytes result; // Execution result
        uint256 gasUsed; // Gas consumed
        uint256 timestamp; // Receipt timestamp
    }

    /// @notice Token mapping
    struct TokenMapping {
        address sourceToken; // Token on source chain
        address destToken; // Token on destination
        bytes32 sourceChain; // Source chain ID
        bytes32 destChain; // Destination chain ID
        uint8 decimals; // Token decimals
        uint256 totalBridged; // Total bridged amount
        bool active; // Is mapping active
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

    /// @notice This chain's blockchain ID
    bytes32 public thisBlockchainId;

    /// @notice Teleporter messenger address
    address public teleporterMessenger;

    /// @notice Transfer nonce
    uint256 public transferNonce;

    /// @notice Message nonce
    uint256 public messageNonce;

    /// @notice Treasury address
    address public treasury;

    /// @notice Required signing weight (percentage basis points)
    uint256 public requiredWeight;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered subnets
    mapping(bytes32 => SubnetConfig) public subnets;
    bytes32[] public subnetIds;

    /// @notice Warp messages by ID
    mapping(bytes32 => WarpMessage) public warpMessages;

    /// @notice Warp signatures by message hash
    mapping(bytes32 => WarpSignature) public warpSignatures;

    /// @notice Transfers by ID
    mapping(bytes32 => CrossChainTransfer) public transfers;

    /// @notice User's transfers
    mapping(address => bytes32[]) public userTransfers;

    /// @notice Teleporter receipts
    mapping(bytes32 => TeleporterReceipt) public teleporterReceipts;

    /// @notice Token mappings by key (sourceToken + destChain hash)
    mapping(bytes32 => TokenMapping) public tokenMappings;
    bytes32[] public tokenMappingKeys;

    /// @notice Processed warp messages
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Allowed relayers
    mapping(address => bool) public allowedRelayers;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalTransfers;
    uint256 public totalMessagesReceived;
    uint256 public totalValueBridged;
    uint256 public totalFeesCollected;
    uint256 public totalRelayerRewards;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event SubnetRegistered(bytes32 indexed subnetId, string name);
    event WarpMessageSent(
        bytes32 indexed messageId,
        bytes32 destChain,
        address destAddress
    );
    event WarpMessageReceived(bytes32 indexed messageId, bytes32 sourceChain);
    event WarpMessageExecuted(bytes32 indexed messageId, bool success);

    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        address recipient,
        bytes32 destChain,
        uint256 amount
    );

    event TransferCompleted(bytes32 indexed transferId);
    event TokenMapped(
        address indexed sourceToken,
        address destToken,
        bytes32 destChain
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error SubnetNotRegistered();
    error InvalidMessage();
    error MessageAlreadyProcessed();
    error InvalidSignature();
    error InsufficientSigningWeight();
    error TokenNotMapped();
    error InvalidAmount();
    error AmountTooLow();
    error AmountTooHigh();
    error InsufficientFee();
    error TransferNotFound();
    error InvalidRecipient();
    error UnauthorizedRelayer();
    error ExecutionFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _admin,
        bytes32 _thisBlockchainId,
        address _teleporterMessenger
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        thisBlockchainId = _thisBlockchainId;
        teleporterMessenger = _teleporterMessenger;

        bridgeFee = 20; // 0.2%
        minTransferAmount = 1e15;
        maxTransferAmount = 1e24;
        requiredWeight = 6700; // 67%
    }

    /*//////////////////////////////////////////////////////////////
                    SUBNET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a subnet
     */
    function registerSubnet(
        bytes32 subnetId,
        bytes32 blockchainId,
        string calldata name,
        address teleporter,
        bool isEVMCompatible
    ) external onlyRole(OPERATOR_ROLE) {
        subnets[subnetId] = SubnetConfig({
            subnetId: subnetId,
            blockchainId: blockchainId,
            name: name,
            teleporterAddress: teleporter,
            isEVMCompatible: isEVMCompatible,
            active: true,
            registeredAt: block.timestamp
        });

        subnetIds.push(subnetId);

        emit SubnetRegistered(subnetId, name);
    }

    /*//////////////////////////////////////////////////////////////
                    WARP MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a warp message
     */
    function sendWarpMessage(
        bytes32 destBlockchainId,
        address destAddress,
        bytes calldata payload,
        uint256 gasLimit
    ) external whenNotPaused returns (bytes32 messageId) {
        if (gasLimit == 0) gasLimit = DEFAULT_GAS_LIMIT;

        messageId = keccak256(
            abi.encodePacked(
                thisBlockchainId,
                destBlockchainId,
                msg.sender,
                destAddress,
                payload,
                messageNonce++,
                block.timestamp
            )
        );

        warpMessages[messageId] = WarpMessage({
            messageId: messageId,
            sourceBlockchainId: thisBlockchainId,
            destBlockchainId: destBlockchainId,
            sourceAddress: msg.sender,
            destAddress: destAddress,
            payload: payload,
            gasLimit: gasLimit,
            timestamp: block.timestamp
        });

        emit WarpMessageSent(messageId, destBlockchainId, destAddress);
    }

    /**
     * @notice Receive a warp message with signature
     */
    function receiveWarpMessage(
        bytes32 messageId,
        bytes32 sourceBlockchainId,
        address sourceAddress,
        bytes calldata payload,
        bytes calldata signature,
        bytes32[] calldata signingSubnetIds,
        uint256 signedWeight,
        uint256 totalWeight
    ) external onlyRole(WARP_ROLE) returns (bool) {
        if (processedMessages[messageId]) revert MessageAlreadyProcessed();

        // Verify signature weight
        if ((signedWeight * 10000) / totalWeight < requiredWeight) {
            revert InsufficientSigningWeight();
        }

        // Verify BLS signature (simplified)
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                messageId,
                sourceBlockchainId,
                thisBlockchainId,
                sourceAddress,
                payload
            )
        );

        if (!_verifyBLSSignature(messageHash, signature, signingSubnetIds)) {
            revert InvalidSignature();
        }

        processedMessages[messageId] = true;

        warpSignatures[messageHash] = WarpSignature({
            messageHash: messageHash,
            signature: signature,
            signingSubnetIds: signingSubnetIds,
            signedWeight: signedWeight,
            totalWeight: totalWeight
        });

        totalMessagesReceived++;

        emit WarpMessageReceived(messageId, sourceBlockchainId);

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                    TOKEN TRANSFERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Transfer tokens to another chain
     */
    function transferToChain(
        bytes32 destChain,
        address recipient,
        address token,
        uint256 amount
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        bytes32 mappingKey = keccak256(abi.encodePacked(token, destChain));
        TokenMapping storage mapping_ = tokenMappings[mappingKey];
        if (!mapping_.active) revert TokenNotMapped();

        if (amount < minTransferAmount) revert AmountTooLow();
        if (amount > maxTransferAmount) revert AmountTooHigh();
        if (recipient == address(0)) revert InvalidRecipient();

        // Calculate fee
        uint256 fee = (amount * bridgeFee) / 10000;
        if (msg.value < fee) revert InsufficientFee();

        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                token,
                amount,
                destChain,
                transferNonce++,
                block.timestamp
            )
        );

        // Create warp message
        bytes32 messageId = keccak256(abi.encodePacked(transferId, "transfer"));
        bytes memory payload = abi.encode(
            recipient,
            mapping_.destToken,
            amount
        );

        warpMessages[messageId] = WarpMessage({
            messageId: messageId,
            sourceBlockchainId: thisBlockchainId,
            destBlockchainId: destChain,
            sourceAddress: address(this),
            destAddress: subnets[destChain].teleporterAddress,
            payload: payload,
            gasLimit: DEFAULT_GAS_LIMIT,
            timestamp: block.timestamp
        });

        transfers[transferId] = CrossChainTransfer({
            transferId: transferId,
            sender: msg.sender,
            recipient: recipient,
            sourceChain: thisBlockchainId,
            destChain: destChain,
            token: token,
            destToken: mapping_.destToken,
            amount: amount,
            messageId: messageId,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        userTransfers[msg.sender].push(transferId);

        mapping_.totalBridged += amount;
        totalTransfers++;
        totalValueBridged += amount;
        totalFeesCollected += fee;

        emit TransferInitiated(
            transferId,
            msg.sender,
            recipient,
            destChain,
            amount
        );
        emit WarpMessageSent(
            messageId,
            destChain,
            subnets[destChain].teleporterAddress
        );
    }

    /**
     * @notice Complete transfer on destination
     */
    function completeTransfer(
        bytes32 transferId,
        bytes32 messageId,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) {
        CrossChainTransfer storage transfer = transfers[transferId];
        if (transfer.initiatedAt == 0) revert TransferNotFound();

        if (!processedMessages[messageId]) revert InvalidMessage();

        transfer.status = TransferStatus.EXECUTED;
        transfer.completedAt = block.timestamp;

        emit TransferCompleted(transferId);
    }

    /*//////////////////////////////////////////////////////////////
                    TOKEN MAPPING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Map a token across chains
     */
    function mapToken(
        address sourceToken,
        address destToken,
        bytes32 destChain,
        uint8 decimals
    ) external onlyRole(OPERATOR_ROLE) {
        bytes32 key = keccak256(abi.encodePacked(sourceToken, destChain));

        tokenMappings[key] = TokenMapping({
            sourceToken: sourceToken,
            destToken: destToken,
            sourceChain: thisBlockchainId,
            destChain: destChain,
            decimals: decimals,
            totalBridged: 0,
            active: true
        });

        tokenMappingKeys.push(key);

        emit TokenMapped(sourceToken, destToken, destChain);
    }

    /*//////////////////////////////////////////////////////////////
                    RELAYER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function addRelayer(address relayer) external onlyRole(OPERATOR_ROLE) {
        allowedRelayers[relayer] = true;
    }

    function removeRelayer(address relayer) external onlyRole(OPERATOR_ROLE) {
        allowedRelayers[relayer] = false;
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

    function setRequiredWeight(
        uint256 weight
    ) external onlyRole(GUARDIAN_ROLE) {
        require(weight >= 5000 && weight <= 10000, "Invalid weight");
        requiredWeight = weight;
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
            uint256 transferCount,
            uint256 messagesReceived,
            uint256 valueBridged,
            uint256 fees,
            uint256 relayerRewards
        )
    {
        return (
            totalTransfers,
            totalMessagesReceived,
            totalValueBridged,
            totalFeesCollected,
            totalRelayerRewards
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _verifyBLSSignature(
        bytes32 messageHash,
        bytes calldata signature,
        bytes32[] calldata signingSubnetIds
    ) internal pure returns (bool) {
        // Simplified BLS verification
        // Real implementation would use BLS12-381 curve operations
        return
            signature.length >= 96 &&
            signingSubnetIds.length > 0 &&
            messageHash != bytes32(0);
    }

    receive() external payable {}
}
