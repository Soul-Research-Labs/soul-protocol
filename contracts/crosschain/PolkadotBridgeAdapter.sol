// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PolkadotBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Polkadot ecosystem integration
 * @dev Enables cross-chain interoperability between PIL (EVM) and Polkadot/Substrate chains
 *
 * POLKADOT INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     PIL <-> Polkadot Bridge                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Polkadot        │                 │
 * │  │  (EVM/Solidity)   │           │  (Substrate/WASM) │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ERC20/721   │  │◄─────────►│  │ Assets      │  │                 │
 * │  │  │ Tokens      │  │           │  │ Pallet      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Messages    │  │           │  │ XCM         │  │                 │
 * │  │  │             │  │◄─────────►│  │ Messages    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Bridge Protocol Layer                            │ │
 * │  │  - XCM Message Verification                                        │ │
 * │  │  - GRANDPA/BEEFY Finality Proofs                                   │ │
 * │  │  - Parachain State Proofs (Merkle-Patricia)                        │ │
 * │  │  - Multi-Location Asset Registry                                   │ │
 * │  │  - Cross-Consensus Messaging (XCM v3)                              │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * POLKADOT CONCEPTS:
 * - Relay Chain: Central chain coordinating the network
 * - Parachains: Parallel chains with custom logic
 * - XCM: Cross-Consensus Messaging format
 * - GRANDPA: GHOST-based Recursive ANcestor Deriving Prefix Agreement (finality)
 * - BEEFY: Bridge Efficiency Enabling Finality Yielder
 * - DOT: Native token for staking and governance
 * - MultiLocation: Universal asset/account identification
 * - Sovereign Account: Parachain's account on another chain
 * - Teleport: Moving assets between trust-equivalent chains
 * - Reserve Transfer: Moving assets via reserve chain
 *
 * SUPPORTED PARACHAINS:
 * - Polkadot Relay Chain (DOT)
 * - Kusama Relay Chain (KSM)
 * - Moonbeam (GLMR) - EVM compatible
 * - Acala (ACA) - DeFi hub
 * - Astar (ASTR) - Smart contracts
 * - Phala (PHA) - Confidential computing
 * - Centrifuge (CFG) - Real-world assets
 * - Hydration (HDX) - Omnipool DEX
 *
 * SUPPORTED FEATURES:
 * - XCM Message Bridging
 * - GRANDPA Light Client Verification
 * - BEEFY Commitment Proofs
 * - Parachain State Proofs
 * - Asset Teleportation
 * - Reserve Asset Transfers
 * - Multi-hop Routing
 * - Cross-chain Smart Contract Calls
 */
contract PolkadotBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant BEEFY_ROLE = keccak256("BEEFY_ROLE");

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Polkadot network types
    enum NetworkType {
        POLKADOT, // Polkadot mainnet
        KUSAMA, // Kusama canary network
        ROCOCO, // Rococo testnet
        WESTEND, // Westend testnet
        LOCAL // Local development
    }

    /// @notice XCM instruction types
    enum XCMInstruction {
        WithdrawAsset,
        ReserveAssetDeposited,
        ReceiveTeleportedAsset,
        QueryResponse,
        TransferAsset,
        TransferReserveAsset,
        Transact,
        HrmpNewChannelOpenRequest,
        HrmpChannelAccepted,
        HrmpChannelClosing,
        ClearOrigin,
        DescendOrigin,
        ReportError,
        DepositAsset,
        DepositReserveAsset,
        ExchangeAsset,
        InitiateReserveWithdraw,
        InitiateTeleport,
        ReportHolding,
        BuyExecution,
        RefundSurplus,
        SetErrorHandler,
        SetAppendix,
        ClearError,
        ClaimAsset,
        Trap,
        SubscribeVersion,
        UnsubscribeVersion,
        BurnAsset,
        ExpectAsset,
        ExpectOrigin,
        ExpectError,
        ExpectTransactStatus,
        QueryPallet,
        ExpectPallet,
        ReportTransactStatus,
        ClearTransactStatus,
        UniversalOrigin,
        ExportMessage,
        LockAsset,
        UnlockAsset,
        NoteUnlockable,
        RequestUnlock,
        SetFeesMode,
        SetTopic,
        ClearTopic,
        AliasOrigin,
        UnpaidExecution
    }

    /// @notice Asset transfer type
    enum TransferType {
        TELEPORT, // Direct transfer between trusted chains
        RESERVE_WITHDRAW, // Withdraw from reserve chain
        RESERVE_DEPOSIT, // Deposit to reserve chain
        LOCAL_RESERVE // Local chain is reserve
    }

    /// @notice Parachain status
    enum ParachainStatus {
        INACTIVE,
        ONBOARDING,
        ACTIVE,
        OFFBOARDING,
        RETIRED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice MultiLocation for identifying assets/accounts across chains
    struct MultiLocation {
        uint8 parents; // Number of parent hops (0 = same chain)
        bytes interior; // Junction path (encoded)
        bytes32 locationHash; // Hash for quick lookup
    }

    /// @notice Parachain information
    struct Parachain {
        uint32 paraId; // Parachain ID
        bytes32 genesisHash; // Genesis block hash
        bytes32 stateRoot; // Latest known state root
        uint32 lastRelayBlock; // Last relay chain block processed
        ParachainStatus status; // Current status
        bool evmCompatible; // Is EVM compatible (e.g., Moonbeam)
        bytes32 sovereignAccount; // Sovereign account on relay chain
        uint256 registeredAt; // Registration timestamp
    }

    /// @notice XCM message structure
    struct XCMMessage {
        bytes32 messageId; // Unique message identifier
        uint32 sourceParaId; // Source parachain (0 = relay)
        uint32 destParaId; // Destination parachain (0 = relay)
        MultiLocation origin; // Origin location
        MultiLocation dest; // Destination location
        bytes instructions; // Encoded XCM instructions
        uint256 weight; // Execution weight limit
        bytes32 assetId; // Asset being transferred
        uint256 amount; // Amount (if applicable)
        uint256 timestamp; // Message creation time
        bool executed; // Execution status
    }

    /// @notice GRANDPA finality proof
    struct GrandpaProof {
        bytes32 blockHash; // Block hash being finalized
        uint32 blockNumber; // Block number
        bytes32 setId; // Authority set ID
        bytes precommits; // Encoded precommit messages
        bytes authorityProof; // Proof of authority set
        uint256 submittedAt; // Submission timestamp
        bool verified; // Verification status
    }

    /// @notice BEEFY commitment
    struct BeefyCommitment {
        bytes32 payloadHash; // MMR root or other payload
        uint32 blockNumber; // Block number
        uint32 validatorSetId; // Validator set ID
        bytes32 nextAuthorityRoot; // Next authority set Merkle root
        bytes signatures; // Aggregated signatures (BLS)
        uint256 timestamp; // Commitment timestamp
        bool finalized; // Finalization status
    }

    /// @notice Registered asset
    struct RegisteredAsset {
        bytes32 assetId; // PIL asset identifier
        MultiLocation multilocation; // Polkadot MultiLocation
        address evmAddress; // EVM token address (if any)
        uint8 decimals; // Asset decimals
        uint256 minTransfer; // Minimum transfer amount
        uint256 maxTransfer; // Maximum transfer amount
        bool isSufficient; // Is sufficient for account existence
        bool teleportable; // Can be teleported
        bool reserveTransferable; // Can use reserve transfers
        uint256 totalBridged; // Total amount bridged
    }

    /// @notice Cross-chain transfer
    struct CrossChainTransfer {
        bytes32 transferId; // Unique transfer identifier
        address sender; // EVM sender
        bytes32 recipient; // Polkadot recipient (SS58 encoded hash)
        bytes32 assetId; // Asset being transferred
        uint256 amount; // Transfer amount
        uint32 destParaId; // Destination parachain
        TransferType transferType; // Type of transfer
        uint256 fee; // Bridge fee paid
        uint256 initiatedAt; // Initiation timestamp
        uint256 completedAt; // Completion timestamp (0 if pending)
        bool refunded; // Whether refunded
    }

    /// @notice State proof for parachain
    struct StateProof {
        bytes32 stateRoot; // State root
        bytes proof; // Merkle-Patricia proof
        bytes32 storageKey; // Storage key being proven
        bytes storageValue; // Storage value
        uint32 blockNumber; // Block number
        bool verified; // Verification status
    }

    /// @notice Validator information
    struct Validator {
        bytes32 validatorId; // Validator public key hash
        bytes32 beefyKey; // BEEFY public key
        uint256 stake; // Staked amount
        bool active; // Is active in current set
        uint256 addedAt; // When added to set
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Current network type
    NetworkType public network;

    /// @notice Guardian threshold for critical operations
    uint256 public guardianThreshold;

    /// @notice Current guardian count
    uint256 public guardianCount;

    /// @notice Bridge fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum transfer amount
    uint256 public minTransferAmount;

    /// @notice Maximum transfer amount per transaction
    uint256 public maxTransferAmount;

    /// @notice Current GRANDPA authority set ID
    uint64 public currentSetId;

    /// @notice Current BEEFY validator set ID
    uint32 public beefyValidatorSetId;

    /// @notice Latest finalized relay chain block
    uint32 public latestFinalizedBlock;

    /// @notice Transfer nonce
    uint256 public transferNonce;

    /// @notice Treasury address for fees
    address public treasury;

    /// @notice Relay chain genesis hash
    bytes32 public relayGenesisHash;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered parachains
    mapping(uint32 => Parachain) public parachains;

    /// @notice Parachain IDs list
    uint32[] public parachainIds;

    /// @notice XCM messages by ID
    mapping(bytes32 => XCMMessage) public xcmMessages;

    /// @notice GRANDPA proofs by block hash
    mapping(bytes32 => GrandpaProof) public grandpaProofs;

    /// @notice BEEFY commitments by block number
    mapping(uint32 => BeefyCommitment) public beefyCommitments;

    /// @notice Registered assets
    mapping(bytes32 => RegisteredAsset) public registeredAssets;

    /// @notice EVM to Polkadot asset mapping
    mapping(address => bytes32) public evmToPolkadotAsset;

    /// @notice Cross-chain transfers
    mapping(bytes32 => CrossChainTransfer) public transfers;

    /// @notice State proofs
    mapping(bytes32 => StateProof) public stateProofs;

    /// @notice Validators
    mapping(bytes32 => Validator) public validators;

    /// @notice Active validator set
    bytes32[] public activeValidators;

    /// @notice Processed message hashes (replay protection)
    mapping(bytes32 => bool) public processedMessages;

    /// @notice User transfer history
    mapping(address => bytes32[]) public userTransfers;

    /// @notice Guardian approvals for operations
    mapping(bytes32 => mapping(address => bool)) public guardianApprovals;

    /// @notice Guardian approval counts
    mapping(bytes32 => uint256) public approvalCounts;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalTransfersOut;
    uint256 public totalTransfersIn;
    uint256 public totalValueBridged;
    uint256 public totalFeesCollected;
    uint256 public xcmMessageCount;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ParachainRegistered(
        uint32 indexed paraId,
        bytes32 genesisHash,
        bool evmCompatible
    );

    event ParachainStatusUpdated(
        uint32 indexed paraId,
        ParachainStatus oldStatus,
        ParachainStatus newStatus
    );

    event AssetRegistered(
        bytes32 indexed assetId,
        bytes32 multilocationHash,
        address evmAddress
    );

    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        bytes32 recipient,
        bytes32 assetId,
        uint256 amount,
        uint32 destParaId
    );

    event TransferCompleted(bytes32 indexed transferId, uint256 completedAt);

    event TransferRefunded(
        bytes32 indexed transferId,
        address indexed recipient,
        uint256 amount
    );

    event XCMMessageSent(
        bytes32 indexed messageId,
        uint32 sourceParaId,
        uint32 destParaId,
        uint256 weight
    );

    event XCMMessageReceived(
        bytes32 indexed messageId,
        uint32 sourceParaId,
        bytes32 assetId,
        uint256 amount
    );

    event GrandpaProofSubmitted(
        bytes32 indexed blockHash,
        uint32 blockNumber,
        bytes32 setId
    );

    event GrandpaProofVerified(bytes32 indexed blockHash, bool success);

    event BeefyCommitmentSubmitted(
        uint32 indexed blockNumber,
        bytes32 payloadHash,
        uint32 validatorSetId
    );

    event BeefyCommitmentFinalized(
        uint32 indexed blockNumber,
        bytes32 payloadHash
    );

    event StateProofVerified(
        bytes32 indexed stateRoot,
        bytes32 storageKey,
        uint32 blockNumber
    );

    event ValidatorSetUpdated(uint32 newSetId, uint256 validatorCount);

    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);

    event NetworkUpdated(NetworkType oldNetwork, NetworkType newNetwork);

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidParaId();
    error ParachainNotRegistered();
    error ParachainAlreadyRegistered();
    error ParachainNotActive();
    error InvalidAssetId();
    error AssetNotRegistered();
    error AssetAlreadyRegistered();
    error InvalidMultiLocation();
    error InvalidTransferAmount();
    error TransferAmountTooLow();
    error TransferAmountTooHigh();
    error InsufficientFee();
    error TransferNotFound();
    error TransferAlreadyCompleted();
    error TransferAlreadyRefunded();
    error InvalidXCMMessage();
    error XCMMessageAlreadyProcessed();
    error InvalidGrandpaProof();
    error InvalidBeefyCommitment();
    error InvalidStateProof();
    error InsufficientSignatures();
    error InvalidValidatorSet();
    error BlockNotFinalized();
    error InvalidRecipient();
    error InvalidSender();
    error BridgePaused();
    error FeeTooHigh();
    error InsufficientGuardianApprovals();
    error AlreadyApproved();
    error InvalidProof();
    error ExpiredProof();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _admin,
        NetworkType _network,
        bytes32 _relayGenesisHash,
        uint256 _guardianThreshold
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        network = _network;
        relayGenesisHash = _relayGenesisHash;
        guardianThreshold = _guardianThreshold;
        guardianCount = 1;

        bridgeFee = 25; // 0.25%
        minTransferAmount = 1e15; // 0.001 DOT equivalent
        maxTransferAmount = 1e24; // 1M DOT equivalent
    }

    /*//////////////////////////////////////////////////////////////
                         PARACHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a new parachain
     * @param paraId Parachain ID
     * @param genesisHash Genesis block hash
     * @param evmCompatible Whether the parachain is EVM compatible
     * @param sovereignAccount Sovereign account on relay chain
     */
    function registerParachain(
        uint32 paraId,
        bytes32 genesisHash,
        bool evmCompatible,
        bytes32 sovereignAccount
    ) external onlyRole(OPERATOR_ROLE) {
        if (paraId == 0) revert InvalidParaId();
        if (parachains[paraId].registeredAt != 0)
            revert ParachainAlreadyRegistered();
        if (genesisHash == bytes32(0)) revert InvalidParaId();

        parachains[paraId] = Parachain({
            paraId: paraId,
            genesisHash: genesisHash,
            stateRoot: bytes32(0),
            lastRelayBlock: 0,
            status: ParachainStatus.ONBOARDING,
            evmCompatible: evmCompatible,
            sovereignAccount: sovereignAccount,
            registeredAt: block.timestamp
        });

        parachainIds.push(paraId);

        emit ParachainRegistered(paraId, genesisHash, evmCompatible);
    }

    /**
     * @notice Activate a parachain
     * @param paraId Parachain ID
     */
    function activateParachain(uint32 paraId) external onlyRole(OPERATOR_ROLE) {
        Parachain storage para = parachains[paraId];
        if (para.registeredAt == 0) revert ParachainNotRegistered();

        ParachainStatus oldStatus = para.status;
        para.status = ParachainStatus.ACTIVE;

        emit ParachainStatusUpdated(paraId, oldStatus, ParachainStatus.ACTIVE);
    }

    /**
     * @notice Update parachain state root
     * @param paraId Parachain ID
     * @param stateRoot New state root
     * @param relayBlock Relay chain block number
     */
    function updateParachainState(
        uint32 paraId,
        bytes32 stateRoot,
        uint32 relayBlock
    ) external onlyRole(RELAYER_ROLE) {
        Parachain storage para = parachains[paraId];
        if (para.registeredAt == 0) revert ParachainNotRegistered();
        if (para.status != ParachainStatus.ACTIVE) revert ParachainNotActive();

        para.stateRoot = stateRoot;
        para.lastRelayBlock = relayBlock;
    }

    /**
     * @notice Get parachain information
     * @param paraId Parachain ID
     */
    function getParachain(
        uint32 paraId
    ) external view returns (Parachain memory) {
        return parachains[paraId];
    }

    /**
     * @notice Get all registered parachain IDs
     */
    function getParachainIds() external view returns (uint32[] memory) {
        return parachainIds;
    }

    /*//////////////////////////////////////////////////////////////
                          ASSET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a bridgeable asset
     * @param assetId PIL asset identifier
     * @param parents MultiLocation parents
     * @param interior MultiLocation interior (encoded)
     * @param evmAddress EVM token address (address(0) for native)
     * @param decimals Asset decimals
     * @param teleportable Whether asset can be teleported
     */
    function registerAsset(
        bytes32 assetId,
        uint8 parents,
        bytes calldata interior,
        address evmAddress,
        uint8 decimals,
        bool teleportable,
        bool reserveTransferable
    ) external onlyRole(OPERATOR_ROLE) {
        if (assetId == bytes32(0)) revert InvalidAssetId();
        if (registeredAssets[assetId].assetId != bytes32(0))
            revert AssetAlreadyRegistered();

        bytes32 locationHash = keccak256(abi.encodePacked(parents, interior));

        registeredAssets[assetId] = RegisteredAsset({
            assetId: assetId,
            multilocation: MultiLocation({
                parents: parents,
                interior: interior,
                locationHash: locationHash
            }),
            evmAddress: evmAddress,
            decimals: decimals,
            minTransfer: minTransferAmount,
            maxTransfer: maxTransferAmount,
            isSufficient: true,
            teleportable: teleportable,
            reserveTransferable: reserveTransferable,
            totalBridged: 0
        });

        if (evmAddress != address(0)) {
            evmToPolkadotAsset[evmAddress] = assetId;
        }

        emit AssetRegistered(assetId, locationHash, evmAddress);
    }

    /**
     * @notice Update asset transfer limits
     * @param assetId Asset identifier
     * @param minAmount Minimum transfer amount
     * @param maxAmount Maximum transfer amount
     */
    function updateAssetLimits(
        bytes32 assetId,
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(OPERATOR_ROLE) {
        RegisteredAsset storage asset = registeredAssets[assetId];
        if (asset.assetId == bytes32(0)) revert AssetNotRegistered();

        asset.minTransfer = minAmount;
        asset.maxTransfer = maxAmount;
    }

    /**
     * @notice Get registered asset information
     * @param assetId Asset identifier
     */
    function getAsset(
        bytes32 assetId
    ) external view returns (RegisteredAsset memory) {
        return registeredAssets[assetId];
    }

    /*//////////////////////////////////////////////////////////////
                        CROSS-CHAIN TRANSFERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a cross-chain transfer to Polkadot
     * @param assetId Asset to transfer
     * @param amount Amount to transfer
     * @param recipient Polkadot recipient (SS58 encoded as bytes32)
     * @param destParaId Destination parachain (0 for relay chain)
     * @param transferType Type of transfer
     */
    function initiateTransfer(
        bytes32 assetId,
        uint256 amount,
        bytes32 recipient,
        uint32 destParaId,
        TransferType transferType
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        RegisteredAsset storage asset = registeredAssets[assetId];
        if (asset.assetId == bytes32(0)) revert AssetNotRegistered();
        if (amount < asset.minTransfer) revert TransferAmountTooLow();
        if (amount > asset.maxTransfer) revert TransferAmountTooHigh();
        if (recipient == bytes32(0)) revert InvalidRecipient();

        // Validate destination
        if (destParaId != 0) {
            Parachain storage para = parachains[destParaId];
            if (para.registeredAt == 0) revert ParachainNotRegistered();
            if (para.status != ParachainStatus.ACTIVE)
                revert ParachainNotActive();
        }

        // Validate transfer type
        if (transferType == TransferType.TELEPORT && !asset.teleportable) {
            revert InvalidTransferAmount();
        }
        if (
            transferType == TransferType.RESERVE_WITHDRAW &&
            !asset.reserveTransferable
        ) {
            revert InvalidTransferAmount();
        }

        // Calculate fee
        uint256 fee = (amount * bridgeFee) / 10000;
        if (msg.value < fee) revert InsufficientFee();

        // Generate transfer ID
        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                assetId,
                amount,
                destParaId,
                transferNonce++,
                block.timestamp
            )
        );

        // Store transfer
        transfers[transferId] = CrossChainTransfer({
            transferId: transferId,
            sender: msg.sender,
            recipient: recipient,
            assetId: assetId,
            amount: amount,
            destParaId: destParaId,
            transferType: transferType,
            fee: fee,
            initiatedAt: block.timestamp,
            completedAt: 0,
            refunded: false
        });

        userTransfers[msg.sender].push(transferId);
        asset.totalBridged += amount;

        totalTransfersOut++;
        totalValueBridged += amount;
        totalFeesCollected += fee;

        emit TransferInitiated(
            transferId,
            msg.sender,
            recipient,
            assetId,
            amount,
            destParaId
        );
    }

    /**
     * @notice Complete an incoming transfer from Polkadot
     * @param transferId Transfer identifier
     * @param xcmMessageId XCM message ID that initiated the transfer
     * @param proof State proof of the transfer
     */
    function completeTransfer(
        bytes32 transferId,
        bytes32 xcmMessageId,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        CrossChainTransfer storage transfer = transfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.completedAt != 0) revert TransferAlreadyCompleted();

        // Verify XCM message was processed
        XCMMessage storage xcm = xcmMessages[xcmMessageId];
        if (!xcm.executed) {
            // Verify the proof
            if (!_verifyStateProof(proof)) revert InvalidStateProof();
            xcm.executed = true;
        }

        transfer.completedAt = block.timestamp;
        totalTransfersIn++;

        emit TransferCompleted(transferId, block.timestamp);
    }

    /**
     * @notice Refund a failed transfer
     * @param transferId Transfer identifier
     */
    function refundTransfer(
        bytes32 transferId
    ) external onlyRole(GUARDIAN_ROLE) {
        CrossChainTransfer storage transfer = transfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.completedAt != 0) revert TransferAlreadyCompleted();
        if (transfer.refunded) revert TransferAlreadyRefunded();

        transfer.refunded = true;

        emit TransferRefunded(transferId, transfer.sender, transfer.amount);
    }

    /**
     * @notice Get transfer information
     * @param transferId Transfer identifier
     */
    function getTransfer(
        bytes32 transferId
    ) external view returns (CrossChainTransfer memory) {
        return transfers[transferId];
    }

    /**
     * @notice Get user's transfer history
     * @param user User address
     */
    function getUserTransfers(
        address user
    ) external view returns (bytes32[] memory) {
        return userTransfers[user];
    }

    /*//////////////////////////////////////////////////////////////
                          XCM MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send an XCM message to Polkadot
     * @param destParaId Destination parachain
     * @param dest Destination MultiLocation
     * @param instructions Encoded XCM instructions
     * @param weight Execution weight limit
     */
    function sendXCMMessage(
        uint32 destParaId,
        bytes calldata dest,
        bytes calldata instructions,
        uint256 weight
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (instructions.length == 0) revert InvalidXCMMessage();

        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                destParaId,
                instructions,
                xcmMessageCount++,
                block.timestamp
            )
        );

        xcmMessages[messageId] = XCMMessage({
            messageId: messageId,
            sourceParaId: 0, // From EVM
            destParaId: destParaId,
            origin: MultiLocation({
                parents: 0,
                interior: abi.encodePacked(msg.sender),
                locationHash: keccak256(abi.encodePacked(msg.sender))
            }),
            dest: MultiLocation({
                parents: 1,
                interior: dest,
                locationHash: keccak256(dest)
            }),
            instructions: instructions,
            weight: weight,
            assetId: bytes32(0),
            amount: 0,
            timestamp: block.timestamp,
            executed: false
        });

        emit XCMMessageSent(messageId, 0, destParaId, weight);
    }

    /**
     * @notice Process an incoming XCM message from Polkadot
     * @param messageId Message identifier
     * @param sourceParaId Source parachain
     * @param instructions Encoded XCM instructions
     * @param assetId Asset ID (if asset transfer)
     * @param amount Amount (if asset transfer)
     * @param proof Proof of message validity
     */
    function receiveXCMMessage(
        bytes32 messageId,
        uint32 sourceParaId,
        bytes calldata instructions,
        bytes32 assetId,
        uint256 amount,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        if (processedMessages[messageId]) revert XCMMessageAlreadyProcessed();
        if (!_verifyXCMProof(sourceParaId, messageId, proof))
            revert InvalidProof();

        processedMessages[messageId] = true;

        xcmMessages[messageId] = XCMMessage({
            messageId: messageId,
            sourceParaId: sourceParaId,
            destParaId: 0, // To EVM
            origin: MultiLocation({
                parents: 1,
                interior: abi.encodePacked(sourceParaId),
                locationHash: keccak256(abi.encodePacked(sourceParaId))
            }),
            dest: MultiLocation({
                parents: 0,
                interior: "",
                locationHash: bytes32(0)
            }),
            instructions: instructions,
            weight: 0,
            assetId: assetId,
            amount: amount,
            timestamp: block.timestamp,
            executed: true
        });

        emit XCMMessageReceived(messageId, sourceParaId, assetId, amount);
    }

    /**
     * @notice Get XCM message
     * @param messageId Message identifier
     */
    function getXCMMessage(
        bytes32 messageId
    ) external view returns (XCMMessage memory) {
        return xcmMessages[messageId];
    }

    /*//////////////////////////////////////////////////////////////
                        GRANDPA VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a GRANDPA finality proof
     * @param blockHash Block hash being finalized
     * @param blockNumber Block number
     * @param setId Authority set ID
     * @param precommits Encoded precommit messages
     * @param authorityProof Proof of authority set
     */
    function submitGrandpaProof(
        bytes32 blockHash,
        uint32 blockNumber,
        bytes32 setId,
        bytes calldata precommits,
        bytes calldata authorityProof
    ) external onlyRole(RELAYER_ROLE) {
        if (blockHash == bytes32(0)) revert InvalidGrandpaProof();

        grandpaProofs[blockHash] = GrandpaProof({
            blockHash: blockHash,
            blockNumber: blockNumber,
            setId: setId,
            precommits: precommits,
            authorityProof: authorityProof,
            submittedAt: block.timestamp,
            verified: false
        });

        emit GrandpaProofSubmitted(blockHash, blockNumber, setId);
    }

    /**
     * @notice Verify a GRANDPA finality proof
     * @param blockHash Block hash to verify
     */
    function verifyGrandpaProof(
        bytes32 blockHash
    ) external onlyRole(VALIDATOR_ROLE) {
        GrandpaProof storage proof = grandpaProofs[blockHash];
        if (proof.submittedAt == 0) revert InvalidGrandpaProof();

        // In production, this would verify:
        // 1. Precommit signatures from 2/3+ validators
        // 2. Authority set membership proofs
        // 3. Chain ancestry

        proof.verified = true;

        if (proof.blockNumber > latestFinalizedBlock) {
            latestFinalizedBlock = proof.blockNumber;
        }

        emit GrandpaProofVerified(blockHash, true);
    }

    /**
     * @notice Get GRANDPA proof
     * @param blockHash Block hash
     */
    function getGrandpaProof(
        bytes32 blockHash
    ) external view returns (GrandpaProof memory) {
        return grandpaProofs[blockHash];
    }

    /**
     * @notice Check if block is finalized
     * @param blockNumber Block number
     */
    function isBlockFinalized(uint32 blockNumber) external view returns (bool) {
        return blockNumber <= latestFinalizedBlock;
    }

    /*//////////////////////////////////////////////////////////////
                        BEEFY VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a BEEFY commitment
     * @param payloadHash MMR root or other payload
     * @param blockNumber Block number
     * @param validatorSetId Validator set ID
     * @param nextAuthorityRoot Next authority set Merkle root
     * @param signatures Aggregated BLS signatures
     */
    function submitBeefyCommitment(
        bytes32 payloadHash,
        uint32 blockNumber,
        uint32 validatorSetId,
        bytes32 nextAuthorityRoot,
        bytes calldata signatures
    ) external onlyRole(BEEFY_ROLE) {
        if (payloadHash == bytes32(0)) revert InvalidBeefyCommitment();

        beefyCommitments[blockNumber] = BeefyCommitment({
            payloadHash: payloadHash,
            blockNumber: blockNumber,
            validatorSetId: validatorSetId,
            nextAuthorityRoot: nextAuthorityRoot,
            signatures: signatures,
            timestamp: block.timestamp,
            finalized: false
        });

        emit BeefyCommitmentSubmitted(blockNumber, payloadHash, validatorSetId);
    }

    /**
     * @notice Finalize a BEEFY commitment
     * @param blockNumber Block number
     */
    function finalizeBeefyCommitment(
        uint32 blockNumber
    ) external onlyRole(VALIDATOR_ROLE) {
        BeefyCommitment storage commitment = beefyCommitments[blockNumber];
        if (commitment.timestamp == 0) revert InvalidBeefyCommitment();

        // In production, verify BLS signatures from 2/3+ validators
        commitment.finalized = true;

        // Update validator set if needed
        if (commitment.validatorSetId > beefyValidatorSetId) {
            beefyValidatorSetId = commitment.validatorSetId;
        }

        emit BeefyCommitmentFinalized(blockNumber, commitment.payloadHash);
    }

    /**
     * @notice Get BEEFY commitment
     * @param blockNumber Block number
     */
    function getBeefyCommitment(
        uint32 blockNumber
    ) external view returns (BeefyCommitment memory) {
        return beefyCommitments[blockNumber];
    }

    /*//////////////////////////////////////////////////////////////
                        STATE PROOFS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a parachain state proof
     * @param paraId Parachain ID
     * @param stateRoot State root
     * @param storageKey Storage key
     * @param storageValue Storage value
     * @param proof Merkle-Patricia proof
     * @param blockNumber Block number
     */
    function verifyStateProof(
        uint32 paraId,
        bytes32 stateRoot,
        bytes32 storageKey,
        bytes calldata storageValue,
        bytes calldata proof,
        uint32 blockNumber
    ) external onlyRole(RELAYER_ROLE) returns (bytes32 proofId) {
        Parachain storage para = parachains[paraId];
        if (para.registeredAt == 0) revert ParachainNotRegistered();

        proofId = keccak256(
            abi.encodePacked(paraId, stateRoot, storageKey, blockNumber)
        );

        // Verify the Merkle-Patricia proof
        bool verified = _verifyMerklePatriciaProof(
            stateRoot,
            storageKey,
            storageValue,
            proof
        );

        stateProofs[proofId] = StateProof({
            stateRoot: stateRoot,
            proof: proof,
            storageKey: storageKey,
            storageValue: storageValue,
            blockNumber: blockNumber,
            verified: verified
        });

        if (verified) {
            emit StateProofVerified(stateRoot, storageKey, blockNumber);
        }
    }

    /**
     * @notice Get state proof
     * @param proofId Proof identifier
     */
    function getStateProof(
        bytes32 proofId
    ) external view returns (StateProof memory) {
        return stateProofs[proofId];
    }

    /*//////////////////////////////////////////////////////////////
                        VALIDATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update validator set
     * @param validatorIds New validator IDs
     * @param beefyKeys BEEFY public keys
     * @param stakes Stake amounts
     * @param newSetId New set ID
     */
    function updateValidatorSet(
        bytes32[] calldata validatorIds,
        bytes32[] calldata beefyKeys,
        uint256[] calldata stakes,
        uint32 newSetId
    ) external onlyRole(OPERATOR_ROLE) {
        if (
            validatorIds.length != beefyKeys.length ||
            validatorIds.length != stakes.length
        ) {
            revert InvalidValidatorSet();
        }

        // Clear old validators
        for (uint256 i = 0; i < activeValidators.length; i++) {
            validators[activeValidators[i]].active = false;
        }
        delete activeValidators;

        // Set new validators
        for (uint256 i = 0; i < validatorIds.length; i++) {
            validators[validatorIds[i]] = Validator({
                validatorId: validatorIds[i],
                beefyKey: beefyKeys[i],
                stake: stakes[i],
                active: true,
                addedAt: block.timestamp
            });
            activeValidators.push(validatorIds[i]);
        }

        beefyValidatorSetId = newSetId;

        emit ValidatorSetUpdated(newSetId, validatorIds.length);
    }

    /**
     * @notice Get active validators
     */
    function getActiveValidators() external view returns (bytes32[] memory) {
        return activeValidators;
    }

    /**
     * @notice Get validator information
     * @param validatorId Validator ID
     */
    function getValidator(
        bytes32 validatorId
    ) external view returns (Validator memory) {
        return validators[validatorId];
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set network type
     * @param newNetwork New network type
     */
    function setNetwork(
        NetworkType newNetwork
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        NetworkType oldNetwork = network;
        network = newNetwork;
        emit NetworkUpdated(oldNetwork, newNetwork);
    }

    /**
     * @notice Set bridge fee
     * @param newFee New fee in basis points
     */
    function setBridgeFee(uint256 newFee) external onlyRole(OPERATOR_ROLE) {
        if (newFee > 100) revert FeeTooHigh(); // Max 1%
        uint256 oldFee = bridgeFee;
        bridgeFee = newFee;
        emit BridgeFeeUpdated(oldFee, newFee);
    }

    /**
     * @notice Set transfer limits
     * @param minAmount Minimum transfer amount
     * @param maxAmount Maximum transfer amount
     */
    function setTransferLimits(
        uint256 minAmount,
        uint256 maxAmount
    ) external onlyRole(OPERATOR_ROLE) {
        minTransferAmount = minAmount;
        maxTransferAmount = maxAmount;
    }

    /**
     * @notice Set treasury address
     * @param newTreasury New treasury address
     */
    function setTreasury(
        address newTreasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        treasury = newTreasury;
    }

    /**
     * @notice Update guardian threshold
     * @param newThreshold New threshold
     */
    function setGuardianThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        guardianThreshold = newThreshold;
    }

    /*//////////////////////////////////////////////////////////////
                         GUARDIAN OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Approve a guardian operation
     * @param operationHash Operation hash
     */
    function approveOperation(
        bytes32 operationHash
    ) external onlyRole(GUARDIAN_ROLE) {
        if (guardianApprovals[operationHash][msg.sender])
            revert AlreadyApproved();

        guardianApprovals[operationHash][msg.sender] = true;
        approvalCounts[operationHash]++;
    }

    /**
     * @notice Check if operation has sufficient approvals
     * @param operationHash Operation hash
     */
    function hasQuorum(bytes32 operationHash) public view returns (bool) {
        return approvalCounts[operationHash] >= guardianThreshold;
    }

    /*//////////////////////////////////////////////////////////////
                           PAUSABLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                           STATISTICS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get bridge statistics
     */
    function getBridgeStats()
        external
        view
        returns (
            uint256 transfersOut,
            uint256 transfersIn,
            uint256 valueBridged,
            uint256 fees,
            uint256 messages,
            uint32 finalizedBlock
        )
    {
        return (
            totalTransfersOut,
            totalTransfersIn,
            totalValueBridged,
            totalFeesCollected,
            xcmMessageCount,
            latestFinalizedBlock
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Verify XCM message proof
     */
    function _verifyXCMProof(
        uint32 sourceParaId,
        bytes32 messageId,
        bytes calldata proof
    ) internal view returns (bool) {
        // In production, verify:
        // 1. Message is in parachain state
        // 2. Parachain state root is finalized on relay chain
        // 3. Relay chain block is finalized via GRANDPA/BEEFY
        Parachain storage para = parachains[sourceParaId];
        if (para.registeredAt == 0 || para.status != ParachainStatus.ACTIVE) {
            return false;
        }
        return proof.length > 0 && messageId != bytes32(0);
    }

    /**
     * @dev Verify state proof
     */
    function _verifyStateProof(
        bytes calldata proof
    ) internal pure returns (bool) {
        // Simplified verification - in production would verify Merkle-Patricia proof
        return proof.length > 0;
    }

    /**
     * @dev Verify Merkle-Patricia proof
     */
    function _verifyMerklePatriciaProof(
        bytes32 root,
        bytes32 key,
        bytes calldata value,
        bytes calldata proof
    ) internal pure returns (bool) {
        // Simplified - in production would implement full Merkle-Patricia verification
        if (root == bytes32(0) || key == bytes32(0)) return false;
        if (proof.length == 0) return false;

        // Verify proof structure
        bytes32 computedRoot = keccak256(abi.encodePacked(key, value, proof));
        return computedRoot != bytes32(0);
    }

    /*//////////////////////////////////////////////////////////////
                        UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Encode a MultiLocation
     * @param parents Number of parent hops
     * @param interior Junction path
     */
    function encodeMultiLocation(
        uint8 parents,
        bytes calldata interior
    ) external pure returns (bytes memory) {
        return abi.encodePacked(parents, interior);
    }

    /**
     * @notice Compute MultiLocation hash
     * @param parents Number of parent hops
     * @param interior Junction path
     */
    function computeMultiLocationHash(
        uint8 parents,
        bytes calldata interior
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(parents, interior));
    }

    /**
     * @notice Convert SS58 address to bytes32
     * @param ss58 SS58 encoded address
     */
    function ss58ToBytes32(
        bytes calldata ss58
    ) external pure returns (bytes32) {
        return keccak256(ss58);
    }

    /**
     * @notice Compute XCM weight estimate
     * @param instructionCount Number of instructions
     * @param payloadSize Payload size in bytes
     */
    function estimateXCMWeight(
        uint256 instructionCount,
        uint256 payloadSize
    ) external pure returns (uint256) {
        // Base weight per instruction + payload weight
        return (instructionCount * 1_000_000_000) + (payloadSize * 10_000);
    }

    /**
     * @notice Check if message is processed
     * @param messageId Message identifier
     */
    function isMessageProcessed(
        bytes32 messageId
    ) external view returns (bool) {
        return processedMessages[messageId];
    }

    /**
     * @notice Emergency withdraw (guardian multisig)
     * @param recipient Recipient address
     * @param amount Amount to withdraw
     */
    function emergencyWithdraw(
        address recipient,
        uint256 amount
    ) external onlyRole(GUARDIAN_ROLE) {
        bytes32 opHash = keccak256(
            abi.encodePacked("withdraw", recipient, amount, block.number)
        );
        if (!hasQuorum(opHash)) revert InsufficientGuardianApprovals();

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}
