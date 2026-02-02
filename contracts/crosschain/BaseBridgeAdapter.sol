// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title BaseBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Base L2 integration (Coinbase's OP Stack chain)
 * @dev Enables cross-chain interoperability with Base using the OP Stack CrossDomainMessenger
 *
 * BASE INTEGRATION:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    Soul <-> Base Bridge                                  │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   Soul Protocol    │           │   Base            │                 │
 * │  │  (L1 Ethereum)    │           │   (L2 OP Stack)   │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ L1 Cross    │  │           │  │ L2 Cross    │  │                 │
 * │  │  │ Domain      │  │──────────►│  │ Domain      │  │                 │
 * │  │  │ Messenger   │  │           │  │ Messenger   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Base        │  │◄──────────│  │ L2 to L1   │  │                 │
 * │  │  │ Portal      │  │           │  │ Messages   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Base (OP Stack) Architecture                     │ │
 * │  │  - OP Stack based Optimistic Rollup                                │ │
 * │  │  - 7-Day Withdrawal Period                                          │ │
 * │  │  - CrossDomainMessenger for L1<->L2 messaging                       │ │
 * │  │  - Native USDC support via CCTP                                     │ │
 * │  │  - Coinbase ecosystem integration                                   │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * BASE CONCEPTS:
 * - OP Stack: Same architecture as Optimism with Bedrock upgrade
 * - CrossDomainMessenger: Native L1<->L2 messaging
 * - BasePortal: L1 contract for deposits and withdrawals
 * - CCTP: Circle's Cross-Chain Transfer Protocol for native USDC
 * - Coinbase Verifications: On-chain attestations for compliance
 */
contract BaseBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CCTP_ROLE = keccak256("CCTP_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Base Mainnet chain ID
    uint256 public constant BASE_MAINNET_CHAIN_ID = 8453;

    /// @notice Base Sepolia chain ID
    uint256 public constant BASE_SEPOLIA_CHAIN_ID = 84532;

    /// @notice Ethereum Mainnet chain ID
    uint256 public constant ETH_MAINNET_CHAIN_ID = 1;

    /// @notice Ethereum Sepolia chain ID
    uint256 public constant ETH_SEPOLIA_CHAIN_ID = 11155111;

    /// @notice Withdrawal period in seconds (~7 days)
    uint256 public constant WITHDRAWAL_PERIOD = 604800;

    /// @notice Default L2 gas limit
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 1000000;

    /// @notice Minimum gas limit for cross-domain messages
    uint256 public constant MIN_GAS_LIMIT = 100000;

    /// @notice CCTP domain for Ethereum
    uint32 public constant CCTP_ETH_DOMAIN = 0;

    /// @notice CCTP domain for Base
    uint32 public constant CCTP_BASE_DOMAIN = 6;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageType {
        PROOF_RELAY,
        STATE_SYNC,
        NULLIFIER_CHECK,
        BATCH_VERIFY,
        USDC_TRANSFER,
        ATTESTATION_SYNC,
        EMERGENCY
    }

    enum MessageStatus {
        PENDING,
        SENT,
        CONFIRMED,
        FAILED,
        WITHDRAWN
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Cross-domain message structure
    struct CrossDomainMessage {
        bytes32 messageId;
        MessageType messageType;
        bytes payload;
        uint256 sourceChainId;
        uint256 targetChainId;
        address sender;
        address target;
        uint256 value;
        uint256 gasLimit;
        uint256 timestamp;
        MessageStatus status;
    }

    /// @notice Proof relay request
    struct ProofRelayRequest {
        bytes32 proofHash;
        bytes proof;
        bytes publicInputs;
        bytes32 stateRoot;
        uint256 nonce;
        uint256 deadline;
    }

    /// @notice Withdrawal request for L2->L1
    struct WithdrawalRequest {
        bytes32 withdrawalId;
        address user;
        bytes32 proofHash;
        uint256 amount;
        uint256 requestedAt;
        uint256 completableAt;
        bool completed;
    }

    /// @notice CCTP USDC transfer
    struct CCTPTransfer {
        bytes32 transferId;
        address sender;
        address recipient;
        uint256 amount;
        uint32 sourceDomain;
        uint32 destDomain;
        uint64 nonce;
        bool completed;
    }

    /// @notice Coinbase attestation sync
    struct AttestationSync {
        bytes32 attestationId;
        address subject;
        bytes32 schemaId;
        bytes data;
        uint256 timestamp;
        bool synced;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice L1 CrossDomainMessenger address
    address public l1CrossDomainMessenger;

    /// @notice L2 CrossDomainMessenger address
    address public l2CrossDomainMessenger;

    /// @notice BasePortal address (L1)
    address public basePortal;

    /// @notice L2 target contract (Soul adapter on Base)
    address public l2Target;

    /// @notice CCTP TokenMessenger address
    address public cctpTokenMessenger;

    /// @notice USDC token address
    address public usdcToken;

    /// @notice Message nonce
    uint256 public messageNonce;

    /// @notice CCTP nonce
    uint64 public cctpNonce;

    /// @notice Whether this adapter is on L1 or L2
    bool public immutable isL1;

    /// @notice Mapping of message ID to message
    mapping(bytes32 => CrossDomainMessage) public messages;

    /// @notice Mapping of withdrawal ID to withdrawal request
    mapping(bytes32 => WithdrawalRequest) public withdrawals;

    /// @notice Pending proof relays
    mapping(bytes32 => ProofRelayRequest) public pendingProofRelays;

    /// @notice Relayed proofs
    mapping(bytes32 => bool) public relayedProofs;

    /// @notice CCTP transfers
    mapping(bytes32 => CCTPTransfer) public cctpTransfers;

    /// @notice Synced attestations
    mapping(bytes32 => AttestationSync) public attestations;

    /// @notice Confirmed state roots
    mapping(bytes32 => uint256) public confirmedStateRoots;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (ETH)
    uint256 public totalValueBridged;

    /// @notice Total USDC bridged via CCTP
    uint256 public totalUSDCBridged;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageId,
        MessageType messageType,
        address indexed sender,
        address indexed target,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageId,
        MessageType messageType,
        address indexed sender,
        uint256 value
    );

    event ProofRelayed(
        bytes32 indexed proofHash,
        uint256 sourceChainId,
        uint256 targetChainId,
        address relayer
    );

    event WithdrawalInitiated(
        bytes32 indexed withdrawalId,
        address indexed user,
        bytes32 proofHash,
        uint256 completableAt
    );

    event WithdrawalCompleted(
        bytes32 indexed withdrawalId,
        address indexed user,
        uint256 amount
    );

    event CCTPTransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        address indexed recipient,
        uint256 amount,
        uint32 destDomain
    );

    event CCTPTransferCompleted(bytes32 indexed transferId, uint256 amount);

    event AttestationSynced(
        bytes32 indexed attestationId,
        address indexed subject,
        bytes32 schemaId
    );

    event StateRootConfirmed(bytes32 indexed stateRoot, uint256 blockNumber);

    event L2TargetUpdated(address indexed oldTarget, address indexed newTarget);

    event MessengerUpdated(address indexed messenger, bool isL1Messenger);

    event CCTPConfigured(
        address indexed tokenMessenger,
        address indexed usdcToken
    );

    /*//////////////////////////////////////////////////////////////
                              ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidChainId();
    error InvalidMessenger();
    error InvalidTarget();
    error MessageNotFound();
    error MessageAlreadyProcessed();
    error ProofAlreadyRelayed();
    error WithdrawalNotReady();
    error WithdrawalAlreadyCompleted();
    error InsufficientGasLimit();
    error UnauthorizedCaller();
    error InvalidProof();
    error DeadlineExpired();
    error CCTPNotConfigured();
    error InvalidAmount();
    error TransferAlreadyCompleted();
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _admin,
        address _l1CrossDomainMessenger,
        address _l2CrossDomainMessenger,
        address _basePortal,
        bool _isL1
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        l1CrossDomainMessenger = _l1CrossDomainMessenger;
        l2CrossDomainMessenger = _l2CrossDomainMessenger;
        basePortal = _basePortal;
        isL1 = _isL1;
    }

    /*//////////////////////////////////////////////////////////////
                          EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a proof relay message to Base L2
     * @param proofHash Hash of the proof to relay
     * @param proof The actual proof data
     * @param publicInputs Public inputs for the proof
     * @param gasLimit Gas limit for L2 execution
     * @return messageId The ID of the sent message
     */
    function sendProofToL2(
        bytes32 proofHash,
        bytes calldata proof,
        bytes calldata publicInputs,
        uint256 gasLimit
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageId)
    {
        if (!isL1) revert InvalidChainId();
        if (gasLimit < MIN_GAS_LIMIT) revert InsufficientGasLimit();
        if (l2Target == address(0)) revert InvalidTarget();

        messageId = _generateMessageId(
            MessageType.PROOF_RELAY,
            msg.sender,
            l2Target
        );

        // Create proof relay payload
        bytes memory payload = abi.encodeWithSelector(
            this.receiveProofFromL1.selector,
            proofHash,
            proof,
            publicInputs,
            block.chainid
        );

        // Store message
        messages[messageId] = CrossDomainMessage({
            messageId: messageId,
            messageType: MessageType.PROOF_RELAY,
            payload: payload,
            sourceChainId: block.chainid,
            targetChainId: BASE_MAINNET_CHAIN_ID,
            sender: msg.sender,
            target: l2Target,
            value: msg.value,
            gasLimit: gasLimit,
            timestamp: block.timestamp,
            status: MessageStatus.SENT
        });

        // Store pending proof relay
        pendingProofRelays[proofHash] = ProofRelayRequest({
            proofHash: proofHash,
            proof: proof,
            publicInputs: publicInputs,
            stateRoot: bytes32(0),
            nonce: messageNonce,
            deadline: block.timestamp + 1 hours
        });

        messageNonce++;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageId,
            MessageType.PROOF_RELAY,
            msg.sender,
            l2Target,
            msg.value
        );

        emit ProofRelayed(
            proofHash,
            block.chainid,
            BASE_MAINNET_CHAIN_ID,
            msg.sender
        );

        // In production, this would call the CrossDomainMessenger
        // ICrossDomainMessenger(l1CrossDomainMessenger).sendMessage{value: msg.value}(
        //     l2Target,
        //     payload,
        //     uint32(gasLimit)
        // );
    }

    /**
     * @notice Receive a proof from L1 (called by CrossDomainMessenger)
     * @param proofHash Hash of the relayed proof
     * @param proof The proof data
     * @param publicInputs Public inputs
     * @param sourceChainId Source chain ID
     */
    function receiveProofFromL1(
        bytes32 proofHash,
        bytes calldata proof,
        bytes calldata publicInputs,
        uint256 sourceChainId
    ) external whenNotPaused {
        // Verify caller is the messenger
        // In production: require(msg.sender == l2CrossDomainMessenger)

        if (relayedProofs[proofHash]) revert ProofAlreadyRelayed();

        relayedProofs[proofHash] = true;
        totalMessagesReceived++;

        bytes32 messageId = keccak256(
            abi.encodePacked(proofHash, sourceChainId, block.timestamp)
        );

        // Silence unused variable warnings
        proof;
        publicInputs;

        emit MessageReceived(messageId, MessageType.PROOF_RELAY, msg.sender, 0);

        emit ProofRelayed(proofHash, sourceChainId, block.chainid, msg.sender);
    }

    /**
     * @notice Initiate USDC transfer via CCTP
     * @param recipient Recipient address on destination chain
     * @param amount Amount of USDC to transfer
     * @param destDomain Destination CCTP domain
     * @return transferId The transfer ID
     */
    function initiateUSDCTransfer(
        address recipient,
        uint256 amount,
        uint32 destDomain
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(CCTP_ROLE)
        returns (bytes32 transferId)
    {
        if (cctpTokenMessenger == address(0)) revert CCTPNotConfigured();
        if (amount == 0) revert InvalidAmount();

        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                amount,
                destDomain,
                cctpNonce
            )
        );

        cctpTransfers[transferId] = CCTPTransfer({
            transferId: transferId,
            sender: msg.sender,
            recipient: recipient,
            amount: amount,
            sourceDomain: isL1 ? CCTP_ETH_DOMAIN : CCTP_BASE_DOMAIN,
            destDomain: destDomain,
            nonce: cctpNonce,
            completed: false
        });

        cctpNonce++;
        totalUSDCBridged += amount;

        emit CCTPTransferInitiated(
            transferId,
            msg.sender,
            recipient,
            amount,
            destDomain
        );

        // In production, this would:
        // 1. Transfer USDC from sender to this contract
        // 2. Approve USDC to TokenMessenger
        // 3. Call TokenMessenger.depositForBurn()
    }

    /**
     * @notice Complete CCTP transfer (receive USDC from other chain)
     * @param transferId Transfer ID
     * @param message CCTP message bytes
     * @param attestation Circle attestation
     */
    function completeCCTPTransfer(
        bytes32 transferId,
        bytes calldata message,
        bytes calldata attestation
    ) external nonReentrant whenNotPaused {
        CCTPTransfer storage transfer = cctpTransfers[transferId];
        if (transfer.completed) revert TransferAlreadyCompleted();

        transfer.completed = true;

        // Silence unused variable warnings
        message;
        attestation;

        emit CCTPTransferCompleted(transferId, transfer.amount);

        // In production, this would call MessageTransmitter.receiveMessage()
    }

    /**
     * @notice Sync Coinbase attestation from L1 to L2
     * @param attestationId Attestation ID
     * @param subject Subject of the attestation
     * @param schemaId Schema ID
     * @param data Attestation data
     */
    function syncAttestation(
        bytes32 attestationId,
        address subject,
        bytes32 schemaId,
        bytes calldata data
    ) external nonReentrant whenNotPaused onlyRole(OPERATOR_ROLE) {
        attestations[attestationId] = AttestationSync({
            attestationId: attestationId,
            subject: subject,
            schemaId: schemaId,
            data: data,
            timestamp: block.timestamp,
            synced: true
        });

        emit AttestationSynced(attestationId, subject, schemaId);
    }

    /**
     * @notice Initiate a withdrawal from L2 to L1
     * @param proofHash Proof hash associated with the withdrawal
     * @return withdrawalId The withdrawal ID
     */
    function initiateWithdrawal(
        bytes32 proofHash
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 withdrawalId)
    {
        if (isL1) revert InvalidChainId();

        withdrawalId = keccak256(
            abi.encodePacked(
                msg.sender,
                proofHash,
                block.timestamp,
                messageNonce++
            )
        );

        withdrawals[withdrawalId] = WithdrawalRequest({
            withdrawalId: withdrawalId,
            user: msg.sender,
            proofHash: proofHash,
            amount: msg.value,
            requestedAt: block.timestamp,
            completableAt: block.timestamp + WITHDRAWAL_PERIOD,
            completed: false
        });

        emit WithdrawalInitiated(
            withdrawalId,
            msg.sender,
            proofHash,
            block.timestamp + WITHDRAWAL_PERIOD
        );
    }

    /**
     * @notice Complete a withdrawal on L1 (after challenge period)
     * @param withdrawalId The withdrawal ID to complete
     */
    function completeWithdrawal(
        bytes32 withdrawalId
    ) external nonReentrant whenNotPaused {
        if (!isL1) revert InvalidChainId();

        WithdrawalRequest storage withdrawal = withdrawals[withdrawalId];
        if (withdrawal.user == address(0)) revert MessageNotFound();
        if (withdrawal.completed) revert WithdrawalAlreadyCompleted();
        if (block.timestamp < withdrawal.completableAt)
            revert WithdrawalNotReady();

        withdrawal.completed = true;

        (bool success, ) = withdrawal.user.call{value: withdrawal.amount}("");
        if (!success) revert TransferFailed();

        emit WithdrawalCompleted(
            withdrawalId,
            withdrawal.user,
            withdrawal.amount
        );
    }

    /**
     * @notice Send state sync message to L2
     * @param stateRoot State root to sync
     * @param blockNumber Associated block number
     * @param gasLimit Gas limit for L2 execution
     */
    function syncStateToL2(
        bytes32 stateRoot,
        uint256 blockNumber,
        uint256 gasLimit
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageId)
    {
        if (!isL1) revert InvalidChainId();
        if (gasLimit < MIN_GAS_LIMIT) revert InsufficientGasLimit();

        messageId = _generateMessageId(
            MessageType.STATE_SYNC,
            msg.sender,
            l2Target
        );

        bytes memory payload = abi.encodeWithSelector(
            this.receiveStateFromL1.selector,
            stateRoot,
            blockNumber
        );

        messages[messageId] = CrossDomainMessage({
            messageId: messageId,
            messageType: MessageType.STATE_SYNC,
            payload: payload,
            sourceChainId: block.chainid,
            targetChainId: BASE_MAINNET_CHAIN_ID,
            sender: msg.sender,
            target: l2Target,
            value: 0,
            gasLimit: gasLimit,
            timestamp: block.timestamp,
            status: MessageStatus.SENT
        });

        totalMessagesSent++;

        emit MessageSent(
            messageId,
            MessageType.STATE_SYNC,
            msg.sender,
            l2Target,
            0
        );
    }

    /**
     * @notice Receive state from L1
     * @param stateRoot The state root
     * @param blockNumber The block number
     */
    function receiveStateFromL1(
        bytes32 stateRoot,
        uint256 blockNumber
    ) external whenNotPaused {
        confirmedStateRoots[stateRoot] = blockNumber;
        totalMessagesReceived++;

        emit StateRootConfirmed(stateRoot, blockNumber);
    }

    /**
     * @notice Check if a proof has been relayed
     */
    function isProofRelayed(bytes32 proofHash) external view returns (bool) {
        return relayedProofs[proofHash];
    }

    /**
     * @notice Get attestation details
     */
    function getAttestation(
        bytes32 attestationId
    ) external view returns (AttestationSync memory) {
        return attestations[attestationId];
    }

    /**
     * @notice Check if subject has a specific attestation
     */
    function hasAttestation(
        address /* subject */,
        bytes32 /* schemaId */
    ) external pure returns (bool) {
        // Would iterate through attestations in production
        // Simplified for now
        return false;
    }

    /**
     * @notice Get adapter statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 messagesSent,
            uint256 messagesReceived,
            uint256 valueBridged,
            uint256 usdcBridged,
            uint256 currentNonce
        )
    {
        return (
            totalMessagesSent,
            totalMessagesReceived,
            totalValueBridged,
            totalUSDCBridged,
            messageNonce
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update L2 target address
     */
    function setL2Target(
        address _l2Target
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address oldTarget = l2Target;
        l2Target = _l2Target;
        emit L2TargetUpdated(oldTarget, _l2Target);
    }

    /**
     * @notice Configure CCTP integration
     */
    function configureCCTP(
        address _tokenMessenger,
        address _usdcToken
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        cctpTokenMessenger = _tokenMessenger;
        usdcToken = _usdcToken;
        emit CCTPConfigured(_tokenMessenger, _usdcToken);
    }

    /**
     * @notice Update messenger addresses
     */
    function setMessenger(
        address _messenger,
        bool _isL1Messenger
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_isL1Messenger) {
            l1CrossDomainMessenger = _messenger;
        } else {
            l2CrossDomainMessenger = _messenger;
        }
        emit MessengerUpdated(_messenger, _isL1Messenger);
    }

    /**
     * @notice Pause the adapter
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the adapter
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /**
     * @notice Emergency withdraw stuck funds
     */
    function emergencyWithdraw(
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool success, ) = to.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _generateMessageId(
        MessageType messageType,
        address sender,
        address target
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    messageType,
                    sender,
                    target,
                    block.chainid,
                    messageNonce,
                    block.timestamp
                )
            );
    }

    receive() external payable {}
}
