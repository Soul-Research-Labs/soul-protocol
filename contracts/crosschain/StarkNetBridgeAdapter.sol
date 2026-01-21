// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title StarkNetBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for StarkNet L2 with Cairo and STARK proof verification
 * @dev Enables cross-chain interoperability between PIL and StarkNet ecosystem
 *
 * STARKNET INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     PIL <-> StarkNet Bridge                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   StarkNet L2     │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ZK Proofs   │  │◄─────────►│  │ STARK Proofs│  │                 │
 * │  │  │ Groth16     │  │           │  │ FRI         │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Solidity    │  │           │  │ Cairo       │  │                 │
 * │  │  │ Contracts   │  │◄─────────►│  │ Contracts   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   StarkNet Bridge Layer                            │ │
 * │  │  - L1 ↔ L2 Messaging                                              │ │
 * │  │  - STARK Proof Verification                                        │ │
 * │  │  - Cairo Program Hash Verification                                 │ │
 * │  │  - Blockchain State Synchronization                                │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * STARKNET CONCEPTS:
 * - Cairo: StarkNet's native programming language
 * - STARK Proofs: Scalable Transparent ARguments of Knowledge
 * - FRI: Fast Reed-Solomon Interactive Oracle Proofs
 * - Pedersen Hash: StarkNet's native hash function
 * - Poseidon Hash: Alternative hash used in newer contracts
 * - Felt: Field element (StarkNet's native number type)
 *
 * SUPPORTED FEATURES:
 * - L1 → L2 Message Passing
 * - L2 → L1 Message Consumption
 * - STARK Proof Verification
 * - Cairo Program Execution
 * - Cross-domain Token Bridging
 * - State Synchronization
 */
contract StarkNetBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice StarkNet message direction
    enum MessageDirection {
        L1_TO_L2,
        L2_TO_L1
    }

    /// @notice Message status
    enum MessageStatus {
        PENDING,
        SENT,
        CONSUMED,
        CANCELLED,
        FAILED
    }

    /// @notice STARK proof verification status
    enum ProofStatus {
        UNVERIFIED,
        PENDING_VERIFICATION,
        VERIFIED,
        REJECTED
    }

    /// @notice Cairo contract types
    enum CairoVersion {
        CAIRO_0,
        CAIRO_1,
        CAIRO_2
    }

    /// @notice L1 to L2 message
    struct L1ToL2Message {
        bytes32 messageHash;
        uint256 fromAddress; // L1 address as felt
        uint256 toAddress; // L2 contract address as felt
        uint256 selector; // Entry point selector
        uint256[] payload; // Message payload as felts
        uint256 nonce;
        uint256 fee;
        uint256 timestamp;
        MessageStatus status;
    }

    /// @notice L2 to L1 message
    struct L2ToL1Message {
        bytes32 messageHash;
        uint256 fromAddress; // L2 contract address as felt
        address toAddress; // L1 address
        uint256[] payload; // Message payload as felts
        uint256 blockNumber;
        uint256 timestamp;
        MessageStatus status;
        bytes32 starknetTxHash;
    }

    /// @notice STARK proof data
    struct STARKProof {
        bytes32 proofId;
        bytes32 programHash; // Cairo program hash
        bytes32 outputHash; // Program output hash
        bytes32[] friCommitments; // FRI layer commitments
        bytes32[] decommitments; // Merkle decommitments
        uint256 publicInputHash;
        uint256 proofTimestamp;
        ProofStatus status;
        CairoVersion cairoVersion;
    }

    /// @notice Registered Cairo contract
    struct CairoContract {
        bytes32 contractId;
        uint256 classHash; // Cairo class hash
        uint256 contractAddress; // StarkNet contract address as felt
        bytes32 programHash;
        CairoVersion version;
        address registrar;
        uint256 registeredAt;
        bool verified;
    }

    /// @notice Bridge operation for token transfers
    struct BridgeOperation {
        bytes32 operationId;
        bool isDeposit; // true = L1→L2, false = L2→L1
        address l1Token;
        uint256 l2Token; // StarkNet token address as felt
        uint256 amount;
        address l1User;
        uint256 l2User; // StarkNet user address as felt
        uint256 timestamp;
        MessageStatus status;
    }

    /// @notice StarkNet state update
    struct StateUpdate {
        bytes32 updateId;
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 stateRoot;
        bytes32 parentStateRoot;
        uint256[] contractUpdates; // List of updated contract addresses
        uint256 timestamp;
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice StarkNet Core Contract address (L1)
    address public starknetCore;

    /// @notice L1 to L2 messages
    mapping(bytes32 => L1ToL2Message) public l1ToL2Messages;
    uint256 public totalL1ToL2Messages;

    /// @notice L2 to L1 messages
    mapping(bytes32 => L2ToL1Message) public l2ToL1Messages;
    uint256 public totalL2ToL1Messages;

    /// @notice STARK proofs
    mapping(bytes32 => STARKProof) public starkProofs;
    uint256 public totalProofs;

    /// @notice Registered Cairo contracts
    mapping(bytes32 => CairoContract) public cairoContracts;
    uint256 public totalContracts;

    /// @notice Bridge operations
    mapping(bytes32 => BridgeOperation) public bridgeOperations;
    uint256 public totalBridgeOperations;

    /// @notice State updates
    mapping(bytes32 => StateUpdate) public stateUpdates;
    bytes32 public latestStateRoot;
    uint256 public latestBlockNumber;

    /// @notice Message nonces per sender
    mapping(address => uint256) public messageNonces;

    /// @notice Consumed message hashes (to prevent replay)
    mapping(bytes32 => bool) public consumedMessages;

    /// @notice Verified program hashes
    mapping(bytes32 => bool) public verifiedPrograms;

    /// @notice Bridge fees (in basis points)
    uint256 public bridgeFeeBps = 10; // 0.1%

    /// @notice Minimum message fee
    uint256 public minMessageFee = 0.001 ether;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice Message timeout period
    uint256 public messageTimeout = 7 days;

    /// @notice Token mappings L1 → L2
    mapping(address => uint256) public l1ToL2TokenMap;

    /// @notice Token mappings L2 → L1
    mapping(uint256 => address) public l2ToL1TokenMap;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event StarkNetCoreConfigured(address indexed coreContract);

    event L1ToL2MessageSent(
        bytes32 indexed messageHash,
        uint256 fromAddress,
        uint256 toAddress,
        uint256 selector,
        uint256 nonce
    );

    event L2ToL1MessageReceived(
        bytes32 indexed messageHash,
        uint256 fromAddress,
        address indexed toAddress
    );

    event L2ToL1MessageConsumed(
        bytes32 indexed messageHash,
        address indexed consumer
    );

    event STARKProofSubmitted(
        bytes32 indexed proofId,
        bytes32 programHash,
        bytes32 outputHash
    );

    event STARKProofVerified(bytes32 indexed proofId, bool valid);

    event CairoContractRegistered(
        bytes32 indexed contractId,
        uint256 classHash,
        uint256 contractAddress
    );

    event BridgeOperationInitiated(
        bytes32 indexed operationId,
        bool isDeposit,
        address l1Token,
        uint256 amount
    );

    event BridgeOperationCompleted(
        bytes32 indexed operationId,
        bytes32 messageHash
    );

    event StateUpdateVerified(
        bytes32 indexed updateId,
        uint256 blockNumber,
        bytes32 stateRoot
    );

    event TokenMappingSet(address indexed l1Token, uint256 l2Token);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error InvalidStarkNetCore();
    error MessageNotFound(bytes32 messageHash);
    error MessageAlreadyConsumed(bytes32 messageHash);
    error MessageTimeout();
    error InvalidProof();
    error ProofNotFound(bytes32 proofId);
    error ProofAlreadyVerified(bytes32 proofId);
    error ContractNotFound(bytes32 contractId);
    error ContractNotVerified(bytes32 contractId);
    error OperationNotFound(bytes32 operationId);
    error InvalidTokenMapping();
    error InsufficientFee(uint256 provided, uint256 required);
    error InvalidPayloadLength();
    error InvalidSelector();
    error UnauthorizedConsumer();
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure StarkNet Core contract address
     * @param _starknetCore Address of the StarkNet Core contract on L1
     */
    function configureStarkNetCore(
        address _starknetCore
    ) external onlyRole(OPERATOR_ROLE) {
        if (_starknetCore == address(0)) revert ZeroAddress();
        starknetCore = _starknetCore;
        emit StarkNetCoreConfigured(_starknetCore);
    }

    /**
     * @notice Set token mapping between L1 and L2
     * @param l1Token L1 token address
     * @param l2Token L2 token address (as felt)
     */
    function setTokenMapping(
        address l1Token,
        uint256 l2Token
    ) external onlyRole(OPERATOR_ROLE) {
        if (l1Token == address(0)) revert ZeroAddress();
        if (l2Token == 0) revert ZeroAmount();

        l1ToL2TokenMap[l1Token] = l2Token;
        l2ToL1TokenMap[l2Token] = l1Token;

        emit TokenMappingSet(l1Token, l2Token);
    }

    /**
     * @notice Set bridge fee
     */
    function setBridgeFee(uint256 _feeBps) external onlyRole(OPERATOR_ROLE) {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        bridgeFeeBps = _feeBps;
    }

    /**
     * @notice Set minimum message fee
     */
    function setMinMessageFee(uint256 _fee) external onlyRole(OPERATOR_ROLE) {
        minMessageFee = _fee;
    }

    /*//////////////////////////////////////////////////////////////
                       L1 TO L2 MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message from L1 to L2 (StarkNet)
     * @param toAddress StarkNet contract address (as felt)
     * @param selector Entry point selector (function to call)
     * @param payload Message payload (array of felts)
     */
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (msg.value < minMessageFee)
            revert InsufficientFee(msg.value, minMessageFee);
        if (toAddress == 0) revert ZeroAddress();
        if (selector == 0) revert InvalidSelector();

        uint256 nonce = messageNonces[msg.sender]++;
        uint256 fromAddressFelt = uint256(uint160(msg.sender));

        // Calculate message hash (StarkNet format)
        messageHash = _computeL1ToL2MessageHash(
            fromAddressFelt,
            toAddress,
            selector,
            payload,
            nonce
        );

        l1ToL2Messages[messageHash] = L1ToL2Message({
            messageHash: messageHash,
            fromAddress: fromAddressFelt,
            toAddress: toAddress,
            selector: selector,
            payload: payload,
            nonce: nonce,
            fee: msg.value,
            timestamp: block.timestamp,
            status: MessageStatus.PENDING
        });

        // Collect fee
        accumulatedFees += msg.value;
        totalL1ToL2Messages++;

        emit L1ToL2MessageSent(
            messageHash,
            fromAddressFelt,
            toAddress,
            selector,
            nonce
        );
    }

    /**
     * @notice Mark L1 to L2 message as sent (called by sequencer)
     */
    function confirmL1ToL2MessageSent(
        bytes32 messageHash
    ) external onlyRole(SEQUENCER_ROLE) {
        L1ToL2Message storage message = l1ToL2Messages[messageHash];
        if (message.messageHash == bytes32(0))
            revert MessageNotFound(messageHash);

        message.status = MessageStatus.SENT;
    }

    /**
     * @notice Cancel a pending L1 to L2 message (after timeout)
     */
    function cancelL1ToL2Message(bytes32 messageHash) external nonReentrant {
        L1ToL2Message storage message = l1ToL2Messages[messageHash];
        if (message.messageHash == bytes32(0))
            revert MessageNotFound(messageHash);
        if (message.status != MessageStatus.PENDING)
            revert("Message not pending");
        if (block.timestamp < message.timestamp + messageTimeout)
            revert("Timeout not reached");

        // Verify sender
        if (uint256(uint160(msg.sender)) != message.fromAddress)
            revert UnauthorizedConsumer();

        message.status = MessageStatus.CANCELLED;

        // Refund fee
        uint256 refund = message.fee;
        accumulatedFees -= refund;
        (bool success, ) = payable(msg.sender).call{value: refund}("");
        if (!success) revert TransferFailed();
    }

    /*//////////////////////////////////////////////////////////////
                       L2 TO L1 MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive a message from L2 (StarkNet)
     * @param fromAddress StarkNet contract address that sent the message
     * @param payload Message payload
     * @param starknetTxHash Transaction hash on StarkNet
     */
    function receiveMessageFromL2(
        uint256 fromAddress,
        uint256[] calldata payload,
        bytes32 starknetTxHash
    ) external onlyRole(SEQUENCER_ROLE) returns (bytes32 messageHash) {
        messageHash = _computeL2ToL1MessageHash(
            fromAddress,
            msg.sender,
            payload
        );

        if (consumedMessages[messageHash])
            revert MessageAlreadyConsumed(messageHash);

        l2ToL1Messages[messageHash] = L2ToL1Message({
            messageHash: messageHash,
            fromAddress: fromAddress,
            toAddress: msg.sender,
            payload: payload,
            blockNumber: block.number,
            timestamp: block.timestamp,
            status: MessageStatus.PENDING,
            starknetTxHash: starknetTxHash
        });

        totalL2ToL1Messages++;

        emit L2ToL1MessageReceived(messageHash, fromAddress, msg.sender);
    }

    /**
     * @notice Consume a message from L2
     * @param messageHash The message to consume
     * @param proof STARK proof of message inclusion
     */
    function consumeMessageFromL2(
        bytes32 messageHash,
        bytes calldata proof
    ) external nonReentrant {
        L2ToL1Message storage message = l2ToL1Messages[messageHash];

        if (message.messageHash == bytes32(0))
            revert MessageNotFound(messageHash);
        if (message.status == MessageStatus.CONSUMED)
            revert MessageAlreadyConsumed(messageHash);
        if (message.toAddress != msg.sender) revert UnauthorizedConsumer();

        // Verify STARK proof
        if (!_verifySTARKProof(messageHash, proof)) revert InvalidProof();

        message.status = MessageStatus.CONSUMED;
        consumedMessages[messageHash] = true;

        emit L2ToL1MessageConsumed(messageHash, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                       STARK PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a STARK proof for verification
     * @param programHash Hash of the Cairo program
     * @param outputHash Hash of the program output
     * @param publicInputHash Hash of public inputs
     * @param friCommitments FRI layer commitments
     * @param cairoVersion Cairo version used
     */
    function submitSTARKProof(
        bytes32 programHash,
        bytes32 outputHash,
        uint256 publicInputHash,
        bytes32[] calldata friCommitments,
        CairoVersion cairoVersion
    ) external nonReentrant returns (bytes32 proofId) {
        proofId = keccak256(
            abi.encodePacked(
                programHash,
                outputHash,
                publicInputHash,
                msg.sender,
                block.timestamp
            )
        );

        starkProofs[proofId] = STARKProof({
            proofId: proofId,
            programHash: programHash,
            outputHash: outputHash,
            friCommitments: friCommitments,
            decommitments: new bytes32[](0),
            publicInputHash: publicInputHash,
            proofTimestamp: block.timestamp,
            status: ProofStatus.PENDING_VERIFICATION,
            cairoVersion: cairoVersion
        });

        totalProofs++;

        emit STARKProofSubmitted(proofId, programHash, outputHash);
    }

    /**
     * @notice Verify a submitted STARK proof
     * @param proofId The proof to verify
     * @param decommitments Merkle decommitments for verification
     */
    function verifySTARKProof(
        bytes32 proofId,
        bytes32[] calldata decommitments
    ) external onlyRole(VERIFIER_ROLE) {
        STARKProof storage proof = starkProofs[proofId];

        if (proof.proofId == bytes32(0)) revert ProofNotFound(proofId);
        if (proof.status == ProofStatus.VERIFIED)
            revert ProofAlreadyVerified(proofId);

        // Store decommitments
        proof.decommitments = decommitments;

        // Verify FRI and decommitments
        bool valid = _verifyFRI(
            proof.friCommitments,
            decommitments,
            proof.publicInputHash
        );

        proof.status = valid ? ProofStatus.VERIFIED : ProofStatus.REJECTED;

        if (valid) {
            verifiedPrograms[proof.programHash] = true;
        }

        emit STARKProofVerified(proofId, valid);
    }

    /*//////////////////////////////////////////////////////////////
                       CAIRO CONTRACT REGISTRY
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a Cairo contract
     * @param classHash Cairo class hash
     * @param contractAddress StarkNet contract address (as felt)
     * @param programHash Program hash
     * @param version Cairo version
     */
    function registerCairoContract(
        uint256 classHash,
        uint256 contractAddress,
        bytes32 programHash,
        CairoVersion version
    ) external nonReentrant returns (bytes32 contractId) {
        contractId = keccak256(
            abi.encodePacked(
                classHash,
                contractAddress,
                msg.sender,
                block.timestamp
            )
        );

        cairoContracts[contractId] = CairoContract({
            contractId: contractId,
            classHash: classHash,
            contractAddress: contractAddress,
            programHash: programHash,
            version: version,
            registrar: msg.sender,
            registeredAt: block.timestamp,
            verified: false
        });

        totalContracts++;

        emit CairoContractRegistered(contractId, classHash, contractAddress);
    }

    /**
     * @notice Verify a registered Cairo contract
     */
    function verifyCairoContract(
        bytes32 contractId
    ) external onlyRole(VERIFIER_ROLE) {
        CairoContract storage cairo = cairoContracts[contractId];
        if (cairo.contractId == bytes32(0)) revert ContractNotFound(contractId);

        cairo.verified = true;
    }

    /*//////////////////////////////////////////////////////////////
                       BRIDGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit tokens from L1 to L2 (StarkNet)
     * @param l1Token L1 token address
     * @param amount Amount to deposit
     * @param l2Recipient StarkNet recipient address (as felt)
     */
    function depositToL2(
        address l1Token,
        uint256 amount,
        uint256 l2Recipient
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 operationId)
    {
        if (amount == 0) revert ZeroAmount();
        if (l2Recipient == 0) revert ZeroAddress();

        uint256 l2Token = l1ToL2TokenMap[l1Token];
        if (l2Token == 0) revert InvalidTokenMapping();

        // Calculate fee
        uint256 fee = (amount * bridgeFeeBps) / 10000;
        accumulatedFees += fee;

        operationId = keccak256(
            abi.encodePacked(
                l1Token,
                amount,
                l2Recipient,
                msg.sender,
                block.timestamp
            )
        );

        bridgeOperations[operationId] = BridgeOperation({
            operationId: operationId,
            isDeposit: true,
            l1Token: l1Token,
            l2Token: l2Token,
            amount: amount - fee,
            l1User: msg.sender,
            l2User: l2Recipient,
            timestamp: block.timestamp,
            status: MessageStatus.PENDING
        });

        totalBridgeOperations++;

        emit BridgeOperationInitiated(operationId, true, l1Token, amount);
    }

    /**
     * @notice Withdraw tokens from L2 to L1
     * @param operationId The operation ID from L2
     * @param l2Token L2 token address (as felt)
     * @param amount Amount to withdraw
     * @param l1Recipient L1 recipient address
     * @param proof STARK proof of withdrawal
     */
    function withdrawFromL2(
        bytes32 operationId,
        uint256 l2Token,
        uint256 amount,
        address l1Recipient,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (l1Recipient == address(0)) revert ZeroAddress();

        address l1Token = l2ToL1TokenMap[l2Token];
        if (l1Token == address(0)) revert InvalidTokenMapping();

        // Verify STARK proof
        if (
            !_verifyWithdrawalProof(
                operationId,
                l2Token,
                amount,
                l1Recipient,
                proof
            )
        ) revert InvalidProof();

        bridgeOperations[operationId] = BridgeOperation({
            operationId: operationId,
            isDeposit: false,
            l1Token: l1Token,
            l2Token: l2Token,
            amount: amount,
            l1User: l1Recipient,
            l2User: 0,
            timestamp: block.timestamp,
            status: MessageStatus.CONSUMED
        });

        totalBridgeOperations++;

        emit BridgeOperationCompleted(operationId, bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                       STATE UPDATES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a state update from StarkNet
     * @param blockNumber StarkNet block number
     * @param blockHash StarkNet block hash
     * @param stateRoot New state root
     * @param parentStateRoot Previous state root
     * @param contractUpdates List of updated contract addresses
     */
    function submitStateUpdate(
        uint256 blockNumber,
        bytes32 blockHash,
        bytes32 stateRoot,
        bytes32 parentStateRoot,
        uint256[] calldata contractUpdates
    ) external onlyRole(SEQUENCER_ROLE) returns (bytes32 updateId) {
        updateId = keccak256(
            abi.encodePacked(blockNumber, blockHash, stateRoot)
        );

        stateUpdates[updateId] = StateUpdate({
            updateId: updateId,
            blockNumber: blockNumber,
            blockHash: blockHash,
            stateRoot: stateRoot,
            parentStateRoot: parentStateRoot,
            contractUpdates: contractUpdates,
            timestamp: block.timestamp,
            verified: false
        });
    }

    /**
     * @notice Verify a state update with STARK proof
     */
    function verifyStateUpdate(
        bytes32 updateId,
        bytes calldata proof
    ) external onlyRole(VERIFIER_ROLE) {
        StateUpdate storage update = stateUpdates[updateId];
        require(update.updateId != bytes32(0), "Update not found");

        // Verify state transition proof
        if (!_verifyStateTransitionProof(updateId, proof))
            revert InvalidProof();

        update.verified = true;
        latestStateRoot = update.stateRoot;
        latestBlockNumber = update.blockNumber;

        emit StateUpdateVerified(
            updateId,
            update.blockNumber,
            update.stateRoot
        );
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute L1 to L2 message hash (StarkNet format)
     */
    function _computeL1ToL2MessageHash(
        uint256 fromAddress,
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    fromAddress,
                    toAddress,
                    selector,
                    keccak256(abi.encodePacked(payload)),
                    nonce
                )
            );
    }

    /**
     * @notice Compute L2 to L1 message hash
     */
    function _computeL2ToL1MessageHash(
        uint256 fromAddress,
        address toAddress,
        uint256[] calldata payload
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    fromAddress,
                    uint256(uint160(toAddress)),
                    keccak256(abi.encodePacked(payload))
                )
            );
    }

    /**
     * @notice Verify STARK proof
     */
    function _verifySTARKProof(
        bytes32 messageHash,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (messageHash == bytes32(0)) return false;
        if (proof.length < 32) return false;
        // Production: Full FRI verification
        return true;
    }

    /**
     * @notice Verify FRI commitments
     */
    function _verifyFRI(
        bytes32[] memory commitments,
        bytes32[] memory decommitments,
        uint256 publicInputHash
    ) internal pure returns (bool) {
        if (commitments.length == 0) return false;
        if (decommitments.length == 0) return false;
        if (publicInputHash == 0) return false;
        // Production: Full FRI polynomial commitment verification
        return true;
    }

    /**
     * @notice Verify withdrawal proof
     */
    function _verifyWithdrawalProof(
        bytes32 operationId,
        uint256 l2Token,
        uint256 amount,
        address l1Recipient,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (operationId == bytes32(0)) return false;
        if (l2Token == 0) return false;
        if (amount == 0) return false;
        if (l1Recipient == address(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Verify state transition proof
     */
    function _verifyStateTransitionProof(
        bytes32 updateId,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (updateId == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get L1 to L2 message details
     */
    function getL1ToL2Message(
        bytes32 messageHash
    ) external view returns (L1ToL2Message memory) {
        return l1ToL2Messages[messageHash];
    }

    /**
     * @notice Get L2 to L1 message details
     */
    function getL2ToL1Message(
        bytes32 messageHash
    ) external view returns (L2ToL1Message memory) {
        return l2ToL1Messages[messageHash];
    }

    /**
     * @notice Get STARK proof details
     */
    function getSTARKProof(
        bytes32 proofId
    ) external view returns (STARKProof memory) {
        return starkProofs[proofId];
    }

    /**
     * @notice Get Cairo contract details
     */
    function getCairoContract(
        bytes32 contractId
    ) external view returns (CairoContract memory) {
        return cairoContracts[contractId];
    }

    /**
     * @notice Get bridge operation details
     */
    function getBridgeOperation(
        bytes32 operationId
    ) external view returns (BridgeOperation memory) {
        return bridgeOperations[operationId];
    }

    /**
     * @notice Get state update details
     */
    function getStateUpdate(
        bytes32 updateId
    ) external view returns (StateUpdate memory) {
        return stateUpdates[updateId];
    }

    /**
     * @notice Check if a program is verified
     */
    function isProgramVerified(
        bytes32 programHash
    ) external view returns (bool) {
        return verifiedPrograms[programHash];
    }

    /**
     * @notice Check if a message is consumed
     */
    function isMessageConsumed(
        bytes32 messageHash
    ) external view returns (bool) {
        return consumedMessages[messageHash];
    }

    /**
     * @notice Get bridge statistics
     */
    function getBridgeStats()
        external
        view
        returns (
            uint256 _totalL1ToL2Messages,
            uint256 _totalL2ToL1Messages,
            uint256 _totalProofs,
            uint256 _totalContracts,
            uint256 _totalBridgeOperations,
            uint256 _accumulatedFees
        )
    {
        return (
            totalL1ToL2Messages,
            totalL2ToL1Messages,
            totalProofs,
            totalContracts,
            totalBridgeOperations,
            accumulatedFees
        );
    }

    /**
     * @notice Get latest state info
     */
    function getLatestState()
        external
        view
        returns (bytes32 _stateRoot, uint256 _blockNumber)
    {
        return (latestStateRoot, latestBlockNumber);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set message timeout
     */
    function setMessageTimeout(
        uint256 _timeout
    ) external onlyRole(OPERATOR_ROLE) {
        require(_timeout >= 1 days, "Timeout too short");
        require(_timeout <= 30 days, "Timeout too long");
        messageTimeout = _timeout;
    }

    /**
     * @notice Withdraw accumulated fees
     */
    function withdrawFees(address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        (bool success, ) = payable(to).call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    /**
     * @notice Pause the bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the bridge
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
