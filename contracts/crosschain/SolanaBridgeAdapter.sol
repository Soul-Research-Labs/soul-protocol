// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SolanaBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Solana integration via Wormhole/LayerZero
 * @dev Enables cross-chain interoperability between PIL (EVM) and Solana (SVM)
 *
 * SOLANA INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     PIL <-> Solana Bridge                               │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Solana          │                 │
 * │  │  (EVM/Solidity)   │           │   (SVM/Rust)      │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ZK Proofs   │  │◄─────────►│  │ SPL Tokens  │  │                 │
 * │  │  │ Groth16     │  │           │  │ Programs    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Contracts   │  │           │  │ PDAs        │  │                 │
 * │  │  │ ERC20/721   │  │◄─────────►│  │ Accounts    │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Bridge Protocol Layer                            │ │
 * │  │  - Wormhole VAA Verification                                       │ │
 * │  │  - Account/PDA Proof Validation                                    │ │
 * │  │  - SPL Token Mapping                                               │ │
 * │  │  - Cross-Program Invocation (CPI) Validation                       │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SOLANA CONCEPTS:
 * - Program: Executable code on Solana (equivalent to smart contract)
 * - Account: Data storage unit with owner program
 * - PDA: Program Derived Address (deterministic account generation)
 * - SPL Token: Solana Program Library Token standard
 * - Instruction: Operation passed to a program
 * - Transaction: Bundle of instructions with signatures
 * - Slot: Time unit (~400ms) for block production
 * - Epoch: Period of ~2-3 days for staking rewards
 *
 * SUPPORTED FEATURES:
 * - SPL Token Bridging (fungible and NFTs)
 * - Cross-chain Message Passing
 * - Account State Proofs
 * - PDA Verification
 * - Wormhole VAA Processing
 */
contract SolanaBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant VAA_VERIFIER_ROLE = keccak256("VAA_VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Solana account types
    enum AccountType {
        SYSTEM, // Native SOL account
        TOKEN, // SPL Token account
        MINT, // SPL Token mint
        METADATA, // Metaplex metadata
        PROGRAM, // Executable program
        PDA // Program Derived Address
    }

    /// @notice Message direction
    enum MessageDirection {
        EVM_TO_SOLANA,
        SOLANA_TO_EVM
    }

    /// @notice Transfer status
    enum TransferStatus {
        PENDING,
        CONFIRMED,
        COMPLETED,
        FAILED,
        REFUNDED
    }

    /// @notice VAA verification status
    enum VAAStatus {
        UNVERIFIED,
        PENDING,
        VERIFIED,
        EXPIRED,
        INVALID
    }

    /// @notice Solana address (32 bytes)
    struct SolanaAddress {
        bytes32 pubkey;
    }

    /// @notice Solana program info
    struct SolanaProgram {
        bytes32 programId;
        string name;
        bool verified;
        uint256 registeredAt;
    }

    /// @notice PDA derivation info
    struct PDAInfo {
        bytes32 programId;
        bytes[] seeds;
        uint8 bump;
        bytes32 derivedAddress;
        bool verified;
    }

    /// @notice SPL Token info
    struct SPLTokenInfo {
        bytes32 mintAddress;
        uint8 decimals;
        uint256 supply;
        address evmToken; // Mapped EVM token
        bool frozen;
        bool verified;
    }

    /// @notice Cross-chain message
    struct CrossChainMessage {
        bytes32 messageId;
        MessageDirection direction;
        bytes32 sourceAddress; // Solana pubkey or EVM address as bytes32
        bytes32 targetAddress; // Target on destination chain
        bytes payload;
        uint64 solanaSlot; // Slot when sent (Solana) or 0 (EVM)
        uint256 evmBlock; // Block when sent (EVM) or 0 (Solana)
        uint256 timestamp;
        TransferStatus status;
        bytes32 vaaHash; // Wormhole VAA hash
    }

    /// @notice Token transfer request
    struct TokenTransfer {
        bytes32 transferId;
        MessageDirection direction;
        bytes32 sourceToken; // SPL mint or EVM token as bytes32
        bytes32 targetToken; // Target token on destination
        uint256 amount;
        bytes32 sender;
        bytes32 recipient;
        uint256 fee;
        TransferStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Wormhole VAA (Verified Action Approval)
    struct WormholeVAA {
        uint8 version;
        uint32 guardianSetIndex;
        bytes signatures;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        bytes32 hash;
        VAAStatus status;
    }

    /// @notice Account proof for Solana state verification
    struct AccountProof {
        bytes32 accountPubkey;
        bytes32 owner;
        uint64 lamports;
        bytes data;
        bool executable;
        uint64 rentEpoch;
        bytes32 stateRoot;
        bytes proof; // Merkle proof
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Solana chain ID for Wormhole
    uint16 public constant SOLANA_CHAIN_ID = 1;

    /// @notice EVM chain ID for Wormhole (Ethereum mainnet)
    uint16 public constant EVM_CHAIN_ID = 2;

    /// @notice Minimum transfer amount
    uint256 public constant MIN_TRANSFER_AMOUNT = 1000;

    /// @notice Maximum payload size (64KB)
    uint256 public constant MAX_PAYLOAD_SIZE = 65536;

    /// @notice Transfer timeout (24 hours)
    uint256 public constant TRANSFER_TIMEOUT = 24 hours;

    /// @notice Solana slot duration (~400ms)
    uint256 public constant SOLANA_SLOT_DURATION = 400;

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Wormhole core bridge address
    address public wormholeCore;

    /// @notice Wormhole token bridge address
    address public wormholeTokenBridge;

    /// @notice Bridge fee (basis points, max 100 = 1%)
    uint256 public bridgeFee;

    /// @notice Minimum message fee
    uint256 public minMessageFee;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total tokens bridged (in USD value)
    uint256 public totalValueBridged;

    /// @notice Registered Solana programs
    mapping(bytes32 => SolanaProgram) public programs;

    /// @notice PDA derivations
    mapping(bytes32 => PDAInfo) public pdaRegistry;

    /// @notice SPL Token mappings
    mapping(bytes32 => SPLTokenInfo) public splTokens;

    /// @notice EVM to SPL token mapping
    mapping(address => bytes32) public evmToSplToken;

    /// @notice Cross-chain messages
    mapping(bytes32 => CrossChainMessage) public messages;

    /// @notice Token transfers
    mapping(bytes32 => TokenTransfer) public transfers;

    /// @notice VAA registry
    mapping(bytes32 => WormholeVAA) public vaaRegistry;

    /// @notice Used VAA hashes (replay protection)
    mapping(bytes32 => bool) public usedVAAHashes;

    /// @notice Account proofs
    mapping(bytes32 => AccountProof) public accountProofs;

    /// @notice Sender nonces for replay protection
    mapping(address => uint256) public senderNonces;

    /// @notice Whitelisted target programs on Solana
    mapping(bytes32 => bool) public whitelistedPrograms;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event WormholeCoreSet(address indexed core);
    event WormholeTokenBridgeSet(address indexed tokenBridge);
    event BridgeFeeSet(uint256 feeBps);
    event MinMessageFeeSet(uint256 fee);

    event ProgramRegistered(bytes32 indexed programId, string name);
    event ProgramVerified(bytes32 indexed programId);
    event ProgramWhitelisted(bytes32 indexed programId, bool status);

    event PDARegistered(
        bytes32 indexed derivedAddress,
        bytes32 indexed programId,
        uint8 bump
    );
    event PDAVerified(bytes32 indexed derivedAddress);

    event SPLTokenRegistered(
        bytes32 indexed mintAddress,
        address indexed evmToken,
        uint8 decimals
    );
    event SPLTokenVerified(bytes32 indexed mintAddress);
    event TokenMappingSet(address indexed evmToken, bytes32 indexed splMint);

    event MessageSent(
        bytes32 indexed messageId,
        MessageDirection direction,
        bytes32 indexed targetAddress,
        uint256 payloadSize
    );
    event MessageReceived(
        bytes32 indexed messageId,
        bytes32 indexed sourceAddress,
        uint64 solanaSlot
    );
    event MessageCompleted(bytes32 indexed messageId);
    event MessageFailed(bytes32 indexed messageId, string reason);

    event TokenTransferInitiated(
        bytes32 indexed transferId,
        MessageDirection direction,
        bytes32 indexed sourceToken,
        uint256 amount
    );
    event TokenTransferCompleted(
        bytes32 indexed transferId,
        bytes32 indexed recipient,
        uint256 amount
    );
    event TokenTransferRefunded(bytes32 indexed transferId);

    event VAASubmitted(bytes32 indexed vaaHash, uint16 emitterChainId);
    event VAAVerified(bytes32 indexed vaaHash);
    event VAAInvalid(bytes32 indexed vaaHash, string reason);

    event AccountProofSubmitted(bytes32 indexed accountPubkey);
    event AccountProofVerified(bytes32 indexed accountPubkey);

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidWormholeAddress();
    error InvalidProgramId();
    error ProgramAlreadyRegistered();
    error ProgramNotRegistered();
    error ProgramNotWhitelisted();
    error InvalidPDA();
    error PDAAlreadyRegistered();
    error InvalidSPLMint();
    error TokenNotMapped();
    error TokenAlreadyMapped();
    error InvalidAmount();
    error AmountTooSmall();
    error PayloadTooLarge();
    error InsufficientFee();
    error TransferNotFound();
    error TransferAlreadyCompleted();
    error TransferExpired();
    error VAAAlreadyUsed();
    error VAANotFound();
    error VAAExpired();
    error InvalidVAASignatures();
    error InvalidAccountProof();
    error AccountProofExpired();
    error InvalidTargetAddress();
    error MessageNotFound();
    error WithdrawalFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        bridgeFee = 10; // 0.1%
        minMessageFee = 0.001 ether;
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Wormhole core bridge address
     */
    function setWormholeCore(
        address _core
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_core == address(0)) revert InvalidWormholeAddress();
        wormholeCore = _core;
        emit WormholeCoreSet(_core);
    }

    /**
     * @notice Set Wormhole token bridge address
     */
    function setWormholeTokenBridge(
        address _tokenBridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_tokenBridge == address(0)) revert InvalidWormholeAddress();
        wormholeTokenBridge = _tokenBridge;
        emit WormholeTokenBridgeSet(_tokenBridge);
    }

    /**
     * @notice Set bridge fee in basis points
     */
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /**
     * @notice Set minimum message fee
     */
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minMessageFee = _fee;
        emit MinMessageFeeSet(_fee);
    }

    /*//////////////////////////////////////////////////////////////
                        PROGRAM MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a Solana program
     */
    function registerProgram(
        bytes32 programId,
        string calldata name
    ) external onlyRole(OPERATOR_ROLE) {
        if (programId == bytes32(0)) revert InvalidProgramId();
        if (programs[programId].programId != bytes32(0))
            revert ProgramAlreadyRegistered();

        programs[programId] = SolanaProgram({
            programId: programId,
            name: name,
            verified: false,
            registeredAt: block.timestamp
        });

        emit ProgramRegistered(programId, name);
    }

    /**
     * @notice Verify a registered program
     */
    function verifyProgram(
        bytes32 programId
    ) external onlyRole(VAA_VERIFIER_ROLE) {
        if (programs[programId].programId == bytes32(0))
            revert ProgramNotRegistered();
        programs[programId].verified = true;
        emit ProgramVerified(programId);
    }

    /**
     * @notice Whitelist/blacklist a program for transfers
     */
    function setWhitelistedProgram(
        bytes32 programId,
        bool status
    ) external onlyRole(GUARDIAN_ROLE) {
        whitelistedPrograms[programId] = status;
        emit ProgramWhitelisted(programId, status);
    }

    /*//////////////////////////////////////////////////////////////
                           PDA MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a PDA derivation
     */
    function registerPDA(
        bytes32 programId,
        bytes[] calldata seeds,
        uint8 bump,
        bytes32 derivedAddress
    ) external onlyRole(OPERATOR_ROLE) {
        if (programId == bytes32(0)) revert InvalidProgramId();
        if (derivedAddress == bytes32(0)) revert InvalidPDA();
        if (pdaRegistry[derivedAddress].derivedAddress != bytes32(0))
            revert PDAAlreadyRegistered();

        pdaRegistry[derivedAddress] = PDAInfo({
            programId: programId,
            seeds: seeds,
            bump: bump,
            derivedAddress: derivedAddress,
            verified: false
        });

        emit PDARegistered(derivedAddress, programId, bump);
    }

    /**
     * @notice Verify a PDA derivation
     */
    function verifyPDA(
        bytes32 derivedAddress,
        bytes calldata /* proof */
    ) external onlyRole(VAA_VERIFIER_ROLE) returns (bool) {
        PDAInfo storage pda = pdaRegistry[derivedAddress];
        if (pda.derivedAddress == bytes32(0)) revert InvalidPDA();

        // In production, verify the PDA derivation cryptographically
        // For now, mark as verified by trusted verifier
        pda.verified = true;

        emit PDAVerified(derivedAddress);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                         SPL TOKEN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register an SPL token mapping
     */
    function registerSPLToken(
        bytes32 mintAddress,
        uint8 decimals,
        address evmToken
    ) external onlyRole(OPERATOR_ROLE) {
        if (mintAddress == bytes32(0)) revert InvalidSPLMint();
        if (evmToken == address(0)) revert TokenNotMapped();
        if (evmToSplToken[evmToken] != bytes32(0)) revert TokenAlreadyMapped();

        splTokens[mintAddress] = SPLTokenInfo({
            mintAddress: mintAddress,
            decimals: decimals,
            supply: 0,
            evmToken: evmToken,
            frozen: false,
            verified: false
        });

        evmToSplToken[evmToken] = mintAddress;

        emit SPLTokenRegistered(mintAddress, evmToken, decimals);
        emit TokenMappingSet(evmToken, mintAddress);
    }

    /**
     * @notice Verify an SPL token
     */
    function verifySPLToken(
        bytes32 mintAddress
    ) external onlyRole(VAA_VERIFIER_ROLE) {
        if (splTokens[mintAddress].mintAddress == bytes32(0))
            revert InvalidSPLMint();
        splTokens[mintAddress].verified = true;
        emit SPLTokenVerified(mintAddress);
    }

    /*//////////////////////////////////////////////////////////////
                           MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to Solana
     */
    function sendMessageToSolana(
        bytes32 targetProgram,
        bytes32 targetAccount,
        bytes calldata payload
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (payload.length > MAX_PAYLOAD_SIZE) revert PayloadTooLarge();
        if (msg.value < minMessageFee) revert InsufficientFee();
        if (targetProgram == bytes32(0)) revert InvalidTargetAddress();

        // Check if program is whitelisted
        if (!whitelistedPrograms[targetProgram]) revert ProgramNotWhitelisted();

        uint256 nonce = senderNonces[msg.sender]++;

        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                targetProgram,
                targetAccount,
                nonce,
                block.timestamp
            )
        );

        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            direction: MessageDirection.EVM_TO_SOLANA,
            sourceAddress: bytes32(uint256(uint160(msg.sender))),
            targetAddress: targetAccount,
            payload: payload,
            solanaSlot: 0,
            evmBlock: block.number,
            timestamp: block.timestamp,
            status: TransferStatus.PENDING,
            vaaHash: bytes32(0)
        });

        accumulatedFees += msg.value;
        totalMessagesSent++;

        emit MessageSent(
            messageId,
            MessageDirection.EVM_TO_SOLANA,
            targetAccount,
            payload.length
        );
    }

    /**
     * @notice Receive a message from Solana (via Wormhole VAA)
     */
    function receiveMessageFromSolana(
        bytes32 vaaHash,
        bytes32 sourceProgram,
        bytes calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        WormholeVAA storage vaa = vaaRegistry[vaaHash];
        if (vaa.hash == bytes32(0)) revert VAANotFound();
        if (vaa.status != VAAStatus.VERIFIED) revert VAANotFound();
        if (usedVAAHashes[vaaHash]) revert VAAAlreadyUsed();

        usedVAAHashes[vaaHash] = true;

        messageId = keccak256(
            abi.encodePacked(vaaHash, sourceProgram, block.timestamp)
        );

        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            direction: MessageDirection.SOLANA_TO_EVM,
            sourceAddress: sourceProgram,
            targetAddress: bytes32(0), // To be set by processing
            payload: payload,
            solanaSlot: vaa.timestamp, // Using VAA timestamp as slot approximation
            evmBlock: block.number,
            timestamp: block.timestamp,
            status: TransferStatus.CONFIRMED,
            vaaHash: vaaHash
        });

        totalMessagesReceived++;

        emit MessageReceived(messageId, sourceProgram, uint64(vaa.timestamp));
    }

    /**
     * @notice Complete a message
     */
    function completeMessage(
        bytes32 messageId
    ) external onlyRole(RELAYER_ROLE) {
        CrossChainMessage storage message = messages[messageId];
        if (message.messageId == bytes32(0)) revert MessageNotFound();

        message.status = TransferStatus.COMPLETED;
        emit MessageCompleted(messageId);
    }

    /*//////////////////////////////////////////////////////////////
                          TOKEN TRANSFERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a token transfer to Solana
     */
    function transferToSolana(
        address evmToken,
        uint256 amount,
        bytes32 recipientAccount
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        if (amount < MIN_TRANSFER_AMOUNT) revert AmountTooSmall();
        if (msg.value < minMessageFee) revert InsufficientFee();
        if (recipientAccount == bytes32(0)) revert InvalidTargetAddress();

        bytes32 splMint = evmToSplToken[evmToken];
        if (splMint == bytes32(0)) revert TokenNotMapped();

        uint256 fee = (amount * bridgeFee) / 10000;
        uint256 netAmount = amount - fee;

        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                evmToken,
                amount,
                recipientAccount,
                block.timestamp,
                senderNonces[msg.sender]++
            )
        );

        transfers[transferId] = TokenTransfer({
            transferId: transferId,
            direction: MessageDirection.EVM_TO_SOLANA,
            sourceToken: bytes32(uint256(uint160(evmToken))),
            targetToken: splMint,
            amount: netAmount,
            sender: bytes32(uint256(uint160(msg.sender))),
            recipient: recipientAccount,
            fee: fee,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee + msg.value;
        totalValueBridged += amount; // In real implementation, convert to USD

        emit TokenTransferInitiated(
            transferId,
            MessageDirection.EVM_TO_SOLANA,
            bytes32(uint256(uint160(evmToken))),
            amount
        );
    }

    /**
     * @notice Complete a token transfer from Solana
     */
    function completeTransferFromSolana(
        bytes32 transferId,
        bytes32 vaaHash
    ) external onlyRole(RELAYER_ROLE) nonReentrant {
        TokenTransfer storage transfer = transfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.status == TransferStatus.COMPLETED)
            revert TransferAlreadyCompleted();
        if (block.timestamp > transfer.initiatedAt + TRANSFER_TIMEOUT)
            revert TransferExpired();

        WormholeVAA storage vaa = vaaRegistry[vaaHash];
        if (vaa.status != VAAStatus.VERIFIED) revert VAANotFound();
        if (usedVAAHashes[vaaHash]) revert VAAAlreadyUsed();

        usedVAAHashes[vaaHash] = true;
        transfer.status = TransferStatus.COMPLETED;
        transfer.completedAt = block.timestamp;

        emit TokenTransferCompleted(
            transferId,
            transfer.recipient,
            transfer.amount
        );
    }

    /**
     * @notice Refund an expired transfer
     */
    function refundTransfer(bytes32 transferId) external nonReentrant {
        TokenTransfer storage transfer = transfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.status == TransferStatus.COMPLETED)
            revert TransferAlreadyCompleted();
        if (block.timestamp <= transfer.initiatedAt + TRANSFER_TIMEOUT)
            revert TransferNotFound();

        transfer.status = TransferStatus.REFUNDED;

        emit TokenTransferRefunded(transferId);
    }

    /*//////////////////////////////////////////////////////////////
                          VAA MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a Wormhole VAA for verification
     */
    function submitVAA(
        uint8 version,
        uint32 guardianSetIndex,
        bytes calldata signatures,
        uint32 timestamp,
        uint32 nonce,
        uint16 emitterChainId,
        bytes32 emitterAddress,
        uint64 sequence,
        uint8 consistencyLevel,
        bytes calldata payload
    ) external onlyRole(RELAYER_ROLE) returns (bytes32 vaaHash) {
        vaaHash = keccak256(
            abi.encodePacked(
                timestamp,
                nonce,
                emitterChainId,
                emitterAddress,
                sequence,
                consistencyLevel,
                payload
            )
        );

        if (vaaRegistry[vaaHash].hash != bytes32(0)) revert VAAAlreadyUsed();

        vaaRegistry[vaaHash] = WormholeVAA({
            version: version,
            guardianSetIndex: guardianSetIndex,
            signatures: signatures,
            timestamp: timestamp,
            nonce: nonce,
            emitterChainId: emitterChainId,
            emitterAddress: emitterAddress,
            sequence: sequence,
            consistencyLevel: consistencyLevel,
            payload: payload,
            hash: vaaHash,
            status: VAAStatus.PENDING
        });

        emit VAASubmitted(vaaHash, emitterChainId);
    }

    /**
     * @notice Verify a submitted VAA
     */
    function verifyVAA(bytes32 vaaHash) external onlyRole(VAA_VERIFIER_ROLE) {
        WormholeVAA storage vaa = vaaRegistry[vaaHash];
        if (vaa.hash == bytes32(0)) revert VAANotFound();

        // In production, verify guardian signatures
        // For now, trusted verifier marks as verified
        vaa.status = VAAStatus.VERIFIED;

        emit VAAVerified(vaaHash);
    }

    /**
     * @notice Mark a VAA as invalid
     */
    function invalidateVAA(
        bytes32 vaaHash,
        string calldata reason
    ) external onlyRole(GUARDIAN_ROLE) {
        WormholeVAA storage vaa = vaaRegistry[vaaHash];
        if (vaa.hash == bytes32(0)) revert VAANotFound();

        vaa.status = VAAStatus.INVALID;

        emit VAAInvalid(vaaHash, reason);
    }

    /*//////////////////////////////////////////////////////////////
                        ACCOUNT PROOFS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an account proof from Solana
     */
    function submitAccountProof(
        bytes32 accountPubkey,
        bytes32 owner,
        uint64 lamports,
        bytes calldata data,
        bool executable,
        uint64 rentEpoch,
        bytes32 stateRoot,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) {
        accountProofs[accountPubkey] = AccountProof({
            accountPubkey: accountPubkey,
            owner: owner,
            lamports: lamports,
            data: data,
            executable: executable,
            rentEpoch: rentEpoch,
            stateRoot: stateRoot,
            proof: proof,
            verified: false
        });

        emit AccountProofSubmitted(accountPubkey);
    }

    /**
     * @notice Verify an account proof
     */
    function verifyAccountProof(
        bytes32 accountPubkey
    ) external onlyRole(VAA_VERIFIER_ROLE) returns (bool) {
        AccountProof storage accountProof = accountProofs[accountPubkey];
        if (accountProof.accountPubkey == bytes32(0))
            revert InvalidAccountProof();

        // In production, verify the Merkle proof against state root
        accountProof.verified = true;

        emit AccountProofVerified(accountPubkey);
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
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
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Withdraw accumulated fees
     */
    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert WithdrawalFailed();

        emit FeesWithdrawn(recipient, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get bridge statistics
     */
    function getBridgeStats()
        external
        view
        returns (
            uint256 messagesSent,
            uint256 messagesReceived,
            uint256 totalBridged,
            uint256 fees
        )
    {
        return (
            totalMessagesSent,
            totalMessagesReceived,
            totalValueBridged,
            accumulatedFees
        );
    }

    /**
     * @notice Check if a program is whitelisted
     */
    function isProgramWhitelisted(
        bytes32 programId
    ) external view returns (bool) {
        return whitelistedPrograms[programId];
    }

    /**
     * @notice Check if a VAA has been used
     */
    function isVAAUsed(bytes32 vaaHash) external view returns (bool) {
        return usedVAAHashes[vaaHash];
    }

    /**
     * @notice Get SPL token info
     */
    function getSPLTokenInfo(
        bytes32 mintAddress
    ) external view returns (SPLTokenInfo memory) {
        return splTokens[mintAddress];
    }

    /**
     * @notice Get transfer details
     */
    function getTransfer(
        bytes32 transferId
    ) external view returns (TokenTransfer memory) {
        return transfers[transferId];
    }

    /**
     * @notice Get message details
     */
    function getMessage(
        bytes32 messageId
    ) external view returns (CrossChainMessage memory) {
        return messages[messageId];
    }

    /**
     * @notice Get sender nonce
     */
    function getSenderNonce(address sender) external view returns (uint256) {
        return senderNonces[sender];
    }
}
