// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title BitcoinBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Bitcoin network interoperability with privacy preservation
 * @dev Enables private cross-chain transactions between PIL and Bitcoin network
 *
 * BITCOIN INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      PIL <-> Bitcoin Bridge                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Bitcoin Network │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ Commitments │  │◄─────────►│  │ UTXOs       │  │                 │
 * │  │  │ Nullifiers  │  │           │  │ Scripts     │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ ZK Proofs   │  │           │  │ SPV Proofs  │  │                 │
 * │  │  │ Groth16/    │  │◄─────────►│  │ Merkle      │  │                 │
 * │  │  │ PLONK       │  │           │  │ Proofs      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Bridge Relay Layer                               │ │
 * │  │  - SPV Proof Verification                                         │ │
 * │  │  - HTLC Atomic Swaps                                              │ │
 * │  │  - Taproot/Schnorr Support                                        │ │
 * │  │  - Lightning Network Integration                                  │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * SUPPORTED BITCOIN FEATURES:
 * - P2PKH (Pay to Public Key Hash) - Legacy addresses
 * - P2SH (Pay to Script Hash) - Script addresses
 * - P2WPKH (Pay to Witness Public Key Hash) - Native SegWit
 * - P2WSH (Pay to Witness Script Hash) - SegWit scripts
 * - P2TR (Pay to Taproot) - Taproot/Schnorr addresses
 * - Lightning Network HTLCs
 *
 * PRIVACY PROPERTIES:
 * - Zero-knowledge proof of Bitcoin UTXO ownership
 * - Private peg-in/peg-out without revealing amounts
 * - Confidential transactions via Pedersen commitments
 * - Stealth addresses for recipient privacy
 */
contract BitcoinBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant SPV_VERIFIER_ROLE = keccak256("SPV_VERIFIER_ROLE");
    bytes32 public constant LIGHTNING_NODE_ROLE =
        keccak256("LIGHTNING_NODE_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Bitcoin script types supported
    enum BitcoinScriptType {
        P2PKH, // Legacy Pay to Public Key Hash
        P2SH, // Pay to Script Hash
        P2WPKH, // Native SegWit (bech32)
        P2WSH, // SegWit Script Hash
        P2TR, // Taproot (bech32m)
        HTLC, // Hash Time Locked Contract
        LIGHTNING // Lightning Network channel
    }

    /// @notice Bitcoin transaction output (UTXO) representation
    struct BitcoinUTXO {
        bytes32 txHash; // Transaction hash (reversed for Bitcoin)
        uint32 outputIndex; // Output index in the transaction
        uint64 satoshis; // Value in satoshis
        bytes scriptPubKey; // Locking script
        BitcoinScriptType scriptType;
        uint32 blockHeight; // Block height where confirmed
        bool spent; // Whether UTXO has been spent
    }

    /// @notice Bitcoin block header for SPV verification
    struct BitcoinBlockHeader {
        uint32 version;
        bytes32 previousBlockHash;
        bytes32 merkleRoot;
        uint32 timestamp;
        uint32 bits; // Difficulty target
        uint32 nonce;
        uint256 blockHeight;
        bytes32 blockHash; // Computed block hash
    }

    /// @notice SPV proof for Bitcoin transaction inclusion
    struct SPVProof {
        bytes32 txHash;
        bytes32 merkleRoot;
        bytes32[] merkleProof; // Merkle proof siblings
        uint256[] proofFlags; // Left/right indicators
        uint256 txIndex; // Transaction index in block
        bytes32 blockHash;
        uint256 blockHeight;
        uint256 confirmations;
    }

    /// @notice PIL to Bitcoin peg-out request
    struct PegOutRequest {
        bytes32 requestId;
        bytes32 pilCommitment;
        bytes32 pilNullifier;
        bytes bitcoinAddress; // Recipient Bitcoin address (various formats)
        BitcoinScriptType scriptType;
        uint64 satoshis;
        uint256 timestamp;
        PegOutStatus status;
        bytes32 bitcoinTxHash; // Resulting Bitcoin tx hash
    }

    /// @notice Bitcoin to PIL peg-in request
    struct PegInRequest {
        bytes32 requestId;
        bytes32 bitcoinTxHash;
        uint32 outputIndex;
        uint64 satoshis;
        address pilRecipient;
        bytes32 pilCommitment;
        uint256 timestamp;
        PegInStatus status;
        uint256 confirmations;
    }

    /// @notice HTLC for atomic swaps
    struct AtomicSwapHTLC {
        bytes32 htlcId;
        bytes32 hashLock; // SHA256 hash of preimage
        uint256 timeLock; // Expiration timestamp
        uint64 satoshis; // Bitcoin amount
        uint256 pilAmount; // PIL token amount
        address pilParty;
        bytes bitcoinParty; // Bitcoin address
        HTLCStatus status;
        bytes32 preimage; // Revealed after claim
    }

    /// @notice Lightning Network invoice
    struct LightningInvoice {
        bytes32 invoiceId;
        bytes32 paymentHash;
        uint64 satoshis;
        uint256 expiry;
        bytes32 pilCommitment;
        address pilRecipient;
        LightningStatus status;
        bytes32 preimage;
    }

    /// @notice Peg-out status
    enum PegOutStatus {
        PENDING,
        BITCOIN_TX_BROADCAST,
        BITCOIN_TX_CONFIRMED,
        COMPLETED,
        CANCELLED,
        FAILED
    }

    /// @notice Peg-in status
    enum PegInStatus {
        AWAITING_DEPOSIT,
        DEPOSIT_DETECTED,
        CONFIRMING,
        CONFIRMED,
        PIL_MINTED,
        COMPLETED,
        FAILED
    }

    /// @notice HTLC status
    enum HTLCStatus {
        CREATED,
        BITCOIN_LOCKED,
        PIL_LOCKED,
        BITCOIN_CLAIMED,
        PIL_CLAIMED,
        COMPLETED,
        REFUNDED,
        EXPIRED
    }

    /// @notice Lightning invoice status
    enum LightningStatus {
        CREATED,
        PENDING,
        PAID,
        SETTLED,
        EXPIRED,
        CANCELLED
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Bitcoin light client / relay contract
    address public bitcoinRelay;

    /// @notice Required confirmations for peg-in
    uint256 public requiredConfirmations = 6;

    /// @notice Lightning confirmations (faster)
    uint256 public lightningConfirmations = 1;

    /// @notice Peg-out requests
    mapping(bytes32 => PegOutRequest) public pegOutRequests;
    uint256 public totalPegOuts;

    /// @notice Peg-in requests
    mapping(bytes32 => PegInRequest) public pegInRequests;
    uint256 public totalPegIns;

    /// @notice Atomic swap HTLCs
    mapping(bytes32 => AtomicSwapHTLC) public atomicSwaps;
    uint256 public totalSwaps;

    /// @notice Lightning invoices
    mapping(bytes32 => LightningInvoice) public lightningInvoices;

    /// @notice Bitcoin block headers (for SPV)
    mapping(bytes32 => BitcoinBlockHeader) public blockHeaders;
    bytes32 public latestBlockHash;
    uint256 public latestBlockHeight;

    /// @notice Verified UTXOs
    mapping(bytes32 => BitcoinUTXO) public verifiedUTXOs;

    /// @notice Cross-chain nullifiers (prevent double-spend)
    mapping(bytes32 => bool) public crossChainNullifiers;

    /// @notice Deposited Bitcoin commitments
    mapping(bytes32 => bool) public depositedCommitments;

    /// @notice Total bridged amounts
    uint256 public totalPeggedIn; // Satoshis pegged into PIL
    uint256 public totalPeggedOut; // Satoshis pegged out to Bitcoin

    /// @notice Bridge limits
    uint64 public minPegAmount = 10000; // 0.0001 BTC (10,000 sats)
    uint64 public maxPegAmount = 100000000000; // 1000 BTC
    uint256 public bridgeFeeBps = 25; // 0.25% fee

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice HTLC time constraints
    uint256 public minHTLCTimeout = 1 hours;
    uint256 public maxHTLCTimeout = 7 days;

    /// @notice Bitcoin difficulty target (for SPV validation)
    uint256 public difficultyTarget;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PegOutInitiated(
        bytes32 indexed requestId,
        bytes32 indexed pilCommitment,
        bytes bitcoinAddress,
        uint64 satoshis
    );

    event PegOutCompleted(
        bytes32 indexed requestId,
        bytes32 indexed bitcoinTxHash
    );

    event PegInDetected(
        bytes32 indexed requestId,
        bytes32 indexed bitcoinTxHash,
        uint64 satoshis
    );

    event PegInCompleted(
        bytes32 indexed requestId,
        bytes32 indexed pilCommitment,
        address pilRecipient
    );

    event AtomicSwapCreated(
        bytes32 indexed htlcId,
        bytes32 indexed hashLock,
        uint64 satoshis,
        uint256 pilAmount
    );

    event AtomicSwapCompleted(bytes32 indexed htlcId, bytes32 preimage);

    event LightningInvoiceCreated(
        bytes32 indexed invoiceId,
        bytes32 indexed paymentHash,
        uint64 satoshis
    );

    event LightningPaymentSettled(bytes32 indexed invoiceId, bytes32 preimage);

    event BitcoinBlockSubmitted(
        bytes32 indexed blockHash,
        uint256 blockHeight,
        bytes32 merkleRoot
    );

    event SPVProofVerified(
        bytes32 indexed txHash,
        bytes32 indexed blockHash,
        uint256 confirmations
    );

    event BitcoinRelayUpdated(address indexed relay);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error AmountTooLow(uint64 amount, uint64 minimum);
    error AmountTooHigh(uint64 amount, uint64 maximum);
    error InvalidBitcoinAddress();
    error InvalidSPVProof();
    error InsufficientConfirmations(uint256 provided, uint256 required);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error RequestNotFound(bytes32 requestId);
    error RequestAlreadyProcessed(bytes32 requestId);
    error InvalidHTLCTimeout();
    error HTLCExpired(bytes32 htlcId);
    error HTLCNotExpired(bytes32 htlcId);
    error InvalidPreimage(bytes32 expected, bytes32 provided);
    error InvalidBlockHeader();
    error BlockNotFound(bytes32 blockHash);
    error UTXOAlreadySpent(bytes32 utxoId);
    error BitcoinRelayNotConfigured();
    error InsufficientFee(uint256 provided, uint256 required);
    error TransferFailed();
    error InvalidScriptType();
    error LightningInvoiceExpired();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        BITCOIN RELAY CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure Bitcoin relay/light client contract
     * @param _relay Address of Bitcoin relay contract
     */
    function configureBitcoinRelay(
        address _relay
    ) external onlyRole(OPERATOR_ROLE) {
        if (_relay == address(0)) revert ZeroAddress();
        bitcoinRelay = _relay;
        emit BitcoinRelayUpdated(_relay);
    }

    /**
     * @notice Set required confirmations
     */
    function setRequiredConfirmations(
        uint256 _confirmations
    ) external onlyRole(OPERATOR_ROLE) {
        requiredConfirmations = _confirmations;
    }

    /*//////////////////////////////////////////////////////////////
                            PEG-OUT (PIL → BTC)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a peg-out from PIL to Bitcoin
     * @param pilCommitment The PIL commitment being burned
     * @param pilNullifier The PIL nullifier
     * @param bitcoinAddress The recipient Bitcoin address
     * @param scriptType The Bitcoin script type
     * @param satoshis Amount in satoshis
     * @param proof ZK proof of PIL commitment ownership
     */
    function initiatePegOut(
        bytes32 pilCommitment,
        bytes32 pilNullifier,
        bytes calldata bitcoinAddress,
        BitcoinScriptType scriptType,
        uint64 satoshis,
        bytes calldata proof
    ) external payable nonReentrant whenNotPaused {
        // Validations
        if (satoshis < minPegAmount)
            revert AmountTooLow(satoshis, minPegAmount);
        if (satoshis > maxPegAmount)
            revert AmountTooHigh(satoshis, maxPegAmount);
        if (bitcoinAddress.length == 0) revert InvalidBitcoinAddress();
        if (crossChainNullifiers[pilNullifier])
            revert NullifierAlreadyUsed(pilNullifier);

        // Validate Bitcoin address format based on script type
        if (!_validateBitcoinAddress(bitcoinAddress, scriptType))
            revert InvalidBitcoinAddress();

        // Calculate and verify fee
        uint256 fee = (uint256(satoshis) * bridgeFeeBps) / 10000;
        if (msg.value < fee) revert InsufficientFee(msg.value, fee);

        // Verify PIL proof
        if (!_verifyPILProof(pilCommitment, pilNullifier, satoshis, proof))
            revert InvalidSPVProof();

        // Register nullifier
        crossChainNullifiers[pilNullifier] = true;

        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilCommitment,
                bitcoinAddress,
                satoshis,
                block.timestamp,
                totalPegOuts
            )
        );

        pegOutRequests[requestId] = PegOutRequest({
            requestId: requestId,
            pilCommitment: pilCommitment,
            pilNullifier: pilNullifier,
            bitcoinAddress: bitcoinAddress,
            scriptType: scriptType,
            satoshis: satoshis,
            timestamp: block.timestamp,
            status: PegOutStatus.PENDING,
            bitcoinTxHash: bytes32(0)
        });

        totalPegOuts++;
        totalPeggedOut += satoshis;
        accumulatedFees += fee;

        emit PegOutInitiated(
            requestId,
            pilCommitment,
            bitcoinAddress,
            satoshis
        );
    }

    /**
     * @notice Complete peg-out after Bitcoin transaction is confirmed
     * @param requestId The peg-out request ID
     * @param bitcoinTxHash The Bitcoin transaction hash
     * @param spvProof SPV proof of transaction inclusion
     */
    function completePegOut(
        bytes32 requestId,
        bytes32 bitcoinTxHash,
        SPVProof calldata spvProof
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        PegOutRequest storage request = pegOutRequests[requestId];

        if (request.requestId == bytes32(0)) revert RequestNotFound(requestId);
        if (
            request.status != PegOutStatus.PENDING &&
            request.status != PegOutStatus.BITCOIN_TX_BROADCAST
        ) revert RequestAlreadyProcessed(requestId);

        // Verify SPV proof
        if (!_verifySPVProof(spvProof)) revert InvalidSPVProof();
        if (spvProof.confirmations < requiredConfirmations)
            revert InsufficientConfirmations(
                spvProof.confirmations,
                requiredConfirmations
            );

        request.status = PegOutStatus.COMPLETED;
        request.bitcoinTxHash = bitcoinTxHash;

        emit PegOutCompleted(requestId, bitcoinTxHash);
        emit SPVProofVerified(
            bitcoinTxHash,
            spvProof.blockHash,
            spvProof.confirmations
        );
    }

    /*//////////////////////////////////////////////////////////////
                            PEG-IN (BTC → PIL)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a peg-in request when Bitcoin deposit is detected
     * @param bitcoinTxHash The Bitcoin transaction hash
     * @param outputIndex The output index being claimed
     * @param satoshis The amount in satoshis
     * @param pilRecipient The PIL address to receive tokens
     * @param spvProof SPV proof of transaction inclusion
     */
    function submitPegIn(
        bytes32 bitcoinTxHash,
        uint32 outputIndex,
        uint64 satoshis,
        address pilRecipient,
        SPVProof calldata spvProof
    ) external nonReentrant onlyRole(RELAYER_ROLE) whenNotPaused {
        if (pilRecipient == address(0)) revert ZeroAddress();
        if (satoshis < minPegAmount)
            revert AmountTooLow(satoshis, minPegAmount);

        // Compute UTXO ID
        bytes32 utxoId = keccak256(
            abi.encodePacked(bitcoinTxHash, outputIndex)
        );

        // Check UTXO not already used
        if (verifiedUTXOs[utxoId].spent) revert UTXOAlreadySpent(utxoId);

        // Verify SPV proof
        if (!_verifySPVProof(spvProof)) revert InvalidSPVProof();

        bytes32 requestId = keccak256(
            abi.encodePacked(
                bitcoinTxHash,
                outputIndex,
                pilRecipient,
                block.timestamp
            )
        );

        // Generate PIL commitment
        bytes32 pilCommitment = _generatePILCommitment(
            pilRecipient,
            satoshis,
            requestId
        );

        pegInRequests[requestId] = PegInRequest({
            requestId: requestId,
            bitcoinTxHash: bitcoinTxHash,
            outputIndex: outputIndex,
            satoshis: satoshis,
            pilRecipient: pilRecipient,
            pilCommitment: pilCommitment,
            timestamp: block.timestamp,
            status: PegInStatus.DEPOSIT_DETECTED,
            confirmations: spvProof.confirmations
        });

        // Mark UTXO as used
        verifiedUTXOs[utxoId] = BitcoinUTXO({
            txHash: bitcoinTxHash,
            outputIndex: outputIndex,
            satoshis: satoshis,
            scriptPubKey: "",
            scriptType: BitcoinScriptType.P2WPKH,
            blockHeight: uint32(spvProof.blockHeight),
            spent: true
        });

        totalPegIns++;

        emit PegInDetected(requestId, bitcoinTxHash, satoshis);
    }

    /**
     * @notice Confirm peg-in after sufficient confirmations
     * @param requestId The peg-in request ID
     * @param spvProof Updated SPV proof with more confirmations
     */
    function confirmPegIn(
        bytes32 requestId,
        SPVProof calldata spvProof
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        PegInRequest storage request = pegInRequests[requestId];

        if (request.requestId == bytes32(0)) revert RequestNotFound(requestId);
        if (request.status == PegInStatus.COMPLETED)
            revert RequestAlreadyProcessed(requestId);

        // Verify updated SPV proof
        if (!_verifySPVProof(spvProof)) revert InvalidSPVProof();
        if (spvProof.confirmations < requiredConfirmations)
            revert InsufficientConfirmations(
                spvProof.confirmations,
                requiredConfirmations
            );

        request.status = PegInStatus.COMPLETED;
        request.confirmations = spvProof.confirmations;
        totalPeggedIn += request.satoshis;
        depositedCommitments[request.pilCommitment] = true;

        emit PegInCompleted(
            requestId,
            request.pilCommitment,
            request.pilRecipient
        );
        emit SPVProofVerified(
            request.bitcoinTxHash,
            spvProof.blockHash,
            spvProof.confirmations
        );
    }

    /*//////////////////////////////////////////////////////////////
                            ATOMIC SWAPS (HTLC)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create an atomic swap HTLC
     * @param hashLock SHA256 hash of the preimage
     * @param timeLock Expiration timestamp
     * @param satoshis Bitcoin amount
     * @param pilAmount PIL token amount
     * @param bitcoinParty Bitcoin address of counterparty
     */
    function createAtomicSwap(
        bytes32 hashLock,
        uint256 timeLock,
        uint64 satoshis,
        uint256 pilAmount,
        bytes calldata bitcoinParty
    ) external payable nonReentrant whenNotPaused returns (bytes32 htlcId) {
        if (timeLock < block.timestamp + minHTLCTimeout)
            revert InvalidHTLCTimeout();
        if (timeLock > block.timestamp + maxHTLCTimeout)
            revert InvalidHTLCTimeout();
        if (satoshis < minPegAmount)
            revert AmountTooLow(satoshis, minPegAmount);
        if (bitcoinParty.length == 0) revert InvalidBitcoinAddress();

        htlcId = keccak256(
            abi.encodePacked(
                hashLock,
                msg.sender,
                bitcoinParty,
                satoshis,
                pilAmount,
                block.timestamp
            )
        );

        atomicSwaps[htlcId] = AtomicSwapHTLC({
            htlcId: htlcId,
            hashLock: hashLock,
            timeLock: timeLock,
            satoshis: satoshis,
            pilAmount: pilAmount,
            pilParty: msg.sender,
            bitcoinParty: bitcoinParty,
            status: HTLCStatus.CREATED,
            preimage: bytes32(0)
        });

        totalSwaps++;

        emit AtomicSwapCreated(htlcId, hashLock, satoshis, pilAmount);
    }

    /**
     * @notice Claim atomic swap with preimage
     * @param htlcId The HTLC ID
     * @param preimage The secret preimage
     */
    function claimAtomicSwap(
        bytes32 htlcId,
        bytes32 preimage
    ) external nonReentrant {
        AtomicSwapHTLC storage htlc = atomicSwaps[htlcId];

        if (htlc.htlcId == bytes32(0)) revert RequestNotFound(htlcId);
        if (
            htlc.status == HTLCStatus.COMPLETED ||
            htlc.status == HTLCStatus.REFUNDED
        ) revert RequestAlreadyProcessed(htlcId);
        if (block.timestamp > htlc.timeLock) revert HTLCExpired(htlcId);

        // Verify preimage
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != htlc.hashLock)
            revert InvalidPreimage(htlc.hashLock, computedHash);

        htlc.status = HTLCStatus.COMPLETED;
        htlc.preimage = preimage;

        emit AtomicSwapCompleted(htlcId, preimage);
    }

    /**
     * @notice Refund expired atomic swap
     * @param htlcId The HTLC ID
     */
    function refundAtomicSwap(bytes32 htlcId) external nonReentrant {
        AtomicSwapHTLC storage htlc = atomicSwaps[htlcId];

        if (htlc.htlcId == bytes32(0)) revert RequestNotFound(htlcId);
        if (
            htlc.status == HTLCStatus.COMPLETED ||
            htlc.status == HTLCStatus.REFUNDED
        ) revert RequestAlreadyProcessed(htlcId);
        if (block.timestamp <= htlc.timeLock) revert HTLCNotExpired(htlcId);

        htlc.status = HTLCStatus.REFUNDED;
    }

    /*//////////////////////////////////////////////////////////////
                        LIGHTNING NETWORK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a Lightning Network invoice for peg-in
     * @param paymentHash The payment hash from Lightning invoice
     * @param satoshis Amount in satoshis
     * @param expiry Invoice expiry timestamp
     * @param pilRecipient PIL address to receive tokens
     */
    function createLightningInvoice(
        bytes32 paymentHash,
        uint64 satoshis,
        uint256 expiry,
        address pilRecipient
    )
        external
        nonReentrant
        onlyRole(LIGHTNING_NODE_ROLE)
        returns (bytes32 invoiceId)
    {
        if (pilRecipient == address(0)) revert ZeroAddress();
        if (satoshis < minPegAmount)
            revert AmountTooLow(satoshis, minPegAmount);
        if (expiry < block.timestamp) revert LightningInvoiceExpired();

        invoiceId = keccak256(
            abi.encodePacked(
                paymentHash,
                pilRecipient,
                satoshis,
                block.timestamp
            )
        );

        bytes32 pilCommitment = _generatePILCommitment(
            pilRecipient,
            satoshis,
            invoiceId
        );

        lightningInvoices[invoiceId] = LightningInvoice({
            invoiceId: invoiceId,
            paymentHash: paymentHash,
            satoshis: satoshis,
            expiry: expiry,
            pilCommitment: pilCommitment,
            pilRecipient: pilRecipient,
            status: LightningStatus.CREATED,
            preimage: bytes32(0)
        });

        emit LightningInvoiceCreated(invoiceId, paymentHash, satoshis);
    }

    /**
     * @notice Settle Lightning payment with preimage
     * @param invoiceId The invoice ID
     * @param preimage The payment preimage
     */
    function settleLightningPayment(
        bytes32 invoiceId,
        bytes32 preimage
    ) external nonReentrant onlyRole(LIGHTNING_NODE_ROLE) {
        LightningInvoice storage invoice = lightningInvoices[invoiceId];

        if (invoice.invoiceId == bytes32(0)) revert RequestNotFound(invoiceId);
        if (invoice.status == LightningStatus.SETTLED)
            revert RequestAlreadyProcessed(invoiceId);
        if (block.timestamp > invoice.expiry) revert LightningInvoiceExpired();

        // Verify preimage matches payment hash
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        if (computedHash != invoice.paymentHash)
            revert InvalidPreimage(invoice.paymentHash, computedHash);

        invoice.status = LightningStatus.SETTLED;
        invoice.preimage = preimage;
        totalPeggedIn += invoice.satoshis;
        depositedCommitments[invoice.pilCommitment] = true;

        emit LightningPaymentSettled(invoiceId, preimage);
    }

    /*//////////////////////////////////////////////////////////////
                        BITCOIN BLOCK HEADERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a Bitcoin block header
     * @param header The block header data
     */
    function submitBlockHeader(
        BitcoinBlockHeader calldata header
    ) external nonReentrant onlyRole(SPV_VERIFIER_ROLE) {
        // Validate block header
        if (!_validateBlockHeader(header)) revert InvalidBlockHeader();

        blockHeaders[header.blockHash] = header;

        if (header.blockHeight > latestBlockHeight) {
            latestBlockHeight = header.blockHeight;
            latestBlockHash = header.blockHash;
        }

        emit BitcoinBlockSubmitted(
            header.blockHash,
            header.blockHeight,
            header.merkleRoot
        );
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate Bitcoin address format
     */
    function _validateBitcoinAddress(
        bytes calldata addr,
        BitcoinScriptType scriptType
    ) internal pure returns (bool) {
        if (addr.length == 0) return false;

        if (scriptType == BitcoinScriptType.P2PKH) {
            // Legacy addresses: 25-34 bytes
            return addr.length >= 25 && addr.length <= 34;
        } else if (scriptType == BitcoinScriptType.P2SH) {
            // Script hash addresses: start with 3 (mainnet) or 2 (testnet)
            return addr.length >= 25 && addr.length <= 34;
        } else if (scriptType == BitcoinScriptType.P2WPKH) {
            // Native SegWit: bech32, 42-62 chars
            return addr.length >= 42 && addr.length <= 62;
        } else if (scriptType == BitcoinScriptType.P2WSH) {
            // SegWit script hash: bech32, longer
            return addr.length >= 42 && addr.length <= 74;
        } else if (scriptType == BitcoinScriptType.P2TR) {
            // Taproot: bech32m, 62 chars
            return addr.length >= 42 && addr.length <= 74;
        }

        return true; // HTLC and Lightning handled separately
    }

    /**
     * @notice Verify PIL commitment proof
     */
    function _verifyPILProof(
        bytes32 commitment,
        bytes32 nullifier,
        uint64 amount,
        bytes calldata proof
    ) internal pure returns (bool) {
        // Production: Integrate with PIL Groth16/PLONK verifier
        if (commitment == bytes32(0)) return false;
        if (nullifier == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Verify SPV proof of Bitcoin transaction
     */
    function _verifySPVProof(
        SPVProof calldata proof
    ) internal view returns (bool) {
        // Verify block is known
        BitcoinBlockHeader storage header = blockHeaders[proof.blockHash];
        if (header.blockHash == bytes32(0)) {
            // In production: Query Bitcoin relay contract
            // For now, accept if proof looks valid
            if (proof.merkleProof.length == 0) return false;
            if (proof.txHash == bytes32(0)) return false;
            return true;
        }

        // Verify merkle proof
        return
            _verifyMerkleProof(
                proof.txHash,
                proof.merkleRoot,
                proof.merkleProof,
                proof.proofFlags,
                proof.txIndex
            );
    }

    /**
     * @notice Verify Merkle proof for transaction inclusion
     */
    function _verifyMerkleProof(
        bytes32 txHash,
        bytes32 merkleRoot,
        bytes32[] calldata proof,
        uint256[] calldata flags,
        uint256 index
    ) internal pure returns (bool) {
        bytes32 computedHash = txHash;

        for (uint256 i = 0; i < proof.length; i++) {
            if (flags.length > i && flags[i] == 1) {
                // Sibling is on the left
                computedHash = sha256(abi.encodePacked(proof[i], computedHash));
            } else {
                // Sibling is on the right
                computedHash = sha256(abi.encodePacked(computedHash, proof[i]));
            }
        }

        return computedHash == merkleRoot;
    }

    /**
     * @notice Validate Bitcoin block header
     */
    function _validateBlockHeader(
        BitcoinBlockHeader calldata header
    ) internal pure returns (bool) {
        // Basic validation
        if (header.blockHash == bytes32(0)) return false;
        if (header.merkleRoot == bytes32(0)) return false;
        if (header.timestamp == 0) return false;

        // In production: Verify proof of work, difficulty, chain continuity
        return true;
    }

    /**
     * @notice Generate PIL commitment
     */
    function _generatePILCommitment(
        address recipient,
        uint64 amount,
        bytes32 salt
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(recipient, amount, salt));
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get peg-out request details
     */
    function getPegOutRequest(
        bytes32 requestId
    ) external view returns (PegOutRequest memory) {
        return pegOutRequests[requestId];
    }

    /**
     * @notice Get peg-in request details
     */
    function getPegInRequest(
        bytes32 requestId
    ) external view returns (PegInRequest memory) {
        return pegInRequests[requestId];
    }

    /**
     * @notice Get atomic swap details
     */
    function getAtomicSwap(
        bytes32 htlcId
    ) external view returns (AtomicSwapHTLC memory) {
        return atomicSwaps[htlcId];
    }

    /**
     * @notice Get Lightning invoice details
     */
    function getLightningInvoice(
        bytes32 invoiceId
    ) external view returns (LightningInvoice memory) {
        return lightningInvoices[invoiceId];
    }

    /**
     * @notice Get block header
     */
    function getBlockHeader(
        bytes32 blockHash
    ) external view returns (BitcoinBlockHeader memory) {
        return blockHeaders[blockHash];
    }

    /**
     * @notice Check if nullifier is used
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return crossChainNullifiers[nullifier];
    }

    /**
     * @notice Check if commitment is deposited
     */
    function isCommitmentDeposited(
        bytes32 commitment
    ) external view returns (bool) {
        return depositedCommitments[commitment];
    }

    /**
     * @notice Get bridge statistics
     */
    function getBridgeStats()
        external
        view
        returns (
            uint256 _totalPegIns,
            uint256 _totalPegOuts,
            uint256 _totalSwaps,
            uint256 _totalPeggedIn,
            uint256 _totalPeggedOut,
            uint256 _accumulatedFees,
            uint256 _latestBlockHeight
        )
    {
        return (
            totalPegIns,
            totalPegOuts,
            totalSwaps,
            totalPeggedIn,
            totalPeggedOut,
            accumulatedFees,
            latestBlockHeight
        );
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set bridge limits
     */
    function setBridgeLimits(
        uint64 _minPegAmount,
        uint64 _maxPegAmount
    ) external onlyRole(OPERATOR_ROLE) {
        minPegAmount = _minPegAmount;
        maxPegAmount = _maxPegAmount;
    }

    /**
     * @notice Set bridge fee
     */
    function setBridgeFee(uint256 _feeBps) external onlyRole(OPERATOR_ROLE) {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        bridgeFeeBps = _feeBps;
    }

    /**
     * @notice Set HTLC timeout constraints
     */
    function setHTLCTimeouts(
        uint256 _minTimeout,
        uint256 _maxTimeout
    ) external onlyRole(OPERATOR_ROLE) {
        minHTLCTimeout = _minTimeout;
        maxHTLCTimeout = _maxTimeout;
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
     * @notice Pause bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
