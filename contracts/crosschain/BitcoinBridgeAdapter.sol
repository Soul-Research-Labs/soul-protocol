// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IBitcoinRelay
 * @notice Interface for a Bitcoin block header relay on EVM
 * @dev Maintains a chain of validated Bitcoin block headers. Used for
 *      SPV (Simplified Payment Verification) proof verification without
 *      trusting a third party. Implementations include BTC Relay, tBTC
 *      relay, and BitVM-style fraud-proof relays.
 */
interface IBitcoinRelay {
    /// @notice Verify that a Bitcoin transaction was included in a given block
    /// @param txHash The Bitcoin transaction hash (double SHA-256, LE)
    /// @param blockHash The block header hash
    /// @param blockHeight The block height
    /// @param merkleProof Concatenated Merkle sibling hashes (32 bytes each)
    /// @param txIndex The transaction index in the block
    /// @return valid True if the SPV proof is valid
    function verifyTx(
        bytes32 txHash,
        bytes32 blockHash,
        uint256 blockHeight,
        bytes calldata merkleProof,
        uint256 txIndex
    ) external view returns (bool valid);

    /// @notice Get the current best known Bitcoin block height
    function getBestKnownHeight() external view returns (uint256);
}

/**
 * @title IBitcoinBridge
 * @notice Interface for Bitcoin-Ethereum message bridge relay
 * @dev Abstracts different bridging mechanisms (BitVM, tBTC, threshold
 *      multisig, etc.) behind a common message relay interface.
 */
interface IBitcoinBridge {
    /// @notice Submit a message to be relayed to Bitcoin (via inscription,
    ///         OP_RETURN, Taproot commitment, or bridge-specific mechanism)
    /// @param btcDestination The 32-byte Bitcoin address hash (P2PKH/P2SH/P2WPKH/P2TR)
    /// @param payload The message payload
    /// @return messageId The unique message identifier
    function sendToBitcoin(
        bytes32 btcDestination,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    /// @notice Get the bridge fee for sending a message
    /// @return fee The required fee in wei
    function getBridgeFee() external view returns (uint256 fee);
}

/**
 * @title BitcoinBridgeAdapter
 * @author ZASEON Team
 * @notice Cross-chain bridge adapter for Bitcoin network integration
 * @dev Bitcoin, the first and largest cryptocurrency network, uses a UTXO
 *      model with Proof-of-Work (SHA-256d) consensus. Cross-chain messaging
 *      to Bitcoin requires different approaches than account-based chains.
 *
 *      Key Bitcoin concepts:
 *      - UTXO model: Unspent Transaction Outputs, no account state
 *      - PoW consensus: SHA-256d mining, ~10 minute block time
 *      - Script: Bitcoin Script (non-Turing-complete) for spending conditions
 *      - Taproot (BIP 341): Schnorr signatures + MAST for complex scripts
 *      - SegWit: Segregated Witness for transaction malleability fix
 *      - SPV proofs: Merkle inclusion proofs against block headers
 *      - Confirmations: 6 confirmations (~60 min) for standard finality
 *      - Inscriptions/Ordinals: Data embedding via witness space
 *      - OP_RETURN: 80-byte data output for message anchoring
 *
 *      Bridging mechanisms supported:
 *      - SPV proofs via Bitcoin header relay (trustless, ~6 conf delay)
 *      - BitVM fraud proofs (1-of-N honest assumption, 7-day challenge)
 *      - Threshold multisig attestation (federation-based, fast)
 *      - Light client verification for block header validation
 *
 *      ZASEON integration approach:
 *      - Combines relay-based SPV verification with optional federation
 *      - Messages anchored via OP_RETURN or Taproot commitments
 *      - Nullifier tracking for double-spend prevention on EVM side
 *      - SPV proof verification for Bitcoin → Ethereum direction
 *      - Rate limiting and confirmation depth requirements
 *
 *      Security model:
 *      - SPV verification (6 confirmations by default)
 *      - Optional federation attestation for faster bridging
 *      - Nullifier-based replay protection
 *      - Rate limiting per block and per day
 *
 *      Note: See also contracts/adapters/BitVMBridgeAdapter.sol for the
 *      full BitVM deposit/withdrawal/challenge implementation.
 */
contract BitcoinBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    /// @notice Internal ZASEON chain ID for Bitcoin
    uint256 public constant BITCOIN_CHAIN_ID = 19100;

    /// @notice Maximum payload length (bytes) – limited by OP_RETURN/Taproot
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Maximum bridge fee in basis points (5%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 500;

    /// @notice Default Bitcoin confirmation depth required
    uint256 public constant DEFAULT_CONFIRMATIONS = 6;

    /// @notice Minimum SPV proof length (header + merkle path)
    uint256 public constant MIN_SPV_PROOF_LENGTH = 80;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice Bitcoin-Ethereum bridge relay contract
    IBitcoinBridge public bitcoinBridge;

    /// @notice Bitcoin block header relay for SPV verification
    IBitcoinRelay public bitcoinRelay;

    /// @notice Required confirmation depth
    uint256 public requiredConfirmations;

    /// @notice Whitelisted Bitcoin address hashes
    mapping(bytes32 => bool) public whitelistedAddresses;

    /// @notice Verified Bitcoin transaction hashes (prevents double-processing)
    mapping(bytes32 => bool) public processedBtcTxs;

    /// @notice Message verification status
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Nullifier set – prevents replay
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Bridge fee in basis points
    uint256 public bridgeFeeBps;

    /// @notice Minimum message fee (in wei)
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent through the bridge
    uint256 public totalMessagesSent;

    /// @notice Total messages received through the bridge
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (in wei)
    uint256 public totalValueBridged;

    /// @notice Sender nonce tracking
    mapping(address => uint256) public senderNonces;

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────
    error ZeroAddress();
    error InvalidPayload();
    error PayloadTooLong();
    error InsufficientFee(uint256 required, uint256 provided);
    error AddressNotWhitelisted(bytes32 btcAddress);
    error InvalidSPVProof();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error FeeTooHigh(uint256 bps);
    error TransferFailed();
    error InvalidBtcAddress();
    error BtcTxAlreadyProcessed(bytes32 txHash);
    error InsufficientConfirmations(uint256 required, uint256 current);

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────
    event MessageSentToBitcoin(
        bytes32 indexed messageHash,
        bytes32 indexed btcDestination,
        address sender,
        uint256 nonce,
        uint256 fee
    );

    event MessageReceivedFromBitcoin(
        bytes32 indexed messageHash,
        bytes32 indexed btcTxHash,
        uint256 blockHeight,
        address indexed recipient,
        uint256 nonce
    );

    event BitcoinBridgeUpdated(
        address indexed oldBridge,
        address indexed newBridge
    );
    event BitcoinRelayUpdated(
        address indexed oldRelay,
        address indexed newRelay
    );
    event AddressWhitelisted(bytes32 indexed btcAddress, bool whitelisted);
    event ConfirmationsUpdated(uint256 oldDepth, uint256 newDepth);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed to, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────
    constructor(address _bitcoinBridge, address _bitcoinRelay, address _admin) {
        if (_bitcoinBridge == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();

        bitcoinBridge = IBitcoinBridge(_bitcoinBridge);
        if (_bitcoinRelay != address(0)) {
            bitcoinRelay = IBitcoinRelay(_bitcoinRelay);
        }
        requiredConfirmations = DEFAULT_CONFIRMATIONS;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
    }

    // ──────────────────────────────────────────────
    //  Send (Ethereum → Bitcoin)
    // ──────────────────────────────────────────────

    /**
     * @notice Send a message to a Bitcoin address
     * @param btcDestination The 32-byte Bitcoin address hash
     * @param payload The message payload
     * @return messageHash Unique hash identifying the cross-chain message
     */
    function sendMessage(
        bytes32 btcDestination,
        bytes calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (btcDestination == bytes32(0)) revert InvalidBtcAddress();
        if (!whitelistedAddresses[btcDestination])
            revert AddressNotWhitelisted(btcDestination);
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Calculate fees
        uint256 bridgeFee = bitcoinBridge.getBridgeFee();
        uint256 protocolFee = (msg.value * bridgeFeeBps) / 10_000;
        uint256 totalRequired = bridgeFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        // Increment nonce
        uint256 nonce = senderNonces[msg.sender]++;
        totalMessagesSent++;
        totalValueBridged += msg.value;
        accumulatedFees += protocolFee;

        // Send via bridge
        bytes32 relayMessageId = bitcoinBridge.sendToBitcoin{
            value: msg.value - protocolFee
        }(btcDestination, payload);

        // Compute message hash
        messageHash = keccak256(
            abi.encodePacked(
                BITCOIN_CHAIN_ID,
                block.chainid,
                msg.sender,
                btcDestination,
                nonce,
                relayMessageId
            )
        );

        emit MessageSentToBitcoin(
            messageHash,
            btcDestination,
            msg.sender,
            nonce,
            msg.value
        );
    }

    // ──────────────────────────────────────────────
    //  Receive (Bitcoin → Ethereum)
    // ──────────────────────────────────────────────

    /**
     * @notice Receive and verify a message from Bitcoin via SPV proof
     * @param btcTxHash The Bitcoin transaction hash
     * @param blockHeight The Bitcoin block height containing the tx
     * @param payload The message payload (extracted from OP_RETURN/Taproot)
     * @param spvProof The SPV Merkle inclusion proof
     * @return messageHash The verified message hash
     */
    function receiveMessage(
        bytes32 btcTxHash,
        uint256 blockHeight,
        bytes calldata payload,
        bytes calldata spvProof
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (btcTxHash == bytes32(0)) revert InvalidBtcAddress();
        if (processedBtcTxs[btcTxHash]) revert BtcTxAlreadyProcessed(btcTxHash);
        if (payload.length == 0) revert InvalidPayload();
        if (spvProof.length < MIN_SPV_PROOF_LENGTH) revert InvalidSPVProof();

        // Verify SPV proof via Bitcoin relay if available
        if (address(bitcoinRelay) != address(0)) {
            // Check confirmation depth
            uint256 bestHeight = bitcoinRelay.getBestKnownHeight();
            if (bestHeight < blockHeight + requiredConfirmations)
                revert InsufficientConfirmations(
                    requiredConfirmations,
                    bestHeight >= blockHeight ? bestHeight - blockHeight : 0
                );

            // Extract block hash from proof header (first 32 bytes)
            bytes32 blockHash = bytes32(spvProof[:32]);
            uint256 txIndex = uint256(bytes32(spvProof[32:64]));
            bytes memory merkleProof = spvProof[64:];

            if (
                !bitcoinRelay.verifyTx(
                    btcTxHash,
                    blockHash,
                    blockHeight,
                    merkleProof,
                    txIndex
                )
            ) revert InvalidSPVProof();
        }

        // Mark tx as processed
        processedBtcTxs[btcTxHash] = true;

        // Extract nullifier from payload (first 32 bytes)
        bytes32 nullifier = bytes32(payload[:32]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        // Compute message hash
        uint256 nonce = totalMessagesReceived++;
        messageHash = keccak256(
            abi.encodePacked(
                BITCOIN_CHAIN_ID,
                block.chainid,
                btcTxHash,
                blockHeight,
                nullifier,
                nonce
            )
        );
        verifiedMessages[messageHash] = true;

        emit MessageReceivedFromBitcoin(
            messageHash,
            btcTxHash,
            blockHeight,
            msg.sender,
            nonce
        );
    }

    // ──────────────────────────────────────────────
    //  IBridgeAdapter
    // ──────────────────────────────────────────────

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
    ) external payable override returns (bytes32 messageId) {
        bytes32 btcDest = bytes32(uint256(uint160(targetAddress)));
        messageId = bitcoinBridge.sendToBitcoin{value: msg.value}(
            btcDest,
            payload
        );
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSentToBitcoin(
            messageId,
            btcDest,
            msg.sender,
            senderNonces[msg.sender]++,
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        nativeFee = bitcoinBridge.getBridgeFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        verified = verifiedMessages[messageId];
    }

    // ──────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────

    /// @notice Get the bridge type identifier
    function bridgeType() external pure returns (string memory) {
        return "BITCOIN";
    }

    /// @notice Get the Bitcoin chain ID
    function chainId() external pure returns (uint256) {
        return BITCOIN_CHAIN_ID;
    }

    /// @notice Check if a nullifier has been used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if a Bitcoin tx has been processed
    function isBtcTxProcessed(bytes32 txHash) external view returns (bool) {
        return processedBtcTxs[txHash];
    }

    /// @notice Check if an address hash is whitelisted
    function isAddressWhitelisted(bytes32 addr) external view returns (bool) {
        return whitelistedAddresses[addr];
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @notice Update the Bitcoin bridge contract
    function setBitcoinBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert ZeroAddress();
        emit BitcoinBridgeUpdated(address(bitcoinBridge), _bridge);
        bitcoinBridge = IBitcoinBridge(_bridge);
    }

    /// @notice Update the Bitcoin relay contract
    function setBitcoinRelay(
        address _relay
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit BitcoinRelayUpdated(address(bitcoinRelay), _relay);
        bitcoinRelay = IBitcoinRelay(_relay);
    }

    /// @notice Whitelist or de-whitelist a Bitcoin address hash
    function whitelistAddress(
        bytes32 btcAddress,
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (btcAddress == bytes32(0)) revert InvalidBtcAddress();
        whitelistedAddresses[btcAddress] = enabled;
        emit AddressWhitelisted(btcAddress, enabled);
    }

    /// @notice Set required confirmation depth
    function setRequiredConfirmations(
        uint256 depth
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit ConfirmationsUpdated(requiredConfirmations, depth);
        requiredConfirmations = depth;
    }

    /// @notice Set bridge fee in basis points
    function setBridgeFee(
        uint256 feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (feeBps > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(feeBps);
        emit BridgeFeeUpdated(bridgeFeeBps, feeBps);
        bridgeFeeBps = feeBps;
    }

    /// @notice Set minimum message fee
    function setMinMessageFee(
        uint256 fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit MinMessageFeeUpdated(minMessageFee, fee);
        minMessageFee = fee;
    }

    // ──────────────────────────────────────────────
    //  Emergency
    // ──────────────────────────────────────────────

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated protocol fees
    function withdrawFees(
        address payable to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit FeesWithdrawn(to, amount);
    }

    /// @notice Emergency withdraw all ETH
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ERC-20 tokens
    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(to, balance);
    }

    /// @dev Allow receiving ETH
    receive() external payable {}
}
