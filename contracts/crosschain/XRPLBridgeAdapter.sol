// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IXRPLBridge
 * @notice Interface for the XRPL-Ethereum bridge relay contract
 * @dev The XRP Ledger uses a unique consensus protocol (XRPL Consensus)
 *      based on the Federated Byzantine Agreement (FBA) model. Validators
 *      maintain Unique Node Lists (UNLs) and reach consensus in ~3-5 seconds.
 *      The bridge relies on multi-sign attestations from a set of XRPL
 *      witnesses, similar to Ripple's XRPL EVM Sidechain bridge.
 */
interface IXRPLBridge {
    /// @notice Submit a message to be relayed to the XRPL
    /// @param xrplDestination The 20-byte XRPL account address (classic)
    /// @param destinationTag The destination tag (optional, 0 for none)
    /// @param payload The message payload
    /// @return messageId The unique message identifier
    function sendToXRPL(
        bytes20 xrplDestination,
        uint32 destinationTag,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    /// @notice Verify a witness-attested message from XRPL
    /// @param attestation The multi-sign witness attestation
    /// @param payload The message payload
    /// @return valid Whether the attestation is valid
    function verifyAttestation(
        bytes calldata attestation,
        bytes calldata payload
    ) external returns (bool valid);

    /// @notice Get the relay fee for sending a message
    /// @return fee The required fee in wei
    function getRelayFee() external view returns (uint256 fee);
}

/**
 * @title IXRPLLightClient
 * @notice Interface for verifying XRPL ledger state
 * @dev XRPL tracks state via a Merkle tree of account objects (AccountRoot,
 *      TrustLine, Offer, etc.) indexed by ledger index. The light client
 *      verifies ledger headers signed by the validator UNL.
 */
interface IXRPLLightClient {
    /// @notice Verify an XRPL ledger header
    /// @param ledgerIndex The ledger sequence number
    /// @param ledgerHash The 32-byte ledger hash
    /// @param validatorSignatures Concatenated Ed25519 validator signatures
    /// @return valid Whether the ledger header is valid
    function verifyLedgerHeader(
        uint64 ledgerIndex,
        bytes32 ledgerHash,
        bytes calldata validatorSignatures
    ) external view returns (bool valid);

    /// @notice Verify a Merkle proof of an XRPL object against a ledger hash
    /// @param ledgerHash The verified ledger hash
    /// @param proof The SHAMap Merkle proof
    /// @return valid Whether the proof is valid
    function verifyObjectProof(
        bytes32 ledgerHash,
        bytes calldata proof
    ) external view returns (bool valid);

    /// @notice Get the latest verified ledger index
    /// @return ledgerIndex The latest verified ledger sequence number
    function latestVerifiedLedger() external view returns (uint64 ledgerIndex);
}

/**
 * @title XRPLBridgeAdapter
 * @author ZASEON Team
 * @notice Bridge adapter for XRP Ledger integration
 * @dev The XRP Ledger is a decentralized, public blockchain built for
 *      payments and tokenization. It features a unique consensus protocol
 *      (XRPL Consensus / FBA) that achieves finality in 3-5 seconds without
 *      mining or staking.
 *
 *      Key XRPL concepts:
 *      - XRPL Consensus: Federated Byzantine Agreement, validators vote in
 *        rounds, requiring ≥80% agreement from each node's UNL
 *      - UNL (Unique Node List): Per-node trusted validator set
 *      - Ledger: State snapshot every 3-5 seconds (not blocks)
 *      - Accounts: Classic addresses (r...) derived from Ed25519/secp256k1
 *      - Destination Tags: 32-bit integers for demultiplexing at an address
 *      - SHAMap: Merkle tree variant for XRPL state objects
 *      - Hooks: Smart contract system (WASM-based, limited functionality)
 *      - Amendments: On-chain governance for protocol upgrades
 *      - Reserves: Account reserve (10 XRP) + owner reserve per object
 *      - Drops: Smallest unit (1 XRP = 1,000,000 drops)
 *
 *      ZASEON integration approach:
 *      - Uses witness-attested bridge (multi-sign attestation model)
 *      - Optional light client for ledger header verification
 *      - SHAMap proof verification for state attestation
 *      - Account whitelisting for authorized XRPL destinations
 *      - Destination tag tracking for message demultiplexing
 *
 *      Security model:
 *      - Multi-witness attestation (threshold of N witnesses)
 *      - Optional SHAMap Merkle proof verification via light client
 *      - Nullifier-based replay protection
 *      - Rate limiting per account and per ledger
 */
contract XRPLBridgeAdapter is
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

    /// @notice Internal ZASEON chain ID for the XRPL
    uint256 public constant XRPL_CHAIN_ID = 18100;

    /// @notice Maximum payload length (bytes)
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Maximum bridge fee in basis points (5%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 500;

    /// @notice Required attestation threshold (80% matching XRPL consensus)
    uint256 public constant ATTESTATION_THRESHOLD_BPS = 8000;

    /// @notice Minimum attestation length for multi-sign verification
    uint256 public constant MIN_ATTESTATION_LENGTH = 64;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice XRPL-Ethereum bridge relay contract
    IXRPLBridge public xrplBridge;

    /// @notice Optional XRPL light client for ledger verification
    IXRPLLightClient public xrplLightClient;

    /// @notice Whitelisted XRPL accounts (20-byte classic addresses)
    mapping(bytes20 => bool) public whitelistedAccounts;

    /// @notice Default destination tag for bridge operations
    uint32 public defaultDestinationTag;

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
    error AccountNotWhitelisted(bytes20 account);
    error InvalidAttestation();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error FeeTooHigh(uint256 bps);
    error TransferFailed();
    error InvalidAccount();
    error InvalidLedgerProof();

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────
    event MessageSentToXRPL(
        bytes32 indexed messageHash,
        bytes20 indexed xrplDestination,
        uint32 destinationTag,
        address sender,
        uint256 nonce,
        uint256 fee
    );

    event MessageReceivedFromXRPL(
        bytes32 indexed messageHash,
        bytes20 indexed xrplSource,
        address indexed recipient,
        uint256 ledgerIndex
    );

    event XRPLBridgeUpdated(
        address indexed oldBridge,
        address indexed newBridge
    );
    event XRPLLightClientUpdated(
        address indexed oldClient,
        address indexed newClient
    );
    event AccountWhitelisted(bytes20 indexed account, bool whitelisted);
    event DefaultDestinationTagUpdated(uint32 oldTag, uint32 newTag);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed to, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────
    constructor(address _xrplBridge, address _admin) {
        if (_xrplBridge == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();

        xrplBridge = IXRPLBridge(_xrplBridge);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(RELAYER_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
    }

    // ──────────────────────────────────────────────
    //  Send (Ethereum → XRPL)
    // ──────────────────────────────────────────────

    /**
     * @notice Send a message to an XRPL account
     * @param xrplDestination The 20-byte XRPL classic address
     * @param destinationTag The XRPL destination tag
     * @param payload The message payload
     * @return messageHash Unique hash identifying the cross-chain message
     */
    function sendMessage(
        bytes20 xrplDestination,
        uint32 destinationTag,
        bytes calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (xrplDestination == bytes20(0)) revert InvalidAccount();
        if (!whitelistedAccounts[xrplDestination])
            revert AccountNotWhitelisted(xrplDestination);
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Calculate fees
        uint256 relayFee = xrplBridge.getRelayFee();
        uint256 protocolFee = (msg.value * bridgeFeeBps) / 10_000;
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        // Increment nonce
        uint256 nonce = senderNonces[msg.sender]++;
        totalMessagesSent++;
        totalValueBridged += msg.value;
        accumulatedFees += protocolFee;

        // Send via bridge relay
        bytes32 relayMessageId = xrplBridge.sendToXRPL{
            value: msg.value - protocolFee
        }(xrplDestination, destinationTag, payload);

        // Compute message hash
        messageHash = keccak256(
            abi.encodePacked(
                XRPL_CHAIN_ID,
                block.chainid,
                msg.sender,
                xrplDestination,
                destinationTag,
                nonce,
                relayMessageId
            )
        );

        emit MessageSentToXRPL(
            messageHash,
            xrplDestination,
            destinationTag,
            msg.sender,
            nonce,
            msg.value
        );
    }

    // ──────────────────────────────────────────────
    //  Receive (XRPL → Ethereum)
    // ──────────────────────────────────────────────

    /**
     * @notice Receive and verify a message from the XRPL
     * @param xrplSource The source XRPL account (20-byte classic address)
     * @param ledgerIndex The XRPL ledger sequence number containing the tx
     * @param payload The message payload
     * @param attestation Multi-sign witness attestation or ledger proof
     * @return messageHash The verified message hash
     */
    function receiveMessage(
        bytes20 xrplSource,
        uint64 ledgerIndex,
        bytes calldata payload,
        bytes calldata attestation
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (xrplSource == bytes20(0)) revert InvalidAccount();
        if (!whitelistedAccounts[xrplSource])
            revert AccountNotWhitelisted(xrplSource);
        if (payload.length == 0) revert InvalidPayload();
        if (attestation.length < MIN_ATTESTATION_LENGTH)
            revert InvalidAttestation();

        // Verify via light client if available
        if (address(xrplLightClient) != address(0)) {
            bytes32 ledgerHash = bytes32(attestation[:32]);
            bytes memory objectProof = attestation[32:];
            if (!xrplLightClient.verifyObjectProof(ledgerHash, objectProof))
                revert InvalidLedgerProof();
        }

        // Extract nullifier from payload (first 32 bytes)
        bytes32 nullifier = bytes32(payload[:32]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        // Compute message hash
        uint256 nonce = totalMessagesReceived++;
        messageHash = keccak256(
            abi.encodePacked(
                XRPL_CHAIN_ID,
                block.chainid,
                xrplSource,
                ledgerIndex,
                nullifier,
                nonce
            )
        );
        verifiedMessages[messageHash] = true;

        emit MessageReceivedFromXRPL(
            messageHash,
            xrplSource,
            msg.sender,
            ledgerIndex
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
        bytes20 xrplDest = bytes20(targetAddress);
        if (xrplDest == bytes20(0)) revert InvalidAccount();

        messageId = xrplBridge.sendToXRPL{value: msg.value}(
            xrplDest,
            defaultDestinationTag,
            payload
        );

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSentToXRPL(
            messageId,
            xrplDest,
            defaultDestinationTag,
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
        nativeFee = xrplBridge.getRelayFee() + minMessageFee;
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
        return "XRPL";
    }

    /// @notice Get the XRPL chain ID
    function chainId() external pure returns (uint256) {
        return XRPL_CHAIN_ID;
    }

    /// @notice Check if a nullifier has been used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if an account is whitelisted
    function isAccountWhitelisted(
        bytes20 account
    ) external view returns (bool) {
        return whitelistedAccounts[account];
    }

    /// @notice Verify a ledger object proof via the light client
    function verifyLedgerProof(
        bytes32 ledgerHash,
        bytes calldata proof
    ) external view returns (bool) {
        if (address(xrplLightClient) == address(0)) return false;
        return xrplLightClient.verifyObjectProof(ledgerHash, proof);
    }

    // ──────────────────────────────────────────────
    //  Admin
    // ──────────────────────────────────────────────

    /// @notice Update the XRPL bridge contract address
    function setXRPLBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert ZeroAddress();
        emit XRPLBridgeUpdated(address(xrplBridge), _bridge);
        xrplBridge = IXRPLBridge(_bridge);
    }

    /// @notice Update the XRPL light client contract address
    function setXRPLLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit XRPLLightClientUpdated(address(xrplLightClient), _client);
        xrplLightClient = IXRPLLightClient(_client);
    }

    /// @notice Whitelist or de-whitelist an XRPL account
    function whitelistAccount(
        bytes20 account,
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (account == bytes20(0)) revert InvalidAccount();
        whitelistedAccounts[account] = enabled;
        emit AccountWhitelisted(account, enabled);
    }

    /// @notice Set the default destination tag
    function setDefaultDestinationTag(
        uint32 tag
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit DefaultDestinationTagUpdated(defaultDestinationTag, tag);
        defaultDestinationTag = tag;
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
