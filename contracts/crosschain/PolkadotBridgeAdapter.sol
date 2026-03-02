// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title ISnowbridge
 * @notice Minimal interface for the Snowbridge Ethereum↔Polkadot bridge
 * @dev Snowbridge is the trustless bridge between Ethereum and Polkadot,
 *      using BEEFY (Bridge Efficiency Enabling Finality Yielder) light client
 *      proofs to verify Polkadot relay chain finality on Ethereum and
 *      Ethereum beacon chain sync committee proofs on Polkadot.
 */
interface ISnowbridge {
    /// @notice Send a message from Ethereum to a Polkadot parachain
    /// @param paraId The target parachain ID
    /// @param payload The XCM-encoded message body
    /// @return messageId Unique message identifier
    function sendMessage(
        uint32 paraId,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    /// @notice Estimate the delivery fee for a cross-chain message
    /// @param paraId The destination parachain ID
    /// @return fee The estimated delivery fee in wei
    function quoteSendFee(uint32 paraId) external view returns (uint256 fee);

    /// @notice Get the current BEEFY validator set commitment
    /// @return commitment The Merkle root of the active BEEFY authority set
    function currentBeefyCommitment() external view returns (bytes32 commitment);
}

/**
 * @title IBeefyVerifier
 * @notice Interface for verifying BEEFY (Polkadot finality gadget) proofs
 * @dev BEEFY proofs attest to Polkadot relay chain finality, signed by
 *      the active BEEFY authority set. The verifier validates these proofs on chain.
 */
interface IBeefyVerifier {
    /// @notice Verify a BEEFY finality proof from Polkadot validators
    /// @param proof The BEEFY signed commitment proof
    /// @param data The payload data being attested
    /// @return valid Whether the proof is valid
    function verifyBeefyProof(
        bytes calldata proof,
        bytes calldata data
    ) external returns (bool valid);

    /// @notice Get the current BEEFY authority set hash
    /// @return hash The hash of the active BEEFY authority set
    function authoritySetHash() external view returns (bytes32 hash);
}

/**
 * @title PolkadotBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Polkadot — heterogeneous multi-chain via Snowbridge
 * @dev Enables ZASEON cross-chain interoperability with Polkadot's parachain
 *      ecosystem via the Snowbridge trustless bridge and BEEFY finality proofs.
 *
 * POLKADOT INTEGRATION:
 * - Heterogeneous multi-chain protocol (relay chain + parachains)
 * - Consensus: GRANDPA (deterministic finality) + BABE (block production)
 * - Finality gadget: BEEFY (Bridge Efficiency Enabling Finality Yielder)
 * - Native token: DOT
 * - Smart contracts: ink! (Rust eDSL for Wasm) on contract parachains
 * - Cross-chain: XCM (Cross-Consensus Messaging) for inter-parachain comms
 * - EVM bridge: Snowbridge (trustless, uses BEEFY light client proofs)
 *
 * MESSAGE FLOW:
 * - ZASEON→Polkadot: sendMessage() → Snowbridge → relay chain → parachain via XCM
 * - Polkadot→ZASEON: BEEFY proof generated → relayer submits → verifier validates
 *
 * SECURITY NOTES:
 * - BEEFY finality proofs verified on-chain by BeefyVerifier contract
 * - Nullifier-based replay protection
 * - Snowbridge is the canonical trustless bridge (no third-party trust assumptions)
 * - GRANDPA provides deterministic finality (~12–60 second finalization)
 */
contract PolkadotBridgeAdapter is IBridgeAdapter, AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                           CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ZASEON virtual chain ID for Polkadot (not an EVM chain ID)
    uint16 public constant POLKADOT_CHAIN_ID = 6100;

    /// @notice Default parachain target (AssetHub, parachain ID 1000)
    uint32 public constant DEFAULT_PARA_ID = 1000;

    /// @notice GRANDPA finality blocks (~2 epochs, deterministic)
    uint256 public constant FINALITY_BLOCKS = 30;

    /// @notice Minimum BEEFY proof size in bytes
    uint256 public constant MIN_PROOF_SIZE = 64;

    /// @notice Maximum bridge fee (1% = 100 basis points)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length in bytes
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /*//////////////////////////////////////////////////////////////
                           STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Snowbridge gateway contract
    ISnowbridge public snowbridge;

    /// @notice BEEFY finality proof verifier
    IBeefyVerifier public beefyVerifier;

    /// @notice Default target parachain ID
    uint32 public targetParaId;

    /// @notice Bridge fee in basis points (0–100)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees available for withdrawal
    uint256 public accumulatedFees;

    /// @notice Total messages sent to Polkadot
    uint256 public totalMessagesSent;

    /// @notice Total messages received from Polkadot
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (wei)
    uint256 public totalValueBridged;

    /*//////////////////////////////////////////////////////////////
                           MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Tracks used nullifiers for replay protection
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Per-sender nonce counter
    mapping(address => uint256) public senderNonces;

    /*//////////////////////////////////////////////////////////////
                          ENUMS & STRUCTS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        NONE,
        PENDING,
        SENT,
        DELIVERED,
        FAILED
    }

    struct MessageRecord {
        MessageStatus status;
        uint32 paraId;
        bytes32 beefyCommitment;
        bytes32 nullifier;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                           ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidSnowbridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                           EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        uint32 paraId,
        bytes32 snowbridgeMessageId,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        uint32 paraId,
        bytes32 indexed nullifier,
        bytes payload
    );

    event SnowbridgeUpdated(address indexed oldBridge, address indexed newBridge);
    event BeefyVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event TargetParaIdUpdated(uint32 oldParaId, uint32 newParaId);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _snowbridge Snowbridge gateway contract address
    /// @param _beefyVerifier BEEFY finality proof verifier address
    /// @param _admin Admin address (receives all initial roles)
    constructor(
        address _snowbridge,
        address _beefyVerifier,
        address _admin
    ) {
        if (_snowbridge == address(0)) revert InvalidSnowbridge();
        if (_beefyVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        snowbridge = ISnowbridge(_snowbridge);
        beefyVerifier = IBeefyVerifier(_beefyVerifier);
        targetParaId = DEFAULT_PARA_ID;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice ZASEON virtual chain ID for Polkadot
    function chainId() external pure returns (uint16) {
        return POLKADOT_CHAIN_ID;
    }

    /// @notice Human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Polkadot";
    }

    /// @notice Whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return address(snowbridge) != address(0) && address(beefyVerifier) != address(0);
    }

    /// @notice Number of blocks for finality
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Get the current BEEFY authority set commitment
    function getBeefyCommitment() external view returns (bytes32) {
        return snowbridge.currentBeefyCommitment();
    }

    /*//////////////////////////////////////////////////////////////
                 SEND MESSAGE (ZASEON → POLKADOT)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a cross-chain message from ZASEON to a Polkadot parachain
     * @param paraId Target parachain ID (e.g. 1000 for AssetHub)
     * @param payload The message payload (XCM-compatible)
     * @return messageHash The unique message hash
     */
    function sendMessage(
        uint32 paraId,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (paraId == 0) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) revert InvalidPayload();

        // Enforce minimum fee
        uint256 gatewayFee = snowbridge.quoteSendFee(paraId);
        uint256 requiredFee = gatewayFee + minMessageFee;
        if (msg.value < requiredFee) revert InsufficientFee(requiredFee, msg.value);

        // Protocol fee
        uint256 protocolFee = 0;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        // Forward to Snowbridge
        bytes32 snowbridgeId = snowbridge.sendMessage{value: msg.value - protocolFee}(
            paraId,
            payload
        );

        // Build message record
        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                POLKADOT_CHAIN_ID,
                msg.sender,
                paraId,
                nonce,
                block.timestamp,
                keccak256(payload)
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            paraId: paraId,
            beefyCommitment: bytes32(0),
            nullifier: bytes32(0),
            timestamp: block.timestamp
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageHash, msg.sender, paraId, snowbridgeId, msg.value);
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (POLKADOT → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a cross-chain message from Polkadot
     * @param proof BEEFY finality proof from Polkadot validators
     * @param publicInputs [beefyCommitment, nullifier, paraId, payloadHash]
     * @param payload The original message payload
     * @return messageHash The unique message hash
     */
    function receiveMessage(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        // Verify BEEFY finality proof
        bool valid = beefyVerifier.verifyBeefyProof(proof, payload);
        if (!valid) revert InvalidProof();

        // Extract public inputs
        bytes32 beefyCommitment = bytes32(publicInputs[0]);
        bytes32 nullifier = bytes32(publicInputs[1]);
        uint32 paraId = uint32(publicInputs[2]);
        bytes32 payloadHash = bytes32(publicInputs[3]);

        // Replay protection
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        // Build message hash
        messageHash = keccak256(
            abi.encodePacked(
                POLKADOT_CHAIN_ID,
                beefyCommitment,
                nullifier,
                paraId,
                payloadHash
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            paraId: paraId,
            beefyCommitment: beefyCommitment,
            nullifier: nullifier,
            timestamp: block.timestamp
        });

        totalMessagesReceived++;

        emit MessageReceived(messageHash, paraId, nullifier, payload);
    }

    /*//////////////////////////////////////////////////////////////
                  IBridgeAdapter COMPLIANCE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
    )
        external
        payable
        override
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageId)
    {
        if (targetAddress == address(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) revert InvalidPayload();

        // Wrap as XCM-compatible payload
        bytes memory xcmPayload = abi.encodePacked(targetAddress, payload);

        bytes32 snowbridgeId = snowbridge.sendMessage{value: msg.value}(
            targetParaId,
            xcmPayload
        );

        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                POLKADOT_CHAIN_ID,
                msg.sender,
                targetAddress,
                nonce,
                block.timestamp,
                keccak256(payload)
            )
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            paraId: targetParaId,
            beefyCommitment: bytes32(0),
            nullifier: bytes32(0),
            timestamp: block.timestamp
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, targetParaId, snowbridgeId, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        uint256 gatewayFee = snowbridge.quoteSendFee(targetParaId);
        return gatewayFee + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(bytes32 messageId) external view override returns (bool) {
        MessageStatus status = messages[messageId].status;
        return status == MessageStatus.SENT || status == MessageStatus.DELIVERED;
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Snowbridge gateway address
    function setSnowbridge(address _snowbridge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_snowbridge == address(0)) revert InvalidSnowbridge();
        address old = address(snowbridge);
        snowbridge = ISnowbridge(_snowbridge);
        emit SnowbridgeUpdated(old, _snowbridge);
    }

    /// @notice Update the BEEFY verifier address
    function setBeefyVerifier(address _verifier) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        address old = address(beefyVerifier);
        beefyVerifier = IBeefyVerifier(_verifier);
        emit BeefyVerifierUpdated(old, _verifier);
    }

    /// @notice Update the default target parachain ID
    function setTargetParaId(uint32 _paraId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_paraId == 0) revert InvalidTarget();
        uint32 old = targetParaId;
        targetParaId = _paraId;
        emit TargetParaIdUpdated(old, _paraId);
    }

    /// @notice Set the bridge fee in basis points (max 100 = 1%)
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        uint256 old = bridgeFee;
        bridgeFee = _fee;
        emit BridgeFeeUpdated(old, _fee);
    }

    /// @notice Set the minimum per-message fee
    function setMinMessageFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 old = minMessageFee;
        minMessageFee = _fee;
        emit MinMessageFeeUpdated(old, _fee);
    }

    /*//////////////////////////////////////////////////////////////
                      PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                     FEE & EMERGENCY
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated protocol fees
    function withdrawFees(address payable _recipient) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_recipient == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = _recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit FeesWithdrawn(_recipient, amount);
    }

    /// @notice Emergency ETH withdrawal
    function emergencyWithdrawETH(
        address payable _to,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        (bool ok, ) = _to.call{value: _amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency ERC20 withdrawal
    function emergencyWithdrawERC20(
        address _token,
        address _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_token == address(0) || _to == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(_to, balance);
    }

    /// @notice Accept ETH transfers
    receive() external payable {}
}
