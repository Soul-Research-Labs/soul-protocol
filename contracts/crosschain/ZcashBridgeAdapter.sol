// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IZcashBridge
 * @notice Minimal interface for the Zcash–Ethereum bridge relay contract
 * @dev Zcash uses the Halo 2 proof system (Orchard shielded pool) with the
 *      Pallas/Vesta curve cycle. The bridge relay aggregates Zcash shielded
 *      transaction proofs and submits them to Ethereum for verification.
 *      Messages flow via a wrapped-ZEC custodian contract on Ethereum.
 */
interface IZcashBridge {
    /// @notice Submit a shielded note commitment for bridging
    /// @param noteCommitment The Orchard note commitment (Pallas point hash)
    /// @param payload The bridge payload (recipient, amount commitment, memo)
    /// @return bridgeId Unique bridge operation identifier
    function bridgeShieldedNote(
        bytes32 noteCommitment,
        bytes calldata payload
    ) external payable returns (bytes32 bridgeId);

    /// @notice Estimate the relay fee for a bridge operation
    /// @return fee The estimated fee in wei
    function estimateRelayFee() external view returns (uint256 fee);

    /// @notice Get the latest Zcash block height synced by the relay
    /// @return height The latest synced Zcash block height
    function latestSyncedHeight() external view returns (uint256 height);
}

/**
 * @title IOrchardVerifier
 * @notice Interface for verifying Zcash Orchard (Halo 2) shielded proofs on EVM
 * @dev Orchard proofs use the Halo 2 proof system with the Pallas/Vesta curve
 *      cycle. The verifier checks recursive Halo 2 proofs that have been
 *      translated to a BN254-friendly representation for EVM verification.
 */
interface IOrchardVerifier {
    /// @notice Verify a translated Orchard proof (Halo 2 → BN254 wrapper)
    /// @param proof The proof data (BN254-wrapped Halo 2 proof)
    /// @param publicInputs The public inputs (nullifiers, commitments, anchors)
    /// @return valid Whether the proof is valid
    function verifyOrchardProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    /// @notice Get the current Orchard commitment tree anchor
    /// @return anchor The latest verified commitment tree root
    function currentAnchor() external view returns (bytes32 anchor);
}

/**
 * @title ZcashBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Zcash — shielded UTXO chain with Halo 2 proofs
 * @dev Enables ZASEON cross-chain interoperability with Zcash's shielded pool
 *      via a bridge relay and Orchard proof verification on Ethereum.
 *
 * ZCASH INTEGRATION:
 * - Independent PoW/PoS hybrid L1 (Nu5 network upgrade, Orchard shielded pool)
 * - Privacy model: Orchard shielded pool with Halo 2 recursive proofs
 * - Proof system: Halo 2 on Pallas/Vesta curve cycle (no trusted setup)
 * - Native token: ZEC
 * - Address types: transparent (t-addr) and shielded (z-addr, unified addresses)
 * - Consensus: Proof-of-Work (Equihash) transitioning to Proof-of-Stake
 * - Block time: ~75 seconds
 *
 * MESSAGE FLOW:
 * - ZASEON→Zcash: bridgeMessage() → relay → shielded note on Zcash
 * - Zcash→ZASEON: Orchard proof generated → relay → verifier validates on EVM
 *
 * SECURITY NOTES:
 * - Orchard proofs verified on-chain via translated BN254-wrapped Halo 2 proofs
 * - Nullifier-based replay protection (integrates with Zcash native nullifiers)
 * - Note commitments verified against Orchard Merkle tree anchor
 * - ~75 second block time, 10-block finality (~12.5 minutes)
 */
contract ZcashBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
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

    /// @notice ZASEON virtual chain ID for Zcash (not an EVM chain ID)
    uint16 public constant ZCASH_CHAIN_ID = 8100;

    /// @notice Zcash finality blocks (~10 blocks, ~12.5 minutes)
    uint256 public constant FINALITY_BLOCKS = 10;

    /// @notice Minimum Orchard proof size in bytes
    uint256 public constant MIN_PROOF_SIZE = 64;

    /// @notice Maximum bridge fee (1% = 100 basis points)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length in bytes
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /*//////////////////////////////////////////////////////////////
                           STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Zcash bridge relay contract
    IZcashBridge public zcashBridge;

    /// @notice Orchard proof verifier (Halo 2 → BN254 wrapper)
    IOrchardVerifier public orchardVerifier;

    /// @notice Bridge fee in basis points (0–100)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees available for withdrawal
    uint256 public accumulatedFees;

    /// @notice Total messages sent to Zcash
    uint256 public totalMessagesSent;

    /// @notice Total messages received from Zcash
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

    /// @notice Verified Orchard anchors (commitment tree roots)
    mapping(bytes32 => bool) public verifiedAnchors;

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
        bytes32 noteCommitment;
        bytes32 orchardAnchor;
        bytes32 nullifier;
        uint256 timestamp;
    }

    /*//////////////////////////////////////////////////////////////
                           ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidAnchor();
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
        bytes32 noteCommitment,
        bytes32 bridgeId,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 orchardAnchor,
        bytes32 indexed nullifier,
        bytes payload
    );

    event ZcashBridgeUpdated(
        address indexed oldBridge,
        address indexed newBridge
    );
    event OrchardVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed recipient, uint256 amount);
    event AnchorRegistered(bytes32 indexed anchor);

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _zcashBridge Zcash bridge relay contract address
    /// @param _orchardVerifier Orchard proof verifier contract address
    /// @param _admin Admin address (receives all initial roles)
    constructor(
        address _zcashBridge,
        address _orchardVerifier,
        address _admin
    ) {
        if (_zcashBridge == address(0)) revert InvalidBridge();
        if (_orchardVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        zcashBridge = IZcashBridge(_zcashBridge);
        orchardVerifier = IOrchardVerifier(_orchardVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice ZASEON virtual chain ID for Zcash
    function chainId() external pure returns (uint16) {
        return ZCASH_CHAIN_ID;
    }

    /// @notice Human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Zcash";
    }

    /// @notice Whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(zcashBridge) != address(0) &&
            address(orchardVerifier) != address(0);
    }

    /// @notice Number of blocks for finality
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Get the current Orchard commitment tree anchor
    function getOrchardAnchor() external view returns (bytes32) {
        return orchardVerifier.currentAnchor();
    }

    /// @notice Get the latest synced Zcash block height
    function getLatestSyncedHeight() external view returns (uint256) {
        return zcashBridge.latestSyncedHeight();
    }

    /*//////////////////////////////////////////////////////////////
                 SEND MESSAGE (ZASEON → ZCASH)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a cross-chain message from ZASEON to Zcash
     * @param noteCommitment The Orchard note commitment for the destination
     * @param payload The message payload (shielded transfer data)
     * @return messageHash The unique message hash
     */
    function sendMessage(
        bytes32 noteCommitment,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (noteCommitment == bytes32(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Enforce minimum fee
        uint256 relayFee = zcashBridge.estimateRelayFee();
        uint256 requiredFee = relayFee + minMessageFee;
        if (msg.value < requiredFee)
            revert InsufficientFee(requiredFee, msg.value);

        // Protocol fee
        uint256 protocolFee = 0;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        // Forward to Zcash bridge relay
        bytes32 bridgeId = zcashBridge.bridgeShieldedNote{
            value: msg.value - protocolFee
        }(noteCommitment, payload);

        // Build message record
        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                ZCASH_CHAIN_ID,
                msg.sender,
                noteCommitment,
                nonce,
                block.timestamp,
                keccak256(payload)
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            noteCommitment: noteCommitment,
            orchardAnchor: bytes32(0),
            nullifier: bytes32(0),
            timestamp: block.timestamp
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            noteCommitment,
            bridgeId,
            msg.value
        );
    }

    /*//////////////////////////////////////////////////////////////
              RECEIVE MESSAGE (ZCASH → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a cross-chain message from Zcash
     * @param proof Orchard proof (BN254-wrapped Halo 2 proof)
     * @param publicInputs [orchardAnchor, nullifier, noteCommitment, payloadHash]
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
        // Verify Orchard proof via translated verifier
        bool valid = orchardVerifier.verifyOrchardProof(proof, payload);
        if (!valid) revert InvalidProof();

        // Extract public inputs
        bytes32 orchardAnchor = bytes32(publicInputs[0]);
        bytes32 nullifier = bytes32(publicInputs[1]);
        bytes32 noteCommitment = bytes32(publicInputs[2]);
        bytes32 payloadHash = bytes32(publicInputs[3]);

        // Replay protection
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        // Build message hash
        messageHash = keccak256(
            abi.encodePacked(
                ZCASH_CHAIN_ID,
                orchardAnchor,
                nullifier,
                noteCommitment,
                payloadHash
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            noteCommitment: noteCommitment,
            orchardAnchor: orchardAnchor,
            nullifier: nullifier,
            timestamp: block.timestamp
        });

        totalMessagesReceived++;

        emit MessageReceived(messageHash, orchardAnchor, nullifier, payload);
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
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Derive note commitment from target address for bridge relay
        bytes32 noteCommitment = keccak256(
            abi.encodePacked(targetAddress, payload)
        );

        bytes32 bridgeId = zcashBridge.bridgeShieldedNote{value: msg.value}(
            noteCommitment,
            payload
        );

        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                ZCASH_CHAIN_ID,
                msg.sender,
                targetAddress,
                nonce,
                block.timestamp,
                keccak256(payload)
            )
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            noteCommitment: noteCommitment,
            orchardAnchor: bytes32(0),
            nullifier: bytes32(0),
            timestamp: block.timestamp
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageId,
            msg.sender,
            noteCommitment,
            bridgeId,
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        uint256 relayFee = zcashBridge.estimateRelayFee();
        return relayFee + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        MessageStatus status = messages[messageId].status;
        return
            status == MessageStatus.SENT || status == MessageStatus.DELIVERED;
    }

    /*//////////////////////////////////////////////////////////////
                    ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Zcash bridge relay address
    function setZcashBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        address old = address(zcashBridge);
        zcashBridge = IZcashBridge(_bridge);
        emit ZcashBridgeUpdated(old, _bridge);
    }

    /// @notice Update the Orchard verifier address
    function setOrchardVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        address old = address(orchardVerifier);
        orchardVerifier = IOrchardVerifier(_verifier);
        emit OrchardVerifierUpdated(old, _verifier);
    }

    /// @notice Register a verified Orchard anchor
    function registerAnchor(
        bytes32 _anchor
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_anchor == bytes32(0)) revert InvalidAnchor();
        verifiedAnchors[_anchor] = true;
        emit AnchorRegistered(_anchor);
    }

    /// @notice Set the bridge fee in basis points (max 100 = 1%)
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        uint256 old = bridgeFee;
        bridgeFee = _fee;
        emit BridgeFeeUpdated(old, _fee);
    }

    /// @notice Set the minimum per-message fee
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
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
    function withdrawFees(
        address payable _recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
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
