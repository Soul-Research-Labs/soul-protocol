// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IPenumbraBridge
 * @notice Minimal interface for the Penumbra–Ethereum bridge relay contract
 * @dev Penumbra is a fully-shielded, cross-chain DEX built on CometBFT consensus.
 *      It uses the Groth16 proof system on the decaf377 curve (embedded in BLS12-377).
 *      The relay bridge aggregates IBC transfers and submits them to Ethereum
 *      via a light client verifier.
 */
interface IPenumbraBridge {
    /// @notice Submit a shielded transfer for bridging
    /// @param noteCommitment The note commitment from Penumbra's shielded pool
    /// @param payload The bridge payload (recipient, amount, memo)
    /// @return relayId Unique relay operation identifier
    function relayShieldedTransfer(
        bytes32 noteCommitment,
        bytes calldata payload
    ) external payable returns (bytes32 relayId);

    /// @notice Estimate the relay fee for bridging
    /// @return fee The estimated relay fee in wei
    function estimateRelayFee() external view returns (uint256 fee);

    /// @notice Get the latest Penumbra epoch height synced by the relay
    /// @return height The latest synced epoch height
    function latestSyncedEpoch() external view returns (uint256 height);
}

/**
 * @title IPenumbraVerifier
 * @notice Interface for verifying Penumbra shielded proofs on EVM
 * @dev Penumbra uses Groth16 on the decaf377 curve embedded in BLS12-377.
 *      The verifier checks proofs that have been translated from decaf377
 *      to a BN254-friendly representation for EVM verification.
 */
interface IPenumbraVerifier {
    /// @notice Verify a translated Penumbra proof (decaf377 → BN254 wrapper)
    /// @param proof The proof data (BN254-wrapped Groth16 proof)
    /// @param publicInputs The public inputs (nullifiers, commitments, anchors)
    /// @return valid Whether the proof is valid
    function verifyPenumbraProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    /// @notice Get the current state commitment tree anchor
    /// @return anchor The current SCT anchor
    function currentAnchor() external view returns (bytes32 anchor);
}

/**
 * @title PenumbraBridgeAdapter
 * @notice ZASEON bridge adapter for Penumbra — fully-shielded IBC DEX chain
 * @dev Penumbra is a privacy-focused Cosmos SDK chain that uses:
 *      - Groth16 proofs on decaf377 (embedded in BLS12-377)
 *      - State Commitment Tree (SCT) for shielded note tracking
 *      - CometBFT consensus with instant finality
 *      - IBC-native cross-chain communication
 *      - Built-in DEX with private swaps (ZSwap)
 *
 *      This adapter bridges shielded Penumbra notes to ZASEON/Ethereum via
 *      a relay that translates decaf377 Groth16 proofs to BN254 for EVM verification.
 *
 *      Key differences from Zcash adapter:
 *      - Cosmos SDK + CometBFT (not PoW)
 *      - Groth16 on decaf377 (not Halo 2 on Pallas/Vesta)
 *      - IBC-native (not custom relay)
 *      - Built-in DEX (ZSwap) for private swaps
 *      - All transactions shielded by default (no transparent pool)
 */
contract PenumbraBridgeAdapter is
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

    /// @notice ZASEON internal virtual chain ID for Penumbra
    uint16 public constant PENUMBRA_CHAIN_ID = 9100;

    /// @notice CometBFT instant deterministic finality (1 block)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Minimum proof size (Groth16 BN254 translation)
    uint256 public constant MIN_PROOF_SIZE = 64;

    /// @notice Maximum protocol fee (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length to prevent DoS
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /*//////////////////////////////////////////////////////////////
                             STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Penumbra bridge relay contract
    IPenumbraBridge public penumbraBridge;

    /// @notice Penumbra proof verifier contract
    IPenumbraVerifier public penumbraVerifier;

    /// @notice Verified SCT (State Commitment Tree) anchors
    mapping(bytes32 => bool) public verifiedAnchors;

    /// @notice Used nullifiers (replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Message hash → verified
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Sender nonces for ordering
    mapping(address => uint256) public senderNonces;

    /// @notice Protocol fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum fee per message
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (wei)
    uint256 public totalValueBridged;

    /*//////////////////////////////////////////////////////////////
                             EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        bytes32 noteCommitment,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 anchor,
        bytes32 indexed nullifier,
        bytes payload
    );

    event BridgeConfigUpdated(string param, address value);
    event AnchorRegistered(bytes32 indexed anchor);
    event FeeUpdated(string param, uint256 value);

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
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy the Penumbra bridge adapter
    /// @param _penumbraBridge Address of the Penumbra relay bridge
    /// @param _penumbraVerifier Address of the Penumbra proof verifier
    /// @param _admin Default admin address
    constructor(
        address _penumbraBridge,
        address _penumbraVerifier,
        address _admin
    ) {
        if (_penumbraBridge == address(0)) revert InvalidBridge();
        if (_penumbraVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        penumbraBridge = IPenumbraBridge(_penumbraBridge);
        penumbraVerifier = IPenumbraVerifier(_penumbraVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                     SEND (ZASEON → PENUMBRA)
    //////////////////////////////////////////////////////////////*/

    /// @notice Send a shielded note commitment to Penumbra
    /// @param noteCommitment The SCT note commitment
    /// @param payload The bridge payload
    /// @return messageHash The unique message identifier
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

        uint256 relayFee = penumbraBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        // Protocol fee
        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 relayId = penumbraBridge.relayShieldedTransfer{
            value: msg.value - protocolFee
        }(noteCommitment, payload);

        messageHash = keccak256(
            abi.encodePacked(
                PENUMBRA_CHAIN_ID,
                msg.sender,
                noteCommitment,
                nonce,
                relayId
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageHash, msg.sender, noteCommitment, msg.value);
    }

    /*//////////////////////////////////////////////////////////////
                   RECEIVE (PENUMBRA → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /// @notice Receive and verify a Penumbra shielded proof
    /// @param proof The BN254-wrapped Groth16 proof
    /// @param publicInputs Public inputs: [anchor, nullifier, noteCommitment, payloadHash]
    /// @param payload The original payload
    /// @return messageHash The verified message identifier
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
        if (proof.length < MIN_PROOF_SIZE) revert InvalidProof();

        // Verify proof
        bool valid = penumbraVerifier.verifyPenumbraProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        // Extract nullifier
        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 anchor = bytes32(publicInputs[0]);

        messageHash = keccak256(
            abi.encodePacked(
                PENUMBRA_CHAIN_ID,
                anchor,
                nullifier,
                keccak256(payload)
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, anchor, nullifier, payload);
    }

    /*//////////////////////////////////////////////////////////////
                    IBridgeAdapter INTERFACE
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

        bytes32 noteCommitment = keccak256(
            abi.encodePacked(targetAddress, payload)
        );

        uint256 relayFee = penumbraBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 relayId = penumbraBridge.relayShieldedTransfer{
            value: msg.value - protocolFee
        }(noteCommitment, payload);

        messageId = keccak256(
            abi.encodePacked(
                PENUMBRA_CHAIN_ID,
                msg.sender,
                noteCommitment,
                nonce,
                relayId
            )
        );

        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, noteCommitment, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        nativeFee = penumbraBridge.estimateRelayFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the ZASEON chain ID for Penumbra
    function chainId() external pure returns (uint16) {
        return PENUMBRA_CHAIN_ID;
    }

    /// @notice Get the chain name
    function chainName() external pure returns (string memory) {
        return "Penumbra";
    }

    /// @notice Check if the adapter is configured
    function isConfigured() external view returns (bool) {
        return
            address(penumbraBridge) != address(0) &&
            address(penumbraVerifier) != address(0);
    }

    /// @notice Get the finality block count
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Get the current SCT anchor from verifier
    function getSCTAnchor() external view returns (bytes32) {
        return penumbraVerifier.currentAnchor();
    }

    /// @notice Get the latest synced epoch height
    function getLatestSyncedEpoch() external view returns (uint256) {
        return penumbraBridge.latestSyncedEpoch();
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Penumbra bridge relay address
    function setPenumbraBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        penumbraBridge = IPenumbraBridge(_bridge);
        emit BridgeConfigUpdated("penumbraBridge", _bridge);
    }

    /// @notice Update the Penumbra proof verifier address
    function setPenumbraVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        penumbraVerifier = IPenumbraVerifier(_verifier);
        emit BridgeConfigUpdated("penumbraVerifier", _verifier);
    }

    /// @notice Register a verified SCT anchor
    function registerAnchor(
        bytes32 _anchor
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_anchor == bytes32(0)) revert InvalidAnchor();
        verifiedAnchors[_anchor] = true;
        emit AnchorRegistered(_anchor);
    }

    /// @notice Set the protocol fee in basis points
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        bridgeFee = _fee;
        emit FeeUpdated("bridgeFee", _fee);
    }

    /// @notice Set the minimum fee per message
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minMessageFee = _fee;
        emit FeeUpdated("minMessageFee", _fee);
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY & FEE WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated protocol fees
    function withdrawFees(
        address payable _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = _to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ETH
    function emergencyWithdrawETH(
        address payable _to,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        (bool ok, ) = _to.call{value: _amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ERC-20 tokens
    function emergencyWithdrawERC20(
        address _token,
        address _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_token == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(_to, balance);
    }

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Accept ETH
    receive() external payable {}
}
