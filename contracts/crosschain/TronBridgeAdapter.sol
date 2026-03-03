// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title ITronBridge
 * @notice Minimal interface for Tron–Ethereum bridge relay
 * @dev Tron is a DPoS Layer 1 with TVM (EVM-compatible). The bridge uses
 *      a multi-signature committee that validates cross-chain messages
 *      between Ethereum and Tron. Tron's 3-second block time and DPoS
 *      finality provide fast bridging with minimal confirmation latency.
 */
interface ITronBridge {
    /// @notice Relay a message to Tron network
    /// @param tronRecipient The Tron address (base58 encoded as bytes)
    /// @param payload The bridge payload
    /// @return messageId Unique message identifier
    function relayToTron(
        bytes calldata tronRecipient,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    /// @notice Estimate the relay fee
    /// @return fee The estimated relay fee in wei
    function estimateRelayFee() external view returns (uint256 fee);

    /// @notice Get the latest verified Tron block number
    /// @return height The latest verified block number
    function latestVerifiedBlock() external view returns (uint256 height);
}

/**
 * @title ITronProofVerifier
 * @notice Interface for verifying Tron DPoS proofs on Ethereum
 * @dev Validates Tron block headers signed by the Super Representative (SR)
 *      committee. Tron uses 27 Super Representatives with 6-second vote cycles.
 */
interface ITronProofVerifier {
    /// @notice Verify a Tron DPoS committee consensus proof
    /// @param proof The SR committee signature proof
    /// @param publicInputs Public verification inputs
    /// @return valid Whether the proof is valid
    function verifyTronProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    /// @notice Get the current SR committee hash
    /// @return committeeHash The hash of the current SR committee
    function currentCommitteeHash()
        external
        view
        returns (bytes32 committeeHash);
}

/**
 * @title TronBridgeAdapter
 * @notice ZASEON bridge adapter for Tron — DPoS L1 with TVM (EVM-compatible)
 * @dev Tron uses:
 *      - Delegated Proof of Stake (DPoS) with 27 Super Representatives
 *      - TVM: EVM-compatible virtual machine (Solidity support)
 *      - 3-second block time with single-slot finality
 *      - TRC-20 token standard (ERC-20 equivalent)
 *      - Massive USDT stablecoin volume ($50B+ daily)
 *      - Energy & bandwidth resource model instead of gas
 *
 *      This adapter bridges ZASEON ↔ Tron messages using
 *      SR committee attestation verification for trustless cross-chain proofs.
 */
contract TronBridgeAdapter is
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

    /// @notice ZASEON internal virtual chain ID for Tron
    uint16 public constant TRON_CHAIN_ID = 20_100;

    /// @notice Tron 3-second blocks, DPoS single-slot finality
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Minimum proof size for DPoS committee proofs
    uint256 public constant MIN_PROOF_SIZE = 48;

    /// @notice Maximum protocol fee (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Tron mainnet chain tag
    bytes32 public constant TRON_MAINNET_TAG = keccak256("TRON_MAINNET");

    /*//////////////////////////////////////////////////////////////
                             STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Tron bridge relay contract
    ITronBridge public tronBridge;

    /// @notice DPoS proof verifier
    ITronProofVerifier public proofVerifier;

    /// @notice Verified SR committee hashes
    mapping(bytes32 => bool) public verifiedCommittees;

    /// @notice Used nullifiers (replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Message hash → verified
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Sender nonces
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
        bytes32 destinationChainId,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 committeeHash,
        bytes32 indexed nullifier,
        bytes payload
    );

    event BridgeConfigUpdated(string param, address value);
    event CommitteeRegistered(bytes32 indexed committeeHash);
    event FeeUpdated(string param, uint256 value);

    /*//////////////////////////////////////////////////////////////
                             ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidCommittee();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _tronBridge, address _proofVerifier, address _admin) {
        if (_tronBridge == address(0)) revert InvalidBridge();
        if (_proofVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        tronBridge = ITronBridge(_tronBridge);
        proofVerifier = ITronProofVerifier(_proofVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                   SEND (ZASEON → TRON)
    //////////////////////////////////////////////////////////////*/

    function sendMessage(
        bytes32 destinationChainId,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (destinationChainId == bytes32(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        uint256 relayFee = tronBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 relayId = tronBridge.relayToTron{
            value: msg.value - protocolFee
        }(abi.encodePacked(destinationChainId), payload);

        messageHash = keccak256(
            abi.encodePacked(
                TRON_CHAIN_ID,
                msg.sender,
                destinationChainId,
                nonce,
                relayId
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            destinationChainId,
            msg.value
        );
    }

    /*//////////////////////////////////////////////////////////////
                 RECEIVE (TRON → ZASEON)
    //////////////////////////////////////////////////////////////*/

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

        bool valid = proofVerifier.verifyTronProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 committeeHash = bytes32(publicInputs[0]);

        messageHash = keccak256(
            abi.encodePacked(
                TRON_CHAIN_ID,
                committeeHash,
                nullifier,
                keccak256(payload)
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, committeeHash, nullifier, payload);
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

        uint256 relayFee = tronBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 transferId = tronBridge.relayToTron{
            value: msg.value - protocolFee
        }(abi.encodePacked(targetAddress), payload);

        messageId = keccak256(
            abi.encodePacked(
                TRON_CHAIN_ID,
                msg.sender,
                TRON_MAINNET_TAG,
                nonce,
                transferId
            )
        );

        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, TRON_MAINNET_TAG, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        nativeFee = tronBridge.estimateRelayFee() + minMessageFee;
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

    function chainId() external pure returns (uint16) {
        return TRON_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Tron";
    }

    function isConfigured() external view returns (bool) {
        return
            address(tronBridge) != address(0) &&
            address(proofVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentCommitteeHash() external view returns (bytes32) {
        return proofVerifier.currentCommitteeHash();
    }

    function getLatestVerifiedBlock() external view returns (uint256) {
        return tronBridge.latestVerifiedBlock();
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function setTronBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        tronBridge = ITronBridge(_bridge);
        emit BridgeConfigUpdated("tronBridge", _bridge);
    }

    function setProofVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        proofVerifier = ITronProofVerifier(_verifier);
        emit BridgeConfigUpdated("proofVerifier", _verifier);
    }

    function registerCommittee(
        bytes32 _committeeHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_committeeHash == bytes32(0)) revert InvalidCommittee();
        verifiedCommittees[_committeeHash] = true;
        emit CommitteeRegistered(_committeeHash);
    }

    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        bridgeFee = _fee;
        emit FeeUpdated("bridgeFee", _fee);
    }

    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minMessageFee = _fee;
        emit FeeUpdated("minMessageFee", _fee);
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY & FEE WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    function withdrawFees(
        address payable _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = _to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function emergencyWithdrawETH(
        address payable _to,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        (bool ok, ) = _to.call{value: _amount}("");
        if (!ok) revert TransferFailed();
    }

    function emergencyWithdrawERC20(
        address _token,
        address _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_token == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(_to, balance);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    receive() external payable {}
}
