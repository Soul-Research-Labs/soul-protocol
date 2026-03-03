// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IAlgorandBridge
 * @notice Minimal interface for Algorand–Ethereum bridge relay
 * @dev Algorand uses Pure Proof-of-Stake with instant finality (~3.3 seconds).
 *      The bridge uses Wormhole for cross-chain message attestation or can
 *      directly verify Algorand state proofs using VRF-based consensus proofs.
 */
interface IAlgorandBridge {
    function relayToAlgorand(
        bytes calldata algorandRecipient,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    function estimateRelayFee() external view returns (uint256 fee);

    function latestVerifiedRound() external view returns (uint256 round);
}

/**
 * @title IAlgorandStateProofVerifier
 * @notice Interface for verifying Algorand State Proofs on Ethereum
 * @dev Algorand State Proofs use Falcon post-quantum signatures and compact
 *      certificates. The verifier validates Merkle proofs over Algorand's
 *      state commitment tree with VRF-based committee selection.
 */
interface IAlgorandStateProofVerifier {
    function verifyAlgorandStateProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentParticipationHash() external view returns (bytes32);
}

/**
 * @title AlgorandBridgeAdapter
 * @notice ZASEON bridge adapter for Algorand — Pure PoS L1 with instant finality
 * @dev Algorand uses:
 *      - Pure Proof-of-Stake with VRF-based committee selection
 *      - Instant finality (~3.3 seconds, 0 forks guaranteed)
 *      - AVM: Algorand Virtual Machine (TEAL/PyTeal smart contracts)
 *      - State Proofs: compact certificates using Falcon signatures
 *      - Atomic Transfers: native multi-party atomic transactions
 *      - ALGO native token
 *      - ASA (Algorand Standard Assets) like ERC-20
 *      - Wormhole bridge support
 *
 *      This adapter bridges ZASEON ↔ Algorand using Algorand State Proofs
 *      (Falcon + compact certificates) for trustless cross-chain verification.
 */
contract AlgorandBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint16 public constant ALGORAND_CHAIN_ID = 26_100;
    uint256 public constant FINALITY_BLOCKS = 1; // Pure PoS instant finality
    uint256 public constant MIN_PROOF_SIZE = 64;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;
    bytes32 public constant ALGORAND_MAINNET_TAG =
        keccak256("ALGORAND_MAINNET");

    IAlgorandBridge public algorandBridge;
    IAlgorandStateProofVerifier public stateProofVerifier;

    mapping(bytes32 => bool) public verifiedParticipationKeys;
    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bool) public verifiedMessages;
    mapping(address => uint256) public senderNonces;

    uint256 public bridgeFee;
    uint256 public minMessageFee;
    uint256 public accumulatedFees;
    uint256 public totalMessagesSent;
    uint256 public totalMessagesReceived;
    uint256 public totalValueBridged;

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        bytes32 destinationChainId,
        uint256 value
    );
    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 participationHash,
        bytes32 indexed nullifier,
        bytes payload
    );
    event BridgeConfigUpdated(string param, address value);
    event ParticipationKeyRegistered(bytes32 indexed participationHash);
    event FeeUpdated(string param, uint256 value);

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidParticipationKey();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    constructor(
        address _algorandBridge,
        address _stateProofVerifier,
        address _admin
    ) {
        if (_algorandBridge == address(0)) revert InvalidBridge();
        if (_stateProofVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        algorandBridge = IAlgorandBridge(_algorandBridge);
        stateProofVerifier = IAlgorandStateProofVerifier(_stateProofVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

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

        uint256 relayFee = algorandBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 relayId = algorandBridge.relayToAlgorand{
            value: msg.value - protocolFee
        }(abi.encodePacked(destinationChainId), payload);

        messageHash = keccak256(
            abi.encodePacked(
                ALGORAND_CHAIN_ID,
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

        bool valid = stateProofVerifier.verifyAlgorandStateProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 participationHash = bytes32(publicInputs[0]);
        messageHash = keccak256(
            abi.encodePacked(
                ALGORAND_CHAIN_ID,
                participationHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(
            messageHash,
            participationHash,
            nullifier,
            payload
        );
    }

    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address
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

        uint256 relayFee = algorandBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 transferId = algorandBridge.relayToAlgorand{
            value: msg.value - protocolFee
        }(abi.encodePacked(targetAddress), payload);

        messageId = keccak256(
            abi.encodePacked(
                ALGORAND_CHAIN_ID,
                msg.sender,
                ALGORAND_MAINNET_TAG,
                nonce,
                transferId
            )
        );
        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageId,
            msg.sender,
            ALGORAND_MAINNET_TAG,
            msg.value
        );
    }

    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = algorandBridge.estimateRelayFee() + minMessageFee;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return ALGORAND_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Algorand";
    }

    function isConfigured() external view returns (bool) {
        return
            address(algorandBridge) != address(0) &&
            address(stateProofVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentParticipationHash() external view returns (bytes32) {
        return stateProofVerifier.currentParticipationHash();
    }

    function getLatestVerifiedRound() external view returns (uint256) {
        return algorandBridge.latestVerifiedRound();
    }

    function setAlgorandBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        algorandBridge = IAlgorandBridge(_bridge);
        emit BridgeConfigUpdated("algorandBridge", _bridge);
    }

    function setStateProofVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        stateProofVerifier = IAlgorandStateProofVerifier(_verifier);
        emit BridgeConfigUpdated("stateProofVerifier", _verifier);
    }

    function registerParticipationKey(
        bytes32 _hash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_hash == bytes32(0)) revert InvalidParticipationKey();
        verifiedParticipationKeys[_hash] = true;
        emit ParticipationKeyRegistered(_hash);
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
        IERC20(_token).safeTransfer(
            _to,
            IERC20(_token).balanceOf(address(this))
        );
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    receive() external payable {}
}
