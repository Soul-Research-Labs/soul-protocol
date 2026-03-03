// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IOasisBridge
 * @notice Minimal interface for Oasis Sapphire–Ethereum bridge relay
 * @dev Oasis Sapphire is a confidential EVM runtime using TEE (SGX) for
 *      encrypted state and computation. This makes it a natural complement
 *      to ZASEON's privacy middleware.
 */
interface IOasisBridge {
    function relayToOasis(
        bytes32 destinationChainId,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    function estimateRelayFee() external view returns (uint256 fee);

    function latestVerifiedBlock() external view returns (uint256 height);
}

/**
 * @title IOasisProofVerifier
 * @notice Interface for verifying Oasis Sapphire TEE attestation proofs
 * @dev Validates SGX remote attestation reports from Oasis validator nodes.
 */
interface IOasisProofVerifier {
    function verifyOasisProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentCommitteeHash() external view returns (bytes32);
}

/**
 * @title OasisBridgeAdapter
 * @notice ZASEON bridge adapter for Oasis Sapphire — confidential EVM with TEE
 * @dev Oasis Network uses:
 *      - Sapphire ParaTime: Confidential EVM (encrypted state via SGX TEE)
 *      - PoS consensus with Tendermint BFT + fast finality
 *      - ParaTime architecture (parallel runtimes)
 *      - ROSE native token
 *      - Privacy-by-default: unique synergy with ZASEON
 *      - Wormhole bridge support
 *
 *      This adapter bridges ZASEON ↔ Oasis using TEE attestation
 *      verification for privacy-preserving cross-chain proofs.
 */
contract OasisBridgeAdapter is
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

    uint16 public constant OASIS_CHAIN_ID = 24_100;
    uint256 public constant FINALITY_BLOCKS = 1; // Tendermint BFT instant finality
    uint256 public constant MIN_PROOF_SIZE = 48;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;
    bytes32 public constant SAPPHIRE_MAINNET_TAG =
        keccak256("OASIS_SAPPHIRE_MAINNET");

    IOasisBridge public oasisBridge;
    IOasisProofVerifier public proofVerifier;

    mapping(bytes32 => bool) public verifiedCommittees;
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
        bytes32 committeeHash,
        bytes32 indexed nullifier,
        bytes payload
    );
    event BridgeConfigUpdated(string param, address value);
    event CommitteeRegistered(bytes32 indexed committeeHash);
    event FeeUpdated(string param, uint256 value);

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

    constructor(address _oasisBridge, address _proofVerifier, address _admin) {
        if (_oasisBridge == address(0)) revert InvalidBridge();
        if (_proofVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        oasisBridge = IOasisBridge(_oasisBridge);
        proofVerifier = IOasisProofVerifier(_proofVerifier);

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

        uint256 relayFee = oasisBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 relayId = oasisBridge.relayToOasis{
            value: msg.value - protocolFee
        }(destinationChainId, payload);

        messageHash = keccak256(
            abi.encodePacked(
                OASIS_CHAIN_ID,
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

        bool valid = proofVerifier.verifyOasisProof(
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
                OASIS_CHAIN_ID,
                committeeHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, committeeHash, nullifier, payload);
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

        uint256 relayFee = oasisBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 transferId = oasisBridge.relayToOasis{
            value: msg.value - protocolFee
        }(SAPPHIRE_MAINNET_TAG, payload);

        messageId = keccak256(
            abi.encodePacked(
                OASIS_CHAIN_ID,
                msg.sender,
                SAPPHIRE_MAINNET_TAG,
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
            SAPPHIRE_MAINNET_TAG,
            msg.value
        );
    }

    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = oasisBridge.estimateRelayFee() + minMessageFee;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return OASIS_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Oasis Sapphire";
    }

    function isConfigured() external view returns (bool) {
        return
            address(oasisBridge) != address(0) &&
            address(proofVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentCommitteeHash() external view returns (bytes32) {
        return proofVerifier.currentCommitteeHash();
    }

    function getLatestVerifiedBlock() external view returns (uint256) {
        return oasisBridge.latestVerifiedBlock();
    }

    function setOasisBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        oasisBridge = IOasisBridge(_bridge);
        emit BridgeConfigUpdated("oasisBridge", _bridge);
    }

    function setProofVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        proofVerifier = IOasisProofVerifier(_verifier);
        emit BridgeConfigUpdated("proofVerifier", _verifier);
    }

    function registerCommittee(
        bytes32 _hash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_hash == bytes32(0)) revert InvalidCommittee();
        verifiedCommittees[_hash] = true;
        emit CommitteeRegistered(_hash);
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
