// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IHederaBridge
 * @notice Minimal interface for Hedera–Ethereum bridge relay
 * @dev Hedera uses Hashgraph aBFT consensus with sub-second finality.
 *      The bridge uses Hedera Consensus Service (HCS) for message ordering
 *      and an EVM-compatible JSON-RPC relay for smart contract interaction.
 */
interface IHederaBridge {
    function relayToHedera(
        bytes32 destinationChainId,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    function estimateRelayFee() external view returns (uint256 fee);

    function latestVerifiedTimestamp()
        external
        view
        returns (uint256 timestamp);
}

/**
 * @title IHashgraphVerifier
 * @notice Interface for verifying Hedera Hashgraph state proofs on Ethereum
 * @dev Validates Hedera state proofs using gossip-about-gossip consensus
 *      with virtual voting. Hedera's aBFT consensus provides mathematical
 *      finality in ~3-5 seconds.
 */
interface IHashgraphVerifier {
    function verifyHashgraphProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentNodeSetHash() external view returns (bytes32);
}

/**
 * @title HederaBridgeAdapter
 * @notice ZASEON bridge adapter for Hedera — Hashgraph aBFT L1 with EVM relay
 * @dev Hedera uses:
 *      - Hashgraph aBFT consensus (gossip-about-gossip + virtual voting)
 *      - Sub-second mathematical finality (~3-5 seconds)
 *      - EVM-compatible smart contracts via JSON-RPC relay
 *      - Hedera Consensus Service (HCS) for message ordering
 *      - HBAR native token
 *      - Enterprise governing council (Google, IBM, Boeing, etc.)
 *      - Fixed low fees ($0.0001/tx for HCS, $0.05/tx for contracts)
 *
 *      This adapter bridges ZASEON ↔ Hedera using Hashgraph state
 *      proof verification for trustless cross-chain proofs.
 */
contract HederaBridgeAdapter is
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

    uint16 public constant HEDERA_CHAIN_ID = 25_100;
    uint256 public constant FINALITY_BLOCKS = 1; // Hashgraph aBFT instant finality
    uint256 public constant MIN_PROOF_SIZE = 48;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;
    bytes32 public constant HEDERA_MAINNET_TAG = keccak256("HEDERA_MAINNET");

    IHederaBridge public hederaBridge;
    IHashgraphVerifier public hashgraphVerifier;

    mapping(bytes32 => bool) public verifiedNodeSets;
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
        bytes32 nodeSetHash,
        bytes32 indexed nullifier,
        bytes payload
    );
    event BridgeConfigUpdated(string param, address value);
    event NodeSetRegistered(bytes32 indexed nodeSetHash);
    event FeeUpdated(string param, uint256 value);

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidNodeSet();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    constructor(
        address _hederaBridge,
        address _hashgraphVerifier,
        address _admin
    ) {
        if (_hederaBridge == address(0)) revert InvalidBridge();
        if (_hashgraphVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        hederaBridge = IHederaBridge(_hederaBridge);
        hashgraphVerifier = IHashgraphVerifier(_hashgraphVerifier);

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

        uint256 relayFee = hederaBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 relayId = hederaBridge.relayToHedera{
            value: msg.value - protocolFee
        }(destinationChainId, payload);

        messageHash = keccak256(
            abi.encodePacked(
                HEDERA_CHAIN_ID,
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

        bool valid = hashgraphVerifier.verifyHashgraphProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 nodeSetHash = bytes32(publicInputs[0]);
        messageHash = keccak256(
            abi.encodePacked(
                HEDERA_CHAIN_ID,
                nodeSetHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, nodeSetHash, nullifier, payload);
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

        uint256 relayFee = hederaBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 transferId = hederaBridge.relayToHedera{
            value: msg.value - protocolFee
        }(HEDERA_MAINNET_TAG, payload);

        messageId = keccak256(
            abi.encodePacked(
                HEDERA_CHAIN_ID,
                msg.sender,
                HEDERA_MAINNET_TAG,
                nonce,
                transferId
            )
        );
        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, HEDERA_MAINNET_TAG, msg.value);
    }

    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = hederaBridge.estimateRelayFee() + minMessageFee;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return HEDERA_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Hedera";
    }

    function isConfigured() external view returns (bool) {
        return
            address(hederaBridge) != address(0) &&
            address(hashgraphVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentNodeSetHash() external view returns (bytes32) {
        return hashgraphVerifier.currentNodeSetHash();
    }

    function getLatestVerifiedTimestamp() external view returns (uint256) {
        return hederaBridge.latestVerifiedTimestamp();
    }

    function setHederaBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        hederaBridge = IHederaBridge(_bridge);
        emit BridgeConfigUpdated("hederaBridge", _bridge);
    }

    function setHashgraphVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        hashgraphVerifier = IHashgraphVerifier(_verifier);
        emit BridgeConfigUpdated("hashgraphVerifier", _verifier);
    }

    function registerNodeSet(
        bytes32 _hash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_hash == bytes32(0)) revert InvalidNodeSet();
        verifiedNodeSets[_hash] = true;
        emit NodeSetRegistered(_hash);
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
