// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IFilecoinBridge
 * @notice Minimal interface for Filecoin FVM–Ethereum bridge relay
 * @dev Filecoin's FEVM provides full EVM compatibility. The bridge uses
 *      storage proof verification — Filecoin's proof-of-replication and
 *      proof-of-spacetime form the consensus layer.
 */
interface IFilecoinBridge {
    function relayToFilecoin(
        bytes32 destinationChainId,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    function estimateRelayFee() external view returns (uint256 fee);

    function latestVerifiedTipset() external view returns (uint256 height);
}

/**
 * @title IFilecoinProofVerifier
 * @notice Interface for verifying Filecoin consensus proofs on Ethereum
 * @dev Validates Filecoin tipset headers using Expected Consensus (EC)
 *      miner power tables and WinningPoSt proofs.
 */
interface IFilecoinProofVerifier {
    function verifyFilecoinProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentPowerTableHash() external view returns (bytes32);
}

/**
 * @title FilecoinBridgeAdapter
 * @notice ZASEON bridge adapter for Filecoin — decentralized storage L1 with FEVM
 * @dev Filecoin uses:
 *      - Expected Consensus (EC) with Proof-of-Storage (PoRep + PoSt)
 *      - FEVM: Full EVM compatibility via FVM
 *      - 30-second block time (tipsets)
 *      - Native FIL token
 *      - Storage proofs provide unique ZK verification opportunities
 *      - Axelar and Celer already bridge to Filecoin
 *
 *      This adapter bridges ZASEON ↔ Filecoin using EC consensus
 *      proofs for trustless cross-chain state verification.
 */
contract FilecoinBridgeAdapter is
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

    uint16 public constant FILECOIN_CHAIN_ID = 22_100;
    uint256 public constant FINALITY_BLOCKS = 900; // ~900 tipsets (~7.5h finality)
    uint256 public constant MIN_PROOF_SIZE = 48;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;
    bytes32 public constant FILECOIN_MAINNET_TAG =
        keccak256("FILECOIN_MAINNET");

    IFilecoinBridge public filecoinBridge;
    IFilecoinProofVerifier public proofVerifier;

    mapping(bytes32 => bool) public verifiedPowerTables;
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
        bytes32 powerTableHash,
        bytes32 indexed nullifier,
        bytes payload
    );
    event BridgeConfigUpdated(string param, address value);
    event PowerTableRegistered(bytes32 indexed powerTableHash);
    event FeeUpdated(string param, uint256 value);

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidPowerTable();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    constructor(
        address _filecoinBridge,
        address _proofVerifier,
        address _admin
    ) {
        if (_filecoinBridge == address(0)) revert InvalidBridge();
        if (_proofVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        filecoinBridge = IFilecoinBridge(_filecoinBridge);
        proofVerifier = IFilecoinProofVerifier(_proofVerifier);

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

        uint256 relayFee = filecoinBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 relayId = filecoinBridge.relayToFilecoin{
            value: msg.value - protocolFee
        }(destinationChainId, payload);

        messageHash = keccak256(
            abi.encodePacked(
                FILECOIN_CHAIN_ID,
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

        bool valid = proofVerifier.verifyFilecoinProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 powerTableHash = bytes32(publicInputs[0]);
        messageHash = keccak256(
            abi.encodePacked(
                FILECOIN_CHAIN_ID,
                powerTableHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, powerTableHash, nullifier, payload);
    }

    /// @inheritdoc IBridgeAdapter
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

        uint256 relayFee = filecoinBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 transferId = filecoinBridge.relayToFilecoin{
            value: msg.value - protocolFee
        }(FILECOIN_MAINNET_TAG, payload);

        messageId = keccak256(
            abi.encodePacked(
                FILECOIN_CHAIN_ID,
                msg.sender,
                FILECOIN_MAINNET_TAG,
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
            FILECOIN_MAINNET_TAG,
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = filecoinBridge.estimateRelayFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return FILECOIN_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Filecoin";
    }

    function isConfigured() external view returns (bool) {
        return
            address(filecoinBridge) != address(0) &&
            address(proofVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentPowerTableHash() external view returns (bytes32) {
        return proofVerifier.currentPowerTableHash();
    }

    function getLatestVerifiedTipset() external view returns (uint256) {
        return filecoinBridge.latestVerifiedTipset();
    }

    function setFilecoinBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        filecoinBridge = IFilecoinBridge(_bridge);
        emit BridgeConfigUpdated("filecoinBridge", _bridge);
    }

    function setProofVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        proofVerifier = IFilecoinProofVerifier(_verifier);
        emit BridgeConfigUpdated("proofVerifier", _verifier);
    }

    function registerPowerTable(
        bytes32 _hash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_hash == bytes32(0)) revert InvalidPowerTable();
        verifiedPowerTables[_hash] = true;
        emit PowerTableRegistered(_hash);
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
