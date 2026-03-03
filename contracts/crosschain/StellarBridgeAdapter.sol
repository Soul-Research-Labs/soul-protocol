// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IStellarBridge
 * @notice Minimal interface for Stellar–Ethereum bridge relay
 * @dev Stellar uses the Stellar Consensus Protocol (SCP), a Federated
 *      Byzantine Agreement (FBA) system. Soroban smart contracts run on
 *      a WASM-based VM. The bridge uses anchor-based relay or Wormhole.
 */
interface IStellarBridge {
    function relayToStellar(
        bytes calldata stellarRecipient,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    function estimateRelayFee() external view returns (uint256 fee);

    function latestVerifiedLedger() external view returns (uint256 ledger);
}

/**
 * @title IStellarSCPVerifier
 * @notice Interface for verifying Stellar SCP consensus proofs on Ethereum
 * @dev Validates Stellar Consensus Protocol quorum slices and
 *      ballot/prepare/commit phases for ledger close proofs.
 */
interface IStellarSCPVerifier {
    function verifySCPProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentQuorumHash() external view returns (bytes32);
}

/**
 * @title StellarBridgeAdapter
 * @notice ZASEON bridge adapter for Stellar — FBA L1 with Soroban smart contracts
 * @dev Stellar uses:
 *      - Stellar Consensus Protocol (SCP) — Federated Byzantine Agreement
 *      - 5-second ledger close time
 *      - Soroban: WASM-based smart contract platform (Rust)
 *      - XLM native token
 *      - Strong payments/remittance focus
 *      - Stellar Development Foundation partnerships
 *      - Cross-border privacy payments align with ZASEON mission
 *
 *      This adapter bridges ZASEON ↔ Stellar using SCP consensus
 *      proof verification for trustless cross-chain state transfer.
 */
contract StellarBridgeAdapter is
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

    uint16 public constant STELLAR_CHAIN_ID = 27_100;
    uint256 public constant FINALITY_BLOCKS = 1; // SCP instant finality (~5 seconds)
    uint256 public constant MIN_PROOF_SIZE = 64;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;
    bytes32 public constant STELLAR_MAINNET_TAG = keccak256("STELLAR_MAINNET");

    IStellarBridge public stellarBridge;
    IStellarSCPVerifier public scpVerifier;

    mapping(bytes32 => bool) public verifiedQuorums;
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
        bytes32 quorumHash,
        bytes32 indexed nullifier,
        bytes payload
    );
    event BridgeConfigUpdated(string param, address value);
    event QuorumRegistered(bytes32 indexed quorumHash);
    event FeeUpdated(string param, uint256 value);

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidQuorum();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    constructor(address _stellarBridge, address _scpVerifier, address _admin) {
        if (_stellarBridge == address(0)) revert InvalidBridge();
        if (_scpVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        stellarBridge = IStellarBridge(_stellarBridge);
        scpVerifier = IStellarSCPVerifier(_scpVerifier);

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

        uint256 relayFee = stellarBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 relayId = stellarBridge.relayToStellar{
            value: msg.value - protocolFee
        }(abi.encodePacked(destinationChainId), payload);

        messageHash = keccak256(
            abi.encodePacked(
                STELLAR_CHAIN_ID,
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

        bool valid = scpVerifier.verifySCPProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 quorumHash = bytes32(publicInputs[0]);
        messageHash = keccak256(
            abi.encodePacked(
                STELLAR_CHAIN_ID,
                quorumHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, quorumHash, nullifier, payload);
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

        uint256 relayFee = stellarBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 transferId = stellarBridge.relayToStellar{
            value: msg.value - protocolFee
        }(abi.encodePacked(targetAddress), payload);

        messageId = keccak256(
            abi.encodePacked(
                STELLAR_CHAIN_ID,
                msg.sender,
                STELLAR_MAINNET_TAG,
                nonce,
                transferId
            )
        );
        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, STELLAR_MAINNET_TAG, msg.value);
    }

    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = stellarBridge.estimateRelayFee() + minMessageFee;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return STELLAR_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Stellar";
    }

    function isConfigured() external view returns (bool) {
        return
            address(stellarBridge) != address(0) &&
            address(scpVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentQuorumHash() external view returns (bytes32) {
        return scpVerifier.currentQuorumHash();
    }

    function getLatestVerifiedLedger() external view returns (uint256) {
        return stellarBridge.latestVerifiedLedger();
    }

    function setStellarBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        stellarBridge = IStellarBridge(_bridge);
        emit BridgeConfigUpdated("stellarBridge", _bridge);
    }

    function setSCPVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        scpVerifier = IStellarSCPVerifier(_verifier);
        emit BridgeConfigUpdated("scpVerifier", _verifier);
    }

    function registerQuorum(
        bytes32 _hash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_hash == bytes32(0)) revert InvalidQuorum();
        verifiedQuorums[_hash] = true;
        emit QuorumRegistered(_hash);
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
