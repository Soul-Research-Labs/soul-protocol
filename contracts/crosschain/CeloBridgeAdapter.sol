// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title ICeloBridge
 * @notice Minimal interface for Celo–Ethereum bridge relay
 * @dev Celo is a mobile-first EVM-compatible PoS L1 with ultra-light client
 *      verification. Uses plumo SNARK light client proofs for efficient
 *      cross-chain header verification. Natively supports Hyperlane.
 */
interface ICeloBridge {
    function relayToCelo(
        bytes32 destinationChainId,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    function estimateRelayFee() external view returns (uint256 fee);

    function latestVerifiedBlock() external view returns (uint256 height);
}

/**
 * @title ICeloLightClient
 * @notice Interface for verifying Celo light client proofs on Ethereum
 * @dev Uses plumo SNARK proofs for efficient ECBLS validator signature
 *      verification. Celo validators sign blocks using BLS over BN254.
 */
interface ICeloLightClient {
    function verifyCeloProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentValidatorSetHash()
        external
        view
        returns (bytes32 validatorSetHash);
}

/**
 * @title CeloBridgeAdapter
 * @notice ZASEON bridge adapter for Celo — mobile-first EVM-compatible PoS L1
 * @dev Celo uses:
 *      - EVM-compatible execution (full Solidity support)
 *      - BFT PoS consensus (instant finality at ~5 seconds)
 *      - Plumo SNARK light client proofs
 *      - Phone number identity attestations
 *      - Multi-currency gas fee support (cUSD, cEUR, cREAL, CELO)
 *      - 20M+ users via MiniPay in Africa
 *      - Native Hyperlane & Wormhole bridge support
 *
 *      This adapter bridges ZASEON ↔ Celo using plumo light client
 *      proofs for trustless cross-chain verification.
 */
contract CeloBridgeAdapter is
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

    /// @notice ZASEON internal virtual chain ID for Celo
    uint16 public constant CELO_CHAIN_ID = 21_100;

    /// @notice Celo BFT instant finality (~5 seconds)
    uint256 public constant FINALITY_BLOCKS = 1;

    uint256 public constant MIN_PROOF_SIZE = 48;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    bytes32 public constant CELO_MAINNET_TAG = keccak256("CELO_MAINNET");

    ICeloBridge public celoBridge;
    ICeloLightClient public lightClient;

    mapping(bytes32 => bool) public verifiedValidatorSets;
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
        bytes32 validatorSetHash,
        bytes32 indexed nullifier,
        bytes payload
    );
    event BridgeConfigUpdated(string param, address value);
    event ValidatorSetRegistered(bytes32 indexed validatorSetHash);
    event FeeUpdated(string param, uint256 value);

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidValidatorSet();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    constructor(address _celoBridge, address _lightClient, address _admin) {
        if (_celoBridge == address(0)) revert InvalidBridge();
        if (_lightClient == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        celoBridge = ICeloBridge(_celoBridge);
        lightClient = ICeloLightClient(_lightClient);

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

        uint256 relayFee = celoBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 relayId = celoBridge.relayToCelo{
            value: msg.value - protocolFee
        }(destinationChainId, payload);

        messageHash = keccak256(
            abi.encodePacked(
                CELO_CHAIN_ID,
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

        bool valid = lightClient.verifyCeloProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 validatorSetHash = bytes32(publicInputs[0]);
        messageHash = keccak256(
            abi.encodePacked(
                CELO_CHAIN_ID,
                validatorSetHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, validatorSetHash, nullifier, payload);
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

        uint256 relayFee = celoBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 transferId = celoBridge.relayToCelo{
            value: msg.value - protocolFee
        }(CELO_MAINNET_TAG, payload);

        messageId = keccak256(
            abi.encodePacked(
                CELO_CHAIN_ID,
                msg.sender,
                CELO_MAINNET_TAG,
                nonce,
                transferId
            )
        );
        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, CELO_MAINNET_TAG, msg.value);
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = celoBridge.estimateRelayFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return CELO_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Celo";
    }

    function isConfigured() external view returns (bool) {
        return
            address(celoBridge) != address(0) &&
            address(lightClient) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentValidatorSetHash() external view returns (bytes32) {
        return lightClient.currentValidatorSetHash();
    }

    function getLatestVerifiedBlock() external view returns (uint256) {
        return celoBridge.latestVerifiedBlock();
    }

    function setCeloBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        celoBridge = ICeloBridge(_bridge);
        emit BridgeConfigUpdated("celoBridge", _bridge);
    }

    function setLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_client == address(0)) revert InvalidVerifier();
        lightClient = ICeloLightClient(_client);
        emit BridgeConfigUpdated("lightClient", _client);
    }

    function registerValidatorSet(
        bytes32 _hash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_hash == bytes32(0)) revert InvalidValidatorSet();
        verifiedValidatorSets[_hash] = true;
        emit ValidatorSetRegistered(_hash);
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
