// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IFantomBridge
 * @notice Minimal interface for Fantom/Sonic–Ethereum bridge relay
 * @dev Fantom evolved into Sonic — a high-performance EVM L1 using the Lachesis
 *      DAG-based aBFT consensus. Sonic provides sub-second finality and
 *      native bridge capabilities via the Sonic Gateway.
 */
interface IFantomBridge {
    function relayToSonic(
        bytes32 destinationChainId,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    function estimateRelayFee() external view returns (uint256 fee);

    function latestVerifiedBlock() external view returns (uint256 height);
}

/**
 * @title ILachesisVerifier
 * @notice Interface for verifying Lachesis aBFT proofs on Ethereum
 * @dev Validates DAG-based asynchronous BFT consensus proofs from the
 *      Fantom/Sonic validator network.
 */
interface ILachesisVerifier {
    function verifyLachesisProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentValidatorSetHash() external view returns (bytes32);
}

/**
 * @title FantomSonicBridgeAdapter
 * @notice ZASEON bridge adapter for Fantom/Sonic — DAG-based aBFT EVM L1
 * @dev Fantom/Sonic uses:
 *      - Lachesis aBFT consensus (DAG-based, sub-second finality)
 *      - Full EVM compatibility
 *      - Sonic Gateway for native cross-chain bridging
 *      - FTM/S native token
 *      - Andre Cronje ecosystem (DeFi-heavy)
 *      - Wormhole + Axelar cross-chain support
 *
 *      This adapter bridges ZASEON ↔ Fantom/Sonic using Lachesis aBFT
 *      proofs for trustless cross-chain verification.
 */
contract FantomSonicBridgeAdapter is
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

    uint16 public constant FANTOM_SONIC_CHAIN_ID = 23_100;
    uint256 public constant FINALITY_BLOCKS = 1;
    uint256 public constant MIN_PROOF_SIZE = 48;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;
    bytes32 public constant SONIC_MAINNET_TAG = keccak256("SONIC_MAINNET");

    IFantomBridge public fantomBridge;
    ILachesisVerifier public lachesisVerifier;

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

    constructor(
        address _fantomBridge,
        address _lachesisVerifier,
        address _admin
    ) {
        if (_fantomBridge == address(0)) revert InvalidBridge();
        if (_lachesisVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        fantomBridge = IFantomBridge(_fantomBridge);
        lachesisVerifier = ILachesisVerifier(_lachesisVerifier);

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

        uint256 relayFee = fantomBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 relayId = fantomBridge.relayToSonic{
            value: msg.value - protocolFee
        }(destinationChainId, payload);

        messageHash = keccak256(
            abi.encodePacked(
                FANTOM_SONIC_CHAIN_ID,
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

        bool valid = lachesisVerifier.verifyLachesisProof(
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
                FANTOM_SONIC_CHAIN_ID,
                validatorSetHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, validatorSetHash, nullifier, payload);
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

        uint256 relayFee = fantomBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        bytes32 transferId = fantomBridge.relayToSonic{
            value: msg.value - protocolFee
        }(SONIC_MAINNET_TAG, payload);

        messageId = keccak256(
            abi.encodePacked(
                FANTOM_SONIC_CHAIN_ID,
                msg.sender,
                SONIC_MAINNET_TAG,
                nonce,
                transferId
            )
        );
        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, SONIC_MAINNET_TAG, msg.value);
    }

    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = fantomBridge.estimateRelayFee() + minMessageFee;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return FANTOM_SONIC_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Fantom/Sonic";
    }

    function isConfigured() external view returns (bool) {
        return
            address(fantomBridge) != address(0) &&
            address(lachesisVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function getCurrentValidatorSetHash() external view returns (bytes32) {
        return lachesisVerifier.currentValidatorSetHash();
    }

    function getLatestVerifiedBlock() external view returns (uint256) {
        return fantomBridge.latestVerifiedBlock();
    }

    function setFantomBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        fantomBridge = IFantomBridge(_bridge);
        emit BridgeConfigUpdated("fantomBridge", _bridge);
    }

    function setLachesisVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        lachesisVerifier = ILachesisVerifier(_verifier);
        emit BridgeConfigUpdated("lachesisVerifier", _verifier);
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
