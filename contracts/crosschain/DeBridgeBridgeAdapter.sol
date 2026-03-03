// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IDeBridgeGate
 * @notice Minimal interface for the deBridge Gate contract
 * @dev deBridge uses an intent-based model where takers fill orders
 *      cross-chain and claim settlement via deBridge validators.
 *      The DLN (deBridge Liquidity Network) provides the liquidity layer.
 */
interface IDeBridgeGate {
    /// @notice Send a cross-chain message/transfer
    /// @param dstChainId The destination chain ID
    /// @param receiver The recipient address (bytes)
    /// @param permit The permit data (empty if no approval)
    /// @param autoParams Auto-execute parameters on destination
    /// @param referralCode Referral code
    /// @param payload The message payload
    function send(
        uint256 dstChainId,
        bytes calldata receiver,
        bytes calldata permit,
        bytes calldata autoParams,
        uint32 referralCode,
        bytes calldata payload
    ) external payable returns (bytes32 submissionId);

    /// @notice Estimate the send fee
    function getChainFee(uint256 _chainId) external view returns (uint256);
}

/**
 * @title IDeBridgeValidator
 * @notice Interface for verifying deBridge cross-chain proofs
 */
interface IDeBridgeValidator {
    function verifySubmission(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentValidatorSetHash() external view returns (bytes32);
}

/**
 * @title DeBridgeBridgeAdapter
 * @notice ZASEON bridge adapter for deBridge — intent-based cross-chain protocol
 * @dev deBridge uses:
 *      - Intent-based model (DLN — deBridge Liquidity Network)
 *      - deBridge validators for cross-chain message verification
 *      - Supports 12+ EVM chains + Solana
 *      - ~$5B+ cumulative volume
 *      - Fast cross-chain swaps via taker network
 *      - Zero slippage for matched orders
 *
 *      This adapter bridges ZASEON ↔ any deBridge-supported chain
 *      using deBridge validator attestations.
 */
contract DeBridgeBridgeAdapter is
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

    uint16 public constant DEBRIDGE_PROTOCOL_ID = 30_100;
    uint256 public constant FINALITY_BLOCKS = 1; // Intent-based
    uint256 public constant MIN_PROOF_SIZE = 32;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    IDeBridgeGate public deBridgeGate;
    IDeBridgeValidator public deBridgeValidator;

    /// @notice Default destination chain ID
    uint256 public defaultDestinationChainId;

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
    event FeeUpdated(string param, uint256 value);

    error InvalidBridge();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    constructor(
        address _deBridgeGate,
        address _deBridgeValidator,
        address _admin
    ) {
        if (_deBridgeGate == address(0)) revert InvalidBridge();
        if (_deBridgeValidator == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        deBridgeGate = IDeBridgeGate(_deBridgeGate);
        deBridgeValidator = IDeBridgeValidator(_deBridgeValidator);

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

        uint256 totalRequired = minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 submissionId = deBridgeGate.send{
            value: msg.value - protocolFee
        }(
            uint256(destinationChainId),
            abi.encodePacked(msg.sender),
            "",
            "",
            0,
            payload
        );

        messageHash = keccak256(
            abi.encodePacked(
                DEBRIDGE_PROTOCOL_ID,
                msg.sender,
                destinationChainId,
                nonce,
                submissionId
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

        bool valid = deBridgeValidator.verifySubmission(
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
                DEBRIDGE_PROTOCOL_ID,
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

        uint256 totalRequired = minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;
        uint256 destChain = defaultDestinationChainId > 0
            ? defaultDestinationChainId
            : 1;

        bytes32 submissionId = deBridgeGate.send{
            value: msg.value - protocolFee
        }(destChain, abi.encodePacked(targetAddress), "", "", 0, payload);

        messageId = keccak256(
            abi.encodePacked(
                DEBRIDGE_PROTOCOL_ID,
                msg.sender,
                bytes32(destChain),
                nonce,
                submissionId
            )
        );
        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(messageId, msg.sender, bytes32(destChain), msg.value);
    }

    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        nativeFee = minMessageFee;
    }

    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    function chainId() external pure returns (uint16) {
        return DEBRIDGE_PROTOCOL_ID;
    }

    function chainName() external pure returns (string memory) {
        return "deBridge";
    }

    function isConfigured() external view returns (bool) {
        return
            address(deBridgeGate) != address(0) &&
            address(deBridgeValidator) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function setDeBridgeGate(
        address _gate
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_gate == address(0)) revert InvalidBridge();
        deBridgeGate = IDeBridgeGate(_gate);
        emit BridgeConfigUpdated("deBridgeGate", _gate);
    }

    function setDeBridgeValidator(
        address _validator
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_validator == address(0)) revert InvalidVerifier();
        deBridgeValidator = IDeBridgeValidator(_validator);
        emit BridgeConfigUpdated("deBridgeValidator", _validator);
    }

    function setDefaultDestinationChainId(
        uint256 _chainId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        defaultDestinationChainId = _chainId;
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
