// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IStargateRouter
 * @notice Minimal interface for the Stargate V2 Router
 * @dev Stargate provides omnichain-native asset bridging with unified liquidity
 *      pools. Built on LayerZero, it uses the Delta algorithm for guaranteed
 *      instant finality of cross-chain swaps.
 */
interface IStargateRouter {
    struct SendParam {
        uint32 dstEid; // LayerZero endpoint ID
        bytes32 to; // recipient as bytes32
        uint256 amountLD; // amount in local decimals
        uint256 minAmountLD; // min amount after slippage
        bytes extraOptions; // lz options
        bytes composeMsg; // compose message
        bytes oftCmd; // OFT command
    }

    struct MessagingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
    }

    function send(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable returns (bytes32 msgReceipt);

    function quoteSend(
        SendParam calldata _sendParam,
        bool _payInLzToken
    ) external view returns (MessagingFee memory);
}

/**
 * @title IStargateVerifier
 * @notice Interface for Stargate fill/delivery verification
 */
interface IStargateVerifier {
    function verifyDelivery(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentPoolHash() external view returns (bytes32);
}

/**
 * @title StargateBridgeAdapter
 * @notice ZASEON bridge adapter for Stargate — LayerZero omnichain asset bridge
 * @dev Stargate uses:
 *      - LayerZero V2 messaging infrastructure
 *      - Unified liquidity pools across chains (Delta algorithm)
 *      - Guaranteed instant finality for cross-chain swaps
 *      - OFT (Omnichain Fungible Token) standard
 *      - ~$15B+ cumulative volume
 *      - Supports 15+ chains natively
 *      - Natural extension of existing LayerZero adapter
 *
 *      This adapter provides Stargate-specific cross-chain asset bridging
 *      with unified liquidity for ZASEON privacy flows.
 */
contract StargateBridgeAdapter is
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

    uint16 public constant STARGATE_PROTOCOL_ID = 29_100;
    uint256 public constant FINALITY_BLOCKS = 1; // LayerZero DVN finality
    uint256 public constant MIN_PROOF_SIZE = 32;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    IStargateRouter public stargateRouter;
    IStargateVerifier public stargateVerifier;

    /// @notice Default LayerZero endpoint ID for destination
    uint32 public defaultDstEid;

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
        bytes32 poolHash,
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
        address _stargateRouter,
        address _stargateVerifier,
        address _admin
    ) {
        if (_stargateRouter == address(0)) revert InvalidBridge();
        if (_stargateVerifier == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        stargateRouter = IStargateRouter(_stargateRouter);
        stargateVerifier = IStargateVerifier(_stargateVerifier);

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

        IStargateRouter.SendParam memory sendParam = IStargateRouter.SendParam({
            dstEid: uint32(uint256(destinationChainId)),
            to: bytes32(uint256(uint160(msg.sender))),
            amountLD: msg.value - protocolFee,
            minAmountLD: ((msg.value - protocolFee) * 99) / 100, // 1% slippage
            extraOptions: "",
            composeMsg: payload,
            oftCmd: ""
        });

        IStargateRouter.MessagingFee memory fee = IStargateRouter.MessagingFee({
            nativeFee: msg.value - protocolFee,
            lzTokenFee: 0
        });

        bytes32 receipt = stargateRouter.send{value: msg.value - protocolFee}(
            sendParam,
            fee,
            msg.sender
        );

        messageHash = keccak256(
            abi.encodePacked(
                STARGATE_PROTOCOL_ID,
                msg.sender,
                destinationChainId,
                nonce,
                receipt
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

        bool valid = stargateVerifier.verifyDelivery(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 poolHash = bytes32(publicInputs[0]);
        messageHash = keccak256(
            abi.encodePacked(
                STARGATE_PROTOCOL_ID,
                poolHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, poolHash, nullifier, payload);
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
        uint32 dstEid = defaultDstEid > 0 ? defaultDstEid : 30101; // Ethereum LZ endpoint

        IStargateRouter.SendParam memory sendParam = IStargateRouter.SendParam({
            dstEid: dstEid,
            to: bytes32(uint256(uint160(targetAddress))),
            amountLD: msg.value - protocolFee,
            minAmountLD: ((msg.value - protocolFee) * 99) / 100,
            extraOptions: "",
            composeMsg: payload,
            oftCmd: ""
        });

        IStargateRouter.MessagingFee memory fee = IStargateRouter.MessagingFee({
            nativeFee: msg.value - protocolFee,
            lzTokenFee: 0
        });

        bytes32 receipt = stargateRouter.send{value: msg.value - protocolFee}(
            sendParam,
            fee,
            msg.sender
        );

        messageId = keccak256(
            abi.encodePacked(
                STARGATE_PROTOCOL_ID,
                msg.sender,
                bytes32(uint256(dstEid)),
                nonce,
                receipt
            )
        );
        verifiedMessages[messageId] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageId,
            msg.sender,
            bytes32(uint256(dstEid)),
            msg.value
        );
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
        return STARGATE_PROTOCOL_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Stargate";
    }

    function isConfigured() external view returns (bool) {
        return
            address(stargateRouter) != address(0) &&
            address(stargateVerifier) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function setStargateRouter(
        address _router
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_router == address(0)) revert InvalidBridge();
        stargateRouter = IStargateRouter(_router);
        emit BridgeConfigUpdated("stargateRouter", _router);
    }

    function setStargateVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert InvalidVerifier();
        stargateVerifier = IStargateVerifier(_verifier);
        emit BridgeConfigUpdated("stargateVerifier", _verifier);
    }

    function setDefaultDstEid(
        uint32 _eid
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        defaultDstEid = _eid;
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
