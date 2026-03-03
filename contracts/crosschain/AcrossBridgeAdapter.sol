// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IAcrossSpokePool
 * @notice Minimal interface for the Across Protocol SpokePool
 * @dev Across uses an optimistic bridge model secured by UMA's optimistic oracle.
 *      Relayers front capital for instant transfers, then claim reimbursement
 *      from the HubPool after the optimistic challenge period.
 */
interface IAcrossSpokePool {
    /// @notice Deposit for a cross-chain transfer
    /// @param recipient The recipient on the destination chain
    /// @param originToken The token to bridge (address(0) for native)
    /// @param amount The amount to bridge
    /// @param destinationChainId The target chain ID
    /// @param relayerFeePct The fee as a percentage of amount (18 decimals)
    /// @param quoteTimestamp The timestamp of the fee quote
    /// @param message Arbitrary message to pass to the recipient
    /// @param maxCount Max fills allowed
    function depositV3(
        address recipient,
        address originToken,
        uint256 amount,
        uint256 destinationChainId,
        int64 relayerFeePct,
        uint32 quoteTimestamp,
        bytes calldata message,
        uint256 maxCount
    ) external payable;

    /// @notice Get the current spoke pool state
    function getCurrentTime() external view returns (uint256);
}

/**
 * @title IAcrossHubPool
 * @notice Interface for verifying Across fill proofs via UMA oracle
 */
interface IAcrossHubPool {
    function verifyFillProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    function currentRelayerPoolHash() external view returns (bytes32);
}

/**
 * @title AcrossBridgeAdapter
 * @notice ZASEON bridge adapter for Across Protocol — UMA-secured optimistic bridge
 * @dev Across Protocol uses:
 *      - Intent-based bridge model (relayers front capital)
 *      - UMA optimistic oracle for dispute resolution
 *      - HubPool on Ethereum L1, SpokePools on L2s
 *      - Sub-minute cross-chain transfers
 *      - ~$10B+ cumulative volume
 *      - Best-in-class speed for L2-to-L2 transfers
 *      - Supports Arbitrum, Optimism, Base, Polygon, zkSync, Linea, etc.
 *
 *      This adapter enables ZASEON ↔ any Across-supported chain bridging
 *      using UMA optimistic verification.
 */
contract AcrossBridgeAdapter is
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

    uint16 public constant ACROSS_PROTOCOL_ID = 28_100;
    uint256 public constant FINALITY_BLOCKS = 1; // Intent-based, near-instant
    uint256 public constant MIN_PROOF_SIZE = 32;
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Default relayer fee (0.04% = 4e14 out of 1e18)
    int64 public constant DEFAULT_RELAYER_FEE_PCT = 4e14;

    IAcrossSpokePool public spokePool;
    IAcrossHubPool public hubPool;

    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => bool) public verifiedMessages;
    mapping(address => uint256) public senderNonces;

    uint256 public bridgeFee;
    uint256 public minMessageFee;
    uint256 public accumulatedFees;
    uint256 public totalMessagesSent;
    uint256 public totalMessagesReceived;
    uint256 public totalValueBridged;

    /// @notice Destination chain ID for default routing
    uint256 public defaultDestinationChainId;

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        bytes32 destinationChainId,
        uint256 value
    );
    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 relayerPoolHash,
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

    constructor(address _spokePool, address _hubPool, address _admin) {
        if (_spokePool == address(0)) revert InvalidBridge();
        if (_hubPool == address(0)) revert InvalidVerifier();
        if (_admin == address(0)) revert InvalidTarget();

        spokePool = IAcrossSpokePool(_spokePool);
        hubPool = IAcrossHubPool(_hubPool);

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

        spokePool.depositV3{value: msg.value - protocolFee}(
            msg.sender,
            address(0), // native ETH
            msg.value - protocolFee,
            uint256(destinationChainId),
            DEFAULT_RELAYER_FEE_PCT,
            uint32(block.timestamp),
            payload,
            type(uint256).max
        );

        messageHash = keccak256(
            abi.encodePacked(
                ACROSS_PROTOCOL_ID,
                msg.sender,
                destinationChainId,
                nonce
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

        bool valid = hubPool.verifyFillProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 relayerPoolHash = bytes32(publicInputs[0]);
        messageHash = keccak256(
            abi.encodePacked(
                ACROSS_PROTOCOL_ID,
                relayerPoolHash,
                nullifier,
                keccak256(payload)
            )
        );
        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, relayerPoolHash, nullifier, payload);
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

        spokePool.depositV3{value: msg.value - protocolFee}(
            targetAddress,
            address(0),
            msg.value - protocolFee,
            destChain,
            DEFAULT_RELAYER_FEE_PCT,
            uint32(block.timestamp),
            payload,
            type(uint256).max
        );

        messageId = keccak256(
            abi.encodePacked(
                ACROSS_PROTOCOL_ID,
                msg.sender,
                bytes32(destChain),
                nonce
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
        return ACROSS_PROTOCOL_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Across";
    }

    function isConfigured() external view returns (bool) {
        return
            address(spokePool) != address(0) && address(hubPool) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function setSpokePool(address _pool) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_pool == address(0)) revert InvalidBridge();
        spokePool = IAcrossSpokePool(_pool);
        emit BridgeConfigUpdated("spokePool", _pool);
    }

    function setHubPool(address _pool) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_pool == address(0)) revert InvalidVerifier();
        hubPool = IAcrossHubPool(_pool);
        emit BridgeConfigUpdated("hubPool", _pool);
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
