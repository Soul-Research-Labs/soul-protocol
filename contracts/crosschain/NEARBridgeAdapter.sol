// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title INEARBridge
 * @notice Minimal interface for the NEAR–Ethereum bridge (Rainbow Bridge)
 * @dev NEAR Protocol is a sharded PoS L1 using Nightshade sharding and
 *      the Aurora EVM compatibility layer. The Rainbow Bridge is a trustless,
 *      permissionless bridge between NEAR and Ethereum using light client proofs.
 */
interface INEARBridge {
    /// @notice Lock and relay tokens/messages to NEAR
    /// @param nearRecipient NEAR account ID as bytes
    /// @param payload The bridge payload
    /// @return transferId Unique transfer identifier
    function lockAndRelay(
        bytes calldata nearRecipient,
        bytes calldata payload
    ) external payable returns (bytes32 transferId);

    /// @notice Estimate the relay fee
    /// @return fee The estimated relay fee in wei
    function estimateRelayFee() external view returns (uint256 fee);

    /// @notice Get the latest NEAR block height synced by the light client
    /// @return height The latest synced NEAR block height
    function latestSyncedHeight() external view returns (uint256 height);
}

/**
 * @title INEARLightClient
 * @notice Interface for verifying NEAR light client proofs on Ethereum
 * @dev The Rainbow Bridge uses a NEAR light client on Ethereum that validates
 *      NEAR block headers via Ed25519 validator signatures. Proofs include
 *      Merkle paths in NEAR's state trie.
 */
interface INEARLightClient {
    /// @notice Verify a NEAR light client proof (block header + state proof)
    /// @param proof The proof data (block header + Merkle proof)
    /// @param publicInputs The public inputs (block hash, state root, etc.)
    /// @return valid Whether the proof is valid
    function verifyNEARProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external returns (bool valid);

    /// @notice Get the current verified NEAR block hash
    /// @return blockHash The latest verified NEAR block hash
    function currentBlockHash() external view returns (bytes32 blockHash);
}

/**
 * @title NEARBridgeAdapter
 * @notice ZASEON bridge adapter for NEAR Protocol — sharded PoS L1 with Rainbow Bridge
 * @dev NEAR Protocol uses:
 *      - Nightshade sharding for parallel transaction processing
 *      - Doomslug + BFT finality (2 epoch finality, ~2 seconds per block)
 *      - Rainbow Bridge (trustless, light client-based)
 *      - Aurora (EVM compatibility layer)
 *      - Named accounts (e.g., alice.near)
 *
 *      This adapter enables ZASEON ↔ NEAR messaging through the Rainbow Bridge
 *      light client infrastructure for trustless cross-chain verification.
 */
contract NEARBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                              ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ZASEON internal virtual chain ID for NEAR
    uint16 public constant NEAR_CHAIN_ID = 10_100;

    /// @notice NEAR uses ~2 epoch finality (~4 blocks, ~4 seconds)
    uint256 public constant FINALITY_BLOCKS = 4;

    /// @notice Minimum proof size for NEAR light client proofs
    uint256 public constant MIN_PROOF_SIZE = 64;

    /// @notice Maximum protocol fee (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length to prevent DoS
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /*//////////////////////////////////////////////////////////////
                             STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice NEAR Rainbow Bridge contract
    INEARBridge public nearBridge;

    /// @notice NEAR light client verifier contract
    INEARLightClient public nearLightClient;

    /// @notice Verified NEAR block hashes
    mapping(bytes32 => bool) public verifiedBlockHashes;

    /// @notice Used nullifiers (replay protection)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Message hash → verified
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Sender nonces for ordering
    mapping(address => uint256) public senderNonces;

    /// @notice Protocol fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum fee per message
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (wei)
    uint256 public totalValueBridged;

    /*//////////////////////////////////////////////////////////////
                             EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        bytes32 nearRecipientHash,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 blockHash,
        bytes32 indexed nullifier,
        bytes payload
    );

    event BridgeConfigUpdated(string param, address value);
    event BlockHashRegistered(bytes32 indexed blockHash);
    event FeeUpdated(string param, uint256 value);

    /*//////////////////////////////////////////////////////////////
                             ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBridge();
    error InvalidLightClient();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidBlockHash();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy the NEAR bridge adapter
    /// @param _nearBridge Address of the Rainbow Bridge contract
    /// @param _nearLightClient Address of the NEAR light client verifier
    /// @param _admin Default admin address
    constructor(address _nearBridge, address _nearLightClient, address _admin) {
        if (_nearBridge == address(0)) revert InvalidBridge();
        if (_nearLightClient == address(0)) revert InvalidLightClient();
        if (_admin == address(0)) revert InvalidTarget();

        nearBridge = INEARBridge(_nearBridge);
        nearLightClient = INEARLightClient(_nearLightClient);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                     SEND (ZASEON → NEAR)
    //////////////////////////////////////////////////////////////*/

    /// @notice Send a message to NEAR via the Rainbow Bridge
    /// @param nearRecipient The NEAR account ID (e.g., "alice.near")
    /// @param payload The bridge payload
    /// @return messageHash The unique message identifier
    function sendMessage(
        bytes calldata nearRecipient,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 messageHash)
    {
        if (nearRecipient.length == 0) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        uint256 relayFee = nearBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 transferId = nearBridge.lockAndRelay{
            value: msg.value - protocolFee
        }(nearRecipient, payload);

        messageHash = keccak256(
            abi.encodePacked(
                NEAR_CHAIN_ID,
                msg.sender,
                keccak256(nearRecipient),
                nonce,
                transferId
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            keccak256(nearRecipient),
            msg.value
        );
    }

    /*//////////////////////////////////////////////////////////////
                   RECEIVE (NEAR → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /// @notice Receive and verify a NEAR light client proof
    /// @param proof The block header + Merkle state proof
    /// @param publicInputs Public inputs: [blockHash, nullifier, stateRoot, payloadHash]
    /// @param payload The original payload
    /// @return messageHash The verified message identifier
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

        bool valid = nearLightClient.verifyNEARProof(
            proof,
            abi.encodePacked(publicInputs)
        );
        if (!valid) revert InvalidProof();

        bytes32 nullifier = bytes32(publicInputs[1]);
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        bytes32 blockHash = bytes32(publicInputs[0]);

        messageHash = keccak256(
            abi.encodePacked(
                NEAR_CHAIN_ID,
                blockHash,
                nullifier,
                keccak256(payload)
            )
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, blockHash, nullifier, payload);
    }

    /*//////////////////////////////////////////////////////////////
                    IBridgeAdapter INTERFACE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
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

        bytes memory nearRecipient = abi.encodePacked(targetAddress);

        uint256 relayFee = nearBridge.estimateRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee;
        if (bridgeFee > 0) {
            protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
        }

        uint256 nonce = senderNonces[msg.sender]++;

        bytes32 transferId = nearBridge.lockAndRelay{
            value: msg.value - protocolFee
        }(nearRecipient, payload);

        messageId = keccak256(
            abi.encodePacked(
                NEAR_CHAIN_ID,
                msg.sender,
                keccak256(nearRecipient),
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
            keccak256(nearRecipient),
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /* targetAddress */,
        bytes calldata /* payload */
    ) external view override returns (uint256 nativeFee) {
        nativeFee = nearBridge.estimateRelayFee() + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the ZASEON chain ID for NEAR
    function chainId() external pure returns (uint16) {
        return NEAR_CHAIN_ID;
    }

    /// @notice Get the chain name
    function chainName() external pure returns (string memory) {
        return "NEAR";
    }

    /// @notice Check if the adapter is configured
    function isConfigured() external view returns (bool) {
        return
            address(nearBridge) != address(0) &&
            address(nearLightClient) != address(0);
    }

    /// @notice Get the finality block count
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Get the current verified NEAR block hash
    function getCurrentBlockHash() external view returns (bytes32) {
        return nearLightClient.currentBlockHash();
    }

    /// @notice Get the latest synced NEAR block height
    function getLatestSyncedHeight() external view returns (uint256) {
        return nearBridge.latestSyncedHeight();
    }

    /*//////////////////////////////////////////////////////////////
                      ADMIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the NEAR Rainbow Bridge address
    function setNEARBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        nearBridge = INEARBridge(_bridge);
        emit BridgeConfigUpdated("nearBridge", _bridge);
    }

    /// @notice Update the NEAR light client verifier address
    function setNEARLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_client == address(0)) revert InvalidLightClient();
        nearLightClient = INEARLightClient(_client);
        emit BridgeConfigUpdated("nearLightClient", _client);
    }

    /// @notice Register a verified NEAR block hash
    function registerBlockHash(
        bytes32 _blockHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_blockHash == bytes32(0)) revert InvalidBlockHash();
        verifiedBlockHashes[_blockHash] = true;
        emit BlockHashRegistered(_blockHash);
    }

    /// @notice Set the protocol fee in basis points
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        bridgeFee = _fee;
        emit FeeUpdated("bridgeFee", _fee);
    }

    /// @notice Set the minimum fee per message
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minMessageFee = _fee;
        emit FeeUpdated("minMessageFee", _fee);
    }

    /*//////////////////////////////////////////////////////////////
                     EMERGENCY & FEE WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated protocol fees
    function withdrawFees(
        address payable _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = _to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ETH
    function emergencyWithdrawETH(
        address payable _to,
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_to == address(0)) revert InvalidTarget();
        (bool ok, ) = _to.call{value: _amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency withdraw ERC-20 tokens
    function emergencyWithdrawERC20(
        address _token,
        address _to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_token == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransfer(_to, balance);
    }

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Accept ETH
    receive() external payable {}
}
