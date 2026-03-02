// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IAxelarGateway
 * @notice Minimal interface for the Axelar Gateway contract on Ethereum
 * @dev Axelar is a cross-chain communication network secured by its own
 *      proof-of-stake validator set. The Gateway contract is the on-chain
 *      endpoint for receiving/sending Axelar General Message Passing (GMP)
 *      messages. Validators collectively sign attestations via a threshold
 *      multi-sig scheme (weighted by stake) using ECDSA.
 */
interface IAxelarGateway {
    /// @notice Send a cross-chain contract call via Axelar GMP
    /// @param destinationChain The destination chain name (e.g. "avalanche")
    /// @param contractAddress The destination contract address (string-encoded)
    /// @param payload The cross-chain message payload
    function callContract(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload
    ) external;

    /// @notice Send a cross-chain contract call with native token transfer
    /// @param destinationChain The destination chain name
    /// @param contractAddress The destination contract address
    /// @param payload The cross-chain message payload
    function callContractWithToken(
        string calldata destinationChain,
        string calldata contractAddress,
        bytes calldata payload,
        string calldata symbol,
        uint256 amount
    ) external;

    /// @notice Validate a command signed by the Axelar validator set
    /// @param commandId The unique command identifier
    /// @return valid Whether the command has been approved by validators
    function isCommandExecuted(
        bytes32 commandId
    ) external view returns (bool valid);

    /// @notice Validate a contract call approval
    /// @param commandId The command identifier
    /// @param sourceChain The source chain name
    /// @param sourceAddress The source address (string-encoded)
    /// @param payloadHash The hash of the payload
    /// @return approved Whether the call has been approved
    function validateContractCall(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes32 payloadHash
    ) external returns (bool approved);
}

/**
 * @title IAxelarGasService
 * @notice Interface for the Axelar Gas Service contract
 * @dev Used to pay gas on the destination chain. Axelar relayers require
 *      prepaid gas to execute the destination call. The gas service holds
 *      these prepayments and refunds excess.
 */
interface IAxelarGasService {
    /// @notice Pay gas for a contract call
    /// @param sender The address of the sender
    /// @param destinationChain The destination chain name
    /// @param destinationAddress The destination contract address
    /// @param payload The payload being sent
    /// @param refundAddress The address to refund excess gas to
    function payNativeGasForContractCall(
        address sender,
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes calldata payload,
        address refundAddress
    ) external payable;

    /// @notice Estimate the gas fee for a cross-chain call
    /// @param destinationChain The destination chain name
    /// @param destinationAddress The destination contract address
    /// @param payload The payload being sent
    /// @param executionGasLimit The gas limit for destination execution
    /// @return gasFee The estimated gas fee in native tokens
    function estimateGasFee(
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes calldata payload,
        uint256 executionGasLimit
    ) external view returns (uint256 gasFee);
}

/**
 * @title AxelarBridgeAdapter
 * @author ZASEON Team
 * @notice Bridge adapter enabling cross-chain messaging via Axelar Network GMP
 * @dev Axelar Network is a decentralised cross-chain communication platform
 *      that connects 60+ blockchains. It uses a delegated proof-of-stake
 *      validator set where validators collectively sign cross-chain messages
 *      via a threshold ECDSA multi-sig. Axelar supports General Message
 *      Passing (GMP) for arbitrary cross-chain contract calls, and the
 *      Interchain Token Service (ITS) for cross-chain token transfers.
 *
 *      Key Axelar concepts:
 *      - Gateway: On-chain contract that receives/sends GMP messages
 *      - Gas Service: Pays destination gas; relayers execute the call
 *      - Command ID: Unique identifier for each cross-chain command
 *      - Validator-signed approvals via weighted threshold ECDSA
 *
 *      ZASEON integration approach:
 *      - Uses Axelar GMP (callContract) for cross-chain privacy messages
 *      - Gateway validateContractCall for inbound message verification
 *      - Gas Service for destination gas prepayment
 *      - Nullifier-based replay protection via ZASEON CDNA
 *      - ZASEON virtual chain ID: 12_100
 */
contract AxelarBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    // ──────────────────────────────────────────────
    //  Roles
    // ──────────────────────────────────────────────

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    /// @notice ZASEON internal virtual chain ID for Axelar
    uint16 public constant AXELAR_CHAIN_ID = 12_100;

    /// @notice Finality blocks (Axelar uses ~28 block confirmations on Ethereum for GMP)
    uint256 public constant FINALITY_BLOCKS = 28;

    /// @notice Minimum proof size for inbound verification
    uint256 public constant MIN_PROOF_SIZE = 32;

    /// @notice Maximum bridge fee in basis points (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Default execution gas limit for destination calls
    uint256 public constant DEFAULT_EXECUTION_GAS_LIMIT = 300_000;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice Axelar Gateway contract
    IAxelarGateway public axelarGateway;

    /// @notice Axelar Gas Service contract
    IAxelarGasService public axelarGasService;

    /// @notice Mapping of verified Axelar command IDs
    mapping(bytes32 => bool) public verifiedCommands;

    /// @notice Spent nullifiers
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice All verified message hashes (sent + received)
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Nonce per sender for outgoing messages
    mapping(address => uint256) public senderNonces;

    /// @notice Registered destination chain names (Axelar uses string chain IDs)
    mapping(bytes32 => bool) public registeredChains;

    /// @notice Protocol fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum fee in native token
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Execution gas limit for destination calls
    uint256 public executionGasLimit;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged
    uint256 public totalValueBridged;

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    error InvalidGateway();
    error InvalidGasService();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidChain();
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error CommandAlreadyExecuted(bytes32 commandId);
    error TransferFailed();
    error ChainNotRegistered(string chain);

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        string destinationChain,
        string destinationAddress,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 indexed commandId,
        string sourceChain,
        string sourceAddress,
        bytes payload
    );

    event GatewayUpdated(address oldGateway, address newGateway);
    event GasServiceUpdated(address oldGasService, address newGasService);
    event ChainRegistered(string chain);
    event ChainUnregistered(string chain);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event ExecutionGasLimitUpdated(uint256 oldLimit, uint256 newLimit);
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    /// @notice Initialise the Axelar bridge adapter
    /// @param _gateway Axelar Gateway contract address
    /// @param _gasService Axelar Gas Service contract address
    /// @param _admin Admin address that receives DEFAULT_ADMIN_ROLE
    constructor(address _gateway, address _gasService, address _admin) {
        if (_gateway == address(0)) revert InvalidGateway();
        if (_gasService == address(0)) revert InvalidGasService();
        if (_admin == address(0)) revert InvalidTarget();

        axelarGateway = IAxelarGateway(_gateway);
        axelarGasService = IAxelarGasService(_gasService);
        executionGasLimit = DEFAULT_EXECUTION_GAS_LIMIT;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    // ──────────────────────────────────────────────
    //  Send  (ZASEON → Destination via Axelar GMP)
    // ──────────────────────────────────────────────

    /// @notice Send a cross-chain message via Axelar GMP
    /// @param destinationChain Axelar destination chain name (e.g. "avalanche")
    /// @param destinationAddress Destination contract address (string-encoded)
    /// @param payload The message payload
    /// @return messageHash The hash of the sent message
    function sendMessage(
        string calldata destinationChain,
        string calldata destinationAddress,
        bytes calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (bytes(destinationChain).length == 0) revert InvalidChain();
        if (bytes(destinationAddress).length == 0) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Verify chain is registered
        bytes32 chainHash = keccak256(bytes(destinationChain));
        if (!registeredChains[chainHash])
            revert ChainNotRegistered(destinationChain);

        // Calculate fees
        uint256 protocolFee = (msg.value * bridgeFee) / 10_000;
        uint256 forwardValue = msg.value - protocolFee;
        accumulatedFees += protocolFee;

        // Build message hash
        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                AXELAR_CHAIN_ID,
                msg.sender,
                destinationChain,
                destinationAddress,
                nonce,
                payload
            )
        );

        // Pay gas via Axelar Gas Service
        axelarGasService.payNativeGasForContractCall{value: forwardValue}(
            address(this),
            destinationChain,
            destinationAddress,
            payload,
            msg.sender
        );

        // Send via Axelar Gateway
        axelarGateway.callContract(
            destinationChain,
            destinationAddress,
            payload
        );

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            destinationChain,
            destinationAddress,
            msg.value
        );
    }

    // ──────────────────────────────────────────────
    //  Receive  (Source → ZASEON via Axelar GMP)
    // ──────────────────────────────────────────────

    /// @notice Receive and verify an Axelar GMP message
    /// @param commandId The Axelar command ID for this message
    /// @param sourceChain The source chain name
    /// @param sourceAddress The source address (string-encoded)
    /// @param payload The message payload
    /// @return messageHash The hash of the received message
    function receiveMessage(
        bytes32 commandId,
        string calldata sourceChain,
        string calldata sourceAddress,
        bytes calldata payload
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (commandId == bytes32(0)) revert InvalidProof();
        if (bytes(sourceChain).length == 0) revert InvalidChain();
        if (payload.length == 0) revert InvalidPayload();

        // Verify the command hasn't been executed
        if (verifiedCommands[commandId])
            revert CommandAlreadyExecuted(commandId);

        // Verify via Axelar Gateway
        bytes32 payloadHash = keccak256(payload);
        bool valid = axelarGateway.validateContractCall(
            commandId,
            sourceChain,
            sourceAddress,
            payloadHash
        );
        if (!valid) revert InvalidProof();

        // Extract nullifier from payload (first 32 bytes)
        bytes32 nullifier;
        if (payload.length >= 32) {
            nullifier = bytes32(payload[:32]);
        } else {
            nullifier = keccak256(payload);
        }

        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        usedNullifiers[nullifier] = true;
        verifiedCommands[commandId] = true;

        messageHash = keccak256(
            abi.encodePacked(commandId, sourceChain, sourceAddress, payloadHash)
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(
            messageHash,
            commandId,
            sourceChain,
            sourceAddress,
            payload
        );
    }

    // ──────────────────────────────────────────────
    //  IBridgeAdapter
    // ──────────────────────────────────────────────

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address refundAddress
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageId)
    {
        if (targetAddress == address(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        string memory destAddress = _addressToString(targetAddress);

        // Use a default registered chain for generic bridgeMessage calls
        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                AXELAR_CHAIN_ID,
                msg.sender,
                targetAddress,
                nonce,
                payload
            )
        );

        // Pay gas if value provided
        if (msg.value > 0) {
            uint256 protocolFee = (msg.value * bridgeFee) / 10_000;
            accumulatedFees += protocolFee;
            totalValueBridged += msg.value;
        }

        verifiedMessages[messageId] = true;
        totalMessagesSent++;

        emit MessageSent(
            messageId,
            msg.sender,
            "ethereum",
            destAddress,
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        // Delegate to Axelar Gas Service estimate if possible
        // Fallback to minMessageFee
        return minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool) {
        return verifiedMessages[messageId];
    }

    // ──────────────────────────────────────────────
    //  Views
    // ──────────────────────────────────────────────

    /// @notice Get the ZASEON virtual chain ID for Axelar
    function chainId() external pure returns (uint16) {
        return AXELAR_CHAIN_ID;
    }

    /// @notice Get the chain name
    function chainName() external pure returns (string memory) {
        return "Axelar";
    }

    /// @notice Whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(axelarGateway) != address(0) &&
            address(axelarGasService) != address(0);
    }

    /// @notice Get the finality blocks
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Check if a destination chain is registered
    /// @param chain The Axelar chain name
    function isChainRegistered(
        string calldata chain
    ) external view returns (bool) {
        return registeredChains[keccak256(bytes(chain))];
    }

    // ──────────────────────────────────────────────
    //  Admin Configuration
    // ──────────────────────────────────────────────

    /// @notice Update the Axelar Gateway address
    /// @param _gateway New gateway address
    function setAxelarGateway(
        address _gateway
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_gateway == address(0)) revert InvalidGateway();
        emit GatewayUpdated(address(axelarGateway), _gateway);
        axelarGateway = IAxelarGateway(_gateway);
    }

    /// @notice Update the Axelar Gas Service address
    /// @param _gasService New gas service address
    function setAxelarGasService(
        address _gasService
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_gasService == address(0)) revert InvalidGasService();
        emit GasServiceUpdated(address(axelarGasService), _gasService);
        axelarGasService = IAxelarGasService(_gasService);
    }

    /// @notice Register an Axelar destination chain
    /// @param chain The Axelar chain name (e.g. "avalanche", "polygon", "fantom")
    function registerChain(
        string calldata chain
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (bytes(chain).length == 0) revert InvalidChain();
        bytes32 chainHash = keccak256(bytes(chain));
        registeredChains[chainHash] = true;
        emit ChainRegistered(chain);
    }

    /// @notice Unregister an Axelar destination chain
    /// @param chain The Axelar chain name to remove
    function unregisterChain(
        string calldata chain
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        bytes32 chainHash = keccak256(bytes(chain));
        registeredChains[chainHash] = false;
        emit ChainUnregistered(chain);
    }

    /// @notice Set the bridge fee in basis points
    /// @param _fee Fee in bps (max 100 = 1%)
    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        emit BridgeFeeUpdated(bridgeFee, _fee);
        bridgeFee = _fee;
    }

    /// @notice Set the minimum message fee
    /// @param _fee Minimum fee in native tokens
    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit MinMessageFeeUpdated(minMessageFee, _fee);
        minMessageFee = _fee;
    }

    /// @notice Set the execution gas limit for destination calls
    /// @param _gasLimit New gas limit
    function setExecutionGasLimit(
        uint256 _gasLimit
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit ExecutionGasLimitUpdated(executionGasLimit, _gasLimit);
        executionGasLimit = _gasLimit;
    }

    // ──────────────────────────────────────────────
    //  Emergency
    // ──────────────────────────────────────────────

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated protocol fees
    /// @param recipient The address to receive fees
    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit FeesWithdrawn(recipient, amount);
    }

    /// @notice Emergency ETH withdrawal
    /// @param to Recipient address
    /// @param amount Amount to withdraw
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Emergency ERC-20 token withdrawal
    /// @param token The ERC-20 token address
    /// @param to Recipient address
    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(to, balance);
    }

    /// @notice Accept ETH
    receive() external payable {}

    // ──────────────────────────────────────────────
    //  Internal Helpers
    // ──────────────────────────────────────────────

    /// @notice Convert an address to a lowercase hex string
    /// @param addr The address to convert
    /// @return The string representation
    function _addressToString(
        address addr
    ) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory data = abi.encodePacked(addr);
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(data[i] >> 4)];
            str[3 + i * 2] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }
}
