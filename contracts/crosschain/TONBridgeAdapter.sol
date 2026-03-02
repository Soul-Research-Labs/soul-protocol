// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title ITONBridge
 * @notice Interface for the TON-Ethereum bridge relay contract
 * @dev TON (The Open Network) uses a workchain architecture with a masterchain
 *      coordinating multiple shardchains. The bridge relies on a set of
 *      validators who produce Merkle proofs of state transitions on the
 *      masterchain. Messages are verified via a validator multisig or
 *      light-client-based proofs.
 */
interface ITONBridge {
    /// @notice Submit a message to be relayed to TON
    /// @param workchain The destination workchain ID (0 = basechain)
    /// @param destination The 32-byte TON address (workchain + hash part)
    /// @param payload The message payload (Cell-serialized)
    /// @return messageId The unique message identifier
    function sendMessage(
        int8 workchain,
        bytes32 destination,
        bytes calldata payload
    ) external payable returns (bytes32 messageId);

    /// @notice Verify and execute a message from TON
    /// @param proof The validator-signed proof or Merkle proof
    /// @param payload The message payload
    /// @return valid Whether the message was successfully verified and executed
    function verifyAndExecute(
        bytes calldata proof,
        bytes calldata payload
    ) external returns (bool valid);

    /// @notice Get the relay fee for sending a message
    /// @return fee The required fee in wei
    function getRelayFee() external view returns (uint256 fee);
}

/**
 * @title ITONLightClient
 * @notice Interface for verifying TON masterchain state proofs
 * @dev TON's masterchain uses Catchain BFT consensus. The light client
 *      tracks validator sets and verifies block headers via BLS aggregated
 *      signatures. State proofs use Merkle Patricia Trees (Cells).
 */
interface ITONLightClient {
    /// @notice Verify a TON masterchain block header
    /// @param blockHeader The serialized block header
    /// @param validatorSignatures Aggregated validator signatures
    /// @return valid Whether the block header is valid
    function verifyBlockHeader(
        bytes calldata blockHeader,
        bytes calldata validatorSignatures
    ) external view returns (bool valid);

    /// @notice Verify a Merkle proof against a verified state root
    /// @param stateRoot The verified masterchain state root
    /// @param proof The Cell-based Merkle proof
    /// @return valid Whether the proof is valid
    function verifyStateProof(
        bytes32 stateRoot,
        bytes calldata proof
    ) external view returns (bool valid);

    /// @notice Get the current validator set hash
    /// @return hash The hash of the current validator set
    function currentValidatorSetHash() external view returns (bytes32 hash);
}

/**
 * @title TONBridgeAdapter
 * @author ZASEON Team
 * @notice Bridge adapter for TON (The Open Network) integration
 * @dev TON is a multi-blockchain platform with a unique architecture featuring
 *      a masterchain, workchains, and shardchains. Originally designed by
 *      Nikolai Durov, it uses the TVM (TON Virtual Machine) and FunC/Tact
 *      smart contract languages.
 *
 *      Key TON concepts:
 *      - TVM (TON Virtual Machine): Stack-based VM using Cells for data
 *      - Masterchain: Coordinates all workchains, validator set rotation
 *      - Workchains: Independent blockchains (workchain 0 = basechain)
 *      - Shardchains: Dynamic sharding within workchains
 *      - Catchain BFT: Consensus protocol for validator agreement
 *      - Cells: Tree-of-cells data structure (up to 1023 bits + 4 refs)
 *      - Addresses: workchain_id + account_id (int8 + bytes32)
 *      - Validators: ~340 validators with rotating sessions
 *      - Block time: ~5 seconds on masterchain
 *
 *      ZASEON integration approach:
 *      - Uses TON Bridge relay contract on Ethereum
 *      - Optional light client for masterchain proof verification
 *      - Validator-signed attestations for message delivery
 *      - Nullifier-based replay protection via ZASEON CDNA
 *      - Workchain 0 (basechain) targeted by default
 *      - ZASEON virtual chain ID: 16_100
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract TONBridgeAdapter is
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

    /// @notice ZASEON internal virtual chain ID for TON
    uint16 public constant TON_CHAIN_ID = 16_100;

    /// @notice Default workchain (basechain)
    int8 public constant DEFAULT_WORKCHAIN = 0;

    /// @notice Finality blocks (~5s masterchain block time)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Maximum bridge fee in basis points (1%)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Maximum payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Minimum proof size for validator signature verification
    uint256 public constant MIN_PROOF_SIZE = 32;

    /// @notice Validator quorum threshold (2/3 + 1)
    uint256 public constant VALIDATOR_QUORUM_BPS = 6_667;

    // ──────────────────────────────────────────────
    //  State
    // ──────────────────────────────────────────────

    /// @notice TON Bridge relay contract
    ITONBridge public tonBridge;

    /// @notice TON Light Client for masterchain proof verification
    ITONLightClient public tonLightClient;

    /// @notice Verified message hashes
    mapping(bytes32 => bool) public verifiedMessages;

    /// @notice Spent nullifiers
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Nonce per sender
    mapping(address => uint256) public senderNonces;

    /// @notice Whitelisted TON contract addresses (workchain-qualified)
    mapping(bytes32 => bool) public whitelistedContracts;

    /// @notice Supported workchain IDs
    mapping(int8 => bool) public supportedWorkchains;

    /// @notice Protocol fee in basis points
    uint256 public bridgeFee;

    /// @notice Minimum fee in native token
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged
    uint256 public totalValueBridged;

    // ──────────────────────────────────────────────
    //  Errors
    // ──────────────────────────────────────────────

    error InvalidBridge();
    error InvalidLightClient();
    error InvalidTarget();
    error InvalidPayload();
    error InvalidProof();
    error InvalidWorkchain(int8 workchain);
    error InsufficientFee(uint256 required, uint256 provided);
    error FeeTooHigh(uint256 fee);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error ContractNotWhitelisted(bytes32 tonContract);
    error TransferFailed();
    error RelayFailed();

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed sender,
        int8 workchain,
        bytes32 destination,
        uint256 value
    );

    event MessageReceived(
        bytes32 indexed messageHash,
        bytes32 indexed tonSender,
        int8 workchain,
        bytes payload
    );

    event BridgeUpdated(address oldBridge, address newBridge);
    event LightClientUpdated(address oldClient, address newClient);
    event ContractWhitelisted(bytes32 indexed tonContract);
    event ContractRemoved(bytes32 indexed tonContract);
    event WorkchainUpdated(int8 workchain, bool supported);
    event BridgeFeeUpdated(uint256 oldFee, uint256 newFee);
    event MinMessageFeeUpdated(uint256 oldFee, uint256 newFee);
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    constructor(address _tonBridge, address _admin) {
        if (_tonBridge == address(0)) revert InvalidBridge();
        if (_admin == address(0)) revert InvalidTarget();

        tonBridge = ITONBridge(_tonBridge);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);

        // Enable basechain (workchain 0) by default
        supportedWorkchains[DEFAULT_WORKCHAIN] = true;
    }

    // ──────────────────────────────────────────────
    //  Send  (ZASEON → TON)
    // ──────────────────────────────────────────────

    /// @notice Send a cross-chain message to TON
    /// @param workchain Target workchain ID (0 for basechain)
    /// @param destination 32-byte TON address (account hash)
    /// @param payload The message payload
    /// @return messageHash The hash of the sent message
    function sendMessage(
        int8 workchain,
        bytes32 destination,
        bytes calldata payload
    )
        external
        payable
        nonReentrant
        whenNotPaused
        onlyRole(OPERATOR_ROLE)
        returns (bytes32 messageHash)
    {
        if (!supportedWorkchains[workchain]) revert InvalidWorkchain(workchain);
        if (destination == bytes32(0)) revert InvalidTarget();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH)
            revert InvalidPayload();

        // Calculate fees
        uint256 relayFee = tonBridge.getRelayFee();
        uint256 totalRequired = relayFee + minMessageFee;
        if (msg.value < totalRequired)
            revert InsufficientFee(totalRequired, msg.value);

        uint256 protocolFee = (msg.value * bridgeFee) / 10_000;
        uint256 forwardValue = msg.value - protocolFee;
        accumulatedFees += protocolFee;

        uint256 nonce = senderNonces[msg.sender]++;
        messageHash = keccak256(
            abi.encodePacked(
                TON_CHAIN_ID,
                msg.sender,
                workchain,
                destination,
                nonce,
                payload
            )
        );

        // Relay to TON bridge
        bytes32 relayId = tonBridge.sendMessage{value: forwardValue}(
            workchain,
            destination,
            payload
        );
        if (relayId == bytes32(0)) revert RelayFailed();

        verifiedMessages[messageHash] = true;
        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSent(
            messageHash,
            msg.sender,
            workchain,
            destination,
            msg.value
        );
    }

    // ──────────────────────────────────────────────
    //  Receive  (TON → ZASEON)
    // ──────────────────────────────────────────────

    /// @notice Receive and verify a message from TON
    /// @param tonSender 32-byte TON sender address
    /// @param workchain Source workchain ID
    /// @param payload The message payload
    /// @param proof Validator signature proof or Merkle proof
    /// @return messageHash The hash of the received message
    function receiveMessage(
        bytes32 tonSender,
        int8 workchain,
        bytes calldata payload,
        bytes calldata proof
    )
        external
        nonReentrant
        whenNotPaused
        onlyRole(RELAYER_ROLE)
        returns (bytes32 messageHash)
    {
        if (tonSender == bytes32(0)) revert InvalidTarget();
        if (!supportedWorkchains[workchain]) revert InvalidWorkchain(workchain);
        if (payload.length == 0) revert InvalidPayload();
        if (proof.length < MIN_PROOF_SIZE) revert InvalidProof();

        // Verify sender is whitelisted
        if (!whitelistedContracts[tonSender])
            revert ContractNotWhitelisted(tonSender);

        // Verify proof via light client if available, else via bridge relay
        bool valid;
        if (address(tonLightClient) != address(0)) {
            bytes32 payloadHash = keccak256(payload);
            valid = tonLightClient.verifyStateProof(payloadHash, proof);
        } else {
            valid = tonBridge.verifyAndExecute(proof, payload);
        }
        if (!valid) revert InvalidProof();

        // Extract nullifier
        bytes32 nullifier;
        if (payload.length >= 32) {
            nullifier = bytes32(payload[:32]);
        } else {
            nullifier = keccak256(payload);
        }

        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        messageHash = keccak256(
            abi.encodePacked(tonSender, workchain, payload, proof)
        );

        verifiedMessages[messageHash] = true;
        totalMessagesReceived++;

        emit MessageReceived(messageHash, tonSender, workchain, payload);
    }

    // ──────────────────────────────────────────────
    //  IBridgeAdapter
    // ──────────────────────────────────────────────

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /* refundAddress */
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

        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                TON_CHAIN_ID,
                msg.sender,
                targetAddress,
                nonce,
                payload
            )
        );

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
            DEFAULT_WORKCHAIN,
            bytes32(uint256(uint160(targetAddress))),
            msg.value
        );
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address,
        bytes calldata
    ) external view override returns (uint256 nativeFee) {
        uint256 relayFee;
        try tonBridge.getRelayFee() returns (uint256 fee) {
            relayFee = fee;
        } catch {
            relayFee = 0;
        }
        uint256 total = relayFee + minMessageFee;
        return total;
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

    function chainId() external pure returns (uint16) {
        return TON_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "TON";
    }

    function isConfigured() external view returns (bool) {
        return address(tonBridge) != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    // ──────────────────────────────────────────────
    //  Admin Configuration
    // ──────────────────────────────────────────────

    function setTONBridge(
        address _bridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_bridge == address(0)) revert InvalidBridge();
        emit BridgeUpdated(address(tonBridge), _bridge);
        tonBridge = ITONBridge(_bridge);
    }

    function setTONLightClient(
        address _client
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit LightClientUpdated(address(tonLightClient), _client);
        tonLightClient = ITONLightClient(_client);
    }

    function whitelistContract(
        bytes32 tonContract
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (tonContract == bytes32(0)) revert InvalidTarget();
        whitelistedContracts[tonContract] = true;
        emit ContractWhitelisted(tonContract);
    }

    function removeContract(
        bytes32 tonContract
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        whitelistedContracts[tonContract] = false;
        emit ContractRemoved(tonContract);
    }

    function setSupportedWorkchain(
        int8 workchain,
        bool supported
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        supportedWorkchains[workchain] = supported;
        emit WorkchainUpdated(workchain, supported);
    }

    function setBridgeFee(uint256 _fee) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_fee > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_fee);
        emit BridgeFeeUpdated(bridgeFee, _fee);
        bridgeFee = _fee;
    }

    function setMinMessageFee(
        uint256 _fee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit MinMessageFeeUpdated(minMessageFee, _fee);
        minMessageFee = _fee;
    }

    // ──────────────────────────────────────────────
    //  Emergency
    // ──────────────────────────────────────────────

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function withdrawFees(
        address payable recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool ok, ) = recipient.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit FeesWithdrawn(recipient, amount);
    }

    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(to, balance);
    }

    receive() external payable {}
}
