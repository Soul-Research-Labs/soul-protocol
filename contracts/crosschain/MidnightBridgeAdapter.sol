// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IMidnightBridge
 * @notice Minimal interface for the Midnight native bridge relay contract
 * @dev Midnight's bridge uses PLONK-based ZK proofs for message verification.
 *      The relay is a purpose-built contract that manages cross-chain state
 *      transitions between EVM and Midnight's Compact runtime.
 */
interface IMidnightBridge {
    /// @notice Publish a message destined for Midnight
    /// @param nonce Unique nonce for ordering
    /// @param payload The encoded message payload
    /// @param proofLevel The proof verification level (0=instant, 1=standard, 2=finalized)
    /// @return sequence Monotonic sequence number assigned by the bridge
    function publishMessage(
        uint32 nonce,
        bytes memory payload,
        uint8 proofLevel
    ) external payable returns (uint64 sequence);

    /// @notice Get the base message fee for publishing
    /// @return fee The fee in native currency
    function messageFee() external view returns (uint256 fee);
}

/**
 * @title IMidnightProofVerifier
 * @notice Interface for verifying PLONK proofs from Midnight
 * @dev Midnight uses PLONK (with Turbo/Ultra extensions) for its ZK proof system.
 *      The verifier validates that a message was included in a Midnight block
 *      and that the state transition is valid.
 */
interface IMidnightProofVerifier {
    /// @notice Verify a PLONK proof from Midnight
    /// @param proof The serialized PLONK proof
    /// @param publicInputs The public inputs for verification
    /// @return valid True if the proof is valid
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool valid);
}

/**
 * @title MidnightBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Midnight (privacy-focused Cardano partner chain)
 * @dev Enables ZASEON cross-chain interoperability with Midnight via a custom
 *      native bridge with PLONK-based ZK proof verification. Midnight uses
 *      the Compact language (TypeScript-like DSL) for its smart contracts.
 *
 * MIDNIGHT INTEGRATION:
 * - Compact VM — ZK-native smart contract execution (not EVM, not UTXO)
 * - Bridge protocol: Custom native bridge with PLONK proof verification
 * - EVM→Midnight: publishMessage on MidnightBridge → relayers propagate → Compact contract receives
 * - Midnight→EVM: Compact contract publishes → PLONK proof generated → receiveMessage on this contract
 * - Addresses: 32-byte identifiers (Compact contract addresses, right-padded)
 * - Proof system: PLONK (Turbo/Ultra extensions) — ZK-native execution environment
 * - Privacy: Midnight has native shielded state; bridge preserves privacy guarantees via ZK proofs
 *
 * SECURITY NOTES:
 * - Incoming messages verified via PLONK proof against Midnight state root
 * - Nullifier-based replay protection (integrates with ZASEON's nullifier system)
 * - Trusted relayer set with multi-sig operator management
 * - Compact contract address whitelisting for authorized message sources
 * - All state-changing functions protected by ReentrancyGuard and access control
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract MidnightBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Role for operators who can manage bridge operations
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    /// @notice Role for guardians who can perform emergency actions
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    /// @notice Role for relayers who can relay cross-chain messages
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Role for pausers who can pause the adapter
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Midnight chain identifier (internal, not an EVM chain ID)
    /// @dev Midnight does not have an EVM chain ID; 2100 is the ZASEON-internal identifier
    uint16 public constant MIDNIGHT_CHAIN_ID = 2100;

    /// @notice Finality in Midnight blocks (~10 blocks, ~120s)
    uint256 public constant FINALITY_BLOCKS = 10;

    /// @notice Max bridge fee in basis points (1% = 100 bps)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Max payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice Proof verification level: finalized (strongest guarantee)
    uint8 public constant PROOF_LEVEL_FINALIZED = 2;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        DELIVERED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        bytes32 midnightTarget; // 32-byte Compact contract address
        uint256 timestamp;
        uint64 sequence; // Bridge sequence number
        bytes32 nullifier; // Nullifier for replay protection
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Midnight native bridge relay contract
    IMidnightBridge public midnightBridge;

    /// @notice PLONK proof verifier for Midnight state transitions
    IMidnightProofVerifier public proofVerifier;

    /// @notice ZASEON Compact contract address on Midnight (32-byte, right-padded)
    bytes32 public zaseonMidnightContract;

    /// @notice Bridge fee in basis points (max 100 = 1%)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent EVM → Midnight
    uint256 public totalMessagesSent;

    /// @notice Total messages received Midnight → EVM
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (native)
    uint256 public totalValueBridged;

    /// @notice Per-sender nonce counter for ordering
    mapping(address => uint256) public senderNonces;

    /// @notice Nullifier → consumed flag (replay protection, integrates with MIDNIGHT_TAG)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Whitelisted Midnight Compact contract addresses that can send messages
    mapping(bytes32 => bool) public whitelistedContracts;

    /// @notice Internal message tracking by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a message is published to Midnight bridge (EVM → Midnight)
    event MessageSentToMidnight(
        bytes32 indexed messageHash,
        bytes32 indexed midnightTarget,
        uint64 sequence,
        uint256 nonce,
        address sender
    );

    /// @notice Emitted when a verified message from Midnight is consumed (Midnight → EVM)
    event MessageReceivedFromMidnight(
        bytes32 indexed messageHash,
        bytes32 indexed sourceContract,
        uint64 sequence,
        bytes32 nullifier
    );

    /// @notice Emitted when the Midnight bridge address is updated
    event MidnightBridgeSet(address indexed bridge);

    /// @notice Emitted when the proof verifier address is updated
    event ProofVerifierSet(address indexed verifier);

    /// @notice Emitted when the ZASEON Midnight contract address is updated
    event ZaseonMidnightContractSet(bytes32 indexed contractHash);

    /// @notice Emitted when the bridge fee is updated
    event BridgeFeeSet(uint256 feeBps);

    /// @notice Emitted when the minimum message fee is updated
    event MinMessageFeeSet(uint256 fee);

    /// @notice Emitted when a Midnight contract is added/removed from whitelist
    event ContractWhitelistUpdated(
        bytes32 indexed contractHash,
        bool whitelisted
    );

    /// @notice Emitted on emergency ETH withdrawal
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                             ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidBridge();
    error InvalidProofVerifier();
    error InvalidMidnightContract();
    error InvalidTarget();
    error InvalidPayload();
    error BridgeNotConfigured();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidProof();
    error UnauthorizedSource(bytes32 sourceContract);
    error ContractNotWhitelisted(bytes32 contractHash);
    error FeeTooHigh(uint256 fee);
    error InsufficientFee(uint256 required, uint256 provided);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _midnightBridge Address of the Midnight native bridge relay
    /// @param _proofVerifier Address of the PLONK proof verifier
    /// @param _admin Address to receive admin roles
    constructor(
        address _midnightBridge,
        address _proofVerifier,
        address _admin
    ) {
        if (_admin == address(0)) revert InvalidTarget();
        if (_midnightBridge == address(0)) revert InvalidBridge();
        if (_proofVerifier == address(0)) revert InvalidProofVerifier();

        midnightBridge = IMidnightBridge(_midnightBridge);
        proofVerifier = IMidnightProofVerifier(_proofVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Midnight bridge relay address
    /// @param _midnightBridge New Midnight bridge relay address
    function setMidnightBridge(
        address _midnightBridge
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_midnightBridge == address(0)) revert InvalidBridge();
        midnightBridge = IMidnightBridge(_midnightBridge);
        emit MidnightBridgeSet(_midnightBridge);
    }

    /// @notice Update the PLONK proof verifier address
    /// @param _proofVerifier New proof verifier address
    function setProofVerifier(
        address _proofVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_proofVerifier == address(0)) revert InvalidProofVerifier();
        proofVerifier = IMidnightProofVerifier(_proofVerifier);
        emit ProofVerifierSet(_proofVerifier);
    }

    /// @notice Set the ZASEON Midnight Compact contract address
    /// @param _contractHash 32-byte Compact contract address (right-padded)
    function setZaseonMidnightContract(
        bytes32 _contractHash
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_contractHash == bytes32(0)) revert InvalidMidnightContract();
        zaseonMidnightContract = _contractHash;
        emit ZaseonMidnightContractSet(_contractHash);
    }

    /// @notice Set the bridge fee in basis points (max 1%)
    /// @param _feeBps Fee in basis points
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_feeBps > MAX_BRIDGE_FEE_BPS) revert FeeTooHigh(_feeBps);
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /// @notice Set the minimum message fee
    /// @param _minFee Minimum fee in native currency
    function setMinMessageFee(
        uint256 _minFee
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minMessageFee = _minFee;
        emit MinMessageFeeSet(_minFee);
    }

    /// @notice Add or remove a Midnight Compact contract from the whitelist
    /// @param _contractHash 32-byte Compact contract address
    /// @param _whitelisted Whether to whitelist the contract
    function setWhitelistedContract(
        bytes32 _contractHash,
        bool _whitelisted
    ) external onlyRole(OPERATOR_ROLE) {
        whitelistedContracts[_contractHash] = _whitelisted;
        emit ContractWhitelistUpdated(_contractHash, _whitelisted);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the Midnight chain ID
    function chainId() external pure returns (uint16) {
        return MIDNIGHT_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Midnight";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(midnightBridge) != address(0) &&
            address(proofVerifier) != address(0) &&
            zaseonMidnightContract != bytes32(0);
    }

    /// @notice Get the number of blocks required for finality
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Check if a nullifier has been consumed
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been consumed
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /// @notice Check if a Midnight contract is whitelisted
    /// @param contractHash The 32-byte Compact contract address
    /// @return True if the contract is whitelisted
    function isContractWhitelisted(
        bytes32 contractHash
    ) external view returns (bool) {
        return whitelistedContracts[contractHash];
    }

    /// @notice Get the nonce for a specific sender
    /// @param sender The sender address
    /// @return The current nonce
    function getSenderNonce(address sender) external view returns (uint256) {
        return senderNonces[sender];
    }

    /*//////////////////////////////////////////////////////////////
                     MESSAGE OPERATIONS (EVM → MIDNIGHT)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a ZASEON message to Midnight via the native bridge
     * @param midnightTarget The 32-byte Compact contract address on Midnight
     * @param payload The ZASEON-encoded message payload
     * @return messageHash Internal unique hash identifying this message
     * @dev Publishes a message via MidnightBridge.publishMessage().
     *      msg.value pays the bridge message fee + optional protocol fee.
     */
    function sendMessage(
        bytes32 midnightTarget,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (midnightTarget == bytes32(0)) revert InvalidTarget();
        if (address(midnightBridge) == address(0)) revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Calculate fees
        uint256 bridgeMsgFee = midnightBridge.messageFee();
        uint256 protocolFee = _calculateProtocolFee(msg.value);
        uint256 totalRequired = bridgeMsgFee + protocolFee + minMessageFee;

        if (msg.value < totalRequired) {
            revert InsufficientFee(totalRequired, msg.value);
        }

        accumulatedFees += protocolFee;

        // Encode ZASEON payload with metadata
        bytes memory zaseonPayload = abi.encode(
            midnightTarget,
            msg.sender,
            senderNonces[msg.sender]++,
            block.timestamp,
            payload
        );

        uint256 nonce = messageNonce++;

        // Publish message to Midnight bridge
        uint64 sequence = midnightBridge.publishMessage{value: bridgeMsgFee}(
            uint32(nonce),
            zaseonPayload,
            PROOF_LEVEL_FINALIZED
        );

        bytes32 messageHash = keccak256(
            abi.encode(midnightTarget, sequence, nonce, block.timestamp)
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            midnightTarget: midnightTarget,
            timestamp: block.timestamp,
            sequence: sequence,
            nullifier: bytes32(0)
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        emit MessageSentToMidnight(
            messageHash,
            midnightTarget,
            sequence,
            nonce,
            msg.sender
        );

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                   MESSAGE OPERATIONS (MIDNIGHT → EVM)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a message from Midnight with PLONK proof
     * @param proof The serialized PLONK proof from Midnight
     * @param publicInputs The public inputs [sourceContract, sequence, payloadHash, stateRoot, nullifier]
     * @param payload The message payload (verified via publicInputs[2] = keccak256(payload))
     * @return messageHash Internal hash for the received message
     * @dev Verifies the PLONK proof, checks source contract whitelist,
     *      marks the nullifier as consumed (replay protection).
     */
    function receiveMessage(
        bytes calldata proof,
        uint256[] calldata publicInputs,
        bytes calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (address(proofVerifier) == address(0)) revert BridgeNotConfigured();

        // publicInputs layout:
        // [0] = sourceContract (Midnight Compact contract address, as uint256)
        // [1] = sequence (monotonic sequence number)
        // [2] = payloadHash (keccak256 of the payload)
        // [3] = stateRoot (Midnight state root at proof time)
        // [4] = nullifier (unique per message, prevents replay)
        require(publicInputs.length >= 5, "Insufficient public inputs");

        // Verify PLONK proof
        bool valid = proofVerifier.verifyProof(proof, publicInputs);
        if (!valid) revert InvalidProof();

        // Extract fields from public inputs
        bytes32 sourceContract = bytes32(publicInputs[0]);
        uint64 sequence = uint64(publicInputs[1]);
        bytes32 payloadHash = bytes32(publicInputs[2]);
        bytes32 nullifier = bytes32(publicInputs[4]);

        // Verify payload integrity
        require(keccak256(payload) == payloadHash, "Payload hash mismatch");

        // Replay protection via nullifier
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        // Validate source is a whitelisted Midnight contract
        if (!whitelistedContracts[sourceContract]) {
            // If zaseonMidnightContract is set, allow it even if not explicitly whitelisted
            if (sourceContract != zaseonMidnightContract) {
                revert ContractNotWhitelisted(sourceContract);
            }
        }

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                sourceContract,
                sequence,
                nonce,
                block.timestamp,
                "MIDNIGHT_TO_EVM"
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            midnightTarget: sourceContract,
            timestamp: block.timestamp,
            sequence: sequence,
            nullifier: nullifier
        });

        totalMessagesReceived++;

        emit MessageReceivedFromMidnight(
            messageHash,
            sourceContract,
            sequence,
            nullifier
        );

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                    IBridgeAdapter COMPLIANCE
    //////////////////////////////////////////////////////////////*/

    /// @inheritdoc IBridgeAdapter
    function bridgeMessage(
        address targetAddress,
        bytes calldata payload,
        address /*refundAddress*/
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
        if (address(midnightBridge) == address(0)) revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Calculate fees
        uint256 bridgeMsgFee = midnightBridge.messageFee();

        // Encode ZASEON payload: target is either the configured Midnight contract
        // or the EVM address converted to bytes32, bridged via native bridge
        bytes32 target = zaseonMidnightContract != bytes32(0)
            ? zaseonMidnightContract
            : bytes32(uint256(uint160(targetAddress)));

        bytes memory zaseonPayload = abi.encode(
            target,
            msg.sender,
            senderNonces[msg.sender]++,
            block.timestamp,
            payload
        );

        uint256 nonce = messageNonce++;

        uint64 sequence = midnightBridge.publishMessage{value: bridgeMsgFee}(
            uint32(nonce),
            zaseonPayload,
            PROOF_LEVEL_FINALIZED
        );

        messageId = keccak256(
            abi.encode(target, sequence, nonce, block.timestamp)
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            midnightTarget: target,
            timestamp: block.timestamp,
            sequence: sequence,
            nullifier: bytes32(0)
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;

        return messageId;
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external view override returns (uint256 nativeFee) {
        // Bridge message fee + minimum protocol fee
        uint256 bridgeMsgFee = address(midnightBridge) != address(0)
            ? midnightBridge.messageFee()
            : 0;
        return bridgeMsgFee + minMessageFee;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageRecord storage record = messages[messageId];
        return
            record.status == MessageStatus.SENT ||
            record.status == MessageStatus.DELIVERED;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Withdraw accumulated protocol fees
    /// @param to Recipient address
    function withdrawFees(
        address payable to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert InvalidTarget();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;
        (bool sent, ) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit FeesWithdrawn(to, amount);
    }

    /// @notice Emergency withdrawal of ETH
    /// @param to The recipient address
    /// @param amount The amount of ETH to withdraw
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert InvalidTarget();
        require(amount <= address(this).balance, "Insufficient balance");
        (bool sent, ) = to.call{value: amount}("");
        if (!sent) revert TransferFailed();
        emit EmergencyWithdrawal(to, amount);
    }

    /// @notice Emergency withdraw ERC-20 tokens accidentally sent to adapter
    /// @param token The ERC-20 token address
    /// @param to The recipient address
    function emergencyWithdrawERC20(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (token == address(0) || to == address(0)) revert InvalidTarget();
        uint256 balance = IERC20(token).balanceOf(address(this));
        require(balance > 0, "No tokens");
        IERC20(token).safeTransfer(to, balance);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Calculate protocol fee from message value
    /// @param value The message value
    /// @return fee The protocol fee
    function _calculateProtocolFee(
        uint256 value
    ) internal view returns (uint256) {
        if (bridgeFee == 0) return 0;
        return (value * bridgeFee) / 10_000;
    }

    /// @notice Allow receiving ETH for bridge message fees
    receive() external payable {}
}
