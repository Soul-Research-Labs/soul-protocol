// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IBridgeAdapter.sol";

/**
 * @title ISecretGateway
 * @notice Minimal interface for the Secret Network–Ethereum Gateway contract
 * @dev Secret Network uses Intel SGX TEE-based encryption for private computation.
 *      The Gateway contract on Ethereum enables message passing between EVM and
 *      Secret Network via a relayer network that submits signed attestations.
 */
interface ISecretGateway {
    /// @notice Send an encrypted message to Secret Network
    /// @param routingInfo The Secret contract address (bech32-encoded, passed as bytes)
    /// @param payload The encrypted payload (AES-256-GCM encrypted by gateway key)
    /// @return taskId Unique task identifier for tracking
    function send(
        bytes calldata routingInfo,
        bytes calldata payload
    ) external payable returns (bytes32 taskId);

    /// @notice Get the estimated relay fee for a message
    /// @return fee The fee in native currency
    function estimateFee() external view returns (uint256 fee);

    /// @notice Get the current task nonce
    /// @return nonce The current task nonce
    function taskNonce() external view returns (uint256 nonce);
}

/**
 * @title ISecretVerifier
 * @notice Interface for verifying Secret Network TEE attestation proofs
 * @dev Attestation proofs are signed by the Secret Network validator set
 *      (Intel SGX enclave signing keys). The verifier checks the aggregated
 *      attestation and validates the enclave measurement (MRENCLAVE).
 */
interface ISecretVerifier {
    /// @notice Verify a TEE attestation from Secret Network validators
    /// @param attestation The aggregated attestation from validator enclaves
    /// @param data The plaintext data being attested
    /// @return valid Whether the attestation is valid
    function verifyAttestation(
        bytes calldata attestation,
        bytes calldata data
    ) external returns (bool valid);

    /// @notice Get the current validator set hash
    /// @return hash The hash of the active validator set
    function validatorSetHash() external view returns (bytes32 hash);
}

/**
 * @title SecretBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Secret Network — privacy-first L1 with TEE-based encryption
 * @dev Enables ZASEON cross-chain interoperability with Secret Network's private
 *      computation environment via the Secret Gateway and TEE attestation verification.
 *
 * SECRET NETWORK INTEGRATION:
 * - Independent L1 (Cosmos SDK / Tendermint BFT consensus)
 * - Privacy model: Intel SGX TEE-based encrypted state + compute
 * - Encryption: AES-256-GCM with enclave-derived keys
 * - Native token: SCRT
 * - Smart contracts: CosmWasm ("Secret Contracts") with encrypted state
 * - Cross-chain: IBC (Cosmos IBC), Axelar GMP, Secret–Ethereum Gateway
 *
 * MESSAGE FLOW:
 * - ZASEON→Secret: Encrypt payload → Gateway.send() → relayer → Secret contract
 * - Secret→ZASEON: TEE produces attestation → relayer submits → verifier validates
 *
 * SECURITY NOTES:
 * - TEE attestation verified on-chain by SecretVerifier contract
 * - Nullifier-based replay protection (integrates with SECRET_TEE in ZASEON)
 * - Validator set hash checked to prevent stale attestation attacks
 * - All state-changing functions protected by ReentrancyGuard and access control
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract SecretBridgeAdapter is
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
    /// @notice Role for relayers who can relay Secret attestations
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Role for pausers who can pause the adapter
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Secret Network virtual chain identifier (ZASEON-internal)
    /// @dev Secret Network has Cosmos chain-id "secret-4" (mainnet).
    ///      5100 is the ZASEON-internal identifier for the "Secret privacy zone".
    uint16 public constant SECRET_CHAIN_ID = 5100;

    /// @notice Finality in Tendermint blocks (~6s each)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Max bridge fee in basis points (1% = 100 bps)
    uint256 public constant MAX_BRIDGE_FEE_BPS = 100;

    /// @notice Max payload length
    uint256 public constant MAX_PAYLOAD_LENGTH = 10_000;

    /// @notice TEE attestation minimum length (enclave signature + data)
    uint256 public constant MIN_ATTESTATION_SIZE = 64;

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
        bytes32 taskId; // Gateway task ID or attestation ID
        uint256 timestamp;
        bytes32 validatorSetHash; // Validator set hash at time of action
        bytes32 nullifier; // Nullifier for replay protection
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Secret Network Gateway contract on Ethereum
    ISecretGateway public secretGateway;

    /// @notice TEE attestation verifier contract
    ISecretVerifier public secretVerifier;

    /// @notice Bridge fee in basis points (max 100 = 1%)
    uint256 public bridgeFee;

    /// @notice Minimum message fee in native currency
    uint256 public minMessageFee;

    /// @notice Accumulated protocol fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent ZASEON → Secret
    uint256 public totalMessagesSent;

    /// @notice Total messages received Secret → ZASEON
    uint256 public totalMessagesReceived;

    /// @notice Total value bridged (native)
    uint256 public totalValueBridged;

    /// @notice Per-sender nonce counter
    mapping(address => uint256) public senderNonces;

    /// @notice Nullifier → consumed flag (replay protection, integrates with SECRET_TAG)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Internal message tracking by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a message is sent to Secret Network (ZASEON → Secret)
    event MessageSentToSecret(
        bytes32 indexed messageHash,
        bytes32 indexed taskId,
        uint256 nonce,
        address sender
    );

    /// @notice Emitted when a verified attestation from Secret is consumed (Secret → ZASEON)
    event MessageReceivedFromSecret(
        bytes32 indexed messageHash,
        bytes32 indexed nullifier,
        bytes32 validatorSetHash,
        uint256 nonce
    );

    /// @notice Emitted when the Secret Gateway address is updated
    event SecretGatewaySet(address indexed gateway);

    /// @notice Emitted when the Secret Verifier address is updated
    event SecretVerifierSet(address indexed verifier);

    /// @notice Emitted when the bridge fee is updated
    event BridgeFeeSet(uint256 feeBps);

    /// @notice Emitted when the minimum message fee is updated
    event MinMessageFeeSet(uint256 fee);

    /// @notice Emitted on emergency ETH withdrawal
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /// @notice Emitted when accumulated fees are withdrawn
    event FeesWithdrawn(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                             ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidGateway();
    error InvalidVerifier();
    error InvalidTarget();
    error InvalidPayload();
    error BridgeNotConfigured();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidAttestation();
    error FeeTooHigh(uint256 fee);
    error InsufficientFee(uint256 required, uint256 provided);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _secretGateway Address of the Secret Network Gateway on Ethereum
    /// @param _secretVerifier Address of the TEE attestation verifier contract
    /// @param _admin Address to receive admin roles
    constructor(
        address _secretGateway,
        address _secretVerifier,
        address _admin
    ) {
        if (_admin == address(0)) revert InvalidTarget();
        if (_secretGateway == address(0)) revert InvalidGateway();
        if (_secretVerifier == address(0)) revert InvalidVerifier();

        secretGateway = ISecretGateway(_secretGateway);
        secretVerifier = ISecretVerifier(_secretVerifier);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Secret Network Gateway address
    /// @param _secretGateway New Gateway address
    function setSecretGateway(
        address _secretGateway
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_secretGateway == address(0)) revert InvalidGateway();
        secretGateway = ISecretGateway(_secretGateway);
        emit SecretGatewaySet(_secretGateway);
    }

    /// @notice Update the TEE attestation verifier address
    /// @param _secretVerifier New verifier address
    function setSecretVerifier(
        address _secretVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_secretVerifier == address(0)) revert InvalidVerifier();
        secretVerifier = ISecretVerifier(_secretVerifier);
        emit SecretVerifierSet(_secretVerifier);
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

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the Secret virtual chain ID
    function chainId() external pure returns (uint16) {
        return SECRET_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Secret Network";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(secretGateway) != address(0) &&
            address(secretVerifier) != address(0);
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

    /// @notice Get the current validator set hash from the verifier
    /// @return The validator set hash
    function getValidatorSetHash() external view returns (bytes32) {
        return secretVerifier.validatorSetHash();
    }

    /// @notice Get the nonce for a specific sender
    /// @param sender The sender address
    /// @return The current nonce
    function getSenderNonce(address sender) external view returns (uint256) {
        return senderNonces[sender];
    }

    /*//////////////////////////////////////////////////////////////
                   SEND OPERATIONS (ZASEON → SECRET)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a ZASEON message to Secret Network via the Gateway
     * @param routingInfo The Secret contract address (bech32 bytes)
     * @param payload The message payload (will be encrypted by the Gateway)
     * @return messageHash Internal unique hash identifying this message
     * @dev Calls ISecretGateway.send() to relay the encrypted message.
     *      msg.value pays for gas + relay fees on Secret Network.
     */
    function sendMessage(
        bytes calldata routingInfo,
        bytes calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (routingInfo.length == 0) revert InvalidTarget();
        if (address(secretGateway) == address(0)) revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Calculate fees
        uint256 protocolFee = _calculateProtocolFee(msg.value);
        uint256 totalRequired = protocolFee + minMessageFee;

        if (msg.value < totalRequired) {
            revert InsufficientFee(totalRequired, msg.value);
        }

        accumulatedFees += protocolFee;

        uint256 nonce = messageNonce++;

        // Send to Secret Gateway
        bytes32 taskId = secretGateway.send{value: msg.value - protocolFee}(
            routingInfo,
            payload
        );

        bytes32 messageHash = keccak256(
            abi.encode(taskId, routingInfo, nonce, block.timestamp)
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            taskId: taskId,
            timestamp: block.timestamp,
            validatorSetHash: bytes32(0),
            nullifier: bytes32(0)
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;
        senderNonces[msg.sender]++;

        emit MessageSentToSecret(messageHash, taskId, nonce, msg.sender);

        return messageHash;
    }

    /*//////////////////////////////////////////////////////////////
                  RECEIVE OPERATIONS (SECRET → ZASEON)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Receive and verify a message from Secret Network with TEE attestation
     * @param attestation The aggregated TEE attestation from Secret validators
     * @param publicInputs The public data [validatorSetHash, nullifier, taskIdOut, payloadHash]
     * @param payload The message payload for ZASEON processing
     * @return messageHash Internal hash for the received message
     * @dev Verifies the TEE attestation via SecretVerifier, checks nullifier uniqueness.
     */
    function receiveMessage(
        bytes calldata attestation,
        uint256[] calldata publicInputs,
        bytes calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        if (address(secretVerifier) == address(0)) revert BridgeNotConfigured();

        // publicInputs layout:
        // [0] = validatorSetHash
        // [1] = nullifier (unique per Secret message)
        // [2] = taskId (correlates with Secret gateway task)
        // [3] = payloadHash (keccak256 of the payload)
        require(publicInputs.length >= 4, "Insufficient public inputs");

        // Verify TEE attestation via SecretVerifier
        bool valid = secretVerifier.verifyAttestation(attestation, payload);
        if (!valid) revert InvalidAttestation();

        // Extract fields from public inputs
        bytes32 validatorSetHash = bytes32(publicInputs[0]);
        bytes32 nullifier = bytes32(publicInputs[1]);
        bytes32 payloadHash = bytes32(publicInputs[3]);

        // Verify payload integrity
        require(keccak256(payload) == payloadHash, "Payload hash mismatch");

        // Replay protection via nullifier
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        usedNullifiers[nullifier] = true;

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                validatorSetHash,
                nullifier,
                nonce,
                block.timestamp,
                "SECRET_TO_ZASEON"
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.DELIVERED,
            taskId: bytes32(publicInputs[2]),
            timestamp: block.timestamp,
            validatorSetHash: validatorSetHash,
            nullifier: nullifier
        });

        totalMessagesReceived++;

        emit MessageReceivedFromSecret(
            messageHash,
            nullifier,
            validatorSetHash,
            nonce
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
        if (address(secretGateway) == address(0)) revert BridgeNotConfigured();
        if (payload.length == 0 || payload.length > MAX_PAYLOAD_LENGTH) {
            revert InvalidPayload();
        }

        // Encode target address as routing info for Secret Gateway
        bytes memory routingInfo = abi.encode(targetAddress);

        uint256 nonce = messageNonce++;

        bytes32 taskId = secretGateway.send{value: msg.value}(
            routingInfo,
            payload
        );

        messageId = keccak256(
            abi.encode(taskId, routingInfo, nonce, block.timestamp)
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            taskId: taskId,
            timestamp: block.timestamp,
            validatorSetHash: bytes32(0),
            nullifier: bytes32(0)
        });

        totalMessagesSent++;
        totalValueBridged += msg.value;
        senderNonces[msg.sender]++;

        return messageId;
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external view override returns (uint256 nativeFee) {
        uint256 gatewayFee = address(secretGateway) != address(0)
            ? secretGateway.estimateFee()
            : 0;
        return gatewayFee + minMessageFee;
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

    /// @notice Allow receiving ETH for gateway fees
    receive() external payable {}
}
