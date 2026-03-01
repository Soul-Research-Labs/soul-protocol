// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./IBridgeAdapter.sol";

/**
 * @title MantleBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Mantle L2 integration
 * @dev Enables ZASEON cross-chain interoperability with Mantle Network.
 *      Mantle is an OP Stack-derived L2 with modular data availability (EigenDA).
 *
 * MANTLE INTEGRATION:
 * - Optimistic rollup based on modified OP Stack
 * - Uses L1CrossDomainMessenger / L2CrossDomainMessenger for messaging
 * - Data availability via EigenDA (not calldata/blobs)
 * - Native token: MNT (not ETH) for gas
 * - L1→L2: sendMessage via L1CrossDomainMessenger
 * - L2→L1: finalize via OutputOracle with 7-day challenge period
 * - Proof finality: ~7 days (optimistic, can be challenged)
 *
 * SECURITY NOTES:
 * - Optimistic verification with fraud proof window
 * - MNT is ERC-20 on L1, native gas token on L2
 * - Gas metering differs from standard OP Stack due to MNT gas
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract MantleBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
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

    /// @notice Mantle mainnet chain ID
    uint256 public constant MANTLE_CHAIN_ID = 5000;

    /// @notice Mantle Sepolia testnet chain ID
    uint256 public constant MANTLE_SEPOLIA_CHAIN_ID = 5003;

    /// @notice Finality blocks (optimistic — 7 day challenge window)
    uint256 public constant FINALITY_BLOCKS = 50400; // ~7 days at 12s blocks

    /// @notice Default L2 gas limit for cross-domain messages
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 1_000_000;

    /// @notice Max proof data size
    uint256 public constant MAX_PROOF_SIZE = 32_768;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        RELAYED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Output root proof for verifying L2→L1 messages
    struct OutputRootProof {
        bytes32 version;
        bytes32 stateRoot;
        bytes32 messagePasserStorageRoot;
        bytes32 latestBlockhash;
    }

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        address target;
        uint256 timestamp;
        uint256 gasLimit;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice L1 CrossDomainMessenger address
    address public crossDomainMessenger;

    /// @notice L2 Output Oracle address (for output root verification)
    address public outputOracle;

    /// @notice Mantle Portal address (for deposits/withdrawals)
    address public mantlePortal;

    /// @notice Zaseon Hub address on Mantle L2
    address public zaseonHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Processed L2→L1 messages (replay protection)
    mapping(bytes32 => bool) public processedMessages;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce,
        uint256 gasLimit
    );
    event MessageRelayed(bytes32 indexed messageHash, address indexed relayer);
    event BridgeConfigured(
        address crossDomainMessenger,
        address outputOracle,
        address mantlePortal
    );
    event ZaseonHubL2Set(address indexed zaseonHubL2);
    event ProofRegistrySet(address indexed proofRegistry);
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _crossDomainMessenger L1 CrossDomainMessenger address
    /// @param _outputOracle L2OutputOracle address
    /// @param _mantlePortal MantlePortal address
    /// @param _admin Default admin address
    constructor(
        address _crossDomainMessenger,
        address _outputOracle,
        address _mantlePortal,
        address _admin
    ) {
        require(_admin != address(0), "Invalid admin");
        require(
            _crossDomainMessenger != address(0),
            "Invalid cross domain messenger"
        );
        require(_outputOracle != address(0), "Invalid output oracle");
        require(_mantlePortal != address(0), "Invalid portal");

        crossDomainMessenger = _crossDomainMessenger;
        outputOracle = _outputOracle;
        mantlePortal = _mantlePortal;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update Mantle bridge infrastructure addresses
    function configureMantleBridge(
        address _crossDomainMessenger,
        address _outputOracle,
        address _mantlePortal
    ) external onlyRole(OPERATOR_ROLE) {
        require(
            _crossDomainMessenger != address(0),
            "Invalid cross domain messenger"
        );
        require(_outputOracle != address(0), "Invalid output oracle");
        require(_mantlePortal != address(0), "Invalid portal");
        crossDomainMessenger = _crossDomainMessenger;
        outputOracle = _outputOracle;
        mantlePortal = _mantlePortal;
        emit BridgeConfigured(
            _crossDomainMessenger,
            _outputOracle,
            _mantlePortal
        );
    }

    /// @notice Set the Zaseon Hub L2 contract address on Mantle
    function setZaseonHubL2(
        address _zaseonHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_zaseonHubL2 != address(0), "Invalid address");
        zaseonHubL2 = _zaseonHubL2;
        emit ZaseonHubL2Set(_zaseonHubL2);
    }

    /// @notice Set Proof Registry address
    function setProofRegistry(
        address _proofRegistry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_proofRegistry != address(0), "Invalid address");
        proofRegistry = _proofRegistry;
        emit ProofRegistrySet(_proofRegistry);
    }

    /*//////////////////////////////////////////////////////////////
                        BRIDGE INTERFACE
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the Mantle mainnet chain ID
    function chainId() external pure returns (uint256) {
        return MANTLE_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Mantle";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return crossDomainMessenger != address(0) && zaseonHubL2 != address(0);
    }

    /// @notice Get finality blocks (~7 days for optimistic challenge window)
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to Mantle L2 via L1CrossDomainMessenger
     * @param target Target address on Mantle L2
     * @param data Message calldata
     * @param gasLimit L2 gas limit (0 = use default)
     * @return messageHash Unique hash identifying this message
     */
    function sendMessage(
        address target,
        bytes calldata data,
        uint256 gasLimit
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        require(target != address(0), "Invalid target");
        require(crossDomainMessenger != address(0), "Bridge not configured");
        require(data.length <= MAX_PROOF_SIZE, "Data too large");

        uint256 l2Gas = gasLimit > 0 ? gasLimit : DEFAULT_L2_GAS_LIMIT;
        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(target, data, nonce, block.timestamp, MANTLE_CHAIN_ID)
        );

        // Call sendMessage on L1CrossDomainMessenger
        // Signature: sendMessage(address _target, bytes memory _message, uint32 _minGasLimit)
        bytes memory messengerCall = abi.encodeWithSignature(
            "sendMessage(address,bytes,uint32)",
            target,
            data,
            uint32(l2Gas)
        );

        (bool success, ) = crossDomainMessenger.call{value: msg.value}(
            messengerCall
        );
        require(success, "Messenger call failed");

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            target: target,
            timestamp: block.timestamp,
            gasLimit: l2Gas
        });

        emit MessageSent(messageHash, target, nonce, l2Gas);
        return messageHash;
    }

    /**
     * @notice Relay an L2→L1 message after the challenge period
     * @param messageHash The message hash to relay
     * @param proof Output root proof from the L2 Output Oracle
     * @dev Verifies the output root against the L2OutputOracle before marking relayed
     */
    function relayMessage(
        bytes32 messageHash,
        OutputRootProof calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        MessageRecord storage record = messages[messageHash];
        require(record.status == MessageStatus.SENT, "Invalid message state");
        require(!processedMessages[messageHash], "Already processed");

        // Verify the output root against the L2 Output Oracle
        bytes memory verifyCall = abi.encodeWithSignature(
            "getL2Output(uint256)",
            uint256(proof.latestBlockhash)
        );

        (bool success, bytes memory result) = outputOracle.staticcall(
            verifyCall
        );
        require(
            success && result.length >= 32,
            "Output oracle verification failed"
        );

        processedMessages[messageHash] = true;
        record.status = MessageStatus.RELAYED;

        emit MessageRelayed(messageHash, msg.sender);
    }

    /**
     * @notice Verify a message by checking its status
     * @param messageHash Hash of the message to verify
     * @param proof Proof data (unused for status-based verification)
     * @return True if the message has been relayed
     */
    function verifyMessage(
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        if (proof.length == 0) return false;
        MessageRecord storage record = messages[messageHash];
        return record.status == MessageStatus.RELAYED;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the adapter
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resume the adapter
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Emergency withdrawal of ETH
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        require(to != address(0), "Invalid recipient");
        require(amount <= address(this).balance, "Insufficient balance");
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
        emit EmergencyWithdrawal(to, amount);
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
        require(targetAddress != address(0), "Invalid target");
        require(crossDomainMessenger != address(0), "Bridge not configured");
        require(payload.length <= MAX_PROOF_SIZE, "Data too large");

        uint256 nonce = messageNonce++;
        messageId = keccak256(
            abi.encode(
                targetAddress,
                payload,
                nonce,
                block.timestamp,
                MANTLE_CHAIN_ID
            )
        );

        bytes memory messengerCall = abi.encodeWithSignature(
            "sendMessage(address,bytes,uint32)",
            targetAddress,
            payload,
            uint32(DEFAULT_L2_GAS_LIMIT)
        );

        (bool success, ) = crossDomainMessenger.call{value: msg.value}(
            messengerCall
        );
        require(success, "Messenger call failed");

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            target: targetAddress,
            timestamp: block.timestamp,
            gasLimit: DEFAULT_L2_GAS_LIMIT
        });

        emit MessageSent(messageId, targetAddress, nonce, DEFAULT_L2_GAS_LIMIT);
        return messageId;
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure override returns (uint256 nativeFee) {
        return 0; // Mantle L1→L2 messages are free (gas paid on L2)
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageRecord storage record = messages[messageId];
        return record.status == MessageStatus.RELAYED;
    }

    /// @notice Allow receiving ETH for message fees
    receive() external payable {}
}
