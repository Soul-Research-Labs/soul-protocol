// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./IBridgeAdapter.sol";

/**
 * @title IStarknetCore
 * @notice Minimal interface for the Starknet Core contract on Ethereum L1
 * @dev The Starknet Core contract handles L1↔L2 messaging and state updates.
 */
interface IStarknetCore {
    /// @notice Send a message to an L2 contract on Starknet
    /// @param toAddress The Starknet L2 contract address (felt252)
    /// @param selector The L2 function selector (felt252)
    /// @param payload The message payload (array of felt252 values)
    /// @return msgHash The L1→L2 message hash
    /// @return nonce The message nonce
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32 msgHash, uint256 nonce);

    /// @notice Consume an L2→L1 message delivered by the Starknet sequencer
    /// @param fromAddress The L2 contract that sent the message (felt252)
    /// @param payload The message payload
    /// @return msgHash The consumed message hash
    function consumeMessageFromL2(
        uint256 fromAddress,
        uint256[] calldata payload
    ) external returns (bytes32 msgHash);

    /// @notice Check the number of pending L1→L2 messages with a given hash
    function l1ToL2Messages(bytes32 msgHash) external view returns (uint256);

    /// @notice Check the number of pending L2→L1 messages with a given hash
    function l2ToL1Messages(bytes32 msgHash) external view returns (uint256);
}

/**
 * @title StarknetBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Starknet L2 integration
 * @dev Enables ZASEON cross-chain interoperability with Starknet via the
 *      StarknetCore contract deployed on Ethereum L1.
 *
 * STARKNET INTEGRATION:
 * - ZK-STARK rollup with Cairo VM (not EVM-compatible)
 * - L1→L2: sendMessageToL2 on StarknetCore (auto-consumed by L2 contract)
 * - L2→L1: consumeMessageFromL2 on StarknetCore (requires sequencer inclusion)
 * - Proof finality: ~2-6 hours (STARK proof computation + L1 verification)
 * - Addresses are 251-bit felt values (not 160-bit EVM addresses)
 * - Function selectors are Pedersen hashes of function names
 *
 * SECURITY NOTES:
 * - Messages are stored in the StarknetCore contract with counters
 * - L2→L1 messages require inclusion in a proven state update
 * - L1→L2 messages can be cancelled after a timeout if not consumed
 * - Payload encoding uses felt252 arrays (each value < FELT_MAX)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract StarknetBridgeAdapter is
    IBridgeAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
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

    /// @notice Starknet mainnet chain ID (SN_MAIN)
    uint256 public constant STARKNET_CHAIN_ID = 0x534e5f4d41494e; // "SN_MAIN" as felt

    /// @notice Starknet Sepolia testnet chain ID (SN_SEPOLIA)
    uint256 public constant STARKNET_SEPOLIA_CHAIN_ID = 0x534e5f5345504f4c4941;

    /// @notice Finality blocks (STARK proof finality ~2-6 hours)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Maximum felt252 value (P - 1 where P is the Stark prime)
    uint256 public constant FELT_MAX =
        0x800000000000011000000000000000000000000000000000000000000000000;

    /// @notice Max payload length (in felt252 elements)
    uint256 public constant MAX_PAYLOAD_LENGTH = 256;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        CONSUMED,
        CANCELLED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        uint256 starknetTarget; // Starknet L2 contract address (felt252)
        uint256 selector; // L2 function selector (felt252)
        uint256 timestamp;
        uint256 starknetNonce;
        bytes32 msgHash;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Starknet Core contract on Ethereum L1
    IStarknetCore public starknetCore;

    /// @notice ZASEON Hub contract address on Starknet (felt252)
    uint256 public zaseonHubStarknet;

    /// @notice Default L2 function selector for receiving ZASEON messages
    /// @dev Pedersen hash of "receive_zaseon_message"
    uint256 public defaultSelector;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by internal hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Starknet msg hash → internal message hash mapping
    mapping(bytes32 => bytes32) public starknetToInternalHash;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a message is sent to Starknet L2
    /// @param messageHash The internal unique hash identifying this message
    /// @param starknetTarget The Starknet L2 contract address (felt252)
    /// @param selector The L2 function selector (felt252)
    /// @param nonce The message nonce
    /// @param starknetMsgHash The Starknet L1→L2 message hash
    event MessageSentToStarknet(
        bytes32 indexed messageHash,
        uint256 indexed starknetTarget,
        uint256 selector,
        uint256 nonce,
        bytes32 starknetMsgHash
    );
    /// @notice Emitted when a message from Starknet L2 is consumed
    /// @param messageHash The internal message hash
    /// @param starknetSender The Starknet L2 contract that sent the message (felt252)
    /// @param starknetMsgHash The consumed L2→L1 message hash
    event MessageConsumedFromStarknet(
        bytes32 indexed messageHash,
        uint256 indexed starknetSender,
        bytes32 starknetMsgHash
    );
    /// @notice Emitted when the bridge configuration is updated
    /// @param starknetCore The new StarknetCore contract address
    event BridgeConfigured(address starknetCore);
    /// @notice Emitted when the Zaseon Hub address on Starknet is set
    /// @param zaseonHubStarknet The new Starknet hub contract address (felt252)
    event ZaseonHubStarknetSet(uint256 indexed zaseonHubStarknet);
    /// @notice Emitted when the default L2 function selector is set
    /// @param selector The new default selector value
    event DefaultSelectorSet(uint256 selector);
    /// @notice Emitted when the proof registry address is set
    /// @param proofRegistry The new proof registry address
    event ProofRegistrySet(address indexed proofRegistry);
    /// @notice Emitted when an emergency ETH withdrawal is performed
    /// @param to The recipient address
    /// @param amount The amount of ETH withdrawn
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _starknetCore Address of the StarknetCore contract on L1
    /// @param _admin Address to receive admin roles
    constructor(address _starknetCore, address _admin) {
        require(_admin != address(0), "Invalid admin");
        require(_starknetCore != address(0), "Invalid StarknetCore");

        starknetCore = IStarknetCore(_starknetCore);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the StarknetCore contract address
    /// @param _starknetCore Address of the new StarknetCore contract
    function configureStarknetBridge(
        address _starknetCore
    ) external onlyRole(OPERATOR_ROLE) {
        require(_starknetCore != address(0), "Invalid StarknetCore");
        starknetCore = IStarknetCore(_starknetCore);
        emit BridgeConfigured(_starknetCore);
    }

    /// @notice Set the ZASEON Hub L2 contract address on Starknet
    /// @param _zaseonHubStarknet The Starknet contract address (felt252)
    function setZaseonHubStarknet(
        uint256 _zaseonHubStarknet
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            _zaseonHubStarknet > 0 && _zaseonHubStarknet < FELT_MAX,
            "Invalid Starknet address"
        );
        zaseonHubStarknet = _zaseonHubStarknet;
        emit ZaseonHubStarknetSet(_zaseonHubStarknet);
    }

    /// @notice Set the default L2 function selector for ZASEON messages
    /// @param _selector Pedersen hash of the function name
    function setDefaultSelector(
        uint256 _selector
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_selector > 0 && _selector < FELT_MAX, "Invalid selector");
        defaultSelector = _selector;
        emit DefaultSelectorSet(_selector);
    }

    /// @notice Set Proof Registry address
    /// @param _proofRegistry Address of the proof registry contract
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

    /// @notice Get the Starknet chain ID
    function chainId() external pure returns (uint256) {
        return STARKNET_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Starknet";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return
            address(starknetCore) != address(0) &&
            zaseonHubStarknet > 0 &&
            defaultSelector > 0;
    }

    /// @notice Get the number of blocks required for finality
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to Starknet L2 via StarknetCore
     * @param starknetTarget The L2 contract address (felt252)
     * @param selector The L2 function selector (felt252, 0 = use default)
     * @param payload Array of felt252 values as the message body
     * @return messageHash Internal unique hash identifying this message
     * @dev Calls sendMessageToL2 on the StarknetCore contract.
     *      msg.value pays the L1→L2 message fee.
     */
    function sendMessage(
        uint256 starknetTarget,
        uint256 selector,
        uint256[] calldata payload
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        require(
            starknetTarget > 0 && starknetTarget < FELT_MAX,
            "Invalid target"
        );
        require(address(starknetCore) != address(0), "Bridge not configured");
        require(payload.length <= MAX_PAYLOAD_LENGTH, "Payload too large");

        uint256 actualSelector = selector > 0 ? selector : defaultSelector;
        require(actualSelector > 0, "No selector configured");

        // Validate all payload elements are valid felts
        for (uint256 i = 0; i < payload.length; ) {
            require(payload[i] < FELT_MAX, "Payload element exceeds felt max");
            unchecked {
                ++i;
            }
        }

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                starknetTarget,
                actualSelector,
                payload,
                nonce,
                block.timestamp
            )
        );

        (bytes32 starknetMsgHash, uint256 starknetNonce) = starknetCore
            .sendMessageToL2{value: msg.value}(
            starknetTarget,
            actualSelector,
            payload
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            starknetTarget: starknetTarget,
            selector: actualSelector,
            timestamp: block.timestamp,
            starknetNonce: starknetNonce,
            msgHash: starknetMsgHash
        });

        starknetToInternalHash[starknetMsgHash] = messageHash;

        emit MessageSentToStarknet(
            messageHash,
            starknetTarget,
            actualSelector,
            nonce,
            starknetMsgHash
        );

        return messageHash;
    }

    /**
     * @notice Consume an L2→L1 message from Starknet
     * @param starknetSender The Starknet contract that sent the message (felt252)
     * @param payload The message payload (felt252 array)
     * @return messageHash Internal hash for the consumed message
     * @dev Calls consumeMessageFromL2 on StarknetCore. The message must have
     *      been included in a proven Starknet state update.
     */
    function consumeMessage(
        uint256 starknetSender,
        uint256[] calldata payload
    )
        external
        onlyRole(RELAYER_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        require(
            starknetSender > 0 && starknetSender < FELT_MAX,
            "Invalid sender"
        );
        require(
            zaseonHubStarknet == 0 || starknetSender == zaseonHubStarknet,
            "Unauthorized sender"
        );
        require(payload.length <= MAX_PAYLOAD_LENGTH, "Payload too large");

        bytes32 starknetMsgHash = starknetCore.consumeMessageFromL2(
            starknetSender,
            payload
        );

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                starknetSender,
                payload,
                nonce,
                block.timestamp,
                "L2_TO_L1"
            )
        );

        messages[messageHash] = MessageRecord({
            status: MessageStatus.CONSUMED,
            starknetTarget: starknetSender,
            selector: 0,
            timestamp: block.timestamp,
            starknetNonce: 0,
            msgHash: starknetMsgHash
        });

        starknetToInternalHash[starknetMsgHash] = messageHash;

        emit MessageConsumedFromStarknet(
            messageHash,
            starknetSender,
            starknetMsgHash
        );

        return messageHash;
    }

    /**
     * @notice Verify a message by checking its status
     * @param messageHash Internal hash of the message to verify
     * @param proof Proof data (unused — status based)
     * @return True if the message was sent or consumed
     */
    function verifyMessage(
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        if (proof.length == 0) return false;
        MessageRecord storage record = messages[messageHash];
        return
            record.status == MessageStatus.SENT ||
            record.status == MessageStatus.CONSUMED;
    }

    /**
     * @notice Check if a Starknet L1→L2 message is still pending
     * @param starknetMsgHash The Starknet message hash
     * @return pending Number of pending instances of this message
     */
    function isPendingL1ToL2(
        bytes32 starknetMsgHash
    ) external view returns (uint256) {
        return starknetCore.l1ToL2Messages(starknetMsgHash);
    }

    /**
     * @notice Check if a Starknet L2→L1 message is available for consumption
     * @param starknetMsgHash The Starknet message hash
     * @return available Number of available instances
     */
    function isAvailableL2ToL1(
        bytes32 starknetMsgHash
    ) external view returns (uint256) {
        return starknetCore.l2ToL1Messages(starknetMsgHash);
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
    /// @param to The recipient address for the withdrawn ETH
    /// @param amount The amount of ETH to withdraw
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
        require(address(starknetCore) != address(0), "Bridge not configured");

        // Encode the EVM payload as a single felt252 element (keccak hash)
        uint256[] memory starknetPayload = new uint256[](1);
        starknetPayload[0] = uint256(keccak256(payload)) % FELT_MAX;

        uint256 target = zaseonHubStarknet > 0
            ? zaseonHubStarknet
            : uint256(uint160(targetAddress));
        uint256 sel = defaultSelector > 0 ? defaultSelector : 1;

        uint256 nonce = messageNonce++;
        messageId = keccak256(
            abi.encode(target, sel, starknetPayload, nonce, block.timestamp)
        );

        (bytes32 starknetMsgHash, uint256 starknetNonce) = starknetCore
            .sendMessageToL2{value: msg.value}(target, sel, starknetPayload);

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            starknetTarget: target,
            selector: sel,
            timestamp: block.timestamp,
            starknetNonce: starknetNonce,
            msgHash: starknetMsgHash
        });

        starknetToInternalHash[starknetMsgHash] = messageId;
        return messageId;
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure override returns (uint256 nativeFee) {
        // Starknet L1→L2 message fee is paid via msg.value; estimate conservatively
        return 0.001 ether;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageRecord storage record = messages[messageId];
        return
            record.status == MessageStatus.SENT ||
            record.status == MessageStatus.CONSUMED;
    }

    /// @notice Allow receiving ETH for L1→L2 message fees
    receive() external payable {}
}
