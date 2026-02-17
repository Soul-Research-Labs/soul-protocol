// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title LineaBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Linea zkEVM integration
 * @dev Enables cross-chain interoperability with Linea L2
 * @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
 *
 * LINEA INTEGRATION:
 * - Type 2 zkEVM rollup by Consensys
 * - Uses IMessageService for cross-chain messaging
 * - L1 -> L2: sendMessage via MessageService (auto-claimed on L2)
 * - L2 -> L1: claimMessage via MessageService with Merkle proof
 * - Proof finality: ~8-32 hours (data submission + proof generation)
 * - Supports both ETH and ERC20 bridging via TokenBridge
 */
contract LineaBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Linea mainnet chain ID
    uint256 public constant LINEA_MAINNET_CHAIN_ID = 59144;

    /// @notice Linea Sepolia testnet chain ID
    uint256 public constant LINEA_SEPOLIA_CHAIN_ID = 59141;

    /// @notice Finality blocks (ZK proof finality)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Default fee for cross-chain messages
    uint256 public constant DEFAULT_MESSAGE_FEE = 0.001 ether;

    /// @notice Max proof data size
    uint256 public constant MAX_PROOF_SIZE = 32_768;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        CLAIMED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Merkle proof for claiming L2-to-L1 messages
    struct ClaimProof {
        uint256 messageNumber;
        uint256 leafIndex;
        bytes32[] merkleProof;
    }

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        address target;
        uint256 timestamp;
        uint256 messageNumber;
        uint256 fee;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Linea MessageService address
    address public messageService;

    /// @notice Linea TokenBridge address
    address public tokenBridge;

    /// @notice Linea Rollup contract (for finalization queries)
    address public rollup;

    /// @notice Soul Hub address on Linea L2
    address public soulHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Processed message numbers (replay protection)
    mapping(uint256 => bool) public processedMessages;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce,
        uint256 fee
    );
    event MessageClaimed(
        bytes32 indexed messageHash,
        address indexed claimer,
        uint256 messageNumber
    );
    event BridgeConfigured(
        address messageService,
        address tokenBridge,
        address rollup
    );
    event SoulHubL2Set(address indexed soulHubL2);
    event ProofRegistrySet(address indexed proofRegistry);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _messageService,
        address _tokenBridge,
        address _rollup,
        address _admin
    ) {
        require(_admin != address(0), "Invalid admin");
        require(_messageService != address(0), "Invalid message service");
        require(_tokenBridge != address(0), "Invalid token bridge");
        require(_rollup != address(0), "Invalid rollup");

        messageService = _messageService;
        tokenBridge = _tokenBridge;
        rollup = _rollup;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update Linea bridge addresses
    function configureLineaBridge(
        address _messageService,
        address _tokenBridge,
        address _rollup
    ) external onlyRole(OPERATOR_ROLE) {
        require(_messageService != address(0), "Invalid message service");
        messageService = _messageService;
        tokenBridge = _tokenBridge;
        rollup = _rollup;
        emit BridgeConfigured(_messageService, _tokenBridge, _rollup);
    }

    /// @notice Set Soul Hub L2 address on Linea
    function setSoulHubL2(
        address _soulHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_soulHubL2 != address(0), "Invalid address");
        soulHubL2 = _soulHubL2;
        emit SoulHubL2Set(_soulHubL2);
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

    function chainId() external pure returns (uint256) {
        return LINEA_MAINNET_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Linea";
    }

    function isConfigured() external view returns (bool) {
        return messageService != address(0) && soulHubL2 != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to Linea L2 via MessageService
     * @param target Target address on L2
     * @param data Message calldata
     * @param messageFee Fee for cross-chain delivery (0 = default)
     * @return messageHash Unique hash identifying this message
     * @dev Calls sendMessage on Linea's IMessageService.
     *      msg.value should cover fee + any ETH to bridge.
     */
    function sendMessage(
        address target,
        bytes calldata data,
        uint256 messageFee
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        require(target != address(0), "Invalid target");
        require(messageService != address(0), "Bridge not configured");
        require(data.length <= MAX_PROOF_SIZE, "Data too large");

        uint256 fee = messageFee > 0 ? messageFee : DEFAULT_MESSAGE_FEE;
        require(msg.value >= fee, "Insufficient fee");

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                target,
                data,
                nonce,
                block.timestamp,
                LINEA_MAINNET_CHAIN_ID
            )
        );

        // Call sendMessage on Linea MessageService
        // Signature: sendMessage(address _to, uint256 _fee, bytes _calldata)
        bytes memory msgCall = abi.encodeWithSignature(
            "sendMessage(address,uint256,bytes)",
            target,
            fee,
            data
        );

        (bool success, ) = messageService.call{value: msg.value}(msgCall);
        require(success, "MessageService call failed");

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            target: target,
            timestamp: block.timestamp,
            messageNumber: nonce,
            fee: fee
        });

        emit MessageSent(messageHash, target, nonce, fee);
        return messageHash;
    }

    /**
     * @notice Claim an L2-to-L1 message using a Merkle proof
     * @param messageHash The message hash to claim
     * @param proof Claim proof with Merkle path
     * @dev Calls claimMessage on the MessageService with the supplied proof
     */
    function claimMessage(
        bytes32 messageHash,
        ClaimProof calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        MessageRecord storage record = messages[messageHash];
        require(record.status == MessageStatus.SENT, "Invalid message state");
        require(!processedMessages[proof.messageNumber], "Already claimed");

        // Verify the Merkle proof against the MessageService
        bytes memory claimCall = abi.encodeWithSignature(
            "claimMessage(uint256,bytes32[])",
            proof.messageNumber,
            proof.merkleProof
        );

        (bool success, ) = messageService.call(claimCall);
        require(success, "Claim failed");

        processedMessages[proof.messageNumber] = true;
        record.status = MessageStatus.CLAIMED;

        emit MessageClaimed(messageHash, msg.sender, proof.messageNumber);
    }

    /**
     * @notice Verify a message from Linea
     * @param messageHash Hash of the message
     * @param proof Proof data
     */
    function verifyMessage(
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        if (proof.length == 0) return false;
        MessageRecord storage record = messages[messageHash];
        return record.status == MessageStatus.CLAIMED;
    }

    /**
     * @notice Check the last finalized L2 block number on Linea
     * @return blockNumber The last finalized L2 block
     */
    function getLastFinalizedBlock() external view returns (uint256) {
        if (rollup == address(0)) return 0;

        bytes memory call_ = abi.encodeWithSignature("currentL2BlockNumber()");
        (bool success, bytes memory result) = rollup.staticcall(call_);
        if (success && result.length >= 32) {
            return abi.decode(result, (uint256));
        }
        return 0;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

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
    }

    /// @notice Allow receiving ETH for fee payments
    receive() external payable {}
}
