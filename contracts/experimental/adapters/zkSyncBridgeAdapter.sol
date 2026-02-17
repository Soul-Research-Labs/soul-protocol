// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title zkSyncBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for zkSync Era integration
 * @dev Enables cross-chain interoperability with zkSync Era L2
 * @custom:experimental This contract is research-tier and NOT production-ready. See contracts/experimental/README.md for promotion criteria.
 *
 * ZKSYNC ERA INTEGRATION:
 * - zkRollup with LLVM-based zkEVM
 * - Uses Diamond Proxy pattern (IMailbox interface)
 * - L1 -> L2: requestL2Transaction via Mailbox facet
 * - L2 -> L1: L2Log proofs via verifyL2Log on Diamond
 * - Native account abstraction support
 * - Proof finality: ~1 hour (batch commitment + proof verification)
 */
contract zkSyncBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
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

    /// @notice zkSync Era mainnet chain ID
    uint256 public constant ZKSYNC_CHAIN_ID = 324;

    /// @notice zkSync Era Sepolia testnet chain ID
    uint256 public constant ZKSYNC_SEPOLIA_CHAIN_ID = 300;

    /// @notice Finality blocks (ZK proof finality, ~1 hour on mainnet)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Default L2 gas limit for requestL2Transaction
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 800_000;

    /// @notice Default gas-per-pubdata-byte for zkSync fee model
    uint256 public constant DEFAULT_GAS_PER_PUBDATA = 800;

    /// @notice Max proof data size
    uint256 public constant MAX_PROOF_SIZE = 32_768;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        PROVED,
        RELAYED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice L2 log proof for verifying messages from zkSync
    struct L2LogProof {
        uint256 batchNumber;
        uint256 messageIndex;
        uint16 txNumberInBatch;
        bytes32[] merkleProof;
    }

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        address target;
        uint256 timestamp;
        bytes32 txHash;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice zkSync Diamond Proxy (Mailbox facet)
    address public zkSyncDiamond;

    /// @notice Soul Hub address on zkSync L2
    address public soulHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Processed L2 transaction hashes (replay protection)
    mapping(bytes32 => bool) public processedL2Txs;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce,
        bytes32 l2TxHash
    );
    event MessageRelayed(bytes32 indexed messageHash, address indexed sender);
    event MessageProved(bytes32 indexed messageHash, uint256 batchNumber);
    event BridgeConfigured(address indexed zkSyncDiamond);
    event SoulHubL2Set(address indexed soulHubL2);
    event ProofRegistrySet(address indexed proofRegistry);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _zkSyncDiamond) {
        require(_admin != address(0), "Invalid admin");
        require(_zkSyncDiamond != address(0), "Invalid diamond");

        zkSyncDiamond = _zkSyncDiamond;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the zkSync Diamond Proxy address
    function configureZkSyncBridge(
        address _zkSyncDiamond
    ) external onlyRole(OPERATOR_ROLE) {
        require(_zkSyncDiamond != address(0), "Invalid diamond");
        zkSyncDiamond = _zkSyncDiamond;
        emit BridgeConfigured(_zkSyncDiamond);
    }

    /// @notice Set Soul Hub L2 address on zkSync
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
        return ZKSYNC_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "zkSync Era";
    }

    function isConfigured() external view returns (bool) {
        return zkSyncDiamond != address(0) && soulHubL2 != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to zkSync Era L2 via the Mailbox facet
     * @param target Target address on L2
     * @param data Message calldata
     * @param gasLimit L2 gas limit (0 = use default)
     * @return messageHash Unique hash identifying this message
     * @dev Calls requestL2Transaction on the zkSync Diamond Proxy.
     *      msg.value covers the L2 execution fee (base cost + l2GasLimit * gasPrice).
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
        require(zkSyncDiamond != address(0), "Bridge not configured");
        require(data.length <= MAX_PROOF_SIZE, "Data too large");

        uint256 l2Gas = gasLimit > 0 ? gasLimit : DEFAULT_L2_GAS_LIMIT;
        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(target, data, nonce, block.timestamp, ZKSYNC_CHAIN_ID)
        );

        // Call requestL2Transaction on the zkSync Diamond (Mailbox facet)
        // Signature: requestL2Transaction(address _contractL2, uint256 _l2Value, bytes _calldata,
        //            uint256 _l2GasLimit, uint256 _l2GasPerPubdataByteLimit, bytes[] _factoryDeps, address _refundRecipient)
        bytes memory mailboxCall = abi.encodeWithSignature(
            "requestL2Transaction(address,uint256,bytes,uint256,uint256,bytes[],address)",
            target,
            0, // no L2 value transfer
            data,
            l2Gas,
            DEFAULT_GAS_PER_PUBDATA,
            new bytes[](0), // no factory deps
            msg.sender // refund to caller
        );

        (bool success, bytes memory result) = zkSyncDiamond.call{
            value: msg.value
        }(mailboxCall);
        require(success, "Mailbox call failed");

        bytes32 l2TxHash = result.length >= 32
            ? abi.decode(result, (bytes32))
            : bytes32(0);

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            target: target,
            timestamp: block.timestamp,
            txHash: l2TxHash
        });

        emit MessageSent(messageHash, target, nonce, l2TxHash);
        return messageHash;
    }

    /**
     * @notice Relay an L2-to-L1 message after proving it on L1
     * @param messageHash The message hash to relay
     * @param data The original message data
     * @param proof L2 log proof from zkSync
     * @dev Uses proveL2LogInclusion on the Diamond to verify the L2 log
     */
    function relayMessage(
        bytes32 messageHash,
        bytes calldata data,
        L2LogProof calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        MessageRecord storage record = messages[messageHash];
        require(
            record.status == MessageStatus.SENT ||
                record.status == MessageStatus.PROVED,
            "Invalid message state"
        );
        require(!processedL2Txs[record.txHash], "Already processed");

        // Verify the L2 log inclusion proof against the zkSync Diamond
        // Uses proveL2LogInclusion(uint256 _batchNumber, uint256 _index,
        //   L2Log memory _log, bytes32[] calldata _proof)
        // We use abi.encodeWithSelector with the function selector directly
        // because abi.encodeWithSignature cannot encode struct (tuple) types.
        bytes4 selector = bytes4(
            keccak256(
                "proveL2LogInclusion(uint256,uint256,(uint8,bool,uint16,address,bytes32,bytes32),bytes32[])"
            )
        );
        bytes memory verifyCall = abi.encodeWithSelector(
            selector,
            proof.batchNumber,
            proof.messageIndex,
            data,
            proof.merkleProof
        );

        (bool success, bytes memory result) = zkSyncDiamond.staticcall(
            verifyCall
        );
        require(success && result.length >= 32, "L2 log proof invalid");
        bool verified = abi.decode(result, (bool));
        require(verified, "L2 log proof rejected");

        processedL2Txs[record.txHash] = true;
        record.status = MessageStatus.RELAYED;

        emit MessageRelayed(messageHash, msg.sender);
    }

    /**
     * @notice Verify a message from zkSync using its L2 log proof
     * @param messageHash Hash of the message
     * @param proof Proof data (ABI-encoded L2LogProof)
     */
    function verifyMessage(
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        if (proof.length == 0) return false;
        MessageRecord storage record = messages[messageHash];
        return
            record.status == MessageStatus.RELAYED ||
            record.status == MessageStatus.PROVED;
    }

    /**
     * @notice Estimate the L1 -> L2 transaction cost
     * @param gasLimit L2 gas limit
     * @return baseCost The base cost in ETH
     */
    function estimateL2TransactionCost(
        uint256 gasLimit
    ) external view returns (uint256) {
        uint256 l2Gas = gasLimit > 0 ? gasLimit : DEFAULT_L2_GAS_LIMIT;

        // Call l2TransactionBaseCost on the Diamond (Mailbox facet)
        bytes memory call_ = abi.encodeWithSignature(
            "l2TransactionBaseCost(uint256,uint256,uint256)",
            tx.gasprice,
            l2Gas,
            DEFAULT_GAS_PER_PUBDATA
        );

        (bool success, bytes memory result) = zkSyncDiamond.staticcall(call_);
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

    /// @notice Allow receiving ETH for L2 fee payments
    receive() external payable {}
}
