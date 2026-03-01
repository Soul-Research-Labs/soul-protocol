// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./IBridgeAdapter.sol";

/**
 * @title PolygonZkEVMBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Polygon zkEVM L2 integration
 * @dev Enables ZASEON cross-chain interoperability with Polygon zkEVM.
 *      Uses the Polygon zkEVM bridge contract for L1 <-> L2 message passing.
 *
 * POLYGON ZKEVM INTEGRATION:
 * - Uses PolygonZkEVMBridge for asset/message bridging
 * - GlobalExitRootManager tracks L2 exit roots on L1
 * - networkId distinguishes L1 (0) vs zkEVM (1) messages
 * - Proof finality: ~1 block (ZK proof verified on L1)
 *
 * MESSAGE FLOW:
 *   L1 → L2: bridgeMessage() on PolygonZkEVMBridge
 *   L2 → L1: claimMessage() with GlobalExitRoot Merkle proof
 *
 * @custom:graduated Promoted from experimental to production. Formally verified via Certora.
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PolygonZkEVMBridgeAdapter is
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
    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Polygon zkEVM mainnet chain ID
    uint256 public constant POLYGON_ZKEVM_MAINNET = 1101;

    /// @notice Polygon zkEVM Cardona testnet chain ID
    uint256 public constant POLYGON_ZKEVM_TESTNET = 1442;

    /// @notice Finality blocks (ZK proof finality — instant on L1)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Network ID for L1 mainnet in Polygon bridge
    uint32 public constant NETWORK_ID_MAINNET = 0;

    /// @notice Network ID for Polygon zkEVM in Polygon bridge
    uint32 public constant NETWORK_ID_ZKEVM = 1;

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

    /// @notice Global Exit Root Merkle proof for claiming L2→L1 messages
    struct ExitProof {
        bytes32[32] smtProof; // Sparse Merkle Tree proof (32 siblings)
        uint32 index; // Leaf index in the exit tree
        bytes32 mainnetExitRoot; // L1 global exit root
        bytes32 rollupExitRoot; // L2 rollup exit root
    }

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        address target;
        uint256 timestamp;
        uint32 depositCount; // Polygon bridge deposit counter
        bytes payload;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice PolygonZkEVMBridge contract address
    address public bridge;

    /// @notice GlobalExitRootManager address
    address public globalExitRootManager;

    /// @notice Polygon zkEVM rollup contract address
    address public polygonZkEVM;

    /// @notice Network ID (0 = L1, 1 = zkEVM)
    uint32 public networkId;

    /// @notice Zaseon Hub address on Polygon zkEVM L2
    address public zaseonHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Claimed deposit indices (replay protection)
    mapping(uint32 => bool) public claimedDeposits;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce,
        uint32 depositCount
    );
    event MessageClaimed(
        bytes32 indexed messageHash,
        address indexed claimer,
        uint32 index
    );
    event BridgeConfigured(
        address bridge,
        address globalExitRootManager,
        address polygonZkEVM
    );
    event ZaseonHubL2Set(address indexed zaseonHubL2);
    event ProofRegistrySet(address indexed proofRegistry);
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Deploy a new PolygonZkEVMBridgeAdapter
    /// @param _bridge Address of the PolygonZkEVMBridge contract on L1
    /// @param _globalExitRootManager Address of the GlobalExitRootManager for exit root verification
    /// @param _polygonZkEVM Address of the Polygon zkEVM rollup contract
    /// @param _networkId Network identifier (0 for L1 mainnet, 1 for zkEVM)
    /// @param _admin Address to receive DEFAULT_ADMIN_ROLE and OPERATOR_ROLE
    constructor(
        address _bridge,
        address _globalExitRootManager,
        address _polygonZkEVM,
        uint32 _networkId,
        address _admin
    ) {
        require(_admin != address(0), "Invalid admin");
        require(_bridge != address(0), "Invalid bridge");
        require(
            _globalExitRootManager != address(0),
            "Invalid exit root manager"
        );
        require(_polygonZkEVM != address(0), "Invalid polygonZkEVM");

        bridge = _bridge;
        globalExitRootManager = _globalExitRootManager;
        polygonZkEVM = _polygonZkEVM;
        networkId = _networkId;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update the Polygon zkEVM bridge infrastructure addresses
    /// @param _bridge Address of the PolygonZkEVMBridge contract
    /// @param _globalExitRootManager Address of the GlobalExitRootManager
    /// @param _polygonZkEVM Address of the Polygon zkEVM rollup contract
    function configurePolygonBridge(
        address _bridge,
        address _globalExitRootManager,
        address _polygonZkEVM
    ) external onlyRole(OPERATOR_ROLE) {
        require(_bridge != address(0), "Invalid bridge");
        require(
            _globalExitRootManager != address(0),
            "Invalid exit root manager"
        );
        require(_polygonZkEVM != address(0), "Invalid polygonZkEVM");
        bridge = _bridge;
        globalExitRootManager = _globalExitRootManager;
        polygonZkEVM = _polygonZkEVM;
        emit BridgeConfigured(_bridge, _globalExitRootManager, _polygonZkEVM);
    }

    /// @notice Set the Zaseon Hub L2 contract address on Polygon zkEVM
    /// @param _zaseonHubL2 The address of the Zaseon Hub deployed on Polygon zkEVM L2
    function setZaseonHubL2(
        address _zaseonHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_zaseonHubL2 != address(0), "Invalid address");
        zaseonHubL2 = _zaseonHubL2;
        emit ZaseonHubL2Set(_zaseonHubL2);
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

    /// @notice Get the Polygon zkEVM mainnet chain ID
    /// @return The chain ID constant (1101)
    function chainId() external pure returns (uint256) {
        return POLYGON_ZKEVM_MAINNET;
    }

    /// @notice Get the human-readable chain name
    /// @return The chain name string ("Polygon zkEVM")
    function chainName() external pure returns (string memory) {
        return "Polygon zkEVM";
    }

    /// @notice Check whether the adapter is fully configured
    /// @return True if bridge and zaseonHubL2 are set
    function isConfigured() external view returns (bool) {
        return bridge != address(0) && zaseonHubL2 != address(0);
    }

    /// @notice Get the number of blocks required for finality on Polygon zkEVM
    /// @return The finality block count (1 — ZK proof provides instant finality)
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to Polygon zkEVM via the PolygonZkEVMBridge
     * @param target Target address on the destination network
     * @param data Message calldata
     * @param forceUpdateGlobalExitRoot Whether to force a global exit root update
     * @return messageHash Unique hash identifying this message
     * @dev Calls bridgeMessage on the PolygonZkEVMBridge contract.
     *      The bridge assigns a depositCount used for exit tree indexing.
     */
    function sendMessage(
        address target,
        bytes calldata data,
        bool forceUpdateGlobalExitRoot
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        require(target != address(0), "Invalid target");
        require(bridge != address(0), "Bridge not configured");
        require(data.length <= MAX_PROOF_SIZE, "Data too large");

        // Determine destination network: if we are on L1 (networkId 0) → send to zkEVM (1), and vice versa
        uint32 destinationNetwork = networkId == NETWORK_ID_MAINNET
            ? NETWORK_ID_ZKEVM
            : NETWORK_ID_MAINNET;

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                target,
                data,
                nonce,
                block.timestamp,
                POLYGON_ZKEVM_MAINNET
            )
        );

        // Call bridgeMessage on PolygonZkEVMBridge
        // Signature: bridgeMessage(uint32 destinationNetwork, address destinationAddress,
        //            bool forceUpdateGlobalExitRoot, bytes calldata metadata)
        bytes memory bridgeCall = abi.encodeWithSignature(
            "bridgeMessage(uint32,address,bool,bytes)",
            destinationNetwork,
            target,
            forceUpdateGlobalExitRoot,
            data
        );

        (bool success, bytes memory result) = bridge.call{value: msg.value}(
            bridgeCall
        );
        require(success, "Bridge call failed");

        // Extract depositCount from return data (if available)
        uint32 depositCount = result.length >= 32
            ? uint32(uint256(abi.decode(result, (uint256))))
            : uint32(nonce);

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            target: target,
            timestamp: block.timestamp,
            depositCount: depositCount,
            payload: data
        });

        emit MessageSent(messageHash, target, nonce, depositCount);
        return messageHash;
    }

    /**
     * @notice Claim an L2→L1 message using a GlobalExitRoot Merkle proof
     * @param messageHash The message hash to claim
     * @param proof Exit proof with sparse Merkle tree path and exit roots
     * @dev Calls claimMessage on the PolygonZkEVMBridge which verifies the
     *      SMT proof against the GlobalExitRootManager's stored roots.
     */
    function claimMessage(
        bytes32 messageHash,
        ExitProof calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        MessageRecord storage record = messages[messageHash];
        require(record.status == MessageStatus.SENT, "Invalid message state");
        require(!claimedDeposits[proof.index], "Already claimed");

        // Determine origin network (the network that sent the message)
        uint32 originNetwork = networkId == NETWORK_ID_MAINNET
            ? NETWORK_ID_ZKEVM
            : NETWORK_ID_MAINNET;

        // Call claimMessage on PolygonZkEVMBridge
        // Signature: claimMessage(bytes32[32] smtProof, uint32 index,
        //   bytes32 mainnetExitRoot, bytes32 rollupExitRoot,
        //   uint32 originNetwork, address originAddress,
        //   uint32 destinationNetwork, address destinationAddress,
        //   uint256 amount, bytes metadata)
        bytes memory claimCall = abi.encodeWithSignature(
            "claimMessage(bytes32[32],uint32,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)",
            proof.smtProof,
            proof.index,
            proof.mainnetExitRoot,
            proof.rollupExitRoot,
            originNetwork,
            address(this), // originAddress (this contract sent it)
            networkId, // destinationNetwork (us)
            record.target, // destinationAddress
            0, // amount (message only, no ETH)
            record.payload
        );

        (bool success, ) = bridge.call(claimCall);
        require(success, "Claim failed");

        claimedDeposits[proof.index] = true;
        record.status = MessageStatus.CLAIMED;

        emit MessageClaimed(messageHash, msg.sender, proof.index);
    }

    /**
     * @notice Verify a message by checking its claim status
     * @param messageHash Hash of the message to verify
     * @param proof Proof data (unused for status-based verification)
     * @return True if the message has been successfully claimed
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
     * @notice Query the latest verified batch number on the zkEVM rollup
     * @return batchNum The last verified batch number
     */
    function getLastVerifiedBatch() external view returns (uint256) {
        if (polygonZkEVM == address(0)) return 0;

        bytes memory call_ = abi.encodeWithSignature("lastVerifiedBatch()");
        (bool success, bytes memory result) = polygonZkEVM.staticcall(call_);
        if (success && result.length >= 32) {
            return abi.decode(result, (uint256));
        }
        return 0;
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Pause the adapter, blocking all bridge operations
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resume the adapter after a pause
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Emergency withdrawal of ETH from the adapter
    /// @param to Recipient address for the withdrawn ETH
    /// @param amount Amount of ETH (in wei) to withdraw
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
        require(bridge != address(0), "Bridge not configured");
        require(payload.length <= MAX_PROOF_SIZE, "Data too large");

        uint256 nonce = messageNonce++;

        uint32 destinationNetwork = networkId == NETWORK_ID_MAINNET
            ? NETWORK_ID_ZKEVM
            : NETWORK_ID_MAINNET;

        bytes memory bridgeCall = abi.encodeWithSignature(
            "bridgeMessage(uint32,address,bool,bytes)",
            destinationNetwork,
            targetAddress,
            true, // forceUpdateGlobalExitRoot
            payload
        );

        (bool success, bytes memory result) = bridge.call{value: msg.value}(
            bridgeCall
        );
        require(success, "Bridge call failed");

        uint32 depositCount = 0;
        if (result.length >= 32) {
            depositCount = uint32(abi.decode(result, (uint256)));
        }

        messageId = keccak256(
            abi.encode(
                targetAddress,
                payload,
                nonce,
                block.timestamp,
                POLYGON_ZKEVM_MAINNET
            )
        );

        messages[messageId] = MessageRecord({
            status: MessageStatus.SENT,
            target: targetAddress,
            timestamp: block.timestamp,
            depositCount: depositCount,
            payload: payload
        });

        emit MessageSent(messageId, targetAddress, nonce, depositCount);
        return messageId;
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure override returns (uint256 nativeFee) {
        return 0; // Polygon zkEVM bridge messages are free
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageRecord storage record = messages[messageId];
        return record.status == MessageStatus.CLAIMED;
    }

    /// @notice Allow receiving ETH for fee payments
    receive() external payable {}
}
