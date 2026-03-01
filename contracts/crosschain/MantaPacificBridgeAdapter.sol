// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./IBridgeAdapter.sol";

/**
 * @title MantaPacificBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Manta Pacific L2 integration
 * @dev Enables ZASEON cross-chain interoperability with Manta Pacific.
 *      Manta Pacific is a modular L2 focused on ZK applications,
 *      with Celestia DA and a Polygon CDK-based ZK proving system.
 *
 * MANTA PACIFIC INTEGRATION:
 * - ZK-rollup (migrated from OP Stack to Polygon CDK / zkEVM)
 * - Uses PolygonZkEVMBridge for messaging (shared with Polygon CDK ecosystem)
 * - Data availability via Celestia (modular DA)
 * - Universal Circuits for cheap ZK proof verification
 * - Proof finality: ~1 block (ZK proof verified on L1)
 *
 * MESSAGE FLOW:
 *   L1 → L2: bridgeMessage() on PolygonZkEVMBridge (CDK variant)
 *   L2 → L1: claimMessage() with GlobalExitRoot Merkle proof (CDK variant)
 *
 * MANTA-SPECIFIC FEATURES:
 * - Celestia DA reduces data posting costs significantly
 * - Universal Circuits: pre-deployed circuits for common ZK operations
 * - Native privacy primitives (aligned with ZASEON's privacy goals)
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract MantaPacificBridgeAdapter is
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

    /// @notice Manta Pacific mainnet chain ID
    uint256 public constant MANTA_PACIFIC_CHAIN_ID = 169;

    /// @notice Manta Pacific Sepolia testnet chain ID
    uint256 public constant MANTA_SEPOLIA_CHAIN_ID = 3441006;

    /// @notice Finality blocks (ZK proof finality)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Network ID for L1 in CDK bridge
    uint32 public constant NETWORK_ID_MAINNET = 0;

    /// @notice Network ID for Manta Pacific in CDK bridge
    uint32 public constant NETWORK_ID_MANTA = 1;

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

    /// @notice CDK Exit proof for claiming L2→L1 messages
    struct CDKExitProof {
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
        uint32 depositCount;
        bytes payload;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice CDK Bridge contract address (PolygonZkEVMBridge variant)
    address public cdkBridge;

    /// @notice Global Exit Root Manager for CDK
    address public globalExitRootManager;

    /// @notice Manta Pacific rollup contract
    address public mantaRollup;

    /// @notice Zaseon Hub address on Manta Pacific L2
    address public zaseonHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Network ID (0 = L1, 1 = Manta Pacific)
    uint32 public networkId;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Claimed deposit indices (replay protection)
    mapping(uint32 => bool) public claimedDeposits;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when a message is sent to Manta Pacific L2
    /// @param messageHash The unique hash identifying this message
    /// @param target The target contract address on Manta Pacific L2
    /// @param nonce The message nonce
    /// @param depositCount The CDK bridge deposit count
    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce,
        uint32 depositCount
    );
    /// @notice Emitted when an L2→L1 message is claimed via CDK bridge
    /// @param messageHash The unique hash of the claimed message
    /// @param claimer The address that claimed the message
    /// @param index The deposit index in the exit tree
    event MessageClaimed(
        bytes32 indexed messageHash,
        address indexed claimer,
        uint32 index
    );
    /// @notice Emitted when the bridge configuration is updated
    /// @param cdkBridge The new CDK Bridge contract address
    /// @param globalExitRootManager The new Global Exit Root Manager address
    /// @param mantaRollup The new Manta Pacific rollup contract address
    event BridgeConfigured(
        address cdkBridge,
        address globalExitRootManager,
        address mantaRollup
    );
    /// @notice Emitted when the Zaseon Hub L2 address is set
    /// @param zaseonHubL2 The new Zaseon Hub address on Manta Pacific L2
    event ZaseonHubL2Set(address indexed zaseonHubL2);
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

    /// @param _cdkBridge CDK Bridge contract address
    /// @param _globalExitRootManager Global Exit Root Manager for CDK
    /// @param _mantaRollup Manta Pacific rollup contract
    /// @param _networkId Network ID (0 = L1, 1 = Manta)
    /// @param _admin Default admin address
    constructor(
        address _cdkBridge,
        address _globalExitRootManager,
        address _mantaRollup,
        uint32 _networkId,
        address _admin
    ) {
        require(_admin != address(0), "Invalid admin");
        require(_cdkBridge != address(0), "Invalid CDK bridge");
        require(
            _globalExitRootManager != address(0),
            "Invalid exit root manager"
        );
        require(_mantaRollup != address(0), "Invalid rollup");

        cdkBridge = _cdkBridge;
        globalExitRootManager = _globalExitRootManager;
        mantaRollup = _mantaRollup;
        networkId = _networkId;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update Manta Pacific bridge infrastructure addresses
    /// @param _cdkBridge CDK Bridge contract address
    /// @param _globalExitRootManager Global Exit Root Manager address
    /// @param _mantaRollup Manta Pacific rollup contract address
    function configureMantaBridge(
        address _cdkBridge,
        address _globalExitRootManager,
        address _mantaRollup
    ) external onlyRole(OPERATOR_ROLE) {
        require(_cdkBridge != address(0), "Invalid CDK bridge");
        require(
            _globalExitRootManager != address(0),
            "Invalid exit root manager"
        );
        require(_mantaRollup != address(0), "Invalid rollup");
        cdkBridge = _cdkBridge;
        globalExitRootManager = _globalExitRootManager;
        mantaRollup = _mantaRollup;
        emit BridgeConfigured(_cdkBridge, _globalExitRootManager, _mantaRollup);
    }

    /// @notice Set Zaseon Hub L2 address on Manta Pacific
    /// @param _zaseonHubL2 Address of the Zaseon Hub on Manta Pacific L2
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

    /// @notice Get the Manta Pacific mainnet chain ID
    function chainId() external pure returns (uint256) {
        return MANTA_PACIFIC_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Manta Pacific";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return cdkBridge != address(0) && zaseonHubL2 != address(0);
    }

    /// @notice Get finality blocks (ZK proof finality)
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to Manta Pacific L2 via the CDK Bridge
     * @param target Target address on Manta Pacific L2
     * @param data Message calldata
     * @param forceUpdateGlobalExitRoot Whether to force a global exit root update
     * @return messageHash Unique hash identifying this message
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
        require(cdkBridge != address(0), "Bridge not configured");
        require(data.length <= MAX_PROOF_SIZE, "Data too large");

        uint32 destinationNetwork = networkId == NETWORK_ID_MAINNET
            ? NETWORK_ID_MANTA
            : NETWORK_ID_MAINNET;

        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(
                target,
                data,
                nonce,
                block.timestamp,
                MANTA_PACIFIC_CHAIN_ID
            )
        );

        // Call bridgeMessage on CDK Bridge (same interface as PolygonZkEVMBridge)
        bytes memory bridgeCall = abi.encodeWithSignature(
            "bridgeMessage(uint32,address,bool,bytes)",
            destinationNetwork,
            target,
            forceUpdateGlobalExitRoot,
            data
        );

        (bool success, bytes memory result) = cdkBridge.call{value: msg.value}(
            bridgeCall
        );
        require(success, "CDK bridge call failed");

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
     * @notice Claim an L2→L1 message using a CDK Exit Root Merkle proof
     * @param messageHash The message hash to claim
     * @param proof CDK Exit proof with SMT path and exit roots
     */
    function claimMessage(
        bytes32 messageHash,
        CDKExitProof calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        MessageRecord storage record = messages[messageHash];
        require(record.status == MessageStatus.SENT, "Invalid message state");
        require(!claimedDeposits[proof.index], "Already claimed");

        uint32 originNetwork = networkId == NETWORK_ID_MAINNET
            ? NETWORK_ID_MANTA
            : NETWORK_ID_MAINNET;

        // Call claimMessage on CDK Bridge
        bytes memory claimCall = abi.encodeWithSignature(
            "claimMessage(bytes32[32],uint32,bytes32,bytes32,uint32,address,uint32,address,uint256,bytes)",
            proof.smtProof,
            proof.index,
            proof.mainnetExitRoot,
            proof.rollupExitRoot,
            originNetwork,
            address(this),
            networkId,
            record.target,
            0, // message only, no ETH
            record.payload
        );

        (bool success, ) = cdkBridge.call(claimCall);
        require(success, "Claim failed");

        claimedDeposits[proof.index] = true;
        record.status = MessageStatus.CLAIMED;

        emit MessageClaimed(messageHash, msg.sender, proof.index);
    }

    /**
     * @notice Verify a message by checking its claim status
     * @param messageHash Hash of the message to verify
     * @param proof Proof data (unused for status-based verification)
     * @return True if the message has been claimed
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
     * @notice Query the latest verified batch on Manta Pacific rollup
     * @return batchNum The last verified batch number
     */
    function getLastVerifiedBatch() external view returns (uint256) {
        if (mantaRollup == address(0)) return 0;

        bytes memory call_ = abi.encodeWithSignature("lastVerifiedBatch()");
        (bool success, bytes memory result) = mantaRollup.staticcall(call_);
        if (success && result.length >= 32) {
            return abi.decode(result, (uint256));
        }
        return 0;
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
        require(cdkBridge != address(0), "Bridge not configured");
        require(payload.length <= MAX_PROOF_SIZE, "Data too large");

        uint256 nonce = messageNonce++;

        uint32 destinationNetwork = networkId == NETWORK_ID_MAINNET
            ? NETWORK_ID_MANTA
            : NETWORK_ID_MAINNET;

        bytes memory bridgeCall = abi.encodeWithSignature(
            "bridgeMessage(uint32,address,bool,bytes)",
            destinationNetwork,
            targetAddress,
            true, // forceUpdateGlobalExitRoot
            payload
        );

        (bool success, bytes memory result) = cdkBridge.call{value: msg.value}(
            bridgeCall
        );
        require(success, "CDK bridge call failed");

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
                MANTA_PACIFIC_CHAIN_ID
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
        return 0; // CDK bridge messages are free
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageRecord storage record = messages[messageId];
        return record.status == MessageStatus.CLAIMED;
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
