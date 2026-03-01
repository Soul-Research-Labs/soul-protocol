// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./IBridgeAdapter.sol";

/**
 * @title ModeBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Mode Network L2 integration
 * @dev Enables ZASEON cross-chain interoperability with Mode Network.
 *      Mode is an OP Stack L2 focused on DeFi and SFS (Sequencer Fee Sharing).
 *
 * MODE INTEGRATION:
 * - Optimistic rollup based on OP Stack (Bedrock)
 * - Standard OP Stack CrossDomainMessenger architecture
 * - Sequencer Fee Sharing (SFS): contracts earn a share of sequencer revenue
 * - L1→L2: sendMessage via L1CrossDomainMessenger
 * - L2→L1: proveWithdrawal + finalizeWithdrawal via OptimismPortal
 * - Proof finality: ~7 days (optimistic challenge window)
 *
 * MODE-SPECIFIC FEATURES:
 * - SFS Register contract lets contracts register for fee sharing
 * - Standard OP Stack withdrawal flow (2-step: prove + finalize)
 * - Compatible with all OP Stack tooling
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract ModeBridgeAdapter is
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

    /// @notice Mode mainnet chain ID
    uint256 public constant MODE_CHAIN_ID = 34443;

    /// @notice Mode Sepolia testnet chain ID
    uint256 public constant MODE_SEPOLIA_CHAIN_ID = 919;

    /// @notice Finality blocks (~7 day optimistic challenge window)
    uint256 public constant FINALITY_BLOCKS = 50400;

    /// @notice Default L2 gas limit for cross-domain messages
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 1_000_000;

    /// @notice Max message data size
    uint256 public constant MAX_MESSAGE_SIZE = 32_768;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        PROVED,
        FINALIZED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        address target;
        uint256 timestamp;
        uint256 gasLimit;
        bytes32 withdrawalHash;
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice L1 CrossDomainMessenger address (Mode/OP Stack)
    address public crossDomainMessenger;

    /// @notice OptimismPortal address on L1 (Mode variant)
    address public modePortal;

    /// @notice L2OutputOracle address for Mode
    address public outputOracle;

    /// @notice Zaseon Hub address on Mode L2
    address public zaseonHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Finalized withdrawal hashes (replay protection)
    mapping(bytes32 => bool) public finalizedWithdrawals;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce,
        uint256 gasLimit
    );
    event WithdrawalProved(
        bytes32 indexed messageHash,
        bytes32 indexed withdrawalHash
    );
    event WithdrawalFinalized(bytes32 indexed messageHash);
    event BridgeConfigured(
        address crossDomainMessenger,
        address modePortal,
        address outputOracle
    );
    event ZaseonHubL2Set(address indexed zaseonHubL2);
    event ProofRegistrySet(address indexed proofRegistry);
    event EmergencyWithdrawal(address indexed to, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _crossDomainMessenger L1CrossDomainMessenger for Mode
    /// @param _modePortal OptimismPortal address for Mode
    /// @param _outputOracle L2OutputOracle for Mode
    /// @param _admin Default admin address
    constructor(
        address _crossDomainMessenger,
        address _modePortal,
        address _outputOracle,
        address _admin
    ) {
        require(_admin != address(0), "Invalid admin");
        require(
            _crossDomainMessenger != address(0),
            "Invalid cross domain messenger"
        );
        require(_modePortal != address(0), "Invalid portal");
        require(_outputOracle != address(0), "Invalid output oracle");

        crossDomainMessenger = _crossDomainMessenger;
        modePortal = _modePortal;
        outputOracle = _outputOracle;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update Mode bridge infrastructure addresses
    function configureModeBridge(
        address _crossDomainMessenger,
        address _modePortal,
        address _outputOracle
    ) external onlyRole(OPERATOR_ROLE) {
        require(
            _crossDomainMessenger != address(0),
            "Invalid cross domain messenger"
        );
        require(_modePortal != address(0), "Invalid portal");
        require(_outputOracle != address(0), "Invalid output oracle");
        crossDomainMessenger = _crossDomainMessenger;
        modePortal = _modePortal;
        outputOracle = _outputOracle;
        emit BridgeConfigured(
            _crossDomainMessenger,
            _modePortal,
            _outputOracle
        );
    }

    /// @notice Set the Zaseon Hub L2 contract address on Mode
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

    /// @notice Get the Mode mainnet chain ID
    function chainId() external pure returns (uint256) {
        return MODE_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Mode";
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
     * @notice Send a message to Mode L2 via L1CrossDomainMessenger
     * @param target Target address on Mode L2
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
        require(data.length <= MAX_MESSAGE_SIZE, "Data too large");

        uint256 l2Gas = gasLimit > 0 ? gasLimit : DEFAULT_L2_GAS_LIMIT;
        uint256 nonce = messageNonce++;

        bytes32 messageHash = keccak256(
            abi.encode(target, data, nonce, block.timestamp, MODE_CHAIN_ID)
        );

        // Call sendMessage on L1CrossDomainMessenger
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
            gasLimit: l2Gas,
            withdrawalHash: bytes32(0)
        });

        emit MessageSent(messageHash, target, nonce, l2Gas);
        return messageHash;
    }

    /**
     * @notice Prove an L2→L1 withdrawal on the OptimismPortal
     * @param messageHash Internal message hash
     * @param withdrawalData ABI-encoded withdrawal transaction data
     * @param outputRootProof ABI-encoded output root proof
     * @param withdrawalProof ABI-encoded storage proof
     * @dev Step 1 of the OP Stack 2-step withdrawal process
     */
    function proveWithdrawal(
        bytes32 messageHash,
        bytes calldata withdrawalData,
        bytes calldata outputRootProof,
        bytes calldata withdrawalProof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        MessageRecord storage record = messages[messageHash];
        require(record.status == MessageStatus.SENT, "Invalid message state");

        bytes memory proveCall = abi.encodeWithSignature(
            "proveWithdrawalTransaction(bytes,uint256,bytes,bytes32[])",
            withdrawalData,
            uint256(0), // l2OutputIndex resolved by portal
            outputRootProof,
            withdrawalProof
        );

        (bool success, ) = modePortal.call(proveCall);
        require(success, "Prove withdrawal failed");

        bytes32 withdrawalHash = keccak256(withdrawalData);
        record.status = MessageStatus.PROVED;
        record.withdrawalHash = withdrawalHash;

        emit WithdrawalProved(messageHash, withdrawalHash);
    }

    /**
     * @notice Finalize a proven withdrawal after the 7-day challenge period
     * @param messageHash Internal message hash
     * @param withdrawalData ABI-encoded withdrawal transaction data
     * @dev Step 2 of the OP Stack 2-step withdrawal process
     */
    function finalizeWithdrawal(
        bytes32 messageHash,
        bytes calldata withdrawalData
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        MessageRecord storage record = messages[messageHash];
        require(record.status == MessageStatus.PROVED, "Not proved");
        require(
            !finalizedWithdrawals[record.withdrawalHash],
            "Already finalized"
        );

        bytes memory finalizeCall = abi.encodeWithSignature(
            "finalizeWithdrawalTransaction(bytes)",
            withdrawalData
        );

        (bool success, ) = modePortal.call(finalizeCall);
        require(success, "Finalize withdrawal failed");

        finalizedWithdrawals[record.withdrawalHash] = true;
        record.status = MessageStatus.FINALIZED;

        emit WithdrawalFinalized(messageHash);
    }

    /**
     * @notice Verify a message by checking its status
     * @param messageHash Hash of the message
     * @param proof Proof data (unused for status check)
     * @return True if the message withdrawal has been finalized
     */
    function verifyMessage(
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        if (proof.length == 0) return false;
        MessageRecord storage record = messages[messageHash];
        return record.status == MessageStatus.FINALIZED;
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
        require(payload.length <= MAX_MESSAGE_SIZE, "Data too large");

        uint256 nonce = messageNonce++;
        messageId = keccak256(
            abi.encode(
                targetAddress,
                payload,
                nonce,
                block.timestamp,
                MODE_CHAIN_ID
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
            gasLimit: DEFAULT_L2_GAS_LIMIT,
            withdrawalHash: bytes32(0)
        });

        emit MessageSent(messageId, targetAddress, nonce, DEFAULT_L2_GAS_LIMIT);
        return messageId;
    }

    /// @inheritdoc IBridgeAdapter
    function estimateFee(
        address /*targetAddress*/,
        bytes calldata /*payload*/
    ) external pure override returns (uint256 nativeFee) {
        return 0;
    }

    /// @inheritdoc IBridgeAdapter
    function isMessageVerified(
        bytes32 messageId
    ) external view override returns (bool verified) {
        MessageRecord storage record = messages[messageId];
        return record.status == MessageStatus.FINALIZED;
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
