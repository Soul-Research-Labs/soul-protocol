// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title TaikoBridgeAdapter
 * @author ZASEON
 * @notice Bridge adapter for Taiko L2 (based rollup) integration
 * @dev Enables ZASEON cross-chain interoperability with Taiko.
 *      Taiko is a "based rollup" — sequencing is done by Ethereum L1 validators,
 *      with ZK proofs for state verification.
 *
 * TAIKO INTEGRATION:
 * - Based rollup: L1 proposers, multi-tier ZK proof system
 * - Type 1 zkEVM (full Ethereum-equivalence)
 * - Uses Signal Service for cross-chain messaging
 * - L1→L2: sendSignal via SignalService (sync'd via L2 anchor tx)
 * - L2→L1: proveSignalReceived with Merkle proof against state roots
 * - Proof finality: ~15 min (SGX tier) to ~24 hours (ZK tier)
 * - Multi-tier proving: optimistic → SGX → ZK (escalation)
 *
 * SECURITY NOTES:
 * - Based sequencing means no centralized sequencer risk
 * - Multi-tier proof system provides progressive security guarantees
 * - Signal Service is the canonical cross-chain messaging primitive
 * - Merkle proofs against synced state roots for L2→L1 verification
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract TaikoBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
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

    /// @notice Taiko mainnet chain ID
    uint256 public constant TAIKO_CHAIN_ID = 167000;

    /// @notice Taiko Hekla testnet chain ID
    uint256 public constant TAIKO_HEKLA_CHAIN_ID = 167009;

    /// @notice Finality blocks (ZK tier finality — ~few hours)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Max proof data size
    uint256 public constant MAX_PROOF_SIZE = 32_768;

    /*//////////////////////////////////////////////////////////////
                              ENUMS
    //////////////////////////////////////////////////////////////*/

    enum MessageStatus {
        PENDING,
        SENT,
        RECEIVED,
        FAILED
    }

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Hop proof for cross-chain signal verification
    struct HopProof {
        uint64 chainId;
        uint64 blockId;
        bytes32 rootHash;
        bytes[] accountProof;
        bytes[] storageProof;
    }

    /// @notice Tracked message metadata
    struct MessageRecord {
        MessageStatus status;
        address target;
        uint256 timestamp;
        bytes32 signal; // Signal value stored in SignalService
    }

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Taiko Signal Service address on L1
    address public signalService;

    /// @notice Taiko Bridge contract address on L1
    address public taikoBridge;

    /// @notice Taiko L1 contract (TaikoL1) for block verification
    address public taikoL1;

    /// @notice Zaseon Hub address on Taiko L2
    address public zaseonHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message records by hash
    mapping(bytes32 => MessageRecord) public messages;

    /// @notice Received signals (replay protection)
    mapping(bytes32 => bool) public receivedSignals;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce,
        bytes32 signal
    );
    event SignalReceived(
        bytes32 indexed messageHash,
        bytes32 indexed signal,
        address indexed prover
    );
    event BridgeConfigured(
        address signalService,
        address taikoBridge,
        address taikoL1
    );
    event ZaseonHubL2Set(address indexed zaseonHubL2);
    event ProofRegistrySet(address indexed proofRegistry);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @param _signalService Taiko SignalService address on L1
    /// @param _taikoBridge Taiko Bridge contract address
    /// @param _taikoL1 TaikoL1 contract address
    /// @param _admin Default admin address
    constructor(
        address _signalService,
        address _taikoBridge,
        address _taikoL1,
        address _admin
    ) {
        require(_admin != address(0), "Invalid admin");
        require(_signalService != address(0), "Invalid signal service");
        require(_taikoBridge != address(0), "Invalid bridge");
        require(_taikoL1 != address(0), "Invalid TaikoL1");

        signalService = _signalService;
        taikoBridge = _taikoBridge;
        taikoL1 = _taikoL1;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Update Taiko bridge infrastructure addresses
    function configureTaikoBridge(
        address _signalService,
        address _taikoBridge,
        address _taikoL1
    ) external onlyRole(OPERATOR_ROLE) {
        require(_signalService != address(0), "Invalid signal service");
        require(_taikoBridge != address(0), "Invalid bridge");
        require(_taikoL1 != address(0), "Invalid TaikoL1");
        signalService = _signalService;
        taikoBridge = _taikoBridge;
        taikoL1 = _taikoL1;
        emit BridgeConfigured(_signalService, _taikoBridge, _taikoL1);
    }

    /// @notice Set Zaseon Hub L2 address on Taiko
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

    /// @notice Get the Taiko mainnet chain ID
    function chainId() external pure returns (uint256) {
        return TAIKO_CHAIN_ID;
    }

    /// @notice Get the human-readable chain name
    function chainName() external pure returns (string memory) {
        return "Taiko";
    }

    /// @notice Check whether the adapter is fully configured
    function isConfigured() external view returns (bool) {
        return signalService != address(0) && zaseonHubL2 != address(0);
    }

    /// @notice Get finality blocks (ZK proof finality)
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a signal/message to Taiko L2 via the SignalService
     * @param target Target address on Taiko L2
     * @param data Message calldata
     * @return messageHash Unique hash identifying this message
     * @dev Sends a signal via SignalService.sendSignal(). The signal is a hash
     *      of the target + data. On L2, the anchor transaction syncs L1 state,
     *      making the signal provable.
     */
    function sendMessage(
        address target,
        bytes calldata data
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        require(target != address(0), "Invalid target");
        require(signalService != address(0), "Bridge not configured");
        require(data.length <= MAX_PROOF_SIZE, "Data too large");

        uint256 nonce = messageNonce++;

        // Create the signal value as a hash of the message content
        bytes32 signal = keccak256(
            abi.encode(target, data, nonce, block.timestamp, TAIKO_CHAIN_ID)
        );

        bytes32 messageHash = keccak256(abi.encode(signal, msg.sender, nonce));

        // Call sendSignal on the SignalService
        // Signature: sendSignal(bytes32 _signal) returns (bytes32)
        bytes memory signalCall = abi.encodeWithSignature(
            "sendSignal(bytes32)",
            signal
        );

        (bool success, ) = signalService.call(signalCall);
        require(success, "Signal service call failed");

        messages[messageHash] = MessageRecord({
            status: MessageStatus.SENT,
            target: target,
            timestamp: block.timestamp,
            signal: signal
        });

        emit MessageSent(messageHash, target, nonce, signal);
        return messageHash;
    }

    /**
     * @notice Prove that an L2 signal was received on L1
     * @param messageHash The internal message hash
     * @param srcChainId Source chain ID (Taiko L2)
     * @param app The L2 application address that sent the signal
     * @param signal The signal value to verify
     * @param proof Hop proof with Merkle storage proof
     * @dev Calls proveSignalReceived on the SignalService with the storage proof
     */
    function proveSignalReceived(
        bytes32 messageHash,
        uint64 srcChainId,
        address app,
        bytes32 signal,
        HopProof[] calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        require(!receivedSignals[signal], "Already received");
        require(proof.length > 0, "Empty proof");

        // Encode the HopProof array for the SignalService call
        // Signature: proveSignalReceived(uint64 _chainId, address _app, bytes32 _signal, bytes _proof)
        bytes memory proveCall = abi.encodeWithSignature(
            "proveSignalReceived(uint64,address,bytes32,bytes)",
            srcChainId,
            app,
            signal,
            abi.encode(proof)
        );

        (bool success, ) = signalService.call(proveCall);
        require(success, "Signal proof failed");

        receivedSignals[signal] = true;

        MessageRecord storage record = messages[messageHash];
        if (record.timestamp > 0) {
            record.status = MessageStatus.RECEIVED;
        }

        emit SignalReceived(messageHash, signal, msg.sender);
    }

    /**
     * @notice Verify a message by checking its status
     * @param messageHash Hash of the message to verify
     * @param proof Proof data (unused for status check)
     * @return True if the signal has been received
     */
    function verifyMessage(
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        if (proof.length == 0) return false;
        MessageRecord storage record = messages[messageHash];
        return record.status == MessageStatus.RECEIVED;
    }

    /**
     * @notice Check if a signal has been proven as received
     * @param signal The signal value to check
     * @return True if this signal has been received and proven
     */
    function isSignalReceived(bytes32 signal) external view returns (bool) {
        return receivedSignals[signal];
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
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
