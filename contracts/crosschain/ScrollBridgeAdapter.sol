// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ScrollBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Scroll zkEVM integration
 * @dev Enables cross-chain interoperability with Scroll L2
 *
 * SCROLL INTEGRATION:
 * - zkEVM rollup with Type 2 EVM equivalence
 * - Uses zkSNARK proofs for state verification
 * - L1 -> L2: L1ScrollMessenger
 * - L2 -> L1: L2ScrollMessenger with withdrawal proofs
 */
contract ScrollBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
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

    /// @notice Scroll mainnet chain ID
    uint256 public constant SCROLL_MAINNET_CHAIN_ID = 534352;

    /// @notice Scroll Sepolia testnet chain ID
    uint256 public constant SCROLL_SEPOLIA_CHAIN_ID = 534351;

    /// @notice Finality blocks for Scroll (ZK proof finality)
    uint256 public constant FINALITY_BLOCKS = 1;

    /// @notice Default L2 gas limit
    uint256 public constant DEFAULT_L2_GAS_LIMIT = 1000000;

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
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Scroll Messenger address
    address public scrollMessenger;

    /// @notice Scroll Gateway Router address
    address public gatewayRouter;

    /// @notice Scroll Rollup contract address
    address public rollupContract;

    /// @notice Soul Hub L2 address
    address public soulHubL2;

    /// @notice Proof Registry address
    address public proofRegistry;

    /// @notice Message nonce counter
    uint256 public messageNonce;

    /// @notice Message status tracking
    mapping(bytes32 => MessageStatus) public messageStatus;

    /*//////////////////////////////////////////////////////////////
                              EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce
    );
    event MessageRelayed(bytes32 indexed messageHash, address indexed sender);
    event BridgeConfigured(
        address scrollMessenger,
        address gatewayRouter,
        address rollupContract
    );
    event SoulHubL2Set(address indexed soulHubL2);
    event ProofRegistrySet(address indexed proofRegistry);

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _scrollMessenger,
        address _gatewayRouter,
        address _rollupContract,
        address _admin
    ) {
        scrollMessenger = _scrollMessenger;
        gatewayRouter = _gatewayRouter;
        rollupContract = _rollupContract;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure Scroll bridge addresses
     * @param _scrollMessenger Scroll Messenger address
     * @param _gatewayRouter Scroll Gateway Router address
     * @param _rollupContract Scroll Rollup contract address
     */
    function configureScrollBridge(
        address _scrollMessenger,
        address _gatewayRouter,
        address _rollupContract
    ) external onlyRole(OPERATOR_ROLE) {
        scrollMessenger = _scrollMessenger;
        gatewayRouter = _gatewayRouter;
        rollupContract = _rollupContract;
        emit BridgeConfigured(
            _scrollMessenger,
            _gatewayRouter,
            _rollupContract
        );
    }

    /**
     * @notice Set Soul Hub L2 address
     * @param _soulHubL2 Soul Hub L2 address
     */
    function setPilHubL2(address _soulHubL2) external onlyRole(DEFAULT_ADMIN_ROLE) {
        soulHubL2 = _soulHubL2;
        emit SoulHubL2Set(_soulHubL2);
    }

    /**
     * @notice Set Proof Registry address
     * @param _proofRegistry Proof Registry address
     */
    function setProofRegistry(address _proofRegistry) external onlyRole(DEFAULT_ADMIN_ROLE) {
        proofRegistry = _proofRegistry;
        emit ProofRegistrySet(_proofRegistry);
    }

    /*//////////////////////////////////////////////////////////////
                        BRIDGE INTERFACE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the chain ID this adapter supports
     */
    function chainId() external pure returns (uint256) {
        return SCROLL_MAINNET_CHAIN_ID;
    }

    /**
     * @notice Get the chain name
     */
    function chainName() external pure returns (string memory) {
        return "Scroll";
    }

    /**
     * @notice Check if the adapter is properly configured
     */
    function isConfigured() external view returns (bool) {
        return scrollMessenger != address(0) && gatewayRouter != address(0);
    }

    /**
     * @notice Get the finality blocks for this chain
     */
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /*//////////////////////////////////////////////////////////////
                        MESSAGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to Scroll L2
     * @param target Target address on L2
     * @param data Message data
     */
    function sendMessage(
        address target,
        bytes calldata data,
        uint256 /* gasLimit */
    )
        external
        payable
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32)
    {
        require(target != address(0), "Invalid target");
        require(scrollMessenger != address(0), "Bridge not configured");

        uint256 nonce = messageNonce++;
        bytes32 messageHash = keccak256(
            abi.encode(target, data, nonce, block.timestamp)
        );

        messageStatus[messageHash] = MessageStatus.SENT;
        emit MessageSent(messageHash, target, nonce);

        // TODO: Integrate with actual ScrollMessenger
        return messageHash;
    }

    /**
     * @notice Verify a message from Scroll
     * @param messageHash Hash of the message
     * @param proof Proof data from Scroll (zkSNARK proof)
     */
    function verifyMessage(
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        // TODO: Implement Scroll zkSNARK proof verification
        return
            proof.length > 0 &&
            messageStatus[messageHash] != MessageStatus.PENDING;
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
}
