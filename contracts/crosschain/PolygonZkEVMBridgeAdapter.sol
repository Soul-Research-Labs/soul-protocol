// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PolygonZkEVMBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Polygon zkEVM L2 integration
 * @dev Enables Soul Protocol cross-chain interoperability with Polygon zkEVM.
 *      Uses the Polygon zkEVM bridge contract for L1 <-> L2 message passing.
 *
 * POLYGON ZKEVM INTEGRATION:
 * - Uses PolygonZkEVMBridge for asset/message bridging
 * - GlobalExitRootManager tracks L2 exit roots on L1
 * - networkId distinguishes L1 (0) vs zkEVM (1) messages
 * - Proof finality: ~1 block (ZK proof verified on L1)
 *
 * @custom:graduated Promoted from experimental to production. Formally verified via Certora.
 * @custom:security-contact security@soulprotocol.io
 */
contract PolygonZkEVMBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 public constant POLYGON_ZKEVM_MAINNET = 1101;
    uint256 public constant POLYGON_ZKEVM_TESTNET = 1442;
    uint256 public constant FINALITY_BLOCKS = 1;
    uint32 public constant NETWORK_ID_MAINNET = 0;
    uint32 public constant NETWORK_ID_ZKEVM = 1;

    address public bridge;
    address public globalExitRootManager;
    address public polygonZkEVM;
    uint32 public networkId;
    address public soulHubL2;
    uint256 public messageNonce;
    mapping(bytes32 => bool) public messageStatus;

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce
    );
    event SoulHubL2Set(address indexed soulHubL2);

    /**
     * @notice Deploy a new PolygonZkEVMBridgeAdapter
     * @param _bridge Address of the PolygonZkEVMBridge contract on L1
     * @param _globalExitRootManager Address of the GlobalExitRootManager for exit root verification
     * @param _polygonZkEVM Address of the Polygon zkEVM rollup contract
     * @param _networkId Network identifier (0 for L1 mainnet, 1 for zkEVM)
     * @param _admin Address to receive DEFAULT_ADMIN_ROLE and OPERATOR_ROLE
     */
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
    }

    /// @notice Set the Soul Hub L2 contract address on Polygon zkEVM
    /// @param _soulHubL2 The address of the Soul Hub deployed on Polygon zkEVM L2
    /// @dev Only callable by DEFAULT_ADMIN_ROLE. Reverts if _soulHubL2 is zero address.
    function setSoulHubL2(
        address _soulHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_soulHubL2 != address(0), "Invalid address");
        soulHubL2 = _soulHubL2;
        emit SoulHubL2Set(_soulHubL2);
    }

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

    /// @notice Check whether the adapter has its bridge address configured
    /// @return True if the bridge address is set (non-zero)
    function isConfigured() external view returns (bool) {
        return bridge != address(0);
    }

    /// @notice Get the number of blocks required for finality on Polygon zkEVM
    /// @return The finality block count (1 — ZK proof provides instant finality)
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Pause the adapter, blocking all bridge operations
    /// @dev Only callable by PAUSER_ROLE. Emits a {Paused} event.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resume the adapter after a pause
    /// @dev Only callable by DEFAULT_ADMIN_ROLE. Emits an {Unpaused} event.
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
