// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title PolygonZkEVMBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Polygon zkEVM integration
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

    constructor(
        address _bridge,
        address _globalExitRootManager,
        address _polygonZkEVM,
        uint32 _networkId,
        address _admin
    ) {
        bridge = _bridge;
        globalExitRootManager = _globalExitRootManager;
        polygonZkEVM = _polygonZkEVM;
        networkId = _networkId;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
    }

    /// @notice Set the Soul Hub L2 contract address
    /// @param _soulHubL2 The address of the Soul Hub on Polygon zkEVM
    function setSoulHubL2(
        address _soulHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        soulHubL2 = _soulHubL2;
        emit SoulHubL2Set(_soulHubL2);
    }

    /// @notice Get the Polygon zkEVM mainnet chain ID
    /// @return The chain ID (1101)
    function chainId() external pure returns (uint256) {
        return POLYGON_ZKEVM_MAINNET;
    }

    /// @notice Get the human-readable chain name
    /// @return The chain name string
    function chainName() external pure returns (string memory) {
        return "Polygon zkEVM";
    }

    /// @notice Check whether the adapter has its bridge address configured
    /// @return True if the bridge address is set (non-zero)
    function isConfigured() external view returns (bool) {
        return bridge != address(0);
    }

    /// @notice Get the number of blocks required for finality
    /// @return The finality block count
    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    /// @notice Pause the adapter (emergency use)
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Resume the adapter after a pause
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
