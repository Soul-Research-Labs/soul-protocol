// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title zkSyncBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for zkSync Era integration
 */
contract zkSyncBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    uint256 public constant ZKSYNC_CHAIN_ID = 324;
    uint256 public constant FINALITY_BLOCKS = 1;

    address public zkSyncDiamond;
    address public soulHubL2;
    uint256 public messageNonce;
    mapping(bytes32 => bool) public messageStatus;

    event MessageSent(
        bytes32 indexed messageHash,
        address indexed target,
        uint256 nonce
    );
    event SoulHubL2Set(address indexed soulHubL2);

    constructor(address _admin, address _zkSyncDiamond) {
        zkSyncDiamond = _zkSyncDiamond;
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
    }

    function setPilHubL2(
        address _soulHubL2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        soulHubL2 = _soulHubL2;
        emit SoulHubL2Set(_soulHubL2);
    }

    function chainId() external pure returns (uint256) {
        return ZKSYNC_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "zkSync Era";
    }

    function isConfigured() external view returns (bool) {
        return zkSyncDiamond != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
