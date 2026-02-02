// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title LineaBridgeAdapter
 * @author Soul Protocol
 * @notice Bridge adapter for Linea zkEVM integration
 */
contract LineaBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant BRIDGE_OPERATOR_ROLE =
        keccak256("BRIDGE_OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    uint256 public constant LINEA_MAINNET_CHAIN_ID = 59144;
    uint256 public constant LINEA_TESTNET_CHAIN_ID = 59140;
    uint256 public constant FINALITY_BLOCKS = 1;

    address public messageService;
    address public tokenBridge;
    address public rollup;
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
        address _messageService,
        address _tokenBridge,
        address _rollup,
        address _admin
    ) {
        messageService = _messageService;
        tokenBridge = _tokenBridge;
        rollup = _rollup;
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
        return LINEA_MAINNET_CHAIN_ID;
    }

    function chainName() external pure returns (string memory) {
        return "Linea";
    }

    function isConfigured() external view returns (bool) {
        return messageService != address(0);
    }

    function getFinalityBlocks() external pure returns (uint256) {
        return FINALITY_BLOCKS;
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
