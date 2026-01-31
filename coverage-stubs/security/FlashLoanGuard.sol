// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract FlashLoanGuard is ReentrancyGuard, AccessControl, Pausable {
    error SameBlockOperation();
    error BalanceManipulationDetected();
    error PriceDeviationTooHigh();
    error VelocityLimitExceeded();
    error TVLDeltaExceeded();
    error TokenNotWhitelisted();
    error OracleNotSet();
    error StaleOraclePrice();

    struct TokenConfig {
        address priceOracle;
        uint256 maxPriceDeviation;
        bool isWhitelisted;
        uint256 lastSnapshotBlock;
        uint256 lastSnapshotBalance;
    }

    struct UserOperations {
        uint256 lastBlock;
        uint256 operationsThisBlock;
        uint256 operationsThisEpoch;
        uint256 epochStartBlock;
        uint256 valueThisBlock;
    }

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    uint256 public constant MAX_OPS_PER_BLOCK = 3;
    uint256 public constant MAX_OPS_PER_EPOCH = 50;
    uint256 public constant EPOCH_LENGTH = 100;

    mapping(address => TokenConfig) public tokenConfigs;
    mapping(address => UserOperations) public userOperations;
    mapping(address => mapping(uint256 => uint256)) public balanceSnapshots;
    mapping(address => bool) public protectedContracts;
    uint256 public lastTVLBlock;
    uint256 public lastTVL;
    uint256 public maxTVLDeltaBps;
    uint256 public maxPriceDeviationBps;

    constructor(uint256 _maxTVLDeltaBps, uint256 _maxPriceDeviationBps, address admin) {
        maxTVLDeltaBps = _maxTVLDeltaBps;
        maxPriceDeviationBps = _maxPriceDeviationBps;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function validateOperation(address, address, uint256) external returns (bool) { return true; }
    function canOperateThisBlock(address) external view returns (bool) { return true; }
    function getRemainingOperations(address) external view returns (uint256) { return MAX_OPS_PER_EPOCH; }
    function whitelistToken(address, address, uint256) external {}
    function updateTVLDeltaLimit(uint256) external {}
    function registerProtectedContract(address) external {}
    function updateTVL(uint256) external {}
    function pause() external {}
    function unpause() external {}
}
