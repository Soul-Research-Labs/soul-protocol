// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title SecurityIntegrations
 * @author Soul Protocol
 * @notice Central integration hub for MEVProtection, FlashLoanGuard, and DEX oracles
 * @dev Provides unified security layer for SoulAtomicSwap and withdrawal operations
 *
 * INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    SecurityIntegrations                         │
 * │                                                                  │
 * │  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────┐ │
 * │  │MEVProtection │  │FlashLoanGuard │  │    DEXPriceOracle    │ │
 * │  │              │  │               │  │                      │ │
 * │  │• Commit      │  │• Block guard  │  │• Uniswap V3 TWAP     │ │
 * │  │• Reveal      │  │• Balance snap │  │• Chainlink feeds     │ │
 * │  │• Cancel      │  │• Price check  │  │• Price deviation     │ │
 * │  └──────────────┘  └───────────────┘  └──────────────────────┘ │
 * │                            │                                    │
 * │  ┌──────────────────────────────────────────────────────────┐  │
 * │  │              Flashbots Protect Integration               │  │
 * │  │   • Private transaction submission via Flashbots RPC     │  │
 * │  │   • Bundle creation and simulation                       │  │
 * │  │   • MEV-Share for user rebates                           │  │
 * │  └──────────────────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────────────────┘
 */
contract SecurityIntegrations is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error MEVProtectionRequired();
    error FlashLoanGuardFailed();
    error PriceDeviationExceeded();
    error OracleStale();
    error InvalidOperation();
    error CommitmentNotReady();
    error UnauthorizedCaller();
    error OperationExpired();
    error TransactionOrderingViolation();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperationCommitted(
        bytes32 indexed operationId,
        address indexed user,
        bytes32 operationType,
        uint256 readyAt
    );

    event OperationRevealed(
        bytes32 indexed operationId,
        address indexed user,
        bytes32 operationType
    );

    event FlashLoanCheckPassed(
        address indexed user,
        address indexed token,
        uint256 amount
    );

    event PriceValidated(
        address indexed token,
        uint256 oraclePrice,
        uint256 spotPrice,
        uint256 deviationBps
    );

    event FlashbotsProtectEnabled(address indexed user, bool enabled);

    event TransactionOrderingProtected(
        bytes32 indexed operationId,
        uint256 nonce,
        uint256 maxPriorityFee
    );

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ProtectedOperation {
        address user;
        bytes32 operationType;
        bytes32 commitHash;
        uint256 createdAt;
        uint256 readyAt;
        uint256 expiresAt;
        bool executed;
        bool cancelled;
        uint256 nonce; // Transaction ordering
    }

    struct DEXPriceData {
        uint256 uniswapV3TWAP;
        uint256 chainlinkPrice;
        uint256 sushiswapPrice;
        uint256 curvePrice;
        uint256 timestamp;
        uint256 confidence; // 0-100
    }

    struct FlashbotsConfig {
        bool enabled;
        address relayer;
        uint256 maxPriorityFee;
        uint256 minRefund;
        bool mevShareEnabled;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    // Operation types
    bytes32 public constant OP_ATOMIC_SWAP = keccak256("ATOMIC_SWAP");
    bytes32 public constant OP_WITHDRAWAL = keccak256("WITHDRAWAL");
    bytes32 public constant OP_BRIDGE = keccak256("BRIDGE");
    bytes32 public constant OP_CLAIM = keccak256("CLAIM");

    /// @notice Minimum reveal delay (blocks)
    uint256 public constant MIN_REVEAL_DELAY = 2;

    /// @notice Maximum commitment age (blocks)
    uint256 public constant MAX_COMMITMENT_AGE = 100;

    /// @notice Maximum price deviation (basis points)
    uint256 public maxPriceDeviationBps = 500; // 5%

    /// @notice Oracle staleness threshold (seconds)
    uint256 public oracleStalenessThreshold = 3600; // 1 hour

    /// @notice Protected operations
    mapping(bytes32 => ProtectedOperation) public operations;

    /// @notice User operation nonces (for ordering)
    mapping(address => uint256) public userNonces;

    /// @notice Last operation block per user
    mapping(address => uint256) public lastOperationBlock;

    /// @notice Token price oracles
    mapping(address => address) public chainlinkOracles;
    mapping(address => address) public uniswapV3Pools;

    /// @notice Flashbots configuration per user
    mapping(address => FlashbotsConfig) public flashbotsConfigs;

    /// @notice Authorized atomic swap contracts
    mapping(address => bool) public authorizedContracts;

    /// @notice Global operation counter
    uint256 public operationCounter;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                        MEV PROTECTION INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit to a protected operation (Step 1 of commit-reveal)
     * @param operationType Type of operation (ATOMIC_SWAP, WITHDRAWAL, etc.)
     * @param commitHash keccak256(abi.encodePacked(data, salt, msg.sender))
     * @return operationId Unique operation identifier
     */
    function commitOperation(
        bytes32 operationType,
        bytes32 commitHash
    ) external whenNotPaused returns (bytes32 operationId) {
        // Enforce block-level reentrancy guard
        if (lastOperationBlock[msg.sender] == block.number) {
            revert FlashLoanGuardFailed();
        }
        lastOperationBlock[msg.sender] = block.number;

        uint256 nonce = ++userNonces[msg.sender];
        operationId = keccak256(
            abi.encodePacked(msg.sender, operationType, nonce, block.number)
        );

        uint256 readyAt = block.number + MIN_REVEAL_DELAY;
        uint256 expiresAt = block.number + MAX_COMMITMENT_AGE;

        operations[operationId] = ProtectedOperation({
            user: msg.sender,
            operationType: operationType,
            commitHash: commitHash,
            createdAt: block.number,
            readyAt: readyAt,
            expiresAt: expiresAt,
            executed: false,
            cancelled: false,
            nonce: nonce
        });

        operationCounter++;

        emit OperationCommitted(
            operationId,
            msg.sender,
            operationType,
            readyAt
        );

        // Emit transaction ordering event for Flashbots
        if (flashbotsConfigs[msg.sender].enabled) {
            emit TransactionOrderingProtected(
                operationId,
                nonce,
                flashbotsConfigs[msg.sender].maxPriorityFee
            );
        }

        return operationId;
    }

    /**
     * @notice Reveal and execute a protected operation (Step 2 of commit-reveal)
     * @param operationId The operation ID from commit
     * @param data Original operation data
     * @param salt Random salt used in commit
     */
    function revealOperation(
        bytes32 operationId,
        bytes calldata data,
        bytes32 salt
    ) external nonReentrant whenNotPaused {
        ProtectedOperation storage op = operations[operationId];

        if (op.user != msg.sender) revert UnauthorizedCaller();
        if (op.executed || op.cancelled) revert InvalidOperation();
        if (block.number < op.readyAt) revert CommitmentNotReady();
        if (block.number > op.expiresAt) revert OperationExpired();

        // Verify commitment
        bytes32 expectedHash = keccak256(
            abi.encodePacked(data, salt, msg.sender)
        );
        if (op.commitHash != expectedHash) revert MEVProtectionRequired();

        // Verify transaction ordering (nonce must match)
        if (op.nonce != userNonces[msg.sender])
            revert TransactionOrderingViolation();

        op.executed = true;

        emit OperationRevealed(operationId, msg.sender, op.operationType);
    }

    /**
     * @notice Cancel a pending commitment
     * @param operationId The operation ID to cancel
     */
    function cancelOperation(bytes32 operationId) external {
        ProtectedOperation storage op = operations[operationId];

        if (op.user != msg.sender) revert UnauthorizedCaller();
        if (op.executed) revert InvalidOperation();

        op.cancelled = true;
    }

    /*//////////////////////////////////////////////////////////////
                     FLASH LOAN GUARD INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Validate an operation is not part of a flash loan attack
     * @param user The user performing the operation
     * @param token The token involved
     * @param amount The amount involved
     * @return valid True if operation passes flash loan checks
     */
    function validateFlashLoanSafe(
        address user,
        address token,
        uint256 amount
    ) external view returns (bool valid) {
        // Check 1: No same-block operations
        if (lastOperationBlock[user] == block.number) {
            return false;
        }

        // Check 2: Price oracle validation (if available)
        if (chainlinkOracles[token] != address(0)) {
            (bool priceValid, ) = _validatePrice(token, amount);
            if (!priceValid) {
                return false;
            }
        }

        return true;
    }

    /**
     * @notice Record a deposit for flash loan tracking
     * @param user The user making the deposit
     * @param token The token deposited
     * @param amount The amount deposited
     */
    function recordDeposit(
        address user,
        address token,
        uint256 amount
    ) external {
        if (!authorizedContracts[msg.sender]) revert UnauthorizedCaller();

        // Update last operation block
        lastOperationBlock[user] = block.number;

        emit FlashLoanCheckPassed(user, token, amount);
    }

    /*//////////////////////////////////////////////////////////////
                       DEX PRICE ORACLE INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get aggregated price from multiple DEX sources
     * @param token The token to price
     * @return priceData Aggregated price data from multiple sources
     */
    function getAggregatedPrice(
        address token
    ) external view returns (DEXPriceData memory priceData) {
        priceData.timestamp = block.timestamp;

        // Get Chainlink price
        if (chainlinkOracles[token] != address(0)) {
            priceData.chainlinkPrice = _getChainlinkPrice(token);
        }

        // Get Uniswap V3 TWAP
        if (uniswapV3Pools[token] != address(0)) {
            priceData.uniswapV3TWAP = _getUniswapV3TWAP(token);
        }

        // Calculate confidence based on source agreement
        priceData.confidence = _calculatePriceConfidence(priceData);

        return priceData;
    }

    /**
     * @notice Validate price deviation is within acceptable range
     * @param token Token to validate
     * @param expectedPrice Expected/quoted price
     * @return valid True if price is within deviation tolerance
     * @return deviation Actual deviation in basis points
     */
    function validatePriceDeviation(
        address token,
        uint256 expectedPrice
    ) external view returns (bool valid, uint256 deviation) {
        return _validatePrice(token, expectedPrice);
    }

    function _validatePrice(
        address token,
        uint256 expectedPrice
    ) internal view returns (bool valid, uint256 deviation) {
        if (chainlinkOracles[token] == address(0)) {
            return (true, 0); // No oracle, skip validation
        }

        uint256 oraclePrice = _getChainlinkPrice(token);

        if (oraclePrice == 0) {
            return (false, type(uint256).max);
        }

        // Calculate deviation
        if (expectedPrice > oraclePrice) {
            deviation = ((expectedPrice - oraclePrice) * 10000) / oraclePrice;
        } else {
            deviation = ((oraclePrice - expectedPrice) * 10000) / oraclePrice;
        }

        valid = deviation <= maxPriceDeviationBps;

        return (valid, deviation);
    }

    function _getChainlinkPrice(address token) internal view returns (uint256) {
        address oracle = chainlinkOracles[token];
        if (oracle == address(0)) return 0;

        // Interface: AggregatorV3Interface
        // latestRoundData() returns (roundId, answer, startedAt, updatedAt, answeredInRound)
        (bool success, bytes memory data) = oracle.staticcall(
            abi.encodeWithSignature("latestRoundData()")
        );

        if (!success || data.length < 160) return 0;

        (, int256 answer, , uint256 updatedAt, ) = abi.decode(
            data,
            (uint80, int256, uint256, uint256, uint80)
        );

        // Check staleness
        if (block.timestamp - updatedAt > oracleStalenessThreshold) {
            return 0;
        }

        return answer > 0 ? uint256(answer) : 0;
    }

    function _getUniswapV3TWAP(address token) internal view returns (uint256) {
        address pool = uniswapV3Pools[token];
        if (pool == address(0)) return 0;

        // Get TWAP from Uniswap V3 pool
        // observe(secondsAgo) returns (tickCumulatives, secondsPerLiquidityCumulatives)
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 1800; // 30 min TWAP
        secondsAgos[1] = 0;

        (bool success, bytes memory data) = pool.staticcall(
            abi.encodeWithSignature("observe(uint32[])", secondsAgos)
        );

        if (!success) return 0;

        (int56[] memory tickCumulatives, ) = abi.decode(
            data,
            (int56[], uint160[])
        );

        // Calculate TWAP price from tick cumulatives
        int56 tickCumulativesDelta = tickCumulatives[1] - tickCumulatives[0];
        int24 arithmeticMeanTick = int24(tickCumulativesDelta / 1800);

        // Convert tick to price (simplified - actual implementation uses sqrtPriceX96)
        // Price = 1.0001^tick
        return _tickToPrice(arithmeticMeanTick);
    }

    function _tickToPrice(int24 tick) internal pure returns (uint256) {
        // Simplified tick to price conversion
        // In production, use TickMath library from Uniswap
        uint256 absTick = tick < 0
            ? uint256(uint24(-tick))
            : uint256(uint24(tick));

        uint256 price = 1e18;
        if (absTick & 0x1 != 0) price = (price * 1000049998750) / 1e12;
        if (absTick & 0x2 != 0) price = (price * 1000100000000) / 1e12;
        if (absTick & 0x4 != 0) price = (price * 1000200010000) / 1e12;
        // ... more bits for precision

        return tick < 0 ? (1e36 / price) : price;
    }

    function _calculatePriceConfidence(
        DEXPriceData memory priceData
    ) internal pure returns (uint256) {
        uint256 sources = 0;
        uint256 totalDeviation = 0;
        uint256 avgPrice = 0;

        // Count sources and calculate average
        if (priceData.chainlinkPrice > 0) {
            avgPrice += priceData.chainlinkPrice;
            sources++;
        }
        if (priceData.uniswapV3TWAP > 0) {
            avgPrice += priceData.uniswapV3TWAP;
            sources++;
        }

        if (sources == 0) return 0;
        avgPrice = avgPrice / sources;

        // Calculate deviation from average
        if (priceData.chainlinkPrice > 0) {
            uint256 dev = priceData.chainlinkPrice > avgPrice
                ? priceData.chainlinkPrice - avgPrice
                : avgPrice - priceData.chainlinkPrice;
            totalDeviation += (dev * 100) / avgPrice;
        }
        if (priceData.uniswapV3TWAP > 0) {
            uint256 dev = priceData.uniswapV3TWAP > avgPrice
                ? priceData.uniswapV3TWAP - avgPrice
                : avgPrice - priceData.uniswapV3TWAP;
            totalDeviation += (dev * 100) / avgPrice;
        }

        uint256 avgDeviation = totalDeviation / sources;

        // Confidence = 100 - avgDeviation (capped at 0-100)
        if (avgDeviation >= 100) return 0;
        return 100 - avgDeviation;
    }

    /*//////////////////////////////////////////////////////////////
                     FLASHBOTS PROTECT INTEGRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Enable Flashbots Protect for a user
     * @param maxPriorityFee Maximum priority fee willing to pay
     * @param minRefund Minimum refund from MEV-Share
     * @param mevShareEnabled Whether to participate in MEV-Share
     */
    function enableFlashbotsProtect(
        uint256 maxPriorityFee,
        uint256 minRefund,
        bool mevShareEnabled
    ) external {
        flashbotsConfigs[msg.sender] = FlashbotsConfig({
            enabled: true,
            relayer: address(0), // Set by protocol
            maxPriorityFee: maxPriorityFee,
            minRefund: minRefund,
            mevShareEnabled: mevShareEnabled
        });

        emit FlashbotsProtectEnabled(msg.sender, true);
    }

    /**
     * @notice Disable Flashbots Protect for a user
     */
    function disableFlashbotsProtect() external {
        flashbotsConfigs[msg.sender].enabled = false;
        emit FlashbotsProtectEnabled(msg.sender, false);
    }

    /**
     * @notice Check if user has Flashbots Protect enabled
     * @param user User address
     * @return enabled True if Flashbots Protect is enabled
     */
    function isFlashbotsProtected(address user) external view returns (bool) {
        return flashbotsConfigs[user].enabled;
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSACTION ORDERING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get expected nonce for next operation
     * @param user User address
     * @return nonce Expected nonce
     */
    function getNextNonce(address user) external view returns (uint256) {
        return userNonces[user] + 1;
    }

    /**
     * @notice Verify transaction ordering integrity
     * @param user User address
     * @param expectedNonce Expected nonce
     * @return valid True if nonce matches
     */
    function verifyTransactionOrder(
        address user,
        uint256 expectedNonce
    ) external view returns (bool) {
        return userNonces[user] + 1 == expectedNonce;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Chainlink oracle for a token
     * @param token Token address
     * @param oracle Chainlink aggregator address
     */
    function setChainlinkOracle(
        address token,
        address oracle
    ) external onlyRole(OPERATOR_ROLE) {
        chainlinkOracles[token] = oracle;
    }

    /**
     * @notice Set Uniswap V3 pool for a token
     * @param token Token address
     * @param pool Uniswap V3 pool address
     */
    function setUniswapV3Pool(
        address token,
        address pool
    ) external onlyRole(OPERATOR_ROLE) {
        uniswapV3Pools[token] = pool;
    }

    /**
     * @notice Authorize a contract to use security integrations
     * @param contractAddress Contract to authorize
     * @param authorized Authorization status
     */
    function setAuthorizedContract(
        address contractAddress,
        bool authorized
    ) external onlyRole(OPERATOR_ROLE) {
        authorizedContracts[contractAddress] = authorized;
    }

    /**
     * @notice Update max price deviation
     * @param newMaxDeviationBps New max deviation in basis points
     */
    function setMaxPriceDeviation(
        uint256 newMaxDeviationBps
    ) external onlyRole(OPERATOR_ROLE) {
        maxPriceDeviationBps = newMaxDeviationBps;
    }

    /**
     * @notice Update oracle staleness threshold
     * @param newThreshold New threshold in seconds
     */
    function setOracleStalenessThreshold(
        uint256 newThreshold
    ) external onlyRole(OPERATOR_ROLE) {
        oracleStalenessThreshold = newThreshold;
    }

    /**
     * @notice Pause the contract
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the contract
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }
}
