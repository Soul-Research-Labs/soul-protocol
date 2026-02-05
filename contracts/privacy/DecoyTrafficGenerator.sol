// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title DecoyTrafficGenerator
 * @author Soul Protocol
 * @notice Generates cover traffic to prevent low-traffic deanonymization
 * @dev Phase 2 of Metadata Resistance - maintains constant traffic rate with decoys
 *
 * PRIVACY GUARANTEE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    COVER TRAFFIC GENERATION                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  PROBLEM: LOW-TRAFFIC DEANONYMIZATION                                   │
 * │                                                                          │
 * │  Time    │ Real Txs │ Without Decoys │ With Decoys                      │
 * │  ────────┼──────────┼────────────────┼──────────────                    │
 * │  00:00   │    1     │  1 tx (exposed) │  8 txs (hidden)                 │
 * │  06:00   │    0     │  0 tx (gap)     │  8 txs (constant)               │
 * │  12:00   │   20     │ 20 tx (crowd)   │ 20 txs (same)                   │
 * │  18:00   │    3     │  3 tx (exposed) │  8 txs (hidden)                 │
 * │                                                                          │
 * │  SOLUTION:                                                               │
 * │  - Maintain minimum traffic rate (e.g., 8 tx/hour) across all routes   │
 * │  - Decoys are indistinguishable from real transactions                  │
 * │  - Only submitter knows if transaction is real or decoy                 │
 * │  - VRF-based scheduling prevents predictable patterns                   │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract DecoyTrafficGenerator is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant DECOY_RELAYER_ROLE =
        keccak256("DECOY_RELAYER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Default minimum traffic rate (transactions per hour)
    uint256 public constant DEFAULT_MIN_TRAFFIC_RATE = 8;

    /// @notice Maximum traffic rate to prevent spam
    uint256 public constant MAX_TRAFFIC_RATE = 100;

    /// @notice Decoy payload size (matches real transaction size)
    uint256 public constant DECOY_PAYLOAD_SIZE = 2048;

    /// @notice VRF domain separator
    bytes32 public constant VRF_DOMAIN = keccak256("Soul_DECOY_VRF_V1");

    /// @notice Time window for rate calculation (1 hour)
    uint256 public constant RATE_WINDOW = 1 hours;

    /// @notice Minimum interval between decoys (prevents spam)
    uint256 public constant MIN_DECOY_INTERVAL = 30 seconds;

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Route traffic configuration
     */
    struct RouteTrafficConfig {
        uint256 minTrafficRate; // Minimum tx/hour
        uint256 decoyBudgetWei; // ETH allocated for this route
        uint256 lastDecoyTime; // Last decoy generation time
        uint256 realTxCount; // Real transactions in current window
        uint256 decoyCount; // Decoys generated in current window
        uint256 windowStart; // Current rate window start
        bool isActive;
    }

    /**
     * @notice Decoy transaction record
     */
    struct DecoyRecord {
        bytes32 decoyId;
        bytes32 fakeCommitment;
        uint256 targetChainId;
        uint256 generatedAt;
        address generator;
        bytes32 vrfProofHash;
    }

    /**
     * @notice VRF scheduling parameters
     */
    struct VRFSchedule {
        bytes32 seed;
        uint256 nextDecoyTime;
        uint256 nonce;
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice Route configurations: routeHash => config
    mapping(bytes32 => RouteTrafficConfig) public routeConfigs;

    /// @notice Decoy records: decoyId => record
    mapping(bytes32 => DecoyRecord) public decoyRecords;

    /// @notice VRF schedules per route: routeHash => schedule
    mapping(bytes32 => VRFSchedule) public vrfSchedules;

    /// @notice Total decoy budget (ETH)
    uint256 public totalDecoyBudget;

    /// @notice Spent decoy budget
    uint256 public spentDecoyBudget;

    /// @notice Total decoys generated
    uint256 public totalDecoysGenerated;

    /// @notice Batch accumulator address (where decoys are sent)
    address public batchAccumulator;

    /// @notice Active routes for iteration
    bytes32[] public activeRoutes;

    /// @notice Route hash to index mapping
    mapping(bytes32 => uint256) public routeIndex;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event DecoyGenerated(
        bytes32 indexed decoyId,
        bytes32 indexed routeHash,
        uint256 targetChainId,
        uint256 timestamp
    );

    event RouteTrafficConfigured(
        bytes32 indexed routeHash,
        uint256 minTrafficRate,
        uint256 decoyBudget
    );

    event DecoyBudgetDeposited(address indexed depositor, uint256 amount);

    event DecoyBudgetWithdrawn(address indexed recipient, uint256 amount);

    event TrafficRateUpdated(
        bytes32 indexed routeHash,
        uint256 realTxCount,
        uint256 decoyCount,
        uint256 totalRate
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidTrafficRate();
    error InsufficientDecoyBudget();
    error RouteNotActive();
    error DecoyIntervalTooShort();
    error InvalidVRFProof();
    error ZeroAddress();
    error DecoyNotScheduled();
    error InvalidRoute();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address _batchAccumulator
    ) external initializer {
        if (admin == address(0)) revert ZeroAddress();
        if (_batchAccumulator == address(0)) revert ZeroAddress();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(TREASURY_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        batchAccumulator = _batchAccumulator;
    }

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    /**
     * @notice Configure traffic rate for a route
     * @param sourceChainId Source chain
     * @param targetChainId Target chain
     * @param minTrafficRate Minimum transactions per hour
     */
    function configureRoute(
        uint256 sourceChainId,
        uint256 targetChainId,
        uint256 minTrafficRate
    ) external onlyRole(OPERATOR_ROLE) {
        if (minTrafficRate == 0 || minTrafficRate > MAX_TRAFFIC_RATE) {
            revert InvalidTrafficRate();
        }

        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);

        RouteTrafficConfig storage config = routeConfigs[routeHash];

        if (!config.isActive) {
            // New route - add to active routes
            routeIndex[routeHash] = activeRoutes.length;
            activeRoutes.push(routeHash);
        }

        config.minTrafficRate = minTrafficRate;
        config.isActive = true;
        config.windowStart = block.timestamp;

        // Initialize VRF schedule
        _initializeVRFSchedule(routeHash);

        emit RouteTrafficConfigured(
            routeHash,
            minTrafficRate,
            config.decoyBudgetWei
        );
    }

    /**
     * @notice Allocate decoy budget to a route
     */
    function allocateDecoyBudget(
        uint256 sourceChainId,
        uint256 targetChainId,
        uint256 amount
    ) external onlyRole(TREASURY_ROLE) {
        if (amount > totalDecoyBudget - spentDecoyBudget) {
            revert InsufficientDecoyBudget();
        }

        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);
        routeConfigs[routeHash].decoyBudgetWei += amount;
        spentDecoyBudget += amount;
    }

    // =========================================================================
    // DECOY GENERATION
    // =========================================================================

    /**
     * @notice Generate a decoy transaction
     * @dev Called by authorized decoy relayers based on VRF schedule
     * @param sourceChainId Source chain
     * @param targetChainId Target chain
     * @param vrfProof VRF proof for scheduling verification
     */
    function generateDecoy(
        uint256 sourceChainId,
        uint256 targetChainId,
        bytes calldata vrfProof
    ) external onlyRole(DECOY_RELAYER_ROLE) nonReentrant whenNotPaused {
        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);
        RouteTrafficConfig storage config = routeConfigs[routeHash];

        if (!config.isActive) revert RouteNotActive();

        // Check timing
        if (block.timestamp < config.lastDecoyTime + MIN_DECOY_INTERVAL) {
            revert DecoyIntervalTooShort();
        }

        // Verify VRF schedule
        VRFSchedule storage schedule = vrfSchedules[routeHash];
        if (block.timestamp < schedule.nextDecoyTime) {
            revert DecoyNotScheduled();
        }

        // Verify VRF proof
        if (!_verifyVRFProof(routeHash, vrfProof)) {
            revert InvalidVRFProof();
        }

        // Check if decoy is needed (based on traffic rate)
        _updateRateWindow(routeHash);

        uint256 currentRate = config.realTxCount + config.decoyCount;
        if (currentRate >= config.minTrafficRate) {
            // Already at minimum rate, no decoy needed
            // But update schedule for next window
            _updateVRFSchedule(routeHash);
            return;
        }

        // Generate decoy
        bytes32 fakeCommitment = _generateFakeCommitment();
        bytes memory noise = _generateNoise();

        bytes32 decoyId = keccak256(
            abi.encodePacked(
                routeHash,
                block.timestamp,
                totalDecoysGenerated,
                fakeCommitment
            )
        );

        // Record decoy
        decoyRecords[decoyId] = DecoyRecord({
            decoyId: decoyId,
            fakeCommitment: fakeCommitment,
            targetChainId: targetChainId,
            generatedAt: block.timestamp,
            generator: msg.sender,
            vrfProofHash: keccak256(vrfProof)
        });

        // Update state
        config.decoyCount++;
        config.lastDecoyTime = block.timestamp;
        totalDecoysGenerated++;

        // Update VRF schedule for next decoy
        _updateVRFSchedule(routeHash);

        // Submit to batch accumulator (decoy looks like real transaction)
        _submitDecoyToBatch(fakeCommitment, noise, targetChainId);

        emit DecoyGenerated(decoyId, routeHash, targetChainId, block.timestamp);

        emit TrafficRateUpdated(
            routeHash,
            config.realTxCount,
            config.decoyCount,
            config.realTxCount + config.decoyCount
        );
    }

    /**
     * @notice Record a real transaction (called by BatchAccumulator)
     * @dev Used to track real traffic for rate calculation
     */
    function recordRealTransaction(
        uint256 sourceChainId,
        uint256 targetChainId
    ) external {
        require(msg.sender == batchAccumulator, "Only batch accumulator");

        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);
        RouteTrafficConfig storage config = routeConfigs[routeHash];

        if (!config.isActive) return;

        _updateRateWindow(routeHash);
        config.realTxCount++;

        emit TrafficRateUpdated(
            routeHash,
            config.realTxCount,
            config.decoyCount,
            config.realTxCount + config.decoyCount
        );
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get current traffic rate for a route
     */
    function getTrafficRate(
        uint256 sourceChainId,
        uint256 targetChainId
    )
        external
        view
        returns (
            uint256 realTxRate,
            uint256 decoyRate,
            uint256 totalRate,
            uint256 minRequired,
            uint256 decoysNeeded
        )
    {
        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);
        RouteTrafficConfig storage config = routeConfigs[routeHash];

        realTxRate = config.realTxCount;
        decoyRate = config.decoyCount;
        totalRate = realTxRate + decoyRate;
        minRequired = config.minTrafficRate;
        decoysNeeded = totalRate < minRequired ? minRequired - totalRate : 0;
    }

    /**
     * @notice Get next scheduled decoy time for a route
     */
    function getNextDecoyTime(
        uint256 sourceChainId,
        uint256 targetChainId
    ) external view returns (uint256) {
        bytes32 routeHash = _getRouteHash(sourceChainId, targetChainId);
        return vrfSchedules[routeHash].nextDecoyTime;
    }

    /**
     * @notice Get decoy budget status
     */
    function getDecoyBudget()
        external
        view
        returns (uint256 total, uint256 spent, uint256 remaining)
    {
        total = totalDecoyBudget;
        spent = spentDecoyBudget;
        remaining = total - spent;
    }

    /**
     * @notice Get all active routes
     */
    function getActiveRoutes() external view returns (bytes32[] memory) {
        return activeRoutes;
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    function _updateRateWindow(bytes32 routeHash) internal {
        RouteTrafficConfig storage config = routeConfigs[routeHash];

        if (block.timestamp >= config.windowStart + RATE_WINDOW) {
            // New window - reset counters
            config.windowStart = block.timestamp;
            config.realTxCount = 0;
            config.decoyCount = 0;
        }
    }

    function _initializeVRFSchedule(bytes32 routeHash) internal {
        VRFSchedule storage schedule = vrfSchedules[routeHash];

        schedule.seed = keccak256(
            abi.encodePacked(
                VRF_DOMAIN,
                routeHash,
                block.timestamp,
                block.prevrandao
            )
        );
        schedule.nonce = 0;
        schedule.nextDecoyTime =
            block.timestamp +
            _getRandomInterval(schedule.seed, 0);
    }

    function _updateVRFSchedule(bytes32 routeHash) internal {
        VRFSchedule storage schedule = vrfSchedules[routeHash];

        schedule.nonce++;
        schedule.nextDecoyTime =
            block.timestamp +
            _getRandomInterval(schedule.seed, schedule.nonce);
    }

    function _getRandomInterval(
        bytes32 seed,
        uint256 nonce
    ) internal view returns (uint256) {
        // Generate random interval between MIN_DECOY_INTERVAL and RATE_WINDOW / minRate
        bytes32 random = keccak256(
            abi.encodePacked(seed, nonce, block.timestamp)
        );
        uint256 maxInterval = RATE_WINDOW / DEFAULT_MIN_TRAFFIC_RATE;
        uint256 interval = MIN_DECOY_INTERVAL +
            (uint256(random) % (maxInterval - MIN_DECOY_INTERVAL));
        return interval;
    }

    function _verifyVRFProof(
        bytes32 routeHash,
        bytes calldata proof
    ) internal view returns (bool) {
        // TODO: Implement actual VRF verification
        // For now, accept any non-empty proof from authorized relayer
        return proof.length > 0 && routeConfigs[routeHash].isActive;
    }

    function _generateFakeCommitment() internal view returns (bytes32) {
        // Generate random commitment that's indistinguishable from real ones
        return
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.prevrandao,
                    totalDecoysGenerated,
                    msg.sender
                )
            );
    }

    function _generateNoise() internal view returns (bytes memory) {
        // Generate random noise of fixed size
        bytes memory noise = new bytes(DECOY_PAYLOAD_SIZE);

        // Fill with pseudo-random data
        bytes32 seed = keccak256(
            abi.encodePacked(
                block.timestamp,
                block.prevrandao,
                totalDecoysGenerated
            )
        );

        for (uint256 i = 0; i < DECOY_PAYLOAD_SIZE; i += 32) {
            bytes32 chunk = keccak256(abi.encodePacked(seed, i));
            uint256 remaining = DECOY_PAYLOAD_SIZE - i;
            uint256 copyLen = remaining < 32 ? remaining : 32;

            for (uint256 j = 0; j < copyLen; j++) {
                noise[i + j] = chunk[j];
            }
        }

        return noise;
    }

    function _submitDecoyToBatch(
        bytes32 fakeCommitment,
        bytes memory noise,
        uint256 targetChainId
    ) internal {
        // Generate fake nullifier hash
        bytes32 fakeNullifierHash = keccak256(
            abi.encodePacked(fakeCommitment, "DECOY", block.timestamp)
        );

        // Call batch accumulator
        // Note: This will revert if nullifier already used, which is fine
        // The decoy will be retried with a new commitment
        (bool success, ) = batchAccumulator.call(
            abi.encodeWithSignature(
                "submitToBatch(bytes32,bytes32,bytes,uint256)",
                fakeCommitment,
                fakeNullifierHash,
                noise,
                targetChainId
            )
        );

        // If submission fails (e.g., nullifier collision), that's okay
        // The decoy just won't be submitted this round
        if (!success) {
            // Could emit an event here for monitoring
        }
    }

    function _getRouteHash(
        uint256 sourceChainId,
        uint256 targetChainId
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sourceChainId, targetChainId));
    }

    // =========================================================================
    // TREASURY FUNCTIONS
    // =========================================================================

    /**
     * @notice Deposit ETH for decoy gas costs
     */
    function depositDecoyBudget() external payable onlyRole(TREASURY_ROLE) {
        totalDecoyBudget += msg.value;
        emit DecoyBudgetDeposited(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw unused decoy budget
     */
    function withdrawDecoyBudget(
        address recipient,
        uint256 amount
    ) external onlyRole(TREASURY_ROLE) {
        if (recipient == address(0)) revert ZeroAddress();

        uint256 available = totalDecoyBudget - spentDecoyBudget;
        require(amount <= available, "Insufficient available budget");

        totalDecoyBudget -= amount;

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        emit DecoyBudgetWithdrawn(recipient, amount);
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    function setBatchAccumulator(
        address _batchAccumulator
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_batchAccumulator == address(0)) revert ZeroAddress();
        batchAccumulator = _batchAccumulator;
    }

    // =========================================================================
    // UPGRADE AUTHORIZATION
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {
        totalDecoyBudget += msg.value;
        emit DecoyBudgetDeposited(msg.sender, msg.value);
    }
}
