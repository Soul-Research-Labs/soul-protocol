// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PILMetricsCollector
 * @notice On-chain metrics collection for PIL protocol
 * @dev Collects and exposes protocol metrics for monitoring
 */
contract PILMetricsCollector {
    // ============================================
    // State Variables
    // ============================================

    address public owner;
    address public protocolAddress;

    // Cumulative metrics
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalBridgeTransfers;
    uint256 public totalVolume;
    uint256 public totalProofsVerified;

    // Time-windowed metrics (24h rolling)
    uint256 public deposits24h;
    uint256 public withdrawals24h;
    uint256 public bridgeTransfers24h;
    uint256 public volume24h;
    uint256 public lastWindowReset;

    // Gas tracking
    uint256 public totalGasUsed;
    uint256 public avgGasPerTx;
    uint256 public txCount;

    // Relayer metrics
    mapping(address => RelayerMetrics) public relayerMetrics;
    address[] public relayers;

    // Bridge metrics per chain
    mapping(bytes32 => BridgeMetrics) public bridgeMetricsByChain;
    bytes32[] public registeredChains;

    // Proof metrics per system
    mapping(bytes32 => ProofMetrics) public proofMetricsBySystem;
    bytes32[] public registeredProofSystems;

    // Health checkpoints
    uint256 public lastHeartbeat;
    uint256 public heartbeatInterval = 5 minutes;

    // ============================================
    // Structs
    // ============================================

    struct RelayerMetrics {
        uint256 totalTransactions;
        uint256 totalGasUsed;
        uint256 successCount;
        uint256 failureCount;
        uint256 lastActive;
        uint256 reputation;
        bool registered;
    }

    struct BridgeMetrics {
        uint256 totalVolume;
        uint256 totalTransfers;
        uint256 pendingTransfers;
        uint256 successfulTransfers;
        uint256 failedTransfers;
        uint256 avgTransferTime;
        uint256 lastTransfer;
    }

    struct ProofMetrics {
        uint256 totalGenerated;
        uint256 totalVerified;
        uint256 totalFailed;
        uint256 avgGenerationTime;
        uint256 avgVerificationGas;
        uint256 lastUsed;
    }

    // ============================================
    // Events
    // ============================================

    event MetricRecorded(string metricType, uint256 value, uint256 timestamp);
    event RelayerMetricsUpdated(
        address indexed relayer,
        uint256 txCount,
        uint256 gasUsed
    );
    event BridgeMetricsUpdated(
        bytes32 indexed chainId,
        uint256 volume,
        uint256 transfers
    );
    event ProofMetricsUpdated(
        bytes32 indexed system,
        uint256 verified,
        uint256 generationTime
    );
    event Heartbeat(uint256 timestamp, uint256 tvl, uint256 activeRelayers);
    event WindowReset(uint256 deposits, uint256 withdrawals, uint256 volume);

    // ============================================
    // Constructor
    // ============================================

    constructor(address _protocolAddress) {
        owner = msg.sender;
        protocolAddress = _protocolAddress;
        lastWindowReset = block.timestamp;
        lastHeartbeat = block.timestamp;
    }

    // ============================================
    // Modifiers
    // ============================================

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyProtocol() {
        require(
            msg.sender == protocolAddress || msg.sender == owner,
            "Not authorized"
        );
        _;
    }

    // ============================================
    // Recording Functions
    // ============================================

    /**
     * @notice Record a deposit
     * @param amount The deposit amount
     * @param gasUsed Gas used for the transaction
     */
    function recordDeposit(
        uint256 amount,
        uint256 gasUsed
    ) external onlyProtocol {
        _checkWindowReset();

        totalDeposits++;
        deposits24h++;
        totalVolume += amount;
        volume24h += amount;
        _updateGasMetrics(gasUsed);

        emit MetricRecorded("deposit", amount, block.timestamp);
    }

    /**
     * @notice Record a withdrawal
     * @param amount The withdrawal amount
     * @param gasUsed Gas used for the transaction
     */
    function recordWithdrawal(
        uint256 amount,
        uint256 gasUsed
    ) external onlyProtocol {
        _checkWindowReset();

        totalWithdrawals++;
        withdrawals24h++;
        _updateGasMetrics(gasUsed);

        emit MetricRecorded("withdrawal", amount, block.timestamp);
    }

    /**
     * @notice Record a bridge transfer
     * @param chainId The target chain identifier
     * @param amount The transfer amount
     * @param success Whether the transfer succeeded
     * @param transferTime Time taken for the transfer
     */
    function recordBridgeTransfer(
        bytes32 chainId,
        uint256 amount,
        bool success,
        uint256 transferTime
    ) external onlyProtocol {
        _checkWindowReset();

        totalBridgeTransfers++;
        bridgeTransfers24h++;
        totalVolume += amount;
        volume24h += amount;

        BridgeMetrics storage bm = bridgeMetricsByChain[chainId];

        if (bm.totalTransfers == 0) {
            registeredChains.push(chainId);
        }

        bm.totalVolume += amount;
        bm.totalTransfers++;
        bm.lastTransfer = block.timestamp;

        if (success) {
            bm.successfulTransfers++;
            // Update average transfer time
            bm.avgTransferTime =
                (bm.avgTransferTime *
                    (bm.successfulTransfers - 1) +
                    transferTime) /
                bm.successfulTransfers;
        } else {
            bm.failedTransfers++;
        }

        emit BridgeMetricsUpdated(chainId, bm.totalVolume, bm.totalTransfers);
    }

    /**
     * @notice Record proof verification
     * @param proofSystem The proof system identifier
     * @param generationTime Time to generate the proof
     * @param verificationGas Gas used for verification
     * @param success Whether verification succeeded
     */
    function recordProofVerification(
        bytes32 proofSystem,
        uint256 generationTime,
        uint256 verificationGas,
        bool success
    ) external onlyProtocol {
        ProofMetrics storage pm = proofMetricsBySystem[proofSystem];

        if (pm.totalGenerated == 0) {
            registeredProofSystems.push(proofSystem);
        }

        pm.totalGenerated++;
        pm.lastUsed = block.timestamp;

        if (success) {
            pm.totalVerified++;
            totalProofsVerified++;

            // Update averages
            pm.avgGenerationTime =
                (pm.avgGenerationTime *
                    (pm.totalVerified - 1) +
                    generationTime) /
                pm.totalVerified;
            pm.avgVerificationGas =
                (pm.avgVerificationGas *
                    (pm.totalVerified - 1) +
                    verificationGas) /
                pm.totalVerified;
        } else {
            pm.totalFailed++;
        }

        emit ProofMetricsUpdated(proofSystem, pm.totalVerified, generationTime);
    }

    /**
     * @notice Update relayer metrics
     * @param relayer The relayer address
     * @param gasUsed Gas used by the relayer
     * @param success Whether the operation succeeded
     */
    function updateRelayerMetrics(
        address relayer,
        uint256 gasUsed,
        bool success
    ) external onlyProtocol {
        RelayerMetrics storage rm = relayerMetrics[relayer];

        if (!rm.registered) {
            rm.registered = true;
            rm.reputation = 100;
            relayers.push(relayer);
        }

        rm.totalTransactions++;
        rm.totalGasUsed += gasUsed;
        rm.lastActive = block.timestamp;

        if (success) {
            rm.successCount++;
            // Increase reputation (max 150)
            if (rm.reputation < 150) {
                rm.reputation += 1;
            }
        } else {
            rm.failureCount++;
            // Decrease reputation
            if (rm.reputation > 10) {
                rm.reputation -= 5;
            }
        }

        emit RelayerMetricsUpdated(
            relayer,
            rm.totalTransactions,
            rm.totalGasUsed
        );
    }

    // ============================================
    // Heartbeat & Health Check
    // ============================================

    /**
     * @notice Emit heartbeat for monitoring systems
     * @param tvl Current total value locked
     */
    function heartbeat(uint256 tvl) external onlyProtocol {
        require(
            block.timestamp >= lastHeartbeat + heartbeatInterval,
            "Too frequent"
        );

        lastHeartbeat = block.timestamp;
        uint256 activeCount = _countActiveRelayers();

        emit Heartbeat(block.timestamp, tvl, activeCount);
    }

    /**
     * @notice Check if protocol is healthy
     * @return healthy Whether the protocol is healthy
     * @return missedHeartbeats Number of missed heartbeats
     */
    function isHealthy()
        external
        view
        returns (bool healthy, uint256 missedHeartbeats)
    {
        uint256 elapsed = block.timestamp - lastHeartbeat;
        missedHeartbeats = elapsed / heartbeatInterval;
        healthy = missedHeartbeats <= 2; // Allow up to 2 missed heartbeats
    }

    // ============================================
    // Query Functions
    // ============================================

    /**
     * @notice Get protocol overview metrics
     */
    function getOverview()
        external
        view
        returns (
            uint256 _totalDeposits,
            uint256 _totalWithdrawals,
            uint256 _totalBridgeTransfers,
            uint256 _totalVolume,
            uint256 _totalProofsVerified,
            uint256 _avgGasPerTx,
            uint256 _relayerCount
        )
    {
        return (
            totalDeposits,
            totalWithdrawals,
            totalBridgeTransfers,
            totalVolume,
            totalProofsVerified,
            avgGasPerTx,
            relayers.length
        );
    }

    /**
     * @notice Get 24h window metrics
     */
    function get24hMetrics()
        external
        view
        returns (
            uint256 _deposits24h,
            uint256 _withdrawals24h,
            uint256 _bridgeTransfers24h,
            uint256 _volume24h,
            uint256 _windowStart
        )
    {
        return (
            deposits24h,
            withdrawals24h,
            bridgeTransfers24h,
            volume24h,
            lastWindowReset
        );
    }

    /**
     * @notice Get bridge metrics for a chain
     */
    function getBridgeMetrics(
        bytes32 chainId
    ) external view returns (BridgeMetrics memory) {
        return bridgeMetricsByChain[chainId];
    }

    /**
     * @notice Get proof metrics for a system
     */
    function getProofMetrics(
        bytes32 proofSystem
    ) external view returns (ProofMetrics memory) {
        return proofMetricsBySystem[proofSystem];
    }

    /**
     * @notice Get all registered chains
     */
    function getRegisteredChains() external view returns (bytes32[] memory) {
        return registeredChains;
    }

    /**
     * @notice Get all registered proof systems
     */
    function getRegisteredProofSystems()
        external
        view
        returns (bytes32[] memory)
    {
        return registeredProofSystems;
    }

    /**
     * @notice Get relayer success rate
     */
    function getRelayerSuccessRate(
        address relayer
    ) external view returns (uint256) {
        RelayerMetrics storage rm = relayerMetrics[relayer];
        if (rm.totalTransactions == 0) return 0;
        return (rm.successCount * 100) / rm.totalTransactions;
    }

    /**
     * @notice Get global success rate
     */
    function getGlobalSuccessRate()
        external
        view
        returns (uint256 bridgeRate, uint256 proofRate)
    {
        uint256 totalSuccess = 0;
        uint256 totalFailed = 0;

        for (uint256 i = 0; i < registeredChains.length; i++) {
            BridgeMetrics storage bm = bridgeMetricsByChain[
                registeredChains[i]
            ];
            totalSuccess += bm.successfulTransfers;
            totalFailed += bm.failedTransfers;
        }

        if (totalSuccess + totalFailed > 0) {
            bridgeRate = (totalSuccess * 100) / (totalSuccess + totalFailed);
        }

        uint256 proofSuccess = 0;
        uint256 proofFailed = 0;

        for (uint256 i = 0; i < registeredProofSystems.length; i++) {
            ProofMetrics storage pm = proofMetricsBySystem[
                registeredProofSystems[i]
            ];
            proofSuccess += pm.totalVerified;
            proofFailed += pm.totalFailed;
        }

        if (proofSuccess + proofFailed > 0) {
            proofRate = (proofSuccess * 100) / (proofSuccess + proofFailed);
        }
    }

    // ============================================
    // Admin Functions
    // ============================================

    function setProtocolAddress(address _protocolAddress) external onlyOwner {
        protocolAddress = _protocolAddress;
    }

    function setHeartbeatInterval(uint256 _interval) external onlyOwner {
        heartbeatInterval = _interval;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }

    // ============================================
    // Internal Functions
    // ============================================

    function _checkWindowReset() internal {
        if (block.timestamp >= lastWindowReset + 24 hours) {
            emit WindowReset(deposits24h, withdrawals24h, volume24h);
            deposits24h = 0;
            withdrawals24h = 0;
            bridgeTransfers24h = 0;
            volume24h = 0;
            lastWindowReset = block.timestamp;
        }
    }

    function _updateGasMetrics(uint256 gasUsed) internal {
        totalGasUsed += gasUsed;
        txCount++;
        avgGasPerTx = totalGasUsed / txCount;
    }

    function _countActiveRelayers() internal view returns (uint256 count) {
        uint256 threshold = block.timestamp - 1 hours;
        for (uint256 i = 0; i < relayers.length; i++) {
            if (relayerMetrics[relayers[i]].lastActive >= threshold) {
                count++;
            }
        }
    }
}
