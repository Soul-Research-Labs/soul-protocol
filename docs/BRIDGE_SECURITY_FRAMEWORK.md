# Cross-Chain Bridge Security Framework

## Problem Statement

ZASEON relies on external bridge infrastructure (LayerZero, Hyperlane, native L2 bridges). Bridge exploits have resulted in $2B+ in losses historically. We must minimize trust assumptions and implement defense-in-depth.

## Threat Model

### Bridge Attack Vectors

1. **Validator Compromise**: Malicious validators forge messages
2. **Relay Manipulation**: Relayers submit false proofs
3. **Smart Contract Bugs**: Bridge contract vulnerabilities
4. **Economic Attacks**: Insufficient security bonds
5. **Censorship**: Validators refuse to relay messages
6. **Front-Running**: MEV attacks on bridge transactions
7. **Replay Attacks**: Same message executed multiple times

### Historical Bridge Exploits

- Ronin Bridge: $625M (validator compromise)
- Poly Network: $611M (contract bug)
- BNB Bridge: $586M (proof forgery)
- Wormhole: $326M (signature verification bug)
- Nomad: $190M (merkle root validation bug)

## Defense-in-Depth Strategy

### Layer 1: Bridge Diversity

**Don't rely on a single bridge**. Use multiple bridges with independent security models.

```solidity
// contracts/bridge/MultiBridgeRouter.sol
pragma solidity ^0.8.24;

contract MultiBridgeRouter {
    enum BridgeType {
        NATIVE_L2,      // Optimism, Arbitrum native bridges
        LAYERZERO,      // LayerZero V2
        HYPERLANE,      // Hyperlane
        CHAINLINK_CCIP, // Chainlink CCIP
        AXELAR          // Axelar Network
    }

    struct BridgeConfig {
        address adapter;
        uint256 securityScore;  // 0-100
        uint256 maxValuePerTx;
        bool isActive;
    }

    mapping(BridgeType => BridgeConfig) public bridges;

    // Route based on value and security requirements
    function selectBridge(uint256 value) public view returns (BridgeType) {
        if (value > 100 ether) {
            // High value: use most secure bridge (native L2)
            return BridgeType.NATIVE_L2;
        } else if (value > 10 ether) {
            // Medium value: use audited bridge (Chainlink CCIP)
            return BridgeType.CHAINLINK_CCIP;
        } else {
            // Low value: use fast bridge (LayerZero)
            return BridgeType.LAYERZERO;
        }
    }

    // Multi-bridge verification for critical operations
    function verifyWithMultipleBridges(
        bytes32 messageHash,
        BridgeType[] calldata bridgesToUse
    ) external view returns (bool) {
        require(bridgesToUse.length >= 2, "Need at least 2 bridges");

        uint256 confirmations = 0;
        for (uint i = 0; i < bridgesToUse.length; i++) {
            if (_verifyMessage(bridgesToUse[i], messageHash)) {
                confirmations++;
            }
        }

        // Require majority confirmation
        return confirmations >= (bridgesToUse.length / 2) + 1;
    }
}
```

### Layer 2: Optimistic Verification

**Challenge period** before finalizing high-value transfers.

```solidity
// contracts/security/OptimisticBridgeVerifier.sol
contract OptimisticBridgeVerifier {
    struct PendingTransfer {
        bytes32 messageHash;
        uint256 value;
        uint256 timestamp;
        address challenger;
        bool finalized;
        bool challenged;
    }

    mapping(bytes32 => PendingTransfer) public pendingTransfers;

    uint256 public constant CHALLENGE_PERIOD = 1 hours;
    uint256 public constant CHALLENGE_BOND = 1 ether;

    // Step 1: Submit transfer (enters challenge period)
    function submitTransfer(
        bytes32 messageHash,
        uint256 value,
        bytes calldata proof
    ) external {
        require(!pendingTransfers[messageHash].finalized, "Already finalized");

        pendingTransfers[messageHash] = PendingTransfer({
            messageHash: messageHash,
            value: value,
            timestamp: block.timestamp,
            challenger: address(0),
            finalized: false,
            challenged: false
        });

        emit TransferSubmitted(messageHash, value, block.timestamp + CHALLENGE_PERIOD);
    }

    // Step 2: Anyone can challenge suspicious transfers
    function challengeTransfer(bytes32 messageHash) external payable {
        require(msg.value >= CHALLENGE_BOND, "Insufficient bond");
        PendingTransfer storage transfer = pendingTransfers[messageHash];
        require(!transfer.finalized, "Already finalized");
        require(!transfer.challenged, "Already challenged");
        require(
            block.timestamp < transfer.timestamp + CHALLENGE_PERIOD,
            "Challenge period expired"
        );

        transfer.challenged = true;
        transfer.challenger = msg.sender;

        emit TransferChallenged(messageHash, msg.sender);

        // Pause and escalate to governance
        _escalateToGovernance(messageHash);
    }

    // Step 3: Finalize after challenge period
    function finalizeTransfer(bytes32 messageHash) external {
        PendingTransfer storage transfer = pendingTransfers[messageHash];
        require(!transfer.finalized, "Already finalized");
        require(!transfer.challenged, "Transfer challenged");
        require(
            block.timestamp >= transfer.timestamp + CHALLENGE_PERIOD,
            "Challenge period not expired"
        );

        transfer.finalized = true;

        // Execute the transfer
        _executeTransfer(messageHash);

        emit TransferFinalized(messageHash);
    }
}
```

### Layer 3: Independent Verification

**Verify bridge messages independently** using multiple data sources.

```solidity
// contracts/security/IndependentBridgeVerifier.sol
contract IndependentBridgeVerifier {
    // Verify using multiple methods
    function verifyMessage(
        uint256 sourceChainId,
        bytes32 messageHash,
        bytes calldata proof
    ) external view returns (bool) {
        // Method 1: Check bridge contract state
        bool bridgeVerified = _verifyViaBridge(sourceChainId, messageHash, proof);

        // Method 2: Check block headers (for L2s)
        bool headerVerified = _verifyViaBlockHeader(sourceChainId, messageHash);

        // Method 3: Check oracle (Chainlink, API3)
        bool oracleVerified = _verifyViaOracle(sourceChainId, messageHash);

        // Require at least 2 out of 3 confirmations
        uint256 confirmations = 0;
        if (bridgeVerified) confirmations++;
        if (headerVerified) confirmations++;
        if (oracleVerified) confirmations++;

        return confirmations >= 2;
    }

    function _verifyViaBlockHeader(
        uint256 sourceChainId,
        bytes32 messageHash
    ) internal view returns (bool) {
        // For Optimistic Rollups: verify via L2OutputOracle
        // For ZK Rollups: verify via state root proof
        // For Arbitrum: verify via RBlock
    }

    function _verifyViaOracle(
        uint256 sourceChainId,
        bytes32 messageHash
    ) internal view returns (bool) {
        // Query Chainlink CCIP or custom oracle
        // Cross-reference with multiple data providers
    }
}
```

### Layer 4: Rate Limiting & Circuit Breakers

**Limit damage** from bridge exploits.

```solidity
// contracts/security/BridgeRateLimiter.sol (Enhanced)
contract BridgeRateLimiterV2 {
    struct RateLimit {
        uint256 maxPerTransaction;
        uint256 maxPerHour;
        uint256 maxPerDay;
        uint256 currentHourVolume;
        uint256 currentDayVolume;
        uint256 lastHourReset;
        uint256 lastDayReset;
    }

    mapping(uint256 => RateLimit) public chainLimits;

    // Anomaly detection
    struct AnomalyDetector {
        uint256 avgVolume;        // Rolling average
        uint256 stdDeviation;     // Standard deviation
        uint256 anomalyThreshold; // 3 sigma = 99.7% confidence
    }

    mapping(uint256 => AnomalyDetector) public anomalyDetectors;

    function checkTransfer(
        uint256 chainId,
        uint256 amount
    ) external returns (bool) {
        RateLimit storage limit = chainLimits[chainId];

        // Check per-transaction limit
        require(amount <= limit.maxPerTransaction, "Exceeds per-tx limit");

        // Update rolling windows
        _updateRollingWindows(chainId);

        // Check hourly limit
        require(
            limit.currentHourVolume + amount <= limit.maxPerHour,
            "Exceeds hourly limit"
        );

        // Check daily limit
        require(
            limit.currentDayVolume + amount <= limit.maxPerDay,
            "Exceeds daily limit"
        );

        // Anomaly detection
        if (_isAnomaly(chainId, amount)) {
            emit AnomalyDetected(chainId, amount);
            _triggerCircuitBreaker(chainId);
            return false;
        }

        // Update volumes
        limit.currentHourVolume += amount;
        limit.currentDayVolume += amount;

        return true;
    }

    function _isAnomaly(uint256 chainId, uint256 amount)
        internal view returns (bool)
    {
        AnomalyDetector memory detector = anomalyDetectors[chainId];

        // Check if amount is > 3 standard deviations from mean
        uint256 threshold = detector.avgVolume +
            (detector.stdDeviation * detector.anomalyThreshold);

        return amount > threshold;
    }
}
```

### Layer 5: Economic Security

**Ensure attackers lose more than they gain**.

```solidity
// contracts/security/BridgeSecurityBonds.sol
contract BridgeSecurityBonds {
    struct SecurityBond {
        uint256 validatorBond;    // Validators stake
        uint256 relayerBond;      // Relayers stake
        uint256 insuranceFund;    // Protocol insurance
        uint256 slashingAmount;   // Amount slashed on fraud
    }

    mapping(uint256 => SecurityBond) public chainBonds;

    // Economic security invariant:
    // Total bonds > 2x max value at risk
    function checkEconomicSecurity(uint256 chainId)
        external view returns (bool)
    {
        SecurityBond memory bond = chainBonds[chainId];
        uint256 totalBonds = bond.validatorBond +
                            bond.relayerBond +
                            bond.insuranceFund;

        uint256 maxValueAtRisk = _getMaxValueAtRisk(chainId);

        return totalBonds >= maxValueAtRisk * 2;
    }

    // Slash validators/relayers on fraud proof
    function slashOnFraud(
        uint256 chainId,
        address maliciousActor,
        bytes calldata fraudProof
    ) external {
        require(_verifyFraudProof(fraudProof), "Invalid fraud proof");

        SecurityBond storage bond = chainBonds[chainId];

        // Slash the malicious actor
        _slash(maliciousActor, bond.slashingAmount);

        // Reward fraud reporter
        _reward(msg.sender, bond.slashingAmount / 10);

        emit FraudSlashed(chainId, maliciousActor, bond.slashingAmount);
    }
}
```

### Layer 6: Watchtower Network

**Real-time monitoring** with automated response.

```solidity
// contracts/security/BridgeWatchtowerV2.sol (Enhanced)
contract BridgeWatchtowerV2 {
    struct Alert {
        AlertType alertType;
        uint256 chainId;
        bytes32 messageHash;
        uint256 timestamp;
        address reporter;
        bool resolved;
    }

    enum AlertType {
        SUSPICIOUS_VOLUME,
        INVALID_PROOF,
        VALIDATOR_COMPROMISE,
        REPLAY_ATTACK,
        ECONOMIC_ATTACK
    }

    Alert[] public alerts;

    // Automated response rules
    mapping(AlertType => ResponseAction) public responseRules;

    enum ResponseAction {
        MONITOR,           // Just log
        SLOW_DOWN,         // Increase challenge period
        PAUSE_CHAIN,       // Pause specific chain
        EMERGENCY_STOP     // Stop all bridges
    }

    function reportAlert(
        AlertType alertType,
        uint256 chainId,
        bytes32 messageHash,
        bytes calldata evidence
    ) external {
        require(_verifyEvidence(evidence), "Invalid evidence");

        alerts.push(Alert({
            alertType: alertType,
            chainId: chainId,
            messageHash: messageHash,
            timestamp: block.timestamp,
            reporter: msg.sender,
            resolved: false
        }));

        // Automated response
        ResponseAction action = responseRules[alertType];
        _executeResponse(action, chainId);

        emit AlertRaised(alertType, chainId, messageHash, msg.sender);
    }

    function _executeResponse(ResponseAction action, uint256 chainId) internal {
        if (action == ResponseAction.MONITOR) {
            // Just log, no action
        } else if (action == ResponseAction.SLOW_DOWN) {
            // Increase challenge period to 24 hours
            optimisticVerifier.setChallengePeriod(chainId, 24 hours);
        } else if (action == ResponseAction.PAUSE_CHAIN) {
            // Pause specific chain
            bridgeRouter.pauseChain(chainId);
        } else if (action == ResponseAction.EMERGENCY_STOP) {
            // Stop all bridges
            bridgeRouter.emergencyStop();
        }
    }
}
```

### Layer 7: Insurance & Recovery

**Protect users** even if bridges fail.

```solidity
// contracts/security/BridgeInsuranceFund.sol
contract BridgeInsuranceFund {
    struct InsurancePolicy {
        uint256 coverageAmount;
        uint256 premium;
        uint256 deductible;
        bool isActive;
    }

    mapping(address => InsurancePolicy) public policies;

    uint256 public totalFund;
    uint256 public constant PREMIUM_RATE = 10; // 0.1% per transfer

    // Users pay small premium for insurance
    function insureTransfer(uint256 amount) external payable {
        uint256 premium = (amount * PREMIUM_RATE) / 10000;
        require(msg.value >= premium, "Insufficient premium");

        totalFund += msg.value;

        policies[msg.sender] = InsurancePolicy({
            coverageAmount: amount,
            premium: premium,
            deductible: amount / 100, // 1% deductible
            isActive: true
        });
    }

    // Claim insurance if bridge fails
    function claimInsurance(bytes calldata lossProof) external {
        InsurancePolicy storage policy = policies[msg.sender];
        require(policy.isActive, "No active policy");
        require(_verifyLoss(lossProof), "Invalid loss proof");

        uint256 payout = policy.coverageAmount - policy.deductible;
        require(totalFund >= payout, "Insufficient fund");

        policy.isActive = false;
        totalFund -= payout;

        payable(msg.sender).transfer(payout);

        emit InsuranceClaimed(msg.sender, payout);
    }
}
```

## Bridge Security Scorecard

Evaluate each bridge on multiple dimensions:

```solidity
// contracts/security/BridgeSecurityScorecard.sol
contract BridgeSecurityScorecard {
    struct SecurityScore {
        uint256 validatorDecentralization;  // 0-20 points
        uint256 economicSecurity;           // 0-20 points
        uint256 auditScore;                 // 0-20 points
        uint256 uptimeScore;                // 0-20 points
        uint256 incidentHistory;            // 0-20 points
        uint256 totalScore;                 // 0-100 points
    }

    mapping(address => SecurityScore) public bridgeScores;

    function calculateScore(address bridge) external view returns (uint256) {
        SecurityScore memory score = bridgeScores[bridge];
        return score.totalScore;
    }

    // Only use bridges with score > 70
    function isBridgeSafe(address bridge) external view returns (bool) {
        return bridgeScores[bridge].totalScore >= 70;
    }
}
```

## Implementation Roadmap

### Phase 1: Immediate (Week 1-2)

- [ ] Deploy OptimisticBridgeVerifier
- [ ] Implement rate limiting enhancements
- [ ] Set up watchtower monitoring
- [ ] Create bridge security scorecard

### Phase 2: Short-term (Month 1-2)

- [ ] Add multi-bridge verification
- [ ] Implement independent verification
- [ ] Deploy insurance fund
- [ ] Integrate Chainlink CCIP as backup

### Phase 3: Medium-term (Month 3-6)

- [ ] Launch bug bounty for bridge security
- [ ] Implement economic security bonds
- [ ] Add anomaly detection ML models
- [ ] Create bridge security dashboard

### Phase 4: Long-term (Month 6-12)

- [ ] Develop custom bridge with minimal trust
- [ ] Implement ZK proof of bridge state
- [ ] Create decentralized watchtower network
- [ ] Achieve 99.9% bridge security SLA

## Monitoring & Metrics

### Key Metrics

- Bridge uptime: > 99.9%
- False positive rate: < 1%
- Challenge success rate: Track
- Insurance fund ratio: > 2x TVL
- Security score: > 70 for all bridges

### Alerts

- Unusual volume spike (> 3 sigma)
- Validator set change
- Bridge contract upgrade
- Failed verification
- Economic security below threshold

## Incident Response

### Bridge Exploit Response Plan

**Detection** (0-5 minutes):

- Watchtower detects anomaly
- Automated circuit breaker triggers
- Alert sent to security team

**Containment** (5-30 minutes):

- Pause affected bridge
- Freeze pending transfers
- Assess damage scope

**Investigation** (30 min - 4 hours):

- Analyze exploit method
- Identify affected users
- Calculate losses

**Recovery** (4-24 hours):

- Deploy fix if needed
- Process insurance claims
- Resume operations gradually

**Post-Mortem** (1-7 days):

- Publish incident report
- Update security measures
- Compensate affected users

## Best Practices

### For Users

1. Use native L2 bridges for large amounts (> 100 ETH)
2. Enable insurance for valuable transfers
3. Wait for challenge period on large transfers
4. Monitor bridge security scores
5. Diversify across multiple bridges

### For Developers

1. Never trust bridge messages blindly
2. Always verify with multiple sources
3. Implement rate limiting
4. Use optimistic verification for high value
5. Monitor bridge health continuously

### For Governance

1. Regularly review bridge security scores
2. Update rate limits based on risk
3. Maintain adequate insurance fund
4. Respond quickly to incidents
5. Deprecate insecure bridges

## Session 8 Security Updates

The following bridge security enhancements were implemented in Session 8:

### MultiBridgeRouter Fixes

- **ETH Fee Forwarding (S8-5/S8-6):** `routeMessage()` now forwards `msg.value` to bridge adapters for fee payment. Previously, ETH sent with the call was permanently trapped.
- **`receive()` Function (S8-15):** Added `receive() external payable` to accept ETH refunds from bridge adapters.
- **Emergency Withdrawal:** Added `emergencyWithdrawETH()` restricted to `DEFAULT_ADMIN_ROLE` for recovering stuck ETH.

### Bridge Adapter Enhancements

- **ERC20 Emergency Recovery (S8-20):** All 7 bridge adapters (Starknet, Mantle, Blast, Taiko, Mode, MantaPacific, PolygonZkEVM) now include `emergencyWithdrawERC20()` for recovering accidentally sent ERC20 tokens.
- Both `emergencyWithdrawETH()` and `emergencyWithdrawERC20()` are protected by `onlyRole(DEFAULT_ADMIN_ROLE)` and `nonReentrant`.

### NullifierRegistryV3

- **Source Root Validation (S8-10):** `receiveCrossChainNullifiers()` now rejects `bytes32(0)` as a source Merkle root.

## Resources

- [L2Beat Bridge Risk Analysis](https://l2beat.com/bridges/risk)
- [Chainlink CCIP Security](https://docs.chain.link/ccip/concepts/security)
- [LayerZero Security](https://layerzero.gitbook.io/docs/faq/security)
- [Bridge Security Best Practices](https://github.com/0xbok/awesome-bridge-security)
- [Rekt News Bridge Exploits](https://rekt.news/leaderboard/)
