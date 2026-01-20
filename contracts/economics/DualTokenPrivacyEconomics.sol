// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title DualTokenPrivacyEconomics
 * @author Soul Protocol
 * @notice Midnight-inspired: Dual-Token Model for Privacy Economics
 * @dev Key insight: Privacy has an ongoing cost and must be paid for SEPARATELY from value transfer.
 *
 * MIDNIGHT'S TOKENOMICS:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ NIGHT: Value / Governance token                                            │
 * │ DUST:  Private computation fuel                                            │
 * │                                                                             │
 * │ This separation:                                                            │
 * │ - Reduces speculation pressure on fees                                      │
 * │ - Eliminates MEV around privacy operations                                  │
 * │ - Treats privacy as a scarce, paid resource                                 │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * SOUL'S IMPLEMENTATION:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ SOUL:  Cross-chain value and governance token                              │
 * │ SHADE: Privacy computation fuel (pays for ZK/TEE/MPC execution)            │
 * │                                                                             │
 * │ Key differences from Midnight:                                              │
 * │ - Network-wide tokenomics, not chain-native                                 │
 * │ - SHADE accrues to execution backend operators                              │
 * │ - Privacy metering is HIDDEN (no gas leakage)                               │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract DualTokenPrivacyEconomics is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ECONOMICS_ADMIN_ROLE =
        keccak256("ECONOMICS_ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant BACKEND_ROLE = keccak256("BACKEND_ROLE");
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Privacy operation type (for costing)
     */
    enum PrivacyOperationType {
        ZKProofGeneration, // ZK-SNARK/STARK proof
        ZKProofVerification, // On-chain verification
        TEEExecution, // TEE enclave execution
        MPCComputation, // Multi-party computation
        StateEncryption, // Encrypt state for privacy
        SelectiveDisclosure, // Prove selective disclosure
        NullifierGeneration, // Generate nullifiers
        PolicyEnforcement, // Enforce privacy policies
        CrossChainPrivacy, // Cross-chain private messaging
        AuditProofGeneration // Generate audit proofs
    }

    /**
     * @notice Backend type (different cost structures)
     */
    enum BackendType {
        ZK_SNARK,
        ZK_STARK,
        ZK_PLONK,
        TEE_SGX,
        TEE_NITRO,
        MPC_THRESHOLD,
        HYBRID
    }

    /**
     * @notice Privacy cost commitment - hides actual cost
     * @dev This is key: cost structure should not leak information
     */
    struct PrivacyCostCommitment {
        bytes32 commitmentId;
        bytes32 executionId;
        // Cost data (commitments, not plaintext)
        bytes32 shadeAmountCommitment; // Commitment to SHADE cost
        bytes32 operationTypeCommitment; // Commitment to operation type
        bytes32 resourceCommitment; // Commitment to resources used
        // Proof that commitment is valid
        bytes32 costProof; // ZK proof of cost calculation
        // Payment
        bool paid;
        bytes32 paymentProof; // Proof of payment
        // Metadata
        address payer;
        uint64 createdAt;
        uint64 paidAt;
    }

    /**
     * @notice Backend operator registration
     */
    struct BackendOperator {
        address operator;
        BackendType backendType;
        bytes32 operatorCommitment; // Hidden operator identity
        // Economics
        uint256 shadeBalance; // Earned SHADE
        uint256 totalExecutions;
        uint256 totalShadeEarned;
        // Status
        bool active;
        uint64 registeredAt;
    }

    /**
     * @notice SHADE distribution pool
     */
    struct DistributionPool {
        bytes32 poolId;
        string name;
        // Allocations (basis points)
        uint256 operatorShare; // To backend operators
        uint256 protocolShare; // To protocol treasury
        uint256 stakerShare; // To SOUL stakers
        uint256 reserveShare; // To reserve fund
        // Totals
        uint256 totalDistributed;
        uint256 pendingDistribution;
    }

    /**
     * @notice Privacy resource pricing
     */
    struct ResourcePricing {
        bytes32 pricingId;
        PrivacyOperationType operationType;
        BackendType backendType;
        // Base price in SHADE (hidden via commitment in actual use)
        uint256 basePrice;
        uint256 perUnitPrice; // Price per unit (e.g., per constraint)
        uint256 complexityMultiplier; // Multiplier for complexity (basis points)
        // Status
        bool active;
        uint64 updatedAt;
    }

    /**
     * @notice Execution cost estimate (privacy-preserving)
     */
    struct CostEstimate {
        bytes32 estimateId;
        bytes32 executionId;
        // Uniform-size response to prevent information leakage
        bytes32 estimatedCostCommitment;
        bytes32 confidenceCommitment; // Confidence level commitment
        bytes32 estimateProof; // Proof estimate is valid
        // Timing
        uint64 estimatedAt;
        uint64 validUntil;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Cost commitments: commitmentId => commitment
    mapping(bytes32 => PrivacyCostCommitment) public costCommitments;

    /// @notice Backend operators: operator => registration
    mapping(address => BackendOperator) public operators;

    /// @notice Operator list
    address[] public operatorList;

    /// @notice Distribution pools: poolId => pool
    mapping(bytes32 => DistributionPool) public pools;

    /// @notice Resource pricing: pricingId => pricing
    mapping(bytes32 => ResourcePricing) public pricing;

    /// @notice Cost estimates: estimateId => estimate
    mapping(bytes32 => CostEstimate) public estimates;

    /// @notice Execution costs: executionId => commitmentId
    mapping(bytes32 => bytes32) public executionCosts;

    /// @notice Default pool
    bytes32 public defaultPoolId;

    /// @notice Counters
    uint256 public totalCostCommitments;
    uint256 public totalOperators;
    uint256 public totalShadeCollected;
    uint256 public totalShadeDistributed;

    /// @notice Protocol treasury
    address public treasury;

    /// @notice SHADE token address (would be ERC20)
    address public shadeToken;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperatorRegistered(
        address indexed operator,
        BackendType backendType,
        bytes32 operatorCommitment
    );

    event CostCommitmentCreated(
        bytes32 indexed commitmentId,
        bytes32 indexed executionId,
        address payer
    );

    event CostPaid(
        bytes32 indexed commitmentId,
        bytes32 indexed executionId,
        bytes32 paymentProof
    );

    event ShadeDistributed(
        bytes32 indexed poolId,
        uint256 amount,
        uint256 operatorAmount,
        uint256 protocolAmount
    );

    event PricingUpdated(
        bytes32 indexed pricingId,
        PrivacyOperationType operationType,
        BackendType backendType
    );

    event CostEstimated(
        bytes32 indexed estimateId,
        bytes32 indexed executionId
    );

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _treasury, address _shadeToken) {
        require(_treasury != address(0), "DTPE: zero treasury");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ECONOMICS_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(TREASURY_ROLE, msg.sender);

        treasury = _treasury;
        shadeToken = _shadeToken;

        // Create default distribution pool
        defaultPoolId = keccak256("DEFAULT_POOL");
        pools[defaultPoolId] = DistributionPool({
            poolId: defaultPoolId,
            name: "Default Distribution",
            operatorShare: 6000, // 60% to operators
            protocolShare: 2000, // 20% to protocol
            stakerShare: 1500, // 15% to stakers
            reserveShare: 500, // 5% to reserve
            totalDistributed: 0,
            pendingDistribution: 0
        });
    }

    /*//////////////////////////////////////////////////////////////
                        OPERATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as a backend operator
     * @param backendType Type of backend operated
     * @param operatorCommitment Commitment to operator identity (privacy)
     */
    function registerOperator(
        BackendType backendType,
        bytes32 operatorCommitment
    ) external {
        require(
            operators[msg.sender].registeredAt == 0,
            "DTPE: already registered"
        );

        operators[msg.sender] = BackendOperator({
            operator: msg.sender,
            backendType: backendType,
            operatorCommitment: operatorCommitment,
            shadeBalance: 0,
            totalExecutions: 0,
            totalShadeEarned: 0,
            active: true,
            registeredAt: uint64(block.timestamp)
        });

        operatorList.push(msg.sender);
        totalOperators++;

        _grantRole(BACKEND_ROLE, msg.sender);

        emit OperatorRegistered(msg.sender, backendType, operatorCommitment);
    }

    /*//////////////////////////////////////////////////////////////
                     COST COMMITMENT (PRIVACY-PRESERVING)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a privacy-preserving cost commitment
     * @dev This hides the actual cost to prevent fee analysis attacks
     * @param executionId Execution this cost is for
     * @param shadeAmountCommitment Commitment to SHADE amount
     * @param operationTypeCommitment Commitment to operation type
     * @param resourceCommitment Commitment to resources used
     * @param costProof ZK proof that cost is correctly calculated
     * @return commitmentId The cost commitment identifier
     */
    function createCostCommitment(
        bytes32 executionId,
        bytes32 shadeAmountCommitment,
        bytes32 operationTypeCommitment,
        bytes32 resourceCommitment,
        bytes32 costProof
    ) external whenNotPaused nonReentrant returns (bytes32 commitmentId) {
        require(executionCosts[executionId] == bytes32(0), "DTPE: cost exists");
        require(shadeAmountCommitment != bytes32(0), "DTPE: amount required");
        require(costProof != bytes32(0), "DTPE: proof required");

        commitmentId = keccak256(
            abi.encodePacked(
                executionId,
                shadeAmountCommitment,
                block.timestamp,
                totalCostCommitments
            )
        );

        costCommitments[commitmentId] = PrivacyCostCommitment({
            commitmentId: commitmentId,
            executionId: executionId,
            shadeAmountCommitment: shadeAmountCommitment,
            operationTypeCommitment: operationTypeCommitment,
            resourceCommitment: resourceCommitment,
            costProof: costProof,
            paid: false,
            paymentProof: bytes32(0),
            payer: msg.sender,
            createdAt: uint64(block.timestamp),
            paidAt: 0
        });

        executionCosts[executionId] = commitmentId;
        totalCostCommitments++;

        emit CostCommitmentCreated(commitmentId, executionId, msg.sender);
    }

    /**
     * @notice Pay for a cost commitment (privacy-preserving)
     * @dev Payment proof hides actual amount transferred
     * @param commitmentId Cost commitment to pay
     * @param paymentProof ZK proof of payment
     */
    function payCost(
        bytes32 commitmentId,
        bytes32 paymentProof
    ) external whenNotPaused nonReentrant {
        PrivacyCostCommitment storage commitment = costCommitments[
            commitmentId
        ];
        require(commitment.commitmentId != bytes32(0), "DTPE: not found");
        require(!commitment.paid, "DTPE: already paid");
        require(paymentProof != bytes32(0), "DTPE: proof required");

        // TODO: Verify payment proof against shadeAmountCommitment
        // In production, this would verify the ZK proof that:
        // 1. Correct amount was transferred
        // 2. Amount matches the commitment
        // 3. Transfer was to correct recipient

        commitment.paid = true;
        commitment.paymentProof = paymentProof;
        commitment.paidAt = uint64(block.timestamp);

        emit CostPaid(commitmentId, commitment.executionId, paymentProof);
    }

    /*//////////////////////////////////////////////////////////////
                         COST ESTIMATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get privacy-preserving cost estimate
     * @dev Returns commitment, not plaintext, to prevent information leakage
     * @param executionId Execution to estimate
     * @param operationType Type of operation
     * @param backendType Backend to use
     * @param complexityHint Hint about complexity (may be hidden)
     * @return estimateId The estimate identifier
     */
    function estimateCost(
        bytes32 executionId,
        PrivacyOperationType operationType,
        BackendType backendType,
        bytes32 complexityHint
    ) external returns (bytes32 estimateId) {
        // Get pricing
        bytes32 pricingId = _getPricingId(operationType, backendType);
        ResourcePricing storage resourcePricing = pricing[pricingId];

        // Calculate estimate commitment (in production, this would be a ZK operation)
        bytes32 estimatedCostCommitment = keccak256(
            abi.encodePacked(
                resourcePricing.basePrice,
                complexityHint,
                block.timestamp
            )
        );

        estimateId = keccak256(
            abi.encodePacked(
                executionId,
                estimatedCostCommitment,
                block.timestamp
            )
        );

        estimates[estimateId] = CostEstimate({
            estimateId: estimateId,
            executionId: executionId,
            estimatedCostCommitment: estimatedCostCommitment,
            confidenceCommitment: complexityHint, // Placeholder
            estimateProof: bytes32(0), // Would be ZK proof in production
            estimatedAt: uint64(block.timestamp),
            validUntil: uint64(block.timestamp + 1 hours)
        });

        emit CostEstimated(estimateId, executionId);
    }

    /*//////////////////////////////////////////////////////////////
                          DISTRIBUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Distribute SHADE to operators and protocol
     * @param poolId Pool to distribute from
     * @param totalAmount Total amount to distribute
     * @param operatorShares Operator shares (parallel array with operatorAddresses)
     * @param operatorAddresses Operators to pay
     */
    function distribute(
        bytes32 poolId,
        uint256 totalAmount,
        uint256[] calldata operatorShares,
        address[] calldata operatorAddresses
    ) external onlyRole(TREASURY_ROLE) {
        require(
            operatorShares.length == operatorAddresses.length,
            "DTPE: length mismatch"
        );

        DistributionPool storage pool = pools[poolId];
        require(pool.poolId != bytes32(0), "DTPE: pool not found");

        // Calculate splits
        uint256 operatorAmount = (totalAmount * pool.operatorShare) / 10000;
        uint256 protocolAmount = (totalAmount * pool.protocolShare) / 10000;

        // Distribute to operators
        for (uint256 i = 0; i < operatorAddresses.length; i++) {
            BackendOperator storage op = operators[operatorAddresses[i]];
            if (op.active) {
                uint256 share = (operatorAmount * operatorShares[i]) / 10000;
                op.shadeBalance += share;
                op.totalShadeEarned += share;
            }
        }

        pool.totalDistributed += totalAmount;
        totalShadeDistributed += totalAmount;

        emit ShadeDistributed(
            poolId,
            totalAmount,
            operatorAmount,
            protocolAmount
        );
    }

    /**
     * @notice Operator withdraws earned SHADE
     */
    function withdrawShade() external nonReentrant {
        BackendOperator storage op = operators[msg.sender];
        require(op.shadeBalance > 0, "DTPE: no balance");

        uint256 amount = op.shadeBalance;
        op.shadeBalance = 0;

        // In production, transfer SHADE token
        // IERC20(shadeToken).transfer(msg.sender, amount);
    }

    /*//////////////////////////////////////////////////////////////
                          PRICING MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set pricing for an operation type
     */
    function setPricing(
        PrivacyOperationType operationType,
        BackendType backendType,
        uint256 basePrice,
        uint256 perUnitPrice,
        uint256 complexityMultiplier
    ) external onlyRole(ECONOMICS_ADMIN_ROLE) {
        bytes32 pricingId = _getPricingId(operationType, backendType);

        pricing[pricingId] = ResourcePricing({
            pricingId: pricingId,
            operationType: operationType,
            backendType: backendType,
            basePrice: basePrice,
            perUnitPrice: perUnitPrice,
            complexityMultiplier: complexityMultiplier,
            active: true,
            updatedAt: uint64(block.timestamp)
        });

        emit PricingUpdated(pricingId, operationType, backendType);
    }

    function _getPricingId(
        PrivacyOperationType operationType,
        BackendType backendType
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(operationType, backendType));
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if execution cost is paid
     */
    function isCostPaid(bytes32 executionId) external view returns (bool) {
        bytes32 commitmentId = executionCosts[executionId];
        if (commitmentId == bytes32(0)) return false;
        return costCommitments[commitmentId].paid;
    }

    /**
     * @notice Get operator balance
     */
    function getOperatorBalance(
        address operator
    ) external view returns (uint256) {
        return operators[operator].shadeBalance;
    }

    /**
     * @notice Get cost commitment
     */
    function getCostCommitment(
        bytes32 commitmentId
    ) external view returns (PrivacyCostCommitment memory) {
        return costCommitments[commitmentId];
    }

    /**
     * @notice Get operator count
     */
    function getOperatorCount() external view returns (uint256) {
        return operatorList.length;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setTreasury(
        address _treasury
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_treasury != address(0), "DTPE: zero address");
        treasury = _treasury;
    }

    function setShadeToken(
        address _shadeToken
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        shadeToken = _shadeToken;
    }

    function deactivateOperator(
        address operator
    ) external onlyRole(ECONOMICS_ADMIN_ROLE) {
        operators[operator].active = false;
        _revokeRole(BACKEND_ROLE, operator);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
