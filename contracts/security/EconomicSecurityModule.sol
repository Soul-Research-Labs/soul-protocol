// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title EconomicSecurityModule
 * @author Soul Protocol
 * @notice Economic security mechanisms for Soul protocol
 * @dev Implements bonded operations, insurance fund, and slashing
 *
 * Security Properties:
 * 1. Bonded Operations: High-value transfers require security bonds
 * 2. Insurance Fund: Protocol-owned fund for loss coverage
 * 3. Slashing: Malicious actors lose their bonds
 * 4. Economic Finality: Transactions have finality thresholds
 * 5. Risk-Adjusted Fees: Fees scale with transaction risk
 */
contract EconomicSecurityModule is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InsufficientBond();
    error BondLocked();
    error BondNotFound();
    error OperationNotFound();
    error OperationAlreadyFinalized();
    error FinalityPeriodNotElapsed();
    error InvalidRiskLevel();
    error InsufficientInsuranceFund();
    error SlashingDisabled();
    error AlreadySlashed();
    error NotOperator();
    error WithdrawalTooLarge();
    error CooldownNotElapsed();
    error WithdrawalFailed();
    error ClaimTransferFailed();


    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event BondDeposited(
        address indexed operator,
        uint256 amount,
        uint256 totalBond
    );
    event BondWithdrawn(
        address indexed operator,
        uint256 amount,
        uint256 remaining
    );
    event BondSlashed(address indexed operator, uint256 amount, bytes32 reason);
    event OperationBonded(
        bytes32 indexed operationId,
        address indexed operator,
        uint256 bondAmount
    );
    event OperationFinalized(bytes32 indexed operationId, bool success);
    event InsuranceFundDeposit(address indexed depositor, uint256 amount);
    event InsuranceClaim(
        bytes32 indexed operationId,
        uint256 amount,
        address beneficiary
    );
    event RiskParametersUpdated(
        uint256 minBondRatio,
        uint256 maxRiskMultiplier
    );
    event FinalityPeriodUpdated(uint256 newPeriod);

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum RiskLevel {
        LOW, // Standard operations
        MEDIUM, // Elevated value
        HIGH, // High value or first-time
        CRITICAL // Very high value or suspicious
    }

    enum OperationStatus {
        PENDING,
        BONDED,
        FINALIZED,
        SLASHED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Operator {
        uint256 totalBond;
        uint256 lockedBond;
        uint256 availableBond;
        uint256 slashedAmount;
        uint256 successfulOps;
        uint256 failedOps;
        uint256 lastOperationTime;
        uint256 reputationScore; // 0-10000
        bool isActive;
    }

    struct BondedOperation {
        bytes32 operationId;
        address operator;
        uint256 value;
        uint256 bondAmount;
        uint256 createdAt;
        uint256 finalityTime;
        RiskLevel riskLevel;
        OperationStatus status;
        bytes32 proofHash;
    }

    struct InsurancePool {
        uint256 totalFunds;
        uint256 reservedFunds;
        uint256 claimedFunds;
        uint256 lastClaimTime;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /// @notice Minimum bond ratio (basis points of operation value)
    uint256 public minBondRatio;

    /// @notice Maximum risk multiplier for bond calculation
    uint256 public maxRiskMultiplier;

    /// @notice Finality period for operations
    uint256 public finalityPeriod;

    /// @notice Minimum operator bond
    uint256 public constant MIN_OPERATOR_BOND = 1 ether;

    /// @notice Bond withdrawal cooldown
    uint256 public constant WITHDRAWAL_COOLDOWN = 7 days;

    /// @notice Slashing enabled
    bool public slashingEnabled;

    /// @notice Operator data
    mapping(address => Operator) public operators;

    /// @notice Bonded operations
    mapping(bytes32 => BondedOperation) public operations;

    /// @notice Operator's pending operations
    mapping(address => bytes32[]) public operatorPendingOps;

    /// @notice Insurance pool
    InsurancePool public insurancePool;

    /// @notice Risk thresholds (value => risk level)
    uint256[4] public riskThresholds;

    /// @notice Bond multipliers per risk level
    uint256[4] public bondMultipliers;

    /// @notice Operation nonce
    uint256 public operationNonce;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint256 _minBondRatio,
        uint256 _maxRiskMultiplier,
        uint256 _finalityPeriod,
        address admin
    ) {
        minBondRatio = _minBondRatio; // e.g., 500 = 5%
        maxRiskMultiplier = _maxRiskMultiplier; // e.g., 400 = 4x
        finalityPeriod = _finalityPeriod; // e.g., 1 hours
        slashingEnabled = true;

        // Default risk thresholds
        riskThresholds = [
            1 ether, // LOW: < 1 ETH
            10 ether, // MEDIUM: 1-10 ETH
            100 ether, // HIGH: 10-100 ETH
            type(uint256).max // CRITICAL: > 100 ETH
        ];

        // Bond multipliers (basis points)
        bondMultipliers = [
            100, // LOW: 1x
            150, // MEDIUM: 1.5x
            250, // HIGH: 2.5x
            400 // CRITICAL: 4x
        ];

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);
        _grantRole(SLASHER_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                         OPERATOR FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register as an operator and deposit bond
     */
    function registerOperator() external payable nonReentrant {
        if (msg.value < MIN_OPERATOR_BOND) revert InsufficientBond();

        Operator storage op = operators[msg.sender];
        op.totalBond += msg.value;
        op.availableBond += msg.value;
        op.isActive = true;
        op.reputationScore = 5000; // Start at 50%

        _grantRole(OPERATOR_ROLE, msg.sender);

        emit BondDeposited(msg.sender, msg.value, op.totalBond);
    }

    /**
     * @notice Deposit additional bond
     */
    function depositBond()
        external
        payable
        nonReentrant
        onlyRole(OPERATOR_ROLE)
    {
        Operator storage op = operators[msg.sender];
        op.totalBond += msg.value;
        op.availableBond += msg.value;

        emit BondDeposited(msg.sender, msg.value, op.totalBond);
    }

    /**
     * @notice Withdraw available bond (after cooldown)
     * @param amount Amount to withdraw
     */
    function withdrawBond(
        uint256 amount
    ) external nonReentrant onlyRole(OPERATOR_ROLE) {
        Operator storage op = operators[msg.sender];

        if (amount > op.availableBond) revert InsufficientBond();
        if (
            op.lockedBond > 0 &&
            block.timestamp < op.lastOperationTime + WITHDRAWAL_COOLDOWN
        ) {
            revert CooldownNotElapsed();
        }

        // Ensure minimum bond maintained
        if (op.totalBond - amount < MIN_OPERATOR_BOND && op.lockedBond > 0) {
            revert InsufficientBond();
        }

        op.totalBond -= amount;
        op.availableBond -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert WithdrawalFailed();

        emit BondWithdrawn(msg.sender, amount, op.totalBond);
    }

    /*//////////////////////////////////////////////////////////////
                         BONDED OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a bonded operation
     * @param value Operation value
     * @param proofHash Associated proof hash
     * @return operationId Unique operation identifier
     */
    function createBondedOperation(
        uint256 value,
        bytes32 proofHash
    )
        external
        onlyRole(OPERATOR_ROLE)
        nonReentrant
        whenNotPaused
        returns (bytes32 operationId)
    {
        Operator storage op = operators[msg.sender];

        RiskLevel riskLevel = _calculateRiskLevel(value, msg.sender);
        uint256 requiredBond = calculateRequiredBond(value, riskLevel);

        if (op.availableBond < requiredBond) revert InsufficientBond();

        operationId = keccak256(
            abi.encodePacked(
                msg.sender,
                value,
                proofHash,
                operationNonce++,
                block.timestamp
            )
        );

        op.availableBond -= requiredBond;
        op.lockedBond += requiredBond;
        op.lastOperationTime = block.timestamp;

        operations[operationId] = BondedOperation({
            operationId: operationId,
            operator: msg.sender,
            value: value,
            bondAmount: requiredBond,
            createdAt: block.timestamp,
            finalityTime: block.timestamp + finalityPeriod,
            riskLevel: riskLevel,
            status: OperationStatus.BONDED,
            proofHash: proofHash
        });

        operatorPendingOps[msg.sender].push(operationId);

        emit OperationBonded(operationId, msg.sender, requiredBond);
    }

    /**
     * @notice Finalize a bonded operation (release bond)
     * @param operationId Operation to finalize
     */
    function finalizeOperation(bytes32 operationId) external nonReentrant {
        BondedOperation storage operation = operations[operationId];
        Operator storage op = operators[operation.operator];

        if (operation.createdAt == 0) revert OperationNotFound();
        if (operation.status != OperationStatus.BONDED)
            revert OperationAlreadyFinalized();
        if (block.timestamp < operation.finalityTime)
            revert FinalityPeriodNotElapsed();

        operation.status = OperationStatus.FINALIZED;

        // Release bond
        op.lockedBond -= operation.bondAmount;
        op.availableBond += operation.bondAmount;
        op.successfulOps++;

        // Increase reputation
        op.reputationScore = _min(op.reputationScore + 10, 10000);

        emit OperationFinalized(operationId, true);
    }

    /*//////////////////////////////////////////////////////////////
                         SLASHING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Slash an operator for malicious behavior
     * @param operationId Operation involved
     * @param reason Reason for slashing
     */
    function slashOperator(
        bytes32 operationId,
        bytes32 reason
    ) external onlyRole(SLASHER_ROLE) nonReentrant {
        if (!slashingEnabled) revert SlashingDisabled();

        BondedOperation storage operation = operations[operationId];
        Operator storage op = operators[operation.operator];

        if (operation.createdAt == 0) revert OperationNotFound();
        if (operation.status == OperationStatus.SLASHED)
            revert AlreadySlashed();

        uint256 slashAmount = operation.bondAmount;

        operation.status = OperationStatus.SLASHED;
        op.lockedBond -= slashAmount;
        op.totalBond -= slashAmount;
        op.slashedAmount += slashAmount;
        op.failedOps++;

        // Decrease reputation significantly
        op.reputationScore = op.reputationScore > 500
            ? op.reputationScore - 500
            : 0;

        // Add to insurance fund
        insurancePool.totalFunds += slashAmount;

        emit BondSlashed(operation.operator, slashAmount, reason);
    }

    /*//////////////////////////////////////////////////////////////
                         INSURANCE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit to insurance fund
     */
    function depositToInsuranceFund() external payable {
        insurancePool.totalFunds += msg.value;
        emit InsuranceFundDeposit(msg.sender, msg.value);
    }

    /**
     * @notice Claim from insurance fund
     * @param operationId Failed operation
     * @param amount Amount to claim
     * @param beneficiary Claim recipient
     */
    function claimInsurance(
        bytes32 operationId,
        uint256 amount,
        address beneficiary
    ) external onlyRole(GUARDIAN_ROLE) nonReentrant {
        BondedOperation storage operation = operations[operationId];

        if (operation.createdAt == 0) revert OperationNotFound();
        if (operation.status != OperationStatus.SLASHED)
            revert OperationNotFound();

        uint256 available = insurancePool.totalFunds -
            insurancePool.reservedFunds;
        if (amount > available) revert InsufficientInsuranceFund();

        insurancePool.claimedFunds += amount;
        insurancePool.totalFunds -= amount;
        insurancePool.lastClaimTime = block.timestamp;

        (bool success, ) = beneficiary.call{value: amount}("");
        if (!success) revert ClaimTransferFailed();

        emit InsuranceClaim(operationId, amount, beneficiary);
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Calculate required bond for an operation
     * @param value Operation value
     * @param riskLevel Risk level
     * @return bond Required bond amount
     */
    function calculateRequiredBond(
        uint256 value,
        RiskLevel riskLevel
    ) public view returns (uint256 bond) {
        uint256 baseBond = (value * minBondRatio) / 10000;
        uint256 multiplier = bondMultipliers[uint8(riskLevel)];
        bond = (baseBond * multiplier) / 100;

        // Minimum bond floor
        if (bond < 0.01 ether) {
            bond = 0.01 ether;
        }
    }

    /**
     * @notice Get operator stats
     * @param operator Operator address
     * @return totalBond Total bond
     * @return availableBond Available bond
     * @return lockedBond Locked bond
     * @return reputation Reputation score
     */
    function getOperatorStats(
        address operator
    )
        external
        view
        returns (
            uint256 totalBond,
            uint256 availableBond,
            uint256 lockedBond,
            uint256 reputation
        )
    {
        Operator storage op = operators[operator];
        return (
            op.totalBond,
            op.availableBond,
            op.lockedBond,
            op.reputationScore
        );
    }

    /**
     * @notice Get insurance fund balance
     * @return available Available funds
     */
    function getInsuranceFundBalance()
        external
        view
        returns (uint256 available)
    {
        return insurancePool.totalFunds - insurancePool.reservedFunds;
    }

    /**
     * @notice Calculate risk level for a value
     * @param value Operation value
     * @return level Risk level
     */
    function getRiskLevel(
        uint256 value
    ) external view returns (RiskLevel level) {
        return _calculateRiskLevel(value, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _calculateRiskLevel(
        uint256 value,
        address operator
    ) internal view returns (RiskLevel) {
        // Base risk from value
        RiskLevel baseRisk;
        if (value < riskThresholds[0]) {
            baseRisk = RiskLevel.LOW;
        } else if (value < riskThresholds[1]) {
            baseRisk = RiskLevel.MEDIUM;
        } else if (value < riskThresholds[2]) {
            baseRisk = RiskLevel.HIGH;
        } else {
            baseRisk = RiskLevel.CRITICAL;
        }

        // Adjust for operator reputation if provided
        if (operator != address(0)) {
            Operator storage op = operators[operator];
            if (op.reputationScore < 3000) {
                // Low reputation increases risk
                if (baseRisk < RiskLevel.CRITICAL) {
                    return RiskLevel(uint8(baseRisk) + 1);
                }
            } else if (op.reputationScore > 8000 && op.successfulOps > 10) {
                // High reputation can decrease risk
                if (baseRisk > RiskLevel.LOW) {
                    return RiskLevel(uint8(baseRisk) - 1);
                }
            }
        }

        return baseRisk;
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update risk parameters
     * @param _minBondRatio New minimum bond ratio
     * @param _maxRiskMultiplier New max risk multiplier
     */
    function updateRiskParameters(
        uint256 _minBondRatio,
        uint256 _maxRiskMultiplier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minBondRatio = _minBondRatio;
        maxRiskMultiplier = _maxRiskMultiplier;
        emit RiskParametersUpdated(_minBondRatio, _maxRiskMultiplier);
    }

    /**
     * @notice Update finality period
     * @param _finalityPeriod New finality period
     */
    function updateFinalityPeriod(
        uint256 _finalityPeriod
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        finalityPeriod = _finalityPeriod;
        emit FinalityPeriodUpdated(_finalityPeriod);
    }

    /**
     * @notice Enable/disable slashing
     * @param enabled Whether slashing is enabled
     */
    function setSlashingEnabled(
        bool enabled
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        slashingEnabled = enabled;
    }

    /**
     * @notice Pause the module
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the module
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH for insurance fund
     */
    /* solhint-disable-next-line no-complex-fallback */
    receive() external payable {
        insurancePool.totalFunds += msg.value;
        emit InsuranceFundDeposit(msg.sender, msg.value);
    }
}
